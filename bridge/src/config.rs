// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::abi::EthBridgeConfig;
use crate::crypto::BridgeAuthorityKeyPair;
use crate::eth_client::EthClient;
use crate::metered_eth_provider::new_metered_eth_provider;
use crate::metered_eth_provider::MeteredEthHttpProvier;
use crate::metrics::BridgeMetrics;
use crate::starcoin_bridge_client::StarcoinBridgeClient;
use crate::types::is_route_valid;
use crate::utils::get_eth_contract_addresses;
use anyhow::anyhow;
use ethers::providers::Middleware;
use ethers::types::Address as EthAddress;
use fastcrypto::ed25519::Ed25519KeyPair;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use starcoin_bridge_config::Config;
use starcoin_bridge_keys::keypair_file::read_key;
use tracing::info;
use starcoin_bridge_types::bridge::BridgeChainId;
use starcoin_bridge_types::crypto::{NetworkKeyPair, StarcoinKeyPair};
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct EthConfig {
    // Rpc url for Eth fullnode, used for query stuff.
    pub eth_rpc_url: String,
    // The proxy address of StarcoinBridge
    pub eth_bridge_proxy_address: String,
    // The expected BridgeChainId on Eth side.
    pub eth_bridge_chain_id: u8,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct StarcoinConfig {
    // Rpc url for Starcoin fullnode, used for query stuff and submit transactions.
    pub starcoin_bridge_rpc_url: String,
    // The Bridge contract address on Starcoin (deployed Move module address)
    pub starcoin_bridge_proxy_address: String,
    // The expected BridgeChainId on Starcoin side.
    pub starcoin_bridge_chain_id: u8,
}

#[serde_as]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct BridgeNodeConfig {
    // The port that the server listens on.
    pub server_listen_port: u16,
    // The port that for metrics server.
    pub metrics_port: u16,
    // Path of the file where bridge authority key (Secp256k1) is stored.
    pub bridge_authority_key_path: PathBuf,
    // Starcoin configuration
    pub starcoin: StarcoinConfig,
    // Eth configuration
    pub eth: EthConfig,
    // Network key used for metrics pushing
    #[serde(default = "default_ed25519_key_pair")]
    pub metrics_key_pair: NetworkKeyPair,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsConfig>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchdog_config: Option<WatchdogConfig>,
}

pub fn default_ed25519_key_pair() -> NetworkKeyPair {
    use fastcrypto::traits::ToFromBytes;
    // Use a fixed test key - in production this should be generated securely
    let test_key_bytes: [u8; 32] = [0; 32]; // Fixed seed for testing
    Ed25519KeyPair::from_bytes(&test_key_bytes).expect("Failed to create default Ed25519 keypair")
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct MetricsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_interval_seconds: Option<u64>,
    pub push_url: String,
    /// Optional username for Basic Auth (Prometheus Pushgateway)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_username: Option<String>,
    /// Password for Basic Auth (required if auth_username is set)
    #[serde(default)]
    pub auth_password: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct WatchdogConfig {
    // Total supplies to watch on Starcoin. Mapping from coin name to coin type tag
    pub total_supplies: BTreeMap<String, String>,
}

impl Config for BridgeNodeConfig {}

impl BridgeNodeConfig {
    pub async fn validate(
        &self,
        metrics: Arc<BridgeMetrics>,
    ) -> anyhow::Result<BridgeServerConfig> {
        info!("Starting config validation");
        if !is_route_valid(
            BridgeChainId::try_from(self.starcoin.starcoin_bridge_chain_id)?,
            BridgeChainId::try_from(self.eth.eth_bridge_chain_id)?,
        ) {
            return Err(anyhow!(
                "Route between Starcoin chain id {} and Eth chain id {} is not valid",
                self.starcoin.starcoin_bridge_chain_id,
                self.eth.eth_bridge_chain_id,
            ));
        };

        // Load bridge authority key from file
        // The key must be a Secp256k1 key for bridge operations
        let bridge_authority_key = match read_key(&self.bridge_authority_key_path, true) {
            Ok(StarcoinKeyPair::Secp256k1(key)) => {
                info!(
                    "Successfully loaded Secp256k1 bridge authority key from {:?}",
                    self.bridge_authority_key_path
                );
                key
            }
            Ok(_) => {
                return Err(anyhow!(
                    "Bridge authority key at {:?} is not a Secp256k1 key. \
                    Bridge requires Secp256k1 keys for compatibility with Ethereum signatures.",
                    self.bridge_authority_key_path
                ));
            }
            Err(e) => {
                return Err(anyhow!(
                    "Failed to read bridge authority key from {:?}: {}. \
                    Please ensure the key file exists and contains a valid Base64-encoded Secp256k1 private key. \
                    You can generate a new key using: starcoin-bridge-keys generate --output <path>",
                    self.bridge_authority_key_path,
                    e
                ));
            }
        };

        // Use JSON-RPC client to avoid nested tokio runtime issues
        tracing::info!("Creating JSON-RPC Starcoin client");

        let starcoin_bridge_client = Arc::new(StarcoinBridgeClient::with_metrics(
            &self.starcoin.starcoin_bridge_rpc_url,
            &self.starcoin.starcoin_bridge_proxy_address,
            metrics.clone(),
        ));

        let (eth_client, eth_contracts) = self.prepare_for_eth(metrics.clone()).await?;

        let bridge_server_config = BridgeServerConfig {
            key: bridge_authority_key,
            metrics_port: self.metrics_port,
            eth_bridge_proxy_address: eth_contracts[0], // the first contract is bridge proxy
            server_listen_port: self.server_listen_port,
            starcoin_bridge_client: starcoin_bridge_client.clone(),
            eth_client: eth_client.clone(),
        };

        info!("Config validation complete");
        Ok(bridge_server_config)
    }

    async fn prepare_for_eth(
        &self,
        metrics: Arc<BridgeMetrics>,
    ) -> anyhow::Result<(Arc<EthClient<MeteredEthHttpProvier>>, Vec<EthAddress>)> {
        info!("Creating Ethereum client provider");
        let bridge_proxy_address = EthAddress::from_str(&self.eth.eth_bridge_proxy_address)?;
        let provider = Arc::new(
            new_metered_eth_provider(&self.eth.eth_rpc_url, metrics.clone())
                .unwrap()
                .interval(std::time::Duration::from_millis(2000)),
        );
        let chain_id = provider.get_chainid().await?;
        let (committee_address, limiter_address, vault_address, config_address, _, _, _, _) =
            get_eth_contract_addresses(bridge_proxy_address, &provider).await?;
        let config = EthBridgeConfig::new(config_address, provider.clone());

        // If bridge chain id is Eth Mainent or Sepolia, we expect to see chain
        // identifier to match accordingly.
        let bridge_chain_id: u8 = config.chain_id().call().await?;
        if self.eth.eth_bridge_chain_id != bridge_chain_id {
            return Err(anyhow!(
                "Bridge chain id mismatch: expected {}, but connected to {}",
                self.eth.eth_bridge_chain_id,
                bridge_chain_id
            ));
        }
        if bridge_chain_id == BridgeChainId::EthMainnet as u8 && chain_id.as_u64() != 1 {
            anyhow::bail!(
                "Expected Eth chain id 1, but connected to {}",
                chain_id.as_u64()
            );
        }
        if bridge_chain_id == BridgeChainId::EthSepolia as u8 && chain_id.as_u64() != 11155111 {
            anyhow::bail!(
                "Expected Eth chain id 11155111, but connected to {}",
                chain_id.as_u64()
            );
        }
        info!(
            "Connected to Eth chain: {}, Bridge chain id: {}",
            chain_id.as_u64(),
            bridge_chain_id,
        );

        // Log all contract addresses for debugging
        info!(
            "ETH contract addresses - proxy: {:?}, committee: {:?}, config: {:?}, limiter: {:?}, vault: {:?}",
            bridge_proxy_address, committee_address, config_address, limiter_address, vault_address
        );

        // EthClient auto-detects local network (chain_id 31337) and uses 'latest' instead of 'finalized'
        let eth_client = Arc::new(
            EthClient::<MeteredEthHttpProvier>::new_with_chain_id(
                &self.eth.eth_rpc_url,
                HashSet::from_iter(vec![
                    bridge_proxy_address,
                    committee_address,
                    config_address,
                    limiter_address,
                    vault_address,
                ]),
                metrics,
                Some(chain_id.as_u64()),
            )
            .await?,
        );
        let contract_addresses = vec![
            bridge_proxy_address,
            committee_address,
            config_address,
            limiter_address,
            vault_address,
        ];
        info!("Ethereum client setup complete");
        Ok((eth_client, contract_addresses))
    }
}

pub struct BridgeServerConfig {
    pub key: BridgeAuthorityKeyPair,
    pub server_listen_port: u16,
    pub eth_bridge_proxy_address: EthAddress,
    pub metrics_port: u16,
    pub starcoin_bridge_client: Arc<StarcoinBridgeClient>,
    pub eth_client: Arc<EthClient<MeteredEthHttpProvier>>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct BridgeCommitteeConfig {
    pub bridge_authority_port_and_key_path: Vec<(u64, PathBuf)>,
}

impl Config for BridgeCommitteeConfig {}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct EthContractAddresses {
    pub starcoin_bridge: EthAddress,
    pub bridge_committee: EthAddress,
    pub bridge_config: EthAddress,
    pub bridge_limiter: EthAddress,
    pub bridge_vault: EthAddress,
}
