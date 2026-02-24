// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::abi::{
    EthBridgeCommittee, EthBridgeConfig, EthBridgeLimiter, EthBridgeVault, EthStarcoinBridge,
};
use crate::config::{
    default_ed25519_key_pair, BridgeNodeConfig, EthConfig, MetricsConfig, StarcoinConfig,
    WatchdogConfig,
};
use crate::crypto::BridgeAuthorityKeyPair;
use crate::crypto::BridgeAuthorityPublicKeyBytes;

use anyhow::anyhow;
use ethers::core::k256::ecdsa::SigningKey;
use ethers::middleware::SignerMiddleware;
use ethers::prelude::*;
use ethers::providers::{Http, Provider};
use ethers::signers::Wallet;
use ethers::types::Address as EthAddress;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::secp256k1::Secp256k1KeyPair;
use fastcrypto::traits::EncodeDecodeBase64;
use fastcrypto::traits::ToFromBytes;
use starcoin_bridge_config::Config;
use starcoin_bridge_keys::keypair_file::read_key;
use starcoin_bridge_types::base_types::StarcoinAddress;
use starcoin_bridge_types::bridge::BridgeChainId;
use starcoin_bridge_types::crypto::get_key_pair;
use starcoin_bridge_types::crypto::StarcoinKeyPair;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

pub type EthSigner = SignerMiddleware<Provider<Http>, Wallet<SigningKey>>;

pub struct EthBridgeContracts<P> {
    pub bridge: EthStarcoinBridge<Provider<P>>,
    pub committee: EthBridgeCommittee<Provider<P>>,
    pub limiter: EthBridgeLimiter<Provider<P>>,
    pub vault: EthBridgeVault<Provider<P>>,
    pub config: EthBridgeConfig<Provider<P>>,
}

// Generate Bridge Authority key (Secp256k1KeyPair) and write to a file as base64 encoded `privkey`.
pub fn generate_bridge_authority_key_and_write_to_file(
    path: &PathBuf,
) -> Result<(), anyhow::Error> {
    use fastcrypto::traits::KeyPair;
    let (_, kp): (_, BridgeAuthorityKeyPair) = get_key_pair();
    let eth_address = BridgeAuthorityPublicKeyBytes::from(kp.public()).to_eth_address();
    tracing::debug!(
        "Corresponding Ethereum address by this ecdsa key: {:?}",
        eth_address
    );
    // Secp256k1PublicKey doesn't have a direct conversion to StarcoinAddress
    // For testing, use first 16 bytes of public key
    let pub_bytes = kp.public().as_bytes();
    let starcoin_bridge_address =
        StarcoinAddress::from_bytes(&pub_bytes[..16.min(pub_bytes.len())])
            .unwrap_or(StarcoinAddress::ZERO);
    tracing::debug!(
        "Corresponding Starcoin address by this ecdsa key: {:?}",
        starcoin_bridge_address
    );
    let base64_encoded = kp.encode_base64();
    std::fs::write(path, base64_encoded)
        .map_err(|err| anyhow!("Failed to write encoded key to path: {:?}", err))
}

// Generate Bridge Client key (Secp256k1KeyPair or Ed25519KeyPair) and write to a file as base64 encoded `flag || privkey`.
pub fn generate_bridge_client_key_and_write_to_file(
    path: &PathBuf,
    use_ecdsa: bool,
) -> Result<(), anyhow::Error> {
    use fastcrypto::traits::KeyPair;
    let kp = if use_ecdsa {
        let (_, kp): (_, Secp256k1KeyPair) = get_key_pair();
        let eth_address = BridgeAuthorityPublicKeyBytes::from(kp.public()).to_eth_address();
        tracing::debug!(
            "Corresponding Ethereum address by this ecdsa key: {:?}",
            eth_address
        );
        StarcoinKeyPair::Secp256k1(kp)
    } else {
        let (_, kp): (_, Ed25519KeyPair) = get_key_pair();
        StarcoinKeyPair::Ed25519(kp)
    };
    // Use proper Starcoin address derivation (SHA3-256 hash algorithm)
    let starcoin_bridge_address = kp.starcoin_address();
    tracing::debug!(
        "Corresponding Starcoin address by this key: {:?}",
        starcoin_bridge_address
    );

    let contents = kp.encode_base64();
    std::fs::write(path, contents)
        .map_err(|err| anyhow!("Failed to write encoded key to path: {:?}", err))
}

// Given the address of StarcoinBridge Proxy, return the addresses of the committee, limiter, vault, and config.
pub async fn get_eth_contract_addresses<P: ethers::providers::JsonRpcClient + 'static>(
    bridge_proxy_address: EthAddress,
    provider: &Arc<Provider<P>>,
) -> anyhow::Result<(
    EthAddress,
    EthAddress,
    EthAddress,
    EthAddress,
    EthAddress,
    EthAddress,
    EthAddress,
    EthAddress,
)> {
    let starcoin_bridge = EthStarcoinBridge::new(bridge_proxy_address, provider.clone());
    let committee_address: EthAddress = starcoin_bridge.committee().call().await?;
    let committee = EthBridgeCommittee::new(committee_address, provider.clone());
    let config_address: EthAddress = committee.config().call().await?;
    let bridge_config = EthBridgeConfig::new(config_address, provider.clone());
    let limiter_address: EthAddress = starcoin_bridge.limiter().call().await?;
    let vault_address: EthAddress = starcoin_bridge.vault().call().await?;
    let vault = EthBridgeVault::new(vault_address, provider.clone());
    let weth_address: EthAddress = vault.w_eth().call().await?;
    let usdt_address: EthAddress = bridge_config.token_address_of(4).call().await?;
    let wbtc_address: EthAddress = bridge_config.token_address_of(1).call().await?;
    let lbtc_address: EthAddress = bridge_config.token_address_of(6).call().await?;

    Ok((
        committee_address,
        limiter_address,
        vault_address,
        config_address,
        weth_address,
        usdt_address,
        wbtc_address,
        lbtc_address,
    ))
}

// Given the address of StarcoinBridge Proxy, return the contracts of the committee, limiter, vault, and config.
pub async fn get_eth_contracts<P: ethers::providers::JsonRpcClient + 'static>(
    bridge_proxy_address: EthAddress,
    provider: &Arc<Provider<P>>,
) -> anyhow::Result<EthBridgeContracts<P>> {
    let starcoin_bridge = EthStarcoinBridge::new(bridge_proxy_address, provider.clone());
    let committee_address: EthAddress = starcoin_bridge.committee().call().await?;
    let limiter_address: EthAddress = starcoin_bridge.limiter().call().await?;
    let vault_address: EthAddress = starcoin_bridge.vault().call().await?;
    let committee = EthBridgeCommittee::new(committee_address, provider.clone());
    let config_address: EthAddress = committee.config().call().await?;

    let limiter = EthBridgeLimiter::new(limiter_address, provider.clone());
    let vault = EthBridgeVault::new(vault_address, provider.clone());
    let config = EthBridgeConfig::new(config_address, provider.clone());
    Ok(EthBridgeContracts {
        bridge: starcoin_bridge,
        committee,
        limiter,
        vault,
        config,
    })
}

// Read bridge key from a file and print the corresponding information.
// If `is_validator_key` is true, the key must be a Secp256k1 key.
pub fn examine_key(path: &PathBuf, is_validator_key: bool) -> Result<(), anyhow::Error> {
    use fastcrypto::traits::KeyPair;
    let key = read_key(path, is_validator_key)?;
    let pubkey = match &key {
        StarcoinKeyPair::Secp256k1(kp) => {
            println!("Key type: Secp256k1");
            let eth_address = BridgeAuthorityPublicKeyBytes::from(kp.public()).to_eth_address();
            println!("Ethereum address: {:x}", eth_address);
            kp.public().as_bytes().to_vec()
        }
        StarcoinKeyPair::Ed25519(kp) => {
            println!("Key type: Ed25519");
            kp.public().as_bytes().to_vec()
        }
    };
    // Derive Starcoin address using proper algorithm:
    // SHA3-256(pubkey || scheme_flag), take last 16 bytes
    let starcoin_bridge_address = key.starcoin_address();
    println!("Starcoin address: {:?}", starcoin_bridge_address);
    println!("PublicKey: {:?}", Hex::encode(pubkey));
    Ok(())
}

// Generate Bridge Node Config template and write to a file.
pub fn generate_bridge_node_config_and_write_to_file(path: &PathBuf) -> Result<(), anyhow::Error> {
    let config = BridgeNodeConfig {
        server_listen_port: 9191,
        metrics_port: 9184,
        bridge_authority_key_path: PathBuf::from("/path/to/your/bridge_authority_key"),
        starcoin: StarcoinConfig {
            starcoin_bridge_rpc_url: "your_starcoin_bridge_rpc_url".to_string(),
            starcoin_bridge_proxy_address: "0x0000000000000000000000000000000000000000".to_string(),
            starcoin_bridge_chain_id: BridgeChainId::StarcoinTestnet as u8,
        },
        eth: EthConfig {
            eth_rpc_url: "your_eth_rpc_url".to_string(),
            eth_bridge_proxy_address: "0x0000000000000000000000000000000000000000".to_string(),
            eth_bridge_chain_id: BridgeChainId::EthSepolia as u8,
        },
        metrics_key_pair: default_ed25519_key_pair(),
        metrics: Some(MetricsConfig {
            push_interval_seconds: None, // use default value
            push_url: "metrics_proxy_url".to_string(),
            auth_username: None,
            auth_password: String::new(),
        }),
        watchdog_config: Some(WatchdogConfig {
            total_supplies: BTreeMap::from_iter(vec![(
                "eth".to_string(),
                "0xd0e89b2af5e4910726fbcd8b8dd37bb79b29e5f83f7491bca830e94f7f226d29::eth::ETH"
                    .to_string(),
            )]),
        }),
    };
    config.save(path)
}

pub async fn get_eth_signer_client(url: &str, private_key_hex: &str) -> anyhow::Result<EthSigner> {
    let provider = Provider::<Http>::try_from(url)
        .unwrap()
        .interval(std::time::Duration::from_millis(2000));
    let chain_id = provider.get_chainid().await?;
    let wallet = Wallet::from_str(private_key_hex)
        .unwrap()
        .with_chain_id(chain_id.as_u64());
    Ok(SignerMiddleware::new(provider, wallet))
}
