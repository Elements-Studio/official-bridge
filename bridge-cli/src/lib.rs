// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use clap::*;
use ethers::providers::Middleware;
use ethers::types::Address as EthAddress;
use ethers::types::U256;
use fastcrypto::encoding::Encoding;
use fastcrypto::encoding::Hex;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use starcoin_bridge::abi::EthBridgeCommittee;
use starcoin_bridge::abi::{eth_starcoin_bridge, EthStarcoinBridge};
use starcoin_bridge::crypto::{
    BridgeAuthorityKeyPair, BridgeAuthorityPublicKeyBytes, BridgeAuthorityRecoverableSignature,
    BridgeAuthoritySignInfo,
};
use starcoin_bridge::error::BridgeResult;
use starcoin_bridge::starcoin_bridge_client::StarcoinBridgeClient;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use starcoin_bridge::types::BridgeAction;
use starcoin_bridge::types::{
    BlocklistCommitteeAction, BlocklistType, EmergencyAction, EmergencyActionType,
    EvmAddMemberAction, EvmContractUpgradeAction, LimitUpdateAction, UpdateCommitteeMemberAction,
    UpdateCommitteeMemberType,
};
use starcoin_bridge::utils::{get_eth_signer_client, EthSigner};
use starcoin_bridge_config::Config;
use starcoin_bridge_keys::keypair_file::read_key;
use starcoin_bridge_types::base_types::StarcoinAddress;
use starcoin_bridge_types::bridge::BridgeChainId;
use starcoin_bridge_types::crypto::StarcoinKeyPair;
use starcoin_bridge_types::TypeTag;
use tracing::info;

pub const SEPOLIA_BRIDGE_PROXY_ADDR: &str = "0xAE68F87938439afEEDd6552B0E83D2CbC2473623";

#[derive(Parser)]
#[clap(rename_all = "kebab-case")]
pub struct Args {
    #[clap(subcommand)]
    pub command: BridgeCommand,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum Network {
    Testnet,
}

#[derive(Parser)]
#[clap(rename_all = "kebab-case")]
pub enum BridgeCommand {
    #[clap(name = "create-bridge-validator-key")]
    CreateBridgeValidatorKey { path: PathBuf },
    #[clap(name = "create-bridge-client-key")]
    CreateBridgeClientKey {
        path: PathBuf,
        #[clap(long = "use-ecdsa", default_value = "false")]
        use_ecdsa: bool,
    },
    // Read bridge key from a file and print related information
    // If `is-validator-key` is true, the key must be a secp256k1 key
    #[clap(name = "examine-key")]
    ExamineKey {
        path: PathBuf,
        #[clap(long = "is-validator-key")]
        is_validator_key: bool,
    },
    #[clap(name = "create-bridge-node-config-template")]
    CreateBridgeNodeConfigTemplate { path: PathBuf },
    // Governance client to facilitate and execute Bridge governance actions
    #[clap(name = "governance")]
    Governance {
        // Path of BridgeCliConfig
        #[clap(long = "config-path")]
        config_path: PathBuf,
        #[clap(long = "chain-id")]
        chain_id: u8,
        #[clap(subcommand)]
        cmd: GovernanceClientCommands,
        // If true, only collect signatures but not execute on chain
        #[clap(long = "dry-run")]
        dry_run: bool,
    },
    // Offline sign a governance action (no network interaction, just sign with admin key)
    // Usage: On machine A with admin private key, sign the action and output signature
    #[clap(name = "governance-sign")]
    GovernanceSign {
        // Path to the admin/authority private key file (secp256k1 key)
        #[clap(long = "key-path")]
        key_path: PathBuf,
        // Target chain: ETH chain ID (e.g., 10=EthMainnet, 11=EthSepolia, 12=EthCustom)
        // Only one of --eth-chain-id or --starcoin-chain-id should be specified
        #[clap(long = "eth-chain-id", conflicts_with = "starcoin_chain_id")]
        eth_chain_id: Option<u8>,
        // Target chain: Starcoin chain ID (e.g., 0=StarcoinMainnet, 1=StarcoinTestnet, 2=StarcoinCustom)
        #[clap(long = "starcoin-chain-id", conflicts_with = "eth_chain_id")]
        starcoin_chain_id: Option<u8>,
        #[clap(subcommand)]
        cmd: GovernanceClientCommands,
    },
    // Execute a governance action with provided signatures (directly interact with chain)
    // Usage: On machine B with ETH/Starcoin signer key, execute the action using pre-signed signatures
    #[clap(name = "governance-execute")]
    GovernanceExecute {
        // Path of BridgeCliConfig (needs eth_rpc_url/starcoin_rpc_url and keys for on-chain interaction)
        #[clap(long = "config-path")]
        config_path: PathBuf,
        // Target chain: ETH chain ID (e.g., 10=EthMainnet, 11=EthSepolia, 12=EthCustom)
        // Only one of --eth-chain-id or --starcoin-chain-id should be specified
        #[clap(long = "eth-chain-id", conflicts_with = "starcoin_chain_id")]
        eth_chain_id: Option<u8>,
        // Target chain: Starcoin chain ID (e.g., 0=StarcoinMainnet, 1=StarcoinTestnet, 2=StarcoinCustom)
        #[clap(long = "starcoin-chain-id", conflicts_with = "eth_chain_id")]
        starcoin_chain_id: Option<u8>,
        #[clap(subcommand)]
        cmd: GovernanceClientCommands,
        // Hex-encoded signatures, separated by comma
        // Each signature is 65 bytes: r (32) + s (32) + v (1)
        #[clap(long = "signatures", use_value_delimiter = true)]
        signatures: Vec<String>,
    },
    // View current status of Eth bridge
    #[clap(name = "view-eth-bridge")]
    ViewEthBridge {
        #[clap(long = "network")]
        network: Option<Network>,
        #[clap(long = "bridge-proxy")]
        bridge_proxy: Option<EthAddress>,
        #[clap(long = "eth-rpc-url")]
        eth_rpc_url: String,
    },
    // View current list of registered validators
    #[clap(name = "view-bridge-registration")]
    ViewBridgeRegistration {
        #[clap(long = "starcoin-bridge-rpc-url")]
        starcoin_bridge_rpc_url: String,
        #[clap(long = "starcoin-bridge-proxy-address")]
        starcoin_bridge_proxy_address: String,
    },
    // View current status of Starcoin bridge
    #[clap(name = "view-starcoin-bridge")]
    ViewStarcoinBridge {
        #[clap(long = "starcoin-bridge-rpc-url")]
        starcoin_bridge_rpc_url: String,
        #[clap(long = "starcoin-bridge-proxy-address")]
        starcoin_bridge_proxy_address: String,
        #[clap(long, default_value = "false")]
        hex: bool,
        #[clap(long, default_value = "false")]
        ping: bool,
    },
    // Client to facilitate and execute Bridge actions
    #[clap(name = "client")]
    Client {
        // Path of BridgeCliConfig
        #[clap(long = "config-path")]
        config_path: PathBuf,
        #[clap(subcommand)]
        cmd: BridgeClientCommands,
    },
}

#[derive(Parser)]
#[clap(rename_all = "kebab-case")]
pub enum GovernanceClientCommands {
    #[clap(name = "emergency-button")]
    EmergencyButton {
        #[clap(name = "nonce", long)]
        nonce: u64,
        #[clap(name = "action-type", long)]
        action_type: EmergencyActionType,
    },
    #[clap(name = "update-committee-blocklist")]
    UpdateCommitteeBlocklist {
        #[clap(name = "nonce", long)]
        nonce: u64,
        #[clap(name = "blocklist-type", long)]
        blocklist_type: BlocklistType,
        #[clap(name = "pubkey-hex", use_value_delimiter = true, long)]
        pubkeys_hex: Vec<BridgeAuthorityPublicKeyBytes>,
    },
    #[clap(name = "update-limit")]
    UpdateLimit {
        #[clap(name = "nonce", long)]
        nonce: u64,
        #[clap(name = "sending-chain", long)]
        sending_chain: u8,
        #[clap(name = "new-usd-limit", long)]
        new_usd_limit: u64,
    },
    /// Upgrade an EVM contract via UUPS proxy pattern.
    /// This is used to update committee by deploying a new implementation contract.
    #[clap(name = "upgrade-evm-contract")]
    UpgradeEvmContract {
        #[clap(name = "nonce", long)]
        nonce: u64,
        /// The proxy contract address to upgrade
        #[clap(name = "proxy-address", long)]
        proxy_address: EthAddress,
        /// The new implementation contract address
        #[clap(name = "new-impl-address", long)]
        new_impl_address: EthAddress,
        /// Optional call data for post-upgrade initialization (hex encoded, without 0x prefix)
        #[clap(name = "call-data", long, default_value = "")]
        call_data: String,
    },
    /// Update committee member on Starcoin (add only).
    /// This allows the committee admin to directly add new members.
    /// Note: To remove members, use the blocklist command instead.
    #[clap(name = "update-committee-member")]
    UpdateCommitteeMember {
        #[clap(name = "nonce", long)]
        nonce: u64,
        /// Update type: only 'add' is supported (use blocklist for removal)
        #[clap(name = "update-type", long)]
        update_type: UpdateCommitteeMemberType,
        /// The bridge public key bytes (hex, 33-byte compressed ECDSA)
        #[clap(name = "pubkey-hex", long)]
        pubkey_hex: String,
        /// The voting power of the member (out of 10000)
        #[clap(name = "voting-power", long)]
        voting_power: u64,
        /// The HTTP REST URL of the member's node
        #[clap(name = "http-rest-url", long)]
        http_rest_url: String,
    },
    /// Add a new committee member on EVM chain.
    /// This uses the ADD_MEMBER (type 8) governance action with EVM-specific payload.
    #[clap(name = "add-member-eth")]
    AddMemberEth {
        #[clap(name = "nonce", long)]
        nonce: u64,
        /// The EVM address of the new committee member (20 bytes, hex with 0x prefix)
        #[clap(name = "member-address", long)]
        member_address: EthAddress,
        /// The stake amount for the member (uint16, 0-65535)
        #[clap(name = "stake", long)]
        stake: u16,
    },
}

pub fn make_action(chain_id: BridgeChainId, cmd: &GovernanceClientCommands) -> BridgeAction {
    match cmd {
        GovernanceClientCommands::EmergencyButton { nonce, action_type } => {
            BridgeAction::EmergencyAction(EmergencyAction {
                nonce: *nonce,
                chain_id,
                action_type: *action_type,
            })
        }
        GovernanceClientCommands::UpdateCommitteeBlocklist {
            nonce,
            blocklist_type,
            pubkeys_hex,
        } => BridgeAction::BlocklistCommitteeAction(BlocklistCommitteeAction {
            nonce: *nonce,
            chain_id,
            blocklist_type: *blocklist_type,
            members_to_update: pubkeys_hex.clone(),
        }),
        GovernanceClientCommands::UpdateLimit {
            nonce,
            sending_chain,
            new_usd_limit,
        } => {
            let sending_chain_id =
                BridgeChainId::try_from(*sending_chain).expect("Invalid sending chain id");
            BridgeAction::LimitUpdateAction(LimitUpdateAction {
                nonce: *nonce,
                chain_id,
                sending_chain_id,
                new_usd_limit: *new_usd_limit,
            })
        }
        GovernanceClientCommands::UpgradeEvmContract {
            nonce,
            proxy_address,
            new_impl_address,
            call_data,
        } => {
            let call_data_bytes = if call_data.is_empty() {
                vec![]
            } else {
                Hex::decode(call_data.trim_start_matches("0x"))
                    .expect("Invalid call_data hex string")
            };
            BridgeAction::EvmContractUpgradeAction(EvmContractUpgradeAction {
                nonce: *nonce,
                chain_id,
                proxy_address: *proxy_address,
                new_impl_address: *new_impl_address,
                call_data: call_data_bytes,
            })
        }
        GovernanceClientCommands::UpdateCommitteeMember {
            nonce,
            update_type,
            pubkey_hex,
            voting_power,
            http_rest_url,
        } => {
            let pubkey_bytes = Hex::decode(pubkey_hex.trim_start_matches("0x"))
                .expect("Invalid pubkey hex string");
            // Derive member_address from pubkey (first 16 bytes)
            let member_address =
                StarcoinAddress::from_bytes(&pubkey_bytes[..16.min(pubkey_bytes.len())])
                    .unwrap_or(StarcoinAddress::ZERO);
            BridgeAction::UpdateCommitteeMemberAction(UpdateCommitteeMemberAction {
                nonce: *nonce,
                chain_id,
                update_type: *update_type,
                member_address,
                bridge_pubkey_bytes: pubkey_bytes,
                voting_power: *voting_power,
                http_rest_url: http_rest_url.clone(),
            })
        }
        GovernanceClientCommands::AddMemberEth {
            nonce,
            member_address,
            stake,
        } => BridgeAction::EvmAddMemberAction(EvmAddMemberAction {
            nonce: *nonce,
            chain_id,
            member_address: *member_address,
            stake: *stake,
        }),
    }
}

pub fn select_contract_address(
    config: &LoadedBridgeCliConfig,
    cmd: &GovernanceClientCommands,
) -> EthAddress {
    match cmd {
        GovernanceClientCommands::EmergencyButton { .. } => config.eth_bridge_proxy_address,
        GovernanceClientCommands::UpdateCommitteeBlocklist { .. } => {
            config.eth_bridge_committee_proxy_address
        }
        GovernanceClientCommands::UpdateLimit { .. } => config.eth_bridge_limiter_proxy_address,
        // For EvmContractUpgrade, the proxy address is specified in the command itself,
        // so we return a placeholder here. The actual address will be extracted from the action.
        GovernanceClientCommands::UpgradeEvmContract { proxy_address, .. } => *proxy_address,
        // UpdateCommitteeMember is a Starcoin-only action, return zero address for ETH
        GovernanceClientCommands::UpdateCommitteeMember { .. } => EthAddress::zero(),
        // AddMemberEth goes to the committee contract
        GovernanceClientCommands::AddMemberEth { .. } => config.eth_bridge_committee_proxy_address,
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct BridgeCliConfig {
    // Rpc url for Starcoin fullnode, used for query stuff and submit transactions.
    pub starcoin_bridge_rpc_url: String,
    // Rpc url for Eth fullnode, used for query stuff.
    pub eth_rpc_url: String,
    // Proxy address for Bridge deployed on Starcoin (Move contract address, for Ed25519)
    pub starcoin_bridge_proxy_address: String,
    // Proxy address for StarcoinBridge deployed on Eth
    pub eth_bridge_proxy_address: EthAddress,
    // Path of the file where private key is stored. The content could be any of the following:
    // - Base64 encoded `flag || privkey` for ECDSA key
    // - Base64 encoded `privkey` for Raw key
    // - Hex encoded `privkey` for Raw key
    // At leaset one of `starcoin_bridge_key_path` or `eth_key_path` must be provided.
    // If only one is provided, it will be used for both Starcoin and Eth.
    pub starcoin_bridge_key_path: Option<PathBuf>,
    // See `starcoin_bridge_key_path`. Must be Secp256k1 key.
    pub eth_key_path: Option<PathBuf>,
    // Optional: separate gas key for Starcoin operations (Ed25519).
    // When set, emergency pause on STC will use the permissionless entry point
    // (`execute_emergency_op_permissionless`) with this key as the gas-paying sender,
    // instead of requiring the bridge admin key.
    // This allows ops teams to execute pre-signed emergency pauses without the admin key.
    #[serde(default)]
    pub starcoin_gas_key_path: Option<PathBuf>,
}

impl Config for BridgeCliConfig {}

pub struct LoadedBridgeCliConfig {
    // Rpc url for Starcoin fullnode, used for query stuff and submit transactions.
    pub starcoin_bridge_rpc_url: String,
    // Rpc url for Eth fullnode, used for query stuff.
    pub eth_rpc_url: String,
    // Proxy address for Bridge deployed on Starcoin (Move contract address, Ed25519)
    pub starcoin_bridge_proxy_address: String,
    // Proxy address for StarcoinBridge deployed on Eth
    pub eth_bridge_proxy_address: EthAddress,
    // Proxy address for BridgeCommittee deployed on Eth
    pub eth_bridge_committee_proxy_address: EthAddress,
    // Proxy address for BridgeConfig deployed on Eth
    pub eth_bridge_config_proxy_address: EthAddress,
    // Proxy address for BridgeLimiter deployed on Eth
    pub eth_bridge_limiter_proxy_address: EthAddress,
    // Key pair for Starcoin operations
    starcoin_bridge_key: StarcoinKeyPair,
    // Key pair for Eth operations, must be Secp256k1 key
    eth_signer: EthSigner,
    // Optional: separate gas key for Starcoin (Ed25519).
    // When present, STC emergency pause uses the permissionless Move entry point.
    pub starcoin_gas_key: Option<StarcoinKeyPair>,
}

impl LoadedBridgeCliConfig {
    pub async fn load(cli_config: BridgeCliConfig) -> anyhow::Result<Self> {
        // Check if we should use starcoin_bridge_proxy_private_key to build the key
        let starcoin_bridge_key =
            if let Some(starcoin_bridge_key_path) = &cli_config.starcoin_bridge_key_path {
                Some(read_key(starcoin_bridge_key_path, false)?)
            } else {
                None
            };

        // Load optional gas key for permissionless STC emergency pause
        let starcoin_gas_key =
            if let Some(gas_key_path) = &cli_config.starcoin_gas_key_path {
                match read_key(gas_key_path, false) {
                    Ok(key) => {
                        tracing::info!("Loaded Starcoin gas key from {:?}", gas_key_path);
                        Some(key)
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load Starcoin gas key: {:?}", e);
                        None
                    }
                }
            } else {
                None
            };

        if cli_config.eth_key_path.is_none() && starcoin_bridge_key.is_none() {
            return Err(anyhow!(
                "At least one of `starcoin_bridge_key_path`, `eth_key_path`, or `starcoin_bridge_proxy_private_key` must be provided"
            ));
        }
        let eth_key = if let Some(eth_key_path) = &cli_config.eth_key_path {
            let eth_key = read_key(eth_key_path, true)?;
            Some(eth_key)
        } else {
            None
        };
        let (eth_key, starcoin_bridge_key) = {
            if eth_key.is_none() {
                let starcoin_bridge_key = starcoin_bridge_key.unwrap();
                if !matches!(starcoin_bridge_key, StarcoinKeyPair::Secp256k1(_)) {
                    return Err(anyhow!("Eth key must be an ECDSA key"));
                }
                let starcoin_bridge_key_clone = match &starcoin_bridge_key {
                    StarcoinKeyPair::Secp256k1(kp) => {
                        use fastcrypto::traits::ToFromBytes;
                        StarcoinKeyPair::Secp256k1(
                            fastcrypto::secp256k1::Secp256k1KeyPair::from_bytes(kp.as_bytes())
                                .unwrap(),
                        )
                    }
                    StarcoinKeyPair::Ed25519(kp) => {
                        use fastcrypto::traits::ToFromBytes;
                        StarcoinKeyPair::Ed25519(
                            fastcrypto::ed25519::Ed25519KeyPair::from_bytes(kp.as_bytes()).unwrap(),
                        )
                    }
                };
                (starcoin_bridge_key_clone, starcoin_bridge_key)
            } else if starcoin_bridge_key.is_none() {
                let eth_key = eth_key.unwrap();
                let eth_key_clone = match &eth_key {
                    StarcoinKeyPair::Secp256k1(kp) => {
                        use fastcrypto::traits::ToFromBytes;
                        StarcoinKeyPair::Secp256k1(
                            fastcrypto::secp256k1::Secp256k1KeyPair::from_bytes(kp.as_bytes())
                                .unwrap(),
                        )
                    }
                    StarcoinKeyPair::Ed25519(kp) => {
                        use fastcrypto::traits::ToFromBytes;
                        StarcoinKeyPair::Ed25519(
                            fastcrypto::ed25519::Ed25519KeyPair::from_bytes(kp.as_bytes()).unwrap(),
                        )
                    }
                };
                (eth_key_clone, eth_key)
            } else {
                (eth_key.unwrap(), starcoin_bridge_key.unwrap())
            }
        };

        let provider = Arc::new(
            ethers::prelude::Provider::<ethers::providers::Http>::try_from(&cli_config.eth_rpc_url)
                .unwrap()
                .interval(std::time::Duration::from_millis(2000)),
        );
        // Extract private key bytes from StarcoinKeyPair
        let private_key = match &eth_key {
            StarcoinKeyPair::Secp256k1(kp) => {
                use fastcrypto::traits::ToFromBytes;
                Hex::encode(kp.as_bytes())
            }
            StarcoinKeyPair::Ed25519(kp) => {
                use fastcrypto::traits::ToFromBytes;
                Hex::encode(kp.as_bytes())
            }
        };
        let eth_signer = get_eth_signer_client(&cli_config.eth_rpc_url, &private_key).await?;
        let starcoin_bridge =
            EthStarcoinBridge::new(cli_config.eth_bridge_proxy_address, provider.clone());
        let eth_bridge_committee_proxy_address: EthAddress =
            starcoin_bridge.committee().call().await?;
        let eth_bridge_limiter_proxy_address: EthAddress = starcoin_bridge.limiter().call().await?;
        let eth_committee =
            EthBridgeCommittee::new(eth_bridge_committee_proxy_address, provider.clone());
        let eth_bridge_committee_proxy_address: EthAddress =
            starcoin_bridge.committee().call().await?;
        let eth_bridge_config_proxy_address: EthAddress = eth_committee.config().call().await?;

        let eth_address = eth_signer.address();
        let eth_chain_id = provider.get_chainid().await?;
        // Convert Vec<u8> to StarcoinAddress (AccountAddress = 16 bytes)
        let pub_bytes = starcoin_bridge_key.public();
        let starcoin_bridge_address =
            StarcoinAddress::from_bytes(&pub_bytes[..16.min(pub_bytes.len())])
                .unwrap_or(StarcoinAddress::ZERO);
        tracing::debug!("Using Starcoin address: {:?}", starcoin_bridge_address);
        tracing::debug!("Using Eth address: {:?}", eth_address);
        tracing::debug!("Using Eth chain: {:?}", eth_chain_id);

        Ok(Self {
            starcoin_bridge_rpc_url: cli_config.starcoin_bridge_rpc_url,
            eth_rpc_url: cli_config.eth_rpc_url,
            starcoin_bridge_proxy_address: cli_config.starcoin_bridge_proxy_address,
            eth_bridge_proxy_address: cli_config.eth_bridge_proxy_address,
            eth_bridge_committee_proxy_address,
            eth_bridge_limiter_proxy_address,
            eth_bridge_config_proxy_address,
            starcoin_bridge_key,
            eth_signer,
            starcoin_gas_key,
        })
    }
}

impl LoadedBridgeCliConfig {
    pub fn eth_signer(self: &LoadedBridgeCliConfig) -> &EthSigner {
        &self.eth_signer
    }

    pub fn get_starcoin_bridge_key(&self) -> StarcoinKeyPair {
        // Clone StarcoinKeyPair
        match &self.starcoin_bridge_key {
            StarcoinKeyPair::Secp256k1(kp) => {
                use fastcrypto::traits::ToFromBytes;
                StarcoinKeyPair::Secp256k1(
                    fastcrypto::secp256k1::Secp256k1KeyPair::from_bytes(kp.as_bytes()).unwrap(),
                )
            }
            StarcoinKeyPair::Ed25519(kp) => {
                use fastcrypto::traits::ToFromBytes;
                StarcoinKeyPair::Ed25519(
                    fastcrypto::ed25519::Ed25519KeyPair::from_bytes(kp.as_bytes()).unwrap(),
                )
            }
        }
    }
}
#[derive(Parser)]
#[clap(rename_all = "kebab-case")]
pub enum BridgeClientCommands {
    #[clap(name = "deposit-native-ether-on-eth")]
    DepositNativeEtherOnEth {
        #[clap(long)]
        ether_amount: f64,
        #[clap(long)]
        target_chain: u8,
        #[clap(long)]
        starcoin_bridge_recipient_address: StarcoinAddress,
    },
    #[clap(name = "deposit-on-starcoin")]
    DepositOnstarcoin {
        #[clap(long, help = "Amount to deposit (in smallest unit)")]
        amount: u128,
        #[clap(long)]
        coin_type: String,
        #[clap(long)]
        target_chain: u8,
        #[clap(long)]
        recipient_address: EthAddress,
    },
    #[clap(name = "claim-on-eth")]
    ClaimOnEth {
        #[clap(long)]
        seq_num: u64,
        #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
        dry_run: bool,
    },
}

impl BridgeClientCommands {
    pub async fn handle(
        self,
        config: &LoadedBridgeCliConfig,
        starcoin_bridge_client: StarcoinBridgeClient,
    ) -> anyhow::Result<()> {
        match self {
            BridgeClientCommands::DepositNativeEtherOnEth {
                ether_amount,
                target_chain,
                starcoin_bridge_recipient_address,
            } => {
                let eth_starcoin_bridge = EthStarcoinBridge::new(
                    config.eth_bridge_proxy_address,
                    Arc::new(config.eth_signer().clone()),
                );
                // Note: even with f64 there may still be loss of precision even there are a lot of 0s
                let int_part = ether_amount.trunc() as u64;
                let frac_part = ether_amount.fract();
                let int_wei = U256::from(int_part) * U256::exp10(18);
                let frac_wei = U256::from((frac_part * 1_000_000_000_000_000_000f64) as u64);
                let amount = int_wei + frac_wei;
                // Starcoin address is 16 bytes, Solidity contract expects exactly 16 bytes
                let addr_bytes = starcoin_bridge_recipient_address.to_vec();
                let eth_tx = eth_starcoin_bridge
                    .bridge_eth(addr_bytes.into(), target_chain)
                    .value(amount);
                let pending_tx = eth_tx.send().await.unwrap();
                let tx_receipt = pending_tx.await.unwrap().unwrap();
                info!(
                    "Deposited {ether_amount} Ethers to {:?} (target chain {target_chain}). Receipt: {:?}", starcoin_bridge_recipient_address, tx_receipt,
                );
                Ok(())
            }
            BridgeClientCommands::ClaimOnEth { seq_num, dry_run } => {
                claim_on_eth(seq_num, config, starcoin_bridge_client, dry_run)
                    .await
                    .map_err(|e| anyhow!("{:?}", e))
            }
            BridgeClientCommands::DepositOnstarcoin {
                amount,
                coin_type,
                target_chain,
                recipient_address,
            } => {
                let target_chain = BridgeChainId::try_from(target_chain).expect("Invalid chain id");
                let coin_type = TypeTag::from_str(&coin_type).expect("Invalid coin type");
                deposit_on_starcoin(coin_type, target_chain, recipient_address, amount, config)
                    .await
            }
        }
    }
}

async fn deposit_on_starcoin(
    coin_type: TypeTag,
    target_chain: BridgeChainId,
    recipient_address: EthAddress,
    amount: u128,
    config: &LoadedBridgeCliConfig,
) -> anyhow::Result<()> {
    use starcoin_bridge::simple_starcoin_rpc::SimpleStarcoinRpcClient;
    use starcoin_bridge::starcoin_bridge_transaction_builder::starcoin_native;

    let target_chain_id = target_chain as u8;

    // Get sender address from the key using proper Starcoin address derivation
    // (SHA3-256 hash of pubkey || scheme_flag, take last 16 bytes)
    let sender_move_addr = config.starcoin_bridge_key.starcoin_address();
    let sender = StarcoinAddress::new(sender_move_addr.into());
    let sender_hex = format!("0x{}", Hex::encode(sender.as_ref()));

    // Create RPC client for sequence number query
    let rpc_client = SimpleStarcoinRpcClient::new(
        &config.starcoin_bridge_rpc_url,
        &config.starcoin_bridge_proxy_address,
    );

    // Get sequence number from chain
    let sequence_number = rpc_client
        .get_sequence_number(&sender_hex)
        .await
        .map_err(|e| anyhow!("Failed to get sequence number: {:?}", e))?;

    // Get current block timestamp for transaction expiration
    let block_timestamp_ms = rpc_client
        .get_block_timestamp()
        .await
        .map_err(|e| anyhow!("Failed to get block timestamp: {:?}", e))?;

    // Get chain ID from Starcoin node (e.g., 254 for dev, 251 for halley)
    // Note: This is different from bridge_summary.chain_id which is the Bridge chain ID
    let chain_id = rpc_client
        .get_chain_id()
        .await
        .map_err(|e| anyhow!("Failed to get chain ID: {:?}", e))?;

    info!(
        sender = ?sender,
        sender_hex = %sender_hex,
        sequence_number = sequence_number,
        target_chain = target_chain_id,
        recipient = ?recipient_address,
        coin_type = ?coin_type,
        amount = amount,
        chain_id = chain_id,
        block_timestamp_ms = block_timestamp_ms,
        "Building deposit transaction on Starcoin"
    );

    // Parse module address from config (starcoin_bridge_proxy_address is where the bridge contract is deployed)
    let module_address = {
        let addr_str = config
            .starcoin_bridge_proxy_address
            .trim_start_matches("0x");
        let bytes = Hex::decode(addr_str)
            .map_err(|e| anyhow!("Invalid bridge proxy address hex: {:?}", e))?;
        if bytes.len() != 16 {
            return Err(anyhow!(
                "Invalid bridge proxy address length: expected 16 bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        StarcoinAddress::new(arr)
    };

    // Build the raw transaction using bridge types
    let raw_txn = starcoin_native::build_send_token(
        module_address,
        sender,
        sequence_number,
        chain_id,
        block_timestamp_ms,
        target_chain_id,
        recipient_address.as_bytes().to_vec(),
        amount,
        coin_type,
    )
    .map_err(|e| anyhow!("Failed to build transaction: {:?}", e))?;

    info!(
        sender = ?raw_txn.sender(),
        seq = raw_txn.sequence_number(),
        max_gas = raw_txn.max_gas_amount(),
        "Raw transaction built"
    );

    // Use sign_and_submit_transaction which uses Starcoin native types for proper BCS serialization
    // This is the same path used by the bridge server for approve/claim transactions
    info!("Signing and submitting transaction to Starcoin...");
    let txn_hash = rpc_client
        .sign_and_submit_transaction(&config.starcoin_bridge_key, raw_txn)
        .await
        .map_err(|e| anyhow!("Failed to sign and submit transaction: {:?}", e))?;

    info!(
        txn_hash = %txn_hash,
        "Transaction submitted successfully"
    );

    tracing::debug!("Transaction submitted!");
    tracing::debug!("Transaction hash: {}", txn_hash);

    Ok(())
}

async fn claim_on_eth(
    seq_num: u64,
    config: &LoadedBridgeCliConfig,
    starcoin_bridge_client: StarcoinBridgeClient,
    dry_run: bool,
) -> BridgeResult<()> {
    let starcoin_bridge_chain_id = starcoin_bridge_client.get_bridge_summary().await?.chain_id;
    let parsed_message = starcoin_bridge_client
        .get_parsed_token_transfer_message(starcoin_bridge_chain_id, seq_num)
        .await?;
    if parsed_message.is_none() {
        tracing::debug!(
            "No record found for seq_num: {seq_num}, chain id: {starcoin_bridge_chain_id}"
        );
        return Ok(());
    }
    let parsed_message = parsed_message.unwrap();
    let sigs = starcoin_bridge_client
        .get_token_transfer_action_onchain_signatures_until_success(
            starcoin_bridge_chain_id,
            seq_num,
        )
        .await;
    if sigs.is_none() {
        tracing::debug!(
            "No signatures found for seq_num: {seq_num}, chain id: {starcoin_bridge_chain_id}"
        );
        return Ok(());
    }
    let signatures = sigs
        .unwrap()
        .into_iter()
        .map(|sig: Vec<u8>| ethers::types::Bytes::from(sig))
        .collect::<Vec<_>>();

    let eth_starcoin_bridge = EthStarcoinBridge::new(
        config.eth_bridge_proxy_address,
        Arc::new(config.eth_signer().clone()),
    );
    let message = eth_starcoin_bridge::Message::from(parsed_message);
    let tx = eth_starcoin_bridge.transfer_bridged_tokens_with_signatures(signatures, message);
    if dry_run {
        let tx = tx.tx;
        let resp = config.eth_signer.estimate_gas(&tx, None).await;
        tracing::debug!(
            "Starcoin to Eth bridge transfer claim dry run result: {:?}",
            resp
        );
    } else {
        let eth_claim_tx_receipt = tx.send().await.unwrap().await.unwrap().unwrap();
        tracing::debug!(
            "Starcoin to Eth bridge transfer claimed: {:?}",
            eth_claim_tx_receipt
        );
    }
    Ok(())
}

// ===========================================================================
// Offline Governance Signing and Execution
// ===========================================================================

/// Sign a governance action offline using the admin/authority private key.
/// This function does NOT interact with any network - it's purely offline signing.
///
/// Returns the hex-encoded signature string.
pub fn sign_governance_action_offline(
    key_path: &PathBuf,
    action: &BridgeAction,
) -> anyhow::Result<String> {
    use fastcrypto::traits::ToFromBytes;

    // Read the secp256k1 private key from file
    let key = read_key(key_path, true)?;
    let keypair = match key {
        StarcoinKeyPair::Secp256k1(kp) => BridgeAuthorityKeyPair::from_bytes(kp.as_bytes())
            .map_err(|e| anyhow!("Failed to parse secp256k1 key: {:?}", e))?,
        _ => {
            return Err(anyhow!(
                "Key must be a secp256k1 key for governance signing"
            ))
        }
    };

    // Create the signature using the existing BridgeAuthoritySignInfo
    let sig_info = BridgeAuthoritySignInfo::new(action, &keypair);

    // Encode the signature as hex (65 bytes: r(32) + s(32) + recovery_id(1))
    let sig_bytes = sig_info.signature.as_ref();
    let sig_hex = Hex::encode(sig_bytes);

    // Also compute and print the signer's ETH address for verification
    let pubkey_bytes = BridgeAuthorityPublicKeyBytes::from(&sig_info.authority_pub_key);
    let eth_address = pubkey_bytes.to_eth_address();

    info!(
        "Signed governance action offline:\n  Action: {}\n  Signer ETH address: {:?}\n  Signature: {}",
        action.action_type(),
        eth_address,
        sig_hex
    );

    Ok(sig_hex)
}

/// Deserialize signatures from hex strings.
/// Each signature should be 65 bytes (hex-encoded).
pub fn parse_signatures(
    signatures_hex: &[String],
) -> anyhow::Result<Vec<BridgeAuthorityRecoverableSignature>> {
    use fastcrypto::traits::ToFromBytes;

    let mut signatures = Vec::new();
    for (i, sig_hex) in signatures_hex.iter().enumerate() {
        let sig_bytes = Hex::decode(sig_hex.trim_start_matches("0x"))
            .map_err(|e| anyhow!("Failed to decode signature {} from hex: {:?}", i, e))?;

        let sig = BridgeAuthorityRecoverableSignature::from_bytes(&sig_bytes)
            .map_err(|e| anyhow!("Failed to parse signature {}: {:?}", i, e))?;

        signatures.push(sig);
    }

    Ok(signatures)
}

/// Execute a governance action on ETH chain with provided signatures.
/// This function directly interacts with the ETH chain, no bridge server involved.
pub async fn execute_governance_on_eth(
    config: &LoadedBridgeCliConfig,
    action: BridgeAction,
    signatures_hex: Vec<String>,
) -> anyhow::Result<()> {
    use starcoin_bridge::abi::{
        eth_bridge_committee, eth_bridge_limiter, eth_starcoin_bridge, EthBridgeLimiter,
    };
    // Parse signatures from hex
    let signatures: Vec<ethers::types::Bytes> = signatures_hex
        .iter()
        .map(|s| {
            let bytes =
                Hex::decode(s.trim_start_matches("0x")).expect("Failed to decode signature hex");
            ethers::types::Bytes::from(bytes)
        })
        .collect();

    if signatures.is_empty() {
        return Err(anyhow!("No signatures provided"));
    }

    info!(
        "Executing governance action on ETH:\n  Action type: {}\n  Chain ID: {:?}\n  Nonce: {}\n  Number of signatures: {}",
        action.action_type(),
        action.chain_id(),
        action.seq_number(),
        signatures.len()
    );

    let eth_signer = config.eth_signer().clone();

    match &action {
        BridgeAction::EmergencyAction(emergency) => {
            let contract =
                EthStarcoinBridge::new(config.eth_bridge_proxy_address, Arc::new(eth_signer));
            let message: eth_starcoin_bridge::Message = emergency
                .clone()
                .try_into()
                .map_err(|e| anyhow!("Failed to convert EmergencyAction to message: {:?}", e))?;

            info!("Sending emergency operation transaction...");
            let tx = contract.execute_emergency_op_with_signatures(signatures, message);
            let pending = tx
                .send()
                .await
                .map_err(|e| anyhow!("Failed to send emergency tx: {:?}", e))?;
            let receipt = pending
                .await
                .map_err(|e| anyhow!("Failed to get receipt: {:?}", e))?
                .ok_or_else(|| anyhow!("No receipt returned"))?;

            info!(
                "Emergency operation executed successfully!\n  Tx hash: {:?}\n  Block: {:?}\n  Status: {:?}",
                receipt.transaction_hash,
                receipt.block_number,
                receipt.status
            );
        }

        BridgeAction::BlocklistCommitteeAction(blocklist) => {
            let contract = EthBridgeCommittee::new(
                config.eth_bridge_committee_proxy_address,
                Arc::new(eth_signer),
            );
            let message: eth_bridge_committee::Message = blocklist
                .clone()
                .try_into()
                .map_err(|e| anyhow!("Failed to convert BlocklistAction to message: {:?}", e))?;

            info!("Sending blocklist update transaction...");
            let tx = contract.update_blocklist_with_signatures(signatures, message);
            let pending = tx
                .send()
                .await
                .map_err(|e| anyhow!("Failed to send blocklist tx: {:?}", e))?;
            let receipt = pending
                .await
                .map_err(|e| anyhow!("Failed to get receipt: {:?}", e))?
                .ok_or_else(|| anyhow!("No receipt returned"))?;

            info!(
                "Blocklist update executed successfully!\n  Tx hash: {:?}\n  Block: {:?}\n  Status: {:?}",
                receipt.transaction_hash,
                receipt.block_number,
                receipt.status
            );
        }

        BridgeAction::LimitUpdateAction(limit) => {
            let contract = EthBridgeLimiter::new(
                config.eth_bridge_limiter_proxy_address,
                Arc::new(eth_signer),
            );
            let message: eth_bridge_limiter::Message = limit
                .clone()
                .try_into()
                .map_err(|e| anyhow!("Failed to convert LimitUpdateAction to message: {:?}", e))?;

            info!("Sending limit update transaction...");
            let tx = contract.update_limit_with_signatures(signatures, message);
            let pending = tx
                .send()
                .await
                .map_err(|e| anyhow!("Failed to send limit tx: {:?}", e))?;
            let receipt = pending
                .await
                .map_err(|e| anyhow!("Failed to get receipt: {:?}", e))?
                .ok_or_else(|| anyhow!("No receipt returned"))?;

            info!(
                "Limit update executed successfully!\n  Tx hash: {:?}\n  Block: {:?}\n  Status: {:?}",
                receipt.transaction_hash,
                receipt.block_number,
                receipt.status
            );
        }

        BridgeAction::EvmContractUpgradeAction(upgrade) => {
            use starcoin_bridge::abi::{
                eth_committee_upgradeable_contract, EthCommitteeUpgradeableContract,
            };

            let contract =
                EthCommitteeUpgradeableContract::new(upgrade.proxy_address, Arc::new(eth_signer));
            let message: eth_committee_upgradeable_contract::Message =
                upgrade.clone().try_into().map_err(|e| {
                    anyhow!(
                        "Failed to convert EvmContractUpgradeAction to message: {:?}",
                        e
                    )
                })?;

            info!(
                "Sending EVM contract upgrade transaction...\n  Proxy: {:?}\n  New impl: {:?}",
                upgrade.proxy_address, upgrade.new_impl_address
            );
            let tx = contract.upgrade_with_signatures(signatures, message);
            let pending = tx
                .send()
                .await
                .map_err(|e| anyhow!("Failed to send upgrade tx: {:?}", e))?;
            let receipt = pending
                .await
                .map_err(|e| anyhow!("Failed to get receipt: {:?}", e))?
                .ok_or_else(|| anyhow!("No receipt returned"))?;

            info!(
                "EVM contract upgrade executed successfully!\n  Tx hash: {:?}\n  Block: {:?}\n  Status: {:?}",
                receipt.transaction_hash,
                receipt.block_number,
                receipt.status
            );
        }

        BridgeAction::EvmAddMemberAction(add_member) => {
            let contract = EthBridgeCommittee::new(
                config.eth_bridge_committee_proxy_address,
                Arc::new(eth_signer),
            );
            let message: eth_bridge_committee::Message = add_member
                .clone()
                .try_into()
                .map_err(|e| anyhow!("Failed to convert EvmAddMemberAction to message: {:?}", e))?;

            info!(
                "Sending add member transaction...\n  Member: {:?}\n  Stake: {}",
                add_member.member_address, add_member.stake
            );
            let tx = contract.add_member_with_signatures(signatures, message);
            let pending = tx
                .send()
                .await
                .map_err(|e| anyhow!("Failed to send add member tx: {:?}", e))?;
            let receipt = pending
                .await
                .map_err(|e| anyhow!("Failed to get receipt: {:?}", e))?
                .ok_or_else(|| anyhow!("No receipt returned"))?;

            info!(
                "Add member executed successfully!\n  Tx hash: {:?}\n  Block: {:?}\n  Status: {:?}",
                receipt.transaction_hash, receipt.block_number, receipt.status
            );
        }

        // These actions are not executed on ETH via governance-execute
        _ => {
            return Err(anyhow!(
                "Action type {} is not supported for governance execution on ETH chain",
                action.action_type()
            ));
        }
    }

    Ok(())
}

/// Execute a governance action on Starcoin chain with provided signatures.
/// This function directly interacts with the Starcoin chain, no bridge server involved.
///
/// For `EmergencyAction`: if `config.starcoin_gas_key` is set, use the
/// permissionless entry point (`execute_emergency_op_permissionless`) so that
/// any funded account can submit the pre-signed pause/unpause.  Otherwise fall
/// back to the admin-only `execute_emergency_op_single`.
pub async fn execute_governance_on_starcoin(
    config: &LoadedBridgeCliConfig,
    action: BridgeAction,
    signatures_hex: Vec<String>,
) -> anyhow::Result<()> {
    use starcoin_bridge::simple_starcoin_rpc::SimpleStarcoinRpcClient;
    use starcoin_bridge::starcoin_bridge_transaction_builder::starcoin_native;
    use starcoin_bridge_types::base_types::StarcoinAddress;

    if signatures_hex.is_empty() {
        return Err(anyhow!("No signatures provided"));
    }

    // For now, only support single signature execution
    // Multi-sig would require the contract to support aggregated signature verification
    if signatures_hex.len() > 1 {
        info!("Warning: Multiple signatures provided. Using first signature only for Starcoin execution.");
    }

    let sig_hex = &signatures_hex[0];
    let sig_bytes = Hex::decode(sig_hex.trim_start_matches("0x"))
        .map_err(|e| anyhow!("Failed to decode signature from hex: {:?}", e))?;

    // Decide which key to use as the transaction sender.
    // For EmergencyAction: prefer `starcoin_gas_key` (permissionless entry, any funded account).
    // For all other actions: must use `starcoin_bridge_key` (admin-only entry).
    let use_permissionless = matches!(&action, BridgeAction::EmergencyAction(_))
        && config.starcoin_gas_key.is_some();

    let signing_key = if use_permissionless {
        info!("Using Starcoin gas key for permissionless emergency pause");
        config.starcoin_gas_key.as_ref().unwrap()
    } else {
        &config.starcoin_bridge_key
    };

    info!(
        "Executing governance action on Starcoin:\n  Action type: {}\n  Chain ID: {:?}\n  Nonce: {}\n  Signature length: {} bytes\n  Permissionless: {}",
        action.action_type(),
        action.chain_id(),
        action.seq_number(),
        sig_bytes.len(),
        use_permissionless,
    );

    // Get sender address from the chosen key
    let sender_move_addr = signing_key.starcoin_address();
    let sender = StarcoinAddress::new(sender_move_addr.into());
    let sender_hex = format!("0x{}", Hex::encode(sender.as_ref()));

    // Create RPC client
    let rpc_client = SimpleStarcoinRpcClient::new(
        &config.starcoin_bridge_rpc_url,
        &config.starcoin_bridge_proxy_address,
    );

    // Get sequence number from chain
    let sequence_number = rpc_client
        .get_sequence_number(&sender_hex)
        .await
        .map_err(|e| anyhow!("Failed to get sequence number: {:?}", e))?;

    // Get current block timestamp for transaction expiration
    let block_timestamp_ms = rpc_client
        .get_block_timestamp()
        .await
        .map_err(|e| anyhow!("Failed to get block timestamp: {:?}", e))?;

    // Get chain ID from Starcoin node
    let starcoin_chain_id = rpc_client
        .get_chain_id()
        .await
        .map_err(|e| anyhow!("Failed to get chain ID: {:?}", e))?;

    // Parse module address
    let module_address = {
        let addr_str = config
            .starcoin_bridge_proxy_address
            .trim_start_matches("0x");
        let bytes = Hex::decode(addr_str)
            .map_err(|e| anyhow!("Invalid bridge proxy address hex: {:?}", e))?;
        if bytes.len() != 16 {
            return Err(anyhow!(
                "Bridge proxy address must be 16 bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        StarcoinAddress::new(arr)
    };

    info!(
        "Building Starcoin transaction:\n  Sender: {}\n  Sequence: {}\n  Chain ID: {}",
        sender_hex, sequence_number, starcoin_chain_id
    );

    // Build transaction based on action type
    let raw_txn = match &action {
        BridgeAction::EmergencyAction(emergency) => {
            let source_chain = emergency.chain_id as u8;
            let op_type = emergency.action_type as u8;

            if use_permissionless {
                starcoin_native::build_execute_emergency_op_permissionless(
                    module_address,
                    sender,
                    sequence_number,
                    starcoin_chain_id,
                    block_timestamp_ms,
                    source_chain,
                    emergency.nonce,
                    op_type,
                    sig_bytes,
                )
                .map_err(|e| anyhow!("Failed to build permissionless emergency op transaction: {:?}", e))?
            } else {
                starcoin_native::build_execute_emergency_op(
                    module_address,
                    sender,
                    sequence_number,
                    starcoin_chain_id,
                    block_timestamp_ms,
                    source_chain,
                    emergency.nonce,
                    op_type,
                    sig_bytes,
                )
                .map_err(|e| anyhow!("Failed to build emergency op transaction: {:?}", e))?
            }
        }

        BridgeAction::LimitUpdateAction(limit) => {
            let source_chain = limit.chain_id as u8;
            let sending_chain = limit.sending_chain_id as u8;

            starcoin_native::build_execute_update_limit(
                module_address,
                sender,
                sequence_number,
                starcoin_chain_id,
                block_timestamp_ms,
                source_chain,
                sending_chain,
                limit.nonce,
                limit.new_usd_limit,
                sig_bytes,
            )
            .map_err(|e| anyhow!("Failed to build limit update transaction: {:?}", e))?
        }

        BridgeAction::BlocklistCommitteeAction(blocklist) => {
            let source_chain = blocklist.chain_id as u8;
            let blocklist_type = blocklist.blocklist_type as u8;

            // Convert BridgeAuthorityPublicKeyBytes to ETH addresses (20 bytes each)
            // The Move contract expects ECDSA addresses, not compressed public keys
            let member_eth_addresses: Vec<Vec<u8>> = blocklist
                .members_to_update
                .iter()
                .map(|pubkey| pubkey.to_eth_address().0.to_vec())
                .collect();

            starcoin_native::build_execute_blocklist(
                module_address,
                sender,
                sequence_number,
                starcoin_chain_id,
                block_timestamp_ms,
                source_chain,
                blocklist.nonce,
                blocklist_type,
                member_eth_addresses,
                sig_bytes,
            )
            .map_err(|e| anyhow!("Failed to build blocklist transaction: {:?}", e))?
        }

        BridgeAction::UpdateCommitteeMemberAction(update_member) => {
            let source_chain = update_member.chain_id as u8;
            let update_type = update_member.update_type as u8;
            let http_url_bytes = update_member.http_rest_url.as_bytes().to_vec();

            // Derive member_address from pubkey (first 16 bytes)
            let pubkey_bytes = &update_member.bridge_pubkey_bytes;
            let member_address =
                StarcoinAddress::from_bytes(&pubkey_bytes[..16.min(pubkey_bytes.len())])
                    .unwrap_or(StarcoinAddress::ZERO);

            starcoin_native::build_execute_update_committee_member(
                module_address,
                sender,
                sequence_number,
                starcoin_chain_id,
                block_timestamp_ms,
                source_chain,
                update_member.nonce,
                update_type,
                member_address,
                update_member.bridge_pubkey_bytes.clone(),
                update_member.voting_power,
                http_url_bytes,
                sig_bytes,
            )
            .map_err(|e| {
                anyhow!(
                    "Failed to build update committee member transaction: {:?}",
                    e
                )
            })?
        }

        // These action types are not supported for Starcoin governance-execute
        _ => {
            return Err(anyhow!(
                "Action type {} is not supported for governance execution on Starcoin chain",
                action.action_type()
            ));
        }
    };

    // Sign and submit the transaction using the RPC client
    info!("Signing and submitting transaction to Starcoin...");
    let tx_hash = rpc_client
        .sign_and_submit_transaction(signing_key, raw_txn)
        .await
        .map_err(|e| anyhow!("Failed to sign and submit transaction: {:?}", e))?;

    info!(
        "Governance action executed successfully on Starcoin!\n  Tx hash: {}",
        tx_hash
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::middleware::SignerMiddleware;
    use ethers::providers::{Http, Provider};
    use ethers::signers::{LocalWallet, Signer};
    use fastcrypto::ed25519::Ed25519KeyPair;
    use fastcrypto::traits::KeyPair as KeyPairTrait;

    /// Helper function to create a test LoadedBridgeCliConfig
    fn create_test_config() -> LoadedBridgeCliConfig {
        // Create test keys
        let mut rng = rand::thread_rng();
        let ed25519_kp = Ed25519KeyPair::generate(&mut rng);
        let starcoin_key = StarcoinKeyPair::Ed25519(ed25519_kp);

        // Create a mock EthSigner using a test provider
        let provider = Provider::<Http>::try_from("http://localhost:8545").unwrap();
        let wallet: LocalWallet =
            "0x0000000000000000000000000000000000000000000000000000000000000001"
                .parse()
                .unwrap();
        let eth_signer = SignerMiddleware::new(provider, wallet.with_chain_id(1u64));

        LoadedBridgeCliConfig {
            starcoin_bridge_rpc_url: "http://localhost:9850".to_string(),
            eth_rpc_url: "http://localhost:8545".to_string(),
            starcoin_bridge_proxy_address: "0x00000000000000000000000000000001".to_string(),
            eth_bridge_proxy_address: ethers::types::Address::from_low_u64_be(1),
            eth_bridge_committee_proxy_address: ethers::types::Address::from_low_u64_be(2),
            eth_bridge_limiter_proxy_address: ethers::types::Address::from_low_u64_be(3),
            eth_bridge_config_proxy_address: ethers::types::Address::from_low_u64_be(4),
            starcoin_bridge_key: starcoin_key,
            starcoin_gas_key: None,
            eth_signer,
        }
    }

    /// Test that GovernanceClientCommands has exactly five variants
    #[test]
    fn test_governance_commands_are_exactly_five() {
        // Verify by exhaustive match that we have 5 governance commands
        let verify_exhaustive = |cmd: &GovernanceClientCommands| match cmd {
            GovernanceClientCommands::EmergencyButton { .. } => "emergency",
            GovernanceClientCommands::UpdateCommitteeBlocklist { .. } => "blocklist",
            GovernanceClientCommands::UpdateLimit { .. } => "limit",
            GovernanceClientCommands::UpgradeEvmContract { .. } => "upgrade",
            GovernanceClientCommands::UpdateCommitteeMember { .. } => "update_member",
            GovernanceClientCommands::AddMemberEth { .. } => "add_member_eth",
        };

        // Create one of each command type to verify exhaustive matching
        let emergency = GovernanceClientCommands::EmergencyButton {
            nonce: 1,
            action_type: EmergencyActionType::Pause,
        };
        assert_eq!(verify_exhaustive(&emergency), "emergency");
    }

    /// Test make_action creates correct BridgeAction for EmergencyButton
    #[test]
    fn test_make_action_emergency_button() {
        let cmd = GovernanceClientCommands::EmergencyButton {
            nonce: 42,
            action_type: EmergencyActionType::Pause,
        };
        let action = make_action(BridgeChainId::EthSepolia, &cmd);

        match action {
            BridgeAction::EmergencyAction(e) => {
                assert_eq!(e.nonce, 42);
                assert_eq!(e.chain_id, BridgeChainId::EthSepolia);
                assert_eq!(e.action_type, EmergencyActionType::Pause);
            }
            _ => panic!("Expected EmergencyAction"),
        }
    }

    /// Test make_action creates correct BridgeAction for UpdateLimit
    #[test]
    fn test_make_action_update_limit() {
        let cmd = GovernanceClientCommands::UpdateLimit {
            nonce: 10,
            sending_chain: 11, // EthSepolia
            new_usd_limit: 1_000_000,
        };
        let action = make_action(BridgeChainId::StarcoinTestnet, &cmd);

        match action {
            BridgeAction::LimitUpdateAction(l) => {
                assert_eq!(l.nonce, 10);
                assert_eq!(l.chain_id, BridgeChainId::StarcoinTestnet);
                assert_eq!(l.sending_chain_id, BridgeChainId::EthSepolia);
                assert_eq!(l.new_usd_limit, 1_000_000);
            }
            _ => panic!("Expected LimitUpdateAction"),
        }
    }

    /// Test make_action creates correct BridgeAction for UpdateCommitteeBlocklist
    #[test]
    fn test_make_action_blocklist() {
        use std::str::FromStr;

        // Create a fake pubkey (33 bytes for compressed secp256k1)
        let pubkey_hex = "03".to_owned() + &"aa".repeat(32);
        let pubkey = BridgeAuthorityPublicKeyBytes::from_str(&pubkey_hex).unwrap();

        let cmd = GovernanceClientCommands::UpdateCommitteeBlocklist {
            nonce: 5,
            blocklist_type: BlocklistType::Blocklist,
            pubkeys_hex: vec![pubkey.clone()],
        };
        let action = make_action(BridgeChainId::EthMainnet, &cmd);

        match action {
            BridgeAction::BlocklistCommitteeAction(b) => {
                assert_eq!(b.nonce, 5);
                assert_eq!(b.chain_id, BridgeChainId::EthMainnet);
                assert_eq!(b.blocklist_type, BlocklistType::Blocklist);
                assert_eq!(b.members_to_update.len(), 1);
            }
            _ => panic!("Expected BlocklistCommitteeAction"),
        }
    }

    /// Test select_contract_address returns correct addresses for each command type
    #[test]
    fn test_select_contract_address() {
        let config = create_test_config();

        let emergency_cmd = GovernanceClientCommands::EmergencyButton {
            nonce: 1,
            action_type: EmergencyActionType::Pause,
        };
        let blocklist_cmd = GovernanceClientCommands::UpdateCommitteeBlocklist {
            nonce: 1,
            blocklist_type: BlocklistType::Blocklist,
            pubkeys_hex: vec![],
        };
        let limit_cmd = GovernanceClientCommands::UpdateLimit {
            nonce: 1,
            sending_chain: 11,
            new_usd_limit: 1000,
        };
        let upgrade_proxy = ethers::types::Address::from_low_u64_be(100);
        let upgrade_cmd = GovernanceClientCommands::UpgradeEvmContract {
            nonce: 1,
            proxy_address: upgrade_proxy,
            new_impl_address: ethers::types::Address::from_low_u64_be(200),
            call_data: "".to_string(),
        };

        // EmergencyButton -> eth_bridge_proxy_address
        assert_eq!(
            select_contract_address(&config, &emergency_cmd),
            ethers::types::Address::from_low_u64_be(1)
        );

        // UpdateCommitteeBlocklist -> eth_bridge_committee_proxy_address
        assert_eq!(
            select_contract_address(&config, &blocklist_cmd),
            ethers::types::Address::from_low_u64_be(2)
        );

        // UpdateLimit -> eth_bridge_limiter_proxy_address
        assert_eq!(
            select_contract_address(&config, &limit_cmd),
            ethers::types::Address::from_low_u64_be(3)
        );

        // UpgradeEvmContract -> returns proxy_address from command
        assert_eq!(
            select_contract_address(&config, &upgrade_cmd),
            upgrade_proxy
        );
    }

    /// Test BridgeChainId classification for ETH vs Starcoin
    #[test]
    fn test_bridge_chain_id_classification() {
        // ETH chains
        assert!(!BridgeChainId::EthMainnet.is_starcoin_bridge_chain());
        assert!(!BridgeChainId::EthSepolia.is_starcoin_bridge_chain());
        assert!(!BridgeChainId::EthCustom.is_starcoin_bridge_chain());

        // Starcoin chains
        assert!(BridgeChainId::StarcoinMainnet.is_starcoin_bridge_chain());
        assert!(BridgeChainId::StarcoinTestnet.is_starcoin_bridge_chain());
        assert!(BridgeChainId::StarcoinCustom.is_starcoin_bridge_chain());
    }

    /// Test that chain ID values are as expected
    #[test]
    fn test_chain_id_values() {
        assert_eq!(BridgeChainId::StarcoinMainnet as u8, 0);
        assert_eq!(BridgeChainId::StarcoinTestnet as u8, 1);
        assert_eq!(BridgeChainId::StarcoinCustom as u8, 2);
        assert_eq!(BridgeChainId::EthMainnet as u8, 10);
        assert_eq!(BridgeChainId::EthSepolia as u8, 11);
        assert_eq!(BridgeChainId::EthCustom as u8, 12);
    }

    /// Test all three EmergencyActionTypes work correctly
    #[test]
    fn test_emergency_action_types() {
        for (action_type, expected_value) in [
            (EmergencyActionType::Pause, 0u8),
            (EmergencyActionType::Unpause, 1u8),
        ] {
            let cmd = GovernanceClientCommands::EmergencyButton {
                nonce: 1,
                action_type,
            };
            let action = make_action(BridgeChainId::EthSepolia, &cmd);

            match action {
                BridgeAction::EmergencyAction(e) => {
                    assert_eq!(e.action_type, action_type);
                    assert_eq!(e.action_type as u8, expected_value);
                }
                _ => panic!("Expected EmergencyAction"),
            }
        }
    }

    /// Test both BlocklistTypes work correctly
    #[test]
    fn test_blocklist_types() {
        use std::str::FromStr;
        let pubkey_hex = "03".to_owned() + &"aa".repeat(32);
        let pubkey = BridgeAuthorityPublicKeyBytes::from_str(&pubkey_hex).unwrap();

        for (blocklist_type, expected_value) in [
            (BlocklistType::Blocklist, 0u8),
            (BlocklistType::Unblocklist, 1u8),
        ] {
            let cmd = GovernanceClientCommands::UpdateCommitteeBlocklist {
                nonce: 1,
                blocklist_type,
                pubkeys_hex: vec![pubkey.clone()],
            };
            let action = make_action(BridgeChainId::EthMainnet, &cmd);

            match action {
                BridgeAction::BlocklistCommitteeAction(b) => {
                    assert_eq!(b.blocklist_type, blocklist_type);
                    assert_eq!(b.blocklist_type as u8, expected_value);
                }
                _ => panic!("Expected BlocklistCommitteeAction"),
            }
        }
    }

    /// Test LimitUpdateAction with different chain combinations
    #[test]
    fn test_limit_update_chain_combinations() {
        let test_cases = vec![
            // (target_chain, sending_chain, expected_target, expected_sending)
            (
                BridgeChainId::StarcoinTestnet,
                11u8,
                BridgeChainId::StarcoinTestnet,
                BridgeChainId::EthSepolia,
            ),
            (
                BridgeChainId::EthSepolia,
                1u8,
                BridgeChainId::EthSepolia,
                BridgeChainId::StarcoinTestnet,
            ),
            (
                BridgeChainId::StarcoinMainnet,
                10u8,
                BridgeChainId::StarcoinMainnet,
                BridgeChainId::EthMainnet,
            ),
            (
                BridgeChainId::EthMainnet,
                0u8,
                BridgeChainId::EthMainnet,
                BridgeChainId::StarcoinMainnet,
            ),
        ];

        for (target_chain, sending_chain, expected_target, expected_sending) in test_cases {
            let cmd = GovernanceClientCommands::UpdateLimit {
                nonce: 100,
                sending_chain,
                new_usd_limit: 5_000_000,
            };
            let action = make_action(target_chain, &cmd);

            match action {
                BridgeAction::LimitUpdateAction(l) => {
                    assert_eq!(l.chain_id, expected_target, "Target chain mismatch");
                    assert_eq!(
                        l.sending_chain_id, expected_sending,
                        "Sending chain mismatch"
                    );
                    assert_eq!(l.new_usd_limit, 5_000_000);
                }
                _ => panic!("Expected LimitUpdateAction"),
            }
        }
    }

    /// Test make_action creates correct BridgeAction for UpgradeEvmContract
    #[test]
    fn test_make_action_upgrade_evm_contract() {
        let proxy = ethers::types::Address::from_low_u64_be(100);
        let new_impl = ethers::types::Address::from_low_u64_be(200);

        // Test with empty call_data
        let cmd = GovernanceClientCommands::UpgradeEvmContract {
            nonce: 42,
            proxy_address: proxy,
            new_impl_address: new_impl,
            call_data: "".to_string(),
        };
        let action = make_action(BridgeChainId::EthSepolia, &cmd);

        match action {
            BridgeAction::EvmContractUpgradeAction(u) => {
                assert_eq!(u.nonce, 42);
                assert_eq!(u.chain_id, BridgeChainId::EthSepolia);
                assert_eq!(u.proxy_address, proxy);
                assert_eq!(u.new_impl_address, new_impl);
                assert!(u.call_data.is_empty());
            }
            _ => panic!("Expected EvmContractUpgradeAction"),
        }

        // Test with call_data (hex encoded)
        let cmd_with_data = GovernanceClientCommands::UpgradeEvmContract {
            nonce: 43,
            proxy_address: proxy,
            new_impl_address: new_impl,
            call_data: "deadbeef".to_string(),
        };
        let action_with_data = make_action(BridgeChainId::EthMainnet, &cmd_with_data);

        match action_with_data {
            BridgeAction::EvmContractUpgradeAction(u) => {
                assert_eq!(u.nonce, 43);
                assert_eq!(u.chain_id, BridgeChainId::EthMainnet);
                assert_eq!(u.call_data, vec![0xde, 0xad, 0xbe, 0xef]);
            }
            _ => panic!("Expected EvmContractUpgradeAction"),
        }

        // Test with 0x prefix
        let cmd_with_0x = GovernanceClientCommands::UpgradeEvmContract {
            nonce: 44,
            proxy_address: proxy,
            new_impl_address: new_impl,
            call_data: "0xcafe".to_string(),
        };
        let action_0x = make_action(BridgeChainId::EthCustom, &cmd_with_0x);

        match action_0x {
            BridgeAction::EvmContractUpgradeAction(u) => {
                assert_eq!(u.call_data, vec![0xca, 0xfe]);
            }
            _ => panic!("Expected EvmContractUpgradeAction"),
        }
    }

    /// Test make_action creates correct BridgeAction for UpdateCommitteeMember
    #[test]
    fn test_make_action_update_committee_member() {
        // Test adding a member
        let cmd = GovernanceClientCommands::UpdateCommitteeMember {
            nonce: 100,
            update_type: UpdateCommitteeMemberType::Add,
            pubkey_hex: "02aabbccdd".to_string(), // simplified pubkey for test
            voting_power: 5000,
            http_rest_url: "http://127.0.0.1:9191".to_string(),
        };
        let action = make_action(BridgeChainId::StarcoinTestnet, &cmd);

        match action {
            BridgeAction::UpdateCommitteeMemberAction(u) => {
                assert_eq!(u.nonce, 100);
                assert_eq!(u.chain_id, BridgeChainId::StarcoinTestnet);
                assert_eq!(u.update_type, UpdateCommitteeMemberType::Add);
                assert_eq!(u.voting_power, 5000);
                assert_eq!(u.http_rest_url, "http://127.0.0.1:9191");
            }
            _ => panic!("Expected UpdateCommitteeMemberAction"),
        }

        // Test removing a member
        let cmd_remove = GovernanceClientCommands::UpdateCommitteeMember {
            nonce: 101,
            update_type: UpdateCommitteeMemberType::Remove,
            pubkey_hex: "0x03aabbccdd".to_string(),
            voting_power: 0,
            http_rest_url: "".to_string(),
        };
        let action_remove = make_action(BridgeChainId::StarcoinCustom, &cmd_remove);

        match action_remove {
            BridgeAction::UpdateCommitteeMemberAction(u) => {
                assert_eq!(u.nonce, 101);
                assert_eq!(u.update_type, UpdateCommitteeMemberType::Remove);
            }
            _ => panic!("Expected UpdateCommitteeMemberAction"),
        }
    }
}
