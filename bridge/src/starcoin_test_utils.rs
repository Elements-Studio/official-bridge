// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Starcoin test utilities for bridge deployment
//!
//! This module provides reusable utilities for testing Starcoin bridge deployment:
//! - Loading Move config and contract packages
//! - Building deployment transactions
//! - Creating test fixtures
//! - Flexible committee configuration for E2E testing

use crate::abi::EthStarcoinBridge;
use anyhow::{Context, Result};
use ethers::providers::{Http, Provider};
use ethers::types::Address;
use fastcrypto::traits::EncodeDecodeBase64;
use once_cell::sync::Lazy;
use starcoin_config::ChainNetwork;
use starcoin_crypto::ed25519::Ed25519PrivateKey;
use starcoin_crypto::ValidCryptoMaterialStringExt;
use starcoin_transaction_builder::{
    create_signed_txn_with_association_account, DEFAULT_MAX_GAS_AMOUNT,
};
use starcoin_txpool_api::TxPoolSyncService;
use starcoin_types::account::Account;
use starcoin_types::account_address::AccountAddress;
use starcoin_types::account_config::{core_code_address, stc_type_tag};
use starcoin_vm_types::identifier::Identifier;
use starcoin_vm_types::language_storage::ModuleId;
use starcoin_vm_types::transaction::authenticator::{AccountPrivateKey, AccountPublicKey};
use starcoin_vm_types::transaction::{
    Package, RawUserTransaction, ScriptFunction, SignedUserTransaction, TransactionPayload,
};
use std::fs;
use std::process::Command;
use std::sync::Arc;
use std::sync::Once;
use std::time::{Duration, Instant};

use crate::e2e_tests::anvil_test_utils::*;

pub const DEFAULT_CONFIG_PATH: &str = "../contracts/move/embeded-node-constant-blob/config.json";
pub const DEFAULT_BLOB_PATH: &str =
    "../contracts/move/embeded-node-constant-blob/Stc-Bridge-Move.v0.0.1.blob";
pub const BUILD_SCRIPT_PATH: &str = "../contracts/move/build_embedded_blob.sh";

/// Ensures the embedded blob is built before any tests run
static BLOB_INIT: Lazy<Result<(), String>> = Lazy::new(build_embedded_blob_internal);

static BLOB_BUILD_ONCE: Once = Once::new();

/// Build the embedded blob file by running the build script
/// This is called automatically before tests that need the blob
fn build_embedded_blob_internal() -> Result<(), String> {
    // By default, compilation is handled by external scripts.
    // For long-form E2E tests that require Move changes, allow opting in to a local rebuild.
    let enabled = std::env::var("STARCOIN_BRIDGE_E2E_BUILD_BLOB")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !enabled {
        return Ok(());
    }

    let script_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(BUILD_SCRIPT_PATH);
    if !script_path.exists() {
        return Err(format!("build script not found: {:?}", script_path));
    }

    BLOB_BUILD_ONCE.call_once(|| {
        let status = Command::new(&script_path).status().unwrap_or_else(|e| {
            panic!("Failed to execute Move build script {:?}: {e}", script_path)
        });
        if !status.success() {
            panic!(
                "Move build script {:?} failed with status {:?}",
                script_path,
                status.code()
            );
        }
    });

    Ok(())
}

/// Ensure the embedded blob is ready for use
/// Call this at the start of any test that needs the blob file
pub fn ensure_blob_ready() -> Result<()> {
    BLOB_INIT.as_ref().map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(())
}

pub const DEV_CHAIN_ID: u8 = 254;

/// Committee member configuration for bridge deployment
#[derive(Clone, Debug)]
pub struct CommitteeMemberConfig {
    /// Starcoin address that identifies this committee member in the Move committee.
    pub validator_address: AccountAddress,
    /// 33-byte compressed secp256k1 public key
    pub bridge_pubkey_bytes: Vec<u8>,
    /// HTTP REST URL for the bridge node
    pub http_rest_url: String,
    /// Voting power (scale of 10000 = 100%)
    pub voting_power: u64,
}

impl CommitteeMemberConfig {
    pub fn new(
        validator_address: AccountAddress,
        bridge_pubkey_bytes: Vec<u8>,
        http_rest_url: &str,
        voting_power: u64,
    ) -> Self {
        Self {
            validator_address,
            bridge_pubkey_bytes,
            http_rest_url: http_rest_url.to_string(),
            voting_power,
        }
    }

    /// Create from hex-encoded public key
    pub fn from_hex(
        validator_address: AccountAddress,
        pubkey_hex: &str,
        http_rest_url: &str,
        voting_power: u64,
    ) -> Result<Self> {
        let pubkey_hex = pubkey_hex.trim_start_matches("0x");
        let pubkey_bytes = hex::decode(pubkey_hex).context("Failed to decode public key hex")?;
        // For committee registration, we need 33-byte compressed key
        let compressed = if pubkey_bytes.len() == 65 {
            // Uncompressed key with 0x04 prefix or 65-byte raw - compress it
            Self::compress_pubkey(&pubkey_bytes)?
        } else if pubkey_bytes.len() == 64 {
            // 64-byte raw key without prefix - add 0x04 and compress
            let mut with_prefix = vec![0x04];
            with_prefix.extend_from_slice(&pubkey_bytes);
            Self::compress_pubkey(&with_prefix)?
        } else if pubkey_bytes.len() == 33 {
            pubkey_bytes
        } else {
            anyhow::bail!(
                "Invalid public key length: {} (expected 33, 64, or 65)",
                pubkey_bytes.len()
            );
        };
        Ok(Self::new(
            validator_address,
            compressed,
            http_rest_url,
            voting_power,
        ))
    }

    /// Compress a 65-byte uncompressed public key to 33-byte compressed
    fn compress_pubkey(uncompressed: &[u8]) -> Result<Vec<u8>> {
        if uncompressed.len() != 65 {
            anyhow::bail!("Expected 65-byte uncompressed key");
        }
        // First byte should be 0x04
        if uncompressed[0] != 0x04 {
            anyhow::bail!("Uncompressed key should start with 0x04");
        }
        // X coordinate is bytes 1-32, Y coordinate is bytes 33-64
        let y_last_byte = uncompressed[64];
        let prefix = if y_last_byte % 2 == 0 { 0x02 } else { 0x03 };
        let mut compressed = vec![prefix];
        compressed.extend_from_slice(&uncompressed[1..33]);
        Ok(compressed)
    }
}

/// Committee configuration for bridge deployment
#[derive(Clone, Debug)]
pub struct CommitteeConfig {
    /// List of committee members
    pub members: Vec<CommitteeMemberConfig>,
    /// Minimum stake participation percentage (scale of 10000)
    pub min_stake_percentage: u64,
    /// Epoch number
    pub epoch: u64,
}

impl CommitteeConfig {
    pub fn new(members: Vec<CommitteeMemberConfig>, min_stake_percentage: u64, epoch: u64) -> Self {
        Self {
            members,
            min_stake_percentage,
            epoch,
        }
    }

    /// Create a single-member committee (for simple testing)
    pub fn single_member(
        validator_address: AccountAddress,
        pubkey_bytes: Vec<u8>,
        url: &str,
        voting_power: u64,
    ) -> Self {
        Self {
            members: vec![CommitteeMemberConfig::new(
                validator_address,
                pubkey_bytes,
                url,
                voting_power,
            )],
            min_stake_percentage: 5000, // 50%
            epoch: 0,
        }
    }

    /// Create a 3-member committee with 2-of-3 threshold (for multi-validator testing)
    ///
    /// Each validator has voting power 3334, totaling 10002 (slightly over 10000).
    /// With TOKEN_TRANSFER_THRESHOLD = 3334 and GOVERNANCE_THRESHOLD = 5001,
    /// 2 validators (6668) can approve token transfers,
    /// and 2 validators (6668) can perform governance actions.
    ///
    /// Each validator needs a unique address to avoid SimpleMap key collision.
    /// `server_ports` specifies the HTTP port for each validator's bridge server.
    pub fn three_member_two_of_three(
        validator_addresses: [AccountAddress; 3],
        pubkeys: [Vec<u8>; 3],
        server_ports: [u16; 3],
    ) -> Self {
        Self {
            members: vec![
                CommitteeMemberConfig::new(
                    validator_addresses[0],
                    pubkeys[0].clone(),
                    &format!("http://127.0.0.1:{}", server_ports[0]),
                    3334,
                ),
                CommitteeMemberConfig::new(
                    validator_addresses[1],
                    pubkeys[1].clone(),
                    &format!("http://127.0.0.1:{}", server_ports[1]),
                    3333,
                ),
                CommitteeMemberConfig::new(
                    validator_addresses[2],
                    pubkeys[2].clone(),
                    &format!("http://127.0.0.1:{}", server_ports[2]),
                    3333,
                ),
            ],
            min_stake_percentage: 5000, // 50%
            epoch: 0,
        }
    }

    /// Generate deterministic validator addresses for testing
    /// Uses simple addresses 0x1001, 0x1002, 0x1003 for validators
    pub fn generate_test_validator_addresses() -> [AccountAddress; 3] {
        [
            AccountAddress::from_hex_literal("0x1001").expect("valid address"),
            AccountAddress::from_hex_literal("0x1002").expect("valid address"),
            AccountAddress::from_hex_literal("0x1003").expect("valid address"),
        ]
    }

    /// Total voting power of all members
    pub fn total_voting_power(&self) -> u64 {
        self.members.iter().map(|m| m.voting_power).sum()
    }
}

/// Move contract configuration
#[derive(serde::Deserialize, Clone, Debug)]
pub struct MoveConfig {
    pub address: String,
    pub public_key: String,
    pub private_key: String,
}

impl MoveConfig {
    /// Load config from default path
    pub fn load() -> Result<Self> {
        Self::load_from(DEFAULT_CONFIG_PATH)
    }

    /// Load config from specific path
    pub fn load_from(path: &str) -> Result<Self> {
        let config_content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config from {}", path))?;
        serde_json::from_str(&config_content).context("Failed to parse config.json")
    }

    /// Parse address from config
    pub fn address(&self) -> Result<AccountAddress> {
        AccountAddress::from_hex_literal(&self.address)
            .context("Failed to parse address from config")
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        let pubkey_hex = self.public_key.trim_start_matches("0x");
        hex::decode(pubkey_hex).context("Failed to decode public key")
    }

    /// Get private key bytes
    pub fn private_key_bytes(&self) -> Result<Vec<u8>> {
        let privkey_hex = self.private_key.trim_start_matches("0x");
        hex::decode(privkey_hex).context("Failed to decode private key")
    }

    /// Create an Account from this config
    pub fn to_account(&self) -> Result<Account> {
        let privkey_hex = self.private_key.trim_start_matches("0x");
        let privkey = Ed25519PrivateKey::from_encoded_string(privkey_hex)
            .context("Failed to parse Ed25519 private key")?;
        let pubkey = (&privkey).into();
        let account_privkey = AccountPrivateKey::Single(privkey);
        let account_pubkey = AccountPublicKey::Single(pubkey);
        let address = self.address()?;
        Ok(Account::with_keypair(
            account_privkey,
            account_pubkey,
            Some(address),
        ))
    }
}

/// Load Move package from blob file
pub fn load_package() -> Result<Package> {
    load_package_from(DEFAULT_BLOB_PATH)
}

/// Load Move package from specific blob file
pub fn load_package_from(path: &str) -> Result<Package> {
    let blob_content =
        fs::read(path).with_context(|| format!("Failed to read blob from {}", path))?;
    bcs_ext::from_bytes(&blob_content).context("Failed to deserialize Package from blob")
}

/// Generate a test secp256k1 compressed public key (33 bytes)
/// Format: 0x02 or 0x03 prefix + 32-byte X coordinate
/// This is a valid compressed secp256k1 public key format that the Move contract expects.
pub fn generate_test_secp256k1_compressed_pubkey() -> Vec<u8> {
    generate_test_secp256k1_compressed_pubkey_with_seed(0)
}

/// Generate a test secp256k1 compressed public key with a specific seed
/// Different seeds produce different keys for multi-validator testing
pub fn generate_test_secp256k1_compressed_pubkey_with_seed(seed: u8) -> Vec<u8> {
    // Use a deterministic test key for reproducibility
    // This is NOT a real key - just for testing purposes
    let mut pubkey = vec![0x02]; // Even Y coordinate prefix

    // Base X coordinate
    let mut x_coord: [u8; 32] = [
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
        0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8,
        0x17, 0x98,
    ];

    // Modify last byte based on seed to create different keys
    x_coord[31] = x_coord[31].wrapping_add(seed);

    pubkey.extend_from_slice(&x_coord);
    pubkey
}

/// Generate multiple test secp256k1 compressed public keys
pub fn generate_test_secp256k1_compressed_pubkeys(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| generate_test_secp256k1_compressed_pubkey_with_seed(i as u8))
        .collect()
}

/// Create a ScriptFunction call for the bridge
pub fn create_bridge_script_function(
    bridge_address: AccountAddress,
    function_name: &str,
    ty_args: Vec<starcoin_vm_types::language_storage::TypeTag>,
    args: Vec<Vec<u8>>,
) -> ScriptFunction {
    ScriptFunction::new(
        ModuleId::new(bridge_address, Identifier::new("Bridge").unwrap()),
        Identifier::new(function_name).unwrap(),
        ty_args,
        args,
    )
}

/// Builder for creating bridge deployment transactions
pub struct BridgeDeploymentBuilder {
    config: MoveConfig,
    package: Package,
    network: ChainNetwork,
    bridge_account: Account,
    sequence_number: u64,
    association_sequence_number: u64,
}

/// Initial amount to fund the bridge account (10 STC = 10 * 10^9 nano STC)
const BRIDGE_ACCOUNT_INITIAL_AMOUNT: u128 = 10_000_000_000_000;

impl BridgeDeploymentBuilder {
    /// Create a new builder with default config and blob
    pub fn new() -> Result<Self> {
        Self::with_paths(DEFAULT_CONFIG_PATH, DEFAULT_BLOB_PATH)
    }

    /// Create a new builder with custom paths
    pub fn with_paths(config_path: &str, blob_path: &str) -> Result<Self> {
        let config = MoveConfig::load_from(config_path)?;
        let package = load_package_from(blob_path)?;
        let network = ChainNetwork::new_builtin(starcoin_config::BuiltinNetworkID::Dev);
        let bridge_account = config.to_account()?;

        Ok(Self {
            config,
            package,
            network,
            bridge_account,
            sequence_number: 0,
            association_sequence_number: 0,
        })
    }

    /// Set the network for signing transactions
    ///
    /// This is important when deploying to an embedded node, as the network
    /// must match the node's chain ID.
    pub fn with_network(mut self, network: ChainNetwork) -> Self {
        self.network = network;
        self
    }

    /// Get the bridge address
    pub fn bridge_address(&self) -> Result<AccountAddress> {
        self.config.address()
    }

    /// Get the Move config
    pub fn config(&self) -> &MoveConfig {
        &self.config
    }

    /// Get the network
    pub fn network(&self) -> &ChainNetwork {
        &self.network
    }

    /// Get the bridge account
    pub fn bridge_account(&self) -> &Account {
        &self.bridge_account
    }

    /// Build transaction to create and fund the bridge account
    /// This must be executed first before any other transactions
    pub fn build_create_bridge_account_transaction(&mut self) -> Result<SignedUserTransaction> {
        let args = vec![
            bcs_ext::to_bytes(self.bridge_account.address())?,
            bcs_ext::to_bytes(&self.bridge_account.auth_key().to_vec())?,
            bcs_ext::to_bytes(&BRIDGE_ACCOUNT_INITIAL_AMOUNT)?,
        ];

        let txn = create_signed_txn_with_association_account(
            TransactionPayload::ScriptFunction(ScriptFunction::new(
                ModuleId::new(core_code_address(), Identifier::new("Account").unwrap()),
                Identifier::new("create_account_with_initial_amount").unwrap(),
                vec![stc_type_tag()],
                args,
            )),
            self.association_sequence_number,
            DEFAULT_MAX_GAS_AMOUNT,
            1,
            3600,
            &self.network,
        );
        self.association_sequence_number += 1;
        Ok(txn)
    }

    /// Create a signed transaction with the bridge account
    fn sign_with_bridge_account(&mut self, payload: TransactionPayload) -> SignedUserTransaction {
        let raw_txn = RawUserTransaction::new_with_default_gas_token(
            *self.bridge_account.address(),
            self.sequence_number,
            payload,
            DEFAULT_MAX_GAS_AMOUNT,
            1,
            3600,
            self.network.chain_id(),
        );
        self.sequence_number += 1;
        self.bridge_account.sign_txn(raw_txn)
    }

    /// Build deploy transaction (signed by bridge account)
    pub fn build_deploy_transaction(&mut self) -> Result<SignedUserTransaction> {
        let payload = TransactionPayload::Package(self.package.clone());
        Ok(self.sign_with_bridge_account(payload))
    }

    /// Build initialize bridge transaction (signed by bridge account)
    pub fn build_initialize_transaction(&mut self) -> Result<SignedUserTransaction> {
        let bridge_address = self.bridge_address()?;
        let args = vec![bcs_ext::to_bytes(&DEV_CHAIN_ID)?];
        let script =
            create_bridge_script_function(bridge_address, "initialize_bridge", vec![], args);
        Ok(self.sign_with_bridge_account(TransactionPayload::ScriptFunction(script)))
    }

    /// Build register committee member transaction (signed by bridge account)
    ///
    /// Note: This uses a test secp256k1 compressed public key (33 bytes).
    /// The Move contract expects a 33-byte compressed secp256k1 public key,
    /// not an Ed25519 key.
    pub fn build_register_committee_transaction(
        &mut self,
        url: &str,
    ) -> Result<SignedUserTransaction> {
        // Use a valid test secp256k1 compressed public key (33 bytes)
        // Format: 0x02 or 0x03 prefix + 32-byte X coordinate
        let test_secp256k1_pubkey = generate_test_secp256k1_compressed_pubkey();
        self.build_register_committee_member_with_pubkey(&test_secp256k1_pubkey, url)
    }

    /// Build create committee transaction (signed by bridge account)
    pub fn build_create_committee_transaction(
        &mut self,
        validator_address: AccountAddress,
        voting_power: u64,
        min_stake_percentage: u64,
        epoch: u64,
    ) -> Result<SignedUserTransaction> {
        let bridge_address = self.bridge_address()?;

        let args = vec![
            bcs_ext::to_bytes(&validator_address)?,
            bcs_ext::to_bytes(&voting_power)?,
            bcs_ext::to_bytes(&min_stake_percentage)?,
            bcs_ext::to_bytes(&epoch)?,
        ];
        let script =
            create_bridge_script_function(bridge_address, "create_committee", vec![], args);
        Ok(self.sign_with_bridge_account(TransactionPayload::ScriptFunction(script)))
    }

    /// Build add_allowed_registrant transaction (signed by bridge account)
    ///
    /// This adds an address to the whitelist of addresses allowed to register
    /// as committee members. Only the Bridge admin can call this.
    pub fn build_add_allowed_registrant_transaction(
        &mut self,
        addr: AccountAddress,
    ) -> Result<SignedUserTransaction> {
        let bridge_address = self.bridge_address()?;
        let args = vec![bcs_ext::to_bytes(&addr)?];
        let script =
            create_bridge_script_function(bridge_address, "add_allowed_registrant", vec![], args);
        Ok(self.sign_with_bridge_account(TransactionPayload::ScriptFunction(script)))
    }

    /// Build token setup transaction (signed by bridge account)
    pub fn build_setup_token_transaction(
        &mut self,
        token_name: &str,
    ) -> Result<SignedUserTransaction> {
        let bridge_address = self.bridge_address()?;
        let function_name = format!("setup_{}_token", token_name.to_lowercase());

        let script = create_bridge_script_function(bridge_address, &function_name, vec![], vec![]);
        Ok(self.sign_with_bridge_account(TransactionPayload::ScriptFunction(script)))
    }

    /// Build all deployment transactions in order
    /// Returns: (create_account_txn, deployment_txns)
    /// The create_account_txn must be executed first to fund the bridge account
    pub fn build_all_transactions(&mut self) -> Result<Vec<SignedUserTransaction>> {
        let bridge_address = self.bridge_address()?;
        let transactions = vec![
            // 0. Create and fund bridge account (signed by association)
            self.build_create_bridge_account_transaction()?,
            // 1. Deploy
            self.build_deploy_transaction()?,
            // 2. Initialize
            self.build_initialize_transaction()?,
            // 3. Register committee
            self.build_register_committee_transaction("http://127.0.0.1:9191")?,
            // 4. Create committee
            self.build_create_committee_transaction(bridge_address, 10000, 5000, 0)?,
            // 5-8. Setup tokens
            self.build_setup_token_transaction("eth")?,
            self.build_setup_token_transaction("btc")?,
            self.build_setup_token_transaction("usdc")?,
            self.build_setup_token_transaction("usdt")?,
        ];

        Ok(transactions)
    }

    /// Build deployment transactions with custom committee configuration
    ///
    /// This allows deploying the bridge with an arbitrary committee setup.
    /// Now supports multi-member committees using the whitelist mechanism:
    /// 1. Add all member addresses to the allowed registrants whitelist
    /// 2. Register each member with their public key
    /// 3. Create committee with all members
    ///
    /// Note: In embedded test mode, all transactions are signed by Bridge account.
    /// Each validator needs a unique address in the whitelist to avoid SimpleMap key collision.
    pub fn build_transactions_with_committee(
        &mut self,
        committee_config: &CommitteeConfig,
    ) -> Result<Vec<SignedUserTransaction>> {
        let mut transactions = Vec::new();
        let bridge_address = self.bridge_address()?;

        // 0. Create and fund bridge account (signed by association)
        transactions.push(self.build_create_bridge_account_transaction()?);

        // 1. Deploy
        transactions.push(self.build_deploy_transaction()?);

        // 2. Initialize (this also initializes AllowedRegistrants with @Bridge)
        transactions.push(self.build_initialize_transaction()?);

        // 3. For multi-member committee, we need to:
        //    a) Add each unique validator address to the whitelist (except bridge_address which is already added)
        //    b) Register each member with their unique address using register_committee_member_for_address

        // Collect unique validator addresses that need to be whitelisted
        let mut seen_addresses = std::collections::HashSet::new();
        seen_addresses.insert(bridge_address); // bridge_address is already in whitelist

        for member in &committee_config.members {
            if !seen_addresses.contains(&member.validator_address) {
                // Add this validator address to the whitelist
                transactions
                    .push(self.build_add_allowed_registrant_transaction(member.validator_address)?);
                seen_addresses.insert(member.validator_address);
            }
        }

        // 4. Register each member using their unique address
        for member in &committee_config.members {
            // Use the new function that allows specifying validator_address explicitly
            transactions.push(
                self.build_register_committee_member_for_address_transaction(
                    member.validator_address,
                    &member.bridge_pubkey_bytes,
                    &member.http_rest_url,
                )?,
            );
        }

        // 5. Create committee with all validators and their voting powers
        //    For multi-member, we use build_create_committee_multi_transaction
        transactions.push(self.build_create_committee_multi_transaction(
            &committee_config.members,
            committee_config.min_stake_percentage,
            committee_config.epoch,
        )?);

        // 6. Setup tokens
        for token in ["eth", "btc", "usdc", "usdt"] {
            transactions.push(self.build_setup_token_transaction(token)?);
        }

        Ok(transactions)
    }

    /// Build create committee transaction for multiple validators
    pub fn build_create_committee_multi_transaction(
        &mut self,
        members: &[CommitteeMemberConfig],
        min_stake_percentage: u64,
        epoch: u64,
    ) -> Result<SignedUserTransaction> {
        let bridge_address = self.bridge_address()?;

        // Build validator addresses and voting powers as vectors
        let addresses: Vec<AccountAddress> = members.iter().map(|m| m.validator_address).collect();
        let voting_powers: Vec<u64> = members.iter().map(|m| m.voting_power).collect();

        let args = vec![
            bcs_ext::to_bytes(&addresses)?,
            bcs_ext::to_bytes(&voting_powers)?,
            bcs_ext::to_bytes(&min_stake_percentage)?,
            bcs_ext::to_bytes(&epoch)?,
        ];
        let script =
            create_bridge_script_function(bridge_address, "create_committee_multi", vec![], args);
        Ok(self.sign_with_bridge_account(TransactionPayload::ScriptFunction(script)))
    }

    /// Build register committee member transaction with specific public key (signed by bridge account)
    pub fn build_register_committee_member_with_pubkey(
        &mut self,
        pubkey_bytes: &[u8],
        url: &str,
    ) -> Result<SignedUserTransaction> {
        let bridge_address = self.bridge_address()?;
        let url_bytes = url.as_bytes().to_vec();

        let args = vec![
            bcs_ext::to_bytes(&pubkey_bytes.to_vec())?,
            bcs_ext::to_bytes(&url_bytes)?,
        ];
        let script = create_bridge_script_function(
            bridge_address,
            "register_committee_member",
            vec![],
            args,
        );
        Ok(self.sign_with_bridge_account(TransactionPayload::ScriptFunction(script)))
    }

    /// Build register committee member for a specific validator address (signed by bridge admin)
    ///
    /// This allows the bridge admin to register multiple validators with unique addresses,
    /// avoiding SimpleMap key collision in the Committee's member_registrations.
    pub fn build_register_committee_member_for_address_transaction(
        &mut self,
        validator_address: AccountAddress,
        pubkey_bytes: &[u8],
        url: &str,
    ) -> Result<SignedUserTransaction> {
        let bridge_address = self.bridge_address()?;
        let url_bytes = url.as_bytes().to_vec();

        let args = vec![
            bcs_ext::to_bytes(&validator_address)?,
            bcs_ext::to_bytes(&pubkey_bytes.to_vec())?,
            bcs_ext::to_bytes(&url_bytes)?,
        ];
        let script = create_bridge_script_function(
            bridge_address,
            "register_committee_member_for_address",
            vec![],
            args,
        );
        Ok(self.sign_with_bridge_account(TransactionPayload::ScriptFunction(script)))
    }
}

impl Default for BridgeDeploymentBuilder {
    fn default() -> Self {
        Self::new().expect("Failed to create default BridgeDeploymentBuilder")
    }
}

/// Embedded Starcoin node for testing
///
/// This manages a Starcoin node running in memory for testing.
/// The node is automatically started and stopped.
/// It uses internal services (TxPool, Chain, Storage) directly instead of RPC.
pub struct EmbeddedStarcoinNode {
    handle: starcoin_test_helper::NodeHandle,
}

impl EmbeddedStarcoinNode {
    /// Start a new embedded Starcoin dev node
    ///
    /// The node will automatically choose random available ports for RPC.
    /// Multiple nodes can be started simultaneously without port conflicts.
    pub fn start() -> Result<Self> {
        use std::num::NonZeroU32;

        let mut config = starcoin_config::NodeConfig::random_for_test();

        // Increase RPC concurrency for tests. Multiple bridge servers / validators will poll
        // the embedded node concurrently; low HTTP worker counts can lead to connection churn.
        let base_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(8);
        config.rpc.http.threads = Some(std::cmp::max(16, base_threads * 4));

        // Disable rate limiting for tests - set very high quotas to prevent
        // "connection reset by peer" errors when multiple bridge servers poll simultaneously
        let high_quota = starcoin_config::ApiQuotaConfig {
            max_burst: NonZeroU32::new(1_000_000).expect("NonZeroU32"),
            duration: starcoin_config::QuotaDuration::Second,
        };
        config.rpc.api_quotas.default_global_api_quota = Some(high_quota.clone());
        config.rpc.api_quotas.default_user_api_quota = Some(high_quota);

        let config = std::sync::Arc::new(config);

        let handle = starcoin_test_helper::run_node_by_config(config)
            .context("Failed to start embedded Starcoin node")?;

        let node = Self { handle };

        // Wait until core services are responsive. A fixed sleep is flaky under load.
        // Increased from 15s to 30s for better reliability under CI load.
        node.generate_block_with_retry(Duration::from_secs(30))
            .context("Starcoin node did not become ready in time")?;

        Ok(node)
    }

    /// Get the node handle for direct service access
    pub fn handle(&self) -> &starcoin_test_helper::NodeHandle {
        &self.handle
    }

    /// Get the node config
    pub fn config(&self) -> std::sync::Arc<starcoin_config::NodeConfig> {
        self.handle.config()
    }

    /// Get the network
    pub fn network(&self) -> ChainNetwork {
        self.handle.config().net().clone()
    }

    /// Submit a transaction directly to the node (no RPC needed)
    pub fn submit_transaction(&self, txn: SignedUserTransaction) -> Result<()> {
        // Access txpool service through the handle
        let txpool = self.handle.txpool();
        let results = txpool.add_txns(vec![txn]);

        // Check if any transaction failed
        for (i, result) in results.into_iter().enumerate() {
            result.map_err(|e| anyhow::anyhow!("Transaction {} failed: {:?}", i, e))?;
        }
        Ok(())
    }

    /// Generate a block (for testing)
    pub fn generate_block(&self) -> Result<starcoin_types::block::Block> {
        self.handle.generate_block()
    }

    /// Generate a block with retries (handles transient startup / bus disconnect races).
    pub fn generate_block_with_retry(
        &self,
        max_wait: Duration,
    ) -> Result<starcoin_types::block::Block> {
        let start = Instant::now();
        let mut delay = Duration::from_millis(100);
        let mut last_err: Option<anyhow::Error> = None;

        while start.elapsed() < max_wait {
            match self.handle.generate_block() {
                Ok(block) => return Ok(block),
                Err(e) => {
                    last_err = Some(e);
                    tracing::debug!(
                        "generate_block failed; retrying in {:?} (elapsed {:?})",
                        delay,
                        start.elapsed()
                    );
                    std::thread::sleep(delay);
                    delay = std::cmp::min(delay.saturating_mul(2), Duration::from_secs(1));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("generate_block timed out")))
            .with_context(|| format!("Wait timeout for generate_block (max_wait={:?})", max_wait))
    }

    /// Get the RPC service
    pub fn rpc_service(
        &self,
    ) -> Result<starcoin_service_registry::ServiceRef<starcoin_rpc_server::service::RpcService>>
    {
        self.handle.rpc_service()
    }

    /// Stop the embedded node gracefully
    pub fn stop(self) {
        // Just drop - the handle's Drop impl will clean up
        drop(self.handle);
    }
}

/// Complete test environment with embedded Starcoin node and deployed bridge
pub struct StarcoinBridgeTestEnv {
    pub node: EmbeddedStarcoinNode,
    pub config: MoveConfig,
    pub bridge_address: AccountAddress,
    pub committee_config: Option<CommitteeConfig>,
}

impl StarcoinBridgeTestEnv {
    /// Create and initialize a complete test environment
    ///
    /// This will:
    /// 1. Start an embedded Starcoin node
    /// 2. Deploy the bridge contract
    /// 3. Initialize the bridge
    /// 4. Set up committee and tokens
    pub fn new() -> Result<Self> {
        let node = EmbeddedStarcoinNode::start()?;
        let config = MoveConfig::load()?;
        let bridge_address = config.address()?;

        tracing::debug!("Starting Starcoin bridge test environment...");
        tracing::debug!("  Network: {:?}", node.network().id());
        tracing::debug!("  Bridge address: {:?}", bridge_address);

        Ok(Self {
            node,
            config,
            bridge_address,
            committee_config: None,
        })
    }

    /// Create and fully deploy the bridge with default single-member committee
    pub fn new_with_deployment() -> Result<Self> {
        let mut env = Self::new()?;
        env.deploy_bridge_default()?;
        Ok(env)
    }

    /// Create a Starcoin-only test environment (embedded Starcoin + deployed Move modules)
    pub fn new_with_starcoin_only() -> Result<Self> {
        Self::new_with_deployment()
    }

    /// Create and fully deploy the bridge with custom committee configuration
    ///
    /// # Arguments
    /// * `committee_config` - Configuration for the committee members
    ///
    /// # Example
    /// ```ignore
    /// let members = vec![
    ///     CommitteeMemberConfig::from_hex(pubkey1_hex, "http://node1:9191", 3334)?,
    ///     CommitteeMemberConfig::from_hex(pubkey2_hex, "http://node2:9191", 3333)?,
    ///     CommitteeMemberConfig::from_hex(pubkey3_hex, "http://node3:9191", 3333)?,
    /// ];
    /// let config = CommitteeConfig::new(members, 5000, 0);
    /// let env = StarcoinBridgeTestEnv::new_with_committee(config)?;
    /// ```
    pub fn new_with_committee(committee_config: CommitteeConfig) -> Result<Self> {
        let mut env = Self::new()?;
        env.deploy_bridge_with_committee(&committee_config)?;
        env.committee_config = Some(committee_config);
        Ok(env)
    }

    /// Deploy the bridge contract with default configuration
    fn deploy_bridge_default(&mut self) -> Result<()> {
        let mut builder = BridgeDeploymentBuilder::new()?.with_network(self.node.network());

        tracing::debug!("Deploying bridge contracts (default configuration)...");

        let transactions = builder.build_all_transactions()?;
        self.submit_and_confirm_transactions(&transactions)?;

        // Store the default committee config
        // Use the same test secp256k1 compressed public key used in registration
        let test_secp256k1_pubkey = generate_test_secp256k1_compressed_pubkey();
        self.committee_config = Some(CommitteeConfig::single_member(
            self.bridge_address,
            test_secp256k1_pubkey,
            "http://127.0.0.1:9191",
            10000,
        ));

        tracing::debug!("✓ Bridge deployment complete!");
        Ok(())
    }

    /// Deploy the bridge contract with custom committee configuration
    fn deploy_bridge_with_committee(&mut self, committee_config: &CommitteeConfig) -> Result<()> {
        let mut builder = BridgeDeploymentBuilder::new()?.with_network(self.node.network());

        tracing::debug!(
            "Deploying bridge contracts with {} committee member(s)...",
            committee_config.members.len()
        );

        let transactions = builder.build_transactions_with_committee(committee_config)?;
        self.submit_and_confirm_transactions(&transactions)?;

        tracing::debug!("✓ Bridge deployment complete!");
        tracing::debug!("  Committee members: {}", committee_config.members.len());
        tracing::debug!(
            "  Total voting power: {}",
            committee_config.total_voting_power()
        );
        Ok(())
    }

    /// Submit transactions and confirm each with a block
    fn submit_and_confirm_transactions(
        &self,
        transactions: &[SignedUserTransaction],
    ) -> Result<()> {
        for (i, txn) in transactions.iter().enumerate() {
            tracing::debug!(
                "  Submitting transaction {}/{}...",
                i + 1,
                transactions.len()
            );
            self.node.submit_transaction(txn.clone())?;

            // Generate a block to include the transaction.
            // Starcoin services can transiently be "Disconnected" under load; retry a bit.
            // Increased from 30s to 60s for better reliability with multiple committee members.
            self.node
                .generate_block_with_retry(Duration::from_secs(60))
                .with_context(|| format!("Failed to generate block for transaction {}", i + 1))?;

            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    /// Get the embedded node
    pub fn node(&self) -> &EmbeddedStarcoinNode {
        &self.node
    }

    /// Get the Move config
    pub fn config(&self) -> &MoveConfig {
        &self.config
    }

    /// Get the bridge address
    pub fn bridge_address(&self) -> AccountAddress {
        self.bridge_address
    }

    /// Get the committee configuration (if deployed)
    pub fn committee_config(&self) -> Option<&CommitteeConfig> {
        self.committee_config.as_ref()
    }

    /// Get the network
    pub fn network(&self) -> ChainNetwork {
        self.node.network()
    }

    /// Generate a block
    pub fn generate_block(&self) -> Result<starcoin_types::block::Block> {
        // Increased from 30s to 60s for better reliability under load.
        self.node.generate_block_with_retry(Duration::from_secs(60))
    }

    /// Get the Starcoin RPC URL (dynamically allocated port for test nodes)
    pub fn rpc_url(&self) -> String {
        let config = self.node.config();
        if let Some(addr) = config.rpc.get_http_address() {
            // Always use 127.0.0.1 for localhost (0.0.0.0 binds to all interfaces but we connect via localhost)
            let host = if addr.address.is_loopback() || addr.address.to_string() == "0.0.0.0" {
                "127.0.0.1".to_string()
            } else {
                addr.address.to_string()
            };
            format!("http://{}:{}", host, addr.port)
        } else {
            // Fallback to default if not configured
            "http://127.0.0.1:9850".to_string()
        }
    }

    /// Submit a transaction and wait for confirmation
    pub fn submit_and_confirm(
        &self,
        txn: SignedUserTransaction,
    ) -> Result<starcoin_types::block::Block> {
        self.node.submit_transaction(txn)?;
        // Increased from 30s to 60s for better reliability under load.
        self.node.generate_block_with_retry(Duration::from_secs(60))
    }

    /// Fund an account with STC for gas payments
    ///
    /// This creates a new Starcoin account and transfers STC to it.
    /// The account must be an Ed25519 keypair for Starcoin compatibility.
    pub fn fund_account(
        &mut self,
        keypair: &starcoin_bridge_types::crypto::StarcoinKeyPair,
        amount: u128,
    ) -> Result<()> {
        use fastcrypto::traits::KeyPair as FastcryptoKeyPair;
        use fastcrypto::traits::ToFromBytes;
        use starcoin_chain_api::ChainAsyncService;
        use starcoin_state_api::StateReaderExt;
        use starcoin_statedb::ChainStateDB;
        use starcoin_types::transaction::authenticator::AuthenticationKey;

        // Get the public key bytes and derive auth key
        let pubkey_bytes = match keypair {
            starcoin_bridge_types::crypto::StarcoinKeyPair::Ed25519(kp) => {
                kp.public().as_bytes().to_vec()
            }
            _ => anyhow::bail!("Only Ed25519 keypairs can be funded on Starcoin"),
        };

        // Create Starcoin Ed25519PublicKey for auth key derivation
        let starcoin_pubkey =
            starcoin_crypto::ed25519::Ed25519PublicKey::try_from(pubkey_bytes.as_slice())
                .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key: {:?}", e))?;
        let auth_key = AuthenticationKey::ed25519(&starcoin_pubkey);
        let target_address = auth_key.derived_address();

        tracing::debug!(
            "Funding Starcoin account 0x{} with {} nanoSTC",
            hex::encode(target_address.as_ref()),
            amount
        );

        // Build create account transaction using association account
        let args = vec![
            bcs_ext::to_bytes(&target_address)?,
            bcs_ext::to_bytes(&auth_key.to_vec())?,
            bcs_ext::to_bytes(&amount)?,
        ];

        // Get current association sequence number from chain state
        // Use futures::executor::block_on to run async code in sync context
        let storage = self.node.handle().storage();
        let chain_service = self.node.handle().chain_service()?;
        let state_root =
            futures::executor::block_on(async { chain_service.main_head_header().await })?
                .state_root();

        let state_db = ChainStateDB::new(storage, Some(state_root));
        let assoc_addr = starcoin_vm_types::account_config::association_address();
        let seq_num = state_db
            .get_account_resource(assoc_addr)?
            .map(|r| r.sequence_number())
            .unwrap_or(0);

        let txn = create_signed_txn_with_association_account(
            TransactionPayload::ScriptFunction(ScriptFunction::new(
                ModuleId::new(core_code_address(), Identifier::new("Account").unwrap()),
                Identifier::new("create_account_with_initial_amount").unwrap(),
                vec![stc_type_tag()],
                args,
            )),
            seq_num,
            DEFAULT_MAX_GAS_AMOUNT,
            1,
            3600,
            &self.node.network(),
        );

        self.submit_and_confirm(txn)?;
        tracing::info!(
            "Funded Starcoin account 0x{} with {} nanoSTC",
            hex::encode(target_address.as_ref()),
            amount
        );
        Ok(())
    }
}

// ============================================================================
// Complete Bridge Test Environment (Starcoin + Ethereum)
// ============================================================================

/// Complete test environment with both Starcoin and Ethereum (Anvil) nodes
///
use crate::crypto::BridgeAuthorityKeyPair;
use tokio::task::JoinHandle;

/// Bridge server handle for managing running bridge servers
pub struct BridgeServerHandle {
    pub handle: JoinHandle<()>,
    pub server_port: u16,
    pub authority_key: BridgeAuthorityKeyPair,
}

impl BridgeServerHandle {
    pub fn health_url(&self) -> String {
        format!("http://127.0.0.1:{}/ping", self.server_port)
    }
}

/// This provides a unified environment for E2E bridge testing.
pub struct BridgeTestEnv {
    /// Starcoin test environment (optional)
    pub starcoin: Option<StarcoinBridgeTestEnv>,
    /// Anvil Ethereum node (optional)
    pub anvil: Option<EmbeddedAnvilNode>,
    /// Deployed ETH contract addresses (if deployed)
    pub eth_contracts: Option<DeployedEthContracts>,
    /// Bridge server handles (one per committee member)
    pub bridge_servers: Vec<BridgeServerHandle>,
}

impl BridgeTestEnv {
    /// Create a new complete bridge test environment WITHOUT deploying ETH contracts
    ///
    /// This will:
    /// 1. Start an embedded Starcoin node and deploy bridge contracts
    /// 2. Start an embedded Anvil node (no contracts deployed)
    ///
    /// Use `new_with_eth_and_starcoin()` if you also need ETH contracts deployed.
    pub fn new() -> Result<Self> {
        let starcoin = StarcoinBridgeTestEnv::new_with_deployment()?;
        let anvil = EmbeddedAnvilNode::start()?;

        Ok(Self {
            starcoin: Some(starcoin),
            anvil: Some(anvil),
            eth_contracts: None,
            bridge_servers: Vec::new(),
        })
    }

    /// Create a complete bridge test environment WITH ETH contracts deployed
    ///
    /// This will:
    /// 1. Start an embedded Starcoin node and deploy bridge contracts
    /// 2. Start an embedded Anvil node
    /// 3. Deploy ETH bridge contracts using forge
    pub fn new_with_eth_and_starcoin() -> Result<Self> {
        let starcoin = StarcoinBridgeTestEnv::new_with_deployment()?;
        let anvil = EmbeddedAnvilNode::start()?;

        // Deploy ETH contracts
        let eth_contracts = anvil.deploy_bridge_contracts()?;

        Ok(Self {
            starcoin: Some(starcoin),
            anvil: Some(anvil),
            eth_contracts: Some(eth_contracts),
            bridge_servers: Vec::new(),
        })
    }

    pub fn new_with_eth_contracts() -> Result<Self> {
        Self::new_with_eth_and_starcoin()
    }

    /// Create with custom committee configuration (no ETH contracts)
    pub fn new_with_committee(committee_config: CommitteeConfig) -> Result<Self> {
        let starcoin = StarcoinBridgeTestEnv::new_with_committee(committee_config)?;
        let anvil = EmbeddedAnvilNode::start()?;

        Ok(Self {
            starcoin: Some(starcoin),
            anvil: Some(anvil),
            eth_contracts: None,
            bridge_servers: Vec::new(),
        })
    }

    /// Create with custom committee configuration AND deploy ETH contracts
    pub fn new_with_committee_and_eth_contracts(committee_config: CommitteeConfig) -> Result<Self> {
        let starcoin = StarcoinBridgeTestEnv::new_with_committee(committee_config)?;
        let anvil = EmbeddedAnvilNode::start()?;

        // Deploy ETH contracts
        let eth_contracts = anvil.deploy_bridge_contracts()?;

        Ok(Self {
            starcoin: Some(starcoin),
            anvil: Some(anvil),
            eth_contracts: Some(eth_contracts),
            bridge_servers: Vec::new(),
        })
    }

    pub fn new_with_committee_and_eth_and_starcoin(
        committee_config: CommitteeConfig,
    ) -> Result<Self> {
        Self::new_with_committee_and_eth_contracts(committee_config)
    }

    /// Deploy ETH contracts if not already deployed
    pub fn deploy_eth_contracts(&mut self) -> Result<&DeployedEthContracts> {
        if self.eth_contracts.is_none() {
            let anvil = self
                .anvil
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Anvil node not initialized"))?;
            let contracts = anvil.deploy_bridge_contracts()?;
            self.eth_contracts = Some(contracts);
        }
        Ok(self.eth_contracts.as_ref().unwrap())
    }

    /// Get the Starcoin bridge address
    pub fn starcoin_bridge_address(&self) -> AccountAddress {
        self.starcoin
            .as_ref()
            .expect("Starcoin environment not initialized")
            .bridge_address
    }

    /// Get the Anvil RPC URL
    pub fn eth_rpc_url(&self) -> &str {
        self.anvil
            .as_ref()
            .expect("Anvil node not initialized")
            .rpc_url()
    }

    /// Get the ETH provider
    pub fn eth_provider(&self) -> Provider<Http> {
        Provider::<Http>::try_from(self.eth_rpc_url()).expect("Failed to create ETH provider")
    }

    /// Get the ETH bridge contract wrapper
    pub fn eth_bridge_contract(&self) -> EthStarcoinBridge<Provider<Http>> {
        let contracts = self
            .eth_contracts
            .as_ref()
            .expect("ETH contracts not deployed");
        let address: Address = contracts
            .starcoin_bridge
            .parse()
            .expect("Invalid bridge address");
        EthStarcoinBridge::new(address, Arc::new(self.eth_provider()))
    }

    /// Get the Starcoin node
    pub fn starcoin_node(&self) -> &EmbeddedStarcoinNode {
        &self
            .starcoin
            .as_ref()
            .expect("Starcoin environment not initialized")
            .node
    }

    /// Get the Starcoin RPC URL
    pub fn starcoin_rpc_url(&self) -> String {
        self.starcoin
            .as_ref()
            .expect("Starcoin environment not initialized")
            .rpc_url()
    }

    /// Get the default Anvil private key
    pub fn eth_private_key(&self) -> &'static str {
        self.anvil
            .as_ref()
            .expect("Anvil node not initialized")
            .default_private_key()
    }

    /// Get deployed ETH contracts (if any)
    pub fn eth_contracts(&self) -> Option<&DeployedEthContracts> {
        self.eth_contracts.as_ref()
    }

    /// Get the ETH bridge proxy address (StarcoinBridge contract)
    pub fn eth_bridge_address(&self) -> Option<&str> {
        self.eth_contracts
            .as_ref()
            .map(|c| c.starcoin_bridge.as_str())
    }

    /// Start bridge servers based on committee configuration
    /// Returns the number of servers started
    pub async fn start_bridge_servers(
        &mut self,
        authority_keys: Vec<BridgeAuthorityKeyPair>,
    ) -> Result<usize> {
        use crate::config::{
            default_ed25519_key_pair, BridgeNodeConfig, EthConfig, StarcoinConfig,
        };

        use crate::node::run_bridge_node;
        use crate::server::BridgeNodePublicMetadata;
        use starcoin_bridge_types::bridge::BridgeChainId;
        use std::net::TcpListener;
        use tempfile::tempdir;

        let committee_config = self
            .starcoin
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Starcoin environment not initialized"))?
            .committee_config()
            .ok_or_else(|| anyhow::anyhow!("Committee not configured"))?;

        let member_count = committee_config.members.len();
        if authority_keys.len() != member_count {
            return Err(anyhow::anyhow!(
                "Number of authority keys ({}) does not match committee members ({})",
                authority_keys.len(),
                member_count
            ));
        }

        let contracts = self
            .eth_contracts
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ETH contracts not deployed"))?;

        // Extract ports from committee config URLs to ensure consistency
        // The committee URLs are in format "http://127.0.0.1:{port}"
        let server_ports: Vec<u16> = committee_config
            .members
            .iter()
            .map(|member| {
                // Parse URL to extract port
                let url = &member.http_rest_url;
                url.split(':')
                    .next_back()
                    .and_then(|port_str| port_str.parse::<u16>().ok())
                    .expect("Committee member URL must have valid port")
            })
            .collect();

        tracing::info!("Using ports from committee config: {:?}", server_ports);

        for (i, authority_key) in authority_keys.into_iter().enumerate() {
            let server_port = server_ports[i];

            tracing::info!(
                "Starting bridge validator server {} on port {}",
                i + 1,
                server_port,
            );

            // Create temp directory for this server
            let tmp_dir = tempdir()?.into_path();
            let authority_key_path = tmp_dir.join("bridge_authority_key");

            // Write authority key
            std::fs::write(&authority_key_path, authority_key.encode_base64())?;

            // Find available metrics port
            let metrics_port = TcpListener::bind("127.0.0.1:0")
                .expect("Failed to bind to ephemeral port")
                .local_addr()
                .expect("Failed to get local addr")
                .port();

            let config = BridgeNodeConfig {
                server_listen_port: server_port,
                metrics_port,
                bridge_authority_key_path: authority_key_path,
                eth: EthConfig {
                    eth_rpc_url: self.eth_rpc_url().to_string(),
                    eth_bridge_proxy_address: contracts.starcoin_bridge.clone(),
                    eth_bridge_chain_id: BridgeChainId::EthCustom as u8,
                },
                starcoin: StarcoinConfig {
                    starcoin_bridge_rpc_url: self.starcoin_rpc_url(),
                    starcoin_bridge_proxy_address: format!(
                        "0x{}",
                        hex::encode(self.starcoin_bridge_address().to_vec())
                    ),
                    starcoin_bridge_chain_id: BridgeChainId::StarcoinCustom as u8,
                },
                metrics_key_pair: default_ed25519_key_pair(),
                metrics: None,
                watchdog_config: None,
            };

            let handle = run_bridge_node(
                config,
                BridgeNodePublicMetadata::empty_for_testing(),
                prometheus::Registry::new(),
            )
            .await?;

            self.bridge_servers.push(BridgeServerHandle {
                handle,
                server_port,
                authority_key,
            });

            tracing::info!("Bridge server {} started successfully", i + 1);

            // Small delay between starting servers
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        Ok(self.bridge_servers.len())
    }

    /// Check health of all bridge servers
    pub async fn check_bridge_servers_health(&self) -> Result<usize> {
        let mut healthy_count = 0;
        let client = reqwest::Client::new();

        for (i, server) in self.bridge_servers.iter().enumerate() {
            let url = server.health_url();
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!("Bridge server {} is healthy", i + 1);
                    healthy_count += 1;
                }
                Ok(resp) => {
                    tracing::warn!("Bridge server {} returned status: {}", i + 1, resp.status());
                }
                Err(e) => {
                    tracing::warn!("Bridge server {} health check failed: {}", i + 1, e);
                }
            }
        }

        Ok(healthy_count)
    }

    /// Get the number of running bridge servers
    pub fn bridge_server_count(&self) -> usize {
        self.bridge_servers.len()
    }

    /// Get committee member count from Starcoin environment
    pub fn committee_member_count(&self) -> Option<usize> {
        self.starcoin
            .as_ref()
            .and_then(|s| s.committee_config())
            .map(|c| c.members.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This test runs first (alphabetically) and ensures the blob is built
    /// before other tests that depend on it
    #[test]
    fn test_00_build_embedded_blob() -> Result<()> {
        // Skip if MPM_PATH is not set - blob should already exist
        if std::env::var("MPM_PATH").is_err() {
            tracing::debug!("MPM_PATH not set, skipping blob build. Using existing blob file.");
            // Just verify the blob file exists
            let blob_path =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_BLOB_PATH);
            if !blob_path.exists() {
                return Err(anyhow::anyhow!(
                    "Blob file not found: {:?}. Set MPM_PATH to build it.",
                    blob_path
                ));
            }
            tracing::debug!("✓ Blob file exists: {:?}", blob_path);
            return Ok(());
        }

        // Build the blob
        ensure_blob_ready()?;
        tracing::debug!("✓ Embedded blob built successfully");
        Ok(())
    }

    #[test]
    fn test_load_move_config() -> Result<()> {
        let config = MoveConfig::load()?;
        assert!(!config.address.is_empty());
        assert!(!config.public_key.is_empty());
        assert!(!config.private_key.is_empty());

        let address = config.address()?;
        tracing::debug!("Loaded config address: {:?}", address);
        Ok(())
    }

    #[test]
    fn test_load_package() -> Result<()> {
        let package = load_package()?;
        assert!(!package.modules().is_empty());
        tracing::debug!("Package has {} modules", package.modules().len());
        Ok(())
    }

    #[test]
    fn test_builder_creates_all_transactions() -> Result<()> {
        let mut builder = BridgeDeploymentBuilder::new()?;
        let transactions = builder.build_all_transactions()?;

        assert_eq!(
            transactions.len(),
            9,
            "Should create 9 transactions (1 create_account + 8 deployment)"
        );

        for (i, txn) in transactions.iter().enumerate() {
            tracing::debug!("Transaction {}: hash={:?}", i + 1, txn.id());
        }

        Ok(())
    }

    #[test]
    fn test_builder_individual_transactions() -> Result<()> {
        let mut builder = BridgeDeploymentBuilder::new()?;

        let create_account = builder.build_create_bridge_account_transaction()?;
        tracing::debug!("Create Account: {:?}", create_account.id());

        let deploy = builder.build_deploy_transaction()?;
        tracing::debug!("Deploy: {:?}", deploy.id());

        let init = builder.build_initialize_transaction()?;
        tracing::debug!("Initialize: {:?}", init.id());

        let register = builder.build_register_committee_transaction("http://test.com")?;
        tracing::debug!("Register: {:?}", register.id());

        let bridge_addr = builder.bridge_address()?;
        let committee = builder.build_create_committee_transaction(bridge_addr, 10000, 5000, 0)?;
        tracing::debug!("Committee: {:?}", committee.id());

        let eth = builder.build_setup_token_transaction("eth")?;
        tracing::debug!("ETH token: {:?}", eth.id());

        Ok(())
    }

    #[test]
    fn test_deploy_and_initialize_bridge() -> Result<()> {
        // Create test environment with default committee
        let env = StarcoinBridgeTestEnv::new_with_deployment()?;

        tracing::debug!("✓ Bridge deployed at: {:?}", env.bridge_address());
        tracing::debug!("✓ Network: {:?}", env.network());

        // Verify deployment by generating a block
        let block = env.generate_block()?;
        tracing::debug!("✓ Block generated: {:?}", block.id());

        Ok(())
    }

    #[test]
    fn test_deploy_with_custom_committee() -> Result<()> {
        // Create a single-member committee with known public key
        let validator_address = MoveConfig::load()?.address()?;
        let member = CommitteeMemberConfig::new(
            validator_address,
            vec![0x02; 33], // compressed secp256k1 public key
            "http://localhost:9191",
            10000, // voting power
        );

        let committee_config = CommitteeConfig::new(
            vec![member],
            5000, // min_stake_percentage (50%)
            0,    // epoch
        );

        let env = StarcoinBridgeTestEnv::new_with_committee(committee_config.clone())?;

        tracing::debug!("✓ Bridge deployed with custom committee");
        tracing::debug!("✓ Committee members: {}", committee_config.members.len());
        tracing::debug!(
            "✓ Total voting power: {}",
            committee_config.total_voting_power()
        );

        // Verify deployment
        let stored_config = env
            .committee_config()
            .expect("Committee config should exist");
        assert_eq!(stored_config.members.len(), 1);
        assert_eq!(stored_config.total_voting_power(), 10000);

        Ok(())
    }

    #[test]
    fn test_committee_config_from_hex() -> Result<()> {
        // Test creating CommitteeMemberConfig from hex pubkey
        // Using a valid 33-byte compressed secp256k1 pubkey hex
        let hex_pubkey = "02".to_string() + &"ab".repeat(32);
        let validator_address = MoveConfig::load()?.address()?;
        let member = CommitteeMemberConfig::from_hex(
            validator_address,
            &hex_pubkey,
            "http://test.com",
            5000,
        )?;

        assert_eq!(member.bridge_pubkey_bytes.len(), 33);
        assert_eq!(member.voting_power, 5000);
        assert_eq!(member.http_rest_url, "http://test.com");

        Ok(())
    }

    #[test]
    fn test_committee_config_compress_65_byte_pubkey() -> Result<()> {
        // Test that 65-byte uncompressed pubkey gets compressed to 33 bytes
        // 65-byte uncompressed format: 0x04 + 32 bytes X + 32 bytes Y
        let uncompressed = vec![0x04; 65];

        // Compress it first, then create the member config
        let compressed = CommitteeMemberConfig::compress_pubkey(&uncompressed)?;
        let validator_address = MoveConfig::load()?.address()?;
        let member =
            CommitteeMemberConfig::new(validator_address, compressed, "http://test.com", 1000);

        // Should be compressed to 33 bytes
        assert_eq!(member.bridge_pubkey_bytes.len(), 33);

        Ok(())
    }

    #[test]
    fn test_embedded_anvil_node() -> Result<()> {
        // Start embedded Anvil node
        let anvil = EmbeddedAnvilNode::start()?;

        tracing::debug!("✓ Anvil started at: {}", anvil.rpc_url());
        tracing::debug!("✓ Port: {}", anvil.port());
        tracing::debug!("✓ Chain ID: {}", anvil.chain_id());
        tracing::debug!("✓ Default address: {}", anvil.default_address());

        // Verify we can make RPC calls
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(anvil.rpc_url())
            .header("Content-Type", "application/json")
            .body(r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#)
            .send()?;

        assert!(res.status().is_success());
        let body: serde_json::Value = res.json()?;
        assert_eq!(body["result"], "0x7a69"); // 31337 in hex

        tracing::debug!("✓ RPC call successful");

        Ok(())
    }

    #[test]
    fn test_complete_bridge_test_env() -> Result<()> {
        // Start complete bridge test environment (Starcoin + Anvil)
        let env = BridgeTestEnv::new()?;

        tracing::debug!("✓ Complete bridge test environment started");
        tracing::debug!("✓ Starcoin bridge at: {:?}", env.starcoin_bridge_address());
        tracing::debug!("✓ Ethereum RPC at: {}", env.eth_rpc_url());
        tracing::debug!("✓ ETH private key: {}...", &env.eth_private_key()[..10]);

        // Verify both nodes are working
        let starcoin = env.starcoin.as_ref().expect("Starcoin not initialized");
        let block = starcoin.generate_block()?;
        tracing::debug!("✓ Starcoin block: {:?}", block.id());

        let client = reqwest::blocking::Client::new();
        let res = client
            .post(env.eth_rpc_url())
            .header("Content-Type", "application/json")
            .body(r#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}"#)
            .send()?;
        assert!(res.status().is_success());
        tracing::debug!("✓ Anvil eth_blockNumber successful");

        Ok(())
    }

    #[test]
    #[ignore = "requires forge to be installed and may be slow"]
    fn test_deploy_eth_contracts() -> Result<()> {
        // Start Anvil and deploy ETH contracts
        let anvil = EmbeddedAnvilNode::start()?;
        tracing::debug!("✓ Anvil started at: {}", anvil.rpc_url());

        let contracts = anvil.deploy_bridge_contracts()?;

        tracing::debug!("✓ ETH contracts deployed:");
        tracing::debug!("  StarcoinBridge: {}", contracts.starcoin_bridge);
        tracing::debug!("  BridgeCommittee: {}", contracts.bridge_committee);
        tracing::debug!("  BridgeConfig: {}", contracts.bridge_config);
        tracing::debug!("  BridgeVault: {}", contracts.bridge_vault);
        tracing::debug!("  BridgeLimiter: {}", contracts.bridge_limiter);

        assert!(!contracts.starcoin_bridge.is_empty());
        assert!(!contracts.bridge_committee.is_empty());

        Ok(())
    }

    #[test]
    #[ignore = "requires forge to be installed and may be slow"]
    fn test_full_bridge_env_with_eth_contracts() -> Result<()> {
        // Start complete bridge test environment with ETH contracts deployed
        let env = BridgeTestEnv::new_with_eth_contracts()?;

        tracing::debug!("✓ Full bridge environment started");
        tracing::debug!("✓ Starcoin bridge at: {:?}", env.starcoin_bridge_address());
        tracing::debug!("✓ Ethereum RPC at: {}", env.eth_rpc_url());

        let eth_contracts = env
            .eth_contracts()
            .expect("ETH contracts should be deployed");
        tracing::debug!("✓ ETH StarcoinBridge: {}", eth_contracts.starcoin_bridge);
        tracing::debug!("✓ ETH BridgeVault: {}", eth_contracts.bridge_vault);

        // Verify we can query the deployed contract
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(env.eth_rpc_url())
            .header("Content-Type", "application/json")
            .body(format!(
                r#"{{"jsonrpc":"2.0","method":"eth_getCode","params":["{}","latest"],"id":1}}"#,
                eth_contracts.starcoin_bridge
            ))
            .send()?;

        let body: serde_json::Value = res.json()?;
        let code = body["result"].as_str().unwrap_or("");
        assert!(code.len() > 2, "Contract should have bytecode");
        tracing::debug!("✓ ETH contract has bytecode (length: {})", code.len());

        Ok(())
    }
}
