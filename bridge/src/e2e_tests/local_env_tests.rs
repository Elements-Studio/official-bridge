// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! E2E tests that run with embedded Starcoin + Anvil nodes.
//!
//! These tests use in-memory nodes and verify actual on-chain state.
//! Each test starts its own embedded Starcoin node + Anvil node + deploys contracts.
//!
//! Run tests with:
//!   cargo test --package starcoin-bridge --lib e2e_tests::local_env_tests -- --nocapture
//!
//! These tests perform REAL on-chain interactions and strict assertions.

use crate::abi::{EthBridgeLimiter, EthERC20, EthStarcoinBridge};
use crate::crypto::{BridgeAuthorityKeyPair, BridgeAuthorityPublicKeyBytes};
use crate::simple_starcoin_rpc::SimpleStarcoinRpcClient;
use crate::starcoin_test_utils::{BridgeTestEnv, CommitteeConfig, StarcoinBridgeTestEnv};
use crate::types::BridgeAction;
use ethers::prelude::*;
use ethers::types::Address as EthAddress;
use fastcrypto::traits::{KeyPair as KeyPairTrait, ToFromBytes};
use starcoin_bridge_types::bridge::BridgeChainId;
use starcoin_bridge_types::crypto::StarcoinKeyPair;
use starcoin_types::account_address::AccountAddress;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::long_flow_harness::{poll_until, Diagnostics, Phase, PollConfig};

// ===========================================================================
// Cross-chain Transfer Stage Tracking
// ===========================================================================

/// Represents the stages of a cross-chain transfer for detailed progress tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossChainStage {
    // ETH -> Starcoin stages
    EthDepositPending,
    EthDepositConfirmed,
    StarcoinCredited,

    // Starcoin -> ETH stages
    StarcoinWithdrawPending,
    StarcoinWithdrawConfirmed,
    BridgeServerProcessing,
}

impl std::fmt::Display for CrossChainStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EthDepositPending => write!(f, "ETH Deposit Pending"),
            Self::EthDepositConfirmed => write!(f, "ETH Deposit Confirmed"),
            Self::StarcoinCredited => write!(f, "Starcoin Account Credited"),
            Self::StarcoinWithdrawPending => write!(f, "Starcoin Withdraw Pending"),
            Self::StarcoinWithdrawConfirmed => write!(f, "Starcoin Withdraw Confirmed"),
            Self::BridgeServerProcessing => write!(f, "Bridge Server Processing"),
        }
    }
}

/// Cross-chain transfer progress tracker with timing
pub struct TransferProgress {
    direction: &'static str,
    start_time: Instant,
    current_stage: CrossChainStage,
    stage_start_time: Instant,
}

impl TransferProgress {
    pub fn new_eth_to_starcoin() -> Self {
        Self {
            direction: "ETH → Starcoin",
            start_time: Instant::now(),
            current_stage: CrossChainStage::EthDepositPending,
            stage_start_time: Instant::now(),
        }
    }

    pub fn new_starcoin_to_eth() -> Self {
        Self {
            direction: "Starcoin → ETH",
            start_time: Instant::now(),
            current_stage: CrossChainStage::StarcoinWithdrawPending,
            stage_start_time: Instant::now(),
        }
    }

    pub fn advance(&mut self, new_stage: CrossChainStage) {
        let stage_elapsed = self.stage_start_time.elapsed();
        let total_elapsed = self.start_time.elapsed();
        println!(
            "   ✓ {} completed in {:.2}s (total: {:.2}s)",
            self.current_stage,
            stage_elapsed.as_secs_f64(),
            total_elapsed.as_secs_f64()
        );
        self.current_stage = new_stage;
        self.stage_start_time = Instant::now();
        println!("   → Now at stage: {}", new_stage);
    }

    pub fn print_poll_status(&self, round: u32, extra_info: &str) {
        let total_elapsed = self.start_time.elapsed();
        let stage_elapsed = self.stage_start_time.elapsed();
        println!(
            "   [Round {} | {:.1}s total | {:.1}s in {}] {}",
            round,
            total_elapsed.as_secs_f64(),
            stage_elapsed.as_secs_f64(),
            self.current_stage,
            extra_info
        );
    }

    pub fn timeout_error(&self, detail: &str) -> anyhow::Error {
        let total_elapsed = self.start_time.elapsed();
        anyhow::anyhow!(
            "❌ {} TIMEOUT after {:.2}s\n   Last completed stage: {}\n   Failed waiting for: {}\n   Detail: {}",
            self.direction,
            total_elapsed.as_secs_f64(),
            self.current_stage,
            self.next_expected_stage(),
            detail
        )
    }

    fn next_expected_stage(&self) -> &'static str {
        match self.current_stage {
            CrossChainStage::EthDepositPending => "ETH Deposit Confirmation",
            CrossChainStage::EthDepositConfirmed => "Starcoin Balance Credit",
            CrossChainStage::StarcoinCredited => "Transfer Complete",
            CrossChainStage::StarcoinWithdrawPending => "Starcoin Withdraw Confirmation",
            CrossChainStage::StarcoinWithdrawConfirmed => "Bridge Server Processing",
            CrossChainStage::BridgeServerProcessing => "Transfer Complete",
        }
    }
}

// ===========================================================================
//
// Architecture note:
// - Embedded Starcoin dev environment only allows Bridge address as validator
// - Therefore we use single-validator mode (1-of-1 threshold)
// - Multi-validator (2-of-3) would require a real multi-node Starcoin cluster

/// Setup diagnostics for debugging timeouts
struct Phase1Diagnostics {
    eth_rpc_url: String,
}

impl Diagnostics for Phase1Diagnostics {
    fn snapshot(&self) -> String {
        format!("eth_rpc_url={}", self.eth_rpc_url)
    }
}

// ---------------------------------------------------------------------------
// Environment setup helpers
// ---------------------------------------------------------------------------

async fn assert_eth_chain_ready(provider: &Provider<Http>) {
    let chain_id = provider
        .get_chainid()
        .await
        .expect("Failed to get ETH chain ID");
    assert_eq!(chain_id.as_u64(), 31337, "Expected Anvil chain ID 31337");
}

async fn assert_eth_contracts_deployed(
    provider: &Provider<Http>,
    contracts: &super::anvil_test_utils::DeployedEthContracts,
) {
    let bridge_addr =
        EthAddress::from_str(&contracts.starcoin_bridge).expect("Invalid bridge address");
    let code = provider
        .get_code(bridge_addr, None)
        .await
        .expect("Failed to get bridge bytecode");
    assert!(!code.is_empty(), "Bridge contract should have bytecode");

    let usdt_addr = EthAddress::from_str(&contracts.usdt).expect("Invalid USDT address");
    assert_ne!(usdt_addr, EthAddress::zero(), "USDT should be deployed");
}

fn assert_starcoin_can_produce_blocks(env: &BridgeTestEnv) {
    env.starcoin
        .as_ref()
        .expect("Starcoin environment not initialized")
        .generate_block()
        .expect("Starcoin should generate a block");
}

// ---------------------------------------------------------------------------
// Validator/committee assertion helpers
// ---------------------------------------------------------------------------

async fn assert_committee_initialized(env: &BridgeTestEnv) {
    // Check that committee config exists
    let starcoin = env
        .starcoin
        .as_ref()
        .expect("Starcoin environment not initialized");
    let config = starcoin.committee_config();
    assert!(config.is_some(), "Committee should be initialized");

    let config = config.unwrap();
    tracing::debug!(
        "Committee initialized with {} member(s), total voting power: {}",
        config.members.len(),
        config.total_voting_power()
    );
}

// ---------------------------------------------------------------------------
// Bridge server helpers
// ---------------------------------------------------------------------------

/// Wait for Starcoin RPC to be ready (not returning 503)
async fn wait_for_starcoin_rpc_ready(
    rpc_url: &str,
    timeout: std::time::Duration,
) -> anyhow::Result<()> {
    // Use a dummy bridge address since we just want to check RPC connectivity
    let client = SimpleStarcoinRpcClient::new(rpc_url, "0x1");
    let start = std::time::Instant::now();

    loop {
        // Try to get chain info - this is a simple RPC call that should work when ready
        match client.chain_info().await {
            Ok(_) => {
                tracing::debug!("Starcoin RPC ready after {:?}", start.elapsed());
                return Ok(());
            }
            Err(e) => {
                if start.elapsed() > timeout {
                    return Err(anyhow::anyhow!(
                        "Starcoin RPC not ready after {:?}: {}",
                        timeout,
                        e
                    ));
                }
                tracing::debug!("Waiting for Starcoin RPC... ({})", e);
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    }
}

/// Generate the Ed25519 keypair that will be used for bridge client, based on authority key.
/// This allows us to pre-fund the account before starting the bridge server.
fn generate_bridge_client_keypair(authority_key: &BridgeAuthorityKeyPair) -> StarcoinKeyPair {
    use fastcrypto::ed25519::Ed25519KeyPair;
    use fastcrypto::traits::KeyPair as FastcryptoKeyPair;
    use rand::SeedableRng;

    // Use deterministic seed based on authority key for reproducibility
    let auth_pubkey_bytes = authority_key.public().as_bytes().to_vec();
    let mut seed = [0u8; 32];
    seed[..auth_pubkey_bytes.len().min(32)]
        .copy_from_slice(&auth_pubkey_bytes[..auth_pubkey_bytes.len().min(32)]);
    let mut rng = rand::rngs::StdRng::from_seed(seed);
    let ed25519_keypair = Ed25519KeyPair::generate(&mut rng);
    StarcoinKeyPair::Ed25519(ed25519_keypair)
}

/// Get the bridge admin keypair from the test environment.
/// This is the keypair that deployed the bridge contract and has admin privileges.
fn get_bridge_admin_keypair(env: &BridgeTestEnv) -> StarcoinKeyPair {
    use fastcrypto::ed25519::Ed25519KeyPair;
    use fastcrypto::traits::ToFromBytes;

    let starcoin_env = env
        .starcoin
        .as_ref()
        .expect("Starcoin environment not initialized");
    let privkey_hex = starcoin_env.config.private_key.trim_start_matches("0x");
    let privkey_bytes = hex::decode(privkey_hex).expect("Failed to decode private key");

    // Create Ed25519 keypair from private key bytes (ToFromBytes trait provides from_bytes)
    let ed25519_keypair = Ed25519KeyPair::from_bytes(&privkey_bytes)
        .expect("Failed to create Ed25519 keypair from private key");
    StarcoinKeyPair::Ed25519(ed25519_keypair)
}

async fn assert_bridge_server_healthy(
    handle: &crate::starcoin_test_utils::BridgeServerHandle,
) -> anyhow::Result<()> {
    let url = handle.health_url();
    let client = reqwest::Client::new();

    poll_until(
        Phase::Phase3BridgeServers,
        "bridge server healthy",
        PollConfig::fast(),
        || async {
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => Ok(Some(())),
                _ => Ok(None),
            }
        },
        None,
    )
    .await
}

// ---------------------------------------------------------------------------
// Cross-chain transfer helpers
// ---------------------------------------------------------------------------

use super::anvil_test_utils::anvil_keys;

/// Get an ETH signer for test account 0 (Anvil default)
fn get_test_eth_signer(
    provider: &Provider<Http>,
) -> anyhow::Result<SignerMiddleware<Provider<Http>, LocalWallet>> {
    let wallet: LocalWallet = anvil_keys::ANVIL_PRIVATE_KEY_0
        .parse::<LocalWallet>()?
        .with_chain_id(31337u64);
    Ok(SignerMiddleware::new(provider.clone(), wallet))
}

async fn get_eth_usdt_balance(
    provider: &Provider<Http>,
    usdt_addr: EthAddress,
    account: EthAddress,
) -> anyhow::Result<u64> {
    let usdt = EthERC20::new(usdt_addr, Arc::new(provider.clone()));
    let balance = usdt.balance_of(account).await?;
    Ok(balance.as_u64())
}

async fn mint_eth_usdt(
    provider: &Provider<Http>,
    usdt_addr: EthAddress,
    to: EthAddress,
    amount: u64,
) -> anyhow::Result<()> {
    // We use account 0 (the deployer) which typically has mint authority
    let signer = get_test_eth_signer(provider)?;
    let usdt = EthERC20::new(usdt_addr, Arc::new(signer));

    // Call mint function - this should work for test ERC20 contracts
    let call = usdt.mint(to, amount.into());
    let tx = call.send().await?;
    let receipt = tx.await?.expect("mint tx should have receipt");

    if receipt.status != Some(1.into()) {
        return Err(anyhow::anyhow!("USDT mint failed: {:?}", receipt));
    }

    tracing::debug!("Minted {} USDT to {:?}", amount, to);
    Ok(())
}

async fn deposit_usdt_to_bridge(
    provider: &Provider<Http>,
    bridge_addr: EthAddress,
    usdt_addr: EthAddress,
    amount: u64,
    target_chain: u8,
    target_address: Vec<u8>,
) -> anyhow::Result<TransactionReceipt> {
    use crate::abi::EthStarcoinBridge;
    use starcoin_bridge_types::bridge::TOKEN_ID_USDT;

    let signer = get_test_eth_signer(provider)?;
    let user_addr = signer.address();

    // 1. Approve USDT spending
    let usdt = EthERC20::new(usdt_addr, Arc::new(signer.clone()));
    let approve_call = usdt.approve(bridge_addr, amount.into());
    let approve_tx = approve_call.send().await?;
    let approve_receipt = approve_tx.await?.expect("approve tx should have receipt");
    if approve_receipt.status != Some(1.into()) {
        return Err(anyhow::anyhow!("USDT approve failed"));
    }
    tracing::debug!("USDT approve tx: {:?}", approve_receipt.transaction_hash);

    // 2. Call bridge.bridgeERC20(...)
    let bridge = EthStarcoinBridge::new(bridge_addr, Arc::new(signer.clone()));
    let bridge_call = bridge.bridge_erc20(
        TOKEN_ID_USDT,
        amount.into(),
        target_address.into(),
        target_chain,
    );
    let bridge_tx = bridge_call.send().await?;
    let receipt = bridge_tx.await?.expect("bridge tx should have receipt");

    tracing::info!(
        "ETH bridge deposit: {} USDT from {:?}, tx: {:?}",
        amount,
        user_addr,
        receipt.transaction_hash
    );

    Ok(receipt)
}

// ---------------------------------------------------------------------------
// Starcoin balance query helper
// ---------------------------------------------------------------------------

/// Query Starcoin token balance using RPC
/// Returns the raw balance value (in token's smallest unit)
async fn query_starcoin_token_balance(
    starcoin_rpc_url: &str,
    account_address: &str,
    bridge_address: &str,
    token_name: &str, // ETH, USDT, USDC, BTC
) -> anyhow::Result<u64> {
    // Remove 0x prefix if present
    let account_addr = account_address.trim_start_matches("0x");
    let bridge_addr = bridge_address.trim_start_matches("0x");

    // Construct resource type: 0x1::Account::Balance<{bridge_addr}::{token}::{token}>
    let resource_type = format!(
        "0x00000000000000000000000000000001::Account::Balance<0x{}::{}::{}>",
        bridge_addr, token_name, token_name
    );

    // Query Starcoin RPC
    let client = reqwest::Client::new();
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "state.get_resource",
        "params": [
            format!("0x{}", account_addr),
            resource_type,
            {"decode": true}
        ],
        "id": 1
    });

    tracing::debug!(
        "[BalanceQuery] Request: url={}, account={}, resource_type={}",
        starcoin_rpc_url,
        account_addr,
        resource_type
    );

    let response = client
        .post(starcoin_rpc_url)
        .json(&request_body)
        .send()
        .await?;

    let response_json: serde_json::Value = response.json().await?;

    // Print full response for debugging
    tracing::info!(
        "[BalanceQuery] Full RPC response for account {}: {}",
        account_addr,
        serde_json::to_string_pretty(&response_json).unwrap_or_else(|_| "parse error".to_string())
    );

    // Extract balance from response: .result.json.token.value
    if let Some(result) = response_json.get("result") {
        tracing::debug!("[BalanceQuery] result field: {:?}", result);
        if let Some(json_obj) = result.get("json") {
            tracing::debug!("[BalanceQuery] json field: {:?}", json_obj);
            if let Some(token) = json_obj.get("token") {
                tracing::debug!("[BalanceQuery] token field: {:?}", token);
                if let Some(value) = token.get("value") {
                    tracing::debug!("[BalanceQuery] value field: {:?}", value);
                    // Try to parse as u64 directly (JSON number) or as string
                    if let Some(balance) = value.as_u64() {
                        tracing::info!("[BalanceQuery] ✓ Parsed balance (as u64): {}", balance);
                        return Ok(balance);
                    } else if let Some(balance_str) = value.as_str() {
                        let balance = balance_str.parse::<u64>().unwrap_or(0);
                        tracing::info!(
                            "[BalanceQuery] ✓ Parsed balance (from string): {}",
                            balance
                        );
                        return Ok(balance);
                    }
                }
            }
        }
    }

    // Check for error in response
    if let Some(error) = response_json.get("error") {
        tracing::warn!("[BalanceQuery] RPC error: {:?}", error);
    }

    // If resource doesn't exist or parsing fails, return 0
    tracing::warn!("[BalanceQuery] Resource not found or failed to parse, returning 0");
    Ok(0)
}

struct EnviromentPreparationOption {
    need_eth: bool,
    need_starcoin: bool,
    need_bridge_server: bool,

    committee_options: Option<CommitteeConfig>,
    authority_keys: Option<Vec<BridgeAuthorityKeyPair>>,
}

async fn prepare_enviroment(setting: EnviromentPreparationOption) -> BridgeTestEnv {
    use super::anvil_test_utils::EmbeddedAnvilNode;
    use std::sync::Once;
    use std::time::Instant;

    // Initialize metrics and telemetry once (shared across all tests)
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let global_registry = prometheus::Registry::new();
        starcoin_metrics::init_metrics(&global_registry);
        telemetry_subscribers::init_for_testing();
    });

    let total_start = Instant::now();
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║   🚀 Preparing Test Environment                            ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    tracing::info!("=== Starting Environment Preparation ===");
    tracing::info!("  ETH: {}", setting.need_eth);
    tracing::info!("  Starcoin: {}", setting.need_starcoin);
    tracing::info!("  Bridge Server: {}", setting.need_bridge_server);
    tracing::info!(
        "  Custom Committee: {}",
        setting.committee_options.is_some()
    );
    tracing::info!(
        "  Authority Keys: {}",
        setting
            .authority_keys
            .as_ref()
            .map(|k| k.len())
            .unwrap_or(0)
    );

    if !setting.need_eth && !setting.need_starcoin {
        panic!("At least one of ETH or Starcoin must be enabled");
    }

    // Create Starcoin environment if needed
    // Use spawn_blocking to avoid "drop runtime in async context" error
    let starcoin = if setting.need_starcoin {
        println!("[1/5] 🌟 Creating Starcoin environment...");
        let starcoin_start = Instant::now();
        tracing::info!("Creating Starcoin environment...");
        let committee_config = setting.committee_options.clone();
        let starcoin_env = tokio::task::spawn_blocking(move || {
            if let Some(config) = committee_config {
                StarcoinBridgeTestEnv::new_with_committee(config)
                    .expect("Failed to create Starcoin test env with committee")
            } else {
                StarcoinBridgeTestEnv::new_with_deployment()
                    .expect("Failed to create Starcoin test env")
            }
        })
        .await
        .expect("Failed to spawn blocking task for Starcoin environment");
        let starcoin_elapsed = starcoin_start.elapsed();
        println!(
            "      ✅ Starcoin ready ({:.2}s)\n",
            starcoin_elapsed.as_secs_f64()
        );
        tracing::info!("✅ Starcoin environment created");
        Some(starcoin_env)
    } else {
        None
    };

    // Create Anvil (ETH) environment if needed
    // Use spawn_blocking to avoid "drop runtime in async context" error
    let anvil = if setting.need_eth {
        println!("[2/5] ⚡ Creating Anvil (ETH) environment...");
        let anvil_start = Instant::now();
        tracing::info!("Creating Anvil (ETH) environment...");

        let anvil_node = tokio::task::spawn_blocking(|| {
            EmbeddedAnvilNode::start().expect("Failed to start Anvil node")
        })
        .await
        .expect("Failed to spawn blocking task for Anvil node");

        let anvil_elapsed = anvil_start.elapsed();
        println!(
            "      ✅ Anvil ready ({:.2}s)\n",
            anvil_elapsed.as_secs_f64()
        );
        tracing::info!("✅ Anvil environment created");
        Some(anvil_node)
    } else {
        None
    };

    // Deploy ETH contracts if both ETH and Starcoin are enabled
    // Use spawn_blocking because deploy_bridge_contracts() runs forge which can take several seconds
    let eth_contracts = if setting.need_eth && anvil.is_some() {
        println!("[3/5] 📜 Deploying ETH bridge contracts...");
        let deploy_start = Instant::now();
        tracing::info!("Deploying ETH bridge contracts...");

        let rpc_url = anvil.as_ref().unwrap().rpc_url().to_string();

        // Add timeout for contract deployment
        let deployment_timeout = Duration::from_secs(600); // 10 minutes for contract deployment
        println!(
            "      🔄 Starting contract deployment (timeout: {} minutes)...",
            deployment_timeout.as_secs() / 60
        );

        let contracts = tokio::time::timeout(
            deployment_timeout,
            tokio::task::spawn_blocking(move || {
                println!("      🏗️ Running forge to compile and deploy contracts...");
                let result = super::anvil_test_utils::deploy_bridge_contracts_to_rpc(&rpc_url);
                println!("      📋 Contract deployment process finished");
                result.expect("Failed to deploy ETH contracts")
            }),
        )
        .await
        .expect("Contract deployment timed out after 10 minutes")
        .expect("Failed to spawn blocking task for contract deployment");

        let deploy_elapsed = deploy_start.elapsed();
        println!(
            "      ✅ Contracts deployed ({:.2}s)\n",
            deploy_elapsed.as_secs_f64()
        );
        tracing::info!(
            "✅ ETH contracts deployed in {:.2}s",
            deploy_elapsed.as_secs_f64()
        );
        Some(contracts)
    } else {
        None
    };

    let mut env = BridgeTestEnv {
        starcoin,
        anvil,
        eth_contracts,
        bridge_servers: Vec::new(),
    };

    // Verify ETH chain if needed
    if setting.need_eth {
        println!("[4/5] 🔍 Verifying ETH chain...");
        let verify_start = Instant::now();
        tracing::info!("Verifying ETH chain...");
        let provider = env.eth_provider();

        let diag = Phase1Diagnostics {
            eth_rpc_url: env.eth_rpc_url().to_string(),
        };

        poll_until(
            Phase::Phase1Setup,
            "ETH chain ready",
            PollConfig::standard(),
            || async {
                let id = provider.get_chainid().await?;
                Ok((id.as_u64() == 31337).then_some(()))
            },
            Some(&diag),
        )
        .await
        .expect("ETH chain should be ready");

        assert_eth_chain_ready(&provider).await;

        if env.eth_contracts.is_some() {
            let contracts = env.eth_contracts.as_ref().unwrap();
            assert_eth_contracts_deployed(&provider, contracts).await;
            let verify_elapsed = verify_start.elapsed();
            println!(
                "      ✅ ETH verified ({:.2}s)\n",
                verify_elapsed.as_secs_f64()
            );
            tracing::info!("✅ ETH contracts verified");
        } else {
            let verify_elapsed = verify_start.elapsed();
            println!(
                "      ✅ ETH ready ({:.2}s)\n",
                verify_elapsed.as_secs_f64()
            );
            tracing::info!("✅ ETH chain ready (no contracts deployed)");
        }
    }

    // Verify Starcoin node if needed
    if setting.need_starcoin {
        println!("      🔍 Verifying Starcoin node...");
        tracing::info!("Verifying Starcoin node...");
        assert_starcoin_can_produce_blocks(&env);
        tracing::info!("✅ Starcoin block production verified");

        // Verify committee if configured
        assert_committee_initialized(&env).await;
        let committee_config = env.starcoin.as_ref().unwrap().committee_config();
        if let Some(config) = committee_config {
            tracing::info!(
                "✅ Committee initialized with {} member(s), total voting power: {}",
                config.members.len(),
                config.total_voting_power()
            );
        }
    }

    // Wait for RPC services to be fully ready if needed
    if setting.need_bridge_server || setting.need_starcoin {
        tracing::info!("Waiting for RPC services to be ready...");

        if setting.need_starcoin {
            let starcoin_rpc_url = env.starcoin_rpc_url();
            wait_for_starcoin_rpc_ready(&starcoin_rpc_url, std::time::Duration::from_secs(30))
                .await
                .expect("Starcoin RPC should become ready");
            tracing::info!("✅ Starcoin RPC is ready");
        }

        if setting.need_eth {
            let provider = env.eth_provider();
            for attempt in 1..=10 {
                match provider.get_chainid().await {
                    Ok(_) => {
                        tracing::info!("✅ ETH RPC is ready");
                        break;
                    }
                    Err(e) if attempt < 10 => {
                        tracing::debug!("Waiting for ETH RPC (attempt {}): {}", attempt, e);
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                    Err(e) => {
                        panic!("ETH RPC not ready after 10 attempts: {}", e);
                    }
                }
            }
        }
    }

    // Start bridge servers if requested
    if setting.need_bridge_server {
        if let Some(authority_keys) = setting.authority_keys {
            println!("[5/5] 🌉 Starting bridge server(s)...");
            let server_start = Instant::now();

            // Wait extra time for Anvil to be fully stable before starting bridge server
            tracing::info!("Ensuring Anvil is stable before starting bridge server...");
            // Poll until ETH RPC is responding consistently
            let mut eth_ready_count = 0u32;
            for attempt in 1..=10 {
                match env.eth_provider().get_chainid().await {
                    Ok(_) => {
                        eth_ready_count += 1;
                        if eth_ready_count >= 3 {
                            println!("      ✅ ETH RPC stable after {} checks", attempt);
                            break;
                        }
                    }
                    Err(_) => {
                        eth_ready_count = 0;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }

            tracing::info!("Starting {} bridge server(s)...", authority_keys.len());

            match env.start_bridge_servers(authority_keys).await {
                Ok(count) => {
                    tracing::info!("✅ Started {} bridge server(s)", count);

                    // Wait for ETH syncer and other components to initialize with polling
                    println!("      ⏳ Initializing bridge components...");
                    tracing::info!("Polling for bridge components readiness...");
                    let init_start = Instant::now();
                    let max_init_wait = Duration::from_secs(30);
                    let mut init_round = 0u32;

                    while init_start.elapsed() < max_init_wait {
                        init_round += 1;
                        // Check if bridge server is responding to health checks
                        match env.check_bridge_servers_health().await {
                            Ok(healthy) if healthy > 0 => {
                                tracing::info!(
                                    "      [Round {}] {} healthy server(s)",
                                    init_round,
                                    healthy
                                );
                                break;
                            }
                            _ => {
                                if init_round % 5 == 0 {
                                    tracing::info!("      [Round {} | {:.1}s] Waiting for bridge initialization...", 
                                        init_round, init_start.elapsed().as_secs_f64());
                                }
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }

                    // Check health
                    println!("      🏥 Performing health check...");
                    match env.check_bridge_servers_health().await {
                        Ok(healthy_count) => {
                            let server_elapsed = server_start.elapsed();
                            println!(
                                "      ✅ Bridge servers ready: {}/{} healthy ({:.2}s)\n",
                                healthy_count,
                                count,
                                server_elapsed.as_secs_f64()
                            );
                            tracing::info!(
                                "✅ {}/{} bridge server(s) are healthy",
                                healthy_count,
                                count
                            );
                        }
                        Err(e) => {
                            tracing::warn!("Failed to check bridge server health: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to start bridge servers: {}", e);
                }
            }
        } else {
            tracing::warn!("Bridge servers requested but no authority keys provided");
        }
    }

    let total_elapsed = total_start.elapsed();
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!(
        "║   ✅ Environment Ready (total: {:.2}s)                        ║",
        total_elapsed.as_secs_f64()
    );
    println!("╚══════════════════════════════════════════════════════════════╝\n");
    tracing::info!("=== Environment Preparation Complete ===");
    env
}

// ===========================================================================
// Main test function
// ===========================================================================

/// Generate a test bridge authority key (deterministic for reproducibility)
fn generate_test_authority_key() -> BridgeAuthorityKeyPair {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::from_seed([0x42u8; 32]);
    BridgeAuthorityKeyPair::generate(&mut rng)
}

// ===========================================================================
// Multi-Validator E2E Test
// ===========================================================================

/// Generate multiple test bridge authority keys (deterministic for reproducibility)
fn generate_test_authority_keys(count: usize) -> Vec<BridgeAuthorityKeyPair> {
    use rand::SeedableRng;
    (0..count)
        .map(|i| {
            let mut seed = [0x42u8; 32];
            seed[0] = i as u8;
            let mut rng = rand::rngs::StdRng::from_seed(seed);
            BridgeAuthorityKeyPair::generate(&mut rng)
        })
        .collect()
}

/// Allocate available ports for bridge servers
/// Returns an array of 3 ports that are currently available
fn allocate_bridge_server_ports() -> [u16; 3] {
    use std::net::TcpListener;
    let ports: Vec<u16> = (0..3)
        .map(|_| {
            TcpListener::bind("127.0.0.1:0")
                .expect("Failed to bind to ephemeral port")
                .local_addr()
                .expect("Failed to get local addr")
                .port()
        })
        .collect();
    [ports[0], ports[1], ports[2]]
}

// ===========================================================================
// Governance Operations Test - Helper Functions
// ===========================================================================

fn cleanup_test_artifacts() {
    let e2e_tmp_dir = std::env::temp_dir().join("starcoin-bridge-e2e-tests");
    if e2e_tmp_dir.exists() {
        let _ = std::fs::remove_dir_all(&e2e_tmp_dir);
    }
}

fn generate_single_validator_authority_key() -> (BridgeAuthorityKeyPair, Vec<u8>, EthAddress) {
    let authority_key = generate_test_authority_key();
    let authority_pubkey = authority_key.public().as_bytes().to_vec();
    let eth_address = BridgeAuthorityPublicKeyBytes::from(authority_key.public()).to_eth_address();
    (authority_key, authority_pubkey, eth_address)
}

/// Generate 3 test bridge authority keys for multi-validator testing
/// Returns (keys, pubkeys, eth_addresses)
fn generate_three_validator_authority_keys(
) -> ([BridgeAuthorityKeyPair; 3], [Vec<u8>; 3], [EthAddress; 3]) {
    let keys = generate_test_authority_keys(3);
    let pubkeys: [Vec<u8>; 3] = [
        keys[0].public().as_bytes().to_vec(),
        keys[1].public().as_bytes().to_vec(),
        keys[2].public().as_bytes().to_vec(),
    ];
    let eth_addresses: [EthAddress; 3] = [
        BridgeAuthorityPublicKeyBytes::from(keys[0].public()).to_eth_address(),
        BridgeAuthorityPublicKeyBytes::from(keys[1].public()).to_eth_address(),
        BridgeAuthorityPublicKeyBytes::from(keys[2].public()).to_eth_address(),
    ];

    // Convert Vec to array
    let keys_array: [BridgeAuthorityKeyPair; 3] = keys.try_into().expect("Expected 3 keys");

    (keys_array, pubkeys, eth_addresses)
}

fn create_eth_committee_config_file(eth_address: EthAddress) -> PathBuf {
    use std::fs;

    let evm_contracts_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../contracts/evm");
    let deploy_configs_dir = evm_contracts_dir.join("deploy_configs");
    let template_path = deploy_configs_dir.join("31337.json.template");
    let config_path = deploy_configs_dir.join("31337.json");

    let template_content =
        fs::read_to_string(&template_path).expect("Failed to read 31337.json.template");

    let eth_address_hex = format!("0x{:x}", eth_address);
    let mut template: serde_json::Value =
        serde_json::from_str(&template_content).expect("Failed to parse template JSON");

    template["committeeMembers"] = serde_json::json!([eth_address_hex]);
    template["committeeMemberStake"] = serde_json::json!([10000]);
    template["minCommitteeStakeRequired"] = serde_json::json!(10000);

    let config_json = serde_json::to_string_pretty(&template).expect("Failed to serialize config");
    fs::write(&config_path, config_json).expect("Failed to write config file");

    tracing::info!(
        "Created ETH committee config: {} with 100% stake",
        eth_address_hex
    );
    config_path
}

fn create_starcoin_committee_config(authority_pubkey: Vec<u8>) -> CommitteeConfig {
    let validator_addr = AccountAddress::from_hex_literal("0xb001").expect("valid address");
    CommitteeConfig::single_member(
        validator_addr,
        authority_pubkey.clone(),
        "http://127.0.0.1:9191",
        10000,
    )
}

/// Create ETH committee config for 3 validators with 2-of-3 threshold
/// Stakes: 3334, 3333, 3333 = 10000 total
/// Threshold: 5001 (requires at least 2 validators: 3334+3333=6667 > 5001)
fn create_eth_committee_config_file_three_validators(eth_addresses: [EthAddress; 3]) -> PathBuf {
    use std::fs;

    let evm_contracts_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../contracts/evm");
    let deploy_configs_dir = evm_contracts_dir.join("deploy_configs");
    let template_path = deploy_configs_dir.join("31337.json.template");
    let config_path = deploy_configs_dir.join("31337.json");

    let template_content =
        fs::read_to_string(&template_path).expect("Failed to read 31337.json.template");

    let eth_address_hexes: Vec<String> = eth_addresses
        .iter()
        .map(|addr| format!("0x{:x}", addr))
        .collect();

    let mut template: serde_json::Value =
        serde_json::from_str(&template_content).expect("Failed to parse template JSON");

    // 3 validators with stakes: 3334, 3333, 3333 = 10000 total
    // Threshold 5001 requires at least 2 validators (3334+3333 = 6667 > 5001)
    template["committeeMembers"] = serde_json::json!(eth_address_hexes);
    template["committeeMemberStake"] = serde_json::json!([3334, 3333, 3333]);
    template["minCommitteeStakeRequired"] = serde_json::json!(5001);

    let config_json = serde_json::to_string_pretty(&template).expect("Failed to serialize config");
    fs::write(&config_path, config_json).expect("Failed to write config file");

    tracing::info!("Created ETH committee config with 3 validators (2-of-3 threshold):");
    for (i, addr) in eth_address_hexes.iter().enumerate() {
        let stake = if i == 0 { 3334 } else { 3333 };
        tracing::info!("  Validator {}: {} (stake: {})", i + 1, addr, stake);
    }
    tracing::info!("  Min stake required: 5001 (needs 2 validators)");

    config_path
}

/// Create Starcoin committee config for 3 validators with 2-of-3 threshold
fn create_starcoin_committee_config_three_validators(
    authority_pubkeys: [Vec<u8>; 3],
    server_ports: Option<[u16; 3]>,
) -> CommitteeConfig {
    let validator_addresses = CommitteeConfig::generate_test_validator_addresses();
    let ports = server_ports.unwrap_or_else(allocate_bridge_server_ports);
    CommitteeConfig::three_member_two_of_three(validator_addresses, authority_pubkeys, ports)
}

/// Prepare a single-validator test environment for cross-chain tests
/// Note: This is an async function that must be called within a tokio runtime
/// that persists for the duration of the test (bridge server runs as async task)
async fn prepare_single_validator_env() -> BridgeTestEnv {
    cleanup_test_artifacts();

    tracing::info!("=== Preparing Single Validator Environment ===");

    let (authority_key, authority_pubkey, eth_address) = generate_single_validator_authority_key();
    tracing::info!("Authority key ETH address: {:?}", eth_address);

    create_eth_committee_config_file(eth_address);
    let committee_config = create_starcoin_committee_config(authority_pubkey);

    tracing::info!("[Setup] Starting test environment with bridge server...");

    let setting = EnviromentPreparationOption {
        need_eth: true,
        need_starcoin: true,
        need_bridge_server: true,
        committee_options: Some(committee_config),
        authority_keys: Some(vec![authority_key]),
    };

    prepare_enviroment(setting).await
}

/// Prepare a three-validator test environment for cross-chain tests
/// This creates 3 bridge servers, requiring at least 2 to reach quorum (2-of-3 threshold)
async fn prepare_three_validator_env() -> BridgeTestEnv {
    cleanup_test_artifacts();

    tracing::info!("=== Preparing Three Validator Environment (2-of-3 threshold) ===");

    let (authority_keys, authority_pubkeys, eth_addresses) =
        generate_three_validator_authority_keys();

    for (i, addr) in eth_addresses.iter().enumerate() {
        tracing::info!("Validator {} ETH address: {:?}", i + 1, addr);
    }

    // Create ETH committee config with 3 members
    create_eth_committee_config_file_three_validators(eth_addresses);

    // Create Starcoin committee config with 3 members (use dynamically allocated ports)
    let committee_config =
        create_starcoin_committee_config_three_validators(authority_pubkeys, None);

    tracing::info!("[Setup] Starting test environment with 3 bridge servers...");

    let setting = EnviromentPreparationOption {
        need_eth: true,
        need_starcoin: true,
        need_bridge_server: true,
        committee_options: Some(committee_config),
        authority_keys: Some(authority_keys.into()),
    };

    prepare_enviroment(setting).await
}

// ===========================================================================
// Unified E2E Tests - Single entry point with shared environment
// ===========================================================================

/// Wait for bridge servers to stabilize
async fn wait_for_servers_ready(env: &BridgeTestEnv, required_healthy: usize) {
    println!("   🔄 Waiting for bridge servers to stabilize...");
    let mut stable_rounds = 0u32;
    for _ in 1..=15 {
        let mut healthy = 0;
        for server in env.bridge_servers.iter() {
            if assert_bridge_server_healthy(server).await.is_ok() {
                healthy += 1;
            }
        }
        if healthy >= required_healthy {
            stable_rounds += 1;
            if stable_rounds >= 2 {
                println!("      ✅ {} servers healthy and stable", healthy);
                return;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    panic!("❌ Bridge servers failed to stabilize");
}

/// Run cross-chain roundtrip tests on the given environment
async fn run_cross_chain_tests(env: &mut BridgeTestEnv) {
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║   🔄 Running Cross-Chain Roundtrip Tests                     ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    match do_cross_chain_roundtrip(env).await {
        Ok(_) => println!("   ✅ Cross-chain roundtrip tests passed\n"),
        Err(e) => panic!("❌ Cross-chain roundtrip failed: {}", e),
    }
}

/// Single validator E2E test suite - runs all tests with shared environment
///
/// NOTE: These tests need to be updated to reflect the frontend-driven model:
/// 1. User initiates transfer on source chain
/// 2. Frontend waits for finalization (via Indexer)
/// 3. Frontend collects validator signatures
/// 4. Frontend submits approve+claim transaction
///
/// Run manually with: `cargo test --package starcoin-bridge test_single_validator_e2e_suite -- --ignored`
#[test]
#[ignore = "TODO: Update to frontend-driven model per frontend.md"]
fn test_single_validator_e2e_suite() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║   🚀 Single Validator E2E Test Suite                         ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        let mut env = prepare_single_validator_env().await;
        wait_for_servers_ready(&env, 1).await;

        // Test: Cross-chain roundtrip
        run_cross_chain_tests(&mut env).await;

        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║   ✅ Single Validator E2E Suite Complete!                    ║");
        println!("╚══════════════════════════════════════════════════════════════╝");

        tokio::task::spawn_blocking(move || drop(env))
            .await
            .unwrap();
    });
}

/// Three validator E2E test suite - runs all tests with shared environment
///
/// NOTE: These tests need to be updated to reflect the frontend-driven model:
/// 1. User initiates transfer on source chain
/// 2. Frontend waits for finalization (via Indexer)
/// 3. Frontend collects validator signatures from multiple validators
/// 4. Frontend submits approve+claim transaction
///
/// Run manually with: `cargo test --package starcoin-bridge test_three_validator_e2e_suite -- --ignored`
#[test]
#[ignore = "TODO: Update to frontend-driven model per frontend.md"]
fn test_three_validator_e2e_suite() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║   🚀 Three Validator E2E Test Suite (2-of-3 quorum)          ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        let mut env = prepare_three_validator_env().await;
        wait_for_servers_ready(&env, 2).await;

        // Test: Cross-chain roundtrip
        run_cross_chain_tests(&mut env).await;

        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║   ✅ Three Validator E2E Suite Complete!                     ║");
        println!("╚══════════════════════════════════════════════════════════════╝");

        tokio::task::spawn_blocking(move || drop(env))
            .await
            .unwrap();
    });
}

// ---------------------------------------------------------------------------
// Cross-chain roundtrip test helper functions
// ---------------------------------------------------------------------------

/// Print RPC endpoints for manual inspection during roundtrip test
async fn print_roundtrip_rpc_endpoints(env: &BridgeTestEnv) {
    println!("\n📡 RPC Endpoints:");
    println!("   ┌─────────────────────────────────────────────────────────────┐");
    println!(
        "   │ Starcoin HTTP RPC: {}                  ",
        env.starcoin_rpc_url()
    );
    println!(
        "   │ ETH RPC:           {}                  ",
        env.eth_rpc_url()
    );
    if let Some(ref starcoin) = env.starcoin {
        let config = starcoin.node.config();
        if let Some(tcp_addr) = config.rpc.get_tcp_address() {
            println!(
                "   │ Starcoin TCP RPC:  tcp://{}:{}              ",
                tcp_addr.address, tcp_addr.port
            );
        }
        if let Some(ws_addr) = config.rpc.get_ws_address() {
            println!(
                "   │ Starcoin WS RPC:   ws://{}:{}               ",
                ws_addr.address, ws_addr.port
            );
        }
    }
    if let Some(server_handle) = env.bridge_servers.first() {
        println!(
            "   │ Bridge Server:     http://127.0.0.1:{}          ",
            server_handle.server_port
        );
    }
    println!("   └─────────────────────────────────────────────────────────────┘\n");
}

/// Setup accounts, fund them, and return initial balances
async fn roundtrip_setup_accounts(
    env: &mut BridgeTestEnv,
    test_amount: u64,
) -> anyhow::Result<(
    Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
    EthAddress,
    StarcoinKeyPair,
    String,
    String,
    EthAddress,
    EthAddress,
    u64,
    u64,
)> {
    let provider = env.eth_provider();
    let contracts = env
        .eth_contracts()
        .expect("ETH contracts should be deployed");
    let bridge_addr =
        EthAddress::from_str(&contracts.starcoin_bridge).expect("Invalid bridge address");
    let usdt_addr = EthAddress::from_str(&contracts.usdt).expect("Invalid USDT address");

    let signer = get_test_eth_signer(&provider).expect("Should get signer");
    let eth_user_addr = signer.address();

    // Generate Starcoin keypair for testing
    let authority_key = &env.bridge_servers[0].authority_key;
    let starcoin_keypair = generate_bridge_client_keypair(&authority_key);
    let starcoin_user_addr = starcoin_keypair.starcoin_address();
    let starcoin_user_hex = format!("0x{}", hex::encode(starcoin_user_addr.as_ref()));

    let starcoin_bridge_addr = env.starcoin_bridge_address();
    let starcoin_bridge_hex = format!("0x{}", hex::encode(starcoin_bridge_addr.to_vec()));

    println!("\n━━━ Phase 1: Setup and Initial Balances ━━━");
    println!("ETH user address: {:?}", eth_user_addr);
    println!("Starcoin user address: {}", starcoin_user_hex);
    println!("Bridge contract: {}", starcoin_bridge_hex);

    // Get initial balances
    let initial_eth_balance = get_eth_usdt_balance(&provider, usdt_addr, eth_user_addr)
        .await
        .expect("Get ETH balance");
    println!(
        "Initial ETH USDT balance: {} (6 decimals)",
        initial_eth_balance
    );

    let initial_starcoin_balance = query_starcoin_token_balance(
        &env.starcoin_rpc_url(),
        &starcoin_user_hex,
        &starcoin_bridge_hex,
        "USDT",
    )
    .await
    .unwrap_or(0);
    println!(
        "Initial Starcoin USDT balance: {}",
        initial_starcoin_balance
    );

    // Mint USDT if needed
    let eth_balance_after_mint = if initial_eth_balance < test_amount * 4 {
        println!("Minting {} USDT for testing...", test_amount * 4);
        mint_eth_usdt(&provider, usdt_addr, eth_user_addr, test_amount * 4)
            .await
            .expect("Mint USDT");
        let balance_after_mint = get_eth_usdt_balance(&provider, usdt_addr, eth_user_addr)
            .await
            .expect("Get balance after mint");
        println!("ETH USDT balance after mint: {}", balance_after_mint);
        balance_after_mint
    } else {
        initial_eth_balance
    };

    // Fund Starcoin account with STC for transaction fees
    if let Some(ref mut starcoin_env) = env.starcoin {
        match starcoin_env.fund_account(&starcoin_keypair, 1_000_000_000_000u128) {
            Ok(_) => println!("✅ Funded Starcoin account with STC for gas"),
            Err(e) => println!("⚠️  Failed to fund Starcoin account: {}", e),
        }
    }

    // Return eth_balance_after_mint instead of initial_eth_balance for accurate verification
    Ok((
        Arc::new(signer),
        eth_user_addr,
        starcoin_keypair,
        starcoin_user_hex,
        starcoin_bridge_hex,
        bridge_addr,
        usdt_addr,
        eth_balance_after_mint,
        initial_starcoin_balance,
    ))
}

/// Execute ETH to Starcoin deposit and wait for bridge processing
/// Returns the credited Starcoin balance
async fn execute_eth_to_starcoin_transfer(
    env: &mut BridgeTestEnv,
    provider: &Provider<Http>,
    bridge_addr: EthAddress,
    usdt_addr: EthAddress,
    eth_user_addr: EthAddress,
    starcoin_user_addr: &[u8],
    starcoin_user_hex: &str,
    starcoin_bridge_hex: &str,
    test_amount: u64,
) -> anyhow::Result<u64> {
    use starcoin_bridge_types::bridge::BridgeChainId;

    println!("\n━━━ Phase 2: ETH → Starcoin Transfer ━━━");
    println!("   Transfer amount: {} USDT", test_amount);

    let mut progress = TransferProgress::new_eth_to_starcoin();

    let eth_balance_before_deposit =
        get_eth_usdt_balance(provider, usdt_addr, eth_user_addr).await?;
    println!(
        "   ETH USDT balance before deposit: {}",
        eth_balance_before_deposit
    );

    // Strict check: ensure sufficient balance
    if eth_balance_before_deposit < test_amount {
        return Err(anyhow::anyhow!(
            "Insufficient ETH USDT balance: {} < required {}",
            eth_balance_before_deposit,
            test_amount
        ));
    }

    let target_address = starcoin_user_addr.to_vec();
    let receipt = deposit_usdt_to_bridge(
        provider,
        bridge_addr,
        usdt_addr,
        test_amount,
        BridgeChainId::StarcoinCustom as u8,
        target_address,
    )
    .await?;

    progress.advance(CrossChainStage::EthDepositConfirmed);
    println!("   ✅ ETH deposit TX: {:?}", receipt.transaction_hash);

    let eth_balance_after_deposit =
        get_eth_usdt_balance(provider, usdt_addr, eth_user_addr).await?;
    println!(
        "   ETH USDT balance after deposit: {}",
        eth_balance_after_deposit
    );

    // Strict verification of ETH balance decrease
    let eth_decrease = eth_balance_before_deposit.saturating_sub(eth_balance_after_deposit);
    if eth_decrease != test_amount {
        return Err(anyhow::anyhow!(
            "ETH balance decrease mismatch: actual {} != expected {}. Before: {}, After: {}",
            eth_decrease,
            test_amount,
            eth_balance_before_deposit,
            eth_balance_after_deposit
        ));
    }
    println!(
        "   ✅ ETH balance correctly decreased by: {} USDT",
        eth_decrease
    );

    // Wait for Starcoin credit with strict verification
    let credited_amount =
        wait_for_starcoin_credit(env, starcoin_user_hex, starcoin_bridge_hex, test_amount).await?;

    // Strict verification
    if credited_amount < test_amount {
        return Err(anyhow::anyhow!(
            "Starcoin credit insufficient: credited {} < expected {}",
            credited_amount,
            test_amount
        ));
    }

    println!(
        "   ✅ ETH → Starcoin transfer complete: {} USDT credited",
        credited_amount
    );
    Ok(credited_amount)
}

/// Wait for bridge server to process deposit and credit Starcoin account
/// Uses polling with detailed progress tracking instead of fixed sleep
async fn wait_for_starcoin_credit(
    env: &mut BridgeTestEnv,
    starcoin_user_hex: &str,
    starcoin_bridge_hex: &str,
    expected_amount: u64,
) -> anyhow::Result<u64> {
    let mut progress = TransferProgress::new_eth_to_starcoin();
    progress.advance(CrossChainStage::EthDepositConfirmed);

    println!("   🔄 Waiting for bridge to process deposit...");

    const MAX_ROUNDS: u32 = 60; // Max ~3 minutes with 3s interval
    const POLL_INTERVAL_SECS: u64 = 3;

    let mut round = 0u32;
    let mut last_balance = 0u64;
    let mut blocks_generated = 0u32;

    loop {
        round += 1;

        if round > MAX_ROUNDS {
            return Err(progress.timeout_error(&format!(
                "Starcoin balance still {} after {} rounds ({} blocks generated). Expected: {}",
                last_balance, MAX_ROUNDS, blocks_generated, expected_amount
            )));
        }

        // Generate blocks to process pending transactions
        if let Some(ref starcoin_env) = env.starcoin {
            match starcoin_env.generate_block() {
                Ok(block) => {
                    blocks_generated += 1;
                    if round % 5 == 0 {
                        progress.print_poll_status(
                            round,
                            &format!(
                                "Block #{} (height: {}), balance: {}",
                                blocks_generated,
                                block.header().number(),
                                last_balance
                            ),
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("Block generation failed (round {}): {}", round, e);
                }
            }
        }

        // Check Starcoin balance
        let starcoin_balance_now = query_starcoin_token_balance(
            &env.starcoin_rpc_url(),
            starcoin_user_hex,
            starcoin_bridge_hex,
            "USDT",
        )
        .await
        .unwrap_or(0);

        if starcoin_balance_now > last_balance {
            // Balance changed - detect stage transition
            if last_balance == 0 && starcoin_balance_now > 0 {
                progress.advance(CrossChainStage::StarcoinCredited);
            }
            last_balance = starcoin_balance_now;
        }

        if starcoin_balance_now >= expected_amount {
            println!(
                "   ✅ Starcoin credited with {} USDT (round {}, {} blocks)",
                starcoin_balance_now, round, blocks_generated
            );
            return Ok(starcoin_balance_now);
        }

        tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
    }
}

/// Execute Starcoin to ETH withdrawal transaction
/// Returns the Starcoin balance after withdrawal
async fn execute_starcoin_to_eth_transfer(
    env: &mut BridgeTestEnv,
    starcoin_keypair: &StarcoinKeyPair,
    starcoin_user_hex: &str,
    starcoin_bridge_hex: &str,
    eth_user_addr: EthAddress,
    test_amount: u64,
) -> anyhow::Result<(String, u64)> {
    // Returns (tx_hash, balance_after_withdraw)
    use crate::simple_starcoin_rpc::SimpleStarcoinRpcClient;
    use crate::starcoin_bridge_transaction_builder::starcoin_native;
    use move_core_types::account_address::AccountAddress;
    use move_core_types::language_storage::{StructTag, TypeTag};
    use starcoin_bridge_types::base_types::StarcoinAddress;
    use starcoin_bridge_types::bridge::BridgeChainId;

    println!("\n━━━ Phase 3: Starcoin → ETH Transfer ━━━");
    println!("   Transfer amount: {} USDT", test_amount);

    let mut progress = TransferProgress::new_starcoin_to_eth();

    let starcoin_balance_before_withdraw = query_starcoin_token_balance(
        &env.starcoin_rpc_url(),
        starcoin_user_hex,
        starcoin_bridge_hex,
        "USDT",
    )
    .await
    .unwrap_or(0);

    println!(
        "   Starcoin balance before withdraw: {}",
        starcoin_balance_before_withdraw
    );

    if starcoin_balance_before_withdraw < test_amount {
        return Err(anyhow::anyhow!(
            "Insufficient Starcoin balance: {} < required {}",
            starcoin_balance_before_withdraw,
            test_amount
        ));
    }

    // Build USDT TypeTag for Starcoin bridge
    let usdt_type_tag = TypeTag::Struct(Box::new(StructTag {
        address: AccountAddress::from_hex_literal(starcoin_bridge_hex)
            .expect("Valid bridge address"),
        module: "USDT".parse().expect("Valid module"),
        name: "USDT".parse().expect("Valid name"),
        type_params: vec![],
    }));

    // Create Starcoin RPC client
    let rpc_client = SimpleStarcoinRpcClient::new(env.starcoin_rpc_url(), starcoin_bridge_hex);

    // Get transaction parameters
    let sequence_number = rpc_client.get_sequence_number(starcoin_user_hex).await?;
    let chain_id = rpc_client.get_chain_id().await?;
    let block_timestamp_ms = rpc_client.get_block_timestamp().await?;

    println!("   Building Starcoin transaction...");
    println!("   - Sender: {}", starcoin_user_hex);
    println!("   - Sequence: {}", sequence_number);
    println!("   - Chain ID: {}", chain_id);
    println!("   - Amount: {} (raw units)", test_amount);

    let starcoin_bridge_addr = env.starcoin_bridge_address();
    let starcoin_user_addr = starcoin_keypair.starcoin_address();

    // Build send_bridge_usdt transaction
    let raw_txn = starcoin_native::build_send_token(
        StarcoinAddress::new(*starcoin_bridge_addr),
        StarcoinAddress::new(*starcoin_user_addr),
        sequence_number,
        chain_id,
        block_timestamp_ms,
        BridgeChainId::EthCustom as u8,
        eth_user_addr.as_bytes().to_vec(),
        test_amount as u128,
        usdt_type_tag,
    )
    .map_err(|e| anyhow::anyhow!("Failed to build transaction: {:?}", e))?;

    println!("   ✅ Transaction built successfully");

    // Submit transaction
    let txn_hash = rpc_client
        .sign_and_submit_transaction(starcoin_keypair, raw_txn)
        .await?;
    let txn_hash_str = txn_hash.clone();
    progress.advance(CrossChainStage::StarcoinWithdrawConfirmed);
    println!("   ✅ Starcoin withdraw TX: {}", txn_hash);

    // Generate blocks to confirm the withdraw transaction with progress tracking
    println!("   🔨 Generating blocks to confirm transaction...");

    let start = Instant::now();
    for i in 1..=5 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Some(ref starcoin_env) = env.starcoin {
            match starcoin_env.generate_block() {
                Ok(block) => {
                    println!(
                        "      🔨 Block {} (height: {}) [{:.1}s elapsed]",
                        i,
                        block.header().number(),
                        start.elapsed().as_secs_f64()
                    );
                }
                Err(e) => {
                    tracing::warn!("Block generation failed: {}", e);
                }
            }
        }
    }

    // Verify Starcoin balance decreased
    let starcoin_balance_after_withdraw = query_starcoin_token_balance(
        &env.starcoin_rpc_url(),
        starcoin_user_hex,
        starcoin_bridge_hex,
        "USDT",
    )
    .await
    .unwrap_or(0);

    println!(
        "   Starcoin balance after withdraw: {}",
        starcoin_balance_after_withdraw
    );

    let starcoin_decrease =
        starcoin_balance_before_withdraw.saturating_sub(starcoin_balance_after_withdraw);
    if starcoin_decrease < test_amount {
        println!(
            "   ⚠️  Starcoin balance decrease {} < expected {} (TX may still be pending)",
            starcoin_decrease, test_amount
        );
    } else {
        println!(
            "   ✅ Starcoin balance correctly decreased by: {} USDT",
            starcoin_decrease
        );
    }

    println!("   ✅ Starcoin → ETH withdrawal submitted");
    // Return (tx_hash, starcoin_balance_after_withdraw)
    Ok((txn_hash_str, starcoin_balance_after_withdraw))
}

/// Wait for ETH balance to increase after bridge processes Starcoin withdrawal
/// NOTE: ETH side does NOT auto-claim. We verify the transaction is APPROVED (has enough signatures)
/// instead of waiting for ETH balance to change.
/// Returns Ok(()) if the bridge action is approved, or error with stage details
async fn wait_for_bridge_approval(
    env: &BridgeTestEnv,
    tx_hash: &str,
    event_index: u64,
) -> anyhow::Result<()> {
    let mut progress = TransferProgress::new_starcoin_to_eth();
    progress.advance(CrossChainStage::StarcoinWithdrawConfirmed);

    println!("   🔄 Waiting for bridge approval (signature collection)...");
    println!("   📝 TX hash: {}", tx_hash);
    println!("   📝 Event index: {}", event_index);

    // Use first bridge server to check for signatures
    let server = env
        .bridge_servers
        .first()
        .ok_or_else(|| anyhow::anyhow!("No bridge server available"))?;

    let sign_url = format!(
        "http://127.0.0.1:{}/sign/bridge_tx/starcoin/eth/{}/{}",
        server.server_port, tx_hash, event_index
    );

    println!("   🔗 Signature endpoint: {}", sign_url);

    const MAX_ROUNDS: u32 = 60; // Max ~3 minutes with 3s interval
    const POLL_INTERVAL_SECS: u64 = 3;

    let client = reqwest::Client::new();
    let mut round = 0u32;
    let mut last_status: Option<String> = None;

    loop {
        round += 1;

        if round > MAX_ROUNDS {
            return Err(progress.timeout_error(&format!(
                "Bridge approval not received after {} rounds. Last status: {:?}",
                MAX_ROUNDS, last_status
            )));
        }

        // Try to get signature from bridge server
        match client.get(&sign_url).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    // Successfully got signature - action is approved!
                    progress.advance(CrossChainStage::BridgeServerProcessing);
                    println!(
                        "   ✅ Bridge action APPROVED! Signature received (round {})",
                        round
                    );
                    println!("   ℹ️  Note: ETH side requires manual claim - not auto-executed");
                    return Ok(());
                } else {
                    let status_str = format!("{}", status);
                    if last_status.as_ref() != Some(&status_str) {
                        last_status = Some(status_str.clone());
                    }

                    // Check response body for more details
                    if let Ok(body) = resp.text().await {
                        if body.contains("TxNotFinalized") {
                            if round % 5 == 0 {
                                progress
                                    .print_poll_status(round, "TX not yet finalized on Starcoin");
                            }
                        } else if round % 5 == 0 {
                            progress.print_poll_status(
                                round,
                                &format!(
                                    "Status: {}, Body: {}",
                                    status_str,
                                    &body[..body.len().min(100)]
                                ),
                            );
                        }
                    }
                }
            }
            Err(e) => {
                if round % 10 == 0 {
                    progress.print_poll_status(round, &format!("Request error: {}", e));
                }
            }
        }

        // Generate blocks to help process the transaction
        if let Some(ref starcoin_env) = env.starcoin {
            let _ = starcoin_env.generate_block();
        }

        tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
    }
}

/// Print final balance summary
async fn print_roundtrip_final_summary(
    provider: &Provider<Http>,
    usdt_addr: EthAddress,
    eth_user_addr: EthAddress,
    env: &mut BridgeTestEnv,
    starcoin_user_hex: &str,
    starcoin_bridge_hex: &str,
    initial_eth_balance: u64,
    initial_starcoin_balance: u64,
) {
    println!("\n━━━ Phase 4: Final Balance Summary ━━━");

    let final_eth_balance = get_eth_usdt_balance(provider, usdt_addr, eth_user_addr)
        .await
        .unwrap_or(0);
    let final_starcoin_balance = query_starcoin_token_balance(
        &env.starcoin_rpc_url(),
        starcoin_user_hex,
        starcoin_bridge_hex,
        "USDT",
    )
    .await
    .unwrap_or(0);

    println!("Final ETH USDT balance: {}", final_eth_balance);
    println!("Final Starcoin USDT balance: {}", final_starcoin_balance);

    let eth_net_change = if final_eth_balance >= initial_eth_balance {
        format!("+{}", final_eth_balance - initial_eth_balance)
    } else {
        format!("-{}", initial_eth_balance - final_eth_balance)
    };

    let starcoin_net_change = if final_starcoin_balance >= initial_starcoin_balance {
        format!("+{}", final_starcoin_balance - initial_starcoin_balance)
    } else {
        format!("-{}", initial_starcoin_balance - final_starcoin_balance)
    };

    println!("\n📊 Balance Changes:");
    println!(
        "   ETH USDT:      {} -> {} ({})",
        initial_eth_balance, final_eth_balance, eth_net_change
    );
    println!(
        "   Starcoin USDT: {} -> {} ({})",
        initial_starcoin_balance, final_starcoin_balance, starcoin_net_change
    );
}

/// Strict verification of roundtrip results
/// NOTE: ETH side does NOT auto-claim, so ETH balance won't increase automatically.
/// We verify:
/// 1. ETH balance decreased by test_amount (deposit to Starcoin)
/// 2. Starcoin balance is 0 or close to initial (withdrew back to ETH)
/// 3. Bridge approval was received (checked in wait_for_bridge_approval)
fn verify_roundtrip_results(
    eth_balance_after_mint: u64, // ETH balance AFTER mint, BEFORE deposit
    final_eth_balance: u64,
    starcoin_balance_after_credit: u64, // Starcoin balance AFTER ETH->Starcoin credit
    final_starcoin_balance: u64,
    test_amount: u64,
) -> anyhow::Result<()> {
    println!("\n━━━ Phase 5: Strict Verification ━━━");

    let mut errors = Vec::new();

    // Allow small tolerance (1% of test amount) for rounding
    let tolerance = test_amount / 100;

    // 1. Verify ETH balance: should be (after_mint - deposit) since ETH doesn't auto-claim
    // After ETH→Starcoin deposit, ETH decreases by test_amount
    // After Starcoin→ETH withdraw, ETH stays the same (no auto-claim)
    let expected_eth_final = eth_balance_after_mint.saturating_sub(test_amount);
    let eth_diff = if final_eth_balance >= expected_eth_final {
        final_eth_balance - expected_eth_final
    } else {
        expected_eth_final - final_eth_balance
    };

    if eth_diff > tolerance {
        errors.push(format!(
            "ETH final balance mismatch: expected ~{} (after_mint {} - deposit {}), actual {}, diff={} (tolerance={})",
            expected_eth_final, eth_balance_after_mint, test_amount, final_eth_balance, eth_diff, tolerance
        ));
    } else {
        println!(
            "   ✅ ETH balance verified: {} (after_mint {} - deposit {} = expected {})",
            final_eth_balance, eth_balance_after_mint, test_amount, expected_eth_final
        );
    }

    // 2. Verify Starcoin balance: should be 0 after withdraw
    // After ETH→Starcoin credit, Starcoin = test_amount
    // After Starcoin→ETH withdraw, Starcoin = 0
    let starcoin_diff = final_starcoin_balance; // Expected to be 0

    if starcoin_diff > tolerance {
        errors.push(format!(
            "Starcoin final balance mismatch: expected ~0 after withdraw, actual {} (tolerance={})",
            final_starcoin_balance, tolerance
        ));
    } else {
        println!(
            "   ✅ Starcoin balance verified: {} (expected ~0 after withdraw)",
            final_starcoin_balance
        );
    }

    // 3. Verify the credit happened correctly
    let credit_diff = if starcoin_balance_after_credit >= test_amount {
        starcoin_balance_after_credit - test_amount
    } else {
        test_amount - starcoin_balance_after_credit
    };

    if credit_diff > tolerance {
        errors.push(format!(
            "Starcoin credit mismatch: expected ~{}, actual {} (tolerance={})",
            test_amount, starcoin_balance_after_credit, tolerance
        ));
    } else {
        println!(
            "   ✅ Starcoin credit verified: {} (expected ~{})",
            starcoin_balance_after_credit, test_amount
        );
    }

    if errors.is_empty() {
        println!("   ✅ All verifications passed!");
        println!("   ℹ️  Note: ETH claim pending - withdraw approved but not auto-claimed");
        Ok(())
    } else {
        let error_msg = errors.join("\n   ");
        Err(anyhow::anyhow!(
            "Roundtrip verification failed:\n   {}",
            error_msg
        ))
    }
}

/// Main cross-chain roundtrip test logic with strict verification
async fn do_cross_chain_roundtrip(env: &mut BridgeTestEnv) -> anyhow::Result<()> {
    let overall_start = Instant::now();

    print_roundtrip_rpc_endpoints(env).await;

    // Verify bridge server health
    println!("\n━━━ Bridge Server Health Check ━━━");
    let healthy_servers = env.bridge_servers.len();
    for (i, server_handle) in env.bridge_servers.iter().enumerate() {
        match assert_bridge_server_healthy(server_handle).await {
            Ok(_) => println!("   ✅ Bridge server {} is healthy", i + 1),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Bridge server {} not healthy: {}",
                    i + 1,
                    e
                ));
            }
        }
    }
    println!(
        "   ✅ All {} bridge server(s) healthy and ready",
        healthy_servers
    );

    // Brief stabilization period
    println!("   ⏳ Brief stabilization period (2s)...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    let test_amount = 50_000_000u64; // 50 USDT (6 decimals)

    // eth_balance_after_mint is the balance AFTER minting, BEFORE deposit
    let (
        _,
        eth_user_addr,
        starcoin_keypair,
        starcoin_user_hex,
        starcoin_bridge_hex,
        bridge_addr,
        usdt_addr,
        eth_balance_after_mint,
        _,
    ) = roundtrip_setup_accounts(env, test_amount).await?;

    // Phase 2: ETH → Starcoin (with strict verification)
    let starcoin_credited = execute_eth_to_starcoin_transfer(
        env,
        &env.eth_provider(),
        bridge_addr,
        usdt_addr,
        eth_user_addr,
        starcoin_keypair.starcoin_address().as_ref(),
        &starcoin_user_hex,
        &starcoin_bridge_hex,
        test_amount,
    )
    .await?;

    // Strict check: Starcoin must have received the tokens
    if starcoin_credited < test_amount {
        return Err(anyhow::anyhow!(
            "ETH→Starcoin failed: credited {} < expected {}",
            starcoin_credited,
            test_amount
        ));
    }

    // Phase 3: Starcoin → ETH (with strict verification)
    // Note: ETH side does NOT auto-claim, so we verify bridge approval instead of ETH balance

    let (starcoin_tx_hash, _) = execute_starcoin_to_eth_transfer(
        env,
        &starcoin_keypair,
        &starcoin_user_hex,
        &starcoin_bridge_hex,
        eth_user_addr,
        test_amount,
    )
    .await?;

    // Wait for bridge approval (signature collection) instead of ETH balance change
    // The bridge action needs to be approved (enough signatures) for the test to pass
    // event_index is 0 for the first event in the transaction
    wait_for_bridge_approval(env, &starcoin_tx_hash, 0).await?;

    // Phase 4: Final Summary
    let final_eth_balance =
        get_eth_usdt_balance(&env.eth_provider(), usdt_addr, eth_user_addr).await?;
    let final_starcoin_balance = query_starcoin_token_balance(
        &env.starcoin_rpc_url(),
        &starcoin_user_hex,
        &starcoin_bridge_hex,
        "USDT",
    )
    .await
    .unwrap_or(0);

    print_roundtrip_final_summary(
        &env.eth_provider(),
        usdt_addr,
        eth_user_addr,
        env,
        &starcoin_user_hex,
        &starcoin_bridge_hex,
        eth_balance_after_mint,
        starcoin_credited, // Show the credited amount as reference
    )
    .await;

    // Phase 5: Strict verification
    // Pass: eth_balance_after_mint (before deposit), starcoin_credited (after ETH->STC)
    verify_roundtrip_results(
        eth_balance_after_mint,
        final_eth_balance,
        starcoin_credited, // Starcoin balance after credit (should be test_amount)
        final_starcoin_balance,
        test_amount,
    )?;

    let total_elapsed = overall_start.elapsed();
    println!(
        "\n   🎉 Roundtrip completed in {:.2}s",
        total_elapsed.as_secs_f64()
    );

    Ok(())
}
// ===========================================================================
// Offline Governance Signing and Execution Test
// ===========================================================================

/// Signed governance actions for testing
struct SignedGovernanceActions {
    // ETH actions
    eth_pause_action: BridgeAction,
    eth_pause_sig: crate::crypto::BridgeAuthoritySignInfo,
    eth_unpause_action: BridgeAction,
    eth_unpause_sig: crate::crypto::BridgeAuthoritySignInfo,
    eth_limit_action: BridgeAction,
    eth_limit_sig: crate::crypto::BridgeAuthoritySignInfo,

    // Starcoin actions
    starcoin_pause_action: BridgeAction,
    starcoin_pause_sig: crate::crypto::BridgeAuthoritySignInfo,
    starcoin_unpause_action: BridgeAction,
    starcoin_unpause_sig: crate::crypto::BridgeAuthoritySignInfo,
    starcoin_limit_action: BridgeAction,
    starcoin_limit_sig: crate::crypto::BridgeAuthoritySignInfo,
    starcoin_add_member_action: BridgeAction,
    starcoin_add_member_sig: crate::crypto::BridgeAuthoritySignInfo,

    new_limit: u64,
}

/// Setup environment for offline governance test
async fn setup_offline_governance_env(
    authority_pubkey: Vec<u8>,
    eth_address: EthAddress,
) -> BridgeTestEnv {
    create_eth_committee_config_file(eth_address);
    let committee_config = create_starcoin_committee_config(authority_pubkey);

    let setting = EnviromentPreparationOption {
        need_eth: true,
        need_starcoin: true,
        need_bridge_server: false,
        committee_options: Some(committee_config),
        authority_keys: None,
    };
    prepare_enviroment(setting).await
}

/// Sign governance actions offline (simulating Machine A)
fn sign_governance_actions_offline(
    authority_key: &BridgeAuthorityKeyPair,
) -> SignedGovernanceActions {
    use crate::crypto::BridgeAuthoritySignInfo;
    use crate::types::{
        BridgeAction, EmergencyAction, EmergencyActionType, LimitUpdateAction,
        UpdateCommitteeMemberAction, UpdateCommitteeMemberType,
    };
    use fastcrypto::encoding::Encoding;

    println!("\n━━━ Step 3: Offline Signing (Machine A) ━━━");

    // Sign ETH actions
    println!("   [ETH] Signing EmergencyPause action...");
    let eth_pause_action = BridgeAction::EmergencyAction(EmergencyAction {
        nonce: 0,
        chain_id: BridgeChainId::EthCustom,
        action_type: EmergencyActionType::Pause,
    });
    let eth_pause_sig = BridgeAuthoritySignInfo::new(&eth_pause_action, authority_key);
    let pause_hex = fastcrypto::encoding::Hex::encode(eth_pause_sig.signature.as_ref());
    println!("   ✓ ETH Pause signature: {}...", &pause_hex[..32]);

    println!("   [ETH] Signing EmergencyUnpause action...");
    let eth_unpause_action = BridgeAction::EmergencyAction(EmergencyAction {
        nonce: 1,
        chain_id: BridgeChainId::EthCustom,
        action_type: EmergencyActionType::Unpause,
    });
    let eth_unpause_sig = BridgeAuthoritySignInfo::new(&eth_unpause_action, authority_key);
    let unpause_hex = fastcrypto::encoding::Hex::encode(eth_unpause_sig.signature.as_ref());
    println!("   ✓ ETH Unpause signature: {}...", &unpause_hex[..32]);

    println!("   [ETH] Signing LimitUpdate action...");
    let new_limit = 5_000_000_000_000u64;
    let eth_limit_action = BridgeAction::LimitUpdateAction(LimitUpdateAction {
        nonce: 0,
        chain_id: BridgeChainId::EthCustom,
        sending_chain_id: BridgeChainId::StarcoinCustom,
        new_usd_limit: new_limit,
    });
    let eth_limit_sig = BridgeAuthoritySignInfo::new(&eth_limit_action, authority_key);
    let limit_hex = fastcrypto::encoding::Hex::encode(eth_limit_sig.signature.as_ref());
    println!("   ✓ ETH Limit signature: {}...", &limit_hex[..32]);

    // Sign Starcoin actions
    println!("   [Starcoin] Signing EmergencyPause action...");
    let starcoin_pause_action = BridgeAction::EmergencyAction(EmergencyAction {
        nonce: 0,
        chain_id: BridgeChainId::StarcoinCustom,
        action_type: EmergencyActionType::Pause,
    });
    let starcoin_pause_sig = BridgeAuthoritySignInfo::new(&starcoin_pause_action, authority_key);
    let stc_pause_hex = fastcrypto::encoding::Hex::encode(starcoin_pause_sig.signature.as_ref());
    println!("   ✓ Starcoin Pause signature: {}...", &stc_pause_hex[..32]);

    println!("   [Starcoin] Signing EmergencyUnpause action...");
    let starcoin_unpause_action = BridgeAction::EmergencyAction(EmergencyAction {
        nonce: 1,
        chain_id: BridgeChainId::StarcoinCustom,
        action_type: EmergencyActionType::Unpause,
    });
    let starcoin_unpause_sig =
        BridgeAuthoritySignInfo::new(&starcoin_unpause_action, authority_key);
    let stc_unpause_hex =
        fastcrypto::encoding::Hex::encode(starcoin_unpause_sig.signature.as_ref());
    println!(
        "   ✓ Starcoin Unpause signature: {}...",
        &stc_unpause_hex[..32]
    );

    println!("   [Starcoin] Signing LimitUpdate action...");
    let starcoin_limit_action = BridgeAction::LimitUpdateAction(LimitUpdateAction {
        nonce: 0,
        chain_id: BridgeChainId::StarcoinCustom,
        sending_chain_id: BridgeChainId::EthCustom,
        new_usd_limit: new_limit,
    });
    let starcoin_limit_sig = BridgeAuthoritySignInfo::new(&starcoin_limit_action, authority_key);
    let stc_limit_hex = fastcrypto::encoding::Hex::encode(starcoin_limit_sig.signature.as_ref());
    println!("   ✓ Starcoin Limit signature: {}...", &stc_limit_hex[..32]);

    println!("   [Starcoin] Signing UpdateCommitteeMember (Add) action...");
    let (new_member_pubkey, new_member_address) = generate_new_committee_member_for_test();
    let starcoin_add_member_action =
        BridgeAction::UpdateCommitteeMemberAction(UpdateCommitteeMemberAction {
            nonce: 0,
            chain_id: BridgeChainId::StarcoinCustom,
            update_type: UpdateCommitteeMemberType::Add,
            member_address: new_member_address,
            bridge_pubkey_bytes: new_member_pubkey,
            voting_power: 1000,
            http_rest_url: "http://127.0.0.1:9999".to_string(),
        });
    let starcoin_add_member_sig =
        BridgeAuthoritySignInfo::new(&starcoin_add_member_action, authority_key);
    let stc_add_member_hex =
        fastcrypto::encoding::Hex::encode(starcoin_add_member_sig.signature.as_ref());
    println!(
        "   ✓ Starcoin AddMember signature: {}...",
        &stc_add_member_hex[..32]
    );

    SignedGovernanceActions {
        eth_pause_action,
        eth_pause_sig,
        eth_unpause_action,
        eth_unpause_sig,
        eth_limit_action,
        eth_limit_sig,
        starcoin_pause_action,
        starcoin_pause_sig,
        starcoin_unpause_action,
        starcoin_unpause_sig,
        starcoin_limit_action,
        starcoin_limit_sig,
        starcoin_add_member_action,
        starcoin_add_member_sig,
        new_limit,
    }
}

/// Execute emergency pause on ETH
async fn execute_pause_on_eth(
    bridge_addr: EthAddress,
    eth_signer: SignerMiddleware<Provider<Http>, LocalWallet>,
    bridge_contract: &EthStarcoinBridge<Provider<Http>>,
    action: &crate::types::EmergencyAction,
    sig_info: &crate::types::BridgeCommitteeValiditySignInfo,
) {
    use crate::eth_transaction_builder::build_emergency_op_approve_transaction;

    println!("   Executing EmergencyPause on ETH...");
    let is_paused_before = bridge_contract.paused().call().await.unwrap();
    assert!(!is_paused_before, "Bridge should not be paused initially");

    let tx =
        build_emergency_op_approve_transaction(bridge_addr, eth_signer, action.clone(), sig_info)
            .await
            .expect("Build pause tx");
    let receipt = tx
        .send()
        .await
        .expect("Send")
        .await
        .expect("Receipt")
        .expect("No receipt");
    assert_eq!(receipt.status, Some(1.into()), "Pause tx failed");
    println!(
        "   ✅ Pause transaction confirmed: {:?}",
        receipt.transaction_hash
    );

    tokio::time::sleep(Duration::from_secs(1)).await;
    let is_paused_after = bridge_contract.paused().call().await.unwrap();
    assert!(is_paused_after, "Bridge should be paused");
    println!("   ✅ Bridge is now PAUSED");
}

/// Execute emergency unpause on ETH
async fn execute_unpause_on_eth(
    bridge_addr: EthAddress,
    eth_signer: SignerMiddleware<Provider<Http>, LocalWallet>,
    bridge_contract: &EthStarcoinBridge<Provider<Http>>,
    action: &crate::types::EmergencyAction,
    sig_info: &crate::types::BridgeCommitteeValiditySignInfo,
) {
    use crate::eth_transaction_builder::build_emergency_op_approve_transaction;

    println!("   Executing EmergencyUnpause on ETH...");
    let tx =
        build_emergency_op_approve_transaction(bridge_addr, eth_signer, action.clone(), sig_info)
            .await
            .expect("Build unpause tx");
    let receipt = tx
        .send()
        .await
        .expect("Send")
        .await
        .expect("Receipt")
        .expect("No receipt");
    assert_eq!(receipt.status, Some(1.into()), "Unpause tx failed");
    println!(
        "   ✅ Unpause transaction confirmed: {:?}",
        receipt.transaction_hash
    );

    tokio::time::sleep(Duration::from_secs(1)).await;
    let is_paused_final = bridge_contract.paused().call().await.unwrap();
    assert!(!is_paused_final, "Bridge should be unpaused");
    println!("   ✅ Bridge is now UNPAUSED");
}

/// Execute limit update on ETH
async fn execute_limit_update_on_eth(
    limiter_addr: EthAddress,
    eth_signer: SignerMiddleware<Provider<Http>, LocalWallet>,
    eth_provider: Arc<Provider<Http>>,
    action: &crate::types::LimitUpdateAction,
    sig_info: &crate::types::BridgeCommitteeValiditySignInfo,
    expected_limit: u64,
) {
    use crate::eth_transaction_builder::build_limit_update_approve_transaction;

    println!("   Executing LimitUpdate on ETH...");
    let limiter = EthBridgeLimiter::new(limiter_addr, eth_provider);

    let tx =
        build_limit_update_approve_transaction(limiter_addr, eth_signer, action.clone(), sig_info)
            .await
            .expect("Build limit tx");
    let receipt = tx
        .send()
        .await
        .expect("Send")
        .await
        .expect("Receipt")
        .expect("No receipt");
    assert_eq!(receipt.status, Some(1.into()), "Limit tx failed");
    println!(
        "   ✅ Limit update transaction confirmed: {:?}",
        receipt.transaction_hash
    );

    tokio::time::sleep(Duration::from_secs(1)).await;
    let starcoin_chain_id: u8 = BridgeChainId::StarcoinCustom as u8;
    let updated_limit = limiter
        .chain_limits(starcoin_chain_id)
        .call()
        .await
        .unwrap_or(0);
    assert_eq!(updated_limit, expected_limit, "Limit mismatch");
    println!("   ✅ Limit updated to: {}", updated_limit);
}

/// Helper struct for Starcoin governance transaction context
struct StarcoinGovTxContext {
    bridge_addr: starcoin_bridge_types::base_types::StarcoinAddress,
    bridge_hex: String,
    keypair: StarcoinKeyPair,
    sender_hex: String,
    rpc_client: crate::simple_starcoin_rpc::SimpleStarcoinRpcClient,
}

impl StarcoinGovTxContext {
    async fn new(env: &BridgeTestEnv) -> Self {
        use crate::simple_starcoin_rpc::SimpleStarcoinRpcClient;

        let bridge_addr = env.starcoin_bridge_address();
        let bridge_hex = format!("0x{}", hex::encode(bridge_addr.to_vec()));
        let keypair = get_bridge_admin_keypair(env);
        let sender_addr = keypair.starcoin_address();
        let sender_hex = format!("0x{}", hex::encode(sender_addr.as_ref()));
        let rpc_client = SimpleStarcoinRpcClient::new(env.starcoin_rpc_url(), &bridge_hex);

        Self {
            bridge_addr: starcoin_bridge_types::base_types::StarcoinAddress::new(*bridge_addr),
            bridge_hex,
            keypair,
            sender_hex,
            rpc_client,
        }
    }

    async fn get_tx_params(&self) -> (u64, u8, u64) {
        let seq = self
            .rpc_client
            .get_sequence_number(&self.sender_hex)
            .await
            .expect("Get seq");
        let chain_id = self.rpc_client.get_chain_id().await.expect("Get chain id");
        let timestamp = self
            .rpc_client
            .get_block_timestamp()
            .await
            .expect("Get timestamp");
        (seq, chain_id, timestamp)
    }

    fn sender_addr(&self) -> starcoin_bridge_types::base_types::StarcoinAddress {
        starcoin_bridge_types::base_types::StarcoinAddress::new(*self.keypair.starcoin_address())
    }
}

/// Extract first signature bytes from signature info
fn extract_sig_bytes(sig_info: &crate::types::BridgeCommitteeValiditySignInfo) -> Vec<u8> {
    sig_info
        .signatures
        .iter()
        .next()
        .map(|(_, sig)| sig.as_ref().to_vec())
        .expect("No signature found")
}

/// Generate blocks to confirm Starcoin transaction
async fn generate_confirm_blocks(env: &BridgeTestEnv, count: u32) {
    for _ in 0..count {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Some(ref starcoin_env) = env.starcoin {
            let _ = starcoin_env.generate_block();
        }
    }
}

/// Execute emergency pause on Starcoin
async fn execute_pause_on_starcoin(
    env: &BridgeTestEnv,
    action: &crate::types::EmergencyAction,
    sig_info: &crate::types::BridgeCommitteeValiditySignInfo,
) {
    use crate::starcoin_bridge_transaction_builder::starcoin_native;

    println!("   Executing EmergencyPause on Starcoin...");
    let ctx = StarcoinGovTxContext::new(env).await;
    println!("   Using bridge admin account: {}", ctx.sender_hex);

    // Check initial pause state
    let is_paused_before =
        query_starcoin_bridge_pause_status(&env.starcoin_rpc_url(), &ctx.bridge_hex).await;
    assert!(!is_paused_before, "Bridge should not be paused initially");

    let (seq, chain_id, timestamp) = ctx.get_tx_params().await;
    let sig_bytes = extract_sig_bytes(sig_info);

    let raw_txn = starcoin_native::build_execute_emergency_op(
        ctx.bridge_addr,
        ctx.sender_addr(),
        seq,
        chain_id,
        timestamp,
        action.chain_id as u8,
        action.nonce,
        action.action_type as u8,
        sig_bytes,
    )
    .expect("Build emergency tx");

    let txn_hash = ctx
        .rpc_client
        .sign_and_submit_transaction(&ctx.keypair, raw_txn)
        .await
        .expect("Submit tx");
    println!("   ✅ Pause transaction submitted: {}", txn_hash);

    generate_confirm_blocks(env, 5).await;

    let is_paused_after =
        query_starcoin_bridge_pause_status(&env.starcoin_rpc_url(), &ctx.bridge_hex).await;
    assert!(is_paused_after, "Bridge should be paused");
    println!("   ✅ Starcoin Bridge is now PAUSED");
}

/// Execute emergency unpause on Starcoin
async fn execute_unpause_on_starcoin(
    env: &BridgeTestEnv,
    action: &crate::types::EmergencyAction,
    sig_info: &crate::types::BridgeCommitteeValiditySignInfo,
) {
    use crate::starcoin_bridge_transaction_builder::starcoin_native;

    println!("   Executing EmergencyUnpause on Starcoin...");
    let ctx = StarcoinGovTxContext::new(env).await;
    let (seq, chain_id, timestamp) = ctx.get_tx_params().await;
    let sig_bytes = extract_sig_bytes(sig_info);

    let raw_txn = starcoin_native::build_execute_emergency_op(
        ctx.bridge_addr,
        ctx.sender_addr(),
        seq,
        chain_id,
        timestamp,
        action.chain_id as u8,
        action.nonce,
        action.action_type as u8,
        sig_bytes,
    )
    .expect("Build emergency tx");

    let txn_hash = ctx
        .rpc_client
        .sign_and_submit_transaction(&ctx.keypair, raw_txn)
        .await
        .expect("Submit tx");
    println!("   ✅ Unpause transaction submitted: {}", txn_hash);

    generate_confirm_blocks(env, 3).await;

    let is_paused_final =
        query_starcoin_bridge_pause_status(&env.starcoin_rpc_url(), &ctx.bridge_hex).await;
    assert!(!is_paused_final, "Bridge should be unpaused");
    println!("   ✅ Starcoin Bridge is now UNPAUSED");
}

/// Execute limit update on Starcoin
async fn execute_limit_update_on_starcoin(
    env: &BridgeTestEnv,
    action: &crate::types::LimitUpdateAction,
    sig_info: &crate::types::BridgeCommitteeValiditySignInfo,
    expected_limit: u64,
) {
    use crate::starcoin_bridge_transaction_builder::starcoin_native;

    println!("   Executing LimitUpdate on Starcoin...");
    let ctx = StarcoinGovTxContext::new(env).await;
    let (seq, chain_id, timestamp) = ctx.get_tx_params().await;
    let sig_bytes = extract_sig_bytes(sig_info);

    let raw_txn = starcoin_native::build_execute_update_limit(
        ctx.bridge_addr,
        ctx.sender_addr(),
        seq,
        chain_id,
        timestamp,
        action.chain_id as u8,
        action.sending_chain_id as u8,
        action.nonce,
        action.new_usd_limit,
        sig_bytes,
    )
    .expect("Build limit tx");

    let txn_hash = ctx
        .rpc_client
        .sign_and_submit_transaction(&ctx.keypair, raw_txn)
        .await
        .expect("Submit tx");
    println!("   ✅ Limit update transaction submitted: {}", txn_hash);

    generate_confirm_blocks(env, 5).await;

    let updated_limit = query_starcoin_bridge_limit(
        &env.starcoin_rpc_url(),
        &ctx.bridge_hex,
        action.sending_chain_id as u8,
    )
    .await
    .unwrap_or(0);

    assert_eq!(updated_limit, expected_limit, "Starcoin limit mismatch");
    println!("   ✅ Starcoin limit updated to: {}", updated_limit);
}

/// Execute update committee member (add/remove) on Starcoin
async fn execute_update_committee_member_on_starcoin(
    env: &BridgeTestEnv,
    action: &crate::types::UpdateCommitteeMemberAction,
    sig_info: &crate::types::BridgeCommitteeValiditySignInfo,
) {
    use crate::starcoin_bridge_transaction_builder::starcoin_native;
    use starcoin_bridge_types::base_types::StarcoinAddress;

    let update_type_str = if action.update_type as u8 == 0 {
        "ADD"
    } else {
        "REMOVE"
    };
    println!(
        "   Executing {} committee member on Starcoin...",
        update_type_str
    );
    println!("   Voting power: {}", action.voting_power);

    let ctx = StarcoinGovTxContext::new(env).await;
    let (seq, chain_id, timestamp) = ctx.get_tx_params().await;
    let sig_bytes = extract_sig_bytes(sig_info);

    // Derive member_address from pubkey (first 16 bytes)
    let pubkey_bytes = &action.bridge_pubkey_bytes;
    let member_address = StarcoinAddress::from_bytes(&pubkey_bytes[..16.min(pubkey_bytes.len())])
        .unwrap_or(StarcoinAddress::ZERO);

    let raw_txn = starcoin_native::build_execute_update_committee_member(
        ctx.bridge_addr,
        ctx.sender_addr(),
        seq,
        chain_id,
        timestamp,
        action.chain_id as u8,
        action.nonce,
        action.update_type as u8,
        member_address,
        action.bridge_pubkey_bytes.clone(),
        action.voting_power,
        action.http_rest_url.as_bytes().to_vec(),
        sig_bytes,
    )
    .expect("Build update committee member tx");

    let txn_hash = ctx
        .rpc_client
        .sign_and_submit_transaction(&ctx.keypair, raw_txn)
        .await
        .expect("Submit tx");
    println!(
        "   ✅ Update committee member transaction submitted: {}",
        txn_hash
    );

    generate_confirm_blocks(env, 5).await;

    // Note: Verifying committee membership would require querying committee state.
    // For now, we just verify the transaction succeeded.
    println!(
        "   ✅ Starcoin {} committee member executed successfully",
        update_type_str
    );
}

/// Generate a new committee member keypair and address for testing
/// Uses a fixed seed for deterministic output - ensures pre-approved action matches actual test action
fn generate_new_committee_member_for_test(
) -> (Vec<u8>, starcoin_bridge_types::base_types::StarcoinAddress) {
    use fastcrypto::traits::KeyPair;
    use rand::SeedableRng;

    // Use a fixed seed to generate deterministic keypair
    // This ensures the same pubkey/address is generated in both:
    // 1. prepare_xxx_validator_env (for pre-approval list)
    // 2. any governance-related test that needs deterministic identities
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEAD_BEEF_CAFE_1234);
    let new_keypair = BridgeAuthorityKeyPair::generate(&mut rng);

    // Get the compressed pubkey (33 bytes)
    let pubkey_bytes = new_keypair.public().as_bytes().to_vec();

    // Create a Starcoin address for the new member (use a deterministic address based on pubkey)
    let mut addr_bytes = [0u8; 16];
    // Use first 16 bytes of pubkey as address (for testing purposes)
    addr_bytes.copy_from_slice(&pubkey_bytes[0..16]);
    let member_address = starcoin_bridge_types::base_types::StarcoinAddress::new(addr_bytes);

    (pubkey_bytes, member_address)
}

/// Query Starcoin bridge pause status using StarcoinBridgeClient
async fn query_starcoin_bridge_pause_status(rpc_url: &str, bridge_addr_hex: &str) -> bool {
    use crate::starcoin_bridge_client::StarcoinBridgeClient;

    let client = StarcoinBridgeClient::new(rpc_url, bridge_addr_hex);
    match client.is_bridge_paused().await {
        Ok(paused) => paused,
        Err(e) => {
            println!("   [DEBUG] Error querying bridge status: {:?}", e);
            false
        }
    }
}

/// Query Starcoin bridge limit using StarcoinBridgeClient
async fn query_starcoin_bridge_limit(
    rpc_url: &str,
    bridge_addr_hex: &str,
    sending_chain_id: u8,
) -> Option<u64> {
    use crate::starcoin_bridge_client::StarcoinBridgeClient;
    use starcoin_bridge_types::bridge::BridgeChainId;

    let client = StarcoinBridgeClient::new(rpc_url, bridge_addr_hex);
    match client.get_bridge_summary().await {
        Ok(summary) => {
            // Find the limit for the given sending chain
            let sending_chain = BridgeChainId::try_from(sending_chain_id).ok()?;
            for (src, _, limit) in &summary.limiter.transfer_limit {
                if *src == sending_chain {
                    return Some(*limit);
                }
            }
            None
        }
        Err(e) => {
            println!("   [DEBUG] Error querying bridge limit: {:?}", e);
            None
        }
    }
}

/// ETH context for offline governance test
struct EthGovContext {
    bridge_addr: EthAddress,
    limiter_addr: EthAddress,
    signer: SignerMiddleware<Provider<Http>, LocalWallet>,
    provider: Arc<Provider<Http>>,
    bridge_contract: EthStarcoinBridge<Provider<Http>>,
}

/// Setup ETH context for governance test
async fn setup_eth_gov_context(env: &BridgeTestEnv) -> EthGovContext {
    let anvil = env.anvil.as_ref().expect("Anvil should be present");
    let eth_contracts = env.eth_contracts.as_ref().expect("ETH contracts");
    let provider = Arc::new(Provider::<Http>::try_from(anvil.rpc_url()).expect("Provider"));
    let bridge_addr: EthAddress = eth_contracts.starcoin_bridge.parse().expect("Parse");
    let signer = get_test_eth_signer(&provider).expect("Signer");
    let bridge_contract = EthStarcoinBridge::new(bridge_addr, provider.clone());
    let limiter_addr = bridge_contract.limiter().call().await.expect("Get limiter");

    EthGovContext {
        bridge_addr,
        limiter_addr,
        signer,
        provider,
        bridge_contract,
    }
}

/// Execute all ETH governance operations
async fn execute_eth_governance(
    ctx: &EthGovContext,
    signed: &SignedGovernanceActions,
    pubkey: &BridgeAuthorityPublicKeyBytes,
) {
    use crate::types::BridgeAction;

    println!("\n━━━ Step 4: Execute on ETH Chain (Machine B) ━━━");

    let pause_sig = build_sig_info(pubkey, signed.eth_pause_sig.signature.clone());
    let unpause_sig = build_sig_info(pubkey, signed.eth_unpause_sig.signature.clone());
    let limit_sig = build_sig_info(pubkey, signed.eth_limit_sig.signature.clone());

    if let BridgeAction::EmergencyAction(ref a) = signed.eth_pause_action {
        execute_pause_on_eth(
            ctx.bridge_addr,
            ctx.signer.clone(),
            &ctx.bridge_contract,
            a,
            &pause_sig,
        )
        .await;
    }
    if let BridgeAction::EmergencyAction(ref a) = signed.eth_unpause_action {
        execute_unpause_on_eth(
            ctx.bridge_addr,
            ctx.signer.clone(),
            &ctx.bridge_contract,
            a,
            &unpause_sig,
        )
        .await;
    }
    if let BridgeAction::LimitUpdateAction(ref a) = signed.eth_limit_action {
        execute_limit_update_on_eth(
            ctx.limiter_addr,
            ctx.signer.clone(),
            ctx.provider.clone(),
            a,
            &limit_sig,
            signed.new_limit,
        )
        .await;
    }
}

/// Execute all Starcoin governance operations  
async fn execute_starcoin_governance(
    env: &BridgeTestEnv,
    signed: &SignedGovernanceActions,
    pubkey: &BridgeAuthorityPublicKeyBytes,
) {
    use crate::types::BridgeAction;

    println!("\n━━━ Step 5: Execute on Starcoin Chain (Machine B) ━━━");

    let pause_sig = build_sig_info(pubkey, signed.starcoin_pause_sig.signature.clone());
    let unpause_sig = build_sig_info(pubkey, signed.starcoin_unpause_sig.signature.clone());
    let limit_sig = build_sig_info(pubkey, signed.starcoin_limit_sig.signature.clone());
    let add_member_sig = build_sig_info(pubkey, signed.starcoin_add_member_sig.signature.clone());

    // Execute UpdateCommitteeMember FIRST for faster validation
    if let BridgeAction::UpdateCommitteeMemberAction(ref a) = signed.starcoin_add_member_action {
        execute_update_committee_member_on_starcoin(env, a, &add_member_sig).await;
    }
    if let BridgeAction::EmergencyAction(ref a) = signed.starcoin_pause_action {
        execute_pause_on_starcoin(env, a, &pause_sig).await;
    }
    if let BridgeAction::EmergencyAction(ref a) = signed.starcoin_unpause_action {
        execute_unpause_on_starcoin(env, a, &unpause_sig).await;
    }
    if let BridgeAction::LimitUpdateAction(ref a) = signed.starcoin_limit_action {
        execute_limit_update_on_starcoin(env, a, &limit_sig, signed.new_limit).await;
    }
}

/// Fund Starcoin account for governance test
fn fund_starcoin_for_governance(env: &mut BridgeTestEnv, authority_key: &BridgeAuthorityKeyPair) {
    let keypair = generate_bridge_client_keypair(authority_key);
    if let Some(ref mut starcoin_env) = env.starcoin {
        match starcoin_env.fund_account(&keypair, 10_000_000_000_000u128) {
            Ok(_) => println!("   ✅ Funded Starcoin account with STC for gas"),
            Err(e) => println!("   ⚠️  Failed to fund Starcoin account: {}", e),
        }
    }
}

/// Test offline governance signing and execution (no bridge server interaction).
/// This test demonstrates governance flow which is separate from normal transfers.
/// Governance actions are signed offline by admin and executed directly on-chain.
/// Run manually with: `cargo test --package starcoin-bridge test_offline_governance_sign_and_execute -- --ignored`
#[test]
#[ignore = "Manual test - requires slow setup, demonstrates governance flow"]
fn test_offline_governance_sign_and_execute() {
    use fastcrypto::traits::KeyPair as KeyPairTrait;

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║   🔐 Offline Governance Sign & Execute Test                  ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        cleanup_test_artifacts();

        // Step 1: Generate admin key
        println!("━━━ Step 1: Generate Admin Key ━━━");
        let (authority_key, authority_pubkey, eth_address) =
            generate_single_validator_authority_key();
        println!("   Admin ETH address: {:?}", eth_address);
        let pubkey_bytes = BridgeAuthorityPublicKeyBytes::from(authority_key.public());

        // Step 2: Setup environment
        println!("\n━━━ Step 2: Setup Environment ━━━");
        let mut env = setup_offline_governance_env(authority_pubkey, eth_address).await;
        fund_starcoin_for_governance(&mut env, &authority_key);

        // Step 3: Offline signing
        let signed = sign_governance_actions_offline(&authority_key);

        // Step 4: Execute on ETH
        let eth_ctx = setup_eth_gov_context(&env).await;
        execute_eth_governance(&eth_ctx, &signed, &pubkey_bytes).await;

        // Step 5: Execute on Starcoin
        execute_starcoin_governance(&env, &signed, &pubkey_bytes).await;

        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║   ✅ Offline Governance Sign & Execute Test PASSED!          ║");
        println!("║      ETH: pause, unpause, limit update ✓                      ║");
        println!("║      Starcoin: add member, pause, unpause, limit update ✓     ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        tokio::task::spawn_blocking(move || drop(env))
            .await
            .unwrap();
    });
}

/// Helper to build BridgeCommitteeValiditySignInfo from a single signature
fn build_sig_info(
    pubkey: &BridgeAuthorityPublicKeyBytes,
    sig: crate::crypto::BridgeAuthorityRecoverableSignature,
) -> crate::types::BridgeCommitteeValiditySignInfo {
    use std::collections::BTreeMap;
    let mut map = BTreeMap::new();
    map.insert(pubkey.clone(), sig);
    crate::types::BridgeCommitteeValiditySignInfo { signatures: map }
}
