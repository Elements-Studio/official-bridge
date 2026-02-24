// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::abi::EthStarcoinBridge;
use anyhow::{Context, Result};
use ethers::providers::{Http, Provider};
use ethers::types::Address;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

/// Solidity contracts are built by external script (scripts/run_e2e_tests.sh)
/// This function is kept for API compatibility but is now a no-op.
#[inline]
pub fn ensure_solidity_ready() -> Result<()> {
    Ok(())
}

// When tests are run directly via `cargo test`, ETH deployments can happen in parallel across
// multiple tests and cause occasional Foundry/Anvil flakiness (e.g. connection resets).
//
// The recommended fast/parallel path is to run via `scripts/run_e2e_tests.sh`, which pre-generates
// an Anvil state snapshot + contract addresses so tests skip deployments.
//
// As a safety net, serialize forge deployments when we are not using predeployed contracts.
static FORGE_DEPLOY_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

const E2E_TMP_DIR_PREFIX: &str = "starcoin-bridge-e2e";
const E2E_TMP_ROOT_ENV: &str = "STARCOIN_BRIDGE_E2E_TMP_ROOT";

const ANVIL_MNEMONIC_FOR_TESTS: &str =
    "test test test test test test test test test test test junk";

fn e2e_tmp_root() -> PathBuf {
    if let Ok(root) = std::env::var(E2E_TMP_ROOT_ENV) {
        let root = root.trim();
        if !root.is_empty() {
            return PathBuf::from(root);
        }
    }
    std::env::temp_dir().join(E2E_TMP_DIR_PREFIX)
}

fn unique_evm_workdir_name() -> String {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("evm-{}-{}", pid, nanos)
}

fn copy_dir_recursive_filtered(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).with_context(|| format!("Failed to create dir: {:?}", dst))?;
    for entry in fs::read_dir(src).with_context(|| format!("Failed to read dir: {:?}", src))? {
        let entry = entry.with_context(|| format!("Failed to read dir entry under {:?}", src))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("Failed to stat dir entry: {:?}", entry.path()))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive_filtered(&src_path, &dst_path)?;
        } else if file_type.is_symlink() {
            use std::os::unix::fs as unix_fs;
            let target = fs::read_link(&src_path)
                .with_context(|| format!("Failed to read symlink: {:?}", src_path))?;
            if let Some(parent) = dst_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create parent dir: {:?}", parent))?;
            }
            // Best-effort: remove if already exists
            let _ = fs::remove_file(&dst_path);
            unix_fs::symlink(&target, &dst_path).with_context(|| {
                format!("Failed to create symlink {:?} -> {:?}", dst_path, target)
            })?;
        } else if file_type.is_file() {
            if let Some(parent) = dst_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create parent dir: {:?}", parent))?;
            }
            fs::copy(&src_path, &dst_path).with_context(|| {
                format!("Failed to copy file from {:?} to {:?}", src_path, dst_path)
            })?;
        }
    }
    Ok(())
}

fn prepare_isolated_evm_workdir(evm_contracts_dir: &Path) -> Result<PathBuf> {
    let tmp_root = e2e_tmp_root();
    fs::create_dir_all(&tmp_root)
        .with_context(|| format!("Failed to create temp root: {:?}", tmp_root))?;

    let workdir = tmp_root.join(unique_evm_workdir_name());
    fs::create_dir_all(&workdir)
        .with_context(|| format!("Failed to create workdir: {:?}", workdir))?;

    let copy_start = Instant::now();

    // Strategy: avoid copying source tree to keep setup fast.
    // - Copy only `out/` and `cache/` (prebuilt artifacts) into the isolated dir.
    // - Create a fresh `broadcast/` (must be unique per test to avoid contention).
    // - Symlink everything else (contracts/, script/, config files, etc) into the isolated dir.
    use std::os::unix::fs as unix_fs;

    for entry in fs::read_dir(evm_contracts_dir)
        .with_context(|| format!("Failed to read EVM dir: {:?}", evm_contracts_dir))?
    {
        let entry = entry.with_context(|| {
            format!("Failed to read EVM dir entry under {:?}", evm_contracts_dir)
        })?;

        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();
        let src_path = entry.path();
        let dst_path = workdir.join(&name_str);

        let file_type = entry
            .file_type()
            .with_context(|| format!("Failed to stat EVM entry: {:?}", src_path))?;

        match name_str.as_str() {
            // Keep these per-test to avoid cross-test contention and allow Foundry to write.
            "out" | "cache" => {
                if file_type.is_dir() {
                    copy_dir_recursive_filtered(&src_path, &dst_path)?;
                } else {
                    // If foundry layout changes and this is not a directory, fall back to symlink.
                    let _ = fs::remove_file(&dst_path);
                    unix_fs::symlink(&src_path, &dst_path).with_context(|| {
                        format!("Failed to symlink {:?} -> {:?}", dst_path, src_path)
                    })?;
                }
            }
            // Always isolate broadcasts.
            "broadcast" => {
                fs::create_dir_all(&dst_path)
                    .with_context(|| format!("Failed to create broadcast dir: {:?}", dst_path))?;
            }
            // Everything else: symlink (no source copy).
            _ => {
                // Best-effort: remove if already exists
                let _ = fs::remove_file(&dst_path);
                let _ = fs::remove_dir_all(&dst_path);
                unix_fs::symlink(&src_path, &dst_path).with_context(|| {
                    format!("Failed to symlink {:?} -> {:?}", dst_path, src_path)
                })?;
            }
        }
    }

    tracing::info!(
        "[e2e][eth] prepared isolated foundry dir {:?} (copy took {:?})",
        workdir,
        copy_start.elapsed()
    );

    Ok(workdir)
}

/// Anvil private keys (deterministic, from Anvil default accounts)
pub mod anvil_keys {
    /// Default Anvil private key for account 0
    pub const ANVIL_PRIVATE_KEY_0: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    /// Default Anvil private key for account 1
    pub const ANVIL_PRIVATE_KEY_1: &str =
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    /// Default Anvil private key for account 2
    pub const ANVIL_PRIVATE_KEY_2: &str =
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
    /// Default Anvil address for account 0
    pub const ANVIL_ADDRESS_0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    /// Default Anvil address for account 1
    pub const ANVIL_ADDRESS_1: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    /// Default Anvil address for account 2
    pub const ANVIL_ADDRESS_2: &str = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
}

/// Embedded Anvil instance for testing
///
/// This manages an Anvil Ethereum node for testing.
/// The node automatically picks an available port to avoid conflicts.
pub struct EmbeddedAnvilNode {
    /// Child process handle
    child: std::process::Child,
    /// HTTP RPC URL
    rpc_url: String,
    /// Port number
    port: u16,
    /// Chain ID
    chain_id: u64,
}

impl EmbeddedAnvilNode {
    /// Start a new embedded Anvil node on a random available port
    pub fn start() -> Result<Self> {
        Self::start_with_args(&[])
    }

    /// Start Anvil with custom arguments
    pub fn start_with_args(extra_args: &[&str]) -> Result<Self> {
        let start_total = Instant::now();
        // Find an available port
        let port = Self::find_available_port()?;
        let chain_id = 31337u64;

        tracing::info!(
            "[e2e][eth] starting anvil (port={}, chain_id={})...",
            port,
            chain_id
        );

        let mut cmd = Command::new("anvil");
        cmd.arg("--host").arg("127.0.0.1");
        cmd.arg("--port").arg(port.to_string());
        cmd.arg("--chain-id").arg(chain_id.to_string());
        cmd.arg("--silent");

        // Keep accounts deterministic and aligned with ANVIL_PRIVATE_KEY_0.
        cmd.arg("--mnemonic").arg(ANVIL_MNEMONIC_FOR_TESTS);

        for arg in extra_args {
            cmd.arg(arg);
        }

        // Redirect output to avoid cluttering test output
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        let child = cmd
            .spawn()
            .context("Failed to spawn anvil. Is anvil installed?")?;

        let rpc_url = format!("http://127.0.0.1:{}", port);

        let node = Self {
            child,
            rpc_url,
            port,
            chain_id,
        };

        // Wait for Anvil to be ready
        node.wait_for_ready()?;

        tracing::info!(
            "[e2e][eth] anvil ready at {} (startup took {:?})",
            node.rpc_url,
            start_total.elapsed()
        );

        Ok(node)
    }

    /// Find an available TCP port
    fn find_available_port() -> Result<u16> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .context("Failed to bind to find available port")?;
        let port = listener.local_addr()?.port();
        drop(listener);
        Ok(port)
    }

    /// Wait for Anvil to be ready by polling the RPC endpoint
    fn wait_for_ready(&self) -> Result<()> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(10);

        while start.elapsed() < timeout {
            if self.is_ready() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        anyhow::bail!("Anvil failed to start within {} seconds", timeout.as_secs())
    }

    /// Check if Anvil is ready
    fn is_ready(&self) -> bool {
        // Use a blocking HTTP request to check if Anvil is ready
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(&self.rpc_url)
            .header("Content-Type", "application/json")
            .body(r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#)
            .send();

        res.is_ok()
    }

    /// Get the HTTP RPC URL
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// Get the port number
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the chain ID
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Get default private key (account 0)
    pub fn default_private_key(&self) -> &'static str {
        anvil_keys::ANVIL_PRIVATE_KEY_0
    }

    /// Get default address (account 0)
    pub fn default_address(&self) -> &'static str {
        anvil_keys::ANVIL_ADDRESS_0
    }

    /// Deploy bridge contracts using forge script
    ///
    /// Returns deployed contract addresses
    pub fn deploy_bridge_contracts(&self) -> Result<DeployedEthContracts> {
        deploy_bridge_contracts_to_rpc(&self.rpc_url)
    }

    /// Parse deployed contract addresses from forge output
    fn parse_deployed_addresses(output: &str) -> Result<DeployedEthContracts> {
        let mut contracts = DeployedEthContracts::default();

        for line in output.lines() {
            if line.contains("[Deployed]") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let address = parts.last().unwrap().trim();
                    if line.contains("StarcoinBridge:") && !line.contains("BridgeConfig") {
                        contracts.starcoin_bridge = address.to_string();
                    } else if line.contains("BridgeCommittee:") {
                        contracts.bridge_committee = address.to_string();
                    } else if line.contains("BridgeConfig:") {
                        contracts.bridge_config = address.to_string();
                    } else if line.contains("BridgeVault:") {
                        contracts.bridge_vault = address.to_string();
                    } else if line.contains("BridgeLimiter:") {
                        contracts.bridge_limiter = address.to_string();
                    } else if line.contains("WETH:") || line.contains("ETH:") {
                        contracts.weth = address.to_string();
                    } else if line.contains("BTC:") {
                        contracts.wbtc = address.to_string();
                    } else if line.contains("USDC:") {
                        contracts.usdc = address.to_string();
                    } else if line.contains("USDT:") {
                        contracts.usdt = address.to_string();
                    }
                }
            }
        }

        if contracts.starcoin_bridge.is_empty() {
            anyhow::bail!("Failed to parse StarcoinBridge address from forge output");
        }

        Ok(contracts)
    }
}

/// Deploy bridge contracts to a given RPC URL using forge script.
/// This is a standalone function that can be called from spawn_blocking.
pub fn deploy_bridge_contracts_to_rpc(rpc_url: &str) -> Result<DeployedEthContracts> {
    // Ensure contracts are built first
    ensure_solidity_ready()?;

    // Serialize deployments to avoid occasional parallel-run flakiness.
    let _deploy_guard = FORGE_DEPLOY_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("FORGE_DEPLOY_LOCK poisoned"))?;

    let evm_contracts_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../contracts/evm");

    if !evm_contracts_dir.exists() {
        anyhow::bail!("EVM contracts directory not found: {:?}", evm_contracts_dir);
    }

    let isolated_evm_dir = prepare_isolated_evm_workdir(&evm_contracts_dir)?;
    tracing::info!(
        "[e2e][eth] deploying contracts via forge (rpc_url={}, foundry_dir={:?})...",
        rpc_url,
        isolated_evm_dir
    );

    // Ensure private key has 0x prefix for PRIVATE_KEY env var
    let private_key_with_prefix = anvil_keys::ANVIL_PRIVATE_KEY_0;
    // For --private-key flag, strip the 0x prefix
    let private_key_no_prefix = private_key_with_prefix.trim_start_matches("0x");

    // Run forge script to deploy contracts
    // Note: Do NOT use --legacy flag as it causes connection issues with Anvil
    let forge_start = Instant::now();
    let output = Command::new("forge")
        .arg("script")
        .arg("script/deploy_bridge.s.sol")
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("--private-key")
        .arg(private_key_no_prefix)
        .arg("--broadcast")
        .arg("-vvv")
        .current_dir(&isolated_evm_dir)
        // PRIVATE_KEY env var needs 0x prefix for vm.envUint
        .env("PRIVATE_KEY", private_key_with_prefix)
        .output()
        .context("Failed to run forge script. Is forge installed?")?;

    tracing::info!(
        "[e2e][eth] forge script finished in {:?} (status: {})",
        forge_start.elapsed(),
        output.status
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Always log important parts of forge output for debugging config issues
    for line in stdout.lines() {
        if line.contains("config path") || line.contains("Deployed") || line.contains("Committee") {
            tracing::info!("[e2e][eth] forge: {}", line);
        }
    }

    if !output.status.success() {
        anyhow::bail!(
            "Forge deploy failed:\nstdout: {}\nstderr: {}",
            stdout,
            stderr
        );
    }

    // Parse deployed addresses from output
    let contracts = EmbeddedAnvilNode::parse_deployed_addresses(&stdout)?;

    tracing::info!(
        "[e2e][eth] deployed: StarcoinBridge={}, Committee={}, Limiter={}, Vault={}, Config={}",
        contracts.starcoin_bridge,
        contracts.bridge_committee,
        contracts.bridge_limiter,
        contracts.bridge_vault,
        contracts.bridge_config
    );

    Ok(contracts)
}

/// Deployed Ethereum contract addresses
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeployedEthContracts {
    pub starcoin_bridge: String,
    pub bridge_committee: String,
    pub bridge_config: String,
    pub bridge_vault: String,
    pub bridge_limiter: String,
    pub weth: String,
    pub wbtc: String,
    pub usdc: String,
    pub usdt: String,
}

impl Drop for EmbeddedAnvilNode {
    fn drop(&mut self) {
        // Kill the Anvil process when dropped
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// ETH-only test environment (Anvil + deployed ETH contracts)
///
/// This is intentionally separate from Starcoin E2E envs to avoid starting
/// embedded Starcoin nodes when tests only need the EVM side.
pub struct EthTestEnv {
    pub anvil: EmbeddedAnvilNode,
    pub eth_contracts: DeployedEthContracts,
}

impl EthTestEnv {
    pub fn new_with_eth_only() -> Result<Self> {
        let start_total = Instant::now();
        let anvil = EmbeddedAnvilNode::start()?;
        let eth_contracts = anvil.deploy_bridge_contracts()?;
        tracing::info!(
            "[e2e][eth] EthTestEnv ready (total took {:?})",
            start_total.elapsed()
        );
        Ok(Self {
            anvil,
            eth_contracts,
        })
    }

    pub fn eth_rpc_url(&self) -> &str {
        self.anvil.rpc_url()
    }

    pub fn eth_provider(&self) -> Provider<Http> {
        Provider::<Http>::try_from(self.eth_rpc_url()).expect("Failed to create ETH provider")
    }

    pub fn eth_contracts(&self) -> &DeployedEthContracts {
        &self.eth_contracts
    }

    pub fn eth_bridge_contract(&self) -> EthStarcoinBridge<Provider<Http>> {
        let address: Address = self
            .eth_contracts
            .starcoin_bridge
            .parse()
            .expect("Invalid bridge address");
        EthStarcoinBridge::new(address, Arc::new(self.eth_provider()))
    }
}
