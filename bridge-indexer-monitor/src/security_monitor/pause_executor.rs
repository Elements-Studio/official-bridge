// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Emergency Pause Executor
//!
//! Executes emergency pause on both ETH and Starcoin chains when mismatch is detected.

use anyhow::Result;
use std::path::Path;
use tracing::{error, info};

/// Environment variable name for the starcoin-bridge-cli path
pub const STARCOIN_BRIDGE_CLI_ENV: &str = "STARCOIN_BRIDGE_CLI";

/// Get the starcoin-bridge-cli path from environment variable
/// Returns error if not set or path doesn't exist
pub fn get_bridge_cli_path() -> Result<String> {
    let path = std::env::var(STARCOIN_BRIDGE_CLI_ENV)
        .map_err(|_| anyhow::anyhow!("{} environment variable not set", STARCOIN_BRIDGE_CLI_ENV))?;

    if !Path::new(&path).exists() {
        return Err(anyhow::anyhow!(
            "{} path does not exist: {}",
            STARCOIN_BRIDGE_CLI_ENV,
            path
        ));
    }

    Ok(path)
}

/// Validate that STARCOIN_BRIDGE_CLI environment variable is set and points to a valid path
/// Call this at startup to fail fast if misconfigured
pub fn validate_bridge_cli_path() -> Result<()> {
    get_bridge_cli_path()?;
    Ok(())
}

/// Executor for emergency pause operations
pub struct PauseExecutor {
    keys_path: String,
    signatures_path: Option<String>,
    eth_rpc_url: String,
    eth_bridge_address: String,
    stc_rpc_url: String,
    stc_bridge_address: String,
}

impl PauseExecutor {
    pub fn new(
        keys_path: String,
        signatures_path: Option<String>,
        eth_rpc_url: String,
        eth_bridge_address: String,
        stc_rpc_url: String,
        stc_bridge_address: String,
    ) -> Self {
        Self {
            keys_path,
            signatures_path,
            eth_rpc_url,
            eth_bridge_address,
            stc_rpc_url,
            stc_bridge_address,
        }
    }

    /// Execute emergency pause on both chains
    ///
    /// Returns (eth_success, stc_success)
    pub async fn execute_pause(&self) -> Result<(bool, bool)> {
        info!("[PauseExecutor] Executing emergency pause on both chains");

        let eth_result = self.pause_eth().await;
        let stc_result = self.pause_stc().await;

        let eth_success = eth_result.is_ok();
        let stc_success = stc_result.is_ok();

        if !eth_success {
            error!("[PauseExecutor] ETH pause failed: {:?}", eth_result.err());
        }
        if !stc_success {
            error!("[PauseExecutor] STC pause failed: {:?}", stc_result.err());
        }

        Ok((eth_success, stc_success))
    }

    async fn pause_eth(&self) -> Result<()> {
        info!(
            "[PauseExecutor] Pausing ETH bridge at {}",
            self.eth_bridge_address
        );

        // Use bridge-cli to execute pause
        // The actual implementation would call the bridge-cli governance module
        let cli_path = get_bridge_cli_path()?;

        let output = tokio::process::Command::new(&cli_path)
            .args([
                "governance",
                "emergency-pause",
                "--chain",
                "eth",
                "--rpc-url",
                &self.eth_rpc_url,
                "--bridge-address",
                &self.eth_bridge_address,
                "--keys-path",
                &self.keys_path,
            ])
            .args(
                self.signatures_path
                    .as_ref()
                    .map(|p| vec!["--signatures-path", p])
                    .unwrap_or_default(),
            )
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("ETH pause failed: {}", stderr));
        }

        info!("[PauseExecutor] ETH bridge paused successfully");
        Ok(())
    }

    async fn pause_stc(&self) -> Result<()> {
        info!(
            "[PauseExecutor] Pausing Starcoin bridge at {}",
            self.stc_bridge_address
        );

        let cli_path = get_bridge_cli_path()?;

        let output = tokio::process::Command::new(&cli_path)
            .args([
                "governance",
                "emergency-pause",
                "--chain",
                "starcoin",
                "--rpc-url",
                &self.stc_rpc_url,
                "--bridge-address",
                &self.stc_bridge_address,
                "--keys-path",
                &self.keys_path,
            ])
            .args(
                self.signatures_path
                    .as_ref()
                    .map(|p| vec!["--signatures-path", p])
                    .unwrap_or_default(),
            )
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Starcoin pause failed: {}", stderr));
        }

        info!("[PauseExecutor] Starcoin bridge paused successfully");
        Ok(())
    }
}

/// Execute ETH pause with pre-aggregated signatures
///
/// This function is called by SecurityMonitor when a mismatch is detected.
/// Uses governance-execute command to execute emergency pause.
pub async fn execute_eth_pause(
    config_path: &str,
    chain_id: u8,
    signatures: &str,
    nonce: u64,
) -> Result<()> {
    info!(
        "[PauseExecutor] Executing ETH pause with chain_id {} and nonce {}",
        chain_id, nonce
    );

    let cli_path = get_bridge_cli_path()?;
    let output = tokio::process::Command::new(&cli_path)
        .arg("governance-execute")
        .arg("--config-path")
        .arg(config_path)
        .arg("--eth-chain-id")
        .arg(chain_id.to_string())
        .arg("--signatures")
        .arg(signatures)
        .arg("emergency-button")
        .arg("--nonce")
        .arg(nonce.to_string())
        .arg("--action-type")
        .arg("pause")
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        error!(
            "[PauseExecutor] ETH pause failed:\nstdout: {}\nstderr: {}",
            stdout, stderr
        );
        return Err(anyhow::anyhow!("ETH pause execution failed: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    info!("[PauseExecutor] ETH bridge paused successfully: {}", stdout);
    Ok(())
}

/// Execute STC pause with pre-aggregated signatures
///
/// This function is called by SecurityMonitor when a mismatch is detected.
/// Uses governance-execute command to execute emergency pause.
pub async fn execute_stc_pause(
    config_path: &str,
    chain_id: u8,
    signatures: &str,
    nonce: u64,
) -> Result<()> {
    info!(
        "[PauseExecutor] Executing STC pause with chain_id {} and nonce {}",
        chain_id, nonce
    );

    let cli_path = get_bridge_cli_path()?;
    let output = tokio::process::Command::new(&cli_path)
        .arg("governance-execute")
        .arg("--config-path")
        .arg(config_path)
        .arg("--starcoin-chain-id")
        .arg(chain_id.to_string())
        .arg("--signatures")
        .arg(signatures)
        .arg("emergency-button")
        .arg("--nonce")
        .arg(nonce.to_string())
        .arg("--action-type")
        .arg("pause")
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        error!(
            "[PauseExecutor] STC pause failed:\nstdout: {}\nstderr: {}",
            stdout, stderr
        );
        return Err(anyhow::anyhow!("STC pause execution failed: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    info!("[PauseExecutor] STC bridge paused successfully: {}", stdout);
    Ok(())
}
