// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! ETH-specific configuration for ChainSyncer
//!
//! This module contains configuration types specific to Ethereum chain syncing.
//! Common configurations (FetchConfig, ReorgConfig, FinalityMode) are in the common module.

use crate::chain_syncer::common::{FetchConfig, FinalityMode, ReorgConfig};
use serde::{Deserialize, Serialize};

/// Main configuration for EthChainSyncer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthChainSyncerConfig {
    /// Chain identifier (e.g., "eth", "sepolia", "anvil")
    pub chain_name: String,

    /// RPC endpoint URL
    pub rpc_url: String,

    /// Contract addresses to monitor (address -> start block)
    #[serde(default)]
    pub contracts: Vec<EthSyncerContractConfig>,

    /// Fetch configuration
    #[serde(default)]
    pub fetch: FetchConfig,

    /// Reorg detection configuration
    #[serde(default)]
    pub reorg: ReorgConfig,

    /// Finality mode
    #[serde(default)]
    pub finality_mode: FinalityMode,

    /// Event channel buffer size
    #[serde(default = "default_channel_size")]
    pub channel_size: usize,
}

fn default_channel_size() -> usize {
    1000
}

/// Configuration for a single ETH contract to monitor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthSyncerContractConfig {
    /// Contract/module address or identifier
    pub address: String,
    /// Block number to start syncing from
    pub start_block: u64,
    /// Optional human-readable name
    pub name: Option<String>,
}

impl Default for EthChainSyncerConfig {
    fn default() -> Self {
        Self {
            chain_name: "unknown".to_string(),
            rpc_url: String::new(),
            contracts: Vec::new(),
            fetch: FetchConfig::default(),
            reorg: ReorgConfig::default(),
            finality_mode: FinalityMode::default(),
            channel_size: default_channel_size(),
        }
    }
}

impl EthChainSyncerConfig {
    /// Create a new config for ETH chain
    pub fn eth(chain_name: &str, rpc_url: &str) -> Self {
        Self {
            chain_name: chain_name.to_string(),
            rpc_url: rpc_url.to_string(),
            reorg: ReorgConfig::eth_mainnet(),
            ..Default::default()
        }
    }

    /// Add a contract to monitor
    pub fn with_contract(mut self, address: &str, start_block: u64) -> Self {
        self.contracts.push(EthSyncerContractConfig {
            address: address.to_string(),
            start_block,
            name: None,
        });
        self
    }

    /// Add a named contract to monitor
    pub fn with_named_contract(mut self, name: &str, address: &str, start_block: u64) -> Self {
        self.contracts.push(EthSyncerContractConfig {
            address: address.to_string(),
            start_block,
            name: Some(name.to_string()),
        });
        self
    }

    /// Enable or disable reorg detection
    pub fn with_reorg_detection(mut self, enabled: bool) -> Self {
        self.reorg.enabled = enabled;
        self
    }

    /// Set finality blocks
    pub fn with_finality_blocks(mut self, blocks: u64) -> Self {
        self.reorg.finality_blocks = blocks;
        self
    }

    /// Set finality mode
    pub fn with_finality_mode(mut self, mode: FinalityMode) -> Self {
        self.finality_mode = mode;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.chain_name.is_empty() {
            return Err("chain_name cannot be empty".to_string());
        }
        if self.rpc_url.is_empty() {
            return Err("rpc_url cannot be empty".to_string());
        }
        if self.contracts.is_empty() {
            return Err("at least one contract must be configured".to_string());
        }
        if self.reorg.finality_blocks == 0 && self.reorg.enabled {
            return Err("finality_blocks must be > 0 when reorg detection is enabled".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EthChainSyncerConfig::default();
        assert!(config.fetch.max_block_range > 0);
        assert!(config.reorg.enabled);
    }

    #[test]
    fn test_eth_config() {
        let config =
            EthChainSyncerConfig::eth("eth", "http://localhost:8545").with_contract("0x1234", 100);
        assert_eq!(config.chain_name, "eth");
        assert_eq!(config.reorg.finality_blocks, 64);
        assert_eq!(config.contracts.len(), 1);
    }

    #[test]
    fn test_validation() {
        let mut config = EthChainSyncerConfig::eth("eth", "http://localhost:8545");

        // Should fail: no contracts
        assert!(config.validate().is_err());

        // Should pass with contract
        config = config.with_contract("0x1234", 100);
        assert!(config.validate().is_ok());

        // Should fail: empty chain name
        config.chain_name = String::new();
        assert!(config.validate().is_err());
    }
}
