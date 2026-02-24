// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Starcoin-specific configuration for ChainSyncer
//!
//! This module contains configuration types specific to Starcoin chain syncing.
//! Common configurations (FetchConfig, ReorgConfig, FinalityMode) are in the common module.

use crate::chain_syncer::common::{FetchConfig, FinalityMode, ReorgConfig};
use serde::{Deserialize, Serialize};

/// Main configuration for StarcoinChainSyncer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarcoinChainSyncerConfig {
    /// Chain identifier (e.g., "starcoin", "halley", "barnard")
    pub chain_name: String,

    /// RPC endpoint URL
    pub rpc_url: String,

    /// Module addresses to monitor (address -> start block)
    #[serde(default)]
    pub modules: Vec<StarcoinSyncerModuleConfig>,

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

/// Configuration for a single Starcoin module to monitor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarcoinSyncerModuleConfig {
    /// Module address or identifier
    pub address: String,
    /// Block number to start syncing from
    pub start_block: u64,
    /// Optional human-readable name
    pub name: Option<String>,
    /// Event types to filter (empty = all events)
    #[serde(default)]
    pub event_types: Vec<String>,
}

impl Default for StarcoinChainSyncerConfig {
    fn default() -> Self {
        Self {
            chain_name: "starcoin".to_string(),
            rpc_url: String::new(),
            modules: Vec::new(),
            fetch: FetchConfig::default(),
            reorg: ReorgConfig::starcoin(),
            finality_mode: FinalityMode::default(),
            channel_size: default_channel_size(),
        }
    }
}

impl StarcoinChainSyncerConfig {
    /// Create a new config for Starcoin mainnet
    pub fn mainnet(rpc_url: &str) -> Self {
        Self {
            chain_name: "starcoin".to_string(),
            rpc_url: rpc_url.to_string(),
            reorg: ReorgConfig::starcoin(),
            ..Default::default()
        }
    }

    /// Create a new config for Halley testnet
    pub fn halley(rpc_url: &str) -> Self {
        Self {
            chain_name: "halley".to_string(),
            rpc_url: rpc_url.to_string(),
            reorg: ReorgConfig::starcoin(),
            ..Default::default()
        }
    }

    /// Add a module to monitor
    pub fn with_module(mut self, address: &str, start_block: u64) -> Self {
        self.modules.push(StarcoinSyncerModuleConfig {
            address: address.to_string(),
            start_block,
            name: None,
            event_types: Vec::new(),
        });
        self
    }

    /// Add a named module to monitor
    pub fn with_named_module(mut self, name: &str, address: &str, start_block: u64) -> Self {
        self.modules.push(StarcoinSyncerModuleConfig {
            address: address.to_string(),
            start_block,
            name: Some(name.to_string()),
            event_types: Vec::new(),
        });
        self
    }

    /// Add a module with specific event type filter
    pub fn with_module_events(
        mut self,
        address: &str,
        start_block: u64,
        event_types: Vec<String>,
    ) -> Self {
        self.modules.push(StarcoinSyncerModuleConfig {
            address: address.to_string(),
            start_block,
            name: None,
            event_types,
        });
        self
    }

    /// Enable or disable reorg detection
    pub fn with_reorg_detection(mut self, enabled: bool) -> Self {
        self.reorg.enabled = enabled;
        self
    }

    /// Set finality blocks (default 16 for Starcoin DAG)
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
        if self.modules.is_empty() {
            return Err("at least one module must be configured".to_string());
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
        let config = StarcoinChainSyncerConfig::default();
        assert!(config.fetch.max_block_range > 0);
        assert!(config.reorg.enabled);
        assert_eq!(config.reorg.finality_blocks, 16);
    }

    #[test]
    fn test_mainnet_config() {
        let config =
            StarcoinChainSyncerConfig::mainnet("http://localhost:9850").with_module("0x1", 100);
        assert_eq!(config.chain_name, "starcoin");
        assert_eq!(config.reorg.finality_blocks, 16);
        assert_eq!(config.modules.len(), 1);
    }

    #[test]
    fn test_halley_config() {
        let config =
            StarcoinChainSyncerConfig::halley("http://localhost:9850").with_module("0x1", 100);
        assert_eq!(config.chain_name, "halley");
        assert_eq!(config.reorg.finality_blocks, 16);
    }

    #[test]
    fn test_validation() {
        let mut config = StarcoinChainSyncerConfig::mainnet("http://localhost:9850");

        // Should fail: no modules
        assert!(config.validate().is_err());

        // Should pass with module
        config = config.with_module("0x1", 100);
        assert!(config.validate().is_ok());

        // Should fail: empty chain name
        config.chain_name = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_module_with_events() {
        let config = StarcoinChainSyncerConfig::mainnet("http://localhost:9850")
            .with_module_events(
                "0x1::Bridge",
                100,
                vec!["DepositEvent".to_string(), "WithdrawEvent".to_string()],
            );
        assert_eq!(config.modules.len(), 1);
        assert_eq!(config.modules[0].event_types.len(), 2);
    }
}
