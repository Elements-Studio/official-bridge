// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Common configuration types for chain syncers
//!
//! These configs are shared across different chain implementations (ETH, Starcoin).

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for the syncer's block fetching behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchConfig {
    /// Maximum number of blocks to query in a single RPC call
    #[serde(default = "default_max_block_range")]
    pub max_block_range: u64,

    /// Interval between finalized block checks
    #[serde(default = "default_finalized_block_interval")]
    pub finalized_block_interval: Duration,

    /// Maximum retry duration for failed requests
    #[serde(default = "default_max_retry_duration")]
    pub max_retry_duration: Duration,

    /// Interval between log queries when caught up
    #[serde(default = "default_poll_interval")]
    pub poll_interval: Duration,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            max_block_range: default_max_block_range(),
            finalized_block_interval: default_finalized_block_interval(),
            max_retry_duration: default_max_retry_duration(),
            poll_interval: default_poll_interval(),
        }
    }
}

fn default_max_block_range() -> u64 {
    1000
}

fn default_finalized_block_interval() -> Duration {
    Duration::from_secs(5)
}

fn default_max_retry_duration() -> Duration {
    Duration::from_secs(600)
}

fn default_poll_interval() -> Duration {
    Duration::from_secs(2)
}

/// Configuration for reorg detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReorgConfig {
    /// Enable reorg detection
    #[serde(default = "default_reorg_enabled")]
    pub enabled: bool,

    /// Number of blocks to consider for finality
    /// For ETH mainnet this is typically 64 blocks
    /// For Starcoin this is typically 16 blocks
    #[serde(default = "default_finality_blocks")]
    pub finality_blocks: u64,

    /// Window size for tracking blocks (multiplier of finality_blocks)
    /// e.g., 2 means we track 2 * finality_blocks
    #[serde(default = "default_window_multiplier")]
    pub window_multiplier: u64,

    /// How often to check for reorgs (in seconds)
    #[serde(default = "default_check_interval")]
    pub check_interval: Duration,

    /// Maximum tracking duration for events (seconds)
    /// Events older than this are considered finalized
    #[serde(default = "default_tracking_duration")]
    pub tracking_duration: Duration,
}

impl Default for ReorgConfig {
    fn default() -> Self {
        Self {
            enabled: default_reorg_enabled(),
            finality_blocks: default_finality_blocks(),
            window_multiplier: default_window_multiplier(),
            check_interval: default_check_interval(),
            tracking_duration: default_tracking_duration(),
        }
    }
}

fn default_reorg_enabled() -> bool {
    true
}

fn default_finality_blocks() -> u64 {
    64 // ETH mainnet default
}

fn default_window_multiplier() -> u64 {
    2
}

fn default_check_interval() -> Duration {
    Duration::from_secs(10)
}

fn default_tracking_duration() -> Duration {
    Duration::from_secs(900) // 15 minutes
}

impl ReorgConfig {
    /// Create config for ETH mainnet (64 block finality)
    pub fn eth_mainnet() -> Self {
        Self {
            enabled: true,
            finality_blocks: 64,
            ..Default::default()
        }
    }

    /// Create config for ETH testnet (faster finality for testing)
    pub fn eth_testnet() -> Self {
        Self {
            enabled: true,
            finality_blocks: 12,
            ..Default::default()
        }
    }

    /// Create config for Starcoin (16 block finality due to DAG)
    pub fn starcoin() -> Self {
        Self {
            enabled: true,
            finality_blocks: 16,
            ..Default::default()
        }
    }

    /// Calculate window size based on finality_blocks and multiplier
    pub fn window_size(&self) -> u64 {
        self.finality_blocks * self.window_multiplier
    }
}

// Re-export FinalityMode from the finality module for unified usage
pub use crate::finality::FinalityMode;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reorg_config_presets() {
        let eth = ReorgConfig::eth_mainnet();
        assert_eq!(eth.finality_blocks, 64);
        assert_eq!(eth.window_size(), 128);

        let starcoin = ReorgConfig::starcoin();
        assert_eq!(starcoin.finality_blocks, 16);
        assert_eq!(starcoin.window_size(), 32);
    }

    #[test]
    fn test_fetch_config_default() {
        let config = FetchConfig::default();
        assert_eq!(config.max_block_range, 1000);
        assert_eq!(config.poll_interval, Duration::from_secs(2));
    }
}
