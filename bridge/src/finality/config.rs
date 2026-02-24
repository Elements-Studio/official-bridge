// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Configuration types for finality checking

use serde::{Deserialize, Serialize};

/// Mode of finality checking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FinalityMode {
    /// Use native chain finality API (e.g., ETH 'finalized' block)
    #[default]
    Native,
    /// Use block counting for finality (count N blocks after the target)
    BlockCounting,
}

/// Configuration for finality checking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityConfig {
    /// Finality mode to use
    #[serde(default)]
    pub mode: FinalityMode,

    /// Number of confirmation blocks required
    /// * For BlockCounting mode: block is final when it has N descendants
    /// * For Native mode: used as fallback or for validation
    ///
    /// Default: 64 for ETH, 16 for Starcoin
    #[serde(default = "default_confirmation_blocks")]
    pub confirmation_blocks: u64,

    /// Cache duration for finalized block queries (in seconds)
    #[serde(default = "default_cache_duration_secs")]
    pub cache_duration_secs: u64,
}

fn default_confirmation_blocks() -> u64 {
    64 // ETH mainnet default
}

fn default_cache_duration_secs() -> u64 {
    2
}

impl Default for FinalityConfig {
    fn default() -> Self {
        Self {
            mode: FinalityMode::Native,
            confirmation_blocks: default_confirmation_blocks(),
            cache_duration_secs: default_cache_duration_secs(),
        }
    }
}

impl FinalityConfig {
    /// Create config for ETH mainnet (native finality)
    pub fn eth_mainnet() -> Self {
        Self {
            mode: FinalityMode::Native,
            confirmation_blocks: 64,
            cache_duration_secs: 2,
        }
    }

    /// Create config for ETH testnet (native finality with faster blocks)
    pub fn eth_testnet() -> Self {
        Self {
            mode: FinalityMode::Native,
            confirmation_blocks: 12,
            cache_duration_secs: 2,
        }
    }

    /// Create config for Starcoin mainnet/testnet (always block counting)
    pub fn starcoin() -> Self {
        Self {
            mode: FinalityMode::BlockCounting,
            confirmation_blocks: 16,
            cache_duration_secs: 2,
        }
    }

    /// Builder: set confirmation blocks
    pub fn with_confirmation_blocks(mut self, blocks: u64) -> Self {
        self.confirmation_blocks = blocks;
        self
    }

    /// Builder: set finality mode
    pub fn with_mode(mut self, mode: FinalityMode) -> Self {
        self.mode = mode;
        self
    }

    /// Builder: set cache duration
    pub fn with_cache_duration(mut self, secs: u64) -> Self {
        self.cache_duration_secs = secs;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preset_configs() {
        let eth = FinalityConfig::eth_mainnet();
        assert_eq!(eth.mode, FinalityMode::Native);
        assert_eq!(eth.confirmation_blocks, 64);

        let stc = FinalityConfig::starcoin();
        assert_eq!(stc.mode, FinalityMode::BlockCounting);
        assert_eq!(stc.confirmation_blocks, 16);
    }

    #[test]
    fn test_config_builder() {
        let config = FinalityConfig::default()
            .with_mode(FinalityMode::BlockCounting)
            .with_confirmation_blocks(32)
            .with_cache_duration(5);

        assert_eq!(config.mode, FinalityMode::BlockCounting);
        assert_eq!(config.confirmation_blocks, 32);
        assert_eq!(config.cache_duration_secs, 5);
    }
}
