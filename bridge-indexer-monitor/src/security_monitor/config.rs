// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Security Monitor Configuration

use serde::{Deserialize, Serialize};

/// Configuration for the security monitor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SecurityMonitorConfig {
    /// Enable the security monitor
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Path to emergency keys file (for pause execution)
    pub emergency_keys_path: Option<String>,

    /// Path to pre-signed emergency pause signatures
    pub emergency_signatures_path: Option<String>,

    /// ETH RPC URL for pause execution
    pub eth_rpc_url: Option<String>,

    /// ETH bridge contract address
    pub eth_bridge_address: Option<String>,

    /// Starcoin RPC URL for pause execution
    pub stc_rpc_url: Option<String>,

    /// Starcoin bridge address
    pub stc_bridge_address: Option<String>,

    /// Batch size for DB scanning (default: 100)
    #[serde(default = "default_batch_size")]
    pub db_scan_batch_size: usize,

    /// Chain IDs for this deployment
    pub eth_chain_id: Option<u8>,
    pub stc_chain_id: Option<u8>,
}

fn default_batch_size() -> usize {
    100
}

fn default_enabled() -> bool {
    true
}

impl Default for SecurityMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            emergency_keys_path: None,
            emergency_signatures_path: None,
            eth_rpc_url: None,
            eth_bridge_address: None,
            stc_rpc_url: None,
            stc_bridge_address: None,
            db_scan_batch_size: default_batch_size(),
            eth_chain_id: None,
            stc_chain_id: None,
        }
    }
}


