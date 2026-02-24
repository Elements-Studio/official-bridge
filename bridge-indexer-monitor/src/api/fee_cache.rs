// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fee estimate cache
//!
//! Simple cache for gas usage estimates. Syncer updates it asynchronously.
//! Always returns cached value - no staleness tracking needed.

use crate::api::types::FeeEstimateResponse;
use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;
use tracing::debug;

/// Global fee cache instance
static GLOBAL_FEE_CACHE: OnceLock<Arc<FeeCache>> = OnceLock::new();

/// Initialize the global fee cache
pub fn init_global_fee_cache() -> Arc<FeeCache> {
    GLOBAL_FEE_CACHE
        .get_or_init(|| Arc::new(FeeCache::new()))
        .clone()
}

/// Get the global fee cache. Returns None if not initialized.
pub fn get_global_fee_cache() -> Option<Arc<FeeCache>> {
    GLOBAL_FEE_CACHE.get().cloned()
}

/// Fee estimate cache
///
/// Stores the latest gas usage for each operation type.
/// Syncer updates this asynchronously when new events are processed.
pub struct FeeCache {
    /// Cached fee values
    value: RwLock<FeeEstimateResponse>,
}

impl FeeCache {
    /// Create a new fee cache
    pub fn new() -> Self {
        Self {
            value: RwLock::new(FeeEstimateResponse::default()),
        }
    }

    /// Get cached value
    pub async fn get(&self) -> FeeEstimateResponse {
        self.value.read().await.clone()
    }

    /// Update the cached value
    pub async fn update(&self, new_value: FeeEstimateResponse) {
        let mut value = self.value.write().await;
        *value = new_value;
        debug!("Fee cache updated");
    }

    /// Update a single field in the cache
    pub async fn update_single(&self, data_source: &str, status: &str, gas: i64) {
        let mut value = self.value.write().await;
        match (data_source, status) {
            ("ETH", "Deposited") => value.eth_to_starcoin_deposit_gas = gas,
            ("STARCOIN", "Approved") => value.eth_to_starcoin_approval_gas = gas,
            ("STARCOIN", "Claimed") => value.eth_to_starcoin_claim_gas = gas,
            ("STARCOIN", "Deposited") => value.starcoin_to_eth_deposit_gas = gas,
            ("ETH", "Approved") => value.starcoin_to_eth_approval_gas = gas,
            ("ETH", "Claimed") => value.starcoin_to_eth_claim_gas = gas,
            _ => return,
        }
        debug!(
            "Fee cache updated: {}/{} -> gas={}",
            data_source, status, gas
        );
    }
}

impl Default for FeeCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fee_cache_basic() {
        let cache = FeeCache::new();

        // Initially all zeros
        let cached = cache.get().await;
        assert_eq!(cached.eth_to_starcoin_deposit_gas, 0);

        // Update full cache
        let fees = FeeEstimateResponse {
            eth_to_starcoin_deposit_gas: 100,
            eth_to_starcoin_approval_gas: 200,
            eth_to_starcoin_claim_gas: 300,
            starcoin_to_eth_deposit_gas: 150,
            starcoin_to_eth_approval_gas: 250,
            starcoin_to_eth_claim_gas: 350,
        };
        cache.update(fees).await;

        let cached = cache.get().await;
        assert_eq!(cached.eth_to_starcoin_deposit_gas, 100);
        assert_eq!(cached.starcoin_to_eth_claim_gas, 350);
    }

    #[tokio::test]
    async fn test_fee_cache_update_single() {
        let cache = FeeCache::new();

        // Update individual fields
        cache.update_single("ETH", "Deposited", 128000).await;
        cache.update_single("STARCOIN", "Approved", 50000).await;

        let cached = cache.get().await;
        assert_eq!(cached.eth_to_starcoin_deposit_gas, 128000);
        assert_eq!(cached.eth_to_starcoin_approval_gas, 50000);
        assert_eq!(cached.eth_to_starcoin_claim_gas, 0); // Not updated
    }
}
