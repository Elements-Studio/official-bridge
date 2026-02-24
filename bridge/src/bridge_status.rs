// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Bridge status cache for efficient paused state checking.
//!
//! This module provides a cached mechanism to check if the bridge is paused,
//! avoiding excessive RPC calls when processing multiple actions.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::{debug, error, warn};

use crate::error::BridgeResult;
use crate::retry_with_max_elapsed_time;
use crate::ttl_cache::{CacheStats, TtlCache};
use crate::types::TransferDirection;

/// Type aliases for backward compatibility
pub type BridgeStatusCache = TtlCache<bool>;
pub type BridgeStatusCacheStats = CacheStats;

/// Trait for clients that can check bridge paused status
#[async_trait]
pub trait BridgePausedClient: Send + Sync {
    /// Check if the bridge is currently paused
    async fn is_bridge_paused(&self) -> BridgeResult<bool>;
}

/// Default cache duration for bridge paused status (in seconds)
const DEFAULT_CACHE_DURATION_SECS: u64 = 5;

/// Maximum retry duration when fetching bridge status
const MAX_RETRY_DURATION_SECS: u64 = 60;

/// Bridge status checker with caching
pub struct BridgeStatusChecker {
    cache: Arc<TtlCache<bool>>,
}

impl Default for BridgeStatusChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl BridgeStatusChecker {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(TtlCache::with_secs(DEFAULT_CACHE_DURATION_SECS)),
        }
    }

    pub fn with_cache_duration(cache_duration_secs: u64) -> Self {
        Self {
            cache: Arc::new(TtlCache::with_secs(cache_duration_secs)),
        }
    }

    /// Check if bridge is paused, using cache when possible
    pub async fn is_bridge_paused<C: BridgePausedClient>(&self, client: &C) -> Result<bool, ()> {
        // Check cache first
        if let Some(cached) = self.cache.get_if_valid().await {
            debug!("Bridge paused status from cache: {}", cached);
            return Ok(cached);
        }

        // Cache miss - fetch from client
        let result = retry_with_max_elapsed_time!(
            client.is_bridge_paused(),
            Duration::from_secs(MAX_RETRY_DURATION_SECS)
        );

        match result {
            Ok(Ok(is_paused)) => {
                debug!("Bridge paused status from RPC: {}", is_paused);
                self.cache.update(is_paused).await;
                Ok(is_paused)
            }
            Ok(Err(e)) => {
                error!("Failed to get bridge status: {:?}", e);
                Err(())
            }
            Err(e) => {
                error!("Failed to get bridge status after retry: {:?}", e);
                Err(())
            }
        }
    }

    /// Check if signing should proceed for a given action based on bridge status and direction
    ///
    /// This improved check considers:
    /// 1. Whether the bridge is paused
    /// 2. The direction of the transfer (Starcoin->Eth or Eth->Starcoin)
    /// 3. Governance actions always proceed even when bridge is paused
    pub async fn should_proceed_signing<C: BridgePausedClient>(
        &self,
        client: &C,
        direction: Option<TransferDirection>,
    ) -> bool {
        // Governance actions (direction = None) always proceed
        // They may be needed to unpause the bridge
        if direction.is_none() {
            debug!("Governance action - proceeding with signing regardless of bridge status");
            return true;
        }

        match self.is_bridge_paused(client).await {
            Ok(is_paused) => {
                if is_paused {
                    warn!(
                        "Bridge is paused, skipping signing for {:?} transfer",
                        direction
                    );
                    false
                } else {
                    true
                }
            }
            Err(()) => {
                // If we can't determine bridge status, err on the side of caution
                warn!("Could not determine bridge status, skipping signing");
                false
            }
        }
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> CacheStats {
        self.cache.stats()
    }

    /// Get a clone of the cache for sharing between tasks
    pub fn cache(&self) -> Arc<TtlCache<bool>> {
        self.cache.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Mock client that tracks call count
    struct MockBridgeClient {
        paused: AtomicBool,
        call_count: AtomicUsize,
    }

    impl MockBridgeClient {
        fn new(paused: bool) -> Self {
            Self {
                paused: AtomicBool::new(paused),
                call_count: AtomicUsize::new(0),
            }
        }

        fn set_paused(&self, paused: bool) {
            self.paused.store(paused, Ordering::SeqCst);
        }

        fn call_count(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl BridgePausedClient for MockBridgeClient {
        async fn is_bridge_paused(&self) -> crate::error::BridgeResult<bool> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(self.paused.load(Ordering::SeqCst))
        }
    }

    #[tokio::test]
    async fn test_cache_basic_functionality() {
        let cache = TtlCache::<bool>::with_secs(10); // 10 second cache

        // Initially, cache should be empty
        assert!(cache.get_if_valid().await.is_none());

        // Update cache
        cache.update(true).await;

        // Cache should now return value
        assert_eq!(cache.get_if_valid().await, Some(true));

        // Update with different value
        cache.update(false).await;
        assert_eq!(cache.get_if_valid().await, Some(false));
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = TtlCache::<bool>::with_secs(0); // 0 second cache = immediate expiry

        cache.update(true).await;

        // Sleep a bit to ensure expiry
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Cache should be expired
        assert!(cache.get_if_valid().await.is_none());
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = TtlCache::<bool>::with_secs(100); // Long cache duration

        cache.update(true).await;

        // First call after update is a miss
        assert_eq!(cache.stats().misses, 1);
        assert_eq!(cache.stats().hits, 0);

        // Subsequent valid reads are hits
        let _ = cache.get_if_valid().await;
        let _ = cache.get_if_valid().await;
        let _ = cache.get_if_valid().await;

        assert_eq!(cache.stats().hits, 3);
        assert_eq!(cache.stats().misses, 1);
    }

    #[tokio::test]
    async fn test_checker_uses_cache() {
        let client = MockBridgeClient::new(false);
        let checker = BridgeStatusChecker::with_cache_duration(100);

        // First call should hit RPC
        let result = checker.is_bridge_paused(&client).await.unwrap();
        assert!(!result);
        assert_eq!(client.call_count(), 1);

        // Second call should use cache
        let result = checker.is_bridge_paused(&client).await.unwrap();
        assert!(!result);
        assert_eq!(client.call_count(), 1); // No additional RPC call

        // Third call should still use cache
        let result = checker.is_bridge_paused(&client).await.unwrap();
        assert!(!result);
        assert_eq!(client.call_count(), 1);

        // Verify cache stats
        let stats = checker.cache_stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 2);
    }

    #[tokio::test]
    async fn test_checker_refresh_after_invalidation() {
        let client = MockBridgeClient::new(false);
        let checker = BridgeStatusChecker::with_cache_duration(100);

        // First call
        let _ = checker.is_bridge_paused(&client).await.unwrap();
        assert_eq!(client.call_count(), 1);

        // Change client state
        client.set_paused(true);

        // Second call should still return cached value (false)
        let result = checker.is_bridge_paused(&client).await.unwrap();
        assert!(!result); // Still cached as false

        // Invalidate cache
        checker.cache.invalidate().await;

        // Now should fetch new value
        let result = checker.is_bridge_paused(&client).await.unwrap();
        assert!(result); // Now true
        assert_eq!(client.call_count(), 2);
    }

    #[tokio::test]
    async fn test_should_proceed_governance_action() {
        let client = MockBridgeClient::new(true); // Bridge is paused
        let checker = BridgeStatusChecker::with_cache_duration(100);

        // Governance actions (None direction) should always proceed
        let result = checker.should_proceed_signing(&client, None).await;
        assert!(result);
        assert_eq!(client.call_count(), 0); // Didn't even check bridge status
    }

    #[tokio::test]
    async fn test_should_proceed_transfer_when_paused() {
        let client = MockBridgeClient::new(true); // Bridge is paused
        let checker = BridgeStatusChecker::with_cache_duration(100);

        // Transfer should be blocked when bridge is paused
        let result = checker
            .should_proceed_signing(&client, Some(TransferDirection::StarcoinToEth))
            .await;
        assert!(!result);

        let result = checker
            .should_proceed_signing(&client, Some(TransferDirection::EthToStarcoin))
            .await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_should_proceed_transfer_when_not_paused() {
        let client = MockBridgeClient::new(false); // Bridge is not paused
        let checker = BridgeStatusChecker::with_cache_duration(100);

        // Transfer should proceed when bridge is not paused
        let result = checker
            .should_proceed_signing(&client, Some(TransferDirection::StarcoinToEth))
            .await;
        assert!(result);

        let result = checker
            .should_proceed_signing(&client, Some(TransferDirection::EthToStarcoin))
            .await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_cache_hit_rate() {
        let stats = CacheStats {
            hits: 80,
            misses: 20,
        };
        assert!((stats.hit_rate() - 0.8).abs() < 0.001);

        let empty_stats = CacheStats { hits: 0, misses: 0 };
        assert_eq!(empty_stats.hit_rate(), 0.0);
    }
}
