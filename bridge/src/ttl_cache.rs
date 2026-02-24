// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Generic TTL (Time-To-Live) cache for reducing RPC calls.
//!
//! This module provides a thread-safe cache with automatic expiration.
//! Used for caching data that changes infrequently to avoid repeated RPC calls.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// A thread-safe TTL cache for atomic-compatible types.
///
/// Uses atomic operations for lock-free reads of the cached value,
/// with RwLock only for the timestamp to minimize contention.
///
/// # Type Parameters
/// - `T`: The cached value type (must implement `AtomicValue`)
///
/// # Example
/// ```ignore
/// let cache = TtlCache::<u64>::new(Duration::from_secs(5));
/// cache.update(12345).await;
/// if let Some(value) = cache.get_if_valid().await {
///     println!("Cached value: {}", value);
/// }
/// ```
#[derive(Debug)]
pub struct TtlCache<T: AtomicValue> {
    /// The atomic storage for the cached value
    value: T::Atomic,
    /// When the cache was last updated
    last_updated: RwLock<Option<Instant>>,
    /// How long the cache is valid
    cache_duration: Duration,
    /// Number of cache hits
    hits: AtomicU64,
    /// Number of cache misses
    misses: AtomicU64,
}

impl<T: AtomicValue> TtlCache<T> {
    /// Create a new cache with the specified TTL duration
    pub fn new(cache_duration: Duration) -> Self {
        Self {
            value: T::new_atomic(T::default_value()),
            last_updated: RwLock::new(None),
            cache_duration,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Create a new cache with TTL specified in seconds
    pub fn with_secs(secs: u64) -> Self {
        Self::new(Duration::from_secs(secs))
    }

    /// Check if cache is valid and return cached value if so
    pub async fn get_if_valid(&self) -> Option<T> {
        let last_updated = self.last_updated.read().await;
        if let Some(updated_at) = *last_updated {
            if updated_at.elapsed() < self.cache_duration {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(T::load(&self.value));
            }
        }
        None
    }

    /// Update the cache with a new value
    pub async fn update(&self, value: T) {
        self.misses.fetch_add(1, Ordering::Relaxed);
        T::store(&self.value, value);
        let mut last_updated = self.last_updated.write().await;
        *last_updated = Some(Instant::now());
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }

    /// Invalidate the cache (force next access to fetch fresh data)
    #[cfg(test)]
    pub async fn invalidate(&self) {
        let mut last_updated = self.last_updated.write().await;
        *last_updated = None;
    }
}

/// Cache statistics for monitoring
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
}

impl CacheStats {
    /// Calculate the cache hit rate (0.0 to 1.0)
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

/// Trait for types that can be stored atomically in the cache.
///
/// This abstraction allows the same cache implementation to work with
/// different atomic types (AtomicU64, AtomicBool, etc.)
pub trait AtomicValue: Copy + Send + Sync + 'static {
    /// The atomic type used for storage
    type Atomic: Send + Sync;

    /// Create a new atomic with the given initial value
    fn new_atomic(value: Self) -> Self::Atomic;

    /// Load the value from the atomic
    fn load(atomic: &Self::Atomic) -> Self;

    /// Store a value into the atomic
    fn store(atomic: &Self::Atomic, value: Self);

    /// Default value when cache is empty
    fn default_value() -> Self;
}

// Implementation for u64
impl AtomicValue for u64 {
    type Atomic = AtomicU64;

    fn new_atomic(value: Self) -> Self::Atomic {
        AtomicU64::new(value)
    }

    fn load(atomic: &Self::Atomic) -> Self {
        atomic.load(Ordering::Acquire)
    }

    fn store(atomic: &Self::Atomic, value: Self) {
        atomic.store(value, Ordering::Release);
    }

    fn default_value() -> Self {
        0
    }
}

// Implementation for bool
use std::sync::atomic::AtomicBool;

impl AtomicValue for bool {
    type Atomic = AtomicBool;

    fn new_atomic(value: Self) -> Self::Atomic {
        AtomicBool::new(value)
    }

    fn load(atomic: &Self::Atomic) -> Self {
        atomic.load(Ordering::Acquire)
    }

    fn store(atomic: &Self::Atomic, value: Self) {
        atomic.store(value, Ordering::Release);
    }

    fn default_value() -> Self {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_u64_cache_basic() {
        let cache = TtlCache::<u64>::with_secs(10);

        // Initially empty
        assert!(cache.get_if_valid().await.is_none());

        // Update and retrieve
        cache.update(12345).await;
        assert_eq!(cache.get_if_valid().await, Some(12345));

        // Update again
        cache.update(67890).await;
        assert_eq!(cache.get_if_valid().await, Some(67890));
    }

    #[tokio::test]
    async fn test_bool_cache_basic() {
        let cache = TtlCache::<bool>::with_secs(10);

        // Initially empty
        assert!(cache.get_if_valid().await.is_none());

        // Update and retrieve
        cache.update(true).await;
        assert_eq!(cache.get_if_valid().await, Some(true));

        // Update to false
        cache.update(false).await;
        assert_eq!(cache.get_if_valid().await, Some(false));
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = TtlCache::<u64>::new(Duration::from_millis(50));

        cache.update(100).await;
        assert_eq!(cache.get_if_valid().await, Some(100));

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(cache.get_if_valid().await.is_none());
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = TtlCache::<u64>::with_secs(100);

        // First access is a miss (triggers update)
        cache.update(42).await;

        // Next accesses are hits
        let _ = cache.get_if_valid().await;
        let _ = cache.get_if_valid().await;
        let _ = cache.get_if_valid().await;

        let stats = cache.stats();
        assert_eq!(stats.hits, 3);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_rate() - 0.75).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_cache_invalidate() {
        let cache = TtlCache::<bool>::with_secs(100);

        cache.update(true).await;
        assert_eq!(cache.get_if_valid().await, Some(true));

        cache.invalidate().await;
        assert!(cache.get_if_valid().await.is_none());
    }

    #[tokio::test]
    async fn test_zero_ttl_always_expired() {
        let cache = TtlCache::<u64>::with_secs(0);

        cache.update(999).await;

        // Even immediate access should miss with 0 TTL
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(cache.get_if_valid().await.is_none());
    }
}
