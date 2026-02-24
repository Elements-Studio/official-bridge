// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Caught-up signal tracking for chain syncers
//!
//! This module provides a mechanism to track when syncers have caught up
//! to the chain head. SecurityMonitor should only be activated after
//! both ETH and STC syncers are caught up to avoid false positives
//! during initial sync.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::watch;
use tracing::info;

/// Tracks caught-up status for a single chain
#[derive(Debug)]
pub struct ChainCaughtUpTracker {
    /// Chain name for logging
    chain: String,
    /// Whether this chain is caught up
    caught_up: AtomicBool,
    /// Sender to notify listeners
    sender: watch::Sender<bool>,
    /// Receiver for listeners
    receiver: watch::Receiver<bool>,
}

impl ChainCaughtUpTracker {
    pub fn new(chain: &str) -> Self {
        let (sender, receiver) = watch::channel(false);
        Self {
            chain: chain.to_string(),
            caught_up: AtomicBool::new(false),
            sender,
            receiver,
        }
    }

    /// Mark this chain as caught up
    pub fn set_caught_up(&self) {
        if !self.caught_up.swap(true, Ordering::SeqCst) {
            info!("[{}] Chain caught up to head", self.chain);
            let _ = self.sender.send(true);
        }
    }

    /// Check if this chain is caught up
    pub fn is_caught_up(&self) -> bool {
        self.caught_up.load(Ordering::SeqCst)
    }

    /// Subscribe to caught-up notifications
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.receiver.clone()
    }
}

/// Tracks caught-up status for multiple chains
pub struct CaughtUpCoordinator {
    eth_tracker: Arc<ChainCaughtUpTracker>,
    stc_tracker: Arc<ChainCaughtUpTracker>,
}

impl CaughtUpCoordinator {
    pub fn new() -> Self {
        Self {
            eth_tracker: Arc::new(ChainCaughtUpTracker::new("ETH")),
            stc_tracker: Arc::new(ChainCaughtUpTracker::new("STC")),
        }
    }

    /// Get ETH tracker
    pub fn eth_tracker(&self) -> Arc<ChainCaughtUpTracker> {
        self.eth_tracker.clone()
    }

    /// Get STC tracker
    pub fn stc_tracker(&self) -> Arc<ChainCaughtUpTracker> {
        self.stc_tracker.clone()
    }

    /// Check if both chains are caught up
    pub fn all_caught_up(&self) -> bool {
        self.eth_tracker.is_caught_up() && self.stc_tracker.is_caught_up()
    }

    /// Wait for both chains to be caught up
    pub async fn wait_all_caught_up(&self) {
        let mut eth_rx = self.eth_tracker.subscribe();
        let mut stc_rx = self.stc_tracker.subscribe();

        loop {
            if self.all_caught_up() {
                info!("[CaughtUpCoordinator] Both chains are caught up");
                return;
            }

            tokio::select! {
                _ = eth_rx.changed() => {
                    if self.all_caught_up() {
                        info!("[CaughtUpCoordinator] Both chains are caught up");
                        return;
                    }
                }
                _ = stc_rx.changed() => {
                    if self.all_caught_up() {
                        info!("[CaughtUpCoordinator] Both chains are caught up");
                        return;
                    }
                }
            }
        }
    }
}

impl Default for CaughtUpCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared caught-up coordinator type
pub type SharedCaughtUpCoordinator = Arc<CaughtUpCoordinator>;

/// Create a new shared caught-up coordinator
pub fn create_caught_up_coordinator() -> SharedCaughtUpCoordinator {
    Arc::new(CaughtUpCoordinator::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_tracker_initial_state() {
        let tracker = ChainCaughtUpTracker::new("ETH");
        assert!(!tracker.is_caught_up());
    }

    #[test]
    fn test_chain_tracker_set_caught_up() {
        let tracker = ChainCaughtUpTracker::new("ETH");
        tracker.set_caught_up();
        assert!(tracker.is_caught_up());
    }

    #[test]
    fn test_chain_tracker_idempotent() {
        // Setting caught_up multiple times should be idempotent
        let tracker = ChainCaughtUpTracker::new("ETH");
        tracker.set_caught_up();
        tracker.set_caught_up();
        tracker.set_caught_up();
        assert!(tracker.is_caught_up());
    }

    #[test]
    fn test_chain_tracker_subscribe() {
        let tracker = ChainCaughtUpTracker::new("ETH");
        let rx = tracker.subscribe();
        assert!(!*rx.borrow()); // Initial value is false

        tracker.set_caught_up();
        // After set_caught_up, subscriber should see true
        assert!(*rx.borrow());
    }

    #[test]
    fn test_coordinator_initial_state() {
        let coordinator = CaughtUpCoordinator::new();
        assert!(!coordinator.all_caught_up());
    }

    #[test]
    fn test_coordinator_partial_caught_up() {
        let coordinator = CaughtUpCoordinator::new();
        coordinator.eth_tracker.set_caught_up();
        assert!(!coordinator.all_caught_up());
    }

    #[test]
    fn test_coordinator_all_caught_up() {
        let coordinator = CaughtUpCoordinator::new();
        coordinator.eth_tracker.set_caught_up();
        coordinator.stc_tracker.set_caught_up();
        assert!(coordinator.all_caught_up());
    }

    #[test]
    fn test_coordinator_stc_only_not_all_caught_up() {
        let coordinator = CaughtUpCoordinator::new();
        coordinator.stc_tracker.set_caught_up();
        assert!(!coordinator.all_caught_up());
    }

    #[test]
    fn test_coordinator_trackers_are_shared() {
        let coordinator = CaughtUpCoordinator::new();
        let eth_tracker = coordinator.eth_tracker();
        let stc_tracker = coordinator.stc_tracker();

        // Set via returned trackers
        eth_tracker.set_caught_up();
        stc_tracker.set_caught_up();

        // Should reflect in coordinator
        assert!(coordinator.all_caught_up());
    }

    #[tokio::test]
    async fn test_wait_all_caught_up() {
        let coordinator = Arc::new(CaughtUpCoordinator::new());
        let coordinator_clone = coordinator.clone();

        // Spawn task to wait
        let wait_handle = tokio::spawn(async move {
            coordinator_clone.wait_all_caught_up().await;
        });

        // Mark both as caught up
        coordinator.eth_tracker.set_caught_up();
        coordinator.stc_tracker.set_caught_up();

        // Wait should complete
        tokio::time::timeout(std::time::Duration::from_secs(1), wait_handle)
            .await
            .expect("Timeout waiting for caught up")
            .expect("Task panicked");
    }

    #[tokio::test]
    async fn test_wait_all_caught_up_delayed_signals() {
        let coordinator = Arc::new(CaughtUpCoordinator::new());
        let coordinator_clone = coordinator.clone();

        // Spawn task to wait
        let wait_handle = tokio::spawn(async move {
            coordinator_clone.wait_all_caught_up().await;
        });

        // Delay before setting ETH caught up
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        coordinator.eth_tracker.set_caught_up();

        // Delay before setting STC caught up
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        coordinator.stc_tracker.set_caught_up();

        // Wait should complete
        tokio::time::timeout(std::time::Duration::from_secs(1), wait_handle)
            .await
            .expect("Timeout waiting for caught up")
            .expect("Task panicked");
    }

    #[tokio::test]
    async fn test_wait_all_caught_up_already_caught_up() {
        let coordinator = Arc::new(CaughtUpCoordinator::new());

        // Set both caught up before waiting
        coordinator.eth_tracker.set_caught_up();
        coordinator.stc_tracker.set_caught_up();

        // Wait should complete immediately
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            coordinator.wait_all_caught_up(),
        )
        .await
        .expect("Should complete immediately when already caught up");
    }

    #[tokio::test]
    async fn test_wait_concurrent_set_caught_up() {
        let coordinator = Arc::new(CaughtUpCoordinator::new());
        let coordinator_clone = coordinator.clone();

        // Spawn wait task
        let wait_handle = tokio::spawn(async move {
            coordinator_clone.wait_all_caught_up().await;
        });

        // Spawn concurrent tasks to set caught up
        let eth_tracker = coordinator.eth_tracker();
        let stc_tracker = coordinator.stc_tracker();

        let eth_handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            eth_tracker.set_caught_up();
        });

        let stc_handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            stc_tracker.set_caught_up();
        });

        // All should complete
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let _ = eth_handle.await;
            let _ = stc_handle.await;
            let _ = wait_handle.await;
        })
        .await
        .expect("Concurrent operations should complete");

        assert!(coordinator.all_caught_up());
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let tracker = Arc::new(ChainCaughtUpTracker::new("ETH"));

        // Create multiple subscribers
        let rx1 = tracker.subscribe();
        let rx2 = tracker.subscribe();
        let rx3 = tracker.subscribe();

        // All should initially be false
        assert!(!*rx1.borrow());
        assert!(!*rx2.borrow());
        assert!(!*rx3.borrow());

        // Set caught up
        tracker.set_caught_up();

        // All subscribers should see true
        assert!(*rx1.borrow());
        assert!(*rx2.borrow());
        assert!(*rx3.borrow());
    }

    #[test]
    fn test_create_caught_up_coordinator() {
        let coordinator = create_caught_up_coordinator();
        assert!(!coordinator.all_caught_up());

        coordinator.eth_tracker.set_caught_up();
        coordinator.stc_tracker.set_caught_up();
        assert!(coordinator.all_caught_up());
    }
}
