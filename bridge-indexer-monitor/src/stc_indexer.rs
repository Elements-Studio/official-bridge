// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Starcoin Bridge Syncer Module
//!
//! Unified syncer that provides events to both Monitor and DB Handler.
//!
//! ## Architecture
//!
//! ```text
//! StarcoinChainSyncer (唯一数据源)
//!        │
//!        ▼ (SyncerEvent)
//!   ┌────┴────────────┐
//!   │                 │
//!   ▼                 ▼
//! Monitor          StcEventHandler
//! (broadcaster)    (直接写 PostgreSQL)
//! ```

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use starcoin_bridge::chain_syncer::starcoin::{
    StarcoinChainSyncer, StarcoinChainSyncerConfig, UnfinalizedTxTracker,
};
use starcoin_bridge::chain_syncer::SyncerEvent;
use starcoin_bridge::simple_starcoin_rpc::SimpleStarcoinRpcClient;
use starcoin_bridge_pg_db::Db;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::caught_up::ChainCaughtUpTracker;
use crate::indexer_progress::IndexerProgressStore;
use crate::telegram::{NotifyChain, SharedTelegramNotifier};

/// Configuration for Starcoin event syncer
#[derive(Debug)]
pub struct StarcoinSyncerConfig {
    /// RPC URL for Starcoin
    pub rpc_url: String,
    /// Bridge contract address
    pub bridge_address: String,
    /// Starting block number (0 to start from latest)
    pub start_block: u64,
    /// Polling interval
    pub poll_interval: Duration,
    /// Number of blocks to consider finalized (default: 16 for Starcoin)
    pub finality_blocks: u64,
    /// Enable reorg detection (polling-based)
    pub enable_reorg_detection: bool,
    /// Optional oneshot receiver to wait for before starting syncer
    /// This allows Monitor to subscribe to broadcaster before syncing begins
    pub ready_signal: Option<tokio::sync::oneshot::Receiver<()>>,
    /// Telegram notifier for sending alerts
    pub telegram: Option<SharedTelegramNotifier>,
    /// Caught-up tracker for signaling when syncer is up to date
    pub caught_up_tracker: Option<Arc<ChainCaughtUpTracker>>,
}

impl Default for StarcoinSyncerConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::new(),
            bridge_address: String::new(),
            start_block: 0,
            poll_interval: Duration::from_secs(3),
            finality_blocks: 16,
            enable_reorg_detection: true,
            ready_signal: None,
            telegram: None,
            caught_up_tracker: None,
        }
    }
}

/// Result from starting Starcoin syncer
pub struct StarcoinSyncerResult {
    /// Task handles for the syncer
    pub handles: Vec<JoinHandle<()>>,
    /// Event receiver for StcEventHandler (DB writes)
    pub event_rx: mpsc::Receiver<SyncerEvent>,
    /// Unfinalized transaction tracker
    pub unfinalized_tracker: Arc<RwLock<UnfinalizedTxTracker>>,
    /// Caught-up tracker
    pub caught_up_tracker: Arc<ChainCaughtUpTracker>,
}

/// Start the unified Starcoin syncer with ready signal support
///
/// This version creates a ready signal channel internally. The caller should:
/// 1. Call this function to start the syncer
/// 2. Subscribe to the broadcaster
/// 3. Call the returned ready_sender.send(()) to signal that Monitor is ready
///
/// ## Watermark Handling (via progress_store table)
/// - Uses IndexerProgressStore for persistent watermark tracking
/// - Calculates start from: max(config_start_block, watermark_from_table+1, max_finalized_event+1)
/// - Falls back to config.start_block if no records exist
///
/// Returns:
/// - result: Standard syncer result (handles, broadcaster, event_rx)
/// - ready_sender: Optional oneshot sender to signal when Monitor is ready
/// - progress_store: IndexerProgressStore for updating watermarks during event processing
pub async fn start_starcoin_syncer_with_ready_signal(
    mut config: StarcoinSyncerConfig,
    db: &Db,
    cancel: CancellationToken,
) -> Result<(
    StarcoinSyncerResult,
    Option<tokio::sync::oneshot::Sender<()>>,
    IndexerProgressStore,
)> {
    // Create progress store and get start block using the new watermark mechanism
    let progress_store = IndexerProgressStore::new(db.clone());
    let start_block = progress_store.get_stc_start_block(config.start_block).await;
    config.start_block = start_block;
    info!(
        "[STC] Using start block from progress_store: {}",
        start_block
    );

    // Create ready signal channel if not already provided
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    config.ready_signal = Some(ready_rx);

    let result = start_starcoin_syncer(config, cancel).await?;
    Ok((result, Some(ready_tx), progress_store))
}

/// Start the unified Starcoin syncer
///
/// Returns:
/// - handles: Background task handles
/// - event_rx: For StcEventHandler to receive events and write to DB
/// - caught_up_tracker: For signaling when syncer is up to date
pub async fn start_starcoin_syncer(
    config: StarcoinSyncerConfig,
    cancel: CancellationToken,
) -> Result<StarcoinSyncerResult> {
    info!(
        "Starting Starcoin syncer (bridge={}, start_block={}, finality_blocks={}, reorg_detection={})",
        config.bridge_address,
        config.start_block,
        config.finality_blocks,
        config.enable_reorg_detection
    );

    // Build StarcoinChainSyncer config - always use mainnet config with finality
    let syncer_config = StarcoinChainSyncerConfig::mainnet(&config.rpc_url)
        .with_module(&config.bridge_address, config.start_block)
        .with_reorg_detection(config.enable_reorg_detection)
        .with_finality_blocks(config.finality_blocks);

    let mut syncer_config = syncer_config;
    syncer_config.fetch.finalized_block_interval = config.poll_interval;
    // Starcoin RPC has a max block range limit of 32
    syncer_config.fetch.max_block_range = 32;

    // Create RPC client
    let rpc = SimpleStarcoinRpcClient::new(&config.rpc_url, &config.bridge_address);

    // Create syncer
    let syncer = StarcoinChainSyncer::new(syncer_config, rpc)?;
    let unfinalized_tracker = syncer.unfinalized_tracker();

    // Create or use provided caught-up tracker
    let caught_up_tracker = config
        .caught_up_tracker
        .clone()
        .unwrap_or_else(|| Arc::new(ChainCaughtUpTracker::new("STC")));

    // Create event channel for StcEventHandler
    let (handler_tx, handler_rx) = mpsc::channel::<SyncerEvent>(1000);

    // Run syncer and get event receiver
    let (syncer_handles, mut event_rx) = syncer.run(cancel.clone()).await?;

    // Start event dispatcher task that fans out events
    let cancel_clone = cancel.clone();
    let ready_signal = config.ready_signal;
    let telegram = config.telegram.clone();
    let caught_up_tracker_clone = caught_up_tracker.clone();

    let dispatcher_handle = tokio::spawn(async move {
        info!("[StarcoinSyncer] Event dispatcher started");

        // Wait for ready signal if provided (allows initialization to complete first)
        if let Some(ready_rx) = ready_signal {
            info!("[StarcoinSyncer] Waiting for ready signal before processing events...");
            tokio::select! {
                result = ready_rx => {
                    match result {
                        Ok(_) => info!("[StarcoinSyncer] Ready signal received, starting event processing"),
                        Err(_) => {
                            warn!("[StarcoinSyncer] Ready signal sender dropped, starting event processing anyway");
                        }
                    }
                }
                _ = cancel_clone.cancelled() => {
                    info!("[StarcoinSyncer] Dispatcher cancelled while waiting for ready signal");
                    return;
                }
            }
        }

        loop {
            tokio::select! {
                _ = cancel_clone.cancelled() => {
                    info!("[StarcoinSyncer] Dispatcher cancelled");
                    break;
                }
                event = event_rx.recv() => {
                    match event {
                        Some(syncer_event) => {
                            // Handle caught-up signal
                            if let SyncerEvent::CaughtUp { height, .. } = &syncer_event {
                                info!("[StarcoinSyncer] Caught up to chain head at block {}", height);
                                caught_up_tracker_clone.set_caught_up();
                            }

                            // Handle reorg - send telegram notification
                            if let SyncerEvent::Reorg(ref reorg_info) = syncer_event {
                                warn!(
                                    "[StarcoinSyncer] Reorg: fork_point={}, {} orphaned blocks",
                                    reorg_info.fork_point,
                                    reorg_info.orphaned_blocks.len()
                                );
                                if let Some(ref tg) = telegram {
                                    let _ = tg.notify_reorg(
                                        NotifyChain::Starcoin,
                                        reorg_info.fork_point,
                                        reorg_info.depth as u64,
                                        reorg_info.orphaned_blocks.len(),
                                    ).await;
                                }
                            }

                            // Send event to handler
                            if let Err(e) = handler_tx.send(syncer_event).await {
                                warn!("[StarcoinSyncer] Failed to send to handler: {:?}", e);
                            }
                        }
                        None => {
                            info!("[StarcoinSyncer] Event channel closed");
                            break;
                        }
                    }
                }
            }
        }

        info!("[StarcoinSyncer] Dispatcher stopped");
    });

    let mut handles = syncer_handles;
    handles.push(dispatcher_handle);

    Ok(StarcoinSyncerResult {
        handles,
        event_rx: handler_rx,
        unfinalized_tracker,
        caught_up_tracker,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = StarcoinSyncerConfig::default();
        assert!(config.rpc_url.is_empty());
        assert_eq!(config.finality_blocks, 16);
        assert!(config.enable_reorg_detection);
    }
}
