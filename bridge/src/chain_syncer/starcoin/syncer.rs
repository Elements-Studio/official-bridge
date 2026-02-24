// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Starcoin Chain Syncer Implementation
//!
//! Unified syncer that combines:
//! - Event/Log fetching from Starcoin RPC
//! - Finalized block tracking (via DAG blue block confirmation)
//! - Simple reorg detection via polling
//!
//! ## Starcoin Finality Model
//!
//! Starcoin uses DAG-based consensus where:
//! - Blocks are finalized when they are in the "blue set" (confirmed)
//! - `chain.get_transaction_info` returns info with `is_in_dag_blue_set` flag
//! - We poll unfinalized transactions until they become finalized or reorged
//!
//! ## Reorg Detection
//!
//! For Starcoin, reorg detection is simpler:
//! - Poll unfinalized transactions every 10s
//! - If txn becomes finalized (in blue set), mark as finalized
//! - If txn is reorged (no longer found or different status), stop polling
//! - Provide API to query recovery status

use crate::chain_syncer::common::{
    BlockId, ChainLog, ReorgInfo, SyncError, SyncResult, SyncerEvent,
};
use crate::metrics::BridgeMetrics;
use crate::simple_starcoin_rpc::SimpleStarcoinRpcClient;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{self, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::config::StarcoinChainSyncerConfig;

/// Status of an unfinalized transaction being tracked
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnfinalizedTxStatus {
    /// Transaction is pending, waiting for finalization
    Pending,
    /// Transaction has been finalized (in blue set)
    Finalized,
    /// Transaction was reorged out
    Reorged,
    /// Transaction not found (might be dropped or invalid)
    NotFound,
}

/// Information about an unfinalized transaction being tracked
#[derive(Debug, Clone)]
pub struct UnfinalizedTxInfo {
    /// Transaction hash
    pub tx_hash: String,
    /// Block number where the transaction was included
    pub block_number: u64,
    /// Block hash (if available)
    pub block_hash: Option<String>,
    /// Current status
    pub status: UnfinalizedTxStatus,
    /// When tracking started
    pub started_at: Instant,
    /// Last poll time
    pub last_polled: Instant,
    /// Number of poll attempts
    pub poll_count: u32,
}

/// Tracker for unfinalized transactions
#[derive(Debug, Default)]
pub struct UnfinalizedTxTracker {
    /// Map of tx_hash -> UnfinalizedTxInfo
    txns: HashMap<String, UnfinalizedTxInfo>,
}

impl UnfinalizedTxTracker {
    pub fn new() -> Self {
        Self {
            txns: HashMap::new(),
        }
    }

    /// Track a new unfinalized transaction
    pub fn track(&mut self, tx_hash: String, block_number: u64, block_hash: Option<String>) {
        if !self.txns.contains_key(&tx_hash) {
            let now = Instant::now();
            self.txns.insert(
                tx_hash.clone(),
                UnfinalizedTxInfo {
                    tx_hash,
                    block_number,
                    block_hash,
                    status: UnfinalizedTxStatus::Pending,
                    started_at: now,
                    last_polled: now,
                    poll_count: 0,
                },
            );
        }
    }

    /// Update transaction status
    pub fn update_status(&mut self, tx_hash: &str, status: UnfinalizedTxStatus) {
        if let Some(info) = self.txns.get_mut(tx_hash) {
            info.status = status;
            info.last_polled = Instant::now();
            info.poll_count += 1;
        }
    }

    /// Get all pending transactions that need polling
    pub fn get_pending_txns(&self) -> Vec<UnfinalizedTxInfo> {
        self.txns
            .values()
            .filter(|t| t.status == UnfinalizedTxStatus::Pending)
            .cloned()
            .collect()
    }

    /// Remove finalized or reorged transactions from tracking
    pub fn cleanup_completed(&mut self) {
        self.txns
            .retain(|_, info| matches!(info.status, UnfinalizedTxStatus::Pending));
    }

    /// Check if a transaction has recovered (was reorged but now back in chain)
    pub fn has_recovered(&self, tx_hash: &str) -> bool {
        if let Some(info) = self.txns.get(tx_hash) {
            // If it was reorged but we're still tracking, check if it recovered
            // This would need external RPC call to verify
            matches!(info.status, UnfinalizedTxStatus::Finalized)
        } else {
            false
        }
    }

    /// Get transaction status
    pub fn get_status(&self, tx_hash: &str) -> Option<UnfinalizedTxStatus> {
        self.txns.get(tx_hash).map(|t| t.status.clone())
    }

    /// Get all tracked transactions
    pub fn get_all(&self) -> Vec<UnfinalizedTxInfo> {
        self.txns.values().cloned().collect()
    }
}

/// Main Starcoin Chain Syncer
///
/// Combines event synchronization and simple polling-based finality tracking.
/// Output is a stream of `SyncerEvent` that business logic can consume.
pub struct StarcoinChainSyncer {
    config: StarcoinChainSyncerConfig,
    rpc: Arc<SimpleStarcoinRpcClient>,
    unfinalized_tracker: Arc<RwLock<UnfinalizedTxTracker>>,
    metrics: Option<Arc<BridgeMetrics>>,
}

impl StarcoinChainSyncer {
    /// Create a new StarcoinChainSyncer
    pub fn new(
        config: StarcoinChainSyncerConfig,
        rpc: SimpleStarcoinRpcClient,
    ) -> SyncResult<Self> {
        config.validate().map_err(SyncError::Other)?;

        Ok(Self {
            config,
            rpc: Arc::new(rpc),
            unfinalized_tracker: Arc::new(RwLock::new(UnfinalizedTxTracker::new())),
            metrics: None,
        })
    }

    /// Attach metrics for monitoring
    pub fn with_metrics(mut self, metrics: Arc<BridgeMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Get the unfinalized transaction tracker for external queries
    pub fn unfinalized_tracker(&self) -> Arc<RwLock<UnfinalizedTxTracker>> {
        self.unfinalized_tracker.clone()
    }

    /// Query if a transaction has recovered from reorg
    pub async fn has_tx_recovered(&self, tx_hash: &str) -> bool {
        let tracker = self.unfinalized_tracker.read().await;
        tracker.has_recovered(tx_hash)
    }

    /// Query transaction finalization status
    pub async fn get_tx_finalization_status(&self, tx_hash: &str) -> Option<UnfinalizedTxStatus> {
        let tracker = self.unfinalized_tracker.read().await;
        tracker.get_status(tx_hash)
    }

    /// Run the syncer and return handles and event receiver
    pub async fn run(
        self,
        cancel: CancellationToken,
    ) -> SyncResult<(Vec<JoinHandle<()>>, mpsc::Receiver<SyncerEvent>)> {
        let (event_tx, event_rx) = mpsc::channel(self.config.channel_size);

        // Emit started event
        let min_start_block = self
            .config
            .modules
            .iter()
            .map(|m| m.start_block)
            .min()
            .unwrap_or(0);

        let _ = event_tx
            .send(SyncerEvent::Started {
                chain: self.config.chain_name.clone(),
                from_block: min_start_block,
            })
            .await;

        let mut handles = Vec::new();

        // Get initial chain height
        let initial_height = get_chain_height(&self.rpc)
            .await
            .map_err(|e| SyncError::Rpc(format!("Failed to get initial chain height: {:?}", e)))?;

        // Create height watch channel
        let (height_tx, height_rx) = watch::channel(initial_height);

        // For Starcoin, finalized height = current height - finality_blocks
        let finalized_height = initial_height.saturating_sub(self.config.reorg.finality_blocks);
        let (finalized_tx, finalized_rx) = watch::channel(finalized_height);

        // Spawn height refresh task
        let rpc_clone = self.rpc.clone();
        let config_clone = self.config.clone();
        let event_tx_clone = event_tx.clone();
        let cancel_clone = cancel.clone();
        let metrics_clone = self.metrics.clone();
        handles.push(tokio::spawn(async move {
            run_height_refresh_task(
                rpc_clone,
                config_clone,
                height_tx,
                finalized_tx,
                event_tx_clone,
                cancel_clone,
                metrics_clone,
            )
            .await;
        }));

        // Spawn per-module event sync tasks
        for module in &self.config.modules {
            let rpc_clone = self.rpc.clone();
            let config_clone = self.config.clone();
            let event_tx_clone = event_tx.clone();
            let height_rx_clone = height_rx.clone();
            let finalized_rx_clone = finalized_rx.clone();
            let cancel_clone = cancel.clone();
            let metrics_clone = self.metrics.clone();
            let module_clone = module.clone();
            let tracker_clone = self.unfinalized_tracker.clone();

            handles.push(tokio::spawn(async move {
                run_module_sync_task(
                    rpc_clone,
                    config_clone,
                    module_clone,
                    height_rx_clone,
                    finalized_rx_clone,
                    event_tx_clone,
                    cancel_clone,
                    tracker_clone,
                    metrics_clone,
                )
                .await;
            }));
        }

        // Spawn finality polling task (polls unfinalized txns every 10s)
        if self.config.reorg.enabled {
            let rpc_clone = self.rpc.clone();
            let config_clone = self.config.clone();
            let event_tx_clone = event_tx.clone();
            let cancel_clone = cancel.clone();
            let tracker_clone = self.unfinalized_tracker.clone();

            handles.push(tokio::spawn(async move {
                run_finality_polling_task(
                    rpc_clone,
                    config_clone,
                    tracker_clone,
                    event_tx_clone,
                    cancel_clone,
                )
                .await;
            }));
        }

        Ok((handles, event_rx))
    }
}

/// Get current chain height from Starcoin RPC
async fn get_chain_height(rpc: &SimpleStarcoinRpcClient) -> SyncResult<u64> {
    let chain_info = rpc
        .chain_info()
        .await
        .map_err(|e| SyncError::Rpc(format!("Failed to get chain info: {:?}", e)))?;

    chain_info
        .get("head")
        .and_then(|h| h.get("number"))
        .and_then(|n| {
            n.as_u64()
                .or_else(|| n.as_str().and_then(|s| s.parse().ok()))
        })
        .ok_or_else(|| SyncError::InvalidResponse("Failed to parse chain height".to_string()))
}

/// Task to refresh chain height and calculate finalized height
async fn run_height_refresh_task(
    rpc: Arc<SimpleStarcoinRpcClient>,
    config: StarcoinChainSyncerConfig,
    height_tx: watch::Sender<u64>,
    finalized_tx: watch::Sender<u64>,
    event_tx: mpsc::Sender<SyncerEvent>,
    cancel: CancellationToken,
    metrics: Option<Arc<BridgeMetrics>>,
) {
    info!(
        "[{}] Starting height refresh task (finality_blocks={})",
        config.chain_name, config.reorg.finality_blocks
    );

    let mut last_height = 0u64;
    let mut interval = time::interval(config.fetch.finalized_block_interval);
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("[{}] Height refresh task cancelled", config.chain_name);
                break;
            }
            _ = interval.tick() => {
                match get_chain_height(&rpc).await {
                    Ok(new_height) => {
                        if new_height > last_height {
                            debug!("[{}] New chain height: {}", config.chain_name, new_height);
                            let _ = height_tx.send(new_height);

                            // Emit latest height updated
                            let _ = event_tx.send(SyncerEvent::LatestHeightUpdated {
                                chain: config.chain_name.clone(),
                                height: new_height,
                            }).await;

                            // Calculate finalized height
                            let finalized_height = new_height.saturating_sub(config.reorg.finality_blocks);
                            let _ = finalized_tx.send(finalized_height);

                            // Emit finalized height updated
                            let _ = event_tx.send(SyncerEvent::FinalizedHeightUpdated {
                                chain: config.chain_name.clone(),
                                height: finalized_height,
                            }).await;

                            // Update metrics
                            if let Some(ref m) = metrics {
                                m.last_synced_starcoin_bridge_blocks
                                    .with_label_values(&["latest"])
                                    .set(new_height as i64);
                                m.last_synced_starcoin_bridge_blocks
                                    .with_label_values(&["finalized"])
                                    .set(finalized_height as i64);
                            }

                            last_height = new_height;
                        }
                    }
                    Err(e) => {
                        warn!("[{}] Failed to get chain height: {:?}", config.chain_name, e);
                        let _ = event_tx.send(SyncerEvent::SyncError {
                            chain: config.chain_name.clone(),
                            error: format!("Failed to get chain height: {:?}", e),
                            recoverable: true,
                        }).await;
                    }
                }
            }
        }
    }
}

/// Task to sync events for a single module
async fn run_module_sync_task(
    rpc: Arc<SimpleStarcoinRpcClient>,
    config: StarcoinChainSyncerConfig,
    module: super::config::StarcoinSyncerModuleConfig,
    mut height_rx: watch::Receiver<u64>,
    mut finalized_rx: watch::Receiver<u64>,
    event_tx: mpsc::Sender<SyncerEvent>,
    cancel: CancellationToken,
    unfinalized_tracker: Arc<RwLock<UnfinalizedTxTracker>>,
    metrics: Option<Arc<BridgeMetrics>>,
) {
    let module_name = module
        .name
        .clone()
        .unwrap_or_else(|| module.address.clone());
    let mut start_block = module.start_block;

    info!(
        "[{}] Starting module sync for {} from block {}",
        config.chain_name, module_name, start_block
    );

    let mut more_blocks = false;

    loop {
        // When catching up (more_blocks=true), we need to continue immediately
        // rather than waiting for new blocks. Only wait when we're caught up.
        if !more_blocks {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("[{}] Module sync task cancelled for {}", config.chain_name, module_name);
                    break;
                }
                result = height_rx.changed() => {
                    if result.is_err() {
                        error!("[{}] Height channel closed", config.chain_name);
                        break;
                    }
                }
                _ = finalized_rx.changed() => {
                    // Finalized height updated
                }
            }
        } else {
            // Still catching up - just check if cancelled
            if cancel.is_cancelled() {
                info!(
                    "[{}] Module sync task cancelled for {} (during catch-up)",
                    config.chain_name, module_name
                );
                break;
            }
        }

        let latest_height = *height_rx.borrow();
        let finalized_height = *finalized_rx.borrow();

        if latest_height < start_block {
            debug!(
                "[{}] Latest height {} < start block {}, waiting",
                config.chain_name, latest_height, start_block
            );
            // Send CaughtUp since we've processed all blocks up to this point
            let _ = event_tx
                .send(SyncerEvent::CaughtUp {
                    chain: config.chain_name.clone(),
                    height: start_block.saturating_sub(1),
                })
                .await;
            more_blocks = false;
            continue;
        }

        // Sync up to latest block for real-time visibility
        let end_block = std::cmp::min(
            start_block + config.fetch.max_block_range - 1,
            latest_height,
        );
        more_blocks = end_block < latest_height;

        // Fetch events
        let events = match fetch_events(&rpc, &module.address, start_block, end_block).await {
            Ok(events) => events,
            Err(e) => {
                error!(
                    "[{}] Failed to fetch events for {}: {:?}",
                    config.chain_name, module_name, e
                );
                let _ = event_tx
                    .send(SyncerEvent::SyncError {
                        chain: config.chain_name.clone(),
                        error: format!("Failed to fetch events for {}: {:?}", module_name, e),
                        recoverable: true,
                    })
                    .await;
                continue;
            }
        };

        debug!(
            "[{}] Fetched {} events from {} in blocks {}-{} (finalized={})",
            config.chain_name,
            events.len(),
            module_name,
            start_block,
            end_block,
            finalized_height
        );

        // Convert to ChainLogs and collect tracking info
        let logs_with_tracking: Vec<(ChainLog, bool, String, u64, Option<String>)> = events
            .iter()
            .filter_map(|event| {
                let block_number = event.get("block_number").and_then(|b| {
                    b.as_u64()
                        .or_else(|| b.as_str().and_then(|s| s.parse().ok()))
                })?;
                let tx_hash = event
                    .get("transaction_hash")
                    .and_then(|t| t.as_str())
                    .unwrap_or_default()
                    .to_string();
                let block_hash = event
                    .get("block_hash")
                    .and_then(|b| b.as_str())
                    .map(|s| s.to_string());
                let log_index = event
                    .get("event_index")
                    .and_then(|i| i.as_u64())
                    .unwrap_or(0) as u32;

                let needs_tracking = block_number > finalized_height;

                // Extract the actual BCS event data from the "data" field
                // The data field contains hex-encoded BCS bytes like "0x0c000000000000000000"
                let event_data = event
                    .get("data")
                    .and_then(|d| d.as_str())
                    .and_then(|hex_str| {
                        let hex_str = hex_str.trim_start_matches("0x");
                        hex::decode(hex_str).ok()
                    })
                    .unwrap_or_default();

                Some((
                    ChainLog {
                        block_id: BlockId {
                            chain: config.chain_name.clone(),
                            number: block_number,
                            hash: block_hash.clone().unwrap_or_default(),
                        },
                        tx_hash: tx_hash.clone(),
                        log_index,
                        emitter: module.address.clone(),
                        data: event_data,
                        topics: extract_event_type(event),
                    },
                    needs_tracking,
                    tx_hash,
                    block_number,
                    block_hash,
                ))
            })
            .collect();

        // Track unfinalized transactions (do this synchronously to avoid race conditions)
        {
            let mut tracker = unfinalized_tracker.write().await;
            for (_, needs_tracking, tx_hash, block_number, block_hash) in &logs_with_tracking {
                if *needs_tracking {
                    tracker.track(tx_hash.clone(), *block_number, block_hash.clone());
                }
            }
        }

        // Extract just the ChainLogs
        let chain_logs: Vec<ChainLog> = logs_with_tracking
            .into_iter()
            .map(|(log, _, _, _, _)| log)
            .collect();

        // Update metrics
        if let Some(ref m) = metrics {
            let last_block = chain_logs
                .last()
                .map(|l| l.block_id.number)
                .unwrap_or(end_block);
            m.last_synced_starcoin_bridge_blocks
                .with_label_values(&[&module_name])
                .set(last_block as i64);
        }

        // Determine finalization status
        let is_finalized = end_block <= finalized_height;

        // Emit event
        if !chain_logs.is_empty() {
            let _ = event_tx
                .send(SyncerEvent::NewLogs {
                    chain: config.chain_name.clone(),
                    contract: module_name.clone(),
                    start_block,
                    end_block,
                    logs: chain_logs,
                    is_finalized,
                })
                .await;
        }

        if !more_blocks {
            let _ = event_tx
                .send(SyncerEvent::CaughtUp {
                    chain: config.chain_name.clone(),
                    height: end_block,
                })
                .await;
        }

        start_block = end_block + 1;
    }
}

/// Fetch events from Starcoin RPC
async fn fetch_events(
    rpc: &SimpleStarcoinRpcClient,
    module_address: &str,
    from_block: u64,
    to_block: u64,
) -> SyncResult<Vec<Value>> {
    let filter = serde_json::json!({
        "from_block": from_block,
        "to_block": to_block,
        "addrs": [module_address],
        "limit": 1000
    });

    rpc.get_events(filter)
        .await
        .map_err(|e| SyncError::Rpc(format!("Failed to fetch events: {:?}", e)))
}

/// Extract event type from event JSON as topics
fn extract_event_type(event: &Value) -> Vec<String> {
    let mut topics = Vec::new();

    // Extract type_tag as the primary topic (like ETH event signature)
    if let Some(type_tag) = event.get("type_tag").and_then(|t| t.as_str()) {
        topics.push(type_tag.to_string());
    }

    topics
}

/// Task for polling unfinalized transactions for finality status
///
/// Polls every 10 seconds to check if unfinalized transactions have:
/// 1. Been finalized (in blue set) - mark as finalized
/// 2. Been reorged out - stop polling, mark as reorged
///
/// This provides a simple reorg detection mechanism for Starcoin.
async fn run_finality_polling_task(
    rpc: Arc<SimpleStarcoinRpcClient>,
    config: StarcoinChainSyncerConfig,
    tracker: Arc<RwLock<UnfinalizedTxTracker>>,
    event_tx: mpsc::Sender<SyncerEvent>,
    cancel: CancellationToken,
) {
    info!(
        "[{}] Starting finality polling task (interval=10s)",
        config.chain_name
    );

    // Poll every 10 seconds
    let mut interval = time::interval(Duration::from_secs(10));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("[{}] Finality polling task cancelled", config.chain_name);
                break;
            }
            _ = interval.tick() => {
                let pending_txns = {
                    let t = tracker.read().await;
                    t.get_pending_txns()
                };

                if pending_txns.is_empty() {
                    continue;
                }

                debug!(
                    "[{}] Polling {} unfinalized transactions",
                    config.chain_name,
                    pending_txns.len()
                );

                for tx_info in pending_txns {
                    match check_transaction_finality(&rpc, &tx_info.tx_hash).await {
                        Ok(status) => {
                            let mut t = tracker.write().await;
                            t.update_status(&tx_info.tx_hash, status.clone());

                            match status {
                                UnfinalizedTxStatus::Finalized => {
                                    debug!(
                                        "[{}] Transaction {} finalized",
                                        config.chain_name, tx_info.tx_hash
                                    );
                                    // Emit block finalized event
                                    let _ = event_tx
                                        .send(SyncerEvent::BlockFinalized {
                                            block_id: BlockId {
                                                chain: config.chain_name.clone(),
                                                number: tx_info.block_number,
                                                hash: tx_info.block_hash.clone().unwrap_or_default(),
                                            },
                                        })
                                        .await;
                                }
                                UnfinalizedTxStatus::Reorged => {
                                    warn!(
                                        "[{}] Transaction {} was reorged out",
                                        config.chain_name, tx_info.tx_hash
                                    );
                                    // Emit reorg event
                                    let reorg_info = ReorgInfo::new(
                                        config.chain_name.clone(),
                                        tx_info.block_number.saturating_sub(1),
                                        vec![BlockId {
                                            chain: config.chain_name.clone(),
                                            number: tx_info.block_number,
                                            hash: tx_info.block_hash.clone().unwrap_or_default(),
                                        }],
                                        format!("Transaction {} reorged out", tx_info.tx_hash),
                                    );
                                    let _ = event_tx.send(SyncerEvent::Reorg(reorg_info)).await;
                                }
                                UnfinalizedTxStatus::NotFound => {
                                    warn!(
                                        "[{}] Transaction {} not found (may have been dropped)",
                                        config.chain_name, tx_info.tx_hash
                                    );
                                }
                                UnfinalizedTxStatus::Pending => {
                                    // Still pending, continue polling
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                "[{}] Failed to check finality for {}: {:?}",
                                config.chain_name, tx_info.tx_hash, e
                            );
                        }
                    }
                }

                // Cleanup completed transactions
                {
                    let mut t = tracker.write().await;
                    t.cleanup_completed();
                }
            }
        }
    }
}

/// Check transaction finality status by querying RPC
///
/// Returns:
/// - Finalized: Transaction is in blue set (confirmed)
/// - Reorged: Transaction was found but block is no longer in main chain
/// - NotFound: Transaction info not available
/// - Pending: Transaction exists but not yet finalized
async fn check_transaction_finality(
    rpc: &SimpleStarcoinRpcClient,
    tx_hash: &str,
) -> SyncResult<UnfinalizedTxStatus> {
    let txn_info = rpc
        .get_transaction_info(tx_hash)
        .await
        .map_err(|e| SyncError::Rpc(format!("Failed to get transaction info: {:?}", e)))?;

    if txn_info.is_null() {
        return Ok(UnfinalizedTxStatus::NotFound);
    }

    // Check if transaction is in blue set (confirmed)
    // In Starcoin's DAG, a block is finalized when it's in the "blue" set
    // The transaction_info includes block_hash which we can use to verify

    // Get block number from transaction info
    let block_number = txn_info.get("block_number").and_then(|b| {
        b.as_u64()
            .or_else(|| b.as_str().and_then(|s| s.parse().ok()))
    });

    let block_hash = txn_info
        .get("block_hash")
        .and_then(|b| b.as_str())
        .map(|s| s.to_string());

    if let Some(block_num) = block_number {
        // Verify the block is still in main chain by querying block info
        let block_info = rpc
            .get_block_info_by_number(block_num)
            .await
            .map_err(|e| SyncError::Rpc(format!("Failed to get block info: {:?}", e)))?;

        if let Some(info) = block_info {
            // Check if block hash matches (if we have both)
            let main_chain_hash = info.get("block_hash").and_then(|b| b.as_str());

            if let (Some(expected), Some(actual)) = (&block_hash, main_chain_hash) {
                if expected != actual {
                    // Block hash mismatch - transaction was reorged
                    return Ok(UnfinalizedTxStatus::Reorged);
                }
            }

            // Transaction is confirmed (block is in main chain)
            return Ok(UnfinalizedTxStatus::Finalized);
        } else {
            // Block not found at this height - might be reorged
            return Ok(UnfinalizedTxStatus::Reorged);
        }
    }

    // Transaction exists but we couldn't determine finality
    Ok(UnfinalizedTxStatus::Pending)
}

/// Builder for StarcoinChainSyncer with fluent API
pub struct StarcoinChainSyncerBuilder {
    config: StarcoinChainSyncerConfig,
    metrics: Option<Arc<BridgeMetrics>>,
}

impl StarcoinChainSyncerBuilder {
    pub fn new(rpc_url: &str, bridge_address: &str) -> Self {
        Self {
            config: StarcoinChainSyncerConfig::mainnet(rpc_url).with_module(bridge_address, 0),
            metrics: None,
        }
    }

    pub fn with_module(mut self, address: &str, start_block: u64) -> Self {
        self.config = self.config.with_module(address, start_block);
        self
    }

    pub fn with_named_module(mut self, name: &str, address: &str, start_block: u64) -> Self {
        self.config = self.config.with_named_module(name, address, start_block);
        self
    }

    pub fn with_reorg_detection(mut self, enabled: bool) -> Self {
        self.config = self.config.with_reorg_detection(enabled);
        self
    }

    pub fn with_finality_blocks(mut self, blocks: u64) -> Self {
        self.config = self.config.with_finality_blocks(blocks);
        self
    }

    pub fn with_max_block_range(mut self, range: u64) -> Self {
        self.config.fetch.max_block_range = range;
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<BridgeMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn build(self) -> SyncResult<StarcoinChainSyncer> {
        let rpc =
            SimpleStarcoinRpcClient::new(&self.config.rpc_url, &self.config.modules[0].address);
        let syncer = StarcoinChainSyncer::new(self.config, rpc)?;
        Ok(if let Some(m) = self.metrics {
            syncer.with_metrics(m)
        } else {
            syncer
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder() {
        let builder = StarcoinChainSyncerBuilder::new("http://localhost:9850", "0x1234::Bridge")
            .with_module("0x1234::Bridge", 100)
            .with_reorg_detection(true)
            .with_finality_blocks(16);

        assert_eq!(builder.config.chain_name, "starcoin");
        assert!(builder.config.reorg.enabled);
        assert_eq!(builder.config.reorg.finality_blocks, 16);
    }

    #[test]
    fn test_unfinalized_tracker() {
        let mut tracker = UnfinalizedTxTracker::new();

        // Track a transaction
        tracker.track("0xabc123".to_string(), 100, Some("0xblock123".to_string()));

        assert_eq!(tracker.get_pending_txns().len(), 1);
        assert_eq!(
            tracker.get_status("0xabc123"),
            Some(UnfinalizedTxStatus::Pending)
        );

        // Update to finalized
        tracker.update_status("0xabc123", UnfinalizedTxStatus::Finalized);
        assert_eq!(
            tracker.get_status("0xabc123"),
            Some(UnfinalizedTxStatus::Finalized)
        );
        assert!(tracker.has_recovered("0xabc123"));

        // Cleanup
        tracker.cleanup_completed();
        assert!(tracker.get_pending_txns().is_empty());
    }

    #[test]
    fn test_unfinalized_tracker_reorg() {
        let mut tracker = UnfinalizedTxTracker::new();

        tracker.track("0xdef456".to_string(), 200, None);
        tracker.update_status("0xdef456", UnfinalizedTxStatus::Reorged);

        assert_eq!(
            tracker.get_status("0xdef456"),
            Some(UnfinalizedTxStatus::Reorged)
        );
        assert!(!tracker.has_recovered("0xdef456"));

        // Cleanup removes non-pending txns
        tracker.cleanup_completed();
        assert!(tracker.get_pending_txns().is_empty());
    }
}
