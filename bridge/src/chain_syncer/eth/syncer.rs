// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Ethereum Chain Syncer Implementation
//!
//! Unified syncer that combines:
//! - Event/Log fetching (from EthSyncer)
//! - Finalized block tracking
//! - Reorg detection (via BlockWindow)
//!
//! This module replaces the separate EthSyncer and provides a clean event-based
//! interface that separates chain sync logic from business logic.

use super::config::EthChainSyncerConfig;
use crate::chain_syncer::common::{
    BlockId, BlockInfo, BlockWindow, ChainLog, ReorgInfo, SyncError, SyncResult, SyncerEvent,
};
use crate::eth_client::EthClient;
use crate::metered_eth_provider::MeteredEthHttpProvier;
use crate::metrics::BridgeMetrics;
use crate::retry_with_max_elapsed_time;
use ethers::providers::Middleware;
use ethers::types::Address as EthAddress;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Main Ethereum Chain Syncer
///
/// Combines event synchronization and reorg detection in a single unified component.
/// Output is a stream of `SyncerEvent` that business logic can consume.
pub struct EthChainSyncer<P> {
    config: EthChainSyncerConfig,
    client: Arc<EthClient<P>>,
    block_window: Arc<RwLock<BlockWindow>>,
    contract_cursors: HashMap<EthAddress, u64>,
    metrics: Option<Arc<BridgeMetrics>>,
}

impl<P> EthChainSyncer<P>
where
    P: ethers::providers::JsonRpcClient + 'static,
{
    /// Create a new EthChainSyncer
    pub fn new(config: EthChainSyncerConfig, client: Arc<EthClient<P>>) -> SyncResult<Self> {
        config.validate().map_err(SyncError::Other)?;

        let window_size = config.reorg.window_size();
        let block_window = Arc::new(RwLock::new(BlockWindow::new(
            &config.chain_name,
            window_size,
            config.reorg.tracking_duration,
        )));

        // Parse contract addresses
        let mut contract_cursors = HashMap::new();
        for c in &config.contracts {
            let addr = c
                .address
                .parse::<EthAddress>()
                .map_err(|e| SyncError::Other(format!("Invalid address {}: {}", c.address, e)))?;
            contract_cursors.insert(addr, c.start_block);
        }

        Ok(Self {
            config,
            client,
            block_window,
            contract_cursors,
            metrics: None,
        })
    }

    /// Attach metrics for monitoring
    pub fn with_metrics(mut self, metrics: Arc<BridgeMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Run the syncer and return handles and event receiver
    pub async fn run(
        self,
        cancel: CancellationToken,
    ) -> SyncResult<(Vec<JoinHandle<()>>, mpsc::Receiver<SyncerEvent>)> {
        let (event_tx, event_rx) = mpsc::channel(self.config.channel_size);

        // Emit started event
        let _ = event_tx
            .send(SyncerEvent::Started {
                chain: self.config.chain_name.clone(),
                from_block: self.contract_cursors.values().copied().min().unwrap_or(0),
            })
            .await;

        let mut handles = Vec::new();

        // Get initial finalized block
        let initial_finalized = self
            .client
            .get_last_finalized_block_id()
            .await
            .map_err(|e| {
                SyncError::Rpc(format!("Failed to get initial finalized block: {:?}", e))
            })?;

        // Get initial latest block
        let initial_latest =
            self.client.get_latest_block_id().await.map_err(|e| {
                SyncError::Rpc(format!("Failed to get initial latest block: {:?}", e))
            })?;

        // Create finalized block watch channel
        let (finalized_tx, finalized_rx) = watch::channel(initial_finalized);

        // Create latest block watch channel
        let (latest_tx, latest_rx) = watch::channel(initial_latest);

        // Spawn finalized block refresh task
        let client_clone = self.client.clone();
        let config_clone = self.config.clone();
        let event_tx_clone = event_tx.clone();
        let cancel_clone = cancel.clone();
        let metrics_clone = self.metrics.clone();
        handles.push(tokio::spawn(async move {
            run_finalized_block_task(
                client_clone,
                config_clone,
                finalized_tx,
                event_tx_clone,
                cancel_clone,
                metrics_clone,
            )
            .await;
        }));

        // Spawn latest block refresh task
        let client_clone = self.client.clone();
        let config_clone = self.config.clone();
        let event_tx_clone = event_tx.clone();
        let cancel_clone = cancel.clone();
        let metrics_clone = self.metrics.clone();
        handles.push(tokio::spawn(async move {
            run_latest_block_task(
                client_clone,
                config_clone,
                latest_tx,
                event_tx_clone,
                cancel_clone,
                metrics_clone,
            )
            .await;
        }));

        // Spawn per-contract event listening tasks
        for (contract, start_block) in self.contract_cursors {
            let client_clone = self.client.clone();
            let config_clone = self.config.clone();
            let event_tx_clone = event_tx.clone();
            let finalized_rx_clone = finalized_rx.clone();
            let latest_rx_clone = latest_rx.clone();
            let cancel_clone = cancel.clone();
            let block_window_clone = self.block_window.clone();
            let metrics_clone = self.metrics.clone();

            handles.push(tokio::spawn(async move {
                run_contract_sync_task(
                    client_clone,
                    config_clone,
                    contract,
                    start_block,
                    finalized_rx_clone,
                    latest_rx_clone,
                    event_tx_clone,
                    cancel_clone,
                    block_window_clone,
                    metrics_clone,
                )
                .await;
            }));
        }

        // Note: Reorg detection task is spawned separately via run_with_reorg_detection()
        // for MeteredEthHttpProvier clients only

        Ok((handles, event_rx))
    }

    /// Get the current block window (for testing/debugging)
    pub fn block_window(&self) -> Arc<RwLock<BlockWindow>> {
        self.block_window.clone()
    }
}

/// Additional methods for production clients with MeteredEthHttpProvier
impl EthChainSyncer<MeteredEthHttpProvier> {
    /// Run the syncer with reorg detection enabled
    ///
    /// This method is only available for MeteredEthHttpProvier clients as it requires
    /// access to the underlying provider for block header fetching.
    ///
    /// Reorg detection monitors blocks between finalized_block and latest_block.
    /// When reorg is detected, unfinalized events are rolled back.
    pub async fn run_with_reorg_detection(
        self,
        cancel: CancellationToken,
    ) -> SyncResult<(Vec<JoinHandle<()>>, mpsc::Receiver<SyncerEvent>)> {
        let reorg_enabled = self.config.reorg.enabled;
        let client_for_reorg = self.client.clone();
        let config_for_reorg = self.config.clone();
        let block_window_for_reorg = self.block_window.clone();
        let cancel_for_reorg = cancel.clone();
        let channel_size = self.config.channel_size;

        // Run base syncer - get the main event channel
        let (mut handles, event_rx) = self.run_internal(cancel.clone(), reorg_enabled).await?;

        // Spawn reorg detection task if enabled, using the main event channel
        if reorg_enabled {
            // Create a new sender for the reorg task from the same channel
            let (event_tx, new_event_rx) = mpsc::channel(channel_size);

            // Forward events from the original receiver to the new sender
            // while also allowing reorg task to send events
            let event_tx_for_reorg = event_tx.clone();
            let mut original_rx = event_rx;

            handles.push(tokio::spawn(async move {
                // Forward all events from original syncer to merged channel
                while let Some(event) = original_rx.recv().await {
                    if event_tx.send(event).await.is_err() {
                        break;
                    }
                }
            }));

            handles.push(tokio::spawn(async move {
                run_reorg_detection_task(
                    client_for_reorg,
                    config_for_reorg,
                    block_window_for_reorg,
                    event_tx_for_reorg,
                    cancel_for_reorg,
                )
                .await;
            }));

            return Ok((handles, new_event_rx));
        }

        Ok((handles, event_rx))
    }

    /// Internal run method that optionally tracks block hashes for reorg detection
    async fn run_internal(
        self,
        cancel: CancellationToken,
        track_block_hashes: bool,
    ) -> SyncResult<(Vec<JoinHandle<()>>, mpsc::Receiver<SyncerEvent>)> {
        let (event_tx, event_rx) = mpsc::channel(self.config.channel_size);

        // Emit started event
        let _ = event_tx
            .send(SyncerEvent::Started {
                chain: self.config.chain_name.clone(),
                from_block: self.contract_cursors.values().copied().min().unwrap_or(0),
            })
            .await;

        let mut handles = Vec::new();

        // Get initial finalized block
        let initial_finalized = self
            .client
            .get_last_finalized_block_id()
            .await
            .map_err(|e| {
                SyncError::Rpc(format!("Failed to get initial finalized block: {:?}", e))
            })?;

        // Get initial latest block
        let initial_latest =
            self.client.get_latest_block_id().await.map_err(|e| {
                SyncError::Rpc(format!("Failed to get initial latest block: {:?}", e))
            })?;

        // Create finalized block watch channel
        let (finalized_tx, finalized_rx) = watch::channel(initial_finalized);

        // Create latest block watch channel
        let (latest_tx, latest_rx) = watch::channel(initial_latest);

        // Spawn finalized block refresh task
        let client_clone = self.client.clone();
        let config_clone = self.config.clone();
        let event_tx_clone = event_tx.clone();
        let cancel_clone = cancel.clone();
        let metrics_clone = self.metrics.clone();
        handles.push(tokio::spawn(async move {
            run_finalized_block_task(
                client_clone,
                config_clone,
                finalized_tx,
                event_tx_clone,
                cancel_clone,
                metrics_clone,
            )
            .await;
        }));

        // Spawn latest block refresh task
        let client_clone = self.client.clone();
        let config_clone = self.config.clone();
        let event_tx_clone = event_tx.clone();
        let cancel_clone = cancel.clone();
        let metrics_clone = self.metrics.clone();
        handles.push(tokio::spawn(async move {
            run_latest_block_task(
                client_clone,
                config_clone,
                latest_tx,
                event_tx_clone,
                cancel_clone,
                metrics_clone,
            )
            .await;
        }));

        // Spawn per-contract event listening tasks
        for (contract, start_block) in self.contract_cursors {
            let client_clone = self.client.clone();
            let config_clone = self.config.clone();
            let event_tx_clone = event_tx.clone();
            let finalized_rx_clone = finalized_rx.clone();
            let latest_rx_clone = latest_rx.clone();
            let cancel_clone = cancel.clone();
            let block_window_clone = self.block_window.clone();
            let metrics_clone = self.metrics.clone();

            handles.push(tokio::spawn(async move {
                run_contract_sync_task_metered(
                    client_clone,
                    config_clone,
                    contract,
                    start_block,
                    finalized_rx_clone,
                    latest_rx_clone,
                    event_tx_clone,
                    cancel_clone,
                    block_window_clone,
                    metrics_clone,
                    track_block_hashes,
                )
                .await;
            }));
        }

        Ok((handles, event_rx))
    }
}

/// Task to refresh the finalized block number
async fn run_finalized_block_task<P>(
    client: Arc<EthClient<P>>,
    config: EthChainSyncerConfig,
    sender: watch::Sender<u64>,
    event_tx: mpsc::Sender<SyncerEvent>,
    cancel: CancellationToken,
    metrics: Option<Arc<BridgeMetrics>>,
) where
    P: ethers::providers::JsonRpcClient + 'static,
{
    info!(
        "[{}] Starting finalized block refresh task",
        config.chain_name
    );

    let mut last_block = 0u64;
    let mut interval = time::interval(config.fetch.finalized_block_interval);
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("[{}] Finalized block task cancelled", config.chain_name);
                break;
            }
            _ = interval.tick() => {
                match retry_with_max_elapsed_time!(
                    client.get_last_finalized_block_id(),
                    config.fetch.max_retry_duration
                ) {
                    Ok(Ok(new_block)) => {
                        if new_block > last_block {
                            debug!("[{}] New finalized block: {}", config.chain_name, new_block);
                            let _ = sender.send(new_block);

                            // Emit FinalizedHeightUpdated for height tracking
                            let _ = event_tx.send(SyncerEvent::FinalizedHeightUpdated {
                                chain: config.chain_name.clone(),
                                height: new_block,
                            }).await;

                            // Emit BlockFinalized for each newly finalized block
                            // This allows downstream handlers to update DB records
                            // Note: We emit for the new finalized height, handlers should
                            // update all records <= this height
                            let _ = event_tx.send(SyncerEvent::BlockFinalized {
                                block_id: BlockId {
                                    chain: config.chain_name.clone(),
                                    number: new_block,
                                    hash: String::new(), // Hash not needed for finalization marking
                                },
                            }).await;

                            // Update metrics if available
                            if let Some(ref m) = metrics {
                                m.last_finalized_eth_block.set(new_block as i64);
                                m.last_successful_sync_timestamp
                                    .with_label_values(&["eth"])
                                    .set(
                                        std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs() as i64,
                                    );
                            }

                            last_block = new_block;
                        }
                    }
                    _ => {
                        error!("[{}] Failed to get finalized block after retry", config.chain_name);
                        let _ = event_tx.send(SyncerEvent::SyncError {
                            chain: config.chain_name.clone(),
                            error: "Failed to get finalized block".to_string(),
                            recoverable: true,
                        }).await;
                    }
                }
            }
        }
    }
}

/// Task to refresh the latest block number (for real-time sync)
async fn run_latest_block_task<P>(
    client: Arc<EthClient<P>>,
    config: EthChainSyncerConfig,
    sender: watch::Sender<u64>,
    event_tx: mpsc::Sender<SyncerEvent>,
    cancel: CancellationToken,
    metrics: Option<Arc<BridgeMetrics>>,
) where
    P: ethers::providers::JsonRpcClient + 'static,
{
    info!("[{}] Starting latest block refresh task", config.chain_name);

    let mut last_block = 0u64;
    // Use a faster interval for latest block (more real-time)
    let mut interval = time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("[{}] Latest block task cancelled", config.chain_name);
                break;
            }
            _ = interval.tick() => {
                match retry_with_max_elapsed_time!(
                    client.get_latest_block_id(),
                    config.fetch.max_retry_duration
                ) {
                    Ok(Ok(new_block)) => {
                        if new_block > last_block {
                            debug!("[{}] New latest block: {}", config.chain_name, new_block);
                            let _ = sender.send(new_block);
                            let _ = event_tx.send(SyncerEvent::LatestHeightUpdated {
                                chain: config.chain_name.clone(),
                                height: new_block,
                            }).await;

                            // Update metrics if available
                            if let Some(ref m) = metrics {
                                m.last_synced_eth_blocks
                                    .with_label_values(&["latest"])
                                    .set(new_block as i64);
                            }

                            last_block = new_block;
                        }
                    }
                    _ => {
                        warn!("[{}] Failed to get latest block after retry", config.chain_name);
                        // Non-critical error, don't emit SyncError for this
                    }
                }
            }
        }
    }
}

/// Task to sync events for a single contract
///
/// Syncs to latest_block for real-time visibility. Logs are marked with
/// is_finalized=true for blocks <= finalized_block, is_finalized=false otherwise.
async fn run_contract_sync_task<P>(
    client: Arc<EthClient<P>>,
    config: EthChainSyncerConfig,
    contract: EthAddress,
    mut start_block: u64,
    mut finalized_rx: watch::Receiver<u64>,
    mut latest_rx: watch::Receiver<u64>,
    event_tx: mpsc::Sender<SyncerEvent>,
    cancel: CancellationToken,
    block_window: Arc<RwLock<BlockWindow>>,
    metrics: Option<Arc<BridgeMetrics>>,
) where
    P: ethers::providers::JsonRpcClient + 'static,
{
    let contract_str = format!("{:?}", contract);
    info!(
        "[{}] Starting contract sync for {} from block {}",
        config.chain_name, contract_str, start_block
    );

    let mut more_blocks = false;

    loop {
        // When catching up (more_blocks=true), don't wait for new block notifications
        if !more_blocks {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("[{}] Contract sync task cancelled for {}", config.chain_name, contract_str);
                    break;
                }
                // Wait for either latest or finalized to change when not catching up
                result = latest_rx.changed() => {
                    if result.is_err() {
                        error!("[{}] Latest block channel closed", config.chain_name);
                        break;
                    }
                }
                _ = finalized_rx.changed() => {
                    // Finalized block updated, may need to emit finalization events
                }
            }
        } else {
            // Check for cancellation without blocking
            if cancel.is_cancelled() {
                info!(
                    "[{}] Contract sync task cancelled for {}",
                    config.chain_name, contract_str
                );
                break;
            }
        }

        let latest_block = *latest_rx.borrow();
        let finalized_block = *finalized_rx.borrow();

        if latest_block < start_block {
            debug!(
                "[{}] Latest block {} < start block {}, waiting",
                config.chain_name, latest_block, start_block
            );
            more_blocks = false;
            continue;
        }

        // Sync up to latest block (not finalized) for real-time visibility
        let end_block = std::cmp::min(start_block + config.fetch.max_block_range - 1, latest_block);
        more_blocks = end_block < latest_block;

        // Fetch logs
        let start_time = Instant::now();
        let logs_result = retry_with_max_elapsed_time!(
            client.get_events_in_range(contract, start_block, end_block),
            config.fetch.max_retry_duration
        );

        match logs_result {
            Ok(Ok(logs)) => {
                debug!(
                    "[{}] Fetched {} logs from {} in {:?} (blocks {}-{}, finalized={})",
                    config.chain_name,
                    logs.len(),
                    contract_str,
                    start_time.elapsed(),
                    start_block,
                    end_block,
                    finalized_block
                );

                // Track unfinalized blocks in window for reorg detection
                // Only track blocks between finalized and latest
                if config.reorg.enabled {
                    let mut blocks_seen: HashMap<u64, String> = HashMap::new();
                    for log in &logs {
                        // Only track unfinalized blocks for reorg detection
                        if log.block_number > finalized_block
                            && !blocks_seen.contains_key(&log.block_number)
                        {
                            blocks_seen.insert(log.block_number, String::new());
                        }
                    }

                    // Add unfinalized blocks to window
                    {
                        let mut window = block_window.write().await;
                        for (block_num, _) in blocks_seen {
                            let block_info = BlockInfo {
                                id: BlockId {
                                    chain: config.chain_name.clone(),
                                    number: block_num,
                                    hash: String::new(), // Would need RPC to get hash
                                },
                                parent_hash: String::new(),
                                timestamp: 0,
                                logs: vec![],
                            };
                            // Note: Reorg detection is done by run_reorg_detection_task
                            let _ = window.add_block(block_info);
                        }
                    }
                }

                // Convert to ChainLogs
                let chain_logs: Vec<ChainLog> = logs
                    .iter()
                    .map(|log| ChainLog {
                        block_id: BlockId {
                            chain: config.chain_name.clone(),
                            number: log.block_number,
                            hash: String::new(),
                        },
                        tx_hash: format!("{:?}", log.tx_hash),
                        log_index: log.log_index_in_tx as u32,
                        emitter: contract_str.clone(),
                        data: log.log.data.to_vec(),
                        topics: log.log.topics.iter().map(|t| format!("{:?}", t)).collect(),
                    })
                    .collect();

                // Update metrics
                if let Some(ref m) = metrics {
                    let last_block = logs.last().map(|l| l.block_number).unwrap_or(end_block);
                    m.last_synced_eth_blocks
                        .with_label_values(&[&contract_str])
                        .set(last_block as i64);
                }

                // Determine finalization status based on block range
                // If all logs are from finalized blocks: is_finalized = true
                // If any log is from unfinalized block: is_finalized = false
                let is_finalized = end_block <= finalized_block;

                // Emit event
                let _ = event_tx
                    .send(SyncerEvent::NewLogs {
                        chain: config.chain_name.clone(),
                        contract: contract_str.clone(),
                        start_block,
                        end_block,
                        logs: chain_logs,
                        is_finalized,
                    })
                    .await;

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
            _ => {
                error!(
                    "[{}] Failed to fetch logs for {} after retry",
                    config.chain_name, contract_str
                );
                let _ = event_tx
                    .send(SyncerEvent::SyncError {
                        chain: config.chain_name.clone(),
                        error: format!("Failed to fetch logs for {}", contract_str),
                        recoverable: true,
                    })
                    .await;
            }
        }
    }
}

/// Task to sync events for a single contract with block hash fetching (MeteredEthHttpProvier only)
///
/// This version fetches block headers to populate block hashes for proper reorg detection.
async fn run_contract_sync_task_metered(
    client: Arc<EthClient<MeteredEthHttpProvier>>,
    config: EthChainSyncerConfig,
    contract: EthAddress,
    mut start_block: u64,
    mut finalized_rx: watch::Receiver<u64>,
    mut latest_rx: watch::Receiver<u64>,
    event_tx: mpsc::Sender<SyncerEvent>,
    cancel: CancellationToken,
    block_window: Arc<RwLock<BlockWindow>>,
    metrics: Option<Arc<BridgeMetrics>>,
    track_block_hashes: bool,
) {
    let contract_str = format!("{:?}", contract);
    info!(
        "[{}] Starting contract sync (metered) for {} from block {} (track_hashes={})",
        config.chain_name, contract_str, start_block, track_block_hashes
    );

    let provider = client.provider();
    let mut more_blocks = false;
    // Cache for block hashes to avoid repeated RPC calls
    let mut block_hash_cache: HashMap<u64, String> = HashMap::new();

    loop {
        // When catching up (more_blocks=true), don't wait for new block notifications
        if !more_blocks {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("[{}] Contract sync task cancelled for {}", config.chain_name, contract_str);
                    break;
                }
                result = latest_rx.changed() => {
                    if result.is_err() {
                        error!("[{}] Latest block channel closed", config.chain_name);
                        break;
                    }
                }
                _ = finalized_rx.changed() => {
                    // Finalized block updated
                }
            }
        } else {
            // Check for cancellation without blocking
            if cancel.is_cancelled() {
                info!(
                    "[{}] Contract sync task cancelled for {}",
                    config.chain_name, contract_str
                );
                break;
            }
        }

        let latest_block = *latest_rx.borrow();
        let finalized_block = *finalized_rx.borrow();

        if latest_block < start_block {
            debug!(
                "[{}] Latest block {} < start block {}, waiting",
                config.chain_name, latest_block, start_block
            );
            more_blocks = false;
            continue;
        }

        let end_block = std::cmp::min(start_block + config.fetch.max_block_range - 1, latest_block);
        more_blocks = end_block < latest_block;

        // Fetch logs
        let start_time = Instant::now();
        let logs_result = retry_with_max_elapsed_time!(
            client.get_events_in_range(contract, start_block, end_block),
            config.fetch.max_retry_duration
        );

        match logs_result {
            Ok(Ok(logs)) => {
                debug!(
                    "[{}] Fetched {} logs from {} in {:?} (blocks {}-{}, finalized={})",
                    config.chain_name,
                    logs.len(),
                    contract_str,
                    start_time.elapsed(),
                    start_block,
                    end_block,
                    finalized_block
                );

                // Fetch block hashes for unfinalized blocks if tracking is enabled
                let mut blocks_to_fetch: Vec<u64> = Vec::new();
                if track_block_hashes && config.reorg.enabled {
                    for log in &logs {
                        if log.block_number > finalized_block
                            && !block_hash_cache.contains_key(&log.block_number)
                        {
                            blocks_to_fetch.push(log.block_number);
                        }
                    }
                    blocks_to_fetch.sort();
                    blocks_to_fetch.dedup();

                    // Fetch block headers for new blocks
                    for block_num in &blocks_to_fetch {
                        if let Ok(Some(block)) = provider.get_block(*block_num).await {
                            if let Some(hash) = block.hash {
                                let hash_str = format!("{:?}", hash);
                                block_hash_cache.insert(*block_num, hash_str.clone());

                                // Add to block window with proper hash
                                let parent_hash = block.parent_hash;
                                let block_info = BlockInfo {
                                    id: BlockId {
                                        chain: config.chain_name.clone(),
                                        number: *block_num,
                                        hash: hash_str,
                                    },
                                    parent_hash: format!("{:?}", parent_hash),
                                    timestamp: block.timestamp.as_u64(),
                                    logs: vec![],
                                };
                                let mut window = block_window.write().await;
                                if let Some(reorg_info) = window.add_block(block_info) {
                                    warn!(
                                        "[{}] Reorg detected while adding block {}: {:?}",
                                        config.chain_name, block_num, reorg_info.reason
                                    );
                                    let _ = event_tx.send(SyncerEvent::Reorg(reorg_info)).await;
                                }
                            }
                        } else {
                            warn!(
                                "[{}] Failed to fetch block {} header",
                                config.chain_name, block_num
                            );
                        }
                    }
                }

                // Prune old entries from cache (keep only recent blocks)
                if block_hash_cache.len() > 200 {
                    let threshold = finalized_block.saturating_sub(10);
                    block_hash_cache.retain(|&k, _| k > threshold);
                }

                // Convert to ChainLogs with block hashes
                let chain_logs: Vec<ChainLog> = logs
                    .iter()
                    .map(|log| {
                        let block_hash = block_hash_cache
                            .get(&log.block_number)
                            .cloned()
                            .unwrap_or_default();
                        ChainLog {
                            block_id: BlockId {
                                chain: config.chain_name.clone(),
                                number: log.block_number,
                                hash: block_hash,
                            },
                            tx_hash: format!("{:?}", log.tx_hash),
                            log_index: log.log_index_in_tx as u32,
                            emitter: contract_str.clone(),
                            data: log.log.data.to_vec(),
                            topics: log.log.topics.iter().map(|t| format!("{:?}", t)).collect(),
                        }
                    })
                    .collect();

                // Update metrics
                if let Some(ref m) = metrics {
                    let last_block = logs.last().map(|l| l.block_number).unwrap_or(end_block);
                    m.last_synced_eth_blocks
                        .with_label_values(&[&contract_str])
                        .set(last_block as i64);
                }

                let is_finalized = end_block <= finalized_block;

                // Emit event
                let _ = event_tx
                    .send(SyncerEvent::NewLogs {
                        chain: config.chain_name.clone(),
                        contract: contract_str.clone(),
                        start_block,
                        end_block,
                        logs: chain_logs,
                        is_finalized,
                    })
                    .await;

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
            _ => {
                error!(
                    "[{}] Failed to fetch logs for {} after retry",
                    config.chain_name, contract_str
                );
                let _ = event_tx
                    .send(SyncerEvent::SyncError {
                        chain: config.chain_name.clone(),
                        error: format!("Failed to fetch logs for {}", contract_str),
                        recoverable: true,
                    })
                    .await;
            }
        }
    }
}

/// Task for reorg detection using BlockWindow
///
/// This task monitors blocks between finalized_block and latest_block for reorganizations.
/// Only unfinalized blocks can be reorged, so we focus on that range.
/// When a reorg is detected:
/// 1. Identifies the fork point
/// 2. Emits a Reorg event with orphaned unfinalized blocks
/// 3. Business logic can use this to rollback unfinalized events
///
/// Note: This task only works with MeteredEthHttpProvier clients that expose provider()
async fn run_reorg_detection_task(
    client: Arc<EthClient<MeteredEthHttpProvier>>,
    config: EthChainSyncerConfig,
    block_window: Arc<RwLock<BlockWindow>>,
    event_tx: mpsc::Sender<SyncerEvent>,
    cancel: CancellationToken,
) {
    info!(
        "[{}] Starting reorg detection task (finality_blocks={}, check_interval={:?})",
        config.chain_name, config.reorg.finality_blocks, config.reorg.check_interval
    );

    let mut interval = time::interval(config.reorg.check_interval);
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("[{}] Reorg detection task cancelled", config.chain_name);
                break;
            }
            _ = interval.tick() => {
                if let Err(e) = check_for_reorg(&client, &config, &block_window, &event_tx).await {
                    warn!("[{}] Reorg check error: {:?}", config.chain_name, e);
                    let _ = event_tx.send(SyncerEvent::SyncError {
                        chain: config.chain_name.clone(),
                        error: format!("Reorg check failed: {:?}", e),
                        recoverable: true,
                    }).await;
                }
            }
        }
    }
}

/// Check for chain reorganization by verifying recent unfinalized block hashes
///
/// This function:
/// 1. Gets the current finalized and latest block numbers
/// 2. Checks blocks in the window that are > finalized (unfinalized blocks)
/// 3. Verifies their hashes haven't changed on chain
/// 4. If hash mismatch found, emits Reorg event to rollback unfinalized events
async fn check_for_reorg(
    client: &Arc<EthClient<MeteredEthHttpProvier>>,
    config: &EthChainSyncerConfig,
    block_window: &Arc<RwLock<BlockWindow>>,
    event_tx: &mpsc::Sender<SyncerEvent>,
) -> SyncResult<()> {
    let provider = client.provider();

    // Get finalized block - only check blocks above this
    let finalized_block = client
        .get_last_finalized_block_id()
        .await
        .map_err(|e| SyncError::Rpc(format!("Failed to get finalized block: {:?}", e)))?;

    // Get latest block
    let latest_block = client
        .get_latest_block_id()
        .await
        .map_err(|e| SyncError::Rpc(format!("Failed to get latest block: {:?}", e)))?;

    let window = block_window.read().await;
    let Some((window_min, window_max)) = window.range() else {
        debug!(
            "[{}] Block window empty, skipping reorg check",
            config.chain_name
        );
        return Ok(());
    };
    drop(window);

    // Only check unfinalized blocks (finalized_block < block <= latest_block)
    let check_start = std::cmp::max(window_min, finalized_block + 1);
    let check_end = std::cmp::min(window_max, latest_block);

    if check_start > check_end {
        debug!(
            "[{}] No unfinalized blocks in window to check (finalized={}, window={}-{})",
            config.chain_name, finalized_block, window_min, window_max
        );
        return Ok(());
    }

    debug!(
        "[{}] Checking unfinalized blocks {}-{} for reorg (finalized={}, latest={})",
        config.chain_name, check_start, check_end, finalized_block, latest_block
    );

    // Check blocks from newest to oldest to find reorgs faster
    let check_count = std::cmp::min(5, check_end.saturating_sub(check_start) + 1);
    for i in 0..check_count {
        let block_num = check_end.saturating_sub(i);
        if block_num < check_start {
            break;
        }

        // Fetch block from chain
        let block =
            match provider.get_block(block_num).await.map_err(|e| {
                SyncError::Rpc(format!("Failed to get block {}: {:?}", block_num, e))
            })? {
                Some(b) => b,
                None => {
                    warn!(
                        "[{}] Block {} not found during reorg check",
                        config.chain_name, block_num
                    );
                    continue;
                }
            };

        let chain_hash = format!("{:?}", block.hash.unwrap_or_default());

        // Verify against our window
        let window = block_window.read().await;
        if !window.verify_block(block_num, &chain_hash) {
            // Reorg detected in unfinalized blocks!
            warn!(
                "[{}] Reorg detected at unfinalized block {}: hash mismatch",
                config.chain_name, block_num
            );

            // Fork point is the block before the mismatch (or finalized block, whichever is higher)
            let fork_point = std::cmp::max(block_num.saturating_sub(1), finalized_block);
            let (orphaned_blocks, orphaned_logs) = window.get_orphaned_blocks_with_logs(fork_point);
            drop(window);

            // Clear orphaned blocks from window
            let mut window_mut = block_window.write().await;
            window_mut.clear_after(fork_point);
            drop(window_mut);

            // Emit reorg event with logs - these are unfinalized events that need to be rolled back
            let reorg_info = ReorgInfo::with_logs(
                config.chain_name.clone(),
                fork_point,
                orphaned_blocks,
                orphaned_logs,
                format!(
                    "Unfinalized block {} hash changed on chain (reorg detected)",
                    block_num
                ),
            );

            let _ = event_tx.send(SyncerEvent::Reorg(reorg_info)).await;
            return Ok(());
        }
    }

    // Prune finalized blocks from window - they can't be reorged
    {
        let window = block_window.read().await;
        let Some((window_min, _)) = window.range() else {
            return Ok(());
        };

        if window_min <= finalized_block {
            drop(window);
            let mut window_mut = block_window.write().await;
            // Keep blocks from finalized_block onwards, remove older ones
            window_mut.prune_before(finalized_block);
        }
    }

    debug!(
        "[{}] Reorg check passed (unfinalized blocks {}-{})",
        config.chain_name, check_start, check_end
    );
    Ok(())
}

/// Builder for EthChainSyncer with fluent API
pub struct EthChainSyncerBuilder {
    config: EthChainSyncerConfig,
    metrics: Option<Arc<BridgeMetrics>>,
}

impl EthChainSyncerBuilder {
    pub fn new(chain_name: &str, rpc_url: &str) -> Self {
        Self {
            config: EthChainSyncerConfig::eth(chain_name, rpc_url),
            metrics: None,
        }
    }

    pub fn with_contract(mut self, address: &str, start_block: u64) -> Self {
        self.config = self.config.with_contract(address, start_block);
        self
    }

    pub fn with_reorg_detection(mut self, enabled: bool) -> Self {
        self.config.reorg.enabled = enabled;
        self
    }

    pub fn with_finality_blocks(mut self, blocks: u64) -> Self {
        self.config.reorg.finality_blocks = blocks;
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

    pub fn build<P>(self, client: Arc<EthClient<P>>) -> SyncResult<EthChainSyncer<P>>
    where
        P: ethers::providers::JsonRpcClient + 'static,
    {
        let syncer = EthChainSyncer::new(self.config, client)?;
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
        let builder = EthChainSyncerBuilder::new("eth", "http://localhost:8545")
            .with_contract("0x0000000000000000000000000000000000000001", 100)
            .with_reorg_detection(true)
            .with_finality_blocks(64);

        assert_eq!(builder.config.chain_name, "eth");
        assert_eq!(builder.config.contracts.len(), 1);
        assert!(builder.config.reorg.enabled);
        assert_eq!(builder.config.reorg.finality_blocks, 64);
    }

    #[test]
    fn test_multiple_contracts() {
        let builder = EthChainSyncerBuilder::new("eth", "http://localhost:8545")
            .with_contract("0x0000000000000000000000000000000000000001", 100)
            .with_contract("0x0000000000000000000000000000000000000002", 200);

        assert_eq!(builder.config.contracts.len(), 2);
        assert_eq!(builder.config.contracts[0].start_block, 100);
        assert_eq!(builder.config.contracts[1].start_block, 200);
    }

    #[test]
    fn test_config_validation() {
        // No contracts - should fail
        let config = EthChainSyncerConfig::eth("eth", "http://localhost:8545");
        assert!(config.validate().is_err());

        // With contract - should pass
        let config = config.with_contract("0x0000000000000000000000000000000000000001", 0);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_is_finalized_logic() {
        // Test the logic for determining is_finalized status
        // Based on: end_block <= finalized_block => is_finalized = true

        let finalized_block = 100u64;

        // Case 1: All blocks are finalized (end_block <= finalized_block)
        let end_block = 100u64;
        let is_finalized = end_block <= finalized_block;
        assert!(
            is_finalized,
            "Blocks 50-100 should be finalized when finalized=100"
        );

        // Case 2: Some blocks are unfinalized (end_block > finalized_block)
        let end_block = 110u64;
        let is_finalized = end_block <= finalized_block;
        assert!(
            !is_finalized,
            "Blocks up to 110 should NOT be finalized when finalized=100"
        );

        // Case 3: All blocks are unfinalized
        let end_block = 120u64;
        let is_finalized = end_block <= finalized_block;
        assert!(
            !is_finalized,
            "Blocks 101-120 should NOT be finalized when finalized=100"
        );
    }

    #[test]
    fn test_reorg_detection_range() {
        // Test the logic for determining which blocks to check for reorg
        // Only check blocks between finalized and latest (unfinalized blocks)

        let finalized_block = 100u64;
        let latest_block = 120u64;
        let window_min = 90u64;
        let window_max = 115u64;

        // Check range should be: max(window_min, finalized+1) to min(window_max, latest)
        let check_start = std::cmp::max(window_min, finalized_block + 1);
        let check_end = std::cmp::min(window_max, latest_block);

        assert_eq!(check_start, 101, "Should start checking from finalized+1");
        assert_eq!(check_end, 115, "Should check up to window_max");

        // All blocks in range should be unfinalized
        for block in check_start..=check_end {
            assert!(
                block > finalized_block,
                "Block {} should be > finalized",
                block
            );
            assert!(block <= latest_block, "Block {} should be <= latest", block);
        }
    }

    #[test]
    fn test_fork_point_calculation() {
        // Test fork point calculation during reorg
        let finalized_block = 100u64;
        let reorg_block = 110u64;

        // Fork point should be max(reorg_block - 1, finalized_block)
        // This ensures we never go below finalized block
        let fork_point = std::cmp::max(reorg_block.saturating_sub(1), finalized_block);

        assert_eq!(fork_point, 109, "Fork point should be reorg_block - 1");

        // Edge case: reorg at finalized+1
        let reorg_block = 101u64;
        let fork_point = std::cmp::max(reorg_block.saturating_sub(1), finalized_block);
        assert_eq!(fork_point, 100, "Fork point should be finalized_block");

        // Edge case: reorg_block equals finalized (shouldn't happen in practice)
        let reorg_block = 100u64;
        let fork_point = std::cmp::max(reorg_block.saturating_sub(1), finalized_block);
        assert_eq!(fork_point, 100, "Fork point clamped to finalized_block");
    }
}
