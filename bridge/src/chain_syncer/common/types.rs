// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Common types used across chain syncers

use super::events::{BlockInfo, ChainLog};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Trait for chain-specific block fetching
#[async_trait::async_trait]
pub trait BlockFetcher: Send + Sync {
    /// Get the latest finalized block number
    async fn get_finalized_block(&self) -> Result<u64, SyncError>;

    /// Get block info by number
    async fn get_block(&self, number: u64) -> Result<Option<BlockInfo>, SyncError>;

    /// Get logs for a contract in a block range
    async fn get_logs(
        &self,
        contract: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<ChainLog>, SyncError>;
}

/// Error type for sync operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum SyncError {
    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("Block not found: {0}")]
    BlockNotFound(u64),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Reorg detected at block {0}")]
    ReorgDetected(u64),

    #[error("{0}")]
    Other(String),
}

impl SyncError {
    /// Whether this error is recoverable (should retry)
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            SyncError::Rpc(_) | SyncError::Timeout(_) | SyncError::BlockNotFound(_)
        )
    }
}

/// Tracked block in the sliding window
#[derive(Debug, Clone)]
pub struct TrackedBlock {
    pub info: BlockInfo,
    pub received_at: Instant,
}

impl TrackedBlock {
    pub fn new(info: BlockInfo) -> Self {
        Self {
            info,
            received_at: Instant::now(),
        }
    }
}

/// Cursor tracking for sync progress
#[derive(Debug, Clone, Default)]
pub struct SyncCursor {
    /// Last synced block number (inclusive)
    pub block_number: u64,
    /// Whether we're caught up to chain head
    pub is_caught_up: bool,
}

/// State for a contract being synced
#[derive(Debug)]
pub struct ContractSyncState {
    /// Contract address
    pub address: String,
    /// Current cursor position
    pub cursor: SyncCursor,
    /// Pending logs not yet finalized
    pub pending_logs: Vec<ChainLog>,
}

impl ContractSyncState {
    pub fn new(address: String, start_block: u64) -> Self {
        Self {
            address,
            cursor: SyncCursor {
                block_number: start_block.saturating_sub(1),
                is_caught_up: false,
            },
            pending_logs: Vec::new(),
        }
    }
}

/// Shared state for the syncer
pub struct SyncerState {
    /// Last known finalized block
    pub finalized_block: u64,
    /// Block tracking window (for reorg detection)
    pub blocks: HashMap<u64, TrackedBlock>,
    /// Per-contract sync state
    pub contracts: HashMap<String, ContractSyncState>,
    /// Whether the syncer is paused
    pub paused: bool,
}

impl SyncerState {
    pub fn new() -> Self {
        Self {
            finalized_block: 0,
            blocks: HashMap::new(),
            contracts: HashMap::new(),
            paused: false,
        }
    }
}

impl Default for SyncerState {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe wrapper for syncer state
pub type SharedSyncerState = Arc<RwLock<SyncerState>>;

/// Create a new shared syncer state
pub fn new_shared_state() -> SharedSyncerState {
    Arc::new(RwLock::new(SyncerState::new()))
}

/// Result type for syncer operations
pub type SyncResult<T> = Result<T, SyncError>;
