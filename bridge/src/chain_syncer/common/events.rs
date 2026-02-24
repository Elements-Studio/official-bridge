// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Events emitted by chain syncers
//!
//! These events represent pure data and can be consumed by business logic
//! without tight coupling to the syncer implementation.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for a block across chains
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockId {
    /// Chain identifier (e.g., "eth", "starcoin", "sepolia")
    pub chain: String,
    /// Block number/height
    pub number: u64,
    /// Block hash (hex string for consistency across chains)
    pub hash: String,
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.chain,
            self.number,
            truncate_hash(&self.hash)
        )
    }
}

/// Log/Event from a blockchain
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainLog {
    /// Block where this log was emitted
    pub block_id: BlockId,
    /// Transaction hash
    pub tx_hash: String,
    /// Log index within the transaction
    pub log_index: u32,
    /// Contract/Module address that emitted the event
    pub emitter: String,
    /// Raw log data (chain-specific encoding)
    pub data: Vec<u8>,
    /// Event topics (for ETH) or event type (for Starcoin)
    pub topics: Vec<String>,
}

/// Block information for tracking
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockInfo {
    /// Block identifier
    pub id: BlockId,
    /// Parent block hash
    pub parent_hash: String,
    /// Timestamp of the block (unix timestamp in seconds)
    pub timestamp: u64,
    /// Logs/events in this block
    pub logs: Vec<ChainLog>,
}

/// Reorg information when chain reorganization is detected
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgInfo {
    /// Chain identifier
    pub chain: String,
    /// Fork point - the last common ancestor block number
    pub fork_point: u64,
    /// Old chain blocks that were orphaned (from fork_point+1 onwards)
    pub orphaned_blocks: Vec<BlockId>,
    /// Logs/events affected by the reorg (from orphaned blocks)
    pub orphaned_logs: Vec<ChainLog>,
    /// Depth of the reorg (number of orphaned blocks)
    pub depth: usize,
    /// Human readable reason
    pub reason: String,
}

impl ReorgInfo {
    pub fn new(
        chain: String,
        fork_point: u64,
        orphaned_blocks: Vec<BlockId>,
        reason: String,
    ) -> Self {
        let depth = orphaned_blocks.len();
        Self {
            chain,
            fork_point,
            orphaned_blocks,
            orphaned_logs: Vec::new(),
            depth,
            reason,
        }
    }

    /// Create ReorgInfo with orphaned logs
    pub fn with_logs(
        chain: String,
        fork_point: u64,
        orphaned_blocks: Vec<BlockId>,
        orphaned_logs: Vec<ChainLog>,
        reason: String,
    ) -> Self {
        let depth = orphaned_blocks.len();
        Self {
            chain,
            fork_point,
            orphaned_blocks,
            orphaned_logs,
            depth,
            reason,
        }
    }
}

/// Events emitted by the ChainSyncer
///
/// These events are the output of the syncer and should be processed by
/// business logic handlers. The syncer itself doesn't perform any business
/// operations - it only emits these events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncerEvent {
    /// New block received (may or may not be finalized)
    NewBlock {
        block: BlockInfo,
        is_finalized: bool,
    },

    /// Multiple logs received for a contract in a block range
    /// This is more efficient than emitting one event per log
    NewLogs {
        chain: String,
        contract: String,
        /// Inclusive start block
        start_block: u64,
        /// Inclusive end block
        end_block: u64,
        logs: Vec<ChainLog>,
        is_finalized: bool,
    },

    /// Block has been finalized (reached sufficient confirmations)
    BlockFinalized { block_id: BlockId },

    /// Chain reorganization detected
    Reorg(ReorgInfo),

    /// New finalized block height observed
    FinalizedHeightUpdated { chain: String, height: u64 },

    /// New latest block height observed (not finalized yet)
    LatestHeightUpdated { chain: String, height: u64 },

    /// Syncer is caught up to the chain head
    CaughtUp { chain: String, height: u64 },

    /// Error occurred during sync (non-fatal, will retry)
    SyncError {
        chain: String,
        error: String,
        /// Whether this error is recoverable
        recoverable: bool,
    },

    /// Syncer started
    Started { chain: String, from_block: u64 },

    /// Syncer stopped
    Stopped { chain: String, reason: String },
}

impl SyncerEvent {
    pub fn chain(&self) -> &str {
        match self {
            SyncerEvent::NewBlock { block, .. } => &block.id.chain,
            SyncerEvent::NewLogs { chain, .. } => chain,
            SyncerEvent::BlockFinalized { block_id } => &block_id.chain,
            SyncerEvent::Reorg(info) => &info.chain,
            SyncerEvent::FinalizedHeightUpdated { chain, .. } => chain,
            SyncerEvent::LatestHeightUpdated { chain, .. } => chain,
            SyncerEvent::CaughtUp { chain, .. } => chain,
            SyncerEvent::SyncError { chain, .. } => chain,
            SyncerEvent::Started { chain, .. } => chain,
            SyncerEvent::Stopped { chain, .. } => chain,
        }
    }
}

/// Actions that can be requested from the syncer
/// These are used for controlling the syncer from outside
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncerCommand {
    /// Pause syncing
    Pause,
    /// Resume syncing
    Resume,
    /// Resync from a specific block (useful after reorg handling)
    ResyncFrom { block: u64 },
    /// Shutdown the syncer
    Shutdown,
    /// Force check for reorgs now
    CheckReorg,
}

/// Trait for handling chain reorganizations
///
/// Consumers can implement this trait to handle reorg events according to
/// their business logic (e.g., deleting orphaned records from DB, sending notifications).
///
/// # Example
///
/// ```ignore
/// struct MyReorgHandler {
///     db: Db,
///     notifier: TelegramNotifier,
/// }
///
/// #[async_trait]
/// impl ReorgHandler for MyReorgHandler {
///     async fn handle_reorg(&self, reorg: &ReorgInfo) -> Result<(), String> {
///         // Delete orphaned events from DB
///         for log in &reorg.orphaned_logs {
///             self.db.delete_event(&log.tx_hash, log.log_index).await?;
///         }
///         // Send notification
///         self.notifier.send(format!("Reorg at {}", reorg.fork_point)).await?;
///         Ok(())
///     }
/// }
/// ```
#[async_trait::async_trait]
pub trait ReorgHandler: Send + Sync {
    /// Handle a chain reorganization event
    ///
    /// Called when a reorg is detected. The implementation should:
    /// 1. Invalidate/delete any orphaned events from storage
    /// 2. Optionally send notifications
    /// 3. Return Ok(()) on success, Err with reason on failure
    async fn handle_reorg(&self, reorg: &ReorgInfo) -> Result<(), String>;

    /// Check if an event is safe to process (not affected by pending reorg)
    ///
    /// Default implementation returns true. Override for custom logic.
    async fn is_event_safe(&self, _: &ChainLog) -> bool {
        true
    }

    /// Called when a block is finalized (can be used to mark records as finalized)
    async fn on_block_finalized(&self, _: &BlockId) -> Result<(), String> {
        Ok(())
    }
}

/// Helper function to truncate hash for display
pub fn truncate_hash(hash: &str) -> String {
    if hash.len() > 16 {
        format!("{}...{}", &hash[..8], &hash[hash.len() - 6..])
    } else {
        hash.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_id_display() {
        let block = BlockId {
            chain: "eth".to_string(),
            number: 12345,
            hash: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        };
        let display = format!("{}", block);
        assert!(display.contains("eth"));
        assert!(display.contains("12345"));
    }

    #[test]
    fn test_truncate_hash() {
        let hash = "0x1234567890abcdef1234567890abcdef12345678";
        let truncated = truncate_hash(hash);
        assert!(truncated.len() < hash.len());
        assert!(truncated.contains("..."));

        // Short hash should not be truncated
        let short = "0x1234";
        assert_eq!(truncate_hash(short), short);
    }

    #[test]
    fn test_reorg_info() {
        let orphaned = vec![
            BlockId {
                chain: "eth".to_string(),
                number: 101,
                hash: "0xabc".to_string(),
            },
            BlockId {
                chain: "eth".to_string(),
                number: 102,
                hash: "0xdef".to_string(),
            },
        ];
        let reorg = ReorgInfo::new(
            "eth".to_string(),
            100,
            orphaned,
            "hash mismatch".to_string(),
        );
        assert_eq!(reorg.depth, 2);
        assert_eq!(reorg.fork_point, 100);
    }

    #[test]
    fn test_syncer_event_chain() {
        let event = SyncerEvent::FinalizedHeightUpdated {
            chain: "eth".to_string(),
            height: 100,
        };
        assert_eq!(event.chain(), "eth");
    }

    #[test]
    fn test_latest_height_updated_event() {
        let event = SyncerEvent::LatestHeightUpdated {
            chain: "eth".to_string(),
            height: 200,
        };
        assert_eq!(event.chain(), "eth");

        // Verify it's different from FinalizedHeightUpdated
        let finalized = SyncerEvent::FinalizedHeightUpdated {
            chain: "eth".to_string(),
            height: 100,
        };
        assert_ne!(event, finalized);
    }

    #[test]
    fn test_new_logs_finalization_status() {
        // Test logs with is_finalized = true
        let finalized_logs = SyncerEvent::NewLogs {
            chain: "eth".to_string(),
            contract: "0x123".to_string(),
            start_block: 100,
            end_block: 110,
            logs: vec![],
            is_finalized: true,
        };

        // Test logs with is_finalized = false
        let unfinalized_logs = SyncerEvent::NewLogs {
            chain: "eth".to_string(),
            contract: "0x123".to_string(),
            start_block: 111,
            end_block: 120,
            logs: vec![],
            is_finalized: false,
        };

        assert_ne!(finalized_logs, unfinalized_logs);

        // Both should have same chain
        assert_eq!(finalized_logs.chain(), unfinalized_logs.chain());
    }
}
