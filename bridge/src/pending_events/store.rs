// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pending event store - manages unfinalized events in memory

use super::types::*;
use crate::finality::{FinalityChecker, FinalityError};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// In-memory store for pending (unfinalized) events
///
/// Events are stored by block number and only written to DB after finalization.
/// This ensures clean restart without dirty data.
pub struct PendingEventStore<F: FinalityChecker> {
    /// Chain identifier for logging
    chain_name: String,
    /// Chain type
    chain_id: ChainId,
    /// Events indexed by block number (ordered for efficient range operations)
    events_by_block: RwLock<BTreeMap<u64, Vec<PendingEvent>>>,
    /// Last known finalized block
    last_finalized_block: RwLock<u64>,
    /// Finality checker for querying chain finality
    finality_checker: Arc<F>,
}

impl<F: FinalityChecker> PendingEventStore<F> {
    /// Create a new pending event store
    pub fn new(chain_name: &str, chain_id: ChainId, finality_checker: Arc<F>) -> Self {
        Self {
            chain_name: chain_name.to_string(),
            chain_id,
            events_by_block: RwLock::new(BTreeMap::new()),
            last_finalized_block: RwLock::new(0),
            finality_checker,
        }
    }

    /// Initialize with a known finalized block (e.g., from DB watermark)
    pub async fn initialize(&self, finalized_block: u64) {
        let mut last = self.last_finalized_block.write().await;
        *last = finalized_block;
        info!(
            "[{}] PendingEventStore initialized with finalized_block={}",
            self.chain_name, finalized_block
        );
    }

    /// Insert a new pending event
    ///
    /// Events at or below the finalized block are rejected (should not happen
    /// in normal operation, indicates a bug in the caller).
    pub async fn insert(&self, event: PendingEvent) -> bool {
        let finalized = *self.last_finalized_block.read().await;

        if event.block_number <= finalized {
            warn!(
                "[{}] Rejecting event at block {} <= finalized {}: tx={}, type={:?}",
                self.chain_name,
                event.block_number,
                finalized,
                event.tx_hash,
                event.event.event_type()
            );
            return false;
        }

        debug!(
            "[{}] Insert pending event: block={}, tx={}, type={:?}",
            self.chain_name,
            event.block_number,
            event.tx_hash,
            event.event.event_type()
        );

        let mut events = self.events_by_block.write().await;
        events.entry(event.block_number).or_default().push(event);

        true
    }

    /// Insert multiple events at once
    pub async fn insert_batch(&self, batch: Vec<PendingEvent>) -> usize {
        let finalized = *self.last_finalized_block.read().await;
        let mut events = self.events_by_block.write().await;
        let mut inserted = 0;
        let total = batch.len();

        for event in batch {
            if event.block_number > finalized {
                events.entry(event.block_number).or_default().push(event);
                inserted += 1;
            }
        }

        if inserted > 0 {
            debug!(
                "[{}] Batch insert: {}/{} events inserted (finalized_block={})",
                self.chain_name, inserted, total, finalized
            );
        }

        inserted
    }

    /// Check for newly finalized events and drain them
    ///
    /// Queries the finality checker for current finalized block and returns
    /// all events that are now finalized.
    pub async fn check_and_drain_finalized(&self) -> Result<DrainResult, FinalityError> {
        let new_finalized = self.finality_checker.get_finalized_block().await?;
        Ok(self.drain_finalized(new_finalized).await)
    }

    /// Drain all events at or below the given finalized block
    ///
    /// Returns events in block order (ascending) for ordered DB writes.
    pub async fn drain_finalized(&self, new_finalized: u64) -> DrainResult {
        let mut last = self.last_finalized_block.write().await;
        let old_finalized = *last;

        if new_finalized <= old_finalized {
            return DrainResult::default();
        }

        let mut events = self.events_by_block.write().await;

        // Split off events > new_finalized (these remain pending)
        let remaining = events.split_off(&(new_finalized + 1));

        // Current map now contains events <= new_finalized
        let mut finalized_events = Vec::new();
        for (block, block_events) in std::mem::replace(&mut *events, remaining) {
            if block > old_finalized {
                finalized_events.extend(block_events);
            }
        }

        let count = finalized_events.len();
        *last = new_finalized;

        if count > 0 {
            info!(
                "[{}] Drained {} finalized events: old_finalized={}, new_finalized={}, remaining_pending={}",
                self.chain_name,
                count,
                old_finalized,
                new_finalized,
                events.values().map(|v| v.len()).sum::<usize>()
            );
        } else {
            debug!(
                "[{}] Finality check: no new events to drain (finalized_block {} -> {})",
                self.chain_name, old_finalized, new_finalized
            );
        }

        DrainResult {
            finalized_events,
            count,
            new_finalized_block: new_finalized,
        }
    }

    /// Handle chain reorganization by removing events after fork point
    pub async fn handle_reorg(&self, fork_point: u64) -> ReorgResult {
        let mut events = self.events_by_block.write().await;

        // Remove all events > fork_point
        let removed = events.split_off(&(fork_point + 1));

        let affected_blocks: Vec<u64> = removed.keys().copied().collect();
        let removed_count: usize = removed.values().map(|v| v.len()).sum();

        if removed_count > 0 {
            warn!(
                "[{}] REORG detected at block {}: removed {} events from {} blocks ({:?}), remaining_pending={}",
                self.chain_name,
                fork_point,
                removed_count,
                affected_blocks.len(),
                affected_blocks,
                events.values().map(|v| v.len()).sum::<usize>()
            );
        } else {
            debug!(
                "[{}] Reorg check at block {}: no events affected",
                self.chain_name, fork_point
            );
        }

        ReorgResult {
            removed_count,
            affected_blocks,
        }
    }

    /// Get current pending event count
    pub async fn pending_count(&self) -> usize {
        let events = self.events_by_block.read().await;
        events.values().map(|v| v.len()).sum()
    }

    /// Get pending block range (min, max)
    pub async fn pending_block_range(&self) -> Option<(u64, u64)> {
        let events = self.events_by_block.read().await;
        let first = events.first_key_value().map(|(k, _)| *k);
        let last = events.last_key_value().map(|(k, _)| *k);
        first.zip(last)
    }

    /// Get current finalized block
    pub async fn finalized_block(&self) -> u64 {
        *self.last_finalized_block.read().await
    }

    /// Get all pending events (for debugging/inspection)
    pub async fn get_all_pending(&self) -> Vec<PendingEvent> {
        let events = self.events_by_block.read().await;
        events.values().flatten().cloned().collect()
    }

    /// Get events at a specific block
    pub async fn get_events_at_block(&self, block: u64) -> Vec<PendingEvent> {
        let events = self.events_by_block.read().await;
        events.get(&block).cloned().unwrap_or_default()
    }

    /// Check if a specific block's events are finalized
    pub async fn is_block_finalized(&self, block: u64) -> Result<bool, FinalityError> {
        self.finality_checker.is_finalized(block).await
    }

    /// Get chain ID
    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Get chain name
    pub fn chain_name(&self) -> &str {
        &self.chain_name
    }
}
