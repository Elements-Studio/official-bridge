// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Sliding window for block tracking and reorg detection
//!
//! Maintains a window of recent blocks to detect chain reorganizations
//! by comparing block hashes when new blocks arrive.

use super::events::{BlockId, BlockInfo, ChainLog, ReorgInfo};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Block entry in the window
#[derive(Debug, Clone)]
pub struct WindowBlock {
    pub info: BlockInfo,
    pub received_at: Instant,
}

/// Sliding window for tracking blocks and detecting reorgs
pub struct BlockWindow {
    /// Chain identifier
    chain: String,
    /// Window size (number of blocks to track)
    window_size: u64,
    /// Maximum age of blocks in window
    max_age: Duration,
    /// Tracked blocks: block_number -> WindowBlock
    blocks: HashMap<u64, WindowBlock>,
    /// Highest block number seen
    highest_block: u64,
}

impl BlockWindow {
    /// Create a new block window
    pub fn new(chain: &str, window_size: u64, max_age: Duration) -> Self {
        Self {
            chain: chain.to_string(),
            window_size,
            max_age,
            blocks: HashMap::new(),
            highest_block: 0,
        }
    }

    /// Add a block to the window
    /// Returns Some(ReorgInfo) if reorg detected, None otherwise
    pub fn add_block(&mut self, info: BlockInfo) -> Option<ReorgInfo> {
        let block_number = info.id.number;

        // Check for reorg before adding
        let reorg = self.check_continuity(&info);

        // Add the block
        self.blocks.insert(
            block_number,
            WindowBlock {
                info,
                received_at: Instant::now(),
            },
        );

        // Update highest block
        if block_number > self.highest_block {
            self.highest_block = block_number;
        }

        // Prune old blocks
        self.prune();

        reorg
    }

    /// Check chain continuity when a new block arrives
    /// Returns Some(ReorgInfo) if reorg detected
    fn check_continuity(&self, new_block: &BlockInfo) -> Option<ReorgInfo> {
        let new_number = new_block.id.number;
        let new_parent = &new_block.parent_hash;

        // Check if we have the previous block
        if let Some(prev_block) = self.blocks.get(&(new_number.saturating_sub(1))) {
            if &prev_block.info.id.hash != new_parent {
                // Reorg detected!
                warn!(
                    "[{}] Chain discontinuity at block {}: expected parent {} but got {}",
                    self.chain,
                    new_number,
                    truncate_hash(&prev_block.info.id.hash),
                    truncate_hash(new_parent)
                );

                // Find fork point
                let fork_point = self.find_fork_point(new_number, new_parent);
                let (orphaned_blocks, orphaned_logs) =
                    self.get_orphaned_blocks_with_logs(fork_point);

                return Some(ReorgInfo::with_logs(
                    self.chain.clone(),
                    fork_point,
                    orphaned_blocks,
                    orphaned_logs,
                    format!(
                        "Block hash mismatch at {}: expected {} but got {}",
                        new_number,
                        truncate_hash(&prev_block.info.id.hash),
                        truncate_hash(new_parent)
                    ),
                ));
            }
        }

        // Also check if we're receiving a block that we already have with different hash
        if let Some(existing) = self.blocks.get(&new_number) {
            if existing.info.id.hash != new_block.id.hash {
                warn!(
                    "[{}] Block {} hash changed: {} -> {}",
                    self.chain,
                    new_number,
                    truncate_hash(&existing.info.id.hash),
                    truncate_hash(&new_block.id.hash)
                );

                let fork_point = new_number.saturating_sub(1);
                let (orphaned_blocks, orphaned_logs) =
                    self.get_orphaned_blocks_with_logs(fork_point);

                return Some(ReorgInfo::with_logs(
                    self.chain.clone(),
                    fork_point,
                    orphaned_blocks,
                    orphaned_logs,
                    format!(
                        "Block {} hash changed from {} to {}",
                        new_number,
                        truncate_hash(&existing.info.id.hash),
                        truncate_hash(&new_block.id.hash)
                    ),
                ));
            }
        }

        None
    }

    /// Find the fork point by walking back the chain
    fn find_fork_point(&self, from_block: u64, _: &str) -> u64 {
        // Simple implementation: return the block before the mismatch
        // A more sophisticated version could verify the full chain
        from_block.saturating_sub(1)
    }

    /// Get all blocks after a given block number with full info (including logs)
    pub fn get_orphaned_blocks_with_logs(&self, fork_point: u64) -> (Vec<BlockId>, Vec<ChainLog>) {
        let mut blocks: Vec<_> = self
            .blocks
            .values()
            .filter(|b| b.info.id.number > fork_point)
            .collect();
        blocks.sort_by(|a, b| a.info.id.number.cmp(&b.info.id.number));

        let block_ids: Vec<BlockId> = blocks.iter().map(|b| b.info.id.clone()).collect();
        let logs: Vec<ChainLog> = blocks.iter().flat_map(|b| b.info.logs.clone()).collect();

        (block_ids, logs)
    }

    /// Verify a block's hash against the chain
    /// Returns true if block hash matches, false if reorg detected
    pub fn verify_block(&self, block_number: u64, expected_hash: &str) -> bool {
        if let Some(block) = self.blocks.get(&block_number) {
            block.info.id.hash == expected_hash
        } else {
            // Block not in window, can't verify
            true
        }
    }

    /// Get a block by number
    pub fn get_block(&self, block_number: u64) -> Option<&BlockInfo> {
        self.blocks.get(&block_number).map(|b| &b.info)
    }

    /// Clear all blocks after a fork point (for reorg rollback)
    pub fn clear_after(&mut self, fork_point: u64) {
        let before_count = self.blocks.len();
        self.blocks.retain(|&num, _| num <= fork_point);
        let removed = before_count - self.blocks.len();

        if removed > 0 {
            info!(
                "[{}] Cleared {} blocks after fork point {}",
                self.chain, removed, fork_point
            );
        }

        // Update highest block
        self.highest_block = self.blocks.keys().copied().max().unwrap_or(0);
    }

    /// Prune blocks before a given block number (for removing finalized blocks from window)
    pub fn prune_before(&mut self, block_number: u64) {
        let before_count = self.blocks.len();
        self.blocks.retain(|&num, _| num >= block_number);
        let removed = before_count - self.blocks.len();

        if removed > 0 {
            info!(
                "[{}] Pruned {} finalized blocks before {}",
                self.chain, removed, block_number
            );
        }
    }

    /// Prune blocks outside the window or too old
    fn prune(&mut self) {
        let now = Instant::now();
        let oldest_to_keep = self.highest_block.saturating_sub(self.window_size);

        self.blocks.retain(|&num, block| {
            let keep_by_number = num >= oldest_to_keep;
            let keep_by_age = now.duration_since(block.received_at) < self.max_age;
            keep_by_number && keep_by_age
        });
    }

    /// Get the number of blocks in the window
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Check if the window is empty
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Get the window range (min, max block numbers)
    pub fn range(&self) -> Option<(u64, u64)> {
        if self.blocks.is_empty() {
            return None;
        }
        let min = *self.blocks.keys().min().unwrap();
        let max = *self.blocks.keys().max().unwrap();
        Some((min, max))
    }

    /// Get the highest tracked block
    pub fn highest(&self) -> u64 {
        self.highest_block
    }
}

/// Helper to truncate hash for display
fn truncate_hash(hash: &str) -> String {
    if hash.len() > 16 {
        format!("{}...{}", &hash[..8], &hash[hash.len() - 6..])
    } else {
        hash.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block(number: u64, hash: &str, parent_hash: &str) -> BlockInfo {
        BlockInfo {
            id: BlockId {
                chain: "test".to_string(),
                number,
                hash: hash.to_string(),
            },
            parent_hash: parent_hash.to_string(),
            timestamp: 0,
            logs: Vec::new(),
        }
    }

    #[test]
    fn test_normal_chain() {
        let mut window = BlockWindow::new("test", 10, Duration::from_secs(300));

        // Add blocks in order
        assert!(window
            .add_block(make_block(1, "hash1", "genesis"))
            .is_none());
        assert!(window.add_block(make_block(2, "hash2", "hash1")).is_none());
        assert!(window.add_block(make_block(3, "hash3", "hash2")).is_none());

        assert_eq!(window.len(), 3);
        assert_eq!(window.highest(), 3);
    }

    #[test]
    fn test_reorg_detection() {
        let mut window = BlockWindow::new("test", 10, Duration::from_secs(300));

        // Build initial chain
        window.add_block(make_block(1, "hash1", "genesis"));
        window.add_block(make_block(2, "hash2", "hash1"));
        window.add_block(make_block(3, "hash3", "hash2"));

        // Now receive a different block 3 (reorg)
        let reorg = window.add_block(make_block(3, "hash3_alt", "hash2"));
        assert!(reorg.is_some());

        let reorg = reorg.unwrap();
        assert_eq!(reorg.fork_point, 2);
        assert_eq!(reorg.orphaned_blocks.len(), 1);
    }

    #[test]
    fn test_parent_mismatch() {
        let mut window = BlockWindow::new("test", 10, Duration::from_secs(300));

        // Build initial chain
        window.add_block(make_block(1, "hash1", "genesis"));
        window.add_block(make_block(2, "hash2", "hash1"));

        // New block with wrong parent
        let reorg = window.add_block(make_block(3, "hash3", "wrong_parent"));
        assert!(reorg.is_some());

        let reorg = reorg.unwrap();
        assert_eq!(reorg.fork_point, 2);
    }

    #[test]
    fn test_window_pruning() {
        let mut window = BlockWindow::new("test", 5, Duration::from_secs(300));

        // Add more blocks than window size
        for i in 1..=10 {
            window.add_block(make_block(
                i,
                &format!("hash{}", i),
                &format!("hash{}", i - 1),
            ));
        }

        // Should only keep last 5 blocks (6-10)
        assert!(window.len() <= 6); // window_size + 1 for boundary
        assert!(window.get_block(1).is_none());
        assert!(window.get_block(10).is_some());
    }

    #[test]
    fn test_clear_after() {
        let mut window = BlockWindow::new("test", 10, Duration::from_secs(300));

        for i in 1..=5 {
            window.add_block(make_block(
                i,
                &format!("hash{}", i),
                &format!("hash{}", i - 1),
            ));
        }

        window.clear_after(3);

        assert_eq!(window.len(), 3);
        assert!(window.get_block(1).is_some());
        assert!(window.get_block(3).is_some());
        assert!(window.get_block(4).is_none());
    }

    #[test]
    fn test_prune_before() {
        let mut window = BlockWindow::new("test", 10, Duration::from_secs(300));

        for i in 1..=5 {
            window.add_block(make_block(
                i,
                &format!("hash{}", i),
                &format!("hash{}", i - 1),
            ));
        }

        window.prune_before(3);

        assert_eq!(window.len(), 3);
        assert!(window.get_block(1).is_none());
        assert!(window.get_block(2).is_none());
        assert!(window.get_block(3).is_some());
        assert!(window.get_block(4).is_some());
        assert!(window.get_block(5).is_some());
    }

    #[test]
    fn test_range() {
        let mut window = BlockWindow::new("test", 10, Duration::from_secs(300));
        assert!(window.range().is_none());

        window.add_block(make_block(5, "hash5", "hash4"));
        window.add_block(make_block(10, "hash10", "hash9"));

        let range = window.range().unwrap();
        assert_eq!(range, (5, 10));
    }
}
