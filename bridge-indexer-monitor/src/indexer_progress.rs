// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Indexer Progress Store
//!
//! This module manages watermarks for ETH and Starcoin indexers using the `progress_store` table.
//! It provides a persistent mechanism to track the last finalized block that has been fully processed.
//!
//! ## Watermark Semantics
//! - The watermark represents the highest finalized block where ALL events have been processed
//! - On restart, syncing starts from `max(config_start_block, watermark + 1, max_finalized_event_block + 1)`
//! - This ensures backward compatibility while leveraging the progress store

use anyhow::{Context, Result};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::RunQueryDsl;
use starcoin_bridge_pg_db::Db;
use starcoin_bridge_schema::models::BridgeDataSource;
use starcoin_bridge_schema::schema::progress_store;
use tracing::{debug, info, warn};

/// Task name for ETH indexer progress
pub const ETH_INDEXER_TASK_NAME: &str = "eth_indexer_watermark";

/// Task name for Starcoin indexer progress
pub const STC_INDEXER_TASK_NAME: &str = "stc_indexer_watermark";

/// Default target block (effectively infinite for live tasks)
const LIVE_TASK_TARGET_BLOCK: i64 = i64::MAX;

/// Indexer Progress Store for managing watermarks
#[derive(Clone)]
pub struct IndexerProgressStore {
    db: Db,
}

impl IndexerProgressStore {
    /// Create a new IndexerProgressStore
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Get the watermark (last fully processed finalized block) for a task
    ///
    /// Returns None if no progress has been recorded yet
    pub async fn get_watermark(&self, task_name: &str) -> Result<Option<u64>> {
        use progress_store::dsl;

        let mut conn = self.db.connect().await?;

        // Only select block_number to avoid type mismatch issues with timestamp
        let result: Option<i64> = dsl::progress_store
            .filter(dsl::task_name.eq(task_name))
            .select(dsl::block_number)
            .first(&mut conn)
            .await
            .optional()?;

        Ok(result.map(|r| r as u64))
    }

    /// Update the watermark for a task
    ///
    /// This should be called when a block is finalized and all its events are processed
    pub async fn update_watermark(&self, task_name: &str, block_number: u64) -> Result<()> {
        use diesel::dsl::now;
        use progress_store::dsl;

        let mut conn = self.db.connect().await?;

        // Upsert: insert or update on conflict
        // Use raw SQL for insert with DEFAULT timestamp
        diesel::insert_into(dsl::progress_store)
            .values((
                dsl::task_name.eq(task_name),
                dsl::block_number.eq(block_number as i64),
                dsl::target_block.eq(LIVE_TASK_TARGET_BLOCK),
                dsl::timestamp.eq(now),
            ))
            .on_conflict(dsl::task_name)
            .do_update()
            .set((
                dsl::block_number.eq(block_number as i64),
                dsl::timestamp.eq(now),
            ))
            .execute(&mut conn)
            .await
            .context("Failed to update watermark")?;

        debug!(
            "[ProgressStore] Updated watermark for '{}' to {}",
            task_name, block_number
        );

        Ok(())
    }

    /// Get the starting block for ETH indexer
    ///
    /// Logic: max(config_start_block, watermark_from_table + 1, max_finalized_event_block + 1)
    pub async fn get_eth_start_block(&self, config_start_block: u64) -> u64 {
        self.get_start_block_internal(
            ETH_INDEXER_TASK_NAME,
            BridgeDataSource::ETH,
            config_start_block,
        )
        .await
    }

    /// Get the starting block for Starcoin indexer
    ///
    /// Logic: max(config_start_block, watermark_from_table + 1, max_finalized_event_block + 1)
    pub async fn get_stc_start_block(&self, config_start_block: u64) -> u64 {
        self.get_start_block_internal(
            STC_INDEXER_TASK_NAME,
            BridgeDataSource::STARCOIN,
            config_start_block,
        )
        .await
    }

    /// Internal helper to get start block with backward compatibility
    async fn get_start_block_internal(
        &self,
        task_name: &str,
        data_source: BridgeDataSource,
        config_start_block: u64,
    ) -> u64 {
        let chain_name = match data_source {
            BridgeDataSource::ETH => "ETH",
            BridgeDataSource::STARCOIN => "STC",
        };

        // 1. Get watermark from progress_store table
        let watermark_from_table = match self.get_watermark(task_name).await {
            Ok(Some(w)) => {
                info!("[{}] Found watermark in progress_store: {}", chain_name, w);
                Some(w)
            }
            Ok(None) => {
                info!("[{}] No watermark found in progress_store", chain_name);
                None
            }
            Err(e) => {
                warn!("[{}] Failed to query progress_store: {:?}", chain_name, e);
                None
            }
        };

        // 2. Get max finalized event block from token_transfer (backward compatibility)
        let max_finalized_event_block = match self.get_max_finalized_event_block(data_source).await
        {
            Ok(Some(b)) => {
                info!(
                    "[{}] Found max finalized event block in token_transfer: {}",
                    chain_name, b
                );
                Some(b)
            }
            Ok(None) => {
                info!(
                    "[{}] No finalized events found in token_transfer",
                    chain_name
                );
                None
            }
            Err(e) => {
                warn!(
                    "[{}] Failed to query max finalized event block: {:?}",
                    chain_name, e
                );
                None
            }
        };

        // 3. Check for unfinalized events (need to re-process from earliest unfinalized)
        let min_unfinalized_block = match self.get_min_unfinalized_event_block(data_source).await {
            Ok(Some(b)) => {
                info!(
                    "[{}] Found unfinalized events starting at block: {}",
                    chain_name, b
                );
                Some(b)
            }
            Ok(None) => None,
            Err(e) => {
                warn!(
                    "[{}] Failed to query min unfinalized block: {:?}",
                    chain_name, e
                );
                None
            }
        };

        // Calculate start block:
        // - If there are unfinalized events, start from the earliest unfinalized block
        // - Otherwise, start from max(config, watermark+1, max_finalized+1)
        let start_block = if let Some(min_unfinalized) = min_unfinalized_block {
            // There are unfinalized events - start from there (might be reorged)
            std::cmp::max(config_start_block, min_unfinalized)
        } else {
            // No unfinalized events - start from after the highest known position
            let watermark_next = watermark_from_table
                .map(|w| w.saturating_add(1))
                .unwrap_or(0);
            let finalized_next = max_finalized_event_block
                .map(|b| b.saturating_add(1))
                .unwrap_or(0);

            std::cmp::max(
                config_start_block,
                std::cmp::max(watermark_next, finalized_next),
            )
        };

        info!(
            "[{}] Calculated start block: {} (config={}, watermark={:?}, max_finalized={:?}, min_unfinalized={:?})",
            chain_name, start_block, config_start_block, watermark_from_table, max_finalized_event_block, min_unfinalized_block
        );

        start_block
    }

    /// Get max finalized event block height from token_transfer table
    async fn get_max_finalized_event_block(
        &self,
        data_source: BridgeDataSource,
    ) -> Result<Option<u64>> {
        use diesel::dsl::max;
        use starcoin_bridge_schema::schema::token_transfer;

        let mut conn = self.db.connect().await?;

        let result: Option<i64> = token_transfer::table
            .filter(token_transfer::data_source.eq(data_source.as_ref()))
            .filter(token_transfer::is_finalized.eq(Some(true)))
            .select(max(token_transfer::block_height))
            .first(&mut conn)
            .await?;

        Ok(result.map(|b| b as u64))
    }

    /// Get min unfinalized event block height from token_transfer table
    async fn get_min_unfinalized_event_block(
        &self,
        data_source: BridgeDataSource,
    ) -> Result<Option<u64>> {
        use diesel::dsl::min;
        use starcoin_bridge_schema::schema::token_transfer;

        let mut conn = self.db.connect().await?;

        let result: Option<i64> = token_transfer::table
            .filter(token_transfer::data_source.eq(data_source.as_ref()))
            .filter(token_transfer::is_finalized.eq(Some(false)))
            .select(min(token_transfer::block_height))
            .first(&mut conn)
            .await?;

        Ok(result.map(|b| b as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // Constants Tests
    // ============================================================================

    #[test]
    fn test_task_names() {
        assert_eq!(ETH_INDEXER_TASK_NAME, "eth_indexer_watermark");
        assert_eq!(STC_INDEXER_TASK_NAME, "stc_indexer_watermark");
    }

    #[test]
    fn test_live_task_target() {
        assert_eq!(LIVE_TASK_TARGET_BLOCK, i64::MAX);
    }

    // ============================================================================
    // Start Block Calculation Logic Tests
    // ============================================================================

    /// Helper to compute start block from given inputs (extracted for testability)
    /// This mirrors the logic in get_start_block_internal
    fn compute_start_block(
        config_start_block: u64,
        watermark_from_table: Option<u64>,
        max_finalized_event_block: Option<u64>,
        min_unfinalized_block: Option<u64>,
    ) -> u64 {
        if let Some(min_unfinalized) = min_unfinalized_block {
            // There are unfinalized events - start from there (might be reorged)
            std::cmp::max(config_start_block, min_unfinalized)
        } else {
            // No unfinalized events - start from after the highest known position
            let watermark_next = watermark_from_table
                .map(|w| w.saturating_add(1))
                .unwrap_or(0);
            let finalized_next = max_finalized_event_block
                .map(|b| b.saturating_add(1))
                .unwrap_or(0);

            std::cmp::max(
                config_start_block,
                std::cmp::max(watermark_next, finalized_next),
            )
        }
    }

    // --------------------------------------------------------------------------
    // Scenario 1: Fresh start (no data in DB)
    // --------------------------------------------------------------------------

    #[test]
    fn test_fresh_start_uses_config() {
        // No watermark, no events -> use config_start_block
        let result = compute_start_block(100, None, None, None);
        assert_eq!(result, 100);
    }

    #[test]
    fn test_fresh_start_config_zero() {
        // Config is 0, no data -> start from 0
        let result = compute_start_block(0, None, None, None);
        assert_eq!(result, 0);
    }

    // --------------------------------------------------------------------------
    // Scenario 2: Only watermark exists (progress_store has data)
    // --------------------------------------------------------------------------

    #[test]
    fn test_watermark_only_higher_than_config() {
        // Watermark at 500 -> start from 501
        let result = compute_start_block(100, Some(500), None, None);
        assert_eq!(result, 501);
    }

    #[test]
    fn test_watermark_only_lower_than_config() {
        // Watermark at 50, config is 100 -> use config (never go below)
        let result = compute_start_block(100, Some(50), None, None);
        assert_eq!(result, 100);
    }

    #[test]
    fn test_watermark_zero() {
        // Watermark at 0 -> start from 1
        let result = compute_start_block(0, Some(0), None, None);
        assert_eq!(result, 1);
    }

    // --------------------------------------------------------------------------
    // Scenario 3: Only finalized events exist (backward compatibility)
    // --------------------------------------------------------------------------

    #[test]
    fn test_finalized_events_only_higher_than_config() {
        // Max finalized at 500 -> start from 501
        let result = compute_start_block(100, None, Some(500), None);
        assert_eq!(result, 501);
    }

    #[test]
    fn test_finalized_events_only_lower_than_config() {
        // Max finalized at 50, config is 100 -> use config
        let result = compute_start_block(100, None, Some(50), None);
        assert_eq!(result, 100);
    }

    // --------------------------------------------------------------------------
    // Scenario 4: Both watermark and finalized events exist
    // --------------------------------------------------------------------------

    #[test]
    fn test_watermark_higher_than_finalized() {
        // Watermark at 600, max finalized at 500 -> use watermark (601)
        let result = compute_start_block(100, Some(600), Some(500), None);
        assert_eq!(result, 601);
    }

    #[test]
    fn test_finalized_higher_than_watermark() {
        // Watermark at 400, max finalized at 500 -> use finalized (501)
        // This can happen if watermark wasn't updated for some reason
        let result = compute_start_block(100, Some(400), Some(500), None);
        assert_eq!(result, 501);
    }

    #[test]
    fn test_watermark_equals_finalized() {
        // Both at 500 -> start from 501
        let result = compute_start_block(100, Some(500), Some(500), None);
        assert_eq!(result, 501);
    }

    #[test]
    fn test_config_higher_than_both() {
        // Config 1000 > watermark 500 > finalized 400 -> use config
        let result = compute_start_block(1000, Some(500), Some(400), None);
        assert_eq!(result, 1000);
    }

    // --------------------------------------------------------------------------
    // Scenario 5: Unfinalized events exist (reorg handling)
    // --------------------------------------------------------------------------

    #[test]
    fn test_unfinalized_events_take_priority() {
        // Unfinalized at 450, watermark at 500, finalized at 400
        // Should start from unfinalized (450) to re-process potential reorg
        let result = compute_start_block(100, Some(500), Some(400), Some(450));
        assert_eq!(result, 450);
    }

    #[test]
    fn test_unfinalized_lower_than_config() {
        // Unfinalized at 50, config is 100 -> use config (never go below)
        let result = compute_start_block(100, Some(500), Some(400), Some(50));
        assert_eq!(result, 100);
    }

    #[test]
    fn test_unfinalized_higher_than_config() {
        // Unfinalized at 200, config is 100 -> use unfinalized
        let result = compute_start_block(100, None, None, Some(200));
        assert_eq!(result, 200);
    }

    #[test]
    fn test_unfinalized_ignores_watermark_and_finalized() {
        // When unfinalized exists, watermark and finalized are ignored
        // Unfinalized at 300, watermark at 1000, finalized at 800 -> use 300
        let result = compute_start_block(100, Some(1000), Some(800), Some(300));
        assert_eq!(result, 300);
    }

    // --------------------------------------------------------------------------
    // Scenario 6: Edge cases and overflow protection
    // --------------------------------------------------------------------------

    #[test]
    fn test_saturating_add_watermark() {
        // Test overflow protection with saturating_add
        // u64::MAX watermark -> should not overflow
        let result = compute_start_block(0, Some(u64::MAX), None, None);
        assert_eq!(result, u64::MAX); // saturating_add prevents overflow
    }

    #[test]
    fn test_saturating_add_finalized() {
        // Test overflow protection for finalized block
        let result = compute_start_block(0, None, Some(u64::MAX), None);
        assert_eq!(result, u64::MAX); // saturating_add prevents overflow
    }

    #[test]
    fn test_large_values() {
        // Test with large but not maximum values
        let large_block = u64::MAX - 1;
        let result = compute_start_block(0, Some(large_block), None, None);
        assert_eq!(result, u64::MAX);
    }

    #[test]
    fn test_all_sources_present() {
        // All data sources present, unfinalized takes priority
        let result = compute_start_block(100, Some(500), Some(400), Some(350));
        assert_eq!(result, 350);
    }

    #[test]
    fn test_all_sources_present_no_unfinalized() {
        // All except unfinalized, watermark is highest
        let result = compute_start_block(100, Some(500), Some(400), None);
        assert_eq!(result, 501);
    }

    // --------------------------------------------------------------------------
    // Scenario 7: Real-world scenarios
    // --------------------------------------------------------------------------

    #[test]
    fn test_normal_restart_scenario() {
        // Normal restart: watermark updated correctly, no unfinalized
        // Config: 0, Watermark: 14780, Finalized: 14780 -> start from 14781
        let result = compute_start_block(0, Some(14780), Some(14780), None);
        assert_eq!(result, 14781);
    }

    #[test]
    fn test_crash_recovery_scenario() {
        // Crash during sync: some events unfinalized
        // Config: 0, Watermark: 14700, Finalized: 14750, Unfinalized: 14760
        // Should start from 14760 to re-process
        let result = compute_start_block(0, Some(14700), Some(14750), Some(14760));
        assert_eq!(result, 14760);
    }

    #[test]
    fn test_first_sync_after_migration() {
        // First sync with migration: no watermark, but finalized events exist
        // Config: 0, Watermark: None, Finalized: 500 -> start from 501
        let result = compute_start_block(0, None, Some(500), None);
        assert_eq!(result, 501);
    }

    #[test]
    fn test_config_override_scenario() {
        // Operator wants to re-sync from a specific block
        // Config: 10000, Watermark: 5000, Finalized: 5000 -> use config
        let result = compute_start_block(10000, Some(5000), Some(5000), None);
        assert_eq!(result, 10000);
    }

    // --------------------------------------------------------------------------
    // BridgeDataSource tests
    // --------------------------------------------------------------------------

    #[test]
    fn test_bridge_data_source_as_ref() {
        assert_eq!(BridgeDataSource::ETH.as_ref(), "ETH");
        assert_eq!(BridgeDataSource::STARCOIN.as_ref(), "STARCOIN");
    }
}
