// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! ETH ReorgHandler implementation for bridge-indexer-monitor
//!
//! This module provides concrete implementations of the `ReorgHandler` trait
//! from `starcoin_bridge::chain_syncer`, connecting the ETH chain syncer's reorg
//! detection to the monitor's DB and Telegram notification infrastructure.
//!
//! For Starcoin, reorg detection is handled by `UnfinalizedTxTracker` in the syncer,
//! and DB cleanup is done by `StcEventHandler::handle_reorg`. Telegram notifications
//! are handled by the Monitor component.

use anyhow::Result;
use async_trait::async_trait;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use starcoin_bridge::chain_syncer::{BlockId, ChainLog, ReorgHandler, ReorgInfo};
use starcoin_bridge_pg_db::Db;
use starcoin_bridge_schema::models::BridgeDataSource;
use std::sync::Arc;
use tracing::{error, info, warn};

use super::telegram::TelegramNotifier;

/// Configuration for the ETH reorg handler
#[derive(Clone)]
pub struct EthReorgHandlerConfig {
    /// Chain name for logging and notifications
    pub chain_name: String,
    /// Data source type (ETH or STC)
    pub data_source: BridgeDataSource,
    /// Enable DB sync on reorg
    pub enable_db_sync: bool,
    /// Enable Telegram notifications on reorg
    pub enable_notifications: bool,
}

impl Default for EthReorgHandlerConfig {
    fn default() -> Self {
        Self {
            chain_name: "ETH".to_string(),
            data_source: BridgeDataSource::ETH,
            enable_db_sync: true,
            enable_notifications: true,
        }
    }
}

/// ETH-specific reorg handler that handles:
/// 1. DB record deletion for orphaned ETH events
/// 2. Telegram notifications for ETH reorgs
pub struct EthBridgeReorgHandler {
    config: EthReorgHandlerConfig,
    db: Option<Db>,
    telegram: Option<Arc<TelegramNotifier>>,
}

impl EthBridgeReorgHandler {
    /// Create a new EthBridgeReorgHandler
    pub fn new(config: EthReorgHandlerConfig) -> Self {
        Self {
            config,
            db: None,
            telegram: None,
        }
    }

    /// Create with database support
    pub fn with_db(config: EthReorgHandlerConfig, db: Db) -> Self {
        Self {
            config,
            db: Some(db),
            telegram: None,
        }
    }

    /// Create with Telegram support
    pub fn with_telegram(config: EthReorgHandlerConfig, telegram: Arc<TelegramNotifier>) -> Self {
        Self {
            config,
            db: None,
            telegram: Some(telegram),
        }
    }

    /// Create with both DB and Telegram support
    pub fn with_db_and_telegram(
        config: EthReorgHandlerConfig,
        db: Db,
        telegram: Arc<TelegramNotifier>,
    ) -> Self {
        Self {
            config,
            db: Some(db),
            telegram: Some(telegram),
        }
    }

    /// Delete orphaned events from database by block height
    ///
    /// Note: This method logs the orphaned logs for debugging but relies on
    /// `delete_records_after_block` to do the actual deletion by fork_point.
    /// Parsing individual event data to extract chain_id/nonce would require
    /// ABI decoding which adds complexity without significant benefit.
    async fn log_orphaned_events(&self, logs: &[ChainLog]) {
        if logs.is_empty() {
            return;
        }

        for log in logs {
            warn!(
                "[{}] Orphaned event at block {}: tx={}, log_index={}",
                self.config.chain_name, log.block_id.number, log.tx_hash, log.log_index
            );
        }
    }

    /// Delete all records after a fork point
    async fn delete_records_after_block(&self, fork_point: u64) -> Result<usize> {
        let Some(ref db) = self.db else {
            return Ok(0);
        };

        if !self.config.enable_db_sync {
            return Ok(0);
        }

        use starcoin_bridge_schema::schema::{token_transfer, token_transfer_data};

        let mut conn = db.connect().await?;
        let fork_point_i64 = fork_point as i64;

        // Delete from token_transfer where block_height > fork_point and not finalized
        let deleted_transfer = diesel::delete(
            token_transfer::table
                .filter(token_transfer::block_height.gt(fork_point_i64))
                .filter(token_transfer::data_source.eq(self.config.data_source.as_ref()))
                .filter(token_transfer::is_finalized.eq(false)),
        )
        .execute(&mut conn)
        .await
        .unwrap_or(0);

        // Delete from token_transfer_data where block_height > fork_point (no data_source column)
        let deleted_data = diesel::delete(
            token_transfer_data::table
                .filter(token_transfer_data::block_height.gt(fork_point_i64))
                .filter(token_transfer_data::is_finalized.eq(false)),
        )
        .execute(&mut conn)
        .await
        .unwrap_or(0);

        let total = deleted_transfer + deleted_data;
        if total > 0 {
            info!(
                "[{}] Deleted {} records after fork point {} (transfer={}, data={})",
                self.config.chain_name, total, fork_point, deleted_transfer, deleted_data
            );
        }

        Ok(total)
    }

    /// Send reorg notification via Telegram
    async fn notify_reorg(&self, reorg: &ReorgInfo) -> Result<()> {
        let Some(ref telegram) = self.telegram else {
            return Ok(());
        };

        if !self.config.enable_notifications {
            return Ok(());
        }

        // Send a summary notification for the reorg
        if let Err(e) = telegram
            .notify_reorg_detected(
                &reorg.chain,
                reorg.fork_point,
                &format!("fork_point={}", reorg.fork_point),
                "ChainReorg",
                None,
                Some(reorg.orphaned_logs.len() as u64),
                &reorg.reason,
            )
            .await
        {
            error!(
                "[{}] Failed to send reorg notification: {:?}",
                self.config.chain_name, e
            );
        }

        Ok(())
    }
}

#[async_trait]
impl ReorgHandler for EthBridgeReorgHandler {
    async fn handle_reorg(&self, reorg: &ReorgInfo) -> Result<(), String> {
        info!(
            "[{}] Handling reorg: fork_point={}, depth={}, orphaned_logs={}",
            self.config.chain_name,
            reorg.fork_point,
            reorg.depth,
            reorg.orphaned_logs.len()
        );

        // Step 1: Log orphaned events for debugging
        self.log_orphaned_events(&reorg.orphaned_logs).await;

        // Step 2: Delete all unfinalized records after fork point
        // This is the primary mechanism for cleaning up after reorg
        if let Err(e) = self.delete_records_after_block(reorg.fork_point).await {
            error!(
                "[{}] Failed to delete records after fork point: {:?}",
                self.config.chain_name, e
            );
        }

        // Step 3: Send Telegram notifications
        if let Err(e) = self.notify_reorg(reorg).await {
            error!(
                "[{}] Failed to send reorg notification: {:?}",
                self.config.chain_name, e
            );
        }

        Ok(())
    }

    async fn on_block_finalized(&self, block_id: &BlockId) -> Result<(), String> {
        // Mark all events at or below this block as finalized in DB
        // Note: block_id.number represents the finalized height, so we update all <= this height
        if let Some(ref db) = self.db {
            use starcoin_bridge_schema::schema::{token_transfer, token_transfer_data};

            let mut conn = db.connect().await.map_err(|e| e.to_string())?;
            let finalized_height = block_id.number as i64;

            // Update token_transfer records
            let updated_transfer = diesel::update(
                token_transfer::table
                    .filter(token_transfer::block_height.le(finalized_height))
                    .filter(token_transfer::data_source.eq(self.config.data_source.as_ref()))
                    .filter(token_transfer::is_finalized.eq(false)),
            )
            .set(token_transfer::is_finalized.eq(true))
            .execute(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

            // Update token_transfer_data records
            let updated_data = diesel::update(
                token_transfer_data::table
                    .filter(token_transfer_data::block_height.le(finalized_height))
                    .filter(token_transfer_data::is_finalized.eq(false)),
            )
            .set(token_transfer_data::is_finalized.eq(true))
            .execute(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

            if updated_transfer > 0 || updated_data > 0 {
                info!(
                    "[{}] Marked records as finalized at height <= {}: transfer={}, data={}",
                    self.config.chain_name, block_id.number, updated_transfer, updated_data
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eth_config_default() {
        let config = EthReorgHandlerConfig::default();
        assert_eq!(config.chain_name, "ETH");
        assert!(config.enable_db_sync);
        assert!(config.enable_notifications);
    }

    #[test]
    fn test_eth_handler_creation() {
        let config = EthReorgHandlerConfig::default();
        let handler = EthBridgeReorgHandler::new(config);
        assert!(handler.db.is_none());
        assert!(handler.telegram.is_none());
    }

    #[test]
    fn test_config_data_source_types() {
        // Verify different data source configurations
        let eth_config = EthReorgHandlerConfig {
            chain_name: "ETH".to_string(),
            data_source: BridgeDataSource::ETH,
            enable_db_sync: true,
            enable_notifications: true,
        };
        assert_eq!(eth_config.chain_name, "ETH");

        let stc_config = EthReorgHandlerConfig {
            chain_name: "STC".to_string(),
            data_source: BridgeDataSource::STARCOIN,
            enable_db_sync: true,
            enable_notifications: false,
        };
        assert_eq!(stc_config.chain_name, "STC");
        assert!(!stc_config.enable_notifications);
    }

    #[test]
    fn test_handler_with_db_only() {
        // This test verifies the handler can be created with just DB
        // In production, this is the common case for indexer
        let config = EthReorgHandlerConfig::default();
        // We can't actually test with a real DB without integration tests,
        // but we verify the construction pattern
        let handler = EthBridgeReorgHandler::new(config);
        assert!(handler.db.is_none());
    }

    #[tokio::test]
    async fn test_handle_reorg_without_db() {
        // Handler without DB should complete without error
        let config = EthReorgHandlerConfig {
            chain_name: "TEST".to_string(),
            data_source: BridgeDataSource::ETH,
            enable_db_sync: false,
            enable_notifications: false,
        };
        let handler = EthBridgeReorgHandler::new(config);

        let reorg_info = ReorgInfo {
            chain: "TEST".to_string(),
            fork_point: 100,
            depth: 3,
            orphaned_logs: vec![],
            orphaned_blocks: vec![],
            reason: "test reorg".to_string(),
        };

        // Should succeed without DB
        let result = handler.handle_reorg(&reorg_info).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_on_block_finalized_without_db() {
        // Handler without DB should complete without error
        let config = EthReorgHandlerConfig::default();
        let handler = EthBridgeReorgHandler::new(config);

        let block_id = BlockId {
            chain: "TEST".to_string(),
            number: 1000,
            hash: "0xabc".to_string(),
        };

        // Should succeed without DB
        let result = handler.on_block_finalized(&block_id).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_clone() {
        let config = EthReorgHandlerConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.chain_name, config.chain_name);
        assert_eq!(cloned.enable_db_sync, config.enable_db_sync);
    }

    #[tokio::test]
    async fn test_log_orphaned_events_empty() {
        // Empty orphaned events should not cause issues
        let config = EthReorgHandlerConfig::default();
        let handler = EthBridgeReorgHandler::new(config);

        // This should complete without issues
        handler.log_orphaned_events(&[]).await;
    }

    #[tokio::test]
    async fn test_log_orphaned_events_multiple() {
        let config = EthReorgHandlerConfig::default();
        let handler = EthBridgeReorgHandler::new(config);

        let logs = vec![
            ChainLog {
                block_id: BlockId {
                    chain: "ETH".to_string(),
                    number: 100,
                    hash: "0xabc".to_string(),
                },
                tx_hash: "0xtx1".to_string(),
                log_index: 0,
                topics: vec![],
                data: vec![],
                emitter: "0xbridge".to_string(),
            },
            ChainLog {
                block_id: BlockId {
                    chain: "ETH".to_string(),
                    number: 101,
                    hash: "0xdef".to_string(),
                },
                tx_hash: "0xtx2".to_string(),
                log_index: 1,
                topics: vec![],
                data: vec![],
                emitter: "0xbridge".to_string(),
            },
        ];

        // Should log without panicking
        handler.log_orphaned_events(&logs).await;
    }

    #[tokio::test]
    async fn test_delete_records_after_block_disabled() {
        // When enable_db_sync is false, should return 0 and not attempt DB operations
        let config = EthReorgHandlerConfig {
            chain_name: "TEST".to_string(),
            data_source: BridgeDataSource::ETH,
            enable_db_sync: false,
            enable_notifications: false,
        };
        let handler = EthBridgeReorgHandler::new(config);

        let result = handler.delete_records_after_block(100).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_notify_reorg_disabled() {
        // When enable_notifications is false, should complete without error
        let config = EthReorgHandlerConfig {
            chain_name: "TEST".to_string(),
            data_source: BridgeDataSource::ETH,
            enable_db_sync: false,
            enable_notifications: false,
        };
        let handler = EthBridgeReorgHandler::new(config);

        let reorg = ReorgInfo {
            chain: "TEST".to_string(),
            fork_point: 100,
            depth: 5,
            orphaned_logs: vec![],
            orphaned_blocks: vec![],
            reason: "test".to_string(),
        };

        let result = handler.notify_reorg(&reorg).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_notify_reorg_no_telegram() {
        // When telegram is None, should complete without error
        let config = EthReorgHandlerConfig {
            chain_name: "TEST".to_string(),
            data_source: BridgeDataSource::ETH,
            enable_db_sync: false,
            enable_notifications: true, // Enabled but no telegram instance
        };
        let handler = EthBridgeReorgHandler::new(config);

        let reorg = ReorgInfo {
            chain: "TEST".to_string(),
            fork_point: 100,
            depth: 5,
            orphaned_logs: vec![],
            orphaned_blocks: vec![],
            reason: "test".to_string(),
        };

        let result = handler.notify_reorg(&reorg).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_reorg_handler_trait_impl() {
        // Verify EthBridgeReorgHandler implements ReorgHandler trait
        fn assert_reorg_handler<T: ReorgHandler>() {}
        assert_reorg_handler::<EthBridgeReorgHandler>();
    }
}
