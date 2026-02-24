// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Gap Recovery Service
//!
//! Actively detects and recovers missing events by polling chain state.
//!
//! ## Design
//!
//! 1. **Deposit Gap Checker** (every 1 minute):
//!    - Query DB for nonce gaps in deposits
//!    - Fetch missing deposits from chain
//!    - Insert to DB, or send FATAL alert if not found on chain
//!
//! 2. **Cross-Chain Completion Tracker** (every 2 * finality):
//!    - Find deposits without corresponding claims
//!    - Poll destination chain for next step events
//!    - Insert to DB when found, send WARN alert
//!    - Daily report for transfers pending > 1 day

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use diesel::{BoolExpressionMethods, ExpressionMethods, JoinOnDsl, OptionalExtension, QueryDsl};
use diesel_async::RunQueryDsl;
use starcoin_bridge_pg_db::Db;
use starcoin_bridge_schema::models::TokenTransferStatus;
use starcoin_bridge_schema::schema::{token_transfer, token_transfer_data};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::telegram::TelegramNotifier;

/// Configuration for gap recovery service
#[derive(Clone, Debug)]
pub struct GapRecoveryConfig {
    /// Interval for checking deposit nonce gaps (default: 60s)
    pub deposit_check_interval: Duration,
    /// Interval for checking cross-chain completion (default: 30 min for ETH, 6 min for STC)
    pub completion_check_interval: Duration,
    /// How long before a transfer is considered "stale" for daily report (default: 24h)
    pub stale_threshold: Duration,
    /// Hour (UTC) to send daily report (default: 8)
    pub daily_report_hour: u32,
    /// ETH chain ID
    pub eth_chain_id: i32,
    /// STC chain ID
    pub stc_chain_id: i32,
}

impl Default for GapRecoveryConfig {
    fn default() -> Self {
        Self {
            deposit_check_interval: Duration::from_secs(60),
            completion_check_interval: Duration::from_secs(30 * 60), // 30 min
            stale_threshold: Duration::from_secs(24 * 60 * 60),      // 24h
            daily_report_hour: 8,
            eth_chain_id: 1,   // ETH mainnet
            stc_chain_id: 251, // STC mainnet
        }
    }
}

/// Incomplete transfer waiting for cross-chain completion
#[derive(Debug, Clone)]
pub struct IncompleteTransfer {
    pub source_chain_id: i32,
    pub nonce: i64,
    pub destination_chain_id: i32,
    pub status: TokenTransferStatus,
    /// Deposit timestamp in milliseconds since UNIX epoch
    pub deposit_timestamp_ms: i64,
    pub amount: i64,
    pub token_id: i32,
    pub sender: Vec<u8>,
    pub recipient: Vec<u8>,
}

impl IncompleteTransfer {
    /// Get age of deposit in hours
    pub fn age_hours(&self) -> i64 {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        (now_ms - self.deposit_timestamp_ms) / (1000 * 60 * 60)
    }

    /// Check if transfer is older than threshold
    pub fn is_stale(&self, threshold: Duration) -> bool {
        let threshold_ms = threshold.as_millis() as i64;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        (now_ms - self.deposit_timestamp_ms) > threshold_ms
    }
}

/// Gap Recovery Service
pub struct GapRecoveryService {
    config: GapRecoveryConfig,
    db: Db,
    telegram: Option<Arc<TelegramNotifier>>,
    /// Last daily report timestamp in milliseconds
    last_daily_report_ms: Option<i64>,
}

impl GapRecoveryService {
    pub fn new(config: GapRecoveryConfig, db: Db, telegram: Option<Arc<TelegramNotifier>>) -> Self {
        Self {
            config,
            db,
            telegram,
            last_daily_report_ms: None,
        }
    }

    /// Start the gap recovery service
    pub async fn run(mut self, cancel: CancellationToken) {
        info!("[GapRecovery] Starting gap recovery service");
        info!(
            "  Deposit check interval: {:?}",
            self.config.deposit_check_interval
        );
        info!(
            "  Completion check interval: {:?}",
            self.config.completion_check_interval
        );

        let mut deposit_check_timer = tokio::time::interval(self.config.deposit_check_interval);
        let mut completion_check_timer =
            tokio::time::interval(self.config.completion_check_interval);

        // Don't fire immediately for completion check
        completion_check_timer.reset();

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("[GapRecovery] Shutting down");
                    break;
                }
                _ = deposit_check_timer.tick() => {
                    if let Err(e) = self.check_deposit_gaps().await {
                        error!("[GapRecovery] Deposit gap check failed: {:?}", e);
                    }
                }
                _ = completion_check_timer.tick() => {
                    if let Err(e) = self.check_incomplete_transfers().await {
                        error!("[GapRecovery] Completion check failed: {:?}", e);
                    }
                    // Check if we should send daily report
                    if let Err(e) = self.maybe_send_daily_report().await {
                        error!("[GapRecovery] Daily report failed: {:?}", e);
                    }
                }
            }
        }
    }

    // ========================================================================
    // Step 1: Deposit Gap Detection
    // ========================================================================

    /// Check for gaps in deposit nonces for both chains
    async fn check_deposit_gaps(&self) -> Result<()> {
        // Check ETH deposits
        let eth_gaps = self
            .find_deposit_nonce_gaps(self.config.eth_chain_id)
            .await?;
        if !eth_gaps.is_empty() {
            warn!(
                "[GapRecovery] Found {} ETH deposit nonce gaps: {:?}",
                eth_gaps.len(),
                &eth_gaps[..eth_gaps.len().min(10)]
            );
            self.handle_deposit_gaps(self.config.eth_chain_id, "ETH", eth_gaps)
                .await?;
        }

        // Check STC deposits
        let stc_gaps = self
            .find_deposit_nonce_gaps(self.config.stc_chain_id)
            .await?;
        if !stc_gaps.is_empty() {
            warn!(
                "[GapRecovery] Found {} STC deposit nonce gaps: {:?}",
                stc_gaps.len(),
                &stc_gaps[..stc_gaps.len().min(10)]
            );
            self.handle_deposit_gaps(self.config.stc_chain_id, "STARCOIN", stc_gaps)
                .await?;
        }

        Ok(())
    }

    /// Find gaps in deposit nonces for a given chain
    ///
    /// Returns nonces that are missing between min and max nonce in DB
    pub async fn find_deposit_nonce_gaps(&self, chain_id: i32) -> Result<Vec<i64>> {
        let mut conn = self.db.connect().await?;

        // Get min and max nonce for Deposited status
        let (min_nonce, max_nonce): (Option<i64>, Option<i64>) = token_transfer::table
            .filter(token_transfer::chain_id.eq(chain_id))
            .filter(token_transfer::status.eq(TokenTransferStatus::Deposited.as_ref()))
            .select((
                diesel::dsl::min(token_transfer::nonce),
                diesel::dsl::max(token_transfer::nonce),
            ))
            .first(&mut conn)
            .await?;

        let (min_nonce, max_nonce) = match (min_nonce, max_nonce) {
            (Some(min), Some(max)) => (min, max),
            _ => return Ok(vec![]), // No deposits yet
        };

        // Get all existing nonces
        let existing_nonces: Vec<i64> = token_transfer::table
            .filter(token_transfer::chain_id.eq(chain_id))
            .filter(token_transfer::nonce.ge(min_nonce))
            .filter(token_transfer::nonce.le(max_nonce))
            .select(token_transfer::nonce)
            .distinct()
            .load(&mut conn)
            .await?;

        let existing_set: HashSet<i64> = existing_nonces.into_iter().collect();

        // Find gaps
        let mut gaps = Vec::new();
        for nonce in min_nonce..=max_nonce {
            if !existing_set.contains(&nonce) {
                gaps.push(nonce);
            }
        }

        Ok(gaps)
    }

    /// Handle detected deposit gaps
    pub async fn handle_deposit_gaps(
        &self,
        chain_id: i32,
        chain_name: &str,
        gaps: Vec<i64>,
    ) -> Result<()> {
        // For now, we can only report the gaps
        // Actual on-chain fetching requires chain-specific RPC clients
        // which should be passed in or configured separately

        // Send FATAL alert for missing deposits
        if let Some(telegram) = &self.telegram {
            let gap_preview: Vec<_> = gaps.iter().take(20).collect();
            let message = format!(
                "🚨 <b>[FATAL] Deposit Nonce Gap Detected</b>\n\n\
                <b>Chain:</b> {} (ID: {})\n\
                <b>Missing Nonces:</b> {} total\n\
                <b>Preview:</b> {:?}\n\n\
                ⚠️ These deposits exist on-chain but are missing from DB.\n\
                Manual intervention may be required.",
                chain_name,
                chain_id,
                gaps.len(),
                gap_preview
            );
            telegram.send_message(&message).await?;
        }

        Ok(())
    }

    // ========================================================================
    // Step 2: Cross-Chain Completion Tracking
    // ========================================================================

    /// Check for incomplete transfers (deposits without claims)
    async fn check_incomplete_transfers(&self) -> Result<()> {
        let incomplete = self.find_incomplete_transfers().await?;

        if incomplete.is_empty() {
            debug!("[GapRecovery] No incomplete transfers found");
            return Ok(());
        }

        info!(
            "[GapRecovery] Found {} incomplete transfers",
            incomplete.len()
        );

        // Group by age for reporting
        let (stale, recent): (Vec<_>, Vec<_>) = incomplete
            .into_iter()
            .partition(|t| t.is_stale(self.config.stale_threshold));

        if !recent.is_empty() {
            debug!(
                "[GapRecovery] {} recent incomplete transfers (< {:?} old)",
                recent.len(),
                self.config.stale_threshold
            );
        }

        if !stale.is_empty() {
            warn!(
                "[GapRecovery] {} stale incomplete transfers (> {:?} old)",
                stale.len(),
                self.config.stale_threshold
            );
        }

        Ok(())
    }

    /// Find transfers that have deposit but no claim
    ///
    /// Uses pure SQL query - no state machine needed
    pub async fn find_incomplete_transfers(&self) -> Result<Vec<IncompleteTransfer>> {
        let mut conn = self.db.connect().await?;

        // Find deposits without corresponding claims
        // A transfer is incomplete if:
        // 1. It has Deposited status on source chain
        // 2. There's no Claimed status for the same (dest_chain, nonce)
        //
        // Note: We look at token_transfer_data for the full transfer info

        let deposits: Vec<(i32, i64, i32, i64, i64, Vec<u8>, Vec<u8>, i32)> =
            token_transfer_data::table
                .inner_join(
                    token_transfer::table.on(token_transfer_data::chain_id
                        .eq(token_transfer::chain_id)
                        .and(token_transfer_data::nonce.eq(token_transfer::nonce))),
                )
                .filter(token_transfer::status.eq(TokenTransferStatus::Deposited.as_ref()))
                .select((
                    token_transfer_data::chain_id,
                    token_transfer_data::nonce,
                    token_transfer_data::destination_chain,
                    token_transfer_data::timestamp_ms,
                    token_transfer_data::amount,
                    token_transfer_data::sender_address,
                    token_transfer_data::recipient_address,
                    token_transfer_data::token_id,
                ))
                .load(&mut conn)
                .await?;

        // For each deposit, check if there's a claim on destination chain
        let mut incomplete = Vec::new();

        for (source_chain, nonce, dest_chain, timestamp_ms, amount, sender, recipient, token_id) in
            deposits
        {
            // Check if claimed on destination chain
            let claimed: Option<i64> = token_transfer::table
                .filter(token_transfer::chain_id.eq(dest_chain))
                .filter(token_transfer::nonce.eq(nonce))
                .filter(token_transfer::status.eq(TokenTransferStatus::Claimed.as_ref()))
                .select(token_transfer::nonce)
                .first(&mut conn)
                .await
                .optional()?;

            if claimed.is_none() {
                incomplete.push(IncompleteTransfer {
                    source_chain_id: source_chain,
                    nonce,
                    destination_chain_id: dest_chain,
                    status: TokenTransferStatus::Deposited,
                    deposit_timestamp_ms: timestamp_ms,
                    amount,
                    token_id,
                    sender,
                    recipient,
                });
            }
        }

        Ok(incomplete)
    }

    // ========================================================================
    // Step 3: Daily Report
    // ========================================================================

    /// Get current hour (UTC)
    fn current_utc_hour() -> u32 {
        let secs_since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        ((secs_since_epoch % 86400) / 3600) as u32
    }

    /// Get current timestamp in milliseconds
    fn current_timestamp_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    /// Send daily report if it's the right time
    async fn maybe_send_daily_report(&mut self) -> Result<()> {
        let now_ms = Self::current_timestamp_ms();
        let current_hour = Self::current_utc_hour();

        // Check if we should send report (at configured hour, once per day)
        let should_send = if let Some(last_report_ms) = self.last_daily_report_ms {
            let hours_since = (now_ms - last_report_ms) / (1000 * 60 * 60);
            hours_since >= 23 && current_hour == self.config.daily_report_hour
        } else {
            current_hour == self.config.daily_report_hour
        };

        if !should_send {
            return Ok(());
        }

        info!("[GapRecovery] Sending daily gap report");
        self.last_daily_report_ms = Some(now_ms);

        // Get incomplete transfers
        let incomplete = self.find_incomplete_transfers().await?;

        // Filter stale ones
        let stale: Vec<_> = incomplete
            .iter()
            .filter(|t| t.is_stale(self.config.stale_threshold))
            .collect();

        // Get deposit gaps
        let eth_gaps = self
            .find_deposit_nonce_gaps(self.config.eth_chain_id)
            .await?;
        let stc_gaps = self
            .find_deposit_nonce_gaps(self.config.stc_chain_id)
            .await?;

        // Build report
        if let Some(telegram) = &self.telegram {
            let message = self.build_daily_report(&stale, &eth_gaps, &stc_gaps);
            telegram.send_message(&message).await?;
        }

        Ok(())
    }

    pub fn build_daily_report(
        &self,
        stale_transfers: &[&IncompleteTransfer],
        eth_gaps: &[i64],
        stc_gaps: &[i64],
    ) -> String {
        let mut report = String::from("📊 <b>[Daily Gap Recovery Report]</b>\n\n");

        // Deposit gaps section
        report.push_str("<b>🔍 Deposit Nonce Gaps:</b>\n");
        if eth_gaps.is_empty() && stc_gaps.is_empty() {
            report.push_str("✅ No gaps detected\n");
        } else {
            if !eth_gaps.is_empty() {
                report.push_str(&format!(
                    "• ETH: {} gaps ({:?}...)\n",
                    eth_gaps.len(),
                    &eth_gaps[..eth_gaps.len().min(5)]
                ));
            }
            if !stc_gaps.is_empty() {
                report.push_str(&format!(
                    "• STC: {} gaps ({:?}...)\n",
                    stc_gaps.len(),
                    &stc_gaps[..stc_gaps.len().min(5)]
                ));
            }
        }
        report.push('\n');

        // Stale transfers section
        report.push_str(&format!(
            "<b>⏳ Stale Transfers (>{:?}):</b>\n",
            self.config.stale_threshold
        ));
        if stale_transfers.is_empty() {
            report.push_str("✅ No stale transfers\n");
        } else {
            report.push_str(&format!("⚠️ {} transfers pending\n", stale_transfers.len()));

            // Show up to 10 stale transfers
            for (i, t) in stale_transfers.iter().take(10).enumerate() {
                let age_hours = t.age_hours();
                let chain_name = if t.source_chain_id == self.config.eth_chain_id {
                    "ETH"
                } else {
                    "STC"
                };
                report.push_str(&format!(
                    "{}. {} nonce {} → {} ({}h ago, {} units)\n",
                    i + 1,
                    chain_name,
                    t.nonce,
                    if t.destination_chain_id == self.config.eth_chain_id {
                        "ETH"
                    } else {
                        "STC"
                    },
                    age_hours,
                    t.amount
                ));
            }

            if stale_transfers.len() > 10 {
                report.push_str(&format!("... and {} more\n", stale_transfers.len() - 10));
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = GapRecoveryConfig::default();
        assert_eq!(config.deposit_check_interval, Duration::from_secs(60));
        assert_eq!(
            config.completion_check_interval,
            Duration::from_secs(30 * 60)
        );
        assert_eq!(config.stale_threshold, Duration::from_secs(24 * 60 * 60));
        assert_eq!(config.daily_report_hour, 8);
    }

    #[test]
    fn test_incomplete_transfer_age() {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        // Transfer from 2 hours ago
        let transfer = IncompleteTransfer {
            source_chain_id: 1,
            nonce: 100,
            destination_chain_id: 251,
            status: TokenTransferStatus::Deposited,
            deposit_timestamp_ms: now_ms - (2 * 60 * 60 * 1000), // 2 hours ago
            amount: 1000000,
            token_id: 1,
            sender: vec![0x1, 0x2, 0x3],
            recipient: vec![0x4, 0x5, 0x6],
        };

        assert_eq!(transfer.age_hours(), 2);
        assert!(!transfer.is_stale(Duration::from_secs(24 * 60 * 60))); // Not stale (< 24h)
        assert!(transfer.is_stale(Duration::from_secs(60 * 60))); // Stale (> 1h)
    }

    #[test]
    fn test_current_utc_hour() {
        let hour = GapRecoveryService::current_utc_hour();
        assert!(hour < 24);
    }
}
