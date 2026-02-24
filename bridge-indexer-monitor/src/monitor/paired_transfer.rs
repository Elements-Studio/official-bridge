// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Paired transfer detector
//!
//! Detects deposits that have not been claimed within a threshold time
//! and sends alerts via Telegram

use anyhow::Result;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use super::config::PairedMessageConfig;
use super::state::StateManager;
use super::telegram::TelegramNotifier;

pub struct PairedTransferDetector {
    state_manager: Arc<StateManager>,
    config: PairedMessageConfig,
}

impl PairedTransferDetector {
    pub fn new(state_manager: Arc<StateManager>, config: PairedMessageConfig) -> Self {
        Self {
            state_manager,
            config,
        }
    }

    pub async fn run(
        &self,
        telegram: Arc<TelegramNotifier>,
        cancel: CancellationToken,
    ) -> Result<()> {
        info!("[Monitor] Paired transfer detector started");
        info!(
            "[Monitor] Alert threshold: {}s, check interval: {}s",
            self.config.alert_threshold_seconds, self.config.check_interval_seconds
        );

        let mut interval = tokio::time::interval(self.config.check_interval());
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            if cancel.is_cancelled() {
                info!("[Monitor] Paired transfer detector cancelled");
                break;
            }

            interval.tick().await;

            if let Err(e) = self.check_stale_transfers(&telegram).await {
                error!("[Monitor] Error checking stale transfers: {:?}", e);
            }
        }

        Ok(())
    }

    async fn check_stale_transfers(&self, telegram: &Arc<TelegramNotifier>) -> Result<()> {
        let pending_transfers = self.state_manager.get_pending_transfers().await;

        if pending_transfers.is_empty() {
            return Ok(());
        }

        let threshold = self.config.alert_threshold_seconds;
        let mut stale_count = 0;

        for transfer in &pending_transfers {
            let age = transfer.age_seconds();

            if age >= threshold {
                stale_count += 1;
                info!(
                    "[Monitor] Found stale transfer: source_chain={}, nonce={}, age={}s",
                    transfer.source_chain_id, transfer.nonce, age
                );

                // Send alert
                let threshold_human = format_duration(threshold);
                if let Err(e) = telegram
                    .notify_unmatched_transfer(transfer, &threshold_human)
                    .await
                {
                    error!("[Monitor] Failed to send unmatched transfer alert: {:?}", e);
                }
            }
        }

        if stale_count > 0 {
            info!(
                "[Monitor] Found {} stale transfers out of {} pending",
                stale_count,
                pending_transfers.len()
            );
        }

        Ok(())
    }
}

fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86400 {
        format!("{}h", seconds / 3600)
    } else {
        format!("{}d", seconds / 86400)
    }
}
