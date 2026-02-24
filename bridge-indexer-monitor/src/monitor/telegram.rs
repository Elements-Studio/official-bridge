// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Telegram notification sender

use anyhow::Result;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;
use tracing::{info, warn};

use super::config::{get_chain_name, get_token_name, TelegramConfig};
use super::events::*;
use super::state::PendingTransfer;

const MAX_RETRIES: u32 = 3;
const RETRY_DELAY_SECS: u64 = 2;

pub struct TelegramNotifier {
    config: TelegramConfig,
    client: Client,
    api_base: String,
}

impl TelegramNotifier {
    pub fn new(config: TelegramConfig) -> Self {
        let api_base = format!("https://api.telegram.org/bot{}", config.bot_token);
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();

        Self {
            config,
            client,
            api_base,
        }
    }

    pub async fn send_message(&self, text: &str) -> Result<()> {
        if self.config.bot_token.is_empty() || self.config.chat_id.is_empty() {
            info!(
                "Telegram not configured, would send: {}",
                &text[..text.len().min(200)]
            );
            return Ok(());
        }

        for attempt in 0..MAX_RETRIES {
            match self
                .client
                .post(format!("{}/sendMessage", self.api_base))
                .json(&json!({
                    "chat_id": self.config.chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": true,
                }))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => {
                    warn!(
                        "Telegram send attempt {}/{} failed: {}",
                        attempt + 1,
                        MAX_RETRIES,
                        resp.status()
                    );
                }
                Err(e) => {
                    warn!(
                        "Telegram send attempt {}/{} failed: {:?}",
                        attempt + 1,
                        MAX_RETRIES,
                        e
                    );
                }
            }

            if attempt < MAX_RETRIES - 1 {
                tokio::time::sleep(Duration::from_secs(RETRY_DELAY_SECS * (attempt as u64 + 1)))
                    .await;
            }
        }

        warn!(
            "Failed to send Telegram message after {} attempts",
            MAX_RETRIES
        );
        Ok(())
    }

    fn build_mention_text(&self) -> String {
        if self.config.emergency_mention_users.is_empty() {
            return String::new();
        }

        let mentions: Vec<String> = self
            .config
            .emergency_mention_users
            .iter()
            .map(|user| {
                let user = user.trim();
                if user.chars().all(|c| c.is_ascii_digit()) {
                    format!(r#"<a href="tg://user?id={}">{}</a>"#, user, user)
                } else {
                    format!("@{}", user.trim_start_matches('@'))
                }
            })
            .collect();

        format!("🔔 {}\n\n", mentions.join(" "))
    }

    fn truncate_addr(addr: &str) -> String {
        if addr.len() > 20 {
            format!("{}...{}", &addr[..10], &addr[addr.len() - 8..])
        } else {
            addr.to_string()
        }
    }

    pub async fn notify_startup(
        &self,
        chain_a_name: &str,
        chain_b_name: &str,
        chain_a_contract: &str,
        chain_b_contract: &str,
    ) -> Result<()> {
        let message = format!(
            "<b>[Starcoin Bridge]</b> ℹ️\n\
            🚀 <b>Bridge Monitor Started</b>\n\n\
            <b>Monitoring:</b>\n\
            • {}: <code>{}</code>\n\
            • {}: <code>{}</code>",
            chain_a_name,
            Self::truncate_addr(chain_a_contract),
            chain_b_name,
            Self::truncate_addr(chain_b_contract)
        );
        self.send_message(&message).await
    }

    pub async fn notify_tokens_deposited(
        &self,
        event: &TokensDepositedEvent,
        chain_name: &str,
        contract_addr: &str,
        remaining_limit: Option<(u64, u64)>,
    ) -> Result<()> {
        let source_chain = get_chain_name(event.source_chain_id);
        let dest_chain = get_chain_name(event.destination_chain_id);
        let token = get_token_name(event.token_id);

        let limit_info = if let Some((remaining, total)) = remaining_limit {
            if total > 0 {
                let percentage = (remaining as f64 / total as f64) * 100.0;
                let indicator = if percentage > 50.0 {
                    "✅"
                } else if percentage >= 20.0 {
                    "⚠️"
                } else {
                    "🔴"
                };
                format!(
                    "<b>Remaining Limit:</b> {:.2} USDT {} ({:.0}% remaining)\n",
                    remaining as f64 / 1e8,
                    indicator,
                    percentage
                )
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let message = format!(
            "<b>[Starcoin Bridge]</b> 📋\n\
            🌉 <b>Bridge Transfer Initiated</b>\n\n\
            <b>Type:</b> Normal\n\
            <b>Chain:</b> {} (ID: {})\n\
            <b>Contract:</b> <code>{}</code>\n\
            <b>Direction:</b> {} → {}\n\
            <b>Token:</b> {}\n\
            <b>Amount:</b> {}\n\
            <b>Nonce:</b> {}\n\
            <b>From:</b> <code>{}</code>\n\
            <b>To:</b> <code>{}</code>\n\
            {}\n\
            <b>Tx:</b> <code>{}</code>\n\
            <b>Block:</b> {}",
            chain_name,
            event.source_chain_id,
            Self::truncate_addr(contract_addr),
            source_chain,
            dest_chain,
            token,
            event.amount_human(),
            event.nonce,
            Self::truncate_addr(&event.sender_address),
            Self::truncate_addr(&event.recipient_address),
            limit_info,
            event.tx_hash,
            event.block_number
        );
        self.send_message(&message).await
    }

    pub async fn notify_tokens_claimed(
        &self,
        event: &TokensClaimedEvent,
        chain_name: &str,
        contract_addr: &str,
    ) -> Result<()> {
        let source_chain = get_chain_name(event.source_chain_id);
        let dest_chain = get_chain_name(event.destination_chain_id);
        let token = get_token_name(event.token_id);

        let message = format!(
            "<b>[Starcoin Bridge]</b> 📋\n\
            ✅ <b>Bridge Transfer Completed</b>\n\n\
            <b>Type:</b> Normal\n\
            <b>Chain:</b> {}\n\
            <b>Contract:</b> <code>{}</code>\n\
            <b>Direction:</b> {} → {}\n\
            <b>Token:</b> {}\n\
            <b>Amount:</b> {}\n\
            <b>Nonce:</b> {}\n\
            <b>Recipient:</b> <code>{}</code>\n\n\
            <b>Tx:</b> <code>{}</code>\n\
            <b>Block:</b> {}",
            chain_name,
            Self::truncate_addr(contract_addr),
            source_chain,
            dest_chain,
            token,
            event.amount_human(),
            event.nonce,
            Self::truncate_addr(&event.recipient_address),
            event.tx_hash,
            event.block_number
        );
        self.send_message(&message).await
    }

    pub async fn notify_emergency_op(
        &self,
        event: &EmergencyOpEvent,
        chain_name: &str,
        contract_addr: &str,
    ) -> Result<()> {
        let status = if event.paused {
            "🛑 PAUSED"
        } else {
            "▶️ RESUMED"
        };
        let mentions = self.build_mention_text();

        let message = format!(
            "{}<b>[Starcoin Bridge]</b> 🚨 EMERGENCY\n\
            ⚠️ <b>EMERGENCY OPERATION</b>\n\n\
            <b>Type:</b> 🚨 EMERGENCY\n\
            <b>Chain:</b> {}\n\
            <b>Contract:</b> <code>{}</code>\n\
            <b>Status:</b> {}\n\
            <b>Nonce:</b> {}\n\n\
            <b>Tx:</b> <code>{}</code>\n\
            <b>Block:</b> {}\n\n\
            ⚠️ <i>Immediate attention required!</i>",
            mentions,
            chain_name,
            Self::truncate_addr(contract_addr),
            status,
            event.nonce,
            event.tx_hash,
            event.block_number
        );
        self.send_message(&message).await
    }

    pub async fn notify_limit_updated(
        &self,
        event: &LimitUpdatedEvent,
        chain_name: &str,
        contract_addr: &str,
    ) -> Result<()> {
        let source_chain = get_chain_name(event.source_chain_id);

        let message = format!(
            "<b>[Starcoin Bridge]</b> ℹ️\n\
            📊 <b>Bridge Limit Updated</b>\n\n\
            <b>Type:</b> Governance\n\
            <b>Chain:</b> {}\n\
            <b>Contract:</b> <code>{}</code>\n\
            <b>Source Chain:</b> {} (ID: {})\n\
            <b>New Limit:</b> {}\n\
            <b>Nonce:</b> {}\n\n\
            <b>Tx:</b> <code>{}</code>\n\
            <b>Block:</b> {}",
            chain_name,
            Self::truncate_addr(contract_addr),
            source_chain,
            event.source_chain_id,
            event.limit_human(),
            event.nonce,
            event.tx_hash,
            event.block_number
        );
        self.send_message(&message).await
    }

    pub async fn notify_blocklist_updated(
        &self,
        event: &BlocklistUpdatedEvent,
        chain_name: &str,
        contract_addr: &str,
    ) -> Result<()> {
        let action_emoji = if event.is_blocklisted { "🚫" } else { "✅" };
        let action_text = if event.is_blocklisted {
            "BLOCKED"
        } else {
            "UNBLOCKED"
        };
        let mentions = if event.is_blocklisted {
            self.build_mention_text()
        } else {
            String::new()
        };

        let members_text: Vec<String> = event
            .members
            .iter()
            .take(5)
            .map(|m| format!("• <code>{}</code>", Self::truncate_addr(m)))
            .collect();
        let mut members_display = members_text.join("\n");
        if event.members.len() > 5 {
            members_display.push_str(&format!("\n• ... and {} more", event.members.len() - 5));
        }

        let message = format!(
            "{}<b>[Starcoin Bridge]</b> {}\n\
            {} <b>Committee Member {}</b>\n\n\
            <b>Type:</b> Governance\n\
            <b>Chain:</b> {}\n\
            <b>Contract:</b> <code>{}</code>\n\
            <b>Action:</b> {}\n\
            <b>Members:</b>\n{}\n\n\
            <b>Tx:</b> <code>{}</code>\n\
            <b>Block:</b> {}",
            mentions,
            if event.is_blocklisted {
                "🚨 EMERGENCY"
            } else {
                "ℹ️"
            },
            action_emoji,
            action_text,
            chain_name,
            Self::truncate_addr(contract_addr),
            action_text,
            members_display,
            event.tx_hash,
            event.block_number
        );
        self.send_message(&message).await
    }

    pub async fn notify_committee_updated(
        &self,
        event: &CommitteeUpdateEvent,
        chain_name: &str,
        contract_addr: &str,
    ) -> Result<()> {
        let message = format!(
            "<b>[Starcoin Bridge]</b> ℹ️\n\
            👥 <b>Committee Updated</b>\n\n\
            <b>Type:</b> Governance\n\
            <b>Chain:</b> {}\n\
            <b>Contract:</b> <code>{}</code>\n\
            <b>Members Updated:</b> {}\n\n\
            <b>Tx:</b> <code>{}</code>\n\
            <b>Block:</b> {}",
            chain_name,
            Self::truncate_addr(contract_addr),
            event.member_count,
            event.tx_hash,
            event.block_number
        );
        self.send_message(&message).await
    }

    pub async fn notify_error(
        &self,
        error: &str,
        chain_name: &str,
        contract_addr: &str,
    ) -> Result<()> {
        let mentions = self.build_mention_text();
        let message = format!(
            "{}<b>[Starcoin Bridge]</b> 🚨 EMERGENCY\n\
            ❌ <b>Monitor Error</b>\n\n\
            <b>Type:</b> 🚨 EMERGENCY\n\
            <b>Chain:</b> {}\n\
            <b>Contract:</b> <code>{}</code>\n\
            <b>Error:</b> {}",
            mentions,
            chain_name,
            Self::truncate_addr(contract_addr),
            error
        );
        self.send_message(&message).await
    }

    pub async fn notify_unmatched_transfer(
        &self,
        transfer: &PendingTransfer,
        threshold_human: &str,
    ) -> Result<()> {
        let source_chain = get_chain_name(transfer.source_chain_id);
        let dest_chain = get_chain_name(transfer.destination_chain_id);
        let token = get_token_name(transfer.token_id);
        let amount_human = format!("{:.4}", transfer.amount as f64 / 1e8);
        let mentions = self.build_mention_text();

        let message = format!(
            "{}<b>[Starcoin Bridge]</b> 🚨 EMERGENCY\n\
            ⚠️ <b>UNMATCHED TRANSFER ALERT</b>\n\n\
            Transfer deposited but not claimed after {}:\n\n\
            <b>Direction:</b> {} → {}\n\
            <b>Nonce:</b> {}\n\
            <b>Token:</b> {}\n\
            <b>Amount:</b> {}\n\
            <b>From:</b> <code>{}</code>\n\
            <b>To:</b> <code>{}</code>\n\n\
            <b>Deposit TX:</b> <code>{}</code>\n\
            <b>Deposit Block:</b> {}\n\
            <b>Age:</b> {}\n\n\
            ⚠️ <i>Please investigate!</i>",
            mentions,
            threshold_human,
            source_chain,
            dest_chain,
            transfer.nonce,
            token,
            amount_human,
            Self::truncate_addr(&transfer.sender_address),
            Self::truncate_addr(&transfer.recipient_address),
            transfer.deposit_tx,
            transfer.deposit_block,
            transfer.age_human()
        );
        self.send_message(&message).await
    }

    // Validator health notifications
    pub async fn notify_validator_down(
        &self,
        validator_name: &str,
        validator_url: &str,
        consecutive_failures: u32,
    ) -> Result<()> {
        let mentions = self.build_mention_text();

        let message = format!(
            "{}<b>[Bridge Validator]</b> 🔴 OFFLINE\n\
            ⚠️ <b>VALIDATOR DOWN</b>\n\n\
            <b>Validator:</b> {}\n\
            <b>URL:</b> <code>{}</code>\n\
            <b>Consecutive Failures:</b> {}\n\n\
            🔍 <i>Checking every minute...</i>",
            mentions, validator_name, validator_url, consecutive_failures
        );
        self.send_message(&message).await
    }

    pub async fn notify_validator_recovered(
        &self,
        validator_name: &str,
        validator_url: &str,
        downtime: &str,
    ) -> Result<()> {
        let message = format!(
            "<b>[Bridge Validator]</b> ✅ RECOVERED\n\
            🟢 <b>VALIDATOR ONLINE</b>\n\n\
            <b>Validator:</b> {}\n\
            <b>URL:</b> <code>{}</code>\n\
            <b>Downtime:</b> {}\n\n\
            ✨ <i>Service restored!</i>",
            validator_name, validator_url, downtime
        );
        self.send_message(&message).await
    }

    pub async fn notify_validator_still_down(
        &self,
        validator_name: &str,
        validator_url: &str,
        downtime: &str,
        consecutive_failures: u32,
    ) -> Result<()> {
        let mentions = self.build_mention_text();

        let message = format!(
            "{}<b>[Bridge Validator]</b> 🔴 STILL OFFLINE\n\
            ⏰ <b>HOURLY REMINDER</b>\n\n\
            <b>Validator:</b> {}\n\
            <b>URL:</b> <code>{}</code>\n\
            <b>Downtime:</b> {}\n\
            <b>Failed Checks:</b> {}\n\n\
            ⚠️ <i>Still investigating...</i>",
            mentions, validator_name, validator_url, downtime, consecutive_failures
        );
        self.send_message(&message).await
    }

    /// Send emergency pause alert (critical priority)
    pub async fn send_emergency_pause_alert(
        &self,
        suspicious_chain: u8,
        suspicious_nonce: u64,
        reason: &str,
    ) -> Result<()> {
        let mentions = self.build_mention_text();
        let chain_name = get_chain_name(suspicious_chain);

        // Format current time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let time_str = format!("Unix: {}", now);

        let message = format!(
            "{}<b>🚨🚨🚨 EMERGENCY PAUSE TRIGGERED 🚨🚨🚨</b>\n\n\
            <b>⚠️ CRITICAL SECURITY ALERT</b>\n\n\
            <b>Reason:</b> {}\n\
            <b>Suspicious Chain:</b> {} (ID: {})\n\
            <b>Event Nonce:</b> {}\n\n\
            <b>Detected Issue:</b>\n\
            • Unauthorized minting detected\n\
            • Possible private key compromise\n\
            • Bridge pause initiated\n\n\
            <b>🔴 IMMEDIATE ACTION REQUIRED:</b>\n\
            1. Verify the security incident\n\
            2. Check validator key security\n\
            3. Review recent transactions\n\
            4. Prepare for emergency procedures\n\n\
            <i>⏰ Time: {}</i>",
            mentions, reason, chain_name, suspicious_chain, suspicious_nonce, time_str
        );

        self.send_message(&message).await
    }

    /// Send emergency pause execution status
    pub async fn send_pause_execution_status(
        &self,
        eth_success: bool,
        starcoin_success: bool,
        error_message: Option<&str>,
    ) -> Result<()> {
        let mentions = self.build_mention_text();

        let eth_status = if eth_success {
            "✅ Success"
        } else {
            "❌ Failed"
        };
        let stc_status = if starcoin_success {
            "✅ Success"
        } else {
            "❌ Failed"
        };

        let mut message = format!(
            "{}<b>[Emergency Pause Execution]</b>\n\n\
            <b>ETH Chain:</b> {}\n\
            <b>Starcoin Chain:</b> {}\n\n",
            mentions, eth_status, stc_status
        );

        if let Some(error) = error_message {
            message.push_str(&format!("<b>Error:</b> <code>{}</code>\n\n", error));
        }

        if !eth_success || !starcoin_success {
            message.push_str(
                "<b>⚠️ MANUAL INTERVENTION REQUIRED</b>\n\
                Please execute pause manually on failed chain(s)!",
            );
        } else {
            message.push_str("✅ <i>Both chains paused successfully</i>");
        }

        self.send_message(&message).await
    }

    /// Send reorg detection notification
    pub async fn notify_reorg_detected(
        &self,
        chain_name: &str,
        block_number: u64,
        tx_hash: &str,
        event_type: &str,
        amount: Option<&str>,
        nonce: Option<u64>,
        reason: &str,
    ) -> Result<()> {
        let mentions = self.build_mention_text();

        let mut message = format!(
            "{}<b>[Starcoin Bridge]</b> ⚠️\n\
            🔄 <b>CHAIN REORGANIZATION DETECTED</b>\n\n\
            <b>Chain:</b> {}\n\
            <b>Block:</b> {}\n\
            <b>Event:</b> {}\n\
            <b>Tx:</b> <code>{}</code>\n",
            mentions,
            chain_name,
            block_number,
            event_type,
            Self::truncate_addr(tx_hash),
        );

        if let Some(amt) = amount {
            message.push_str(&format!("<b>Amount:</b> {}\n", amt));
        }
        if let Some(n) = nonce {
            message.push_str(&format!("<b>Nonce:</b> {}\n", n));
        }

        message.push_str(&format!(
            "\n<b>Reason:</b> {}\n\n\
            ⚠️ <i>Previously sent notification for this event may be INVALID.</i>\n\
            <i>Please verify the transaction status on chain explorer.</i>",
            reason
        ));

        self.send_message(&message).await
    }

    /// Send CRITICAL alert when reorg affects finalized data
    /// This should never happen in normal operation and indicates a serious issue
    pub async fn notify_finalized_reorg_conflict(
        &self,
        chain_name: &str,
        block_number: u64,
        tx_hash: &str,
        chain_id: i32,
        nonce: u64,
    ) -> Result<()> {
        let mentions = self.build_mention_text();

        let message = format!(
            "{}<b>[Starcoin Bridge]</b> 🚨🚨🚨\n\
            <b>CRITICAL: FINALIZED DATA REORG CONFLICT</b>\n\n\
            ⚠️ <b>A chain reorganization is attempting to invalidate\n\
            data that was already marked as FINALIZED!</b>\n\n\
            <b>Chain:</b> {}\n\
            <b>Block:</b> {}\n\
            <b>Chain ID:</b> {}\n\
            <b>Nonce:</b> {}\n\
            <b>Tx:</b> <code>{}</code>\n\n\
            🔴 <b>ACTION REQUIRED:</b>\n\
            • This record was NOT deleted from database\n\
            • Manual investigation is REQUIRED\n\
            • Check if the finalized syncer is misconfigured\n\
            • Verify the finality depth settings\n\n\
            ⚠️ <i>This alert indicates a potential configuration issue\n\
            or an extremely deep chain reorganization.</i>",
            mentions,
            chain_name,
            block_number,
            chain_id,
            nonce,
            Self::truncate_addr(tx_hash),
        );

        self.send_message(&message).await
    }
}
