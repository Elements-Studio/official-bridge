// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Telegram Notification Module
//!
//! This module provides real-time Telegram notifications for bridge events.
//! It is designed to be called directly from syncers when events occur,
//! without any intermediate buffering or event broadcasting.
//!
//! ## Usage Pattern
//!
//! ```text
//!   EthSyncer/StcSyncer
//!         │
//!         ├─► Pending Event ──► TelegramNotifier.notify_pending()
//!         │
//!         └─► Finalized Event ──► TelegramNotifier.notify_finalized()
//! ```

use anyhow::Result;
use reqwest::Client;
use serde_json::json;
use starcoin_bridge::pending_events::TransferRecord;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::api::get_global_quota_cache;
use crate::network::NetworkType;

const MAX_RETRIES: u32 = 3;
const RETRY_DELAY_SECS: u64 = 2;

/// Structured bridge environment info for Telegram footers
#[derive(Debug, Clone, Default)]
pub struct BridgeEnvInfo {
    pub eth_chain_name: String,
    pub eth_chain_id: u8,
    pub eth_contract: String,
    pub stc_chain_name: String,
    pub stc_chain_id: u8,
    pub stc_contract: String,
}

/// Telegram notification configuration
#[derive(Debug, Clone, Default)]
pub struct TelegramConfig {
    pub bot_token: String,
    pub chat_id: String,
    pub emergency_mention_users: Vec<String>,
    /// Structured bridge environment info for footer
    pub bridge_env: BridgeEnvInfo,
}

impl TelegramConfig {
    pub fn is_configured(&self) -> bool {
        !self.bot_token.is_empty() && !self.chat_id.is_empty()
    }
}

/// Chain identifier for notifications
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyChain {
    Eth,
    Starcoin,
}

impl NotifyChain {
    pub fn name(&self) -> &'static str {
        match self {
            NotifyChain::Eth => "Ethereum",
            NotifyChain::Starcoin => "Starcoin",
        }
    }
}

/// Bridge event for notification
#[derive(Debug, Clone)]
pub enum BridgeNotifyEvent {
    /// Token deposit on source chain
    Deposit {
        source_chain_id: u8,
        destination_chain_id: u8,
        nonce: u64,
        token_id: u8,
        amount: u64,
        sender_address: String,
        recipient_address: String,
        tx_hash: String,
        block_number: u64,
    },
    /// Token claim on destination chain
    Claim {
        source_chain_id: u8,
        destination_chain_id: u8,
        nonce: u64,
        token_id: u8,
        amount: u64,
        recipient_address: String,
        tx_hash: String,
        block_number: u64,
    },
    /// Emergency operation (pause/unpause)
    Emergency {
        paused: bool,
        nonce: u64,
        tx_hash: String,
        block_number: u64,
    },
    /// Bridge limit updated
    LimitUpdated {
        source_chain_id: u8,
        new_limit: u64,
        nonce: u64,
        tx_hash: String,
        block_number: u64,
    },
    /// Committee blocklist updated
    BlocklistUpdated {
        members: Vec<String>,
        is_blocklisted: bool,
        nonce: u64,
        tx_hash: String,
        block_number: u64,
    },
    /// Token transfer approved (committee signature)
    Approval {
        source_chain_id: u8,
        destination_chain_id: u8,
        nonce: u64,
        token_id: u8,
        amount: u64,
        recipient_address: String,
        tx_hash: String,
        block_number: u64,
    },
}

impl BridgeNotifyEvent {
    /// Get unique event ID for logging
    pub fn event_id(&self) -> String {
        match self {
            BridgeNotifyEvent::Deposit { tx_hash, nonce, .. } => {
                format!("Deposit:{}:{}", tx_hash, nonce)
            }
            BridgeNotifyEvent::Claim { tx_hash, nonce, .. } => {
                format!("Claim:{}:{}", tx_hash, nonce)
            }
            BridgeNotifyEvent::Approval { tx_hash, nonce, .. } => {
                format!("Approval:{}:{}", tx_hash, nonce)
            }
            BridgeNotifyEvent::Emergency { tx_hash, nonce, .. } => {
                format!("Emergency:{}:{}", tx_hash, nonce)
            }
            BridgeNotifyEvent::LimitUpdated { tx_hash, nonce, .. } => {
                format!("Limit:{}:{}", tx_hash, nonce)
            }
            BridgeNotifyEvent::BlocklistUpdated { tx_hash, nonce, .. } => {
                format!("Blocklist:{}:{}", tx_hash, nonce)
            }
        }
    }
}

/// Maximum number of dedup entries before clearing.
/// This prevents unbounded memory growth while being large enough
/// to cover any realistic burst of duplicate events.
const DEDUP_CAPACITY: usize = 10_000;

/// Telegram notifier for bridge events
pub struct TelegramNotifier {
    config: TelegramConfig,
    client: Client,
    api_base: String,
    /// Tracks already-sent finalized event IDs to prevent duplicate notifications.
    /// Uses `BridgeNotifyEvent::event_id()` ("Type:tx_hash:nonce") as the key.
    sent_events: Mutex<HashSet<String>>,
}

impl std::fmt::Debug for TelegramNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramNotifier")
            .field("configured", &self.is_configured())
            .field("api_base", &"<redacted>")
            .finish()
    }
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
            sent_events: Mutex::new(HashSet::new()),
        }
    }

    /// Check if Telegram is configured
    pub fn is_configured(&self) -> bool {
        self.config.is_configured()
    }

    /// Build environment footer with bridge info and current quota
    async fn env_footer(&self) -> String {
        let env = &self.config.bridge_env;
        if env.eth_chain_name.is_empty() && env.stc_chain_name.is_empty() {
            return String::new();
        }

        let mut lines = vec!["\n\n───────────".to_string()];
        lines.push(format!(
            "<b>ETH:</b> {} [{}] <code>{}</code>",
            env.eth_chain_name, env.eth_chain_id, env.eth_contract
        ));
        lines.push(format!(
            "<b>STC:</b> {} [{}] <code>{}</code>",
            env.stc_chain_name, env.stc_chain_id, env.stc_contract
        ));

        // Append live quota if available
        if let Some(cache) = get_global_quota_cache() {
            let q = cache.get().await;
            let decimals = q.decimals.0 as f64;
            let fmt_quota = |v: Option<&crate::api::BigIntValue>| -> String {
                match v {
                    Some(bv) => format!("${:.2}", bv.0 as f64 / 10f64.powf(decimals)),
                    None => "N/A".to_string(),
                }
            };
            lines.push(format!(
                "<b>Quota:</b> ETH claim {} · STC claim {}",
                fmt_quota(q.eth_claim.as_ref()),
                fmt_quota(q.starcoin_claim.as_ref()),
            ));
        }

        lines.join("\n")
    }

    /// Send a raw message to Telegram
    pub async fn send_message(&self, text: &str) -> Result<()> {
        if !self.is_configured() {
            info!(
                "Telegram not configured, would send: {}",
                &text[..text.len().min(200)]
            );
            return Ok(());
        }

        let text = format!("{}{}", text, self.env_footer().await);

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

    /// Notify about a pending (unfinalized) event
    pub async fn notify_pending(
        &self,
        chain: NotifyChain,
        event: &BridgeNotifyEvent,
    ) -> Result<()> {
        let message = self.format_event_message(chain, event, false);
        self.send_message(&message).await
    }

    /// Notify about a finalized event.
    /// Deduplicates by `event_id` so the same event is only sent once
    /// even if multiple code paths trigger notification for it.
    pub async fn notify_finalized(
        &self,
        chain: NotifyChain,
        event: &BridgeNotifyEvent,
    ) -> Result<()> {
        let key = event.event_id();
        {
            let mut sent = self.sent_events.lock().await;
            if !sent.insert(key.clone()) {
                info!("[Telegram] Skipping duplicate finalized notification: {}", key);
                return Ok(());
            }
            if sent.len() > DEDUP_CAPACITY {
                sent.clear();
            }
        }
        let message = self.format_event_message(chain, event, true);
        self.send_message(&message).await
    }

    /// Format event message
    fn format_event_message(
        &self,
        chain: NotifyChain,
        event: &BridgeNotifyEvent,
        is_finalized: bool,
    ) -> String {
        let status = if is_finalized {
            "✅ FINALIZED"
        } else {
            "⏳ PENDING"
        };

        match event {
            BridgeNotifyEvent::Deposit {
                source_chain_id,
                destination_chain_id,
                nonce,
                token_id,
                amount,
                sender_address,
                recipient_address,
                tx_hash,
                block_number,
            } => {
                let source_chain = get_chain_name(*source_chain_id);
                let dest_chain = get_chain_name(*destination_chain_id);
                let token = get_token_name(*token_id);
                let amount_human = format!("{:.4}", *amount as f64 / 1e8);

                format!(
                    "<b>[Starcoin Bridge]</b> {}\n\
                    🌉 <b>Deposited</b>\n\n\
                    <b>Status:</b> {}\n\
                    <b>Direction:</b> {} → {}\n\
                    <b>Token:</b> {}\n\
                    <b>Amount:</b> {}\n\
                    <b>Nonce:</b> {}\n\
                    <b>From:</b> <code>{}</code>\n\
                    <b>To:</b> <code>{}</code>\n\n\
                    <b>Tx:</b> <code>{}</code>\n\
                    <b>Block:</b> {}",
                    if is_finalized { "📋" } else { "⏳" },
                    status,
                    source_chain,
                    dest_chain,
                    token,
                    amount_human,
                    nonce,
                    Self::truncate_addr(sender_address),
                    Self::truncate_addr(recipient_address),
                    tx_hash,
                    block_number
                )
            }
            BridgeNotifyEvent::Claim {
                source_chain_id,
                destination_chain_id,
                nonce,
                token_id,
                amount,
                recipient_address,
                tx_hash,
                block_number,
            } => {
                let source_chain = get_chain_name(*source_chain_id);
                let dest_chain = get_chain_name(*destination_chain_id);
                let token = get_token_name(*token_id);
                // USDT has 6 decimals on EVM
                let decimals = if *token_id == 3 { 6 } else { 8 };
                let amount_human = format!("{:.4}", *amount as f64 / 10f64.powi(decimals));

                format!(
                    "<b>[Starcoin Bridge]</b> {}\n\
                    ✅ <b>Claimed</b>\n\n\
                    <b>Status:</b> {}\n\
                    <b>Direction:</b> {} → {}\n\
                    <b>Token:</b> {}\n\
                    <b>Amount:</b> {}\n\
                    <b>Nonce:</b> {}\n\
                    <b>Recipient:</b> <code>{}</code>\n\n\
                    <b>Tx:</b> <code>{}</code>\n\
                    <b>Block:</b> {}",
                    if is_finalized { "📋" } else { "⏳" },
                    status,
                    source_chain,
                    dest_chain,
                    token,
                    amount_human,
                    nonce,
                    Self::truncate_addr(recipient_address),
                    tx_hash,
                    block_number
                )
            }
            BridgeNotifyEvent::Emergency {
                paused,
                nonce,
                tx_hash,
                block_number,
            } => {
                let mentions = self.build_mention_text();
                let status_emoji = if *paused {
                    "🛑 PAUSED"
                } else {
                    "▶️ RESUMED"
                };

                format!(
                    "{}<b>[Starcoin Bridge]</b> 🚨 EMERGENCY\n\
                    ⚠️ <b>EMERGENCY OPERATION</b>\n\n\
                    <b>Status:</b> {}\n\
                    <b>Chain:</b> {}\n\
                    <b>Operation:</b> {}\n\
                    <b>Nonce:</b> {}\n\n\
                    <b>Tx:</b> <code>{}</code>\n\
                    <b>Block:</b> {}\n\n\
                    ⚠️ <i>Immediate attention required!</i>",
                    mentions,
                    status,
                    chain.name(),
                    status_emoji,
                    nonce,
                    tx_hash,
                    block_number
                )
            }
            BridgeNotifyEvent::LimitUpdated {
                source_chain_id,
                new_limit,
                nonce,
                tx_hash,
                block_number,
            } => {
                let source_chain = get_chain_name(*source_chain_id);
                let limit_human = format!("{:.2}", *new_limit as f64 / 1e8);

                format!(
                    "<b>[Starcoin Bridge]</b> ℹ️\n\
                    📊 <b>Bridge Limit Updated</b>\n\n\
                    <b>Status:</b> {}\n\
                    <b>Chain:</b> {}\n\
                    <b>Source Chain:</b> {}\n\
                    <b>New Limit:</b> {} USDT\n\
                    <b>Nonce:</b> {}\n\n\
                    <b>Tx:</b> <code>{}</code>\n\
                    <b>Block:</b> {}",
                    status,
                    chain.name(),
                    source_chain,
                    limit_human,
                    nonce,
                    tx_hash,
                    block_number
                )
            }
            BridgeNotifyEvent::BlocklistUpdated {
                members,
                is_blocklisted,
                nonce: _,
                tx_hash,
                block_number,
            } => {
                let action_emoji = if *is_blocklisted { "🚫" } else { "✅" };
                let action_text = if *is_blocklisted {
                    "BLOCKED"
                } else {
                    "UNBLOCKED"
                };
                let mentions = if *is_blocklisted {
                    self.build_mention_text()
                } else {
                    String::new()
                };

                let members_text: Vec<String> = members
                    .iter()
                    .take(5)
                    .map(|m| format!("• <code>{}</code>", Self::truncate_addr(m)))
                    .collect();
                let mut members_display = members_text.join("\n");
                if members.len() > 5 {
                    members_display.push_str(&format!("\n• ... and {} more", members.len() - 5));
                }

                format!(
                    "{}<b>[Starcoin Bridge]</b> {}\n\
                    {} <b>Committee Member {}</b>\n\n\
                    <b>Status:</b> {}\n\
                    <b>Chain:</b> {}\n\
                    <b>Action:</b> {}\n\
                    <b>Members:</b>\n{}\n\n\
                    <b>Tx:</b> <code>{}</code>\n\
                    <b>Block:</b> {}",
                    mentions,
                    if *is_blocklisted {
                        "🚨 EMERGENCY"
                    } else {
                        "ℹ️"
                    },
                    action_emoji,
                    action_text,
                    status,
                    chain.name(),
                    action_text,
                    members_display,
                    tx_hash,
                    block_number
                )
            }
            BridgeNotifyEvent::Approval {
                source_chain_id,
                destination_chain_id,
                nonce,
                token_id,
                amount,
                recipient_address,
                tx_hash,
                block_number,
            } => {
                let source_chain = get_chain_name(*source_chain_id);
                let dest_chain = get_chain_name(*destination_chain_id);
                let token = get_token_name(*token_id);
                let amount_human = format!("{:.4}", *amount as f64 / 1e8);

                format!(
                    "<b>[Starcoin Bridge]</b> {}\n\
                    🔐 <b>Transfer Approved</b>\n\n\
                    <b>Status:</b> {}\n\
                    <b>Direction:</b> {} → {}\n\
                    <b>Token:</b> {}\n\
                    <b>Amount:</b> {}\n\
                    <b>Nonce:</b> {}\n\
                    <b>Recipient:</b> <code>{}</code>\n\n\
                    <b>Tx:</b> <code>{}</code>\n\
                    <b>Block:</b> {}",
                    if is_finalized { "📋" } else { "⏳" },
                    status,
                    source_chain,
                    dest_chain,
                    token,
                    amount_human,
                    nonce,
                    Self::truncate_addr(recipient_address),
                    tx_hash,
                    block_number
                )
            }
        }
    }

    /// Send startup notification
    pub async fn notify_startup(&self, eth_contract: &str, stc_contract: &str) -> Result<()> {
        let message = format!(
            "<b>[Starcoin Bridge]</b> ℹ️\n\
            🚀 <b>Bridge Indexer Started</b>\n\n\
            <b>Monitoring:</b>\n\
            • Ethereum: <code>{}</code>\n\
            • Starcoin: <code>{}</code>",
            Self::truncate_addr(eth_contract),
            Self::truncate_addr(stc_contract)
        );
        self.send_message(&message).await
    }

    /// Send reorg notification
    pub async fn notify_reorg(
        &self,
        chain: NotifyChain,
        fork_point: u64,
        depth: u64,
        orphaned_count: usize,
    ) -> Result<()> {
        let mentions = self.build_mention_text();
        let message = format!(
            "{}<b>[Starcoin Bridge]</b> ⚠️\n\
            🔄 <b>CHAIN REORGANIZATION DETECTED</b>\n\n\
            <b>Chain:</b> {}\n\
            <b>Fork Point:</b> {}\n\
            <b>Depth:</b> {} blocks\n\
            <b>Orphaned Events:</b> {}\n\n\
            ⚠️ <i>Previously sent notifications may be INVALID.</i>",
            mentions,
            chain.name(),
            fork_point,
            depth,
            orphaned_count
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

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

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
            <i>⏰ Time: Unix {}</i>",
            mentions, reason, chain_name, suspicious_chain, suspicious_nonce, now
        );

        self.send_message(&message).await
    }

    /// Send pause execution status
    pub async fn send_pause_execution_status(
        &self,
        eth_success: bool,
        stc_success: bool,
        error_message: Option<&str>,
    ) -> Result<()> {
        let mentions = self.build_mention_text();

        let eth_status = if eth_success {
            "✅ Success"
        } else {
            "❌ Failed"
        };
        let stc_status = if stc_success {
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

        if !eth_success || !stc_success {
            message.push_str(
                "<b>⚠️ MANUAL INTERVENTION REQUIRED</b>\n\
                Please execute pause manually on failed chain(s)!",
            );
        } else {
            message.push_str("✅ <i>Both chains paused successfully</i>");
        }

        self.send_message(&message).await
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
}

/// Shared telegram notifier type
pub type SharedTelegramNotifier = Arc<TelegramNotifier>;

/// Create a shared telegram notifier
pub fn create_telegram_notifier(config: TelegramConfig) -> SharedTelegramNotifier {
    Arc::new(TelegramNotifier::new(config))
}

/// Get human-readable chain name from chain ID
fn get_chain_name(chain_id: u8) -> &'static str {
    match chain_id {
        0 => "Starcoin Mainnet",
        1 => "Starcoin Testnet",
        2 => "Starcoin Custom",
        10 => "Ethereum Mainnet",
        11 => "Ethereum Sepolia",
        12 => "Ethereum Custom",
        _ => "Unknown",
    }
}

/// Get human-readable token name from token ID
fn get_token_name(token_id: u8) -> &'static str {
    match token_id {
        1 => "STC",
        2 => "WETH",
        3 => "USDC",
        4 => "USDT",
        5 => "BTC",
        _ => "Unknown",
    }
}

/// Create BridgeNotifyEvent(s) from a finalized TransferRecord.
///
/// This is used by finalize_and_persist_records paths where events transition
/// from unfinalized (memory) to finalized (DB), and we need to send
/// telegram notifications that were deferred during the unfinalized phase.
///
/// `caller_chain` filters events to only those observed on the caller's chain,
/// preventing duplicate notifications when both ETH and STC handlers process
/// the same shared TransferRecord:
/// - Deposit: only if source_chain == caller_chain (deposit observed on source)
/// - Approval: only if recorded_chain == caller_chain (approval recorded on destination)
/// - Claim: only if source_chain != caller_chain (claim observed on destination)
pub fn create_notify_events_from_record(
    record: &TransferRecord,
    network: NetworkType,
) -> Vec<BridgeNotifyEvent> {
    let mut events = Vec::new();
    let source_chain_id = network.chain_id_to_bridge_i32(record.key.source_chain) as u8;

    // Emit all event types present in the record.
    // Whichever handler finalizes the record sends all notifications;
    // the dedup mechanism in notify_finalized prevents duplicates.

    if let Some(ref deposit) = record.deposit {
        let destination_chain_id =
            network.chain_id_to_bridge_i32(deposit.destination_chain) as u8;
        events.push(BridgeNotifyEvent::Deposit {
            source_chain_id,
            destination_chain_id,
            nonce: record.key.nonce,
            token_id: deposit.token_id,
            amount: deposit.amount,
            sender_address: deposit.sender_address.clone(),
            recipient_address: deposit.recipient_address.clone(),
            tx_hash: deposit.tx_hash.clone(),
            block_number: deposit.block_number,
        });
    }

    if let Some(ref approval) = record.approval {
        let destination_chain_id =
            network.chain_id_to_bridge_i32(approval.recorded_chain) as u8;
        events.push(BridgeNotifyEvent::Approval {
            source_chain_id,
            destination_chain_id,
            nonce: record.key.nonce,
            token_id: record.deposit.as_ref().map(|d| d.token_id).unwrap_or(0),
            amount: record.deposit.as_ref().map(|d| d.amount).unwrap_or(0),
            recipient_address: record
                .deposit
                .as_ref()
                .map(|d| d.recipient_address.clone())
                .unwrap_or_default(),
            tx_hash: approval.tx_hash.clone(),
            block_number: approval.block_number,
        });
    }

    if let Some(ref claim) = record.claim {
        let destination_chain_id = record
            .deposit
            .as_ref()
            .map(|d| network.chain_id_to_bridge_i32(d.destination_chain) as u8)
            .unwrap_or(0);
        // Fallback to deposit's recipient_address when claimer_address is empty
        // (MoveTokenTransferClaimed on Starcoin doesn't include recipient info)
        let recipient = if claim.claimer_address.is_empty() {
            record
                .deposit
                .as_ref()
                .map(|d| d.recipient_address.clone())
                .unwrap_or_default()
        } else {
            claim.claimer_address.clone()
        };
        events.push(BridgeNotifyEvent::Claim {
            source_chain_id,
            destination_chain_id,
            nonce: record.key.nonce,
            token_id: record.deposit.as_ref().map(|d| d.token_id).unwrap_or(0),
            amount: record.deposit.as_ref().map(|d| d.amount).unwrap_or(0),
            recipient_address: recipient,
            tx_hash: claim.tx_hash.clone(),
            block_number: claim.block_number,
        });
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_addr() {
        let short = "0x1234";
        assert_eq!(TelegramNotifier::truncate_addr(short), "0x1234");

        let long = "0x1234567890abcdef1234567890abcdef12345678";
        let truncated = TelegramNotifier::truncate_addr(long);
        assert!(truncated.contains("..."));
        assert_eq!(truncated.len(), 21); // 10 + 3 + 8
    }

    #[test]
    fn test_chain_name() {
        assert_eq!(get_chain_name(0), "Starcoin Mainnet");
        assert_eq!(get_chain_name(10), "Ethereum Mainnet");
        assert_eq!(get_chain_name(12), "Ethereum Custom");
    }

    #[test]
    fn test_token_name() {
        assert_eq!(get_token_name(4), "USDT");
        assert_eq!(get_token_name(1), "STC");
    }
}
