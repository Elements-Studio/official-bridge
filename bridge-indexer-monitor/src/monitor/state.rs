// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! State management for monitor

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Pending transfer (deposited but not yet claimed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTransfer {
    pub source_chain_id: u8,
    pub nonce: u64,
    pub destination_chain_id: u8,
    pub token_id: u8,
    pub amount: u64,
    pub sender_address: String,
    pub recipient_address: String,
    pub deposit_tx: String,
    pub deposit_block: u64,
    pub deposit_time: u64,         // Unix timestamp in seconds
    pub deposit_chain_key: String, // "chain_a" or "chain_b"
}

impl PendingTransfer {
    pub fn age_seconds(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.deposit_time)
    }

    pub fn age_human(&self) -> String {
        let age = self.age_seconds();
        if age < 60 {
            format!("{}s", age)
        } else if age < 3600 {
            format!("{}m {}s", age / 60, age % 60)
        } else {
            let hours = age / 3600;
            let minutes = (age % 3600) / 60;
            format!("{}h {}m", hours, minutes)
        }
    }

    pub fn transfer_key(&self) -> String {
        format!("{}:{}", self.source_chain_id, self.nonce)
    }
}

/// State for a single chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    pub chain_id: u8,
    pub contract_address: String,
    pub last_block: Option<u64>,
    #[serde(default)]
    pub sent_event_ids: Vec<String>, // Keep as Vec for serialization
}

impl ChainState {
    pub fn new(chain_id: u8, contract_address: String) -> Self {
        Self {
            chain_id,
            contract_address,
            last_block: None,
            sent_event_ids: vec![],
        }
    }

    pub fn is_event_sent(&self, event_id: &str) -> bool {
        self.sent_event_ids.contains(&event_id.to_string())
    }

    pub fn add_sent_event(&mut self, event_id: String) {
        if !self.sent_event_ids.contains(&event_id) {
            self.sent_event_ids.push(event_id);
            // Keep only last 5000 events
            if self.sent_event_ids.len() > 5000 {
                self.sent_event_ids
                    .drain(0..self.sent_event_ids.len() - 5000);
            }
        }
    }
}

/// Complete monitor state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorState {
    pub version: u32,
    pub chain_a: ChainState,
    pub chain_b: ChainState,
    #[serde(default)]
    pub pending_transfers: HashMap<String, PendingTransfer>,
}

impl MonitorState {
    pub fn new(
        chain_a_id: u8,
        chain_a_contract: String,
        chain_b_id: u8,
        chain_b_contract: String,
    ) -> Self {
        Self {
            version: 2,
            chain_a: ChainState::new(chain_a_id, chain_a_contract),
            chain_b: ChainState::new(chain_b_id, chain_b_contract),
            pending_transfers: HashMap::new(),
        }
    }
}

/// State manager with thread-safe access
pub struct StateManager {
    file_path: PathBuf,
    state: Arc<RwLock<MonitorState>>,
}

impl StateManager {
    pub fn new(file_path: PathBuf) -> Result<Self> {
        let state = if file_path.exists() {
            let contents =
                std::fs::read_to_string(&file_path).context("Failed to read state file")?;
            serde_json::from_str(&contents).context("Failed to parse state file")?
        } else {
            // Create default state (will be properly initialized when load() is called)
            MonitorState::new(0, String::new(), 0, String::new())
        };

        Ok(Self {
            file_path,
            state: Arc::new(RwLock::new(state)),
        })
    }

    /// Load state for specific chains, or create new if mismatch
    pub async fn load(
        &self,
        chain_a_id: u8,
        chain_a_contract: &str,
        chain_b_id: u8,
        chain_b_contract: &str,
    ) -> Result<()> {
        let mut state = self.state.write().await;

        // Check if state matches current configuration
        let a_match = state.chain_a.chain_id == chain_a_id
            && (state.chain_a.contract_address.is_empty()
                || state.chain_a.contract_address == chain_a_contract);
        let b_match = state.chain_b.chain_id == chain_b_id
            && (state.chain_b.contract_address.is_empty()
                || state.chain_b.contract_address == chain_b_contract);

        if a_match && b_match {
            // Update contract addresses if not set
            if state.chain_a.contract_address.is_empty() {
                state.chain_a.contract_address = chain_a_contract.to_string();
            }
            if state.chain_b.contract_address.is_empty() {
                state.chain_b.contract_address = chain_b_contract.to_string();
            }

            info!("📂 Loaded state from {:?}", self.file_path);
            if let Some(block) = state.chain_a.last_block {
                info!("   Chain A: resuming from block {}", block);
            }
            if let Some(block) = state.chain_b.last_block {
                info!("   Chain B: resuming from block {}", block);
            }
            let sent_count =
                state.chain_a.sent_event_ids.len() + state.chain_b.sent_event_ids.len();
            if sent_count > 0 {
                info!("   Loaded {} sent event IDs for deduplication", sent_count);
            }
        } else {
            warn!("⚠ State file chain/contract mismatch, starting fresh");
            *state = MonitorState::new(
                chain_a_id,
                chain_a_contract.to_string(),
                chain_b_id,
                chain_b_contract.to_string(),
            );
        }

        Ok(())
    }

    /// Save state to file
    pub async fn save(&self) -> Result<()> {
        let state = self.state.read().await;
        let contents =
            serde_json::to_string_pretty(&*state).context("Failed to serialize state")?;
        std::fs::write(&self.file_path, contents).context("Failed to write state file")?;
        Ok(())
    }

    /// Get last block for a chain
    pub async fn get_last_block(&self, chain_key: &str) -> Option<u64> {
        let state = self.state.read().await;
        match chain_key {
            "chain_a" => state.chain_a.last_block,
            "chain_b" => state.chain_b.last_block,
            _ => None,
        }
    }

    /// Update last block for a chain
    pub async fn update_last_block(&self, chain_key: &str, block: u64) -> Result<()> {
        let mut state = self.state.write().await;
        match chain_key {
            "chain_a" => state.chain_a.last_block = Some(block),
            "chain_b" => state.chain_b.last_block = Some(block),
            _ => {}
        }
        drop(state);
        self.save().await
    }

    /// Check if event was already sent
    pub async fn is_event_sent(&self, chain_key: &str, event_id: &str) -> bool {
        let state = self.state.read().await;
        match chain_key {
            "chain_a" => state.chain_a.is_event_sent(event_id),
            "chain_b" => state.chain_b.is_event_sent(event_id),
            _ => false,
        }
    }

    /// Mark event as sent
    pub async fn mark_event_sent(&self, chain_key: &str, event_id: String) -> Result<()> {
        let mut state = self.state.write().await;
        match chain_key {
            "chain_a" => state.chain_a.add_sent_event(event_id),
            "chain_b" => state.chain_b.add_sent_event(event_id),
            _ => {}
        }
        drop(state);
        self.save().await
    }

    /// Add a pending transfer
    pub async fn add_pending_transfer(&self, transfer: PendingTransfer) -> Result<()> {
        let mut state = self.state.write().await;
        state
            .pending_transfers
            .insert(transfer.transfer_key(), transfer);
        drop(state);
        self.save().await
    }

    /// Remove a pending transfer (when claimed)
    pub async fn remove_pending_transfer(&self, source_chain_id: u8, nonce: u64) -> Result<()> {
        let mut state = self.state.write().await;
        let key = format!("{}:{}", source_chain_id, nonce);
        state.pending_transfers.remove(&key);
        drop(state);
        self.save().await
    }

    /// Get all pending transfers
    pub async fn get_pending_transfers(&self) -> Vec<PendingTransfer> {
        let state = self.state.read().await;
        state.pending_transfers.values().cloned().collect()
    }

    /// Clear sent events after a specific block (for reorg handling)
    ///
    /// Event IDs are in format "Type:tx_hash:block_number".
    /// This removes all events where block_number > fork_point.
    pub async fn clear_events_after_block(&self, chain_key: &str, fork_point: u64) -> Result<()> {
        let mut state = self.state.write().await;
        let chain_state = match chain_key {
            "chain_a" => &mut state.chain_a,
            "chain_b" => &mut state.chain_b,
            _ => return Ok(()),
        };

        let before_count = chain_state.sent_event_ids.len();

        // Keep only events at or before fork_point
        chain_state.sent_event_ids.retain(|event_id| {
            // Parse block number from event_id format "Type:tx_hash:block_number"
            if let Some(block_str) = event_id.rsplit(':').next() {
                if let Ok(block) = block_str.parse::<u64>() {
                    return block <= fork_point;
                }
            }
            // If we can't parse, keep the event (conservative)
            true
        });

        let removed_count = before_count - chain_state.sent_event_ids.len();
        if removed_count > 0 {
            info!(
                "[StateManager] Cleared {} sent event IDs after block {} for {}",
                removed_count, fork_point, chain_key
            );
        }

        // Also reset last_block if it was ahead of fork_point
        if let Some(last_block) = chain_state.last_block {
            if last_block > fork_point {
                chain_state.last_block = Some(fork_point);
                info!(
                    "[StateManager] Reset last_block from {} to {} for {}",
                    last_block, fork_point, chain_key
                );
            }
        }

        drop(state);
        self.save().await
    }

    /// Remove pending transfers with deposit_block > fork_point (for reorg handling)
    pub async fn clear_pending_transfers_after_block(&self, fork_point: u64) -> Result<()> {
        let mut state = self.state.write().await;
        let before_count = state.pending_transfers.len();

        state
            .pending_transfers
            .retain(|_, transfer| transfer.deposit_block <= fork_point);

        let removed_count = before_count - state.pending_transfers.len();
        if removed_count > 0 {
            info!(
                "[StateManager] Cleared {} pending transfers after block {}",
                removed_count, fork_point
            );
        }

        drop(state);
        self.save().await
    }
}
