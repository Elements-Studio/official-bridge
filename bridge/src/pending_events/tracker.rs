// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Transfer lifecycle tracker
//!
//! Links deposit/approval/claim events into unified transfer records
//! and detects potential key compromise via mismatches.

use super::types::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Callback for mismatch detection
pub(crate) type MismatchCallback = Arc<dyn Fn(TransferMismatch) + Send + Sync>;

/// Callback when events change (for SecurityMonitor notification)
pub(crate) type ChangeCallback = Arc<dyn Fn() + Send + Sync>;

/// Tracks cross-chain transfers across their lifecycle
///
/// Maintains:
/// - Pending transfers (deposit observed, waiting for claim)
/// - Finalized deposits (loaded from DB for claim matching)
/// - Mismatch detection for security monitoring
pub struct TransferTracker {
    /// Pending transfers indexed by key
    pending: RwLock<HashMap<TransferKey, TransferRecord>>,
    /// Finalized deposits loaded from DB (for matching claims)
    finalized_deposits: RwLock<HashMap<TransferKey, DepositInfo>>,
    /// Callback when mismatch is detected (RwLock allows runtime setting)
    on_mismatch: RwLock<Option<MismatchCallback>>,
    /// Callback when events change (for SecurityMonitor)
    on_change: RwLock<Option<ChangeCallback>>,
}

impl TransferTracker {
    /// Create a new transfer tracker
    pub fn new() -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            finalized_deposits: RwLock::new(HashMap::new()),
            on_mismatch: RwLock::new(None),
            on_change: RwLock::new(None),
        }
    }

    /// Create a new transfer tracker with mismatch callback
    pub fn new_with_callback(callback: MismatchCallback) -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            finalized_deposits: RwLock::new(HashMap::new()),
            on_mismatch: RwLock::new(Some(callback)),
            on_change: RwLock::new(None),
        }
    }

    /// Set callback for mismatch detection (builder pattern)
    ///
    /// Note: This method must be called from a non-async context (e.g., during initialization).
    /// In async contexts, use `set_mismatch_callback` instead.
    pub fn with_mismatch_callback(self, callback: MismatchCallback) -> Self {
        // Create new tracker with the callback directly
        Self {
            pending: self.pending,
            finalized_deposits: self.finalized_deposits,
            on_mismatch: RwLock::new(Some(callback)),
            on_change: self.on_change,
        }
    }

    /// Set mismatch callback after creation (runtime)
    ///
    /// This can be called on Arc<TransferTracker> after creation.
    pub async fn set_mismatch_callback(&self, callback: MismatchCallback) {
        let mut guard = self.on_mismatch.write().await;
        *guard = Some(callback);
    }

    /// Set change callback for SecurityMonitor notification
    ///
    /// This callback is invoked whenever events are added/modified.
    pub async fn set_change_callback(&self, callback: ChangeCallback) {
        let mut guard = self.on_change.write().await;
        *guard = Some(callback);
    }

    /// Notify that events have changed
    async fn notify_change(&self) {
        let guard = self.on_change.read().await;
        if let Some(callback) = guard.as_ref() {
            callback();
        }
    }

    /// Check if a deposit exists for the given key (in pending or finalized)
    pub async fn has_deposit(&self, key: &TransferKey) -> bool {
        // Check pending
        {
            let pending = self.pending.read().await;
            if let Some(record) = pending.get(key) {
                if record.deposit.is_some() {
                    return true;
                }
            }
        }

        // Check finalized
        {
            let finalized = self.finalized_deposits.read().await;
            if finalized.contains_key(key) {
                return true;
            }
        }

        false
    }

    /// Load finalized deposits from DB
    ///
    /// Call this on startup to populate the finalized_deposits map
    /// for claim matching.
    pub async fn load_finalized_deposits(&self, deposits: Vec<(TransferKey, DepositInfo)>) {
        let mut finalized = self.finalized_deposits.write().await;
        let count = deposits.len();
        for (key, info) in deposits {
            finalized.insert(key, info);
        }
        info!(
            "TransferTracker: loaded {} finalized deposits from DB",
            count
        );
    }

    /// Process a deposit event
    pub async fn on_deposit(&self, event: &PendingEvent, deposit: &DepositEvent) {
        let key = TransferKey::new(deposit.source_chain, deposit.nonce);

        let mut pending = self.pending.write().await;

        if let Some(existing) = pending.get_mut(&key) {
            // Update existing record
            if existing.deposit.is_some() {
                warn!(
                    "[TransferTracker] Duplicate deposit for {}: tx={}, ignoring",
                    key, event.tx_hash
                );
                return;
            }
            existing.deposit = Some(DepositInfo {
                tx_hash: event.tx_hash.clone(),
                block_number: event.block_number,
                timestamp_ms: event.timestamp_ms,
                destination_chain: deposit.destination_chain,
                token_id: deposit.token_id,
                amount: deposit.amount,
                sender_address: deposit.sender_address.clone(),
                recipient_address: deposit.recipient_address.clone(),
                is_finalized: false,
            });
        } else {
            // Create new record
            pending.insert(
                key,
                TransferRecord {
                    key,
                    status: TransferStatus::Deposited,
                    deposit: Some(DepositInfo {
                        tx_hash: event.tx_hash.clone(),
                        block_number: event.block_number,
                        timestamp_ms: event.timestamp_ms,
                        destination_chain: deposit.destination_chain,
                        token_id: deposit.token_id,
                        amount: deposit.amount,
                        sender_address: deposit.sender_address.clone(),
                        recipient_address: deposit.recipient_address.clone(),
                        is_finalized: false,
                    }),
                    approval: None,
                    claim: None,
                },
            );
        }

        info!(
            "[TransferTracker] Deposit recorded: key={}, tx={}, block={}, amount={}, sender={}, recipient={}, dest_chain={:?}",
            key, event.tx_hash, event.block_number, deposit.amount,
            deposit.sender_address, deposit.recipient_address, deposit.destination_chain
        );

        // Notify SecurityMonitor of event change
        drop(pending); // Release lock before async call
        self.notify_change().await;
    }

    /// Process an approval event
    ///
    /// Returns a `MismatchAlert` if the approval has no matching deposit.
    /// This indicates a potential key compromise attack.
    pub async fn on_approval(
        &self,
        event: &PendingEvent,
        approval: &ApprovalEvent,
    ) -> Option<MismatchAlert> {
        let key = TransferKey::new(approval.source_chain, approval.nonce);

        // Check if deposit exists in finalized deposits
        let has_finalized_deposit = {
            let finalized = self.finalized_deposits.read().await;
            finalized.contains_key(&key)
        };

        let mut pending = self.pending.write().await;

        let has_deposit = if let Some(existing) = pending.get_mut(&key) {
            if existing.approval.is_some() {
                warn!(
                    "[TransferTracker] Duplicate approval for {}: tx={}, ignoring",
                    key, event.tx_hash
                );
                return None;
            }
            existing.approval = Some(ApprovalInfo {
                tx_hash: event.tx_hash.clone(),
                block_number: event.block_number,
                timestamp_ms: event.timestamp_ms,
                recorded_chain: approval.recorded_chain,
                is_finalized: false,
            });
            existing.status = TransferStatus::Approved;
            info!(
                "[TransferTracker] Approval recorded: key={}, tx={}, block={}, has_deposit={}",
                key,
                event.tx_hash,
                event.block_number,
                existing.deposit.is_some()
            );
            existing.deposit.is_some()
        } else {
            // No pending record - create one
            pending.insert(
                key,
                TransferRecord {
                    key,
                    status: TransferStatus::Approved,
                    deposit: None,
                    approval: Some(ApprovalInfo {
                        tx_hash: event.tx_hash.clone(),
                        block_number: event.block_number,
                        timestamp_ms: event.timestamp_ms,
                        recorded_chain: approval.recorded_chain,
                        is_finalized: false,
                    }),
                    claim: None,
                },
            );
            info!(
                "[TransferTracker] Approval recorded (no pending deposit): key={}, tx={}, block={}",
                key, event.tx_hash, event.block_number
            );
            false
        };

        // Notify SecurityMonitor of event change
        drop(pending); // Release lock before async call
        self.notify_change().await;

        // Return alert if no deposit found anywhere
        if !has_deposit && !has_finalized_deposit {
            error!(
                "[TransferTracker] CRITICAL: Approval without deposit detected! key={}, tx={}, block={}",
                key, event.tx_hash, event.block_number
            );
            return Some(MismatchAlert::ApprovalWithoutDeposit {
                source_chain: approval.source_chain,
                nonce: approval.nonce,
                tx_hash: event.tx_hash.clone(),
                block_number: event.block_number,
            });
        }

        None
    }

    /// Process a claim event
    ///
    /// This is where we check for deposit/claim matching to detect key compromise.
    /// Returns a `MismatchAlert` if the claim has no matching deposit.
    pub async fn on_claim(
        &self,
        event: &PendingEvent,
        claim: &ClaimEvent,
    ) -> Option<MismatchAlert> {
        let key = TransferKey::new(claim.source_chain, claim.nonce);

        info!(
            "[TransferTracker] Processing claim: key={}, tx={}, block={}, amount={}, claimer={}",
            key, event.tx_hash, event.block_number, claim.amount, claim.claimer_address
        );

        let claim_info = ClaimInfo {
            tx_hash: event.tx_hash.clone(),
            block_number: event.block_number,
            timestamp_ms: event.timestamp_ms,
            claimer_address: claim.claimer_address.clone(),
            is_finalized: false,
        };

        // First, try to find matching deposit
        let deposit_info = {
            let pending = self.pending.read().await;
            pending.get(&key).and_then(|r| r.deposit.clone())
        }
        .or_else(|| {
            // Check finalized deposits from DB
            let finalized = self.finalized_deposits.try_read().ok()?;
            finalized.get(&key).cloned()
        });

        let mut alert: Option<MismatchAlert> = None;

        // Check for mismatches
        if let Some(deposit) = &deposit_info {
            debug!(
                "[TransferTracker] Claim {} matched deposit: deposit_tx={}, deposit_amount={}, deposit_recipient={}",
                key, deposit.tx_hash, deposit.amount, deposit.recipient_address
            );
            // Verify claim matches deposit
            if let Some(mismatch_reason) = self.check_claim_mismatch(deposit, claim) {
                error!(
                    "[TransferTracker] MISMATCH DETECTED for {}: reason={}, deposit_tx={}, claim_tx={}, deposit_amount={}, claim_amount={}",
                    key, mismatch_reason, deposit.tx_hash, event.tx_hash, deposit.amount, claim.amount
                );
                let mismatch_record = TransferMismatch {
                    key,
                    reason: mismatch_reason,
                    deposit: Some(deposit.clone()),
                    claim: claim_info.clone(),
                };
                // Invoke callback asynchronously
                let callback_guard = self.on_mismatch.read().await;
                if let Some(callback) = callback_guard.as_ref() {
                    callback(mismatch_record);
                }
            } else {
                info!(
                    "[TransferTracker] Claim validated successfully: key={}, deposit_tx={}, claim_tx={}",
                    key, deposit.tx_hash, event.tx_hash
                );
            }
        } else {
            // Claim without matching deposit - CRITICAL SECURITY ISSUE
            error!(
                "[TransferTracker] CRITICAL: Claim {} without matching deposit! tx={}, amount={}, claimer={}, recipient={}. Potential key compromise!",
                key, event.tx_hash, claim.amount, claim.claimer_address, claim.recipient_address
            );
            let mismatch_record = TransferMismatch {
                key,
                reason: MismatchReason::NoMatchingDeposit,
                deposit: None,
                claim: claim_info.clone(),
            };
            // Invoke callback asynchronously
            let callback_guard = self.on_mismatch.read().await;
            if let Some(callback) = callback_guard.as_ref() {
                callback(mismatch_record);
            }

            // Return alert for immediate sync check
            alert = Some(MismatchAlert::ClaimWithoutDeposit {
                source_chain: claim.source_chain,
                nonce: claim.nonce,
                tx_hash: event.tx_hash.clone(),
                block_number: event.block_number,
            });
        }

        // Update pending record
        let mut pending = self.pending.write().await;
        if let Some(existing) = pending.get_mut(&key) {
            existing.claim = Some(claim_info);
            existing.status = TransferStatus::Claimed;
        } else {
            pending.insert(
                key,
                TransferRecord {
                    key,
                    status: TransferStatus::Claimed,
                    deposit: None,
                    approval: None,
                    claim: Some(claim_info),
                },
            );
        }

        debug!("[TransferTracker] Claim record updated: key={}", key);

        // Notify SecurityMonitor of event change
        drop(pending); // Release lock before async call
        self.notify_change().await;

        alert
    }

    /// Check if claim matches deposit
    fn check_claim_mismatch(
        &self,
        deposit: &DepositInfo,
        claim: &ClaimEvent,
    ) -> Option<MismatchReason> {
        // Token ID must match
        if deposit.token_id != claim.token_id {
            return Some(MismatchReason::TokenMismatch {
                deposit_token: deposit.token_id,
                claim_token: claim.token_id,
            });
        }

        // Amount check: claim amount should match deposit (adjusted for decimals)
        // Note: Different chains may have different decimal representations
        // For USDT: Bridge uses 8 decimals, EVM uses 6 decimals
        let expected_claim_amount = if claim.token_id == 3 {
            // USDT: 8 decimals -> 6 decimals
            deposit.amount / 100
        } else {
            deposit.amount
        };

        if claim.amount != expected_claim_amount {
            return Some(MismatchReason::AmountMismatch {
                deposit_amount: deposit.amount,
                claim_amount: claim.amount,
            });
        }

        // Recipient should match
        if !addresses_match(&deposit.recipient_address, &claim.recipient_address) {
            return Some(MismatchReason::RecipientMismatch {
                expected: deposit.recipient_address.clone(),
                actual: claim.recipient_address.clone(),
            });
        }

        None
    }

    /// Mark events as finalized
    pub async fn mark_finalized(&self, keys: &[TransferKey], event_type: &str) {
        let mut pending = self.pending.write().await;
        let mut marked_count = 0;

        for key in keys {
            if let Some(record) = pending.get_mut(key) {
                match event_type {
                    "deposit" => {
                        if let Some(ref mut d) = record.deposit {
                            d.is_finalized = true;
                            marked_count += 1;
                        }
                    }
                    "approval" => {
                        if let Some(ref mut a) = record.approval {
                            a.is_finalized = true;
                            marked_count += 1;
                        }
                    }
                    "claim" => {
                        if let Some(ref mut c) = record.claim {
                            c.is_finalized = true;
                            marked_count += 1;
                        }
                    }
                    _ => {}
                }
            }
        }

        if marked_count > 0 {
            info!(
                "[TransferTracker] Marked {} {} events as finalized (requested {})",
                marked_count,
                event_type,
                keys.len()
            );
        }
    }

    /// Move finalized deposits to the finalized_deposits map
    /// Called when deposits are written to DB
    pub async fn archive_finalized_deposits(&self, keys: &[TransferKey]) {
        let pending = self.pending.read().await;
        let mut finalized = self.finalized_deposits.write().await;
        let mut archived_count = 0;

        for key in keys {
            if let Some(record) = pending.get(key) {
                if let Some(deposit) = &record.deposit {
                    if deposit.is_finalized {
                        finalized.insert(*key, deposit.clone());
                        archived_count += 1;
                    }
                }
            }
        }

        if archived_count > 0 {
            info!(
                "[TransferTracker] Archived {} finalized deposits (total finalized_deposits={})",
                archived_count,
                finalized.len()
            );
        }
    }

    /// Remove completed transfers (claimed and finalized)
    pub async fn cleanup_completed(&self) -> usize {
        let mut pending = self.pending.write().await;
        let before = pending.len();

        pending.retain(|_, record| {
            // Keep if not fully completed
            !(record.status == TransferStatus::Claimed
                && record
                    .claim
                    .as_ref()
                    .map(|c| c.is_finalized)
                    .unwrap_or(false))
        });

        let removed = before - pending.len();
        if removed > 0 {
            info!(
                "[TransferTracker] Cleanup: removed {} completed transfers, remaining={}",
                removed,
                pending.len()
            );
        }
        removed
    }

    /// Get transfer record by key
    pub async fn get_transfer(&self, key: &TransferKey) -> Option<TransferRecord> {
        let pending = self.pending.read().await;
        pending.get(key).cloned()
    }

    /// Get all pending transfers
    pub async fn get_all_pending(&self) -> Vec<TransferRecord> {
        let pending = self.pending.read().await;
        pending.values().cloned().collect()
    }

    /// Get all pending events organized by transfer key
    ///
    /// Returns a map of TransferKey -> Vec<PendingEvent> for SecurityMonitor
    pub async fn get_all_pending_events(&self) -> HashMap<TransferKey, Vec<PendingEvent>> {
        let pending = self.pending.read().await;
        let mut result: HashMap<TransferKey, Vec<PendingEvent>> = HashMap::new();

        for (key, record) in pending.iter() {
            let mut events = Vec::new();

            if let Some(deposit) = &record.deposit {
                events.push(PendingEvent {
                    event: PendingEventType::Deposit(DepositEvent {
                        source_chain: key.source_chain,
                        destination_chain: deposit.destination_chain,
                        nonce: key.nonce,
                        token_id: deposit.token_id,
                        amount: deposit.amount,
                        sender_address: deposit.sender_address.clone(),
                        recipient_address: deposit.recipient_address.clone(),
                        block_number: deposit.block_number,
                    }),
                    tx_hash: deposit.tx_hash.clone(),
                    block_number: deposit.block_number,
                    timestamp_ms: deposit.timestamp_ms,
                    observed_chain: key.source_chain,
                });
            }

            if let Some(approval) = &record.approval {
                events.push(PendingEvent {
                    event: PendingEventType::Approval(ApprovalEvent {
                        source_chain: key.source_chain,
                        nonce: key.nonce,
                        recorded_chain: approval.recorded_chain,
                        block_number: approval.block_number,
                    }),
                    tx_hash: approval.tx_hash.clone(),
                    block_number: approval.block_number,
                    timestamp_ms: approval.timestamp_ms,
                    observed_chain: approval.recorded_chain,
                });
            }

            if let Some(claim) = &record.claim {
                events.push(PendingEvent {
                    event: PendingEventType::Claim(ClaimEvent {
                        source_chain: key.source_chain,
                        destination_chain: ChainId::Starcoin, // Claims are always to STC in this direction
                        nonce: key.nonce,
                        token_id: 0, // Not stored in ClaimInfo
                        amount: 0,   // Not stored in ClaimInfo
                        sender_address: String::new(),
                        recipient_address: String::new(),
                        claimer_address: claim.claimer_address.clone(),
                        block_number: claim.block_number,
                    }),
                    tx_hash: claim.tx_hash.clone(),
                    block_number: claim.block_number,
                    timestamp_ms: claim.timestamp_ms,
                    observed_chain: ChainId::Starcoin,
                });
            }

            if !events.is_empty() {
                result.insert(*key, events);
            }
        }

        result
    }

    /// Get events for a specific transfer key
    ///
    /// Returns all pending events (deposit, approval, claim) for the given key
    pub async fn get_events_for_key(&self, key: &TransferKey) -> Option<Vec<PendingEvent>> {
        let pending = self.pending.read().await;
        let record = pending.get(key)?;

        let mut events = Vec::new();

        if let Some(deposit) = &record.deposit {
            events.push(PendingEvent {
                event: PendingEventType::Deposit(DepositEvent {
                    source_chain: key.source_chain,
                    destination_chain: deposit.destination_chain,
                    nonce: key.nonce,
                    token_id: deposit.token_id,
                    amount: deposit.amount,
                    sender_address: deposit.sender_address.clone(),
                    recipient_address: deposit.recipient_address.clone(),
                    block_number: deposit.block_number,
                }),
                tx_hash: deposit.tx_hash.clone(),
                block_number: deposit.block_number,
                timestamp_ms: deposit.timestamp_ms,
                observed_chain: key.source_chain,
            });
        }

        if let Some(approval) = &record.approval {
            events.push(PendingEvent {
                event: PendingEventType::Approval(ApprovalEvent {
                    source_chain: key.source_chain,
                    nonce: key.nonce,
                    recorded_chain: approval.recorded_chain,
                    block_number: approval.block_number,
                }),
                tx_hash: approval.tx_hash.clone(),
                block_number: approval.block_number,
                timestamp_ms: approval.timestamp_ms,
                observed_chain: approval.recorded_chain,
            });
        }

        if let Some(claim) = &record.claim {
            events.push(PendingEvent {
                event: PendingEventType::Claim(ClaimEvent {
                    source_chain: key.source_chain,
                    destination_chain: ChainId::Starcoin,
                    nonce: key.nonce,
                    token_id: 0,
                    amount: 0,
                    sender_address: String::new(),
                    recipient_address: String::new(),
                    claimer_address: claim.claimer_address.clone(),
                    block_number: claim.block_number,
                }),
                tx_hash: claim.tx_hash.clone(),
                block_number: claim.block_number,
                timestamp_ms: claim.timestamp_ms,
                observed_chain: ChainId::Starcoin,
            });
        }

        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }

    /// Drain all finalized records up to the given block number
    ///
    /// Returns records where ALL events (deposit/approval/claim) have
    /// block_number <= finalized_block. Records with any event above
    /// finalized_block remain pending.
    ///
    /// IMPORTANT: Records that have approval/claim but NO deposit (neither in
    /// pending nor in finalized_deposits) are kept in pending for SecurityMonitor
    /// to detect. Records where deposit exists in finalized_deposits (late
    /// arrival of approval/claim) are still removed as valid transfers.
    pub async fn drain_finalized_up_to(&self, finalized_block: u64) -> Vec<TransferRecord> {
        let mut pending = self.pending.write().await;
        let finalized_deposits = self.finalized_deposits.read().await;
        let mut finalized_records = Vec::new();
        let mut keys_to_remove = Vec::new();

        for (key, record) in pending.iter() {
            // Check if all events in this record are finalized
            let deposit_finalized = record
                .deposit
                .as_ref()
                .map(|d| d.block_number <= finalized_block)
                .unwrap_or(true);
            let approval_finalized = record
                .approval
                .as_ref()
                .map(|a| a.block_number <= finalized_block)
                .unwrap_or(true);
            let claim_finalized = record
                .claim
                .as_ref()
                .map(|c| c.block_number <= finalized_block)
                .unwrap_or(true);

            // Check if deposit exists either in this record or in finalized_deposits
            // This handles the case where approval/claim arrives after deposit was finalized
            let has_deposit_in_record = record.deposit.is_some();
            let has_deposit_in_finalized = finalized_deposits.contains_key(key);
            let has_valid_deposit = has_deposit_in_record || has_deposit_in_finalized;

            let has_events =
                has_deposit_in_record || record.approval.is_some() || record.claim.is_some();

            // Only mark for removal if ALL events are finalized AND has valid deposit
            // This ensures anomalous records (approval/claim without any matching deposit) stay pending
            if has_events
                && has_valid_deposit
                && deposit_finalized
                && approval_finalized
                && claim_finalized
            {
                finalized_records.push(record.clone());
                keys_to_remove.push(*key);
            }
        }

        // Remove finalized records from pending
        for key in &keys_to_remove {
            pending.remove(key);
        }

        if !finalized_records.is_empty() {
            info!(
                "[TransferTracker] Drained {} finalized records at block {}, remaining_pending={}",
                finalized_records.len(),
                finalized_block,
                pending.len()
            );
        }

        finalized_records
    }

    /// Get finalized records and their keys WITHOUT removing from memory
    ///
    /// This is the first step of the "DB-first" pattern:
    /// 1. Call this to get records that should be finalized
    /// 2. Write them to DB
    /// 3. On DB success, call `remove_keys` to remove from memory
    /// 4. On DB failure, data is still in memory (safe)
    ///
    /// Returns records where ALL events have block_number <= finalized_block.
    /// IMPORTANT: Only returns records that have a deposit (in pending OR in finalized_deposits).
    /// Records with approval/claim but no matching deposit anywhere are anomalies
    /// and should be kept in pending for SecurityMonitor to detect.
    pub async fn get_finalized_records(
        &self,
        finalized_block: u64,
    ) -> (Vec<TransferKey>, Vec<TransferRecord>) {
        let pending = self.pending.read().await;
        let finalized_deposits = self.finalized_deposits.read().await;
        let mut keys = Vec::new();
        let mut records = Vec::new();

        for (key, record) in pending.iter() {
            let deposit_finalized = record
                .deposit
                .as_ref()
                .map(|d| d.block_number <= finalized_block)
                .unwrap_or(true);
            let approval_finalized = record
                .approval
                .as_ref()
                .map(|a| a.block_number <= finalized_block)
                .unwrap_or(true);
            let claim_finalized = record
                .claim
                .as_ref()
                .map(|c| c.block_number <= finalized_block)
                .unwrap_or(true);

            // Check if deposit exists either in this record or in finalized_deposits
            // This handles the case where approval/claim arrives after deposit was finalized
            let has_deposit_in_record = record.deposit.is_some();
            let has_deposit_in_finalized = finalized_deposits.contains_key(key);
            let has_valid_deposit = has_deposit_in_record || has_deposit_in_finalized;

            let has_events =
                has_deposit_in_record || record.approval.is_some() || record.claim.is_some();

            if has_events
                && has_valid_deposit
                && deposit_finalized
                && approval_finalized
                && claim_finalized
            {
                keys.push(*key);
                records.push(record.clone());
            }
        }

        if !records.is_empty() {
            debug!(
                "[TransferTracker] Found {} finalized records at block {}, pending={}",
                records.len(),
                finalized_block,
                pending.len()
            );
        }

        (keys, records)
    }

    /// Remove specified keys from pending (after successful DB write)
    ///
    /// This is the second step of the "DB-first" pattern.
    /// Only call this AFTER successfully writing records to the database.
    pub async fn remove_keys(&self, keys: &[TransferKey]) {
        if keys.is_empty() {
            return;
        }

        let mut pending = self.pending.write().await;
        for key in keys {
            pending.remove(key);
        }

        info!(
            "[TransferTracker] Removed {} finalized keys from memory, remaining_pending={}",
            keys.len(),
            pending.len()
        );
    }

    /// Handle chain reorganization by removing events after fork point
    pub async fn handle_reorg(&self, fork_point: u64) {
        let mut pending = self.pending.write().await;
        let mut affected_keys = Vec::new();
        let mut removed_events = 0;

        for (key, record) in pending.iter_mut() {
            let mut modified = false;

            // Remove deposit if it's after fork point
            if let Some(deposit) = &record.deposit {
                if deposit.block_number > fork_point {
                    record.deposit = None;
                    record.status = TransferStatus::Deposited; // Reset status
                    modified = true;
                    removed_events += 1;
                }
            }

            // Remove approval if it's after fork point
            if let Some(approval) = &record.approval {
                if approval.block_number > fork_point {
                    record.approval = None;
                    // Reset status based on what remains
                    record.status = TransferStatus::Deposited;
                    modified = true;
                    removed_events += 1;
                }
            }

            // Remove claim if it's after fork point
            if let Some(claim) = &record.claim {
                if claim.block_number > fork_point {
                    record.claim = None;
                    // Reset status
                    record.status = if record.approval.is_some() {
                        TransferStatus::Approved
                    } else {
                        TransferStatus::Deposited
                    };
                    modified = true;
                    removed_events += 1;
                }
            }

            if modified {
                affected_keys.push(*key);
            }
        }

        // Remove records with no events left
        pending.retain(|_, record| {
            record.deposit.is_some() || record.approval.is_some() || record.claim.is_some()
        });

        let remaining = pending.len();

        // Release lock before async notify
        drop(pending);

        if removed_events > 0 {
            warn!(
                "[TransferTracker] REORG at block {}: removed {} events from {} transfers, remaining={}",
                fork_point,
                removed_events,
                affected_keys.len(),
                remaining
            );

            // Notify SecurityMonitor after all events are removed
            // This triggers a re-check of pending events
            self.notify_change().await;
        }
    }

    /// Get pending count
    pub async fn pending_count(&self) -> usize {
        let pending = self.pending.read().await;
        pending.len()
    }

    /// Get counts by status
    pub async fn status_counts(&self) -> (usize, usize, usize) {
        let pending = self.pending.read().await;
        let mut deposited = 0;
        let mut approved = 0;
        let mut claimed = 0;

        for record in pending.values() {
            match record.status {
                TransferStatus::Deposited => deposited += 1,
                TransferStatus::Approved => approved += 1,
                TransferStatus::Claimed => claimed += 1,
            }
        }

        (deposited, approved, claimed)
    }
}

impl Default for TransferTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Compare addresses (case-insensitive, with or without 0x prefix)
fn addresses_match(a: &str, b: &str) -> bool {
    let a = a.trim_start_matches("0x").to_lowercase();
    let b = b.trim_start_matches("0x").to_lowercase();
    a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_deposit_event(nonce: u64, amount: u64) -> (PendingEvent, DepositEvent) {
        let deposit = DepositEvent {
            source_chain: ChainId::Eth,
            destination_chain: ChainId::Starcoin,
            nonce,
            token_id: 3, // USDT
            amount,
            sender_address: "0x1234".to_string(),
            recipient_address: "0x5678".to_string(),
            block_number: 100,
        };
        let event = PendingEvent {
            event: PendingEventType::Deposit(deposit.clone()),
            tx_hash: format!("0x{:064x}", nonce),
            block_number: 100,
            timestamp_ms: 1000000,
            observed_chain: ChainId::Eth,
        };
        (event, deposit)
    }

    fn create_claim_event(nonce: u64, amount: u64, recipient: &str) -> (PendingEvent, ClaimEvent) {
        let claim = ClaimEvent {
            source_chain: ChainId::Eth,
            destination_chain: ChainId::Starcoin,
            nonce,
            token_id: 3,
            amount,
            sender_address: "0x1234".to_string(),
            recipient_address: recipient.to_string(),
            claimer_address: recipient.to_string(),
            block_number: 200,
        };
        let event = PendingEvent {
            event: PendingEventType::Claim(claim.clone()),
            tx_hash: format!("0xclaim{:060x}", nonce),
            block_number: 200,
            timestamp_ms: 2000000,
            observed_chain: ChainId::Starcoin,
        };
        (event, claim)
    }

    #[tokio::test]
    async fn test_normal_transfer_lifecycle() {
        let tracker = TransferTracker::new();

        // Deposit 100 USDT (8 decimals = 10_000_000_000)
        let (event, deposit) = create_deposit_event(1, 10_000_000_000);
        tracker.on_deposit(&event, &deposit).await;

        // Claim (6 decimals = 100_000_000)
        let (event, claim) = create_claim_event(1, 100_000_000, "0x5678");
        tracker.on_claim(&event, &claim).await;

        let record = tracker.get_transfer(&TransferKey::eth(1)).await.unwrap();
        assert_eq!(record.status, TransferStatus::Claimed);
        assert!(record.deposit.is_some());
        assert!(record.claim.is_some());
    }

    #[tokio::test]
    async fn test_claim_without_deposit() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let mismatch_detected = Arc::new(AtomicBool::new(false));
        let mismatch_clone = mismatch_detected.clone();

        let tracker = TransferTracker::new().with_mismatch_callback(Arc::new(move |_| {
            mismatch_clone.store(true, Ordering::SeqCst);
        }));

        // Claim without deposit
        let (event, claim) = create_claim_event(999, 100_000_000, "0x5678");
        tracker.on_claim(&event, &claim).await;

        // Should trigger mismatch callback
        assert!(mismatch_detected.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_amount_mismatch() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let mismatch_detected = Arc::new(AtomicBool::new(false));
        let mismatch_clone = mismatch_detected.clone();

        let tracker = TransferTracker::new().with_mismatch_callback(Arc::new(move |m| {
            if matches!(m.reason, MismatchReason::AmountMismatch { .. }) {
                mismatch_clone.store(true, Ordering::SeqCst);
            }
        }));

        // Deposit 100 USDT
        let (event, deposit) = create_deposit_event(1, 10_000_000_000);
        tracker.on_deposit(&event, &deposit).await;

        // Try to claim 200 USDT (attacker trying to steal)
        let (event, claim) = create_claim_event(1, 200_000_000, "0x5678");
        tracker.on_claim(&event, &claim).await;

        assert!(mismatch_detected.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_address_matching() {
        assert!(addresses_match("0x1234", "0x1234"));
        assert!(addresses_match("0x1234", "1234"));
        assert!(addresses_match("0xABCD", "0xabcd"));
        assert!(!addresses_match("0x1234", "0x5678"));
    }

    #[tokio::test]
    async fn test_status_counts() {
        let tracker = TransferTracker::new();

        // Add deposits
        for i in 1..=3 {
            let (event, deposit) = create_deposit_event(i, 10_000_000_000);
            tracker.on_deposit(&event, &deposit).await;
        }

        // Claim one
        let (event, claim) = create_claim_event(1, 100_000_000, "0x5678");
        tracker.on_claim(&event, &claim).await;

        let (deposited, _, claimed) = tracker.status_counts().await;
        assert_eq!(deposited, 2);
        assert_eq!(claimed, 1);
    }

    #[tokio::test]
    async fn test_handle_reorg_removes_events_after_fork() {
        let tracker = TransferTracker::new();

        // Add deposit at block 100
        let (mut event, deposit) = create_deposit_event(1, 10_000_000_000);
        event.block_number = 100;
        tracker.on_deposit(&event, &deposit).await;

        // Add approval at block 150
        let (mut approval_event, approval) = create_approval_event(1);
        approval_event.block_number = 150;
        tracker.on_approval(&approval_event, &approval).await;

        // Verify both exist
        let record = tracker.get_transfer(&TransferKey::eth(1)).await.unwrap();
        assert!(record.deposit.is_some());
        assert!(record.approval.is_some());

        // Reorg at block 120 - should remove approval but keep deposit
        tracker.handle_reorg(120).await;

        let record = tracker.get_transfer(&TransferKey::eth(1)).await.unwrap();
        assert!(
            record.deposit.is_some(),
            "Deposit at block 100 should remain"
        );
        assert!(
            record.approval.is_none(),
            "Approval at block 150 should be removed"
        );
    }

    #[tokio::test]
    async fn test_handle_reorg_removes_entire_record_if_all_events_gone() {
        let tracker = TransferTracker::new();

        // Add deposit at block 200
        let (mut event, deposit) = create_deposit_event(1, 10_000_000_000);
        event.block_number = 200;
        tracker.on_deposit(&event, &deposit).await;

        assert_eq!(tracker.pending_count().await, 1);

        // Reorg at block 100 - should remove everything
        tracker.handle_reorg(100).await;

        assert_eq!(tracker.pending_count().await, 0);
        assert!(tracker.get_transfer(&TransferKey::eth(1)).await.is_none());
    }

    #[tokio::test]
    async fn test_change_callback_called_on_events() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let callback_count = Arc::new(AtomicU32::new(0));
        let callback_count_clone = callback_count.clone();

        let tracker = TransferTracker::new();
        tracker
            .set_change_callback(Arc::new(move || {
                callback_count_clone.fetch_add(1, Ordering::SeqCst);
            }))
            .await;

        // Add deposit - should trigger callback
        let (event, deposit) = create_deposit_event(1, 10_000_000_000);
        tracker.on_deposit(&event, &deposit).await;
        assert_eq!(callback_count.load(Ordering::SeqCst), 1);

        // Add approval - should trigger callback
        let (event, approval) = create_approval_event(1);
        tracker.on_approval(&event, &approval).await;
        assert_eq!(callback_count.load(Ordering::SeqCst), 2);

        // Add claim - should trigger callback
        let (event, claim) = create_claim_event(1, 100_000_000, "0x5678");
        tracker.on_claim(&event, &claim).await;
        assert_eq!(callback_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_change_callback_called_on_reorg() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let callback_count = Arc::new(AtomicU32::new(0));
        let callback_count_clone = callback_count.clone();

        let tracker = TransferTracker::new();
        tracker
            .set_change_callback(Arc::new(move || {
                callback_count_clone.fetch_add(1, Ordering::SeqCst);
            }))
            .await;

        // Add deposit at block 200
        let (mut event, deposit) = create_deposit_event(1, 10_000_000_000);
        event.block_number = 200;
        tracker.on_deposit(&event, &deposit).await;
        assert_eq!(callback_count.load(Ordering::SeqCst), 1);

        // Reorg at block 100 - should trigger callback once after all removals
        tracker.handle_reorg(100).await;
        assert_eq!(callback_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_get_all_pending_events() {
        let tracker = TransferTracker::new();

        // Add multiple deposits
        for i in 1..=3 {
            let (event, deposit) = create_deposit_event(i, 10_000_000_000);
            tracker.on_deposit(&event, &deposit).await;
        }

        // Add approval for one
        let (event, approval) = create_approval_event(2);
        tracker.on_approval(&event, &approval).await;

        let all_events = tracker.get_all_pending_events().await;
        assert_eq!(all_events.len(), 3);

        // Check that transfer 2 has both deposit and approval
        let key2 = TransferKey::eth(2);
        let events2 = all_events.get(&key2).unwrap();
        assert_eq!(events2.len(), 2); // deposit + approval
    }

    #[tokio::test]
    async fn test_get_events_for_key() {
        let tracker = TransferTracker::new();

        // Add deposit and approval for key 1
        let (event, deposit) = create_deposit_event(1, 10_000_000_000);
        tracker.on_deposit(&event, &deposit).await;

        let (event, approval) = create_approval_event(1);
        tracker.on_approval(&event, &approval).await;

        // Get events for key 1
        let events = tracker.get_events_for_key(&TransferKey::eth(1)).await;
        assert!(events.is_some());
        assert_eq!(events.unwrap().len(), 2);

        // Get events for non-existent key
        let events = tracker.get_events_for_key(&TransferKey::eth(999)).await;
        assert!(events.is_none());
    }

    fn create_approval_event(nonce: u64) -> (PendingEvent, ApprovalEvent) {
        let approval = ApprovalEvent {
            source_chain: ChainId::Eth,
            nonce,
            recorded_chain: ChainId::Starcoin,
            block_number: 150,
        };
        let event = PendingEvent {
            event: PendingEventType::Approval(approval.clone()),
            tx_hash: format!("0xapproval{:056x}", nonce),
            block_number: 150,
            timestamp_ms: 1500000,
            observed_chain: ChainId::Starcoin,
        };
        (event, approval)
    }

    #[tokio::test]
    async fn test_approval_without_deposit_returns_alert() {
        let tracker = TransferTracker::new();

        // Approval without deposit should return MismatchAlert
        let (event, approval) = create_approval_event(999);
        let alert = tracker.on_approval(&event, &approval).await;

        assert!(alert.is_some());
        match alert.unwrap() {
            MismatchAlert::ApprovalWithoutDeposit {
                source_chain,
                nonce,
                ..
            } => {
                assert_eq!(source_chain, ChainId::Eth);
                assert_eq!(nonce, 999);
            }
            _ => panic!("Expected ApprovalWithoutDeposit alert"),
        }
    }

    #[tokio::test]
    async fn test_approval_with_deposit_returns_none() {
        let tracker = TransferTracker::new();

        // First add a deposit
        let (event, deposit) = create_deposit_event(1, 10_000_000_000);
        tracker.on_deposit(&event, &deposit).await;

        // Then approval should return None (no alert)
        let (event, approval) = create_approval_event(1);
        let alert = tracker.on_approval(&event, &approval).await;

        assert!(alert.is_none());
    }

    #[tokio::test]
    async fn test_claim_without_deposit_returns_alert() {
        let tracker = TransferTracker::new();

        // Claim without deposit should return MismatchAlert
        let (event, claim) = create_claim_event(999, 100_000_000, "0x5678");
        let alert = tracker.on_claim(&event, &claim).await;

        assert!(alert.is_some());
        match alert.unwrap() {
            MismatchAlert::ClaimWithoutDeposit {
                source_chain,
                nonce,
                ..
            } => {
                assert_eq!(source_chain, ChainId::Eth);
                assert_eq!(nonce, 999);
            }
            _ => panic!("Expected ClaimWithoutDeposit alert"),
        }
    }

    #[tokio::test]
    async fn test_claim_with_deposit_returns_none() {
        let tracker = TransferTracker::new();

        // First add a deposit
        let (event, deposit) = create_deposit_event(1, 10_000_000_000);
        tracker.on_deposit(&event, &deposit).await;

        // Then claim should return None (no alert)
        let (event, claim) = create_claim_event(1, 100_000_000, "0x5678");
        let alert = tracker.on_claim(&event, &claim).await;

        assert!(alert.is_none());
    }

    #[tokio::test]
    async fn test_get_finalized_records_does_not_remove() {
        let tracker = TransferTracker::new();

        // Add deposits at different blocks
        let (event1, deposit1) = create_deposit_event(1, 10_000_000_000);
        let (event2, deposit2) = create_deposit_event(2, 20_000_000_000);

        tracker.on_deposit(&event1, &deposit1).await;
        tracker.on_deposit(&event2, &deposit2).await;

        // Check initial state
        assert_eq!(tracker.pending_count().await, 2);

        // Get finalized records (all deposits are at block 100)
        let (keys, records) = tracker.get_finalized_records(100).await;

        // Both should be returned
        assert_eq!(keys.len(), 2);
        assert_eq!(records.len(), 2);

        // But memory should NOT be modified
        assert_eq!(tracker.pending_count().await, 2);

        // Can call again and get same results
        let (keys2, records2) = tracker.get_finalized_records(100).await;
        assert_eq!(keys2.len(), 2);
        assert_eq!(records2.len(), 2);
    }

    #[tokio::test]
    async fn test_remove_keys_removes_specified_keys() {
        let tracker = TransferTracker::new();

        // Add three deposits
        for i in 1..=3 {
            let (event, deposit) = create_deposit_event(i, 10_000_000_000);
            tracker.on_deposit(&event, &deposit).await;
        }
        assert_eq!(tracker.pending_count().await, 3);

        // Remove only keys 1 and 2
        let keys_to_remove = vec![TransferKey::eth(1), TransferKey::eth(2)];
        tracker.remove_keys(&keys_to_remove).await;

        // Only key 3 should remain
        assert_eq!(tracker.pending_count().await, 1);
        assert!(!(tracker.has_deposit(&TransferKey::eth(1)).await));
        assert!(!(tracker.has_deposit(&TransferKey::eth(2)).await));
        assert!(tracker.has_deposit(&TransferKey::eth(3)).await);
    }

    #[tokio::test]
    async fn test_db_first_pattern_workflow() {
        // Test the complete "DB-first" workflow:
        // 1. Get finalized records (memory unchanged)
        // 2. Simulate DB write success
        // 3. Remove keys (memory cleaned up)

        let tracker = TransferTracker::new();

        // Add deposits
        let (event, deposit) = create_deposit_event(1, 10_000_000_000);
        tracker.on_deposit(&event, &deposit).await;
        let (event, deposit) = create_deposit_event(2, 20_000_000_000);
        tracker.on_deposit(&event, &deposit).await;

        assert_eq!(tracker.pending_count().await, 2);

        // Step 1: Get finalized records
        let (keys, records) = tracker.get_finalized_records(100).await;
        assert_eq!(records.len(), 2);
        assert_eq!(tracker.pending_count().await, 2); // Still in memory!

        // Step 2: Simulate DB write success (would write records here)
        // ...

        // Step 3: Remove from memory after DB success
        tracker.remove_keys(&keys).await;
        assert_eq!(tracker.pending_count().await, 0); // Now cleaned up
    }
}
