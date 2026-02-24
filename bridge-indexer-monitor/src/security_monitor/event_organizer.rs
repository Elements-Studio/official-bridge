//! Event Organizer Module
//!
//! Responsible for organizing bridge events into (deposit, approval, claim) pairs
//! for mismatch checking. Data sources:
//! - TransferTracker: in-memory pending events
//! - Database: persisted events
//!
//! This module provides a unified interface for gathering events from different
//! sources and organizing them into checkable pairs.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use starcoin_bridge::pending_events::{
    ApprovalEvent, ChainId, ClaimEvent, DepositEvent, PendingEventType, TransferKey,
    TransferTracker,
};
use starcoin_bridge_pg_db::Db;
use starcoin_bridge_schema::models::TokenTransferData;
use starcoin_bridge_schema::schema::token_transfer_data::dsl as tt_dsl;
use tracing::{debug, warn};

use crate::network::NetworkType;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

/// Event pair for mismatch checking
#[derive(Debug, Clone)]
pub struct EventPair {
    pub key: TransferKey,
    pub deposit: Option<DepositEventData>,
    pub approval: Option<ApprovalEventData>,
    pub claim: Option<ClaimEventData>,
}

/// Deposit event data (unified from memory/DB)
#[derive(Debug, Clone)]
pub struct DepositEventData {
    pub source_chain: ChainId,
    pub nonce: u64,
    pub destination_chain: ChainId,
    pub token_id: u8,
    pub amount: u64,
    pub sender_address: String,
    pub recipient_address: String,
    pub tx_hash: String,
    pub block_height: u64,
    pub from_db: bool,
}

/// Approval event data (unified from memory/DB)
#[derive(Debug, Clone)]
pub struct ApprovalEventData {
    pub source_chain: ChainId,
    pub nonce: u64,
    pub recorded_chain: ChainId,
    pub tx_hash: String,
    pub block_height: u64,
    pub from_db: bool,
}

/// Claim event data (unified from memory/DB)
#[derive(Debug, Clone)]
pub struct ClaimEventData {
    pub source_chain: ChainId,
    pub nonce: u64,
    pub destination_chain: ChainId,
    pub token_id: u8,
    pub amount: u64,
    pub recipient_address: String,
    pub claimer_address: String,
    pub tx_hash: String,
    pub block_height: u64,
    pub from_db: bool,
}

impl From<&DepositEvent> for DepositEventData {
    fn from(e: &DepositEvent) -> Self {
        Self {
            source_chain: e.source_chain,
            nonce: e.nonce,
            destination_chain: e.destination_chain,
            token_id: e.token_id,
            amount: e.amount,
            sender_address: e.sender_address.clone(),
            recipient_address: e.recipient_address.clone(),
            tx_hash: String::new(), // Will be set from PendingEvent
            block_height: e.block_number,
            from_db: false,
        }
    }
}

impl From<&ApprovalEvent> for ApprovalEventData {
    fn from(e: &ApprovalEvent) -> Self {
        Self {
            source_chain: e.source_chain,
            nonce: e.nonce,
            recorded_chain: e.recorded_chain,
            tx_hash: String::new(), // Will be set from PendingEvent
            block_height: e.block_number,
            from_db: false,
        }
    }
}

impl From<&ClaimEvent> for ClaimEventData {
    fn from(e: &ClaimEvent) -> Self {
        Self {
            source_chain: e.source_chain,
            nonce: e.nonce,
            destination_chain: e.destination_chain,
            token_id: e.token_id,
            amount: e.amount,
            recipient_address: e.recipient_address.clone(),
            claimer_address: e.claimer_address.clone(),
            tx_hash: String::new(), // Will be set from PendingEvent
            block_height: e.block_number,
            from_db: false,
        }
    }
}

/// Event Organizer
///
/// Gathers events from TransferTracker and/or DB, organizes them into
/// (deposit, approval, claim) pairs by TransferKey.
pub struct EventOrganizer {
    transfer_tracker: Arc<TransferTracker>,
    db: Db,
    network: NetworkType,
}

impl EventOrganizer {
    pub fn new(transfer_tracker: Arc<TransferTracker>, db: Db, network: NetworkType) -> Self {
        Self {
            transfer_tracker,
            db,
            network,
        }
    }

    /// Get all event pairs from in-memory TransferTracker
    ///
    /// This is called when we want to check pending (unfinalized) events.
    pub async fn get_pending_pairs(&self) -> Vec<EventPair> {
        let mut pairs: HashMap<TransferKey, EventPair> = HashMap::new();

        // Get all pending events from tracker
        let pending_events = self.transfer_tracker.get_all_pending_events().await;

        for (key, events) in pending_events {
            let pair = pairs.entry(key).or_insert_with(|| EventPair {
                key,
                deposit: None,
                approval: None,
                claim: None,
            });

            for pending in events {
                match &pending.event {
                    PendingEventType::Deposit(deposit) => {
                        let mut data = DepositEventData::from(deposit);
                        data.tx_hash = pending.tx_hash.clone();
                        pair.deposit = Some(data);
                    }
                    PendingEventType::Approval(approval) => {
                        let mut data = ApprovalEventData::from(approval);
                        data.tx_hash = pending.tx_hash.clone();
                        pair.approval = Some(data);
                    }
                    PendingEventType::Claim(claim) => {
                        let mut data = ClaimEventData::from(claim);
                        data.tx_hash = pending.tx_hash.clone();
                        pair.claim = Some(data);
                    }
                }
            }
        }

        pairs.into_values().collect()
    }

    /// Get event pair for a specific key, combining memory and DB data
    ///
    /// This is used when a new event arrives and we want to check it with
    /// any existing data from both memory and DB.
    pub async fn get_pair_for_key(&self, key: &TransferKey) -> Result<EventPair> {
        let mut pair = EventPair {
            key: *key,
            deposit: None,
            approval: None,
            claim: None,
        };

        // First, check memory
        if let Some(events) = self.transfer_tracker.get_events_for_key(key).await {
            for pending in events {
                match &pending.event {
                    PendingEventType::Deposit(deposit) => {
                        let mut data = DepositEventData::from(deposit);
                        data.tx_hash = pending.tx_hash.clone();
                        pair.deposit = Some(data);
                    }
                    PendingEventType::Approval(approval) => {
                        let mut data = ApprovalEventData::from(approval);
                        data.tx_hash = pending.tx_hash.clone();
                        pair.approval = Some(data);
                    }
                    PendingEventType::Claim(claim) => {
                        let mut data = ClaimEventData::from(claim);
                        data.tx_hash = pending.tx_hash.clone();
                        pair.claim = Some(data);
                    }
                }
            }
        }

        // Then, check DB for any missing pieces
        // Use network-aware chain ID conversion for DB queries
        let chain_id = self.network.chain_id_to_bridge_i32(key.source_chain);

        if let Err(e) = self
            .fill_from_db(&mut pair, chain_id, key.nonce as i64)
            .await
        {
            warn!(
                "[EventOrganizer] Failed to query DB for key {:?}: {}",
                key, e
            );
        }

        Ok(pair)
    }

    /// Get unchecked pairs from database
    ///
    /// This queries the DB for transfers that haven't been verified by the monitor yet.
    /// Returns pairs organized by (source_chain, nonce).
    pub async fn get_unchecked_pairs_from_db(&self, limit: i64) -> Result<Vec<EventPair>> {
        let mut conn = self.db.connect().await?;

        // Query transfers that are not yet monitor_verified
        // Group by (chain_id, nonce) to form pairs
        let transfers: Vec<TokenTransferData> = tt_dsl::token_transfer_data
            .filter(tt_dsl::monitor_verified.eq(false))
            .order(tt_dsl::block_height.asc())
            .limit(limit)
            .load(&mut conn)
            .await?;

        if transfers.is_empty() {
            return Ok(vec![]);
        }

        debug!(
            "[EventOrganizer] Found {} unchecked transfers in DB",
            transfers.len()
        );

        // Organize into pairs by (source_chain_id, nonce)
        // For deposits: source_chain = chain_id (where deposit is recorded)
        // For claims: source_chain = the OTHER chain (since claim is on destination)
        let mut pairs: HashMap<(i32, i64), EventPair> = HashMap::new();

        for transfer in transfers {
            let tx_hash = hex::encode(&transfer.txn_hash);

            // Determine event type and source_chain based on chain relationship
            if transfer.destination_chain != transfer.chain_id {
                // This is a deposit (recorded on source chain)
                // source_chain = chain_id
                let source_chain = self.chain_id_to_enum(transfer.chain_id);
                let key = TransferKey::new(source_chain, transfer.nonce as u64);

                let pair = pairs
                    .entry((transfer.chain_id, transfer.nonce))
                    .or_insert_with(|| EventPair {
                        key,
                        deposit: None,
                        approval: None,
                        claim: None,
                    });

                pair.deposit = Some(DepositEventData {
                    source_chain,
                    nonce: transfer.nonce as u64,
                    destination_chain: self.chain_id_to_enum(transfer.destination_chain),
                    token_id: transfer.token_id as u8,
                    amount: transfer.amount as u64,
                    sender_address: hex::encode(&transfer.sender_address),
                    recipient_address: hex::encode(&transfer.recipient_address),
                    tx_hash,
                    block_height: transfer.block_height as u64,
                    from_db: true,
                });
            } else {
                // This is a claim (recorded on destination chain)
                // source_chain = the OTHER chain (not where the claim was recorded)
                // Since we only have ETH and STC, source = the chain that isn't destination
                let source_chain_id = self.get_other_chain_id(transfer.chain_id);
                let source_chain = self.chain_id_to_enum(source_chain_id);
                let key = TransferKey::new(source_chain, transfer.nonce as u64);

                let pair = pairs
                    .entry((source_chain_id, transfer.nonce))
                    .or_insert_with(|| EventPair {
                        key,
                        deposit: None,
                        approval: None,
                        claim: None,
                    });

                pair.claim = Some(ClaimEventData {
                    source_chain,
                    nonce: transfer.nonce as u64,
                    destination_chain: self.chain_id_to_enum(transfer.destination_chain),
                    token_id: transfer.token_id as u8,
                    amount: transfer.amount as u64,
                    recipient_address: hex::encode(&transfer.recipient_address),
                    claimer_address: hex::encode(&transfer.sender_address),
                    tx_hash,
                    block_height: transfer.block_height as u64,
                    from_db: true,
                });
            }
        }

        // CRITICAL: Fill in missing deposits for pairs that have approvals or claims but no deposit
        // This handles the case where deposit was already verified but approval/claim is not
        let mut result_pairs: Vec<EventPair> = Vec::new();
        for ((source_chain_id, nonce), mut pair) in pairs {
            // Fill deposit if we have approval or claim but no deposit
            if (pair.approval.is_some() || pair.claim.is_some()) && pair.deposit.is_none() {
                // Query for the deposit on the source chain (may already be verified)
                if let Err(e) = self
                    .fill_deposit_from_db(&mut pair, source_chain_id, nonce)
                    .await
                {
                    warn!(
                        "[EventOrganizer] Failed to fill deposit for source_chain={}, nonce={}: {}",
                        source_chain_id, nonce, e
                    );
                }
            }
            result_pairs.push(pair);
        }

        Ok(result_pairs)
    }

    /// Fill missing parts of an event pair from the database
    async fn fill_from_db(&self, pair: &mut EventPair, chain_id: i32, nonce: i64) -> Result<()> {
        let mut conn = self.db.connect().await?;

        // Query deposits: chain_id = source_chain (where deposit was made)
        // and destination_chain != chain_id (to ensure it's a deposit from this chain, not a claim)
        let deposit_transfers: Vec<TokenTransferData> = tt_dsl::token_transfer_data
            .filter(tt_dsl::nonce.eq(nonce))
            .filter(tt_dsl::chain_id.eq(chain_id))
            .filter(tt_dsl::destination_chain.ne(chain_id))
            .load(&mut conn)
            .await?;

        // Query claims: Claims are recorded on destination chain where destination_chain = chain_id
        // and source chain is the other chain
        let other_chain_id = self.get_other_chain_id(chain_id);
        let claim_transfers: Vec<TokenTransferData> = tt_dsl::token_transfer_data
            .filter(tt_dsl::nonce.eq(nonce))
            .filter(tt_dsl::chain_id.eq(other_chain_id))
            .filter(tt_dsl::destination_chain.eq(other_chain_id))
            .load(&mut conn)
            .await?;

        for transfer in deposit_transfers.into_iter() {
            let tx_hash = hex::encode(&transfer.txn_hash);

            if pair.deposit.is_none() {
                let source_chain = self.chain_id_to_enum(transfer.chain_id);
                pair.deposit = Some(DepositEventData {
                    source_chain,
                    nonce: transfer.nonce as u64,
                    destination_chain: self.chain_id_to_enum(transfer.destination_chain),
                    token_id: transfer.token_id as u8,
                    amount: transfer.amount as u64,
                    sender_address: hex::encode(&transfer.sender_address),
                    recipient_address: hex::encode(&transfer.recipient_address),
                    tx_hash,
                    block_height: transfer.block_height as u64,
                    from_db: true,
                });
            }
        }

        for transfer in claim_transfers.into_iter() {
            let tx_hash = hex::encode(&transfer.txn_hash);

            if pair.claim.is_none() {
                // source_chain is the OTHER chain (deposit was on source, claim is on destination)
                let source_chain = self.chain_id_to_enum(chain_id);
                pair.claim = Some(ClaimEventData {
                    source_chain,
                    nonce: transfer.nonce as u64,
                    destination_chain: self.chain_id_to_enum(transfer.destination_chain),
                    token_id: transfer.token_id as u8,
                    amount: transfer.amount as u64,
                    recipient_address: hex::encode(&transfer.recipient_address),
                    claimer_address: hex::encode(&transfer.sender_address),
                    tx_hash,
                    block_height: transfer.block_height as u64,
                    from_db: true,
                });
            }
        }

        Ok(())
    }

    /// Fill deposit from DB for a specific (source_chain, nonce), regardless of verified status
    /// This is used when we find an unchecked claim but the deposit was already verified.
    async fn fill_deposit_from_db(
        &self,
        pair: &mut EventPair,
        source_chain_id: i32,
        nonce: i64,
    ) -> Result<()> {
        let mut conn = self.db.connect().await?;

        // Query for deposit: chain_id = source_chain, destination_chain != chain_id
        let transfers: Vec<TokenTransferData> = tt_dsl::token_transfer_data
            .filter(tt_dsl::chain_id.eq(source_chain_id))
            .filter(tt_dsl::nonce.eq(nonce))
            .filter(tt_dsl::destination_chain.ne(source_chain_id))
            .load(&mut conn)
            .await?;

        for transfer in transfers {
            if pair.deposit.is_none() {
                let source_chain = self.chain_id_to_enum(transfer.chain_id);
                let tx_hash = hex::encode(&transfer.txn_hash);
                pair.deposit = Some(DepositEventData {
                    source_chain,
                    nonce: transfer.nonce as u64,
                    destination_chain: self.chain_id_to_enum(transfer.destination_chain),
                    token_id: transfer.token_id as u8,
                    amount: transfer.amount as u64,
                    sender_address: hex::encode(&transfer.sender_address),
                    recipient_address: hex::encode(&transfer.recipient_address),
                    tx_hash,
                    block_height: transfer.block_height as u64,
                    from_db: true,
                });
                debug!(
                    "[EventOrganizer] Filled missing deposit for source_chain={}, nonce={}",
                    source_chain_id, nonce
                );
                break;
            }
        }

        Ok(())
    }

    /// Convert chain_id (stored as enum value in DB) to ChainId enum
    /// DB stores: Starcoin=0, Eth=1
    fn chain_id_to_enum(&self, chain_id: i32) -> ChainId {
        if chain_id == ChainId::Starcoin as i32 {
            ChainId::Starcoin
        } else {
            ChainId::Eth
        }
    }

    /// Get the other chain ID (for claims where we need to determine source)
    /// Since we only have ETH and STC, source = the chain that isn't destination
    /// Uses DB enum values: Starcoin=0, Eth=1
    fn get_other_chain_id(&self, chain_id: i32) -> i32 {
        if chain_id == ChainId::Starcoin as i32 {
            ChainId::Eth as i32
        } else {
            ChainId::Starcoin as i32
        }
    }

    /// Check if a deposit exists for the given key (memory or DB)
    ///
    /// This is used to re-verify deferred alerts after grace period.
    pub async fn deposit_exists(&self, key: &TransferKey) -> bool {
        // First check TransferTracker (pending + finalized memory)
        if self.transfer_tracker.has_deposit(key).await {
            return true;
        }

        // Then check DB
        let chain_id = self.network.chain_id_to_bridge_i32(key.source_chain);
        let nonce = key.nonce as i64;

        if let Ok(mut conn) = self.db.connect().await {
            // Query for deposit record in token_transfer_data
            let result: Result<Option<TokenTransferData>, _> = tt_dsl::token_transfer_data
                .filter(tt_dsl::chain_id.eq(chain_id))
                .filter(tt_dsl::nonce.eq(nonce))
                .filter(tt_dsl::destination_chain.ne(chain_id)) // deposit: source != destination
                .first(&mut conn)
                .await
                .optional();

            if let Ok(Some(_)) = result {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deposit_event_data_from() {
        let deposit = DepositEvent {
            source_chain: ChainId::Eth,
            nonce: 123,
            destination_chain: ChainId::Starcoin,
            token_id: 4,
            amount: 1000000,
            sender_address: "0x1234".to_string(),
            recipient_address: "0xabcd".to_string(),
            block_number: 100,
        };

        let data = DepositEventData::from(&deposit);
        assert_eq!(data.nonce, 123);
        assert_eq!(data.amount, 1000000);
        assert!(!data.from_db);
    }

    #[test]
    fn test_event_pair_creation() {
        let key = TransferKey::new(ChainId::Eth, 100);
        let pair = EventPair {
            key,
            deposit: None,
            approval: None,
            claim: None,
        };

        assert!(pair.deposit.is_none());
        assert!(pair.approval.is_none());
        assert!(pair.claim.is_none());
    }
}
