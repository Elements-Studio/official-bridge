//! Event Organizer
//!
//! Provides deposit lookup for approval verification from two data sources:
//! - TransferTracker: in-memory pending (unfinalized) events
//! - Database: persisted finalized events
//!
//! Also handles:
//! - Querying unchecked approvals from DB (for periodic scan)
//! - Marking verified approvals in DB

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use starcoin_bridge::pending_events::{ChainId, DepositEvent, TransferKey, TransferTracker};
use starcoin_bridge_pg_db::Db;
use starcoin_bridge_schema::models::{TokenTransfer, TokenTransferData};
use starcoin_bridge_schema::schema::token_transfer::dsl as tt_status_dsl;
use starcoin_bridge_schema::schema::token_transfer_data::dsl as tt_dsl;
use tracing::{debug, info, warn};

use crate::network::NetworkType;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

/// Trait for deposit lookup and approval management, enabling testability.
///
/// `SecurityMonitor` depends on this trait rather than concrete `EventOrganizer`,
/// so behavioral tests can use a mock implementation without a real database.
#[async_trait]
pub(crate) trait DepositLookup: Send + Sync {
    /// Find deposit for (source_chain, nonce). Checks memory first, then DB.
    async fn find_deposit(&self, key: &TransferKey) -> Result<Option<DepositEventData>>;

    /// Get approvals from DB that haven't been verified yet.
    async fn get_unchecked_approvals(&self, limit: i64) -> Result<Vec<UncheckedApproval>>;

    /// Mark a deposit as monitor_verified.
    async fn mark_verified(&self, source_chain: ChainId, nonce: u64) -> Result<()>;
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
}

/// An approval record from DB that needs verification
#[derive(Debug, Clone)]
pub struct UncheckedApproval {
    pub source_chain: ChainId,
    pub nonce: u64,
    pub tx_hash: String,
    pub block_height: u64,
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
            tx_hash: String::new(),
            block_height: e.block_number,
        }
    }
}

/// Gathers deposit data from memory and DB for approval verification.
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

    /// Find the deposit for a given (source_chain, nonce), checking memory first then DB.
    ///
    /// This is the core lookup used by both real-time and periodic scan paths.
    pub async fn find_deposit(&self, key: &TransferKey) -> Result<Option<DepositEventData>> {
        // 1. Check in-memory TransferTracker (pending + finalized deposits)
        if let Some(deposit) = self.find_deposit_in_memory(key).await {
            return Ok(Some(deposit));
        }

        // 2. Fall back to DB
        self.find_deposit_in_db(key).await
    }

    /// Check in-memory TransferTracker for deposit
    async fn find_deposit_in_memory(&self, key: &TransferKey) -> Option<DepositEventData> {
        use starcoin_bridge::pending_events::PendingEventType;

        let events = self.transfer_tracker.get_events_for_key(key).await?;
        for pending in events {
            if let PendingEventType::Deposit(deposit) = &pending.event {
                let mut data = DepositEventData::from(deposit);
                data.tx_hash = pending.tx_hash.clone();
                return Some(data);
            }
        }
        None
    }

    /// Query DB for deposit matching (source_chain, nonce)
    async fn find_deposit_in_db(&self, key: &TransferKey) -> Result<Option<DepositEventData>> {
        let chain_id = self.network.chain_id_to_bridge_i32(key.source_chain);
        let nonce = key.nonce as i64;

        let mut conn = self.db.connect().await?;

        // Deposit: chain_id = source_chain, destination_chain != chain_id
        let transfer: Option<TokenTransferData> = tt_dsl::token_transfer_data
            .filter(tt_dsl::chain_id.eq(chain_id))
            .filter(tt_dsl::nonce.eq(nonce))
            .filter(tt_dsl::destination_chain.ne(chain_id))
            .first(&mut conn)
            .await
            .optional()?;

        Ok(transfer.map(|t| {
            let source_chain = self.chain_id_to_enum(t.chain_id);
            DepositEventData {
                source_chain,
                nonce: t.nonce as u64,
                destination_chain: self.chain_id_to_enum(t.destination_chain),
                token_id: t.token_id as u8,
                amount: t.amount as u64,
                sender_address: hex::encode(&t.sender_address),
                recipient_address: hex::encode(&t.recipient_address),
                tx_hash: hex::encode(&t.txn_hash),
                block_height: t.block_height as u64,
            }
        }))
    }

    /// Get approvals from DB that haven't been verified yet.
    ///
    /// Two-phase approach:
    ///   1. Load the set of already-verified (chain_id, nonce) deposit pairs.
    ///   2. Load all Approved records, filter out verified ones, take up to `limit`.
    ///
    /// This ensures LIMIT applies AFTER filtering, so verified old records
    /// cannot push genuinely unchecked approvals out of the result window.
    pub async fn get_unchecked_approvals(&self, limit: i64) -> Result<Vec<UncheckedApproval>> {
        let mut conn = self.db.connect().await?;
        let stc_bridge_id = self.network.chain_id_to_bridge_i32(ChainId::Starcoin);
        let eth_bridge_id = self.network.chain_id_to_bridge_i32(ChainId::Eth);

        // Phase 1: Build a set of verified (source_chain_id, nonce) deposit pairs.
        // Size = number of verified deposits, bounded and grows slowly.
        let verified: Vec<(i32, i64)> = tt_dsl::token_transfer_data
            .select((tt_dsl::chain_id, tt_dsl::nonce))
            .filter(tt_dsl::monitor_verified.eq(true))
            .load(&mut conn)
            .await?;
        let verified_set: HashSet<(i32, i64)> = verified.into_iter().collect();

        // Phase 2: Load Approved records on known chains, ordered by block_height.
        // Total count = number of bridge transfers (bounded for a cross-chain bridge).
        let approvals: Vec<TokenTransfer> = tt_status_dsl::token_transfer
            .filter(tt_status_dsl::status.eq("Approved"))
            .filter(
                tt_status_dsl::chain_id
                    .eq(stc_bridge_id)
                    .or(tt_status_dsl::chain_id.eq(eth_bridge_id)),
            )
            .order(tt_status_dsl::block_height.asc())
            .load(&mut conn)
            .await?;

        // Filter: keep approvals whose source-chain deposit is NOT yet verified.
        // approval.chain_id = recording/destination chain; source = OTHER chain.
        let mut unchecked = Vec::new();
        for approval in &approvals {
            if unchecked.len() >= limit as usize {
                break;
            }

            let source_chain_id = if approval.chain_id == stc_bridge_id {
                eth_bridge_id
            } else {
                stc_bridge_id
            };

            if verified_set.contains(&(source_chain_id, approval.nonce)) {
                continue;
            }

            unchecked.push(UncheckedApproval {
                source_chain: self.chain_id_to_enum(source_chain_id),
                nonce: approval.nonce as u64,
                tx_hash: hex::encode(&approval.txn_hash),
                block_height: approval.block_height as u64,
            });
        }

        if !unchecked.is_empty() {
            debug!(
                "[EventOrganizer] Found {} unchecked approvals in DB",
                unchecked.len()
            );
        }

        Ok(unchecked)
    }

    /// Mark a deposit as monitor_verified after successful approval verification.
    pub async fn mark_verified(&self, source_chain: ChainId, nonce: u64) -> Result<()> {
        let chain_id = self.network.chain_id_to_bridge_i32(source_chain);
        let nonce_i64 = nonce as i64;

        let mut conn = self.db.connect().await?;

        let updated = diesel::update(
            tt_dsl::token_transfer_data
                .filter(tt_dsl::chain_id.eq(chain_id))
                .filter(tt_dsl::nonce.eq(nonce_i64)),
        )
        .set(tt_dsl::monitor_verified.eq(true))
        .execute(&mut conn)
        .await?;

        if updated > 0 {
            info!(
                "[EventOrganizer] Marked verified: source_chain={:?}, nonce={}",
                source_chain, nonce
            );
        } else {
            warn!(
                "[EventOrganizer] No deposit found to mark verified: source_chain={:?}, nonce={}",
                source_chain, nonce
            );
        }

        Ok(())
    }

    fn chain_id_to_enum(&self, chain_id: i32) -> ChainId {
        self.network.bridge_i32_to_chain_id(chain_id)
    }
}

#[async_trait]
impl DepositLookup for EventOrganizer {
    async fn find_deposit(&self, key: &TransferKey) -> Result<Option<DepositEventData>> {
        self.find_deposit(key).await
    }

    async fn get_unchecked_approvals(&self, limit: i64) -> Result<Vec<UncheckedApproval>> {
        self.get_unchecked_approvals(limit).await
    }

    async fn mark_verified(&self, source_chain: ChainId, nonce: u64) -> Result<()> {
        self.mark_verified(source_chain, nonce).await
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
        assert_eq!(data.token_id, 4);
    }
}
