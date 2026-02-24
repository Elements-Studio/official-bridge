// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A mock implementation of Starcoin JSON-RPC client.

use crate::error::{BridgeError, BridgeResult};
use async_trait::async_trait;
use starcoin_bridge_json_rpc_types::StarcoinTransactionBlockResponse;
use starcoin_bridge_json_rpc_types::{EventFilter, EventPage, StarcoinEvent};
use starcoin_bridge_types::base_types::TransactionDigest;
use starcoin_bridge_types::bridge::{
    BridgeCommitteeSummary, BridgeSummary, MoveTypeParsedTokenTransferMessage,
};
use starcoin_bridge_types::event::EventID;
use starcoin_bridge_types::transaction::Transaction;
use starcoin_bridge_types::Identifier;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use crate::starcoin_bridge_client::StarcoinClientInner;
use crate::types::{BridgeAction, BridgeActionStatus, IsBridgePaused};

/// Event key type for mock client - uses (address_hex, module, cursor)
type EventKey = (String, Identifier, Option<EventID>);

// Mock client used in test environments.
#[allow(clippy::type_complexity)]
#[derive(Clone, Debug)]
pub struct StarcoinMockClient {
    // the top two fields do not change during tests so we don't need them to be Arc<Mutex>>
    chain_identifier: String,
    latest_block_number: Arc<AtomicU64>,
    events: Arc<Mutex<HashMap<EventKey, EventPage>>>,
    past_event_query_params: Arc<Mutex<VecDeque<EventKey>>>,
    events_by_tx_digest: Arc<
        Mutex<
            HashMap<
                TransactionDigest,
                Result<Vec<StarcoinEvent>, starcoin_bridge_sdk::error::Error>,
            >,
        >,
    >,
    transaction_responses:
        Arc<Mutex<HashMap<TransactionDigest, BridgeResult<StarcoinTransactionBlockResponse>>>>,
    wildcard_transaction_response:
        Arc<Mutex<Option<BridgeResult<StarcoinTransactionBlockResponse>>>>,
    onchain_status: Arc<Mutex<HashMap<(u8, u64), BridgeActionStatus>>>,
    bridge_committee_summary: Arc<Mutex<Option<BridgeCommitteeSummary>>>,
    is_paused: Arc<Mutex<Option<IsBridgePaused>>>,
    requested_transactions_tx: tokio::sync::broadcast::Sender<TransactionDigest>,
    // Mock for sign_and_submit_transaction
    sign_and_submit_responses: Arc<Mutex<VecDeque<BridgeResult<String>>>>,
    wildcard_sign_and_submit_response: Arc<Mutex<Option<BridgeResult<String>>>>,
}

impl StarcoinMockClient {
    pub fn default() -> Self {
        Self {
            chain_identifier: "".to_string(),
            latest_block_number: Arc::new(AtomicU64::new(0)),
            events: Default::default(),
            past_event_query_params: Default::default(),
            events_by_tx_digest: Default::default(),
            transaction_responses: Default::default(),
            wildcard_transaction_response: Default::default(),
            onchain_status: Default::default(),
            bridge_committee_summary: Default::default(),
            is_paused: Default::default(),
            requested_transactions_tx: tokio::sync::broadcast::channel(10000).0,
            sign_and_submit_responses: Default::default(),
            wildcard_sign_and_submit_response: Default::default(),
        }
    }

    pub fn add_events_by_tx_digest(
        &self,
        tx_digest: TransactionDigest,
        events: Vec<StarcoinEvent>,
    ) {
        self.events_by_tx_digest
            .lock()
            .unwrap()
            .insert(tx_digest, Ok(events));
    }

    pub fn add_events_by_tx_digest_error(&self, tx_digest: TransactionDigest) {
        self.events_by_tx_digest.lock().unwrap().insert(
            tx_digest,
            Err(starcoin_bridge_sdk::error::Error::StarcoinError(
                "".to_string(),
            )),
        );
    }

    pub fn set_action_onchain_status(&self, action: &BridgeAction, status: BridgeActionStatus) {
        self.onchain_status
            .lock()
            .unwrap()
            .insert((action.chain_id() as u8, action.seq_number()), status);
    }

    pub fn set_bridge_committee(&self, committee: BridgeCommitteeSummary) {
        self.bridge_committee_summary
            .lock()
            .unwrap()
            .replace(committee);
    }

    pub fn set_is_bridge_paused(&self, value: IsBridgePaused) {
        self.is_paused.lock().unwrap().replace(value);
    }

    pub fn set_wildcard_transaction_response(
        &self,
        response: BridgeResult<StarcoinTransactionBlockResponse>,
    ) {
        *self.wildcard_transaction_response.lock().unwrap() = Some(response);
    }

    pub fn set_latest_block_number(&self, value: u64) {
        self.latest_block_number
            .store(value, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn subscribe_to_requested_transactions(
        &self,
    ) -> tokio::sync::broadcast::Receiver<TransactionDigest> {
        self.requested_transactions_tx.subscribe()
    }

    /// Set a wildcard response for sign_and_submit_transaction (used when queue is empty)
    pub fn set_wildcard_sign_and_submit_response(&self, response: BridgeResult<String>) {
        *self.wildcard_sign_and_submit_response.lock().unwrap() = Some(response);
    }
}

#[async_trait]
impl StarcoinClientInner for StarcoinMockClient {
    type Error = starcoin_bridge_sdk::error::Error;

    fn bridge_address(&self) -> &str {
        // Return the actual bridge address used in init_all_struct_tags()
        // This matches BRIDGE_PACKAGE_ID[16..32] = 0x0b8e0206e990e41e913a7f03d1c60675
        "0x0b8e0206e990e41e913a7f03d1c60675"
    }

    // Unwraps in this function: We assume the responses are pre-populated
    // by the test before calling into this function.
    async fn query_events(
        &self,
        query: EventFilter,
        cursor: Option<EventID>,
    ) -> Result<EventPage, Self::Error> {
        let events = self.events.lock().unwrap();

        // EventFilter is now a struct with type_tags field
        // Extract module info from type_tags if available
        if let Some(type_tags) = &query.type_tags {
            if let Some(first_tag) = type_tags.first() {
                // Parse module and package from type tag string
                // Format: "0x{address}::{module}::{struct}"
                let parts: Vec<&str> = first_tag.split("::").collect();
                if parts.len() >= 2 {
                    let address = parts[0].trim_start_matches("0x").to_string();
                    let module = parts[1].to_string();
                    let module_id = Identifier::new(module.as_str()).unwrap();
                    let key = (address.clone(), module_id.clone(), cursor);
                    self.past_event_query_params
                        .lock()
                        .unwrap()
                        .push_back(key.clone());
                    return Ok(events.get(&key).cloned().unwrap_or_else(|| {
                        panic!(
                            "No preset events found for type_tag: {:?}, cursor: {:?}",
                            first_tag, cursor
                        )
                    }));
                }
            }
        }

        // Default: return empty page
        Ok(EventPage {
            data: vec![],
            next_cursor: None,
            has_next_page: false,
        })
    }

    async fn get_events_by_tx_digest(
        &self,
        tx_digest: TransactionDigest,
    ) -> Result<Vec<StarcoinEvent>, Self::Error> {
        let events = self.events_by_tx_digest.lock().unwrap();

        match events
            .get(&tx_digest)
            .unwrap_or_else(|| panic!("No preset events found for tx_digest: {:?}", tx_digest))
        {
            Ok(events) => Ok(events.clone()),
            // starcoin_bridge_sdk::error::Error is not Clone
            Err(_) => Err(starcoin_bridge_sdk::error::Error::StarcoinError(
                "Mock error".to_string(),
            )),
        }
    }

    async fn get_chain_identifier(&self) -> Result<String, Self::Error> {
        Ok(self.chain_identifier.clone())
    }

    async fn get_chain_id(&self) -> Result<u8, Self::Error> {
        // Parse chain_id from chain_identifier string (default to 255 for test)
        Ok(self.chain_identifier.parse().unwrap_or(255))
    }

    async fn get_latest_block_number(&self) -> Result<u64, Self::Error> {
        Ok(self
            .latest_block_number
            .load(std::sync::atomic::Ordering::Relaxed))
    }

    async fn get_reference_gas_price(&self) -> Result<u64, Self::Error> {
        Ok(1000)
    }

    async fn get_bridge_summary(&self) -> Result<BridgeSummary, Self::Error> {
        Ok(BridgeSummary {
            bridge_version: 0,
            message_version: 0,
            chain_id: 0,
            sequence_nums: vec![],
            is_frozen: self.is_paused.lock().unwrap().unwrap_or_default(),
            limiter: Default::default(),
            committee: self
                .bridge_committee_summary
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_default(),
            treasury: Default::default(),
        })
    }

    async fn get_token_transfer_action_onchain_status(
        &self,
        source_chain_id: u8,
        seq_number: u64,
    ) -> Result<BridgeActionStatus, BridgeError> {
        Ok(self
            .onchain_status
            .lock()
            .unwrap()
            .get(&(source_chain_id, seq_number))
            .cloned()
            .unwrap_or(BridgeActionStatus::Pending))
    }

    async fn get_token_transfer_action_onchain_signatures(
        &self,
        _source_chain_id: u8,
        _seq_number: u64,
    ) -> Result<Option<Vec<Vec<u8>>>, BridgeError> {
        unimplemented!()
    }

    async fn get_parsed_token_transfer_message(
        &self,
        _source_chain_id: u8,
        _seq_number: u64,
    ) -> Result<Option<MoveTypeParsedTokenTransferMessage>, BridgeError> {
        unimplemented!()
    }

    async fn execute_transaction_block_with_effects(
        &self,
        tx: Transaction,
    ) -> Result<StarcoinTransactionBlockResponse, BridgeError> {
        self.requested_transactions_tx.send(*tx.digest()).unwrap();
        match self.transaction_responses.lock().unwrap().get(tx.digest()) {
            Some(response) => response.clone(),
            None => self
                .wildcard_transaction_response
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| panic!("No preset transaction response found for tx: {:?}", tx)),
        }
    }

    async fn get_sequence_number(&self, _: &str) -> Result<u64, BridgeError> {
        // Mock implementation for testing
        Ok(0)
    }

    async fn get_block_timestamp(&self) -> Result<u64, BridgeError> {
        // Mock implementation: return current system time in milliseconds
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64)
    }

    async fn sign_and_submit_transaction(
        &self,
        _: &starcoin_bridge_types::crypto::StarcoinKeyPair,
        _: starcoin_bridge_types::transaction::RawUserTransaction,
    ) -> Result<String, BridgeError> {
        // Try to get a response from the queue first
        if let Some(response) = self.sign_and_submit_responses.lock().unwrap().pop_front() {
            return response;
        }
        // Fall back to wildcard response if set
        if let Some(response) = self
            .wildcard_sign_and_submit_response
            .lock()
            .unwrap()
            .clone()
        {
            return response;
        }
        // Default: return success with a dummy tx hash
        Ok("0x0000000000000000000000000000000000000000000000000000000000000000".to_string())
    }
}
