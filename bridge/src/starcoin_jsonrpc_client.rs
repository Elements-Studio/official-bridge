// StarcoinClientInner implementation using simple JSON-RPC
// This completely replaces the starcoin-rpc-client SDK

use crate::error::BridgeError;
use crate::simple_starcoin_rpc::SimpleStarcoinRpcClient;
use crate::starcoin_bridge_client::StarcoinClientInner;
use async_trait::async_trait;
use starcoin_bridge_json_rpc_types::{
    EventFilter, EventPage, StarcoinEvent, StarcoinExecutionStatus,
    StarcoinTransactionBlockEffects, StarcoinTransactionBlockResponse,
};
// Use the tuple EventID type from starcoin_bridge_types
use starcoin_bridge_types::base_types::TransactionDigest;
use starcoin_bridge_types::bridge::{
    BridgeChainId, BridgeSummary, MoveTypeBridgeTransferRecord, MoveTypeParsedTokenTransferMessage,
    MoveTypeTokenTransferPayload,
};
use starcoin_bridge_types::event::EventID;
use starcoin_bridge_types::transaction::Transaction;

use crate::types::BridgeActionStatus;

#[async_trait]
trait EventQueryRpc {
    async fn chain_info(&self) -> Result<serde_json::Value, JsonRpcError>;
    async fn get_events(
        &self,
        filter: serde_json::Value,
    ) -> Result<Vec<serde_json::Value>, JsonRpcError>;
    async fn get_block_by_number(&self, number: u64) -> Result<serde_json::Value, JsonRpcError>;
    async fn get_events_by_txn_hash(
        &self,
        txn_hash: &str,
    ) -> Result<Vec<serde_json::Value>, JsonRpcError>;
}

#[async_trait]
impl EventQueryRpc for SimpleStarcoinRpcClient {
    async fn chain_info(&self) -> Result<serde_json::Value, JsonRpcError> {
        SimpleStarcoinRpcClient::chain_info(self)
            .await
            .map_err(JsonRpcError::from)
    }

    async fn get_events(
        &self,
        filter: serde_json::Value,
    ) -> Result<Vec<serde_json::Value>, JsonRpcError> {
        SimpleStarcoinRpcClient::get_events(self, filter)
            .await
            .map_err(JsonRpcError::from)
    }

    async fn get_block_by_number(&self, number: u64) -> Result<serde_json::Value, JsonRpcError> {
        SimpleStarcoinRpcClient::get_block_by_number(self, number)
            .await
            .map_err(JsonRpcError::from)
    }

    async fn get_events_by_txn_hash(
        &self,
        txn_hash: &str,
    ) -> Result<Vec<serde_json::Value>, JsonRpcError> {
        SimpleStarcoinRpcClient::get_events_by_txn_hash(self, txn_hash)
            .await
            .map_err(JsonRpcError::from)
    }
}

/// Bridge module name
const BRIDGE_MODULE: &str = "Bridge";

/// Transfer status constants (matching Move contract)
const TRANSFER_STATUS_PENDING: u8 = 0;
const TRANSFER_STATUS_APPROVED: u8 = 1;
const TRANSFER_STATUS_CLAIMED: u8 = 2;
const TRANSFER_STATUS_NOT_FOUND: u8 = 3;

#[derive(Clone, Debug)]
pub struct StarcoinJsonRpcClient {
    rpc: SimpleStarcoinRpcClient,
}

impl StarcoinJsonRpcClient {
    pub fn new(rpc_url: &str, bridge_address: &str) -> Self {
        Self {
            rpc: SimpleStarcoinRpcClient::new(rpc_url, bridge_address),
        }
    }

    /// Get the underlying RPC client
    pub fn rpc(&self) -> &SimpleStarcoinRpcClient {
        &self.rpc
    }

    /// Get the bridge contract address
    pub fn bridge_address(&self) -> &str {
        self.rpc.bridge_address()
    }

    /// Get the chain ID as u8 for transaction signing
    pub async fn get_chain_id(&self) -> Result<u8, JsonRpcError> {
        self.rpc.get_chain_id().await.map_err(JsonRpcError::from)
    }

    // NOTE: fallback logic is implemented in `get_events_from_block_fallback_impl` so tests can
    // reuse it with an in-process RPC implementation without HTTP.

    /// Call a Move view function on the Bridge module
    async fn call_bridge_function(
        &self,
        function_name: &str,
        type_args: Vec<String>,
        args: Vec<String>,
    ) -> Result<serde_json::Value, JsonRpcError> {
        let function_id = format!(
            "{}::{}::{}",
            self.bridge_address(),
            BRIDGE_MODULE,
            function_name
        );
        self.rpc
            .call_contract(&function_id, type_args, args)
            .await
            .map_err(JsonRpcError::from)
    }

    /// Convert u8 status code from Move contract to BridgeActionStatus
    fn parse_transfer_status(status: u8) -> BridgeActionStatus {
        match status {
            TRANSFER_STATUS_PENDING => BridgeActionStatus::Pending,
            TRANSFER_STATUS_APPROVED => BridgeActionStatus::Approved,
            TRANSFER_STATUS_CLAIMED => BridgeActionStatus::Claimed,
            TRANSFER_STATUS_NOT_FOUND => BridgeActionStatus::NotFound,
            _ => BridgeActionStatus::NotFound,
        }
    }

    /// Parse Move response into signatures
    fn parse_signatures_response(response: &serde_json::Value) -> Option<Vec<Vec<u8>>> {
        // Response format from contract.call_v2:
        // [{"type": "option", "value": {"type": "vector", "value": [...]}}]
        if let Some(arr) = response.as_array() {
            if let Some(first) = arr.first() {
                // Check if it's an Option type with Some value
                if let Some(opt_value) = first.get("value") {
                    if !opt_value.is_null() {
                        // Parse vector of vector<u8>
                        if let Some(inner_arr) = opt_value.get("value").and_then(|v| v.as_array()) {
                            let mut signatures = Vec::new();
                            for item in inner_arr {
                                if let Some(bytes) = item.get("value").and_then(|v| v.as_array()) {
                                    let sig: Vec<u8> = bytes
                                        .iter()
                                        .filter_map(|b| b.as_u64().map(|n| n as u8))
                                        .collect();
                                    signatures.push(sig);
                                } else if let Some(hex_str) = item.as_str() {
                                    if let Ok(bytes) = hex::decode(hex_str.trim_start_matches("0x"))
                                    {
                                        signatures.push(bytes);
                                    }
                                }
                            }
                            if !signatures.is_empty() {
                                return Some(signatures);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Parse RPC bridge summary response into BridgeSummary
    fn parse_rpc_bridge_summary(
        rpc_response: &serde_json::Value,
    ) -> Result<BridgeSummary, JsonRpcError> {
        use starcoin_bridge_types::base_types::StarcoinAddress;
        use starcoin_bridge_types::bridge::{
            BridgeCommitteeSummary, BridgeLimiterSummary, BridgeTokenMetadata,
            BridgeTreasurySummary, MoveTypeCommitteeMember,
        };

        // The RPC response has structure: { "json": { "inner": { ... } }, "raw": "..." }
        // Extract the inner bridge data
        let inner = rpc_response
            .get("json")
            .and_then(|j| j.get("inner"))
            .unwrap_or(rpc_response);

        // Parse bridge version and chain id
        let bridge_version = inner
            .get("bridge_version")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);
        let message_version = inner
            .get("message_version")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u8;
        let chain_id = inner.get("chain_id").and_then(|v| v.as_u64()).unwrap_or(1) as u8;
        let is_frozen = inner
            .get("paused")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Parse committee
        // Structure: { "committee": { "members": { "data": [ { "key": "...", "value": { ... } } ] } } }
        let committee = inner.get("committee").unwrap_or(&serde_json::Value::Null);
        let mut committee_members = vec![];

        if let Some(members_data) = committee
            .get("members")
            .and_then(|m| m.get("data"))
            .and_then(|d| d.as_array())
        {
            for entry in members_data {
                let key = entry.get("key").and_then(|k| k.as_str()).unwrap_or("");
                let value = entry.get("value").unwrap_or(&serde_json::Value::Null);

                let pubkey_hex = value
                    .get("bridge_pubkey_bytes")
                    .and_then(|v| v.as_str())
                    .unwrap_or(key);
                let voting_power = value
                    .get("voting_power")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let address_hex = value
                    .get("starcoin_address")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let blocklisted = value
                    .get("blocklisted")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let http_rest_url_hex = value
                    .get("http_rest_url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // Decode pubkey (strip 0x prefix if present)
                let pubkey_clean = pubkey_hex.trim_start_matches("0x");
                if let Ok(pubkey_bytes) = hex::decode(pubkey_clean) {
                    let starcoin_addr = StarcoinAddress::from_hex_literal(address_hex)
                        .unwrap_or(StarcoinAddress::ZERO);

                    // Decode http_rest_url from hex to bytes
                    let url_clean = http_rest_url_hex.trim_start_matches("0x");
                    let http_rest_url = hex::decode(url_clean).unwrap_or_default();

                    committee_members.push((
                        pubkey_bytes.clone(),
                        MoveTypeCommitteeMember {
                            starcoin_bridge_address: starcoin_addr,
                            bridge_pubkey_bytes: pubkey_bytes,
                            voting_power,
                            http_rest_url,
                            blocklisted,
                        },
                    ));
                }
            }
        }

        let last_committee_update_epoch = committee
            .get("last_committee_update_epoch")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let committee_summary = BridgeCommitteeSummary {
            members: committee_members,
            member_registration: vec![],
            last_committee_update_epoch,
        };

        // Parse treasury
        // Structure: { "treasury": { "supported_tokens": { "data": [...] }, "id_token_type_map": { "data": [...] } } }
        let treasury = inner.get("treasury").unwrap_or(&serde_json::Value::Null);
        let mut supported_tokens = vec![];
        let mut id_token_type_map = vec![];

        if let Some(tokens_data) = treasury
            .get("supported_tokens")
            .and_then(|t| t.get("data"))
            .and_then(|d| d.as_array())
        {
            for entry in tokens_data {
                let token_type = entry.get("key").and_then(|k| k.as_str()).unwrap_or("");
                supported_tokens.push((token_type.to_string(), BridgeTokenMetadata::default()));
            }
        }

        if let Some(map_data) = treasury
            .get("id_token_type_map")
            .and_then(|t| t.get("data"))
            .and_then(|d| d.as_array())
        {
            for entry in map_data {
                let id = entry.get("key").and_then(|k| k.as_u64()).unwrap_or(0) as u8;
                let token_type = entry
                    .get("value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                id_token_type_map.push((id, token_type));
            }
        }

        let treasury_summary = BridgeTreasurySummary {
            supported_tokens,
            id_token_type_map,
        };

        // Parse sequence_nums
        let mut sequence_nums = vec![];
        if let Some(seq_data) = inner
            .get("sequence_nums")
            .and_then(|s| s.get("data"))
            .and_then(|d| d.as_array())
        {
            for entry in seq_data {
                let chain_id = entry.get("key").and_then(|k| k.as_u64()).unwrap_or(0) as u8;
                let seq_num = entry.get("value").and_then(|v| v.as_u64()).unwrap_or(0);
                sequence_nums.push((chain_id, seq_num));
            }
        }

        // Parse limiter
        // Structure: { "limiter": { "transfer_limits": { "data": [ { "key": { "source": u8, "destination": u8 }, "value": u64 } ] } } }
        let limiter = inner.get("limiter").unwrap_or(&serde_json::Value::Null);
        let mut transfer_limit = vec![];

        if let Some(limits_data) = limiter
            .get("transfer_limits")
            .and_then(|t| t.get("data"))
            .and_then(|d| d.as_array())
        {
            for entry in limits_data {
                let key = entry.get("key").unwrap_or(&serde_json::Value::Null);
                let source = key.get("source").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
                let destination =
                    key.get("destination").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
                let limit = entry.get("value").and_then(|v| v.as_u64()).unwrap_or(0);

                // Convert chain IDs to BridgeChainId
                if let (Ok(src_chain), Ok(dst_chain)) = (
                    BridgeChainId::try_from(source),
                    BridgeChainId::try_from(destination),
                ) {
                    transfer_limit.push((src_chain, dst_chain, limit));
                }
            }
        }

        // Parse transfer_records
        // Structure: { "limiter": { "transfer_records": { "data": [ { "key": { "source": u8, "destination": u8 }, "value": { "total_amount": u64, ... } } ] } } }
        let mut transfer_records = vec![];
        if let Some(records_data) = limiter
            .get("transfer_records")
            .and_then(|t| t.get("data"))
            .and_then(|d| d.as_array())
        {
            for entry in records_data {
                let key = entry.get("key").unwrap_or(&serde_json::Value::Null);
                let source = key.get("source").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
                let destination =
                    key.get("destination").and_then(|v| v.as_u64()).unwrap_or(0) as u8;

                let value = entry.get("value").unwrap_or(&serde_json::Value::Null);
                let total_amount = value
                    .get("total_amount")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let hour_head = value.get("hour_head").and_then(|v| v.as_u64()).unwrap_or(0);
                let hour_tail = value.get("hour_tail").and_then(|v| v.as_u64()).unwrap_or(0);

                // Convert chain IDs to BridgeChainId
                if let (Ok(src_chain), Ok(dst_chain)) = (
                    BridgeChainId::try_from(source),
                    BridgeChainId::try_from(destination),
                ) {
                    let record = MoveTypeBridgeTransferRecord {
                        hour_head,
                        hour_tail,
                        per_hour_amounts: vec![], // Not critical for quota calculation
                        total_amount,
                    };
                    transfer_records.push((src_chain, dst_chain, record));
                }
            }
        }

        let limiter_summary = BridgeLimiterSummary {
            transfer_limit,
            transfer_records,
        };

        Ok(BridgeSummary {
            bridge_version,
            message_version,
            chain_id,
            sequence_nums,
            committee: committee_summary,
            treasury: treasury_summary,
            limiter: limiter_summary,
            is_frozen,
        })
    }
}

/// Fallback method to fetch events by iterating over transactions in a block.
/// Used when pagination via `chain.get_events` is stuck (e.g. block size > limit).
async fn get_events_from_block_fallback_impl<R: EventQueryRpc + Sync>(
    rpc: &R,
    block_number: u64,
    cursor: Option<EventID>,
    limit: usize,
    current_block: u64,
) -> Result<EventPage, JsonRpcError> {
    let block = rpc.get_block_by_number(block_number).await?;

    // Starcoin BlockView body can be either {"Full": [txn...] } or {"Hashes": [hash...]}
    let body = block.get("body");

    let mut txn_hashes: Vec<String> = Vec::new();
    if let Some(full) = body.and_then(|b| b.get("Full")).and_then(|v| v.as_array()) {
        for txn in full {
            if let Some(hash) = txn.get("transaction_hash").and_then(|v| v.as_str()) {
                txn_hashes.push(hash.to_string());
            }
        }
    } else if let Some(hashes) = body
        .and_then(|b| b.get("Hashes"))
        .and_then(|v| v.as_array())
    {
        for h in hashes {
            if let Some(hash) = h.as_str() {
                txn_hashes.push(hash.to_string());
            }
        }
    }

    // Some block views can contain repeated transaction hashes (e.g. system txns). Ensure we
    // don't query the same transaction twice, which would duplicate events.
    txn_hashes.sort();
    txn_hashes.dedup();

    let mut events = Vec::new();
    for hash in txn_hashes {
        let tx_events = rpc.get_events_by_txn_hash(&hash).await?;
        for event_value in tx_events {
            let tx_digest_bytes = hex::decode(hash.trim_start_matches("0x")).unwrap_or_default();
            let mut tx_digest = [0u8; 32];
            let len = tx_digest_bytes.len().min(32);
            tx_digest[..len].copy_from_slice(&tx_digest_bytes[..len]);

            if let Ok(event) = StarcoinEvent::try_from_rpc_event(&event_value, tx_digest) {
                if let Some((cursor_block, cursor_event_seq)) = cursor {
                    if event.id.block_number < cursor_block {
                        continue;
                    }
                    if event.id.block_number == cursor_block
                        && event.id.event_seq <= cursor_event_seq
                    {
                        continue;
                    }
                }
                events.push(event);
            }
        }
    }

    // Defensive de-duplication: some RPC paths can return identical event entries more than once
    // for a transaction. The cursor semantics assume each (tx_digest, block_number, event_seq)
    // is unique in the returned stream.
    {
        use std::collections::HashSet;
        let mut seen: HashSet<([u8; 32], u64, u64)> = HashSet::new();
        events.retain(|e| seen.insert((e.id.tx_digest, e.id.block_number, e.id.event_seq)));
    }

    // Ensure deterministic ordering so downstream cursor logic always advances.
    // Cursor type is (block_number, event_seq), so we must return events in increasing order.
    events.sort_by(|a, b| {
        (a.id.block_number, a.id.event_seq, a.id.tx_digest).cmp(&(
            b.id.block_number,
            b.id.event_seq,
            b.id.tx_digest,
        ))
    });

    let has_more_in_block = events.len() > limit;
    if events.len() > limit {
        events.truncate(limit);
    }

    let next_cursor = events
        .last()
        .map(|e| (e.id.block_number, e.id.event_seq))
        .or(Some((block_number + 1, 0)));

    let has_next_page = has_more_in_block || (block_number < current_block);

    Ok(EventPage {
        data: events,
        next_cursor,
        has_next_page,
    })
}

async fn query_events_impl<R: EventQueryRpc + Sync>(
    rpc: &R,
    query: EventFilter,
    cursor: Option<EventID>,
) -> Result<EventPage, JsonRpcError> {
    // Get current block height from chain
    let chain_info = rpc.chain_info().await?;
    let current_block = chain_info
        .get("head")
        .and_then(|h| h.get("number"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| {
            chain_info
                .get("head")
                .and_then(|h| h.get("number"))
                .and_then(|v| v.as_u64())
        })
        .unwrap_or(0);

    let mut filter = query.clone();
    if filter.limit.is_none() {
        filter.limit = Some(100);
    }
    let limit = filter.limit.unwrap_or(100);

    let mut search_from_block = if let Some((block_num, _)) = cursor {
        block_num
    } else {
        filter.from_block.unwrap_or(0)
    };

    loop {
        if search_from_block > current_block {
            return Ok(EventPage {
                data: vec![],
                next_cursor: cursor,
                has_next_page: false,
            });
        }

        let to_block = std::cmp::min(
            search_from_block.saturating_add(MAX_BLOCK_RANGE - 1),
            current_block,
        );

        filter.from_block = Some(search_from_block);
        filter.to_block = Some(to_block);

        tracing::debug!(
            from_block = search_from_block,
            to_block = to_block,
            current_block = current_block,
            "Querying Starcoin events"
        );

        let raw_events = rpc.get_events(filter.to_rpc_filter()).await?;
        let raw_events_len = raw_events.len();

        let mut events = Vec::new();
        for event_value in raw_events.iter() {
            let tx_hash = event_value
                .get("transaction_hash")
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
                .map(|bytes| {
                    let mut arr = [0u8; 32];
                    let len = bytes.len().min(32);
                    arr[..len].copy_from_slice(&bytes[..len]);
                    arr
                })
                .unwrap_or([0u8; 32]);

            if let Ok(event) = StarcoinEvent::try_from_rpc_event(event_value, tx_hash) {
                if let Some((cursor_block, cursor_event_seq)) = cursor {
                    if event.id.block_number < cursor_block {
                        continue;
                    }
                    if event.id.block_number == cursor_block
                        && event.id.event_seq <= cursor_event_seq
                    {
                        continue;
                    }
                }
                events.push(event);
            }
        }

        if !events.is_empty() {
            // Keep output order deterministic and monotonic with the cursor semantics.
            events.sort_by(|a, b| {
                (a.id.block_number, a.id.event_seq, a.id.tx_digest).cmp(&(
                    b.id.block_number,
                    b.id.event_seq,
                    b.id.tx_digest,
                ))
            });

            // When querying a single block and the server returns exactly `limit` items, we
            // cannot assume the server returns the *earliest* events. If it returns the *latest*
            // events instead, advancing the cursor to the last returned event can skip earlier
            // events still greater than the cursor. Use the block-scanning fallback in this case
            // to guarantee completeness.
            if to_block == search_from_block && raw_events_len == limit {
                return get_events_from_block_fallback_impl(
                    rpc,
                    search_from_block,
                    cursor,
                    limit,
                    current_block,
                )
                .await;
            }

            // If the server returned `limit` items, there may be more events even when
            // `to_block == current_block`.
            let has_next_page = (to_block < current_block) || (raw_events_len == limit);
            let next_cursor: Option<EventID> =
                events.last().map(|e| (e.id.block_number, e.id.event_seq));
            return Ok(EventPage {
                data: events,
                next_cursor,
                has_next_page,
            });
        }

        if raw_events_len < limit {
            search_from_block = to_block + 1;
            continue;
        }

        tracing::warn!(
            "Query hit limit {} but all events were filtered out. Stuck at block {}. Using fallback to fetch full block.",
            limit,
            search_from_block
        );

        match get_events_from_block_fallback_impl(
            rpc,
            search_from_block,
            cursor,
            limit,
            current_block,
        )
        .await
        {
            Ok(page) => {
                if !page.data.is_empty() {
                    return Ok(page);
                }
                search_from_block += 1;
                continue;
            }
            Err(e) => {
                tracing::error!("Fallback failed: {:?}", e);
                return Ok(EventPage {
                    data: vec![],
                    next_cursor: cursor,
                    has_next_page: false,
                });
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct JsonRpcError(String);

impl From<anyhow::Error> for JsonRpcError {
    fn from(e: anyhow::Error) -> Self {
        JsonRpcError(e.to_string())
    }
}

impl From<serde_json::Error> for JsonRpcError {
    fn from(e: serde_json::Error) -> Self {
        JsonRpcError(e.to_string())
    }
}

/// Maximum block range allowed by Starcoin RPC for event queries
const MAX_BLOCK_RANGE: u64 = 32;

#[async_trait]
impl StarcoinClientInner for StarcoinJsonRpcClient {
    type Error = JsonRpcError;

    fn bridge_address(&self) -> &str {
        self.rpc.bridge_address()
    }

    async fn query_events(
        &self,
        query: EventFilter,
        cursor: Option<EventID>,
    ) -> Result<EventPage, Self::Error> {
        query_events_impl(&self.rpc, query, cursor).await
    }

    async fn get_events_by_tx_digest(
        &self,
        tx_digest: TransactionDigest,
    ) -> Result<Vec<StarcoinEvent>, Self::Error> {
        let tx_hash = format!("0x{}", hex::encode(tx_digest));
        let raw_events = self.rpc.get_events_by_txn_hash(&tx_hash).await?;

        // Parse each event from RPC response into StarcoinEvent
        let mut events = Vec::new();
        for event_value in raw_events {
            match StarcoinEvent::try_from_rpc_event(&event_value, tx_digest) {
                Ok(event) => events.push(event),
                Err(e) => {
                    tracing::warn!("Failed to parse event: {:?}, error: {}", event_value, e);
                }
            }
        }
        Ok(events)
    }

    async fn get_events_by_tx_digest_verbose(
        &self,
        tx_digest: TransactionDigest,
    ) -> Result<Vec<StarcoinEvent>, Self::Error> {
        let tx_hash = format!("0x{}", hex::encode(tx_digest));
        let raw_events = self.rpc.get_events_by_txn_hash_verbose(&tx_hash).await?;

        // Parse each event from RPC response into StarcoinEvent
        let mut events = Vec::new();
        for (i, event_value) in raw_events.iter().enumerate() {
            match StarcoinEvent::try_from_rpc_event(event_value, tx_digest) {
                Ok(event) => {
                    tracing::info!(
                        "[StarcoinJsonRpc] Parsed event[{}]: type={:?}, block={}",
                        i,
                        event.type_,
                        event.id.block_number
                    );
                    events.push(event);
                }
                Err(e) => {
                    tracing::warn!(
                        "[StarcoinJsonRpc] Failed to parse event[{}]: {:?}, error: {}",
                        i,
                        event_value,
                        e
                    );
                }
            }
        }
        Ok(events)
    }

    async fn get_chain_identifier(&self) -> Result<String, Self::Error> {
        let chain_info = self.rpc.chain_info().await?;
        let chain_id = chain_info
            .get("chain_id")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| JsonRpcError("Missing chain_id".into()))?;
        Ok(format!("{}", chain_id))
    }

    async fn get_chain_id(&self) -> Result<u8, Self::Error> {
        self.rpc.get_chain_id().await.map_err(JsonRpcError::from)
    }

    async fn get_reference_gas_price(&self) -> Result<u64, Self::Error> {
        Ok(self.rpc.get_gas_price().await?)
    }

    async fn get_latest_block_number(&self) -> Result<u64, Self::Error> {
        let chain_info = self.rpc.chain_info().await?;
        // Starcoin returns block number as string, so try both as_u64() and as_str().parse()
        let block_number = chain_info
            .get("head")
            .and_then(|h| h.get("number"))
            .and_then(|n| {
                n.as_u64()
                    .or_else(|| n.as_str().and_then(|s| s.parse().ok()))
            })
            .ok_or_else(|| JsonRpcError("Missing block number".into()))?;
        Ok(block_number)
    }

    async fn get_latest_block_number_verbose(&self) -> Result<u64, Self::Error> {
        let chain_info = self.rpc.chain_info_verbose().await?;
        // Starcoin returns block number as string, so try both as_u64() and as_str().parse()
        let block_number = chain_info
            .get("head")
            .and_then(|h| h.get("number"))
            .and_then(|n| {
                n.as_u64()
                    .or_else(|| n.as_str().and_then(|s| s.parse().ok()))
            })
            .ok_or_else(|| JsonRpcError("Missing block number".into()))?;
        Ok(block_number)
    }

    async fn get_bridge_summary(&self) -> Result<BridgeSummary, Self::Error> {
        // Call bridge.get_latest_bridge RPC
        let rpc_response = self.rpc.get_latest_bridge().await?;

        // Parse the RPC response and convert to BridgeSummary
        // RPC returns: { committee: {...}, treasury: {...}, config: {...} }
        Self::parse_rpc_bridge_summary(&rpc_response)
    }

    async fn execute_transaction_block_with_effects(
        &self,
        tx: Transaction,
    ) -> Result<StarcoinTransactionBlockResponse, BridgeError> {
        // Transaction wraps serialized signed transaction bytes
        let signed_txn_hex = hex::encode(&tx.0);

        // Submit and wait for transaction confirmation
        let txn_info = self
            .rpc
            .submit_and_wait_transaction(&signed_txn_hex)
            .await
            .map_err(|e| BridgeError::Generic(format!("Transaction execution failed: {}", e)))?;

        // Parse the response into StarcoinTransactionBlockResponse
        let tx_hash = txn_info
            .get("transaction_hash")
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
            .map(|bytes| {
                let mut arr = [0u8; 32];
                let len = bytes.len().min(32);
                arr[..len].copy_from_slice(&bytes[..len]);
                arr
            })
            .unwrap_or([0u8; 32]);

        let status = txn_info
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let success = status == "Executed" || status == "executed";

        Ok(StarcoinTransactionBlockResponse {
            digest: Some(tx_hash),
            effects: Some(StarcoinTransactionBlockEffects {
                status: if success {
                    StarcoinExecutionStatus::Success
                } else {
                    StarcoinExecutionStatus::Failure {
                        error: status.to_string(),
                    }
                },
                transaction_digest: Some(tx_hash),
            }),
            events: None,
            object_changes: None,
        })
    }

    async fn get_token_transfer_action_onchain_status(
        &self,
        source_chain_id: u8,
        seq_number: u64,
    ) -> Result<BridgeActionStatus, BridgeError> {
        // Call query_token_transfer_status via contract.call_v2
        // Function signature: query_token_transfer_status(source_chain: u8, bridge_seq_num: u64): u8
        // Note: Starcoin contract.call_v2 requires type suffix on arguments (e.g., "12u8", "0u64")
        let args = vec![
            format!("{}u8", source_chain_id), // source_chain as u8
            format!("{}u64", seq_number),     // bridge_seq_num as u64
        ];

        let args_display = format!("[{}u8, {}u64]", source_chain_id, seq_number);

        match self
            .call_bridge_function("query_token_transfer_status", vec![], args)
            .await
        {
            Ok(response) => {
                // Parse u8 status from response
                // Response format: [1] (direct array of values)
                let status = response
                    .as_array()
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u8)
                    .unwrap_or(TRANSFER_STATUS_NOT_FOUND);

                let parsed_status = Self::parse_transfer_status(status);
                tracing::info!(
                    "[RPC] >>> query_token_transfer_status({}) => [{}] ({:?})",
                    args_display,
                    status,
                    parsed_status
                );
                Ok(parsed_status)
            }
            Err(e) => {
                tracing::warn!(
                    "[RPC] >>> query_token_transfer_status({}) => ERROR: {:?}",
                    args_display,
                    e
                );
                // If function call fails (e.g., function not found), return NotFound
                Ok(BridgeActionStatus::NotFound)
            }
        }
    }

    async fn get_token_transfer_action_onchain_signatures(
        &self,
        source_chain_id: u8,
        seq_number: u64,
    ) -> Result<Option<Vec<Vec<u8>>>, BridgeError> {
        // Call query_token_transfer_signatures via contract.call_v2
        // Note: Starcoin contract.call_v2 requires type suffix on arguments
        let args = vec![
            format!("{}u8", source_chain_id),
            format!("{}u64", seq_number),
        ];

        match self
            .call_bridge_function("query_token_transfer_signatures", vec![], args)
            .await
        {
            Ok(response) => Ok(Self::parse_signatures_response(&response)),
            Err(e) => {
                tracing::warn!("Failed to query transfer signatures: {:?}", e);
                Ok(None)
            }
        }
    }

    async fn get_parsed_token_transfer_message(
        &self,
        source_chain_id: u8,
        seq_number: u64,
    ) -> Result<Option<MoveTypeParsedTokenTransferMessage>, BridgeError> {
        // Call get_parsed_token_transfer_message via contract.call_v2
        // Note: Starcoin contract.call_v2 requires type suffix on arguments
        let args = vec![
            format!("{}u8", source_chain_id),
            format!("{}u64", seq_number),
        ];

        match self
            .call_bridge_function("test_get_parsed_token_transfer_message", vec![], args)
            .await
        {
            Ok(response) => {
                // Parse the response into MoveTypeParsedTokenTransferMessage
                // Response format: [{"type": "option", "value": {...}}]
                if let Some(arr) = response.as_array() {
                    if let Some(first) = arr.first() {
                        if let Some(opt_value) = first.get("value") {
                            if !opt_value.is_null() {
                                // Parse the struct fields
                                let message_version = opt_value
                                    .get("message_version")
                                    .and_then(|v| v.as_u64())
                                    .map(|n| n as u8)
                                    .unwrap_or(1);

                                let seq_num = opt_value
                                    .get("seq_num")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(seq_number);

                                let source_chain = opt_value
                                    .get("source_chain")
                                    .and_then(|v| v.as_u64())
                                    .map(|n| n as u8)
                                    .unwrap_or(source_chain_id);

                                let payload = opt_value
                                    .get("payload")
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
                                    .unwrap_or_default();

                                // Parse parsed_payload struct
                                let parsed_payload = opt_value.get("parsed_payload");
                                let sender_address = parsed_payload
                                    .and_then(|p| p.get("sender_address"))
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
                                    .unwrap_or_default();

                                let target_chain = parsed_payload
                                    .and_then(|p| p.get("target_chain"))
                                    .and_then(|v| v.as_u64())
                                    .map(|n| n as u8)
                                    .unwrap_or(0);

                                let target_address = parsed_payload
                                    .and_then(|p| p.get("target_address"))
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
                                    .unwrap_or_default();

                                let token_type = parsed_payload
                                    .and_then(|p| p.get("token_type"))
                                    .and_then(|v| v.as_u64())
                                    .map(|n| n as u8)
                                    .unwrap_or(0);

                                let amount = parsed_payload
                                    .and_then(|p| p.get("amount"))
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0);

                                return Ok(Some(MoveTypeParsedTokenTransferMessage {
                                    message_version,
                                    seq_num,
                                    source_chain,
                                    payload,
                                    parsed_payload: MoveTypeTokenTransferPayload {
                                        sender_address,
                                        target_chain,
                                        target_address,
                                        token_type,
                                        amount,
                                    },
                                }));
                            }
                        }
                    }
                }
                Ok(None)
            }
            Err(e) => {
                tracing::warn!("Failed to query parsed token transfer message: {:?}", e);
                Ok(None)
            }
        }
    }

    async fn get_sequence_number(&self, address: &str) -> Result<u64, BridgeError> {
        self.rpc
            .get_sequence_number(address)
            .await
            .map_err(|e| BridgeError::Generic(format!("Failed to get sequence number: {}", e)))
    }

    async fn get_block_timestamp(&self) -> Result<u64, BridgeError> {
        self.rpc
            .get_block_timestamp()
            .await
            .map_err(|e| BridgeError::Generic(format!("Failed to get block timestamp: {}", e)))
    }

    async fn sign_and_submit_transaction(
        &self,
        key: &starcoin_bridge_types::crypto::StarcoinKeyPair,
        raw_txn: starcoin_bridge_types::transaction::RawUserTransaction,
    ) -> Result<String, BridgeError> {
        self.rpc
            .sign_and_submit_transaction(key, raw_txn)
            .await
            .map_err(|e| {
                BridgeError::Generic(format!("Failed to sign and submit transaction: {}", e))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::starcoin_test_utils::EmbeddedStarcoinNode;
    use serde_json::json;
    use starcoin_rpc_client::{Params, RpcClient};
    use starcoin_transaction_builder::{
        create_signed_txn_with_association_account, encode_transfer_script_function,
        DEFAULT_MAX_GAS_AMOUNT,
    };
    use starcoin_types::account_address::AccountAddress;
    use starcoin_vm_types::transaction::TransactionPayload;
    use std::collections::BTreeSet;
    use std::time::Duration;

    /// Helper trait to parse JSON values that might be strings or numbers (test-only)
    trait JsonValueExt {
        fn as_u64_flex(&self) -> Option<u64>;
    }

    impl JsonValueExt for serde_json::Value {
        fn as_u64_flex(&self) -> Option<u64> {
            self.as_u64()
                .or_else(|| self.as_str().and_then(|s| s.parse().ok()))
        }
    }

    struct InProcessEventRpc {
        client: std::sync::Arc<RpcClient>,
    }

    impl InProcessEventRpc {
        fn new(client: RpcClient) -> Self {
            Self {
                client: std::sync::Arc::new(client),
            }
        }

        async fn call(
            &self,
            method: &str,
            params: Vec<serde_json::Value>,
        ) -> Result<serde_json::Value, JsonRpcError> {
            let client = self.client.clone();
            let method = method.to_string();
            let params = Params::Array(params);
            tokio::task::spawn_blocking(move || client.call_raw_api(&method, params))
                .await
                .map_err(|e| JsonRpcError(format!("join error: {e}")))?
                .map_err(|e| JsonRpcError(e.to_string()))
        }
    }

    #[async_trait]
    impl EventQueryRpc for InProcessEventRpc {
        async fn chain_info(&self) -> Result<serde_json::Value, JsonRpcError> {
            self.call("chain.info", vec![]).await
        }

        async fn get_events(
            &self,
            filter: serde_json::Value,
        ) -> Result<Vec<serde_json::Value>, JsonRpcError> {
            let v = self
                .call("chain.get_events", vec![filter, json!({ "decode": true })])
                .await?;
            serde_json::from_value(v).map_err(JsonRpcError::from)
        }

        async fn get_block_by_number(
            &self,
            number: u64,
        ) -> Result<serde_json::Value, JsonRpcError> {
            self.call(
                "chain.get_block_by_number",
                vec![json!(number), json!({ "decode": true })],
            )
            .await
        }

        async fn get_events_by_txn_hash(
            &self,
            txn_hash: &str,
        ) -> Result<Vec<serde_json::Value>, JsonRpcError> {
            let v = self
                .call(
                    "chain.get_events_by_txn_hash",
                    vec![json!(txn_hash), json!({ "decode": true })],
                )
                .await?;
            serde_json::from_value(v).map_err(JsonRpcError::from)
        }
    }

    async fn get_sequence_number_via_local_rpc(
        rpc: std::sync::Arc<RpcClient>,
        address: String,
    ) -> Result<u64, JsonRpcError> {
        let v = tokio::task::spawn_blocking(move || {
            rpc.call_raw_api(
                "txpool.next_sequence_number",
                Params::Array(vec![json!(address)]),
            )
        })
        .await
        .map_err(|e| JsonRpcError(format!("join error: {e}")))?
        .map_err(|e| JsonRpcError(e.to_string()))?;

        Ok(v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            .unwrap_or(0))
    }

    fn tx_digest_from_event_value(event_value: &serde_json::Value) -> [u8; 32] {
        event_value
            .get("transaction_hash")
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
            .map(|bytes| {
                let mut arr = [0u8; 32];
                let len = bytes.len().min(32);
                arr[..len].copy_from_slice(&bytes[..len]);
                arr
            })
            .unwrap_or([0u8; 32])
    }

    fn parse_events_from_raw(raw_events: &[serde_json::Value]) -> Vec<StarcoinEvent> {
        raw_events
            .iter()
            .filter_map(|event_value| {
                let tx_digest = tx_digest_from_event_value(event_value);
                StarcoinEvent::try_from_rpc_event(event_value, tx_digest).ok()
            })
            .collect()
    }

    fn event_key(event: &StarcoinEvent) -> (u64, u64, [u8; 32]) {
        (
            event.id.block_number,
            event.id.event_seq,
            event.id.tx_digest,
        )
    }

    async fn drop_on_blocking_thread<T: Send + 'static>(value: T) {
        tokio::task::spawn_blocking(move || drop(value))
            .await
            .expect("drop join failed");
    }

    #[tokio::test]
    async fn test_query_events_pagination_logic_real_node() {
        // 1) Start embedded Starcoin node (in-memory)
        let mut node = Some(EmbeddedStarcoinNode::start().expect("Failed to start node"));
        let config = node.as_ref().unwrap().config();

        // 2) Connect to the node via in-process RPC (no HTTP)
        let rpc_service = node
            .as_ref()
            .unwrap()
            .handle()
            .rpc_service()
            .expect("Failed to get RpcService");
        let local_rpc = tokio::task::spawn_blocking(move || RpcClient::connect_local(rpc_service))
            .await
            .expect("connect_local join failed")
            .expect("connect_local failed");
        let mut rpc = Some(InProcessEventRpc::new(local_rpc));

        // 2. Generate transactions to create events
        // We want multiple events in one block.
        // We will send 10 transfers from association account to a random account.
        // Each transfer emits DepositEvent and WithdrawEvent (and maybe others).

        let receiver = AccountAddress::random();
        let mut txns = vec![];

        // Get current sequence number for association account via local RPC
        let association_addr = starcoin_vm_types::account_config::association_address();
        let start_seq = get_sequence_number_via_local_rpc(
            rpc.as_ref().unwrap().client.clone(),
            association_addr.to_string(),
        )
        .await
        .expect("Failed to read association sequence number");

        for i in 0..10 {
            let payload = TransactionPayload::ScriptFunction(encode_transfer_script_function(
                receiver, 1000, // amount
            ));

            let txn = create_signed_txn_with_association_account(
                payload,
                start_seq + i,
                DEFAULT_MAX_GAS_AMOUNT,
                1,    // gas_price
                3600, // expiration
                config.net(),
            );
            txns.push(txn);
        }

        // 3. Submit transactions
        for txn in txns {
            node.as_ref()
                .unwrap()
                .submit_transaction(txn)
                .expect("Failed to submit txn");
        }

        // 4. Generate block
        let block = node
            .as_ref()
            .unwrap()
            .generate_block()
            .expect("Failed to generate block");
        let block_number = block.header().number();
        tracing::debug!("Generated block {}", block_number);

        // Allow in-process services to observe the new head event
        tokio::time::sleep(Duration::from_millis(200)).await;

        // 5) Pick a cursor inside this block so there should be "events after cursor"
        let all_raw = rpc
            .as_ref()
            .unwrap()
            .get_events(
                EventFilter {
                    from_block: Some(block_number),
                    to_block: Some(block_number),
                    type_tags: None,
                    limit: Some(5000),
                }
                .to_rpc_filter(),
            )
            .await
            .expect("Failed to get raw events");

        // Starcoin's `event_seq_number` is per event-handle/key; across different event types it may
        // not be globally unique or totally ordered. The production client uses a cursor of
        // (block_number, event_seq) and expects `event_seq` to be monotonic within the queried
        // event stream. To make the test meaningful, pick a single event `type_tag` that appears
        // many times in this block, and query only that type.
        use std::collections::HashMap;
        let mut type_counts: HashMap<String, usize> = HashMap::new();
        for e in &all_raw {
            if let Some(t) = e.get("type_tag").and_then(|v| v.as_str()) {
                *type_counts.entry(t.to_string()).or_default() += 1;
            }
        }

        let (selected_type_tag, selected_count) = type_counts
            .into_iter()
            .max_by_key(|(_, c)| *c)
            .expect("No type_tag in returned events");
        assert!(
            selected_count >= 3,
            "Not enough repeated events in block to validate pagination; got {selected_count} for type_tag={selected_type_tag}"
        );

        let selected_raw: Vec<_> = all_raw
            .iter()
            .filter(|e| {
                e.get("type_tag").and_then(|v| v.as_str()) == Some(selected_type_tag.as_str())
            })
            .collect();

        // If we didn't produce any events, something is very wrong with the node/txns.
        assert!(
            !selected_raw.is_empty(),
            "No events returned for generated block; cannot validate pagination"
        );

        let mut max_seq = 0u64;
        for e in &selected_raw {
            if let Some(seq) = e.get("event_seq_number").and_then(|v| v.as_u64_flex()) {
                max_seq = max_seq.max(seq);
            }
        }
        let cursor_seq = max_seq.saturating_sub(2);
        let cursor = Some((block_number, cursor_seq));

        // 6) Run the production pagination logic against the in-process RPC
        let filter = EventFilter {
            from_block: Some(block_number),
            to_block: Some(block_number),
            type_tags: Some(vec![selected_type_tag]),
            limit: Some(5),
        };

        let page = tokio::time::timeout(
            Duration::from_secs(10),
            query_events_impl(rpc.as_ref().unwrap(), filter.clone(), cursor),
        )
        .await
        .expect("query_events timed out")
        .expect("query_events failed");

        for ev in &page.data {
            assert_eq!(ev.id.block_number, block_number);
            assert!(ev.id.event_seq > cursor_seq);
        }

        let mut ids = page
            .data
            .iter()
            .map(|e| (e.id.tx_digest, e.id.block_number, e.id.event_seq))
            .collect::<Vec<_>>();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), page.data.len(), "Duplicate events found");

        // `RpcClient` internally owns a Tokio runtime; dropping it on an async runtime worker
        // thread can panic. Explicitly drop it on a blocking thread.
        let rpc_to_drop = rpc.take().unwrap();
        tokio::task::spawn_blocking(move || drop(rpc_to_drop))
            .await
            .expect("drop rpc join failed");

        let node_to_drop = node.take().unwrap();
        drop_on_blocking_thread(node_to_drop).await;
    }

    #[tokio::test]
    async fn test_query_events_limit_1_paginates_subset_real_node() {
        // Start embedded Starcoin node (in-memory)
        let mut node = Some(EmbeddedStarcoinNode::start().expect("Failed to start node"));
        let config = node.as_ref().unwrap().config();

        // Connect via in-process RPC (no HTTP)
        let rpc_service = node
            .as_ref()
            .unwrap()
            .handle()
            .rpc_service()
            .expect("Failed to get RpcService");
        let local_rpc = tokio::task::spawn_blocking(move || RpcClient::connect_local(rpc_service))
            .await
            .expect("connect_local join failed")
            .expect("connect_local failed");
        let mut rpc = Some(InProcessEventRpc::new(local_rpc));

        // Generate a batch of transfers to produce many events in one block.
        let receiver = AccountAddress::random();
        let mut txns = vec![];

        let association_addr = starcoin_vm_types::account_config::association_address();
        let start_seq = get_sequence_number_via_local_rpc(
            rpc.as_ref().unwrap().client.clone(),
            association_addr.to_string(),
        )
        .await
        .expect("Failed to read association sequence number");

        for i in 0..10 {
            let payload =
                TransactionPayload::ScriptFunction(encode_transfer_script_function(receiver, 1000));
            let txn = create_signed_txn_with_association_account(
                payload,
                start_seq + i,
                DEFAULT_MAX_GAS_AMOUNT,
                1,
                3600,
                config.net(),
            );
            txns.push(txn);
        }

        for txn in txns {
            node.as_ref()
                .unwrap()
                .submit_transaction(txn)
                .expect("Failed to submit txn");
        }

        let block = node
            .as_ref()
            .unwrap()
            .generate_block()
            .expect("Failed to generate block");
        let block_number = block.header().number();

        tokio::time::sleep(Duration::from_millis(200)).await;

        // Determine a repeated type_tag from this block.
        let all_raw = rpc
            .as_ref()
            .unwrap()
            .get_events(
                EventFilter {
                    from_block: Some(block_number),
                    to_block: Some(block_number),
                    type_tags: None,
                    limit: Some(5000),
                }
                .to_rpc_filter(),
            )
            .await
            .expect("Failed to get raw events");

        use std::collections::HashMap;
        let mut type_counts: HashMap<String, usize> = HashMap::new();
        for e in &all_raw {
            if let Some(t) = e.get("type_tag").and_then(|v| v.as_str()) {
                *type_counts.entry(t.to_string()).or_default() += 1;
            }
        }

        let (selected_type_tag, selected_count) = type_counts
            .into_iter()
            .max_by_key(|(_, c)| *c)
            .expect("No type_tag in returned events");
        assert!(
            selected_count >= 3,
            "Not enough repeated events in block to validate pagination; got {selected_count} for type_tag={selected_type_tag}"
        );

        // Baseline: fetch all events for the chosen type_tag in this block.
        let baseline_raw = rpc
            .as_ref()
            .unwrap()
            .get_events(
                EventFilter {
                    from_block: Some(block_number),
                    to_block: Some(block_number),
                    type_tags: Some(vec![selected_type_tag.clone()]),
                    limit: Some(5000),
                }
                .to_rpc_filter(),
            )
            .await
            .expect("Failed to fetch baseline events");
        let baseline_events = parse_events_from_raw(&baseline_raw);
        assert!(
            !baseline_events.is_empty(),
            "Baseline returned no events; cannot validate pagination"
        );

        // Pick a cursor near the end so only a few events remain. This makes the
        // limit=1 pagination test fast while still exercising cursor semantics.
        let mut baseline_keys: Vec<_> = baseline_events.iter().map(event_key).collect();
        baseline_keys.sort();
        let last_key = *baseline_keys
            .last()
            .expect("baseline_keys must be non-empty");
        let cursor_seq = last_key.1.saturating_sub(3);
        let cursor: Option<EventID> = Some((block_number, cursor_seq));

        let expected_set: BTreeSet<_> = baseline_events
            .iter()
            .filter(|e| e.id.event_seq > cursor_seq)
            .map(event_key)
            .collect();
        assert!(
            !expected_set.is_empty(),
            "Need at least one event after cursor to validate pagination"
        );

        // Paginated: use the production pagination logic with limit=1.
        let filter = EventFilter {
            from_block: Some(block_number),
            to_block: Some(block_number),
            type_tags: Some(vec![selected_type_tag]),
            limit: Some(1),
        };

        let mut current_cursor = cursor;
        let mut paged_set: BTreeSet<(u64, u64, [u8; 32])> = BTreeSet::new();
        let mut last_cursor: Option<EventID> = None;

        for _ in 0..20 {
            let page = tokio::time::timeout(
                Duration::from_secs(5),
                query_events_impl(rpc.as_ref().unwrap(), filter.clone(), current_cursor),
            )
            .await
            .expect("query_events timed out")
            .expect("query_events failed");

            if page.data.is_empty() {
                assert!(!page.has_next_page, "Empty page must be terminal");
                break;
            }

            for ev in &page.data {
                assert_eq!(ev.id.block_number, block_number);
                assert!(ev.id.event_seq > cursor_seq);
            }

            let mut keys: Vec<_> = page.data.iter().map(event_key).collect();
            let mut sorted = keys.clone();
            sorted.sort();
            assert_eq!(keys, sorted, "Page data is not deterministically sorted");

            for k in keys.drain(..) {
                paged_set.insert(k);
            }

            if !page.has_next_page {
                break;
            }

            let next = page
                .next_cursor
                .expect("has_next_page=true but next_cursor is None");
            if let Some(prev) = last_cursor {
                assert!(next > prev, "Cursor must be strictly increasing");
            }
            last_cursor = Some(next);
            current_cursor = Some(next);

            if paged_set.len() >= expected_set.len() {
                // We collected everything expected after the cursor; no need to continue.
                break;
            }
        }

        assert_eq!(
            paged_set, expected_set,
            "Paginated subset mismatched baseline subset"
        );

        // Drop runtime-owning objects on a blocking thread.
        let rpc_to_drop = rpc.take().unwrap();
        drop_on_blocking_thread(rpc_to_drop).await;
        let node_to_drop = node.take().unwrap();
        drop_on_blocking_thread(node_to_drop).await;
    }
}
