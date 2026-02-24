// Wrapper around Starcoin RPC types for bridge compatibility

use serde::{Deserialize, Serialize};

// Re-export Starcoin RPC types
pub use starcoin_rpc_api::types::*;

// Add Starcoin-specific types that Bridge needs

/// Bridge-compatible Starcoin event structure
/// Constructed from Starcoin RPC's TransactionEventView
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarcoinEvent {
    pub id: EventID,
    pub type_: move_core_types::language_storage::StructTag,
    pub bcs: Vec<u8>,
    pub block_hash: Option<starcoin_crypto::HashValue>,
}

impl StarcoinEvent {
    /// Create StarcoinEvent from TransactionEventView returned by RPC
    pub fn try_from_rpc_event(
        event_view: &serde_json::Value,
        tx_digest: [u8; 32],
    ) -> anyhow::Result<Self> {
        use std::str::FromStr;

        // Extract type_tag string (e.g., "0x246b237c16c761e9478783dd83f7004a::bridge::TokenDepositedEvent")
        let type_tag_str = event_view
            .get("type_tag")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing type_tag in event"))?;

        // Parse StructTag from string
        let struct_tag = move_core_types::language_storage::StructTag::from_str(type_tag_str)?;

        // Extract event data (BCS encoded bytes, hex string)
        let data_hex = event_view
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing data in event"))?;
        let data = hex::decode(data_hex.trim_start_matches("0x"))?;

        // Extract event sequence number
        let event_seq = event_view
            .get("event_seq_number")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        // Extract block number - handle both string and number formats
        let block_number = event_view
            .get("block_number")
            .and_then(|v| {
                if let Some(s) = v.as_str() {
                    s.parse::<u64>().ok()
                } else {
                    v.as_u64()
                }
            })
            .unwrap_or(0);

        // Extract block hash if available
        let block_hash = event_view
            .get("block_hash")
            .and_then(|v| v.as_str())
            .and_then(|s| starcoin_crypto::HashValue::from_str(s).ok());

        Ok(Self {
            id: EventID {
                tx_digest,
                event_seq,
                block_number,
            },
            type_: struct_tag,
            bcs: data,
            block_hash,
        })
    }

    /// Create a dummy StarcoinEvent for testing (deterministic)
    #[cfg(test)]
    pub fn dummy_for_testing() -> Self {
        use std::str::FromStr;

        Self {
            id: EventID {
                tx_digest: [0u8; 32],
                event_seq: 0,
                block_number: 1,
            },
            type_: move_core_types::language_storage::StructTag::from_str("0x1::test::TestEvent")
                .unwrap(),
            bcs: vec![],
            block_hash: None,
        }
    }

    /// Create a random StarcoinEvent for testing
    pub fn random_for_testing() -> Self {
        use rand::RngCore;
        use std::str::FromStr;

        let mut tx_digest = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut tx_digest);

        Self {
            id: EventID {
                tx_digest,
                event_seq: rand::random(),
                block_number: rand::random(),
            },
            type_: move_core_types::language_storage::StructTag::from_str("0x1::test::TestEvent")
                .unwrap(),
            bcs: vec![],
            block_hash: None,
        }
    }
}

/// Event ID contains transaction digest, event sequence, and block number
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Copy)]
pub struct EventID {
    pub tx_digest: [u8; 32],
    pub event_seq: u64,
    /// Block number where this event was emitted - used for cursor pagination
    pub block_number: u64,
}

impl From<EventID> for (u64, u64) {
    fn from(id: EventID) -> (u64, u64) {
        // For cursor: (block_number, event_seq) - used to paginate event queries
        (id.block_number, id.event_seq)
    }
}

// Placeholder for Starcoin execution status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StarcoinExecutionStatus {
    Success,
    Failure { error: String },
}

// Placeholder for Starcoin transaction block effects API
pub trait StarcoinTransactionBlockEffectsAPI {
    fn status(&self) -> &StarcoinExecutionStatus;
}

/// Wrapper for transaction block events
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StarcoinTransactionBlockEvents {
    pub data: Vec<StarcoinEvent>,
}

impl StarcoinTransactionBlockEvents {
    /// Iterate over events
    pub fn iter(&self) -> impl Iterator<Item = &StarcoinEvent> {
        self.data.iter()
    }
}

// Placeholder for Starcoin transaction block response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarcoinTransactionBlockResponse {
    pub digest: Option<[u8; 32]>,
    pub effects: Option<StarcoinTransactionBlockEffects>,
    pub events: Option<StarcoinTransactionBlockEvents>,
    pub object_changes: Option<Vec<ObjectChange>>,
}

impl StarcoinTransactionBlockResponse {
    /// Create a new response with the given digest
    pub fn new(digest: [u8; 32]) -> Self {
        Self {
            digest: Some(digest),
            effects: None,
            events: None,
            object_changes: None,
        }
    }

    pub fn status_ok(&self) -> Option<bool> {
        self.effects
            .as_ref()
            .map(|e| matches!(e.status(), StarcoinExecutionStatus::Success))
    }

    /// Get the status directly if effects exist
    pub fn execution_status(&self) -> Option<&StarcoinExecutionStatus> {
        self.effects.as_ref().map(|e| e.status())
    }
}

// Static default for when no effects exist
static DEFAULT_FAILURE_STATUS: std::sync::OnceLock<StarcoinExecutionStatus> =
    std::sync::OnceLock::new();

impl StarcoinTransactionBlockEffectsAPI for StarcoinTransactionBlockResponse {
    fn status(&self) -> &StarcoinExecutionStatus {
        self.effects
            .as_ref()
            .map(|e| e.status())
            .unwrap_or_else(|| {
                DEFAULT_FAILURE_STATUS.get_or_init(|| StarcoinExecutionStatus::Failure {
                    error: "No effects".to_string(),
                })
            })
    }
}

// Placeholder for transaction effects
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarcoinTransactionBlockEffects {
    pub status: StarcoinExecutionStatus,
    pub transaction_digest: Option<[u8; 32]>,
}

impl StarcoinTransactionBlockEffects {
    /// Create new effects for testing
    pub fn new_for_testing(tx_digest: [u8; 32], status: StarcoinExecutionStatus) -> Self {
        Self {
            status,
            transaction_digest: Some(tx_digest),
        }
    }

    pub fn status(&self) -> &StarcoinExecutionStatus {
        &self.status
    }
}

// Placeholder for Starcoin transaction block response options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StarcoinTransactionBlockResponseOptions {
    pub show_input: bool,
    pub show_raw_input: bool,
    pub show_effects: bool,
    pub show_events: bool,
    pub show_object_changes: bool,
    pub show_balance_changes: bool,
}

impl StarcoinTransactionBlockResponseOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_input(mut self) -> Self {
        self.show_input = true;
        self
    }

    pub fn with_effects(mut self) -> Self {
        self.show_effects = true;
        self
    }

    pub fn with_events(mut self) -> Self {
        self.show_events = true;
        self
    }

    pub fn with_object_changes(mut self) -> Self {
        self.show_object_changes = true;
        self
    }

    pub fn with_balance_changes(mut self) -> Self {
        self.show_balance_changes = true;
        self
    }
}

/// Event filter for querying Starcoin events
/// Compatible with Starcoin RPC's EventFilter structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventFilter {
    /// From block number
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_block: Option<u64>,
    /// To block number
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_block: Option<u64>,
    /// Type tags to filter events (e.g., "0x1::bridge::TokenDepositedEvent")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_tags: Option<Vec<String>>,
    /// Maximum number of events to return
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl EventFilter {
    /// Create a filter for events of a specific type
    pub fn move_event_type(type_tag: &str) -> Self {
        Self {
            type_tags: Some(vec![type_tag.to_string()]),
            ..Default::default()
        }
    }

    /// Create a filter with block range
    pub fn block_range(from_block: u64, to_block: u64) -> Self {
        Self {
            from_block: Some(from_block),
            to_block: Some(to_block),
            ..Default::default()
        }
    }

    /// Convert to JSON Value for RPC call
    pub fn to_rpc_filter(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

// Placeholder for generic page
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<T, C = (u64, u64)> {
    pub data: Vec<T>,
    pub next_cursor: Option<C>,
    pub has_next_page: bool,
}

impl<T, C> Page<T, C> {
    /// Create an empty page for testing
    pub fn empty() -> Self {
        Self {
            data: vec![],
            next_cursor: None,
            has_next_page: false,
        }
    }
}

// EventPage with (u64, u64) tuple as cursor (block_num, event_idx)
pub type EventPage = Page<StarcoinEvent, (u64, u64)>;

// Placeholder for StarcoinObjectDataOptions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StarcoinObjectDataOptions {
    pub show_type: bool,
    pub show_owner: bool,
    pub show_previous_transaction: bool,
    pub show_display: bool,
    pub show_content: bool,
    pub show_bcs: bool,
    pub show_storage_rebate: bool,
}

impl StarcoinObjectDataOptions {
    pub fn with_owner(mut self) -> Self {
        self.show_owner = true;
        self
    }

    pub fn with_content(mut self) -> Self {
        self.show_content = true;
        self
    }

    pub fn new() -> Self {
        Self::default()
    }
}

// Placeholder for StarcoinExecutionResult
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarcoinExecutionResult {
    pub return_values: Vec<(Vec<u8>, String)>, // (value_bytes, type_tag)
}

// Placeholder for DevInspectResults
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevInspectResults {
    pub results: Option<Vec<StarcoinExecutionResult>>,
    pub effects: Option<String>, // Simplified - should be StarcoinTransactionBlockEffects
}

// Placeholder for StarcoinObjectResponse
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarcoinObjectResponse {
    pub data: Option<StarcoinObjectData>,
}

// Placeholder for StarcoinObjectData
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarcoinObjectData {
    pub object_id: [u8; 32],
    pub version: u64,
    pub digest: [u8; 32],
    pub owner: Option<Owner>,
}

impl StarcoinObjectData {
    pub fn object_ref(&self) -> ([u8; 32], u64, [u8; 32]) {
        (self.object_id, self.version, self.digest)
    }
}

// Placeholder for Owner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Owner {
    AddressOwner([u8; 32]),
    ObjectOwner([u8; 32]),
    Shared { initial_shared_version: u64 },
    Immutable,
}

// Placeholder for Supply
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Supply {
    pub value: u64,
}

// Placeholder for Coin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coin {
    pub coin_object_id: [u8; 32],
    pub version: u64,
    pub digest: [u8; 32],
    pub balance: u64,
    pub coin_type: String,
    pub previous_transaction: [u8; 32],
}

impl Coin {
    pub fn object_ref(&self) -> ([u8; 32], u64, [u8; 32]) {
        (self.coin_object_id, self.version, self.digest)
    }
}

// Placeholder for ObjectChange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObjectChange {
    Created {
        sender: [u8; 32],
        owner: String,
        object_type: move_core_types::language_storage::StructTag,
        object_id: [u8; 32],
        version: u64,
        digest: [u8; 32],
    },
    Mutated {
        sender: [u8; 32],
        owner: String,
        object_type: move_core_types::language_storage::StructTag,
        object_id: [u8; 32],
        version: u64,
        previous_version: u64,
        digest: [u8; 32],
    },
    Deleted {
        sender: [u8; 32],
        object_id: [u8; 32],
        version: u64,
    },
}

impl ObjectChange {
    pub fn object_ref(&self) -> ([u8; 32], u64, [u8; 32]) {
        match self {
            ObjectChange::Created {
                object_id,
                version,
                digest,
                ..
            } => (*object_id, *version, *digest),
            ObjectChange::Mutated {
                object_id,
                version,
                digest,
                ..
            } => (*object_id, *version, *digest),
            ObjectChange::Deleted {
                object_id, version, ..
            } => (*object_id, *version, [0u8; 32]),
        }
    }
}

// Placeholder for StarcoinSystemStateSummary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarcoinValidatorSummary {
    pub starcoin_bridge_address: [u8; 32],
    pub protocol_pubkey_bytes: Vec<u8>,
    pub name: String,
    pub voting_power: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarcoinSystemStateSummary {
    pub epoch: u64,
    pub protocol_version: u64,
    pub system_state_version: u64,
    pub active_validators: Vec<StarcoinValidatorSummary>,
}

// Placeholder for StarcoinCommittee
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarcoinCommittee {
    pub epoch: u64,
    pub validators: std::collections::HashMap<[u8; 32], u64>, // address -> voting_power
}

// Coin page for paginated coin queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinPage {
    pub data: Vec<Coin>,
    pub next_cursor: Option<String>,
    pub has_next_page: bool,
}
