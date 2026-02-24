// Wrapper around Starcoin RPC client for bridge compatibility

use anyhow::Result;
use starcoin_rpc_client::RpcClient;
use starcoin_types::account_address::AccountAddress;
use starcoin_types::language_storage::StructTag;
use std::str::FromStr;

// Bridge module address on Starcoin
const BRIDGE_ADDRESS: &str = "0x246b237c16c761e9478783dd83f7004a";
const BRIDGE_MODULE: &str = "Bridge";
const BRIDGE_RESOURCE: &str = "Bridge";

// Sub-modules
pub mod error;

// StarcoinClient wraps Starcoin's RpcClient
// Note: RpcClient doesn't implement Clone, so we wrap it in Arc
pub struct StarcoinClient {
    client: std::sync::Arc<RpcClient>,
}

impl Clone for StarcoinClient {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
        }
    }
}

impl StarcoinClient {
    // Create a new StarcoinClient from a Starcoin RPC client
    pub fn new(client: RpcClient) -> Self {
        Self {
            client: std::sync::Arc::new(client),
        }
    }

    // Create a new StarcoinClient by connecting to a WebSocket URL
    pub fn connect_websocket(url: &str) -> Result<Self> {
        let client = RpcClient::connect_websocket(url)?;
        Ok(Self::new(client))
    }

    // Get read API interface
    pub fn read_api(&self) -> ReadApi {
        ReadApi {
            client: self.client.clone(),
        }
    }

    // Get governance API interface
    pub fn governance_api(&self) -> GovernanceApi {
        GovernanceApi {
            client: self.client.clone(),
        }
    }

    // Get event API interface
    pub fn event_api(&self) -> EventApi {
        EventApi {
            client: self.client.clone(),
        }
    }

    // Get Bridge Read API interface
    pub fn http(&self) -> BridgeReadApi {
        BridgeReadApi {
            client: self.client.clone(),
        }
    }

    // Get quorum driver API (stub)
    pub fn quorum_driver_api(&self) -> QuorumDriverApi {
        QuorumDriverApi {
            client: self.client.clone(),
        }
    }

    // Get the underlying Starcoin client
    pub fn starcoin_client(&self) -> &RpcClient {
        &self.client
    }
}

impl std::fmt::Debug for StarcoinClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StarcoinClient").finish()
    }
}

// ReadApi provides read-only access to blockchain data
pub struct ReadApi {
    client: std::sync::Arc<RpcClient>,
}

impl ReadApi {
    // Get the underlying Starcoin client
    pub fn starcoin_client(&self) -> &RpcClient {
        &self.client
    }

    // Get the latest block number
    pub async fn get_latest_block_number(&self) -> Result<u64> {
        // Query latest block number from Starcoin node
        let chain_info = self.client.chain_info()?;
        Ok(chain_info.head.number.0)
    }

    // Get bridge summary
    pub async fn get_bridge_summary(&self) -> Result<starcoin_bridge_types::bridge::BridgeSummary> {
        // Query actual bridge state from Starcoin via RPC
        let bridge_addr = AccountAddress::from_hex_literal(BRIDGE_ADDRESS)?;
        let resource_type = format!("{}::{}::{}", BRIDGE_ADDRESS, BRIDGE_MODULE, BRIDGE_RESOURCE);
        let struct_tag = StructTag::from_str(&resource_type)?;

        let resource_opt = self.client.get_resource(bridge_addr, struct_tag)?;

        if let Some(resource) = resource_opt {
            // Parse the Bridge resource and convert to BridgeSummary
            parse_bridge_summary_from_resource(resource)
        } else {
            anyhow::bail!("Bridge resource not found at address {}", BRIDGE_ADDRESS)
        }
    }

    // Dev inspect transaction block
    // Note: Parameters are kept for API compatibility but not used in Starcoin
    pub async fn dev_inspect_transaction_block(
        &self,
        _sender: [u8; 32],
        _tx_kind: starcoin_bridge_types::transaction::TransactionKind,
        _gas_price: Option<u64>,
        _epoch: Option<u64>,
    ) -> Result<starcoin_bridge_json_rpc_types::DevInspectResults> {
        // Starcoin uses contract.dry_run for transaction simulation
        // Since we don't have the full transaction structure yet, return minimal results
        log::debug!("dev_inspect_transaction_block called - returning minimal results");
        Ok(starcoin_bridge_json_rpc_types::DevInspectResults {
            results: None,
            effects: None,
        })
    }

    // Get chain identifier
    pub async fn get_chain_identifier(&self) -> Result<String> {
        // Query chain info from Starcoin node
        let node_info = self.client.node_info()?;
        Ok(node_info.net.to_string())
    }
}

// GovernanceApi provides governance-related access
pub struct GovernanceApi {
    client: std::sync::Arc<RpcClient>,
}

impl GovernanceApi {
    // Get the underlying Starcoin client
    pub fn starcoin_client(&self) -> &RpcClient {
        &self.client
    }

    // Get latest system state
    pub async fn get_latest_starcoin_bridge_system_state(
        &self,
    ) -> Result<starcoin_bridge_json_rpc_types::StarcoinSystemStateSummary> {
        // Query actual Starcoin epoch and chain info
        let chain_info = self.client.chain_info()?;

        Ok(starcoin_bridge_json_rpc_types::StarcoinSystemStateSummary {
            epoch: chain_info.head.number.0, // Use block number as epoch
            protocol_version: 1,             // Starcoin doesn't expose protocol version in same way
            system_state_version: 1,
            active_validators: vec![],
        })
    }

    // Get committee info
    pub async fn get_committee_info(
        &self,
        epoch: Option<u64>,
    ) -> Result<starcoin_bridge_json_rpc_types::StarcoinCommittee> {
        // TODO: Query actual Starcoin bridge committee from chain
        use std::collections::HashMap;

        Ok(starcoin_bridge_json_rpc_types::StarcoinCommittee {
            epoch: epoch.unwrap_or(0),
            validators: HashMap::new(),
        })
    }

    // Get reference gas price
    pub async fn get_reference_gas_price(&self) -> Result<u64> {
        // Query gas price from Starcoin node
        // In Starcoin, gas price is in nanoSTC
        let _chain_info = self.client.chain_info()?;
        // Use a default gas price based on the chain if available
        // For now, return 1 nanoSTC as minimum
        Ok(1)
    }
}

// EventApi provides event query access
pub struct EventApi {
    client: std::sync::Arc<RpcClient>,
}

impl EventApi {
    // Get the underlying Starcoin client
    pub fn starcoin_client(&self) -> &RpcClient {
        &self.client
    }

    // Query events
    // Note: Parameters are kept for API compatibility but not all used in current implementation
    pub async fn query_events(
        &self,
        query: starcoin_bridge_json_rpc_types::EventFilter,
        cursor: Option<starcoin_bridge_types::event::EventID>,
        _limit: Option<usize>,
        _descending: bool,
    ) -> Result<starcoin_bridge_json_rpc_types::EventPage> {
        log::debug!(
            "query_events called with query: {:?}, cursor: {:?}",
            query,
            cursor
        );

        // For now, return empty results
        // This is a stub for SDK-based test client; production uses StarcoinJsonRpcClient
        Ok(starcoin_bridge_json_rpc_types::EventPage {
            data: vec![],
            next_cursor: None,
            has_next_page: false,
        })
    }

    // Get events by transaction digest
    pub async fn get_events(
        &self,
        digest: &[u8; 32],
    ) -> Result<Vec<starcoin_bridge_types::event::Event>> {
        // Query transaction events from Starcoin using call_raw_api
        // This avoids HashValue type conflicts between different crates
        let tx_hash_hex = format!("0x{}", hex::encode(digest));

        // Use raw API call to get transaction info
        let result = self.client.call_raw_api(
            "chain.get_transaction_info",
            starcoin_rpc_client::Params::Array(vec![serde_json::Value::String(
                tx_hash_hex.clone(),
            )]),
        )?;

        // Check if transaction was found
        if result.is_null() {
            log::debug!("Transaction {} not found", hex::encode(digest));
            return Ok(vec![]);
        }

        // TODO: Parse transaction info and extract events
        // For now, return empty list as event conversion needs implementation
        log::debug!(
            "Found transaction {}, but event conversion not yet implemented",
            hex::encode(digest)
        );
        Ok(vec![])
    }
}

// QuorumDriverApi provides quorum driver access
pub struct QuorumDriverApi {
    client: std::sync::Arc<RpcClient>,
}

impl QuorumDriverApi {
    // Get the underlying Starcoin client
    pub fn starcoin_client(&self) -> &RpcClient {
        &self.client
    }

    // Execute transaction block
    // Note: Parameters are kept for API compatibility but not used in current stub implementation
    pub async fn execute_transaction_block(
        &self,
        _tx: starcoin_bridge_types::transaction::Transaction,
        _options: starcoin_bridge_json_rpc_types::StarcoinTransactionBlockResponseOptions,
        _request_type: starcoin_bridge_types::quorum_driver_types::ExecuteTransactionRequestType,
    ) -> Result<starcoin_bridge_json_rpc_types::StarcoinTransactionBlockResponse> {
        log::warn!("execute_transaction_block called - full implementation requires transaction format conversion");

        Ok(
            starcoin_bridge_json_rpc_types::StarcoinTransactionBlockResponse {
                digest: None,
                effects: None,
                events: None,
                object_changes: None,
            },
        )
    }
}

// BridgeReadApi provides bridge-specific read access
pub struct BridgeReadApi {
    client: std::sync::Arc<RpcClient>,
}

impl BridgeReadApi {
    // Get the underlying Starcoin client
    pub fn starcoin_client(&self) -> &RpcClient {
        &self.client
    }

    // Get chain identifier (returns network name)
    pub async fn bridge_get_chain_identifier(&self) -> Result<String> {
        // Query chain info from Starcoin node
        let node_info = self.client.node_info()?;
        Ok(node_info.net.to_string())
    }

    // Get latest block number
    pub async fn bridge_get_latest_block_number(&self) -> Result<u64> {
        // Query latest block number from Starcoin
        let chain_info = self.client.chain_info()?;
        Ok(chain_info.head.number.0)
    }
}

// Implement BridgeReadApiClient for BridgeReadApi
#[async_trait::async_trait]
impl starcoin_bridge_json_rpc_api::BridgeReadApiClient for BridgeReadApi {
    async fn get_bridge_object_initial_shared_version(&self) -> Result<u64, eyre::Error> {
        // Starcoin doesn't have shared objects concept, return a fixed version
        Ok(1)
    }

    async fn get_latest_bridge(
        &self,
    ) -> Result<starcoin_bridge_vm_types::bridge::bridge::BridgeSummary, eyre::Error> {
        // Get the actual bridge summary from chain
        let summary = self
            .starcoin_client()
            .get_resource(
                AccountAddress::from_hex_literal(BRIDGE_ADDRESS)
                    .map_err(|e| eyre::eyre!("Invalid bridge address: {}", e))?,
                StructTag::from_str(&format!(
                    "{}::{}::{}",
                    BRIDGE_ADDRESS, BRIDGE_MODULE, BRIDGE_RESOURCE
                ))
                .map_err(|e| eyre::eyre!("Invalid struct tag: {}", e))?,
            )
            .map_err(|e| eyre::eyre!("Failed to get bridge resource: {}", e))?;

        if let Some(resource) = summary {
            parse_bridge_vm_summary_from_resource(resource)
                .map_err(|e| eyre::eyre!("Failed to parse bridge summary: {}", e))
        } else {
            Err(eyre::eyre!(
                "Bridge resource not found at address {}",
                BRIDGE_ADDRESS
            ))
        }
    }
}

// StarcoinClientBuilder for constructing StarcoinClient instances
pub struct StarcoinClientBuilder {
    url: Option<String>,
}

impl StarcoinClientBuilder {
    // Create a new builder
    pub fn new() -> Self {
        Self { url: None }
    }

    // Set the RPC URL
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    // Build the StarcoinClient from a URL string (static method)
    pub fn build_from_url(url: impl AsRef<str>) -> Result<StarcoinClient> {
        let url_str = url.as_ref();
        let client = if url_str.starts_with("ws://") || url_str.starts_with("wss://") {
            RpcClient::connect_websocket(url_str)?
        } else if url_str.starts_with("http://") || url_str.starts_with("https://") {
            // For HTTP URLs, convert to WebSocket
            let ws_url = url_str
                .replace("http://", "ws://")
                .replace("https://", "wss://");
            RpcClient::connect_websocket(&ws_url)?
        } else {
            // Assume it's an IPC path
            RpcClient::connect_ipc(url_str)?
        };

        Ok(StarcoinClient::new(client))
    }

    // Build with configured URL (instance method)
    pub fn build(self) -> Result<StarcoinClient> {
        let url = self.url.ok_or_else(|| anyhow::anyhow!("URL not set"))?;
        Self::build_from_url(&url)
    }
}

impl Default for StarcoinClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

//////////////////////////////////////////////////////
// Helper functions to parse Bridge resources from Starcoin
//

use starcoin_rpc_api::types::AnnotatedMoveStructView;
use starcoin_types::identifier::Identifier;

// Helper to get field from Vec<(Identifier, AnnotatedMoveValueView)>
fn get_field<'a>(
    fields: &'a [(Identifier, starcoin_rpc_api::types::AnnotatedMoveValueView)],
    name: &str,
) -> Option<&'a starcoin_rpc_api::types::AnnotatedMoveValueView> {
    fields
        .iter()
        .find(|(id, _)| id.as_str() == name)
        .map(|(_, v)| v)
}

// Parse BridgeSummary from Move resource (for starcoin_bridge_types)
fn parse_bridge_summary_from_resource(
    resource: AnnotatedMoveStructView,
) -> Result<starcoin_bridge_types::bridge::BridgeSummary> {
    use starcoin_bridge_types::bridge::*;

    // The Bridge resource has an 'inner' field of type BridgeInner
    let inner = get_field(&resource.value, "inner")
        .ok_or_else(|| anyhow::anyhow!("Missing 'inner' field in Bridge resource"))?;

    let inner_struct = match inner {
        starcoin_rpc_api::types::AnnotatedMoveValueView::Struct(s) => s,
        _ => anyhow::bail!("Expected 'inner' to be a struct"),
    };

    // Extract fields from BridgeInner
    let bridge_version = extract_u64(&inner_struct.value, "bridge_version")?;
    let message_version = extract_u8(&inner_struct.value, "message_version")?;
    let chain_id = extract_u8(&inner_struct.value, "chain_id")?;
    let paused = extract_bool(&inner_struct.value, "paused")?;

    // Parse committee
    let committee = parse_committee(&inner_struct.value)?;

    // Parse treasury
    let treasury = BridgeTreasurySummary::default(); // TODO: parse treasury details

    Ok(BridgeSummary {
        committee,
        treasury,
        bridge_version,
        message_version,
        chain_id,
        sequence_nums: Default::default(),
        limiter: Default::default(),
        is_frozen: paused,
    })
}

// Parse BridgeSummary from Move resource (for starcoin_bridge_vm_types)
fn parse_bridge_vm_summary_from_resource(
    resource: AnnotatedMoveStructView,
) -> Result<starcoin_bridge_vm_types::bridge::bridge::BridgeSummary> {
    use starcoin_bridge_vm_types::bridge::bridge::*;

    let inner = get_field(&resource.value, "inner")
        .ok_or_else(|| anyhow::anyhow!("Missing 'inner' field in Bridge resource"))?;

    let inner_struct = match inner {
        starcoin_rpc_api::types::AnnotatedMoveValueView::Struct(s) => s,
        _ => anyhow::bail!("Expected 'inner' to be a struct"),
    };

    let bridge_version = extract_u64(&inner_struct.value, "bridge_version")?;
    let message_version = extract_u8(&inner_struct.value, "message_version")?;
    let chain_id = extract_u8(&inner_struct.value, "chain_id")?;
    let paused = extract_bool(&inner_struct.value, "paused")?;

    let committee = parse_committee_vm(&inner_struct.value)?;
    let treasury = BridgeTreasurySummary::default();

    Ok(BridgeSummary {
        committee,
        treasury,
        bridge_version,
        message_version,
        chain_id,
        sequence_nums: Default::default(),
        limiter: Default::default(),
        is_frozen: paused,
    })
}

// Parse committee for starcoin_bridge_types
fn parse_committee(
    fields: &[(Identifier, starcoin_rpc_api::types::AnnotatedMoveValueView)],
) -> Result<starcoin_bridge_types::bridge::BridgeCommitteeSummary> {
    use starcoin_bridge_types::bridge::*;

    let committee_field = get_field(fields, "committee")
        .ok_or_else(|| anyhow::anyhow!("Missing 'committee' field"))?;

    let committee_struct = match committee_field {
        starcoin_rpc_api::types::AnnotatedMoveValueView::Struct(s) => s,
        _ => anyhow::bail!("Expected 'committee' to be a struct"),
    };

    let last_committee_update_epoch =
        extract_u64(&committee_struct.value, "last_committee_update_epoch")?;

    // Parse members from SimpleMap - returns Vec<(Vec<u8>, MoveTypeCommitteeMember)>
    let members = parse_committee_members(&committee_struct.value)?;

    Ok(BridgeCommitteeSummary {
        members,
        member_registration: vec![],
        last_committee_update_epoch,
    })
}

// Parse committee for starcoin_bridge_vm_types
fn parse_committee_vm(
    fields: &[(Identifier, starcoin_rpc_api::types::AnnotatedMoveValueView)],
) -> Result<starcoin_bridge_vm_types::bridge::bridge::BridgeCommitteeSummary> {
    use starcoin_bridge_vm_types::bridge::bridge::*;

    let committee_field = get_field(fields, "committee")
        .ok_or_else(|| anyhow::anyhow!("Missing 'committee' field"))?;

    let committee_struct = match committee_field {
        starcoin_rpc_api::types::AnnotatedMoveValueView::Struct(s) => s,
        _ => anyhow::bail!("Expected 'committee' to be a struct"),
    };

    let last_committee_update_epoch =
        extract_u64(&committee_struct.value, "last_committee_update_epoch")?;

    let members = parse_committee_members_vm(&committee_struct.value)?;

    Ok(BridgeCommitteeSummary {
        members,
        member_registration: vec![],
        last_committee_update_epoch,
    })
}

// Parse committee members from SimpleMap for starcoin_bridge_types
fn parse_committee_members(
    fields: &[(Identifier, starcoin_rpc_api::types::AnnotatedMoveValueView)],
) -> Result<
    Vec<(
        Vec<u8>,
        starcoin_bridge_vm_types::bridge::bridge::MoveTypeCommitteeMember,
    )>,
> {
    let members_field =
        get_field(fields, "members").ok_or_else(|| anyhow::anyhow!("Missing 'members' field"))?;

    // SimpleMap is represented as a struct with 'data' field containing vector of key-value pairs
    let members_struct = match members_field {
        starcoin_rpc_api::types::AnnotatedMoveValueView::Struct(s) => s,
        _ => anyhow::bail!("Expected 'members' to be a struct"),
    };

    let data_field = get_field(&members_struct.value, "data")
        .ok_or_else(|| anyhow::anyhow!("Missing 'data' field in SimpleMap"))?;

    let data_vec = match data_field {
        starcoin_rpc_api::types::AnnotatedMoveValueView::Vector(v) => v,
        _ => anyhow::bail!("Expected 'data' to be a vector"),
    };

    let mut members = Vec::new();
    for entry in data_vec {
        if let starcoin_rpc_api::types::AnnotatedMoveValueView::Struct(entry_struct) = entry {
            // Each entry has 'key' (pubkey bytes) and 'value' (CommitteeMember)
            let key_field = get_field(&entry_struct.value, "key")
                .ok_or_else(|| anyhow::anyhow!("Missing 'key' field in map entry"))?;
            let pubkey = extract_bytes_from_value(key_field)?;

            let value_field = get_field(&entry_struct.value, "value")
                .ok_or_else(|| anyhow::anyhow!("Missing 'value' field in map entry"))?;

            if let starcoin_rpc_api::types::AnnotatedMoveValueView::Struct(member_struct) =
                value_field
            {
                let member = parse_committee_member_vm(&member_struct.value)?;
                members.push((pubkey, member));
            }
        }
    }

    Ok(members)
}

// Parse committee members for starcoin_bridge_vm_types
fn parse_committee_members_vm(
    fields: &[(Identifier, starcoin_rpc_api::types::AnnotatedMoveValueView)],
) -> Result<
    Vec<(
        Vec<u8>,
        starcoin_bridge_vm_types::bridge::bridge::MoveTypeCommitteeMember,
    )>,
> {
    let members_field =
        get_field(fields, "members").ok_or_else(|| anyhow::anyhow!("Missing 'members' field"))?;

    let members_struct = match members_field {
        starcoin_rpc_api::types::AnnotatedMoveValueView::Struct(s) => s,
        _ => anyhow::bail!("Expected 'members' to be a struct"),
    };

    let data_field = get_field(&members_struct.value, "data")
        .ok_or_else(|| anyhow::anyhow!("Missing 'data' field in SimpleMap"))?;

    let data_vec = match data_field {
        starcoin_rpc_api::types::AnnotatedMoveValueView::Vector(v) => v,
        _ => anyhow::bail!("Expected 'data' to be a vector"),
    };

    let mut members = Vec::new();
    for entry in data_vec {
        if let starcoin_rpc_api::types::AnnotatedMoveValueView::Struct(entry_struct) = entry {
            let key_field = get_field(&entry_struct.value, "key")
                .ok_or_else(|| anyhow::anyhow!("Missing 'key' field in map entry"))?;
            let pubkey = extract_bytes_from_value(key_field)?;

            let value_field = get_field(&entry_struct.value, "value")
                .ok_or_else(|| anyhow::anyhow!("Missing 'value' field in map entry"))?;

            if let starcoin_rpc_api::types::AnnotatedMoveValueView::Struct(member_struct) =
                value_field
            {
                let member = parse_committee_member_vm(&member_struct.value)?;
                members.push((pubkey, member));
            }
        }
    }

    Ok(members)
}

// Parse individual committee member for starcoin_bridge_vm_types
fn parse_committee_member_vm(
    fields: &[(Identifier, starcoin_rpc_api::types::AnnotatedMoveValueView)],
) -> Result<starcoin_bridge_vm_types::bridge::bridge::MoveTypeCommitteeMember> {
    use move_core_types::account_address::AccountAddress as MoveAccountAddress;
    use starcoin_bridge_vm_types::bridge::bridge::*;

    let starcoin_address = extract_address(fields, "starcoin_address")?;
    let bridge_pubkey_bytes = extract_bytes(fields, "bridge_pubkey_bytes")?;
    let voting_power = extract_u64(fields, "voting_power")?;
    let http_rest_url = extract_bytes(fields, "http_rest_url")?;
    let blocklisted = extract_bool(fields, "blocklisted")?;

    // Convert AccountAddress to MoveAccountAddress (16 bytes)
    let move_addr = MoveAccountAddress::from_bytes(starcoin_address.as_ref())
        .unwrap_or(MoveAccountAddress::ZERO);

    Ok(MoveTypeCommitteeMember {
        starcoin_bridge_address: move_addr,
        bridge_pubkey_bytes,
        voting_power,
        http_rest_url,
        blocklisted,
    })
}

// Extract u64 from Move value
fn extract_u64(
    fields: &[(Identifier, starcoin_rpc_api::types::AnnotatedMoveValueView)],
    field_name: &str,
) -> Result<u64> {
    let value = get_field(fields, field_name)
        .ok_or_else(|| anyhow::anyhow!("Missing '{}' field", field_name))?;

    match value {
        starcoin_rpc_api::types::AnnotatedMoveValueView::U64(v) => Ok(v.0),
        _ => anyhow::bail!("Expected '{}' to be u64, got {:?}", field_name, value),
    }
}

// Extract u8 from Move value
fn extract_u8(
    fields: &[(Identifier, starcoin_rpc_api::types::AnnotatedMoveValueView)],
    field_name: &str,
) -> Result<u8> {
    let value = get_field(fields, field_name)
        .ok_or_else(|| anyhow::anyhow!("Missing '{}' field", field_name))?;

    match value {
        starcoin_rpc_api::types::AnnotatedMoveValueView::U8(v) => Ok(*v),
        _ => anyhow::bail!("Expected '{}' to be u8, got {:?}", field_name, value),
    }
}

// Extract bool from Move value
fn extract_bool(
    fields: &[(Identifier, starcoin_rpc_api::types::AnnotatedMoveValueView)],
    field_name: &str,
) -> Result<bool> {
    let value = get_field(fields, field_name)
        .ok_or_else(|| anyhow::anyhow!("Missing '{}' field", field_name))?;

    match value {
        starcoin_rpc_api::types::AnnotatedMoveValueView::Bool(v) => Ok(*v),
        _ => anyhow::bail!("Expected '{}' to be bool, got {:?}", field_name, value),
    }
}

// Extract bytes from Move value by field name
fn extract_bytes(
    fields: &[(Identifier, starcoin_rpc_api::types::AnnotatedMoveValueView)],
    field_name: &str,
) -> Result<Vec<u8>> {
    let value = get_field(fields, field_name)
        .ok_or_else(|| anyhow::anyhow!("Missing '{}' field", field_name))?;
    extract_bytes_from_value(value)
}

// Extract bytes from a Move value
fn extract_bytes_from_value(
    value: &starcoin_rpc_api::types::AnnotatedMoveValueView,
) -> Result<Vec<u8>> {
    match value {
        starcoin_rpc_api::types::AnnotatedMoveValueView::Bytes(v) => Ok(v.0.clone()),
        starcoin_rpc_api::types::AnnotatedMoveValueView::Vector(v) => {
            // Vector of u8
            let mut bytes = Vec::new();
            for item in v {
                if let starcoin_rpc_api::types::AnnotatedMoveValueView::U8(byte) = item {
                    bytes.push(*byte);
                } else {
                    anyhow::bail!("Expected vector of u8, got {:?}", item);
                }
            }
            Ok(bytes)
        }
        _ => anyhow::bail!("Expected bytes or vector<u8>, got {:?}", value),
    }
}

// Extract address from Move value
fn extract_address(
    fields: &[(Identifier, starcoin_rpc_api::types::AnnotatedMoveValueView)],
    field_name: &str,
) -> Result<AccountAddress> {
    let value = get_field(fields, field_name)
        .ok_or_else(|| anyhow::anyhow!("Missing '{}' field", field_name))?;

    match value {
        starcoin_rpc_api::types::AnnotatedMoveValueView::Address(addr) => Ok(*addr),
        _ => anyhow::bail!("Expected '{}' to be address, got {:?}", field_name, value),
    }
}
