// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::base_types::StarcoinAddress;
use super::collection_types::VecMap;
use move_core_types::ident_str;
use move_core_types::identifier::IdentStr;
use num_enum::TryFromPrimitive;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use strum_macros::Display;

// Module name constants
pub const BRIDGE_MODULE_NAME: &IdentStr = ident_str!("bridge");
pub const BRIDGE_TREASURY_MODULE_NAME: &IdentStr = ident_str!("treasury");
pub const BRIDGE_LIMITER_MODULE_NAME: &IdentStr = ident_str!("limiter");
pub const BRIDGE_COMMITTEE_MODULE_NAME: &IdentStr = ident_str!("committee");
pub const BRIDGE_MESSAGE_MODULE_NAME: &IdentStr = ident_str!("message");

// Function name constants
pub const BRIDGE_CREATE_FUNCTION_NAME: &IdentStr = ident_str!("create");
pub const BRIDGE_INIT_COMMITTEE_FUNCTION_NAME: &IdentStr = ident_str!("init_bridge_committee");
pub const BRIDGE_REGISTER_FOREIGN_TOKEN_FUNCTION_NAME: &IdentStr =
    ident_str!("register_foreign_token");
pub const BRIDGE_CREATE_ADD_TOKEN_ON_STARCOIN_MESSAGE_FUNCTION_NAME: &IdentStr =
    ident_str!("create_add_native_token_on_starcoin");
pub const BRIDGE_EXECUTE_SYSTEM_MESSAGE_FUNCTION_NAME: &IdentStr =
    ident_str!("execute_system_message");
pub const BRIDGE_SUPPORTED_ASSET: &[&str] = &["btc", "eth", "usdc", "usdt"];

// Committee voting power constants
pub const BRIDGE_COMMITTEE_MINIMAL_VOTING_POWER: u64 = 7500; // out of 10000 (75%)
pub const BRIDGE_COMMITTEE_MAXIMAL_VOTING_POWER: u64 = 10000; // (100%)

// Approval threshold constants
pub const APPROVAL_THRESHOLD_TOKEN_TRANSFER: u64 = 3334;
pub const APPROVAL_THRESHOLD_EMERGENCY_PAUSE: u64 = 450;
pub const APPROVAL_THRESHOLD_EMERGENCY_UNPAUSE: u64 = 5001;
pub const APPROVAL_THRESHOLD_COMMITTEE_BLOCKLIST: u64 = 5001;
pub const APPROVAL_THRESHOLD_LIMIT_UPDATE: u64 = 5001;
pub const APPROVAL_THRESHOLD_ASSET_PRICE_UPDATE: u64 = 5001;
pub const APPROVAL_THRESHOLD_EVM_CONTRACT_UPGRADE: u64 = 5001;
pub const APPROVAL_THRESHOLD_ADD_TOKENS_ON_STARCOIN: u64 = 5001;
pub const APPROVAL_THRESHOLD_ADD_TOKENS_ON_EVM: u64 = 5001;
pub const APPROVAL_THRESHOLD_UPDATE_COMMITTEE_MEMBER: u64 = 5001;

// const for initial token ids for convenience
pub const TOKEN_ID_STARCOIN: u8 = 0;
pub const TOKEN_ID_BTC: u8 = 1;
pub const TOKEN_ID_ETH: u8 = 2;
pub const TOKEN_ID_USDC: u8 = 3;
pub const TOKEN_ID_USDT: u8 = 4;

#[derive(
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Clone,
    Copy,
    TryFromPrimitive,
    JsonSchema,
    Hash,
    Display,
)]
#[repr(u8)]
pub enum BridgeChainId {
    StarcoinMainnet = 0,
    StarcoinTestnet = 1,
    StarcoinCustom = 2,

    EthMainnet = 10,
    EthSepolia = 11,
    EthCustom = 12,
}

impl BridgeChainId {
    pub fn is_starcoin_bridge_chain(&self) -> bool {
        matches!(
            self,
            BridgeChainId::StarcoinMainnet
                | BridgeChainId::StarcoinTestnet
                | BridgeChainId::StarcoinCustom
        )
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BridgeSummary {
    #[schemars(with = "String")]
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub bridge_version: u64,
    // Message version
    pub message_version: u8,
    /// Self Chain ID
    pub chain_id: u8,
    /// Sequence numbers of all message types
    pub sequence_nums: Vec<(u8, u64)>,
    pub committee: BridgeCommitteeSummary,
    /// Summary of the treasury
    pub treasury: BridgeTreasurySummary,
    /// Summary of the limiter
    pub limiter: BridgeLimiterSummary,
    /// Whether the bridge is currently frozen or not
    pub is_frozen: bool,
    // TODO: add treasury
}

impl Default for BridgeSummary {
    fn default() -> Self {
        BridgeSummary {
            bridge_version: 1,
            message_version: 1,
            chain_id: 1,
            sequence_nums: vec![],
            committee: BridgeCommitteeSummary::default(),
            treasury: BridgeTreasurySummary::default(),
            limiter: BridgeLimiterSummary::default(),
            is_frozen: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BridgeTokenMetadata {
    pub id: u8,
    pub decimal_multiplier: u64,
    pub notional_value: u64,
    pub native_token: bool,
}

/// Rust version of the Move committee::BridgeCommittee type.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MoveTypeBridgeCommittee {
    pub members: VecMap<Vec<u8>, MoveTypeCommitteeMember>,
    pub member_registrations: VecMap<StarcoinAddress, MoveTypeCommitteeMemberRegistration>,
    pub last_committee_update_epoch: u64,
}

/// Rust version of the Move committee::CommitteeMemberRegistration type.
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MoveTypeCommitteeMemberRegistration {
    pub starcoin_bridge_address: StarcoinAddress,
    pub bridge_pubkey_bytes: Vec<u8>,
    pub http_rest_url: Vec<u8>,
}

impl Default for MoveTypeCommitteeMemberRegistration {
    fn default() -> Self {
        Self {
            starcoin_bridge_address: StarcoinAddress::ZERO,
            bridge_pubkey_bytes: Vec::new(),
            http_rest_url: Vec::new(),
        }
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct BridgeCommitteeSummary {
    pub members: Vec<(Vec<u8>, MoveTypeCommitteeMember)>,
    pub member_registration: Vec<(StarcoinAddress, MoveTypeCommitteeMemberRegistration)>,
    pub last_committee_update_epoch: u64,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct BridgeLimiterSummary {
    pub transfer_limit: Vec<(BridgeChainId, BridgeChainId, u64)>,
    pub transfer_records: Vec<(BridgeChainId, BridgeChainId, MoveTypeBridgeTransferRecord)>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct BridgeTreasurySummary {
    pub supported_tokens: Vec<(String, BridgeTokenMetadata)>,
    pub id_token_type_map: Vec<(u8, String)>,
}

/// Rust version of the Move committee::CommitteeMember type.
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MoveTypeCommitteeMember {
    pub starcoin_bridge_address: StarcoinAddress,
    pub bridge_pubkey_bytes: Vec<u8>,
    pub voting_power: u64,
    pub http_rest_url: Vec<u8>,
    pub blocklisted: bool,
}

impl Default for MoveTypeCommitteeMember {
    fn default() -> Self {
        Self {
            starcoin_bridge_address: StarcoinAddress::ZERO,
            bridge_pubkey_bytes: Vec::new(),
            voting_power: 0,
            http_rest_url: Vec::new(),
            blocklisted: false,
        }
    }
}

/// Rust version of the Move message::BridgeMessageKey type.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct MoveTypeBridgeMessageKey {
    pub source_chain: u8,
    pub message_type: u8,
    pub bridge_seq_num: u64,
}

/// Rust version of the Move limiter::TransferRecord type.
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct MoveTypeBridgeTransferRecord {
    pub hour_head: u64,
    pub hour_tail: u64,
    pub per_hour_amounts: Vec<u64>,
    pub total_amount: u64,
}

/// Rust version of the Move message::BridgeMessage type.
#[derive(Debug, Serialize, Deserialize)]
pub struct MoveTypeBridgeMessage {
    pub message_type: u8,
    pub message_version: u8,
    pub seq_num: u64,
    pub source_chain: u8,
    pub payload: Vec<u8>,
}

/// Rust version of the Move message::BridgeMessage type.
#[derive(Debug, Serialize, Deserialize)]
pub struct MoveTypeBridgeRecord {
    pub message: MoveTypeBridgeMessage,
    pub verified_signatures: Option<Vec<Vec<u8>>>,
    pub claimed: bool,
}

/// Rust version of the Move message::TokenTransferPayload type.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct MoveTypeTokenTransferPayload {
    pub sender_address: Vec<u8>,
    pub target_chain: u8,
    pub target_address: Vec<u8>,
    pub token_type: u8,
    pub amount: u64,
}

/// Rust version of the Move message::ParsedTokenTransferMessage type.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct MoveTypeParsedTokenTransferMessage {
    pub message_version: u8,
    pub seq_num: u64,
    pub source_chain: u8,
    pub payload: Vec<u8>,
    pub parsed_payload: MoveTypeTokenTransferPayload,
}
