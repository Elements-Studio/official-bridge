// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This file contains the definition of the StarcoinBridgeEvent enum, of
//! which each variant is an emitted Event struct defind in the Move
//! Bridge module. We rely on structures in this file to decode
//! the bcs content of the emitted events.

#![allow(non_upper_case_globals)]

use crate::crypto::BridgeAuthorityPublicKey;
use crate::error::BridgeError;
use crate::error::BridgeResult;
use crate::types::BridgeAction;
use crate::types::StarcoinToEthBridgeAction;
use ethers::types::Address as EthAddress;
use fastcrypto::encoding::Encoding;
use fastcrypto::encoding::Hex;
use fastcrypto::traits::ToFromBytes;
use move_core_types::language_storage::StructTag;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use starcoin_bridge_json_rpc_types::StarcoinEvent;
use starcoin_bridge_types::base_types::StarcoinAddress;
use starcoin_bridge_types::base_types::TransactionDigest;
use starcoin_bridge_types::bridge::BridgeChainId;
use starcoin_bridge_types::bridge::MoveTypeBridgeMessageKey;
use starcoin_bridge_types::bridge::MoveTypeCommitteeMemberRegistration;
use starcoin_bridge_types::collection_types::VecMap;
use starcoin_bridge_types::parse_token_code_bytes_to_type_tag;
use starcoin_bridge_types::TypeTag;
use starcoin_bridge_types::BRIDGE_PACKAGE_ID;
use std::str::FromStr;

// `TokendDepositedEvent` emitted in bridge.move
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct MoveTokenDepositedEvent {
    pub seq_num: u64,
    pub source_chain: u8,
    pub sender_address: Vec<u8>,
    pub target_chain: u8,
    pub target_address: Vec<u8>,
    pub token_type: u8,
    pub amount_starcoin_bridge_adjusted: u64,
}

macro_rules! new_move_event {
    ($struct_name:ident, $move_struct_name:ident) => {

        // `$move_struct_name` emitted in bridge.move
        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
        pub struct $move_struct_name {
            pub message_key: MoveTypeBridgeMessageKey,
        }

        // Sanitized version of the given `move_struct_name`
        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Hash)]
        pub struct $struct_name {
            pub nonce: u64,
            pub source_chain: BridgeChainId,
        }

        impl TryFrom<$move_struct_name> for $struct_name {
            type Error = BridgeError;

            fn try_from(event: $move_struct_name) -> BridgeResult<Self> {
                let source_chain = BridgeChainId::try_from(event.message_key.source_chain).map_err(|_| {
                    BridgeError::Generic(format!(
                        "Failed to convert {} to {}. Failed to convert source chain {} to BridgeChainId",
                        stringify!($move_struct_name),
                        stringify!($struct_name),
                        event.message_key.source_chain,
                    ))
                })?;
                Ok(Self {
                    nonce: event.message_key.bridge_seq_num,
                    source_chain,
                })
            }
        }
    };
}

new_move_event!(TokenTransferClaimed, MoveTokenTransferClaimed);
new_move_event!(TokenTransferApproved, MoveTokenTransferApproved);
new_move_event!(
    TokenTransferAlreadyApproved,
    MoveTokenTransferAlreadyApproved
);
new_move_event!(TokenTransferAlreadyClaimed, MoveTokenTransferAlreadyClaimed);
new_move_event!(TokenTransferLimitExceed, MoveTokenTransferLimitExceed);

// `EmergencyOpEvent` emitted in bridge.move
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct EmergencyOpEvent {
    pub frozen: bool,
}

// Move struct CommitteeMember used in CommitteeUpdateEvent
// This matches the Move contract's CommitteeMember struct exactly
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct MoveCommitteeMemberEvent {
    pub bridge_pubkey_bytes: Vec<u8>,
    pub voting_power: u64,
    pub http_rest_url: Vec<u8>,
    pub blocklisted: bool,
}

// `CommitteeUpdateEvent` emitted in committee.move
// Note: The Move contract only emits `members` field, not `stake_participation_percentage`
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MoveCommitteeUpdateEvent {
    pub members: VecMap<Vec<u8>, MoveCommitteeMemberEvent>,
}

// `CommitteeMemberUrlUpdateEvent` emitted in committee.move
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MoveCommitteeMemberUrlUpdateEvent {
    pub member: Vec<u8>,
    pub new_url: Vec<u8>,
}

// `BlocklistValidatorEvent` emitted in committee.move
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MoveBlocklistValidatorEvent {
    pub blocklisted: bool,
    pub public_keys: Vec<Vec<u8>>,
}

// `UpdateRouteLimitEvent` emitted in limiter.move
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct UpdateRouteLimitEvent {
    pub sending_chain: u8,
    pub receiving_chain: u8,
    pub new_limit: u64,
}

// `TokenRegistrationEvent` emitted in treasury.move
// Note: type_name is Vec<u8> because Move uses vector<u8> from BCS::to_bytes(&Token::token_code<T>())
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MoveTokenRegistrationEvent {
    pub type_name: Vec<u8>,
    pub decimal: u8,
    pub native_token: bool,
}

// Sanitized version of MoveTokenRegistrationEvent
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct TokenRegistrationEvent {
    pub type_name: TypeTag,
    pub decimal: u8,
    pub native_token: bool,
}

impl TryFrom<MoveTokenRegistrationEvent> for TokenRegistrationEvent {
    type Error = BridgeError;

    fn try_from(event: MoveTokenRegistrationEvent) -> BridgeResult<Self> {
        // type_name is BCS-encoded TokenCode, parse it to TypeTag
        let type_name = parse_token_code_bytes_to_type_tag(&event.type_name).map_err(|e| {
            BridgeError::InternalError(format!(
                "Failed to parse TypeTag from token code bytes: {e}, bytes: {:?}",
                event.type_name
            ))
        })?;

        Ok(Self {
            type_name,
            decimal: event.decimal,
            native_token: event.native_token,
        })
    }
}

// `NewTokenEvent` emitted in treasury.move
// Note: type_name is Vec<u8> because Move uses vector<u8> from BCS::to_bytes(&Token::token_code<T>())
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MoveNewTokenEvent {
    pub token_id: u8,
    pub type_name: Vec<u8>,
    pub native_token: bool,
    pub decimal_multiplier: u64,
    pub notional_value: u64,
}

// Sanitized version of MoveNewTokenEvent
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct NewTokenEvent {
    pub token_id: u8,
    pub type_name: TypeTag,
    pub native_token: bool,
    pub decimal_multiplier: u64,
    pub notional_value: u64,
}

impl TryFrom<MoveNewTokenEvent> for NewTokenEvent {
    type Error = BridgeError;

    fn try_from(event: MoveNewTokenEvent) -> BridgeResult<Self> {
        // type_name is BCS-encoded TokenCode, parse it to TypeTag
        let type_name = parse_token_code_bytes_to_type_tag(&event.type_name).map_err(|e| {
            BridgeError::InternalError(format!(
                "Failed to parse TypeTag from token code bytes: {e}, bytes: {:?}",
                event.type_name
            ))
        })?;

        Ok(Self {
            token_id: event.token_id,
            type_name,
            native_token: event.native_token,
            decimal_multiplier: event.decimal_multiplier,
            notional_value: event.notional_value,
        })
    }
}

// `UpdateTokenPriceEvent` emitted in treasury.move
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct UpdateTokenPriceEvent {
    pub token_id: u8,
    pub new_price: u64,
}

// Sanitized version of MoveTokenDepositedEvent
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Hash)]
pub struct EmittedStarcoinToEthTokenBridgeV1 {
    pub nonce: u64,
    pub starcoin_bridge_chain_id: BridgeChainId,
    pub eth_chain_id: BridgeChainId,
    pub starcoin_bridge_address: StarcoinAddress,
    pub eth_address: EthAddress,
    pub token_id: u8,
    // The amount of tokens deposited with decimal points on Starcoin side
    pub amount_starcoin_bridge_adjusted: u64,
}

// Sanitized version of MoveCommitteeUpdateEvent
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct CommitteeUpdate {
    pub members: Vec<MoveCommitteeMemberEvent>,
}

impl TryFrom<MoveCommitteeUpdateEvent> for CommitteeUpdate {
    type Error = BridgeError;

    fn try_from(event: MoveCommitteeUpdateEvent) -> BridgeResult<Self> {
        let members = event
            .members
            .contents
            .into_iter()
            .map(|v| v.value)
            .collect();
        Ok(Self { members })
    }
}

// Sanitized version of MoveBlocklistValidatorEvent
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct BlocklistValidatorEvent {
    pub blocklisted: bool,
    pub public_keys: Vec<BridgeAuthorityPublicKey>,
}

impl TryFrom<MoveBlocklistValidatorEvent> for BlocklistValidatorEvent {
    type Error = BridgeError;

    fn try_from(event: MoveBlocklistValidatorEvent) -> BridgeResult<Self> {
        let public_keys = event.public_keys.into_iter().map(|bytes|
            BridgeAuthorityPublicKey::from_bytes(&bytes).map_err(|e|
                BridgeError::Generic(format!("Failed to convert MoveBlocklistValidatorEvent to BlocklistValidatorEvent. Failed to convert public key to BridgeAuthorityPublicKey: {:?}", e))
            )
        ).collect::<BridgeResult<Vec<_>>>()?;
        Ok(Self {
            blocklisted: event.blocklisted,
            public_keys,
        })
    }
}

// Sanitized version of MoveCommitteeMemberUrlUpdateEvent
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct CommitteeMemberUrlUpdateEvent {
    pub member: BridgeAuthorityPublicKey,
    pub new_url: String,
}

impl TryFrom<MoveCommitteeMemberUrlUpdateEvent> for CommitteeMemberUrlUpdateEvent {
    type Error = BridgeError;

    fn try_from(event: MoveCommitteeMemberUrlUpdateEvent) -> BridgeResult<Self> {
        let member = BridgeAuthorityPublicKey::from_bytes(&event.member).map_err(|e|
            BridgeError::Generic(format!("Failed to convert MoveBlocklistValidatorEvent to BlocklistValidatorEvent. Failed to convert public key to BridgeAuthorityPublicKey: {:?}", e))
        )?;
        let new_url = String::from_utf8(event.new_url).map_err(|e|
            BridgeError::Generic(format!("Failed to convert MoveBlocklistValidatorEvent to BlocklistValidatorEvent. Failed to convert new_url to String: {:?}", e))
        )?;
        Ok(Self { member, new_url })
    }
}

impl TryFrom<MoveTokenDepositedEvent> for EmittedStarcoinToEthTokenBridgeV1 {
    type Error = BridgeError;

    fn try_from(event: MoveTokenDepositedEvent) -> BridgeResult<Self> {
        if event.amount_starcoin_bridge_adjusted == 0 {
            return Err(BridgeError::ZeroValueBridgeTransfer(format!(
                "Failed to convert MoveTokenDepositedEvent to EmittedStarcoinToEthTokenBridgeV1. Manual intervention is required. 0 value transfer should not be allowed in Move: {:?}",
                event,
            )));
        }

        let token_id = event.token_type;
        let starcoin_bridge_chain_id = BridgeChainId::try_from(event.source_chain).map_err(|_| {
            BridgeError::Generic(format!(
                "Failed to convert MoveTokenDepositedEvent to EmittedStarcoinToEthTokenBridgeV1. Failed to convert source chain {} to BridgeChainId",
                event.token_type,
            ))
        })?;
        let eth_chain_id = BridgeChainId::try_from(event.target_chain).map_err(|_| {
            BridgeError::Generic(format!(
                "Failed to convert MoveTokenDepositedEvent to EmittedStarcoinToEthTokenBridgeV1. Failed to convert target chain {} to BridgeChainId",
                event.token_type,
            ))
        })?;
        if !starcoin_bridge_chain_id.is_starcoin_bridge_chain() {
            return Err(BridgeError::Generic(format!(
                "Failed to convert MoveTokenDepositedEvent to EmittedStarcoinToEthTokenBridgeV1. Invalid source chain {}",
                event.source_chain
            )));
        }
        if eth_chain_id.is_starcoin_bridge_chain() {
            return Err(BridgeError::Generic(format!(
                "Failed to convert MoveTokenDepositedEvent to EmittedStarcoinToEthTokenBridgeV1. Invalid target chain {}",
                event.target_chain
            )));
        }

        let starcoin_bridge_address = StarcoinAddress::from_bytes(event.sender_address)
            .map_err(|e| BridgeError::Generic(format!("Failed to convert MoveTokenDepositedEvent to EmittedStarcoinToEthTokenBridgeV1. Failed to convert sender_address to StarcoinAddress: {:?}", e)))?;
        let eth_address = EthAddress::from_str(&Hex::encode(&event.target_address))?;

        Ok(Self {
            nonce: event.seq_num,
            starcoin_bridge_chain_id,
            eth_chain_id,
            starcoin_bridge_address,
            eth_address,
            token_id,
            amount_starcoin_bridge_adjusted: event.amount_starcoin_bridge_adjusted,
        })
    }
}

crate::declare_events!(
    StarcoinToEthTokenBridgeV1(EmittedStarcoinToEthTokenBridgeV1) => ("bridge::TokenDepositedEvent", MoveTokenDepositedEvent),
    TokenTransferApproved(TokenTransferApproved) => ("bridge::TokenTransferApproved", MoveTokenTransferApproved),
    TokenTransferClaimed(TokenTransferClaimed) => ("bridge::TokenTransferClaimed", MoveTokenTransferClaimed),
    TokenTransferAlreadyApproved(TokenTransferAlreadyApproved) => ("bridge::TokenTransferAlreadyApproved", MoveTokenTransferAlreadyApproved),
    TokenTransferAlreadyClaimed(TokenTransferAlreadyClaimed) => ("bridge::TokenTransferAlreadyClaimed", MoveTokenTransferAlreadyClaimed),
    TokenTransferLimitExceed(TokenTransferLimitExceed) => ("bridge::TokenTransferLimitExceed", MoveTokenTransferLimitExceed),
    EmergencyOpEvent(EmergencyOpEvent) => ("bridge::EmergencyOpEvent", EmergencyOpEvent),
    // No need to define a sanitized event struct for MoveTypeCommitteeMemberRegistration
    // because the info provided by validators could be invalid
    CommitteeMemberRegistration(MoveTypeCommitteeMemberRegistration) => ("committee::CommitteeMemberRegistration", MoveTypeCommitteeMemberRegistration),
    CommitteeUpdateEvent(CommitteeUpdate) => ("committee::CommitteeUpdateEvent", MoveCommitteeUpdateEvent),
    CommitteeMemberUrlUpdateEvent(CommitteeMemberUrlUpdateEvent) => ("committee::CommitteeMemberUrlUpdateEvent", MoveCommitteeMemberUrlUpdateEvent),
    BlocklistValidatorEvent(BlocklistValidatorEvent) => ("committee::BlocklistValidatorEvent", MoveBlocklistValidatorEvent),
    TokenRegistrationEvent(TokenRegistrationEvent) => ("treasury::TokenRegistrationEvent", MoveTokenRegistrationEvent),
    NewTokenEvent(NewTokenEvent) => ("treasury::NewTokenEvent", MoveNewTokenEvent),
    UpdateTokenPriceEvent(UpdateTokenPriceEvent) => ("treasury::UpdateTokenPriceEvent", UpdateTokenPriceEvent),
    UpdateRouteLimitEvent(UpdateRouteLimitEvent) => ("limiter::UpdateRouteLimitEvent", UpdateRouteLimitEvent),

    // Add new event types here. Format:
    // EnumVariantName(Struct) => ("{module}::{event_struct}", CorrespondingMoveStruct)
);

#[macro_export]
macro_rules! declare_events {
    ($($variant:ident($type:path) => ($event_tag:expr, $event_struct:path)),* $(,)?) => {

        #[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
        pub enum StarcoinBridgeEvent {
            $($variant($type),)*
        }

        $(pub static $variant: OnceCell<StructTag> = OnceCell::new();)*

        pub(crate) fn init_all_struct_tags() {
            $($variant.get_or_init(|| {
                // Extract last 16 bytes for Starcoin address (first 16 bytes are padding)
                let starcoin_addr = &BRIDGE_PACKAGE_ID[16..32];
                let addr_hex = hex::encode(starcoin_addr);
                StructTag::from_str(&format!("0x{}::{}", addr_hex, $event_tag)).unwrap()
            });)*
        }

        /// Helper to extract module::name from event tag like "bridge::TokenDepositedEvent"
        fn matches_event_type(event: &StarcoinEvent, event_tag: &str) -> bool {
            // event_tag is like "bridge::TokenDepositedEvent"
            // event.type_ is a StructTag with module and name fields
            let parts: Vec<&str> = event_tag.split("::").collect();
            if parts.len() != 2 {
                return false;
            }
            let expected_module = parts[0];
            let expected_name = parts[1];

            // Compare module and name (case-insensitive for module to handle Bridge vs bridge)
            event.type_.module.as_str().eq_ignore_ascii_case(expected_module)
                && event.type_.name.as_str() == expected_name
        }

        // Try to convert a StarcoinEvent into StarcoinBridgeEvent
        impl StarcoinBridgeEvent {
            pub fn try_from_starcoin_bridge_event(event: &StarcoinEvent) -> BridgeResult<Option<StarcoinBridgeEvent>> {
                // Match by module::event_name instead of full StructTag to support dynamic bridge addresses
                $(
                    if matches_event_type(event, $event_tag) {
                        let event_struct: $event_struct = bcs::from_bytes(&event.bcs).map_err(|e| BridgeError::InternalError(format!("Failed to deserialize event to {}: {:?}", stringify!($event_struct), e)))?;
                        return Ok(Some(StarcoinBridgeEvent::$variant(event_struct.try_into()?)));
                    }
                )*
                Ok(None)
            }
        }
    };
}

impl StarcoinBridgeEvent {
    pub fn try_into_bridge_action(
        self,
        starcoin_bridge_tx_digest: TransactionDigest,
        starcoin_bridge_tx_event_index: u16,
    ) -> Option<BridgeAction> {
        match self {
            StarcoinBridgeEvent::StarcoinToEthTokenBridgeV1(event) => Some(
                BridgeAction::StarcoinToEthBridgeAction(StarcoinToEthBridgeAction {
                    starcoin_bridge_tx_digest,
                    starcoin_bridge_tx_event_index,
                    starcoin_bridge_event: event.clone(),
                }),
            ),
            StarcoinBridgeEvent::TokenTransferApproved(_) => None,
            StarcoinBridgeEvent::TokenTransferClaimed(_) => None,
            StarcoinBridgeEvent::TokenTransferAlreadyApproved(_) => None,
            StarcoinBridgeEvent::TokenTransferAlreadyClaimed(_) => None,
            StarcoinBridgeEvent::TokenTransferLimitExceed(_) => None,
            StarcoinBridgeEvent::EmergencyOpEvent(_) => None,
            StarcoinBridgeEvent::CommitteeMemberRegistration(_) => None,
            StarcoinBridgeEvent::CommitteeUpdateEvent(_) => None,
            StarcoinBridgeEvent::CommitteeMemberUrlUpdateEvent(_) => None,
            StarcoinBridgeEvent::BlocklistValidatorEvent(_) => None,
            StarcoinBridgeEvent::TokenRegistrationEvent(_) => None,
            StarcoinBridgeEvent::NewTokenEvent(_) => None,
            StarcoinBridgeEvent::UpdateTokenPriceEvent(_) => None,
            StarcoinBridgeEvent::UpdateRouteLimitEvent(_) => None,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::crypto::BridgeAuthorityKeyPair;
    use crate::types::BridgeAction;
    use crate::types::StarcoinToEthBridgeAction;
    use ethers::types::Address as EthAddress;
    use rand::RngCore;
    use starcoin_bridge_json_rpc_types::{EventID, StarcoinEvent};
    use starcoin_bridge_types::base_types::StarcoinAddress;
    use starcoin_bridge_types::bridge::BridgeChainId;
    use starcoin_bridge_types::bridge::TOKEN_ID_STARCOIN;
    use starcoin_bridge_types::crypto::get_key_pair;

    /// Generate a random 32-byte digest
    fn random_digest() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }

    // TODO: Re-enable when BridgeTestClusterBuilder is implemented with Starcoin test infrastructure
    // #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    // async fn test_bridge_events_when_init() {
    //     telemetry_subscribers::init_for_testing();
    //     init_all_struct_tags();
    //     let mut bridge_test_cluster = BridgeTestClusterBuilder::new()
    //         .with_eth_env(false)
    //         .with_bridge_cluster(false)
    //         .with_num_validators(2)
    //         .build()
    //         .await;
    //
    //     let events = bridge_test_cluster
    //         .new_bridge_events(
    //             HashSet::from_iter([
    //                 CommitteeMemberRegistration.get().unwrap().clone(),
    //                 CommitteeUpdateEvent.get().unwrap().clone(),
    //                 TokenRegistrationEvent.get().unwrap().clone(),
    //                 NewTokenEvent.get().unwrap().clone(),
    //             ]),
    //             false,
    //         )
    //         .await;
    //     let mut mask = 0u8;
    //     for event in events.iter() {
    //         match StarcoinBridgeEvent::try_from_starcoin_bridge_event(event).unwrap().unwrap() {
    //             StarcoinBridgeEvent::CommitteeMemberRegistration(_event) => mask |= 0x1,
    //             StarcoinBridgeEvent::CommitteeUpdateEvent(_event) => mask |= 0x2,
    //             StarcoinBridgeEvent::TokenRegistrationEvent(_event) => mask |= 0x4,
    //             StarcoinBridgeEvent::NewTokenEvent(_event) => mask |= 0x8,
    //             _ => panic!("Got unexpected event: {:?}", event),
    //         }
    //     }
    //     // assert all the above events are emitted
    //     assert_eq!(mask, 0xF);
    // }

    #[test]
    fn test_conversion_for_committee_member_url_update_event() {
        let (_, kp): (_, BridgeAuthorityKeyPair) = get_key_pair();
        let new_url = "https://example.com:443";
        let event: CommitteeMemberUrlUpdateEvent = MoveCommitteeMemberUrlUpdateEvent {
            member: kp.public.as_bytes().to_vec(),
            new_url: new_url.as_bytes().to_vec(),
        }
        .try_into()
        .unwrap();
        assert_eq!(event.member, kp.public);
        assert_eq!(event.new_url, new_url);

        CommitteeMemberUrlUpdateEvent::try_from(MoveCommitteeMemberUrlUpdateEvent {
            member: vec![1, 2, 3],
            new_url: new_url.as_bytes().to_vec(),
        })
        .unwrap_err();

        CommitteeMemberUrlUpdateEvent::try_from(MoveCommitteeMemberUrlUpdateEvent {
            member: kp.public.as_bytes().to_vec(),
            new_url: [240, 130, 130, 172].into(),
        })
        .unwrap_err();
    }

    #[test]
    fn test_0_starcoin_bridge_amount_conversion_for_starcoin_bridge_event() {
        // Create a random starcoin address for testing
        let mut addr_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut addr_bytes);
        let starcoin_addr = StarcoinAddress::new(addr_bytes);

        let emitted_event = MoveTokenDepositedEvent {
            seq_num: 1,
            source_chain: BridgeChainId::StarcoinTestnet as u8,
            sender_address: starcoin_addr.to_vec(),
            target_chain: BridgeChainId::EthSepolia as u8,
            target_address: EthAddress::random().as_bytes().to_vec(),
            token_type: TOKEN_ID_STARCOIN,
            amount_starcoin_bridge_adjusted: 0,
        };
        match EmittedStarcoinToEthTokenBridgeV1::try_from(emitted_event).unwrap_err() {
            BridgeError::ZeroValueBridgeTransfer(_) => (),
            other => panic!("Expected ZeroValueBridgeTransfer error, got: {:?}", other),
        }
    }
}
