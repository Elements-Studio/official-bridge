// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::abi::EthToStarcoinTokenBridgeV1;
use crate::crypto::BridgeAuthorityPublicKeyBytes;
use crate::crypto::{
    BridgeAuthorityPublicKey, BridgeAuthorityRecoverableSignature, BridgeAuthoritySignInfo,
};
use crate::encoding::BridgeMessageEncoding;
use crate::error::{BridgeError, BridgeResult};
use crate::events::EmittedStarcoinToEthTokenBridgeV1;
use enum_dispatch::enum_dispatch;
use ethers::types::Address as EthAddress;
use ethers::types::Log;
use ethers::types::H256;
pub use ethers::types::H256 as EthTransactionHash;
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::hash::{Digest, HashFunction, Keccak256};
use fastcrypto::traits::ToFromBytes;
use num_enum::TryFromPrimitive;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use shared_crypto::intent::IntentScope;
use starcoin_bridge_types::base_types::StarcoinAddress;
use starcoin_bridge_types::base_types::TransactionDigest;
use starcoin_bridge_types::bridge::{
    BridgeChainId, MoveTypeTokenTransferPayload, APPROVAL_THRESHOLD_ADD_TOKENS_ON_EVM,
    APPROVAL_THRESHOLD_ADD_TOKENS_ON_STARCOIN, BRIDGE_COMMITTEE_MAXIMAL_VOTING_POWER,
    BRIDGE_COMMITTEE_MINIMAL_VOTING_POWER,
};
use starcoin_bridge_types::bridge::{
    MoveTypeParsedTokenTransferMessage, APPROVAL_THRESHOLD_ASSET_PRICE_UPDATE,
    APPROVAL_THRESHOLD_COMMITTEE_BLOCKLIST, APPROVAL_THRESHOLD_EMERGENCY_PAUSE,
    APPROVAL_THRESHOLD_EMERGENCY_UNPAUSE, APPROVAL_THRESHOLD_EVM_CONTRACT_UPGRADE,
    APPROVAL_THRESHOLD_LIMIT_UPDATE, APPROVAL_THRESHOLD_TOKEN_TRANSFER,
    APPROVAL_THRESHOLD_UPDATE_COMMITTEE_MEMBER,
};
use starcoin_bridge_types::committee::CommitteeTrait;
use starcoin_bridge_types::committee::StakeUnit;
use starcoin_bridge_types::message_envelope::{Envelope, Message, VerifiedEnvelope};
use starcoin_bridge_types::TypeTag;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use strum_macros::Display;

pub const BRIDGE_AUTHORITY_TOTAL_VOTING_POWER: u64 = 10000;

pub const USD_MULTIPLIER: u64 = 10000; // decimal places = 4

pub type IsBridgePaused = bool;
pub const BRIDGE_PAUSED: bool = true;
pub const BRIDGE_UNPAUSED: bool = false;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct BridgeAuthority {
    pub starcoin_bridge_address: StarcoinAddress,
    pub pubkey: BridgeAuthorityPublicKey,
    pub voting_power: u64,
    pub base_url: String,
    pub is_blocklisted: bool,
}

impl BridgeAuthority {
    pub fn pubkey_bytes(&self) -> BridgeAuthorityPublicKeyBytes {
        BridgeAuthorityPublicKeyBytes::from(&self.pubkey)
    }
}

#[derive(Debug, Clone)]
pub struct BridgeCommittee {
    /// Bridge committee version number (incremented when members change)
    pub committee_version: u64,
    members: BTreeMap<BridgeAuthorityPublicKeyBytes, BridgeAuthority>,
    total_blocklisted_stake: StakeUnit,
}

impl BridgeCommittee {
    pub fn new(members: Vec<BridgeAuthority>) -> BridgeResult<Self> {
        let mut members_map = BTreeMap::new();
        let mut total_blocklisted_stake = 0;
        let mut total_stake = 0;
        for member in members {
            let public_key = BridgeAuthorityPublicKeyBytes::from(&member.pubkey);
            if members_map.contains_key(&public_key) {
                return Err(BridgeError::InvalidBridgeCommittee(
                    "Duplicate BridgeAuthority Public key".into(),
                ));
            }
            // TODO: should we disallow identical network addresses?
            if member.is_blocklisted {
                total_blocklisted_stake += member.voting_power;
            }
            total_stake += member.voting_power;
            members_map.insert(public_key, member);
        }
        if total_stake < BRIDGE_COMMITTEE_MINIMAL_VOTING_POWER {
            return Err(BridgeError::InvalidBridgeCommittee(format!(
                "Total voting power is below minimal {BRIDGE_COMMITTEE_MINIMAL_VOTING_POWER}"
            )));
        }
        if total_stake > BRIDGE_COMMITTEE_MAXIMAL_VOTING_POWER {
            return Err(BridgeError::InvalidBridgeCommittee(format!(
                "Total voting power is above maximal {BRIDGE_COMMITTEE_MAXIMAL_VOTING_POWER}"
            )));
        }
        Ok(Self {
            committee_version: 0, // TODO: Pass committee_version parameter
            members: members_map,
            total_blocklisted_stake,
        })
    }

    pub fn is_active_member(&self, member: &BridgeAuthorityPublicKeyBytes) -> bool {
        self.members.contains_key(member) && !self.members.get(member).unwrap().is_blocklisted
    }

    pub fn members(&self) -> &BTreeMap<BridgeAuthorityPublicKeyBytes, BridgeAuthority> {
        &self.members
    }

    pub fn member(&self, member: &BridgeAuthorityPublicKeyBytes) -> Option<&BridgeAuthority> {
        self.members.get(member)
    }

    pub fn total_blocklisted_stake(&self) -> StakeUnit {
        self.total_blocklisted_stake
    }

    // Testing helper: shuffle by stake with optional RNG seed and preferences
    #[cfg(test)]
    pub fn shuffle_by_stake(
        &self,
        exclude: Option<&BTreeSet<BridgeAuthorityPublicKeyBytes>>,
    ) -> Vec<BridgeAuthorityPublicKeyBytes> {
        let mut candidates: Vec<_> = self
            .members
            .iter()
            .filter_map(|(name, a)| {
                // Remove blocklisted members
                if a.is_blocklisted {
                    return None;
                }
                // Exclude specified members
                if let Some(exclude_set) = exclude {
                    if exclude_set.contains(name) {
                        return None;
                    }
                }
                Some(name.clone())
            })
            .collect();

        candidates.sort_by_key(|name| {
            std::cmp::Reverse(self.members.get(name).map(|a| a.voting_power).unwrap_or(0))
        });

        candidates
    }
}

impl core::fmt::Display for BridgeCommittee {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        for m in self.members.values() {
            writeln!(
                f,
                "pubkey: {:?}, url: {:?}, stake: {:?}, blocklisted: {}, eth address: {:x}",
                Hex::encode(m.pubkey_bytes().as_bytes()),
                m.base_url,
                m.voting_power,
                m.is_blocklisted,
                m.pubkey_bytes().to_eth_address(),
            )?;
        }
        Ok(())
    }
}

impl CommitteeTrait for BridgeCommittee {
    fn version(&self) -> u64 {
        self.committee_version
    }

    fn num_members(&self) -> usize {
        self.members.len()
    }

    // Note: blocklisted members are always excluded.
    fn shuffle_by_stake_with_rng<R: rand::Rng>(
        &self,
        preferences: &[[u8; 32]],
        rng: &mut R,
    ) -> Vec<[u8; 32]> {
        // Convert preferences to BridgeAuthorityPublicKeyBytes set
        let pref_set: Option<BTreeSet<BridgeAuthorityPublicKeyBytes>> = if preferences.is_empty() {
            None
        } else {
            Some(
                preferences
                    .iter()
                    .map(|addr| BridgeAuthorityPublicKeyBytes::from(*addr))
                    .collect(),
            )
        };

        let mut candidates = self
            .members
            .iter()
            .filter_map(|(name, a)| {
                // Remove blocklisted members
                if a.is_blocklisted {
                    return None;
                }
                // exclude non-allowlisted members
                if let Some(ref pref_set) = pref_set {
                    match pref_set.contains(name) {
                        true => Some((name.clone(), a.voting_power)),
                        false => None,
                    }
                } else {
                    Some((name.clone(), a.voting_power))
                }
            })
            .collect::<Vec<_>>();

        if pref_set.is_some() {
            candidates.sort_by(|(_, a), (_, b)| b.cmp(a));
            candidates
                .iter()
                .map(|(name, _)| {
                    let bytes = name.as_bytes();
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes[..bytes.len().min(32)]);
                    arr
                })
                .collect()
        } else {
            // Simple random shuffle when no preferences
            candidates.shuffle(rng);
            candidates
                .iter()
                .map(|(name, _)| {
                    let bytes = name.as_bytes();
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes[..bytes.len().min(32)]);
                    arr
                })
                .collect()
        }
    }

    fn weight(&self, author: &[u8; 32]) -> StakeUnit {
        let author_key = BridgeAuthorityPublicKeyBytes::from(*author);
        self.members
            .get(&author_key)
            .map(|a| a.voting_power)
            .unwrap_or(0)
    }
}

// Implement starcoin-bridge-authority-aggregation CommitteeTrait for BridgeCommittee
impl starcoin_bridge_authority_aggregation::CommitteeTrait for BridgeCommittee {
    type AuthorityKey = BridgeAuthorityPublicKeyBytes;

    fn weight(&self, author: &BridgeAuthorityPublicKeyBytes) -> u64 {
        self.members
            .get(author)
            .map(|a| a.voting_power)
            .unwrap_or(0)
    }
}

#[derive(Serialize, Copy, Clone, PartialEq, Eq, TryFromPrimitive, Hash, Display)]
#[repr(u8)]
pub enum BridgeActionType {
    TokenTransfer = 0,
    UpdateCommitteeBlocklist = 1,
    EmergencyButton = 2,
    LimitUpdate = 3,
    AssetPriceUpdate = 4,
    EvmContractUpgrade = 5,
    AddTokensOnstarcoin = 6,
    AddTokensOnEvm = 7,
    UpdateCommitteeMember = 8,
}

#[derive(Clone, PartialEq, Eq)]
pub struct BridgeActionKey {
    pub action_type: BridgeActionType,
    pub chain_id: BridgeChainId,
    pub seq_num: u64,
}

impl Debug for BridgeActionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BridgeActionKey({},{},{})",
            self.action_type as u8, self.chain_id as u8, self.seq_num
        )
    }
}

#[derive(Debug, PartialEq, Eq, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum BridgeActionStatus {
    Pending = 0,
    Approved = 1,
    Claimed = 2,
    NotFound = 3,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct StarcoinToEthBridgeAction {
    // Digest of the transaction where the event was emitted
    pub starcoin_bridge_tx_digest: TransactionDigest,
    // The index of the event in the transaction
    pub starcoin_bridge_tx_event_index: u16,
    pub starcoin_bridge_event: EmittedStarcoinToEthTokenBridgeV1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EthToStarcoinBridgeAction {
    // Digest of the transaction where the event was emitted
    pub eth_tx_hash: EthTransactionHash,
    // The index of the event in the transaction
    pub eth_event_index: u16,
    pub eth_bridge_event: EthToStarcoinTokenBridgeV1,
}

#[derive(
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Clone,
    Copy,
    TryFromPrimitive,
    Hash,
    clap::ValueEnum,
)]
#[repr(u8)]
pub enum BlocklistType {
    Blocklist = 0,
    Unblocklist = 1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BlocklistCommitteeAction {
    pub nonce: u64,
    pub chain_id: BridgeChainId,
    pub blocklist_type: BlocklistType,
    pub members_to_update: Vec<BridgeAuthorityPublicKeyBytes>,
}

#[derive(
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Clone,
    Copy,
    TryFromPrimitive,
    Hash,
    clap::ValueEnum,
)]
#[repr(u8)]
pub enum EmergencyActionType {
    Pause = 0,
    Unpause = 1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EmergencyAction {
    pub nonce: u64,
    pub chain_id: BridgeChainId,
    pub action_type: EmergencyActionType,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct LimitUpdateAction {
    pub nonce: u64,
    // The chain id that will receive this signed action. It's also the destination chain id
    // for the limit update. For example, if chain_id is EthMainnet and sending_chain_id is StarcoinMainnet,
    // it means we want to update the limit for the StarcoinMainnet to EthMainnet route.
    pub chain_id: BridgeChainId,
    // The sending chain id for the limit update.
    pub sending_chain_id: BridgeChainId,
    // 4 decimal places, namely 1 USD = 10000
    pub new_usd_limit: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AssetPriceUpdateAction {
    pub nonce: u64,
    pub chain_id: BridgeChainId,
    pub token_id: u8,
    pub new_usd_price: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EvmContractUpgradeAction {
    pub nonce: u64,
    pub chain_id: BridgeChainId,
    pub proxy_address: EthAddress,
    pub new_impl_address: EthAddress,
    pub call_data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AddTokensOnStarcoinAction {
    pub nonce: u64,
    pub chain_id: BridgeChainId,
    pub native: bool,
    pub token_ids: Vec<u8>,
    pub token_type_names: Vec<TypeTag>,
    pub token_prices: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AddTokensOnEvmAction {
    pub nonce: u64,
    pub chain_id: BridgeChainId,
    pub native: bool,
    pub token_ids: Vec<u8>,
    pub token_addresses: Vec<EthAddress>,
    pub token_starcoin_bridge_decimals: Vec<u8>,
    pub token_prices: Vec<u64>,
}

/// Type of committee member update action
#[derive(
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Clone,
    Copy,
    TryFromPrimitive,
    Hash,
    clap::ValueEnum,
)]
#[repr(u8)]
pub enum UpdateCommitteeMemberType {
    Add = 0,
    Remove = 1,
}

/// Action to add or remove a committee member
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct UpdateCommitteeMemberAction {
    pub nonce: u64,
    pub chain_id: BridgeChainId,
    pub update_type: UpdateCommitteeMemberType,
    /// The Starcoin address of the member (first 16 bytes of pubkey)
    pub member_address: StarcoinAddress,
    pub bridge_pubkey_bytes: Vec<u8>,
    pub voting_power: u64,
    pub http_rest_url: String,
}

/// Action to add a committee member on EVM chain.
/// This uses message type 8 (same as UpdateCommitteeMember) but with EVM-specific payload format.
/// Payload format: address (20 bytes) + stake (uint16, 2 bytes) = 22 bytes total.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EvmAddMemberAction {
    pub nonce: u64,
    pub chain_id: BridgeChainId,
    /// The EVM address of the new committee member
    pub member_address: EthAddress,
    /// The stake amount for the member (uint16)
    pub stake: u16,
}

// The type of actions Bridge Committee verify and sign off to execution.
// Its relationship with BridgeEvent is similar to the relationship between
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[enum_dispatch(BridgeMessageEncoding)]
pub enum BridgeAction {
    // Starcoin to Eth bridge action
    StarcoinToEthBridgeAction(StarcoinToEthBridgeAction),
    // Eth to starcoin bridge action
    EthToStarcoinBridgeAction(EthToStarcoinBridgeAction),
    BlocklistCommitteeAction(BlocklistCommitteeAction),
    EmergencyAction(EmergencyAction),
    LimitUpdateAction(LimitUpdateAction),
    AssetPriceUpdateAction(AssetPriceUpdateAction),
    EvmContractUpgradeAction(EvmContractUpgradeAction),
    AddTokensOnStarcoinAction(AddTokensOnStarcoinAction),
    AddTokensOnEvmAction(AddTokensOnEvmAction),
    UpdateCommitteeMemberAction(UpdateCommitteeMemberAction),
    EvmAddMemberAction(EvmAddMemberAction),
}

impl BridgeAction {
    // Digest of BridgeAction (with Keccak256 hasher)
    pub fn digest(&self) -> BridgeActionDigest {
        let mut hasher = Keccak256::default();
        hasher.update(
            self.to_bytes()
                .expect("Message encoding should not fail for valid actions"),
        );
        BridgeActionDigest::new(hasher.finalize().into())
    }

    pub fn key(&self) -> BridgeActionKey {
        BridgeActionKey {
            action_type: self.action_type(),
            chain_id: self.chain_id(),
            seq_num: self.seq_number(),
        }
    }

    pub fn chain_id(&self) -> BridgeChainId {
        match self {
            BridgeAction::StarcoinToEthBridgeAction(a) => {
                a.starcoin_bridge_event.starcoin_bridge_chain_id
            }
            BridgeAction::EthToStarcoinBridgeAction(a) => a.eth_bridge_event.eth_chain_id,
            BridgeAction::BlocklistCommitteeAction(a) => a.chain_id,
            BridgeAction::EmergencyAction(a) => a.chain_id,
            BridgeAction::LimitUpdateAction(a) => a.chain_id,
            BridgeAction::AssetPriceUpdateAction(a) => a.chain_id,
            BridgeAction::EvmContractUpgradeAction(a) => a.chain_id,
            BridgeAction::AddTokensOnStarcoinAction(a) => a.chain_id,
            BridgeAction::AddTokensOnEvmAction(a) => a.chain_id,
            BridgeAction::UpdateCommitteeMemberAction(a) => a.chain_id,
            BridgeAction::EvmAddMemberAction(a) => a.chain_id,
        }
    }

    /// Returns the token_id for token transfer actions, None for governance actions
    pub fn token_id(&self) -> Option<u8> {
        match self {
            BridgeAction::StarcoinToEthBridgeAction(a) => Some(a.starcoin_bridge_event.token_id),
            BridgeAction::EthToStarcoinBridgeAction(a) => Some(a.eth_bridge_event.token_id),
            _ => None,
        }
    }

    pub fn is_governace_action(&self) -> bool {
        match self.action_type() {
            BridgeActionType::TokenTransfer => false,
            BridgeActionType::UpdateCommitteeBlocklist => true,
            BridgeActionType::EmergencyButton => true,
            BridgeActionType::LimitUpdate => true,
            BridgeActionType::AssetPriceUpdate => true,
            BridgeActionType::EvmContractUpgrade => true,
            BridgeActionType::AddTokensOnstarcoin => true,
            BridgeActionType::AddTokensOnEvm => true,
            BridgeActionType::UpdateCommitteeMember => true,
        }
    }

    // Also called `message_type`
    pub fn action_type(&self) -> BridgeActionType {
        match self {
            BridgeAction::StarcoinToEthBridgeAction(_) => BridgeActionType::TokenTransfer,
            BridgeAction::EthToStarcoinBridgeAction(_) => BridgeActionType::TokenTransfer,
            BridgeAction::BlocklistCommitteeAction(_) => BridgeActionType::UpdateCommitteeBlocklist,
            BridgeAction::EmergencyAction(_) => BridgeActionType::EmergencyButton,
            BridgeAction::LimitUpdateAction(_) => BridgeActionType::LimitUpdate,
            BridgeAction::AssetPriceUpdateAction(_) => BridgeActionType::AssetPriceUpdate,
            BridgeAction::EvmContractUpgradeAction(_) => BridgeActionType::EvmContractUpgrade,
            BridgeAction::AddTokensOnStarcoinAction(_) => BridgeActionType::AddTokensOnstarcoin,
            BridgeAction::AddTokensOnEvmAction(_) => BridgeActionType::AddTokensOnEvm,
            BridgeAction::UpdateCommitteeMemberAction(_) => BridgeActionType::UpdateCommitteeMember,
            // EvmAddMemberAction also uses message type 8, same as UpdateCommitteeMember
            BridgeAction::EvmAddMemberAction(_) => BridgeActionType::UpdateCommitteeMember,
        }
    }

    // Also called `nonce`
    pub fn seq_number(&self) -> u64 {
        match self {
            BridgeAction::StarcoinToEthBridgeAction(a) => a.starcoin_bridge_event.nonce,
            BridgeAction::EthToStarcoinBridgeAction(a) => a.eth_bridge_event.nonce,
            BridgeAction::BlocklistCommitteeAction(a) => a.nonce,
            BridgeAction::EmergencyAction(a) => a.nonce,
            BridgeAction::LimitUpdateAction(a) => a.nonce,
            BridgeAction::AssetPriceUpdateAction(a) => a.nonce,
            BridgeAction::EvmContractUpgradeAction(a) => a.nonce,
            BridgeAction::AddTokensOnStarcoinAction(a) => a.nonce,
            BridgeAction::AddTokensOnEvmAction(a) => a.nonce,
            BridgeAction::UpdateCommitteeMemberAction(a) => a.nonce,
            BridgeAction::EvmAddMemberAction(a) => a.nonce,
        }
    }

    pub fn approval_threshold(&self) -> u64 {
        match self {
            BridgeAction::StarcoinToEthBridgeAction(_) => APPROVAL_THRESHOLD_TOKEN_TRANSFER,
            BridgeAction::EthToStarcoinBridgeAction(_) => APPROVAL_THRESHOLD_TOKEN_TRANSFER,
            BridgeAction::BlocklistCommitteeAction(_) => APPROVAL_THRESHOLD_COMMITTEE_BLOCKLIST,
            BridgeAction::EmergencyAction(a) => match a.action_type {
                EmergencyActionType::Pause => APPROVAL_THRESHOLD_EMERGENCY_PAUSE,
                EmergencyActionType::Unpause => APPROVAL_THRESHOLD_EMERGENCY_UNPAUSE,
            },
            BridgeAction::LimitUpdateAction(_) => APPROVAL_THRESHOLD_LIMIT_UPDATE,
            BridgeAction::AssetPriceUpdateAction(_) => APPROVAL_THRESHOLD_ASSET_PRICE_UPDATE,
            BridgeAction::EvmContractUpgradeAction(_) => APPROVAL_THRESHOLD_EVM_CONTRACT_UPGRADE,
            BridgeAction::AddTokensOnStarcoinAction(_) => APPROVAL_THRESHOLD_ADD_TOKENS_ON_STARCOIN,
            BridgeAction::AddTokensOnEvmAction(_) => APPROVAL_THRESHOLD_ADD_TOKENS_ON_EVM,
            BridgeAction::UpdateCommitteeMemberAction(_) => {
                APPROVAL_THRESHOLD_UPDATE_COMMITTEE_MEMBER
            }
            // EvmAddMemberAction uses same threshold as UpdateCommitteeMember
            BridgeAction::EvmAddMemberAction(_) => APPROVAL_THRESHOLD_UPDATE_COMMITTEE_MEMBER,
        }
    }

    /// Returns the direction of a token transfer action
    /// Returns None for non-transfer actions (governance actions)
    pub fn transfer_direction(&self) -> Option<TransferDirection> {
        match self {
            BridgeAction::StarcoinToEthBridgeAction(_) => Some(TransferDirection::StarcoinToEth),
            BridgeAction::EthToStarcoinBridgeAction(_) => Some(TransferDirection::EthToStarcoin),
            // Governance actions don't have a transfer direction
            _ => None,
        }
    }

    /// Returns true if this is a Starcoin to Eth transfer
    pub fn is_starcoin_to_eth_transfer(&self) -> bool {
        matches!(self, BridgeAction::StarcoinToEthBridgeAction(_))
    }

    /// Returns true if this is an Eth to Starcoin transfer
    pub fn is_eth_to_starcoin_transfer(&self) -> bool {
        matches!(self, BridgeAction::EthToStarcoinBridgeAction(_))
    }
}

/// Direction of a token transfer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransferDirection {
    /// Transfer from Starcoin to Ethereum
    StarcoinToEth,
    /// Transfer from Ethereum to Starcoin
    EthToStarcoin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BridgeActionDigest(Digest<32>);

impl BridgeActionDigest {
    pub fn new(digest: [u8; 32]) -> Self {
        Self(Digest::new(digest))
    }
}

#[derive(Debug, Clone)]
pub struct BridgeCommitteeValiditySignInfo {
    pub signatures: BTreeMap<BridgeAuthorityPublicKeyBytes, BridgeAuthorityRecoverableSignature>,
}

pub type SignedBridgeAction = Envelope<BridgeAction, BridgeAuthoritySignInfo>;
pub type VerifiedSignedBridgeAction = VerifiedEnvelope<BridgeAction, BridgeAuthoritySignInfo>;
pub type CertifiedBridgeAction = Envelope<BridgeAction, BridgeCommitteeValiditySignInfo>;
pub type VerifiedCertifiedBridgeAction =
    VerifiedEnvelope<BridgeAction, BridgeCommitteeValiditySignInfo>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BridgeEventDigest(Digest<32>);

impl BridgeEventDigest {
    pub fn new(digest: [u8; 32]) -> Self {
        Self(Digest::new(digest))
    }
}

impl Message for BridgeAction {
    type DigestType = BridgeEventDigest;

    // this is not encoded in message today
    const SCOPE: IntentScope = IntentScope::BridgeEventUnused;

    // this is not used today
    fn digest(&self) -> Self::DigestType {
        unreachable!("BridgeEventDigest is not used today")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthLog {
    pub block_number: u64,
    pub tx_hash: H256,
    pub log_index_in_tx: u16,
    pub log: Log,
}

// The version of EthLog that does not have
// `log_index_in_tx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEthLog {
    pub block_number: u64,
    pub tx_hash: H256,
    pub log: Log,
}

pub trait EthEvent {
    fn block_number(&self) -> u64;
    fn tx_hash(&self) -> H256;
    fn log(&self) -> &Log;
}

impl EthEvent for EthLog {
    fn block_number(&self) -> u64 {
        self.block_number
    }
    fn tx_hash(&self) -> H256 {
        self.tx_hash
    }
    fn log(&self) -> &Log {
        &self.log
    }
}

impl EthEvent for RawEthLog {
    fn block_number(&self) -> u64 {
        self.block_number
    }
    fn tx_hash(&self) -> H256 {
        self.tx_hash
    }
    fn log(&self) -> &Log {
        &self.log
    }
}

// Check if the bridge route is valid
// Only mainnet can bridge to mainnet, other than that we do not care.
pub fn is_route_valid(one: BridgeChainId, other: BridgeChainId) -> bool {
    if one.is_starcoin_bridge_chain() && other.is_starcoin_bridge_chain() {
        return false;
    }
    if !one.is_starcoin_bridge_chain() && !other.is_starcoin_bridge_chain() {
        return false;
    }
    if one == BridgeChainId::EthMainnet {
        return other == BridgeChainId::StarcoinMainnet;
    }
    if one == BridgeChainId::StarcoinMainnet {
        return other == BridgeChainId::EthMainnet;
    }
    if other == BridgeChainId::EthMainnet {
        return one == BridgeChainId::StarcoinMainnet;
    }
    if other == BridgeChainId::StarcoinMainnet {
        return one == BridgeChainId::EthMainnet;
    }
    true
}

// Sanitized version of MoveTypeParsedTokenTransferMessage
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct ParsedTokenTransferMessage {
    pub message_version: u8,
    pub seq_num: u64,
    pub source_chain: BridgeChainId,
    pub payload: Vec<u8>,
    pub parsed_payload: MoveTypeTokenTransferPayload,
}

impl TryFrom<MoveTypeParsedTokenTransferMessage> for ParsedTokenTransferMessage {
    type Error = BridgeError;

    fn try_from(message: MoveTypeParsedTokenTransferMessage) -> BridgeResult<Self> {
        let source_chain = BridgeChainId::try_from(message.source_chain).map_err(|_| {
            BridgeError::Generic(format!(
                "Failed to convert MoveTypeParsedTokenTransferMessage to ParsedTokenTransferMessage. Failed to convert source chain {} to BridgeChainId",
                message.source_chain,
            ))
        })?;
        Ok(Self {
            message_version: message.message_version,
            seq_num: message.seq_num,
            source_chain,
            payload: message.payload,
            parsed_payload: message.parsed_payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::get_test_authority_and_key;
    use crate::test_utils::get_test_eth_to_starcoin_bridge_action;
    use crate::test_utils::get_test_starcoin_bridge_to_eth_bridge_action;
    use ethers::types::Address as EthAddress;
    use fastcrypto::traits::KeyPair;
    use starcoin_bridge_types::bridge::TOKEN_ID_BTC;
    use starcoin_bridge_types::crypto::get_key_pair;

    use super::*;

    #[test]
    fn test_bridge_committee_construction() -> anyhow::Result<()> {
        let (mut authority, _, _) = get_test_authority_and_key(8000, 9999);
        // This is ok
        let _ = BridgeCommittee::new(vec![authority.clone()]).unwrap();

        // This is not ok - total voting power < BRIDGE_COMMITTEE_MINIMAL_VOTING_POWER
        authority.voting_power = BRIDGE_COMMITTEE_MINIMAL_VOTING_POWER - 1;
        let _ = BridgeCommittee::new(vec![authority.clone()]).unwrap_err();

        // This is not ok - total voting power > BRIDGE_COMMITTEE_MAXIMAL_VOTING_POWER
        authority.voting_power = BRIDGE_COMMITTEE_MAXIMAL_VOTING_POWER + 1;
        let _ = BridgeCommittee::new(vec![authority.clone()]).unwrap_err();

        // This is ok
        authority.voting_power = 5000;
        let mut authority_2 = authority.clone();
        let (_, kp): (_, fastcrypto::secp256k1::Secp256k1KeyPair) = get_key_pair();
        let pubkey = kp.public().clone();
        authority_2.pubkey = pubkey.clone();
        let _ = BridgeCommittee::new(vec![authority.clone(), authority_2.clone()]).unwrap();

        // This is not ok - duplicate pub key
        authority_2.pubkey = authority.pubkey.clone();
        let _ = BridgeCommittee::new(vec![authority.clone(), authority.clone()]).unwrap_err();
        Ok(())
    }

    #[test]
    fn test_bridge_committee_total_blocklisted_stake() -> anyhow::Result<()> {
        let (mut authority1, _, _) = get_test_authority_and_key(10000, 9999);
        assert_eq!(
            BridgeCommittee::new(vec![authority1.clone()])
                .unwrap()
                .total_blocklisted_stake(),
            0
        );
        authority1.voting_power = 6000;

        let (mut authority2, _, _) = get_test_authority_and_key(4000, 9999);
        authority2.is_blocklisted = true;
        assert_eq!(
            BridgeCommittee::new(vec![authority1.clone(), authority2.clone()])
                .unwrap()
                .total_blocklisted_stake(),
            4000
        );

        authority1.voting_power = 7000;
        authority2.voting_power = 2000;
        let (mut authority3, _, _) = get_test_authority_and_key(1000, 9999);
        authority3.is_blocklisted = true;
        assert_eq!(
            BridgeCommittee::new(vec![authority1, authority2, authority3])
                .unwrap()
                .total_blocklisted_stake(),
            3000
        );

        Ok(())
    }

    // Regression test to avoid accidentally change to approval threshold
    #[test]
    fn test_bridge_action_approval_threshold_regression_test() -> anyhow::Result<()> {
        let action =
            get_test_starcoin_bridge_to_eth_bridge_action(None, None, None, None, None, None, None);
        assert_eq!(action.approval_threshold(), 3334);

        let action = get_test_eth_to_starcoin_bridge_action(None, None, None, None);
        assert_eq!(action.approval_threshold(), 3334);

        let action = BridgeAction::BlocklistCommitteeAction(BlocklistCommitteeAction {
            nonce: 94,
            chain_id: BridgeChainId::EthSepolia,
            blocklist_type: BlocklistType::Unblocklist,
            members_to_update: vec![],
        });
        assert_eq!(action.approval_threshold(), 5001);

        let action = BridgeAction::EmergencyAction(EmergencyAction {
            nonce: 56,
            chain_id: BridgeChainId::EthSepolia,
            action_type: EmergencyActionType::Pause,
        });
        assert_eq!(action.approval_threshold(), 450);

        let action = BridgeAction::EmergencyAction(EmergencyAction {
            nonce: 56,
            chain_id: BridgeChainId::EthSepolia,
            action_type: EmergencyActionType::Unpause,
        });
        assert_eq!(action.approval_threshold(), 5001);

        let action = BridgeAction::LimitUpdateAction(LimitUpdateAction {
            nonce: 15,
            chain_id: BridgeChainId::StarcoinCustom,
            sending_chain_id: BridgeChainId::EthCustom,
            new_usd_limit: 1_000_000 * USD_MULTIPLIER,
        });
        assert_eq!(action.approval_threshold(), 5001);

        let action = BridgeAction::AssetPriceUpdateAction(AssetPriceUpdateAction {
            nonce: 266,
            chain_id: BridgeChainId::StarcoinCustom,
            token_id: TOKEN_ID_BTC,
            new_usd_price: 100_000 * USD_MULTIPLIER,
        });
        assert_eq!(action.approval_threshold(), 5001);

        let action = BridgeAction::EvmContractUpgradeAction(EvmContractUpgradeAction {
            nonce: 123,
            chain_id: BridgeChainId::EthCustom,
            proxy_address: EthAddress::repeat_byte(6),
            new_impl_address: EthAddress::repeat_byte(9),
            call_data: vec![],
        });
        assert_eq!(action.approval_threshold(), 5001);
        Ok(())
    }

    #[test]
    fn test_bridge_committee_filter_blocklisted_authorities() -> anyhow::Result<()> {
        // Note: today BridgeCommittee does not shuffle authorities
        let (authority1, _, _) = get_test_authority_and_key(5000, 9999);
        let (mut authority2, _, _) = get_test_authority_and_key(3000, 9999);
        authority2.is_blocklisted = true;
        let (authority3, _, _) = get_test_authority_and_key(2000, 9999);
        let committee = BridgeCommittee::new(vec![
            authority1.clone(),
            authority2.clone(),
            authority3.clone(),
        ])
        .unwrap();

        // No explicit exclude, but authority2 is blocklisted so should be filtered out
        let result = committee.shuffle_by_stake(None);
        assert_eq!(result.len(), 2); // authority1 and authority3, but not blocklisted authority2
        assert!(result.contains(&authority1.pubkey_bytes()));
        assert!(result.contains(&authority3.pubkey_bytes()));
        assert!(!result.contains(&authority2.pubkey_bytes()));

        // Explicitly exclude authority1 and authority2 (authority2 already blocklisted)
        // So only authority3 should remain
        let result = committee.shuffle_by_stake(Some(
            &[authority1.pubkey_bytes(), authority2.pubkey_bytes()]
                .iter()
                .cloned()
                .collect(),
        ));
        assert_eq!(result.len(), 1); // only authority3 remains
        assert!(result.contains(&authority3.pubkey_bytes()));
        assert!(!result.contains(&authority1.pubkey_bytes()));
        assert!(!result.contains(&authority2.pubkey_bytes()));

        Ok(())
    }
}
