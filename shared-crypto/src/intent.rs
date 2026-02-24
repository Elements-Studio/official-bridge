// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

use eyre::eyre;
use fastcrypto::encoding::decode_bytes_hex;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::str::FromStr;

pub const INTENT_PREFIX_LENGTH: usize = 3;

#[derive(Serialize_repr, Deserialize_repr, Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum IntentVersion {
    V0 = 0,
}

impl TryFrom<u8> for IntentVersion {
    type Error = eyre::Report;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        bcs::from_bytes(&[value]).map_err(|_| eyre!("Invalid IntentVersion"))
    }
}

#[derive(Serialize_repr, Deserialize_repr, Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum AppId {
    Starcoin = 0,
    Narwhal = 1,
    Consensus = 2,
}

impl TryFrom<u8> for AppId {
    type Error = eyre::Report;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        bcs::from_bytes(&[value]).map_err(|_| eyre!("Invalid AppId"))
    }
}

impl Default for AppId {
    fn default() -> Self {
        Self::Starcoin
    }
}

#[derive(Serialize_repr, Deserialize_repr, Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum IntentScope {
    TransactionData = 0,
    TransactionEffects = 1,
    CheckpointSummary = 2,
    PersonalMessage = 3,
    SenderSignedTransaction = 4,
    ProofOfPossession = 5,
    HeaderDigest = 6,
    BridgeEventUnused = 7,
    ConsensusBlock = 8,
    DiscoveryPeers = 9,
}

impl TryFrom<u8> for IntentScope {
    type Error = eyre::Report;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        bcs::from_bytes(&[value]).map_err(|_| eyre!("Invalid IntentScope"))
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Hash)]
pub struct Intent {
    pub scope: IntentScope,
    pub version: IntentVersion,
    pub app_id: AppId,
}

impl Intent {
    pub fn to_bytes(&self) -> [u8; INTENT_PREFIX_LENGTH] {
        [self.scope as u8, self.version as u8, self.app_id as u8]
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, eyre::Report> {
        if bytes.len() != INTENT_PREFIX_LENGTH {
            return Err(eyre!("Invalid Intent"));
        }
        Ok(Self {
            scope: bytes[0].try_into()?,
            version: bytes[1].try_into()?,
            app_id: bytes[2].try_into()?,
        })
    }

    pub fn starcoin_bridge_app(scope: IntentScope) -> Self {
        Self {
            version: IntentVersion::V0,
            scope,
            app_id: AppId::Starcoin,
        }
    }

    pub fn starcoin_bridge_transaction() -> Self {
        Self {
            scope: IntentScope::TransactionData,
            version: IntentVersion::V0,
            app_id: AppId::Starcoin,
        }
    }

    pub fn personal_message() -> Self {
        Self {
            scope: IntentScope::PersonalMessage,
            version: IntentVersion::V0,
            app_id: AppId::Starcoin,
        }
    }

    pub fn narwhal_app(scope: IntentScope) -> Self {
        Self {
            scope,
            version: IntentVersion::V0,
            app_id: AppId::Narwhal,
        }
    }

    pub fn consensus_app(scope: IntentScope) -> Self {
        Self {
            scope,
            version: IntentVersion::V0,
            app_id: AppId::Consensus,
        }
    }
}

impl FromStr for Intent {
    type Err = eyre::Report;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: Vec<u8> = decode_bytes_hex(s).map_err(|_| eyre!("Invalid Intent"))?;
        Self::from_bytes(bytes.as_slice())
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Hash, Deserialize)]
pub struct IntentMessage<T> {
    pub intent: Intent,
    pub value: T,
}

impl<T> IntentMessage<T> {
    pub fn new(intent: Intent, value: T) -> Self {
        Self { intent, value }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct PersonalMessage {
    pub message: Vec<u8>,
}

pub trait SecureIntent: Serialize + private::SealedIntent {}

pub(crate) mod private {
    use super::IntentMessage;
    pub trait SealedIntent {}
    impl<T> SealedIntent for IntentMessage<T> {}
}

#[derive(Serialize_repr, Deserialize_repr, Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum HashingIntentScope {
    ChildObjectId = 0xf0,
    RegularObjectId = 0xf1,
}
