// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::types::AddTokensOnEvmAction;
use crate::types::AddTokensOnStarcoinAction;
use crate::types::AssetPriceUpdateAction;
use crate::types::BlocklistCommitteeAction;
use crate::types::BridgeAction;
use crate::types::BridgeActionType;
use crate::types::EmergencyAction;
use crate::types::EthToStarcoinBridgeAction;
use crate::types::EvmAddMemberAction;
use crate::types::EvmContractUpgradeAction;
use crate::types::LimitUpdateAction;
use crate::types::StarcoinToEthBridgeAction;
use crate::types::UpdateCommitteeMemberAction;
use anyhow::Result;
use enum_dispatch::enum_dispatch;
use ethers::types::Address as EthAddress;

// Starcoin uses 16-byte addresses (128-bit)
pub const STARCOIN_ADDRESS_LENGTH: usize = 16;
pub const TOKEN_TRANSFER_MESSAGE_VERSION: u8 = 1;
pub const COMMITTEE_BLOCKLIST_MESSAGE_VERSION: u8 = 1;
pub const EMERGENCY_BUTTON_MESSAGE_VERSION: u8 = 1;
pub const LIMIT_UPDATE_MESSAGE_VERSION: u8 = 1;
pub const ASSET_PRICE_UPDATE_MESSAGE_VERSION: u8 = 1;
pub const EVM_CONTRACT_UPGRADE_MESSAGE_VERSION: u8 = 1;
pub const ADD_TOKENS_ON_STARCOIN_MESSAGE_VERSION: u8 = 1;
pub const ADD_TOKENS_ON_EVM_MESSAGE_VERSION: u8 = 1;
pub const UPDATE_COMMITTEE_MEMBER_MESSAGE_VERSION: u8 = 1;

pub const BRIDGE_MESSAGE_PREFIX: &[u8] = b"STARCOIN_BRIDGE_MESSAGE";

// Encoded bridge message consists of the following fields:
// 1. Message type (1 byte)
// 2. Message version (1 byte)
// 3. Nonce (8 bytes in big endian)
// 4. Chain id (1 byte)
// 4. Payload (variable length)
#[enum_dispatch]
pub trait BridgeMessageEncoding {
    // Convert the entire message to bytes
    fn as_bytes(&self) -> anyhow::Result<Vec<u8>>;
    // Convert the payload piece to bytes
    fn as_payload_bytes(&self) -> anyhow::Result<Vec<u8>>;
}

impl BridgeMessageEncoding for StarcoinToEthBridgeAction {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let e = &self.starcoin_bridge_event;
        // Add message type
        bytes.push(BridgeActionType::TokenTransfer as u8);
        // Add message version
        bytes.push(TOKEN_TRANSFER_MESSAGE_VERSION);
        // Add nonce
        bytes.extend_from_slice(&e.nonce.to_be_bytes());
        // Add source chain id
        bytes.push(e.starcoin_bridge_chain_id as u8);

        // Add payload bytes
        bytes.extend_from_slice(&self.as_payload_bytes()?);

        Ok(bytes)
    }

    fn as_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let e = &self.starcoin_bridge_event;

        // Add source address length
        bytes.push(STARCOIN_ADDRESS_LENGTH as u8);
        // Add source address
        bytes.extend_from_slice(&e.starcoin_bridge_address.to_vec());
        // Add dest chain id
        bytes.push(e.eth_chain_id as u8);
        // Add dest address length
        bytes.push(EthAddress::len_bytes() as u8);
        // Add dest address
        bytes.extend_from_slice(e.eth_address.as_bytes());

        // Add token id
        bytes.push(e.token_id);

        // Add token amount
        bytes.extend_from_slice(&e.amount_starcoin_bridge_adjusted.to_be_bytes());

        Ok(bytes)
    }
}

impl BridgeMessageEncoding for EthToStarcoinBridgeAction {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let e = &self.eth_bridge_event;
        // Add message type
        bytes.push(BridgeActionType::TokenTransfer as u8);
        // Add message version
        bytes.push(TOKEN_TRANSFER_MESSAGE_VERSION);
        // Add nonce
        bytes.extend_from_slice(&e.nonce.to_be_bytes());
        // Add source chain id
        bytes.push(e.eth_chain_id as u8);

        // Add payload bytes
        bytes.extend_from_slice(&self.as_payload_bytes()?);

        Ok(bytes)
    }

    fn as_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let e = &self.eth_bridge_event;

        // Add source address length
        bytes.push(EthAddress::len_bytes() as u8);
        // Add source address
        bytes.extend_from_slice(e.eth_address.as_bytes());
        // Add dest chain id
        bytes.push(e.starcoin_bridge_chain_id as u8);
        // Add dest address length
        bytes.push(STARCOIN_ADDRESS_LENGTH as u8);
        // Add dest address
        bytes.extend_from_slice(&e.starcoin_bridge_address.to_vec());

        // Add token id
        bytes.push(e.token_id);

        // Add token amount
        bytes.extend_from_slice(&e.starcoin_bridge_adjusted_amount.to_be_bytes());

        Ok(bytes)
    }
}

impl BridgeMessageEncoding for BlocklistCommitteeAction {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // Add message type
        bytes.push(BridgeActionType::UpdateCommitteeBlocklist as u8);
        // Add message version
        bytes.push(COMMITTEE_BLOCKLIST_MESSAGE_VERSION);
        // Add nonce
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        // Add chain id
        bytes.push(self.chain_id as u8);

        // Add payload bytes
        bytes.extend_from_slice(&self.as_payload_bytes()?);

        Ok(bytes)
    }

    fn as_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();

        // Add blocklist type
        bytes.push(self.blocklist_type as u8);
        // Add length of updated members.
        // Unwrap: It should not overflow given what we have today.
        bytes.push(u8::try_from(self.members_to_update.len())?);

        // Add list of updated members
        // Members are represented as pubkey derived evm addresses (20 bytes)
        let members_bytes = self
            .members_to_update
            .iter()
            .map(|m| m.to_eth_address().to_fixed_bytes().to_vec())
            .collect::<Vec<_>>();
        for members_bytes in members_bytes {
            bytes.extend_from_slice(&members_bytes);
        }

        Ok(bytes)
    }
}

impl BridgeMessageEncoding for EmergencyAction {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // Add message type
        bytes.push(BridgeActionType::EmergencyButton as u8);
        // Add message version
        bytes.push(EMERGENCY_BUTTON_MESSAGE_VERSION);
        // Add nonce
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        // Add chain id
        bytes.push(self.chain_id as u8);

        // Add payload bytes
        bytes.extend_from_slice(&self.as_payload_bytes()?);

        Ok(bytes)
    }

    fn as_payload_bytes(&self) -> Result<Vec<u8>> {
        Ok(vec![self.action_type as u8])
    }
}

impl BridgeMessageEncoding for LimitUpdateAction {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // Add message type
        bytes.push(BridgeActionType::LimitUpdate as u8);
        // Add message version
        bytes.push(LIMIT_UPDATE_MESSAGE_VERSION);
        // Add nonce
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        // Add chain id
        bytes.push(self.chain_id as u8);

        // Add payload bytes
        bytes.extend_from_slice(&self.as_payload_bytes()?);

        Ok(bytes)
    }

    fn as_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // Add sending chain id
        bytes.push(self.sending_chain_id as u8);
        // Add new usd limit
        bytes.extend_from_slice(&self.new_usd_limit.to_be_bytes());
        Ok(bytes)
    }
}

impl BridgeMessageEncoding for AssetPriceUpdateAction {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // Add message type
        bytes.push(BridgeActionType::AssetPriceUpdate as u8);
        // Add message version
        bytes.push(EMERGENCY_BUTTON_MESSAGE_VERSION);
        // Add nonce
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        // Add chain id
        bytes.push(self.chain_id as u8);

        // Add payload bytes
        bytes.extend_from_slice(&self.as_payload_bytes()?);

        Ok(bytes)
    }

    fn as_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // Add token id
        bytes.push(self.token_id);
        // Add new usd limit
        bytes.extend_from_slice(&self.new_usd_price.to_be_bytes());
        Ok(bytes)
    }
}

impl BridgeMessageEncoding for EvmContractUpgradeAction {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // Add message type
        bytes.push(BridgeActionType::EvmContractUpgrade as u8);
        // Add message version
        bytes.push(EVM_CONTRACT_UPGRADE_MESSAGE_VERSION);
        // Add nonce
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        // Add chain id
        bytes.push(self.chain_id as u8);

        // Add payload bytes
        bytes.extend_from_slice(&self.as_payload_bytes()?);

        Ok(bytes)
    }

    fn as_payload_bytes(&self) -> Result<Vec<u8>> {
        Ok(ethers::abi::encode(&[
            ethers::abi::Token::Address(self.proxy_address),
            ethers::abi::Token::Address(self.new_impl_address),
            ethers::abi::Token::Bytes(self.call_data.clone()),
        ]))
    }
}

impl BridgeMessageEncoding for AddTokensOnStarcoinAction {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // Add message type
        bytes.push(BridgeActionType::AddTokensOnstarcoin as u8);
        // Add message version
        bytes.push(ADD_TOKENS_ON_STARCOIN_MESSAGE_VERSION);
        // Add nonce
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        // Add chain id
        bytes.push(self.chain_id as u8);

        // Add payload bytes
        bytes.extend_from_slice(&self.as_payload_bytes()?);

        Ok(bytes)
    }

    fn as_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // Add native
        bytes.push(self.native as u8);
        // Add token ids
        bytes.extend_from_slice(&bcs::to_bytes(&self.token_ids)?);

        // Add token type names
        bytes.extend_from_slice(&bcs::to_bytes(
            &self
                .token_type_names
                .iter()
                .map(|m| m.to_canonical_string())
                .collect::<Vec<_>>(),
        )?);

        // Add token prices
        bytes.extend_from_slice(&bcs::to_bytes(&self.token_prices)?);

        Ok(bytes)
    }
}

impl BridgeMessageEncoding for AddTokensOnEvmAction {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // Add message type
        bytes.push(BridgeActionType::AddTokensOnEvm as u8);
        // Add message version
        bytes.push(ADD_TOKENS_ON_EVM_MESSAGE_VERSION);
        // Add nonce
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        // Add chain id
        bytes.push(self.chain_id as u8);

        // Add payload bytes
        bytes.extend_from_slice(&self.as_payload_bytes()?);

        Ok(bytes)
    }

    fn as_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // Add native
        bytes.push(self.native as u8);
        // Add token ids
        bytes.push(u8::try_from(self.token_ids.len())?);
        for token_id in &self.token_ids {
            bytes.push(*token_id);
        }

        // Add token addresses
        bytes.push(u8::try_from(self.token_addresses.len())?);
        for token_address in &self.token_addresses {
            bytes.extend_from_slice(&token_address.to_fixed_bytes());
        }

        // Add token starcoin decimals
        bytes.push(u8::try_from(self.token_starcoin_bridge_decimals.len())?);
        for token_starcoin_bridge_decimal in &self.token_starcoin_bridge_decimals {
            bytes.push(*token_starcoin_bridge_decimal);
        }

        // Add token prices
        bytes.push(u8::try_from(self.token_prices.len())?);
        for token_price in &self.token_prices {
            bytes.extend_from_slice(&token_price.to_be_bytes());
        }
        Ok(bytes)
    }
}

impl BridgeMessageEncoding for UpdateCommitteeMemberAction {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // Add message type
        bytes.push(BridgeActionType::UpdateCommitteeMember as u8);
        // Add message version
        bytes.push(UPDATE_COMMITTEE_MEMBER_MESSAGE_VERSION);
        // Add nonce
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        // Add chain id
        bytes.push(self.chain_id as u8);

        // Add payload bytes
        bytes.extend_from_slice(&self.as_payload_bytes()?);

        Ok(bytes)
    }

    fn as_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();

        // Add update type (0 = add, 1 = remove)
        bytes.push(self.update_type as u8);

        // Add member address (16 bytes Starcoin address)
        bytes.extend_from_slice(self.member_address.as_ref());

        // Add bridge pubkey bytes with length prefix
        bytes.push(u8::try_from(self.bridge_pubkey_bytes.len())?);
        bytes.extend_from_slice(&self.bridge_pubkey_bytes);

        // Add voting power (8 bytes big endian)
        bytes.extend_from_slice(&self.voting_power.to_be_bytes());

        // Add http rest url with length prefix
        let url_bytes = self.http_rest_url.as_bytes();
        bytes.push(u8::try_from(url_bytes.len())?);
        bytes.extend_from_slice(url_bytes);

        Ok(bytes)
    }
}

/// EVM-specific add member action encoding.
/// Uses message type 8 (UpdateCommitteeMember) but with EVM-compatible payload.
/// Payload format: address (20 bytes) + stake (uint16, 2 bytes) = 22 bytes total.
pub const EVM_ADD_MEMBER_MESSAGE_VERSION: u8 = 1;

impl BridgeMessageEncoding for EvmAddMemberAction {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // Add message type (8 = UpdateCommitteeMember, same as EVM ADD_MEMBER)
        bytes.push(BridgeActionType::UpdateCommitteeMember as u8);
        // Add message version
        bytes.push(EVM_ADD_MEMBER_MESSAGE_VERSION);
        // Add nonce
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        // Add chain id
        bytes.push(self.chain_id as u8);

        // Add payload bytes
        bytes.extend_from_slice(&self.as_payload_bytes()?);

        Ok(bytes)
    }

    fn as_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // Add member address (20 bytes EVM address)
        bytes.extend_from_slice(self.member_address.as_bytes());
        // Add stake amount (uint16, 2 bytes big endian)
        bytes.extend_from_slice(&self.stake.to_be_bytes());
        Ok(bytes)
    }
}

impl BridgeAction {
    // Convert to message bytes to verify in Move and Solidity
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // Add prefix
        bytes.extend_from_slice(BRIDGE_MESSAGE_PREFIX);
        // Add bytes from message itself
        bytes.extend_from_slice(&self.as_bytes()?);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use crate::abi::EthToStarcoinTokenBridgeV1;
    use crate::crypto::BridgeAuthorityKeyPair;
    use crate::crypto::BridgeAuthorityPublicKeyBytes;
    use crate::crypto::BridgeAuthoritySignInfo;
    use crate::events::EmittedStarcoinToEthTokenBridgeV1;
    use crate::test_utils::{StarcoinAddressTestExt, TransactionDigestTestExt}; // Import test traits
    use crate::types::BlocklistType;
    use crate::types::EmergencyActionType;
    use crate::types::USD_MULTIPLIER;
    use ethers::abi::ParamType;
    use ethers::types::{Address as EthAddress, TxHash};
    use fastcrypto::encoding::Encoding;
    use fastcrypto::encoding::Hex;
    use fastcrypto::hash::HashFunction;
    use fastcrypto::hash::Keccak256;
    use fastcrypto::traits::ToFromBytes;
    use prometheus::Registry;
    use starcoin_bridge_types::base_types::{StarcoinAddress, TransactionDigest};
    use starcoin_bridge_types::bridge::BridgeChainId;
    use starcoin_bridge_types::bridge::TOKEN_ID_BTC;
    use starcoin_bridge_types::bridge::TOKEN_ID_USDC;
    use starcoin_bridge_types::TypeTag;
    use std::str::FromStr;

    use super::*;

    /// Helper to get the hex-encoded prefix
    fn prefix_hex() -> String {
        Hex::encode(BRIDGE_MESSAGE_PREFIX)
    }

    /// Helper to build expected bytes dynamically: prefix + payload_hex
    fn expected_bytes(payload_hex: &str) -> Vec<u8> {
        let mut bytes = BRIDGE_MESSAGE_PREFIX.to_vec();
        bytes.extend_from_slice(&Hex::decode(payload_hex).unwrap());
        bytes
    }

    #[test]
    fn test_bridge_message_encoding() -> anyhow::Result<()> {
        telemetry_subscribers::init_for_testing();
        let registry = Registry::new();
        starcoin_metrics::init_metrics(&registry);
        let nonce = 54321u64;
        let starcoin_bridge_tx_digest = TransactionDigest::random();
        let starcoin_bridge_chain_id = BridgeChainId::StarcoinTestnet;
        let starcoin_bridge_tx_event_index = 1u16;
        let eth_chain_id = BridgeChainId::EthSepolia;
        let starcoin_bridge_address = StarcoinAddress::random_for_testing_only();
        let eth_address = EthAddress::random();
        let token_id = TOKEN_ID_USDC;
        let amount_starcoin_bridge_adjusted = 1_000_000;

        let starcoin_bridge_event = EmittedStarcoinToEthTokenBridgeV1 {
            nonce,
            starcoin_bridge_chain_id,
            eth_chain_id,
            starcoin_bridge_address,
            eth_address,
            token_id,
            amount_starcoin_bridge_adjusted,
        };

        let encoded_bytes = BridgeAction::StarcoinToEthBridgeAction(StarcoinToEthBridgeAction {
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            starcoin_bridge_event,
        })
        .to_bytes()?;

        // Construct the expected bytes
        let prefix_bytes = BRIDGE_MESSAGE_PREFIX.to_vec(); // len: 23
        let message_type = vec![BridgeActionType::TokenTransfer as u8]; // len: 1
        let message_version = vec![TOKEN_TRANSFER_MESSAGE_VERSION]; // len: 1
        let nonce_bytes = nonce.to_be_bytes().to_vec(); // len: 8
        let source_chain_id_bytes = vec![starcoin_bridge_chain_id as u8]; // len: 1

        let starcoin_bridge_address_length_bytes = vec![STARCOIN_ADDRESS_LENGTH as u8]; // len: 1
        let starcoin_bridge_address_bytes = starcoin_bridge_address.to_vec(); // len: 16
        let dest_chain_id_bytes = vec![eth_chain_id as u8]; // len: 1
        let eth_address_length_bytes = vec![EthAddress::len_bytes() as u8]; // len: 1
        let eth_address_bytes = eth_address.as_bytes().to_vec(); // len: 20

        let token_id_bytes = vec![token_id]; // len: 1
        let token_amount_bytes = amount_starcoin_bridge_adjusted.to_be_bytes().to_vec(); // len: 8

        let mut combined_bytes = Vec::new();
        combined_bytes.extend_from_slice(&prefix_bytes);
        combined_bytes.extend_from_slice(&message_type);
        combined_bytes.extend_from_slice(&message_version);
        combined_bytes.extend_from_slice(&nonce_bytes);
        combined_bytes.extend_from_slice(&source_chain_id_bytes);
        combined_bytes.extend_from_slice(&starcoin_bridge_address_length_bytes);
        combined_bytes.extend_from_slice(&starcoin_bridge_address_bytes);
        combined_bytes.extend_from_slice(&dest_chain_id_bytes);
        combined_bytes.extend_from_slice(&eth_address_length_bytes);
        combined_bytes.extend_from_slice(&eth_address_bytes);
        combined_bytes.extend_from_slice(&token_id_bytes);
        combined_bytes.extend_from_slice(&token_amount_bytes);

        assert_eq!(combined_bytes, encoded_bytes);

        // Assert fixed length: prefix + message_type + version + nonce + source_chain +
        // starcoin_addr_len + starcoin_addr + dest_chain + eth_addr_len + eth_addr + token_id + amount
        assert_eq!(
            combined_bytes.len(),
            BRIDGE_MESSAGE_PREFIX.len() + 1 + 1 + 8 + 1 + 1 + 16 + 1 + 1 + 20 + 1 + 8
        );
        Ok(())
    }

    #[test]
    fn test_bridge_message_encoding_regression_emitted_starcoin_bridge_to_eth_token_bridge_v1(
    ) -> anyhow::Result<()> {
        telemetry_subscribers::init_for_testing();
        let registry = Registry::new();
        starcoin_metrics::init_metrics(&registry);
        let starcoin_bridge_tx_digest = TransactionDigest::random();
        let starcoin_bridge_tx_event_index = 1u16;

        let nonce = 10u64;
        let starcoin_bridge_chain_id = BridgeChainId::StarcoinTestnet;
        let eth_chain_id = BridgeChainId::EthSepolia;
        // Starcoin uses 16-byte addresses
        let starcoin_bridge_address =
            StarcoinAddress::from_str("0x00000000000000000000000000000064").unwrap();
        let eth_address =
            EthAddress::from_str("0x00000000000000000000000000000000000000c8").unwrap();
        let token_id = TOKEN_ID_USDC;
        let amount_starcoin_bridge_adjusted = 12345;

        let starcoin_bridge_event = EmittedStarcoinToEthTokenBridgeV1 {
            nonce,
            starcoin_bridge_chain_id,
            eth_chain_id,
            starcoin_bridge_address,
            eth_address,
            token_id,
            amount_starcoin_bridge_adjusted,
        };
        let encoded_bytes = BridgeAction::StarcoinToEthBridgeAction(StarcoinToEthBridgeAction {
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            starcoin_bridge_event,
        })
        .to_bytes()?;

        // Verify encoding format:
        // prefix(STARCOIN_BRIDGE_MESSAGE) + msg_type(00) + version(01) + nonce(8 bytes) +
        // source_chain(01) + addr_len(10=16) + starcoin_addr(16 bytes) +
        // dest_chain(0b) + addr_len(14=20) + eth_addr(20 bytes) + token_id(03) + amount(8 bytes)
        let expected_hex = format!(
            "{}0001000000000000000a0110000000000000000000000000000000640b1400000000000000000000000000000000000000c8030000000000003039",
            Hex::encode(BRIDGE_MESSAGE_PREFIX)
        );
        assert_eq!(Hex::encode(&encoded_bytes), expected_hex);

        // Verify hash for regression
        let hash = Keccak256::digest(&encoded_bytes).digest;
        assert_eq!(hash.len(), 32);
        Ok(())
    }

    #[test]
    fn test_bridge_message_encoding_blocklist_update_v1() {
        telemetry_subscribers::init_for_testing();
        let registry = Registry::new();
        starcoin_metrics::init_metrics(&registry);

        let pub_key_bytes = BridgeAuthorityPublicKeyBytes::from_bytes(
            &Hex::decode("02321ede33d2c2d7a8a152f275a1484edef2098f034121a602cb7d767d38680aa4")
                .unwrap(),
        )
        .unwrap();
        let blocklist_action = BridgeAction::BlocklistCommitteeAction(BlocklistCommitteeAction {
            nonce: 129,
            chain_id: BridgeChainId::StarcoinCustom,
            blocklist_type: BlocklistType::Blocklist,
            members_to_update: vec![pub_key_bytes.clone()],
        });
        let bytes = blocklist_action.to_bytes().unwrap();
        // prefix + msg_type(01) + version(01) + nonce(0000000000000081) + chain_id(02) +
        // blocklist_type(00) + members_len(01) + member(68b43fd906c0b8f024a18c56e06744f7c6157c65)
        assert_eq!(
            bytes,
            expected_bytes("0101000000000000008102000168b43fd906c0b8f024a18c56e06744f7c6157c65")
        );

        let pub_key_bytes_2 = BridgeAuthorityPublicKeyBytes::from_bytes(
            &Hex::decode("027f1178ff417fc9f5b8290bd8876f0a157a505a6c52db100a8492203ddd1d4279")
                .unwrap(),
        )
        .unwrap();
        // its evm address: 0xacaef39832cb995c4e049437a3e2ec6a7bad1ab5
        let blocklist_action = BridgeAction::BlocklistCommitteeAction(BlocklistCommitteeAction {
            nonce: 68,
            chain_id: BridgeChainId::StarcoinCustom,
            blocklist_type: BlocklistType::Unblocklist,
            members_to_update: vec![pub_key_bytes.clone(), pub_key_bytes_2.clone()],
        });
        let bytes = blocklist_action.to_bytes().unwrap();
        // prefix + msg_type(01) + version(01) + nonce(0000000000000044) + chain_id(02) +
        // blocklist_type(01) + members_len(02) + members
        assert_eq!(bytes, expected_bytes("0101000000000000004402010268b43fd906c0b8f024a18c56e06744f7c6157c65acaef39832cb995c4e049437a3e2ec6a7bad1ab5"));

        let blocklist_action = BridgeAction::BlocklistCommitteeAction(BlocklistCommitteeAction {
            nonce: 49,
            chain_id: BridgeChainId::EthCustom,
            blocklist_type: BlocklistType::Blocklist,
            members_to_update: vec![pub_key_bytes.clone()],
        });
        let bytes = blocklist_action.to_bytes().unwrap();
        // prefix + msg_type(01) + version(01) + nonce(0000000000000031) + chain_id(0c) +
        // blocklist_type(00) + members_len(01) + member
        assert_eq!(
            bytes,
            expected_bytes("010100000000000000310c000168b43fd906c0b8f024a18c56e06744f7c6157c65")
        );

        let blocklist_action = BridgeAction::BlocklistCommitteeAction(BlocklistCommitteeAction {
            nonce: 94,
            chain_id: BridgeChainId::EthSepolia,
            blocklist_type: BlocklistType::Unblocklist,
            members_to_update: vec![pub_key_bytes.clone(), pub_key_bytes_2.clone()],
        });
        let bytes = blocklist_action.to_bytes().unwrap();
        // prefix + msg_type(01) + version(01) + nonce(000000000000005e) + chain_id(0b) +
        // blocklist_type(01) + members_len(02) + members
        assert_eq!(bytes, expected_bytes("0101000000000000005e0b010268b43fd906c0b8f024a18c56e06744f7c6157c65acaef39832cb995c4e049437a3e2ec6a7bad1ab5"));
    }

    #[test]
    fn test_bridge_message_encoding_emergency_action() {
        let action = BridgeAction::EmergencyAction(EmergencyAction {
            nonce: 55,
            chain_id: BridgeChainId::StarcoinCustom,
            action_type: EmergencyActionType::Pause,
        });
        let bytes = action.to_bytes().unwrap();
        // prefix + msg_type(02) + version(01) + nonce(0000000000000037) + chain_id(02) + action_type(00)
        assert_eq!(bytes, expected_bytes("020100000000000000370200"));

        let action = BridgeAction::EmergencyAction(EmergencyAction {
            nonce: 56,
            chain_id: BridgeChainId::EthSepolia,
            action_type: EmergencyActionType::Unpause,
        });
        let bytes = action.to_bytes().unwrap();
        // prefix + msg_type(02) + version(01) + nonce(0000000000000038) + chain_id(0b) + action_type(01)
        assert_eq!(bytes, expected_bytes("020100000000000000380b01"));
    }

    #[test]
    fn test_bridge_message_encoding_limit_update_action() {
        let action = BridgeAction::LimitUpdateAction(LimitUpdateAction {
            nonce: 15,
            chain_id: BridgeChainId::StarcoinCustom,
            sending_chain_id: BridgeChainId::EthCustom,
            new_usd_limit: 1_000_000 * USD_MULTIPLIER, // $1M USD
        });
        let bytes = action.to_bytes().unwrap();
        // prefix + msg_type(03) + version(01) + nonce(000000000000000f) + chain_id(02) +
        // sending_chain_id(0c) + new_usd_limit(00000002540be400)
        assert_eq!(
            bytes,
            expected_bytes("0301000000000000000f020c00000002540be400")
        );
    }

    #[test]
    fn test_bridge_message_encoding_asset_price_update_action() {
        let action = BridgeAction::AssetPriceUpdateAction(AssetPriceUpdateAction {
            nonce: 266,
            chain_id: BridgeChainId::StarcoinCustom,
            token_id: TOKEN_ID_BTC,
            new_usd_price: 100_000 * USD_MULTIPLIER, // $100k USD
        });
        let bytes = action.to_bytes().unwrap();
        // prefix + msg_type(04) + version(01) + nonce(000000000000010a) + chain_id(02) +
        // token_id(01) + new_usd_price(000000003b9aca00)
        assert_eq!(
            bytes,
            expected_bytes("0401000000000000010a0201000000003b9aca00")
        );
    }

    #[test]
    fn test_bridge_message_encoding_evm_contract_upgrade_action() {
        // Calldata with only the function selector and no parameters: `function initializeV2()`
        let function_signature = "initializeV2()";
        let selector = &Keccak256::digest(function_signature).digest[0..4];
        let call_data = selector.to_vec();
        assert_eq!(Hex::encode(call_data.clone()), "5cd8a76b");

        let action = BridgeAction::EvmContractUpgradeAction(EvmContractUpgradeAction {
            nonce: 123,
            chain_id: BridgeChainId::EthCustom,
            proxy_address: EthAddress::repeat_byte(6),
            new_impl_address: EthAddress::repeat_byte(9),
            call_data,
        });
        // prefix + msg_type(05) + version(01) + nonce + chain_id + proxy_address + new_impl_address + call_data
        let data = action.to_bytes().unwrap();
        assert_eq!(Hex::encode(data.clone()), format!("{}0501000000000000007b0c00000000000000000000000006060606060606060606060606060606060606060000000000000000000000000909090909090909090909090909090909090909000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000045cd8a76b00000000000000000000000000000000000000000000000000000000", prefix_hex()));

        // Calldata with one parameter: `function newMockFunction(bool)`
        let function_signature = "newMockFunction(bool)";
        let selector = &Keccak256::digest(function_signature).digest[0..4];
        let mut call_data = selector.to_vec();
        call_data.extend(ethers::abi::encode(&[ethers::abi::Token::Bool(true)]));
        assert_eq!(
            Hex::encode(call_data.clone()),
            "417795ef0000000000000000000000000000000000000000000000000000000000000001"
        );
        let action = BridgeAction::EvmContractUpgradeAction(EvmContractUpgradeAction {
            nonce: 123,
            chain_id: BridgeChainId::EthCustom,
            proxy_address: EthAddress::repeat_byte(6),
            new_impl_address: EthAddress::repeat_byte(9),
            call_data,
        });
        // prefix + msg_type(05) + version(01) + nonce + chain_id + proxy_address + new_impl_address + call_data
        assert_eq!(Hex::encode(action.to_bytes().unwrap().clone()), format!("{}0501000000000000007b0c0000000000000000000000000606060606060606060606060606060606060606000000000000000000000000090909090909090909090909090909090909090900000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000024417795ef000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000", prefix_hex()));

        // Calldata with two parameters: `function newerMockFunction(bool, uint8)`
        let function_signature = "newMockFunction(bool,uint8)";
        let selector = &Keccak256::digest(function_signature).digest[0..4];
        let mut call_data = selector.to_vec();
        call_data.extend(ethers::abi::encode(&[
            ethers::abi::Token::Bool(true),
            ethers::abi::Token::Uint(42u8.into()),
        ]));
        assert_eq!(
            Hex::encode(call_data.clone()),
            "be8fc25d0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002a"
        );
        let action = BridgeAction::EvmContractUpgradeAction(EvmContractUpgradeAction {
            nonce: 123,
            chain_id: BridgeChainId::EthCustom,
            proxy_address: EthAddress::repeat_byte(6),
            new_impl_address: EthAddress::repeat_byte(9),
            call_data,
        });
        // prefix + msg_type(05) + version(01) + nonce + chain_id + proxy_address + new_impl_address + call_data
        assert_eq!(Hex::encode(action.to_bytes().unwrap().clone()), format!("{}0501000000000000007b0c0000000000000000000000000606060606060606060606060606060606060606000000000000000000000000090909090909090909090909090909090909090900000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044be8fc25d0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000", prefix_hex()));

        // Empty calldata
        let action = BridgeAction::EvmContractUpgradeAction(EvmContractUpgradeAction {
            nonce: 123,
            chain_id: BridgeChainId::EthCustom,
            proxy_address: EthAddress::repeat_byte(6),
            new_impl_address: EthAddress::repeat_byte(9),
            call_data: vec![],
        });
        // prefix + msg_type(05) + version(01) + nonce + chain_id + proxy_address + new_impl_address + empty_call_data
        let data = action.to_bytes().unwrap();
        assert_eq!(Hex::encode(data.clone()), format!("{}0501000000000000007b0c0000000000000000000000000606060606060606060606060606060606060606000000000000000000000000090909090909090909090909090909090909090900000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000", prefix_hex()));
        let types = vec![ParamType::Address, ParamType::Address, ParamType::Bytes];
        // Ensure that the call data (start from bytes after prefix) can be decoded
        ethers::abi::decode(&types, &data[BRIDGE_MESSAGE_PREFIX.len() + 11..]).unwrap();
    }

    #[test]
    fn test_bridge_message_encoding_regression_eth_to_starcoin_bridge_token_bridge_v1(
    ) -> anyhow::Result<()> {
        telemetry_subscribers::init_for_testing();
        let registry = Registry::new();
        starcoin_metrics::init_metrics(&registry);
        let eth_tx_hash = TxHash::random();
        let eth_event_index = 1u16;

        let nonce = 10u64;
        let starcoin_bridge_chain_id = BridgeChainId::StarcoinTestnet;
        let eth_chain_id = BridgeChainId::EthSepolia;
        // Starcoin uses 16-byte addresses
        let starcoin_bridge_address =
            StarcoinAddress::from_str("0x00000000000000000000000000000064").unwrap();
        let eth_address =
            EthAddress::from_str("0x00000000000000000000000000000000000000c8").unwrap();
        let token_id = TOKEN_ID_USDC;
        let starcoin_bridge_adjusted_amount = 12345;

        let eth_bridge_event = EthToStarcoinTokenBridgeV1 {
            nonce,
            starcoin_bridge_chain_id,
            eth_chain_id,
            starcoin_bridge_address,
            eth_address,
            token_id,
            starcoin_bridge_adjusted_amount,
        };
        let encoded_bytes = BridgeAction::EthToStarcoinBridgeAction(EthToStarcoinBridgeAction {
            eth_tx_hash,
            eth_event_index,
            eth_bridge_event,
        })
        .to_bytes()?;

        // Verify encoding format for ETH->Starcoin:
        // prefix(STARCOIN_BRIDGE_MESSAGE) + msg_type(00) + version(01) + nonce(8 bytes) +
        // source_chain(0b=EthSepolia) + addr_len(14=20) + eth_addr(20 bytes) +
        // dest_chain(01=StarcoinTestnet) + addr_len(10=16) + starcoin_addr(16 bytes) + token_id(03) + amount(8 bytes)
        let expected_hex = format!(
            "{}0001000000000000000a0b1400000000000000000000000000000000000000c80110000000000000000000000000000000640300000000000030 39",
            Hex::encode(BRIDGE_MESSAGE_PREFIX)
        ).replace(" ", "");
        assert_eq!(Hex::encode(&encoded_bytes), expected_hex);

        // Verify hash is computed correctly
        let hash = Keccak256::digest(&encoded_bytes).digest;
        assert_eq!(hash.len(), 32);
        Ok(())
    }

    #[test]
    fn test_bridge_message_encoding_regression_add_coins_on_starcoin() -> anyhow::Result<()> {
        telemetry_subscribers::init_for_testing();

        let action = BridgeAction::AddTokensOnStarcoinAction(AddTokensOnStarcoinAction {
            nonce: 0,
            chain_id: BridgeChainId::StarcoinCustom,
            native: false,
            token_ids: vec![1, 2, 3, 4],
            token_type_names: vec![
                TypeTag::from_str("0x9b5e13bcd0cb23ff25c07698e89d4805::btc::BTC").unwrap(),
                TypeTag::from_str("0x7970d71c03573f540a7157f0d3970e11::eth::ETH").unwrap(),
                TypeTag::from_str("0x500e429a24478405d5130222b20f8570::usdc::USDC").unwrap(),
                TypeTag::from_str("0x46bfe51da1bd9511919a92eb11541496::usdt::USDT").unwrap(),
            ],
            token_prices: vec![500_000_000u64, 30_000_000u64, 1_000u64, 1_000u64],
        });
        let encoded_bytes = action.to_bytes().unwrap();

        // Verify the encoding starts with STARCOIN_BRIDGE_MESSAGE prefix
        // Format: prefix + msg_type(06) + version(01) + nonce + chain_id + native_flag +
        //         token_count + token_ids + type_tags + prices
        let expected_prefix = format!(
            "{}0601000000000000000002000401020304",
            Hex::encode(BRIDGE_MESSAGE_PREFIX)
        );
        let encoded_hex = Hex::encode(&encoded_bytes);
        assert!(
            encoded_hex.starts_with(&expected_prefix),
            "Encoded bytes should start with correct prefix. Got: {}",
            encoded_hex
        );

        // Verify the encoding is valid by checking it can be used
        assert!(encoded_bytes.len() > BRIDGE_MESSAGE_PREFIX.len() + 20);
        Ok(())
    }

    /// Helper test to generate signature for Move test
    #[test]
    fn test_generate_add_tokens_signature_for_move_test() -> anyhow::Result<()> {
        use fastcrypto::hash::Keccak256;
        use fastcrypto::traits::{KeyPair, RecoverableSigner, ToFromBytes};

        // Construct the exact same message bytes as Move test
        // msg_bytes = STARCOIN_BRIDGE_MESSAGE + serialized_message
        let message_hex = "0601000000000000000002000401020304044a396235653133626364306362323366663235633037363938653839643438303536633734353333386438633964626430333361343137326238373032373037333a3a6274633a3a4254434a373937306437316330333537336635343061373135376630643339373065313137656666613661653136636566643530623435633734393637306232346536613a3a6574683a3a4554484c353030653432396132343437383430356435313330323232623230663835373061373436623662633232343233663134623464346536613865613538303733363a3a757364633a3a555344434c343662666535316461316264393531313931396139326562313135343134396233366330663432313231323138303865313365336535383537643630376139633a3a757364743a3a55534454040065cd1d0000000080c3c90100000000e803000000000000e803000000000000";
        let message_bytes = Hex::decode(message_hex).unwrap();

        let mut full_message = BRIDGE_MESSAGE_PREFIX.to_vec();
        full_message.extend_from_slice(&message_bytes);

        println!("Full message hex: {}", Hex::encode(&full_message));

        // Get test key
        let key = BridgeAuthorityKeyPair::from_bytes(
            &Hex::decode("e42c82337ce12d4a7ad6cd65876d91b2ab6594fd50cdab1737c91773ba7451db")
                .unwrap(),
        )
        .unwrap();

        let pubkey = key.public();
        println!(
            "Public key (compressed): {}",
            Hex::encode(pubkey.as_bytes())
        );

        // Sign the message with keccak256 hash mode (mode 0)
        let sig = key.sign_recoverable_with_hash::<Keccak256>(&full_message);
        println!("Signature: {}", Hex::encode(sig.as_bytes()));

        Ok(())
    }

    #[test]
    fn test_bridge_message_encoding_regression_add_coins_on_evm() -> anyhow::Result<()> {
        let action = BridgeAction::AddTokensOnEvmAction(crate::types::AddTokensOnEvmAction {
            nonce: 0,
            chain_id: BridgeChainId::EthCustom,
            native: true,
            token_ids: vec![99, 100, 101],
            token_addresses: vec![
                EthAddress::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                EthAddress::from_str("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84").unwrap(),
                EthAddress::from_str("0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72").unwrap(),
            ],
            token_starcoin_bridge_decimals: vec![5, 6, 7],
            token_prices: vec![1_000_000_000, 2_000_000_000, 3_000_000_000],
        });
        let encoded_bytes = action.to_bytes().unwrap();

        // Verify the encoded bytes start with the correct prefix and payload
        assert_eq!(
            Hex::encode(encoded_bytes),
            format!("{}070100000000000000000c0103636465036b175474e89094c44da98b954eedeac495271d0fae7ab96520de3a18e5e111b5eaab095312d7fe84c18360217d8f7ab5e7c516566761ea12ce7f9d720305060703000000003b9aca00000000007735940000000000b2d05e00", prefix_hex()),
        );
        // To generate regression test for sol contracts
        let keys = get_bridge_encoding_regression_test_keys();
        for key in keys {
            let pub_key = key.public.as_bytes();
            tracing::debug!("pub_key: {:?}", Hex::encode(pub_key));
            tracing::debug!(
                "sig: {:?}",
                Hex::encode(
                    BridgeAuthoritySignInfo::new(&action, &key)
                        .signature
                        .as_bytes()
                )
            );
        }
        Ok(())
    }

    fn get_bridge_encoding_regression_test_keys() -> Vec<BridgeAuthorityKeyPair> {
        vec![
            BridgeAuthorityKeyPair::from_bytes(
                &Hex::decode("e42c82337ce12d4a7ad6cd65876d91b2ab6594fd50cdab1737c91773ba7451db")
                    .unwrap(),
            )
            .unwrap(),
            BridgeAuthorityKeyPair::from_bytes(
                &Hex::decode("1aacd610da3d0cc691a04b83b01c34c6c65cda0fe8d502df25ff4b3185c85687")
                    .unwrap(),
            )
            .unwrap(),
            BridgeAuthorityKeyPair::from_bytes(
                &Hex::decode("53e7baf8378fbc62692e3056c2e10c6666ef8b5b3a53914830f47636d1678140")
                    .unwrap(),
            )
            .unwrap(),
            BridgeAuthorityKeyPair::from_bytes(
                &Hex::decode("08b5350a091faabd5f25b6e290bfc3f505d43208775b9110dfed5ee6c7a653f0")
                    .unwrap(),
            )
            .unwrap(),
        ]
    }

    /// Helper test to print pubkeys for each key to help find which keys to use for Move tests
    #[test]
    fn test_print_all_keys_pubkeys() -> anyhow::Result<()> {
        use fastcrypto::traits::{KeyPair, ToFromBytes};

        let keys = get_bridge_encoding_regression_test_keys();
        for (i, key) in keys.iter().enumerate() {
            println!("Key {}: {}", i + 1, Hex::encode(key.public().as_bytes()));
        }

        // VALIDATOR1_PUBKEY from Move test
        println!("\nVALIDATOR1_PUBKEY in Move test: 029bef8d556d80e43ae7e0becb3a7e6838b95defe45896ed6075bb9035d06c9964");
        println!("VALIDATOR2_PUBKEY in Move test: 033e99a541db69bd32040dfe5037fbf5210dafa8151a71e21c5204b05d95ce0a62");

        Ok(())
    }

    /// Helper test to generate signatures for token transfer approve→claim tests in Move.
    /// Generates hardcoded (message_bytes, signatures) pairs that can be pasted into Move test code.
    ///
    /// The message represents an ETH→Starcoin token transfer:
    ///   source_chain = EthCustom(12), target_chain = StarcoinCustom(2)
    ///   source_address = 0x0000...1234 (20 bytes)
    ///   target_address = 0xba0f421cab925857ae31f058c2f027f8 (Bridge address)
    ///   token_id = 2 (ETH), amount = 1000
    ///   nonce = 0
    #[test]
    fn test_generate_token_transfer_signatures_for_move_test() -> anyhow::Result<()> {
        use crate::abi::EthToStarcoinTokenBridgeV1;
        use ethers::types::H256;
        use fastcrypto::hash::Keccak256;
        use fastcrypto::traits::{KeyPair, RecoverableSigner, ToFromBytes};
        use starcoin_bridge_types::base_types::StarcoinAddress;

        // Use Bridge address as target so tests can use bridge_admin signer
        // Bridge = 0xba0f421cab925857ae31f058c2f027f8
        let starcoin_addr =
            StarcoinAddress::new(hex_literal::hex!("ba0f421cab925857ae31f058c2f027f8"));
        let eth_addr: EthAddress = "0x0000000000000000000000000000000000001234"
            .parse()
            .unwrap();

        let action = BridgeAction::EthToStarcoinBridgeAction(EthToStarcoinBridgeAction {
            eth_tx_hash: H256::zero(),
            eth_event_index: 0,
            eth_bridge_event: EthToStarcoinTokenBridgeV1 {
                nonce: 0,
                starcoin_bridge_chain_id: BridgeChainId::StarcoinCustom,
                eth_chain_id: BridgeChainId::EthCustom,
                starcoin_bridge_address: starcoin_addr,
                eth_address: eth_addr,
                token_id: 2, // ETH token
                starcoin_bridge_adjusted_amount: 1000,
            },
        });

        let msg_bytes = action.as_bytes()?;
        let mut full_message = BRIDGE_MESSAGE_PREFIX.to_vec();
        full_message.extend_from_slice(&msg_bytes);

        println!("=== Token Transfer Message for Move Tests ===");
        println!(
            "Message bytes (without prefix): {}",
            Hex::encode(&msg_bytes)
        );
        println!(
            "Full message (prefix + msg): {}",
            Hex::encode(&full_message)
        );
        println!();

        // Sign with all 4 test keys (same keys used in existing Move committee tests)
        let keys = get_bridge_encoding_regression_test_keys();
        for (i, key) in keys.iter().enumerate() {
            let pubkey = key.public();
            let sig = key.sign_recoverable_with_hash::<Keccak256>(&full_message);
            println!("Key {} (for Move hardcoded test):", i + 1);
            println!("  Pubkey (compressed): {}", Hex::encode(pubkey.as_bytes()));
            println!("  Signature (65 bytes): {}", Hex::encode(sig.as_bytes()));
        }

        // Also generate a second transfer message with nonce=1, amount=500, token=4 (USDT)
        println!("\n=== Token Transfer Message 2 (USDT, nonce=1, amount=500) ===");
        let action2 = BridgeAction::EthToStarcoinBridgeAction(EthToStarcoinBridgeAction {
            eth_tx_hash: H256::zero(),
            eth_event_index: 0,
            eth_bridge_event: EthToStarcoinTokenBridgeV1 {
                nonce: 1,
                starcoin_bridge_chain_id: BridgeChainId::StarcoinCustom,
                eth_chain_id: BridgeChainId::EthCustom,
                starcoin_bridge_address: starcoin_addr,
                eth_address: eth_addr,
                token_id: 4, // USDT
                starcoin_bridge_adjusted_amount: 500,
            },
        });

        let msg_bytes2 = action2.as_bytes()?;
        let mut full_message2 = BRIDGE_MESSAGE_PREFIX.to_vec();
        full_message2.extend_from_slice(&msg_bytes2);

        println!(
            "Message bytes (without prefix): {}",
            Hex::encode(&msg_bytes2)
        );
        for (i, key) in keys.iter().enumerate() {
            let pubkey = key.public();
            let sig = key.sign_recoverable_with_hash::<Keccak256>(&full_message2);
            println!("Key {} sig: {}", i + 1, Hex::encode(sig.as_bytes()));
            let _ = pubkey; // suppress unused warning
        }

        // Also generate emergency-op signatures for system message tests
        println!("\n=== Emergency Pause Message (nonce=0, StarcoinCustom) ===");
        let em_action = BridgeAction::EmergencyAction(EmergencyAction {
            nonce: 0,
            chain_id: BridgeChainId::StarcoinCustom,
            action_type: crate::types::EmergencyActionType::Pause,
        });
        let em_bytes = em_action.as_bytes()?;
        let mut em_full = BRIDGE_MESSAGE_PREFIX.to_vec();
        em_full.extend_from_slice(&em_bytes);
        println!("Message bytes (without prefix): {}", Hex::encode(&em_bytes));
        for (i, key) in keys.iter().enumerate() {
            let sig = key.sign_recoverable_with_hash::<Keccak256>(&em_full);
            println!("Key {} sig: {}", i + 1, Hex::encode(sig.as_bytes()));
        }

        // Emergency Unpause (nonce=1)
        println!("\n=== Emergency Unpause Message (nonce=1, StarcoinCustom) ===");
        let em_action2 = BridgeAction::EmergencyAction(EmergencyAction {
            nonce: 1,
            chain_id: BridgeChainId::StarcoinCustom,
            action_type: crate::types::EmergencyActionType::Unpause,
        });
        let em_bytes2 = em_action2.as_bytes()?;
        let mut em_full2 = BRIDGE_MESSAGE_PREFIX.to_vec();
        em_full2.extend_from_slice(&em_bytes2);
        println!(
            "Message bytes (without prefix): {}",
            Hex::encode(&em_bytes2)
        );
        for (i, key) in keys.iter().enumerate() {
            let sig = key.sign_recoverable_with_hash::<Keccak256>(&em_full2);
            println!("Key {} sig: {}", i + 1, Hex::encode(sig.as_bytes()));
        }

        // Message 3: ETH nonce=1, amount=700 (for multiple-transfer tests)
        println!("\n=== Token Transfer Message 3 (ETH, nonce=1, amount=700) ===");
        let action3 = BridgeAction::EthToStarcoinBridgeAction(EthToStarcoinBridgeAction {
            eth_tx_hash: H256::zero(),
            eth_event_index: 0,
            eth_bridge_event: EthToStarcoinTokenBridgeV1 {
                nonce: 1,
                starcoin_bridge_chain_id: BridgeChainId::StarcoinCustom,
                eth_chain_id: BridgeChainId::EthCustom,
                starcoin_bridge_address: starcoin_addr,
                eth_address: eth_addr,
                token_id: 2, // ETH
                starcoin_bridge_adjusted_amount: 700,
            },
        });
        let msg_bytes3 = action3.as_bytes()?;
        let mut full_message3 = BRIDGE_MESSAGE_PREFIX.to_vec();
        full_message3.extend_from_slice(&msg_bytes3);
        println!(
            "Message bytes (without prefix): {}",
            Hex::encode(&msg_bytes3)
        );
        for (i, key) in keys.iter().enumerate() {
            let sig = key.sign_recoverable_with_hash::<Keccak256>(&full_message3);
            println!("Key {} sig: {}", i + 1, Hex::encode(sig.as_bytes()));
        }

        // Message 4: ETH nonce=0, amount=4_000_000_000 (for limit-exceeded tests)
        println!("\n=== Token Transfer Message 4 (ETH, nonce=0, amount=4000000000) ===");
        let action4 = BridgeAction::EthToStarcoinBridgeAction(EthToStarcoinBridgeAction {
            eth_tx_hash: H256::zero(),
            eth_event_index: 0,
            eth_bridge_event: EthToStarcoinTokenBridgeV1 {
                nonce: 0,
                starcoin_bridge_chain_id: BridgeChainId::StarcoinCustom,
                eth_chain_id: BridgeChainId::EthCustom,
                starcoin_bridge_address: starcoin_addr,
                eth_address: eth_addr,
                token_id: 2, // ETH
                starcoin_bridge_adjusted_amount: 4_000_000_000,
            },
        });
        let msg_bytes4 = action4.as_bytes()?;
        let mut full_message4 = BRIDGE_MESSAGE_PREFIX.to_vec();
        full_message4.extend_from_slice(&msg_bytes4);
        println!(
            "Message bytes (without prefix): {}",
            Hex::encode(&msg_bytes4)
        );
        for (i, key) in keys.iter().enumerate() {
            let sig = key.sign_recoverable_with_hash::<Keccak256>(&full_message4);
            println!("Key {} sig: {}", i + 1, Hex::encode(sig.as_bytes()));
        }

        Ok(())
    }

    /// Helper test to generate signatures for verify_signatures tests in Move
    /// These signatures are generated using STARCOIN_BRIDGE_MESSAGE prefix
    #[test]
    fn test_generate_verify_signatures_for_move_test() -> anyhow::Result<()> {
        use fastcrypto::hash::Keccak256;
        use fastcrypto::traits::{KeyPair, RecoverableSigner, ToFromBytes};

        // TEST_MSG from Move commitee_test.move
        let test_msg_hex = "00010a0000000000000000200000000000000000000000000000000000000000000000000000000000000064012000000000000000000000000000000000000000000000000000000000000000c8033930000000000000";
        let test_msg = Hex::decode(test_msg_hex).unwrap();

        // Add STARCOIN_BRIDGE_MESSAGE prefix
        let mut full_message = BRIDGE_MESSAGE_PREFIX.to_vec();
        full_message.extend_from_slice(&test_msg);

        println!("Test message with prefix: {}", Hex::encode(&full_message));

        // Try all keys and print signatures
        let keys = get_bridge_encoding_regression_test_keys();
        for (i, key) in keys.iter().enumerate() {
            let pubkey = key.public();
            let sig = key.sign_recoverable_with_hash::<Keccak256>(&full_message);
            println!("\nKey {}:", i + 1);
            println!("  Pubkey (compressed): {}", Hex::encode(pubkey.as_bytes()));
            println!("  Signature: {}", Hex::encode(sig.as_bytes()));
        }

        Ok(())
    }
}
