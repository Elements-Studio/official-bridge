// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::abi::EthToStarcoinTokenBridgeV1;
use crate::eth_mock_provider::EthMockProvider;
use crate::server::mock_handler::run_mock_server;
use crate::types::{
    BridgeCommittee, BridgeCommitteeValiditySignInfo, CertifiedBridgeAction,
    VerifiedCertifiedBridgeAction,
};
use crate::{
    crypto::{BridgeAuthorityKeyPair, BridgeAuthorityPublicKey, BridgeAuthoritySignInfo},
    events::EmittedStarcoinToEthTokenBridgeV1,
    server::mock_handler::BridgeRequestMockHandler,
    types::{
        BridgeAction, BridgeAuthority, EthToStarcoinBridgeAction, SignedBridgeAction,
        StarcoinToEthBridgeAction,
    },
};
use ethers::abi::{long_signature, ParamType};
use ethers::types::Address as EthAddress;
use ethers::types::{
    Block, BlockNumber, Filter, FilterBlockOption, Log, TransactionReceipt, TxHash, ValueOrArray,
    U64,
};
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::traits::KeyPair;
use fastcrypto::traits::ToFromBytes;
use hex_literal::hex;

use starcoin_bridge_config::local_ip_utils;
use starcoin_bridge_json_rpc_types::StarcoinEvent;
use starcoin_bridge_types::base_types::{SequenceNumber, StarcoinAddress, TransactionDigest};
use starcoin_bridge_types::bridge::{
    BridgeChainId, BridgeCommitteeSummary, MoveTypeCommitteeMember, TOKEN_ID_USDT,
};
use starcoin_bridge_types::crypto::get_key_pair;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use tokio::task::JoinHandle;

// Testing helper extensions - publicly export for use in test modules
pub trait StarcoinAddressTestExt {
    fn random_for_testing_only() -> Self;
}

impl StarcoinAddressTestExt for StarcoinAddress {
    fn random_for_testing_only() -> Self {
        use move_core_types::account_address::AccountAddress;
        AccountAddress::random()
    }
}

pub trait TransactionDigestTestExt {
    fn random() -> Self;
}

impl TransactionDigestTestExt for TransactionDigest {
    fn random() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let bytes: [u8; 32] = rng.gen();
        bytes // TransactionDigest is just [u8; 32]
    }
}

pub trait StarcoinEventTestExt {
    fn random_for_testing() -> Self;
}

impl StarcoinEventTestExt for StarcoinEvent {
    fn random_for_testing() -> Self {
        use rand::Rng;
        use starcoin_bridge_json_rpc_types::EventID;
        use std::str::FromStr;

        let mut rng = rand::thread_rng();
        let tx_digest: [u8; 32] = rng.gen();
        let event_seq: u64 = rng.gen_range(0..1000);
        let block_number: u64 = rng.gen_range(1..10000);

        StarcoinEvent {
            id: EventID {
                tx_digest,
                event_seq,
                block_number,
            },
            type_: move_core_types::language_storage::StructTag::from_str("0x1::test::TestEvent")
                .unwrap(),
            bcs: vec![],
            block_hash: None,
        }
    }
}

pub trait SequenceNumberTestExt {
    fn from_u64(value: u64) -> Self;
}

impl SequenceNumberTestExt for SequenceNumber {
    fn from_u64(value: u64) -> Self {
        SequenceNumber::from(value)
    }
}

/// Stub type for WalletContext - used in test helpers
pub struct WalletContext;

// WalletContext testing helpers - stub implementations
pub trait WalletContextTestExt {
    async fn get_reference_gas_price(&mut self) -> Result<u64, anyhow::Error>;
    fn active_address(&mut self) -> Result<StarcoinAddress, anyhow::Error>;
    async fn execute_transaction_must_succeed(
        &mut self,
        tx: starcoin_bridge_types::transaction::Transaction,
    ) -> starcoin_bridge_json_rpc_types::StarcoinTransactionBlockResponse;
}

impl WalletContextTestExt for WalletContext {
    async fn get_reference_gas_price(&mut self) -> Result<u64, anyhow::Error> {
        Ok(1000) // Dummy gas price
    }

    fn active_address(&mut self) -> Result<StarcoinAddress, anyhow::Error> {
        Ok(StarcoinAddress::random_for_testing_only())
    }

    async fn execute_transaction_must_succeed(
        &mut self,
        _tx: starcoin_bridge_types::transaction::Transaction,
    ) -> starcoin_bridge_json_rpc_types::StarcoinTransactionBlockResponse {
        unimplemented!("execute_transaction_must_succeed is not implemented for testing")
    }
}

pub fn get_test_authority_and_key(
    voting_power: u64,
    port: u16,
) -> (
    BridgeAuthority,
    BridgeAuthorityPublicKey,
    BridgeAuthorityKeyPair,
) {
    let (_, kp): (_, fastcrypto::secp256k1::Secp256k1KeyPair) = get_key_pair();
    let pubkey = kp.public().clone();
    let authority = BridgeAuthority {
        starcoin_bridge_address: StarcoinAddress::random_for_testing_only(),
        pubkey: pubkey.clone(),
        voting_power,
        base_url: format!("http://127.0.0.1:{}", port),
        is_blocklisted: false,
    };

    (authority, pubkey, kp)
}

// TODO: make a builder for this
pub fn get_test_starcoin_bridge_to_eth_bridge_action(
    starcoin_bridge_tx_digest: Option<TransactionDigest>,
    starcoin_bridge_tx_event_index: Option<u16>,
    nonce: Option<u64>,
    amount_starcoin_bridge_adjusted: Option<u64>,
    sender_address: Option<StarcoinAddress>,
    recipient_address: Option<EthAddress>,
    token_id: Option<u8>,
) -> BridgeAction {
    BridgeAction::StarcoinToEthBridgeAction(StarcoinToEthBridgeAction {
        starcoin_bridge_tx_digest: starcoin_bridge_tx_digest
            .unwrap_or_else(TransactionDigest::random),
        starcoin_bridge_tx_event_index: starcoin_bridge_tx_event_index.unwrap_or(0),
        starcoin_bridge_event: EmittedStarcoinToEthTokenBridgeV1 {
            nonce: nonce.unwrap_or_default(),
            starcoin_bridge_chain_id: BridgeChainId::StarcoinCustom,
            starcoin_bridge_address: sender_address
                .unwrap_or_else(StarcoinAddress::random_for_testing_only),
            eth_chain_id: BridgeChainId::EthCustom,
            eth_address: recipient_address.unwrap_or_else(EthAddress::random),
            token_id: token_id.unwrap_or(TOKEN_ID_USDT),
            amount_starcoin_bridge_adjusted: amount_starcoin_bridge_adjusted.unwrap_or(100_000),
        },
    })
}

pub fn get_test_eth_to_starcoin_bridge_action(
    nonce: Option<u64>,
    amount: Option<u64>,
    starcoin_bridge_address: Option<StarcoinAddress>,
    token_id: Option<u8>,
) -> BridgeAction {
    BridgeAction::EthToStarcoinBridgeAction(EthToStarcoinBridgeAction {
        eth_tx_hash: TxHash::random(),
        eth_event_index: 0,
        eth_bridge_event: EthToStarcoinTokenBridgeV1 {
            eth_chain_id: BridgeChainId::EthCustom,
            nonce: nonce.unwrap_or_default(),
            starcoin_bridge_chain_id: BridgeChainId::StarcoinCustom,
            token_id: token_id.unwrap_or(TOKEN_ID_USDT),
            starcoin_bridge_adjusted_amount: amount.unwrap_or(100_000),
            starcoin_bridge_address: starcoin_bridge_address
                .unwrap_or_else(StarcoinAddress::random_for_testing_only),
            eth_address: EthAddress::random(),
        },
    })
}

pub fn run_mock_bridge_server(
    mock_handlers: Vec<BridgeRequestMockHandler>,
) -> (Vec<JoinHandle<()>>, Vec<u16>) {
    let mut handles = vec![];
    let mut ports = vec![];
    for mock_handler in mock_handlers {
        let localhost = local_ip_utils::localhost_for_testing();
        let port = local_ip_utils::get_available_port(&localhost);
        // start server
        let server_handle = run_mock_server(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
            mock_handler.clone(),
        );
        ports.push(port);
        handles.push(server_handle);
    }
    (handles, ports)
}

pub fn get_test_authorities_and_run_mock_bridge_server(
    voting_power: Vec<u64>,
    mock_handlers: Vec<BridgeRequestMockHandler>,
) -> (
    Vec<JoinHandle<()>>,
    Vec<BridgeAuthority>,
    Vec<BridgeAuthorityKeyPair>,
) {
    assert_eq!(voting_power.len(), mock_handlers.len());
    let (handles, ports) = run_mock_bridge_server(mock_handlers);
    let mut authorites = vec![];
    let mut secrets = vec![];
    for (port, vp) in ports.iter().zip(voting_power) {
        let (authority, _, secret) = get_test_authority_and_key(vp, *port);
        authorites.push(authority);
        secrets.push(secret);
    }

    (handles, authorites, secrets)
}

pub fn sign_action_with_key(
    action: &BridgeAction,
    secret: &BridgeAuthorityKeyPair,
) -> SignedBridgeAction {
    let sig = BridgeAuthoritySignInfo::new(action, secret);
    SignedBridgeAction::new_from_data_and_sig(action.clone(), sig)
}

pub fn mock_last_finalized_block(mock_provider: &EthMockProvider, block_number: u64) {
    let block = Block::<ethers::types::TxHash> {
        number: Some(U64::from(block_number)),
        ..Default::default()
    };
    mock_provider
        .add_response("eth_getBlockByNumber", ("finalized", false), block)
        .unwrap();
}

// Returns a test Log and corresponding BridgeAction
// Refernece: https://github.com/rust-ethereum/ethabi/blob/master/ethabi/src/event.rs#L192
pub fn get_test_log_and_action(
    contract_address: EthAddress,
    tx_hash: TxHash,
    event_index: u16,
) -> (Log, BridgeAction) {
    let token_id = 4u8; // TOKEN_ID_USDT - the only supported token
    let starcoin_bridge_adjusted_amount = 10000000u64;
    let source_address = EthAddress::random();
    let starcoin_bridge_address: StarcoinAddress = StarcoinAddress::random_for_testing_only();
    let target_address = Hex::decode(&starcoin_bridge_address.to_string()).unwrap();
    // Note: must use `encode` rather than `encode_packged`
    let encoded = ethers::abi::encode(&[
        // u8/u64 is encoded as u256 in abi standard
        ethers::abi::Token::Uint(ethers::types::U256::from(token_id)),
        ethers::abi::Token::Uint(ethers::types::U256::from(starcoin_bridge_adjusted_amount)),
        ethers::abi::Token::Address(source_address),
        ethers::abi::Token::Bytes(target_address.clone()),
    ]);
    let log = Log {
        address: contract_address,
        topics: vec![
            long_signature(
                "TokensDeposited",
                &[
                    ParamType::Uint(8),
                    ParamType::Uint(64),
                    ParamType::Uint(8),
                    ParamType::Uint(8),
                    ParamType::Uint(64),
                    ParamType::Address,
                    ParamType::Bytes,
                ],
            ),
            hex!("0000000000000000000000000000000000000000000000000000000000000001").into(), // chain id: starcoin testnet
            hex!("0000000000000000000000000000000000000000000000000000000000000010").into(), // nonce: 16
            hex!("000000000000000000000000000000000000000000000000000000000000000b").into(), // chain id: sepolia
        ],
        data: encoded.into(),
        block_hash: Some(TxHash::random()),
        block_number: Some(1.into()),
        transaction_hash: Some(tx_hash),
        log_index: Some(0.into()),
        ..Default::default()
    };
    let topic_1: [u8; 32] = log.topics[1].into();
    let topic_3: [u8; 32] = log.topics[3].into();

    let bridge_action = BridgeAction::EthToStarcoinBridgeAction(EthToStarcoinBridgeAction {
        eth_tx_hash: tx_hash,
        eth_event_index: event_index,
        eth_bridge_event: EthToStarcoinTokenBridgeV1 {
            eth_chain_id: BridgeChainId::try_from(topic_1[topic_1.len() - 1]).unwrap(),
            nonce: u64::from_be_bytes(log.topics[2].as_ref()[24..32].try_into().unwrap()),
            starcoin_bridge_chain_id: BridgeChainId::try_from(topic_3[topic_3.len() - 1]).unwrap(),
            token_id,
            starcoin_bridge_adjusted_amount,
            starcoin_bridge_address,
            eth_address: source_address,
        },
    });
    (log, bridge_action)
}

// Returns a VerifiedCertifiedBridgeAction with signatures from the given
// BridgeAction and BridgeAuthorityKeyPair
pub fn get_certified_action_with_validator_secrets(
    action: BridgeAction,
    secrets: &Vec<BridgeAuthorityKeyPair>,
) -> VerifiedCertifiedBridgeAction {
    let mut sigs = BTreeMap::new();
    for secret in secrets {
        let signed_action = sign_action_with_key(&action, secret);
        sigs.insert(secret.public().into(), signed_action.into_sig().signature);
    }
    let certified_action = CertifiedBridgeAction::new_from_data_and_sig(
        action,
        BridgeCommitteeValiditySignInfo { signatures: sigs },
    );
    VerifiedCertifiedBridgeAction::new_from_verified(certified_action)
}

pub fn bridge_committee_to_bridge_committee_summary(
    committee: BridgeCommittee,
) -> BridgeCommitteeSummary {
    BridgeCommitteeSummary {
        members: committee
            .members()
            .iter()
            .map(|(k, v)| {
                let bytes = k.as_bytes().to_vec();
                (
                    bytes.clone(),
                    MoveTypeCommitteeMember {
                        starcoin_bridge_address: StarcoinAddress::random_for_testing_only(),
                        bridge_pubkey_bytes: bytes,
                        voting_power: v.voting_power,
                        http_rest_url: v.base_url.as_bytes().to_vec(),
                        blocklisted: v.is_blocklisted,
                    },
                )
            })
            .collect(),
        member_registration: vec![],
        last_committee_update_epoch: 0,
    }
}
