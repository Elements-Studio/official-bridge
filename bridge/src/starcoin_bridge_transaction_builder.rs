// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Transaction builder for Starcoin Bridge.
//!
//! This module provides two sets of transaction building functions:
//!
//! 1. **Starcoin Native (recommended)**: Uses `RawUserTransaction` + `ScriptFunction`
//!    - Functions prefixed with `starcoin_` or in the `starcoin_native` module
//!    - Direct mapping to Starcoin's transaction model

use move_core_types::language_storage::ModuleId;
use starcoin_bridge_types::{
    base_types::StarcoinAddress,
    transaction::{ChainId, RawUserTransaction, ScriptFunction},
    Identifier, TypeTag,
};

use crate::error::{BridgeError, BridgeResult};

// =============================================================================
// Starcoin Native Transaction Builders
// =============================================================================

/// Bridge module address as StarcoinAddress (16 bytes)
/// This matches the Bridge address in stc-bridge-move/Move.toml: 0xf8eda27b31a0dcd9b6c06074d74a2c6c
pub fn bridge_module_address() -> StarcoinAddress {
    StarcoinAddress::new([
        0xf8, 0xed, 0xa2, 0x7b, 0x31, 0xa0, 0xdc, 0xd9, 0xb6, 0xc0, 0x60, 0x74, 0xd7, 0x4a, 0x2c,
        0x6c,
    ])
}

/// Create token bridge message bytes for Starcoin approve_token_transfer
/// This creates the BCS-serialized message that the Move contract expects
pub fn create_token_bridge_message_bytes(
    source_chain: u8,
    seq_num: u64,
    sender: Vec<u8>,
    target_chain: u8,
    target: Vec<u8>,
    token_type: u8,
    amount: u64,
) -> Vec<u8> {
    // The message format expected by Move:
    // struct TokenTransferMessage {
    //     message_version: u8,  // always 1
    //     seq_num: u64,
    //     source_chain: u8,
    //     sender: vector<u8>,
    //     target_chain: u8,
    //     target: vector<u8>,
    //     token_type: u8,
    //     amount: u64,
    // }
    let mut msg = Vec::new();
    msg.push(1u8); // message_version
    msg.extend_from_slice(&seq_num.to_le_bytes());
    msg.push(source_chain);
    // sender as length-prefixed bytes
    msg.push(sender.len() as u8);
    msg.extend_from_slice(&sender);
    msg.push(target_chain);
    // target as length-prefixed bytes
    msg.push(target.len() as u8);
    msg.extend_from_slice(&target);
    msg.push(token_type);
    msg.extend_from_slice(&amount.to_le_bytes());
    msg
}

/// Transaction builder for Starcoin bridge operations
pub struct StarcoinBridgeTransactionBuilder;

impl StarcoinBridgeTransactionBuilder {
    /// Build a claim and transfer transaction
    /// After approve succeeds, this transfers tokens to the recipient
    pub fn build_claim_and_transfer(
        module_address: StarcoinAddress,
        sender: StarcoinAddress,
        sequence_number: u64,
        chain_id: u8,
        block_timestamp_ms: u64,
        clock_timestamp_ms: u64,
        source_chain: u8,
        seq_num: u64,
        token_id: u8,
    ) -> BridgeResult<starcoin_bridge_types::transaction::RawUserTransaction> {
        starcoin_native::build_claim_and_transfer(
            module_address,
            sender,
            sequence_number,
            chain_id,
            block_timestamp_ms,
            clock_timestamp_ms,
            source_chain,
            seq_num,
            token_id,
        )
    }
}

/// Build a Starcoin native transaction for bridge operations
pub mod starcoin_native {
    use super::*;

    /// Calculate expiration timestamp for Starcoin transactions based on current block timestamp
    ///
    /// # Arguments
    /// * `block_timestamp_ms` - Current block timestamp in milliseconds from chain
    ///
    /// Returns the expiration timestamp in **seconds** (current + 1 hour)
    /// Note: Starcoin's RawUserTransaction expects expiration_timestamp_secs in seconds
    fn calculate_expiration_from_block(block_timestamp_ms: u64) -> u64 {
        // Convert milliseconds to seconds, then add 1 hour (3600 seconds)
        // Starcoin's RawUserTransaction.expiration_timestamp_secs expects seconds
        let current_secs = block_timestamp_ms / 1000;
        current_secs.saturating_add(3_600)
    }

    /// Build a RawUserTransaction for approving token transfer
    /// Uses the script function `approve_bridge_token_transfer_single` for single signature
    /// or `approve_bridge_token_transfer_two`/`approve_bridge_token_transfer_three` for multiple signatures
    ///
    /// # Arguments
    /// * `module_address` - The address where the bridge module is deployed
    /// * `sender` - The sender address
    /// * `sequence_number` - The transaction sequence number
    /// * `chain_id` - The Starcoin chain ID
    /// * `block_timestamp_ms` - Current block timestamp in milliseconds (from chain.info)
    /// * `source_chain` - Source chain ID (e.g., ETH chain ID)
    /// * `seq_num` - Bridge sequence number
    /// * `sender_address` - Original sender address on source chain
    /// * `target_chain` - Target chain ID (Starcoin chain ID)
    /// * `target_address` - Target address on Starcoin
    /// * `token_type` - Token type ID
    /// * `amount` - Amount to transfer
    /// * `signatures` - The aggregated signatures (1-3 signatures supported)
    pub fn build_approve_token_transfer(
        module_address: StarcoinAddress,
        sender: StarcoinAddress,
        sequence_number: u64,
        chain_id: u8,
        block_timestamp_ms: u64,
        // Message parameters
        source_chain: u8,
        seq_num: u64,
        sender_address: Vec<u8>,
        target_chain: u8,
        target_address: Vec<u8>,
        token_type: u8,
        amount: u64,
        signatures: Vec<Vec<u8>>,
    ) -> BridgeResult<RawUserTransaction> {
        let module_id = ModuleId::new(
            module_address,
            Identifier::new("Bridge").map_err(|e| BridgeError::Generic(e.to_string()))?,
        );

        // Choose function based on number of signatures
        let (function_name, args) = match signatures.len() {
            1 => (
                "approve_bridge_token_transfer_single",
                vec![
                    bcs::to_bytes(&source_chain)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&seq_num)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&sender_address)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&target_chain)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&target_address)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&token_type)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&amount)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&signatures[0])
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                ],
            ),
            2 => (
                "approve_bridge_token_transfer_two",
                vec![
                    bcs::to_bytes(&source_chain)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&seq_num)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&sender_address)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&target_chain)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&target_address)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&token_type)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&amount)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&signatures[0])
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&signatures[1])
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                ],
            ),
            3 => (
                "approve_bridge_token_transfer_three",
                vec![
                    bcs::to_bytes(&source_chain)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&seq_num)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&sender_address)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&target_chain)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&target_address)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&token_type)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&amount)
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&signatures[0])
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&signatures[1])
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                    bcs::to_bytes(&signatures[2])
                        .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                ],
            ),
            n => {
                return Err(BridgeError::Generic(format!(
                    "Unsupported number of signatures: {}. Only 1-3 signatures are supported.",
                    n
                )))
            }
        };

        let script_function = ScriptFunction::new(
            module_id,
            Identifier::new(function_name).map_err(|e| BridgeError::Generic(e.to_string()))?,
            vec![],
            args,
        );

        Ok(RawUserTransaction::new_script_function(
            sender,
            sequence_number,
            script_function,
            10_000_000, // max_gas_amount
            1,          // gas_unit_price
            calculate_expiration_from_block(block_timestamp_ms),
            ChainId::new(chain_id),
        ))
    }

    /// Build a RawUserTransaction for claiming and transferring tokens
    ///
    /// # Arguments
    /// * `module_address` - The address where the bridge module is deployed
    /// * `sender` - The sender address
    /// * `sequence_number` - The transaction sequence number
    /// * `chain_id` - The Starcoin chain ID
    /// * `block_timestamp_ms` - Current block timestamp in milliseconds (from chain.info)
    /// * `clock_timestamp_ms` - Clock timestamp for the claim operation
    /// * `source_chain` - Source chain ID
    /// * `seq_num` - Bridge sequence number
    /// * `token_id` - Token ID (1=BTC, 2=ETH, 3=USDC, 4=USDT)
    pub fn build_claim_and_transfer(
        module_address: StarcoinAddress,
        sender: StarcoinAddress,
        sequence_number: u64,
        chain_id: u8,
        block_timestamp_ms: u64,
        clock_timestamp_ms: u64,
        source_chain: u8,
        seq_num: u64,
        token_id: u8,
    ) -> BridgeResult<RawUserTransaction> {
        let module_id = ModuleId::new(
            module_address,
            Identifier::new("Bridge").map_err(|e| BridgeError::Generic(e.to_string()))?,
        );

        // Choose function based on token ID
        let function_name = match token_id {
            1 => "claim_bridge_btc",
            2 => "claim_bridge_eth",
            3 => "claim_bridge_usdc",
            4 => "claim_bridge_usdt",
            _ => return Err(BridgeError::UnknownTokenId(token_id)),
        };

        let script_function = ScriptFunction::new(
            module_id,
            Identifier::new(function_name).map_err(|e| BridgeError::Generic(e.to_string()))?,
            vec![],
            vec![
                bcs::to_bytes(&clock_timestamp_ms)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&source_chain)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&seq_num)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
            ],
        );

        Ok(RawUserTransaction::new_script_function(
            sender,
            sequence_number,
            script_function,
            10_000_000,
            1,
            calculate_expiration_from_block(block_timestamp_ms),
            ChainId::new(chain_id),
        ))
    }

    /// Build a RawUserTransaction for executing emergency operations
    ///
    /// # Arguments
    /// * `module_address` - The address where the bridge module is deployed
    /// * `sender` - The sender address
    /// * `sequence_number` - The transaction sequence number
    /// * `chain_id` - The Starcoin chain ID
    /// * `block_timestamp_ms` - Current block timestamp in milliseconds (from chain.info)
    /// * `source_chain` - Source chain ID
    /// * `seq_num` - Bridge sequence number
    /// * `op_type` - Emergency operation type
    /// * `signature` - The signature for the operation
    pub fn build_execute_emergency_op(
        module_address: StarcoinAddress,
        sender: StarcoinAddress,
        sequence_number: u64,
        chain_id: u8,
        block_timestamp_ms: u64,
        source_chain: u8,
        seq_num: u64,
        op_type: u8,
        signature: Vec<u8>,
    ) -> BridgeResult<RawUserTransaction> {
        let module_id = ModuleId::new(
            module_address,
            Identifier::new("Bridge").map_err(|e| BridgeError::Generic(e.to_string()))?,
        );

        let script_function = ScriptFunction::new(
            module_id,
            Identifier::new("execute_emergency_op_single")
                .map_err(|e| BridgeError::Generic(e.to_string()))?,
            vec![],
            vec![
                bcs::to_bytes(&source_chain)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&seq_num)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&op_type)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&signature)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
            ],
        );

        Ok(RawUserTransaction::new_script_function(
            sender,
            sequence_number,
            script_function,
            10_000_000,
            1,
            calculate_expiration_from_block(block_timestamp_ms),
            ChainId::new(chain_id),
        ))
    }

    /// Build a RawUserTransaction for **permissionless** emergency operations.
    ///
    /// Unlike `build_execute_emergency_op` (which calls `execute_emergency_op_single`
    /// and requires the sender to be the bridge admin), this calls
    /// `execute_emergency_op_permissionless` which allows **any funded account** to
    /// submit a pre-signed emergency pause/unpause.  Security is enforced by
    /// committee signature verification inside the Move contract.
    ///
    /// # Arguments
    /// * `module_address` - The address where the bridge module is deployed
    /// * `sender` - The sender address (any funded account, pays gas)
    /// * `sequence_number` - The transaction sequence number
    /// * `chain_id` - The Starcoin chain ID
    /// * `block_timestamp_ms` - Current block timestamp in milliseconds
    /// * `source_chain` - Source chain ID
    /// * `seq_num` - Bridge sequence number
    /// * `op_type` - Emergency operation type
    /// * `signature` - The committee signature for the operation
    pub fn build_execute_emergency_op_permissionless(
        module_address: StarcoinAddress,
        sender: StarcoinAddress,
        sequence_number: u64,
        chain_id: u8,
        block_timestamp_ms: u64,
        source_chain: u8,
        seq_num: u64,
        op_type: u8,
        signature: Vec<u8>,
    ) -> BridgeResult<RawUserTransaction> {
        let module_id = ModuleId::new(
            module_address,
            Identifier::new("Bridge").map_err(|e| BridgeError::Generic(e.to_string()))?,
        );

        let script_function = ScriptFunction::new(
            module_id,
            Identifier::new("execute_emergency_op_permissionless")
                .map_err(|e| BridgeError::Generic(e.to_string()))?,
            vec![],
            vec![
                bcs::to_bytes(&source_chain)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&seq_num)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&op_type)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&signature)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
            ],
        );

        Ok(RawUserTransaction::new_script_function(
            sender,
            sequence_number,
            script_function,
            10_000_000,
            1,
            calculate_expiration_from_block(block_timestamp_ms),
            ChainId::new(chain_id),
        ))
    }

    /// Build a RawUserTransaction for updating bridge transfer limit
    ///
    /// # Arguments
    /// * `module_address` - The address where the bridge module is deployed
    /// * `sender` - The sender address
    /// * `sequence_number` - The transaction sequence number
    /// * `chain_id` - The Starcoin chain ID
    /// * `block_timestamp_ms` - Current block timestamp in milliseconds (from chain.info)
    /// * `source_chain` - Source chain ID (which chain this limit applies to)
    /// * `sending_chain` - The sending chain ID
    /// * `seq_num` - Bridge sequence number (nonce)
    /// * `new_usd_limit` - New USD limit in cents
    /// * `signature` - The signature for the operation
    pub fn build_execute_update_limit(
        module_address: StarcoinAddress,
        sender: StarcoinAddress,
        sequence_number: u64,
        chain_id: u8,
        block_timestamp_ms: u64,
        source_chain: u8,
        sending_chain: u8,
        seq_num: u64,
        new_usd_limit: u64,
        signature: Vec<u8>,
    ) -> BridgeResult<RawUserTransaction> {
        let module_id = ModuleId::new(
            module_address,
            Identifier::new("Bridge").map_err(|e| BridgeError::Generic(e.to_string()))?,
        );

        // Move function signature: execute_update_limit_single(
        //     bridge_admin: signer,
        //     receiving_chain: u8,
        //     seq_num: u64,
        //     sending_chain: u8,
        //     new_limit: u64,
        //     signature: vector<u8>,
        // )
        let script_function = ScriptFunction::new(
            module_id,
            Identifier::new("execute_update_limit_single")
                .map_err(|e| BridgeError::Generic(e.to_string()))?,
            vec![],
            vec![
                bcs::to_bytes(&source_chain)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&seq_num)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&sending_chain)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&new_usd_limit)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&signature)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
            ],
        );

        Ok(RawUserTransaction::new_script_function(
            sender,
            sequence_number,
            script_function,
            10_000_000,
            1,
            calculate_expiration_from_block(block_timestamp_ms),
            ChainId::new(chain_id),
        ))
    }

    /// Build a RawUserTransaction for updating committee blocklist
    ///
    /// # Arguments
    /// * `module_address` - The address where the bridge module is deployed
    /// * `sender` - The sender address
    /// * `sequence_number` - The transaction sequence number
    /// * `chain_id` - The Starcoin chain ID
    /// * `block_timestamp_ms` - Current block timestamp in milliseconds (from chain.info)
    /// * `source_chain` - Source chain ID
    /// * `seq_num` - Bridge sequence number (nonce)
    /// * `blocklist_type` - 0 for blocklist, 1 for unblocklist
    /// * `member_pubkeys` - List of committee member public keys to blocklist/unblocklist
    /// * `signature` - The signature for the operation
    pub fn build_execute_blocklist(
        module_address: StarcoinAddress,
        sender: StarcoinAddress,
        sequence_number: u64,
        chain_id: u8,
        block_timestamp_ms: u64,
        source_chain: u8,
        seq_num: u64,
        blocklist_type: u8,
        member_pubkeys: Vec<Vec<u8>>,
        signature: Vec<u8>,
    ) -> BridgeResult<RawUserTransaction> {
        let module_id = ModuleId::new(
            module_address,
            Identifier::new("Bridge").map_err(|e| BridgeError::Generic(e.to_string()))?,
        );

        let script_function = ScriptFunction::new(
            module_id,
            Identifier::new("execute_blocklist_single")
                .map_err(|e| BridgeError::Generic(e.to_string()))?,
            vec![],
            vec![
                bcs::to_bytes(&source_chain)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&seq_num)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&blocklist_type)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&member_pubkeys)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&signature)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
            ],
        );

        Ok(RawUserTransaction::new_script_function(
            sender,
            sequence_number,
            script_function,
            10_000_000,
            1,
            calculate_expiration_from_block(block_timestamp_ms),
            ChainId::new(chain_id),
        ))
    }

    /// Build a RawUserTransaction for updating committee member (add/remove)
    ///
    /// # Arguments
    /// * `module_address` - The address where the bridge module is deployed
    /// * `sender` - The sender address
    /// * `sequence_number` - The transaction sequence number
    /// * `chain_id` - The Starcoin chain ID
    /// * `block_timestamp_ms` - Current block timestamp in milliseconds (from chain.info)
    /// * `source_chain` - Source chain ID
    /// * `seq_num` - Bridge sequence number (nonce)
    /// * `update_type` - 0 for add, 1 for remove
    /// * `bridge_pubkey_bytes` - The bridge public key bytes (33-byte compressed ECDSA)
    /// * `voting_power` - The voting power of the member
    /// * `http_rest_url` - The HTTP REST URL of the member's node
    /// * `signature` - The signature for the operation
    pub fn build_execute_update_committee_member(
        module_address: StarcoinAddress,
        sender: StarcoinAddress,
        sequence_number: u64,
        chain_id: u8,
        block_timestamp_ms: u64,
        source_chain: u8,
        seq_num: u64,
        update_type: u8,
        member_address: StarcoinAddress,
        bridge_pubkey_bytes: Vec<u8>,
        voting_power: u64,
        http_rest_url: Vec<u8>,
        signature: Vec<u8>,
    ) -> BridgeResult<RawUserTransaction> {
        let module_id = ModuleId::new(
            module_address,
            Identifier::new("Bridge").map_err(|e| BridgeError::Generic(e.to_string()))?,
        );

        // Move function signature: execute_update_committee_member_single(
        //     bridge_admin: signer,
        //     source_chain: u8,
        //     seq_num: u64,
        //     update_type: u8,
        //     member_address: address,
        //     bridge_pubkey_bytes: vector<u8>,
        //     voting_power: u64,
        //     http_rest_url: vector<u8>,
        //     signature: vector<u8>,
        // )
        let script_function = ScriptFunction::new(
            module_id,
            Identifier::new("execute_update_committee_member_single")
                .map_err(|e| BridgeError::Generic(e.to_string()))?,
            vec![],
            vec![
                bcs::to_bytes(&source_chain)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&seq_num)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&update_type)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&member_address)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&bridge_pubkey_bytes)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&voting_power)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&http_rest_url)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&signature)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
            ],
        );

        Ok(RawUserTransaction::new_script_function(
            sender,
            sequence_number,
            script_function,
            10_000_000,
            1,
            calculate_expiration_from_block(block_timestamp_ms),
            ChainId::new(chain_id),
        ))
    }

    /// Build a RawUserTransaction for sending tokens to another chain (Starcoin -> ETH)
    ///
    /// # Arguments
    /// * `module_address` - The address where the bridge module is deployed
    /// * `sender` - The sender address
    /// * `sequence_number` - The transaction sequence number
    /// * `chain_id` - The Starcoin chain ID
    /// * `block_timestamp_ms` - Current block timestamp in milliseconds (from chain.info)
    /// * `target_chain` - Target chain ID
    /// * `target_address` - Target address on the target chain
    /// * `amount` - Amount to transfer
    /// * `token_type` - The token type tag
    pub fn build_send_token(
        module_address: StarcoinAddress,
        sender: StarcoinAddress,
        sequence_number: u64,
        chain_id: u8,
        block_timestamp_ms: u64,
        target_chain: u8,
        target_address: Vec<u8>,
        amount: u128,
        token_type: TypeTag,
    ) -> BridgeResult<RawUserTransaction> {
        let module_id = ModuleId::new(
            module_address,
            Identifier::new("Bridge").map_err(|e| BridgeError::Generic(e.to_string()))?,
        );

        // Determine function name based on token type
        // Token type is like: 0xADDR::ETH::ETH, we extract the module name
        let function_name = match &token_type {
            TypeTag::Struct(s) => {
                let module_name = s.module.as_str();
                match module_name {
                    "ETH" => "send_bridge_eth",
                    "BTC" => "send_bridge_btc",
                    "USDC" => "send_bridge_usdc",
                    "USDT" => "send_bridge_usdt",
                    _ => {
                        return Err(BridgeError::Generic(format!(
                            "Unsupported token type: {}",
                            module_name
                        )))
                    }
                }
            }
            _ => return Err(BridgeError::Generic("Expected struct type tag".to_string())),
        };

        let script_function = ScriptFunction::new(
            module_id,
            Identifier::new(function_name).map_err(|e| BridgeError::Generic(e.to_string()))?,
            vec![], // No type args needed, function is specific to token
            vec![
                bcs::to_bytes(&target_chain)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&target_address)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
                bcs::to_bytes(&amount)
                    .map_err(|e| BridgeError::BridgeSerializationError(e.to_string()))?,
            ],
        );

        Ok(RawUserTransaction::new_script_function(
            sender,
            sequence_number,
            script_function,
            10_000_000,
            1,
            calculate_expiration_from_block(block_timestamp_ms),
            ChainId::new(chain_id),
        ))
    }
}
