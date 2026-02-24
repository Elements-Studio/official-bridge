// Starcoin Transaction Builder
// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::base_types::StarcoinAddress;
use crate::transaction::{ChainId, RawUserTransaction, ScriptFunction};
use crate::{Identifier, TypeTag};
use move_core_types::language_storage::ModuleId;

/// Bridge package address as StarcoinAddress (16 bytes)
/// This matches the Bridge address in stc-bridge-move/Move.toml: 0xf8eda27b31a0dcd9b6c06074d74a2c6c
pub fn bridge_module_address() -> StarcoinAddress {
    StarcoinAddress::new([
        0xf8, 0xed, 0xa2, 0x7b, 0x31, 0xa0, 0xdc, 0xd9, 0xb6, 0xc0, 0x60, 0x74, 0xd7, 0x4a, 0x2c,
        0x6c,
    ])
}

/// Default gas configuration for bridge transactions
pub struct GasConfig {
    pub max_gas_amount: u64,
    pub gas_unit_price: u64,
}

impl Default for GasConfig {
    fn default() -> Self {
        Self {
            max_gas_amount: 10_000_000, // 10M gas units
            gas_unit_price: 1,          // 1 nano STC per gas unit
        }
    }
}

/// Builder for Starcoin bridge transactions
pub struct StarcoinTransactionBuilder {
    sender: StarcoinAddress,
    sequence_number: u64,
    chain_id: ChainId,
    gas_config: GasConfig,
    expiration_secs: u64,
}

impl StarcoinTransactionBuilder {
    /// Create a new transaction builder
    pub fn new(sender: StarcoinAddress, sequence_number: u64, chain_id: u8) -> Self {
        Self {
            sender,
            sequence_number,
            chain_id: ChainId::new(chain_id),
            gas_config: GasConfig::default(),
            expiration_secs: 3600, // 1 hour default
        }
    }

    /// Set gas configuration
    pub fn with_gas(mut self, max_gas_amount: u64, gas_unit_price: u64) -> Self {
        self.gas_config = GasConfig {
            max_gas_amount,
            gas_unit_price,
        };
        self
    }

    /// Set expiration time in seconds from now
    pub fn with_expiration(mut self, expiration_secs: u64) -> Self {
        self.expiration_secs = expiration_secs;
        self
    }

    /// Build a script function call transaction
    pub fn build_script_function(
        &self,
        module_address: StarcoinAddress,
        module_name: &str,
        function_name: &str,
        type_args: Vec<TypeTag>,
        args: Vec<Vec<u8>>,
    ) -> Result<RawUserTransaction, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();

        let module_id = ModuleId::new(
            module_address,
            Identifier::new(module_name).map_err(|e| e.to_string())?,
        );

        let script_function = ScriptFunction::new(
            module_id,
            Identifier::new(function_name).map_err(|e| e.to_string())?,
            type_args,
            args,
        );

        Ok(RawUserTransaction::new_script_function(
            self.sender,
            self.sequence_number,
            script_function,
            self.gas_config.max_gas_amount,
            self.gas_config.gas_unit_price,
            now + self.expiration_secs,
            self.chain_id,
        ))
    }

    /// Build a bridge module call (convenience method)
    pub fn build_bridge_call(
        &self,
        module_name: &str,
        function_name: &str,
        type_args: Vec<TypeTag>,
        args: Vec<Vec<u8>>,
    ) -> Result<RawUserTransaction, String> {
        self.build_script_function(
            bridge_module_address(),
            module_name,
            function_name,
            type_args,
            args,
        )
    }
}

// =============================================================================
// Bridge-specific transaction builders
// =============================================================================

/// Build transaction for approving a token transfer
pub fn build_approve_token_transfer(
    sender: StarcoinAddress,
    sequence_number: u64,
    chain_id: u8,
    // Message parameters
    source_chain: u8,
    seq_num: u64,
    sender_bytes: Vec<u8>,
    target_chain: u8,
    target_bytes: Vec<u8>,
    token_type: u8,
    amount: u128,
    // Signatures
    signatures: Vec<Vec<u8>>,
) -> Result<RawUserTransaction, String> {
    let builder = StarcoinTransactionBuilder::new(sender, sequence_number, chain_id);

    // Serialize arguments using BCS
    let args = vec![
        bcs::to_bytes(&source_chain).map_err(|e| e.to_string())?,
        bcs::to_bytes(&seq_num).map_err(|e| e.to_string())?,
        bcs::to_bytes(&sender_bytes).map_err(|e| e.to_string())?,
        bcs::to_bytes(&target_chain).map_err(|e| e.to_string())?,
        bcs::to_bytes(&target_bytes).map_err(|e| e.to_string())?,
        bcs::to_bytes(&token_type).map_err(|e| e.to_string())?,
        bcs::to_bytes(&amount).map_err(|e| e.to_string())?,
        bcs::to_bytes(&signatures).map_err(|e| e.to_string())?,
    ];

    builder.build_bridge_call("Bridge", "approve_token_transfer", vec![], args)
}

/// Build transaction for sending tokens to another chain
/// This calls the specific send_bridge_* entry functions based on token type
pub fn build_send_token(
    sender: StarcoinAddress,
    sequence_number: u64,
    chain_id: u8,
    target_chain: u8,
    target_address: Vec<u8>,
    amount: u128,
    token_type_tag: TypeTag,
) -> Result<RawUserTransaction, String> {
    let builder = StarcoinTransactionBuilder::new(sender, sequence_number, chain_id);

    let args = vec![
        bcs::to_bytes(&target_chain).map_err(|e| e.to_string())?,
        bcs::to_bytes(&target_address).map_err(|e| e.to_string())?,
        bcs::to_bytes(&amount).map_err(|e| e.to_string())?,
    ];

    // Determine which entry function to call based on token type
    let function_name = match &token_type_tag {
        TypeTag::Struct(s) => match s.name.as_str() {
            "ETH" => "send_bridge_eth",
            "BTC" => "send_bridge_btc",
            "USDC" => "send_bridge_usdc",
            "USDT" => "send_bridge_usdt",
            _ => return Err(format!("Unsupported token type: {}", s.name)),
        },
        _ => return Err("Token type must be a struct".to_string()),
    };

    // The send_bridge_* functions don't take type parameters
    builder.build_bridge_call("Bridge", function_name, vec![], args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use move_core_types::account_address::AccountAddress;
    use move_core_types::identifier::Identifier;
    use move_core_types::language_storage::StructTag;

    #[test]
    fn test_build_send_token() {
        let sender = StarcoinAddress::ZERO;

        // Create a proper ETH token type tag
        let eth_type_tag = TypeTag::Struct(Box::new(StructTag {
            address: AccountAddress::from_hex_literal("0xf8eda27b31a0dcd9b6c06074d74a2c6c")
                .unwrap(),
            module: Identifier::new("ETH").unwrap(),
            name: Identifier::new("ETH").unwrap(),
            type_params: vec![],
        }));

        let result = build_send_token(
            sender,
            0,
            1,
            2,
            vec![0u8; 20], // ETH address
            1000000000,
            eth_type_tag,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_transaction_builder() {
        let sender = StarcoinAddress::ZERO;
        let builder = StarcoinTransactionBuilder::new(sender, 0, 1)
            .with_gas(5_000_000, 2)
            .with_expiration(7200);

        let result = builder.build_bridge_call("Bridge", "test_function", vec![], vec![]);
        assert!(result.is_ok());
    }
}
