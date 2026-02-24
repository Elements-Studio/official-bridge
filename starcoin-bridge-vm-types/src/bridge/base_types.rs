// Base types for Starcoin Bridge
// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use move_core_types::language_storage::StructTag;
use serde::{Deserialize, Serialize};
use std::fmt;

// =============================================================================
// Core Starcoin Types
// =============================================================================

/// Re-export Starcoin address type (16 bytes)
pub use move_core_types::account_address::AccountAddress as StarcoinAddress;

/// Transaction digest (hash) - 32 bytes
pub type TransactionDigest = [u8; 32];

/// Authority name (public key bytes) - 32 bytes for Ed25519 public key
pub type AuthorityName = [u8; 32];

/// Sequence number for transaction ordering
pub type SequenceNumber = u64;

// =============================================================================
// Resource Path Types (Starcoin-native)
// =============================================================================

/// Resource identifier in Starcoin - points to a specific resource under an account
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ResourcePath {
    /// The account address that owns this resource
    pub address: StarcoinAddress,
    /// The type of the resource (module_address::module_name::StructName)
    pub resource_type: StructTag,
}

impl ResourcePath {
    pub fn new(address: StarcoinAddress, resource_type: StructTag) -> Self {
        Self {
            address,
            resource_type,
        }
    }
}

impl fmt::Display for ResourcePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.address, self.resource_type)
    }
}

/// Module reference - points to a Move module
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ModuleRef {
    pub address: StarcoinAddress,
    pub module: move_core_types::identifier::Identifier,
}

impl ModuleRef {
    pub fn new(address: StarcoinAddress, module: move_core_types::identifier::Identifier) -> Self {
        Self { address, module }
    }
}

// =============================================================================
// Display Traits
// =============================================================================

/// Trait for concise name display
pub trait ConciseableName<'a> {
    type ConciseTypeRef;
    type ConciseType;

    fn concise(&'a self) -> Self::ConciseTypeRef;
    fn concise_owned(&self) -> Self::ConciseType;
}

impl<'a> ConciseableName<'a> for StarcoinAddress {
    type ConciseTypeRef = &'a StarcoinAddress;
    type ConciseType = String;

    fn concise(&'a self) -> Self::ConciseTypeRef {
        self
    }

    fn concise_owned(&self) -> String {
        format!("0x{}", hex::encode(self.as_ref()))
    }
}

/// Trait for hex display
pub trait ToHex {
    fn to_hex(&self) -> String;
}

impl ToHex for [u8; 32] {
    fn to_hex(&self) -> String {
        hex::encode(self)
    }
}

impl ToHex for [u8; 16] {
    fn to_hex(&self) -> String {
        hex::encode(self)
    }
}

impl ToHex for StarcoinAddress {
    fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.as_ref()))
    }
}

// =============================================================================
// Conversion Utilities
// =============================================================================

/// Convert a 32-byte array to StarcoinAddress (takes last 16 bytes)
pub fn bytes32_to_starcoin_address(bytes: &[u8; 32]) -> StarcoinAddress {
    let addr_bytes: [u8; 16] = bytes[16..32].try_into().expect("slice is exactly 16 bytes");
    StarcoinAddress::new(addr_bytes)
}

/// Convert StarcoinAddress to a 32-byte array (left-padded with zeros)
pub fn starcoin_address_to_bytes32(addr: &StarcoinAddress) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[16..32].copy_from_slice(addr.as_ref());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_path() {
        use move_core_types::identifier::Identifier;

        let addr = StarcoinAddress::ZERO;
        let struct_tag = StructTag {
            address: addr,
            module: Identifier::new("bridge").unwrap(),
            name: Identifier::new("Bridge").unwrap(),
            type_params: vec![],
        };

        let path = ResourcePath::new(addr, struct_tag);
        assert_eq!(path.address, addr);
    }
}
