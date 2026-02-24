// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Bridge VM Types - Standalone bridge type definitions
//!
//! This crate contains all the bridge-related type definitions that were previously
//! part of starcoin_vm_types. It's now independent and can be used by the bridge
//! as a standalone dapp.

// Re-export move types that bridge needs
pub use move_core_types::{
    account_address::AccountAddress as StarcoinAddress,
    ident_str,
    identifier::{IdentStr, Identifier},
    language_storage::{ModuleId, StructTag, TypeTag},
};

// Bridge modules
pub mod bridge;

// Re-export main types for convenience
pub use bridge::{
    base_types, bridge as bridge_types, collection_types, committee, crypto,
    message_envelope,
};
