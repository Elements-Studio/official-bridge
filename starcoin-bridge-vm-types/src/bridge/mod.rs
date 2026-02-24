// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Bridge-related modules organized in a submodule

#![allow(clippy::module_inception)]

// Infrastructure modules
pub mod base_types;
pub mod crypto;

// Bridge business logic modules
pub mod bridge;
pub mod collection_types;
pub mod committee;
pub mod message_envelope;

// Re-export main types for convenience
pub use bridge::BridgeSummary;
pub use message_envelope::{Envelope, VerifiedEnvelope};
