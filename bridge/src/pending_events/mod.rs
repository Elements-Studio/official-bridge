// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pending Events Module
//!
//! Manages unfinalized cross-chain events in memory, providing:
//! - Memory-only storage for unfinalized events (no DB writes until finalized)
//! - Cross-chain transfer lifecycle tracking (deposit → approval → claim)
//! - Integration with FinalityChecker for finalization detection
//! - Key compromise detection via deposit/claim matching
//!
//! ## Design Principles
//!
//! 1. **Crash-safe by design**: No unfinalized data in DB means no dirty data on restart
//! 2. **Simple data structure**: BTreeMap for ordered access by block height
//! 3. **Lifecycle tracking**: Links deposit/approval/claim into unified transfer records
//! 4. **Security monitoring**: Load finalized deposits from DB for matching against claims
//!
//! ## Architecture
//!
//! ```text
//! Chain Events (latest)
//!        │
//!        ▼
//! ┌─────────────────────────────────────────────┐
//! │         PendingEventStore (Memory)          │
//! │                                             │
//! │  unfinalized_events: BTreeMap<block, Vec>   │
//! │  transfer_tracker: HashMap<nonce, Transfer> │
//! │  finalized_deposits: HashMap<nonce, Dep>    │ ← loaded from DB
//! └─────────────────────────────────────────────┘
//!        │
//!        │ on finality confirmed
//!        ▼
//! ┌─────────────────────────────────────────────┐
//! │  drain_finalized() → Write to DB            │
//! │  (is_finalized=true)                        │
//! └─────────────────────────────────────────────┘
//! ```

mod store;
mod tracker;
mod types;

pub use store::PendingEventStore;
pub use tracker::TransferTracker;
pub use types::*;
