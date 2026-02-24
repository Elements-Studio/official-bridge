// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Chain Syncer Module
//!
//! A unified, configurable chain synchronization module that combines:
//! - Block/event synchronization
//! - Reorg detection
//! - Finality tracking
//!
//! ## Design Goals
//!
//! 1. **Separation of concerns**: Output events/actions instead of directly executing business logic
//! 2. **Configurable behavior**: Enable/disable features via configuration
//! 3. **Testability**: Easy to test without complex mocking
//! 4. **Chain agnostic**: Common interface for different chains (ETH, Starcoin)
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────────┐
//! │                         ChainSyncer                                   │
//! ├──────────────────────────────────────────────────────────────────────┤
//! │                                                                       │
//! │  ┌─────────────────┐   ┌─────────────────┐   ┌──────────────────┐   │
//! │  │  Block Fetcher  │   │  Reorg Detector │   │ Finality Tracker │   │
//! │  │                 │──▶│                 │──▶│                  │   │
//! │  │  - Pagination   │   │  - Window mgmt  │   │  - Confirm blocks│   │
//! │  │  - Retry logic  │   │  - Hash verify  │   │  - Mark finalized│   │
//! │  └─────────────────┘   └─────────────────┘   └──────────────────┘   │
//! │                                                                       │
//! │  Output: SyncerEvent (NewBlock, Reorg, Finalized, Error)             │
//! └──────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage Example
//!
//! ```ignore
//! use starcoin_bridge::chain_syncer::{EthChainSyncerBuilder, SyncerEvent};
//!
//! // Create syncer with builder pattern
//! let syncer = EthChainSyncerBuilder::new("eth", "http://localhost:8545")
//!     .with_contract("0x...", 1000)
//!     .with_reorg_detection(true)
//!     .build(eth_client)?;
//!
//! // Run and receive events
//! let (handles, mut events_rx) = syncer.run(cancel_token).await?;
//!
//! // Process events (business logic separated)
//! while let Some(event) = events_rx.recv().await {
//!     match event {
//!         SyncerEvent::NewLogs { logs, .. } => { /* process logs */ }
//!         SyncerEvent::Reorg(info) => { /* handle reorg */ }
//!         _ => {}
//!     }
//! }
//! ```

// Common types and utilities shared across all chains
pub mod common;

// Ethereum-specific implementation
mod eth;

// Starcoin-specific implementation
pub mod starcoin;

// Re-export common types
pub use common::*;

// Re-export chain-specific types
pub use eth::*;
pub use starcoin::*;
