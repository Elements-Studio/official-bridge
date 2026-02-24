// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Unified Finality Checking Module
//!
//! This module provides a unified interface for checking block/transaction finality
//! for Ethereum chain. It supports:
//!
//! 1. **Local testing mode**: Uses block counting (configurable confirmation blocks)
//! 2. **Production mode**: Uses native 'finalized' block tag
//!
//! ## Architecture
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────┐
//! │                    FinalityChecker (trait)                        │
//! ├───────────────────────────────────────────────────────────────────┤
//! │  + is_finalized(block_number) -> Result<bool>                     │
//! │  + get_finalized_block() -> Result<u64>                           │
//! │  + get_latest_block() -> Result<u64>                              │
//! │  + confirmation_blocks() -> u64                                   │
//! └───────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//!                    ┌─────────────────┐
//!                    │ EthFinality     │
//!                    │ Checker         │
//!                    ├─────────────────┤
//!                    │ - Native API    │
//!                    │   (production)  │
//!                    │ - Block count   │
//!                    │   (local test)  │
//!                    └─────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```ignore
//! // Production ETH (uses native finalized block)
//! let checker = EthFinalityChecker::new(provider, false, 64);
//!
//! // Local test ETH (uses block counting)
//! let checker = EthFinalityChecker::new(provider, true, 12);
//!
//! // Check if a block is finalized
//! let is_final = checker.is_finalized(block_number).await?;
//! ```

mod checker;
mod config;
mod eth;

pub use checker::{FinalityChecker, FinalityError, FinalityResult};
pub use config::{FinalityConfig, FinalityMode};
pub use eth::EthFinalityChecker;
