// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Ethereum-specific chain syncer implementation
//!
//! This module provides:
//! - `EthChainSyncer`: Main syncer implementation
//! - `EthChainSyncerBuilder`: Fluent API for building syncers
//! - `EthChainSyncerConfig`: ETH-specific configuration
//! - `EthSyncerContractConfig`: Contract monitoring configuration
//! - `EthSyncerCompatAdapter`: Compatibility layer for legacy code

mod config;
mod syncer;

pub use config::*;
pub use syncer::*;
