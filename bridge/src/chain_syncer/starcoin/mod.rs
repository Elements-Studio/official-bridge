// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Starcoin-specific chain syncer implementation
//!
//! This module provides:
//! - Starcoin-specific configuration
//! - Starcoin chain syncer implementation with DAG-aware finality
//! - Simple polling-based reorg detection
//! - Unfinalized transaction tracking with recovery query API

mod config;
mod syncer;

pub use config::*;
pub use syncer::*;
