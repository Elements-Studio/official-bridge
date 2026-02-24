// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Bridge Monitor Module
//!
//! This module provides configuration and utilities for bridge monitoring.
//! The actual monitoring is now handled by the `security_monitor` module.

pub mod config;
pub mod emergency_pause;
pub mod events;
pub mod gap_recovery;
pub mod paired_transfer;
pub mod reorg_handler;
pub mod state;
pub mod telegram;
pub mod validator_health;

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "db-tests"))]
mod gap_recovery_tests;
