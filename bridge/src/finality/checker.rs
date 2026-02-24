// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Core finality checker trait and types

use async_trait::async_trait;
use std::fmt::Debug;
use thiserror::Error;

/// Result type for finality operations
pub type FinalityResult<T> = Result<T, FinalityError>;

/// Errors that can occur during finality checking
#[derive(Debug, Error)]
pub enum FinalityError {
    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("Block not found: {0}")]
    BlockNotFound(u64),

    #[error("Transaction not found: {0}")]
    TxNotFound(String),

    #[error("Provider error: {0}")]
    Provider(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<anyhow::Error> for FinalityError {
    fn from(e: anyhow::Error) -> Self {
        FinalityError::Internal(e.to_string())
    }
}

/// Information about finality status
#[derive(Debug, Clone)]
pub struct FinalityStatus {
    /// Whether the block is considered finalized
    pub is_finalized: bool,
    /// The block number being checked
    pub block_number: u64,
    /// Current finalized block number
    pub finalized_block: u64,
    /// Current latest block number
    pub latest_block: u64,
    /// Number of confirmations (latest - block_number)
    pub confirmations: u64,
    /// Required confirmations for finality (in block counting mode)
    pub required_confirmations: u64,
}

/// Core trait for finality checking
///
/// Implementors provide chain-specific logic for determining when
/// blocks are considered finalized. The trait supports both:
/// - Native finality APIs (e.g., ETH's 'finalized' block tag)
/// - Block counting based finality (for local testing or chains without native finality)
#[async_trait]
pub trait FinalityChecker: Send + Sync + Debug {
    /// Check if a specific block number is finalized
    ///
    /// Returns `true` if the block is finalized, `false` otherwise.
    /// This is the primary method for finality checking.
    async fn is_finalized(&self, block_number: u64) -> FinalityResult<bool>;

    /// Get the current finalized block number
    ///
    /// For chains with native finality: returns the chain's finalized block
    /// For block counting mode: returns `latest_block - confirmation_blocks`
    async fn get_finalized_block(&self) -> FinalityResult<u64>;

    /// Get the latest block number
    async fn get_latest_block(&self) -> FinalityResult<u64>;

    /// Get the number of confirmation blocks required
    ///
    /// This is used for block counting mode finality.
    /// For native finality mode, this returns the configured value but may not be used.
    fn confirmation_blocks(&self) -> u64;

    /// Check if using native finality API or block counting
    fn uses_native_finality(&self) -> bool;

    /// Get detailed finality status for a block
    ///
    /// Provides comprehensive information about finality status,
    /// useful for debugging and monitoring.
    async fn get_finality_status(&self, block_number: u64) -> FinalityResult<FinalityStatus> {
        let finalized_block = self.get_finalized_block().await?;
        let latest_block = self.get_latest_block().await?;
        let confirmations = latest_block.saturating_sub(block_number);
        let is_finalized = block_number <= finalized_block;

        Ok(FinalityStatus {
            is_finalized,
            block_number,
            finalized_block,
            latest_block,
            confirmations,
            required_confirmations: self.confirmation_blocks(),
        })
    }

    /// Chain identifier for logging/metrics
    fn chain_name(&self) -> &str;
}
