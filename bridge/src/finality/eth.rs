// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! ETH finality checker implementation

use async_trait::async_trait;
use ethers::providers::{JsonRpcClient, Middleware, Provider};
use ethers::types::Block;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::checker::{FinalityChecker, FinalityError, FinalityResult};
use super::config::{FinalityConfig, FinalityMode};

/// Cache entry for finalized block
#[derive(Debug)]
struct FinalizedBlockCache {
    block_number: u64,
    cached_at: std::time::Instant,
}

/// ETH finality checker
///
/// Supports two modes:
/// - Native mode: Uses ETH's 'finalized' block tag (production)
/// - Block counting mode: Uses `latest - confirmation_blocks` (local testing)
#[derive(Debug)]
pub struct EthFinalityChecker<P> {
    provider: Arc<Provider<P>>,
    config: FinalityConfig,
    chain_name: String,
    /// Cache for finalized block to reduce RPC calls
    cache: Arc<RwLock<Option<FinalizedBlockCache>>>,
}

impl<P> EthFinalityChecker<P>
where
    P: JsonRpcClient + 'static,
{
    /// Create a new ETH finality checker with default config
    pub fn new(provider: Arc<Provider<P>>, chain_name: impl Into<String>) -> Self {
        Self::with_config(provider, chain_name, FinalityConfig::eth_mainnet())
    }

    /// Create a new ETH finality checker with custom config
    pub fn with_config(
        provider: Arc<Provider<P>>,
        chain_name: impl Into<String>,
        config: FinalityConfig,
    ) -> Self {
        Self {
            provider,
            config,
            chain_name: chain_name.into(),
            cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Get configuration
    pub fn config(&self) -> &FinalityConfig {
        &self.config
    }

    /// Check if cache is still valid
    async fn get_cached_finalized_block(&self) -> Option<u64> {
        let cache = self.cache.read().await;
        if let Some(entry) = cache.as_ref() {
            if entry.cached_at.elapsed().as_secs() < self.config.cache_duration_secs {
                return Some(entry.block_number);
            }
        }
        None
    }

    /// Update cache
    async fn update_cache(&self, block_number: u64) {
        let mut cache = self.cache.write().await;
        *cache = Some(FinalizedBlockCache {
            block_number,
            cached_at: std::time::Instant::now(),
        });
    }

    /// Invalidate the finalized block cache
    /// Useful for testing or when the underlying chain state has changed
    pub async fn invalidate_cache(&self) {
        let mut cache = self.cache.write().await;
        *cache = None;
    }

    /// Fetch finalized block using native 'finalized' tag
    async fn fetch_native_finalized_block(&self) -> FinalityResult<u64> {
        debug!(
            "[{}] Fetching finalized block using native 'finalized' tag",
            self.chain_name
        );

        let block: Option<Block<ethers::types::TxHash>> = self
            .provider
            .request("eth_getBlockByNumber", ("finalized", false))
            .await
            .map_err(|e| {
                warn!("[{}] Failed to get finalized block: {}", self.chain_name, e);
                FinalityError::Rpc(format!("Failed to get finalized block: {}", e))
            })?;

        let block = block.ok_or_else(|| {
            warn!(
                "[{}] Provider returned empty finalized block",
                self.chain_name
            );
            FinalityError::Provider("Provider failed to return finalized block".into())
        })?;

        let block_num = block.number.map(|n| n.as_u64()).ok_or_else(|| {
            warn!("[{}] Finalized block has no number", self.chain_name);
            FinalityError::Provider("Finalized block has no number".into())
        })?;

        debug!(
            "[{}] Native finalized block: {}",
            self.chain_name, block_num
        );
        Ok(block_num)
    }

    /// Fetch finalized block using block counting (latest - confirmation_blocks)
    async fn fetch_counting_finalized_block(&self) -> FinalityResult<u64> {
        let latest = self.get_latest_block().await?;
        let finalized = latest.saturating_sub(self.config.confirmation_blocks);
        debug!(
            "[{}] Block counting finalized: latest={}, confirmations={}, finalized={}",
            self.chain_name, latest, self.config.confirmation_blocks, finalized
        );
        Ok(finalized)
    }
}

#[async_trait]
impl<P> FinalityChecker for EthFinalityChecker<P>
where
    P: JsonRpcClient + 'static,
{
    async fn is_finalized(&self, block_number: u64) -> FinalityResult<bool> {
        let finalized = self.get_finalized_block().await?;
        let is_final = block_number <= finalized;
        debug!(
            "[{}] is_finalized check: block={}, finalized={}, result={}",
            self.chain_name, block_number, finalized, is_final
        );
        Ok(is_final)
    }

    async fn get_finalized_block(&self) -> FinalityResult<u64> {
        // Check cache first
        if let Some(cached) = self.get_cached_finalized_block().await {
            debug!(
                "[{}] Using cached finalized block: {}",
                self.chain_name, cached
            );
            return Ok(cached);
        }

        // Fetch based on mode
        debug!(
            "[{}] Fetching finalized block, mode={:?}",
            self.chain_name, self.config.mode
        );

        let block = match self.config.mode {
            FinalityMode::Native => self.fetch_native_finalized_block().await?,
            FinalityMode::BlockCounting => self.fetch_counting_finalized_block().await?,
        };

        // Update cache
        self.update_cache(block).await;
        info!(
            "[{}] Finalized block updated: {} (mode={:?})",
            self.chain_name, block, self.config.mode
        );

        Ok(block)
    }

    async fn get_latest_block(&self) -> FinalityResult<u64> {
        let block_number = self
            .provider
            .get_block_number()
            .await
            .map_err(|e| FinalityError::Rpc(format!("Failed to get latest block: {}", e)))?;

        Ok(block_number.as_u64())
    }

    fn confirmation_blocks(&self) -> u64 {
        self.config.confirmation_blocks
    }

    fn uses_native_finality(&self) -> bool {
        self.config.mode == FinalityMode::Native
    }

    fn chain_name(&self) -> &str {
        &self.chain_name
    }
}
