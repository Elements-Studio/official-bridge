// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! REST API for bridge indexer
//!
//! Provides endpoints for querying cross-chain transfer data:
//! - List transfers by account address
//! - Get transfer details by chain_id and nonce
//!
//! API queries combine data from:
//! - Database (finalized events)
//! - Memory store (pending/unfinalized events)

mod fee_cache;
pub mod gas_service;
mod handlers;
mod quota_cache;
mod types;

pub use fee_cache::{get_global_fee_cache, init_global_fee_cache, FeeCache};
pub use gas_service::{refresh_fee_estimates, update_fee_cache_async, update_gas_for_new_event};
pub use handlers::create_api_router;
pub use quota_cache::{
    get_global_quota_cache, init_global_quota_cache, init_global_quota_cache_with_config,
    mark_quota_stale, QuotaCache, QuotaCacheConfig,
};
pub use types::*;

use std::sync::Arc;

use crate::network::NetworkType;
use starcoin_bridge::pending_events::TransferTracker;
use starcoin_bridge_pg_db::Db;

/// Shared state for API handlers
#[derive(Clone)]
pub struct ApiState {
    pub db: Db,
    pub quota_cache: Arc<QuotaCache>,
    pub fee_cache: Arc<FeeCache>,
    /// Transfer tracker for pending (unfinalized) events
    pub transfer_tracker: Option<Arc<TransferTracker>>,
    /// Claim delay in seconds - time to wait after approval before claim is allowed
    pub claim_delay_seconds: u64,
    /// ETH RPC URL for gas queries
    pub eth_rpc_url: String,
    /// Starcoin RPC URL for gas queries
    pub starcoin_rpc_url: String,
    /// Network type for correct bridge chain ID mapping
    pub network: NetworkType,
}

impl ApiState {
    pub fn new(db: Db) -> Arc<Self> {
        Arc::new(Self {
            db,
            quota_cache: QuotaCache::new(),
            fee_cache: Arc::new(FeeCache::new()),
            transfer_tracker: None,
            claim_delay_seconds: 0,
            eth_rpc_url: String::new(),
            starcoin_rpc_url: String::new(),
            network: NetworkType::Local,
        })
    }

    pub fn new_with_quota_cache(db: Db, quota_cache: Arc<QuotaCache>) -> Arc<Self> {
        Arc::new(Self {
            db,
            quota_cache,
            fee_cache: Arc::new(FeeCache::new()),
            transfer_tracker: None,
            claim_delay_seconds: 0,
            eth_rpc_url: String::new(),
            starcoin_rpc_url: String::new(),
            network: NetworkType::Local,
        })
    }

    pub fn new_with_config(
        db: Db,
        quota_cache: Arc<QuotaCache>,
        claim_delay_seconds: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            db,
            quota_cache,
            fee_cache: init_global_fee_cache(),
            transfer_tracker: None,
            claim_delay_seconds,
            eth_rpc_url: String::new(),
            starcoin_rpc_url: String::new(),
            network: NetworkType::Local,
        })
    }

    pub fn new_with_rpc(
        db: Db,
        quota_cache: Arc<QuotaCache>,
        claim_delay_seconds: u64,
        eth_rpc_url: String,
        starcoin_rpc_url: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            db,
            quota_cache,
            fee_cache: init_global_fee_cache(),
            transfer_tracker: None,
            claim_delay_seconds,
            eth_rpc_url,
            starcoin_rpc_url,
            network: NetworkType::Local,
        })
    }

    /// Create with transfer tracker for memory store queries
    pub fn new_with_tracker(
        db: Db,
        quota_cache: Arc<QuotaCache>,
        claim_delay_seconds: u64,
        eth_rpc_url: String,
        starcoin_rpc_url: String,
        transfer_tracker: Arc<TransferTracker>,
        network: NetworkType,
    ) -> Arc<Self> {
        Arc::new(Self {
            db,
            quota_cache,
            fee_cache: init_global_fee_cache(),
            transfer_tracker: Some(transfer_tracker),
            claim_delay_seconds,
            eth_rpc_url,
            starcoin_rpc_url,
            network,
        })
    }
}
