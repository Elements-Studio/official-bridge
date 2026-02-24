// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Gas query service for fee estimation
//!
//! Provides a unified interface to query gas usage from both ETH and Starcoin chains,
//! with caching to avoid repeated RPC calls.

use crate::api::types::FeeEstimateResponse;
use crate::api::FeeCache;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use ethers::prelude::Middleware;
use serde_json::Value;
use starcoin_bridge_pg_db::Db;
use starcoin_bridge_schema::models::{BridgeDataSource, TokenTransfer};
use starcoin_bridge_schema::schema::token_transfer;
use std::sync::Arc;
use tracing::{debug, warn};

/// Gas query configuration
#[derive(Clone)]
pub struct GasQueryConfig {
    pub eth_rpc_url: String,
    pub starcoin_rpc_url: String,
}

/// Query gas usage for a transaction from ETH chain
pub async fn query_eth_gas(rpc_url: &str, tx_hash: &str) -> Option<i64> {
    let provider = match ethers::providers::Provider::<ethers::providers::Http>::try_from(rpc_url) {
        Ok(p) => p,
        Err(e) => {
            warn!("Failed to create ETH provider: {:?}", e);
            return None;
        }
    };

    let hash = tx_hash.parse::<ethers::types::H256>().ok()?;
    match provider.get_transaction_receipt(hash).await {
        Ok(Some(receipt)) => {
            let gas = receipt.gas_used.map(|g| g.as_u64() as i64).unwrap_or(0);
            debug!("ETH gas for {}: {}", tx_hash, gas);
            Some(gas)
        }
        Ok(None) => {
            debug!("No receipt found for ETH tx {}", tx_hash);
            None
        }
        Err(e) => {
            warn!("Failed to get ETH receipt for {}: {:?}", tx_hash, e);
            None
        }
    }
}

/// Query gas usage for a transaction from Starcoin chain
pub async fn query_starcoin_gas(rpc_url: &str, tx_hash: &str) -> Option<i64> {
    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "chain.get_transaction_info",
        "params": [tx_hash],
        "id": 1
    });

    match client.post(rpc_url).json(&payload).send().await {
        Ok(resp) => {
            if let Ok(json) = resp.json::<Value>().await {
                if let Some(result) = json.get("result") {
                    if let Some(gas_str) = result.get("gas_used").and_then(|v| v.as_str()) {
                        if let Ok(gas) = gas_str.parse::<i64>() {
                            debug!("Starcoin gas for {}: {}", tx_hash, gas);
                            return Some(gas);
                        }
                    }
                }
            }
            None
        }
        Err(e) => {
            warn!("Failed to get Starcoin tx info for {}: {:?}", tx_hash, e);
            None
        }
    }
}

/// Represents one type of transfer operation for gas tracking
#[derive(Debug, Clone, Copy)]
pub enum TransferType {
    /// ETH -> Starcoin: deposit on ETH
    EthToStarcoinDeposit,
    /// ETH -> Starcoin: approval on Starcoin  
    EthToStarcoinApproval,
    /// ETH -> Starcoin: claim on Starcoin
    EthToStarcoinClaim,
    /// Starcoin -> ETH: deposit on Starcoin
    StarcoinToEthDeposit,
    /// Starcoin -> ETH: approval on ETH
    StarcoinToEthApproval,
    /// Starcoin -> ETH: claim on ETH
    StarcoinToEthClaim,
}

impl TransferType {
    /// Get the status string for database query
    pub fn status(&self) -> &'static str {
        match self {
            TransferType::EthToStarcoinDeposit | TransferType::StarcoinToEthDeposit => "Deposited",
            TransferType::EthToStarcoinApproval | TransferType::StarcoinToEthApproval => "Approved",
            TransferType::EthToStarcoinClaim | TransferType::StarcoinToEthClaim => "Claimed",
        }
    }

    /// Get the data source for database query
    pub fn data_source(&self) -> BridgeDataSource {
        match self {
            TransferType::EthToStarcoinDeposit => BridgeDataSource::ETH,
            TransferType::EthToStarcoinApproval => BridgeDataSource::STARCOIN,
            TransferType::EthToStarcoinClaim => BridgeDataSource::STARCOIN,
            TransferType::StarcoinToEthDeposit => BridgeDataSource::STARCOIN,
            TransferType::StarcoinToEthApproval => BridgeDataSource::ETH,
            TransferType::StarcoinToEthClaim => BridgeDataSource::ETH,
        }
    }

    /// Check if this transfer type uses ETH RPC
    pub fn is_eth(&self) -> bool {
        matches!(
            self,
            TransferType::EthToStarcoinDeposit
                | TransferType::StarcoinToEthApproval
                | TransferType::StarcoinToEthClaim
        )
    }

    /// All transfer types
    pub fn all() -> [TransferType; 6] {
        [
            TransferType::EthToStarcoinDeposit,
            TransferType::EthToStarcoinApproval,
            TransferType::EthToStarcoinClaim,
            TransferType::StarcoinToEthDeposit,
            TransferType::StarcoinToEthApproval,
            TransferType::StarcoinToEthClaim,
        ]
    }
}

/// Get the latest transfer record for a specific type from database
pub async fn get_latest_transfer(db: &Db, transfer_type: TransferType) -> Option<TokenTransfer> {
    let mut conn = db.connect().await.ok()?;

    token_transfer::table
        .filter(token_transfer::status.eq(transfer_type.status()))
        .filter(token_transfer::data_source.eq(transfer_type.data_source().as_ref()))
        .order(token_transfer::timestamp_ms.desc())
        .first::<TokenTransfer>(&mut conn)
        .await
        .ok()
}

/// Query gas for a transfer and update the database record
pub async fn query_and_update_gas(
    db: &Db,
    transfer: &TokenTransfer,
    eth_rpc_url: &str,
    starcoin_rpc_url: &str,
) -> Option<i64> {
    let tx_hash = format!("0x{}", hex::encode(&transfer.txn_hash));

    let gas = match transfer.data_source {
        BridgeDataSource::ETH => query_eth_gas(eth_rpc_url, &tx_hash).await,
        BridgeDataSource::STARCOIN => query_starcoin_gas(starcoin_rpc_url, &tx_hash).await,
    }?;

    // Update database if gas changed
    if gas != transfer.gas_usage && gas > 0 {
        if let Ok(mut conn) = db.connect().await {
            let _ = diesel::update(
                token_transfer::table
                    .filter(token_transfer::chain_id.eq(transfer.chain_id))
                    .filter(token_transfer::nonce.eq(transfer.nonce))
                    .filter(token_transfer::status.eq(&transfer.status)),
            )
            .set(token_transfer::gas_usage.eq(gas))
            .execute(&mut conn)
            .await;
            debug!(
                "Updated gas_usage to {} for chain_id={} nonce={} status={:?}",
                gas, transfer.chain_id, transfer.nonce, transfer.status
            );
        }
    }

    Some(gas)
}

/// Refresh all fee estimates from database, querying RPC for missing gas values
pub async fn refresh_fee_estimates(
    db: &Db,
    fee_cache: &Arc<FeeCache>,
    eth_rpc_url: &str,
    starcoin_rpc_url: &str,
) -> FeeEstimateResponse {
    let mut response = FeeEstimateResponse::default();

    for transfer_type in TransferType::all() {
        if let Some(transfer) = get_latest_transfer(db, transfer_type).await {
            // Use existing gas if available, otherwise query RPC
            let gas = if transfer.gas_usage > 0 {
                transfer.gas_usage
            } else {
                query_and_update_gas(db, &transfer, eth_rpc_url, starcoin_rpc_url)
                    .await
                    .unwrap_or(0)
            };

            // Set the appropriate field
            match transfer_type {
                TransferType::EthToStarcoinDeposit => response.eth_to_starcoin_deposit_gas = gas,
                TransferType::EthToStarcoinApproval => response.eth_to_starcoin_approval_gas = gas,
                TransferType::EthToStarcoinClaim => response.eth_to_starcoin_claim_gas = gas,
                TransferType::StarcoinToEthDeposit => response.starcoin_to_eth_deposit_gas = gas,
                TransferType::StarcoinToEthApproval => response.starcoin_to_eth_approval_gas = gas,
                TransferType::StarcoinToEthClaim => response.starcoin_to_eth_claim_gas = gas,
            }
        }
    }

    // Update cache
    fee_cache.update(response.clone()).await;
    response
}

/// Update fee cache asynchronously for a new event
/// This spawns a background task to query gas and update the global cache
/// Does not block the caller
pub fn update_fee_cache_async(
    tx_hash: String,
    data_source: BridgeDataSource,
    status: String,
    eth_rpc_url: String,
    starcoin_rpc_url: String,
) {
    let Some(fee_cache) = crate::api::get_global_fee_cache() else {
        return;
    };

    tokio::spawn(async move {
        // Query gas from RPC
        let gas = match data_source {
            BridgeDataSource::ETH => query_eth_gas(&eth_rpc_url, &tx_hash).await,
            BridgeDataSource::STARCOIN => query_starcoin_gas(&starcoin_rpc_url, &tx_hash).await,
        };

        let Some(gas) = gas else {
            debug!("Failed to query gas for tx {}", tx_hash);
            return;
        };

        if gas == 0 {
            return;
        }

        // Update cache with new gas value
        let mut cached = fee_cache.get().await;

        match (data_source, status.as_str()) {
            (BridgeDataSource::ETH, "Deposited") => cached.eth_to_starcoin_deposit_gas = gas,
            (BridgeDataSource::STARCOIN, "Approved") => cached.eth_to_starcoin_approval_gas = gas,
            (BridgeDataSource::STARCOIN, "Claimed") => cached.eth_to_starcoin_claim_gas = gas,
            (BridgeDataSource::STARCOIN, "Deposited") => cached.starcoin_to_eth_deposit_gas = gas,
            (BridgeDataSource::ETH, "Approved") => cached.starcoin_to_eth_approval_gas = gas,
            (BridgeDataSource::ETH, "Claimed") => cached.starcoin_to_eth_claim_gas = gas,
            _ => return,
        }

        fee_cache.update(cached).await;
        debug!(
            "Updated fee cache: {:?}/{} -> gas={}",
            data_source, status, gas
        );
    });
}

/// Update fee cache for a specific transfer type after syncer processes a new event
/// This is called asynchronously by the syncer
pub async fn update_gas_for_new_event(
    _: &Db,
    fee_cache: &Arc<FeeCache>,
    tx_hash: &str,
    data_source: BridgeDataSource,
    status: &str,
    eth_rpc_url: &str,
    starcoin_rpc_url: &str,
) {
    // Query gas from RPC
    let gas = match data_source {
        BridgeDataSource::ETH => query_eth_gas(eth_rpc_url, tx_hash).await,
        BridgeDataSource::STARCOIN => query_starcoin_gas(starcoin_rpc_url, tx_hash).await,
    };

    let Some(gas) = gas else {
        return;
    };

    if gas == 0 {
        return;
    }

    // Update cache with new gas value
    let mut cached = fee_cache.get().await;

    match (data_source, status) {
        (BridgeDataSource::ETH, "Deposited") => cached.eth_to_starcoin_deposit_gas = gas,
        (BridgeDataSource::STARCOIN, "Approved") => cached.eth_to_starcoin_approval_gas = gas,
        (BridgeDataSource::STARCOIN, "Claimed") => cached.eth_to_starcoin_claim_gas = gas,
        (BridgeDataSource::STARCOIN, "Deposited") => cached.starcoin_to_eth_deposit_gas = gas,
        (BridgeDataSource::ETH, "Approved") => cached.starcoin_to_eth_approval_gas = gas,
        (BridgeDataSource::ETH, "Claimed") => cached.starcoin_to_eth_claim_gas = gas,
        _ => return,
    }

    fee_cache.update(cached).await;
    debug!(
        "Updated fee cache: {:?}/{} -> gas={}",
        data_source, status, gas
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_type_properties() {
        // ETH -> Starcoin direction
        assert_eq!(TransferType::EthToStarcoinDeposit.status(), "Deposited");
        assert!(matches!(
            TransferType::EthToStarcoinDeposit.data_source(),
            BridgeDataSource::ETH
        ));
        assert!(TransferType::EthToStarcoinDeposit.is_eth());

        assert_eq!(TransferType::EthToStarcoinApproval.status(), "Approved");
        assert!(matches!(
            TransferType::EthToStarcoinApproval.data_source(),
            BridgeDataSource::STARCOIN
        ));
        assert!(!TransferType::EthToStarcoinApproval.is_eth());

        assert_eq!(TransferType::EthToStarcoinClaim.status(), "Claimed");
        assert!(matches!(
            TransferType::EthToStarcoinClaim.data_source(),
            BridgeDataSource::STARCOIN
        ));
        assert!(!TransferType::EthToStarcoinClaim.is_eth());

        // Starcoin -> ETH direction
        assert_eq!(TransferType::StarcoinToEthDeposit.status(), "Deposited");
        assert!(matches!(
            TransferType::StarcoinToEthDeposit.data_source(),
            BridgeDataSource::STARCOIN
        ));
        assert!(!TransferType::StarcoinToEthDeposit.is_eth());

        assert_eq!(TransferType::StarcoinToEthApproval.status(), "Approved");
        assert!(matches!(
            TransferType::StarcoinToEthApproval.data_source(),
            BridgeDataSource::ETH
        ));
        assert!(TransferType::StarcoinToEthApproval.is_eth());

        assert_eq!(TransferType::StarcoinToEthClaim.status(), "Claimed");
        assert!(matches!(
            TransferType::StarcoinToEthClaim.data_source(),
            BridgeDataSource::ETH
        ));
        assert!(TransferType::StarcoinToEthClaim.is_eth());
    }

    #[test]
    fn test_all_transfer_types() {
        let all = TransferType::all();
        assert_eq!(all.len(), 6);
    }

    #[tokio::test]
    async fn test_fee_cache_update() {
        let cache = Arc::new(FeeCache::new());

        // Initial state - all zeros
        let initial = cache.get().await;
        assert_eq!(initial.eth_to_starcoin_deposit_gas, 0);

        // Simulate updating individual gas values
        let response = FeeEstimateResponse {
            eth_to_starcoin_deposit_gas: 100000,
            ..Default::default()
        };
        cache.update(response).await;

        let cached = cache.get().await;
        assert_eq!(cached.eth_to_starcoin_deposit_gas, 100000);
        assert_eq!(cached.eth_to_starcoin_approval_gas, 0);
    }
}
