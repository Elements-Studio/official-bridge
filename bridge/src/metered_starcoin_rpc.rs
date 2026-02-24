// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Metered wrapper for Starcoin RPC client that tracks query counts and latencies.

use crate::metrics::BridgeMetrics;
use crate::simple_starcoin_rpc::SimpleStarcoinRpcClient;
use anyhow::Result;
use serde_json::Value;
use std::sync::Arc;

/// A wrapper around SimpleStarcoinRpcClient that records metrics for each RPC call.
#[derive(Clone, Debug)]
pub struct MeteredStarcoinRpcClient {
    inner: SimpleStarcoinRpcClient,
    metrics: Arc<BridgeMetrics>,
}

impl MeteredStarcoinRpcClient {
    pub fn new(inner: SimpleStarcoinRpcClient, metrics: Arc<BridgeMetrics>) -> Self {
        Self { inner, metrics }
    }

    /// Get the bridge contract address
    pub fn bridge_address(&self) -> &str {
        self.inner.bridge_address()
    }

    /// Get the underlying RPC client (for compatibility)
    pub fn inner(&self) -> &SimpleStarcoinRpcClient {
        &self.inner
    }

    fn record_query(&self, method: &str) {
        self.metrics
            .starcoin_rpc_queries
            .with_label_values(&[method])
            .inc();
    }

    fn start_timer(&self, method: &str) -> prometheus::HistogramTimer {
        self.metrics
            .starcoin_rpc_queries_latency
            .with_label_values(&[method])
            .start_timer()
    }

    // Chain info
    pub async fn chain_info(&self) -> Result<Value> {
        self.record_query("chain_info");
        let _timer = self.start_timer("chain_info");
        self.inner.chain_info().await
    }

    // Node info
    pub async fn node_info(&self) -> Result<Value> {
        self.record_query("node_info");
        let _timer = self.start_timer("node_info");
        self.inner.node_info().await
    }

    /// Get the Starcoin network chain ID
    pub async fn get_chain_id(&self) -> Result<u8> {
        self.record_query("get_chain_id");
        let _timer = self.start_timer("get_chain_id");
        self.inner.get_chain_id().await
    }

    /// Get events with filter
    pub async fn get_events(&self, filter: Value) -> Result<Vec<Value>> {
        self.record_query("get_events");
        let _timer = self.start_timer("get_events");
        self.inner.get_events(filter).await
    }

    /// Get block by number
    pub async fn get_block_by_number(&self, number: u64) -> Result<Value> {
        self.record_query("get_block_by_number");
        let _timer = self.start_timer("get_block_by_number");
        self.inner.get_block_by_number(number).await
    }

    /// Get events by transaction hash
    pub async fn get_events_by_txn_hash(&self, txn_hash: &str) -> Result<Vec<Value>> {
        self.record_query("get_events_by_txn_hash");
        let _timer = self.start_timer("get_events_by_txn_hash");
        self.inner.get_events_by_txn_hash(txn_hash).await
    }

    /// Get resource by address and type
    pub async fn get_resource(&self, address: &str, resource_type: &str) -> Result<Option<Value>> {
        self.record_query("get_resource");
        let _timer = self.start_timer("get_resource");
        self.inner.get_resource(address, resource_type).await
    }

    /// Call a contract function (view)
    pub async fn call_contract(
        &self,
        function_id: &str,
        type_args: Vec<String>,
        args: Vec<String>,
    ) -> Result<Value> {
        self.record_query("call_contract");
        let _timer = self.start_timer("call_contract");
        self.inner.call_contract(function_id, type_args, args).await
    }

    /// Submit a signed transaction
    pub async fn submit_transaction(&self, signed_txn_hex: &str) -> Result<Value> {
        self.record_query("submit_transaction");
        let _timer = self.start_timer("submit_transaction");
        // Record submission metric
        self.metrics.starcoin_tx_submitted.inc();
        self.inner.submit_transaction(signed_txn_hex).await
    }

    /// Get transaction info by hash
    pub async fn get_transaction_info(&self, txn_hash: &str) -> Result<Value> {
        self.record_query("get_transaction_info");
        let _timer = self.start_timer("get_transaction_info");
        self.inner.get_transaction_info(txn_hash).await
    }

    /// Get account sequence number
    pub async fn get_sequence_number(&self, address: &str) -> Result<u64> {
        self.record_query("get_sequence_number");
        let _timer = self.start_timer("get_sequence_number");
        self.inner.get_sequence_number(address).await
    }

    /// Update node connection status
    pub fn update_connection_status(&self, connected: bool) {
        self.metrics
            .starcoin_node_connected
            .set(if connected { 1 } else { 0 });
    }

    /// Record transaction confirmation
    pub fn record_tx_confirmed(&self) {
        self.metrics.starcoin_tx_confirmed.inc();
    }

    /// Record transaction failure
    pub fn record_tx_failed(&self) {
        self.metrics.starcoin_tx_failed.inc();
    }

    /// Record transaction latency
    pub fn record_tx_latency(&self, tx_type: &str, duration_secs: f64) {
        self.metrics
            .starcoin_tx_latency
            .with_label_values(&[tx_type])
            .observe(duration_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Registry;

    #[test]
    fn test_metered_starcoin_rpc_client_creation() {
        let inner = SimpleStarcoinRpcClient::new("http://localhost:9850", "0x1");
        let metrics = Arc::new(BridgeMetrics::new(&Registry::new()));
        let metered = MeteredStarcoinRpcClient::new(inner, metrics.clone());

        assert_eq!(metered.bridge_address(), "0x1");
    }
}
