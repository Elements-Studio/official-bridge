// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    register_int_counter_with_registry, register_int_gauge_vec_with_registry,
    register_int_gauge_with_registry, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Registry,
};

const FINE_GRAINED_LATENCY_SEC_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.6, 0.7, 0.8, 0.9,
    1.0, 1.2, 1.4, 1.6, 1.8, 2.0, 2.5, 3.0, 3.5, 4.0, 5.0, 6.0, 6.5, 7.0, 7.5, 8.0, 8.5, 9.0, 9.5,
    10., 15., 20., 25., 30., 35., 40., 45., 50., 60., 70., 80., 90., 100., 120., 140., 160., 180.,
    200., 250., 300., 350., 400.,
];

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct BridgeMetrics {
    pub(crate) err_build_starcoin_bridge_transaction: IntCounter,
    pub(crate) err_signature_aggregation: IntCounter,
    pub(crate) err_signature_aggregation_too_many_failures: IntCounter,
    pub(crate) err_starcoin_bridge_transaction_submission: IntCounter,
    pub(crate) err_starcoin_bridge_transaction_submission_too_many_failures: IntCounter,
    pub(crate) err_starcoin_bridge_transaction_execution: IntCounter,
    pub(crate) requests_received: IntCounterVec,
    pub(crate) requests_ok: IntCounterVec,
    pub(crate) err_requests: IntCounterVec,
    pub(crate) requests_inflight: IntGaugeVec,

    pub(crate) last_synced_starcoin_bridge_blocks: IntGaugeVec,
    pub(crate) last_finalized_eth_block: IntGauge,
    pub(crate) last_synced_eth_blocks: IntGaugeVec,

    pub(crate) starcoin_bridge_watcher_received_events: IntCounter,
    pub(crate) starcoin_bridge_watcher_received_actions: IntCounter,
    pub(crate) starcoin_bridge_watcher_unrecognized_events: IntCounter,
    pub(crate) eth_watcher_received_events: IntCounter,
    pub(crate) eth_watcher_received_actions: IntCounter,
    pub(crate) eth_watcher_unrecognized_events: IntCounter,
    pub(crate) action_executor_already_processed_actions: IntCounter,
    pub(crate) action_executor_signing_queue_received_actions: IntCounter,
    pub(crate) action_executor_signing_queue_skipped_actions: IntCounter,
    pub(crate) action_executor_execution_queue_received_actions: IntCounter,
    pub(crate) action_executor_execution_queue_skipped_actions_due_to_pausing: IntCounter,

    pub(crate) last_observed_actions_seq_num: IntGaugeVec,

    pub(crate) signer_with_cache_hit: IntCounterVec,
    pub(crate) signer_with_cache_miss: IntCounterVec,

    pub(crate) eth_rpc_queries: IntCounterVec,
    pub(crate) eth_rpc_queries_latency: HistogramVec,

    pub(crate) starcoin_bridge_rpc_errors: IntCounterVec,
    pub(crate) observed_governance_actions: IntCounterVec,
    pub(crate) current_bridge_voting_rights: IntGaugeVec,

    pub(crate) auth_agg_ok_responses: IntCounterVec,
    pub(crate) auth_agg_bad_responses: IntCounterVec,

    pub(crate) starcoin_bridge_eth_token_transfer_approved: IntCounter,
    pub(crate) starcoin_bridge_eth_token_transfer_claimed: IntCounter,
    pub(crate) eth_starcoin_bridge_token_transfer_approved: IntCounter,
    pub(crate) eth_starcoin_bridge_token_transfer_claimed: IntCounter,

    // ========== NEW METRICS ==========

    // Starcoin RPC Monitoring (P0)
    pub(crate) starcoin_rpc_queries: IntCounterVec,
    pub(crate) starcoin_rpc_queries_latency: HistogramVec,

    // Transaction Execution Monitoring (P1)
    pub(crate) starcoin_tx_submitted: IntCounter,
    pub(crate) starcoin_tx_confirmed: IntCounter,
    pub(crate) starcoin_tx_failed: IntCounter,
    pub(crate) starcoin_tx_latency: HistogramVec,

    // Token Transfer Amount Monitoring (P1)
    pub(crate) token_transfer_amount_total: IntCounterVec,
    pub(crate) token_transfer_count_total: IntCounterVec,

    // Signature Aggregation Monitoring (P2)
    pub(crate) signature_aggregation_latency: HistogramVec,
    pub(crate) committee_members_online: IntGauge,
    pub(crate) committee_members_total: IntGauge,

    // Health Check Metrics (P0)
    pub(crate) starcoin_node_connected: IntGauge,
    pub(crate) eth_node_connected: IntGauge,
    pub(crate) server_uptime_seconds: IntGauge,
    pub(crate) last_successful_sync_timestamp: IntGaugeVec,

    // Event Processing Latency (P2)
    pub(crate) event_processing_latency: HistogramVec,

    // Storage/Queue Monitoring (P3)
    pub(crate) pending_actions_count: IntGaugeVec,

    // Critical Error Metrics (P0) - indicates potential stuck funds
    pub(crate) bridge_action_conversion_errors: IntCounterVec,
}

impl BridgeMetrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            err_build_starcoin_bridge_transaction: register_int_counter_with_registry!(
                "bridge_err_build_starcoin_bridge_transaction",
                "Total number of errors of building starcoin transactions",
                registry,
            )
            .unwrap(),
            err_signature_aggregation: register_int_counter_with_registry!(
                "bridge_err_signature_aggregation",
                "Total number of errors of aggregating validators signatures",
                registry,
            )
            .unwrap(),
            err_signature_aggregation_too_many_failures: register_int_counter_with_registry!(
                "bridge_err_signature_aggregation_too_many_failures",
                "Total number of continuous failures during validator signature aggregation",
                registry,
            )
            .unwrap(),
            err_starcoin_bridge_transaction_submission: register_int_counter_with_registry!(
                "bridge_err_starcoin_bridge_transaction_submission",
                "Total number of errors of submitting starcoin transactions",
                registry,
            )
            .unwrap(),
            err_starcoin_bridge_transaction_submission_too_many_failures: register_int_counter_with_registry!(
                "bridge_err_starcoin_bridge_transaction_submission_too_many_failures",
                "Total number of continuous failures to submitting starcoin transactions",
                registry,
            )
            .unwrap(),
            err_starcoin_bridge_transaction_execution: register_int_counter_with_registry!(
                "bridge_err_starcoin_bridge_transaction_execution",
                "Total number of failures of starcoin transaction execution",
                registry,
            )
            .unwrap(),
            requests_received: register_int_counter_vec_with_registry!(
                "bridge_requests_received",
                "Total number of requests received in Server, by request type",
                &["type"],
                registry,
            )
            .unwrap(),
            requests_ok: register_int_counter_vec_with_registry!(
                "bridge_requests_ok",
                "Total number of ok requests, by request type",
                &["type"],
                registry,
            )
            .unwrap(),
            err_requests: register_int_counter_vec_with_registry!(
                "bridge_err_requests",
                "Total number of erred requests, by request type",
                &["type"],
                registry,
            )
            .unwrap(),
            requests_inflight: register_int_gauge_vec_with_registry!(
                "bridge_requests_inflight",
                "Total number of inflight requests, by request type",
                &["type"],
                registry,
            )
            .unwrap(),
            starcoin_bridge_watcher_received_events: register_int_counter_with_registry!(
                "bridge_starcoin_bridge_watcher_received_events",
                "Total number of received events in starcoin watcher",
                registry,
            )
            .unwrap(),
            eth_watcher_received_events: register_int_counter_with_registry!(
                "bridge_eth_watcher_received_events",
                "Total number of received events in eth watcher",
                registry,
            )
            .unwrap(),
            starcoin_bridge_watcher_received_actions: register_int_counter_with_registry!(
                "bridge_starcoin_bridge_watcher_received_actions",
                "Total number of received actions in starcoin watcher",
                registry,
            )
            .unwrap(),
            eth_watcher_received_actions: register_int_counter_with_registry!(
                "bridge_eth_watcher_received_actions",
                "Total number of received actions in eth watcher",
                registry,
            )
            .unwrap(),
            starcoin_bridge_watcher_unrecognized_events: register_int_counter_with_registry!(
                "bridge_starcoin_bridge_watcher_unrecognized_events",
                "Total number of unrecognized events in starcoin watcher",
                registry,
            )
            .unwrap(),
            eth_watcher_unrecognized_events: register_int_counter_with_registry!(
                "bridge_eth_watcher_unrecognized_events",
                "Total number of unrecognized events in eth watcher",
                registry,
            )
            .unwrap(),
            action_executor_already_processed_actions: register_int_counter_with_registry!(
                "bridge_action_executor_already_processed_actions",
                "Total number of already processed actions action executor",
                registry,
            )
            .unwrap(),
            action_executor_signing_queue_received_actions: register_int_counter_with_registry!(
                "bridge_action_executor_signing_queue_received_actions",
                "Total number of received actions in action executor signing queue",
                registry,
            )
            .unwrap(),
            action_executor_signing_queue_skipped_actions: register_int_counter_with_registry!(
                "bridge_action_executor_signing_queue_skipped_actions",
                "Total number of skipped actions in action executor signing queue",
                registry,
            )
            .unwrap(),
            action_executor_execution_queue_received_actions: register_int_counter_with_registry!(
                "bridge_action_executor_execution_queue_received_actions",
                "Total number of received actions in action executor execution queue",
                registry,
            )
            .unwrap(),
            action_executor_execution_queue_skipped_actions_due_to_pausing: register_int_counter_with_registry!(
                "bridge_action_executor_execution_queue_skipped_actions_due_to_pausing",
                "Total number of skipped actions in action executor execution queue because of pausing",
                registry,
            )
            .unwrap(),
            eth_rpc_queries: register_int_counter_vec_with_registry!(
                "bridge_eth_rpc_queries",
                "Total number of queries issued to eth provider, by request type",
                &["type"],
                registry,
            )
            .unwrap(),
            eth_rpc_queries_latency: register_histogram_vec_with_registry!(
                "bridge_eth_rpc_queries_latency",
                "Latency of queries issued to eth provider, by request type",
                &["type"],
                FINE_GRAINED_LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            last_synced_starcoin_bridge_blocks: register_int_gauge_vec_with_registry!(
                "bridge_last_synced_starcoin_bridge_blocks",
                "The latest starcoin blocks synced for each module",
                &["module_name"],
                registry,
            )
            .unwrap(),
            last_synced_eth_blocks: register_int_gauge_vec_with_registry!(
                "bridge_last_synced_eth_blocks",
                "The latest synced eth blocks synced for each contract",
                &["contract_address"],
                registry,
            )
            .unwrap(),
            last_finalized_eth_block: register_int_gauge_with_registry!(
                "bridge_last_finalized_eth_block",
                "The latest finalized eth block observed",
                registry,
            )
            .unwrap(),
            last_observed_actions_seq_num: register_int_gauge_vec_with_registry!(
                "bridge_last_observed_actions_seq_num",
                "The latest observed action sequence number per chain_id and action_type",
                &["chain_id", "action_type"],
                registry,
            )
            .unwrap(),
            signer_with_cache_hit: register_int_counter_vec_with_registry!(
                "bridge_signer_with_cache_hit",
                "Total number of hit in signer's cache, by verifier type",
                &["type"],
                registry,
            )
            .unwrap(),
            signer_with_cache_miss: register_int_counter_vec_with_registry!(
                "bridge_signer_with_cache_miss",
                "Total number of miss in signer's cache, by verifier type",
                &["type"],
                registry,
            )
            .unwrap(),
            starcoin_bridge_rpc_errors: register_int_counter_vec_with_registry!(
                "bridge_starcoin_bridge_rpc_errors",
                "Total number of errors from starcoin RPC, by RPC method",
                &["method"],
                registry,
            )
            .unwrap(),
            observed_governance_actions: register_int_counter_vec_with_registry!(
                "bridge_observed_governance_actions",
                "Total number of observed governance actions",
                &["action_type", "chain_id"],
                registry,
            )
            .unwrap(),
            current_bridge_voting_rights: register_int_gauge_vec_with_registry!(
                "current_bridge_voting_rights",
                "Current voting power in the bridge committee",
                &["authority"],
                registry
            )
            .unwrap(),
            auth_agg_ok_responses: register_int_counter_vec_with_registry!(
                "bridge_auth_agg_ok_responses",
                "Total number of ok response from auth agg",
                &["authority"],
                registry,
            )
            .unwrap(),
            auth_agg_bad_responses: register_int_counter_vec_with_registry!(
                "bridge_auth_agg_bad_responses",
                "Total number of bad response from auth agg",
                &["authority"],
                registry,
            )
            .unwrap(),
            starcoin_bridge_eth_token_transfer_approved: register_int_counter_with_registry!(
                "bridge_starcoin_bridge_eth_token_transfer_approved",
                "Total number of approved starcoin to eth token transfers (since metric introduced). \
                Should be used to track rates rather than absolute values.",
                registry,
            )
            .unwrap(),
            starcoin_bridge_eth_token_transfer_claimed: register_int_counter_with_registry!(
                "bridge_starcoin_bridge_eth_token_transfer_claimed",
                "Total number of claimed starcoin to eth token transfers (since metric introduced). \
                Should be used to track rates rather than absolute values.",
                registry,
            )
            .unwrap(),
            eth_starcoin_bridge_token_transfer_approved: register_int_counter_with_registry!(
                "bridge_eth_starcoin_bridge_token_transfer_approved",
                "Total number of approved eth to starcoin token transfers (since metric introduced). \
                Should be used to track rates rather than absolute values.",
                registry,
            )
            .unwrap(),
            eth_starcoin_bridge_token_transfer_claimed: register_int_counter_with_registry!(
                "bridge_eth_starcoin_bridge_token_transfer_claimed",
                "Total number of claimed eth to starcoin token transfers (since metric introduced). \
                Should be used to track rates rather than absolute values.",
                registry,
            )
            .unwrap(),

            // ========== NEW METRICS INITIALIZATION ==========

            // Starcoin RPC Monitoring (P0)
            starcoin_rpc_queries: register_int_counter_vec_with_registry!(
                "bridge_starcoin_rpc_queries",
                "Total number of queries issued to starcoin provider, by request type",
                &["type"],
                registry,
            )
            .unwrap(),
            starcoin_rpc_queries_latency: register_histogram_vec_with_registry!(
                "bridge_starcoin_rpc_queries_latency",
                "Latency of queries issued to starcoin provider, by request type",
                &["type"],
                FINE_GRAINED_LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),

            // Transaction Execution Monitoring (P1)
            starcoin_tx_submitted: register_int_counter_with_registry!(
                "bridge_starcoin_tx_submitted",
                "Total number of starcoin transactions submitted",
                registry,
            )
            .unwrap(),
            starcoin_tx_confirmed: register_int_counter_with_registry!(
                "bridge_starcoin_tx_confirmed",
                "Total number of starcoin transactions confirmed",
                registry,
            )
            .unwrap(),
            starcoin_tx_failed: register_int_counter_with_registry!(
                "bridge_starcoin_tx_failed",
                "Total number of starcoin transactions failed",
                registry,
            )
            .unwrap(),
            starcoin_tx_latency: register_histogram_vec_with_registry!(
                "bridge_starcoin_tx_latency",
                "Latency from transaction submission to confirmation, by tx type",
                &["tx_type"],
                FINE_GRAINED_LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            // Token Transfer Amount Monitoring (P1)
            token_transfer_amount_total: register_int_counter_vec_with_registry!(
                "bridge_token_transfer_amount_total",
                "Total amount of tokens transferred, by source chain, target chain and token type",
                &["source_chain", "target_chain", "token_type"],
                registry,
            )
            .unwrap(),
            token_transfer_count_total: register_int_counter_vec_with_registry!(
                "bridge_token_transfer_count_total",
                "Total number of token transfers, by source chain, target chain and token type",
                &["source_chain", "target_chain", "token_type"],
                registry,
            )
            .unwrap(),

            // Signature Aggregation Monitoring (P2)
            signature_aggregation_latency: register_histogram_vec_with_registry!(
                "bridge_signature_aggregation_latency",
                "Latency of signature aggregation process, by action type",
                &["action_type"],
                FINE_GRAINED_LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            committee_members_online: register_int_gauge_with_registry!(
                "bridge_committee_members_online",
                "Number of committee members currently online",
                registry,
            )
            .unwrap(),
            committee_members_total: register_int_gauge_with_registry!(
                "bridge_committee_members_total",
                "Total number of committee members",
                registry,
            )
            .unwrap(),

            // Health Check Metrics (P0)
            starcoin_node_connected: register_int_gauge_with_registry!(
                "bridge_starcoin_node_connected",
                "Whether the bridge is connected to starcoin node (0=disconnected, 1=connected)",
                registry,
            )
            .unwrap(),
            eth_node_connected: register_int_gauge_with_registry!(
                "bridge_eth_node_connected",
                "Whether the bridge is connected to eth node (0=disconnected, 1=connected)",
                registry,
            )
            .unwrap(),
            server_uptime_seconds: register_int_gauge_with_registry!(
                "bridge_server_uptime_seconds",
                "Bridge server uptime in seconds",
                registry,
            )
            .unwrap(),
            last_successful_sync_timestamp: register_int_gauge_vec_with_registry!(
                "bridge_last_successful_sync_timestamp",
                "Timestamp of last successful sync, by chain",
                &["chain"],
                registry,
            )
            .unwrap(),

            // Event Processing Latency (P2)
            event_processing_latency: register_histogram_vec_with_registry!(
                "bridge_event_processing_latency",
                "Latency from event occurrence to processing, by event type",
                &["event_type"],
                FINE_GRAINED_LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),

            // Storage/Queue Monitoring (P3)
            pending_actions_count: register_int_gauge_vec_with_registry!(
                "bridge_pending_actions_count",
                "Number of pending actions, by action type",
                &["action_type"],
                registry,
            )
            .unwrap(),

            // Critical Error Metrics (P0) - indicates potential stuck funds
            bridge_action_conversion_errors: register_int_counter_vec_with_registry!(
                "bridge_action_conversion_errors",
                "Errors converting bridge events to actions - may indicate stuck funds! Alert immediately!",
                &["chain", "error_type"],
                registry,
            )
            .unwrap(),
        }
    }

    pub fn new_for_testing() -> Self {
        let registry = Registry::new();
        Self::new(&registry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that BridgeMetrics can be constructed without panicking
    #[test]
    fn test_metrics_construction() {
        let registry = Registry::new();
        let metrics = BridgeMetrics::new(&registry);

        // Verify bridge_action_conversion_errors is properly initialized
        // by checking we can use it with labels
        metrics
            .bridge_action_conversion_errors
            .with_label_values(&["eth", "test_error"])
            .inc();

        let count = metrics
            .bridge_action_conversion_errors
            .with_label_values(&["eth", "test_error"])
            .get();
        assert_eq!(count, 1);
    }

    /// Test that bridge_action_conversion_errors metric has correct labels
    #[test]
    fn test_conversion_errors_metric_labels() {
        let registry = Registry::new();
        let metrics = BridgeMetrics::new(&registry);

        // Test with various chain and error type combinations
        let test_cases = vec![
            ("eth", "unrecognized_eth_contract"),
            ("eth", "no_bridge_events"),
            ("eth", "event_not_actionable"),
            ("starcoin", "unrecognized_starcoin_package"),
            ("starcoin", "internal_error"),
        ];

        for (chain, error_type) in test_cases {
            metrics
                .bridge_action_conversion_errors
                .with_label_values(&[chain, error_type])
                .inc();
        }

        // Verify each counter is tracked independently
        assert_eq!(
            metrics
                .bridge_action_conversion_errors
                .with_label_values(&["eth", "unrecognized_eth_contract"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .bridge_action_conversion_errors
                .with_label_values(&["starcoin", "internal_error"])
                .get(),
            1
        );
    }

    /// Test that metrics are registered to the registry
    #[test]
    fn test_metrics_are_registered() {
        let registry = Registry::new();
        let metrics = BridgeMetrics::new(&registry);

        // CounterVec metrics only appear in gather() after being used at least once
        metrics
            .bridge_action_conversion_errors
            .with_label_values(&["test_chain", "test_error"])
            .inc();

        // The registry should have metrics registered
        let metric_families = registry.gather();

        // Find our specific metric
        let conversion_errors = metric_families
            .iter()
            .find(|mf| mf.get_name().contains("action_conversion_errors"));

        assert!(
            conversion_errors.is_some(),
            "bridge_action_conversion_errors should be registered. Found: {:?}",
            metric_families
                .iter()
                .map(|mf| mf.get_name())
                .collect::<Vec<_>>()
        );
    }

    /// Test new_for_testing helper
    #[test]
    fn test_new_for_testing() {
        // Should not panic
        let metrics = BridgeMetrics::new_for_testing();

        // Should be usable
        metrics
            .bridge_action_conversion_errors
            .with_label_values(&["test", "test"])
            .inc();
    }

    /// Test that incrementing counters works correctly
    #[test]
    fn test_counter_increment() {
        let metrics = BridgeMetrics::new_for_testing();

        let counter = metrics
            .bridge_action_conversion_errors
            .with_label_values(&["eth", "provider_error"]);

        assert_eq!(counter.get(), 0);

        counter.inc();
        assert_eq!(counter.get(), 1);

        counter.inc_by(5);
        assert_eq!(counter.get(), 6);
    }

    /// Test that all required metrics fields exist and are initialized
    #[test]
    fn test_all_p0_metrics_exist() {
        let registry = Registry::new();
        let metrics = BridgeMetrics::new(&registry);

        // P0 Critical Error Metrics - these must exist for alerting
        metrics
            .bridge_action_conversion_errors
            .with_label_values(&["eth", "test"])
            .inc();

        // P0 Health Check Metrics
        metrics.starcoin_node_connected.set(1);
        metrics.eth_node_connected.set(1);
        metrics.server_uptime_seconds.set(3600);

        // Verify the metrics have the expected values
        assert_eq!(metrics.starcoin_node_connected.get(), 1);
        assert_eq!(metrics.eth_node_connected.get(), 1);
        assert_eq!(metrics.server_uptime_seconds.get(), 3600);
    }
}
