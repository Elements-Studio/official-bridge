// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Metrics push client for Starcoin Bridge.
//!
//! This module wraps starcoin-native-metrics' push_metrics functionality
//! to provide periodic metrics pushing with tokio async runtime.

use starcoin_metrics::RegistryService;
use std::time::Duration;

/// Configuration for metrics push
#[derive(Clone, Debug)]
pub struct MetricsPushConfig {
    /// Push interval in seconds (default: 60)
    pub push_interval_seconds: u64,
    /// Push gateway URL (e.g., "http://pushgateway:9091")
    pub push_url: String,
    /// Optional username for Basic Auth
    pub auth_username: Option<String>,
    /// Password for Basic Auth (required if username is set)
    pub auth_password: String,
}

impl Default for MetricsPushConfig {
    fn default() -> Self {
        Self {
            push_interval_seconds: 60,
            push_url: String::new(),
            auth_username: None,
            auth_password: String::new(),
        }
    }
}

/// Starts a background task to periodically push metrics to a Prometheus Pushgateway.
///
/// Uses starcoin-native-metrics' `push_metrics` function which supports:
/// - Basic Auth authentication
/// - Standard Prometheus push format
///
/// # Arguments
/// * `config` - Push configuration including URL and auth credentials
/// * `_registry` - Registry service (currently uses default prometheus registry)
///
/// # Example
/// ```ignore
/// let config = MetricsPushConfig {
///     push_interval_seconds: 60,
///     push_url: "http://pushgateway:9091".to_string(),
///     auth_username: Some("user".to_string()),
///     auth_password: "password".to_string(),
/// };
/// start_metrics_push_task(config, registry);
/// ```
pub fn start_metrics_push_task(config: MetricsPushConfig, _registry: RegistryService) {
    if config.push_url.is_empty() {
        tracing::warn!("Metrics push URL is empty, skipping metrics push task");
        return;
    }

    let interval = Duration::from_secs(config.push_interval_seconds);

    tokio::spawn(async move {
        tracing::info!(
            push_url = %config.push_url,
            interval = ?interval,
            "Started Metrics Push Service"
        );

        let mut interval_timer = tokio::time::interval(interval);
        interval_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval_timer.tick().await;

            // Use starcoin-native-metrics' push_metrics function
            // It uses prometheus::gather() internally to collect all registered metrics
            starcoin_native_metrics::metric_server::push_metrics(
                config.push_url.clone(),
                config.auth_username.clone(),
                config.auth_password.clone(),
            );
        }
    });
}
