// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::metrics::BridgeMetrics;
use ethers::providers::{Http, HttpClientError, JsonRpcClient, Provider};
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use url::{ParseError, Url};

/// Minimum delay between requests to avoid rate limiting (in milliseconds)
/// Increased from 1000ms to 2000ms to reduce query frequency and avoid rate limits
const MIN_REQUEST_DELAY_MS: u64 = 2000;

/// Semaphore to limit concurrent requests to avoid overwhelming the provider
/// Reduced from 5 to 2 to prevent burst requests during startup
const MAX_CONCURRENT_REQUESTS: usize = 2;

#[derive(Debug, Clone)]
pub struct MeteredEthHttpProvier {
    inner: Http,
    metrics: Arc<BridgeMetrics>,
    /// Semaphore to limit concurrent requests
    semaphore: Arc<tokio::sync::Semaphore>,
    /// Last request time to enforce minimum delay between requests
    last_request_time: Arc<Mutex<Instant>>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl JsonRpcClient for MeteredEthHttpProvier {
    type Error = HttpClientError;

    async fn request<T: Serialize + Send + Sync + Debug, R: DeserializeOwned + Send>(
        &self,
        method: &str,
        params: T,
    ) -> Result<R, HttpClientError> {
        // Acquire semaphore permit to limit concurrent requests
        // This should never fail unless the semaphore is closed, which shouldn't happen
        let _permit = self
            .semaphore
            .acquire()
            .await
            .expect("Semaphore should never be closed");

        // Enforce minimum delay between requests to avoid rate limiting
        let mut last_request = self.last_request_time.lock().await;
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(*last_request);
        // If less than MIN_REQUEST_DELAY_MS has passed, wait for the remainder
        if elapsed.as_millis() < MIN_REQUEST_DELAY_MS as u128 {
            let delay = Duration::from_millis(MIN_REQUEST_DELAY_MS) - elapsed;
            tokio::time::sleep(delay).await;
        }
        *last_request = Instant::now();
        drop(last_request);

        self.metrics
            .eth_rpc_queries
            .with_label_values(&[method])
            .inc();
        let _guard = self
            .metrics
            .eth_rpc_queries_latency
            .with_label_values(&[method])
            .start_timer();

        // Retry logic for rate limit errors with exponential backoff
        let mut result = self.inner.request(method, &params).await;
        let mut retry_count = 0;
        const MAX_RETRIES: u32 = 3;

        while retry_count < MAX_RETRIES {
            // Check if error is rate limit related
            // Infura may return non-standard JSON-RPC format like {"code":-32005,"message":"Too Many Requests"}
            // which causes deserialization errors, so we need to check the error message for rate limit indicators
            let is_rate_limit = match &result {
                Err(e) => {
                    let error_str = format!("{:?}", e).to_lowercase();
                    error_str.contains("rate limit") 
                        || error_str.contains("429") 
                        || error_str.contains("too many requests")
                        || error_str.contains("quota exceeded")
                        || error_str.contains("-32005")  // Infura rate limit error code
                        || (error_str.contains("deserialization") && error_str.contains("too many requests"))
                }
                Ok(_) => false,
            };

            if !is_rate_limit {
                break;
            }

            // Exponential backoff: 1s, 2s, 4s
            let backoff_duration = Duration::from_secs(1 << retry_count);
            tracing::warn!(
                "Rate limit error detected, retrying after {:?} (attempt {}/{})",
                backoff_duration,
                retry_count + 1,
                MAX_RETRIES
            );
            tokio::time::sleep(backoff_duration).await;

            // Retry the request
            result = self.inner.request(method, &params).await;
            retry_count += 1;
        }

        // Update ETH node connection status based on request result
        match &result {
            Ok(_) => self.metrics.eth_node_connected.set(1),
            Err(_) => self.metrics.eth_node_connected.set(0),
        }
        result
    }
}

impl MeteredEthHttpProvier {
    pub fn new(url: impl Into<Url>, metrics: Arc<BridgeMetrics>) -> Self {
        let inner = Http::new(url);
        Self {
            inner,
            metrics,
            semaphore: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_REQUESTS)),
            last_request_time: Arc::new(Mutex::new(
                Instant::now() - Duration::from_millis(MIN_REQUEST_DELAY_MS),
            )),
        }
    }
}

pub fn new_metered_eth_provider(
    url: &str,
    metrics: Arc<BridgeMetrics>,
) -> Result<Provider<MeteredEthHttpProvier>, ParseError> {
    let http_provider = MeteredEthHttpProvier::new(Url::parse(url)?, metrics);
    Ok(Provider::new(http_provider))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::providers::Middleware;
    use prometheus::Registry;

    #[tokio::test]
    async fn test_metered_eth_provider() {
        let metrics = Arc::new(BridgeMetrics::new(&Registry::new()));
        let provider = new_metered_eth_provider("http://localhost:9876", metrics.clone()).unwrap();

        assert_eq!(
            metrics
                .eth_rpc_queries
                .get_metric_with_label_values(&["eth_blockNumber"])
                .unwrap()
                .get(),
            0
        );
        assert_eq!(
            metrics
                .eth_rpc_queries_latency
                .get_metric_with_label_values(&["eth_blockNumber"])
                .unwrap()
                .get_sample_count(),
            0
        );

        provider.get_block_number().await.unwrap_err(); // the rpc cal will fail but we don't care

        assert_eq!(
            metrics
                .eth_rpc_queries
                .get_metric_with_label_values(&["eth_blockNumber"])
                .unwrap()
                .get(),
            1
        );
        assert_eq!(
            metrics
                .eth_rpc_queries_latency
                .get_metric_with_label_values(&["eth_blockNumber"])
                .unwrap()
                .get_sample_count(),
            1
        );
    }
}
