// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Failover-enabled RPC client wrappers
//!
//! Provides RPC clients with automatic failover to backup URLs when the primary fails.

use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::warn;

/// Configuration for failover behavior
#[derive(Debug, Clone)]
pub struct FailoverConfig {
    /// Maximum number of retries per URL before failing over
    pub max_retries_per_url: u32,
    /// Delay between retries
    pub retry_delay: Duration,
    /// Cooldown period before trying a failed URL again
    pub cooldown_period: Duration,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            max_retries_per_url: 3,
            retry_delay: Duration::from_millis(500),
            cooldown_period: Duration::from_secs(60),
        }
    }
}

/// A failover-enabled wrapper for multiple RPC URLs
#[derive(Debug)]
pub struct FailoverRpcUrls {
    urls: Vec<String>,
    current_index: AtomicUsize,
    failed_urls: RwLock<std::collections::HashMap<usize, std::time::Instant>>,
    config: FailoverConfig,
}

impl FailoverRpcUrls {
    pub fn new(urls: Vec<String>) -> Self {
        Self::with_config(urls, FailoverConfig::default())
    }

    pub fn with_config(urls: Vec<String>, config: FailoverConfig) -> Self {
        assert!(!urls.is_empty(), "At least one URL is required");
        Self {
            urls,
            current_index: AtomicUsize::new(0),
            failed_urls: RwLock::new(std::collections::HashMap::new()),
            config,
        }
    }

    /// Get the current URL
    pub fn current_url(&self) -> &str {
        let idx = self.current_index.load(Ordering::SeqCst);
        &self.urls[idx % self.urls.len()]
    }

    /// Get all URLs
    pub fn all_urls(&self) -> &[String] {
        &self.urls
    }

    /// Report a failure and potentially failover to next URL
    pub async fn report_failure(&self) {
        let current = self.current_index.load(Ordering::SeqCst);
        let next = (current + 1) % self.urls.len();

        // Mark current URL as failed
        {
            let mut failed = self.failed_urls.write().await;
            failed.insert(current, std::time::Instant::now());
        }

        // Try to find a non-failed URL
        for offset in 1..=self.urls.len() {
            let candidate = (current + offset) % self.urls.len();
            let failed = self.failed_urls.read().await;

            if let Some(failed_time) = failed.get(&candidate) {
                if failed_time.elapsed() < self.config.cooldown_period {
                    continue; // Still in cooldown
                }
            }

            // This URL is available
            if self
                .current_index
                .compare_exchange(current, candidate, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                warn!(
                    "[Failover] Switched from {} to {}",
                    self.urls[current], self.urls[candidate]
                );
                return;
            }
        }

        // All URLs are in cooldown, just rotate anyway
        self.current_index.store(next, Ordering::SeqCst);
        warn!(
            "[Failover] All URLs in cooldown, rotating to {}",
            self.urls[next]
        );
    }

    /// Report a success - clears the failure state for current URL
    pub async fn report_success(&self) {
        let current = self.current_index.load(Ordering::SeqCst);
        let mut failed = self.failed_urls.write().await;
        failed.remove(&current);
    }

    /// Execute a function with failover support
    pub async fn with_failover<F, Fut, T>(&self, mut f: F) -> Result<T>
    where
        F: FnMut(&str) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut last_error = None;
        let total_attempts = self.urls.len() * self.config.max_retries_per_url as usize;

        for attempt in 0..total_attempts {
            let url = self.current_url();

            match f(url).await {
                Ok(result) => {
                    self.report_success().await;
                    return Ok(result);
                }
                Err(e) => {
                    last_error = Some(e);
                    warn!(
                        "[Failover] Request failed on {} (attempt {}/{})",
                        url,
                        attempt + 1,
                        total_attempts
                    );

                    // Failover after max retries per URL
                    if (attempt + 1) % self.config.max_retries_per_url as usize == 0 {
                        self.report_failure().await;
                    } else {
                        tokio::time::sleep(self.config.retry_delay).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("All RPC URLs failed")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_failover_urls_current() {
        let urls = FailoverRpcUrls::new(vec![
            "http://rpc1".to_string(),
            "http://rpc2".to_string(),
            "http://rpc3".to_string(),
        ]);

        assert_eq!(urls.current_url(), "http://rpc1");
    }

    #[tokio::test]
    async fn test_failover_urls_rotation() {
        let urls = FailoverRpcUrls::new(vec![
            "http://rpc1".to_string(),
            "http://rpc2".to_string(),
            "http://rpc3".to_string(),
        ]);

        assert_eq!(urls.current_url(), "http://rpc1");

        urls.report_failure().await;
        assert_eq!(urls.current_url(), "http://rpc2");

        urls.report_failure().await;
        assert_eq!(urls.current_url(), "http://rpc3");

        urls.report_failure().await;
        // Wraps around
        assert_eq!(urls.current_url(), "http://rpc1");
    }

    #[tokio::test]
    async fn test_failover_with_failover_success() {
        let urls = FailoverRpcUrls::new(vec!["http://rpc1".to_string()]);

        let result = urls
            .with_failover(|_| async { Ok::<_, anyhow::Error>(42) })
            .await;

        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_failover_with_failover_retry() {
        let urls = FailoverRpcUrls::with_config(
            vec!["http://rpc1".to_string(), "http://rpc2".to_string()],
            FailoverConfig {
                max_retries_per_url: 1,
                retry_delay: Duration::from_millis(1),
                cooldown_period: Duration::from_secs(0),
            },
        );

        let call_count = Arc::new(AtomicUsize::new(0));

        let mut attempts = 0;
        let result = urls
            .with_failover(|url| {
                attempts += 1;
                let url_owned = url.to_string();
                let call_count = call_count.clone();
                async move {
                    let count = call_count.fetch_add(1, Ordering::SeqCst);
                    if count < 1 {
                        Err(anyhow!("Simulated failure"))
                    } else {
                        Ok(url_owned)
                    }
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "http://rpc2");
        assert!(call_count.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn test_single_url_no_failover() {
        let urls = FailoverRpcUrls::new(vec!["http://rpc1".to_string()]);

        // Even with a single URL, it should retry
        urls.report_failure().await;
        assert_eq!(urls.current_url(), "http://rpc1");
    }
}
