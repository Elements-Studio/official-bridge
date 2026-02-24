// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Validator health check module
//!
//! Monitors bridge validator nodes for availability by checking their HTTP health endpoints.
//! Only monitors validators with stake=1 (excludes stake=5001 validators).
//!
//! Alert strategy:
//! - First failure: Send warning to Telegram immediately
//! - Still down: Check every 1 minute
//! - If recovered: Send recovery notification
//! - If still down: Send hourly reminder

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use super::telegram::TelegramNotifier;

/// Validator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    pub url: String,
    pub stake: u64,
    #[serde(default)]
    pub name: Option<String>,
}

impl ValidatorConfig {
    pub fn new(url: String, stake: u64) -> Self {
        Self {
            url,
            stake,
            name: None,
        }
    }

    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    /// Check if this validator should be monitored (stake=1, not 5001)
    pub fn should_monitor(&self) -> bool {
        self.stake == 1
    }

    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.url.clone())
    }
}

/// Validator health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

/// Validator health check state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorHealthState {
    pub validator: ValidatorConfig,
    pub status: HealthStatus,
    pub last_check_time: u64, // Unix timestamp
    pub last_healthy_time: Option<u64>,
    pub last_unhealthy_time: Option<u64>,
    pub consecutive_failures: u32,
    pub last_alert_time: Option<u64>,
    pub last_hourly_alert_time: Option<u64>,
}

impl ValidatorHealthState {
    pub fn new(validator: ValidatorConfig) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            validator,
            status: HealthStatus::Unknown,
            last_check_time: now,
            last_healthy_time: None,
            last_unhealthy_time: None,
            consecutive_failures: 0,
            last_alert_time: None,
            last_hourly_alert_time: None,
        }
    }

    /// Duration since last health check
    pub fn time_since_last_check(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Duration::from_secs(now.saturating_sub(self.last_check_time))
    }

    /// Duration since validator went unhealthy
    pub fn downtime_duration(&self) -> Option<Duration> {
        self.last_unhealthy_time.map(|t| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Duration::from_secs(now.saturating_sub(t))
        })
    }

    /// Human-readable downtime
    pub fn downtime_human(&self) -> String {
        match self.downtime_duration() {
            Some(duration) => {
                let secs = duration.as_secs();
                if secs < 60 {
                    format!("{}s", secs)
                } else if secs < 3600 {
                    format!("{}m", secs / 60)
                } else {
                    let hours = secs / 3600;
                    let minutes = (secs % 3600) / 60;
                    format!("{}h {}m", hours, minutes)
                }
            }
            None => "N/A".to_string(),
        }
    }

    /// Check if hourly alert should be sent
    pub fn should_send_hourly_alert(&self) -> bool {
        if self.status != HealthStatus::Unhealthy {
            return false;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        match self.last_hourly_alert_time {
            None => true, // Never sent hourly alert
            Some(last_time) => {
                // Send if 1 hour has passed
                now.saturating_sub(last_time) >= 3600
            }
        }
    }
}

/// Validator health checker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckerConfig {
    /// Check interval in seconds (default: 60)
    #[serde(default = "default_check_interval")]
    pub check_interval_seconds: u64,

    /// HTTP request timeout in seconds (default: 10)
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,

    /// Enable health checker
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_check_interval() -> u64 {
    60 // 1 minute
}

fn default_timeout() -> u64 {
    10
}

fn default_enabled() -> bool {
    true
}

impl Default for HealthCheckerConfig {
    fn default() -> Self {
        Self {
            check_interval_seconds: default_check_interval(),
            timeout_seconds: default_timeout(),
            enabled: default_enabled(),
        }
    }
}

/// Validator health checker
pub struct ValidatorHealthChecker {
    config: HealthCheckerConfig,
    client: Client,
    states: Arc<RwLock<HashMap<String, ValidatorHealthState>>>,
}

impl ValidatorHealthChecker {
    pub fn new(config: HealthCheckerConfig, validators: Vec<ValidatorConfig>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .unwrap();

        let mut states = HashMap::new();
        for validator in validators {
            if validator.should_monitor() {
                let state = ValidatorHealthState::new(validator.clone());
                states.insert(validator.url.clone(), state);
            }
        }

        info!(
            "[Health Checker] Initialized with {} validators (stake=1 only)",
            states.len()
        );

        Self {
            config,
            client,
            states: Arc::new(RwLock::new(states)),
        }
    }

    /// Check health of a single validator
    async fn check_validator_health(&self, url: &str) -> Result<bool> {
        let health_url = if url.ends_with('/') {
            format!("{}health", url)
        } else {
            format!("{}/health", url)
        };

        match self.client.get(&health_url).send().await {
            Ok(resp) if resp.status().is_success() => Ok(true),
            Ok(resp) => {
                warn!(
                    "[Health Checker] Validator {} returned status {}",
                    url,
                    resp.status()
                );
                Ok(false)
            }
            Err(e) => {
                warn!(
                    "[Health Checker] Failed to check validator {}: {:?}",
                    url, e
                );
                Ok(false)
            }
        }
    }

    /// Update validator state after health check
    async fn update_state(
        &self,
        url: &str,
        is_healthy: bool,
        telegram: &Arc<TelegramNotifier>,
    ) -> Result<()> {
        let mut states = self.states.write().await;
        let state = match states.get_mut(url) {
            Some(s) => s,
            None => return Ok(()), // Validator not monitored
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let previous_status = state.status;
        state.last_check_time = now;

        if is_healthy {
            state.last_healthy_time = Some(now);
            state.consecutive_failures = 0;

            // Check if this is a recovery
            if previous_status == HealthStatus::Unhealthy {
                info!(
                    "[Health Checker] Validator {} recovered",
                    state.validator.display_name()
                );

                // Send recovery notification
                telegram
                    .notify_validator_recovered(
                        &state.validator.display_name(),
                        url,
                        &state.downtime_human(),
                    )
                    .await
                    .ok();
            }

            state.status = HealthStatus::Healthy;
        } else {
            state.last_unhealthy_time = Some(now);
            state.consecutive_failures += 1;

            // Check if this is a new failure
            if previous_status != HealthStatus::Unhealthy {
                error!(
                    "[Health Checker] Validator {} went down (consecutive failures: {})",
                    state.validator.display_name(),
                    state.consecutive_failures
                );

                // Send immediate alert
                telegram
                    .notify_validator_down(
                        &state.validator.display_name(),
                        url,
                        state.consecutive_failures,
                    )
                    .await
                    .ok();

                state.last_alert_time = Some(now);
            } else if state.should_send_hourly_alert() {
                // Send hourly reminder if still down
                warn!(
                    "[Health Checker] Validator {} still down (downtime: {})",
                    state.validator.display_name(),
                    state.downtime_human()
                );

                telegram
                    .notify_validator_still_down(
                        &state.validator.display_name(),
                        url,
                        &state.downtime_human(),
                        state.consecutive_failures,
                    )
                    .await
                    .ok();

                state.last_hourly_alert_time = Some(now);
            }

            state.status = HealthStatus::Unhealthy;
        }

        Ok(())
    }

    /// Run health checker loop
    pub async fn run(
        self: Arc<Self>,
        telegram: Arc<TelegramNotifier>,
        cancel: CancellationToken,
    ) -> Result<()> {
        if !self.config.enabled {
            info!("[Health Checker] Disabled, skipping");
            return Ok(());
        }

        let check_interval = Duration::from_secs(self.config.check_interval_seconds);
        let mut interval = tokio::time::interval(check_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!(
            "[Health Checker] Started with interval: {:?}",
            check_interval
        );

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("[Health Checker] Cancelled");
                    break;
                }
                _ = interval.tick() => {
                    self.check_all_validators(&telegram).await;
                }
            }
        }

        Ok(())
    }

    /// Check all validators
    async fn check_all_validators(&self, telegram: &Arc<TelegramNotifier>) {
        let states = self.states.read().await;
        let urls: Vec<String> = states.keys().cloned().collect();
        drop(states);

        for url in urls {
            match self.check_validator_health(&url).await {
                Ok(is_healthy) => {
                    if let Err(e) = self.update_state(&url, is_healthy, telegram).await {
                        error!(
                            "[Health Checker] Failed to update state for {}: {:?}",
                            url, e
                        );
                    }
                }
                Err(e) => {
                    error!("[Health Checker] Health check failed for {}: {:?}", url, e);
                    // Treat errors as unhealthy
                    self.update_state(&url, false, telegram).await.ok();
                }
            }
        }
    }

    /// Get current health summary
    pub async fn get_health_summary(&self) -> HashMap<String, HealthStatus> {
        let states = self.states.read().await;
        states
            .iter()
            .map(|(url, state)| (url.clone(), state.status))
            .collect()
    }

    /// Get detailed validator states
    pub async fn get_validator_states(&self) -> Vec<ValidatorHealthState> {
        let states = self.states.read().await;
        states.values().cloned().collect()
    }
}
