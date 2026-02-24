// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for long-running E2E tests.
//!
//! Design principles:
//! - Each helper function is <= 40 lines
//! - Structured code over comments
//! - Strong assertions with diagnostic context
//! - Unified polling with timeout/interval

use anyhow::Context;
use std::fmt;
use std::time::Duration;
use tokio::time::Instant;

// ---------------------------------------------------------------------------
// Phase enum
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Phase1Setup,
    Phase3BridgeServers,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Phase::Phase1Setup => "Phase 1: setup + health",
            Phase::Phase3BridgeServers => "Phase 3: bridge servers ready",
        };
        write!(f, "{name}")
    }
}

// ---------------------------------------------------------------------------
// Poll configuration
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct PollConfig {
    pub timeout: Duration,
    pub interval: Duration,
}

impl PollConfig {
    pub fn standard() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            interval: Duration::from_millis(500),
        }
    }

    pub fn fast() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            interval: Duration::from_millis(100),
        }
    }
}

// ---------------------------------------------------------------------------
// Diagnostics trait
// ---------------------------------------------------------------------------

pub trait Diagnostics: Send + Sync {
    fn snapshot(&self) -> String;
}

impl<F> Diagnostics for F
where
    F: Fn() -> String + Send + Sync,
{
    fn snapshot(&self) -> String {
        self()
    }
}

// ---------------------------------------------------------------------------
// poll_until helper
// ---------------------------------------------------------------------------

pub async fn poll_until<T, Fut>(
    phase: Phase,
    what: &'static str,
    cfg: PollConfig,
    mut check: impl FnMut() -> Fut,
    diagnostics: Option<&dyn Diagnostics>,
) -> anyhow::Result<T>
where
    Fut: std::future::Future<Output = anyhow::Result<Option<T>>>,
{
    let start = Instant::now();
    let mut last_err: Option<anyhow::Error> = None;

    loop {
        match check().await {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => {}
            Err(e) => last_err = Some(e),
        }

        if start.elapsed() >= cfg.timeout {
            let diag = diagnostics.map(|d| d.snapshot()).unwrap_or_default();
            let err_ctx = format_timeout_error(phase, what, &diag);
            return match last_err {
                Some(e) => Err(e).context(err_ctx),
                None => Err(anyhow::anyhow!("{err_ctx}")),
            };
        }

        tokio::time::sleep(cfg.interval).await;
    }
}

fn format_timeout_error(phase: Phase, what: &str, diag: &str) -> String {
    if diag.is_empty() {
        format!("timeout waiting for {what} ({phase})")
    } else {
        format!("timeout waiting for {what} ({phase}). diagnostics:\n{diag}")
    }
}
