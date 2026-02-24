// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The StarcoinBridgeStatus observable monitors whether the Starcoin Bridge is paused.

use crate::starcoin_bridge_client::StarcoinBridgeClient;
use crate::starcoin_bridge_watchdog::Observable;
use async_trait::async_trait;
use prometheus::IntGauge;
use std::sync::Arc;

use tokio::time::Duration;
use tracing::{error, info};

pub struct StarcoinBridgeStatus {
    starcoin_bridge_client: Arc<StarcoinBridgeClient>,
    metric: IntGauge,
}

impl StarcoinBridgeStatus {
    pub fn new(starcoin_bridge_client: Arc<StarcoinBridgeClient>, metric: IntGauge) -> Self {
        Self {
            starcoin_bridge_client,
            metric,
        }
    }
}

#[async_trait]
impl Observable for StarcoinBridgeStatus {
    fn name(&self) -> &str {
        "StarcoinBridgeStatus"
    }

    async fn observe_and_report(&self) {
        let status = self.starcoin_bridge_client.is_bridge_paused().await;
        match status {
            Ok(status) => {
                self.metric.set(status as i64);
                info!("Starcoin Bridge Status: {:?}", status);
            }
            Err(e) => {
                error!("Error getting starcoin bridge status: {:?}", e);
            }
        }
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(10)
    }
}
