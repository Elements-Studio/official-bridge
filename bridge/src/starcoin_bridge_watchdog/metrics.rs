// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

use prometheus::{register_int_gauge_with_registry, IntGauge, Registry};

#[derive(Clone, Debug)]
pub struct WatchdogMetrics {
    pub eth_vault_balance: IntGauge,
    pub usdt_vault_balance: IntGauge,
    pub wbtc_vault_balance: IntGauge,
    pub lbtc_vault_balance: IntGauge,
    pub eth_bridge_paused: IntGauge,
    pub starcoin_bridge_paused: IntGauge,
}

impl WatchdogMetrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            eth_vault_balance: register_int_gauge_with_registry!(
                "bridge_eth_vault_balance",
                "Current balance of eth vault",
                registry,
            )
            .unwrap(),
            usdt_vault_balance: register_int_gauge_with_registry!(
                "bridge_usdt_vault_balance",
                "Current balance of usdt eth vault",
                registry,
            )
            .unwrap(),
            wbtc_vault_balance: register_int_gauge_with_registry!(
                "bridge_wbtc_vault_balance",
                "Current balance of wbtc eth vault",
                registry,
            )
            .unwrap(),
            lbtc_vault_balance: register_int_gauge_with_registry!(
                "bridge_lbtc_vault_balance",
                "Current balance of lbtc eth vault",
                registry,
            )
            .unwrap(),
            eth_bridge_paused: register_int_gauge_with_registry!(
                "bridge_eth_bridge_paused",
                "Whether the eth bridge is paused",
                registry,
            )
            .unwrap(),
            starcoin_bridge_paused: register_int_gauge_with_registry!(
                "bridge_starcoin_bridge_paused",
                "Whether the starcoin bridge is paused",
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
