// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use fastcrypto::traits::KeyPair;
use starcoin_bridge::config::BridgeNodeConfig;
use starcoin_bridge::node::run_bridge_node;
use starcoin_bridge::server::BridgeNodePublicMetadata;
use starcoin_bridge_config::Config;
use starcoin_bridge_metrics_push_client::{start_metrics_push_task, MetricsPushConfig};
use starcoin_metrics::start_prometheus_server;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};
use tracing::info;

// Define the `GIT_REVISION` and `VERSION` consts
bin_version::bin_version!();

#[derive(Parser)]
#[clap(rename_all = "kebab-case")]
#[clap(name = env!("CARGO_BIN_NAME"))]
#[clap(version = VERSION)]
struct Args {
    #[clap(long)]
    pub config_path: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = BridgeNodeConfig::load(&args.config_path).unwrap();

    // JSON-RPC client is fully async compatible - no runtime conflicts!

    let metrics_address =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), config.metrics_port);
    let registry_service = start_prometheus_server(metrics_address);
    let prometheus_registry = registry_service.default_registry();

    starcoin_metrics::init_metrics(&prometheus_registry);
    info!("Metrics server started at port {}", config.metrics_port);

    // Init logging
    let (_log_guard, _filter_handle) = telemetry_subscribers::TelemetryConfig::new()
        .with_env()
        .with_prom_registry(&prometheus_registry)
        .init();

    let metadata = BridgeNodePublicMetadata::new(VERSION, config.metrics_key_pair.public().clone());

    // Start metrics push task if configured
    if let Some(metrics_config) = &config.metrics {
        let push_config = MetricsPushConfig {
            push_interval_seconds: metrics_config.push_interval_seconds.unwrap_or(60),
            push_url: metrics_config.push_url.clone(),
            auth_username: metrics_config.auth_username.clone(),
            auth_password: metrics_config.auth_password.clone(),
        };
        start_metrics_push_task(push_config, registry_service.clone());
    }

    let handle = run_bridge_node(config, metadata, prometheus_registry).await?;
    handle
        .await
        .map_err(|e| anyhow::anyhow!("Task join error: {}", e))
}
