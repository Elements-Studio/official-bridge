// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::config::WatchdogConfig;
use crate::metered_eth_provider::MeteredEthHttpProvier;
use crate::starcoin_bridge_client::StarcoinBridgeClient;
use crate::starcoin_bridge_watchdog::eth_bridge_status::EthBridgeStatus;
use crate::starcoin_bridge_watchdog::eth_vault_balance::{EthereumVaultBalance, VaultAsset};
use crate::starcoin_bridge_watchdog::metrics::WatchdogMetrics;
use crate::starcoin_bridge_watchdog::starcoin_bridge_status::StarcoinBridgeStatus;
use crate::starcoin_bridge_watchdog::{BridgeWatchDog, Observable};
use crate::utils::get_eth_contract_addresses;
use crate::{
    config::BridgeNodeConfig,
    events::init_all_struct_tags,
    metrics::BridgeMetrics,
    server::{handler::BridgeRequestHandler, run_server, BridgeNodePublicMetadata},
};
use ethers::providers::Provider;
use ethers::types::Address as EthAddress;
use starcoin_metrics::spawn_logged_monitored_task;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::task::JoinHandle;

pub async fn run_bridge_node(
    config: BridgeNodeConfig,
    metadata: BridgeNodePublicMetadata,
    prometheus_registry: prometheus::Registry,
) -> anyhow::Result<JoinHandle<()>> {
    init_all_struct_tags();
    let metrics = Arc::new(BridgeMetrics::new(&prometheus_registry));
    let start_time = std::time::Instant::now();

    // Start server uptime tracking task
    let uptime_metrics = metrics.clone();
    tokio::spawn(async move {
        loop {
            uptime_metrics
                .server_uptime_seconds
                .set(start_time.elapsed().as_secs() as i64);
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    });

    let watchdog_config = config.watchdog_config.clone();
    let server_config = config.validate(metrics.clone()).await?;
    let starcoin_bridge_chain_identifier = server_config
        .starcoin_bridge_client
        .get_chain_identifier()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get starcoin chain identifier: {:?}", e))?;
    let eth_chain_identifier = server_config
        .eth_client
        .get_chain_id()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get eth chain identifier: {:?}", e))?;
    prometheus_registry
        .register(starcoin_metrics::bridge_uptime_metric(
            "bridge",
            metadata.version,
            &starcoin_bridge_chain_identifier,
            &eth_chain_identifier.to_string(),
            false, // Bridge server is validator-only, no client
        ))
        .unwrap();

    let mut handles = vec![];

    // Start watchdog
    let eth_provider = server_config.eth_client.provider();
    let eth_bridge_proxy_address = server_config.eth_bridge_proxy_address;
    let starcoin_bridge_client = server_config.starcoin_bridge_client.clone();
    handles.push(spawn_logged_monitored_task!(start_watchdog(
        watchdog_config,
        &prometheus_registry,
        eth_provider,
        eth_bridge_proxy_address,
        starcoin_bridge_client
    )));

    // Start Server
    let socket_address = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        server_config.server_listen_port,
    );
    Ok(run_server(
        &socket_address,
        BridgeRequestHandler::new(
            server_config.key,
            server_config.starcoin_bridge_client,
            server_config.eth_client,
            metrics.clone(),
        ),
        metrics,
        Arc::new(metadata),
    ))
}

async fn start_watchdog(
    watchdog_config: Option<WatchdogConfig>,
    registry: &prometheus::Registry,
    eth_provider: Arc<Provider<MeteredEthHttpProvier>>,
    eth_bridge_proxy_address: EthAddress,
    starcoin_bridge_client: Arc<StarcoinBridgeClient>,
) {
    // Skip watchdog entirely if not configured
    // This avoids unnecessary RPC calls during tests
    if watchdog_config.is_none() {
        tracing::info!("Watchdog not configured, skipping initialization");
        return;
    }

    let watchdog_metrics = WatchdogMetrics::new(registry);
    let (_, _, vault_address, _, weth_address, usdt_address, wbtc_address, lbtc_address) =
        get_eth_contract_addresses(eth_bridge_proxy_address, &eth_provider)
            .await
            .unwrap_or_else(|e| panic!("get_eth_contract_addresses should not fail: {}", e));

    let eth_vault_balance = EthereumVaultBalance::new(
        eth_provider.clone(),
        vault_address,
        weth_address,
        VaultAsset::WETH,
        watchdog_metrics.eth_vault_balance.clone(),
    )
    .await
    .unwrap_or_else(|e| panic!("Failed to create eth vault balance: {}", e));

    let usdt_vault_balance = EthereumVaultBalance::new(
        eth_provider.clone(),
        vault_address,
        usdt_address,
        VaultAsset::USDT,
        watchdog_metrics.usdt_vault_balance.clone(),
    )
    .await
    .unwrap_or_else(|e| panic!("Failed to create usdt vault balance: {}", e));

    let wbtc_vault_balance = EthereumVaultBalance::new(
        eth_provider.clone(),
        vault_address,
        wbtc_address,
        VaultAsset::WBTC,
        watchdog_metrics.wbtc_vault_balance.clone(),
    )
    .await
    .unwrap_or_else(|e| panic!("Failed to create wbtc vault balance: {}", e));

    let lbtc_vault_balance = if !lbtc_address.is_zero() {
        Some(
            EthereumVaultBalance::new(
                eth_provider.clone(),
                vault_address,
                lbtc_address,
                VaultAsset::LBTC,
                watchdog_metrics.lbtc_vault_balance.clone(),
            )
            .await
            .unwrap_or_else(|e| panic!("Failed to create lbtc vault balance: {}", e)),
        )
    } else {
        None
    };

    let eth_bridge_status = EthBridgeStatus::new(
        eth_provider,
        eth_bridge_proxy_address,
        watchdog_metrics.eth_bridge_paused.clone(),
    );

    let starcoin_bridge_status = StarcoinBridgeStatus::new(
        starcoin_bridge_client.clone(),
        watchdog_metrics.starcoin_bridge_paused.clone(),
    );

    let mut observables: Vec<Box<dyn Observable + Send + Sync>> = vec![
        Box::new(eth_vault_balance),
        Box::new(usdt_vault_balance),
        Box::new(wbtc_vault_balance),
        Box::new(eth_bridge_status),
        Box::new(starcoin_bridge_status),
    ];

    // Add lbtc_vault_balance if it's available
    if let Some(balance) = lbtc_vault_balance {
        observables.push(Box::new(balance));
    }

    let _ = watchdog_config; // Silence unused warning

    BridgeWatchDog::new(observables).run().await
}
