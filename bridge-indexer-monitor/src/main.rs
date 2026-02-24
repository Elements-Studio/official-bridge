// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Starcoin Bridge Indexer/Monitor
//!
//! ## Architecture (Simplified)
//!
//! ```text
//! ┌─────────────────────┐    ┌─────────────────────┐
//! │ StarcoinChainSyncer │    │   EthChainSyncer    │
//! └──────────┬──────────┘    └──────────┬──────────┘
//!            │                          │
//!            ▼                          ▼
//!    ┌───────┴───────┐          ┌───────┴───────┐
//!    │               │          │               │
//!    ▼               ▼          ▼               ▼
//! StcEventHandler  Monitor   EthIndexer     Monitor
//! (PostgreSQL)   (alerts)   (PostgreSQL)   (alerts)
//! ```
//!
//! ## Finality-Aware Processing
//!
//! - Unfinalized events: stored in TransferTracker (memory only)
//! - Finalized events: written to PostgreSQL
//! - API queries: merge DB + memory results

use anyhow::Context;
use clap::Parser;
use prometheus::Registry;
use starcoin_bridge::metrics::BridgeMetrics;
use starcoin_bridge::pending_events::TransferTracker;
use starcoin_bridge_indexer_alt_metrics::{MetricsArgs, MetricsService};
use starcoin_bridge_indexer_monitor::api::{
    create_api_router, init_global_quota_cache_with_config, refresh_fee_estimates, ApiState,
    QuotaCacheConfig,
};
use starcoin_bridge_indexer_monitor::caught_up::{
    create_caught_up_coordinator, SharedCaughtUpCoordinator,
};
use starcoin_bridge_indexer_monitor::eth_indexer::{start_unified_eth_indexer, EthIndexerConfig};
use starcoin_bridge_indexer_monitor::handlers::{
    run_stc_event_handler, StcEventHandler, StcEventHandlerConfig,
};
use starcoin_bridge_indexer_monitor::metrics::BridgeIndexerMetrics;
use starcoin_bridge_indexer_monitor::monitor;
use starcoin_bridge_indexer_monitor::network::NetworkType;
use starcoin_bridge_indexer_monitor::security_monitor::{
    start_security_monitor, SecurityMonitorConfig, SharedSecurityMonitor,
};
use starcoin_bridge_indexer_monitor::stc_indexer::{
    start_starcoin_syncer_with_ready_signal, StarcoinSyncerConfig, StarcoinSyncerResult,
};
use starcoin_bridge_indexer_monitor::telegram::{
    create_telegram_notifier, SharedTelegramNotifier, TelegramConfig,
};
use starcoin_bridge_pg_db::Db;
use starcoin_bridge_pg_db::DbArgs;
use starcoin_bridge_schema::MIGRATIONS as BRIDGE_SCHEMA_MIGRATIONS;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;

// ============================================================================
// CLI Arguments
// ============================================================================

#[derive(Parser)]
#[clap(rename_all = "kebab-case", author, version)]
struct Args {
    #[command(flatten)]
    db_args: DbArgs,
    #[clap(env, long, default_value = "0.0.0.0:9184")]
    metrics_address: SocketAddr,
    #[clap(
        env,
        long,
        default_value = "postgres://postgres:postgrespw@localhost:5432/bridge"
    )]
    database_url: Url,
    #[clap(env, long)]
    starcoin_rpc_url: String,
    #[clap(env, long)]
    bridge_address: String,
    #[clap(env, long, default_value = "0")]
    starcoin_start_block: u64,
    #[clap(env, long)]
    eth_rpc_url: Option<String>,
    #[clap(env, long)]
    eth_bridge_address: Option<String>,
    #[clap(env, long)]
    eth_start_block: Option<u64>,
    #[clap(env, long)]
    api_address: Option<SocketAddr>,
    #[clap(env, long)]
    monitor_config: Option<PathBuf>,
}

// ============================================================================
// Network Detection
// ============================================================================

async fn detect_starcoin_network(rpc_url: &str) -> anyhow::Result<NetworkType> {
    #[derive(serde::Deserialize)]
    struct JsonRpcResponse {
        result: Option<ChainInfo>,
    }
    #[derive(serde::Deserialize)]
    struct ChainInfo {
        chain_id: u64,
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let response = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "chain.info",
            "params": [],
            "id": 1
        }))
        .send()
        .await?;

    let rpc_response: JsonRpcResponse = response.json().await?;
    let chain_info = rpc_response
        .result
        .ok_or_else(|| anyhow::anyhow!("No result in chain.info response"))?;

    Ok(NetworkType::from_starcoin_chain_id(chain_info.chain_id))
}

fn detect_network_with_fallback(result: anyhow::Result<NetworkType>) -> NetworkType {
    match result {
        Ok(net) => {
            tracing::info!("Detected network: {:?}", net);
            net
        }
        Err(e) => {
            tracing::warn!("Failed to detect network, defaulting to Local: {}", e);
            NetworkType::Local
        }
    }
}

// ============================================================================
// API Server
// ============================================================================

async fn start_api_server(
    addr: SocketAddr,
    db: Db,
    network: NetworkType,
    eth_rpc_url: Option<String>,
    eth_bridge_address: Option<String>,
    starcoin_rpc_url: String,
    bridge_address: String,
    monitor_config: Option<&PathBuf>,
    transfer_tracker: Arc<TransferTracker>,
) -> anyhow::Result<JoinHandle<()>> {
    let monitor_cfg =
        monitor_config.and_then(|p| monitor::config::MonitorConfig::from_file(p).ok());
    let claim_delay = monitor_cfg
        .as_ref()
        .map(|c| c.claim_delay_seconds)
        .unwrap_or(60);

    let quota_config = QuotaCacheConfig {
        eth_rpc_url: eth_rpc_url.clone(),
        eth_bridge_address: eth_bridge_address.and_then(|s| s.parse().ok()),
        starcoin_rpc_url: Some(starcoin_rpc_url.clone()),
        starcoin_bridge_address: Some(bridge_address),
        starcoin_chain_id: network.to_bridge_chain_id(),
        eth_chain_id: network.to_eth_chain_id(),
    };

    let quota_cache = init_global_quota_cache_with_config(quota_config);
    let eth_rpc = eth_rpc_url.unwrap_or_default();

    // Use new_with_tracker to include the transfer tracker for memory queries
    let api_state = ApiState::new_with_tracker(
        db.clone(),
        quota_cache,
        claim_delay,
        eth_rpc.clone(),
        starcoin_rpc_url.clone(),
        transfer_tracker,
        network,
    );

    spawn_fee_cache_init(db, api_state.fee_cache.clone(), eth_rpc, starcoin_rpc_url);

    let app = create_api_router(api_state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("API server listening on {}", addr);

    Ok(tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("API server error: {:?}", e);
        }
    }))
}

fn spawn_fee_cache_init(
    db: Db,
    fee_cache: Arc<starcoin_bridge_indexer_monitor::api::FeeCache>,
    eth_rpc: String,
    stc_rpc: String,
) {
    tokio::spawn(async move {
        tracing::info!("Initializing fee cache from database...");
        refresh_fee_estimates(&db, &fee_cache, &eth_rpc, &stc_rpc).await;
        tracing::info!("Fee cache initialized");
    });
}

// ============================================================================
// Starcoin Syncer
// ============================================================================

async fn start_starcoin_syncer(
    db: &Db,
    config: StarcoinSyncerConfig,
    cancel: CancellationToken,
) -> anyhow::Result<(StarcoinSyncerResult, Option<oneshot::Sender<()>>)> {
    let (result, ready_sender, _) =
        start_starcoin_syncer_with_ready_signal(config, db, cancel).await?;
    Ok((result, ready_sender))
}

fn start_stc_event_handler(
    db: Db,
    syncer_result: StarcoinSyncerResult,
    config: StcEventHandlerConfig,
    metrics: Arc<BridgeIndexerMetrics>,
    cancel: CancellationToken,
    transfer_tracker: Arc<TransferTracker>,
    security_monitor: Option<SharedSecurityMonitor>,
) -> Vec<JoinHandle<()>> {
    let handler = StcEventHandler::new(db, config, metrics, transfer_tracker, security_monitor);
    let handler_handle = run_stc_event_handler(handler, syncer_result.event_rx, cancel);

    let mut handles = syncer_result.handles;
    handles.push(handler_handle);
    handles
}

// ============================================================================
// ETH Indexer
// ============================================================================

async fn start_eth_indexer(
    eth_rpc_url: Option<String>,
    eth_bridge_address: Option<String>,
    eth_start_block: Option<u64>,
    network: NetworkType,
    db: Db,
    metrics: Arc<BridgeMetrics>,
    transfer_tracker: Arc<TransferTracker>,
    telegram: SharedTelegramNotifier,
    caught_up_coordinator: SharedCaughtUpCoordinator,
    security_monitor: Option<SharedSecurityMonitor>,
) -> anyhow::Result<Vec<JoinHandle<()>>> {
    let (eth_rpc, eth_addr) = match (eth_rpc_url, eth_bridge_address) {
        (Some(rpc), Some(addr)) => (rpc, addr),
        _ => {
            tracing::warn!(
                "ETH indexer not started (missing --eth-rpc-url or --eth-bridge-address)"
            );
            return Ok(vec![]);
        }
    };

    let start_block = eth_start_block.ok_or_else(|| {
        anyhow::anyhow!("--eth-start-block is required when --eth-rpc-url is provided")
    })?;

    let result = start_unified_eth_indexer(
        EthIndexerConfig {
            eth_rpc_url: eth_rpc,
            eth_bridge_address: eth_addr,
            eth_start_block: start_block,
            network,
            finality_blocks: None,
            enable_reorg_detection: None,
            transfer_tracker: Some(transfer_tracker),
            telegram: Some(telegram),
            caught_up_tracker: Some(caught_up_coordinator.eth_tracker()),
            security_monitor,
        },
        db,
        metrics,
    )
    .await?;

    tracing::info!("ETH indexer started");
    Ok(result.handles)
}

// ============================================================================
// Telegram Notifier
// ============================================================================

/// Create TelegramNotifier from monitor config
fn create_telegram_notifier_from_config(config_path: Option<&PathBuf>) -> SharedTelegramNotifier {
    let config = config_path
        .and_then(|p| monitor::config::MonitorConfig::from_file(p).ok())
        .map(|c| TelegramConfig {
            bot_token: c.telegram.bot_token,
            chat_id: c.telegram.chat_id,
            emergency_mention_users: c.telegram.emergency_mention_users,
        })
        .unwrap_or_default();

    create_telegram_notifier(config)
}

// ============================================================================
// Security Monitor
// ============================================================================

/// Create SecurityMonitor from config
async fn create_security_monitor(
    config_path: Option<&PathBuf>,
    db: Db,
    transfer_tracker: Arc<TransferTracker>,
    telegram: SharedTelegramNotifier,
    network: NetworkType,
    cancel: CancellationToken,
) -> Option<SharedSecurityMonitor> {
    let monitor_cfg =
        config_path.and_then(|p| monitor::config::MonitorConfig::from_file(p).ok())?;

    // Get emergency pause config if available
    let emergency_cfg = monitor_cfg.emergency_pause;

    // Determine if we can execute pause
    let can_execute = emergency_cfg
        .as_ref()
        .map(|e| {
            e.bridge_cli_config_path.is_some()
                && !e.eth_signatures.is_empty()
                && !e.starcoin_signatures.is_empty()
        })
        .unwrap_or(false);

    // Get pre-signed pause signatures from config
    let (
        bridge_cli_config_path,
        eth_pause_signatures,
        stc_pause_signatures,
        eth_pause_nonce,
        stc_pause_nonce,
    ) = if let Some(ref e) = emergency_cfg {
        (
            e.bridge_cli_config_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            if e.eth_signatures.is_empty() {
                None
            } else {
                Some(e.eth_signatures.join(","))
            },
            if e.starcoin_signatures.is_empty() {
                None
            } else {
                Some(e.starcoin_signatures.join(","))
            },
            Some(e.eth_nonce),      // nonce=0 is valid (initial nonce)
            Some(e.starcoin_nonce), // nonce=0 is valid (initial nonce)
        )
    } else {
        (None, None, None, None, None)
    };

    let security_config = SecurityMonitorConfig {
        eth_chain_id: Some(network.to_eth_chain_id() as u8),
        stc_chain_id: Some(network.to_bridge_chain_id() as u8),
        can_execute,
        bridge_cli_config_path,
        eth_pause_signatures,
        stc_pause_signatures,
        eth_pause_nonce,
        stc_pause_nonce,
    };

    match start_security_monitor(
        security_config,
        db,
        transfer_tracker,
        network,
        Some(telegram),
        cancel,
    )
    .await
    {
        Ok(result) => {
            tracing::info!("[Main] SecurityMonitor created (inactive until chains caught up)");
            Some(result.monitor)
        }
        Err(e) => {
            tracing::warn!("[Main] Failed to create SecurityMonitor: {:?}", e);
            None
        }
    }
}

fn signal_syncer_ready(ready_sender: Option<oneshot::Sender<()>>) {
    if let Some(tx) = ready_sender {
        if tx.send(()).is_err() {
            tracing::warn!("Failed to send ready signal (receiver dropped)");
        } else {
            tracing::info!("Sent ready signal to Starcoin syncer - broadcasting enabled");
        }
    }
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_env()
        .init();

    // Validate STARCOIN_BRIDGE_CLI environment variable at startup
    if let Err(e) =
        starcoin_bridge_indexer_monitor::security_monitor::pause_executor::validate_bridge_cli_path(
        )
    {
        tracing::error!("[Main] {}", e);
        tracing::error!("[Main] Please set STARCOIN_BRIDGE_CLI environment variable to the path of starcoin-bridge-cli binary");
        return Err(e);
    }
    tracing::info!(
        "[Main] STARCOIN_BRIDGE_CLI validated: {}",
        std::env::var("STARCOIN_BRIDGE_CLI").unwrap()
    );

    let args = Args::parse();
    let cancel = CancellationToken::new();

    // Initialize metrics and database
    let (_, metrics_service, bridge_indexer_metrics, bridge_metrics) =
        init_metrics(&args.metrics_address, cancel.child_token())?;

    let network =
        detect_network_with_fallback(detect_starcoin_network(&args.starcoin_rpc_url).await);

    let db = init_database(&args.database_url, &args.db_args).await?;
    let bridge_addr = parse_bridge_address(&args.bridge_address)?;

    // Create shared TransferTracker for pending (unfinalized) events
    let transfer_tracker = Arc::new(TransferTracker::new());
    tracing::info!("Created shared TransferTracker for pending events");

    // Create Telegram notifier (standalone, can be used immediately)
    let telegram = create_telegram_notifier_from_config(args.monitor_config.as_ref());

    // Create SecurityMonitor (will be activated after both chains caught up)
    let security_monitor = create_security_monitor(
        args.monitor_config.as_ref(),
        db.clone(),
        transfer_tracker.clone(),
        telegram.clone(),
        network,
        cancel.clone(),
    )
    .await;

    // Start API server early for health checks (with TransferTracker)
    let api_handle = start_api_if_configured(&args, &db, network, transfer_tracker.clone()).await?;

    // Create caught-up coordinator to track when both chains are synced
    let caught_up_coordinator = create_caught_up_coordinator();

    // Start Starcoin syncer (with TransferTracker, Telegram and caught-up tracking)
    let (stc_handles, stc_ready_sender) = start_starcoin_components(
        &args,
        &db,
        bridge_addr,
        network,
        bridge_indexer_metrics,
        cancel.clone(),
        transfer_tracker.clone(),
        telegram.clone(),
        caught_up_coordinator.clone(),
        security_monitor.clone(),
    )
    .await?;

    // Start ETH indexer (with TransferTracker, Telegram and caught-up tracking)
    let eth_handles = start_eth_indexer(
        args.eth_rpc_url.clone(),
        args.eth_bridge_address.clone(),
        args.eth_start_block,
        network,
        db,
        bridge_metrics,
        transfer_tracker,
        telegram,
        caught_up_coordinator.clone(),
        security_monitor.clone(),
    )
    .await?;

    // Signal Starcoin syncer ready to broadcast
    signal_syncer_ready(stc_ready_sender);

    // Activate SecurityMonitor after both chains are caught up
    if let Some(ref monitor) = security_monitor {
        let monitor_clone = monitor.clone();
        let monitor_clone2 = monitor.clone();
        let coordinator = caught_up_coordinator.clone();
        tokio::spawn(async move {
            tracing::info!(
                "[Main] Waiting for both chains to catch up before activating SecurityMonitor..."
            );
            coordinator.wait_all_caught_up().await;
            tracing::info!("[Main] Both chains caught up, activating SecurityMonitor");
            monitor_clone.activate();

            // Spawn a task to process deferred alerts after grace period
            tokio::spawn(async move {
                monitor_clone2.process_deferred_alerts().await;
            });
        });
    }

    // Wait for all tasks
    wait_for_tasks(metrics_service, stc_handles, eth_handles, api_handle).await?;
    cancel.cancel();
    Ok(())
}

fn parse_bridge_address(
    addr: &str,
) -> anyhow::Result<move_core_types::account_address::AccountAddress> {
    move_core_types::account_address::AccountAddress::from_hex_literal(addr)
        .context("Failed to parse bridge address")
}

async fn start_starcoin_components(
    args: &Args,
    db: &Db,
    bridge_addr: move_core_types::account_address::AccountAddress,
    network: NetworkType,
    metrics: Arc<BridgeIndexerMetrics>,
    cancel: CancellationToken,
    transfer_tracker: Arc<TransferTracker>,
    telegram: SharedTelegramNotifier,
    caught_up_coordinator: SharedCaughtUpCoordinator,
    security_monitor: Option<SharedSecurityMonitor>,
) -> anyhow::Result<(Vec<JoinHandle<()>>, Option<oneshot::Sender<()>>)> {
    let stc_config = build_stc_syncer_config(args, telegram.clone(), caught_up_coordinator);
    let (syncer_result, ready_sender) =
        start_starcoin_syncer(db, stc_config, cancel.clone()).await?;

    let handler_config = build_stc_handler_config(args, bridge_addr, network, telegram);
    let handles = start_stc_event_handler(
        db.clone(),
        syncer_result,
        handler_config,
        metrics,
        cancel,
        transfer_tracker,
        security_monitor,
    );

    tracing::info!("Starcoin syncer started");
    Ok((handles, ready_sender))
}

// ============================================================================
// Initialization Helpers
// ============================================================================

fn init_metrics(
    metrics_address: &SocketAddr,
    cancel: CancellationToken,
) -> anyhow::Result<(
    Registry,
    MetricsService,
    Arc<BridgeIndexerMetrics>,
    Arc<BridgeMetrics>,
)> {
    let registry = Registry::new_custom(Some("bridge".into()), None)
        .context("Failed to create Prometheus registry")?;
    starcoin_metrics::init_metrics(&registry);

    let indexer_metrics = BridgeIndexerMetrics::new(&registry);
    let bridge_metrics = Arc::new(BridgeMetrics::new(&registry));
    let service = MetricsService::new(
        MetricsArgs {
            metrics_address: *metrics_address,
        },
        registry.clone(),
        cancel,
    );

    Ok((registry, service, indexer_metrics, bridge_metrics))
}

async fn init_database(database_url: &Url, db_args: &DbArgs) -> anyhow::Result<Db> {
    let db = Db::for_write(database_url.clone(), db_args.clone()).await?;
    db.run_migrations(Some(&BRIDGE_SCHEMA_MIGRATIONS))
        .await
        .context("Failed to run database migrations")?;
    tracing::info!("Database migrations completed");
    Ok(db)
}

async fn start_api_if_configured(
    args: &Args,
    db: &Db,
    network: NetworkType,
    transfer_tracker: Arc<TransferTracker>,
) -> anyhow::Result<Option<JoinHandle<()>>> {
    match args.api_address {
        Some(addr) => Ok(Some(
            start_api_server(
                addr,
                db.clone(),
                network,
                args.eth_rpc_url.clone(),
                args.eth_bridge_address.clone(),
                args.starcoin_rpc_url.clone(),
                args.bridge_address.clone(),
                args.monitor_config.as_ref(),
                transfer_tracker,
            )
            .await?,
        )),
        None => Ok(None),
    }
}

fn build_stc_syncer_config(
    args: &Args,
    telegram: SharedTelegramNotifier,
    caught_up_coordinator: SharedCaughtUpCoordinator,
) -> StarcoinSyncerConfig {
    StarcoinSyncerConfig {
        rpc_url: args.starcoin_rpc_url.clone(),
        bridge_address: args.bridge_address.clone(),
        start_block: args.starcoin_start_block,
        poll_interval: std::time::Duration::from_secs(1),
        finality_blocks: 16,
        enable_reorg_detection: true,
        ready_signal: None,
        telegram: Some(telegram),
        caught_up_tracker: Some(caught_up_coordinator.stc_tracker()),
    }
}

fn build_stc_handler_config(
    args: &Args,
    bridge_addr: move_core_types::account_address::AccountAddress,
    network: NetworkType,
    telegram: SharedTelegramNotifier,
) -> StcEventHandlerConfig {
    StcEventHandlerConfig {
        bridge_address: bridge_addr,
        network,
        starcoin_rpc_url: args.starcoin_rpc_url.clone(),
        eth_rpc_url: args.eth_rpc_url.clone().unwrap_or_default(),
        telegram: Some(telegram),
    }
}

async fn wait_for_tasks(
    metrics_service: MetricsService,
    stc_handles: Vec<JoinHandle<()>>,
    eth_handles: Vec<JoinHandle<()>>,
    api_handle: Option<JoinHandle<()>>,
) -> anyhow::Result<()> {
    let h_metrics = metrics_service.run().await?;

    let mut all_handles = vec![h_metrics];
    all_handles.extend(stc_handles);
    all_handles.extend(eth_handles);
    if let Some(h) = api_handle {
        all_handles.push(h);
    }

    tracing::info!("Waiting for {} tasks to complete", all_handles.len());
    let _ = futures::future::join_all(all_handles).await;
    tracing::warn!("All services stopped");
    Ok(())
}
