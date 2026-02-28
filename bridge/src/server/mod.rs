// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::inconsistent_digit_grouping)]
use crate::with_metrics;
use crate::{
    error::BridgeError,
    metrics::BridgeMetrics,
    server::handler::{BridgeRequestHandler, BridgeRequestHandlerTrait},
    types::SignedBridgeAction,
};
use axum::{
    extract::{Path, State},
    Json,
};
use axum::{http::StatusCode, routing::get, Router};
use fastcrypto::ed25519::Ed25519PublicKey;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, instrument};

pub mod handler;

#[cfg(test)]
pub(crate) mod mock_handler;

pub const APPLICATION_JSON: &str = "application/json";

pub const PING_PATH: &str = "/ping";
pub const METRICS_KEY_PATH: &str = "/metrics_pub_key";

// Important: for BridgeActions, the paths need to match the ones in bridge_client.rs
// Note: Using :param syntax for axum 0.7.x (not {param} which is for axum 0.8.x)
pub const ETH_TO_STARCOIN_TX_PATH: &str = "/sign/bridge_tx/eth/starcoin/:tx_hash/:event_index";
pub const STARCOIN_TO_ETH_TX_PATH: &str = "/sign/bridge_tx/starcoin/eth/:tx_digest/:event_index";
// BridgeNode's public metadata that is accessible via the `/ping` endpoint.
// Be careful with what to put here, as it is public.
#[derive(serde::Serialize)]
pub struct BridgeNodePublicMetadata {
    pub version: &'static str,
    pub metrics_pubkey: Option<Arc<Ed25519PublicKey>>,
}

// Fee estimation response
#[derive(serde::Serialize)]
pub struct FeeEstimation {
    pub source_tx_estimate: String,
    pub combined_approve_and_claim_estimate: String,
    pub approve_estimate: String,
    pub claim_estimate: String,
}

impl BridgeNodePublicMetadata {
    pub fn new(version: &'static str, metrics_pubkey: Ed25519PublicKey) -> Self {
        Self {
            version,
            metrics_pubkey: Some(metrics_pubkey.into()),
        }
    }

    pub fn empty_for_testing() -> Self {
        Self {
            version: "testing",
            metrics_pubkey: None,
        }
    }
}

pub fn run_server(
    socket_address: &SocketAddr,
    handler: BridgeRequestHandler,
    metrics: Arc<BridgeMetrics>,
    metadata: Arc<BridgeNodePublicMetadata>,
) -> tokio::task::JoinHandle<()> {
    let socket_address = *socket_address;
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(socket_address).await.unwrap();
        axum::serve(
            listener,
            make_router(Arc::new(handler), metrics, metadata).into_make_service(),
        )
        .await
        .unwrap();
    })
}

pub(crate) fn make_router(
    handler: Arc<impl BridgeRequestHandlerTrait + Sync + Send + 'static>,
    metrics: Arc<BridgeMetrics>,
    metadata: Arc<BridgeNodePublicMetadata>,
) -> Router {
    Router::new()
        .route("/", get(health_check))
        .route("/health", get(health_check))
        .route(PING_PATH, get(ping))
        .route(METRICS_KEY_PATH, get(metrics_key_fetch))
        .route(ETH_TO_STARCOIN_TX_PATH, get(handle_eth_tx_hash))
        .route(
            STARCOIN_TO_ETH_TX_PATH,
            get(handle_starcoin_bridge_tx_digest),
        )
        .with_state((handler, metrics, metadata))
}

impl axum::response::IntoResponse for BridgeError {
    // TODO: distinguish client error.
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {:?}", self),
        )
            .into_response()
    }
}

impl<E> From<E> for BridgeError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self::Generic(err.into().to_string())
    }
}

async fn health_check() -> StatusCode {
    StatusCode::OK
}

async fn ping(
    State((_, _, metadata)): State<(
        Arc<impl BridgeRequestHandlerTrait + Sync + Send>,
        Arc<BridgeMetrics>,
        Arc<BridgeNodePublicMetadata>,
    )>,
) -> Result<Json<Arc<BridgeNodePublicMetadata>>, BridgeError> {
    Ok(Json(metadata))
}

async fn metrics_key_fetch(
    State((_, _, metadata)): State<(
        Arc<impl BridgeRequestHandlerTrait + Sync + Send>,
        Arc<BridgeMetrics>,
        Arc<BridgeNodePublicMetadata>,
    )>,
) -> Result<Json<Option<Arc<Ed25519PublicKey>>>, BridgeError> {
    Ok(Json(metadata.metrics_pubkey.clone()))
}

#[instrument(level = "error", skip_all, fields(tx_hash_hex=tx_hash_hex, event_idx=event_idx))]
async fn handle_eth_tx_hash(
    Path((tx_hash_hex, event_idx)): Path<(String, u16)>,
    State((handler, metrics, _)): State<(
        Arc<impl BridgeRequestHandlerTrait + Sync + Send>,
        Arc<BridgeMetrics>,
        Arc<BridgeNodePublicMetadata>,
    )>,
) -> Result<Json<SignedBridgeAction>, BridgeError> {
    let future = async {
        let sig = handler.handle_eth_tx_hash(tx_hash_hex, event_idx).await?;
        Ok(sig)
    };
    with_metrics!(metrics.clone(), "handle_eth_tx_hash", future).await
}

#[instrument(level = "error", skip_all, fields(tx_digest_hex=tx_digest_hex, event_idx=event_idx))]
async fn handle_starcoin_bridge_tx_digest(
    Path((tx_digest_hex, event_idx)): Path<(String, u16)>,
    State((handler, metrics, _)): State<(
        Arc<impl BridgeRequestHandlerTrait + Sync + Send>,
        Arc<BridgeMetrics>,
        Arc<BridgeNodePublicMetadata>,
    )>,
) -> Result<Json<SignedBridgeAction>, BridgeError> {
    let future = async {
        let sig: Json<SignedBridgeAction> = handler
            .handle_starcoin_bridge_tx_digest(tx_digest_hex, event_idx)
            .await?;
        Ok(sig)
    };
    with_metrics!(metrics.clone(), "handle_starcoin_bridge_tx_digest", future).await
}

#[macro_export]
macro_rules! with_metrics {
    ($metrics:expr, $type_:expr, $func:expr) => {
        async move {
            info!("Received {} request", $type_);
            $metrics
                .requests_received
                .with_label_values(&[$type_])
                .inc();
            $metrics
                .requests_inflight
                .with_label_values(&[$type_])
                .inc();

            let result = $func.await;

            match &result {
                Ok(_) => {
                    info!("{} request succeeded", $type_);
                    $metrics.requests_ok.with_label_values(&[$type_]).inc();
                }
                Err(e) => {
                    info!("{} request failed: {:?}", $type_, e);
                    $metrics.err_requests.with_label_values(&[$type_]).inc();
                }
            }

            $metrics
                .requests_inflight
                .with_label_values(&[$type_])
                .dec();
            result
        }
    };
}
