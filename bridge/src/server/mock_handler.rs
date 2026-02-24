// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A mock implementation for `BridgeRequestHandlerTrait`
//! that handles requests according to preset behaviors.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::crypto::BridgeAuthorityKeyPair;
use crate::error::BridgeError;
use crate::error::BridgeResult;
use crate::metrics::BridgeMetrics;
use crate::server::BridgeNodePublicMetadata;
use crate::types::SignedBridgeAction;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use axum::Json;
use starcoin_bridge_types::digests::TransactionDigest;

use super::handler::BridgeRequestHandlerTrait;
use super::make_router;

#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub struct BridgeRequestMockHandler {
    signer: Arc<ArcSwap<Option<BridgeAuthorityKeyPair>>>,
    starcoin_bridge_token_events: Arc<
        Mutex<
            HashMap<(TransactionDigest, u16), (BridgeResult<SignedBridgeAction>, Option<Duration>)>,
        >,
    >,
    starcoin_bridge_token_events_requested: Arc<Mutex<HashMap<(TransactionDigest, u16), u64>>>,
}

impl BridgeRequestMockHandler {
    pub fn new() -> Self {
        Self {
            signer: Arc::new(ArcSwap::new(Arc::new(None))),
            starcoin_bridge_token_events: Arc::new(Mutex::new(HashMap::new())),
            starcoin_bridge_token_events_requested: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_starcoin_bridge_event_response(
        &self,
        tx_digest: TransactionDigest,
        idx: u16,
        response: BridgeResult<SignedBridgeAction>,
        delay: Option<Duration>,
    ) {
        self.starcoin_bridge_token_events
            .lock()
            .unwrap()
            .insert((tx_digest, idx), (response, delay));
    }

    pub fn get_starcoin_bridge_token_events_requested(
        &self,
        tx_digest: TransactionDigest,
        event_index: u16,
    ) -> u64 {
        *self
            .starcoin_bridge_token_events_requested
            .lock()
            .unwrap()
            .get(&(tx_digest, event_index))
            .unwrap_or(&0)
    }

    pub fn set_signer(&self, signer: BridgeAuthorityKeyPair) {
        self.signer.store(Arc::new(Some(signer)));
    }
}

impl Default for BridgeRequestMockHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BridgeRequestHandlerTrait for BridgeRequestMockHandler {
    async fn handle_eth_tx_hash(
        &self,
        _: String,
        _: u16,
    ) -> Result<Json<SignedBridgeAction>, BridgeError> {
        unimplemented!()
    }

    async fn handle_starcoin_bridge_tx_digest(
        &self,
        tx_digest_base58: String,
        event_idx: u16,
    ) -> Result<Json<SignedBridgeAction>, BridgeError> {
        // Decode hex string to TransactionDigest ([u8; 32])
        let tx_digest = hex::decode(tx_digest_base58.trim_start_matches("0x"))
            .map_err(|_| BridgeError::InvalidTxHash)?
            .try_into()
            .map_err(|_| BridgeError::InvalidTxHash)?;
        let (result, delay) = {
            let preset = self.starcoin_bridge_token_events.lock().unwrap();
            if !preset.contains_key(&(tx_digest, event_idx)) {
                // Ok to panic in test
                panic!(
                    "No preset handle_starcoin_bridge_tx_digest result for tx_digest: {:?}, event_idx: {}",
                    tx_digest, event_idx
                );
            }
            let mut requested = self.starcoin_bridge_token_events_requested.lock().unwrap();
            let entry = requested.entry((tx_digest, event_idx)).or_default();
            *entry += 1;
            let (result, delay) = preset.get(&(tx_digest, event_idx)).unwrap();
            (result.clone(), *delay)
        };
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        let signed_action: starcoin_bridge_types::message_envelope::Envelope<
            crate::types::BridgeAction,
            crate::crypto::BridgeAuthoritySignInfo,
        > = result?;
        Ok(Json(signed_action))
    }
}

pub fn run_mock_server(
    socket_address: SocketAddr,
    mock_handler: BridgeRequestMockHandler,
) -> tokio::task::JoinHandle<()> {
    tracing::info!("Starting mock server at {}", socket_address);
    let listener = std::net::TcpListener::bind(socket_address).unwrap();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    tokio::spawn(async move {
        let router = make_router(
            Arc::new(mock_handler),
            Arc::new(BridgeMetrics::new_for_testing()),
            Arc::new(BridgeNodePublicMetadata::empty_for_testing()),
        );
        axum::serve(listener, router).await.unwrap()
    })
}
