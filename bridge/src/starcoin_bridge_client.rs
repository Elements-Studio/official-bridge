// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
use anyhow::anyhow;
use async_trait::async_trait;
use fastcrypto::traits::ToFromBytes;

#[cfg(test)]
use starcoin_bridge_json_rpc_api::BridgeReadApiClient;

#[cfg(test)]
use starcoin_bridge_json_rpc_types::StarcoinTransactionBlockResponseOptions;
use starcoin_bridge_json_rpc_types::{EventFilter, StarcoinEvent};
use starcoin_bridge_json_rpc_types::{EventPage, StarcoinTransactionBlockResponse};
#[cfg(test)]
use starcoin_bridge_sdk::{StarcoinClient as StarcoinSdkClient, StarcoinClientBuilder};
#[cfg(test)]
use starcoin_bridge_types::base_types::StarcoinAddress;
use starcoin_bridge_types::base_types::TransactionDigest;
use starcoin_bridge_types::bridge::{
    BridgeSummary, BridgeTreasurySummary, MoveTypeCommitteeMember,
    MoveTypeParsedTokenTransferMessage,
};
use starcoin_bridge_types::event::EventID;
use starcoin_bridge_types::parse_starcoin_bridge_type_tag;

use starcoin_bridge_types::transaction::Transaction;
#[cfg(test)]
use starcoin_bridge_types::Identifier;
use starcoin_bridge_types::TypeTag;

use std::collections::HashMap;
use std::str::from_utf8;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, warn};

use crate::crypto::BridgeAuthorityPublicKey;
use crate::error::{BridgeError, BridgeResult};
use crate::events::StarcoinBridgeEvent;
use crate::metrics::BridgeMetrics;
use crate::retry_with_max_elapsed_time;
use crate::starcoin_jsonrpc_client::StarcoinJsonRpcClient;
use crate::types::BridgeActionStatus;
use crate::types::ParsedTokenTransferMessage;
use crate::types::{BridgeAction, BridgeAuthority, BridgeCommittee};

pub struct StarcoinClient<P> {
    inner: P,
    bridge_metrics: Arc<BridgeMetrics>,
}

// JSON-RPC based client (default, no runtime conflicts)
pub type StarcoinBridgeClient = StarcoinClient<StarcoinJsonRpcClient>;

// Legacy type alias for backward compatibility
pub type StarcoinBridgeSdkClient = StarcoinBridgeClient;

impl StarcoinBridgeClient {
    pub fn new(rpc_url: &str, bridge_address: &str) -> Self {
        Self {
            inner: StarcoinJsonRpcClient::new(rpc_url, bridge_address),
            bridge_metrics: Arc::new(BridgeMetrics::new_for_testing()),
        }
    }

    pub fn with_metrics(
        rpc_url: &str,
        bridge_address: &str,
        bridge_metrics: Arc<BridgeMetrics>,
    ) -> Self {
        Self {
            inner: StarcoinJsonRpcClient::new(rpc_url, bridge_address),
            bridge_metrics,
        }
    }

    pub fn starcoin_bridge_client(&self) -> &StarcoinJsonRpcClient {
        &self.inner
    }

    /// Get access to the underlying JSON-RPC client
    pub fn json_rpc_client(&self) -> &StarcoinJsonRpcClient {
        &self.inner
    }
}

// SDK-based client (only for tests)
#[cfg(test)]
impl StarcoinClient<StarcoinSdkClient> {
    pub async fn new(rpc_url: &str, bridge_metrics: Arc<BridgeMetrics>) -> anyhow::Result<Self> {
        let inner = StarcoinClientBuilder::default()
            .url(rpc_url)
            .build()
            .map_err(|e| {
                anyhow!("Can't establish connection with Starcoin Rpc {rpc_url}. Error: {e}")
            })?;
        let self_ = Self {
            inner,
            bridge_metrics,
        };
        self_.describe().await?;
        Ok(self_)
    }

    pub fn starcoin_bridge_client(&self) -> &StarcoinSdkClient {
        &self.inner
    }
}

impl<P> StarcoinClient<P>
where
    P: StarcoinClientInner,
{
    pub fn new_for_testing(inner: P) -> Self {
        Self {
            inner,
            bridge_metrics: Arc::new(BridgeMetrics::new_for_testing()),
        }
    }

    /// Get the configured bridge contract address
    pub fn bridge_address(&self) -> &str {
        self.inner.bridge_address()
    }

    #[cfg(test)]
    async fn describe(&self) -> anyhow::Result<()> {
        let chain_id = self.inner.get_chain_identifier().await?;
        let block_number = self.inner.get_latest_block_number().await?;
        tracing::info!(
            "StarcoinClient is connected to chain {chain_id}, current block number: {block_number}"
        );
        // Chain identifier is informational - actual chain ID validation happens in config.rs
        Ok(())
    }

    // Returns BridgeAction from a Starcoin Transaction with transaction hash
    // and the event index. If event is declared in an unrecognized
    // package, return error.
    //
    // Note: event_idx refers to the Nth bridge event in the transaction (0-indexed),
    // not the absolute index in the transaction's event list. This is because
    // Starcoin transactions may emit multiple events (e.g., Account::WithdrawEvent,
    // Token::BurnEvent) before the Bridge event.
    pub async fn get_bridge_action_by_tx_digest_and_event_idx_maybe(
        &self,
        tx_digest: &TransactionDigest,
        event_idx: u16,
    ) -> BridgeResult<BridgeAction> {
        self.get_finalized_bridge_action_maybe(tx_digest, event_idx, None)
            .await
    }

    /// Get bridge action with optional finality check.
    ///
    /// # Arguments
    /// * `tx_digest` - Transaction digest
    /// * `event_idx` - Event index (relative to bridge events)
    /// * `finality_config` - Optional finality config (finality_blocks, block_time_secs).
    ///   If None, no finality check is performed.
    ///
    /// # Returns
    /// * `Ok(BridgeAction)` if the event is found and finalized
    /// * `Err(TxNotFinalized)` if finality check is enabled and event is not yet finalized
    pub async fn get_finalized_bridge_action_maybe(
        &self,
        tx_digest: &TransactionDigest,
        event_idx: u16,
        finality_config: Option<(u64, u64)>, // (finality_blocks, block_time_secs)
    ) -> BridgeResult<BridgeAction> {
        tracing::info!(
            "[StarcoinClient] Fetching events for tx_digest={:?}, event_idx={}, finality_config={:?}",
            tx_digest, event_idx, finality_config
        );
        // Use verbose version for signature request path
        let events = self
            .inner
            .get_events_by_tx_digest_verbose(*tx_digest)
            .await
            .map_err(|e| {
                tracing::error!(
                    "[StarcoinClient] ❌ RPC error getting events: tx_digest={:?}, error={:?}",
                    tx_digest,
                    e
                );
                BridgeError::RestAPIError(format!("Failed to get events: {:?}", e))
            })?;

        tracing::info!(
            "[StarcoinClient] RPC returned {} total events for tx_digest={:?}",
            events.len(),
            tx_digest
        );

        // Get expected bridge address from config (16 bytes for Starcoin)
        let expected_addr = hex::decode(self.bridge_address().trim_start_matches("0x"))
            .map_err(|_| BridgeError::BridgeEventInUnrecognizedStarcoinPackage)?;

        // Find all bridge events (events from the bridge module)
        let bridge_events: Vec<_> = events
            .iter()
            .enumerate()
            .filter(|(_, event)| event.type_.address.as_ref() == expected_addr.as_slice())
            .collect();

        tracing::info!(
            "[StarcoinClient] Found {} bridge events (from address={}) in tx {:?}, looking for event_idx {}",
            bridge_events.len(),
            self.bridge_address(),
            tx_digest,
            event_idx
        );

        // Get the Nth bridge event (event_idx is relative to bridge events only)
        let (actual_idx, event) = bridge_events.get(event_idx as usize).ok_or_else(|| {
            tracing::warn!(
                "[StarcoinClient] ❌ No bridge event at index {} in tx {:?}, total bridge events: {}",
                event_idx,
                tx_digest,
                bridge_events.len()
            );
            BridgeError::NoBridgeEventsInTxPosition
        })?;

        tracing::info!(
            "[StarcoinClient] Using bridge event at actual index {} (requested bridge event idx {}), type={:?}",
            actual_idx,
            event_idx,
            event.type_
        );

        // Check finality if config is provided
        if let Some((finality_blocks, block_time_secs)) = finality_config {
            let event_block = event.id.block_number;
            // Use verbose version for signature request path
            let current_block =
                self.inner
                    .get_latest_block_number_verbose()
                    .await
                    .map_err(|e| {
                        tracing::error!(
                            "[StarcoinClient] ❌ RPC error getting current block: error={:?}",
                            e
                        );
                        BridgeError::InternalError(format!("Failed to get current block: {:?}", e))
                    })?;
            let finalized_block = current_block.saturating_sub(finality_blocks);

            tracing::info!(
                "[StarcoinClient] Finality check: tx_digest={:?}, event_block={}, current_block={}, finalized_block={}, finality_blocks={}, is_finalized={}",
                tx_digest, event_block, current_block, finalized_block, finality_blocks, event_block <= finalized_block
            );

            if event_block > finalized_block {
                let blocks_to_finalize = event_block.saturating_sub(finalized_block);
                let estimated_wait_secs = Some(blocks_to_finalize * block_time_secs);
                tracing::warn!(
                    "[StarcoinClient] ⏳ Tx not finalized: tx_digest={:?}, event_block={}, finalized_block={}, blocks_remaining={}, estimated_wait_secs={:?}",
                    tx_digest, event_block, finalized_block, blocks_to_finalize, estimated_wait_secs
                );
                return Err(BridgeError::TxNotFinalized(
                    crate::error::TxNotFinalizedInfo {
                        chain: "starcoin".to_string(),
                        tx_block: event_block,
                        finalized_block,
                        blocks_to_finalize,
                        estimated_wait_secs,
                    },
                ));
            }
        }

        let bridge_event = StarcoinBridgeEvent::try_from_starcoin_bridge_event(event)?
            .ok_or(BridgeError::NoBridgeEventsInTxPosition)?;

        tracing::info!(
            "[StarcoinClient] ✅ Parsed bridge event successfully: tx_digest={:?}, event_idx={}, event_type={}",
            tx_digest, event_idx, std::any::type_name_of_val(&bridge_event)
        );

        bridge_event
            .try_into_bridge_action(*tx_digest, event_idx)
            .ok_or(BridgeError::BridgeEventNotActionable)
    }

    pub async fn get_bridge_summary(&self) -> BridgeResult<BridgeSummary> {
        self.inner
            .get_bridge_summary()
            .await
            .map_err(|e| BridgeError::InternalError(format!("Can't get bridge committee: {e}")))
    }

    pub async fn is_bridge_paused(&self) -> BridgeResult<bool> {
        self.get_bridge_summary()
            .await
            .map(|summary| summary.is_frozen)
    }

    pub async fn get_treasury_summary(&self) -> BridgeResult<BridgeTreasurySummary> {
        Ok(self.get_bridge_summary().await?.treasury)
    }

    pub async fn get_token_id_map(&self) -> BridgeResult<HashMap<u8, TypeTag>> {
        self.get_bridge_summary()
            .await?
            .treasury
            .id_token_type_map
            .into_iter()
            .map(|(id, name)| {
                parse_starcoin_bridge_type_tag(&format!("0x{name}"))
                    .map(|name| (id, name))
                    .map_err(|e| {
                        BridgeError::InternalError(format!(
                            "Failed to retrieve token id mapping: {e}, type name: {name}"
                        ))
                    })
            })
            .collect()
    }

    pub async fn get_notional_values(&self) -> BridgeResult<HashMap<u8, u64>> {
        let bridge_summary = self.get_bridge_summary().await?;
        bridge_summary
            .treasury
            .id_token_type_map
            .iter()
            .map(|(id, type_name)| {
                bridge_summary
                    .treasury
                    .supported_tokens
                    .iter()
                    .find_map(|(tn, metadata)| {
                        if type_name == tn {
                            Some((*id, metadata.notional_value))
                        } else {
                            None
                        }
                    })
                    .ok_or(BridgeError::InternalError(
                        "Error encountered when retrieving token notional values.".into(),
                    ))
            })
            .collect()
    }

    pub async fn get_bridge_committee(&self) -> BridgeResult<BridgeCommittee> {
        let bridge_summary =
            self.inner.get_bridge_summary().await.map_err(|e| {
                BridgeError::InternalError(format!("Can't get bridge committee: {e}"))
            })?;
        let move_type_bridge_committee = bridge_summary.committee;

        let mut authorities = vec![];
        // Convert MoveTypeBridgeCommittee members to BridgeAuthority
        // This logic is here because BridgeCommittee needs to be constructed from authorities
        for (_, member) in move_type_bridge_committee.members {
            let MoveTypeCommitteeMember {
                starcoin_bridge_address,
                bridge_pubkey_bytes,
                voting_power,
                http_rest_url,
                blocklisted,
            } = member;
            // Handle 64-byte raw pubkey (x, y without 0x04 prefix) by prepending 0x04
            let pubkey_bytes_for_parsing = if bridge_pubkey_bytes.len() == 64 {
                let mut full = vec![0x04];
                full.extend_from_slice(&bridge_pubkey_bytes);
                full
            } else {
                bridge_pubkey_bytes.clone()
            };
            let pubkey = BridgeAuthorityPublicKey::from_bytes(&pubkey_bytes_for_parsing)?;
            let base_url = from_utf8(&http_rest_url).unwrap_or_else(|_| {
                warn!(
                    "Bridge authority address: {}, pubkey: {:?} has invalid http url: {:?}",
                    starcoin_bridge_address, bridge_pubkey_bytes, http_rest_url
                );
                ""
            });
            authorities.push(BridgeAuthority {
                starcoin_bridge_address,
                pubkey,
                voting_power,
                base_url: base_url.into(),
                is_blocklisted: blocklisted,
            });
        }
        BridgeCommittee::new(authorities)
    }

    pub async fn get_chain_identifier(&self) -> BridgeResult<String> {
        Ok(self.inner.get_chain_identifier().await?)
    }

    /// Get the chain ID as u8 for transaction signing
    pub async fn get_chain_id(&self) -> BridgeResult<u8> {
        let chain_id = self.inner.get_chain_id().await?;
        Ok(chain_id)
    }

    pub async fn get_reference_gas_price_until_success(&self) -> u64 {
        loop {
            let Ok(Ok(rgp)) = retry_with_max_elapsed_time!(
                self.inner.get_reference_gas_price(),
                Duration::from_secs(30)
            ) else {
                self.bridge_metrics
                    .starcoin_bridge_rpc_errors
                    .with_label_values(&["get_reference_gas_price"])
                    .inc();
                error!("Failed to get reference gas price");
                continue;
            };
            return rgp;
        }
    }

    pub async fn get_latest_block_number(&self) -> BridgeResult<u64> {
        Ok(self.inner.get_latest_block_number().await?)
    }

    pub async fn execute_transaction_block_with_effects(
        &self,
        tx: starcoin_bridge_types::transaction::Transaction,
    ) -> BridgeResult<StarcoinTransactionBlockResponse> {
        self.inner.execute_transaction_block_with_effects(tx).await
    }

    // This function polls until action status is success
    // Performance in tests can be improved by using a mock client
    pub async fn get_token_transfer_action_onchain_status_until_success(
        &self,
        source_chain_id: u8,
        seq_number: u64,
    ) -> BridgeActionStatus {
        loop {
            let Ok(Ok(status)) = retry_with_max_elapsed_time!(
                self.inner
                    .get_token_transfer_action_onchain_status(source_chain_id, seq_number),
                Duration::from_secs(30)
            ) else {
                self.bridge_metrics
                    .starcoin_bridge_rpc_errors
                    .with_label_values(&["get_token_transfer_action_onchain_status"])
                    .inc();
                error!(
                    "[QUERY] Failed to get token transfer action onchain status: source_chain={}, seq_num={}",
                    source_chain_id, seq_number
                );
                continue;
            };

            return status;
        }
    }

    pub async fn get_token_transfer_action_onchain_signatures_until_success(
        &self,
        source_chain_id: u8,
        seq_number: u64,
    ) -> Option<Vec<Vec<u8>>> {
        loop {
            let Ok(Ok(sigs)) = retry_with_max_elapsed_time!(
                self.inner
                    .get_token_transfer_action_onchain_signatures(source_chain_id, seq_number),
                Duration::from_secs(30)
            ) else {
                self.bridge_metrics
                    .starcoin_bridge_rpc_errors
                    .with_label_values(&["get_token_transfer_action_onchain_signatures"])
                    .inc();
                error!(
                    source_chain_id,
                    seq_number, "Failed to get token transfer action onchain signatures"
                );
                continue;
            };
            return sigs;
        }
    }

    pub async fn get_parsed_token_transfer_message(
        &self,
        source_chain_id: u8,
        seq_number: u64,
    ) -> BridgeResult<Option<ParsedTokenTransferMessage>> {
        let message = self
            .inner
            .get_parsed_token_transfer_message(source_chain_id, seq_number)
            .await?;
        Ok(match message {
            Some(payload) => Some(ParsedTokenTransferMessage::try_from(payload)?),
            None => None,
        })
    }

    /// Get account sequence number for transaction building
    pub async fn get_sequence_number(&self, address: &str) -> BridgeResult<u64> {
        self.inner.get_sequence_number(address).await.map_err(|e| {
            BridgeError::InternalError(format!("Failed to get sequence number: {:?}", e))
        })
    }

    /// Get the current block timestamp from the Starcoin chain
    /// Returns the timestamp in milliseconds from genesis
    pub async fn get_block_timestamp(&self) -> BridgeResult<u64> {
        self.inner.get_block_timestamp().await.map_err(|e| {
            BridgeError::InternalError(format!("Failed to get block timestamp: {:?}", e))
        })
    }

    /// Sign and submit a transaction to the Starcoin network
    pub async fn sign_and_submit_transaction(
        &self,
        key: &starcoin_bridge_types::crypto::StarcoinKeyPair,
        raw_txn: starcoin_bridge_types::transaction::RawUserTransaction,
    ) -> BridgeResult<String> {
        self.inner
            .sign_and_submit_transaction(key, raw_txn)
            .await
            .map_err(|e| {
                BridgeError::InternalError(format!("Transaction submission failed: {:?}", e))
            })
    }

    /// Sign, submit and wait for transaction confirmation
    /// Polls for up to 30 seconds until the transaction is confirmed on chain
    /// by checking that the account sequence number has incremented
    pub async fn sign_and_submit_and_wait_transaction(
        &self,
        key: &starcoin_bridge_types::crypto::StarcoinKeyPair,
        raw_txn: starcoin_bridge_types::transaction::RawUserTransaction,
    ) -> BridgeResult<String> {
        // Get the expected sequence number after transaction confirms
        let expected_seq = raw_txn.sequence_number() + 1;
        let sender_address = key.starcoin_address().to_hex_literal();

        let txn_hash = self.sign_and_submit_transaction(key, raw_txn).await?;

        tracing::info!(
            ?txn_hash,
            expected_seq,
            "Transaction submitted, waiting for confirmation"
        );

        // Poll for transaction confirmation (max 30 seconds, check every 500ms)
        for i in 0..60 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            // Check if transaction is confirmed by verifying sequence number has incremented
            match self.get_sequence_number(&sender_address).await {
                Ok(current_seq) => {
                    if current_seq >= expected_seq {
                        tracing::info!(
                            ?txn_hash,
                            current_seq,
                            expected_seq,
                            "Transaction confirmed on chain"
                        );
                        return Ok(txn_hash);
                    }
                    if i % 10 == 0 {
                        tracing::debug!(
                            ?txn_hash,
                            current_seq,
                            expected_seq,
                            "Still waiting for confirmation..."
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(?txn_hash, ?e, "Failed to get sequence number, retrying...");
                }
            }
        }

        Err(BridgeError::InternalError(format!(
            "Transaction {} not confirmed after 30 seconds timeout",
            txn_hash
        )))
    }
}

// Implement BridgePausedClient for StarcoinClient
#[async_trait]
impl<P> crate::bridge_status::BridgePausedClient for StarcoinClient<P>
where
    P: StarcoinClientInner + Send + Sync,
{
    async fn is_bridge_paused(&self) -> BridgeResult<bool> {
        self.get_bridge_summary()
            .await
            .map(|summary| summary.is_frozen)
    }
}

// Use a trait to abstract over the StarcoinSDKClient and StarcoinMockClient for testing.
#[async_trait]
pub trait StarcoinClientInner: Send + Sync {
    type Error: Into<anyhow::Error> + Send + Sync + std::error::Error + 'static;

    /// Get the configured bridge contract address
    fn bridge_address(&self) -> &str;

    async fn query_events(
        &self,
        query: EventFilter,
        cursor: Option<EventID>,
    ) -> Result<EventPage, Self::Error>;

    async fn get_events_by_tx_digest(
        &self,
        tx_digest: TransactionDigest,
    ) -> Result<Vec<StarcoinEvent>, Self::Error>;

    /// Get events by tx digest with verbose logging (for validator signature requests)
    async fn get_events_by_tx_digest_verbose(
        &self,
        tx_digest: TransactionDigest,
    ) -> Result<Vec<StarcoinEvent>, Self::Error> {
        // Default implementation uses non-verbose version
        self.get_events_by_tx_digest(tx_digest).await
    }

    async fn get_chain_identifier(&self) -> Result<String, Self::Error>;

    /// Get the chain ID as u8 for transaction signing
    async fn get_chain_id(&self) -> Result<u8, Self::Error>;

    async fn get_reference_gas_price(&self) -> Result<u64, Self::Error>;

    async fn get_latest_block_number(&self) -> Result<u64, Self::Error>;

    /// Get latest block number with verbose logging (for validator finality checks)
    async fn get_latest_block_number_verbose(&self) -> Result<u64, Self::Error> {
        // Default implementation uses non-verbose version
        self.get_latest_block_number().await
    }

    async fn get_bridge_summary(&self) -> Result<BridgeSummary, Self::Error>;

    async fn execute_transaction_block_with_effects(
        &self,
        tx: Transaction,
    ) -> Result<StarcoinTransactionBlockResponse, BridgeError>;

    async fn get_token_transfer_action_onchain_status(
        &self,
        source_chain_id: u8,
        seq_number: u64,
    ) -> Result<BridgeActionStatus, BridgeError>;

    async fn get_token_transfer_action_onchain_signatures(
        &self,
        source_chain_id: u8,
        seq_number: u64,
    ) -> Result<Option<Vec<Vec<u8>>>, BridgeError>;

    async fn get_parsed_token_transfer_message(
        &self,
        source_chain_id: u8,
        seq_number: u64,
    ) -> Result<Option<MoveTypeParsedTokenTransferMessage>, BridgeError>;

    /// Get account sequence number for transaction building
    async fn get_sequence_number(&self, address: &str) -> Result<u64, BridgeError>;

    /// Get the current block timestamp from the chain
    /// Returns the timestamp in milliseconds from genesis
    async fn get_block_timestamp(&self) -> Result<u64, BridgeError>;

    /// Sign and submit a raw transaction to the network
    async fn sign_and_submit_transaction(
        &self,
        key: &starcoin_bridge_types::crypto::StarcoinKeyPair,
        raw_txn: starcoin_bridge_types::transaction::RawUserTransaction,
    ) -> Result<String, BridgeError>;
}

// SDK-based implementation (only for tests)
#[cfg(test)]
#[async_trait]
impl StarcoinClientInner for StarcoinSdkClient {
    type Error = starcoin_bridge_sdk::error::Error;

    fn bridge_address(&self) -> &str {
        // Return a dummy address for testing
        "0x0000000000000000000000000000000b"
    }

    async fn query_events(
        &self,
        query: EventFilter,
        cursor: Option<EventID>,
    ) -> Result<EventPage, Self::Error> {
        self.event_api()
            .query_events(query, cursor, None, false)
            .await
            .map_err(|e| {
                starcoin_bridge_sdk::error::Error::from(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })
    }

    async fn get_events_by_tx_digest(
        &self,
        tx_digest: TransactionDigest,
    ) -> Result<Vec<StarcoinEvent>, Self::Error> {
        // Query events from Starcoin using the SDK
        // Note: Currently get_events returns Vec<Event> where Event is Vec<u8> (stub)
        // We need to convert these to proper StarcoinEvent objects
        let _ = self.event_api().get_events(&tx_digest).await.map_err(|e| {
            starcoin_bridge_sdk::error::Error::from(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to get events: {}", e),
            ))
        })?;

        // TODO: Parse the raw event bytes into StarcoinEvent objects
        // This requires understanding the event structure from Starcoin transactions
        Ok(vec![])
    }

    async fn get_chain_identifier(&self) -> Result<String, Self::Error> {
        self.read_api().get_chain_identifier().await.map_err(|e| {
            starcoin_bridge_sdk::error::Error::from(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })
    }

    async fn get_chain_id(&self) -> Result<u8, Self::Error> {
        // For SDK client, return default test chain ID
        Ok(255)
    }

    async fn get_reference_gas_price(&self) -> Result<u64, Self::Error> {
        self.governance_api()
            .get_reference_gas_price()
            .await
            .map_err(|e| {
                starcoin_bridge_sdk::error::Error::from(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })
    }

    async fn get_latest_block_number(&self) -> Result<u64, Self::Error> {
        self.read_api()
            .get_latest_block_number()
            .await
            .map_err(|e| {
                starcoin_bridge_sdk::error::Error::from(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })
    }

    async fn get_bridge_summary(&self) -> Result<BridgeSummary, Self::Error> {
        self.http().get_latest_bridge().await.map_err(|e| {
            starcoin_bridge_sdk::error::Error::from(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })
    }

    async fn get_token_transfer_action_onchain_status(
        &self,
        source_chain_id: u8,
        seq_number: u64,
    ) -> Result<BridgeActionStatus, BridgeError> {
        // SDK-based test stub - return Pending as default
        let _ = (source_chain_id, seq_number);
        Ok(BridgeActionStatus::Pending)
    }

    async fn get_token_transfer_action_onchain_signatures(
        &self,
        source_chain_id: u8,
        seq_number: u64,
    ) -> Result<Option<Vec<Vec<u8>>>, BridgeError> {
        // SDK-based test stub
        let _ = (source_chain_id, seq_number);
        Ok(None)
    }

    async fn execute_transaction_block_with_effects(
        &self,
        tx: Transaction,
    ) -> Result<StarcoinTransactionBlockResponse, BridgeError> {
        match self
            .quorum_driver_api()
            .execute_transaction_block(
                tx,
                StarcoinTransactionBlockResponseOptions::new()
                    .with_effects()
                    .with_events(),
                starcoin_bridge_types::quorum_driver_types::ExecuteTransactionRequestType::WaitForEffectsCert,
            )
            .await
        {
            Ok(response) => Ok(response),
            Err(e) => return Err(BridgeError::StarcoinTxFailureGeneric(e.to_string())),
        }
    }

    async fn get_parsed_token_transfer_message(
        &self,
        source_chain_id: u8,
        seq_number: u64,
    ) -> Result<Option<MoveTypeParsedTokenTransferMessage>, BridgeError> {
        // SDK-based test stub
        let _ = (source_chain_id, seq_number);
        Ok(None)
    }

    async fn get_sequence_number(&self, _: &str) -> Result<u64, BridgeError> {
        // SDK-based implementation for tests only
        // Returns 0 as a stub since SDK client is only used in unit tests
        // where sequence numbers don't need to be accurate.
        // Production code uses StarcoinJsonRpcClient which properly queries the chain.
        Ok(0)
    }

    async fn get_block_timestamp(&self) -> Result<u64, BridgeError> {
        // SDK-based implementation for tests
        // Return current system time in milliseconds
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64)
    }

    async fn sign_and_submit_transaction(
        &self,
        _: &starcoin_bridge_types::crypto::StarcoinKeyPair,
        _: starcoin_bridge_types::transaction::RawUserTransaction,
    ) -> Result<String, BridgeError> {
        // SDK-based implementation for tests
        // This is only used in tests and will use mock transactions
        Err(BridgeError::Generic(
            "SDK-based transaction submission not implemented".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    // Tests using StarcoinMockClient - no real Starcoin environment needed
    use crate::{
        events::{EmittedStarcoinToEthTokenBridgeV1, MoveTokenDepositedEvent},
        starcoin_bridge_mock_client::StarcoinMockClient,
        test_utils::{StarcoinAddressTestExt, TransactionDigestTestExt},
        types::StarcoinToEthBridgeAction,
    };
    use ethers::types::Address as EthAddress;
    use move_core_types::account_address::AccountAddress;
    use serde::{Deserialize, Serialize};
    use starcoin_bridge_types::bridge::{BridgeChainId, TOKEN_ID_STARCOIN};
    use std::str::FromStr;

    use super::*;
    use crate::events::{init_all_struct_tags, StarcoinToEthTokenBridgeV1};

    #[tokio::test]
    async fn get_bridge_action_by_tx_digest_and_event_idx_maybe() {
        // Note: for random events generated in this test, we only care about
        // tx_digest and event_seq, so it's ok that package and module does
        // not match the query parameters.
        telemetry_subscribers::init_for_testing();
        let mock_client = StarcoinMockClient::default();
        let starcoin_bridge_client = StarcoinClient::new_for_testing(mock_client.clone());
        let tx_digest = TransactionDigest::random();

        // Ensure all struct tags are inited
        init_all_struct_tags();

        let sanitized_event_1 = EmittedStarcoinToEthTokenBridgeV1 {
            nonce: 1,
            starcoin_bridge_chain_id: BridgeChainId::StarcoinTestnet,
            starcoin_bridge_address: StarcoinAddress::random_for_testing_only(),
            eth_chain_id: BridgeChainId::EthSepolia,
            eth_address: EthAddress::random(),
            token_id: TOKEN_ID_STARCOIN,
            amount_starcoin_bridge_adjusted: 100,
        };
        let emitted_event_1 = MoveTokenDepositedEvent {
            seq_num: sanitized_event_1.nonce,
            source_chain: sanitized_event_1.starcoin_bridge_chain_id as u8,
            sender_address: sanitized_event_1.starcoin_bridge_address.to_vec(),
            target_chain: sanitized_event_1.eth_chain_id as u8,
            target_address: sanitized_event_1.eth_address.as_bytes().to_vec(),
            token_type: sanitized_event_1.token_id,
            amount_starcoin_bridge_adjusted: sanitized_event_1.amount_starcoin_bridge_adjusted,
        };

        let mut starcoin_bridge_event_1 = StarcoinEvent::random_for_testing();
        starcoin_bridge_event_1.type_ = StarcoinToEthTokenBridgeV1.get().unwrap().clone();
        starcoin_bridge_event_1.bcs = bcs::to_bytes(&emitted_event_1).unwrap();

        #[derive(Serialize, Deserialize)]
        struct RandomStruct {}

        let event_2: RandomStruct = RandomStruct {};
        // undeclared struct tag
        let mut starcoin_bridge_event_2 = StarcoinEvent::random_for_testing();
        starcoin_bridge_event_2.type_ = StarcoinToEthTokenBridgeV1.get().unwrap().clone();
        starcoin_bridge_event_2.type_.module = Identifier::from_str("unrecognized_module").unwrap();
        starcoin_bridge_event_2.bcs = bcs::to_bytes(&event_2).unwrap();

        // Event 3 is defined in non-bridge package
        let mut starcoin_bridge_event_3 = starcoin_bridge_event_1.clone();
        starcoin_bridge_event_3.type_.address = AccountAddress::random();

        mock_client.add_events_by_tx_digest(
            tx_digest,
            vec![
                starcoin_bridge_event_1.clone(),
                starcoin_bridge_event_2.clone(),
                starcoin_bridge_event_1.clone(),
                starcoin_bridge_event_3.clone(),
            ],
        );
        let expected_action_1 =
            BridgeAction::StarcoinToEthBridgeAction(StarcoinToEthBridgeAction {
                starcoin_bridge_tx_digest: tx_digest,
                starcoin_bridge_tx_event_index: 0,
                starcoin_bridge_event: sanitized_event_1.clone(),
            });
        assert_eq!(
            starcoin_bridge_client
                .get_bridge_action_by_tx_digest_and_event_idx_maybe(&tx_digest, 0)
                .await
                .unwrap(),
            expected_action_1,
        );
        let expected_action_2 =
            BridgeAction::StarcoinToEthBridgeAction(StarcoinToEthBridgeAction {
                starcoin_bridge_tx_digest: tx_digest,
                starcoin_bridge_tx_event_index: 2,
                starcoin_bridge_event: sanitized_event_1.clone(),
            });
        assert_eq!(
            starcoin_bridge_client
                .get_bridge_action_by_tx_digest_and_event_idx_maybe(&tx_digest, 2)
                .await
                .unwrap(),
            expected_action_2,
        );
        // Event 1 is from bridge package but unrecognized module - expect NoBridgeEventsInTxPosition
        assert!(matches!(
            starcoin_bridge_client
                .get_bridge_action_by_tx_digest_and_event_idx_maybe(&tx_digest, 1)
                .await
                .unwrap_err(),
            BridgeError::NoBridgeEventsInTxPosition
        ),);
        // Event 3 is from non-bridge package, so it's filtered out.
        // We only have 3 bridge events (0, 1, 2), so requesting index 3 is out of bounds
        assert!(matches!(
            starcoin_bridge_client
                .get_bridge_action_by_tx_digest_and_event_idx_maybe(&tx_digest, 3)
                .await
                .unwrap_err(),
            BridgeError::NoBridgeEventsInTxPosition
        ),);
        // Event 4 is definitely out of bounds
        assert!(matches!(
            starcoin_bridge_client
                .get_bridge_action_by_tx_digest_and_event_idx_maybe(&tx_digest, 4)
                .await
                .unwrap_err(),
            BridgeError::NoBridgeEventsInTxPosition
        ),);

        // if the StructTag matches with unparsable bcs, it returns an error
        starcoin_bridge_event_2.type_ = StarcoinToEthTokenBridgeV1.get().unwrap().clone();
        mock_client.add_events_by_tx_digest(tx_digest, vec![starcoin_bridge_event_2]);
        starcoin_bridge_client
            .get_bridge_action_by_tx_digest_and_event_idx_maybe(&tx_digest, 2)
            .await
            .unwrap_err();
    }
}
