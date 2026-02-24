// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use crate::crypto::{BridgeAuthorityKeyPair, BridgeAuthoritySignInfo};
use crate::error::{BridgeError, BridgeResult};
use crate::eth_client::EthClient;
use crate::metrics::BridgeMetrics;
use crate::starcoin_bridge_client::{StarcoinClient, StarcoinClientInner};
use crate::types::{BridgeAction, SignedBridgeAction};
use async_trait::async_trait;
use axum::Json;
use ethers::providers::JsonRpcClient;
use ethers::types::TxHash;
use lru::LruCache;
use starcoin_bridge_types::base_types::TransactionDigest;
use starcoin_bridge_types::bridge::TOKEN_ID_USDT;
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use tracing::{error, info, warn};

#[async_trait]
pub trait BridgeRequestHandlerTrait {
    // Handles a request to sign a BridgeAction that bridges assets
    // from Ethereum to Starcoin. The inputs are a transaction hash on Ethereum
    // that emitted the bridge event and the Event index in that transaction
    async fn handle_eth_tx_hash(
        &self,
        tx_hash_hex: String,
        event_idx: u16,
    ) -> Result<Json<SignedBridgeAction>, BridgeError>;
    // Handles a request to sign a BridgeAction that bridges assets
    // from Starcoin to Ethereum. The inputs are a transaction digest on Starcoin
    // that emitted the bridge event and the Event index in that transaction
    async fn handle_starcoin_bridge_tx_digest(
        &self,
        tx_digest_base58: String,
        event_idx: u16,
    ) -> Result<Json<SignedBridgeAction>, BridgeError>;
}

#[async_trait::async_trait]
pub trait ActionVerifier<K>: Send + Sync {
    // Name of the verifier, used for metrics
    fn name(&self) -> &'static str;
    async fn verify(&self, key: K) -> BridgeResult<BridgeAction>;
}

struct StarcoinActionVerifier<C> {
    starcoin_bridge_client: Arc<StarcoinClient<C>>,
}

struct EthActionVerifier<P> {
    eth_client: Arc<EthClient<P>>,
}

#[async_trait::async_trait]
impl<C> ActionVerifier<(TransactionDigest, u16)> for StarcoinActionVerifier<C>
where
    C: StarcoinClientInner + Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        "StarcoinActionVerifier"
    }

    async fn verify(&self, key: (TransactionDigest, u16)) -> BridgeResult<BridgeAction> {
        let (tx_digest, event_idx) = key;
        // Starcoin finality: 16 blocks * 3 seconds = ~48 seconds
        let finality_config = Some((16u64, 3u64));
        info!(
            "[StarcoinVerifier] Verifying Starcoin tx: digest={:?}, event_idx={}",
            tx_digest, event_idx
        );
        let result = self
            .starcoin_bridge_client
            .get_finalized_bridge_action_maybe(&tx_digest, event_idx, finality_config)
            .await;
        match &result {
            Ok(action) => {
                // Only USDT is supported
                if let Some(token_id) = action.token_id() {
                    if token_id != TOKEN_ID_USDT {
                        warn!(
                            "[StarcoinVerifier] ❌ Unsupported token_id={} (only USDT={} allowed): digest={:?}, event_idx={}",
                            token_id, TOKEN_ID_USDT, tx_digest, event_idx
                        );
                        return Err(BridgeError::UnsupportedTokenId(token_id));
                    }
                }
                info!(
                    "[StarcoinVerifier] ✅ Starcoin action verified: digest={:?}, event_idx={}, action={:?}",
                    tx_digest, event_idx, action
                );
            }
            Err(e) => {
                warn!(
                    "[StarcoinVerifier] ❌ Starcoin verification failed: digest={:?}, event_idx={}, error={:?}",
                    tx_digest, event_idx, e
                );
            }
        }
        result
    }
}

#[async_trait::async_trait]
impl<C> ActionVerifier<(TxHash, u16)> for EthActionVerifier<C>
where
    C: JsonRpcClient + Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        "EthActionVerifier"
    }

    async fn verify(&self, key: (TxHash, u16)) -> BridgeResult<BridgeAction> {
        let (tx_hash, event_idx) = key;
        info!(
            "[EthVerifier] Verifying ETH tx: hash={:?}, event_idx={}",
            tx_hash, event_idx
        );
        let result = self
            .eth_client
            .get_finalized_bridge_action_maybe(tx_hash, event_idx)
            .await;
        match &result {
            Ok(action) => {
                // Only USDT is supported
                if let Some(token_id) = action.token_id() {
                    if token_id != TOKEN_ID_USDT {
                        warn!(
                            "[EthVerifier] ❌ Unsupported token_id={} (only USDT={} allowed): hash={:?}, event_idx={}",
                            token_id, TOKEN_ID_USDT, tx_hash, event_idx
                        );
                        return Err(BridgeError::UnsupportedTokenId(token_id));
                    }
                }
                info!(
                    "[EthVerifier] ✅ ETH action verified: hash={:?}, event_idx={}, action={:?}",
                    tx_hash, event_idx, action
                );
            }
            Err(e) => {
                warn!(
                    "[EthVerifier] ❌ ETH verification failed: hash={:?}, event_idx={}, error={:?}",
                    tx_hash, event_idx, e
                );
            }
        }
        result
    }
}

struct SignerWithCache<K> {
    signer: Arc<BridgeAuthorityKeyPair>,
    verifier: Arc<dyn ActionVerifier<K>>,
    mutex: Arc<Mutex<()>>,
    cache: LruCache<K, Arc<Mutex<Option<BridgeResult<SignedBridgeAction>>>>>,
    metrics: Arc<BridgeMetrics>,
}

impl<K> SignerWithCache<K>
where
    K: std::hash::Hash + Eq + Clone + Send + Sync + 'static,
{
    fn new(
        signer: Arc<BridgeAuthorityKeyPair>,
        verifier: impl ActionVerifier<K> + 'static,
        metrics: Arc<BridgeMetrics>,
    ) -> Self {
        Self {
            signer,
            verifier: Arc::new(verifier),
            mutex: Arc::new(Mutex::new(())),
            cache: LruCache::new(NonZeroUsize::new(1000).unwrap()),
            metrics,
        }
    }

    fn spawn(
        mut self,
        mut rx: starcoin_metrics::metered_channel::Receiver<(
            K,
            oneshot::Sender<BridgeResult<SignedBridgeAction>>,
        )>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let (key, tx) = rx
                    .recv()
                    .await
                    .unwrap_or_else(|| panic!("Server signer's channel is closed"));
                let result = self.sign(key).await;
                // The receiver may be dropped before the sender (client connection was dropped for example),
                // we ignore the error in that case.
                let _ = tx.send(result);
            }
        })
    }

    async fn get_cache_entry(
        &mut self,
        key: K,
    ) -> Arc<Mutex<Option<BridgeResult<SignedBridgeAction>>>> {
        // This mutex exists to make sure everyone gets the same entry, namely no double insert
        let _ = self.mutex.lock().await;
        self.cache
            .get_or_insert(key, || Arc::new(Mutex::new(None)))
            .clone()
    }

    async fn sign(&mut self, key: K) -> BridgeResult<SignedBridgeAction> {
        let signer = self.signer.clone();
        let verifier = self.verifier.clone();
        let verifier_name = verifier.name();
        let entry = self.get_cache_entry(key.clone()).await;
        let mut guard = entry.lock().await;
        if let Some(result) = &*guard {
            self.metrics
                .signer_with_cache_hit
                .with_label_values(&[verifier_name])
                .inc();
            info!(
                "[Signer] Cache hit for verifier={}, result={}",
                verifier_name,
                if result.is_ok() { "Ok" } else { "Err" }
            );
            return result.clone();
        }
        self.metrics
            .signer_with_cache_miss
            .with_label_values(&[verifier_name])
            .inc();
        info!(
            "[Signer] Cache miss for verifier={}, proceeding to verify",
            verifier_name
        );
        match verifier.verify(key.clone()).await {
            Ok(bridge_action) => {
                let sig = BridgeAuthoritySignInfo::new(&bridge_action, &signer);
                let result = SignedBridgeAction::new_from_data_and_sig(bridge_action.clone(), sig);
                info!(
                    "[Signer] ✅ Signed action successfully: verifier={}, action_chain_id={:?}, action_seq={}, action_type={}",
                    verifier_name,
                    bridge_action.chain_id(),
                    bridge_action.seq_number(),
                    std::any::type_name_of_val(&bridge_action)
                );
                // Cache result if Ok
                *guard = Some(Ok(result.clone()));
                Ok(result)
            }
            Err(e) => {
                let is_cached = matches!(
                    e,
                    BridgeError::BridgeEventInUnrecognizedStarcoinPackage
                        | BridgeError::BridgeEventInUnrecognizedEthContract
                        | BridgeError::BridgeEventNotActionable
                        | BridgeError::NoBridgeEventsInTxPosition
                        | BridgeError::UnsupportedTokenId(_)
                );
                if is_cached {
                    error!(
                        "[Signer] ❌ Non-transient error (will be cached): verifier={}, error={:?}",
                        verifier_name, e
                    );
                    *guard = Some(Err(e.clone()));
                } else {
                    warn!(
                        "[Signer] ⏳ Transient error (not cached, will retry): verifier={}, error={:?}",
                        verifier_name, e
                    );
                }
                Err(e)
            }
        }
    }

    #[cfg(test)]
    async fn get_testing_only(
        &mut self,
        key: K,
    ) -> Option<&Arc<Mutex<Option<BridgeResult<SignedBridgeAction>>>>> {
        let _ = self.mutex.lock().await;
        self.cache.get(&key)
    }
}

pub struct BridgeRequestHandler {
    starcoin_bridge_signer_tx: starcoin_metrics::metered_channel::Sender<(
        (TransactionDigest, u16),
        oneshot::Sender<BridgeResult<SignedBridgeAction>>,
    )>,
    eth_signer_tx: starcoin_metrics::metered_channel::Sender<(
        (TxHash, u16),
        oneshot::Sender<BridgeResult<SignedBridgeAction>>,
    )>,
}

impl BridgeRequestHandler {
    pub fn new<
        SC: StarcoinClientInner + Send + Sync + 'static,
        EP: JsonRpcClient + Send + Sync + 'static,
    >(
        signer: BridgeAuthorityKeyPair,
        starcoin_bridge_client: Arc<StarcoinClient<SC>>,
        eth_client: Arc<EthClient<EP>>,
        metrics: Arc<BridgeMetrics>,
    ) -> Self {
        let (starcoin_bridge_signer_tx, starcoin_bridge_rx) =
            starcoin_metrics::metered_channel::channel(
                1000,
                &starcoin_metrics::get_metrics()
                    .unwrap()
                    .channel_inflight
                    .with_label_values(&["server_starcoin_bridge_action_signing_queue"]),
            );
        let (eth_signer_tx, eth_rx) = starcoin_metrics::metered_channel::channel(
            1000,
            &starcoin_metrics::get_metrics()
                .unwrap()
                .channel_inflight
                .with_label_values(&["server_eth_action_signing_queue"]),
        );
        let signer = Arc::new(signer);

        SignerWithCache::new(
            signer.clone(),
            StarcoinActionVerifier {
                starcoin_bridge_client,
            },
            metrics.clone(),
        )
        .spawn(starcoin_bridge_rx);
        SignerWithCache::new(
            signer.clone(),
            EthActionVerifier { eth_client },
            metrics.clone(),
        )
        .spawn(eth_rx);

        Self {
            starcoin_bridge_signer_tx,
            eth_signer_tx,
        }
    }
}

#[async_trait]
impl BridgeRequestHandlerTrait for BridgeRequestHandler {
    async fn handle_eth_tx_hash(
        &self,
        tx_hash_hex: String,
        event_idx: u16,
    ) -> Result<Json<SignedBridgeAction>, BridgeError> {
        info!(
            "[Handler] 📥 Received ETH signature request: tx_hash={}, event_idx={}",
            tx_hash_hex, event_idx
        );
        let tx_hash = TxHash::from_str(&tx_hash_hex).map_err(|e| {
            error!(
                "[Handler] ❌ Invalid ETH tx_hash format: tx_hash={}, error={:?}",
                tx_hash_hex, e
            );
            BridgeError::InvalidTxHash
        })?;

        let (tx, rx) = oneshot::channel();
        self.eth_signer_tx
            .send(((tx_hash, event_idx), tx))
            .await
            .unwrap_or_else(|_| panic!("Server eth signing channel is closed"));
        let result = rx
            .await
            .unwrap_or_else(|_| panic!("Server signing task's oneshot channel is dropped"));
        match &result {
            Ok(signed_action) => {
                info!(
                    "[Handler] ✅ ETH signature request completed: tx_hash={}, event_idx={}, sig_pubkey={:?}",
                    tx_hash_hex, event_idx, signed_action.auth_sig().authority_pub_key_bytes()
                );
            }
            Err(e) => {
                warn!(
                    "[Handler] ❌ ETH signature request failed: tx_hash={}, event_idx={}, error={:?}",
                    tx_hash_hex, event_idx, e
                );
            }
        }
        Ok(Json(result?))
    }

    async fn handle_starcoin_bridge_tx_digest(
        &self,
        tx_digest_hex: String,
        event_idx: u16,
    ) -> Result<Json<SignedBridgeAction>, BridgeError> {
        info!(
            "[Handler] 📥 Received Starcoin signature request: tx_digest={}, event_idx={}",
            tx_digest_hex, event_idx
        );
        // Client sends hex-encoded tx_digest, decode it
        let tx_digest: TransactionDigest = hex::decode(tx_digest_hex.trim_start_matches("0x"))
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| {
                error!(
                    "[Handler] ❌ Invalid Starcoin tx_digest format: tx_digest={}",
                    tx_digest_hex
                );
                BridgeError::InvalidTxHash
            })?;
        let (tx, rx) = oneshot::channel();
        self.starcoin_bridge_signer_tx
            .send(((tx_digest, event_idx), tx))
            .await
            .unwrap_or_else(|_| panic!("Server starcoin signing channel is closed"));
        let result = rx
            .await
            .unwrap_or_else(|_| panic!("Server signing task's oneshot channel is dropped"));
        match &result {
            Ok(signed_action) => {
                info!(
                    "[Handler] ✅ Starcoin signature request completed: tx_digest={}, event_idx={}, sig_pubkey={:?}",
                    tx_digest_hex, event_idx, signed_action.auth_sig().authority_pub_key_bytes()
                );
            }
            Err(e) => {
                warn!(
                    "[Handler] ❌ Starcoin signature request failed: tx_digest={}, event_idx={}, error={:?}",
                    tx_digest_hex, event_idx, e
                );
            }
        }
        Ok(Json(result?))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::{
        eth_mock_provider::EthMockProvider,
        events::{init_all_struct_tags, MoveTokenDepositedEvent, StarcoinToEthTokenBridgeV1},
        starcoin_bridge_mock_client::StarcoinMockClient,
        test_utils::{
            get_test_log_and_action, get_test_starcoin_bridge_to_eth_bridge_action,
            mock_last_finalized_block, StarcoinAddressTestExt, TransactionDigestTestExt,
        },
    };
    use ethers::types::{Address as EthAddress, TransactionReceipt};
    use starcoin_bridge_json_rpc_types::StarcoinEvent;
    use starcoin_bridge_types::bridge::{BridgeChainId, TOKEN_ID_USDC, TOKEN_ID_USDT};
    use starcoin_bridge_types::{base_types::StarcoinAddress, crypto::get_key_pair};

    #[tokio::test]
    async fn test_starcoin_bridge_signer_with_cache() {
        let (_, kp): (_, BridgeAuthorityKeyPair) = get_key_pair();
        let signer = Arc::new(kp);
        let starcoin_bridge_client_mock = StarcoinMockClient::default();
        let starcoin_bridge_verifier = StarcoinActionVerifier {
            starcoin_bridge_client: Arc::new(StarcoinClient::new_for_testing(
                starcoin_bridge_client_mock.clone(),
            )),
        };
        let metrics = Arc::new(BridgeMetrics::new_for_testing());
        let mut starcoin_bridge_signer_with_cache =
            SignerWithCache::new(signer.clone(), starcoin_bridge_verifier, metrics);

        // Test `get_cache_entry` creates a new entry if not exist
        let starcoin_bridge_tx_digest = TransactionDigest::random();
        let starcoin_bridge_event_idx = 42;
        assert!(starcoin_bridge_signer_with_cache
            .get_testing_only((starcoin_bridge_tx_digest, starcoin_bridge_event_idx))
            .await
            .is_none());
        let entry = starcoin_bridge_signer_with_cache
            .get_cache_entry((starcoin_bridge_tx_digest, starcoin_bridge_event_idx))
            .await;
        let entry_ = starcoin_bridge_signer_with_cache
            .get_testing_only((starcoin_bridge_tx_digest, starcoin_bridge_event_idx))
            .await;
        assert!(entry_.unwrap().lock().await.is_none());

        let action = get_test_starcoin_bridge_to_eth_bridge_action(
            Some(starcoin_bridge_tx_digest),
            Some(starcoin_bridge_event_idx),
            None,
            None,
            None,
            None,
            None,
        );
        let sig = BridgeAuthoritySignInfo::new(&action, &signer);
        let signed_action = SignedBridgeAction::new_from_data_and_sig(action.clone(), sig);
        entry.lock().await.replace(Ok(signed_action));
        let entry_ = starcoin_bridge_signer_with_cache
            .get_testing_only((starcoin_bridge_tx_digest, starcoin_bridge_event_idx))
            .await;
        assert!(entry_.unwrap().lock().await.is_some());

        // Test `sign` caches Err result
        let starcoin_bridge_tx_digest = TransactionDigest::random();
        let starcoin_bridge_event_idx = 0;

        // Mock an non-cacheable error such as rpc error
        starcoin_bridge_client_mock.add_events_by_tx_digest_error(starcoin_bridge_tx_digest);
        starcoin_bridge_signer_with_cache
            .sign((starcoin_bridge_tx_digest, starcoin_bridge_event_idx))
            .await
            .unwrap_err();
        let entry_ = starcoin_bridge_signer_with_cache
            .get_testing_only((starcoin_bridge_tx_digest, starcoin_bridge_event_idx))
            .await;
        assert!(entry_.unwrap().lock().await.is_none());

        // Mock a cacheable error such as no bridge events in tx position (empty event list)
        starcoin_bridge_client_mock.add_events_by_tx_digest(starcoin_bridge_tx_digest, vec![]);
        assert!(matches!(
            starcoin_bridge_signer_with_cache
                .sign((starcoin_bridge_tx_digest, starcoin_bridge_event_idx))
                .await,
            Err(BridgeError::NoBridgeEventsInTxPosition)
        ));
        let entry_ = starcoin_bridge_signer_with_cache
            .get_testing_only((starcoin_bridge_tx_digest, starcoin_bridge_event_idx))
            .await;
        assert_eq!(
            entry_.unwrap().lock().await.clone().unwrap().unwrap_err(),
            BridgeError::NoBridgeEventsInTxPosition,
        );

        // TODO: test BridgeEventInUnrecognizedStarcoinPackage, StarcoinBridgeEvent::try_from_starcoin_bridge_event
        // and BridgeEventNotActionable to be cached

        // Test `sign` caches Ok result
        let emitted_event_1 = MoveTokenDepositedEvent {
            seq_num: 1,
            source_chain: BridgeChainId::StarcoinCustom as u8,
            sender_address: StarcoinAddress::random_for_testing_only().to_vec(),
            target_chain: BridgeChainId::EthCustom as u8,
            target_address: EthAddress::random().as_bytes().to_vec(),
            token_type: TOKEN_ID_USDT,
            amount_starcoin_bridge_adjusted: 12345,
        };

        init_all_struct_tags();

        let mut starcoin_bridge_event_1 = StarcoinEvent::random_for_testing();
        starcoin_bridge_event_1.type_ = StarcoinToEthTokenBridgeV1.get().unwrap().clone();
        starcoin_bridge_event_1.bcs = bcs::to_bytes(&emitted_event_1).unwrap();
        // Set block_number to a known value so finality check passes
        starcoin_bridge_event_1.id.block_number = 100;
        let starcoin_bridge_tx_digest = starcoin_bridge_event_1.id.tx_digest;

        let mut starcoin_bridge_event_2 = StarcoinEvent::random_for_testing();
        starcoin_bridge_event_2.type_ = StarcoinToEthTokenBridgeV1.get().unwrap().clone();
        starcoin_bridge_event_2.bcs = bcs::to_bytes(&emitted_event_1).unwrap();
        // Same block_number for finality check
        starcoin_bridge_event_2.id.block_number = 100;
        let starcoin_bridge_event_idx_2 = 1;

        // Set current block high enough so finality check passes (block 100 + 16 finality blocks)
        starcoin_bridge_client_mock.set_latest_block_number(200);
        starcoin_bridge_client_mock.add_events_by_tx_digest(
            starcoin_bridge_tx_digest,
            vec![starcoin_bridge_event_2.clone()],
        );

        starcoin_bridge_client_mock.add_events_by_tx_digest(
            starcoin_bridge_tx_digest,
            vec![
                starcoin_bridge_event_1.clone(),
                starcoin_bridge_event_2.clone(),
            ],
        );
        let signed_1 = starcoin_bridge_signer_with_cache
            .sign((starcoin_bridge_tx_digest, starcoin_bridge_event_idx))
            .await
            .unwrap();
        let signed_2 = starcoin_bridge_signer_with_cache
            .sign((starcoin_bridge_tx_digest, starcoin_bridge_event_idx_2))
            .await
            .unwrap();

        // Because the result is cached now, the verifier should not be called again.
        // Even though we remove the `add_events_by_tx_digest` mock, we will still get the same result.
        starcoin_bridge_client_mock.add_events_by_tx_digest(starcoin_bridge_tx_digest, vec![]);
        assert_eq!(
            starcoin_bridge_signer_with_cache
                .sign((starcoin_bridge_tx_digest, starcoin_bridge_event_idx))
                .await
                .unwrap(),
            signed_1
        );
        assert_eq!(
            starcoin_bridge_signer_with_cache
                .sign((starcoin_bridge_tx_digest, starcoin_bridge_event_idx_2))
                .await
                .unwrap(),
            signed_2
        );
    }

    #[tokio::test]
    async fn test_eth_signer_with_cache() {
        let (_, kp): (_, BridgeAuthorityKeyPair) = get_key_pair();
        let signer = Arc::new(kp);
        let eth_mock_provider = EthMockProvider::default();
        let contract_address = EthAddress::random();
        let eth_client = EthClient::new_mocked(
            eth_mock_provider.clone(),
            HashSet::from_iter(vec![contract_address]),
        );
        let eth_verifier = EthActionVerifier {
            eth_client: Arc::new(eth_client),
        };
        let metrics = Arc::new(BridgeMetrics::new_for_testing());
        let mut eth_signer_with_cache =
            SignerWithCache::new(signer.clone(), eth_verifier, metrics.clone());

        // Test `get_cache_entry` creates a new entry if not exist
        let eth_tx_hash = TxHash::random();
        let eth_event_idx = 42;
        assert!(eth_signer_with_cache
            .get_testing_only((eth_tx_hash, eth_event_idx))
            .await
            .is_none());
        let entry = eth_signer_with_cache
            .get_cache_entry((eth_tx_hash, eth_event_idx))
            .await;
        let entry_ = eth_signer_with_cache
            .get_testing_only((eth_tx_hash, eth_event_idx))
            .await;
        // first unwrap should not pacic because the entry should have been inserted by `get_cache_entry`
        assert!(entry_.unwrap().lock().await.is_none());

        let (_, action) = get_test_log_and_action(contract_address, eth_tx_hash, eth_event_idx);
        let sig = BridgeAuthoritySignInfo::new(&action, &signer);
        let signed_action = SignedBridgeAction::new_from_data_and_sig(action.clone(), sig);
        entry.lock().await.replace(Ok(signed_action.clone()));
        let entry_ = eth_signer_with_cache
            .get_testing_only((eth_tx_hash, eth_event_idx))
            .await;
        assert_eq!(
            entry_.unwrap().lock().await.clone().unwrap().unwrap(),
            signed_action
        );

        // Test `sign` caches Ok result
        let eth_tx_hash = TxHash::random();
        let eth_event_idx = 0;
        let (log, _action) = get_test_log_and_action(contract_address, eth_tx_hash, eth_event_idx);
        eth_mock_provider
            .add_response::<[TxHash; 1], TransactionReceipt, TransactionReceipt>(
                "eth_getTransactionReceipt",
                [log.transaction_hash.unwrap()],
                TransactionReceipt {
                    block_number: log.block_number,
                    logs: vec![log.clone()],
                    ..Default::default()
                },
            )
            .unwrap();
        mock_last_finalized_block(&eth_mock_provider, log.block_number.unwrap().as_u64());

        eth_signer_with_cache
            .sign((eth_tx_hash, eth_event_idx))
            .await
            .unwrap();
        let entry_ = eth_signer_with_cache
            .get_testing_only((eth_tx_hash, eth_event_idx))
            .await;
        entry_.unwrap().lock().await.clone().unwrap().unwrap();
    }

    // TODO: add tests for BridgeRequestHandler (need to hook up local eth node)

    #[tokio::test]
    async fn test_eth_rejects_non_usdt_token() {
        // Construct an ETH log with token_id=3 (USDC) to verify the hardcoded
        // USDT-only check rejects it.
        let (_, kp): (_, BridgeAuthorityKeyPair) = get_key_pair();
        let signer = Arc::new(kp);
        let eth_mock_provider = EthMockProvider::default();
        let contract_address = EthAddress::random();
        let eth_client = EthClient::new_mocked(
            eth_mock_provider.clone(),
            HashSet::from_iter(vec![contract_address]),
        );
        let eth_verifier = EthActionVerifier {
            eth_client: Arc::new(eth_client),
        };
        let metrics = Arc::new(BridgeMetrics::new_for_testing());
        let mut eth_signer_with_cache =
            SignerWithCache::new(signer.clone(), eth_verifier, metrics.clone());

        let eth_tx_hash = TxHash::random();
        let eth_event_idx = 0;

        // Build a log with token_id=3 (USDC) directly
        let starcoin_bridge_address: StarcoinAddress = StarcoinAddress::random_for_testing_only();
        let target_address = {
            use fastcrypto::encoding::{Encoding, Hex};
            Hex::decode(&starcoin_bridge_address.to_string()).unwrap()
        };
        let encoded = ethers::abi::encode(&[
            ethers::abi::Token::Uint(ethers::types::U256::from(TOKEN_ID_USDC)), // USDC
            ethers::abi::Token::Uint(ethers::types::U256::from(10000000u64)),
            ethers::abi::Token::Address(EthAddress::random()),
            ethers::abi::Token::Bytes(target_address),
        ]);
        let log = ethers::types::Log {
            address: contract_address,
            topics: vec![
                ethers::abi::long_signature(
                    "TokensDeposited",
                    &[
                        ethers::abi::ParamType::Uint(8),
                        ethers::abi::ParamType::Uint(64),
                        ethers::abi::ParamType::Uint(8),
                        ethers::abi::ParamType::Uint(8),
                        ethers::abi::ParamType::Uint(64),
                        ethers::abi::ParamType::Address,
                        ethers::abi::ParamType::Bytes,
                    ],
                ),
                hex_literal::hex!(
                    "0000000000000000000000000000000000000000000000000000000000000001"
                )
                .into(),
                hex_literal::hex!(
                    "0000000000000000000000000000000000000000000000000000000000000010"
                )
                .into(),
                hex_literal::hex!(
                    "000000000000000000000000000000000000000000000000000000000000000b"
                )
                .into(),
            ],
            data: encoded.into(),
            block_hash: Some(TxHash::random()),
            block_number: Some(1.into()),
            transaction_hash: Some(eth_tx_hash),
            log_index: Some(0.into()),
            ..Default::default()
        };
        eth_mock_provider
            .add_response::<[TxHash; 1], TransactionReceipt, TransactionReceipt>(
                "eth_getTransactionReceipt",
                [eth_tx_hash],
                TransactionReceipt {
                    block_number: log.block_number,
                    logs: vec![log.clone()],
                    ..Default::default()
                },
            )
            .unwrap();
        mock_last_finalized_block(&eth_mock_provider, log.block_number.unwrap().as_u64());

        // Should reject USDC token
        let result = eth_signer_with_cache
            .sign((eth_tx_hash, eth_event_idx))
            .await;
        assert!(
            matches!(result, Err(BridgeError::UnsupportedTokenId(TOKEN_ID_USDC))),
            "Expected UnsupportedTokenId({}), got: {:?}",
            TOKEN_ID_USDC,
            result
        );

        // Verify the error is cached (deterministic, not transient)
        let entry = eth_signer_with_cache
            .get_testing_only((eth_tx_hash, eth_event_idx))
            .await;
        assert!(matches!(
            entry.unwrap().lock().await.clone().unwrap(),
            Err(BridgeError::UnsupportedTokenId(TOKEN_ID_USDC))
        ));
    }

    #[tokio::test]
    async fn test_eth_allows_usdt_token() {
        // get_test_log_and_action now produces token_id=4 (USDT), should succeed
        let (_, kp): (_, BridgeAuthorityKeyPair) = get_key_pair();
        let signer = Arc::new(kp);
        let eth_mock_provider = EthMockProvider::default();
        let contract_address = EthAddress::random();
        let eth_client = EthClient::new_mocked(
            eth_mock_provider.clone(),
            HashSet::from_iter(vec![contract_address]),
        );
        let eth_verifier = EthActionVerifier {
            eth_client: Arc::new(eth_client),
        };
        let metrics = Arc::new(BridgeMetrics::new_for_testing());
        let mut eth_signer_with_cache =
            SignerWithCache::new(signer.clone(), eth_verifier, metrics.clone());

        let eth_tx_hash = TxHash::random();
        let eth_event_idx = 0;
        let (log, _action) = get_test_log_and_action(contract_address, eth_tx_hash, eth_event_idx);
        eth_mock_provider
            .add_response::<[TxHash; 1], TransactionReceipt, TransactionReceipt>(
                "eth_getTransactionReceipt",
                [log.transaction_hash.unwrap()],
                TransactionReceipt {
                    block_number: log.block_number,
                    logs: vec![log.clone()],
                    ..Default::default()
                },
            )
            .unwrap();
        mock_last_finalized_block(&eth_mock_provider, log.block_number.unwrap().as_u64());

        // Should succeed because token_id=4 is USDT
        eth_signer_with_cache
            .sign((eth_tx_hash, eth_event_idx))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_starcoin_rejects_non_usdt_token() {
        let (_, kp): (_, BridgeAuthorityKeyPair) = get_key_pair();
        let signer = Arc::new(kp);
        let starcoin_bridge_client_mock = StarcoinMockClient::default();
        let starcoin_bridge_verifier = StarcoinActionVerifier {
            starcoin_bridge_client: Arc::new(StarcoinClient::new_for_testing(
                starcoin_bridge_client_mock.clone(),
            )),
        };
        let metrics = Arc::new(BridgeMetrics::new_for_testing());
        let mut starcoin_bridge_signer_with_cache =
            SignerWithCache::new(signer.clone(), starcoin_bridge_verifier, metrics);

        init_all_struct_tags();

        let emitted_event = MoveTokenDepositedEvent {
            seq_num: 1,
            source_chain: BridgeChainId::StarcoinCustom as u8,
            sender_address: StarcoinAddress::random_for_testing_only().to_vec(),
            target_chain: BridgeChainId::EthCustom as u8,
            target_address: EthAddress::random().as_bytes().to_vec(),
            token_type: TOKEN_ID_USDC, // token_id=3, not USDT
            amount_starcoin_bridge_adjusted: 12345,
        };

        let mut starcoin_bridge_event = StarcoinEvent::random_for_testing();
        starcoin_bridge_event.type_ = StarcoinToEthTokenBridgeV1.get().unwrap().clone();
        starcoin_bridge_event.bcs = bcs::to_bytes(&emitted_event).unwrap();
        // Set block_number to known value for finality check
        starcoin_bridge_event.id.block_number = 100;
        let starcoin_bridge_tx_digest = starcoin_bridge_event.id.tx_digest;

        // Set current block high enough so finality check passes first
        starcoin_bridge_client_mock.set_latest_block_number(200);
        starcoin_bridge_client_mock
            .add_events_by_tx_digest(starcoin_bridge_tx_digest, vec![starcoin_bridge_event]);

        // Should reject because token_id=3 is not USDT
        let result = starcoin_bridge_signer_with_cache
            .sign((starcoin_bridge_tx_digest, 0))
            .await;
        assert!(
            matches!(result, Err(BridgeError::UnsupportedTokenId(TOKEN_ID_USDC))),
            "Expected UnsupportedTokenId({}), got: {:?}",
            TOKEN_ID_USDC,
            result
        );
    }
}
