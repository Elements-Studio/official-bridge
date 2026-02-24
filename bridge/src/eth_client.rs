// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::sync::Arc;

use crate::abi::EthBridgeEvent;
use crate::error::{BridgeError, BridgeResult};
use crate::finality::{EthFinalityChecker, FinalityChecker, FinalityConfig, FinalityMode};
use crate::metered_eth_provider::{new_metered_eth_provider, MeteredEthHttpProvier};
use crate::metrics::BridgeMetrics;
use crate::types::{BridgeAction, EthLog, RawEthLog};
use ethers::providers::{JsonRpcClient, Middleware, Provider};
use ethers::types::Filter;
use ethers::types::TxHash;
use tap::TapFallible;

#[cfg(test)]
use crate::eth_mock_provider::EthMockProvider;
use ethers::types::Address as EthAddress;

/// Anvil/Hardhat local network chain ID
const LOCAL_CHAIN_ID: u64 = 31337;

pub struct EthClient<P> {
    provider: Provider<P>,
    contract_addresses: HashSet<EthAddress>,
    /// Expected chain ID for validation
    expected_chain_id: Option<u64>,
    /// Finality checker for determining block finality
    finality_checker: EthFinalityChecker<P>,
}

impl EthClient<MeteredEthHttpProvier> {
    pub async fn new(
        provider_url: &str,
        contract_addresses: HashSet<EthAddress>,
        metrics: Arc<BridgeMetrics>,
    ) -> anyhow::Result<Self> {
        Self::new_with_options(
            provider_url,
            contract_addresses,
            metrics,
            None,
            None, // Auto-detect
        )
        .await
    }

    pub async fn new_with_chain_id(
        provider_url: &str,
        contract_addresses: HashSet<EthAddress>,
        metrics: Arc<BridgeMetrics>,
        expected_chain_id: Option<u64>,
    ) -> anyhow::Result<Self> {
        Self::new_with_options(
            provider_url,
            contract_addresses,
            metrics,
            expected_chain_id,
            None, // Auto-detect
        )
        .await
    }

    /// Create ETH client with full options
    ///
    /// # Arguments
    /// * `force_latest_block` - If Some(true), always use 'latest' block (local mode).
    ///   If Some(false), always use 'finalized' block (native finality).
    ///   If None, auto-detect based on chain ID.
    pub async fn new_with_options(
        provider_url: &str,
        contract_addresses: HashSet<EthAddress>,
        metrics: Arc<BridgeMetrics>,
        expected_chain_id: Option<u64>,
        force_latest_block: Option<bool>,
    ) -> anyhow::Result<Self> {
        let provider = new_metered_eth_provider(provider_url, metrics)?;

        // Determine if this is a local network
        let chain_id = provider.get_chainid().await?.as_u64();
        let is_local = match force_latest_block {
            Some(force) => force,
            None => chain_id == LOCAL_CHAIN_ID, // Auto-detect for local network
        };

        // Create finality config based on network type
        let finality_config = if is_local {
            FinalityConfig::eth_testnet().with_mode(FinalityMode::BlockCounting)
        } else {
            FinalityConfig::eth_mainnet()
        };

        // Create finality checker
        let provider_arc = Arc::new(provider.clone());
        let finality_checker =
            EthFinalityChecker::with_config(provider_arc, "eth", finality_config);

        let self_ = Self {
            provider,
            contract_addresses,
            expected_chain_id,
            finality_checker,
        };

        match force_latest_block {
            Some(true) => tracing::info!("Using block counting finality (forced by config)"),
            Some(false) => tracing::info!("Using native finality (forced by config)"),
            None if is_local => {
                tracing::info!(
                    "Local network detected (chain_id={}), using block counting finality",
                    chain_id
                );
            }
            None => {
                tracing::info!("Using native finality for chain_id={}", chain_id);
            }
        }

        self_.describe().await?;
        Ok(self_)
    }

    /// Check if this client uses block counting (local mode) instead of native finality
    pub fn uses_latest_block(&self) -> bool {
        !self.finality_checker.uses_native_finality()
    }

    pub fn provider(&self) -> Arc<Provider<MeteredEthHttpProvier>> {
        Arc::new(self.provider.clone())
    }

    /// Get the current chain ID that was detected during construction
    pub async fn get_detected_chain_id(&self) -> anyhow::Result<u64> {
        self.get_chain_id().await
    }
}

#[cfg(test)]
impl EthClient<EthMockProvider> {
    pub fn new_mocked(provider: EthMockProvider, contract_addresses: HashSet<EthAddress>) -> Self {
        let provider = Provider::new(provider);
        let provider_arc = Arc::new(provider.clone());
        // Use native finality mode for mocked tests (tests can override behavior via mock responses)
        let finality_config = FinalityConfig::eth_mainnet();
        let finality_checker =
            EthFinalityChecker::with_config(provider_arc, "eth-mock", finality_config);
        Self {
            provider,
            contract_addresses,
            expected_chain_id: None,
            finality_checker,
        }
    }

    /// Create a mocked client with local (block counting) finality mode
    pub fn new_mocked_local(
        provider: EthMockProvider,
        contract_addresses: HashSet<EthAddress>,
    ) -> Self {
        let provider = Provider::new(provider);
        let provider_arc = Arc::new(provider.clone());
        let finality_config = FinalityConfig::eth_testnet().with_mode(FinalityMode::BlockCounting);
        let finality_checker =
            EthFinalityChecker::with_config(provider_arc, "eth-mock-local", finality_config);
        Self {
            provider,
            contract_addresses,
            expected_chain_id: None,
            finality_checker,
        }
    }
}

impl<P> EthClient<P>
where
    P: JsonRpcClient + 'static,
{
    pub async fn get_chain_id(&self) -> Result<u64, anyhow::Error> {
        let chain_id = self.provider.get_chainid().await?;
        Ok(chain_id.as_u64())
    }

    // Validate chain identifier and log connection info
    async fn describe(&self) -> anyhow::Result<()> {
        let chain_id = self.get_chain_id().await?;
        let block_number = self.provider.get_block_number().await?;

        // Validate chain ID if expected value is set
        if let Some(expected) = self.expected_chain_id {
            if chain_id != expected {
                return Err(anyhow::anyhow!(
                    "Chain ID mismatch: expected {}, got {}. This could indicate connecting to the wrong network!",
                    expected,
                    chain_id
                ));
            }
            tracing::info!(
                "EthClient connected to chain {} (verified), current block: {}",
                chain_id,
                block_number
            );
        } else {
            tracing::warn!(
                "EthClient connected to chain {} (NOT VERIFIED - no expected chain ID set), current block: {}",
                chain_id,
                block_number
            );
        }
        Ok(())
    }

    // Returns BridgeAction from an Eth Transaction with transaction hash
    // and the event index. If event is declared in an unrecognized
    // contract, return error.
    pub async fn get_finalized_bridge_action_maybe(
        &self,
        tx_hash: TxHash,
        event_idx: u16,
    ) -> BridgeResult<BridgeAction> {
        tracing::info!(
            "[EthClient] Fetching receipt for tx_hash={:?}, event_idx={}",
            tx_hash,
            event_idx
        );
        let receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(|e| {
                tracing::error!(
                    "[EthClient] ❌ RPC error getting receipt: tx_hash={:?}, error={:?}",
                    tx_hash,
                    e
                );
                BridgeError::from(e)
            })?
            .ok_or_else(|| {
                tracing::warn!(
                    "[EthClient] ⚠️ Receipt not found (tx may be pending): tx_hash={:?}",
                    tx_hash
                );
                BridgeError::TxNotFound
            })?;
        let receipt_block_num = receipt.block_number.ok_or(BridgeError::ProviderError(
            "Provider returns log without block_number".into(),
        ))?;
        tracing::info!(
            "[EthClient] Receipt found: tx_hash={:?}, block_num={}, status={:?}, logs_count={}",
            tx_hash,
            receipt_block_num,
            receipt.status,
            receipt.logs.len()
        );
        // Finalized block ID is cached to reduce RPC calls
        let last_finalized_block_id = self.get_last_finalized_block_id().await?;
        let tx_block = receipt_block_num.as_u64();
        tracing::info!(
            "[EthClient] Finality check: tx_hash={:?}, tx_block={}, finalized_block={}, is_finalized={}",
            tx_hash, tx_block, last_finalized_block_id, tx_block <= last_finalized_block_id
        );
        if tx_block > last_finalized_block_id {
            // Calculate blocks remaining and estimated wait time
            let blocks_to_finalize = tx_block.saturating_sub(last_finalized_block_id);
            // ETH block time is ~12 seconds
            let estimated_wait_secs = Some(blocks_to_finalize * 12);
            tracing::warn!(
                "[EthClient] ⏳ Tx not finalized: tx_hash={:?}, tx_block={}, finalized_block={}, blocks_remaining={}, estimated_wait_secs={:?}",
                tx_hash, tx_block, last_finalized_block_id, blocks_to_finalize, estimated_wait_secs
            );
            return Err(BridgeError::TxNotFinalized(
                crate::error::TxNotFinalizedInfo {
                    chain: "ethereum".to_string(),
                    tx_block,
                    finalized_block: last_finalized_block_id,
                    blocks_to_finalize,
                    estimated_wait_secs,
                },
            ));
        }
        let log = receipt
            .logs
            .get(event_idx as usize)
            .ok_or(BridgeError::NoBridgeEventsInTxPosition)?;

        tracing::info!(
            "[EthClient] Found log at event_idx={}: address={:?}, topics={:?}, data_len={}",
            event_idx,
            log.address,
            log.topics,
            log.data.len()
        );

        // Ignore events emitted from unrecognized contracts
        if !self.contract_addresses.contains(&log.address) {
            tracing::warn!(
                "[EthClient] ❌ BridgeEventInUnrecognizedEthContract: log.address={:?}, known_addresses={:?}",
                log.address,
                self.contract_addresses
            );
            return Err(BridgeError::BridgeEventInUnrecognizedEthContract);
        }

        let eth_log = EthLog {
            block_number: receipt_block_num.as_u64(),
            tx_hash,
            log_index_in_tx: event_idx,
            log: log.clone(),
        };
        let bridge_event = EthBridgeEvent::try_from_eth_log(&eth_log)
            .ok_or(BridgeError::NoBridgeEventsInTxPosition)?;
        tracing::info!(
            "[EthClient] ✅ Parsed bridge event successfully: tx_hash={:?}, event_idx={}, event_type={:?}",
            tx_hash, event_idx, std::any::type_name_of_val(&bridge_event)
        );
        bridge_event
            .try_into_bridge_action(tx_hash, event_idx)?
            .ok_or(BridgeError::BridgeEventNotActionable)
    }

    /// Get the last finalized block ID with caching.
    ///
    /// This method uses the internal FinalityChecker which caches the finalized
    /// block ID to reduce RPC calls.
    ///
    /// Note: The finalized block can only increase, so cached values
    /// are always safe (we might just reject some valid but recent transactions
    /// as "not finalized" for a short period).
    pub async fn get_last_finalized_block_id(&self) -> BridgeResult<u64> {
        self.finality_checker
            .get_finalized_block()
            .await
            .map_err(|e| {
                BridgeError::TransientProviderError(format!("Finality check failed: {}", e))
            })
    }

    /// Check if a specific block is finalized
    pub async fn is_block_finalized(&self, block_number: u64) -> BridgeResult<bool> {
        self.finality_checker
            .is_finalized(block_number)
            .await
            .map_err(|e| {
                BridgeError::TransientProviderError(format!("Finality check failed: {}", e))
            })
    }

    /// Get the finality checker for advanced usage
    pub fn finality_checker(&self) -> &EthFinalityChecker<P> {
        &self.finality_checker
    }

    /// Get the latest block number (not finalized, for real-time sync)
    pub async fn get_latest_block_id(&self) -> BridgeResult<u64> {
        self.finality_checker.get_latest_block().await.map_err(|e| {
            BridgeError::TransientProviderError(format!("Failed to get latest block: {}", e))
        })
    }

    // Note: query may fail if range is too big. Callsite is responsible
    // for chunking the query.
    pub async fn get_events_in_range(
        &self,
        address: ethers::types::Address,
        start_block: u64,
        end_block: u64,
    ) -> BridgeResult<Vec<EthLog>> {
        let filter = Filter::new()
            .from_block(start_block)
            .to_block(end_block)
            .address(address);
        let logs = self
            .provider
            // TODO use get_logs_paginated?
            .get_logs(&filter)
            .await
            .map_err(BridgeError::from)
            .tap_err(|e| {
                tracing::error!(
                    "get_events_in_range failed. Filter: {:?}. Error {:?}",
                    filter,
                    e
                )
            })?;

        // Safeguard check that all events are emitted from requested contract address
        if logs.iter().any(|log| log.address != address) {
            return Err(BridgeError::ProviderError(format!(
                "Provider returns logs from different contract address (expected: {:?}): {:?}",
                address, logs
            )));
        }
        if logs.is_empty() {
            return Ok(vec![]);
        }

        let tasks = logs.into_iter().map(|log| self.get_log_tx_details(log));
        futures::future::join_all(tasks)
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .tap_err(|e| {
                tracing::error!(
                    "get_log_tx_details failed. Filter: {:?}. Error {:?}",
                    filter,
                    e
                )
            })
    }

    // Note: query may fail if range is too big. Callsite is responsible
    // for chunking the query.
    pub async fn get_raw_events_in_range(
        &self,
        addresses: Vec<ethers::types::Address>,
        start_block: u64,
        end_block: u64,
    ) -> BridgeResult<Vec<RawEthLog>> {
        let filter = Filter::new()
            .from_block(start_block)
            .to_block(end_block)
            .address(addresses.clone());
        let logs = self
            .provider
            .get_logs(&filter)
            .await
            .map_err(BridgeError::from)
            .tap_err(|e| {
                tracing::error!(
                    "get_events_in_range failed. Filter: {:?}. Error {:?}",
                    filter,
                    e
                )
            })?;
        // Safeguard check that all events are emitted from requested contract addresses
        logs.into_iter().map(
            |log| {
                if !addresses.contains(&log.address) {
                    return Err(BridgeError::ProviderError(format!("Provider returns logs from different contract address (expected: {:?}): {:?}", addresses, log)));
                }
                Ok(RawEthLog {
                block_number: log.block_number.ok_or(BridgeError::ProviderError("Provider returns log without block_number".into()))?.as_u64(),
                tx_hash: log.transaction_hash.ok_or(BridgeError::ProviderError("Provider returns log without transaction_hash".into()))?,
                log,
            })}
        ).collect::<Result<Vec<_>, _>>()
    }

    // This function converts a `Log` to `EthLog`, to make sure the `block_num`, `tx_hash` and `log_index_in_tx`
    // are available for downstream.
    // It's frustratingly ugly because of the nulliability of many fields in `Log`.
    async fn get_log_tx_details(&self, log: ethers::types::Log) -> BridgeResult<EthLog> {
        let block_number = log
            .block_number
            .ok_or(BridgeError::ProviderError(
                "Provider returns log without block_number".into(),
            ))?
            .as_u64();
        let tx_hash = log.transaction_hash.ok_or(BridgeError::ProviderError(
            "Provider returns log without transaction_hash".into(),
        ))?;
        // This is the log index in the block, rather than transaction.
        let log_index = log.log_index.ok_or(BridgeError::ProviderError(
            "Provider returns log without log_index".into(),
        ))?;

        // Now get the log's index in the transaction. There is `transaction_log_index` field in
        // `Log`, but I never saw it populated.

        let receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(BridgeError::from)?
            .ok_or(BridgeError::ProviderError(format!(
                "Provide cannot find eth transaction for log: {:?})",
                log
            )))?;

        let receipt_block_num = receipt.block_number.ok_or(BridgeError::ProviderError(
            "Provider returns log without block_number".into(),
        ))?;
        if receipt_block_num.as_u64() != block_number {
            return Err(BridgeError::ProviderError(format!("Provider returns receipt with different block number from log. Receipt: {:?}, Log: {:?}", receipt, log)));
        }

        // Find the log index in the transaction
        let mut log_index_in_tx = None;
        for (idx, receipt_log) in receipt.logs.iter().enumerate() {
            // match log index (in the block)
            if receipt_log.log_index == Some(log_index) {
                // make sure the topics and data match
                if receipt_log.topics != log.topics || receipt_log.data != log.data {
                    return Err(BridgeError::ProviderError(format!("Provider returns receipt with different log from log. Receipt: {:?}, Log: {:?}", receipt, log)));
                }
                log_index_in_tx = Some(idx);
            }
        }
        let log_index_in_tx = log_index_in_tx.ok_or(BridgeError::ProviderError(format!(
            "Couldn't find matching log: {:?} in transaction {}",
            log, tx_hash
        )))?;

        Ok(EthLog {
            block_number,
            tx_hash,
            log_index_in_tx: log_index_in_tx as u16,
            log,
        })
    }
}

#[cfg(test)]
mod tests {
    use ethers::types::{Address as EthAddress, Block, Log, TransactionReceipt, U64};
    use prometheus::Registry;

    use super::*;
    use crate::test_utils::{get_test_log_and_action, mock_last_finalized_block};

    #[tokio::test]
    async fn test_get_finalized_bridge_action_maybe() {
        telemetry_subscribers::init_for_testing();
        let registry = Registry::new();
        starcoin_metrics::init_metrics(&registry);
        let mock_provider = EthMockProvider::new();
        mock_last_finalized_block(&mock_provider, 777);

        let client = EthClient::new_mocked(
            mock_provider.clone(),
            HashSet::from_iter(vec![EthAddress::zero()]),
        );
        let result = client.get_last_finalized_block_id().await.unwrap();
        assert_eq!(result, 777);

        let eth_tx_hash = TxHash::random();
        let log = Log {
            transaction_hash: Some(eth_tx_hash),
            block_number: Some(U64::from(778)),
            ..Default::default()
        };
        let (good_log, bridge_action) = get_test_log_and_action(EthAddress::zero(), eth_tx_hash, 1);
        // Mocks `eth_getTransactionReceipt` to return `log` and `good_log` in order
        mock_provider
            .add_response::<[TxHash; 1], TransactionReceipt, TransactionReceipt>(
                "eth_getTransactionReceipt",
                [log.transaction_hash.unwrap()],
                TransactionReceipt {
                    block_number: log.block_number,
                    logs: vec![log, good_log],
                    ..Default::default()
                },
            )
            .unwrap();

        let error = client
            .get_finalized_bridge_action_maybe(eth_tx_hash, 0)
            .await
            .unwrap_err();
        match error {
            BridgeError::TxNotFinalized(info) => {
                assert_eq!(info.chain, "ethereum");
                assert_eq!(info.tx_block, 778);
                assert_eq!(info.finalized_block, 777);
                assert_eq!(info.blocks_to_finalize, 1);
            }
            _ => panic!("expected TxNotFinalized"),
        };

        // 778 is now finalized
        mock_last_finalized_block(&mock_provider, 778);
        // Invalidate cache so the new mock value is fetched
        client.finality_checker.invalidate_cache().await;

        let error = client
            .get_finalized_bridge_action_maybe(eth_tx_hash, 2)
            .await
            .unwrap_err();
        // Receipt only has 2 logs
        match error {
            BridgeError::NoBridgeEventsInTxPosition => {}
            _ => panic!("expected NoBridgeEventsInTxPosition"),
        };

        let error = client
            .get_finalized_bridge_action_maybe(eth_tx_hash, 0)
            .await
            .unwrap_err();
        // Same, `log` is not a BridgeEvent
        match error {
            BridgeError::NoBridgeEventsInTxPosition => {}
            _ => panic!("expected NoBridgeEventsInTxPosition"),
        };

        let action = client
            .get_finalized_bridge_action_maybe(eth_tx_hash, 1)
            .await
            .unwrap();
        assert_eq!(action, bridge_action);
    }

    #[tokio::test]
    async fn test_get_finalized_bridge_action_maybe_unrecognized_contract() {
        telemetry_subscribers::init_for_testing();
        let registry = Registry::new();
        starcoin_metrics::init_metrics(&registry);
        let mock_provider = EthMockProvider::new();
        mock_last_finalized_block(&mock_provider, 777);

        let client = EthClient::new_mocked(
            mock_provider.clone(),
            HashSet::from_iter(vec![
                EthAddress::repeat_byte(5),
                EthAddress::repeat_byte(6),
                EthAddress::repeat_byte(7),
            ]),
        );
        let result = client.get_last_finalized_block_id().await.unwrap();
        assert_eq!(result, 777);

        let eth_tx_hash = TxHash::random();
        // Event emitted from a different contract address
        let (log, _) = get_test_log_and_action(EthAddress::repeat_byte(4), eth_tx_hash, 0);
        mock_provider
            .add_response::<[TxHash; 1], TransactionReceipt, TransactionReceipt>(
                "eth_getTransactionReceipt",
                [log.transaction_hash.unwrap()],
                TransactionReceipt {
                    block_number: log.block_number,
                    logs: vec![log],
                    ..Default::default()
                },
            )
            .unwrap();

        let error = client
            .get_finalized_bridge_action_maybe(eth_tx_hash, 0)
            .await
            .unwrap_err();
        match error {
            BridgeError::BridgeEventInUnrecognizedEthContract => {}
            _ => panic!("expected TxNotFinalized"),
        };

        // Ok if emitted from the right contract
        let (log, bridge_action) =
            get_test_log_and_action(EthAddress::repeat_byte(6), eth_tx_hash, 0);
        mock_provider
            .add_response::<[TxHash; 1], TransactionReceipt, TransactionReceipt>(
                "eth_getTransactionReceipt",
                [log.transaction_hash.unwrap()],
                TransactionReceipt {
                    block_number: log.block_number,
                    logs: vec![log],
                    ..Default::default()
                },
            )
            .unwrap();
        let action = client
            .get_finalized_bridge_action_maybe(eth_tx_hash, 0)
            .await
            .unwrap();
        assert_eq!(action, bridge_action);
    }

    #[tokio::test]
    async fn test_chain_id_validation_with_mocked_client() {
        // Test that chain ID is correctly retrieved and can be validated
        telemetry_subscribers::init_for_testing();
        let mock_provider = EthMockProvider::new();

        // Mock chain ID response
        mock_provider
            .add_response("eth_chainId", (), ethers::types::U256::from(1u64))
            .unwrap();

        let client = EthClient::new_mocked(
            mock_provider.clone(),
            HashSet::from_iter(vec![EthAddress::zero()]),
        );

        // Verify chain ID is returned correctly
        let chain_id = client.get_chain_id().await.unwrap();
        assert_eq!(chain_id, 1);
    }

    #[tokio::test]
    async fn test_chain_id_validation_different_networks() {
        // Test with various network chain IDs to ensure correct behavior
        let test_cases = vec![
            (1u64, "mainnet"),
            (5, "goerli"),
            (11155111, "sepolia"),
            (31337, "hardhat/anvil local"),
            (42161, "arbitrum"),
        ];

        for (expected_chain_id, network_name) in test_cases {
            let mock_provider = EthMockProvider::new();
            mock_provider
                .add_response(
                    "eth_chainId",
                    (),
                    ethers::types::U256::from(expected_chain_id),
                )
                .unwrap();

            let client =
                EthClient::new_mocked(mock_provider, HashSet::from_iter(vec![EthAddress::zero()]));

            let chain_id = client.get_chain_id().await.unwrap();
            assert_eq!(
                chain_id, expected_chain_id,
                "Chain ID mismatch for {}: expected {}, got {}",
                network_name, expected_chain_id, chain_id
            );
        }
    }

    #[tokio::test]
    async fn test_expected_chain_id_field() {
        // Test that expected_chain_id field is correctly set
        let mock_provider = EthMockProvider::new();

        // Create client with no expected chain ID
        let client = EthClient::new_mocked(
            mock_provider.clone(),
            HashSet::from_iter(vec![EthAddress::zero()]),
        );
        assert!(client.expected_chain_id.is_none());

        // Create another client with different mock provider
        let mock_provider2 = EthMockProvider::new();
        let client2 =
            EthClient::new_mocked(mock_provider2, HashSet::from_iter(vec![EthAddress::zero()]));
        // Both should have None as expected_chain_id (set via new_with_chain_id only)
        assert_eq!(client2.expected_chain_id, None);
    }

    #[tokio::test]
    async fn test_finalized_block_caching() {
        // Test that finality checker caching works correctly
        telemetry_subscribers::init_for_testing();
        let mock_provider = EthMockProvider::new();

        // Mock finalized block response
        mock_provider
            .add_response::<(&str, bool), Block<TxHash>, _>(
                "eth_getBlockByNumber",
                ("finalized", false),
                Block::<TxHash> {
                    number: Some(U64::from(12345)),
                    ..Default::default()
                },
            )
            .unwrap();

        let client = EthClient::new_mocked(
            mock_provider.clone(),
            HashSet::from_iter(vec![EthAddress::zero()]),
        );

        // First call should fetch from provider
        let block1 = client.get_last_finalized_block_id().await.unwrap();
        assert_eq!(block1, 12345);

        // Second call should use cache (provider won't be called again)
        let block2 = client.get_last_finalized_block_id().await.unwrap();
        assert_eq!(block2, 12345);
    }

    #[tokio::test]
    async fn test_get_last_finalized_block_id_uses_cache() {
        telemetry_subscribers::init_for_testing();
        let mock_provider = EthMockProvider::new();

        // Mock finalized block response
        mock_provider
            .add_response::<(&str, bool), Block<TxHash>, _>(
                "eth_getBlockByNumber",
                ("finalized", false),
                Block::<TxHash> {
                    number: Some(U64::from(1000)),
                    ..Default::default()
                },
            )
            .unwrap();

        let client = EthClient::new_mocked(
            mock_provider.clone(),
            HashSet::from_iter(vec![EthAddress::zero()]),
        );

        // First call should fetch from provider
        let block1 = client.get_last_finalized_block_id().await.unwrap();
        assert_eq!(block1, 1000);

        // Second call should use cache (provider won't be called again)
        // If it wasn't cached, this would fail because mock only responds once per unique params
        let block2 = client.get_last_finalized_block_id().await.unwrap();
        assert_eq!(block2, 1000);
    }

    #[tokio::test]
    async fn test_get_latest_block_id() {
        telemetry_subscribers::init_for_testing();
        let mock_provider = EthMockProvider::new();

        // Mock eth_blockNumber response (used by finality_checker.get_latest_block)
        mock_provider
            .add_response("eth_blockNumber", (), U64::from(2000))
            .unwrap();

        let client = EthClient::new_mocked(
            mock_provider.clone(),
            HashSet::from_iter(vec![EthAddress::zero()]),
        );

        let latest = client.get_latest_block_id().await.unwrap();
        assert_eq!(latest, 2000);
    }

    #[tokio::test]
    async fn test_latest_vs_finalized_block() {
        telemetry_subscribers::init_for_testing();
        let mock_provider = EthMockProvider::new();

        // Mock finalized block response
        mock_provider
            .add_response::<(&str, bool), Block<TxHash>, _>(
                "eth_getBlockByNumber",
                ("finalized", false),
                Block::<TxHash> {
                    number: Some(U64::from(1000)),
                    ..Default::default()
                },
            )
            .unwrap();

        // Mock eth_blockNumber response (used by finality_checker.get_latest_block)
        mock_provider
            .add_response("eth_blockNumber", (), U64::from(1050))
            .unwrap();

        let client = EthClient::new_mocked(
            mock_provider.clone(),
            HashSet::from_iter(vec![EthAddress::zero()]),
        );

        let finalized = client.get_last_finalized_block_id().await.unwrap();
        let latest = client.get_latest_block_id().await.unwrap();

        // Latest should always be >= finalized
        assert!(latest >= finalized);
        assert_eq!(finalized, 1000);
        assert_eq!(latest, 1050);
    }
}
