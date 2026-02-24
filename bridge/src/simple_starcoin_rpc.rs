// Simple async JSON-RPC client for Starcoin
// Replaces the heavy starcoin-rpc-client to avoid tokio runtime conflicts
// Uses HTTP JSON-RPC (default port 9850)

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct SimpleStarcoinRpcClient {
    http_client: reqwest::Client,
    rpc_url: String,
    request_id: std::sync::Arc<AtomicU64>,
    bridge_address: String,
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<Value>,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    result: Option<Value>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl SimpleStarcoinRpcClient {
    pub fn new(rpc_url: impl Into<String>, bridge_address: impl Into<String>) -> Self {
        fn shared_http_client() -> reqwest::Client {
            static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
            CLIENT
                .get_or_init(|| {
                    // Keep pooling enabled (production-friendly), but tune it for
                    // bursty test workloads with many concurrent pollers.
                    reqwest::Client::builder()
                        .pool_max_idle_per_host(64)
                        .tcp_keepalive(Some(Duration::from_secs(30)))
                        .connect_timeout(Duration::from_secs(2))
                        .timeout(Duration::from_secs(30))
                        .build()
                        .expect("Failed to build reqwest client")
                })
                .clone()
        }

        Self {
            http_client: shared_http_client(),
            rpc_url: rpc_url.into(),
            request_id: std::sync::Arc::new(AtomicU64::new(1)),
            bridge_address: bridge_address.into(),
        }
    }

    /// Get the bridge contract address
    pub fn bridge_address(&self) -> &str {
        &self.bridge_address
    }

    async fn call(&self, method: &str, params: Vec<Value>) -> Result<Value> {
        self.call_with_log(method, params, false).await
    }

    /// Call RPC with optional verbose logging
    /// verbose=true: INFO level with full JSON request/response
    /// verbose=false: No logging (silent mode for background polling)
    async fn call_with_log(
        &self,
        method: &str,
        params: Vec<Value>,
        verbose: bool,
    ) -> Result<Value> {
        let id = self.request_id.fetch_add(1, Ordering::SeqCst);

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id,
        };

        // Only log if verbose mode is enabled
        if verbose {
            let request_json = serde_json::to_string_pretty(&request).unwrap_or_default();
            tracing::info!("[RPC] >>> {}\n{}", method, request_json);
        }

        fn is_transient_transport_error(err: &reqwest::Error) -> bool {
            if err.is_connect() || err.is_timeout() {
                return true;
            }

            let msg = err.to_string().to_lowercase();
            msg.contains("connection closed")
                || msg.contains("connection reset")
                || msg.contains("broken pipe")
                || msg.contains("unexpected eof")
                || msg.contains("incomplete")
        }

        let max_attempts: usize = 3;
        let mut last_transport_err: Option<anyhow::Error> = None;

        for attempt in 0..max_attempts {
            let response = match self
                .http_client
                .post(&self.rpc_url)
                .json(&request)
                .send()
                .await
            {
                Ok(resp) => resp,
                Err(err) => {
                    if attempt + 1 < max_attempts && is_transient_transport_error(&err) {
                        last_transport_err = Some(anyhow!(err));
                        tracing::warn!(
                            "[RPC] transport error calling {} (attempt {}/{}), retrying",
                            method,
                            attempt + 1,
                            max_attempts
                        );
                        tokio::time::sleep(Duration::from_millis(50 * (attempt as u64 + 1))).await;
                        continue;
                    }
                    return Err(anyhow!(err));
                }
            };

            if !response.status().is_success() {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_default();
                tracing::error!("[RPC] <<< HTTP error {} \n{}", status, error_text);
                return Err(anyhow!("HTTP error: {} - {}", status, error_text));
            }

            let response_text = match response.text().await {
                Ok(text) => text,
                Err(err) => {
                    if attempt + 1 < max_attempts && is_transient_transport_error(&err) {
                        last_transport_err = Some(anyhow!(err));
                        tracing::warn!(
                            "[RPC] failed reading response for {} (attempt {}/{}), retrying",
                            method,
                            attempt + 1,
                            max_attempts
                        );
                        tokio::time::sleep(Duration::from_millis(50 * (attempt as u64 + 1))).await;
                        continue;
                    }
                    return Err(anyhow!(err));
                }
            };

            if verbose {
                tracing::info!("[RPC] <<< {}\n{}", method, response_text);
            }

            let rpc_response: JsonRpcResponse = serde_json::from_str(&response_text)?;

            if let Some(error) = rpc_response.error {
                // Always log RPC errors
                let request_json = serde_json::to_string_pretty(&request).unwrap_or_default();
                tracing::error!(
                    "[RPC] RPC error - Request:\n{}\nResponse:\n{}",
                    request_json,
                    &response_text
                );
                return Err(anyhow!("RPC error {}: {}", error.code, error.message));
            }

            // Return the result, which may be null (valid for queries that return Option)
            return Ok(rpc_response.result.unwrap_or(Value::Null));
        }

        Err(last_transport_err.unwrap_or_else(|| anyhow!("RPC call failed after retries")))
    }

    // Chain info
    pub async fn chain_info(&self) -> Result<Value> {
        self.call("chain.info", vec![]).await
    }

    // Chain info with verbose logging (for validator finality checks)
    pub async fn chain_info_verbose(&self) -> Result<Value> {
        tracing::info!("[StarcoinRPC] >>> chain.info()");
        let result = self.call("chain.info", vec![]).await?;
        if let Some(head) = result.get("head") {
            let block_num = head.get("number").and_then(|n| {
                n.as_u64()
                    .or_else(|| n.as_str().and_then(|s| s.parse().ok()))
            });
            let block_hash = head.get("block_hash").and_then(|h| h.as_str());
            tracing::info!(
                "[StarcoinRPC] <<< chain.info: head_number={:?}, head_hash={:?}",
                block_num,
                block_hash
            );
        }
        Ok(result)
    }

    // Node info
    pub async fn node_info(&self) -> Result<Value> {
        self.call("node.info", vec![]).await
    }

    /// Get the Starcoin network chain ID from chain.info
    /// This is the transaction chain_id (e.g., 254 for dev, 251 for halley, 1 for main, 255 for test)
    pub async fn get_chain_id(&self) -> Result<u8> {
        // First try to get from chain.info which has the accurate chain_id
        let chain_info = self.call("chain.info", vec![]).await?;

        // Try to parse chain_id from chain.info response
        // Format: {"chain_id": {"id": 255}, ...}
        if let Some(chain_id_obj) = chain_info.get("chain_id") {
            if let Some(id) = chain_id_obj.get("id").and_then(|v| v.as_u64()) {
                return Ok(id as u8);
            }
        }

        // Fallback to node.info if chain.info doesn't have the chain_id
        let node_info = self.node_info().await?;

        // Parse chain id from node_info.net (ChainNetworkID serialized as string).
        // Builtin examples: "dev", "halley", "proxima", "barnard", "main", "test".
        // Custom example: "test:255" (name:chain_id).
        let chain_id = node_info
            .get("net")
            .and_then(|n| n.as_str())
            .and_then(|net| {
                let net = net.trim();
                if let Some((_, id_part)) = net.rsplit_once(':') {
                    return id_part.trim().parse::<u8>().ok();
                }

                match net.to_lowercase().as_str() {
                    // Keep these for compatibility with legacy expectations.
                    "dev" => Some(254u8),
                    "halley" => Some(253u8),
                    "proxima" => Some(252u8),
                    "barnard" => Some(251u8),
                    "main" => Some(1u8),
                    // Some environments may serialize test network as just "test".
                    "test" => Some(255u8),
                    _ => net.parse::<u8>().ok(),
                }
            })
            .ok_or_else(|| anyhow!("Failed to parse chain_id from node info"))?;

        Ok(chain_id)
    }

    /// Get the current block time in seconds from genesis
    /// Uses node.info.now_seconds which is what Starcoin uses for transaction expiration
    pub async fn get_block_timestamp(&self) -> Result<u64> {
        let node_info = self.node_info().await?;

        // Parse now_seconds from node_info response
        let now_seconds = node_info
            .get("now_seconds")
            .and_then(|t| t.as_u64())
            .or_else(|| {
                node_info
                    .get("now_seconds")
                    .and_then(|t| t.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .ok_or_else(|| anyhow!("Failed to parse now_seconds from node info"))?;

        // Return in milliseconds for compatibility with existing code
        Ok(now_seconds * 1000)
    }

    // Get resource at address (with decode option for json format)
    pub async fn get_resource(&self, address: &str, resource_type: &str) -> Result<Option<Value>> {
        let result = self
            .call(
                "state.get_resource",
                vec![
                    json!(address),
                    json!(resource_type),
                    json!({"decode": true}),
                ],
            )
            .await?;

        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    // Get account state
    pub async fn get_account(&self, address: &str) -> Result<Option<Value>> {
        let result = self.call("state.get_account", vec![json!(address)]).await?;

        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    // Get account sequence number
    // First try txpool.next_sequence_number, if null then query state.get_resource
    pub async fn get_sequence_number(&self, address: &str) -> Result<u64> {
        // Try txpool first - returns the next sequence number including pending txs
        let result = self
            .call("txpool.next_sequence_number", vec![json!(address)])
            .await?;

        // If txpool returns a number, use it
        if let Some(seq) = result.as_u64() {
            return Ok(seq);
        }

        // Otherwise, query the on-chain account resource for sequence_number
        // Starcoin uses full module path: 0x00000000000000000000000000000001::Account::Account
        let resource = self
            .get_resource(
                address,
                "0x00000000000000000000000000000001::Account::Account",
            )
            .await?;

        match resource {
            Some(res) => {
                // The resource has a "json" field with the decoded struct
                // Format: {"json": {"sequence_number": 123, ...}, "raw": "0x..."}
                let seq = res
                    .get("json")
                    .and_then(|j| j.get("sequence_number"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                Ok(seq)
            }
            None => Ok(0), // Account doesn't exist, start from 0
        }
    }

    // Query events by transaction hash
    pub async fn get_events_by_txn_hash(&self, txn_hash: &str) -> Result<Vec<Value>> {
        let result = self
            .call("chain.get_events_by_txn_hash", vec![json!(txn_hash)])
            .await?;

        Ok(serde_json::from_value(result)?)
    }

    // Query events by transaction hash with verbose logging (for validator signature requests)
    pub async fn get_events_by_txn_hash_verbose(&self, txn_hash: &str) -> Result<Vec<Value>> {
        tracing::info!(
            "[StarcoinRPC] >>> chain.get_events_by_txn_hash({})",
            txn_hash
        );
        let result = self
            .call("chain.get_events_by_txn_hash", vec![json!(txn_hash)])
            .await?;

        let events: Vec<Value> = serde_json::from_value(result)?;
        tracing::info!(
            "[StarcoinRPC] <<< chain.get_events_by_txn_hash: got {} events",
            events.len()
        );
        for (i, event) in events.iter().enumerate() {
            if let Some(type_tag) = event.get("type_tag").and_then(|t| t.as_str()) {
                tracing::info!("[StarcoinRPC]     event[{}]: type_tag={}", i, type_tag);
            }
        }
        Ok(events)
    }

    // Query events with filter
    // Starcoin RPC format: chain.get_events(filter)
    // filter: { from_block, to_block, event_keys, addrs, type_tags, limit }
    pub async fn get_events(&self, filter: Value) -> Result<Vec<Value>> {
        let result = self.call("chain.get_events", vec![filter]).await?;

        Ok(serde_json::from_value(result)?)
    }

    // Get transaction
    pub async fn get_transaction(&self, txn_hash: &str) -> Result<Value> {
        self.call("chain.get_transaction", vec![json!(txn_hash)])
            .await
    }

    // Get block by number
    pub async fn get_block_by_number(&self, number: u64) -> Result<Value> {
        self.call("chain.get_block_by_number", vec![json!(number)])
            .await
    }

    // Submit transaction with verbose logging
    pub async fn submit_transaction(&self, signed_txn: &str) -> Result<Value> {
        // Use verbose logging for transaction submission (shows full JSON request/response)
        self.call_with_log(
            "txpool.submit_hex_transaction",
            vec![json!(signed_txn)],
            true,
        )
        .await
    }

    /// Sign a RawUserTransaction and submit it to the network
    /// Uses Starcoin native types for correct BCS serialization
    pub async fn sign_and_submit_transaction(
        &self,
        key: &starcoin_bridge_types::crypto::StarcoinKeyPair,
        raw_txn: starcoin_bridge_types::transaction::RawUserTransaction,
    ) -> Result<String> {
        use starcoin_bridge_types::crypto::StarcoinKeyPair;
        use starcoin_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
        use starcoin_vm_types::account_address::AccountAddress;
        use starcoin_vm_types::genesis_config::ChainId as NativeChainId;
        use starcoin_vm_types::identifier::Identifier;
        use starcoin_vm_types::language_storage::{ModuleId, TypeTag};
        use starcoin_vm_types::transaction::{
            RawUserTransaction as NativeRawUserTransaction, ScriptFunction,
            TransactionPayload as NativeTransactionPayload,
        };

        tracing::info!(
            "[RPC] >>> sign_and_submit_transaction(sender={:?}, seq={}, chain_id={}, gas={}/{})",
            raw_txn.sender,
            raw_txn.sequence_number,
            raw_txn.chain_id.0,
            raw_txn.max_gas_amount,
            raw_txn.gas_unit_price
        );

        // Convert our RawUserTransaction to Starcoin native RawUserTransaction
        // StarcoinAddress is [u8; 16], AccountAddress::new expects [u8; 16]
        let sender = AccountAddress::new(*raw_txn.sender);

        // Convert payload - need to rebuild with starcoin_vm_types types
        let native_payload = match &raw_txn.payload {
            starcoin_bridge_types::transaction::TransactionPayload::ScriptFunction(sf) => {
                tracing::info!(
                    "[RPC]     payload: {:?}::{}::{}, type_args={:?}, args_count={}",
                    sf.module.address(),
                    sf.module.name(),
                    sf.function,
                    sf.ty_args,
                    sf.args.len()
                );

                // Rebuild ModuleId with starcoin_vm_types types
                let module_addr = AccountAddress::new(**sf.module.address());
                let module_name = Identifier::new(sf.module.name().as_str())
                    .map_err(|e| anyhow!("Invalid module name: {:?}", e))?;
                let native_module = ModuleId::new(module_addr, module_name);

                let function_name = Identifier::new(sf.function.as_str())
                    .map_err(|e| anyhow!("Invalid function name: {:?}", e))?;

                // Convert type args - they should be compatible via BCS
                let native_ty_args: Vec<TypeTag> = sf
                    .ty_args
                    .iter()
                    .map(|t| {
                        // Serialize and deserialize to convert between move_core_types versions
                        let bytes = bcs::to_bytes(t).unwrap();
                        bcs_ext::from_bytes(&bytes).unwrap()
                    })
                    .collect();

                NativeTransactionPayload::ScriptFunction(ScriptFunction::new(
                    native_module,
                    function_name,
                    native_ty_args,
                    sf.args.clone(),
                ))
            }
            _ => return Err(anyhow!("Only ScriptFunction payload is supported")),
        };

        let native_raw_txn = NativeRawUserTransaction::new_with_default_gas_token(
            sender,
            raw_txn.sequence_number,
            native_payload,
            raw_txn.max_gas_amount,
            raw_txn.gas_unit_price,
            raw_txn.expiration_timestamp_secs,
            NativeChainId::new(raw_txn.chain_id.0),
        );

        // Get Ed25519 private key bytes and create Starcoin Ed25519PrivateKey
        let (public_key_bytes, private_key_bytes) = match key {
            StarcoinKeyPair::Ed25519(kp) => {
                use fastcrypto::traits::{KeyPair as FastcryptoKeyPair, ToFromBytes};
                let priv_bytes = kp.as_bytes()[..32].to_vec(); // Ed25519 private key is first 32 bytes
                let pub_bytes = kp.public().as_bytes().to_vec();
                (pub_bytes, priv_bytes)
            }
            _ => return Err(anyhow!("Only Ed25519 keys are supported for Starcoin")),
        };

        // Create Starcoin native Ed25519 keys
        let private_key = Ed25519PrivateKey::try_from(private_key_bytes.as_slice())
            .map_err(|e| anyhow!("Invalid Ed25519 private key: {:?}", e))?;
        let public_key = Ed25519PublicKey::try_from(public_key_bytes.as_slice())
            .map_err(|e| anyhow!("Invalid Ed25519 public key: {:?}", e))?;

        // Sign using Starcoin's native signing
        let signed_txn = native_raw_txn
            .sign(&private_key, public_key)
            .map_err(|e| anyhow!("Failed to sign transaction: {:?}", e))?
            .into_inner();

        // Serialize using BCS
        let signed_txn_bytes = bcs_ext::to_bytes(&signed_txn)
            .map_err(|e| anyhow!("Failed to serialize signed transaction: {}", e))?;

        // Convert to hex and submit
        let signed_txn_hex = hex::encode(&signed_txn_bytes);

        tracing::debug!(
            "[RPC]     tx_hex(len={}): {}...",
            signed_txn_hex.len(),
            &signed_txn_hex[..std::cmp::min(100, signed_txn_hex.len())]
        );

        let result = self.submit_transaction(&signed_txn_hex).await?;

        // Return transaction hash
        let txn_hash_str = result
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{:?}", result));

        // Poll for transaction execution status (max 30 seconds)
        let mut executed = false;
        for i in 0..30 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // Use verbose logging only on first successful query
            let txn_info_result = if i == 0 {
                self.get_transaction_info_verbose(&txn_hash_str).await
            } else {
                self.get_transaction_info(&txn_hash_str).await
            };

            if let Ok(txn_info) = txn_info_result {
                if !txn_info.is_null() {
                    let status = txn_info
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown");

                    // Only log when status changes or is final
                    if status == "Executed" || status == "executed" {
                        // Print full JSON response for successful execution
                        tracing::info!(
                            "[RPC] <<< chain.get_transaction_info({}) after {}s:\\n{}",
                            txn_hash_str,
                            i + 1,
                            serde_json::to_string_pretty(&txn_info).unwrap_or_default()
                        );
                        tracing::info!(
                            "[RPC] ✓ Transaction EXECUTED successfully! txn_hash={}",
                            txn_hash_str
                        );
                        executed = true;
                        break;
                    } else if status.contains("Discard")
                        || status.contains("error")
                        || status.contains("Error")
                    {
                        // Print full JSON response for failed execution
                        tracing::error!(
                            "[RPC] <<< chain.get_transaction_info({}) FAILED:\\n{}",
                            txn_hash_str,
                            serde_json::to_string_pretty(&txn_info).unwrap_or_default()
                        );
                        executed = true;
                        break;
                    }
                }
            }

            if i > 0 && i % 5 == 0 {
                tracing::debug!("[RPC] Still waiting for transaction execution... ({}s)", i);
            }
        }

        if !executed {
            tracing::warn!(
                "[RPC] ⚠ Transaction not confirmed after 30s: txn_hash={}",
                txn_hash_str
            );
            tracing::warn!(
                "[RPC] Transaction may still be pending. Check manually with: starcoin chain get-txn {}",
                txn_hash_str
            );
        }

        Ok(txn_hash_str)
    }

    /// Sign, submit and wait for transaction confirmation
    pub async fn sign_and_submit_and_wait_transaction(
        &self,
        key: &starcoin_bridge_types::crypto::StarcoinKeyPair,
        raw_txn: starcoin_bridge_types::transaction::RawUserTransaction,
    ) -> Result<String> {
        let txn_hash = self.sign_and_submit_transaction(key, raw_txn).await?;

        // Poll for transaction confirmation (max 30 seconds)
        for _ in 0..60 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if let Ok(txn_info) = self.get_transaction_info(&txn_hash).await {
                if !txn_info.is_null() {
                    tracing::info!(?txn_hash, "Transaction confirmed on chain");
                    return Ok(txn_hash);
                }
            }
        }

        Err(anyhow!(
            "Transaction {} not confirmed after 30 seconds timeout",
            txn_hash
        ))
    }

    // Dry run transaction
    pub async fn dry_run_transaction(&self, signed_txn: &str) -> Result<Value> {
        self.call("contract.dry_run", vec![json!(signed_txn)]).await
    }

    // Get gas price (estimate from recent blocks)
    pub async fn get_gas_price(&self) -> Result<u64> {
        // Starcoin doesn't have dynamic gas price, return default
        Ok(1)
    }

    /// Get the Bridge resource from chain state
    /// Uses state.get_resource RPC to read the Bridge struct directly
    pub async fn get_latest_bridge(&self) -> Result<Value> {
        // Resource type: {bridge_address}::Bridge::Bridge
        let resource_type = format!("{}::Bridge::Bridge", self.bridge_address);

        // Call state.get_resource to read the Bridge struct
        self.call(
            "state.get_resource",
            vec![
                json!(&self.bridge_address),
                json!(resource_type),
                json!({"decode": true}),
            ],
        )
        .await
    }

    /// Call a Move contract function (read-only)
    /// function_id format: "0xADDRESS::MODULE::FUNCTION"
    /// type_args: vector of type tag strings like "0x1::STC::STC"
    /// args: vector of TransactionArgument hex strings
    pub async fn call_contract(
        &self,
        function_id: &str,
        type_args: Vec<String>,
        args: Vec<String>,
    ) -> Result<Value> {
        let contract_call = json!({
            "function_id": function_id,
            "type_args": type_args,
            "args": args
        });
        // Use normal logging, verbose logging is handled by specific callers
        self.call("contract.call_v2", vec![contract_call]).await
    }

    /// Execute transaction and return the result
    pub async fn submit_and_wait_transaction(&self, signed_txn_hex: &str) -> Result<Value> {
        // Submit transaction
        let txn_hash = self.submit_transaction(signed_txn_hex).await?;
        let txn_hash_str = txn_hash
            .as_str()
            .ok_or_else(|| anyhow!("Invalid transaction hash response"))?;

        // Poll for transaction info (simple polling with retries)
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if let Ok(txn_info) = self.get_transaction_info(txn_hash_str).await {
                if !txn_info.is_null() {
                    return Ok(txn_info);
                }
            }
        }

        Err(anyhow!("Transaction not confirmed after timeout"))
    }

    /// Get transaction info (uses DEBUG logging to avoid spam during polling)
    pub async fn get_transaction_info(&self, txn_hash: &str) -> Result<Value> {
        let result = self
            .call("chain.get_transaction_info", vec![json!(txn_hash)])
            .await?;
        Ok(result)
    }

    /// Get transaction info with verbose INFO logging (for first query)
    pub async fn get_transaction_info_verbose(&self, txn_hash: &str) -> Result<Value> {
        let result = self
            .call_with_log("chain.get_transaction_info", vec![json!(txn_hash)], true)
            .await?;
        Ok(result)
    }

    /// Get block info by height/number - needed for DAG finality checking
    /// Returns BlockInfoView with blue_blocks (descendants in DAG)
    pub async fn get_block_info_by_number(&self, block_number: u64) -> Result<Option<Value>> {
        let result = self
            .call("chain.get_block_info_by_number", vec![json!(block_number)])
            .await?;

        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_chain_info() {
        let client = SimpleStarcoinRpcClient::new(
            "http://127.0.0.1:9850",
            "0x0000000000000000000000000000dead", // dummy address for test
        );
        let result = client.chain_info().await;
        tracing::debug!("{:?}", result);
    }
}
