// Starcoin RPC Proxy - handles all Starcoin RPC calls in a separate process
// This avoids tokio runtime conflicts with the main bridge server

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use starcoin_bridge_sdk::StarcoinClient as StarcoinSdkClient;
use starcoin_rpc_client::RpcClient;
use std::io::{BufRead, BufReader, Write};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
enum RpcRequest {
    Connect { url: String },
    GetChainIdentifier,
    GetBridgeCommittee,
    GetBridgeSummary,
    GetLatestBlockNumber,
    Ping,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum RpcResponse {
    Success { result: serde_json::Value },
    Error { error: String },
}

struct ProxyState {
    client: Option<StarcoinSdkClient>,
}

impl ProxyState {
    fn new() -> Self {
        Self { client: None }
    }

    fn handle_request(&mut self, req: RpcRequest) -> RpcResponse {
        match self.handle_request_inner(req) {
            Ok(result) => RpcResponse::Success { result },
            Err(e) => RpcResponse::Error {
                error: format!("{:?}", e),
            },
        }
    }

    fn handle_request_inner(&mut self, req: RpcRequest) -> Result<serde_json::Value> {
        match req {
            RpcRequest::Connect { url } => {
                tracing::debug!("[proxy] Connecting to {}", url);
                let client = if url.starts_with("ws://") || url.starts_with("wss://") {
                    RpcClient::connect_websocket(&url)?
                } else {
                    RpcClient::connect_ipc(&url)?
                };
                self.client = Some(StarcoinSdkClient::new(client));
                Ok(serde_json::json!({"status": "connected"}))
            }
            RpcRequest::GetChainIdentifier => {
                let client = self
                    .client
                    .as_ref()
                    .ok_or_else(|| anyhow!("Not connected"))?;
                let chain_info = client.starcoin_client().chain_info()?;
                let chain_id = format!("{}", chain_info.chain_id);
                Ok(serde_json::to_value(chain_id)?)
            }
            RpcRequest::GetBridgeCommittee => {
                // Check we're connected
                let _client = self
                    .client
                    .as_ref()
                    .ok_or_else(|| anyhow!("Not connected"))?;
                // TODO: Implement proper bridge committee query via RPC
                // For now return placeholder
                Ok(serde_json::json!({"members": []}))
            }
            RpcRequest::GetBridgeSummary => {
                // Check we're connected
                let _client = self
                    .client
                    .as_ref()
                    .ok_or_else(|| anyhow!("Not connected"))?;
                // TODO: Implement proper bridge summary query via RPC
                Ok(serde_json::json!({"chain_id": 0}))
            }
            RpcRequest::GetLatestBlockNumber => {
                let client = self
                    .client
                    .as_ref()
                    .ok_or_else(|| anyhow!("Not connected"))?;
                let chain_info = client.starcoin_client().chain_info()?;
                let block_number = chain_info.head.number.0;
                Ok(serde_json::to_value(block_number)?)
            }
            RpcRequest::Ping => Ok(serde_json::json!({"pong": true})),
        }
    }
}

fn main() -> Result<()> {
    // Simple stderr-based logging
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::debug!("[proxy] Starcoin RPC Proxy started");

    let mut state = ProxyState::new();
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut stdout = std::io::stdout();

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // EOF - parent process closed stdin, we should exit
                tracing::debug!("[proxy] Parent closed stdin, exiting");
                break;
            }
            Ok(_) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                match serde_json::from_str::<RpcRequest>(line) {
                    Ok(req) => {
                        tracing::debug!("[proxy] Processing request: {:?}", req);
                        let response = state.handle_request(req);
                        let response_json = serde_json::to_string(&response)?;
                        writeln!(stdout, "{}", response_json)?;
                        stdout.flush()?;
                    }
                    Err(e) => {
                        tracing::debug!("[proxy] Failed to parse request: {}", e);
                        let error_response = RpcResponse::Error {
                            error: format!("Invalid request: {}", e),
                        };
                        let response_json = serde_json::to_string(&error_response)?;
                        writeln!(stdout, "{}", response_json)?;
                        stdout.flush()?;
                    }
                }
            }
            Err(e) => {
                tracing::debug!("[proxy] Error reading from stdin: {}", e);
                break;
            }
        }
    }

    tracing::debug!("[proxy] Shutting down");
    Ok(())
}
