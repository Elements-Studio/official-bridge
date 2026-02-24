// Stub for starcoin-bridge-json-rpc-api

use async_trait::async_trait;

/// Stub for Bridge Read API Client
#[async_trait]
pub trait BridgeReadApiClient {
    async fn get_bridge_object_initial_shared_version(&self) -> Result<u64, eyre::Error>;

    async fn get_latest_bridge(
        &self,
    ) -> Result<starcoin_bridge_types::bridge::BridgeSummary, eyre::Error>;
}
