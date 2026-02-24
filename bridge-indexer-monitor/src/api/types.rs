// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! API response types for cross-chain transfers

use serde::{Deserialize, Serialize};

/// Transfer status enum matching database
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    Deposited,
    Approved,
    Claimed,
}

impl From<starcoin_bridge_schema::models::TokenTransferStatus> for TransferStatus {
    fn from(status: starcoin_bridge_schema::models::TokenTransferStatus) -> Self {
        match status {
            starcoin_bridge_schema::models::TokenTransferStatus::Deposited => {
                TransferStatus::Deposited
            }
            starcoin_bridge_schema::models::TokenTransferStatus::Approved => {
                TransferStatus::Approved
            }
            starcoin_bridge_schema::models::TokenTransferStatus::Claimed => TransferStatus::Claimed,
        }
    }
}

/// Data source enum matching database
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DataSource {
    Starcoin,
    Eth,
}

impl From<starcoin_bridge_schema::models::BridgeDataSource> for DataSource {
    fn from(source: starcoin_bridge_schema::models::BridgeDataSource) -> Self {
        match source {
            starcoin_bridge_schema::models::BridgeDataSource::STARCOIN => DataSource::Starcoin,
            starcoin_bridge_schema::models::BridgeDataSource::ETH => DataSource::Eth,
        }
    }
}

/// Full transfer details - includes transfer data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferDetail {
    /// Source chain ID
    pub chain_id: i32,
    /// Transfer nonce (unique within chain)
    pub nonce: i64,
    /// Current status
    pub status: TransferStatus,
    /// Block height where event occurred
    pub block_height: i64,
    /// Timestamp in milliseconds
    pub timestamp_ms: i64,
    /// Transaction hash (hex encoded)
    pub txn_hash: String,
    /// Sender address (hex encoded)
    pub sender_address: String,
    /// Whether the transfer is finalized
    pub is_finalized: bool,
    /// Data source (STARCOIN or ETH)
    pub data_source: DataSource,
    /// Gas usage
    pub gas_usage: i64,
    /// Transfer data (if available)
    pub transfer_data: Option<TransferDataDetail>,
    /// All status updates for this transfer
    pub status_history: Vec<TransferStatusUpdate>,
}

/// Transfer data details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferDataDetail {
    /// Destination chain ID
    pub destination_chain: i32,
    /// Recipient address (hex encoded)
    pub recipient_address: String,
    /// Token ID
    pub token_id: i32,
    /// Amount formatted as "100.123456 USDT"
    pub amount: String,
}

/// Status update history item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferStatusUpdate {
    pub status: TransferStatus,
    pub block_height: i64,
    pub timestamp_ms: i64,
    pub txn_hash: String,
    pub data_source: DataSource,
}

/// Pagination info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pagination {
    pub page: u32,
    pub page_size: u32,
    pub total_count: i64,
    pub total_pages: u32,
}

/// Transfer list response - returns complete cross-chain procedure info for each transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferListResponse {
    pub transfers: Vec<CrossChainProcedure>,
    pub pagination: Pagination,
    /// Claim delay in seconds - time to wait after approval before claim is allowed
    #[serde(default)]
    pub claim_delay_seconds: u64,
}

/// Transfer detail response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferDetailResponse {
    pub transfer: TransferDetail,
    /// Claim delay in seconds - time to wait after approval before claim is allowed
    #[serde(default)]
    pub claim_delay_seconds: u64,
}

// ============================================================================
// Cross-chain procedure types (for querying by deposit txn)
// ============================================================================

/// Complete cross-chain transfer procedure response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferByDepositTxnResponse {
    pub procedure: CrossChainProcedure,
    /// Claim delay in seconds
    #[serde(default)]
    pub claim_delay_seconds: u64,
}

/// Full cross-chain procedure data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainProcedure {
    /// Source chain ID where deposit occurred
    pub source_chain_id: i32,
    /// Source chain name ("ETH" or "STARCOIN")
    pub source_chain: String,
    /// Destination chain ID where claim will occur
    pub destination_chain_id: i32,
    /// Destination chain name ("ETH" or "STARCOIN")
    pub destination_chain: String,
    /// Transfer nonce (unique within source chain)
    pub nonce: i64,
    /// Current status of the transfer
    pub current_status: TransferStatus,
    /// Whether the transfer is complete (claimed)
    pub is_complete: bool,

    /// Deposit information (always present)
    pub deposit: DepositInfo,
    /// Approval information (present after bridge committee approval)
    pub approval: Option<ApprovalInfo>,
    /// Claim information (present after successful claim)
    pub claim: Option<ClaimInfo>,
}

/// Deposit event information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositInfo {
    /// Deposit transaction hash (hex)
    pub txn_hash: String,
    /// Block height on source chain
    pub block_height: i64,
    /// Timestamp in milliseconds
    pub timestamp_ms: i64,
    /// Sender address (hex)
    pub sender_address: String,
    /// Recipient address on destination chain (hex)
    pub recipient_address: String,
    /// Token ID being transferred
    pub token_id: i32,
    /// Amount formatted as "100.123456 USDT"
    pub amount: String,
    /// Whether deposit is finalized on source chain
    pub is_finalized: bool,
}

/// Approval event information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalInfo {
    /// Approval transaction hash (hex)
    pub txn_hash: String,
    /// Block height where approval was recorded
    pub block_height: i64,
    /// Timestamp in milliseconds
    pub timestamp_ms: i64,
    /// Which chain recorded the approval
    pub data_source: DataSource,
    /// Whether approval is finalized
    pub is_finalized: bool,
}

/// Claim event information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimInfo {
    /// Claim transaction hash (hex)
    pub txn_hash: String,
    /// Block height on destination chain
    pub block_height: i64,
    /// Timestamp in milliseconds
    pub timestamp_ms: i64,
    /// Address that executed the claim (hex)
    pub claimer_address: String,
    /// Gas used for claim transaction
    pub gas_usage: i64,
    /// Destination chain
    pub data_source: DataSource,
    /// Whether claim is finalized
    pub is_finalized: bool,
}

/// Query parameters for list endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct TransferListQuery {
    /// Filter by sender OR recipient address (hex, with or without 0x prefix)
    pub address: Option<String>,
    /// Filter by sender address only (hex, with or without 0x prefix)
    pub sender: Option<String>,
    /// Filter by recipient address only (hex, with or without 0x prefix)
    pub receiver: Option<String>,
    /// Filter by source chain ID
    pub chain_id: Option<i32>,
    /// Filter by status
    pub status: Option<String>,
    /// Only include finalized transfers
    pub finalized_only: Option<bool>,
    /// Page number (1-based)
    #[serde(default = "default_page")]
    pub page: u32,
    /// Page size
    #[serde(default = "default_page_size")]
    pub page_size: u32,
}

fn default_page() -> u32 {
    1
}

fn default_page_size() -> u32 {
    20
}

/// API error response
#[derive(Debug, Clone, Serialize)]
pub struct ApiError {
    pub error: String,
    pub message: String,
}

/// BigInt wrapper for JSON serialization to avoid precision loss
/// Serializes to {"__@json.bigint__": "value"} format
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BigIntValue(pub u64);

impl Serialize for BigIntValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("__@json.bigint__", &self.0.to_string())?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for BigIntValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};
        use std::fmt;

        struct BigIntVisitor;

        impl<'de> Visitor<'de> for BigIntVisitor {
            type Value = BigIntValue;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with __@json.bigint__ key")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut value: Option<String> = None;
                while let Some(key) = access.next_key::<String>()? {
                    if key == "__@json.bigint__" {
                        value = Some(access.next_value()?);
                    } else {
                        let _: serde::de::IgnoredAny = access.next_value()?;
                    }
                }
                let value =
                    value.ok_or_else(|| serde::de::Error::missing_field("__@json.bigint__"))?;
                let num = value.parse::<u64>().map_err(serde::de::Error::custom)?;
                Ok(BigIntValue(num))
            }
        }

        deserializer.deserialize_map(BigIntVisitor)
    }
}

/// Bridge quota/limit remaining response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaResponse {
    /// Remaining quota for ETH chain (raw value, use decimals to convert)
    /// Will be None if query failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eth_claim: Option<BigIntValue>,
    /// Error message if ETH quota query failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eth_error: Option<String>,
    /// Remaining quota for Starcoin chain (raw value, use decimals to convert)
    /// Will be None if query failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starcoin_claim: Option<BigIntValue>,
    /// Error message if Starcoin quota query failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starcoin_error: Option<String>,
    /// Decimal precision for quota values (default: 8)
    pub decimals: BigIntValue,
}

/// Fee estimation response - returns last gas consumption for bridge operations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeeEstimateResponse {
    /// Last gas used for deposit transaction (ETH -> Starcoin direction)
    pub eth_to_starcoin_deposit_gas: i64,
    /// Last gas used for approval transaction (ETH -> Starcoin direction)
    pub eth_to_starcoin_approval_gas: i64,
    /// Last gas used for claim transaction (ETH -> Starcoin direction)
    pub eth_to_starcoin_claim_gas: i64,
    /// Last gas used for deposit transaction (Starcoin -> ETH direction)
    pub starcoin_to_eth_deposit_gas: i64,
    /// Last gas used for approval transaction (Starcoin -> ETH direction)
    pub starcoin_to_eth_approval_gas: i64,
    /// Last gas used for claim transaction (Starcoin -> ETH direction)
    pub starcoin_to_eth_claim_gas: i64,
}

/// Watermark response - returns current indexer progress for both chains
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatermarkResponse {
    /// ETH indexer watermark (last finalized block processed)
    pub eth_watermark: Option<u64>,
    /// Starcoin indexer watermark (last finalized block processed)
    pub stc_watermark: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_status_from_db_model() {
        use starcoin_bridge_schema::models::TokenTransferStatus as DbStatus;

        assert_eq!(
            TransferStatus::from(DbStatus::Deposited),
            TransferStatus::Deposited
        );
        assert_eq!(
            TransferStatus::from(DbStatus::Approved),
            TransferStatus::Approved
        );
        assert_eq!(
            TransferStatus::from(DbStatus::Claimed),
            TransferStatus::Claimed
        );
    }

    #[test]
    fn test_data_source_from_db_model() {
        use starcoin_bridge_schema::models::BridgeDataSource as DbSource;

        assert!(matches!(
            DataSource::from(DbSource::STARCOIN),
            DataSource::Starcoin
        ));
        assert!(matches!(DataSource::from(DbSource::ETH), DataSource::Eth));
    }

    #[test]
    fn test_transfer_status_serialization() {
        // Test snake_case serialization
        let deposited = TransferStatus::Deposited;
        let json = serde_json::to_string(&deposited).unwrap();
        assert_eq!(json, r#""deposited""#);

        let approved = TransferStatus::Approved;
        let json = serde_json::to_string(&approved).unwrap();
        assert_eq!(json, r#""approved""#);

        let claimed = TransferStatus::Claimed;
        let json = serde_json::to_string(&claimed).unwrap();
        assert_eq!(json, r#""claimed""#);
    }

    #[test]
    fn test_transfer_status_deserialization() {
        let deposited: TransferStatus = serde_json::from_str(r#""deposited""#).unwrap();
        assert_eq!(deposited, TransferStatus::Deposited);

        let approved: TransferStatus = serde_json::from_str(r#""approved""#).unwrap();
        assert_eq!(approved, TransferStatus::Approved);

        let claimed: TransferStatus = serde_json::from_str(r#""claimed""#).unwrap();
        assert_eq!(claimed, TransferStatus::Claimed);
    }

    #[test]
    fn test_data_source_serialization() {
        // Test UPPERCASE serialization
        let starcoin = DataSource::Starcoin;
        let json = serde_json::to_string(&starcoin).unwrap();
        assert_eq!(json, r#""STARCOIN""#);

        let eth = DataSource::Eth;
        let json = serde_json::to_string(&eth).unwrap();
        assert_eq!(json, r#""ETH""#);
    }

    #[test]
    fn test_transfer_list_query_defaults() {
        // Test that default values are applied
        let query: TransferListQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(query.page, 1);
        assert_eq!(query.page_size, 20);
        assert!(query.address.is_none());
        assert!(query.chain_id.is_none());
        assert!(query.status.is_none());
        assert!(query.finalized_only.is_none());
    }

    #[test]
    fn test_transfer_list_query_with_values() {
        let json = r#"{
            "address": "0x1234",
            "chain_id": 2,
            "status": "deposited",
            "finalized_only": true,
            "page": 3,
            "page_size": 50
        }"#;
        let query: TransferListQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.address, Some("0x1234".to_string()));
        assert_eq!(query.chain_id, Some(2));
        assert_eq!(query.status, Some("deposited".to_string()));
        assert_eq!(query.finalized_only, Some(true));
        assert_eq!(query.page, 3);
        assert_eq!(query.page_size, 50);
    }

    #[test]
    fn test_pagination_total_pages_calculation() {
        // Test that pagination properly calculates total_pages
        let pagination = Pagination {
            page: 1,
            page_size: 20,
            total_count: 45,
            total_pages: 3, // ceil(45/20) = 3
        };
        assert_eq!(pagination.total_pages, 3);

        let pagination = Pagination {
            page: 1,
            page_size: 20,
            total_count: 40,
            total_pages: 2, // 40/20 = 2
        };
        assert_eq!(pagination.total_pages, 2);
    }

    #[test]
    fn test_transfer_list_response_serialization() {
        // TransferListResponse now uses CrossChainProcedure format
        let procedure = CrossChainProcedure {
            source_chain_id: 2,
            source_chain: "STARCOIN".to_string(),
            destination_chain_id: 12,
            destination_chain: "ETH".to_string(),
            nonce: 0,
            current_status: TransferStatus::Deposited,
            is_complete: false,
            deposit: DepositInfo {
                txn_hash: "abcd1234".to_string(),
                block_height: 100,
                timestamp_ms: 1234567890000,
                sender_address: "0x1234".to_string(),
                recipient_address: "0x5678".to_string(),
                token_id: 1,
                amount: "1 USDT".to_string(),
                is_finalized: true,
            },
            approval: None,
            claim: None,
        };

        let response = TransferListResponse {
            transfers: vec![procedure],
            pagination: Pagination {
                page: 1,
                page_size: 20,
                total_count: 1,
                total_pages: 1,
            },
            claim_delay_seconds: 0,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains(r#""current_status":"deposited""#));
        assert!(json.contains(r#""is_complete":false"#));
        assert!(json.contains(r#""deposit""#));
        assert!(json.contains(r#""sender_address""#));
    }

    #[test]
    fn test_transfer_detail_with_transfer_data() {
        let detail = TransferDetail {
            chain_id: 2,
            nonce: 0,
            status: TransferStatus::Approved,
            block_height: 100,
            timestamp_ms: 1234567890000,
            txn_hash: "abcd1234".to_string(),
            sender_address: "0x1234".to_string(),
            is_finalized: true,
            data_source: DataSource::Starcoin,
            gas_usage: 50000,
            transfer_data: Some(TransferDataDetail {
                destination_chain: 12,
                recipient_address: "0x5678".to_string(),
                token_id: 4,
                amount: "10 USDT".to_string(),
            }),
            status_history: vec![
                TransferStatusUpdate {
                    status: TransferStatus::Deposited,
                    block_height: 99,
                    timestamp_ms: 1234567889000,
                    txn_hash: "prev1234".to_string(),
                    data_source: DataSource::Starcoin,
                },
                TransferStatusUpdate {
                    status: TransferStatus::Approved,
                    block_height: 100,
                    timestamp_ms: 1234567890000,
                    txn_hash: "abcd1234".to_string(),
                    data_source: DataSource::Starcoin,
                },
            ],
        };

        let json = serde_json::to_string(&detail).unwrap();
        assert!(json.contains(r#""destination_chain":12"#));
        assert!(json.contains(r#""token_id":4"#));
        assert!(json.contains(r#""amount":"10 USDT""#));
        assert!(json.contains(r#""status_history""#));
    }

    #[test]
    fn test_transfer_detail_without_transfer_data() {
        let detail = TransferDetail {
            chain_id: 2,
            nonce: 0,
            status: TransferStatus::Approved,
            block_height: 100,
            timestamp_ms: 1234567890000,
            txn_hash: "abcd1234".to_string(),
            sender_address: "0x1234".to_string(),
            is_finalized: false,
            data_source: DataSource::Eth,
            gas_usage: 0,
            transfer_data: None,
            status_history: vec![],
        };

        let json = serde_json::to_string(&detail).unwrap();
        assert!(json.contains(r#""transfer_data":null"#));
        assert!(json.contains(r#""is_finalized":false"#));
        assert!(json.contains(r#""data_source":"ETH""#));
    }

    #[test]
    fn test_fee_estimate_response_default() {
        let response = FeeEstimateResponse::default();
        assert_eq!(response.eth_to_starcoin_deposit_gas, 0);
        assert_eq!(response.eth_to_starcoin_approval_gas, 0);
        assert_eq!(response.eth_to_starcoin_claim_gas, 0);
        assert_eq!(response.starcoin_to_eth_deposit_gas, 0);
        assert_eq!(response.starcoin_to_eth_approval_gas, 0);
        assert_eq!(response.starcoin_to_eth_claim_gas, 0);
    }

    #[test]
    fn test_fee_estimate_response_serialization() {
        let response = FeeEstimateResponse {
            eth_to_starcoin_deposit_gas: 21000,
            eth_to_starcoin_approval_gas: 50000,
            eth_to_starcoin_claim_gas: 100000,
            starcoin_to_eth_deposit_gas: 15000,
            starcoin_to_eth_approval_gas: 45000,
            starcoin_to_eth_claim_gas: 80000,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains(r#""eth_to_starcoin_deposit_gas":21000"#));
        assert!(json.contains(r#""eth_to_starcoin_approval_gas":50000"#));
        assert!(json.contains(r#""eth_to_starcoin_claim_gas":100000"#));
        assert!(json.contains(r#""starcoin_to_eth_deposit_gas":15000"#));
        assert!(json.contains(r#""starcoin_to_eth_approval_gas":45000"#));
        assert!(json.contains(r#""starcoin_to_eth_claim_gas":80000"#));
    }

    #[test]
    fn test_fee_estimate_response_deserialization() {
        let json = r#"{"eth_to_starcoin_deposit_gas":21000,"eth_to_starcoin_approval_gas":50000,"eth_to_starcoin_claim_gas":100000,"starcoin_to_eth_deposit_gas":15000,"starcoin_to_eth_approval_gas":45000,"starcoin_to_eth_claim_gas":80000}"#;
        let response: FeeEstimateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.eth_to_starcoin_deposit_gas, 21000);
        assert_eq!(response.eth_to_starcoin_approval_gas, 50000);
        assert_eq!(response.eth_to_starcoin_claim_gas, 100000);
        assert_eq!(response.starcoin_to_eth_deposit_gas, 15000);
        assert_eq!(response.starcoin_to_eth_approval_gas, 45000);
        assert_eq!(response.starcoin_to_eth_claim_gas, 80000);
    }
}
