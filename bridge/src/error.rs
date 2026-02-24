// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::BridgeAuthorityPublicKeyBytes;

/// Information about why a transaction is not yet finalized
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxNotFinalizedInfo {
    /// The chain where the transaction is pending (e.g., "ethereum", "starcoin")
    pub chain: String,
    /// Block number where the transaction was included
    pub tx_block: u64,
    /// Current finalized block number
    pub finalized_block: u64,
    /// Number of blocks needed for finalization (only for block-based finality)
    pub blocks_to_finalize: u64,
    /// Estimated time until finalization (in seconds)
    pub estimated_wait_secs: Option<u64>,
}

impl std::fmt::Display for TxNotFinalizedInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Transaction at block {} is not finalized on {}. Current finalized block: {}. \
             Blocks remaining: {}.",
            self.tx_block, self.chain, self.finalized_block, self.blocks_to_finalize
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    // The input is not an invalid transaction digest/hash
    InvalidTxHash,
    // The referenced transaction failed
    OriginTxFailed,
    // The referenced transction does not exist
    TxNotFound,
    // Tx is not yet finalized - contains details about finality status
    TxNotFinalized(TxNotFinalizedInfo),
    // No recognized bridge event in specified transaction and event position
    NoBridgeEventsInTxPosition,
    // Found a bridge event but not in a recognized Eth bridge contract
    BridgeEventInUnrecognizedEthContract,
    // Found a bridge event but not in a recognized Starcoin bridge package
    BridgeEventInUnrecognizedStarcoinPackage,
    // Found BridgeEvent but not BridgeAction
    BridgeEventNotActionable,
    // Failure to serialize
    BridgeSerializationError(String),
    // Internal Bridge error
    InternalError(String),
    // Authority signature duplication
    AuthoritySignatureDuplication(String),
    // Too many errors when aggregating authority signatures
    AuthoritySignatureAggregationTooManyError(String),
    // Transient Ethereum provider error
    TransientProviderError(String),
    // Ethereum provider error
    ProviderError(String),
    // TokenId is unknown
    UnknownTokenId(u8),
    // Invalid BridgeCommittee
    InvalidBridgeCommittee(String),
    // Invalid Bridge authority signature
    InvalidBridgeAuthoritySignature((BridgeAuthorityPublicKeyBytes, String)),
    // Entity is not in the Bridge committee or is blocklisted
    InvalidBridgeAuthority(BridgeAuthorityPublicKeyBytes),
    // Authority's base_url is invalid
    InvalidAuthorityUrl(BridgeAuthorityPublicKeyBytes),
    // Invalid Bridge Client request
    InvalidBridgeClientRequest(String),
    // Invalid ChainId
    InvalidChainId,
    // Message is signed by mismatched authority
    MismatchedAuthoritySigner,
    // Signature is over a mismatched action
    MismatchedAction,
    // Authority has invalid url
    AuthoirtyUrlInvalid,
    // Action is not token transfer
    ActionIsNotTokenTransferAction,
    // Starcoin transaction failure due to generic error
    StarcoinTxFailureGeneric(String),
    // Zero value bridge transfer should not be allowed
    ZeroValueBridgeTransfer(String),
    // Token ID is not in the supported token whitelist
    UnsupportedTokenId(u8),
    // Storage Error
    StorageError(String),
    // Rest API Error
    RestAPIError(String),
    // Uncategorized error
    Generic(String),
}

impl BridgeError {
    /// Returns a short string identifying the error type for metrics labels
    pub fn error_type(&self) -> &'static str {
        match self {
            BridgeError::InvalidTxHash => "invalid_tx_hash",
            BridgeError::OriginTxFailed => "origin_tx_failed",
            BridgeError::TxNotFound => "tx_not_found",
            BridgeError::TxNotFinalized(_) => "tx_not_finalized",
            BridgeError::NoBridgeEventsInTxPosition => "no_bridge_events",
            BridgeError::BridgeEventInUnrecognizedEthContract => "unrecognized_eth_contract",
            BridgeError::BridgeEventInUnrecognizedStarcoinPackage => {
                "unrecognized_starcoin_package"
            }
            BridgeError::BridgeEventNotActionable => "event_not_actionable",
            BridgeError::BridgeSerializationError(_) => "serialization_error",
            BridgeError::InternalError(_) => "internal_error",
            BridgeError::AuthoritySignatureDuplication(_) => "signature_duplication",
            BridgeError::AuthoritySignatureAggregationTooManyError(_) => {
                "signature_aggregation_error"
            }
            BridgeError::TransientProviderError(_) => "transient_provider_error",
            BridgeError::ProviderError(_) => "provider_error",
            BridgeError::UnknownTokenId(_) => "unknown_token_id",
            BridgeError::InvalidBridgeCommittee(_) => "invalid_committee",
            BridgeError::InvalidBridgeAuthoritySignature(_) => "invalid_authority_signature",
            BridgeError::InvalidBridgeAuthority(_) => "invalid_authority",
            BridgeError::InvalidAuthorityUrl(_) => "invalid_authority_url",
            BridgeError::InvalidBridgeClientRequest(_) => "invalid_client_request",
            BridgeError::InvalidChainId => "invalid_chain_id",
            BridgeError::MismatchedAuthoritySigner => "mismatched_signer",
            BridgeError::MismatchedAction => "mismatched_action",
            BridgeError::AuthoirtyUrlInvalid => "authority_url_invalid",
            BridgeError::ActionIsNotTokenTransferAction => "not_token_transfer",
            BridgeError::StarcoinTxFailureGeneric(_) => "starcoin_tx_failure",
            BridgeError::ZeroValueBridgeTransfer(_) => "zero_value_transfer",
            BridgeError::UnsupportedTokenId(_) => "unsupported_token_id",
            BridgeError::StorageError(_) => "storage_error",
            BridgeError::RestAPIError(_) => "rest_api_error",
            BridgeError::Generic(_) => "generic",
        }
    }
}

pub type BridgeResult<T> = Result<T, BridgeError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that error_type returns consistent, valid strings for simple error variants
    #[test]
    fn test_error_type_simple_variants() {
        // Test variants without complex payloads
        let simple_errors = vec![
            (BridgeError::InvalidTxHash, "invalid_tx_hash"),
            (BridgeError::OriginTxFailed, "origin_tx_failed"),
            (BridgeError::TxNotFound, "tx_not_found"),
            (
                BridgeError::TxNotFinalized(TxNotFinalizedInfo {
                    chain: "test".to_string(),
                    tx_block: 100,
                    finalized_block: 90,
                    blocks_to_finalize: 10,
                    estimated_wait_secs: Some(120),
                }),
                "tx_not_finalized",
            ),
            (BridgeError::NoBridgeEventsInTxPosition, "no_bridge_events"),
            (
                BridgeError::BridgeEventInUnrecognizedEthContract,
                "unrecognized_eth_contract",
            ),
            (
                BridgeError::BridgeEventInUnrecognizedStarcoinPackage,
                "unrecognized_starcoin_package",
            ),
            (
                BridgeError::BridgeEventNotActionable,
                "event_not_actionable",
            ),
            (BridgeError::InvalidChainId, "invalid_chain_id"),
            (BridgeError::MismatchedAuthoritySigner, "mismatched_signer"),
            (BridgeError::MismatchedAction, "mismatched_action"),
            (BridgeError::AuthoirtyUrlInvalid, "authority_url_invalid"),
            (
                BridgeError::ActionIsNotTokenTransferAction,
                "not_token_transfer",
            ),
        ];

        for (error, expected_type) in simple_errors {
            assert_eq!(
                error.error_type(),
                expected_type,
                "error_type for {:?} should be '{}'",
                error,
                expected_type
            );
        }
    }

    /// Test error_type for variants with String payloads
    #[test]
    fn test_error_type_string_variants() {
        let string_errors = vec![
            (
                BridgeError::BridgeSerializationError("test".to_string()),
                "serialization_error",
            ),
            (
                BridgeError::InternalError("test".to_string()),
                "internal_error",
            ),
            (
                BridgeError::AuthoritySignatureDuplication("test".to_string()),
                "signature_duplication",
            ),
            (
                BridgeError::AuthoritySignatureAggregationTooManyError("test".to_string()),
                "signature_aggregation_error",
            ),
            (
                BridgeError::TransientProviderError("test".to_string()),
                "transient_provider_error",
            ),
            (
                BridgeError::ProviderError("test".to_string()),
                "provider_error",
            ),
            (
                BridgeError::InvalidBridgeCommittee("test".to_string()),
                "invalid_committee",
            ),
            (
                BridgeError::InvalidBridgeClientRequest("test".to_string()),
                "invalid_client_request",
            ),
            (
                BridgeError::StarcoinTxFailureGeneric("test".to_string()),
                "starcoin_tx_failure",
            ),
            (
                BridgeError::ZeroValueBridgeTransfer("test".to_string()),
                "zero_value_transfer",
            ),
            (
                BridgeError::StorageError("test".to_string()),
                "storage_error",
            ),
            (
                BridgeError::RestAPIError("test".to_string()),
                "rest_api_error",
            ),
            (BridgeError::Generic("test".to_string()), "generic"),
        ];

        for (error, expected_type) in string_errors {
            assert_eq!(error.error_type(), expected_type, "error_type mismatch");
        }
    }

    /// Test error_type for UnknownTokenId
    #[test]
    fn test_error_type_unknown_token_id() {
        // Different token IDs should have same error_type
        assert_eq!(
            BridgeError::UnknownTokenId(0).error_type(),
            "unknown_token_id"
        );
        assert_eq!(
            BridgeError::UnknownTokenId(99).error_type(),
            "unknown_token_id"
        );
        assert_eq!(
            BridgeError::UnknownTokenId(255).error_type(),
            "unknown_token_id"
        );
    }

    /// Test that error_type values are valid Prometheus label values
    /// (lowercase, underscores only, no spaces or special chars)
    #[test]
    fn test_error_type_valid_prometheus_labels() {
        let errors_to_test = vec![
            BridgeError::InvalidTxHash,
            BridgeError::TxNotFound,
            BridgeError::ProviderError("test".to_string()),
            BridgeError::InternalError("test".to_string()),
            BridgeError::UnknownTokenId(1),
        ];

        for error in errors_to_test {
            let error_type = error.error_type();

            // Must not be empty
            assert!(!error_type.is_empty(), "error_type should not be empty");

            // Must only contain lowercase letters and underscores
            for c in error_type.chars() {
                assert!(
                    c.is_ascii_lowercase() || c == '_',
                    "error_type '{}' contains invalid character '{}' for Prometheus label",
                    error_type,
                    c
                );
            }

            // Should not start or end with underscore
            assert!(
                !error_type.starts_with('_'),
                "error_type '{}' should not start with underscore",
                error_type
            );
            assert!(
                !error_type.ends_with('_'),
                "error_type '{}' should not end with underscore",
                error_type
            );
        }
    }

    /// Test that error_type is consistent regardless of payload content
    #[test]
    fn test_error_type_payload_independence() {
        // Same error type with different payloads should return same error_type
        let err1 = BridgeError::ProviderError("short".to_string());
        let err2 = BridgeError::ProviderError(
            "a very long error message with lots of details".to_string(),
        );
        let err3 = BridgeError::ProviderError("".to_string());

        assert_eq!(err1.error_type(), err2.error_type());
        assert_eq!(err2.error_type(), err3.error_type());

        let err4 = BridgeError::InternalError("error 1".to_string());
        let err5 = BridgeError::InternalError("completely different error".to_string());
        assert_eq!(err4.error_type(), err5.error_type());
    }

    /// Verify critical error types used in alerts have stable names
    #[test]
    fn test_critical_error_types_stability() {
        // These error types are used in monitoring dashboards and alerts
        // Changing them would break alerting - they MUST remain stable

        // Errors that indicate potential stuck funds
        assert_eq!(
            BridgeError::BridgeEventInUnrecognizedEthContract.error_type(),
            "unrecognized_eth_contract"
        );
        assert_eq!(
            BridgeError::NoBridgeEventsInTxPosition.error_type(),
            "no_bridge_events"
        );
        assert_eq!(
            BridgeError::BridgeEventNotActionable.error_type(),
            "event_not_actionable"
        );

        // Errors that indicate infrastructure problems
        assert_eq!(
            BridgeError::ProviderError("any".to_string()).error_type(),
            "provider_error"
        );
        assert_eq!(
            BridgeError::TransientProviderError("any".to_string()).error_type(),
            "transient_provider_error"
        );
    }

    /// Test TxNotFinalizedInfo Display formatting
    #[test]
    fn test_tx_not_finalized_info_display() {
        // Test with estimated wait time (should not be printed)
        let info = TxNotFinalizedInfo {
            chain: "ethereum".to_string(),
            tx_block: 100,
            finalized_block: 90,
            blocks_to_finalize: 10,
            estimated_wait_secs: Some(120),
        };
        let display = format!("{}", info);
        assert!(display.contains("block 100"));
        assert!(display.contains("ethereum"));
        assert!(display.contains("finalized block: 90"));
        assert!(display.contains("Blocks remaining: 10"));
        assert!(!display.contains("seconds")); // Should NOT contain estimated wait

        // Test without estimated wait time
        let info_no_wait = TxNotFinalizedInfo {
            chain: "starcoin".to_string(),
            tx_block: 200,
            finalized_block: 184,
            blocks_to_finalize: 16,
            estimated_wait_secs: None,
        };
        let display_no_wait = format!("{}", info_no_wait);
        assert!(display_no_wait.contains("block 200"));
        assert!(display_no_wait.contains("starcoin"));
        assert!(display_no_wait.contains("Blocks remaining: 16"));
        assert!(!display_no_wait.contains("seconds"));
    }
}
