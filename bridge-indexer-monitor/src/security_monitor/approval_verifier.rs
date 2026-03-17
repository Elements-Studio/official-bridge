//! Approval Verifier
//!
//! Pure validation logic: for each approval, verify a matching deposit exists.
//! Any mismatch = potential key compromise = freeze the bridge.
//!
//! We only check approvals because:
//! - Deposits are user actions (can't be faked)
//! - Claims are strictly enforced by the contract
//! - Approvals are the attack surface: stolen committee keys → fabricated approval

use starcoin_bridge::pending_events::ChainId;
use tracing::error;

use super::event_organizer::DepositEventData;

/// Why an approval failed verification
#[derive(Debug, Clone)]
pub enum MismatchReason {
    /// No matching deposit found for this approval.
    /// This means someone approved a transfer that was never deposited → key compromise.
    NoMatchingDeposit {
        source_chain: ChainId,
        nonce: u64,
    },
}

impl std::fmt::Display for MismatchReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MismatchReason::NoMatchingDeposit {
                source_chain,
                nonce,
            } => {
                write!(
                    f,
                    "Approval without matching deposit (source={:?}, nonce={}) - POTENTIAL KEY COMPROMISE",
                    source_chain, nonce
                )
            }
        }
    }
}

/// Result of verifying one approval
#[derive(Debug, Clone)]
pub(super) struct VerifyResult {
    pub is_valid: bool,
    pub reason: Option<MismatchReason>,
    pub approval_tx: Option<String>,
}

impl VerifyResult {
    pub(super) fn ok() -> Self {
        Self {
            is_valid: true,
            reason: None,
            approval_tx: None,
        }
    }

    pub(super) fn mismatch(reason: MismatchReason, approval_tx: Option<String>) -> Self {
        Self {
            is_valid: false,
            reason: Some(reason),
            approval_tx,
        }
    }
}

/// Verify that an approval has a matching deposit.
///
/// Returns `VerifyResult::ok()` if deposit exists, or a mismatch if not.
pub(super) fn verify_approval(
    source_chain: ChainId,
    nonce: u64,
    approval_tx: &str,
    deposit: Option<&DepositEventData>,
) -> VerifyResult {
    match deposit {
        Some(_deposit) => VerifyResult::ok(),
        None => {
            error!(
                "[ApprovalVerifier] CRITICAL: Approval without deposit! source={:?}, nonce={}, tx={}",
                source_chain, nonce, approval_tx
            );
            VerifyResult::mismatch(
                MismatchReason::NoMatchingDeposit {
                    source_chain,
                    nonce,
                },
                Some(approval_tx.to_string()),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::event_organizer::DepositEventData;
    use super::*;

    fn create_deposit(nonce: u64) -> DepositEventData {
        DepositEventData {
            source_chain: ChainId::Eth,
            nonce,
            destination_chain: ChainId::Starcoin,
            token_id: 4,
            amount: 1000000,
            sender_address: "0x1234".to_string(),
            recipient_address: "0xabcd".to_string(),
            tx_hash: format!("deposit_tx_{}", nonce),
            block_height: 100,
        }
    }

    #[test]
    fn test_approval_with_deposit_is_valid() {
        let deposit = create_deposit(1);
        let result = verify_approval(ChainId::Eth, 1, "0xabc", Some(&deposit));
        assert!(result.is_valid);
        assert!(result.reason.is_none());
    }

    #[test]
    fn test_approval_without_deposit_is_mismatch() {
        let result = verify_approval(ChainId::Eth, 1, "0xabc", None);
        assert!(!result.is_valid);
        assert!(matches!(
            result.reason,
            Some(MismatchReason::NoMatchingDeposit { nonce: 1, .. })
        ));
        assert_eq!(result.approval_tx.as_deref(), Some("0xabc"));
    }

    #[test]
    fn test_stc_source_chain() {
        let result = verify_approval(ChainId::Starcoin, 5, "0xdef", None);
        assert!(!result.is_valid);
        match result.reason {
            Some(MismatchReason::NoMatchingDeposit {
                source_chain,
                nonce,
            }) => {
                assert_eq!(source_chain, ChainId::Starcoin);
                assert_eq!(nonce, 5);
            }
            _ => panic!("Expected NoMatchingDeposit"),
        }
    }
}
