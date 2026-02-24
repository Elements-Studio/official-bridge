//! Mismatch Checker Module
//!
//! Provides unified interface for checking bridge event mismatches.
//! This module only contains pure checking logic - no data fetching.
//!
//! The checker accepts (deposit, approval, claim) pairs organized by EventOrganizer
//! and returns mismatch results for the SecurityMonitor to handle.

use starcoin_bridge::pending_events::ChainId;
use tracing::{debug, error};

use super::event_organizer::EventPair;

/// Mismatch reason enum
#[derive(Debug, Clone)]
pub enum MismatchReason {
    /// No matching deposit found for approval/claim
    NoMatchingDeposit {
        source_chain: ChainId,
        nonce: u64,
        event_type: &'static str, // "Approval" or "Claim"
    },
    /// Amount mismatch between deposit and claim
    AmountMismatch {
        deposit_amount: u64,
        claim_amount: u64,
        expected_claim_amount: u64,
    },
    /// Token ID mismatch
    TokenMismatch { deposit_token: u8, claim_token: u8 },
    /// Recipient mismatch
    RecipientMismatch { expected: String, actual: String },
}

impl std::fmt::Display for MismatchReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MismatchReason::NoMatchingDeposit {
                source_chain,
                nonce,
                event_type,
            } => {
                write!(
                    f,
                    "{} without matching deposit (source={:?}, nonce={}) - POTENTIAL KEY COMPROMISE",
                    event_type, source_chain, nonce
                )
            }
            MismatchReason::AmountMismatch {
                deposit_amount,
                claim_amount,
                expected_claim_amount,
            } => {
                write!(
                    f,
                    "Amount mismatch: deposited {} (expected claim {}), but claimed {}",
                    deposit_amount, expected_claim_amount, claim_amount
                )
            }
            MismatchReason::TokenMismatch {
                deposit_token,
                claim_token,
            } => {
                write!(
                    f,
                    "Token mismatch: deposited token {} but claimed token {}",
                    deposit_token, claim_token
                )
            }
            MismatchReason::RecipientMismatch { expected, actual } => {
                write!(
                    f,
                    "Recipient mismatch: expected {} but got {}",
                    expected, actual
                )
            }
        }
    }
}

/// Mismatch detection result
#[derive(Debug, Clone)]
pub struct MismatchResult {
    pub has_mismatch: bool,
    pub reason: Option<MismatchReason>,
    pub deposit_tx: Option<String>,
    pub approval_tx: Option<String>,
    pub claim_tx: Option<String>,
}

impl MismatchResult {
    pub fn ok() -> Self {
        Self {
            has_mismatch: false,
            reason: None,
            deposit_tx: None,
            approval_tx: None,
            claim_tx: None,
        }
    }

    pub fn mismatch(
        reason: MismatchReason,
        deposit_tx: Option<String>,
        approval_tx: Option<String>,
        claim_tx: Option<String>,
    ) -> Self {
        Self {
            has_mismatch: true,
            reason: Some(reason),
            deposit_tx,
            approval_tx,
            claim_tx,
        }
    }
}

/// Mismatch Checker
///
/// Pure checking logic - no data fetching.
/// Accepts EventPair and returns MismatchResult.
pub struct MismatchChecker;

impl MismatchChecker {
    pub fn new() -> Self {
        Self
    }

    /// Check an event pair for mismatches
    ///
    /// # Mismatch Detection Rules
    /// 1. Approval without deposit → CRITICAL (key compromise)
    /// 2. Claim without deposit → CRITICAL (key compromise)
    /// 3. Claim with deposit but amount mismatch → CRITICAL
    /// 4. Claim with deposit but token mismatch → CRITICAL
    /// 5. Claim with deposit but recipient mismatch → CRITICAL
    pub fn check(&self, pair: &EventPair) -> MismatchResult {
        let deposit = pair.deposit.as_ref();
        let approval = pair.approval.as_ref();
        let claim = pair.claim.as_ref();

        // Rule 1: Approval without deposit
        if let Some(approval) = approval {
            if deposit.is_none() {
                error!(
                    "[MismatchChecker] CRITICAL: Approval without deposit! source={:?}, nonce={}, tx={}",
                    approval.source_chain, approval.nonce, approval.tx_hash
                );
                return MismatchResult::mismatch(
                    MismatchReason::NoMatchingDeposit {
                        source_chain: approval.source_chain,
                        nonce: approval.nonce,
                        event_type: "Approval",
                    },
                    None,
                    Some(approval.tx_hash.clone()),
                    None,
                );
            }
        }

        // Rule 2: Claim without deposit
        if let Some(claim) = claim {
            if deposit.is_none() {
                error!(
                    "[MismatchChecker] CRITICAL: Claim without deposit! source={:?}, nonce={}, tx={}",
                    claim.source_chain, claim.nonce, claim.tx_hash
                );
                return MismatchResult::mismatch(
                    MismatchReason::NoMatchingDeposit {
                        source_chain: claim.source_chain,
                        nonce: claim.nonce,
                        event_type: "Claim",
                    },
                    None,
                    None,
                    Some(claim.tx_hash.clone()),
                );
            }
        }

        // Rule 3-5: Verify deposit/claim match
        if let (Some(deposit), Some(claim)) = (deposit, claim) {
            // Only check if claim has valid data (non-zero values)
            // Some claim events from STC don't have full details
            if claim.token_id != 0 && claim.amount != 0 {
                // Token ID must match
                if deposit.token_id != claim.token_id {
                    error!(
                        "[MismatchChecker] Token mismatch: deposit_token={}, claim_token={}",
                        deposit.token_id, claim.token_id
                    );
                    return MismatchResult::mismatch(
                        MismatchReason::TokenMismatch {
                            deposit_token: deposit.token_id,
                            claim_token: claim.token_id,
                        },
                        Some(deposit.tx_hash.clone()),
                        approval.map(|a| a.tx_hash.clone()),
                        Some(claim.tx_hash.clone()),
                    );
                }

                // Amount must match (with decimal conversion for USDT)
                let expected_claim_amount =
                    convert_amount_for_claim(deposit.amount, deposit.token_id);
                if claim.amount != expected_claim_amount {
                    error!(
                        "[MismatchChecker] Amount mismatch: deposit={}, expected_claim={}, actual_claim={}",
                        deposit.amount, expected_claim_amount, claim.amount
                    );
                    return MismatchResult::mismatch(
                        MismatchReason::AmountMismatch {
                            deposit_amount: deposit.amount,
                            claim_amount: claim.amount,
                            expected_claim_amount,
                        },
                        Some(deposit.tx_hash.clone()),
                        approval.map(|a| a.tx_hash.clone()),
                        Some(claim.tx_hash.clone()),
                    );
                }

                // Recipient must match (if we have valid addresses)
                if !claim.recipient_address.is_empty()
                    && !deposit.recipient_address.is_empty()
                    && !addresses_match(&deposit.recipient_address, &claim.recipient_address)
                {
                    error!(
                        "[MismatchChecker] Recipient mismatch: expected={}, actual={}",
                        deposit.recipient_address, claim.recipient_address
                    );
                    return MismatchResult::mismatch(
                        MismatchReason::RecipientMismatch {
                            expected: deposit.recipient_address.clone(),
                            actual: claim.recipient_address.clone(),
                        },
                        Some(deposit.tx_hash.clone()),
                        approval.map(|a| a.tx_hash.clone()),
                        Some(claim.tx_hash.clone()),
                    );
                }
            }

            debug!(
                "[MismatchChecker] Deposit/Claim validated: nonce={}, amount={}, recipient={}",
                deposit.nonce, deposit.amount, deposit.recipient_address
            );
        }

        MismatchResult::ok()
    }

    /// Check multiple pairs and return all mismatches
    pub fn check_all(&self, pairs: &[EventPair]) -> Vec<(EventPair, MismatchResult)> {
        pairs
            .iter()
            .map(|pair| {
                let result = self.check(pair);
                (pair.clone(), result)
            })
            .filter(|(_, result)| result.has_mismatch)
            .collect()
    }
}

impl Default for MismatchChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert deposit amount to expected claim amount
///
/// Handles decimal conversion between chains:
/// - USDT (token_id=3 or 4): Bridge uses 8 decimals, EVM uses 6 decimals
fn convert_amount_for_claim(deposit_amount: u64, token_id: u8) -> u64 {
    match token_id {
        3 | 4 => {
            // USDT: 8 decimals (STC) -> 6 decimals (EVM)
            deposit_amount / 100
        }
        _ => deposit_amount,
    }
}

/// Check if two addresses match (case-insensitive, handles 0x prefix)
fn addresses_match(addr1: &str, addr2: &str) -> bool {
    let normalize = |s: &str| -> String {
        let s = s.trim().to_lowercase();
        s.strip_prefix("0x").unwrap_or(&s).to_string()
    };

    normalize(addr1) == normalize(addr2)
}

#[cfg(test)]
mod tests {
    use super::super::event_organizer::{ApprovalEventData, ClaimEventData, DepositEventData};
    use super::*;
    use starcoin_bridge::pending_events::TransferKey;

    fn create_deposit(nonce: u64, amount: u64, token_id: u8) -> DepositEventData {
        DepositEventData {
            source_chain: ChainId::Eth,
            nonce,
            destination_chain: ChainId::Starcoin,
            token_id,
            amount,
            sender_address: "0x1234".to_string(),
            recipient_address: "0xabcd".to_string(),
            tx_hash: format!("deposit_tx_{}", nonce),
            block_height: 100,
            from_db: false,
        }
    }

    fn create_approval(nonce: u64) -> ApprovalEventData {
        ApprovalEventData {
            source_chain: ChainId::Eth,
            nonce,
            recorded_chain: ChainId::Starcoin,
            tx_hash: format!("approval_tx_{}", nonce),
            block_height: 200,
            from_db: false,
        }
    }

    fn create_claim(nonce: u64, amount: u64, token_id: u8) -> ClaimEventData {
        ClaimEventData {
            source_chain: ChainId::Eth,
            nonce,
            destination_chain: ChainId::Starcoin,
            token_id,
            amount,
            recipient_address: "0xabcd".to_string(),
            claimer_address: "0x5678".to_string(),
            tx_hash: format!("claim_tx_{}", nonce),
            block_height: 300,
            from_db: false,
        }
    }

    #[test]
    fn test_no_mismatch_with_matching_pair() {
        let checker = MismatchChecker::new();
        let key = TransferKey::new(ChainId::Eth, 100);

        let pair = EventPair {
            key,
            deposit: Some(create_deposit(100, 1000000, 1)),
            approval: Some(create_approval(100)),
            claim: Some(create_claim(100, 1000000, 1)),
        };

        let result = checker.check(&pair);
        assert!(!result.has_mismatch);
    }

    #[test]
    fn test_approval_without_deposit() {
        let checker = MismatchChecker::new();
        let key = TransferKey::new(ChainId::Eth, 100);

        let pair = EventPair {
            key,
            deposit: None,
            approval: Some(create_approval(100)),
            claim: None,
        };

        let result = checker.check(&pair);
        assert!(result.has_mismatch);
        assert!(matches!(
            result.reason,
            Some(MismatchReason::NoMatchingDeposit {
                event_type: "Approval",
                ..
            })
        ));
    }

    #[test]
    fn test_claim_without_deposit() {
        let checker = MismatchChecker::new();
        let key = TransferKey::new(ChainId::Eth, 100);

        let pair = EventPair {
            key,
            deposit: None,
            approval: None,
            claim: Some(create_claim(100, 1000000, 1)),
        };

        let result = checker.check(&pair);
        assert!(result.has_mismatch);
        assert!(matches!(
            result.reason,
            Some(MismatchReason::NoMatchingDeposit {
                event_type: "Claim",
                ..
            })
        ));
    }

    #[test]
    fn test_amount_mismatch() {
        let checker = MismatchChecker::new();
        let key = TransferKey::new(ChainId::Eth, 100);

        let pair = EventPair {
            key,
            deposit: Some(create_deposit(100, 1000000, 1)),
            approval: None,
            claim: Some(create_claim(100, 2000000, 1)), // Wrong amount
        };

        let result = checker.check(&pair);
        assert!(result.has_mismatch);
        assert!(matches!(
            result.reason,
            Some(MismatchReason::AmountMismatch { .. })
        ));
    }

    #[test]
    fn test_token_mismatch() {
        let checker = MismatchChecker::new();
        let key = TransferKey::new(ChainId::Eth, 100);

        let pair = EventPair {
            key,
            deposit: Some(create_deposit(100, 1000000, 1)),
            approval: None,
            claim: Some(create_claim(100, 1000000, 2)), // Wrong token
        };

        let result = checker.check(&pair);
        assert!(result.has_mismatch);
        assert!(matches!(
            result.reason,
            Some(MismatchReason::TokenMismatch { .. })
        ));
    }

    #[test]
    fn test_usdt_decimal_conversion() {
        let checker = MismatchChecker::new();
        let key = TransferKey::new(ChainId::Eth, 100);

        // USDT: 8 decimals -> 6 decimals (divide by 100)
        let pair = EventPair {
            key,
            deposit: Some(create_deposit(100, 100000000, 4)), // 1 USDT in 8 decimals
            approval: None,
            claim: Some(create_claim(100, 1000000, 4)), // 1 USDT in 6 decimals
        };

        let result = checker.check(&pair);
        assert!(!result.has_mismatch);
    }

    #[test]
    fn test_addresses_match_case_insensitive() {
        assert!(addresses_match("0xABCD", "0xabcd"));
        assert!(addresses_match("ABCD", "0xabcd"));
        assert!(addresses_match("0xABCD", "abcd"));
    }

    #[test]
    fn test_convert_amount_for_claim() {
        // USDT conversion
        assert_eq!(convert_amount_for_claim(100000000, 3), 1000000);
        assert_eq!(convert_amount_for_claim(100000000, 4), 1000000);
        // Non-USDT stays same
        assert_eq!(convert_amount_for_claim(100000000, 1), 100000000);
    }

    #[test]
    fn test_check_all() {
        let checker = MismatchChecker::new();

        let pairs = vec![
            EventPair {
                key: TransferKey::new(ChainId::Eth, 1),
                deposit: Some(create_deposit(1, 1000, 1)),
                approval: None,
                claim: Some(create_claim(1, 1000, 1)),
            },
            EventPair {
                key: TransferKey::new(ChainId::Eth, 2),
                deposit: None, // Missing deposit!
                approval: Some(create_approval(2)),
                claim: None,
            },
            EventPair {
                key: TransferKey::new(ChainId::Eth, 3),
                deposit: Some(create_deposit(3, 2000, 1)),
                approval: None,
                claim: Some(create_claim(3, 2000, 1)),
            },
        ];

        let mismatches = checker.check_all(&pairs);
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].0.key.nonce, 2);
    }
}
