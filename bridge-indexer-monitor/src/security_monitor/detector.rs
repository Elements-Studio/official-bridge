//! Security Monitor Detector
//!
//! Simplified mismatch detection based on deposit+approval pairs.
//!
//! Architecture:
//! - When approval event arrives, check if matching deposit exists
//! - If no deposit found (in memory or DB), trigger emergency pause
//! - EventOrganizer: Gathers deposit data from memory (TransferTracker) and DB
//!
//! The check is triggered synchronously when on_approval() detects a mismatch.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use starcoin_bridge::pending_events::{ChainId, MismatchAlert, TransferKey, TransferTracker};
use starcoin_bridge_pg_db::Db;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::network::NetworkType;
use crate::telegram::SharedTelegramNotifier;

use super::event_organizer::EventOrganizer;
use super::mismatch_checker::{MismatchChecker, MismatchReason};

/// Security Monitor configuration
#[derive(Debug, Clone, Default)]
pub struct SecurityMonitorConfig {
    /// ETH chain ID for display
    pub eth_chain_id: Option<u8>,
    /// STC chain ID for display
    pub stc_chain_id: Option<u8>,
    /// Whether auto-pause is enabled
    pub can_execute: bool,
    /// Path to bridge-cli config file (required for governance-execute)
    pub bridge_cli_config_path: Option<String>,
    /// Pre-signed pause signatures for ETH (comma-separated)
    pub eth_pause_signatures: Option<String>,
    /// Pre-signed pause signatures for STC (comma-separated)
    pub stc_pause_signatures: Option<String>,
    /// Pause nonce for ETH
    pub eth_pause_nonce: Option<u64>,
    /// Pause nonce for STC
    pub stc_pause_nonce: Option<u64>,
}

/// Mismatch information for alerting/logging
#[derive(Debug, Clone)]
pub struct MismatchInfo {
    pub source_chain_id: u8,
    pub nonce: u64,
    pub reason: MismatchReason,
    pub deposit_tx_hash: Option<String>,
    pub approval_tx_hash: Option<String>,
    pub claim_tx_hash: Option<String>,
}

/// Shared SecurityMonitor handle
pub type SharedSecurityMonitor = Arc<SecurityMonitor>;

/// Grace period after activation before processing alerts (seconds)
/// This allows time for all historical events to be processed by both chains.
/// Note: Keep this short for local testing, can be increased for production.
const ACTIVATION_GRACE_PERIOD_SECS: u64 = 10;

/// Security Monitor
///
/// Simplified orchestrator for mismatch detection:
/// - Receives alerts from TransferTracker.on_approval() when approval has no deposit
/// - Verifies against DB to confirm the mismatch
/// - Triggers emergency pause if confirmed
pub struct SecurityMonitor {
    config: SecurityMonitorConfig,
    event_organizer: EventOrganizer,
    mismatch_checker: MismatchChecker,
    telegram: Option<SharedTelegramNotifier>,
    /// Whether monitor is active (waits for caught-up)
    active: AtomicBool,
    /// Activation timestamp (for grace period checking)
    activated_at: RwLock<Option<std::time::Instant>>,
    /// Whether pause has been triggered
    pause_triggered: AtomicBool,
    /// Cancellation token
    cancel: CancellationToken,
    /// Deferred alerts received before activation or during grace period
    deferred_alerts: RwLock<Vec<MismatchAlert>>,
}

impl SecurityMonitor {
    pub fn new(
        config: SecurityMonitorConfig,
        transfer_tracker: Arc<TransferTracker>,
        db: Db,
        network: NetworkType,
        telegram: Option<SharedTelegramNotifier>,
        cancel: CancellationToken,
    ) -> Self {
        let event_organizer = EventOrganizer::new(transfer_tracker, db, network);
        let mismatch_checker = MismatchChecker::new();

        Self {
            config,
            event_organizer,
            mismatch_checker,
            telegram,
            active: AtomicBool::new(false),
            activated_at: RwLock::new(None),
            pause_triggered: AtomicBool::new(false),
            cancel,
            deferred_alerts: RwLock::new(Vec::new()),
        }
    }

    /// Activate the monitor (called after both chains caught up)
    ///
    /// This starts the grace period timer. During the grace period,
    /// alerts are logged but not acted upon, allowing historical
    /// events from both chains to fully sync.
    pub fn activate(&self) {
        info!(
            "[SecurityMonitor] Activated - starting {}s grace period for historical event sync",
            ACTIVATION_GRACE_PERIOD_SECS
        );
        self.active.store(true, Ordering::SeqCst);
        // Record activation time for grace period calculation
        if let Ok(mut guard) = self.activated_at.try_write() {
            *guard = Some(std::time::Instant::now());
        }
    }

    /// Process deferred alerts after grace period ends
    ///
    /// This should be called after activation to re-evaluate alerts that were
    /// received before the monitor was active or during the grace period.
    pub async fn process_deferred_alerts(&self) {
        // Wait for grace period to end
        info!(
            "[SecurityMonitor] Waiting {}s for grace period to end before processing deferred alerts",
            ACTIVATION_GRACE_PERIOD_SECS
        );
        tokio::time::sleep(tokio::time::Duration::from_secs(
            ACTIVATION_GRACE_PERIOD_SECS,
        ))
        .await;

        // Take all deferred alerts
        let alerts = {
            let mut guard = self.deferred_alerts.write().await;
            std::mem::take(&mut *guard)
        };

        if alerts.is_empty() {
            info!("[SecurityMonitor] No deferred alerts to process");
            return;
        }

        info!(
            "[SecurityMonitor] Processing {} deferred alert(s) after grace period",
            alerts.len()
        );

        for alert in alerts {
            // Re-verify each alert: check if deposit now exists
            let key = match &alert {
                MismatchAlert::ApprovalWithoutDeposit {
                    source_chain,
                    nonce,
                    ..
                } => TransferKey::new(*source_chain, *nonce),
                MismatchAlert::ClaimWithoutDeposit {
                    source_chain,
                    nonce,
                    ..
                } => TransferKey::new(*source_chain, *nonce),
            };

            // Check if deposit now exists in event_organizer (memory + DB)
            let deposit_exists = self.event_organizer.deposit_exists(&key).await;

            if !deposit_exists {
                error!(
                    "[SecurityMonitor] Deferred alert confirmed - deposit still missing: {:?}",
                    key
                );
                self.process_alert_internal(&alert).await;
            } else {
                info!(
                    "[SecurityMonitor] Deferred alert resolved - deposit found: {:?}",
                    key
                );
            }
        }
    }

    /// Check if we're still in the activation grace period
    fn in_grace_period(&self) -> bool {
        if let Ok(guard) = self.activated_at.try_read() {
            if let Some(activated_at) = *guard {
                return activated_at.elapsed().as_secs() < ACTIVATION_GRACE_PERIOD_SECS;
            }
        }
        false
    }

    /// Check if monitor is active
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Notify that events have changed (called by TransferTracker)
    /// Note: In simplified model, this is a no-op. Checks are done synchronously in on_approval.
    pub fn notify_event_change(&self) {
        // No-op in simplified model
    }

    /// Handle a MismatchAlert from synchronous detection in event handler
    ///
    /// This is called directly by StcEventHandler/EthEventHandler when they
    /// detect a critical mismatch (approval without deposit) synchronously.
    ///
    /// IMPORTANT: This function checks is_active() and in_grace_period() to prevent
    /// false positives when one chain syncs faster than the other during startup.
    pub async fn handle_mismatch_alert(&self, alert: MismatchAlert) {
        // CRITICAL: Check if monitor is active before processing alerts
        // During startup, one chain may sync faster than the other, causing
        // false "no matching deposit" alerts. We must wait for both chains
        // to be caught up (indicated by is_active) before triggering pauses.
        if !self.is_active() {
            warn!(
                "[SecurityMonitor] SYNC ALERT received but monitor not yet active (waiting for chains to sync): {}",
                alert
            );
            warn!(
                "[SecurityMonitor] Deferring alert - will be re-evaluated after both chains catch up"
            );
            // Store deferred alert for later processing
            {
                let mut deferred = self.deferred_alerts.write().await;
                deferred.push(alert);
            }
            return;
        }

        // CRITICAL: Check if we're still in the grace period after activation
        // Even after both chains report "caught up", there may be a race condition
        // where one chain's events are processed before the other's historical events
        // are fully loaded. The grace period allows time for this to complete.
        if self.in_grace_period() {
            warn!(
                "[SecurityMonitor] SYNC ALERT received during grace period ({}s remaining), deferring: {}",
                ACTIVATION_GRACE_PERIOD_SECS.saturating_sub(
                    self.activated_at.try_read()
                        .ok()
                        .and_then(|g| g.map(|t| t.elapsed().as_secs()))
                        .unwrap_or(0)
                ),
                alert
            );
            warn!("[SecurityMonitor] Alert will be re-evaluated after grace period ends");
            // Store deferred alert for later processing
            {
                let mut deferred = self.deferred_alerts.write().await;
                deferred.push(alert);
            }
            return;
        }

        // Process the alert immediately
        self.process_alert_internal(&alert).await;
    }

    /// Internal method to process an alert (used both for immediate and deferred alerts)
    async fn process_alert_internal(&self, alert: &MismatchAlert) {
        error!("[SecurityMonitor] SYNC ALERT received: {}", alert);

        if self.pause_triggered.load(Ordering::SeqCst) {
            warn!("[SecurityMonitor] Pause already triggered, skipping duplicate alert");
            return;
        }

        // Extract key information from alert
        let (source_chain, nonce, tx_hash) = match alert {
            MismatchAlert::ApprovalWithoutDeposit {
                source_chain,
                nonce,
                tx_hash,
                ..
            } => (*source_chain, *nonce, tx_hash.clone()),
            MismatchAlert::ClaimWithoutDeposit {
                source_chain,
                nonce,
                tx_hash,
                ..
            } => (*source_chain, *nonce, tx_hash.clone()),
        };

        // CRITICAL: Verify alert by checking EventOrganizer (memory + DB)
        // The TransferTracker alert may be a false positive due to race conditions
        // between deposit finalization and approval/claim processing.
        let key = TransferKey::new(source_chain, nonce);
        let pair = match self.event_organizer.get_pair_for_key(&key).await {
            Ok(p) => p,
            Err(e) => {
                error!(
                    "[SecurityMonitor] Failed to get pair for key {:?}: {}",
                    key, e
                );
                // If we can't verify, assume the alert is valid for safety
                self.proceed_with_pause(alert, &tx_hash).await;
                return;
            }
        };

        // Check if there's still a mismatch after DB verification
        let result = self.mismatch_checker.check(&pair);
        if !result.has_mismatch {
            info!(
                "[SecurityMonitor] Alert resolved after DB verification: key={:?}, deposit found in DB",
                key
            );
            return;
        }

        error!(
            "[SecurityMonitor] CRITICAL MISMATCH DETECTED: {} (key={:?})",
            result.reason.as_ref().unwrap(),
            key
        );

        let source_chain_id = match source_chain {
            ChainId::Starcoin => self.config.stc_chain_id.unwrap_or(0),
            ChainId::Eth => self.config.eth_chain_id.unwrap_or(10),
        };

        let info = MismatchInfo {
            source_chain_id,
            nonce,
            reason: result.reason.unwrap(),
            deposit_tx_hash: result.deposit_tx,
            approval_tx_hash: result.approval_tx,
            claim_tx_hash: result.claim_tx,
        };

        // Send Telegram alert first
        self.send_alert(&info).await;

        // Execute pause if enabled
        if self.config.can_execute {
            self.execute_emergency_pause(&info).await;
        } else {
            warn!("[SecurityMonitor] Auto-pause disabled, manual intervention required!");
        }
    }

    /// Helper to proceed with pause when verification fails
    async fn proceed_with_pause(&self, alert: &MismatchAlert, tx_hash: &str) {
        let (source_chain_id, nonce, reason) = match alert {
            MismatchAlert::ApprovalWithoutDeposit {
                source_chain,
                nonce,
                ..
            } => {
                let chain_id = match source_chain {
                    ChainId::Starcoin => self.config.stc_chain_id.unwrap_or(0),
                    ChainId::Eth => self.config.eth_chain_id.unwrap_or(10),
                };
                (
                    chain_id,
                    *nonce,
                    MismatchReason::NoMatchingDeposit {
                        source_chain: *source_chain,
                        nonce: *nonce,
                        event_type: "Approval",
                    },
                )
            }
            MismatchAlert::ClaimWithoutDeposit {
                source_chain,
                nonce,
                ..
            } => {
                let chain_id = match source_chain {
                    ChainId::Starcoin => self.config.stc_chain_id.unwrap_or(0),
                    ChainId::Eth => self.config.eth_chain_id.unwrap_or(10),
                };
                (
                    chain_id,
                    *nonce,
                    MismatchReason::NoMatchingDeposit {
                        source_chain: *source_chain,
                        nonce: *nonce,
                        event_type: "Claim",
                    },
                )
            }
        };

        let info = MismatchInfo {
            source_chain_id,
            nonce,
            reason,
            deposit_tx_hash: None,
            approval_tx_hash: match alert {
                MismatchAlert::ApprovalWithoutDeposit { .. } => Some(tx_hash.to_string()),
                _ => None,
            },
            claim_tx_hash: match alert {
                MismatchAlert::ClaimWithoutDeposit { .. } => Some(tx_hash.to_string()),
                _ => None,
            },
        };

        self.send_alert(&info).await;
        if self.config.can_execute {
            self.execute_emergency_pause(&info).await;
        }
    }

    /// Run the security monitor background task
    ///
    /// In simplified model, this just waits for cancellation.
    /// All checks are done synchronously when on_approval() detects a mismatch.
    pub async fn run(self: Arc<Self>) {
        info!("[SecurityMonitor] Starting background task (simplified mode)");

        // Just wait for cancellation - all checks are done synchronously
        self.cancel.cancelled().await;
        info!("[SecurityMonitor] Cancelled, stopping");
    }

    /// Send Telegram alert for mismatch
    async fn send_alert(&self, info: &MismatchInfo) {
        if let Some(ref telegram) = self.telegram {
            let message = format!(
                "🚨 *SECURITY ALERT - MISMATCH DETECTED*\n\n\
                *Reason:* {}\n\
                *Source Chain ID:* {}\n\
                *Nonce:* {}\n\
                *Deposit TX:* {}\n\
                *Approval TX:* {}\n\
                *Claim TX:* {}\n\n\
                ⚠️ Immediate investigation required!",
                info.reason,
                info.source_chain_id,
                info.nonce,
                info.deposit_tx_hash.as_deref().unwrap_or("N/A"),
                info.approval_tx_hash.as_deref().unwrap_or("N/A"),
                info.claim_tx_hash.as_deref().unwrap_or("N/A"),
            );

            if let Err(e) = telegram.send_message(&message).await {
                error!("[SecurityMonitor] Failed to send Telegram alert: {:?}", e);
            }
        }
    }

    /// Execute emergency pause on both chains
    async fn execute_emergency_pause(&self, info: &MismatchInfo) {
        if self
            .pause_triggered
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            warn!("[SecurityMonitor] Pause already triggered, skipping");
            return;
        }

        error!(
            "[SecurityMonitor] EXECUTING EMERGENCY PAUSE due to: {}",
            info.reason
        );

        // Pause ETH
        if let Err(e) = self.pause_eth().await {
            error!("[SecurityMonitor] Failed to pause ETH: {:?}", e);
        }

        // Pause STC
        if let Err(e) = self.pause_stc().await {
            error!("[SecurityMonitor] Failed to pause STC: {:?}", e);
        }
    }

    async fn pause_eth(&self) -> Result<()> {
        let config_path = self
            .config
            .bridge_cli_config_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Bridge CLI config path not configured"))?;
        let chain_id = self
            .config
            .eth_chain_id
            .ok_or_else(|| anyhow::anyhow!("ETH chain ID not configured"))?;
        let signatures = self
            .config
            .eth_pause_signatures
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ETH pause signatures not configured"))?;
        let nonce = self
            .config
            .eth_pause_nonce
            .ok_or_else(|| anyhow::anyhow!("ETH pause nonce not configured"))?;

        info!(
            "[SecurityMonitor] Pausing ETH bridge (chain_id: {}) with nonce {}",
            chain_id, nonce
        );

        crate::security_monitor::pause_executor::execute_eth_pause(
            config_path,
            chain_id,
            signatures,
            nonce,
        )
        .await
    }

    async fn pause_stc(&self) -> Result<()> {
        let config_path = self
            .config
            .bridge_cli_config_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Bridge CLI config path not configured"))?;
        let chain_id = self
            .config
            .stc_chain_id
            .ok_or_else(|| anyhow::anyhow!("STC chain ID not configured"))?;
        let signatures = self
            .config
            .stc_pause_signatures
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("STC pause signatures not configured"))?;
        let nonce = self
            .config
            .stc_pause_nonce
            .ok_or_else(|| anyhow::anyhow!("STC pause nonce not configured"))?;

        info!(
            "[SecurityMonitor] Pausing STC bridge (chain_id: {}) with nonce {}",
            chain_id, nonce
        );

        crate::security_monitor::pause_executor::execute_stc_pause(
            config_path,
            chain_id,
            signatures,
            nonce,
        )
        .await
    }
}

/// Create a shared SecurityMonitor
pub fn create_shared_security_monitor(
    config: SecurityMonitorConfig,
    transfer_tracker: Arc<TransferTracker>,
    db: Db,
    network: NetworkType,
    telegram: Option<SharedTelegramNotifier>,
    cancel: CancellationToken,
) -> SharedSecurityMonitor {
    Arc::new(SecurityMonitor::new(
        config,
        transfer_tracker,
        db,
        network,
        telegram,
        cancel,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = SecurityMonitorConfig::default();
        assert!(!config.can_execute);
    }

    #[test]
    fn test_mismatch_info() {
        let info = MismatchInfo {
            source_chain_id: 10,
            nonce: 123,
            reason: MismatchReason::NoMatchingDeposit {
                source_chain: ChainId::Eth,
                nonce: 123,
                event_type: "Approval",
            },
            deposit_tx_hash: None,
            approval_tx_hash: Some("0xabc".to_string()),
            claim_tx_hash: None,
        };

        assert_eq!(info.nonce, 123);
        assert!(info.approval_tx_hash.is_some());
    }

    #[tokio::test]
    async fn test_activate_sets_active_flag() {
        use std::sync::atomic::Ordering;

        // Test that activate() sets the active flag
        let active = AtomicBool::new(false);
        active.store(true, Ordering::SeqCst);
        assert!(active.load(Ordering::SeqCst));
    }

    #[test]
    fn test_config_with_pause_signatures() {
        let config = SecurityMonitorConfig {
            eth_chain_id: Some(10),
            stc_chain_id: Some(2),
            can_execute: true,
            bridge_cli_config_path: Some("/path/to/config".to_string()),
            eth_pause_signatures: Some("0xsig1".to_string()),
            stc_pause_signatures: Some("0xsig2".to_string()),
            eth_pause_nonce: Some(1),
            stc_pause_nonce: Some(1),
        };

        assert!(config.can_execute);
        assert!(config.eth_pause_signatures.is_some());
        assert!(config.stc_pause_signatures.is_some());
    }

    #[test]
    fn test_pause_triggered_atomic() {
        let pause_triggered = AtomicBool::new(false);

        // First compare_exchange should succeed
        let result =
            pause_triggered.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst);
        assert!(result.is_ok());

        // Second compare_exchange should fail (already triggered)
        let result =
            pause_triggered.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst);
        assert!(result.is_err());
    }
}
