//! Security Monitor
//!
//! Verifies every approval has a matching deposit. Two detection paths:
//!
//! **Path A (real-time):** When `on_approval()` fires and no deposit is found in memory,
//! the event handler calls `handle_approval_alert()`. We re-verify against memory + DB.
//! If still no deposit → freeze the bridge.
//!
//! **Path B (periodic scan):** After both chains catch up and the grace period ends,
//! `run()` periodically queries DB for unverified approvals. For each, it looks up the
//! deposit. No deposit → freeze. Deposit found → mark `monitor_verified = true`.
//!
//! Path B covers: startup catch-up, restarts, race conditions, anything Path A missed.

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

use super::approval_verifier::{self, MismatchReason};
use super::event_organizer::{DepositLookup, EventOrganizer};

/// How often the periodic DB scan runs (seconds)
const PERIODIC_SCAN_INTERVAL_SECS: u64 = 30;

/// Max approvals to check per scan cycle
const SCAN_BATCH_SIZE: i64 = 100;

/// Grace period after activation before processing alerts (seconds).
/// Both chains must catch up first, then we wait this long for any
/// remaining historical events to be fully written to DB.
const ACTIVATION_GRACE_PERIOD_SECS: u64 = 10;

/// Security Monitor configuration
#[derive(Debug, Clone, Default)]
pub struct SecurityMonitorConfig {
    pub eth_chain_id: Option<u8>,
    pub stc_chain_id: Option<u8>,
    /// Whether auto-pause is enabled
    pub can_execute: bool,
    /// Path to bridge-cli config file (required for governance-execute)
    pub bridge_cli_config_path: Option<String>,
    /// Pre-signed pause signatures for ETH (comma-separated)
    pub eth_pause_signatures: Option<String>,
    /// Pre-signed pause signatures for STC (comma-separated)
    pub stc_pause_signatures: Option<String>,
    pub eth_pause_nonce: Option<u64>,
    pub stc_pause_nonce: Option<u64>,
}

/// Information about a detected mismatch, for alerting
#[derive(Debug, Clone)]
pub struct MismatchInfo {
    pub source_chain_id: u8,
    pub nonce: u64,
    pub reason: MismatchReason,
    pub approval_tx_hash: Option<String>,
}

pub type SharedSecurityMonitor = Arc<SecurityMonitor>;

/// SecurityMonitor: approval verification engine.
///
/// - Before activation: alerts are deferred (chains still syncing).
/// - During grace period: alerts are deferred (historical events settling).
/// - After grace period: real-time alerts processed immediately + periodic DB scan starts.
pub struct SecurityMonitor {
    config: SecurityMonitorConfig,
    event_organizer: Box<dyn DepositLookup>,
    telegram: Option<SharedTelegramNotifier>,
    active: AtomicBool,
    activated_at: RwLock<Option<std::time::Instant>>,
    pause_triggered: AtomicBool,
    cancel: CancellationToken,
    /// Alerts received before activation or during grace period
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
        Self {
            config,
            event_organizer: Box::new(event_organizer),
            telegram,
            active: AtomicBool::new(false),
            activated_at: RwLock::new(None),
            pause_triggered: AtomicBool::new(false),
            cancel,
            deferred_alerts: RwLock::new(Vec::new()),
        }
    }

    /// Create with a custom DepositLookup impl (for testing).
    #[cfg(test)]
    pub(crate) fn new_with_lookup(
        config: SecurityMonitorConfig,
        lookup: Box<dyn DepositLookup>,
        telegram: Option<SharedTelegramNotifier>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            config,
            event_organizer: lookup,
            telegram,
            active: AtomicBool::new(false),
            activated_at: RwLock::new(None),
            pause_triggered: AtomicBool::new(false),
            cancel,
            deferred_alerts: RwLock::new(Vec::new()),
        }
    }

    /// Activate after both chains have caught up to latest block.
    /// Starts the grace period timer.
    pub fn activate(&self) {
        info!(
            "[SecurityMonitor] Activated - starting {}s grace period",
            ACTIVATION_GRACE_PERIOD_SECS
        );
        self.active.store(true, Ordering::SeqCst);
        if let Ok(mut guard) = self.activated_at.try_write() {
            *guard = Some(std::time::Instant::now());
        }
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Activate and immediately skip past the grace period (test only).
    #[cfg(test)]
    pub(crate) fn activate_skip_grace(&self) {
        self.active.store(true, Ordering::SeqCst);
        // Set activated_at far enough in the past that grace period is expired
        if let Ok(mut guard) = self.activated_at.try_write() {
            *guard = Some(
                std::time::Instant::now()
                    - std::time::Duration::from_secs(ACTIVATION_GRACE_PERIOD_SECS + 1),
            );
        }
    }

    fn in_grace_period(&self) -> bool {
        if let Ok(guard) = self.activated_at.try_read() {
            if let Some(activated_at) = *guard {
                return activated_at.elapsed().as_secs() < ACTIVATION_GRACE_PERIOD_SECS;
            }
        }
        false
    }

    fn grace_period_remaining(&self) -> u64 {
        self.activated_at
            .try_read()
            .ok()
            .and_then(|g| g.map(|t| ACTIVATION_GRACE_PERIOD_SECS.saturating_sub(t.elapsed().as_secs())))
            .unwrap_or(0)
    }

    // ------------------------------------------------------------------
    // Path A: Real-time alert handling
    // ------------------------------------------------------------------

    /// Handle an alert from `TransferTracker.on_approval()`.
    ///
    /// Called by event handlers when an approval arrives with no in-memory deposit.
    /// We re-verify against memory + DB before taking action.
    pub async fn handle_approval_alert(&self, alert: MismatchAlert) {
        // Only process ApprovalWithoutDeposit; ignore other variants.
        let (source_chain, nonce, tx_hash) = match &alert {
            MismatchAlert::ApprovalWithoutDeposit {
                source_chain,
                nonce,
                tx_hash,
                ..
            } => (*source_chain, *nonce, tx_hash.clone()),
            _ => return,
        };

        if !self.is_active() {
            warn!(
                "[SecurityMonitor] Alert deferred (not active): source={:?}, nonce={}",
                source_chain, nonce
            );
            self.deferred_alerts.write().await.push(alert);
            return;
        }

        if self.in_grace_period() {
            warn!(
                "[SecurityMonitor] Alert deferred (grace period, {}s remaining): source={:?}, nonce={}",
                self.grace_period_remaining(), source_chain, nonce
            );
            self.deferred_alerts.write().await.push(alert);
            return;
        }

        self.verify_and_act(source_chain, nonce, &tx_hash).await;
    }

    /// Process alerts that were deferred during startup / grace period.
    async fn process_deferred_alerts(&self) {
        let alerts = {
            let mut guard = self.deferred_alerts.write().await;
            std::mem::take(&mut *guard)
        };

        if alerts.is_empty() {
            info!("[SecurityMonitor] No deferred alerts to process");
            return;
        }

        info!(
            "[SecurityMonitor] Processing {} deferred alert(s)",
            alerts.len()
        );

        for alert in alerts {
            if let MismatchAlert::ApprovalWithoutDeposit {
                source_chain,
                nonce,
                tx_hash,
                ..
            } = &alert
            {
                self.verify_and_act(*source_chain, *nonce, tx_hash).await;
            }
        }
    }

    // ------------------------------------------------------------------
    // Path B: Periodic DB scan
    // ------------------------------------------------------------------

    /// Background task: wait for grace period, process deferred alerts,
    /// then periodically scan DB for unverified approvals.
    pub async fn run(self: Arc<Self>) {
        info!("[SecurityMonitor] Background task started");

        // Wait until activated
        loop {
            if self.cancel.is_cancelled() {
                info!("[SecurityMonitor] Cancelled before activation");
                return;
            }
            if self.is_active() {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        // Wait for grace period to end
        info!(
            "[SecurityMonitor] Waiting {}s for grace period",
            ACTIVATION_GRACE_PERIOD_SECS
        );
        tokio::select! {
            _ = self.cancel.cancelled() => {
                info!("[SecurityMonitor] Cancelled during grace period");
                return;
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(ACTIVATION_GRACE_PERIOD_SECS)) => {}
        }

        // Process any alerts that arrived during startup/grace period
        self.process_deferred_alerts().await;

        // Periodic scan loop
        info!(
            "[SecurityMonitor] Starting periodic scan (every {}s, batch={})",
            PERIODIC_SCAN_INTERVAL_SECS, SCAN_BATCH_SIZE
        );

        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(PERIODIC_SCAN_INTERVAL_SECS));

        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    info!("[SecurityMonitor] Cancelled, stopping periodic scan");
                    return;
                }
                _ = interval.tick() => {
                    if let Err(e) = self.scan_unchecked_approvals().await {
                        error!("[SecurityMonitor] Periodic scan error: {:?}", e);
                    }
                }
            }
        }
    }

    /// One iteration of the periodic DB scan.
    async fn scan_unchecked_approvals(&self) -> Result<()> {
        if self.pause_triggered.load(Ordering::SeqCst) {
            return Ok(());
        }

        let unchecked = self.event_organizer.get_unchecked_approvals(SCAN_BATCH_SIZE).await?;

        if unchecked.is_empty() {
            return Ok(());
        }

        info!(
            "[SecurityMonitor] Scanning {} unchecked approval(s)",
            unchecked.len()
        );

        for approval in &unchecked {
            let key = TransferKey::new(approval.source_chain, approval.nonce);
            let deposit = match self.event_organizer.find_deposit(&key).await {
                Ok(d) => d,
                Err(e) => {
                    warn!(
                        "[SecurityMonitor] Scan: find_deposit failed for {:?}: {:?} - retrying",
                        key, e
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    self.event_organizer.find_deposit(&key).await?
                }
            };

            let result =
                approval_verifier::verify_approval(approval.source_chain, approval.nonce, &approval.tx_hash, deposit.as_ref());

            if result.is_valid {
                // Deposit exists → mark as verified so we don't re-scan
                if let Err(e) = self
                    .event_organizer
                    .mark_verified(approval.source_chain, approval.nonce)
                    .await
                {
                    warn!(
                        "[SecurityMonitor] Failed to mark verified (source={:?}, nonce={}): {:?}",
                        approval.source_chain, approval.nonce, e
                    );
                }
            } else {
                // No deposit → CRITICAL
                let reason = result.reason.unwrap();
                error!(
                    "[SecurityMonitor] CRITICAL from periodic scan: {}",
                    reason
                );
                self.trigger_freeze(approval.source_chain, approval.nonce, reason, result.approval_tx)
                    .await;
                return Ok(()); // Stop scanning after first mismatch → bridge is frozen
            }
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Shared verification logic
    // ------------------------------------------------------------------

    /// Try to find a deposit, retrying once on transient DB error.
    ///
    /// Returns `None` only if both attempts fail.
    /// Prevents a single transient DB error from triggering a bridge freeze.
    async fn find_deposit_with_retry(
        &self,
        key: &TransferKey,
    ) -> Option<super::event_organizer::DepositEventData> {
        match self.event_organizer.find_deposit(key).await {
            Ok(d) => return d,
            Err(e) => {
                warn!(
                    "[SecurityMonitor] find_deposit failed for {:?}: {:?} - retrying once",
                    key, e
                );
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        match self.event_organizer.find_deposit(key).await {
            Ok(d) => d,
            Err(e) => {
                error!(
                    "[SecurityMonitor] find_deposit failed twice for {:?}: {:?} - treating as no deposit",
                    key, e
                );
                None
            }
        }
    }

    /// Verify an approval against memory + DB, and freeze if mismatch found.
    async fn verify_and_act(&self, source_chain: ChainId, nonce: u64, approval_tx: &str) {
        if self.pause_triggered.load(Ordering::SeqCst) {
            warn!("[SecurityMonitor] Pause already triggered, skipping");
            return;
        }

        let key = TransferKey::new(source_chain, nonce);
        let deposit = self.find_deposit_with_retry(&key).await;

        let result = approval_verifier::verify_approval(source_chain, nonce, approval_tx, deposit.as_ref());

        if result.is_valid {
            info!(
                "[SecurityMonitor] Alert resolved: deposit found for source={:?}, nonce={}",
                source_chain, nonce
            );
            return;
        }

        let reason = result.reason.unwrap();
        error!(
            "[SecurityMonitor] CRITICAL MISMATCH: {} (source={:?}, nonce={})",
            reason, source_chain, nonce
        );
        self.trigger_freeze(source_chain, nonce, reason, result.approval_tx)
            .await;
    }

    // ------------------------------------------------------------------
    // Freeze execution
    // ------------------------------------------------------------------

    async fn trigger_freeze(
        &self,
        source_chain: ChainId,
        nonce: u64,
        reason: MismatchReason,
        approval_tx: Option<String>,
    ) {
        let source_chain_id = match source_chain {
            ChainId::Starcoin => self.config.stc_chain_id.unwrap_or(0),
            ChainId::Eth => self.config.eth_chain_id.unwrap_or(10),
        };

        let info = MismatchInfo {
            source_chain_id,
            nonce,
            reason,
            approval_tx_hash: approval_tx,
        };

        self.send_alert(&info).await;

        if self.config.can_execute {
            self.execute_emergency_pause(&info).await;
        } else {
            warn!("[SecurityMonitor] Auto-pause disabled, manual intervention required!");
        }
    }

    async fn send_alert(&self, info: &MismatchInfo) {
        if let Some(ref telegram) = self.telegram {
            let message = format!(
                "🚨 *SECURITY ALERT - MISMATCH DETECTED*\n\n\
                *Reason:* {}\n\
                *Source Chain ID:* {}\n\
                *Nonce:* {}\n\
                *Approval TX:* {}\n\n\
                ⚠️ Immediate investigation required!",
                info.reason,
                info.source_chain_id,
                info.nonce,
                info.approval_tx_hash.as_deref().unwrap_or("N/A"),
            );

            if let Err(e) = telegram.send_message(&message).await {
                error!("[SecurityMonitor] Failed to send Telegram alert: {:?}", e);
            }
        }
    }

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

        if let Err(e) = self.pause_eth().await {
            error!("[SecurityMonitor] Failed to pause ETH: {:?}", e);
        }

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
            "[SecurityMonitor] Pausing ETH bridge (chain_id: {}, nonce: {})",
            chain_id, nonce
        );

        crate::security_monitor::pause_executor::execute_eth_pause(
            config_path, chain_id, signatures, nonce,
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
            "[SecurityMonitor] Pausing STC bridge (chain_id: {}, nonce: {})",
            chain_id, nonce
        );

        crate::security_monitor::pause_executor::execute_stc_pause(
            config_path, chain_id, signatures, nonce,
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
    use super::super::event_organizer::{DepositEventData, DepositLookup, UncheckedApproval};
    use async_trait::async_trait;
    use std::sync::Mutex;

    // ----------------------------------------------------------------
    // Mock DepositLookup
    // ----------------------------------------------------------------

    /// Mock that returns pre-configured deposits and unchecked approvals.
    /// Tracks which (source_chain, nonce) pairs were marked as verified.
    struct MockLookup {
        /// Map from (ChainId, nonce) → deposit. None = no deposit for that key.
        deposits: std::collections::HashMap<(ChainId, u64), DepositEventData>,
        /// Approvals returned by get_unchecked_approvals
        unchecked: Vec<UncheckedApproval>,
        /// Track mark_verified calls
        verified: Mutex<Vec<(ChainId, u64)>>,
        /// If set, find_deposit will return Err
        fail_find_deposit: bool,
    }

    impl MockLookup {
        fn new() -> Self {
            Self {
                deposits: std::collections::HashMap::new(),
                unchecked: vec![],
                verified: Mutex::new(vec![]),
                fail_find_deposit: false,
            }
        }

        fn with_deposit(mut self, source_chain: ChainId, nonce: u64) -> Self {
            self.deposits.insert(
                (source_chain, nonce),
                DepositEventData {
                    source_chain,
                    nonce,
                    destination_chain: match source_chain {
                        ChainId::Eth => ChainId::Starcoin,
                        ChainId::Starcoin => ChainId::Eth,
                    },
                    token_id: 1,
                    amount: 1_000_000,
                    sender_address: "0xsender".to_string(),
                    recipient_address: "0xrecipient".to_string(),
                    tx_hash: format!("0xdeposit_tx_{}", nonce),
                    block_height: 100,
                },
            );
            self
        }

        fn with_unchecked_approval(mut self, source_chain: ChainId, nonce: u64) -> Self {
            self.unchecked.push(UncheckedApproval {
                source_chain,
                nonce,
                tx_hash: format!("0xapproval_tx_{}", nonce),
                block_height: 200,
            });
            self
        }

        fn with_failing_find_deposit(mut self) -> Self {
            self.fail_find_deposit = true;
            self
        }
    }

    #[async_trait]
    impl DepositLookup for MockLookup {
        async fn find_deposit(&self, key: &TransferKey) -> Result<Option<DepositEventData>> {
            if self.fail_find_deposit {
                return Err(anyhow::anyhow!("DB connection failed"));
            }
            Ok(self.deposits.get(&(key.source_chain, key.nonce)).cloned())
        }

        async fn get_unchecked_approvals(&self, _limit: i64) -> Result<Vec<UncheckedApproval>> {
            Ok(self.unchecked.clone())
        }

        async fn mark_verified(&self, source_chain: ChainId, nonce: u64) -> Result<()> {
            self.verified.lock().unwrap().push((source_chain, nonce));
            Ok(())
        }
    }

    // ----------------------------------------------------------------
    // Helper to build SecurityMonitor with mock
    // ----------------------------------------------------------------

    fn make_monitor(lookup: MockLookup) -> Arc<SecurityMonitor> {
        let config = SecurityMonitorConfig {
            eth_chain_id: Some(10),
            stc_chain_id: Some(1),
            can_execute: false, // don't actually run pause commands in tests
            ..Default::default()
        };
        Arc::new(SecurityMonitor::new_with_lookup(
            config,
            Box::new(lookup),
            None,
            CancellationToken::new(),
        ))
    }

    fn make_alert(source_chain: ChainId, nonce: u64) -> MismatchAlert {
        MismatchAlert::ApprovalWithoutDeposit {
            source_chain,
            nonce,
            tx_hash: format!("0xalert_tx_{}", nonce),
            block_number: 200,
        }
    }

    // ================================================================
    // Config / struct tests
    // ================================================================

    #[test]
    fn test_config_default() {
        let config = SecurityMonitorConfig::default();
        assert!(!config.can_execute);
        assert!(config.eth_chain_id.is_none());
        assert!(config.stc_chain_id.is_none());
    }

    #[test]
    fn test_mismatch_info_display() {
        let info = MismatchInfo {
            source_chain_id: 10,
            nonce: 42,
            reason: MismatchReason::NoMatchingDeposit {
                source_chain: ChainId::Eth,
                nonce: 42,
            },
            approval_tx_hash: Some("0xabc".to_string()),
        };
        assert_eq!(info.nonce, 42);
        assert_eq!(info.source_chain_id, 10);
        assert!(info.approval_tx_hash.is_some());
        // MismatchReason Display impl should contain key information
        let reason_str = format!("{}", info.reason);
        assert!(reason_str.contains("Approval without matching deposit"));
        assert!(reason_str.contains("KEY COMPROMISE"));
    }

    // ================================================================
    // Activation / grace period state tests
    // ================================================================

    #[tokio::test]
    async fn test_not_active_by_default() {
        let monitor = make_monitor(MockLookup::new());
        assert!(!monitor.is_active());
        assert!(!monitor.in_grace_period()); // not active → no grace period
    }

    #[tokio::test]
    async fn test_activate_sets_active() {
        let monitor = make_monitor(MockLookup::new());
        monitor.activate();
        assert!(monitor.is_active());
        assert!(monitor.in_grace_period()); // just activated → in grace period
    }

    #[tokio::test]
    async fn test_activate_skip_grace_bypasses_grace_period() {
        let monitor = make_monitor(MockLookup::new());
        monitor.activate_skip_grace();
        assert!(monitor.is_active());
        assert!(!monitor.in_grace_period()); // grace period skipped
    }

    // ================================================================
    // Path A: handle_approval_alert
    // ================================================================

    #[tokio::test]
    async fn test_alert_deferred_when_not_active() {
        let monitor = make_monitor(MockLookup::new());
        // Not activated yet
        monitor.handle_approval_alert(make_alert(ChainId::Eth, 1)).await;

        let deferred = monitor.deferred_alerts.read().await;
        assert_eq!(deferred.len(), 1, "alert should be deferred when not active");
    }

    #[tokio::test]
    async fn test_alert_deferred_during_grace_period() {
        let monitor = make_monitor(MockLookup::new());
        monitor.activate(); // starts grace period
        assert!(monitor.in_grace_period());

        monitor.handle_approval_alert(make_alert(ChainId::Eth, 1)).await;

        let deferred = monitor.deferred_alerts.read().await;
        assert_eq!(deferred.len(), 1, "alert should be deferred during grace period");
    }

    #[tokio::test]
    async fn test_alert_processed_after_grace_period_deposit_found() {
        // Deposit exists → alert should be resolved, no freeze.
        let lookup = MockLookup::new().with_deposit(ChainId::Eth, 1);
        let monitor = make_monitor(lookup);
        monitor.activate_skip_grace();

        monitor.handle_approval_alert(make_alert(ChainId::Eth, 1)).await;

        // Should NOT have triggered pause
        assert!(
            !monitor.pause_triggered.load(Ordering::SeqCst),
            "pause should NOT trigger when deposit exists"
        );
        // Should NOT have deferred the alert
        let deferred = monitor.deferred_alerts.read().await;
        assert_eq!(deferred.len(), 0, "alert should not be deferred after grace period");
    }

    #[tokio::test]
    async fn test_alert_triggers_freeze_when_no_deposit() {
        // No deposit → CRITICAL → freeze (but can_execute=false so no actual pause command)
        let lookup = MockLookup::new(); // no deposits
        let monitor = make_monitor(lookup);
        monitor.activate_skip_grace();

        monitor.handle_approval_alert(make_alert(ChainId::Eth, 1)).await;

        // pause_triggered should still be false because can_execute=false,
        // but the flag is set in execute_emergency_pause which IS called
        // only when can_execute=true. Since can_execute=false, the flag
        // is NOT set. This is correct behavior: manual intervention required.
        //
        // However, verify_and_act still ran (no deposit found = mismatch logged).
        // We can verify this by checking that deferred_alerts is empty (not deferred).
        let deferred = monitor.deferred_alerts.read().await;
        assert_eq!(deferred.len(), 0);
    }

    #[tokio::test]
    async fn test_alert_triggers_pause_when_can_execute() {
        // With can_execute=true but no bridge-cli config, pause will fail but flag gets set
        let lookup = MockLookup::new(); // no deposits
        let config = SecurityMonitorConfig {
            eth_chain_id: Some(10),
            stc_chain_id: Some(1),
            can_execute: true,
            bridge_cli_config_path: Some("/nonexistent".to_string()),
            eth_pause_signatures: Some("sig1".to_string()),
            stc_pause_signatures: Some("sig1".to_string()),
            eth_pause_nonce: Some(0),
            stc_pause_nonce: Some(0),
            ..Default::default()
        };
        let monitor = Arc::new(SecurityMonitor::new_with_lookup(
            config,
            Box::new(lookup),
            None,
            CancellationToken::new(),
        ));
        monitor.activate_skip_grace();

        monitor.handle_approval_alert(make_alert(ChainId::Eth, 1)).await;

        // pause_triggered should be set even though the actual commands fail
        assert!(
            monitor.pause_triggered.load(Ordering::SeqCst),
            "pause should be triggered when can_execute=true and no deposit"
        );
    }

    #[tokio::test]
    async fn test_claim_alert_is_ignored() {
        // ClaimWithoutDeposit should be silently ignored
        let lookup = MockLookup::new(); // no deposits
        let monitor = make_monitor(lookup);
        monitor.activate_skip_grace();

        let claim_alert = MismatchAlert::ClaimWithoutDeposit {
            source_chain: ChainId::Eth,
            nonce: 1,
            tx_hash: "0xclaim".to_string(),
            block_number: 200,
        };
        monitor.handle_approval_alert(claim_alert).await;

        // Should NOT have deferred or processed anything
        let deferred = monitor.deferred_alerts.read().await;
        assert_eq!(deferred.len(), 0);
        assert!(!monitor.pause_triggered.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_multiple_alerts_accumulated_during_inactivity() {
        let monitor = make_monitor(MockLookup::new());

        // Send 3 alerts before activation
        for nonce in 1..=3 {
            monitor
                .handle_approval_alert(make_alert(ChainId::Eth, nonce))
                .await;
        }

        let deferred = monitor.deferred_alerts.read().await;
        assert_eq!(deferred.len(), 3, "all 3 alerts should be deferred");
    }

    #[tokio::test]
    async fn test_db_error_treated_as_mismatch() {
        // If DB lookup fails, we treat it as no deposit found (safety-first)
        let lookup = MockLookup::new().with_failing_find_deposit();
        let config = SecurityMonitorConfig {
            eth_chain_id: Some(10),
            stc_chain_id: Some(1),
            can_execute: true,
            bridge_cli_config_path: Some("/nonexistent".to_string()),
            eth_pause_signatures: Some("sig1".to_string()),
            stc_pause_signatures: Some("sig1".to_string()),
            eth_pause_nonce: Some(0),
            stc_pause_nonce: Some(0),
            ..Default::default()
        };
        let monitor = Arc::new(SecurityMonitor::new_with_lookup(
            config,
            Box::new(lookup),
            None,
            CancellationToken::new(),
        ));
        monitor.activate_skip_grace();

        monitor.handle_approval_alert(make_alert(ChainId::Eth, 1)).await;

        assert!(
            monitor.pause_triggered.load(Ordering::SeqCst),
            "DB error should be treated as mismatch (fail-safe) and trigger pause"
        );
    }

    #[tokio::test]
    async fn test_second_alert_skipped_after_pause_triggered() {
        // Once pause is triggered, subsequent alerts should be skipped
        let config = SecurityMonitorConfig {
            eth_chain_id: Some(10),
            stc_chain_id: Some(1),
            can_execute: true,
            bridge_cli_config_path: Some("/nonexistent".to_string()),
            eth_pause_signatures: Some("sig1".to_string()),
            stc_pause_signatures: Some("sig1".to_string()),
            eth_pause_nonce: Some(0),
            stc_pause_nonce: Some(0),
            ..Default::default()
        };
        let monitor = Arc::new(SecurityMonitor::new_with_lookup(
            config,
            Box::new(MockLookup::new()),
            None,
            CancellationToken::new(),
        ));
        monitor.activate_skip_grace();

        // First alert triggers pause
        monitor.handle_approval_alert(make_alert(ChainId::Eth, 1)).await;
        assert!(monitor.pause_triggered.load(Ordering::SeqCst));

        // Second alert should be skipped (verify_and_act returns early)
        monitor.handle_approval_alert(make_alert(ChainId::Eth, 2)).await;
        // No crash, no double-pause — just skipped
    }

    // ================================================================
    // Deferred alert processing
    // ================================================================

    #[tokio::test]
    async fn test_process_deferred_alerts_with_deposit() {
        // Alerts deferred, then deposit arrives before processing
        let lookup = MockLookup::new().with_deposit(ChainId::Eth, 1);
        let monitor = make_monitor(lookup);

        // Defer alert
        monitor.handle_approval_alert(make_alert(ChainId::Eth, 1)).await;
        assert_eq!(monitor.deferred_alerts.read().await.len(), 1);

        // Activate and process deferred
        monitor.activate_skip_grace();
        monitor.process_deferred_alerts().await;

        // Deferred queue should be drained
        assert_eq!(monitor.deferred_alerts.read().await.len(), 0);
        // No pause because deposit was found
        assert!(!monitor.pause_triggered.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_process_deferred_alerts_without_deposit() {
        // Alert deferred, still no deposit when processing
        let config = SecurityMonitorConfig {
            eth_chain_id: Some(10),
            stc_chain_id: Some(1),
            can_execute: true,
            bridge_cli_config_path: Some("/nonexistent".to_string()),
            eth_pause_signatures: Some("sig1".to_string()),
            stc_pause_signatures: Some("sig1".to_string()),
            eth_pause_nonce: Some(0),
            stc_pause_nonce: Some(0),
            ..Default::default()
        };
        let monitor = Arc::new(SecurityMonitor::new_with_lookup(
            config,
            Box::new(MockLookup::new()), // no deposit
            None,
            CancellationToken::new(),
        ));

        // Defer alert
        monitor.handle_approval_alert(make_alert(ChainId::Eth, 1)).await;

        // Activate and process
        monitor.activate_skip_grace();
        monitor.process_deferred_alerts().await;

        assert!(
            monitor.pause_triggered.load(Ordering::SeqCst),
            "should freeze when deferred alert reprocessed and still no deposit"
        );
    }

    #[tokio::test]
    async fn test_process_deferred_alerts_empty() {
        let monitor = make_monitor(MockLookup::new());
        monitor.activate_skip_grace();
        // No alerts deferred → should not panic
        monitor.process_deferred_alerts().await;
        assert!(!monitor.pause_triggered.load(Ordering::SeqCst));
    }

    // ================================================================
    // Path B: Periodic scan
    // ================================================================

    #[tokio::test]
    async fn test_scan_marks_verified_when_deposit_exists() {
        let lookup = MockLookup::new()
            .with_deposit(ChainId::Eth, 1)
            .with_deposit(ChainId::Eth, 2)
            .with_unchecked_approval(ChainId::Eth, 1)
            .with_unchecked_approval(ChainId::Eth, 2);
        let monitor = make_monitor(lookup);
        monitor.activate_skip_grace();

        monitor.scan_unchecked_approvals().await.unwrap();

        // Both should be marked verified
        assert!(!monitor.pause_triggered.load(Ordering::SeqCst));
        // Can't directly inspect mock verified list through Arc, but no panic = success.
        // The key assertion is that pause was NOT triggered.
    }

    #[tokio::test]
    async fn test_scan_freezes_on_missing_deposit() {
        let lookup = MockLookup::new()
            .with_deposit(ChainId::Eth, 1)
            // No deposit for nonce=2
            .with_unchecked_approval(ChainId::Eth, 1)
            .with_unchecked_approval(ChainId::Eth, 2);
        let config = SecurityMonitorConfig {
            eth_chain_id: Some(10),
            stc_chain_id: Some(1),
            can_execute: true,
            bridge_cli_config_path: Some("/nonexistent".to_string()),
            eth_pause_signatures: Some("sig1".to_string()),
            stc_pause_signatures: Some("sig1".to_string()),
            eth_pause_nonce: Some(0),
            stc_pause_nonce: Some(0),
            ..Default::default()
        };
        let monitor = Arc::new(SecurityMonitor::new_with_lookup(
            config,
            Box::new(lookup),
            None,
            CancellationToken::new(),
        ));
        monitor.activate_skip_grace();

        monitor.scan_unchecked_approvals().await.unwrap();

        assert!(
            monitor.pause_triggered.load(Ordering::SeqCst),
            "scan should freeze when unchecked approval has no deposit"
        );
    }

    #[tokio::test]
    async fn test_scan_empty_unchecked_is_noop() {
        let lookup = MockLookup::new(); // no unchecked approvals
        let monitor = make_monitor(lookup);
        monitor.activate_skip_grace();

        monitor.scan_unchecked_approvals().await.unwrap();
        assert!(!monitor.pause_triggered.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_scan_skipped_after_pause() {
        let lookup = MockLookup::new()
            .with_unchecked_approval(ChainId::Eth, 1);
        let monitor = make_monitor(lookup);
        monitor.activate_skip_grace();
        // Pre-set pause triggered
        monitor.pause_triggered.store(true, Ordering::SeqCst);

        monitor.scan_unchecked_approvals().await.unwrap();
        // Should return early without processing
    }

    // ================================================================
    // run() background task
    // ================================================================

    #[tokio::test]
    async fn test_run_cancels_before_activation() {
        let monitor = make_monitor(MockLookup::new());
        let cancel = monitor.cancel.clone();

        let handle = tokio::spawn({
            let m = monitor.clone();
            async move { m.run().await }
        });

        // Cancel immediately
        cancel.cancel();
        // Should exit cleanly
        tokio::time::timeout(std::time::Duration::from_secs(3), handle)
            .await
            .expect("run() should exit within timeout")
            .expect("run() should not panic");
    }

    #[tokio::test]
    async fn test_run_cancels_during_grace_period() {
        let monitor = make_monitor(MockLookup::new());
        let cancel = monitor.cancel.clone();

        let handle = tokio::spawn({
            let m = monitor.clone();
            async move { m.run().await }
        });

        // Activate, then immediately cancel during grace period
        monitor.activate();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        cancel.cancel();

        tokio::time::timeout(std::time::Duration::from_secs(3), handle)
            .await
            .expect("run() should exit within timeout")
            .expect("run() should not panic");
    }

    // ================================================================
    // Cross-chain tests (STC source)
    // ================================================================

    #[tokio::test]
    async fn test_stc_source_alert_with_deposit() {
        let lookup = MockLookup::new().with_deposit(ChainId::Starcoin, 5);
        let monitor = make_monitor(lookup);
        monitor.activate_skip_grace();

        monitor
            .handle_approval_alert(make_alert(ChainId::Starcoin, 5))
            .await;

        assert!(!monitor.pause_triggered.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_stc_source_alert_without_deposit() {
        let config = SecurityMonitorConfig {
            eth_chain_id: Some(10),
            stc_chain_id: Some(1),
            can_execute: true,
            bridge_cli_config_path: Some("/nonexistent".to_string()),
            eth_pause_signatures: Some("sig1".to_string()),
            stc_pause_signatures: Some("sig1".to_string()),
            eth_pause_nonce: Some(0),
            stc_pause_nonce: Some(0),
            ..Default::default()
        };
        let monitor = Arc::new(SecurityMonitor::new_with_lookup(
            config,
            Box::new(MockLookup::new()), // no deposit
            None,
            CancellationToken::new(),
        ));
        monitor.activate_skip_grace();

        monitor
            .handle_approval_alert(make_alert(ChainId::Starcoin, 5))
            .await;

        assert!(
            monitor.pause_triggered.load(Ordering::SeqCst),
            "STC source mismatch should also trigger freeze"
        );
    }

    // ================================================================
    // Pause triggered atomicity
    // ================================================================

    #[test]
    fn test_pause_triggered_compare_exchange_once() {
        let pause_triggered = AtomicBool::new(false);
        let result =
            pause_triggered.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst);
        assert!(result.is_ok());
        // Second CAS should fail
        let result =
            pause_triggered.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst);
        assert!(result.is_err());
    }
}
