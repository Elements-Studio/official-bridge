//! Security Monitor Module
//!
//! Detects deposit/claim mismatches that indicate potential key compromise.
//!
//! ## Architecture
//!
//! ```text
//!   ┌───────────────────────────────────────────────────────────┐
//!   │                    SecurityMonitor                         │
//!   │                                                            │
//!   │   ┌─────────────────────────────────────────────────────┐ │
//!   │   │              EventOrganizer                          │ │
//!   │   │  ┌────────────────┐  ┌──────────────────────────┐  │ │
//!   │   │  │ TransferTracker │  │  Database                │  │ │
//!   │   │  │ (pending)       │  │  (finalized)             │  │ │
//!   │   │  └───────┬────────┘  └───────────┬──────────────┘  │ │
//!   │   │          └──────────┬────────────┘                  │ │
//!   │   │                     ▼                               │ │
//!   │   │          Organize into (deposit, approval, claim)   │ │
//!   │   └─────────────────────┬───────────────────────────────┘ │
//!   │                         ▼                                 │
//!   │   ┌─────────────────────────────────────────────────────┐ │
//!   │   │              MismatchChecker                         │ │
//!   │   │         Check pairs for mismatches                   │ │
//!   │   └─────────────────────┬───────────────────────────────┘ │
//!   │                         ▼                                 │
//!   │                  Mismatch Detected?                       │
//!   │                         │                                 │
//!   │                  Yes    │                                 │
//!   │                         ▼                                 │
//!   │   ┌─────────────────────────────────────────────────────┐ │
//!   │   │  Alert (Telegram) + Emergency Pause (both chains)   │ │
//!   │   └─────────────────────────────────────────────────────┘ │
//!   └───────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Trigger Points
//!
//! 1. Real-time: When TransferTracker notifies of event changes
//! 2. Periodic: Background scan of DB for unchecked transfers

mod config;
mod detector;
mod event_organizer;
mod mismatch_checker;
pub mod pause_executor;

pub use detector::{
    create_shared_security_monitor, MismatchInfo, SecurityMonitor, SecurityMonitorConfig,
    SharedSecurityMonitor,
};
pub use event_organizer::{
    ApprovalEventData, ClaimEventData, DepositEventData, EventOrganizer, EventPair,
};
pub use mismatch_checker::{MismatchChecker, MismatchReason, MismatchResult};
pub use pause_executor::PauseExecutor;

use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::network::NetworkType;
use crate::telegram::SharedTelegramNotifier;
use starcoin_bridge::pending_events::TransferTracker;
use starcoin_bridge_pg_db::Db;

/// Result of monitor startup
pub struct SecurityMonitorResult {
    pub monitor: SharedSecurityMonitor,
    pub cancel: CancellationToken,
    /// Handle for background task
    pub handle: JoinHandle<()>,
}

/// Start the security monitor
///
/// This sets up:
/// 1. EventOrganizer for gathering events from memory and DB
/// 2. MismatchChecker for validating event pairs
/// 3. Background task for periodic DB scanning
/// 4. Notification mechanism for real-time event checking
///
/// Note: The monitor should only be activated AFTER both chains are caught up.
/// Call `monitor.activate()` once ready.
pub async fn start_security_monitor(
    config: detector::SecurityMonitorConfig,
    db: Db,
    transfer_tracker: Arc<TransferTracker>,
    network: NetworkType,
    telegram: Option<SharedTelegramNotifier>,
    cancel: CancellationToken,
) -> anyhow::Result<SecurityMonitorResult> {
    info!("[SecurityMonitor] Starting security monitor");
    info!(
        "[SecurityMonitor] Emergency pause enabled: {}",
        config.can_execute
    );

    let monitor = create_shared_security_monitor(
        config,
        transfer_tracker.clone(),
        db,
        network,
        telegram,
        cancel.clone(),
    );

    // Set up notification callback on TransferTracker
    let monitor_for_callback = monitor.clone();
    let callback = Arc::new(move || {
        monitor_for_callback.notify_event_change();
    });
    transfer_tracker.set_change_callback(callback).await;
    info!("[SecurityMonitor] Change callback set on TransferTracker");

    // Start background task
    let monitor_clone = monitor.clone();
    let handle = tokio::spawn(async move {
        monitor_clone.run().await;
    });

    Ok(SecurityMonitorResult {
        monitor,
        cancel,
        handle,
    })
}
