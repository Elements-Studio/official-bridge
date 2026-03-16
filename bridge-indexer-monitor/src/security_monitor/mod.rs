//! Security Monitor Module
//!
//! Verifies every approval has a matching deposit. Any mismatch = freeze the bridge.
//!
//! ## Architecture
//!
//! ```text
//!   ┌──────────────────────────────────────────────────────────┐
//!   │                   SecurityMonitor                         │
//!   │                                                           │
//!   │  Path A (real-time):                                      │
//!   │    approval event → on_approval() → no deposit in mem?    │
//!   │    → handle_approval_alert() → verify mem+DB → freeze     │
//!   │                                                           │
//!   │  Path B (periodic scan):                                  │
//!   │    run() loop → get_unchecked_approvals() from DB         │
//!   │    → find_deposit() → no deposit? → freeze                │
//!   │    → deposit found? → mark_verified(true)                 │
//!   │                                                           │
//!   │  Data sources:                                            │
//!   │    EventOrganizer → TransferTracker (memory) + DB         │
//!   │                                                           │
//!   │  On mismatch:                                             │
//!   │    Telegram alert + emergency pause (both chains)         │
//!   └──────────────────────────────────────────────────────────┘
//! ```

mod approval_verifier;
mod config;
mod detector;
mod event_organizer;
pub mod pause_executor;

pub use approval_verifier::MismatchReason;
pub use detector::{
    create_shared_security_monitor, MismatchInfo, SecurityMonitor, SecurityMonitorConfig,
    SharedSecurityMonitor,
};
pub use event_organizer::{DepositEventData, EventOrganizer};
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
    pub handle: JoinHandle<()>,
}

/// Start the security monitor.
///
/// The monitor is NOT active immediately — call `monitor.activate()` after
/// both chains have caught up to latest block.
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
        transfer_tracker,
        db,
        network,
        telegram,
        cancel.clone(),
    );

    // Start background task (waits for activation, then runs periodic scan)
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
