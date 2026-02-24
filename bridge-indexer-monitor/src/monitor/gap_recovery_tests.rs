// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for GapRecoveryService using TempDb
//!
//! Run with: cargo test -p starcoin-bridge-indexer-monitor --features db-tests gap_recovery_tests

#![cfg(all(test, feature = "db-tests"))]

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use diesel_async::RunQueryDsl;
use starcoin_bridge_pg_db::temp::TempDb;
use starcoin_bridge_pg_db::{Db, DbArgs};
use starcoin_bridge_schema::models::{
    BridgeDataSource, TokenTransfer, TokenTransferData, TokenTransferStatus,
};
use starcoin_bridge_schema::schema::{token_transfer, token_transfer_data};
use starcoin_bridge_schema::MIGRATIONS;

use super::config::TelegramConfig;
use super::gap_recovery::{GapRecoveryConfig, GapRecoveryService};
use super::telegram::TelegramNotifier;

const ETH_CHAIN_ID: i32 = 12; // Local ETH
const STC_CHAIN_ID: i32 = 2; // Starcoin Custom

/// Helper to create TempDb with migrations
async fn setup_temp_db() -> (TempDb, Db) {
    let temp_db = TempDb::new().expect("Failed to create TempDb");
    let url = temp_db.database().url();

    let db = Db::for_write(url.clone(), DbArgs::default())
        .await
        .expect("Failed to create Db");

    // Run migrations
    db.run_migrations(Some(&MIGRATIONS))
        .await
        .expect("Failed to run migrations");

    (temp_db, db)
}

/// Create a mock TelegramNotifier that doesn't send real messages
fn mock_telegram() -> Arc<TelegramNotifier> {
    Arc::new(TelegramNotifier::new(TelegramConfig {
        bot_token: String::new(), // Empty token = log only, no actual send
        chat_id: String::new(),
        emergency_mention_users: vec![],
    }))
}

/// Helper to get current timestamp in ms
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// Insert a token transfer record
async fn insert_transfer(
    db: &Db,
    chain_id: i32,
    nonce: i64,
    status: TokenTransferStatus,
    timestamp_ms: i64,
) {
    let mut conn = db.connect().await.unwrap();

    let transfer = TokenTransfer {
        chain_id,
        nonce,
        status,
        block_height: nonce * 100,
        timestamp_ms,
        txn_hash: vec![0u8; 32],
        txn_sender: vec![1u8; 20],
        gas_usage: 21000,
        data_source: if chain_id == ETH_CHAIN_ID {
            BridgeDataSource::ETH
        } else {
            BridgeDataSource::STARCOIN
        },
        is_finalized: Some(true),
    };

    diesel::insert_into(token_transfer::table)
        .values(&transfer)
        .execute(&mut *conn)
        .await
        .expect("Failed to insert transfer");
}

/// Insert transfer data (for incomplete transfer tests)
async fn insert_transfer_data(
    db: &Db,
    chain_id: i32,
    nonce: i64,
    destination_chain: i32,
    timestamp_ms: i64,
    amount: i64,
) {
    let mut conn = db.connect().await.unwrap();

    let data = TokenTransferData {
        chain_id,
        nonce,
        block_height: nonce * 100,
        timestamp_ms,
        txn_hash: vec![0u8; 32],
        sender_address: vec![1u8; 20],
        destination_chain,
        recipient_address: vec![2u8; 20],
        token_id: 3, // USDT
        amount,
        is_finalized: Some(true),
        monitor_verified: false,
    };

    diesel::insert_into(token_transfer_data::table)
        .values(&data)
        .execute(&mut *conn)
        .await
        .expect("Failed to insert transfer data");
}

// =============================================================================
// Test: find_deposit_nonce_gaps
// =============================================================================

#[tokio::test]
async fn test_find_gaps_empty_db() {
    let (_temp_db, db) = setup_temp_db().await;

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        ..Default::default()
    };

    let service = GapRecoveryService::new(config, db, None);
    let gaps = service.find_deposit_nonce_gaps(ETH_CHAIN_ID).await.unwrap();

    assert!(gaps.is_empty(), "Empty DB should have no gaps");
}

#[tokio::test]
async fn test_find_gaps_no_gaps() {
    let (_temp_db, db) = setup_temp_db().await;
    let now = now_ms();

    // Insert consecutive nonces: 1, 2, 3
    for nonce in 1..=3 {
        insert_transfer(
            &db,
            ETH_CHAIN_ID,
            nonce,
            TokenTransferStatus::Deposited,
            now,
        )
        .await;
    }

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        ..Default::default()
    };

    let service = GapRecoveryService::new(config, db, None);
    let gaps = service.find_deposit_nonce_gaps(ETH_CHAIN_ID).await.unwrap();

    assert!(gaps.is_empty(), "Consecutive nonces should have no gaps");
}

#[tokio::test]
async fn test_find_gaps_single_gap() {
    let (_temp_db, db) = setup_temp_db().await;
    let now = now_ms();

    // Insert nonces: 1, 2, 4 (missing 3)
    insert_transfer(&db, ETH_CHAIN_ID, 1, TokenTransferStatus::Deposited, now).await;
    insert_transfer(&db, ETH_CHAIN_ID, 2, TokenTransferStatus::Deposited, now).await;
    insert_transfer(&db, ETH_CHAIN_ID, 4, TokenTransferStatus::Deposited, now).await;

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        ..Default::default()
    };

    let service = GapRecoveryService::new(config, db, None);
    let gaps = service.find_deposit_nonce_gaps(ETH_CHAIN_ID).await.unwrap();

    assert_eq!(gaps, vec![3], "Should detect missing nonce 3");
}

#[tokio::test]
async fn test_find_gaps_multiple_gaps() {
    let (_temp_db, db) = setup_temp_db().await;
    let now = now_ms();

    // Insert nonces: 1, 3, 6 (missing 2, 4, 5)
    insert_transfer(&db, ETH_CHAIN_ID, 1, TokenTransferStatus::Deposited, now).await;
    insert_transfer(&db, ETH_CHAIN_ID, 3, TokenTransferStatus::Deposited, now).await;
    insert_transfer(&db, ETH_CHAIN_ID, 6, TokenTransferStatus::Deposited, now).await;

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        ..Default::default()
    };

    let service = GapRecoveryService::new(config, db, None);
    let gaps = service.find_deposit_nonce_gaps(ETH_CHAIN_ID).await.unwrap();

    assert_eq!(gaps, vec![2, 4, 5], "Should detect all missing nonces");
}

#[tokio::test]
async fn test_find_gaps_different_chains_isolated() {
    let (_temp_db, db) = setup_temp_db().await;
    let now = now_ms();

    // ETH chain: nonces 1, 3 (missing 2)
    insert_transfer(&db, ETH_CHAIN_ID, 1, TokenTransferStatus::Deposited, now).await;
    insert_transfer(&db, ETH_CHAIN_ID, 3, TokenTransferStatus::Deposited, now).await;

    // STC chain: nonces 1, 2, 3 (no gaps)
    insert_transfer(&db, STC_CHAIN_ID, 1, TokenTransferStatus::Deposited, now).await;
    insert_transfer(&db, STC_CHAIN_ID, 2, TokenTransferStatus::Deposited, now).await;
    insert_transfer(&db, STC_CHAIN_ID, 3, TokenTransferStatus::Deposited, now).await;

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        ..Default::default()
    };

    let service = GapRecoveryService::new(config, db, None);

    let eth_gaps = service.find_deposit_nonce_gaps(ETH_CHAIN_ID).await.unwrap();
    let stc_gaps = service.find_deposit_nonce_gaps(STC_CHAIN_ID).await.unwrap();

    assert_eq!(eth_gaps, vec![2], "ETH should have gap at 2");
    assert!(stc_gaps.is_empty(), "STC should have no gaps");
}

#[tokio::test]
async fn test_find_gaps_only_deposited_status() {
    let (_temp_db, db) = setup_temp_db().await;
    let now = now_ms();

    // Insert nonces with different statuses
    insert_transfer(&db, ETH_CHAIN_ID, 1, TokenTransferStatus::Deposited, now).await;
    insert_transfer(&db, ETH_CHAIN_ID, 2, TokenTransferStatus::Claimed, now).await; // Claimed
    insert_transfer(&db, ETH_CHAIN_ID, 3, TokenTransferStatus::Deposited, now).await;

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        ..Default::default()
    };

    let service = GapRecoveryService::new(config, db, None);
    let gaps = service.find_deposit_nonce_gaps(ETH_CHAIN_ID).await.unwrap();

    // find_deposit_nonce_gaps only queries Deposited status records for min/max range
    // Nonce 2 has Claimed status, which is not included in the Deposited range query
    // So the range is 1..3 based on Deposited records only
    // Then it checks ALL nonces in that range - nonce 2 EXISTS in the table
    // (even though with Claimed status), so no gap is detected
    // Actually looking at the code - it queries all nonces regardless of status in the gap check
    assert!(gaps.is_empty(), "Nonce 2 exists in token_transfer table");
}

// =============================================================================
// Test: find_incomplete_transfers
// =============================================================================

#[tokio::test]
async fn test_incomplete_transfers_empty_db() {
    let (_temp_db, db) = setup_temp_db().await;

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        ..Default::default()
    };

    let service = GapRecoveryService::new(config, db, None);
    let incomplete = service.find_incomplete_transfers().await.unwrap();

    assert!(
        incomplete.is_empty(),
        "Empty DB should have no incomplete transfers"
    );
}

#[tokio::test]
async fn test_incomplete_transfer_deposit_without_claim() {
    let (_temp_db, db) = setup_temp_db().await;
    let now = now_ms();

    // ETH deposit at nonce 1 (to STC)
    insert_transfer(&db, ETH_CHAIN_ID, 1, TokenTransferStatus::Deposited, now).await;
    insert_transfer_data(&db, ETH_CHAIN_ID, 1, STC_CHAIN_ID, now, 1_000_000).await;

    // No claim on STC

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        ..Default::default()
    };

    let service = GapRecoveryService::new(config, db, None);
    let incomplete = service.find_incomplete_transfers().await.unwrap();

    assert_eq!(incomplete.len(), 1, "Should find one incomplete transfer");
    assert_eq!(incomplete[0].source_chain_id, ETH_CHAIN_ID);
    assert_eq!(incomplete[0].nonce, 1);
    assert_eq!(incomplete[0].destination_chain_id, STC_CHAIN_ID);
    assert_eq!(incomplete[0].amount, 1_000_000);
}

#[tokio::test]
async fn test_complete_transfer_has_claim() {
    let (_temp_db, db) = setup_temp_db().await;
    let now = now_ms();

    // ETH deposit at nonce 1 (to STC)
    insert_transfer(&db, ETH_CHAIN_ID, 1, TokenTransferStatus::Deposited, now).await;
    insert_transfer_data(&db, ETH_CHAIN_ID, 1, STC_CHAIN_ID, now, 1_000_000).await;

    // STC claim for nonce 1
    insert_transfer(&db, STC_CHAIN_ID, 1, TokenTransferStatus::Claimed, now).await;

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        ..Default::default()
    };

    let service = GapRecoveryService::new(config, db, None);
    let incomplete = service.find_incomplete_transfers().await.unwrap();

    assert!(
        incomplete.is_empty(),
        "Completed transfer should not appear as incomplete"
    );
}

#[tokio::test]
async fn test_stale_vs_recent_incomplete_transfers() {
    let (_temp_db, db) = setup_temp_db().await;
    let now = now_ms();
    let hours_25_ago = now - (25 * 60 * 60 * 1000); // 25 hours ago
    let hours_2_ago = now - (2 * 60 * 60 * 1000); // 2 hours ago

    // Stale transfer (25 hours old)
    insert_transfer(
        &db,
        ETH_CHAIN_ID,
        1,
        TokenTransferStatus::Deposited,
        hours_25_ago,
    )
    .await;
    insert_transfer_data(&db, ETH_CHAIN_ID, 1, STC_CHAIN_ID, hours_25_ago, 1_000_000).await;

    // Recent transfer (2 hours old)
    insert_transfer(
        &db,
        ETH_CHAIN_ID,
        2,
        TokenTransferStatus::Deposited,
        hours_2_ago,
    )
    .await;
    insert_transfer_data(&db, ETH_CHAIN_ID, 2, STC_CHAIN_ID, hours_2_ago, 2_000_000).await;

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        stale_threshold: Duration::from_secs(24 * 60 * 60), // 24 hours
        ..Default::default()
    };

    let service = GapRecoveryService::new(config.clone(), db, None);
    let incomplete = service.find_incomplete_transfers().await.unwrap();

    assert_eq!(incomplete.len(), 2, "Should find both transfers");

    let stale: Vec<_> = incomplete
        .iter()
        .filter(|t| t.is_stale(config.stale_threshold))
        .collect();
    let recent: Vec<_> = incomplete
        .iter()
        .filter(|t| !t.is_stale(config.stale_threshold))
        .collect();

    assert_eq!(stale.len(), 1, "Should have one stale transfer");
    assert_eq!(stale[0].nonce, 1);

    assert_eq!(recent.len(), 1, "Should have one recent transfer");
    assert_eq!(recent[0].nonce, 2);
}

#[tokio::test]
async fn test_incomplete_transfer_age_hours() {
    let (_temp_db, db) = setup_temp_db().await;
    let now = now_ms();
    let hours_48_ago = now - (48 * 60 * 60 * 1000); // 48 hours ago

    insert_transfer(
        &db,
        ETH_CHAIN_ID,
        1,
        TokenTransferStatus::Deposited,
        hours_48_ago,
    )
    .await;
    insert_transfer_data(&db, ETH_CHAIN_ID, 1, STC_CHAIN_ID, hours_48_ago, 1_000_000).await;

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        ..Default::default()
    };

    let service = GapRecoveryService::new(config, db, None);
    let incomplete = service.find_incomplete_transfers().await.unwrap();

    assert_eq!(incomplete.len(), 1);
    // Allow some tolerance due to test execution time
    let age = incomplete[0].age_hours();
    assert!(
        age >= 47 && age <= 49,
        "Age should be ~48 hours, got {}",
        age
    );
}

// =============================================================================
// Test: handle_deposit_gaps (Telegram notification)
// =============================================================================

#[tokio::test]
async fn test_handle_gaps_sends_telegram_alert() {
    let (_temp_db, db) = setup_temp_db().await;

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        ..Default::default()
    };

    let telegram = mock_telegram();
    let service = GapRecoveryService::new(config, db, Some(telegram));

    // This should log the alert (since mock telegram has empty token)
    let result = service
        .handle_deposit_gaps(ETH_CHAIN_ID, "ETH", vec![1, 2, 3])
        .await;
    assert!(result.is_ok(), "handle_deposit_gaps should succeed");
}

#[tokio::test]
async fn test_handle_gaps_without_telegram() {
    let (_temp_db, db) = setup_temp_db().await;

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        ..Default::default()
    };

    let service = GapRecoveryService::new(config, db, None);

    // Should succeed even without telegram
    let result = service
        .handle_deposit_gaps(ETH_CHAIN_ID, "ETH", vec![1, 2, 3])
        .await;
    assert!(
        result.is_ok(),
        "handle_deposit_gaps should succeed without telegram"
    );
}

// =============================================================================
// Test: Daily Report
// =============================================================================

#[tokio::test]
async fn test_build_daily_report_no_issues() {
    let (_temp_db, db) = setup_temp_db().await;

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        ..Default::default()
    };

    let service = GapRecoveryService::new(config, db, None);

    let report = service.build_daily_report(&[], &[], &[]);

    assert!(report.contains("No gaps detected"));
    assert!(report.contains("No stale transfers"));
}

#[tokio::test]
async fn test_build_daily_report_with_gaps() {
    let (_temp_db, db) = setup_temp_db().await;

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        ..Default::default()
    };

    let service = GapRecoveryService::new(config, db, None);

    let eth_gaps = vec![1, 2, 3];
    let stc_gaps = vec![10, 11];

    let report = service.build_daily_report(&[], &eth_gaps, &stc_gaps);

    assert!(report.contains("ETH: 3 gaps"));
    assert!(report.contains("STC: 2 gaps"));
}

#[tokio::test]
async fn test_build_daily_report_with_stale_transfers() {
    let (_temp_db, db) = setup_temp_db().await;
    let now = now_ms();
    let hours_48_ago = now - (48 * 60 * 60 * 1000);

    insert_transfer(
        &db,
        ETH_CHAIN_ID,
        1,
        TokenTransferStatus::Deposited,
        hours_48_ago,
    )
    .await;
    insert_transfer_data(&db, ETH_CHAIN_ID, 1, STC_CHAIN_ID, hours_48_ago, 1_000_000).await;

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        stale_threshold: Duration::from_secs(24 * 60 * 60),
        ..Default::default()
    };

    let service = GapRecoveryService::new(config.clone(), db, None);
    let incomplete = service.find_incomplete_transfers().await.unwrap();

    let stale: Vec<_> = incomplete
        .iter()
        .filter(|t| t.is_stale(config.stale_threshold))
        .collect();

    let report = service.build_daily_report(&stale, &[], &[]);

    assert!(report.contains("1 transfers pending"));
    assert!(report.contains("ETH nonce 1"));
}

// =============================================================================
// Test: Large scale gap detection
// =============================================================================

#[tokio::test]
async fn test_find_gaps_large_range() {
    let (_temp_db, db) = setup_temp_db().await;
    let now = now_ms();

    // Insert nonces from 1 to 99, skipping every 10th (10, 20, 30, ...)
    // Max nonce will be 99, so 100 is not in the range
    let mut expected_gaps = Vec::new();
    for nonce in 1..=99 {
        if nonce % 10 == 0 {
            // Skip every 10th nonce (10, 20, 30, ... 90)
            expected_gaps.push(nonce);
        } else {
            insert_transfer(
                &db,
                ETH_CHAIN_ID,
                nonce,
                TokenTransferStatus::Deposited,
                now,
            )
            .await;
        }
    }

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        ..Default::default()
    };

    let service = GapRecoveryService::new(config, db, None);
    let gaps = service.find_deposit_nonce_gaps(ETH_CHAIN_ID).await.unwrap();

    assert_eq!(gaps, expected_gaps, "Should find 9 gaps (10, 20, ..., 90)");
}

// =============================================================================
// Test: Bidirectional transfers
// =============================================================================

#[tokio::test]
async fn test_bidirectional_incomplete_transfers() {
    let (_temp_db, db) = setup_temp_db().await;
    let now = now_ms();

    // ETH -> STC deposit (incomplete)
    insert_transfer(&db, ETH_CHAIN_ID, 1, TokenTransferStatus::Deposited, now).await;
    insert_transfer_data(&db, ETH_CHAIN_ID, 1, STC_CHAIN_ID, now, 1_000_000).await;

    // STC -> ETH deposit (incomplete)
    insert_transfer(&db, STC_CHAIN_ID, 1, TokenTransferStatus::Deposited, now).await;
    insert_transfer_data(&db, STC_CHAIN_ID, 1, ETH_CHAIN_ID, now, 2_000_000).await;

    let config = GapRecoveryConfig {
        eth_chain_id: ETH_CHAIN_ID,
        stc_chain_id: STC_CHAIN_ID,
        ..Default::default()
    };

    let service = GapRecoveryService::new(config, db, None);
    let incomplete = service.find_incomplete_transfers().await.unwrap();

    assert_eq!(incomplete.len(), 2, "Should find both incomplete transfers");

    let eth_to_stc: Vec<_> = incomplete
        .iter()
        .filter(|t| t.source_chain_id == ETH_CHAIN_ID)
        .collect();
    let stc_to_eth: Vec<_> = incomplete
        .iter()
        .filter(|t| t.source_chain_id == STC_CHAIN_ID)
        .collect();

    assert_eq!(eth_to_stc.len(), 1);
    assert_eq!(eth_to_stc[0].amount, 1_000_000);

    assert_eq!(stc_to_eth.len(), 1);
    assert_eq!(stc_to_eth[0].amount, 2_000_000);
}
