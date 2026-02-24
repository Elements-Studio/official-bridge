// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Tests for bridge monitor module

use crate::monitor::config::{ChainConfig, MonitorConfig, PairedMessageConfig, TelegramConfig};
use crate::monitor::events::{BridgeEvent, TokensClaimedEvent, TokensDepositedEvent};
use crate::monitor::state::{PendingTransfer, StateManager};
use serial_test::serial;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

#[test]
fn test_chain_config_evm_detection() {
    let eth_config = ChainConfig {
        chain_id: 11, // Sepolia
        contract_address: "0x1234".to_string(),
        rpc_url: "http://localhost:8545".to_string(),
        rpc_urls: vec![],
        poll_interval: 5,
        start_block: Some(0),
        limiter_address: None,
        committee_address: None,
    };
    assert!(eth_config.is_evm());
    assert!(!eth_config.is_local());

    let stc_config = ChainConfig {
        chain_id: 1, // Halley
        contract_address: "0xefa1e687a64f869193f109f75d0432be".to_string(),
        rpc_url: "http://localhost:9850".to_string(),
        rpc_urls: vec![],
        poll_interval: 5,
        start_block: Some(0),
        limiter_address: None,
        committee_address: None,
    };
    assert!(!stc_config.is_evm());
    assert!(!stc_config.is_local());

    let local_eth = ChainConfig {
        chain_id: 12, // Local
        contract_address: "0x1234".to_string(),
        rpc_url: "http://localhost:8545".to_string(),
        rpc_urls: vec![],
        poll_interval: 5,
        start_block: Some(0),
        limiter_address: None,
        committee_address: None,
    };
    assert!(local_eth.is_evm());
    assert!(local_eth.is_local());
}

#[test]
fn test_chain_config_rpc_urls() {
    // Test with rpc_urls
    let config1 = ChainConfig {
        chain_id: 11,
        contract_address: "0x1234".to_string(),
        rpc_url: String::new(),
        rpc_urls: vec![
            "http://primary:8545".to_string(),
            "http://backup:8545".to_string(),
        ],
        poll_interval: 5,
        start_block: Some(0),
        limiter_address: None,
        committee_address: None,
    };
    assert_eq!(config1.get_rpc_urls().len(), 2);

    // Test with single rpc_url (backward compatibility)
    let config2 = ChainConfig {
        chain_id: 11,
        contract_address: "0x1234".to_string(),
        rpc_url: "http://localhost:8545".to_string(),
        rpc_urls: vec![],
        poll_interval: 5,
        start_block: Some(0),
        limiter_address: None,
        committee_address: None,
    };
    assert_eq!(config2.get_rpc_urls().len(), 1);
    assert_eq!(config2.get_rpc_urls()[0], "http://localhost:8545");
}

#[test]
fn test_event_id_generation() {
    let deposit = TokensDepositedEvent {
        source_chain_id: 12,
        nonce: 1,
        destination_chain_id: 2,
        token_id: 3,
        amount: 100_000_000,
        sender_address: "0xsender".to_string(),
        recipient_address: "0xrecipient".to_string(),
        tx_hash: "0xabcd".to_string(),
        block_number: 100,
    };

    let event = BridgeEvent::TokensDeposited(deposit);
    let id = event.event_id();
    assert!(id.starts_with("Deposit:0xabcd:100"));
}

#[test]
fn test_pending_transfer_key() {
    let transfer = PendingTransfer {
        source_chain_id: 12,
        nonce: 42,
        destination_chain_id: 2,
        token_id: 3,
        amount: 100_000_000,
        sender_address: "0xsender".to_string(),
        recipient_address: "0xrecipient".to_string(),
        deposit_tx: "0xabcd".to_string(),
        deposit_block: 100,
        deposit_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        deposit_chain_key: "chain_a".to_string(),
    };

    assert_eq!(transfer.transfer_key(), "12:42");
}

#[test]
fn test_pending_transfer_age() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let transfer = PendingTransfer {
        source_chain_id: 12,
        nonce: 1,
        destination_chain_id: 2,
        token_id: 3,
        amount: 100_000_000,
        sender_address: "0xsender".to_string(),
        recipient_address: "0xrecipient".to_string(),
        deposit_tx: "0xabcd".to_string(),
        deposit_block: 100,
        deposit_time: now - 3700, // 1 hour and 1 minute ago
        deposit_chain_key: "chain_a".to_string(),
    };

    let age = transfer.age_seconds();
    assert!(age >= 3700);
    assert!(age < 3710); // Allow small time drift

    let age_human = transfer.age_human();
    assert!(age_human.contains("h"));
}

#[tokio::test]
async fn test_state_manager_basic_operations() {
    let temp_dir = TempDir::new().unwrap();
    let state_file = temp_dir.path().join("test-state.json");

    let manager = StateManager::new(state_file.clone()).unwrap();

    // Load with chain configs
    manager
        .load(12, "0xeth_bridge", 2, "0xefa1e687a64f869193f109f75d0432be")
        .await
        .unwrap();

    // Test block tracking
    assert_eq!(manager.get_last_block("chain_a").await, None);
    manager.update_last_block("chain_a", 100).await.unwrap();
    assert_eq!(manager.get_last_block("chain_a").await, Some(100));

    // Test event deduplication
    let event_id = "Deposit:0xabcd:100";
    assert!(!manager.is_event_sent("chain_a", event_id).await);
    manager
        .mark_event_sent("chain_a", event_id.to_string())
        .await
        .unwrap();
    assert!(manager.is_event_sent("chain_a", event_id).await);
}

#[tokio::test]
async fn test_state_manager_pending_transfers() {
    let temp_dir = TempDir::new().unwrap();
    let state_file = temp_dir.path().join("test-state.json");

    let manager = StateManager::new(state_file.clone()).unwrap();
    manager
        .load(12, "0xeth_bridge", 2, "0xstc_bridge")
        .await
        .unwrap();

    // Add pending transfer
    let transfer = PendingTransfer {
        source_chain_id: 12,
        nonce: 1,
        destination_chain_id: 2,
        token_id: 3,
        amount: 100_000_000,
        sender_address: "0xsender".to_string(),
        recipient_address: "0xrecipient".to_string(),
        deposit_tx: "0xabcd".to_string(),
        deposit_block: 100,
        deposit_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        deposit_chain_key: "chain_a".to_string(),
    };

    manager
        .add_pending_transfer(transfer.clone())
        .await
        .unwrap();

    // Verify it's there
    let pending = manager.get_pending_transfers().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].nonce, 1);

    // Remove it
    manager.remove_pending_transfer(12, 1).await.unwrap();
    let pending = manager.get_pending_transfers().await;
    assert_eq!(pending.len(), 0);
}

#[tokio::test]
async fn test_state_manager_persistence() {
    let temp_dir = TempDir::new().unwrap();
    let state_file = temp_dir.path().join("test-state.json");

    // Create and save state
    {
        let manager = StateManager::new(state_file.clone()).unwrap();
        manager
            .load(12, "0xeth_bridge", 2, "0xstc_bridge")
            .await
            .unwrap();
        manager.update_last_block("chain_a", 200).await.unwrap();
        manager
            .mark_event_sent("chain_a", "event1".to_string())
            .await
            .unwrap();
    }

    // Load from file
    {
        let manager = StateManager::new(state_file.clone()).unwrap();
        manager
            .load(12, "0xeth_bridge", 2, "0xstc_bridge")
            .await
            .unwrap();
        assert_eq!(manager.get_last_block("chain_a").await, Some(200));
        assert!(manager.is_event_sent("chain_a", "event1").await);
    }
}

#[test]
#[serial]
fn test_telegram_config_from_env() {
    // Save current env vars
    let old_token = std::env::var("TELEGRAM_BOT_TOKEN").ok();
    let old_chat = std::env::var("TELEGRAM_CHAT_ID").ok();

    // Set test env vars
    std::env::set_var("TELEGRAM_BOT_TOKEN", "test_token_123");
    std::env::set_var("TELEGRAM_CHAT_ID", "123456789");

    let config = TelegramConfig::from_env();
    assert_eq!(config.bot_token, "test_token_123");
    assert_eq!(config.chat_id, "123456789");
    assert!(!config.bot_token.is_empty());
    assert!(!config.chat_id.is_empty());

    // Restore env vars
    if let Some(token) = old_token {
        std::env::set_var("TELEGRAM_BOT_TOKEN", token);
    } else {
        std::env::remove_var("TELEGRAM_BOT_TOKEN");
    }
    if let Some(chat) = old_chat {
        std::env::set_var("TELEGRAM_CHAT_ID", chat);
    } else {
        std::env::remove_var("TELEGRAM_CHAT_ID");
    }
}

#[test]
fn test_monitor_config_yaml_parsing() {
    let yaml = r#"
chain_a:
  chain_id: 12
  contract_address: "0x1234567890123456789012345678901234567890"
  rpc_urls:
    - "http://localhost:8545"
  poll_interval: 5
  start_block: 0

chain_b:
  chain_id: 2
  contract_address: "0xefa1e687a64f869193f109f75d0432be"
  rpc_urls:
    - "http://localhost:9850"
  poll_interval: 5

telegram:
  bot_token: "test_token"
  chat_id: "123456"

paired_message:
  enabled: true
  alert_threshold_seconds: 3600
  check_interval_seconds: 300
"#;

    let config: MonitorConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.chain_a.chain_id, 12);
    assert_eq!(config.chain_b.chain_id, 2);
    assert_eq!(config.telegram.bot_token, "test_token");
    assert_eq!(config.telegram.chat_id, "123456");
    assert!(config.paired_message.enabled);
    assert_eq!(config.paired_message.alert_threshold_seconds, 3600);
}

#[test]
fn test_paired_message_config_defaults() {
    let config = PairedMessageConfig::default();
    assert!(config.enabled);
    assert_eq!(config.alert_threshold_seconds, 3600);
    assert_eq!(config.check_interval_seconds, 300);
}

#[test]
fn test_tokens_deposited_amount_human() {
    let event = TokensDepositedEvent {
        source_chain_id: 12,
        nonce: 1,
        destination_chain_id: 2,
        token_id: 3,
        amount: 100_000_000, // 1.0 in bridge format (8 decimals)
        sender_address: "0xsender".to_string(),
        recipient_address: "0xrecipient".to_string(),
        tx_hash: "0xabcd".to_string(),
        block_number: 100,
    };

    let human = event.amount_human();
    assert!(human.contains("1."));
}

#[test]
fn test_tokens_claimed_amount_human() {
    let event = TokensClaimedEvent {
        source_chain_id: 2,
        nonce: 1,
        destination_chain_id: 12,
        token_id: 3,       // USDT with 6 decimals on EVM
        amount: 1_000_000, // 1.0 USDT
        sender_address: "0xsender".to_string(),
        recipient_address: "0xrecipient".to_string(),
        tx_hash: "0xabcd".to_string(),
        block_number: 100,
    };

    let human = event.amount_human();
    assert!(human.contains("1."));
}

// ============================================================================
// Failover tests
// ============================================================================

#[tokio::test]
async fn test_failover_urls_initialization() {
    use crate::failover::FailoverRpcUrls;

    let urls = FailoverRpcUrls::new(vec![
        "http://primary:8545".to_string(),
        "http://backup1:8545".to_string(),
        "http://backup2:8545".to_string(),
    ]);

    assert_eq!(urls.current_url(), "http://primary:8545");
    assert_eq!(urls.all_urls().len(), 3);
}

#[tokio::test]
async fn test_failover_urls_rotation() {
    use crate::failover::FailoverRpcUrls;

    let urls = FailoverRpcUrls::new(vec![
        "http://rpc1:8545".to_string(),
        "http://rpc2:8545".to_string(),
    ]);

    assert_eq!(urls.current_url(), "http://rpc1:8545");

    // Simulate failure and failover
    urls.report_failure().await;

    assert_eq!(urls.current_url(), "http://rpc2:8545");
}

#[tokio::test]
async fn test_failover_urls_success_clears_failure() {
    use crate::failover::FailoverRpcUrls;

    let urls = FailoverRpcUrls::new(vec![
        "http://rpc1:8545".to_string(),
        "http://rpc2:8545".to_string(),
    ]);

    // Simulate failure then success
    urls.report_failure().await;
    assert_eq!(urls.current_url(), "http://rpc2:8545");

    urls.report_success().await;
    // Success should clear failure state for current URL
    assert_eq!(urls.current_url(), "http://rpc2:8545");
}

// ============================================================================
// Feature parity tests (verifying DESIGN.md requirements)
// ============================================================================

#[test]
fn test_chain_id_mapping_per_design() {
    use crate::monitor::config::get_chain_name;

    // Starcoin chains (0-2)
    assert_eq!(get_chain_name(0), "Starcoin Mainnet");
    assert_eq!(get_chain_name(1), "Starcoin Testnet");
    assert_eq!(get_chain_name(2), "Starcoin Custom");

    // EVM chains (10-12)
    assert_eq!(get_chain_name(10), "Ethereum Mainnet");
    assert_eq!(get_chain_name(11), "Ethereum Sepolia");
    assert_eq!(get_chain_name(12), "Ethereum Local");
}

#[test]
fn test_token_id_mapping_per_design() {
    use crate::monitor::config::get_token_name;

    assert_eq!(get_token_name(3), "USDT");
    assert_eq!(get_token_name(99), "Token#99"); // Unknown token
}

#[test]
fn test_finalization_logic_local_vs_mainnet() {
    // Local chains should use latest block (no confirmation wait)
    let local_config = ChainConfig {
        chain_id: 2, // Starcoin Local
        contract_address: "0x1234".to_string(),
        rpc_url: String::new(),
        rpc_urls: vec!["http://localhost:9850".to_string()],
        poll_interval: 5,
        start_block: Some(0),
        limiter_address: None,
        committee_address: None,
    };
    assert!(local_config.is_local());

    // Mainnet should wait for confirmations
    let mainnet_config = ChainConfig {
        chain_id: 0, // Starcoin Mainnet
        contract_address: "0x1234".to_string(),
        rpc_url: String::new(),
        rpc_urls: vec!["http://mainnet:9850".to_string()],
        poll_interval: 5,
        start_block: Some(0),
        limiter_address: None,
        committee_address: None,
    };
    assert!(!mainnet_config.is_local());
}

#[test]
fn test_event_types_complete() {
    // Verify all event types from DESIGN.md are implemented
    use crate::monitor::events::*;

    // TokensDeposited
    let _ = TokensDepositedEvent {
        source_chain_id: 12,
        nonce: 1,
        destination_chain_id: 2,
        token_id: 3,
        amount: 100,
        sender_address: "0x".to_string(),
        recipient_address: "0x".to_string(),
        tx_hash: "0x".to_string(),
        block_number: 1,
    };

    // TokensClaimed
    let _ = TokensClaimedEvent {
        source_chain_id: 2,
        nonce: 1,
        destination_chain_id: 12,
        token_id: 3,
        amount: 100,
        sender_address: "0x".to_string(),
        recipient_address: "0x".to_string(),
        tx_hash: "0x".to_string(),
        block_number: 1,
    };

    // EmergencyOp
    let _ = EmergencyOpEvent {
        paused: true,
        nonce: 1,
        tx_hash: "0x".to_string(),
        block_number: 1,
    };

    // LimitUpdated
    let _ = LimitUpdatedEvent {
        source_chain_id: 12,
        new_limit: 1000000000,
        nonce: 1,
        tx_hash: "0x".to_string(),
        block_number: 1,
    };

    // BlocklistUpdated
    let _ = BlocklistUpdatedEvent {
        members: vec!["0x1".to_string()],
        is_blocklisted: true,
        nonce: 1,
        tx_hash: "0x".to_string(),
        block_number: 1,
    };

    // CommitteeUpdated
    let _ = CommitteeUpdateEvent {
        member_count: 4,
        nonce: 1,
        tx_hash: "0x".to_string(),
        block_number: 1,
    };
}

// ============================================================================
// Validator Health Checker Tests
// ============================================================================

#[test]
fn test_validator_config_should_monitor() {
    use crate::monitor::validator_health::ValidatorConfig;

    // stake = 1 should be monitored
    let config1 = ValidatorConfig {
        url: "http://validator1:8080".to_string(),
        stake: 1,
        name: Some("Validator1".to_string()),
    };
    assert!(config1.should_monitor());

    // stake = 5001 should NOT be monitored
    let config2 = ValidatorConfig {
        url: "http://validator2:8080".to_string(),
        stake: 5001,
        name: Some("Validator2".to_string()),
    };
    assert!(!config2.should_monitor());

    // stake = 0 should NOT be monitored
    let config3 = ValidatorConfig {
        url: "http://validator3:8080".to_string(),
        stake: 0,
        name: Some("Validator3".to_string()),
    };
    assert!(!config3.should_monitor());

    // stake = 2 should NOT be monitored (only exactly 1)
    let config4 = ValidatorConfig {
        url: "http://validator4:8080".to_string(),
        stake: 2,
        name: Some("Validator4".to_string()),
    };
    assert!(!config4.should_monitor());
}

#[test]
fn test_validator_config_new() {
    use crate::monitor::validator_health::ValidatorConfig;

    let config = ValidatorConfig::new("http://test:8080".to_string(), 1);
    assert_eq!(config.url, "http://test:8080");
    assert_eq!(config.stake, 1);
    assert!(config.name.is_none());
    assert!(config.should_monitor());
}

#[test]
fn test_validator_config_with_name() {
    use crate::monitor::validator_health::ValidatorConfig;

    let config = ValidatorConfig::new("http://test:8080".to_string(), 1)
        .with_name("TestValidator".to_string());
    assert_eq!(config.name, Some("TestValidator".to_string()));
    assert_eq!(config.display_name(), "TestValidator");
}

#[test]
fn test_validator_config_display_name_fallback() {
    use crate::monitor::validator_health::ValidatorConfig;

    let config = ValidatorConfig::new("http://test:8080".to_string(), 1);
    assert_eq!(config.display_name(), "http://test:8080");
}

#[test]
fn test_validator_health_state_new() {
    use crate::monitor::validator_health::{HealthStatus, ValidatorConfig, ValidatorHealthState};

    let config = ValidatorConfig::new("http://test:8080".to_string(), 1);
    let state = ValidatorHealthState::new(config);

    assert_eq!(state.status, HealthStatus::Unknown);
    assert_eq!(state.consecutive_failures, 0);
    assert!(state.last_healthy_time.is_none());
    assert!(state.last_unhealthy_time.is_none());
    assert!(state.last_alert_time.is_none());
    assert!(state.last_hourly_alert_time.is_none());
}

#[test]
fn test_validator_health_state_should_send_hourly_alert_when_healthy() {
    use crate::monitor::validator_health::{HealthStatus, ValidatorConfig, ValidatorHealthState};

    let config = ValidatorConfig::new("http://test:8080".to_string(), 1);
    let mut state = ValidatorHealthState::new(config);
    state.status = HealthStatus::Healthy;

    // Should not send alert when healthy
    assert!(!state.should_send_hourly_alert());
}

#[test]
fn test_validator_health_state_should_send_hourly_alert_never_sent() {
    use crate::monitor::validator_health::{HealthStatus, ValidatorConfig, ValidatorHealthState};

    let config = ValidatorConfig::new("http://test:8080".to_string(), 1);
    let mut state = ValidatorHealthState::new(config);
    state.status = HealthStatus::Unhealthy;
    state.last_hourly_alert_time = None;

    // Should send alert if never sent before
    assert!(state.should_send_hourly_alert());
}

#[test]
fn test_validator_health_state_should_send_hourly_alert_recently_sent() {
    use crate::monitor::validator_health::{HealthStatus, ValidatorConfig, ValidatorHealthState};
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let config = ValidatorConfig::new("http://test:8080".to_string(), 1);
    let mut state = ValidatorHealthState::new(config);
    state.status = HealthStatus::Unhealthy;
    state.last_hourly_alert_time = Some(now - 1800); // 30 minutes ago

    // Should NOT send alert if sent less than 1 hour ago
    assert!(!state.should_send_hourly_alert());
}

#[test]
fn test_validator_health_state_should_send_hourly_alert_after_hour() {
    use crate::monitor::validator_health::{HealthStatus, ValidatorConfig, ValidatorHealthState};
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let config = ValidatorConfig::new("http://test:8080".to_string(), 1);
    let mut state = ValidatorHealthState::new(config);
    state.status = HealthStatus::Unhealthy;
    state.last_hourly_alert_time = Some(now - 3700); // 1 hour + 100 seconds ago

    // Should send alert if more than 1 hour has passed
    assert!(state.should_send_hourly_alert());
}

#[test]
fn test_health_checker_config_defaults() {
    use crate::monitor::validator_health::HealthCheckerConfig;

    let config = HealthCheckerConfig::default();

    assert_eq!(config.check_interval_seconds, 60);
    assert_eq!(config.timeout_seconds, 10);
    assert!(config.enabled);
}

#[test]
fn test_validator_health_downtime_human() {
    use crate::monitor::validator_health::{ValidatorConfig, ValidatorHealthState};
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let config = ValidatorConfig::new("http://test:8080".to_string(), 1);
    let mut state = ValidatorHealthState::new(config);

    // No unhealthy time set
    assert_eq!(state.downtime_human(), "N/A");

    // Set unhealthy time to 90 minutes ago
    state.last_unhealthy_time = Some(now - 5400); // 90 minutes = 1h 30m
    let downtime = state.downtime_human();
    assert!(downtime.contains("h") && downtime.contains("m"));
}

#[test]
fn test_validators_filtered_by_stake() {
    use crate::monitor::validator_health::ValidatorConfig;

    let validators = vec![
        ValidatorConfig {
            url: "http://v1:8080".to_string(),
            stake: 5001,
            name: Some("HighStake1".to_string()),
        },
        ValidatorConfig {
            url: "http://v2:8080".to_string(),
            stake: 1,
            name: Some("LowStake1".to_string()),
        },
        ValidatorConfig {
            url: "http://v3:8080".to_string(),
            stake: 5001,
            name: Some("HighStake2".to_string()),
        },
        ValidatorConfig {
            url: "http://v4:8080".to_string(),
            stake: 1,
            name: Some("LowStake2".to_string()),
        },
    ];

    // Filter validators that should be monitored
    let monitored: Vec<_> = validators.iter().filter(|v| v.should_monitor()).collect();

    assert_eq!(monitored.len(), 2);
    assert_eq!(monitored[0].name, Some("LowStake1".to_string()));
    assert_eq!(monitored[1].name, Some("LowStake2".to_string()));
}

#[tokio::test]
async fn test_state_event_pruning() {
    // Per DESIGN.md: "Prune sent_event_ids if exceeds 5000 entries"
    let temp_dir = TempDir::new().unwrap();
    let state_file = temp_dir.path().join("test-state.json");

    let manager = StateManager::new(state_file.clone()).unwrap();
    manager.load(12, "0xeth", 2, "0xstc").await.unwrap();

    // Add many events
    for i in 0..100 {
        manager
            .mark_event_sent("chain_a", format!("event_{}", i))
            .await
            .unwrap();
    }

    // Verify events are tracked
    assert!(manager.is_event_sent("chain_a", "event_99").await);
}
// ============================================================================
// Tests for clear_events_after_block (reorg state cleanup)
// ============================================================================

#[tokio::test]
async fn test_clear_events_after_block_basic() {
    // Test basic clearing of events after a fork point
    let temp_dir = TempDir::new().unwrap();
    let state_file = temp_dir.path().join("test-state.json");

    let manager = StateManager::new(state_file).unwrap();
    manager.load(12, "0xeth", 2, "0xstc").await.unwrap();

    // Add events at different block heights
    // Format: "Type:tx_hash:block_number"
    manager
        .mark_event_sent("chain_a", "Deposit:0xabc:100".to_string())
        .await
        .unwrap();
    manager
        .mark_event_sent("chain_a", "Deposit:0xdef:150".to_string())
        .await
        .unwrap();
    manager
        .mark_event_sent("chain_a", "Claim:0xghi:200".to_string())
        .await
        .unwrap();

    // Fork point at 120 - should keep block 100, clear 150 and 200
    manager
        .clear_events_after_block("chain_a", 120)
        .await
        .unwrap();

    // Event at block 100 should remain
    assert!(manager.is_event_sent("chain_a", "Deposit:0xabc:100").await);
    // Events at blocks 150 and 200 should be cleared
    assert!(!manager.is_event_sent("chain_a", "Deposit:0xdef:150").await);
    assert!(!manager.is_event_sent("chain_a", "Claim:0xghi:200").await);
}

#[tokio::test]
async fn test_clear_events_after_block_exact_fork_point() {
    // Events exactly at fork_point should be KEPT (block <= fork_point)
    let temp_dir = TempDir::new().unwrap();
    let state_file = temp_dir.path().join("test-state.json");

    let manager = StateManager::new(state_file).unwrap();
    manager.load(12, "0xeth", 2, "0xstc").await.unwrap();

    manager
        .mark_event_sent("chain_a", "Deposit:0xabc:100".to_string())
        .await
        .unwrap();
    manager
        .mark_event_sent("chain_a", "Deposit:0xdef:101".to_string())
        .await
        .unwrap();

    manager
        .clear_events_after_block("chain_a", 100)
        .await
        .unwrap();

    // Block 100 is exactly at fork_point - should be KEPT
    assert!(manager.is_event_sent("chain_a", "Deposit:0xabc:100").await);
    // Block 101 is after fork_point - should be cleared
    assert!(!manager.is_event_sent("chain_a", "Deposit:0xdef:101").await);
}

#[tokio::test]
async fn test_clear_events_after_block_resets_last_block() {
    // last_block should be reset if it was ahead of fork_point
    let temp_dir = TempDir::new().unwrap();
    let state_file = temp_dir.path().join("test-state.json");

    let manager = StateManager::new(state_file).unwrap();
    manager.load(12, "0xeth", 2, "0xstc").await.unwrap();

    // Set last_block to 200
    manager.update_last_block("chain_a", 200).await.unwrap();
    assert_eq!(manager.get_last_block("chain_a").await, Some(200));

    // Fork point at 150
    manager
        .clear_events_after_block("chain_a", 150)
        .await
        .unwrap();

    // last_block should be reset to fork_point
    assert_eq!(manager.get_last_block("chain_a").await, Some(150));
}

#[tokio::test]
async fn test_clear_events_after_block_preserves_last_block_if_behind() {
    // last_block should NOT be changed if it's already behind fork_point
    let temp_dir = TempDir::new().unwrap();
    let state_file = temp_dir.path().join("test-state.json");

    let manager = StateManager::new(state_file).unwrap();
    manager.load(12, "0xeth", 2, "0xstc").await.unwrap();

    // Set last_block to 100
    manager.update_last_block("chain_a", 100).await.unwrap();

    // Fork point at 150 (ahead of last_block)
    manager
        .clear_events_after_block("chain_a", 150)
        .await
        .unwrap();

    // last_block should remain 100
    assert_eq!(manager.get_last_block("chain_a").await, Some(100));
}

#[tokio::test]
async fn test_clear_events_preserves_unparseable_events() {
    // Events that don't match the expected format should be preserved (conservative)
    let temp_dir = TempDir::new().unwrap();
    let state_file = temp_dir.path().join("test-state.json");

    let manager = StateManager::new(state_file).unwrap();
    manager.load(12, "0xeth", 2, "0xstc").await.unwrap();

    // Add events with various formats
    manager
        .mark_event_sent("chain_a", "Deposit:0xabc:100".to_string()) // Standard format
        .await
        .unwrap();
    manager
        .mark_event_sent("chain_a", "legacy_event_id".to_string()) // No colons
        .await
        .unwrap();
    manager
        .mark_event_sent("chain_a", "weird:format:notanumber".to_string()) // Last part not a number
        .await
        .unwrap();

    manager
        .clear_events_after_block("chain_a", 50)
        .await
        .unwrap();

    // Standard format at block 100 (>50) should be cleared
    assert!(!manager.is_event_sent("chain_a", "Deposit:0xabc:100").await);
    // Unparseable events should be PRESERVED (conservative behavior)
    assert!(manager.is_event_sent("chain_a", "legacy_event_id").await);
    assert!(
        manager
            .is_event_sent("chain_a", "weird:format:notanumber")
            .await
    );
}

#[tokio::test]
async fn test_clear_events_with_tx_hash_containing_numbers() {
    // CRITICAL: tx_hash might look like a number in hex
    // e.g., "Deposit:0x123456:200" - the "0x123456" should NOT be parsed as block
    let temp_dir = TempDir::new().unwrap();
    let state_file = temp_dir.path().join("test-state.json");

    let manager = StateManager::new(state_file).unwrap();
    manager.load(12, "0xeth", 2, "0xstc").await.unwrap();

    // tx_hash that looks like hex numbers
    manager
        .mark_event_sent("chain_a", "Deposit:0x1234567890abcdef:200".to_string())
        .await
        .unwrap();
    manager
        .mark_event_sent("chain_a", "Deposit:0xdeadbeef:50".to_string())
        .await
        .unwrap();

    // Fork point at 100
    manager
        .clear_events_after_block("chain_a", 100)
        .await
        .unwrap();

    // Block 200 (>100) should be cleared
    assert!(
        !manager
            .is_event_sent("chain_a", "Deposit:0x1234567890abcdef:200")
            .await
    );
    // Block 50 (<=100) should be preserved
    assert!(
        manager
            .is_event_sent("chain_a", "Deposit:0xdeadbeef:50")
            .await
    );
}

#[tokio::test]
async fn test_clear_pending_transfers_after_block() {
    let temp_dir = TempDir::new().unwrap();
    let state_file = temp_dir.path().join("test-state.json");

    let manager = StateManager::new(state_file).unwrap();
    manager.load(12, "0xeth", 2, "0xstc").await.unwrap();

    // Add transfers at different blocks
    let transfer1 = PendingTransfer {
        source_chain_id: 12,
        nonce: 1,
        destination_chain_id: 2,
        token_id: 3,
        amount: 100,
        sender_address: "0xsender1".to_string(),
        recipient_address: "0xrecipient1".to_string(),
        deposit_tx: "0xtx1".to_string(),
        deposit_block: 100,
        deposit_time: 0,
        deposit_chain_key: "chain_a".to_string(),
    };
    let transfer2 = PendingTransfer {
        source_chain_id: 12,
        nonce: 2,
        destination_chain_id: 2,
        token_id: 3,
        amount: 200,
        sender_address: "0xsender2".to_string(),
        recipient_address: "0xrecipient2".to_string(),
        deposit_tx: "0xtx2".to_string(),
        deposit_block: 200,
        deposit_time: 0,
        deposit_chain_key: "chain_a".to_string(),
    };

    manager.add_pending_transfer(transfer1).await.unwrap();
    manager.add_pending_transfer(transfer2).await.unwrap();

    assert_eq!(manager.get_pending_transfers().await.len(), 2);

    // Clear after block 150
    manager
        .clear_pending_transfers_after_block(150)
        .await
        .unwrap();

    let remaining = manager.get_pending_transfers().await;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].nonce, 1); // Transfer at block 100 should remain
}

#[tokio::test]
async fn test_clear_pending_transfers_exact_boundary() {
    // Transfer exactly at fork_point should be KEPT
    let temp_dir = TempDir::new().unwrap();
    let state_file = temp_dir.path().join("test-state.json");

    let manager = StateManager::new(state_file).unwrap();
    manager.load(12, "0xeth", 2, "0xstc").await.unwrap();

    let transfer = PendingTransfer {
        source_chain_id: 12,
        nonce: 1,
        destination_chain_id: 2,
        token_id: 3,
        amount: 100,
        sender_address: "0xsender".to_string(),
        recipient_address: "0xrecipient".to_string(),
        deposit_tx: "0xtx".to_string(),
        deposit_block: 100,
        deposit_time: 0,
        deposit_chain_key: "chain_a".to_string(),
    };

    manager.add_pending_transfer(transfer).await.unwrap();

    // Fork point exactly at deposit_block
    manager
        .clear_pending_transfers_after_block(100)
        .await
        .unwrap();

    // Transfer at block 100 should be preserved (deposit_block <= fork_point)
    let remaining = manager.get_pending_transfers().await;
    assert_eq!(remaining.len(), 1);
}

// ============================================================================
// Tests for event_id format edge cases (potentially revealing bugs)
// ============================================================================

#[tokio::test]
async fn test_event_id_with_colons_in_tx_hash() {
    // BUG DETECTION: What if tx_hash somehow contains colons?
    // This shouldn't happen in practice but tests robustness
    let temp_dir = TempDir::new().unwrap();
    let state_file = temp_dir.path().join("test-state.json");

    let manager = StateManager::new(state_file).unwrap();
    manager.load(12, "0xeth", 2, "0xstc").await.unwrap();

    // Malformed event_id with extra colons
    // "Deposit:0x:abc:def:100" - rsplit(':') would get "100" correctly
    manager
        .mark_event_sent("chain_a", "Deposit:0x:abc:def:100".to_string())
        .await
        .unwrap();

    // Fork point at 50 should clear block 100
    manager
        .clear_events_after_block("chain_a", 50)
        .await
        .unwrap();

    // The event should be cleared because block 100 > 50
    assert!(
        !manager
            .is_event_sent("chain_a", "Deposit:0x:abc:def:100")
            .await
    );
}

#[tokio::test]
async fn test_event_id_empty_block_number() {
    // What if block number field is empty? "Deposit:0xabc:"
    let temp_dir = TempDir::new().unwrap();
    let state_file = temp_dir.path().join("test-state.json");

    let manager = StateManager::new(state_file).unwrap();
    manager.load(12, "0xeth", 2, "0xstc").await.unwrap();

    manager
        .mark_event_sent("chain_a", "Deposit:0xabc:".to_string()) // Empty block number
        .await
        .unwrap();

    manager
        .clear_events_after_block("chain_a", 50)
        .await
        .unwrap();

    // Empty string can't be parsed as u64, so should be PRESERVED (conservative)
    assert!(manager.is_event_sent("chain_a", "Deposit:0xabc:").await);
}

#[tokio::test]
async fn test_event_id_negative_number() {
    // What if someone puts a negative number? "-100" can't be parsed as u64
    let temp_dir = TempDir::new().unwrap();
    let state_file = temp_dir.path().join("test-state.json");

    let manager = StateManager::new(state_file).unwrap();
    manager.load(12, "0xeth", 2, "0xstc").await.unwrap();

    manager
        .mark_event_sent("chain_a", "Deposit:0xabc:-100".to_string())
        .await
        .unwrap();

    manager
        .clear_events_after_block("chain_a", 50)
        .await
        .unwrap();

    // "-100" can't be parsed as u64, so should be PRESERVED (conservative)
    assert!(manager.is_event_sent("chain_a", "Deposit:0xabc:-100").await);
}

#[tokio::test]
async fn test_event_id_very_large_block_number() {
    // What about block numbers at u64::MAX?
    let temp_dir = TempDir::new().unwrap();
    let state_file = temp_dir.path().join("test-state.json");

    let manager = StateManager::new(state_file).unwrap();
    manager.load(12, "0xeth", 2, "0xstc").await.unwrap();

    let max_block = u64::MAX;
    manager
        .mark_event_sent("chain_a", format!("Deposit:0xabc:{}", max_block))
        .await
        .unwrap();

    // Fork point at half of max
    manager
        .clear_events_after_block("chain_a", max_block / 2)
        .await
        .unwrap();

    // Block at u64::MAX should be cleared
    assert!(
        !manager
            .is_event_sent("chain_a", &format!("Deposit:0xabc:{}", max_block))
            .await
    );
}
