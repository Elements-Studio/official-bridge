// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Bridge event definitions

use serde::{Deserialize, Serialize};

/// Event types for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BridgeEvent {
    TokensDeposited(TokensDepositedEvent),
    TokensClaimed(TokensClaimedEvent),
    EmergencyOp(EmergencyOpEvent),
    LimitUpdated(LimitUpdatedEvent),
    BlocklistUpdated(BlocklistUpdatedEvent),
    CommitteeUpdated(CommitteeUpdateEvent),
}

impl BridgeEvent {
    /// Generate unique event ID for deduplication
    pub fn event_id(&self) -> String {
        match self {
            BridgeEvent::TokensDeposited(e) => {
                format!("Deposit:{}:{}", e.tx_hash, e.block_number)
            }
            BridgeEvent::TokensClaimed(e) => {
                format!("Claim:{}:{}", e.tx_hash, e.block_number)
            }
            BridgeEvent::EmergencyOp(e) => {
                format!("Emergency:{}:{}", e.tx_hash, e.block_number)
            }
            BridgeEvent::LimitUpdated(e) => {
                format!("Limit:{}:{}", e.tx_hash, e.block_number)
            }
            BridgeEvent::BlocklistUpdated(e) => {
                format!("Blocklist:{}:{}", e.tx_hash, e.block_number)
            }
            BridgeEvent::CommitteeUpdated(e) => {
                format!("Committee:{}:{}", e.tx_hash, e.block_number)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokensDepositedEvent {
    pub source_chain_id: u8,
    pub nonce: u64,
    pub destination_chain_id: u8,
    pub token_id: u8,
    pub amount: u64, // Bridge-adjusted amount (8 decimals)
    pub sender_address: String,
    pub recipient_address: String,
    pub tx_hash: String,
    pub block_number: u64,
}

impl TokensDepositedEvent {
    pub fn amount_human(&self) -> String {
        format!("{:.4}", self.amount as f64 / 1e8)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokensClaimedEvent {
    pub source_chain_id: u8,
    pub nonce: u64,
    pub destination_chain_id: u8,
    pub token_id: u8,
    pub amount: u64, // ERC20/native amount (may have different decimals)
    pub sender_address: String,
    pub recipient_address: String,
    pub tx_hash: String,
    pub block_number: u64,
}

impl TokensClaimedEvent {
    pub fn amount_human(&self) -> String {
        // USDT has 6 decimals on EVM
        let decimals = if self.token_id == 3 { 6 } else { 8 };
        format!("{:.4}", self.amount as f64 / 10f64.powi(decimals))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyOpEvent {
    pub paused: bool,
    pub nonce: u64,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitUpdatedEvent {
    pub source_chain_id: u8,
    pub new_limit: u64, // 8 decimals
    pub nonce: u64,
    pub tx_hash: String,
    pub block_number: u64,
}

impl LimitUpdatedEvent {
    pub fn limit_human(&self) -> String {
        format!("{:.2}", self.new_limit as f64 / 1e8)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistUpdatedEvent {
    pub members: Vec<String>,
    pub is_blocklisted: bool,
    pub nonce: u64,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeUpdateEvent {
    pub member_count: u64,
    pub nonce: u64,
    pub tx_hash: String,
    pub block_number: u64,
}
