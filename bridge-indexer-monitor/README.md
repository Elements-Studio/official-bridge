# Bridge Indexer

A unified multi-chain bridge indexer and monitor that:
- **Indexes** bridge events to PostgreSQL database
- **Monitors** bridge events in real-time with Telegram notifications

## Features

- **Dual-chain indexing**: Starcoin + Ethereum event indexing
- **Real-time monitoring**: Telegram notifications for bridge events
- **Finalized event filtering**: Uses EthSyncer and StarcoinSyncer for safe event processing
- **Paired transfer detection**: Alerts on deposits without matching claims
- **State persistence**: Resume from last processed block
- **Unified binary**: Single executable with modular components

## Quick Start

The easiest way to manage the indexer is through the `scripts/indexer.sh` script.

### Basic Commands

```bash
# Start PostgreSQL database
./scripts/indexer.sh start-db

# Start Starcoin-only indexer (foreground)
./scripts/indexer.sh start-indexer [start_block]

# Start indexer with ETH support (foreground)
./scripts/indexer.sh start-eth [start_block]

# Start indexer with ETH support (background)
./scripts/indexer.sh start-eth-bg [start_block]

# Start indexer with Monitor enabled (NEW)
./scripts/indexer.sh start-with-monitor [monitor_config]

# Clean start: reset DB and start with ETH support (background)
./scripts/indexer.sh clean-start-eth-bg [start_block]

# Check indexer status
./scripts/indexer.sh status

# Stop indexer
./scripts/indexer.sh stop

# Reset database (drop and recreate)
./scripts/indexer.sh reset-db

# View logs
./scripts/indexer.sh logs
./scripts/indexer.sh logs -f  # follow mode
```

### Configuration

The indexer reads configuration from `bridge-config/server-config.yaml`. Key settings:

- `starcoin-bridge-proxy-address`: Starcoin bridge contract address
- `eth-bridge-proxy-address`: Ethereum bridge contract address
- `indexer-db-url`: PostgreSQL connection string

Environment variables can override config file settings:
- `BRIDGE_ADDRESS`: Starcoin bridge address
- `ETH_BRIDGE_ADDRESS`: Ethereum bridge address
- `RPC_URL`: Starcoin RPC endpoint
- `ETH_RPC_URL`: Ethereum RPC endpoint

## Monitor Feature (NEW)

The monitor provides real-time Telegram notifications for bridge events. It **reuses** the same event listening logic as the indexer (EthSyncer/StarcoinSyncer) to avoid code duplication.

### Setup Monitor

1. **Create monitor config file:**

```bash
cp monitor-config.example.yaml monitor-config.yaml
# Edit with your configuration
```

2. **Set Telegram credentials:**

```bash
export TELEGRAM_BOT_TOKEN="your_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"
```

3. **Start indexer with monitor enabled:**

```bash
./bridge-indexer-monitor \
  --monitor-config monitor-config.yaml \
  --eth-rpc-url http://localhost:8545 \
  --eth-bridge-address 0x... \
  --rpc-api-url http://localhost:9850 \
  --bridge-address 0x...
```

### Monitor Configuration

See `monitor-config.example.yaml` for full configuration options:

```yaml
chain_a:
  chain_id: 12  # EVM chain
  contract_address: "0x..."
  rpc_urls: ["http://localhost:8545"]
  
chain_b:
  chain_id: 2  # Starcoin chain
  contract_address: "0x..."
  rpc_urls: ["http://localhost:9850"]

telegram:
  # Environment variable substitution supported with ${VAR_NAME} syntax
  bot_token: "${TELEGRAM_BOT_TOKEN}"
  chat_id: "${TELEGRAM_CHAT_ID}"
  
  # Option 1: Direct list
  emergency_mention_users: ["@username1", "123456789"]
  
  # Option 2: From environment variable (comma-separated)
  # emergency_mention_users: ${TELEGRAM_EMERGENCY_MENTION}

paired_message:
  enabled: true
  alert_threshold_seconds: 3600  # Alert if not claimed within 1h
```

**Environment Variable Substitution:**

The configuration file supports `${VAR_NAME}` syntax to read values from environment variables:
- Any field can use this syntax
- If the environment variable is not set, the placeholder is kept as-is
- Example: `bot_token: ${TELEGRAM_BOT_TOKEN}` will be replaced with the actual token value

**Telegram Auto-Enable:**

Telegram notifications are automatically enabled when both `bot_token` and `chat_id` are provided:
- No need for an `enabled` flag
- If environment variables are not set or empty, notifications are silently skipped
- Set the environment variables and restart the monitor to enable notifications

**Setting Environment Variables:**

```bash
export TELEGRAM_BOT_TOKEN="123456:ABC-DEF"
export TELEGRAM_CHAT_ID="-100123456789"
# For multiple users, comma-separated:
export TELEGRAM_EMERGENCY_MENTION="@user1,123456789,@user2"
```

### Monitor Events

The monitor sends Telegram notifications for:

- **TokensDeposited**: Cross-chain transfer initiated
- **TokensClaimed**: Cross-chain transfer completed
- **EmergencyOperation**: Bridge paused/resumed
- **LimitUpdated**: Rate limit changed
- **BlocklistUpdated**: Committee member blocked/unblocked
- **Unmatched Transfers**: Deposits without matching claims (after threshold)
- **Emergency Pause**: Auto-pause triggered when detecting unauthorized minting

### Emergency Pause

The monitor includes an emergency pause feature that automatically detects potential key compromises:

- **Detection**: If a mint/claim occurs without a corresponding deposit/burn within the detection window, it indicates possible key compromise
- **Action**: Monitor automatically executes pause on both chains via `bridge-cli`
- **Configuration**: Requires pre-signed pause signatures from committee members

**Setup Emergency Pause:**

```bash
# Set environment variable for bridge-cli path
export STARCOIN_BRIDGE_CLI="/path/to/starcoin-bridge-cli"

# Configure in monitor-config.yaml
emergency_pause:
  detection_window_seconds: 300  # Wait 5 minutes before declaring mismatch
  bridge_cli_path: "${STARCOIN_BRIDGE_CLI}"
  bridge_cli_config_path: "./bridge-cli-config.yaml"
  
  # Pre-signed signatures from committee members (generated offline)
  eth_signatures:
    - "0x1234567890abcdef..."
  starcoin_signatures:
    - "0xabcdef1234567890..."
  
  eth_nonce: 0
  starcoin_nonce: 0
```

See [EMERGENCY_PAUSE.md](EMERGENCY_PAUSE.md) for detailed setup instructions.

## Architecture

```
bridge-indexer-monitor (Unified Binary)
├── Indexer Module
│   ├── Starcoin event indexing → PostgreSQL
│   ├── Ethereum event indexing → PostgreSQL
│   └── API server (optional)
│
└── Monitor Module  
    ├── EVM listener (reuses EthSyncer)
    ├── Starcoin listener (reuses finality logic)
    ├── Telegram notifier
    ├── State manager (deduplication)
    └── Paired transfer detector
```

**Key Design Principles:**
- **Code reuse**: Monitor uses existing EthSyncer and finality checking
- **Code separation**: Monitor code lives in `src/monitor/`, completely independent
- **No pollution**: Indexer code remains unchanged, monitor is additive only

## Database Schema

The indexer writes to three main tables:

### `token_transfer`

Tracks the **lifecycle status** of each cross-chain transfer.

| Column | Description |
|--------|-------------|
| chain_id | Source chain ID (2=Starcoin, 12=ETH) |
| nonce | Sequence number for this chain |
| status | Transfer status: `Deposited`, `Approved`, `Claimed` |
| block_height | Block where this status change occurred |
| data_source | Which chain produced this event (`STARCOIN` or `ETH`) |

Primary Key: `(chain_id, nonce, status)`

Each transfer has multiple records tracking its progress:
- `Deposited` - User initiated the cross-chain transfer on source chain
- `Approved` - Bridge committee approved the transfer on destination chain
- `Claimed` - User claimed the tokens on destination chain

### `token_transfer_data`

Stores **detailed deposit information** when a transfer is initiated.

| Column | Description |
|--------|-------------|
| chain_id | Source chain ID |
| nonce | Sequence number |
| sender_address | Address that initiated the transfer |
| recipient_address | Destination address on target chain |
| destination_chain | Target chain ID |
| token_id | Token type identifier |
| amount | Transfer amount |

Primary Key: `(chain_id, nonce)`

This table only contains deposit events (one record per transfer) with full transfer details.

### `governance_actions`

Records bridge governance events like:
- Route limit updates
- Emergency operations
- Validator blocklist changes
- Token registrations

## Data Flow Example

**ETH → Starcoin Transfer:**
```
1. User deposits on ETH
   → token_transfer_data: (chain_id=12, nonce=0, sender=0x..., amount=100)
   → token_transfer: (chain_id=12, nonce=0, status=Deposited, data_source=ETH)

2. Bridge committee approves on Starcoin
   → token_transfer: (chain_id=12, nonce=0, status=Approved, data_source=STARCOIN)

3. User claims on Starcoin
   → token_transfer: (chain_id=12, nonce=0, status=Claimed, data_source=STARCOIN)
```

**Starcoin → ETH Transfer:**
```
1. User deposits on Starcoin
   → token_transfer_data: (chain_id=2, nonce=0, sender=0x..., amount=100)
   → token_transfer: (chain_id=2, nonce=0, status=Deposited, data_source=STARCOIN)

2. Bridge committee approves on Starcoin
   → token_transfer: (chain_id=2, nonce=0, status=Approved, data_source=STARCOIN)

3. User claims on ETH
   → token_transfer: (chain_id=2, nonce=0, status=Claimed, data_source=ETH)
```

## Monitoring

The indexer exposes Prometheus metrics on port 9184 (or next available port).

Check the watermark table for sync progress:
```sql
SELECT * FROM watermarks;
```

## Troubleshooting

**Connection reset errors with ETH RPC:**
- Ensure Anvil/Hardhat node is running
- Check if the RPC endpoint is correct

**Empty tables after running:**
- Verify bridge addresses match your deployment
- Check `./scripts/indexer.sh logs` for errors
- Ensure starting block is before any bridge events

**Database connection issues:**
- Run `./scripts/indexer.sh start-db` to start PostgreSQL
- Check if port 5432 is available
