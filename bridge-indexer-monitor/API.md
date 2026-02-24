# Bridge Indexer API

## Overview

Bridge Indexer provides a REST API for querying cross-chain transfer data. The API offers:

1. **Transfer List** - Query all cross-chain transfers for an account (with filtering and pagination)
2. **Transfer Details** - Query complete information for a specific transfer (including status history)

## Starting the API Server

### Command Line Options

```bash
# Specify API server bind address (if provided, API server will be started)
--api-address 0.0.0.0:8080
```

### Network Type Auto-Detection

The indexer automatically detects the network type by querying the Starcoin RPC for chain ID:

- **Local networks** (chain ID 253, 254, or unknown): All transactions are immediately marked as finalized
- **Testnet** (chain ID 2, 251, 252): Transactions need confirmation before being marked as finalized
- **Mainnet** (chain ID 1): Transactions need confirmation before being marked as finalized

### Startup Examples

```bash
# Local development (auto-detects as local network)
cargo run --bin bridge-indexer-monitor -- \
  --api-address 0.0.0.0:8080 \
  --database-url postgres://postgres:postgrespw@localhost:5432/bridge \
  --rpc-api-url http://localhost:9850 \
  --bridge-address 0xefa1e687a64f869193f109f75d0432be

# Without API server (omit --api-address)
cargo run --bin bridge-indexer-monitor -- \
  --database-url postgres://postgres:postgrespw@localhost:5432/bridge \
  --rpc-api-url http://localhost:9850 \
  --bridge-address 0xefa1e687a64f869193f109f75d0432be
```

## API Endpoints

### 1. Health Check

```
GET /health
```

**Response Example:**
```json
{
  "status": "ok",
  "service": "bridge-indexer-api"
}
```

### 2. Estimate Fees

```
GET /estimate_fees
```

Returns the last gas consumption for deposit/approval/claim operations. Returns 0 for each field if no data exists.

**Response Example:**
```json
{
  "deposit_gas": 21000,
  "approval_gas": 50000,
  "claim_gas": 100000
}
```

**Initial/Empty State Response:**
```json
{
  "deposit_gas": 0,
  "approval_gas": 0,
  "claim_gas": 0
}
```

**Usage Example:**
```bash
curl "http://localhost:8080/estimate_fees"
```

### 3. Transfer List

```
GET /transfers?address=<address>&chain_id=<chain_id>&status=<status>&finalized_only=<bool>&page=<page>&page_size=<page_size>
```

**Query Parameters:**
- `address` (optional): Filter by sender address (hex, with or without 0x prefix)
- `chain_id` (optional): Filter by source chain ID
- `status` (optional): Filter by status (`deposited`, `approved`, `claimed`)
- `finalized_only` (optional): Only return finalized transfers
- `page` (optional): Page number, starting from 1 (default: 1)
- `page_size` (optional): Items per page, max 100 (default: 20)

**Response Example:**
```json
{
  "transfers": [
    {
      "chain_id": 2,
      "nonce": 1,
      "status": "deposited",
      "block_height": 12345,
      "timestamp_ms": 1704988800000,
      "txn_hash": "0x1234...",
      "sender_address": "0xabcd...",
      "is_finalized": true,
      "data_source": "STARCOIN"
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total_count": 42,
    "total_pages": 3
  }
}
```

**Usage Examples:**
```bash
# Query all transfers for an address
curl "http://localhost:8080/transfers?address=0x1234567890abcdef"

# Query completed transfers for an address
curl "http://localhost:8080/transfers?address=0x1234567890abcdef&status=claimed"

# Query only finalized transfers
curl "http://localhost:8080/transfers?address=0x1234567890abcdef&finalized_only=true"

# Paginated query
curl "http://localhost:8080/transfers?page=2&page_size=10"
```

### 3. Transfer Details

```
GET /transfers/:chain_id/:nonce
```

**Path Parameters:**
- `chain_id`: Source chain ID
- `nonce`: Transfer sequence number

**Response Example:**
```json
{
  "transfer": {
    "chain_id": 2,
    "nonce": 1,
    "status": "claimed",
    "block_height": 12350,
    "timestamp_ms": 1704988900000,
    "txn_hash": "0x5678...",
    "sender_address": "0xabcd...",
    "is_finalized": true,
    "data_source": "STARCOIN",
    "gas_usage": 100000,
    "transfer_data": {
      "destination_chain": 12,
      "recipient_address": "0x9876...",
      "token_id": 1,
      "amount": 1000000000
    },
    "status_history": [
      {
        "status": "deposited",
        "block_height": 12345,
        "timestamp_ms": 1704988800000,
        "txn_hash": "0x1234...",
        "data_source": "STARCOIN"
      },
      {
        "status": "approved",
        "block_height": 12348,
        "timestamp_ms": 1704988850000,
        "txn_hash": "0x3456...",
        "data_source": "STARCOIN"
      },
      {
        "status": "claimed",
        "block_height": 12350,
        "timestamp_ms": 1704988900000,
        "txn_hash": "0x5678...",
        "data_source": "ETH"
      }
    ]
  }
}
```

**Usage Example:**
```bash
# Query transfer details
curl "http://localhost:8080/transfers/2/1"
```

## Data Field Reference

### TransferStatus
- `deposited`: Deposited (cross-chain transfer initiated)
- `approved`: Approved (validator signatures collected)
- `claimed`: Claimed (tokens claimed on destination chain)

### DataSource
- `STARCOIN`: Events from Starcoin chain
- `ETH`: Events from Ethereum chain

### is_finalized
- `true`: Transaction is confirmed and will not be rolled back
- `false`: Transaction is not yet confirmed, may be rolled back

Based on auto-detected network type:
- Local networks: Always `true` (immediate finality)
- Testnet/Mainnet: `false` until block confirmation

## Error Responses

All API errors return a unified format:

```json
{
  "error": "error_code",
  "message": "Detailed error message"
}
```

Common error codes:
- `bad_request` (400): Invalid request parameters
- `not_found` (404): Resource not found
- `internal_error` (500): Server internal error

## Frontend Integration Example

### JavaScript/TypeScript

```typescript
interface Transfer {
  chain_id: number;
  nonce: number;
  status: 'deposited' | 'approved' | 'claimed';
  block_height: number;
  timestamp_ms: number;
  txn_hash: string;
  sender_address: string;
  is_finalized: boolean;
  data_source: 'STARCOIN' | 'ETH';
}

// Get user's cross-chain transfer list
async function getUserTransfers(address: string): Promise<Transfer[]> {
  const response = await fetch(
    `http://localhost:8080/transfers?address=${address}&finalized_only=true`
  );
  const data = await response.json();
  return data.transfers;
}

// Get transfer details
async function getTransferDetail(chainId: number, nonce: number) {
  const response = await fetch(
    `http://localhost:8080/transfers/${chainId}/${nonce}`
  );
  const data = await response.json();
  return data.transfer;
}
```

## Performance Tips

1. **Use pagination**: Avoid loading large amounts of data at once
2. **Add filters**: Use `status` and `finalized_only` to reduce response size
3. **Cache results**: For finalized transfers, frontend can cache results
4. **Batch queries**: Use list endpoint instead of multiple detail calls

## Database Indexes

For optimal API performance, the following indexes are recommended (defined in schema):

```sql
-- Primary key index (auto-created)
PRIMARY KEY (chain_id, nonce, status)

-- Sender query index
CREATE INDEX idx_token_transfer_sender ON token_transfer(txn_sender);

-- Block height and timestamp ordering index
CREATE INDEX idx_token_transfer_block_time ON token_transfer(block_height DESC, timestamp_ms DESC);

-- Finalized status index
CREATE INDEX idx_token_transfer_finalized ON token_transfer(is_finalized) WHERE is_finalized = true;
```
