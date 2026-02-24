# End-to-End (E2E) Tests

This directory contains self-contained E2E tests for the Starcoin Bridge.

## Overview

The E2E tests run **fully embedded** environments - they automatically:
1. Start an embedded Starcoin dev node
2. Start an Anvil (Ethereum) node
3. Deploy all bridge contracts to both chains
4. Start bridge server(s)
5. Run the tests
6. Clean up everything

**No external setup required** - just run `cargo test`.

## Test Suites

### `test_single_validator_e2e_suite`
- Single validator mode (1-of-1 threshold)
- Tests governance operations (blocklist, pause/unpause, limit update)
- Tests cross-chain roundtrip (ETH → Starcoin → ETH)

### `test_three_validator_e2e_suite`
- Three validator mode (2-of-3 quorum)
- Uses `BridgeAuthorityAggregator` to collect multi-signatures
- Same test coverage as single validator suite

## Prerequisites

### 1. Pre-compiled Move Blob (Required)

The embedded Starcoin node loads bridge contracts from a pre-compiled `.blob` file:
```
contracts/move/embeded-node-constant-blob/Stc-Bridge-Move.v0.0.1.blob
```

**Why pre-compile?** The embedded node cannot compile Move code at runtime. The blob contains serialized bytecode that gets deployed to the dev chain's genesis block.

**If you modify Move contracts**, rebuild the blob:
```bash
export MPM_PATH=/path/to/mpm   # Starcoin Move Package Manager
cd contracts/move
./build_embedded_blob.sh
```

The build script:
1. Reads bridge address from `embeded-node-constant-blob/config.json`
2. Updates `Move.toml` with the address
3. Runs `mpm release` to compile and package
4. Copies the blob to `embeded-node-constant-blob/`
5. Restores `Move.toml`

### 2. Install Foundry (for Anvil + Forge)

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

Verify installation:
```bash
anvil --version   # Should print version
forge --version   # Should print version
```

### 3. Ensure Solidity Contracts Are Present

The tests need Solidity contracts in `contracts/` directory:
```
contracts/
├── foundry.toml
├── src/
│   ├── BridgeCommittee.sol
│   ├── BridgeLimiter.sol
│   ├── StarcoinBridge.sol
│   └── ...
└── lib/
    └── ... (forge dependencies)
```

If `contracts/lib/` is missing, run:
```bash
cd contracts && forge install
```

### 4. Starcoin Dev Node Dependencies

The embedded Starcoin node is built into the test binary. No separate installation needed.

## Running Tests

```bash
# Run single validator suite (~2 minutes)
cargo test --package starcoin-bridge test_single_validator_e2e_suite -- --nocapture

# Run three validator suite (~2.5 minutes)
cargo test --package starcoin-bridge test_three_validator_e2e_suite -- --nocapture

# Run both suites (sequentially)
cargo test --package starcoin-bridge e2e_suite -- --nocapture
```

### Using the Helper Script

```bash
# Run all E2E tests with proper environment
./scripts/run_e2e_tests.sh
```

## Test Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Test Process                             │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ Embedded        │  │ Anvil           │  │ Bridge          │ │
│  │ Starcoin Node   │  │ (ETH Node)      │  │ Server(s)       │ │
│  │ (dev mode)      │  │                 │  │ (1 or 3)        │ │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘ │
│           │                    │                    │          │
│           ▼                    ▼                    ▼          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    BridgeTestEnv                          │  │
│  │  - Manages lifecycle of all components                    │  │
│  │  - Provides RPC URLs and contract addresses               │  │
│  │  - Auto-cleanup on drop                                   │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## File Structure

```
e2e_tests/
├── README.md              # This file
├── mod.rs                 # Module exports
├── local_env_tests.rs     # Main E2E test suites
├── anvil_test_utils.rs    # Anvil/ETH test helpers
└── long_flow_harness.rs   # Cross-chain flow utilities
```

## Key Components

### `BridgeTestEnv`
Central test environment holder:
- `starcoin: Option<StarcoinBridgeTestEnv>` - Embedded Starcoin node
- `anvil: Option<EthTestEnv>` - Anvil Ethereum node
- `eth_contracts: Option<DeployedEthContracts>` - Deployed contract addresses
- `bridge_servers: Vec<BridgeServerHandle>` - Running bridge servers

### `BridgeAuthorityAggregator`
Used in three-validator mode to automatically collect signatures from multiple bridge servers until quorum is reached.

## Test Phases

### Phase 1: Environment Setup (~40s)
1. Start embedded Starcoin dev node
2. Start Anvil with auto-mining
3. Deploy ETH bridge contracts via `forge script`
4. Verify both chains are operational

### Phase 2: Bridge Server(s) (~3s)
1. Generate authority keypairs
2. Create bridge node configs
3. Start bridge server(s)
4. Wait for health checks

### Phase 3: Governance Tests (~10s)
1. Blocklist update (add address to blocklist)
2. Emergency pause (pause bridge)
3. Emergency unpause (unpause bridge)
4. Limit update (change transfer limits)

### Phase 4: Cross-Chain Roundtrip (~60s)
1. Mint test USDT on ETH
2. Deposit ETH → Starcoin
3. Wait for bridge to credit Starcoin
4. Withdraw Starcoin → ETH
5. Verify final balances

## Troubleshooting

### "forge: command not found"
Install Foundry: `curl -L https://foundry.paradigm.xyz | bash && foundryup`

### "Failed to start Anvil"
Check if port 8545 is in use: `lsof -i :8545`
Kill any existing Anvil: `pkill -f anvil`

### "Starcoin RPC not ready"
The embedded node takes ~20-30s to start. Tests automatically wait.

### "Insufficient stake amount" (three-validator)
Ensure the `BridgeAuthorityAggregator` is collecting signatures from multiple servers. The 2-of-3 quorum requires at least 2 signatures.

### Test timeout
- Single validator: ~2 minutes expected
- Three validator: ~2.5 minutes expected
- If timeout, check for hung forge/anvil processes

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `STARCOIN_BRIDGE_E2E_TMP_ROOT` | Temp directory for test artifacts | System temp dir |
| `RUST_LOG` | Log level (e.g., `info,starcoin_bridge=debug`) | - |

## Development Notes

- Tests use dynamic ports to avoid conflicts
- Each test suite creates isolated environments
- Temporary files are cleaned up automatically
- Authority keys are generated fresh each run

