// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for Move contract loading and transaction building.
//!
//! These tests validate:
//! - Move config file parsing
//! - Move bytecode blob loading and structure
//! - BridgeDeploymentBuilder API
//!
//! For full deployment E2E tests, see `e2e_tests/local_env_tests.rs`.

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};
    use starcoin_vm_types::transaction::Package;
    use std::fs;

    use crate::starcoin_test_utils::{
        BridgeDeploymentBuilder, MoveConfig, DEFAULT_BLOB_PATH as BLOB_PATH,
    };

    /// Test: Load and validate Move config file
    #[test]
    fn test_load_move_config() -> Result<()> {
        let move_config = MoveConfig::load()?;

        // Verify all required fields are present
        assert!(
            !move_config.address.is_empty(),
            "address should not be empty"
        );
        assert!(
            !move_config.private_key.is_empty(),
            "private_key should not be empty"
        );
        assert!(
            !move_config.public_key.is_empty(),
            "public_key should not be empty"
        );

        // Verify address can be parsed
        let address = move_config.address()?;
        assert_eq!(
            format!("0x{}", hex::encode(address.to_vec())).to_lowercase(),
            move_config.address.to_lowercase(),
            "parsed address should match config"
        );

        // Verify public key is valid hex and has reasonable length for secp256k1
        // Acceptable lengths:
        // - 33 bytes: compressed (prefix + X)
        // - 64 bytes: raw X || Y
        // - 65 bytes: full uncompressed (may have various prefix conventions)
        let pubkey_hex = move_config.public_key.trim_start_matches("0x");
        let pubkey_bytes = hex::decode(pubkey_hex)?;
        assert!(
            pubkey_bytes.len() == 33 || pubkey_bytes.len() == 64 || pubkey_bytes.len() == 65,
            "public key should be 33, 64, or 65 bytes, got {}",
            pubkey_bytes.len()
        );

        Ok(())
    }

    /// Test: Load and validate Move bytecode blob structure
    #[test]
    fn test_load_move_blob() -> Result<()> {
        let blob_content = fs::read(BLOB_PATH).context("Failed to read blob file")?;
        assert!(!blob_content.is_empty(), "blob file should not be empty");

        // Parse as BCS-serialized Package
        let package: Package = bcs_ext::from_bytes(&blob_content)
            .context("Failed to deserialize Package from blob")?;

        // Verify minimum module count (Bridge, Committee, Treasury, Limiter, tokens, etc.)
        let module_count = package.modules().len();
        assert!(
            module_count >= 10,
            "expected at least 10 modules, got {}",
            module_count
        );

        // Verify all modules have non-empty bytecode
        for (i, module) in package.modules().iter().enumerate() {
            assert!(
                !module.code().is_empty(),
                "module {} should have non-empty bytecode",
                i
            );
        }

        Ok(())
    }

    /// Test: BridgeDeploymentBuilder API for individual transaction creation
    #[test]
    fn test_builder_api() -> Result<()> {
        let mut builder = BridgeDeploymentBuilder::new()?;

        // Verify builder initialization
        let bridge_addr = builder.bridge_address()?;
        assert!(
            !bridge_addr.to_vec().is_empty(),
            "bridge address should be valid"
        );

        // Test individual transaction building methods
        let deploy = builder.build_deploy_transaction()?;
        assert!(
            !deploy.id().to_vec().is_empty(),
            "deploy transaction should have valid id"
        );

        let init = builder.build_initialize_transaction()?;
        assert!(
            !init.id().to_vec().is_empty(),
            "init transaction should have valid id"
        );

        let register = builder.build_register_committee_transaction("http://test.url")?;
        assert!(
            !register.id().to_vec().is_empty(),
            "register transaction should have valid id"
        );

        let committee = builder.build_create_committee_transaction(bridge_addr, 10000, 5000, 0)?;
        assert!(
            !committee.id().to_vec().is_empty(),
            "committee transaction should have valid id"
        );

        let eth = builder.build_setup_token_transaction("eth")?;
        assert!(
            !eth.id().to_vec().is_empty(),
            "eth token transaction should have valid id"
        );

        let btc = builder.build_setup_token_transaction("btc")?;
        assert!(
            !btc.id().to_vec().is_empty(),
            "btc token transaction should have valid id"
        );

        let usdc = builder.build_setup_token_transaction("usdc")?;
        assert!(
            !usdc.id().to_vec().is_empty(),
            "usdc token transaction should have valid id"
        );

        let usdt = builder.build_setup_token_transaction("usdt")?;
        assert!(
            !usdt.id().to_vec().is_empty(),
            "usdt token transaction should have valid id"
        );

        Ok(())
    }
}
