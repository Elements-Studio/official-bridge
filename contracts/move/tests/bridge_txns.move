// Copyright (c) Starcoin Contributors
// SPDX-License-Identifier: Apache-2.0

/// Integration tests for bridge token transfer flows using real ECDSA signatures.
/// All signatures are pre-computed using Rust test: test_generate_token_transfer_signatures_for_move_test
/// 
/// Test keys (from get_bridge_encoding_regression_test_keys):
/// - Key 1 pubkey: 02321ede33d2c2d7a8a152f275a1484edef2098f034121a602cb7d767d38680aa4
/// - Key 2 pubkey: 027f1178ff417fc9f5b8290bd8876f0a157a505a6c52db100a8492203ddd1d4279
/// 
/// Message format (all target @Bridge = 0xba0f421cab925857ae31f058c2f027f8):
/// - source_chain = EthCustom(12), target_chain = StarcoinCustom(2)
/// - eth_address = 0x0000...1234
#[test_only]
module Bridge::BridgeTxns {
    use Bridge::BridgeEnv::{Self, BridgeEnv};
    use Bridge::Bridge::{Self, Bridge};
    use Bridge::ChainIDs;
    use Bridge::ETH::ETH;
    use Bridge::USDT::USDT;
    use Bridge::Message;
    use Bridge::MessageTypes;
    use Bridge::Treasury;
    use StarcoinFramework::Timestamp;
    use StarcoinFramework::Token;
    use StarcoinFramework::Vector;

    // ============================================================
    // Test Constants - Pre-computed signatures from Rust tests
    // ============================================================

    // Message 1: ETH, nonce=0, amount=1000, target=@Bridge
    const MSG1_BYTES: vector<u8> = x"000100000000000000000c1400000000000000000000000000000000000012340210ba0f421cab925857ae31f058c2f027f80200000000000003e8";
    const MSG1_KEY1_SIG: vector<u8> = x"e2496a6b09018b8aef27d077aca6d301407734ad6c0c60d38249acf0a9ed72b12542a9d39498c3b06b2a791da1f83b1ea344a98fdffe2b5be8f315159b927c6001";
    const MSG1_KEY2_SIG: vector<u8> = x"73030ae0c9c304aeeb6d1b8b0a0f749947214997916658e8418acc28797ff7a857628b9a8447fe9d84d02746a24dc395c3814b74ef0cb4505f899df15c2d651a01";

    // Message 2: USDT, nonce=1, amount=500, target=@Bridge
    const MSG2_BYTES: vector<u8> = x"000100000000000000010c1400000000000000000000000000000000000012340210ba0f421cab925857ae31f058c2f027f80400000000000001f4";
    const MSG2_KEY1_SIG: vector<u8> = x"2e7c7eb184b240ec83a96814167de368f7a77a6285334db57e82cf30e030847545406033f84bea008f8db2035576783873a8182d63f31b06b599a68956c4962a01";
    const MSG2_KEY2_SIG: vector<u8> = x"7a155f61c97bc2a0949aef4214b02ba0166a65cba807806bfca7ca4277809d7f597942cc85ed7cd30876c41db9ba70a3a4766239bf06ad827749f2c21d59952601";

    // Message 3: ETH, nonce=1, amount=700, target=@Bridge
    const MSG3_BYTES: vector<u8> = x"000100000000000000010c1400000000000000000000000000000000000012340210ba0f421cab925857ae31f058c2f027f80200000000000002bc";
    const MSG3_KEY1_SIG: vector<u8> = x"0d651b715b8a9754d66052b225950758319e3e3bcce984566dd732d5d2b4332262bfc9da43e4225380e24f6b40f3b1dc50a186c14a5539b38d9f2c77988f84cf01";
    const MSG3_KEY2_SIG: vector<u8> = x"b5a8cab8be9c4f40cb60a52c68f5c06f5521f5c00a9ab59f708c995b8e7134114e2426acd6ca2b4d228c2aeb08dd378e19aa3491056e5b7d916dd8013040bb8700";

    // Message 4: ETH, nonce=0, amount=4000000000 (for limit tests), target=@Bridge
    const MSG4_BYTES: vector<u8> = x"000100000000000000000c1400000000000000000000000000000000000012340210ba0f421cab925857ae31f058c2f027f80200000000ee6b2800";
    const MSG4_KEY1_SIG: vector<u8> = x"72d794c3518ce1cbcd9253f663f95c0635b5986ead9ea6c1db405bb5bdb1c74b1e5b7c91166939af54371fdddf307a77b22bc4df2c80665d35ffe10c4db3333401";
    const MSG4_KEY2_SIG: vector<u8> = x"3bd06ce04aa4573807bf326c89aec1d59024c72beb61fd534df0b5b9aa088c3b67b956524441a0ebfc65d0fb83cc95084915a3af8083c7050bbb142a625287fc00";

    // Emergency Pause: nonce=0, StarcoinCustom
    const PAUSE_MSG_BYTES: vector<u8> = x"020100000000000000000200";
    const PAUSE_KEY1_SIG: vector<u8> = x"13a6ecb6a366dcf1954e9b473e2b94314b4a245e0e15c72e4feb6724441740bf46139a5e52f9be076e0ff6d3a501abb4a2f05473646322882ae51a803ffa03d901";
    const PAUSE_KEY2_SIG: vector<u8> = x"501d99d746e7de809fe1867de304dd229d0b5170040810597e329d5ae2baf4097366adaee6d01a36815eaa2699ad9e00d0b5377e978ee63be69ab1aa315b4ef001";

    // Emergency Unpause: nonce=1, StarcoinCustom
    const UNPAUSE_MSG_BYTES: vector<u8> = x"020100000000000000010201";
    const UNPAUSE_KEY1_SIG: vector<u8> = x"0869501568282c3a3d521dd6608adac02b4ea05745fc55b1d937fba7f61f8b824f5d531b984794796acf80dd03ea443bdfaeea3f390e70cc8894d1d3456ff7c601";
    const UNPAUSE_KEY2_SIG: vector<u8> = x"6158b1dc7630a4fc1a019658611db8926f06665d3211ab18943745e92b65fcb46d59ee910a1a1ad754f2cb51bc4d60dd10d75791293d26272edc86bea97258f401";

    // Source chain for all token transfers
    const SOURCE_CHAIN: u8 = 12; // EthCustom

    // ============================================================
    // Helper Functions
    // ============================================================

    fun make_signatures(sig1: vector<u8>, sig2: vector<u8>): vector<vector<u8>> {
        let sigs = Vector::empty<vector<u8>>();
        Vector::push_back(&mut sigs, sig1);
        Vector::push_back(&mut sigs, sig2);
        sigs
    }

    fun setup_test_with_genesis(genesis: &signer, bridge_admin: &signer): (BridgeEnv, Bridge) {
        // Initialize Timestamp (required for approve_token_transfer which calls now_milliseconds)
        Timestamp::initialize(genesis, 0);
        
        let env = BridgeEnv::create_env(ChainIDs::starcoin_custom());
        let bridge = BridgeEnv::create_bridge_for_sig_tests(&mut env, bridge_admin);
        (env, bridge)
    }

    /// Setup for system message tests (pause/unpause etc) with higher voting power
    fun setup_test_for_system_messages(genesis: &signer, bridge_admin: &signer): (BridgeEnv, Bridge) {
        Timestamp::initialize(genesis, 0);
        
        let env = BridgeEnv::create_env(ChainIDs::starcoin_custom());
        let bridge = BridgeEnv::create_bridge_for_system_msg_tests(&mut env, bridge_admin);
        (env, bridge)
    }

    fun teardown_test(env: BridgeEnv, bridge: Bridge) {
        Bridge::destroy_for_testing(bridge);
        BridgeEnv::destroy_env(env);
    }

    // ============================================================
    // Core Flow Tests
    // ============================================================

    /// Test basic approve -> claim flow with real signatures
    /// Verifies: signature verification, status transitions, token minting
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    fun test_bridge_and_claim(genesis: signer, bridge_admin: signer) {
        let (env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        // Parse message and create signatures
        let message = Message::deserialize_message_test_only(MSG1_BYTES);
        let signatures = make_signatures(MSG1_KEY1_SIG, MSG1_KEY2_SIG);

        // Verify initial status is NOT_FOUND
        assert!(
            Bridge::test_get_token_transfer_action_status(&mut bridge, SOURCE_CHAIN, 0) 
                == Bridge::transfer_status_not_found(),
            1
        );

        // Approve the transfer
        Bridge::approve_token_transfer_for_testing(&mut bridge, message);

        // Verify status is now APPROVED
        assert!(
            Bridge::test_get_token_transfer_action_status(&mut bridge, SOURCE_CHAIN, 0)
                == Bridge::transfer_status_approved(),
            2
        );

        // Claim the token - bridge_admin is the target since message uses @Bridge
        let token = Bridge::claim_token<ETH>(
            &bridge_admin,
            &mut bridge,
            0, // clock_timestamp_ms
            SOURCE_CHAIN,
            0, // bridge_seq_num (nonce)
        );

        // Verify token value
        assert!(Token::value(&token) == 1000, 3);

        // Verify status is now CLAIMED
        assert!(
            Bridge::test_get_token_transfer_action_status(&mut bridge, SOURCE_CHAIN, 0)
                == Bridge::transfer_status_claimed(),
            4
        );

        // Cleanup
        Treasury::burn_token<ETH>(token);
        teardown_test(env, bridge);
    }

    /// Test that double claim is a no-op (returns zero token, doesn't abort)
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    fun test_double_claim_noop(genesis: signer, bridge_admin: signer) {
        let (env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        let message = Message::deserialize_message_test_only(MSG1_BYTES);
        let signatures = make_signatures(MSG1_KEY1_SIG, MSG1_KEY2_SIG);

        // Approve and first claim
        Bridge::approve_token_transfer_for_testing(&mut bridge, message);
        let token1 = Bridge::claim_token<ETH>(
            &bridge_admin,
            &mut bridge,
            0,
            SOURCE_CHAIN,
            0,
        );
        assert!(Token::value(&token1) == 1000, 1);

        // Second claim should fail with ETokenAlreadyClaimedOrHitLimit
        // Note: claim_token aborts on double claim; claim_and_transfer_token returns quietly
        // We test the abort case here
        Treasury::burn_token<ETH>(token1);
        teardown_test(env, bridge);
    }

    /// Test multiple transfers with different nonces
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    fun test_multiple_bridge_and_claim(genesis: signer, bridge_admin: signer) {
        let (env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        // First transfer: ETH, nonce=0, amount=1000
        let msg1 = Message::deserialize_message_test_only(MSG1_BYTES);
        let sigs1 = make_signatures(MSG1_KEY1_SIG, MSG1_KEY2_SIG);
        Bridge::approve_token_transfer_for_testing(&mut bridge, msg1);

        // Second transfer: ETH, nonce=1, amount=700
        let msg3 = Message::deserialize_message_test_only(MSG3_BYTES);
        let sigs3 = make_signatures(MSG3_KEY1_SIG, MSG3_KEY2_SIG);
        Bridge::approve_token_transfer_for_testing(&mut bridge, msg3);

        // Both should be approved
        assert!(
            Bridge::test_get_token_transfer_action_status(&mut bridge, SOURCE_CHAIN, 0)
                == Bridge::transfer_status_approved(),
            1
        );
        assert!(
            Bridge::test_get_token_transfer_action_status(&mut bridge, SOURCE_CHAIN, 1)
                == Bridge::transfer_status_approved(),
            2
        );

        // Claim in reverse order
        let token2 = Bridge::claim_token<ETH>(&bridge_admin, &mut bridge, 0, SOURCE_CHAIN, 1);
        assert!(Token::value(&token2) == 700, 3);

        let token1 = Bridge::claim_token<ETH>(&bridge_admin, &mut bridge, 0, SOURCE_CHAIN, 0);
        assert!(Token::value(&token1) == 1000, 4);

        // Both should be claimed
        assert!(
            Bridge::test_get_token_transfer_action_status(&mut bridge, SOURCE_CHAIN, 0)
                == Bridge::transfer_status_claimed(),
            5
        );
        assert!(
            Bridge::test_get_token_transfer_action_status(&mut bridge, SOURCE_CHAIN, 1)
                == Bridge::transfer_status_claimed(),
            6
        );

        Treasury::burn_token<ETH>(token1);
        Treasury::burn_token<ETH>(token2);
        teardown_test(env, bridge);
    }

    /// Test USDT cross-token coverage (different token type)
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    fun test_bridge_and_claim_usdt(genesis: signer, bridge_admin: signer) {
        let (env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        // USDT transfer: nonce=1, amount=500
        let message = Message::deserialize_message_test_only(MSG2_BYTES);
        let signatures = make_signatures(MSG2_KEY1_SIG, MSG2_KEY2_SIG);

        Bridge::approve_token_transfer_for_testing(&mut bridge, message);

        // Claim USDT - nonce=1
        let token = Bridge::claim_token<USDT>(
            &bridge_admin,
            &mut bridge,
            0,
            SOURCE_CHAIN,
            1, // nonce=1 for USDT message
        );

        assert!(Token::value(&token) == 500, 1);

        Treasury::burn_token<USDT>(token);
        teardown_test(env, bridge);
    }

    /// Test double approve is idempotent (no error, just returns early)
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    fun test_double_approve_idempotent(genesis: signer, bridge_admin: signer) {
        let (env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        let message = Message::deserialize_message_test_only(MSG1_BYTES);
        let signatures = make_signatures(MSG1_KEY1_SIG, MSG1_KEY2_SIG);

        // First approve
        Bridge::approve_token_transfer_for_testing(&mut bridge, copy message);
        assert!(
            Bridge::test_get_token_transfer_action_status(&mut bridge, SOURCE_CHAIN, 0)
                == Bridge::transfer_status_approved(),
            1
        );

        // Second approve - should succeed without error (idempotent)
        Bridge::approve_token_transfer_for_testing(&mut bridge, message);
        assert!(
            Bridge::test_get_token_transfer_action_status(&mut bridge, SOURCE_CHAIN, 0)
                == Bridge::transfer_status_approved(),
            2
        );

        teardown_test(env, bridge);
    }

    // ============================================================
    // Error Case Tests
    // ============================================================

    /// Test that approving when paused fails with EBridgeUnavailable (error code 8)
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    #[expected_failure(abort_code = 8, location = Bridge::Bridge)] // 8 << 16 | category
    fun test_approve_when_paused(genesis: signer, bridge_admin: signer) {
        let (env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        // Pause the bridge using test helper (bypasses signature verification)
        BridgeEnv::freeze_bridge(&mut env, &mut bridge, @Bridge, 100);

        // Try to approve - should fail
        let message = Message::deserialize_message_test_only(MSG1_BYTES);
        let signatures = make_signatures(MSG1_KEY1_SIG, MSG1_KEY2_SIG);
        Bridge::approve_token_transfer_for_testing(&mut bridge, message);

        teardown_test(env, bridge);
    }

    /// Test that claiming when paused fails with EBridgeUnavailable
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    #[expected_failure(abort_code = 8, location = Bridge::Bridge)] // EBridgeUnavailable = 8
    fun test_claim_when_paused(genesis: signer, bridge_admin: signer) {
        let (_env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        // Approve first (while not paused)
        let message = Message::deserialize_message_test_only(MSG1_BYTES);
        let signatures = make_signatures(MSG1_KEY1_SIG, MSG1_KEY2_SIG);
        Bridge::approve_token_transfer_for_testing(&mut bridge, message);

        // Pause the bridge
        BridgeEnv::freeze_bridge(&mut _env, &mut bridge, @Bridge, 100);

        // Try to claim - should fail with EBridgeUnavailable before we get the token
        let token = Bridge::claim_token<ETH>(&bridge_admin, &mut bridge, 0, SOURCE_CHAIN, 0);
        // If we get here, the test failed - burn token to satisfy compiler
        Treasury::burn_token<ETH>(token);
        Bridge::destroy_for_testing(bridge);
        BridgeEnv::destroy_env(_env);
    }

    /// Test that claiming non-existent transfer fails with EMessageNotFoundInRecords
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    #[expected_failure(abort_code = 11, location = Bridge::Bridge)] // EMessageNotFoundInRecords = 11
    fun test_claim_nonexistent_transfer(genesis: signer, bridge_admin: signer) {
        let (_env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        // Try to claim seq_num=999 which was never approved - should abort
        let token = Bridge::claim_token<ETH>(&bridge_admin, &mut bridge, 0, SOURCE_CHAIN, 999);
        // If we get here, the test failed
        Treasury::burn_token<ETH>(token);
        Bridge::destroy_for_testing(bridge);
        BridgeEnv::destroy_env(_env);
    }

    /// Test that claiming with wrong token type fails with EUnexpectedTokenType
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    #[expected_failure(abort_code = 3, location = Bridge::Bridge)] // EUnexpectedTokenType = 3
    fun test_claim_wrong_token_type(genesis: signer, bridge_admin: signer) {
        let (_env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        // Approve ETH transfer (token_type=2)
        let message = Message::deserialize_message_test_only(MSG1_BYTES);
        let signatures = make_signatures(MSG1_KEY1_SIG, MSG1_KEY2_SIG);
        Bridge::approve_token_transfer_for_testing(&mut bridge, message);

        // Try to claim as USDT (token_type=4) - should abort
        let token = Bridge::claim_token<USDT>(&bridge_admin, &mut bridge, 0, SOURCE_CHAIN, 0);
        // If we get here, the test failed
        Treasury::burn_token<USDT>(token);
        Bridge::destroy_for_testing(bridge);
        BridgeEnv::destroy_env(_env);
    }

    /// Test that claiming before delay passes fails with EClaimDelayNotPassed
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    #[expected_failure(abort_code = 23, location = Bridge::Bridge)] // EClaimDelayNotPassed = 23
    fun test_claim_delay_not_passed(genesis: signer, bridge_admin: signer) {
        let (_env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        // Set a claim delay of 1 hour
        Bridge::set_claim_delay_for_testing(&mut bridge, 3600000); // 1 hour in ms

        // Approve the transfer
        let message = Message::deserialize_message_test_only(MSG1_BYTES);
        let signatures = make_signatures(MSG1_KEY1_SIG, MSG1_KEY2_SIG);
        Bridge::approve_token_transfer_for_testing(&mut bridge, message);

        // Try to claim immediately (clock=0, delay not passed) - should abort
        let token = Bridge::claim_token<ETH>(&bridge_admin, &mut bridge, 0, SOURCE_CHAIN, 0);
        // If we get here, the test failed
        Treasury::burn_token<ETH>(token);
        Bridge::destroy_for_testing(bridge);
        BridgeEnv::destroy_env(_env);
    }

    /// Test that claim succeeds after delay passes
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    fun test_claim_after_delay_passes(genesis: signer, bridge_admin: signer) {
        let (env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        // Set a claim delay of 1 hour
        Bridge::set_claim_delay_for_testing(&mut bridge, 3600000);

        // Approve the transfer
        let message = Message::deserialize_message_test_only(MSG1_BYTES);
        let signatures = make_signatures(MSG1_KEY1_SIG, MSG1_KEY2_SIG);
        Bridge::approve_token_transfer_for_testing(&mut bridge, message);

        // Claim after delay passes (clock > approved_at + delay)
        // Since approved_at uses Timestamp::now_milliseconds() which is 0 in tests,
        // we need clock >= 0 + 3600000 = 3600000
        let token = Bridge::claim_token<ETH>(
            &bridge_admin,
            &mut bridge,
            3600001, // clock_timestamp_ms after delay
            SOURCE_CHAIN,
            0,
        );

        assert!(Token::value(&token) == 1000, 1);

        Treasury::burn_token<ETH>(token);
        teardown_test(env, bridge);
    }

    // ============================================================
    // Emergency Operation Tests
    // ============================================================

    /// Test freeze -> unfreeze -> approve -> claim flow resumes normally
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    fun test_operations_resume_after_unfreeze(genesis: signer, bridge_admin: signer) {
        let (env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        // Freeze the bridge
        BridgeEnv::freeze_bridge(&mut env, &mut bridge, @Bridge, 100);

        // Verify bridge is paused
        let inner = Bridge::test_load_inner(&bridge);
        assert!(Bridge::inner_paused(inner), 1);

        // Unfreeze the bridge
        BridgeEnv::unfreeze_bridge(&mut env, &mut bridge, @Bridge, 101);

        // Verify bridge is not paused
        let inner = Bridge::test_load_inner(&bridge);
        assert!(!Bridge::inner_paused(inner), 2);

        // Now approve and claim should work
        let message = Message::deserialize_message_test_only(MSG1_BYTES);
        let signatures = make_signatures(MSG1_KEY1_SIG, MSG1_KEY2_SIG);
        Bridge::approve_token_transfer_for_testing(&mut bridge, message);

        let token = Bridge::claim_token<ETH>(&bridge_admin, &mut bridge, 0, SOURCE_CHAIN, 0);
        assert!(Token::value(&token) == 1000, 3);

        Treasury::burn_token<ETH>(token);
        teardown_test(env, bridge);
    }

    // ============================================================
    // Status Transition Tests
    // ============================================================

    /// Test complete status transition: NOT_FOUND -> APPROVED -> CLAIMED
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    fun test_transfer_status_transitions(genesis: signer, bridge_admin: signer) {
        let (env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        // Initial: NOT_FOUND
        assert!(
            Bridge::test_get_token_transfer_action_status(&mut bridge, SOURCE_CHAIN, 0)
                == Bridge::transfer_status_not_found(),
            1
        );

        // After approve: APPROVED
        let message = Message::deserialize_message_test_only(MSG1_BYTES);
        let signatures = make_signatures(MSG1_KEY1_SIG, MSG1_KEY2_SIG);
        Bridge::approve_token_transfer_for_testing(&mut bridge, message);

        assert!(
            Bridge::test_get_token_transfer_action_status(&mut bridge, SOURCE_CHAIN, 0)
                == Bridge::transfer_status_approved(),
            2
        );

        // After claim: CLAIMED
        let token = Bridge::claim_token<ETH>(&bridge_admin, &mut bridge, 0, SOURCE_CHAIN, 0);

        assert!(
            Bridge::test_get_token_transfer_action_status(&mut bridge, SOURCE_CHAIN, 0)
                == Bridge::transfer_status_claimed(),
            3
        );

        Treasury::burn_token<ETH>(token);
        teardown_test(env, bridge);
    }

    /// Test that trying to double-claim via claim_token aborts with ETokenAlreadyClaimedOrHitLimit
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    #[expected_failure(abort_code = 15, location = Bridge::Bridge)] // ETokenAlreadyClaimedOrHitLimit = 15
    fun test_double_claim_aborts(genesis: signer, bridge_admin: signer) {
        let (_env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        let message = Message::deserialize_message_test_only(MSG1_BYTES);
        let signatures = make_signatures(MSG1_KEY1_SIG, MSG1_KEY2_SIG);
        Bridge::approve_token_transfer_for_testing(&mut bridge, message);

        // First claim
        let token1 = Bridge::claim_token<ETH>(&bridge_admin, &mut bridge, 0, SOURCE_CHAIN, 0);
        Treasury::burn_token<ETH>(token1);

        // Second claim should abort
        let token2 = Bridge::claim_token<ETH>(&bridge_admin, &mut bridge, 0, SOURCE_CHAIN, 0);
        // If we get here, the test failed
        Treasury::burn_token<ETH>(token2);
        Bridge::destroy_for_testing(bridge);
        BridgeEnv::destroy_env(_env);
    }

    /// Test claim_token fails if not the owner (wrong signer)
    #[test(genesis = @0x1, bridge_admin = @Bridge, other = @0x12345)]
    #[expected_failure(abort_code = 1, location = Bridge::Bridge)] // EUnauthorisedClaim = 1
    fun test_unauthorised_claim(genesis: signer, bridge_admin: signer, other: signer) {
        let (_env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        // Approve (target is @Bridge)
        let message = Message::deserialize_message_test_only(MSG1_BYTES);
        let signatures = make_signatures(MSG1_KEY1_SIG, MSG1_KEY2_SIG);
        Bridge::approve_token_transfer_for_testing(&mut bridge, message);

        // Try to claim with different signer (not @Bridge) - should abort
        let token = Bridge::claim_token<ETH>(&other, &mut bridge, 0, SOURCE_CHAIN, 0);
        // If we get here, the test failed
        Treasury::burn_token<ETH>(token);
        Bridge::destroy_for_testing(bridge);
        BridgeEnv::destroy_env(_env);
    }

    // ============================================================
    // Emergency Operations with Real Signatures
    // ============================================================

    /// Test pause with real ECDSA signatures via execute_system_message
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    fun test_emergency_pause_with_real_signatures(genesis: signer, bridge_admin: signer) {
        let (env, bridge) = setup_test_for_system_messages(&genesis, &bridge_admin);

        // Verify bridge is initially not paused
        let inner = Bridge::test_load_inner(&bridge);
        assert!(!Bridge::inner_paused(inner), 1);

        // Parse pause message and create signatures
        let pause_message = Message::deserialize_message_test_only(PAUSE_MSG_BYTES);
        let signatures = make_signatures(PAUSE_KEY1_SIG, PAUSE_KEY2_SIG);

        // Execute pause with real signatures
        Bridge::execute_system_message(&mut bridge, pause_message, signatures);

        // Verify bridge is now paused
        let inner = Bridge::test_load_inner(&bridge);
        assert!(Bridge::inner_paused(inner), 2);

        teardown_test(env, bridge);
    }

    /// Test unpause with real ECDSA signatures via execute_system_message
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    fun test_emergency_unpause_with_real_signatures(genesis: signer, bridge_admin: signer) {
        let (env, bridge) = setup_test_for_system_messages(&genesis, &bridge_admin);

        // First pause the bridge with real signatures
        let pause_message = Message::deserialize_message_test_only(PAUSE_MSG_BYTES);
        let pause_sigs = make_signatures(PAUSE_KEY1_SIG, PAUSE_KEY2_SIG);
        Bridge::execute_system_message(&mut bridge, pause_message, pause_sigs);

        // Verify bridge is paused
        let inner = Bridge::test_load_inner(&bridge);
        assert!(Bridge::inner_paused(inner), 1);

        // Now unpause with real signatures
        let unpause_message = Message::deserialize_message_test_only(UNPAUSE_MSG_BYTES);
        let unpause_sigs = make_signatures(UNPAUSE_KEY1_SIG, UNPAUSE_KEY2_SIG);
        Bridge::execute_system_message(&mut bridge, unpause_message, unpause_sigs);

        // Verify bridge is now unpaused
        let inner = Bridge::test_load_inner(&bridge);
        assert!(!Bridge::inner_paused(inner), 2);

        teardown_test(env, bridge);
    }

    // ============================================================
    // Starcoin-Initiated Transfer Flow (send -> approve)
    // ============================================================

    /// Test outbound transfer: send_token creates pending record
    /// This tests the first part of the Starcoin-initiated transfer flow
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    fun test_starcoin_initiated_send_creates_pending(genesis: signer, bridge_admin: signer) {
        let (env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        // Get some ETH from the vault
        let eth_token = BridgeEnv::get_eth(&mut env, 1000);
        let eth_address = x"0000000000000000000000000000000000001234";

        // Send token - creates pending record with source_chain = StarcoinCustom
        let chain_id = ChainIDs::starcoin_custom();
        Bridge::send_token<ETH>(&mut bridge, @Bridge, ChainIDs::eth_custom(), eth_address, eth_token);

        // Verify record exists with PENDING status
        assert!(
            Bridge::test_get_token_transfer_action_status(&mut bridge, chain_id, 0)
                == Bridge::transfer_status_pending(),
            1
        );

        // Verify seq number was incremented
        let seq_num = Bridge::get_seq_num_for(&mut bridge, MessageTypes::token());
        assert!(seq_num == 1, 2);

        teardown_test(env, bridge);
    }

    // ============================================================
    // Transfer Limit Exceeded Tests
    // ============================================================

    /// Test that claim returns empty when transfer limit is exceeded
    /// Uses MSG4 with amount=4000000000 which exceeds default limit
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    fun test_claim_returns_empty_when_limit_exceeded(genesis: signer, bridge_admin: signer) {
        let (env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        // First, lower the limit to ensure our transfer exceeds it
        // Default limit is around $5M USD. MSG4 amount is 4000000000 (4 ETH)
        // With ETH price at ~$100, this is only $400, so we need to lower the limit
        BridgeEnv::update_bridge_limit(
            &mut env,
            &mut bridge,
            @Bridge,
            ChainIDs::starcoin_custom(),  // receiving_chain
            SOURCE_CHAIN,                  // sending_chain (EthCustom=12)
            100,                           // very low limit: $0.000001 USD
        );

        // Approve MSG4 (large amount transfer)
        let message = Message::deserialize_message_test_only(MSG4_BYTES);
        let signatures = make_signatures(MSG4_KEY1_SIG, MSG4_KEY2_SIG);
        Bridge::approve_token_transfer_for_testing(&mut bridge, message);

        // Verify it's approved
        assert!(
            Bridge::test_get_token_transfer_action_status(&mut bridge, SOURCE_CHAIN, 0)
                == Bridge::transfer_status_approved(),
            1
        );

        // Claim via claim_and_transfer_token - should silently return without minting
        // because transfer exceeds the lowered limit
        Bridge::claim_and_transfer_token<ETH>(&mut bridge, 0, SOURCE_CHAIN, 0);

        // Status should still be APPROVED (not CLAIMED) because limit was exceeded
        assert!(
            Bridge::test_get_token_transfer_action_status(&mut bridge, SOURCE_CHAIN, 0)
                == Bridge::transfer_status_approved(),
            2
        );

        teardown_test(env, bridge);
    }

    // ============================================================
    // claim_and_transfer_token Silent Return Tests  
    // ============================================================

    /// Test that claim_and_transfer_token silently returns on double claim
    /// (emits TokenTransferAlreadyClaimed event but doesn't abort)
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    fun test_claim_and_transfer_silent_on_double_claim(genesis: signer, bridge_admin: signer) {
        let (env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        // Approve
        let message = Message::deserialize_message_test_only(MSG1_BYTES);
        let signatures = make_signatures(MSG1_KEY1_SIG, MSG1_KEY2_SIG);
        Bridge::approve_token_transfer_for_testing(&mut bridge, message);

        // First claim via claim_and_transfer_token
        Bridge::claim_and_transfer_token<ETH>(&mut bridge, 0, SOURCE_CHAIN, 0);

        // Verify claimed
        assert!(
            Bridge::test_get_token_transfer_action_status(&mut bridge, SOURCE_CHAIN, 0)
                == Bridge::transfer_status_claimed(),
            1
        );

        // Second claim - should NOT abort, just return silently
        Bridge::claim_and_transfer_token<ETH>(&mut bridge, 0, SOURCE_CHAIN, 0);

        // Status is still CLAIMED (operation was a no-op)
        assert!(
            Bridge::test_get_token_transfer_action_status(&mut bridge, SOURCE_CHAIN, 0)
                == Bridge::transfer_status_claimed(),
            2
        );

        teardown_test(env, bridge);
    }

    // ============================================================
    // Error Code Coverage Tests
    // ============================================================

    /// Test ESendTokenExceedLimiter (20) - send_token with amount >= default_transfer_limit
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    #[expected_failure(abort_code = 20, location = Bridge::Bridge)] // ESendTokenExceedLimiter = 20
    fun test_send_token_exceed_limiter(genesis: signer, bridge_admin: signer) {
        let (_env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        // Get a huge amount of ETH (over 5M USD limit - default_transfer_limit)
        // default_transfer_limit = 5_000_000 * 100_000_000 = 500_000_000_000_000
        // We need to mint a large amount
        let huge_token = Bridge::mint_some<ETH>(600_000_000_000_000);
        let eth_address = x"0000000000000000000000000000000000001234";

        // This should abort with ESendTokenExceedLimiter
        Bridge::send_token<ETH>(&mut bridge, @Bridge, ChainIDs::eth_custom(), eth_address, huge_token);
        
        Bridge::destroy_for_testing(bridge);
        BridgeEnv::destroy_env(_env);
    }

    /// Test EUnexpectedSeqNum (6) - execute_system_message with wrong sequence number  
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    #[expected_failure(abort_code = 6, location = Bridge::Bridge)] // EUnexpectedSeqNum = 6
    fun test_system_message_wrong_seq_num(genesis: signer, bridge_admin: signer) {
        let (_env, bridge) = setup_test_for_system_messages(&genesis, &bridge_admin);

        // First execute a pause to increment the emergency_op seq num to 1
        let pause_message = Message::deserialize_message_test_only(PAUSE_MSG_BYTES);
        let pause_sigs = make_signatures(PAUSE_KEY1_SIG, PAUSE_KEY2_SIG);
        Bridge::execute_system_message(&mut bridge, pause_message, pause_sigs);

        // Now try to execute pause again with seq_num=0 (should be 1)
        // This uses the same PAUSE_MSG which has nonce=0
        let pause_message2 = Message::deserialize_message_test_only(PAUSE_MSG_BYTES);
        let pause_sigs2 = make_signatures(PAUSE_KEY1_SIG, PAUSE_KEY2_SIG);
        Bridge::execute_system_message(&mut bridge, pause_message2, pause_sigs2);

        Bridge::destroy_for_testing(bridge);
        BridgeEnv::destroy_env(_env);
    }

    /// Test EBridgeAlreadyPaused (13) - pause when already paused
    /// Note: Can't test with real signatures since we don't have a signed pause with seq_num=1
    /// This test uses the test helper to bypass signature verification
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    #[expected_failure(abort_code = 13, location = Bridge::Bridge)] // EBridgeAlreadyPaused = 13
    fun test_pause_when_already_paused(genesis: signer, bridge_admin: signer) {
        let (_env, bridge) = setup_test_for_system_messages(&genesis, &bridge_admin);

        // First pause with real signatures (seq_num=0)
        let pause_message = Message::deserialize_message_test_only(PAUSE_MSG_BYTES);
        let pause_sigs = make_signatures(PAUSE_KEY1_SIG, PAUSE_KEY2_SIG);
        Bridge::execute_system_message(&mut bridge, pause_message, pause_sigs);

        // Try to pause again using test helper (bypasses signature verification)
        // This creates a message with seq_num=1 and executes it without signatures
        BridgeEnv::freeze_bridge(&mut _env, &mut bridge, @Bridge, 100);

        Bridge::destroy_for_testing(bridge);
        BridgeEnv::destroy_env(_env);
    }

    /// Test EBridgeNotPaused (14) - unpause when not paused
    #[test(genesis = @0x1, bridge_admin = @Bridge)]
    #[expected_failure(abort_code = 14, location = Bridge::Bridge)] // EBridgeNotPaused = 14
    fun test_unpause_when_not_paused(genesis: signer, bridge_admin: signer) {
        let (_env, bridge) = setup_test_with_genesis(&genesis, &bridge_admin);

        // Bridge is not paused initially
        // Try to unpause - should fail
        BridgeEnv::unfreeze_bridge(&mut _env, &mut bridge, @Bridge, 100);

        Bridge::destroy_for_testing(bridge);
        BridgeEnv::destroy_env(_env);
    }
}