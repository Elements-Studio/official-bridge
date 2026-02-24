// // Copyright (c) Starcoin, Inc.
// // SPDX-License-Identifier: Apache-2.0
//
#[test_only]
#[allow(deprecated_usage)] // TODO: update tests to not use deprecated governance
module Bridge::CommitteeTest {
    use Bridge::ChainIDs;
    use Bridge::Committee;
    use Bridge::Committee::{
        BridgeCommittee, CommitteeMember,
        make_bridge_committee, make_committee_member
    };
    use Bridge::Crypto;
    use Bridge::EcdsaK1;
    use Bridge::Message;
    use StarcoinFramework::SimpleMap::{Self, SimpleMap};
    use StarcoinFramework::Vector;

    // Error constants with category codes (Errors::invalid_state wraps with category 1)
    // Format: (reason << 8) | category, where INVALID_STATE category = 1
    // ESignatureBelowThreshold = 0, Errors::invalid_state(0) = (0 << 8) | 1 = 1
    const ESignatureBelowThresholdWithCategory: u64 = 1;
    // EDuplicatedSignature = 1, Errors::invalid_state(1) = (1 << 8) | 1 = 257
    const EDuplicatedSignatureWithCategory: u64 = 257;
    // EInvalidSignatureLength in EcdsaK1 = 2, Errors::invalid_argument(2) = (2 << 8) | 7 = 519
    const EInvalidSignatureLengthWithCategory: u64 = 519;

    // This is a token transfer message for testing
    const TEST_MSG: vector<u8> =
        x"00010a0000000000000000200000000000000000000000000000000000000000000000000000000000000064012000000000000000000000000000000000000000000000000000000000000000c8033930000000000000";

    // Validator pubkeys matching the Rust test keys in encoding.rs
    // Key 1 private: e42c82337ce12d4a7ad6cd65876d91b2ab6594fd50cdab1737c91773ba7451db
    const VALIDATOR1_PUBKEY: vector<u8> =
        x"02321ede33d2c2d7a8a152f275a1484edef2098f034121a602cb7d767d38680aa4";
    // Key 2 private: 1aacd610da3d0cc691a04b83b01c34c6c65cda0fe8d502df25ff4b3185c85687
    const VALIDATOR2_PUBKEY: vector<u8> =
        x"027f1178ff417fc9f5b8290bd8876f0a157a505a6c52db100a8492203ddd1d4279";

    /// Helper function to convert compressed pubkey to raw 64-byte pubkey (for map key)
    fun compressed_to_raw_pubkey(compressed: vector<u8>): vector<u8> {
        let uncompressed = EcdsaK1::decompress_pubkey(&compressed);
        let raw_pubkey = Vector::empty<u8>();
        let j = 1; // Skip 0x04 prefix
        while (j < 65) {
            Vector::push_back(&mut raw_pubkey, *Vector::borrow(&uncompressed, j));
            j = j + 1;
        };
        raw_pubkey
    }

    public fun active_validator_addresses(): SimpleMap<address, u64> {
        let voting_powers = SimpleMap::create<address, u64>();
        SimpleMap::add(&mut voting_powers, @0xAAAA, 5000);
        SimpleMap::add(&mut voting_powers, @0xBBBB, 5000);
        SimpleMap::add(&mut voting_powers, @0xCCCC, 5000);
        voting_powers
    }

    public fun validator_voting_powers_for_testing(): SimpleMap<address, u64> {
        active_validator_addresses()
    }

    #[test]
    fun test_verify_signatures_good_path() {
        let committee = setup_test();
        let msg = Message::deserialize_message_test_only(TEST_MSG);
        // good path - signatures generated using STARCOIN_BRIDGE_MESSAGE prefix + TEST_MSG
        // Key 1 signature for VALIDATOR1_PUBKEY
        // Key 2 signature for VALIDATOR2_PUBKEY
        Committee::verify_signatures(&committee,
            msg,
            vector[
                x"a448b0bdff960a308e50be98bcc6c1eaf207046dfff124b12a5a1277bef441762e26ef4097811011bf7e2369020fd594fd037be018e7b31842bd5e35f0399e2300",
                x"fc9e1ee2cb5dbd937035d35a8a3c95a2e653328bcb74453498e9f2065bbb4eee051e4c61f1275e4520e2c5d70aa182d4b109d0dcd518b6910bb2e6a0a6d895cc01",
            ],
        );
        // Clean up
        Committee::destroy(committee);
    }

    #[test, expected_failure(abort_code = EDuplicatedSignatureWithCategory, location = Bridge::Committee)]
    fun test_verify_signatures_duplicated_sig() {
        let committee = setup_test();
        let msg = Message::deserialize_message_test_only(TEST_MSG);
        // Duplicated signature should fail
        Committee::verify_signatures(&committee,
            msg,
            vector[
                x"a448b0bdff960a308e50be98bcc6c1eaf207046dfff124b12a5a1277bef441762e26ef4097811011bf7e2369020fd594fd037be018e7b31842bd5e35f0399e2300",
                x"a448b0bdff960a308e50be98bcc6c1eaf207046dfff124b12a5a1277bef441762e26ef4097811011bf7e2369020fd594fd037be018e7b31842bd5e35f0399e2300",
            ],
        );
        abort 1
    }

    #[test, expected_failure(abort_code = EInvalidSignatureLengthWithCategory, location = Bridge::EcdsaK1)]
    fun test_verify_signatures_invalid_signature() {
        let committee = setup_test();
        let msg = Message::deserialize_message_test_only(TEST_MSG);
        // Invalid signature (wrong length) should fail in EcdsaK1
        Committee::verify_signatures(&committee,
            msg,
            vector[b"6ffb3e5ce04dd138611c49520fddfbd6778879c2db4696139f53a487043409536c369c6ffaca165ce3886723cfa8b74f3e043e226e206ea25e313ea2215e6caf01"],
        );
        abort 1
    }

    #[test, expected_failure(abort_code = ESignatureBelowThresholdWithCategory, location = Bridge::Committee)]
    fun test_verify_signatures_below_threshold() {
        let committee = setup_test();
        let msg = Message::deserialize_message_test_only(TEST_MSG);
        // Only one signature when threshold requires more
        Committee::verify_signatures(&committee,
            msg,
            vector[x"a448b0bdff960a308e50be98bcc6c1eaf207046dfff124b12a5a1277bef441762e26ef4097811011bf7e2369020fd594fd037be018e7b31842bd5e35f0399e2300"],
        );
        abort 1
    }


    #[test, expected_failure(abort_code = ESignatureBelowThresholdWithCategory, location = Bridge::Committee)]
    fun test_verify_signatures_with_blocked_committee_member() {
        let committee = setup_test();
        let msg = Message::deserialize_message_test_only(TEST_MSG);

        // good path, this test should have passed in previous test
        Committee::verify_signatures(&committee,
            msg,
            vector[
                x"a448b0bdff960a308e50be98bcc6c1eaf207046dfff124b12a5a1277bef441762e26ef4097811011bf7e2369020fd594fd037be018e7b31842bd5e35f0399e2300",
                x"fc9e1ee2cb5dbd937035d35a8a3c95a2e653328bcb74453498e9f2065bbb4eee051e4c61f1275e4520e2c5d70aa182d4b109d0dcd518b6910bb2e6a0a6d895cc01",
            ],
        );

        let (validator1, member) = SimpleMap::borrow_index(Committee::members(&committee), 0);
        assert!(!Committee::blocklisted(member), 0);

        // Block a member
        let blocklist = Message::create_blocklist_message(
            ChainIDs::starcoin_testnet(),
            0,
            0, // type 0 is block
            vector[Crypto::ecdsa_pub_key_to_eth_address(validator1)],
        );
        let blocklist = Message::extract_blocklist_payload(&blocklist);
        Committee::execute_blocklist_for_testing(&mut committee, blocklist);

        let (_, blocked_member) = SimpleMap::borrow_index(Committee::members(&committee), 0);
        assert!(Committee::blocklisted(blocked_member), 1);

        // Verify signature should fail now
        Committee::verify_signatures(
            &committee,
            msg,
            vector[
                x"a448b0bdff960a308e50be98bcc6c1eaf207046dfff124b12a5a1277bef441762e26ef4097811011bf7e2369020fd594fd037be018e7b31842bd5e35f0399e2300",
                x"fc9e1ee2cb5dbd937035d35a8a3c95a2e653328bcb74453498e9f2065bbb4eee051e4c61f1275e4520e2c5d70aa182d4b109d0dcd518b6910bb2e6a0a6d895cc01",
            ],
        );

        // Clean up
        Committee::destroy(committee);
    }

    #[test, expected_failure(abort_code = Bridge::Committee::EValidatorBlocklistContainsUnknownKey)]
    fun test_execute_blocklist_abort_upon_unknown_validator() {
        let committee = setup_test();

        // val0 and val1 are not blocked yet
        let (validator0, member0) =
            SimpleMap::borrow_index(Committee::members(&committee), 0);
        assert!(!Committee::blocklisted(member0), 0);
        let (_validator1, member1) =
            SimpleMap::borrow_index(Committee::members(&committee), 1);
        assert!(!Committee::blocklisted(member1), 0);

        let eth_address0 = Crypto::ecdsa_pub_key_to_eth_address(validator0);
        let invalid_eth_address1 = x"0000000000000000000000000000000000000000";

        // Blocklist both
        let blocklist = Message::create_blocklist_message(
            ChainIDs::starcoin_testnet(),
            0, // seq
            0, // type 0 is blocklist
            vector[eth_address0, invalid_eth_address1],
        );
        let blocklist = Message::extract_blocklist_payload(&blocklist);
        Committee::execute_blocklist_for_testing(&mut committee, blocklist);

        // Clean up
        Committee::destroy(committee);
    }

    //
    #[test]
    fun test_execute_blocklist() {
        let committee = setup_test();

        // val0 and val1 are not blocked yet
        let (validator0, member0) = SimpleMap::borrow_index(Committee::members(&committee), 0);
        assert!(!Committee::blocklisted(member0), 0);
        let (validator1, member1) = SimpleMap::borrow_index(Committee::members(&committee), 1);
        assert!(!Committee::blocklisted(member1), 1);

        let eth_address0 = Crypto::ecdsa_pub_key_to_eth_address(validator0);
        let eth_address1 = Crypto::ecdsa_pub_key_to_eth_address(validator1);

        // Blocklist both
        let blocklist = Message::create_blocklist_message(
            ChainIDs::starcoin_testnet(),
            0, // seq
            0, // type 0 is blocklist
            vector[eth_address0, eth_address1],
        );
        let blocklist = Message::extract_blocklist_payload(&blocklist);
        Committee::execute_blocklist_for_testing(&mut committee, blocklist);

        // Blocklist both reverse order
        let blocklist = Message::create_blocklist_message(
            ChainIDs::starcoin_testnet(),
            0, // seq
            0, // type 0 is blocklist
            vector[eth_address1, eth_address0],
        );
        let blocklist = Message::extract_blocklist_payload(&blocklist);
        Committee::execute_blocklist_for_testing(&mut committee, blocklist);

        // val 0 is blocklisted
        let (_, blocked_member) = SimpleMap::borrow_index(Committee::members(&committee), 0);
        assert!(Committee::blocklisted(blocked_member), 1);
        // val 1 is too
        let (_, blocked_member) = SimpleMap::borrow_index(Committee::members(&committee), 1);
        assert!(Committee::blocklisted(blocked_member), 1);

        // unblocklist val1
        let blocklist = Message::create_blocklist_message(
            ChainIDs::starcoin_testnet(),
            1, // seq, this is supposed to increment, but we don't test it here
            1, // type 1 is unblocklist
            vector[eth_address1],
        );
        let blocklist = Message::extract_blocklist_payload(&blocklist);
        Committee::execute_blocklist_for_testing(&mut committee, blocklist);

        // val 0 is still blocklisted
        let (_, blocked_member) = SimpleMap::borrow_index(Committee::members(&committee), 0);
        assert!(Committee::blocklisted(blocked_member), 0);
        // val 1 is not
        let (_, blocked_member) = SimpleMap::borrow_index(Committee::members(&committee), 1);
        assert!(!Committee::blocklisted(blocked_member), 0);

        // Clean up
        Committee::destroy(committee);
    }

    fun setup_test(): BridgeCommittee {
        let members = SimpleMap::create<vector<u8>, CommitteeMember>();

        // Use raw 64-byte pubkey as map key (matches what ecdsa_recover returns)
        // Each validator has voting_power = 1, so two validators (total 2) meet token threshold (2)
        let bridge_pubkey_bytes = VALIDATOR1_PUBKEY;
        let raw_pubkey1 = compressed_to_raw_pubkey(bridge_pubkey_bytes);
        SimpleMap::add(&mut members,
            raw_pubkey1,
            make_committee_member(
                bridge_pubkey_bytes,
                1,
                b"https://127.0.0.1:9191",
                false,
            ),
        );

        let bridge_pubkey_bytes = VALIDATOR2_PUBKEY;
        let raw_pubkey2 = compressed_to_raw_pubkey(bridge_pubkey_bytes);
        SimpleMap::add(
            &mut members,
            raw_pubkey2,
            make_committee_member(
                bridge_pubkey_bytes,
                1,
                b"https://127.0.0.1:9192",
                false,
            ),
        );
        make_bridge_committee(members)
    }
}