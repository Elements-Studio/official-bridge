// // Copyright (c) Starcoin, Inc.
// // SPDX-License-Identifier: Apache-2.0
//

#[test_only]
module Bridge::MessageTests {
    use Bridge::AssetUtil;
    use Bridge::BCSUtil;
    use Bridge::BTC::BTC;
    use Bridge::ChainIDs;
    use Bridge::ETH::ETH;
    use Bridge::EcdsaK1;
    use Bridge::Message::{
        Self,
        blocklist_validator_addresses,
        BridgeMessage,
        create_add_tokens_on_starcoin_message,
        create_blocklist_message,
        create_emergency_op_message,
        create_token_bridge_message,
        create_update_asset_price_message,
        create_update_bridge_limit_message,
        deserialize_message_test_only,
        emergency_op_pause,
        emergency_op_unpause,
        extract_add_tokens_on_starcoin,
        extract_blocklist_payload,
        extract_emergency_op_payload,
        extract_token_bridge_payload,
        extract_update_asset_price,
        extract_update_bridge_limit,
        is_native,
        make_add_token_on_starcoin,
        make_generic_message,
        payload,
        peel_u64_be_for_testing,
        required_voting_power,
        reverse_bytes_test,
        serialize_message,
        set_payload,
        to_parsed_token_transfer_message,
        token_ids,
        token_prices,
        token_type_names,
        update_asset_price_payload_new_price, update_asset_price_payload_token_id, update_bridge_limit_payload_limit,
        update_bridge_limit_payload_receiving_chain, update_bridge_limit_payload_sending_chain
    };
    use Bridge::Treasury::{Self, token_id};
    use Bridge::USDC::USDC;
    use Bridge::USDT;
    use StarcoinFramework::Account;
    use StarcoinFramework::BCS;
    use StarcoinFramework::Debug;
    use StarcoinFramework::STC::STC;
    use StarcoinFramework::Token;
    use StarcoinFramework::Vector;

    const INVALID_CHAIN: u8 = 42;

    #[test(bridge = @Bridge)]
    fun test_message_serialization_starcoin_to_eth(bridge: signer) {
        let sender_address = @0x64;
        Account::create_account_with_address<STC>(@Bridge);
        Account::set_auto_accept_token(&bridge, true);
        let token = AssetUtil::quick_mint_for_test<USDT::USDT>(&bridge, 12345);

        let token_bridge_message = default_token_bridge_message(
            sender_address,
            &token,
            ChainIDs::starcoin_testnet(),
            ChainIDs::eth_sepolia(),
        );

        // Test payload extraction
        let token_payload = Message::make_payload(
            BCS::to_bytes(&sender_address),
            ChainIDs::eth_sepolia(),
            x"00000000000000000000000000000000000000c8",
            3u8,
            (Token::value(&token) as u64),
        );

        let payload = Message::extract_token_bridge_payload(&token_bridge_message);
        assert!(Message::token_target_chain(&payload) == Message::token_target_chain(&token_payload), 1);
        assert!(Message::token_target_address(&payload) == Message::token_target_address(&token_payload), 2);
        assert!(Message::token_type(&payload) == Message::token_type(&payload), 3);
        assert!(Message::token_amount(&payload) == Message::token_amount(&payload), 4);
        assert!(payload == token_payload, 5);

        // Test message serialization
        let message = Message::serialize_message(token_bridge_message);
        // msg type 0, version 1, seq 10 (0a), source 1(stc_testnet), sender_len 16, sender addr
        // target 11(eth_sepolia), target_len 20, target addr, token_type 3, amount 12345
        let expected_msg = x"0001000000000000000a0110000000000000000000000000000000640b1400000000000000000000000000000000000000c8030000000000003039";
        assert!(message == expected_msg, 6);
        assert!(token_bridge_message == Message::deserialize_message_test_only(message), 7);

        Account::deposit_with_metadata(@Bridge, token, Vector::empty<u8>());
    }


    #[test(bridge = @Bridge)]
    fun test_message_serialization_eth_to_starcoin(bridge: &signer) {
        Account::create_account_with_address<STC>(@Bridge);
        Account::set_auto_accept_token(bridge, true);

        let address_1 = @0x64;
        let token = AssetUtil::quick_mint_for_test<USDT::USDT>(bridge, 12345);

        let token_bridge_message = create_token_bridge_message(
            ChainIDs::eth_sepolia(), // source chain
            10, // seq_num
            // Eth address is 20 bytes long
            x"00000000000000000000000000000000000000c8", // eth sender address
            ChainIDs::starcoin_testnet(), // target_chain
            BCS::to_bytes(&address_1), // target address
            3u8, // token_type
            (Token::value(&token) as u64), // amount: u64
        );

        // Test payload extraction
        let token_payload = Message::make_payload(
            x"00000000000000000000000000000000000000c8",
            ChainIDs::starcoin_testnet(),
            BCS::to_bytes(&address_1),
            3u8,
            (Token::value(&token) as u64),
        );
        assert!(Message::extract_token_bridge_payload(&token_bridge_message) == token_payload, 1);

        // Test message serialization
        let message = serialize_message(token_bridge_message);
        // msg type 0, version 1, seq 10 (0a), source 11 (0b=eth_sepolia)
        // sender_len 20 (0x14), sender addr (eth), target 1(stc_testnet), target_len 16 (0x10), target addr, token_type 3, amount 12345
        let expected_msg =
            x"0001000000000000000a0b1400000000000000000000000000000000000000c8011000000000000000000000000000000064030000000000003039";
        assert!(message == expected_msg, 2);
        assert!(Message::deserialize_message_test_only(message) == token_bridge_message, 3);

        Account::deposit(@Bridge, token);
    }


    #[test]
    fun test_emergency_op_message_serialization() {
        let emergency_op_message = create_emergency_op_message(
            ChainIDs::starcoin_testnet(), // source chain
            10, // seq_num
            emergency_op_pause(),
        );

        // Test message serialization
        let message = serialize_message(emergency_op_message);
        let expected_msg = x"0201000000000000000a0100";

        assert!(message == expected_msg, 1);
        assert!(emergency_op_message == deserialize_message_test_only(message), 2);
    }

    // Do not change/remove this test, it uses move bytes generated by Rust
    #[test]
    fun test_emergency_op_message_serialization_regression() {
        let emergency_op_message = create_emergency_op_message(
            ChainIDs::starcoin_custom(),
            55, // seq_num
            emergency_op_pause(),
        );

        // Test message serialization
        let message = serialize_message(emergency_op_message);
        let expected_msg = x"020100000000000000370200";

        assert!(expected_msg == message, 1);
        assert!(emergency_op_message == deserialize_message_test_only(message), 2);
    }

    #[test]
    fun test_blocklist_message_serialization() {
        let validator_pub_key1 = x"b14d3c4f5fbfbcfb98af2d330000d49c95b93aa7";
        let validator_pub_key2 = x"f7e93cc543d97af6632c9b8864417379dba4bf15";

        let validator_eth_addresses = vector[validator_pub_key1, validator_pub_key2];
        let blocklist_message = create_blocklist_message(
            ChainIDs::starcoin_testnet(), // source chain
            10, // seq_num
            0,
            validator_eth_addresses,
        );
        // Test message serialization
        let message = serialize_message(blocklist_message);

        let expected_msg =
            x"0101000000000000000a010002b14d3c4f5fbfbcfb98af2d330000d49c95b93aa7f7e93cc543d97af6632c9b8864417379dba4bf15";

        assert!(message == expected_msg, 1);
        assert!(blocklist_message == deserialize_message_test_only(message), 2);

        let blocklist = extract_blocklist_payload(&blocklist_message);
        assert!(*blocklist_validator_addresses(&blocklist) == validator_eth_addresses, 3)
    }

    // Do not change/remove this test, it uses move bytes generated by Rust
    #[test]
    fun test_blocklist_message_serialization_regression() {
        let validator_eth_addr_1 = x"68b43fd906c0b8f024a18c56e06744f7c6157c65";
        let validator_eth_addr_2 = x"acaef39832cb995c4e049437a3e2ec6a7bad1ab5";
        // Test 1
        let validator_eth_addresses = vector[validator_eth_addr_1];
        let blocklist_message = create_blocklist_message(
            ChainIDs::starcoin_custom(), // source chain
            129, // seq_num
            0, // blocklist
            validator_eth_addresses,
        );
        // Test message serialization
        let message = serialize_message(blocklist_message);

        let expected_msg = x"0101000000000000008102000168b43fd906c0b8f024a18c56e06744f7c6157c65";

        assert!(expected_msg == message, 1);
        assert!(blocklist_message == deserialize_message_test_only(message), 2);

        let blocklist = extract_blocklist_payload(&blocklist_message);
        assert!(*blocklist_validator_addresses(&blocklist) == validator_eth_addresses, 3);

        // Test 2
        let validator_eth_addresses = vector[validator_eth_addr_1, validator_eth_addr_2];
        let blocklist_message = create_blocklist_message(
            ChainIDs::starcoin_custom(), // source chain
            68, // seq_num
            1, // unblocklist
            validator_eth_addresses,
        );
        // Test message serialization
        let message = serialize_message(blocklist_message);

        let expected_msg =
            x"0101000000000000004402010268b43fd906c0b8f024a18c56e06744f7c6157c65acaef39832cb995c4e049437a3e2ec6a7bad1ab5";

        assert!(expected_msg == message, 1);
        assert!(blocklist_message == deserialize_message_test_only(message), 2);

        let blocklist = extract_blocklist_payload(&blocklist_message);
        assert!(*blocklist_validator_addresses(&blocklist) == validator_eth_addresses, 3)
    }

    #[test]
    fun test_update_bridge_limit_message_serialization() {
        let update_bridge_limit = create_update_bridge_limit_message(
            ChainIDs::starcoin_testnet(), // source chain
            10, // seq_num
            ChainIDs::eth_sepolia(),
            1000000000,
        );

        // Test message serialization
        let message = serialize_message(update_bridge_limit);
        let expected_msg = x"0301000000000000000a010b000000003b9aca00";

        assert!(message == expected_msg, 1);
        assert!(update_bridge_limit == deserialize_message_test_only(message), 2);

        let bridge_limit = extract_update_bridge_limit(&update_bridge_limit);
        assert!(
            update_bridge_limit_payload_receiving_chain(&bridge_limit) == ChainIDs::starcoin_testnet(),
            3,
        );
        assert!(
            update_bridge_limit_payload_sending_chain(&bridge_limit)
                == ChainIDs::eth_sepolia(),
            4,
        );
        assert!(update_bridge_limit_payload_limit(&bridge_limit) == 1000000000, 5);
    }

    // Do not change/remove this test, it uses move bytes generated by Rust
    #[test]
    fun test_update_bridge_limit_message_serialization_regression() {
        let update_bridge_limit = create_update_bridge_limit_message(
            ChainIDs::starcoin_custom(), // source chain
            15, // seq_num
            ChainIDs::eth_custom(),
            10_000_000_000, // 1M USD
        );

        // Test message serialization
        let message = serialize_message(update_bridge_limit);
        // msg type 3 (update_bridge_limit), version 1, seq 15 (0f), source 2(stc_custom = receiving_chain)
        // payload: sending_chain 12 (0c = eth_custom), limit 10_000_000_000 (0x2540be400)
        let expected_msg = x"0301000000000000000f020c00000002540be400";

        assert!(message == expected_msg, 1);
        assert!(update_bridge_limit == deserialize_message_test_only(message), 2);

        let bridge_limit = extract_update_bridge_limit(&update_bridge_limit);
        assert!(
            update_bridge_limit_payload_receiving_chain(&bridge_limit)
                == ChainIDs::starcoin_custom(),
            3
        );
        assert!(
            update_bridge_limit_payload_sending_chain(&bridge_limit)
                == ChainIDs::eth_custom(),
            4
        );
        assert!(update_bridge_limit_payload_limit(&bridge_limit) == 10_000_000_000, 5);
    }


    #[test]
    fun test_update_asset_price_message_serialization() {
        let asset_price_message = create_update_asset_price_message(
            2,
            ChainIDs::starcoin_testnet(), // source chain
            10, // seq_num
            12345,
        );

        // Test message serialization
        let message = serialize_message(asset_price_message);
        let expected_msg = x"0401000000000000000a01020000000000003039";
        assert!(message == expected_msg, 1);
        assert!(asset_price_message == deserialize_message_test_only(message), 2);

        let asset_price = extract_update_asset_price(&asset_price_message);
        let treasury = Treasury::mock_for_test();

        assert!(
            Message::update_asset_price_payload_token_id(&asset_price) == Treasury::token_id<ETH>(&treasury),
            3,
        );
        assert!(update_asset_price_payload_new_price(&asset_price) == 12345, 4);

        Treasury::destroy(treasury);
    }

    // Do not change/remove this test, it uses move bytes generated by Rust
    #[test]
    fun test_update_asset_price_message_serialization_regression() {
        let treasury = Treasury::mock_for_test();

        let asset_price_message = create_update_asset_price_message(
            Treasury::token_id<BTC>(&treasury),
            ChainIDs::starcoin_custom(), // source chain
            266, // seq_num
            1_000_000_000, // $100k USD
        );

        // Test message serialization
        let message = serialize_message(asset_price_message);
        let expected_msg = x"0401000000000000010a0201000000003b9aca00";
        assert!(expected_msg == message, 1);
        assert!(asset_price_message == deserialize_message_test_only(message), 2);

        let asset_price = extract_update_asset_price(&asset_price_message);
        assert!(update_asset_price_payload_token_id(&asset_price) == Treasury::token_id<BTC>(&treasury), 3);
        assert!(update_asset_price_payload_new_price(&asset_price) == 1_000_000_000, 4);

        Treasury::destroy(treasury);
    }

    #[test]
    fun test_add_tokens_on_starcoin_message_serialization() {
        let treasury = Treasury::mock_for_test();

        let add_tokens_on_starcoin_message = create_add_tokens_on_starcoin_message(
            ChainIDs::starcoin_custom(),
            1, // seq_num
            false, // native_token
            vector[Treasury::token_id<BTC>(&treasury), Treasury::token_id<ETH>(&treasury)],
            vector[
                b"28ac483b6f2b62dd58abdf0bbc3f86900d86bbdc710c704ba0b33b7f1c4b43c8::btc::BTC",
                b"0xbd69a54e7c754a332804f325307c6627c06631dc41037239707e3242bc542e99::eth::ETH",
            ],
            vector[100, 100],
        );
        let payload = Message::extract_add_tokens_on_starcoin(&add_tokens_on_starcoin_message);
        assert!(is_native(&payload) == false, 1);
        assert!(
            token_ids(&payload) == vector[Treasury::token_id<BTC>(&treasury), Treasury::token_id<ETH>(&treasury)],
            2
        );
        assert!(
            token_type_names(&payload) ==
                vector[
                    b"28ac483b6f2b62dd58abdf0bbc3f86900d86bbdc710c704ba0b33b7f1c4b43c8::btc::BTC",
                    b"0xbd69a54e7c754a332804f325307c6627c06631dc41037239707e3242bc542e99::eth::ETH",
                ],
            3
        );
        assert!(token_prices(&payload) == vector[100, 100], 4);
        assert!(
            payload == make_add_token_on_starcoin(
                false,
                vector[Treasury::token_id<BTC>(&treasury), Treasury::token_id<ETH>(&treasury)],
                vector[
                    b"28ac483b6f2b62dd58abdf0bbc3f86900d86bbdc710c704ba0b33b7f1c4b43c8::btc::BTC",
                    b"0xbd69a54e7c754a332804f325307c6627c06631dc41037239707e3242bc542e99::eth::ETH",
                ],
                vector[100, 100],
            ),
            4
        );
        // Test message serialization
        let message = serialize_message(add_tokens_on_starcoin_message);
        let expected_msg =
            x"060100000000000000010200020102024a323861633438336236663262363264643538616264663062626333663836393030643836626264633731306337303462613062333362376631633462343363383a3a6274633a3a4254434c3078626436396135346537633735346133333238303466333235333037633636323763303636333164633431303337323339373037653332343262633534326539393a3a6574683a3a4554480264000000000000006400000000000000";
        assert!(message == expected_msg, 1);
        assert!(add_tokens_on_starcoin_message == deserialize_message_test_only(message), 2);

        Treasury::destroy(treasury);
    }

    #[test]
    fun test_add_tokens_on_starcoin_message_serialization_2() {
        let treasury = Treasury::mock_for_test();

        let add_tokens_on_starcoin_message = create_add_tokens_on_starcoin_message(
            ChainIDs::starcoin_custom(),
            0, // seq_num
            false, // native_token
            vector[1, 2, 3, 4],
            vector[
                b"9b5e13bcd0cb23ff25c07698e89d48056c745338d8c9dbd033a4172b87027073::btc::BTC",
                b"7970d71c03573f540a7157f0d3970e117effa6ae16cefd50b45c749670b24e6a::eth::ETH",
                b"500e429a24478405d5130222b20f8570a746b6bc22423f14b4d4e6a8ea580736::usdc::USDC",
                b"46bfe51da1bd9511919a92eb1154149b36c0f4212121808e13e3e5857d607a9c::usdt::USDT",
            ],
            vector[500_000_000, 30_000_000, 1_000, 1_000],
        );
        let payload = extract_add_tokens_on_starcoin(&add_tokens_on_starcoin_message);
        assert!(
            payload == make_add_token_on_starcoin(
                false,
                vector[1, 2, 3, 4],
                vector[
                    b"9b5e13bcd0cb23ff25c07698e89d48056c745338d8c9dbd033a4172b87027073::btc::BTC",
                    b"7970d71c03573f540a7157f0d3970e117effa6ae16cefd50b45c749670b24e6a::eth::ETH",
                    b"500e429a24478405d5130222b20f8570a746b6bc22423f14b4d4e6a8ea580736::usdc::USDC",
                    b"46bfe51da1bd9511919a92eb1154149b36c0f4212121808e13e3e5857d607a9c::usdt::USDT"
                ],
                vector[500_000_000, 30_000_000, 1_000, 1_000],
            ),
            1,
        );

        // Test message serialization
        let message = serialize_message(add_tokens_on_starcoin_message);
        let expected_msg =
            x"0601000000000000000002000401020304044a396235653133626364306362323366663235633037363938653839643438303536633734353333386438633964626430333361343137326238373032373037333a3a6274633a3a4254434a373937306437316330333537336635343061373135376630643339373065313137656666613661653136636566643530623435633734393637306232346536613a3a6574683a3a4554484c353030653432396132343437383430356435313330323232623230663835373061373436623662633232343233663134623464346536613865613538303733363a3a757364633a3a555344434c343662666535316461316264393531313931396139326562313135343134396233366330663432313231323138303865313365336535383537643630376139633a3a757364743a3a55534454040065cd1d0000000080c3c90100000000e803000000000000e803000000000000";
        assert!(message == expected_msg, 2);
        assert!(add_tokens_on_starcoin_message == deserialize_message_test_only(message), 3);

        // Use STARCOIN_BRIDGE_MESSAGE prefix
        let message_bytes = b"STARCOIN_BRIDGE_MESSAGE";
        Vector::append(&mut message_bytes, message);

        // Signature generated by Rust test with key e42c82337ce12d4a7ad6cd65876d91b2ab6594fd50cdab1737c91773ba7451db
        let evm_address = EcdsaK1::secp256k1_ecrecover(
            &x"7e586ef8b996240cec525e490f6e76bdf12b6c8270a3403d3729cbf48d5d06881949ded133e953c873006a60826b72b4e640d5227bc79ff98c995c838b89a92f01",
            &message_bytes,
            0,
        );

        // The recovered address is a 20-byte EVM address derived from the raw pubkey:
        // Raw pubkey: 321ede33d2c2d7a8a152f275a1484edef2098f034121a602cb7d767d38680aa4abcfe1a969c7143c8a983cfa9e44ff6494e9802ebff1db64df53ff1c992f556c
        // EVM address = keccak256(raw_pubkey)[-20:]
        let expected_evm_address = x"68b43fd906c0b8f024a18c56e06744f7c6157c65";
        assert!(evm_address == expected_evm_address, 4);
        Treasury::destroy(treasury);
    }

    #[test]
    fun test_be_to_le_conversion() {
        let input = x"78563412";
        let expected = x"12345678";
        assert!(reverse_bytes_test(input) == expected, 1);
    }

    #[test]
    fun test_peel_u64_be() {
        // Big-endian representation of 12345 is x"0000000000003039"
        // But BCSUtil uses pop_back, so we need to reverse it first
        let input = x"3930000000000000"; // reversed version
        let expected = 12345u64;
        assert!(peel_u64_be_for_testing(&mut input) == expected, 1);
    }

    #[test(bridge = @Bridge)]
    #[expected_failure(abort_code = Bridge::Message::ETrailingBytes)]
    fun test_bad_payload(bridge: &signer) {
        Account::create_account_with_address<STC>(@Bridge);
        Account::set_auto_accept_token(bridge, true);

        let sender_address = @0x64;
        let token = AssetUtil::quick_mint_for_test<USDT::USDT>(bridge, 12345);

        let token_bridge_message = create_token_bridge_message(
            ChainIDs::starcoin_testnet(), // source chain
            10, // seq_num
            BCS::to_bytes(&sender_address), // sender address
            ChainIDs::eth_sepolia(), // target_chain
            // Eth address is 20 bytes long
            x"00000000000000000000000000000000000000c8", // target_address
            3u8, // token_type
            (Token::value(&token) as u64), // amount: u64
        );
        let payload = payload(&token_bridge_message);
        Vector::push_back(&mut payload, 0u8);
        set_payload(&mut token_bridge_message, payload);

        extract_token_bridge_payload(&token_bridge_message);

        abort 1
    }


    #[test]
    #[expected_failure(abort_code = Bridge::Message::ETrailingBytes)]
    fun test_bad_emergency_op() {
        let msg = create_emergency_op_message(
            ChainIDs::starcoin_testnet(),
            0,
            emergency_op_pause(),
        );
        let payload = payload(&msg);
        Vector::push_back(&mut payload, 0u8);
        set_payload(&mut msg, payload);
        extract_emergency_op_payload(&msg);
    }


    #[test]
    #[expected_failure(abort_code = Bridge::Message::EEmptyList)]
    fun test_bad_blocklist() {
        let blocklist_message = create_blocklist_message(
            ChainIDs::starcoin_testnet(),
            10,
            0,
            vector[],
        );
        extract_blocklist_payload(&blocklist_message);
    }

    #[test]
    #[expected_failure(abort_code = Bridge::Message::ETrailingBytes)]
    fun test_bad_blocklist_1() {
        let blocklist_message = default_blocklist_message();
        let payload = payload(&blocklist_message);
        Vector::push_back(&mut payload, 0u8);
        set_payload(&mut blocklist_message, payload);
        extract_blocklist_payload(&blocklist_message);
    }

    #[test]
    #[expected_failure(abort_code = Bridge::Message::EInvalidAddressLength)]
    fun test_bad_blocklist_2() {
        let validator_pub_key1 = x"b14d3c4f5fbfbcfb98af2d330000d49c95b93aa7";
        // bad address
        let validator_pub_key2 = x"f7e93cc543d97af6632c9b8864417379dba4bf150000";
        let validator_eth_addresses = vector[validator_pub_key1, validator_pub_key2];
        create_blocklist_message(ChainIDs::starcoin_testnet(), 10, 0, validator_eth_addresses);
    }


    #[test]
    #[expected_failure(abort_code = Bridge::Message::ETrailingBytes)]
    fun test_bad_bridge_limit() {
        let update_bridge_limit = create_update_bridge_limit_message(
            ChainIDs::starcoin_testnet(),
            10,
            ChainIDs::eth_sepolia(),
            1000000000,
        );
        let payload = payload(&update_bridge_limit);
        Vector::push_back(&mut payload, 0u8);
        set_payload(&mut update_bridge_limit, payload);
        extract_update_bridge_limit(&update_bridge_limit);
    }

    #[test]
    #[expected_failure(abort_code = Bridge::Message::ETrailingBytes)]
    fun test_bad_update_price() {
        let asset_price_message = create_update_asset_price_message(
            2,
            ChainIDs::starcoin_testnet(), // source chain
            10, // seq_num
            12345,
        );
        let payload = payload(&asset_price_message);
        Vector::push_back(&mut payload, 0u8);
        set_payload(&mut asset_price_message, payload);
        extract_update_asset_price(&asset_price_message);
    }

    #[test]
    #[expected_failure(abort_code = Bridge::Message::ETrailingBytes)]
    fun test_bad_add_token() {
        let treasury = Treasury::mock_for_test();

        let add_token_message = create_add_tokens_on_starcoin_message(
            ChainIDs::starcoin_custom(),
            1, // seq_num
            false, // native_token
            vector[token_id<BTC>(&treasury), token_id<ETH>(&treasury)],
            vector[
                b"28ac483b6f2b62dd58abdf0bbc3f86900d86bbdc710c704ba0b33b7f1c4b43c8::btc::BTC",
                b"0xbd69a54e7c754a332804f325307c6627c06631dc41037239707e3242bc542e99::eth::ETH",
            ],
            vector[100, 100],
        );
        let payload = payload(&add_token_message);
        Vector::push_back(&mut payload, 0u8);
        set_payload(&mut add_token_message, payload);
        extract_add_tokens_on_starcoin(&add_token_message);

        abort 1
    }


    #[test(bridge = @Bridge)]
    #[expected_failure(abort_code = Bridge::Message::EInvalidPayloadLength)]
    fun test_bad_payload_size(bridge: &signer) {
        Account::create_account_with_address<STC>(@Bridge);
        Account::set_auto_accept_token(bridge, true);

        let sender_address = @0x64;
        let sender = BCS::to_bytes(&sender_address);
        let token = AssetUtil::quick_mint_for_test<USDT::USDT>(bridge, 12345);

        // double sender which wil make the payload different the 64 bytes
        Vector::append(&mut sender, BCS::to_bytes(&sender_address));
        create_token_bridge_message(
            ChainIDs::starcoin_testnet(), // source chain
            10, // seq_num
            sender, // sender address
            ChainIDs::eth_sepolia(), // target_chain
            // Eth address is 20 bytes long
            x"00000000000000000000000000000000000000c8", // target_address
            3u8, // token_type
            (Token::value(&token) as u64),
        );

        abort 1
    }


    #[test]
    #[expected_failure(abort_code = Bridge::Message::EMustBeTokenMessage)]
    fun test_bad_token_transfer_type() {
        let msg = create_update_asset_price_message(2, ChainIDs::starcoin_testnet(), 10, 12345);
        to_parsed_token_transfer_message(&msg);
    }

    #[test(bridge = @Bridge)]
    fun test_voting_power(bridge: &signer) {
        Account::create_account_with_address<STC>(@Bridge);
        Account::set_auto_accept_token(bridge, true);

        let sender_address = @0x64;
        let token = AssetUtil::quick_mint_for_test<USDC>(bridge, 12345);
        let message = default_token_bridge_message(
            sender_address,
            &token,
            ChainIDs::starcoin_testnet(),
            ChainIDs::eth_sepolia(),
        );
        assert!(required_voting_power(&message) == 2, 1);

        let treasury = Treasury::mock_for_test();
        let message = create_add_tokens_on_starcoin_message(
            ChainIDs::starcoin_custom(),
            1, // seq_num
            false, // native_token
            vector[token_id<BTC>(&treasury), token_id<ETH>(&treasury)],
            vector[
                b"28ac483b6f2b62dd58abdf0bbc3f86900d86bbdc710c704ba0b33b7f1c4b43c8::btc::BTC",
                b"0xbd69a54e7c754a332804f325307c6627c06631dc41037239707e3242bc542e99::eth::ETH",
            ],
            vector[100, 100],
        );
        assert!(required_voting_power(&message) == 5001, 2);


        let message = create_emergency_op_message(
            ChainIDs::starcoin_testnet(),
            10,
            emergency_op_pause(),
        );
        assert!(required_voting_power(&message) == 450, 3);
        let message = create_emergency_op_message(
            ChainIDs::starcoin_testnet(),
            10,
            emergency_op_unpause(),
        );
        assert!(required_voting_power(&message) == 5001, 4);

        let message = default_blocklist_message();
        assert!(required_voting_power(&message) == 5001, 5);

        let message = create_update_asset_price_message(2, ChainIDs::starcoin_testnet(), 10, 12345);
        assert!(required_voting_power(&message) == 5001, 6);

        let message = create_update_bridge_limit_message(
            ChainIDs::starcoin_testnet(), // source chain
            10, // seq_num
            ChainIDs::eth_sepolia(),
            1000000000,
        );
        assert!(required_voting_power(&message) == 5001, 7);

        Treasury::destroy(treasury);
        Account::deposit(@Bridge, token);
    }

    #[test]
    #[expected_failure(abort_code = Bridge::Message::EInvalidEmergencyOpType)]
    fun test_bad_voting_power_1() {
        let message = create_emergency_op_message(ChainIDs::starcoin_testnet(), 10, 3);
        required_voting_power(&message);
    }

    #[test]
    #[expected_failure(abort_code = Bridge::Message::EInvalidMessageType)]
    fun test_bad_voting_power_2() {
        let message = make_generic_message(
            100, // bad message type
            1,
            10,
            ChainIDs::starcoin_testnet(),
            vector[],
        );
        required_voting_power(&message);
    }

    fun default_token_bridge_message<T: store>(
        sender: address,
        token: &Token::Token<T>,
        source_chain: u8,
        target_chain: u8,
    ): BridgeMessage {
        create_token_bridge_message(
            source_chain,
            10, // seq_num
            BCS::to_bytes(&sender),
            target_chain,
            // Eth address is 20 bytes long
            x"00000000000000000000000000000000000000c8",
            3u8, // token_type
            (Token::value(token) as u64),
        )
    }

    #[test(bridge = @Bridge)]
    #[expected_failure(abort_code = Bridge::ChainIDs::EInvalidBridgeRoute)]
    fun test_invalid_chain_id_1(bridge: &signer) {
        Account::create_account_with_address<STC>(@Bridge);
        Account::set_auto_accept_token(bridge, true);

        let sender_address = @0x64;
        let token = AssetUtil::quick_mint_for_test<USDC>(bridge, 1);

        default_token_bridge_message(
            sender_address,
            &token,
            INVALID_CHAIN,
            ChainIDs::eth_sepolia(),
        );
        abort 1
    }

    #[test(bridge = @Bridge)]
    #[expected_failure(abort_code = Bridge::ChainIDs::EInvalidBridgeRoute)]
    fun test_invalid_chain_id_2(bridge: &signer) {
        Account::create_account_with_address<STC>(@Bridge);
        Account::set_auto_accept_token(bridge, true);

        let sender_address = @0x64;
        let token = AssetUtil::quick_mint_for_test<USDC>(bridge, 1);
        default_token_bridge_message(
            sender_address,
            &token,
            ChainIDs::starcoin_testnet(),
            INVALID_CHAIN,
        );
        abort 1
    }

    #[test]
    #[expected_failure(abort_code = Bridge::ChainIDs::EInvalidBridgeRoute)]
    fun test_invalid_chain_id_3() {
        create_emergency_op_message(
            INVALID_CHAIN,
            10, // seq_num
            emergency_op_pause(),
        );
        abort 1
    }

    #[test]
    #[expected_failure(abort_code = Bridge::ChainIDs::EInvalidBridgeRoute)]
    fun test_invalid_chain_id_4() {
        create_blocklist_message(INVALID_CHAIN, 10, 0, vector[]);
        abort 1
    }

    #[test]
    #[expected_failure(abort_code = Bridge::ChainIDs::EInvalidBridgeRoute)]
    fun test_invalid_chain_id_5() {
        create_update_bridge_limit_message(INVALID_CHAIN, 1, ChainIDs::eth_sepolia(), 1);
        abort 1
    }

    #[test]
    #[expected_failure(abort_code = Bridge::ChainIDs::EInvalidBridgeRoute)]
    fun test_invalid_chain_id_6() {
        create_update_bridge_limit_message(ChainIDs::starcoin_testnet(), 1, INVALID_CHAIN, 1);
        abort 1
    }

    #[test]
    #[expected_failure(abort_code = Bridge::ChainIDs::EInvalidBridgeRoute)]
    fun test_invalid_chain_id_7() {
        create_update_asset_price_message(2, INVALID_CHAIN, 1, 5);
        abort 1
    }

    #[test]
    #[expected_failure(abort_code = Bridge::ChainIDs::EInvalidBridgeRoute)]
    fun test_invalid_chain_id_8() {
        create_add_tokens_on_starcoin_message(INVALID_CHAIN, 1, false, vector[], vector[], vector[]);
        abort 1
    }

    fun default_blocklist_message(): BridgeMessage {
        let validator_pub_key1 = x"b14d3c4f5fbfbcfb98af2d330000d49c95b93aa7";
        let validator_pub_key2 = x"f7e93cc543d97af6632c9b8864417379dba4bf15";
        let validator_eth_addresses = vector[validator_pub_key1, validator_pub_key2];
        create_blocklist_message(ChainIDs::starcoin_testnet(), 10, 0, validator_eth_addresses)
    }

    #[test]
    fun test_create_token_bridge_message() {
        let message = create_token_bridge_message(
            1,
            1,
            BCS::to_bytes(&@0x1),
            12,
            x"00000000000000000000000000000000000000c8",
            23,
            12345
        );
        let payload = Message::payload(&message);
        Vector::reverse(&mut payload);
        Debug::print(&payload);

        let address = BCSUtil::peel_vec_u8(&mut payload);
        Debug::print(&address);
        assert!(BCS::to_address(address) == @0x1, 1);

        let target_chain = BCSUtil::peel_u8(&mut payload);
        Debug::print(&target_chain);
        assert!(target_chain == 12, 2);

        let target_address = BCSUtil::peel_vec_u8(&mut payload);
        Debug::print(&target_address);
        assert!(target_address == x"00000000000000000000000000000000000000c8", 3);

        let token_type = BCSUtil::peel_u8(&mut payload);
        Debug::print(&token_type);
        assert!(token_type == 23, 4);

        Debug::print(&payload);
        let amount = Message::peel_u64_be(&mut payload);
        Debug::print(&amount);
        assert!(amount == 12345, 5);
    }

    //////////////////////////////////////////////////////
    // Tests for UpdateCommitteeMember message
    //

    #[test]
    fun test_update_committee_member_message_serialization() {
        let member_address = @0x00000000000000000000000000000064;
        // Use 64-byte uncompressed pubkey (raw x,y coordinates)
        let bridge_pubkey_bytes = x"9bef8d556d80e43ae7e0becb3a7e6838b95defe45896ed6075bb9035d06c9964058d24456ffbf25b675c768bbb2212a7ef76e07f36bb13d1f8f714041bb78c24";
        let voting_power = 5000u64;
        let http_rest_url = b"https://127.0.0.1:9191";

        let update_committee_member_message = Message::create_update_committee_member_message(
            ChainIDs::starcoin_testnet(), // source chain
            10, // seq_num
            0, // update_type: 0 = add
            member_address,
            bridge_pubkey_bytes,
            voting_power,
            http_rest_url,
        );

        // Test message serialization
        let message = serialize_message(update_committee_member_message);
        // Verify can deserialize back
        let deserialized = deserialize_message_test_only(message);
        assert!(Message::message_type(&deserialized) == Message::message_type(&update_committee_member_message), 1);
        assert!(Message::seq_num(&deserialized) == Message::seq_num(&update_committee_member_message), 2);

        // Test payload extraction
        let payload = Message::extract_update_committee_member(&update_committee_member_message);
        assert!(Message::update_committee_member_type(&payload) == 0, 3);
        assert!(Message::update_committee_member_address(&payload) == member_address, 4);
        assert!(Message::update_committee_member_pubkey(&payload) == bridge_pubkey_bytes, 5);
        assert!(Message::update_committee_member_voting_power(&payload) == voting_power, 6);
        assert!(Message::update_committee_member_http_url(&payload) == http_rest_url, 7);
    }

    #[test]
    fun test_update_committee_member_required_voting_power() {
        let member_address = @0x00000000000000000000000000000001;
        // Use 64-byte uncompressed pubkey
        let bridge_pubkey_bytes = x"9bef8d556d80e43ae7e0becb3a7e6838b95defe45896ed6075bb9035d06c9964058d24456ffbf25b675c768bbb2212a7ef76e07f36bb13d1f8f714041bb78c24";

        let message = Message::create_update_committee_member_message(
            ChainIDs::starcoin_testnet(),
            1,
            0,
            member_address,
            bridge_pubkey_bytes,
            5000,
            b"https://test.com",
        );

        // UpdateCommitteeMember should require 5001 voting power (governance level)
        assert!(required_voting_power(&message) == 5001, 1);
    }

    #[test]
    #[expected_failure(abort_code = Bridge::ChainIDs::EInvalidBridgeRoute)]
    fun test_update_committee_member_invalid_chain_id() {
        let member_address = @0x00000000000000000000000000000001;
        // Use 64-byte uncompressed pubkey
        let bridge_pubkey_bytes = x"9bef8d556d80e43ae7e0becb3a7e6838b95defe45896ed6075bb9035d06c9964058d24456ffbf25b675c768bbb2212a7ef76e07f36bb13d1f8f714041bb78c24";

        Message::create_update_committee_member_message(
            INVALID_CHAIN, // invalid chain
            1,
            0,
            member_address,
            bridge_pubkey_bytes,
            5000,
            b"https://test.com",
        );
        abort 1
    }

    //////////////////////////////////////////////////////
    // Tests for BCSUtil::to_address
    //

    #[test]
    fun test_bcsutil_to_address() {
        // Test converting 16 bytes to address
        let addr_bytes = x"00000000000000000000000000000064";
        let addr = BCSUtil::to_address(addr_bytes);
        assert!(addr == @0x64, 1);

        // Test another address
        let addr_bytes2 = x"00000000000000000000000000000001";
        let addr2 = BCSUtil::to_address(addr_bytes2);
        assert!(addr2 == @0x1, 2);
    }
}