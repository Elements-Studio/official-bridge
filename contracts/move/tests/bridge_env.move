// // Copyright (c) Starcoin, Inc.
// // SPDX-License-Identifier: Apache-2.0

#[test_only]
module Bridge::BridgeEnv {
    use Bridge::AssetUtil;
    use Bridge::BTC::BTC;
    use Bridge::Bridge::{Self, Bridge, get_total_supply, mint_some};
    use Bridge::ChainIDs;
    use Bridge::Committee;
    use Bridge::ETH::ETH;
    use Bridge::EcdsaK1;
    use Bridge::Limiter;
    use Bridge::Message;
    use Bridge::Message::{BridgeMessage, create_add_tokens_on_starcoin_message, create_blocklist_message,
        emergency_op_pause, emergency_op_unpause
    };
    use Bridge::MessageTypes;
    use Bridge::TestToken::TEST_TOKEN;
    use Bridge::Treasury;
    use Bridge::USDC::USDC;
    use Bridge::USDT::USDT;
    use StarcoinFramework::Account;
    use StarcoinFramework::BCS;
    use StarcoinFramework::STC::STC;
    use StarcoinFramework::Signer;
    use Bridge::SimpleMap;
    use StarcoinFramework::Token;
    use StarcoinFramework::Token::{BurnCapability, MintCapability};
    use StarcoinFramework::Vector;

    // Token IDs
    const BTC_ID: u8 = 1;
    const ETH_ID: u8 = 2;
    const USDC_ID: u8 = 3;
    const USDT_ID: u8 = 4;
    const TEST_TOKEN_ID: u8 = 5;

    public fun btc_id(): u8 {
        BTC_ID
    }

    public fun eth_id(): u8 {
        ETH_ID
    }

    public fun usdc_id(): u8 {
        USDC_ID
    }

    public fun usdt_id(): u8 {
        USDT_ID
    }

    public fun test_token_id(): u8 {
        TEST_TOKEN_ID
    }


    // Claim status
    //
    const CLAIMED: u8 = 1;
    const ALREADY_CLAIMED: u8 = 2;
    const LIMIT_EXCEEDED: u8 = 3;

    public fun claimed(): u8 {
        CLAIMED
    }

    public fun already_claimed(): u8 {
        ALREADY_CLAIMED
    }

    public fun limit_exceeded(): u8 {
        LIMIT_EXCEEDED
    }

    //
    // Approve status
    //
    const APPROVED: u8 = 1;
    const ALREADY_APPROVED: u8 = 2;

    public fun approved(): u8 {
        APPROVED
    }

    public fun already_approved(): u8 {
        ALREADY_APPROVED
    }

    //
    // Validators setup and info
    //

    // Validator info
    struct ValidatorInfo has drop {
        validator_addr: address,
        public_key: vector<u8>,
        private_key: vector<u8>,
        stake_amount: u64,
    }

    public fun addr(validator: &ValidatorInfo): address {
        validator.validator_addr
    }

    public fun public_key(validator: &ValidatorInfo): &vector<u8> {
        &validator.public_key
    }

    public fun create_validator(
        validator: address,
        stake_amount: u64,
        public_key: vector<u8>,
        private_key: vector<u8>,
        _seed: &vector<u8>,
    ): ValidatorInfo {
        ValidatorInfo {
            validator_addr: validator,
            public_key,
            private_key,
            stake_amount,
        }
    }

    // Bridge environemnt
    struct BridgeEnv {
        validators: vector<ValidatorInfo>,
        chain_id: u8,
        vault: Vault,
        clock: u64,
    }

    // Holds coins for different bridged tokens
    struct Vault {
        btc_coins: Token::Token<BTC>,
        eth_coins: Token::Token<ETH>,
        usdc_coins: Token::Token<USDC>,
        usdt_coins: Token::Token<USDT>,
        test_coins: Token::Token<TEST_TOKEN>,
    }

    struct ValtTokenCaps<phantom T> {
        burn_cap: Token::BurnCapability<T>,
        mint_cap: Token::MintCapability<T>,
    }

    // HotPotato to access shared state
    // TODO: if the bridge is the only shared state we could remvove this
    struct BridgeWrapper {
        bridge: Bridge,
    }

    public fun bridge_wrapper(env: &mut BridgeEnv, sender: address): BridgeWrapper {
        BridgeWrapper { bridge: Bridge::new_for_testing(env.chain_id, sender) }
    }

    public fun bridge_ref(wrapper: &BridgeWrapper): &Bridge {
        &wrapper.bridge
    }

    public fun bridge_ref_mut(wrapper: &mut BridgeWrapper): &mut Bridge {
        &mut wrapper.bridge
    }

    public fun destroy_bridge_wrapper(wrapper: BridgeWrapper) {
        let BridgeWrapper { bridge } = wrapper;
        Bridge::destroy_for_testing(bridge);
    }

    //
    // Public functions
    //

    //
    // Environment creation and destruction
    //

    public fun create_env(chain_id: u8): BridgeEnv {
        let btc_coins = Token::zero<BTC>();
        let eth_coins = Token::zero<ETH>();
        let usdc_coins = Token::zero<USDC>();
        let usdt_coins = Token::zero<USDT>();
        let test_coins = Token::zero<TEST_TOKEN>();

        Account::create_account_with_address<STC>(@Bridge);

        let vault = Vault {
            btc_coins,
            eth_coins,
            usdc_coins,
            usdt_coins,
            test_coins,
        };
        BridgeEnv {
            chain_id,
            vault,
            validators: Vector::empty(),
            clock: 0,
        }
    }

    public fun destroy_env(env: BridgeEnv) {
        let BridgeEnv {
            chain_id: _,
            vault,
            validators: _,
            clock: _,
        } = env;

        let Vault {
            btc_coins,
            eth_coins,
            usdc_coins,
            usdt_coins,
            test_coins,
        } = vault;

        Treasury::burn_token<BTC>(btc_coins);
        Treasury::burn_token<ETH>(eth_coins);
        Treasury::burn_token<USDC>(usdc_coins);
        Treasury::burn_token<USDT>(usdt_coins);
        Treasury::burn_token<TEST_TOKEN>(test_coins);
    }

    // Add a set of validators to the chain.
    // Call only once in a test scenario.
    public fun setup_validators(env: &mut BridgeEnv, validators_info: vector<ValidatorInfo>) {
        // let validators = validators_info.map_ref!(|validator| {
        // create_validator_for_testing(
        // validator.validator,
        // validator.stake_amount,
        // ctx,
        // )
        // });
        // env.validators = validators_info;
        // create_starcoin_system_state_for_testing(validators, 0, 0, ctx);
        // advance_epoch_with_reward_amounts(0, 0, scenario);
        env.validators = validators_info;
    }

    //
    // Bridge creation and setup
    //

    // Set up an environment with 3 validators, a bridge with
    // a treasury and a committee with all 3 validators.
    // The treasury will contain 4 tokens: ETH, BTC, USDT, USDC.
    // Save the Bridge as a shared object.
    public fun create_bridge_default(env: &mut BridgeEnv, sender: &signer): Bridge {
        // Initialize all global resources first
        Bridge::initialize_for_testing(sender);
        
        let seed = b"test_seed";
        // Use 64-byte uncompressed ECDSA pubkeys (raw x,y coordinates)
        let validators = vector[
            create_validator(
                @0xAAAA,
                100,
                x"9bef8d556d80e43ae7e0becb3a7e6838b95defe45896ed6075bb9035d06c9964058d24456ffbf25b675c768bbb2212a7ef76e07f36bb13d1f8f714041bb78c24",
                b"",
                &seed,
            ),
            create_validator(
                @0xBBBB,
                100,
                x"3e99a541db69bd32040dfe5037fbf5210dafa8151a71e21c5204b05d95ce0a62fb83ba8696f00ef5621d84c840181aad568794f9d9b096999d3f9bec5215479d",
                b"",
                &seed
            ),
            create_validator(
                @0xCCCC,
                100,
                x"3e99a541db69bd32040dfe5037fbf5210dafa8151a71e21c5204b05d95ce0a6397e1bb3b38f4312e874ab5ec49c3a75dfe042d1c7b072ac36bbc1856800fe43f",
                b"",
                &seed
            ),
        ];
        Self::setup_validators(env, validators);

        let sender_address = Signer::address_of(sender);
        let bridge = Self::create_bridge(env, sender_address);

        Self::register_committee(env, &mut bridge, sender_address);
        Self::init_committee(env, &mut bridge);
        Self::setup_treasury(env, &mut bridge, sender);

        bridge
    }

    /// Create a bridge configured for signature verification tests.
    /// Uses real test keys (Key 1 & Key 2) with voting_power=1 each.
    /// Token transfers require voting_power >= 2, so both signatures are needed.
    public fun create_bridge_for_sig_tests(env: &mut BridgeEnv, sender: &signer): Bridge {
        Bridge::initialize_for_testing(sender);
        
        // Real test keys from Rust get_bridge_encoding_regression_test_keys()
        // Key 1: 02321ede33d2c2d7a8a152f275a1484edef2098f034121a602cb7d767d38680aa4
        // Key 2: 027f1178ff417fc9f5b8290bd8876f0a157a505a6c52db100a8492203ddd1d4279
        // 64-byte uncompressed versions:
        let seed = b"sig_test_seed";
        let validators = vector[
            create_validator(
                @0xAAAA,
                1, // voting_power=1
                x"321ede33d2c2d7a8a152f275a1484edef2098f034121a602cb7d767d38680aa4abcfe1a969c7143c8a983cfa9e44ff6494e9802ebff1db64df53ff1c992f556c",
                b"",
                &seed,
            ),
            create_validator(
                @0xBBBB,
                1, // voting_power=1
                x"7f1178ff417fc9f5b8290bd8876f0a157a505a6c52db100a8492203ddd1d42793c8b33ae43a7d969ca006fa7b20a4d09c5400524b7f0e1e27cd5646e9af6926a",
                b"",
                &seed
            ),
        ];
        Self::setup_validators(env, validators);

        let sender_address = Signer::address_of(sender);
        let bridge = Self::create_bridge(env, sender_address);

        Self::register_committee(env, &mut bridge, sender_address);
        Self::init_committee(env, &mut bridge);
        Self::setup_treasury(env, &mut bridge, sender);

        bridge
    }

    /// Create a bridge configured for system message tests (pause/unpause etc).
    /// Uses real test keys (Key 1 & Key 2) with voting_power=3000 each.
    /// System messages require high voting power:
    /// - PAUSE requires voting_power >= 450
    /// - UNPAUSE requires voting_power >= 5001
    /// With 2 signatures at 3000 each = 6000 total, all system ops are supported.
    public fun create_bridge_for_system_msg_tests(env: &mut BridgeEnv, sender: &signer): Bridge {
        Bridge::initialize_for_testing(sender);
        
        // Same keys as sig_tests but with higher voting power for system messages
        // 64-byte uncompressed pubkeys:
        let seed = b"sig_test_seed";
        let validators = vector[
            create_validator(
                @0xAAAA,
                3000, // voting_power=3000
                x"321ede33d2c2d7a8a152f275a1484edef2098f034121a602cb7d767d38680aa4abcfe1a969c7143c8a983cfa9e44ff6494e9802ebff1db64df53ff1c992f556c",
                b"",
                &seed,
            ),
            create_validator(
                @0xBBBB,
                3000, // voting_power=3000
                x"7f1178ff417fc9f5b8290bd8876f0a157a505a6c52db100a8492203ddd1d42793c8b33ae43a7d969ca006fa7b20a4d09c5400524b7f0e1e27cd5646e9af6926a",
                b"",
                &seed
            ),
        ];
        Self::setup_validators(env, validators);

        let sender_address = Signer::address_of(sender);
        let bridge = Self::create_bridge(env, sender_address);

        Self::register_committee(env, &mut bridge, sender_address);
        Self::init_committee(env, &mut bridge);
        Self::setup_treasury(env, &mut bridge, sender);

        bridge
    }

    // Create a bridge and set up a treasury.
    // The treasury will contain 4 tokens: ETH, BTC, USDT, USDC.
    // Save the Bridge as a shared object.
    // No operation on the validators.
    public fun create_bridge(env: &mut BridgeEnv, sender: address): Bridge {
        Bridge::new_for_testing(env.chain_id, sender)
    }

    // Register 3 committee members (validators `@0xA`, `@0xB`, `@0xC`)
    // Now uses add_member_for_testing since committee_registration_for_testing was removed
    public fun register_committee(env: &mut BridgeEnv, bridge: &mut Bridge, _sender: address) {
        let inner = Bridge::test_load_inner_mut(bridge);
        let committee = Bridge::inner_committee_mut(inner);
        let len = Vector::length(&env.validators);
        let i = 0;
        while (i < len) {
            let vi = Vector::borrow(&env.validators, i);
            Committee::add_member_for_testing(
                committee,
                vi.public_key,
                vi.stake_amount,
                b"",
            );
            i = i + 1;
        };
    }

    // Init the bridge committee
    // Committee is now initialized when members are added, so this is a no-op
    public fun init_committee(_env: &mut BridgeEnv, _bridge: &mut Bridge) {
        // Committee initialization now happens when members are added via governance
        // The add_member_for_testing already populates the committee
    }

    // Set up a treasury with 4 tokens: ETH, BTC, USDT, USDC.
    public fun setup_treasury(env: &mut BridgeEnv, bridge: &mut Bridge, sender: &signer) {
        Self::register_default_tokens(env, bridge, sender);
        Self::add_default_tokens(env, bridge);
        Self::load_vault(env);
    }

    // Register 4 tokens with the Bridge: ETH, BTC, USDT, USDC.
    fun register_default_tokens(env: &mut BridgeEnv, bridge: &mut Bridge, bridge_admin: &signer) {
        let crypto_precision = 9; // BTC, ETH use 9 decimals
        let stablecoin_precision = 6; // USDT, USDC use 6 decimals (matching ERC20)

        // BTC
        let (mint_cap, burn_cap) = AssetUtil::initialize<BTC>(bridge_admin, crypto_precision);
        Self::register_foreign_token<BTC>(bridge_admin, bridge, env, mint_cap, burn_cap);

        // ETH
        let (mint_cap, burn_cap) = AssetUtil::initialize<ETH>(bridge_admin, crypto_precision);
        Self::register_foreign_token<ETH>(bridge_admin, bridge, env, mint_cap, burn_cap);

        // USDT
        let (mint_cap, burn_cap) = AssetUtil::initialize<USDT>(bridge_admin, stablecoin_precision);
        Self::register_foreign_token<USDT>(bridge_admin, bridge, env, mint_cap, burn_cap);

        // USDC
        let (mint_cap, burn_cap) = AssetUtil::initialize<USDC>(bridge_admin, stablecoin_precision);
        Self::register_foreign_token<USDC>(bridge_admin, bridge, env, mint_cap, burn_cap);
    }

    // Add the 4 tokens previously registered: ETH, BTC, USDT, USDC.
    fun add_default_tokens(env: &mut BridgeEnv, bridge: &mut Bridge) {
        let add_token_message = create_add_tokens_on_starcoin_message(
            env.chain_id,
            Bridge::get_seq_num_for(bridge, MessageTypes::add_tokens_on_starcoin()),
            false,
            vector[BTC_ID, ETH_ID, USDC_ID, USDT_ID],
            vector[
                AssetUtil::token_type_name<BTC>(),
                AssetUtil::token_type_name<ETH>(),
                AssetUtil::token_type_name<USDC>(),
                AssetUtil::token_type_name<USDT>(),
            ],
            vector[1000, 100, 1, 1],
        );
        Bridge::execute_system_message_for_testing(bridge, add_token_message);
    }

    //
    // Utility functions for custom behavior
    //

    public fun token_type<T: store>(_env: &mut BridgeEnv, bridge: &mut Bridge): u8 {
        let inner = Bridge::test_load_inner(bridge);
        let treasury = Bridge::inner_treasury(inner);
        Treasury::token_id<T>(treasury)
    }

    const STARCOIN_MESSAGE_PREFIX: vector<u8> = b"STARCOIN_BRIDGE_MESSAGE";

    /// Note: secp256k1_sign is not available on mainnet, so we can't generate real signatures
    /// in Move tests. Tests should use *_for_testing functions that skip signature verification.
    /// This function is kept for API compatibility but the signatures are not used.
    fun sign_message(_env: &BridgeEnv, _message: BridgeMessage): vector<vector<u8>> {
        // Return empty signatures - tests should use *_for_testing functions
        Vector::empty<vector<u8>>()
    }

    /// Note: secp256k1_sign is not available on mainnet, so we can't generate real signatures.
    /// This function returns empty signatures for API compatibility.
    public fun sign_message_with(
        _env: &BridgeEnv,
        _message: BridgeMessage,
        _validator_idxs: vector<u64>,
    ): vector<vector<u8>> {
        Vector::empty<vector<u8>>()
    }

    public fun bridge_in_message<Token: store>(
        env: &mut BridgeEnv,
        bridge: &mut Bridge,
        source_chain: u8,
        source_address: vector<u8>,
        target_address: address,
        amount: u64,
    ): BridgeMessage {
        let message = Message::create_token_bridge_message(
            source_chain,
            Bridge::get_seq_num_inc_for(bridge, MessageTypes::token()),
            source_address,
            env.chain_id,
            BCS::to_bytes(&target_address),
            token_type<Token>(env, bridge),
            amount,
        );
        message
    }

    public fun bridge_out_message<Token: store>(
        env: &mut BridgeEnv,
        bridge: &mut Bridge,
        target_chain: u8,
        target_address: vector<u8>,
        source_address: address,
        amount: u64,
        transfer_id: u64,
    ): BridgeMessage {
        let token_type = Self::token_type<Token>(env, bridge);
        Message::create_token_bridge_message(
            env.chain_id,
            transfer_id,
            BCS::to_bytes(&source_address),
            target_chain,
            target_address,
            token_type,
            amount,
        )
    }

    public fun bridge_token_signed_message<Token: store>(
        env: &mut BridgeEnv,
        bridge: &mut Bridge,
        source_chain: u8,
        source_address: vector<u8>,
        target_address: address,
        amount: u64,
    ): (BridgeMessage, vector<vector<u8>>) {
        let token_type = Self::token_type<Token>(env, bridge);
        let seq_num = Bridge::get_seq_num_inc_for(bridge, MessageTypes::token());
        let message = Message::create_token_bridge_message(
            source_chain,
            seq_num,
            source_address,
            env.chain_id,
            BCS::to_bytes(&target_address),
            token_type,
            amount,
        );
        let signatures = Self::sign_message(env, message);
        (message, signatures)
    }


    // Bridge the `amount` of the given `Token` from the `source_chain`.
    public fun bridge_to_starcoin<Token: store>(
        env: &mut BridgeEnv,
        bridge: &mut Bridge,
        source_chain: u8,
        source_address: vector<u8>,
        target_address: address,
        amount: u64,
    ): u64 {
        let token_type = Self::token_type<Token>(env, bridge);

        // sign message
        let seq_num = Bridge::get_seq_num_inc_for(bridge, MessageTypes::token());
        let message = Message::create_token_bridge_message(
            source_chain,
            seq_num,
            source_address,
            env.chain_id,
            BCS::to_bytes(&target_address),
            token_type,
            amount,
        );
        let signatures = Self::sign_message(env, message);

        // run approval
        Bridge::approve_token_transfer_for_testing(bridge, message);

        // verify approval events (Not support verify dispatched by starcoin)
        // let approved_events = Event::events_by_type<TokenTransferApproved>();
        // let already_approved_events = event::events_by_type<TokenTransferAlreadyApproved>();
        // assert!(approved_events.length() == 1 || already_approved_events.length() == 1, 0);
        // let key = if (approved_events.length() == 1) {
        //     approved_events[0].transfer_approve_key()
        // } else {
        //     already_approved_events[0].transfer_already_approved_key()
        // };
        // let (sc, mt, sn) = key.unpack_message();
        // assert!(source_chain == sc);
        // assert!(mt == MessageTypes::token());
        // assert!(sn == seq_num);
        seq_num
    }

    //
    // Approves a token transer
    public fun approve_token_transfer(
        _env: &mut BridgeEnv,
        bridge: &mut Bridge,
        message: BridgeMessage,
        signatures: vector<vector<u8>>,
    ): u8 {
        // let msg_key = message.key();

        // run approval
        Bridge::approve_token_transfer_for_testing(bridge, message);

        // // verify approval events
        // let approved = event::events_by_type<TokenTransferApproved>();
        // let already_approved = event::events_by_type<TokenTransferAlreadyApproved>();
        // assert!(approved.length() == 1 || already_approved.length() == 1);
        // let (key, approve_status) = if (approved.length() == 1) {
        //     (approved[0].transfer_approve_key(), APPROVED)
        // } else {
        //     (already_approved[0].transfer_already_approved_key(), ALREADY_APPROVED)
        // };
        // assert!(msg_key == key);
        //
        // // tear down
        // test_scenario::return_shared(bridge);
        // approve_status
        // 0
        0
    }

    // Clain a token transfer and returns the coin
    public fun claim_token<T: store>(
        sender: &signer,
        env: &mut BridgeEnv,
        bridge: &mut Bridge,
        source_chain: u8,
        bridge_seq_num: u64,
    ): Token::Token<T> {
        // set up
        let _total_supply_before = Bridge::get_total_supply<T>();
        // run claim
        let token = Bridge::claim_token<T>(
            sender,
            bridge,
            env.clock,
            source_chain,
            bridge_seq_num,
        );

        // verify value change and claim events
        // let token_value = token.value();
        // assert!(total_supply_before + token_value == get_total_supply<T>(&bridge));
        // let claimed = event::events_by_type<TokenTransferClaimed>();
        // let already_claimed = event::events_by_type<TokenTransferAlreadyClaimed>();
        // let limit_exceeded = event::events_by_type<TokenTransferLimitExceed>();
        // assert!(
        //     claimed.length() == 1 || already_claimed.length() == 1 ||
        //     limit_exceeded.length() == 1,
        // );
        // let key = if (claimed.length() == 1) {
        //     claimed[0].transfer_claimed_key()
        // } else if (already_claimed.length() == 1) {
        //     already_claimed[0].transfer_already_claimed_key()
        // } else {
        //     limit_exceeded[0].transfer_limit_exceed_key()
        // };
        // let (sc, mt, sn) = key.unpack_message();
        // assert!(source_chain == sc);
        // assert!(mt == MessageTypes::token());
        // assert!(sn == bridge_seq_num);

        // tear down
        // test_scenario::return_shared(bridge);
        token
    }

    // Claim a token and transfer to the receiver in the bridge message
    public fun claim_and_transfer_token<T: store>(
        env: &mut BridgeEnv,
        bridge: &mut Bridge,
        source_chain: u8,
        bridge_seq_num: u64,
    ): u8 {
        // set up
        // let sender = @0xA1B2C3; // random sender
        let _total_supply_before = get_total_supply<T>();

        // run claim and transfer
        Bridge::claim_and_transfer_token<T>(
            bridge,
            env.clock,
            source_chain,
            bridge_seq_num,
        );

        // verify claim events
        // let claimed = event::events_by_type<TokenTransferClaimed>();
        // let already_claimed = event::events_by_type<TokenTransferAlreadyClaimed>();
        // let limit_exceeded = event::events_by_type<TokenTransferLimitExceed>();
        // assert!(
        //     claimed.length() == 1 || already_claimed.length() == 1 ||
        //         limit_exceeded.length() == 1,
        // );
        // let (key, claim_status) = if (claimed.length() == 1) {
        //     (claimed[0].transfer_claimed_key(), CLAIMED)
        // } else if (already_claimed.length() == 1) {
        //     (already_claimed[0].transfer_already_claimed_key(), ALREADY_CLAIMED)
        // } else {
        //     (limit_exceeded[0].transfer_limit_exceed_key(), LIMIT_EXCEEDED)
        // };
        // let (sc, mt, sn) = key.unpack_message();
        // assert!(source_chain == sc);
        // assert!(mt == MessageTypes::token());
        // assert!(sn == bridge_seq_num);
        //
        // // verify effects
        // let effects = scenario.next_tx(@0xABCDEF);
        // let created = effects.created();
        // if (!created.is_empty()) {
        //     let token_id = effects.created()[0];
        //     let token = scenario.take_from_sender_by_id < Coin<T> > (token_id);
        //     let token_value = token.value();
        //     assert!(
        //         total_supply_before + token_value ==
        //             get_total_supply<T>(&bridge),
        //     );
        //     scenario.return_to_sender(token);
        // };
        //
        // // tear down
        // test_scenario::return_shared(bridge);
        // claim_status
        0
    }


    // Send a coin (token) to the target chain
    public fun send_token<T: store>(
        env: &mut BridgeEnv,
        bridge: &mut Bridge,
        sender: address,
        target_chain_id: u8,
        eth_address: vector<u8>,
        token: Token::Token<T>,
    ): u64 {
        // set up
        let _chain_id = env.chain_id;
        let _coin_value = Token::value(&token);
        let _total_supply_before = get_total_supply<T>();
        let _seq_num = Bridge::get_seq_num_for(bridge, MessageTypes::token());

        // run send
        Bridge::send_token(bridge, sender, target_chain_id, eth_address, token);

        // verify send events
        // assert!(total_supply_before - coin_value == get_total_supply<T>(&bridge));
        // let deposited_events = event::events_by_type<TokenDepositedEvent>();
        // assert!(deposited_events.length() == 1);
        // let (
        //     event_seq_num,
        //     _event_source_chain,
        //     _event_sender_address,
        //     _event_target_chain,
        //     _event_target_address,
        //     _event_token_type,
        //     event_amount,
        // ) = deposited_events[0].unwrap_deposited_event();
        // assert!(event_seq_num == seq_num);
        // assert!(event_amount == coin_value);
        // assert_key(chain_id, &bridge);
        //
        // // tear down
        // test_scenario::return_shared(bridge);
        // seq_num

        0
    }


    // Update the limit for a given route
    public fun update_bridge_limit(
        env: &mut BridgeEnv,
        bridge: &mut Bridge,
        _sender: address,
        receiving_chain: u8,
        sending_chain: u8,
        limit: u64,
    ): u64 {
        // message signed
        let msg = Message::create_update_bridge_limit_message(
            receiving_chain,
            Bridge::get_seq_num_for(bridge, MessageTypes::update_bridge_limit()),
            sending_chain,
            limit,
        );

        // run limit update
        Bridge::execute_system_message_for_testing(bridge, msg);

        // // verify limit events
        // let limit_events = event::events_by_type<UpdateRouteLimitEvent>();
        // assert!(limit_events.length() == 1);
        // let event = limit_events[0];
        // let (sc, rc, new_limit) = event.unpack_route_limit_event();
        // assert!(sc == sending_chain);
        // assert!(rc == receiving_chain);
        // assert!(new_limit == limit);
        //
        // // tear down
        // test_scenario::return_shared(bridge);
        // new_limit

        0
    }

    // Update a given asset price (notional value)
    public fun update_asset_price(
        env: &mut BridgeEnv,
        bridge: &mut Bridge,
        _sender: &signer,
        token_id: u8,
        value: u64
    ) {
        // message signed
        let message = Message::create_update_asset_price_message(
            token_id,
            env.chain_id,
            Bridge::get_seq_num_for(bridge, MessageTypes::update_asset_price()),
            value,
        );

        // run price update
        Bridge::execute_system_message_for_testing(bridge, message);
        //
        // // verify price events
        // let update_events = event::events_by_type<UpdateTokenPriceEvent>();
        // assert!(update_events.length() == 1);
        // let (event_token_id, event_new_price) = update_events[0].unwrap_update_event();
        // assert!(event_token_id == token_id);
        // assert!(event_new_price == value);
        //
        // // tear down
        // test_scenario::return_shared(bridge);
    }


    // Register the `TEST_TOKEN` token
    public fun register_test_token(bridge_admin: &signer, _env: &mut BridgeEnv, bridge: &mut Bridge) {
        // "create" the `Coin`
        // let (upgrade_cap, treasury_cap, metadata) = test_token::create_bridge_token(scenario.ctx());
        // register the coin/token with the bridge
        let (mint_cap, burn_cap) = AssetUtil::initialize<TEST_TOKEN>(bridge_admin, 9);
        Bridge::register_foreign_token<TEST_TOKEN>(
            bridge,
            bridge_admin,
            mint_cap,
            burn_cap,
        );
        //
        // // verify registration events
        // let register_events = event::events_by_type<TokenRegistrationEvent>();
        // assert!(register_events.length() == 1);
        // let (type_name, decimal, nat) = register_events[0].unwrap_registration_event();
        // assert!(type_name == type_name::with_defining_ids<TEST_TOKEN>());
        // assert!(decimal == 8);
        // assert!(nat == false);
        //
        // // tear down
        // destroy(metadata);
        // test_scenario::return_shared(bridge);
    }


    // Add a list of tokens to the bridge.
    public fun add_tokens(
        env: &mut BridgeEnv,
        bridge: &mut Bridge,
        _sender: address,
        native_token: bool,
        token_ids: vector<u8>,
        type_names: vector<vector<u8>>,
        token_prices: vector<u64>,
    ) {
        // message signed
        let message = create_add_tokens_on_starcoin_message(
            env.chain_id,
            Bridge::get_seq_num_for(bridge, MessageTypes::add_tokens_on_starcoin()),
            native_token,
            token_ids,
            type_names,
            token_prices,
        );

        // run token addition
        Bridge::execute_system_message_for_testing(bridge, message);

        // // verify token addition events
        // let new_tokens_events = event::events_by_type<NewTokenEvent>();
        // assert!(new_tokens_events.length() <= token_ids.length());
        //
        // // tear down
        // test_scenario::return_shared(bridge);
    }

    // Blocklist a list of bridge nodes
    public fun execute_blocklist(
        env: &mut BridgeEnv,
        bridge: &mut Bridge,
        _sender: address,
        chain_id: u8,
        blocklist_type: u8,
        validator_ecdsa_addresses: vector<vector<u8>>,
    ) {
        // message signed
        let blocklist = create_blocklist_message(
            chain_id,
            Bridge::get_seq_num_for(bridge, MessageTypes::committee_blocklist()),
            blocklist_type,
            validator_ecdsa_addresses,
        );

        // run blocklist
        Bridge::execute_system_message_for_testing(bridge, blocklist);
    }

    // Update committee member (add a new member)
    public fun execute_update_committee_member(
        env: &mut BridgeEnv,
        bridge: &mut Bridge,
        _sender: address,
        chain_id: u8,
        update_type: u8,
        member_address: address,
        bridge_pubkey_bytes: vector<u8>,
        voting_power: u64,
        http_rest_url: vector<u8>,
    ) {
        // message signed
        let message = Message::create_update_committee_member_message(
            chain_id,
            Bridge::get_seq_num_for(bridge, MessageTypes::update_committee_member()),
            update_type,
            member_address,
            bridge_pubkey_bytes,
            voting_power,
            http_rest_url,
        );

        // run update committee member
        Bridge::execute_system_message_for_testing(bridge, message);
    }

    // Register new token
    public fun register_foreign_token<T: store>(
        bridge_admin: &signer,
        bridge: &mut Bridge,
        _env: &mut BridgeEnv,
        mint_cap: MintCapability<T>,
        burn_cap: BurnCapability<T>,
    ) {
        Bridge::register_foreign_token<T>(bridge, bridge_admin, mint_cap, burn_cap);

        // // verify registration events
        // let register_events = event::events_by_type<TokenRegistrationEvent>();
        // assert!(register_events.length() == 1);

        // verify changes in bridge
        let type_name = AssetUtil::token_type_name<T>();
        let treasury = Bridge::inner_treasury(Bridge::test_load_inner(bridge));
        let waiting_room = Treasury::wating_room(treasury);
        assert!(SimpleMap::contains_key(waiting_room, &type_name), 0);
        assert!(Treasury::contains_treasury<T>(), 1);
    }

    //
    // Freeze the bridge
    public fun freeze_bridge(env: &mut BridgeEnv, bridge: &mut Bridge, _sender: address, error: u64) {
        // set up
        // let scenario = env.scenario();
        // scenario.next_tx(sender);
        // let bridge = scenario.take_shared < Bridge > ();
        let seq_num = Bridge::get_seq_num_for(bridge, MessageTypes::emergency_op());

        // message signed
        let msg = Message::create_emergency_op_message(
            env.chain_id,
            seq_num,
            emergency_op_pause(),
        );

        // run freeze
        Bridge::execute_system_message_for_testing(bridge, msg);
        //
        // // verify freeze events
        // let register_events = event::events_by_type<EmergencyOpEvent>();
        // assert!(register_events.length() == 1);
        // assert!(register_events[0].unwrap_emergency_op_event() == true);

        // verify freeze
        let inner = Bridge::test_load_inner_mut(bridge);
        Bridge::assert_paused(inner, error);

        // // tear down
        // test_scenario::return_shared(bridge);
    }

    // Unfreeze the bridge
    public fun unfreeze_bridge(env: &mut BridgeEnv, bridge: &mut Bridge, _sender: address, error: u64) {
        let seq_num = Bridge::get_seq_num_for(bridge, MessageTypes::emergency_op());

        // message signed
        let msg = Message::create_emergency_op_message(
            env.chain_id,
            seq_num,
            emergency_op_unpause(),
        );

        // run unfreeze
        Bridge::execute_system_message_for_testing(bridge, msg);

        // let register_events = event::events_by_type<EmergencyOpEvent>();
        // assert!(register_events.length() == 1);
        // assert!(register_events[0].unwrap_emergency_op_event() == false);

        // verify unfreeze events

        // verify unfreeze
        let inner = Bridge::test_load_inner(bridge);
        Bridge::assert_not_paused(inner, error);
    }

    //
    // Getters
    //
    public fun chain_id(env: &mut BridgeEnv): u8 {
        env.chain_id
    }

    public fun validators(env: &BridgeEnv): &vector<ValidatorInfo> {
        &env.validators
    }


    public fun get_btc(env: &mut BridgeEnv, amount: u64): Token::Token<BTC> {
        Token::withdraw(&mut env.vault.btc_coins, (amount as u128))
    }

    public fun get_eth(env: &mut BridgeEnv, amount: u64): Token::Token<ETH> {
        Token::withdraw(&mut env.vault.eth_coins, (amount as u128))
    }

    //
    public fun get_usdc(env: &mut BridgeEnv, amount: u64): Token::Token<USDC> {
        Token::withdraw(&mut env.vault.usdc_coins, (amount as u128))
    }

    public fun get_usdt(env: &mut BridgeEnv, amount: u64): Token::Token<USDT> {
        Token::withdraw(&mut env.vault.usdt_coins, (amount as u128))
    }

    public fun limits(env: &mut BridgeEnv, bridge: &mut Bridge, dest: u8): u64 {
        let route = ChainIDs::get_route(dest, env.chain_id);
        let inner = Bridge::test_load_inner(bridge);
        Limiter::get_route_limit(Bridge::inner_limiter(inner), &route)
    }

    fun assert_key(chain_id: u8, bridge: &Bridge) {
        let bridge_inner = Bridge::test_load_inner(bridge);
        let transfer_record = Bridge::inner_token_transfer_records(bridge_inner);
        let seq_num = *SimpleMap::borrow(Bridge::sequence_nums(bridge_inner), &MessageTypes::token()) - 1;
        let key = Message::create_key(
            chain_id,
            MessageTypes::token(),
            seq_num,
        );
        assert!(SimpleMap::contains_key(transfer_record, &key), 1);
    }

    // Internal functions


    // Load the vault with some coins
    fun load_vault(env: &mut BridgeEnv) {
        Token::deposit(&mut env.vault.eth_coins, mint_some<ETH>(10_000_000_000));
        Token::deposit(&mut env.vault.btc_coins, mint_some<BTC>(10_000_000_000));
        Token::deposit(&mut env.vault.usdc_coins, mint_some<USDC>(10_000_000_000));
        Token::deposit(&mut env.vault.usdt_coins, mint_some<USDT>(10_000_000_000));
    }
}

#[test_only]
module Bridge::TestToken {
    struct TEST_TOKEN has store, drop {}
}