// Copyright (c) Starcoin
// SPDX-License-Identifier: Apache-2.0

module Bridge::Bridge {
    use StarcoinFramework::Timestamp;
    use Bridge::ChainIDs;
    use Bridge::Committee::{Self, BridgeCommittee};
    use Bridge::Limiter::{Self, TransferLimiter};
    use Bridge::Message::{
        Self,
        AddTokenOnStarcoin,
        BridgeMessage,
        BridgeMessageKey,
        EmergencyOp,
        ParsedTokenTransferMessage,
        UpdateAssetPrice,
        UpdateBridgeLimit,
        UpdateCommitteeMember
    };
    use Bridge::MessageTypes;
    use Bridge::Treasury::{Self, BridgeTreasury};

    use StarcoinFramework::Account;
    use StarcoinFramework::BCS;
    use StarcoinFramework::Errors;
    use StarcoinFramework::Event;
    use StarcoinFramework::Option::{Self, Option};
    use StarcoinFramework::Signer;
    use StarcoinFramework::SimpleMap::{Self, SimpleMap};
    use StarcoinFramework::Token::{Self, Token};
    use StarcoinFramework::Vector;

    const MESSAGE_VERSION: u8 = 1;

    // Transfer Status
    const TRANSFER_STATUS_PENDING: u8 = 0;
    const TRANSFER_STATUS_APPROVED: u8 = 1;
    const TRANSFER_STATUS_CLAIMED: u8 = 2;
    const TRANSFER_STATUS_NOT_FOUND: u8 = 3;

    const EVM_ADDRESS_LENGTH: u64 = 20;

    ////////////////////////////////////////////////////
    // Types

    struct Bridge has key {
        id: address,
        // owner
        inner: BridgeInner,
        // version
    }

    struct BridgeInner has store {
        bridge_version: u64,
        message_version: u8,
        chain_id: u8,
        // nonce for replay protection
        // key: message type, value: next sequence number
        sequence_nums: SimpleMap<u8, u64>,
        // committee
        committee: BridgeCommittee,
        // Bridge treasury for mint/burn bridged tokens
        treasury: BridgeTreasury,
        // TODO(VR): replace as table
        token_transfer_records: SimpleMap<BridgeMessageKey, BridgeRecord>,
        limiter: TransferLimiter,
        paused: bool,
        // Claim delay in milliseconds - time to wait after approval before claim is allowed
        claim_delay_ms: u64,
    }

    struct TokenDepositedEvent has copy, drop, store {
        seq_num: u64,
        source_chain: u8,
        sender_address: vector<u8>,
        target_chain: u8,
        target_address: vector<u8>,
        token_type: u8,
        amount: u64,
    }

    struct EmergencyOpEvent has copy, drop, store {
        frozen: bool,
    }

    struct BridgeRecord has drop, store {
        message: BridgeMessage,
        verified_signatures: Option<vector<vector<u8>>>,
        claimed: bool,
        // Timestamp when the transfer was approved (in milliseconds)
        approved_at_ms: u64,
    }

    const EUnexpectedMessageType: u64 = 0;
    const EUnauthorisedClaim: u64 = 1;
    const EMalformedMessageError: u64 = 2;
    const EUnexpectedTokenType: u64 = 3;
    const EUnexpectedChainID: u64 = 4;
    const ENotSystemAddress: u64 = 5;
    const EUnexpectedSeqNum: u64 = 6;
    // const EWrongInnerVersion: u64 = 7;
    const EBridgeUnavailable: u64 = 8;
    const EUnexpectedOperation: u64 = 9;
    const EInvariantStarcoinInitializedTokenTransferShouldNotBeClaimed: u64 = 10;
    const EMessageNotFoundInRecords: u64 = 11;
    const EUnexpectedMessageVersion: u64 = 12;
    const EBridgeAlreadyPaused: u64 = 13;
    const EBridgeNotPaused: u64 = 14;
    const ETokenAlreadyClaimedOrHitLimit: u64 = 15;
    const EInvalidBridgeRoute: u64 = 16;
    const EMustBeTokenMessage: u64 = 17;
    const EInvalidEvmAddress: u64 = 18;
    const ETokenValueIsZero: u64 = 19;
    const ESendTokenExceedLimiter: u64 = 20;
    const ETokenAlreadyRegistered: u64 = 21;
    const ECommitteeAlreadyInitialized: u64 = 22;
    const EClaimDelayNotPassed: u64 = 23;

    const CURRENT_VERSION: u64 = 1;


    struct TokenTransferApproved has copy, drop, store {
        message_key: BridgeMessageKey,
    }

    struct TokenTransferClaimed has copy, drop, store {
        message_key: BridgeMessageKey,
    }

    struct TokenTransferAlreadyApproved has copy, drop, store {
        message_key: BridgeMessageKey,
    }

    struct TokenTransferAlreadyClaimed has copy, drop, store {
        message_key: BridgeMessageKey,
    }

    struct TokenTransferLimitExceed has copy, drop, store {
        message_key: BridgeMessageKey,
    }

    struct EventHandlePod has key, store {
        token_transfer_approved: Event::EventHandle<TokenTransferApproved>,
        token_transfer_claimed: Event::EventHandle<TokenTransferClaimed>,
        token_transfer_already_approved: Event::EventHandle<TokenTransferAlreadyApproved>,
        token_transfer_already_claimed: Event::EventHandle<TokenTransferAlreadyClaimed>,
        token_transfer_limit_exceed: Event::EventHandle<TokenTransferLimitExceed>,
        token_deposited_event: Event::EventHandle<TokenDepositedEvent>,
        emergency_op_event: Event::EventHandle<EmergencyOpEvent>,
    }

    //////////////////////////////////////////////////////
    // Internal initialization functions
    //

    // this method is called once in end of epoch tx to create the bridge
    fun initial_event(bridge: &signer) {
        assert!(Signer::address_of(bridge) == @Bridge, ENotSystemAddress);
        let bridge_addr = Signer::address_of(bridge);
        if (!exists<EventHandlePod>(bridge_addr)) {
            move_to(bridge, EventHandlePod {
                token_transfer_approved: Event::new_event_handle<TokenTransferApproved>(bridge),
                token_transfer_claimed: Event::new_event_handle<TokenTransferClaimed>(bridge),
                token_transfer_already_approved: Event::new_event_handle<TokenTransferAlreadyApproved>(bridge),
                token_transfer_already_claimed: Event::new_event_handle<TokenTransferAlreadyClaimed>(bridge),
                token_transfer_limit_exceed: Event::new_event_handle<TokenTransferLimitExceed>(bridge),
                token_deposited_event: Event::new_event_handle<TokenDepositedEvent>(bridge),
                emergency_op_event: Event::new_event_handle<EmergencyOpEvent>(bridge),
            });
        };
    }

    #[allow(unused_function)]
    public fun create(bridge_admin: &signer, chain_id: u8, claim_delay_ms: u64) {
        assert!(Signer::address_of(bridge_admin) == @Bridge, ENotSystemAddress);
        // Claim delay must be positive
        assert!(claim_delay_ms > 0, EUnexpectedOperation);
        // Max delay: 30 days (30 * 24 * 60 * 60 * 1000 ms = 2592000000 ms)
        assert!(claim_delay_ms <= 2592000000, EUnexpectedOperation);
        let bridge_inner = BridgeInner {
            bridge_version: CURRENT_VERSION,
            message_version: MESSAGE_VERSION,
            chain_id,
            sequence_nums: SimpleMap::create(),
            committee: Committee::create(),
            treasury: Treasury::create(),
            token_transfer_records: SimpleMap::create(),
            limiter: Limiter::new(),
            paused: false,
            claim_delay_ms, // Set at initialization, immutable
        };

        Self::initial_event(bridge_admin);
        Treasury::initialize(bridge_admin);

        move_to(bridge_admin, Bridge {
            id: Signer::address_of(bridge_admin),
            inner: bridge_inner,
        });
    }

    //////////////////////////////////////////////////////
    // Entry functions - callable via execute-function
    //

    /// Initialize the bridge. Must be called once by the Bridge address.
    /// node_chain_id: The Starcoin node chain ID (1=mainnet, 251/252/253=testnet, 254=dev)
    /// This will be automatically converted to Bridge protocol chain ID (0=mainnet, 1=testnet, 2=custom)
    /// claim_delay_ms: Delay in milliseconds between approval and claim (immutable after init)
    public entry fun initialize_bridge(bridge_admin: signer, node_chain_id: u8, claim_delay_ms: u64) {
        assert!(Signer::address_of(&bridge_admin) == @Bridge, ENotSystemAddress);

        // Convert node chain ID to bridge protocol chain ID
        let bridge_chain_id = ChainIDs::starcoin_node_to_bridge_chain_id(node_chain_id);
        // create() handles: Bridge resource, EventHandlePod, Treasury::EventHandler
        create(&bridge_admin, bridge_chain_id, claim_delay_ms);
        // Initialize Committee event handles
        Committee::initialize(&bridge_admin);
        // Initialize Limiter event handles
        Limiter::initialize(&bridge_admin);
    }

    /// Initialize committee with exactly 4 members in a single call.
    /// Convenience function for local dev/test with multi-validator setup.
    /// Must be called by bridge admin after initialize_bridge.
    /// Can only be called once - subsequent calls will fail.
    public entry fun create_committee_four(
        bridge_admin: signer,
        pubkey1: vector<u8>, power1: u64, url1: vector<u8>,
        pubkey2: vector<u8>, power2: u64, url2: vector<u8>,
        pubkey3: vector<u8>, power3: u64, url3: vector<u8>,
        pubkey4: vector<u8>, power4: u64, url4: vector<u8>,
    ) acquires Bridge {
        assert!(Signer::address_of(&bridge_admin) == @Bridge, ENotSystemAddress);
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        // Ensure committee is not already initialized
        assert!(Committee::is_empty(&bridge.inner.committee), ECommitteeAlreadyInitialized);
        Committee::init_committee_four(
            &mut bridge.inner.committee,
            pubkey1, power1, url1,
            pubkey2, power2, url2,
            pubkey3, power3, url3,
            pubkey4, power4, url4,
        );
    }

    /// Script entry for approving token transfer with a single signature
    /// For testing with single validator committee
    public entry fun approve_bridge_token_transfer_single(
        _sender: signer,
        source_chain: u8,
        seq_num: u64,
        sender_address: vector<u8>,
        target_chain: u8,
        target_address: vector<u8>,
        token_type: u8,
        amount: u64,
        signature: vector<u8>,
    ) acquires Bridge, EventHandlePod {
        let message = Message::create_token_bridge_message(
            source_chain,
            seq_num,
            sender_address,
            target_chain,
            target_address,
            token_type,
            amount,
        );
        let signatures = Vector::singleton(signature);
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        approve_token_transfer(bridge, message, signatures);
    }

    /// Script entry for approving token transfer with two signatures
    public entry fun approve_bridge_token_transfer_two(
        _sender: signer,
        source_chain: u8,
        seq_num: u64,
        sender_address: vector<u8>,
        target_chain: u8,
        target_address: vector<u8>,
        token_type: u8,
        amount: u64,
        sig1: vector<u8>,
        sig2: vector<u8>,
    ) acquires Bridge, EventHandlePod {
        let message = Message::create_token_bridge_message(
            source_chain,
            seq_num,
            sender_address,
            target_chain,
            target_address,
            token_type,
            amount,
        );
        let signatures = Vector::empty<vector<u8>>();
        Vector::push_back(&mut signatures, sig1);
        Vector::push_back(&mut signatures, sig2);
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        approve_token_transfer(bridge, message, signatures);
    }

    /// Script entry for approving token transfer with three signatures
    public entry fun approve_bridge_token_transfer_three(
        _sender: signer,
        source_chain: u8,
        seq_num: u64,
        sender_address: vector<u8>,
        target_chain: u8,
        target_address: vector<u8>,
        token_type: u8,
        amount: u64,
        sig1: vector<u8>,
        sig2: vector<u8>,
        sig3: vector<u8>,
    ) acquires Bridge, EventHandlePod {
        let message = Message::create_token_bridge_message(
            source_chain,
            seq_num,
            sender_address,
            target_chain,
            target_address,
            token_type,
            amount,
        );
        let signatures = Vector::empty<vector<u8>>();
        Vector::push_back(&mut signatures, sig1);
        Vector::push_back(&mut signatures, sig2);
        Vector::push_back(&mut signatures, sig3);
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        approve_token_transfer(bridge, message, signatures);
    }

    /// Script entry for claiming tokens after approval (ETH token)
    public entry fun claim_bridge_eth(
        _sender: signer,
        clock_timestamp_ms: u64,
        source_chain: u8,
        bridge_seq_num: u64,
    ) acquires Bridge, EventHandlePod {
        use Bridge::ETH::ETH;
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        claim_and_transfer_token<ETH>(bridge, clock_timestamp_ms, source_chain, bridge_seq_num);
    }

    /// Script entry for claiming tokens after approval (BTC token)
    public entry fun claim_bridge_btc(
        _sender: signer,
        clock_timestamp_ms: u64,
        source_chain: u8,
        bridge_seq_num: u64,
    ) acquires Bridge, EventHandlePod {
        use Bridge::BTC::BTC;
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        claim_and_transfer_token<BTC>(bridge, clock_timestamp_ms, source_chain, bridge_seq_num);
    }

    /// Script entry for claiming tokens after approval (USDC token)
    public entry fun claim_bridge_usdc(
        _sender: signer,
        clock_timestamp_ms: u64,
        source_chain: u8,
        bridge_seq_num: u64,
    ) acquires Bridge, EventHandlePod {
        use Bridge::USDC::USDC;
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        claim_and_transfer_token<USDC>(bridge, clock_timestamp_ms, source_chain, bridge_seq_num);
    }

    /// Script entry for claiming tokens after approval (USDT token)
    public entry fun claim_bridge_usdt(
        _sender: signer,
        clock_timestamp_ms: u64,
        source_chain: u8,
        bridge_seq_num: u64,
    ) acquires Bridge, EventHandlePod {
        use Bridge::USDT::USDT;
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        claim_and_transfer_token<USDT>(bridge, clock_timestamp_ms, source_chain, bridge_seq_num);
    }

    /// Script entry for sending ETH tokens to ETH chain
    public entry fun send_bridge_eth(
        sender: signer,
        target_chain: u8,
        target_address: vector<u8>,
        amount: u128,
    ) acquires Bridge, EventHandlePod {
        use Bridge::ETH::ETH;
        let sender_addr = Signer::address_of(&sender);
        let token = Account::withdraw<ETH>(&sender, amount);
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        send_token<ETH>(bridge, sender_addr, target_chain, target_address, token);
    }

    /// Script entry for sending BTC tokens to ETH chain
    public entry fun send_bridge_btc(
        sender: signer,
        target_chain: u8,
        target_address: vector<u8>,
        amount: u128,
    ) acquires Bridge, EventHandlePod {
        use Bridge::BTC::BTC;
        let sender_addr = Signer::address_of(&sender);
        let token = Account::withdraw<BTC>(&sender, amount);
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        send_token<BTC>(bridge, sender_addr, target_chain, target_address, token);
    }

    /// Script entry for sending USDC tokens to ETH chain
    public entry fun send_bridge_usdc(
        sender: signer,
        target_chain: u8,
        target_address: vector<u8>,
        amount: u128,
    ) acquires Bridge, EventHandlePod {
        use Bridge::USDC::USDC;
        let sender_addr = Signer::address_of(&sender);
        let token = Account::withdraw<USDC>(&sender, amount);
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        send_token<USDC>(bridge, sender_addr, target_chain, target_address, token);
    }

    /// Script entry for sending USDT tokens to ETH chain
    public entry fun send_bridge_usdt(
        sender: signer,
        target_chain: u8,
        target_address: vector<u8>,
        amount: u128,
    ) acquires Bridge, EventHandlePod {
        use Bridge::USDT::USDT;
        let sender_addr = Signer::address_of(&sender);
        let token = Account::withdraw<USDT>(&sender, amount);
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        send_token<USDT>(bridge, sender_addr, target_chain, target_address, token);
    }

    /// Script entry for emergency operations (pause/unpause) with single signature.
    /// Requires the sender to be the bridge admin (@Bridge address).
    public entry fun execute_emergency_op_single(
        bridge_admin: signer,
        source_chain: u8,
        seq_num: u64,
        op_type: u8,
        signature: vector<u8>,
    ) acquires Bridge, EventHandlePod {
        assert!(Signer::address_of(&bridge_admin) == @Bridge, ENotSystemAddress);

        let message = Message::create_emergency_op_message(source_chain, seq_num, op_type);
        let signatures = Vector::singleton(signature);
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        execute_system_message(bridge, message, signatures);
    }

    /// Permissionless entry for emergency operations (pause/unpause) with pre-signed signature.
    /// Any account can call this function - security is guaranteed by committee signature
    /// verification inside `execute_system_message`. The submitter only pays gas.
    /// This allows ops teams to execute pre-signed emergency pauses without holding
    /// the bridge admin key.
    public entry fun execute_emergency_op_permissionless(
        _submitter: signer,
        source_chain: u8,
        seq_num: u64,
        op_type: u8,
        signature: vector<u8>,
    ) acquires Bridge, EventHandlePod {
        let message = Message::create_emergency_op_message(source_chain, seq_num, op_type);
        let signatures = Vector::singleton(signature);
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        execute_system_message(bridge, message, signatures);
    }

    /// Script entry for update bridge limit with single signature
    public entry fun execute_update_limit_single(
        bridge_admin: signer,
        receiving_chain: u8,
        seq_num: u64,
        sending_chain: u8,
        new_limit: u64,
        signature: vector<u8>,
    ) acquires Bridge, EventHandlePod {
        assert!(Signer::address_of(&bridge_admin) == @Bridge, ENotSystemAddress);

        let message = Message::create_update_bridge_limit_message(receiving_chain, seq_num, sending_chain, new_limit);
        let signatures = Vector::singleton(signature);
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        execute_system_message(bridge, message, signatures);
    }

    /// Script entry for blocklist committee member with single signature
    public entry fun execute_blocklist_single(
        bridge_admin: signer,
        source_chain: u8,
        seq_num: u64,
        blocklist_type: u8,
        validator_ecdsa_addresses: vector<vector<u8>>,
        signature: vector<u8>,
    ) acquires Bridge, EventHandlePod {
        assert!(Signer::address_of(&bridge_admin) == @Bridge, ENotSystemAddress);

        let message = Message::create_blocklist_message(source_chain, seq_num, blocklist_type, validator_ecdsa_addresses);
        let signatures = Vector::singleton(signature);
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        execute_system_message(bridge, message, signatures);
    }

    /// Script entry for update committee member (add/remove) with single signature
    /// update_type: 0 = add, 1 = remove
    public entry fun execute_update_committee_member_single(
        bridge_admin: signer,
        source_chain: u8,
        seq_num: u64,
        update_type: u8,
        member_address: address,
        bridge_pubkey_bytes: vector<u8>,
        voting_power: u64,
        http_rest_url: vector<u8>,
        signature: vector<u8>,
    ) acquires Bridge, EventHandlePod {
        assert!(Signer::address_of(&bridge_admin) == @Bridge, ENotSystemAddress);

        let message = Message::create_update_committee_member_message(
            source_chain, seq_num, update_type, member_address, bridge_pubkey_bytes, voting_power, http_rest_url
        );
        let signatures = Vector::singleton(signature);
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        execute_system_message(bridge, message, signatures);
    }

    //////////////////////////////////////////////////////
    // Token Setup Functions - Initialize and register bridge tokens
    //

    /// Setup ETH token (ID: 2) - must be called by bridge admin after contract deployment
    /// Can only be called once - subsequent calls will fail.
    public entry fun setup_eth_token(bridge_admin: signer) acquires Bridge {
        use Bridge::ETH::ETH;
        use Bridge::AssetUtil;

        assert!(Signer::address_of(&bridge_admin) == @Bridge, ENotSystemAddress);
        // Ensure token is not already registered
        assert!(!Treasury::contains_treasury<ETH>(), ETokenAlreadyRegistered);

        let (mint_cap, burn_cap) = AssetUtil::initialize<ETH>(&bridge_admin, 9);
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        Treasury::register_foreign_token<ETH>(&mut bridge.inner.treasury, &bridge_admin, mint_cap, burn_cap);
        // token_type_name is BCS serialized token code
        let token_name = AssetUtil::token_type_name<ETH>();
        // ETH token ID = 2, notional_value = 3000 * 10^8 (3000 USD with 8 decimal places)
        Treasury::add_new_token(&mut bridge.inner.treasury, token_name, 2, 300000000000);
    }

    /// Setup BTC token (ID: 1) - must be called by bridge admin after contract deployment
    /// Can only be called once - subsequent calls will fail.
    public entry fun setup_btc_token(bridge_admin: signer) acquires Bridge {
        use Bridge::BTC::BTC;
        use Bridge::AssetUtil;

        assert!(Signer::address_of(&bridge_admin) == @Bridge, ENotSystemAddress);
        // Ensure token is not already registered
        assert!(!Treasury::contains_treasury<BTC>(), ETokenAlreadyRegistered);

        let (mint_cap, burn_cap) = AssetUtil::initialize<BTC>(&bridge_admin, 9);
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        Treasury::register_foreign_token<BTC>(&mut bridge.inner.treasury, &bridge_admin, mint_cap, burn_cap);
        let token_name = AssetUtil::token_type_name<BTC>();
        // BTC token ID = 1, notional_value = 50000 * 10^8 (50000 USD with 8 decimal places)
        Treasury::add_new_token(&mut bridge.inner.treasury, token_name, 1, 5000000000000);
    }

    /// Setup USDC token (ID: 3) - must be called by bridge admin after contract deployment
    /// Can only be called once - subsequent calls will fail.
    public entry fun setup_usdc_token(bridge_admin: signer) acquires Bridge {
        use Bridge::USDC::USDC;
        use Bridge::AssetUtil;

        assert!(Signer::address_of(&bridge_admin) == @Bridge, ENotSystemAddress);
        // Ensure token is not already registered
        assert!(!Treasury::contains_treasury<USDC>(), ETokenAlreadyRegistered);

        let (mint_cap, burn_cap) = AssetUtil::initialize<USDC>(&bridge_admin, 6);
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        Treasury::register_foreign_token<USDC>(&mut bridge.inner.treasury, &bridge_admin, mint_cap, burn_cap);
        let token_name = AssetUtil::token_type_name<USDC>();
        // USDC token ID = 3, notional_value = 1 * 10^8 (1 USD with 8 decimal places)
        Treasury::add_new_token(&mut bridge.inner.treasury, token_name, 3, 100000000);
    }

    /// Setup USDT token (ID: 4) - must be called by bridge admin after contract deployment
    /// Can only be called once - subsequent calls will fail.
    public entry fun setup_usdt_token(bridge_admin: signer) acquires Bridge {
        use Bridge::USDT::USDT;
        use Bridge::AssetUtil;

        assert!(Signer::address_of(&bridge_admin) == @Bridge, ENotSystemAddress);
        // Ensure token is not already registered
        assert!(!Treasury::contains_treasury<USDT>(), ETokenAlreadyRegistered);

        let (mint_cap, burn_cap) = AssetUtil::initialize<USDT>(&bridge_admin, 6);
        let bridge = borrow_global_mut<Bridge>(@Bridge);
        Treasury::register_foreign_token<USDT>(&mut bridge.inner.treasury, &bridge_admin, mint_cap, burn_cap);
        let token_name = AssetUtil::token_type_name<USDT>();
        // USDT token ID = 4, notional_value = 1 * 10^8 (1 USD with 8 decimal places)
        Treasury::add_new_token(&mut bridge.inner.treasury, token_name, 4, 100000000);
    }

    //////////////////////////////////////////////////////
    // Public functions
    //

    // Create bridge request to send token to other chain, the request will be in
    // pending state until approved
    public fun send_token<T: store>(
        bridge: &mut Bridge,
        sender: address,
        target_chain: u8,
        target_address: vector<u8>,
        token: Token::Token<T>,
    ) acquires EventHandlePod {
        let inner = load_inner_mut(bridge);
        assert!(!inner.paused, EBridgeUnavailable);
        assert!(ChainIDs::is_valid_route(inner.chain_id, target_chain), EInvalidBridgeRoute);
        assert!(Vector::length(&target_address) == EVM_ADDRESS_LENGTH, EInvalidEvmAddress);

        let bridge_seq_num = Self::get_current_seq_num_and_increment(inner, MessageTypes::token());
        let token_id = Treasury::token_id<T>(&inner.treasury);
        let token_amount = (Token::value(&token) as u64);
        assert!(token_amount > 0, ETokenValueIsZero);
        assert!(token_amount < Limiter::default_transfer_limit(), ESendTokenExceedLimiter);

        // create bridge message
        let message = Message::create_token_bridge_message(
            inner.chain_id,
            bridge_seq_num,
            BCS::to_bytes(&sender),
            target_chain,
            target_address,
            token_id,
            token_amount,
        );

        // burn / escrow token, unsupported coins will fail in this step
        Treasury::burn(token);

        // Store pending bridge request
        SimpleMap::add(&mut inner.token_transfer_records,
            Message::key(&message),
            BridgeRecord {
                message,
                verified_signatures: Option::none(),
                claimed: false,
                approved_at_ms: 0, // Not approved yet
            }
        );

        // emit event
        let eh = borrow_global_mut<EventHandlePod>(@Bridge);
        Event::emit_event(&mut eh.token_deposited_event, TokenDepositedEvent {
            seq_num: bridge_seq_num,
            source_chain: inner.chain_id,
            sender_address: BCS::to_bytes(&sender),
            target_chain,
            target_address,
            token_type: token_id,
            amount: token_amount,
        });
    }


    // Record bridge message approvals in Starcoin, called by the bridge client
    // If already approved, return early instead of aborting.
    public fun approve_token_transfer(
        bridge: &mut Bridge,
        message: BridgeMessage,
        signatures: vector<vector<u8>>,
    ) acquires EventHandlePod {
        let eh = borrow_global_mut<EventHandlePod>(@Bridge);
        let inner = load_inner_mut(bridge);
        assert!(!inner.paused, EBridgeUnavailable);

        // verify signatures
        Committee::verify_signatures(&inner.committee, message, signatures);

        assert!(Message::message_type(&message) == MessageTypes::token(), EMustBeTokenMessage);
        assert!(Message::message_version(&message) == MESSAGE_VERSION, EUnexpectedMessageVersion);

        let token_payload = Message::extract_token_bridge_payload(&message);
        let target_chain = Message::token_target_chain(&token_payload);

        assert!(
            Message::source_chain(&message) == inner.chain_id || target_chain == inner.chain_id,
            EUnexpectedChainID,
        );

        let message_key = Message::key(&message);
        let current_time_ms = Timestamp::now_milliseconds();
        
        // retrieve pending message if source chain is Starcoin, the initial message
        // must exist on chain
        if (Message::source_chain(&message) == inner.chain_id) {
            let record = SimpleMap::borrow_mut(&mut inner.token_transfer_records, &message_key);

            assert!(record.message == message, EMalformedMessageError);
            assert!(!record.claimed, EInvariantStarcoinInitializedTokenTransferShouldNotBeClaimed);

            // If record already has verified signatures, it means the message has been approved
            // Then we exit early.
            if (Option::is_some(&record.verified_signatures)) {
                Event::emit_event(
                    &mut eh.token_transfer_already_approved,
                    TokenTransferAlreadyApproved { message_key }
                );
                return
            };
            // Store approval with timestamp
            record.verified_signatures = Option::some(signatures);
            record.approved_at_ms = current_time_ms;
        } else {
            // At this point, if this message is in token_transfer_records, we know
            // it's already approved because we only add a message to token_transfer_records
            // after verifying the signatures
            if (SimpleMap::contains_key(&mut inner.token_transfer_records, &message_key)) {
                Event::emit_event(
                    &mut eh.token_transfer_already_approved,
                    TokenTransferAlreadyApproved { message_key }
                );
                return
            };
            // Store message and approval with timestamp
            SimpleMap::add(&mut inner.token_transfer_records,
                message_key,
                BridgeRecord {
                    message,
                    verified_signatures: Option::some(signatures),
                    claimed: false,
                    approved_at_ms: current_time_ms,
                },
            );
        };
        Event::emit_event(&mut eh.token_transfer_approved, TokenTransferApproved { message_key });
    }


    // This function can only be called by the token recipient
    // Abort if the token has already been claimed or hits limiter currently,
    // in which case, no event will be emitted and only abort code will be returned.
    public fun claim_token<T: store>(
        sender: &signer,
        bridge: &mut Bridge,
        clock_timestamp_ms: u64,
        source_chain: u8,
        bridge_seq_num: u64,
    ): Token::Token<T> acquires EventHandlePod {
        let (maybe_token, owner) = Self::claim_token_internal<T>(
            bridge,
            clock_timestamp_ms,
            source_chain,
            bridge_seq_num,
        );
        // Only token owner can claim the token
        assert!(Signer::address_of(sender) == owner, EUnauthorisedClaim);
        assert!(Option::is_some(&maybe_token), ETokenAlreadyClaimedOrHitLimit);
        Option::destroy_some(maybe_token)
    }

    // This function can be called by anyone to claim and transfer the token to the recipient
    // If the token has already been claimed or hits limiter currently, it will return instead of aborting.
    public fun claim_and_transfer_token<T: store>(
        bridge: &mut Bridge,
        _clock_timestamp_ms: u64,
        source_chain: u8,
        bridge_seq_num: u64,
    ) acquires EventHandlePod {
        let clock_timetamp_ms = Timestamp::now_milliseconds();
        let (token, owner) = Self::claim_token_internal<T>(bridge, clock_timetamp_ms, source_chain, bridge_seq_num);
        if (Option::is_some(&token)) {
            Account::deposit(owner, Option::destroy_some(token));
        } else {
            Option::destroy_none(token)
        }
    }

    public fun execute_system_message(
        bridge: &mut Bridge,
        message: BridgeMessage,
        signatures: vector<vector<u8>>,
    ) acquires EventHandlePod {
        let message_type = Message::message_type(&message);

        // Verify message version matches expected version
        assert!(Message::message_version(&message) == MESSAGE_VERSION, EUnexpectedMessageVersion);
        let inner = load_inner_mut(bridge);

        assert!(Message::source_chain(&message) == inner.chain_id, EUnexpectedChainID);

        // check system ops seq number and increment it
        let expected_seq_num = Self::get_current_seq_num_and_increment(inner, message_type);
        assert!(Message::seq_num(&message) == expected_seq_num, EUnexpectedSeqNum);

        Committee::verify_signatures(&inner.committee, message, signatures);

        if (message_type == MessageTypes::emergency_op()) {
            let payload = Message::extract_emergency_op_payload(&message);
            Self::execute_emergency_op(inner, payload);
        } else if (message_type == MessageTypes::committee_blocklist()) {
            let payload = Message::extract_blocklist_payload(&message);
            Committee::execute_blocklist(&mut inner.committee, payload);
        } else if (message_type == MessageTypes::update_bridge_limit()) {
            let payload = Message::extract_update_bridge_limit(&message);
            Self::execute_update_bridge_limit(inner, payload);
        } else if (message_type == MessageTypes::update_asset_price()) {
            let payload = Message::extract_update_asset_price(&message);
            Self::execute_update_asset_price(inner, payload);
        } else if (message_type == MessageTypes::add_tokens_on_starcoin()) {
            let payload = Message::extract_add_tokens_on_starcoin(&message);
            Self::execute_add_tokens_on_starcoin(inner, payload);
        } else if (message_type == MessageTypes::update_committee_member()) {
            let payload = Message::extract_update_committee_member(&message);
            Self::execute_update_committee_member(inner, payload);
        } else {
            abort EUnexpectedMessageType
        };
    }


    //////////////////////////////////////////////////////
    // DevInspect Functions for Read
    //

    #[allow(unused_function)]
    fun get_token_transfer_action_status(bridge: &Bridge, source_chain: u8, bridge_seq_num: u64): u8 {
        let inner = load_inner(bridge);
        let key = Message::create_key(
            source_chain,
            MessageTypes::token(),
            bridge_seq_num,
        );

        if (!SimpleMap::contains_key(&inner.token_transfer_records, &key)) {
            return TRANSFER_STATUS_NOT_FOUND
        };

        let record = SimpleMap::borrow(&inner.token_transfer_records, &key);
        if (record.claimed) {
            return TRANSFER_STATUS_CLAIMED
        };

        if (Option::is_some(&record.verified_signatures)) {
            return TRANSFER_STATUS_APPROVED
        };

        TRANSFER_STATUS_PENDING
    }

    #[allow(unused_function)]
    fun get_token_transfer_action_signatures(
        bridge: &Bridge,
        source_chain: u8,
        bridge_seq_num: u64,
    ): Option<vector<vector<u8>>> {
        let inner = load_inner(bridge);
        let key = Message::create_key(
            source_chain,
            MessageTypes::token(),
            bridge_seq_num,
        );

        if (!SimpleMap::contains_key(&inner.token_transfer_records, &key)) {
            return Option::none()
        };

        let record = SimpleMap::borrow(&inner.token_transfer_records, &key);
        record.verified_signatures
    }

    // //////////////////////////////////////////////////////
    // // Internal functions

    fun load_inner(bridge: &Bridge): &BridgeInner {
        &bridge.inner
    }

    fun load_inner_mut(bridge: &mut Bridge): &mut BridgeInner {
        &mut bridge.inner
    }

    //////////////////////////////////////////////////////
    // Public Query Functions (for RPC calls)
    //

    /// Query the status of a token transfer action
    /// Returns: 0 = PENDING, 1 = APPROVED, 2 = CLAIMED, 3 = NOT_FOUND
    public fun query_token_transfer_status(
        source_chain: u8,
        bridge_seq_num: u64,
    ): u8 acquires Bridge {
        let bridge = borrow_global<Bridge>(@Bridge);
        get_token_transfer_action_status(bridge, source_chain, bridge_seq_num)
    }

    /// Query the signatures of a token transfer action
    public fun query_token_transfer_signatures(
        source_chain: u8,
        bridge_seq_num: u64,
    ): Option<vector<vector<u8>>> acquires Bridge {
        let bridge = borrow_global<Bridge>(@Bridge);
        get_token_transfer_action_signatures(bridge, source_chain, bridge_seq_num)
    }

    // Claim token from approved bridge message
    // Returns Some(Coin) if coin can be claimed. If already claimed, return None
    fun claim_token_internal<T: store>(
        bridge: &mut Bridge,
        clock_timestamp_ms: u64,
        source_chain: u8,
        bridge_seq_num: u64,
    ): (Option<Token<T>>, address) acquires EventHandlePod {
        let eh = borrow_global_mut<EventHandlePod>(@Bridge);

        let inner = load_inner_mut(bridge);
        assert!(!inner.paused, EBridgeUnavailable);

        let key = Message::create_key(source_chain, MessageTypes::token(), bridge_seq_num);
        assert!(SimpleMap::contains_key(&inner.token_transfer_records, &key), EMessageNotFoundInRecords);

        // retrieve approved bridge message
        let record = SimpleMap::borrow_mut(&mut inner.token_transfer_records, &key);
        // ensure this is a token bridge message
        assert!(Message::message_type(&record.message) == MessageTypes::token(), EUnexpectedMessageType);
        // Ensure it's signed
        assert!(Option::is_some(&record.verified_signatures), EUnauthorisedClaim);

        // Check claim delay has passed
        assert!(
            clock_timestamp_ms >= record.approved_at_ms + inner.claim_delay_ms,
            EClaimDelayNotPassed
        );

        // extract token message
        let token_payload = Message::extract_token_bridge_payload(&record.message);
        // get owner address
        let owner = BCS::to_address(Message::token_target_address(&token_payload));

        // If already claimed, exit early
        if (record.claimed) {
            Event::emit_event(
                &mut eh.token_transfer_already_claimed,
                TokenTransferAlreadyClaimed { message_key: key }
            );
            return (Option::none(), owner)
        };

        let target_chain = Message::token_target_chain(&token_payload);
        // ensure target chain matches bridge.chain_id
        assert!(target_chain == inner.chain_id, EUnexpectedChainID);

        // Defense-in-depth: validate the route is registered even after signature verification.
        // `get_route` aborts if route is invalid, preventing token minting on unknown routes.
        let route = ChainIDs::get_route(source_chain, target_chain);
        // check token type
        assert!(
            Treasury::token_id<T>(&inner.treasury) == Message::token_type(&token_payload),
            EUnexpectedTokenType,
        );

        let amount = Message::token_amount(&token_payload);

        // Make sure transfer is within limit.
        // check_and_record_sending_transfer returns true if within limit, false if exceeded
        let within_limit = Limiter::check_and_record_sending_transfer<T>(
            &mut inner.limiter,
            &inner.treasury,
            clock_timestamp_ms,
            route,
            amount,
        );

        if (!within_limit) {
            Event::emit_event(&mut eh.token_transfer_limit_exceed, TokenTransferLimitExceed { message_key: key });
            return (Option::none(), owner)
        };

        // claim from treasury
        let token = Treasury::mint<T>(amount);

        // Record changes
        record.claimed = true;
        Event::emit_event(&mut eh.token_transfer_claimed, TokenTransferClaimed { message_key: key });

        (Option::some(token), owner)
    }


    fun execute_emergency_op(inner: &mut BridgeInner, payload: EmergencyOp) acquires EventHandlePod {
        let ehp = borrow_global_mut<EventHandlePod>(@Bridge);
        let op = Message::emergency_op_type(&payload);
        if (op == Message::emergency_op_pause()) {
            assert!(!inner.paused, EBridgeAlreadyPaused);
            inner.paused = true;
            Event::emit_event(&mut ehp.emergency_op_event, EmergencyOpEvent { frozen: true });
        } else if (op == Message::emergency_op_unpause()) {
            assert!(inner.paused, EBridgeNotPaused);
            inner.paused = false;
            Event::emit_event(&mut ehp.emergency_op_event, EmergencyOpEvent { frozen: false });
        } else {
            abort EUnexpectedOperation
        };
    }

    fun execute_update_bridge_limit(inner: &mut BridgeInner, payload: UpdateBridgeLimit) {
        let receiving_chain = Message::update_bridge_limit_payload_receiving_chain(&payload);
        assert!(receiving_chain == inner.chain_id, EUnexpectedChainID);
        let route = ChainIDs::get_route(
            Message::update_bridge_limit_payload_sending_chain(&payload),
            receiving_chain,
        );

        Limiter::update_route_limit(
            &mut inner.limiter,
            &route,
            Message::update_bridge_limit_payload_limit(&payload),
        );
    }

    fun execute_update_asset_price(inner: &mut BridgeInner, payload: UpdateAssetPrice) {
        Treasury::update_asset_notional_price(
            &mut inner.treasury,
            Message::update_asset_price_payload_token_id(&payload),
            Message::update_asset_price_payload_new_price(&payload),
        );
    }

    fun execute_add_tokens_on_starcoin(inner: &mut BridgeInner, payload: AddTokenOnStarcoin) {
        let native_token = Message::is_native(&payload);
        // Native token addition is a NO-OP for now
        if (native_token) {
            return
        };
        let token_ids = Message::token_ids(&payload);
        let token_type_names = Message::token_type_names(&payload);
        let token_prices = Message::token_prices(&payload);

        // Make sure token data is consistent
        assert!(
            Vector::length(&token_ids) == Vector::length(&token_type_names),
            Errors::invalid_state(EMalformedMessageError)
        );
        assert!(
            Vector::length(&token_ids) == Vector::length(&token_prices),
            Errors::invalid_state(EMalformedMessageError)
        );

        while (Vector::length(&token_ids) > 0) {
            let token_id = Vector::pop_back(&mut token_ids);
            let token_type_name = Vector::pop_back(&mut token_type_names);
            let token_price = Vector::pop_back(&mut token_prices);
            Treasury::add_new_token(&mut inner.treasury, token_type_name, token_id, token_price);
        }
    }

    /// Execute update committee member action (add member only)
    /// update_type: 0 = add (for remove, use blocklist action instead)
    fun execute_update_committee_member(inner: &mut BridgeInner, payload: UpdateCommitteeMember) {
        let update_type = Message::update_committee_member_type(&payload);
        let bridge_pubkey_bytes = Message::update_committee_member_pubkey(&payload);
        let voting_power = Message::update_committee_member_voting_power(&payload);
        let http_rest_url = Message::update_committee_member_http_url(&payload);

        // Only support add operation (update_type == 0)
        // For removing members, use the blocklist action instead
        assert!(update_type == 0, EUnexpectedOperation);

        Committee::add_member(
            &mut inner.committee,
            bridge_pubkey_bytes,
            voting_power,
            http_rest_url,
        );
    }

    //
    // Verify seq number matches the next expected seq number for the message type,
    // and increment it.
    fun get_current_seq_num_and_increment(bridge: &mut BridgeInner, msg_type: u8): u64 {
        if (!SimpleMap::contains_key(&bridge.sequence_nums, &msg_type)) {
            SimpleMap::add(&mut bridge.sequence_nums, msg_type, 1);
            return 0
        };

        let entry = SimpleMap::borrow_mut(&mut bridge.sequence_nums, &msg_type);
        let seq_num = *entry;
        *entry = seq_num + 1;
        seq_num
    }

    #[allow(unused_function)]
    fun get_parsed_token_transfer_message(
        bridge: &Bridge,
        source_chain: u8,
        bridge_seq_num: u64,
    ): Option<ParsedTokenTransferMessage> {
        let inner = Self::load_inner(bridge);
        let key = Message::create_key(
            source_chain,
            MessageTypes::token(),
            bridge_seq_num,
        );

        if (!SimpleMap::contains_key(&inner.token_transfer_records, &key)) {
            return Option::none()
        };

        let record = SimpleMap::borrow(&inner.token_transfer_records, &key);
        let message = &record.message;
        Option::some(Message::to_parsed_token_transfer_message(message))
    }

    //////////////////////////////////////////////////////
    // Test functions
    //

    // Mint some coins
    #[test_only]
    public fun mint_some<T: store>(amount: u64): Token::Token<T> {
        Treasury::mint(amount)
    }

    #[test_only]
    public fun get_total_supply<T: store>(): u64 {
        (Token::market_cap<T>() as u64)
    }

    #[test_only]
    /// Test-only: register a foreign token directly on bridge (bypasses entry function)
    public fun register_foreign_token<T: store>(
        bridge: &mut Bridge,
        bridge_admin: &signer,
        mint_cap: Token::MintCapability<T>,
        burn_cap: Token::BurnCapability<T>,
    ) {
        Treasury::register_foreign_token<T>(&mut bridge.inner.treasury, bridge_admin, mint_cap, burn_cap);
    }

    #[test_only]
    public fun new_for_testing(chain_id: u8, addr: address): Bridge {
        let inner = BridgeInner {
            bridge_version: CURRENT_VERSION,
            message_version: MESSAGE_VERSION,
            chain_id,
            sequence_nums: SimpleMap::create<u8, u64>(),
            committee: Committee::create(),
            treasury: Treasury::create(),
            token_transfer_records: SimpleMap::create<BridgeMessageKey, BridgeRecord>(),
            limiter: Limiter::new(),
            paused: false,
            claim_delay_ms: 0,
        };
        let bridge = Bridge {
            id: addr,
            inner,
        };
        Treasury::setup_for_testing(&mut bridge.inner.treasury);
        bridge
    }

    public fun destroy_for_testing(bridge: Bridge) {
        let Bridge {
            id: _,
            inner: inner,
        } = bridge;

        let BridgeInner {
            bridge_version: _,
            message_version: _,
            chain_id: _,
            sequence_nums: _,
            committee,
            treasury,
            token_transfer_records: _,
            limiter,
            paused: _,
            claim_delay_ms: _,
        } = inner;

        Limiter::destroy(limiter);
        Treasury::destroy(treasury);
        Committee::destroy(committee);
    }

    #[test_only]
    public fun new_bridge_record_for_testing(
        message: BridgeMessage,
        verified_signatures: Option<vector<vector<u8>>>,
        claimed: bool,
    ): BridgeRecord {
        BridgeRecord {
            message,
            verified_signatures,
            claimed,
            approved_at_ms: 0,
        }
    }

    #[test_only]
    public fun test_load_inner_mut(bridge: &mut Bridge): &mut BridgeInner {
        &mut bridge.inner
    }

    #[test_only]
    public fun test_load_inner(bridge: &Bridge): &BridgeInner {
        &bridge.inner
    }


    #[test_only]
    public fun test_get_token_transfer_action_status(
        bridge: &mut Bridge,
        source_chain: u8,
        bridge_seq_num: u64,
    ): u8 {
        Self::get_token_transfer_action_status(bridge, source_chain, bridge_seq_num)
    }

    #[test_only]
    public fun test_get_token_transfer_action_signatures(
        bridge: &mut Bridge,
        source_chain: u8,
        bridge_seq_num: u64,
    ): Option<vector<vector<u8>>> {
        Self::get_token_transfer_action_signatures(bridge, source_chain, bridge_seq_num)
    }

    #[test_only]
    public fun test_get_parsed_token_transfer_message(
        bridge: &Bridge,
        source_chain: u8,
        bridge_seq_num: u64,
    ): Option<ParsedTokenTransferMessage> {
        Self::get_parsed_token_transfer_message(bridge, source_chain, bridge_seq_num)
    }

    #[test_only]
    public fun inner_limiter(bridge_inner: &BridgeInner): &TransferLimiter {
        &bridge_inner.limiter
    }

    #[test_only]
    public fun inner_treasury(bridge_inner: &BridgeInner): &BridgeTreasury {
        &bridge_inner.treasury
    }

    #[test_only]
    public fun inner_treasury_mut(bridge_inner: &mut BridgeInner): &mut BridgeTreasury {
        &mut bridge_inner.treasury
    }

    #[test_only]
    public fun inner_paused(bridge_inner: &BridgeInner): bool {
        bridge_inner.paused
    }

    #[test_only]
    public fun inner_committee_mut(bridge_inner: &mut BridgeInner): &mut BridgeCommittee {
        &mut bridge_inner.committee
    }

    #[test_only]
    public fun inner_token_transfer_records(
        bridge_inner: &BridgeInner,
    ): &SimpleMap<BridgeMessageKey, BridgeRecord> {
        &bridge_inner.token_transfer_records
    }

    #[test_only]
    public fun inner_token_transfer_records_mut(
        bridge_inner: &mut BridgeInner,
    ): &mut SimpleMap<BridgeMessageKey, BridgeRecord> {
        &mut bridge_inner.token_transfer_records
    }

    #[test_only]
    public fun test_execute_emergency_op(bridge_inner: &mut BridgeInner, payload: EmergencyOp) acquires EventHandlePod {
        Self::execute_emergency_op(bridge_inner, payload)
    }

    #[test_only]
    public fun sequence_nums(bridge_inner: &BridgeInner): &SimpleMap<u8, u64> {
        &bridge_inner.sequence_nums
    }

    #[test_only]
    public fun assert_paused(bridge_inner: &BridgeInner, error: u64) {
        assert!(bridge_inner.paused, error);
    }

    #[test_only]
    public fun assert_not_paused(bridge_inner: &BridgeInner, error: u64) {
        assert!(!bridge_inner.paused, error);
    }

    #[test_only]
    public fun set_claim_delay_for_testing(bridge: &mut Bridge, delay_ms: u64) {
        bridge.inner.claim_delay_ms = delay_ms;
    }

    #[test_only]
    public fun get_claim_delay(bridge: &Bridge): u64 {
        bridge.inner.claim_delay_ms
    }

    #[test_only]
    public fun test_get_current_seq_num_and_increment(
        bridge_inner: &mut BridgeInner,
        msg_type: u8,
    ): u64 {
        get_current_seq_num_and_increment(bridge_inner, msg_type)
    }

    #[test_only]
    public fun test_execute_update_bridge_limit(inner: &mut BridgeInner, payload: UpdateBridgeLimit) {
        execute_update_bridge_limit(inner, payload)
    }

    #[test_only]
    public fun test_execute_update_asset_price(inner: &mut BridgeInner, payload: UpdateAssetPrice) {
        execute_update_asset_price(inner, payload)
    }

    #[test_only]
    public fun transfer_status_pending(): u8 {
        TRANSFER_STATUS_PENDING
    }

    #[test_only]
    public fun transfer_status_approved(): u8 {
        TRANSFER_STATUS_APPROVED
    }

    #[test_only]
    public fun transfer_status_claimed(): u8 {
        TRANSFER_STATUS_CLAIMED
    }

    #[test_only]
    public fun transfer_status_not_found(): u8 {
        TRANSFER_STATUS_NOT_FOUND
    }

    #[test_only]
    public fun test_execute_add_tokens_on_starcoin(bridge: &mut Bridge, payload: AddTokenOnStarcoin) {
        let inner = load_inner_mut(bridge);
        Self::execute_add_tokens_on_starcoin(inner, payload);
    }

    #[test_only]
    public fun get_seq_num_for(bridge: &mut Bridge, message_type: u8): u64 {
        let inner = load_inner_mut(bridge);
        let seq_num = if (SimpleMap::contains_key(&inner.sequence_nums, &message_type)) {
            *SimpleMap::borrow(&inner.sequence_nums, &message_type)
        } else {
            SimpleMap::add(&mut inner.sequence_nums, message_type, 0);
            0
        };
        seq_num
    }

    #[test_only]
    public fun get_seq_num_inc_for(bridge: &mut Bridge, message_type: u8): u64 {
        let inner = load_inner_mut(bridge);
        Self::get_current_seq_num_and_increment(inner, message_type)
    }

    #[test_only]
    public fun transfer_approve_key(event: TokenTransferApproved): BridgeMessageKey {
        event.message_key
    }

    #[test_only]
    public fun transfer_claimed_key(event: TokenTransferClaimed): BridgeMessageKey {
        event.message_key
    }

    #[test_only]
    public fun transfer_already_approved_key(event: TokenTransferAlreadyApproved): BridgeMessageKey {
        event.message_key
    }

    #[test_only]
    public fun transfer_already_claimed_key(event: TokenTransferAlreadyClaimed): BridgeMessageKey {
        event.message_key
    }

    #[test_only]
    public fun transfer_limit_exceed_key(event: TokenTransferLimitExceed): BridgeMessageKey {
        event.message_key
    }

    #[test_only]
    public fun unwrap_deposited_event(
        event: TokenDepositedEvent,
    ): (u64, u8, vector<u8>, u8, vector<u8>, u8, u64) {
        (
            event.seq_num,
            event.source_chain,
            event.sender_address,
            event.target_chain,
            event.target_address,
            event.token_type,
            event.amount,
        )
    }

    #[test_only]
    public fun unwrap_emergency_op_event(event: EmergencyOpEvent): bool {
        event.frozen
    }

    #[test_only]
    /// Initialize all global resources required for testing.
    /// This includes Bridge::EventHandlePod, Treasury::EventHandler, and Limiter::EventHandlePod.
    public fun initialize_for_testing(bridge_admin: &signer) {
        let bridge_addr = Signer::address_of(bridge_admin);
        // Initialize Bridge event handles
        if (!exists<EventHandlePod>(bridge_addr)) {
            initial_event(bridge_admin);
        };
        // Initialize Committee event handles
        Committee::initialize_for_testing(bridge_admin);
        // Initialize Treasury event handles
        Treasury::initialize_for_testing(bridge_admin);
        // Initialize Limiter event handles
        Limiter::initialize_for_testing(bridge_admin);
    }

    #[test_only]
    /// Create a bridge for testing with all global resources initialized.
    public fun create_bridge_for_testing(bridge_admin: &signer, chain_id: u8) {
        Self::initialize_for_testing(bridge_admin);
        
        let bridge_inner = BridgeInner {
            bridge_version: CURRENT_VERSION,
            message_version: MESSAGE_VERSION,
            chain_id,
            sequence_nums: SimpleMap::create(),
            committee: Committee::create(),
            treasury: Treasury::create(),
            token_transfer_records: SimpleMap::create(),
            limiter: Limiter::new(),
            paused: false,
            claim_delay_ms: 0,
        };

        move_to(bridge_admin, Bridge {
            id: Signer::address_of(bridge_admin),
            inner: bridge_inner,
        });
    }

    #[test_only]
    /// Execute a system message WITHOUT signature verification.
    /// This is only used for testing when secp256k1_sign native function is unavailable.
    public fun execute_system_message_for_testing(
        bridge: &mut Bridge,
        message: BridgeMessage,
    ) acquires EventHandlePod {
        let message_type = Message::message_type(&message);

        assert!(Message::message_version(&message) == MESSAGE_VERSION, EUnexpectedMessageVersion);
        let inner = load_inner_mut(bridge);

        assert!(Message::source_chain(&message) == inner.chain_id, EUnexpectedChainID);

        // check system ops seq number and increment it
        let expected_seq_num = Self::get_current_seq_num_and_increment(inner, message_type);
        assert!(Message::seq_num(&message) == expected_seq_num, EUnexpectedSeqNum);

        // Skip signature verification for testing

        if (message_type == MessageTypes::emergency_op()) {
            let payload = Message::extract_emergency_op_payload(&message);
            Self::execute_emergency_op(inner, payload);
        } else if (message_type == MessageTypes::committee_blocklist()) {
            let payload = Message::extract_blocklist_payload(&message);
            Committee::execute_blocklist(&mut inner.committee, payload);
        } else if (message_type == MessageTypes::update_bridge_limit()) {
            let payload = Message::extract_update_bridge_limit(&message);
            Self::execute_update_bridge_limit(inner, payload);
        } else if (message_type == MessageTypes::update_asset_price()) {
            let payload = Message::extract_update_asset_price(&message);
            Self::execute_update_asset_price(inner, payload);
        } else if (message_type == MessageTypes::add_tokens_on_starcoin()) {
            let payload = Message::extract_add_tokens_on_starcoin(&message);
            Self::execute_add_tokens_on_starcoin(inner, payload);
        } else if (message_type == MessageTypes::update_committee_member()) {
            let payload = Message::extract_update_committee_member(&message);
            Self::execute_update_committee_member(inner, payload);
        } else {
            abort EUnexpectedMessageType
        };
    }
}