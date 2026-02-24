// Copyright (c) Starcoin Contributors
// SPDX-License-Identifier: Apache-2.0

module Bridge::Treasury {
    use StarcoinFramework::Math;
    use StarcoinFramework::BCS;
    use StarcoinFramework::Errors;
    use StarcoinFramework::Event;
    use StarcoinFramework::Signer;
    use StarcoinFramework::SimpleMap::{Self, SimpleMap};
    use StarcoinFramework::Token;

    friend Bridge::Bridge;

    const EUnsupportedTokenType: u64 = 1;
    const EInvalidUpgradeCap: u64 = 2;
    const ETokenSupplyNonZero: u64 = 3;
    const EInvalidNotionalValue: u64 = 4;
    const EInvalidSigner: u64 = 5;
    const ETreasuryTokenNotExists: u64 = 6;

    #[test_only]
    const USD_VALUE_MULTIPLIER: u64 = 100000000; // 8 DP accuracy

    //////////////////////////////////////////////////////
    // Types
    //
    struct BridgeTreasury has key, store {
        // token treasuries, values are TreasuryCaps for native bridge V1.
        // treasuries: ObjectBag,
        supported_tokens: SimpleMap<vector<u8>, BridgeTokenMetadata>,
        // Mapping token id to type name
        id_token_type_map: SimpleMap<u8, vector<u8>>,
        // Storing potential new token waiting to be approved
        waiting_room: SimpleMap<vector<u8>, ForeignTokenRegistration>,
    }

    struct BridgeTokenMetadata has copy, drop, store {
        id: u8,
        decimal_multiplier: u64,
        notional_value: u64,
        native_token: bool,
    }

    struct BridgeTreasuryCap<phantom T> has key {
        mint_cap: Token::MintCapability<T>,
        burn_cap: Token::BurnCapability<T>
    }

    struct ForeignTokenRegistration has store, drop {
        type_name: vector<u8>,
        decimal: u8,
    }

    struct UpdateTokenPriceEvent has store, copy, drop {
        token_id: u8,
        new_price: u64,
    }

    struct NewTokenEvent has store, copy, drop {
        token_id: u8,
        type_name: vector<u8>,
        native_token: bool,
        decimal_multiplier: u64,
        notional_value: u64,
    }

    struct TokenRegistrationEvent has store, copy, drop {
        type_name: vector<u8>,
        decimal: u8,
        native_token: bool,
    }

    struct EventHandler has key {
        update_token_price_event_handler: Event::EventHandle<UpdateTokenPriceEvent>,
        new_token_event_handler: Event::EventHandle<NewTokenEvent>,
        token_registration_event_handler: Event::EventHandle<TokenRegistrationEvent>,
    }

    public fun token_id<T: store>(self: &BridgeTreasury): u8 {
        let metadata = Self::get_token_metadata<T>(self);
        metadata.id
    }

    public fun decimal_multiplier<T: store>(self: &BridgeTreasury): u64 {
        let metadata = Self::get_token_metadata<T>(self);
        metadata.decimal_multiplier
    }

    public fun notional_value<T: store>(self: &BridgeTreasury): u64 {
        let metadata = Self::get_token_metadata<T>(self);
        metadata.notional_value
    }

    public fun initialize(bridge_admin: &signer) {
        assert!(Signer::address_of(bridge_admin) == @Bridge, EInvalidSigner);
        let bridge_addr = Signer::address_of(bridge_admin);
        if (!exists<EventHandler>(bridge_addr)) {
            move_to(bridge_admin, EventHandler {
                update_token_price_event_handler: Event::new_event_handle<UpdateTokenPriceEvent>(bridge_admin),
                new_token_event_handler: Event::new_event_handle<NewTokenEvent>(bridge_admin),
                token_registration_event_handler: Event::new_event_handle<TokenRegistrationEvent>(bridge_admin),
            });
        };
    }

    public fun create(): BridgeTreasury {
        BridgeTreasury {
            supported_tokens: SimpleMap::create<vector<u8>, BridgeTokenMetadata>(),
            id_token_type_map: SimpleMap::create<u8, vector<u8>>(),
            waiting_room: SimpleMap::create<vector<u8>, ForeignTokenRegistration>(),
        }
    }

    public fun destroy(t: BridgeTreasury) {
        let BridgeTreasury { supported_tokens: _, id_token_type_map: _, waiting_room: _ } = t;
    }

    public fun contains_treasury<T: store>(): bool {
        exists<BridgeTreasuryCap<T>>(@Bridge)
    }

    //////////////////////////////////////////////////////
    // Internal functions
    //
    fun get_decimal<T: store>(): u8 {
        // Calculate decimal from Token's scaling_factor
        // scaling_factor = 10^precision, so we need to find the exponent
        let scaling_factor = Token::scaling_factor<T>();
        let decimal: u8 = 0;
        let factor = scaling_factor;
        while (factor > 1) {
            factor = factor / 10;
            decimal = decimal + 1;
        };
        decimal
    }


    public fun register_foreign_token<T: store>(
        self: &mut BridgeTreasury,
        bridge_admin: &signer,
        mint_cap: Token::MintCapability<T>,
        burn_cap: Token::BurnCapability<T>,
    ) acquires EventHandler {
        // Make sure TreasuryCap has not been minted before.
        assert!(Token::market_cap<T>() == 0, ETokenSupplyNonZero);

        let type_name = BCS::to_bytes(&Token::token_code<T>());

        SimpleMap::add(&mut self.waiting_room, type_name, ForeignTokenRegistration {
            type_name,
            decimal: Self::get_decimal<T>(),
        });

        move_to(bridge_admin, BridgeTreasuryCap<T> {
            mint_cap,
            burn_cap,
        });

        let eh = borrow_global_mut<EventHandler>(@Bridge);
        Event::emit_event(&mut eh.token_registration_event_handler, TokenRegistrationEvent {
            type_name,
            decimal: Self::get_decimal<T>(),
            native_token: false,
        });
    }

    public fun add_new_token(
        self: &mut BridgeTreasury,
        token_name: vector<u8>,
        token_id: u8,
        notional_value: u64,
    ) acquires EventHandler {
        assert!(notional_value > 0, EInvalidNotionalValue);
        let (_key, ForeignTokenRegistration {
            type_name,
            decimal,
        }) = SimpleMap::remove(&mut self.waiting_room, &token_name);

        let decimal_multiplier = (Math::pow(10u64, (decimal as u64)) as u64);
        let token_metadata = BridgeTokenMetadata {
            id: token_id,
            decimal_multiplier,
            notional_value,
            native_token: false,
        };

        SimpleMap::add(&mut self.supported_tokens, type_name, token_metadata);
        SimpleMap::add(&mut self.id_token_type_map, token_id, type_name);

        let event_handler = borrow_global_mut<EventHandler>(@Bridge);
        Event::emit_event(&mut event_handler.new_token_event_handler, NewTokenEvent {
            token_id,
            type_name,
            native_token: false,
            decimal_multiplier,
            notional_value,
        })
    }

    public(friend) fun burn<T: store>(token: Token::Token<T>) acquires BridgeTreasuryCap {
        assert!(exists<BridgeTreasuryCap<T>>(@Bridge), ETreasuryTokenNotExists);
        let tt = borrow_global_mut<BridgeTreasuryCap<T>>(@Bridge);
        Token::burn_with_capability<T>(&tt.burn_cap, token);
    }

    public(friend) fun mint<T: store>(amount: u64): Token::Token<T> acquires BridgeTreasuryCap {
        assert!(exists<BridgeTreasuryCap<T>>(@Bridge), ETreasuryTokenNotExists);
        let tt = borrow_global_mut<BridgeTreasuryCap<T>>(@Bridge);
        Token::mint_with_capability<T>(&tt.mint_cap, (amount as u128))
    }

    public fun update_asset_notional_price(
        self: &mut BridgeTreasury,
        token_id: u8,
        new_usd_price: u64,
    ) acquires EventHandler {
        assert!(SimpleMap::contains_key(&self.id_token_type_map, &token_id), EUnsupportedTokenType);
        let type_name = SimpleMap::borrow(&self.id_token_type_map, &token_id);
        assert!(new_usd_price > 0, EInvalidNotionalValue);
        let metadata = SimpleMap::borrow_mut(&mut self.supported_tokens, type_name);
        metadata.notional_value = new_usd_price;

        let eh = borrow_global_mut<EventHandler>(@Bridge);
        Event::emit_event(&mut eh.update_token_price_event_handler, UpdateTokenPriceEvent {
            token_id,
            new_price: new_usd_price,
        })
    }

    fun get_token_metadata<T: store>(self: &BridgeTreasury): BridgeTokenMetadata {
        // Use BCS::to_bytes to match the format used in register_foreign_token
        let coin_type = BCS::to_bytes(&Token::token_code<T>());
        assert!(SimpleMap::contains_key(&self.supported_tokens, &coin_type), Errors::invalid_argument(EUnsupportedTokenType));
        *SimpleMap::borrow(&self.supported_tokens, &coin_type)
    }

    //////////////////////////////////////////////////////
    // Test functions
    //

    #[test_only]
    public fun initialize_for_testing(bridge_admin: &signer) {
        let bridge_addr = Signer::address_of(bridge_admin);
        if (!exists<EventHandler>(bridge_addr)) {
            move_to(bridge_admin, EventHandler {
                update_token_price_event_handler: Event::new_event_handle<UpdateTokenPriceEvent>(bridge_admin),
                new_token_event_handler: Event::new_event_handle<NewTokenEvent>(bridge_admin),
                token_registration_event_handler: Event::new_event_handle<TokenRegistrationEvent>(bridge_admin),
            });
        };
        if (!exists<BridgeTreasury>(bridge_addr)) {
            Self::initialize(bridge_admin);
        };
    }

    #[test_only]
    public fun mock_for_test(): BridgeTreasury {
        use Bridge::BTC::BTC;
        use Bridge::ETH::ETH;
        use Bridge::USDC::USDC;
        use Bridge::USDT::USDT;

        let treasury = Self::create();

        SimpleMap::add(&mut treasury.supported_tokens,
            BCS::to_bytes(&Token::token_code<BTC>()),
            BridgeTokenMetadata {
                id: 1,
                decimal_multiplier: 100_000_000,
                notional_value: 50_000 * USD_VALUE_MULTIPLIER,
                native_token: false,
            },
        );

        SimpleMap::add(&mut treasury.supported_tokens,
            BCS::to_bytes(&Token::token_code<ETH>()),
            BridgeTokenMetadata {
                id: 2,
                decimal_multiplier: 100_000_000,
                notional_value: 3_000 * USD_VALUE_MULTIPLIER,
                native_token: false,
            },
        );

        SimpleMap::add(&mut treasury.supported_tokens,
            BCS::to_bytes(&Token::token_code<USDC>()),
            BridgeTokenMetadata {
                id: 3,
                decimal_multiplier: 1_000_000,
                notional_value: USD_VALUE_MULTIPLIER,
                native_token: false,
            },
        );

        SimpleMap::add(&mut treasury.supported_tokens,
            BCS::to_bytes(&Token::token_code<USDT>()),
            BridgeTokenMetadata {
                id: 4,
                decimal_multiplier: 1_000_000,
                notional_value: USD_VALUE_MULTIPLIER,
                native_token: false,
            },
        );

        SimpleMap::add(&mut treasury.id_token_type_map, 1, BCS::to_bytes(&Token::token_code<BTC>()));
        SimpleMap::add(&mut treasury.id_token_type_map, 2, BCS::to_bytes(&Token::token_code<ETH>()));
        SimpleMap::add(&mut treasury.id_token_type_map, 3, BCS::to_bytes(&Token::token_code<USDC>()));
        SimpleMap::add(&mut treasury.id_token_type_map, 4, BCS::to_bytes(&Token::token_code<USDT>()));

        treasury
    }

    #[test_only]
    /// Setup treasury for testing - tokens will be added via add_default_tokens flow
    /// This function is intentionally empty to avoid duplicate SimpleMap key errors
    public fun setup_for_testing(_treasury: &mut BridgeTreasury) {
        // Tokens are now added via register_default_tokens + add_default_tokens
        // Adding them here would cause SimpleMap duplicate key errors
    }

    #[test_only]
    /// Test-only: burn tokens for test teardown (bypasses friend access)
    public fun burn_token<T: store>(token: Token::Token<T>) acquires BridgeTreasuryCap {
        if (Token::value(&token) == 0) {
            Token::destroy_zero(token);
        } else {
            assert!(exists<BridgeTreasuryCap<T>>(@Bridge), ETreasuryTokenNotExists);
            let tt = borrow_global_mut<BridgeTreasuryCap<T>>(@Bridge);
            Token::burn_with_capability<T>(&tt.burn_cap, token);
        }
    }

    #[test_only]
    /// Test-only: access waiting_room for verification in tests
    public fun wating_room(treasury: &BridgeTreasury): &SimpleMap<vector<u8>, ForeignTokenRegistration> {
        &treasury.waiting_room
    }

    #[test_only]
    public fun update_asset_notional_price_for_testing(
        self: &mut BridgeTreasury,
        token_id: u8,
        new_usd_price: u64,
    ) {
        let type_name = SimpleMap::borrow(&self.id_token_type_map, &token_id);
        assert!(new_usd_price > 0, EInvalidNotionalValue);
        let metadata = SimpleMap::borrow_mut(&mut self.supported_tokens, type_name);
        metadata.notional_value = new_usd_price;
    }

    // #[test_only]
    // public fun waiting_room(treasury: &BridgeTreasury): &SimpleMap<vector<u8>, ForeignTokenRegistration> {
    //     &treasury.waiting_room
    // }

    // #[test_only]
    // public fun treasuries(treasury: &BridgeTreasury): &ObjectBag {
    //     &treasury.treasuries
    // }
    //
    // #[test_only]
    // public fun unwrap_update_event(event: UpdateTokenPriceEvent): (u8, u64) {
    //     (event.token_id, event.new_price)
    // }
    //
    // #[test_only]
    // public fun unwrap_new_token_event(event: NewTokenEvent): (u8, TypeName, bool, u64, u64) {
    //     (
    //         event.token_id,
    //         event.type_name,
    //         event.native_token,
    //         event.decimal_multiplier,
    //         event.notional_value,
    //     )
    // }
    //
    // #[test_only]
    // public fun unwrap_registration_event(event: TokenRegistrationEvent): (TypeName, u8, bool) {
    //     (event.type_name, event.decimal, event.native_token)
    // }
}
