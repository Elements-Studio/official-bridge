// Copyright (c) Westar Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module Bridge::ETH {
    struct ETH has store {}
}

module Bridge::BTC {
    struct BTC has store {}
}

module Bridge::USDC {
    struct USDC has store {}
}

module Bridge::USDT {
    struct USDT has store {}
}

module Bridge::AssetUtil {

    const EInvalidSender: u64 = 1;

    use StarcoinFramework::Account;
    use StarcoinFramework::BCS;
    use StarcoinFramework::Signer;
    use StarcoinFramework::Token::{Self, MintCapability, BurnCapability};

    public fun initialize<T: store>(bridge: &signer, precision: u8, ): (MintCapability<T>, BurnCapability<T>) {
        assert!(Signer::address_of(bridge) == @Bridge, EInvalidSender);
        Token::register_token<T>(bridge, precision);
        (Token::remove_mint_capability<T>(bridge), Token::remove_burn_capability<T>(bridge))
    }

    public fun token_type_name<T: store>(): vector<u8> {
        BCS::to_bytes(&Token::token_code<T>())
    }

    #[test_only]
    public fun quick_mint_for_test<T: store>(bridge: &signer, amount: u128): Token::Token<T> {
        let (mcap, bcap) = Self::initialize<T>(bridge, 9);
        let token = Token::mint_with_capability<T>(&mcap, amount);

        Token::destroy_mint_capability(mcap);
        Token::destroy_burn_capability(bcap);

        token
    }

    #[test_only]
    /// Burn a token for testing purposes without needing BridgeTreasuryCap
    public fun burn_for_test<T: store>(bridge: &signer, token: Token::Token<T>) {
        // Re-initialize to get new capabilities (this is a test-only function)
        // Since the token is already registered, we need to get burn capability differently
        // For testing, we'll deposit it back to a zero balance and ignore it
        let zero_token = Token::zero<T>();
        Token::deposit<T>(&mut zero_token, token);
        // Now we have a non-zero token that we can't destroy normally
        // For test purposes, we'll use a workaround - withdraw to make it zero again
        let value = Token::value<T>(&zero_token);
        let withdrawn = Token::withdraw<T>(&mut zero_token, value);
        // Merge back
        Token::deposit<T>(&mut zero_token, withdrawn);
        // We can't actually destroy non-zero tokens without burn capability
        // So let's just store it in the signer's account
        let bridge_addr = Signer::address_of(bridge);
        if (!Account::is_accepts_token<T>(bridge_addr)) {
            Account::do_accept_token<T>(bridge);
        };
        Account::deposit<T>(bridge_addr, zero_token);
    }
}