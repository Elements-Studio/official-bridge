// // Copyright (c) Starcoin, Inc.
// // SPDX-License-Identifier: Apache-2.0
//
#[test_only]
module Bridge::LimiterTests {
    use Bridge::BTC::BTC;
    use Bridge::ChainIDs;
    use Bridge::ETH::ETH;
    use Bridge::Limiter::{Self, check_and_record_sending_transfer, hour_head, hour_tail, make_transfer_limiter,
        max_transfer_limit, per_hour_amounts, total_amount, transfer_limits_mut, transfer_records,
        update_route_limit_for_testing, usd_value_multiplier
    };
    use Bridge::Treasury::{Self, decimal_multiplier, notional_value, token_id, update_asset_notional_price_for_testing};
    use Bridge::USDC::USDC;
    use Bridge::USDT::USDT;
    use StarcoinFramework::SimpleMap;

    //
    #[test]
    fun test_24_hours_windows() {
        let limiter = make_transfer_limiter();

        let route = ChainIDs::get_route(ChainIDs::starcoin_custom(), ChainIDs::eth_sepolia());
        let treasury = Treasury::mock_for_test();

        // Global transfer limit is 100M USD
        let transfer_limit = transfer_limits_mut(&mut limiter);
        SimpleMap::add(transfer_limit, route, 100_000_000 * usd_value_multiplier());
        // Notional price for ETH is 5 USD
        let id = Treasury::token_id<ETH>(&treasury);
        update_asset_notional_price_for_testing(&mut treasury, id, 5 * usd_value_multiplier());

        let clock = 1706288001377;

        // transfer 10000 ETH every hour, the totol should be 10000 * 5
        assert!(
            check_and_record_sending_transfer<ETH>(
                &mut limiter,
                &treasury,
                clock,
                route,
                10_000 * decimal_multiplier<ETH>(&treasury),
            ),
            0,
        );

        let limiter_records = transfer_records(&limiter);
        let transfer_record = SimpleMap::borrow(limiter_records, &route);
        assert!(total_amount(transfer_record) == 10000 * 5 * usd_value_multiplier(), 1);

        // transfer 1000 ETH every hour for 50 hours, the 24 hours totol should be 24000 * 10
        let i = 0;
        while (i < 50) {
            clock = clock + 60 * 60 * 1000;
            assert!(
                check_and_record_sending_transfer<ETH>(&mut limiter,
                    &treasury,
                    clock,
                    route,
                    1_000 * decimal_multiplier<ETH>(&treasury),
                ),
                2,
            );
            i = i + 1;
        };
        let limiter_records = transfer_records(&limiter);
        let record = SimpleMap::borrow(limiter_records, &route);
        let expected_value = 24000 * 5 * usd_value_multiplier();
        assert!(total_amount(record) == expected_value, 3);

        // transfer 1000 * i ETH every hour for 24 hours, the 24 hours
        // totol should be 300 * 1000 * 5
        let i = 0;
        // At this point, every hour in past 24 hour has value $5000.
        // In each iteration, the old $5000 gets replaced with (i * 5000)
        while (i < 24) {
            clock = clock + 60 * 60 * 1000;
            assert!(
                check_and_record_sending_transfer<ETH>(&mut limiter,
                    &treasury,
                    clock,
                    route,
                    1_000 * decimal_multiplier<ETH>(&treasury) * (i + 1),
                ),
                4,
            );

            let record = SimpleMap::borrow(transfer_records(&limiter), &route);

            expected_value = expected_value + 1000 * 5 * i * usd_value_multiplier();
            assert!(total_amount(record) == expected_value, 5);
            i = i + 1;
        };

        let record = SimpleMap::borrow(transfer_records(&limiter), &route);
        assert!(total_amount(record) == 300 * 1000 * 5 * usd_value_multiplier(), 6);

        Limiter::destroy(limiter);
        Treasury::destroy(treasury);
    }

    #[test]
    fun test_24_hours_windows_multiple_route() {
        let limiter = make_transfer_limiter();
        let treasury = Treasury::mock_for_test();

        let route = ChainIDs::get_route(ChainIDs::starcoin_custom(), ChainIDs::eth_sepolia());
        let route2 = ChainIDs::get_route(ChainIDs::eth_sepolia(), ChainIDs::starcoin_custom());

        // Global transfer limit is 1M USD
        SimpleMap::add(transfer_limits_mut(&mut limiter), route, 1_000_000 * usd_value_multiplier());
        SimpleMap::add(transfer_limits_mut(&mut limiter), route2, 500_000 * usd_value_multiplier());
        // Notional price for ETH is 5 USD
        let id = Treasury::token_id<ETH>(&treasury);
        update_asset_notional_price_for_testing(&mut treasury, id, 5 * usd_value_multiplier());

        let clock = 1706288001377;

        // Transfer 10000 ETH on route 1
        assert!(
            check_and_record_sending_transfer<ETH>(&mut limiter,
                &treasury,
                clock,
                route,
                10_000 * Treasury::decimal_multiplier<ETH>(&treasury),
            ),
            0,
        );
        // Transfer 50000 ETH on route 2
        assert!(
            check_and_record_sending_transfer<ETH>(&mut limiter,
                &treasury,
                clock,
                route2,
                50_000 * Treasury::decimal_multiplier<ETH>(&treasury),
            ),
            0,
        );

        let record = SimpleMap::borrow(transfer_records(&limiter), &route);
        assert!(total_amount(record) == 10000 * 5 * usd_value_multiplier(), 2);

        let record = SimpleMap::borrow(transfer_records(&limiter), &route2);
        assert!(total_amount(record) == 50000 * 5 * usd_value_multiplier(), 3);

        Limiter::destroy(limiter);
        Treasury::destroy(treasury);
    }

    #[test]
    fun test_exceed_limit() {
        let limiter = make_transfer_limiter();
        let treasury = Treasury::mock_for_test();

        let route = ChainIDs::get_route(ChainIDs::starcoin_custom(), ChainIDs::eth_sepolia());
        // Global transfer limit is 1M USD
        SimpleMap::add(transfer_limits_mut(&mut limiter), route, 1_000_000 * usd_value_multiplier());
        // Notional price for ETH is 10 USD
        let id = Treasury::token_id<ETH>(&treasury);
        update_asset_notional_price_for_testing(&mut treasury, id, 10 * usd_value_multiplier());

        let clock = 1706288001377;

        assert!(
            check_and_record_sending_transfer<ETH>(&mut limiter,
                &treasury,
                clock,
                route,
                90_000 * Treasury::decimal_multiplier<ETH>(&treasury),
            ),
            0,
        );

        let record = SimpleMap::borrow(transfer_records(&limiter), &route);
        assert!(total_amount(record) == 90000 * 10 * usd_value_multiplier(), 0);

        clock = clock + 60 * 60 * 1000;
        assert!(
            check_and_record_sending_transfer<ETH>(&mut limiter,
                &treasury,
                clock,
                route,
                10_000 * Treasury::decimal_multiplier<ETH>(&treasury),
            ),
            1,
        );
        let record = SimpleMap::borrow(transfer_records(&limiter), &route);
        assert!(total_amount(record) == 100000 * 10 * usd_value_multiplier(), 0);

        // Tx should fail with a tiny amount because the limit is hit
        assert!(!check_and_record_sending_transfer<ETH>(&mut limiter, &treasury, clock, route, 1), 3);
        assert!(
            !check_and_record_sending_transfer<ETH>(&mut limiter,
                &treasury,
                clock,
                route,
                90_000 * Treasury::decimal_multiplier<ETH>(&treasury),
            ),
            4,
        );

        // Fast forward 23 hours, now the first 90k should be discarded
        clock = clock + 60 * 60 * 1000 * 23;
        assert!(
            check_and_record_sending_transfer<ETH>(&mut limiter,
                &treasury,
                clock,
                route,
                90_000 * Treasury::decimal_multiplier<ETH>(&treasury),
            ),
            5,
        );
        let record = SimpleMap::borrow(transfer_records(&limiter), &route);
        assert!(total_amount(record) == 100000 * 10 * usd_value_multiplier(), 6);

        // But now limit is hit again
        assert!(!check_and_record_sending_transfer<ETH>(&mut limiter, &treasury, clock, route, 1), 7);
        let record = SimpleMap::borrow(transfer_records(&limiter), &route);
        assert!(total_amount(record) == 100000 * 10 * usd_value_multiplier(), 8);

        Limiter::destroy(limiter);
        Treasury::destroy(treasury);
    }

    #[test]
    fun test_limiter_bidirectional_mainnet_limits() {
        // Test that both directions (ETH->STC and STC->ETH) have limits on mainnet
        let limiter = Limiter::new();
        let treasury = Treasury::mock_for_test();
        let clock = 1706288001377;

        // Test 1: ETH mainnet -> Starcoin mainnet (incoming to Starcoin)
        let eth_to_stc_route = ChainIDs::get_route(ChainIDs::eth_mainnet(), ChainIDs::starcoin_mainnet());
        let limit_eth_to_stc = Limiter::get_route_limit(&limiter, &eth_to_stc_route);
        assert!(limit_eth_to_stc > 0, 1); // Should have a limit

        // Test 2: Starcoin mainnet -> ETH mainnet (outgoing from Starcoin)
        let stc_to_eth_route = ChainIDs::get_route(ChainIDs::starcoin_mainnet(), ChainIDs::eth_mainnet());
        let limit_stc_to_eth = Limiter::get_route_limit(&limiter, &stc_to_eth_route);
        assert!(limit_stc_to_eth > 0, 2); // Should have a limit

        // Test 3: Both directions should have same default limit
        assert!(limit_eth_to_stc == limit_stc_to_eth, 3);

        // Test 4: Verify transfers work within limit
        let result = check_and_record_sending_transfer<ETH>(&mut limiter,
            &treasury,
            clock,
            stc_to_eth_route,
            1 * Treasury::decimal_multiplier<ETH>(&treasury),
        );
        assert!(result, 4); // Small transfer should succeed

        Limiter::destroy(limiter);
        Treasury::destroy(treasury);
    }

    #[test]
    fun test_limiter_basic_op() {
        // In this test we use very simple number for easier calculation.
        let limiter = make_transfer_limiter();
        let treasury = Treasury::mock_for_test();

        let route = ChainIDs::get_route(ChainIDs::eth_sepolia(), ChainIDs::starcoin_testnet());
        // Global transfer limit is 100 USD
        SimpleMap::add(transfer_limits_mut(&mut limiter), route, 100 * usd_value_multiplier());
        // BTC: $10, ETH: $2.5, USDC: $1, USDT: $0.5
        let id = Treasury::token_id<BTC>(&treasury);
        update_asset_notional_price_for_testing(&mut treasury, id, 10 * usd_value_multiplier());
        let id = Treasury::token_id<ETH>(&treasury);
        let eth_price = 250000000;
        update_asset_notional_price_for_testing(&mut treasury, id, eth_price);
        let id = Treasury::token_id<USDC>(&treasury);
        update_asset_notional_price_for_testing(&mut treasury, id, 1 * usd_value_multiplier());
        let id = Treasury::token_id<USDT>(&treasury);
        update_asset_notional_price_for_testing(&mut treasury, id, 50000000);


        let clock = 36082800000; // hour 10023

        // hour 0 (10023): $15 * 2.5 = $37.5
        // 15 eth = $37.5
        assert!(
            check_and_record_sending_transfer<ETH>(&mut limiter,
                &treasury,
                clock,
                route,
                15 * Treasury::decimal_multiplier<ETH>(&treasury),
            ),
            0,
        );

        let record = SimpleMap::borrow(transfer_records(&limiter), &route);
        assert!(hour_head(record) == 10023, 0);
        assert!(hour_tail(record) == 10000, 0);
        assert!(
            per_hour_amounts(record) ==
                &vector[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    15 * eth_price,
                ],
            3,
        );
        assert!(total_amount(record) == 15 * eth_price, 0);

        // hour 0 (10023): $37.5 + $10 = $47.5
        // 10 uddc = $10
        assert!(
            check_and_record_sending_transfer<USDC>(&mut limiter,
                &treasury,
                clock,
                route,
                10 * Treasury::decimal_multiplier<USDC>(&treasury),
            ),
            0,
        );
        let record = SimpleMap::borrow(transfer_records(&limiter), &route);
        assert!(hour_head(record) == 10023, 0);
        assert!(hour_tail(record) == 10000, 0);
        let expected_notion_amount_10023 = 15 * eth_price + 10 * usd_value_multiplier();
        assert!(
            per_hour_amounts(record) ==
                &vector[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    expected_notion_amount_10023,
                ],
            9,
        );
        assert!(total_amount(record) == expected_notion_amount_10023, 0);

        // hour 1 (10024): $20
        clock = clock + 60 * 60 * 1000;

        // 2 btc = $20
        assert!(
            check_and_record_sending_transfer<BTC>(
                &mut limiter,
                &treasury,
                clock,
                route,
                2 * Treasury::decimal_multiplier<BTC>(&treasury),
            ),
            0,
        );
        let record = SimpleMap::borrow(transfer_records(&limiter), &route);
        assert!(hour_head(record) == 10024, 0);
        assert!(hour_tail(record) == 10001, 0);
        let expected_notion_amount_10024 = 20 * usd_value_multiplier();
        assert!(
            per_hour_amounts(record) ==
                &vector[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    expected_notion_amount_10023,
                    expected_notion_amount_10024,
                ],
            0,
        );
        assert!(total_amount(record) == expected_notion_amount_10023 + expected_notion_amount_10024, 0);

        // Fast forward 22 hours, now hour 23 (10046): try to transfer $33 willf fail
        clock = clock + 60 * 60 * 1000 * 22;
        // fail
        // 65 usdt = $33
        assert!(
            !check_and_record_sending_transfer<USDT>(
                &mut limiter,
                &treasury,
                clock,
                route,
                66 * 1_000_000,
            ),
            0,
        );
        // but window slid
        let record = SimpleMap::borrow(transfer_records(&limiter), &route);
        assert!(hour_head(record) == 10046, 0);
        assert!(hour_tail(record) == 10023, 0);
        assert!(
            per_hour_amounts(record) ==
                &vector[
                    expected_notion_amount_10023, expected_notion_amount_10024,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
            0,
        );
        assert!(total_amount(record) == expected_notion_amount_10023 + expected_notion_amount_10024, 0);

        // hour 23 (10046): $32.5 deposit will succeed
        // 65 usdt = $32.5
        assert!(
            check_and_record_sending_transfer<USDT>(
                &mut limiter,
                &treasury,
                clock,
                route,
                65 * 1_000_000,
            ),
            0,
        );
        let record = SimpleMap::borrow(transfer_records(&limiter), &route);
        let expected_notion_amount_10046 = 325 * usd_value_multiplier() / 10;
        assert!(hour_head(record) == 10046, 0);
        assert!(hour_tail(record) == 10023, 0);
        assert!(
            per_hour_amounts(record) ==
                &vector[
                    expected_notion_amount_10023,
                    expected_notion_amount_10024,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    expected_notion_amount_10046,
                ],
            0,
        );
        assert!(
            total_amount(record) ==
                expected_notion_amount_10023 + expected_notion_amount_10024 + expected_notion_amount_10046,
            0,
        );

        // Hour 24 (10047), we can deposit $0.5 now
        clock = clock + 60 * 60 * 1000;
        // 1 usdt = $0.5
        assert!(
            check_and_record_sending_transfer<USDT>(&mut limiter, &treasury, clock, route, 1_000_000),
            0,
        );

        let record = SimpleMap::borrow(transfer_records(&limiter), &route);
        let expected_notion_amount_10047 = 5 * usd_value_multiplier() / 10;
        assert!(hour_head(record) == 10047, 0);
        assert!(hour_tail(record) == 10024, 0);
        assert!(per_hour_amounts(record) ==
            &vector[
                expected_notion_amount_10024,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                expected_notion_amount_10046,
                expected_notion_amount_10047,
            ],
            0,
        );
        assert!(
            total_amount(record) ==
                expected_notion_amount_10024 + expected_notion_amount_10046 + expected_notion_amount_10047,
            0,
        );

        // Fast forward to Hour 30 (10053)
        clock = clock + 60 * 60 * 1000 * 6;
        // 1 usdc = $1
        assert!(
            check_and_record_sending_transfer<USDC>(&mut limiter,
                &treasury,
                clock,
                route,
                1 * Treasury::decimal_multiplier<USDC>(&treasury),
            ),
            0,
        );

        let record = SimpleMap::borrow(transfer_records(&limiter), &route);
        let expected_notion_amount_10053 = 1 * usd_value_multiplier();
        assert!(hour_head(record) == 10053, 0);
        assert!(hour_tail(record) == 10030, 0);
        assert!(
            per_hour_amounts(record) ==
                &vector[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    expected_notion_amount_10046,
                    expected_notion_amount_10047,
                    0, 0, 0, 0, 0,
                    expected_notion_amount_10053,
                ],
            0,
        );
        assert!(
            total_amount(record) ==
                expected_notion_amount_10046 + expected_notion_amount_10047 + expected_notion_amount_10053,
            0
        );

        // Fast forward to hour 130 (10153)
        clock = clock + 60 * 60 * 1000 * 100;
        // 1 usdc = $1
        assert!(
            check_and_record_sending_transfer<USDC>(
                &mut limiter,
                &treasury,
                clock,
                route,
                Treasury::decimal_multiplier<USDC>(&treasury),
            ),
            0,
        );
        let record = SimpleMap::borrow(transfer_records(&limiter), &route);
        let expected_notion_amount_10153 = 1 * usd_value_multiplier();
        assert!(hour_head(record) == 10153, 0);
        assert!(hour_tail(record) == 10130, 0);
        assert!(
            per_hour_amounts(record) ==
                &vector[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    expected_notion_amount_10153,
                ],
            0,
        );
        assert!(total_amount(record) == expected_notion_amount_10153, 0);

        Limiter::destroy(limiter);
        Treasury::destroy(treasury);
    }

    #[test]
    fun test_update_route_limit_for_testing() {
        // default routes, default notion values
        let limiter = Limiter::new();
        assert!(
            *SimpleMap::borrow(
                Limiter::transfer_limits(&limiter),
                &ChainIDs::get_route(ChainIDs::eth_mainnet(), ChainIDs::starcoin_mainnet()),
            ) == 5_000_000 * usd_value_multiplier(),
            0,
        );

        assert!(
            *SimpleMap::borrow(Limiter::transfer_limits(&limiter),
                &ChainIDs::get_route(ChainIDs::eth_sepolia(), ChainIDs::starcoin_testnet()),
            ) == max_transfer_limit(),
            0
        );

        // shrink testnet limit
        update_route_limit_for_testing(
            &mut limiter,
            &ChainIDs::get_route(ChainIDs::eth_sepolia(), ChainIDs::starcoin_testnet()),
            1_000 * usd_value_multiplier(),
        );
        assert!(
            *SimpleMap::borrow(Limiter::transfer_limits(&limiter),
                &ChainIDs::get_route(ChainIDs::eth_sepolia(), ChainIDs::starcoin_testnet()),
            ) == (1_000 * usd_value_multiplier()),
            0,
        );

        // mainnet route does not change
        assert!(
            *SimpleMap::borrow(Limiter::transfer_limits(&limiter),
                &ChainIDs::get_route(ChainIDs::eth_mainnet(), ChainIDs::starcoin_mainnet()),
            ) == 5_000_000 * usd_value_multiplier(),
            0
        );

        Limiter::destroy(limiter);
    }

    #[test]
    fun test_update_route_limit_all_paths() {
        let limiter = Limiter::new();

        // pick an existing route limit
        assert!(
            *SimpleMap::borrow(Limiter::transfer_limits(&limiter),
                &ChainIDs::get_route(ChainIDs::eth_sepolia(), ChainIDs::starcoin_testnet()),
            ) == max_transfer_limit(),
            1
        );

        let new_limit = 1_000 * usd_value_multiplier();
        update_route_limit_for_testing(
            &mut limiter,
            &ChainIDs::get_route(ChainIDs::eth_sepolia(), ChainIDs::starcoin_testnet()),
            new_limit,
        );

        assert!(
            *SimpleMap::borrow(Limiter::transfer_limits(&limiter),
                &ChainIDs::get_route(ChainIDs::eth_sepolia(), ChainIDs::starcoin_testnet()),
            ) == new_limit, 2
        );

        // pick a new route limit
        update_route_limit_for_testing(
            &mut limiter,
            &ChainIDs::get_route(ChainIDs::starcoin_testnet(), ChainIDs::eth_sepolia()),
            new_limit,
        );
        assert!(
            *SimpleMap::borrow(Limiter::transfer_limits(&limiter),
                &ChainIDs::get_route(ChainIDs::eth_sepolia(), ChainIDs::starcoin_testnet()),
            ) == new_limit,
            3
        );

        Limiter::destroy(limiter);
    }

    #[test]
    fun test_update_asset_price() {
        // default routes, default notion values
        let treasury = Treasury::mock_for_test();

        assert!(notional_value<BTC>(&treasury) == (50_000 * usd_value_multiplier()), 1);
        assert!(notional_value<ETH>(&treasury) == (3_000 * usd_value_multiplier()), 2);
        assert!(notional_value<USDC>(&treasury) == (1 * usd_value_multiplier()), 3);
        assert!(notional_value<USDT>(&treasury) == (1 * usd_value_multiplier()), 4);
        // change usdt price
        let id = token_id<USDT>(&treasury);
        update_asset_notional_price_for_testing(&mut treasury, id, 11 * usd_value_multiplier() / 10);
        assert!(notional_value<USDT>(&treasury) == (11 * usd_value_multiplier() / 10), 5);
        // other prices do not change
        assert!(notional_value<BTC>(&treasury) == (50_000 * usd_value_multiplier()), 6);
        assert!(notional_value<ETH>(&treasury) == (3_000 * usd_value_multiplier()), 7);
        assert!(notional_value<USDC>(&treasury) == (1 * usd_value_multiplier()), 8);

        Treasury::destroy(treasury);
    }
}