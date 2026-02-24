// Copyright (c) Starcoin Contributors
// SPDX-License-Identifier: Apache-2.0

module Bridge::Limiter {
    use Bridge::ChainIDs::{Self, BridgeRoute};
    use Bridge::Treasury;
    use Bridge::Treasury::BridgeTreasury;
    use StarcoinFramework::Event;
    use StarcoinFramework::Signer;
    use StarcoinFramework::SimpleMap::{Self, SimpleMap};
    use StarcoinFramework::Vector;

    const ELimitNotFoundForRoute: u64 = 0;

    // U64::MAX - upper bound constant. Actual per-route limits are set via governance.
    const MAX_TRANSFER_LIMIT: u64 = 18_446_744_073_709_551_615;

    const DEFAULT_TRANSFER_LIMIT: u64 = 5_000_000;

    const USD_VALUE_MULTIPLIER: u64 = 100000000; // 8 DP accuracy


    //////////////////////////////////////////////////////
    // Types
    //

    struct TransferLimiter has store {
        transfer_limits: SimpleMap<BridgeRoute, u64>,
        // Per hour transfer amount for each bridge route
        transfer_records: SimpleMap<BridgeRoute, TransferRecord>,
    }

    struct TransferRecord has copy, store, drop {
        hour_head: u64,
        hour_tail: u64,
        per_hour_amounts: vector<u64>,
        // total amount in USD, 4 DP accuracy, so 10000 => 1USD
        total_amount: u64,
    }

    struct UpdateRouteLimitEvent has store, copy, drop {
        sending_chain: u8,
        receiving_chain: u8,
        new_limit: u64,
    }

    struct EventHandlePod has key {
        update_router_limit_event_handler: Event::EventHandle<UpdateRouteLimitEvent>
    }

    //////////////////////////////////////////////////////
    // Public functions
    //

    public fun initialize(bridge: &signer) {
        let bridge_addr = Signer::address_of(bridge);
        if (!exists<EventHandlePod>(bridge_addr)) {
            move_to(bridge, EventHandlePod {
                update_router_limit_event_handler: Event::new_event_handle<UpdateRouteLimitEvent>(bridge),
            });
        };
    }

    // Abort if the route limit is not found
    public fun get_route_limit(self: &TransferLimiter, route: &BridgeRoute): u64 {
        *SimpleMap::borrow(&self.transfer_limits, route)
    }

    //////////////////////////////////////////////////////
    // Internal functions
    //
    public fun new(): TransferLimiter {
        // hardcoded limit for bridge genesis
        TransferLimiter {
            transfer_limits: initial_transfer_limits(),
            transfer_records: SimpleMap::create(),
        }
    }

    public fun destroy(limitter: TransferLimiter) {
        let TransferLimiter { transfer_limits: _, transfer_records: _ } = limitter;
    }

    public fun check_and_record_sending_transfer<T: store>(
        self: &mut TransferLimiter,
        treasury: &BridgeTreasury,
        clock_timestamp_ms: u64,
        route: BridgeRoute,
        amount: u64,
    ): bool {
        // Create record for route if not exists
        if (!SimpleMap::contains_key(&self.transfer_records, &route)) {
            // Initialize with one element for the current hour
            SimpleMap::add(&mut self.transfer_records,
                route,
                TransferRecord {
                    hour_head: 0,
                    hour_tail: 0,
                    per_hour_amounts: vector[0], // Initialize with one zero element
                    total_amount: 0,
                },
            )
        };

        let record = SimpleMap::borrow_mut(&mut self.transfer_records, &route);
        let current_hour_since_epoch = Self::current_hour_since_epoch(clock_timestamp_ms);

        Self::adjust_transfer_records(record, current_hour_since_epoch);

        // Get limit for the route
        assert!(SimpleMap::contains_key(&self.transfer_limits, &route), ELimitNotFoundForRoute);
        let route_limit = SimpleMap::borrow(&mut self.transfer_limits, &route);

        let route_limit_adjusted = (*route_limit as u128) * (Treasury::decimal_multiplier<T>(treasury) as u128);

        // Compute notional amount
        // Upcast to u128 to prevent overflow, to not miss out on small amounts.
        let value = (Treasury::notional_value<T>(treasury) as u128);
        let notional_amount_with_token_multiplier = value * (amount as u128);

        // Check if transfer amount exceed limit
        // Upscale them to the token's decimal.
        if (
            (record.total_amount as u128)
                * (Treasury::decimal_multiplier<T>(treasury) as u128)
                + notional_amount_with_token_multiplier > route_limit_adjusted
        ) {
            return false
        };

        // Now scale down to notional value
        let notional_amount =
            notional_amount_with_token_multiplier / (Treasury::decimal_multiplier<T>(treasury) as u128);
        // Should be safe to downcast to u64 after dividing by the decimals
        let notional_amount = (notional_amount as u64);

        // Record transfer value
        let new_amount = Vector::pop_back(&mut record.per_hour_amounts) + notional_amount;
        Vector::push_back(&mut record.per_hour_amounts, new_amount);
        record.total_amount = record.total_amount + notional_amount;
        true
    }


    public fun update_route_limit(
        self: &mut TransferLimiter,
        route: &BridgeRoute,
        new_usd_limit: u64,
    ) acquires EventHandlePod {
        let receiving_chain = *ChainIDs::route_destination(route);

        SimpleMap::upsert(&mut self.transfer_limits, *route, new_usd_limit);

        let eh = borrow_global_mut<EventHandlePod>(@Bridge);
        Event::emit_event(&mut eh.update_router_limit_event_handler, UpdateRouteLimitEvent {
            sending_chain: *ChainIDs::route_source(route),
            receiving_chain,
            new_limit: new_usd_limit,
        })
    }

    public fun default_transfer_limit(): u64 {
        DEFAULT_TRANSFER_LIMIT * USD_VALUE_MULTIPLIER
    }
    //
    // // Current hour since unix epoch
    fun current_hour_since_epoch(clock_timestamp_ms: u64): u64 {
        clock_timestamp_ms / 3600000
    }

    //
    fun adjust_transfer_records(self: &mut TransferRecord, current_hour_since_epoch: u64) {
        if (self.hour_head == current_hour_since_epoch) {
            return // nothing to backfill
        };

        // Prevent underflow when current_hour_since_epoch < 23
        let target_tail = if (current_hour_since_epoch >= 23) {
            current_hour_since_epoch - 23
        } else {
            0
        };

        // If `hour_head` is even older than 24 hours ago, it means all items in
        // `per_hour_amounts` are to be evicted.
        if (self.hour_head < target_tail) {
            self.per_hour_amounts = vector[];
            self.total_amount = 0;
            self.hour_tail = target_tail;
            self.hour_head = target_tail;
            // Don't forget to insert this hour's record
            Vector::push_back(&mut self.per_hour_amounts, 0);
        } else {
            // self.hour_head is within 24 hour range.
            // some items in `per_hour_amounts` are still valid, we remove stale hours.
            while (self.hour_tail < target_tail) {
                self.total_amount = self.total_amount - Vector::remove(&mut self.per_hour_amounts, 0);
                self.hour_tail = self.hour_tail + 1;
            }
        };

        // Backfill from hour_head to current hour
        while (self.hour_head < current_hour_since_epoch) {
            Vector::push_back(&mut self.per_hour_amounts, 0);
            self.hour_head = self.hour_head + 1;
        }
    }

    //
    // It's tedious to list every pair, but it's safer to do so so we don't
    // accidentally turn off limiter for a new production route in the future.
    // Note limiter only takes effects on the receiving chain, so we only need to
    // specify routes from Ethereum to Starcoin.
    fun initial_transfer_limits(): SimpleMap<BridgeRoute, u64> {
        let transfer_limits = SimpleMap::create<BridgeRoute, u64>();

        // 5M limit on Starcoin <- Ethereum mainnet (only this direction has limit)
        SimpleMap::add(
            &mut transfer_limits,
            ChainIDs::get_route(ChainIDs::eth_mainnet(), ChainIDs::starcoin_mainnet()),
            DEFAULT_TRANSFER_LIMIT * USD_VALUE_MULTIPLIER,
        );

        SimpleMap::add(
            &mut transfer_limits,
            ChainIDs::get_route(ChainIDs::starcoin_mainnet(), ChainIDs::eth_mainnet()),
            DEFAULT_TRANSFER_LIMIT * USD_VALUE_MULTIPLIER,
        );

        // MAX limit for testnet and devnet
        SimpleMap::add(
            &mut transfer_limits,
            ChainIDs::get_route(ChainIDs::eth_sepolia(), ChainIDs::starcoin_testnet()),
            MAX_TRANSFER_LIMIT,
        );
        SimpleMap::add(
            &mut transfer_limits,
            ChainIDs::get_route(ChainIDs::starcoin_testnet(), ChainIDs::eth_sepolia()),
            MAX_TRANSFER_LIMIT,
        );

        SimpleMap::add(
            &mut transfer_limits,
            ChainIDs::get_route(ChainIDs::eth_sepolia(), ChainIDs::starcoin_custom()),
            MAX_TRANSFER_LIMIT,
        );

        SimpleMap::add(
            &mut transfer_limits,
            ChainIDs::get_route(ChainIDs::eth_custom(), ChainIDs::starcoin_testnet()),
            MAX_TRANSFER_LIMIT,
        );

        SimpleMap::add(
            &mut transfer_limits,
            ChainIDs::get_route(ChainIDs::eth_custom(), ChainIDs::starcoin_custom()),
            MAX_TRANSFER_LIMIT,
        );

        transfer_limits
    }

    //////////////////////////////////////////////////////
    // Test functions
    //

    #[test_only]
    public fun transfer_limits(limiter: &TransferLimiter): &SimpleMap<BridgeRoute, u64> {
        &limiter.transfer_limits
    }

    #[test_only]
    public fun transfer_limits_mut(
        limiter: &mut TransferLimiter,
    ): &mut SimpleMap<BridgeRoute, u64> {
        &mut limiter.transfer_limits
    }

    //
    #[test_only]
    public fun transfer_records(
        limiter: &TransferLimiter,
    ): &SimpleMap<BridgeRoute, TransferRecord> {
        &limiter.transfer_records
    }

    #[test_only]
    public fun transfer_records_mut(
        limiter: &mut TransferLimiter,
    ): &mut SimpleMap<BridgeRoute, TransferRecord> {
        &mut limiter.transfer_records
    }

    #[test_only]
    public fun usd_value_multiplier(): u64 {
        USD_VALUE_MULTIPLIER
    }

    #[test_only]
    public fun max_transfer_limit(): u64 {
        MAX_TRANSFER_LIMIT
    }

    #[test_only]
    public fun make_transfer_limiter(): TransferLimiter {
        TransferLimiter {
            transfer_limits: SimpleMap::create<BridgeRoute, u64>(),
            transfer_records: SimpleMap::create<BridgeRoute, TransferRecord>(),
        }
    }

    //
    #[test_only]
    public fun total_amount(record: &TransferRecord): u64 {
        record.total_amount
    }

    #[test_only]
    public fun per_hour_amounts(record: &TransferRecord): &vector<u64> {
        &record.per_hour_amounts
    }

    #[test_only]
    public fun hour_head(record: &TransferRecord): u64 {
        record.hour_head
    }

    #[test_only]
    public fun hour_tail(record: &TransferRecord): u64 {
        record.hour_tail
    }

    #[test_only]
    public fun unpack_route_limit_event(event: UpdateRouteLimitEvent): (u8, u8, u64) {
        (event.sending_chain, event.receiving_chain, event.new_limit)
    }

    #[test_only]
    /// Initialize global resources for testing. Must be called with @Bridge signer.
    public fun initialize_for_testing(bridge: &signer) {
        let bridge_addr = Signer::address_of(bridge);
        if (!exists<EventHandlePod>(bridge_addr)) {
            initialize(bridge);
        };
    }

    #[test_only]
    /// Update route limit without emitting events (for testing without global resources).
    public fun update_route_limit_for_testing(
        limiter: &mut TransferLimiter,
        route: &BridgeRoute,
        new_limit: u64,
    ) {
        if (SimpleMap::contains_key(&limiter.transfer_limits, route)) {
            let limit = SimpleMap::borrow_mut(&mut limiter.transfer_limits, route);
            *limit = new_limit;
        } else {
            SimpleMap::add(&mut limiter.transfer_limits, *route, new_limit);
        }
    }
}