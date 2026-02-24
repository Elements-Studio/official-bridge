// Copyright (c) Starcoin Contributors
// SPDX-License-Identifier: Apache-2.0

module Bridge::ChainIDs {
    use StarcoinFramework::Vector;

    // Starcoin chain IDs (matching bridge rust code)
    const STARCOIN_MAINNET: u8 = 0;
    const STARCOIN_TESTNET: u8 = 1;
    const STARCOIN_CUSTOM: u8 = 2;

    // ETH chain IDs
    const ETH_MAINNET: u8 = 10;
    const ETH_SEPOLIA: u8 = 11;
    const ETH_CUSTOM: u8 = 12;

    const EInvalidBridgeRoute: u64 = 0;
    const EInvalidStarcoinChainId: u64 = 1;

    // Starcoin node chain IDs (from starcoin-vm config)
    // These are different from Bridge protocol chain IDs
    const STARCOIN_NODE_MAINNET: u8 = 1;
    const STARCOIN_NODE_BARNARD: u8 = 251;   // testnet
    const STARCOIN_NODE_PROXIMA: u8 = 252;   // testnet
    const STARCOIN_NODE_HALLEY: u8 = 253;    // testnet
    const STARCOIN_NODE_DEV: u8 = 254;       // dev/custom

    //////////////////////////////////////////////////////
    // Types
    //

    struct BridgeRoute has copy, drop, store {
        source: u8,
        destination: u8,
    }

    //////////////////////////////////////////////////////
    // Public functions
    //
    public fun eth_mainnet(): u8 { ETH_MAINNET }

    public fun eth_sepolia(): u8 { ETH_SEPOLIA }

    public fun eth_custom(): u8 { ETH_CUSTOM }

    public fun starcoin_mainnet(): u8 { STARCOIN_MAINNET }

    public fun starcoin_testnet(): u8 { STARCOIN_TESTNET }

    public fun starcoin_custom(): u8 { STARCOIN_CUSTOM }


    public fun route_source(route: &BridgeRoute): &u8 {
        &route.source
    }

    public fun route_destination(route: &BridgeRoute): &u8 {
        &route.destination
    }

    public fun assert_valid_chain_id(id: u8) {
        assert!(
            id == STARCOIN_MAINNET ||
                id == STARCOIN_TESTNET ||
                id == STARCOIN_CUSTOM ||
                id == ETH_MAINNET ||
                id == ETH_SEPOLIA ||
                id == ETH_CUSTOM,
            EInvalidBridgeRoute,
        )
    }

    public fun valid_routes(): vector<BridgeRoute> {
        vector[
            // Mainnet routes
            BridgeRoute { source: STARCOIN_MAINNET, destination: ETH_MAINNET },
            BridgeRoute { source: ETH_MAINNET, destination: STARCOIN_MAINNET },
            // Testnet routes
            BridgeRoute { source: STARCOIN_TESTNET, destination: ETH_SEPOLIA },
            BridgeRoute { source: ETH_SEPOLIA, destination: STARCOIN_TESTNET },
            // Custom/Dev routes
            BridgeRoute { source: STARCOIN_CUSTOM, destination: ETH_CUSTOM },
            BridgeRoute { source: ETH_CUSTOM, destination: STARCOIN_CUSTOM },
            BridgeRoute { source: STARCOIN_CUSTOM, destination: ETH_SEPOLIA },
            BridgeRoute { source: ETH_SEPOLIA, destination: STARCOIN_CUSTOM },
            BridgeRoute { source: STARCOIN_TESTNET, destination: ETH_CUSTOM },
            BridgeRoute { source: ETH_CUSTOM, destination: STARCOIN_TESTNET },
        ]
    }

    public fun is_valid_route(source: u8, destination: u8): bool {
        let route = BridgeRoute { source, destination };
        Vector::contains(&valid_routes(), &route)
    }

    // Checks and return BridgeRoute if the route is supported by the bridge.
    public fun get_route(source: u8, destination: u8): BridgeRoute {
        let route = BridgeRoute { source, destination };
        assert!(Vector::contains(&valid_routes(), &route), EInvalidBridgeRoute);
        route
    }

    /// Convert Starcoin node chain ID to Bridge protocol chain ID
    /// Node chain IDs: 1 (mainnet), 251/252/253 (testnets), 254 (dev)
    /// Bridge protocol IDs: 0 (mainnet), 1 (testnet), 2 (custom/dev)
    public fun starcoin_node_to_bridge_chain_id(node_chain_id: u8): u8 {
        if (node_chain_id == STARCOIN_NODE_MAINNET) {
            STARCOIN_MAINNET  // 1 -> 0
        } else if (node_chain_id == STARCOIN_NODE_BARNARD ||
                   node_chain_id == STARCOIN_NODE_PROXIMA ||
                   node_chain_id == STARCOIN_NODE_HALLEY) {
            STARCOIN_TESTNET  // 251/252/253 -> 1
        } else if (node_chain_id == STARCOIN_NODE_DEV) {
            STARCOIN_CUSTOM   // 254 -> 2
        } else {
            // For any other chain ID, treat as custom
            STARCOIN_CUSTOM
        }
    }

    /// Check if a node chain ID is valid
    public fun is_valid_starcoin_node_chain_id(node_chain_id: u8): bool {
        node_chain_id == STARCOIN_NODE_MAINNET ||
        node_chain_id == STARCOIN_NODE_BARNARD ||
        node_chain_id == STARCOIN_NODE_PROXIMA ||
        node_chain_id == STARCOIN_NODE_HALLEY ||
        node_chain_id == STARCOIN_NODE_DEV
    }

    //////////////////////////////////////////////////////
    // Test functions
    //

    #[test]
    fun test_chains_ok() {
        assert_valid_chain_id(STARCOIN_MAINNET);
        assert_valid_chain_id(STARCOIN_TESTNET);
        assert_valid_chain_id(STARCOIN_CUSTOM);
        assert_valid_chain_id(ETH_MAINNET);
        assert_valid_chain_id(ETH_SEPOLIA);
        assert_valid_chain_id(ETH_CUSTOM);
    }

    #[test, expected_failure(abort_code = EInvalidBridgeRoute)]
    fun test_chains_error() {
        assert_valid_chain_id(100);
    }

    #[test, expected_failure(abort_code = EInvalidBridgeRoute)]
    fun test_starcoin_chains_error() {
        // this will break if we add one more starcoin chain id and should be corrected
        assert_valid_chain_id(3);
    }

    #[test, expected_failure(abort_code = EInvalidBridgeRoute)]
    fun test_eth_chains_error() {
        // this will break if we add one more eth chain id and should be corrected
        assert_valid_chain_id(13);
    }

    #[test]
    fun test_routes() {
        use StarcoinFramework::Debug;
        let valid_routes = vector[
            BridgeRoute { source: STARCOIN_MAINNET, destination: ETH_MAINNET },
            BridgeRoute { source: ETH_MAINNET, destination: STARCOIN_MAINNET },
            BridgeRoute { source: STARCOIN_TESTNET, destination: ETH_SEPOLIA },
            BridgeRoute { source: ETH_SEPOLIA, destination: STARCOIN_TESTNET },
            BridgeRoute { source: STARCOIN_CUSTOM, destination: ETH_CUSTOM },
            BridgeRoute { source: ETH_CUSTOM, destination: STARCOIN_CUSTOM },
            BridgeRoute { source: STARCOIN_CUSTOM, destination: ETH_SEPOLIA },
            BridgeRoute { source: ETH_SEPOLIA, destination: STARCOIN_CUSTOM },
            BridgeRoute { source: STARCOIN_TESTNET, destination: ETH_CUSTOM },
            BridgeRoute { source: ETH_CUSTOM, destination: STARCOIN_TESTNET },
        ];
        let size = Vector::length(&valid_routes);
        while (size > 0) {
            size = size - 1;
            let route = Vector::borrow(&valid_routes, size);
            if (!is_valid_route(route.source, route.destination)) {
                Debug::print(&route.source);
                Debug::print(&route.destination);
            };
            assert!(is_valid_route(route.source, route.destination), 1); // should not assert
        }
    }

    #[test, expected_failure(abort_code = EInvalidBridgeRoute)]
    fun test_routes_err_stc_1() {
        get_route(STARCOIN_MAINNET, STARCOIN_MAINNET);
    }

    #[test, expected_failure(abort_code = EInvalidBridgeRoute)]
    fun test_routes_err_stc_2() {
        get_route(STARCOIN_MAINNET, STARCOIN_TESTNET);
    }

    #[test, expected_failure(abort_code = EInvalidBridgeRoute)]
    fun test_routes_err_stc_3() {
        get_route(STARCOIN_MAINNET, ETH_SEPOLIA);
    }

    #[test, expected_failure(abort_code = EInvalidBridgeRoute)]
    fun test_routes_err_stc_4() {
        get_route(STARCOIN_MAINNET, ETH_CUSTOM);
    }

    #[test, expected_failure(abort_code = EInvalidBridgeRoute)]
    fun test_routes_err_eth_1() {
        get_route(ETH_MAINNET, ETH_MAINNET);
    }

    #[test, expected_failure(abort_code = EInvalidBridgeRoute)]
    fun test_routes_err_eth_2() {
        get_route(ETH_MAINNET, ETH_CUSTOM);
    }

    #[test, expected_failure(abort_code = EInvalidBridgeRoute)]
    fun test_routes_err_eth_3() {
        get_route(ETH_MAINNET, STARCOIN_CUSTOM);
    }

    #[test, expected_failure(abort_code = EInvalidBridgeRoute)]
    fun test_routes_err_eth_4() {
        get_route(ETH_MAINNET, STARCOIN_TESTNET);
    }
}
