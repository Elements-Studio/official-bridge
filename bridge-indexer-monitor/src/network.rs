// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Network type configuration for finalized handling

use starcoin_bridge::pending_events::ChainId;
use starcoin_bridge_types::bridge::BridgeChainId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
    /// Local development networks (dev, local, anvil)
    /// All blocks are immediately considered finalized
    Local,
    /// Testnet networks (halley, barnard, sepolia, goerli)
    /// Blocks need confirmation before being marked as finalized
    Testnet,
    /// Mainnet networks
    /// Blocks need confirmation before being marked as finalized
    Mainnet,
}

impl NetworkType {
    /// Detect network type from Starcoin chain ID
    /// Chain IDs:
    /// - 1: Mainnet
    /// - 251: Barnard (testnet)
    /// - 252: Proxima (testnet)
    /// - 253: Halley (testnet)
    /// - 254: Dev (local)
    /// - 255: Test (local)
    pub fn from_starcoin_chain_id(chain_id: u64) -> Self {
        match chain_id {
            1 => NetworkType::Mainnet,
            2 | 251 | 252 | 253 => NetworkType::Testnet,
            254 | 255 => NetworkType::Local,
            _ => panic!("Unknown Starcoin chain ID: {}", chain_id),
        }
    }

    /// Detect network type from Ethereum chain ID
    /// Chain IDs:
    /// - 1: Mainnet
    /// - 5: Goerli (testnet)
    /// - 11155111: Sepolia (testnet)
    /// - 31337: Hardhat/Anvil (local)
    pub fn from_eth_chain_id(chain_id: u64) -> Self {
        match chain_id {
            1 => NetworkType::Mainnet,
            5 | 11155111 => NetworkType::Testnet,
            31337 => NetworkType::Local,
            _ => panic!("Unknown Ethereum chain ID: {}", chain_id),
        }
    }

    /// Convert to Starcoin BridgeChainId
    pub fn to_bridge_chain_id(&self) -> BridgeChainId {
        match self {
            NetworkType::Mainnet => BridgeChainId::StarcoinMainnet,
            NetworkType::Testnet => BridgeChainId::StarcoinTestnet,
            NetworkType::Local => BridgeChainId::StarcoinCustom,
        }
    }

    /// Convert to Ethereum BridgeChainId
    pub fn to_eth_chain_id(&self) -> BridgeChainId {
        match self {
            NetworkType::Mainnet => BridgeChainId::EthMainnet,
            NetworkType::Testnet => BridgeChainId::EthSepolia,
            NetworkType::Local => BridgeChainId::EthCustom,
        }
    }

    /// Convert a generic ChainId to the correct bridge chain ID (i32) for DB storage.
    ///
    /// The `ChainId` enum (Starcoin=0, Eth=1) loses the network-specific bridge chain ID.
    /// This method maps it back to the correct BridgeChainId value based on the current network.
    pub fn chain_id_to_bridge_i32(&self, chain_id: ChainId) -> i32 {
        let bridge_id = match chain_id {
            ChainId::Starcoin => self.to_bridge_chain_id(),
            ChainId::Eth => self.to_eth_chain_id(),
        };
        bridge_id as u8 as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_starcoin_chain_id_detection() {
        assert_eq!(NetworkType::from_starcoin_chain_id(1), NetworkType::Mainnet);
        assert_eq!(
            NetworkType::from_starcoin_chain_id(251),
            NetworkType::Testnet
        );
        assert_eq!(
            NetworkType::from_starcoin_chain_id(252),
            NetworkType::Testnet
        );
        assert_eq!(
            NetworkType::from_starcoin_chain_id(253),
            NetworkType::Testnet
        );
        assert_eq!(NetworkType::from_starcoin_chain_id(254), NetworkType::Local);
    }

    #[test]
    fn test_starcoin_proxima_testnet() {
        // Chain ID 2 is Proxima testnet
        assert_eq!(NetworkType::from_starcoin_chain_id(2), NetworkType::Testnet);
    }

    #[test]
    fn test_starcoin_all_testnets() {
        // All testnet chain IDs should return Testnet
        for chain_id in [2, 251, 252] {
            assert_eq!(
                NetworkType::from_starcoin_chain_id(chain_id),
                NetworkType::Testnet,
                "Chain ID {} should be Testnet",
                chain_id
            );
        }
    }

    #[test]
    fn test_starcoin_all_local_networks() {
        // All local chain IDs should return Local
        for chain_id in [254, 255] {
            assert_eq!(
                NetworkType::from_starcoin_chain_id(chain_id),
                NetworkType::Local,
                "Chain ID {} should be Local",
                chain_id
            );
        }
    }

    #[test]
    fn test_eth_chain_id_detection() {
        assert_eq!(NetworkType::from_eth_chain_id(1), NetworkType::Mainnet);
        assert_eq!(NetworkType::from_eth_chain_id(5), NetworkType::Testnet);
        assert_eq!(
            NetworkType::from_eth_chain_id(11155111),
            NetworkType::Testnet
        );
        assert_eq!(NetworkType::from_eth_chain_id(31337), NetworkType::Local);
    }

    #[test]
    fn test_eth_goerli_testnet() {
        // Goerli is deprecated but should still be recognized
        assert_eq!(NetworkType::from_eth_chain_id(5), NetworkType::Testnet);
    }

    #[test]
    fn test_eth_sepolia_testnet() {
        assert_eq!(
            NetworkType::from_eth_chain_id(11155111),
            NetworkType::Testnet
        );
    }

    #[test]
    fn test_eth_anvil_local() {
        // Anvil/Hardhat default chain ID
        assert_eq!(NetworkType::from_eth_chain_id(31337), NetworkType::Local);
    }

    #[test]
    fn test_network_type_debug() {
        // Ensure Debug trait is implemented correctly
        assert_eq!(format!("{:?}", NetworkType::Local), "Local");
        assert_eq!(format!("{:?}", NetworkType::Testnet), "Testnet");
        assert_eq!(format!("{:?}", NetworkType::Mainnet), "Mainnet");
    }

    #[test]
    fn test_network_type_clone() {
        let local = NetworkType::Local;
        #[allow(clippy::clone_on_copy)]
        let cloned = local.clone();
        assert_eq!(local, cloned);
    }

    #[test]
    fn test_network_type_copy() {
        let local = NetworkType::Local;
        let copied: NetworkType = local; // Copy, not move
        assert_eq!(local, copied);
    }

    #[test]
    #[should_panic(expected = "Unknown Starcoin chain ID")]
    fn test_unknown_starcoin_chain_id_panics() {
        NetworkType::from_starcoin_chain_id(99999);
    }

    #[test]
    #[should_panic(expected = "Unknown Ethereum chain ID")]
    fn test_unknown_eth_chain_id_panics() {
        NetworkType::from_eth_chain_id(99999);
    }

    // === chain_id_to_bridge_i32 tests ===
    // These verify that ChainId (Starcoin=0, Eth=1) is correctly mapped
    // to BridgeChainId values for DB storage. This is the core of the
    // chain ID display fix: without this mapping, ChainId::Eth (=1) would
    // be stored as 1 in the DB, which falls in the Starcoin range (0-2),
    // causing both source and destination chains to display as "STARCOIN".

    #[test]
    fn test_chain_id_to_bridge_i32_local() {
        let network = NetworkType::Local;
        // Local: Starcoin -> StarcoinCustom (2), Eth -> EthCustom (12)
        assert_eq!(network.chain_id_to_bridge_i32(ChainId::Starcoin), 2);
        assert_eq!(network.chain_id_to_bridge_i32(ChainId::Eth), 12);
    }

    #[test]
    fn test_chain_id_to_bridge_i32_testnet() {
        let network = NetworkType::Testnet;
        // Testnet: Starcoin -> StarcoinTestnet (1), Eth -> EthSepolia (11)
        assert_eq!(network.chain_id_to_bridge_i32(ChainId::Starcoin), 1);
        assert_eq!(network.chain_id_to_bridge_i32(ChainId::Eth), 11);
    }

    #[test]
    fn test_chain_id_to_bridge_i32_mainnet() {
        let network = NetworkType::Mainnet;
        // Mainnet: Starcoin -> StarcoinMainnet (0), Eth -> EthMainnet (10)
        assert_eq!(network.chain_id_to_bridge_i32(ChainId::Starcoin), 0);
        assert_eq!(network.chain_id_to_bridge_i32(ChainId::Eth), 10);
    }

    #[test]
    fn test_chain_id_to_bridge_i32_never_overlaps() {
        // Critical safety test: Eth chain ID must NEVER fall in Starcoin range (0-2)
        // and Starcoin chain ID must NEVER fall in Eth range (10-12)
        for network in [
            NetworkType::Local,
            NetworkType::Testnet,
            NetworkType::Mainnet,
        ] {
            let stc_id = network.chain_id_to_bridge_i32(ChainId::Starcoin);
            let eth_id = network.chain_id_to_bridge_i32(ChainId::Eth);

            assert!(
                stc_id >= 0 && stc_id <= 2,
                "Starcoin bridge ID {} not in range 0-2 for {:?}",
                stc_id,
                network
            );
            assert!(
                eth_id >= 10 && eth_id <= 12,
                "Eth bridge ID {} not in range 10-12 for {:?}",
                eth_id,
                network
            );
            assert_ne!(
                stc_id, eth_id,
                "Starcoin and Eth bridge IDs must differ for {:?}",
                network
            );
        }
    }

    #[test]
    fn test_chain_id_to_bridge_i32_consistent_with_chain_id_to_name() {
        // Verify that the bridge IDs produced by chain_id_to_bridge_i32
        // will resolve to the correct chain names in the API layer.
        // chain_id_to_name: 0..=2 -> "STARCOIN", 10..=12 -> "ETH"
        fn chain_id_to_name(id: i32) -> &'static str {
            match id {
                0..=2 => "STARCOIN",
                10..=12 => "ETH",
                _ => "UNKNOWN",
            }
        }

        for network in [
            NetworkType::Local,
            NetworkType::Testnet,
            NetworkType::Mainnet,
        ] {
            assert_eq!(
                chain_id_to_name(network.chain_id_to_bridge_i32(ChainId::Starcoin)),
                "STARCOIN",
                "ChainId::Starcoin should resolve to STARCOIN for {:?}",
                network
            );
            assert_eq!(
                chain_id_to_name(network.chain_id_to_bridge_i32(ChainId::Eth)),
                "ETH",
                "ChainId::Eth should resolve to ETH for {:?}",
                network
            );
        }
    }
}
