// Copyright (c) Starcoin Contributors
// SPDX-License-Identifier: Apache-2.0

module Bridge::Crypto {

    use StarcoinFramework::Hash;
    use StarcoinFramework::Vector;

    /// Convert a public key to Ethereum address.
    /// Accepts either:
    /// - 33-byte compressed pubkey (will be decompressed first)
    /// - 64-byte raw pubkey (x, y coordinates)
    /// Returns 20-byte Ethereum address.
    public fun ecdsa_pub_key_to_eth_address(pub_key: &vector<u8>): vector<u8> {
        let len = Vector::length(pub_key);
        let raw_64: vector<u8>;
        
        if (len == 33) {
            // Compressed pubkey: decompress to 65 bytes, then extract 64 bytes
            let decompressed = Bridge::EcdsaK1::decompress_pubkey(pub_key);
            raw_64 = Vector::empty<u8>();
            let i = 1; // Skip 0x04 prefix
            while (i < 65) {
                Vector::push_back(&mut raw_64, *Vector::borrow(&decompressed, i));
                i = i + 1;
            };
        } else if (len == 64) {
            // Already raw 64-byte pubkey
            raw_64 = *pub_key;
        } else {
            abort 1 // Invalid pubkey length
        };
        
        // Keccak256 hash of 64-byte pubkey, take last 20 bytes as ETH address
        let hash = Hash::keccak_256(raw_64);
        let eth_address = Vector::empty<u8>();
        let i = 12; // Skip first 12 bytes, take last 20
        while (i < 32) {
            Vector::push_back(&mut eth_address, *Vector::borrow(&hash, i));
            i = i + 1;
        };
        eth_address
    }

    #[test]
    fun test_pub_key_to_eth_address() {
        let validator_pub_key = x"029bef8d556d80e43ae7e0becb3a7e6838b95defe45896ed6075bb9035d06c9964";
        let expected_address = x"b14d3c4f5fbfbcfb98af2d330000d49c95b93aa7";

        assert!(ecdsa_pub_key_to_eth_address(&validator_pub_key) == expected_address, 1);
    }
}
