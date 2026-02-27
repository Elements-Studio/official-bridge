// Copyright (c) Starcoin Contributors
// SPDX-License-Identifier: Apache-2.0

/// Cryptographic utilities for bridge operations.
/// NOTE: This module only accepts uncompressed public keys (64 or 65 bytes).
/// Compressed pubkeys must be decompressed OFF-CHAIN before submission.
module Bridge::Crypto {

    use StarcoinFramework::Hash;
    use StarcoinFramework::Vector;

    const EInvalidPubkeyLength: u64 = 1;

    /// Convert a public key to Ethereum address.
    /// Accepts:
    /// - 64-byte raw pubkey (x, y coordinates)
    /// - 65-byte uncompressed pubkey with 0x04 prefix
    /// Returns 20-byte Ethereum address.
    /// NOTE: Compressed pubkeys (33 bytes) are NOT supported. Decompress off-chain first.
    public fun ecdsa_pub_key_to_eth_address(pub_key: &vector<u8>): vector<u8> {
        let len = Vector::length(pub_key);
        let raw_64: vector<u8>;
        
        if (len == 64) {
            // Raw 64-byte pubkey (x, y coordinates)
            raw_64 = *pub_key;
        } else if (len == 65) {
            // Uncompressed pubkey with 0x04 prefix, extract 64 bytes
            raw_64 = Vector::empty<u8>();
            let i = 1; // Skip 0x04 prefix
            while (i < 65) {
                Vector::push_back(&mut raw_64, *Vector::borrow(pub_key, i));
                i = i + 1;
            };
        } else {
            // Compressed pubkeys (33 bytes) NOT supported - decompress off-chain
            abort EInvalidPubkeyLength
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
    fun test_pub_key_to_eth_address_64bytes() {
        // 64-byte raw pubkey (x, y coordinates without 0x04 prefix)
        let raw_pubkey = x"9bef8d556d80e43ae7e0becb3a7e6838b95defe45896ed6075bb9035d06c99643ffaba1aa8b09ee1cbb83c0e29da8d7ccaccc5d8c95c89b20d4bbdcb7e62f30f";
        // keccak256 hash: d9930313c18795ccd01c98f4b750f7c7be5f1997f225d2fc3b1b1f9dbe976926
        let expected_address = x"b750f7c7be5f1997f225d2fc3b1b1f9dbe976926";

        assert!(ecdsa_pub_key_to_eth_address(&raw_pubkey) == expected_address, 1);
    }

    #[test]
    fun test_pub_key_to_eth_address_65bytes() {
        // 65-byte uncompressed pubkey with 0x04 prefix
        let uncompressed_pubkey = x"049bef8d556d80e43ae7e0becb3a7e6838b95defe45896ed6075bb9035d06c99643ffaba1aa8b09ee1cbb83c0e29da8d7ccaccc5d8c95c89b20d4bbdcb7e62f30f";
        let expected_address = x"b750f7c7be5f1997f225d2fc3b1b1f9dbe976926";

        assert!(ecdsa_pub_key_to_eth_address(&uncompressed_pubkey) == expected_address, 1);
    }
}
