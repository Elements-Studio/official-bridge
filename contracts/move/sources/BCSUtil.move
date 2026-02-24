// Copyright (c) Starcoin Contributors
// SPDX-License-Identifier: Apache-2.0

module Bridge::BCSUtil {
    use StarcoinFramework::Errors;
    use StarcoinFramework::Vector;

    const EOutOfRange: u64 = 1;
    const ELenOutOfRange: u64 = 2;
    const ENotBool: u64 = 3;

    public fun peel_vec_length(bcs: &mut vector<u8>): u64 {
        let (total, shift, len) = (0u64, 0, 0);
        loop {
            assert!(len <= 4, ELenOutOfRange);
            let byte = Vector::pop_back(bcs);
            len = len + 1;
            total = total | (((byte & 0x7f) << shift) as u64);
            if ((byte & 0x80) == 0) break;
            shift = shift + 7;
        };
        total
    }

    public fun peel_bool(bcs: &mut vector<u8>): bool {
        let value = Self::peel_u8(bcs);
        if (value == 0) {
            false
        } else if (value == 1) {
            true
        } else {
            abort ENotBool
        }
    }


    public fun peel_u8(bcs: &mut vector<u8>): u8 {
        assert!(Vector::length(bcs) >= 1, Errors::limit_exceeded(EOutOfRange));
        Vector::pop_back(bcs)
    }

    /// Read `u64` value from bcs-serialized bytes.
    public fun peel_u64(bcs: &mut vector<u8>): u64 {
        assert!(Vector::length(bcs) >= 8, EOutOfRange);
        let value: u64 = 0;
        let i: u8 = 0;
        while (i < 64) {
            let byte = (Vector::pop_back(bcs) as u64);
            value = value + (byte << i);
            i = i + 8;
        };
        value
    }

    /// Peel a vector of `u8` (eg string) from serialized bytes.
    public fun peel_vec_u8(bcs: &mut vector<u8>): vector<u8> {
        let len = Self::peel_vec_length(bcs);
        let v = vector[];
        let i = 0;
        while (i < len) {
            Vector::push_back(&mut v, Self::peel_u8(bcs));
            i = i + 1;
        };
        v
    }

    public fun peel_vec_u64(bcs: &mut vector<u8>): vector<u64> {
        let len = Self::peel_vec_length(bcs);
        let v = vector[];
        let i = 0;
        while (i < len) {
            Vector::push_back(&mut v, Self::peel_u64(bcs));
            i = i + 1;
        };
        v
    }

    /// Peel a `vector<vector<u8>>` (eg vec of string) from serialized bytes.
    public fun peel_vec_vec_u8(bcs: &mut vector<u8>): vector<vector<u8>> {
        let len = Self::peel_vec_length(bcs);

        let result = Vector::empty<vector<u8>>();
        let i = 0;
        while (i < len) {
            let inner_len = Self::peel_vec_length(bcs);
            let inner_vec = vector[];
            let j = 0;
            while (j < inner_len) {
                Vector::push_back(&mut inner_vec, Self::peel_u8(bcs));
                j = j + 1;
            };
            Vector::push_back(&mut result, inner_vec);
            i = i + 1;
        };
        result
    }

    public fun into_remainder_bytes(bcs: vector<u8>): vector<u8> {
        let result = copy bcs;
        Vector::reverse(&mut result);
        result
    }

    /// Convert a 16-byte vector to address.
    /// Starcoin addresses are 16 bytes (128 bits).
    public fun to_address(bytes: vector<u8>): address {
        assert!(Vector::length(&bytes) == 16, Errors::limit_exceeded(EOutOfRange));
        // In Move, we can use native BCS deserialization
        // The bytes should already be in correct order (big-endian for address)
        StarcoinFramework::BCS::to_address(bytes)
    }
}
