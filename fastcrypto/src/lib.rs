// Copyright (c) 2021, Facebook, Inc. and its affiliates
#![allow(unexpected_cfgs)]
// Copyright (c) 2022, Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Minimal version for Starcoin Bridge - only includes necessary crypto primitives
#![warn(
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]

#[cfg(test)]
#[path = "tests/ed25519_tests.rs"]
pub mod ed25519_tests;

#[cfg(test)]
#[path = "tests/secp256k1_tests.rs"]
pub mod secp256k1_tests;

#[cfg(test)]
#[path = "tests/secp256k1_recoverable_tests.rs"]
pub mod secp256k1_recoverable_tests;

#[cfg(test)]
#[path = "tests/hash_tests.rs"]
pub mod hash_tests;

#[cfg(test)]
#[path = "tests/hmac_tests.rs"]
pub mod hmac_tests;

#[cfg(test)]
#[path = "tests/encoding_tests.rs"]
pub mod encoding_tests;

#[cfg(test)]
#[path = "tests/test_helpers.rs"]
pub mod test_helpers;

#[cfg(test)]
#[path = "tests/utils_tests.rs"]
pub mod utils_tests;

#[cfg(test)]
#[path = "tests/secp256k1_group_tests.rs"]
pub mod secp256k1_group_tests;

// Core modules needed by Starcoin Bridge
pub mod ed25519;
pub mod encoding;
pub mod error;
pub mod groups;
pub mod hash;
pub mod hmac;
pub mod private_seed;
pub mod secp256k1;
pub mod serde_helpers;
pub mod traits;
pub mod utils;
