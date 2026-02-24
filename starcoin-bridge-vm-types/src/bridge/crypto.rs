// Crypto types for Starcoin Bridge
// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature};
use fastcrypto::secp256k1::Secp256k1KeyPair;
use fastcrypto::traits::Signer as SignerTrait;
use serde::{Deserialize, Serialize};

pub use fastcrypto::traits::KeyPair;

// Authority key types (Ed25519 for consensus)
pub type AuthorityKeyPair = Ed25519KeyPair;
pub type AuthorityPublicKey = Ed25519PublicKey;
pub type AuthoritySignature = Ed25519Signature;

// Network key types
pub type NetworkKeyPair = Ed25519KeyPair;
pub type NetworkPublicKey = Ed25519PublicKey;

// General Starcoin key pair (Secp256k1 for user keys)
pub type StarcoinKeyPair = Secp256k1KeyPair;

// Authority public key bytes
pub type AuthorityPublicKeyBytes = [u8; 32];

/// Signature wrapper
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature(pub Vec<u8>);

impl Signature {
    // Create a new secure signature - compatible with starcoin_bridge_types::crypto::Signature
    pub fn new_secure<T, S>(_intent_msg: &T, _signer: &S) -> Self
    where
        T: Serialize,
        S: ?Sized + Signer<AuthoritySignature>,
    {
        // For now, return an empty signature (stub implementation)
        // In real implementation, this would:
        // 1. Serialize the intent message
        // 2. Hash it
        // 3. Sign with the signer
        Signature(Vec::new())
    }
}

/// Signer trait
pub trait Signer<Sig> {
    fn sign(&self, msg: &[u8]) -> Sig;
}

impl Signer<AuthoritySignature> for AuthorityKeyPair {
    fn sign(&self, msg: &[u8]) -> AuthoritySignature {
        SignerTrait::sign(self, msg)
    }
}

// Authority sign info
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthoritySignInfo {
    /// Bridge committee version number (incremented when committee members change)
    pub committee_version: u64,
    pub authority: AuthorityPublicKeyBytes,
    pub signature: AuthoritySignature,
}

impl AuthoritySignInfo {
    pub fn new<S>(
        committee_version: u64,
        data: &impl Serialize,
        intent: &shared_crypto::intent::Intent,
        authority: AuthorityPublicKeyBytes,
        secret: &S,
    ) -> Self
    where
        S: Signer<AuthoritySignature>,
    {
        let mut message = bcs::to_bytes(intent).expect("intent serialization should not fail");
        message.extend(bcs::to_bytes(data).expect("data serialization should not fail"));

        let signature = secret.sign(&message);

        Self {
            committee_version,
            authority,
            signature,
        }
    }
}

pub trait AuthoritySignInfoTrait {
    fn committee_version(&self) -> u64;
}

impl AuthoritySignInfoTrait for AuthoritySignInfo {
    fn committee_version(&self) -> u64 {
        self.committee_version
    }
}

/// Empty sign info
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmptySignInfo {}
