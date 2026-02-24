/// ECDSA secp256k1 signature utilities.
/// Uses only functions available on Starcoin mainnet (no node upgrade needed).
/// Uses Signature::ecrecover which is available since v12.
module Bridge::EcdsaK1 {
    use StarcoinFramework::Errors;
    use StarcoinFramework::Hash;
    use StarcoinFramework::Vector;
    use StarcoinFramework::Signature;
    use StarcoinFramework::Option;
    use StarcoinFramework::EVMAddress;
    
    use Bridge::Crypto;

    const ERecoverFailed: u64 = 1;
    const EInvalidSignatureLength: u64 = 2;
    const EInvalidDigestLength: u64 = 3;

    /// Expected signature length: 64 bytes (r, s) + 1 byte recovery_id = 65 bytes
    const RECOVERABLE_SIGNATURE_LENGTH: u64 = 65;
    /// Expected digest length: 32 bytes (result of keccak256 or sha256)
    const DIGEST_LENGTH: u64 = 32;
    /// Expected EVM address length
    const EVM_ADDRESS_LENGTH: u64 = 20;

    /// Hash modes
    const KECCAK256: u8 = 0;
    const SHA256: u8 = 1;

    /// Recovers the EVM address from a 65-byte recoverable signature.
    /// The signature format is: [r (32 bytes) | s (32 bytes) | recovery_id (1 byte)]
    /// The `hash` parameter specifies the hash function:
    ///   0 = Keccak256 (used by Ethereum)
    ///   1 = SHA256
    /// Returns 20-byte EVM address, or empty vector if recovery fails.
    public fun secp256k1_ecrecover(signature: &vector<u8>, message: &vector<u8>, hash: u8): vector<u8> {
        // Hash the message to get 32-byte digest
        let digest = if (hash == KECCAK256) {
            Hash::keccak_256(*message)
        } else {
            Hash::sha2_256(*message)
        };

        secp256k1_ecrecover_digest(signature, &digest)
    }

    /// Recovers the EVM address from a 65-byte recoverable signature using pre-hashed digest.
    /// The signature format is: [r (32 bytes) | s (32 bytes) | recovery_id (1 byte)]
    /// The digest must be 32 bytes (result of keccak256 or sha256 hash).
    /// Returns 20-byte EVM address, or empty vector if recovery fails.
    public fun secp256k1_ecrecover_digest(signature: &vector<u8>, digest: &vector<u8>): vector<u8> {
        let sig_len = Vector::length(signature);
        assert!(sig_len == RECOVERABLE_SIGNATURE_LENGTH, Errors::invalid_argument(EInvalidSignatureLength));
        assert!(Vector::length(digest) == DIGEST_LENGTH, Errors::invalid_argument(EInvalidDigestLength));

        // Use the public ecrecover function which returns Option<EVMAddress>
        let result = Signature::ecrecover(*digest, *signature);
        if (Option::is_none(&result)) {
            return Vector::empty<u8>()
        };
        let evm_address = Option::destroy_some(result);
        EVMAddress::into_bytes(evm_address)
    }

    /// Verifies that a signature was created by the owner of the given public key.
    /// 
    /// signature: 65-byte recoverable signature [r (32) | s (32) | v (1)]
    /// message: the message that was signed
    /// public_key: 64-byte uncompressed public key (x, y coordinates)
    /// hash: hash mode (0 = Keccak256, 1 = SHA256)
    /// 
    /// Returns true if the signature is valid and was created by the public key owner.
    public fun verify_signature(
        signature: &vector<u8>,
        message: &vector<u8>,
        public_key: &vector<u8>,
        hash: u8
    ): bool {
        // Recover the EVM address from the signature
        let recovered_address = secp256k1_ecrecover(signature, message, hash);
        
        // If recovery failed, return false
        if (Vector::length(&recovered_address) != EVM_ADDRESS_LENGTH) {
            return false
        };
        
        // Compute EVM address from the provided public key
        let expected_address = Crypto::ecdsa_pub_key_to_eth_address(public_key);
        
        // Compare addresses
        recovered_address == expected_address
    }

    /// Verifies that a signature was created by the owner of the given public key.
    /// Uses pre-hashed digest instead of raw message.
    /// 
    /// signature: 65-byte recoverable signature [r (32) | s (32) | v (1)]
    /// digest: 32-byte message hash
    /// public_key: 64-byte uncompressed public key (x, y coordinates)
    /// 
    /// Returns true if the signature is valid and was created by the public key owner.
    public fun verify_signature_digest(
        signature: &vector<u8>,
        digest: &vector<u8>,
        public_key: &vector<u8>
    ): bool {
        // Recover the EVM address from the signature
        let recovered_address = secp256k1_ecrecover_digest(signature, digest);
        
        // If recovery failed, return false
        if (Vector::length(&recovered_address) != EVM_ADDRESS_LENGTH) {
            return false
        };
        
        // Compute EVM address from the provided public key
        let expected_address = Crypto::ecdsa_pub_key_to_eth_address(public_key);
        
        // Compare addresses
        recovered_address == expected_address
    }
}
