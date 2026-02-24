// Starcoin Bridge Types
// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::too_many_arguments)]
#![allow(clippy::large_enum_variant)]

use serde::{Deserialize, Serialize};

// =============================================================================
// Starcoin Native Transaction Builder
// =============================================================================

pub mod starcoin_transaction_builder;
pub use starcoin_transaction_builder::*;

// =============================================================================
// Re-exports from starcoin_bridge_vm_types
// =============================================================================

pub mod base_types {
    pub use starcoin_bridge_vm_types::bridge::base_types::*;

    // STARCOIN_ADDRESS_LENGTH - Starcoin uses 16-byte addresses
    pub const STARCOIN_ADDRESS_LENGTH: usize = 16;

    // For compatibility, also define a 32-byte length
    pub const OBJECT_ID_LENGTH: usize = 32;

    /// Extension trait for concise display
    pub trait ConciseDisplay {
        fn concise(&self) -> String;
    }

    impl ConciseDisplay for usize {
        fn concise(&self) -> String {
            self.to_string()
        }
    }

    impl ConciseDisplay for u64 {
        fn concise(&self) -> String {
            self.to_string()
        }
    }
}

pub mod bridge {
    pub use starcoin_bridge_vm_types::bridge::bridge::*;
}

pub mod committee {
    pub use starcoin_bridge_vm_types::bridge::committee::*;
}

#[allow(hidden_glob_reexports)]
pub mod crypto {
    pub use starcoin_bridge_vm_types::bridge::crypto::*;

    use fastcrypto::{
        ed25519::Ed25519KeyPair,
        error::FastCryptoError,
        secp256k1::Secp256k1KeyPair,
        traits::{EncodeDecodeBase64, KeyPair as KeypairTraits, ToFromBytes},
    };
    use serde::{Deserialize, Serialize};

    // Re-export Signature from starcoin_bridge_vm_types
    pub use starcoin_bridge_vm_types::bridge::crypto::Signature;

    // NetworkKeyPair is just an alias for Ed25519KeyPair in Starcoin
    pub type NetworkKeyPair = Ed25519KeyPair;

    // Extension trait to add copy() method to NetworkKeyPair
    pub trait NetworkKeyPairExt {
        fn copy(&self) -> Self;
    }

    impl NetworkKeyPairExt for NetworkKeyPair {
        fn copy(&self) -> Self {
            // Create a copy by serializing and deserializing
            use fastcrypto::traits::ToFromBytes;
            let bytes = self.as_bytes();
            Ed25519KeyPair::from_bytes(bytes).expect("Failed to copy keypair")
        }
    }

    // Generic key pair generation function
    pub fn get_key_pair<KP: KeypairTraits>() -> ((), KP) {
        let mut rng = rand::thread_rng();
        ((), KP::generate(&mut rng))
    }

    // Re-export Secp256k1PublicKey for convenience
    pub use fastcrypto::secp256k1::Secp256k1PublicKey;

    // Define StarcoinKeyPair enum (simplified - only Ed25519 and Secp256k1)
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "type")]
    pub enum StarcoinKeyPair {
        Ed25519(Ed25519KeyPair),
        Secp256k1(Secp256k1KeyPair),
        // TODO: Add Secp256r1 support when fastcrypto adds it
        // Secp256r1(Secp256r1KeyPair),
    }

    impl StarcoinKeyPair {
        pub fn public(&self) -> Vec<u8> {
            use fastcrypto::traits::KeyPair;
            match self {
                StarcoinKeyPair::Ed25519(kp) => kp.public().as_bytes().to_vec(),
                StarcoinKeyPair::Secp256k1(kp) => kp.public().as_bytes().to_vec(),
            }
        }

        /// Derive Starcoin account address from keypair's public key.
        ///
        /// The address derivation follows Starcoin's algorithm:
        /// 1. Create preimage: pubkey_bytes || scheme_flag (0x00 for Ed25519)
        /// 2. Hash with SHA3-256 to get AuthenticationKey (32 bytes)
        /// 3. Take the last 16 bytes as the AccountAddress
        pub fn starcoin_address(&self) -> move_core_types::account_address::AccountAddress {
            use sha3::{Digest, Sha3_256};

            // Get public key bytes
            let pubkey_bytes = self.public();

            // Create preimage: pubkey || scheme_flag
            // Ed25519 = 0x00, Secp256k1 = 0x01
            let scheme_flag: u8 = match self {
                StarcoinKeyPair::Ed25519(_) => 0x00,
                StarcoinKeyPair::Secp256k1(_) => 0x01,
            };
            let mut preimage = pubkey_bytes;
            preimage.push(scheme_flag);

            // Hash with SHA3-256
            let hash = Sha3_256::digest(&preimage);

            // Take last 16 bytes as address
            let mut addr_bytes = [0u8; 16];
            addr_bytes.copy_from_slice(&hash[16..32]);

            move_core_types::account_address::AccountAddress::new(addr_bytes)
        }

        /// Sign a message and return (public_key, signature) bytes
        pub fn sign_message(&self, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
            use fastcrypto::traits::KeyPair;
            match self {
                StarcoinKeyPair::Ed25519(kp) => {
                    let sig =
                        fastcrypto::traits::Signer::<fastcrypto::ed25519::Ed25519Signature>::sign(
                            kp, msg,
                        );
                    (kp.public().as_bytes().to_vec(), sig.as_bytes().to_vec())
                }
                StarcoinKeyPair::Secp256k1(kp) => {
                    let sig = fastcrypto::traits::Signer::<fastcrypto::secp256k1::Secp256k1Signature>::sign(kp, msg);
                    (kp.public().as_bytes().to_vec(), sig.as_bytes().to_vec())
                }
            }
        }

        /// Get the private key bytes (for Ed25519 signing)
        pub fn private_key_bytes(&self) -> Vec<u8> {
            match self {
                StarcoinKeyPair::Ed25519(kp) => kp.as_bytes()[..32].to_vec(), // Ed25519 private key is first 32 bytes
                StarcoinKeyPair::Secp256k1(kp) => kp.as_bytes().to_vec(),
            }
        }
    }

    // Implement Signer trait for Signature compatibility
    impl fastcrypto::traits::Signer<Signature> for StarcoinKeyPair {
        fn sign(&self, msg: &[u8]) -> Signature {
            let (_, sig_bytes) = self.sign_message(msg);
            Signature(sig_bytes)
        }
    }

    // Implement starcoin Signer for StarcoinKeyPair
    impl
        starcoin_bridge_vm_types::bridge::crypto::Signer<
            starcoin_bridge_vm_types::bridge::crypto::AuthoritySignature,
        > for StarcoinKeyPair
    {
        fn sign(
            &self,
            _msg: &[u8],
        ) -> starcoin_bridge_vm_types::bridge::crypto::AuthoritySignature {
            // Stub implementation - returns placeholder signature
            use fastcrypto::traits::ToFromBytes;
            // Create a placeholder Ed25519Signature with zeros
            starcoin_bridge_vm_types::bridge::crypto::AuthoritySignature::from_bytes(&[0u8; 64])
                .expect("Failed to create placeholder signature")
        }
    }

    impl EncodeDecodeBase64 for StarcoinKeyPair {
        /// Encode keypair as base64 string with scheme flag prefix (flag || privkey)
        fn encode_base64(&self) -> String {
            use base64ct::{Base64, Encoding};
            Base64::encode_string(&self.to_bytes())
        }

        /// Decode base64 string with scheme flag prefix to keypair
        fn decode_base64(value: &str) -> Result<Self, FastCryptoError> {
            use base64ct::{Base64, Encoding};
            let bytes = Base64::decode_vec(value).map_err(|_| FastCryptoError::InvalidInput)?;
            Self::from_bytes(&bytes).map_err(|_| FastCryptoError::InvalidInput)
        }
    }

    /// Signature scheme flags matching Starcoin's implementation
    const ED25519_FLAG: u8 = 0x00;
    const SECP256K1_FLAG: u8 = 0x01;

    impl StarcoinKeyPair {
        /// Get the scheme flag for this keypair
        fn scheme_flag(&self) -> u8 {
            match self {
                StarcoinKeyPair::Ed25519(_) => ED25519_FLAG,
                StarcoinKeyPair::Secp256k1(_) => SECP256K1_FLAG,
            }
        }

        /// Convert keypair to bytes with scheme flag prefix (flag || privkey)
        pub fn to_bytes(&self) -> Vec<u8> {
            let mut bytes: Vec<u8> = Vec::new();
            // Add scheme flag as first byte
            bytes.push(self.scheme_flag());

            // Add private key bytes
            match self {
                StarcoinKeyPair::Ed25519(kp) => {
                    bytes.extend_from_slice(kp.as_bytes());
                }
                StarcoinKeyPair::Secp256k1(kp) => {
                    bytes.extend_from_slice(kp.as_bytes());
                }
            }
            bytes
        }

        /// Parse keypair from bytes with scheme flag prefix (flag || privkey)
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
            let flag = bytes.first().ok_or(FastCryptoError::InvalidInput)?;

            match *flag {
                ED25519_FLAG => {
                    let kp = Ed25519KeyPair::from_bytes(&bytes[1..])
                        .map_err(|_| FastCryptoError::InvalidInput)?;
                    Ok(StarcoinKeyPair::Ed25519(kp))
                }
                SECP256K1_FLAG => {
                    let kp = Secp256k1KeyPair::from_bytes(&bytes[1..])
                        .map_err(|_| FastCryptoError::InvalidInput)?;
                    Ok(StarcoinKeyPair::Secp256k1(kp))
                }
                _ => Err(FastCryptoError::InvalidInput),
            }
        }
    }
}

pub mod message_envelope {
    pub use starcoin_bridge_vm_types::bridge::message_envelope::*;
}

// Block number type alias (was CheckpointSequenceNumber from Sui)
pub type BlockNumber = u64;

pub mod collection_types {
    pub use starcoin_bridge_vm_types::bridge::collection_types::*;
}

// ============= Types still needing stubs =============

// Add quorum_driver_types module
pub mod quorum_driver_types {
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Serialize, Deserialize, Default)]
    pub struct ExecuteTransactionRequestV3 {
        pub transaction: Vec<u8>,
        pub include_events: bool,
        pub include_input_objects: bool,
        pub include_output_objects: bool,
        pub include_auxiliary_data: bool,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum ExecuteTransactionRequestType {
        WaitForEffectsCert,
        WaitForLocalExecution,
    }
}

pub mod digests {
    pub use starcoin_bridge_vm_types::bridge::base_types::TransactionDigest;

    // Digest trait placeholder
    pub trait Digest: Clone + std::fmt::Debug {}
    impl Digest for TransactionDigest {}
}

pub mod transaction {
    use super::*;
    use move_core_types::identifier::{IdentStr, Identifier};
    use move_core_types::language_storage::{ModuleId, TypeTag};

    // ==========================================================================
    // Starcoin Native Transaction Types
    // ==========================================================================

    /// ScriptFunction - calls a Move function on-chain
    /// This is the primary way to interact with Move contracts on Starcoin
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ScriptFunction {
        pub module: ModuleId,
        pub function: Identifier,
        pub ty_args: Vec<TypeTag>,
        pub args: Vec<Vec<u8>>,
    }

    impl ScriptFunction {
        pub fn new(
            module: ModuleId,
            function: Identifier,
            ty_args: Vec<TypeTag>,
            args: Vec<Vec<u8>>,
        ) -> Self {
            Self {
                module,
                function,
                ty_args,
                args,
            }
        }

        pub fn module(&self) -> &ModuleId {
            &self.module
        }

        pub fn function(&self) -> &IdentStr {
            &self.function
        }

        pub fn ty_args(&self) -> &[TypeTag] {
            &self.ty_args
        }

        pub fn args(&self) -> &[Vec<u8>] {
            &self.args
        }
    }

    /// Transaction payload - what the transaction does
    /// Order MUST match Starcoin's TransactionPayload enum: Script=0, Package=1, ScriptFunction=2
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum TransactionPayload {
        /// Script (legacy, not used)
        Script(Vec<u8>),
        /// Package deployment (not used in bridge)
        Package(Vec<u8>),
        /// Call a script function (this is what we use)
        ScriptFunction(ScriptFunction),
    }

    /// Chain ID for replay protection
    #[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
    pub struct ChainId(pub u8);

    impl ChainId {
        pub fn new(id: u8) -> Self {
            ChainId(id)
        }

        pub fn id(&self) -> u8 {
            self.0
        }
    }

    /// RawUserTransaction - the core transaction structure in Starcoin
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct RawUserTransaction {
        pub sender: super::base_types::StarcoinAddress,
        pub sequence_number: u64,
        pub payload: TransactionPayload,
        pub max_gas_amount: u64,
        pub gas_unit_price: u64,
        pub gas_token_code: String,
        pub expiration_timestamp_secs: u64,
        pub chain_id: ChainId,
    }

    impl RawUserTransaction {
        /// Create a new RawUserTransaction with a script function
        pub fn new_script_function(
            sender: super::base_types::StarcoinAddress,
            sequence_number: u64,
            script_function: ScriptFunction,
            max_gas_amount: u64,
            gas_unit_price: u64,
            expiration_timestamp_secs: u64,
            chain_id: ChainId,
        ) -> Self {
            Self {
                sender,
                sequence_number,
                payload: TransactionPayload::ScriptFunction(script_function),
                max_gas_amount,
                gas_unit_price,
                gas_token_code: "0x1::STC::STC".to_string(),
                expiration_timestamp_secs,
                chain_id,
            }
        }

        pub fn sender(&self) -> super::base_types::StarcoinAddress {
            self.sender
        }

        pub fn sequence_number(&self) -> u64 {
            self.sequence_number
        }

        pub fn payload(&self) -> &TransactionPayload {
            &self.payload
        }

        pub fn max_gas_amount(&self) -> u64 {
            self.max_gas_amount
        }

        pub fn gas_unit_price(&self) -> u64 {
            self.gas_unit_price
        }

        pub fn expiration_timestamp_secs(&self) -> u64 {
            self.expiration_timestamp_secs
        }

        pub fn chain_id(&self) -> ChainId {
            self.chain_id
        }

        /// Serialize for signing
        pub fn to_bytes(&self) -> Vec<u8> {
            bcs::to_bytes(self).expect("RawUserTransaction serialization should not fail")
        }
    }

    /// Signed transaction ready for submission
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SignedUserTransaction {
        pub raw_txn: RawUserTransaction,
        pub authenticator: TransactionAuthenticator,
    }

    impl SignedUserTransaction {
        pub fn new(raw_txn: RawUserTransaction, authenticator: TransactionAuthenticator) -> Self {
            Self {
                raw_txn,
                authenticator,
            }
        }

        /// Compute transaction hash
        pub fn hash(&self) -> super::base_types::TransactionDigest {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            let bytes = self.to_bytes();
            let mut hasher = DefaultHasher::new();
            bytes.hash(&mut hasher);
            let hash = hasher.finish();

            let mut digest = [0u8; 32];
            digest[..8].copy_from_slice(&hash.to_le_bytes());
            digest[8..16].copy_from_slice(&hash.to_be_bytes());
            digest
        }

        /// Serialize to BCS bytes - combines raw_txn and authenticator
        pub fn to_bytes(&self) -> Vec<u8> {
            let raw_bytes = bcs::to_bytes(&self.raw_txn).unwrap_or_default();
            let auth_bytes = self.authenticator.to_bcs_bytes();
            let mut result = raw_bytes;
            result.extend_from_slice(&auth_bytes);
            result
        }

        /// Encode as hex string for RPC submission
        pub fn to_hex(&self) -> String {
            hex::encode(self.to_bytes())
        }
    }

    /// Transaction authenticator (signature)
    /// Uses fixed-size arrays to match Starcoin's BCS serialization format
    #[derive(Clone, Debug)]
    pub enum TransactionAuthenticator {
        /// Ed25519 signature (32-byte public key, 64-byte signature)
        Ed25519 {
            public_key: [u8; 32],
            signature: [u8; 64],
        },
        /// Multi-ed25519 (not commonly used)
        MultiEd25519 {
            public_key: Vec<u8>,
            signature: Vec<u8>,
        },
    }

    impl TransactionAuthenticator {
        /// Serialize to BCS bytes manually to ensure correct format
        pub fn to_bcs_bytes(&self) -> Vec<u8> {
            match self {
                TransactionAuthenticator::Ed25519 {
                    public_key,
                    signature,
                } => {
                    // BCS format: variant_index (1 byte for small enum) + public_key (32 bytes) + signature (64 bytes)
                    let mut bytes = Vec::with_capacity(1 + 32 + 64);
                    bytes.push(0u8); // variant index for Ed25519
                    bytes.extend_from_slice(public_key);
                    bytes.extend_from_slice(signature);
                    bytes
                }
                TransactionAuthenticator::MultiEd25519 {
                    public_key,
                    signature,
                } => {
                    let mut bytes = Vec::new();
                    bytes.push(1u8); // variant index for MultiEd25519
                                     // Vec<u8> needs length prefix
                    bytes.extend_from_slice(&(public_key.len() as u32).to_le_bytes()[..]);
                    bytes.extend_from_slice(public_key);
                    bytes.extend_from_slice(&(signature.len() as u32).to_le_bytes()[..]);
                    bytes.extend_from_slice(signature);
                    bytes
                }
            }
        }
    }

    impl serde::Serialize for TransactionAuthenticator {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            // Use manual BCS serialization
            serializer.serialize_bytes(&self.to_bcs_bytes())
        }
    }

    impl<'de> serde::Deserialize<'de> for TransactionAuthenticator {
        fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            // Not commonly needed for our use case
            Err(serde::de::Error::custom(
                "TransactionAuthenticator deserialization not implemented",
            ))
        }
    }

    // ==========================================================================
    // Backward Compatibility Layer (for migration from Sui)
    // These types are kept for code that still uses Sui patterns
    // ==========================================================================

    /// Legacy: Placeholder for Starcoin transaction type
    pub type StarcoinTransaction = Vec<u8>;

    /// Legacy: Wrapper type for Transaction with backward-compatible interface
    #[derive(Clone, Debug)]
    pub struct Transaction(pub StarcoinTransaction);

    impl Transaction {
        pub fn from_data(
            _data: TransactionData,
            _signatures: Vec<super::crypto::Signature>,
        ) -> Self {
            // Stub implementation - use SignedUserTransaction instead
            Transaction(vec![])
        }

        pub fn digest(&self) -> &super::base_types::TransactionDigest {
            static DIGEST: super::base_types::TransactionDigest = [0u8; 32];
            &DIGEST
        }
    }

    /// Legacy: TransactionData for backward compatibility
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct TransactionData {
        /// The actual Starcoin transaction (if built)
        #[serde(skip)]
        pub inner: Option<RawUserTransaction>,
    }

    impl TransactionData {
        /// Legacy constructor - kept for compatibility but does nothing useful
        pub fn new_programmable(
            _sender: super::base_types::StarcoinAddress,
            _gas_payment: Vec<([u8; 32], u64, [u8; 32])>,
            _pt: ProgrammableTransaction,
            _gas_budget: u64,
            _gas_price: u64,
        ) -> Self {
            TransactionData { inner: None }
        }
    }

    /// Transaction metadata and digest wrapper
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct TransactionDigestWrapper(pub [u8; 32]);

    impl TransactionDigestWrapper {
        /// Get reference to inner bytes
        pub fn inner(&self) -> &[u8; 32] {
            &self.0
        }

        /// Convert to Vec<u8> for storage
        pub fn to_vec(&self) -> Vec<u8> {
            self.0.to_vec()
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct TransactionDataAPI {
        pub transaction: StarcoinTransaction,
        /// Transaction hash/digest
        #[serde(default)]
        pub digest: [u8; 32],
        /// Sender address (16 bytes for Starcoin, padded to 32)
        #[serde(default)]
        pub sender: [u8; 32],
    }

    impl TransactionDataAPI {
        /// Get the transaction digest wrapper (owned copy)
        pub fn digest(&self) -> TransactionDigestWrapper {
            TransactionDigestWrapper(self.digest)
        }

        /// Get the transaction digest as bytes directly (for cases needing longer lifetime)
        pub fn digest_bytes(&self) -> &[u8; 32] {
            &self.digest
        }

        /// Get the sender address as bytes
        pub fn sender_address(&self) -> [u8; 32] {
            self.sender
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum CallArg {
        Pure(Vec<u8>),
        Object(ObjectArg),
    }

    impl CallArg {
        pub const CLOCK_IMM: Self = CallArg::Object(ObjectArg::SharedObject {
            id: [0u8; 32],
            initial_shared_version: 1,
            mutable: false,
        });
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum ObjectArg {
        ImmOrOwnedObject(([u8; 32], u64, [u8; 32])),
        SharedObject {
            id: [u8; 32],
            initial_shared_version: u64,
            mutable: bool,
        },
    }

    impl ObjectArg {
        pub const STARCOIN_SYSTEM_MUT: Self = ObjectArg::SharedObject {
            id: [0u8; 32],
            initial_shared_version: 1,
            mutable: true,
        };
    }

    #[derive(Copy, Clone, Debug, Serialize, Deserialize)]
    pub enum Argument {
        Input(u16),
        Result(u16),
        NestedResult(u16, u16),
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum Command {
        MoveCall(Box<ProgrammableMoveCall>),
        TransferObjects(Vec<Argument>, Argument),
        SplitCoins(Argument, Vec<Argument>),
        MergeCoins(Argument, Vec<Argument>),
    }

    impl Command {
        pub fn move_call(
            package: [u8; 32],
            module: Identifier,
            function: Identifier,
            type_arguments: Vec<TypeTag>,
            arguments: Vec<Argument>,
        ) -> Self {
            Command::MoveCall(Box::new(ProgrammableMoveCall {
                package,
                module,
                function,
                type_arguments,
                arguments,
            }))
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ProgrammableMoveCall {
        pub package: [u8; 32],
        pub module: Identifier,
        pub function: Identifier,
        pub type_arguments: Vec<TypeTag>,
        pub arguments: Vec<Argument>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ProgrammableTransaction {
        pub inputs: Vec<CallArg>,
        pub commands: Vec<Command>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum TransactionKind {
        ProgrammableTransaction(ProgrammableTransaction),
    }

    impl TransactionKind {
        pub fn programmable(pt: ProgrammableTransaction) -> Self {
            TransactionKind::ProgrammableTransaction(pt)
        }
    }
}

pub mod event {
    use move_core_types::language_storage::StructTag;
    use serde::{Deserialize, Serialize};

    // Use a simple tuple for EventID (checkpoint_sequence, event_index)
    pub type EventID = (u64, u64);

    /// Contract event with type tag and BCS-encoded contents
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Event {
        /// The type of the event (Move struct tag)
        pub type_: StructTag,
        /// BCS-encoded event contents
        pub contents: Vec<u8>,
    }
}

/// Transaction effects containing gas usage and execution results
pub mod effects {
    use serde::{Deserialize, Serialize};

    /// Gas cost summary for a transaction
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct GasCostSummary {
        /// Gas used for computation
        pub computation_cost: u64,
        /// Gas used for storage
        pub storage_cost: u64,
        /// Storage rebate (refund)
        pub storage_rebate: u64,
        /// Non-refundable storage fee
        pub non_refundable_storage_fee: u64,
    }

    impl GasCostSummary {
        /// Net gas usage (total cost minus rebate)
        pub fn net_gas_usage(&self) -> i64 {
            let total = self.computation_cost + self.storage_cost;
            total as i64 - self.storage_rebate as i64
        }

        /// Total gas cost (computation + storage)
        pub fn total_gas_cost(&self) -> u64 {
            self.computation_cost + self.storage_cost
        }
    }

    /// Transaction effects
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct TransactionEffects {
        /// Gas usage summary
        pub gas_used: GasCostSummary,
        /// Execution status
        #[serde(default)]
        pub execution_status: super::execution_status::ExecutionStatus,
    }

    impl TransactionEffects {
        /// Get the gas cost summary
        pub fn gas_cost_summary(&self) -> &GasCostSummary {
            &self.gas_used
        }

        /// Get the execution status
        pub fn status(&self) -> &super::execution_status::ExecutionStatus {
            &self.execution_status
        }
    }

    /// Trait for types that provide transaction effects info
    pub trait TransactionEffectsAPI {
        fn gas_cost_summary(&self) -> &GasCostSummary;
    }

    impl TransactionEffectsAPI for TransactionEffects {
        fn gas_cost_summary(&self) -> &GasCostSummary {
            &self.gas_used
        }
    }
}

/// Execution status of a transaction
pub mod execution_status {
    use serde::{Deserialize, Serialize};

    /// Execution status enum
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub enum ExecutionStatus {
        /// Transaction executed successfully
        #[default]
        Success,
        /// Transaction failed with error
        Failure {
            /// Error message or code
            error: String,
            /// Command index that failed (if applicable)
            command: Option<u64>,
        },
    }

    impl ExecutionStatus {
        /// Check if the execution was successful
        pub fn is_success(&self) -> bool {
            matches!(self, ExecutionStatus::Success)
        }

        /// Check if the execution failed
        pub fn is_failure(&self) -> bool {
            matches!(self, ExecutionStatus::Failure { .. })
        }
    }
}

pub mod programmable_transaction_builder {
    use super::transaction::*;

    pub struct ProgrammableTransactionBuilder {
        inputs: Vec<CallArg>,
        commands: Vec<Command>,
        next_input: u16,
    }

    impl Default for ProgrammableTransactionBuilder {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ProgrammableTransactionBuilder {
        pub fn new() -> Self {
            Self {
                inputs: Vec::new(),
                commands: Vec::new(),
                next_input: 0,
            }
        }

        pub fn pure<T: serde::Serialize>(&mut self, value: T) -> Result<Argument, String> {
            let bytes = bcs::to_bytes(&value).map_err(|e| e.to_string())?;
            let input_idx = self.next_input;
            self.next_input += 1;
            self.inputs.push(CallArg::Pure(bytes));
            Ok(Argument::Input(input_idx))
        }

        pub fn input(&mut self, call_arg: CallArg) -> Result<Argument, String> {
            let input_idx = self.next_input;
            self.next_input += 1;
            self.inputs.push(call_arg);
            Ok(Argument::Input(input_idx))
        }

        pub fn obj(&mut self, obj_arg: ObjectArg) -> Result<Argument, String> {
            let input_idx = self.next_input;
            self.next_input += 1;
            self.inputs.push(CallArg::Object(obj_arg));
            Ok(Argument::Input(input_idx))
        }

        pub fn programmable_move_call(
            &mut self,
            package: [u8; 32],
            module: move_core_types::identifier::Identifier,
            function: move_core_types::identifier::Identifier,
            type_arguments: Vec<move_core_types::language_storage::TypeTag>,
            call_args: Vec<Argument>,
        ) -> Argument {
            let command_idx = self.commands.len() as u16;
            self.commands.push(Command::move_call(
                package,
                module,
                function,
                type_arguments,
                call_args,
            ));
            Argument::Result(command_idx)
        }

        pub fn finish(self) -> ProgrammableTransaction {
            ProgrammableTransaction {
                inputs: self.inputs,
                commands: self.commands,
            }
        }
    }
}

pub mod gas_coin {
    #[derive(Clone, Debug)]
    pub struct GasCoin {
        pub value: u64,
    }

    impl GasCoin {
        pub fn value(&self) -> u64 {
            self.value
        }

        /// Create a new GasCoin for testing with the given value
        pub fn new_for_testing(value: u64) -> Self {
            Self { value }
        }
    }
}

pub mod starcoin_bridge_system_state {
    use super::*;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct StarcoinSystemState {
        pub epoch: u64,
    }

    pub mod starcoin_bridge_system_state_summary {
        use super::*;

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct StarcoinSystemStateSummary {
            pub epoch: u64,
            pub active_validators: Vec<StarcoinValidatorSummary>,
        }

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct StarcoinValidatorSummary {
            pub starcoin_bridge_address: super::base_types::StarcoinAddress,
            pub name: String,
        }
    }
}

// ============= Constants =============
// Starcoin bridge package address (32 bytes for compatibility, but Starcoin uses 16 bytes)
// Bridge contract deployed address on Starcoin dev network: 0x0b8e0206e990e41e913a7f03d1c60675
// Padded with zeros in front to maintain compatibility with existing code expecting 32 bytes
pub const BRIDGE_PACKAGE_ID: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16 zero bytes padding
    0x0b, 0x8e, 0x02, 0x06, 0xe9, 0x90, 0xe4, 0x1e, // Actual Starcoin address
    0x91, 0x3a, 0x7f, 0x03, 0xd1, 0xc6, 0x06, 0x75,
];
// Note: Starcoin doesn't have a separate bridge object like Starcoin
pub const STARCOIN_BRIDGE_OBJECT_ID: [u8; 32] = [0; 32];

/// Bridge address constant as [u8; 32] (for backward compatibility)
pub const BRIDGE_ADDRESS_BYTES: [u8; 32] = BRIDGE_PACKAGE_ID;

/// Starcoin bridge contract address (16 bytes)
/// 0x0b8e0206e990e41e913a7f03d1c60675
pub const BRIDGE_ADDRESS_16: [u8; 16] = [
    0x0b, 0x8e, 0x02, 0x06, 0xe9, 0x90, 0xe4, 0x1e, 0x91, 0x3a, 0x7f, 0x03, 0xd1, 0xc6, 0x06, 0x75,
];

// Use Starcoin/Move types instead of stubs
use move_core_types::account_address::AccountAddress;
pub use move_core_types::identifier::Identifier;
use move_core_types::language_storage::StructTag;
pub use move_core_types::language_storage::TypeTag;

/// Bridge address as Move AccountAddress (for StructTag usage)
pub const BRIDGE_ADDRESS: AccountAddress = AccountAddress::new(BRIDGE_ADDRESS_16);

/// Parse a Starcoin type tag from hex-encoded BCS bytes
/// Format: 0x<address><module_name_len><module_name><struct_name_len><struct_name>
/// Example: 0x17124f9c12268ee0b18f73483beb6f4c0345544803455448 -> 0x...::ETH::ETH
pub fn parse_starcoin_bridge_type_tag(s: &str) -> Result<TypeTag, String> {
    // Handle multiple 0x prefixes (e.g., "0x0x..." from double formatting)
    let mut hex_str = s;
    while hex_str.starts_with("0x") || hex_str.starts_with("0X") {
        hex_str = &hex_str[2..];
    }
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    parse_token_code_bytes_to_type_tag(&bytes)
}

/// Parse a TypeTag from BCS-encoded TokenCode bytes (from BCS::to_bytes(&Token::token_code<T>()))
/// Format: <address:16 bytes><module_name_len:1 byte><module_name><struct_name_len:1 byte><struct_name>
pub fn parse_token_code_bytes_to_type_tag(bytes: &[u8]) -> Result<TypeTag, String> {
    if bytes.len() < 16 {
        return Err(format!("Type tag too short: {} bytes", bytes.len()));
    }

    // First 16 bytes are the address
    let mut address_bytes = [0u8; 16];
    address_bytes.copy_from_slice(&bytes[0..16]);
    let address = AccountAddress::new(address_bytes);

    let mut offset = 16;

    // Read module name (length-prefixed string)
    if offset >= bytes.len() {
        return Err("Missing module name".to_string());
    }
    let module_len = bytes[offset] as usize;
    offset += 1;
    if offset + module_len > bytes.len() {
        return Err("Module name truncated".to_string());
    }
    let module_name = String::from_utf8(bytes[offset..offset + module_len].to_vec())
        .map_err(|e| format!("Invalid module name UTF-8: {}", e))?;
    offset += module_len;

    // Read struct name (length-prefixed string)
    if offset >= bytes.len() {
        return Err("Missing struct name".to_string());
    }
    let struct_len = bytes[offset] as usize;
    offset += 1;
    if offset + struct_len > bytes.len() {
        return Err("Struct name truncated".to_string());
    }
    let struct_name = String::from_utf8(bytes[offset..offset + struct_len].to_vec())
        .map_err(|e| format!("Invalid struct name UTF-8: {}", e))?;

    Ok(TypeTag::Struct(Box::new(StructTag {
        address,
        module: Identifier::new(module_name)
            .map_err(|e| format!("Invalid module identifier: {}", e))?,
        name: Identifier::new(struct_name)
            .map_err(|e| format!("Invalid struct identifier: {}", e))?,
        type_params: vec![],
    })))
}
