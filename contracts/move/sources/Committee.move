// Copyright (c) Starcoin Contributors
// SPDX-License-Identifier: Apache-2.0

module Bridge::Committee {

    use Bridge::Crypto;
    use Bridge::EcdsaK1;
    use Bridge::Message::{Self, Blocklist, BridgeMessage};

    use StarcoinFramework::Errors;
    use StarcoinFramework::Event;
    use StarcoinFramework::Hash;
    use StarcoinFramework::Signer;
    use StarcoinFramework::SimpleMap;
    use StarcoinFramework::SimpleMap::SimpleMap;
    use StarcoinFramework::Vector;

    const ESignatureBelowThreshold: u64 = 0;
    const EDuplicatedSignature: u64 = 1;
    const EInvalidSignature: u64 = 2;
    const ENotSystemAddress: u64 = 3;
    const EValidatorBlocklistContainsUnknownKey: u64 = 4;
    const EInvalidPubkeyLength: u64 = 6;
    const EDuplicatePubkey: u64 = 8;

    const STARCOIN_MESSAGE_PREFIX: vector<u8> = b"STARCOIN_BRIDGE_MESSAGE";

    const ECDSA_COMPRESSED_PUBKEY_LENGTH: u64 = 33;

    //////////////////////////////////////////////////////
    // Types
    //
    struct BlocklistValidatorEvent has copy, drop, store {
        blocklisted: bool,
        public_keys: vector<vector<u8>>,
    }

    struct BridgeCommittee has store {
        /// Committee members keyed by raw pubkey (64-byte uncompressed without 0x04 prefix)
        members: SimpleMap<vector<u8>, CommitteeMember>,
    }

    struct EventHandlePod has key, store {
        committee_update_event: Event::EventHandle<CommitteeUpdateEvent>,
        block_list_validator_event: Event::EventHandle<BlocklistValidatorEvent>,
    }

    struct CommitteeUpdateEvent has copy, drop, store {
        members: SimpleMap<vector<u8>, CommitteeMember>,
    }

    struct CommitteeMember has copy, drop, store {
        /// The public key bytes of the bridge key (33-byte compressed ECDSA)
        bridge_pubkey_bytes: vector<u8>,
        /// Voting power, values are voting power in the scale of 10000.
        voting_power: u64,
        /// The HTTP REST URL the member's node listens to
        /// e.g., b'https://127.0.0.1:9191'
        http_rest_url: vector<u8>,
        /// If this member is blocklisted
        blocklisted: bool,
    }

    //////////////////////////////////////////////////////
    // Public functions
    //

    public fun initialize(bridge: &signer) {
        let bridge_addr = Signer::address_of(bridge);
        assert!(bridge_addr == @Bridge, Errors::requires_address(EInvalidSignature));
        if (!exists<EventHandlePod>(bridge_addr)) {
            move_to(bridge, EventHandlePod {
                committee_update_event: Event::new_event_handle<CommitteeUpdateEvent>(bridge),
                block_list_validator_event: Event::new_event_handle<BlocklistValidatorEvent>(bridge),
            });
        };
    }

    public fun verify_signatures(
        self: &BridgeCommittee,
        message: BridgeMessage,
        signatures: vector<vector<u8>>,
    ) {
        let (i, signature_counts) = (0, Vector::length(&signatures));
        let seen_pub_key = Vector::empty<vector<u8>>();
        let required_voting_power = Message::required_voting_power(&message);
        // add prefix to the message bytes, then hash with keccak256
        let message_bytes = STARCOIN_MESSAGE_PREFIX;
        Vector::append(&mut message_bytes, Message::serialize_message(message));
        let message_hash = Hash::keccak_256(message_bytes);

        let threshold = 0;
        while (i < signature_counts) {
            // Use secp256k1_ecrecover_digest since we already have the hash
            let pubkey = EcdsaK1::secp256k1_ecrecover_digest(Vector::borrow(&signatures, i), &message_hash);

            // check duplicate
            // and make sure pub key is part of the committee
            assert!(!Vector::contains(&seen_pub_key, &pubkey), Errors::invalid_state(EDuplicatedSignature));
            assert!(SimpleMap::contains_key(&self.members, &pubkey), Errors::requires_address(EInvalidSignature));

            // get committee signature weight and check pubkey is part of the committee
            let member = SimpleMap::borrow(&self.members, &pubkey);
            if (!member.blocklisted) {
                threshold = threshold + member.voting_power;
            };
            Vector::push_back(&mut seen_pub_key, pubkey);
            i = i + 1;
        };
        assert!(threshold >= required_voting_power, Errors::invalid_state(ESignatureBelowThreshold));
    }

    //////////////////////////////////////////////////////
    // Internal functions
    //

    public fun create(): BridgeCommittee {
        BridgeCommittee {
            members: SimpleMap::create<vector<u8>, CommitteeMember>(),
        }
    }

    public fun destroy(committee: BridgeCommittee) {
        let BridgeCommittee { members: _ } = committee;
    }

    // This function applys the blocklist to the committee members, we won't need to run this very often so this is not gas optimised.
    public fun execute_blocklist(self: &mut BridgeCommittee, blocklist: Blocklist) acquires EventHandlePod {
        let blocklisted = Message::blocklist_type(&blocklist) != 1;
        let eth_addresses = Message::blocklist_validator_addresses(&blocklist);
        let list_len = Vector::length(eth_addresses);
        let list_idx = 0;
        let member_idx = 0;
        let pub_keys = vector[];

        let members_len = SimpleMap::length(&self.members);
        while (list_idx < list_len) {
            let target_address = Vector::borrow(eth_addresses, list_idx);
            let found = false;


            while (member_idx < members_len) {
                let (pub_key, member) = SimpleMap::borrow_index_mut(&mut self.members, member_idx);
                let eth_address = Crypto::ecdsa_pub_key_to_eth_address(pub_key);

                if (*target_address == eth_address) {
                    member.blocklisted = blocklisted;
                    Vector::push_back(&mut pub_keys, *pub_key);
                    found = true;
                    member_idx = 0;
                    break
                };

                member_idx = member_idx + 1;
            };

            assert!(found, EValidatorBlocklistContainsUnknownKey);
            list_idx = list_idx + 1;
        };

        let eh = borrow_global_mut<EventHandlePod>(@Bridge);
        Event::emit_event(&mut eh.block_list_validator_event, BlocklistValidatorEvent {
            blocklisted,
            public_keys: pub_keys,
        })
    }

    public fun committee_members(self: &BridgeCommittee): &SimpleMap<vector<u8>, CommitteeMember> {
        &self.members
    }

    /// Check if the committee is empty (no members registered)
    public fun is_empty(self: &BridgeCommittee): bool {
        SimpleMap::length(&self.members) == 0
    }

    /// Internal helper to add a member without emitting events.
    /// Used during initial committee setup.
    fun add_member_internal(
        self: &mut BridgeCommittee,
        bridge_pubkey_bytes: vector<u8>,
        voting_power: u64,
        http_rest_url: vector<u8>,
    ) {
        // Validate pubkey length
        assert!(
            Vector::length(&bridge_pubkey_bytes) == ECDSA_COMPRESSED_PUBKEY_LENGTH,
            Errors::invalid_state(EInvalidPubkeyLength)
        );

        // Decompress the pubkey to get raw pubkey for map key
        let uncompressed = EcdsaK1::decompress_pubkey(&bridge_pubkey_bytes);
        let raw_pubkey = Vector::empty<u8>();
        let j = 1; // Skip 0x04 prefix
        while (j < 65) {
            Vector::push_back(&mut raw_pubkey, *Vector::borrow(&uncompressed, j));
            j = j + 1;
        };

        // Check if member already exists
        assert!(!SimpleMap::contains_key(&self.members, &raw_pubkey), EDuplicatePubkey);

        let member = CommitteeMember {
            bridge_pubkey_bytes,
            voting_power,
            http_rest_url,
            blocklisted: false,
        };

        SimpleMap::add(&mut self.members, raw_pubkey, member);
    }

    /// Initialize committee with a single member (for dev/test).
    /// Only Bridge admin can call this.
    public fun init_committee(
        self: &mut BridgeCommittee,
        bridge_pubkey_bytes: vector<u8>,
        voting_power: u64,
        http_rest_url: vector<u8>,
    ) acquires EventHandlePod {
        add_member_internal(self, bridge_pubkey_bytes, voting_power, http_rest_url);

        // Emit event
        let eh = borrow_global_mut<EventHandlePod>(@Bridge);
        Event::emit_event(&mut eh.committee_update_event, CommitteeUpdateEvent {
            members: self.members,
        });
    }

    /// Initialize committee with exactly 4 members in a single call.
    /// This is a convenience function for local dev/test with multi-validator setup.
    public fun init_committee_four(
        self: &mut BridgeCommittee,
        pubkey1: vector<u8>, power1: u64, url1: vector<u8>,
        pubkey2: vector<u8>, power2: u64, url2: vector<u8>,
        pubkey3: vector<u8>, power3: u64, url3: vector<u8>,
        pubkey4: vector<u8>, power4: u64, url4: vector<u8>,
    ) acquires EventHandlePod {
        add_member_internal(self, pubkey1, power1, url1);
        add_member_internal(self, pubkey2, power2, url2);
        add_member_internal(self, pubkey3, power3, url3);
        add_member_internal(self, pubkey4, power4, url4);

        // Emit event once after all members are added
        let eh = borrow_global_mut<EventHandlePod>(@Bridge);
        Event::emit_event(&mut eh.committee_update_event, CommitteeUpdateEvent {
            members: self.members,
        });
    }

    /// Add a new member to the committee via governance action.
    /// The bridge_pubkey_bytes should be 33-byte compressed ECDSA pubkey.
    public fun add_member(
        self: &mut BridgeCommittee,
        bridge_pubkey_bytes: vector<u8>,
        voting_power: u64,
        http_rest_url: vector<u8>,
    ) acquires EventHandlePod {
        // Validate pubkey length
        assert!(
            Vector::length(&bridge_pubkey_bytes) == ECDSA_COMPRESSED_PUBKEY_LENGTH,
            Errors::invalid_state(EInvalidPubkeyLength)
        );

        // Decompress the pubkey to get raw pubkey for map key
        let uncompressed = EcdsaK1::decompress_pubkey(&bridge_pubkey_bytes);
        let raw_pubkey = Vector::empty<u8>();
        let j = 1; // Skip 0x04 prefix
        while (j < 65) {
            Vector::push_back(&mut raw_pubkey, *Vector::borrow(&uncompressed, j));
            j = j + 1;
        };

        // Check if member already exists
        assert!(!SimpleMap::contains_key(&self.members, &raw_pubkey), EDuplicatePubkey);

        let member = CommitteeMember {
            bridge_pubkey_bytes,
            voting_power,
            http_rest_url,
            blocklisted: false,
        };

        SimpleMap::add(&mut self.members, raw_pubkey, member);

        // Emit event
        let eh = borrow_global_mut<EventHandlePod>(@Bridge);
        Event::emit_event(&mut eh.committee_update_event, CommitteeUpdateEvent {
            members: self.members,
        });
    }

    //////////////////////////////////////////////////////
    // Test functions
    //

    #[test_only]
    public fun members(self: &BridgeCommittee): &SimpleMap<vector<u8>, CommitteeMember> {
        &self.members
    }

    #[test_only]
    public fun voting_power(member: &CommitteeMember): u64 {
        member.voting_power
    }

    #[test_only]
    public fun http_rest_url(member: &CommitteeMember): vector<u8> {
        member.http_rest_url
    }

    #[test_only]
    public fun blocklisted(member: &CommitteeMember): bool {
        member.blocklisted
    }

    #[test_only]
    public fun make_bridge_committee(
        members: SimpleMap<vector<u8>, CommitteeMember>,
    ): BridgeCommittee {
        BridgeCommittee {
            members,
        }
    }

    #[test_only]
    public fun make_committee_member(
        bridge_pubkey_bytes: vector<u8>,
        voting_power: u64,
        http_rest_url: vector<u8>,
        blocklisted: bool,
    ): CommitteeMember {
        CommitteeMember {
            bridge_pubkey_bytes,
            voting_power,
            http_rest_url,
            blocklisted,
        }
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
    /// Add member without emitting events (for testing without global resources).
    public fun add_member_for_testing(
        self: &mut BridgeCommittee,
        bridge_pubkey_bytes: vector<u8>,
        voting_power: u64,
        http_rest_url: vector<u8>,
    ) {
        // Validate pubkey length
        assert!(
            Vector::length(&bridge_pubkey_bytes) == ECDSA_COMPRESSED_PUBKEY_LENGTH,
            Errors::invalid_state(EInvalidPubkeyLength)
        );

        // Decompress the pubkey to get raw pubkey for map key
        let uncompressed = EcdsaK1::decompress_pubkey(&bridge_pubkey_bytes);
        let raw_pubkey = Vector::empty<u8>();
        let j = 1; // Skip 0x04 prefix
        while (j < 65) {
            Vector::push_back(&mut raw_pubkey, *Vector::borrow(&uncompressed, j));
            j = j + 1;
        };

        // Check if member already exists
        assert!(!SimpleMap::contains_key(&self.members, &raw_pubkey), EDuplicatePubkey);

        let member = CommitteeMember {
            bridge_pubkey_bytes,
            voting_power,
            http_rest_url,
            blocklisted: false,
        };

        SimpleMap::add(&mut self.members, raw_pubkey, member);
    }

    #[test_only]
    /// Execute blocklist without emitting events (for testing without global resources).
    public fun execute_blocklist_for_testing(self: &mut BridgeCommittee, blocklist: Blocklist) {
        let blocklisted = Message::blocklist_type(&blocklist) != 1;
        let eth_addresses = Message::blocklist_validator_addresses(&blocklist);
        let list_len = Vector::length(eth_addresses);
        let list_idx = 0;
        let member_idx = 0;

        let members_len = SimpleMap::length(&self.members);
        while (list_idx < list_len) {
            let target_address = Vector::borrow(eth_addresses, list_idx);
            let found = false;

            while (member_idx < members_len) {
                let (pub_key, member) = SimpleMap::borrow_index_mut(&mut self.members, member_idx);
                let eth_address = Crypto::ecdsa_pub_key_to_eth_address(pub_key);

                if (*target_address == eth_address) {
                    member.blocklisted = blocklisted;
                    found = true;
                    member_idx = 0;
                    break
                };

                member_idx = member_idx + 1;
            };

            assert!(found, EValidatorBlocklistContainsUnknownKey);
            list_idx = list_idx + 1;
        };
    }
}