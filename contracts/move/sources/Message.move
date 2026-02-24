// Copyright (c) Starcoin Contributors
// SPDX-License-Identifier: Apache-2.0

module Bridge::Message {
    use Bridge::BCSUtil;
    use Bridge::ChainIDs;
    use Bridge::MessageTypes;
    use StarcoinFramework::BCS;
    use StarcoinFramework::Vector;

    const CURRENT_MESSAGE_VERSION: u8 = 1;
    const ECDSA_ADDRESS_LENGTH: u64 = 20;

    const ETrailingBytes: u64 = 0;
    const EInvalidAddressLength: u64 = 1;
    const EEmptyList: u64 = 2;
    const EInvalidMessageType: u64 = 3;
    const EInvalidEmergencyOpType: u64 = 4;
    const EInvalidPayloadLength: u64 = 5;
    const EMustBeTokenMessage: u64 = 6;

    // Emergency Op types
    const PAUSE: u8 = 0;
    const UNPAUSE: u8 = 1;

    //////////////////////////////////////////////////////
    // Types
    //

    struct BridgeMessage has copy, drop, store {
        message_type: u8,
        message_version: u8,
        seq_num: u64,
        source_chain: u8,
        payload: vector<u8>,
    }

    struct BridgeMessageKey has copy, drop, store {
        source_chain: u8,
        message_type: u8,
        bridge_seq_num: u64,
    }

    struct TokenTransferPayload has drop {
        sender_address: vector<u8>,
        target_chain: u8,
        target_address: vector<u8>,
        token_type: u8,
        amount: u64,
    }

    struct EmergencyOp has drop {
        op_type: u8,
    }

    struct Blocklist has drop {
        blocklist_type: u8,
        validator_eth_addresses: vector<vector<u8>>,
    }

    // Update the limit for route from sending_chain to receiving_chain
    // This message is supposed to be processed by `chain` or the receiving chain
    struct UpdateBridgeLimit has drop {
        // The receiving chain, also the chain that checks and processes this message
        receiving_chain: u8,
        // The sending chain
        sending_chain: u8,
        limit: u64,
    }

    struct UpdateAssetPrice has drop {
        token_id: u8,
        new_price: u64,
    }

    struct AddTokenOnStarcoin has drop {
        native_token: bool,
        token_ids: vector<u8>,
        token_type_names: vector<vector<u8>>,
        token_prices: vector<u64>,
    }

    // Update committee member (add or remove)
    // update_type: 0 = add, 1 = remove
    struct UpdateCommitteeMember has drop {
        update_type: u8,
        member_address: address,
        bridge_pubkey_bytes: vector<u8>,
        voting_power: u64,
        http_rest_url: vector<u8>,
    }

    // For read
    struct ParsedTokenTransferMessage has drop {
        message_version: u8,
        seq_num: u64,
        source_chain: u8,
        payload: vector<u8>,
        parsed_payload: TokenTransferPayload,
    }

    //////////////////////////////////////////////////////
    // Public functions
    //

    // Note: `bcs::peel_vec_u8` *happens* to work here because
    // `sender_address` and `target_address` are no longer than 255 bytes.
    // Therefore their length can be represented by a single byte.
    // See `create_token_bridge_message` for the actual encoding rule.
    public fun extract_token_bridge_payload(message: &BridgeMessage): TokenTransferPayload {
        let payload = Self::payload(message);
        Vector::reverse(&mut payload);

        let sender_address = BCSUtil::peel_vec_u8(&mut payload);
        let target_chain = BCSUtil::peel_u8(&mut payload);
        let target_address = BCSUtil::peel_vec_u8(&mut payload);
        let token_type = BCSUtil::peel_u8(&mut payload);
        let amount = Self::peel_u64_be(&mut payload);

        ChainIDs::assert_valid_chain_id(target_chain);
        assert!(Vector::is_empty(&BCSUtil::into_remainder_bytes(payload)), ETrailingBytes);

        TokenTransferPayload {
            sender_address,
            target_chain,
            target_address,
            token_type,
            amount,
        }
    }

    /// Emergency op payload is just a single byte
    public fun extract_emergency_op_payload(message: &BridgeMessage): EmergencyOp {
        assert!(Vector::length(&message.payload) == 1, ETrailingBytes);
        EmergencyOp { op_type: *Vector::borrow(&message.payload, 0) }
    }

    public fun extract_blocklist_payload(message: &BridgeMessage): Blocklist {
        // blocklist payload should consist of one byte blocklist type, and list of 20 bytes evm addresses
        // derived from ECDSA public keys
        let bcs = Self::payload(message);
        Vector::reverse(&mut bcs);
        let blocklist_type = BCSUtil::peel_u8(&mut bcs);
        let address_count = BCSUtil::peel_u8(&mut bcs);

        assert!(address_count != 0, EEmptyList);

        let validator_eth_addresses = vector[];
        while (address_count > 0) {
            let (address, i) = (vector[], 0);
            while (i < ECDSA_ADDRESS_LENGTH) {
                Vector::push_back(&mut address, BCSUtil::peel_u8(&mut bcs));
                i = i + 1;
            };
            // validator_eth_addresses.push_back(address);
            Vector::push_back(&mut validator_eth_addresses, address);
            address_count = address_count - 1;
        };

        assert!(Vector::is_empty(&BCSUtil::into_remainder_bytes(bcs)), ETrailingBytes);

        Blocklist {
            blocklist_type,
            validator_eth_addresses,
        }
    }

    public fun extract_update_bridge_limit(message: &BridgeMessage): UpdateBridgeLimit {
        let bcs = Self::payload(message);
        Vector::reverse(&mut bcs);
        let sending_chain = BCSUtil::peel_u8(&mut bcs);
        let limit = peel_u64_be(&mut bcs);

        ChainIDs::assert_valid_chain_id(sending_chain);
        assert!(Vector::is_empty(&BCSUtil::into_remainder_bytes(bcs)), ETrailingBytes);

        UpdateBridgeLimit {
            receiving_chain: message.source_chain,
            sending_chain,
            limit,
        }
    }

    public fun extract_update_asset_price(message: &BridgeMessage): UpdateAssetPrice {
        let bcs = Self::payload(message);
        Vector::reverse(&mut bcs);
        let token_id = BCSUtil::peel_u8(&mut bcs);
        let new_price = peel_u64_be(&mut bcs);

        assert!(Vector::is_empty(&BCSUtil::into_remainder_bytes(bcs)), ETrailingBytes);

        UpdateAssetPrice {
            token_id,
            new_price,
        }
    }

    public fun extract_add_tokens_on_starcoin(message: &BridgeMessage): AddTokenOnStarcoin {
        let bcs = Self::payload(message);
        Vector::reverse(&mut bcs);
        let native_token = BCSUtil::peel_bool(&mut bcs);
        let token_ids = BCSUtil::peel_vec_u8(&mut bcs);
        let token_type_names_bytes = BCSUtil::peel_vec_vec_u8(&mut bcs);
        let token_prices = BCSUtil::peel_vec_u64(&mut bcs);

        let n = 0;
        let token_type_names = vector[];
        while (n < Vector::length(&token_type_names_bytes)) {
            Vector::push_back(&mut token_type_names, *Vector::borrow(&token_type_names_bytes, n));
            n = n + 1;
        };
        assert!(Vector::is_empty(&BCSUtil::into_remainder_bytes(bcs)), ETrailingBytes);
        AddTokenOnStarcoin {
            native_token,
            token_ids,
            token_type_names,
            token_prices,
        }
    }

    /// Extract UpdateCommitteeMember payload
    /// Payload format:
    /// [update_type: u8]  (0 = add, 1 = remove)
    /// [member_address: 16 bytes]
    /// [pubkey_length: u8]
    /// [bridge_pubkey_bytes: byte[]]
    /// [voting_power: u64]
    /// [url_length: u8]
    /// [http_rest_url: byte[]]
    public fun extract_update_committee_member(message: &BridgeMessage): UpdateCommitteeMember {
        let bcs = Self::payload(message);
        Vector::reverse(&mut bcs);

        let update_type = BCSUtil::peel_u8(&mut bcs);
        // member_address is 16 bytes
        let addr_bytes = vector[];
        let i = 0;
        while (i < 16) {
            Vector::push_back(&mut addr_bytes, BCSUtil::peel_u8(&mut bcs));
            i = i + 1;
        };
        let member_address = BCSUtil::to_address(addr_bytes);
        let bridge_pubkey_bytes = BCSUtil::peel_vec_u8(&mut bcs);
        let voting_power = peel_u64_be(&mut bcs);
        let http_rest_url = BCSUtil::peel_vec_u8(&mut bcs);

        assert!(Vector::is_empty(&BCSUtil::into_remainder_bytes(bcs)), ETrailingBytes);

        UpdateCommitteeMember {
            update_type,
            member_address,
            bridge_pubkey_bytes,
            voting_power,
            http_rest_url,
        }
    }

    public fun serialize_message(message: BridgeMessage): vector<u8> {
        let BridgeMessage {
            message_type,
            message_version,
            seq_num,
            source_chain,
            payload,
        } = message;

        let message = vector[message_type, message_version];

        // bcs serializes u64 as 8 bytes
        Vector::append(&mut message, reverse_bytes(BCS::to_bytes(&seq_num)));
        Vector::push_back(&mut message, source_chain);
        Vector::append(&mut message, payload);
        message
    }

    /// Token Transfer Message Format:
    /// [message_type: u8]
    /// [version:u8]
    /// [nonce:u64]
    /// [source_chain: u8]
    /// [sender_address_length:u8]
    /// [sender_address: byte[]]
    /// [target_chain:u8]
    /// [target_address_length:u8]
    /// [target_address: byte[]]
    /// [token_type:u8]
    /// [amount:u64]
    public fun create_token_bridge_message(
        source_chain: u8,
        seq_num: u64,
        sender_address: vector<u8>,
        target_chain: u8,
        target_address: vector<u8>,
        token_type: u8,
        amount: u64,
    ): BridgeMessage {
        ChainIDs::assert_valid_chain_id(source_chain);
        ChainIDs::assert_valid_chain_id(target_chain);

        let payload = vector[];

        // sender address should be less than 255 bytes so can fit into u8
        Vector::push_back(&mut payload, (Vector::length(&sender_address) as u8));
        Vector::append(&mut payload, sender_address);
        Vector::push_back(&mut payload, target_chain);

        // target address should be less than 255 bytes so can fit into u8
        Vector::push_back(&mut payload, (Vector::length(&target_address) as u8));
        Vector::append(&mut payload, target_address);
        Vector::push_back(&mut payload, token_type);

        // bcs serialzies u64 as 8 bytes
        Vector::append(&mut payload, reverse_bytes(BCS::to_bytes(&amount)));

        // Starcoin addres length is 16, ETH address is 20, and fixed length is 12
        assert!(Vector::length(&payload) == 48, EInvalidPayloadLength);

        BridgeMessage {
            message_type: MessageTypes::token(),
            message_version: CURRENT_MESSAGE_VERSION,
            seq_num,
            source_chain,
            payload,
        }
    }

    /// Emergency Op Message Format:
    /// [message_type: u8]
    /// [version:u8]
    /// [nonce:u64]
    /// [chain_id: u8]
    /// [op_type: u8]
    public fun create_emergency_op_message(source_chain: u8, seq_num: u64, op_type: u8): BridgeMessage {
        ChainIDs::assert_valid_chain_id(source_chain);

        BridgeMessage {
            message_type: MessageTypes::emergency_op(),
            message_version: CURRENT_MESSAGE_VERSION,
            seq_num,
            source_chain,
            payload: vector[op_type],
        }
    }

    /// Blocklist Message Format:
    /// [message_type: u8]
    /// [version:u8]
    /// [nonce:u64]
    /// [chain_id: u8]
    /// [blocklist_type: u8]
    /// [validator_length: u8]
    /// [validator_ecdsa_addresses: byte[][]]
    public fun create_blocklist_message(
        source_chain: u8,
        seq_num: u64,
        // 0: block, 1: unblock
        blocklist_type: u8,
        validator_ecdsa_addresses: vector<vector<u8>>,
    ): BridgeMessage {
        ChainIDs::assert_valid_chain_id(source_chain);

        let address_length = Vector::length(&validator_ecdsa_addresses);
        let payload = vector[blocklist_type, (address_length as u8)];
        let i = 0;

        while (i < address_length) {
            let address = *Vector::borrow(&validator_ecdsa_addresses, i);
            assert!(Vector::length(&address) == ECDSA_ADDRESS_LENGTH, EInvalidAddressLength);
            Vector::append(&mut payload, address);

            i = i + 1;
        };

        BridgeMessage {
            message_type: MessageTypes::committee_blocklist(),
            message_version: CURRENT_MESSAGE_VERSION,
            seq_num,
            source_chain,
            payload,
        }
    }


    /// Update bridge limit Message Format:
    /// [message_type: u8]
    /// [version:u8]
    /// [nonce:u64]
    /// [receiving_chain_id: u8]
    /// [sending_chain_id: u8]
    /// [new_limit: u64]
    public fun create_update_bridge_limit_message(
        receiving_chain: u8,
        seq_num: u64,
        sending_chain: u8,
        new_limit: u64,
    ): BridgeMessage {
        ChainIDs::assert_valid_chain_id(receiving_chain);
        ChainIDs::assert_valid_chain_id(sending_chain);

        let payload = vector[sending_chain];
        Vector::append(&mut payload, reverse_bytes(BCS::to_bytes(&new_limit)));

        BridgeMessage {
            message_type: MessageTypes::update_bridge_limit(),
            message_version: CURRENT_MESSAGE_VERSION,
            seq_num,
            source_chain: receiving_chain,
            payload,
        }
    }

    /// Update asset price message
    /// [message_type: u8]
    /// [version:u8]
    /// [nonce:u64]
    /// [chain_id: u8]
    /// [token_id: u8]
    /// [new_price:u64]
    public fun create_update_asset_price_message(
        token_id: u8,
        source_chain: u8,
        seq_num: u64,
        new_price: u64,
    ): BridgeMessage {
        ChainIDs::assert_valid_chain_id(source_chain);

        let payload = vector[token_id];
        Vector::append(&mut payload, reverse_bytes(BCS::to_bytes(&new_price)));
        BridgeMessage {
            message_type: MessageTypes::update_asset_price(),
            message_version: CURRENT_MESSAGE_VERSION,
            seq_num,
            source_chain,
            payload,
        }
    }


    /// Update Starcoin token message
    /// [message_type:u8]
    /// [version:u8]
    /// [nonce:u64]
    /// [chain_id: u8]
    /// [native_token:bool]
    /// [token_ids:vector<u8>]
    /// [token_type_name:vector<String>]
    /// [token_prices:vector<u64>]
    public fun create_add_tokens_on_starcoin_message(
        source_chain: u8,
        seq_num: u64,
        native_token: bool,
        token_ids: vector<u8>,
        type_names: vector<vector<u8>>,
        token_prices: vector<u64>,
    ): BridgeMessage {
        ChainIDs::assert_valid_chain_id(source_chain);
        let payload = BCS::to_bytes(&native_token);
        Vector::append(&mut payload, BCS::to_bytes(&token_ids));
        Vector::append(&mut payload, BCS::to_bytes(&type_names));
        Vector::append(&mut payload, BCS::to_bytes(&token_prices));
        BridgeMessage {
            message_type: MessageTypes::add_tokens_on_starcoin(),
            message_version: CURRENT_MESSAGE_VERSION,
            seq_num,
            source_chain,
            payload,
        }
    }

    /// Update committee member message (add/remove)
    /// [message_type:u8]
    /// [version:u8]
    /// [nonce:u64]
    /// [chain_id: u8]
    /// [update_type: u8] (0 = add, 1 = remove)
    /// [member_address: 16 bytes]
    /// [pubkey_length: u8]
    /// [bridge_pubkey_bytes: byte[]]
    /// [voting_power: u64]
    /// [url_length: u8]
    /// [http_rest_url: byte[]]
    public fun create_update_committee_member_message(
        source_chain: u8,
        seq_num: u64,
        update_type: u8,
        member_address: address,
        bridge_pubkey_bytes: vector<u8>,
        voting_power: u64,
        http_rest_url: vector<u8>,
    ): BridgeMessage {
        ChainIDs::assert_valid_chain_id(source_chain);

        let payload = vector[update_type];
        // Address is 16 bytes in Starcoin
        Vector::append(&mut payload, BCS::to_bytes(&member_address));
        // pubkey with length prefix
        Vector::push_back(&mut payload, (Vector::length(&bridge_pubkey_bytes) as u8));
        Vector::append(&mut payload, bridge_pubkey_bytes);
        // voting power as u64 big endian
        Vector::append(&mut payload, reverse_bytes(BCS::to_bytes(&voting_power)));
        // url with length prefix
        Vector::push_back(&mut payload, (Vector::length(&http_rest_url) as u8));
        Vector::append(&mut payload, http_rest_url);

        BridgeMessage {
            message_type: MessageTypes::update_committee_member(),
            message_version: CURRENT_MESSAGE_VERSION,
            seq_num,
            source_chain,
            payload,
        }
    }

    public fun create_key(source_chain: u8, message_type: u8, bridge_seq_num: u64): BridgeMessageKey {
        BridgeMessageKey { source_chain, message_type, bridge_seq_num }
    }

    public fun key(self: &BridgeMessage): BridgeMessageKey {
        create_key(self.source_chain, self.message_type, self.seq_num)
    }

    // BridgeMessage getters
    public fun message_version(self: &BridgeMessage): u8 {
        self.message_version
    }

    public fun message_type(self: &BridgeMessage): u8 {
        self.message_type
    }

    public fun seq_num(self: &BridgeMessage): u64 {
        self.seq_num
    }

    public fun source_chain(self: &BridgeMessage): u8 {
        self.source_chain
    }

    public fun payload(self: &BridgeMessage): vector<u8> {
        self.payload
    }

    public fun token_target_chain(self: &TokenTransferPayload): u8 {
        self.target_chain
    }

    public fun token_target_address(self: &TokenTransferPayload): vector<u8> {
        self.target_address
    }

    public fun token_type(self: &TokenTransferPayload): u8 {
        self.token_type
    }

    public fun token_amount(self: &TokenTransferPayload): u64 {
        self.amount
    }

    // EmergencyOpPayload getters
    public fun emergency_op_type(self: &EmergencyOp): u8 {
        self.op_type
    }

    public fun blocklist_type(self: &Blocklist): u8 {
        self.blocklist_type
    }

    public fun blocklist_validator_addresses(self: &Blocklist): &vector<vector<u8>> {
        &self.validator_eth_addresses
    }

    public fun update_bridge_limit_payload_sending_chain(self: &UpdateBridgeLimit): u8 {
        self.sending_chain
    }

    public fun update_bridge_limit_payload_receiving_chain(self: &UpdateBridgeLimit): u8 {
        self.receiving_chain
    }

    public fun update_bridge_limit_payload_limit(self: &UpdateBridgeLimit): u64 {
        self.limit
    }

    public fun update_asset_price_payload_token_id(self: &UpdateAssetPrice): u8 {
        self.token_id
    }

    public fun update_asset_price_payload_new_price(self: &UpdateAssetPrice): u64 {
        self.new_price
    }

    public fun is_native(self: &AddTokenOnStarcoin): bool {
        self.native_token
    }

    public fun token_ids(self: &AddTokenOnStarcoin): vector<u8> {
        self.token_ids
    }

    public fun token_type_names(self: &AddTokenOnStarcoin): vector<vector<u8>> {
        self.token_type_names
    }

    public fun token_prices(self: &AddTokenOnStarcoin): vector<u64> {
        self.token_prices
    }

    // UpdateCommitteeMember getters
    public fun update_committee_member_type(self: &UpdateCommitteeMember): u8 {
        self.update_type
    }

    public fun update_committee_member_address(self: &UpdateCommitteeMember): address {
        self.member_address
    }

    public fun update_committee_member_pubkey(self: &UpdateCommitteeMember): vector<u8> {
        self.bridge_pubkey_bytes
    }

    public fun update_committee_member_voting_power(self: &UpdateCommitteeMember): u64 {
        self.voting_power
    }

    public fun update_committee_member_http_url(self: &UpdateCommitteeMember): vector<u8> {
        self.http_rest_url
    }

    public fun emergency_op_pause(): u8 {
        PAUSE
    }

    public fun emergency_op_unpause(): u8 {
        UNPAUSE
    }

    /// Return the required signature threshold for the message, values are voting power in the scale of 10000
    public fun required_voting_power(self: &BridgeMessage): u64 {
        let message_type = message_type(self);

        if (message_type == MessageTypes::token()) {
            2
        } else if (message_type == MessageTypes::emergency_op()) {
            let payload = extract_emergency_op_payload(self);
            if (payload.op_type == PAUSE) {
                450
            } else if (payload.op_type == UNPAUSE) {
                5001
            } else {
                abort EInvalidEmergencyOpType
            }
        } else if (message_type == MessageTypes::committee_blocklist()) {
            5001
        } else if (message_type == MessageTypes::update_asset_price()) {
            5001
        } else if (message_type == MessageTypes::update_bridge_limit()) {
            5001
        } else if (message_type == MessageTypes::add_tokens_on_starcoin()) {
            5001
        } else if (message_type == MessageTypes::update_committee_member()) {
            5001
        } else {
            abort EInvalidMessageType
        }
    }

    // Convert BridgeMessage to ParsedTokenTransferMessage
    public fun to_parsed_token_transfer_message(message: &BridgeMessage): ParsedTokenTransferMessage {
        assert!(message.message_type == MessageTypes::token(), EMustBeTokenMessage);
        let payload = Self::extract_token_bridge_payload(message);
        ParsedTokenTransferMessage {
            message_version: message.message_version,
            seq_num: message.seq_num,
            source_chain: message.source_chain,
            payload: message.payload,
            parsed_payload: payload,
        }
    }

    //////////////////////////////////////////////////////
    // Internal functions
    //

    fun reverse_bytes(bytes: vector<u8>): vector<u8> {
        Vector::reverse(&mut bytes);
        bytes
    }

    public fun peel_u64_be(bcs: &mut vector<u8>): u64 {
        let (value, i) = (0u64, 64u8);
        while (i > 0) {
            i = i - 8;
            let byte = (BCSUtil::peel_u8(bcs) as u64);
            value = value + (byte << i);
        };
        value
    }

    #[test_only]
    public fun peel_u64_be_for_testing(bcs: &mut vector<u8>): u64 {
        peel_u64_be(bcs)
    }

    #[test_only]
    public fun make_generic_message(
        message_type: u8,
        message_version: u8,
        seq_num: u64,
        source_chain: u8,
        payload: vector<u8>,
    ): BridgeMessage {
        BridgeMessage {
            message_type,
            message_version,
            seq_num,
            source_chain,
            payload,
        }
    }

    #[test_only]
    public fun make_payload(
        sender_address: vector<u8>,
        target_chain: u8,
        target_address: vector<u8>,
        token_type: u8,
        amount: u64,
    ): TokenTransferPayload {
        TokenTransferPayload {
            sender_address,
            target_chain,
            target_address,
            token_type,
            amount,
        }
    }

    #[test_only]
    public fun deserialize_message_test_only(message: vector<u8>): BridgeMessage {
        Vector::reverse(&mut message);
        let message_type = BCSUtil::peel_u8(&mut message);
        let message_version = BCSUtil::peel_u8(&mut message);
        let seq_num = peel_u64_be_for_testing(&mut message);
        let source_chain = BCSUtil::peel_u8(&mut message);
        let payload = BCSUtil::into_remainder_bytes(message);
        make_generic_message(
            message_type,
            message_version,
            seq_num,
            source_chain,
            payload,
        )
    }

    #[test_only]
    public fun reverse_bytes_test(bytes: vector<u8>): vector<u8> {
        reverse_bytes(bytes)
    }

    #[test_only]
    public fun set_payload(message: &mut BridgeMessage, bytes: vector<u8>) {
        message.payload = bytes;
    }

    #[test_only]
    public fun make_add_token_on_starcoin(
        native_token: bool,
        token_ids: vector<u8>,
        token_type_names: vector<vector<u8>>,
        token_prices: vector<u64>,
    ): AddTokenOnStarcoin {
        AddTokenOnStarcoin {
            native_token,
            token_ids,
            token_type_names,
            token_prices,
        }
    }

    #[test_only]
    public fun unpack_message(msg: BridgeMessageKey): (u8, u8, u64) {
        (msg.source_chain, msg.message_type, msg.bridge_seq_num)
    }
}