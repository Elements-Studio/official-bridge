// Copyright (c) Starcoin Contributors
// SPDX-License-Identifier: Apache-2.0

module Bridge::MessageTypes {

    // message types
    const TOKEN: u8 = 0;
    const COMMITTEE_BLOCKLIST: u8 = 1;
    const EMERGENCY_OP: u8 = 2;
    const UPDATE_BRIDGE_LIMIT: u8 = 3;
    const UPDATE_ASSET_PRICE: u8 = 4;
    const ADD_TOKENS_ON_STARCOIN: u8 = 6;
    const UPDATE_COMMITTEE_MEMBER: u8 = 8;

    public fun token(): u8 { TOKEN }

    public fun committee_blocklist(): u8 { COMMITTEE_BLOCKLIST }

    public fun emergency_op(): u8 { EMERGENCY_OP }

    public fun update_bridge_limit(): u8 { UPDATE_BRIDGE_LIMIT }

    public fun update_asset_price(): u8 { UPDATE_ASSET_PRICE }

    public fun add_tokens_on_starcoin(): u8 { ADD_TOKENS_ON_STARCOIN }

    public fun update_committee_member(): u8 { UPDATE_COMMITTEE_MEMBER }
}