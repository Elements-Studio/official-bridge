// @generated automatically by Diesel CLI.

diesel::table! {
    governance_actions (id) {
        id -> Int8,
        nonce -> Nullable<Int8>,
        data_source -> Text,
        txn_digest -> Bytea,
        sender_address -> Bytea,
        timestamp_ms -> Int8,
        action -> Text,
        data -> Jsonb,
    }
}

diesel::table! {
    progress_store (task_name) {
        task_name -> Text,
        block_number -> Int8,
        target_block -> Int8,
        timestamp -> Timestamp,
    }
}

diesel::table! {
    starcoin_bridge_error_transactions (txn_digest) {
        txn_digest -> Bytea,
        sender_address -> Bytea,
        timestamp_ms -> Int8,
        failure_status -> Text,
        cmd_idx -> Nullable<Int8>,
    }
}

diesel::table! {
    starcoin_bridge_progress_store (id) {
        id -> Int4,
        txn_digest -> Bytea,
    }
}

diesel::table! {
    token_transfer (chain_id, nonce, status) {
        chain_id -> Int4,
        nonce -> Int8,
        status -> Text,
        block_height -> Int8,
        timestamp_ms -> Int8,
        txn_hash -> Bytea,
        txn_sender -> Bytea,
        gas_usage -> Int8,
        data_source -> Text,
        is_finalized -> Nullable<Bool>,
    }
}

diesel::table! {
    token_transfer_data (chain_id, nonce) {
        chain_id -> Int4,
        nonce -> Int8,
        block_height -> Int8,
        timestamp_ms -> Int8,
        txn_hash -> Bytea,
        sender_address -> Bytea,
        destination_chain -> Int4,
        recipient_address -> Bytea,
        token_id -> Int4,
        amount -> Int8,
        is_finalized -> Nullable<Bool>,
        monitor_verified -> Bool,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    governance_actions,
    progress_store,
    starcoin_bridge_error_transactions,
    starcoin_bridge_progress_store,
    token_transfer,
    token_transfer_data,
);
