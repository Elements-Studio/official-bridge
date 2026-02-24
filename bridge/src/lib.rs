// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

// Allow common warnings during Starcoin bridge adaptation
#![allow(
    unused_assignments,
    deprecated,
    clippy::too_many_arguments,
    clippy::new_without_default,
    clippy::should_implement_trait,
    clippy::needless_borrows_for_generic_args,
    clippy::for_kv_map,
    clippy::useless_conversion,
    clippy::ptr_arg,
    clippy::needless_borrow
)]
#![cfg_attr(test, allow(async_fn_in_trait))]

pub mod abi;
pub mod bridge_status;
pub mod chain_syncer;
pub mod client;
pub mod config;
pub mod crypto;
pub mod encoding;
pub mod error;
pub mod eth_client;
pub mod finality;

pub mod eth_transaction_builder;
pub mod events;
pub mod metered_eth_provider;
pub mod metered_starcoin_rpc;
pub mod metrics;
pub mod node;
pub mod pending_events;
pub mod server;
pub mod simple_starcoin_rpc;
pub mod starcoin_bridge_client;
pub mod starcoin_bridge_transaction_builder;
pub mod starcoin_bridge_watchdog;
pub mod starcoin_jsonrpc_client;
#[cfg(test)]
mod starcoin_node_test;
#[cfg(test)]
pub mod starcoin_test_utils;
pub mod ttl_cache;
pub mod types;
pub mod utils;

#[cfg(test)]
pub mod eth_mock_provider;

#[cfg(test)]
pub mod starcoin_bridge_mock_client;

#[cfg(test)]
pub mod test_utils;

pub const BRIDGE_ENABLE_PROTOCOL_VERSION: u64 = 45;

#[cfg(test)]
pub mod e2e_tests;

#[macro_export]
macro_rules! retry_with_max_elapsed_time {
    ($func:expr, $max_elapsed_time:expr) => {{
        // The following delay sequence (in secs) will be used, applied with jitter
        // 0.4, 0.8, 1.6, 3.2, 6.4, 12.8, 25.6, 30, 60, 120, 120 ...
        let backoff = backoff::ExponentialBackoff {
            initial_interval: Duration::from_millis(400),
            randomization_factor: 0.1,
            multiplier: 2.0,
            max_interval: Duration::from_secs(120),
            max_elapsed_time: Some($max_elapsed_time),
            ..Default::default()
        };
        backoff::future::retry(backoff, || {
            let fut = async {
                let result = $func.await;
                match result {
                    Ok(_) => {
                        return Ok(result);
                    }
                    Err(e) => {
                        // For simplicity we treat every error as transient so we can retry until max_elapsed_time
                        tracing::debug!("Retrying due to error: {:?}", e);
                        return Err(backoff::Error::transient(e));
                    }
                }
            };
            std::boxed::Box::pin(fut)
        })
        .await
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn example_func_ok() -> anyhow::Result<()> {
        Ok(())
    }

    async fn example_func_err() -> anyhow::Result<()> {
        tracing::info!("example_func_err");
        Err(anyhow::anyhow!(""))
    }

    #[tokio::test]
    async fn test_retry_with_max_elapsed_time() {
        telemetry_subscribers::init_for_testing();
        // no retry is needed, should return immediately. We give it a very small
        // max_elapsed_time and it should still finish in time.
        let max_elapsed_time = Duration::from_millis(20);
        retry_with_max_elapsed_time!(example_func_ok(), max_elapsed_time)
            .unwrap()
            .unwrap();

        // now call a function that always errors and expect it to return before max_elapsed_time runs out
        let max_elapsed_time = Duration::from_secs(10);
        let instant = std::time::Instant::now();
        retry_with_max_elapsed_time!(example_func_err(), max_elapsed_time).unwrap_err();
        assert!(instant.elapsed() < max_elapsed_time);
    }
}
