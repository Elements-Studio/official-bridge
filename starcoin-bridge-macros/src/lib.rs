// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0
// Simplified version for Starcoin Bridge - only includes actually used macros

#![allow(unexpected_cfgs)]

use futures::future::BoxFuture;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

/// Simply evaluates expr.
#[macro_export]
macro_rules! nondeterministic {
    ($expr: expr) => {
        $expr
    };
}

type FpCallback = dyn Fn() -> Box<dyn std::any::Any + Send + 'static> + Send + Sync;
type FpMap = HashMap<&'static str, Arc<FpCallback>>;

fn with_fp_map<T>(func: impl FnOnce(&mut FpMap) -> T) -> T {
    use once_cell::sync::Lazy;
    use std::sync::Mutex;

    static MAP: Lazy<Mutex<FpMap>> = Lazy::new(Default::default);
    let mut map = MAP.lock().unwrap();
    func(&mut map)
}

fn get_callback(identifier: &'static str) -> Option<Arc<FpCallback>> {
    with_fp_map(|map| map.get(identifier).cloned())
}

fn get_sync_fp_result(result: Box<dyn std::any::Any + Send + 'static>) {
    if result.downcast::<()>().is_err() {
        panic!("sync failpoint must return ()");
    }
}

fn get_async_fp_result(result: Box<dyn std::any::Any + Send + 'static>) -> BoxFuture<'static, ()> {
    match result.downcast::<BoxFuture<'static, ()>>() {
        Ok(fut) => *fut,
        Err(err) => panic!(
            "async failpoint must return BoxFuture<'static, ()> {:?}",
            err
        ),
    }
}

fn get_fp_if_result(result: Box<dyn std::any::Any + Send + 'static>) -> bool {
    match result.downcast::<bool>() {
        Ok(b) => *b,
        Err(_) => panic!("failpoint-if must return bool"),
    }
}

fn get_fp_some_result<T: Send + 'static>(
    result: Box<dyn std::any::Any + Send + 'static>,
) -> Option<T> {
    match result.downcast::<Option<T>>() {
        Ok(opt) => *opt,
        Err(_) => panic!("failpoint-arg must return Option<T>"),
    }
}

pub fn handle_fail_point(identifier: &'static str) {
    if let Some(callback) = get_callback(identifier) {
        get_sync_fp_result(callback());
        tracing::trace!("hit failpoint {}", identifier);
    }
}

pub async fn handle_fail_point_async(identifier: &'static str) {
    if let Some(callback) = get_callback(identifier) {
        tracing::trace!("hit async failpoint {}", identifier);
        let fut = get_async_fp_result(callback());
        fut.await;
    }
}

pub fn handle_fail_point_if(identifier: &'static str) -> bool {
    if let Some(callback) = get_callback(identifier) {
        tracing::trace!("hit failpoint_if {}", identifier);
        get_fp_if_result(callback())
    } else {
        false
    }
}

pub fn handle_fail_point_arg<T: Send + 'static>(identifier: &'static str) -> Option<T> {
    if let Some(callback) = get_callback(identifier) {
        tracing::trace!("hit failpoint_arg {}", identifier);
        get_fp_some_result(callback())
    } else {
        None
    }
}

fn register_fail_point_impl(identifier: &'static str, callback: Arc<FpCallback>) {
    with_fp_map(move |map| {
        assert!(
            map.insert(identifier, callback).is_none(),
            "duplicate fail point registration"
        );
    })
}

fn clear_fail_point_impl(identifier: &'static str) {
    with_fp_map(move |map| {
        assert!(
            map.remove(identifier).is_some(),
            "fail point {:?} does not exist",
            identifier
        );
    })
}

pub fn register_fail_point(identifier: &'static str, callback: impl Fn() + Sync + Send + 'static) {
    register_fail_point_impl(
        identifier,
        Arc::new(move || {
            callback();
            Box::new(())
        }),
    );
}

/// Register an asynchronous fail point.
pub fn register_fail_point_async<F>(
    identifier: &'static str,
    callback: impl Fn() -> F + Sync + Send + 'static,
) where
    F: Future<Output = ()> + Send + 'static,
{
    register_fail_point_impl(
        identifier,
        Arc::new(move || {
            let result: BoxFuture<'static, ()> = Box::pin(callback());
            Box::new(result)
        }),
    );
}

pub fn register_fail_point_if(
    identifier: &'static str,
    callback: impl Fn() -> bool + Sync + Send + 'static,
) {
    register_fail_point_impl(identifier, Arc::new(move || Box::new(callback())));
}

pub fn register_fail_point_arg<T: Send + 'static>(
    identifier: &'static str,
    callback: impl Fn() -> Option<T> + Sync + Send + 'static,
) {
    register_fail_point_impl(identifier, Arc::new(move || Box::new(callback())));
}

pub fn register_fail_points(
    identifiers: &[&'static str],
    callback: impl Fn() + Sync + Send + 'static,
) {
    let cb: Arc<FpCallback> = Arc::new(move || {
        callback();
        Box::new(())
    });
    for id in identifiers {
        register_fail_point_impl(id, cb.clone());
    }
}

pub fn clear_fail_point(identifier: &'static str) {
    clear_fail_point_impl(identifier);
}

/// Trigger a fail point.
#[cfg(fail_points)]
#[macro_export]
macro_rules! fail_point {
    ($tag: expr) => {
        $crate::handle_fail_point($tag)
    };
}

/// Trigger an async fail point.
#[cfg(fail_points)]
#[macro_export]
macro_rules! fail_point_async {
    ($tag: expr) => {
        $crate::handle_fail_point_async($tag).await
    };
}

#[cfg(fail_points)]
#[macro_export]
macro_rules! fail_point_if {
    ($tag: expr, $callback: expr) => {
        if $crate::handle_fail_point_if($tag) {
            ($callback)();
        }
    };
}

#[cfg(fail_points)]
#[macro_export]
macro_rules! fail_point_arg {
    ($tag: expr, $callback: expr) => {
        if let Some(arg) = $crate::handle_fail_point_arg($tag) {
            ($callback)(arg);
        }
    };
}

#[cfg(not(fail_points))]
#[macro_export]
macro_rules! fail_point {
    ($tag: expr) => {};
}

#[cfg(not(fail_points))]
#[macro_export]
macro_rules! fail_point_async {
    ($tag: expr) => {};
}

#[cfg(not(fail_points))]
#[macro_export]
macro_rules! fail_point_if {
    ($tag: expr, $callback: expr) => {};
}

#[cfg(not(fail_points))]
#[macro_export]
macro_rules! fail_point_arg {
    ($tag: expr, $callback: expr) => {};
}

/// Use to write INFO level logs only when REPLAY_LOG environment variable is set.
#[macro_export]
macro_rules! replay_log {
    ($($arg:tt)+) => {
        if std::env::var("REPLAY_LOG").is_ok() {
            tracing::info!($($arg)+);
        }
    };
}
