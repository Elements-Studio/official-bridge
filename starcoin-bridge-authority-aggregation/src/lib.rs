// Stub for starcoin-bridge-authority-aggregation - Byzantine fault-tolerant quorum aggregation

use futures::{future::BoxFuture, stream::FuturesUnordered, Future};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout as tokio_timeout;

pub type AsyncResult<'a, T, E> = BoxFuture<'a, Result<T, E>>;

// Result of quorum reduce operation
pub enum ReduceOutput<R, S> {
    Continue(S),
    Failed(S),
    Success(R),
}

impl<R, S> ReduceOutput<R, S> {
    // Map error type
    pub fn map_err<E, F>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(S) -> E,
    {
        match self {
            ReduceOutput::Success(r) => Ok(r),
            ReduceOutput::Failed(s) | ReduceOutput::Continue(s) => Err(f(s)),
        }
    }
}

// Signature request preferences for controlling validator ordering
pub struct SigRequestPrefs<K> {
    pub ordering_pref: std::collections::BTreeSet<K>,
    pub prefetch_timeout: Duration,
}

/// Trait for committee to provide authority weights
pub trait CommitteeTrait {
    type AuthorityKey: Ord + Clone;
    fn weight(&self, author: &Self::AuthorityKey) -> u64;
}

// Byzantine fault-tolerant quorum map-reduce with timeout and preferences
// Based on Starcoin's authority aggregation implementation
pub async fn quorum_map_then_reduce_with_timeout_and_prefs<
    'a,
    Committee,
    K,
    Client: 'a,
    State,
    V,
    R,
    E,
    FMap,
    FReduce,
>(
    committee: Arc<Committee>,
    authority_clients: Arc<BTreeMap<K, Arc<Client>>>,
    authority_preferences: Option<SigRequestPrefs<K>>,
    mut accumulated_state: State,
    map_each_authority: FMap,
    reduce_result: FReduce,
    total_timeout: Duration,
) -> Result<
    (
        R,
        FuturesUnordered<impl Future<Output = (K, Result<V, E>)> + 'a>,
    ),
    State,
>
where
    Committee: CommitteeTrait<AuthorityKey = K>,
    K: Ord + Clone + Send + 'a,
    FMap: FnOnce(K, Arc<Client>) -> AsyncResult<'a, V, E> + Clone + 'a,
    FReduce: Fn(State, K, u64, Result<V, E>) -> BoxFuture<'a, ReduceOutput<R, State>> + 'a,
    State: Send + 'a,
    V: Send + 'a,
    E: Send + 'a,
{
    use futures::{stream::FuturesUnordered, StreamExt};

    let start = Instant::now();

    // Collect all authority names - honor preferences for ordering
    let mut authorities: Vec<K> = authority_clients.keys().cloned().collect();

    // If preferences provided, try those first
    if let Some(prefs) = &authority_preferences {
        // Split into preferred and others
        let (mut preferred, mut others): (Vec<_>, Vec<_>) = authorities
            .into_iter()
            .partition(|k| prefs.ordering_pref.contains(k));

        // Preferred authorities first, then others
        preferred.append(&mut others);
        authorities = preferred;
    }

    // Collect all authority futures
    let mut responses: FuturesUnordered<_> = authorities
        .into_iter()
        .map(|name| {
            let execute = map_each_authority.clone();
            let name_ret = name.clone();
            let client = authority_clients[&name].clone();
            async move { (name_ret.clone(), execute(name_ret, client).await) }
        })
        .collect();

    // Process results as they arrive
    while let Ok(Some((authority_name, result))) = tokio_timeout(
        total_timeout.saturating_sub(start.elapsed()),
        responses.next(),
    )
    .await
    {
        // Get authority weight from committee
        let authority_weight = committee.weight(&authority_name);

        accumulated_state = match reduce_result(
            accumulated_state,
            authority_name,
            authority_weight,
            result,
        )
        .await
        {
            ReduceOutput::Continue(state) => state,
            ReduceOutput::Failed(state) => {
                return Err(state);
            }
            ReduceOutput::Success(result) => {
                // Reducer returned Success with final result
                return Ok((result, responses));
            }
        };
    }

    // Exhausted all authorities or timeout
    Err(accumulated_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    #[derive(Clone, Debug)]
    struct TestCommittee {
        weights: BTreeMap<u8, u64>,
    }

    impl CommitteeTrait for TestCommittee {
        type AuthorityKey = u8;

        fn weight(&self, author: &Self::AuthorityKey) -> u64 {
            *self.weights.get(author).unwrap_or(&0)
        }
    }

    #[derive(Clone, Debug)]
    struct TestClient {
        delay: Duration,
        result: Result<&'static str, &'static str>,
    }

    #[tokio::test]
    async fn test_quorum_map_reduce_succeeds_at_threshold() {
        let committee = Arc::new(TestCommittee {
            weights: BTreeMap::from([(1, 3), (2, 3), (3, 3)]),
        });

        let clients: Arc<BTreeMap<u8, Arc<TestClient>>> = Arc::new(BTreeMap::from([
            (
                1,
                Arc::new(TestClient {
                    delay: Duration::from_millis(10),
                    result: Ok("ok1"),
                }),
            ),
            (
                2,
                Arc::new(TestClient {
                    delay: Duration::from_millis(20),
                    result: Ok("ok2"),
                }),
            ),
            (
                3,
                Arc::new(TestClient {
                    delay: Duration::from_millis(5),
                    result: Err("bad"),
                }),
            ),
        ]));

        #[derive(Clone, Debug)]
        struct State {
            ok_weight: u64,
            threshold: u64,
        }

        let initial_state = State {
            ok_weight: 0,
            threshold: 6,
        };

        let (final_state, _remaining) = quorum_map_then_reduce_with_timeout_and_prefs(
            committee,
            clients,
            None,
            initial_state,
            |name: u8, client: Arc<TestClient>| {
                Box::pin(async move {
                    tokio::time::sleep(client.delay).await;
                    client.result.map(|s| (name, s))
                })
            },
            |mut state: State,
             _name: u8,
             weight: u64,
             result: Result<(u8, &'static str), &'static str>| {
                Box::pin(async move {
                    if result.is_ok() {
                        state.ok_weight = state.ok_weight.saturating_add(weight);
                    }
                    if state.ok_weight >= state.threshold {
                        ReduceOutput::Success(state)
                    } else {
                        ReduceOutput::Continue(state)
                    }
                })
            },
            Duration::from_secs(2),
        )
        .await
        .expect("expected quorum success");

        assert!(final_state.ok_weight >= final_state.threshold);
    }

    #[tokio::test]
    async fn test_quorum_map_reduce_times_out_and_returns_state() {
        let committee = Arc::new(TestCommittee {
            weights: BTreeMap::from([(1, 1), (2, 1)]),
        });

        let clients: Arc<BTreeMap<u8, Arc<TestClient>>> = Arc::new(BTreeMap::from([
            (
                1,
                Arc::new(TestClient {
                    delay: Duration::from_secs(2),
                    result: Ok("ok1"),
                }),
            ),
            (
                2,
                Arc::new(TestClient {
                    delay: Duration::from_secs(2),
                    result: Ok("ok2"),
                }),
            ),
        ]));

        #[derive(Clone, Debug)]
        struct State {
            ok_weight: u64,
        }

        let initial_state = State { ok_weight: 0 };

        let err_state = quorum_map_then_reduce_with_timeout_and_prefs(
            committee,
            clients,
            None,
            initial_state,
            |_name: u8, client: Arc<TestClient>| {
                Box::pin(async move {
                    tokio::time::sleep(client.delay).await;
                    client.result
                })
            },
            |mut state: State,
             _name: u8,
             weight: u64,
             result: Result<&'static str, &'static str>| {
                Box::pin(async move {
                    if result.is_ok() {
                        state.ok_weight = state.ok_weight.saturating_add(weight);
                    }
                    ReduceOutput::<(), State>::Continue(state)
                })
            },
            Duration::from_millis(50),
        )
        .await
        .expect_err("expected timeout to return accumulated state");

        assert_eq!(err_state.ok_weight, 0);
    }
}
