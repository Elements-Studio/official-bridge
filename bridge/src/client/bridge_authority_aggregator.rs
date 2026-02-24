// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

//! BridgeAuthorityAggregator aggregates signatures from BridgeCommittee.

use crate::client::bridge_client::BridgeClient;
use crate::crypto::BridgeAuthorityPublicKeyBytes;
use crate::crypto::BridgeAuthoritySignInfo;
use crate::error::{BridgeError, BridgeResult};
use crate::metrics::BridgeMetrics;
use crate::types::BridgeCommitteeValiditySignInfo;
use crate::types::{
    BridgeAction, BridgeCommittee, CertifiedBridgeAction, VerifiedCertifiedBridgeAction,
    VerifiedSignedBridgeAction,
};
use starcoin_bridge_authority_aggregation::ReduceOutput;
use starcoin_bridge_authority_aggregation::{
    quorum_map_then_reduce_with_timeout_and_prefs, SigRequestPrefs,
};
use starcoin_bridge_types::base_types::ConciseableName;
use starcoin_bridge_types::committee::{StakeUnit, TOTAL_VOTING_POWER};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

const TOTAL_TIMEOUT_MS: u64 = 5_000;
const PREFETCH_TIMEOUT_MS: u64 = 1_500;
const RETRY_INTERVAL_MS: u64 = 500;

pub struct BridgeAuthorityAggregator {
    pub committee: Arc<BridgeCommittee>,
    pub clients: Arc<BTreeMap<BridgeAuthorityPublicKeyBytes, Arc<BridgeClient>>>,
    pub metrics: Arc<BridgeMetrics>,
    pub committee_keys_to_names: Arc<BTreeMap<BridgeAuthorityPublicKeyBytes, String>>,
}

impl BridgeAuthorityAggregator {
    pub fn new(
        committee: Arc<BridgeCommittee>,
        metrics: Arc<BridgeMetrics>,
        committee_keys_to_names: Arc<BTreeMap<BridgeAuthorityPublicKeyBytes, String>>,
    ) -> Self {
        let clients: BTreeMap<BridgeAuthorityPublicKeyBytes, Arc<BridgeClient>> = committee
            .members()
            .iter()
            .filter_map(|(name, authority)| {
                if authority.is_blocklisted {
                    warn!("Ignored blocklisted authority {:?} (stake: {}) when creating BridgeAuthorityAggregator", name.concise(), authority.voting_power);
                    return None;
                }
                // TODO: we could also record bad stakes here and use in signature aggregation
                match BridgeClient::new(
                    name.clone(),
                    committee.clone(),
                ) {
                    Ok(client) => Some((name.clone(), Arc::new(client))),
                    Err(e) => {
                        error!(
                            "Failed to create BridgeClient for {:?}: {:?}",
                            name.concise(),
                            e
                        );
                        None
                    }
                }
            })
            .collect::<BTreeMap<_, _>>();

        // Set committee members count metrics
        metrics
            .committee_members_total
            .set(committee.members().len() as i64);
        metrics.committee_members_online.set(clients.len() as i64);

        Self {
            committee,
            clients: Arc::new(clients),
            metrics,
            committee_keys_to_names,
        }
    }

    #[cfg(test)]
    pub fn new_for_testing(committee: Arc<BridgeCommittee>) -> Self {
        Self::new(
            committee,
            Arc::new(BridgeMetrics::new_for_testing()),
            Arc::new(BTreeMap::new()),
        )
    }

    pub async fn request_committee_signatures(
        &self,
        action: BridgeAction,
    ) -> BridgeResult<VerifiedCertifiedBridgeAction> {
        let state = GetSigsState::new(
            action.approval_threshold(),
            self.committee.clone(),
            self.metrics.clone(),
            self.committee_keys_to_names.clone(),
        );
        request_sign_bridge_action_into_certification(
            action,
            self.committee.clone(),
            self.clients.clone(),
            state,
            Duration::from_millis(PREFETCH_TIMEOUT_MS),
        )
        .await
    }
}

#[derive(Debug)]
struct GetSigsState {
    total_bad_stake: StakeUnit,
    total_ok_stake: StakeUnit,
    sigs: BTreeMap<BridgeAuthorityPublicKeyBytes, BridgeAuthoritySignInfo>,
    validity_threshold: StakeUnit,
    committee: Arc<BridgeCommittee>,
    metrics: Arc<BridgeMetrics>,
    committee_keys_to_names: Arc<BTreeMap<BridgeAuthorityPublicKeyBytes, String>>,
    certified_action: Option<VerifiedCertifiedBridgeAction>,
}

impl GetSigsState {
    fn new(
        validity_threshold: StakeUnit,
        committee: Arc<BridgeCommittee>,
        metrics: Arc<BridgeMetrics>,
        committee_keys_to_names: Arc<BTreeMap<BridgeAuthorityPublicKeyBytes, String>>,
    ) -> Self {
        Self {
            committee,
            total_bad_stake: 0,
            total_ok_stake: 0,
            sigs: BTreeMap::new(),
            validity_threshold,
            metrics,
            committee_keys_to_names,
            certified_action: None,
        }
    }

    fn handle_verified_signed_action(
        &mut self,
        name: BridgeAuthorityPublicKeyBytes,
        stake: StakeUnit,
        signed_action: VerifiedSignedBridgeAction,
    ) -> BridgeResult<Option<VerifiedCertifiedBridgeAction>> {
        info!("Got signatures from {}, stake: {}", name.concise(), stake);
        if !self.committee.is_active_member(&name) {
            return Err(BridgeError::InvalidBridgeAuthority(name));
        }

        // safeguard here to assert passed in stake matches the stake in committee
        // unwrap safe: if name is an active member then it must be in committee set
        assert_eq!(stake, self.committee.member(&name).unwrap().voting_power);

        match self.sigs.entry(name.clone()) {
            Entry::Vacant(e) => {
                e.insert(signed_action.auth_sig().clone());
                self.add_ok_stake(stake, &name);
            }
            Entry::Occupied(_) => {
                return Err(BridgeError::AuthoritySignatureDuplication(format!(
                    "Got signatures for the same authority twice: {}",
                    name.concise()
                )));
            }
        }
        if self.total_ok_stake >= self.validity_threshold {
            info!(
                "Got enough signatures from {} validators with total_ok_stake {}",
                self.sigs.len(),
                self.total_ok_stake
            );
            let signatures = self
                .sigs
                .iter()
                .map(|(k, v)| (k.clone(), v.signature.clone()))
                .collect::<BTreeMap<_, _>>();
            let sig_info = BridgeCommitteeValiditySignInfo { signatures };
            let certified_action: starcoin_bridge_types::message_envelope::Envelope<
                BridgeAction,
                BridgeCommitteeValiditySignInfo,
            > = CertifiedBridgeAction::new_from_data_and_sig(
                signed_action.into_inner().into_data(),
                sig_info,
            );
            // `BridgeClient` already verified individual signatures
            let verified_certified =
                VerifiedCertifiedBridgeAction::new_from_verified(certified_action);
            self.certified_action = Some(verified_certified.clone());
            Ok(Some(verified_certified))
        } else {
            Ok(None)
        }
    }

    fn add_ok_stake(&mut self, ok_stake: StakeUnit, name: &BridgeAuthorityPublicKeyBytes) {
        if let Some(host_name) = self.committee_keys_to_names.get(name) {
            self.metrics
                .auth_agg_ok_responses
                .with_label_values(&[host_name])
                .inc();
        }
        self.total_ok_stake += ok_stake;
    }

    fn add_bad_stake(&mut self, bad_stake: StakeUnit, name: &BridgeAuthorityPublicKeyBytes) {
        if let Some(host_name) = self.committee_keys_to_names.get(name) {
            self.metrics
                .auth_agg_bad_responses
                .with_label_values(&[host_name])
                .inc();
        }
        self.total_bad_stake += bad_stake;
    }

    fn is_too_many_error(&self) -> bool {
        TOTAL_VOTING_POWER - self.total_bad_stake - self.committee.total_blocklisted_stake()
            < self.validity_threshold
    }
}

async fn request_sign_bridge_action_into_certification(
    action: BridgeAction,
    committee: Arc<BridgeCommittee>,
    clients: Arc<BTreeMap<BridgeAuthorityPublicKeyBytes, Arc<BridgeClient>>>,
    state: GetSigsState,
    prefetch_timeout: Duration,
) -> BridgeResult<VerifiedCertifiedBridgeAction> {
    // `preferences` is used as a trick here to influence the order of validators to be requested.
    // * if `Some(_)`, then we will request validators in the order of the voting power.
    // * if `None`, we still refer to voting power, but they are shuffled by randomness.
    // Because ethereum gas price is not negligible, when the signatures are to be verified on ethereum,
    // we pass in `Some` to make sure the validators with higher voting power are requested first
    // to save gas cost.
    let preference = match action {
        BridgeAction::StarcoinToEthBridgeAction(_) => Some(SigRequestPrefs {
            ordering_pref: BTreeSet::new(),
            prefetch_timeout,
        }),
        BridgeAction::EthToStarcoinBridgeAction(_) => None,
        _ => {
            if action.chain_id().is_starcoin_bridge_chain() {
                None
            } else {
                Some(SigRequestPrefs {
                    ordering_pref: BTreeSet::new(),
                    prefetch_timeout,
                })
            }
        }
    };
    let action_clone = action.clone();
    let (final_state, _) = quorum_map_then_reduce_with_timeout_and_prefs(
        committee,
        clients,
        preference,
        state,
        |name: BridgeAuthorityPublicKeyBytes, client: Arc<BridgeClient>| {
            let action = action_clone.clone();
            Box::pin(async move {
                let start = std::time::Instant::now();
                let timeout = Duration::from_millis(TOTAL_TIMEOUT_MS);
                let retry_interval = Duration::from_millis(RETRY_INTERVAL_MS);
                while start.elapsed() < timeout {
                    match client.request_sign_bridge_action(action.clone()).await {
                        Ok(result) => {
                            return Ok(result);
                        }
                        // retryable errors
                        Err(BridgeError::TxNotFinalized(info)) => {
                            warn!(
                                "Bridge authority {} observing transaction not yet finalized: {}. Retrying in {:?}",
                                name.concise(),
                                info,
                                retry_interval
                            );
                            tokio::time::sleep(retry_interval).await;
                        }
                        // non-retryable errors
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                Err(BridgeError::TransientProviderError(format!("Bridge authority {} did not observe finalized transaction after {:?}", name.concise(), timeout)))
            })
        },
        |mut state, name, stake, verified_signed_action_result| {
            Box::pin(async move {
                let verified_signed_action = match verified_signed_action_result {
                    Ok(v) => v,
                    Err(e) => {
                        error!(
                            "Failed to get verified signed action from {}: {:?}",
                            name.concise(),
                            e
                        );
                        state.add_bad_stake(stake, &name);
                        return if state.is_too_many_error() {
                            ReduceOutput::Failed(state)
                        } else {
                            ReduceOutput::Continue(state)
                        };
                    }
                };

                match state.handle_verified_signed_action(
                    name.clone(),
                    stake,
                    verified_signed_action,
                ) {
                    Ok(Some(_)) => {
                        return ReduceOutput::Success(state)
                    }
                    Ok(None) => (),
                    Err(e) => {
                        error!(
                            "Failed to handle verified signed action from {}: {:?}",
                            name.concise(),
                            e
                        );
                        state.add_bad_stake(stake, &name);
                    }
                }

                // If bad stake (including blocklisted stake) is too high to reach validity threshold, return error
                if state.is_too_many_error() {
                    ReduceOutput::Failed(state)
                } else {
                    ReduceOutput::Continue(state)
                }
            })
        },
        Duration::from_millis(TOTAL_TIMEOUT_MS),
    )
    .await
    .map_err(|state| {
        error!(
            "Failed to get enough signatures, bad stake: {}, blocklisted stake: {}, good stake: {}, validity threshold: {}",
            state.total_bad_stake,
            state.committee.total_blocklisted_stake(),
            state.total_ok_stake,
            state.validity_threshold,
        );
        BridgeError::AuthoritySignatureAggregationTooManyError(format!(
            "Failed to get enough signatures, bad stake: {}, blocklisted stake: {}, good stake: {}, validity threshold: {}",
            state.total_bad_stake,
            state.committee.total_blocklisted_stake(),
            state.total_ok_stake,
            state.validity_threshold,
        ))
    })?;

    final_state.certified_action.ok_or_else(|| {
        BridgeError::InternalError(
            "Quorum succeeded but no certified action was created".to_string(),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::time::Duration;

    use fastcrypto::traits::ToFromBytes;
    use starcoin_bridge_types::committee::VALIDITY_THRESHOLD;
    use starcoin_bridge_types::digests::TransactionDigest;

    use crate::starcoin_test_utils::EmbeddedStarcoinNode;
    use serde_json::json;
    use starcoin_rpc_client::{Params, RpcClient};
    use starcoin_transaction_builder::{
        create_signed_txn_with_association_account, encode_transfer_script_function,
        DEFAULT_MAX_GAS_AMOUNT,
    };
    use starcoin_vm_types::transaction::TransactionPayload;

    use crate::crypto::BridgeAuthorityPublicKey;
    use crate::server::mock_handler::BridgeRequestMockHandler;
    use crate::test_utils::TransactionDigestTestExt;

    use super::*;
    use crate::test_utils::{
        get_test_authorities_and_run_mock_bridge_server, get_test_authority_and_key,
        get_test_starcoin_bridge_to_eth_bridge_action, sign_action_with_key,
    };
    use crate::types::BridgeCommittee;

    #[tokio::test]
    async fn test_bridge_auth_agg_construction() {
        telemetry_subscribers::init_for_testing();

        let mut authorities = vec![];
        for _ in 0..4 {
            let (authority, _, _) = get_test_authority_and_key(2500, 12345);
            authorities.push(authority);
        }
        let committee = BridgeCommittee::new(authorities.clone()).unwrap();

        let agg = BridgeAuthorityAggregator::new_for_testing(Arc::new(committee));
        assert_eq!(
            agg.clients.keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from_iter(vec![
                authorities[0].pubkey_bytes(),
                authorities[1].pubkey_bytes(),
                authorities[2].pubkey_bytes(),
                authorities[3].pubkey_bytes()
            ])
        );

        // authority 2 is blocklisted
        authorities[2].is_blocklisted = true;
        let committee = BridgeCommittee::new(authorities.clone()).unwrap();
        let agg = BridgeAuthorityAggregator::new_for_testing(Arc::new(committee));
        assert_eq!(
            agg.clients.keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from_iter(vec![
                authorities[0].pubkey_bytes(),
                authorities[1].pubkey_bytes(),
                authorities[3].pubkey_bytes()
            ])
        );

        // authority 3 has bad url
        authorities[3].base_url = "".into();
        let committee = BridgeCommittee::new(authorities.clone()).unwrap();
        let agg = BridgeAuthorityAggregator::new_for_testing(Arc::new(committee));
        assert_eq!(
            agg.clients.keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from_iter(vec![
                authorities[0].pubkey_bytes(),
                authorities[1].pubkey_bytes(),
                authorities[3].pubkey_bytes()
            ])
        );
    }

    #[tokio::test]
    async fn test_bridge_auth_agg_ok() {
        telemetry_subscribers::init_for_testing();

        let mock0 = BridgeRequestMockHandler::new();
        let mock1 = BridgeRequestMockHandler::new();
        let mock2 = BridgeRequestMockHandler::new();
        let mock3 = BridgeRequestMockHandler::new();

        // start servers
        let (_handles, authorities, secrets) = get_test_authorities_and_run_mock_bridge_server(
            vec![2500, 2500, 2500, 2500],
            vec![mock0.clone(), mock1.clone(), mock2.clone(), mock3.clone()],
        );

        let committee = BridgeCommittee::new(authorities).unwrap();

        let agg = BridgeAuthorityAggregator::new_for_testing(Arc::new(committee));

        let starcoin_bridge_tx_digest = TransactionDigest::random();
        let starcoin_bridge_tx_event_index = 0;
        let nonce = 0;
        let amount = 1000;
        let action = get_test_starcoin_bridge_to_eth_bridge_action(
            Some(starcoin_bridge_tx_digest),
            Some(starcoin_bridge_tx_event_index),
            Some(nonce),
            Some(amount),
            None,
            None,
            None,
        );

        // All authorities return signatures
        mock0.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[0])),
            None,
        );
        mock1.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[1])),
            None,
        );
        mock2.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[2])),
            None,
        );
        mock3.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[3])),
            None,
        );
        agg.request_committee_signatures(action.clone())
            .await
            .unwrap();

        // 1 out of 4 authorities returns error
        mock3.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Err(BridgeError::RestAPIError("".into())),
            None,
        );
        agg.request_committee_signatures(action.clone())
            .await
            .unwrap();

        // 2 out of 4 authorities returns error
        mock2.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Err(BridgeError::RestAPIError("".into())),
            None,
        );
        agg.request_committee_signatures(action.clone())
            .await
            .unwrap();

        // 3 out of 4 authorities returns error - good stake below valdiity threshold
        mock1.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Err(BridgeError::RestAPIError("".into())),
            None,
        );
        let err = agg
            .request_committee_signatures(action.clone())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            BridgeError::AuthoritySignatureAggregationTooManyError(_)
        ));
    }

    // Removed: test_bridge_auth_agg_optimized - timing-sensitive performance test
    // If needed, can be re-implemented with deterministic timing controls

    #[tokio::test]
    #[ignore] // TODO: Fix timing-sensitive test
    async fn test_bridge_auth_agg_optimized() {
        telemetry_subscribers::init_for_testing();

        let mock0 = BridgeRequestMockHandler::new();
        let mock1 = BridgeRequestMockHandler::new();
        let mock2 = BridgeRequestMockHandler::new();
        let mock3 = BridgeRequestMockHandler::new();
        let mock4 = BridgeRequestMockHandler::new();
        let mock5 = BridgeRequestMockHandler::new();
        let mock6 = BridgeRequestMockHandler::new();
        let mock7 = BridgeRequestMockHandler::new();
        let mock8 = BridgeRequestMockHandler::new();

        // start servers - there is only one permutation of size 2 (1112, 2222) that will achieve quorum
        let (_handles, authorities, secrets) = get_test_authorities_and_run_mock_bridge_server(
            vec![666, 1000, 900, 900, 900, 900, 900, 1612, 2222],
            vec![
                mock0.clone(),
                mock1.clone(),
                mock2.clone(),
                mock3.clone(),
                mock4.clone(),
                mock5.clone(),
                mock6.clone(),
                mock7.clone(),
                mock8.clone(),
            ],
        );

        let authorities_clone = authorities.clone();
        let committee = Arc::new(BridgeCommittee::new(authorities_clone).unwrap());

        let agg = BridgeAuthorityAggregator::new_for_testing(committee.clone());

        let starcoin_bridge_tx_digest = TransactionDigest::random();
        let starcoin_bridge_tx_event_index = 0;
        let nonce = 0;
        let amount = 1000;
        let action = get_test_starcoin_bridge_to_eth_bridge_action(
            Some(starcoin_bridge_tx_digest),
            Some(starcoin_bridge_tx_event_index),
            Some(nonce),
            Some(amount),
            None,
            None,
            None,
        );

        // All authorities return signatures
        mock0.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[0])),
            Some(Duration::from_millis(200)),
        );
        mock1.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[1])),
            Some(Duration::from_millis(200)),
        );
        mock2.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[2])),
            Some(Duration::from_millis(700)),
        );
        mock3.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[3])),
            Some(Duration::from_millis(700)),
        );
        mock4.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[4])),
            Some(Duration::from_millis(700)),
        );
        mock5.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[5])),
            Some(Duration::from_millis(700)),
        );
        mock6.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[6])),
            Some(Duration::from_millis(700)),
        );
        mock7.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[7])),
            Some(Duration::from_millis(900)),
        );
        mock8.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[8])),
            Some(Duration::from_millis(1_500)),
        );

        // we should receive all signatures in time, but only aggregate 2 authorities
        // to achieve quorum
        let metrics = Arc::new(BridgeMetrics::new_for_testing());
        let state = GetSigsState::new(
            action.approval_threshold(),
            committee.clone(),
            metrics.clone(),
            Arc::new(BTreeMap::new()),
        );
        let resp = request_sign_bridge_action_into_certification(
            action.clone(),
            agg.committee.clone(),
            agg.clients.clone(),
            state,
            Duration::from_millis(2_000),
        )
        .await
        .unwrap();
        let sig_keys = resp.auth_sig().signatures.keys().collect::<BTreeSet<_>>();
        assert_eq!(sig_keys.len(), 2);
        assert!(sig_keys.contains(&authorities[7].pubkey_bytes()));
        assert!(sig_keys.contains(&authorities[8].pubkey_bytes()));

        // we should receive all but the highest stake signatures in time, but still be able to
        // achieve quorum with 3 sigs
        let state = GetSigsState::new(
            action.approval_threshold(),
            committee.clone(),
            metrics.clone(),
            Arc::new(BTreeMap::new()),
        );
        let resp = request_sign_bridge_action_into_certification(
            action.clone(),
            agg.committee.clone(),
            agg.clients.clone(),
            state,
            Duration::from_millis(1_200),
        )
        .await
        .unwrap();
        let sig_keys = resp.auth_sig().signatures.keys().collect::<BTreeSet<_>>();
        assert_eq!(sig_keys.len(), 3);
        assert!(sig_keys.contains(&authorities[7].pubkey_bytes()));
        // this should not have come in time
        assert!(!sig_keys.contains(&authorities[8].pubkey_bytes()));

        // we should have fallen back to arrival order given that we timeout before we reach quorum
        let state = GetSigsState::new(
            action.approval_threshold(),
            committee.clone(),
            metrics.clone(),
            Arc::new(BTreeMap::new()),
        );
        let start = std::time::Instant::now();
        let resp = request_sign_bridge_action_into_certification(
            action.clone(),
            agg.committee.clone(),
            agg.clients.clone(),
            state,
            Duration::from_millis(500),
        )
        .await
        .unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(700),
            "Expected to have to wait at least 700ms to fallback to arrival order and achieve quorum, but was {:?}",
            elapsed
        );
        let sig_keys = resp.auth_sig().signatures.keys().collect::<BTreeSet<_>>();
        assert_eq!(sig_keys.len(), 4);
        // These two do not make it on time initially, and then we should be able
        // to achieve quorum before these ultimately arrive
        assert!(!sig_keys.contains(&authorities[7].pubkey_bytes()));
        assert!(!sig_keys.contains(&authorities[8].pubkey_bytes()));
        // These were the first two to respond, and should be immediately
        // included once we fallback to arrival order
        assert!(sig_keys.contains(&authorities[0].pubkey_bytes()));
        assert!(sig_keys.contains(&authorities[1].pubkey_bytes()));
    }

    #[tokio::test]
    async fn test_bridge_auth_agg_more_cases() {
        telemetry_subscribers::init_for_testing();

        let mock0 = BridgeRequestMockHandler::new();
        let mock1 = BridgeRequestMockHandler::new();
        let mock2 = BridgeRequestMockHandler::new();
        let mock3 = BridgeRequestMockHandler::new();

        // start servers
        let (_handles, mut authorities, secrets) = get_test_authorities_and_run_mock_bridge_server(
            vec![2500, 2500, 2500, 2500],
            vec![mock0.clone(), mock1.clone(), mock2.clone(), mock3.clone()],
        );
        // 0 and 1 are blocklisted
        authorities[0].is_blocklisted = true;
        authorities[1].is_blocklisted = true;

        let committee = BridgeCommittee::new(authorities.clone()).unwrap();

        let agg = BridgeAuthorityAggregator::new_for_testing(Arc::new(committee));

        let starcoin_bridge_tx_digest = TransactionDigest::random();
        let starcoin_bridge_tx_event_index = 0;
        let nonce = 0;
        let amount = 1000;
        let action = get_test_starcoin_bridge_to_eth_bridge_action(
            Some(starcoin_bridge_tx_digest),
            Some(starcoin_bridge_tx_event_index),
            Some(nonce),
            Some(amount),
            None,
            None,
            None,
        );

        // Only mock authority 2 and 3 to return signatures, such that if BridgeAuthorityAggregator
        // requests to authority 0 and 1 (which should not happen) it will panic.
        mock2.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[2])),
            None,
        );
        mock3.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[3])),
            None,
        );
        let certified = agg
            .request_committee_signatures(action.clone())
            .await
            .unwrap();
        let signers = certified
            .auth_sig()
            .signatures
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            signers,
            BTreeSet::from_iter(vec![
                authorities[2].pubkey_bytes(),
                authorities[3].pubkey_bytes()
            ])
        );

        // if mock 3 returns error, then it won't reach validity threshold
        mock3.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Err(BridgeError::RestAPIError("".into())),
            None,
        );
        let err = agg
            .request_committee_signatures(action.clone())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            BridgeError::AuthoritySignatureAggregationTooManyError(_)
        ));

        // if mock 3 returns duplicated signature (by authority 2), `BridgeClient` will catch this
        mock3.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[2])),
            None,
        );
        let err = agg
            .request_committee_signatures(action.clone())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            BridgeError::AuthoritySignatureAggregationTooManyError(_)
        ));
    }

    #[test]
    fn test_get_sigs_state() {
        telemetry_subscribers::init_for_testing();

        let mut authorities = vec![];
        let mut secrets = vec![];
        for _ in 0..4 {
            let (authority, _, secret) = get_test_authority_and_key(2500, 12345);
            authorities.push(authority);
            secrets.push(secret);
        }

        let committee = BridgeCommittee::new(authorities.clone()).unwrap();

        let threshold = VALIDITY_THRESHOLD;
        let metrics = Arc::new(BridgeMetrics::new_for_testing());
        let mut state = GetSigsState::new(
            threshold,
            Arc::new(committee),
            metrics.clone(),
            Arc::new(BTreeMap::new()),
        );

        assert!(!state.is_too_many_error());
        let dummy = authorities[0].pubkey_bytes();
        // bad stake: 2500
        state.add_bad_stake(2500, &dummy);
        assert!(!state.is_too_many_error());

        // bad stake ; 5000
        state.add_bad_stake(2500, &dummy);
        assert!(!state.is_too_many_error());

        // bad stake : 6666
        state.add_bad_stake(1666, &dummy);
        assert!(!state.is_too_many_error());

        // bad stake : 6667 - too many errors
        state.add_bad_stake(1, &dummy);
        assert!(state.is_too_many_error());

        // Authority 0 is blocklisted, we lose 2500 stake
        authorities[0].is_blocklisted = true;
        let committee = BridgeCommittee::new(authorities.clone()).unwrap();
        let threshold = VALIDITY_THRESHOLD;
        let metrics = Arc::new(BridgeMetrics::new_for_testing());
        let mut state = GetSigsState::new(
            threshold,
            Arc::new(committee),
            metrics.clone(),
            Arc::new(BTreeMap::new()),
        );

        assert!(!state.is_too_many_error());

        // bad stake: 2500 + 2500
        state.add_bad_stake(2500, &dummy);
        assert!(!state.is_too_many_error());

        // bad stake: 5000 + 2500 - too many errors
        state.add_bad_stake(2500, &dummy);
        assert!(state.is_too_many_error());

        // Below we test `handle_verified_signed_action`
        authorities[0].is_blocklisted = false;
        authorities[1].voting_power = 1; // set authority's voting power to minimal
        authorities[2].voting_power = 4999;
        authorities[3].is_blocklisted = true; // blocklist authority 3

        let committee = BridgeCommittee::new(authorities.clone()).unwrap();
        let threshold = VALIDITY_THRESHOLD;
        let mut state = GetSigsState::new(
            threshold,
            Arc::new(committee.clone()),
            metrics.clone(),
            Arc::new(BTreeMap::new()),
        );

        let starcoin_bridge_tx_digest = TransactionDigest::random();
        let starcoin_bridge_tx_event_index = 0;
        let nonce = 0;
        let amount = 1000;
        let action = get_test_starcoin_bridge_to_eth_bridge_action(
            Some(starcoin_bridge_tx_digest),
            Some(starcoin_bridge_tx_event_index),
            Some(nonce),
            Some(amount),
            None,
            None,
            None,
        );

        let sig_0 = sign_action_with_key(&action, &secrets[0]);
        // returns Ok(None)
        assert!(state
            .handle_verified_signed_action(
                authorities[0].pubkey_bytes().clone(),
                authorities[0].voting_power,
                VerifiedSignedBridgeAction::new_from_verified(sig_0.clone())
            )
            .unwrap()
            .is_none());
        assert_eq!(state.total_ok_stake, 2500);

        // Handling a sig from an already signed authority would fail
        let new_sig_0 = sign_action_with_key(&action, &secrets[0]);
        // returns Err(BridgeError::AuthoritySignatureDuplication)
        let err = state
            .handle_verified_signed_action(
                authorities[0].pubkey_bytes().clone(),
                authorities[0].voting_power,
                VerifiedSignedBridgeAction::new_from_verified(new_sig_0.clone()),
            )
            .unwrap_err();
        assert!(matches!(err, BridgeError::AuthoritySignatureDuplication(_)));
        assert_eq!(state.total_ok_stake, 2500);

        // Handling a sig from an authority not in committee would fail
        let (unknown_authority, _, kp) = get_test_authority_and_key(2500, 12345);
        let unknown_sig = sign_action_with_key(&action, &kp);
        // returns Err(BridgeError::InvalidBridgeAuthority)
        let err = state
            .handle_verified_signed_action(
                unknown_authority.pubkey_bytes().clone(),
                authorities[0].voting_power,
                VerifiedSignedBridgeAction::new_from_verified(unknown_sig.clone()),
            )
            .unwrap_err();
        assert!(matches!(err, BridgeError::InvalidBridgeAuthority(_)));
        assert_eq!(state.total_ok_stake, 2500);

        // Handling a blocklisted authority would fail
        let sig_3 = sign_action_with_key(&action, &secrets[3]);
        // returns Err(BridgeError::InvalidBridgeAuthority)
        let err = state
            .handle_verified_signed_action(
                authorities[3].pubkey_bytes().clone(),
                authorities[3].voting_power,
                VerifiedSignedBridgeAction::new_from_verified(sig_3.clone()),
            )
            .unwrap_err();
        assert!(matches!(err, BridgeError::InvalidBridgeAuthority(_)));
        assert_eq!(state.total_ok_stake, 2500);

        // Collect signtuare from authority 1 (voting power = 1)
        let sig_1 = sign_action_with_key(&action, &secrets[1]);
        // returns Ok(None)
        assert!(state
            .handle_verified_signed_action(
                authorities[1].pubkey_bytes().clone(),
                authorities[1].voting_power,
                VerifiedSignedBridgeAction::new_from_verified(sig_1.clone())
            )
            .unwrap()
            .is_none());
        assert_eq!(state.total_ok_stake, 2501);

        // Collect signature from authority 2 - reach validity threshold
        let sig_2 = sign_action_with_key(&action, &secrets[2]);
        // returns Ok(None)
        let certificate = state
            .handle_verified_signed_action(
                authorities[2].pubkey_bytes().clone(),
                authorities[2].voting_power,
                VerifiedSignedBridgeAction::new_from_verified(sig_2.clone()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(state.total_ok_stake, 7500);

        assert_eq!(certificate.data(), &action);
        let signers = certificate
            .auth_sig()
            .signatures
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            signers,
            BTreeSet::from_iter(vec![
                authorities[0].pubkey_bytes(),
                authorities[1].pubkey_bytes(),
                authorities[2].pubkey_bytes()
            ])
        );

        for (pubkey, sig) in &certificate.auth_sig().signatures {
            let sign_info = BridgeAuthoritySignInfo {
                authority_pub_key: BridgeAuthorityPublicKey::from_bytes(pubkey.as_ref()).unwrap(),
                signature: sig.clone(),
            };
            assert!(sign_info.verify(&action, &committee).is_ok());
        }
    }

    async fn drop_on_blocking_thread<T: Send + 'static>(value: T) {
        tokio::task::spawn_blocking(move || drop(value))
            .await
            .expect("drop join failed");
    }

    async fn get_sequence_number_via_local_rpc(
        rpc: std::sync::Arc<RpcClient>,
        address: String,
    ) -> Result<u64, anyhow::Error> {
        let v = tokio::task::spawn_blocking(move || {
            rpc.call_raw_api(
                "txpool.next_sequence_number",
                Params::Array(vec![json!(address)]),
            )
        })
        .await
        .map_err(|e| anyhow::anyhow!("join error: {e}"))??;

        Ok(v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            .unwrap_or(0))
    }

    fn tx_digest_from_event_value(event_value: &serde_json::Value) -> [u8; 32] {
        event_value
            .get("transaction_hash")
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
            .and_then(|bytes| bytes.try_into().ok())
            .unwrap_or([0u8; 32])
    }

    #[tokio::test]
    #[ignore = "Governance actions not supported by validator API - per design in frontend.md"]
    async fn test_bridge_auth_agg_blocklist_requires_three_signatures() {
        telemetry_subscribers::init_for_testing();

        // Use embedded Starcoin node to derive a unique nonce (proof of in-memory node interaction).
        let mut node = Some(EmbeddedStarcoinNode::start().expect("Failed to start embedded node"));
        let block = node
            .as_ref()
            .unwrap()
            .generate_block()
            .expect("Failed to generate block");
        let nonce = block.header().number();

        // Start 3 mock bridge servers (committee members) that can sign governance actions.
        let mock0 = BridgeRequestMockHandler::new();
        let mock1 = BridgeRequestMockHandler::new();
        let mock2 = BridgeRequestMockHandler::new();
        let mocks = vec![mock0.clone(), mock1.clone(), mock2.clone()];

        let (_handles, ports) = crate::test_utils::run_mock_bridge_server(mocks);

        // Create committee members with 2500 voting power each.
        // Blocklist committee action threshold is 5001, so 2*2500=5000 is insufficient,
        // and all 3 signatures are required to succeed.
        let mut authorities = vec![];
        let mut secrets = vec![];
        for port in ports {
            let (authority, _pubkey, secret) = get_test_authority_and_key(2500, port);
            authorities.push(authority);
            secrets.push(secret);
        }

        // Configure each mock server with its signer key.
        mock0.set_signer(secrets.remove(0));
        mock1.set_signer(secrets.remove(0));
        mock2.set_signer(secrets.remove(0));

        let committee = BridgeCommittee::new(authorities.clone()).unwrap();
        let agg = BridgeAuthorityAggregator::new_for_testing(Arc::new(committee));

        // Create a governance action (blocklist) that requires the higher threshold.
        let action =
            BridgeAction::BlocklistCommitteeAction(crate::types::BlocklistCommitteeAction {
                nonce,
                chain_id: starcoin_bridge_types::bridge::BridgeChainId::EthSepolia,
                blocklist_type: crate::types::BlocklistType::Blocklist,
                members_to_update: vec![
                    authorities[0].pubkey_bytes(),
                    authorities[1].pubkey_bytes(),
                ],
            });

        let certified = agg
            .request_committee_signatures(action)
            .await
            .expect("blocklist signature aggregation should succeed with 3 signatures");

        let signers = certified
            .auth_sig()
            .signatures
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();

        assert_eq!(
            signers.len(),
            3,
            "expected exactly 3 signatures to reach threshold 5001 with 3x2500 stake"
        );

        let expected = authorities
            .iter()
            .map(|a| a.pubkey_bytes())
            .collect::<BTreeSet<_>>();
        assert_eq!(signers, expected);

        let node_to_drop = node.take().unwrap();
        drop_on_blocking_thread(node_to_drop).await;
    }

    #[tokio::test]
    async fn test_bridge_auth_agg_with_embedded_starcoin_tx_digest() {
        telemetry_subscribers::init_for_testing();

        // 1) Start embedded Starcoin node (in-memory) and connect via in-process RPC.
        let mut node = Some(EmbeddedStarcoinNode::start().expect("Failed to start embedded node"));
        let config = node.as_ref().unwrap().config();

        let rpc_service = node
            .as_ref()
            .unwrap()
            .handle()
            .rpc_service()
            .expect("Failed to get RpcService");
        let local_rpc = tokio::task::spawn_blocking(move || RpcClient::connect_local(rpc_service))
            .await
            .expect("connect_local join failed")
            .expect("connect_local failed");
        let mut rpc = Some(std::sync::Arc::new(local_rpc));

        // 2) Submit a transfer to ensure there is at least one event with a real tx hash.
        let receiver = starcoin_types::account_address::AccountAddress::random();
        let association_addr = starcoin_vm_types::account_config::association_address();
        let start_seq = get_sequence_number_via_local_rpc(
            rpc.as_ref().unwrap().clone(),
            association_addr.to_string(),
        )
        .await
        .expect("Failed to read association sequence number");

        let payload =
            TransactionPayload::ScriptFunction(encode_transfer_script_function(receiver, 1_000));
        let txn = create_signed_txn_with_association_account(
            payload,
            start_seq,
            DEFAULT_MAX_GAS_AMOUNT,
            1,
            3600,
            config.net(),
        );

        node.as_ref()
            .unwrap()
            .submit_transaction(txn)
            .expect("Failed to submit txn");
        let block = node
            .as_ref()
            .unwrap()
            .generate_block()
            .expect("Failed to generate block");
        let block_number = block.header().number();

        // Give internal services a moment to observe the new head.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // 3) Fetch any event from this block and extract its real transaction hash.
        let raw = tokio::task::spawn_blocking({
            let rpc = rpc.as_ref().unwrap().clone();
            move || {
                rpc.call_raw_api(
                    "chain.get_events",
                    Params::Array(vec![
                        json!({
                            "from_block": block_number,
                            "to_block": block_number,
                            "limit": 100,
                        }),
                        json!({ "decode": true }),
                    ]),
                )
            }
        })
        .await
        .expect("chain.get_events join failed")
        .expect("chain.get_events failed");

        let raw_events: Vec<serde_json::Value> =
            serde_json::from_value(raw).expect("Failed to parse chain.get_events response");
        assert!(
            !raw_events.is_empty(),
            "Expected at least one event in generated block"
        );

        let starcoin_bridge_tx_digest: TransactionDigest =
            tx_digest_from_event_value(&raw_events[0]);
        assert_ne!(
            starcoin_bridge_tx_digest, [0u8; 32],
            "Expected a non-zero tx digest from embedded node events"
        );

        // 4) Run BridgeAuthorityAggregator with mock authorities, using the real tx digest.
        let mock0 = BridgeRequestMockHandler::new();
        let mock1 = BridgeRequestMockHandler::new();
        let mock2 = BridgeRequestMockHandler::new();
        let mock3 = BridgeRequestMockHandler::new();

        let (_handles, authorities, secrets) = get_test_authorities_and_run_mock_bridge_server(
            vec![2500, 2500, 2500, 2500],
            vec![mock0.clone(), mock1.clone(), mock2.clone(), mock3.clone()],
        );
        let committee = BridgeCommittee::new(authorities.clone()).unwrap();
        let agg = BridgeAuthorityAggregator::new_for_testing(Arc::new(committee));

        let starcoin_bridge_tx_event_index = 0;
        let nonce = 0;
        let amount = 1000;
        let action = get_test_starcoin_bridge_to_eth_bridge_action(
            Some(starcoin_bridge_tx_digest),
            Some(starcoin_bridge_tx_event_index),
            Some(nonce),
            Some(amount),
            None,
            None,
            None,
        );

        // Token transfer approval threshold is 3334, so 2 authorities with 2500 stake each is sufficient.
        mock0.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[0])),
            None,
        );
        mock1.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[1])),
            None,
        );
        mock2.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Ok(sign_action_with_key(&action, &secrets[2])),
            None,
        );
        mock3.add_starcoin_bridge_event_response(
            starcoin_bridge_tx_digest,
            starcoin_bridge_tx_event_index,
            Err(BridgeError::RestAPIError("".into())),
            None,
        );

        let certified = agg
            .request_committee_signatures(action)
            .await
            .expect("signature aggregation should succeed");

        let signers = certified
            .auth_sig()
            .signatures
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            signers.len(),
            2,
            "expected to stop after reaching threshold with 2 signatures, got {}: {:?}",
            signers.len(),
            signers
        );
        assert!(
            !signers.contains(&authorities[3].pubkey_bytes()),
            "unexpectedly included the authority configured to error: {:?}",
            signers
        );
        for signer in &signers {
            assert!(
                authorities.iter().any(|a| &a.pubkey_bytes() == signer),
                "signature from non-committee member: {:?}",
                signer
            );
        }

        // RpcClient owns a Tokio runtime internally; drop it on a blocking thread.
        let rpc_to_drop = rpc.take().unwrap();
        drop_on_blocking_thread(rpc_to_drop).await;

        let node_to_drop = node.take().unwrap();
        drop_on_blocking_thread(node_to_drop).await;
    }
}
