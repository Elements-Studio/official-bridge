// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0
// Simplified for Starcoin Bridge

/// Committee version number (incremented when committee members change)
pub type CommitteeVersion = u64;
pub type StakeUnit = u64;

// Voting power constants (Bridge uses these)
pub const TOTAL_VOTING_POWER: StakeUnit = 10_000;
/// Quorum threshold (2/3 of voting power)
pub const QUORUM_THRESHOLD: StakeUnit = 6_667;
/// Validity threshold (1/3 of voting power + 1)
pub const VALIDITY_THRESHOLD: StakeUnit = 3_334;

/// Committee trait for Bridge compatibility
pub trait CommitteeTrait {
    fn version(&self) -> CommitteeVersion;
    fn num_members(&self) -> usize;

    // Shuffle committee members by stake with random number generator
    fn shuffle_by_stake_with_rng<R: rand::Rng>(
        &self,
        preferences: &[super::base_types::AuthorityName],
        rng: &mut R,
    ) -> Vec<super::base_types::AuthorityName>;

    // Get weight/stake of an authority
    fn weight(&self, authority: &super::base_types::AuthorityName) -> StakeUnit;
}
