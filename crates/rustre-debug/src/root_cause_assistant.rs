//! AI root-cause assistant (Tier 2, item 7 of `rustre_debug_enhancement_plan.md`).
//!
//! Turns a single "this value is wrong" observation into a ranked list of suspect
//! instructions, in two stages:
//!
//! 1. **Causal slice**: walk [`crate::omniscient_query::OmniscientIndex::trace_origin`] backward from the bad
//!    address/time to get the exact chain of writes that produced the observed value —
//!    the ground truth, when the chain terminates cleanly.
//! 2. **Bayesian pre-filter**: when the causal slice alone doesn't pinpoint a single
//!    culprit (e.g. many candidate writers touched the address, or the chain is long),
//!    rank every writer PC that touched the bad address by how much more often it writes
//!    there in the *bad* run than in a known-*good* baseline run of the same index type.
//!    This is deliberately simple counting with Laplace smoothing, not a full Bayesian
//!    network — it is a cheap pre-filter to narrow the search before a human (or a
//!    heavier analysis) looks at the causal slice in detail.

use std::collections::BTreeMap;

use rustre_core::address::Address;

use crate::omniscient_query::{OmniscientIndex, OriginHop};

/// A single writer PC's suspicion score for a bad-value observation.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SuspectScore {
    /// The instruction pointer that performed a write to the bad address.
    pub pc: Address,
    /// Times this PC wrote to the bad address in the bad run (at or before the
    /// observation time).
    pub bad_hits: u64,
    /// Times this PC wrote to the bad address anywhere in the good baseline run.
    pub good_hits: u64,
    /// Laplace-smoothed posterior that this PC is implicated in the bad value:
    /// `(bad_hits + 1) / (bad_hits + good_hits + 2)`. Ranges over `(0, 1)`;
    /// `0.5` means no evidence either way (an unseen PC in both runs).
    pub score: f64,
}

/// Full root-cause report for one bad-value observation.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RootCauseReport {
    /// The exact backward write chain for the observation, oldest cause last.
    pub causal_slice: Vec<OriginHop>,
    /// Writer PCs that touched the bad address, ranked by suspicion score
    /// (highest first).
    pub suspects: Vec<SuspectScore>,
}

impl RootCauseReport {
    /// The single most likely culprit PC, if any suspects were found.
    #[must_use]
    pub fn top_suspect(&self) -> Option<&SuspectScore> {
        self.suspects.first()
    }

    /// `true` if the causal slice terminated at a write with no further source
    /// (a clean origin was found, rather than hitting the chain-length cap or
    /// running out of history).
    #[must_use]
    pub fn has_clean_origin(&self) -> bool {
        self.causal_slice
            .last()
            .is_some_and(|hop| hop.write.source_address.is_none())
    }
}

/// Rank every writer PC that touched `bad_address` (at or before `bad_time` in
/// `bad_index`) by how much more often it writes there in `bad_index` than in
/// `good_baseline`, using Laplace-smoothed counts. Highest score first.
#[must_use]
pub fn bayesian_prefilter(
    bad_index: &OmniscientIndex,
    bad_address: Address,
    bad_time: u64,
    good_baseline: &OmniscientIndex,
) -> Vec<SuspectScore> {
    let bad_writes = bad_index.who_wrote(bad_address, bad_time);
    let good_writes = good_baseline.who_wrote(bad_address, u64::MAX);

    let mut bad_counts: BTreeMap<u64, u64> = BTreeMap::new();
    for w in &bad_writes {
        if let Some(pc) = w.writer_pc {
            *bad_counts.entry(pc.as_u64()).or_insert(0) += 1;
        }
    }
    let mut good_counts: BTreeMap<u64, u64> = BTreeMap::new();
    for w in &good_writes {
        if let Some(pc) = w.writer_pc {
            *good_counts.entry(pc.as_u64()).or_insert(0) += 1;
        }
    }

    let mut pcs: Vec<u64> = bad_counts.keys().chain(good_counts.keys()).copied().collect();
    pcs.sort_unstable();
    pcs.dedup();

    let mut suspects: Vec<SuspectScore> = pcs
        .into_iter()
        .map(|pc| {
            let bad_hits = bad_counts.get(&pc).copied().unwrap_or(0);
            let good_hits = good_counts.get(&pc).copied().unwrap_or(0);
            #[allow(clippy::cast_precision_loss)]
            let score = (bad_hits as f64 + 1.0) / (bad_hits as f64 + good_hits as f64 + 2.0);
            SuspectScore { pc: Address(pc), bad_hits, good_hits, score }
        })
        .collect();

    suspects.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.pc.as_u64().cmp(&b.pc.as_u64()))
    });
    suspects
}

/// Build a full root-cause report for a bad-value observation: the exact causal
/// slice (via [`crate::omniscient_query::OmniscientIndex::trace_origin`]) plus a Bayesian-ranked suspect
/// list of writer PCs, comparing `bad_index` against `good_baseline`.
#[must_use]
pub fn root_cause(
    bad_index: &OmniscientIndex,
    bad_address: Address,
    bad_time: u64,
    good_baseline: &OmniscientIndex,
) -> RootCauseReport {
    RootCauseReport {
        causal_slice: bad_index.trace_origin(bad_address, bad_time),
        suspects: bayesian_prefilter(bad_index, bad_address, bad_time, good_baseline),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::omniscient_query::MemoryWrite;
    use crate::ThreadId;

    fn tid() -> ThreadId {
        ThreadId(1)
    }

    fn write(seq: u64, addr: u64, pc: u64) -> MemoryWrite {
        MemoryWrite {
            sequence: seq,
            address: Address(addr),
            size: 4,
            tid: tid(),
            writer_pc: Some(Address(pc)),
            source_address: None,
        }
    }

    #[test]
    fn prefilter_ranks_bad_only_pc_above_shared_pc() {
        // pc 0x100 writes the bad address only in the bad run; pc 0x200 writes
        // it in both runs equally often — 0x100 should be the top suspect.
        let bad = OmniscientIndex::from_writes(vec![write(0, 0x1000, 0x100), write(1, 0x1000, 0x200)]);
        let good = OmniscientIndex::from_writes(vec![write(0, 0x1000, 0x200)]);

        let suspects = bayesian_prefilter(&bad, Address(0x1000), 10, &good);
        assert_eq!(suspects[0].pc, Address(0x100));
        assert!(suspects[0].score > suspects.iter().find(|s| s.pc == Address(0x200)).unwrap().score);
    }

    #[test]
    fn prefilter_empty_when_no_writes() {
        let bad = OmniscientIndex::new();
        let good = OmniscientIndex::new();
        assert!(bayesian_prefilter(&bad, Address(0x1000), 10, &good).is_empty());
    }

    #[test]
    fn root_cause_combines_slice_and_suspects() {
        let bad = OmniscientIndex::from_writes(vec![write(0, 0x1000, 0x100)]);
        let good = OmniscientIndex::new();
        let report = root_cause(&bad, Address(0x1000), 10, &good);
        assert_eq!(report.causal_slice.len(), 1);
        assert!(report.has_clean_origin());
        assert_eq!(report.top_suspect().unwrap().pc, Address(0x100));
    }

    #[test]
    fn causal_slice_follows_source_chain() {
        let mut bad = OmniscientIndex::new();
        bad.push(MemoryWrite {
            sequence: 0,
            address: Address(0x2000),
            size: 4,
            tid: tid(),
            writer_pc: Some(Address(0x50)),
            source_address: None,
        });
        bad.push(MemoryWrite {
            sequence: 1,
            address: Address(0x3000),
            size: 4,
            tid: tid(),
            writer_pc: Some(Address(0x60)),
            source_address: Some(Address(0x2000)),
        });
        let good = OmniscientIndex::new();
        let report = root_cause(&bad, Address(0x3000), 10, &good);
        assert_eq!(report.causal_slice.len(), 2);
        assert_eq!(report.causal_slice[0].write.writer_pc, Some(Address(0x60)));
        assert_eq!(report.causal_slice[1].write.writer_pc, Some(Address(0x50)));
        assert!(report.has_clean_origin());
    }

    #[test]
    fn no_evidence_pc_scores_around_half() {
        let bad = OmniscientIndex::new();
        let good = OmniscientIndex::from_writes(vec![write(0, 0x1000, 0x100)]);
        let suspects = bayesian_prefilter(&bad, Address(0x1000), 10, &good);
        assert_eq!(suspects.len(), 1);
        assert!(suspects[0].score < 0.5);
    }
}
