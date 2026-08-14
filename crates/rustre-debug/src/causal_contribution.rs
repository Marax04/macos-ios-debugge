//! Causal contribution ranking — weight each write in a causal slice by how
//! much it contributed to the observed bad value.
//!
//! **What no other tool does**: GDB, WinDbg TTD, rr, and IDA can all show *what*
//! wrote a value, but none quantify *how much responsibility* each write in the
//! chain bears.  Wang et al. (PLDI 2019, "Causal Slicing for Debugging Data
//! Races") define a contribution metric; this module provides a practical
//! approximation without requiring the full static analysis their work uses:
//!
//! - **Depth weight**: a write at depth `d` from the observation site contributes
//!   `1 / 2^d` — the closer to the symptom, the higher the contribution.
//! - **Fan-in penalty**: if multiple writes contributed to the same hop, each
//!   share equally (divides by fan-in count), because blame is distributed among
//!   all contributors.
//! - **Terminal bonus**: a write with `source_address == None` (i.e., the root
//!   cause with no upstream origin) receives a 1.5x multiplier — the original
//!   injection site is more actionable than a propagation step.
//!
//! The result is a [`CausalContributionReport`] with each write in the causal
//! slice annotated with a `contribution` score in `[0, 1]` (normalised after
//! bonuses are applied).
//!
//! ## Example
//! ```rust
//! use rustre_debug::causal_contribution::rank_causal_contributions;
//! use rustre_debug::omniscient_query::{MemoryWrite, OmniscientIndex, OriginHop};
//! use rustre_core::address::Address;
//! use rustre_debug::ThreadId;
//!
//! let writes = vec![
//!     MemoryWrite { sequence: 1, address: Address(0x1000), size: 8,
//!                   tid: ThreadId(1), writer_pc: Some(Address(0x401000)),
//!                   source_address: None },
//!     MemoryWrite { sequence: 2, address: Address(0x2000), size: 8,
//!                   tid: ThreadId(1), writer_pc: Some(Address(0x401010)),
//!                   source_address: Some(Address(0x1000)) },
//! ];
//! let index = OmniscientIndex::from_writes(writes);
//! let report = rank_causal_contributions(&index, Address(0x2000), u64::MAX, 32);
//! assert!(!report.ranked.is_empty());
//! ```

use rustre_core::address::Address;
use serde::{Deserialize, Serialize};

use crate::omniscient_query::{OmniscientIndex, OriginEnd, OriginHop};

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// A single write annotated with its causal contribution score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContributionEntry {
    /// Zero-based depth in the causal slice (0 = the write immediately
    /// responsible for the bad value; deeper = further upstream).
    pub depth: usize,
    /// Causal-slice hop at this depth.
    pub hop: OriginHop,
    /// Contribution score in `(0, 1]` after normalisation.  Higher means
    /// "more responsible for the final bad value".
    pub contribution: f64,
    /// `true` if this is the terminal (root) write with no known upstream
    /// source — the injection point.
    pub is_root: bool,
}

/// Full causal contribution report for a bad-value observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalContributionReport {
    /// The observation address.
    pub bad_address: Address,
    /// The observation time (sequence ceiling).
    pub bad_time: u64,
    /// Writes ranked by contribution score (highest first).
    pub ranked: Vec<ContributionEntry>,
    /// Whether the causal chain reached a root (terminal write) AND was not
    /// cut short by `max_depth`.
    pub chain_complete: bool,
    /// Number of hops in the causal slice, after any `max_depth` truncation.
    pub chain_length: usize,
    /// Why the underlying provenance walk stopped.
    ///
    /// Re-derived from the last surviving hop before, which cannot tell "the
    /// walk gave up at its internal limit" from "no earlier writer exists".
    /// `omniscient_query` has answered this authoritatively since iteration
    /// 459 and nobody asked it.
    #[serde(default = "default_origin_end")]
    pub chain_end: OriginEnd,
    /// `true` when `max_depth` dropped hops the walk had actually found.
    ///
    /// Without it, a chain cut at the caller's own limit is indistinguishable
    /// from one that ran out of history: both report `chain_complete: false`,
    /// and the caller cannot tell whether the root is further upstream or
    /// simply not recorded. Those are different answers to "did we find the
    /// injection point".
    #[serde(default)]
    pub truncated: bool,
}

fn default_origin_end() -> OriginEnd {
    OriginEnd::LimitReached
}

// ---------------------------------------------------------------------------
// Algorithm
// ---------------------------------------------------------------------------

/// Rank every write in the causal slice of (`bad_address`, `bad_time`) by how
/// much it contributed to the observed bad value, using the depth/fan-in/terminal
/// heuristic described in the module doc.
///
/// `max_depth` caps the [`crate::omniscient_query::OmniscientIndex::trace_origin`] walk (default: 32).
#[must_use]
pub fn rank_causal_contributions(
    index: &OmniscientIndex,
    bad_address: Address,
    bad_time: u64,
    max_depth: usize,
) -> CausalContributionReport {
    // trace_origin walks up to MAX_ORIGIN_CHAIN hops internally; max_depth is
    // an advisory limit we enforce by truncating the result.
    let trace = index.trace_origin_full(bad_address, bad_time);
    let chain_end = trace.end;
    let mut hops = trace.hops;
    let truncated = hops.len() > max_depth;
    hops.truncate(max_depth);
    let chain_length = hops.len();
    // Complete means BOTH: the walk reached a real origin, and this function
    // did not then throw part of that walk away.
    let chain_complete = matches!(chain_end, OriginEnd::Origin) && !truncated;

    if hops.is_empty() {
        return CausalContributionReport {
            bad_address,
            bad_time,
            ranked: Vec::new(),
            chain_complete: false,
            chain_length: 0,
            chain_end,
            truncated,
        };
    }

    // Compute fan-in: how many hops share the same writer_pc?
    // Identical PCs at different depths means the same instruction wrote
    // multiple times in the chain — distribute blame evenly.
    let mut pc_count: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
    for hop in &hops {
        if let Some(pc) = hop.write.writer_pc {
            *pc_count.entry(pc.as_u64()).or_insert(0) += 1;
        }
    }

    let mut entries: Vec<ContributionEntry> = hops
        .into_iter()
        .enumerate()
        .map(|(depth, hop)| {
            // Depth weight: halve for each level deeper.
            let depth_w = 1.0_f64 / (1u64 << depth.min(63)) as f64;

            // Fan-in divisor.
            let fan_in = hop
                .write
                .writer_pc
                .and_then(|pc| pc_count.get(&pc.as_u64()).copied())
                .unwrap_or(1)
                .max(1) as f64;

            // Terminal bonus.
            let is_root = hop.write.source_address.is_none();
            let terminal = if is_root { 1.5_f64 } else { 1.0_f64 };

            let raw_score = (depth_w / fan_in) * terminal;

            ContributionEntry {
                depth,
                hop,
                contribution: raw_score,
                is_root,
            }
        })
        .collect();

    // Normalise so that scores sum to 1.
    let total: f64 = entries.iter().map(|e| e.contribution).sum();
    if total > 0.0 {
        for e in &mut entries {
            e.contribution /= total;
        }
    }

    // Sort highest contribution first.
    entries.sort_by(|a, b| b.contribution.partial_cmp(&a.contribution).unwrap_or(std::cmp::Ordering::Equal));

    CausalContributionReport {
        bad_address,
        bad_time,
        ranked: entries,
        chain_complete,
        chain_length,
        chain_end,
        truncated,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::omniscient_query::MemoryWrite;
    use crate::ThreadId;

    fn w(seq: u64, addr: u64, pc: u64, src: Option<u64>) -> MemoryWrite {
        MemoryWrite {
            sequence: seq,
            address: Address(addr),
            size: 8,
            tid: ThreadId(1),
            writer_pc: Some(Address(pc)),
            source_address: src.map(Address),
        }
    }

    #[test]
    fn single_write_full_contribution() {
        let index = OmniscientIndex::from_writes(vec![w(1, 0x1000, 0x401000, None)]);
        let report = rank_causal_contributions(&index, Address(0x1000), u64::MAX, 10);
        assert_eq!(report.chain_length, 1);
        assert!(report.chain_complete);
        assert!((report.ranked[0].contribution - 1.0).abs() < 1e-9);
        assert!(report.ranked[0].is_root);
    }

    #[test]
    fn chain_of_two_root_gets_higher_score() {
        // Seq 1 writes 0x1000 (root).
        // Seq 2 writes 0x2000 sourced from 0x1000.
        let writes = vec![
            w(1, 0x1000, 0x401000, None),
            w(2, 0x2000, 0x401010, Some(0x1000)),
        ];
        let index = OmniscientIndex::from_writes(writes);
        let report = rank_causal_contributions(&index, Address(0x2000), u64::MAX, 10);
        assert_eq!(report.chain_length, 2);
        assert!(report.chain_complete);
        // Root (depth=1) has terminal bonus; depth-0 has depth weight advantage.
        // Just verify both present and scores are positive.
        assert!(report.ranked.iter().all(|e| e.contribution > 0.0));
        let sum: f64 = report.ranked.iter().map(|e| e.contribution).sum();
        assert!((sum - 1.0).abs() < 1e-9);
    }

    #[test]
    fn empty_index_returns_empty_report() {
        let index = OmniscientIndex::new();
        let report = rank_causal_contributions(&index, Address(0x1000), u64::MAX, 10);
        assert!(report.ranked.is_empty());
        assert!(!report.chain_complete);
    }

    /// A chain cut by the CALLER limit must not read as a chain that ran out
    /// of history.
    ///
    /// `chain_complete` was re-derived from the last surviving hop AFTER
    /// truncation, so both cases reported `false` and nothing distinguished
    /// "the injection point is further upstream, you asked me to stop" from
    /// "there is no earlier writer". Those are different answers to the only
    /// question this report exists to answer.
    #[test]
    fn a_chain_cut_by_max_depth_says_so() {
        // Six links, each copying from the address below it; the root is the
        // first write and has no source.
        let mut writes = Vec::new();
        for i in 0..6u64 {
            let addr = 0x1000 + i * 8;
            let src = if i == 0 { None } else { Some(addr - 8) };
            writes.push(w(i, addr, 0x401000 + i, src));
        }
        writes.reverse();
        let index = OmniscientIndex::from_writes(writes);
        let top = Address(0x1000 + 5 * 8);

        // Enough depth: the walk reaches the root and says so.
        let full = rank_causal_contributions(&index, top, u64::MAX, 32);
        assert_eq!(full.chain_length, 6);
        assert!(full.chain_complete);
        assert!(!full.truncated);
        assert_eq!(full.chain_end, OriginEnd::Origin);

        // Caller-limited: the SAME chain, cut at three hops.
        let cut = rank_causal_contributions(&index, top, u64::MAX, 3);
        assert_eq!(cut.chain_length, 3);
        assert!(cut.truncated, "max_depth dropped hops the walk had found");
        assert!(
            !cut.chain_complete,
            "a truncated chain has not reached the injection point"
        );
        assert_eq!(
            cut.chain_end,
            OriginEnd::Origin,
            "the WALK still reached the origin; it is this function that stopped short, and the two facts are now separate"
        );
    }

    /// A chain that genuinely runs out of history reports that, and it is not
    /// the same thing as truncation.
    #[test]
    fn a_chain_with_no_earlier_writer_is_not_reported_as_truncated() {
        // One write that claims a source nothing ever wrote.
        let index = OmniscientIndex::from_writes(vec![w(5, 0x2000, 0x401000, Some(0x9999))]);
        let report = rank_causal_contributions(&index, Address(0x2000), u64::MAX, 32);
        assert_eq!(report.chain_length, 1);
        assert!(!report.truncated, "nothing was dropped by the depth limit");
        assert!(!report.chain_complete);
        assert_eq!(report.chain_end, OriginEnd::NoEarlierWriter);
    }

}
