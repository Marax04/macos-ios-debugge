//! Semantic diff between two execution traces.
//!
//! **What no other tool does**: WinDbg TTD, rr, x64dbg, and IDA can each replay
//! *one* trace.  None of them compare two traces and answer "at exactly which
//! instruction did the two executions diverge, and what was the value difference?"
//! Chronon's differential debugging (academic) is the closest prior work but is
//! not available in any shipping debugger.  This module provides a practical
//! equivalent over two [`crate::omniscient_query::OmniscientIndex`] traces.
//!
//! ## Algorithm
//! 1. Build a sequence-aligned view of writes to every address that appears in
//!    *either* trace.
//! 2. For each address, find the minimum sequence number at which the value
//!    (proxied by writer PC, since `MemoryWrite` doesn't carry payload bytes yet)
//!    differs between the two traces.
//! 3. Return a [`RunDiff`] containing the globally earliest divergence event plus
//!    a per-address breakdown sorted by divergence time.
//!
//! When `MemoryWrite` gains a `value: u64` field (planned), replace the PC proxy
//! with the actual written value — the algorithm is identical.

use std::collections::BTreeSet;

use rustre_core::address::Address;
use serde::{Deserialize, Serialize};

use crate::omniscient_query::{MemoryWrite, OmniscientIndex};

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// One divergence point between two runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergencePoint {
    /// Memory address where the divergence was observed.
    pub address: Address,
    /// Sequence number of the earliest write in either trace that differs
    /// between the two runs for this address.
    pub sequence: u64,
    /// Writer PC in the first (reference) trace at this point, if any.
    pub pc_run_a: Option<Address>,
    /// Writer PC in the second trace at this point, if any.
    pub pc_run_b: Option<Address>,
    /// `true` if the address was written in run A but *not* run B at this
    /// sequence number (one-sided write — the other run hadn't written yet).
    pub one_sided: bool,
}

/// Full semantic diff between two recorded runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunDiff {
    /// The globally earliest divergence point across all addresses, i.e. the
    /// single instruction that "first caused" the two runs to diverge.
    pub first_divergence: Option<DivergencePoint>,
    /// All divergence points, one per address, sorted ascending by sequence.
    pub divergences: Vec<DivergencePoint>,
    /// Addresses written in run A but never in run B.
    pub only_in_a: Vec<Address>,
    /// Addresses written in run B but never in run A.
    pub only_in_b: Vec<Address>,
    /// Total addresses examined.
    pub total_addresses: usize,
    /// Addresses where the two runs could not be compared at all, because the
    /// writes on both sides carry no writer pc.
    ///
    /// Those addresses produce no divergence — not because the runs agree, but
    /// because there is nothing to compare. Counting them is what separates
    /// "the runs match here" from "I could not tell". Without it, a trace
    /// recorded without pcs diffs as a perfect match against any other.
    pub inconclusive_addresses: usize,
}

impl RunDiff {
    /// Whether every examined address could actually be compared.
    ///
    /// `false` means `divergences` is a floor: the two runs may differ at an
    /// address this diff had no evidence about.
    #[must_use]
    pub const fn is_conclusive(&self) -> bool {
        self.inconclusive_addresses == 0
    }
}

// ---------------------------------------------------------------------------
// Core diff computation
// ---------------------------------------------------------------------------

/// Compute the semantic diff between `trace_a` (reference / good run) and
/// `trace_b` (second run).
///
/// Returns a [`RunDiff`] describing where and when the two traces diverged.
#[must_use]
pub fn diff_runs(trace_a: &OmniscientIndex, trace_b: &OmniscientIndex) -> RunDiff {
    // Collect all addresses present in either trace.
    let addrs_a: BTreeSet<Address> = trace_a.all_addresses().into_iter().collect();
    let addrs_b: BTreeSet<Address> = trace_b.all_addresses().into_iter().collect();

    let only_in_a: Vec<Address> = addrs_a.difference(&addrs_b).copied().collect();
    let only_in_b: Vec<Address> = addrs_b.difference(&addrs_a).copied().collect();

    let all_addrs: BTreeSet<Address> = addrs_a.union(&addrs_b).copied().collect();
    let total_addresses = all_addrs.len();

    let mut divergences: Vec<DivergencePoint> = Vec::new();
    let mut inconclusive_addresses = 0usize;

    for &addr in &all_addrs {
        // Writes sorted ascending by sequence.
        let mut wa: Vec<&MemoryWrite> = trace_a.who_wrote(addr, u64::MAX);
        let mut wb: Vec<&MemoryWrite> = trace_b.who_wrote(addr, u64::MAX);
        wa.sort_by_key(|w| w.sequence);
        wb.sort_by_key(|w| w.sequence);

        // Build sequence-aligned comparison: for each write in A, find the
        // write with the same ordinal position in B (same "nth write to this
        // address").  This is a positional diff, not a timestamp diff, which
        // is meaningful when the two runs have shifted clocks but identical
        // logic up to a point.
        let len = wa.len().max(wb.len());
        for i in 0..len {
            match (wa.get(i), wb.get(i)) {
                (Some(a), Some(b)) => {
                    let pc_a = a.writer_pc;
                    let pc_b = b.writer_pc;
                    // Two writes with no recorded pc on EITHER side used to
                    // compare equal (`None != None` is false) and the address
                    // was reported as agreeing. Absence of evidence was read as
                    // evidence of sameness — so a trace recorded without pcs
                    // diffed as a perfect match against any other run.
                    if pc_a.is_none() && pc_b.is_none() {
                        inconclusive_addresses += 1;
                        break;
                    }
                    // Identity is more than the pc. The same instruction
                    // writing the same location from a DIFFERENT THREAD, or
                    // writing a different WIDTH, is exactly the kind of
                    // divergence this tool exists to find, and comparing pcs
                    // alone called both cases identical.
                    if (pc_a, a.tid, a.size) != (pc_b, b.tid, b.size) {
                        divergences.push(DivergencePoint {
                            address: addr,
                            sequence: a.sequence.min(b.sequence),
                            pc_run_a: pc_a,
                            pc_run_b: pc_b,
                            one_sided: false,
                        });
                        break; // first divergence per address is enough
                    }
                }
                (Some(a), None) => {
                    divergences.push(DivergencePoint {
                        address: addr,
                        sequence: a.sequence,
                        pc_run_a: a.writer_pc,
                        pc_run_b: None,
                        one_sided: true,
                    });
                    break;
                }
                (None, Some(b)) => {
                    divergences.push(DivergencePoint {
                        address: addr,
                        sequence: b.sequence,
                        pc_run_a: None,
                        pc_run_b: b.writer_pc,
                        one_sided: true,
                    });
                    break;
                }
                (None, None) => break,
            }
        }
    }

    divergences.sort_by_key(|d| d.sequence);
    let first_divergence = divergences.first().cloned();

    RunDiff {
        first_divergence,
        divergences,
        only_in_a,
        only_in_b,
        total_addresses,
        inconclusive_addresses,
    }
}

/// Build a timeline of writes to a specific address from both traces, suitable
/// for displaying a side-by-side comparison.
#[must_use]
pub fn address_timeline(
    addr: Address,
    trace_a: &OmniscientIndex,
    trace_b: &OmniscientIndex,
) -> Vec<TimelineRow> {
    let mut wa: Vec<&MemoryWrite> = trace_a.who_wrote(addr, u64::MAX);
    let mut wb: Vec<&MemoryWrite> = trace_b.who_wrote(addr, u64::MAX);
    wa.sort_by_key(|w| w.sequence);
    wb.sort_by_key(|w| w.sequence);

    let len = wa.len().max(wb.len());
    (0..len)
        .map(|i| TimelineRow {
            ordinal: i as u64,
            run_a: wa.get(i).map(|&w| w.clone()),
            run_b: wb.get(i).map(|&w| w.clone()),
            diverges: {
                match (wa.get(i), wb.get(i)) {
                    (Some(a), Some(b)) => a.writer_pc != b.writer_pc,
                    (Some(_), None) | (None, Some(_)) => true,
                    _ => false,
                }
            },
        })
        .collect()
}

/// One row in an [`address_timeline`] result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineRow {
    /// Zero-based ordinal (nth write to this address).
    pub ordinal: u64,
    /// Write from run A at this position, if any.
    pub run_a: Option<MemoryWrite>,
    /// Write from run B at this position, if any.
    pub run_b: Option<MemoryWrite>,
    /// `true` if this row represents a divergence.
    pub diverges: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ThreadId;

    fn w(seq: u64, addr: u64, pc: u64) -> MemoryWrite {
        MemoryWrite {
            sequence: seq,
            address: Address(addr),
            size: 8,
            tid: ThreadId(1),
            writer_pc: Some(Address(pc)),
            source_address: None,
        }
    }

    #[test]
    fn identical_runs_no_divergence() {
        let writes = vec![w(1, 0x1000, 0x401000), w(2, 0x2000, 0x401010)];
        let a = OmniscientIndex::from_writes(writes.clone());
        let b = OmniscientIndex::from_writes(writes);
        let diff = diff_runs(&a, &b);
        assert!(diff.first_divergence.is_none());
        assert!(diff.divergences.is_empty());
    }

    #[test]
    fn detects_pc_divergence() {
        let a = OmniscientIndex::from_writes(vec![w(1, 0x1000, 0x401000)]);
        let b = OmniscientIndex::from_writes(vec![w(1, 0x1000, 0x402000)]);
        let diff = diff_runs(&a, &b);
        assert!(diff.first_divergence.is_some());
        let dp = diff.first_divergence.unwrap();
        assert_eq!(dp.address, Address(0x1000));
        assert_eq!(dp.pc_run_a, Some(Address(0x401000)));
        assert_eq!(dp.pc_run_b, Some(Address(0x402000)));
    }

    #[test]
    fn detects_one_sided_write() {
        let a = OmniscientIndex::from_writes(vec![w(1, 0x1000, 0x401000), w(2, 0x1000, 0x401010)]);
        let b = OmniscientIndex::from_writes(vec![w(1, 0x1000, 0x401000)]);
        let diff = diff_runs(&a, &b);
        assert!(diff.first_divergence.is_some());
        assert!(diff.first_divergence.unwrap().one_sided);
    }

    fn w_full(seq: u64, addr: u64, pc: Option<u64>, tid: u32, size: u64) -> MemoryWrite {
        MemoryWrite {
            sequence: seq,
            address: Address(addr),
            size,
            tid: ThreadId(tid),
            writer_pc: pc.map(Address),
            source_address: None,
        }
    }

    /// Two writes with no recorded pc are NOT evidence that the runs agree.
    ///
    /// The comparison was `pc_a != pc_b`, and `None != None` is false, so an
    /// address written without a recorded pc in both runs was reported as
    /// matching. A trace recorded without pcs therefore diffed as a perfect
    /// match against any other run - absence of evidence read as evidence of
    /// sameness.
    #[test]
    fn writes_with_no_recorded_pc_are_inconclusive_not_equal() {
        let a = OmniscientIndex::from_writes(vec![w_full(1, 0x1000, None, 1, 8)]);
        let b = OmniscientIndex::from_writes(vec![w_full(1, 0x1000, None, 1, 8)]);
        let diff = diff_runs(&a, &b);
        assert!(diff.divergences.is_empty(), "nothing was compared, so nothing can diverge");
        assert_eq!(diff.inconclusive_addresses, 1);
        assert!(
            !diff.is_conclusive(),
            "an empty divergence list with nothing comparable must not read as the runs matching"
        );

        // With pcs on both sides the same diff IS conclusive, so the flag is
        // not a constant.
        let a = OmniscientIndex::from_writes(vec![w(1, 0x1000, 0x401000)]);
        let b = OmniscientIndex::from_writes(vec![w(1, 0x1000, 0x401000)]);
        let diff = diff_runs(&a, &b);
        assert!(diff.is_conclusive());
        assert!(diff.divergences.is_empty());
    }

    /// The same instruction writing the same address from a DIFFERENT THREAD,
    /// or writing a different width, is a divergence.
    ///
    /// Only the pc was compared, so a race that shows up as a different thread
    /// performing the write was reported as identical - in a tool whose whole
    /// purpose is answering "why did these two runs differ".
    #[test]
    fn a_write_from_another_thread_or_of_another_width_is_a_divergence() {
        let a = OmniscientIndex::from_writes(vec![w_full(1, 0x1000, Some(0x401000), 1, 8)]);
        let b = OmniscientIndex::from_writes(vec![w_full(1, 0x1000, Some(0x401000), 2, 8)]);
        let diff = diff_runs(&a, &b);
        assert_eq!(diff.divergences.len(), 1, "a different thread wrote it: that is a divergence");
        assert!(diff.is_conclusive());

        let a = OmniscientIndex::from_writes(vec![w_full(1, 0x2000, Some(0x401000), 1, 4)]);
        let b = OmniscientIndex::from_writes(vec![w_full(1, 0x2000, Some(0x401000), 1, 8)]);
        let diff = diff_runs(&a, &b);
        assert_eq!(diff.divergences.len(), 1, "a different width is a different write");
    }

}
