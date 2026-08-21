//! Race-condition/concurrency replay (Tier 3, item 10 of `rustre_debug_enhancement_plan.md`).
//!
//! Post-hoc, ThreadSanitizer-style conflict detection over a recorded trace: given
//! a chronological list of memory accesses tagged with thread ID, flag every pair
//! of accesses from *different* threads that touch overlapping memory where at
//! least one is a write. Unlike TSan this has no happens-before/lockset model (the
//! recording layer this crate has today — [`crate::debug_session_recorder`] /
//! [`crate::omniscient_query`] — does not capture lock acquire/release events), so
//! every flagged pair is a *candidate* race: a genuinely racy access, or a pair
//! correctly ordered by a lock/atomic this detector can't see. Report accordingly —
//! this narrows a huge trace down to a short list for a human (or the causal-slice
//! tooling in [`crate::root_cause_assistant`]) to check by hand.

use rustre_core::address::Address;

use crate::ThreadId;

/// Whether a recorded memory access was a read or a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AccessKind {
    Read,
    Write,
}

/// One recorded memory access, thread-tagged, for race detection.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemoryAccess {
    /// Sequence number in the recorded trace (chronological order).
    pub sequence: u64,
    pub address: Address,
    pub size: u64,
    pub tid: ThreadId,
    pub kind: AccessKind,
}

impl MemoryAccess {
    const fn end(&self) -> u64 {
        self.address.as_u64().saturating_add(self.size)
    }

    /// Exact interval intersection, without ever materialising an end address.
    ///
    /// `end()` saturates, so for an access touching the last bytes of the
    /// address space it reports `u64::MAX` where the true end is `u64::MAX + 1`.
    /// The strict `<` comparisons then miss an overlap that is real: a race on
    /// the final byte of memory went unreported. Comparing the OFFSET between
    /// the two starts is exact everywhere and cannot overflow — the same
    /// correction made for `Symbol::contains` and the watchpoint coverage test
    /// in iter 273, which is where this shape was first found.
    const fn overlaps(&self, other: &Self) -> bool {
        let (a, b) = (self.address.as_u64(), other.address.as_u64());
        if a <= b {
            b - a < self.size
        } else {
            a - b < other.size
        }
    }
}

/// A candidate data race: two accesses from different threads to overlapping
/// memory, with no ordering information available, where at least one is a write.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RaceCandidate {
    pub first: MemoryAccess,
    pub second: MemoryAccess,
}

impl RaceCandidate {
    /// `true` if both accesses are writes (write/write races are unconditionally
    /// racy regardless of any missing synchronization info — never benign).
    #[must_use]
    pub fn is_write_write(&self) -> bool {
        self.first.kind == AccessKind::Write && self.second.kind == AccessKind::Write
    }
}

/// Scan a chronological access trace for candidate races: pairs of accesses
/// from different threads that touch overlapping memory where at least one is
/// a write. `O(n^2)` in the number of accesses — intended for the size of
/// trace a debugging session records around a suspected race, not a whole
/// unbounded execution.
#[must_use]
pub fn detect_races(accesses: &[MemoryAccess]) -> Vec<RaceCandidate> {
    let mut races = Vec::new();
    for i in 0..accesses.len() {
        for j in (i + 1)..accesses.len() {
            let a = &accesses[i];
            let b = &accesses[j];
            if a.tid == b.tid {
                continue;
            }
            if a.kind == AccessKind::Read && b.kind == AccessKind::Read {
                continue;
            }
            if a.overlaps(b) {
                // Order the pair by `sequence`, not by position in the slice.
                // The slice is only chronological if the caller made it so, and
                // a trace assembled from per-thread buffers is not; reporting
                // the later access as `first` inverts cause and effect in the
                // one place the reader is looking for it.
                let (first, second) = if a.sequence <= b.sequence { (a, b) } else { (b, a) };
                races.push(RaceCandidate { first: first.clone(), second: second.clone() });
            }
        }
    }
    // Deterministic, chronological order.
    races.sort_by(|x, y| x.first.sequence.cmp(&y.first.sequence).then(x.second.sequence.cmp(&y.second.sequence)));
    races
}

/// Write/write races only — the subset of [`detect_races`]'s output that is
/// racy no matter what synchronization this detector can't see (two threads
/// cannot both correctly hold exclusive access to the same location).
#[must_use]
pub fn detect_write_write_races(accesses: &[MemoryAccess]) -> Vec<RaceCandidate> {
    detect_races(accesses).into_iter().filter(RaceCandidate::is_write_write).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(seq: u64, addr: u64, size: u64, tid: u32, kind: AccessKind) -> MemoryAccess {
        MemoryAccess { sequence: seq, address: Address(addr), size, tid: ThreadId(tid), kind }
    }

    /// `first` must be the access that happened FIRST, by sequence number.
    ///
    /// Pairs were built from array order, not from `sequence`, so the field
    /// that exists precisely to carry chronological order was ignored. A trace
    /// assembled by concatenating per-thread buffers — which is how a recorder
    /// naturally collects them, and what `scripting_api` forwards straight from
    /// a script — is not sorted by sequence, and the report then claimed the
    /// later access happened first. For a race report that inverts cause and
    /// effect, which is the one thing the reader is trying to establish.
    #[test]
    fn first_is_the_chronologically_earlier_access() {
        // Thread 2's write (sequence 10) really happened AFTER thread 1's read
        // (sequence 5), but is listed earlier in the slice.
        let accesses = vec![
            access(10, 0x1000, 4, 2, AccessKind::Write),
            access(5, 0x1000, 4, 1, AccessKind::Read),
        ];
        let races = detect_races(&accesses);
        assert_eq!(races.len(), 1, "one overlapping read/write pair");
        assert_eq!(
            (races[0].first.sequence, races[0].second.sequence),
            (5, 10),
            "first/second must follow sequence order, not slice order"
        );

        // Already-ordered input must keep behaving exactly as before.
        let ordered = vec![
            access(5, 0x1000, 4, 1, AccessKind::Read),
            access(10, 0x1000, 4, 2, AccessKind::Write),
        ];
        let races = detect_races(&ordered);
        assert_eq!((races[0].first.sequence, races[0].second.sequence), (5, 10));
    }

    #[test]
    fn flags_write_write_race_across_threads() {
        let a = access(0, 0x1000, 4, 1, AccessKind::Write);
        let b = access(1, 0x1000, 4, 2, AccessKind::Write);
        let races = detect_races(&[a, b]);
        assert_eq!(races.len(), 1);
        assert!(races[0].is_write_write());
    }

    #[test]
    fn flags_read_write_race_across_threads() {
        let a = access(0, 0x1000, 4, 1, AccessKind::Read);
        let b = access(1, 0x1000, 4, 2, AccessKind::Write);
        let races = detect_races(&[a, b]);
        assert_eq!(races.len(), 1);
        assert!(!races[0].is_write_write());
    }

    #[test]
    fn ignores_read_read_pairs() {
        let a = access(0, 0x1000, 4, 1, AccessKind::Read);
        let b = access(1, 0x1000, 4, 2, AccessKind::Read);
        assert!(detect_races(&[a, b]).is_empty());
    }

    #[test]
    fn ignores_same_thread_accesses() {
        let a = access(0, 0x1000, 4, 1, AccessKind::Write);
        let b = access(1, 0x1000, 4, 1, AccessKind::Write);
        assert!(detect_races(&[a, b]).is_empty());
    }

    #[test]
    fn ignores_non_overlapping_addresses() {
        let a = access(0, 0x1000, 4, 1, AccessKind::Write);
        let b = access(1, 0x2000, 4, 2, AccessKind::Write);
        assert!(detect_races(&[a, b]).is_empty());
    }

    /// A race on the last bytes of the address space must still be reported.
    ///
    /// `end()` saturates, so an access that runs to the very top reported
    /// `u64::MAX` as its end where the true end is one past it. The strict `<`
    /// in the old `overlaps` then denied a real overlap, and the race went
    /// unreported — a MISSED race, which is the failure a race detector cannot
    /// afford: a false positive gets argued about, a false negative is never
    /// even seen. Kernel-space addresses live exactly here.
    ///
    /// Same shape as `Symbol::contains` and the watchpoint coverage check
    /// corrected in iter 273: whenever a range can touch `u64::MAX`, do not
    /// materialise its end.
    #[test]
    fn a_race_on_the_last_byte_of_memory_is_not_missed() {
        let top = u64::MAX; // one byte, at the very end
        let accesses = vec![
            access(1, top, 1, 1, AccessKind::Write),
            access(2, top, 1, 2, AccessKind::Read),
        ];
        assert_eq!(
            detect_races(&accesses).len(),
            1,
            "a write/read race on the final byte of memory was not reported"
        );

        // And two genuinely disjoint accesses at the top are still not a race.
        let disjoint = vec![
            access(1, top - 1, 1, 1, AccessKind::Write),
            access(2, top, 1, 2, AccessKind::Write),
        ];
        assert!(
            detect_races(&disjoint).is_empty(),
            "adjacent, non-overlapping accesses must not be flagged"
        );
    }

    #[test]
    fn partial_overlap_still_flagged() {
        let a = access(0, 0x1000, 8, 1, AccessKind::Write);
        let b = access(1, 0x1004, 8, 2, AccessKind::Read);
        assert_eq!(detect_races(&[a, b]).len(), 1);
    }

    #[test]
    fn write_write_filter_excludes_read_write() {
        let a = access(0, 0x1000, 4, 1, AccessKind::Read);
        let b = access(1, 0x1000, 4, 2, AccessKind::Write);
        let c = access(2, 0x1000, 4, 3, AccessKind::Write);
        let races = detect_write_write_races(&[a, b, c]);
        assert!(!races.is_empty());
        assert!(races.iter().all(RaceCandidate::is_write_write));
    }

    #[test]
    fn results_are_chronologically_ordered() {
        // This test previously asserted the opposite of its own name: given
        // sequences 5 and 0 passed in that slice order, it required `first` to
        // be sequence 5 — i.e. it froze the array-order behaviour that inverted
        // cause and effect. Its name and its comment both say chronological, so
        // what it should pin down is: (a) each pair is ordered by sequence, and
        // (b) the LIST is sorted by (first.sequence, second.sequence), which
        // needs more than one candidate to mean anything.
        let a = access(5, 0x1000, 4, 1, AccessKind::Write);
        let b = access(0, 0x1000, 4, 2, AccessKind::Write);
        let c = access(9, 0x1000, 4, 3, AccessKind::Write);
        let races = detect_races(&[a, b, c]);

        // Every pair is internally ordered by sequence.
        for r in &races {
            assert!(
                r.first.sequence <= r.second.sequence,
                "pair {:?}/{:?} is not in chronological order",
                r.first.sequence,
                r.second.sequence
            );
        }
        // ...and the list itself is sorted by (first.sequence, second.sequence).
        let keys: Vec<(u64, u64)> = races.iter().map(|r| (r.first.sequence, r.second.sequence)).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "candidates are not listed chronologically");
        assert_eq!(keys, vec![(0, 5), (0, 9), (5, 9)]);
    }
}
