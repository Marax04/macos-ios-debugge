//! Live invariant tracking — watch a memory address for a predicate violation.
//!
//! **What no other tool does**: WinDbg, GDB, x64dbg, and IDA all support hardware
//! watchpoints (trigger on write) but none support *expression-level invariants* —
//! the user specifies a constraint `value OP rhs` and the engine continuously
//! monitors the address across an entire recorded trace, returning every violation
//! and the instruction that caused it.  GDB's `watch (expr)` fires on any change;
//! it does not evaluate a predicate or scan history.  WinDbg TTD can query via
//! `dx @$curthread.TTD.Memory` but only returns raw writes, not invariant failures.
//! This module provides the predicate layer on top of an [`crate::omniscient_query::OmniscientIndex`].
//!
//! ## Usage
//! ```rust
//! use rustre_debug::live_invariant::{InvariantSpec, InvariantOp, InvariantEngine};
//! use rustre_debug::omniscient_query::{MemoryWrite, OmniscientIndex};
//! use rustre_core::address::Address;
//! use rustre_debug::ThreadId;
//!
//! let writes = vec![
//!     MemoryWrite { sequence: 1, address: Address(0x1000), size: 8,
//!                   tid: ThreadId(1), writer_pc: Some(Address(0x401000)),
//!                   source_address: None },
//! ];
//! let index = OmniscientIndex::from_writes(writes);
//! let spec = InvariantSpec {
//!     address: Address(0x1000),
//!     op: InvariantOp::Lt,
//!     rhs: 42,
//!     name: "counter_bounded".to_string(),
//! };
//! let engine = InvariantEngine::new(vec![spec]);
//! let violations = engine.check_against(&index);
//! ```

use std::collections::BTreeMap;

use rustre_core::address::Address;
use serde::{Deserialize, Serialize};

use crate::omniscient_query::{MemoryWrite, OmniscientIndex};

// ---------------------------------------------------------------------------
// Predicate types
// ---------------------------------------------------------------------------

/// Comparison operator for an invariant predicate.
///
/// The predicate is always: `observed_value OP rhs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantOp {
    /// Value must equal `rhs`.
    Eq,
    /// Value must differ from `rhs`.
    Ne,
    /// Value must be strictly less than `rhs`.
    Lt,
    /// Value must be less than or equal to `rhs`.
    Le,
    /// Value must be strictly greater than `rhs`.
    Gt,
    /// Value must be greater than or equal to `rhs`.
    Ge,
    /// Value AND `rhs` must be zero (all masked bits are clear).
    BitsClear,
    /// Value AND `rhs` must equal `rhs` (all masked bits are set).
    BitsSet,
    /// Value must not be zero (non-null pointer / flag active).
    NonZero,
    /// Value must be zero (null / cleared).
    IsZero,
}

impl InvariantOp {
    /// Evaluate `value OP rhs`, returning `true` if the invariant **holds**.
    #[must_use]
    pub const fn holds(&self, value: u64, rhs: u64) -> bool {
        match self {
            Self::Eq        => value == rhs,
            Self::Ne        => value != rhs,
            Self::Lt        => value < rhs,
            Self::Le        => value <= rhs,
            Self::Gt        => value > rhs,
            Self::Ge        => value >= rhs,
            Self::BitsClear => (value & rhs) == 0,
            Self::BitsSet   => (value & rhs) == rhs,
            Self::NonZero   => value != 0,
            Self::IsZero    => value == 0,
        }
    }
}

// ---------------------------------------------------------------------------
// InvariantSpec
// ---------------------------------------------------------------------------

/// The outcome of running an [`InvariantEngine`] over recorded writes.
///
/// `violations.is_empty()` alone never means the invariants hold: it means no
/// violation was found among the `checked_writes`. `unchecked_writes` is what
/// separates a clean run from one where the values were never available.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantReport {
    /// Violations found, in recording order.
    pub violations: Vec<Violation>,
    /// Writes actually evaluated.
    pub checked_writes: usize,
    /// Writes skipped because their stored value was not available.
    pub unchecked_writes: usize,
}

impl InvariantReport {
    /// Whether every matching write was evaluated.
    #[must_use]
    pub const fn is_conclusive(&self) -> bool {
        self.unchecked_writes == 0
    }
}
/// A named invariant to enforce on a memory address across a trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantSpec {
    /// Human-readable name, e.g. `"refcount_non_negative"`.
    pub name: String,
    /// The memory address to watch.
    pub address: Address,
    /// Predicate operator applied to each new value written there.
    pub op: InvariantOp,
    /// Right-hand side of the predicate (ignored by `NonZero`/`IsZero`).
    pub rhs: u64,
}

// ---------------------------------------------------------------------------
// Violation
// ---------------------------------------------------------------------------

/// A single invariant violation: the write that produced a value violating the
/// predicate, together with context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    /// Name of the invariant that was violated.
    pub invariant_name: String,
    /// The address that was watched.
    pub address: Address,
    /// The value written (8-byte representation of the write; partial writes
    /// are zero-extended to 8 bytes for comparison purposes).
    pub bad_value: u64,
    /// The expected relationship (e.g. `"Lt 42"`).
    pub expected: String,
    /// Write record that triggered the violation.
    pub write: MemoryWrite,
}

// ---------------------------------------------------------------------------
// InvariantEngine
// ---------------------------------------------------------------------------

/// Engine that checks a set of [`InvariantSpec`]s against an [`crate::omniscient_query::OmniscientIndex`].
///
/// Designed for offline use (post-record) over a replay index.  Real-time
/// enforcement (during live debugging) is done by registering the invariant as
/// a conditional watchpoint via [`crate::watchpoint_engine`] and evaluating the
/// predicate in the watchpoint callback — this engine is the offline analogue
/// that scans the entire recorded history in one pass.
#[derive(Debug, Default)]
pub struct InvariantEngine {
    specs: Vec<InvariantSpec>,
}

impl InvariantEngine {
    /// Create an engine with the given invariant specifications.
    #[must_use]
    pub const fn new(specs: Vec<InvariantSpec>) -> Self {
        Self { specs }
    }

    /// Add an invariant to the engine.
    pub fn add(&mut self, spec: InvariantSpec) {
        self.specs.push(spec);
    }

    /// Check every recorded write against the invariants.
    ///
    /// # This index does not carry values
    ///
    /// [`MemoryWrite`] is METADATA — sequence, address, size, tid, writer pc.
    /// It does not record the bytes that were written, and every operator here
    /// except none of them needs that value.
    ///
    /// This function used to invent one:
    /// `w.writer_pc.map(|a| a.as_u64()).unwrap_or(w.size)` — the program
    /// counter of the writing instruction, or failing that the WIDTH of the
    /// write. It then reported a fully formed `Violation`, naming the
    /// invariant and quoting the bad value, so `debug.invariant_check`
    /// serialised claims like "`refcount_non_negative` violated with value
    /// 0x401000" that were about nothing at all. Both directions were
    /// meaningless: the violations it reported and the silence when it
    /// reported none.
    ///
    /// Now it checks nothing it cannot check, and says how much that was.
    /// Use [`Self::check_against_with`] when the caller can supply the value,
    /// or [`Self::check_write`] on a live watchpoint hit.
    #[must_use]
    pub fn check_against(&self, index: &OmniscientIndex) -> InvariantReport {
        self.check_against_with(index, |_| None)
    }

    /// [`Self::check_against`], with a source for the value each write stored.
    ///
    /// A write whose value `value_of` cannot supply is COUNTED as unchecked
    /// rather than evaluated against a stand-in. An empty violation list plus
    /// a non-zero `unchecked_writes` means "I could not look", which is a
    /// different answer from "the invariants hold".
    #[must_use]
    pub fn check_against_with(
        &self,
        index: &OmniscientIndex,
        value_of: impl Fn(&MemoryWrite) -> Option<u64>,
    ) -> InvariantReport {
        let mut report = InvariantReport::default();
        for spec in &self.specs {
            let mut ordered: Vec<&MemoryWrite> = index.who_wrote(spec.address, u64::MAX);
            // `who_wrote` returns newest first; check in recording order.
            ordered.sort_by_key(|w| w.sequence);
            for w in ordered {
                let Some(value) = value_of(w) else {
                    report.unchecked_writes += 1;
                    continue;
                };
                report.checked_writes += 1;
                if !spec.op.holds(value, spec.rhs) {
                    report.violations.push(Violation {
                        invariant_name: spec.name.clone(),
                        address: spec.address,
                        bad_value: value,
                        expected: format!("{:?} {}", spec.op, spec.rhs),
                        write: w.clone(),
                    });
                }
            }
        }
        report.violations.sort_by_key(|v| v.write.sequence);
        report
    }
    /// Check a single write against all invariants and return any violations.
    ///
    /// Intended for real-time use: call on every watchpoint hit in a live
    /// debugging session to detect the exact moment an invariant breaks.
    #[must_use]
    pub fn check_write(&self, write: &MemoryWrite, value: u64) -> Vec<Violation> {
        self.specs
            .iter()
            .filter(|s| s.address == write.address)
            .filter(|s| !s.op.holds(value, s.rhs))
            .map(|s| Violation {
                invariant_name: s.name.clone(),
                address: s.address,
                bad_value: value,
                expected: format!("{:?} {}", s.op, s.rhs),
                write: write.clone(),
            })
            .collect()
    }

    /// Summarize check results: first-violation-per-invariant and total counts.
    #[must_use]
    pub fn summarize(violations: &[Violation]) -> BTreeMap<String, ViolationSummary> {
        let mut map: BTreeMap<String, ViolationSummary> = BTreeMap::new();
        for v in violations {
            let entry = map
                .entry(v.invariant_name.clone())
                .or_insert_with(|| ViolationSummary {
                    invariant_name: v.invariant_name.clone(),
                    total_violations: 0,
                    first_violation: v.clone(),
                });
            entry.total_violations += 1;
        }
        map
    }
}

/// Per-invariant summary from [`InvariantEngine::summarize`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationSummary {
    /// Name of the invariant.
    pub invariant_name: String,
    /// Total number of times the invariant was violated across the trace.
    pub total_violations: u64,
    /// The earliest violation.
    pub first_violation: Violation,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ThreadId;

    fn make_write(seq: u64, addr: u64, pc: u64) -> MemoryWrite {
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
    fn invariant_op_holds() {
        assert!(InvariantOp::Lt.holds(10, 100));
        assert!(!InvariantOp::Lt.holds(100, 10));
        assert!(InvariantOp::BitsSet.holds(0xFF, 0x0F));
        assert!(!InvariantOp::BitsSet.holds(0xF0, 0x0F));
        assert!(InvariantOp::NonZero.holds(1, 0));
        assert!(!InvariantOp::NonZero.holds(0, 0));
    }

    #[test]
    fn detects_violations_in_index() {
        // The value each write stored, supplied by the caller — the engine
        // itself has no access to it (see `check_against`).
        let writes = vec![
            make_write(1, 0x1000, 5),
            make_write(2, 0x1000, 200),
            make_write(3, 0x1000, 50),
        ];
        let index = OmniscientIndex::from_writes(writes);
        let spec = InvariantSpec {
            name: "bounded".to_string(),
            address: Address(0x1000),
            op: InvariantOp::Lt,
            rhs: 100,
        };
        let engine = InvariantEngine::new(vec![spec]);
        let report = engine
            .check_against_with(&index, |w| w.writer_pc.map(rustre_core::Address::as_u64));
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].write.sequence, 2);
        assert_eq!(report.violations[0].bad_value, 200);
        assert_eq!(report.checked_writes, 3);
        assert!(report.is_conclusive());
    }

    /// Without values the engine must report that it could not check, never
    /// an empty violation list that reads as a clean bill of health.
    ///
    /// `check_against` used to invent the value: the writing instruction's PC,
    /// or failing that the WIDTH of the write. It then produced fully formed
    /// violations naming the invariant and quoting the bad value, so
    /// `debug.invariant_check` reported claims like "`refcount_non_negative`
    /// violated with value 0x401000" that were about nothing at all — and its
    /// silence, when it was silent, was worth exactly as little.
    #[test]
    fn without_values_the_check_is_inconclusive_not_clean() {
        let writes = vec![
            make_write(1, 0x1000, 0x0040_1000),
            make_write(2, 0x1000, 0x0040_1010),
        ];
        let index = OmniscientIndex::from_writes(writes);
        let engine = InvariantEngine::new(vec![InvariantSpec {
            name: "never_zero".to_string(),
            address: Address(0x1000),
            op: InvariantOp::IsZero,
            rhs: 0,
        }]);
        let report = engine.check_against(&index);
        assert!(report.violations.is_empty(), "nothing was evaluated, so nothing can be a violation");
        assert_eq!(report.checked_writes, 0);
        assert_eq!(report.unchecked_writes, 2);
        assert!(
            !report.is_conclusive(),
            "an empty violation list without values must not read as the invariants holding"
        );
    }

    #[test]
    fn summary_counts_correctly() {
        let w = make_write(1, 0x1000, 200);
        let v = Violation {
            invariant_name: "inv".to_string(),
            address: Address(0x1000),
            bad_value: 200,
            expected: "Lt 100".to_string(),
            write: w,
        };
        let violations = vec![v.clone(), v];
        let summary = InvariantEngine::summarize(&violations);
        assert_eq!(summary["inv"].total_violations, 2);
    }
}
