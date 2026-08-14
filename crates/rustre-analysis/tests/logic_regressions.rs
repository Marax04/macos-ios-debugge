//! Regression tests for logic defects found by the wave-1 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact output the audit predicted.

use rustre_analysis::analysis_index::{FunctionEntry, FunctionIndex};

fn entry(start: u64, len: u64, name: &str) -> FunctionEntry {
    FunctionEntry::new(start, len, Some(name.to_string()))
}

/// Only the single nearest preceding function start was tested, so an address
/// covered by an earlier, LONGER function was reported as belonging to no
/// function at all. A short thunk sitting inside a large function is enough to
/// hide the whole rest of that function from the index.
#[test]
fn an_enclosing_function_is_found_past_a_shorter_one() {
    let mut idx = FunctionIndex::default();
    idx.insert(entry(0x1000, 0x100, "outer")); // 0x1000..0x1100
    idx.insert(entry(0x1010, 0x4, "thunk")); // 0x1010..0x1014

    // Inside the thunk: the thunk wins (it is the tightest match).
    assert_eq!(
        idx.find_containing(0x1012).and_then(|e| e.name.clone()),
        Some("thunk".to_string())
    );

    // Past the thunk but still inside `outer`: the nearest preceding start is
    // the thunk, which does NOT contain this address — but `outer` does.
    assert_eq!(
        idx.find_containing(0x1050).and_then(|e| e.name.clone()),
        Some("outer".to_string()),
        "0x1050 lies inside outer (0x1000..0x1100)"
    );
}

/// Every address inside a function must resolve to it, whatever else is
/// indexed nearby.
#[test]
fn every_address_inside_the_outer_function_resolves() {
    let mut idx = FunctionIndex::default();
    idx.insert(entry(0x2000, 0x80, "big"));
    idx.insert(entry(0x2008, 0x8, "inner_a"));
    idx.insert(entry(0x2020, 0x8, "inner_b"));

    for addr in [0x2000u64, 0x2007, 0x2018, 0x2040, 0x207F] {
        let got = idx.find_containing(addr).and_then(|e| e.name.clone());
        assert!(
            got.is_some(),
            "{addr:#x} is inside big (0x2000..0x2080) but resolved to nothing"
        );
    }
}

/// Addresses genuinely outside every function must still resolve to nothing.
/// The fix must not turn "search further back" into "return whatever is
/// closest".
#[test]
fn addresses_outside_every_function_stay_unresolved() {
    let mut idx = FunctionIndex::default();
    idx.insert(entry(0x1000, 0x10, "a"));
    idx.insert(entry(0x2000, 0x10, "b"));

    assert!(idx.find_containing(0x0FFF).is_none(), "before everything");
    assert!(idx.find_containing(0x1010).is_none(), "in the gap after a");
    assert!(idx.find_containing(0x1FFF).is_none(), "in the gap before b");
    assert!(idx.find_containing(0x2010).is_none(), "past the last function");
}

/// A zero-length entry means "unknown length" and deliberately matches later
/// addresses. That is existing behaviour and must be preserved.
#[test]
fn zero_length_entries_keep_matching_forward() {
    let mut idx = FunctionIndex::default();
    idx.insert(FunctionEntry::new(0x3000, 0, None));
    assert!(idx.find_containing(0x3000).is_some());
    assert!(idx.find_containing(0x3FFF).is_some());
}

// ── ControlFlowAnalysis: reducibility ──────────────────────────────────────

use rustre_analysis::control_flow_analysis::{ControlFlowAnalysis, ILInstr};

/// `is_reducible` re-checked the very property `BackEdgeDetector::detect` uses
/// to select its edges — that the target dominates the source — so it was
/// vacuously true for every CFG ever analysed, including irreducible ones.
///
/// The classic two-entry loop: block 0 branches to both 1 and 2, and 1 and 2
/// jump to each other. Neither dominates the other, so the cycle has two
/// entries and the CFG is irreducible by definition.
#[test]
fn a_two_entry_loop_is_reported_irreducible() {
    let (_, _, bed, _, result) = ControlFlowAnalysis::run(
        3,
        vec![
            (
                0,
                ILInstr::CondJump {
                    cond: "c".to_string(),
                    true_target: 1,
                    false_target: 2,
                },
            ),
            (1, ILInstr::Jump { target: 2 }),
            (2, ILInstr::Jump { target: 1 }),
        ],
    );

    // The cycle 1 ⇄ 2 has no dominating header, so nothing qualifies as a
    // back edge — which is exactly why the old check had nothing to reject.
    assert!(
        bed.back_edges.is_empty(),
        "neither 1 nor 2 dominates the other, so there is no back edge: {:?}",
        bed.back_edges
    );
    assert!(
        !result.is_reducible,
        "a two-entry loop is irreducible; reporting it reducible makes the \
         flag meaningless"
    );
}

/// A well-structured loop must still be reported reducible — the fix must not
/// simply invert the answer.
#[test]
fn a_natural_loop_is_still_reducible() {
    let (_, _, bed, _, result) = ControlFlowAnalysis::run(
        3,
        vec![
            (0, ILInstr::Jump { target: 1 }),
            (
                1,
                ILInstr::CondJump {
                    cond: "c".to_string(),
                    true_target: 2,
                    false_target: 1,
                },
            ),
            (2, ILInstr::Ret),
        ],
    );

    assert!(
        !bed.back_edges.is_empty(),
        "1 → 1 is a genuine back edge"
    );
    assert!(result.is_reducible, "a single-entry loop is reducible");
}

/// Straight-line code has no cycles at all and is trivially reducible.
#[test]
fn acyclic_code_is_reducible() {
    let (_, _, _, _, result) = ControlFlowAnalysis::run(
        2,
        vec![(0, ILInstr::Jump { target: 1 }), (1, ILInstr::Ret)],
    );
    assert!(result.is_reducible);
}

// ── VulnerabilityScanner::scan_all: duplicate findings ─────────────────────

use rustre_analysis::vulnerability_scanner::{CallRecord, VulnType, VulnerabilityScanner};

fn call(addr: u64, callee: &str, tainted: bool) -> CallRecord {
    CallRecord {
        call_addr: addr,
        callee: callee.to_string(),
        format_arg_tainted: tainted,
        arg_count: 3,
    }
}

/// printf/fprintf/snprintf are listed BOTH in the hard-coded `format_sinks`
/// of `scan_for_format_string` and in `dangerous_functions()`, so a single
/// tainted call site produced two records of the same `FormatString` type —
/// and for snprintf with two DIFFERENT severities, inflating both the high and
/// the medium counters for one bug.
#[test]
fn one_tainted_format_call_yields_one_finding() {
    for callee in ["printf", "fprintf", "snprintf"] {
        let mut s = VulnerabilityScanner::default();
        let report = s.scan_all(&[call(0x401000, callee, true)], &[]);

        let fmt: Vec<_> = report
            .vulns
            .iter()
            .filter(|v| v.vuln_type == VulnType::FormatString)
            .collect();
        assert_eq!(
            fmt.len(),
            1,
            "{callee}: one call site must produce one FormatString finding, got {fmt:#?}"
        );

        let counted = report.total_critical
            + report.total_high
            + report.total_medium
            + report.total_low
            + report.total_info;
        assert_eq!(
            counted, 1,
            "{callee}: the severity counters must add up to one finding, \
             got critical={} high={} medium={} low={} info={}",
            report.total_critical,
            report.total_high,
            report.total_medium,
            report.total_low,
            report.total_info
        );
    }
}

/// A genuinely distinct finding at the same address must survive: `sprintf` is
/// flagged as an unconditional BufferOverflow, which is not the same defect as
/// a tainted format string.
#[test]
fn distinct_vulnerability_types_at_one_address_are_kept() {
    let mut s = VulnerabilityScanner::default();
    let report = s.scan_all(&[call(0x402000, "sprintf", true)], &[]);
    assert!(
        report
            .vulns
            .iter()
            .any(|v| v.vuln_type == VulnType::BufferOverflow),
        "sprintf must still be reported as a buffer overflow"
    );
}

/// Two different call sites of the same function are two different bugs.
#[test]
fn separate_call_sites_stay_separate() {
    let mut s = VulnerabilityScanner::default();
    let report = s.scan_all(
        &[call(0x401000, "printf", true), call(0x401100, "printf", true)],
        &[],
    );
    let addrs: std::collections::HashSet<u64> = report
        .vulns
        .iter()
        .filter(|v| v.vuln_type == VulnType::FormatString)
        .map(|v| v.location)
        .collect();
    assert_eq!(addrs.len(), 2, "two call sites, two findings");
}

// ── CallGraph::bottom_up_order: determinism ────────────────────────────────

use rustre_analysis::interprocedural_analysis::{CallGraph, CallSite, FunctionId};

/// Roots come from a `HashSet` and callees are funnelled through another, so
/// the traversal order — and hence the order in which the summary database is
/// populated — varied between processes for identical input. Analyses that are
/// order-sensitive then produce different results run to run.
///
/// Eight isolated functions: matching sorted order by accident is 1 in 40320.
#[test]
fn bottom_up_order_is_deterministic_for_isolated_functions() {
    let addrs = [0x80u64, 0x10, 0x50, 0x20, 0x70, 0x30, 0x60, 0x40];
    let mut cg = CallGraph::new();
    for &a in &addrs {
        cg.add_function(FunctionId::new(a));
    }

    let order: Vec<u64> = cg.bottom_up_order().into_iter().map(|f| f.0).collect();
    let mut expected = addrs.to_vec();
    expected.sort_unstable();
    assert_eq!(
        order, expected,
        "the traversal must not depend on hash iteration order"
    );
}

/// Callees of one caller must also come out in a stable order.
#[test]
fn callees_are_visited_in_a_stable_order() {
    let mut cg = CallGraph::new();
    let root = FunctionId::new(0x100);
    cg.add_function(root);
    let callees = [0x900u64, 0x300, 0x700, 0x200, 0x500];
    for (i, &c) in callees.iter().enumerate() {
        cg.add_function(FunctionId::new(c));
        cg.add_call_site(CallSite {
            call_addr: 0x100 + i as u64 * 4,
            caller: root,
            callee: Some(FunctionId::new(c)),
            is_tail_call: false,
            is_indirect: false,
            confidence: 100,
        });
    }

    let order: Vec<u64> = cg.bottom_up_order().into_iter().map(|f| f.0).collect();

    // Post-order: every callee before the caller.
    let root_pos = order.iter().position(|&x| x == 0x100).unwrap();
    for &c in &callees {
        let p = order.iter().position(|&x| x == c).unwrap();
        assert!(p < root_pos, "callee {c:#x} must precede its caller");
    }

    // And the callees themselves in a deterministic (sorted) order.
    let visited: Vec<u64> = order.iter().copied().filter(|x| *x != 0x100).collect();
    let mut expected = callees.to_vec();
    expected.sort_unstable();
    assert_eq!(visited, expected, "callee visit order must be stable");
}
