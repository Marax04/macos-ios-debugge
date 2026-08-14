//! Regression tests for logic defects found by the wave-1 semantic audit.
//!
//! All of these produced a plausible-looking but wrong answer rather than a
//! crash: a taint analysis that silently reports *fewer* findings than it
//! should is the worst failure mode this crate has, because the output still
//! looks like a clean bill of health.

use std::collections::HashSet;

use rustre_symb_taint::interprocedural::CallGraph;
use rustre_symb_taint::taint_sinks_full::{SinkCategory, TaintSinksFull};

// ── CallGraph ordering ─────────────────────────────────────────────────────

fn chain() -> CallGraph {
    use rustre_symb_taint::interprocedural::CallSite;
    let mut cg = CallGraph::new();
    let site = |s: u64, t: u64| CallSite {
        call_addr: s,
        target_addr: t,
        target_name: None,
        args: vec![],
    };
    // A calls B calls C.
    cg.add_call_edge(0xA, 0xB, site(0xA0, 0xB));
    cg.add_call_edge(0xB, 0xC, site(0xB0, 0xC));
    cg
}

/// A bottom-up summary pass needs every callee BEFORE its callers; running it
/// on the caller-first order meant summaries were always missing and every
/// call degraded to the conservative branch.
#[test]
fn reverse_topo_order_puts_leaves_first() {
    let cg = chain();
    let order = cg.reverse_topo_order().expect("acyclic");
    let pos = |x: u64| order.iter().position(|&y| y == x).unwrap();
    assert!(pos(0xC) < pos(0xB), "leaf C must precede its caller B");
    assert!(pos(0xB) < pos(0xA), "B must precede its caller A");
}

/// The two orders must be exact mirrors — and `topo_order` must keep its
/// documented caller-first meaning, which existing callers rely on.
#[test]
fn the_two_orders_are_mirrors() {
    let cg = chain();
    let mut fwd = cg.topo_order().expect("acyclic");
    let rev = cg.reverse_topo_order().expect("acyclic");
    assert_eq!(fwd.len(), rev.len());
    fwd.reverse();
    assert_eq!(fwd, rev);
}

// ── TaintSinksFull ─────────────────────────────────────────────────────────

/// The classic overflow is an attacker-controlled LENGTH, not a tainted
/// pointer. The three sibling implementations (lib.rs, taint_sinks.rs,
/// taint_policy.rs) all check argument 2; the "full" DB did not.
#[test]
fn memcpy_family_treats_the_length_as_a_sink_argument() {
    let db = TaintSinksFull::new();
    for name in [
        "memcpy", "memmove", "bcopy", "wmemcpy", "wmemmove", "mempcpy", "memccpy",
    ] {
        let e = db.get(name).unwrap_or_else(|| panic!("{name} missing from DB"));
        assert!(
            e.affects_arg(2),
            "{name}: tainted length must be a sink argument, got {:?}",
            e.tainted_arg_indices
        );
        // The pointers must remain sink arguments too.
        assert!(e.affects_arg(0), "{name}: dest dropped");
        assert!(e.affects_arg(1), "{name}: src dropped");
    }
}

/// `add` used a plain `insert`, so a second registration of the same name
/// silently deleted the first — losing both the category and sink argument
/// positions the DB had explicitly been told about.
#[test]
fn duplicate_registrations_do_not_erase_the_first() {
    let db = TaintSinksFull::new();

    // WinExec / ShellExecuteW are registered as CommandInjection first and
    // ProcessExecution later; the primary classification must survive.
    let cmd: HashSet<String> = db
        .sinks_of_category(SinkCategory::CommandInjection)
        .into_iter()
        .map(|e| e.name.clone())
        .collect();
    for name in ["WinExec", "ShellExecuteW"] {
        assert!(
            cmd.contains(name),
            "{name} lost its CommandInjection classification"
        );
    }

    // CryptEncrypt is registered with arg 5 (pbData) and later with arg 3.
    // Neither may be dropped.
    let ce = db.get("CryptEncrypt").expect("CryptEncrypt present");
    assert!(ce.affects_arg(5), "pbData (arg 5) was erased");
    assert!(ce.affects_arg(3), "arg 3 was erased");
}

/// Merging must never *shrink* what the DB knows: for every registered sink at
/// least one tainted argument index must survive.
#[test]
fn every_sink_keeps_at_least_one_argument() {
    let db = TaintSinksFull::new();
    for name in ["VirtualProtect", "CreateRemoteThread", "WinExec", "memcpy"] {
        let e = db.get(name).unwrap_or_else(|| panic!("{name} missing"));
        assert!(
            !e.tainted_arg_indices.is_empty(),
            "{name} ended up with no sink arguments"
        );
        // Indices must stay sorted and duplicate-free after merging.
        let mut sorted = e.tainted_arg_indices.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted, e.tainted_arg_indices,
            "{name} has unsorted or duplicated argument indices"
        );
    }
}
