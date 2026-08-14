//! Regression tests for logic defects found by the wave-1 semantic audit.
//!
//! Every test was written BEFORE its fix and confirmed to fail against the
//! then-current code, with the exact output the audit predicted.
//!
//! Most of these are SOUNDNESS defects, which for an abstract domain is the
//! direction that matters: a value set is allowed to be too wide (imprecise but
//! safe), never too narrow. A result that omits a value the concrete execution
//! can produce will silently mislead every consumer downstream.

use rustre_analysis_vsa::abstract_interpretation::ConstantDomain;
use rustre_analysis_vsa::ValueSet;
use rustre_analysis_vsa::strided_interval::StridedInterval;

// ── StridedInterval::mul ───────────────────────────────────────────────────

/// Products expand as `(a + s·i)(c + t·j) = ac + s·c·i + t·a·j + s·t·i·j`, so
/// the achievable increments include the CROSS TERM `s·t`. Leaving it out of
/// the gcd yields a stride that is too large, and the result then fails to
/// contain products that really occur.
#[test]
fn mul_stride_includes_the_cross_term() {
    // {2, 3} × {2, 3} = {4, 6, 9}
    let a = StridedInterval::new(1, 2, 3, 64);
    let r = a.mul(&a);

    for v in [4u64, 6, 9] {
        assert!(
            r.contains(v),
            "{v} is a real product of {{2,3}}×{{2,3}} but the result excludes it: {r:?}"
        );
    }
}

/// The general property: for small concrete sets, every real product must be
/// inside the abstract result. Over-approximation is fine; omission is not.
#[test]
fn mul_over_approximates_every_concrete_product() {
    let cases = [
        (1u64, 2u64, 3u64, 1u64, 2u64, 3u64),
        (2, 1, 7, 3, 2, 11),
        (1, 0, 4, 1, 0, 4),
        (5, 5, 20, 1, 1, 3),
    ];
    for (sa, la, ha, sb, lb, hb) in cases {
        let a = StridedInterval::new(sa, la, ha, 64);
        let b = StridedInterval::new(sb, lb, hb, 64);
        let r = a.mul(&b);

        let mut x = la;
        while x <= ha {
            let mut y = lb;
            while y <= hb {
                let p = x * y;
                assert!(
                    r.contains(p),
                    "{x}*{y} = {p} missing from {a:?} * {b:?} = {r:?}"
                );
                y += sb;
            }
            x += sa;
        }
    }
}

// ── widening: pointer.rs and jumptable.rs ──────────────────────────────────

/// Widening must produce an UPPER BOUND of both operands. Taking
/// `gcd(s1, s2)` while keeping the smaller `lo` ignores the offset between the
/// two lower bounds, so members of `next` in a different residue class are
/// silently dropped — the widened set is not above `next` at all.
#[test]
fn pointer_widen_keeps_every_member_of_both_operands() {
    let prev = ValueSet::Range {
        lo: 0,
        hi: 10,
        stride: 2,
    }; // {0,2,…,10}
    let next = ValueSet::Range {
        lo: 1,
        hi: 11,
        stride: 2,
    }; // {1,3,…,11}

    let w = rustre_analysis_vsa::pointer::widen(&prev, &next);
    assert!(
        w.contains(1),
        "1 belongs to `next` and must survive widening, got {w:?}"
    );
    assert!(w.contains(0), "0 belongs to `prev` and must survive");
    assert!(w.contains(3), "3 belongs to `next` and must survive");
}

/// Same defect, second unfixed copy. Downstream this feeds jump-table bounds,
/// where a dropped residue class means real switch targets go missing.
#[test]
fn jumptable_widen_keeps_every_member_of_both_operands() {
    let prev = ValueSet::strided(0, 10, 2);
    let next = ValueSet::strided(1, 11, 2);

    let w = rustre_analysis_vsa::jumptable::widen(&prev, &next);
    assert!(
        w.contains(1),
        "1 belongs to `next` and must survive widening, got {w:?}"
    );
    assert!(w.contains(0), "0 belongs to `prev` and must survive");
}

/// Widening an interval with itself must not lose anything either.
#[test]
fn widening_is_idempotent_on_equal_operands() {
    let s = ValueSet::strided(4, 20, 4);
    for w in [
        rustre_analysis_vsa::pointer::widen(&s, &s),
        rustre_analysis_vsa::jumptable::widen(&s, &s),
    ] {
        for v in [4u64, 8, 12, 16, 20] {
            assert!(v % 4 == 0 && w.contains(v), "{v} lost widening {s:?}");
        }
    }
}

// ── ConstantDomain::mul ────────────────────────────────────────────────────

/// Bottom means "unreachable", so γ(Bottom) = ∅ and any product involving it is
/// empty. The `Const(0)` short-circuit was matched BEFORE the Bottom arm, so
/// `0 * ⊥` produced `Const(0)` — resurrecting dead code as a real value. The
/// sibling `add`/`sub` in the same impl put Bottom first.
#[test]
fn multiplying_by_bottom_stays_bottom() {
    assert_eq!(
        ConstantDomain::Const(0).mul(&ConstantDomain::Bottom),
        ConstantDomain::Bottom,
        "0 * ⊥ must be ⊥, not Const(0)"
    );
    assert_eq!(
        ConstantDomain::Bottom.mul(&ConstantDomain::Const(0)),
        ConstantDomain::Bottom,
        "⊥ * 0 must be ⊥"
    );
}

/// Bottom must absorb uniformly across the whole domain — the property the
/// sibling operations already satisfy.
#[test]
fn bottom_is_strict_in_every_arithmetic_op() {
    let bot = ConstantDomain::Bottom;
    for other in [
        ConstantDomain::Const(0),
        ConstantDomain::Const(1),
        ConstantDomain::Const(-7),
        ConstantDomain::Top,
        ConstantDomain::Bottom,
    ] {
        for (name, got) in [
            ("add", bot.add(&other)),
            ("sub", bot.sub(&other)),
            ("mul", bot.mul(&other)),
            ("add-rev", other.add(&bot)),
            ("sub-rev", other.sub(&bot)),
            ("mul-rev", other.mul(&bot)),
        ] {
            assert_eq!(
                got,
                ConstantDomain::Bottom,
                "{name} with ⊥ and {other:?} must be ⊥"
            );
        }
    }
}

/// The `Const(0)` short-circuit must still work where it is legitimate.
#[test]
fn zero_still_absorbs_over_reachable_values() {
    assert_eq!(
        ConstantDomain::Const(0).mul(&ConstantDomain::Top),
        ConstantDomain::Const(0)
    );
    assert_eq!(
        ConstantDomain::Const(0).mul(&ConstantDomain::Const(9)),
        ConstantDomain::Const(0)
    );
}

// ── Andersen worklist: synthetic deref variables ───────────────────────────

use rustre_analysis_vsa::alias_analysis::{AllocSite, AndersenSolver, AndersonConstraint};

/// The worklist dependency graph is built from `constraint_sources` /
/// `constraint_outputs`, and neither mentions the SYNTHETIC deref variables
/// that `Load` reads and `Store` writes. A `Store` that grows a deref variable
/// therefore never re-enqueues a `Load` reading it through a different
/// pointer, and the solver converges on an incomplete points-to set.
///
/// That is the unsound direction: a missing points-to edge makes the analysis
/// answer `NoAlias` for pointers that really can alias.
#[test]
fn a_store_reenqueues_loads_that_read_the_same_object() {
    // a = &G1000;  b = a;  p = *b;  s = &G2000;  *a = s;
    // Since b and a point at the same object and *a = s, p must point at G2000.
    let cs = vec![
        AndersonConstraint::Alloc {
            ptr: 1,
            site: AllocSite::Global(0x1000),
            offset: 0,
        },
        AndersonConstraint::Assign { dst: 2, src: 1 },
        AndersonConstraint::Load {
            dst: 4,
            src_ptr: 2,
        },
        AndersonConstraint::Alloc {
            ptr: 3,
            site: AllocSite::Global(0x2000),
            offset: 0,
        },
        AndersonConstraint::Store {
            dst_ptr: 1,
            src: 3,
        },
    ];

    let (graph, stats) = AndersenSolver::new(cs).solve();
    assert!(stats.converged, "solver must reach a fixpoint");

    let pts_p: Vec<AllocSite> = graph.get(4).iter().map(|t| t.site).collect();
    assert!(
        pts_p.contains(&AllocSite::Global(0x2000)),
        "p = *b must point at G2000 (b aliases a, and *a = s = &G2000); \
         got pts(p) = {pts_p:?}"
    );
}

/// The same shape with the constraints in the "lucky" order must already work,
/// so this pins down that the fix is about re-enqueueing, not about ordering.
#[test]
fn the_same_facts_hold_regardless_of_constraint_order() {
    let build = |load_last: bool| {
        let alloc_a = AndersonConstraint::Alloc {
            ptr: 1,
            site: AllocSite::Global(0x1000),
            offset: 0,
        };
        let assign = AndersonConstraint::Assign { dst: 2, src: 1 };
        let load = AndersonConstraint::Load {
            dst: 4,
            src_ptr: 2,
        };
        let alloc_s = AndersonConstraint::Alloc {
            ptr: 3,
            site: AllocSite::Global(0x2000),
            offset: 0,
        };
        let store = AndersonConstraint::Store {
            dst_ptr: 1,
            src: 3,
        };
        if load_last {
            vec![alloc_a, assign, alloc_s, store, load]
        } else {
            vec![alloc_a, assign, load, alloc_s, store]
        }
    };

    for load_last in [true, false] {
        let (graph, _) = AndersenSolver::new(build(load_last)).solve();
        let pts_p: Vec<AllocSite> = graph.get(4).iter().map(|t| t.site).collect();
        assert!(
            pts_p.contains(&AllocSite::Global(0x2000)),
            "load_last = {load_last}: pts(p) = {pts_p:?}"
        );
    }
}
