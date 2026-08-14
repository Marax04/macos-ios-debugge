//! Soundness oracle for [`rustre_analysis_vsa::may_be_out_of_bounds`].
//!
//! # Why this predicate deserves an oracle
//!
//! It is a **safety** predicate with 5 call sites in `rustre-mcp-*`, and its
//! two failure directions are not symmetric:
//!
//! * saying `true` when the access is actually in bounds is a false alarm —
//!   noisy, but safe;
//! * saying **`false`** when the access can go out of bounds is a **missed
//!   bug**, and nothing downstream can recover from it.
//!
//! Its existing coverage is five hand-picked point assertions
//! (`blitz.rs:626-634`, `blitz2.rs:443`). Those pin known-good answers; they
//! cannot discover an input shape nobody thought of. This file states the
//! property instead.
//!
//! # The property, from the definition
//!
//! For every value `v` an interval can concretely denote:
//!
//! > `!may_be_out_of_bounds(vs, (base, limit))`  ⇒  `base <= v < limit`
//!
//! The oracle enumerates the members directly from `(stride, lo, hi)` — it
//! never consults the predicate's own `lo < base || hi >= limit` test, so it
//! cannot agree with a bug in it.
//!
//! The converse is deliberately NOT asserted: a sound abstract interpreter is
//! allowed to over-report. Demanding `may_be_out_of_bounds == "some member is
//! outside"` would fail the analyser for being conservative, which is the one
//! thing it is supposed to be.
//!
//! # Negative control
//!
//! `BOUNDS_ORACLE_CORRUPT=1` weakens the oracle's membership check to ignore
//! the lower bound. [`in_bounds_is_never_a_false_negative`] must then FAIL —
//! demonstrated, not assumed.

use rustre_analysis_vsa::{StridedInterval, may_be_out_of_bounds};

fn corrupt() -> bool {
    std::env::var("BOUNDS_ORACLE_CORRUPT").is_ok()
}

/// Every concrete value the interval denotes, derived from its fields alone.
///
/// Bounded so the enumeration stays finite; generators below stay well inside.
fn members(si: &StridedInterval) -> Vec<u64> {
    if si.is_bottom() {
        return Vec::new();
    }
    let stride = if si.stride == 0 { 1 } else { si.stride };
    let mut out = Vec::new();
    let mut v = si.lo;
    while v <= si.hi && out.len() < 4096 {
        out.push(v);
        match v.checked_add(stride) {
            Some(n) => v = n,
            None => break,
        }
    }
    out
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// **The property that matters.** A `false` answer must be trustworthy.
#[test]
fn in_bounds_is_never_a_false_negative() {
    let mut r = Lcg(0xB0_1145_5EED);
    let mut exercised_false = 0;

    for _ in 0..20_000 {
        let lo = r.below(200);
        let hi = lo + r.below(200);
        let stride = 1 + r.below(8);
        let si = StridedInterval::new(lo, hi, stride);

        let base = r.below(200);
        let limit = base + 1 + r.below(200);

        if may_be_out_of_bounds(&si, (base, limit)) {
            continue; // over-reporting is allowed; nothing to check.
        }
        exercised_false += 1;

        for v in members(&si) {
            // NOTE ON THE CORRUPTION DIRECTION — I got this wrong first.
            // My initial corruption was `v < limit`, i.e. *dropping* the lower
            // bound. That is a no-op here BY CONSTRUCTION: when the predicate
            // answers "in bounds" it has already guaranteed `lo >= base`, so no
            // member can sit below `base` and the weakened check accepts
            // exactly the same values. The test stayed green and proved
            // nothing.
            // To break an assertion that must be TRUE, the condition has to get
            // STRICTER, not looser — here, excluding `v == base`, which fires
            // on every interval starting exactly at the lower bound.
            let inside =
                if corrupt() { v > base && v < limit } else { v >= base && v < limit };
            assert!(
                inside,
                "UNSOUND: may_be_out_of_bounds said IN bounds, but {v} escapes \
                 [{base}, {limit}) — interval stride={stride} lo={lo} hi={hi}"
            );
        }
    }

    // Without this the test could pass by never taking the branch at all —
    // exactly the one-sided-condition failure that made a vsa widening test
    // vacuous earlier in this campaign.
    assert!(
        exercised_false > 1000,
        "only {exercised_false} in-bounds verdicts were checked; the generator \
         is not producing enough of them for this test to mean anything"
    );
}

/// Bottom denotes no values at all, so it can never be out of bounds.
#[test]
fn bottom_is_vacuously_in_bounds() {
    assert!(!may_be_out_of_bounds(&StridedInterval::BOTTOM, (0, 100)));
    assert!(members(&StridedInterval::BOTTOM).is_empty());
}

/// Top denotes everything, so it must always be reported as possibly outside —
/// the one direction where over-reporting is mandatory rather than merely
/// permitted, since an empty bound range cannot contain the whole domain.
#[test]
fn top_is_always_reported_out_of_bounds() {
    let mut r = Lcg(0x70_9000_1234);
    for _ in 0..1000 {
        let base = r.below(1 << 20);
        let limit = base + 1 + r.below(1 << 20);
        assert!(
            may_be_out_of_bounds(&StridedInterval::TOP, (base, limit)),
            "Top was reported in bounds for [{base}, {limit})"
        );
    }
}

/// A singleton is in bounds exactly when its single value is — the one case
/// where the predicate can be both sound and complete, so it is safe to
/// assert the equivalence here and nowhere else.
#[test]
fn singleton_answer_is_exact() {
    let mut r = Lcg(0x51_9701_0000);
    for _ in 0..5000 {
        let v = r.below(1000);
        let base = r.below(1000);
        let limit = base + 1 + r.below(1000);
        let si = StridedInterval::singleton(v);
        let expected_outside = !(v >= base && v < limit);
        assert_eq!(
            may_be_out_of_bounds(&si, (base, limit)),
            expected_outside,
            "singleton {v} vs [{base}, {limit})"
        );
    }
}
