//! Laws every strided-interval operation must obey.
//!
//! These are not fixture tests: they enumerate small intervals, enumerate the
//! concrete values each one denotes, and check the defining property of an
//! abstract domain — the abstract result must contain every concrete result.
//! A domain that violates this is *unsound*: the analysis will confidently
//! report that a value cannot occur when it can.

use rustre_analysis_vsa::strided_interval::StridedInterval as SI;

const BITS: u8 = 8;
const MASK: u64 = 0xFF;

/// A small but varied set of intervals, including singletons and wide ranges.
fn samples() -> Vec<SI> {
    let mut v = vec![SI::Bottom];
    for stride in [0u64, 1, 2, 3] {
        for lo in [0u64, 1, 5, 16, 200, 255] {
            for span in [0u64, 1, 4, 15] {
                let hi = lo.saturating_add(span).min(MASK);
                if hi < lo {
                    continue;
                }
                // A stride-0 interval is a singleton by the module's invariant.
                if stride == 0 && hi != lo {
                    continue;
                }
                v.push(SI::new(stride, lo, hi, BITS));
            }
        }
    }
    v
}

/// Concrete values denoted by an interval (bounded, for test runtime).
fn members(si: &SI) -> Vec<u64> {
    match si {
        SI::Bottom => Vec::new(),
        SI::Interval { stride, lo, hi, .. } => {
            let step = if *stride == 0 { 1 } else { *stride };
            let mut out = Vec::new();
            let mut v = *lo;
            while v <= *hi && out.len() < 64 {
                out.push(v & MASK);
                match v.checked_add(step) {
                    Some(n) => v = n,
                    None => break,
                }
                if step == 0 {
                    break;
                }
            }
            out
        }
    }
}

#[test]
fn join_is_an_upper_bound() {
    for a in samples() {
        for b in samples() {
            let j = a.join(&b);
            for m in members(&a).into_iter().chain(members(&b)) {
                assert!(
                    j.contains(m),
                    "join lost a value: {m} is in {a:?} or {b:?} but not in {j:?}"
                );
            }
        }
    }
}

#[test]
fn meet_is_a_lower_bound() {
    for a in samples() {
        for b in samples() {
            let m = a.meet(&b);
            for v in members(&m) {
                assert!(
                    a.contains(v) && b.contains(v),
                    "meet invented a value: {v} is in {m:?} but not in both {a:?} and {b:?}"
                );
            }
        }
    }
}

#[test]
fn widen_covers_both_operands() {
    for a in samples() {
        for b in samples() {
            let w = a.widen(&b);
            for m in members(&a).into_iter().chain(members(&b)) {
                assert!(
                    w.contains(m),
                    "widen lost a value: {m} is in {a:?} or {b:?} but not in {w:?}"
                );
            }
        }
    }
}

/// The soundness obligation for arithmetic: every concrete result must be
/// contained in the abstract result.
#[test]
fn arithmetic_is_sound() {
    let ops: [(&str, fn(&SI, &SI) -> SI, fn(u64, u64) -> u64); 6] = [
        ("add", |a, b| a.add(b), |x, y| x.wrapping_add(y) & MASK),
        ("sub", |a, b| a.sub(b), |x, y| x.wrapping_sub(y) & MASK),
        ("mul", |a, b| a.mul(b), |x, y| x.wrapping_mul(y) & MASK),
        ("and", |a, b| a.band(b), |x, y| x & y),
        ("or", |a, b| a.bor(b), |x, y| x | y),
        ("xor", |a, b| a.bxor(b), |x, y| x ^ y),
    ];

    let s = samples();
    for (name, abstract_op, concrete_op) in ops {
        for a in &s {
            for b in &s {
                let r = abstract_op(a, b);
                for x in members(a) {
                    for y in members(b) {
                        let c = concrete_op(x, y);
                        assert!(
                            r.contains(c),
                            "{name} unsound: {x} {name} {y} = {c}, \
                             but {a:?} {name} {b:?} = {r:?} which excludes it"
                        );
                    }
                }
            }
        }
    }
}
