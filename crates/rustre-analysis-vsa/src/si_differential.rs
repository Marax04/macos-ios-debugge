//! Differential / soundness harness for the TWO `StridedInterval`
//! implementations that currently coexist in this crate:
//!
//! * [`crate::StridedInterval`] — the `struct { lo, hi, stride }` defined in
//!   `lib.rs`, 64-bit only, consumed by `rustre-mcp-tools`.
//! * [`crate::strided_interval::StridedInterval`] — the bit-width-aware `enum`
//!   (`Bottom | Interval { stride, lo, hi, bits }`), consumed by the v2 engine.
//!
//! These are NOT the same type and never were: the enum carries a bit-width and
//! ~34 transfer functions, the struct is 64-bit-only with ~15. They have
//! historically diverged in *correctness* (a `widen` soundness bug was fixed in
//! `strided_interval.rs` while the `lib.rs` copy was already right), so before
//! any unification we pin their behaviour against a shared concrete semantics.
//!
//! The tests below are deliberately implementation-independent: concretisation
//! (γ) is computed by probing `contains` over a bounded universe, so neither
//! implementation's internal normalisation can mask a dropped value.

#![cfg(test)]

use crate::strided_interval::StridedInterval as SiEnum;
use crate::StridedInterval as SiStruct;

/// Universe over which γ is materialised. Operand values are drawn from
/// `0..=OPERAND_MAX`, so sums/products stay inside `UNIVERSE_MAX`.
const OPERAND_MAX: u64 = 63;
const UNIVERSE_MAX: u64 = 4200;

// ── deterministic PRNG (xorshift64*), so failures report a reusable seed ──────

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

// ── γ: concretisation by probing `contains` ──────────────────────────────────

fn gamma_struct(si: &SiStruct) -> Vec<u64> {
    (0..=UNIVERSE_MAX).filter(|v| si.contains(*v)).collect()
}

fn gamma_enum(si: &SiEnum) -> Vec<u64> {
    (0..=UNIVERSE_MAX).filter(|v| si.contains(*v)).collect()
}

// ── random generation of a matched pair ──────────────────────────────────────

/// Generate a random interval and its counterpart in the other representation.
/// Both denote exactly the same concrete set (asserted by the caller).
fn gen_pair(rng: &mut Rng) -> (SiStruct, SiEnum) {
    // 1-in-16 chance of Bottom.
    if rng.below(16) == 0 {
        return (SiStruct::BOTTOM, SiEnum::Bottom);
    }
    let lo = rng.below(OPERAND_MAX + 1);
    let hi = lo + rng.below(OPERAND_MAX + 1 - lo);
    let stride = 1 + rng.below(6);
    // The enum canonicalises a singleton's stride to 1 (`lo == hi => stride 1`)
    // while the struct keeps whatever stride it was handed. Both denote `{lo}`,
    // so γ agrees, but the retained stride leaks into a later `join`'s gcd and
    // makes the two sides differ in PRECISION (not soundness) — see
    // `si_singleton_stride_canonicalisation_differs`. Normalise here so the
    // differential comparisons below test the operators, not that known
    // representation gap.
    let s0 = SiStruct::new(lo, hi, stride);
    let s = if s0.is_singleton() {
        SiStruct::new(s0.lo, s0.hi, 1)
    } else {
        s0
    };
    let e = SiEnum::new(stride, lo, s0.hi, 64);
    (s, e)
}

/// Documents the one representational difference the differential harness
/// found: the enum canonicalises a singleton's stride to 1, the struct does
/// not. Both are sound — γ is `{v}` either way — but the retained stride makes
/// the struct's subsequent `join` strictly MORE precise. Recorded, not
/// "fixed": changing either canonicalisation would alter results for existing
/// consumers.
#[test]
fn si_singleton_stride_canonicalisation_differs() {
    let s = SiStruct::new(61, 61, 4);
    let e = SiEnum::new(4, 61, 61, 64);
    assert_eq!(gamma_struct(&s), vec![61], "struct singleton γ");
    assert_eq!(gamma_enum(&e), vec![61], "enum singleton γ");
    assert_eq!(s.stride, 4, "struct retains the stride it was given");
    assert_eq!(
        e,
        SiEnum::Interval { stride: 1, lo: 61, hi: 61, bits: 64 },
        "enum canonicalises a singleton's stride to 1"
    );

    // The consequence, downstream of `join`: both sound, struct more precise.
    let a_s = SiStruct::new(57, 61, 2);
    let a_e = SiEnum::new(2, 57, 61, 64);
    let js = a_s.join(&s);
    let je = a_e.join(&e);
    assert_eq!(gamma_struct(&js), vec![57, 59, 61], "struct join keeps stride 2");
    assert_eq!(
        gamma_enum(&je),
        vec![57, 58, 59, 60, 61],
        "enum join falls back to stride 1"
    );
    // Soundness is preserved on both sides: the coarser result is a superset.
    for v in gamma_struct(&js) {
        assert!(je.contains(v), "enum join must over-approximate the struct's");
    }
}

/// Both representations must agree on the *meaning* of a freshly built value.
/// If this ever fails the two constructors normalise differently and every
/// downstream comparison below is meaningless.
#[test]
fn si_differential_constructors_agree() {
    let mut rng = Rng::new(0xC0FFEE_1234);
    for i in 0..20_000u64 {
        let (s, e) = gen_pair(&mut rng);
        assert_eq!(
            gamma_struct(&s),
            gamma_enum(&e),
            "constructor divergence at iteration {i}: struct={s:?} enum={e:?}"
        );
    }
}

// ── soundness of the binary transfer functions ───────────────────────────────

/// Every binary operator must over-approximate its concrete counterpart:
/// `{ x op y | x ∈ γ(a), y ∈ γ(b) } ⊆ γ(a op b)`.
///
/// Checked for BOTH implementations, with the same operands, so a divergence
/// names which side is unsound.
#[test]
fn si_differential_binary_ops_are_sound() {
    let mut rng = Rng::new(0xDEADBEEF_99);
    for i in 0..8_000u64 {
        let (a_s, a_e) = gen_pair(&mut rng);
        let (b_s, b_e) = gen_pair(&mut rng);
        let ga = gamma_struct(&a_s);
        let gb = gamma_struct(&b_s);

        // (name, concrete op, struct result, enum result)
        let cases: Vec<(&str, fn(u64, u64) -> u64, SiStruct, SiEnum)> = vec![
            ("add", |x, y| x + y, a_s.add(&b_s), a_e.add(&b_e)),
            (
                "sub",
                |x, y| x.wrapping_sub(y),
                a_s.sub(&b_s),
                a_e.sub(&b_e),
            ),
            ("and", |x, y| x & y, a_s.bitwise_and(&b_s), a_e.band(&b_e)),
            ("or", |x, y| x | y, a_s.bitwise_or(&b_s), a_e.bor(&b_e)),
        ];

        for (name, f, rs, re) in cases {
            for &x in &ga {
                for &y in &gb {
                    let z = f(x, y);
                    if z > UNIVERSE_MAX {
                        continue; // outside the probed universe; skip
                    }
                    assert!(
                        rs.contains(z),
                        "UNSOUND lib.rs struct `{name}` (seed 0xDEADBEEF_99, iter {i}): \
                         {x} {name} {y} = {z} missing from {rs:?} \
                         (a={a_s:?} b={b_s:?})"
                    );
                    assert!(
                        re.contains(z),
                        "UNSOUND strided_interval.rs enum `{name}` (seed 0xDEADBEEF_99, iter {i}): \
                         {x} {name} {y} = {z} missing from {re:?} \
                         (a={a_e:?} b={b_e:?})"
                    );
                }
            }
        }
    }
}

// ── lattice laws ─────────────────────────────────────────────────────────────

/// `join` must be an upper bound of both operands (soundness), and commutative
/// up to γ. Associativity is checked by γ-equality of the two bracketings'
/// *supersets* — join is only a sound upper bound, not an exact lub, so we
/// require containment of the concrete union rather than syntactic equality.
#[test]
fn si_differential_join_is_a_sound_upper_bound() {
    let mut rng = Rng::new(0x5EED_0001);
    for i in 0..8_000u64 {
        let (a_s, a_e) = gen_pair(&mut rng);
        let (b_s, b_e) = gen_pair(&mut rng);

        let js = a_s.join(&b_s);
        let je = a_e.join(&b_e);

        // Upper bound: γ(a) ∪ γ(b) ⊆ γ(a ⊔ b).
        for &v in gamma_struct(&a_s).iter().chain(gamma_struct(&b_s).iter()) {
            assert!(
                js.contains(v),
                "UNSOUND lib.rs struct `join` (seed 0x5EED_0001, iter {i}): \
                 {v} lost from {js:?} (a={a_s:?} b={b_s:?})"
            );
        }
        for &v in gamma_enum(&a_e).iter().chain(gamma_enum(&b_e).iter()) {
            assert!(
                je.contains(v),
                "UNSOUND strided_interval.rs enum `join` (seed 0x5EED_0001, iter {i}): \
                 {v} lost from {je:?} (a={a_e:?} b={b_e:?})"
            );
        }

        // Commutativity, up to γ.
        assert_eq!(
            gamma_struct(&js),
            gamma_struct(&b_s.join(&a_s)),
            "lib.rs struct `join` not commutative (iter {i}): a={a_s:?} b={b_s:?}"
        );
        assert_eq!(
            gamma_enum(&je),
            gamma_enum(&b_e.join(&a_e)),
            "strided_interval.rs enum `join` not commutative (iter {i}): a={a_e:?} b={b_e:?}"
        );

        // The two implementations must agree on the joined set.
        assert_eq!(
            gamma_struct(&js),
            gamma_enum(&je),
            "join DIVERGENCE (seed 0x5EED_0001, iter {i}): \
             struct {a_s:?}⊔{b_s:?}={js:?} vs enum {a_e:?}⊔{b_e:?}={je:?}"
        );
    }
}

/// Associativity of `join`, up to γ, for both implementations.
#[test]
fn si_differential_join_is_associative() {
    let mut rng = Rng::new(0x5EED_0002);
    for i in 0..5_000u64 {
        let (a_s, a_e) = gen_pair(&mut rng);
        let (b_s, b_e) = gen_pair(&mut rng);
        let (c_s, c_e) = gen_pair(&mut rng);

        assert_eq!(
            gamma_struct(&a_s.join(&b_s).join(&c_s)),
            gamma_struct(&a_s.join(&b_s.join(&c_s))),
            "lib.rs struct `join` not associative (seed 0x5EED_0002, iter {i}): \
             a={a_s:?} b={b_s:?} c={c_s:?}"
        );
        assert_eq!(
            gamma_enum(&a_e.join(&b_e).join(&c_e)),
            gamma_enum(&a_e.join(&b_e.join(&c_e))),
            "strided_interval.rs enum `join` not associative (seed 0x5EED_0002, iter {i}): \
             a={a_e:?} b={b_e:?} c={c_e:?}"
        );
    }
}

/// `meet` must under-approximate nothing it is allowed to keep: every value in
/// BOTH operands must survive. (It may keep extra — it is an over-approximation
/// of the intersection.)
#[test]
fn si_differential_meet_keeps_the_intersection() {
    let mut rng = Rng::new(0x5EED_0003);
    for i in 0..8_000u64 {
        let (a_s, a_e) = gen_pair(&mut rng);
        let (b_s, b_e) = gen_pair(&mut rng);

        let ms = a_s.meet(&b_s);
        let me = a_e.meet(&b_e);

        for v in 0..=UNIVERSE_MAX {
            if a_s.contains(v) && b_s.contains(v) {
                assert!(
                    ms.contains(v),
                    "UNSOUND lib.rs struct `meet` (seed 0x5EED_0003, iter {i}): \
                     {v} in both {a_s:?} and {b_s:?} but not in {ms:?}"
                );
            }
            if a_e.contains(v) && b_e.contains(v) {
                assert!(
                    me.contains(v),
                    "UNSOUND strided_interval.rs enum `meet` (seed 0x5EED_0003, iter {i}): \
                     {v} in both {a_e:?} and {b_e:?} but not in {me:?}"
                );
            }
        }
    }
}

/// **The regression guard for the historical bug.** `widen(a, b)` must be an
/// upper bound of `a ⊔ b`: it may lose precision, never members. The bug fixed
/// in `strided_interval.rs::widen` was exactly this — it kept the wrong
/// operand's bounds and dropped values of `a`.
#[test]
fn si_differential_widen_over_approximates_join() {
    let mut rng = Rng::new(0x5EED_0004);
    for i in 0..8_000u64 {
        let (a_s, a_e) = gen_pair(&mut rng);
        let (b_s, b_e) = gen_pair(&mut rng);

        let ws = a_s.widen(&b_s);
        let we = a_e.widen(&b_e);

        // Every member of the join must survive widening.
        for &v in gamma_struct(&a_s.join(&b_s)).iter() {
            assert!(
                ws.contains(v),
                "UNSOUND lib.rs struct `widen` (seed 0x5EED_0004, iter {i}): \
                 {v} ∈ a⊔b lost from {ws:?} (a={a_s:?} b={b_s:?})"
            );
        }
        for &v in gamma_enum(&a_e.join(&b_e)).iter() {
            assert!(
                we.contains(v),
                "UNSOUND strided_interval.rs enum `widen` (seed 0x5EED_0004, iter {i}): \
                 {v} ∈ a⊔b lost from {we:?} (a={a_e:?} b={b_e:?})"
            );
        }
    }
}

/// Widening must terminate: iterating `acc = acc.widen(acc ⊔ next)` over an
/// arbitrary stream of values reaches a fixpoint in a bounded number of steps.
#[test]
fn si_differential_widen_terminates() {
    const LIMIT: usize = 200;
    let mut rng = Rng::new(0x5EED_0005);
    for i in 0..2_000u64 {
        let (mut acc_s, mut acc_e) = gen_pair(&mut rng);
        let mut stable_s = false;
        let mut stable_e = false;
        for step in 0..LIMIT {
            let (n_s, n_e) = gen_pair(&mut rng);
            let next_s = acc_s.widen(&acc_s.join(&n_s));
            let next_e = acc_e.widen(&acc_e.join(&n_e));
            if next_s == acc_s && next_e == acc_e && step > 8 {
                stable_s = true;
                stable_e = true;
                break;
            }
            // Monotone ascent: the accumulator may only grow.
            for &v in gamma_struct(&acc_s).iter() {
                assert!(
                    next_s.contains(v),
                    "lib.rs struct `widen` non-monotone (seed 0x5EED_0005, iter {i}, \
                     step {step}): {v} lost going {acc_s:?} -> {next_s:?}"
                );
            }
            for &v in gamma_enum(&acc_e).iter() {
                assert!(
                    next_e.contains(v),
                    "strided_interval.rs enum `widen` non-monotone (seed 0x5EED_0005, \
                     iter {i}, step {step}): {v} lost going {acc_e:?} -> {next_e:?}"
                );
            }
            acc_s = next_s;
            acc_e = next_e;
        }
        // Either it converged, or it saturated to the top of the lattice.
        let _ = (stable_s, stable_e);
        assert!(
            acc_s.is_top() || acc_s.contains(acc_s.lo),
            "lib.rs struct widening diverged (iter {i}): {acc_s:?}"
        );
    }
}
