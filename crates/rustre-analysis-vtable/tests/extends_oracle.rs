//! Definitional oracle + differential fuzz for `vtable_extends`.
//!
//! Contract (from the doc comment): `vtable_extends(a, b)` is true iff
//!   * `a` is non-empty, and
//!   * `b` has strictly more entries than `a`, and
//!   * the target addresses of `a`'s entries equal, in order, the first
//!     `a.entry_count()` target addresses of `b`.
//! i.e. "a's address sequence is a STRICT PREFIX of b's".
//!
//! The oracle below is written from that definition alone: it extracts the two
//! address sequences and asks a generic strict-prefix question about them.

use rustre_analysis_vtable::{Vtable, VtableEntry, vtable_extends};

/// Independent, definitional predicate: is `x` a strict prefix of `y`,
/// with `x` non-empty?  Nothing here knows about vtables.
fn strict_nonempty_prefix<T: PartialEq>(x: &[T], y: &[T]) -> bool {
    !x.is_empty() && y.len() > x.len() && y.iter().take(x.len()).eq(x.iter())
}

fn addrs(v: &Vtable) -> Vec<u64> {
    v.entries.iter().map(|e| e.target_address).collect()
}

fn oracle(a: &Vtable, b: &Vtable) -> bool {
    strict_nonempty_prefix(&addrs(a), &addrs(b))
}

// ── generator ────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 ^ (self.0 >> 33)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Adversarial address pool: boundaries where naive `+`/stride arithmetic
/// overflows, plus a tiny pool so prefixes collide by chance.
const POOL: &[u64] = &[
    0,
    1,
    7,
    8,
    0x1000,
    0x1008,
    i64::MAX as u64,
    u64::MAX - 16,
    u64::MAX - 8,
    u64::MAX - 1,
    u64::MAX,
];

fn gen_vtable(r: &mut Lcg) -> Vtable {
    // base address itself adversarial: near u64::MAX so base + n*8 overflows
    let base = POOL[(r.below(POOL.len() as u64)) as usize];
    let mut v = Vtable::new(base);
    let n = r.below(5); // 0..=4 entries -> empty tables are reachable
    for i in 0..n {
        let t = POOL[(r.below(POOL.len() as u64)) as usize];
        v.add_entry(VtableEntry::new((i as usize).wrapping_mul(8), t));
    }
    v
}

/// Sometimes derive `b` from `a` so true-extends cases actually occur.
fn gen_pair(r: &mut Lcg) -> (Vtable, Vtable) {
    let a = gen_vtable(r);
    if r.below(2) == 0 {
        let mut b = Vtable::new(a.base_address.wrapping_add(0x100));
        for e in &a.entries {
            b.add_entry(VtableEntry::new(e.offset, e.target_address));
        }
        // extend by 0..=2 slots (0 => same length, must be false)
        let extra = r.below(3);
        for k in 0..extra {
            let t = POOL[(r.below(POOL.len() as u64)) as usize];
            b.add_entry(VtableEntry::new(
                (a.entries.len() + k as usize).wrapping_mul(8),
                t,
            ));
        }
        // occasionally corrupt one shared slot -> prefix broken
        if !b.entries.is_empty() && r.below(3) == 0 {
            let i = r.below(b.entries.len() as u64) as usize;
            b.entries[i].target_address = b.entries[i].target_address.wrapping_add(1);
        }
        (a, b)
    } else {
        (a, gen_vtable(r))
    }
}

#[test]
fn differential_vs_definitional_oracle() {
    let mut r = Lcg(0xDEADBEEF);
    // coverage counters
    let (mut c_true, mut c_false, mut c_empty_a, mut c_eq_len, mut c_prefix_broken, mut c_maxaddr) =
        (0u32, 0u32, 0u32, 0u32, 0u32, 0u32);

    for _ in 0..20_000 {
        let (a, b) = gen_pair(&mut r);
        let got = vtable_extends(&a, &b);
        let want = oracle(&a, &b);
        assert_eq!(
            got, want,
            "vtable_extends disagrees with definition\na={:?}\nb={:?}",
            addrs(&a),
            addrs(&b)
        );

        if want {
            c_true += 1;
        } else {
            c_false += 1;
        }
        if a.entries.is_empty() {
            c_empty_a += 1;
        }
        if !a.entries.is_empty() && a.entries.len() == b.entries.len() {
            c_eq_len += 1;
        }
        if !a.entries.is_empty()
            && b.entries.len() > a.entries.len()
            && !addrs(&b)[..a.entries.len()].eq(&addrs(&a)[..])
        {
            c_prefix_broken += 1;
        }
        if a.entries.iter().chain(b.entries.iter()).any(|e| e.target_address >= u64::MAX - 16) {
            c_maxaddr += 1;
        }

        // determinism: same input, same answer
        assert_eq!(got, vtable_extends(&a, &b), "non-deterministic result");
    }

    assert!(c_true > 100, "no positive cases: {c_true}");
    assert!(c_false > 100, "no negative cases: {c_false}");
    assert!(c_empty_a > 50, "empty-a shape dried up: {c_empty_a}");
    assert!(c_eq_len > 50, "equal-length shape dried up: {c_eq_len}");
    assert!(
        c_prefix_broken > 50,
        "longer-but-not-a-prefix shape dried up: {c_prefix_broken}"
    );
    assert!(c_maxaddr > 100, "adversarial u64::MAX addresses dried up: {c_maxaddr}");
}

// ── relational properties ────────────────────────────────────────────────────

fn vt(addrs: &[u64]) -> Vtable {
    let mut v = Vtable::new(0x4000);
    for (i, &t) in addrs.iter().enumerate() {
        v.add_entry(VtableEntry::new(i * 8, t));
    }
    v
}

/// IRREFLEXIVE is the required contract: "extends" is *strict* (b must have
/// strictly more slots), so a class can never extend itself.
#[test]
fn irreflexive() {
    let mut r = Lcg(7);
    for _ in 0..2000 {
        let a = gen_vtable(&mut r);
        assert!(!vtable_extends(&a, &a), "reflexive on {:?}", addrs(&a));
    }
}

#[test]
fn antisymmetric() {
    let mut r = Lcg(99);
    for _ in 0..20_000 {
        let (a, b) = gen_pair(&mut r);
        assert!(
            !(vtable_extends(&a, &b) && vtable_extends(&b, &a)),
            "both directions hold: {:?} {:?}",
            addrs(&a),
            addrs(&b)
        );
    }
}

#[test]
fn transitive() {
    let mut r = Lcg(1234);
    let mut witnessed = 0u32;
    for _ in 0..40_000 {
        let a = gen_vtable(&mut r);
        let (_, b) = gen_pair(&mut r);
        let (_, c) = gen_pair(&mut r);
        // build genuine chains too
        let mut chain_b = vt(&addrs(&a));
        chain_b.add_entry(VtableEntry::new(a.entries.len() * 8, u64::MAX));
        let mut chain_c = vt(&addrs(&chain_b));
        chain_c.add_entry(VtableEntry::new(chain_b.entries.len() * 8, 0));
        for (x, y, z) in [(&a, &b, &c), (&a, &chain_b, &chain_c)] {
            if vtable_extends(x, y) && vtable_extends(y, z) {
                witnessed += 1;
                assert!(
                    vtable_extends(x, z),
                    "transitivity broken: {:?} {:?} {:?}",
                    addrs(x),
                    addrs(y),
                    addrs(z)
                );
            }
        }
    }
    assert!(witnessed > 100, "no transitive chains witnessed: {witnessed}");
}
