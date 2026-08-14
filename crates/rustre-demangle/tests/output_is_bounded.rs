//! A short symbol must not render a huge output.
//!
//! Substitutions and back-references *reuse* an expansion, so in principle each
//! reuse multiplies it: a few hundred bytes of symbol could render megabytes. That
//! is a memory-exhaustion vector distinct from everything iters 81-85 covered — it
//! needs no panic, no overflow, no unbounded recursion, and it does not even make
//! the parser slow.
//!
//! Measured on 2026-07-30 across every ABI, with the reuse count escalating to 4096:
//!
//! * **worst amplification x16.7**, on an MSVC back-reference chain;
//! * the ratio **plateaus** rather than climbing — output is linear in the reuse
//!   count, so amplification tends to a constant;
//! * the compounding shape (one large real expansion referenced thousands of times,
//!   which would be quadratic) does not expand at all: amplification *falls* to
//!   x1.0 as the trailing references are rejected.
//!
//! No defect. Asserted rather than merely recorded because — unlike the timing
//! measurement in `tests/adversarial_backrefs.rs`, which is deliberately not a test
//! — **output length is deterministic**: it does not depend on machine load, so the
//! bound is stable.
//!
//! The bound is generous (x50) on purpose. The point is to catch a *class* change —
//! a substitution rule that starts expanding exponentially — not to pin 16.7.

/// Amplification is output length over input length.
fn amplification(sym: &str) -> f64 {
    let out = rustre_demangle::demangle(sym).map_or(0, |r| r.demangled.len());
    #[expect(clippy::cast_precision_loss, reason = "lengths are far below f64 precision limits")]
    let ratio = out as f64 / sym.len() as f64;
    ratio
}

#[test]
fn no_symbol_amplifies_more_than_fifty_fold() {
    type Maker = fn(usize) -> String;
    let makers: &[(&str, Maker)] = &[
        // Repeated reuse of one substitution, per ABI.
        ("itanium_reuse", |n| {
            format!("_Z1fPKSt9type_info{}", "S1_".repeat(n))
        }),
        ("itanium_template", |n| {
            format!("_Z1fISt6vectorIiSaIiEEE{}", "S1_".repeat(n))
        }),
        ("msvc_backref", |n| {
            format!("?f@@YAXU?$V@HH@std@@{}@Z", "0".repeat(n))
        }),
        ("swift_substitution", |n| {
            format!("$s4main3foo{}yyF", "S".repeat(n))
        }),
        ("d_array", |n| format!("_D4main3fooF{}iZv", "A".repeat(n))),
    ];

    let mut worst = 0.0f64;
    let mut worst_sym = String::new();
    let mut checked = 0;

    for (_, make) in makers {
        for n in [1usize, 4, 16, 64, 256, 1024, 4096] {
            let sym = make(n);
            let amp = amplification(&sym);
            if amp > worst {
                worst = amp;
                worst_sym = sym.clone();
            }
            checked += 1;
        }
    }

    assert!(checked == 35, "expected 35 cases, checked {checked}");
    assert!(
        worst < 50.0,
        "amplification x{worst:.1} on a {}-byte input ({worst_sym}) — a reuse rule \
         has started expanding super-linearly",
        worst_sym.len()
    );
    // Vacuity: if nothing decoded, every ratio would be 0 and the bound would hold
    // trivially.
    assert!(
        worst > 2.0,
        "worst amplification is only x{worst:.1} — the carriers stopped decoding, \
         so this bound is vacuous"
    );
}

/// The compounding shape: one large real expansion, referenced many times.
///
/// This is the quadratic candidate — output would be `size_of_expansion x
/// references` from an input that is only `size + references`. Uses the **longest
/// real corpus symbol** as the base, so the expansion is genuinely large rather
/// than something I hand-built.
#[test]
fn referencing_a_large_expansion_many_times_does_not_blow_up() {
    let longest = include_str!("data/real_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|s| s.starts_with("_Z"))
        .max_by_key(|s| s.len())
        .expect("the corpus must hold Itanium symbols");

    // Premise: the base itself amplifies modestly.
    let base_amp = amplification(longest);
    assert!(
        base_amp > 1.0 && base_amp < 20.0,
        "unexpected base amplification x{base_amp:.1} for {longest}"
    );

    for refs in [1usize, 8, 64, 512, 4096] {
        let sym = format!("{}{}", longest.trim_end_matches('E'), "S1_".repeat(refs));
        let amp = amplification(&sym);
        assert!(
            amp < 50.0,
            "x{amp:.1} amplification with {refs} references — the compounding shape \
             now expands"
        );
    }
}
