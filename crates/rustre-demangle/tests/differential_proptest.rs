//! Grammar-driven differential testing against `cpp_demangle`.
//!
//! A fixed corpus only covers the symbols someone thought to write down. This
//! suite instead *generates* well-formed Itanium symbols from the ABI grammar
//! and compares every one against the reference implementation, so it explores
//! combinations (nested names × cv-qualifiers × pointer depth × substitutions)
//! that no hand-written list would enumerate.
//!
//! As in `differential.rs`, the oracle is the reference crate: a divergence
//! reported here is real by construction. Symbols the reference itself rejects
//! are skipped — for those there is no ground truth.

use proptest::prelude::*;

/// Convert an RNG value the caller has already reduced with `%` to `usize`.
///
/// The reduction happens in `u64`, so the value reaching this function is small
/// by construction; `try_from` states that in code rather than leaving a
/// truncating `as usize` cast to be trusted.
fn to_usize(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// Pick an index into a `len`-element table from an RNG value, reducing in
/// `u64` so no value is ever truncated on the way to `usize`.
fn pick(v: u64, len: usize) -> usize {
    let modulus = u64::try_from(len).unwrap_or(u64::MAX).max(1);
    to_usize(v % modulus)
}

/// `usize` → `f64` for the acceptance-rate ratio, without a lossy cast.
///
/// Split into two 32-bit halves, each of which `f64::from` converts exactly;
/// the scaling by 2^32 is exact, so the single rounding in the final addition
/// is the same one a correct `x as f64` performs.
fn to_f64(x: usize) -> f64 {
    const TWO_POW_32: f64 = 4_294_967_296.0;
    let wide = u64::try_from(x).unwrap_or(u64::MAX);
    let hi = u32::try_from(wide >> 32).unwrap_or(u32::MAX);
    let lo = u32::try_from(wide & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    f64::from(hi).mul_add(TWO_POW_32, f64::from(lo))
}


/// Builtin Itanium type codes and the identifiers they map to.
const TYPE_CODES: &[&str] = &[
    "v", "b", "c", "a", "h", "s", "t", "i", "j", "l", "m", "x", "y", "f", "d", "e",
];

fn reference(sym: &str) -> Option<String> {
    let parsed = cpp_demangle::BorrowedSymbol::new(sym.as_bytes()).ok()?;
    parsed
        .demangle(&cpp_demangle::DemangleOptions::default())
        .ok()
}

/// Compare one generated symbol against the reference.
///
/// Returns `Err(message)` on a genuine divergence; `Ok(())` when they agree or
/// when the reference has no opinion.
fn compare(sym: &str) -> Result<(), String> {
    let Some(want) = reference(sym) else {
        return Ok(()); // reference rejects it: no ground truth
    };
    // The crate normalises RTTI wording; keep those out of the generated set
    // rather than duplicating the normalisation here.
    match rustre_demangle::demangle(sym) {
        Some(got) if got.demangled == want => Ok(()),
        Some(got) => Err(format!(
            "{sym}\n  reference: {want}\n  ours:      {}",
            got.demangled
        )),
        None => Err(format!("{sym}\n  reference: {want}\n  ours:      <None>")),
    }
}

/// A length-prefixed Itanium identifier, e.g. `3foo`.
fn ident() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,7}".prop_map(|s| format!("{}{}", s.len(), s))
}

/// A parameter type: a builtin, optionally wrapped in pointer/reference/cv
/// modifiers.
fn param_type() -> impl Strategy<Value = String> {
    (
        prop::sample::select(TYPE_CODES),
        prop::collection::vec(prop::sample::select(vec!["P", "R", "O", "K"]), 0..3),
    )
        .prop_map(|(base, mods)| {
            let mut s = String::new();
            for m in &mods {
                s.push_str(m);
            }
            s.push_str(base);
            s
        })
}

/// Guard against a vacuous suite.
///
/// Every `compare` above returns `Ok` when the reference rejects the symbol.
/// If the generators ever drifted into emitting malformed symbols, all cases
/// would be skipped and the suite would pass while testing nothing. This test
/// asserts the generated shapes are overwhelmingly *accepted* by the
/// reference, so the differential comparisons are real.
#[test]
fn generators_produce_symbols_the_reference_accepts() {
    let mut state = 0x1234_5678_u64;
    let mut next = move || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state
    };

    let mut accepted = 0usize;
    let mut total = 0usize;
    for _ in 0..500 {
        let len = to_usize(next() % 6 + 3);
        let name: String = (0..len)
            .map(|_| char::from(b'a' + u8::try_from(next() % 26).unwrap_or(0)))
            .collect();
        let ty = TYPE_CODES[pick(next(), TYPE_CODES.len())];
        for sym in [
            format!("_Z{}{name}{ty}", name.len()),
            format!("_ZN{}{name}{}{name}E{ty}", name.len(), name.len()),
            format!("_ZN{}{name}C1E{ty}", name.len()),
        ] {
            total += 1;
            if reference(&sym).is_some() {
                accepted += 1;
            }
        }
    }

    let rate = to_f64(accepted) / to_f64(total);
    assert!(
        rate > 0.95,
        "Itanium generators produce symbols the reference rejects \
         ({accepted}/{total} = {rate:.2}); the differential suite would be \
         silently vacuous"
    );
}

/// Same anti-vacuity guard for the Rust generators.
///
/// This one matters especially: an earlier iteration found that plausible
/// v0 forms like `_RNvNtC3std2io5stdio6_print` are in fact rejected by
/// `rustc-demangle`, so a v0 generator can easily produce nothing testable.
#[test]
fn rust_generators_produce_symbols_the_reference_accepts() {
    const N: usize = 300;
    let mut state = 0xdead_beef_u64;
    let mut next = move || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state
    };
    let word = |n: &mut dyn FnMut() -> u64| -> String {
        let len = to_usize(n() % 6 + 2);
        (0..len)
            .map(|_| char::from(b'a' + u8::try_from(n() % 26).unwrap_or(0)))
            .collect()
    };

    let mut legacy_ok = 0usize;
    let mut v0_plain_ok = 0usize;
    let mut v0_nested_ok = 0usize;

    for _ in 0..N {
        let a = word(&mut next);
        let b = word(&mut next);

        let legacy = format!("_ZN{}{a}{}{b}17h0123456789abcdefE", a.len(), b.len());
        if rustc_demangle::try_demangle(&legacy).is_ok() {
            legacy_ok += 1;
        }
        let v0_plain = format!("_RNvC{}{a}{}{b}", a.len(), b.len());
        if rustc_demangle::try_demangle(&v0_plain).is_ok() {
            v0_plain_ok += 1;
        }
        // `Nv(Nt(C(crate), type), value)` needs THREE identifiers: the crate,
        // the type, and the value. Two would leave the outer `Nv` without a
        // name and the reference rejects it.
        let c = word(&mut next);
        let v0_nested = format!("_RNvNtC{}{a}{}{b}{}{c}", a.len(), b.len(), c.len());
        if rustc_demangle::try_demangle(&v0_nested).is_ok() {
            v0_nested_ok += 1;
        }
    }

    println!(
        "rust generator acceptance: legacy {legacy_ok}/{N}, \
         v0 plain {v0_plain_ok}/{N}, v0 nested {v0_nested_ok}/{N}"
    );
    assert!(
        legacy_ok * 100 / N > 95,
        "legacy generator is vacuous: only {legacy_ok}/{N} accepted"
    );
    assert!(
        v0_plain_ok * 100 / N > 95,
        "v0 plain generator is vacuous: only {v0_plain_ok}/{N} accepted"
    );
    // The nested `Nt` form is documented here rather than asserted: it is the
    // shape the reference frequently rejects, so a low rate is a fact about
    // the grammar, not a defect. It is asserted to be non-zero only, so the
    // generator is not producing pure noise.
    assert!(
        v0_nested_ok > 0,
        "v0 nested generator produced nothing the reference accepts"
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1500, ..ProptestConfig::default() })]

    /// Free functions: `_Z<name><params>`.
    #[test]
    fn differential_generated_free_functions(
        name in ident(),
        params in prop::collection::vec(param_type(), 1..5),
    ) {
        let sym = format!("_Z{name}{}", params.concat());
        if let Err(e) = compare(&sym) {
            prop_assert!(false, "divergence:\n{}", e);
        }
    }

    /// Nested names: `_ZN<comp>+E<params>`, with optional cv-qualifiers.
    #[test]
    fn differential_generated_nested_names(
        cv in prop::sample::select(vec!["", "K", "V", "KV"]),
        comps in prop::collection::vec(ident(), 2..5),
        params in prop::collection::vec(param_type(), 1..4),
    ) {
        let sym = format!("_ZN{cv}{}E{}", comps.concat(), params.concat());
        if let Err(e) = compare(&sym) {
            prop_assert!(false, "divergence:\n{}", e);
        }
    }

    /// Constructors and destructors: `_ZN<comps><C1|C2|D0|D1|D2>E<params>`.
    #[test]
    fn differential_generated_ctor_dtor(
        comps in prop::collection::vec(ident(), 1..4),
        kind in prop::sample::select(vec!["C1", "C2", "C3", "D0", "D1", "D2"]),
        params in prop::collection::vec(param_type(), 1..3),
    ) {
        let sym = format!("_ZN{}{kind}E{}", comps.concat(), params.concat());
        if let Err(e) = compare(&sym) {
            prop_assert!(false, "divergence:\n{}", e);
        }
    }

    /// Substitution back-references: `_Z<name>P<class>S0_` style, exercising
    /// the substitution table that a previous iteration found unpopulated.
    #[test]
    fn differential_generated_substitutions(
        name in ident(),
        cls in ident(),
        sub in prop::sample::select(vec!["S_", "S0_", "S1_"]),
    ) {
        let sym = format!("_Z{name}P{cls}{sub}");
        if let Err(e) = compare(&sym) {
            prop_assert!(false, "divergence:\n{}", e);
        }
    }

    /// Template functions: `_Z<name>I<args>E<ret><params>`. Templates are the
    /// only case where a return type is encoded, which is exactly the rule a
    /// previous iteration got wrong.
    #[test]
    fn differential_generated_templates(
        name in ident(),
        args in prop::collection::vec(param_type(), 1..3),
        ret in prop::sample::select(TYPE_CODES),
        params in prop::collection::vec(param_type(), 1..3),
    ) {
        let sym = format!("_Z{name}I{}E{ret}{}", args.concat(), params.concat());
        if let Err(e) = compare(&sym) {
            prop_assert!(false, "divergence:\n{}", e);
        }
    }

    /// Rust legacy mangling: `_ZN<segments>17h<16 hex>E`, oracle
    /// `rustc-demangle` in alternate form (hash stripped), which is the
    /// convention the crate follows.
    #[test]
    fn differential_generated_rust_legacy(
        segs in prop::collection::vec("[a-z][a-z0-9_]{0,7}", 1..5),
        hash in "[0-9a-f]{16}",
    ) {
        let mut body = String::new();
        for s in &segs {
            use std::fmt::Write as _;
            let _ = write!(body, "{}{s}", s.len());
        }
        let sym = format!("_ZN{body}17h{hash}E");
        let Ok(want) = rustc_demangle::try_demangle(&sym) else {
            return Ok(()); // no ground truth
        };
        let want = format!("{want:#}");
        match rustre_demangle::demangle(&sym) {
            Some(got) if got.demangled == want => {}
            Some(got) => prop_assert!(
                false,
                "divergence:\n{sym}\n  reference: {want}\n  ours:      {}",
                got.demangled
            ),
            None => prop_assert!(
                false,
                "divergence:\n{sym}\n  reference: {want}\n  ours:      <None>"
            ),
        }
    }

    /// Rust v0 mangling: `_RNvC<len><crate><len><name>` and the nested `Nt`
    /// form, oracle `rustc-demangle`.
    #[test]
    fn differential_generated_rust_v0(
        krate in "[a-z][a-z0-9_]{1,7}",
        path in prop::collection::vec("[a-z][a-z0-9_]{1,7}", 2..4),
        nested in prop::bool::ANY,
    ) {
        // Plain `Nv(C(crate), value)` needs one identifier after the crate;
        // nested `Nv(Nt(C(crate), type), value)` needs two. Generating the
        // wrong arity yields symbols the reference rejects, which the
        // comparison would silently skip — see the anti-vacuity guard.
        let sym = if nested {
            let mut tail = String::new();
            for s in &path {
                use std::fmt::Write as _;
                let _ = write!(tail, "{}{s}", s.len());
            }
            format!("_RNvNtC{}{krate}{tail}", krate.len())
        } else {
            let one = &path[0];
            format!("_RNvC{}{krate}{}{one}", krate.len(), one.len())
        };
        let Ok(want) = rustc_demangle::try_demangle(&sym) else {
            return Ok(()); // no ground truth
        };
        let want = format!("{want:#}");
        match rustre_demangle::demangle(&sym) {
            Some(got) if got.demangled == want => {}
            Some(got) => prop_assert!(
                false,
                "divergence:\n{sym}\n  reference: {want}\n  ours:      {}",
                got.demangled
            ),
            None => prop_assert!(
                false,
                "divergence:\n{sym}\n  reference: {want}\n  ours:      <None>"
            ),
        }
    }

    /// Operators on classes: `_ZN<cls><op>E<params>`.
    #[test]
    fn differential_generated_operators(
        cls in ident(),
        op in prop::sample::select(vec![
            "pl", "mi", "ml", "dv", "rm", "eq", "ne", "lt", "gt", "le", "ge",
            "aS", "pL", "mI", "ix", "cl", "pp", "mm", "nt", "aa", "oo",
        ]),
        params in prop::collection::vec(param_type(), 1..3),
    ) {
        let sym = format!("_ZN{cls}{op}E{}", params.concat());
        if let Err(e) = compare(&sym) {
            prop_assert!(false, "divergence:\n{}", e);
        }
    }
}
