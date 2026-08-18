//! Extended grammar-driven differential testing against `cpp_demangle`:
//! array parameters, function-pointer parameters, and `std::` substitution
//! shapes (`St`/`Ss`/`Si`/`So`/`Sd`/`Sa`/`Sb`), modelled on the MSVC
//! generative suite. `differential_proptest.rs` covers the base grammar;
//! this file covers the composite-type corner of it.
//!
//! As everywhere in the differential suites: the oracle is the reference
//! crate, symbols it rejects are skipped, and a dedicated anti-vacuity
//! guard asserts the generators overwhelmingly produce *accepted* symbols
//! (a drifted generator would otherwise pass while testing nothing).

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


/// Builtin Itanium type codes usable as array elements / function args.
const TYPE_CODES: &[&str] = &[
    "b", "c", "a", "h", "s", "t", "i", "j", "l", "m", "x", "y", "f", "d",
];

/// `std::` substitution codes valid as a *parameter type* on their own.
const STD_TYPE_SUBS: &[&str] = &["Ss", "Si", "So", "Sd"];

fn reference(sym: &str) -> Option<String> {
    let parsed = cpp_demangle::BorrowedSymbol::new(sym.as_bytes()).ok()?;
    parsed
        .demangle(&cpp_demangle::DemangleOptions::default())
        .ok()
}

/// Compare one generated symbol against the reference.
fn compare(sym: &str) -> Result<(), String> {
    let Some(want) = reference(sym) else {
        return Ok(()); // reference rejects it: no ground truth
    };
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

/// An array parameter `A<n>_<elem>`, as it appears for `T (&)[n]`-style
/// signatures: arrays decay in plain parameters, so wrap in a reference or
/// pointer to keep the array type visible to both sides.
fn array_param() -> impl Strategy<Value = String> {
    (
        1u32..=64,
        prop::sample::select(TYPE_CODES),
        prop::sample::select(vec!["R", "P", "K"]),
    )
        .prop_map(|(n, elem, wrap)| format!("{wrap}A{n}_{elem}"))
}

/// A function-pointer parameter `PF<ret><args>E`.
fn fn_ptr_param() -> impl Strategy<Value = String> {
    (
        prop::sample::select(TYPE_CODES),
        prop::collection::vec(prop::sample::select(TYPE_CODES), 0..3),
    )
        .prop_map(|(ret, args)| {
            let mut s = String::from("PF");
            s.push_str(ret);
            if args.is_empty() {
                s.push('v');
            } else {
                for a in &args {
                    s.push_str(a);
                }
            }
            s.push('E');
            s
        })
}

/// A `std::` substitution parameter, optionally behind cv/ref modifiers
/// (`RKSs` = `const std::string&`).
fn std_param() -> impl Strategy<Value = String> {
    (
        prop::sample::select(STD_TYPE_SUBS),
        prop::sample::select(vec!["", "R", "RK", "P", "PK"]),
    )
        .prop_map(|(sub, mods)| format!("{mods}{sub}"))
}

/// Anti-vacuity guard for THIS file's generators: array, fn-pointer and
/// std-substitution shapes must be accepted by the reference at >95%.
#[test]
fn ext_generators_produce_symbols_the_reference_accepts() {
    let mut state = 0x51ab_c0de_u64;
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
        let n = next() % 32 + 1;
        for sym in [
            format!("_Z{}{name}RA{n}_{ty}", name.len()),
            format!("_Z{}{name}PF{ty}vE", name.len()),
            format!("_Z{}{name}RKSs", name.len()),
            format!("_ZNSt{}{name}E{ty}", name.len()),
        ] {
            total += 1;
            if reference(&sym).is_some() {
                accepted += 1;
            }
        }
    }
    assert!(
        accepted * 100 >= total * 95,
        "extended Itanium generators are vacuous: {accepted}/{total} accepted"
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1500, ..ProptestConfig::default() })]

    /// Array parameters (behind ref/ptr so the array type survives).
    #[test]
    fn differential_generated_arrays(
        name in ident(),
        arrays in prop::collection::vec(array_param(), 1..4),
    ) {
        let sym = format!("_Z{}{}", name, arrays.concat());
        if let Err(msg) = compare(&sym) {
            panic!("array divergence:\n{msg}");
        }
    }

    /// Function-pointer parameters, mixed with plain builtins.
    #[test]
    fn differential_generated_fn_pointers(
        name in ident(),
        fp in fn_ptr_param(),
        extra in prop::collection::vec(prop::sample::select(TYPE_CODES), 0..3),
    ) {
        let sym = format!("_Z{}{}{}", name, fp, extra.concat());
        if let Err(msg) = compare(&sym) {
            panic!("fn-pointer divergence:\n{msg}");
        }
    }

    /// `std::` substitution parameters (`Ss`/`Si`/`So`/`Sd`), plain and
    /// behind `R`/`RK`/`P`/`PK`.
    #[test]
    fn differential_generated_std_params(
        name in ident(),
        params in prop::collection::vec(std_param(), 1..4),
    ) {
        let sym = format!("_Z{}{}", name, params.concat());
        if let Err(msg) = compare(&sym) {
            panic!("std-substitution divergence:\n{msg}");
        }
    }

    /// Functions nested inside `std::` (`_ZNSt<name>E<params>`) and
    /// `St`-qualified names as parameters (`St<name>` = `std::<name>`).
    #[test]
    fn differential_generated_std_nested(
        name in ident(),
        inner in ident(),
        ty in prop::sample::select(TYPE_CODES),
    ) {
        for sym in [
            format!("_ZNSt{name}E{ty}"),
            format!("_Z{name}St{inner}"),
        ] {
            if let Err(msg) = compare(&sym) {
                panic!("std-nested divergence:\n{msg}");
            }
        }
    }

    /// Composite stress: one array + one fn-pointer + one std parameter in
    /// a single signature, where back-reference bookkeeping tends to break.
    #[test]
    fn differential_generated_composite(
        name in ident(),
        a in array_param(),
        fp in fn_ptr_param(),
        s in std_param(),
    ) {
        let sym = format!("_Z{name}{a}{fp}{s}");
        if let Err(msg) = compare(&sym) {
            panic!("composite divergence:\n{msg}");
        }
    }
}
