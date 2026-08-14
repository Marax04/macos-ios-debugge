//! Differential testing against the reference demanglers.
//!
//! Hand-written expectations are error-prone: an earlier iteration of this
//! suite tracked four "bugs" that turned out to be malformed test symbols,
//! where the reference implementation produced exactly our output. This suite
//! removes that failure mode by construction — the oracle is the reference
//! crate itself (`cpp_demangle` for Itanium, `rustc-demangle` for Rust), so
//! any divergence reported here is a real difference, never a typo in an
//! expected string.
//!
//! Symbols the reference itself rejects are skipped: for those there is no
//! ground truth to compare against.

/// Itanium symbols drawn from real C++ binaries and the ABI specification.
const ITANIUM_CORPUS: &[&str] = &[
    // Free functions, builtin parameter types.
    "_Z3fooi", "_Z3foov", "_Z3fooc", "_Z3foos", "_Z3fool", "_Z3foox", "_Z3fooy",
    "_Z3foof", "_Z3food", "_Z3fooe", "_Z3foob", "_Z3fooh", "_Z3fooj", "_Z3foom",
    "_Z3fooPi", "_Z3fooPKi", "_Z3fooRi", "_Z3fooRKi", "_Z3fooOi",
    "_Z3fooPPi", "_Z3fooPPKc", "_Z3fooA10_i", "_Z3fooPFivE",
    "_Z3addii", "_Z1hic", "_Z4funcidc", "_Z1fPFivE", "_Z1fA37_iPS_",
    // Nested names and namespaces.
    "_ZN3foo3barEv", "_ZN2ns5funcsEid", "_ZN4outr5inner4funcEi",
    "_ZN9wikipedia7article6formatEv", "_ZN9wikipedia7article8print_toERSo",
    "_ZN1A1B1C1DEv", "_ZN3foo3bar3bazEiii",
    // cv-qualified members.
    "_ZNK3Foo3barEv", "_ZNK3Map4sizeEv", "_ZNV3Foo3barEv", "_ZNKV3Foo3barEv",
    // Constructors / destructors.
    "_ZN3FooC1Ev", "_ZN3FooC2Ei", "_ZN3FooD1Ev", "_ZN3FooD0Ev", "_ZN3FooD2Ev",
    // Operators.
    "_ZplRK1XS1_", "_ZN1XplERKS_", "_ZdlPv", "_Znwm", "_ZnamPv",
    "_ZN1XeqERKS_", "_ZN1XltERKS_", "_ZN1XixEi", "_ZN1XclEv", "_ZN1XppEv",
    // RTTI / vtables.
    "_ZTV3Foo", "_ZTI3Foo", "_ZTS3Foo", "_ZTV6Widget", "_ZTI6Widget",
    // Templates.
    "_Z4funcIiEvT_", "_Z3maxIiET_S0_S0_", "_Z3fooIiiEvT_T0_",
    "_ZN1N1TIiiE2mfES0_IddE", "_ZNK1C1fIiEEvv",
    // std substitutions.
    "_ZNSt6vectorIiSaIiEE9push_backERKi",
    "_ZNSt12basic_stringIcSt11char_traitsIcESaIcEE5clearEv",
    "_ZNSaIcEC1Ev", "_ZNSs4sizeEv", "_ZNSt6vectorIiSaIiEEC1Ev",
    "_ZSt4sqrtf", "_Z6promptRSt6vectorIiSaIiEE",
    "_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc",
    "_ZSt4moveIRPcENSt16remove_referenceIT_E4typeEOS3_",
    // Internal linkage, local entities, anonymous namespaces.
    "_ZL9static_fnv", "_ZL3fooi", "_ZN12_GLOBAL__N_13fooEv",
    // Substitution back-references.
    "_Z1fP1XS0_", "_Z1f1XS_", "_Z1fPK1XS1_",
];

/// Rust symbols: legacy (`_ZN…17h<hash>E`) and v0 (`_R…`).
const RUST_CORPUS: &[&str] = &[
    "_ZN4core3fmt9Formatter3pad17h1234567890abcdefE",
    "_ZN4core3ptr13drop_in_place17h1234567890abcdefE",
    "_ZN3std2io5stdio6_print17h1234567890abcdefE",
    "_ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$7reserve17h1234567890abcdefE",
    "_ZN41_$LT$Test$u20$as$u20$core..fmt..Debug$GT$3fmt17h1234567890abcdefE",
    "_ZN4testE",
    "_RNvC6_123foo3bar",
    "_RNvCs1234_7mycrate3foo",
    "_RNvNtC8my_crate6module8function",
    "_RINvNtC3std3mem8align_ofjE",
    "_RNvMC0INtC8my_crate3FooiE3bar",
    "_RNvNtCs1234_7mycrate3foo3bar",
];

fn itanium_reference(sym: &str) -> Option<String> {
    let parsed = cpp_demangle::BorrowedSymbol::new(sym.as_bytes()).ok()?;
    parsed
        .demangle(&cpp_demangle::DemangleOptions::default())
        .ok()
}

/// `cpp_demangle` renders RTTI/vtable entities as `{vtable(T)}`; the crate
/// normalises these to the `c++filt` wording. Apply the same normalisation to
/// the reference so the comparison comes down to actual demangling, not
/// presentation.
fn normalise_reference(raw: &str) -> String {
    let s = raw.trim();
    if let Some(body) = s.strip_prefix('{').and_then(|t| t.strip_suffix('}'))
        && let Some(open) = body.find('(')
        && body.ends_with(')')
    {
        let label = match body[..open].trim() {
            "vtable" => Some("vtable for"),
            "vtt" | "VTT" => Some("VTT for"),
            "typeinfo" => Some("typeinfo for"),
            "typeinfo name" => Some("typeinfo name for"),
            "construction vtable" => Some("construction vtable for"),
            _ => None,
        };
        if let Some(lbl) = label {
            return format!("{lbl} {}", &body[open + 1..body.len() - 1]);
        }
    }
    raw.to_owned()
}

#[test]
fn differential_itanium_matches_reference() {
    let mut mismatches = Vec::new();
    let mut compared = 0usize;
    let mut skipped = 0usize;

    for sym in ITANIUM_CORPUS {
        let Some(reference) = itanium_reference(sym).map(|r| normalise_reference(&r)) else {
            // No ground truth: the reference rejects this symbol too.
            skipped += 1;
            continue;
        };
        compared += 1;
        match rustre_demangle::demangle(sym) {
            Some(ours) if ours.demangled == reference => {}
            Some(ours) => mismatches.push(format!(
                "  {sym}\n    reference: {reference}\n    ours:      {}",
                ours.demangled
            )),
            None => mismatches.push(format!(
                "  {sym}\n    reference: {reference}\n    ours:      <None>"
            )),
        }
    }

    println!("itanium differential: {compared} compared, {skipped} skipped (reference rejects)");
    assert!(
        mismatches.is_empty(),
        "{} of {compared} Itanium symbols differ from cpp_demangle:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
fn differential_rust_matches_reference() {
    let mut mismatches = Vec::new();
    let mut compared = 0usize;
    let mut skipped = 0usize;

    for sym in RUST_CORPUS {
        let Ok(reference) = rustc_demangle::try_demangle(sym) else {
            skipped += 1;
            continue;
        };
        // `{:#}` selects the alternate form, which omits the trailing hash —
        // the same convention the crate applies.
        let reference = format!("{reference:#}");
        compared += 1;
        match rustre_demangle::demangle(sym) {
            Some(ours) if ours.demangled == reference => {}
            Some(ours) => mismatches.push(format!(
                "  {sym}\n    reference: {reference}\n    ours:      {}",
                ours.demangled
            )),
            None => mismatches.push(format!(
                "  {sym}\n    reference: {reference}\n    ours:      <None>"
            )),
        }
    }

    println!("rust differential: {compared} compared, {skipped} skipped (reference rejects)");
    assert!(
        mismatches.is_empty(),
        "{} of {compared} Rust symbols differ from rustc-demangle:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// MSVC symbols spanning free functions, member functions, ctors/dtors,
/// data symbols and RTTI.
const MSVC_CORPUS: &[&str] = &[
    "?foo@@YAHH@Z",
    "?value@@YAHXZ",
    "?print@@YAXPEBD@Z",
    "??2@YAPEAX_K@Z",
    "??3@YAXPEAX@Z",
    "?foo@bar@@QEAAHXZ",
    "?func@MyClass@@QEAAHH@Z",
    "??0Foo@@QEAA@XZ",
    "??1Foo@@QEAA@XZ",
    "?name@Person@@QEBAPEBDXZ",
    "?bar@Foo@ns@@QEAAXXZ",
    "?GetValue@Widget@ns@@QEBAHXZ",
    "?x@@3HA",
    "??_7Foo@@6B@",
];

/// The crate exposes two public MSVC entry points. They must not disagree.
///
/// They once did, on 10 of these 14 symbols: `msvc_demangler` carried an
/// unfixed copy of the `this`-pointer-modifier bug, so it rendered
/// `?foo@bar@@QEAAHXZ` as `void& __cdecl bar::foo(void)` while the dispatcher
/// rendered the correct `public: int __cdecl bar::foo(void)`.
#[test]
fn msvc_public_paths_agree() {
    let mut mismatches = Vec::new();
    for sym in MSVC_CORPUS {
        let via_dispatcher = rustre_demangle::demangle(sym).map(|r| r.demangled);
        let raw = rustre_demangle::msvc_demangler::MsvcDemangler::demangle_to_string(sym);
        // The standalone API echoes the input when it cannot decode.
        let via_msvc = if raw == **sym { None } else { Some(raw) };
        if via_dispatcher != via_msvc {
            mismatches.push(format!(
                "  {sym}\n    demangle():      {via_dispatcher:?}\n    msvc_demangler:  {via_msvc:?}"
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} MSVC symbols differ between the two public paths:\n{}",
        mismatches.len(),
        MSVC_CORPUS.len(),
        mismatches.join("\n")
    );
}

/// Every public string-returning path for a given ABI must return the same
/// answer for the same symbol.
///
/// This crate accumulated several parsers per ABI, and fixing one used to
/// leave the others rendering different results from the same public surface.
/// A systematic audit once found 8 of 13 symbol groups diverging: a third
/// MSVC parser turned the data symbol `?x@@3HA` into `x()`, the D wrapper
/// emitted `main.foo -> ?(F)`, and the Rust v0 wrapper kept the crate
/// disambiguator (`mycrate[3c1c0]::foo`) that the rest of the crate strips.
///
/// Deliberate differences are excluded explicitly rather than silently: a
/// *v0* demangler correctly declines a *legacy* symbol.
/// Push a mismatch entry when the public paths in `paths` disagree.
fn check_agreement(
    label: &str,
    sym: &str,
    paths: &[(&str, Option<String>)],
    mismatches: &mut Vec<String>,
) {
    if let Some((_, first)) = paths.first()
        && !paths.iter().all(|(_, v)| v == first)
    {
        mismatches.push(format!("  [{label}] {sym}: {paths:?}"));
    }
}

#[test]
fn all_public_paths_agree_per_abi() {
    fn norm(v: Option<String>, input: &str) -> Option<String> {
        // Some APIs echo the input when they cannot decode it.
        v.filter(|s| s != input && !s.is_empty())
    }

    let mut mismatches = Vec::new();

    for sym in [
        "_ZN3foo3barEv",
        "_Z3fooi",
        "_ZNSt6vectorIiSaIiEE9push_backERKi",
        "_ZTV3Foo",
        "_ZN3FooC1Ev",
    ] {
        let paths = [
            ("demangle()", norm(rustre_demangle::demangle(sym).map(|r| r.demangled), sym)),
            (
                "cpp_demangler::demangle_itanium",
                norm(rustre_demangle::cpp_demangler::demangle_itanium(sym).ok(), sym),
            ),
            (
                "cpp_demangler::demangle_cpp",
                norm(rustre_demangle::cpp_demangler::demangle_cpp(sym).ok(), sym),
            ),
        ];
        check_agreement("itanium", sym, &paths, &mut mismatches);
    }

    for sym in ["?foo@bar@@QEAAHXZ", "?foo@@YAHH@Z", "?x@@3HA", "??0Foo@@QEAA@XZ"] {
        let paths = [
            ("demangle()", norm(rustre_demangle::demangle(sym).map(|r| r.demangled), sym)),
            (
                "msvc_demangler",
                norm(
                    Some(rustre_demangle::msvc_demangler::MsvcDemangler::demangle_to_string(sym)),
                    sym,
                ),
            ),
            (
                "cpp_demangler::demangle_msvc",
                norm(rustre_demangle::cpp_demangler::demangle_msvc(sym).ok(), sym),
            ),
            (
                "cpp_demangler::demangle_cpp",
                norm(rustre_demangle::cpp_demangler::demangle_cpp(sym).ok(), sym),
            ),
        ];
        check_agreement("msvc", sym, &paths, &mut mismatches);
    }

    // Rust: only v0 symbols, since `RustV0Demangler` deliberately declines
    // legacy `_ZN…17h…E` names.
    for sym in ["_RNvCs1234_7mycrate3foo", "_RNvC6_123foo3bar"] {
        let paths = [
            ("demangle()", norm(rustre_demangle::demangle(sym).map(|r| r.demangled), sym)),
            (
                "RustV0Demangler",
                norm(rustre_demangle::RustV0Demangler::demangle(sym), sym),
            ),
        ];
        check_agreement("rust v0", sym, &paths, &mut mismatches);
    }

    // Swift: the dispatcher, the heuristic helper and the module-level
    // renderer are all public string-returning paths.
    for sym in ["$s4main3fooyyF", "$s10Foundation4DataV5countSivg"] {
        let paths = [
            ("demangle()", norm(rustre_demangle::demangle(sym).map(|r| r.demangled), sym)),
            (
                "swift_demangle",
                norm(Some(rustre_demangle::swift_demangler::swift_demangle(sym)), sym),
            ),
        ];
        check_agreement("swift", sym, &paths, &mut mismatches);
    }

    // Go: the dispatcher vs the structured decoder's rendered form.
    for sym in ["main.main", "runtime.mallocgc", "main.Map[go.shape.int].Get"] {
        let paths = [
            ("demangle()", norm(rustre_demangle::demangle(sym).map(|r| r.demangled), sym)),
            (
                "decode_go_symbol",
                norm(
                    rustre_demangle::go_demangler::decode_go_symbol(sym, true)
                        .map(|s| s.demangled),
                    sym,
                ),
            ),
        ];
        check_agreement("go", sym, &paths, &mut mismatches);
    }

    for sym in ["_D4main3fooFZv", "_D3app4funcFiZi"] {
        let paths = [
            ("demangle()", norm(rustre_demangle::demangle(sym).map(|r| r.demangled), sym)),
            (
                "DDemangler",
                norm(rustre_demangle::DDemangler::demangle(sym), sym),
            ),
        ];
        check_agreement("d", sym, &paths, &mut mismatches);
    }

    assert!(
        mismatches.is_empty(),
        "{} symbol groups diverge across public paths:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// A *v0* demangler must decline a *legacy* symbol: this asymmetry is
/// intentional and is asserted so it cannot silently change.
#[test]
fn rust_v0_demangler_declines_legacy_symbols() {
    let legacy = "_ZN4core3fmt9Formatter3pad17h1234567890abcdefE";
    assert!(
        rustre_demangle::RustV0Demangler::demangle(legacy).is_none(),
        "RustV0Demangler should not claim legacy symbols"
    );
    assert!(
        rustre_demangle::demangle(legacy).is_some(),
        "the dispatcher must still handle legacy symbols"
    );
}

/// The consolidated Itanium entry point must agree with the top-level
/// dispatcher: two public paths to the same answer must not disagree.
#[test]
fn differential_internal_paths_agree() {
    let mut mismatches = Vec::new();
    for sym in ITANIUM_CORPUS {
        if itanium_reference(sym).is_none() {
            continue;
        }
        let via_dispatcher = rustre_demangle::demangle(sym).map(|r| r.demangled);
        let via_cpp = rustre_demangle::cpp_demangler::demangle_itanium(sym).ok();
        if let (Some(a), Some(b)) = (&via_dispatcher, &via_cpp)
            && a != b
        {
            mismatches.push(format!("  {sym}\n    demangle():        {a}\n    demangle_itanium(): {b}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} symbols where the two public Itanium paths disagree:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
