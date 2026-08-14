//! `cpp_demangler` must keep agreeing with the live path.
//!
//! This is the one alternative entry point measured *healthy*: over the real
//! corpora it matches `crate::demangle` on 815/815 Itanium symbols (differing
//! only on 2 legacy-Rust hash renderings) and 32/32 MSVC ones. It has ~12 call
//! sites in other workspace crates.
//!
//! The others drifted precisely because nothing checked them:
//! `demangler_registry` still carries a `_R` false positive fixed in the live
//! path, `Demangler2` never received Go support, `rust_demangler` is correct on
//! 0 of 135 real v0 symbols, and `ItaniumNativeDemangler` gets 37% of parameter
//! counts wrong. This suite exists so the healthy one does not join them.

/// MSVC shapes covering the grammar the corpora barely exercise — the corpora
/// hold only 14 MSVC symbols, too few to conclude anything alone.
const MSVC_SHAPES: &[&str] = &[
    "?foo@@YAHH@Z",
    "?foo@bar@@QEAAHXZ",
    "?name@Person@@QEBAPEBDXZ",
    "?update@Engine@@IEAAXN@Z",
    "?instance@Singleton@@SAPEAV1@XZ",
    "?draw@Shape@@UEAAXXZ",
    "??0Point@@QEAA@HH@Z",
    "??1Foo@@QEAA@XZ",
    "??2@YAPEAX_K@Z",
    "??HFoo@@QEAA?AV0@AEBV0@@Z",
    "?x@@3HA",
    "?g_name@@3PEBDEB",
    "?value@Config@@2HA",
    "??$max@H@@YAHHH@Z",
    "?push_back@?$vector@H@std@@QEAAXH@Z",
    "?get@?$array@H$09@std@@QEAAHXZ",
    "??_7Foo@@6B@",
    "?_OptionsStorage@?1??__local_stdio_printf_options@@9@4_KA",
];

fn corpora() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// Legacy Rust reuses the Itanium prefix; `crate::demangle` renders it with
/// the alternate formatter that drops the trailing `::h<16 hex>`, while
/// `cpp_demangler` keeps it. That is a deliberate presentation difference, not
/// drift, so those symbols are excluded rather than silently tolerated.
fn is_legacy_rust(s: &str) -> bool {
    s.strip_suffix('E').is_some_and(|t| {
        t.rfind("17h").is_some_and(|i| {
            t[i + 3..].len() == 16 && t[i + 3..].chars().all(|c| c.is_ascii_hexdigit())
        })
    })
}

#[test]
fn itanium_path_agrees_with_demangle() {
    let syms: Vec<&str> = corpora()
        .into_iter()
        .filter(|l| l.starts_with("_Z") || l.starts_with("__Z"))
        .filter(|l| !is_legacy_rust(l))
        .collect();
    assert!(
        syms.len() > 700,
        "expected >700 Itanium symbols, found {} — suite gone vacuous",
        syms.len()
    );

    let mismatches: Vec<(&str, String, String)> = syms
        .iter()
        .filter_map(|s| {
            let live = rustre_demangle::demangle(s)?.demangled;
            let alt = rustre_demangle::cpp_demangler::demangle_itanium(s).ok()?;
            (live != alt).then_some((*s, live, alt))
        })
        .collect();

    assert!(
        mismatches.is_empty(),
        "{} Itanium symbols drifted from the live path; first 5: {:#?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(5)]
    );
}

#[test]
fn msvc_path_agrees_with_demangle() {
    let syms: Vec<&str> = corpora()
        .into_iter()
        .filter(|l| l.starts_with('?'))
        .chain(MSVC_SHAPES.iter().copied())
        .collect();
    assert!(syms.len() > 25, "suite gone vacuous: {}", syms.len());

    let mismatches: Vec<(&str, String, String)> = syms
        .iter()
        .filter_map(|s| {
            let live = rustre_demangle::demangle(s)?.demangled;
            let alt = rustre_demangle::cpp_demangler::demangle_msvc(s).ok()?;
            (live != alt).then_some((*s, live, alt))
        })
        .collect();

    assert!(
        mismatches.is_empty(),
        "{} MSVC symbols drifted from the live path; first 5: {:#?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(5)]
    );
}
