//! Does the unwired `msvc_full` parser decode anything the live path cannot?
//!
//! `msvc_full` is public API documented as extending the basic MSVC demangler
//! with every calling convention, templates, nested classes, lambdas, RTTI and
//! `__declspec`. Nothing in the crate calls it: `demangle()` routes MSVC
//! symbols through `backends::demangle_msvc_internal` instead, and no other
//! module references `msvc_full::` at all.
//!
//! That matters because a gap in the live path was found on 2026-07-23 —
//! function-local statics (`?x@?1??enclosing@@9@4_KA`) — and had to be
//! implemented from scratch. If the unwired parser already handled shapes the
//! live one declines, the crate is carrying capability it never offers.
//!
//! This suite measures that rather than asserting a preference: which symbols
//! each path decodes, over the real corpora.

/// The corpora hold only 14 MSVC symbols, which is too few to conclude
/// anything: `msvc_full` advertises templates, calling conventions, nested
/// classes, lambdas and RTTI, and the real corpus exercises almost none of
/// them. These shapes come from `differential_msvc.rs`, where they are already
/// validated against the reference engine, so the comparison covers what the
/// unwired parser actually claims to add.
const MSVC_SHAPES: &[&str] = &[
    // Calling conventions and access specifiers.
    "?foo@@YAHH@Z",
    "?foo@bar@@QEAAHXZ",
    "?name@Person@@QEBAPEBDXZ",
    "?update@Engine@@IEAAXN@Z",
    "?reset@State@@AEAAXXZ",
    "?instance@Singleton@@SAPEAV1@XZ",
    "?draw@Shape@@UEAAXXZ",
    // Constructors, destructors, operators.
    "??0Point@@QEAA@HH@Z",
    "??1Foo@@QEAA@XZ",
    "??2@YAPEAX_K@Z",
    "??HFoo@@QEAA?AV0@AEBV0@@Z",
    // Data symbols.
    "?x@@3HA",
    "?g_name@@3PEBDEB",
    "?value@Config@@2HA",
    // Templates, including non-type arguments.
    "??$max@H@@YAHHH@Z",
    "?push_back@?$vector@H@std@@QEAAXH@Z",
    "?get@?$array@H$09@std@@QEAAHXZ",
    "?f@?$A@$0?4@@QEAAHXZ",
    // Vftables and function-local statics.
    "??_7Foo@@6B@",
    "?_OptionsStorage@?1??__local_stdio_printf_options@@9@4_KA",
];

fn msvc_symbols() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| l.starts_with('?'))
        .chain(MSVC_SHAPES.iter().copied())
        .collect()
}

/// `msvc_full::msvc_demangle` returns the input unchanged when it cannot
/// parse, so "decoded" means "returned something different".
fn full_decodes(s: &str) -> bool {
    rustre_demangle::msvc_full::msvc_demangle(s) != s
}

/// Report what each path handles, and fail only if the unwired parser is
/// strictly better on some symbol — that would be unused capability.
#[test]
fn live_path_is_not_beaten_by_the_unwired_parser() {
    let syms = msvc_symbols();
    assert!(
        !syms.is_empty(),
        "expected MSVC symbols in the corpora — the PDB corpus carries them"
    );

    let mut live_only = Vec::new();
    let mut full_only = Vec::new();
    let mut both = 0usize;
    for s in &syms {
        let live = rustre_demangle::demangle(s).is_some();
        let full = full_decodes(s);
        match (live, full) {
            (true, true) => both += 1,
            (true, false) => live_only.push(*s),
            (false, true) => full_only.push(*s),
            (false, false) => {}
        }
    }

    println!(
        "{} MSVC symbols: {both} both, {} live only, {} full only",
        syms.len(),
        live_only.len(),
        full_only.len()
    );
    for s in &live_only {
        println!("  live only: {s}");
    }

    assert!(
        full_only.is_empty(),
        "{} symbols decode only through the unwired `msvc_full`, i.e. the \
         crate carries capability `demangle()` does not offer; first 10: {:#?}",
        full_only.len(),
        &full_only[..full_only.len().min(10)]
    );
}
