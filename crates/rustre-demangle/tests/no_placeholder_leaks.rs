//! An internal parser marker must never reach a caller.
//!
//! Every parser in this crate has private "I could not read this" markers.
//! Reaching output turns one into a claim: `?SPECIAL(4)` and `~<dtor>(void)` are
//! not names, and a consumer cannot tell them from a decode. The live path
//! already refuses them — the D `?`-placeholder rule and the Swift `?module`
//! rule both decline rather than emit — but that was only enforced per-ABI, at
//! the point each rule was added.
//!
//! This is the crate-wide version, over both real corpora (3161 symbols).
//! Measured on 2026-07-30:
//!
//! | entry point | decoded | leaks |
//! |---|---|---|
//! | `crate::demangle` | 3161 | **0** |
//! | `cpp_demangler::demangle_cpp` | 829 | **0** |
//! | `demangler_dispatcher::auto_demangle` | 1233 | **0** |
//! | `itanium_full` | 502 | 89 |
//! | `msvc_full` | 14 | 4 |
//!
//! So the class is confined to the two unwired modules already pinned by
//! `tests/itanium_full_accuracy.rs` and `tests/msvc_full_accuracy.rs`, and the
//! three paths callers actually reach are clean across 5223 decodes.
//!
//! The two leaky modules are pinned rather than fixed: they are public API with
//! callers in other crates, and whether to repair, delegate or retire them is an
//! open decision. What this file adds is the guarantee that the leak does not
//! *spread* — a new marker escaping into `crate::demangle` fails here.

/// Markers produced by this crate's own parsers when they give up.
///
/// `S0.` is the Swift substitution index that used to leak (iter 6);
/// `U+FFFD` is what `from_utf8_lossy` leaves behind. Both are kept even though
/// they are currently unreachable — a marker list is only useful if it outlives
/// the specific bug that motivated each entry.
const MARKERS: &[&str] = &[
    "<dtor>",
    "?SPECIAL",
    "?module",
    "?(",
    "<invalid>",
    "\u{fffd}",
    "S0.",
];

fn corpus() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

fn leaked(d: &str) -> Option<&'static str> {
    MARKERS.iter().copied().find(|m| d.contains(m))
}

/// The paths a caller reaches must be clean.
#[test]
fn no_live_entry_point_leaks_an_internal_marker() {
    type Entry = (&'static str, fn(&str) -> Option<String>);
    let entries: &[Entry] = &[
        ("crate::demangle", |s| {
            rustre_demangle::demangle(s).map(|r| r.demangled)
        }),
        ("cpp_demangler::demangle_cpp", |s| {
            rustre_demangle::cpp_demangler::demangle_cpp(s).ok()
        }),
        ("demangler_dispatcher::auto_demangle", |s| {
            let d = rustre_demangle::demangler_dispatcher::auto_demangle(s);
            (d != s).then_some(d)
        }),
    ];

    let syms = corpus();
    for (name, f) in entries {
        let mut decoded = 0;
        let mut leaks: Vec<String> = Vec::new();
        for s in &syms {
            if let Some(d) = f(s) {
                decoded += 1;
                if let Some(m) = leaked(&d) {
                    leaks.push(format!("[{m}] {s} -> {d}"));
                }
            }
        }
        // Per-entry-point vacuity: a path that stops decoding would otherwise
        // pass by emitting nothing at all.
        assert!(
            decoded > 700,
            "{name} decoded only {decoded} of {} — the guard is vacuous",
            syms.len()
        );
        assert!(
            leaks.is_empty(),
            "{name} leaked {} internal markers; first 5: {:#?}",
            leaks.len(),
            &leaks[..leaks.len().min(5)]
        );
    }
}

/// The two unwired modules leak, and the counts are pinned so it cannot grow.
///
/// Deliberately an upper bound, not an equality: repairing either module is
/// welcome and should re-baseline this, while a new leak fails it.
#[test]
fn the_unwired_modules_leak_no_more_than_measured() {
    let syms = corpus();

    let mut itanium_decoded = 0;
    let mut itanium_leaks = 0;
    let mut msvc_decoded = 0;
    let mut msvc_leaks = 0;

    for s in &syms {
        if let Ok(d) = rustre_demangle::itanium_full::ItaniumDemangler::demangle(s) {
            itanium_decoded += 1;
            if leaked(&d).is_some() {
                itanium_leaks += 1;
            }
        }
        let m = rustre_demangle::msvc_full::msvc_demangle(s);
        if m != *s {
            msvc_decoded += 1;
            if leaked(&m).is_some() {
                msvc_leaks += 1;
            }
        }
    }

    assert!(
        itanium_decoded > 400 && msvc_decoded > 10,
        "vacuous: itanium_full {itanium_decoded}, msvc_full {msvc_decoded}"
    );
    assert!(
        itanium_leaks <= 89,
        "itanium_full leaks grew: {itanium_leaks} (was 89 of {itanium_decoded})"
    );
    assert!(
        msvc_leaks <= 4,
        "msvc_full leaks grew: {msvc_leaks} (was 4 of {msvc_decoded})"
    );
}
