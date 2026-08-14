//! `msvc_full` measured against the MSVC oracle for the first time.
//!
//! `msvc_full` is public API advertising every calling convention, templates,
//! nested classes, lambdas, RTTI and `__declspec`. `tests/unused_msvc_full.rs`
//! already measures *which* symbols each path decodes; nothing measured whether
//! `msvc_full` is **right**. It was the last row in the crate CLAUDE.md's
//! accuracy table with a caller count but no accuracy figure — the same gap that
//! hid `itanium_full` at 91/813 (see `tests/itanium_full_accuracy.rs`).
//!
//! MSVC is the lucky ABI here: `msvc-demangler` is a real oracle, so this is
//! measured against ground truth rather than against the live path.
//!
//! Measured on 2026-07-30 over the 20 curated shapes in `unused_msvc_full.rs`
//! plus every `?`-prefixed symbol in `pdb_symbols.txt`, keeping the 33 the
//! oracle has an opinion on:
//!
//! | | count |
//! |---|---|
//! | live path agrees with the oracle | **33 / 33** |
//! | `msvc_full` agrees | 16 |
//! | `msvc_full` disagrees | 16 |
//! | `msvc_full` echoes its input | 1 |
//!
//! Two of the disagreements are substantive, and the second is the interesting
//! one:
//!
//! * **A parser marker reaches the output.** `??_Etype_info@@UEAAPEAXI@Z` and
//!   `??_G…` render `?SPECIAL(4)` — the parser's internal tag, not a name. Same
//!   class as `itanium_full`'s `<dtor>`.
//! * **The 2026-07-23 RTTI fix never propagated.** The crate CLAUDE.md records
//!   that RTTI descriptors used to be "character-scraped into fabricated fields"
//!   and that `??_R1` now decodes by grammar to four signed MSVC numbers,
//!   `(0,-1,0,64)`. The live path does. `msvc_full` still scrapes:
//!   `RTTI Base Class Descriptor at type_info::EA::A::ctor::A`. **One rule, two
//!   copies, only one updated** — this crate's recurring shape, in the module
//!   nobody had measured.
//!
//! The remaining differences are presentation (`` `vftable for Foo' `` where the
//! oracle writes ``const Foo::`vftable' ``), which this suite counts but does not
//! treat as a defect class.
//!
//! No preference is asserted between fixing `msvc_full`, making it delegate, or
//! removing it: it is public API with callers outside this crate. The figures are
//! pinned so that decision rests on measurement, and so the module cannot get
//! quietly worse.

mod msvc_oracle;

use msvc_oracle::{normalise, reference};

/// Curated shapes plus every real MSVC symbol, deduplicated.
fn symbols() -> Vec<String> {
    let mut v: Vec<String> = MSVC_SHAPES.iter().map(|s| (*s).to_owned()).collect();
    for s in include_str!("data/pdb_symbols.txt").lines().map(str::trim) {
        if s.starts_with('?') {
            v.push(s.to_owned());
        }
    }
    v.sort();
    v.dedup();
    v
}

/// The shapes `msvc_full` claims to add, mirrored from `unused_msvc_full.rs`.
const MSVC_SHAPES: &[&str] = &[
    "?foo@@YAHH@Z",
    "?foo@bar@@QEAAHXZ",
    "?name@Person@@QEBAPEBDXZ",
    "?update@Engine@@IEAAXN@Z",
    "?reset@State@@AEAAXXZ",
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
    "?f@?$A@$0?4@@QEAAHXZ",
    "??_7Foo@@6B@",
    "?_OptionsStorage@?1??__local_stdio_printf_options@@9@4_KA",
];

#[test]
fn msvc_full_accuracy_is_pinned() {
    let syms = symbols();
    let (mut compared, mut live_ok, mut full_ok, mut full_bad, mut echoed) = (0, 0, 0, 0, 0);

    for s in &syms {
        let Some(want) = reference(s) else {
            continue; // no ground truth
        };
        compared += 1;
        let w = normalise(&want);

        if rustre_demangle::demangle(s).is_some_and(|r| normalise(&r.demangled) == w) {
            live_ok += 1;
        }

        let full = rustre_demangle::msvc_full::msvc_demangle(s);
        if full == *s {
            echoed += 1;
        } else if normalise(&full) == w {
            full_ok += 1;
        } else {
            full_bad += 1;
        }
    }

    assert!(compared >= 30, "suite gone vacuous: only {compared} symbols compared");
    assert_eq!(compared, full_ok + full_bad + echoed, "counts must partition");

    // The live path is the reason this is a finding about `msvc_full` and not
    // about the oracle: it agrees on every symbol.
    assert_eq!(
        live_ok, compared,
        "the LIVE path regressed: {live_ok} of {compared} agree with the oracle"
    );

    assert!(
        full_ok >= 15,
        "msvc_full agreement regressed: {full_ok} of {compared} (was 16)"
    );
    assert!(
        full_bad <= 18,
        "msvc_full disagreements grew: {full_bad} (was 16)"
    );
}

/// The two substantive defect classes, as concrete cases.
///
/// Asserted so that *fixing* `msvc_full` fails here and says what changed.
#[test]
fn msvc_full_carries_two_substantive_defects() {
    let full = rustre_demangle::msvc_full::msvc_demangle;

    // 1. An internal parser tag reaches the output.
    for sym in ["??_Etype_info@@UEAAPEAXI@Z", "??_Gtype_info@@UEAAPEAXI@Z"] {
        let got = full(sym);
        assert!(
            got.contains("?SPECIAL"),
            "expected the internal marker for {sym}, got {got}"
        );
        // The live path names the destructor kind properly.
        let live = rustre_demangle::demangle(sym).expect("live decodes").demangled;
        assert!(
            live.contains("deleting destructor"),
            "the live path must name it: {live}"
        );
    }

    // 2. The 2026-07-23 RTTI fix is present in the live path and absent here.
    let sym = "??_R1A@?0A@EA@type_info@@8";
    let got = full(sym);
    assert!(
        got.contains("type_info::EA::A"),
        "expected the character-scraped fields, got {got}"
    );
    let live = rustre_demangle::demangle(sym).expect("live decodes").demangled;
    assert!(
        live.contains("(0,-1,0,64)"),
        "the live path decodes the four signed numbers by grammar: {live}"
    );
}
