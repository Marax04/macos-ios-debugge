//! Real-world corpus harness: every symbol extracted (via `nm`) from the 12
//! real C/C++/Rust/Go/C# executables in the repo-root decompiler corpus,
//! checked into `tests/data/real_symbols.txt`.
//!
//! Regenerate with `tests/data/regenerate.sh` — never by hand. `nm` prints
//! `ADDRESS TYPE NAME`, and Go generic symbols contain spaces
//! (`internal/sync.(*HashTrieMap[go.shape.interface {},…])`), so taking the
//! last whitespace-separated field truncated 13 of them to fragments like
//! `{}]).Load` and lost the symbols themselves. The script joins everything
//! from the NAME field onward and asserts that property afterwards; the
//! failure is silent otherwise, since the file looks plausible either way.
//!
//! Unlike the generated suites, these names were produced by real compilers
//! (mingw-gcc/g++, rustc, the Go toolchain, .NET AOT stubs) — including
//! runtime internals, thunks and import stubs no grammar generator would
//! emit. The harness asserts three things: no panic on any symbol, minimum
//! demangling coverage for the ABIs the corpus is known to contain, and no
//! silent regression of the overall decode count.

use std::collections::BTreeMap;

fn symbols() -> Vec<String> {
    let raw = include_str!("data/real_symbols.txt");
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Every real symbol must demangle or be declined — never panic.
/// (Panics would abort the test process, so completing the loop is the proof.)
#[test]
fn no_panic_on_real_symbols() {
    // Absolute ratchet on the overall decode count, so a change that silently
    // drops a previously-decoded symbol fails here even when every per-ABI
    // percentage floor still holds.
    //
    // History (2026-07-23): 3009 → 3042 when `.refptr.`/`__imp_` linker
    // wrappers were unwrapped → 3016 when GCC clone suffixes stopped being
    // claimed by the Go detector → 3048 when the corpus itself was
    // regenerated without truncating space-bearing Go generic symbols (see
    // the module docs), which restored 32 real symbols and dropped 13
    // fragments → 3024 when the Go linker's constant pool (`$f64.<hex>`)
    // stopped being echoed back as if decoded → 3023 when the Python 2
    // `init<module>` rule left the generic dispatcher, which had been
    // decoding the C symbol `initialized` as `python2 module init: ialized`
    // → 3020 when leading-dot section names stopped reaching the backends,
    // which had the GHC detector rendering `.pdata$_ZL17parse_lsda_header…`
    // as `.pdata$:(17parse_lsda_header…lsda.header (info)`.
    //
    // Four of those steps LOWERED the count, which this comment exists to
    // justify: what they removed were not decodes. `__pformat_int.isra.0` was
    // reported as `__pformat_int.isra {closure-1 #?}`, a C function dressed up
    // as a Go closure; `initialized` as `python2 module init: ialized`.
    // Removing fabricated output is a fidelity gain that a raw decode count
    // necessarily reads as a loss, which is why
    // `no_mangled_symbol_goes_unhandled` is the authoritative metric and this
    // one is only a tripwire. Lower this number ONLY alongside that kind of
    // evidence, never to make a red test green.
    //
    // 3020 → 3010 (2026-07-23): a fifth such step. GCC function-local statics
    // (`msg.0`, `table.0`, `C.9.0` — 10 in the corpus) were being echoed back
    // by the Go detector as `abi: Go`. They have no demangling — they are
    // undecorated C data — so refusing them removes 10 identity echoes, not 10
    // decodes. `SUBSTANTIVE_FLOOR` is unmoved (an echo was never substantive)
    // and the classification asserts stay green because they now land in
    // `UndecoratedC` rather than being counted as Go.
    const DECODED_FLOOR: usize = 3010;

    // Companion tripwire covering what `DECODED_FLOOR` cannot: a backend that
    // stopped decoding and started echoing its input would hold the total
    // steady while this fell.
    //
    // It is NOT the "only ever rises" ratchet an earlier revision claimed.
    // Fabricated output is often a real transformation — `initialized` →
    // `python2 module init: ialized` counted here too — so removing a lie can
    // legitimately lower this figure. What it is immune to is churn in
    // identity echoes, which move `DECODED_FLOOR` without meaning anything.
    // Neither number is authoritative on its own; that is the point of having
    // both, plus the defect and classification asserts below.
    // Raised 1200 -> 1201 when GCC emulated-TLS wrappers started decoding
    // their payload: `__emutls_v._ZZN12_GLOBAL__N_1L10get_globalEvE6global`
    // was previously claimed by the permissive Go backend and echoed back
    // unchanged, so it counted toward `DECODED_FLOOR` while contributing
    // nothing here. The total is unmoved and this rose by exactly one — the
    // signature of an identity echo becoming a real decode, which is the one
    // shape that justifies raising this floor.
    const SUBSTANTIVE_FLOOR: usize = 1201;

    let syms = symbols();
    assert!(syms.len() > 5000, "corpus file went missing or was truncated");
    let mut decoded = 0usize;
    let mut substantive = 0usize;
    for s in &syms {
        if let Some(r) = rustre_demangle::demangle(s) {
            decoded += 1;
            // Go names are frequently already readable, so a result equal to
            // its input is a legitimate outcome — but it conveys nothing. The
            // substantive count tracks decodes that actually transformed the
            // symbol, and unlike the total it cannot be moved by adding or
            // removing identity echoes.
            if r.demangled != *s {
                substantive += 1;
            }
        }
    }
    println!(
        "real corpus: {decoded}/{} symbols demangled ({substantive} substantive)",
        syms.len()
    );

    assert!(
        substantive >= SUBSTANTIVE_FLOOR,
        "substantive decodes regressed: {substantive} < {SUBSTANTIVE_FLOOR}"
    );

    assert!(
        decoded >= DECODED_FLOOR,
        "overall decode count regressed: {decoded} < {DECODED_FLOOR}"
    );
}

/// The number that actually measures this crate's coverage.
///
/// Raw decode counts on this corpus are unreadable: ~2200 of the 6055 entries
/// are linker section names and ~800 are undecorated C identifiers, none of
/// which have a demangling. `DeclineReason` separates those correct declines
/// from the one failing case that means a defect — a string carrying a
/// recognised mangling sigil that no backend decoded.
#[test]
fn no_mangled_symbol_goes_unhandled() {
    use rustre_demangle::{DeclineReason, decline_reason};

    let syms = symbols();
    let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
    let mut defects: Vec<&String> = Vec::new();
    let mut unclassified: Vec<&String> = Vec::new();
    for s in &syms {
        let reason = decline_reason(s);
        let label = match reason {
            DeclineReason::Decoded => "decoded",
            DeclineReason::LinkerSection => "linker section (not a symbol)",
            DeclineReason::LinkerArtifact => "toolchain artifact",
            DeclineReason::UndecoratedC => "undecorated C",
            DeclineReason::UnsupportedAbi => "UNSUPPORTED ABI (defect)",
            DeclineReason::DotNetMetadata => ".NET metadata name (nothing to demangle)",
            DeclineReason::AlreadyDemangled => "already demangled (debug-info name)",
            DeclineReason::Unknown => "unknown shape",
        };
        *tally.entry(label).or_default() += 1;
        if reason.is_defect() {
            defects.push(s);
        }
        if reason == DeclineReason::Unknown {
            unclassified.push(s);
        }
    }
    for (label, n) in &tally {
        println!("  {n:>5}  {label}");
    }

    // Zero defects as of 2026-07-23, and this must stay zero: every string in
    // the corpus carrying a recognised mangling sigil decodes. A new backend
    // gap or a decoding regression lands here as a non-empty list, naming the
    // offending symbols instead of moving an aggregate percentage.
    assert!(
        defects.is_empty(),
        "{} mangled symbols went unhandled; first 10: {:#?}",
        defects.len(),
        &defects[..defects.len().min(10)]
    );

    // Every entry in the corpus is accounted for by a specific reason. This
    // held for the first time on 2026-07-23; keeping it means a new symbol
    // shape has to be understood and named, not silently parked in `Unknown`.
    assert!(
        unclassified.is_empty(),
        "{} symbols fall into no known category; first 10: {:#?}",
        unclassified.len(),
        &unclassified[..unclassified.len().min(10)]
    );
}

/// An encoded ABI must never echo its input back.
///
/// A result equal to its input is a legitimate outcome for Go, whose names are
/// already human-readable (`main.main` demangles to itself). It is never
/// legitimate for a strict-prefix ABI: Itanium, MSVC, Rust and Swift names are
/// encoded, so echoing one back means the backend claimed a symbol it did not
/// decode — a silent failure that still counts towards the decode total.
#[test]
fn only_go_may_decode_a_symbol_to_itself() {
    let syms = symbols();
    let mut offenders: Vec<(&String, String)> = Vec::new();
    for s in &syms {
        let Some(r) = rustre_demangle::demangle(s) else {
            continue;
        };
        if r.demangled == *s && r.abi != rustre_demangle::ManglingAbi::Go {
            offenders.push((s, format!("{:?}", r.abi)));
        }
    }
    assert!(
        offenders.is_empty(),
        "{} symbols were echoed back by an encoded ABI; first 10: {:#?}",
        offenders.len(),
        &offenders[..offenders.len().min(10)]
    );
}

/// Per-ABI coverage floors. These are deliberately conservative so the test
/// fails only on genuine regressions, not on corpus regeneration noise.
#[test]
fn abi_coverage_floors() {
    let syms = symbols();
    let mut per_prefix: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for s in &syms {
        let bucket = if s.starts_with("_Z") || s.starts_with("__Z") {
            "itanium/rust-legacy"
        } else if s.starts_with("_R") {
            "rust-v0"
        } else if s.starts_with('?') {
            "msvc"
        } else if rustre_demangle::decline::is_gcc_local_static(s)
            || rustre_demangle::decline::is_gcc_clone(s)
        {
            // GCC local statics (`msg.0`, `C.9.0`) and clone suffixes
            // (`classify.cold`, `d_encoding.part.0`) match the go-like shape
            // heuristic below but are not Go — they are undecorated C symbols
            // that are correctly declined. Counting them as go-like candidates
            // would penalise Go's coverage for refusing what is not its own.
            "other"
        } else if s.contains('.') && s.chars().next().is_some_and(char::is_alphabetic) {
            "go-like"
        } else {
            "other"
        };
        let e = per_prefix.entry(bucket).or_insert((0, 0));
        e.0 += 1;
        if rustre_demangle::demangle(s).is_some() {
            e.1 += 1;
        }
    }
    for (bucket, (total, ok)) in &per_prefix {
        println!("  {bucket}: {ok}/{total}");
    }

    let check = |bucket: &str, min_pct: usize| {
        if let Some((total, ok)) = per_prefix.get(bucket)
            && *total >= 20
        {
            assert!(
                ok * 100 >= total * min_pct,
                "{bucket} coverage regressed: {ok}/{total} < {min_pct}%"
            );
        }
    };
    // Both buckets measure a clean 100% as of 2026-07-23 — itanium 813/813 and
    // go-like 2163/2163, once GCC clone-suffix C names (`classify.cold`,
    // `d_encoding.part.0`) are bucketed as `other` rather than dragging Go down.
    // Held at 100 (raised from 99): the former slack was absorbing exactly that
    // misclassification, and with the C names now excluded any drop is a genuine
    // regression. A new undecodable symbol from corpus regeneration SHOULD trip
    // this — that is the tripwire working, not noise.
    check("itanium/rust-legacy", 100);
    check("go-like", 100);
}
