//! A truncated MSVC symbol was reported as a complete one.
//!
//! `tests/trailing_input.rs` states the rule this crate holds its demanglers
//! to: a decoder must account for the whole symbol, because two distinct linker
//! symbols rendering the same string are indistinguishable to any consumer.
//! That file compares the backends on *extra* input. This is the same defect
//! from the other side — **missing** input — and it caught MSVC, which the file
//! does not cover.
//!
//! The parameter loop treated running out of input as a valid termination, but
//! the grammar requires `Z`:
//!
//! ```text
//! ?bar@Foo@@QAEXXZ  =>  public: void __thiscall Foo::bar(void)
//! ?bar@Foo@@QAEXX   =>  public: void __thiscall Foo::bar(void)   // truncated
//! ?bar@Foo@@QAEX    =>  public: void __thiscall Foo::bar(void)   // truncated
//! ```
//!
//! `msvc-demangler` rejects both truncations, so this is oracle-confirmed
//! rather than a reading of the spec. In a stripped or damaged binary a
//! truncated symbol would have read as a perfectly ordinary function.
//!
//! Measured while extending the trailing-input comparison to the backends it
//! omits: Go, Rust v0, legacy Rust and Obj-C absorb neither extra nor missing
//! input, and D, Swift and Itanium were already covered there. **MSVC was the
//! only one.**

fn oracle(sym: &str) -> Option<String> {
    msvc_demangler::demangle(sym, msvc_demangler::DemangleFlags::COMPLETE).ok()
}

fn ours(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| r.demangled)
}

/// A truncated function symbol must not decode.
///
/// Discriminating: the intact symbol passed before this fix — it is what every
/// existing MSVC test covers. The truncations are what separate a parser that
/// requires the terminator from one that stops when the bytes run out.
#[test]
fn truncated_function_symbols_decline() {
    const TRUNCATED: &[&str] = &[
        "?bar@Foo@@QAEXX",
        "?bar@Foo@@QAEX",
        "??0Foo@@QAE@X",
        "??0Foo@@QAE@",
        "?foo@@YAXX",
        "?foo@@YAX",
    ];
    let mut checked = 0;
    for sym in TRUNCATED {
        assert!(
            oracle(sym).is_none(),
            "{sym}: the oracle accepts it, so this vector is not truncated"
        );
        checked += 1;
        assert_eq!(ours(sym), None, "{sym} is truncated and must not decode");
    }
    assert_eq!(checked, 6);
}

/// The intact symbols are unchanged, and still agree with the oracle.
///
/// Guards against the fix over-rejecting: requiring a terminator must not cost
/// a single well-formed symbol.
#[test]
fn intact_symbols_still_decode() {
    for sym in [
        "?bar@Foo@@QAEXXZ",
        "??0Foo@@QAE@XZ",
        "?foo@@YAXXZ",
        "?f@@YAXHH@Z",
        "?f@@YAXABH0@Z",
        "??$max@H@@YAHABH0@Z",
        "??_7Foo@@6B@",
    ] {
        let got = ours(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(oracle(sym).is_some(), "{sym}: the oracle rejects it");
        assert!(!got.is_empty());
    }
}

/// Data symbols legitimately end without a `Z` — the rule applies to
/// signatures only.
///
/// `?x@@3H` (missing the storage-class byte) is accepted by the oracle too, so
/// declining it would be over-rejection rather than rigour.
#[test]
fn data_symbols_are_not_subject_to_the_terminator_rule() {
    for sym in ["?x@@3HA", "?x@@3H"] {
        assert!(oracle(sym).is_some(), "{sym}: the oracle rejects it");
        assert!(ours(sym).is_some(), "{sym} must still decode");
    }
}

/// No truncation of a well-formed symbol may render as the whole symbol.
///
/// Stated over every prefix rather than a hand-picked list, so a truncation
/// nobody thought of still fails it. This is the property the defect violated.
#[test]
fn no_prefix_of_a_symbol_renders_as_the_symbol() {
    let mut checked = 0;
    let mut offenders = Vec::new();
    for sym in [
        "?bar@Foo@@QAEXXZ",
        "??0Foo@@QAE@XZ",
        "?foo@@YAXXZ",
        "?f@@YAXHH@Z",
    ] {
        let full = ours(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        checked += 1;
        for cut in 1..sym.len() {
            let prefix = &sym[..cut];
            if ours(prefix).as_deref() == Some(full.as_str()) {
                offenders.push(format!("{prefix} renders as the complete {sym}"));
            }
        }
    }
    assert!(checked >= 4, "vacuous: only {checked} symbols");
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}
