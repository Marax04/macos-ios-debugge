//! Swift 5 operator suffixes named different symbols and rendered alike.
//!
//! `TA` (partial-apply forwarder), `To` (Obj-C thunk), `TD` (dynamic-dispatch
//! thunk), `Tj`, `Tq`, `Tm`, `TU`, `Tu`, `Tw` … each name a **different symbol
//! at a different address**. The parser stopped at the entity terminator `F`
//! and ignored everything after it, so eleven distinct symbols all rendered
//! `main.foo() -> ()`.
//!
//! Swift has no oracle, so nothing could contradict the rendering — but
//! injectivity needs none: two different inputs must not become one output.
//!
//! **Why the fix is not "require the whole symbol to be consumed".** That rule
//! exists in the D demangler, whose comment says a leftover tail means
//! "reporting a partial reading as a complete one" — but Swift is deliberately
//! exempt, and for a *measured* reason recorded in `tests/trailing_input.rs`:
//! its parser consumes the whole symbol for only 9 of 16 realistic inputs, so
//! demanding full consumption would decline 7 legitimate symbols. Applying D's
//! rule here would have traded one defect for a worse one.
//!
//! **The test used instead is self-verifying.** The suffix is reported only
//! when removing it yields the *same* rendering — exactly the case where the
//! parser ignored it. A suffix the parser does consume changes the output and
//! is left alone, so this cannot misfire on a symbol that merely ends in those
//! letters. And the marker is echoed verbatim rather than spelled out
//! ("partial apply forwarder for …"): those spellings are Swift's own, and with
//! no oracle here an unverified label would be fabrication. A faithful echo
//! loses nothing and fixes the collision, which is the defect at hand.

use std::collections::BTreeMap;

fn ours(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| r.demangled)
}

const SUFFIXES: &[&str] = &[
    "", "TA", "To", "TD", "Tm", "Tj", "Tq", "TU", "Tu", "Twxx",
];

/// Distinct operator suffixes render distinctly.
#[test]
fn operator_suffixes_do_not_collide() {
    let base = "$s4main3fooyyF";
    let mut seen: BTreeMap<String, &str> = BTreeMap::new();
    let mut collisions = Vec::new();
    for sfx in SUFFIXES {
        let sym = format!("{base}{sfx}");
        let out = ours(&sym).unwrap_or_else(|| panic!("{sym} must decode"));
        if let Some(prev) = seen.insert(out.clone(), sfx) {
            collisions.push(format!("{prev:?} and {sfx:?} both render {out}"));
        }
    }
    assert_eq!(seen.len(), SUFFIXES.len(), "{collisions:?}");
    assert!(collisions.is_empty(), "{}", collisions.join("\n"));
}

/// The base name survives, and the suffix is reported verbatim.
///
/// Discriminating: the unsuffixed symbol passed before the fix — it is what
/// every existing Swift test covers. `TA` is what separates a decoder that
/// accounts for the whole symbol from one that stops at `F`.
#[test]
fn the_suffix_is_reported_and_the_name_kept() {
    for sfx in &SUFFIXES[1..] {
        let sym = format!("$s4main3fooyyF{sfx}");
        let out = ours(&sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(out.starts_with("main.foo() -> ()"), "{sym} lost its name: {out}");
        assert!(out.ends_with(&format!("[{sfx}]")), "{sym} lost its suffix: {out}");
    }
}

/// The Mach-O form behaves identically — the underscore must not change it.
#[test]
fn the_mach_o_form_reports_the_same_suffix() {
    for sfx in ["TA", "To", "TD"] {
        assert_eq!(
            ours(&format!("$s4main3fooyyF{sfx}")),
            ours(&format!("_$s4main3fooyyF{sfx}")),
            "the Mach-O underscore changed the rendering for {sfx}"
        );
    }
}

/// A suffix the parser *does* consume is left alone.
///
/// This is what makes the rule self-verifying rather than a guess: it fires
/// only where removing the tail changes nothing, so a symbol whose grammar
/// genuinely ends in those bytes keeps its rendering.
#[test]
fn a_consumed_tail_gains_no_marker() {
    for sym in [
        "$s4main3fooyyF",
        "$s4main3barSiyF",
        "$s4main1aySiSSF",
        "_TtC4main3Foo",
        "_TF4main3fooFT_T_",
    ] {
        let out = ours(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(
            !out.contains('['),
            "{sym} gained a suffix marker it does not have: {out}"
        );
    }
}

/// Chained suffixes are reported whole, and repetition does not collide.
///
/// Swift chains these (`TATm`). Reporting only the final group made `…FTA` and
/// `…FTATA` render alike — the very collision the marker exists to remove,
/// reintroduced by the first attempt at the recursion fix.
#[test]
fn chained_suffixes_are_reported_whole() {
    let mut seen = std::collections::BTreeSet::new();
    for sfx in ["", "TA", "TATA", "TATm", "TmTA", "To", "Twxx", "TATATA"] {
        let out = ours(&format!("$s4main3fooyyF{sfx}"))
            .unwrap_or_else(|| panic!("{sfx} must decode"));
        assert!(seen.insert(out.clone()), "{sfx:?} collided: {out}");
    }
    assert_eq!(seen.len(), 8);
    assert_eq!(
        ours("$s4main3fooyyFTATm").as_deref(),
        Some("main.foo() -> () [TATm]")
    );
}

/// A long run of suffixes must not exhaust the stack.
///
/// The first version of this check re-parsed the stem through
/// `crate::demangle`, which re-entered the check — one recursion per suffix —
/// and `TA` x1024 **overflowed the stack**, an uncatchable process kill. The
/// stem is now re-parsed with the Swift parser directly, so there is no path
/// back through the public entry point.
#[test]
fn a_long_suffix_run_does_not_exhaust_the_stack() {
    for n in [64usize, 1024, 20000] {
        let sym = format!("$s4main3fooyyF{}", "TA".repeat(n));
        // Any answer is acceptable; returning at all is the requirement.
        let _ = rustre_demangle::demangle(&sym);
    }
}

/// The plain symbol is unchanged — the fix adds information, never alters it.
#[test]
fn unsuffixed_renderings_are_unchanged() {
    assert_eq!(ours("$s4main3fooyyF").as_deref(), Some("main.foo() -> ()"));
    assert_eq!(ours("$s4main3barSiyF").as_deref(), Some("main.bar(Swift.Int) -> ()"));
    assert_eq!(ours("_TtC4main3Foo").as_deref(), Some("class main.Foo"));
}
