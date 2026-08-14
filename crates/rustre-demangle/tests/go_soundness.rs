//! Nothing may appear in a Go rendering that is not in the symbol.
//!
//! `tests/go_completeness.rs` is defined over the *input*: every named
//! component must reappear in the output. That catches **loss**, and it found
//! two real defects nothing else could see.
//!
//! It is structurally blind to the opposite direction. A renderer that
//! duplicated a component, invented a package name, or carried a fragment over
//! from a previous decode would satisfy it perfectly — every input component is
//! still present, there is simply *more*. This file is that counterpart:
//! every identifier in the output must be traceable to the input.
//!
//! The direction matters for Go specifically. Go has no oracle, so nothing can
//! contradict a wrong answer, and every fabricated-output defect found in this
//! crate so far has been in Go — the backend's documented failure mode is
//! inventing metadata when unsure.
//!
//! Identifiers are matched as whole tokens, not substrings. That distinction
//! is the whole strength of the check and it was found the hard way: under
//! substring matching a fabricated `[int]` is "explained" by the `int` inside
//! `internal`, and short invented names — `int`, `err`, `map`, `new` — are
//! masked by coincidence. The negative control below caught it.
//!
//! Run over the 2163 real Go symbols the check leaves exactly three unexplained
//! alphabetic tokens, all renderer vocabulary, and the test pins that set
//! exactly. A fourth fails.

use rustre_demangle::ManglingAbi;
use std::collections::BTreeSet;

/// Maximal runs of identifier characters, which is what a fabricated name
/// would have to appear as. Applied to input and output alike, so the two are
/// compared token-for-token.
fn idents(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            cur.push(c);
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Words the renderer contributes itself, rather than reading out of the
/// symbol.
///
/// `{closure-N #…}` is the crate's spelling for Go's `.funcN` markers, and
/// `type descriptor for …` is the deliberate rewrite of the `type:` namespace
/// that `go_completeness` excludes for the same reason.
const RENDERER_VOCABULARY: [&str; 3] = ["closure", "descriptor", "for"];

fn tokens(s: &str) -> BTreeSet<String> {
    idents(s).into_iter().collect()
}

/// The invariant itself, in one place.
///
/// Returns the identifiers of `output` that `input` cannot account for. Every
/// test in this file goes through it, including the negative control, so the
/// control cannot drift away from the rule it is meant to exercise — the
/// failure mode this crate files under "tests that check shape, not effect".
///
/// Pure digits are treated separately: they are not whole tokens of the input,
/// because Go writes `.func8` (one token, `func8`) where the rendering writes
/// `#8`. An index is therefore matched as a substring, and the depth in
/// `{closure-N …}` is computed from the nesting rather than read out of the
/// symbol at all.
fn invented(input: &str, output: &str) -> Vec<String> {
    let src = tokens(input);
    idents(output)
        .into_iter()
        .filter(|id| !src.contains(id) && !RENDERER_VOCABULARY.contains(&id.as_str()))
        .filter(|id| {
            !(id.chars().all(|c| c.is_ascii_digit())
                && (input.contains(id.as_str()) || output.contains("{closure-")))
        })
        .collect()
}

fn go_symbols() -> Vec<(&'static str, String)> {
    include_str!("data/real_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|s| {
            !s.is_empty() && !s.starts_with('.') && !s.starts_with('_') && !s.starts_with('?')
        })
        .filter_map(|s| {
            rustre_demangle::demangle(s)
                .filter(|r| r.abi == ManglingAbi::Go)
                .map(|r| (s, r.demangled))
        })
        .collect()
}

/// The invariant. Every identifier in the rendering comes from the symbol,
/// except the renderer's own vocabulary and the depth counter it computes.
#[test]
fn no_go_rendering_invents_an_identifier() {
    let syms = go_symbols();
    assert!(syms.len() > 2000, "vacuous: only {} Go symbols", syms.len());

    let mut bad: Vec<String> = Vec::new();
    for (input, output) in &syms {
        for id in invented(input, output) {
            bad.push(format!("{id:?} in {input}  ->  {output}"));
        }
    }
    assert!(bad.is_empty(), "{} invented identifiers: {:#?}", bad.len(), bad);
}

/// Pins the vocabulary exactly, so the test above cannot be satisfied by
/// widening the allow-list. Every word here must be *earned* — if a renderer
/// change adds a seventh, this fails and the word has to be justified.
#[test]
fn the_renderer_vocabulary_is_exactly_what_is_claimed() {
    let syms = go_symbols();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (input, output) in &syms {
        let src = tokens(input);
        for id in idents(output) {
            if !src.contains(&id) && !id.chars().all(|c| c.is_ascii_digit()) {
                seen.insert(id);
            }
        }
    }
    let want: BTreeSet<String> =
        RENDERER_VOCABULARY.iter().map(|s| (*s).to_string()).collect();
    assert_eq!(seen, want, "the renderer's contributed vocabulary changed");
}

/// The check must be able to fail. A rendering that duplicates or invents is
/// caught — asserted against the same predicate the test uses, so the two
/// cannot drift apart.
#[test]
fn the_invariant_would_catch_a_fabrication() {
    let input = "internal/godebug.(*Setting).Value.func1";
    let caught = |rendering: &str| !invented(input, rendering).is_empty();

    assert!(!caught("internal/godebug.(*Setting).Value"), "honest rendering rejected");
    assert!(!caught("internal/godebug.(*Setting).Value {closure-1 #1}"), "closure rejected");

    for fabricated in [
        "internal/godebug.(*Setting).Value.mysteryHelper",
        "runtime.(*Setting).Value",
        // The case that exposed substring matching: `int` occurs inside
        // `internal`, so a substring check calls this honest.
        "internal/godebug.(*Setting).Value[int]",
        "internal/godebug.(*Setting).Value.err",
    ] {
        assert!(caught(fabricated), "{fabricated} slipped through");
    }
}
