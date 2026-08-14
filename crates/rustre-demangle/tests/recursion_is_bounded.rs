//! Deeply nested types must not exhaust the stack.
//!
//! A crafted symbol crashed the process. `?foo@@YAX` + `PEA` x 4096 + `H@Z` drove
//! `parse_msvc_type` into unbounded mutual recursion with `parse_msvc_pointer`
//! until the thread **overflowed its stack**.
//!
//! That is worse than a panic in two ways: `catch_unwind` cannot rescue it, so a
//! consumer walking the symbol table of an untrusted binary loses the whole
//! process; and it is invisible to every existing guard — `tests/hardening.rs`
//! checks that `demangle` does not *panic*, which a stack overflow is not.
//!
//! Root cause: `MsvcParser` was the **only** parser in the crate with no recursion
//! limit. `cpp_demangler` has `MAX_DEPTH`, `d_demangler` has `enter()`/`leave()`,
//! `swift_demangler` tracks `depth`. Fixed by adding `MSVC_MAX_DEPTH = 64` at
//! `parse_msvc_type`, the choke point every recursive path passes through.
//!
//! Found by sweeping nesting depth per ABI — the same generate-don't-read approach
//! that found three overflow panics at iters 82-83.

/// Escalating nesting per ABI. The assertion is that each returns at all.
///
/// Depths run past any plausible real symbol on purpose: 20000 nested pointers is
/// not something a compiler emits, but it is something an attacker writes, and the
/// crate's job is to decline rather than die.
#[test]
fn deep_nesting_is_declined_not_fatal() {
    type Maker = fn(usize) -> String;
    let makers: &[(&str, Maker)] = &[
        ("d_pointer", |n| format!("_D4main3fooF{}iZv", "P".repeat(n))),
        ("d_array", |n| format!("_D4main3fooF{}iZv", "A".repeat(n))),
        ("d_const", |n| format!("_D4main3fooF{}iZv", "x".repeat(n))),
        ("itanium_pointer", |n| format!("_Z3foo{}i", "P".repeat(n))),
        ("itanium_template", |n| {
            format!("_Z3fooI{}iE{}v", "I".repeat(n), "E".repeat(n))
        }),
        ("swift_nest", |n| format!("$s4main3foo{}yyF", "S".repeat(n))),
        ("msvc_pointer", |n| format!("?foo@@YAX{}H@Z", "PEA".repeat(n))),
        ("rust_v0_ref", |n| format!("_RNvC4main3foo{}", "R".repeat(n))),
        // REPEATED SUFFIXES, not nested types. This shape was absent, and a
        // stack overflow lived in it for three iterations: the Swift
        // operator-suffix check added at iter 131 re-parsed the stem through
        // `crate::demangle`, which re-entered the same check, so one recursion
        // per suffix. `$s4main3fooyyF` + `TA` x1024 killed the process.
        //
        // A depth limit inside a parser does not cover this: the recursion was
        // *between* the public entry point and a backend, so every parser's own
        // guard was satisfied at every step. Repetition at the symbol's edge is
        // its own shape and belongs in this sweep.
        ("swift_operator_suffix", |n| {
            format!("$s4main3fooyyF{}", "TA".repeat(n))
        }),
        ("swift_suffix_mixed", |n| {
            format!("$s4main3fooyyF{}", "TATm".repeat(n))
        }),
        ("go_dots", |n| format!("main.foo{}", ".func1".repeat(n))),
        ("objc_nesting", |n| format!("-[Foo {}bar]", "a:".repeat(n))),
    ];

    let mut tried = 0;
    for (name, make) in makers {
        for depth in [8usize, 64, 256, 1024, 4096, 20000] {
            let sym = make(depth);
            // Any answer is acceptable; surviving is the requirement.
            let _ = rustre_demangle::demangle(&sym);
            tried += 1;
            let _ = name;
        }
    }
    assert!(tried == 72, "expected 72 nesting cases, tried {tried}");
}

/// Shallow nesting — what compilers actually emit — must still decode.
///
/// This is the half that makes the depth limit a fix rather than a mute button: a
/// limit of 1 would satisfy the test above.
#[test]
fn ordinary_nesting_still_decodes() {
    // MSVC, the parser that gained the limit.
    assert!(
        rustre_demangle::demangle("?foo@@YAXPEAH@Z").is_some(),
        "a single pointer parameter must decode"
    );
    assert!(
        rustre_demangle::demangle("?foo@@YAXPEAPEAH@Z").is_some(),
        "a pointer-to-pointer must decode"
    );
    assert!(
        rustre_demangle::demangle("?foo@@YAXPEAPEAPEAH@Z").is_some(),
        "three levels must decode"
    );

    // And the real corpus figure is the strongest control: if the limit were too
    // tight, the MSVC decode count would move.
    let msvc = include_str!("data/pdb_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|s| s.starts_with('?'))
        .filter(|s| rustre_demangle::demangle(s).is_some())
        .count();
    assert!(
        msvc >= 14,
        "only {msvc} real MSVC symbols decode — the depth limit is too tight"
    );
}
