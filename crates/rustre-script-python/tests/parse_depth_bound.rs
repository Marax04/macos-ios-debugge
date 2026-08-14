//! The parser must survive hostile nesting.
//!
//! `PythonEngine::parse` recurses once per bracket level, and a script is
//! untrusted input — this crate exists to sandbox it. Before the bound below
//! existed, a 10 KB script of nested parentheses exhausted the native stack:
//! *"thread has overflowed its stack"*, which aborts the process rather than
//! raising a catchable error, so neither `Result` nor `catch_unwind` could save
//! a caller. The interpreter's own step budget does not help — it counts steps
//! taken while executing and is not active during parsing.
//!
//! These tests are only safe to run because the bound exists. Removing it turns
//! them from failures into a process abort, which is the point.

use rustre_script_python::PythonEngine;

/// Nesting far beyond the limit is rejected, not crashed on.
#[test]
fn hostile_nesting_is_rejected() {
    for depth in [201usize, 1_000, 10_000, 100_000] {
        let src = format!("x = {}1{}", "(".repeat(depth), ")".repeat(depth));
        let engine = PythonEngine::new();
        let err = engine
            .parse(&src)
            .expect_err("nesting of {depth} should be refused");
        let text = err.to_string();
        assert!(
            text.contains("nested"),
            "depth {depth} was refused, but for the wrong reason: {text}"
        );
    }
}

/// Nesting a real script might plausibly contain still parses.
///
/// A bound that rejected ordinary expressions would trade a crash for a
/// correctness bug, so the accepted side has to be pinned too.
#[test]
fn ordinary_nesting_still_parses() {
    let engine = PythonEngine::new();

    for src in [
        "x = 1",
        "x = (1 + 2) * (3 - 4)",
        "x = ((((1))))",
        "x = [1, 2, [3, [4, 5]]]",
        "y = f(g(h(1)))",
    ] {
        assert!(
            engine.parse(src).is_ok(),
            "{src:?} is ordinary Python but was refused: {:?}",
            engine.parse(src)
        );
    }

    // Right at the limit — 200 levels is accepted, so the check is `>` and not
    // an off-by-one that eats a legal depth.
    let at_limit = format!("x = {}1{}", "(".repeat(200), ")".repeat(200));
    assert!(
        engine.parse(&at_limit).is_ok(),
        "200 levels is the documented limit and must still parse"
    );
}

/// Brackets inside a string literal are text, not nesting.
///
/// Counting them would reject a script that merely mentions parentheses — a
/// false rejection introduced by the very check meant to prevent a crash.
#[test]
fn brackets_inside_strings_do_not_count() {
    let engine = PythonEngine::new();
    let many = "(".repeat(500);

    for src in [
        format!("x = \"{many}\""),
        format!("x = '{many}'"),
        format!("x = \"{many}\" + \"tail\""),
    ] {
        assert!(
            engine.parse(&src).is_ok(),
            "brackets inside a string literal were counted as nesting: {src:.40}…"
        );
    }
}

/// Unbalanced closing brackets must not underflow the depth counter.
#[test]
fn unbalanced_brackets_do_not_underflow() {
    let engine = PythonEngine::new();
    // Whether these parse is the parser's business; what matters is that
    // counting them neither panics nor wraps around.
    for src in [")))", "x = )", "x = ())", "]]]", "x = }"] {
        let _ = engine.parse(src);
    }
}

/// Executing — not just parsing — is also bounded, since `execute` parses first.
#[test]
fn execution_inherits_the_bound() {
    let src = format!("x = {}1{}", "(".repeat(5_000), ")".repeat(5_000));
    let mut engine = PythonEngine::new();
    let mut scope = rustre_script_python::PyScope::new();
    assert!(
        engine.execute(&src, &mut scope).is_err(),
        "execute() parses first, so it must refuse the same input"
    );
}
