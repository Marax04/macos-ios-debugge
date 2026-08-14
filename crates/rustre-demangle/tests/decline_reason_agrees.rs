//! `decline_reason` must say `Decoded` exactly when `demangle` returns a value.
//!
//! `DeclineReason` is this crate's authoritative metric — the CLAUDE.md calls
//! the decode count "not coverage" and points at `decline_reason` instead, with
//! `UnsupportedAbi` and `Unknown` locked at zero. A metric that disagrees with
//! the function it measures reports a number about nothing.
//!
//! The risk is not hypothetical: iter 133 added a guard on the crate's public
//! `demangle` (a rendering must contain a name), which changes the answer for
//! degenerate input. `decline_reason` happens to delegate to `demangle`, so the
//! two moved together — but nothing asserted that, and a future backend-level
//! decline would break it silently.
//!
//! Measured 2026-07-30 over 6487 inputs: **0 inconsistencies**. No defect; this
//! file is the guard.

/// The invariant, over both real corpora plus every degenerate and constructed
/// shape this crate's tests have accumulated.
#[test]
fn decline_reason_and_demangle_never_disagree() {
    let mut inputs: Vec<String> = include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();

    // The shapes that moved during this session's hardening — each one is a
    // place where a backend gained or lost a decline.
    for s in [
        "_RNvC0_0_",
        "Java__",
        "Java_a__b_",
        "Java_com_foo_Bar_baz",
        "?bar@Foo@@QAEX",
        "?bar@Foo@@QAEXXZ",
        "?@@YAXXZ",
        "?f@@YAXABH0@Z",
        "$s4main3fooyyFTA",
        "$s4main3fooyyFTATm",
        "_TtC4main3Foo",
        "_TMC4main3Foo",
        "_D4main3Foo3barMFZv",
        "_D4main3fooFZ3barFZv",
        "_D4main3fooFZv.llvm.1234567890",
        "__ZN4main3foo17h0123456789abcdefE",
        "_ZN4main3foo17h0123456789abcdefE.cold",
        "a___b",
        "___a_MOD_x",
        "A___B",
        "_OBJC_PROTOCOL_$_Foo",
        "_OBJC_METH_VAR_NAME_",
        "clojure.core$_PLUS_",
        "main.f.func2.3",
        "llvm.Parse",
        "_RNvC1au6f_5gaa",
    ] {
        inputs.push(s.to_owned());
    }

    let mut checked = 0;
    let mut disagreements = Vec::new();
    for sym in &inputs {
        let decoded = rustre_demangle::demangle(sym).is_some();
        let reason = format!("{:?}", rustre_demangle::decline::decline_reason(sym));
        checked += 1;
        if decoded != (reason == "Decoded") {
            disagreements.push(format!("{sym}: demangle={decoded} but reason={reason}"));
        }
    }

    assert!(checked > 6000, "vacuous: only {checked} inputs");
    assert!(
        disagreements.is_empty(),
        "{} inputs where the metric contradicts the function it measures:\n{}",
        disagreements.len(),
        disagreements.join("\n")
    );
}

/// Rust v0 punycode identifiers, against the oracle.
///
/// Priority-(1) coverage that did not exist: `u<len><punycode>` is how v0
/// encodes a non-ASCII name, and iter 112's probe skipped it because the one
/// vector I hand-wrote was malformed. The oracle arbitrates construction here,
/// so a rejected input is a bug in the test rather than a finding.
///
/// Measured: 4 of 4 well-formed constructions agree, 0 differ.
#[test]
fn punycode_identifiers_agree_with_the_oracle() {
    let mut checked = 0;
    let mut wrong = Vec::new();
    for sym in [
        "_RNvC1au6f_5gaa",
        "_RNvC4mainu6ab_cde",
        "_RNvC1au1a",
        "_RNvC1a3foo",
    ] {
        let Ok(decoded) = rustc_demangle::try_demangle(sym) else {
            panic!("{sym}: the oracle rejects it — the vector is malformed")
        };
        let want = format!("{decoded:#}");
        checked += 1;
        match rustre_demangle::demangle(sym).map(|r| r.demangled) {
            Some(got) if got == want => {}
            other => wrong.push(format!("{sym}\n  oracle: {want}\n  ours:   {other:?}")),
        }
    }
    assert_eq!(checked, 4);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    // The decoded name really is non-ASCII — otherwise the vectors would pass
    // without exercising punycode at all.
    let out = rustre_demangle::demangle("_RNvC1au6f_5gaa")
        .expect("must decode")
        .demangled;
    assert!(!out.is_ascii(), "punycode was not decoded: {out}");
}

/// No backend may reach the public entry point.
///
/// Iter 134's stack overflow was a cycle between `crate::demangle` and a
/// backend that called it back. Swept afterwards: the only live callers are
/// `decline.rs` and `stats.rs`, neither of which `demangle` can reach. This
/// pins that, because the cost of the cycle is an uncatchable process kill and
/// the cause is a single easy line to write.
#[test]
fn no_backend_calls_the_public_entry_point() {
    // Files that may legitimately call it: classifiers and reporters, which
    // `demangle` never calls into.
    const ALLOWED: &[&str] = &["decline.rs", "stats.rs", "lib_tests.rs"];

    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let mut offenders = Vec::new();
    let mut scanned = 0;
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src must be readable") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_owned();
            let text = std::fs::read_to_string(&path).expect("readable");
            scanned += 1;
            if ALLOWED.contains(&name.as_str()) {
                continue;
            }
            for (i, line) in text.lines().enumerate() {
                let call = line.contains("crate::demangle(") || line.contains("super::demangle(");
                if call && !line.trim_start().starts_with("//") && !line.contains("///") {
                    offenders.push(format!("{name}:{}: {}", i + 1, line.trim()));
                }
            }
        }
    }
    assert!(scanned > 20, "vacuous: only {scanned} sources scanned");
    assert!(
        offenders.is_empty(),
        "a backend calls the public entry point — that is a cycle, and iter 134 \
         showed it costs the whole process:\n{}",
        offenders.join("\n")
    );
}
