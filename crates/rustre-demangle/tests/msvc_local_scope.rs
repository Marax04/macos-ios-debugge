//! MSVC function-local scopes: `?<name>@?<N>?<enclosing symbol>@…`.
//!
//! A `static` declared inside a function is mangled with its enclosing
//! function embedded as a scope. `undname` renders the scope as
//! `` `enclosing'::`N+1' `` — note the index is reported one higher than
//! encoded.
//!
//! Before this was handled, the leading `1` of `?1?` was decoded as a
//! destructor operator and the whole symbol was declined. The two symbols
//! below are real: they come from the CRT in the corpus Rust binaries.

/// The canonical case, checked end to end.
#[test]
fn function_local_static_decodes() {
    let r = rustre_demangle::demangle("?_OptionsStorage@?1??__local_stdio_printf_options@@9@4_KA")
        .expect("function-local static must decode");
    assert_eq!(
        r.demangled,
        "unsigned long long `__local_stdio_printf_options'::`2'::_OptionsStorage"
    );
}

/// The scanf twin, to confirm the enclosing name is read rather than assumed.
#[test]
fn enclosing_function_name_is_read_not_assumed() {
    let r = rustre_demangle::demangle("?_OptionsStorage@?1??__local_stdio_scanf_options@@9@4_KA")
        .expect("function-local static must decode");
    assert!(
        r.demangled.contains("`__local_stdio_scanf_options'"),
        "enclosing function must come from the symbol: {}",
        r.demangled
    );
}

/// The scope index is rendered `N+1`, matching `undname`.
#[test]
fn scope_index_is_incremented() {
    let r = rustre_demangle::demangle("?_OptionsStorage@?1??__local_stdio_printf_options@@9@4_KA")
        .expect("must decode");
    assert!(r.demangled.contains("`2'"), "{}", r.demangled);
    assert!(!r.demangled.contains("`1'"), "{}", r.demangled);
}

/// A real destructor must still decode as one: `?1?` is a local scope only
/// when a second `?` follows the digit, and `??1Foo@@QEAA@XZ` has none.
#[test]
fn destructors_are_not_mistaken_for_local_scopes() {
    let r = rustre_demangle::demangle("??1Foo@@QEAA@XZ").expect("destructor must decode");
    assert!(
        r.demangled.contains("~Foo"),
        "expected a destructor: {}",
        r.demangled
    );
}

/// Ordinary member functions and data symbols are untouched by the new branch.
#[test]
fn ordinary_msvc_symbols_are_unaffected() {
    for (sym, needle) in [
        ("?foo@bar@@QEAAHXZ", "bar::foo"),
        ("?x@@3HA", "int x"),
        ("??3@YAXPEAX@Z", "operator delete"),
    ] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(
            r.demangled.contains(needle),
            "{sym}: expected {needle:?} in {}",
            r.demangled
        );
    }
}

// ── The enclosing signature ───────────────────────────────────────────────────
//
// The two real symbols above take NO parameters, and that is the whole reason
// the following defect survived: the scope component was skipped by scanning to
// the **first `@`**, which is correct only for a `void` parameter list. A
// parameter list is terminated by `@Z`, and a class-typed parameter carries
// `@`s of its own, so the scan stopped mid-encoding and everything after was
// misread:
//
//   ?x@?1??f@@YAXXZ@4HA    decoded    — `YAXXZ` happens to contain no `@`
//   ?x@?1??f@@YAXH@Z@4HA   DECLINED   — stopped inside `H@Z`
//
// Same shape as the legacy-Rust hash length at iter 155: the corpus had one
// example, it exercised one point of the grammar, and the check passed.

fn oracle(sym: &str) -> Option<String> {
    msvc_demangler::demangle(sym, msvc_demangler::DemangleFlags::llvm()).ok()
}

/// Every enclosing signature the oracle accepts must decode.
#[test]
fn a_local_static_decodes_whatever_its_enclosing_signature() {
    const RETURNS: [&str; 5] = ["X", "H", "D", "PAH", "_N"];
    const PARAMS: [&str; 6] = ["XZ", "H@Z", "HH@Z", "PAH@Z", "PAVFoo@@@Z", "ABH@Z"];

    let mut compared = 0;
    let mut declined = Vec::new();
    for r in RETURNS {
        for p in PARAMS {
            for idx in ['1', '2', '3'] {
                let sym = format!("?x@?{idx}??f@@YA{r}{p}@4HA");
                // The oracle arbitrates validity: a shape it rejects is a
                // generator artefact, not a finding.
                if oracle(&sym).is_none() {
                    continue;
                }
                compared += 1;
                if rustre_demangle::demangle(&sym).is_none() {
                    declined.push(sym);
                }
            }
        }
    }
    assert!(compared > 60, "vacuous: only {compared} shapes had ground truth");
    assert!(declined.is_empty(), "{} declined: {declined:#?}", declined.len());
}

/// Variable, type and scope index survive a parameterised enclosing function.
///
/// These expectations named the bare enclosing function for one iteration,
/// while the signature was still skipped; they pinned the gap rather than the
/// intended behaviour, and were updated when it was closed.
#[test]
fn the_variable_and_scope_index_survive_a_parameterised_enclosing() {
    for (sym, want) in [
        ("?x@?1??f@@YAXXZ@4HA", "int `void __cdecl f(void)'::`2'::x"),
        ("?x@?2??f@@YAXXZ@4HA", "int `void __cdecl f(void)'::`3'::x"),
        ("?y@?1??f@@YAXH@Z@4HA", "int `void __cdecl f(int)'::`2'::y"),
        ("?x@?1??g@@YAHXZ@4HA", "int `int __cdecl g(void)'::`2'::x"),
    ] {
        assert_eq!(rustre_demangle::demangle(sym).map(|r| r.demangled).as_deref(), Some(want));
    }
}

/// The enclosing *overload* is named, so distinct symbols render distinctly.
///
/// This was an ignored gap for one iteration. The blocker was a parser detail,
/// not ground truth: the shared function-tail parser requires full input
/// consumption — correctly, for a standalone symbol, since the trailing-input
/// fix — while a local scope embeds a complete symbol and is followed by the
/// variable's own storage class. Split into a `_partial` variant that reports
/// what it built and leaves the cursor where it stopped.
///
/// Asserted against the oracle rather than a hard-coded string, so it records
/// agreement rather than a belief about MSVC.
#[test]
fn the_enclosing_overload_is_named() {
    let normalise = |s: &str| s.replace(' ', "").replace("class", "").replace("struct", "");
    for sym in [
        "?x@?1??f@@YAXXZ@4HA",
        "?x@?1??f@@YAXH@Z@4HA",
        "?x@?1??f@@YAXPAVFoo@@@Z@4HA",
        "?x@?2??g@@YAHXZ@4HA",
    ] {
        let want = oracle(sym).unwrap_or_else(|| panic!("{sym}: invalid test input"));
        let got = rustre_demangle::demangle(sym)
            .unwrap_or_else(|| panic!("{sym} must decode"))
            .demangled;
        assert_eq!(normalise(&got), normalise(&want), "{sym}");
    }

    // The point of the change: overloads no longer collapse.
    let void_f = rustre_demangle::demangle("?x@?1??f@@YAXXZ@4HA").map(|r| r.demangled);
    let int_f = rustre_demangle::demangle("?x@?1??f@@YAXH@Z@4HA").map(|r| r.demangled);
    assert_ne!(void_f, int_f, "different overloads must give different scopes");
}

/// The no-signature marker `9` has no function tail to parse, so it falls back
/// to the bare name — the path the two real corpus symbols take. Pinned
/// separately because the fallback is what the parameterised fix must not
/// break, and it broke it once already.
#[test]
fn the_no_signature_marker_still_falls_back_to_the_bare_name() {
    let r = rustre_demangle::demangle("?_OptionsStorage@?1??__local_stdio_printf_options@@9@4_KA")
        .expect("must decode");
    assert_eq!(
        r.demangled,
        "unsigned long long `__local_stdio_printf_options'::`2'::_OptionsStorage"
    );
}

/// The gap is a defect, not a presentation preference: the oracle separates
/// them. Asserted so the ignored test above cannot be waved away as style.
#[test]
fn the_oracle_distinguishes_what_we_collapse() {
    let a = oracle("?x@?1??f@@YAXXZ@4HA").expect("valid");
    let b = oracle("?x@?1??f@@YAXH@Z@4HA").expect("valid");
    assert_ne!(a, b, "the oracle must separate the overloads");
    assert!(a.contains("f(void)"), "oracle names the signature: {a}");
    assert!(b.contains("f(int)"), "oracle names the signature: {b}");
}
