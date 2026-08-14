//! Adversarial input crossed with the features, which had never been combined.
//!
//! Iter 132 found MSVC absorbing a TRUNCATED symbol; iters 134 and 84 found
//! stack overflows from deep NESTING. Both were probed alone. `recursion_is_
//! bounded.rs` sweeps nesting per ABI but every shape there carries one feature
//! and no modifier — no clone suffix, no Mach-O prefix, no operator suffix.
//!
//! That matters because iter 149 showed a modifier can change which backend
//! claims a symbol: a clone suffix now diverts anything that does not account
//! for it to the shared wrapper. A diverted path is a path the nesting sweep
//! never exercised.
//!
//! **Measured 2026-07-30: clean.** No modifier rescues a broken symbol, and no
//! composed shape exhausts the stack — including a 20000-level chain of nested
//! D functions (a 168 KB symbol) through iter 130's speculative parse.

/// A modifier must not make a broken symbol look whole.
///
/// The property that would have caught iter 132's defect had the truncation
/// carried a suffix: a decoder that skips a suffix it cannot parse could just as
/// easily skip the damage.
#[test]
fn a_modifier_never_rescues_a_truncated_symbol() {
    const TRUNCATED: &[&str] = &[
        "?bar@Foo@@QAEXX",
        "?bar@Foo@@QAEX",
        "??0Foo@@QAE@",
        "_D4main3fooFiZ",
        "_RNvC1a1",
        "pkg__",
        "Java_com_foo_",
        "_ZN2ns4func",
    ];
    let mut checked = 0;
    let mut rescued = Vec::new();
    for base in TRUNCATED {
        assert_eq!(
            rustre_demangle::demangle(base),
            None,
            "{base} must decline on its own — the vector is not truncated"
        );
        for sfx in [".cold", ".llvm.123", ".part.0"] {
            let sym = format!("{base}{sfx}");
            checked += 1;
            if let Some(r) = rustre_demangle::demangle(&sym) {
                rescued.push(format!("{sym} => {}", r.demangled));
            }
        }
    }
    assert!(checked >= 24, "vacuous: only {checked} combinations");
    assert!(
        rescued.is_empty(),
        "a modifier rescued a broken symbol:\n{}",
        rescued.join("\n")
    );
}

/// Deep nesting composed with each modifier must return, not abort.
///
/// Returning at all is the requirement: a stack overflow cannot be caught, so a
/// consumer walking an untrusted symbol table loses the process.
#[test]
fn composed_deep_nesting_does_not_exhaust_the_stack() {
    type Maker = fn(usize) -> String;
    let makers: &[(&str, Maker)] = &[
        ("d pointers + clone", |n| {
            format!("_D4main3fooF{}iZv.cold", "P".repeat(n))
        }),
        ("d pointers + mach-o", |n| {
            format!("__D4main3fooF{}iZv", "P".repeat(n))
        }),
        ("msvc pointers + clone", |n| {
            format!("?foo@@YAX{}H@Z.cold", "PEA".repeat(n))
        }),
        ("itanium + mach-o", |n| format!("__Z3foo{}i", "P".repeat(n))),
        ("swift nesting + suffixes", |n| {
            format!("$s4main3foo{}yyF{}", "S".repeat(n), "TA".repeat(n))
        }),
        ("swift suffixes + clone", |n| {
            format!("$s4main3fooyyF{}.cold", "TA".repeat(n))
        }),
        ("go nested generics", |n| {
            format!("main.{}A[go.shape.int]{}.m.func1", "B[".repeat(n), "]".repeat(n))
        }),
        ("go closure chain", |n| format!("main.f{}", ".func1".repeat(n))),
        ("d nested functions", |n| {
            let mut s = String::from("_D4main3fooFZ");
            for i in 0..n {
                let name = format!("b{i}");
                s.push_str(&name.len().to_string());
            s.push_str(&name);
            s.push_str("FZ");
            }
            s.push('v');
            s
        }),
    ];

    let mut tried = 0;
    for (_name, make) in makers {
        for depth in [8usize, 64, 256, 1024, 4096, 20000] {
            let _ = rustre_demangle::demangle(&make(depth));
            tried += 1;
        }
    }
    assert_eq!(tried, 54, "expected 54 composed nesting cases, tried {tried}");
}

/// Nesting stays CORRECT as it deepens, not merely survivable.
///
/// A depth limit that silently truncated would pass the test above. These check
/// the rendering actually grows with the input — and that brackets stay
/// balanced, the property that exposed iter 148's defect.
#[test]
fn composed_nesting_stays_correct_as_it_deepens() {
    for n in 1..=4usize {
        // Go: nested generic instantiations plus a closure.
        let sym = format!("main.{}A[go.shape.int]{}.m.func1", "B[".repeat(n), "]".repeat(n));
        let out = rustre_demangle::demangle(&sym)
            .unwrap_or_else(|| panic!("{sym} must decode"))
            .demangled;
        assert_eq!(out.matches("B[").count(), n, "{sym} lost a level: {out}");
        let mut depth = 0i32;
        for c in out.chars() {
            match c {
                '[' => depth += 1,
                ']' => depth -= 1,
                _ => {}
            }
            assert!(depth >= 0, "{sym} closed a bracket that was never opened: {out}");
        }
        assert_eq!(depth, 0, "{sym} left brackets open: {out}");

        // D: a chain of functions nested in one another's scope.
        let mut d = String::from("_D4main3fooFZ");
        for i in 0..n {
            let name = format!("b{i}");
            d.push_str(&name.len().to_string());
            d.push_str(&name);
            d.push_str("FZ");
        }
        d.push('v');
        let out = rustre_demangle::demangle(&d)
            .unwrap_or_else(|| panic!("{d} must decode"))
            .demangled;
        for i in 0..n {
            assert!(out.contains(&format!("b{i}")), "{d} lost b{i}: {out}");
        }
    }
}
