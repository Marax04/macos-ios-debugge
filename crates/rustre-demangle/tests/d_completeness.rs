//! Every named component of a D symbol must reach the rendering.
//!
//! The inverse of `tests/d_invents_no_name.rs` (iter 107): that one checks nothing is
//! *added*, this one that nothing is *lost*. Go has had both since iters 64 and 71, and
//! several D defects fixed earlier this session were omissions — the tuple count read as
//! a length (iter 53), named types rendering empty (iter 60) — so the guard is apt.
//!
//! Measured 2026-07-30: 80 grammar-derived renderings, **zero lost components.**
//!
//! ### Why the extractor is scoped to the leading qualified name
//!
//! A general "every length-prefixed identifier" extractor is **impossible without
//! parsing D**, because a digit in *type* position is a grammar number rather than a
//! length:
//!
//! ```text
//! _D…FG3iZv     the 3 is an array dimension  -> a naive reader sees identifier "iZv"
//! _D…FB2iiZv    the 2 is a tuple count       -> a naive reader sees identifier "ii"
//! ```
//!
//! My first version did exactly that and reported six false losses. Scoping to `_D`
//! followed by consecutive `<len><chars>` pairs — which stops at the first non-digit —
//! is unambiguous, and it covers what the guard is for: the symbol's own name
//! components.

/// `_D` followed by consecutive `<len><chars>` pairs. Stops at the first byte that is
/// not a digit, which is where the module path ends and the type grammar begins.
fn module_path(sym: &str) -> Vec<String> {
    let Some(rest) = sym.strip_prefix("_D") else {
        return Vec::new();
    };
    let bytes = rest.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            break;
        }
        let Ok(len) = rest[start..i].parse::<usize>() else {
            break;
        };
        // Checked: the length comes from the symbol (iters 82-83).
        let Some(end) = i.checked_add(len) else {
            break;
        };
        if len == 0 || end > bytes.len() {
            break;
        }
        let Some(name) = rest.get(i..end) else {
            break;
        };
        out.push(name.to_owned());
        i = end;
    }
    out
}

/// Length prefixes computed, never hand-counted.
fn sym(parts: &[&str], tail: &str) -> String {
    let mut out = String::from("_D");
    for p in parts {
        out.push_str(&p.len().to_string());
        out.push_str(p);
    }
    out.push_str(tail);
    out
}

const TAILS: &[&str] = &[
    "FiZv", "FZv", "FAyaZv", "FPiZv", "FG3iZv", "FB2iiZv", "FHiAyaZv", "FDFiZvZv",
    "FC4main3FooZv", "FS4main3BarZv", "FE4main3ColZv", "FT4main3TypZv", "FNaiZv",
    "FNhiZv", "FNnZv", "i", "FPFiZvZv", "FC4main3FooC4main3BarZv", "FAS4main3BarZv",
    "FiiZv",
];

#[test]
fn no_d_symbol_loses_a_named_component() {
    let paths: &[&[&str]] = &[
        &["main", "foo"],
        &["mymod", "myclass", "method"],
        &["verylongmodulename", "fn"],
        &["a", "b", "c", "d"],
    ];

    let mut examined = 0;
    let mut lost: Vec<String> = Vec::new();
    for parts in paths {
        for tail in TAILS {
            let s = sym(parts, tail);
            let Some(r) = rustre_demangle::demangle(&s) else {
                continue;
            };
            if r.abi != rustre_demangle::ManglingAbi::D {
                continue;
            }
            examined += 1;
            for component in module_path(&s) {
                if !r.demangled.contains(&component) {
                    lost.push(format!("{component:?} missing\n  in  {s}\n  out {}", r.demangled));
                }
            }
        }
    }

    assert!(examined > 70, "vacuous: only {examined} D renderings examined");
    assert!(
        lost.is_empty(),
        "{} D symbols lost a named component; first 5:\n{:#?}",
        lost.len(),
        &lost[..lost.len().min(5)]
    );
}

/// The extractor must find the components, and must not find ones that are not there.
///
/// Without this the sweep above passes trivially if `module_path` returns nothing — the
/// vacuity trap, and the reason the scoping decision needs its own evidence.
#[test]
fn the_module_path_extractor_is_correct_and_sensitive() {
    // Finds exactly the components, in order.
    assert_eq!(module_path("_D4main3fooFiZv"), vec!["main", "foo"]);
    assert_eq!(
        module_path("_D5mymod7myclass6methodFiZv"),
        vec!["mymod", "myclass", "method"]
    );
    assert_eq!(module_path("_D1a1b1c1dFiZv"), vec!["a", "b", "c", "d"]);

    // Stops at the type grammar rather than reading grammar numbers as lengths — the
    // mistake that produced six false losses.
    assert_eq!(
        module_path("_D4main3fooFG3iZv"),
        vec!["main", "foo"],
        "the array dimension 3 must not be read as a length prefix"
    );
    assert_eq!(
        module_path("_D4main3fooFB2iiZv"),
        vec!["main", "foo"],
        "the tuple count 2 must not be read as a length prefix"
    );

    // Sensitive: a component that is genuinely absent from a rendering is reported.
    let rendering = "void main.foo(int)";
    assert!(
        module_path("_D4main3fooFiZv")
            .iter()
            .all(|c| rendering.contains(c)),
        "premise: both components are present"
    );
    assert!(
        !rendering.contains("missingname"),
        "the check would flag a component the rendering omits"
    );

    // Not a D symbol: no components, so the sweep skips it rather than passing it.
    assert!(module_path("_Z3fooi").is_empty());
}
