//! The structured decomposition must agree with the rendered string.
//!
//! `DemanglingResult` carries both a `demangled` string and a decomposition
//! (`namespace`, `class`, `function`). Consumers use the fields — the
//! decompiler names variables from them — so the two must describe the same
//! symbol. Nothing checked that before: a backend could report
//! `function: "foo"` while rendering `bar::baz()` and every existing test
//! would still pass.

use std::collections::BTreeMap;

fn corpora() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// `class` and `namespace` must describe the same symbol as the string.
///
/// Completes the check below, which only covered `function`. A backend that
/// reported the wrong enclosing type would still render correctly and pass
/// every differential suite, since those compare strings alone.
#[test]
fn class_and_namespace_appear_in_the_rendered_string() {
    let mut offenders: Vec<(&str, &'static str, String, String)> = Vec::new();
    let mut checked = 0usize;
    for s in corpora() {
        let Some(r) = rustre_demangle::demangle(s) else {
            continue;
        };
        for (label, field) in [("class", &r.class), ("namespace", &r.namespace)] {
            let Some(value) = field.as_deref().filter(|v| !v.is_empty()) else {
                continue;
            };
            checked += 1;
            if !r.demangled.contains(value) {
                offenders.push((s, label, value.to_owned(), r.demangled.clone()));
            }
        }
    }

    // Guard against passing vacuously: no offenders because the fields are
    // right, and no offenders because the fields are empty, look identical
    // from a green test.
    println!("checked {checked} class/namespace entries");
    assert!(
        checked > 500,
        "only {checked} class/namespace entries populated — the decomposition \
         is not being filled in"
    );
    assert!(
        offenders.is_empty(),
        "{} symbols report a class/namespace absent from their rendered \
         form; first 10: {:#?}",
        offenders.len(),
        &offenders[..offenders.len().min(10)]
    );
}

/// Decoded parameter types and return type must appear in the rendered form.
///
/// The last two fields of the decomposition, and the ones a decompiler builds
/// signatures from: a wrong `args` entry becomes a wrong function prototype
/// downstream, with nothing in the rendered string to contradict it.
#[test]
fn args_and_return_type_appear_in_the_rendered_string() {
    let mut offenders: Vec<(&str, &'static str, String, String)> = Vec::new();
    let mut checked = 0usize;
    for s in corpora() {
        let Some(r) = rustre_demangle::demangle(s) else {
            continue;
        };
        for arg in r.args.iter().filter(|a| !a.is_empty()) {
            checked += 1;
            if !r.demangled.contains(arg) {
                offenders.push((s, "arg", arg.clone(), r.demangled.clone()));
            }
        }
        if let Some(ret) = r.return_type.as_deref().filter(|t| !t.is_empty()) {
            checked += 1;
            if !r.demangled.contains(ret) {
                offenders.push((s, "return_type", ret.to_owned(), r.demangled.clone()));
            }
        }
    }

    // Without this the suite would pass vacuously if `args` stopped being
    // populated at all — a silent loss of the decomposition, indistinguishable
    // from every field being consistent.
    println!("checked {checked} arg/return-type entries");
    assert!(
        checked > 500,
        "only {checked} arg/return-type entries populated across both corpora \
         — the decomposition is not being filled in"
    );
    assert!(
        offenders.is_empty(),
        "{} symbols report an arg or return type absent from their rendered \
         form; first 10: {:#?}",
        offenders.len(),
        &offenders[..offenders.len().min(10)]
    );
}

/// Every decoded symbol's `function` must appear in its rendered form.
#[test]
fn function_field_appears_in_the_rendered_string() {
    let mut offenders: BTreeMap<String, Vec<(&str, String, String)>> = BTreeMap::new();
    let mut checked = 0usize;

    for s in corpora() {
        let Some(r) = rustre_demangle::demangle(s) else {
            continue;
        };
        if r.function.is_empty() {
            continue;
        }
        checked += 1;
        if !r.demangled.contains(&r.function) {
            offenders
                .entry(format!("{:?}", r.abi))
                .or_default()
                .push((s, r.function.clone(), r.demangled.clone()));
        }
    }

    let total: usize = offenders.values().map(Vec::len).sum();
    for (abi, items) in &offenders {
        println!("  {:>5}  {abi}", items.len());
        for (sym, func, dem) in items.iter().take(3) {
            println!("           {sym}\n             function: {func}\n             rendered: {dem}");
        }
    }
    println!("checked {checked} decoded symbols, {total} inconsistent");

    // Same vacuity guard as the sibling tests: an empty `function` on every
    // symbol would make this pass while the decomposition carried nothing.
    assert!(
        checked > 2000,
        "only {checked} symbols reported a non-empty `function` — the \
         decomposition is not being filled in"
    );
    assert!(
        offenders.is_empty(),
        "{total} symbols report a `function` that does not appear in their \
         rendered form — the decomposition and the string disagree"
    );
}

/// The decomposition must account for the *whole* qualified name, not merely
/// have each part appear somewhere in it.
///
/// Containment is the weaker property: if a middle component is dropped, every
/// surviving part still appears, and the check passes. That is exactly how Go
/// lost `OnceValue` from `init.OnceValue.func5` while `namespace`, `class` and
/// `function` all remained individually present in the output.
///
/// Joining `namespace::class::function` and requiring the result to appear
/// closes that gap for the `::`-separated ABIs: Itanium, MSVC, legacy Rust
/// (which shares the `_Z` sigil) and Rust v0, whose `_R` form has to be
/// matched through `sigil::is_rust_v0` rather than a prefix test — writing
/// `starts_with("_R")` here would claim `_RTC_Initialize` and other plain C
/// names, the exact defect `src/sigil.rs` exists to prevent.
///
/// Widening the filter from Itanium/MSVC alone moved the count 825 -> 889
/// with no new offenders, so Rust's decomposition satisfies the same property.
#[test]
fn namespace_class_function_rejoin_into_the_rendered_name() {
    let mut checked = 0usize;
    let mut offenders: Vec<(&str, String, String)> = Vec::new();

    for s in corpora()
        .into_iter()
        .filter(|l| {
            l.starts_with("_Z") || l.starts_with("__Z") || l.starts_with('?')
                || rustre_demangle::sigil::is_rust_v0(l)
        })
    {
        let Some(r) = rustre_demangle::demangle(s) else {
            continue;
        };
        if r.function.is_empty() {
            continue;
        }
        let mut joined = String::new();
        if let Some(ns) = &r.namespace {
            joined.push_str(ns);
            joined.push_str("::");
        }
        if let Some(c) = &r.class {
            joined.push_str(c);
            joined.push_str("::");
        }
        joined.push_str(&r.function);

        checked += 1;
        // Compare with the angle brackets removed from BOTH sides.
        //
        // An inherent impl renders as `<std::path::Path>::is_absolute`, and the
        // brackets are syntax rather than part of any name, so the fields
        // report `std::path` / `Path` / `is_absolute`. Every component is
        // present and in order — the join is `std::path::Path::is_absolute` —
        // but a literal `contains` cannot see that through the punctuation.
        //
        // This does NOT weaken what the test is for. Its purpose is to catch a
        // DROPPED middle component (Go losing `OnceValue` from
        // `init.OnceValue.func5`), and a dropped component still fails: the
        // join would name something the rendering does not contain in that
        // order, brackets or no brackets.
        let strip = |t: &str| -> String { t.chars().filter(|c| *c != '<' && *c != '>').collect() };
        if !strip(&r.demangled).contains(&strip(&joined)) {
            offenders.push((s, joined, r.demangled.clone()));
        }
    }

    println!("{checked} Itanium/MSVC/Rust symbols rejoined");
    assert!(
        checked > 500,
        "only {checked} symbols reached the check — suite gone vacuous"
    );
    assert!(
        offenders.is_empty(),
        "{} decompositions do not rejoin into the rendered name; first 5: {:#?}",
        offenders.len(),
        &offenders[..offenders.len().min(5)]
    );
}
