//! `args.len()` must equal the parameter count in the rendered signature.
//!
//! `tests/structured_consistency.rs` already checks that every entry in `args`
//! *appears* in the rendered string. That is containment, not arity: a list
//! can hold the right strings and the wrong number of them. Wrong arity is the
//! worst shape a demangler can hand a consumer — a caller building a prototype
//! from `args` gets one that compiles cleanly and is silently false, which is
//! the failure mode the decompiler's own notes single out.
//!
//! It caught one: MSVC mangles an empty parameter list as `X`, rendered
//! `f(void)`, and `args` held `["void"]` — a phantom parameter on a function
//! that takes none. The Itanium path (`v`) always reported an empty list.

fn corpora() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// Count top-level parameters in a rendered signature, or `None` when there is
/// no argument list to count.
fn rendered_arity(s: &str) -> Option<usize> {
    let close = s.rfind(')')?;
    let mut depth = 0i32;
    let mut open = None;
    for (i, c) in s[..=close].char_indices().rev() {
        match c {
            ')' => depth += 1,
            '(' => {
                depth -= 1;
                if depth == 0 {
                    open = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let inner = &s[open? + 1..close];
    let trimmed = inner.trim();
    if trimmed.is_empty() || trimmed == "void" {
        return Some(0);
    }
    let mut d = 0i32;
    let mut n = 1usize;
    for c in inner.chars() {
        match c {
            '(' | '<' | '[' => d += 1,
            ')' | '>' | ']' => d -= 1,
            ',' if d == 0 => n += 1,
            _ => {}
        }
    }
    Some(n)
}

#[test]
fn args_count_matches_the_rendered_signature() {
    let mut checked = 0usize;
    let mut mismatches: Vec<(&str, usize, usize, String)> = Vec::new();

    for s in corpora() {
        let Some(r) = rustre_demangle::demangle(s) else {
            continue;
        };
        if r.args.is_empty() {
            continue;
        }
        let Some(want) = rendered_arity(&r.demangled) else {
            continue;
        };
        checked += 1;
        if want != r.args.len() {
            mismatches.push((s, r.args.len(), want, r.demangled.clone()));
        }
    }

    println!("{checked} symbols with a non-empty `args` checked");
    assert!(
        checked > 300,
        "only {checked} symbols carried arguments — suite gone vacuous"
    );
    assert!(
        mismatches.is_empty(),
        "{} symbols report an arity that contradicts their signature; \
         first 5: {:#?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(5)]
    );
}

/// `(void)` is an empty parameter list in both spellings the crate emits.
#[test]
fn void_parameter_list_is_zero_arity() {
    for sym in ["?__scrt_initialize_type_info@@YAXXZ", "?foo@@YAHXZ", "_Z3foov"] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(
            r.args.is_empty(),
            "{sym} takes no parameters, got args={:?} ({})",
            r.args,
            r.demangled
        );
    }
}
