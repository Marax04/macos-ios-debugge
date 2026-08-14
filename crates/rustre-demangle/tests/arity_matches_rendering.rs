//! The `args` field must have the same arity as the rendered parameter list.
//!
//! `tests/structured_consistency.rs` requires each argument to *appear* in the
//! rendering. That is satisfied by a list that is too short, by one that is too
//! long if the extra text occurs anywhere in the string, and — vacuously — by
//! an empty list. Arity is the property it cannot see.
//!
//! It is worth checking directly because a wrong parameter count is the defect
//! this project treats as first-class elsewhere: the sibling decompiler crate
//! tracks phantom parameters separately from missing ones precisely because a
//! phantom argument compiles cleanly and is silently wrong. The same reasoning
//! applies to a symbol table: a caller reading `args.len()` gets a signature.
//!
//! No oracle is needed. The rendering already states the parameter list, so the
//! two views of the same symbol can be required to agree with each other —
//! 724 symbols across the real corpora carry one. Measured at **zero**
//! mismatches (2026-07-28); this exists so it stays there.

/// Arity of the trailing parameter list of a rendering, if it has one.
///
/// Deliberately conservative — it returns `None` rather than guessing whenever
/// the shape is not clearly a parameter list, so a parsing weakness here can
/// only weaken the check, never make it lie:
///
/// * the `(…)` must be balanced and sit at the end, modulo cv/ref qualifiers,
///   so `(anonymous namespace)::x` is not mistaken for a call;
/// * commas are counted at bracket depth zero only, so a function-pointer
///   parameter (`void (*)(int, int)`) or a template argument list
///   (`map<int, int>`) counts once, not twice;
/// * `(void)` is zero parameters, the C spelling of an empty list.
fn rendered_arity(rendering: &str) -> Option<usize> {
    let bytes = rendering.as_bytes();
    let (mut depth, mut close, mut open) = (0i32, None, None);
    for i in (0..bytes.len()).rev() {
        match bytes[i] {
            b')' => {
                if depth == 0 {
                    close = Some(i);
                }
                depth += 1;
            }
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    open = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let (open, close) = open.zip(close)?;

    let tail = rendering[close + 1..].trim();
    let qualifier_only = tail.is_empty()
        || ["const", "volatile", "&", "&&", "noexcept", "const&", "const&&"].contains(&tail);
    if !qualifier_only {
        return None;
    }

    let inner = rendering[open + 1..close].trim();
    if inner.is_empty() || inner == "void" {
        return Some(0);
    }
    let mut depth = 0i32;
    let mut count = 1;
    for c in inner.chars() {
        match c {
            '(' | '<' | '[' => depth += 1,
            ')' | '>' | ']' => depth -= 1,
            ',' if depth == 0 => count += 1,
            _ => {}
        }
    }
    Some(count)
}

fn corpus() -> impl Iterator<Item = &'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
}

#[test]
fn args_arity_agrees_with_the_rendered_parameter_list() {
    let mut offenders: Vec<(&str, String, usize, usize)> = Vec::new();
    let mut checked = 0usize;

    for sym in corpus() {
        let Some(r) = rustre_demangle::demangle(sym) else {
            continue;
        };
        let Some(want) = rendered_arity(&r.demangled) else {
            continue;
        };
        checked += 1;
        if r.args.len() != want {
            offenders.push((sym, r.demangled, want, r.args.len()));
        }
    }

    assert!(
        offenders.is_empty(),
        "{} signatures disagree with their own rendering; first 5: {:?}",
        offenders.len(),
        &offenders[..offenders.len().min(5)]
    );
    assert!(
        checked > 600,
        "vacuity guard: only {checked} parameter lists examined — either the \
         corpora moved or `rendered_arity` stopped recognising them"
    );
}

/// The arity extractor must not be the thing that is right.
///
/// A `rendered_arity` that returned `None` everywhere, or `Some(0)` always,
/// would make the sweep above pass while checking nothing. These pin the cases
/// it exists to handle — nested commas, an empty list spelled `(void)`, and a
/// `(…)` group that is part of a name rather than a call.
#[test]
fn the_arity_extractor_reads_what_it_claims_to() {
    assert_eq!(rendered_arity("foo::bar(int)"), Some(1));
    assert_eq!(rendered_arity("foo::bar(int, char const*)"), Some(2));
    assert_eq!(rendered_arity("foo::bar()"), Some(0));
    assert_eq!(rendered_arity("f(void)"), Some(0));
    // Commas inside a nested group belong to one parameter.
    assert_eq!(rendered_arity("f(void (*)(int, int))"), Some(1));
    assert_eq!(rendered_arity("f(std::map<int, int>, char)"), Some(2));
    // Trailing qualifiers still count as a parameter list.
    assert_eq!(rendered_arity("f(int) const"), Some(1));
    // Not a parameter list: the parens are inside the name.
    assert_eq!(rendered_arity("(anonymous namespace)::__new_handler"), None);
    // No parens at all.
    assert_eq!(rendered_arity("int x"), None);
}

/// Symbols whose ABI does not encode a return type must not invent one.
///
/// Itanium omits the return type of ordinary functions — `c++filt` prints none
/// either — and Rust does not encode one at all. Reporting a type there would
/// be fabrication, and reporting the *descriptive prefix* of a special symbol
/// as one is the specific way it could happen: `transaction clone for
/// std::bad_exception::what() const` has text before the name that is not a
/// type.
#[test]
fn no_return_type_is_invented_where_the_abi_encodes_none() {
    for sym in [
        "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE11_M_is_localEv",
        "_ZGTtNKSt13bad_exception4whatEv",
        "_ZN3foo3barEi",
        "_RNvC4main3foo",
    ] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(
            r.return_type.is_none(),
            "{sym} gained a return type its ABI does not encode: {:?}",
            r.return_type
        );
    }

    // Control: MSVC *does* encode one, and it must be reported.
    let r = rustre_demangle::demangle("?foo@@YAHH@Z").expect("must decode");
    assert_eq!(r.return_type.as_deref(), Some("int"));
}
