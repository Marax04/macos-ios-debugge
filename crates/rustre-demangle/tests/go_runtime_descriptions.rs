//! Every key in the Go runtime description table must be answerable.
//!
//! `describe_runtime_symbol` is a curated lookup of well-known Go runtime
//! symbols. Its two existing unit tests check only that *one* known name
//! returns `Some` and *one* unknown name returns `None` — the "shape, not
//! effect" pattern this crate has been bitten by: they hold whether or not the
//! table is internally consistent.
//!
//! The failure they cannot see is a **dead entry**: a key added with a typo, a
//! trailing space, or a name the `match` arm spells differently from the
//! comment beside it. Such a key is unreachable and silently never described.
//!
//! Deliberately *not* asserted: that the table covers the corpus. It describes
//! 24 symbols and the corpora contain ~950 distinct `runtime.*` names, so 934
//! have no description — and that is correct. The table is a convenience for
//! well-known trampolines and panics, not a completeness claim, and
//! `describe_runtime_symbol` returns `Option` precisely to say "not one I
//! know". Nine of its keys (`runtime.goexit`, `runtime.morestack`, …) do not
//! appear in these corpora at all, which likewise is not a defect: they are
//! real Go symbols these twelve binaries happen not to reference.

use rustre_demangle::go_demangler::describe_runtime_symbol;

/// Extract the string literals the `match` arms key on, from the source.
///
/// Read out of the source rather than duplicated here, so the test cannot drift
/// from the table it checks — a hand-copied list would be exactly the kind of
/// second copy this crate keeps finding out of step with the first.
fn table_keys() -> Vec<String> {
    let src = include_str!("../src/go_demangler.rs");
    let start = src
        .find("pub fn describe_runtime_symbol")
        .expect("describe_runtime_symbol must exist");
    let body = &src[start..];
    let end = body.find("\n}\n").unwrap_or(body.len());

    let mut keys: Vec<String> = body[..end]
        .lines()
        .flat_map(|line| {
            line.split('"')
                .skip(1)
                .step_by(2)
                .filter(|p| p.starts_with("runtime."))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

#[test]
fn every_key_in_the_table_is_answered() {
    let keys = table_keys();
    assert!(
        keys.len() > 15,
        "vacuity guard: only {} keys extracted — the extractor broke, not the table",
        keys.len()
    );

    for key in &keys {
        let got = describe_runtime_symbol(key);
        assert!(
            got.is_some(),
            "{key} appears as a key but the function does not answer for it — \
             a dead entry (typo, stray whitespace, or a duplicated arm)"
        );
        let text = got.unwrap_or_default();
        assert!(!text.is_empty(), "{key} has an empty description");
        assert_ne!(
            text, key,
            "{key} is described by echoing itself, which tells a caller nothing"
        );
    }
}

/// A name that is not in the table must not be described.
///
/// The negative half, on inputs close enough to the real keys that a sloppy
/// prefix match would claim them — which a single `main.foo` cannot show.
#[test]
fn near_misses_are_not_described() {
    for name in [
        "main.foo",
        "runtime.mallocgc2",       // key plus a suffix
        "runtime.malloc",          // key minus a suffix
        "myruntime.mallocgc",      // key with a prefix
        "runtime.mallocgc.func1",  // key with a closure suffix
        "runtime.",
        "",
    ] {
        assert!(
            describe_runtime_symbol(name).is_none(),
            "{name:?} is not a table key but was described"
        );
    }
}
