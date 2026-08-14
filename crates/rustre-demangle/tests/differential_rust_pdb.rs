//! Differential testing of the real Rust v0 symbols against `rustc-demangle`.
//!
//! `pdb_corpus.rs` asserts that all 137 rustc-emitted `_R…` names decode. That
//! is a weaker claim than it looks: decoding and decoding *correctly* are
//! different properties, and the crate has already been caught producing
//! confident-but-wrong output elsewhere (Go closures invented on symbols that
//! had none). These symbols come from rustc 1.96, so `rustc-demangle` — the
//! compiler's own demangler — is authoritative ground truth for every one.

/// Rust v0 proper: `_R` followed by an RFC 2603 path tag. Excludes MSVC CRT
/// names such as `_RTC_Initialize`, which merely share the prefix.
fn is_rust_v0(s: &str) -> bool {
    s.strip_prefix("_R")
        .and_then(|r| r.chars().next())
        .is_some_and(|c| matches!(c, 'N' | 'I' | 'C' | 'M' | 'X' | 'Y' | 'K' | 'B'))
}

fn symbols() -> Vec<&'static str> {
    include_str!("data/pdb_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|l| is_rust_v0(l))
        .collect()
}

/// `rustc-demangle`'s rendering, without the trailing hash it may append.
fn reference(sym: &str) -> String {
    format!("{:#}", rustc_demangle::demangle(sym))
}

/// Cosmetic differences that are not disagreements about the symbol.
///
/// Kept deliberately small: every rule here is a place where a real divergence
/// could hide, so anything beyond whitespace has to earn its place.
fn normalise(s: &str) -> String {
    s.replace(", ", ",").replace(' ', "")
}

#[test]
fn real_rust_v0_symbols_match_rustc_demangle() {
    let syms = symbols();
    assert!(
        syms.len() > 100,
        "expected >100 real Rust v0 symbols, found {}",
        syms.len()
    );

    let mut mismatches: Vec<(&str, String, String)> = Vec::new();
    let mut compared = 0usize;
    for s in &syms {
        let want = reference(s);
        // `rustc-demangle` echoes anything it cannot parse; with no opinion of
        // its own there is no ground truth to compare against.
        if want == *s {
            continue;
        }
        compared += 1;
        match rustre_demangle::demangle(s) {
            Some(got) if normalise(&got.demangled) == normalise(&want) => {}
            Some(got) => mismatches.push((s, want, got.demangled)),
            None => mismatches.push((s, want, "<declined>".to_owned())),
        }
    }

    // Report the count actually compared, not the corpus size: symbols the
    // oracle echoes are skipped above, and printing `syms.len()` here would
    // overstate the coverage — the metric-honesty this crate insists on.
    println!("real Rust v0: {compared} compared of {}", syms.len());
    assert!(
        mismatches.is_empty(),
        "{} of {compared} real Rust v0 symbols diverge from rustc-demangle; first 10: {:#?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(10)]
    );
}

/// The oracle must actually have an opinion on most of the corpus, or the
/// suite above passes vacuously by skipping everything.
#[test]
fn oracle_is_not_vacuous() {
    let syms = symbols();
    let with_opinion = syms.iter().filter(|s| reference(s) != ***s).count();
    assert!(
        with_opinion * 10 >= syms.len() * 9,
        "rustc-demangle only decoded {with_opinion}/{} symbols — the \
         differential suite is going vacuous",
        syms.len()
    );
}
