//! A Go `type:` descriptor rewrite must preserve its whole payload.
//!
//! `go_completeness.rs` deliberately excludes the `type:` and `go:` namespaces
//! because they are *rewritten* rather than echoed — `type:.eq.T` becomes
//! `type descriptor for .eq.T`, so the literal `type:` prefix does not survive
//! and the component-reappearance check there would false-positive on it.
//!
//! That exclusion left the rewrite itself unguarded: it has its own completeness
//! property — everything after `type:` must reappear verbatim — and nothing
//! checked it. Since Go has no oracle, a rewrite that dropped a component of a
//! nested generic (`sync/atomic.Pointer[go.shape.struct { … }]`) would be
//! invisible to every other test, exactly the failure mode that lost `OnceValue`
//! and `osyield` from ordinary Go names.
//!
//! Measured 2026-07-23: every decoding `type:` symbol keeps its full payload;
//! this pins that.
//!
//! Amended 2026-07-30 (iter 141): a change that stripped the synthetic
//! `<pkg>.shape.` qualifier here was REVERTED. The corpus holds both
//! `type:.eq.internal/sync.indirect[go.shape.interface {},…]` and
//! `type:.eq.internal/sync.indirect[interface {},…]` as separate symbols, so
//! the qualifier distinguishes a shape-instantiated descriptor from a concrete
//! one and removing it merges two real symbols. Verbatim is correct here, even
//! though type ARGUMENTS elsewhere do strip it — see
//! `tests/shape_qualifier_is_load_bearing.rs`.

#[test]
fn type_descriptor_payload_survives_the_rewrite() {
    let syms: Vec<&str> = include_str!("data/real_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|s| s.starts_with("type:"))
        .collect();

    let mut checked = 0usize;
    let mut offenders: Vec<(&str, String)> = Vec::new();

    for s in &syms {
        let Some(r) = rustre_demangle::demangle(s) else {
            // A declined `type:` symbol (e.g. the bare wildcard `type:*`) has no
            // payload to preserve; only the ones that decode are constrained.
            continue;
        };
        // The payload is everything after the `type:` prefix. The rewrite may
        // reword the prefix (`type:` -> `type descriptor for `) but must carry
        // the payload through unchanged.
        let payload = s.strip_prefix("type:").unwrap_or(s);
        checked += 1;
        if !r.demangled.contains(payload) {
            offenders.push((s, r.demangled.clone()));
        }
    }

    println!("{checked} type: descriptors checked for payload completeness");
    assert!(
        checked > 40,
        "only {checked} type: descriptors decoded — the suite has gone vacuous"
    );
    assert!(
        offenders.is_empty(),
        "{} type: descriptors dropped part of their payload in the rewrite; \
         first 10: {:#?}",
        offenders.len(),
        &offenders[..offenders.len().min(10)]
    );
}
