//! Demangled output must stay proportional to its input.
//!
//! `tests/hardening.rs` and `examples/bench_baseline.rs` cover the crash and
//! hang shapes of adversarial input. Unbounded *output* is a third, distinct
//! denial-of-service: Itanium back-references (`S_`, `S0_`…) each re-expand a
//! previously seen type, and a type may itself contain back-references, so a
//! short symbol could in principle expand super-linearly and exhaust memory
//! without ever panicking or looping.
//!
//! Measured worst case on 2026-07-23 was 1.5×. The bound below is deliberately
//! far looser: it is a tripwire for a lost recursion limit, not a style rule.

/// Inputs built to maximise expansion: back-reference runs, nested templates,
/// deep pointer chains and long length-prefixed names.
fn adversarial() -> Vec<String> {
    let mut cases = Vec::new();
    for depth in [1usize, 2, 4, 8, 16, 32, 64, 128] {
        let mut s = String::from("_Z1f");
        for _ in 0..depth {
            s.push_str("1AIiE");
        }
        s.push('E');
        cases.push(s);
    }
    for n in [8usize, 32, 128, 512, 2048] {
        let mut s = String::from("_Z1fIiEvT_");
        for _ in 0..n {
            s.push_str("S_");
        }
        cases.push(s);
    }
    for n in [16usize, 64, 256, 1024] {
        cases.push(format!("_Z1f{}i", "P".repeat(n)));
    }
    for n in [64usize, 256, 1024] {
        cases.push(format!("_ZN{n}{}E", "a".repeat(n)));
    }
    // The same shapes under the MSVC and Rust sigils, so a regression in
    // either backend is covered too.
    for n in [32usize, 256, 1024] {
        cases.push(format!("?f@@YAX{}H@Z", "PEA".repeat(n)));
        cases.push(format!("_RNvC{n}{}", "a".repeat(n)));
    }
    cases
}

/// No input may expand beyond a small constant factor.
#[test]
fn output_stays_proportional_to_input() {
    // 20× leaves ample room above the measured 1.5× while still failing long
    // before a symbol could expand into gigabytes.
    const MAX_RATIO: usize = 20;

    let mut decoded = 0usize;
    let mut offenders: Vec<(String, usize, usize)> = Vec::new();
    for c in adversarial() {
        let Some(r) = rustre_demangle::demangle(&c) else {
            continue;
        };
        decoded += 1;
        if r.demangled.len() > c.len() * MAX_RATIO {
            offenders.push((c.clone(), c.len(), r.demangled.len()));
        }
    }

    // Without this the test would pass vacuously the day every adversarial
    // shape starts being declined — which would look like safety while
    // actually meaning the suite stopped exercising the expansion paths.
    println!("{decoded} adversarial inputs decoded");
    assert!(
        decoded >= 10,
        "only {decoded} adversarial inputs decoded — this suite no longer \
         exercises the expansion paths"
    );

    assert!(
        offenders.is_empty(),
        "{} inputs expanded past {MAX_RATIO}x; first 5: {:#?}",
        offenders.len(),
        &offenders[..offenders.len().min(5)]
    );
}

/// The real corpus must not expand either — the same property on inputs that
/// are not adversarial at all, where a blowup would mean an ordinary symbol
/// triggering it.
#[test]
fn real_symbols_stay_proportional() {
    const MAX_RATIO: usize = 20;
    let mut worst = (0usize, 0usize, "");
    let mut checked = 0usize;
    for s in include_str!("data/real_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
    {
        let Some(r) = rustre_demangle::demangle(s) else {
            continue;
        };
        checked += 1;
        assert!(
            r.demangled.len() <= s.len() * MAX_RATIO,
            "{s} expanded {}x to {} bytes",
            r.demangled.len() / s.len().max(1),
            r.demangled.len()
        );
        if r.demangled.len() > worst.1 {
            worst = (s.len(), r.demangled.len(), s);
        }
    }
    println!(
        "largest output: {} bytes from {} bytes ({})",
        worst.1, worst.0, worst.2
    );
    // Vacuity guard: every symbol that declines is skipped, so an empty corpus
    // or a decoding regression would leave the ratio assertion untested.
    assert!(
        checked > 2000,
        "only {checked} symbols measured — nothing was checked for amplification"
    );
}
