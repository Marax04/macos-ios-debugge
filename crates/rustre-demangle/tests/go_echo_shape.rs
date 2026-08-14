//! Every Go identity-echo must be a genuinely Go-shaped name.
//!
//! Go names are already human-readable, so decoding one to itself is faithful,
//! not fabrication — `errors.Is`, `internal/cpu.Initialize` and ~1800 others in
//! the corpus legitimately echo, which is why `only_go_may_decode_a_symbol_to_
//! itself` permits Go (and only Go) to do so. The defect is never the echo; it
//! is a *non-Go* symbol wearing a Go label. `__emutls_v.<mangled>` (a C++
//! thread-local) and `msg.0` / `C.9.0` (GCC local statics) were each caught
//! exactly that way — echoed back as `abi: Go`.
//!
//! Those were fixed at the detector, but the detector is one function and this
//! is the property stated over the whole corpus: if a Go identity-echo is ever
//! *not* Go-shaped, some non-Go class has slipped back into the permissive
//! path. The shape test is intentionally strict about the two forms already
//! seen — a bare `<ident>.<digits>` local static, and anything that is not a
//! dotted name at all — because those are the intrusions that actually
//! happened, not hypothetical ones.

/// A Go symbol carries a package path and at least one named component; it is
/// never a GCC local static, and never a non-dotted bare name.
fn is_go_shaped(s: &str) -> bool {
    if !s.contains('.') {
        return false;
    }
    if rustre_demangle::decline::is_gcc_local_static(s) {
        return false;
    }
    // At least one dot-separated component must be a named identifier rather
    // than a bare integer — the same grammar property that separates Go from a
    // local static, applied to the whole name so `go:func`, `internal/abi.Name`
    // and `errors..typeAssert.2` all qualify.
    s.split('.')
        .any(|c| !c.is_empty() && !c.bytes().all(|b| b.is_ascii_digit()))
}

#[test]
fn every_go_identity_echo_is_go_shaped() {
    let corpus = include_str!("data/real_symbols.txt");
    let mut echoes = 0usize;
    let mut offenders: Vec<&str> = Vec::new();

    for s in corpus.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Some(r) = rustre_demangle::demangle(s) else {
            continue;
        };
        if r.abi != rustre_demangle::ManglingAbi::Go || r.demangled != s {
            continue;
        }
        echoes += 1;
        if !is_go_shaped(s) {
            offenders.push(s);
        }
    }

    // Vacuity guard: the corpus carries ~1800 Go echoes. A collapse to near
    // zero would make this pass while measuring nothing — the same green-but-
    // empty trap the emutls fix could otherwise reintroduce by over-rejecting.
    println!("{echoes} Go identity echoes, {} not Go-shaped", offenders.len());
    assert!(
        echoes > 1000,
        "only {echoes} Go identity echoes — the permissive path changed shape \
         and this guard is no longer measuring it"
    );
    assert!(
        offenders.is_empty(),
        "{} Go identity echoes are not Go-shaped — a non-Go class has slipped \
         back into the permissive detector; first 10: {:#?}",
        offenders.len(),
        &offenders[..offenders.len().min(10)]
    );
}
