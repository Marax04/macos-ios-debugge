//! Shared oracle plumbing for the MSVC differential suites
//! (`differential_msvc.rs` and `differential_proptest_msvc.rs`).

#![allow(
    dead_code,
    reason = "shared test module: each test target uses a different subset"
)]

use msvc_demangler::{demangle as reference_demangle, DemangleFlags};

/// Demangle with the reference crate; `None` when it rejects the symbol
/// (no ground truth).
pub fn reference(sym: &str) -> Option<String> {
    reference_demangle(sym, DemangleFlags::COMPLETE).ok()
}

/// The reference and this crate agree on substance but not always on
/// presentation: `undname` writes east-const (`char const *`), elaborates
/// class tags (`class Foo`) and uses fixed-width aliases (`uint64_t`), while
/// this crate writes `const char*` and `unsigned long long`. Collapse those
/// purely cosmetic differences so the comparison is about demangling, not
/// formatting.
///
/// `const` placement is normalised by *removing* the `const` tokens and
/// appending their count: placement no longer matters, but dropping or
/// inventing a `const` still fails the comparison.
pub fn normalise(s: &str) -> String {
    let mut out = s
        .replace("class ", "")
        .replace("struct ", "")
        .replace("union ", "")
        .replace("enum ", "")
        // 128-bit: the reference writes `int128_t`, MSVC and this crate write
        // `__int128`. Placed before the 64-bit rules so `uint128_t` is not
        // partially matched by them.
        .replace("uint128_t", "unsigned __int128")
        .replace("int128_t", "__int128")
        .replace("uint64_t", "unsigned long long")
        .replace("uint32_t", "unsigned int")
        .replace("uint16_t", "unsigned short")
        // Keep after the unsigned forms: `uint64_t` contains `int64_t`.
        .replace("int64_t", "long long")
        .replace("int32_t", "int")
        .replace("int16_t", "short")
        .replace("__ptr64", "");
    let const_count = out.matches("const").count();
    out = out.replace("const", "");
    // Drop whitespace entirely: `undname` is inconsistent about spacing (it
    // even joins a UDT type and the variable name, `struct A0A`), and both
    // sides receive the same transform, so genuinely different words still
    // diverge.
    out.retain(|c| c != ' ');
    format!("{out}|const x{const_count}")
}

/// Compare one symbol against the reference.
///
/// Returns `Err(message)` on a genuine divergence; `Ok(())` when they agree
/// or when the reference has no opinion.
pub fn compare(sym: &str) -> Result<(), String> {
    let Some(want) = reference(sym) else {
        return Ok(()); // reference rejects it: no ground truth
    };
    match rustre_demangle::demangle(sym) {
        Some(got) if normalise(&got.demangled) == normalise(&want) => Ok(()),
        Some(got) => Err(format!(
            "{sym}\n  reference: {want}\n  ours:      {}",
            got.demangled
        )),
        None => Err(format!("{sym}\n  reference: {want}\n  ours:      <None>")),
    }
}
