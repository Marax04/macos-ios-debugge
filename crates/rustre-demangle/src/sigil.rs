//! One place for "does this string carry ABI X's sigil?".
//!
//! These predicates existed as ad-hoc `starts_with` tests scattered across the
//! crate, and they drifted apart.
//!
//! The `_R` test appeared in five places, `_D` in five, `_T` in three. Every
//! instance was too loose, so each claimed ordinary C names:
//! `_RTC_Initialize` (MSVC CRT) as Rust, `_DllMainCRTStartup` as D,
//! `_TIFFOpen` as Swift. A claimed-but-undecodable symbol is reported as
//! `DeclineReason::UnsupportedAbi` — a phantom defect, which is what hides
//! real ones.
//!
//! Clearing the `_R` copies took forty iterations of one-at-a-time discovery,
//! each fix looking complete because the evidence to hand showed a single
//! copy. Worse, tightening one side of a `detect`/`demangle` pair while
//! leaving the other turned a consistent error into a divergence that panicked
//! `if d.detect(s) { d.demangle(s).unwrap() }`.
//!
//! New sigil checks belong here. A bare `starts_with` on a two-character
//! prefix is almost always wrong.

/// Rust v0 (RFC 2603): `_R` followed by a path tag, or `__R` on Mach-O.
///
/// `C` crate root, `N` nested path, `M`/`X`/`Y` impl / trait-impl /
/// trait-definition, `I` generic args, `K` constant, `B` backreference. `T` is
/// deliberately absent — it is what `_RTC_Initialize` starts with.
///
/// The `__R` form is what an Apple symbol table holds, since Mach-O prefixes
/// every symbol with an underscore. `rustc-demangle` accepts both, and the
/// crate used to decline the second — losing every Rust v0 symbol read from a
/// macOS or iOS binary.
#[must_use]
pub fn is_rust_v0(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("__R").or_else(|| s.strip_prefix("_R")) else {
        return false;
    };
    let mut chars = rest.chars();
    let tag_ok = chars
        .next()
        .is_some_and(|c| matches!(c, 'C' | 'N' | 'M' | 'X' | 'Y' | 'I' | 'K' | 'B'));
    // A path tag introduces a path, so something must follow it. Without this
    // a truncated `_RN` was claimed here and declined by every decoder — the
    // `detect`/`demangle` divergence that panics
    // `if detect(s) { demangle(s).unwrap() }`.
    tag_ok && chars.next().is_some()
}

/// Legacy Rust: Itanium-shaped `_ZN…17h<16 hex digits>E`.
#[must_use]
pub fn is_rust_legacy(s: &str) -> bool {
    // `__ZN` is the Mach-O form. `is_rust_v0` and `is_d` were both taught their
    // underscored variants on 2026-07-23; this one was missed, so on a real
    // macOS or iOS binary — where EVERY symbol carries the extra underscore —
    // legacy Rust fell through to the Itanium backend and was labelled
    // `ManglingAbi::Itanium`. The rendered string was right (the Itanium path
    // strips the hash too), which is why nothing noticed: only the ABI field
    // was wrong, and consumers route on it.
    s.strip_prefix("__ZN")
        .or_else(|| s.strip_prefix("_ZN"))
        // A compiler suffix may follow the closing `E`: `.llvm.<hash>` from
        // ThinLTO, `.cold`, `.part.N`, `.constprop.N`. Requiring the symbol to
        // END with `E` rejected every one of them, so on an optimised binary —
        // where these are ubiquitous — legacy Rust fell through to the Itanium
        // backend. That mislabelled the ABI *and* leaked the hash the crate
        // strips everywhere else:
        //
        //   _ZN4core3fmt5write17h…E.cold
        //     was  core::fmt::write::h0123456789abcdef [clone .cold]
        //     want core::fmt::write.cold
        //
        // The trailing-hash test below still does the discriminating, so
        // admitting a suffix cannot let a C++ symbol in.
        .map(|t| t.split_once("E.").map_or(t, |(head, _)| head))
        .and_then(|t| t.strip_suffix('E').or(Some(t)))
        .is_some_and(ends_with_legacy_hash)
}

/// Whether `t` ends in legacy Rust's `<len>h<hex…>` disambiguator component.
///
/// This used to demand exactly `17h` + 16 hex digits, and that was too tight.
/// `rustc-demangle` — the oracle for this ABI — accepts a hash of *any* length,
/// down to a single digit, and rustc has not always emitted 16. The cost of the
/// narrow rule was the defect class this module exists to prevent, in its worst
/// form: a legacy symbol with an 8- or 20-digit hash was labelled
/// `ManglingAbi::Itanium` **and** rendered with the hash still attached —
///
/// ```text
///   _ZN4core3fmt5write9haaaaaaaaE
///     was  core::fmt::write::haaaaaaaa   [Itanium]
///     want core::fmt::write              [Rust]
/// ```
///
/// — leaking the very thing the crate strips everywhere else, and disagreeing
/// with the oracle on both fields at once.
///
/// Loosening a sigil test is the direction that historically invents defects,
/// so this is not a bare "ends in hex". The component must be *length-
/// prefixed*: the decimal immediately before the `h` must equal the hash length
/// plus one, exactly as the mangling emits it. Measured, not assumed — the
/// rule newly claims **0** of the 813 real Itanium symbols in the corpus, and
/// `_ZN3foo17hello_there_worldE` still fails it because `ello_there_world` is
/// not hex.
fn ends_with_legacy_hash(t: &str) -> bool {
    let bytes = t.as_bytes();
    for i in (0..bytes.len()).rev() {
        if bytes[i] != b'h' {
            continue;
        }
        let hash = &t[i + 1..];
        if hash.is_empty() || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let head = &t[..i];
        let digits = head.chars().rev().take_while(char::is_ascii_digit).count();
        if digits == 0 {
            continue;
        }
        if head[head.len() - digits..].parse::<usize>() == Ok(hash.len() + 1) {
            return true;
        }
    }
    false
}

/// Either Rust mangling scheme.
#[must_use]
pub fn is_rust(s: &str) -> bool {
    is_rust_v0(s) || is_rust_legacy(s)
}

/// D: `_D` followed by a length-prefixed `QualifiedName`, so a digit.
///
/// The bare prefix test claimed `_DllMainCRTStartup`, the entry point of every
/// Windows DLL.
///
/// `__D` is the Mach-O form, by the same platform convention as `__R`.
#[must_use]
pub fn is_d(s: &str) -> bool {
    s.strip_prefix("__D")
        .or_else(|| s.strip_prefix("_D"))
        .and_then(|rest| rest.chars().next())
        .is_some_and(|c| c.is_ascii_digit())
}

/// Swift: `$s`/`$S` (current), or legacy `_T`/`__T` with an entity code and a
/// length prefix.
///
/// Legacy Swift entities are length-prefixed (`_TFC4test3Foo`), so requiring
/// both an entity code and a digit separates them from English C identifiers
/// such as `_TIFFOpen`.
#[must_use]
pub fn is_swift(s: &str) -> bool {
    // `_$s`/`_$S` are the Mach-O forms: Apple's symbol table prefixes every
    // symbol with an underscore, so this is what real Swift symbols look like
    // on macOS and iOS.
    if s.starts_with("$s") || s.starts_with("$S") || s.starts_with("_$s") || s.starts_with("_$S")
    {
        return true;
    }
    let Some(rest) = s.strip_prefix("__T").or_else(|| s.strip_prefix("_T")) else {
        return false;
    };
    rest.chars()
        .next()
        .is_some_and(|c| c == '0' || c == 't' || c.is_ascii_uppercase())
        && rest.chars().any(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::{is_d, is_rust, is_rust_legacy, is_rust_v0, is_swift};

    /// The C names that each loose rule used to claim.
    #[test]
    fn plain_c_names_carry_no_sigil() {
        for s in ["_RTC_Initialize", "_RTC_Terminate", "_RTC_InitBase"] {
            assert!(!is_rust_v0(s), "{s}");
            assert!(!is_rust(s), "{s}");
        }
        for s in ["_DllMainCRTStartup", "_Dispatch", "_DEBUG_flag"] {
            assert!(!is_d(s), "{s}");
        }
        for s in ["_TIFFOpen", "_Tcl_Init", "_TABLE_SIZE"] {
            assert!(!is_swift(s), "{s}");
        }
    }

    /// The converse: real symbols must still be recognised, so no predicate
    /// can be satisfied by rejecting everything.
    #[test]
    fn real_symbols_carry_their_sigil() {
        assert!(is_rust_v0("_RNvCs4SDFJOLwvtW_7___rustc10rust_panic"));
        assert!(is_rust_legacy("_ZN4core3fmt9Formatter3pad17h1234567890abcdefE"));
        assert!(is_rust("_RNvNtCs189ThkfrTWj_4core3fmt5write"));
        assert!(is_d("_D4main3fooFZv"));
        assert!(is_d("_D3std5stdio7writelnFiZv"));
        assert!(is_swift("$s4main3fooyyF"));
        assert!(is_swift("_TFC4test3Foo3barfS0_FT_T_"));
        // Mach-O underscore forms — what Swift symbols actually look like in
        // an Apple symbol table, and what the crate used to decline outright.
        assert!(is_swift("_$s4main3fooyyF"));
        assert!(is_swift("_$S4main3fooyyF"));
        // Mach-O double-underscore forms; `rustc-demangle` accepts `__R`.
        assert!(is_rust_v0("__RNvCs4SDFJOLwvtW_7___rustc10rust_panic"));
        assert!(is_d("__D4main3fooFZv"));
        // Legacy Rust had been missed when v0 and D were given their Mach-O
        // forms, so on a real Apple binary every legacy symbol was labelled
        // `ManglingAbi::Itanium`.
        assert!(is_rust_legacy(
            "__ZN4core3fmt9Formatter3pad17h1234567890abcdefE"
        ));
    }

    /// Legacy Rust is Itanium-shaped; plain Itanium must not match it.
    #[test]
    fn plain_itanium_is_not_legacy_rust() {
        assert!(!is_rust_legacy("_ZN3foo3barEv"));
        assert!(!is_rust_legacy("_ZNSt10bad_typeidD1Ev"));
        assert!(!is_rust("_ZN10__cxxabiv119__terminate_handlerE"));
        // Widening the prefix must not widen the discrimination: the Mach-O
        // forms of those same C++ symbols stay out too.
        assert!(!is_rust_legacy("__ZN3foo3barEv"));
        assert!(!is_rust_legacy("__ZNSt10bad_typeidD1Ev"));
        assert!(!is_rust("__ZN10__cxxabiv119__terminate_handlerE"));
        // A trailing component that merely looks like a hash is not one.
        assert!(!is_rust_legacy("__ZN3foo17hello_there_worldE"));
    }
}
