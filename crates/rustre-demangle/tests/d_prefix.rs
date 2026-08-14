//! `_D` alone does not make a symbol D.
//!
//! `DDemangler::detect` accepted any name starting with `_D`, and
//! `SymbolClassifier::classify` routes D through it. Since no backend can
//! decode a C name, every such symbol was reported as
//! `DeclineReason::UnsupportedAbi` — a phantom defect. The most visible
//! casualty was `_DllMainCRTStartup`, the entry point of every Windows DLL.
//!
//! The D ABI length-prefixes its `QualifiedName` (`_D4main3fooFZv`), so a
//! digit must follow the sigil. Same shape as the `_R`/Rust and `_T`/Swift
//! fixes; the corpora contain no `_D` symbols, so only a targeted probe can
//! cover it.

use rustre_demangle::{DeclineReason, MangleLanguage, SymbolClassifier, decline_reason};

/// C names starting with `_D` are not D symbols.
#[test]
fn c_names_starting_with_d_are_not_d_symbols() {
    for s in [
        "_DllMainCRTStartup",
        "_Dispatch",
        "_DEBUG_flag",
        "_Data_init",
        "_DefWindowProc",
    ] {
        assert_ne!(
            SymbolClassifier::classify(s),
            MangleLanguage::D,
            "{s} is a C identifier, not D"
        );
        assert_ne!(
            decline_reason(s),
            DeclineReason::UnsupportedAbi,
            "{s} must not be reported as an unhandled mangled symbol"
        );
    }
}

/// Real D symbols still decode — the fix must not be met by rejecting all D.
#[test]
fn real_d_symbols_still_decode() {
    for (sym, needle) in [
        ("_D4main3fooFZv", "main.foo"),
        ("_D3std5stdio7writelnFiZv", "std.stdio.writeln"),
    ] {
        assert_eq!(SymbolClassifier::classify(sym), MangleLanguage::D, "{sym}");
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(
            r.demangled.contains(needle),
            "{sym} -> {}",
            r.demangled
        );
    }
}

/// A stdcall-decorated C function is undecorated, not demangled as D.
///
/// `_DllMain@12` starts with `_D` but is `_name@bytes`; it must reach the
/// Windows decoration handler and keep an accurate label.
#[test]
fn stdcall_decoration_is_not_d() {
    assert_ne!(SymbolClassifier::classify("_DllMain@12"), MangleLanguage::D);
    let r = rustre_demangle::demangle("_DllMain@12").expect("stdcall decoration must decode");
    assert_eq!(r.demangled, "DllMain");
}
