//! `rustre-demangle`
//!
//! Multi-ABI symbol demangler supporting Itanium (GCC/Clang), MSVC, Rust, Swift,
//! D language, and Objective-C mangling schemes.
//!
//! # Quick start
//! ```rust
//! use rustre_demangle::demangle;
//! let result = demangle("_ZN3foo3barEi");
//! assert!(result.is_some());
//! ```
#![warn(missing_docs)]

pub mod demangler_benchmark;
pub mod cpp_demangler;
pub mod d_demangler;
pub mod demangler_cache;
pub mod itanium_full;
pub mod msvc_full;
/// Rust symbol demangler: v0 mangling scheme (RFC 2603) and legacy hashes.
pub mod rust_demangler;
pub mod swift_demangler;

/// Demangler registry and dispatcher: DemanglerRegistry, Demangler trait,
///
/// ItaniumDemangler, MsvcDemangler, SwiftDemangler, RustDemangler, DDemangler,
/// BorlandDemangler, AutoDemangler, DemanglerCache (LRU), BulkDemangler.
///
pub mod demangler_registry;
pub mod msvc_demangler;
pub mod go_demangler;
/// Additional language runtimes.
///
/// Java (JNI), Objective-C routing, gfortran, GNAT Ada, OCaml, GHC Haskell,
/// Windows C calling-convention decorations.
pub mod lang_extra;
pub mod lang_more;
pub mod demangler_dispatcher;

// ── Crate-root implementation modules ────────────────────────────────────────
//
// These are private modules whose public items are re-exported below so the
// crate-root API stays flat and identical to the pre-split layout. Note that
// several names here (SymbolKind, MsvcDemangler, DDemangler, DemanglerCache)
// deliberately shadow-free coexist with same-named items inside the public
// modules above — those remain reachable only via their own module paths.
mod backends;
mod classify;
mod core_types;
/// Sigil predicates for ABI prefixes.
///
/// The single place that answers "does this string carry ABI X's prefix?".
/// Ad-hoc `starts_with` tests drifted apart and claimed plain C names; new
/// checks belong here.
pub mod sigil;
/// Why a symbol was declined: separates correct declines (section names,
/// undecorated C, toolchain artifacts) from genuine coverage gaps.
pub mod decline;
mod dispatch;
mod itanium_native;
mod lang_wrappers;
mod msvc_extras;
mod stats;

pub use backends::{
    demangle, repair_ss_ctor_dropped_param, split_linker_wrapper, AutoDemangler, ItaniumDemangler,
    MsvcDemangler, RustDemangler, SwiftDemangler,
};
pub use classify::{
    batch_demangle, batch_demangle_parallel, normalize_type, DemangleFilter, ObjCDemangler,
    SwiftExtendedParser, SwiftSymbol, SymbolCache, SymbolClassifier, Verbosity,
};
pub use core_types::{
    DemangleOptions, DemangleResult, DemangledSymbol, Demangler, DemanglingResult, MangleLanguage,
    ManglingAbi, SymbolKind,
};
pub use decline::{decline_reason, DeclineReason};
pub use dispatch::{
    is_constructor, is_destructor, is_typeinfo, is_vtable, standard_substitution, BulkDemangler,
    Demangler2,
};
pub use itanium_native::ItaniumNativeDemangler;
pub use lang_wrappers::{DDemangler, RustV0Demangler};
pub use msvc_extras::{demangle_msvc_rtti, msvc_calling_convention, CallingConvention, MsvcRttiKind};
pub use stats::{DemanglerBenchmark, DemanglerCache, DemanglerStats, RUST_TEST_VECTORS};

#[cfg(test)]
mod lib_tests;
