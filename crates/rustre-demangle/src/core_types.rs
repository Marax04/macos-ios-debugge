//! Core public types shared by every demangler backend.

use crate::classify::Verbosity;
use serde::{Deserialize, Serialize};

// ── Public types ──────────────────────────────────────────────────────────────

/// The name-mangling ABI used for a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManglingAbi {
    /// Itanium C++ ABI (GCC/Clang, `_Z` prefix).
    Itanium,
    /// Microsoft Visual C++ ABI (`?` prefix).
    Msvc,
    /// Rust symbol mangling (legacy or v0 `_R`).
    Rust,
    /// Swift mangling (`$s` prefix).
    Swift,
    /// Go symbol naming (`pkg/path.Func`, `pkg.(*T).Method`).
    Go,
    /// D language mangling (`_D` prefix).
    D,
    /// Java JNI native-method naming (`Java_pkg_Class_method`).
    Java,
    /// Objective-C (`-[Class method]`, `_OBJC_CLASS_$_…`).
    ObjC,
    /// gfortran module procedures (`__mod_MOD_proc`).
    Fortran,
    /// GNAT Ada (`pkg__subprogram`).
    Ada,
    /// OCaml (`camlModule__name_123`).
    OCaml,
    /// GHC Haskell z-encoded symbols (`pkg_GHCziBase_name_info`).
    Haskell,
    /// C with Windows calling-convention decoration (`_f@8`, `@f@8`).
    C,
    /// ABI could not be determined.
    Unknown,
}

/// Language that produced the mangled symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MangleLanguage {
    /// C++ compiled with an Itanium-ABI compiler (GCC/Clang).
    CppItanium,
    /// C++ compiled with MSVC.
    CppMsvc,
    /// Rust.
    Rust,
    /// Swift.
    Swift,
    /// D language.
    D,
    /// Java (JNI-style mangling).
    Java,
    /// Objective-C.
    ObjC,
    /// Language could not be determined.
    Unknown,
}

/// Kind of symbol that was decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolKind {
    /// Ordinary function or method.
    Function,
    /// Data object (global/static variable).
    Data,
    /// Virtual function table (`_ZTV…`).
    VTable,
    /// Type information object (`_ZTI…`).
    Typeinfo,
    /// Type information name string (`_ZTS…`).
    TypeinfoName,
    /// Virtual table table for construction (`_ZTT…`).
    VTT,
    /// Constructor (`C1`/`C2`/`C3` variants).
    Constructor,
    /// Destructor (`D0`/`D1`/`D2` variants).
    Destructor,
    /// Thunk (virtual-call or this-pointer adjustment).
    Thunk,
    /// Kind could not be determined.
    Unknown,
}

/// Options controlling demangling behaviour.
///
/// # Not yet honoured
///
/// **No demangling path currently reads these fields.** No function in the
/// crate takes a `DemangleOptions` parameter, so constructing one — including
/// via [`Self::with_verbosity`] — has no effect on any output:
/// [`Verbosity::Minimal`] and [`Verbosity::Full`] produce byte-identical
/// results. The type describes intended behaviour that is not implemented.
///
/// This is stated here because the shape of the API implies otherwise, and the
/// existing tests only assert that the constructors set the fields they were
/// given — they pass whether or not anything consumes them.
/// `tests/options_are_honoured.rs` holds an ignored test asserting the
/// behaviour these fields promise, so the gap stays visible.
#[derive(Debug, Clone)]
pub struct DemangleOptions {
    /// Simplify deep template arguments. Currently inert; see the type docs.
    pub simplify_templates: bool,
    /// Maximum nesting depth for template argument expansion. Currently inert.
    ///
    /// Note that the backends *do* bound recursion, but with their own
    /// internal limits rather than this field.
    pub max_template_depth: usize,
    /// Verbose mode: include all qualifiers. Currently inert.
    pub verbose: bool,
    /// How much detail the demangled output should carry. Currently inert.
    pub verbosity: Verbosity,
}

impl Default for DemangleOptions {
    fn default() -> Self {
        Self {
            simplify_templates: false,
            max_template_depth: 32,
            verbose: true,
            verbosity: Verbosity::Normal,
        }
    }
}

impl DemangleOptions {
    /// Build options preset for a given [`Verbosity`] level.
    ///
    /// * [`Verbosity::Minimal`] simplifies templates and disables verbose
    ///   qualifier output.
    /// * [`Verbosity::Normal`] uses the [`Default`] settings.
    /// * [`Verbosity::Full`] keeps every qualifier and template argument.
    #[must_use]
    pub fn with_verbosity(verbosity: Verbosity) -> Self {
        match verbosity {
            Verbosity::Minimal => Self {
                simplify_templates: true,
                max_template_depth: 0,
                verbose: false,
                verbosity,
            },
            Verbosity::Normal => Self {
                verbosity,
                ..Self::default()
            },
            Verbosity::Full => Self {
                simplify_templates: false,
                max_template_depth: 64,
                verbose: true,
                verbosity,
            },
        }
    }
}

/// Rich result of a successful demangling operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemanglingResult {
    /// The original mangled symbol.
    pub original: String,
    /// The fully demangled human-readable representation.
    pub demangled: String,
    /// ABI that successfully decoded the symbol.
    pub abi: ManglingAbi,
    /// Namespace path, e.g. `"std::collections"`.
    pub namespace: Option<String>,
    /// Class / type the symbol belongs to (if any).
    pub class: Option<String>,
    /// The bare function or variable name (final component).
    pub function: String,
    /// Decoded parameter types (may be empty for non-functions).
    pub args: Vec<String>,
    /// Decoded return type (if known).
    pub return_type: Option<String>,
}

/// Extended result carrying richer metadata.
#[derive(Debug, Clone)]
pub struct DemangleResult {
    /// The original mangled string.
    pub mangled: String,
    /// The demangled human-readable string.
    pub demangled: String,
    /// Language detected.
    pub language: MangleLanguage,
    /// High-level kind of this symbol.
    pub kind: SymbolKind,
}

impl DemangleResult {
    /// Render this result as a single human-readable line, preferring the
    /// demangled form and falling back to the original mangled string.
    #[must_use]
    pub fn to_display_string(&self) -> String {
        if self.demangled.is_empty() {
            self.mangled.clone()
        } else {
            self.demangled.clone()
        }
    }
}

/// Structured decomposition of a demangled symbol.
#[derive(Debug, Clone, Default)]
pub struct DemangledSymbol {
    /// Namespace components, e.g. `["std", "collections"]`.
    pub namespace: Vec<String>,
    /// Class name (if member).
    pub class: Option<String>,
    /// Bare function or variable name.
    pub function: String,
    /// Template arguments as strings.
    pub template_args: Vec<String>,
    /// CV qualifiers: `const`, `volatile`, etc.
    pub cv_qualifiers: Vec<String>,
}

// ── Demangler trait ───────────────────────────────────────────────────────────

/// A demangler for a specific ABI.
pub trait Demangler: Send + Sync {
    /// Returns `true` if `mangled` looks like it belongs to this ABI.
    fn detect(&self, mangled: &str) -> bool;
    /// Attempt to demangle `mangled`.  Returns `None` if parsing fails.
    fn demangle(&self, mangled: &str) -> Option<DemanglingResult>;
}
