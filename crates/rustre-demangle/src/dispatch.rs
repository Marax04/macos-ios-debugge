//! Dispatch layer: [`Demangler2`], [`BulkDemangler`], symbol-kind helpers,
//! and the Itanium standard-substitution table.

use crate::backends::{demangle_msvc_internal, demangle_swift_heuristic};
use crate::core_types::{DemangleResult, MangleLanguage, SymbolKind};
use crate::itanium_native::ItaniumNativeDemangler;
use crate::lang_wrappers::{DDemangler, RustV0Demangler};
// AHashMap is used for all caches whose keys are attacker-controlled mangled
// symbol strings, preventing hash-collision DoS (std HashMap uses SipHash
// which degrades to O(n) on adversarially-chosen keys).
use ahash::AHashMap;

// ── Dispatch struct ───────────────────────────────────────────────────────────

/// Demangle an Itanium symbol with the crate's most accurate engine.
///
/// Measured on the reference corpus (`examples/itanium_compare.rs`), the
/// consolidated engine scores 28/28 exact matches against `cpp_demangle`,
/// versus 13/28 for the native structural parser, which stays as the
/// fallback for the vendor forms the reference engine rejects.
fn demangle_itanium_best(mangled: &str) -> Option<String> {
    crate::cpp_demangler::demangle_itanium(mangled)
        .ok()
        .or_else(|| ItaniumNativeDemangler::demangle(mangled))
}

/// Dispatch demangler: detects language and calls the appropriate backend.
pub struct Demangler2;

impl Demangler2 {
    /// Demangle a symbol, auto-detecting the language.
    #[must_use] 
    pub fn demangle(mangled: &str) -> DemangleResult {
        // Linker indirection wrappers: `.refptr.f` and `__imp_f` wrap a real
        // mangled symbol. The live path unwraps, decodes and re-prefixes; this
        // dispatcher tested `starts_with("_Z")` and so declined all 34 of them
        // in the corpus, echoing the symbol back under `Unknown`.
        //
        // Loops, because wrappers nest (`.refptr.__imp_f`), and the prefix
        // survives into the output: `.refptr.f` must never read as `f`.
        if let Some((prefix, rest)) = crate::backends::split_linker_wrapper(mangled) {
            let inner = Self::demangle(rest);
            if inner.language != MangleLanguage::Unknown {
                return DemangleResult {
                    mangled: mangled.to_owned(),
                    demangled: format!("{prefix}{}", inner.demangled),
                    language: inner.language,
                    kind: inner.kind,
                };
            }
        }
        // Legacy Rust, BEFORE Itanium: `_ZN…17h<hex>E` is Itanium-shaped, so the
        // Itanium arm below claimed it and got both fields wrong —
        //
        //   _ZN19sample3_struct_loop4main17h051ebe1ecfcb2bb2E
        //     was  sample3_struct_loop::main::h051ebe1ecfcb2bb2  [CppItanium]
        //     want sample3_struct_loop::main                     [Rust]
        //
        // — leaking the disambiguator hash the crate strips everywhere else.
        // The same defect pair iter 155 fixed on the live path, still here
        // because this dispatcher never consulted `sigil`, which exists so that
        // every claiming site shares one rule.
        if crate::sigil::is_rust_legacy(mangled)
            && let Ok(d) = rustc_demangle::try_demangle(mangled)
        {
            return DemangleResult {
                mangled: mangled.to_owned(),
                demangled: format!("{d:#}"),
                language: MangleLanguage::Rust,
                kind: SymbolKind::Function,
            };
        }
        // Rust v0
        if crate::sigil::is_rust_v0(mangled)
            && let Some(d) = RustV0Demangler::demangle(mangled) {
                return DemangleResult {
                    mangled: mangled.to_owned(),
                    demangled: d,
                    language: MangleLanguage::Rust,
                    kind: SymbolKind::Function,
                };
            }
        // D language
        if DDemangler::detect(mangled)
            && let Some(d) = DDemangler::demangle(mangled) {
                return DemangleResult {
                    mangled: mangled.to_owned(),
                    demangled: d,
                    language: MangleLanguage::D,
                    kind: SymbolKind::Function,
                };
            }
        // Itanium C++
        if mangled.starts_with("_Z") || mangled.starts_with("__Z") {
            let kind = ItaniumNativeDemangler::detect_kind(mangled);
            if let Some(d) = demangle_itanium_best(mangled) {
                return DemangleResult {
                    mangled: mangled.to_owned(),
                    demangled: d,
                    language: MangleLanguage::CppItanium,
                    kind,
                };
            }
        }
        // MSVC C++
        if mangled.starts_with('?')
            && let Some(d) = demangle_msvc_internal(mangled) {
                return DemangleResult {
                    mangled: mangled.to_owned(),
                    demangled: d,
                    language: MangleLanguage::CppMsvc,
                    kind: SymbolKind::Function,
                };
            }
        // Swift
        if (mangled.starts_with("$s") || mangled.starts_with("$S") || mangled.starts_with("_T0"))
            && let Some(d) = demangle_swift_heuristic(mangled) {
                return DemangleResult {
                    mangled: mangled.to_owned(),
                    demangled: d,
                    language: MangleLanguage::Swift,
                    kind: SymbolKind::Function,
                };
            }
        DemangleResult {
            mangled: mangled.to_owned(),
            demangled: mangled.to_owned(),
            language: MangleLanguage::Unknown,
            kind: SymbolKind::Unknown,
        }
    }

    /// Demangle with an explicit language hint.
    #[must_use] 
    pub fn demangle_with_language(s: &str, lang: MangleLanguage) -> DemangleResult {
        match lang {
            MangleLanguage::CppItanium => {
                let kind = ItaniumNativeDemangler::detect_kind(s);
                let d = demangle_itanium_best(s).unwrap_or_else(|| s.to_owned());
                DemangleResult {
                    mangled: s.to_owned(),
                    demangled: d,
                    language: lang,
                    kind,
                }
            }
            MangleLanguage::CppMsvc => {
                let d = demangle_msvc_internal(s).unwrap_or_else(|| s.to_owned());
                DemangleResult {
                    mangled: s.to_owned(),
                    demangled: d,
                    language: lang,
                    kind: SymbolKind::Function,
                }
            }
            MangleLanguage::Rust => {
                let d = RustV0Demangler::demangle(s).unwrap_or_else(|| s.to_owned());
                DemangleResult {
                    mangled: s.to_owned(),
                    demangled: d,
                    language: lang,
                    kind: SymbolKind::Function,
                }
            }
            MangleLanguage::Swift => {
                let d = demangle_swift_heuristic(s).unwrap_or_else(|| s.to_owned());
                DemangleResult {
                    mangled: s.to_owned(),
                    demangled: d,
                    language: lang,
                    kind: SymbolKind::Function,
                }
            }
            MangleLanguage::D => {
                let d = DDemangler::demangle(s).unwrap_or_else(|| s.to_owned());
                DemangleResult {
                    mangled: s.to_owned(),
                    demangled: d,
                    language: lang,
                    kind: SymbolKind::Function,
                }
            }
            _ => Self::demangle(s),
        }
    }
}

// ── BulkDemangler ─────────────────────────────────────────────────────────────

/// Processes a slice of mangled symbols, returning results.
/// Caches repeated lookups.
pub struct BulkDemangler {
    // AHashMap: mangled symbol strings come from untrusted input; using the
    // default SipHash HashMap would allow an attacker to craft symbols that
    // all collide into the same bucket, causing O(n²) lookup (dos-hash-collision).
    cache: AHashMap<String, DemangleResult>,
}

impl BulkDemangler {
    /// Create a new bulk demangler with an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: AHashMap::new(),
        }
    }

    /// Demangle all symbols in the slice, using the cache for repeated entries.
    pub fn demangle_all(&mut self, symbols: &[String]) -> Vec<DemangleResult> {
        symbols
            .iter()
            .map(|s| {
                if let Some(cached) = self.cache.get(s) {
                    cached.clone()
                } else {
                    let result = Demangler2::demangle(s);
                    self.cache.insert(s.clone(), result.clone());
                    result
                }
            })
            .collect()
    }

    /// Returns the number of entries in the cache.
    #[must_use] 
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    /// Clear the internal cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

impl Default for BulkDemangler {
    fn default() -> Self {
        Self::new()
    }
}

// ── Symbol kind helpers ───────────────────────────────────────────────────────

/// Determine if a mangled Itanium symbol is a constructor.
///
/// Checks for the Itanium ABI constructor encoding `C1`, `C2`, or `C3`
/// preceded by a `_` or digit (end of a length-encoded name component) to
/// avoid false positives on arbitrary substrings.
#[must_use]
pub fn is_constructor(mangled: &str) -> bool {
    if !mangled.starts_with("_Z") {
        return false;
    }
    let bytes = mangled.as_bytes();
    for i in 0..bytes.len().saturating_sub(2) {
        if matches!(bytes[i], b'_' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
            && bytes[i + 1] == b'C'
            && matches!(bytes[i + 2], b'1' | b'2' | b'3')
            && bytes.get(i + 3).is_none_or(|&b| b == b'E' || b == b'v')
        {
            return true;
        }
    }
    false
}

/// Determine if a mangled Itanium symbol is a destructor.
///
/// Checks for the Itanium ABI destructor encoding `D0`, `D1`, or `D2`
/// preceded by a `_` or digit (end of a length-encoded name component) to
/// avoid false positives on arbitrary substrings.
#[must_use]
pub fn is_destructor(mangled: &str) -> bool {
    if !mangled.starts_with("_Z") {
        return false;
    }
    let bytes = mangled.as_bytes();
    for i in 0..bytes.len().saturating_sub(2) {
        if matches!(bytes[i], b'_' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
            && bytes[i + 1] == b'D'
            && matches!(bytes[i + 2], b'0' | b'1' | b'2')
            && bytes.get(i + 3).is_none_or(|&b| b == b'E' || b == b'v')
        {
            return true;
        }
    }
    false
}

/// Determine if a mangled Itanium symbol is a vtable entry.
#[must_use] 
pub fn is_vtable(mangled: &str) -> bool {
    mangled.starts_with("_ZTV")
}

/// Determine if a mangled Itanium symbol is typeinfo.
#[must_use] 
pub fn is_typeinfo(mangled: &str) -> bool {
    mangled.starts_with("_ZTI") || mangled.starts_with("_ZTS")
}

// ── Standard substitutions table ─────────────────────────────────────────────

/// Return the human-readable expansion of Itanium standard substitutions.
#[must_use] 
pub fn standard_substitution(code: &str) -> Option<&'static str> {
    match code {
        "St" => Some("std"),
        "Sa" => Some("std::allocator"),
        "Sb" => Some("std::basic_string"),
        "Ss" => Some("std::string"),
        "Si" => Some("std::istream"),
        "So" => Some("std::ostream"),
        "Sd" => Some("std::iostream"),
        _ => None,
    }
}
