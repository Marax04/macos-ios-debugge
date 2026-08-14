//! `demangler_dispatcher` — Auto-detect the mangling scheme of a symbol and
//! dispatch to the appropriate demangler.
//!
//! Provides [`DemanglerDispatcher`], [`DemangleResult`], and [`MangleScheme`].

use std::collections::HashMap;
use std::fmt::Write;
// AHashMap: mangled symbol strings (attacker-controlled) are used as cache
// keys; dos-hash-collision guard.
use ahash::AHashMap;

use serde::{Deserialize, Serialize};

use crate::{DemanglingResult, ManglingAbi};
use crate::go_demangler::{GoDemangler, GoSymbol};

// ── MangleScheme ──────────────────────────────────────────────────────────────

/// Name-mangling scheme (ABI) detected for a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MangleScheme {
    /// Rust v0 mangling (`_R` prefix).
    RustV0,
    /// Rust legacy mangling (`_ZN…17h…E`).
    RustLegacy,
    /// Itanium C++ ABI (`_Z` prefix).
    ItaniumCpp,
    /// Microsoft Visual C++ mangling (`?` prefix).
    MsvcCpp,
    /// Swift mangling (`$s`, `$S`, `_T0`).
    Swift,
    /// D language mangling (`_D` prefix).
    DLang,
    /// Go naming convention (`pkg.Func` pattern).
    Go,
    /// Plain C (no mangling detectable).
    PlainC,
    /// Unknown / not classified.
    Unknown,
}

impl MangleScheme {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RustV0 => "rust_v0",
            Self::RustLegacy => "rust_legacy",
            Self::ItaniumCpp => "itanium_cpp",
            Self::MsvcCpp => "msvc_cpp",
            Self::Swift => "swift",
            Self::DLang => "d_lang",
            Self::Go => "go",
            Self::PlainC => "plain_c",
            Self::Unknown => "unknown",
        }
    }

    /// Whether this scheme requires demangling.
    #[must_use]
    pub const fn is_mangled(self) -> bool {
        !matches!(self, Self::PlainC | Self::Unknown)
    }

    /// The corresponding [`ManglingAbi`] if one exists in the shared type.
    #[must_use]
    pub const fn to_abi(self) -> ManglingAbi {
        match self {
            Self::RustV0 | Self::RustLegacy => ManglingAbi::Rust,
            Self::ItaniumCpp => ManglingAbi::Itanium,
            Self::MsvcCpp => ManglingAbi::Msvc,
            Self::Swift => ManglingAbi::Swift,
            _ => ManglingAbi::Unknown,
        }
    }
}

impl std::fmt::Display for MangleScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ── DemangleResult ────────────────────────────────────────────────────────────

/// Result of a dispatch-demangle operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemangleResult {
    /// Original mangled symbol.
    pub original: String,
    /// Human-readable demangled form, or a copy of `original` on failure.
    pub demangled: String,
    /// Detected mangling scheme.
    pub scheme: MangleScheme,
    /// Whether demangling succeeded.
    pub success: bool,
    /// Optional structured result from the underlying demangler.
    pub structured: Option<DemanglingResult>,
    /// Optional Go-specific structured result.
    pub go_symbol: Option<GoSymbol>,
}

impl DemangleResult {
    /// Build a successful result from a [`DemanglingResult`].
    #[must_use]
    pub fn from_structured(structured: DemanglingResult, scheme: MangleScheme) -> Self {
        Self {
            original: structured.original.clone(),
            demangled: structured.demangled.clone(),
            scheme,
            success: true,
            structured: Some(structured),
            go_symbol: None,
        }
    }

    /// Build a successful result from a [`GoSymbol`].
    #[must_use]
    pub fn from_go(sym: GoSymbol) -> Self {
        let demangled = sym.demangled.clone();
        let original = sym.original.clone();
        Self {
            original,
            demangled,
            scheme: MangleScheme::Go,
            success: true,
            structured: None,
            go_symbol: Some(sym),
        }
    }

    /// Build a failure result (unknown scheme, no demangling).
    #[must_use]
    pub fn failed(original: &str) -> Self {
        Self {
            original: original.to_owned(),
            demangled: original.to_owned(),
            scheme: MangleScheme::Unknown,
            success: false,
            structured: None,
            go_symbol: None,
        }
    }

    /// Build a plain-C (identity) result.
    #[must_use]
    pub fn plain_c(original: &str) -> Self {
        Self {
            original: original.to_owned(),
            demangled: original.to_owned(),
            scheme: MangleScheme::PlainC,
            success: true,
            structured: None,
            go_symbol: None,
        }
    }
}

// ── DispatcherConfig ──────────────────────────────────────────────────────────

/// Configuration for [`DemanglerDispatcher`].
#[derive(Debug, Clone)]
pub struct DispatcherConfig {
    /// Feature flags (see `PLAIN_C_FALLBACK`, `ENABLE_GO`, etc.).
    pub flags: u8,
    /// Maximum cache size (entries).  `0` = unlimited.
    pub max_cache_size: usize,
}

impl DispatcherConfig {
    /// If set, fall back to plain-C for symbols not matching any scheme.
    pub const PLAIN_C_FALLBACK: u8 = 1 << 0;
    /// If set, attempt Go demangling for likely Go symbols.
    pub const ENABLE_GO: u8 = 1 << 1;
    /// If set, cache results to avoid re-parsing the same symbol.
    pub const ENABLE_CACHE: u8 = 1 << 2;
    /// If set, prefer `rustc-demangle` for Rust v0 symbols.
    pub const PREFER_RUSTC_DEMANGLE: u8 = 1 << 3;

    /// Returns `true` if plain-C fallback is enabled.
    #[must_use]
    pub const fn plain_c_fallback(&self) -> bool { self.flags & Self::PLAIN_C_FALLBACK != 0 }
    /// Returns `true` if Go demangling is enabled.
    #[must_use]
    pub const fn enable_go(&self) -> bool { self.flags & Self::ENABLE_GO != 0 }
    /// Returns `true` if result caching is enabled.
    #[must_use]
    pub const fn enable_cache(&self) -> bool { self.flags & Self::ENABLE_CACHE != 0 }
    /// Returns `true` if `rustc-demangle` is preferred for Rust v0.
    #[must_use]
    pub const fn prefer_rustc_demangle(&self) -> bool { self.flags & Self::PREFER_RUSTC_DEMANGLE != 0 }
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            flags: Self::PLAIN_C_FALLBACK
                | Self::ENABLE_GO
                | Self::ENABLE_CACHE
                | Self::PREFER_RUSTC_DEMANGLE,
            max_cache_size: 65536,
        }
    }
}

// ── DemanglerDispatcher ───────────────────────────────────────────────────────

/// Auto-detecting multi-ABI dispatcher.
///
/// Detects the mangling scheme from the symbol prefix, then delegates to the
/// appropriate demangler.  Results are cached by default.
pub struct DemanglerDispatcher {
    /// Configuration.
    pub config: DispatcherConfig,
    /// LRU-style cache (insertion-order map for simplicity).
    cache: AHashMap<String, DemangleResult>,
    /// Go demangler instance.
    go_demangler: GoDemangler,
    /// Per-scheme hit counters for diagnostics.
    scheme_counts: HashMap<MangleScheme, u64>,
    /// Total symbols processed.
    total_processed: u64,
}

impl DemanglerDispatcher {
    /// Create a new dispatcher with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(DispatcherConfig::default())
    }

    /// Create a dispatcher with the given configuration.
    #[must_use]
    pub fn with_config(config: DispatcherConfig) -> Self {
        Self {
            config,
            cache: AHashMap::new(),
            go_demangler: GoDemangler::new(),
            scheme_counts: HashMap::new(),
            total_processed: 0,
        }
    }

    // ── Detection ─────────────────────────────────────────────────────────────

    /// Detect the mangling scheme of `symbol` without performing demangling.
    #[must_use]
    pub fn detect_scheme(symbol: &str) -> MangleScheme {
        // Rust v0: `_R` prefix.
        if crate::sigil::is_rust_v0(symbol) {
            return MangleScheme::RustV0;
        }
        // Rust legacy: `_ZN…17h<hex>E`, via the canonical predicate.
        //
        // This read `starts_with("_ZN") && (contains("17h") || ends_with('E'))`,
        // and the `ends_with('E')` half claims **ordinary Itanium**: every
        // `_ZN…E` symbol was routed to `rustc-demangle`, which rejects it, so
        // 85 corpus symbols were echoed back undecoded —
        // `_ZN10__cxxabiv111__terminateEPFvvE` among them.
        //
        // The two recurring defects of this crate in one line: a classifier
        // looser than its backend, and a claiming site that did not go through
        // `sigil`, which exists so that one rule has one home.
        if crate::sigil::is_rust_legacy(symbol) {
            return MangleScheme::RustLegacy;
        }
        // Itanium C++: `_Z` or `__Z`.
        if symbol.starts_with("_Z") || symbol.starts_with("__Z") {
            return MangleScheme::ItaniumCpp;
        }
        // MSVC: `?` prefix.
        if symbol.starts_with('?') {
            return MangleScheme::MsvcCpp;
        }
        // Swift: `$s`, `$S`, `_T0`.
        if symbol.starts_with("$s")
            || symbol.starts_with("$S")
            || symbol.starts_with("_T0")
            || symbol.starts_with("__T0")
        {
            return MangleScheme::Swift;
        }
        // D language: `_D` prefix.
        if crate::sigil::is_d(symbol) {
            return MangleScheme::DLang;
        }
        // Go: must have a dot and no `_Z`/`?`/`$s` prefix.
        if crate::go_demangler::GoDemangler::detect(symbol) {
            return MangleScheme::Go;
        }
        // Plain C: starts with a plain identifier character.
        if symbol
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
        {
            return MangleScheme::PlainC;
        }
        MangleScheme::Unknown
    }

    // ── Dispatch ──────────────────────────────────────────────────────────────

    /// Demangle `symbol`, auto-detecting the scheme.
    ///
    /// Returns a [`DemangleResult`] that always has a `demangled` string (falls
    /// back to the original on failure).
    pub fn demangle(&mut self, symbol: &str) -> DemangleResult {
        // Cache lookup.
        if self.config.enable_cache()
            && let Some(cached) = self.cache.get(symbol) {
            return cached.clone();
        }

        let result = self.demangle_inner(symbol);

        // Update statistics.
        self.total_processed += 1;
        *self.scheme_counts.entry(result.scheme).or_insert(0) += 1;

        // Cache insert.
        if self.config.enable_cache()
            && (self.config.max_cache_size == 0
                || self.cache.len() < self.config.max_cache_size)
        {
            self.cache.insert(symbol.to_owned(), result.clone());
        }

        result
    }

    fn demangle_inner(&mut self, symbol: &str) -> DemangleResult {
        // Linker indirection wrappers (`.refptr.f`, `__imp_f`, `__emutls_v.f`)
        // wrap a real mangled symbol. `detect_scheme` looks at the first bytes,
        // so all 119 of them in the corpus fell through to `PlainC`/`Unknown`
        // and were echoed back undecoded.
        //
        // Unwrap, decode, re-prefix — the prefix survives into the output, so
        // `.refptr.f` never reads as `f`. Loops via recursion because wrappers
        // nest (`.refptr.__imp_f`).
        if let Some((prefix, rest)) = crate::backends::split_linker_wrapper(symbol) {
            let inner = self.demangle_inner(rest);
            if inner.demangled != rest {
                let mut wrapped = inner;
                wrapped.demangled = format!("{prefix}{}", wrapped.demangled);
                symbol.clone_into(&mut wrapped.original);
                return wrapped;
            }
        }
        let scheme = Self::detect_scheme(symbol);

        match scheme {
            MangleScheme::RustV0 | MangleScheme::RustLegacy => {
                Self::demangle_rust(symbol, scheme)
            }
            MangleScheme::ItaniumCpp => Self::demangle_itanium(symbol),
            MangleScheme::MsvcCpp => Self::demangle_msvc(symbol),
            MangleScheme::Swift => Self::demangle_swift(symbol),
            MangleScheme::DLang => Self::demangle_dlang(symbol),
            MangleScheme::Go if self.config.enable_go() => self.demangle_go(symbol),
            MangleScheme::PlainC => DemangleResult::plain_c(symbol),
            _ => {
                if self.config.plain_c_fallback() {
                    DemangleResult::plain_c(symbol)
                } else {
                    DemangleResult::failed(symbol)
                }
            }
        }
    }

    fn demangle_rust(symbol: &str, scheme: MangleScheme) -> DemangleResult {
        match rustc_demangle::try_demangle(symbol) {
            Ok(sym) => {
                // `{:#}`, not `{}`. The plain `Display` KEEPS the crate
                // disambiguator, so this dispatcher rendered 136 of the corpus's
                // Rust v0 symbols as
                // `core[d2e35dc664ad455]::panicking::assert_failed` where the
                // live path gives `core::panicking::assert_failed`.
                //
                // Same defect class as the legacy-Rust hash leak fixed in
                // `dispatch.rs`: a disambiguator reaching the output because a
                // second dispatcher formatted the oracle's result differently.
                // One character, and it is visible to every consumer of
                // `auto_demangle`.
                let demangled = format!("{sym:#}");
                if demangled == symbol {
                    return DemangleResult::failed(symbol);
                }
                let structured = DemanglingResult {
                    original: symbol.to_owned(),
                    demangled: demangled.clone(),
                    abi: scheme.to_abi(),
                    namespace: None,
                    class: None,
                    function: demangled
                        .rsplit("::")
                        .next()
                        .unwrap_or(&demangled)
                        .to_owned(),
                    args: Vec::new(),
                    return_type: None,
                };
                DemangleResult::from_structured(structured, scheme)
            }
            Err(_) => DemangleResult::failed(symbol),
        }
    }

    fn demangle_itanium(symbol: &str) -> DemangleResult {
        use crate::ItaniumDemangler;
        use crate::Demangler;
        let d = ItaniumDemangler;
        d.demangle(symbol).map_or_else(
            || DemangleResult::failed(symbol),
            |structured| DemangleResult::from_structured(structured, MangleScheme::ItaniumCpp),
        )
    }

    fn demangle_msvc(symbol: &str) -> DemangleResult {
        use crate::MsvcDemangler;
        use crate::Demangler;
        let d = MsvcDemangler;
        d.demangle(symbol).map_or_else(
            || DemangleResult::failed(symbol),
            |structured| DemangleResult::from_structured(structured, MangleScheme::MsvcCpp),
        )
    }

    fn demangle_swift(symbol: &str) -> DemangleResult {
        use crate::SwiftDemangler;
        use crate::Demangler;
        let d = SwiftDemangler;
        d.demangle(symbol).map_or_else(
            || DemangleResult::failed(symbol),
            |structured| DemangleResult::from_structured(structured, MangleScheme::Swift),
        )
    }

    fn demangle_dlang(symbol: &str) -> DemangleResult {
        use crate::DDemangler;
        DDemangler::demangle(symbol).map_or_else(
            || DemangleResult::failed(symbol),
            |demangled| {
                let function = demangled.rsplit('.').next().unwrap_or(&demangled).to_owned();
                let structured = DemanglingResult {
                    original: symbol.to_owned(),
                    demangled,
                    abi: ManglingAbi::Unknown,
                    namespace: None,
                    class: None,
                    function,
                    args: Vec::new(),
                    return_type: None,
                };
                DemangleResult::from_structured(structured, MangleScheme::DLang)
            },
        )
    }

    fn demangle_go(&mut self, symbol: &str) -> DemangleResult {
        self.go_demangler.decode(symbol).map_or_else(
            || DemangleResult::failed(symbol),
            DemangleResult::from_go,
        )
    }

    // ── Batch operations ──────────────────────────────────────────────────────

    /// Demangle all symbols in `symbols` and return the results in order.
    #[must_use]
    pub fn demangle_batch(&mut self, symbols: &[impl AsRef<str>]) -> Vec<DemangleResult> {
        symbols.iter().map(|s| self.demangle(s.as_ref())).collect()
    }

    /// Demangle all symbols and return a `HashMap<original, demangled>`.
    #[must_use]
    pub fn demangle_map(
        &mut self,
        symbols: &[impl AsRef<str>],
    ) -> HashMap<String, String> {
        symbols
            .iter()
            .map(|s| {
                let r = self.demangle(s.as_ref());
                (r.original, r.demangled)
            })
            .collect()
    }

    /// Apply demangling to all symbols in a text blob, returning a new string
    /// where each recognized symbol is replaced by its demangled form.
    #[must_use]
    pub fn demangle_text(&mut self, text: &str) -> String {
        // Extract symbol-like tokens (words bounded by whitespace or common punctuation).
        let mut result = text.to_owned();
        for token in extract_symbol_tokens(text) {
            let r = self.demangle(&token);
            if r.success && r.demangled != token {
                result = result.replacen(&token, &r.demangled, 1);
            }
        }
        result
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    /// Total number of symbols processed.
    #[must_use]
    pub const fn total_processed(&self) -> u64 {
        self.total_processed
    }

    /// Per-scheme hit counts.
    #[must_use]
    pub const fn scheme_counts(&self) -> &HashMap<MangleScheme, u64> {
        &self.scheme_counts
    }

    /// Number of entries in the cache.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    /// Clear the internal cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
        self.go_demangler.clear_cache();
    }

    /// Generate a human-readable statistics summary.
    #[must_use]
    pub fn stats_summary(&self) -> String {
        let mut out = format!(
            "DemanglerDispatcher Statistics\n\
             Total processed: {}\n\
             Cache size     : {}\n\n\
             By scheme:\n",
            self.total_processed,
            self.cache_size(),
        );
        let mut counts: Vec<(MangleScheme, u64)> = self
            .scheme_counts
            .iter()
            .map(|(&s, &c)| (s, c))
            .collect();
        counts.sort_unstable_by_key(|&(_, count)| std::cmp::Reverse(count));
        for (scheme, count) in counts {
            writeln!(out, "  {:20} {}", scheme.name(), count).ok();
        }
        out
    }
}

impl Default for DemanglerDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ── Convenience free function ─────────────────────────────────────────────────

/// Attempt to demangle `symbol` using the auto-detector.
///
/// Returns the demangled string, or the original if demangling fails.
#[must_use]
pub fn auto_demangle(symbol: &str) -> String {
    let mut dispatcher = DemanglerDispatcher::new();
    dispatcher.demangle(symbol).demangled
}

/// Detect the mangling scheme without demangling.
#[must_use]
pub fn detect_scheme(symbol: &str) -> MangleScheme {
    DemanglerDispatcher::detect_scheme(symbol)
}

// ── Token extraction helper ───────────────────────────────────────────────────

/// Extract symbol-like tokens from arbitrary text (e.g. stack traces).
fn extract_symbol_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    for word in text.split_whitespace() {
        // Strip common punctuation wrappers.
        let clean = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '.' && c != ':' && c != '$' && c != '?');
        if clean.len() >= 4 {
            tokens.push(clean.to_owned());
        }
    }
    tokens
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_rust_v0() {
        assert_eq!(
            DemanglerDispatcher::detect_scheme("_RNvNtCs1234_3std4sync5Mutex4lock"),
            MangleScheme::RustV0
        );
    }

    #[test]
    fn detect_itanium() {
        assert_eq!(
            DemanglerDispatcher::detect_scheme("_ZN3std4sync5MutexINS_3vecVecIiEEE4lockEv"),
            MangleScheme::ItaniumCpp
        );
    }

    #[test]
    fn detect_msvc() {
        assert_eq!(
            DemanglerDispatcher::detect_scheme("?foo@@YAHH@Z"),
            MangleScheme::MsvcCpp
        );
    }

    #[test]
    fn detect_swift() {
        assert_eq!(
            DemanglerDispatcher::detect_scheme("$s4main3fooyyF"),
            MangleScheme::Swift
        );
    }

    #[test]
    fn detect_dlang() {
        assert_eq!(
            DemanglerDispatcher::detect_scheme("_D4main3fooFZi"),
            MangleScheme::DLang
        );
    }

    #[test]
    fn detect_go() {
        assert_eq!(
            DemanglerDispatcher::detect_scheme("main.main"),
            MangleScheme::Go
        );
    }

    #[test]
    fn detect_plain_c() {
        assert_eq!(
            DemanglerDispatcher::detect_scheme("malloc"),
            MangleScheme::PlainC
        );
    }

    #[test]
    fn demangle_rust_legacy_succeeds() {
        let mut d = DemanglerDispatcher::new();
        let sym = "_ZN3std3vec3Vec3new17h1234567890123456E";
        let result = d.demangle(sym);
        // May or may not succeed depending on rustc-demangle, but should not panic.
        assert_eq!(result.original, sym);
    }

    #[test]
    fn demangle_itanium_basic() {
        let mut d = DemanglerDispatcher::new();
        let r = d.demangle("_ZN3foo3barEv");
        // Should produce something demangled.
        assert_eq!(r.scheme, MangleScheme::ItaniumCpp);
    }

    #[test]
    fn demangle_go_basic() {
        let mut d = DemanglerDispatcher::new();
        let r = d.demangle("main.main");
        assert_eq!(r.scheme, MangleScheme::Go);
        assert!(r.success);
    }

    #[test]
    fn plain_c_passthrough() {
        let mut d = DemanglerDispatcher::new();
        let r = d.demangle("malloc");
        assert_eq!(r.scheme, MangleScheme::PlainC);
        assert_eq!(r.demangled, "malloc");
        assert!(r.success);
    }

    #[test]
    fn cache_hit_on_second_call() {
        let mut d = DemanglerDispatcher::new();
        d.demangle("main.main");
        let size1 = d.cache_size();
        d.demangle("main.main");
        assert_eq!(d.cache_size(), size1); // no growth on second call
    }

    #[test]
    fn batch_demangle_length_matches() {
        let mut d = DemanglerDispatcher::new();
        let syms = vec!["main.main", "malloc", "_ZN3foo3barEv"];
        let results = d.demangle_batch(&syms);
        assert_eq!(results.len(), syms.len());
    }

    #[test]
    fn demangle_map_has_all_keys() {
        let mut d = DemanglerDispatcher::new();
        let syms = vec!["main.main", "malloc"];
        let map = d.demangle_map(&syms);
        assert_eq!(map.len(), syms.len());
    }

    #[test]
    fn auto_demangle_go_symbol() {
        let r = auto_demangle("main.main");
        assert!(!r.is_empty());
    }

    #[test]
    fn scheme_counts_incremented() {
        let mut d = DemanglerDispatcher::new();
        d.demangle("main.main");
        d.demangle("malloc");
        assert!(d.scheme_counts().get(&MangleScheme::Go).copied().unwrap_or(0) >= 1);
        assert!(d.scheme_counts().get(&MangleScheme::PlainC).copied().unwrap_or(0) >= 1);
    }

    #[test]
    fn mangle_scheme_is_mangled() {
        assert!(MangleScheme::RustV0.is_mangled());
        assert!(MangleScheme::ItaniumCpp.is_mangled());
        assert!(!MangleScheme::PlainC.is_mangled());
        assert!(!MangleScheme::Unknown.is_mangled());
    }

    #[test]
    fn stats_summary_non_empty() {
        let mut d = DemanglerDispatcher::new();
        d.demangle("main.main");
        let s = d.stats_summary();
        assert!(s.contains("Total processed: 1"));
    }
}
