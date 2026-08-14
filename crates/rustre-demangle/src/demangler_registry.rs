//! `demangler_registry` — Demangler registry and dispatcher for RustRE.
//!
//! Provides [`DemanglerRegistry`], [`Demangler`] trait, concrete implementations
//! (`ItaniumDemangler`, `MsvcDemangler`, `SwiftDemangler`, `RustDemangler`,
//! `DDemangler`, `BorlandDemangler`), `AutoDemangler`, `DemanglerCache`, and
//! `BulkDemangler`.

use std::fmt;
// AHashMap: used where attacker-controlled mangled symbol strings are keys,
// to prevent hash-collision DoS via std's SipHash.

// ── MangleScheme ──────────────────────────────────────────────────────────────

/// Name-mangling scheme detected from a symbol's prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MangleScheme {
    /// GCC / Clang C++ ABI (`_Z` prefix).
    Itanium,
    /// MSVC (`?` prefix).
    Msvc,
    /// Swift (`$s` prefix).
    Swift,
    /// Rust (`_R` prefix or `__ZN…Rust`).
    Rust,
    /// D language (`_D` prefix).
    D,
    /// Borland C++ (`@` / `%` prefix).
    Borland,
    /// Objective-C (simple `+` / `-` prefix).
    ObjC,
    /// No recognised mangling prefix.
    Unknown,
}

impl MangleScheme {
    /// Detect the mangling scheme of `symbol` from its prefix.
    #[must_use]
    pub fn detect(symbol: &str) -> Self {
        if symbol.starts_with("_Z") || symbol.starts_with("__Z") {
            // Could be Itanium or Rust — check further.
            if symbol.contains("_Rust_") || crate::sigil::is_rust_legacy(symbol) {
                return Self::Rust;
            }
            return Self::Itanium;
        }
        if crate::sigil::is_rust_v0(symbol) {
            return Self::Rust;
        }
        if symbol.starts_with('?') {
            return Self::Msvc;
        }
        if symbol.starts_with("$s") || symbol.starts_with("_$s") {
            return Self::Swift;
        }
        if crate::sigil::is_d(symbol) {
            return Self::D;
        }
        if symbol.starts_with('@') || symbol.starts_with('%') {
            return Self::Borland;
        }
        if symbol.starts_with('+') || symbol.starts_with('-') {
            return Self::ObjC;
        }
        Self::Unknown
    }

    /// Lowercase name of the scheme (e.g. `"itanium"`, `"msvc"`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Itanium => "itanium",
            Self::Msvc => "msvc",
            Self::Swift => "swift",
            Self::Rust => "rust",
            Self::D => "d",
            Self::Borland => "borland",
            Self::ObjC => "objc",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for MangleScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ── DemangleResult ────────────────────────────────────────────────────────────

/// Result of a successful demangling attempt, with a confidence score.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemangleResult {
    /// The original mangled symbol.
    pub original: String,
    /// The demangled human-readable form.
    pub demangled: String,
    /// The [`MangleScheme`] that decoded the symbol.
    pub scheme: MangleScheme,
    /// Confidence in the result, 0-100.
    pub confidence: u8, // 0-100
}

impl DemangleResult {
    /// Create a result from its parts, cloning `original`.
    #[must_use]
    pub fn new(original: &str, demangled: String, scheme: MangleScheme, confidence: u8) -> Self {
        Self {
            original: original.to_owned(),
            demangled,
            scheme,
            confidence,
        }
    }
    /// Returns `true` if `confidence` is at least 80.
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 80
    }
}

impl fmt::Display for DemangleResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}@{}]",
            self.demangled, self.scheme, self.confidence
        )
    }
}

// ── Demangler trait ───────────────────────────────────────────────────────────

/// A demangler for one [`MangleScheme`], registrable in [`DemanglerRegistry`].
pub trait Demangler: Send + Sync + fmt::Debug {
    /// Short identifier of this demangler (e.g. `"itanium"`).
    fn name(&self) -> &str;
    /// The [`MangleScheme`] this demangler handles.
    fn scheme(&self) -> MangleScheme;
    /// Returns `true` if `symbol` looks decodable by this demangler.
    fn can_demangle(&self, symbol: &str) -> bool;
    /// Attempt to demangle `symbol`; returns `None` on failure.
    fn demangle(&self, symbol: &str) -> Option<DemangleResult>;
}

// ── ItaniumDemangler ──────────────────────────────────────────────────────────

/// Simplified Itanium ABI demangler.
#[derive(Debug)]
pub struct ItaniumDemangler;

impl Demangler for ItaniumDemangler {
    fn name(&self) -> &'static str {
        "itanium"
    }
    fn scheme(&self) -> MangleScheme {
        MangleScheme::Itanium
    }

    fn can_demangle(&self, symbol: &str) -> bool {
        symbol.starts_with("_Z") || symbol.starts_with("__Z")
    }

    fn demangle(&self, symbol: &str) -> Option<DemangleResult> {
        if !self.can_demangle(symbol) {
            return None;
        }

        // Try cpp_demangle if available (otherwise use simplified decoder).
        let demangled = Self::decode_itanium(symbol);
        Some(DemangleResult::new(
            symbol,
            demangled,
            MangleScheme::Itanium,
            75,
        ))
    }
}

impl ItaniumDemangler {
    fn decode_itanium(s: &str) -> String {
        // Minimal Itanium parser: handle common patterns.
        let body = s.strip_prefix("__Z").unwrap_or_else(|| &s[2..]);

        // _ZN<qualifier>E pattern
        if let Some(demangled) = Self::try_decode_nested(body) {
            return demangled;
        }

        // Simple substitutions.
        let result = body
            .replace("St", "std::")
            .replace("3std", "std")
            .replace('v', "void");
        format!("<itanium:{result}>")
    }

    fn try_decode_nested(s: &str) -> Option<String> {
        if !s.starts_with('N') {
            return None;
        }
        let mut parts = Vec::new();
        let mut i = 1;
        let bytes = s.as_bytes();
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                let mut len: usize = 0;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    len = len.checked_mul(10)?.checked_add((bytes[i] - b'0') as usize)?;
                    i += 1;
                }
                if i + len > s.len() {
                    return None;
                }
                parts.push(s[i..i + len].to_owned());
                i += len;
            } else if bytes[i] == b'E' {
                break;
            } else {
                i += 1;
            }
        }
        if parts.is_empty() {
            return None;
        }
        Some(parts.join("::"))
    }
}

// ── MsvcDemangler ─────────────────────────────────────────────────────────────

/// Simplified MSVC demangler.
#[derive(Debug)]
pub struct MsvcDemangler;

impl Demangler for MsvcDemangler {
    fn name(&self) -> &'static str {
        "msvc"
    }
    fn scheme(&self) -> MangleScheme {
        MangleScheme::Msvc
    }
    fn can_demangle(&self, symbol: &str) -> bool {
        symbol.starts_with('?')
    }

    fn demangle(&self, symbol: &str) -> Option<DemangleResult> {
        if !self.can_demangle(symbol) {
            return None;
        }
        let decoded = Self::decode_msvc(symbol);
        Some(DemangleResult::new(symbol, decoded, MangleScheme::Msvc, 70))
    }
}

impl MsvcDemangler {
    fn decode_msvc(s: &str) -> String {
        // Very minimal: extract name before @ signs.
        let stripped = s.trim_start_matches('?');
        let name_part = stripped.split('@').next().unwrap_or(stripped);
        // Common decorations
        let name = name_part.replace("_cdecl", "").replace("_stdcall", "");
        format!("{}(…)", name.trim_matches('_'))
    }
}

// ── SwiftDemangler ────────────────────────────────────────────────────────────

/// Simplified Swift demangler (`$s` / `_$s` / `$S` prefixes).
#[derive(Debug)]
pub struct SwiftDemangler;

impl Demangler for SwiftDemangler {
    fn name(&self) -> &'static str {
        "swift"
    }
    fn scheme(&self) -> MangleScheme {
        MangleScheme::Swift
    }
    fn can_demangle(&self, symbol: &str) -> bool {
        symbol.starts_with("$s") || symbol.starts_with("_$s") || symbol.starts_with("$S")
    }
    fn demangle(&self, symbol: &str) -> Option<DemangleResult> {
        if !self.can_demangle(symbol) {
            return None;
        }
        let body = symbol
            .trim_start_matches("_$s")
            .trim_start_matches("$s")
            .trim_start_matches("$S");
        let decoded = format!("<swift:{body}>");
        Some(DemangleResult::new(
            symbol,
            decoded,
            MangleScheme::Swift,
            60,
        ))
    }
}

// ── RustDemangler ─────────────────────────────────────────────────────────────

/// Simplified Rust demangler (v0 `_R` prefix and legacy `_Z…Rust` forms).
#[derive(Debug)]
pub struct RustDemangler;

impl Demangler for RustDemangler {
    fn name(&self) -> &'static str {
        "rust"
    }
    fn scheme(&self) -> MangleScheme {
        MangleScheme::Rust
    }
    fn can_demangle(&self, symbol: &str) -> bool {
        crate::sigil::is_rust_v0(symbol)
            || symbol.contains("_Rust_")
            || (symbol.starts_with("_Z") && (symbol.contains("Rust") || symbol.contains("rust")))
    }
    fn demangle(&self, symbol: &str) -> Option<DemangleResult> {
        if !self.can_demangle(symbol) {
            return None;
        }
        // v0 mangling: _R prefix
        let decoded = if crate::sigil::is_rust_v0(symbol) {
            Self::decode_v0(symbol)
        } else {
            format!("<rust:{}>", &symbol[2..])
        };
        Some(DemangleResult::new(symbol, decoded, MangleScheme::Rust, 65))
    }
}

impl RustDemangler {
    fn decode_v0(s: &str) -> String {
        // Simplified Rust v0 demangling.
        let body = &s[2..]; // strip _R
        // Strip hash suffix (_hXXX)
        let no_hash = body.rfind("_h").map_or(body, |pos| &body[..pos]);
        // Replace _ separators and decode length-prefixed names.
        let mut result = no_hash.replace("__", "::");
        result = result.replace('_', "::");
        format!("rust::{result}")
    }
}

// ── DDemangler ────────────────────────────────────────────────────────────────

/// Simplified D language demangler (`_D` prefix, length-prefixed names).
#[derive(Debug)]
pub struct DDemangler;

impl Demangler for DDemangler {
    fn name(&self) -> &'static str {
        "d"
    }
    fn scheme(&self) -> MangleScheme {
        MangleScheme::D
    }
    fn can_demangle(&self, symbol: &str) -> bool {
        crate::sigil::is_d(symbol)
    }
    fn demangle(&self, symbol: &str) -> Option<DemangleResult> {
        if !self.can_demangle(symbol) {
            return None;
        }
        let body = &symbol[2..];
        // Decode length-prefixed names like _D3foo3barFiZi → foo.bar(int) int
        let decoded = Self::decode_d(body);
        Some(DemangleResult::new(symbol, decoded, MangleScheme::D, 60))
    }
}

impl DDemangler {
    fn decode_d(s: &str) -> String {
        let mut parts = Vec::new();
        let mut i = 0;
        let bytes = s.as_bytes();
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            let mut len: usize = 0;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                len = len.saturating_mul(10).saturating_add((bytes[i] - b'0') as usize);
                i += 1;
            }
            if i + len > s.len() {
                break;
            }
            parts.push(s[i..i + len].to_owned());
            i += len;
        }
        if parts.is_empty() {
            format!("<D:{s}>")
        } else {
            parts.join(".")
        }
    }
}

// ── BorlandDemangler ──────────────────────────────────────────────────────────

/// Simplified Borland C++ demangler (`@` / `%` prefixes).
#[derive(Debug)]
pub struct BorlandDemangler;

impl Demangler for BorlandDemangler {
    fn name(&self) -> &'static str {
        "borland"
    }
    fn scheme(&self) -> MangleScheme {
        MangleScheme::Borland
    }
    fn can_demangle(&self, symbol: &str) -> bool {
        symbol.starts_with('@') || symbol.starts_with('%')
    }
    fn demangle(&self, symbol: &str) -> Option<DemangleResult> {
        if !self.can_demangle(symbol) {
            return None;
        }
        let stripped = symbol.trim_start_matches('@').trim_start_matches('%');
        let parts: Vec<_> = stripped.split('@').collect();
        let decoded = parts.join("::");
        Some(DemangleResult::new(
            symbol,
            decoded,
            MangleScheme::Borland,
            55,
        ))
    }
}

// ── AutoDemangler ─────────────────────────────────────────────────────────────

/// Tries all registered demanglers in priority order.
pub struct AutoDemangler {
    demanglers: Vec<Box<dyn Demangler>>,
}

impl AutoDemangler {
    /// Create an empty `AutoDemangler` with no registered demanglers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            demanglers: Vec::new(),
        }
    }

    /// Create an `AutoDemangler` with all built-in demanglers registered
    /// in priority order (Rust before Itanium, since both use `_Z`).
    #[must_use]
    pub fn standard() -> Self {
        let mut a = Self::new();
        // Priority order: Rust before Itanium (both use _Z prefix).
        a.register(Box::new(RustDemangler));
        a.register(Box::new(ItaniumDemangler));
        a.register(Box::new(MsvcDemangler));
        a.register(Box::new(SwiftDemangler));
        a.register(Box::new(DDemangler));
        a.register(Box::new(BorlandDemangler));
        a
    }

    /// Append a demangler; earlier registrations take priority.
    pub fn register(&mut self, d: Box<dyn Demangler>) {
        self.demanglers.push(d);
    }

    /// Try each registered demangler in order; first success wins.
    #[must_use]
    pub fn demangle(&self, symbol: &str) -> Option<DemangleResult> {
        for d in &self.demanglers {
            if d.can_demangle(symbol)
                && let Some(r) = d.demangle(symbol) {
                    return Some(r);
                }
        }
        None
    }

    /// Demangle `symbol`, falling back to the original string on failure.
    #[must_use]
    pub fn demangle_or_original(&self, symbol: &str) -> String {
        self.demangle(symbol).map_or_else(|| symbol.to_owned(), |r| r.demangled)
    }
}

impl Default for AutoDemangler {
    fn default() -> Self {
        Self::standard()
    }
}

impl fmt::Debug for AutoDemangler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AutoDemangler({} demanglers)", self.demanglers.len())
    }
}

// ── DemanglerCache (LRU) ──────────────────────────────────────────────────────

/// LRU cache for demangled symbols.
pub struct DemanglerCache {
    capacity: usize,
    core: crate::demangler_cache::LruCore<Option<DemangleResult>>,
}

impl DemanglerCache {
    /// Create an empty cache holding at most `capacity` entries.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            core: crate::demangler_cache::LruCore::new(capacity),
        }
    }

    /// Look up a cached result. The outer `Option` is presence in the cache;
    /// the inner `Option` is the cached demangling outcome (failures are cached too).
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Option<DemangleResult>> {
        self.core.peek(key)
    }

    /// Insert a demangling outcome, evicting the oldest entries (FIFO)
    /// once `capacity` is reached.
    pub fn insert(&mut self, key: &str, val: Option<DemangleResult>) {
        // `insert_keep_order` never promotes, so recency order == insertion
        // order and eviction stays FIFO — matching this cache's contract
        // (its `get` takes `&self` and therefore cannot promote).
        self.core.insert_keep_order(key.to_owned(), val);
    }

    /// Number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.core.len()
    }
    /// Returns `true` if the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.core.is_empty()
    }
    /// Remove all entries.
    pub fn clear(&mut self) {
        self.core.clear();
    }
}

impl fmt::Debug for DemanglerCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DemanglerCache({}/{} entries)",
            self.core.len(),
            self.capacity
        )
    }
}

// ── DemanglerRegistry ─────────────────────────────────────────────────────────

/// The central demangler registry.
pub struct DemanglerRegistry {
    demanglers: Vec<Box<dyn Demangler>>,
    cache: DemanglerCache,
}

impl DemanglerRegistry {
    /// Create an empty registry with a 4096-entry result cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            demanglers: Vec::new(),
            cache: DemanglerCache::new(4096),
        }
    }

    /// Create a registry with all built-in demanglers registered in
    /// priority order (Rust before Itanium, since both use `_Z`).
    #[must_use]
    pub fn standard() -> Self {
        let mut r = Self::new();
        r.register(Box::new(RustDemangler));
        r.register(Box::new(ItaniumDemangler));
        r.register(Box::new(MsvcDemangler));
        r.register(Box::new(SwiftDemangler));
        r.register(Box::new(DDemangler));
        r.register(Box::new(BorlandDemangler));
        r
    }

    /// Append a demangler; earlier registrations take priority.
    pub fn register(&mut self, d: Box<dyn Demangler>) {
        self.demanglers.push(d);
    }

    /// Number of registered demanglers.
    #[must_use]
    pub fn demangler_count(&self) -> usize {
        self.demanglers.len()
    }

    /// Detect the [`MangleScheme`] of `symbol` (delegates to [`MangleScheme::detect`]).
    #[must_use]
    pub fn detect_scheme(&self, symbol: &str) -> MangleScheme {
        MangleScheme::detect(symbol)
    }

    /// Demangle `symbol` with the first capable demangler, caching the
    /// outcome (including failures) for subsequent calls.
    pub fn demangle(&mut self, symbol: &str) -> Option<DemangleResult> {
        if let Some(cached) = self.cache.get(symbol) {
            return cached.clone();
        }
        let result = self
            .demanglers
            .iter()
            .find(|d| d.can_demangle(symbol))
            .and_then(|d| d.demangle(symbol));
        self.cache.insert(symbol, result.clone());
        result
    }

    /// Demangle `symbol`, falling back to the original string on failure.
    pub fn demangle_or_original(&mut self, symbol: &str) -> String {
        self.demangle(symbol).map_or_else(|| symbol.to_owned(), |r| r.demangled)
    }
}

impl Default for DemanglerRegistry {
    fn default() -> Self {
        Self::standard()
    }
}

impl fmt::Debug for DemanglerRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DemanglerRegistry({} demanglers, cache={:?})",
            self.demanglers.len(),
            self.cache
        )
    }
}

// ── BulkDemangler ─────────────────────────────────────────────────────────────

/// Batch demangling of symbol lists.
pub struct BulkDemangler {
    auto: AutoDemangler,
}

impl BulkDemangler {
    /// Create a bulk demangler backed by [`AutoDemangler::standard`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            auto: AutoDemangler::standard(),
        }
    }

    /// Demangle a list of symbols. Returns (original, `demangled_or_original`) pairs.
    #[must_use] 
    pub fn demangle_all(&self, symbols: &[&str]) -> Vec<(String, String)> {
        symbols
            .iter()
            .map(|&s| {
                let d = self.auto.demangle_or_original(s);
                (s.to_owned(), d)
            })
            .collect()
    }

    /// Return only symbols that were successfully demangled (changed).
    #[must_use] 
    pub fn demangled_only(&self, symbols: &[&str]) -> Vec<DemangleResult> {
        symbols
            .iter()
            .filter_map(|&s| self.auto.demangle(s))
            .filter(|r| r.demangled != r.original)
            .collect()
    }

    /// Statistics about a list of symbols.
    #[must_use] 
    pub fn stats(&self, symbols: &[&str]) -> BulkStats {
        let mut stats = BulkStats {
            total: symbols.len(),
            ..BulkStats::default()
        };
        for &s in symbols {
            let scheme = MangleScheme::detect(s);
            if scheme != MangleScheme::Unknown {
                stats.mangled += 1;
                match scheme {
                    MangleScheme::Itanium => stats.itanium += 1,
                    MangleScheme::Msvc => stats.msvc += 1,
                    MangleScheme::Swift => stats.swift += 1,
                    MangleScheme::Rust => stats.rust += 1,
                    MangleScheme::D => stats.d += 1,
                    MangleScheme::Borland => stats.borland += 1,
                    _ => {}
                }
            }
        }
        stats
    }
}

impl Default for BulkDemangler {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-scheme symbol counts produced by [`BulkDemangler::stats`].
#[derive(Debug, Clone, Default)]
pub struct BulkStats {
    /// Total symbols examined.
    pub total: usize,
    /// Symbols with any recognised mangling scheme.
    pub mangled: usize,
    /// Itanium-mangled symbols.
    pub itanium: usize,
    /// MSVC-mangled symbols.
    pub msvc: usize,
    /// Swift-mangled symbols.
    pub swift: usize,
    /// Rust-mangled symbols.
    pub rust: usize,
    /// D-mangled symbols.
    pub d: usize,
    /// Borland-mangled symbols.
    pub borland: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MangleScheme::detect ──────────────────────────────────────────────────

    #[test]
    fn test_detect_itanium() {
        assert_eq!(MangleScheme::detect("_ZN3foo3barEi"), MangleScheme::Itanium);
    }
    #[test]
    fn test_detect_msvc() {
        assert_eq!(MangleScheme::detect("?foo@@YAHH@Z"), MangleScheme::Msvc);
    }
    #[test]
    fn test_detect_swift() {
        assert_eq!(MangleScheme::detect("$s4main3fooyyF"), MangleScheme::Swift);
    }
    #[test]
    fn test_detect_d() {
        assert_eq!(MangleScheme::detect("_D3foo3barFiZi"), MangleScheme::D);
    }
    #[test]
    fn test_detect_borland() {
        assert_eq!(MangleScheme::detect("@ns@foo$i"), MangleScheme::Borland);
    }
    #[test]
    fn test_detect_unknown() {
        assert_eq!(MangleScheme::detect("main"), MangleScheme::Unknown);
    }

    // ── ItaniumDemangler ──────────────────────────────────────────────────────

    #[test]
    fn test_itanium_can_demangle() {
        let d = ItaniumDemangler;
        assert!(d.can_demangle("_ZN3foo3barEi"));
        assert!(!d.can_demangle("?foo@@YAHH@Z"));
    }
    #[test]
    fn test_itanium_demangle_returns_some() {
        let r = ItaniumDemangler.demangle("_ZN3foo3barEi");
        assert!(r.is_some());
        assert_eq!(r.unwrap().scheme, MangleScheme::Itanium);
    }
    #[test]
    fn test_itanium_nested_decode() {
        let r = ItaniumDemangler.demangle("_ZN3foo3barEv").unwrap();
        assert!(r.demangled.contains("foo"), "demangled='{}'", r.demangled);
        assert!(r.demangled.contains("bar"), "demangled='{}'", r.demangled);
    }

    // ── MsvcDemangler ─────────────────────────────────────────────────────────

    #[test]
    fn test_msvc_can_demangle() {
        let d = MsvcDemangler;
        assert!(d.can_demangle("?foo@@YAHH@Z"));
        assert!(!d.can_demangle("_Zfoo"));
    }
    #[test]
    fn test_msvc_demangle_returns_some() {
        let r = MsvcDemangler.demangle("?foo@@YAHH@Z");
        assert!(r.is_some());
    }

    // ── RustDemangler ─────────────────────────────────────────────────────────

    #[test]
    fn test_rust_can_demangle() {
        let d = RustDemangler;
        assert!(d.can_demangle("_RC3foo3bar"));
        assert!(d.can_demangle("_ZN4_Rust3fooE"));
    }
    #[test]
    fn test_rust_demangle_v0() {
        let r = RustDemangler.demangle("_RC3foo3bar").unwrap();
        assert_eq!(r.scheme, MangleScheme::Rust);
    }

    // ── DDemangler ────────────────────────────────────────────────────────────

    #[test]
    fn test_d_demangle() {
        let r = DDemangler.demangle("_D3foo3barFiZi").unwrap();
        assert!(r.demangled.contains("foo"), "demangled='{}'", r.demangled);
    }

    // ── BorlandDemangler ──────────────────────────────────────────────────────

    #[test]
    fn test_borland_demangle() {
        let r = BorlandDemangler.demangle("@ns@foo$i");
        assert!(r.is_some());
        let r = r.unwrap();
        assert!(r.demangled.contains("ns"), "demangled='{}'", r.demangled);
    }

    // ── AutoDemangler ─────────────────────────────────────────────────────────

    #[test]
    fn test_auto_demangles_itanium() {
        let a = AutoDemangler::standard();
        let r = a.demangle("_ZN3foo3barEv");
        assert!(r.is_some(), "expected Some for _ZN3foo3barEv");
    }
    #[test]
    fn test_auto_demangles_msvc() {
        let a = AutoDemangler::standard();
        let r = a.demangle("?foo@@YAHH@Z");
        assert!(r.is_some());
    }
    #[test]
    fn test_auto_demangles_d() {
        let a = AutoDemangler::standard();
        assert!(a.demangle("_D3foo3barFiZi").is_some());
    }
    #[test]
    fn test_auto_demangle_or_original_unknown() {
        let a = AutoDemangler::standard();
        assert_eq!(a.demangle_or_original("main"), "main");
    }

    // ── DemanglerCache ────────────────────────────────────────────────────────

    #[test]
    fn test_cache_insert_get() {
        let mut cache = DemanglerCache::new(10);
        assert!(cache.is_empty());
        let r = Some(DemangleResult::new(
            "_Zfoo",
            "foo()".to_owned(),
            MangleScheme::Itanium,
            80,
        ));
        cache.insert("_Zfoo", r);
        assert!(cache.get("_Zfoo").is_some());
        assert_eq!(cache.len(), 1);
    }
    #[test]
    fn test_cache_eviction() {
        let mut cache = DemanglerCache::new(2);
        cache.insert("a", None);
        cache.insert("b", None);
        cache.insert("c", None); // evicts "a"
        assert!(cache.get("a").is_none());
        assert!(cache.get("b").is_some());
        assert!(cache.get("c").is_some());
    }
    #[test]
    fn test_cache_clear() {
        let mut cache = DemanglerCache::new(10);
        cache.insert("x", None);
        cache.clear();
        assert!(cache.is_empty());
    }

    // ── DemanglerRegistry ─────────────────────────────────────────────────────

    #[test]
    fn test_registry_demangle_itanium() {
        let mut r = DemanglerRegistry::standard();
        let result = r.demangle("_ZN3std6string6StringE");
        assert!(result.is_some(), "expected demangled result");
    }
    #[test]
    fn test_registry_demangle_cached() {
        let mut r = DemanglerRegistry::standard();
        let _ = r.demangle("_ZN3foo3barEv");
        let _ = r.demangle("_ZN3foo3barEv"); // second call → from cache
        assert!(!r.cache.is_empty());
    }
    #[test]
    fn test_registry_demangler_count() {
        let r = DemanglerRegistry::standard();
        assert!(r.demangler_count() >= 5, "expected >= 5 demanglers");
    }
    #[test]
    fn test_registry_detect_scheme() {
        let r = DemanglerRegistry::standard();
        assert_eq!(r.detect_scheme("?foo@@YAHH@Z"), MangleScheme::Msvc);
    }

    // ── BulkDemangler ─────────────────────────────────────────────────────────

    #[test]
    fn test_bulk_demangle_all() {
        let b = BulkDemangler::new();
        let syms = ["_ZN3foo3barEv", "main", "?foo@@YAHH@Z"];
        let results = b.demangle_all(&syms);
        assert_eq!(results.len(), 3);
    }
    #[test]
    fn test_bulk_demangled_only() {
        let b = BulkDemangler::new();
        let syms = ["_ZN3foo3barEv", "main"];
        let demangled = b.demangled_only(&syms);
        assert!(!demangled.is_empty());
    }
    #[test]
    fn test_bulk_stats() {
        let b = BulkDemangler::new();
        let syms = ["_ZN3foo3barEv", "?foo@@YAHH@Z", "main"];
        let stats = b.stats(&syms);
        assert_eq!(stats.total, 3);
        assert!(stats.mangled >= 2);
        assert!(stats.itanium >= 1);
        assert!(stats.msvc >= 1);
    }
    #[test]
    fn test_mangle_scheme_name() {
        assert_eq!(MangleScheme::Itanium.name(), "itanium");
        assert_eq!(MangleScheme::Msvc.name(), "msvc");
        assert_eq!(MangleScheme::Rust.name(), "rust");
    }
    #[test]
    fn test_demangle_result_display() {
        let r = DemangleResult::new("_Zfoo", "foo()".to_owned(), MangleScheme::Itanium, 90);
        let s = r.to_string();
        assert!(s.contains("foo()"), "display='{s}'");
        assert!(s.contains("itanium"), "display='{s}'");
    }
    #[test]
    fn test_demangle_result_high_confidence() {
        let r = DemangleResult::new("x", "y".to_owned(), MangleScheme::Msvc, 85);
        assert!(r.is_high_confidence());
        let r2 = DemangleResult::new("x", "y".to_owned(), MangleScheme::Msvc, 50);
        assert!(!r2.is_high_confidence());
    }
}
