//! Symbol classification, verbosity, Objective-C / extended Swift parsing,
//! caching, batch demangling, filtering, and type normalization.

use crate::core_types::{DemangleResult, MangleLanguage};
use crate::dispatch::Demangler2;
use crate::lang_wrappers::DDemangler;
// AHashMap: keys are untrusted mangled symbols; dos-hash-collision guard.
use ahash::AHashMap;
use serde::{Deserialize, Serialize};

// ── Symbol classification ──────────────────────────────────────────────────────

/// Classifies a mangled symbol string into the language / scheme that produced
/// it, using cheap prefix and shape heuristics (no full parse).
#[derive(Debug, Clone, Copy, Default)]
pub struct SymbolClassifier;

impl SymbolClassifier {
    /// Construct a new classifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Classify `mangled`, returning the [`MangleLanguage`] it most likely
    /// belongs to (or [`MangleLanguage::Unknown`]).
    #[must_use]
    pub fn classify(mangled: &str) -> MangleLanguage {
        // Objective-C method names: `+[Class sel]` / `-[Class sel]`.
        if ObjCDemangler::detect(mangled) {
            return MangleLanguage::ObjC;
        }
        // Swift: `$s` / `$S` (current) or `_T` (legacy) prefixes.
        if is_swift_prefix(mangled) {
            return MangleLanguage::Swift;
        }
        // Rust v0 (`_R`) — must be tested before Itanium's `_Z`.
        if is_rust_v0_prefix(mangled) {
            return MangleLanguage::Rust;
        }
        // D language: `_D` followed by a length-prefixed name.
        if DDemangler::detect(mangled) {
            return MangleLanguage::D;
        }
        // Itanium C++ (GCC/Clang): `_Z` / `__Z`. Legacy Rust also used `_ZN`
        // with a trailing `17h…` hash; detect that as Rust.
        if mangled.starts_with("_Z") || mangled.starts_with("__Z") {
            if is_legacy_rust_symbol(mangled) {
                return MangleLanguage::Rust;
            }
            return MangleLanguage::CppItanium;
        }
        // MSVC C++: `?`-prefixed.
        if mangled.starts_with('?') {
            return MangleLanguage::CppMsvc;
        }
        // JNI native methods (`Java_pkg_Class_method`). Delegates to the
        // detector the JNI decoder itself uses, so this cannot drift looser
        // than what actually decodes — the failure mode that had `_R`, `_T`
        // and `_D` inventing defects for plain C names.
        //
        // Without this, `MangleLanguage::Java` was a variant `classify` could
        // never return, even though the crate decodes JNI symbols happily:
        // `DemangleFilter::filter_by_language(syms, MangleLanguage::Java)`
        // silently yielded nothing on input full of `Java_…` names.
        if crate::lang_extra::detect_jni(mangled) {
            return MangleLanguage::Java;
        }
        MangleLanguage::Unknown
    }

    /// Instance method form of [`SymbolClassifier::classify`].
    #[must_use]
    pub fn classify_symbol(&self, mangled: &str) -> MangleLanguage {
        Self::classify(mangled)
    }
}

/// Whether `mangled` uses Swift mangling.
///
/// Delegates to [`crate::sigil`]; a bare `_T` test claimed `_TIFFOpen`.
fn is_swift_prefix(mangled: &str) -> bool {
    crate::sigil::is_swift(mangled)
}

/// Whether `mangled` opens with a Rust v0 path.
///
/// Delegates to [`crate::sigil`]; a bare `_R` test claimed `_RTC_Initialize`.
fn is_rust_v0_prefix(mangled: &str) -> bool {
    crate::sigil::is_rust_v0(mangled)
}

/// Heuristic: a legacy (`_ZN…`) Rust symbol carries a trailing `17h<16 hex>E`
/// hash component.
fn is_legacy_rust_symbol(mangled: &str) -> bool {
    if let Some(idx) = mangled.rfind("17h") {
        let after = &mangled[idx + 3..];
        let hex: String = after
            .chars()
            .take(16)
            .take_while(char::is_ascii_hexdigit)
            .collect();
        return hex.len() == 16 && after[hex.len()..].starts_with('E');
    }
    false
}

// ── Verbosity ──────────────────────────────────────────────────────────────────

/// How much detail a demangled string should carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum Verbosity {
    /// Drop template arguments and qualifiers; keep the bare name.
    Minimal,
    /// A balanced representation (the default).
    #[default]
    Normal,
    /// Keep every qualifier, template argument, and parameter.
    Full,
}


// ── Objective-C demangler ──────────────────────────────────────────────────────

/// Demangler for Objective-C method symbols.
///
/// clang's Obj-C metadata symbols, beyond the class/metaclass/ivar trio.
///
/// Longest-first is not required — no prefix here is a prefix of another once
/// `_OBJC_` is stripped (`CLASS_RO_$_` does not start with `CLASS_$_`) — but
/// the order is kept specific-to-general so that stays true if one is added.
const OBJC_METADATA: &[(&str, &str)] = &[
    ("LABEL_PROTOCOL_$_", "protocol label"),
    ("PROTOCOL_$_", "protocol"),
    ("CLASS_RO_$_", "class metadata"),
    ("METACLASS_RO_$_", "metaclass metadata"),
    ("$_INSTANCE_METHODS_", "instance methods of"),
    ("$_CLASS_METHODS_", "class methods of"),
    ("$_INSTANCE_VARIABLES_", "instance variables of"),
    ("$_PROP_LIST_", "properties of"),
    ("$_PROTOCOL_REFS_", "protocol refs of"),
];

/// Handles the human-readable method syntax `+[Class selector:]` /
/// `-[Class selector:]` and the linker mangling `_OBJC_…` produced by older
/// toolchains.
#[derive(Debug, Clone, Copy, Default)]

pub struct ObjCDemangler;

impl ObjCDemangler {
    /// Returns `true` if `mangled` looks like an Objective-C symbol.
    ///
    /// Requires the same structure [`Self::demangle`] needs, so the two cannot
    /// disagree. A bare-bracket `-[]` used to pass here and be declined there,
    /// which both panics `if detect(s) { demangle(s).unwrap() }` and files the
    /// symbol as an unhandled ABI — a phantom defect.
    #[must_use]
    pub fn detect(mangled: &str) -> bool {
        let trimmed = mangled.trim();
        if let Some(inner) = trimmed
            .strip_prefix("+[")
            .or_else(|| trimmed.strip_prefix("-["))
            .and_then(|t| t.strip_suffix(']'))
        {
            // A class name is mandatory; the selector is not (`-[Foo]` is a
            // legitimate shorthand).
            return !inner.split_whitespace().next().unwrap_or("").is_empty();
        }
        // Delegate for the linker forms. This doc comment already PROMISED the
        // two agree, and restating the rule broke that promise the moment
        // `demangle` learned to decline the literal-pool anchors
        // (`_OBJC_METH_VAR_NAME_`), which carry no name to decode.
        Self::demangle(mangled).is_some()
    }

    /// Demangle an Objective-C symbol into a `Class::method` representation.
    ///
    /// `+[Foo bar:]` becomes `+[Foo bar:]` normalised, and the `_OBJC_`
    /// linker forms are decoded into their `Class` / method parts.
    #[must_use]
    pub fn demangle(mangled: &str) -> Option<String> {
        let trimmed = mangled.trim();
        if (trimmed.starts_with("+[") || trimmed.starts_with("-[")) && trimmed.ends_with(']') {
            let is_class = trimmed.starts_with('+');
            let inner = &trimmed[2..trimmed.len() - 1];
            let mut it = inner.splitn(2, char::is_whitespace);
            let class = it.next().unwrap_or("").trim();
            let method = it.next().unwrap_or("").trim();
            if class.is_empty() {
                return None;
            }
            let marker = if is_class { '+' } else { '-' };
            if method.is_empty() {
                return Some(format!("{marker}[{class}]"));
            }
            return Some(format!("{marker}[{class} {method}]"));
        }

        // Linker forms: `_OBJC_CLASS_$_Foo`, `_OBJC_METACLASS_$_Foo`,
        // `_OBJC_IVAR_$_Foo._field`.
        if let Some(rest) = mangled.strip_prefix("_OBJC_") {
            // The empty-name guard below is the same one the fallback used to
            // carry, and these three predate it: `_OBJC_CLASS_$_` decoded to
            // `"class "`, which holds exactly as much information as the
            // `Some("")` the code already refuses.
            if let Some(name) = rest.strip_prefix("CLASS_$_") {
                return (!name.is_empty()).then(|| format!("class {name}"));
            }
            if let Some(name) = rest.strip_prefix("METACLASS_$_") {
                return (!name.is_empty()).then(|| format!("metaclass {name}"));
            }
            if let Some(name) = rest.strip_prefix("IVAR_$_") {
                return (!name.is_empty()).then(|| format!("ivar {}", name.replace('.', "::")));
            }
            // The rest of clang's Obj-C metadata symbols. These are as
            // documented as the three above; only three had ever been written
            // down, and everything else fell through to a fallback that
            // replaced `_` with a space — turning `_OBJC_PROTOCOL_$_Foo` into
            // `PROTOCOL $ Foo`. That is not a demangling: the `$` is a
            // mangling sigil reaching the output, and the result is neither
            // the input nor a decoded name.
            for (prefix, render) in OBJC_METADATA {
                if let Some(name) = rest.strip_prefix(prefix) {
                    if name.is_empty() {
                        return None;
                    }
                    return Some(format!("{render} {name}"));
                }
            }
            // Anything else — `_OBJC_METH_VAR_NAME_`, `_OBJC_SELECTOR_REFERENCES_`
            // and the other literal-pool anchors — carries no name to decode.
            // Declining is the honest answer; mutilating the symbol was not.
            return None;
        }
        None
    }
}

// ── Swift extended parser ──────────────────────────────────────────────────────

/// The structured pieces extracted from a Swift mangled symbol by
/// [`SwiftExtendedParser`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SwiftSymbol {
    /// The Swift module the symbol is declared in.
    pub module: String,
    /// The nominal-type / declaration path within the module.
    pub path: Vec<String>,
    /// `true` if the symbol denotes a function.
    pub is_function: bool,
}

/// Extended parser for the Swift `$s` / `$S` (and legacy `_T0`) mangling
/// schemes. It walks the length-prefixed identifier sequence and recognises
/// the common trailing operator codes.
#[derive(Debug, Clone, Copy, Default)]
pub struct SwiftExtendedParser;

impl SwiftExtendedParser {
    /// Parse a Swift mangled symbol into a [`SwiftSymbol`], or `None` if it
    /// does not carry a recognised Swift prefix or yields no module.
    #[must_use]
    pub fn parse(mangled: &str) -> Option<SwiftSymbol> {
        let body = mangled
            .strip_prefix("$s")
            .or_else(|| mangled.strip_prefix("$S"))
            .or_else(|| mangled.strip_prefix("_T0"))?;

        let bytes = body.as_bytes();
        let mut pos = 0usize;
        let mut idents: Vec<String> = Vec::new();

        // Read consecutive `<len><chars>` identifiers.
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            let mut len = 0usize;
            while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                len = len * 10 + (bytes[pos] - b'0') as usize;
                pos += 1;
            }
            if len == 0 || pos + len > bytes.len() {
                break;
            }
            idents.push(body[pos..pos + len].to_owned());
            pos += len;

            // A nominal-type kind marker (C=class, V=struct, O=enum, P=protocol)
            // may follow each identifier; skip it.
            if pos < bytes.len() && matches!(bytes[pos], b'C' | b'V' | b'O' | b'P') {
                pos += 1;
            }
        }

        if idents.is_empty() {
            return None;
        }

        // A trailing `F` marks a function, `y…F` a function with arguments.
        let is_function = body.as_bytes().last() == Some(&b'F');

        let module = idents.remove(0);
        Some(SwiftSymbol {
            module,
            path: idents,
            is_function,
        })
    }
}

// ── Symbol cache ───────────────────────────────────────────────────────────────

/// A simple in-memory cache mapping mangled symbol strings to their
/// (optional) demangled [`DemangleResult`].
#[derive(Debug, Clone, Default)]
pub struct SymbolCache {
    // AHashMap: keys are untrusted mangled symbols; dos-hash-collision guard.
    entries: AHashMap<String, DemangleResult>,
}

impl SymbolCache {
    /// Create an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: AHashMap::new(),
        }
    }

    /// Look up a previously cached result for `mangled`, if any.
    #[must_use]
    pub fn get(&self, mangled: &str) -> Option<&DemangleResult> {
        self.entries.get(mangled)
    }

    /// Insert a demangling result for `mangled`.
    pub fn insert(&mut self, mangled: String, result: DemangleResult) {
        self.entries.insert(mangled, result);
    }

    /// Demangle `mangled`, caching and returning the result. Repeated calls
    /// for the same input reuse the cached value.
    pub fn demangle_cached(&mut self, mangled: &str) -> DemangleResult {
        if let Some(v) = self.entries.get(mangled) {
            return v.clone();
        }
        let result = Demangler2::demangle(mangled);
        self.entries.insert(mangled.to_owned(), result.clone());
        result
    }

    /// Number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove all cached entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ── Batch demangling ───────────────────────────────────────────────────────────

/// Demangle a batch of symbols, returning one [`DemangleResult`] per input in
/// the same order.
#[must_use]
pub fn batch_demangle<S: AsRef<str>>(symbols: &[S]) -> Vec<DemangleResult> {
    symbols
        .iter()
        .map(|s| Demangler2::demangle(s.as_ref()))
        .collect()
}

/// Like [`batch_demangle`], but deduplicates work across repeated inputs via a
/// shared cache. The name reflects its role as the throughput-oriented batch
/// entry point; results preserve input order.
#[must_use]
pub fn batch_demangle_parallel<S: AsRef<str>>(symbols: &[S]) -> Vec<DemangleResult> {
    // AHashMap: keys are untrusted mangled symbols; dos-hash-collision guard.
    let mut cache: AHashMap<&str, DemangleResult> = AHashMap::new();
    symbols
        .iter()
        .map(|s| {
            let key = s.as_ref();
            cache
                .entry(key)
                .or_insert_with(|| Demangler2::demangle(key))
                .clone()
        })
        .collect()
}

// ── Demangle filtering ─────────────────────────────────────────────────────────

/// Utility for filtering collections of mangled symbols by classification.
#[derive(Debug, Clone, Copy, Default)]
pub struct DemangleFilter;

impl DemangleFilter {
    /// Return the subset of `symbols` whose classified language equals `lang`.
    #[must_use]
    pub fn filter_by_language(symbols: &[String], lang: MangleLanguage) -> Vec<String> {
        symbols
            .iter()
            .filter(|s| SymbolClassifier::classify(s) == lang)
            .cloned()
            .collect()
    }

    /// Return the subset of `symbols` that demangle to a known language.
    #[must_use]
    pub fn filter_known_only(symbols: &[String]) -> Vec<String> {
        symbols
            .iter()
            .filter(|s| SymbolClassifier::classify(s) != MangleLanguage::Unknown)
            .cloned()
            .collect()
    }
}

// ── Type normalization ─────────────────────────────────────────────────────────

/// Normalize a demangled type string: collapse runs of whitespace and tighten
/// spacing around pointer / reference sigils.
#[must_use]
pub fn normalize_type(ty: &str) -> String {
    // Collapse all whitespace runs to a single space and trim.
    let mut collapsed = String::with_capacity(ty.len());
    let mut prev_space = false;
    for c in ty.trim().chars() {
        if c.is_whitespace() {
            if !prev_space {
                collapsed.push(' ');
            }
            prev_space = true;
        } else {
            collapsed.push(c);
            prev_space = false;
        }
    }

    // Remove the space before `*` and `&`, and collapse a trailing sigil's
    // surrounding spaces (e.g. `int * const` -> `int* const`, `int * ` -> `int*`).
    let mut out = String::with_capacity(collapsed.len());
    let chars: Vec<char> = collapsed.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == ' ' && i + 1 < chars.len() && (chars[i + 1] == '*' || chars[i + 1] == '&') {
            // Skip the space before a pointer/reference sigil.
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out.trim_end().to_owned()
}
