//! `dex_obfuscation` — DEX/Dalvik obfuscation detection and analysis.
//!
//! Provides:
//! * [`ProGuardPatterns`]   — ProGuard-style rename detection
//! * [`R8Optimizer`]        — R8/D8 optimizer fingerprinting
//! * [`SingleLetterNames`]  — single-letter class/method/field name detector
//! * [`EncryptedStrings`]   — encrypted string detection in DEX
//! * [`ReflectionAbuse`]    — suspicious reflection API usage
//! * [`DexObfuscation`]     — top-level facade

use std::collections::{HashMap, HashSet};
use std::fmt;

// ---------------------------------------------------------------------------
// ProGuard patterns
// ---------------------------------------------------------------------------

/// ProGuard-obfuscated name style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProGuardStyle {
    /// Single lowercase letter (a, b, c, …).
    SingleLower,
    /// Short lowercase sequence (aa, ab, …).
    ShortSequence,
    /// Numeric suffix (a1, b2, …).
    NumericSuffix,
    /// Preserved (keep annotation present).
    Preserved,
}

impl fmt::Display for ProGuardStyle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SingleLower => "single-lower",
            Self::ShortSequence => "short-sequence",
            Self::NumericSuffix => "numeric-suffix",
            Self::Preserved => "preserved",
        };
        f.write_str(s)
    }
}

/// A ProGuard-obfuscated identifier.
#[derive(Debug, Clone)]
pub struct ProGuardName {
    pub name: String,
    pub style: ProGuardStyle,
    pub is_class: bool,
    pub is_method: bool,
    pub is_field: bool,
}

/// `ProGuard` pattern detector.
#[derive(Debug, Clone, Default)]
pub struct ProGuardPatterns {
    /// Detected obfuscated identifiers.
    pub names: Vec<ProGuardName>,
    /// Total identifiers analyzed.
    pub total: usize,
    /// Single-letter count.
    pub single_letter_count: usize,
}

impl ProGuardPatterns {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Classify a name as ProGuard-obfuscated.
    #[must_use]
    pub fn classify(name: &str) -> Option<ProGuardStyle> {
        if name.is_empty() {
            return None;
        }
        // Single lowercase letter
        if name.len() == 1 && name.chars().all(|c| c.is_ascii_lowercase()) {
            return Some(ProGuardStyle::SingleLower);
        }
        // Short sequence (2–3 lowercase letters, may have digits)
        if name.len() <= 3
            && name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_lowercase())
        {
            let alpha: String = name.chars().filter(|c| c.is_alphabetic()).collect();
            let digits: String = name.chars().filter(char::is_ascii_digit).collect();
            if alpha.len() <= 2 && alpha.chars().all(|c| c.is_ascii_lowercase()) {
                if digits.is_empty() {
                    return Some(ProGuardStyle::ShortSequence);
                }
                return Some(ProGuardStyle::NumericSuffix);
            }
        }
        None
    }

    /// Analyze a name.
    pub fn analyze(&mut self, name: &str, is_class: bool, is_method: bool, is_field: bool) {
        self.total += 1;
        if let Some(style) = Self::classify(name) {
            if style == ProGuardStyle::SingleLower {
                self.single_letter_count += 1;
            }
            self.names.push(ProGuardName {
                name: name.to_string(),
                style,
                is_class,
                is_method,
                is_field,
            });
        }
    }

    /// Obfuscation ratio (obfuscated / total).
    #[must_use]
    pub fn ratio(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.names.len() as f64 / self.total as f64
        }
    }

    /// Whether `ProGuard` obfuscation is detected.
    #[must_use]
    pub fn is_proguard(&self) -> bool {
        self.ratio() > 0.25
    }
}

// ---------------------------------------------------------------------------
// R8 Optimizer
// ---------------------------------------------------------------------------

/// R8/D8 optimizer fingerprinting.
///
/// R8 produces specific patterns like:
/// - Empty constructors that call super.<init>
/// - Inlined constants
/// - Specific DEX version in header
#[derive(Debug, Clone, Default)]
pub struct R8Optimizer {
    /// DEX version string if detected.
    pub dex_version: Option<String>,
    /// Number of empty constructors (just super call).
    pub empty_constructors: usize,
    /// Number of inlined constants detected.
    pub inlined_constants: usize,
    /// Whether R8 signature was detected.
    pub r8_detected: bool,
    /// Whether D8 (R8 predecessor) signature was detected.
    pub d8_detected: bool,
}

impl R8Optimizer {
    /// Create a new R8 fingerprinter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record DEX version string.
    pub fn set_dex_version(&mut self, version: String) {
        // R8 typically produces DEX 035, D8 produces 035 or 037
        if version == "035" || version == "037" || version == "039" {
            self.d8_detected = true;
        }
        self.dex_version = Some(version);
    }

    /// Record an empty constructor.
    pub const fn record_empty_constructor(&mut self) {
        self.empty_constructors += 1;
        if self.empty_constructors > 5 {
            self.r8_detected = true;
        }
    }

    /// Record an inlined constant.
    pub const fn record_inlined_constant(&mut self) {
        self.inlined_constants += 1;
    }

    /// Whether this APK was processed by R8 or D8.
    #[must_use]
    pub const fn is_minified(&self) -> bool {
        self.r8_detected || self.d8_detected
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "R8: {}, D8: {}, empty_ctors: {}, inlined: {}",
            self.r8_detected, self.d8_detected, self.empty_constructors, self.inlined_constants
        )
    }
}

// ---------------------------------------------------------------------------
// Single-letter names
// ---------------------------------------------------------------------------

/// Statistics about single-letter identifier usage.
#[derive(Debug, Clone, Default)]
pub struct SingleLetterNames {
    /// Number of single-letter class names.
    pub class_count: usize,
    /// Number of single-letter method names.
    pub method_count: usize,
    /// Number of single-letter field names.
    pub field_count: usize,
    /// Total names analyzed.
    pub total: usize,
    /// Map: letter → count.
    pub letter_freq: HashMap<char, usize>,
}

impl SingleLetterNames {
    /// Create a new analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a name (checking if it's single-letter).
    pub fn record(&mut self, name: &str, is_class: bool, is_method: bool, is_field: bool) {
        self.total += 1;
        if name.len() == 1
            && let Some(c) = name.chars().next() {
                *self.letter_freq.entry(c).or_insert(0) += 1;
                if is_class {
                    self.class_count += 1;
                }
                if is_method {
                    self.method_count += 1;
                }
                if is_field {
                    self.field_count += 1;
                }
            }
    }

    /// Total single-letter names.
    #[must_use]
    pub const fn total_single_letter(&self) -> usize {
        self.class_count + self.method_count + self.field_count
    }

    /// Single-letter ratio.
    #[must_use]
    pub fn ratio(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.total_single_letter() as f64 / self.total as f64
        }
    }

    /// Whether single-letter names dominate.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.ratio() > 0.3
    }

    /// Most common single letter.
    #[must_use]
    pub fn most_common(&self) -> Option<char> {
        self.letter_freq
            .iter()
            .max_by_key(|&(_, &v)| v)
            .map(|(&k, _)| k)
    }
}

// ---------------------------------------------------------------------------
// Encrypted Strings
// ---------------------------------------------------------------------------

/// A suspected encrypted string in a DEX file.
#[derive(Debug, Clone)]
pub struct DexEncryptedString {
    /// Index in the DEX string pool.
    pub string_index: u32,
    /// Original bytes.
    pub raw: Vec<u8>,
    /// Entropy score.
    pub entropy: f64,
    /// Whether it contains non-printable chars (likely encrypted).
    pub has_nonprintable: bool,
}

/// DEX encrypted string detector.
#[derive(Debug, Clone, Default)]
pub struct EncryptedStrings {
    /// Candidates.
    pub candidates: Vec<DexEncryptedString>,
    /// Total strings analyzed.
    pub total: usize,
    /// Number of high-entropy strings.
    pub high_entropy_count: usize,
}

impl EncryptedStrings {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute Shannon entropy.
    #[must_use]
    pub fn entropy(bytes: &[u8]) -> f64 {
        if bytes.is_empty() {
            return 0.0;
        }
        let mut freq = [0u32; 256];
        for &b in bytes {
            freq[b as usize] += 1;
        }
        let len = bytes.len() as f64;
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(c) / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Record a DEX string for analysis.
    pub fn record(&mut self, index: u32, raw: Vec<u8>) {
        self.total += 1;
        let entropy = Self::entropy(&raw);
        let has_nonprintable = raw.iter().any(|&b| !(0x20..=0x7E).contains(&b));
        let is_suspicious = entropy > 5.0 || (has_nonprintable && raw.len() > 4);
        if is_suspicious {
            self.high_entropy_count += 1;
            self.candidates.push(DexEncryptedString {
                string_index: index,
                raw,
                entropy,
                has_nonprintable,
            });
        }
    }

    /// Whether encrypted strings were detected.
    #[must_use]
    pub const fn has_encrypted(&self) -> bool {
        !self.candidates.is_empty()
    }

    /// Fraction of strings that look encrypted.
    #[must_use]
    pub fn encrypted_ratio(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.candidates.len() as f64 / self.total as f64
        }
    }
}

// ---------------------------------------------------------------------------
// Reflection Abuse
// ---------------------------------------------------------------------------

/// A suspicious reflection API call.
#[derive(Debug, Clone)]
pub struct ReflectionCall {
    /// Method reference address (virtual address).
    pub address: u64,
    /// Method name called.
    pub method: String,
    /// Class name involved.
    pub class: String,
    /// Whether it's loading a class dynamically.
    pub is_class_load: bool,
    /// Whether it's invoking a method dynamically.
    pub is_method_invoke: bool,
}

/// Known dangerous reflection methods.
const DANGEROUS_REFLECTION: &[(&str, &str)] = &[
    ("java/lang/Class", "forName"),
    ("java/lang/Class", "getDeclaredMethod"),
    ("java/lang/Class", "getMethod"),
    ("java/lang/reflect/Method", "invoke"),
    ("java/lang/ClassLoader", "loadClass"),
    ("java/lang/ClassLoader", "defineClass"),
    ("dalvik/system/DexClassLoader", "<init>"),
    ("dalvik/system/PathClassLoader", "<init>"),
    ("dalvik/system/DexFile", "loadDex"),
    ("java/lang/Class", "getDeclaredField"),
    ("java/lang/reflect/Field", "get"),
    ("java/lang/reflect/Field", "set"),
];

/// Reflection abuse detector.
#[derive(Debug, Clone, Default)]
pub struct ReflectionAbuse {
    /// Detected suspicious reflection calls.
    pub calls: Vec<ReflectionCall>,
    /// Total reflection calls seen.
    pub total_reflection_calls: usize,
    /// Whether `DexClassLoader` or `PathClassLoader` was constructed.
    pub dynamic_class_loading: bool,
    /// Whether Method.invoke was used.
    pub dynamic_invocation: bool,
}

impl ReflectionAbuse {
    /// Create a new reflection abuse detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether a (class, method) pair is dangerous.
    #[must_use]
    pub fn is_dangerous(class: &str, method: &str) -> bool {
        DANGEROUS_REFLECTION
            .iter()
            .any(|(c, m)| *c == class && *m == method)
    }

    /// Record a method call.
    pub fn record_call(&mut self, address: u64, class: &str, method: &str) {
        if Self::is_dangerous(class, method) {
            let is_class_load =
                method == "forName" || method == "loadClass" || method == "defineClass";
            let is_method_invoke = method == "invoke";
            if is_class_load {
                self.dynamic_class_loading = true;
            }
            if is_method_invoke {
                self.dynamic_invocation = true;
            }
            self.total_reflection_calls += 1;
            self.calls.push(ReflectionCall {
                address,
                method: method.to_string(),
                class: class.to_string(),
                is_class_load,
                is_method_invoke,
            });
        }
    }

    /// Whether dangerous reflection patterns are present.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        self.dynamic_class_loading || self.dynamic_invocation || self.calls.len() > 3
    }

    /// Number of distinct dangerous methods called.
    #[must_use]
    pub fn distinct_dangerous_methods(&self) -> usize {
        let set: HashSet<&str> = self.calls.iter().map(|c| c.method.as_str()).collect();
        set.len()
    }
}

// ---------------------------------------------------------------------------
// Top-level facade
// ---------------------------------------------------------------------------

/// An obfuscation analysis finding.
#[derive(Debug, Clone)]
pub struct DexObfFinding {
    pub message: String,
    pub severity: u8,
}

/// Top-level DEX obfuscation analysis facade.
#[derive(Debug, Clone)]
pub struct DexObfuscation {
    /// `ProGuard` rename patterns.
    pub proguard: ProGuardPatterns,
    /// R8/D8 optimizer fingerprint.
    pub r8: R8Optimizer,
    /// Single-letter name tracker.
    pub single_letter: SingleLetterNames,
    /// Encrypted string detector.
    pub encrypted_strings: EncryptedStrings,
    /// Reflection abuse detector.
    pub reflection: ReflectionAbuse,
    /// Findings.
    pub findings: Vec<DexObfFinding>,
    /// Total classes analyzed.
    pub total_classes: usize,
    /// Total methods analyzed.
    pub total_methods: usize,
}

impl Default for DexObfuscation {
    fn default() -> Self {
        Self::new()
    }
}

impl DexObfuscation {
    /// Create a new DEX obfuscation analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            proguard: ProGuardPatterns::new(),
            r8: R8Optimizer::new(),
            single_letter: SingleLetterNames::new(),
            encrypted_strings: EncryptedStrings::new(),
            reflection: ReflectionAbuse::new(),
            findings: Vec::new(),
            total_classes: 0,
            total_methods: 0,
        }
    }

    /// Analyze a class name.
    pub fn record_class(&mut self, name: &str) {
        self.total_classes += 1;
        self.proguard.analyze(name, true, false, false);
        self.single_letter.record(name, true, false, false);
    }

    /// Analyze a method name.
    pub fn record_method(&mut self, name: &str) {
        self.total_methods += 1;
        self.proguard.analyze(name, false, true, false);
        self.single_letter.record(name, false, true, false);
    }

    /// Record a method call for reflection analysis.
    pub fn record_call(&mut self, address: u64, class: &str, method: &str) {
        self.reflection.record_call(address, class, method);
        if ReflectionAbuse::is_dangerous(class, method) {
            self.findings.push(DexObfFinding {
                message: format!("Dangerous reflection: {class}.{method}"),
                severity: 80,
            });
        }
    }

    /// Record a DEX string.
    pub fn record_string(&mut self, index: u32, raw: Vec<u8>) {
        self.encrypted_strings.record(index, raw);
    }

    /// Whether any obfuscation was detected.
    #[must_use]
    pub fn is_obfuscated(&self) -> bool {
        self.proguard.is_proguard()
            || self.r8.is_minified()
            || self.single_letter.is_suspicious()
            || self.encrypted_strings.has_encrypted()
            || self.reflection.is_suspicious()
    }

    /// Aggregate obfuscation score (0–100).
    #[must_use]
    pub fn score(&self) -> u8 {
        let mut s: u32 = 0;
        if self.proguard.is_proguard() {
            s += 25;
        }
        if self.r8.is_minified() {
            s += 15;
        }
        if self.single_letter.is_suspicious() {
            s += 20;
        }
        if self.encrypted_strings.has_encrypted() {
            s += 25;
        }
        if self.reflection.is_suspicious() {
            s += 15;
        }
        s.min(100) as u8
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── ProGuardPatterns ──────────────────────────────────────────────────────

    #[test]
    fn test_proguard_classify_single_lower() {
        assert_eq!(
            ProGuardPatterns::classify("a"),
            Some(ProGuardStyle::SingleLower)
        );
        assert_eq!(
            ProGuardPatterns::classify("z"),
            Some(ProGuardStyle::SingleLower)
        );
    }

    #[test]
    fn test_proguard_classify_short_sequence() {
        assert_eq!(
            ProGuardPatterns::classify("ab"),
            Some(ProGuardStyle::ShortSequence)
        );
    }

    #[test]
    fn test_proguard_classify_numeric_suffix() {
        assert_eq!(
            ProGuardPatterns::classify("a1"),
            Some(ProGuardStyle::NumericSuffix)
        );
    }

    #[test]
    fn test_proguard_classify_normal_name() {
        assert!(ProGuardPatterns::classify("MainActivity").is_none());
        assert!(ProGuardPatterns::classify("getUserData").is_none());
    }

    #[test]
    fn test_proguard_ratio() {
        let mut pg = ProGuardPatterns::new();
        for _ in 0..4 {
            pg.analyze("a", true, false, false);
        }
        for _ in 0..6 {
            pg.analyze("NormalClass", true, false, false);
        }
        let ratio = pg.ratio();
        assert!((ratio - 0.4).abs() < 1e-9);
    }

    #[test]
    fn test_proguard_is_proguard() {
        let mut pg = ProGuardPatterns::new();
        for _ in 0..4 {
            pg.analyze("a", true, false, false);
        }
        for _ in 0..6 {
            pg.analyze("Normal", true, false, false);
        }
        assert!(pg.is_proguard()); // 4/10 = 0.4 > 0.25
    }

    // ── R8Optimizer ───────────────────────────────────────────────────────────

    #[test]
    fn test_r8_set_dex_version_035() {
        let mut r8 = R8Optimizer::new();
        r8.set_dex_version("035".to_string());
        assert!(r8.d8_detected);
    }

    #[test]
    fn test_r8_unknown_version() {
        let mut r8 = R8Optimizer::new();
        r8.set_dex_version("999".to_string());
        assert!(!r8.d8_detected);
    }

    #[test]
    fn test_r8_empty_constructors() {
        let mut r8 = R8Optimizer::new();
        for _ in 0..6 {
            r8.record_empty_constructor();
        }
        assert!(r8.r8_detected);
    }

    #[test]
    fn test_r8_is_minified() {
        let mut r8 = R8Optimizer::new();
        r8.set_dex_version("037".to_string());
        assert!(r8.is_minified());
    }

    #[test]
    fn test_r8_summary() {
        let r8 = R8Optimizer::new();
        let s = r8.summary();
        assert!(s.contains("R8:"));
    }

    // ── SingleLetterNames ─────────────────────────────────────────────────────

    #[test]
    fn test_single_letter_record() {
        let mut sln = SingleLetterNames::new();
        sln.record("a", true, false, false);
        sln.record("b", false, true, false);
        assert_eq!(sln.class_count, 1);
        assert_eq!(sln.method_count, 1);
    }

    #[test]
    fn test_single_letter_ratio() {
        let mut sln = SingleLetterNames::new();
        for _ in 0..4 {
            sln.record("a", true, false, false);
        }
        for _ in 0..6 {
            sln.record("LongName", true, false, false);
        }
        let ratio = sln.ratio();
        assert!((ratio - 0.4).abs() < 1e-9);
    }

    #[test]
    fn test_single_letter_is_suspicious() {
        let mut sln = SingleLetterNames::new();
        for _ in 0..4 {
            sln.record("a", true, false, false);
        }
        for _ in 0..6 {
            sln.record("Normal", true, false, false);
        }
        assert!(sln.is_suspicious()); // 0.4 > 0.3
    }

    #[test]
    fn test_single_letter_most_common() {
        let mut sln = SingleLetterNames::new();
        sln.record("a", true, false, false);
        sln.record("a", false, true, false);
        sln.record("b", false, false, true);
        assert_eq!(sln.most_common(), Some('a'));
    }

    // ── EncryptedStrings ──────────────────────────────────────────────────────

    #[test]
    fn test_encrypted_entropy() {
        let uniform = vec![0xAAu8; 16];
        assert_eq!(EncryptedStrings::entropy(&uniform), 0.0);
        let mixed: Vec<u8> = (0..=255u8).collect();
        let e = EncryptedStrings::entropy(&mixed);
        assert!((e - 8.0).abs() < 0.001);
    }

    #[test]
    fn test_encrypted_record_high_entropy() {
        let mut es = EncryptedStrings::new();
        let data: Vec<u8> = (0..200).map(|i| i as u8).collect();
        es.record(0, data);
        assert!(es.has_encrypted());
    }

    #[test]
    fn test_encrypted_record_plain() {
        let mut es = EncryptedStrings::new();
        let plain = b"Hello World".to_vec();
        es.record(0, plain);
        assert!(!es.has_encrypted());
    }

    #[test]
    fn test_encrypted_nonprintable() {
        let mut es = EncryptedStrings::new();
        let data = vec![0x01u8, 0x02, 0x03, 0x04, 0x05];
        es.record(0, data);
        assert!(es.has_encrypted()); // has_nonprintable && len > 4
    }

    #[test]
    fn test_encrypted_ratio() {
        let mut es = EncryptedStrings::new();
        let plain = b"Normal string".to_vec();
        let enc: Vec<u8> = (0..200).map(|i| i as u8).collect();
        es.record(0, plain);
        es.record(1, enc);
        let ratio = es.encrypted_ratio();
        assert!(ratio > 0.0);
    }

    // ── ReflectionAbuse ───────────────────────────────────────────────────────

    #[test]
    fn test_reflection_is_dangerous() {
        assert!(ReflectionAbuse::is_dangerous("java/lang/Class", "forName"));
        assert!(ReflectionAbuse::is_dangerous(
            "java/lang/reflect/Method",
            "invoke"
        ));
        assert!(!ReflectionAbuse::is_dangerous(
            "java/lang/String",
            "toString"
        ));
    }

    #[test]
    fn test_reflection_record_class_load() {
        let mut r = ReflectionAbuse::new();
        r.record_call(0x1000, "java/lang/Class", "forName");
        assert!(r.dynamic_class_loading);
        assert_eq!(r.total_reflection_calls, 1);
    }

    #[test]
    fn test_reflection_record_method_invoke() {
        let mut r = ReflectionAbuse::new();
        r.record_call(0x2000, "java/lang/reflect/Method", "invoke");
        assert!(r.dynamic_invocation);
    }

    #[test]
    fn test_reflection_is_suspicious_many_calls() {
        let mut r = ReflectionAbuse::new();
        r.record_call(0x1000, "java/lang/Class", "getDeclaredMethod");
        r.record_call(0x2000, "java/lang/Class", "getMethod");
        r.record_call(0x3000, "java/lang/reflect/Method", "invoke");
        r.record_call(0x4000, "java/lang/ClassLoader", "loadClass");
        assert!(r.is_suspicious());
    }

    #[test]
    fn test_reflection_distinct_methods() {
        let mut r = ReflectionAbuse::new();
        r.record_call(0x1000, "java/lang/Class", "forName");
        r.record_call(0x2000, "java/lang/Class", "forName"); // duplicate
        r.record_call(0x3000, "java/lang/reflect/Method", "invoke");
        assert_eq!(r.distinct_dangerous_methods(), 2);
    }

    // ── DexObfuscation ────────────────────────────────────────────────────────

    #[test]
    fn test_dex_record_class() {
        let mut d = DexObfuscation::new();
        d.record_class("a");
        d.record_class("MainActivity");
        assert_eq!(d.total_classes, 2);
    }

    #[test]
    fn test_dex_record_method() {
        let mut d = DexObfuscation::new();
        d.record_method("b");
        assert_eq!(d.total_methods, 1);
    }

    #[test]
    fn test_dex_record_call_dangerous() {
        let mut d = DexObfuscation::new();
        d.record_call(0x1000, "java/lang/Class", "forName");
        assert_eq!(d.findings.len(), 1);
        assert!(d.reflection.dynamic_class_loading);
    }

    #[test]
    fn test_dex_is_obfuscated_proguard() {
        let mut d = DexObfuscation::new();
        for _ in 0..4 {
            d.record_class("a");
        }
        for _ in 0..6 {
            d.record_class("Normal");
        }
        assert!(d.is_obfuscated());
    }

    #[test]
    fn test_dex_score() {
        let d = DexObfuscation::new();
        assert_eq!(d.score(), 0);
    }

    #[test]
    fn test_dex_score_with_reflection() {
        let mut d = DexObfuscation::new();
        d.record_call(0x1000, "java/lang/Class", "forName");
        d.record_call(0x2000, "java/lang/reflect/Method", "invoke");
        d.record_call(0x3000, "java/lang/ClassLoader", "loadClass");
        d.record_call(0x4000, "dalvik/system/DexClassLoader", "<init>");
        // 4 calls → is_suspicious, so score += 15
        let s = d.score();
        assert!(s >= 15);
    }

    // ── Additional coverage ───────────────────────────────────────────────────

    #[test]
    fn test_proguard_method_names() {
        let mut pg = ProGuardPatterns::new();
        pg.analyze("a", false, true, false);
        pg.analyze("b", false, true, false);
        pg.analyze("onClick", false, true, false);
        assert_eq!(pg.single_letter_count, 2);
    }

    #[test]
    fn test_proguard_field_names() {
        let mut pg = ProGuardPatterns::new();
        pg.analyze("f", false, false, true);
        pg.analyze("g", false, false, true);
        pg.analyze("fieldName", false, false, true);
        assert_eq!(pg.names.iter().filter(|n| n.is_field).count(), 2);
    }

    #[test]
    fn test_r8_inlined_constants() {
        let mut r8 = R8Optimizer::new();
        r8.record_inlined_constant();
        r8.record_inlined_constant();
        assert_eq!(r8.inlined_constants, 2);
    }

    #[test]
    fn test_single_letter_total_single() {
        let mut sln = SingleLetterNames::new();
        sln.record("a", true, false, false);
        sln.record("b", false, true, false);
        sln.record("c", false, false, true);
        assert_eq!(sln.total_single_letter(), 3);
    }

    #[test]
    fn test_reflection_dexclassloader_init() {
        let mut r = ReflectionAbuse::new();
        r.record_call(0x1000, "dalvik/system/DexClassLoader", "<init>");
        // `is_class_load` matches only forName/loadClass/defineClass, so a
        // constructor call is recorded as reflection but does not by itself set
        // the dynamic-class-loading flag.
        assert!(!r.dynamic_class_loading);
        assert_eq!(r.total_reflection_calls, 1);
        assert_eq!(r.calls.len(), 1);
        assert!(!r.calls[0].is_class_load);
    }

    #[test]
    fn test_dex_record_string_high_entropy() {
        let mut d = DexObfuscation::new();
        let enc: Vec<u8> = (0u8..200).collect();
        d.record_string(0, enc);
        assert!(d.encrypted_strings.has_encrypted());
    }

    #[test]
    fn test_dex_is_obfuscated_encrypted_strings() {
        let mut d = DexObfuscation::new();
        let enc: Vec<u8> = (0u8..200).collect();
        d.record_string(0, enc);
        assert!(d.is_obfuscated());
    }
}
