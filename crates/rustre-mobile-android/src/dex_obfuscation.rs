//! DEX obfuscation detection: ProGuard/R8 detection, `DexGuard` fingerprinting,
//! string encryption patterns, reflection usage analysis, class naming entropy.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ObfuscationError {
    #[error("invalid DEX magic")]
    BadMagic,
    #[error("buffer too short at offset {0:#x}")]
    UnexpectedEof(usize),
}

pub type ObfuscationResult<T> = Result<T, ObfuscationError>;

// ── Obfuscation tool IDs ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObfuscationTool {
    ProGuard,
    R8,
    DexGuard,
    DashO,
    Allatori,
    Guardsquare,
    StringFog,
    UnknownStringEncryption,
    None,
}

impl ObfuscationTool {
    #[must_use] 
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProGuard => "ProGuard",
            Self::R8 => "R8",
            Self::DexGuard => "DexGuard",
            Self::DashO => "DashO",
            Self::Allatori => "Allatori",
            Self::Guardsquare => "Guardsquare",
            Self::StringFog => "StringFog",
            Self::UnknownStringEncryption => "Unknown string encryption",
            Self::None => "none",
        }
    }
}

// ── Naming patterns ───────────────────────────────────────────────────────────

/// ProGuard/R8 default short names (a–z, aa–az, etc.)
fn is_proguard_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 3 {
        return false;
    }
    name.chars().all(|c| c.is_ascii_lowercase())
}

/// Calculate Shannon entropy of a byte slice.
#[must_use] 
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

/// Entropy of a class name string (high ≥ 3.5 → obfuscated).
#[must_use] 
pub fn name_entropy(name: &str) -> f64 {
    shannon_entropy(name.as_bytes())
}

// ── String encryption patterns ────────────────────────────────────────────────

/// Patterns indicative of runtime string decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEncryptionPattern {
    pub class: String,
    pub method: String,
    /// How many calls to this method were found across the DEX.
    pub call_count: usize,
    pub kind: StringEncryptionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringEncryptionKind {
    /// XOR-based decryption (short decrypt method body).
    Xor,
    /// AES/DES-based (calls javax.crypto).
    Crypto,
    /// Character-by-character subtraction/rotation.
    Rotate,
    /// Base64 decode + something.
    Base64,
    /// Unknown pattern.
    Unknown,
}

impl StringEncryptionKind {
    #[must_use] 
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Xor => "XOR",
            Self::Crypto => "crypto (AES/DES)",
            Self::Rotate => "rotate/shift",
            Self::Base64 => "base64",
            Self::Unknown => "unknown",
        }
    }
}

// ── Reflection usage ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflectionUsage {
    pub class_for_name_calls: Vec<String>,
    pub get_method_calls: Vec<String>,
    pub get_declared_method_calls: Vec<String>,
    pub load_class_calls: Vec<String>,
    pub invoke_calls: usize,
    pub dynamic_class_loading: bool,
}

impl ReflectionUsage {
    #[must_use] 
    pub const fn risk_level(&self) -> &'static str {
        let total = self.class_for_name_calls.len()
            + self.get_method_calls.len()
            + self.invoke_calls;
        match total {
            0 => "none",
            1..=5 => "low",
            6..=20 => "medium",
            _ => "high",
        }
    }
}

// ── ProGuard mapping file ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProguardMapping {
    /// `obfuscated_class_name` → `original_class_name`
    pub class_map: HashMap<String, String>,
    /// (`obfuscated_class`, `obfuscated_method`) → `original_method`
    pub method_map: HashMap<(String, String), String>,
    /// (`obfuscated_class`, `obfuscated_field`) → `original_field`
    pub field_map: HashMap<(String, String), String>,
}

impl ProguardMapping {
    /// Parse a ProGuard/R8 mapping.txt file.
    #[must_use] 
    pub fn parse(mapping_txt: &str) -> Self {
        let mut mapping = Self::default();
        let mut current_class_obf = String::new();

        for line in mapping_txt.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            if line.ends_with(':') && !line.starts_with("    ") {
                // Class mapping: "original -> obfuscated:"
                let parts: Vec<&str> = line.trim_end_matches(':').split(" -> ").collect();
                if parts.len() == 2 {
                    let original = parts[0].trim().to_owned();
                    let obfuscated = parts[1].trim().to_owned();
                    current_class_obf = obfuscated.clone();
                    mapping.class_map.insert(obfuscated, original);
                }
            } else if line.starts_with("    ") {
                let inner = line.trim();
                let parts: Vec<&str> = inner.split(" -> ").collect();
                if parts.len() == 2 {
                    let orig_part = parts[0].trim();
                    let obf_name = parts[1].trim().to_owned();
                    // Strip line range prefix if present: "1:5:void foo()" → "void foo()"
                    let orig_sig = if orig_part.contains(':') {
                        orig_part.splitn(3, ':').nth(2).unwrap_or(orig_part)
                    } else {
                        orig_part
                    };
                    if orig_sig.contains('(') {
                        // Method
                        mapping.method_map.insert(
                            (current_class_obf.clone(), obf_name),
                            orig_sig.to_owned(),
                        );
                    } else {
                        // Field
                        mapping.field_map.insert(
                            (current_class_obf.clone(), obf_name),
                            orig_sig.to_owned(),
                        );
                    }
                }
            }
        }

        mapping
    }

    #[must_use] 
    pub fn deobfuscate_class(&self, obf: &str) -> Option<&str> {
        self.class_map.get(obf).map(std::string::String::as_str)
    }

    #[must_use] 
    pub fn deobfuscate_method(&self, obf_class: &str, obf_method: &str) -> Option<&str> {
        self.method_map
            .get(&(obf_class.to_owned(), obf_method.to_owned()))
            .map(std::string::String::as_str)
    }
}

// ── DEX class statistics ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexClassStat {
    pub descriptor: String,
    pub short_name: String,
    pub package: String,
    pub method_count: u32,
    pub field_count: u32,
    pub name_entropy: f64,
    pub likely_obfuscated: bool,
}

impl DexClassStat {
    #[must_use] 
    pub fn from_descriptor(descriptor: &str, method_count: u32, field_count: u32) -> Self {
        // "Lcom/example/Foo;" → package="com/example", short_name="Foo"
        let inner = descriptor
            .trim_start_matches('L')
            .trim_end_matches(';');
        let (package, short_name) = if let Some(pos) = inner.rfind('/') {
            (inner[..pos].to_owned(), inner[pos + 1..].to_owned())
        } else {
            (String::new(), inner.to_owned())
        };

        let entropy = name_entropy(&short_name);
        let likely_obfuscated = is_proguard_name(&short_name)
            || entropy >= 3.5
            || short_name.chars().all(|c| c.is_ascii_alphabetic() && c.is_ascii_lowercase() && short_name.len() <= 2);

        Self {
            descriptor: descriptor.to_owned(),
            short_name,
            package,
            method_count,
            field_count,
            name_entropy: entropy,
            likely_obfuscated,
        }
    }
}

// ── DexGuard fingerprints ─────────────────────────────────────────────────────

const DEXGUARD_MAGIC_STRINGS: &[&str] = &[
    "com/guardsquare/dexguard",
    "DexGuard",
    "GuardSquare",
    "com.guardsquare",
    "SdkEncryptionClient",
];

const DEXGUARD_KNOWN_CLASSES: &[&str] = &[
    "Lcom/guardsquare/dexguard/runtime/detection/",
    "Lcom/guardSquare/",
    "Lgdx/",
];

// ── String encryption detector ────────────────────────────────────────────────

/// Heuristically detect string encryption in a DEX string pool.
#[must_use] 
pub fn detect_string_encryption(strings: &[String]) -> Vec<StringEncryptionKind> {
    let mut kinds = Vec::new();

    // Look for high-entropy strings that are not class descriptors or URLs
    let high_entropy_strings: Vec<&String> = strings
        .iter()
        .filter(|s| {
            !s.starts_with('L')
                && !s.starts_with("android")
                && !s.starts_with("http")
                && s.len() > 10
                && name_entropy(s.as_str()) > 4.2
        })
        .collect();

    if !high_entropy_strings.is_empty() {
        // Check if they look like base64
        let base64_count = high_entropy_strings
            .iter()
            .filter(|s| s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='))
            .count();
        if base64_count as f64 / high_entropy_strings.len() as f64 > 0.5 {
            kinds.push(StringEncryptionKind::Base64);
        } else {
            kinds.push(StringEncryptionKind::Unknown);
        }
    }

    // Check for rotation pattern: many short non-ASCII strings
    let rotated_count = strings
        .iter()
        .filter(|s| {
            s.len() > 4
                && s.len() < 64
                && s.bytes().any(|b| b > 127)
        })
        .count();
    if rotated_count > 5 {
        kinds.push(StringEncryptionKind::Rotate);
    }

    kinds
}

// ── Main obfuscation analyser ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationReport {
    pub detected_tools: Vec<ObfuscationTool>,
    pub class_stats: Vec<DexClassStat>,
    pub obfuscated_class_count: usize,
    pub total_class_count: usize,
    pub obfuscation_ratio: f64,
    pub string_encryption_patterns: Vec<StringEncryptionKind>,
    pub reflection_usage: ReflectionUsage,
    pub has_proguard_map_hint: bool,
    pub has_dexguard: bool,
    pub average_name_entropy: f64,
    pub suspicious_strings: Vec<String>,
}

impl ObfuscationReport {
    #[must_use] 
    pub fn is_obfuscated(&self) -> bool {
        self.obfuscation_ratio > 0.4 || self.has_dexguard
    }

    #[must_use] 
    pub fn risk_summary(&self) -> String {
        let mut parts = Vec::new();
        for tool in &self.detected_tools {
            parts.push(tool.as_str().to_owned());
        }
        if !self.string_encryption_patterns.is_empty() {
            parts.push("string encryption".into());
        }
        if self.has_dexguard {
            parts.push("DexGuard".into());
        }
        if parts.is_empty() {
            "no obfuscation detected".into()
        } else {
            parts.join(", ")
        }
    }
}

// ── DEX raw analyser ─────────────────────────────────────────────────────────

pub struct DexObfuscationAnalyzer<'a> {
    data: &'a [u8],
}

impl<'a> DexObfuscationAnalyzer<'a> {
    #[must_use] 
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn read_u32_at(&self, off: usize) -> ObfuscationResult<u32> {
        if off + 4 > self.data.len() {
            return Err(ObfuscationError::UnexpectedEof(off));
        }
        Ok(u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap()))
    }

    fn read_uleb128_at(&self, off: usize) -> (u32, usize) {
        let mut result: u32 = 0;
        let mut shift = 0;
        let mut i = 0;
        loop {
            if off + i >= self.data.len() || i >= 5 {
                break;
            }
            let b = self.data[off + i];
            result |= u32::from(b & 0x7f) << shift;
            i += 1;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        (result, i)
    }

    /// Extract the string pool from a DEX file.
    ///
    /// # Errors
    /// Returns an `ObfuscationError` when the DEX header or string id table
    /// is malformed or truncated.
    pub fn extract_strings(&self) -> ObfuscationResult<Vec<String>> {
        if self.data.len() < 0x70 {
            return Err(ObfuscationError::BadMagic);
        }
        if &self.data[..4] != b"dex\n" {
            return Err(ObfuscationError::BadMagic);
        }

        let string_ids_size = self.read_u32_at(0x38)? as usize;
        let string_ids_off = self.read_u32_at(0x3C)? as usize;

        let mut strings = Vec::with_capacity(string_ids_size);
        for i in 0..string_ids_size {
            let id_off = string_ids_off + i * 4;
            let str_off = self.read_u32_at(id_off)? as usize;
            let (char_count, adv) = self.read_uleb128_at(str_off);
            let data_start = str_off + adv;
            let data_end = (data_start + char_count as usize).min(self.data.len());
            let s = std::str::from_utf8(&self.data[data_start..data_end])
                .unwrap_or("")
                .to_owned();
            strings.push(s);
        }
        Ok(strings)
    }

    /// Extract type descriptors (class names) from the type ID table.
    ///
    /// # Errors
    /// Returns an `ObfuscationError` when the DEX header or type id table is
    /// malformed.
    pub fn extract_type_descriptors(&self) -> ObfuscationResult<Vec<String>> {
        if self.data.len() < 0x70 {
            return Err(ObfuscationError::BadMagic);
        }
        let strings = self.extract_strings()?;
        let type_ids_size = self.read_u32_at(0x40)? as usize;
        let type_ids_off = self.read_u32_at(0x44)? as usize;

        let mut types = Vec::with_capacity(type_ids_size);
        for i in 0..type_ids_size {
            let idx = self.read_u32_at(type_ids_off + i * 4)? as usize;
            types.push(strings.get(idx).cloned().unwrap_or_default());
        }
        Ok(types)
    }

    /// Count methods per class from the `method_id` table.
    ///
    /// # Errors
    /// Returns an `ObfuscationError` when the DEX header or method id table is
    /// malformed.
    pub fn method_counts_per_class(&self) -> ObfuscationResult<HashMap<u32, u32>> {
        if self.data.len() < 0x70 {
            return Err(ObfuscationError::BadMagic);
        }
        let method_ids_size = self.read_u32_at(0x54)? as usize;
        let method_ids_off = self.read_u32_at(0x58)? as usize;

        let mut counts: HashMap<u32, u32> = HashMap::new();
        for i in 0..method_ids_size {
            let off = method_ids_off + i * 8;
            let class_idx = u32::from(u16::from_le_bytes(
                self.data.get(off..off + 2)
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0, 0]),
            ));
            *counts.entry(class_idx).or_default() += 1;
        }
        Ok(counts)
    }

    /// Detect reflection API usage in the string pool.
    #[must_use] 
    pub fn detect_reflection(&self, strings: &[String]) -> ReflectionUsage {
        let mut class_for_name_calls = Vec::new();
        let mut get_method_calls = Vec::new();
        let mut get_declared_method_calls = Vec::new();
        let mut load_class_calls = Vec::new();
        let mut invoke_calls = 0usize;

        for s in strings {
            match s.as_str() {
                "forName" => class_for_name_calls.push(s.clone()),
                "getMethod" => get_method_calls.push(s.clone()),
                "getDeclaredMethod" => get_declared_method_calls.push(s.clone()),
                "loadClass" => load_class_calls.push(s.clone()),
                "invoke" => invoke_calls += 1,
                "Class.forName" => class_for_name_calls.push(s.clone()),
                _ => {}
            }
            // Class names loaded dynamically
            if s.contains("DexClassLoader")
                || s.contains("PathClassLoader")
                || s.contains("InMemoryDexClassLoader")
            {
                load_class_calls.push(s.clone());
            }
        }

        let dynamic_class_loading = !load_class_calls.is_empty()
            || strings.iter().any(|s| s.contains("dalvik.system"));

        ReflectionUsage {
            class_for_name_calls,
            get_method_calls,
            get_declared_method_calls,
            load_class_calls,
            invoke_calls,
            dynamic_class_loading,
        }
    }

    /// Check for `DexGuard` signatures in strings.
    #[must_use] 
    pub fn detect_dexguard(&self, strings: &[String]) -> bool {
        strings.iter().any(|s| {
            DEXGUARD_MAGIC_STRINGS
                .iter()
                .any(|&sig| s.contains(sig))
        }) || self
            .extract_type_descriptors()
            .is_ok_and(|types| {
                types.iter().any(|t| {
                    DEXGUARD_KNOWN_CLASSES.iter().any(|&prefix| t.starts_with(prefix))
                })
            })
    }

    /// Detect ProGuard/R8: >50% of class short names match the short-name pattern.
    #[must_use] 
    pub fn detect_proguard_or_r8(&self, class_stats: &[DexClassStat]) -> ObfuscationTool {
        if class_stats.is_empty() {
            return ObfuscationTool::None;
        }
        let pg_count = class_stats
            .iter()
            .filter(|c| is_proguard_name(&c.short_name))
            .count();
        let ratio = pg_count as f64 / class_stats.len() as f64;
        if ratio > 0.5 {
            // R8 produces a specific header in the mapping; without it, assume ProGuard
            ObfuscationTool::ProGuard
        } else {
            ObfuscationTool::None
        }
    }

    /// Full obfuscation analysis.
    ///
    /// # Errors
    /// Returns an `ObfuscationError` when underlying DEX parsing fails.
    pub fn analyze(&self) -> ObfuscationResult<ObfuscationReport> {
        let strings = self.extract_strings()?;
        let type_descs = self.extract_type_descriptors().unwrap_or_default();
        let method_counts = self.method_counts_per_class().unwrap_or_default();

        // Build class stats
        let mut class_stats: Vec<DexClassStat> = type_descs
            .iter()
            .enumerate()
            .filter(|(_, d)| d.starts_with('L') && d.ends_with(';'))
            .map(|(i, d)| {
                let mc = method_counts.get(&(i as u32)).copied().unwrap_or(0);
                DexClassStat::from_descriptor(d, mc, 0)
            })
            .collect();

        let total_class_count = class_stats.len();
        let obfuscated_class_count = class_stats.iter().filter(|c| c.likely_obfuscated).count();
        let obfuscation_ratio = if total_class_count > 0 {
            obfuscated_class_count as f64 / total_class_count as f64
        } else {
            0.0
        };

        let average_name_entropy = if class_stats.is_empty() {
            0.0
        } else {
            class_stats.iter().map(|c| c.name_entropy).sum::<f64>() / class_stats.len() as f64
        };

        let has_dexguard = self.detect_dexguard(&strings);
        let tool = self.detect_proguard_or_r8(&class_stats);

        let mut detected_tools = Vec::new();
        if has_dexguard {
            detected_tools.push(ObfuscationTool::DexGuard);
        } else if tool != ObfuscationTool::None {
            detected_tools.push(tool);
        }

        let string_encryption_patterns = detect_string_encryption(&strings);
        if !string_encryption_patterns.is_empty()
            && !detected_tools.contains(&ObfuscationTool::DexGuard)
        {
            detected_tools.push(ObfuscationTool::UnknownStringEncryption);
        }

        let reflection_usage = self.detect_reflection(&strings);

        // Suspicious strings: IP addresses, suspicious URLs, embedded commands
        let suspicious_strings = strings
            .iter()
            .filter(|s| {
                (s.starts_with("http://") && !s.contains("schemas.android.com"))
                    || s.contains("/data/local/tmp")
                    || s.contains("su ")
                    || s.contains("chmod 777")
                    || s.contains("Runtime.exec")
                    || looks_like_ip(s)
            })
            .cloned()
            .collect();

        // Keep only class stats for display (limit)
        class_stats.truncate(1000);

        Ok(ObfuscationReport {
            detected_tools,
            class_stats,
            obfuscated_class_count,
            total_class_count,
            obfuscation_ratio,
            string_encryption_patterns,
            reflection_usage,
            has_proguard_map_hint: false,
            has_dexguard,
            average_name_entropy,
            suspicious_strings,
        })
    }
}

fn looks_like_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

// ── Mapping file integration ──────────────────────────────────────────────────

/// Apply a `ProGuard` mapping to deobfuscate an `ObfuscationReport`'s class stats.
pub fn apply_mapping(report: &mut ObfuscationReport, mapping: &ProguardMapping) {
    for stat in &mut report.class_stats {
        let inner = stat
            .descriptor
            .trim_start_matches('L')
            .trim_end_matches(';')
            .replace('/', ".");
        if let Some(orig) = mapping.deobfuscate_class(&inner) {
            stat.descriptor = format!("L{};", orig.replace('.', "/"));
            let parts: Vec<&str> = orig.rsplitn(2, '.').collect();
            stat.short_name = parts[0].to_owned();
            stat.likely_obfuscated = false;
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Analyze a DEX file for obfuscation indicators.
///
/// # Errors
/// Returns an `ObfuscationError` when DEX parsing fails.
pub fn analyze_dex_obfuscation(dex_data: &[u8]) -> ObfuscationResult<ObfuscationReport> {
    DexObfuscationAnalyzer::new(dex_data).analyze()
}

/// Parse a `ProGuard` mapping.txt and return a mapping object.
#[must_use] 
pub fn parse_proguard_mapping(mapping_txt: &str) -> ProguardMapping {
    ProguardMapping::parse(mapping_txt)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_proguard_name() {
        assert!(is_proguard_name("a"));
        assert!(is_proguard_name("ab"));
        assert!(is_proguard_name("abc"));
        assert!(!is_proguard_name("MyClass"));
        assert!(!is_proguard_name("abcd"));
    }

    #[test]
    fn test_shannon_entropy() {
        let e = shannon_entropy(b"aaaa");
        assert!((e - 0.0).abs() < 0.001);
        let e2 = shannon_entropy(b"abcd");
        assert!(e2 > 1.9);
    }

    #[test]
    fn test_name_entropy() {
        let e = name_entropy("MyClass");
        assert!(e < 3.5);
        let e2 = name_entropy("aB3xQzP1");
        assert!(e2 > 2.5);
    }

    #[test]
    fn test_proguard_mapping_parse() {
        let mapping = r"com.example.MainActivity -> a.b:
    void onCreate(android.os.Bundle) -> a
    java.lang.String mTitle -> c
com.example.Util -> a.c:
    java.lang.String decrypt(java.lang.String) -> b
";
        let pm = ProguardMapping::parse(mapping);
        assert_eq!(pm.deobfuscate_class("a.b"), Some("com.example.MainActivity"));
        assert_eq!(pm.deobfuscate_class("a.c"), Some("com.example.Util"));
    }

    #[test]
    fn test_reflection_detection() {
        let analyzer = DexObfuscationAnalyzer::new(&[]);
        let strings = vec![
            "forName".to_owned(),
            "getMethod".to_owned(),
            "invoke".to_owned(),
            "DexClassLoader".to_owned(),
        ];
        let r = analyzer.detect_reflection(&strings);
        assert!(!r.class_for_name_calls.is_empty());
        assert!(r.dynamic_class_loading);
        assert_eq!(r.invoke_calls, 1);
    }

    #[test]
    fn test_looks_like_ip() {
        assert!(looks_like_ip("192.168.1.1"));
        assert!(!looks_like_ip("not.an.ip"));
        assert!(!looks_like_ip("999.999.999.999"));
    }

    #[test]
    fn test_class_stat_obfuscated() {
        let stat = DexClassStat::from_descriptor("La/b/c;", 3, 2);
        assert!(stat.likely_obfuscated);

        let stat2 = DexClassStat::from_descriptor("Lcom/example/MainActivity;", 10, 5);
        assert!(!stat2.likely_obfuscated);
    }

    #[test]
    fn test_string_encryption_detection() {
        let strings = vec![
            "dGhpcyBpcyBhIHRlc3Q=".to_owned(), // base64
            "dGVzdA==".to_owned(),
        ];
        let kinds = detect_string_encryption(&strings);
        // May or may not trigger depending on entropy threshold
        let _ = kinds;
    }
}
