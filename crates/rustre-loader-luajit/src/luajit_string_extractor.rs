/// `luajit_string_extractor.rs` â€” Extract and classify string constants from `LuaJIT` 2.x bytecode.
///
/// Covers:
///   â€¢ KGC string constants (GC object table)
///   â€¢ Source file names embedded in proto headers
///   â€¢ Local variable names from debug info
///   â€¢ Upvalue names from debug info
///   â€¢ Classification into semantic categories
///   â€¢ Obfuscation detection heuristics

use std::collections::HashMap;
use std::fmt;

// â”€â”€â”€ StringCategory â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Semantic category for an extracted string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StringCategory {
    /// Likely a Lua standard library or API call target (e.g. "print", "require").
    ApiCall,
    /// Looks like a file system path (starts with `/`, `./`, `../`, `C:\`, etc.).
    FilePath,
    /// Matches URL patterns (http/https/ftp).
    Url,
    /// Matches error/warning message patterns.
    ErrorMessage,
    /// Likely an obfuscated string (high entropy or mostly non-printable).
    Obfuscated,
    /// Debug: local variable name.
    LocalName,
    /// Debug: upvalue name.
    UpvalueName,
    /// Source file reference (from proto header).
    SourceFile,
    /// Short identifier (â‰¤ 32 chars, all identifier-like chars).
    Identifier,
    /// Everything else.
    Generic,
}

impl fmt::Display for StringCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ApiCall      => "ApiCall",
            Self::FilePath     => "FilePath",
            Self::Url          => "Url",
            Self::ErrorMessage => "ErrorMessage",
            Self::Obfuscated   => "Obfuscated",
            Self::LocalName    => "LocalName",
            Self::UpvalueName  => "UpvalueName",
            Self::SourceFile   => "SourceFile",
            Self::Identifier   => "Identifier",
            Self::Generic      => "Generic",
        };
        write!(f, "{s}")
    }
}

// â”€â”€â”€ LjString â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A single extracted string with context.
#[derive(Debug, Clone)]
pub struct LjString {
    /// The string value (UTF-8 best-effort).
    pub value: String,
    /// Semantic category.
    pub category: StringCategory,
    /// Proto index where this string was found.
    pub proto_idx: usize,
    /// KGC slot index, or None for debug/source strings.
    pub kgc_slot: Option<usize>,
    /// Shannon entropy of the string (bits per byte, 0.0â€“8.0).
    pub entropy: f64,
}

impl LjString {
    /// True if the string is short enough to display inline.
    #[must_use]
    pub const fn is_short(&self) -> bool {
        self.value.len() <= 80
    }

    /// True if this string is suspected to be interesting (not a boring identifier).
    #[must_use]
    pub const fn is_interesting(&self) -> bool {
        !matches!(
            self.category,
            StringCategory::Identifier | StringCategory::LocalName | StringCategory::UpvalueName
        )
    }
}

impl fmt::Display for LjString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let preview = if self.value.len() > 60 {
            format!("{}â€¦", &self.value[..60])
        } else {
            self.value.clone()
        };
        write!(
            f,
            "[proto={} cat={} H={:.2}] {:?}",
            self.proto_idx, self.category, self.entropy, preview
        )
    }
}

// â”€â”€â”€ ObfuscatedString â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A string suspected to be obfuscated, with analysis details.
#[derive(Debug, Clone)]
pub struct ObfuscatedString {
    pub lj_string: LjString,
    /// Fraction of non-printable bytes.
    pub non_printable_ratio: f64,
    /// Number of unique byte values.
    pub unique_bytes: usize,
    /// Heuristic confidence (0.0â€“1.0) that this is intentionally obfuscated.
    pub confidence: f64,
}

impl fmt::Display for ObfuscatedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ObfuscatedString(proto={} len={} H={:.2} conf={:.2})",
            self.lj_string.proto_idx,
            self.lj_string.value.len(),
            self.lj_string.entropy,
            self.confidence
        )
    }
}

// â”€â”€â”€ Entropy helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

// â”€â”€â”€ Lua standard-library API names â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const LUA_API_NAMES: &[&str] = &[
    "print", "require", "pcall", "xpcall", "error", "assert", "tostring", "tonumber",
    "type", "pairs", "ipairs", "next", "select", "unpack", "rawget", "rawset",
    "rawequal", "rawlen", "setmetatable", "getmetatable", "load", "loadfile",
    "loadstring", "dofile", "collectgarbage", "newproxy",
    "io.open", "io.read", "io.write", "io.close",
    "os.time", "os.date", "os.clock", "os.exit", "os.getenv",
    "string.format", "string.find", "string.match", "string.gmatch",
    "string.sub", "string.len", "string.byte", "string.char", "string.rep",
    "string.reverse", "string.upper", "string.lower", "string.gsub",
    "table.insert", "table.remove", "table.sort", "table.concat", "table.unpack",
    "math.floor", "math.ceil", "math.abs", "math.max", "math.min",
    "math.sqrt", "math.random", "math.randomseed",
    "jit.on", "jit.off", "jit.status",
    "ffi.cdef", "ffi.load", "ffi.new", "ffi.cast",
];

fn is_api_name(s: &str) -> bool {
    LUA_API_NAMES.contains(&s)
}

// â”€â”€â”€ Category classifier â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

fn classify_string(value: &str, entropy: f64) -> StringCategory {
    if entropy > 6.5 && value.len() > 12 {
        return StringCategory::Obfuscated;
    }
    if is_api_name(value) {
        return StringCategory::ApiCall;
    }
    let lower = value.to_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ftp://") {
        return StringCategory::Url;
    }
    if value.starts_with('/') || value.starts_with("./") || value.starts_with("../")
        || (value.len() > 2 && &value[1..3] == ":\\")
    {
        return StringCategory::FilePath;
    }
    if lower.contains("error") || lower.contains("failed") || lower.contains("invalid")
        || lower.contains("cannot") || lower.contains("expected")
    {
        return StringCategory::ErrorMessage;
    }
    // Check identifier-like.
    if value.len() <= 64 && value.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return StringCategory::Identifier;
    }
    StringCategory::Generic
}

// â”€â”€â”€ ProtoStringInput â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Input descriptor for a single proto's string data.
pub struct ProtoStringInput {
    pub proto_idx: usize,
    /// KGC strings in table order.
    pub kgc_strings: Vec<String>,
    /// Source file from proto header (may start with `@` for file names).
    pub source_name: Option<String>,
    /// Local variable names from debug info.
    pub local_names: Vec<String>,
    /// Upvalue names from debug info.
    pub upvalue_names: Vec<String>,
}

// â”€â”€â”€ StringExtractor â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Extracts and classifies all strings across multiple protos.
pub struct StringExtractor {
    strings: Vec<LjString>,
}

impl StringExtractor {
    /// Create an empty extractor.
    #[must_use]
    pub const fn new() -> Self {
        Self { strings: Vec::new() }
    }

    /// Ingest one proto's string data.
    pub fn ingest_proto(&mut self, input: &ProtoStringInput) {
        // KGC strings.
        for (slot, s) in input.kgc_strings.iter().enumerate() {
            let bytes = s.as_bytes();
            let entropy = shannon_entropy(bytes);
            let category = classify_string(s, entropy);
            self.strings.push(LjString {
                value: s.clone(),
                category,
                proto_idx: input.proto_idx,
                kgc_slot: Some(slot),
                entropy,
            });
        }

        // Source file name.
        if let Some(ref src) = input.source_name {
            let clean = src.trim_start_matches('@').to_owned();
            self.strings.push(LjString {
                value: clean,
                category: StringCategory::SourceFile,
                proto_idx: input.proto_idx,
                kgc_slot: None,
                entropy: shannon_entropy(src.as_bytes()),
            });
        }

        // Local names.
        for name in &input.local_names {
            self.strings.push(LjString {
                value: name.clone(),
                category: StringCategory::LocalName,
                proto_idx: input.proto_idx,
                kgc_slot: None,
                entropy: shannon_entropy(name.as_bytes()),
            });
        }

        // Upvalue names.
        for name in &input.upvalue_names {
            self.strings.push(LjString {
                value: name.clone(),
                category: StringCategory::UpvalueName,
                proto_idx: input.proto_idx,
                kgc_slot: None,
                entropy: shannon_entropy(name.as_bytes()),
            });
        }
    }

    /// Consume the extractor and produce a `StringReport`.
    #[must_use]
    pub fn into_report(self) -> StringReport {
        StringReport::new(self.strings)
    }

    /// Borrow the collected strings.
    #[must_use]
    pub fn strings(&self) -> &[LjString] {
        &self.strings
    }

    /// Count of strings collected so far.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.strings.len()
    }
}

impl Default for StringExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// â”€â”€â”€ StringReport â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Aggregate report over all extracted strings.
pub struct StringReport {
    strings: Vec<LjString>,
    obfuscated: Vec<ObfuscatedString>,
}

impl StringReport {
    fn new(strings: Vec<LjString>) -> Self {
        let obfuscated = strings
            .iter()
            .filter(|s| s.category == StringCategory::Obfuscated || s.entropy > 5.5)
            .map(|s| {
                let bytes = s.value.as_bytes();
                let non_printable = bytes.iter().filter(|&&b| !(0x20..=0x7e).contains(&b)).count();
                let non_printable_ratio = if bytes.is_empty() {
                    0.0
                } else {
                    non_printable as f64 / bytes.len() as f64
                };
                let unique: std::collections::HashSet<u8> = bytes.iter().copied().collect();
                let unique_bytes = unique.len();
                let confidence = (s.entropy / 8.0).mul_add(0.5, non_printable_ratio * 0.3)
                    + if unique_bytes > 200 { 0.2 } else { 0.0 };
                ObfuscatedString {
                    lj_string: s.clone(),
                    non_printable_ratio,
                    unique_bytes,
                    confidence: confidence.min(1.0),
                }
            })
            .collect();
        Self { strings, obfuscated }
    }

    /// All extracted strings.
    #[must_use]
    pub fn all(&self) -> &[LjString] {
        &self.strings
    }

    /// Strings of a specific category.
    #[must_use]
    pub fn by_category(&self, cat: &StringCategory) -> Vec<&LjString> {
        self.strings.iter().filter(|s| &s.category == cat).collect()
    }

    /// All detected obfuscated strings.
    #[must_use]
    pub fn obfuscated(&self) -> &[ObfuscatedString] {
        &self.obfuscated
    }

    /// Interesting strings only (excludes identifiers and debug names).
    #[must_use]
    pub fn interesting(&self) -> Vec<&LjString> {
        self.strings.iter().filter(|s| s.is_interesting()).collect()
    }

    /// Count per category.
    #[must_use]
    pub fn category_counts(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for s in &self.strings {
            *map.entry(s.category.to_string()).or_insert(0) += 1;
        }
        map
    }

    /// Top-N strings by entropy (descending).
    #[must_use]
    pub fn top_entropy(&self, n: usize) -> Vec<&LjString> {
        let mut sorted: Vec<&LjString> = self.strings.iter().collect();
        sorted.sort_by(|a, b| b.entropy.partial_cmp(&a.entropy).unwrap_or(std::cmp::Ordering::Equal));
        sorted.into_iter().take(n).collect()
    }

    /// Deduplicated string values.
    #[must_use]
    pub fn unique_values(&self) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        self.strings
            .iter()
            .filter(|s| seen.insert(s.value.as_str()))
            .map(|s| s.value.as_str())
            .collect()
    }

    /// Produce a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let counts = self.category_counts();
        let mut s = format!(
            "StringReport: {} total ({} unique), {} obfuscated\n",
            self.strings.len(),
            self.unique_values().len(),
            self.obfuscated.len()
        );
        let mut pairs: Vec<(String, usize)> = counts.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        for (cat, count) in pairs {
            s.push_str(&format!("  {cat:<16} {count}\n"));
        }
        s
    }

    /// Render obfuscated strings with details.
    #[must_use]
    pub fn render_obfuscated(&self) -> String {
        if self.obfuscated.is_empty() {
            return "No obfuscated strings detected.\n".to_owned();
        }
        let mut out = format!("Suspected obfuscated strings ({}):\n", self.obfuscated.len());
        for ob in &self.obfuscated {
            out.push_str(&format!(
                "  {} non_print={:.2} unique_bytes={}\n",
                ob, ob.non_printable_ratio, ob.unique_bytes
            ));
        }
        out
    }
}

impl fmt::Display for StringReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

impl fmt::Debug for StringReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StringReport")
            .field("total", &self.strings.len())
            .field("obfuscated", &self.obfuscated.len())
            .finish()
    }
}

// â”€â”€â”€ tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    fn make_input(idx: usize, kgc: &[&str]) -> ProtoStringInput {
        ProtoStringInput {
            proto_idx: idx,
            kgc_strings: kgc.iter().map(std::string::ToString::to_string).collect(),
            source_name: Some("@test.lua".to_string()),
            local_names: vec!["a".to_string(), "b".to_string()],
            upvalue_names: vec!["_ENV".to_string()],
        }
    }

    #[test]
    fn api_call_classification() {
        assert_eq!(classify_string("print", 0.0), StringCategory::ApiCall);
        assert_eq!(classify_string("require", 0.0), StringCategory::ApiCall);
        assert_eq!(classify_string("string.format", 0.0), StringCategory::ApiCall);
    }

    #[test]
    fn url_classification() {
        assert_eq!(classify_string("https://example.com/api", 0.0), StringCategory::Url);
        assert_eq!(classify_string("http://evil.com", 0.0), StringCategory::Url);
    }

    #[test]
    fn file_path_classification() {
        assert_eq!(classify_string("/etc/passwd", 0.0), StringCategory::FilePath);
        assert_eq!(classify_string("./config.lua", 0.0), StringCategory::FilePath);
    }

    #[test]
    fn error_message_classification() {
        assert_eq!(classify_string("invalid argument", 0.0), StringCategory::ErrorMessage);
        assert_eq!(classify_string("operation failed", 0.0), StringCategory::ErrorMessage);
    }

    #[test]
    fn obfuscated_classification() {
        // Construct a high-entropy string.
        let s: String = (0u8..=127).map(|b| b as char).collect();
        let entropy = shannon_entropy(s.as_bytes());
        let cat = classify_string(&s, entropy);
        assert_eq!(cat, StringCategory::Obfuscated);
    }

    #[test]
    fn extractor_ingest_and_categories() {
        let input = make_input(0, &["print", "https://example.com", "/tmp/x", "abcDEF"]);
        let mut ext = StringExtractor::new();
        ext.ingest_proto(&input);
        let report = ext.into_report();

        let api = report.by_category(&StringCategory::ApiCall);
        assert!(!api.is_empty());

        let urls = report.by_category(&StringCategory::Url);
        assert!(!urls.is_empty());

        let paths = report.by_category(&StringCategory::FilePath);
        assert!(!paths.is_empty());

        let src = report.by_category(&StringCategory::SourceFile);
        assert!(!src.is_empty());
        assert_eq!(src[0].value, "test.lua"); // '@' stripped
    }

    #[test]
    fn debug_names() {
        let input = make_input(0, &[]);
        let mut ext = StringExtractor::new();
        ext.ingest_proto(&input);
        let report = ext.into_report();

        let locals = report.by_category(&StringCategory::LocalName);
        assert_eq!(locals.len(), 2);

        let upvalues = report.by_category(&StringCategory::UpvalueName);
        assert_eq!(upvalues.len(), 1);
        assert_eq!(upvalues[0].value, "_ENV");
    }

    #[test]
    fn unique_values_deduplicated() {
        let mut input = make_input(0, &["print", "print", "require"]);
        input.source_name = None;
        input.local_names = vec![];
        input.upvalue_names = vec![];
        let mut ext = StringExtractor::new();
        ext.ingest_proto(&input);
        let report = ext.into_report();
        let unique = report.unique_values();
        assert_eq!(unique.len(), 2); // "print" deduplicated
    }

    #[test]
    fn top_entropy_ordering() {
        let high: String = (0u8..128).map(|b| b as char).collect();
        let mut input = make_input(0, &[&high, "hello"]);
        input.local_names = vec![];
        input.upvalue_names = vec![];
        input.source_name = None;
        let mut ext = StringExtractor::new();
        ext.ingest_proto(&input);
        let report = ext.into_report();
        let top = report.top_entropy(1);
        assert!(!top.is_empty());
        assert!(top[0].entropy > 5.0);
    }

    #[test]
    fn summary_format() {
        let input = make_input(0, &["print", "require"]);
        let mut ext = StringExtractor::new();
        ext.ingest_proto(&input);
        let report = ext.into_report();
        let s = report.summary();
        assert!(s.contains("StringReport:"));
        assert!(s.contains("ApiCall"));
    }

    #[test]
    fn shannon_entropy_uniform() {
        let bytes: Vec<u8> = (0..=255).collect();
        let h = shannon_entropy(&bytes);
        assert!((h - 8.0).abs() < 0.01, "expected ~8.0 bits, got {h}");
    }

    #[test]
    fn shannon_entropy_constant() {
        let bytes = vec![0u8; 100];
        assert_eq!(shannon_entropy(&bytes), 0.0);
    }

    #[test]
    fn obfuscated_report() {
        let high: String = (0u8..128).map(|b| b as char).collect();
        let mut input = make_input(0, &[&high]);
        input.local_names = vec![];
        input.upvalue_names = vec![];
        input.source_name = None;
        let mut ext = StringExtractor::new();
        ext.ingest_proto(&input);
        let report = ext.into_report();
        let rendered = report.render_obfuscated();
        assert!(rendered.contains("ObfuscatedString") || rendered.contains("Suspected"));
    }

    #[test]
    fn category_counts_non_zero() {
        let input = make_input(1, &["print", "io.open", "/var/log"]);
        let mut ext = StringExtractor::new();
        ext.ingest_proto(&input);
        let report = ext.into_report();
        let cc = report.category_counts();
        assert!(cc.values().sum::<usize>() > 0);
    }
}
