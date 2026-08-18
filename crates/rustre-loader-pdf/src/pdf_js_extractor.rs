//! JavaScript extraction and analysis for PDF files.
//!
//! Finds all `/JS` and `/JavaScript` entries, extracts code, detects obfuscation
//! patterns, tracks heap spray patterns, identifies shellcode-like byte sequences,
//! and computes a per-script risk score.

use std::fmt;

use serde::{Deserialize, Serialize};

// ─── ObfuscationKind ─────────────────────────────────────────────────────────

/// A type of JavaScript obfuscation pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObfuscationKind {
    /// String split and join: `"a"+"b"+"c"`.
    StringConcatenation,
    /// `eval()` call wrapping another expression.
    EvalWrapper,
    /// Hex-encoded strings: `"\x41\x42"`.
    HexEncoding,
    /// Unicode escape sequences: `"A"`.
    UnicodeEscape,
    /// Reversed string: `"esrever".split("").reverse().join("")`.
    ReversedString,
    /// `unescape()` with percent-encoded payload.
    UnescapeEncoding,
    /// `String.fromCharCode(...)` array.
    CharCodeArray,
    /// Base64-encoded blobs.
    Base64Blob,
    /// Obfuscated variable names (single-char or random-looking).
    ObfuscatedNames,
    /// `Function(...)()` constructor call.
    FunctionConstructor,
    /// Packed / compressed payload (e.g. `JsPacker`).
    PackedPayload,
}

impl fmt::Display for ObfuscationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::StringConcatenation => "string_concat",
            Self::EvalWrapper => "eval_wrapper",
            Self::HexEncoding => "hex_encoding",
            Self::UnicodeEscape => "unicode_escape",
            Self::ReversedString => "reversed_string",
            Self::UnescapeEncoding => "unescape_encoding",
            Self::CharCodeArray => "charcode_array",
            Self::Base64Blob => "base64_blob",
            Self::ObfuscatedNames => "obfuscated_names",
            Self::FunctionConstructor => "function_constructor",
            Self::PackedPayload => "packed_payload",
        };
        write!(f, "{s}")
    }
}

// ─── ObfuscationPattern ───────────────────────────────────────────────────────

/// A detected obfuscation pattern within a JavaScript snippet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationPattern {
    /// The kind of obfuscation.
    pub kind: ObfuscationKind,
    /// Byte offset within the script where the pattern was found.
    pub offset: usize,
    /// Short excerpt of the matching region (first 80 chars).
    pub excerpt: String,
    /// Severity contribution [0, 10].
    pub severity: u32,
}

impl ObfuscationPattern {
    /// Create a new pattern.
    #[must_use]
    pub fn new(kind: ObfuscationKind, offset: usize, excerpt: impl Into<String>, severity: u32) -> Self {
        Self {
            kind,
            offset,
            excerpt: excerpt.into(),
            severity,
        }
    }
}

// ─── HeapSprayDetect ─────────────────────────────────────────────────────────

/// Result of heap-spray analysis within a JavaScript snippet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapSprayDetect {
    /// Whether a heap spray was detected.
    pub detected: bool,
    /// The NOP sled or fill pattern found (first 16 bytes as hex).
    pub nop_pattern: Option<String>,
    /// Estimated allocation size in bytes.
    pub alloc_size: Option<usize>,
    /// The pattern used for filling (e.g. `unescape("邐邐")`).
    pub fill_expression: Option<String>,
    /// Confidence [0.0, 1.0].
    pub confidence: f32,
}

impl HeapSprayDetect {
    /// Create a "not detected" result.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            detected: false,
            nop_pattern: None,
            alloc_size: None,
            fill_expression: None,
            confidence: 0.0,
        }
    }

    /// Create a positive detection.
    #[must_use]
    pub const fn positive(
        nop_pattern: Option<String>,
        alloc_size: Option<usize>,
        fill_expression: Option<String>,
        confidence: f32,
    ) -> Self {
        Self {
            detected: true,
            nop_pattern,
            alloc_size,
            fill_expression,
            confidence,
        }
    }
}

// ─── ShellcodeHint ────────────────────────────────────────────────────────────

/// A shellcode-like byte sequence found within decoded JavaScript data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellcodeHint {
    /// Byte offset within the decoded script data.
    pub offset: usize,
    /// Length of the suspicious sequence.
    pub length: usize,
    /// First bytes of the sequence as hex.
    pub bytes_hex: String,
    /// Heuristic that triggered this detection.
    pub heuristic: String,
    /// Confidence [0.0, 1.0].
    pub confidence: f32,
}

impl ShellcodeHint {
    /// Create a new shellcode hint.
    #[must_use]
    pub fn new(
        offset: usize,
        length: usize,
        bytes_hex: impl Into<String>,
        heuristic: impl Into<String>,
        confidence: f32,
    ) -> Self {
        Self {
            offset,
            length,
            bytes_hex: bytes_hex.into(),
            heuristic: heuristic.into(),
            confidence,
        }
    }
}

// ─── JavaScriptRisk ───────────────────────────────────────────────────────────

/// Computed risk assessment for a single JavaScript snippet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaScriptRisk {
    /// Total risk score [0, 100].
    pub score: u32,
    /// Risk level.
    pub level: RiskLevel,
    /// Identified risk factors.
    pub factors: Vec<RiskFactor>,
}

/// Risk level classification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => write!(f, "CLEAN"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl RiskLevel {
    /// Compute from a numeric score.
    #[must_use]
    pub const fn from_score(s: u32) -> Self {
        if s == 0 {
            Self::Clean
        } else if s < 20 {
            Self::Low
        } else if s < 50 {
            Self::Medium
        } else if s < 80 {
            Self::High
        } else {
            Self::Critical
        }
    }
}

/// A single risk factor contributing to the score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    /// Factor name.
    pub name: String,
    /// Points added to the score.
    pub points: u32,
    /// Explanation.
    pub explanation: String,
}

impl RiskFactor {
    /// Create a new risk factor.
    #[must_use]
    pub fn new(name: impl Into<String>, points: u32, explanation: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            points,
            explanation: explanation.into(),
        }
    }
}

// ─── PdfJsScript ─────────────────────────────────────────────────────────────

/// A JavaScript snippet found within a PDF, with full analysis results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfJsScript {
    /// PDF object number containing the JS.
    pub object_id: u32,
    /// Byte offset within the PDF file.
    pub file_offset: usize,
    /// Raw source text.
    pub source: String,
    /// Source length in bytes.
    pub source_len: usize,
    /// Whether the source appears to be obfuscated.
    pub is_obfuscated: bool,
    /// All detected obfuscation patterns.
    pub obfuscation_patterns: Vec<ObfuscationPattern>,
    /// Heap spray analysis result.
    pub heap_spray: HeapSprayDetect,
    /// Shellcode-like sequences found.
    pub shellcode_hints: Vec<ShellcodeHint>,
    /// Computed risk score.
    pub risk: JavaScriptRisk,
    /// Suspicious API calls referenced (document.write, eval, etc.).
    pub suspicious_calls: Vec<String>,
}

impl PdfJsScript {
    /// Create a new script record with full analysis.
    #[must_use]
    pub fn analyze(object_id: u32, file_offset: usize, source: String) -> Self {
        let source_len = source.len();
        let obfuscation_patterns = detect_obfuscation(&source);
        let is_obfuscated = !obfuscation_patterns.is_empty();
        let heap_spray = detect_heap_spray(&source);
        let shellcode_hints = detect_shellcode_hints(source.as_bytes());
        let suspicious_calls = find_suspicious_calls(&source);
        let risk = compute_risk(
            &obfuscation_patterns,
            &heap_spray,
            &shellcode_hints,
            &suspicious_calls,
        );
        Self {
            object_id,
            file_offset,
            source,
            source_len,
            is_obfuscated,
            obfuscation_patterns,
            heap_spray,
            shellcode_hints,
            risk,
            suspicious_calls,
        }
    }
}

// ─── Detection functions ──────────────────────────────────────────────────────

/// Detect obfuscation patterns in a JavaScript string.
#[must_use]
pub fn detect_obfuscation(source: &str) -> Vec<ObfuscationPattern> {
    let mut patterns = Vec::new();

    // eval() wrapper
    if let Some(pos) = find_token(source, "eval(") {
        patterns.push(ObfuscationPattern::new(
            ObfuscationKind::EvalWrapper,
            pos,
            excerpt(source, pos),
            9,
        ));
    }

    // Function constructor
    if let Some(pos) = find_token(source, "Function(") {
        patterns.push(ObfuscationPattern::new(
            ObfuscationKind::FunctionConstructor,
            pos,
            excerpt(source, pos),
            8,
        ));
    }

    // unescape()
    if let Some(pos) = find_token(source, "unescape(") {
        patterns.push(ObfuscationPattern::new(
            ObfuscationKind::UnescapeEncoding,
            pos,
            excerpt(source, pos),
            7,
        ));
    }

    // String.fromCharCode
    if let Some(pos) = find_token(source, "String.fromCharCode") {
        patterns.push(ObfuscationPattern::new(
            ObfuscationKind::CharCodeArray,
            pos,
            excerpt(source, pos),
            7,
        ));
    }

    // Hex encoding: count \x sequences
    let hex_count = source.as_bytes().windows(2).filter(|w| w[0] == b'\\' && w[1] == b'x').count();
    if hex_count > 10 {
        patterns.push(ObfuscationPattern::new(
            ObfuscationKind::HexEncoding,
            0,
            format!("{hex_count} \\x escapes"),
            6,
        ));
    }

    // Unicode escapes
    let uni_count = source.as_bytes().windows(2).filter(|w| w[0] == b'\\' && w[1] == b'u').count();
    if uni_count > 5 {
        patterns.push(ObfuscationPattern::new(
            ObfuscationKind::UnicodeEscape,
            0,
            format!("{uni_count} \\u escapes"),
            5,
        ));
    }

    // String concatenation (many "+"  between string literals)
    let concat_count = source.as_bytes().windows(3)
        .filter(|w| w[0] == b'"' && w[1] == b'+' && w[2] == b'"')
        .count();
    if concat_count > 5 {
        patterns.push(ObfuscationPattern::new(
            ObfuscationKind::StringConcatenation,
            0,
            format!("{concat_count} inline string concat"),
            4,
        ));
    }

    // Base64 blobs: long strings of base64 chars
    if let Some(pos) = find_base64_blob(source) {
        patterns.push(ObfuscationPattern::new(
            ObfuscationKind::Base64Blob,
            pos,
            excerpt(source, pos),
            6,
        ));
    }

    // Obfuscated variable names: many single-char identifiers
    let single_char_vars = count_single_char_identifiers(source);
    if single_char_vars > 15 {
        patterns.push(ObfuscationPattern::new(
            ObfuscationKind::ObfuscatedNames,
            0,
            format!("{single_char_vars} single-char identifiers"),
            5,
        ));
    }

    // Reversed string pattern
    if source.contains("split(\"\").reverse().join(\"\")") {
        if let Some(pos) = find_token(source, "reverse()") {
            patterns.push(ObfuscationPattern::new(
                ObfuscationKind::ReversedString,
                pos,
                excerpt(source, pos),
                6,
            ));
        }
    }

    patterns
}

fn find_token(source: &str, token: &str) -> Option<usize> {
    source.find(token)
}

fn excerpt(source: &str, offset: usize) -> String {
    let end = (offset + 80).min(source.len());
    source[offset..end].replace('\n', " ")
}

fn find_base64_blob(source: &str) -> Option<usize> {
    // Look for a string of 40+ consecutive base64-valid characters.
    let bytes = source.as_bytes();
    let mut run = 0usize;
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' {
            if run == 0 {
                start = i;
            }
            run += 1;
            if run >= 40 {
                return Some(start);
            }
        } else {
            run = 0;
        }
    }
    None
}

fn count_single_char_identifiers(source: &str) -> usize {
    // Very rough heuristic: count occurrences of " x=" or " x " where x is a single alpha.
    let mut count = 0usize;
    let bytes = source.as_bytes();
    for i in 1..bytes.len().saturating_sub(2) {
        let prev = bytes[i - 1];
        let cur = bytes[i];
        let next = bytes[i + 1];
        if (prev == b' ' || prev == b'\n')
            && cur.is_ascii_lowercase()
            && (next == b'=' || next == b' ' || next == b';')
        {
            count += 1;
        }
    }
    count
}

/// Detect heap spray patterns in JavaScript source.
#[must_use]
pub fn detect_heap_spray(source: &str) -> HeapSprayDetect {
    // Classic heap spray: large string repeated via string multiplication or repeat()
    let has_repeat = source.contains(".repeat(") || source.contains("Array(");
    let has_unescape_nop = source.contains("\\u9090") || source.contains("\\x90\\x90");
    let has_fill = source.contains(".join(\"\")")
        || (source.contains("for(") && source.contains("+="));

    if has_unescape_nop {
        return HeapSprayDetect::positive(
            Some("9090".to_string()),
            Some(1024 * 1024),
            Some("unescape NOP sled".to_string()),
            0.90,
        );
    }

    if has_repeat && has_fill {
        // Try to estimate allocation: look for large numeric literals
        let alloc = find_large_number(source).map(|n| n * 2);
        return HeapSprayDetect::positive(
            None,
            alloc,
            Some("repeat+join fill pattern".to_string()),
            0.70,
        );
    }

    if has_unescape_nop || (has_repeat && source.len() > 5000) {
        return HeapSprayDetect::positive(None, None, None, 0.55);
    }

    HeapSprayDetect::none()
}

fn find_large_number(source: &str) -> Option<usize> {
    // Find integers >= 10000 in the source.
    let mut i = 0;
    let bytes = source.as_bytes();
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if let Ok(n) = std::str::from_utf8(&bytes[start..i]).unwrap_or("0").parse::<usize>() {
                if n >= 10_000 {
                    return Some(n);
                }
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Detect shellcode-like byte sequences in raw data.
#[must_use]
pub fn detect_shellcode_hints(data: &[u8]) -> Vec<ShellcodeHint> {
    let mut hints = Vec::new();

    // NOP sled detection: 8+ consecutive 0x90 bytes.
    let mut nop_run = 0usize;
    let mut nop_start = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if b == 0x90 {
            if nop_run == 0 {
                nop_start = i;
            }
            nop_run += 1;
            if nop_run >= 8 {
                let len = nop_run;
                hints.push(ShellcodeHint::new(
                    nop_start,
                    len,
                    "90".repeat(len.min(16)),
                    "NOP sled",
                    0.88,
                ));
                nop_run = 0;
                continue;
            }
        } else {
            nop_run = 0;
        }
    }

    // Common shellcode prologue patterns: push ebp; mov ebp, esp (55 89 E5)
    let prologue = &[0x55u8, 0x89, 0xE5];
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i + 3] == prologue {
            hints.push(ShellcodeHint::new(i, 3, "5589e5", "x86 function prologue in data", 0.70));
        }
    }

    // 64-bit prologue: 55 48 89 E5
    let prologue64 = &[0x55u8, 0x48, 0x89, 0xE5];
    for i in 0..data.len().saturating_sub(4) {
        if &data[i..i + 4] == prologue64 {
            hints.push(ShellcodeHint::new(i, 4, "554889e5", "x64 function prologue in data", 0.72));
        }
    }

    // MZ header (embedded PE): 4D 5A
    for i in 0..data.len().saturating_sub(2) {
        if data[i] == 0x4D && data[i + 1] == 0x5A {
            let hex = format!("{:02x}{:02x}", data[i], data[i + 1]);
            hints.push(ShellcodeHint::new(i, 2, hex, "embedded MZ/PE header", 0.95));
            // Only report the first hit.
            break;
        }
    }

    // High density of null bytes (possibly encoded payload region)
    let null_density = data.iter().filter(|&&b| b == 0x00).count();
    if data.len() > 64 && null_density * 100 / data.len() > 40 {
        hints.push(ShellcodeHint::new(
            0,
            data.len(),
            "null-heavy".to_string(),
            "high null byte density (possible encoded shellcode)",
            0.60,
        ));
    }

    hints
}

/// Find suspicious JavaScript API call names in the source.
#[must_use]
pub fn find_suspicious_calls(source: &str) -> Vec<String> {
    let suspicious: &[&str] = &[
        "eval",
        "document.write",
        "ActiveXObject",
        "WScript.Shell",
        "shell.application",
        "Shell.Application",
        "XMLHttpRequest",
        "getURL",
        "submitForm",
        "openDoc",
        "launchURL",
        "importData",
        "saveAs",
        "Collab.getIcon",
        "Collab.collectEmailInfo",
        "util.printf",
        "this.exportDataObject",
        "app.openDoc",
        "app.launchURL",
        "app.response",
        "app.alert",
        "this.getField",
        "media.newPlayer",
        "sound.play",
        "annot.setFocus",
    ];
    let mut found = Vec::new();
    for &name in suspicious {
        if source.contains(name) {
            found.push(name.to_string());
        }
    }
    found
}

/// Compute the risk score for a JavaScript snippet.
#[must_use]
pub fn compute_risk(
    obfuscation: &[ObfuscationPattern],
    heap_spray: &HeapSprayDetect,
    shellcode: &[ShellcodeHint],
    suspicious_calls: &[String],
) -> JavaScriptRisk {
    let mut factors = Vec::new();
    let mut score: u32 = 0;

    // Obfuscation
    let obf_score: u32 = obfuscation.iter().map(|p| p.severity).sum::<u32>().min(40);
    if obf_score > 0 {
        factors.push(RiskFactor::new(
            "obfuscation",
            obf_score,
            format!("{} obfuscation pattern(s)", obfuscation.len()),
        ));
        score += obf_score;
    }

    // Heap spray
    if heap_spray.detected {
        let pts = (heap_spray.confidence * 30.0) as u32;
        factors.push(RiskFactor::new("heap_spray", pts, "Heap spray pattern detected"));
        score += pts;
    }

    // Shellcode
    if !shellcode.is_empty() {
        let pts = shellcode
            .iter()
            .map(|s| (s.confidence * 20.0) as u32)
            .sum::<u32>()
            .min(30);
        factors.push(RiskFactor::new(
            "shellcode",
            pts,
            format!("{} shellcode hint(s)", shellcode.len()),
        ));
        score += pts;
    }

    // Suspicious API calls
    if !suspicious_calls.is_empty() {
        let pts = (suspicious_calls.len() as u32 * 5).min(25);
        factors.push(RiskFactor::new(
            "suspicious_apis",
            pts,
            format!("{} suspicious API call(s)", suspicious_calls.len()),
        ));
        score += pts;
    }

    let score = score.min(100);
    JavaScriptRisk {
        score,
        level: RiskLevel::from_score(score),
        factors,
    }
}

// ─── PdfJsExtractorFull ───────────────────────────────────────────────────────

/// Full JavaScript extractor: scans a PDF byte buffer for all JS snippets
/// and returns a fully analysed `PdfJsScript` for each one.
pub struct PdfJsExtractorFull;

impl PdfJsExtractorFull {
    /// Create a new extractor.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Extract and analyse all JS from a PDF byte buffer.
    #[must_use]
    pub fn extract_all(&self, data: &[u8]) -> Vec<PdfJsScript> {
        let mut scripts = Vec::new();
        let markers: &[&[u8]] = &[b"/JavaScript", b"/JS"];
        for marker in markers {
            let mut pos = 0usize;
            while pos + marker.len() < data.len() {
                let found = data[pos..].windows(marker.len()).position(|w| w == *marker);
                let rel = match found {
                    Some(p) => p,
                    None => break,
                };
                let abs = pos + rel;
                let key_end = abs + marker.len();

                // Skip whitespace after the key.
                let skip = data[key_end..]
                    .iter()
                    .take_while(|&&b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
                    .count();
                let val_pos = key_end + skip;

                let obj_id = find_obj_id_before_fast(data, abs);
                let source = extract_js_value(data, val_pos);

                if !source.is_empty() {
                    scripts.push(PdfJsScript::analyze(obj_id, val_pos, source));
                }

                pos = abs + marker.len();
            }
        }

        // Deduplicate by file offset.
        scripts.sort_by_key(|s| s.file_offset);
        scripts.dedup_by_key(|s| s.file_offset);
        scripts
    }

    /// Compute an aggregate risk score across all extracted scripts.
    #[must_use]
    pub fn aggregate_risk(scripts: &[PdfJsScript]) -> u32 {
        if scripts.is_empty() {
            return 0;
        }
        let max = scripts.iter().map(|s| s.risk.score).max().unwrap_or(0);
        // Combine max with a small per-script bonus.
        let bonus = ((scripts.len() as u32).saturating_sub(1) * 2).min(10);
        (max + bonus).min(100)
    }
}

impl Default for PdfJsExtractorFull {
    fn default() -> Self {
        Self::new()
    }
}

/// Find the enclosing PDF object number by walking backward from `before`.
fn find_obj_id_before_fast(data: &[u8], before: usize) -> u32 {
    let scan = &data[..before];
    let mut last = None;
    for (i, w) in scan.windows(4).enumerate() {
        if w == b" obj" {
            last = Some(i);
        }
    }
    let Some(obj_pos) = last else { return 0 };
    // Walk back from obj_pos to find "N G obj"
    let mut p = obj_pos;
    while p > 0 && scan[p - 1] != b'\n' && scan[p - 1] != b'\r' {
        p -= 1;
    }
    let line = &scan[p..obj_pos];
    let parts: Vec<&[u8]> = line.split(|&b| b == b' ').collect();
    if let Some(first) = parts.first() {
        std::str::from_utf8(first).ok().and_then(|s| s.parse().ok()).unwrap_or(0)
    } else {
        0
    }
}

/// Extract the JavaScript value at `pos` in `data`.
fn extract_js_value(data: &[u8], pos: usize) -> String {
    if pos >= data.len() {
        return String::new();
    }
    match data[pos] {
        b'(' => {
            // Literal string
            let mut out = Vec::new();
            let mut i = pos + 1;
            let mut depth = 1i32;
            while i < data.len() && depth > 0 {
                match data[i] {
                    b'\\' => { i += 2; }
                    b'(' => { depth += 1; out.push(b'('); i += 1; }
                    b')' => {
                        depth -= 1;
                        if depth > 0 { out.push(b')'); }
                        i += 1;
                    }
                    b => { out.push(b); i += 1; }
                }
            }
            String::from_utf8_lossy(&out).into_owned()
        }
        b'<' if data.get(pos + 1) != Some(&b'<') => {
            // Hex string
            let end = data[pos + 1..].iter().position(|&b| b == b'>').unwrap_or(0);
            let hex = &data[pos + 1..pos + 1 + end];
            let filtered: Vec<u8> = hex.iter().copied().filter(|b| b.is_ascii_alphanumeric()).collect();
            let mut decoded = Vec::new();
            let mut idx = 0;
            while idx + 1 < filtered.len() {
                let hi = hex_nibble(filtered[idx]);
                let lo = hex_nibble(filtered[idx + 1]);
                decoded.push((hi << 4) | lo);
                idx += 2;
            }
            String::from_utf8_lossy(&decoded).into_owned()
        }
        _ => String::new(),
    }
}

const fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_eval_obfuscation() {
        let source = r#"eval("alert(1)");"#;
        let patterns = detect_obfuscation(source);
        assert!(patterns.iter().any(|p| p.kind == ObfuscationKind::EvalWrapper));
    }

    #[test]
    fn test_detect_hex_encoding() {
        let source = "\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x49\\x4a\\x4b";
        let patterns = detect_obfuscation(source);
        assert!(patterns.iter().any(|p| p.kind == ObfuscationKind::HexEncoding));
    }

    #[test]
    fn test_heap_spray_nop() {
        let source = "var x = unescape('\\u9090\\u9090')";
        let hs = detect_heap_spray(source);
        assert!(hs.detected);
    }

    #[test]
    fn test_heap_spray_none() {
        let source = "var x = 1 + 2;";
        let hs = detect_heap_spray(source);
        assert!(!hs.detected);
    }

    #[test]
    fn test_shellcode_mz_header() {
        let data = b"some data \x4d\x5a rest";
        let hints = detect_shellcode_hints(data);
        assert!(hints.iter().any(|h| h.heuristic.contains("MZ")));
    }

    #[test]
    fn test_shellcode_nop_sled() {
        let mut data = b"prefix".to_vec();
        data.extend(vec![0x90u8; 16]);
        data.extend(b"suffix");
        let hints = detect_shellcode_hints(&data);
        assert!(hints.iter().any(|h| h.heuristic.contains("NOP")));
    }

    #[test]
    fn test_find_suspicious_calls() {
        let source = "eval(document.write('x'))";
        let calls = find_suspicious_calls(source);
        assert!(calls.contains(&"eval".to_string()));
        assert!(calls.contains(&"document.write".to_string()));
    }

    #[test]
    fn test_risk_level_from_score() {
        assert_eq!(RiskLevel::from_score(0), RiskLevel::Clean);
        assert_eq!(RiskLevel::from_score(60), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(95), RiskLevel::Critical);
    }

    #[test]
    fn test_extractor_full_literal() {
        let data = b"%PDF-1.7\n1 0 obj\n<<\n/JS (alert(1);)\n>>\nendobj\n%%EOF\n";
        let extractor = PdfJsExtractorFull::new();
        let scripts = extractor.extract_all(data);
        assert!(!scripts.is_empty());
        assert!(scripts[0].source.contains("alert(1)"));
    }

    #[test]
    fn test_aggregate_risk_empty() {
        assert_eq!(PdfJsExtractorFull::aggregate_risk(&[]), 0);
    }
}
