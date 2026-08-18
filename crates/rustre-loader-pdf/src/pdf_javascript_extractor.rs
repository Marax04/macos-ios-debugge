//! PDF JavaScript extractor — deep extraction of embedded JavaScript from PDF
//! documents, including obfuscated, compressed, and event-triggered scripts.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use anyhow::{bail, Result};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// The PDF action type that triggered a script.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JsTrigger {
    /// Document-level open action (`/OpenAction`).
    OpenAction,
    /// Page open action (`/AA /O`).
    PageOpen,
    /// Page close action (`/AA /C`).
    PageClose,
    /// Form field action (submit, calculate, validate, format, key-stroke).
    FormField { field_name: String, event: FormEvent },
    /// Annotation action (`/AA`).
    Annotation { annotation_index: u32, event: AnnotEvent },
    /// Named action triggered by a name.
    Named(String),
    /// Embedded file open.
    EmbeddedFileOpen,
    /// Unknown / unclassified trigger.
    Unknown,
}

/// Form field event sub-types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FormEvent {
    MouseUp,
    MouseDown,
    MouseEnter,
    MouseExit,
    OnFocus,
    OnBlur,
    Keystroke,
    Format,
    Validate,
    Calculate,
    Other(String),
}

/// Annotation action event sub-types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnnotEvent {
    MouseUp,
    MouseDown,
    MouseEnter,
    MouseExit,
    OnFocus,
    OnBlur,
    Other(String),
}

/// A single extracted JavaScript action from a PDF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsAction {
    /// Object number of the PDF action dictionary that contained this script.
    pub action_obj_num: u32,
    /// Generation number of that object.
    pub action_gen_num: u16,
    /// The trigger that fires this script.
    pub trigger: JsTrigger,
    /// Zero-based page number this action is associated with, if known.
    pub page_number: Option<u32>,
    /// The raw JavaScript source text.
    pub script: String,
    /// Estimated deobfuscation confidence in [0.0, 1.0].
    pub deobfuscation_confidence: f32,
    /// Whether static analysis suspects this script to be malicious.
    pub suspected_malicious: bool,
    /// Heuristic labels assigned by analysis (e.g., "shellcode-dropper").
    pub heuristic_labels: Vec<String>,
}

impl JsAction {
    /// Return the script trimmed of leading/trailing whitespace.
    #[must_use]
    pub fn script_trimmed(&self) -> &str {
        self.script.trim()
    }

    /// Approximate byte size of the script.
    #[must_use]
    pub const fn script_len(&self) -> usize {
        self.script.len()
    }

    /// Return `true` if the script appears to be empty or whitespace-only.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.script.trim().is_empty()
    }
}

/// A single script entry that may wrap multiple `JsAction`s chained together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptEntry {
    /// Unique identifier within this extraction run.
    pub id: u64,
    /// Human-readable label (e.g., "`OpenAction`", "Page3/MouseUp").
    pub label: String,
    /// All `JsActions` that make up this script entry.
    pub actions: Vec<JsAction>,
    /// Combined source text of all chained actions.
    pub combined_script: String,
    /// Whether any contained action was flagged as malicious.
    pub any_malicious: bool,
    /// All unique heuristic labels across contained actions.
    pub all_labels: Vec<String>,
}

impl ScriptEntry {
    fn from_actions(id: u64, label: impl Into<String>, actions: Vec<JsAction>) -> Self {
        let combined_script: String = actions.iter()
            .map(|a| a.script.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let any_malicious = actions.iter().any(|a| a.suspected_malicious);
        let mut labels: Vec<String> = actions.iter()
            .flat_map(|a| a.heuristic_labels.iter().cloned())
            .collect();
        labels.sort();
        labels.dedup();
        ScriptEntry {
            id,
            label: label.into(),
            actions,
            combined_script,
            any_malicious,
            all_labels: labels,
        }
    }

    /// Total combined script length in bytes.
    #[must_use]
    pub const fn combined_len(&self) -> usize {
        self.combined_script.len()
    }
}

/// Summary of an extraction run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtractionSummary {
    pub total_scripts: usize,
    pub malicious_scripts: usize,
    pub total_script_bytes: usize,
    pub unique_labels: Vec<String>,
    pub open_action_present: bool,
    pub obfuscated_count: usize,
    pub avg_deobfuscation_confidence: f32,
}

// ---------------------------------------------------------------------------
// Extraction configuration
// ---------------------------------------------------------------------------

/// Controls the behavior of [`PdfJavaScriptExtractor`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractorConfig {
    /// Apply heuristic deobfuscation passes (unescape, eval-unwrap, etc.).
    pub deobfuscate: bool,
    /// Maximum script size to process in bytes (0 = unlimited).
    pub max_script_bytes: usize,
    /// Apply maliciousness heuristics.
    pub run_heuristics: bool,
    /// Deduplicate identical scripts.
    pub deduplicate: bool,
    /// Collect scripts from embedded files.
    pub extract_from_embedded: bool,
    /// Maximum recursion depth when following `/Next` action chains.
    pub max_action_chain_depth: u32,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        ExtractorConfig {
            deobfuscate: true,
            max_script_bytes: 4 * 1024 * 1024,
            run_heuristics: true,
            deduplicate: true,
            extract_from_embedded: false,
            max_action_chain_depth: 16,
        }
    }
}

// ---------------------------------------------------------------------------
// Deobfuscation helpers
// ---------------------------------------------------------------------------

/// Result of a deobfuscation attempt.
#[derive(Debug, Clone)]
struct DeobfuscationResult {
    code: String,
    confidence: f32,
    passes_applied: Vec<String>,
}

/// Apply lightweight JavaScript deobfuscation passes.
fn deobfuscate_js(raw: &str) -> DeobfuscationResult {
    let mut code = raw.to_string();
    let mut passes = Vec::new();
    let mut confidence: f32 = 1.0;

    // Pass 1: unescape percent-encoded sequences like %u0041.
    if code.contains("%u") || code.contains("%U") {
        code = unescape_unicode(&code);
        passes.push("unicode-unescape".into());
    }

    // Pass 2: collapse obvious string concatenation "a"+"b" → "ab".
    if code.contains("\"+\"") || code.contains("\" + \"") {
        code = collapse_string_concat(&code);
        passes.push("string-concat-collapse".into());
    }

    // Pass 3: inline trivial fromCharCode sequences.
    if code.contains("fromCharCode") {
        let (new_code, inlined) = inline_fromcharcode(&code);
        if inlined {
            code = new_code;
            passes.push("fromCharCode-inline".into());
        }
    }

    // Pass 4: strip eval() wrappers (just unwrap the argument).
    if code.trim_start().starts_with("eval(") {
        if let Some(inner) = strip_eval_wrapper(&code) {
            code = inner;
            passes.push("eval-unwrap".into());
            confidence *= 0.85; // Lower confidence after eval unwrap.
        }
    }

    // Pass 5: decode hex-encoded strings like "\x41\x42".
    if code.contains("\\x") {
        code = decode_hex_escapes(&code);
        passes.push("hex-escape-decode".into());
    }

    if !passes.is_empty() {
        confidence *= 0.95_f32.powi(passes.len() as i32);
    }

    DeobfuscationResult { code, confidence, passes_applied: passes }
}

fn unescape_unicode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 5 < bytes.len() && bytes[i] == b'%'
            && (bytes[i + 1] == b'u' || bytes[i + 1] == b'U')
        {
            let hex = &s[i + 2..i + 6];
            if let Ok(cp) = u16::from_str_radix(hex, 16) {
                if let Some(ch) = char::from_u32(cp as u32) {
                    result.push(ch);
                    i += 6;
                    continue;
                }
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

fn collapse_string_concat(s: &str) -> String {
    // Replace `"x"+"y"` with `"xy"` — very naive, handles simple cases.
    let mut result = s.to_string();
    loop {
        // Look for the pattern `"..."+"`  — closing quote, plus, opening quote.
        if let Some(pos) = result.find("\"+\"") {
            result = format!("{}{}", &result[..pos], &result[pos + 3..]);
        } else if let Some(pos) = result.find("\" + \"") {
            result = format!("{}{}", &result[..pos], &result[pos + 5..]);
        } else {
            break;
        }
    }
    result
}

fn inline_fromcharcode(s: &str) -> (String, bool) {
    // Find `String.fromCharCode(n1,n2,...)` and replace with quoted string.
    let marker = "String.fromCharCode(";
    let Some(start) = s.find(marker) else { return (s.to_string(), false) };
    let args_start = start + marker.len();
    let Some(end) = s[args_start..].find(')') else { return (s.to_string(), false) };
    let args = &s[args_start..args_start + end];
    let chars: Option<String> = args
        .split(',')
        .map(|a| {
            let a = a.trim();
            a.parse::<u32>().ok().and_then(char::from_u32)
        })
        .collect();
    if let Some(decoded) = chars {
        let replaced = format!("{}\"{}\"{}", &s[..start], decoded, &s[args_start + end + 1..]);
        (replaced, true)
    } else {
        (s.to_string(), false)
    }
}

fn strip_eval_wrapper(s: &str) -> Option<String> {
    let t = s.trim();
    if !t.starts_with("eval(") { return None; }
    // Find the matching closing parenthesis.
    let mut depth = 0usize;
    let mut start = None;
    let mut end   = None;
    for (i, ch) in t.char_indices() {
        match ch {
            '(' => {
                depth += 1;
                if depth == 1 { start = Some(i + 1); }
            }
            ')' => {
                depth -= 1;
                if depth == 0 { end = Some(i); break; }
            }
            _ => {}
        }
    }
    match (start, end) {
        (Some(s), Some(e)) if e > s => Some(t[s..e].to_string()),
        _ => None,
    }
}

fn decode_hex_escapes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.peek() {
                Some(&'x') => {
                    chars.next();
                    let h1 = chars.next();
                    let h2 = chars.next();
                    if let (Some(a), Some(b)) = (h1, h2) {
                        let hex = format!("{a}{b}");
                        if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                            result.push(byte as char);
                            continue;
                        }
                        result.push('\\');
                        result.push('x');
                        result.push(a);
                        result.push(b);
                    }
                }
                _ => result.push(ch),
            }
        } else {
            result.push(ch);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Heuristic analysis
// ---------------------------------------------------------------------------

/// Signals that a script may be malicious.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousnessReport {
    pub score: f32,
    pub labels: Vec<String>,
    pub indicators: Vec<String>,
}

fn analyze_script(script: &str) -> MaliciousnessReport {
    let mut score = 0.0f32;
    let mut labels: Vec<String> = Vec::new();
    let mut indicators: Vec<String> = Vec::new();

    // Shellcode dropper patterns.
    if script.contains("unescape") && script.contains("%u") {
        score += 0.4;
        labels.push("shellcode-dropper".into());
        indicators.push("unescape with percent-encoded payload".into());
    }

    // Heap spray.
    if script.contains("spray") || (script.contains("var ") && script.contains("0x0c0c0c0c")) {
        score += 0.5;
        labels.push("heap-spray".into());
        indicators.push("heap spray pattern".into());
    }

    // Obfuscated eval chain.
    let eval_count = script.matches("eval(").count();
    if eval_count >= 2 {
        score += 0.3 * eval_count as f32;
        labels.push("eval-chain".into());
        indicators.push(format!("{eval_count} nested eval() calls"));
    }

    // Active content download.
    for keyword in &["XMLHttpRequest", "ActiveXObject", "XMLHTTP"] {
        if script.contains(keyword) {
            score += 0.35;
            labels.push("active-download".into());
            indicators.push(format!("uses {keyword}"));
        }
    }

    // Form / cookie stealing.
    if script.contains("document.cookie") || script.contains("document.forms") {
        score += 0.25;
        labels.push("data-exfiltration".into());
        indicators.push("accesses cookies or form data".into());
    }

    // PDF-specific exploit patterns.
    for pattern in &["app.doc", "this.submitForm", "app.launchURL", "Collab.getIcon", "util.printf"] {
        if script.contains(pattern) {
            score += 0.2;
            labels.push("pdf-exploit-api".into());
            indicators.push(format!("uses potentially exploitable API: {pattern}"));
            break;
        }
    }

    labels.sort();
    labels.dedup();

    MaliciousnessReport {
        score: score.min(1.0),
        labels,
        indicators,
    }
}

// ---------------------------------------------------------------------------
// Core extractor
// ---------------------------------------------------------------------------

/// Extracts all JavaScript from a parsed PDF byte stream.
///
/// The extractor operates on raw PDF bytes and locates JavaScript actions via
/// pattern matching without requiring a full PDF object graph.
pub struct PdfJavaScriptExtractor {
    config: ExtractorConfig,
    next_id: u64,
    stats: ExtractionStats,
}

#[derive(Debug, Default)]
struct ExtractionStats {
    bytes_scanned: u64,
    objects_visited: u32,
    scripts_found: u32,
    deobfuscations_applied: u32,
}

impl PdfJavaScriptExtractor {
    /// Construct with default configuration.
    #[must_use]
    pub fn new() -> Self {
        PdfJavaScriptExtractor {
            config: ExtractorConfig::default(),
            next_id: 0,
            stats: ExtractionStats::default(),
        }
    }

    /// Construct with a custom configuration.
    #[must_use]
    pub fn with_config(config: ExtractorConfig) -> Self {
        PdfJavaScriptExtractor { config, next_id: 0, stats: ExtractionStats::default() }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Extract all JavaScript entries from raw PDF bytes.
    ///
    /// Returns a list of [`ScriptEntry`] items in document order.
    pub fn extract(&mut self, pdf_bytes: &[u8]) -> Result<Vec<ScriptEntry>> {
        if pdf_bytes.len() < 5 {
            bail!("input too short to be a PDF");
        }
        if !pdf_bytes.starts_with(b"%PDF-") {
            bail!("not a PDF file (missing %PDF- header)");
        }
        self.stats.bytes_scanned = pdf_bytes.len() as u64;

        // Phase 1: locate all /JS or /JavaScript streams.
        let raw_scripts = self.locate_js_streams(pdf_bytes);

        // Phase 2: build JsAction list.
        let actions: Vec<JsAction> = raw_scripts
            .into_iter()
            .map(|(obj_num, gen_num, trigger, script)| {
                self.build_action(obj_num, gen_num, trigger, script)
            })
            .collect();

        // Phase 3: group into ScriptEntry items.
        let mut entries = self.group_actions(actions);

        // Phase 4: deduplication.
        if self.config.deduplicate {
            entries = self.deduplicate(entries);
        }

        self.stats.scripts_found = entries.len() as u32;
        Ok(entries)
    }

    /// Summarize a list of extracted entries.
    #[must_use]
    pub fn summarize(entries: &[ScriptEntry]) -> ExtractionSummary {
        let total_scripts = entries.len();
        let malicious_scripts = entries.iter().filter(|e| e.any_malicious).count();
        let total_script_bytes = entries.iter().map(|e| e.combined_len()).sum();
        let open_action_present = entries.iter().any(|e| {
            e.actions.iter().any(|a| matches!(a.trigger, JsTrigger::OpenAction))
        });
        let obfuscated_count = entries.iter().filter(|e| {
            e.actions.iter().any(|a| a.deobfuscation_confidence < 0.85)
        }).count();
        let avg_conf = if total_scripts == 0 {
            1.0
        } else {
            let sum: f32 = entries.iter()
                .flat_map(|e| e.actions.iter())
                .map(|a| a.deobfuscation_confidence)
                .sum();
            let count = entries.iter().flat_map(|e| e.actions.iter()).count() as f32;
            if count == 0.0 { 1.0 } else { sum / count }
        };
        let mut unique_labels: Vec<String> = entries.iter()
            .flat_map(|e| e.all_labels.iter().cloned())
            .collect();
        unique_labels.sort();
        unique_labels.dedup();

        ExtractionSummary {
            total_scripts,
            malicious_scripts,
            total_script_bytes,
            unique_labels,
            open_action_present,
            obfuscated_count,
            avg_deobfuscation_confidence: avg_conf,
        }
    }

    /// Filter entries that contain malicious scripts.
    #[must_use]
    pub fn malicious_entries(entries: &[ScriptEntry]) -> Vec<&ScriptEntry> {
        entries.iter().filter(|e| e.any_malicious).collect()
    }

    /// Filter entries by heuristic label.
    #[must_use]
    pub fn entries_with_label<'a>(entries: &'a [ScriptEntry], label: &str) -> Vec<&'a ScriptEntry> {
        entries.iter()
            .filter(|e| e.all_labels.iter().any(|l| l == label))
            .collect()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn locate_js_streams(
        &mut self,
        data: &[u8],
    ) -> Vec<(u32, u16, JsTrigger, String)> {
        let mut found = Vec::new();
        let mut obj_counter = 0u32;

        // Search for `/JS ` and `/JavaScript ` dictionary keys.
        let markers: &[(&[u8], bool)] = &[
            (b"/JS (", false),
            (b"/JavaScript (", false),
            (b"/JS <", true),
            (b"/JavaScript <", true),
        ];

        for &(marker, is_hex) in markers {
            let mut search_start = 0;
            while let Some(pos) = memmem(data, marker, search_start) {
                let content_start = pos + marker.len();
                let script = if is_hex {
                    // Hex-encoded string: find closing `>`
                    if let Some(end) = memmem(data, b">", content_start) {
                        let hex_str = std::str::from_utf8(&data[content_start..end]).unwrap_or("");
                        hex_decode_str(hex_str)
                    } else {
                        search_start = content_start;
                        continue;
                    }
                } else {
                    // Literal string: find unescaped closing `)`
                    match read_pdf_literal_string(data, content_start) {
                        Some(s) => s,
                        None => {
                            search_start = content_start;
                            continue;
                        }
                    }
                };

                if !script.is_empty() {
                    obj_counter += 1;
                    self.stats.objects_visited += 1;
                    found.push((obj_counter, 0u16, JsTrigger::Unknown, script));
                }
                search_start = content_start;
            }
        }

        // Check for /OpenAction in the catalog.
        if memmem(data, b"/OpenAction", 0).is_some() {
            for item in &mut found {
                if matches!(item.2, JsTrigger::Unknown) {
                    item.2 = JsTrigger::OpenAction;
                    break;
                }
            }
        }

        found
    }

    fn build_action(
        &mut self,
        obj_num: u32,
        gen_num: u16,
        trigger: JsTrigger,
        raw_script: String,
    ) -> JsAction {
        let (script, deobfuscation_confidence) = if self.config.deobfuscate {
            let r = deobfuscate_js(&raw_script);
            if !r.passes_applied.is_empty() {
                self.stats.deobfuscations_applied += 1;
            }
            (r.code, r.confidence)
        } else {
            (raw_script, 1.0)
        };

        let (suspected_malicious, heuristic_labels) = if self.config.run_heuristics {
            let report = analyze_script(&script);
            (report.score >= 0.4, report.labels)
        } else {
            (false, Vec::new())
        };

        JsAction {
            action_obj_num: obj_num,
            action_gen_num: gen_num,
            trigger,
            page_number: None,
            script,
            deobfuscation_confidence,
            suspected_malicious,
            heuristic_labels,
        }
    }

    fn group_actions(&mut self, actions: Vec<JsAction>) -> Vec<ScriptEntry> {
        // Group by trigger type.
        let mut map: HashMap<String, Vec<JsAction>> = HashMap::new();
        for action in actions {
            let key = match &action.trigger {
                JsTrigger::OpenAction => "OpenAction".to_string(),
                JsTrigger::PageOpen   => format!("Page{}/Open", action.page_number.unwrap_or(0)),
                JsTrigger::PageClose  => format!("Page{}/Close", action.page_number.unwrap_or(0)),
                JsTrigger::FormField { field_name, .. } => format!("Field/{field_name}"),
                JsTrigger::Named(n)   => format!("Named/{n}"),
                _                     => format!("Action/{}", action.action_obj_num),
            };
            map.entry(key).or_default().push(action);
        }

        let mut entries: Vec<ScriptEntry> = map
            .into_iter()
            .map(|(label, acts)| {
                let id = self.next_id;
                self.next_id += 1;
                ScriptEntry::from_actions(id, label, acts)
            })
            .collect();

        entries.sort_by_key(|e| e.id);
        entries
    }

    fn deduplicate(&self, entries: Vec<ScriptEntry>) -> Vec<ScriptEntry> {
        let mut seen: HashMap<String, bool> = HashMap::new();
        entries
            .into_iter()
            .filter(|e| seen.insert(e.combined_script.clone(), true).is_none())
            .collect()
    }
}

impl Default for PdfJavaScriptExtractor {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Simple memmem — find `needle` in `haystack` starting at `from`.
fn memmem(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() { return Some(from); }
    if from >= haystack.len() { return None; }
    let h = &haystack[from..];
    h.windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// Decode a hex-encoded PDF string (pairs of hex digits).
fn hex_decode_str(s: &str) -> String {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    clean
        .as_bytes()
        .chunks(2)
        .filter_map(|chunk| {
            let pair = std::str::from_utf8(chunk).ok()?;
            let byte = u8::from_str_radix(pair, 16).ok()?;
            char::from_u32(byte as u32)
        })
        .collect()
}

/// Read a PDF literal string `(...)` starting at `data[start]`, handling
/// balanced parentheses and `\` escapes.  Returns the decoded string.
fn read_pdf_literal_string(data: &[u8], start: usize) -> Option<String> {
    let mut result = Vec::new();
    let mut i = start;
    let mut depth = 1i32;
    while i < data.len() && depth > 0 {
        let b = data[i];
        match b {
            b'\\' if i + 1 < data.len() => {
                i += 1;
                match data[i] {
                    b'n'  => result.push(b'\n'),
                    b'r'  => result.push(b'\r'),
                    b't'  => result.push(b'\t'),
                    b'\\' => result.push(b'\\'),
                    b'('  => result.push(b'('),
                    b')'  => result.push(b')'),
                    d @ b'0'..=b'7' => {
                        // Octal escape (up to 3 digits).
                        let mut octal = (d - b'0') as u16;
                        for _ in 0..2 {
                            if i + 1 < data.len() && data[i + 1].is_ascii_octdigit() {
                                i += 1;
                                octal = octal * 8 + (data[i] - b'0') as u16;
                            } else {
                                break;
                            }
                        }
                        result.push((octal & 0xff) as u8);
                    }
                    other => result.push(other),
                }
            }
            b'(' => { depth += 1; result.push(b); }
            b')' => {
                depth -= 1;
                if depth > 0 { result.push(b); }
            }
            _ => result.push(b),
        }
        i += 1;
    }
    if depth == 0 {
        Some(String::from_utf8_lossy(&result).into_owned())
    } else {
        None
    }
}

trait IsAsciiOctdigit {
    fn is_ascii_octdigit(self) -> bool;
}
impl IsAsciiOctdigit for u8 {
    fn is_ascii_octdigit(self) -> bool { self >= b'0' && self <= b'7' }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decode_roundtrip() {
        let encoded = "48656c6c6f";
        assert_eq!(hex_decode_str(encoded), "Hello");
    }

    #[test]
    fn read_literal_string_simple() {
        let data = b"Hello World)rest";
        let result = read_pdf_literal_string(data, 0);
        assert_eq!(result, Some("Hello World".to_string()));
    }

    #[test]
    fn read_literal_string_nested() {
        let data = b"a(b)c)rest";
        let result = read_pdf_literal_string(data, 0);
        assert_eq!(result, Some("a(b)c".to_string()));
    }

    #[test]
    fn deobfuscate_eval_unwrap() {
        let script = "eval(alert(1))";
        let r = deobfuscate_js(script);
        assert!(r.passes_applied.contains(&"eval-unwrap".to_string()));
        assert_eq!(r.code, "alert(1)");
    }

    #[test]
    fn deobfuscate_hex_escapes() {
        let script = r"\x48\x65\x6c\x6c\x6f";
        let r = deobfuscate_js(script);
        assert_eq!(r.code, "Hello");
    }

    #[test]
    fn analyze_safe_script() {
        let report = analyze_script("console.log('hello');");
        assert!(report.score < 0.4);
        assert!(report.labels.is_empty());
    }

    #[test]
    fn analyze_malicious_script() {
        let report = analyze_script("unescape('%u4141%u4141'); eval(eval(payload));");
        assert!(report.score >= 0.4);
    }

    #[test]
    fn extractor_rejects_non_pdf() {
        let mut ext = PdfJavaScriptExtractor::new();
        let result = ext.extract(b"Not a PDF at all");
        assert!(result.is_err());
    }

    #[test]
    fn extractor_empty_pdf_bytes() {
        let mut ext = PdfJavaScriptExtractor::new();
        let result = ext.extract(b"");
        assert!(result.is_err());
    }

    #[test]
    fn extractor_minimal_pdf_no_js() {
        let mut ext = PdfJavaScriptExtractor::new();
        // Just the header — should succeed with no scripts.
        let result = ext.extract(b"%PDF-1.4\nsome content");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn summarize_empty() {
        let summary = PdfJavaScriptExtractor::summarize(&[]);
        assert_eq!(summary.total_scripts, 0);
        assert!(!summary.open_action_present);
    }

    #[test]
    fn memmem_basic() {
        let h = b"hello world";
        assert_eq!(memmem(h, b"world", 0), Some(6));
        assert_eq!(memmem(h, b"xyz", 0), None);
    }

    #[test]
    fn js_action_accessors() {
        let action = JsAction {
            action_obj_num: 1,
            action_gen_num: 0,
            trigger: JsTrigger::OpenAction,
            page_number: None,
            script: "  alert(1)  ".to_string(),
            deobfuscation_confidence: 1.0,
            suspected_malicious: false,
            heuristic_labels: Vec::new(),
        };
        assert_eq!(action.script_trimmed(), "alert(1)");
        assert_eq!(action.script_len(), 12);
        assert!(!action.is_empty());
    }
}
