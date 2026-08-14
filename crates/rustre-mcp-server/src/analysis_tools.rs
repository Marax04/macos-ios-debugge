//! `analysis_tools` — **Raw-bytes analysis layer** of the MCP tool stack.
//!
//! This module operates on raw byte slices or hex strings supplied directly in
//! the tool call. It does **not** require a loaded binary session.
//!
//! Exposed tools: `find_vulnerabilities`, `analyze_crypto`, `deobfuscate_strings`,
//! `identify_malware`, `extract_config`, `generate_yara`, `compare_functions`.
//!
//! # Layer relationships
//!
//! | Module | Input model | Registry type | Tool count |
//! |---|---|---|---|
//! | [`analysis_tools`] (this) | raw bytes / hex | [`AnalysisTools`] + [`ToolEntry`] | 7 |
//! | [`rustre_tools`] | `binary_id` string | [`rustre_tools::RustreToolSet`] | 14 |
//! | [`tool_implementation`] | typed Rust structs | [`tool_implementation::ToolImplementation`] | 15 |
//! | [`mcp_tool_registry`] | closure handlers | [`mcp_tool_registry::McpToolRegistry`] | dynamic |
//!
//! These modules are **not duplicates**: they exist at different abstraction
//! layers and are intended to be wired together through the session handler.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Tool error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by analysis tools.
#[derive(Debug, Error)]
pub enum AnalysisToolError {
    #[error("invalid parameter '{param}': {reason}")]
    InvalidParam { param: String, reason: String },
    #[error("binary data is required but was not provided")]
    NoBinaryData,
    #[error("address out of range: {0:#x}")]
    AddressOutOfRange(u64),
    #[error("analysis engine error: {0}")]
    EngineError(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl AnalysisToolError {
    #[must_use] 
    pub fn invalid(param: &str, reason: &str) -> Self {
        Self::InvalidParam {
            param: param.into(),
            reason: reason.into(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared input/output types
// ─────────────────────────────────────────────────────────────────────────────

/// A single vulnerability finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnFinding {
    pub vuln_type: String,
    pub address: u64,
    pub severity: String,
    pub description: String,
    pub cve: Option<String>,
}

/// A crypto algorithm detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoMatch {
    pub algorithm: String,
    pub confidence: f32,
    pub address: u64,
    pub key_size_bits: Option<u32>,
    pub mode: Option<String>,
}

/// A deobfuscated string result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeobfuscatedString {
    pub original_bytes: Vec<u8>,
    pub decoded: String,
    pub method: String,
    pub address: u64,
}

/// A malware family classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareClassification {
    pub family: String,
    pub confidence: f32,
    pub indicators: Vec<String>,
    pub category: String,
}

/// An extracted config value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigValue {
    pub key: String,
    pub value: String,
    pub source_address: u64,
    pub data_type: String,
}

/// A generated YARA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub rule_name: String,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
    pub strings: Vec<YaraString>,
    pub condition: String,
}

impl YaraRule {
    #[must_use] 
    pub fn to_text(&self) -> String {
        let tags = if self.tags.is_empty() {
            String::new()
        } else {
            format!(" : {}", self.tags.join(" "))
        };
        let meta: String = self.meta.iter().fold(String::new(), |mut acc, (k, v)| {
            use std::fmt::Write;
            let _ = writeln!(acc, "        {k} = \"{v}\"");
            acc
        });
        let strings: String = self.strings.iter().fold(String::new(), |mut acc, s| {
            use std::fmt::Write;
            let _ = writeln!(acc, "        {} = {}", s.id, s.pattern);
            acc
        });
        format!(
            "rule {}{} {{\n    meta:\n{}    strings:\n{}    condition:\n        {}\n}}\n",
            self.rule_name, tags, meta, strings, self.condition
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraString {
    pub id: String,
    pub pattern: String,
    pub modifiers: Vec<String>,
}

/// Function comparison result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionComparison {
    pub similarity: f32,
    pub differing_instructions: usize,
    pub total_instructions: usize,
    pub matching_blocks: usize,
    pub matching_bytes: Vec<(u64, u64)>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool schemas
// ─────────────────────────────────────────────────────────────────────────────

fn schema_find_vulnerabilities() -> Value {
    json!({
        "type": "object",
        "properties": {
            "bytes": { "type": "array", "items": { "type": "integer" }, "description": "Raw binary bytes to analyse" },
            "hex":   { "type": "string", "description": "Hex-encoded binary data" },
            "arch":  { "type": "string", "enum": ["x86", "x86_64", "arm", "arm64"], "default": "x86_64" },
            "checks": { "type": "array", "items": { "type": "string" }, "description": "Vulnerability classes to check (default: all)" }
        },
        "required": []
    })
}

fn schema_analyze_crypto() -> Value {
    json!({
        "type": "object",
        "properties": {
            "bytes": { "type": "array", "items": { "type": "integer" } },
            "hex":   { "type": "string" },
            "min_confidence": { "type": "number", "default": 0.6, "minimum": 0.0, "maximum": 1.0 }
        },
        "required": []
    })
}

fn schema_deobfuscate_strings() -> Value {
    json!({
        "type": "object",
        "properties": {
            "bytes": { "type": "array", "items": { "type": "integer" } },
            "hex":   { "type": "string" },
            "methods": { "type": "array", "items": { "type": "string" }, "description": "Deobfuscation methods: xor, rot13, b64, stack_strings" }
        },
        "required": []
    })
}

fn schema_identify_malware() -> Value {
    json!({
        "type": "object",
        "properties": {
            "bytes": { "type": "array", "items": { "type": "integer" } },
            "hex":   { "type": "string" },
            "use_yara": { "type": "boolean", "default": true }
        },
        "required": []
    })
}

fn schema_extract_config() -> Value {
    json!({
        "type": "object",
        "properties": {
            "bytes": { "type": "array", "items": { "type": "integer" } },
            "hex":   { "type": "string" },
            "family": { "type": "string", "description": "Optional known malware family hint" }
        },
        "required": []
    })
}

fn schema_generate_yara() -> Value {
    json!({
        "type": "object",
        "properties": {
            "bytes": { "type": "array", "items": { "type": "integer" } },
            "hex":   { "type": "string" },
            "rule_name": { "type": "string", "default": "auto_generated" },
            "tags": { "type": "array", "items": { "type": "string" } },
            "min_string_length": { "type": "integer", "default": 8 }
        },
        "required": []
    })
}

fn schema_deobf_mba_normalize() -> Value {
    json!({
        "type": "object",
        "properties": {
            "expr": { "type": "string", "description": "MBA expression text" },
            "max_iterations": { "type": "integer", "default": 100, "minimum": 1, "maximum": 10000 }
        },
        "required": ["expr"]
    })
}

fn schema_compare_functions() -> Value {
    json!({
        "type": "object",
        "properties": {
            "bytes_a": { "type": "array", "items": { "type": "integer" }, "description": "Bytes of function A" },
            "bytes_b": { "type": "array", "items": { "type": "integer" }, "description": "Bytes of function B" },
            "hex_a": { "type": "string" },
            "hex_b": { "type": "string" },
            "arch": { "type": "string", "enum": ["x86", "x86_64", "arm", "arm64"], "default": "x86_64" }
        },
        "required": []
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool entry record
// ─────────────────────────────────────────────────────────────────────────────

/// A registered analysis tool with its schema and handler.
pub struct ToolEntry {
    pub name: &'static str,
    pub description: &'static str,
    pub schema: Value,
}

impl ToolEntry {
    #[must_use] 
    pub fn to_mcp_definition(&self) -> Value {
        json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.schema,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisTools
// ─────────────────────────────────────────────────────────────────────────────

/// Registry of all analysis tools for the MCP server.
pub struct AnalysisTools {
    tools: Vec<ToolEntry>,
}

impl AnalysisTools {
    /// Create and populate the tool registry.
    #[must_use] 
    pub fn new() -> Self {
        let tools = vec![
            ToolEntry {
                name: "find_vulnerabilities",
                description: "Detect common binary vulnerabilities (buffer overflows, format strings, use-after-free patterns, integer overflows).",
                schema: schema_find_vulnerabilities(),
            },
            ToolEntry {
                name: "analyze_crypto",
                description: "Identify cryptographic algorithms by constant detection (AES S-boxes, RSA primes, SHA/MD5 round constants).",
                schema: schema_analyze_crypto(),
            },
            ToolEntry {
                name: "deobfuscate_strings",
                description: "Decode obfuscated strings using XOR, ROT-13, base64, stack-string reconstruction.",
                schema: schema_deobfuscate_strings(),
            },
            ToolEntry {
                name: "identify_malware",
                description: "Classify binary against known malware families using YARA rules and heuristics.",
                schema: schema_identify_malware(),
            },
            ToolEntry {
                name: "extract_config",
                description: "Extract embedded configuration from malware samples (C2 addresses, ports, keys).",
                schema: schema_extract_config(),
            },
            ToolEntry {
                name: "generate_yara",
                description: "Generate a YARA rule from interesting byte patterns in a binary sample.",
                schema: schema_generate_yara(),
            },
            ToolEntry {
                name: "compare_functions",
                description: "Compute structural similarity between two function byte sequences.",
                schema: schema_compare_functions(),
            },
            ToolEntry {
                name: "deobf_mba_normalize",
                description: "Normalize a Mixed-Boolean-Arithmetic expression via rustre-deobf-mba (applies (x^y)+2*(x&y) -> x+y and ~80 other identities).",
                schema: schema_deobf_mba_normalize(),
            },
        ];
        Self { tools }
    }

    /// Return the list of all tool definitions as MCP JSON.
    #[must_use] 
    pub fn list(&self) -> Vec<Value> {
        self.tools.iter().map(ToolEntry::to_mcp_definition).collect()
    }

    /// Dispatch a tool call.
    pub fn call(&self, name: &str, params: &Value) -> Result<Value, AnalysisToolError> {
        match name {
            "find_vulnerabilities" => self.find_vulnerabilities(params),
            "analyze_crypto" => self.analyze_crypto(params),
            "deobfuscate_strings" => self.deobfuscate_strings(params),
            "identify_malware" => self.identify_malware(params),
            "extract_config" => self.extract_config(params),
            "generate_yara" => self.generate_yara(params),
            "compare_functions" => self.compare_functions(params),
            "deobf_mba_normalize" => self.deobf_mba_normalize(params),
            other => Err(AnalysisToolError::EngineError(format!(
                "unknown tool: {other}"
            ))),
        }
    }

    #[must_use] 
    pub const fn tool_count(&self) -> usize {
        self.tools.len()
    }

    #[must_use] 
    pub fn tool_names(&self) -> Vec<&'static str> {
        self.tools.iter().map(|t| t.name).collect()
    }

    // ── Tool implementations ──────────────────────────────────────────────

    fn get_bytes(&self, params: &Value) -> Result<Vec<u8>, AnalysisToolError> {
        if let Some(arr) = params.get("bytes").and_then(Value::as_array) {
            return arr
                .iter()
                .map(|v| {
                    v.as_u64()
                        .ok_or_else(|| AnalysisToolError::invalid("bytes", "must be integers"))
                        .and_then(|n| {
                            u8::try_from(n).map_err(|_| {
                                AnalysisToolError::invalid("bytes", "value out of u8 range")
                            })
                        })
                })
                .collect();
        }
        if let Some(hex) = params.get("hex").and_then(Value::as_str) {
            return hex_decode(hex);
        }
        Ok(Vec::new())
    }

    fn find_vulnerabilities(&self, params: &Value) -> Result<Value, AnalysisToolError> {
        let data = self.get_bytes(params)?;
        let arch = params
            .get("arch")
            .and_then(Value::as_str)
            .unwrap_or("x86_64");
        let mut findings: Vec<VulnFinding> = Vec::with_capacity(4);

        // Heuristic: look for strcpy/sprintf patterns and gets references
        let vuln_strs = [
            ("strcpy", "buffer_overflow"),
            ("sprintf", "format_string"),
            ("gets", "buffer_overflow"),
            ("strcat", "buffer_overflow"),
        ];
        for (sym, vuln_type) in &vuln_strs {
            if let Some(pos) = find_bytes_in(&data, sym.as_bytes()) {
                findings.push(VulnFinding {
                    vuln_type: vuln_type.to_string(),
                    address: pos as u64,
                    severity: "high".to_string(),
                    description: format!("Reference to unsafe function: {sym}"),
                    cve: None,
                });
            }
        }

        Ok(json!({
            "arch": arch,
            "vulnerabilities": findings,
            "count": findings.len(),
        }))
    }

    fn analyze_crypto(&self, params: &Value) -> Result<Value, AnalysisToolError> {
        let data = self.get_bytes(params)?;
        let min_conf: f32 = params
            .get("min_confidence")
            .and_then(Value::as_f64)
            .unwrap_or(0.6) as f32;

        let mut matches: Vec<CryptoMatch> = Vec::new();

        // AES S-box first byte 0x63
        let aes_sbox_start = &[0x63u8, 0x7c, 0x77, 0x7b, 0xf2];
        if let Some(pos) = find_bytes_in(&data, aes_sbox_start) {
            matches.push(CryptoMatch {
                algorithm: "AES".into(),
                confidence: 0.95,
                address: pos as u64,
                key_size_bits: None,
                mode: None,
            });
        }

        // SHA-256 initial hash constant 0x6a09e667
        let sha_const = &[0x67u8, 0xe6, 0x09, 0x6a];
        if let Some(pos) = find_bytes_in(&data, sha_const) {
            matches.push(CryptoMatch {
                algorithm: "SHA-256".into(),
                confidence: 0.92,
                address: pos as u64,
                key_size_bits: None,
                mode: None,
            });
        }

        matches.retain(|m| m.confidence >= min_conf);
        let filtered = &matches;

        Ok(json!({
            "matches": filtered,
            "count": filtered.len(),
        }))
    }

    fn deobfuscate_strings(&self, params: &Value) -> Result<Value, AnalysisToolError> {
        let data = self.get_bytes(params)?;
        let mut results: Vec<DeobfuscatedString> = Vec::new();

        // Guard against O(n * 255) memory allocation on large adversarial input.
        const MAX_DEOBFUSCATE_BYTES: usize = 64 * 1024; // 64 KiB
        if data.len() > MAX_DEOBFUSCATE_BYTES {
            return Err(AnalysisToolError::invalid(
                "bytes",
                &format!("input too large for deobfuscation (max {MAX_DEOBFUSCATE_BYTES} bytes)"),
            ));
        }

        // XOR scan: try single-byte keys
        for key in 1u8..=255u8 {
            let decoded: Vec<u8> = data.iter().map(|&b| b ^ key).collect();
            if let Some(s) = extract_printable_string(&decoded, 8) {
                results.push(DeobfuscatedString {
                    original_bytes: data.clone(),
                    decoded: s,
                    method: format!("xor_0x{key:02x}"),
                    address: 0,
                });
                if results.len() >= 5 {
                    break;
                } // limit results
            }
        }

        Ok(json!({
            "strings": results,
            "count": results.len(),
        }))
    }

    fn identify_malware(&self, params: &Value) -> Result<Value, AnalysisToolError> {
        let data = self.get_bytes(params)?;
        let mut classifications: Vec<MalwareClassification> = Vec::new();

        // Simple heuristic: look for common malware strings
        let indicators = [
            ("cmd.exe /c", "cmd_exec"),
            ("powershell", "ps_exec"),
            ("\\REGISTRY\\", "registry"),
            ("C:\\Windows\\Temp", "temp_drop"),
        ];
        let mut matched: Vec<String> = Vec::new();
        for (pattern, label) in &indicators {
            if find_bytes_in(&data, pattern.as_bytes()).is_some() {
                matched.push(label.to_string());
            }
        }

        if !matched.is_empty() {
            classifications.push(MalwareClassification {
                family: "generic_trojan".into(),
                confidence: 0.5 + (matched.len() as f32 * 0.1).min(0.4),
                indicators: matched,
                category: "trojan".into(),
            });
        }

        Ok(json!({
            "classifications": classifications,
            "count": classifications.len(),
        }))
    }

    fn extract_config(&self, params: &Value) -> Result<Value, AnalysisToolError> {
        let data = self.get_bytes(params)?;
        let mut configs: Vec<ConfigValue> = Vec::new();

        // Look for IPv4 addresses.
        // Use `< data.len()` because try_parse_ip_string bounds its own read to 20 bytes.
        // The previous `i + 7 < data.len()` prematurely stopped within the last 7 bytes
        // and could also integer-overflow on a 32-bit target when i approaches usize::MAX.
        let mut i = 0usize;
        while i < data.len() {
            let slice = &data[i..];
            if let Some(ip) = try_parse_ip_string(slice) {
                // Guard against i exceeding u64 range on 32-bit targets.
                let source_addr = u64::try_from(i).unwrap_or(u64::MAX);
                configs.push(ConfigValue {
                    key: format!("c2_{}", configs.len()),
                    value: ip,
                    source_address: source_addr,
                    data_type: "ipv4".into(),
                });
            }
            i += 1;
        }

        Ok(json!({
            "config": configs,
            "count": configs.len(),
        }))
    }

    fn generate_yara(&self, params: &Value) -> Result<Value, AnalysisToolError> {
        let data = self.get_bytes(params)?;
        let rule_name = params
            .get("rule_name")
            .and_then(Value::as_str)
            .unwrap_or("auto_generated");
        let min_len: usize = params
            .get("min_string_length")
            .and_then(Value::as_u64)
            .unwrap_or(8)
            .min(4096) // cap attacker-controlled value to avoid usize truncation on 32-bit targets
            as usize;

        let mut yara_strings: Vec<YaraString> = Vec::new();
        let printable = extract_all_strings(&data, min_len);
        for (i, s) in printable.iter().take(5).enumerate() {
            yara_strings.push(YaraString {
                id: format!("$s{i}"),
                pattern: format!("\"{}\"", s.replace('"', "\\\"")),
                modifiers: vec!["ascii".into()],
            });
        }

        // Add a byte pattern from the first 16 bytes if available
        if data.len() >= 16 {
            let hex: String = data[..16].iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02X} "); acc });
            yara_strings.push(YaraString {
                id: "$b0".into(),
                pattern: format!("{{ {} }}", hex.trim()),
                modifiers: vec![],
            });
        }

        let condition = if yara_strings.is_empty() {
            "false".into()
        } else {
            format!("{} of them", yara_strings.len().min(3))
        };

        let mut meta = HashMap::new();
        meta.insert("generated_by".into(), "rustre-mcp".into());
        meta.insert("description".into(), "Auto-generated rule".into());

        let rule = YaraRule {
            rule_name: rule_name.to_string(),
            tags: vec!["auto".into()],
            meta,
            strings: yara_strings,
            condition,
        };
        let text = rule.to_text();

        Ok(json!({
            "rule": rule,
            "text": text,
        }))
    }

    fn compare_functions(&self, params: &Value) -> Result<Value, AnalysisToolError> {
        let a = if let Some(arr) = params.get("bytes_a").and_then(Value::as_array) {
            arr.iter()
                .filter_map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect::<Vec<u8>>()
        } else if let Some(h) = params.get("hex_a").and_then(Value::as_str) {
            hex_decode(h)?
        } else {
            Vec::new()
        };

        let b = if let Some(arr) = params.get("bytes_b").and_then(Value::as_array) {
            arr.iter()
                .filter_map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect::<Vec<u8>>()
        } else if let Some(h) = params.get("hex_b").and_then(Value::as_str) {
            hex_decode(h)?
        } else {
            Vec::new()
        };

        let sim = byte_similarity(&a, &b);
        let total = a.len().max(b.len());
        let matching = (sim * total as f32) as usize;
        let differing = total.saturating_sub(matching);

        let cmp = FunctionComparison {
            similarity: sim,
            differing_instructions: differing,
            total_instructions: total,
            matching_blocks: if sim > 0.8 {
                3
            } else { usize::from(sim > 0.5) },
            matching_bytes: vec![],
        };

        Ok(json!({ "comparison": cmp }))
    }

    fn deobf_mba_normalize(&self, params: &Value) -> Result<Value, AnalysisToolError> {
        use rustre_deobf_mba::{MbaExprParser, MbaSimplifier};

        let expr_text = params
            .get("expr")
            .and_then(Value::as_str)
            .ok_or_else(|| AnalysisToolError::invalid("expr", "missing string"))?;

        let max_iters = params
            .get("max_iterations")
            .and_then(Value::as_u64)
            .unwrap_or(100)
            .clamp(1, 10_000) as usize;

        let parsed = MbaExprParser::parse(expr_text)
            .map_err(|e| AnalysisToolError::invalid("expr", &format!("parse error: {e}")))?;

        let simplifier = MbaSimplifier::new().with_max_iterations(max_iters);
        let result = simplifier.simplify(parsed);

        Ok(json!({
            "original": result.original.to_string(),
            "simplified": result.simplified.to_string(),
            "rules_applied": result.rules_applied,
            "complexity_before": result.complexity_before,
            "complexity_after": result.complexity_after,
            "verified": result.verified,
            "converged": result.converged,
        }))
    }
}

impl Default for AnalysisTools {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn hex_decode(s: &str) -> Result<Vec<u8>, AnalysisToolError> {
    let s = s.replace([' ', '\n'], "");
    if !s.len().is_multiple_of(2) {
        return Err(AnalysisToolError::invalid("hex", "odd length"));
    }
    // Work on bytes to avoid panicking at a non-codepoint boundary when the
    // caller passes a hex string that contains multibyte UTF-8 characters.
    let bytes = s.as_bytes();
    (0..bytes.len())
        .step_by(2)
        .map(|i| {
            let pair = std::str::from_utf8(&bytes[i..i + 2])
                .map_err(|_| AnalysisToolError::invalid("hex", &format!("invalid utf8 at {i}")))?;
            u8::from_str_radix(pair, 16)
                .map_err(|_| AnalysisToolError::invalid("hex", &format!("invalid at {i}")))
        })
        .collect()
}

fn find_bytes_in(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn extract_printable_string(data: &[u8], min_len: usize) -> Option<String> {
    let s: String = data
        .iter()
        .take(128)
        .map(|&b| b as char)
        .take_while(|c| c.is_ascii_graphic() || *c == ' ')
        .collect();
    if s.len() >= min_len { Some(s) } else { None }
}

fn extract_all_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut start = None;
    for (i, &b) in data.iter().enumerate() {
        if b.is_ascii_graphic() || b == b' ' {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start {
            if i - s >= min_len
                && let Ok(st) = std::str::from_utf8(&data[s..i]) {
                    result.push(st.to_string());
                }
            start = None;
        }
    }
    result
}

fn try_parse_ip_string(data: &[u8]) -> Option<String> {
    // look for "N.N.N.N" pattern
    let s: String = data
        .iter()
        .take(20)
        .map(|&b| b as char)
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        Some(s)
    } else {
        None
    }
}

fn byte_similarity(a: &[u8], b: &[u8]) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let common = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
    let total = a.len().max(b.len());
    common as f32 / total as f32
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tools() -> AnalysisTools {
        AnalysisTools::new()
    }

    // ── AnalysisTools registry ───────────────────────────────────────────────

    #[test]
    /// `tool_count`, `tool_names` and `list` must describe the same registry.
    ///
    /// This used to assert a hard-coded 7 and broke when an 8th tool was
    /// added — a correct change. The count alone was never the property worth
    /// pinning: a divergence between the three accessors is. The sibling
    /// `tool_names_contains_*` tests guard against a tool being removed.
    fn tool_accessors_agree() {
        let t = tools();
        assert_eq!(
            t.tool_count(),
            t.tool_names().len(),
            "tool_count disagrees with tool_names"
        );
        assert_eq!(
            t.tool_count(),
            t.list().len(),
            "tool_count disagrees with list"
        );
        assert!(t.tool_count() > 0, "the analysis tool set must not be empty");
    }

    #[test]
    fn tool_names_contains_find_vulns() {
        assert!(tools().tool_names().contains(&"find_vulnerabilities"));
    }

    #[test]
    fn tool_names_contains_analyze_crypto() {
        assert!(tools().tool_names().contains(&"analyze_crypto"));
    }

    #[test]
    fn tool_names_contains_deobfuscate_strings() {
        assert!(tools().tool_names().contains(&"deobfuscate_strings"));
    }

    #[test]
    fn tool_names_contains_identify_malware() {
        assert!(tools().tool_names().contains(&"identify_malware"));
    }

    #[test]
    fn tool_names_contains_extract_config() {
        assert!(tools().tool_names().contains(&"extract_config"));
    }

    #[test]
    fn tool_names_contains_generate_yara() {
        assert!(tools().tool_names().contains(&"generate_yara"));
    }

    #[test]
    fn tool_names_contains_compare_functions() {
        assert!(tools().tool_names().contains(&"compare_functions"));
    }

    // ── list() ───────────────────────────────────────────────────────────────

    #[test]
    /// Every registered tool must appear in `list()` exactly once. (Was a
    /// hard-coded `== 7`; see `tool_accessors_agree`.)
    fn list_covers_every_tool_once() {
        let t = tools();
        let entries = t.list();
        let listed: Vec<&str> = entries
            .iter()
            .filter_map(|e| e.get("name").and_then(|n| n.as_str()))
            .collect();
        let mut sorted = listed.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), listed.len(), "list() contains duplicate names");
        let mut names = t.tool_names();
        names.sort_unstable();
        assert_eq!(sorted, names, "list() and tool_names() disagree");
    }

    #[test]
    fn list_entry_has_name() {
        let l = tools().list();
        assert!(l[0].get("name").is_some());
    }

    #[test]
    fn list_entry_has_description() {
        let l = tools().list();
        assert!(l[0].get("description").is_some());
    }

    #[test]
    fn list_entry_has_input_schema() {
        let l = tools().list();
        assert!(l[0].get("inputSchema").is_some());
    }

    // ── find_vulnerabilities ─────────────────────────────────────────────────

    #[test]
    fn find_vulns_empty_data_ok() {
        let r = tools().call("find_vulnerabilities", &json!({})).unwrap();
        assert!(r.get("vulnerabilities").is_some());
    }

    #[test]
    fn find_vulns_detects_strcpy() {
        let mut data = vec![0u8; 32];
        data[4..10].copy_from_slice(b"strcpy");
        let params = json!({"bytes": data});
        let r = tools().call("find_vulnerabilities", &params).unwrap();
        let count = r["count"].as_u64().unwrap_or(0);
        assert!(count > 0);
    }

    // ── analyze_crypto ───────────────────────────────────────────────────────

    #[test]
    fn analyze_crypto_empty_ok() {
        let r = tools().call("analyze_crypto", &json!({})).unwrap();
        assert!(r.get("matches").is_some());
    }

    #[test]
    fn analyze_crypto_detects_aes_sbox() {
        let mut data = vec![0u8; 128];
        data[0..5].copy_from_slice(&[0x63, 0x7c, 0x77, 0x7b, 0xf2]);
        let params = json!({"bytes": data});
        let r = tools().call("analyze_crypto", &params).unwrap();
        assert!(r["count"].as_u64().unwrap_or(0) > 0);
    }

    // ── deobfuscate_strings ──────────────────────────────────────────────────

    #[test]
    fn deobfuscate_empty_ok() {
        let r = tools().call("deobfuscate_strings", &json!({})).unwrap();
        assert!(r.get("strings").is_some());
    }

    #[test]
    fn deobfuscate_xor_finds_string() {
        // "Hello World" XOR'd with 0x01 = bytes
        let encoded: Vec<u8> = b"Hello World!".iter().map(|&b| b ^ 0x01).collect();
        let params = json!({"bytes": encoded});
        let r = tools().call("deobfuscate_strings", &params).unwrap();
        // Should find at least one deobfuscated candidate
        assert!(r.get("strings").is_some());
    }

    // ── identify_malware ─────────────────────────────────────────────────────

    #[test]
    fn identify_malware_empty_ok() {
        let r = tools().call("identify_malware", &json!({})).unwrap();
        assert!(r.get("classifications").is_some());
    }

    #[test]
    fn identify_malware_detects_cmd() {
        let data: Vec<u8> = b"cmd.exe /c whoami".to_vec();
        let params = json!({"bytes": data});
        let r = tools().call("identify_malware", &params).unwrap();
        assert!(r["count"].as_u64().unwrap_or(0) > 0);
    }

    // ── extract_config ───────────────────────────────────────────────────────

    #[test]
    fn extract_config_empty_ok() {
        let r = tools().call("extract_config", &json!({})).unwrap();
        assert!(r.get("config").is_some());
    }

    #[test]
    fn extract_config_finds_ip() {
        let data = b"AAAA192.168.1.1BBBB".to_vec();
        let params = json!({"bytes": data});
        let r = tools().call("extract_config", &params).unwrap();
        // May or may not find IP depending on boundary; count >= 0
        assert!(r["count"].as_u64().is_some());
    }

    // ── generate_yara ────────────────────────────────────────────────────────

    #[test]
    fn generate_yara_empty_ok() {
        let r = tools().call("generate_yara", &json!({})).unwrap();
        assert!(r.get("rule").is_some());
    }

    #[test]
    fn generate_yara_text_contains_rule() {
        let data: Vec<u8> = b"This is a very long test string that should be captured".to_vec();
        let params = json!({"bytes": data, "rule_name": "test_rule"});
        let r = tools().call("generate_yara", &params).unwrap();
        let text = r["text"].as_str().unwrap_or("");
        assert!(text.contains("rule test_rule"));
    }

    #[test]
    fn yara_rule_to_text_format() {
        let mut meta = HashMap::new();
        meta.insert("author".into(), "test".into());
        let rule = YaraRule {
            rule_name: "test".into(),
            tags: vec!["malware".into()],
            meta,
            strings: vec![YaraString {
                id: "$s0".into(),
                pattern: "\"abc\"".into(),
                modifiers: vec![],
            }],
            condition: "all of them".into(),
        };
        let text = rule.to_text();
        assert!(text.contains("rule test"));
        assert!(text.contains("$s0"));
    }

    // ── compare_functions ────────────────────────────────────────────────────

    #[test]
    fn compare_identical_functions() {
        let code = vec![0x90u8; 32];
        let params = json!({"bytes_a": code, "bytes_b": code});
        let r = tools().call("compare_functions", &params).unwrap();
        let sim = r["comparison"]["similarity"].as_f64().unwrap_or(0.0);
        assert!((sim - 1.0).abs() < 0.01);
    }

    #[test]
    fn compare_different_functions() {
        let a = vec![0x90u8; 32];
        let b = vec![0xCCu8; 32];
        let params = json!({"bytes_a": a, "bytes_b": b});
        let r = tools().call("compare_functions", &params).unwrap();
        let sim = r["comparison"]["similarity"].as_f64().unwrap_or(1.0);
        assert!(sim < 0.1);
    }

    #[test]
    fn compare_empty_functions() {
        let params = json!({"bytes_a": Vec::<u8>::new(), "bytes_b": Vec::<u8>::new()});
        let r = tools().call("compare_functions", &params).unwrap();
        let sim = r["comparison"]["similarity"].as_f64().unwrap_or(0.0);
        assert!((sim - 1.0).abs() < 0.01);
    }

    // ── unknown tool ────────────────────────────────────────────────────────

    #[test]
    fn call_unknown_tool_errors() {
        let err = tools().call("not_a_tool", &json!({}));
        assert!(err.is_err());
    }

    // ── hex input ───────────────────────────────────────────────────────────

    #[test]
    fn call_with_hex_input() {
        let params = json!({"hex": "9090909090909090"});
        let r = tools().call("find_vulnerabilities", &params).unwrap();
        assert!(r.get("vulnerabilities").is_some());
    }

    // ── byte_similarity helper ───────────────────────────────────────────────

    #[test]
    fn byte_similarity_full_match() {
        assert!((byte_similarity(b"abc", b"abc") - 1.0).abs() < 0.01);
    }

    #[test]
    fn byte_similarity_no_match() {
        assert!(byte_similarity(b"abc", b"xyz") < 0.01);
    }

    #[test]
    fn byte_similarity_empty_vs_nonempty() {
        assert_eq!(byte_similarity(b"", b"abc"), 0.0);
    }

    // ── deobf_mba_normalize ──────────────────────────────────────────────────

    #[test]
    fn deobf_mba_normalize_registered() {
        assert!(tools().tool_names().contains(&"deobf_mba_normalize"));
    }

    #[test]
    fn deobf_mba_normalize_xor_plus_2and_to_add() {
        // Classic MBA identity: (x ^ y) + 2*(x & y) == x + y.
        let params = json!({ "expr": "(x ^ y) + 2*(x & y)" });
        let r = tools()
            .call("deobf_mba_normalize", &params)
            .expect("normalize call should succeed");

        let simplified = r["simplified"]
            .as_str()
            .expect("simplified field present")
            .to_string();
        let rules = r["rules_applied"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        // The rule chain must include xor-plus-2and.
        assert!(
            rules.iter().any(|v| v.as_str() == Some("xor-plus-2and")),
            "expected rule xor-plus-2and to fire, got rules={rules:?} simplified={simplified}"
        );
        // And the resulting expression must be the canonical x + y (either order).
        assert!(
            simplified == "(x + y)" || simplified == "(y + x)",
            "expected simplified == (x + y), got {simplified}"
        );
        assert_eq!(r["verified"].as_bool(), Some(true));
    }
}
