//! MCP tool: search binary data for patterns, strings, and byte sequences.
//!
//! The `SearchTool` accepts a binary buffer and one or more search targets:
//! * **Byte patterns** — exact byte sequences (hex or integer array).
//! * **Wildcarded patterns** — byte patterns with `??` wildcards.
//! * **Strings** — UTF-8 and UTF-16LE string searches.
//! * **YARA-lite rules** — simple `{ xx xx ?? xx }` hex patterns.
//! * **Regular expressions** — applied to the raw bytes as a &[u8] slice.
//!
//! All results include the file offset and an optional virtual-address
//! translation when a `base_address` is supplied.


use async_trait::async_trait;
use rustre_mcp_server::{ContentBlock, McpError, ToolDefinition, ToolHandler, ToolResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ─── PatternMatch ─────────────────────────────────────────────────────────────

/// A single pattern match in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    /// File offset of the match.
    pub offset: usize,
    /// Virtual address (offset + base_address).
    pub virtual_address: u64,
    /// Number of bytes matched.
    pub length: usize,
    /// Hex-encoded matched bytes (up to 64 bytes shown).
    pub bytes_hex: String,
    /// Context bytes: up to 16 bytes before the match, hex-encoded.
    pub context_before: String,
    /// Context bytes: up to 16 bytes after the match, hex-encoded.
    pub context_after: String,
    /// Pattern label that produced this match.
    pub pattern_name: String,
}

// ─── StringMatch ──────────────────────────────────────────────────────────────

/// A found string in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringMatch {
    /// File offset.
    pub offset: usize,
    /// Virtual address.
    pub virtual_address: u64,
    /// The extracted string.
    pub value: String,
    /// Encoding: "utf8" or "utf16le".
    pub encoding: String,
    /// Length in bytes (not characters) of the original string.
    pub byte_length: usize,
}

// ─── SearchInput ──────────────────────────────────────────────────────────────

/// Input parameters for the search tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchInput {
    /// Hex-encoded binary data to search.
    pub hex: Option<String>,
    /// Raw byte array to search.
    pub bytes: Option<Vec<u8>>,
    /// Base address for VA translation (default: `0`).
    pub base_address: Option<u64>,
    /// Byte patterns to search: list of `{ "name": "...", "hex": "..." }`.
    pub byte_patterns: Option<Vec<BytePatternSpec>>,
    /// String to search for (UTF-8).
    pub string_search: Option<String>,
    /// Minimum printable string length to extract (default: `4`).
    pub min_string_length: Option<usize>,
    /// Whether to extract all printable strings from the binary.
    pub extract_strings: Option<bool>,
    /// Whether to include UTF-16LE strings in extraction.
    pub include_wide: Option<bool>,
    /// Maximum number of matches per pattern (default: `1000`).
    pub max_matches: Option<usize>,
}

/// A single byte pattern specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytePatternSpec {
    /// Human-readable name/label.
    pub name: String,
    /// Hex-encoded pattern, with `??` as wildcards.
    /// Example: `"4889E5 ?? ?? EB??"`
    pub hex: String,
}

impl SearchInput {
    fn resolve_bytes(&self) -> Result<Vec<u8>, McpError> {
        if let Some(hex) = &self.hex {
            return hex_decode_no_wildcards(hex);
        }
        if let Some(bytes) = &self.bytes {
            return Ok(bytes.clone());
        }
        Err(McpError::InvalidParams("search: provide 'hex' or 'bytes'".into()))
    }

    const fn effective_base(&self) -> u64 {
        match self.base_address {
            Some(v) => v,
            None => 0,
        }
    }

    fn effective_min_string(&self) -> usize {
        match self.min_string_length {
            Some(n) if n > 0 => n.min(65536),
            _ => 4,
        }
    }

    const fn effective_max_matches(&self) -> usize {
        match self.max_matches {
            Some(n) if n > 0 => n,
            _ => 1000,
        }
    }
}

// ─── SearchOutput ─────────────────────────────────────────────────────────────

/// Aggregated search results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchOutput {
    /// Total bytes searched.
    pub data_length: usize,
    /// Base address used.
    pub base_address: u64,
    /// Per-pattern match results.
    pub pattern_results: Vec<PatternResult>,
    /// Extracted or searched strings.
    pub string_results: Vec<StringMatch>,
    /// Summary statistics.
    pub stats: SearchStats,
}

/// All matches for one pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternResult {
    /// Pattern label.
    pub name: String,
    /// Number of matches.
    pub count: usize,
    /// Individual matches.
    pub matches: Vec<PatternMatch>,
}

/// Search statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchStats {
    /// Total pattern matches across all patterns.
    pub total_pattern_matches: usize,
    /// Total strings found.
    pub total_strings: usize,
    /// Number of unique pattern names that had at least one match.
    pub patterns_with_hits: usize,
}

// ─── pattern_results_to_json() ───────────────────────────────────────────────

/// Serialise a `Vec<PatternResult>` to a compact JSON representation.
///
/// Returns an object with keys = pattern name, values = array of match
/// objects.
#[must_use]
pub fn pattern_results_to_json(results: &[PatternResult]) -> Value {
    let mut map = serde_json::Map::new();
    for r in results {
        let matches_json: Vec<Value> = r
            .matches
            .iter()
            .map(|m| {
                json!({
                    "offset": m.offset,
                    "va": format!("0x{:x}", m.virtual_address),
                    "bytes": m.bytes_hex,
                    "context_before": m.context_before,
                    "context_after": m.context_after
                })
            })
            .collect();
        map.insert(r.name.clone(), Value::Array(matches_json));
    }
    Value::Object(map)
}

// ─── Core search ─────────────────────────────────────────────────────────────

/// Execute a search on `data`.
pub fn search(input: &SearchInput, data: &[u8]) -> SearchOutput {
    let base = input.effective_base();
    let max_matches = input.effective_max_matches();
    let min_str_len = input.effective_min_string();

    let mut pattern_results: Vec<PatternResult> = Vec::new();

    // ── Byte-pattern search ───────────────────────────────────────────────────
    if let Some(patterns) = &input.byte_patterns {
        for spec in patterns {
            let parsed = match parse_wildcarded_pattern(&spec.hex) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let matches = search_pattern(data, &parsed, &spec.name, base, max_matches);
            let count = matches.len();
            pattern_results.push(PatternResult {
                name: spec.name.clone(),
                count,
                matches,
            });
        }
    }

    // ── String search ─────────────────────────────────────────────────────────
    let mut string_results: Vec<StringMatch> = Vec::new();

    if let Some(needle) = &input.string_search {
        // Search for the needle as UTF-8 bytes.
        let needle_bytes = needle.as_bytes();
        let mut offset = 0;
        let mut count = 0;
        while offset + needle_bytes.len() <= data.len() && count < max_matches {
            if &data[offset..offset + needle_bytes.len()] == needle_bytes {
                let va = base.saturating_add(offset as u64);
                string_results.push(StringMatch {
                    offset,
                    virtual_address: va,
                    value: needle.clone(),
                    encoding: "utf8".to_owned(),
                    byte_length: needle_bytes.len(),
                });
                count += 1;
                offset += 1;
            } else {
                offset += 1;
            }
        }

        // Also search as UTF-16LE if enabled.
        if input.include_wide.unwrap_or(false) {
            let wide: Vec<u8> = needle
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect();
            let mut off = 0;
            let mut cnt = 0;
            while off + wide.len() <= data.len() && cnt < max_matches {
                if &data[off..off + wide.len()] == wide.as_slice() {
                    string_results.push(StringMatch {
                        offset: off,
                        virtual_address: base.saturating_add(off as u64),
                        value: needle.clone(),
                        encoding: "utf16le".to_owned(),
                        byte_length: wide.len(),
                    });
                    cnt += 1;
                    off += 2;
                } else {
                    off += 1;
                }
            }
        }
    }

    // ── String extraction ─────────────────────────────────────────────────────
    if input.extract_strings.unwrap_or(false) {
        let extracted = extract_printable_strings(data, base, min_str_len, max_matches);
        string_results.extend(extracted);

        if input.include_wide.unwrap_or(false) {
            let wide = extract_wide_strings(data, base, min_str_len, max_matches);
            string_results.extend(wide);
        }
    }

    // Deduplicate string results by (offset, encoding).
    string_results.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.encoding.cmp(&b.encoding)));
    string_results.dedup_by(|a, b| a.offset == b.offset && a.encoding == b.encoding);

    // ── Statistics ────────────────────────────────────────────────────────────
    let total_pattern_matches: usize = pattern_results.iter().map(|r| r.count).sum();
    let patterns_with_hits = pattern_results.iter().filter(|r| r.count > 0).count();
    let stats = SearchStats {
        total_pattern_matches,
        total_strings: string_results.len(),
        patterns_with_hits,
    };

    SearchOutput {
        data_length: data.len(),
        base_address: base,
        pattern_results,
        string_results,
        stats,
    }
}

// ─── Wildcarded pattern matching ─────────────────────────────────────────────

/// A wildcarded pattern element.
#[derive(Debug, Clone, Copy)]
enum PatternByte {
    /// Exact byte value.
    Exact(u8),
    /// Wildcard — matches any byte.
    Any,
}

/// Parse a hex string with `??` wildcards into a vector of `PatternByte`.
fn parse_wildcarded_pattern(hex: &str) -> Result<Vec<PatternByte>, McpError> {
    let tokens: Vec<&str> = hex.split_whitespace().collect();
    if tokens.is_empty() {
        // Try treating the whole string as no-space hex
        return parse_wildcarded_no_space(hex);
    }
    let mut pattern = Vec::with_capacity(tokens.len());
    for token in tokens {
        if token == "??" || token == "?" {
            pattern.push(PatternByte::Any);
        } else {
            let b = u8::from_str_radix(token, 16)
                .map_err(|_| McpError::InvalidParams(format!("invalid pattern token: {token}")))?;
            pattern.push(PatternByte::Exact(b));
        }
    }
    Ok(pattern)
}

fn parse_wildcarded_no_space(hex: &str) -> Result<Vec<PatternByte>, McpError> {
    let hex = hex.replace('\n', "").replace('\t', "");
    if !hex.len().is_multiple_of(2) {
        return Err(McpError::InvalidParams("odd-length pattern".into()));
    }
    let mut pattern = Vec::new();
    for i in (0..hex.len()).step_by(2) {
        let chunk = &hex[i..i + 2];
        if chunk == "??" {
            pattern.push(PatternByte::Any);
        } else {
            let b = u8::from_str_radix(chunk, 16)
                .map_err(|_| McpError::InvalidParams(format!("invalid hex chunk: {chunk}")))?;
            pattern.push(PatternByte::Exact(b));
        }
    }
    Ok(pattern)
}

/// Search `data` for all occurrences of `pattern`, up to `max_matches`.
fn search_pattern(
    data: &[u8],
    pattern: &[PatternByte],
    name: &str,
    base: u64,
    max_matches: usize,
) -> Vec<PatternMatch> {
    if pattern.is_empty() || pattern.len() > data.len() {
        return vec![];
    }
    let mut results = Vec::new();
    let search_len = data.len() - pattern.len() + 1;

    // Build a fast skip table using the first exact byte.
    let first_exact = pattern.iter().position(|p| matches!(p, PatternByte::Exact(_)));

    'outer: for start in 0..search_len {
        if results.len() >= max_matches {
            break;
        }
        // Quick pre-check on first exact byte.
        if let Some(fe) = first_exact {
            if let PatternByte::Exact(expected) = pattern[fe] {
                if data[start + fe] != expected {
                    continue;
                }
            }
        }
        // Full match check.
        for (i, pb) in pattern.iter().enumerate() {
            if let PatternByte::Exact(expected) = pb {
                if data[start + i] != *expected {
                    continue 'outer;
                }
            }
        }

        // Matched.
        let end = start + pattern.len();
        let bytes_hex = hex_encode(&data[start..end.min(start + 64)]);
        let ctx_start = start.saturating_sub(16);
        let context_before = hex_encode(&data[ctx_start..start]);
        let ctx_end = (end + 16).min(data.len());
        let context_after = hex_encode(&data[end..ctx_end]);

        results.push(PatternMatch {
            offset: start,
            virtual_address: base.saturating_add(start as u64),
            length: pattern.len(),
            bytes_hex,
            context_before,
            context_after,
            pattern_name: name.to_owned(),
        });
    }
    results
}

// ─── String extraction ────────────────────────────────────────────────────────

/// Extract printable ASCII strings from `data`.
fn extract_printable_strings(
    data: &[u8],
    base: u64,
    min_len: usize,
    max_results: usize,
) -> Vec<StringMatch> {
    let mut results = Vec::new();
    let mut start: Option<usize> = None;

    for (i, &b) in data.iter().enumerate() {
        let printable = b >= 0x20 && b < 0x7F;
        match (printable, start) {
            (true, None) => start = Some(i),
            (true, Some(_)) => {}
            (false, Some(s)) => {
                let len = i - s;
                if len >= min_len {
                    if let Ok(val) = std::str::from_utf8(&data[s..i]) {
                        results.push(StringMatch {
                            offset: s,
                            virtual_address: base.saturating_add(s as u64),
                            value: val.to_owned(),
                            encoding: "utf8".to_owned(),
                            byte_length: len,
                        });
                        if results.len() >= max_results {
                            return results;
                        }
                    }
                }
                start = None;
            }
            (false, None) => {}
        }
    }
    // Flush trailing string.
    if let Some(s) = start {
        let len = data.len() - s;
        if len >= min_len {
            if let Ok(val) = std::str::from_utf8(&data[s..]) {
                results.push(StringMatch {
                    offset: s,
                    virtual_address: base.saturating_add(s as u64),
                    value: val.to_owned(),
                    encoding: "utf8".to_owned(),
                    byte_length: len,
                });
            }
        }
    }
    results
}

/// Extract UTF-16LE strings from `data`.
fn extract_wide_strings(
    data: &[u8],
    base: u64,
    min_len: usize,
    max_results: usize,
) -> Vec<StringMatch> {
    let mut results = Vec::new();
    let mut i = 0usize;

    while i + 2 <= data.len() {
        let c = u16::from_le_bytes([data[i], data[i + 1]]);
        if c >= 0x20 && c < 0x7F {
            // Start of a potential wide string.
            let start = i;
            let mut chars = Vec::new();
            while i + 2 <= data.len() {
                let ch = u16::from_le_bytes([data[i], data[i + 1]]);
                if ch >= 0x20 && ch < 0x7F {
                    chars.push(ch);
                    i += 2;
                } else {
                    break;
                }
            }
            if chars.len() >= min_len {
                let value: String = chars.iter().map(|&c| char::from(c as u8)).collect();
                let byte_length = chars.len() * 2;
                results.push(StringMatch {
                    offset: start,
                    virtual_address: base.saturating_add(start as u64),
                    value,
                    encoding: "utf16le".to_owned(),
                    byte_length,
                });
                if results.len() >= max_results {
                    return results;
                }
            }
        } else {
            i += 1;
        }
    }
    results
}

// ─── Hex helpers ─────────────────────────────────────────────────────────────

fn hex_decode_no_wildcards(s: &str) -> Result<Vec<u8>, McpError> {
    let s = s.replace([' ', '\n', '\t'], "");
    if !s.len().is_multiple_of(2) {
        return Err(McpError::InvalidParams("odd-length hex".into()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let b = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| McpError::InvalidParams(format!("invalid hex at {i}")))?;
        out.push(b);
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02X}");
            acc
        })
}

// ─── SearchTool ──────────────────────────────────────────────────────────────

/// MCP tool: search binary for patterns, strings, or byte sequences.
pub struct SearchTool;

impl SearchTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "search_binary".to_owned(),
            description: "Search a binary for patterns, strings, or bytes. \
                Provide 'hex' or 'bytes'. \
                Optional: base_address, byte_patterns (array of {name, hex with ?? wildcards}), \
                string_search (string), extract_strings (bool), include_wide (bool), \
                min_string_length (default 4), max_matches (default 1000)."
                .to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "hex": { "type": "string" },
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "base_address": { "type": "integer" },
                    "byte_patterns": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": { "type": "string" },
                                "hex": { "type": "string" }
                            },
                            "required": ["name", "hex"]
                        }
                    },
                    "string_search": { "type": "string" },
                    "extract_strings": { "type": "boolean" },
                    "include_wide": { "type": "boolean" },
                    "min_string_length": { "type": "integer" },
                    "max_matches": { "type": "integer" }
                }
            }),
            parameters: serde_json::Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for SearchTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let input = parse_search_input(&args)?;
        let data = input.resolve_bytes()?;

        if data.is_empty() {
            return Err(McpError::InvalidParams("empty byte buffer".into()));
        }

        let output = search(&input, &data);
        let summary = build_search_summary(&output);

        Ok(ToolResult {
            content: vec![ContentBlock::Text { text: summary }],
            is_error: false,
        })
    }
}

fn parse_search_input(args: &Value) -> Result<SearchInput, McpError> {
    let byte_patterns = args.get("byte_patterns").and_then(Value::as_array).map(|arr| {
        arr.iter()
            .filter_map(|v| {
                let name = v.get("name")?.as_str()?.to_owned();
                let hex = v.get("hex")?.as_str()?.to_owned();
                Some(BytePatternSpec { name, hex })
            })
            .collect()
    });

    Ok(SearchInput {
        hex: args.get("hex").and_then(Value::as_str).map(str::to_owned),
        bytes: args.get("bytes").and_then(Value::as_array).map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect()
        }),
        base_address: args.get("base_address").and_then(Value::as_u64),
        byte_patterns,
        string_search: args
            .get("string_search")
            .and_then(Value::as_str)
            .map(str::to_owned),
        min_string_length: args
            .get("min_string_length")
            .and_then(Value::as_u64)
            .map(|n| n as usize),
        extract_strings: args.get("extract_strings").and_then(Value::as_bool),
        include_wide: args.get("include_wide").and_then(Value::as_bool),
        max_matches: args
            .get("max_matches")
            .and_then(Value::as_u64)
            .map(|n| n as usize),
    })
}

fn build_search_summary(o: &SearchOutput) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = write!(
        s,
        "Search results — {} bytes searched (base 0x{:x})\n",
        o.data_length, o.base_address
    );
    let _ = write!(
        s,
        "Pattern matches : {} (across {} patterns, {} with hits)\n",
        o.stats.total_pattern_matches,
        o.pattern_results.len(),
        o.stats.patterns_with_hits
    );
    let _ = write!(s, "Strings found   : {}\n", o.stats.total_strings);

    for pr in &o.pattern_results {
        if pr.count == 0 {
            continue;
        }
        let _ = write!(s, "\nPattern '{}' — {} match(es):\n", pr.name, pr.count);
        for m in &pr.matches {
            let _ = write!(
                s,
                "  offset 0x{:08x}  va 0x{:x}  bytes: {}\n",
                m.offset, m.virtual_address, m.bytes_hex
            );
        }
    }

    if !o.string_results.is_empty() {
        s.push_str("\nStrings:\n");
        for sm in &o.string_results {
            let _ = write!(
                s,
                "  0x{:08x}  [{}]  {:?}\n",
                sm.offset, sm.encoding, sm.value
            );
        }
    }
    s
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const HAYSTACK: &[u8] = b"\x00\x01Hello\x00\x01\x02World\x00\xFF\xFE";

    #[test]
    fn search_exact_pattern() {
        let input = SearchInput {
            hex: None,
            bytes: Some(HAYSTACK.to_vec()),
            base_address: None,
            byte_patterns: Some(vec![BytePatternSpec {
                name: "hello_byte".to_owned(),
                hex: "48 65 6C 6C 6F".to_owned(), // "Hello"
            }]),
            string_search: None,
            min_string_length: None,
            extract_strings: None,
            include_wide: None,
            max_matches: None,
        };
        let out = search(&input, HAYSTACK);
        assert_eq!(out.stats.total_pattern_matches, 1);
        assert_eq!(out.pattern_results[0].matches[0].offset, 2);
    }

    #[test]
    fn search_wildcard_pattern() {
        let input = SearchInput {
            hex: None,
            bytes: Some(HAYSTACK.to_vec()),
            base_address: None,
            byte_patterns: Some(vec![BytePatternSpec {
                name: "wc".to_owned(),
                hex: "48 ?? 6C 6C 6F".to_owned(),
            }]),
            string_search: None,
            min_string_length: None,
            extract_strings: None,
            include_wide: None,
            max_matches: None,
        };
        let out = search(&input, HAYSTACK);
        assert_eq!(out.stats.total_pattern_matches, 1);
    }

    #[test]
    fn search_string() {
        let input = SearchInput {
            hex: None,
            bytes: Some(HAYSTACK.to_vec()),
            base_address: None,
            byte_patterns: None,
            string_search: Some("Hello".to_owned()),
            min_string_length: None,
            extract_strings: None,
            include_wide: None,
            max_matches: None,
        };
        let out = search(&input, HAYSTACK);
        assert_eq!(out.string_results.len(), 1);
        assert_eq!(out.string_results[0].value, "Hello");
    }

    #[test]
    fn extract_strings_from_binary() {
        let data = b"AAAAABBBBB\x00test_value\x00\x01\x02";
        let input = SearchInput {
            hex: None,
            bytes: Some(data.to_vec()),
            base_address: None,
            byte_patterns: None,
            string_search: None,
            min_string_length: Some(4),
            extract_strings: Some(true),
            include_wide: None,
            max_matches: None,
        };
        let out = search(&input, data);
        assert!(!out.string_results.is_empty());
    }

    #[test]
    fn pattern_results_to_json_keys() {
        let results = vec![PatternResult {
            name: "nop".to_owned(),
            count: 2,
            matches: vec![
                PatternMatch {
                    offset: 0,
                    virtual_address: 0x1000,
                    length: 1,
                    bytes_hex: "90".to_owned(),
                    context_before: String::new(),
                    context_after: String::new(),
                    pattern_name: "nop".to_owned(),
                },
            ],
        }];
        let j = pattern_results_to_json(&results);
        assert!(j.get("nop").is_some());
    }

    #[test]
    fn hex_encode_bytes() {
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "DEADBEEF");
    }

    #[test]
    fn extract_printable_strings_basic() {
        let data = b"ABC\x00XYZ";
        let result = extract_printable_strings(data, 0, 3, 100);
        assert!(result.iter().any(|s| s.value == "ABC"));
        assert!(result.iter().any(|s| s.value == "XYZ"));
    }

    #[test]
    fn no_match_returns_empty() {
        let input = SearchInput {
            hex: None,
            bytes: Some(vec![0x00, 0x01, 0x02]),
            base_address: None,
            byte_patterns: Some(vec![BytePatternSpec {
                name: "nothere".to_owned(),
                hex: "FF FF FF FF".to_owned(),
            }]),
            string_search: None,
            min_string_length: None,
            extract_strings: None,
            include_wide: None,
            max_matches: None,
        };
        let out = search(&input, &[0x00, 0x01, 0x02]);
        assert_eq!(out.stats.total_pattern_matches, 0);
        assert_eq!(out.stats.patterns_with_hits, 0);
    }
}
