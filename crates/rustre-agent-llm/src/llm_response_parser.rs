//! `llm_response_parser` — Parse LLM responses for reverse-engineering tasks.
//!
//! Provides [`LlmResponseParser`], [`ParsedResponse`], [`RenameCandidate`], [`CodeBlock`],
//! and the [`extract_code_blocks`] helper.

use std::collections::HashMap;

// ── CodeBlock ─────────────────────────────────────────────────────────────────

/// A fenced code block extracted from an LLM response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeBlock {
    /// Language tag from the fence (empty if not specified).
    pub language: String,
    /// The raw content inside the fence.
    pub content: String,
    /// Byte offset in the original response where this block starts.
    pub start_offset: usize,
    /// Byte offset in the original response where this block ends (exclusive).
    pub end_offset: usize,
}

impl CodeBlock {
    /// Whether the block has a non-empty language tag.
    #[must_use]
    pub const fn has_language(&self) -> bool {
        !self.language.is_empty()
    }

    /// Trim leading/trailing whitespace from the content.
    #[must_use]
    pub fn trimmed_content(&self) -> &str {
        self.content.trim()
    }

    /// Number of non-empty lines in the content.
    #[must_use]
    pub fn line_count(&self) -> usize {
        self.content.lines().filter(|l| !l.trim().is_empty()).count()
    }
}

/// Extract all fenced code blocks from a markdown-formatted LLM response.
///
/// Supports triple-backtick fences with an optional language tag on the
/// opening fence.  Nested fences are not supported.
#[must_use]
pub fn extract_code_blocks(text: &str) -> Vec<CodeBlock> {
    let mut blocks = Vec::new();
    let mut i = 0usize;
    let bytes = text.as_bytes();
    let len = bytes.len();

    while i < len {
        // Find the opening "```"
        if let Some(fence_start) = find_fence_start(text, i) {
            let fence_line_end = text[fence_start..]
                .find('\n')
                .map_or(len - fence_start, |n| n)
                + fence_start;

            // Extract language tag (rest of the opening fence line after the
            // fence). The opening run may be longer than three backticks, and
            // its true length must be preserved: hard-coding 3 would leave the
            // surplus backticks to be misread as part of the language tag, and
            // would let a plain ``` line close a ```` block early.
            let fence_len = fence_run_len(text, fence_start);
            let lang_raw = text[fence_start + fence_len..fence_line_end].trim();
            let language = lang_raw.to_string();

            let content_start = fence_line_end + 1;
            if content_start >= len {
                break;
            }

            // Find the closing "```" on its own line
            if let Some(close_rel) = find_fence_close(&text[content_start..], fence_len) {
                let content = text[content_start..content_start + close_rel].to_string();
                let block_end = content_start + close_rel + fence_len;
                blocks.push(CodeBlock {
                    language,
                    content,
                    start_offset: fence_start,
                    end_offset: block_end.min(len),
                });
                i = block_end.min(len);
            } else {
                // No closing fence — take rest of text as content
                let content = text[content_start..].to_string();
                blocks.push(CodeBlock {
                    language,
                    content,
                    start_offset: fence_start,
                    end_offset: len,
                });
                break;
            }
        } else {
            break;
        }
    }

    blocks
}

fn find_fence_start(text: &str, from: usize) -> Option<usize> {
    let sub = &text[from..];
    let mut idx = 0;
    while idx < sub.len() {
        // Must be at start of line (or very start of text)
        let at_line_start = idx == 0 || sub.as_bytes().get(idx - 1) == Some(&b'\n');
        if at_line_start && sub[idx..].starts_with("```") {
            return Some(from + idx);
        }
        // Advance to next newline
        if let Some(nl) = sub[idx..].find('\n') {
            idx += nl + 1;
        } else {
            break;
        }
    }
    None
}

/// Length of the run of backticks starting at `at`, in bytes.
fn fence_run_len(text: &str, at: usize) -> usize {
    text.as_bytes()[at..]
        .iter()
        .take_while(|&&b| b == b'`')
        .count()
}

/// Find the fence that closes a block opened with `fence_len` backticks.
///
/// The closer must be a run of exactly `fence_len` backticks at the start of a
/// line: a shorter run does not terminate the block, and a longer one is
/// content belonging to it.
fn find_fence_close(text: &str, fence_len: usize) -> Option<usize> {
    let opening = "`".repeat(fence_len);
    let mut idx = 0;
    while idx < text.len() {
        let at_line_start = idx == 0 || text.as_bytes().get(idx - 1) == Some(&b'\n');
        if at_line_start && text[idx..].starts_with(&opening) {
            // Ensure the fence is followed by newline or end-of-string (not more backticks)
            let after = text.as_bytes().get(idx + fence_len).copied();
            if after.is_none() || after == Some(b'\n') || after == Some(b'\r') {
                return Some(idx);
            }
        }
        if let Some(nl) = text[idx..].find('\n') {
            idx += nl + 1;
        } else {
            break;
        }
    }
    None
}

// ── RenameCandidate ───────────────────────────────────────────────────────────

/// A proposed symbol rename extracted from an LLM rename response.
#[derive(Debug, Clone)]
pub struct RenameCandidate {
    /// Current (old) symbol name.
    pub old_name: String,
    /// Proposed new name.
    pub new_name: String,
    /// Confidence score in [0.0, 1.0].
    pub confidence: f64,
    /// Optional rationale provided by the LLM.
    pub rationale: Option<String>,
    /// Optional resolved address if the old name includes one.
    pub address: Option<u64>,
}

impl RenameCandidate {
    /// Whether the confidence is above a given threshold.
    #[must_use]
    pub fn is_high_confidence(&self, threshold: f64) -> bool {
        self.confidence >= threshold
    }

    /// Whether the new name is different from the old name.
    #[must_use]
    pub fn is_actual_rename(&self) -> bool {
        self.old_name != self.new_name
    }

    /// Return the new name if confidence is at least `threshold`, otherwise `None`.
    #[must_use]
    pub fn accept_if(&self, threshold: f64) -> Option<&str> {
        if self.is_high_confidence(threshold) && self.is_actual_rename() {
            Some(&self.new_name)
        } else {
            None
        }
    }
}

// ── ParsedResponse ────────────────────────────────────────────────────────────

/// The structured result of parsing an LLM response for an RE task.
#[derive(Debug, Clone)]
pub struct ParsedResponse {
    /// Raw response text.
    pub raw: String,
    /// All code blocks found.
    pub code_blocks: Vec<CodeBlock>,
    /// Rename candidates (populated when the response is a rename reply).
    pub rename_candidates: Vec<RenameCandidate>,
    /// Key/value pairs extracted from structured sections.
    pub structured_fields: HashMap<String, String>,
    /// Plain-text narrative (everything that isn't a code block).
    pub narrative: String,
    /// True if parsing succeeded without errors.
    pub is_valid: bool,
    /// Human-readable parse warnings.
    pub warnings: Vec<String>,
}

impl ParsedResponse {
    /// The first code block, if any.
    #[must_use]
    pub fn first_code_block(&self) -> Option<&CodeBlock> {
        self.code_blocks.first()
    }

    /// The first code block with a matching language tag.
    #[must_use]
    pub fn code_block_by_language(&self, lang: &str) -> Option<&CodeBlock> {
        self.code_blocks.iter().find(|b| b.language == lang)
    }

    /// All rename candidates with confidence above `threshold`.
    #[must_use]
    pub fn high_confidence_renames(&self, threshold: f64) -> Vec<&RenameCandidate> {
        self.rename_candidates
            .iter()
            .filter(|c| c.is_high_confidence(threshold))
            .collect()
    }

    /// Whether any code blocks were found.
    #[must_use]
    pub const fn has_code(&self) -> bool {
        !self.code_blocks.is_empty()
    }

    /// Whether any rename candidates were found.
    #[must_use]
    pub const fn has_renames(&self) -> bool {
        !self.rename_candidates.is_empty()
    }
}

// ── LlmResponseParser ─────────────────────────────────────────────────────────

/// Parses LLM responses for reverse-engineering tasks.
///
/// Configurable via builder methods; `parse()` consumes the raw string and
/// returns a [`ParsedResponse`].
#[derive(Debug, Clone)]
pub struct LlmResponseParser {
    /// If `true`, attempt to parse JSON rename arrays.
    parse_renames: bool,
    /// Minimum rename confidence to include.
    min_confidence: f64,
    /// If `true`, extract structured key:value fields from the narrative.
    parse_fields: bool,
    /// Language tags to prefer when there are multiple code blocks.
    preferred_languages: Vec<String>,
}

impl Default for LlmResponseParser {
    fn default() -> Self {
        Self {
            parse_renames: true,
            min_confidence: 0.0,
            parse_fields: true,
            preferred_languages: vec!["c".to_string(), "cpp".to_string(), "asm".to_string()],
        }
    }
}

impl LlmResponseParser {
    /// Create a parser with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable rename candidate parsing.
    #[must_use]
    pub const fn rename_parsing(mut self, enabled: bool) -> Self {
        self.parse_renames = enabled;
        self
    }

    /// Only include rename candidates above this confidence.
    #[must_use]
    pub const fn min_confidence(mut self, threshold: f64) -> Self {
        // `f64::clamp` propagates NaN; a NaN threshold would reject every
        // candidate silently, since all comparisons against it are false.
        self.min_confidence = if threshold.is_nan() {
            0.0
        } else {
            threshold.clamp(0.0, 1.0)
        };
        self
    }

    /// Enable or disable structured field extraction.
    #[must_use]
    pub const fn field_parsing(mut self, enabled: bool) -> Self {
        self.parse_fields = enabled;
        self
    }

    /// Set the preferred code block language tags.
    #[must_use]
    pub fn preferred_languages(mut self, langs: Vec<String>) -> Self {
        self.preferred_languages = langs;
        self
    }

    /// Parse `text` into a [`ParsedResponse`].
    #[must_use]
    pub fn parse(&self, text: &str) -> ParsedResponse {
        let raw = text.to_string();
        let mut warnings = Vec::new();

        let code_blocks = extract_code_blocks(text);

        let rename_candidates = if self.parse_renames {
            self.extract_renames(text, &code_blocks, &mut warnings)
        } else {
            Vec::new()
        };

        let structured_fields = if self.parse_fields {
            Self::extract_fields(text)
        } else {
            HashMap::new()
        };

        let narrative = Self::extract_narrative(text, &code_blocks);

        let is_valid = !text.trim().is_empty();

        ParsedResponse {
            raw,
            code_blocks,
            rename_candidates,
            structured_fields,
            narrative,
            is_valid,
            warnings,
        }
    }

    /// Parse a rename-specific response (JSON array of candidates).
    fn extract_renames(
        &self,
        text: &str,
        code_blocks: &[CodeBlock],
        warnings: &mut Vec<String>,
    ) -> Vec<RenameCandidate> {
        let mut candidates = Vec::new();

        // First try JSON code blocks
        for block in code_blocks {
            if (block.language == "json" || block.language.is_empty())
                && let Some(parsed) = Self::try_parse_rename_json(block.trimmed_content()) {
                    candidates.extend(parsed);
                }
        }

        // If nothing found in code blocks, try inline JSON arrays
        if candidates.is_empty()
            && let Some(parsed) = Self::try_parse_rename_json_inline(text) {
                candidates.extend(parsed);
            }

        if candidates.is_empty() && text.contains("old") && text.contains("new") {
            warnings.push("No structured rename candidates found; response may be free-form.".to_string());
        }

        candidates
            .into_iter()
            .filter(|c| c.confidence >= self.min_confidence)
            .collect()
    }

    fn try_parse_rename_json(json: &str) -> Option<Vec<RenameCandidate>> {
        let value: serde_json::Value = serde_json::from_str(json).ok()?;
        let arr = value.as_array()?;
        let mut out = Vec::new();
        for item in arr {
            let old = item["old"].as_str().unwrap_or("").to_string();
            let new = item["new"].as_str().unwrap_or("").to_string();
            if old.is_empty() || new.is_empty() {
                continue;
            }
            let confidence = item["confidence"].as_f64().unwrap_or(0.5).clamp(0.0, 1.0);
            let rationale = item["rationale"].as_str().map(str::to_string);
            out.push(RenameCandidate {
                old_name: old,
                new_name: new,
                confidence,
                rationale,
                address: None,
            });
        }
        Some(out)
    }

    fn try_parse_rename_json_inline(text: &str) -> Option<Vec<RenameCandidate>> {
        // Find the first '[' ... ']' span and try to parse it
        let start = text.find('[')?;
        let end = text.rfind(']')?;
        if end <= start {
            return None;
        }
        Self::try_parse_rename_json(&text[start..=end])
    }

    fn extract_fields(text: &str) -> HashMap<String, String> {
        let mut fields = HashMap::new();
        for line in text.lines() {
            let trimmed = line.trim();
            // Match "Key: Value" or "**Key**: Value"
            let line_clean = trimmed.trim_start_matches('*').trim_end_matches('*');
            if let Some(colon_pos) = line_clean.find(':') {
                let key = line_clean[..colon_pos].trim().trim_matches('*').trim();
                let val = line_clean[colon_pos + 1..].trim();
                if !key.is_empty() && !val.is_empty() && key.len() <= 60 {
                    fields.entry(key.to_string()).or_insert_with(|| val.to_string());
                }
            }
        }
        fields
    }

    fn extract_narrative(text: &str, code_blocks: &[CodeBlock]) -> String {
        if code_blocks.is_empty() {
            return text.to_string();
        }
        let mut result = String::new();
        let mut last = 0usize;
        for block in code_blocks {
            if block.start_offset > last {
                result.push_str(&text[last..block.start_offset]);
            }
            last = block.end_offset;
        }
        if last < text.len() {
            result.push_str(&text[last..]);
        }
        result.trim().to_string()
    }

    /// Convenience: parse and return just the first C/ASM code block's content.
    #[must_use]
    pub fn extract_decompiled_code(&self, text: &str) -> Option<String> {
        let parsed = self.parse(text);
        // Try preferred languages first
        for lang in &self.preferred_languages {
            if let Some(blk) = parsed.code_block_by_language(lang) {
                return Some(blk.content.clone());
            }
        }
        parsed.first_code_block().map(|b| b.content.clone())
    }

    /// Parse and return rename candidates sorted by descending confidence.
    #[must_use]
    pub fn extract_renames_sorted(&self, text: &str) -> Vec<RenameCandidate> {
        let parsed = self.parse(text);
        let mut cands = parsed.rename_candidates;
        cands.sort_unstable_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        cands
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const RESPONSE_WITH_C: &str = r"
Here is the decompiled code:

```c
int add(int a, int b) {
    return a + b;
}
```

This function adds two integers.
";

    const RESPONSE_WITH_RENAMES: &str = r#"
Based on analysis:

```json
[
  {"old": "sub_1000", "new": "init_crypto", "confidence": 0.92},
  {"old": "var_8", "new": "key_buf", "confidence": 0.75, "rationale": "used as AES key"}
]
```
"#;

    #[test]
    fn test_extract_code_blocks_basic() {
        let blocks = extract_code_blocks(RESPONSE_WITH_C);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].language, "c");
        assert!(blocks[0].content.contains("int add"));
    }

    #[test]
    fn test_extract_code_blocks_empty() {
        let blocks = extract_code_blocks("No code here.");
        assert!(blocks.is_empty());
    }

    #[test]
    fn test_extract_code_blocks_multiple() {
        let text = "```asm\nnop\nret\n```\n\nSome text.\n\n```c\nint x = 1;\n```\n";
        let blocks = extract_code_blocks(text);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].language, "asm");
        assert_eq!(blocks[1].language, "c");
    }

    #[test]
    fn test_extract_code_blocks_no_language() {
        let text = "```\nsome code\n```\n";
        let blocks = extract_code_blocks(text);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].language.is_empty());
    }

    #[test]
    fn test_code_block_trimmed_content() {
        let block = CodeBlock {
            language: "c".to_string(),
            content: "  int x;\n  ".to_string(),
            start_offset: 0,
            end_offset: 10,
        };
        assert_eq!(block.trimmed_content(), "int x;");
    }

    #[test]
    fn test_code_block_line_count() {
        let block = CodeBlock {
            language: "c".to_string(),
            content: "int a;\n\nint b;\n".to_string(),
            start_offset: 0,
            end_offset: 20,
        };
        assert_eq!(block.line_count(), 2);
    }

    #[test]
    fn test_parser_parse_c_response() {
        let parser = LlmResponseParser::new();
        let resp = parser.parse(RESPONSE_WITH_C);
        assert!(resp.is_valid);
        assert_eq!(resp.code_blocks.len(), 1);
        assert!(resp.narrative.contains("This function adds"));
    }

    #[test]
    fn test_parser_parse_renames() {
        let parser = LlmResponseParser::new();
        let resp = parser.parse(RESPONSE_WITH_RENAMES);
        assert_eq!(resp.rename_candidates.len(), 2);
        let first = &resp.rename_candidates[0];
        assert_eq!(first.old_name, "sub_1000");
        assert_eq!(first.new_name, "init_crypto");
        assert!((first.confidence - 0.92).abs() < 0.001);
    }

    #[test]
    fn test_parser_rename_rationale() {
        let parser = LlmResponseParser::new();
        let resp = parser.parse(RESPONSE_WITH_RENAMES);
        let with_rationale = resp
            .rename_candidates
            .iter()
            .find(|c| c.rationale.is_some());
        assert!(with_rationale.is_some());
        assert!(with_rationale.unwrap().rationale.as_deref().unwrap().contains("AES"));
    }

    #[test]
    fn test_parser_min_confidence_filter() {
        let parser = LlmResponseParser::new().min_confidence(0.9);
        let resp = parser.parse(RESPONSE_WITH_RENAMES);
        assert_eq!(resp.rename_candidates.len(), 1);
        assert_eq!(resp.rename_candidates[0].old_name, "sub_1000");
    }

    #[test]
    fn test_parser_extract_fields() {
        let text = "Analysis:\nConfidence: high\nPattern: AES-128\n```c\nint x;\n```";
        let parser = LlmResponseParser::new();
        let resp = parser.parse(text);
        assert!(resp.structured_fields.contains_key("Confidence"));
        assert_eq!(resp.structured_fields["Confidence"], "high");
    }

    #[test]
    fn test_parser_extract_decompiled_code() {
        let parser = LlmResponseParser::new();
        let result = parser.extract_decompiled_code(RESPONSE_WITH_C);
        assert!(result.is_some());
        assert!(result.unwrap().contains("int add"));
    }

    #[test]
    fn test_parser_extract_decompiled_code_no_blocks() {
        let parser = LlmResponseParser::new();
        let result = parser.extract_decompiled_code("No code here at all.");
        assert!(result.is_none());
    }

    #[test]
    fn test_parser_extract_renames_sorted() {
        let parser = LlmResponseParser::new();
        let cands = parser.extract_renames_sorted(RESPONSE_WITH_RENAMES);
        assert!(!cands.is_empty());
        // Should be sorted descending by confidence
        for i in 1..cands.len() {
            assert!(cands[i - 1].confidence >= cands[i].confidence);
        }
    }

    #[test]
    fn test_rename_candidate_accept_if() {
        let c = RenameCandidate {
            old_name: "sub_1000".to_string(),
            new_name: "do_work".to_string(),
            confidence: 0.85,
            rationale: None,
            address: None,
        };
        assert_eq!(c.accept_if(0.8), Some("do_work"));
        assert_eq!(c.accept_if(0.9), None);
    }

    #[test]
    fn test_rename_candidate_no_actual_rename() {
        let c = RenameCandidate {
            old_name: "foo".to_string(),
            new_name: "foo".to_string(),
            confidence: 0.99,
            rationale: None,
            address: None,
        };
        assert!(!c.is_actual_rename());
        assert_eq!(c.accept_if(0.5), None);
    }

    #[test]
    fn test_parsed_response_has_code() {
        let parser = LlmResponseParser::new();
        let resp = parser.parse(RESPONSE_WITH_C);
        assert!(resp.has_code());
        assert!(!resp.has_renames());
    }

    #[test]
    fn test_parsed_response_high_confidence_renames() {
        let parser = LlmResponseParser::new();
        let resp = parser.parse(RESPONSE_WITH_RENAMES);
        let hi = resp.high_confidence_renames(0.9);
        assert_eq!(hi.len(), 1);
        assert_eq!(hi[0].new_name, "init_crypto");
    }

    #[test]
    fn test_parser_inline_json_renames() {
        let text = r#"Here are the renames: [{"old":"fn_a","new":"compute_hash","confidence":0.8}]"#;
        let parser = LlmResponseParser::new();
        let resp = parser.parse(text);
        assert_eq!(resp.rename_candidates.len(), 1);
        assert_eq!(resp.rename_candidates[0].new_name, "compute_hash");
    }

    #[test]
    fn test_parser_empty_response() {
        let parser = LlmResponseParser::new();
        let resp = parser.parse("");
        assert!(!resp.is_valid);
        assert!(resp.code_blocks.is_empty());
    }
}
