//! `response_parser` — Parse and structure LLM text responses.
//!
//! Extracts fenced code blocks, JSON objects, hexadecimal addresses,
//! function-name references, and structured tables from raw LLM output.
//! All parsing is done with manual string scanning — no regex crate required.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

// ── FinishReason ──────────────────────────────────────────────────────────────

/// Why the model stopped generating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinishReason {
    /// Normal stop (end-of-sequence token or stop sequence).
    Stop,
    /// Output truncated because the context window was exhausted.
    Length,
    /// Stopped due to a content policy filter.
    ContentFilter,
    /// Stopped to invoke a tool.
    ToolCall,
    /// An unknown or unrecognised stop reason.
    Unknown(String),
}

impl FinishReason {
    /// Parse a string as returned by common LLM APIs.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "stop" | "end_turn" => Self::Stop,
            "length" | "max_tokens" => Self::Length,
            "content_filter" => Self::ContentFilter,
            "tool_calls" | "tool_use" => Self::ToolCall,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

impl FromStr for FinishReason {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(s))
    }
}

impl fmt::Display for FinishReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stop => write!(f, "stop"),
            Self::Length => write!(f, "length"),
            Self::ContentFilter => write!(f, "content_filter"),
            Self::ToolCall => write!(f, "tool_call"),
            Self::Unknown(s) => write!(f, "unknown({s})"),
        }
    }
}

// ── TokenUsage ────────────────────────────────────────────────────────────────

/// Token usage statistics reported by the model.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TokenUsage {
    /// Tokens in the prompt (input).
    pub prompt_tokens: u32,
    /// Tokens generated (output).
    pub completion_tokens: u32,
    /// Total = prompt + completion.
    pub total_tokens: u32,
}

impl TokenUsage {
    /// Create a new `TokenUsage` and compute `total_tokens` automatically.
    #[must_use]
    pub const fn new(prompt: u32, completion: u32) -> Self {
        Self {
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: prompt + completion,
        }
    }
}

// ── LlmResponse ───────────────────────────────────────────────────────────────

/// A raw response from an LLM API.
#[derive(Debug, Clone)]
pub struct LlmResponse {
    /// The raw text content of the response.
    pub raw: String,
    /// Model identifier that produced the response.
    pub model: String,
    /// Why the model stopped generating.
    pub finish_reason: FinishReason,
    /// Token consumption statistics.
    pub usage: TokenUsage,
}

impl LlmResponse {
    /// Create a new `LlmResponse`.
    #[must_use]
    pub fn new(raw: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            raw: raw.into(),
            model: model.into(),
            finish_reason: FinishReason::Stop,
            usage: TokenUsage::default(),
        }
    }
}

// ── ContentSection ────────────────────────────────────────────────────────────

/// A structured section extracted from LLM output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentSection {
    /// Plain prose text.
    Text(String),
    /// A fenced code block with optional language tag and code body.
    CodeBlock { lang: String, code: String },
    /// A JSON object or array extracted from the text.
    JsonBlock(String),
    /// A markdown bullet/numbered list.
    List(Vec<String>),
    /// A markdown table.
    Table {
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
    },
}

impl ContentSection {
    /// Return a short label for the section type.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Text(_) => "text",
            Self::CodeBlock { .. } => "code",
            Self::JsonBlock(_) => "json",
            Self::List(_) => "list",
            Self::Table { .. } => "table",
        }
    }
}

// ── ParsedContent ─────────────────────────────────────────────────────────────

/// Fully structured output from an LLM response.
#[derive(Debug, Clone, Default)]
pub struct ParsedContent {
    /// Ordered sections of structured content.
    pub sections: Vec<ContentSection>,
}

impl ParsedContent {
    /// Return all code blocks.
    #[must_use]
    pub fn code_blocks(&self) -> Vec<(&str, &str)> {
        self.sections
            .iter()
            .filter_map(|s| {
                if let ContentSection::CodeBlock { lang, code } = s {
                    Some((lang.as_str(), code.as_str()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return all JSON blocks.
    #[must_use]
    pub fn json_blocks(&self) -> Vec<&str> {
        self.sections
            .iter()
            .filter_map(|s| {
                if let ContentSection::JsonBlock(j) = s {
                    Some(j.as_str())
                } else {
                    None
                }
            })
            .collect()
    }
}

// ── FunctionCall ──────────────────────────────────────────────────────────────

/// A detected function call pattern in LLM output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionCall {
    /// Name of the function.
    pub name: String,
    /// Key-value arguments (may be empty).
    pub arguments: HashMap<String, String>,
}

// ── ResponseParser ────────────────────────────────────────────────────────────

/// Stateless LLM response parser.
///
/// All methods are pure functions that operate on a `&str` or [`LlmResponse`].
#[derive(Debug, Clone, Default)]
pub struct ResponseParser;

impl ResponseParser {
    /// Create a new `ResponseParser`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    // ── Fenced code blocks ────────────────────────────────────────────────────

    /// Extract all fenced code blocks from `text`.
    ///
    /// Handles both ` ``` ` and ` ~~~ ` fences.  The optional language tag on
    /// the opening fence is captured in `lang`.
    #[must_use]
    pub fn parse_markdown_blocks(text: &str) -> Vec<ContentSection> {
        let mut sections = Vec::new();
        let mut remaining = text;

        while let Some(fence_start) = find_fence_start(remaining) {
            let before = &remaining[..fence_start];
            if !before.trim().is_empty() {
                sections.push(ContentSection::Text(before.to_owned()));
            }
            remaining = &remaining[fence_start..];

            // Determine fence character and length
            let fence_char = remaining.chars().next().unwrap_or('`');
            // Preserve the FULL opening-fence length: clamping it to 3 would
            // leave the extra fence characters of a ```` block to be misread as
            // a language tag, and would let a plain ``` line close it.
            let fence_len = remaining.chars().take_while(|&c| c == fence_char).count();
            let fence = &fence_char.to_string().repeat(fence_len);

            // Everything after the opening fence marker to EOL is the lang tag
            let after_fence = &remaining[fence_len..];
            let newline_pos = after_fence.find('\n').unwrap_or(after_fence.len());
            let lang = after_fence[..newline_pos].trim().to_owned();
            let after_lang = if newline_pos < after_fence.len() {
                &after_fence[newline_pos + 1..]
            } else {
                ""
            };

            // Find the closing fence
            if let Some(close_pos) = find_closing_fence(after_lang, fence) {
                let code = after_lang[..close_pos].to_owned();
                sections.push(ContentSection::CodeBlock { lang, code });
                let after_close = &after_lang[close_pos + fence.len()..];
                // Skip to end of closing fence line
                let eol = after_close.find('\n').map_or(after_close.len(), |p| p + 1);
                remaining = &after_lang[close_pos + fence.len() + eol.min(after_close.len())..];
            } else {
                // Unclosed fence — treat rest as text
                sections.push(ContentSection::Text(remaining.to_owned()));
                remaining = "";
                break;
            }
        }

        if !remaining.trim().is_empty() {
            sections.push(ContentSection::Text(remaining.to_owned()));
        }
        sections
    }

    // ── JSON extraction ───────────────────────────────────────────────────────

    /// Extract all top-level JSON objects (`{ ... }`) from `text`.
    ///
    /// Uses a simple bracket-depth counter; does not validate JSON syntax.
    #[must_use]
    pub fn extract_json_objects(text: &str) -> Vec<String> {
        let mut results = Vec::new();
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'{' {
                let start = i;
                let mut depth = 0usize;
                let mut in_string = false;
                let mut escape = false;
                while i < bytes.len() {
                    let ch = bytes[i];
                    if escape {
                        escape = false;
                    } else if in_string {
                        if ch == b'\\' {
                            escape = true;
                        } else if ch == b'"' {
                            in_string = false;
                        }
                    } else {
                        match ch {
                            b'"' => in_string = true,
                            b'{' => depth = depth.saturating_add(1),
                            b'}' => {
                                depth = depth.saturating_sub(1);
                                if depth == 0 {
                                    results.push(text[start..=i].to_owned());
                                    i += 1;
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
        results
    }

    // ── Address extraction ────────────────────────────────────────────────────

    /// Extract all hexadecimal addresses (`0x[0-9a-fA-F]{4,16}`) from `text`.
    #[must_use]
    pub fn extract_addresses(text: &str) -> Vec<u64> {
        let mut addresses = Vec::new();
        let chars: Vec<char> = text.chars().collect();
        let mut i = 0;
        while i + 1 < chars.len() {
            if chars[i] == '0' && (chars[i + 1] == 'x' || chars[i + 1] == 'X') {
                let start = i + 2;
                let mut end = start;
                while end < chars.len() && chars[end].is_ascii_hexdigit() {
                    end += 1;
                }
                let len = end - start;
                if (4..=16).contains(&len) {
                    let hex_str: String = chars[start..end].iter().collect();
                    if let Ok(v) = u64::from_str_radix(&hex_str, 16) {
                        addresses.push(v);
                    }
                }
                i = end;
            } else {
                i += 1;
            }
        }
        // Deduplicate while preserving order
        let mut seen = std::collections::HashSet::new();
        addresses.retain(|a| seen.insert(*a));
        addresses
    }

    // ── Function name extraction ──────────────────────────────────────────────

    /// Extract identifiers immediately followed by `(` from `text`.
    ///
    /// Captures C-style identifiers (`[A-Za-z_][A-Za-z0-9_]*`) followed
    /// directly by `(`.
    #[must_use]
    pub fn extract_function_names(text: &str) -> Vec<String> {
        let mut names = Vec::new();
        let chars: Vec<char> = text.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i].is_ascii_alphabetic() || chars[i] == '_' {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                if i < chars.len() && chars[i] == '(' {
                    let name: String = chars[start..i].iter().collect();
                    if !names.contains(&name) {
                        names.push(name);
                    }
                }
            } else {
                i += 1;
            }
        }
        names
    }

    // ── Full parse ────────────────────────────────────────────────────────────

    /// Parse a complete [`LlmResponse`] into a [`ParsedContent`].
    #[must_use]
    pub fn parse(response: &LlmResponse) -> ParsedContent {
        let sections = Self::parse_markdown_blocks(&response.raw);
        ParsedContent { sections }
    }

    // ── Markdown table extraction ─────────────────────────────────────────────

    /// Extract markdown tables from `text`.
    ///
    /// Expects `| col | col |` row format with a separator line
    /// `| --- | --- |` after the header.
    #[must_use]
    pub fn extract_tables(text: &str) -> Vec<ContentSection> {
        let mut tables = Vec::new();
        let lines: Vec<&str> = text.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i].trim();
            if line.starts_with('|') && line.ends_with('|') {
                let headers = parse_table_row(line);
                // Check for separator line
                if i + 1 < lines.len() {
                    let sep = lines[i + 1].trim();
                    if is_table_separator(sep) {
                        let mut rows = Vec::new();
                        let mut j = i + 2;
                        while j < lines.len() {
                            let row_line = lines[j].trim();
                            if row_line.starts_with('|') && row_line.ends_with('|') {
                                rows.push(parse_table_row(row_line));
                                j += 1;
                            } else {
                                break;
                            }
                        }
                        tables.push(ContentSection::Table { headers, rows });
                        i = j;
                        continue;
                    }
                }
            }
            i += 1;
        }
        tables
    }

    /// Extract bullet list items from `text`.
    #[must_use]
    pub fn extract_lists(text: &str) -> Vec<String> {
        text.lines()
            .filter_map(|line| {
                let t = line.trim();
                if t.starts_with("- ") || t.starts_with("* ") || t.starts_with("+ ") {
                    Some(t[2..].trim().to_owned())
                } else if t.len() > 2 {
                    // Numbered list: "1. " or "12. "
                    let dot_pos = t.find(". ");
                    if let Some(pos) = dot_pos
                        && t[..pos].chars().all(|c| c.is_ascii_digit()) {
                            return Some(t[pos + 2..].trim().to_owned());
                        }
                    None
                } else {
                    None
                }
            })
            .collect()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn find_fence_start(text: &str) -> Option<usize> {
    // Find ``` or ~~~ at the start of a line
    let mut i = 0;
    let bytes = text.as_bytes();
    while i < bytes.len() {
        // Check for ``` or ~~~
        if i + 2 < bytes.len()
            && ((bytes[i] == b'`' && bytes[i + 1] == b'`' && bytes[i + 2] == b'`')
                || (bytes[i] == b'~' && bytes[i + 1] == b'~' && bytes[i + 2] == b'~'))
        {
            return Some(i);
        }
        // Advance to next line
        while i < bytes.len() && bytes[i] != b'\n' {
            i += 1;
        }
        i += 1; // skip the newline
    }
    None
}

fn find_closing_fence(text: &str, fence: &str) -> Option<usize> {
    let fence_bytes = fence.as_bytes();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(fence_bytes) {
            // The closing fence must be at the start of a line (or start of text)
            let is_line_start = i == 0 || bytes[i - 1] == b'\n';
            // …and must not be followed by MORE fence characters: a longer run
            // is content belonging to the block, not its terminator. Without
            // this, a nested ```` line closes a ``` block early, truncating the
            // code and leaving the surplus backtick to start a phantom block.
            let ends_here = match bytes.get(i + fence_bytes.len()) {
                None => true,
                Some(&b) => b != fence_bytes[0],
            };
            if is_line_start && ends_here {
                return Some(i);
            }
        }
        while i < bytes.len() && bytes[i] != b'\n' {
            i += 1;
        }
        i += 1;
    }
    None
}

fn parse_table_row(line: &str) -> Vec<String> {
    line.trim_matches('|')
        .split('|')
        .map(|cell| cell.trim().to_owned())
        .collect()
}

fn is_table_separator(line: &str) -> bool {
    line.starts_with('|')
        && line.ends_with('|')
        && line.chars().all(|c| matches!(c, '|' | '-' | ':' | ' '))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finish_reason_stop() {
        assert_eq!(FinishReason::parse("stop"), FinishReason::Stop);
        assert_eq!(FinishReason::parse("end_turn"), FinishReason::Stop);
    }

    #[test]
    fn test_finish_reason_length() {
        assert_eq!(FinishReason::parse("length"), FinishReason::Length);
        assert_eq!(FinishReason::parse("max_tokens"), FinishReason::Length);
    }

    #[test]
    fn test_finish_reason_unknown() {
        match FinishReason::parse("weird_reason") {
            FinishReason::Unknown(s) => assert_eq!(s, "weird_reason"),
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn test_token_usage_total() {
        let u = TokenUsage::new(100, 200);
        assert_eq!(u.total_tokens, 300);
    }

    #[test]
    fn test_parse_markdown_blocks_single_block() {
        let text = "Here is code:\n```rust\nfn main() {}\n```\nThat's it.";
        let sections = ResponseParser::parse_markdown_blocks(text);
        let code_blocks: Vec<_> = sections
            .iter()
            .filter(|s| matches!(s, ContentSection::CodeBlock { .. }))
            .collect();
        assert_eq!(code_blocks.len(), 1);
        if let ContentSection::CodeBlock { lang, code } = &code_blocks[0] {
            assert_eq!(lang, "rust");
            assert!(code.contains("fn main"));
        }
    }

    #[test]
    fn test_parse_markdown_blocks_no_blocks() {
        let text = "Just plain text.";
        let sections = ResponseParser::parse_markdown_blocks(text);
        assert_eq!(sections.len(), 1);
        assert!(matches!(&sections[0], ContentSection::Text(_)));
    }

    #[test]
    fn test_parse_markdown_blocks_multiple_blocks() {
        let text = "```python\nprint('hi')\n```\nMiddle text.\n```c\nint x = 0;\n```";
        let sections = ResponseParser::parse_markdown_blocks(text);
        let code_count = sections.iter().filter(|s| matches!(s, ContentSection::CodeBlock { .. })).count();
        assert_eq!(code_count, 2);
    }

    #[test]
    fn test_extract_json_objects_single() {
        let text = r#"Result: {"key": "value", "n": 42}"#;
        let jsons = ResponseParser::extract_json_objects(text);
        assert_eq!(jsons.len(), 1);
        assert!(jsons[0].contains("key"));
    }

    #[test]
    fn test_extract_json_objects_nested() {
        let text = r#"{"outer": {"inner": 1}}"#;
        let jsons = ResponseParser::extract_json_objects(text);
        assert_eq!(jsons.len(), 1);
    }

    #[test]
    fn test_extract_json_objects_empty_text() {
        assert!(ResponseParser::extract_json_objects("no json here").is_empty());
    }

    #[test]
    fn test_extract_addresses_basic() {
        let text = "Jump to 0x401000 or 0xdeadbeef";
        let addrs = ResponseParser::extract_addresses(text);
        assert!(addrs.contains(&0x401000));
        assert!(addrs.contains(&0xdeadbeef));
    }

    #[test]
    fn test_extract_addresses_too_short() {
        // 0x12 is only 2 hex digits — too short
        let text = "at 0x12";
        let addrs = ResponseParser::extract_addresses(text);
        assert!(addrs.is_empty());
    }

    #[test]
    fn test_extract_addresses_dedup() {
        let text = "0x401000 appears at 0x401000 twice";
        let addrs = ResponseParser::extract_addresses(text);
        assert_eq!(addrs.iter().filter(|&&a| a == 0x401000).count(), 1);
    }

    #[test]
    fn test_extract_function_names_basic() {
        let text = "Call malloc(size) and free(ptr) to manage memory.";
        let names = ResponseParser::extract_function_names(text);
        assert!(names.contains(&"malloc".to_owned()));
        assert!(names.contains(&"free".to_owned()));
    }

    #[test]
    fn test_extract_function_names_dedup() {
        let text = "foo() called foo() again";
        let names = ResponseParser::extract_function_names(text);
        assert_eq!(names.iter().filter(|n| n.as_str() == "foo").count(), 1);
    }

    #[test]
    fn test_extract_function_names_no_parens() {
        let text = "no functions here";
        let names = ResponseParser::extract_function_names(text);
        assert!(names.is_empty());
    }

    #[test]
    fn test_extract_tables_basic() {
        let text = "| Name | Value |\n| --- | --- |\n| foo | 42 |\n| bar | 99 |";
        let tables = ResponseParser::extract_tables(text);
        assert_eq!(tables.len(), 1);
        if let ContentSection::Table { headers, rows } = &tables[0] {
            assert_eq!(headers, &["Name".to_owned(), "Value".to_owned()]);
            assert_eq!(rows.len(), 2);
        } else {
            panic!("expected Table");
        }
    }

    #[test]
    fn test_extract_lists_bullet() {
        let text = "- item one\n- item two\n- item three";
        let items = ResponseParser::extract_lists(text);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], "item one");
    }

    #[test]
    fn test_extract_lists_numbered() {
        let text = "1. first\n2. second\n3. third";
        let items = ResponseParser::extract_lists(text);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], "first");
    }

    #[test]
    fn test_parsed_content_code_blocks_accessor() {
        let text = "```python\nprint(1)\n```";
        let sections = ResponseParser::parse_markdown_blocks(text);
        let pc = ParsedContent { sections };
        let blocks = pc.code_blocks();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, "python");
    }

    #[test]
    fn test_content_section_kind() {
        assert_eq!(ContentSection::Text("x".into()).kind(), "text");
        assert_eq!(ContentSection::CodeBlock { lang: "c".into(), code: String::new() }.kind(), "code");
        assert_eq!(ContentSection::JsonBlock("{}".into()).kind(), "json");
    }
}
