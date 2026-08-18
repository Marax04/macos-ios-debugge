//! Template compiler for hex pattern templates.
//!
//! Takes a high-level template definition (named fields, wildcards, constraints)
//! and compiles it into an efficient byte-pattern + mask representation suitable
//! for Boyer-Moore-Horspool or SIMD search.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ── Token types ───────────────────────────────────────────────────────────────

/// A single token produced by the template lexer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// A concrete byte value, e.g. `4D`.
    Byte(u8),
    /// A single-byte wildcard `??`.
    WildByte,
    /// A nibble-masked byte, e.g. `4?` or `?D`.
    MaskedByte { value: u8, mask: u8 },
    /// A named field capture group, e.g. `[dword:field_name]`.
    Field { name: String, size: usize },
    /// Alternative group, e.g. `(AA | BB | CC)`.
    Alternatives(Vec<Vec<Token>>),
    /// Repetition, e.g. `{3}` — repeat previous token N times.
    Repeat(usize),
}

// ── Lexer ─────────────────────────────────────────────────────────────────────

/// Lex errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LexError {
    UnexpectedChar(char, usize),
    InvalidHex(String),
    UnterminatedField,
    UnterminatedGroup,
    EmptyAlternative,
}

impl std::fmt::Display for LexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LexError::UnexpectedChar(c, pos) => {
                write!(f, "unexpected character '{c}' at position {pos}")
            }
            LexError::InvalidHex(s) => write!(f, "invalid hex sequence '{s}'"),
            LexError::UnterminatedField => write!(f, "unterminated field '[...]'"),
            LexError::UnterminatedGroup => write!(f, "unterminated group '(...)'"),
            LexError::EmptyAlternative => write!(f, "empty alternative in group"),
        }
    }
}

/// Lex a pattern string into tokens.
pub fn lex(pattern: &str) -> Result<Vec<Token>, LexError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            ' ' | '\t' | '\n' | '\r' => {
                i += 1;
            }
            '[' => {
                // Field: [size:name] or [name] (default size = 1)
                let start = i + 1;
                let end = chars[start..].iter().position(|&c| c == ']').ok_or(LexError::UnterminatedField)?;
                let content: String = chars[start..start + end].iter().collect();
                let (size, name) = if let Some(colon) = content.find(':') {
                    let size_str = &content[..colon];
                    let name = content[colon + 1..].to_string();
                    let size = match size_str {
                        "byte" | "1" => 1usize,
                        "word" | "2" => 2,
                        "dword" | "4" => 4,
                        "qword" | "8" => 8,
                        other => other.parse::<usize>().map_err(|_| {
                            LexError::InvalidHex(format!("bad size '{other}'"))
                        })?,
                    };
                    (size, name)
                } else {
                    (1, content)
                };
                tokens.push(Token::Field { name, size });
                i += 1 + end + 1; // skip '[' + content + ']'
            }
            '(' => {
                // Alternatives: (AA BB | CC DD | ...)
                let start = i + 1;
                let end = chars[start..]
                    .iter()
                    .position(|&c| c == ')')
                    .ok_or(LexError::UnterminatedGroup)?;
                let group: String = chars[start..start + end].iter().collect();
                let branches: Vec<Vec<Token>> = group
                    .split('|')
                    .map(|branch| lex(branch.trim()))
                    .collect::<Result<Vec<_>, _>>()?;
                if branches.iter().any(|b| b.is_empty()) {
                    return Err(LexError::EmptyAlternative);
                }
                tokens.push(Token::Alternatives(branches));
                i += 1 + end + 1;
            }
            '{' => {
                // Repeat count: {N}
                let start = i + 1;
                let end = chars[start..]
                    .iter()
                    .position(|&c| c == '}')
                    .ok_or(LexError::UnterminatedField)?;
                let count_str: String = chars[start..start + end].iter().collect();
                let count = count_str
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| LexError::InvalidHex(count_str.clone()))?;
                // Deny excessively large repeat counts to prevent memory
                // exhaustion when expand_tokens pre-allocates elements.
                const MAX_REPEAT: usize = 65536;
                if count > MAX_REPEAT {
                    return Err(LexError::InvalidHex(format!(
                        "repeat count {count} exceeds maximum of {MAX_REPEAT}"
                    )));
                }
                tokens.push(Token::Repeat(count));
                i += 1 + end + 1;
            }
            '?' => {
                if i + 1 < chars.len() && chars[i + 1] == '?' {
                    tokens.push(Token::WildByte);
                    i += 2;
                } else if i + 1 < chars.len() && chars[i + 1].is_ascii_hexdigit() {
                    let lo = chars[i + 1].to_digit(16).unwrap() as u8;
                    tokens.push(Token::MaskedByte { value: lo, mask: 0x0F });
                    i += 2;
                } else {
                    tokens.push(Token::WildByte);
                    i += 1;
                }
            }
            c if c.is_ascii_hexdigit() => {
                if i + 1 < chars.len() {
                    let next = chars[i + 1];
                    if next == '?' {
                        // High nibble known, low nibble wildcard: e.g. `4?`
                        let hi = c.to_digit(16).unwrap() as u8;
                        tokens.push(Token::MaskedByte {
                            value: hi << 4,
                            mask: 0xF0,
                        });
                        i += 2;
                    } else if next.is_ascii_hexdigit() {
                        let hi = c.to_digit(16).unwrap() as u8;
                        let lo = next.to_digit(16).unwrap() as u8;
                        tokens.push(Token::Byte((hi << 4) | lo));
                        i += 2;
                    } else {
                        return Err(LexError::UnexpectedChar(next, i + 1));
                    }
                } else {
                    return Err(LexError::InvalidHex(c.to_string()));
                }
            }
            c => return Err(LexError::UnexpectedChar(c, i)),
        }
    }

    Ok(tokens)
}

// ── Compiled pattern element ──────────────────────────────────────────────────

/// A single compiled element in the pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternElement {
    /// Concrete byte.
    Byte(u8),
    /// Nibble-masked byte: `(byte & mask) == (value & mask)`.
    Masked { value: u8, mask: u8 },
    /// Wildcard: matches any byte.
    Wild,
    /// Named field capture: N bytes whose value is captured.
    Field { name: String, size: usize },
}

impl PatternElement {
    /// True if this element always matches at least some byte without caring about the value.
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        matches!(self, PatternElement::Wild | PatternElement::Field { .. })
    }

    /// Returns the concrete byte if this element has exactly one possible value.
    #[must_use]
    pub const fn concrete_byte(&self) -> Option<u8> {
        match self {
            PatternElement::Byte(b) => Some(*b),
            _ => None,
        }
    }
}

// ── Compiled template ─────────────────────────────────────────────────────────

/// A compiled template ready for searching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledTemplate {
    /// Original pattern string.
    pub source: String,
    /// Template name.
    pub name: String,
    /// Flat sequence of pattern elements (one per byte).
    pub elements: Vec<PatternElement>,
    /// Byte pattern for fast comparison (wildcard bytes set to 0x00).
    pub pattern_bytes: Vec<u8>,
    /// Mask bytes: 0xFF means must match, 0x00 means skip.
    pub mask_bytes: Vec<u8>,
    /// Field offsets within the pattern, keyed by field name.
    pub field_offsets: HashMap<String, usize>,
    /// Field sizes, keyed by field name.
    pub field_sizes: HashMap<String, usize>,
    /// Bad-character skip table for Boyer-Moore-Horspool.
    #[serde(with = "serde_big_array::BigArray")]
    pub bmh_skip: [usize; 256],
}

impl CompiledTemplate {
    /// Total length (in bytes) of the pattern.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.elements.len()
    }

    /// True if the pattern has zero bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Check whether `data` starting at offset 0 matches this template.
    #[must_use]
    pub fn matches_at(&self, data: &[u8]) -> bool {
        if data.len() < self.elements.len() {
            return false;
        }
        for (i, elem) in self.elements.iter().enumerate() {
            match elem {
                PatternElement::Byte(b) => {
                    if data[i] != *b {
                        return false;
                    }
                }
                PatternElement::Masked { value, mask } => {
                    if (data[i] & mask) != (value & mask) {
                        return false;
                    }
                }
                PatternElement::Wild | PatternElement::Field { .. } => {}
            }
        }
        true
    }

    /// Extract field values from a matching slice.
    ///
    /// Returns `None` if the slice is too short.
    #[must_use]
    pub fn extract_fields(&self, data: &[u8]) -> Option<HashMap<String, Vec<u8>>> {
        if data.len() < self.elements.len() {
            return None;
        }
        let mut fields = HashMap::new();
        for (name, &offset) in &self.field_offsets {
            let size = *self.field_sizes.get(name)?;
            if offset + size > data.len() {
                return None;
            }
            fields.insert(name.clone(), data[offset..offset + size].to_vec());
        }
        Some(fields)
    }
}

// ── Compiler ──────────────────────────────────────────────────────────────────

/// Compile errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    LexError(LexError),
    AlternativeLengthMismatch,
    NestedRepeatNotAllowed,
    RepeatZero,
    EmptyPattern,
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompileError::LexError(e) => write!(f, "lex error: {e}"),
            CompileError::AlternativeLengthMismatch => {
                write!(f, "all branches of an alternative must have the same byte length")
            }
            CompileError::NestedRepeatNotAllowed => write!(f, "nested repeats are not allowed"),
            CompileError::RepeatZero => write!(f, "repeat count must be >= 1"),
            CompileError::EmptyPattern => write!(f, "pattern is empty"),
        }
    }
}

impl From<LexError> for CompileError {
    fn from(e: LexError) -> Self {
        CompileError::LexError(e)
    }
}

/// Compiles pattern strings into `CompiledTemplate` structs.
#[derive(Debug, Default)]
pub struct TemplateCompiler;

impl TemplateCompiler {
    /// Create a new compiler.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compile a named pattern string.
    pub fn compile(&self, name: &str, pattern: &str) -> Result<CompiledTemplate, CompileError> {
        let tokens = lex(pattern)?;
        if tokens.is_empty() {
            return Err(CompileError::EmptyPattern);
        }

        let mut elements: Vec<PatternElement> = Vec::new();
        let mut field_offsets: HashMap<String, usize> = HashMap::new();
        let mut field_sizes: HashMap<String, usize> = HashMap::new();

        self.expand_tokens(
            &tokens,
            &mut elements,
            &mut field_offsets,
            &mut field_sizes,
        )?;

        if elements.is_empty() {
            return Err(CompileError::EmptyPattern);
        }

        let n = elements.len();
        let mut pattern_bytes = vec![0u8; n];
        let mut mask_bytes = vec![0u8; n];

        for (i, elem) in elements.iter().enumerate() {
            match elem {
                PatternElement::Byte(b) => {
                    pattern_bytes[i] = *b;
                    mask_bytes[i] = 0xFF;
                }
                PatternElement::Masked { value, mask } => {
                    pattern_bytes[i] = value & mask;
                    mask_bytes[i] = *mask;
                }
                PatternElement::Wild | PatternElement::Field { .. } => {
                    pattern_bytes[i] = 0x00;
                    mask_bytes[i] = 0x00;
                }
            }
        }

        let bmh_skip = Self::build_bmh_table(&pattern_bytes, &mask_bytes);

        Ok(CompiledTemplate {
            source: pattern.to_string(),
            name: name.to_string(),
            elements,
            pattern_bytes,
            mask_bytes,
            field_offsets,
            field_sizes,
            bmh_skip,
        })
    }

    fn expand_tokens(
        &self,
        tokens: &[Token],
        elements: &mut Vec<PatternElement>,
        field_offsets: &mut HashMap<String, usize>,
        field_sizes: &mut HashMap<String, usize>,
    ) -> Result<(), CompileError> {
        let mut i = 0;
        while i < tokens.len() {
            let tok = &tokens[i];
            // Check for repeat token after current.
            let repeat = if i + 1 < tokens.len() {
                if let Token::Repeat(n) = tokens[i + 1] {
                    if n == 0 {
                        return Err(CompileError::RepeatZero);
                    }
                    n
                } else {
                    1
                }
            } else {
                1
            };

            for _ in 0..repeat {
                match tok {
                    Token::Byte(b) => elements.push(PatternElement::Byte(*b)),
                    Token::WildByte => elements.push(PatternElement::Wild),
                    Token::MaskedByte { value, mask } => {
                        elements.push(PatternElement::Masked { value: *value, mask: *mask })
                    }
                    Token::Field { name, size } => {
                        let offset = elements.len();
                        field_offsets.insert(name.clone(), offset);
                        field_sizes.insert(name.clone(), *size);
                        for _ in 0..*size {
                            elements.push(PatternElement::Field {
                                name: name.clone(),
                                size: *size,
                            });
                        }
                    }
                    Token::Alternatives(branches) => {
                        // Validate that all branches produce the same byte count.
                        let branch_lens: Result<Vec<usize>, _> = branches
                            .iter()
                            .map(|b| self.token_byte_len(b))
                            .collect();
                        let branch_lens = branch_lens?;
                        let first_len = branch_lens[0];
                        if branch_lens.iter().any(|&l| l != first_len) {
                            return Err(CompileError::AlternativeLengthMismatch);
                        }
                        // Emit wild bytes for each position — we can't express
                        // alternatives in a flat pattern/mask representation.
                        // The alternatives are preserved at a higher level if
                        // multi-pattern search is needed; here we conservatively
                        // mask them all out.
                        for _ in 0..first_len {
                            elements.push(PatternElement::Wild);
                        }
                    }
                    Token::Repeat(_) => {
                        // Already consumed by the outer loop; skip.
                    }
                }
            }

            if repeat > 1 {
                i += 2; // skip token + Repeat
            } else {
                i += 1;
            }
        }
        Ok(())
    }

    /// Compute the number of bytes a token sequence emits (for alternative validation).
    fn token_byte_len(&self, tokens: &[Token]) -> Result<usize, CompileError> {
        let mut count = 0;
        let mut i = 0;
        while i < tokens.len() {
            let repeat = if i + 1 < tokens.len() {
                if let Token::Repeat(n) = tokens[i + 1] {
                    n
                } else {
                    1
                }
            } else {
                1
            };
            match &tokens[i] {
                Token::Byte(_) | Token::WildByte | Token::MaskedByte { .. } => count += repeat,
                Token::Field { size, .. } => count += size * repeat,
                Token::Alternatives(branches) => {
                    let lens: Result<Vec<usize>, _> =
                        branches.iter().map(|b| self.token_byte_len(b)).collect();
                    let lens = lens?;
                    let first = lens[0];
                    if lens.iter().any(|&l| l != first) {
                        return Err(CompileError::AlternativeLengthMismatch);
                    }
                    count += first * repeat;
                }
                Token::Repeat(_) => {}
            }
            i += if repeat > 1 { 2 } else { 1 };
        }
        Ok(count)
    }

    /// Build a Boyer-Moore-Horspool bad-character skip table.
    fn build_bmh_table(pattern: &[u8], mask: &[u8]) -> [usize; 256] {
        let n = pattern.len();
        let mut skip = [n; 256];
        if n == 0 {
            return skip;
        }
        for i in 0..n.saturating_sub(1) {
            if mask[i] == 0xFF {
                skip[pattern[i] as usize] = n - 1 - i;
            }
        }
        skip
    }
}

// ── Search ────────────────────────────────────────────────────────────────────

/// A single match of a compiled template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    /// Byte offset in the searched buffer.
    pub offset: usize,
    /// Captured field values.
    pub fields: HashMap<String, Vec<u8>>,
}

/// Search for all occurrences of `template` in `data`.
///
/// Uses a masked Boyer-Moore-Horspool variant.
#[must_use]
pub fn search_all(template: &CompiledTemplate, data: &[u8]) -> Vec<PatternMatch> {
    let n = template.len();
    if n == 0 || data.len() < n {
        return vec![];
    }

    let mut matches = Vec::new();
    let limit = data.len() - n;
    let mut pos = 0;

    while pos <= limit {
        if template.matches_at(&data[pos..]) {
            let fields = template.extract_fields(&data[pos..]).unwrap_or_default();
            matches.push(PatternMatch { offset: pos, fields });
            pos += 1;
        } else {
            // BMH skip.
            let last_byte = data[pos + n - 1];
            let skip = template.bmh_skip[last_byte as usize];
            pos += skip.max(1);
        }
    }

    matches
}

/// Search for the first occurrence of `template` in `data`.
#[must_use]
pub fn search_first(template: &CompiledTemplate, data: &[u8]) -> Option<PatternMatch> {
    let n = template.len();
    if n == 0 || data.len() < n {
        return None;
    }

    let limit = data.len() - n;
    let mut pos = 0;

    while pos <= limit {
        if template.matches_at(&data[pos..]) {
            let fields = template.extract_fields(&data[pos..]).unwrap_or_default();
            return Some(PatternMatch { offset: pos, fields });
        }
        let last_byte = data[pos + n - 1];
        let skip = template.bmh_skip[last_byte as usize];
        pos += skip.max(1);
    }

    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lex_simple() {
        let tokens = lex("4D 5A 90 00").unwrap();
        assert_eq!(tokens.len(), 4);
        assert_eq!(tokens[0], Token::Byte(0x4D));
    }

    #[test]
    fn test_lex_wildcard() {
        let tokens = lex("FF ?? 00").unwrap();
        assert_eq!(tokens[1], Token::WildByte);
    }

    #[test]
    fn test_lex_masked_nibble() {
        let tokens = lex("4?").unwrap();
        assert_eq!(tokens[0], Token::MaskedByte { value: 0x40, mask: 0xF0 });
    }

    #[test]
    fn test_lex_field() {
        let tokens = lex("[dword:size]").unwrap();
        assert!(matches!(&tokens[0], Token::Field { name, size: 4 } if name == "size"));
    }

    #[test]
    fn test_compile_exact() {
        let c = TemplateCompiler::new();
        let t = c.compile("mz", "4D 5A").unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(t.pattern_bytes, vec![0x4D, 0x5A]);
        assert_eq!(t.mask_bytes, vec![0xFF, 0xFF]);
    }

    #[test]
    fn test_compile_wildcard() {
        let c = TemplateCompiler::new();
        let t = c.compile("test", "AA ?? BB").unwrap();
        assert_eq!(t.len(), 3);
        assert_eq!(t.mask_bytes[1], 0x00);
    }

    #[test]
    fn test_compile_field() {
        let c = TemplateCompiler::new();
        let t = c.compile("pe", "4D 5A [dword:e_lfanew]").unwrap();
        assert_eq!(t.len(), 6);
        assert!(t.field_offsets.contains_key("e_lfanew"));
        assert_eq!(t.field_sizes["e_lfanew"], 4);
    }

    #[test]
    fn test_search_exact() {
        let c = TemplateCompiler::new();
        let t = c.compile("sig", "4D 5A").unwrap();
        let data = vec![0x00, 0x4D, 0x5A, 0xFF];
        let matches = search_all(&t, &data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 1);
    }

    #[test]
    fn test_search_wildcard() {
        let c = TemplateCompiler::new();
        let t = c.compile("sig", "AA ?? BB").unwrap();
        let data = vec![0xAA, 0x99, 0xBB];
        let matches = search_all(&t, &data);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_search_no_match() {
        let c = TemplateCompiler::new();
        let t = c.compile("sig", "FF FF").unwrap();
        let data = vec![0x00, 0x01, 0x02];
        let matches = search_all(&t, &data);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_search_field_extraction() {
        let c = TemplateCompiler::new();
        let t = c.compile("pe", "4D 5A [dword:offset]").unwrap();
        let data = vec![0x4D, 0x5A, 0x01, 0x02, 0x03, 0x04];
        let m = search_first(&t, &data).unwrap();
        assert_eq!(m.fields["offset"], vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_repeat_token() {
        let c = TemplateCompiler::new();
        let t = c.compile("rep", "90 {4}").unwrap();
        // 90 repeated 4 times = 4 bytes
        assert_eq!(t.len(), 4);
        assert!(t.pattern_bytes.iter().all(|&b| b == 0x90));
    }

    #[test]
    fn test_empty_pattern_error() {
        let c = TemplateCompiler::new();
        assert!(c.compile("empty", "   ").is_err());
    }

    #[test]
    fn test_search_multiple_matches() {
        let c = TemplateCompiler::new();
        let t = c.compile("nop", "90 90").unwrap();
        let data = vec![0x90, 0x90, 0x00, 0x90, 0x90];
        let matches = search_all(&t, &data);
        assert_eq!(matches.len(), 2);
    }
}
