// rustre-triage-peid/src/userdb_parser.rs
// Parser for PEiD userdb.txt signature database format.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};

/// Error during userdb parsing.
#[derive(Debug, Clone)]
pub enum UserdbError {
    Io(String),
    MalformedEntry { line: usize, detail: String },
    EmptyDatabase,
}

impl std::fmt::Display for UserdbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "I/O error: {s}"),
            Self::MalformedEntry { line, detail } => write!(f, "Line {line}: {detail}"),
            Self::EmptyDatabase => write!(f, "Empty signature database"),
        }
    }
}

pub type UserdbResult<T> = Result<T, UserdbError>;

/// PEiD signature category, inferred from name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeidCategory {
    Packer,
    Protector,
    Compiler,
    Linker,
    Installer,
    Runtime,
    Overlay,
    Unknown,
}

impl PeidCategory {
    /// Infer category from signature name string.
    pub fn infer(name: &str) -> Self {
        let lower = name.to_lowercase();
        if lower.contains("upx") || lower.contains("mpress") || lower.contains("aspack")
            || lower.contains("pecompact") || lower.contains("fsg") || lower.contains("mew")
            || lower.contains("pack") || lower.contains("compress")
        { return Self::Packer; }
        if lower.contains("themida") || lower.contains("vmprotect") || lower.contains("armadillo")
            || lower.contains("obsidium") || lower.contains("enigma") || lower.contains("execryptor")
            || lower.contains("protect") || lower.contains("crypt")
        { return Self::Protector; }
        if lower.contains("delphi") || lower.contains("msvc") || lower.contains("gcc")
            || lower.contains("borland") || lower.contains("intel c") || lower.contains("clang")
            || lower.contains("visual basic") || lower.contains("vb6") || lower.contains("fpc")
            || lower.contains("compiler") || lower.contains("g++")
        { return Self::Compiler; }
        if lower.contains("linker") || lower.contains("link.exe") { return Self::Linker; }
        if lower.contains("nsis") || lower.contains("inno") || lower.contains("installshield")
            || lower.contains("installer") { return Self::Installer; }
        if lower.contains(".net") || lower.contains("dotnet") || lower.contains("runtime") {
            return Self::Runtime;
        }
        if lower.contains("overlay") { return Self::Overlay; }
        Self::Unknown
    }
}

/// A parsed PEiD signature.
#[derive(Debug, Clone)]
pub struct ParsedSignature {
    pub name: String,
    pub category: PeidCategory,
    /// Raw wildcard pattern bytes. None = wildcard.
    pub pattern: Vec<Option<u8>>,
    pub ep_only: bool,
    pub section_start_only: bool,
    pub source_line: usize,
}

impl ParsedSignature {
    /// Match this signature against `data`.
    /// If `ep_only`, only match at offset 0 of `ep_bytes`.
    pub fn matches_ep(&self, ep_bytes: &[u8]) -> bool {
        if self.pattern.is_empty() { return false; }
        if ep_bytes.len() < self.pattern.len() { return false; }
        self.pattern.iter().zip(ep_bytes.iter()).all(|(p, b)| {
            p.map_or(true, |expected| expected == *b)
        })
    }

    /// Match this signature against any window in `data`.
    pub fn matches_anywhere(&self, data: &[u8]) -> bool {
        if self.pattern.is_empty() { return false; }
        let pat_len = self.pattern.len();
        if data.len() < pat_len { return false; }
        data.windows(pat_len).any(|w| {
            self.pattern.iter().zip(w.iter()).all(|(p, b)| p.map_or(true, |e| e == *b))
        })
    }

    /// Full match according to ep_only flag.
    pub fn matches(&self, data: &[u8], ep_bytes: &[u8]) -> bool {
        if self.ep_only { self.matches_ep(ep_bytes) } else { self.matches_anywhere(data) }
    }
}

/// Parse a single hex byte token. Returns `Ok(None)` for wildcards `??`/`??`.
pub fn parse_byte_token(token: &str) -> UserdbResult<Option<u8>> {
    let t = token.trim();
    if t == "??" || t == "?" || t == "?X" || t == "X?" {
        return Ok(None);
    }
    u8::from_str_radix(t, 16)
        .map(Some)
        .map_err(|_| UserdbError::MalformedEntry { line: 0, detail: format!("Invalid byte token: {t}") })
}

/// Parse a PEiD hex pattern string like `"4D 5A ?? 90 00 03"`.
pub fn parse_pattern_string(pattern_str: &str) -> UserdbResult<Vec<Option<u8>>> {
    let inner = pattern_str.trim().trim_start_matches('"').trim_end_matches('"');
    if inner.is_empty() { return Ok(Vec::new()); }
    inner.split_whitespace()
        .map(|t| parse_byte_token(t))
        .collect()
}

/// Parse a full PEiD userdb.txt reader into a list of signatures.
///
/// The format is:
/// ```text
/// [Signature Name]
/// signature = 4D 5A 90 00 ??
/// ep_only = true
/// section_start_only = false
/// ```
pub fn parse_userdb<R: Read>(reader: R) -> UserdbResult<Vec<ParsedSignature>> {
    let buf = BufReader::new(reader);
    let mut sigs = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_pattern: Vec<Option<u8>> = Vec::new();
    let mut ep_only = false;
    let mut section_start_only = false;
    let mut entry_start_line = 0usize;

    for (line_num, line_result) in buf.lines().enumerate() {
        let line = line_result.map_err(|e| UserdbError::Io(e.to_string()))?;
        let trimmed = line.trim();

        // Skip empty lines and comments.
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with("//") {
            continue;
        }

        // New entry: [Name]
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            // Commit previous entry.
            if let Some(name) = current_name.take() {
                if !current_pattern.is_empty() {
                    let category = PeidCategory::infer(&name);
                    sigs.push(ParsedSignature {
                        name,
                        category,
                        pattern: std::mem::take(&mut current_pattern),
                        ep_only,
                        section_start_only,
                        source_line: entry_start_line,
                    });
                }
            }
            let name = trimmed[1..trimmed.len() - 1].to_string();
            current_name = Some(name);
            ep_only = false;
            section_start_only = false;
            current_pattern = Vec::new();
            entry_start_line = line_num + 1;
            continue;
        }

        // Key-value pair.
        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim().to_lowercase();
            let value = value.trim();
            match key.as_str() {
                "signature" => {
                    current_pattern = parse_pattern_string(value)
                        .map_err(|mut e| {
                            if let UserdbError::MalformedEntry { ref mut line, .. } = e {
                                *line = line_num + 1;
                            }
                            e
                        })?;
                }
                "ep_only" => {
                    ep_only = value.eq_ignore_ascii_case("true");
                }
                "section_start_only" => {
                    section_start_only = value.eq_ignore_ascii_case("true");
                }
                _ => {} // Unknown keys are ignored.
            }
        }
    }

    // Commit last entry.
    if let Some(name) = current_name {
        if !current_pattern.is_empty() {
            let category = PeidCategory::infer(&name);
            sigs.push(ParsedSignature {
                name,
                category,
                pattern: current_pattern,
                ep_only,
                section_start_only,
                source_line: entry_start_line,
            });
        }
    }

    if sigs.is_empty() {
        return Err(UserdbError::EmptyDatabase);
    }
    Ok(sigs)
}

/// Deduplicate signatures by (name, pattern). Returns the deduplicated list.
pub fn dedup_signatures(sigs: Vec<ParsedSignature>) -> Vec<ParsedSignature> {
    let mut seen: HashMap<(String, Vec<Option<u8>>), usize> = HashMap::new();
    let mut result = Vec::new();
    for sig in sigs {
        let key = (sig.name.clone(), sig.pattern.clone());
        seen.entry(key).or_insert_with(|| {
            let idx = result.len();
            result.push(sig);
            idx
        });
    }
    result
}

/// Merge two signature lists, deduplicating.
pub fn merge_signatures(base: Vec<ParsedSignature>, additional: Vec<ParsedSignature>) -> Vec<ParsedSignature> {
    let mut combined = base;
    combined.extend(additional);
    dedup_signatures(combined)
}

/// Database of parsed signatures with fast lookup by category.
pub struct UserdbDatabase {
    pub signatures: Vec<ParsedSignature>,
    by_category: HashMap<PeidCategory, Vec<usize>>,
    by_name: HashMap<String, Vec<usize>>,
}

impl UserdbDatabase {
    pub fn from_signatures(sigs: Vec<ParsedSignature>) -> Self {
        let mut by_category: HashMap<PeidCategory, Vec<usize>> = HashMap::new();
        let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, sig) in sigs.iter().enumerate() {
            by_category.entry(sig.category).or_default().push(i);
            by_name.entry(sig.name.to_lowercase()).or_default().push(i);
        }
        Self { signatures: sigs, by_category, by_name }
    }

    pub fn len(&self) -> usize { self.signatures.len() }
    pub fn is_empty(&self) -> bool { self.signatures.is_empty() }

    pub fn by_category(&self, cat: PeidCategory) -> Vec<&ParsedSignature> {
        self.by_category.get(&cat)
            .map(|idxs| idxs.iter().map(|&i| &self.signatures[i]).collect())
            .unwrap_or_default()
    }

    pub fn by_name(&self, name: &str) -> Vec<&ParsedSignature> {
        self.by_name.get(&name.to_lowercase())
            .map(|idxs| idxs.iter().map(|&i| &self.signatures[i]).collect())
            .unwrap_or_default()
    }

    /// Scan data and return matching signatures.
    pub fn scan(&self, data: &[u8], ep_bytes: &[u8]) -> Vec<&ParsedSignature> {
        self.signatures.iter()
            .filter(|sig| sig.matches(data, ep_bytes))
            .collect()
    }
}

/// Build a tiny inline userdb from a &str (for testing and embedded defaults).
pub fn parse_inline(text: &str) -> UserdbResult<Vec<ParsedSignature>> {
    parse_userdb(std::io::Cursor::new(text.as_bytes()))
}

/// Generate a minimal userdb.txt text for a list of signatures (for export).
pub fn to_userdb_text(sigs: &[ParsedSignature]) -> String {
    let mut out = String::new();
    for sig in sigs {
        out.push('[');
        out.push_str(&sig.name);
        out.push_str("]\n");
        out.push_str("signature = ");
        let pat_str: Vec<String> = sig.pattern.iter().map(|b| {
            b.map_or("??".to_string(), |v| format!("{v:02X}"))
        }).collect();
        out.push_str(&pat_str.join(" "));
        out.push('\n');
        out.push_str(&format!("ep_only = {}\n", sig.ep_only));
        out.push_str(&format!("section_start_only = {}\n", sig.section_start_only));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_DB: &str = r#"
[UPX 3.94 (x86)]
signature = 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF
ep_only = true
section_start_only = false

[MSVC 14.x]
signature = 48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20
ep_only = false
section_start_only = false

; A comment
[Delphi 7]
signature = 55 8B EC 83 C4 F0 53 56 57
ep_only = true
section_start_only = false
"#;

    #[test]
    fn parse_sample_db() {
        let sigs = parse_inline(SAMPLE_DB).expect("parse failed");
        assert_eq!(sigs.len(), 3);
    }

    #[test]
    fn names_correct() {
        let sigs = parse_inline(SAMPLE_DB).unwrap();
        assert_eq!(sigs[0].name, "UPX 3.94 (x86)");
        assert_eq!(sigs[1].name, "MSVC 14.x");
        assert_eq!(sigs[2].name, "Delphi 7");
    }

    #[test]
    fn ep_only_parsed() {
        let sigs = parse_inline(SAMPLE_DB).unwrap();
        assert!(sigs[0].ep_only);
        assert!(!sigs[1].ep_only);
        assert!(sigs[2].ep_only);
    }

    #[test]
    fn category_inferred() {
        let sigs = parse_inline(SAMPLE_DB).unwrap();
        assert_eq!(sigs[0].category, PeidCategory::Packer);
        assert_eq!(sigs[1].category, PeidCategory::Compiler);
        assert_eq!(sigs[2].category, PeidCategory::Compiler);
    }

    #[test]
    fn wildcard_pattern() {
        let sigs = parse_inline(SAMPLE_DB).unwrap();
        // Pattern for UPX: 60 BE ?? ?? ?? ?? 8D ...
        assert_eq!(sigs[0].pattern[0], Some(0x60));
        assert_eq!(sigs[0].pattern[2], None); // wildcard
    }

    #[test]
    fn match_ep_bytes() {
        let sigs = parse_inline(SAMPLE_DB).unwrap();
        let upx = &sigs[0];
        let ep = [0x60, 0xBE, 0xAA, 0xBB, 0xCC, 0xDD, 0x8D, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x57, 0x83, 0xCD, 0xFF];
        assert!(upx.matches_ep(&ep));
    }

    #[test]
    fn dedup_removes_duplicates() {
        let sigs = parse_inline(SAMPLE_DB).unwrap();
        let doubled: Vec<_> = sigs.iter().cloned().chain(sigs.iter().cloned()).collect();
        let deduped = dedup_signatures(doubled);
        assert_eq!(deduped.len(), 3);
    }

    #[test]
    fn to_userdb_text_round_trip() {
        let sigs = parse_inline(SAMPLE_DB).unwrap();
        let text = to_userdb_text(&sigs);
        let re_parsed = parse_inline(&text).unwrap();
        assert_eq!(re_parsed.len(), sigs.len());
    }

    #[test]
    fn database_scan() {
        let sigs = parse_inline(SAMPLE_DB).unwrap();
        let db = UserdbDatabase::from_signatures(sigs);
        let ep = [0x60, 0xBE, 0xAA, 0xBB, 0xCC, 0xDD, 0x8D, 0xBE,
                  0x00, 0x00, 0x00, 0x00, 0x57, 0x83, 0xCD, 0xFF];
        let matches = db.scan(&ep, &ep);
        assert!(matches.iter().any(|s| s.name.contains("UPX")));
    }
}
