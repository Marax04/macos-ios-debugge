//! Serialization and deserialization of FLIRT patterns to/from `.pat` text and JSON.
//!
//! Uses the [`rustre_flirt::FlirtPattern`] type as the canonical representation.

use rustre_flirt::{FlirtName, FlirtPattern, PatternByte};

// ── SerializeError ────────────────────────────────────────────────────────────

/// Errors that can occur during pattern serialization or deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerializeError {
    /// The input format was not recognized or was structurally invalid.
    InvalidFormat,
    /// A specific pattern could not be serialized.
    InvalidPattern(String),
    /// A JSON encoding/decoding error.
    JsonError(String),
}

impl std::fmt::Display for SerializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid format"),
            Self::InvalidPattern(s) => write!(f, "invalid pattern: {s}"),
            Self::JsonError(s) => write!(f, "json error: {s}"),
        }
    }
}

impl std::error::Error for SerializeError {}

// ── PatSerializer ─────────────────────────────────────────────────────────────

/// Serializes [`FlirtPattern`] collections to `.pat` text format.
pub struct PatSerializer;

impl PatSerializer {
    /// Convert a single [`FlirtPattern`] to a `.pat` format line.
    ///
    /// Format:
    /// ```text
    /// PATBYTES :CRC_LEN CRC16 TOTAL_LEN :0000:public:NAME [...]
    /// ```
    ///
    /// Pattern bytes are padded to at least 32 bytes with `..` wildcards.
    #[must_use]
    pub fn to_pat_line(pattern: &FlirtPattern) -> String {
        use std::fmt::Write as _;
        // Build hex pattern string (minimum 32 bytes, padded with wildcards)
        let min_len = 32;
        let actual_len = pattern.initial_bytes.len().max(min_len);
        let mut hex = String::with_capacity(actual_len * 2);

        for i in 0..actual_len {
            if i < pattern.initial_bytes.len() {
                match &pattern.initial_bytes[i] {
                    PatternByte::Exact(b) => {
                        let _ = write!(hex, "{b:02X}");
                    }
                    PatternByte::Wildcard => {
                        hex.push_str("..");
                    }
                }
            } else {
                hex.push_str("..");
            }
        }

        // Build the rest of the line
        let crc_len = pattern.crc_length;
        let crc16 = pattern.crc16;
        let total_len = pattern.pattern_length;

        let mut line = format!("{hex} :{crc_len} {crc16:04X} {total_len}");

        // Primary name at offset 0
        if let Some(primary) = pattern.primary_name() {
            let _ = write!(line, " :0000:public:{primary}");
        } else if !pattern.names.is_empty() {
            let n = &pattern.names[0];
            let kind = if n.is_local { "local" } else { "public" };
            let _ = write!(line, " :{:04X}:{kind}:{}", n.offset, n.name);
        }

        // Additional names at non-zero offsets
        for n in &pattern.names {
            if n.offset == 0 && n.is_public {
                continue; // already emitted as primary
            }
            let kind = if n.is_local { "local" } else { "public" };
            let _ = write!(line, " :{:04X}:{kind}:{}", n.offset, n.name);
        }

        line
    }

    /// Convert a slice of patterns to a complete `.pat` file string.
    ///
    /// A `---` footer line is appended.
    #[must_use]
    pub fn to_pat(patterns: &[FlirtPattern]) -> String {
        // Heuristic: assume ~80 chars per pattern line.
        let mut out = String::with_capacity(patterns.len() * 80 + 4);
        for pat in patterns {
            out.push_str(&Self::to_pat_line(pat));
            out.push('\n');
        }
        out.push_str("---\n");
        out
    }

    /// Serialize patterns to JSON using a simplified representation.
    ///
    /// Each pattern is encoded as a JSON object with fields:
    /// `hex_pattern`, `crc_len`, `crc16`, `total_len`, `names`.
    ///
    /// # Errors
    ///
    /// Returns [`SerializeError::JsonError`] if serialization fails.
    pub fn to_json(patterns: &[FlirtPattern]) -> Result<String, SerializeError> {
        let entries: Vec<serde_json::Value> = patterns
            .iter()
            .map(|p| {
                let hex: String = {
                    use std::fmt::Write as _;
                    let mut s = String::with_capacity(p.initial_bytes.len() * 2);
                    for pb in &p.initial_bytes {
                        match pb {
                            PatternByte::Exact(b) => {
                                let _ = write!(s, "{b:02X}");
                            }
                            PatternByte::Wildcard => s.push_str(".."),
                        }
                    }
                    s
                };

                let names: Vec<serde_json::Value> = p
                    .names
                    .iter()
                    .map(|n| {
                        serde_json::json!({
                            "name": n.name,
                            "offset": n.offset,
                            "is_public": n.is_public,
                            "is_local": n.is_local,
                        })
                    })
                    .collect();

                serde_json::json!({
                    "hex_pattern": hex,
                    "crc_len": p.crc_length,
                    "crc16": p.crc16,
                    "total_len": p.pattern_length,
                    "names": names,
                })
            })
            .collect();

        serde_json::to_string_pretty(&serde_json::Value::Array(entries))
            .map_err(|e| SerializeError::JsonError(e.to_string()))
    }
}

// ── PatDeserializer ───────────────────────────────────────────────────────────

/// Deserializes [`FlirtPattern`] collections from `.pat` text format or JSON.
pub struct PatDeserializer;

impl PatDeserializer {
    /// Parse a `.pat` text file into a list of [`FlirtPattern`]s.
    ///
    /// Lines starting with `---` are treated as separators and skipped.
    ///
    /// # Errors
    ///
    /// Returns [`SerializeError::InvalidFormat`] for malformed lines.
    pub fn from_pat(text: &str) -> Result<Vec<FlirtPattern>, SerializeError> {
        let mut patterns = Vec::new();

        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with("---") {
                continue;
            }
            let pat = parse_pat_line_to_flirt(line)
                .ok_or_else(|| SerializeError::InvalidPattern(format!("line {}", lineno + 1)))?;
            patterns.push(pat);
        }

        Ok(patterns)
    }

    /// Deserialize patterns from a JSON string produced by [`PatSerializer::to_json`].
    ///
    /// # Errors
    ///
    /// Returns [`SerializeError::JsonError`] on JSON parse failure, or
    /// [`SerializeError::InvalidFormat`] if the structure does not match.
    pub fn from_json(json: &str) -> Result<Vec<FlirtPattern>, SerializeError> {
        let val: serde_json::Value =
            serde_json::from_str(json).map_err(|e| SerializeError::JsonError(e.to_string()))?;

        let arr = val.as_array().ok_or(SerializeError::InvalidFormat)?;

        let mut patterns = Vec::new();

        for entry in arr {
            let hex = entry["hex_pattern"]
                .as_str()
                .ok_or(SerializeError::InvalidFormat)?;
            let crc_len = u8::try_from(
                entry["crc_len"].as_u64().ok_or(SerializeError::InvalidFormat)?
            ).unwrap_or(u8::MAX);
            let crc16 = u16::try_from(
                entry["crc16"].as_u64().ok_or(SerializeError::InvalidFormat)?
            ).unwrap_or(u16::MAX);
            let total_len = u16::try_from(
                entry["total_len"].as_u64().ok_or(SerializeError::InvalidFormat)?
            ).unwrap_or(u16::MAX);

            let initial_bytes = parse_hex_to_pattern_bytes(hex)
                .ok_or_else(|| SerializeError::InvalidPattern(hex.to_string()))?;

            let names_val = entry["names"]
                .as_array()
                .ok_or(SerializeError::InvalidFormat)?;
            let mut names = Vec::new();
            for n in names_val {
                let name = n["name"].as_str().unwrap_or("").to_string();
                let offset = u16::try_from(n["offset"].as_u64().unwrap_or(0)).unwrap_or(0);
                let is_public = n["is_public"].as_bool().unwrap_or(false);
                let is_local = n["is_local"].as_bool().unwrap_or(false);
                names.push(FlirtName {
                    name,
                    offset,
                    is_public,
                    is_local,
                });
            }

            let mut pat = FlirtPattern::new(initial_bytes);
            pat.crc_length = crc_len;
            pat.crc16 = crc16;
            pat.pattern_length = total_len;
            pat.names = names;

            patterns.push(pat);
        }

        Ok(patterns)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Parse a single `.pat` line into a [`FlirtPattern`].
///
/// Returns `None` if the line is malformed.
fn parse_pat_line_to_flirt(line: &str) -> Option<FlirtPattern> {
    // Split pattern-bytes from the rest
    let (pat_hex, rest) = line.split_once(char::is_whitespace)?;
    let rest = rest.trim_start();

    let initial_bytes = parse_hex_to_pattern_bytes(pat_hex)?;

    // Must start with ':'
    let rest = rest.strip_prefix(':')?;

    // CRC_LEN (decimal)
    let (crc_len_tok, rest) = rest.split_once(char::is_whitespace)?;
    let crc_len: u8 = crc_len_tok.parse().ok()?;
    let rest = rest.trim_start();

    // CRC16 (hex)
    let (crc16_tok, rest) = rest.split_once(char::is_whitespace)?;
    let crc16: u16 = u16::from_str_radix(crc16_tok, 16).ok()?;
    let rest = rest.trim_start();

    // TOTAL_LEN — extends until whitespace or end
    let (total_tok, rest) = rest.split_once(char::is_whitespace).map_or((rest, ""), |p| p);
    let total_len: u16 = total_tok.trim().parse().ok()?;
    let rest = rest.trim_start();

    // Parse name entries: each `:OFFSET:KIND:NAME`
    let names = parse_name_entries_flirt(rest);

    let mut pat = FlirtPattern::new(initial_bytes);
    pat.crc_length = crc_len;
    pat.crc16 = crc16;
    pat.pattern_length = total_len;
    pat.names = names;

    Some(pat)
}

/// Parse name entries from the trailing part of a `.pat` line.
fn parse_name_entries_flirt(s: &str) -> Vec<FlirtName> {
    let mut names = Vec::new();
    let mut rest = s;

    while !rest.is_empty() {
        let r = rest.trim_start();
        if r.is_empty() || !r.starts_with(':') {
            break;
        }
        let inner = &r[1..]; // skip ':'

        // offset:kind:name (possibly followed by more ` :...` entries)
        let (offset_tok, inner) = match inner.find(':') {
            Some(p) => (&inner[..p], &inner[p + 1..]),
            None => break,
        };
        let (kind_tok, inner) = match inner.find(':') {
            Some(p) => (&inner[..p], &inner[p + 1..]),
            None => break,
        };
        let (name_tok, remaining) = split_at_space_colon(inner);

        let offset: u16 = u16::from_str_radix(offset_tok, 16)
            .or_else(|_| offset_tok.parse::<u16>())
            .unwrap_or(0);
        let is_local = kind_tok == "local" || kind_tok == "l";
        let is_public = !is_local;

        if !name_tok.is_empty() {
            names.push(FlirtName {
                name: name_tok.trim().to_string(),
                offset,
                is_public,
                is_local,
            });
        }
        rest = remaining;
    }

    names
}

/// Split `s` at the first ` :` (space colon) boundary.
fn split_at_space_colon(s: &str) -> (&str, &str) {
    let bytes = s.as_bytes();
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == b' ' && bytes[i + 1] == b':' {
            return (&s[..i], &s[i + 1..]);
        }
    }
    (s.trim_end(), "")
}

/// Convert a no-whitespace hex string (with `..` wildcards) to [`PatternByte`]s.
fn parse_hex_to_pattern_bytes(hex: &str) -> Option<Vec<PatternByte>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut result = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = bytes[i];
        let lo = bytes[i + 1];
        if hi == b'.' && lo == b'.' {
            result.push(PatternByte::Wildcard);
        } else {
            let h = hex_nibble(hi)?;
            let l = hex_nibble(lo)?;
            result.push(PatternByte::Exact((h << 4) | l));
        }
        i += 2;
    }
    Some(result)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pattern(name: &str, bytes: &[PatternByte]) -> FlirtPattern {
        let mut p = FlirtPattern::new(bytes.to_vec());
        p.names.push(FlirtName {
            name: name.to_string(),
            offset: 0,
            is_public: true,
            is_local: false,
        });
        p.pattern_length = u16::try_from(bytes.len()).expect("test pattern fits in u16");
        p
    }

    // ── PatSerializer::to_pat_line ────────────────────────────────────────────

    #[test]
    fn test_to_pat_line_basic() {
        let mut p = FlirtPattern::new(vec![
            PatternByte::Exact(0x55),
            PatternByte::Exact(0x8B),
            PatternByte::Exact(0xEC),
        ]);
        p.names.push(FlirtName {
            name: "my_fn".to_string(),
            offset: 0,
            is_public: true,
            is_local: false,
        });
        p.pattern_length = 3;
        let line = PatSerializer::to_pat_line(&p);
        assert!(line.contains("558BEC"));
        assert!(line.contains(":0000:public:my_fn"));
    }

    #[test]
    fn test_to_pat_line_pads_to_32_bytes() {
        let p = make_pattern("f", &[PatternByte::Exact(0x55)]);
        let line = PatSerializer::to_pat_line(&p);
        // 32 bytes = 64 hex chars
        let hex_part = line.split_whitespace().next().unwrap();
        assert_eq!(hex_part.len(), 64);
    }

    #[test]
    fn test_to_pat_line_wildcard_bytes() {
        let p = make_pattern(
            "f",
            &[
                PatternByte::Exact(0x55),
                PatternByte::Wildcard,
                PatternByte::Exact(0xEC),
            ],
        );
        let line = PatSerializer::to_pat_line(&p);
        assert!(line.contains("55..EC") || line.contains("55..ec"));
    }

    #[test]
    fn test_to_pat_no_names_no_crash() {
        let p = FlirtPattern::new(vec![PatternByte::Exact(0x55)]);
        let line = PatSerializer::to_pat_line(&p);
        assert!(!line.is_empty());
    }

    // ── PatSerializer::to_pat ─────────────────────────────────────────────────

    #[test]
    fn test_to_pat_ends_with_separator() {
        let pats = vec![make_pattern("f", &[PatternByte::Exact(0x55)])];
        let text = PatSerializer::to_pat(&pats);
        assert!(text.trim_end().ends_with("---"));
    }

    #[test]
    fn test_to_pat_multiple_patterns() {
        let pats = vec![
            make_pattern("func1", &[PatternByte::Exact(0x55)]),
            make_pattern("func2", &[PatternByte::Exact(0x8B)]),
        ];
        let text = PatSerializer::to_pat(&pats);
        assert!(text.contains("func1"));
        assert!(text.contains("func2"));
    }

    #[test]
    fn test_to_pat_empty_patterns() {
        let text = PatSerializer::to_pat(&[]);
        assert_eq!(text.trim(), "---");
    }

    // ── PatSerializer::to_json ────────────────────────────────────────────────

    #[test]
    fn test_to_json_valid() {
        let pats = vec![make_pattern("fn1", &[PatternByte::Exact(0x55)])];
        let json = PatSerializer::to_json(&pats).unwrap();
        assert!(json.contains("hex_pattern"));
        assert!(json.contains("fn1"));
    }

    #[test]
    fn test_to_json_empty() {
        let json = PatSerializer::to_json(&[]).unwrap();
        assert_eq!(json.trim(), "[]");
    }

    // ── PatDeserializer::from_pat ─────────────────────────────────────────────

    #[test]
    fn test_from_pat_basic() {
        // 32-byte pattern in compact form: 3 real bytes + 29 wildcard pairs
        let hex = "558BEC".to_string() + &"..".repeat(29);
        let line = format!("{hex} :4 ABCD 20 :0000:public:myfunc\n---\n");
        let pats = PatDeserializer::from_pat(&line).unwrap();
        assert_eq!(pats.len(), 1);
        assert_eq!(pats[0].names[0].name, "myfunc");
        assert_eq!(pats[0].crc16, 0xABCD);
        assert_eq!(pats[0].total_len(), 20);
    }

    #[test]
    fn test_from_pat_skips_separators() {
        let hex = "558BEC".to_string() + &"..".repeat(29);
        let text = format!("---\n{hex} :0 0000 3 :0000:public:f\n---END---\n");
        let pats = PatDeserializer::from_pat(&text).unwrap();
        assert_eq!(pats.len(), 1);
    }

    #[test]
    fn test_from_pat_empty() {
        let pats = PatDeserializer::from_pat("---\n").unwrap();
        assert!(pats.is_empty());
    }

    // ── PatDeserializer::from_json ────────────────────────────────────────────

    #[test]
    fn test_from_json_roundtrip() {
        let pats = vec![make_pattern(
            "round_trip",
            &[
                PatternByte::Exact(0x55),
                PatternByte::Exact(0x8B),
                PatternByte::Wildcard,
            ],
        )];
        let json = PatSerializer::to_json(&pats).unwrap();
        let pats2 = PatDeserializer::from_json(&json).unwrap();
        assert_eq!(pats2.len(), 1);
        assert_eq!(pats2[0].names[0].name, "round_trip");
        assert_eq!(pats2[0].initial_bytes[2], PatternByte::Wildcard);
    }

    #[test]
    fn test_from_json_invalid_json() {
        let r = PatDeserializer::from_json("not json");
        assert!(matches!(r, Err(SerializeError::JsonError(_))));
    }

    #[test]
    fn test_from_json_not_array() {
        let r = PatDeserializer::from_json("{}");
        assert!(matches!(r, Err(SerializeError::InvalidFormat)));
    }

    // ── Round-trip pat ────────────────────────────────────────────────────────

    #[test]
    fn test_pat_roundtrip_name_preserved() {
        let pats = vec![make_pattern(
            "rt_func",
            &[
                PatternByte::Exact(0x48),
                PatternByte::Exact(0x89),
                PatternByte::Exact(0xE5),
            ],
        )];
        let text = PatSerializer::to_pat(&pats);
        let pats2 = PatDeserializer::from_pat(&text).unwrap();
        assert_eq!(pats2.len(), 1);
        assert_eq!(pats2[0].names[0].name, "rt_func");
    }

    #[test]
    fn test_json_roundtrip_crc_fields() {
        let mut p = FlirtPattern::new(vec![PatternByte::Exact(0x55); 4]);
        p.crc_length = 8;
        p.crc16 = 0x1234;
        p.pattern_length = 32;
        p.names.push(FlirtName {
            name: "crc_test".to_string(),
            offset: 0,
            is_public: true,
            is_local: false,
        });
        let json = PatSerializer::to_json(&[p]).unwrap();
        let pats2 = PatDeserializer::from_json(&json).unwrap();
        assert_eq!(pats2[0].crc_length, 8);
        assert_eq!(pats2[0].crc16, 0x1234);
    }

    // ── SerializeError display ────────────────────────────────────────────────

    #[test]
    fn test_error_display_invalid_format() {
        assert!(!SerializeError::InvalidFormat.to_string().is_empty());
    }

    #[test]
    fn test_error_display_invalid_pattern() {
        let e = SerializeError::InvalidPattern("bad".to_string());
        assert!(e.to_string().contains("bad"));
    }

    #[test]
    fn test_error_display_json_error() {
        let e = SerializeError::JsonError("oops".to_string());
        assert!(e.to_string().contains("oops"));
    }

    // ── FlirtPattern helper method ────────────────────────────────────────────

    /// Access `total_len` via `pattern_length` field
    trait PatLen {
        fn total_len(&self) -> u16;
    }
    impl PatLen for FlirtPattern {
        fn total_len(&self) -> u16 {
            self.pattern_length
        }
    }
}
