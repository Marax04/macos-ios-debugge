// pat_parser.rs — Parse IDA FLIRT .pat source format

use serde::{Deserialize, Serialize};
use anyhow::{bail, Context, Result};

// ── PAT format structures ──────────────────────────────────────────────────────

/// A single .pat entry (one line = one function signature)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatEntry {
    /// Initial bytes pattern (up to 32 bytes, '..' for wildcards)
    pub initial_bytes: Vec<PatByte>,
    /// CRC16 length (2 hex digits)
    pub crc_len: u8,
    /// CRC16 value over the byte range after `initial_bytes`
    pub crc16: u16,
    /// Total function length
    pub total_len: u32,
    /// Primary function name (at offset 0)
    pub primary_name: String,
    /// Offset of primary name (usually 0 for the function entry)
    pub primary_offset: u32,
    /// Additional public names within this function, keyed by offset
    pub public_names: Vec<PatPublicName>,
    /// Referenced names (tail bytes reference other functions)
    pub ref_names: Vec<PatRefName>,
    /// Tail bytes: remaining pattern after the initial bytes + CRC area
    pub tail_bytes: Vec<PatTailByte>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatByte {
    Exact(u8),
    Wildcard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatPublicName {
    pub offset: u32,
    pub name: String,
    pub is_local: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatRefName {
    pub offset: u32,
    pub name: String,
    pub addend: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatTailByte {
    pub offset: u32,
    pub byte: u8,
}

type ParsedNamesAndTail = (String, u32, Vec<PatPublicName>, Vec<PatRefName>, Vec<PatTailByte>);

// ── Parser ─────────────────────────────────────────────────────────────────────

pub struct PatParser {
    pub strict_mode: bool,
}

impl Default for PatParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PatParser {
    #[must_use] 
    pub const fn new() -> Self {
        Self { strict_mode: false }
    }

    /// # Errors
    /// Returns an error if any line fails to parse.
    pub fn parse_str(&self, source: &str) -> Result<Vec<PatEntry>> {
        let mut entries = Vec::new();

        for (line_num, line) in source.lines().enumerate() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with(';') || line.starts_with("---") {
                continue;
            }

            match Self::parse_line(line) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    if self.strict_mode {
                        return Err(e).with_context(|| format!("Line {}", line_num + 1));
                    }
                    // In lenient mode, skip bad lines
                    tracing::debug!("Skipping bad pat line {}: {}", line_num + 1, e);
                }
            }
        }

        Ok(entries)
    }

    fn parse_line(line: &str) -> Result<PatEntry> {
        let mut pos = 0;
        let bytes = line.as_bytes();

        // Read initial bytes (up to 64 hex chars = 32 bytes, '..' for wildcards)
        let mut initial_bytes = Vec::new();
        while pos + 1 < bytes.len() {
            if bytes[pos] == b'.' && bytes[pos + 1] == b'.' {
                initial_bytes.push(PatByte::Wildcard);
                pos += 2;
            } else if bytes[pos].is_ascii_hexdigit() && pos + 1 < bytes.len() && bytes[pos + 1].is_ascii_hexdigit() {
                let hi = hex_nibble(bytes[pos]);
                let lo = hex_nibble(bytes[pos + 1]);
                initial_bytes.push(PatByte::Exact((hi << 4) | lo));
                pos += 2;
            } else {
                break;
            }

            // Max 32 bytes for initial pattern
            if initial_bytes.len() >= 32 {
                break;
            }
        }

        if initial_bytes.is_empty() {
            bail!("No initial bytes found");
        }

        // Skip spaces
        while pos < bytes.len() && bytes[pos] == b' ' {
            pos += 1;
        }

        // Read CRC length (2 hex digits)
        if pos + 2 > bytes.len() {
            bail!("Missing CRC length");
        }
        let crc_len = (hex_nibble(bytes[pos]) << 4) | hex_nibble(bytes[pos + 1]);
        pos += 2;

        // Skip spaces
        while pos < bytes.len() && bytes[pos] == b' ' {
            pos += 1;
        }

        // Read CRC16 (4 hex digits)
        if pos + 4 > bytes.len() {
            bail!("Missing CRC16");
        }
        // Use the byte array for slicing to avoid splitting multibyte UTF-8 codepoints.
        let crc16_str = std::str::from_utf8(&bytes[pos..pos + 4])
            .map_err(|_| anyhow::anyhow!("Invalid UTF-8 in CRC16 field"))?;
        let crc16 = u16::from_str_radix(crc16_str, 16)
            .with_context(|| "Invalid CRC16")?;
        pos += 4;

        // Skip spaces
        while pos < bytes.len() && bytes[pos] == b' ' {
            pos += 1;
        }

        // Read total length (hex, variable width, followed by space)
        let total_len_start = pos;
        while pos < bytes.len() && bytes[pos] != b' ' {
            pos += 1;
        }
        let total_len_str = std::str::from_utf8(&bytes[total_len_start..pos])
            .map_err(|_| anyhow::anyhow!("Invalid UTF-8 in total_len field"))?;
        let total_len = u32::from_str_radix(total_len_str, 16)
            .with_context(|| "Invalid total length")?;

        // Skip spaces
        while pos < bytes.len() && bytes[pos] == b' ' {
            pos += 1;
        }

        // Read public names and tail bytes from the rest.
        // Use get() to avoid panicking if pos points into a multibyte UTF-8 sequence.
        let rest = line.get(pos..).unwrap_or("");
        let (primary_name, primary_offset, public_names, ref_names, tail_bytes) =
            Self::parse_names_and_tail(rest);

        Ok(PatEntry {
            initial_bytes,
            crc_len,
            crc16,
            total_len,
            primary_name,
            primary_offset,
            public_names,
            ref_names,
            tail_bytes,
        })
    }

    fn parse_names_and_tail(s: &str) -> ParsedNamesAndTail {
        // Format: [:offset] name1 [offset2:name2 ...] [^offset:refname[+addend]] [tail_bytes]
        // Example: :0 _malloc_r ^000A:malloc :0070 _malloc_align
        let mut public_names: Vec<PatPublicName> = Vec::new();
        let mut ref_names: Vec<PatRefName> = Vec::new();
        let mut tail_bytes: Vec<PatTailByte> = Vec::new();
        let mut primary_name = String::new();
        let mut primary_offset = 0u32;

        let parts: Vec<&str> = s.split_whitespace().collect();
        let mut i = 0;

        while i < parts.len() {
            let part = parts[i];

            if let Some(rest) = part.strip_prefix('^') {
                // Referenced name: ^offset:name[+addend]
                if let Some(colon_pos) = rest.find(':') {
                    let offset = u32::from_str_radix(&rest[..colon_pos], 16).unwrap_or(0);
                    let name_part = &rest[colon_pos + 1..];
                    let (name, addend) = name_part.find('+').map_or_else(
                        || name_part.find('-').map_or_else(
                            || (name_part.to_string(), 0),
                            |minus_pos| {
                                let n = &name_part[..minus_pos];
                                let a = -(i32::from_str_radix(&name_part[minus_pos + 1..], 16).unwrap_or(0));
                                (n.to_string(), a)
                            }
                        ),
                        |plus_pos| {
                            let n = &name_part[..plus_pos];
                            let a = i32::from_str_radix(&name_part[plus_pos + 1..], 16).unwrap_or(0);
                            (n.to_string(), a)
                        }
                    );
                    ref_names.push(PatRefName { offset, name, addend });
                }
            } else if let Some(offset_str) = part.strip_prefix(':') {
                // Offset annotation: :hexoffset funcname
                let offset = u32::from_str_radix(offset_str, 16).unwrap_or(0);
                i += 1;
                if i < parts.len() {
                    let name = parts[i];
                    if name.starts_with('(') {
                        // Local symbol
                        let clean = name.trim_matches(|c| c == '(' || c == ')');
                        public_names.push(PatPublicName {
                            offset,
                            name: clean.to_string(),
                            is_local: true,
                        });
                    } else if primary_name.is_empty() {
                        primary_name = name.to_string();
                        primary_offset = offset;
                    } else {
                        public_names.push(PatPublicName {
                            offset,
                            name: name.to_string(),
                            is_local: false,
                        });
                    }
                }
            } else if part.len() == 4 && part.chars().all(|c| c.is_ascii_hexdigit()) {
                // Tail byte: offset (4 hex digits) followed by byte value
                if i + 1 < parts.len() && parts[i + 1].len() == 2 {
                    let offset = u32::from_str_radix(part, 16).unwrap_or(0);
                    let byte_val = u8::from_str_radix(parts[i + 1], 16).unwrap_or(0);
                    tail_bytes.push(PatTailByte { offset, byte: byte_val });
                    i += 1;
                } else {
                    // Just a name at this point
                    if primary_name.is_empty() {
                        primary_name = part.to_string();
                    }
                }
            } else if !part.is_empty() && part.chars().next().is_some_and(|c| c.is_alphanumeric() || c == '_') {
                // Plain function name (primary, offset = 0)
                if primary_name.is_empty() {
                    primary_name = part.to_string();
                } else {
                    public_names.push(PatPublicName {
                        offset: 0,
                        name: part.to_string(),
                        is_local: false,
                    });
                }
            }

            i += 1;
        }

        if primary_name.is_empty() {
            primary_name = "unknown".to_string();
        }

        (primary_name, primary_offset, public_names, ref_names, tail_bytes)
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

// ── CRC16 (CCITT) ─────────────────────────────────────────────────────────────

#[must_use] 
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    crate::crc::ccitt_false(data)
}

/// Verify that a `PatEntry`'s CRC16 matches the provided function bytes
#[must_use] 
pub fn verify_pat_crc(entry: &PatEntry, func_bytes: &[u8]) -> bool {
    let initial_len = entry.initial_bytes.len();
    let crc_start = initial_len;
    let crc_end = crc_start + entry.crc_len as usize;

    if crc_end > func_bytes.len() {
        return false;
    }

    // BUG FIX: this verified the .pat tail CRC with CCITT-FALSE while the rest
    // of the stack writes and checks it with the reflected FLIRT CRC.
    let computed = crate::crc::flirt_tail(&func_bytes[crc_start..crc_end]);
    computed == entry.crc16
}

// ── Match function bytes against PatEntry ─────────────────────────────────────

#[must_use] 
pub fn matches_pat_entry(entry: &PatEntry, func_bytes: &[u8]) -> bool {
    // Check total length
    if func_bytes.len() < entry.total_len as usize {
        return false;
    }

    // Match initial bytes
    for (i, pat_byte) in entry.initial_bytes.iter().enumerate() {
        if i >= func_bytes.len() {
            return false;
        }
        if let PatByte::Exact(expected) = pat_byte
            && func_bytes[i] != *expected {
                return false;
            }
    }

    // Verify CRC16
    if entry.crc_len > 0 && !verify_pat_crc(entry, func_bytes) {
        return false;
    }

    // Check tail bytes
    for tail in &entry.tail_bytes {
        let idx = tail.offset as usize;
        if idx >= func_bytes.len() {
            return false;
        }
        if func_bytes[idx] != tail.byte {
            return false;
        }
    }

    true
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_pat_line() {
        // Simplified pat line: initial bytes, crc_len, crc16, total_len, name
        let line = "5589E5538B5D0883EB0183FFFE 10 1234 0020 :0000 my_function";
        let parser = PatParser::new();
        let entries = parser.parse_str(line).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].primary_name, "my_function");
    }

    #[test]
    fn test_crc16() {
        let data = b"hello";
        let crc = crc16_ccitt(data);
        assert_ne!(crc, 0);
    }

    #[test]
    fn test_matches_exact() {
        let entry = PatEntry {
            initial_bytes: vec![PatByte::Exact(0x55), PatByte::Exact(0x89), PatByte::Exact(0xE5)],
            crc_len: 0,
            crc16: 0,
            total_len: 3,
            primary_name: "test".to_string(),
            primary_offset: 0,
            public_names: vec![],
            ref_names: vec![],
            tail_bytes: vec![],
        };
        assert!(matches_pat_entry(&entry, &[0x55, 0x89, 0xE5, 0x00]));
        assert!(!matches_pat_entry(&entry, &[0x55, 0x89, 0xE6, 0x00]));
    }

    #[test]
    fn test_wildcard() {
        let entry = PatEntry {
            initial_bytes: vec![PatByte::Exact(0x55), PatByte::Wildcard, PatByte::Exact(0xE5)],
            crc_len: 0,
            crc16: 0,
            total_len: 3,
            primary_name: "test".to_string(),
            primary_offset: 0,
            public_names: vec![],
            ref_names: vec![],
            tail_bytes: vec![],
        };
        assert!(matches_pat_entry(&entry, &[0x55, 0x42, 0xE5]));
        assert!(matches_pat_entry(&entry, &[0x55, 0xFF, 0xE5]));
    }
}
