//! The canonical IDA `.pat` line format — one parser, matching what we write.
//!
//! # Why this exists (T4)
//!
//! Iteration 48 measured the writer × parser matrix: **six combinations of six
//! recovered zero lines**, including each writer paired with the parser living
//! in its own crate. The three existing parsers each implement a different
//! bespoke dialect:
//!
//! * `flirt_apply::pat_parser` — requires a leading `:` and a **decimal**
//!   `crc_len` (`HEX :8 BEEF 64 :0:0:name`);
//! * `flirt::pat_parser_v2` — requires every name to carry a known prefix and a
//!   `delta` field;
//! * `flirt::SimpleFlirtDatabase::parse_pat_text` — accepts none of the above.
//!
//! None of them accepts the documented IDA format, which is what
//! `pat_file_writer` and `flirt_signature_writer` both emit, and which is the
//! only format an external tool (flair, `sigmake`, IDA itself) will produce.
//!
//! This module implements that documented format and nothing else. It is
//! **additive**: the three dialect parsers are untouched, so their tests keep
//! passing. Collapsing them into re-exports of this one is the rest of T4 and
//! needs a decision about which callers move first.
//!
//! # The grammar
//!
//! ```text
//! <pattern> <crc_len> <crc16> <total_len> <name-entry>...
//! ```
//!
//! * `pattern` — hex byte pairs, `..` for a wildcard, e.g. `4041..43`;
//! * `crc_len` — 2 hex digits, bytes covered by the CRC after the pattern;
//! * `crc16` — 4 hex digits;
//! * `total_len` — 4 hex digits, the function's full length;
//! * name entries — one or more, each optionally preceded by a positional
//!   marker: `:OFFSET` (public name at that offset), `^OFFSET` (a reference to
//!   another name), or no marker at all (a public name at offset 0, which is
//!   what our own writers emit).
//!
//! A line of `---` terminates the file; blank lines and lines starting with `;`
//! or `#` are comments.

use crate::{FlirtName, FlirtPattern, PatternByte};

/// Why a `.pat` line could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatCanonicalError {
    /// Fewer than the five required fields.
    TooFewFields { line: usize, got: usize },
    /// The pattern field is not hex byte pairs / `..`.
    BadPattern { line: usize, field: String },
    /// A fixed numeric field is not the expected hex width.
    BadNumber { line: usize, field: String },
    /// A name entry carried a marker that could not be decoded.
    BadName { line: usize, field: String },
}

/// Parse the pattern field: hex byte pairs, `..` for a wildcard.
fn parse_pattern(field: &str, line: usize) -> Result<Vec<PatternByte>, PatCanonicalError> {
    if field.is_empty() || !field.len().is_multiple_of(2) {
        return Err(PatCanonicalError::BadPattern {
            line,
            field: field.to_string(),
        });
    }
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(field.len() / 2);
    for pair in bytes.chunks_exact(2) {
        // `..` and `??` both appear in the wild for "don't care".
        if pair == b".." || pair == b"??" {
            out.push(PatternByte::Wildcard);
            continue;
        }
        let hi = (pair[0] as char).to_digit(16);
        let lo = (pair[1] as char).to_digit(16);
        match (hi, lo) {
            (Some(h), Some(l)) => {
                // Both digits valid: a concrete byte. `to_digit(16)` yields
                // 0..=15, so `h * 16 + l` is 0..=255 and the conversion cannot
                // fail; the error arm is propagated rather than unwrapped so a
                // future change to the digit parser cannot turn into a panic on
                // attacker-supplied .pat input.
                let Ok(byte) = u8::try_from(h * 16 + l) else {
                    return Err(PatCanonicalError::BadPattern {
                        line,
                        field: field.to_string(),
                    });
                };
                out.push(PatternByte::Exact(byte));
            }
            _ => {
                return Err(PatCanonicalError::BadPattern {
                    line,
                    field: field.to_string(),
                });
            }
        }
    }
    Ok(out)
}

fn parse_hex<T: TryFrom<u32>>(field: &str, line: usize) -> Result<T, PatCanonicalError> {
    u32::from_str_radix(field, 16)
        .ok()
        .and_then(|v| T::try_from(v).ok())
        .ok_or_else(|| PatCanonicalError::BadNumber {
            line,
            field: field.to_string(),
        })
}

/// True when a line carries no data: blank, a comment, or the `---` terminator.
#[must_use]
pub fn is_ignorable(line: &str) -> bool {
    let t = line.trim();
    t.is_empty() || t.starts_with("---") || t.starts_with(';') || t.starts_with('#')
}

/// Parse one canonical `.pat` line.
///
/// # Errors
///
/// Returns a [`PatCanonicalError`] describing which field failed and on which
/// line, rather than a bare "invalid line" — the three existing parsers report
/// the latter, which is why the format mismatch went unnoticed for so long.
pub fn parse_line(line: &str, lineno: usize) -> Result<FlirtPattern, PatCanonicalError> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 5 {
        return Err(PatCanonicalError::TooFewFields {
            line: lineno,
            got: fields.len(),
        });
    }

    let initial_bytes = parse_pattern(fields[0], lineno)?;
    let crc_length: u8 = parse_hex(fields[1], lineno)?;
    let crc16: u16 = parse_hex(fields[2], lineno)?;
    let pattern_length: u16 = parse_hex(fields[3], lineno)?;

    let mut pattern = FlirtPattern::new(initial_bytes);
    pattern.crc_length = crc_length;
    pattern.crc16 = crc16;
    pattern.pattern_length = pattern_length;

    // Name entries. A bare token is a public name at offset 0; `:HHHH` and
    // `^HHHH` set the offset for the token that follows.
    let mut pending_offset: Option<u16> = None;
    let mut is_ref = false;
    for tok in &fields[4..] {
        if let Some(rest) = tok.strip_prefix(':').or_else(|| tok.strip_prefix('^')) {
            is_ref = tok.starts_with('^');
            // `:0000name` (glued) and `:0000 name` (separate) both occur.
            let (digits, glued) = rest.split_at(rest.len().min(4));
            pending_offset = Some(parse_hex::<u16>(digits, lineno)?);
            if !glued.is_empty() {
                pattern.names.push(FlirtName {
                    offset: pending_offset.take().unwrap_or(0),
                    name: glued.to_string(),
                    is_public: !is_ref,
                    is_local: false,
                });
            }
            continue;
        }
        pattern.names.push(FlirtName {
            offset: pending_offset.take().unwrap_or(0),
            name: (*tok).to_string(),
            is_public: !is_ref,
            is_local: false,
        });
        is_ref = false;
    }

    if pattern.names.is_empty() {
        return Err(PatCanonicalError::BadName {
            line: lineno,
            field: fields[4..].join(" "),
        });
    }
    Ok(pattern)
}

/// Parse a whole `.pat` file, skipping comments and stopping at `---`.
///
/// Returns the patterns and the per-line errors, so a caller can decide whether
/// a partial read is acceptable instead of having the decision made for it —
/// `SimpleFlirtDatabase::parse_pat_text` swallows errors silently, which is how
/// "zero patterns recovered" looked like success.
#[must_use]
pub fn parse_text(text: &str) -> (Vec<FlirtPattern>, Vec<PatCanonicalError>) {
    let mut pats = Vec::new();
    let mut errs = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().starts_with("---") {
            break;
        }
        if is_ignorable(line) {
            continue;
        }
        match parse_line(line, i) {
            Ok(p) => pats.push(p),
            Err(e) => errs.push(e),
        }
    }
    (pats, errs)
}
