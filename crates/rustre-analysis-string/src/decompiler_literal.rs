//! Adapter: the *string-literal-at-a-pointer-target* question the decompiler
//! asks today, answered by this crate's [`StringScanner`] engine.
//!
//! `rustre-decompiler::binary_entry::read_string_literal` privately
//! re-implements string recovery: given the bytes at the target of a
//! `lea …(%rip)`, decide whether they are a NUL-terminated ASCII or
//! UTF-16LE(ASCII-subset) string, and if so render a C literal.
//!
//! That splits into two concerns:
//!   * **recovery** — locate/validate the NUL-terminated run. This crate owns
//!     it ([`StringScanner::scan_ascii`] / [`StringScanner::scan_utf16_le`]).
//!   * **emission** — C escaping, 60-char truncation, `L"…"` spelling. That is
//!     genuinely the decompiler's concern and stays there; it is reproduced
//!     here only so the seam can be proved output-identical.
//!
//! Nothing consumes this yet. It exists so a later landing can delete the
//! private copy without changing a byte of emitted output.
//!
//! ## One real semantic gap, compensated here
//!
//! [`StringScanner::is_printable_ascii_cfg`] treats only `0x20..0x7F` as
//! printable. The decompiler additionally accepts `\t`, `\n`, `\r` inside a
//! run (they are perfectly legal in a C string literal, and format strings are
//! full of `\n`). Feeding raw bytes to the scanner would therefore *lose*
//! every literal containing them. [`normalize_c_whitespace`] substitutes those
//! three bytes with a printable placeholder before scanning — a length- and
//! offset-preserving 1:1 map, so the recovered run is re-read from the
//! original bytes and nothing is corrupted.

use crate::{Address, FoundString, StringScanner, StringScannerConfig};

/// Minimum run length, matching the decompiler's `MIN_LEN`.
pub const MIN_LEN: usize = 4;
/// Bytes examined at the pointer target, matching the decompiler's `MAX_SCAN`.
pub const MAX_SCAN: usize = 512;
/// Characters emitted before an ellipsis, matching the decompiler's `MAX_EMIT`.
pub const MAX_EMIT: usize = 60;

/// Placeholder standing in for `\t`/`\n`/`\r` during scanning. Any byte in
/// `0x20..0x7F` works; `'~'` is arbitrary and never read back.
const WS_PLACEHOLDER: u8 = b'~';

/// True for the byte set the *decompiler* considers literal-worthy.
#[must_use]
pub fn is_c_printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r'
}

/// Replace `\t`/`\n`/`\r` with a printable placeholder, 1:1 by offset.
#[must_use]
pub fn normalize_c_whitespace(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .map(|&b| {
            if b == b'\t' || b == b'\n' || b == b'\r' {
                WS_PLACEHOLDER
            } else {
                b
            }
        })
        .collect()
}

fn scanner() -> StringScanner {
    StringScanner::new(StringScannerConfig {
        min_length: MIN_LEN,
        max_length: MAX_SCAN,
        require_null_terminator: true,
        allow_high_ascii: false,
        ..StringScannerConfig::default()
    })
}

/// C-escape a byte run and truncate the way the decompiler emits.
#[must_use]
pub fn escape_c(run: &[u8]) -> String {
    let mut out = String::new();
    for &b in run.iter().take(MAX_EMIT) {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            b'\r' => out.push_str("\\r"),
            _ => out.push(b as char),
        }
    }
    if run.len() > MAX_EMIT {
        out.push_str("...");
    }
    out
}

/// The ASCII run this crate recovers *starting exactly at offset 0* of the
/// pointer target, or `None`.
#[must_use]
pub fn recover_ascii_at_target(bytes: &[u8]) -> Option<FoundString> {
    let window = &bytes[..bytes.len().min(MAX_SCAN)];
    let norm = normalize_c_whitespace(window);
    scanner()
        .scan_ascii(Address(0), &norm)
        .into_iter()
        .find(|s| s.address.0 == 0)
}

/// The UTF-16LE run this crate recovers starting exactly at offset 0.
#[must_use]
pub fn recover_utf16_at_target(bytes: &[u8]) -> Option<FoundString> {
    let window = &bytes[..bytes.len().min(MAX_SCAN)];
    let norm = normalize_c_whitespace(window);
    scanner()
        .scan_utf16_le(Address(0), &norm)
        .into_iter()
        .find(|s| s.address.0 == 0)
}

/// Full adapter: the C literal the decompiler would emit for `bytes`, derived
/// entirely from this crate's recovery engine.
///
/// Returns e.g. `"\"hello\""` or `"L\"wide\""`.
#[must_use]
pub fn literal_at_target(bytes: &[u8]) -> Option<String> {
    let window = &bytes[..bytes.len().min(MAX_SCAN)];

    if let Some(found) = recover_ascii_at_target(window) {
        let run = &window[..found.length - usize::from(found.is_null_terminated)];
        return Some(format!("\"{}\"", escape_c(run)));
    }

    // The decompiler only considers UTF-16 when the ASCII run is 0 or 1 bytes
    // long (a wide "A\0B\0" starts with one printable byte then a NUL).
    let ascii_run = window.iter().take_while(|&&b| is_c_printable(b)).count();
    if ascii_run <= 1
        && let Some(found) = recover_utf16_at_target(window)
    {
        let chars: Vec<u8> = window
            .iter()
            .step_by(2)
            .take(found.char_count)
            .copied()
            .collect();
        return Some(format!("L\"{}\"", escape_c(&chars)));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim copy of `rustre_decompiler::binary_entry::read_string_literal`
    /// as of 2026-07-20 — the oracle the adapter is differentially tested
    /// against. Do not "improve" it; its job is to be the other side.
    fn oracle_read_string_literal(bytes: &[u8]) -> Option<String> {
        const MIN_LEN: usize = 4;
        const MAX_SCAN: usize = 512;
        const MAX_EMIT: usize = 60;
        let printable = |b: u8| (0x20..0x7f).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r';
        let escape = |s: &[u8]| {
            let mut out = String::new();
            for &b in s.iter().take(MAX_EMIT) {
                match b {
                    b'\\' => out.push_str("\\\\"),
                    b'"' => out.push_str("\\\""),
                    b'\n' => out.push_str("\\n"),
                    b'\t' => out.push_str("\\t"),
                    b'\r' => out.push_str("\\r"),
                    _ => out.push(b as char),
                }
            }
            if s.len() > MAX_EMIT {
                out.push_str("...");
            }
            out
        };
        let window = &bytes[..bytes.len().min(MAX_SCAN)];
        let run = window.iter().take_while(|&&b| printable(b)).count();
        if run >= MIN_LEN && window.get(run) == Some(&0) {
            return Some(format!("\"{}\"", escape(&window[..run])));
        }
        if run <= 1 {
            let mut chars: Vec<u8> = Vec::new();
            let mut k = 0;
            while k + 1 < window.len() && printable(window[k]) && window[k + 1] == 0 {
                chars.push(window[k]);
                k += 2;
            }
            if chars.len() >= MIN_LEN && k + 1 < window.len() && window[k] == 0 && window[k + 1] == 0
            {
                return Some(format!("L\"{}\"", escape(&chars)));
            }
        }
        None
    }

    fn agree(bytes: &[u8]) {
        assert_eq!(
            literal_at_target(bytes),
            oracle_read_string_literal(bytes),
            "adapter disagrees with decompiler oracle on {bytes:?}"
        );
    }

    #[test]
    fn differential_ascii_cases() {
        agree(b"hello world\0junk");
        agree(b"a\"b\\c\nd\0");
        agree(b"with\ttab\0");
        agree(b"crlf\r\n\0");
        agree(b"hi\0"); // too short
        agree(b"\x01\x02\x03\x04");
        agree(b"abcdef"); // no NUL in window
        agree(b"");
        agree(b"\0\0\0\0");
        agree(b"exact\0");
    }

    #[test]
    fn differential_utf16_cases() {
        agree(b"w\0i\0d\0e\0!\0\0\0");
        agree(b"w\0i\0d\0e\0"); // no double-NUL terminator
        agree(b"a\0b\0\0\0"); // too short
    }

    #[test]
    fn differential_truncation() {
        let mut long = vec![b'A'; 200];
        long.push(0);
        agree(&long);
        let mut exact = vec![b'B'; MAX_EMIT];
        exact.push(0);
        agree(&exact);
        let mut over = vec![b'C'; MAX_EMIT + 1];
        over.push(0);
        agree(&over);
    }

    #[test]
    fn differential_max_scan_boundary() {
        // NUL sits just past the 512-byte window: both must decline.
        let mut v = vec![b'D'; MAX_SCAN];
        v.push(0);
        agree(&v);
        // NUL is the last byte inside the window: both must accept.
        let mut w = vec![b'E'; MAX_SCAN - 1];
        w.push(0);
        agree(&w);
    }

    #[test]
    fn differential_exhaustive_small_inputs() {
        // Every 3-byte string over a byte alphabet that exercises each class:
        // printable, C whitespace, NUL, high, control.
        const ALPHABET: [u8; 6] = [b'A', b'\t', b'\n', 0, 0x80, 0x01];
        for a in ALPHABET {
            for b in ALPHABET {
                for c in ALPHABET {
                    for d in ALPHABET {
                        for e in ALPHABET {
                            // Built inside the loop: the previous form declared
                            // `let mut v = [0u8; 5]` outside it and overwrote the
                            // initial value on the very first iteration without
                            // ever reading it, so the zeroed case — a 5-byte NUL
                            // string, a real input class — was never tested even
                            // though the array looked like it covered it.
                            // ALPHABET does contain 0, so the all-NUL case is
                            // reached on merit here.
                            let v = [a, b, c, d, e];
                            agree(&v);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn whitespace_normalization_is_length_preserving() {
        let src = b"a\tb\nc\rd";
        let n = normalize_c_whitespace(src);
        assert_eq!(n.len(), src.len());
        assert!(n.iter().all(|&b| is_c_printable(b) && b >= 0x20));
    }
}
