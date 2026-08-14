//! Reader and `.sig` converter for the project's own `RFLIRTBIN` container.
//!
//! # Why this module exists
//!
//! `assets/rust-stdlib.sig` is a 10.8 MB database of generated signatures in
//! this project's own `RFLIRTBIN\0` format. It was written by the
//! `rust_stdlib_sigs` binary and read by **nothing on the decompilation path**:
//! the only decoder lived in `rustre-gui`. Meanwhile the decompiler identified
//! functions using 22 hand-written signatures.
//!
//! So the format had a writer here and a reader in a different crate that no
//! part of the pipeline consults — which is how a committed, generated,
//! multi-megabyte database ends up being dead weight.
//!
//! This module puts the reader next to the writer and adds the one thing that
//! makes the data useful: conversion to the `IDASGN` `.sig` that
//! `rustre_flirt_apply::FlirtScanner` can load.
//!
//! # Format
//!
//! ```text
//! "RFLIRTBIN\0"                       magic, 10 bytes
//! [u32 count]
//! per pattern:
//!   [u16 prefix_len][prefix_bytes]
//!   [u16 mask_len][mask_bytes]        0xFF = exact, 0x00 = wildcard
//!   [u16 crc16][u8 crc_length][u16 pattern_length]
//!   [u8 name_count]
//!   per name:
//!     [u8 flags]                      bit0 = is_public, bit1 = is_local
//!     [u16 offset]
//!     [u16 name_len][name_bytes]
//! ```

use rustre_flirt::{FlirtName, FlirtPattern, PatternByte};

use crate::GenError;

/// Magic that opens an `RFLIRTBIN` container.
pub const MAGIC: &[u8; 10] = b"RFLIRTBIN\0";

/// A cursor that refuses to read past the end of the buffer.
///
/// These files are inputs like any other, so every field length is checked
/// before use rather than trusted. A declared length that overruns is an error,
/// never a clamp: a truncated name or pattern would produce a signature that
/// looks valid and matches the wrong code.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn need(&self, n: usize) -> Result<(), GenError> {
        if self.pos + n > self.buf.len() {
            return Err(GenError::Parse(format!(
                "RFLIRTBIN truncated: need {n} bytes at offset {}, only {} left",
                self.pos,
                self.buf.len().saturating_sub(self.pos)
            )));
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, GenError> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn u16(&mut self) -> Result<u16, GenError> {
        self.need(2)?;
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn u32(&mut self) -> Result<u32, GenError> {
        self.need(4)?;
        let v = u32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], GenError> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

/// Decode an `RFLIRTBIN` container into patterns.
///
/// # Errors
///
/// Returns [`GenError::Parse`] on a bad magic or any truncated field.
pub fn parse(buf: &[u8]) -> Result<Vec<FlirtPattern>, GenError> {
    if buf.len() < MAGIC.len() + 4 || &buf[..MAGIC.len()] != MAGIC {
        return Err(GenError::Parse("not an RFLIRTBIN container".to_owned()));
    }
    let mut c = Cursor { buf, pos: MAGIC.len() };
    let count = c.u32()? as usize;

    // A declared count is only a hint until the bytes back it up. Each pattern
    // needs at least 10 bytes, so a count implying more than the file can hold
    // is corrupt — checking up front avoids a huge speculative allocation.
    let min_per_pattern = 10usize;
    let remaining = buf.len() - c.pos;
    if count.saturating_mul(min_per_pattern) > remaining {
        return Err(GenError::Parse(format!(
            "RFLIRTBIN declares {count} patterns but only {remaining} bytes remain"
        )));
    }

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let prefix_len = c.u16()? as usize;
        let prefix = c.bytes(prefix_len)?.to_vec();
        let mask_len = c.u16()? as usize;
        let mask = c.bytes(mask_len)?;

        if mask_len != prefix_len {
            return Err(GenError::Parse(format!(
                "pattern {i}: mask is {mask_len} bytes but prefix is {prefix_len}"
            )));
        }

        let initial_bytes: Vec<PatternByte> = prefix
            .iter()
            .zip(mask.iter())
            .map(|(&b, &m)| {
                if m == 0 {
                    PatternByte::Wildcard
                } else {
                    PatternByte::Exact(b)
                }
            })
            .collect();

        let mut pat = FlirtPattern::new(initial_bytes);
        pat.crc16 = c.u16()?;
        pat.crc_length = c.u8()?;
        pat.pattern_length = c.u16()?;

        let name_count = c.u8()? as usize;
        for _ in 0..name_count {
            let flags = c.u8()?;
            let offset = c.u16()?;
            let name_len = c.u16()? as usize;
            let name_bytes = c.bytes(name_len)?;
            pat.names.push(FlirtName {
                name: String::from_utf8_lossy(name_bytes).into_owned(),
                offset,
                is_public: flags & 0x01 != 0,
                is_local: flags & 0x02 != 0,
            });
        }
        out.push(pat);
    }
    Ok(out)
}

/// Read an `RFLIRTBIN` file from disk.
///
/// # Errors
///
/// Returns [`GenError::Parse`] on I/O failure or a malformed container.
pub fn parse_file(path: &std::path::Path) -> Result<Vec<FlirtPattern>, GenError> {
    let data = std::fs::read(path)
        .map_err(|e| GenError::Parse(format!("read {}: {e}", path.display())))?;
    parse(&data)
}

/// Convert an `RFLIRTBIN` container into `IDASGN` `.sig` bytes.
///
/// The result is what `rustre_flirt_apply::FlirtScanner::from_sig_bytes` loads,
/// so this is the bridge that turns the generated database into something the
/// decompilation path can actually use.
///
/// # Errors
///
/// Returns [`GenError::Parse`] on a malformed container.
pub fn to_sig_bytes(buf: &[u8], lib_name: &str, arch: u8) -> Result<Vec<u8>, GenError> {
    to_sig_bytes_filtered(buf, lib_name, arch, false)
}

/// Like [`to_sig_bytes`], but optionally keeps only patterns whose offset-0 name
/// is **public**.
///
/// 38.7% of the rust-stdlib database names its function only with a file-local
/// symbol (destructors, trait thunks). Whether those are worth keeping is a
/// precision/recall trade-off, so this exists to measure both sides rather than
/// to assume one.
///
/// # Errors
///
/// Returns [`GenError::Parse`] on a malformed container.
pub fn to_sig_bytes_filtered(
    buf: &[u8],
    lib_name: &str,
    arch: u8,
    public_names_only: bool,
) -> Result<Vec<u8>, GenError> {
    let mut pats = parse(buf)?;
    if public_names_only {
        pats.retain(|p| {
            p.names
                .iter()
                .any(|n| n.offset == 0 && n.is_public && !n.name.is_empty())
        });
    }
    let writer = crate::SigWriter { arch, ..crate::SigWriter::default() };
    Ok(writer.build(&pats, lib_name))
}

/// Convert an `RFLIRTBIN` file on disk into a `.sig` file on disk.
///
/// # Errors
///
/// Returns [`GenError::Parse`] on I/O failure or a malformed container,
/// [`GenError::Serialize`] if the output cannot be written.
pub fn convert_file(
    src: &std::path::Path,
    dst: &std::path::Path,
    lib_name: &str,
    arch: u8,
) -> Result<usize, GenError> {
    let pats = parse_file(src)?;
    let n = pats.len();
    let writer = crate::SigWriter { arch, ..crate::SigWriter::default() };
    let bytes = writer.build(&pats, lib_name);
    std::fs::write(dst, &bytes)
        .map_err(|e| GenError::Serialize(format!("write {}: {e}", dst.display())))?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an `RFLIRTBIN` container the same way `rust_stdlib_sigs` does, so
    /// the test exercises the real writer's layout rather than this reader's
    /// idea of it.
    fn encode(pats: &[FlirtPattern]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(MAGIC);
        f.extend_from_slice(&u32::try_from(pats.len()).unwrap().to_le_bytes());
        for p in pats {
            let mut prefix = Vec::new();
            let mut mask = Vec::new();
            for b in &p.initial_bytes {
                match b {
                    PatternByte::Exact(v) => {
                        prefix.push(*v);
                        mask.push(0xff);
                    }
                    PatternByte::Wildcard => {
                        prefix.push(0);
                        mask.push(0);
                    }
                }
            }
            f.extend_from_slice(&u16::try_from(prefix.len()).unwrap().to_le_bytes());
            f.extend_from_slice(&prefix);
            f.extend_from_slice(&u16::try_from(mask.len()).unwrap().to_le_bytes());
            f.extend_from_slice(&mask);
            f.extend_from_slice(&p.crc16.to_le_bytes());
            f.push(p.crc_length);
            f.extend_from_slice(&p.pattern_length.to_le_bytes());
            f.push(u8::try_from(p.names.len()).unwrap());
            for n in &p.names {
                let mut flags = 0u8;
                if n.is_public {
                    flags |= 0x01;
                }
                if n.is_local {
                    flags |= 0x02;
                }
                f.push(flags);
                f.extend_from_slice(&n.offset.to_le_bytes());
                let nb = n.name.as_bytes();
                f.extend_from_slice(&u16::try_from(nb.len()).unwrap().to_le_bytes());
                f.extend_from_slice(nb);
            }
        }
        f
    }

    fn sample() -> Vec<FlirtPattern> {
        let mut a = FlirtPattern::new(vec![
            PatternByte::Exact(0x55),
            PatternByte::Wildcard,
            PatternByte::Exact(0x89),
            PatternByte::Exact(0xE5),
        ]);
        a.crc16 = 0xABCD;
        a.crc_length = 7;
        a.pattern_length = 40;
        a.names.push(FlirtName {
            name: "alpha".into(),
            offset: 0,
            is_public: true,
            is_local: false,
        });
        a.names.push(FlirtName {
            name: "alpha_local".into(),
            offset: 12,
            is_public: false,
            is_local: true,
        });

        let mut b = FlirtPattern::new(vec![PatternByte::Exact(0x48), PatternByte::Exact(0x83)]);
        b.crc16 = 0x1234;
        b.crc_length = 3;
        b.pattern_length = 16;
        b.names.push(FlirtName {
            name: "beta".into(),
            offset: 0,
            is_public: true,
            is_local: false,
        });
        vec![a, b]
    }

    #[test]
    fn round_trips_every_field() {
        let pats = sample();
        let back = parse(&encode(&pats)).expect("parse");
        assert_eq!(back.len(), pats.len());
        for (got, want) in back.iter().zip(pats.iter()) {
            assert_eq!(got.initial_bytes, want.initial_bytes);
            assert_eq!(got.crc16, want.crc16);
            assert_eq!(got.crc_length, want.crc_length);
            assert_eq!(got.pattern_length, want.pattern_length);
            assert_eq!(got.names.len(), want.names.len());
            for (n, w) in got.names.iter().zip(want.names.iter()) {
                assert_eq!(n.name, w.name);
                assert_eq!(n.offset, w.offset);
                assert_eq!(n.is_public, w.is_public, "flag is_public per {}", w.name);
                assert_eq!(n.is_local, w.is_local, "flag is_local per {}", w.name);
            }
        }
    }

    #[test]
    fn wildcards_survive_the_mask_encoding() {
        // The mask is what distinguishes a wildcard from a literal zero byte.
        // Losing it would turn every wildcard into `Exact(0x00)` — a pattern
        // that still matches *something*, just never the right thing.
        let back = parse(&encode(&sample())).unwrap();
        assert_eq!(back[0].initial_bytes[1], PatternByte::Wildcard);
        assert_eq!(back[0].initial_bytes[0], PatternByte::Exact(0x55));
    }

    #[test]
    fn a_literal_zero_byte_is_not_confused_with_a_wildcard() {
        let mut p = FlirtPattern::new(vec![PatternByte::Exact(0x00), PatternByte::Wildcard]);
        p.names.push(FlirtName {
            name: "z".into(),
            offset: 0,
            is_public: true,
            is_local: false,
        });
        let back = parse(&encode(&[p])).unwrap();
        assert_eq!(back[0].initial_bytes[0], PatternByte::Exact(0x00));
        assert_eq!(back[0].initial_bytes[1], PatternByte::Wildcard);
    }

    #[test]
    fn empty_container_is_valid() {
        let back = parse(&encode(&[])).expect("un container vuoto è valido");
        assert!(back.is_empty());
    }

    // ── malformed input ─────────────────────────────────────────────────────

    #[test]
    fn bad_magic_is_rejected() {
        assert!(parse(b"NOTFLIRT\0\0\0\0\0\0").is_err());
        assert!(parse(&[]).is_err());
        assert!(parse(b"RFLIRTBIN\0").is_err(), "manca il count");
    }

    #[test]
    fn a_declared_count_larger_than_the_file_is_rejected_without_allocating() {
        let mut buf = MAGIC.to_vec();
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        let err = parse(&buf).expect_err("un count assurdo deve essere respinto");
        assert!(
            format!("{err:?}").contains("declares"),
            "atteso un errore sul count, ottenuto {err:?}"
        );
    }

    #[test]
    fn a_mask_of_the_wrong_length_is_rejected() {
        let mut buf = encode(&sample());
        // Il primo mask_len sta subito dopo magic(10) + count(4) + prefix_len(2)
        // + prefix(4). Lo falsifico.
        let mask_len_at = 10 + 4 + 2 + 4;
        buf[mask_len_at] = 0x03; // era 4
        assert!(parse(&buf).is_err(), "mask e prefix di lunghezza diversa");
    }

    #[test]
    fn truncation_at_every_offset_is_an_error_and_never_a_panic() {
        let full = encode(&sample());
        for cut in 0..full.len() {
            let _ = parse(&full[..cut]);
        }
    }

    // ── the point of the module: conversion to a loadable .sig ──────────────

    #[test]
    fn public_only_filter_keeps_only_publicly_named_patterns() {
        // `sample()` has two patterns: one whose offset-0 name is local, one
        // public. The filter must keep exactly the public one.
        let mut local_only = FlirtPattern::new(vec![PatternByte::Exact(0x90)]);
        local_only.names.push(FlirtName {
            name: "?dtor$1@".into(),
            offset: 0,
            is_public: false,
            is_local: true,
        });
        let mut public_one = FlirtPattern::new(vec![PatternByte::Exact(0x91)]);
        public_one.names.push(FlirtName {
            name: "visible".into(),
            offset: 0,
            is_public: true,
            is_local: false,
        });
        let raw = encode(&[local_only, public_one]);

        let all = to_sig_bytes_filtered(&raw, "lib", 75, false).unwrap();
        let pub_only = to_sig_bytes_filtered(&raw, "lib", 75, true).unwrap();

        let n_all = rustre_flirt::sig_header::SigFileHeader::decode(&all).unwrap().n_functions;
        let n_pub = rustre_flirt::sig_header::SigFileHeader::decode(&pub_only).unwrap().n_functions;
        assert_eq!(n_all, 2);
        assert_eq!(n_pub, 1, "solo il pattern con nome pubblico deve sopravvivere");
    }

    #[test]
    fn public_only_filter_never_keeps_more_than_the_unfiltered_set() {
        // Monotonicity: a filter can only remove. Measured on the real database
        // this is 67 168 -> 41 203.
        let raw = encode(&sample());
        let all = to_sig_bytes_filtered(&raw, "lib", 75, false).unwrap();
        let pub_only = to_sig_bytes_filtered(&raw, "lib", 75, true).unwrap();
        let n_all = rustre_flirt::sig_header::SigFileHeader::decode(&all).unwrap().n_functions;
        let n_pub = rustre_flirt::sig_header::SigFileHeader::decode(&pub_only).unwrap().n_functions;
        assert!(n_pub <= n_all);
    }

    #[test]
    fn converts_to_sig_bytes_that_carry_the_same_names() {
        let raw = encode(&sample());
        let sig = to_sig_bytes(&raw, "converted", 75).expect("conversione");

        let h = rustre_flirt::sig_header::SigFileHeader::decode(&sig)
            .expect("il .sig prodotto deve avere un header canonico");
        assert_eq!(h.lib_name, "converted");
        assert_eq!(h.n_functions, 2);
    }
}
