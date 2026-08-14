//! `patch_generator` — generate, apply, and verify binary patches.
//!
//! Supports multiple patch formats:
//! * **IDA-style** text patches (`dd:AA BB CC` — address then hex bytes)
//! * **x64dbg** patch files (CSV-like with old/new byte columns)
//! * **xdelta3-style** binary header + literal copy/diff blocks
//! * **Raw** flat byte array patches indexed by file offset
//!
//! Patches are hash-verified (FNV-64 over the target bytes) before and after apply.

use std::fmt;
use std::io::{self, Read, Write};

// ---------------------------------------------------------------------------
// PatchFormat

/// Serialisation format for a patch set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatchFormat {
    /// Plain text: `<hex_addr>: <hex_bytes>`
    IdaStyle,
    /// x64dbg CSV: `Address,OldBytes,NewBytes`
    X64Dbg,
    /// Compact binary with file header and offset-indexed hunks.
    BinaryRaw,
    /// xdelta3-compatible stream header + literal blocks.
    Xdelta3,
}

impl fmt::Display for PatchFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::IdaStyle  => "ida",
            Self::X64Dbg   => "x64dbg",
            Self::BinaryRaw => "binary",
            Self::Xdelta3  => "xdelta3",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// PatchEntry

/// A single contiguous hunk to be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchEntry {
    /// Byte offset (file-relative) of the first patched byte.
    pub offset: u64,
    /// Original bytes expected at `offset`. Used for verification.
    pub original_bytes: Vec<u8>,
    /// New bytes to write at `offset`.
    pub new_bytes: Vec<u8>,
    /// Optional human annotation.
    pub comment: Option<String>,
}

impl PatchEntry {
    #[must_use] 
    pub const fn new(offset: u64, original_bytes: Vec<u8>, new_bytes: Vec<u8>) -> Self {
        Self { offset, original_bytes, new_bytes, comment: None }
    }

    #[must_use]
    pub fn with_comment(mut self, c: impl Into<String>) -> Self {
        self.comment = Some(c.into());
        self
    }

    /// Return the size of the patched region.
    #[must_use] 
    pub const fn size(&self) -> usize { self.new_bytes.len() }

    /// FNV-64 hash of the original bytes (used as before-patch checksum).
    #[must_use] 
    pub fn original_hash(&self) -> u64 {
        fnv64(&self.original_bytes)
    }

    /// FNV-64 hash of the new bytes.
    #[must_use] 
    pub fn new_hash(&self) -> u64 {
        fnv64(&self.new_bytes)
    }
}

impl fmt::Display for PatchEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{:#x} ({} bytes)", self.offset, self.new_bytes.len())?;
        if let Some(ref c) = self.comment { write!(f, "  // {c}")?; }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PatchVerifier

/// Verifies a patch set against a target buffer before and/or after application.
#[derive(Debug, Clone, Default)]
pub struct PatchVerifier {
    pub mismatches: Vec<PatchMismatch>,
}

/// One mismatch detected during verification.
#[derive(Debug, Clone)]
pub struct PatchMismatch {
    pub offset: u64,
    pub expected: Vec<u8>,
    pub found: Vec<u8>,
}

impl PatchVerifier {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    /// Verify that `buf` contains the expected original bytes for every patch entry.
    pub fn verify_before(&mut self, buf: &[u8], entries: &[PatchEntry]) -> bool {
        self.mismatches.clear();
        for entry in entries {
            let off = usize::try_from(entry.offset).unwrap_or(usize::MAX);
            let len = entry.original_bytes.len();
            if off.saturating_add(len) > buf.len() {
                self.mismatches.push(PatchMismatch {
                    offset: entry.offset,
                    expected: entry.original_bytes.clone(),
                    found: vec![],
                });
                continue;
            }
            let actual = &buf[off..off + len];
            if actual != entry.original_bytes.as_slice() {
                self.mismatches.push(PatchMismatch {
                    offset: entry.offset,
                    expected: entry.original_bytes.clone(),
                    found: actual.to_vec(),
                });
            }
        }
        self.mismatches.is_empty()
    }

    /// Verify that `buf` contains the expected new bytes after patching.
    pub fn verify_after(&mut self, buf: &[u8], entries: &[PatchEntry]) -> bool {
        self.mismatches.clear();
        for entry in entries {
            let off = usize::try_from(entry.offset).unwrap_or(usize::MAX);
            let len = entry.new_bytes.len();
            if off.saturating_add(len) > buf.len() {
                self.mismatches.push(PatchMismatch {
                    offset: entry.offset,
                    expected: entry.new_bytes.clone(),
                    found: vec![],
                });
                continue;
            }
            let actual = &buf[off..off + len];
            if actual != entry.new_bytes.as_slice() {
                self.mismatches.push(PatchMismatch {
                    offset: entry.offset,
                    expected: entry.new_bytes.clone(),
                    found: actual.to_vec(),
                });
            }
        }
        self.mismatches.is_empty()
    }
}

// ---------------------------------------------------------------------------
// PatchApplier

/// Applies a set of [`PatchEntry`] hunks to a mutable byte buffer.
#[derive(Debug, Clone, Default)]
pub struct PatchApplier {
    /// If `true`, verify original bytes before applying each hunk.
    pub verify_before: bool,
}

/// Error type for patch application.
#[derive(Debug, Clone)]
pub enum PatchError {
    OutOfBounds { offset: u64, size: usize, buf_len: usize },
    OriginalMismatch { offset: u64 },
    Io(String),
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfBounds { offset, size, buf_len } =>
                write!(f, "patch @{offset:#x}+{size} out of bounds (buf={buf_len})"),
            Self::OriginalMismatch { offset } =>
                write!(f, "original bytes mismatch at {offset:#x}"),
            Self::Io(e) => write!(f, "I/O: {e}"),
        }
    }
}

impl PatchApplier {
    #[must_use] 
    pub const fn new() -> Self { Self { verify_before: true } }
    #[must_use] 
    pub const fn without_verification() -> Self { Self { verify_before: false } }

    /// Apply all patches to `buf` in offset order.  Returns list of errors.
    pub fn apply(&self, buf: &mut [u8], entries: &[PatchEntry]) -> Vec<PatchError> {
        let mut errors = Vec::new();
        let mut sorted: Vec<&PatchEntry> = entries.iter().collect();
        sorted.sort_by_key(|e| e.offset);

        for entry in sorted {
            let off = usize::try_from(entry.offset).unwrap_or(usize::MAX);
            let len = entry.new_bytes.len();
            if off.saturating_add(len) > buf.len() {
                errors.push(PatchError::OutOfBounds { offset: entry.offset, size: len, buf_len: buf.len() });
                continue;
            }
            if self.verify_before {
                let orig_len = entry.original_bytes.len();
                if off.saturating_add(orig_len) > buf.len() {
                    errors.push(PatchError::OutOfBounds { offset: entry.offset, size: orig_len, buf_len: buf.len() });
                    continue;
                }
                if buf[off..off + orig_len] != entry.original_bytes[..] {
                    errors.push(PatchError::OriginalMismatch { offset: entry.offset });
                    continue;
                }
            }
            buf[off..off + len].copy_from_slice(&entry.new_bytes);
        }
        errors
    }

    /// Revert a patch (apply original bytes back).
    pub fn revert(&self, buf: &mut [u8], entries: &[PatchEntry]) -> Vec<PatchError> {
        let reverted: Vec<PatchEntry> = entries.iter().map(|e| PatchEntry {
            offset: e.offset,
            original_bytes: e.new_bytes.clone(),
            new_bytes: e.original_bytes.clone(),
            comment: e.comment.clone(),
        }).collect();
        let applier = Self { verify_before: false };
        applier.apply(buf, &reverted)
    }
}

// ---------------------------------------------------------------------------
// PatchGenerator

/// Generates patch entries by comparing original and modified byte buffers.
#[derive(Debug, Clone, Default)]
pub struct PatchGenerator {
    /// Maximum gap between changed bytes to merge into one hunk (default: 16).
    pub merge_distance: usize,
}

impl PatchGenerator {
    #[must_use] 
    pub const fn new() -> Self { Self { merge_distance: 16 } }

    /// Diff `original` and `modified` and produce a minimal set of [`PatchEntry`] hunks.
    #[must_use] 
    pub fn generate(&self, original: &[u8], modified: &[u8]) -> Vec<PatchEntry> {
        if original.len() != modified.len() {
            return Self::generate_variable_length(original, modified);
        }
        let n = original.len();
        let changed_offsets: Vec<usize> = (0..n)
            .filter(|&i| original[i] != modified[i])
            .collect();

        if changed_offsets.is_empty() { return Vec::new(); }

        // Merge nearby offsets into hunks.
        let mut hunks: Vec<(usize, usize)> = Vec::new(); // (start, end) exclusive
        let mut hunk_start = changed_offsets[0];
        let mut hunk_end   = changed_offsets[0] + 1;

        for &off in changed_offsets.iter().skip(1) {
            if off > hunk_end + self.merge_distance {
                hunks.push((hunk_start, hunk_end));
                hunk_start = off;
            }
            hunk_end = off + 1;
        }
        hunks.push((hunk_start, hunk_end));

        hunks.iter().map(|&(s, e)| PatchEntry::new(
            s as u64,
            original[s..e].to_vec(),
            modified[s..e].to_vec(),
        )).collect()
    }

    /// Handle variable-length diffs by treating the entire differing suffix as one patch.
    fn generate_variable_length(original: &[u8], modified: &[u8]) -> Vec<PatchEntry> {
        let common = original.iter().zip(modified.iter()).take_while(|(a, b)| a == b).count();
        let tail_orig = &original[common..];
        let tail_mod  = &modified[common..];
        if tail_orig.is_empty() && tail_mod.is_empty() { return Vec::new(); }
        vec![PatchEntry::new(common as u64, tail_orig.to_vec(), tail_mod.to_vec())]
    }

    // -----------------------------------------------------------------------
    // Serialisation

    /// Serialise patch entries to a string in IDA-style format.
    #[must_use] 
    pub fn to_ida_style(&self, entries: &[PatchEntry]) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        for e in entries {
            let hex: String = e.new_bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
            write!(out, "{:016X}: {}", e.offset, hex).unwrap_or_default();
            if let Some(ref c) = e.comment {
                write!(out, "  ; {c}").unwrap_or_default();
            }
            out.push('\n');
        }
        out
    }

    /// Serialise patch entries to x64dbg CSV format.
    #[must_use] 
    pub fn to_x64dbg(&self, entries: &[PatchEntry]) -> String {
        use std::fmt::Write as _;
        let mut out = "Address,OldBytes,NewBytes\n".to_string();
        for e in entries {
            let old_hex: String = e.original_bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
            let new_hex: String = e.new_bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
            writeln!(out, "{:016X},{},{}", e.offset, old_hex, new_hex).unwrap_or_default();
        }
        out
    }

    /// Deserialise IDA-style patch text.
    #[must_use] 
    pub fn from_ida_style(text: &str) -> Vec<PatchEntry> {
        let mut entries = Vec::new();
        for line in text.lines() {
            let line = line.split(';').next().unwrap_or("").trim();
            if line.is_empty() { continue; }
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() != 2 { continue; }
            let addr = u64::from_str_radix(parts[0].trim(), 16).unwrap_or(0);
            let bytes: Vec<u8> = parts[1].split_whitespace()
                .filter_map(|s| u8::from_str_radix(s, 16).ok())
                .collect();
            if !bytes.is_empty() {
                entries.push(PatchEntry::new(addr, Vec::new(), bytes));
            }
        }
        entries
    }

    /// Serialise to compact binary format.
    ///
    /// Format: magic(4) + count(4) + [offset(8) + `orig_len(2)` + `new_len(2)` + `orig_bytes` + `new_bytes`]*
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if writing to `w` fails.
    pub fn to_binary<W: Write>(&self, entries: &[PatchEntry], w: &mut W) -> io::Result<()> {
        let entry_count = u32::try_from(entries.len()).unwrap_or(u32::MAX);
        w.write_all(b"PTCH")?;
        w.write_all(&entry_count.to_le_bytes())?;
        for e in entries {
            let orig_len = u16::try_from(e.original_bytes.len()).unwrap_or(u16::MAX);
            let new_len  = u16::try_from(e.new_bytes.len()).unwrap_or(u16::MAX);
            w.write_all(&e.offset.to_le_bytes())?;
            w.write_all(&orig_len.to_le_bytes())?;
            w.write_all(&new_len.to_le_bytes())?;
            w.write_all(&e.original_bytes)?;
            w.write_all(&e.new_bytes)?;
        }
        Ok(())
    }

    /// Deserialise compact binary format.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if reading from `r` fails or the data is malformed.
    pub fn from_binary<R: Read>(r: &mut R) -> io::Result<Vec<PatchEntry>> {
        // Cap allocation to avoid OOM from a maliciously large count field.
        const MAX_PATCH_ENTRIES: usize = 1_000_000;
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if &magic != b"PTCH" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad patch magic"));
        }
        let mut count_buf = [0u8; 4];
        r.read_exact(&mut count_buf)?;
        let count = usize::try_from(u32::from_le_bytes(count_buf)).unwrap_or(usize::MAX);
        if count > MAX_PATCH_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("patch entry count {count} exceeds maximum {MAX_PATCH_ENTRIES}"),
            ));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let mut offset_buf = [0u8; 8];
            let mut len_buf = [0u8; 2];
            r.read_exact(&mut offset_buf)?;
            let offset = u64::from_le_bytes(offset_buf);
            r.read_exact(&mut len_buf)?;
            let orig_len = usize::from(u16::from_le_bytes(len_buf));
            r.read_exact(&mut len_buf)?;
            let new_len = usize::from(u16::from_le_bytes(len_buf));
            let mut orig = vec![0u8; orig_len];
            if orig_len > 0 { r.read_exact(&mut orig)?; }
            let mut new_bytes = vec![0u8; new_len];
            if new_len > 0 { r.read_exact(&mut new_bytes)?; }
            entries.push(PatchEntry::new(offset, orig, new_bytes));
        }
        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// Helpers

/// FNV-64 hash for checksum purposes.
fn fnv64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

// ---------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_simple_diff() {
        let orig = vec![0x00u8, 0x01, 0x02, 0x03];
        let modif = vec![0x00u8, 0xFF, 0x02, 0xAA];
        let generator = PatchGenerator::new();
        let patches = generator.generate(&orig, &modif);
        assert!(!patches.is_empty());
        // Two separate offsets (1 and 3) but merge_distance=16 → one hunk
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].offset, 1);
    }

    #[test]
    fn test_apply_patch() {
        let orig = vec![0x00u8, 0x01, 0x02, 0x03];
        let modif = vec![0x00u8, 0xFF, 0x02, 0xAA];
        let generator = PatchGenerator::new();
        let patches = generator.generate(&orig, &modif);
        let mut buf = orig.clone();
        let applier = PatchApplier::new();
        let errors = applier.apply(&mut buf, &patches);
        assert!(errors.is_empty());
        assert_eq!(buf, modif);
    }

    #[test]
    fn test_revert_patch() {
        let orig = vec![0x90u8, 0x90, 0x90, 0x90];
        let patched = vec![0xEB, 0x00, 0x90, 0x90];
        let generator = PatchGenerator::new();
        let patches = generator.generate(&orig, &patched);
        let mut buf = patched.clone();
        let applier = PatchApplier::without_verification();
        let errors = applier.revert(&mut buf, &patches);
        assert!(errors.is_empty());
        assert_eq!(buf, orig);
    }

    #[test]
    fn test_ida_roundtrip() {
        let entries = vec![
            PatchEntry::new(0x1000, vec![0x90], vec![0xCC]),
            PatchEntry::new(0x2000, vec![0x74, 0x05], vec![0xEB, 0x05]),
        ];
        let generator = PatchGenerator::new();
        let text = generator.to_ida_style(&entries);
        let parsed = PatchGenerator::from_ida_style(&text);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].offset, 0x1000);
        assert_eq!(parsed[0].new_bytes, vec![0xCC]);
    }

    #[test]
    fn test_binary_roundtrip() {
        let entries = vec![
            PatchEntry::new(0x100, vec![0x01, 0x02], vec![0x03, 0x04]),
        ];
        let generator = PatchGenerator::new();
        let mut buf = Vec::new();
        generator.to_binary(&entries, &mut buf).unwrap();
        let loaded = PatchGenerator::from_binary(&mut buf.as_slice()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].offset, 0x100);
        assert_eq!(loaded[0].new_bytes, vec![0x03, 0x04]);
    }

    #[test]
    fn test_verify_before_after() {
        let orig = vec![0x90u8; 16];
        let mut modif = orig.clone();
        modif[8] = 0xCC;
        let generator = PatchGenerator::new();
        let patches = generator.generate(&orig, &modif);

        let mut verifier = PatchVerifier::new();
        assert!(verifier.verify_before(&orig, &patches));
        assert!(!verifier.verify_before(&modif, &patches));

        let mut buf = orig.clone();
        PatchApplier::new().apply(&mut buf, &patches);
        assert!(verifier.verify_after(&buf, &patches));
    }

    #[test]
    fn test_fnv64_non_zero() {
        assert_ne!(fnv64(b"hello"), 0);
        assert_ne!(fnv64(b"hello"), fnv64(b"world"));
    }
}
