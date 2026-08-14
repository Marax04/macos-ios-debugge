//! `binary_diff` — Compute and apply diff-based binary patches.
//!
//! Produces a compact, self-describing delta between two byte buffers and
//! applies it to reconstruct the new buffer from the old. The format is
//! deterministic, length-prefixed, and SHA-256 verified end-to-end.
//!
//! Encoding (little-endian):
//! ```text
//!   magic        : "RRDF"            (4 bytes)
//!   version      : u16               (currently 1)
//!   old_size     : u64
//!   new_size     : u64
//!   old_sha256   : [u8; 32]
//!   new_sha256   : [u8; 32]
//!   op_count     : u32
//!   ops          : op_count × Op
//!
//!   Op tag byte:
//!     0x01 Copy   { src_offset: u64, length: u64 }   — copy from old buffer
//!     0x02 Insert { length: u64, bytes: [u8; length] } — literal bytes from delta
//! ```

use std::fmt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced when building or applying a binary diff.
#[derive(Debug, Error)]
pub enum DiffError {
    /// The delta blob is too short to contain a valid header.
    #[error("delta too short ({0} bytes)")]
    Truncated(usize),
    /// The delta magic bytes do not match.
    #[error("bad magic: expected 'RRDF'")]
    BadMagic,
    /// Unsupported delta format version.
    #[error("unsupported delta version: {0}")]
    UnsupportedVersion(u16),
    /// The supplied old buffer does not match the delta's recorded hash.
    #[error("source binary hash mismatch")]
    SourceHashMismatch,
    /// After application the resulting buffer does not match the recorded target hash.
    #[error("target binary hash mismatch after applying delta")]
    TargetHashMismatch,
    /// A Copy op references a region outside the old buffer.
    #[error("copy op out of bounds: src_offset={src_offset}, length={length}, old_size={old_size}")]
    CopyOutOfBounds { src_offset: u64, length: u64, old_size: u64 },
    /// An Insert op claims more bytes than remain in the delta.
    #[error("insert op truncated: needed {needed} bytes, only {available} available")]
    InsertTruncated { needed: u64, available: u64 },
    /// Unknown op tag encountered while decoding the delta.
    #[error("unknown op tag {0:#04x}")]
    UnknownOpTag(u8),
    /// Recorded `new_size` does not match the sum of op output lengths.
    #[error("size mismatch: header says {expected} bytes, produced {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
}

// ---------------------------------------------------------------------------
// Op
// ---------------------------------------------------------------------------

/// A single op in a binary delta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffOp {
    /// Copy `length` bytes from `src_offset` in the old buffer.
    Copy { src_offset: u64, length: u64 },
    /// Insert literal `bytes` from the delta payload.
    Insert { bytes: Vec<u8> },
}

impl fmt::Display for DiffOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Copy { src_offset, length } => write!(f, "Copy @{src_offset:#x} len={length}"),
            Self::Insert { bytes } => write!(f, "Insert len={}", bytes.len()),
        }
    }
}

// ---------------------------------------------------------------------------
// BinaryDelta
// ---------------------------------------------------------------------------

const MAGIC: &[u8; 4] = b"RRDF";
const VERSION: u16 = 1;

/// A serialisable binary delta between two byte buffers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryDelta {
    /// Size of the source (old) buffer.
    pub old_size: u64,
    /// Size of the target (new) buffer.
    pub new_size: u64,
    /// SHA-256 of the source buffer.
    pub old_sha256: [u8; 32],
    /// SHA-256 of the target buffer.
    pub new_sha256: [u8; 32],
    /// Ordered list of ops to reconstruct the target.
    pub ops: Vec<DiffOp>,
}

impl BinaryDelta {
    /// Encode the delta to its compact binary representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 2 + 16 + 64 + 4 + self.ops.len() * 24);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&self.old_size.to_le_bytes());
        out.extend_from_slice(&self.new_size.to_le_bytes());
        out.extend_from_slice(&self.old_sha256);
        out.extend_from_slice(&self.new_sha256);
        out.extend_from_slice(&u32::try_from(self.ops.len()).unwrap_or(u32::MAX).to_le_bytes());
        for op in &self.ops {
            match op {
                DiffOp::Copy { src_offset, length } => {
                    out.push(0x01);
                    out.extend_from_slice(&src_offset.to_le_bytes());
                    out.extend_from_slice(&length.to_le_bytes());
                }
                DiffOp::Insert { bytes } => {
                    out.push(0x02);
                    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                    out.extend_from_slice(bytes);
                }
            }
        }
        out
    }

    /// Decode a delta from its compact binary representation.
    ///
    /// # Errors
    ///
    /// Returns [`DiffError`] when the blob is truncated, has bad magic, an unsupported
    /// version, or contains malformed ops.
    ///
    /// # Panics
    ///
    /// Panics only if internal `try_into` from a slice of known length fails, which is
    /// statically impossible given the preceding bounds checks.
    pub fn decode(blob: &[u8]) -> Result<Self, DiffError> {
        const HEADER: usize = 4 + 2 + 8 + 8 + 32 + 32 + 4;
        if blob.len() < HEADER {
            return Err(DiffError::Truncated(blob.len()));
        }
        if &blob[0..4] != MAGIC {
            return Err(DiffError::BadMagic);
        }
        let version = u16::from_le_bytes([blob[4], blob[5]]);
        if version != VERSION {
            return Err(DiffError::UnsupportedVersion(version));
        }
        let old_size = u64::from_le_bytes(blob[6..14].try_into().unwrap());
        let new_size = u64::from_le_bytes(blob[14..22].try_into().unwrap());
        let mut old_sha256 = [0u8; 32];
        old_sha256.copy_from_slice(&blob[22..54]);
        let mut new_sha256 = [0u8; 32];
        new_sha256.copy_from_slice(&blob[54..86]);
        let op_count = u32::from_le_bytes(blob[86..90].try_into().unwrap()) as usize;

        let mut cursor = HEADER;
        // Guard against adversarial op_count that would cause a multi-GB allocation.
        // Each op is at minimum 1 (tag) + 8 (length field) = 9 bytes; cap capacity.
        let ops_cap = op_count.min((blob.len() - cursor).saturating_add(8) / 9);
        let mut ops = Vec::with_capacity(ops_cap);
        for _ in 0..op_count {
            if cursor >= blob.len() {
                return Err(DiffError::Truncated(blob.len()));
            }
            let tag = blob[cursor];
            cursor += 1;
            match tag {
                0x01 => {
                    if cursor + 16 > blob.len() {
                        return Err(DiffError::Truncated(blob.len()));
                    }
                    let src_offset = u64::from_le_bytes(blob[cursor..cursor + 8].try_into().unwrap());
                    let length = u64::from_le_bytes(blob[cursor + 8..cursor + 16].try_into().unwrap());
                    cursor += 16;
                    ops.push(DiffOp::Copy { src_offset, length });
                }
                0x02 => {
                    if cursor + 8 > blob.len() {
                        return Err(DiffError::Truncated(blob.len()));
                    }
                    let length = u64::from_le_bytes(blob[cursor..cursor + 8].try_into().unwrap());
                    cursor += 8;
                    let available = (blob.len() - cursor) as u64;
                    if length > available {
                        return Err(DiffError::InsertTruncated { needed: length, available });
                    }
                    let length_usize = usize::try_from(length).map_err(|_| DiffError::Truncated(blob.len()))?;
                    let bytes = blob[cursor..cursor + length_usize].to_vec();
                    cursor += length_usize;
                    ops.push(DiffOp::Insert { bytes });
                }
                other => return Err(DiffError::UnknownOpTag(other)),
            }
        }

        Ok(Self { old_size, new_size, old_sha256, new_sha256, ops })
    }

    /// Apply the delta against `old`, producing the reconstructed target.
    ///
    /// # Errors
    ///
    /// Returns [`DiffError`] when the source size/hash do not match, when an op
    /// is out of bounds, or when the reconstructed buffer's size/hash do not match.
    pub fn apply(&self, old: &[u8]) -> Result<Vec<u8>, DiffError> {
        if old.len() as u64 != self.old_size {
            return Err(DiffError::SourceHashMismatch);
        }
        if sha256(old) != self.old_sha256 {
            return Err(DiffError::SourceHashMismatch);
        }

        let mut out = Vec::with_capacity(usize::try_from(self.new_size).unwrap_or(usize::MAX));
        for op in &self.ops {
            match op {
                DiffOp::Copy { src_offset, length } => {
                    let end = src_offset
                        .checked_add(*length)
                        .ok_or(DiffError::CopyOutOfBounds {
                            src_offset: *src_offset,
                            length: *length,
                            old_size: self.old_size,
                        })?;
                    if end > self.old_size {
                        return Err(DiffError::CopyOutOfBounds {
                            src_offset: *src_offset,
                            length: *length,
                            old_size: self.old_size,
                        });
                    }
                    let so = usize::try_from(*src_offset).map_err(|_| DiffError::CopyOutOfBounds {
                        src_offset: *src_offset,
                        length: *length,
                        old_size: self.old_size,
                    })?;
                    let eo = usize::try_from(end).map_err(|_| DiffError::CopyOutOfBounds {
                        src_offset: *src_offset,
                        length: *length,
                        old_size: self.old_size,
                    })?;
                    out.extend_from_slice(&old[so..eo]);
                }
                DiffOp::Insert { bytes } => out.extend_from_slice(bytes),
            }
        }

        if out.len() as u64 != self.new_size {
            return Err(DiffError::SizeMismatch {
                expected: self.new_size,
                actual: out.len() as u64,
            });
        }
        if sha256(&out) != self.new_sha256 {
            return Err(DiffError::TargetHashMismatch);
        }
        Ok(out)
    }

    /// Total encoded size in bytes (approximate — exact when encoded).
    #[must_use]
    pub fn encoded_size(&self) -> usize {
        self.encode().len()
    }
}

// ---------------------------------------------------------------------------
// Diff builder
// ---------------------------------------------------------------------------

/// Configuration for [`build_delta`].
#[derive(Debug, Clone)]
pub struct DiffOptions {
    /// Minimum length of a matching run to emit as a Copy op. Smaller matches
    /// are absorbed into Insert ops to keep the delta compact.
    pub min_match: usize,
    /// Sliding window size (bytes) used when searching for matches. Larger
    /// windows find more matches at the cost of build time.
    pub window: usize,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self { min_match: 16, window: 4096 }
    }
}

/// Build a [`BinaryDelta`] that turns `old` into `new`.
///
/// The algorithm is a simple but deterministic greedy longest-match search:
/// at each position in `new`, look for the longest substring (`>= min_match`)
/// also present in a sliding window of `old`. Falls back to a literal Insert
/// when no qualifying match exists.
#[must_use] 
pub fn build_delta(old: &[u8], new: &[u8], opts: &DiffOptions) -> BinaryDelta {
    let mut delta_ops: Vec<DiffOp> = Vec::new();
    let mut pending_insert: Vec<u8> = Vec::new();
    let mut idx = 0usize;

    while idx < new.len() {
        let m = find_longest_match(old, new, idx, opts);
        if let Some((src, len)) = m {
            if !pending_insert.is_empty() {
                delta_ops.push(DiffOp::Insert { bytes: std::mem::take(&mut pending_insert) });
            }
            delta_ops.push(DiffOp::Copy { src_offset: src as u64, length: len as u64 });
            idx += len;
        } else {
            pending_insert.push(new[idx]);
            idx += 1;
        }
    }
    if !pending_insert.is_empty() {
        delta_ops.push(DiffOp::Insert { bytes: pending_insert });
    }

    BinaryDelta {
        old_size: old.len() as u64,
        new_size: new.len() as u64,
        old_sha256: sha256(old),
        new_sha256: sha256(new),
        ops: delta_ops,
    }
}

fn find_longest_match(
    old: &[u8],
    new: &[u8],
    new_pos: usize,
    opts: &DiffOptions,
) -> Option<(usize, usize)> {
    if new_pos + opts.min_match > new.len() || old.is_empty() {
        return None;
    }
    let needle = &new[new_pos..new_pos + opts.min_match];
    // Center the search window around the proportional offset in old.
    let center = if new.is_empty() {
        0
    } else {
        let c = new_pos as u64 * old.len() as u64 / new.len().max(1) as u64;
        usize::try_from(c).unwrap_or(usize::MAX)
    };
    let half = opts.window / 2;
    let start = center.saturating_sub(half);
    let end = (center + half).min(old.len().saturating_sub(opts.min_match) + 1);
    if start >= end {
        return None;
    }

    let mut best: Option<(usize, usize)> = None;
    let mut search_start = start;
    while search_start < end {
        // Find next occurrence of needle in [search_start..end+min_match)
        let slice_end = (end + opts.min_match).min(old.len());
        if search_start + opts.min_match > slice_end {
            break;
        }
        let hay = &old[search_start..slice_end];
        let Some(rel) = memmem(hay, needle) else { break };
        let src = search_start + rel;
        // Extend the match as far as possible.
        let max_len = old.len() - src;
        let max_new = new.len() - new_pos;
        let cap = max_len.min(max_new);
        let mut len = opts.min_match;
        let old_tail = &old[src..src + cap];
        let new_tail = &new[new_pos..new_pos + cap];
        while len < cap && old_tail[len] == new_tail[len] {
            len += 1;
        }
        if best.is_none_or(|(_, bl)| len > bl) {
            best = Some((src, len));
        }
        search_start = src + 1;
    }
    best
}

fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    let first = needle[0];
    let last_start = haystack.len() - needle.len();
    let mut i = 0;
    while i <= last_start {
        if haystack[i] == first && &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// High-level convenience
// ---------------------------------------------------------------------------

/// Build a delta using default options and return its encoded blob.
#[must_use] 
pub fn diff(old: &[u8], new: &[u8]) -> Vec<u8> {
    build_delta(old, new, &DiffOptions::default()).encode()
}

/// Decode a delta blob and apply it to `old`.
///
/// # Errors
///
/// Returns [`DiffError`] when the delta cannot be decoded or applied.
pub fn patch(old: &[u8], delta: &[u8]) -> Result<Vec<u8>, DiffError> {
    BinaryDelta::decode(delta)?.apply(old)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_identical() {
        let buf = vec![0xAAu8; 1024];
        let delta = build_delta(&buf, &buf, &DiffOptions::default());
        let out = delta.apply(&buf).unwrap();
        assert_eq!(out, buf);
    }

    #[test]
    fn roundtrip_modified_middle() {
        let mut old = (0u8..=255).cycle().take(4096).collect::<Vec<_>>();
        let mut new = old.clone();
        for b in &mut new[1000..1064] {
            *b = 0x77;
        }
        old[0] = 0xFE; // also touch start
        let delta = build_delta(&old, &new, &DiffOptions::default());
        let blob = delta.encode();
        let decoded = BinaryDelta::decode(&blob).unwrap();
        let reconstructed = decoded.apply(&old).unwrap();
        assert_eq!(reconstructed, new);
    }

    #[test]
    fn roundtrip_completely_different() {
        let old: Vec<u8> = (0u16..256).map(|i| u8::try_from(i & 0xFF).unwrap()).collect();
        let new: Vec<u8> = (0u16..256).map(|i| u8::try_from((255 - i) & 0xFF).unwrap()).collect();
        let delta = build_delta(&old, &new, &DiffOptions::default());
        let out = delta.apply(&old).unwrap();
        assert_eq!(out, new);
    }

    #[test]
    fn encode_decode_preserves_ops() {
        let old = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let new = vec![1u8, 2, 3, 99, 5, 6, 7, 8, 9, 10];
        let delta = build_delta(&old, &new, &DiffOptions { min_match: 4, window: 32 });
        let blob = delta.encode();
        let decoded = BinaryDelta::decode(&blob).unwrap();
        assert_eq!(decoded, delta);
        assert_eq!(decoded.apply(&old).unwrap(), new);
    }

    #[test]
    fn detects_source_mismatch() {
        let old = vec![1u8; 64];
        let new = vec![2u8; 64];
        let delta = build_delta(&old, &new, &DiffOptions::default());
        let wrong = vec![9u8; 64];
        assert!(matches!(delta.apply(&wrong), Err(DiffError::SourceHashMismatch)));
    }

    #[test]
    fn rejects_bad_magic() {
        let bad = vec![0u8; 256];
        assert!(matches!(BinaryDelta::decode(&bad), Err(DiffError::BadMagic)));
    }

    #[test]
    fn rejects_truncated() {
        let blob = vec![b'R', b'R', b'D', b'F', 1, 0];
        assert!(matches!(BinaryDelta::decode(&blob), Err(DiffError::Truncated(_))));
    }

    #[test]
    fn convenience_functions() {
        let old = b"hello world this is a long string for diffing".to_vec();
        let mut new = old.clone();
        new[6..11].copy_from_slice(b"there");
        let blob = diff(&old, &new);
        let out = patch(&old, &blob).unwrap();
        assert_eq!(out, new);
    }
}
