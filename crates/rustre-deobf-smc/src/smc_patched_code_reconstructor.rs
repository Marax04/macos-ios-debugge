//! SMC patched-code reconstruction.
//!
//! [`SmcPatchedCodeReconstructor`] takes the raw captured write events from
//! [`crate::smc_region_tracker::SmcRegionTracker`] and the decryptor
//! information from [`crate::smc_decryptor_extractor::SmcDecryptorExtractor`],
//! applies the reverse-decryption, and produces a [`PatchedRegion`] whose
//! `bytes` field contains the fully-decrypted payload ready for disassembly.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ReconstructResult
// ---------------------------------------------------------------------------

/// Outcome of a reconstruction attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReconstructResult {
    /// Reconstruction succeeded.
    Success,
    /// The reconstructed bytes look like code (heuristic check passed).
    LikelyCode,
    /// The bytes were decrypted but do not look like valid code.
    DecryptedButSuspect,
    /// No decryptor was available; the raw bytes are returned as-is.
    RawOnly,
    /// The source region was empty or could not be located.
    Empty,
    /// An error occurred during reconstruction.
    Error(String),
}

impl fmt::Display for ReconstructResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success               => write!(f, "OK"),
            Self::LikelyCode            => write!(f, "LIKELY_CODE"),
            Self::DecryptedButSuspect   => write!(f, "SUSPECT"),
            Self::RawOnly               => write!(f, "RAW_ONLY"),
            Self::Empty                 => write!(f, "EMPTY"),
            Self::Error(e)              => write!(f, "ERROR({e})"),
        }
    }
}

impl ReconstructResult {
    /// Returns `true` when the reconstruction is considered usable.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        matches!(self, Self::Success | Self::LikelyCode | Self::RawOnly)
    }
}

// ---------------------------------------------------------------------------
// PatchedRegion
// ---------------------------------------------------------------------------

/// A reconstructed code region with decrypted bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchedRegion {
    /// Virtual address of the region base.
    pub base: u64,
    /// Original (encrypted / modified) bytes.
    pub original: Vec<u8>,
    /// Reconstructed (decrypted) bytes.
    pub bytes: Vec<u8>,
    /// Result of the reconstruction attempt.
    pub result: ReconstructResult,
    /// Shannon entropy of the reconstructed bytes (bits/byte).
    pub entropy: f64,
    /// Number of valid code-like instructions estimated (heuristic).
    pub estimated_instruction_count: usize,
    /// Analyst notes.
    pub notes: Vec<String>,
}

impl PatchedRegion {
    /// Create a new patched region.
    #[must_use]
    pub fn new(base: u64, original: Vec<u8>, bytes: Vec<u8>, result: ReconstructResult) -> Self {
        let entropy = shannon_entropy(&bytes);
        let estimated_instruction_count = estimate_instruction_count(&bytes);
        Self {
            base,
            original,
            bytes,
            result,
            entropy,
            estimated_instruction_count,
            notes: Vec::new(),
        }
    }

    /// Returns `true` when the reconstructed bytes are identical to the original.
    #[must_use]
    pub fn is_unchanged(&self) -> bool {
        self.bytes == self.original
    }

    /// Returns the number of bytes that differ between original and reconstructed.
    #[must_use]
    pub fn diff_count(&self) -> usize {
        self.original
            .iter()
            .zip(self.bytes.iter())
            .filter(|(a, b)| a != b)
            .count()
    }

    /// Add a note.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// Export the reconstructed bytes as a hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
    }
}

impl fmt::Display for PatchedRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PatchedRegion base={:#x} len={} result={} entropy={:.2} insns~{}",
            self.base,
            self.bytes.len(),
            self.result,
            self.entropy,
            self.estimated_instruction_count
        )
    }
}

// ---------------------------------------------------------------------------
// WriteEvent — minimal representation from the tracker
// ---------------------------------------------------------------------------

/// A minimal write event fed into the reconstructor.
///
/// The caller extracts these from the tracker's event history.
#[derive(Debug, Clone)]
pub struct WriteEvent {
    /// Offset within the region being reconstructed.
    pub region_offset: usize,
    /// Payload bytes written.
    pub bytes: Vec<u8>,
    /// Sequence number (lower = earlier).
    pub seq: u64,
}

impl WriteEvent {
    /// Create a new write event.
    #[must_use]
    pub const fn new(region_offset: usize, bytes: Vec<u8>, seq: u64) -> Self {
        Self { region_offset, bytes, seq }
    }
}

// ---------------------------------------------------------------------------
// DecryptorHint — minimal representation from the extractor
// ---------------------------------------------------------------------------

/// Enough information to undo one decryptor loop, extracted from
/// [`crate::smc_decryptor_extractor::DecryptorLoop`].
#[derive(Debug, Clone)]
pub struct DecryptorHint {
    /// Which algorithm to use for decryption.
    pub kind: DecryptKind,
    /// Key material.
    pub key: Vec<u8>,
}

impl DecryptorHint {
    /// Construct from raw kind + key.
    #[must_use]
    pub const fn new(kind: DecryptKind, key: Vec<u8>) -> Self {
        Self { kind, key }
    }

    /// Apply decryption to `data` in place.
    pub fn decrypt_inplace(&self, data: &mut [u8]) {
        if self.key.is_empty() {
            return;
        }
        match self.kind {
            DecryptKind::Xor8 => {
                let k = self.key[0];
                for b in data.iter_mut() { *b ^= k; }
            }
            DecryptKind::XorMultibyte => {
                let kl = self.key.len();
                for (i, b) in data.iter_mut().enumerate() {
                    *b ^= self.key[i % kl];
                }
            }
            DecryptKind::AddSub => {
                let k = self.key[0];
                for b in data.iter_mut() { *b = b.wrapping_sub(k); }
            }
            DecryptKind::Rotate => {
                let k = (self.key[0] % 8).max(1);
                for b in data.iter_mut() { *b = b.rotate_right(u32::from(k)); }
            }
            DecryptKind::None => {}
        }
    }
}

/// Decryption algorithm to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptKind {
    None,
    Xor8,
    XorMultibyte,
    AddSub,
    Rotate,
}

// ---------------------------------------------------------------------------
// SmcPatchedCodeReconstructor
// ---------------------------------------------------------------------------

/// Reassembles a patched code region from write events and optional decryptor.
pub struct SmcPatchedCodeReconstructor {
    /// Code-like entropy range.  Bytes within this range pass the heuristic.
    min_code_entropy: f64,
    max_code_entropy: f64,
}

impl Default for SmcPatchedCodeReconstructor {
    fn default() -> Self {
        Self::new()
    }
}

impl SmcPatchedCodeReconstructor {
    /// Create a new reconstructor with default thresholds.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_code_entropy: 3.5,
            max_code_entropy: 7.2,
        }
    }

    /// Override the acceptable entropy range for "looks like code".
    #[must_use]
    pub const fn with_entropy_range(mut self, min: f64, max: f64) -> Self {
        self.min_code_entropy = min;
        self.max_code_entropy = max;
        self
    }

    /// Reconstruct a code region from write events and an optional decryptor hint.
    ///
    /// Steps:
    /// 1. Merge overlapping write events (later seq wins) into a byte buffer.
    /// 2. Apply the decryptor (if provided).
    /// 3. Run the "looks like code" heuristic.
    /// 4. Return a [`PatchedRegion`].
    #[must_use]
    pub fn reconstruct(
        &self,
        base: u64,
        region_size: usize,
        events: &[WriteEvent],
        decryptor: Option<&DecryptorHint>,
    ) -> PatchedRegion {
        if events.is_empty() {
            return PatchedRegion::new(
                base,
                Vec::new(),
                Vec::new(),
                ReconstructResult::Empty,
            );
        }

        // Merge writes (BTreeMap: offset → byte, higher seq wins)
        let mut byte_map: BTreeMap<usize, (u8, u64)> = BTreeMap::new();
        let mut events_sorted = events.to_vec();
        events_sorted.sort_by_key(|e| e.seq);
        for ev in &events_sorted {
            for (i, &b) in ev.bytes.iter().enumerate() {
                let off = ev.region_offset + i;
                if off < region_size {
                    let entry = byte_map.entry(off).or_insert((0, 0));
                    if ev.seq >= entry.1 {
                        *entry = (b, ev.seq);
                    }
                }
            }
        }

        // Build the original buffer
        let mut buf = vec![0u8; region_size];
        for (&off, &(b, _)) in &byte_map {
            if off < buf.len() {
                buf[off] = b;
            }
        }
        let original = buf.clone();

        // Apply decryptor
        let result;
        if let Some(dec) = decryptor {
            dec.decrypt_inplace(&mut buf);
            let ent = shannon_entropy(&buf);
            if looks_like_code(&buf) && ent >= self.min_code_entropy && ent <= self.max_code_entropy {
                result = ReconstructResult::LikelyCode;
            } else if dec.kind != DecryptKind::None {
                result = ReconstructResult::DecryptedButSuspect;
            } else {
                result = ReconstructResult::Success;
            }
        } else {
            result = ReconstructResult::RawOnly;
        }

        let mut pr = PatchedRegion::new(base, original, buf, result);
        pr.add_note(format!(
            "merged {} write event(s) into {} bytes",
            events.len(),
            region_size
        ));
        if let Some(dec) = decryptor {
            pr.add_note(format!("decryptor applied: {:?}", dec.kind));
        }
        pr
    }

    /// Reconstruct multiple regions and return results sorted by base address.
    #[must_use]
    pub fn reconstruct_batch(
        &self,
        regions: &[(u64, usize, Vec<WriteEvent>, Option<DecryptorHint>)],
    ) -> Vec<PatchedRegion> {
        let mut out: Vec<PatchedRegion> = regions
            .iter()
            .map(|(base, size, events, dec)| {
                self.reconstruct(*base, *size, events, dec.as_ref())
            })
            .collect();
        out.sort_by_key(|r| r.base);
        out
    }

    /// Check if the bytes look like valid x86 code.
    #[must_use]
    pub fn is_likely_code(&self, bytes: &[u8]) -> bool {
        let ent = shannon_entropy(bytes);
        ent >= self.min_code_entropy && ent <= self.max_code_entropy && looks_like_code(bytes)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[usize::from(b)] += 1;
    }
    let len = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / len;
            -p * p.log2()
        })
        .sum()
}

/// Heuristic: a byte buffer "looks like code" if it contains at least
/// two valid x86 single-byte opcodes in the first 32 bytes.
fn looks_like_code(data: &[u8]) -> bool {
    const COMMON: &[u8] = &[
        0x55, 0x48, 0x89, 0x8B, 0x83, 0x81, 0xEB, 0xE8, 0xE9,
        0xFF, 0x50, 0x51, 0x52, 0x53, 0x90, 0xC3, 0xC2, 0x31,
        0x33, 0x29, 0x2B, 0x01, 0x03, 0x68, 0x6A,
    ];
    let window = data.len().min(32);
    data[..window].iter().filter(|b| COMMON.contains(b)).count() >= 2
}

fn estimate_instruction_count(data: &[u8]) -> usize {
    // Very rough: count common single-byte opcodes as proxies for instructions
    data.iter().filter(|&&b| {
        matches!(b, 0x55 | 0x5D | 0xC3 | 0x90 | 0xCC | 0xCB | 0xCA | 0xC2 | 0xEB | 0xE9)
    }).count()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn xor8_hint(key: u8) -> DecryptorHint {
        DecryptorHint::new(DecryptKind::Xor8, vec![key])
    }

    #[test]
    fn test_reconstruct_no_events() {
        let r = SmcPatchedCodeReconstructor::new();
        let pr = r.reconstruct(0x1000, 64, &[], None);
        assert_eq!(pr.result, ReconstructResult::Empty);
    }

    #[test]
    fn test_reconstruct_raw_only() {
        let r = SmcPatchedCodeReconstructor::new();
        let events = vec![WriteEvent::new(0, vec![0x90u8; 16], 0)];
        let pr = r.reconstruct(0x2000, 16, &events, None);
        assert_eq!(pr.result, ReconstructResult::RawOnly);
        assert_eq!(pr.bytes, vec![0x90u8; 16]);
    }

    #[test]
    fn test_reconstruct_xor8_round_trip() {
        let key = 0x42u8;
        let plain: Vec<u8> = vec![0x55, 0x48, 0x89, 0xE5, 0x90, 0x90, 0xC3, 0x00,
                                   0x90, 0x90, 0x90, 0x90, 0x55, 0x48, 0x89, 0xE5];
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let events = vec![WriteEvent::new(0, cipher, 0)];
        let hint = xor8_hint(key);
        let r = SmcPatchedCodeReconstructor::new().with_entropy_range(0.0, 8.0);
        let pr = r.reconstruct(0x3000, 16, &events, Some(&hint));
        assert_eq!(pr.bytes, plain);
        assert!(pr.result.is_usable());
    }

    #[test]
    fn test_reconstruct_overlapping_events_later_wins() {
        let r = SmcPatchedCodeReconstructor::new();
        let events = vec![
            WriteEvent::new(0, vec![0x00u8; 8], 0),   // seq 0
            WriteEvent::new(0, vec![0x90u8; 4], 1),   // seq 1 overwrites first 4
        ];
        let pr = r.reconstruct(0x4000, 8, &events, None);
        assert_eq!(&pr.bytes[0..4], &[0x90u8; 4]);
        assert_eq!(&pr.bytes[4..8], &[0x00u8; 4]);
    }

    #[test]
    fn test_patched_region_diff_count() {
        let pr = PatchedRegion::new(
            0,
            vec![0x00, 0x00, 0x00, 0x00],
            vec![0x90, 0x00, 0x90, 0x00],
            ReconstructResult::RawOnly,
        );
        assert_eq!(pr.diff_count(), 2);
    }

    #[test]
    fn test_patched_region_is_unchanged() {
        let pr = PatchedRegion::new(0, vec![0x90; 4], vec![0x90; 4], ReconstructResult::RawOnly);
        assert!(pr.is_unchanged());
    }

    #[test]
    fn test_patched_region_to_hex() {
        let pr = PatchedRegion::new(0, vec![], vec![0xDE, 0xAD, 0xBE, 0xEF], ReconstructResult::RawOnly);
        assert_eq!(pr.to_hex(), "de ad be ef");
    }

    #[test]
    fn test_patched_region_display() {
        let pr = PatchedRegion::new(0x1000, vec![], vec![0x90; 16], ReconstructResult::Success);
        let s = pr.to_string();
        assert!(s.contains("0x1000"));
        assert!(s.contains("OK"));
    }

    #[test]
    fn test_reconstruct_result_is_usable() {
        assert!(ReconstructResult::Success.is_usable());
        assert!(ReconstructResult::LikelyCode.is_usable());
        assert!(ReconstructResult::RawOnly.is_usable());
        assert!(!ReconstructResult::Empty.is_usable());
        assert!(!ReconstructResult::Error("x".into()).is_usable());
    }

    #[test]
    fn test_decrypt_hint_xor_multibyte() {
        let hint = DecryptorHint::new(DecryptKind::XorMultibyte, vec![0x11, 0x22]);
        let mut data = vec![0x11 ^ 0xAA, 0x22 ^ 0xBB];
        hint.decrypt_inplace(&mut data);
        assert_eq!(data, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_decrypt_hint_rotate() {
        let hint = DecryptorHint::new(DecryptKind::Rotate, vec![1]);
        let original = vec![0b0000_0010u8]; // 2 → after ROR1 = 1
        let mut data = original.clone();
        hint.decrypt_inplace(&mut data);
        assert_eq!(data[0], original[0].rotate_right(1));
    }

    #[test]
    fn test_batch_reconstruct_sorted() {
        let r = SmcPatchedCodeReconstructor::new();
        let regions: Vec<(u64, usize, Vec<WriteEvent>, Option<DecryptorHint>)> = vec![
            (0x3000, 8, vec![WriteEvent::new(0, vec![0x90u8; 8], 0)], None),
            (0x1000, 8, vec![WriteEvent::new(0, vec![0x90u8; 8], 0)], None),
        ];
        let out = r.reconstruct_batch(&regions);
        assert_eq!(out[0].base, 0x1000);
        assert_eq!(out[1].base, 0x3000);
    }

    #[test]
    fn test_is_likely_code_nop_sled() {
        let r = SmcPatchedCodeReconstructor::new().with_entropy_range(0.0, 8.0);
        // NOP sled contains 0x90, 0x55 (common opcodes)
        let code = vec![0x90u8, 0x55, 0x48, 0x89, 0xE5, 0x90, 0x90, 0xC3];
        assert!(r.is_likely_code(&code));
    }

    #[test]
    fn test_looks_like_code_all_zeros() {
        // All-zero buffer should NOT look like code
        let data = vec![0x00u8; 32];
        assert!(!looks_like_code(&data));
    }
}
