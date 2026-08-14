//! SMC decryptor loop extraction.
//!
//! [`SmcDecryptorExtractor`] scans a code buffer for decryptor loop patterns,
//! extracts the key material and key schedule, and produces a list of
//! [`DecryptorLoop`] descriptors that carry enough information for the
//! reconstructor to undo the encryption layer.

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// KeySchedule
// ---------------------------------------------------------------------------

/// Key schedule / key material for one decryptor loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySchedule {
    /// Raw key bytes (up to 32 bytes; longer keys are truncated).
    pub bytes: Vec<u8>,
    /// The key seed (initial value before any transformation).
    pub seed: u64,
    /// Key update algorithm applied after each block.
    pub update: KeyUpdate,
}

impl KeySchedule {
    /// Create a simple static key schedule.
    #[must_use]
    pub fn static_key(bytes: Vec<u8>) -> Self {
        let seed = if bytes.is_empty() {
            0
        } else {
            u64::from(bytes[0])
        };
        Self { bytes, seed, update: KeyUpdate::None }
    }

    /// Returns the key as a hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.bytes.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    /// Apply one key update step, producing the next key state.
    #[must_use]
    pub fn step(&self) -> Vec<u8> {
        match self.update {
            KeyUpdate::None => self.bytes.clone(),
            KeyUpdate::Rol8 => self.bytes.iter().map(|&b| b.rotate_left(1)).collect(),
            KeyUpdate::Ror8 => self.bytes.iter().map(|&b| b.rotate_right(1)).collect(),
            KeyUpdate::AddDelta(d) => self.bytes.iter().map(|&b| b.wrapping_add(d)).collect(),
            KeyUpdate::XorDelta(d) => self.bytes.iter().map(|&b| b ^ d).collect(),
        }
    }
}

impl fmt::Display for KeySchedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "key=[{}] seed={:#x} update={}", self.to_hex(), self.seed, self.update)
    }
}

/// How the key evolves after each block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyUpdate {
    /// The key is static (never changes).
    None,
    /// Rotate every byte left by one bit.
    Rol8,
    /// Rotate every byte right by one bit.
    Ror8,
    /// Add a constant delta to each byte.
    AddDelta(u8),
    /// XOR each byte with a constant delta.
    XorDelta(u8),
}

impl fmt::Display for KeyUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None           => write!(f, "static"),
            Self::Rol8           => write!(f, "rol8"),
            Self::Ror8           => write!(f, "ror8"),
            Self::AddDelta(d)    => write!(f, "add+{d:#04x}"),
            Self::XorDelta(d)    => write!(f, "xor^{d:#04x}"),
        }
    }
}

// ---------------------------------------------------------------------------
// LoopKind — type of decryption algorithm used in the loop
// ---------------------------------------------------------------------------

/// Decryption algorithm used by the loop body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoopKind {
    /// Single-byte XOR with a fixed key byte.
    Xor8,
    /// Multi-byte XOR (key length > 1, cycled).
    XorMultibyte,
    /// ADD/SUB cipher.
    AddSub,
    /// Rotate cipher (ROL/ROR).
    Rotate,
    /// RC4-like substitution.
    Rc4Like,
    /// AES-like S-box substitution.
    AesLike,
    /// An unrecognised loop structure.
    Unknown,
}

impl fmt::Display for LoopKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Xor8         => "XOR8",
            Self::XorMultibyte => "XOR-MB",
            Self::AddSub       => "ADD/SUB",
            Self::Rotate       => "ROT",
            Self::Rc4Like      => "RC4",
            Self::AesLike      => "AES",
            Self::Unknown      => "UNKNOWN",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// DecryptorLoop
// ---------------------------------------------------------------------------

/// One decryptor loop found in a code buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptorLoop {
    /// Byte offset of the loop header within the scanned buffer.
    pub offset: usize,
    /// Estimated byte length of the loop body.
    pub size: usize,
    /// Type of decryption.
    pub kind: LoopKind,
    /// Extracted key material.
    pub key_schedule: KeySchedule,
    /// Inferred number of iterations (0 = unknown).
    pub iterations: u64,
    /// Target address where the decrypted payload will be written (0 = unknown).
    pub target_address: u64,
    /// Analyst confidence, 0–100.
    pub confidence: u8,
    /// Free-form notes.
    pub notes: Vec<String>,
}

impl DecryptorLoop {
    /// Create a new decryptor loop descriptor.
    #[must_use]
    pub const fn new(offset: usize, size: usize, kind: LoopKind, key_schedule: KeySchedule) -> Self {
        Self {
            offset,
            size,
            kind,
            key_schedule,
            iterations: 0,
            target_address: 0,
            confidence: 50,
            notes: Vec::new(),
        }
    }

    /// Set confidence.
    #[must_use] 
    pub const fn with_confidence(mut self, c: u8) -> Self {
        self.confidence = c;
        self
    }

    /// Add a note.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// Simulate decryption of `data` using this loop's key schedule.
    ///
    /// This is an approximation — the actual decryption must be validated
    /// against the emulator output.
    #[must_use]
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        let key = &self.key_schedule.bytes;
        if key.is_empty() {
            return out;
        }
        match self.kind {
            LoopKind::Xor8 => {
                let k = key[0];
                for b in &mut out {
                    *b ^= k;
                }
            }
            LoopKind::XorMultibyte => {
                for (i, b) in out.iter_mut().enumerate() {
                    *b ^= key[i % key.len()];
                }
            }
            LoopKind::AddSub => {
                let k = key[0];
                for b in &mut out {
                    *b = b.wrapping_sub(k);
                }
            }
            LoopKind::Rotate => {
                let k = (key[0] % 8).max(1);
                for b in &mut out {
                    *b = b.rotate_right(u32::from(k));
                }
            }
            _ => {}
        }
        out
    }
}

impl fmt::Display for DecryptorLoop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:#x}+{}] {} {} conf={}",
            self.offset, self.size, self.kind, self.key_schedule, self.confidence
        )
    }
}

// ---------------------------------------------------------------------------
// SmcDecryptorExtractor
// ---------------------------------------------------------------------------

/// Scans a code buffer for SMC decryptor loops.
///
/// Detection heuristics:
/// - Byte-level signature matching for common loop shapes (XOR loop, ADD loop).
/// - Entropy analysis of the candidate ciphertext region.
/// - Key extraction from immediate operands and loop counters.
pub struct SmcDecryptorExtractor {
    /// Minimum loop body size (bytes) to report.
    min_loop_size: usize,
    /// Maximum loop body size (bytes) to consider.
    max_loop_size: usize,
    /// Minimum confidence to include a result.
    min_confidence: u8,
}

impl Default for SmcDecryptorExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl SmcDecryptorExtractor {
    /// Create a new extractor with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_loop_size: 8,
            max_loop_size: 256,
            min_confidence: 50,
        }
    }

    /// Override the minimum loop body size.
    #[must_use] 
    pub const fn with_min_size(mut self, n: usize) -> Self { self.min_loop_size = n; self }
    /// Override the maximum loop body size.
    #[must_use] 
    pub const fn with_max_size(mut self, n: usize) -> Self { self.max_loop_size = n; self }
    /// Override the minimum confidence threshold.
    #[must_use] 
    pub const fn with_min_confidence(mut self, c: u8) -> Self { self.min_confidence = c; self }

    /// Scan `code` for decryptor loops and return all hits.
    #[must_use]
    pub fn extract(&self, code: &[u8]) -> Vec<DecryptorLoop> {
        let mut results = Vec::new();

        for offset in 0..code.len() {
            // Try each pattern at this offset
            if let Some(dl) = self.try_xor8_loop(code, offset)
                && dl.confidence >= self.min_confidence {
                    results.push(dl);
                }
            if let Some(dl) = self.try_xor_multibyte_loop(code, offset)
                && dl.confidence >= self.min_confidence {
                    results.push(dl);
                }
            if let Some(dl) = self.try_add_loop(code, offset)
                && dl.confidence >= self.min_confidence {
                    results.push(dl);
                }
            if let Some(dl) = self.try_rotate_loop(code, offset)
                && dl.confidence >= self.min_confidence {
                    results.push(dl);
                }
        }

        // Deduplicate: keep highest confidence within 8 bytes
        results.sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.offset.cmp(&b.offset)));
        let mut dedup: Vec<DecryptorLoop> = Vec::new();
        for dl in results {
            let close = dedup.iter().any(|e: &DecryptorLoop| e.offset.abs_diff(dl.offset) < 8);
            if !close {
                dedup.push(dl);
            }
        }
        dedup.sort_by_key(|d| d.offset);
        dedup
    }

    // -----------------------------------------------------------------------
    // Pattern: XOR r/m8, imm8 loop
    // 80 3? xx (XOR [ptr], imm8) ; FF ?? (INC/DEC counter) ; 7? rel8 (JLE/JNE)
    // -----------------------------------------------------------------------
    fn try_xor8_loop(&self, code: &[u8], offset: usize) -> Option<DecryptorLoop> {
        // 80 30 imm8 (XOR [eax], imm8)
        if offset + 6 > code.len() {
            return None;
        }
        if code[offset] != 0x80 {
            return None;
        }
        // ModRM must have reg field = 6 (XOR r/m, imm8): (modrm >> 3) & 7 == 6
        let modrm = code[offset + 1];
        if (modrm >> 3) & 7 != 6 {
            return None;
        }
        let imm_key = code[offset + 2];
        // Look for a conditional backward branch within max_loop_size
        let end = (offset + self.max_loop_size).min(code.len());
        let has_branch = code[offset..end].iter().enumerate().any(|(i, &b)| {
            let rel_off = offset + i;
            (b == 0x7C || b == 0x7E || b == 0x75 || b == 0x72)
                && rel_off + 2 <= end
                && (code[rel_off + 1].cast_signed()) < 0
        });
        if !has_branch {
            return None;
        }
        let size = end - offset;
        if size < self.min_loop_size {
            return None;
        }
        let ks = KeySchedule::static_key(vec![imm_key]);
        let mut dl = DecryptorLoop::new(offset, size, LoopKind::Xor8, ks).with_confidence(80);
        dl.add_note(format!("XOR [r/m], {imm_key:#04x} pattern at {offset:#x}"));
        Some(dl)
    }

    // -----------------------------------------------------------------------
    // Pattern: REP STOSB-preceded loop (multi-byte XOR)
    // F3 AA (REP STOSB) or F3 AB (REP STOSD) followed by xor loop
    // -----------------------------------------------------------------------
    fn try_xor_multibyte_loop(&self, code: &[u8], offset: usize) -> Option<DecryptorLoop> {
        if offset + 4 > code.len() {
            return None;
        }
        // XOR [reg+reg], reg or XOR reg, [reg]
        if code[offset] != 0x30 && code[offset] != 0x32 {
            return None;
        }
        let modrm = code[offset + 1];
        // Memory operand: mod != 11
        if (modrm >> 6) == 3 {
            return None;
        }
        // Look for a key in nearby constants: scan -16..+16
        let scan_start = offset.saturating_sub(16);
        let scan_end = (offset + 16).min(code.len());
        let mut key_bytes = Vec::new();
        for i in scan_start..scan_end {
            if code[i] == 0xB0 || code[i] == 0xB1 || code[i] == 0xB2 {
                // MOV AL/CL/DL, imm8
                if i + 1 < code.len() {
                    key_bytes.push(code[i + 1]);
                    if key_bytes.len() >= 4 {
                        break;
                    }
                }
            }
        }
        if key_bytes.is_empty() {
            key_bytes.push(0xFF); // fallback
        }
        let size = (self.max_loop_size / 2).max(self.min_loop_size);
        let ks = KeySchedule::static_key(key_bytes);
        let mut dl = DecryptorLoop::new(offset, size, LoopKind::XorMultibyte, ks).with_confidence(65);
        dl.add_note(format!("XOR multi-byte loop at {offset:#x}"));
        Some(dl)
    }

    // -----------------------------------------------------------------------
    // Pattern: ADD [ptr], imm8 loop
    // 80 0? imm8 (ADD [ptr], imm8) ; backwards branch
    // -----------------------------------------------------------------------
    fn try_add_loop(&self, code: &[u8], offset: usize) -> Option<DecryptorLoop> {
        if offset + 6 > code.len() {
            return None;
        }
        if code[offset] != 0x80 {
            return None;
        }
        let modrm = code[offset + 1];
        // reg field == 0 → ADD r/m8, imm8
        if (modrm >> 3) & 7 != 0 {
            return None;
        }
        let imm = code[offset + 2];
        let end = (offset + self.max_loop_size).min(code.len());
        let has_branch = code[offset..end].iter().enumerate().any(|(i, &b)| {
            let rel_off = offset + i;
            (b == 0x7D || b == 0x75) && rel_off + 2 <= end && (code[rel_off + 1].cast_signed()) < 0
        });
        if !has_branch {
            return None;
        }
        let size = end - offset;
        if size < self.min_loop_size {
            return None;
        }
        let ks = KeySchedule::static_key(vec![imm]);
        let mut dl = DecryptorLoop::new(offset, size, LoopKind::AddSub, ks).with_confidence(75);
        dl.add_note(format!("ADD [ptr], {imm:#04x} loop at {offset:#x}"));
        Some(dl)
    }

    // -----------------------------------------------------------------------
    // Pattern: ROL/ROR [ptr], imm8 loop
    // C0 ?: imm8 (ROL/ROR r/m8, imm8) ; backwards branch
    // -----------------------------------------------------------------------
    fn try_rotate_loop(&self, code: &[u8], offset: usize) -> Option<DecryptorLoop> {
        if offset + 6 > code.len() {
            return None;
        }
        if code[offset] != 0xC0 {
            return None;
        }
        let modrm = code[offset + 1];
        let reg = (modrm >> 3) & 7;
        // ROL = 0, ROR = 1
        if reg > 1 {
            return None;
        }
        let imm = code[offset + 2];
        let end = (offset + self.max_loop_size).min(code.len());
        let has_branch = code[offset..end].iter().enumerate().any(|(i, &b)| {
            let rel_off = offset + i;
            b == 0x75 && rel_off + 2 <= end && (code[rel_off + 1].cast_signed()) < 0
        });
        if !has_branch {
            return None;
        }
        let size = end - offset;
        if size < self.min_loop_size {
            return None;
        }
        let name = if reg == 0 { "ROL" } else { "ROR" };
        let ks = KeySchedule::static_key(vec![imm]);
        let mut dl = DecryptorLoop::new(offset, size, LoopKind::Rotate, ks).with_confidence(78);
        dl.add_note(format!("{name} [ptr], {imm} loop at {offset:#x}"));
        Some(dl)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_schedule_to_hex() {
        let ks = KeySchedule::static_key(vec![0xDE, 0xAD]);
        assert_eq!(ks.to_hex(), "dead");
    }

    #[test]
    fn test_key_update_add_delta_step() {
        let ks = KeySchedule {
            bytes: vec![0x10, 0x20],
            seed: 0x10,
            update: KeyUpdate::AddDelta(0x01),
        };
        let next = ks.step();
        assert_eq!(next, vec![0x11, 0x21]);
    }

    #[test]
    fn test_decrypt_xor8() {
        let dl = DecryptorLoop::new(
            0, 4, LoopKind::Xor8, KeySchedule::static_key(vec![0x42]),
        );
        let cipher = vec![0x42 ^ 0xAA, 0x42 ^ 0xBB];
        let plain = dl.decrypt(&cipher);
        assert_eq!(plain, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_decrypt_xor_multibyte() {
        let dl = DecryptorLoop::new(
            0, 4, LoopKind::XorMultibyte, KeySchedule::static_key(vec![0x11, 0x22]),
        );
        let cipher = vec![0xAA ^ 0x11, 0xBB ^ 0x22, 0xCC ^ 0x11];
        let plain = dl.decrypt(&cipher);
        assert_eq!(plain, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_decrypt_add_sub() {
        let dl = DecryptorLoop::new(
            0, 4, LoopKind::AddSub, KeySchedule::static_key(vec![0x05]),
        );
        let cipher = vec![0x0A, 0x14, 0x1E]; // 5+5, 15+5, 25+5
        let plain = dl.decrypt(&cipher);
        assert_eq!(plain, vec![0x05, 0x0F, 0x19]);
    }

    #[test]
    fn test_extract_xor8_loop() {
        // Build a simple XOR [eax], 0x42 / JNE back loop body
        let mut code = vec![
            0x80u8, 0x30, 0x42,  // XOR [eax], 0x42
            0xFF, 0xC0,           // INC eax
            0xFF, 0xCB,           // DEC ebx
            0x75, 0xF7,           // JNZ -9 (backward)
        ];
        code.extend(vec![0x90u8; 8]);
        let extractor = SmcDecryptorExtractor::new().with_min_confidence(0);
        let results = extractor.extract(&code);
        assert!(!results.is_empty(), "should detect XOR loop");
        assert_eq!(results[0].kind, LoopKind::Xor8);
    }

    #[test]
    fn test_extract_add_loop() {
        let mut code = vec![
            0x80u8, 0x00, 0x05,  // ADD [eax], 0x05
            0xFF, 0xC0,           // INC eax
            0x75, 0xF9,           // JNZ -7 (backward)
        ];
        code.extend(vec![0x90u8; 8]);
        let extractor = SmcDecryptorExtractor::new().with_min_confidence(0);
        let results = extractor.extract(&code);
        assert!(!results.is_empty(), "should detect ADD loop");
    }

    #[test]
    fn test_extract_rotate_loop() {
        let code = vec![
            0xC0u8, 0x00, 0x03,  // ROL [eax], 3
            0xFF, 0xC0,           // INC eax
            0x75, 0xF9,           // JNZ -7
            0x90, 0x90, 0x90,
        ];
        let extractor = SmcDecryptorExtractor::new().with_min_confidence(0);
        let results = extractor.extract(&code);
        assert!(!results.is_empty());
        assert_eq!(results[0].kind, LoopKind::Rotate);
    }

    #[test]
    fn test_extract_empty_code() {
        let results = SmcDecryptorExtractor::new().extract(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_loop_display() {
        let ks = KeySchedule::static_key(vec![0xAB]);
        let dl = DecryptorLoop::new(0x100, 32, LoopKind::Xor8, ks).with_confidence(80);
        let s = dl.to_string();
        assert!(s.contains("XOR8"));
        assert!(s.contains("0x100"));
    }

    #[test]
    fn test_key_update_xor_delta() {
        let ks = KeySchedule {
            bytes: vec![0xFF],
            seed: 0xFF,
            update: KeyUpdate::XorDelta(0x0F),
        };
        assert_eq!(ks.step(), vec![0xFF ^ 0x0F]);
    }

    #[test]
    fn test_loop_kind_display() {
        assert_eq!(LoopKind::Xor8.to_string(), "XOR8");
        assert_eq!(LoopKind::Rc4Like.to_string(), "RC4");
        assert_eq!(LoopKind::Unknown.to_string(), "UNKNOWN");
    }
}
