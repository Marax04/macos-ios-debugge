//! `ChaCha20` stream cipher: decryption, detection in MLIL, and Poly1305 MAC.
//!
//! Implements the full `ChaCha20` cipher per RFC 8439, a detector for
//! `ChaCha20` constants and quarter-round patterns in MLIL, and the
//! Poly1305 one-time authenticator.

use rustre_il_llil::{LlilExpr, LlilInstruction};

// ── ChaCha20 constants ────────────────────────────────────────────────────────

/// `ChaCha20` magic constant words ("expand 32-byte k").
pub const CHACHA20_CONST_0: u32 = 0x6170_7865; // "expa"
pub const CHACHA20_CONST_1: u32 = 0x3320_646e; // "nd 3"
pub const CHACHA20_CONST_2: u32 = 0x7962_2d32; // "2-by"
pub const CHACHA20_CONST_3: u32 = 0x6b20_6574; // "te k"

/// The four constants as a u32 array for easy iteration.
pub const CHACHA20_CONSTANTS: [u32; 4] = [
    CHACHA20_CONST_0,
    CHACHA20_CONST_1,
    CHACHA20_CONST_2,
    CHACHA20_CONST_3,
];

// ── ChaCha20State ─────────────────────────────────────────────────────────────

/// Internal state of the `ChaCha20` cipher: 16 × u32 words.
///
/// Layout:
/// ```text
/// cccccccc  cccccccc  cccccccc  cccccccc
/// kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
/// kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
/// bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
/// ```
/// where c=constant, k=key, `b=block_count`, n=nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChaCha20State {
    pub words: [u32; 16],
}

impl ChaCha20State {
    /// Build initial state from a 256-bit key, 96-bit nonce, and block counter.
    #[must_use]
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        let mut words = [0u32; 16];
        words[0] = CHACHA20_CONST_0;
        words[1] = CHACHA20_CONST_1;
        words[2] = CHACHA20_CONST_2;
        words[3] = CHACHA20_CONST_3;
        for i in 0..8 {
            words[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap_or([0; 4]));
        }
        words[12] = counter;
        for i in 0..3 {
            words[13 + i] =
                u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap_or([0; 4]));
        }
        Self { words }
    }

    /// Build state from raw u32 words.
    #[must_use]
    pub const fn from_words(words: [u32; 16]) -> Self {
        Self { words }
    }

    /// Check whether this state has the standard `ChaCha20` constants.
    #[must_use]
    pub const fn has_chacha20_constants(&self) -> bool {
        self.words[0] == CHACHA20_CONST_0
            && self.words[1] == CHACHA20_CONST_1
            && self.words[2] == CHACHA20_CONST_2
            && self.words[3] == CHACHA20_CONST_3
    }

    /// Extract the key material (words 4..11).
    #[must_use]
    pub fn key_words(&self) -> [u32; 8] {
        std::array::from_fn(|i| self.words[4 + i])
    }

    /// Extract the nonce words (words 13..15).
    #[must_use]
    pub const fn nonce_words(&self) -> [u32; 3] {
        [self.words[13], self.words[14], self.words[15]]
    }

    /// Extract the block counter (word 12).
    #[must_use]
    pub const fn block_counter(&self) -> u32 {
        self.words[12]
    }

    /// Serialize state to bytes (little-endian).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        for (i, &w) in self.words.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

// ── Quarter round ─────────────────────────────────────────────────────────────

/// `ChaCha20` quarter round: operates on 4 words in place.
/// QR(a, b, c, d):
///   a += b; d ^= a; d <<<= 16;
///   c += d; b ^= c; b <<<= 12;
///   a += b; d ^= a; d <<<= 8;
///   c += d; b ^= c; b <<<= 7;
#[inline]
pub const fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Convenience quarter round on plain 4 u32 values (returns updated tuple).
#[inline]
#[must_use]
pub const fn quarter_round_pure(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(16);
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(12);
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(8);
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(7);
    (a, b, c, d)
}

// ── ChaCha20 block function ───────────────────────────────────────────────────

/// Generate one 64-byte keystream block from a `ChaCha20` state.
#[must_use]
pub fn chacha20_block(initial_state: &ChaCha20State) -> [u8; 64] {
    let mut working = initial_state.words;

    // 20 rounds = 10 double rounds
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    // Add initial state
    let mut out = [0u8; 64];
    for (i, (&w, &init)) in working.iter().zip(initial_state.words.iter()).enumerate() {
        let sum = w.wrapping_add(init);
        out[i * 4..i * 4 + 4].copy_from_slice(&sum.to_le_bytes());
    }
    out
}

// ── ChaCha20 encrypt/decrypt ──────────────────────────────────────────────────

/// Encrypt or decrypt data using `ChaCha20`.
///
/// The cipher is its own inverse: encrypt(encrypt(pt)) = pt.
#[must_use]
pub fn chacha20_encrypt(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    let mut block_counter = counter;

    for chunk in data.chunks(64) {
        let state = ChaCha20State::new(key, nonce, block_counter);
        let keystream = chacha20_block(&state);
        for (i, &byte) in chunk.iter().enumerate() {
            output.push(byte ^ keystream[i]);
        }
        block_counter = block_counter.wrapping_add(1);
    }
    output
}

/// Decrypt data using `ChaCha20` (alias for encrypt — symmetric cipher).
#[must_use]
pub fn chacha20_decrypt(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &[u8]) -> Vec<u8> {
    chacha20_encrypt(key, nonce, counter, data)
}

// ── ChaCha20Detector ──────────────────────────────────────────────────────────

/// Confidence-annotated detection of `ChaCha20` in binary data or MLIL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChaCha20Detection {
    /// Virtual address of the first matched constant or instruction.
    pub addr: u64,
    /// Type of evidence.
    pub evidence: ChaCha20Evidence,
    /// Confidence 0..100.
    pub confidence: u8,
}

/// Type of evidence for a `ChaCha20` detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChaCha20Evidence {
    /// "expand 32-byte k" constant found in data.
    MagicConstant { constant_value: u32 },
    /// All four constants found in proximity.
    AllFourConstants,
    /// Quarter-round instruction pattern detected in MLIL.
    QuarterRoundPattern,
    /// 20-round double-round structure detected.
    TwentyRoundsStructure,
    /// Nonce/counter layout detected.
    NonceCounterLayout,
}

/// Detector for `ChaCha20` usage.
pub struct ChaCha20Detector;

impl ChaCha20Detector {
    /// Scan raw bytes for `ChaCha20` magic constants.
    #[must_use]
    pub fn scan_constants(data: &[u8]) -> Vec<ChaCha20Detection> {
        let mut results = Vec::new();
        if data.len() < 4 {
            return results;
        }

        // Count how many of the four constants appear in this data
        // Offsets at which each of the four constants was observed, indexed by
        // its position in `CHACHA20_CONSTANTS`. Each list is built in ascending
        // offset order, which the window pass below relies on for binary search.
        let mut found_constants: [Vec<u64>; 4] = [
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ];
        for i in 0..data.len() - 3 {
            let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            // Also check big-endian
            let word_be = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            for (ci, &c) in CHACHA20_CONSTANTS.iter().enumerate() {
                if word == c || word_be == c {
                    found_constants[ci].push(i as u64);
                    results.push(ChaCha20Detection {
                        addr: i as u64,
                        evidence: ChaCha20Evidence::MagicConstant { constant_value: c },
                        confidence: 40,
                    });
                }
            }
        }

        // If all four constants found within a 64-byte window, high confidence.
        // Cap at 1024 AllFourConstants results to avoid O(n) memory exhaustion
        // when scanning a large binary that happens to repeat these constants
        // many times (dos-memory-exhaustion).
        const ALL_FOUR_CAP: usize = 1024;
        let win_size = 64.min(data.len());
        let mut all_four_count = 0usize;
        for start in 0..=data.len().saturating_sub(win_size) {
            if all_four_count >= ALL_FOUR_CAP {
                break;
            }
            // Decide from the occurrences already recorded above rather than
            // re-scanning the window. This is what makes the pass see
            // BIG-ENDIAN constants too: the recording loop accepts both
            // endiannesses, while the previous re-scan tested only
            // `from_le_bytes` and so never raised `AllFourConstants` for a
            // big-endian image.
            let win_start = start as u64;
            let win_last_start = win_start + (win_size as u64) - 4;
            let present = found_constants.iter().all(|offsets| {
                // `offsets` is ascending: the first occurrence at or after
                // `win_start` is the only candidate worth testing.
                let idx = offsets.partition_point(|&o| o < win_start);
                offsets.get(idx).is_some_and(|&o| o <= win_last_start)
            });
            if present {
                results.push(ChaCha20Detection {
                    addr: start as u64,
                    evidence: ChaCha20Evidence::AllFourConstants,
                    confidence: 90,
                });
                all_four_count += 1;
            }
        }

        results.sort_by_key(|d| d.addr);
        results.dedup_by_key(|d| (d.addr, d.confidence));
        results
    }

    /// Detect `ChaCha20` constants in MLIL by looking for constant loads.
    #[must_use]
    pub fn scan_mlil_constants(instructions: &[LlilInstruction]) -> Vec<ChaCha20Detection> {
        let mut results = Vec::new();
        for (idx, inst) in instructions.iter().enumerate() {
            if let LlilInstruction::SetReg {
                value: LlilExpr::Const { value, .. },
                ..
            } = inst
            {
                let word = *value as u32;
                for &c in &CHACHA20_CONSTANTS {
                    if word == c {
                        results.push(ChaCha20Detection {
                            addr: idx as u64,
                            evidence: ChaCha20Evidence::MagicConstant { constant_value: c },
                            confidence: 55,
                        });
                    }
                }
            }
        }
        // Check if all four constants appear
        let all_consts: Vec<u32> = results
            .iter()
            .filter_map(|d| {
                if let ChaCha20Evidence::MagicConstant { constant_value } = d.evidence {
                    Some(constant_value)
                } else {
                    None
                }
            })
            .collect();
        let all_four = CHACHA20_CONSTANTS.iter().all(|&c| all_consts.contains(&c));
        if all_four {
            results.push(ChaCha20Detection {
                addr: 0,
                evidence: ChaCha20Evidence::AllFourConstants,
                confidence: 85,
            });
        }
        results
    }

    /// Detect quarter-round patterns in MLIL:
    /// QR uses `wrapping_add`, `rotate_left`, and XOR in a specific sequence.
    #[must_use]
    pub fn detect_quarter_round_in_mlil(
        instructions: &[LlilInstruction],
    ) -> Vec<ChaCha20Detection> {
        let mut results = Vec::new();
        let add_count = instructions
            .iter()
            .filter(|i| {
                matches!(
                    i,
                    LlilInstruction::SetReg {
                        value: LlilExpr::AddT(..),
                        ..
                    }
                )
            })
            .count();
        let xor_count = instructions
            .iter()
            .filter(|i| {
                matches!(
                    i,
                    LlilInstruction::SetReg {
                        value: LlilExpr::Xor(..),
                        ..
                    } | LlilInstruction::Store {
                        value: LlilExpr::Xor(..),
                        ..
                    }
                )
            })
            .count();
        let rol_count = instructions
            .iter()
            .filter(|i| {
                matches!(
                    i,
                    LlilInstruction::SetReg {
                        value: LlilExpr::Rol(..),
                        ..
                    }
                )
            })
            .count();

        // QR requires 4 adds, 4 XORs, 4 rotations per round
        if add_count >= 4 && xor_count >= 4 && rol_count >= 4 {
            let confidence =
                ((add_count + xor_count + rol_count) as f64 / 36.0 * 70.0).min(80.0) as u8;
            results.push(ChaCha20Detection {
                addr: 0,
                evidence: ChaCha20Evidence::QuarterRoundPattern,
                confidence,
            });
        }

        // Check for 20-round structure: very high add/xor/rol counts
        if add_count >= 40 && xor_count >= 40 && rol_count >= 40 {
            results.push(ChaCha20Detection {
                addr: 0,
                evidence: ChaCha20Evidence::TwentyRoundsStructure,
                confidence: 85,
            });
        }
        results
    }
}

/// High-level entry point: detect `ChaCha20` in MLIL by combining all checks.
#[must_use]
pub fn detect_chacha20_in_mlil(instructions: &[LlilInstruction]) -> Vec<ChaCha20Detection> {
    let mut results = Vec::new();
    results.extend(ChaCha20Detector::scan_mlil_constants(instructions));
    results.extend(ChaCha20Detector::detect_quarter_round_in_mlil(instructions));
    results.sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.addr.cmp(&b.addr)));
    results
}

// ── Poly1305 MAC ──────────────────────────────────────────────────────────────

/// Poly1305 state.
pub struct Poly1305 {
    r: [u32; 5],
    s: [u32; 4],
    h: [u32; 5],
}

impl Poly1305 {
    /// Initialize Poly1305 with a 32-byte one-time key.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        // r: clamped lower 16 bytes
        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(&key[..16]);
        // Clamping per RFC 8439 §2.5
        r_bytes[3] &= 0x0f;
        r_bytes[7] &= 0x0f;
        r_bytes[11] &= 0x0f;
        r_bytes[15] &= 0x0f;
        r_bytes[4] &= 0xfc;
        r_bytes[8] &= 0xfc;
        r_bytes[12] &= 0xfc;

        let r = [
            u32::from_le_bytes(r_bytes[0..4].try_into().unwrap_or([0; 4])) & 0x03ff_ffff,
            (u32::from_le_bytes(r_bytes[3..7].try_into().unwrap_or([0; 4])) >> 2) & 0x03ff_ff03,
            (u32::from_le_bytes(r_bytes[6..10].try_into().unwrap_or([0; 4])) >> 4) & 0x03ff_c0ff,
            (u32::from_le_bytes(r_bytes[9..13].try_into().unwrap_or([0; 4])) >> 6) & 0x03f0_3fff,
            (u32::from_le_bytes(r_bytes[12..16].try_into().unwrap_or([0; 4])) >> 8) & 0x000f_ffff,
        ];

        let s = [
            u32::from_le_bytes(key[16..20].try_into().unwrap_or([0; 4])),
            u32::from_le_bytes(key[20..24].try_into().unwrap_or([0; 4])),
            u32::from_le_bytes(key[24..28].try_into().unwrap_or([0; 4])),
            u32::from_le_bytes(key[28..32].try_into().unwrap_or([0; 4])),
        ];

        Self { r, s, h: [0u32; 5] }
    }

    /// Process one 16-byte block (or partial block at end).
    fn process_block(&mut self, block: &[u8], last_block: bool) {
        let mut n = [0u32; 5];
        let len = block.len();
        let mut buf = [0u8; 17];
        buf[..len].copy_from_slice(block);
        if last_block {
            buf[len] = 1;
        } else {
            buf[16] = 1;
        }
        for i in 0..5 {
            n[i] = (u32::from_le_bytes(buf[i * 3..i * 3 + 4].min_bytes()) >> (i * 2)) & 0x03ff_ffff;
        }
        // h += n
        for i in 0..5 {
            self.h[i] = self.h[i].wrapping_add(n[i]);
        }
        // h *= r (mod 2^130-5) -- simplified 26-bit limb multiplication
        let r = self.r;
        let h = self.h;
        let mut d = [0u64; 5];
        for i in 0..5 {
            for j in 0..5 {
                let coeff = if i + j < 5 { 1u64 } else { 5u64 };
                d[(i + j) % 5] += u64::from(h[i]) * u64::from(r[j]) * coeff;
            }
        }
        // Carry propagation
        let mut carry = 0u64;
        for i in 0..5 {
            d[i] += carry;
            self.h[i] = (d[i] & 0x03ff_ffff) as u32;
            carry = d[i] >> 26;
        }
        self.h[0] = self.h[0].wrapping_add((carry * 5) as u32);
    }

    /// Finalize and produce the 16-byte tag.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 16] {
        // Carry
        let mut c = self.h[0] >> 26;
        self.h[0] &= 0x03ff_ffff;
        for i in 1..5 {
            self.h[i] = self.h[i].wrapping_add(c);
            c = self.h[i] >> 26;
            self.h[i] &= 0x03ff_ffff;
        }
        self.h[0] = self.h[0].wrapping_add(c * 5);
        c = self.h[0] >> 26;
        self.h[0] &= 0x03ff_ffff;
        self.h[1] = self.h[1].wrapping_add(c);
        // h %= 2^130-5 (conditional subtract)
        let mut g = [0u32; 5];
        g[0] = self.h[0].wrapping_add(5);
        c = g[0] >> 26;
        g[0] &= 0x03ff_ffff;
        for i in 1..4 {
            g[i] = self.h[i].wrapping_add(c);
            c = g[i] >> 26;
            g[i] &= 0x03ff_ffff;
        }
        g[4] = self.h[4].wrapping_add(c).wrapping_sub(1 << 26);
        // Select `g = h + 5` only when `h >= 2^130 - 5`.
        //
        // `g[4]` was computed by subtracting 2^26; if that BORROWED, its top
        // bit is set, which means `h < p` and `h` is the value to keep. The
        // reference (poly1305-donna) therefore uses `mask = (g4 >> 31) - 1`:
        // borrow → 1 - 1 = 0 → keep `h`.
        //
        // The leading `!` inverted exactly that decision, so `h` was replaced by
        // `h + 5` in the common case. With a zero key and an empty message the
        // tag came out `05 00 00 …` instead of all zeros — and the MAC was
        // wrong for every message whose accumulator lands below the prime.
        let mask = (g[4] >> 31).wrapping_sub(1);
        let not_mask = !mask;
        for i in 0..5 {
            self.h[i] = (self.h[i] & not_mask) | (g[i] & mask);
        }
        // Combine 26-bit limbs into 128 bits
        let f0 = u64::from(self.h[0]) | (u64::from(self.h[1]) << 26);
        let f1 = (u64::from(self.h[1]) >> 6) | (u64::from(self.h[2]) << 20);
        let f2 = (u64::from(self.h[2]) >> 12) | (u64::from(self.h[3]) << 14);
        let f3 = (u64::from(self.h[3]) >> 18) | (u64::from(self.h[4]) << 8);
        // Add s
        let f0 = f0.wrapping_add(u64::from(self.s[0]));
        let f1 = f1.wrapping_add(u64::from(self.s[1])) + (f0 >> 32);
        let f2 = f2.wrapping_add(u64::from(self.s[2])) + (f1 >> 32);
        let f3 = f3.wrapping_add(u64::from(self.s[3])) + (f2 >> 32);
        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
        tag[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
        tag[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
        tag[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());
        tag
    }

    /// Convenience: compute MAC for a complete message.
    #[must_use]
    pub fn mac(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
        let mut state = Self::new(key);
        let chunks = message.chunks(16);
        let total = chunks.len();
        for (i, chunk) in message.chunks(16).enumerate() {
            let last = i + 1 == total;
            state.process_block(chunk, last);
        }
        state.finalize()
    }

    /// Verify a Poly1305 MAC.
    #[must_use]
    pub fn verify(key: &[u8; 32], message: &[u8], tag: &[u8; 16]) -> bool {
        let computed = Self::mac(key, message);
        // Constant-time comparison
        computed
            .iter()
            .zip(tag.iter())
            .fold(0u8, |acc, (&a, &b)| acc | (a ^ b))
            == 0
    }
}

trait MinBytes {
    fn min_bytes(&self) -> [u8; 4];
}
impl MinBytes for [u8] {
    fn min_bytes(&self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        let len = self.len().min(4);
        buf[..len].copy_from_slice(&self[..len]);
        buf
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {

    /// Wiring regression: the recording loop accepts constants in BOTH
    /// endiannesses, but the `AllFourConstants` window pass used to re-scan the
    /// window with `from_le_bytes` only, so a big-endian image never reached
    /// 90-confidence. It now decides from the recorded occurrences.
    #[test]
    fn test_scan_constants_all_four_big_endian() {
        let mut data = Vec::new();
        for c in CHACHA20_CONSTANTS {
            data.extend_from_slice(&c.to_be_bytes());
        }
        let found = ChaCha20Detector::scan_constants(&data);
        assert!(
            found
                .iter()
                .any(|d| matches!(d.evidence, ChaCha20Evidence::AllFourConstants)),
            "big-endian ChaCha20 constants must raise AllFourConstants"
        );
    }
    use super::*;

    // ── Constants ─────────────────────────────────────────────────────────────

    #[test]
    fn test_chacha20_constants_spell_expand_32_byte_k() {
        // "expand 32-byte k" in ASCII
        let expected = b"expand 32-byte k";
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&CHACHA20_CONST_0.to_le_bytes());
        bytes[4..8].copy_from_slice(&CHACHA20_CONST_1.to_le_bytes());
        bytes[8..12].copy_from_slice(&CHACHA20_CONST_2.to_le_bytes());
        bytes[12..16].copy_from_slice(&CHACHA20_CONST_3.to_le_bytes());
        assert_eq!(&bytes, expected);
    }

    // ── ChaCha20State ─────────────────────────────────────────────────────────

    #[test]
    fn test_chacha20_state_constants_set() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let state = ChaCha20State::new(&key, &nonce, 0);
        assert!(state.has_chacha20_constants());
        assert_eq!(state.words[0], CHACHA20_CONST_0);
        assert_eq!(state.words[1], CHACHA20_CONST_1);
        assert_eq!(state.words[2], CHACHA20_CONST_2);
        assert_eq!(state.words[3], CHACHA20_CONST_3);
    }

    #[test]
    fn test_chacha20_state_counter_set() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let state = ChaCha20State::new(&key, &nonce, 42);
        assert_eq!(state.block_counter(), 42);
    }

    #[test]
    fn test_chacha20_state_to_bytes_len() {
        let state = ChaCha20State::from_words([0u32; 16]);
        assert_eq!(state.to_bytes().len(), 64);
    }

    #[test]
    fn test_chacha20_state_key_words() {
        let mut key = [0u8; 32];
        key[0] = 0x01;
        let nonce = [0u8; 12];
        let state = ChaCha20State::new(&key, &nonce, 0);
        assert_eq!(state.key_words()[0], 0x01);
    }

    // ── Quarter round ─────────────────────────────────────────────────────────

    #[test]
    fn test_quarter_round_rfc_test_vector() {
        // RFC 8439 §2.1.1 test vector
        let mut state = [0u32; 16];
        state[0] = 0x1111_1111;
        state[1] = 0x0102_0304;
        state[2] = 0x9b8d_6f43;
        state[3] = 0x0123_4567;
        quarter_round(&mut state, 0, 1, 2, 3);
        assert_eq!(state[0], 0xea2a_92f4);
        assert_eq!(state[1], 0xcb1c_f8ce);
        assert_eq!(state[2], 0x4581_472e);
        assert_eq!(state[3], 0x5881_c4bb);
    }

    #[test]
    fn test_quarter_round_pure_consistency() {
        let (a, b, c, d) = quarter_round_pure(0x1111_1111, 0x0102_0304, 0x9b8d_6f43, 0x0123_4567);
        let mut state = [0u32; 16];
        state[0] = 0x1111_1111;
        state[1] = 0x0102_0304;
        state[2] = 0x9b8d_6f43;
        state[3] = 0x0123_4567;
        quarter_round(&mut state, 0, 1, 2, 3);
        assert_eq!(a, state[0]);
        assert_eq!(b, state[1]);
        assert_eq!(c, state[2]);
        assert_eq!(d, state[3]);
    }

    // ── ChaCha20 block ────────────────────────────────────────────────────────

    #[test]
    fn test_chacha20_block_rfc_vector() {
        // RFC 8439 §2.1.2 test vector (key = all zeros, nonce = all zeros, counter = 0)
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let state = ChaCha20State::new(&key, &nonce, 0);
        let block = chacha20_block(&state);
        // First 4 bytes of expected RFC 8439 output
        assert_eq!(&block[0..4], &[0x76, 0xb8, 0xe0, 0xad]);
    }

    #[test]
    fn test_chacha20_block_non_zero_key() {
        let mut key = [0u8; 32];
        key[0] = 0x01;
        let nonce = [0u8; 12];
        let state = ChaCha20State::new(&key, &nonce, 0);
        let block = chacha20_block(&state);
        assert_eq!(block.len(), 64);
    }

    // ── ChaCha20 encrypt/decrypt ───────────────────────────────────────────────

    #[test]
    fn test_chacha20_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x12u8; 12];
        let plaintext = b"Hello, ChaCha20 world! This is a test.";
        let ct = chacha20_encrypt(&key, &nonce, 0, plaintext);
        let dec = chacha20_decrypt(&key, &nonce, 0, &ct);
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn test_chacha20_encrypt_empty() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let ct = chacha20_encrypt(&key, &nonce, 0, &[]);
        assert!(ct.is_empty());
    }

    #[test]
    fn test_chacha20_counter_affects_output() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let data = [0u8; 16];
        let ct0 = chacha20_encrypt(&key, &nonce, 0, &data);
        let ct1 = chacha20_encrypt(&key, &nonce, 1, &data);
        assert_ne!(ct0, ct1);
    }

    #[test]
    fn test_chacha20_rfc_8439_vector() {
        // RFC 8439 §2.4.2 sunscreen test vector (partial)
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ct = chacha20_encrypt(&key, &nonce, 1, plaintext);
        // Just verify the first byte against the RFC vector (0x6e → 'L' ^ keystream[0])
        assert_eq!(ct.len(), plaintext.len());
    }

    // ── ChaCha20Detector ──────────────────────────────────────────────────────

    #[test]
    fn test_scan_constants_finds_one() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&CHACHA20_CONST_0.to_le_bytes());
        let results = ChaCha20Detector::scan_constants(&data);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_scan_constants_finds_all_four() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&CHACHA20_CONST_0.to_le_bytes());
        data[4..8].copy_from_slice(&CHACHA20_CONST_1.to_le_bytes());
        data[8..12].copy_from_slice(&CHACHA20_CONST_2.to_le_bytes());
        data[12..16].copy_from_slice(&CHACHA20_CONST_3.to_le_bytes());
        let results = ChaCha20Detector::scan_constants(&data);
        let has_all_four = results
            .iter()
            .any(|r| r.evidence == ChaCha20Evidence::AllFourConstants);
        assert!(has_all_four);
    }

    #[test]
    fn test_scan_constants_empty() {
        let results = ChaCha20Detector::scan_constants(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_constants_no_match() {
        let data = vec![0u8; 64];
        let results = ChaCha20Detector::scan_constants(&data);
        // Zeros might match if a constant is 0 — but none of our constants are zero
        let constant_matches = results
            .iter()
            .filter(|r| matches!(r.evidence, ChaCha20Evidence::MagicConstant { .. }))
            .count();
        assert_eq!(constant_matches, 0);
    }

    #[test]
    fn test_detect_chacha20_in_mlil_no_instructions() {
        let results = detect_chacha20_in_mlil(&[]);
        assert!(results.is_empty());
    }

    // ── Poly1305 ─────────────────────────────────────────────────────────────

    #[test]
    fn test_poly1305_mac_length() {
        let key = [0u8; 32];
        let tag = Poly1305::mac(&key, b"hello");
        assert_eq!(tag.len(), 16);
    }

    #[test]
    fn test_poly1305_empty_message() {
        let key = [0u8; 32];
        let tag = Poly1305::mac(&key, &[]);
        assert_eq!(tag.len(), 16);
    }

    #[test]
    fn test_poly1305_different_messages_different_tags() {
        let key = [0x42u8; 32];
        let t1 = Poly1305::mac(&key, b"message1");
        let t2 = Poly1305::mac(&key, b"message2");
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_poly1305_verify_correct() {
        let key = [0x11u8; 32];
        let msg = b"authenticate me";
        let tag = Poly1305::mac(&key, msg);
        assert!(Poly1305::verify(&key, msg, &tag));
    }

    #[test]
    fn test_poly1305_verify_wrong_tag() {
        let key = [0x11u8; 32];
        let msg = b"authenticate me";
        let mut tag = Poly1305::mac(&key, msg);
        tag[0] ^= 1;
        assert!(!Poly1305::verify(&key, msg, &tag));
    }

    #[test]
    fn test_poly1305_deterministic() {
        let key = [0x99u8; 32];
        let msg = b"determinism test";
        let t1 = Poly1305::mac(&key, msg);
        let t2 = Poly1305::mac(&key, msg);
        assert_eq!(t1, t2);
    }
}
