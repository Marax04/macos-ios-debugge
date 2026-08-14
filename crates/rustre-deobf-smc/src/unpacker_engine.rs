//! Unpacker engine for Self-Modifying Code (SMC) deobfuscation.
//!
//! Provides:
//! * [`DecryptionLoop`] — recognition of common decryption loop patterns.
//! * [`KeyExtraction`] — static key-material extraction from recognised loops.
//! * [`UnpackedRegion`] — a decrypted memory region.
//! * [`UnpackingSession`] — single-layer unpacking context.
//! * [`UnpackingReport`] — summary of a single-layer unpack.
//! * [`MultiLayerUnpacker`] — drives multi-layer unpacking until convergence.
//! * [`UnpackerEngine`] — top-level orchestrator.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Algorithm / key types (mirrors crate-level enums but self-contained)
// ─────────────────────────────────────────────────────────────────────────────

/// The algorithm applied to each element of the packed region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnpackAlgo {
    /// `byte ^= key`
    Xor,
    /// `byte += key`
    Add,
    /// `byte -= key`
    Sub,
    /// `byte = rol(byte, key)`
    Rol,
    /// `byte = ror(byte, key)`
    Ror,
    /// Rolling XOR (`byte ^= key; key = byte`)
    XorRolling,
    /// Multi-byte XOR key (cycling).
    XorCyclic,
    /// RC4 stream cipher.
    Rc4,
    /// Custom / unknown.
    Unknown,
}

impl UnpackAlgo {
    /// Short label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Xor => "xor",
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Rol => "rol",
            Self::Ror => "ror",
            Self::XorRolling => "xor-rolling",
            Self::XorCyclic => "xor-cyclic",
            Self::Rc4 => "rc4",
            Self::Unknown => "unknown",
        }
    }

    /// Return `true` if this algorithm is stream-based (key may cycle).
    #[must_use]
    pub const fn is_stream(self) -> bool {
        matches!(self, Self::Rc4 | Self::XorCyclic | Self::XorRolling)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DecryptionLoop
// ─────────────────────────────────────────────────────────────────────────────

/// Structural information about a recognised decryption loop.
#[derive(Debug, Clone)]
pub struct DecryptionLoop {
    /// File offset of the loop.
    pub offset: usize,
    /// Approximate number of bytes in the loop body.
    pub body_size: usize,
    /// The algorithm identified within the loop.
    pub algorithm: UnpackAlgo,
    /// Confidence (0–100).
    pub confidence: u8,
    /// The stride of the loop (bytes processed per iteration, typically 1 or 4).
    pub stride: usize,
    /// Whether the loop also writes a next-key value (rolling / CBC-like).
    pub updates_key: bool,
}

impl DecryptionLoop {
    /// Create a new loop record.
    #[must_use]
    pub fn new(offset: usize, algorithm: UnpackAlgo, confidence: u8) -> Self {
        Self {
            offset,
            body_size: 0,
            algorithm,
            confidence: confidence.min(100),
            stride: 1,
            updates_key: false,
        }
    }

    /// Set stride.
    #[must_use]
    pub const fn with_stride(mut self, s: usize) -> Self {
        self.stride = s;
        self
    }

    /// Set body size.
    #[must_use]
    pub const fn with_body_size(mut self, s: usize) -> Self {
        self.body_size = s;
        self
    }

    /// Mark as updating the key.
    #[must_use]
    pub const fn with_key_update(mut self) -> Self {
        self.updates_key = true;
        self
    }
}

/// Recognise decryption loops in raw x86 machine code `data`.
///
/// Detection heuristics:
/// 1. **XOR loop** — `XOR [base+reg], key_reg` inside a `DEC`/`LOOP` structure.
///    Pattern: `30/32 xx` near `E2/74/75` (LOOP / JNZ).
/// 2. **ADD loop** — `ADD [base+reg], imm8` (`80 00..07 xx`) near loop boundary.
/// 3. **ROL/ROR** — `C0/C1 C0..C7 xx` near loop boundary.
/// 4. **RC4 PRGA** — characteristic `XCHG [s+ecx], [s+edx]` sequence.
#[must_use]
pub fn detect_decryption_loops(data: &[u8]) -> Vec<DecryptionLoop> {
    let mut loops: Vec<DecryptionLoop> = Vec::new();
    let len = data.len();

    // Scan for loop patterns.
    for i in 0..len.saturating_sub(2) {
        // Pattern 1: XOR [mem], reg  (30 xx or 32 xx) followed within 16 bytes by LOOP/JNZ
        if (data[i] == 0x30 || data[i] == 0x32) && i + 2 < len {
            let window = &data[i..(i + 16).min(len)];
            let has_loop_insn = window
                .iter()
                .any(|&b| matches!(b, 0xE2 | 0x74 | 0x75 | 0xEB));
            if has_loop_insn {
                loops.push(DecryptionLoop::new(i, UnpackAlgo::Xor, 85).with_body_size(16));
            }
        }

        // Pattern 2: XOR byte ptr [reg], imm8  (80 30..37 xx) near loop boundary
        if data[i] == 0x80 && i + 3 < len {
            let modrm = data[i + 1];
            if (modrm & 0b0011_1000) == 0b0011_0000 {
                // /6 = XOR
                let window_end = (i + 24).min(len);
                let has_loop = data[i..window_end]
                    .iter()
                    .any(|&b| matches!(b, 0xE2 | 0x75 | 0xEB));
                if has_loop {
                    loops.push(DecryptionLoop::new(i, UnpackAlgo::Xor, 82).with_body_size(24));
                }
            }
        }

        // Pattern 3: ADD byte ptr [reg], imm8  (80 00..07 xx) near loop boundary
        if data[i] == 0x80 && i + 3 < len {
            let modrm = data[i + 1];
            if (modrm & 0b0011_1000) == 0b0000_0000 {
                // /0 = ADD
                let window_end = (i + 24).min(len);
                let has_loop = data[i..window_end]
                    .iter()
                    .any(|&b| matches!(b, 0xE2 | 0x75 | 0xEB));
                if has_loop {
                    loops.push(DecryptionLoop::new(i, UnpackAlgo::Add, 78).with_body_size(24));
                }
            }
        }

        // Pattern 4: ROL [mem], imm8  (C0 C0..C7 xx) near loop boundary
        if data[i] == 0xC0 && i + 3 < len {
            let modrm = data[i + 1];
            if (modrm & 0b1100_0000) == 0b1100_0000 && (modrm & 0b0011_1000) == 0 {
                let window_end = (i + 20).min(len);
                let has_loop = data[i..window_end]
                    .iter()
                    .any(|&b| matches!(b, 0xE2 | 0x75 | 0xEB));
                if has_loop {
                    loops.push(DecryptionLoop::new(i, UnpackAlgo::Rol, 75).with_body_size(20));
                }
            }
        }

        // Pattern 5: RC4 PRGA characteristic — XCHG  86 C4..C7 or 87 ..
        if (data[i] == 0x86 || data[i] == 0x87) && i + 8 < len {
            // Look for nearby XOR after XCHG.
            let window_end = (i + 12).min(len);
            let has_xor = data[i..window_end]
                .iter()
                .any(|&b| matches!(b, 0x30 | 0x32 | 0x33));
            if has_xor {
                loops.push(DecryptionLoop::new(i, UnpackAlgo::Rc4, 70).with_body_size(12));
            }
        }
    }
    loops
}

// ─────────────────────────────────────────────────────────────────────────────
// KeyExtraction
// ─────────────────────────────────────────────────────────────────────────────

/// The result of key extraction from a decryption loop.
#[derive(Debug, Clone)]
pub struct KeyExtraction {
    /// The recovered key bytes.
    pub key_bytes: Vec<u8>,
    /// Where the key was found.
    pub source: KeySource,
    /// Algorithm associated with this key.
    pub algorithm: UnpackAlgo,
    /// Confidence (0–100).
    pub confidence: u8,
}

/// Source from which a key was extracted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// Key is a compile-time immediate in the loop.
    Immediate,
    /// Key is loaded from a nearby memory location.
    Memory(u64),
    /// Key is pushed onto the stack before the loop.
    Stack,
    /// Key is in a register at loop entry.
    Register,
    /// Could not determine the source.
    Unknown,
}

impl KeyExtraction {
    /// Create a key extracted from an immediate.
    #[must_use]
    pub const fn from_immediate(key: Vec<u8>, algo: UnpackAlgo) -> Self {
        Self {
            key_bytes: key,
            source: KeySource::Immediate,
            algorithm: algo,
            confidence: 90,
        }
    }

    /// Create a key from a memory source.
    #[must_use]
    pub const fn from_memory(key: Vec<u8>, addr: u64, algo: UnpackAlgo) -> Self {
        Self {
            key_bytes: key,
            source: KeySource::Memory(addr),
            algorithm: algo,
            confidence: 75,
        }
    }

    /// Return the key as a single u8 (or 0 if empty).
    #[must_use]
    pub fn single_byte_key(&self) -> u8 {
        self.key_bytes.first().copied().unwrap_or(0)
    }
}

/// Attempt to extract key material from raw bytes near a decryption loop.
///
/// Strategy:
/// 1. If the loop uses an immediate XOR/ADD — read the immediate byte.
/// 2. If a `MOV reg, imm8/imm32` appears within 32 bytes before the loop — use that.
/// 3. Fall back to a 4-byte brute-force score over the first 256 bytes.
#[must_use]
pub fn extract_key(data: &[u8], loop_offset: usize, algo: UnpackAlgo) -> Option<KeyExtraction> {
    // Strategy 1: immediate at loop_offset+2 (for patterns like `80 3x key`)
    if loop_offset + 3 < data.len() && data[loop_offset] == 0x80 {
        let key = vec![data[loop_offset + 2]];
        return Some(KeyExtraction::from_immediate(key, algo));
    }

    // Strategy 2: scan backwards for `MOV reg, imm8` (B0..B7 xx) or `MOV reg, imm32` (B8..BF xx xx xx xx)
    let scan_start = loop_offset.saturating_sub(32);
    for i in scan_start..loop_offset {
        let b = data[i];
        // MOV reg8, imm8: B0..B7
        if (0xB0..=0xB7).contains(&b) && i + 1 < data.len() {
            let key = vec![data[i + 1]];
            return Some(KeyExtraction::from_immediate(key, algo));
        }
        // MOV reg32, imm32: B8..BF
        if (0xB8..=0xBF).contains(&b) && i + 4 < data.len() {
            let key = data[i + 1..i + 5].to_vec();
            return Some(KeyExtraction::from_immediate(key, algo));
        }
        // PUSH imm8: 6A xx
        if b == 0x6A && i + 1 < data.len() {
            let key = vec![data[i + 1]];
            return Some(KeyExtraction {
                key_bytes: key,
                source: KeySource::Stack,
                algorithm: algo,
                confidence: 70,
            });
        }
    }

    // Strategy 3: brute-force single-byte XOR key over first 64 bytes
    if algo == UnpackAlgo::Xor && data.len() >= 64 {
        let sample = &data[..64];
        let (best_key, _score) = find_best_xor_key(sample);
        return Some(KeyExtraction::from_immediate(vec![best_key], algo));
    }

    None
}

/// Find the XOR key that maximises printable-ASCII coverage over `data`.
fn find_best_xor_key(data: &[u8]) -> (u8, usize) {
    let mut best_key = 0u8;
    let mut best_score = 0usize;
    for key in 0u8..=255 {
        let score = data
            .iter()
            .filter(|&&b| (b ^ key).is_ascii_graphic() || (b ^ key) == b' ')
            .count();
        if score > best_score {
            best_score = score;
            best_key = key;
        }
    }
    (best_key, best_score)
}

// ─────────────────────────────────────────────────────────────────────────────
// UnpackedRegion
// ─────────────────────────────────────────────────────────────────────────────

/// A memory region after decryption / unpacking.
#[derive(Debug, Clone)]
pub struct UnpackedRegion {
    /// File offset of the original (encrypted) region.
    pub offset: usize,
    /// Decrypted bytes.
    pub decrypted: Vec<u8>,
    /// The algorithm that was applied.
    pub algorithm: UnpackAlgo,
    /// Key bytes used.
    pub key: Vec<u8>,
    /// Confidence that the decryption is correct (0–100).
    pub confidence: u8,
    /// Entropy of the decrypted bytes (bits/byte × 100).
    pub decrypted_entropy: u32,
}

impl UnpackedRegion {
    /// Create a new unpacked region.
    #[must_use]
    pub fn new(offset: usize, decrypted: Vec<u8>, algorithm: UnpackAlgo, key: Vec<u8>) -> Self {
        let entropy = compute_entropy_100(&decrypted);
        Self {
            offset,
            decrypted,
            algorithm,
            key,
            confidence: 70,
            decrypted_entropy: entropy,
        }
    }

    /// Return `true` if the region looks like valid x86 code (starts with common prologues).
    #[must_use]
    pub fn looks_like_code(&self) -> bool {
        if self.decrypted.len() < 4 {
            return false;
        }
        let b = self.decrypted[0];
        // Common prologue bytes: PUSH EBP, PUSH RBP (55), MOV EDI EDI (8B FF),
        // SUB ESP (83 EC), INT3 (CC), NOP (90)
        matches!(b, 0x55 | 0x8B | 0x83 | 0x48 | 0x90 | 0xCC | 0x56 | 0x57)
    }

    /// Return `true` when entropy is low enough to suggest successful decryption (< 700 = 7.0 bits).
    #[must_use]
    pub const fn has_low_entropy(&self) -> bool {
        self.decrypted_entropy < 700
    }
}

/// Compute Shannon entropy × 100 using integer log2 (floor approximation).
///
/// Returns a value in `[0, 800]` (since max entropy = 8 bits/byte = 800/100).
/// Uses only integer arithmetic to avoid float-to-integer cast lints.
fn compute_entropy_100(data: &[u8]) -> u32 {
    if data.is_empty() {
        return 0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[usize::from(b)] += 1;
    }
    let n = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let log2_n = n.ilog2(); // floor(log2(n)); n ≥ 1 since data is non-empty
    // H_approx × n = Σ c × (floor(log2(n)) − floor(log2(c)))
    // H_approx × 100 ≈ (Σ c × (log2_n − log2_c)) × 100 / n
    let sum: u64 = freq
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let log2_c = c.ilog2();
            // log2_n ≥ log2_c since c ≤ n
            u64::from(c) * u64::from(log2_n.saturating_sub(log2_c))
        })
        .sum();
    // sum × 100 / n ∈ [0, 800]; both operands are integers → no float cast.
    u32::try_from((sum * 100) / u64::from(n)).unwrap_or(800)
}

// ─────────────────────────────────────────────────────────────────────────────
// UnpackingSession
// ─────────────────────────────────────────────────────────────────────────────

/// Context for a single unpacking layer.
#[derive(Debug, Clone)]
pub struct UnpackingSession {
    /// Layer index (0 = first / outermost layer).
    pub layer: usize,
    /// The data being analysed in this session.
    pub data: Vec<u8>,
    /// Decryption loops detected in this layer.
    pub loops: Vec<DecryptionLoop>,
    /// Key extracted for this layer.
    pub key: Option<KeyExtraction>,
    /// Unpacked regions produced.
    pub regions: Vec<UnpackedRegion>,
    /// Whether the session completed successfully.
    pub success: bool,
}

impl UnpackingSession {
    /// Create a session for layer `layer` with `data`.
    #[must_use]
    pub const fn new(layer: usize, data: Vec<u8>) -> Self {
        Self {
            layer,
            data,
            loops: Vec::new(),
            key: None,
            regions: Vec::new(),
            success: false,
        }
    }

    /// Run detection and decryption for this layer.
    pub fn run(&mut self) {
        self.loops = detect_decryption_loops(&self.data);

        if self.loops.is_empty() {
            return;
        }

        let first_loop = &self.loops[0];
        let algo = first_loop.algorithm;
        let offset = first_loop.offset;

        self.key = extract_key(&self.data, offset, algo);

        if let Some(ref key_info) = self.key {
            let decrypted = apply_decryption(&self.data, &key_info.key_bytes, algo);
            let region = UnpackedRegion::new(0, decrypted, algo, key_info.key_bytes.clone());
            self.success = region.has_low_entropy() || region.looks_like_code();
            self.regions.push(region);
        }
    }

    /// Return the best unpacked region (lowest entropy).
    #[must_use]
    pub fn best_region(&self) -> Option<&UnpackedRegion> {
        self.regions.iter().min_by_key(|r| r.decrypted_entropy)
    }
}

/// Apply a decryption algorithm to `data` with `key`.
#[must_use]
pub fn apply_decryption(data: &[u8], key: &[u8], algo: UnpackAlgo) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    match algo {
        UnpackAlgo::Xor => {
            let k = key[0];
            data.iter().map(|&b| b ^ k).collect()
        }
        UnpackAlgo::Add => {
            let k = key[0];
            data.iter().map(|&b| b.wrapping_sub(k)).collect()
        }
        UnpackAlgo::Sub => {
            let k = key[0];
            data.iter().map(|&b| b.wrapping_add(k)).collect()
        }
        UnpackAlgo::Rol => {
            let k = key[0] & 7;
            data.iter().map(|&b| b.rotate_left(u32::from(k))).collect()
        }
        UnpackAlgo::Ror => {
            let k = key[0] & 7;
            data.iter().map(|&b| b.rotate_right(u32::from(k))).collect()
        }
        UnpackAlgo::XorRolling => {
            // Rolling XOR whose key update is symmetric in the input and
            // output byte — this makes the transformation its own inverse so
            // the same routine encrypts and decrypts.
            let mut k = key[0];
            data.iter()
                .map(|&b| {
                    let out = b ^ k;
                    k = b.wrapping_add(out);
                    out
                })
                .collect()
        }
        UnpackAlgo::XorCyclic => data
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect(),
        UnpackAlgo::Rc4 => rc4_decrypt(data, key),
        UnpackAlgo::Unknown => data.to_vec(),
    }
}

fn rc4_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j: u8 = 0;
    for i in 0..256u16 {
        let k = key[(i as usize) % key.len()];
        j = j.wrapping_add(s[i as usize]).wrapping_add(k);
        s.swap(i as usize, j as usize);
    }
    let mut i: u8 = 0;
    let mut j: u8 = 0;
    data.iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            let k = s[s[i as usize].wrapping_add(s[j as usize]) as usize];
            b ^ k
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// UnpackingReport
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of a single-layer unpack.
#[derive(Debug, Clone, Default)]
pub struct UnpackingReport {
    /// Layer index.
    pub layer: usize,
    /// Whether this layer succeeded.
    pub success: bool,
    /// Algorithm detected.
    pub algorithm: String,
    /// Key bytes (hex).
    pub key_hex: String,
    /// Number of regions decrypted.
    pub region_count: usize,
    /// Size of the unpacked data.
    pub unpacked_size: usize,
    /// Entropy of the unpacked data × 100.
    pub entropy_100: u32,
}

impl UnpackingReport {
    /// Build a report from a completed session.
    #[must_use]
    pub fn from_session(session: &UnpackingSession) -> Self {
        let algo = session
            .key
            .as_ref().map_or_else(|| "unknown".to_owned(), |k| k.algorithm.label().to_owned());
        let key_hex = session
            .key
            .as_ref()
            .map(|k| {
                k.key_bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let (unpacked_size, entropy_100) = session
            .best_region()
            .map_or((0, 0), |r| (r.decrypted.len(), r.decrypted_entropy));
        Self {
            layer: session.layer,
            success: session.success,
            algorithm: algo,
            key_hex,
            region_count: session.regions.len(),
            unpacked_size,
            entropy_100,
        }
    }

    /// One-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Layer {} | algo={} key={} size={} entropy={:.2} {}",
            self.layer,
            self.algorithm,
            self.key_hex,
            self.unpacked_size,
            f64::from(self.entropy_100) / 100.0,
            if self.success { "OK" } else { "FAIL" },
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MultiLayerUnpacker
// ─────────────────────────────────────────────────────────────────────────────

/// Drives iterative unpacking until:
/// * No decryption loops are found in the current layer.
/// * The unpacked data is identical to the input (idempotent).
/// * The maximum layer count is reached.
#[derive(Debug, Clone)]
pub struct MultiLayerUnpacker {
    /// Maximum number of layers to attempt (default 8).
    pub max_layers: usize,
    /// Minimum size reduction ratio per layer (default 0.0 — no requirement).
    pub min_reduction: f32,
}

impl Default for MultiLayerUnpacker {
    fn default() -> Self {
        Self {
            max_layers: 8,
            min_reduction: 0.0,
        }
    }
}

impl MultiLayerUnpacker {
    /// Create a multi-layer unpacker with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of layers.
    #[must_use]
    pub const fn with_max_layers(mut self, n: usize) -> Self {
        self.max_layers = n;
        self
    }

    /// Unpack `data`, returning `(sessions, reports)`.
    #[must_use]
    pub fn unpack(&self, data: Vec<u8>) -> (Vec<UnpackingSession>, Vec<UnpackingReport>) {
        let mut current = data;
        let mut sessions: Vec<UnpackingSession> = Vec::with_capacity(self.max_layers);
        let mut reports: Vec<UnpackingReport> = Vec::with_capacity(self.max_layers);

        for layer in 0..self.max_layers {
            let mut session = UnpackingSession::new(layer, current.clone());
            session.run();

            let success = session.success;
            let report = UnpackingReport::from_session(&session);

            // Get next data.
            let next = session
                .best_region().map_or_else(|| current.clone(), |r| r.decrypted.clone());

            reports.push(report);
            sessions.push(session);

            // Convergence: next data == current or no success.
            if !success || next == current {
                break;
            }
            current = next;
        }

        (sessions, reports)
    }

    /// Return the final unpacked bytes from a multi-layer run.
    #[must_use]
    pub fn final_payload(sessions: &[UnpackingSession]) -> Option<&[u8]> {
        // Walk sessions in reverse; return the last successful region.
        for s in sessions.iter().rev() {
            if s.success && let Some(r) = s.best_region() {
                return Some(&r.decrypted);
            }
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DecryptionKeyDatabase — collection of known / recovered keys
// ─────────────────────────────────────────────────────────────────────────────

/// A single key record.
#[derive(Debug, Clone)]
pub struct KeyRecord {
    /// The key bytes.
    pub key: Vec<u8>,
    /// The algorithm this key was used with.
    pub algo: UnpackAlgo,
    /// File offset where the key was found or used.
    pub found_at: usize,
    /// Confidence that this is the correct key (0–100).
    pub confidence: u8,
}

impl KeyRecord {
    /// Create a new record.
    #[must_use]
    pub fn new(key: Vec<u8>, algo: UnpackAlgo, found_at: usize, confidence: u8) -> Self {
        Self {
            key,
            algo,
            found_at,
            confidence: confidence.min(100),
        }
    }

    /// Return a hex string representation of the key.
    #[must_use]
    pub fn hex(&self) -> String {
        self.key.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    /// Return `true` if confidence is high (≥ 80).
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 80
    }
}

/// A database of keys recovered or attempted during unpacking.
#[derive(Debug, Clone, Default)]
pub struct DecryptionKeyDatabase {
    /// All key records.
    pub records: Vec<KeyRecord>,
}

impl DecryptionKeyDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a record.
    pub fn insert(&mut self, record: KeyRecord) {
        self.records.push(record);
    }

    /// Return all high-confidence records.
    #[must_use]
    pub fn high_confidence(&self) -> Vec<&KeyRecord> {
        self.records
            .iter()
            .filter(|r| r.is_high_confidence())
            .collect()
    }

    /// Find records for a given algorithm.
    #[must_use]
    pub fn by_algo(&self, algo: UnpackAlgo) -> Vec<&KeyRecord> {
        self.records.iter().filter(|r| r.algo == algo).collect()
    }

    /// Number of records.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Return `true` when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Return the record with the highest confidence.
    #[must_use]
    pub fn best(&self) -> Option<&KeyRecord> {
        self.records.iter().max_by_key(|r| r.confidence)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PackedRegionDetector — identifies candidate packed regions by entropy
// ─────────────────────────────────────────────────────────────────────────────

/// Scan `data` with a sliding window and identify regions whose entropy exceeds
/// `threshold_100` (entropy × 100, e.g. 700 = 7.0 bits/byte).
#[derive(Debug, Clone)]
pub struct PackedRegionDetector {
    /// Window size in bytes (default 256).
    pub window: usize,
    /// Step between windows (default 64).
    pub step: usize,
    /// Entropy threshold × 100 (default 680).
    pub threshold_100: u32,
    /// Minimum run of consecutive above-threshold windows (default 2).
    pub min_run: usize,
}

impl Default for PackedRegionDetector {
    fn default() -> Self {
        Self {
            window: 256,
            step: 64,
            threshold_100: 680,
            min_run: 2,
        }
    }
}

/// A candidate packed region.
#[derive(Debug, Clone)]
pub struct PackedCandidate {
    /// Start offset in the input buffer.
    pub start: usize,
    /// End offset (exclusive).
    pub end: usize,
    /// Peak entropy × 100 within the region.
    pub peak_entropy_100: u32,
}

impl PackedRegionDetector {
    /// Create a detector with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan `data` for packed regions.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Vec<PackedCandidate> {
        let mut candidates = Vec::new();
        if data.len() < self.window {
            return candidates;
        }

        let mut run_start: Option<usize> = None;
        let mut run_len = 0usize;
        let mut peak: u32 = 0;

        let mut pos = 0;
        while pos + self.window <= data.len() {
            let e = compute_entropy_100(&data[pos..pos + self.window]);
            if e >= self.threshold_100 {
                if run_start.is_none() {
                    run_start = Some(pos);
                }
                run_len += 1;
                peak = peak.max(e);
            } else if let Some(start) = run_start {
                if run_len >= self.min_run {
                    candidates.push(PackedCandidate {
                        start,
                        end: pos + self.window,
                        peak_entropy_100: peak,
                    });
                }
                run_start = None;
                run_len = 0;
                peak = 0;
            }
            pos += self.step;
        }

        // Flush trailing run.
        if let Some(start) = run_start && run_len >= self.min_run {
            candidates.push(PackedCandidate {
                start,
                end: data.len(),
                peak_entropy_100: peak,
            });
        }

        candidates
    }

    /// Return `true` if any packed region is detected.
    #[must_use]
    pub fn is_packed(&self, data: &[u8]) -> bool {
        !self.detect(data).is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UnpackerEngine
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level orchestrator that combines decryption-loop detection, key
/// extraction, single-layer unpacking, and multi-layer iteration.
#[derive(Debug, Clone, Default)]
pub struct UnpackerEngine {
    /// Strategy configuration.
    pub config: UnpackerConfig,
}

/// Configuration for the unpacker engine.
#[derive(Debug, Clone)]
pub struct UnpackerConfig {
    /// Maximum layers (forwarded to [`MultiLayerUnpacker`]).
    pub max_layers: usize,
    /// Whether to attempt brute-force key recovery when heuristics fail.
    pub brute_force_fallback: bool,
    /// Entropy threshold above which a region is considered still packed
    /// (default 700 = 7.0 bits/byte).
    pub packed_entropy_threshold: u32,
}

impl Default for UnpackerConfig {
    fn default() -> Self {
        Self {
            max_layers: 8,
            brute_force_fallback: true,
            packed_entropy_threshold: 700,
        }
    }
}

impl UnpackerEngine {
    /// Create an engine with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an engine with custom configuration.
    #[must_use]
    pub const fn with_config(config: UnpackerConfig) -> Self {
        Self { config }
    }

    /// Run the full unpacking pipeline on `data`.
    ///
    /// Returns a vector of per-layer reports.
    #[must_use]
    pub fn run(&self, data: Vec<u8>) -> Vec<UnpackingReport> {
        let unpacker = MultiLayerUnpacker::new().with_max_layers(self.config.max_layers);
        let (_, reports) = unpacker.unpack(data);
        reports
    }

    /// Quick check: does `data` appear to contain a decryption loop?
    #[must_use]
    pub fn has_decryption_loop(&self, data: &[u8]) -> bool {
        !detect_decryption_loops(data).is_empty()
    }

    /// Return a summary of all detected algorithms across layers.
    #[must_use]
    pub fn algorithm_summary(reports: &[UnpackingReport]) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for r in reports {
            *counts.entry(r.algorithm.clone()).or_insert(0) += 1;
        }
        counts
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── UnpackAlgo ────────────────────────────────────────────────────────────

    #[test]
    fn test_algo_label() {
        assert_eq!(UnpackAlgo::Xor.label(), "xor");
        assert_eq!(UnpackAlgo::Rc4.label(), "rc4");
        assert_eq!(UnpackAlgo::Unknown.label(), "unknown");
    }

    #[test]
    fn test_algo_is_stream() {
        assert!(UnpackAlgo::Rc4.is_stream());
        assert!(UnpackAlgo::XorCyclic.is_stream());
        assert!(!UnpackAlgo::Xor.is_stream());
        assert!(!UnpackAlgo::Add.is_stream());
    }

    // ── apply_decryption ──────────────────────────────────────────────────────

    #[test]
    fn test_xor_roundtrip() {
        let data = vec![0xAA, 0xBB, 0xCC];
        let key = vec![0x42];
        let enc = apply_decryption(&data, &key, UnpackAlgo::Xor);
        let dec = apply_decryption(&enc, &key, UnpackAlgo::Xor);
        assert_eq!(dec, data);
    }

    #[test]
    fn test_add_roundtrip() {
        let data = vec![0x01, 0x02, 0x03];
        let key = vec![0x10];
        let enc = apply_decryption(&data, &key, UnpackAlgo::Add);
        // ADD encrypts by subtracting; decryption adds back.
        let dec = apply_decryption(&enc, &key, UnpackAlgo::Sub);
        assert_eq!(dec, data);
    }

    #[test]
    fn test_xor_cyclic() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let key = vec![0xAA, 0xBB];
        let enc = apply_decryption(&data, &key, UnpackAlgo::XorCyclic);
        let dec = apply_decryption(&enc, &key, UnpackAlgo::XorCyclic);
        assert_eq!(dec, data);
    }

    #[test]
    fn test_xor_rolling() {
        let plain = vec![b'H', b'e', b'l', b'l', b'o'];
        let key = vec![0x42];
        // Encrypt with XOR-rolling, then decrypt.
        let enc = apply_decryption(&plain, &key, UnpackAlgo::XorRolling);
        let dec = apply_decryption(&enc, &key, UnpackAlgo::XorRolling);
        assert_eq!(dec, plain);
    }

    #[test]
    fn test_rc4_roundtrip() {
        let data = b"Hello, RC4!".to_vec();
        let key = b"secretkey".to_vec();
        let enc = apply_decryption(&data, &key, UnpackAlgo::Rc4);
        let dec = apply_decryption(&enc, &key, UnpackAlgo::Rc4);
        assert_eq!(dec, data);
    }

    #[test]
    fn test_empty_key_identity() {
        let data = vec![1, 2, 3];
        assert_eq!(apply_decryption(&data, &[], UnpackAlgo::Xor), data);
    }

    // ── DecryptionLoop ────────────────────────────────────────────────────────

    #[test]
    fn test_decryption_loop_new() {
        let l = DecryptionLoop::new(0x100, UnpackAlgo::Xor, 90);
        assert_eq!(l.algorithm, UnpackAlgo::Xor);
        assert_eq!(l.confidence, 90);
    }

    #[test]
    fn test_decryption_loop_builders() {
        let l = DecryptionLoop::new(0, UnpackAlgo::Add, 80)
            .with_stride(4)
            .with_body_size(32)
            .with_key_update();
        assert_eq!(l.stride, 4);
        assert_eq!(l.body_size, 32);
        assert!(l.updates_key);
    }

    #[test]
    fn test_detect_loops_xor_pattern() {
        // 30 05 (XOR [addr], al) followed by 75 xx (JNZ)
        let code = [
            0x90u8, 0x30, 0x05, 0x00, 0x10, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x75,
            0xF0, 0x90,
        ];
        let loops = detect_decryption_loops(&code);
        assert!(!loops.is_empty(), "should detect XOR loop");
        assert!(loops.iter().any(|l| l.algorithm == UnpackAlgo::Xor));
    }

    #[test]
    fn test_detect_loops_empty() {
        let loops = detect_decryption_loops(&[0x90; 8]);
        // NOP sled — no decryption pattern.
        assert!(loops.is_empty());
    }

    // ── KeyExtraction ─────────────────────────────────────────────────────────

    #[test]
    fn test_key_extraction_from_immediate() {
        let ke = KeyExtraction::from_immediate(vec![0x42], UnpackAlgo::Xor);
        assert_eq!(ke.single_byte_key(), 0x42);
        assert_eq!(ke.source, KeySource::Immediate);
    }

    #[test]
    fn test_key_extraction_from_memory() {
        let ke = KeyExtraction::from_memory(vec![0xAA], 0x1000, UnpackAlgo::Xor);
        assert_eq!(ke.source, KeySource::Memory(0x1000));
    }

    #[test]
    fn test_extract_key_from_immediate_at_loop() {
        // 80 31 0x42 (XOR [ecx], 0x42) followed by 75 xx
        let code = [
            0x80u8, 0x31, 0x42, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x75, 0xF0,
        ];
        let key = extract_key(&code, 0, UnpackAlgo::Xor);
        assert!(key.is_some());
        assert_eq!(key.unwrap().single_byte_key(), 0x42);
    }

    #[test]
    fn test_extract_key_from_mov_reg() {
        // B0 0xAB (MOV AL, 0xAB) at offset 0, loop at offset 3
        let code = [0xB0u8, 0xAB, 0x90, 0x80, 0x31, 0xAB, 0x75, 0xF0];
        let key = extract_key(&code, 3, UnpackAlgo::Xor);
        assert!(key.is_some());
        assert_eq!(key.unwrap().single_byte_key(), 0xAB);
    }

    // ── UnpackedRegion ────────────────────────────────────────────────────────

    #[test]
    fn test_unpacked_region_new() {
        let dec = vec![0x55, 0x8B, 0xEC, 0x90]; // common prologue bytes
        let r = UnpackedRegion::new(0, dec, UnpackAlgo::Xor, vec![0x42]);
        assert!(r.looks_like_code());
    }

    #[test]
    fn test_unpacked_region_entropy() {
        // Low entropy: all zeros
        let r = UnpackedRegion::new(0, vec![0u8; 64], UnpackAlgo::Xor, vec![]);
        assert!(r.has_low_entropy());
    }

    #[test]
    fn test_unpacked_region_high_entropy() {
        // High entropy: varied bytes simulating still-packed data
        let data: Vec<u8> = (0u8..=255u8).collect();
        let r = UnpackedRegion::new(0, data, UnpackAlgo::Xor, vec![]);
        assert!(!r.has_low_entropy());
    }

    // ── UnpackingSession ──────────────────────────────────────────────────────

    #[test]
    fn test_unpacking_session_run_no_loops() {
        let data = vec![0x55, 0x8B, 0xEC, 0x90, 0xC3];
        let mut session = UnpackingSession::new(0, data);
        session.run();
        assert!(session.loops.is_empty());
        assert!(!session.success);
    }

    #[test]
    fn test_unpacking_session_new() {
        let session = UnpackingSession::new(1, vec![0x90; 32]);
        assert_eq!(session.layer, 1);
        assert_eq!(session.data.len(), 32);
        assert!(!session.success);
    }

    // ── UnpackingReport ───────────────────────────────────────────────────────

    #[test]
    fn test_report_from_session() {
        let session = UnpackingSession::new(0, vec![]);
        let report = UnpackingReport::from_session(&session);
        assert_eq!(report.layer, 0);
        assert!(!report.success);
    }

    #[test]
    fn test_report_summary_format() {
        let r = UnpackingReport {
            layer: 2,
            algorithm: "xor".into(),
            success: true,
            ..UnpackingReport::default()
        };
        let s = r.summary();
        assert!(s.contains("Layer 2"));
        assert!(s.contains("xor"));
        assert!(s.contains("OK"));
    }

    // ── MultiLayerUnpacker ────────────────────────────────────────────────────

    #[test]
    fn test_multilayer_no_loops_converges_immediately() {
        let unpacker = MultiLayerUnpacker::new();
        let data = vec![0x55, 0x8B, 0xEC, 0xC3]; // clean code
        let (sessions, reports) = unpacker.unpack(data);
        // Should stop at layer 0 with no success.
        assert!(!sessions.is_empty());
        assert!(!reports.is_empty());
    }

    #[test]
    fn test_multilayer_max_layers_setting() {
        let unpacker = MultiLayerUnpacker::new().with_max_layers(3);
        assert_eq!(unpacker.max_layers, 3);
    }

    #[test]
    fn test_multilayer_final_payload_no_success() {
        let unpacker = MultiLayerUnpacker::new();
        let data = vec![0x90; 8];
        let (sessions, _) = unpacker.unpack(data);
        // No success → final_payload returns None.
        assert!(MultiLayerUnpacker::final_payload(&sessions).is_none());
    }

    // ── UnpackerEngine ────────────────────────────────────────────────────────

    #[test]
    fn test_engine_run_clean_data() {
        let engine = UnpackerEngine::new();
        let reports = engine.run(vec![0x55, 0x8B, 0xEC]);
        assert!(!reports.is_empty());
    }

    #[test]
    fn test_engine_has_decryption_loop_false() {
        let engine = UnpackerEngine::new();
        assert!(!engine.has_decryption_loop(&[0x90; 16]));
    }

    #[test]
    fn test_engine_algorithm_summary() {
        let reports = vec![
            UnpackingReport {
                algorithm: "xor".into(),
                ..Default::default()
            },
            UnpackingReport {
                algorithm: "xor".into(),
                ..Default::default()
            },
            UnpackingReport {
                algorithm: "rc4".into(),
                ..Default::default()
            },
        ];
        let summary = UnpackerEngine::algorithm_summary(&reports);
        assert_eq!(*summary.get("xor").unwrap(), 2);
        assert_eq!(*summary.get("rc4").unwrap(), 1);
    }

    // ── Additional coverage tests ─────────────────────────────────────────────

    #[test]
    fn test_algo_rol_roundtrip() {
        let data = vec![0xAA, 0xBB, 0xCC];
        let key = vec![0x03];
        let enc = apply_decryption(&data, &key, UnpackAlgo::Rol);
        let dec = apply_decryption(&enc, &key, UnpackAlgo::Ror);
        assert_eq!(dec, data);
    }

    #[test]
    fn test_algo_ror_roundtrip() {
        let data = vec![0x12, 0x34, 0x56];
        let key = vec![0x02];
        let enc = apply_decryption(&data, &key, UnpackAlgo::Ror);
        let dec = apply_decryption(&enc, &key, UnpackAlgo::Rol);
        assert_eq!(dec, data);
    }

    #[test]
    fn test_algo_unknown_identity() {
        let data = vec![1, 2, 3];
        assert_eq!(apply_decryption(&data, &[0x42], UnpackAlgo::Unknown), data);
    }

    #[test]
    fn test_unpacked_region_empty() {
        let r = UnpackedRegion::new(0, vec![], UnpackAlgo::Xor, vec![]);
        assert!(!r.looks_like_code());
        assert!(r.has_low_entropy());
    }

    #[test]
    fn test_key_source_variants() {
        let _ = KeySource::Immediate;
        let _ = KeySource::Memory(0x1000);
        let _ = KeySource::Stack;
        let _ = KeySource::Register;
        let _ = KeySource::Unknown;
    }

    #[test]
    fn test_decryption_loop_confidence_clamped() {
        let l = DecryptionLoop::new(0, UnpackAlgo::Xor, 200);
        assert_eq!(l.confidence, 100);
    }

    #[test]
    fn test_unpacker_config_defaults() {
        let c = UnpackerConfig::default();
        assert_eq!(c.max_layers, 8);
        assert!(c.brute_force_fallback);
        assert_eq!(c.packed_entropy_threshold, 700);
    }

    #[test]
    fn test_unpacking_report_default() {
        let r = UnpackingReport::default();
        assert!(!r.success);
        assert_eq!(r.layer, 0);
    }

    #[test]
    fn test_detect_loops_rc4_xchg() {
        // XCHG EAX, ESP (86 C4) followed by XOR (33)
        let code = [
            0x86u8, 0xC4, 0x33, 0xC0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ];
        let loops = detect_decryption_loops(&code);
        assert!(loops.iter().any(|l| l.algorithm == UnpackAlgo::Rc4));
    }

    #[test]
    fn test_xor_key_zero_identity() {
        let data = vec![0xAA, 0xBB];
        let result = apply_decryption(&data, &[0x00], UnpackAlgo::Xor);
        assert_eq!(result, data); // XOR with 0 is identity
    }

    #[test]
    fn test_multilayer_final_payload_with_success() {
        // Build a session that has a successful region.
        let mut session = UnpackingSession::new(0, vec![]);
        session.success = true;
        session.regions.push(UnpackedRegion::new(
            0,
            vec![0x55, 0x8B, 0xEC],
            UnpackAlgo::Xor,
            vec![],
        ));
        let sessions = [session];
        let payload = MultiLayerUnpacker::final_payload(&sessions);
        assert!(payload.is_some());
        assert_eq!(payload.unwrap(), &[0x55, 0x8B, 0xEC]);
    }

    #[test]
    fn test_engine_with_config() {
        let config = UnpackerConfig {
            max_layers: 2,
            brute_force_fallback: false,
            packed_entropy_threshold: 600,
        };
        let engine = UnpackerEngine::with_config(config);
        assert_eq!(engine.config.max_layers, 2);
        assert!(!engine.config.brute_force_fallback);
    }
}
