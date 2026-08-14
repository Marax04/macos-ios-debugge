//! Mutation engine — AFL/libFuzzer-style input mutation strategies.
//!
//! Provides:
//! - Primitive mutators: bit-flip, byte-flip, arithmetic, interesting values.
//! - Dictionary-guided mutations (user-supplied tokens).
//! - Structure-aware mutations for PNG, ZIP, XML, JSON, PE.
//! - A composable [`MutationEngine`] that chains strategies with weights.

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

// ─── PRNG ─────────────────────────────────────────────────────────────────────

/// A fast non-cryptographic PRNG (xorshift64).
#[derive(Debug, Clone)]
pub struct FastRng {
    state: u64,
}

impl FastRng {
    #[must_use] 
    pub const fn new(seed: u64) -> Self {
        Self { state: if seed == 0 { 0xdead_beef_cafe_babe } else { seed } }
    }

    pub const fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub const fn next_usize(&mut self, max: usize) -> usize {
        if max == 0 { return 0; }
        (self.next_u64() as usize) % max
    }

    pub const fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    pub const fn next_u32(&mut self) -> u32 {
        (self.next_u64()) as u32
    }

    pub const fn next_byte(&mut self) -> u8 {
        (self.next_u64()) as u8
    }
}

// ─── Interesting values ───────────────────────────────────────────────────────

const INTERESTING_U8: &[u8] = &[0, 1, 16, 32, 64, 100, 127, 128, 192, 254, 255];

const INTERESTING_U16: &[u16] = &[
    0, 1, 0x7f, 0x80, 0xff, 0x100, 0x7ffe, 0x7fff, 0x8000, 0x8001, 0xfffe, 0xffff,
];

const INTERESTING_U32: &[u32] = &[
    0, 1, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x10000,
    0x7fff_fffe, 0x7fff_ffff, 0x8000_0000, 0x8000_0001, 0xffff_fffe, 0xffff_ffff,
];

const INTERESTING_U64: &[u64] = &[
    0, 1, 0x7f, 0xff, 0xffff, 0xffff_ffff,
    0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000,
    0xffff_ffff_ffff_fffe, 0xffff_ffff_ffff_ffff,
];

// ─── Mutation strategy enum ───────────────────────────────────────────────────

/// Identifies which mutation strategy produced a mutant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MutationKind {
    BitFlip { pos: usize, width: u8 },
    ByteFlip { pos: usize },
    ByteSet { pos: usize, value: u8 },
    ArithmeticAdd { pos: usize, delta: i32, width: u8 },
    InterestingByte { pos: usize },
    InterestingWord { pos: usize },
    InterestingDword { pos: usize },
    InterestingQword { pos: usize },
    ByteInsert { pos: usize },
    ByteDelete { pos: usize, count: usize },
    ChunkCopy { src: usize, dst: usize, len: usize },
    ChunkDelete { pos: usize, len: usize },
    DictionaryInsert { pos: usize, token_idx: usize },
    DictionaryReplace { pos: usize, len: usize, token_idx: usize },
    FormatSpecific(String),
    Splice { other_hash: u64, split: usize },
}

// ─── Mutation result ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MutationResult {
    pub data: Vec<u8>,
    pub kind: MutationKind,
    pub original_len: usize,
}

// ─── Dictionary ───────────────────────────────────────────────────────────────

/// A dictionary of tokens to use for guided mutation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Dictionary {
    pub tokens: Vec<Vec<u8>>,
    pub source: String,
}

impl Dictionary {
    pub fn new(source: impl Into<String>) -> Self {
        Self { tokens: Vec::new(), source: source.into() }
    }

    pub fn add_str(&mut self, s: &str) {
        self.tokens.push(s.as_bytes().to_vec());
    }

    pub fn add_bytes(&mut self, b: &[u8]) {
        self.tokens.push(b.to_vec());
    }

    /// Parse AFL-style dictionary file (one token per line, optional `=` prefix).
    #[must_use] 
    pub fn from_afl_format(text: &str) -> Self {
        let mut dict = Self::new("afl_dict");
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() { continue; }
            let token = line.split_once('=').map_or(line, |rest| rest.1);
            // Unescape common escape sequences
            let bytes = unescape_afl_token(token.trim_matches('"'));
            if !bytes.is_empty() { dict.tokens.push(bytes); }
        }
        dict
    }

    #[must_use] 
    pub const fn len(&self) -> usize { self.tokens.len() }
    #[must_use] 
    pub const fn is_empty(&self) -> bool { self.tokens.is_empty() }
}

fn unescape_afl_token(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'n' => { out.push(b'\n'); i += 2; }
                b't' => { out.push(b'\t'); i += 2; }
                b'r' => { out.push(b'\r'); i += 2; }
                b'\\' => { out.push(b'\\'); i += 2; }
                b'x' if i + 3 < bytes.len() => {
                    if let Ok(hex) = std::str::from_utf8(&bytes[i+2..i+4])
                        && let Ok(v) = u8::from_str_radix(hex, 16) {
                            out.push(v); i += 4; continue;
                        }
                    out.push(bytes[i]); i += 1;
                }
                other => { out.push(other); i += 2; }
            }
        } else {
            out.push(bytes[i]); i += 1;
        }
    }
    out
}

// ─── Core mutator ─────────────────────────────────────────────────────────────

/// Configuration for the mutation engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationConfig {
    pub max_output_len: usize,
    pub min_output_len: usize,
    pub max_mutations_per_round: usize,
    pub enable_structure_aware: bool,
    pub structure_hint: Option<FormatHint>,
}

impl Default for MutationConfig {
    fn default() -> Self {
        Self {
            max_output_len: 65536,
            min_output_len: 1,
            max_mutations_per_round: 8,
            enable_structure_aware: false,
            structure_hint: None,
        }
    }
}

/// A hint about the input format for structure-aware mutations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FormatHint {
    Png,
    Zip,
    Xml,
    Json,
    Pe,
    Elf,
    Generic,
}

impl FormatHint {
    /// Detect format from magic bytes.
    #[must_use] 
    pub fn detect(data: &[u8]) -> Self {
        if data.starts_with(b"\x89PNG\r\n\x1a\n") { return Self::Png; }
        if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") { return Self::Zip; }
        if data.starts_with(b"<?xml") || (data.len() > 1 && data[0] == b'<') { return Self::Xml; }
        if data.first() == Some(&b'{') || data.first() == Some(&b'[') { return Self::Json; }
        if data.starts_with(b"MZ") { return Self::Pe; }
        if data.starts_with(b"\x7fELF") { return Self::Elf; }
        Self::Generic
    }
}

/// The primary mutation engine.
pub struct MutationEngine {
    config: MutationConfig,
    dictionary: Dictionary,
    rng: FastRng,
    corpus_pool: Vec<Vec<u8>>,
}

impl MutationEngine {
    #[must_use] 
    pub fn new(config: MutationConfig, seed: u64) -> Self {
        Self { config, dictionary: Dictionary::default(), rng: FastRng::new(seed), corpus_pool: Vec::new() }
    }

    pub fn set_dictionary(&mut self, dict: Dictionary) {
        self.dictionary = dict;
    }

    pub fn add_corpus_entry(&mut self, data: Vec<u8>) {
        self.corpus_pool.push(data);
    }

    /// Apply one or more mutations to `input`, returning a new mutant.
    pub fn mutate(&mut self, input: &[u8]) -> MutationResult {
        if input.is_empty() {
            let data = vec![self.rng.next_byte()];
            return MutationResult { data, kind: MutationKind::ByteInsert { pos: 0 }, original_len: 0 };
        }

        let mut data = input.to_vec();
        let kind;

        // Try structure-aware first if hint set
        if self.config.enable_structure_aware {
            let hint = self.config.structure_hint.clone()
                .unwrap_or_else(|| FormatHint::detect(input));
            if let Some(result) = self.structure_mutate(&data, &hint) {
                return result;
            }
        }

        // Weighted random strategy selection
        let strategy = self.rng.next_usize(100);
        match strategy {
            0..=9 => {
                // Bit flip (1-bit)
                let pos = self.rng.next_usize(data.len());
                let bit = (self.rng.next_usize(8)) as u8;
                data[pos] ^= 1 << bit;
                kind = MutationKind::BitFlip { pos, width: 1 };
            }
            10..=19 => {
                // Byte flip
                let pos = self.rng.next_usize(data.len());
                data[pos] ^= 0xff;
                kind = MutationKind::ByteFlip { pos };
            }
            20..=27 => {
                // Byte set to interesting value
                let pos = self.rng.next_usize(data.len());
                let v = INTERESTING_U8[self.rng.next_usize(INTERESTING_U8.len())];
                data[pos] = v;
                kind = MutationKind::InterestingByte { pos };
            }
            28..=35 => {
                // 16-bit interesting value
                if data.len() >= 2 {
                    let pos = self.rng.next_usize(data.len() - 1);
                    let v = INTERESTING_U16[self.rng.next_usize(INTERESTING_U16.len())];
                    let bytes = if self.rng.next_bool() { v.to_le_bytes() } else { v.to_be_bytes() };
                    data[pos] = bytes[0];
                    data[pos + 1] = bytes[1];
                    kind = MutationKind::InterestingWord { pos };
                } else {
                    data[0] = 0xff;
                    kind = MutationKind::ByteSet { pos: 0, value: 0xff };
                }
            }
            36..=39 => {
                // 32-bit interesting value
                if data.len() >= 4 {
                    let pos = self.rng.next_usize(data.len() - 3);
                    let v = INTERESTING_U32[self.rng.next_usize(INTERESTING_U32.len())];
                    let bytes = if self.rng.next_bool() { v.to_le_bytes() } else { v.to_be_bytes() };
                    data[pos..pos + 4].copy_from_slice(&bytes);
                    kind = MutationKind::InterestingDword { pos };
                } else {
                    data[0] = 0x80;
                    kind = MutationKind::ByteSet { pos: 0, value: 0x80 };
                }
            }
            40..=43 => {
                // 64-bit interesting value (sentinel/overflow boundaries).
                if data.len() >= 8 {
                    let pos = self.rng.next_usize(data.len() - 7);
                    let v = INTERESTING_U64[self.rng.next_usize(INTERESTING_U64.len())];
                    let bytes = if self.rng.next_bool() { v.to_le_bytes() } else { v.to_be_bytes() };
                    data[pos..pos + 8].copy_from_slice(&bytes);
                    kind = MutationKind::InterestingQword { pos };
                } else if data.len() >= 4 {
                    let pos = self.rng.next_usize(data.len() - 3);
                    let v = INTERESTING_U32[self.rng.next_usize(INTERESTING_U32.len())];
                    data[pos..pos + 4].copy_from_slice(&v.to_le_bytes());
                    kind = MutationKind::InterestingDword { pos };
                } else {
                    data[0] = 0xff;
                    kind = MutationKind::ByteSet { pos: 0, value: 0xff };
                }
            }
            44..=51 => {
                // Arithmetic add/sub on a byte
                let pos = self.rng.next_usize(data.len());
                let delta = (self.rng.next_usize(35) as i32) - 17; // -17..+17
                data[pos] = data[pos].wrapping_add(delta as u8);
                kind = MutationKind::ArithmeticAdd { pos, delta, width: 8 };
            }
            52..=59 => {
                // Random byte insert
                if data.len() < self.config.max_output_len {
                    let pos = self.rng.next_usize(data.len() + 1);
                    data.insert(pos, self.rng.next_byte());
                    kind = MutationKind::ByteInsert { pos };
                } else {
                    let pos = self.rng.next_usize(data.len());
                    data[pos] = self.rng.next_byte();
                    kind = MutationKind::ByteSet { pos, value: data[pos] };
                }
            }
            60..=67 => {
                // Delete 1-4 bytes
                if data.len() > self.config.min_output_len + 4 {
                    let count = self.rng.next_usize(4) + 1;
                    let pos = self.rng.next_usize(data.len().saturating_sub(count));
                    data.drain(pos..pos + count.min(data.len() - pos));
                    kind = MutationKind::ByteDelete { pos, count };
                } else {
                    let pos = self.rng.next_usize(data.len());
                    data[pos] = 0;
                    kind = MutationKind::ByteSet { pos, value: 0 };
                }
            }
            68..=75 => {
                // Chunk copy (overwrites)
                if data.len() > 8 {
                    let src = self.rng.next_usize(data.len() / 2);
                    let dst = self.rng.next_usize(data.len() / 2) + data.len() / 2;
                    let len = self.rng.next_usize(8).min(data.len() - src).min(data.len() - dst);
                    if len > 0 {
                        let chunk: Vec<u8> = data[src..src + len].to_vec();
                        data[dst..dst + len].copy_from_slice(&chunk);
                        kind = MutationKind::ChunkCopy { src, dst, len };
                    } else {
                        kind = MutationKind::ByteFlip { pos: 0 };
                    }
                } else {
                    kind = MutationKind::ByteFlip { pos: 0 };
                    if !data.is_empty() { data[0] ^= 0xff; }
                }
            }
            76..=83 if !self.dictionary.is_empty() => {
                // Dictionary token insertion
                let tok_idx = self.rng.next_usize(self.dictionary.len());
                let token = self.dictionary.tokens[tok_idx].clone();
                let pos = self.rng.next_usize(data.len() + 1);
                if data.len() + token.len() <= self.config.max_output_len {
                    for (i, &b) in token.iter().enumerate() {
                        data.insert(pos + i, b);
                    }
                    kind = MutationKind::DictionaryInsert { pos, token_idx: tok_idx };
                } else {
                    kind = MutationKind::ByteFlip { pos: 0 };
                    if !data.is_empty() { data[0] ^= 1; }
                }
            }
            84..=90 if !self.corpus_pool.is_empty() => {
                // Splice with corpus entry
                let other_idx = self.rng.next_usize(self.corpus_pool.len());
                let other = self.corpus_pool[other_idx].clone();
                if other.is_empty() {
                    kind = MutationKind::ByteFlip { pos: 0 };
                    if !data.is_empty() { data[0] ^= 1; }
                } else {
                    let split = self.rng.next_usize(data.len().max(1));
                    let mut spliced = data[..split].to_vec();
                    let other_start = self.rng.next_usize(other.len());
                    spliced.extend_from_slice(&other[other_start..]);
                    spliced.truncate(self.config.max_output_len);
                    let hash = fnv1a_hash(&other);
                    data = spliced;
                    kind = MutationKind::Splice { other_hash: hash, split };
                }
            }
            _ => {
                // Random byte replacement
                let pos = self.rng.next_usize(data.len());
                let v = self.rng.next_byte();
                data[pos] = v;
                kind = MutationKind::ByteSet { pos, value: v };
            }
        }

        MutationResult { original_len: input.len(), data, kind }
    }

    /// Apply `n` mutations in sequence.
    pub fn mutate_n(&mut self, input: &[u8], n: usize) -> Vec<u8> {
        let mut data = input.to_vec();
        for _ in 0..n {
            let r = self.mutate(&data);
            data = r.data;
        }
        data
    }

    // ── Structure-aware mutations ─────────────────────────────────────────────

    fn structure_mutate(&mut self, data: &[u8], hint: &FormatHint) -> Option<MutationResult> {
        match hint {
            FormatHint::Png => self.mutate_png(data),
            FormatHint::Zip => self.mutate_zip(data),
            FormatHint::Json => Some(self.mutate_json(data)),
            FormatHint::Xml => Some(self.mutate_xml(data)),
            FormatHint::Pe => self.mutate_pe(data),
            _ => None,
        }
    }

    fn mutate_png(&mut self, data: &[u8]) -> Option<MutationResult> {
        if data.len() < 12 { return None; }
        // Flip a bit in the IHDR width or height field (bytes 16-23)
        if data.len() > 24 {
            let mut out = data.to_vec();
            let pos = 16 + self.rng.next_usize(8);
            out[pos] = out[pos].wrapping_add(self.rng.next_byte());
            return Some(MutationResult {
                data: out,
                kind: MutationKind::FormatSpecific("png_ihdr_field".into()),
                original_len: data.len(),
            });
        }
        None
    }

    fn mutate_zip(&mut self, data: &[u8]) -> Option<MutationResult> {
        if data.len() < 30 { return None; }
        // Corrupt the compressed size field in a local file header (bytes 18-21)
        let mut out = data.to_vec();
        let v = INTERESTING_U32[self.rng.next_usize(INTERESTING_U32.len())];
        let pos = 18.min(out.len() - 4);
        out[pos..pos + 4].copy_from_slice(&v.to_le_bytes());
        Some(MutationResult {
            data: out,
            kind: MutationKind::FormatSpecific("zip_compressed_size".into()),
            original_len: data.len(),
        })
    }

    fn mutate_json(&mut self, data: &[u8]) -> MutationResult {
        // Insert JSON-specific tokens
        let tokens: &[&[u8]] = &[b"null", b"true", b"false", b"0", b"-1", b"999999999", b"\"\"", b"[]", b"{}"];
        let tok = tokens[self.rng.next_usize(tokens.len())];
        let pos = self.rng.next_usize(data.len().max(1));
        let mut out = data[..pos].to_vec();
        out.extend_from_slice(tok);
        out.extend_from_slice(&data[pos..]);
        out.truncate(self.config.max_output_len);
        MutationResult {
            data: out,
            kind: MutationKind::FormatSpecific("json_token_insert".into()),
            original_len: data.len(),
        }
    }

    fn mutate_xml(&mut self, data: &[u8]) -> MutationResult {
        let tokens: &[&[u8]] = &[b"<", b">", b"/>", b"</", b"<!--", b"-->", b"&lt;", b"&gt;", b"&amp;"];
        let tok = tokens[self.rng.next_usize(tokens.len())];
        let pos = self.rng.next_usize(data.len().max(1));
        let mut out = data[..pos].to_vec();
        out.extend_from_slice(tok);
        out.extend_from_slice(&data[pos..]);
        out.truncate(self.config.max_output_len);
        MutationResult {
            data: out,
            kind: MutationKind::FormatSpecific("xml_token_insert".into()),
            original_len: data.len(),
        }
    }

    fn mutate_pe(&mut self, data: &[u8]) -> Option<MutationResult> {
        if data.len() < 64 { return None; }
        // Corrupt PE optional header SizeOfImage (offset 0x50 from PE header start)
        let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
        let size_of_image_off = pe_off.checked_add(0x58)?;
        if size_of_image_off.checked_add(4).is_none_or(|end| end > data.len()) { return None; }
        let mut out = data.to_vec();
        let v = INTERESTING_U32[self.rng.next_usize(INTERESTING_U32.len())];
        out[size_of_image_off..size_of_image_off + 4].copy_from_slice(&v.to_le_bytes());
        Some(MutationResult {
            data: out,
            kind: MutationKind::FormatSpecific("pe_size_of_image".into()),
            original_len: data.len(),
        })
    }
}

fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

// ─── Mutation statistics ─────────────────────────────────────────────────────

/// Tracks mutation strategy effectiveness over time.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MutationStats {
    /// Total mutations applied.
    pub total: u64,
    /// Mutations that produced new coverage.
    pub coverage_gain: u64,
    /// Mutations that triggered a crash.
    pub crash: u64,
    /// Per-strategy effectiveness: `kind_name` → (tried, success).
    pub per_kind: HashMap<String, (u64, u64)>,
}

impl MutationStats {
    pub fn record(&mut self, kind: &MutationKind, new_coverage: bool, crashed: bool) {
        self.total += 1;
        if new_coverage { self.coverage_gain += 1; }
        if crashed { self.crash += 1; }
        let key = format!("{kind:?}").split(' ').next().unwrap_or("unknown").to_string();
        let entry = self.per_kind.entry(key).or_insert((0, 0));
        entry.0 += 1;
        if new_coverage || crashed { entry.1 += 1; }
    }

    #[must_use] 
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 { 0.0 } else { (self.coverage_gain + self.crash) as f64 / (self.total) as f64 * 100.0 }
    }

    #[must_use] 
    pub fn format_report(&self) -> String {
        let mut out = String::new();
        writeln!(out, "Mutation Strategy Report").ok();
        writeln!(out, "  Total mutations : {}", self.total).ok();
        writeln!(out, "  Coverage gains  : {}", self.coverage_gain).ok();
        writeln!(out, "  Crashes         : {}", self.crash).ok();
        writeln!(out, "  Overall success : {:.1}%", self.success_rate()).ok();
        writeln!(out, "\n  Per-strategy effectiveness:").ok();
        let mut strategies: Vec<_> = self.per_kind.iter().collect();
        strategies.sort_by(|a, b| {
            let rate_a = if a.1.0 == 0 { 0.0 } else { (a.1.1) as f64 / (a.1.0) as f64 };
            let rate_b = if b.1.0 == 0 { 0.0 } else { (b.1.1) as f64 / (b.1.0) as f64 };
            rate_b.partial_cmp(&rate_a).unwrap_or(std::cmp::Ordering::Equal)
        });
        for (kind, (tried, success)) in strategies {
            let rate = if *tried == 0 { 0.0 } else { (*success) as f64 / (*tried) as f64 * 100.0 };
            writeln!(out, "    {kind:<25} tried={tried:<8} success={success:<8} rate={rate:.1}%").ok();
        }
        out
    }
}

// ─── Mutation schedule (energy-based) ────────────────────────────────────────

/// Energy-based mutation scheduler: allocates more mutations to seeds with
/// higher coverage potential, similar to AFL's power schedule.
pub struct MutationScheduler {
    /// (`seed_hash`, energy) — energy ∝ coverage gain per past mutation.
    seed_energy: HashMap<u64, f64>,
    base_energy: f64,
    max_energy: f64,
    rng: FastRng,
}

impl MutationScheduler {
    #[must_use] 
    pub fn new(base_energy: f64, seed: u64) -> Self {
        Self { seed_energy: HashMap::new(), base_energy, max_energy: base_energy * 16.0, rng: FastRng::new(seed) }
    }

    /// Return the number of mutations to apply to a seed.
    #[must_use] 
    pub fn mutations_for_seed(&self, seed_hash: u64) -> usize {
        let e = self.seed_energy.get(&seed_hash).copied().unwrap_or(self.base_energy);
        (e.round().max(1.0)) as usize
    }

    /// Update energy for a seed after observing its results.
    pub fn update(&mut self, seed_hash: u64, new_coverage: usize, crash: bool) {
        let e = self.seed_energy.entry(seed_hash).or_insert(self.base_energy);
        if crash {
            // Reduce energy after crash (we found a bug, move on)
            *e = (*e * 0.5).max(1.0);
        } else if new_coverage > 0 {
            // Increase energy proportionally to new edges found
            *e = (*e).mul_add(1.2, new_coverage as f64 * 2.0).min(self.max_energy);
        } else {
            // Slightly decay energy for unproductive seeds
            *e = (*e * 0.95).max(1.0);
        }
    }

    /// Select a seed to fuzz next (weighted by energy, with randomness).
    pub fn select_seed<'a>(&mut self, seed_hashes: &'a [u64]) -> Option<&'a u64> {
        if seed_hashes.is_empty() { return None; }
        let total_energy: f64 = seed_hashes.iter()
            .map(|h| self.seed_energy.get(h).copied().unwrap_or(self.base_energy))
            .sum();
        if total_energy == 0.0 { return seed_hashes.first(); }
        let mut pick = (self.rng.next_u64() as f64 / u64::MAX as f64) * total_energy;
        for hash in seed_hashes {
            let e = self.seed_energy.get(hash).copied().unwrap_or(self.base_energy);
            pick -= e;
            if pick <= 0.0 { return Some(hash); }
        }
        seed_hashes.last()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> MutationEngine {
        MutationEngine::new(MutationConfig::default(), 42)
    }

    #[test]
    fn test_bit_flip_changes_data() {
        let mut eng = make_engine();
        let input = vec![0u8; 64];
        let mut changed = false;
        for _ in 0..50 {
            let r = eng.mutate(&input);
            if r.data != input { changed = true; break; }
        }
        assert!(changed);
    }

    #[test]
    fn test_interesting_values_used() {
        let mut eng = make_engine();
        let input = vec![0xaau8; 32];
        let mut found_interesting = false;
        for _ in 0..200 {
            let r = eng.mutate(&input);
            if r.data.iter().any(|&b| INTERESTING_U8.contains(&b)) {
                found_interesting = true;
                break;
            }
        }
        assert!(found_interesting, "should use interesting bytes");
    }

    #[test]
    fn test_dictionary_insertion() {
        let mut eng = make_engine();
        let mut dict = Dictionary::new("test");
        dict.add_str("FUZZ");
        eng.set_dictionary(dict);
        let input = b"hello world".to_vec();
        let mut found = false;
        for _ in 0..200 {
            let r = eng.mutate(&input);
            if r.data.windows(4).any(|w| w == b"FUZZ") {
                found = true; break;
            }
        }
        assert!(found, "dictionary token should be inserted");
    }

    #[test]
    fn test_afl_dict_parse() {
        let text = "# comment\ntoken1=\"PNG\"\ntoken2=\"\\x89PNG\"\n";
        let dict = Dictionary::from_afl_format(text);
        assert_eq!(dict.len(), 2);
        assert_eq!(dict.tokens[0], b"PNG");
        assert_eq!(dict.tokens[1][0], 0x89);
    }

    #[test]
    fn test_format_detect() {
        assert_eq!(FormatHint::detect(b"\x89PNG\r\n\x1a\n"), FormatHint::Png);
        assert_eq!(FormatHint::detect(b"PK\x03\x04"), FormatHint::Zip);
        assert_eq!(FormatHint::detect(b"MZ"), FormatHint::Pe);
        assert_eq!(FormatHint::detect(b"{\"key\": 1}"), FormatHint::Json);
    }

    #[test]
    fn test_mutate_n_changes_input() {
        let mut eng = make_engine();
        let input = vec![0u8; 100];
        let out = eng.mutate_n(&input, 5);
        assert_ne!(out, input, "5 mutations should change the input");
    }

    #[test]
    fn test_splice() {
        let mut eng = make_engine();
        eng.add_corpus_entry(b"CORPUS_ENTRY_DATA".to_vec());
        let input = b"original_input_data_here".to_vec();
        let mut spliced = false;
        for _ in 0..100 {
            let r = eng.mutate(&input);
            if matches!(r.kind, MutationKind::Splice { .. }) { spliced = true; break; }
        }
        assert!(spliced, "splice should be attempted with corpus entries");
    }
}
