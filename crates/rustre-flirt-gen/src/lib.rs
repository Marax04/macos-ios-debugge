//! `rustre-flirt-gen` — FLIRT signature generator for the `RustRE` Suite.
//!
//! Provides pattern generation from raw function bytes with relocation masking,
//! a minimal ELF object-file parser, and a library builder with deduplication.

// These crates parse third-party `.sig`, `.pat` and `.lib` files. Every memory
// error in a parser of untrusted input is a security bug, so the whole family
// is kept free of `unsafe` by construction rather than by convention: the
// compiler refuses to build a violation.
//
// Measured 2026-07-29: all four crates already contained zero `unsafe` blocks.
// (An earlier inventory reported "3 unsafe in rustre-flirt-apply" — that was a
// grep counting the *word* inside comments that said "no unsafe".)
#![forbid(unsafe_code)]
pub mod batch_processor;
pub mod coff_archive;
pub mod compiler_profile;
pub mod pattern_extractor;
pub mod sig_writer;
pub mod lib_crawler;
pub mod database_builder;
pub mod lib_analyzer;
pub mod library_scanner;
pub mod pat_sig_format;
pub mod rflirt_bin;
pub mod pat_writer;
pub mod pattern_optimizer;
pub mod serializer;
pub mod sig_database;
pub mod sig_generator;
pub mod signature_extractor;
pub mod signature_index;
pub mod trie_structure;
pub mod variance_analyzer;
pub mod pat_file_writer;
pub mod signature_deduplicator;

use rustre_flirt::{
    FlirtArch, FlirtError, FlirtLibrary, FlirtName, FlirtOs, FlirtPattern, PatternByte,
    ReferencedName, TailByte, crc16_flirt,
};

// Re-export FunctionSample at crate level for use by database_builder
pub use library_scanner::FunctionSample;

// ── GenError ─────────────────────────────────────────────────────────────────

/// Top-level error type for `rustre-flirt-gen`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GenError {
    /// A pattern could not be generated (forwarded from [`FlirtError`]).
    #[error("invalid pattern: {0}")]
    InvalidPattern(String),
    /// A parse error occurred.
    #[error("parse error: {0}")]
    Parse(String),
    /// Serialization / deserialization error.
    #[error("serialize error: {0}")]
    Serialize(String),
}

impl From<FlirtError> for GenError {
    fn from(e: FlirtError) -> Self {
        Self::InvalidPattern(e.to_string())
    }
}

// ── Type aliases ──────────────────────────────────────────────────────────────

/// A tuple of `(function_name, raw_bytes, relocations)` as returned by the parsers.
type FunctionEntry = (String, Vec<u8>, Vec<RelocationEntry>);

// ── RelocationEntry ───────────────────────────────────────────────────────────

/// Describes a relocation within a function body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationEntry {
    /// Byte offset within the function where the relocation target begins.
    pub offset: u16,
    /// Number of bytes the relocation occupies (usually 4 or 8).
    pub size: u8,
}

// ── PatternGenerator ──────────────────────────────────────────────────────────

/// Generates [`FlirtPattern`]s from raw function bytes and relocation tables.
pub struct PatternGenerator {
    /// Number of leading bytes to include in the initial masked pattern (default 32).
    pub initial_length: usize,
    /// Number of bytes after `initial_length` to cover with the CRC-16 (default 16).
    pub crc_length: usize,
}

impl Default for PatternGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternGenerator {
    /// Create a generator with default lengths (initial=32, crc=16).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            initial_length: 32,
            crc_length: 16,
        }
    }

    /// Generate a single [`FlirtPattern`] from raw bytes, a relocation table, and names.
    ///
    /// # Errors
    ///
    /// Returns [`FlirtError::InvalidPattern`] if `bytes` is empty.
    pub fn generate(
        &self,
        bytes: &[u8],
        relocs: &[RelocationEntry],
        names: Vec<FlirtName>,
    ) -> Result<FlirtPattern, FlirtError> {
        if bytes.is_empty() {
            return Err(FlirtError::InvalidPattern("empty byte slice".to_string()));
        }

        let initial_len = self.initial_length.min(bytes.len());
        let initial_bytes = Self::apply_relocations(&bytes[..initial_len], relocs);

        let crc_start = initial_len;
        let crc_end = (crc_start + self.crc_length).min(bytes.len());
        let (crc16, actual_crc_len) = if crc_end > crc_start {
            let crc = crc16_flirt(&bytes[crc_start..crc_end]);
            let len = u8::try_from(crc_end - crc_start).unwrap_or(u8::MAX);
            (crc, len)
        } else {
            (0u16, 0u8)
        };

        let tail_bytes = Self::compute_tail_bytes(bytes, relocs, initial_len);

        let mut pat = FlirtPattern::new(initial_bytes);
        pat.crc16 = crc16;
        pat.crc_length = actual_crc_len;
        pat.pattern_length = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
        pat.names = names;
        pat.tail_bytes = tail_bytes;

        Ok(pat)
    }

    /// Generate a [`FlirtPattern`] from explicit relocation/variable byte ranges.
    ///
    /// Unlike [`PatternGenerator::generate`], which takes a list of
    /// [`RelocationEntry`] records, this entry point accepts raw `(start, len)`
    /// byte ranges (in *function-relative* coordinates) that should be masked
    /// out as wildcards — convenient when relocations come from a disassembler's
    /// immediate/displacement analysis rather than an object-file reloc table.
    ///
    /// The CRC-16/CCITT is computed over the stable region immediately following
    /// the initial masked block, skipping any byte that falls inside a masked
    /// range, so the CRC stays reproducible across relocated copies. Referenced
    /// names are attached verbatim.
    ///
    /// # Errors
    ///
    /// Returns [`FlirtError::InvalidPattern`] if `bytes` is empty.
    pub fn generate_from_ranges(
        &self,
        bytes: &[u8],
        masked_ranges: &[(u16, u8)],
        names: Vec<FlirtName>,
        referenced: Vec<ReferencedName>,
    ) -> Result<FlirtPattern, FlirtError> {
        if bytes.is_empty() {
            return Err(FlirtError::InvalidPattern("empty byte slice".to_string()));
        }

        let relocs: Vec<RelocationEntry> = masked_ranges
            .iter()
            .map(|&(offset, size)| RelocationEntry { offset, size })
            .collect();

        let initial_len = self.initial_length.min(bytes.len());
        let initial_bytes = Self::apply_relocations(&bytes[..initial_len], &relocs);

        let masked = Self::masked_offset_set(&relocs);
        let (crc16, crc_len) =
            Self::crc_over_stable_region(bytes, initial_len, self.crc_length, &masked);

        let mut pat = FlirtPattern::new(initial_bytes);
        pat.crc16 = crc16;
        pat.crc_length = crc_len;
        pat.pattern_length = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
        pat.names = names;
        pat.tail_bytes = Self::compute_tail_bytes(bytes, &relocs, initial_len);
        pat.referenced_names = referenced;

        Ok(pat)
    }

    /// Collect the set of all masked byte offsets covered by `relocs`.
    fn masked_offset_set(relocs: &[RelocationEntry]) -> std::collections::HashSet<usize> {
        let mut set = std::collections::HashSet::new();
        for reloc in relocs {
            let start = reloc.offset as usize;
            for off in start..start + reloc.size as usize {
                set.insert(off);
            }
        }
        set
    }

    /// Compute the CRC-16 over the run of **contiguous unmasked** bytes that
    /// follows the initial block, returning `(crc, covered_len)`.
    ///
    /// # Why contiguous, and why this changed (T3c)
    ///
    /// This used to *skip* masked offsets anywhere in the window and collect
    /// `crc_length` survivors, so the bytes hashed were non-contiguous and
    /// `covered_len` was a count of survivors. The scanner, meanwhile, hashes
    /// `crc_len` **contiguous** bytes starting right after the pattern. The two
    /// definitions coincide only when nothing in the window is masked — which is
    /// why the divergence was invisible on simple functions and fatal on
    /// relocated ones.
    ///
    /// Measured before this change: clearing the CRC field outright took
    /// self-match from 65.2% to 97.0%, i.e. the field was rejecting matches
    /// rather than confirming them.
    ///
    /// The window now stops at the first masked byte. `crc_len` therefore means
    /// the same thing on both sides — "this many contiguous bytes, starting
    /// after the pattern" — so generator and scanner agree by construction
    /// instead of by luck. A function whose very next byte is relocated gets
    /// `crc_len == 0`, i.e. no CRC, which is honest: there is no stable
    /// contiguous run to check.
    fn crc_over_stable_region(
        bytes: &[u8],
        initial_len: usize,
        crc_length: usize,
        masked: &std::collections::HashSet<usize>,
    ) -> (u16, u8) {
        if initial_len >= bytes.len() || crc_length == 0 {
            return (0, 0);
        }
        let mut region: Vec<u8> = Vec::with_capacity(crc_length);
        for (off, &b) in bytes.iter().enumerate().skip(initial_len) {
            if region.len() >= crc_length || masked.contains(&off) {
                break;
            }
            region.push(b);
        }
        if region.is_empty() {
            return (0, 0);
        }
        let crc = crc16_flirt(&region);
        (crc, u8::try_from(region.len()).unwrap_or(u8::MAX))
    }

    /// Generate patterns for a batch of `(name, bytes, relocs)` tuples.
    ///
    /// Silently skips any function that fails to generate.
    #[must_use]
    pub fn generate_batch(&self, functions: Vec<FunctionEntry>) -> Vec<FlirtPattern> {
        functions
            .into_iter()
            .filter_map(|(name, bytes, relocs)| {
                let fname = FlirtName {
                    name,
                    offset: 0,
                    is_public: true,
                    is_local: false,
                };
                self.generate(&bytes, &relocs, vec![fname]).ok()
            })
            .collect()
    }

    /// Mask relocations in the given byte slice, returning [`PatternByte`] values.
    ///
    /// Any byte position covered by a [`RelocationEntry`] becomes [`PatternByte::Wildcard`].
    fn apply_relocations(bytes: &[u8], relocs: &[RelocationEntry]) -> Vec<PatternByte> {
        let mut result: Vec<PatternByte> = bytes.iter().map(|&b| PatternByte::Exact(b)).collect();

        for reloc in relocs {
            let start = reloc.offset as usize;
            let end = start + reloc.size as usize;
            for item in result
                .iter_mut()
                .skip(start)
                .take(end.saturating_sub(start))
            {
                *item = PatternByte::Wildcard;
            }
        }
        result
    }

    /// Compute tail bytes: up to 8 non-relocated bytes sampled from beyond the initial block.
    fn compute_tail_bytes(
        bytes: &[u8],
        relocs: &[RelocationEntry],
        initial_length: usize,
    ) -> Vec<TailByte> {
        let mut tail = Vec::new();
        if initial_length >= bytes.len() {
            return tail;
        }

        let mut reloc_offsets = std::collections::HashSet::new();
        for reloc in relocs {
            let rstart = reloc.offset as usize;
            for i in rstart..rstart + reloc.size as usize {
                reloc_offsets.insert(i);
            }
        }

        for (off, &byte) in bytes.iter().enumerate().skip(initial_length) {
            if tail.len() >= 8 {
                break;
            }
            if !reloc_offsets.contains(&off) {
                tail.push(TailByte {
                    offset: u16::try_from(off).unwrap_or(u16::MAX),
                    value: byte,
                });
            }
        }
        tail
    }
}

// ── PatternWithQuality ────────────────────────────────────────────────────────

/// Quality tier of a generated pattern, derived from the wildcard density.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternQuality {
    /// `mask_ratio` <= 0.20 — almost entirely concrete; ideal for FLIRT identification.
    High,
    /// `mask_ratio` <= 0.40 — moderate masking; usable but less discriminating.
    Medium,
    /// `mask_ratio` > 0.40 — heavy masking; weak signature.
    Low,
}

impl PatternQuality {
    /// Lower-case label used in human-readable reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

/// Pattern plus masking-density telemetry returned by
/// [`PatternGenerator::generate_pattern_with_quality`].
#[derive(Debug, Clone)]
pub struct PatternWithQuality {
    /// The fully-formed [`FlirtPattern`].
    pub pattern: FlirtPattern,
    /// Count of wildcard bytes in the initial block.
    pub masked_bytes: usize,
    /// Length of the initial block in bytes.
    pub total_bytes: usize,
    /// `masked_bytes / total_bytes`, in `[0.0, 1.0]`. Zero when `total_bytes` is zero.
    pub mask_ratio: f32,
    /// Tier derived from `mask_ratio`.
    pub quality: PatternQuality,
}

// ── x86 instruction-aware masking ─────────────────────────────────────────────

/// Scan an x86-64 byte stream and return masked ranges `(offset, size)` covering
/// the immediate operands of direct calls/jumps, RIP-relative loads, and
/// 4/8-byte absolute address immediates.
///
/// Recognised forms:
/// * `E8 dd dd dd dd` — `CALL rel32` — masks the 4 displacement bytes
/// * `E9 dd dd dd dd` — `JMP rel32` — masks the 4 displacement bytes
/// * `0F 8x dd dd dd dd` — `Jcc rel32` — masks the 4 displacement bytes
/// * `EB cb` — `JMP rel8` — masks the 1 displacement byte
/// * `7x cb` / `E0..E3 cb` — short `Jcc` / loop — masks the 1 displacement byte
/// * ModR/M with `mod=00, rm=101` (RIP-relative `[rip+disp32]`) — masks the 4 disp bytes
/// * `REX.W + B8+r io` (`MOV r64, imm64`) — masks the 8 immediate bytes
///
/// On any unknown opcode the walker advances one byte rather than misaligning;
/// this is intentionally conservative and is good enough to wildcard the most
/// common relocatable operands.
#[must_use]
/// Skip x86 legacy prefixes and return `(new_p, rex_w)`.
fn skip_x86_prefixes(bytes: &[u8], mut p: usize) -> (usize, bool) {
    while p < bytes.len() && matches!(bytes[p], 0xF0 | 0xF2 | 0xF3 | 0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67) {
        p += 1;
    }
    let rex_w = if p < bytes.len() && bytes[p] & 0xF0 == 0x40 { p += 1; bytes[p - 1] & 0x08 != 0 } else { false };
    (p, rex_w)
}

#[must_use]
pub fn scan_x86_masks(bytes: &[u8]) -> Vec<(u16, u8)> {
    let mut ranges: Vec<(u16, u8)> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let (p, rex_w) = skip_x86_prefixes(bytes, i);
        if p >= bytes.len() {
            break;
        }
        let op = bytes[p];

        if op == 0xE8 || op == 0xE9 {
            let disp_off = p + 1;
            if disp_off + 4 <= bytes.len() {
                if let Ok(off) = u16::try_from(disp_off) {
                    ranges.push((off, 4));
                }
                i = disp_off + 4;
                continue;
            }
        }
        if op == 0x0F && p + 1 < bytes.len() && (bytes[p + 1] & 0xF0) == 0x80 {
            let disp_off = p + 2;
            if disp_off + 4 <= bytes.len() {
                if let Ok(off) = u16::try_from(disp_off) {
                    ranges.push((off, 4));
                }
                i = disp_off + 4;
                continue;
            }
        }
        if op == 0xEB || (op & 0xF0) == 0x70 || (0xE0..=0xE3).contains(&op) {
            let disp_off = p + 1;
            if disp_off < bytes.len() {
                if let Ok(off) = u16::try_from(disp_off) {
                    ranges.push((off, 1));
                }
                i = disp_off + 1;
                continue;
            }
        }
        if rex_w && (0xB8..=0xBF).contains(&op) {
            let imm_off = p + 1;
            if imm_off + 8 <= bytes.len() {
                if let Ok(off) = u16::try_from(imm_off) {
                    ranges.push((off, 8));
                }
                i = imm_off + 8;
                continue;
            }
        }
        let has_modrm = matches!(
            op,
            0x00..=0x03
                | 0x08..=0x0B
                | 0x10..=0x13
                | 0x18..=0x1B
                | 0x20..=0x23
                | 0x28..=0x2B
                | 0x30..=0x33
                | 0x38..=0x3B
                | 0x69
                | 0x6B
                | 0x84..=0x8B
                | 0x8D
                | 0x8F
                | 0xC6
                | 0xC7
                | 0xD0..=0xD3
                | 0xF6
                | 0xF7
                | 0xFE
                | 0xFF
        );
        if has_modrm && p + 1 < bytes.len() {
            let modrm = bytes[p + 1];
            let mod_ = modrm >> 6;
            let rm = modrm & 0x07;
            if mod_ == 0 && rm == 5 {
                let disp_off = p + 2;
                if disp_off + 4 <= bytes.len() {
                    if let Ok(off) = u16::try_from(disp_off) {
                        ranges.push((off, 4));
                    }
                    i = disp_off + 4;
                    continue;
                }
            }
        }
        i = p + 1;
    }
    ranges
}

impl PatternGenerator {
    /// Generate a pattern using [`scan_x86_masks`] to derive wildcard ranges
    /// from raw bytes, then report quality telemetry.
    ///
    /// # Errors
    ///
    /// Returns [`FlirtError::InvalidPattern`] if `bytes` is empty.
    pub fn generate_pattern_with_quality(
        &self,
        bytes: &[u8],
        name: &str,
    ) -> Result<PatternWithQuality, FlirtError> {
        let ranges = scan_x86_masks(bytes);
        let fname = FlirtName {
            name: name.to_string(),
            offset: 0,
            is_public: true,
            is_local: false,
        };
        let pattern = self.generate_from_ranges(bytes, &ranges, vec![fname], vec![])?;

        let total_bytes = pattern.initial_bytes.len();
        let masked_bytes = pattern
            .initial_bytes
            .iter()
            .filter(|b| matches!(b, PatternByte::Wildcard))
            .count();
        let mask_ratio = if total_bytes == 0 {
            0.0
        } else {
            f32::from(u16::try_from(masked_bytes).unwrap_or(u16::MAX)) / f32::from(u16::try_from(total_bytes).unwrap_or(u16::MAX))
        };
        let quality = if mask_ratio <= 0.20 {
            PatternQuality::High
        } else if mask_ratio <= 0.40 {
            PatternQuality::Medium
        } else {
            PatternQuality::Low
        };

        Ok(PatternWithQuality {
            pattern,
            masked_bytes,
            total_bytes,
            mask_ratio,
            quality,
        })
    }
}

// ── ElfObjectParser ───────────────────────────────────────────────────────────

/// Minimal ELF relocatable object (`.o`) parser with no external dependencies.
///
/// Extracts `(function_name, bytes, relocations)` tuples from `STT_FUNC` symbols.
pub struct ElfObjectParser;

fn elf_read_u16(data: &[u8], o: usize, le: bool) -> Result<u16, FlirtError> {
    // `o` comes from a file field; release builds have overflow-checks OFF,
    // so a plain `o + 2` can WRAP and pass this check. Use checked_add.
    if o.checked_add(2).is_none_or(|end| end > data.len()) {
        return Err(FlirtError::ParseError(format!("read_u16 oob @ {o:#x}")));
    }
    let arr: [u8; 2] = data[o..o + 2].try_into().unwrap();
    Ok(if le {
        u16::from_le_bytes(arr)
    } else {
        u16::from_be_bytes(arr)
    })
}

fn elf_read_u32(data: &[u8], o: usize, le: bool) -> Result<u32, FlirtError> {
    // `o` comes from a file field; release builds have overflow-checks OFF,
    // so a plain `o + 4` can WRAP and pass this check. Use checked_add.
    if o.checked_add(4).is_none_or(|end| end > data.len()) {
        return Err(FlirtError::ParseError(format!("read_u32 oob @ {o:#x}")));
    }
    let arr: [u8; 4] = data[o..o + 4].try_into().unwrap();
    Ok(if le {
        u32::from_le_bytes(arr)
    } else {
        u32::from_be_bytes(arr)
    })
}

fn elf_read_u64(data: &[u8], o: usize, le: bool) -> Result<u64, FlirtError> {
    // `o` comes from a file field; release builds have overflow-checks OFF,
    // so a plain `o + 8` can WRAP and pass this check. Use checked_add.
    if o.checked_add(8).is_none_or(|end| end > data.len()) {
        return Err(FlirtError::ParseError(format!("read_u64 oob @ {o:#x}")));
    }
    let arr: [u8; 8] = data[o..o + 8].try_into().unwrap();
    Ok(if le {
        u64::from_le_bytes(arr)
    } else {
        u64::from_be_bytes(arr)
    })
}

fn read_cstr(data: &[u8], off: usize) -> String {
    if off >= data.len() {
        return String::new();
    }
    let end = data[off..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(data.len() - off);
    String::from_utf8_lossy(&data[off..off + end]).to_string()
}

/// Relocations keyed by the section index they apply to, ELF32 variant.
type Elf32RelaMap = std::collections::HashMap<u32, Vec<(u32, u8)>>;
/// Relocations keyed by the section index they apply to, ELF64 variant.
type Elf64RelaMap = std::collections::HashMap<u32, Vec<(u64, u8)>>;

/// Bundle of ELF symbol-table data passed to `extract_functions` helpers.
struct ElfSymtabCtx<'a> {
    off: usize,
    size: usize,
    strtab: &'a [u8],
}

impl ElfObjectParser {
    /// Parse an ELF object file and return all functions with their relocations.
    ///
    /// # Errors
    ///
    /// Returns [`FlirtError::ParseError`] if the file is not valid ELF, and
    /// propagates any structural parse errors encountered during parsing.
    pub fn parse(elf_bytes: &[u8]) -> Result<Vec<FunctionEntry>, FlirtError> {
        if elf_bytes.len() < 16 {
            return Err(FlirtError::ParseError("ELF too short".to_string()));
        }
        if &elf_bytes[0..4] != b"\x7fELF" {
            return Err(FlirtError::ParseError("not an ELF file".to_string()));
        }

        let ei_class = elf_bytes[4];
        let ei_data = elf_bytes[5];
        let le = ei_data == 1;

        match ei_class {
            1 => Self::parse_elf32(elf_bytes, le),
            2 => Self::parse_elf64(elf_bytes, le),
            _ => Err(FlirtError::ParseError(format!(
                "unknown EI_CLASS {ei_class}"
            ))),
        }
    }

    // ── ELF32 ────────────────────────────────────────────────────────────────

    fn parse_elf32(elf_bytes: &[u8], le: bool) -> Result<Vec<FunctionEntry>, FlirtError> {
        let e_shoff = elf_read_u32(elf_bytes, 0x20, le)? as usize;
        let e_shentsize = elf_read_u16(elf_bytes, 0x2E, le)? as usize;
        let e_shnum = elf_read_u16(elf_bytes, 0x30, le)? as usize;
        let e_shstrndx = elf_read_u16(elf_bytes, 0x32, le)? as usize;

        if e_shoff == 0 || e_shnum == 0 {
            return Err(FlirtError::ParseError(
                "no section headers (elf32)".to_string(),
            ));
        }
        if e_shentsize < 40 {
            return Err(FlirtError::ParseError(
                "shentsize too small (elf32)".to_string(),
            ));
        }
        // Validate that the section-header table itself fits in the file.
        let sh_table_end = e_shoff
            .checked_add(e_shnum.checked_mul(e_shentsize).ok_or_else(|| {
                FlirtError::ParseError("section-header table size overflow (elf32)".to_string())
            })?)
            .ok_or_else(|| {
                FlirtError::ParseError("section-header table end overflow (elf32)".to_string())
            })?;
        if sh_table_end > elf_bytes.len() {
            return Err(FlirtError::ParseError(
                "section-header table oob (elf32)".to_string(),
            ));
        }
        if e_shstrndx >= e_shnum {
            return Err(FlirtError::ParseError(
                "e_shstrndx out of range (elf32)".to_string(),
            ));
        }

        let sh32 = |idx: usize, field: usize| -> Result<u32, FlirtError> {
            elf_read_u32(elf_bytes, e_shoff + idx * e_shentsize + field, le)
        };

        let shstr_offset = sh32(e_shstrndx, 0x10)? as usize;
        let shstr_size = sh32(e_shstrndx, 0x14)? as usize;
        let shstr_end = shstr_offset
            .checked_add(shstr_size)
            .ok_or_else(|| FlirtError::ParseError("shstrtab end overflow (elf32)".to_string()))?;
        if shstr_end > elf_bytes.len() {
            return Err(FlirtError::ParseError("shstrtab oob (elf32)".to_string()));
        }
        let shstr = &elf_bytes[shstr_offset..shstr_end];

        let (symtab_idx, strtab_idx) =
            Self::find_symtab_strtab_32(elf_bytes, e_shnum, &sh32, shstr)?;

        let symtab_off = sh32(symtab_idx, 0x10)? as usize;
        let symtab_size = sh32(symtab_idx, 0x14)? as usize;
        // Without this the symbol COUNT (`symtab_size / entsize`) is unbounded by
        // the file, so a forged size spins the extraction loop for ~forever.
        if symtab_off
            .checked_add(symtab_size)
            .is_none_or(|end| end > elf_bytes.len())
        {
            return Err(FlirtError::ParseError("symtab oob (elf32)".to_string()));
        }
        let strtab_off = sh32(strtab_idx, 0x10)? as usize;
        let strtab_size = sh32(strtab_idx, 0x14)? as usize;
        let strtab_end = strtab_off
            .checked_add(strtab_size)
            .ok_or_else(|| FlirtError::ParseError("strtab end overflow (elf32)".to_string()))?;
        if strtab_end > elf_bytes.len() {
            return Err(FlirtError::ParseError("strtab oob (elf32)".to_string()));
        }
        let strtab = &elf_bytes[strtab_off..strtab_end];

        let rela_map = Self::build_rela_map_32(elf_bytes, e_shnum, &sh32, le)?;

        Self::extract_functions_32(
            elf_bytes,
            le,
            e_shnum,
            &ElfSymtabCtx { off: symtab_off, size: symtab_size, strtab },
            &sh32,
            &rela_map,
        )
    }

    fn find_symtab_strtab_32(
        elf_bytes: &[u8],
        e_shnum: usize,
        sh32: &impl Fn(usize, usize) -> Result<u32, FlirtError>,
        shstr: &[u8],
    ) -> Result<(usize, usize), FlirtError> {
        let mut symtab_idx = None;
        let mut strtab_idx = None;

        for i in 0..e_shnum {
            match sh32(i, 0x04)? {
                2 => symtab_idx = Some(i),
                3 => {
                    let name_off = sh32(i, 0x00)? as usize;
                    let name = read_cstr(shstr, name_off);
                    if name == ".strtab" || name.is_empty() {
                        strtab_idx = Some(i);
                    }
                }
                _ => {}
            }
        }

        let _ = elf_bytes; // suppress unused warning
        let symtab_idx =
            symtab_idx.ok_or_else(|| FlirtError::ParseError("no symtab (elf32)".to_string()))?;
        let strtab_idx =
            strtab_idx.ok_or_else(|| FlirtError::ParseError("no strtab (elf32)".to_string()))?;
        Ok((symtab_idx, strtab_idx))
    }

    fn build_rela_map_32(
        elf_bytes: &[u8],
        e_shnum: usize,
        sh32: &impl Fn(usize, usize) -> Result<u32, FlirtError>,
        le: bool,
    ) -> Result<Elf32RelaMap, FlirtError> {
        let mut map: Elf32RelaMap = std::collections::HashMap::new();

        for i in 0..e_shnum {
            let stype = sh32(i, 0x04)?;
            if stype == 4 || stype == 9 {
                let target_sec = sh32(i, 0x1C)?;
                let rela_off = sh32(i, 0x10)? as usize;
                let rela_size = sh32(i, 0x14)? as usize;
                let entry_sz = if stype == 4 { 12usize } else { 8usize };
                let num = rela_size / entry_sz;
                let list = map.entry(target_sec).or_default();
                for r in 0..num {
                    let Some(base) = r.checked_mul(entry_sz).and_then(|o| rela_off.checked_add(o)) else { break };
                    if base + 4 > elf_bytes.len() {
                        break;
                    }
                    let r_offset = elf_read_u32(elf_bytes, base, le)?;
                    // For SHT_RELA (type 4) entries the addend is a signed 32-bit
                    // value at offset +8 within the entry. We incorporate it into
                    // the relocated offset so that relocation masking operates on
                    // the correct byte range.
                    let effective_offset = if stype == 4 {
                        if base + 12 > elf_bytes.len() {
                            break;
                        }
                        let addend = (elf_read_u32(elf_bytes, base + 8, le)?).cast_signed();
                        u32::try_from(i64::from(r_offset) + i64::from(addend)).unwrap_or(0)
                    } else {
                        r_offset
                    };
                    list.push((effective_offset, 4u8));
                }
            }
        }
        Ok(map)
    }

    fn extract_functions_32(
        elf_bytes: &[u8],
        le: bool,
        e_shnum: usize,
        symtab: &ElfSymtabCtx<'_>,
        sh32: &impl Fn(usize, usize) -> Result<u32, FlirtError>,
        rela_map: &Elf32RelaMap,
    ) -> Result<Vec<FunctionEntry>, FlirtError> {
        let sym_entry_size = 16usize;
        let symtab_off = symtab.off;
        let symtab_size = symtab.size;
        let strtab = symtab.strtab;
        let num_syms = symtab_size / sym_entry_size;

        let sym_u32 = |si: usize, field: usize| -> Result<u32, FlirtError> {
            elf_read_u32(elf_bytes, symtab_off + si * sym_entry_size + field, le)
        };
        let sym_u16 = |si: usize, field: usize| -> Result<u16, FlirtError> {
            elf_read_u16(elf_bytes, symtab_off + si * sym_entry_size + field, le)
        };

        let mut results = Vec::new();

        for sym_i in 0..num_syms {
            let st_info_off = symtab_off + sym_i * sym_entry_size + 12;
            if st_info_off >= elf_bytes.len() {
                break;
            }
            if elf_bytes[st_info_off] & 0x0F != 2 {
                continue;
            }

            let name_off = sym_u32(sym_i, 0)? as usize;
            let st_value = sym_u32(sym_i, 4)? as usize;
            let st_size = sym_u32(sym_i, 8)? as usize;
            let st_shndx = sym_u16(sym_i, 14)? as usize;

            if st_size == 0 || st_shndx == 0 || st_shndx >= e_shnum {
                continue;
            }

            let name = read_cstr(strtab, name_off);
            if name.is_empty() {
                continue;
            }

            let sec_off = sh32(st_shndx, 0x10)? as usize;
            let sec_size = sh32(st_shndx, 0x14)? as usize;
            let Some(fn_start) = sec_off.checked_add(st_value) else { continue };
            let Some(fn_end) = fn_start.checked_add(st_size) else { continue };
            let Some(sec_end) = sec_off.checked_add(sec_size) else { continue };
            if fn_end > elf_bytes.len() || fn_end > sec_end {
                continue;
            }

            let fn_bytes = elf_bytes[fn_start..fn_end].to_vec();
            let shndx_u32 = u32::try_from(st_shndx).unwrap_or(u32::MAX);
            let relocs = Self::collect_relocs_32(rela_map.get(&shndx_u32), st_value, st_size);

            results.push((name, fn_bytes, relocs));
        }
        Ok(results)
    }

    fn collect_relocs_32(
        rela_list: Option<&Vec<(u32, u8)>>,
        st_value: usize,
        st_size: usize,
    ) -> Vec<RelocationEntry> {
        let mut relocs = Vec::new();
        if let Some(list) = rela_list {
            for &(r_off, r_size) in list {
                let r_off_u = r_off as usize;
                if r_off_u >= st_value && r_off_u < st_value + st_size {
                    relocs.push(RelocationEntry {
                        offset: u16::try_from(r_off_u - st_value).unwrap_or(u16::MAX),
                        size: r_size,
                    });
                }
            }
        }
        relocs
    }

    // ── ELF64 ────────────────────────────────────────────────────────────────

    fn parse_elf64(elf_bytes: &[u8], le: bool) -> Result<Vec<FunctionEntry>, FlirtError> {
        let e_shoff = usize::try_from(elf_read_u64(elf_bytes, 0x28, le)?)
            .map_err(|_| FlirtError::ParseError("e_shoff overflow".to_string()))?;
        let e_shentsize = elf_read_u16(elf_bytes, 0x3A, le)? as usize;
        let e_shnum = elf_read_u16(elf_bytes, 0x3C, le)? as usize;
        let e_shstrndx = elf_read_u16(elf_bytes, 0x3E, le)? as usize;

        if e_shoff == 0 || e_shnum == 0 {
            return Err(FlirtError::ParseError(
                "no section headers (elf64)".to_string(),
            ));
        }
        if e_shentsize < 64 {
            return Err(FlirtError::ParseError(
                "shentsize too small (elf64)".to_string(),
            ));
        }
        // Validate that the section-header table itself fits in the file.
        let sh_table_end64 = e_shoff
            .checked_add(e_shnum.checked_mul(e_shentsize).ok_or_else(|| {
                FlirtError::ParseError("section-header table size overflow (elf64)".to_string())
            })?)
            .ok_or_else(|| {
                FlirtError::ParseError("section-header table end overflow (elf64)".to_string())
            })?;
        if sh_table_end64 > elf_bytes.len() {
            return Err(FlirtError::ParseError(
                "section-header table oob (elf64)".to_string(),
            ));
        }
        if e_shstrndx >= e_shnum {
            return Err(FlirtError::ParseError(
                "e_shstrndx out of range (elf64)".to_string(),
            ));
        }

        let sh64_u64 = |idx: usize, field: usize| -> Result<u64, FlirtError> {
            elf_read_u64(elf_bytes, e_shoff + idx * e_shentsize + field, le)
        };
        let sh64_u32 = |idx: usize, field: usize| -> Result<u32, FlirtError> {
            elf_read_u32(elf_bytes, e_shoff + idx * e_shentsize + field, le)
        };

        let shstr_offset = usize::try_from(sh64_u64(e_shstrndx, 0x18)?)
            .map_err(|_| FlirtError::ParseError("shstr offset overflow".to_string()))?;
        let shstr_size = usize::try_from(sh64_u64(e_shstrndx, 0x20)?)
            .map_err(|_| FlirtError::ParseError("shstr size overflow".to_string()))?;
        // Both operands are 64-bit file fields, so `shstr_offset + shstr_size`
        // WRAPS in release (overflow-checks off) and the comparison then passes
        // with `shstr_offset` still far past the end -- the slice below panics.
        let shstr_end = shstr_offset
            .checked_add(shstr_size)
            .ok_or_else(|| FlirtError::ParseError("shstrtab end overflow (elf64)".to_string()))?;
        if shstr_end > elf_bytes.len() {
            return Err(FlirtError::ParseError("shstrtab oob (elf64)".to_string()));
        }
        let shstr = &elf_bytes[shstr_offset..shstr_end];

        let (symtab_idx, strtab_idx) =
            Self::find_symtab_strtab_64(e_shnum, &sh64_u32, &sh64_u64, shstr)?;

        let symtab_off = usize::try_from(sh64_u64(symtab_idx, 0x18)?)
            .map_err(|_| FlirtError::ParseError("symtab off overflow".to_string()))?;
        let symtab_size = usize::try_from(sh64_u64(symtab_idx, 0x20)?)
            .map_err(|_| FlirtError::ParseError("symtab size overflow".to_string()))?;
        // Same reasoning as the elf32 path: bound the table by the file itself.
        if symtab_off
            .checked_add(symtab_size)
            .is_none_or(|end| end > elf_bytes.len())
        {
            return Err(FlirtError::ParseError("symtab oob (elf64)".to_string()));
        }
        let strtab_off = usize::try_from(sh64_u64(strtab_idx, 0x18)?)
            .map_err(|_| FlirtError::ParseError("strtab off overflow".to_string()))?;
        let strtab_size = usize::try_from(sh64_u64(strtab_idx, 0x20)?)
            .map_err(|_| FlirtError::ParseError("strtab size overflow".to_string()))?;
        let strtab_end = strtab_off
            .checked_add(strtab_size)
            .ok_or_else(|| FlirtError::ParseError("strtab end overflow (elf64)".to_string()))?;
        if strtab_end > elf_bytes.len() {
            return Err(FlirtError::ParseError("strtab oob (elf64)".to_string()));
        }
        let strtab = &elf_bytes[strtab_off..strtab_end];

        let rela_map = Self::build_rela_map_64(elf_bytes, e_shnum, &sh64_u64, &sh64_u32, le)?;

        Self::extract_functions_64(
            elf_bytes,
            le,
            e_shnum,
            &ElfSymtabCtx { off: symtab_off, size: symtab_size, strtab },
            &sh64_u64,
            &rela_map,
        )
    }

    fn find_symtab_strtab_64(
        e_shnum: usize,
        sh64_u32: &impl Fn(usize, usize) -> Result<u32, FlirtError>,
        sh64_u64: &impl Fn(usize, usize) -> Result<u64, FlirtError>,
        shstr: &[u8],
    ) -> Result<(usize, usize), FlirtError> {
        let mut symtab_idx = None;
        let mut strtab_idx = None;

        for i in 0..e_shnum {
            match sh64_u32(i, 0x04)? {
                2 => symtab_idx = Some(i),
                3 => {
                    let name_off = sh64_u32(i, 0x00)? as usize;
                    let name = read_cstr(shstr, name_off);
                    if name == ".strtab" || name.is_empty() {
                        strtab_idx = Some(i);
                    }
                }
                _ => {}
            }
        }

        let _ = sh64_u64; // used by callers
        let symtab_idx =
            symtab_idx.ok_or_else(|| FlirtError::ParseError("no symtab (elf64)".to_string()))?;
        let strtab_idx =
            strtab_idx.ok_or_else(|| FlirtError::ParseError("no strtab (elf64)".to_string()))?;
        Ok((symtab_idx, strtab_idx))
    }

    fn build_rela_map_64(
        elf_bytes: &[u8],
        e_shnum: usize,
        sh64_u64: &impl Fn(usize, usize) -> Result<u64, FlirtError>,
        sh64_u32: &impl Fn(usize, usize) -> Result<u32, FlirtError>,
        le: bool,
    ) -> Result<Elf64RelaMap, FlirtError> {
        let mut map: Elf64RelaMap = std::collections::HashMap::new();

        for i in 0..e_shnum {
            let stype = sh64_u32(i, 0x04)?;
            if stype == 4 || stype == 9 {
                let target_sec = sh64_u32(i, 0x2C)?;
                let rela_off = usize::try_from(sh64_u64(i, 0x18)?)
                    .map_err(|_| FlirtError::ParseError("rela off overflow".to_string()))?;
                let rela_size = usize::try_from(sh64_u64(i, 0x20)?)
                    .map_err(|_| FlirtError::ParseError("rela size overflow".to_string()))?;
                let entry_sz = if stype == 4 { 24usize } else { 16usize };
                let num = rela_size / entry_sz;
                let list = map.entry(target_sec).or_default();
                for r in 0..num {
                    let base = rela_off + r * entry_sz;
                    if base + 8 > elf_bytes.len() {
                        break;
                    }
                    let r_offset = elf_read_u64(elf_bytes, base, le)?;
                    list.push((r_offset, 8u8));
                }
            }
        }
        Ok(map)
    }

    fn extract_functions_64(
        elf_bytes: &[u8],
        le: bool,
        e_shnum: usize,
        symtab: &ElfSymtabCtx<'_>,
        sh64_u64: &impl Fn(usize, usize) -> Result<u64, FlirtError>,
        rela_map: &Elf64RelaMap,
    ) -> Result<Vec<FunctionEntry>, FlirtError> {
        let sym_entry_size = 24usize;
        let symtab_off = symtab.off;
        let symtab_size = symtab.size;
        let strtab = symtab.strtab;
        let num_syms = symtab_size / sym_entry_size;

        let sym_u32 = |si: usize, field: usize| -> Result<u32, FlirtError> {
            elf_read_u32(elf_bytes, symtab_off + si * sym_entry_size + field, le)
        };
        let sym_u64 = |si: usize, field: usize| -> Result<u64, FlirtError> {
            elf_read_u64(elf_bytes, symtab_off + si * sym_entry_size + field, le)
        };
        let sym_u16 = |si: usize, field: usize| -> Result<u16, FlirtError> {
            elf_read_u16(elf_bytes, symtab_off + si * sym_entry_size + field, le)
        };

        let mut results = Vec::new();

        for sym_i in 0..num_syms {
            let st_info_off = symtab_off + sym_i * sym_entry_size + 4;
            if st_info_off >= elf_bytes.len() {
                break;
            }
            if elf_bytes[st_info_off] & 0x0F != 2 {
                continue;
            }

            let name_off = sym_u32(sym_i, 0)? as usize;
            let st_shndx = sym_u16(sym_i, 6)? as usize;
            let st_value = usize::try_from(sym_u64(sym_i, 8)?)
                .map_err(|_| FlirtError::ParseError("st_value overflow".to_string()))?;
            let st_size = usize::try_from(sym_u64(sym_i, 16)?)
                .map_err(|_| FlirtError::ParseError("st_size overflow".to_string()))?;

            if st_size == 0 || st_shndx == 0 || st_shndx >= e_shnum {
                continue;
            }

            let name = read_cstr(strtab, name_off);
            if name.is_empty() {
                continue;
            }

            let sec_off = usize::try_from(sh64_u64(st_shndx, 0x18)?)
                .map_err(|_| FlirtError::ParseError("sec_off overflow".to_string()))?;
            let sec_size = usize::try_from(sh64_u64(st_shndx, 0x20)?)
                .map_err(|_| FlirtError::ParseError("sec_size overflow".to_string()))?;
            let Some(fn_start) = sec_off.checked_add(st_value) else { continue };
            let Some(fn_end) = fn_start.checked_add(st_size) else { continue };
            let Some(sec_end) = sec_off.checked_add(sec_size) else { continue };
            if fn_end > elf_bytes.len() || fn_end > sec_end {
                continue;
            }

            let fn_bytes = elf_bytes[fn_start..fn_end].to_vec();
            let shndx_u32 = u32::try_from(st_shndx).unwrap_or(u32::MAX);
            let relocs = Self::collect_relocs_64(rela_map.get(&shndx_u32), st_value, st_size);

            results.push((name, fn_bytes, relocs));
        }
        Ok(results)
    }

    fn collect_relocs_64(
        rela_list: Option<&Vec<(u64, u8)>>,
        st_value: usize,
        st_size: usize,
    ) -> Vec<RelocationEntry> {
        let mut relocs = Vec::new();
        if let Some(list) = rela_list {
            for &(r_off, r_size) in list {
                let r_off_u = usize::try_from(r_off).unwrap_or(usize::MAX);
                if r_off_u >= st_value && r_off_u < st_value + st_size {
                    relocs.push(RelocationEntry {
                        offset: u16::try_from(r_off_u - st_value).unwrap_or(u16::MAX),
                        size: r_size,
                    });
                }
            }
        }
        relocs
    }
}

// ── GenerationStats ───────────────────────────────────────────────────────────

/// Statistics collected during a library-build run.
#[derive(Debug, Default, Clone)]
pub struct GenerationStats {
    /// Total functions seen.
    pub functions_processed: usize,
    /// Patterns successfully generated.
    pub patterns_generated: usize,
    /// Functions skipped due to errors.
    pub patterns_skipped: usize,
    /// Duplicates removed by [`LibraryBuilder::dedup_patterns`].
    pub duplicates_removed: usize,
}

// ── LibraryBuilder ────────────────────────────────────────────────────────────

/// Accumulates patterns from multiple sources and builds a [`FlirtLibrary`].
pub struct LibraryBuilder {
    /// Human-readable name of the library being built.
    pub name: String,
    /// Target CPU architecture.
    pub arch: FlirtArch,
    /// Target operating system.
    pub os: FlirtOs,
    generator: PatternGenerator,
    patterns: Vec<FlirtPattern>,
    stats: GenerationStats,
}

impl LibraryBuilder {
    /// Create a new builder for the named library.
    #[must_use]
    pub fn new(name: impl Into<String>, arch: FlirtArch, os: FlirtOs) -> Self {
        Self {
            name: name.into(),
            arch,
            os,
            generator: PatternGenerator::new(),
            patterns: Vec::new(),
            stats: GenerationStats::default(),
        }
    }

    /// Generate a pattern from a single function and add it to the library.
    pub fn add_function(
        &mut self,
        name: String,
        bytes: &[u8],
        relocs: impl Into<Vec<RelocationEntry>>,
    ) {
        let relocs = relocs.into();
        self.stats.functions_processed += 1;
        let fname = FlirtName {
            name,
            offset: 0,
            is_public: true,
            is_local: false,
        };
        match self.generator.generate(bytes, &relocs, vec![fname]) {
            Ok(pat) => {
                self.patterns.push(pat);
                self.stats.patterns_generated += 1;
            }
            Err(_) => {
                self.stats.patterns_skipped += 1;
            }
        }
    }

    /// Parse an ELF `.o` file and add all functions found in it.
    ///
    /// Returns the number of functions successfully processed.
    ///
    /// # Errors
    ///
    /// Returns [`FlirtError::ParseError`] if the ELF data is structurally invalid.
    pub fn add_elf_object(&mut self, elf_bytes: &[u8]) -> Result<usize, FlirtError> {
        let functions = ElfObjectParser::parse(elf_bytes)?;
        let count = functions.len();
        for (name, bytes, relocs) in functions {
            self.add_function(name, &bytes, relocs);
        }
        Ok(count)
    }

    /// Remove duplicate patterns (same initial-byte hex, same CRC-16, same primary name).
    pub fn dedup_patterns(&mut self) {
        let before = self.patterns.len();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        self.patterns.retain(|p| {
            let key = format!(
                "{}:{}:{}:{}",
                p.pattern_hex(),
                p.crc16,
                p.crc_length,
                p.primary_name().unwrap_or("")
            );
            seen.insert(key)
        });
        let after = self.patterns.len();
        self.stats.duplicates_removed += before - after;
    }

    /// Consume the builder and return the finished library plus statistics.
    #[must_use]
    pub fn build(self) -> (FlirtLibrary, GenerationStats) {
        let mut lib = FlirtLibrary::new(self.name, self.arch, self.os);
        for pat in self.patterns {
            lib.add_pattern(pat);
        }
        (lib, self.stats)
    }
}

// ── IDA FLIRT .sig v9 binary format writer ────────────────────────────────────
//
// Reference: IDA SDK / Hex-Rays documentation for .sig v9.
//
// Header layout (little-endian unless stated):
//   [0..6]   Magic          b"IDASGN"
//   [6]      Version        u8  = 9
//   [7]      Arch           u8  (0 = 386, 75 = x86_64)
//   [8..12]  FileTypes      u32
//   [12..14] OsTypes        u16
//   [14..16] AppTypes       u16
//   [16..18] FeatureFlags   u16
//   [18..20] OldNumFuncs    u16  (always 0 for v9+)
//   [20..22] Crc16          u16  CRC-16 of header bytes [0..20]
//   [22..34] CtypesCrc      [u8; 12]  (zero-filled)
//   [34..38] NumFunctions   u32
//   [38..40] PatternSize    u16  (leading bytes used in pattern, default 32)
//   [40..104] LibraryName   [u8; 64]  (null-terminated)
//
// After the 104-byte header the trie follows. Each trie node is:
//   length: u8       — number of pattern bytes at this node
//   bytes:  [u8]     — the pattern bytes
//   Then either:
//     0x00           — child-node sentinel (children follow recursively)
//   Or leaf data (must match sig_file_loader::read_leaf_payload exactly):
//     flags: u8  > 0
//     crc_offset: u16 (BE)
//     crc_len: u8
//     crc16: u16 (BE)
//     name_len: u8
//     name: [u8]
//     0x00              — terminator of the extra-names list

use std::path::Path;

// ── CRC-16 (FLIRT / IDA variant) ─────────────────────────────────────────────

/// Compute the CRC-16 used by IDA's .sig header and trie nodes.
///
/// Polynomial 0x8005 with initial value 0xFFFF and no reflection — this is the
/// classical CRC-16/IBM/ARC *non-reflected* form used in older IDA builds.
/// The reflected variant (0x8408 poly) is used in .pat CRC fields; here we
/// use the non-reflected form as documented for the .sig header CRC field.
#[must_use]
pub fn crc16_sig_header(data: &[u8]) -> u16 {
    rustre_flirt::crc::cms(data)
}

// ── SigTrieNode ───────────────────────────────────────────────────────────────

/// A node in the compact FLIRT signature trie serialized into .sig files.
///
/// Internal nodes carry prefix bytes and a list of children; leaf nodes carry
/// the pattern metadata (CRC, function name, module offset).
#[derive(Debug, Clone)]
pub enum SigTrieNode {
    /// Internal node: prefix bytes and child nodes.
    Branch {
        /// The bytes that label this edge from parent to this node.
        prefix: Vec<u8>,
        /// Child nodes that extend this prefix further.
        children: Vec<Self>,
    },
    /// Leaf node: a complete pattern with its identification data.
    Leaf {
        /// The bytes that label this edge from parent to this node.
        prefix: Vec<u8>,
        /// Number of bytes covered by the CRC-16 check.
        crc_len: u8,
        /// CRC-16 value over the `crc_len` bytes following the pattern prefix.
        crc16: u16,
        /// Byte offset of the primary name within the matched function.
        module_offset: u16,
        /// Primary function name (ASCII, max 255 bytes).
        func_name: String,
        /// Pattern bytes **after** the trie prefix, with `tail_mask` marking
        /// which of them are wildcards.
        ///
        /// The trie is keyed on concrete bytes, so a wildcard cannot appear in
        /// the key; emitting one as `0x00` in-band would be indistinguishable
        /// from a real `0x00`. Before this field existed the writer simply
        /// stopped the prefix at the first wildcard and threw the rest away,
        /// which measured as a 16-byte pattern crossing the container as a
        /// 3-byte one — the cause of essentially every false positive in the
        /// cross-binary measurement.
        tail: Vec<u8>,
        /// `0xFF` where `tail` carries a concrete byte, `0x00` for a wildcard.
        tail_mask: Vec<u8>,
    },
}

impl SigTrieNode {
    /// Encode this node (and all descendants) into `buf` in .sig trie format.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Branch { prefix, children } => {
                let plen = u8::try_from(prefix.len().min(255)).unwrap_or(255);
                buf.push(plen);
                buf.extend_from_slice(&prefix[..plen as usize]);
                // child-node sentinel
                buf.push(0x00);
                for child in children {
                    child.encode(buf);
                }
                // end-of-children sentinel
                buf.push(0x00);
            }
            Self::Leaf {
                prefix,
                crc_len,
                crc16,
                module_offset,
                func_name,
                tail,
                tail_mask,
            } => {
                let plen = u8::try_from(prefix.len().min(255)).unwrap_or(255);
                buf.push(plen);
                buf.extend_from_slice(&prefix[..plen as usize]);
                // Control byte: 0 = internal node, non-zero = leaf.
                // `0x02` is a leaf that carries a masked tail after the control
                // byte; `0x01` is the original leaf with no tail. Readers that
                // predate the tail keep working on `0x01` files, and this writer
                // only emits `0x02` when there is actually something to carry.
                let has_tail = !tail.is_empty() && tail.len() == tail_mask.len();
                buf.push(if has_tail { 0x02 } else { 0x01 });
                if has_tail {
                    let tlen = u8::try_from(tail.len().min(255)).unwrap_or(255);
                    buf.push(tlen);
                    buf.extend_from_slice(&tail[..tlen as usize]);
                    buf.extend_from_slice(&tail_mask[..tlen as usize]);
                }

                // BUG FIX (T31): this used to emit
                //   crc_len:u8, crc16:u16 LE, module_offset:u16 LE, name…
                // and **nothing** after the name, while
                // `rustre_flirt_apply::sig_file_loader::read_leaf_payload` reads
                //   crc_offset:u16 BE, crc_len:u8, crc:u16 BE, name…,
                //   then a list of extra names terminated by a 0x00 byte.
                //
                // Two consequences, and the second was the fatal one:
                //   * the 5 fixed bytes were consumed in the right *count* but
                //     read as different fields, in the wrong endianness — so
                //     CRCs decoded as garbage;
                //   * with no terminator after the name, the decoder read the
                //     **next node's** prefix-length byte as an extra-name
                //     length and swallowed part of it, desynchronising the
                //     stream. Every leaf after the first was lost, which is why
                //     a 67 168-pattern database decoded to exactly one
                //     signature regardless of size.
                buf.extend_from_slice(&module_offset.to_be_bytes()); // crc_offset
                buf.push(*crc_len);
                buf.extend_from_slice(&crc16.to_be_bytes()); // crc

                // name, length-prefixed
                let name_bytes = func_name.as_bytes();
                let name_len = u8::try_from(name_bytes.len().min(255)).unwrap_or(255);
                buf.push(name_len);
                buf.extend_from_slice(&name_bytes[..name_len as usize]);

                // Terminator for the extra-names list. Without it the decoder
                // keeps reading into the following node.
                buf.push(0x00);
            }
        }
    }
}

// ── SigWriter ─────────────────────────────────────────────────────────────────

/// Builds the byte representation of a FLIRT .sig v9 file from a slice of
/// [`FlirtPattern`] (from `rustre_flirt`) plus library metadata.
pub struct SigWriter {
    /// CPU architecture code: 0 = i386, 75 = `x86_64`.
    pub arch: u8,
    /// IDA `id` / file-type bitmask (e.g. 0x0002 for PE).
    pub file_types: u32,
    /// IDA OS-type bitmask (e.g. 0x0002 for Win32).
    pub os_types: u16,
    /// IDA application-type bitmask.
    pub app_types: u16,
    /// Feature flags (0 for standard libraries).
    pub feature_flags: u16,
}

impl Default for SigWriter {
    fn default() -> Self {
        Self {
            arch: 75, // x86_64
            file_types: 0x0002,
            os_types: 0x0002,
            app_types: 0x0001,
            feature_flags: 0,
        }
    }
}

impl SigWriter {
    /// Serialise `sigs` into a complete .sig v9 byte vector.
    ///
    /// `lib_name` is truncated to 63 bytes if longer.
    #[must_use]
    pub fn build(&self, sigs: &[rustre_flirt::FlirtPattern], lib_name: &str) -> Vec<u8> {
        const PATTERN_SIZE: u16 = 32;
        let num_functions = u32::try_from(sigs.len()).unwrap_or(u32::MAX);

        // ── Trie body ─────────────────────────────────────────────────────────
        let mut trie_buf: Vec<u8> = Vec::new();
        for pat in sigs {
            // Collect concrete leading bytes (up to PATTERN_SIZE).
            // IDA .sig v9 uses a separate bitmask to mark wildcard positions;
            // wildcard bytes must NOT be emitted as 0x00 in-band because that
            // is indistinguishable from a real 0x00 byte and causes false
            // matches/misses. Instead we stop the prefix at the first wildcard
            // run, so the trie node length is shortened to exclude wildcards.
            // The crc_len / crc16 fields (computed over bytes *after* the prefix)
            // still cover the full intended window.
            let initial_bytes: Vec<_> = pat
                .initial_bytes
                .iter()
                .take(PATTERN_SIZE as usize)
                .collect();

            // Build prefix: include only the bytes up to (but not including)
            // the first Wildcard, so no spurious 0x00 wildcards enter the trie.
            let prefix: Vec<u8> = initial_bytes
                .iter()
                .take_while(|pb| matches!(pb, rustre_flirt::PatternByte::Exact(_)))
                .map(|pb| match pb {
                    rustre_flirt::PatternByte::Exact(b) => *b,
                    rustre_flirt::PatternByte::Wildcard => unreachable!(),
                })
                .collect();

            // Everything after the trie key, carried explicitly with its mask
            // instead of discarded. This is what made a wildcarded 16-byte
            // pattern cross the container as a 3-byte one.
            let (tail, tail_mask): (Vec<u8>, Vec<u8>) = initial_bytes
                .iter()
                .skip(prefix.len())
                .map(|pb| match pb {
                    rustre_flirt::PatternByte::Exact(b) => (*b, 0xFFu8),
                    rustre_flirt::PatternByte::Wildcard => (0x00, 0x00),
                })
                .unzip();

            let func_name = pat.primary_name().unwrap_or("").to_string();
            let node = SigTrieNode::Leaf {
                prefix,
                crc_len: pat.crc_length,
                crc16: pat.crc16,
                module_offset: 0,
                func_name,
                tail,
                tail_mask,
            };
            node.encode(&mut trie_buf);
        }
        // End-of-trie sentinel
        trie_buf.push(0x00);

        // ── Header (104 bytes) ────────────────────────────────────────────────
        // We build the header without the CRC field first, compute the CRC,
        // then insert it.
        // BUG FIX: this emitted a fixed 104-byte header with `num_functions` as
        // a u32 at offset 34 and the library name in a fixed 40..104 window.
        // Offset 34 is IDA's one-byte `library_name_len`, so files written this
        // way were unreadable by anything following the published layout — IDA
        // included. Now delegated to the single codec in
        // `rustre_flirt::sig_header`; the header is variable length.
        let mut h = rustre_flirt::sig_header::SigFileHeader {
            version: 9,
            arch: self.arch,
            file_types: self.file_types,
            os_types: self.os_types,
            app_types: self.app_types,
            feature_flags: self.feature_flags,
            n_functions: num_functions,
            pattern_size: PATTERN_SIZE,
            lib_name: lib_name.to_string(),
            ..rustre_flirt::sig_header::SigFileHeader::default()
        };
        // The CRC covers the 20 bytes preceding its own slot: encode once with a
        // zero placeholder, compute, then re-encode with the real value.
        h.crc16 = 0;
        let probe = h.encode();
        h.crc16 = crc16_sig_header(&probe[..20]);
        let hdr = h.encode();

        // ── Assemble final file ───────────────────────────────────────────────
        let mut out = Vec::with_capacity(hdr.len() + trie_buf.len());
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&trie_buf);
        out
    }
}

// ── write_sig_file ────────────────────────────────────────────────────────────

/// Write a set of FLIRT signatures as an IDA-compatible .sig v9 binary file.
///
/// # Arguments
///
/// * `sigs`     — patterns to encode (from `rustre_flirt::FlirtPattern`)
/// * `lib_name` — human-readable library name embedded in the .sig header
/// * `arch`     — CPU architecture byte: `0` = i386, `75` = `x86_64`
/// * `path`     — output file path
///
/// # Errors
///
/// Returns [`GenError::Serialize`] on I/O failures.
pub fn write_sig_file(
    sigs: &[rustre_flirt::FlirtPattern],
    lib_name: &str,
    arch: u8,
    path: &Path,
) -> Result<(), GenError> {
    use std::io::Write;

    let writer = SigWriter {
        arch,
        ..SigWriter::default()
    };
    let bytes = writer.build(sigs, lib_name);
    let mut f = std::fs::File::create(path)
        .map_err(|e| GenError::Serialize(format!("create {}: {e}", path.display())))?;
    f.write_all(&bytes)
        .map_err(|e| GenError::Serialize(format!("write {}: {e}", path.display())))?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_flirt::{FlirtArch, FlirtMatcher, FlirtOs};

    // ── PatternGenerator ─────────────────────────────────────────────────────

    #[test]
    fn test_generate_correct_initial_length() {
        let pg = PatternGenerator::new();
        let bytes: Vec<u8> = (0u8..50).collect();
        let pat = pg.generate(&bytes, &[], vec![]).unwrap();
        assert_eq!(pat.initial_bytes.len(), 32);
    }

    #[test]
    fn test_generate_short_function_under_initial_length() {
        let pg = PatternGenerator::new();
        let bytes = vec![0x55u8, 0x48, 0x89, 0xE5];
        let pat = pg.generate(&bytes, &[], vec![]).unwrap();
        assert_eq!(pat.initial_bytes.len(), 4);
        assert_eq!(pat.crc_length, 0);
    }

    #[test]
    fn test_apply_relocations_wildcards_correct() {
        let bytes = vec![0x55u8, 0x48, 0x89, 0xE5, 0xC3];
        let relocs = vec![RelocationEntry { offset: 2, size: 2 }];
        let result = PatternGenerator::apply_relocations(&bytes, &relocs);
        assert_eq!(result[0], PatternByte::Exact(0x55));
        assert_eq!(result[1], PatternByte::Exact(0x48));
        assert_eq!(result[2], PatternByte::Wildcard);
        assert_eq!(result[3], PatternByte::Wildcard);
        assert_eq!(result[4], PatternByte::Exact(0xC3));
    }

    #[test]
    fn test_apply_relocations_empty_relocs() {
        let bytes = vec![0xAAu8, 0xBB, 0xCC];
        let result = PatternGenerator::apply_relocations(&bytes, &[]);
        assert_eq!(
            result,
            vec![
                PatternByte::Exact(0xAA),
                PatternByte::Exact(0xBB),
                PatternByte::Exact(0xCC)
            ]
        );
    }

    #[test]
    fn test_generate_batch_creates_multiple() {
        let pg = PatternGenerator::new();
        let funcs: Vec<FunctionEntry> = vec![
            ("func_a".to_string(), vec![0x55u8, 0x48, 0x89, 0xE5], vec![]),
            ("func_b".to_string(), vec![0x56u8, 0x48, 0x89, 0xE5], vec![]),
            ("func_c".to_string(), vec![0x57u8, 0x48, 0x89, 0xE5], vec![]),
        ];
        let pats = pg.generate_batch(funcs);
        assert_eq!(pats.len(), 3);
        assert_eq!(pats[0].primary_name(), Some("func_a"));
        assert_eq!(pats[1].primary_name(), Some("func_b"));
        assert_eq!(pats[2].primary_name(), Some("func_c"));
    }

    #[test]
    fn test_generate_empty_bytes_error() {
        let pg = PatternGenerator::new();
        let result = pg.generate(&[], &[], vec![]);
        assert!(matches!(result, Err(FlirtError::InvalidPattern(_))));
    }

    // ── generate_from_ranges ─────────────────────────────────────────────────

    #[test]
    fn test_generate_from_ranges_masks_ranges() {
        let pg = PatternGenerator {
            initial_length: 6,
            crc_length: 4,
        };
        let bytes = vec![0x55u8, 0x48, 0x89, 0xE5, 0x12, 0x34, 0xAA, 0xBB];
        // Mask bytes [2..4] (a 2-byte range starting at offset 2).
        let pat = pg
            .generate_from_ranges(&bytes, &[(2, 2)], vec![], vec![])
            .unwrap();
        assert_eq!(pat.initial_bytes[0], PatternByte::Exact(0x55));
        assert_eq!(pat.initial_bytes[2], PatternByte::Wildcard);
        assert_eq!(pat.initial_bytes[3], PatternByte::Wildcard);
        assert_eq!(pat.initial_bytes[4], PatternByte::Exact(0x12));
        assert_eq!(pat.pattern_length, 8);
    }

    #[test]
    fn test_generate_from_ranges_empty_error() {
        let pg = PatternGenerator::new();
        assert!(matches!(
            pg.generate_from_ranges(&[], &[], vec![], vec![]),
            Err(FlirtError::InvalidPattern(_))
        ));
    }

    #[test]
    fn test_generate_from_ranges_attaches_referenced_names() {
        let pg = PatternGenerator::new();
        let bytes: Vec<u8> = (0u8..40).collect();
        let refs = vec![ReferencedName {
            offset: 12,
            name: "callee".to_string(),
        }];
        let pat = pg.generate_from_ranges(&bytes, &[], vec![], refs).unwrap();
        assert_eq!(pat.referenced_names.len(), 1);
        assert_eq!(pat.referenced_names[0].name, "callee");
    }

    #[test]
    fn test_crc_window_stops_at_the_first_masked_byte() {
        // Intent unchanged from the original test: two functions differing only
        // inside a relocated dword must produce the same CRC. What changed is
        // *how* (T3c, iteration 54).
        //
        // The window used to skip masked offsets anywhere and collect
        // `crc_length` survivors, so the hashed bytes were non-contiguous while
        // the scanner hashes a contiguous run — the two agreed only when nothing
        // was masked. The window now stops at the first masked byte, so
        // `crc_len` means the same thing on both sides.
        let pg = PatternGenerator { initial_length: 4, crc_length: 8 };

        // Case 1: the byte right after the pattern is masked. There is no stable
        // contiguous run, so there is no CRC — which is honest rather than
        // hashing bytes the scanner cannot reproduce.
        let mut a = vec![0x55u8, 0x48, 0x89, 0xE5];
        a.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0xC3, 0x90]);
        let mut b = a.clone();
        b[4] = 0xFF;
        b[5] = 0xEE;
        let pa = pg.generate_from_ranges(&a, &[(4, 4)], vec![], vec![]).unwrap();
        let pb = pg.generate_from_ranges(&b, &[(4, 4)], vec![], vec![]).unwrap();
        assert_eq!(pa.crc16, pb.crc16, "il CRC deve ignorare i byte rilocati");
        assert_eq!(
            pa.crc_length, 0,
            "nessun byte stabile prima della rilocazione: crc_len deve essere 0"
        );

        // Case 2: two stable bytes, then the relocated dword. The window covers
        // exactly those two, and the two functions still agree.
        let mut c = vec![0x55u8, 0x48, 0x89, 0xE5];
        c.extend_from_slice(&[0xAA, 0xBB, 0x11, 0x22, 0x33, 0x44, 0xC3]);
        let mut d = c.clone();
        d[6] = 0xFF;
        d[7] = 0xEE;
        let pc = pg.generate_from_ranges(&c, &[(6, 4)], vec![], vec![]).unwrap();
        let pd = pg.generate_from_ranges(&d, &[(6, 4)], vec![], vec![]).unwrap();
        assert_eq!(pc.crc_length, 2, "la finestra copre i due byte stabili");
        assert_eq!(pc.crc16, pd.crc16, "il CRC deve ignorare i byte rilocati");
        assert_eq!(
            pc.crc16,
            crc16_flirt(&[0xAA, 0xBB]),
            "il CRC deve essere quello dei due byte contigui, ricalcolabile              dallo scanner leggendo crc_len byte dopo il pattern"
        );
    }

    // ── LibraryBuilder ───────────────────────────────────────────────────────

    #[test]
    fn test_library_builder_add_function_and_build() {
        let mut builder = LibraryBuilder::new("mylib", FlirtArch::X64, FlirtOs::Linux);
        builder.add_function(
            "my_func".to_string(),
            &[0x55u8, 0x48, 0x89, 0xE5, 0xC3],
            vec![],
        );
        let (lib, stats) = builder.build();
        assert_eq!(lib.name, "mylib");
        assert_eq!(lib.pattern_count(), 1);
        assert_eq!(stats.functions_processed, 1);
        assert_eq!(stats.patterns_generated, 1);
        assert_eq!(stats.patterns_skipped, 0);
    }

    #[test]
    fn test_library_builder_stats_skipped_on_error() {
        let mut builder = LibraryBuilder::new("skiplib", FlirtArch::X86, FlirtOs::Windows);
        builder.add_function("empty".to_string(), &[], vec![]);
        let (_lib, stats) = builder.build();
        assert_eq!(stats.functions_processed, 1);
        assert_eq!(stats.patterns_generated, 0);
        assert_eq!(stats.patterns_skipped, 1);
    }

    #[test]
    fn test_dedup_patterns_removes_duplicates() {
        let mut builder = LibraryBuilder::new("deduplib", FlirtArch::X64, FlirtOs::Linux);
        let bytes = vec![0x55u8, 0x48, 0x89, 0xE5, 0xC3];
        builder.add_function("foo".to_string(), &bytes, vec![]);
        builder.add_function("foo".to_string(), &bytes, vec![]);
        builder.add_function("bar".to_string(), &[0x56u8, 0x48], vec![]);
        builder.dedup_patterns();
        let (lib, stats) = builder.build();
        assert_eq!(lib.pattern_count(), 2, "duplicate should be removed");
        assert_eq!(stats.duplicates_removed, 1);
    }

    // ── Round-trip test ──────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_generate_serialize_deserialize_match() {
        let func_bytes = [0x55u8, 0x48, 0x89, 0xE5, 0xC3, 0x90, 0x90, 0x90];

        let mut builder = LibraryBuilder::new("rtlib", FlirtArch::X64, FlirtOs::Linux);
        builder.add_function("rt_func".to_string(), &func_bytes, vec![]);
        let (lib, _stats) = builder.build();

        let serialized = lib.serialize();
        let lib2 = FlirtLibrary::deserialize(&serialized).expect("deserialize failed");
        assert_eq!(lib2.pattern_count(), 1);

        let mut matcher = FlirtMatcher::new();
        matcher.add_library(lib2);
        let hits =
            matcher.match_function(rustre_core::address::Address::new(0x1000), &func_bytes);
        assert!(!hits.is_empty(), "should match after round-trip");
        assert_eq!(hits[0].name, "rt_func");
    }

    // ── crc16_flirt via rustre_flirt ─────────────────────────────────────────

    #[test]
    fn test_crc16_known_vector_via_rustre_flirt() {
        assert_eq!(crc16_flirt(b"123456789"), 0x6F91);
    }

    // ── GenerationStats correctness ──────────────────────────────────────────

    #[test]
    fn test_generation_stats_after_batch() {
        let mut builder = LibraryBuilder::new("statslib", FlirtArch::Arm64, FlirtOs::Android);
        for i in 0u8..5 {
            builder.add_function(format!("fn_{i}"), &[0x55u8 + i, 0x48, 0x89, 0xE5], vec![]);
        }
        builder.add_function("bad".to_string(), &[], vec![]);
        let (_lib, stats) = builder.build();
        assert_eq!(stats.functions_processed, 6);
        assert_eq!(stats.patterns_generated, 5);
        assert_eq!(stats.patterns_skipped, 1);
    }

    // ── ElfObjectParser ──────────────────────────────────────────────────────

    #[test]
    fn test_elf_parser_rejects_non_elf() {
        let result = ElfObjectParser::parse(b"this is not elf data at all!!!");
        assert!(matches!(result, Err(FlirtError::ParseError(_))));
    }

    #[test]
    fn test_elf_parser_rejects_too_short() {
        let result = ElfObjectParser::parse(b"short");
        assert!(matches!(result, Err(FlirtError::ParseError(_))));
    }


    // ── Adversarial ELF parsing (attacker-controlled .o input) ───────────────

    /// Build a minimal little-endian ELF64 whose section-header table is valid
    /// but whose `shstrtab` section claims an offset/size pair that OVERFLOWS
    /// when added: `0x100 + (u64::MAX - 0x80)` wraps to `0x80`, which is inside
    /// the file, so a plain `offset + size > len` guard passes and the slice
    /// `&bytes[0x100..0x80]` panics.
    fn forged_elf64_with_wrapping_shstrtab() -> Vec<u8> {
        let mut b = vec![0u8; 0x200];
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2; // EI_CLASS = 64-bit
        b[5] = 1; // EI_DATA  = little-endian
        b[0x28..0x30].copy_from_slice(&0x40u64.to_le_bytes()); // e_shoff
        b[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        b[0x3C..0x3E].copy_from_slice(&2u16.to_le_bytes()); // e_shnum
        b[0x3E..0x40].copy_from_slice(&1u16.to_le_bytes()); // e_shstrndx
        let sh1 = 0x40 + 64; // second section header
        b[sh1 + 0x18..sh1 + 0x20].copy_from_slice(&0x100u64.to_le_bytes()); // sh_offset
        b[sh1 + 0x20..sh1 + 0x28].copy_from_slice(&(u64::MAX - 0x80).to_le_bytes()); // sh_size
        b
    }

    #[test]
    fn test_elf64_shstrtab_offset_size_overflow_is_rejected_not_panic() {
        let bytes = forged_elf64_with_wrapping_shstrtab();
        // Pre-condition of the attack: the wrapped sum really does look in-range.
        assert!(0x100usize.wrapping_add(usize::MAX - 0x80) < bytes.len());
        let result = ElfObjectParser::parse(&bytes);
        assert!(
            matches!(result, Err(FlirtError::ParseError(_))),
            "forged shstrtab must be rejected, got {result:?}"
        );
    }

    #[test]
    fn test_elf_readers_reject_offsets_that_wrap_the_bound_check() {
        let data = [0u8; 16];
        // `o + 4` and `o + 8` wrap to a small value at these offsets; without a
        // checked_add the guard passes and the slice below it panics.
        assert!(elf_read_u16(&data, usize::MAX - 1, true).is_err());
        assert!(elf_read_u32(&data, usize::MAX - 3, true).is_err());
        assert!(elf_read_u64(&data, usize::MAX - 7, true).is_err());
    }

    // ── Additional tests to reach 25+ ──────────────────────────────────────

    #[test]
    fn test_pattern_generator_custom_initial_length() {
        let mut pg = PatternGenerator::new();
        pg.initial_length = 4;
        let bytes: Vec<u8> = (0u8..20).collect();
        let pat = pg.generate(&bytes, &[], vec![]).unwrap();
        assert_eq!(pat.initial_bytes.len(), 4);
    }

    #[test]
    fn test_crc16_deterministic() {
        let data = b"hello world";
        let a = crc16_flirt(data);
        let b = crc16_flirt(data);
        assert_eq!(a, b);
    }

    #[test]
    fn test_pattern_generator_default_fields() {
        let pg = PatternGenerator::default();
        assert_eq!(pg.initial_length, 32);
        assert_eq!(pg.crc_length, 16);
    }

    #[test]
    fn test_library_builder_default_new() {
        let builder = LibraryBuilder::new("lib", FlirtArch::X86, FlirtOs::Windows);
        let (lib, stats) = builder.build();
        assert_eq!(lib.name, "lib");
        assert_eq!(stats.functions_processed, 0);
    }

    #[test]
    fn test_apply_relocations_full_wildcard() {
        let bytes = vec![0x55u8, 0x48, 0x89, 0xE5];
        let relocs = vec![RelocationEntry { offset: 0, size: 4 }];
        let result = PatternGenerator::apply_relocations(&bytes, &relocs);
        assert!(result.iter().all(|b| *b == PatternByte::Wildcard));
    }

    #[test]
    fn test_tail_bytes_computed_for_long_function() {
        let pg = PatternGenerator {
            initial_length: 4,
            crc_length: 4,
        };
        let bytes: Vec<u8> = (0u8..20).collect();
        let pat = pg.generate(&bytes, &[], vec![]).unwrap();
        // tail bytes should be sampled from beyond the initial block
        assert!(!pat.tail_bytes.is_empty());
        assert!(pat.tail_bytes[0].offset >= 4);
    }

    #[test]
    fn test_generate_batch_empty_skips_gracefully() {
        let pg = PatternGenerator::new();
        let funcs: Vec<FunctionEntry> = vec![("bad".into(), vec![], vec![])];
        let pats = pg.generate_batch(funcs);
        assert!(pats.is_empty());
    }

    #[test]
    fn test_pattern_length_stored_correctly() {
        let pg = PatternGenerator::new();
        let bytes: Vec<u8> = vec![0xAA; 10];
        let pat = pg.generate(&bytes, &[], vec![]).unwrap();
        assert_eq!(pat.pattern_length, 10);
    }

    #[test]
    fn test_relocation_entry_fields() {
        let r = RelocationEntry { offset: 4, size: 8 };
        assert_eq!(r.offset, 4);
        assert_eq!(r.size, 8);
    }

    #[test]
    fn test_builder_dedup_no_duplicates() {
        let mut builder = LibraryBuilder::new("test", FlirtArch::X64, FlirtOs::Linux);
        builder.add_function("fn1".into(), &[0x55, 0x48, 0x89, 0xE5], vec![]);
        builder.add_function("fn2".into(), &[0x56, 0x48, 0x89, 0xE5], vec![]);
        builder.dedup_patterns();
        let (lib, stats) = builder.build();
        assert_eq!(lib.pattern_count(), 2);
        assert_eq!(stats.duplicates_removed, 0);
    }

    #[test]
    fn test_crc_length_capped_to_available_bytes() {
        let pg = PatternGenerator {
            initial_length: 6,
            crc_length: 100,
        };
        let bytes = vec![0xAAu8; 10]; // only 4 bytes after initial block
        let pat = pg.generate(&bytes, &[], vec![]).unwrap();
        assert_eq!(pat.initial_bytes.len(), 6);
        assert_eq!(pat.crc_length, 4);
    }

    // ── .sig binary format ───────────────────────────────────────────────────

    #[test]
    fn test_sig_writer_produces_idasgn_magic() {
        let writer = SigWriter::default();
        let bytes = writer.build(&[], "testlib");
        assert_eq!(&bytes[..6], b"IDASGN");
    }

    #[test]
    fn test_sig_writer_version_byte() {
        let writer = SigWriter::default();
        let bytes = writer.build(&[], "testlib");
        assert_eq!(bytes[6], 9, "version must be 9");
    }

    #[test]
    fn test_sig_writer_arch_byte() {
        let writer = SigWriter {
            arch: 0, // i386
            ..SigWriter::default()
        };
        let bytes = writer.build(&[], "lib");
        assert_eq!(bytes[7], 0);
    }

    #[test]
    fn test_sig_writer_lib_name_embedded() {
        let writer = SigWriter::default();
        let bytes = writer.build(&[], "myspeciallib");
        // Decoded with the canonical codec rather than read from a fixed
        // 40..104 window: that window was the old, wrong layout, and a test
        // that pokes it keeps the wrong layout alive.
        let h = rustre_flirt::sig_header::SigFileHeader::decode(&bytes)
            .expect("l'header scritto deve essere leggibile");
        assert_eq!(h.lib_name, "myspeciallib");
    }

    #[test]
    fn test_sig_writer_lib_name_truncated_at_255() {
        // `library_name_len` is a single byte, so 255 is the format's ceiling —
        // not the 63 that the old fixed 64-byte window imposed.
        let writer = SigWriter::default();
        let long_name: String = "x".repeat(300);
        let bytes = writer.build(&[], &long_name);
        let h = rustre_flirt::sig_header::SigFileHeader::decode(&bytes)
            .expect("un nome lungo deve comunque produrre un header valido");
        assert!(h.lib_name.len() <= 255, "il nome deve stare in un byte di lunghezza");
        assert!(h.lib_name.starts_with("xxx"));
    }

    #[test]
    fn test_sig_writer_num_functions_field() {
        use rustre_flirt::FlirtArch;
        use rustre_flirt::FlirtOs;
        let mut builder = LibraryBuilder::new("lib", FlirtArch::X64, FlirtOs::Linux);
        builder.add_function("fn_a".into(), &[0x55u8, 0x48, 0x89, 0xE5], vec![]);
        builder.add_function("fn_b".into(), &[0x56u8, 0x48, 0x89, 0xE5], vec![]);
        let (lib, _) = builder.build();
        let writer = SigWriter::default();
        let bytes = writer.build(&lib.patterns, "testlib");
        let num = rustre_flirt::sig_header::SigFileHeader::decode(&bytes)
            .expect("l'header scritto deve essere leggibile")
            .n_functions;
        assert_eq!(num, 2, "n_functions sta a offset 37, non a 34");
    }

    #[test]
    fn test_sig_writer_header_crc_nonzero_for_nonempty_data() {
        let writer = SigWriter::default();
        let bytes = writer.build(&[], "lib");
        // header CRC at [20..22]
        let crc = u16::from_le_bytes(bytes[20..22].try_into().unwrap());
        // CRC over a non-trivial header should not be zero in general.
        // We verify the stored CRC matches what crc16_sig_header computes.
        let recomputed = crc16_sig_header(&bytes[..20]);
        assert_eq!(crc, recomputed);
    }

    #[test]
    fn test_write_sig_file_creates_valid_file() {
        use rustre_flirt::FlirtArch;
        use rustre_flirt::FlirtOs;
        let mut builder = LibraryBuilder::new("lib", FlirtArch::X64, FlirtOs::Linux);
        builder.add_function("my_fn".into(), &[0x55u8, 0x48, 0x89, 0xE5, 0xC3], vec![]);
        let (lib, _) = builder.build();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.sig");
        write_sig_file(&lib.patterns, "mylib", 75, &path).unwrap();
        let data = std::fs::read(&path).unwrap();
        assert_eq!(&data[..6], b"IDASGN");
        assert_eq!(data[6], 9);
    }

    #[test]
    fn test_crc16_sig_header_deterministic() {
        let data = b"hello world";
        assert_eq!(crc16_sig_header(data), crc16_sig_header(data));
    }

    #[test]
    fn test_sig_trie_leaf_encode_roundtrip() {
        let node = SigTrieNode::Leaf {
            prefix: vec![0x55, 0x48, 0x89, 0xE5],
            crc_len: 4,
            crc16: 0xABCD,
            module_offset: 0,
            func_name: "foo".to_string(),
            tail: Vec::new(),
            tail_mask: Vec::new(),
        };
        let mut buf = Vec::new();
        node.encode(&mut buf);
        // Should start with length byte 4 then the 4 prefix bytes.
        assert_eq!(buf[0], 4);
        assert_eq!(&buf[1..5], &[0x55, 0x48, 0x89, 0xE5]);
        // flags byte > 0 signals leaf
        assert!(buf[5] > 0);
    }

    #[test]
    fn test_sig_trie_branch_encode_sentinel() {
        let node = SigTrieNode::Branch {
            prefix: vec![0x55],
            children: vec![],
        };
        let mut buf = Vec::new();
        node.encode(&mut buf);
        // length=1, byte=0x55, child sentinel=0x00, end-of-children=0x00
        assert_eq!(buf[0], 1);
        assert_eq!(buf[1], 0x55);
        assert_eq!(buf[2], 0x00); // child sentinel
        assert_eq!(buf[3], 0x00); // end of children
    }

    #[test]
    fn test_sig_writer_pattern_size_field() {
        let writer = SigWriter::default();
        let bytes = writer.build(&[], "lib");
        // pattern_size is at offset 41 in the published layout, not 38.
        let ps = rustre_flirt::sig_header::SigFileHeader::decode(&bytes)
            .expect("l'header scritto deve essere leggibile")
            .pattern_size;
        assert_eq!(ps, 32);
    }

    // ── generate_pattern_with_quality ────────────────────────────────────────

    #[test]
    fn test_quality_no_relocs_is_high() {
        let pg = PatternGenerator::new();
        let mut bytes = vec![0x55u8, 0x48, 0x89, 0xE5];
        bytes.extend(std::iter::repeat_n(0x90u8, 40));
        let q = pg.generate_pattern_with_quality(&bytes, "leaf").unwrap();
        assert_eq!(q.quality, PatternQuality::High);
        assert_eq!(q.masked_bytes, 0);
        assert!((q.mask_ratio - 0.0).abs() < f32::EPSILON);
        assert_eq!(q.pattern.primary_name(), Some("leaf"));
    }

    #[test]
    fn test_quality_one_call_has_masking() {
        let pg = PatternGenerator::new();
        let mut bytes = vec![
            0x55, 0x48, 0x89, 0xE5,
            0xE8, 0x11, 0x22, 0x33, 0x44,
            0x48, 0x89, 0xC3, 0x5D, 0xC3,
        ];
        bytes.extend(std::iter::repeat_n(0x90u8, 20));
        let q = pg.generate_pattern_with_quality(&bytes, "calls_one").unwrap();
        assert_eq!(q.masked_bytes, 4);
        assert!(q.mask_ratio > 0.0);
        assert!(matches!(q.quality, PatternQuality::High | PatternQuality::Medium));
        for i in 5..9 {
            assert!(matches!(q.pattern.initial_bytes[i], PatternByte::Wildcard));
        }
    }

    #[test]
    fn test_quality_many_rip_relative_loads_is_low() {
        let pg = PatternGenerator::new();
        let mut bytes = Vec::new();
        for _ in 0..6 {
            bytes.extend_from_slice(&[0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xDD]);
        }
        let q = pg.generate_pattern_with_quality(&bytes, "many_loads").unwrap();
        assert!(q.mask_ratio > 0.40, "ratio was {}", q.mask_ratio);
        assert_eq!(q.quality, PatternQuality::Low);
    }

    #[test]
    fn test_crc16_footer_correctness() {
        let pg = PatternGenerator {
            initial_length: 8,
            crc_length: 16,
        };
        let mut bytes: Vec<u8> = (0u8..8).collect();
        let footer: Vec<u8> = (0x80u8..0x90).collect();
        bytes.extend_from_slice(&footer);
        let pat = pg.generate(&bytes, &[], vec![]).unwrap();
        assert_eq!(pat.crc_length, 16);
        let expected = crc16_flirt(&footer);
        assert_eq!(pat.crc16, expected);
        let q = pg.generate_pattern_with_quality(&bytes, "footer_fn").unwrap();
        assert_eq!(q.pattern.crc_length, 16);
        assert_eq!(q.pattern.crc16, expected);
    }
}
