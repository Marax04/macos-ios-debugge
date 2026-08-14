//! `match_context` — Rich match context: PE section mapping, entropy of
//! surrounding bytes, disassembly hints, and capture-group offsets.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// Module-private cast helpers — boundary for lossy numeric conversions.
#[inline]
fn u64_to_usize(v: u64) -> usize { usize::try_from(v).unwrap_or(usize::MAX) }
#[inline]
fn usize_to_f64(v: usize) -> f64 { u64_to_f64(v as u64) }
#[inline]
fn u64_to_f64(v: u64) -> f64 {
    let lo = f64::from(u32::try_from(v & 0xFFFF_FFFF).unwrap_or(u32::MAX));
    let hi = f64::from(u32::try_from(v >> 32).unwrap_or(u32::MAX));
    hi.mul_add(4_294_967_296.0, lo)
}
#[inline]
const fn u64_as_i64(v: u64) -> i64 { v.cast_signed() }
#[inline]
const fn i64_as_u64(v: i64) -> u64 { v.cast_unsigned() }
#[inline]
const fn u8_as_i8(v: u8) -> i8 { v.cast_signed() }

// ── PE section map ────────────────────────────────────────────────────────────

/// A single PE section entry (name + file offset range).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSectionRange {
    /// Section name (e.g. `.text`, `.data`, `.rsrc`).
    pub name: String,
    /// File offset of the first byte of the section data.
    pub raw_start: u64,
    /// File offset of the last byte (exclusive).
    pub raw_end: u64,
    /// Virtual address (RVA) relative to image base.
    pub virtual_address: u32,
    /// Characteristics flags.
    pub characteristics: u32,
}

impl PeSectionRange {
    /// Does the given file offset fall inside this section?
    #[inline]
    #[must_use] 
    pub const fn contains_offset(&self, offset: u64) -> bool {
        offset >= self.raw_start && offset < self.raw_end
    }

    /// Is this section executable?
    #[inline]
    #[must_use] 
    pub const fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }

    /// Is this section readable/writable data?
    #[inline]
    #[must_use] 
    pub const fn is_data(&self) -> bool {
        self.characteristics & 0x4000_0000 != 0
    }
}

/// Categorises a file offset relative to a parsed PE image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OffsetCategory {
    /// DOS/PE headers.
    Header,
    /// Inside a named section.
    Section(String),
    /// After the last section (overlay area).
    Overlay,
    /// Unknown / outside parsed regions.
    Unknown,
}

impl std::fmt::Display for OffsetCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Header => write!(f, "PE Header"),
            Self::Section(s) => write!(f, "Section {s}"),
            Self::Overlay => write!(f, "Overlay"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ── Capture group ─────────────────────────────────────────────────────────────

/// A named or indexed capture group within a YARA regex match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureGroup {
    /// Group index (0 = full match).
    pub index: usize,
    /// Optional name from `(?P<name>…)`.
    pub name: Option<String>,
    /// Offset within the file/buffer.
    pub offset: u64,
    /// Length in bytes.
    pub length: usize,
    /// Raw bytes of the captured group.
    pub data: Vec<u8>,
}

impl CaptureGroup {
    /// Attempt UTF-8 decode of the captured bytes.
    #[must_use] 
    pub fn as_utf8(&self) -> Option<&str> {
        std::str::from_utf8(&self.data).ok()
    }
}

// ── Entropy context ───────────────────────────────────────────────────────────

/// Shannon entropy summary for the bytes surrounding a match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchEntropy {
    /// Entropy of the 256 bytes immediately before the match.
    pub pre_entropy: f64,
    /// Entropy of the matched bytes themselves.
    pub match_entropy: f64,
    /// Entropy of the 256 bytes immediately after the match.
    pub post_entropy: f64,
    /// Rolling-window entropy of the enclosing 4 KiB block.
    pub block_entropy: f64,
}

impl MatchEntropy {
    /// Compute from a buffer and the match offset/length.
    #[must_use] 
    pub fn compute(data: &[u8], offset: u64, length: usize) -> Self {
        // Clamp the offset to the buffer FIRST. Every window below is built by
        // walking back from `off` (`saturating_sub`) and clamping only forward
        // (`.min(data.len())`); for an `off` past the end that leaves the start of
        // `pre_slice`/`block_slice` ABOVE its own end, which panics rather than
        // yielding an empty window. `triage-yara::ioc_extractor` clamps up front
        // for exactly this reason, and says so.
        let off = u64_to_usize(offset).min(data.len());
        let window = 256;
        let pre_start = off.saturating_sub(window);
        let post_end = off.saturating_add(length).saturating_add(window).min(data.len());
        let block_start = off.saturating_sub(2048);
        let block_end = off.saturating_add(2048).min(data.len());

        let match_end = off.saturating_add(length).min(data.len());
        let pre_slice  = &data[pre_start..off];
        let match_slice = &data[off..match_end];
        let post_slice = &data[match_end..post_end];
        let block_slice = &data[block_start..block_end];

        Self {
            pre_entropy: shannon_entropy(pre_slice),
            match_entropy: shannon_entropy(match_slice),
            post_entropy: shannon_entropy(post_slice),
            block_entropy: shannon_entropy(block_slice),
        }
    }

    /// True if the matched region is inside a high-entropy (packed/encrypted) block.
    #[must_use] 
    pub fn is_high_entropy_context(&self) -> bool {
        self.block_entropy > 6.8
    }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = usize_to_f64(data.len());
    let mut h = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = f64::from(c) / len;
            h = p.mul_add(-p.log2(), h);
        }
    }
    h.clamp(0.0, 8.0)
}

// ── Disassembly hint ──────────────────────────────────────────────────────────

/// Architecture for disassembly hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisasmArch {
    X86,
    X86_64,
    Arm32,
    Arm64,
    Unknown,
}

/// A single disassembled instruction near a match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisasmLine {
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
}

impl DisasmLine {
    /// Format as a human-readable string.
    #[must_use] 
    pub fn display(&self) -> String {
        format!("{:#010x}  {}  {} {}", self.offset, hex_str(&self.bytes), self.mnemonic, self.operands)
    }
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

/// Minimal x86 instruction length table for the 32 most common opcodes.
/// Used for the lightweight disassembly hint without pulling in capstone.
fn x86_insn_len(data: &[u8]) -> usize {
    if data.is_empty() { return 1; }
    match data[0] {
        // Single-byte NOPs/RET + PUSH/POP r16/r32/r64 (0x50–0x5F)
        0x90 | 0xC3 | 0xCB | 0xC9 | 0x50..=0x5F => 1,
        // MOV reg, imm32 (0xB8–0xBF) or CALL/JMP rel32
        0xB8..=0xBF | 0xE8 | 0xE9 if data.len() >= 5 => 5,
        // Short JMP, Jcc (rel8) or ADD/SUB/CMP/XOR/AND/OR r/m, r (ModRM)
        0xEB | 0x70..=0x7F | 0x00..=0x3F if data.len() >= 2 => 2,
        // MOV r/m, imm8 (0xC6) or Two-byte escape
        0xC6 | 0x0F if data.len() >= 3 => 3,
        _ => 2,
    }
}

/// Produce up to `count` disassembled lines starting at `offset`.
#[must_use] 
pub fn disasm_hint(
    data: &[u8],
    offset: u64,
    count: usize,
    arch: DisasmArch,
) -> Vec<DisasmLine> {
    let mut result = Vec::with_capacity(count);
    let mut pos = u64_to_usize(offset);

    // x86/x86_64 only — other archs return raw bytes with "db" mnemonic
    for _ in 0..count {
        if pos >= data.len() { break; }
        let slice = &data[pos..];
        let (mnemonic, operands, len) = decode_x86_simple(slice, pos as u64, arch);
        let end = (pos + len).min(data.len());
        result.push(DisasmLine {
            offset: pos as u64,
            bytes: data[pos..end].to_vec(),
            mnemonic,
            operands,
        });
        pos += len.max(1);
    }
    result
}

fn decode_x86_simple(data: &[u8], va: u64, arch: DisasmArch) -> (String, String, usize) {
    if data.is_empty() {
        return ("???".into(), String::new(), 1);
    }
    match arch {
        DisasmArch::X86 | DisasmArch::X86_64 => {
            let len = x86_insn_len(data);
            let (m, op) = match data[0] {
                0x90 => ("nop", String::new()),
                0xC3 => ("ret", String::new()),
                0xC9 => ("leave", String::new()),
                0x50..=0x57 => {
                    let regs = ["eax","ecx","edx","ebx","esp","ebp","esi","edi"];
                    ("push", regs[(data[0] - 0x50) as usize].to_string())
                }
                0x58..=0x5F => {
                    let regs = ["eax","ecx","edx","ebx","esp","ebp","esi","edi"];
                    ("pop", regs[(data[0] - 0x58) as usize].to_string())
                }
                0xE8 if data.len() >= 5 => {
                    let rel = i32::from_le_bytes(data[1..5].try_into().unwrap());
                    let target = i64_as_u64(u64_as_i64(va) + 5 + i64::from(rel));
                    ("call", format!("{target:#x}"))
                }
                0xE9 if data.len() >= 5 => {
                    let rel = i32::from_le_bytes(data[1..5].try_into().unwrap());
                    let target = i64_as_u64(u64_as_i64(va) + 5 + i64::from(rel));
                    ("jmp", format!("{target:#x}"))
                }
                0xEB if data.len() >= 2 => {
                    let rel = u8_as_i8(data[1]);
                    let target = i64_as_u64(u64_as_i64(va) + 2 + i64::from(rel));
                    ("jmp", format!("{target:#x}"))
                }
                0x0F if data.len() >= 2 && data[1] == 0x05 => ("syscall", String::new()),
                0xB8..=0xBF if data.len() >= 5 => {
                    let regs = ["eax","ecx","edx","ebx","esp","ebp","esi","edi"];
                    let imm = u32::from_le_bytes(data[1..5].try_into().unwrap());
                    ("mov", format!("{}, {:#x}", regs[(data[0] - 0xB8) as usize], imm))
                }
                _ => ("db", format!("{:#04x}", data[0])),
            };
            (m.to_string(), op, len)
        }
        _ => {
            ("db".to_string(), format!("{:#04x}", data[0]), 1)
        }
    }
}

// ── MatchContext ───────────────────────────────────────────────────────────────

/// Full contextual information for a single YARA match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchContext {
    /// Offset in the file/buffer.
    pub offset: u64,
    /// Length of the matched bytes.
    pub length: usize,
    /// Up to 64 raw matched bytes.
    pub matched_bytes: Vec<u8>,
    /// 32 bytes of context before the match.
    pub context_before: Vec<u8>,
    /// 32 bytes of context after the match.
    pub context_after: Vec<u8>,
    /// Name of the YARA string that produced the match.
    pub string_id: String,
    /// Capture groups (if the match came from a regex string).
    pub captures: Vec<CaptureGroup>,
    /// Where in the PE image this offset falls.
    pub pe_location: OffsetCategory,
    /// Entropy info around this match.
    pub entropy: MatchEntropy,
    /// Nearby disassembly (x86/64).
    pub disasm: Vec<DisasmLine>,
    /// Any extra metadata from the rule condition context.
    pub metadata: HashMap<String, String>,
}

impl MatchContext {
    /// Build a `MatchContext` from raw scan data.
    ///
    /// * `data` — the full buffer that was scanned.
    /// * `offset` — byte offset of the match.
    /// * `length` — length of the matched bytes.
    /// * `string_id` — the YARA `$identifier`.
    /// * `sections` — PE sections parsed from the file header (may be empty).
    /// * `arch` — architecture hint for disassembly.
    pub fn build(
        data: &[u8],
        offset: u64,
        length: usize,
        string_id: impl Into<String>,
        sections: &[PeSectionRange],
        arch: DisasmArch,
    ) -> Self {
        let off = u64_to_usize(offset);
        let end = (off + length).min(data.len());
        let pre_start = off.saturating_sub(32);
        let post_end = (end + 32).min(data.len());

        let matched_bytes = data[off..end].to_vec();
        let context_before = data[pre_start..off].to_vec();
        let context_after = data[end..post_end].to_vec();

        let pe_location = classify_pe_offset(offset, sections, data);
        let entropy = MatchEntropy::compute(data, offset, length);
        let disasm = if matches!(arch, DisasmArch::X86 | DisasmArch::X86_64) {
            disasm_hint(data, offset, 8, arch)
        } else {
            Vec::new()
        };

        Self {
            offset,
            length,
            matched_bytes,
            context_before,
            context_after,
            string_id: string_id.into(),
            captures: Vec::new(),
            pe_location,
            entropy,
            disasm,
            metadata: HashMap::new(),
        }
    }

    /// Add a capture group.
    pub fn add_capture(&mut self, grp: CaptureGroup) {
        self.captures.push(grp);
    }

    /// Add a metadata key-value pair.
    pub fn set_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Is the match inside a code section?
    #[must_use] 
    pub fn is_in_code_section(&self) -> bool {
        match &self.pe_location {
            OffsetCategory::Section(name) => name == ".text" || name == "CODE",
            _ => false,
        }
    }

    /// Is the match inside the overlay (after last section)?
    #[must_use] 
    pub const fn is_in_overlay(&self) -> bool {
        matches!(self.pe_location, OffsetCategory::Overlay)
    }

    /// Short human-readable summary of this context.
    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "offset={:#x} len={} location={} entropy_ctx={:.2} captures={}",
            self.offset,
            self.length,
            self.pe_location,
            self.entropy.block_entropy,
            self.captures.len(),
        )
    }
}

// ── PE offset classifier ──────────────────────────────────────────────────────

/// Classify a file offset against the parsed PE section table.
#[must_use] 
pub fn classify_pe_offset(
    offset: u64,
    sections: &[PeSectionRange],
    data: &[u8],
) -> OffsetCategory {
    // Quick PE header check
    if offset < 0x40 {
        return OffsetCategory::Header;
    }
    // Check if offset is inside the PE header region (DOS + NT headers)
    if data.len() >= 4 && &data[0..2] == b"MZ" {
        let e_lfanew_off = 0x3C;
        if data.len() > e_lfanew_off + 4 {
            let e_lfanew = u64::from(u32::from_le_bytes(
                data[e_lfanew_off..e_lfanew_off + 4].try_into().unwrap_or([0; 4])
            ));
            if offset < e_lfanew + 0x200 {
                return OffsetCategory::Header;
            }
        }
    }

    for sec in sections {
        if sec.contains_offset(offset) {
            return OffsetCategory::Section(sec.name.clone());
        }
    }

    // Check for overlay
    if let Some(last) = sections.iter().max_by_key(|s| s.raw_end)
        && offset >= last.raw_end {
            return OffsetCategory::Overlay;
        }

    OffsetCategory::Unknown
}

/// Parse the section table from raw PE bytes.
/// Returns an empty Vec if the file is not a PE or headers are malformed.
#[must_use] 
pub fn parse_pe_sections(data: &[u8]) -> Vec<PeSectionRange> {
    if data.len() < 0x40 { return Vec::new(); }
    if &data[0..2] != b"MZ" { return Vec::new(); }

    let e_lfanew = u32::from_le_bytes(
        data.get(0x3C..0x40)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0; 4])
    ) as usize;

    if e_lfanew + 4 > data.len() { return Vec::new(); }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return Vec::new(); }

    let coff = e_lfanew + 4;
    if coff + 20 > data.len() { return Vec::new(); }

    let num_sections = u16::from_le_bytes(data[coff + 2..coff + 4].try_into().unwrap_or([0; 2])) as usize;
    let opt_hdr_size = u16::from_le_bytes(data[coff + 16..coff + 18].try_into().unwrap_or([0; 2])) as usize;
    let section_table = coff + 20 + opt_hdr_size;

    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let base = section_table + i * 40;
        if base + 40 > data.len() { break; }
        let name_bytes = &data[base..base + 8];
        let name = String::from_utf8_lossy(name_bytes)
            .trim_end_matches('\0')
            .to_string();
        let raw_size   = u64::from(u32::from_le_bytes(data[base + 16..base + 20].try_into().unwrap_or([0; 4])));
        let raw_offset = u64::from(u32::from_le_bytes(data[base + 20..base + 24].try_into().unwrap_or([0; 4])));
        let virtual_address = u32::from_le_bytes(data[base + 12..base + 16].try_into().unwrap_or([0; 4]));
        let characteristics = u32::from_le_bytes(data[base + 36..base + 40].try_into().unwrap_or([0; 4]));

        sections.push(PeSectionRange {
            name,
            raw_start: raw_offset,
            raw_end: raw_offset + raw_size,
            virtual_address,
            characteristics,
        });
    }
    sections
}

// ── ContextBuilder ────────────────────────────────────────────────────────────

/// Helper to build rich contexts for a batch of matches.
pub struct ContextBuilder {
    sections: Vec<PeSectionRange>,
    arch: DisasmArch,
}

impl ContextBuilder {
    /// Create a builder for a PE file. Parses the section table automatically.
    #[must_use] 
    pub fn for_pe(data: &[u8], arch: DisasmArch) -> Self {
        Self {
            sections: parse_pe_sections(data),
            arch,
        }
    }

    /// Create a builder for a raw binary (no PE headers).
    #[must_use] 
    pub const fn for_raw(arch: DisasmArch) -> Self {
        Self { sections: Vec::new(), arch }
    }

    /// Build a [`MatchContext`] for the given offset and length.
    pub fn build(
        &self,
        data: &[u8],
        offset: u64,
        length: usize,
        string_id: impl Into<String>,
    ) -> MatchContext {
        MatchContext::build(data, offset, length, string_id, &self.sections, self.arch)
    }

    /// Sections parsed from the PE header.
    #[must_use] 
    pub fn sections(&self) -> &[PeSectionRange] {
        &self.sections
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_all_same() {
        let data = vec![0xAAu8; 1024];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        let h = shannon_entropy(&data);
        assert!(h > 7.9, "expected near-8, got {h}");
    }

    #[test]
    fn test_context_before_after() {
        let data: Vec<u8> = (0u8..=255u8).cycle().take(512).collect();
        let ctx = MatchContext::build(&data, 100, 8, "$a", &[], DisasmArch::X86_64);
        assert_eq!(ctx.context_before.len(), 32);
        assert_eq!(ctx.context_after.len(), 32);
        assert_eq!(ctx.matched_bytes.len(), 8);
    }

    #[test]
    fn test_overlay_classification() {
        let sections = vec![PeSectionRange {
            name: ".text".to_string(),
            raw_start: 0x400,
            raw_end: 0x2000,
            virtual_address: 0x1000,
            characteristics: 0x6000_0020,
        }];
        let data = vec![0u8; 0x3000];
        assert_eq!(
            classify_pe_offset(0x2500, &sections, &data),
            OffsetCategory::Overlay
        );
    }

    #[test]
    fn test_disasm_hint_ret() {
        let code = vec![0xC3u8, 0x90, 0xC3];
        let lines = disasm_hint(&code, 0, 3, DisasmArch::X86);
        assert_eq!(lines[0].mnemonic, "ret");
        assert_eq!(lines[1].mnemonic, "nop");
    }

    #[test]
    fn test_match_entropy_offset_past_buffer_does_not_panic() {
        // Every window here walks BACK from the offset and clamps only forward,
        // so an offset past the end used to leave a slice starting after it ended.
        let data = vec![0xABu8; 64];
        for off in [64u64, 65, 4096, u64::MAX] {
            let e = MatchEntropy::compute(&data, off, 16);
            assert!(e.match_entropy >= 0.0, "off={off}");
        }
        // The in-range case still measures the real windows.
        let e = MatchEntropy::compute(&data, 8, 16);
        assert!(e.match_entropy >= 0.0);
    }
}
