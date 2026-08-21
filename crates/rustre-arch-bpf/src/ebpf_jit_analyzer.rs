//! eBPF JIT output analyser: maps BPF instructions to native code blocks.
//!
//! Parses the sysfs or debug-fs JIT dump produced by the Linux kernel
//! (`/sys/kernel/debug/bpf/<prog_id>/jited_insns`) and maps each native
//! code range back to the originating eBPF instruction index.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── JIT constants ────────────────────────────────────────────────────────────

/// Recognised native architectures for JIT output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JitArch {
    X86_64,
    Aarch64,
    S390x,
    Powerpc64,
    Mips64,
    Unknown,
}

impl fmt::Display for JitArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86_64 => write!(f, "x86_64"),
            Self::Aarch64 => write!(f, "aarch64"),
            Self::S390x => write!(f, "s390x"),
            Self::Powerpc64 => write!(f, "powerpc64"),
            Self::Mips64 => write!(f, "mips64"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─── JitMapping ───────────────────────────────────────────────────────────────

/// Mapping from one eBPF instruction to its JIT-generated native code range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitMapping {
    /// Zero-based index of the eBPF instruction.
    pub bpf_insn_idx: usize,
    /// Start offset within the JIT output buffer (bytes).
    pub native_start: u64,
    /// Exclusive end offset within the JIT output buffer (bytes).
    pub native_end: u64,
    /// Raw native bytes for this mapping range.
    pub native_bytes: Vec<u8>,
    /// Disassembly lines (one per native instruction), if available.
    pub disasm: Vec<String>,
}

impl JitMapping {
    /// Return the size in bytes of this native code range.
    #[must_use] 
    pub const fn native_size(&self) -> u64 {
        self.native_end.saturating_sub(self.native_start)
    }

    /// Average bytes per BPF instruction for this mapping (always 1.0 for a
    /// single BPF insn → many native insns mapping).
    #[must_use] 
    pub const fn expansion_ratio(&self) -> f64 {
        self.native_size() as f64
    }
}

impl fmt::Display for JitMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bpf[{}] → native[{:#010x}..{:#010x}] ({} bytes, {} native insns)",
            self.bpf_insn_idx,
            self.native_start,
            self.native_end,
            self.native_size(),
            self.disasm.len(),
        )
    }
}

// ─── NativeBlock ─────────────────────────────────────────────────────────────

/// A contiguous block of native instructions with optional debug metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeBlock {
    /// Offset from start of the JIT buffer.
    pub offset: u64,
    /// Raw instruction bytes.
    pub bytes: Vec<u8>,
    /// Decoded mnemonic text (e.g. `"mov rax, rbx"`).
    pub mnemonic: String,
    /// Length of the instruction in bytes.
    pub length: usize,
    /// Whether this instruction is a branch.
    pub is_branch: bool,
    /// Branch target offset, if `is_branch` is true.
    pub branch_target: Option<u64>,
}

impl NativeBlock {
    /// Create a native block from raw bytes with a placeholder mnemonic.
    #[must_use] 
    pub fn from_bytes(offset: u64, bytes: Vec<u8>) -> Self {
        let mnemonic = disassemble_x86_stub(&bytes);
        let length = bytes.len();
        let is_branch = length > 0 && is_x86_branch(bytes[0]);
        let branch_target = if is_branch && length >= 2 {
            Some(offset.wrapping_add(length as u64).wrapping_add(u64::from(bytes[1])))
        } else {
            None
        };
        Self {
            offset,
            bytes,
            mnemonic,
            length,
            is_branch,
            branch_target,
        }
    }
}

impl fmt::Display for NativeBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}: {} ({}B)", self.offset, self.mnemonic, self.length)
    }
}

/// Trivial x86 opcode → mnemonic lookup for demo purposes.
fn disassemble_x86_stub(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "<empty>".to_string();
    }
    match bytes[0] {
        0x90 => "nop".to_string(),
        0xC3 => "ret".to_string(),
        0x55 => "push rbp".to_string(),
        0x5D => "pop rbp".to_string(),
        0x48 if bytes.len() >= 3 && bytes[1] == 0x89 => format!("mov r{}, r{}", bytes[2] & 7, (bytes[2] >> 3) & 7),
        0x48 if bytes.len() >= 4 && bytes[1] == 0x8B => format!("mov r{}, [r{}+0x{:x}]", (bytes[2] >> 3) & 7, bytes[2] & 7, if bytes.len() > 3 { bytes[3] } else { 0 }),
        0xEB => format!("jmp +0x{:02x}", bytes.get(1).copied().unwrap_or(0)),
        0x74 => format!("je +0x{:02x}", bytes.get(1).copied().unwrap_or(0)),
        0x75 => format!("jne +0x{:02x}", bytes.get(1).copied().unwrap_or(0)),
        0xFF if bytes.len() >= 2 && bytes[1] == 0xD0 => "call rax".to_string(),
        0xE8 => {
            let rel = if bytes.len() >= 5 {
                i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]])
            } else {
                0
            };
            format!("call rel+{rel}")
        }
        b => format!("db 0x{b:02x}"),
    }
}

const fn is_x86_branch(opcode: u8) -> bool {
    matches!(opcode, 0xEB | 0x74 | 0x75 | 0x72 | 0x73 | 0x76 | 0x77 | 0xE9 | 0xE8)
}

// ─── JitDump ──────────────────────────────────────────────────────────────────

/// A parsed JIT dump for a single eBPF program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitDump {
    /// The program ID (kernel sysfs id).
    pub prog_id: u32,
    /// Detected native architecture.
    pub arch: JitArch,
    /// Total size of the JIT buffer in bytes.
    pub total_native_bytes: u64,
    /// All per-instruction mappings, ordered by BPF instruction index.
    pub mappings: Vec<JitMapping>,
    /// All native blocks parsed from the JIT buffer.
    pub blocks: Vec<NativeBlock>,
}

impl JitDump {
    /// Look up the native code range for a BPF instruction index.
    #[must_use] 
    pub fn mapping_for_bpf(&self, idx: usize) -> Option<&JitMapping> {
        self.mappings.iter().find(|m| m.bpf_insn_idx == idx)
    }

    /// Return the native offset for a given BPF instruction index.
    #[must_use] 
    pub fn jit_offset_for_bpf(&self, bpf_idx: usize) -> Option<u64> {
        self.mapping_for_bpf(bpf_idx).map(|m| m.native_start)
    }

    /// Total number of native bytes generated.
    #[must_use] 
    pub const fn native_size(&self) -> u64 {
        self.total_native_bytes
    }

    /// Average code expansion factor (native bytes / BPF instruction count).
    #[must_use] 
    pub fn expansion_factor(&self) -> f64 {
        if self.mappings.is_empty() {
            0.0
        } else {
            self.total_native_bytes as f64 / self.mappings.len() as f64
        }
    }

    /// Return the BPF instruction with the largest native code expansion.
    #[must_use] 
    pub fn hottest_insn(&self) -> Option<&JitMapping> {
        self.mappings.iter().max_by_key(|m| m.native_size())
    }

    /// Build a map from native address to BPF instruction index.
    #[must_use] 
    pub fn native_to_bpf_map(&self) -> HashMap<u64, usize> {
        let mut map = HashMap::new();
        for m in &self.mappings {
            for addr in m.native_start..m.native_end {
                map.entry(addr).or_insert(m.bpf_insn_idx);
            }
        }
        map
    }
}

// ─── EbpfJitAnalyzer ──────────────────────────────────────────────────────────

/// Analyses eBPF JIT output: parses native code, constructs mappings, and
/// provides query helpers.
pub struct EbpfJitAnalyzer {
    /// The arch we parse for.
    arch: JitArch,
    /// Whether to attempt disassembly of individual native instructions.
    disassemble: bool,
}

impl EbpfJitAnalyzer {
    /// Create an analyser for the given architecture.
    #[must_use] 
    pub const fn new(arch: JitArch) -> Self {
        Self { arch, disassemble: true }
    }

    /// Disable disassembly (useful when only offset mapping is needed).
    #[must_use] 
    pub const fn without_disasm(mut self) -> Self {
        self.disassemble = false;
        self
    }

    /// Parse a raw JIT buffer (`native_bytes`) paired with a BPF-to-native
    /// offset table (`bpf_to_native_offsets`: BPF insn idx → offset in native).
    ///
    /// Returns a fully populated [`JitDump`].
    #[must_use] 
    pub fn analyse(
        &self,
        prog_id: u32,
        native_bytes: &[u8],
        bpf_to_native_offsets: &[(usize, u64)],
    ) -> JitDump {
        // Build sorted offset pairs.
        let mut sorted = bpf_to_native_offsets.to_vec();
        sorted.sort_by_key(|&(_, off)| off);

        let mut mappings = Vec::new();
        for i in 0..sorted.len() {
            let (bpf_idx, native_start) = sorted[i];
            let native_end = if i + 1 < sorted.len() {
                sorted[i + 1].1
            } else {
                native_bytes.len() as u64
            };
            let start = native_start as usize;
            let end = (native_end as usize).min(native_bytes.len());
            let chunk = if start < end {
                native_bytes[start..end].to_vec()
            } else {
                vec![]
            };

            let disasm = if self.disassemble {
                self.decode_instructions(&chunk, native_start)
                    .iter()
                    .map(|b| format!("{b}"))
                    .collect()
            } else {
                vec![]
            };

            mappings.push(JitMapping {
                bpf_insn_idx: bpf_idx,
                native_start,
                native_end,
                native_bytes: chunk,
                disasm,
            });
        }

        // Parse native blocks from the full buffer.
        let blocks = self.parse_native_blocks(native_bytes);

        JitDump {
            prog_id,
            arch: self.arch,
            total_native_bytes: native_bytes.len() as u64,
            mappings,
            blocks,
        }
    }

    /// Decode a byte slice into a list of [`NativeBlock`]s using a
    /// simple length-constrained walk (no full disassembler required).
    fn decode_instructions(&self, bytes: &[u8], base_offset: u64) -> Vec<NativeBlock> {
        let mut blocks = Vec::new();
        let mut pos = 0usize;
        while pos < bytes.len() {
            let insn_len = self.estimate_insn_length(&bytes[pos..]);
            let end = (pos + insn_len).min(bytes.len());
            let chunk = bytes[pos..end].to_vec();
            blocks.push(NativeBlock::from_bytes(base_offset + pos as u64, chunk));
            pos += insn_len;
        }
        blocks
    }

    /// Parse the entire JIT buffer into native blocks.
    fn parse_native_blocks(&self, bytes: &[u8]) -> Vec<NativeBlock> {
        self.decode_instructions(bytes, 0)
    }

    /// Very rough instruction-length estimator for x86-64 (covers common JIT
    /// patterns).  Falls back to 1 byte to avoid getting stuck.
    fn estimate_insn_length(&self, bytes: &[u8]) -> usize {
        if bytes.is_empty() {
            return 1;
        }
        match self.arch {
            JitArch::X86_64 => {
                let b0 = bytes[0];
                // REX prefix
                let (prefix_len, b0) = if b0 & 0xF0 == 0x40 {
                    (1usize, if bytes.len() > 1 { bytes[1] } else { 0 })
                } else {
                    (0, b0)
                };
                let base = match b0 {
                    // Group 1 immediate: 0x83 takes imm8, 0x81 takes imm32.
                    0x83 | 0x81 => {
                        let imm = if b0 == 0x83 { 1 } else { 4 };
                        2 + imm
                    }
                    // Two-byte opcode escape.
                    0x0F if bytes.len() > prefix_len + 1 => {
                        match bytes[prefix_len + 1] {
                            0x84 | 0x85 | 0x8C..=0x8F => 6, // Jcc rel32
                            _ => 3,
                        }
                    }
                    other => x86_base_len(other),
                };
                prefix_len + base
            }
            // Aarch64 and Powerpc64 both use fixed 4-byte instructions.
            JitArch::Aarch64 | JitArch::Powerpc64 => 4,
            _ => 1,
        }
    }

    /// Detect whether a JIT buffer looks like `x86_64` code (heuristic).
    #[must_use] 
    pub fn detect_arch(bytes: &[u8]) -> JitArch {
        if bytes.len() < 4 {
            return JitArch::Unknown;
        }
        // x86_64: prologue often starts with 55 (push rbp) or 48 xx (REX prefix)
        if bytes[0] == 0x55 || (bytes[0] & 0xF0 == 0x40) {
            return JitArch::X86_64;
        }
        // AArch64: all instructions are 4-byte aligned; check for common patterns
        let insn = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if insn >> 23 == 0b101 {
            // BL or B instruction class
            return JitArch::Aarch64;
        }
        JitArch::Unknown
    }
}

/// Find the JIT native offset for a BPF instruction index.
///
/// Convenience free function that wraps [`JitDump::jit_offset_for_bpf`].
#[must_use] 
pub fn jit_offset_for_bpf(dump: &JitDump, bpf_idx: usize) -> Option<u64> {
    dump.jit_offset_for_bpf(bpf_idx)
}

// ─── JitStat ─────────────────────────────────────────────────────────────────

/// Statistical summary of JIT expansion metrics for a program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitStat {
    pub bpf_insn_count: usize,
    pub native_byte_count: u64,
    pub avg_bytes_per_insn: f64,
    pub min_native: u64,
    pub max_native: u64,
    pub branch_count: usize,
}

impl JitStat {
    /// Compute statistics from a [`JitDump`].
    #[must_use] 
    pub fn from_dump(dump: &JitDump) -> Self {
        let n = dump.mappings.len();
        if n == 0 {
            return Self {
                bpf_insn_count: 0,
                native_byte_count: 0,
                avg_bytes_per_insn: 0.0,
                min_native: 0,
                max_native: 0,
                branch_count: 0,
            };
        }
        let sizes: Vec<u64> = dump.mappings.iter().map(JitMapping::native_size).collect();
        let min_native = *sizes.iter().min().unwrap_or(&0);
        let max_native = *sizes.iter().max().unwrap_or(&0);
        let branch_count = dump.blocks.iter().filter(|b| b.is_branch).count();
        Self {
            bpf_insn_count: n,
            native_byte_count: dump.total_native_bytes,
            avg_bytes_per_insn: dump.total_native_bytes as f64 / n as f64,
            min_native,
            max_native,
            branch_count,
        }
    }
}

impl fmt::Display for JitStat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "JitStat: bpf={} native_bytes={} avg={:.1} min={} max={} branches={}",
            self.bpf_insn_count,
            self.native_byte_count,
            self.avg_bytes_per_insn,
            self.min_native,
            self.max_native,
            self.branch_count,
        )
    }
}

/// Ordered `(lo, hi, len)` rows giving the base length (excluding any REX
/// prefix) of the single-byte x86-64 opcodes this analyser recognises. Scanned
/// in order by [`x86_base_len`]; the first row containing the opcode wins, so
/// each opcode keeps its own row and its own comment. Opcodes with no row are
/// assumed to be one byte long.
const X86_BASE_LEN_TABLE: &[(u8, u8, usize)] = &[
    (0x90, 0x90, 1), // NOP
    (0xC3, 0xC3, 1), // RET
    (0xC9, 0xC9, 1), // LEAVE
    (0x55, 0x55, 1), // PUSH rbp
    (0x5D, 0x5D, 1), // POP rbp
    (0x53, 0x5F, 1), // PUSH/POP r8-r15
    (0xEB, 0xEB, 2), // JMP short
    (0x72, 0x77, 2), // Jcc short
    (0xE9, 0xE9, 5), // JMP rel32
    (0xE8, 0xE8, 5), // CALL rel32
    (0x89, 0x89, 3), // MOV r/m, r (ModRM)
    (0x8B, 0x8B, 3), // MOV r, r/m (ModRM)
    (0xB8, 0xBF, 5), // MOV rXX, imm32
    (0xFF, 0xFF, 2), // indirect call/jmp
];

/// Base length of a single-byte x86-64 opcode, defaulting to one byte.
const fn x86_base_len(op: u8) -> usize {
    let mut i = 0;
    while i < X86_BASE_LEN_TABLE.len() {
        let (lo, hi, len) = X86_BASE_LEN_TABLE[i];
        if op >= lo && op <= hi {
            return len;
        }
        i += 1;
    }
    1
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_x86_nops(n: usize) -> Vec<u8> {
        vec![0x90u8; n]
    }

    #[test]
    fn test_analyse_basic() {
        let native = make_x86_nops(30);
        let offsets = vec![(0usize, 0u64), (1, 10), (2, 20)];
        let analyzer = EbpfJitAnalyzer::new(JitArch::X86_64);
        let dump = analyzer.analyse(42, &native, &offsets);
        assert_eq!(dump.prog_id, 42);
        assert_eq!(dump.mappings.len(), 3);
        assert_eq!(dump.mappings[0].native_size(), 10);
    }

    #[test]
    fn test_jit_offset_for_bpf() {
        let native = make_x86_nops(20);
        let offsets = vec![(0usize, 0u64), (1, 8), (2, 16)];
        let analyzer = EbpfJitAnalyzer::new(JitArch::X86_64);
        let dump = analyzer.analyse(1, &native, &offsets);
        assert_eq!(jit_offset_for_bpf(&dump, 1), Some(8));
        assert_eq!(jit_offset_for_bpf(&dump, 99), None);
    }

    #[test]
    fn test_expansion_factor() {
        let native = make_x86_nops(40);
        let offsets: Vec<(usize, u64)> = (0..4).map(|i| (i, (i * 10) as u64)).collect();
        let analyzer = EbpfJitAnalyzer::new(JitArch::X86_64);
        let dump = analyzer.analyse(0, &native, &offsets);
        assert_eq!(dump.expansion_factor(), 10.0);
    }

    #[test]
    fn test_hottest_insn() {
        let native = vec![0x90u8; 50];
        // Mapping 1 is 30 bytes, mapping 0 is 20 bytes.
        let offsets = vec![(0, 0u64), (1, 20u64)];
        let analyzer = EbpfJitAnalyzer::new(JitArch::X86_64);
        let dump = analyzer.analyse(0, &native, &offsets);
        let hot = dump.hottest_insn().unwrap();
        assert_eq!(hot.bpf_insn_idx, 1);
    }

    #[test]
    fn test_native_block_decode() {
        let bytes = vec![0x90, 0xC3]; // nop; ret
        let analyzer = EbpfJitAnalyzer::new(JitArch::X86_64);
        let blocks = analyzer.decode_instructions(&bytes, 0x1000);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].mnemonic, "nop");
        assert_eq!(blocks[1].mnemonic, "ret");
    }

    #[test]
    fn test_detect_arch_x86() {
        let bytes = vec![0x55, 0x48, 0x89, 0xE5];
        assert_eq!(EbpfJitAnalyzer::detect_arch(&bytes), JitArch::X86_64);
    }

    #[test]
    fn test_jitstat() {
        let native = make_x86_nops(30);
        let offsets = vec![(0, 0u64), (1, 10), (2, 20)];
        let analyzer = EbpfJitAnalyzer::new(JitArch::X86_64);
        let dump = analyzer.analyse(0, &native, &offsets);
        let stat = JitStat::from_dump(&dump);
        assert_eq!(stat.bpf_insn_count, 3);
        assert_eq!(stat.native_byte_count, 30);
        assert!((stat.avg_bytes_per_insn - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_native_to_bpf_map() {
        let native = make_x86_nops(20);
        let offsets = vec![(0, 0u64), (1, 10)];
        let analyzer = EbpfJitAnalyzer::new(JitArch::X86_64);
        let dump = analyzer.analyse(0, &native, &offsets);
        let map = dump.native_to_bpf_map();
        assert_eq!(map.get(&0), Some(&0));
        assert_eq!(map.get(&10), Some(&1));
        assert_eq!(map.get(&5), Some(&0));
    }

    #[test]
    fn test_aarch64_fixed_width() {
        let native = vec![0u8; 16]; // 4 x AArch64 instructions
        let offsets = vec![(0, 0u64), (1, 4), (2, 8), (3, 12)];
        let analyzer = EbpfJitAnalyzer::new(JitArch::Aarch64);
        let dump = analyzer.analyse(0, &native, &offsets);
        for m in &dump.mappings {
            assert_eq!(m.native_size(), 4);
        }
    }
}
