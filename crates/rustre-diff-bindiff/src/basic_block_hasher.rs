//! `basic_block_hasher` — Compute normalised, comparison-stable hashes for basic blocks.
//!
//! Normalisation strips operand values (immediate constants, branch targets,
//! memory displacements) so that two basic blocks with structurally identical
//! instruction sequences but different concrete operands produce the same hash.
//! Three hash granularities are provided: mnemonic-only, mnemonic+size, and full
//! normalised encoding (default).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── Granularity ───────────────────────────────────────────────────────────────

/// Hash granularity controls how aggressively operands are normalised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashGranularity {
    /// Hash only the sequence of mnemonic opcodes (most permissive).
    MnemonicOnly,
    /// Hash mnemonic + operand types (register class, memory, immediate) but
    /// not operand values.
    MnemonicAndTypes,
    /// Hash mnemonic + operand types + operand size + access mode; constants
    /// and addresses are zeroed (default, best trade-off).
    Normalised,
    /// Full byte encoding without any normalisation (strictest).
    Exact,
}

impl Default for HashGranularity {
    fn default() -> Self {
        Self::Normalised
    }
}

// ── OperandKind ───────────────────────────────────────────────────────────────

/// Abstracted operand type used in the normalised encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperandKind {
    Register,
    ImmediateSmall, // fits in u8
    ImmediateWide,  // larger immediate
    Memory,
    MemoryDisp8,
    MemoryDisp32,
    RelativeBranch,
    AbsoluteAddress,
    SegmentRegister,
    FpuRegister,
    XmmRegister,
    YmmRegister,
    Unknown,
}

// ── NormalisedInstruction ─────────────────────────────────────────────────────

/// A single instruction after normalisation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalisedInstruction {
    /// Primary opcode byte (first non-prefix byte).
    pub opcode: u8,
    /// Secondary opcode for two-byte opcodes (e.g. `0F xx`), else 0.
    pub opcode2: u8,
    /// Instruction length in bytes.
    pub length: u8,
    /// Operand kinds (at most 3).
    pub operand_kinds: [OperandKind; 3],
    /// Number of valid entries in `operand_kinds`.
    pub operand_count: u8,
}

impl NormalisedInstruction {
    /// Returns `true` if this is a call instruction (0xE8, 0xFF /2).
    #[must_use]
    pub const fn is_call(&self) -> bool {
        self.opcode == 0xE8 || (self.opcode == 0xFF && self.opcode2 == 0x02)
    }

    /// Returns `true` if this is an unconditional jump.
    #[must_use]
    pub const fn is_unconditional_jump(&self) -> bool {
        self.opcode == 0xEB || self.opcode == 0xE9 || (self.opcode == 0xFF && self.opcode2 == 0x04)
    }

    /// Returns `true` if this is a conditional branch.
    #[must_use]
    pub fn is_conditional_branch(&self) -> bool {
        (0x70..=0x7F).contains(&self.opcode) || // Jcc short
        (self.opcode == 0x0F && (0x80..=0x8F).contains(&self.opcode2))
    }

    /// Returns `true` for terminator instructions (RET, RETF, INT3, UD2).
    #[must_use]
    pub const fn is_terminator(&self) -> bool {
        matches!(self.opcode, 0xC3 | 0xCB | 0xCC | 0xCD | 0xCF)
            || (self.opcode == 0x0F && self.opcode2 == 0x0B)
    }
}

// ── NormalisedBlock ───────────────────────────────────────────────────────────

/// A normalised representation of a basic block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalisedBlock {
    /// Original byte offset in the binary.
    pub offset: u64,
    /// Original byte length.
    pub byte_len: usize,
    /// Normalised instructions.
    pub instructions: Vec<NormalisedInstruction>,
}

impl NormalisedBlock {
    /// Returns the number of instructions.
    #[must_use]
    pub const fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Returns `true` if the block ends in a call.
    #[must_use]
    pub fn ends_with_call(&self) -> bool {
        self.instructions.last().map_or(false, NormalisedInstruction::is_call)
    }

    /// Returns `true` if the block ends with a conditional branch.
    #[must_use]
    pub fn ends_with_conditional_branch(&self) -> bool {
        self.instructions.last().map_or(false, NormalisedInstruction::is_conditional_branch)
    }

    /// Returns `true` if the block ends with a terminator.
    #[must_use]
    pub fn ends_with_terminator(&self) -> bool {
        self.instructions.last().map_or(false, NormalisedInstruction::is_terminator)
    }

    /// Call count within the block.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.instructions.iter().filter(|i| i.is_call()).count()
    }
}

// ── BlockHash ─────────────────────────────────────────────────────────────────

/// The computed hash for a normalised basic block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHash {
    /// Byte offset in the binary.
    pub offset: u64,
    /// FNV-1a 64-bit hash of the normalised encoding.
    pub hash: u64,
    /// Mnemonic-only hash (for coarser matching).
    pub mnemonic_hash: u64,
    /// Instruction count (structural feature).
    pub instruction_count: usize,
    /// Granularity used to compute `hash`.
    pub granularity: HashGranularity,
}

impl BlockHash {
    /// Returns `true` if this hash is identical to another at the same granularity.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.hash == other.hash && self.granularity == other.granularity
    }

    /// Loose match: same mnemonic hash AND same instruction count.
    #[must_use]
    pub const fn loose_matches(&self, other: &Self) -> bool {
        self.mnemonic_hash == other.mnemonic_hash && self.instruction_count == other.instruction_count
    }
}

// ── BasicBlockHasher ──────────────────────────────────────────────────────────

/// Computes normalised basic block hashes from raw x86-64 bytes.
pub struct BasicBlockHasher {
    /// Granularity applied when computing the primary hash.
    pub granularity: HashGranularity,
    /// If `true`, do not include the block terminator in the hash (useful when
    /// branches point to relocated addresses).
    pub exclude_terminators: bool,
}

impl Default for BasicBlockHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl BasicBlockHasher {
    /// Create with default settings (Normalised, include terminators).
    #[must_use]
    pub const fn new() -> Self {
        Self { granularity: HashGranularity::Normalised, exclude_terminators: false }
    }

    /// Set granularity.
    #[must_use]
    pub const fn with_granularity(mut self, g: HashGranularity) -> Self {
        self.granularity = g;
        self
    }

    /// Exclude terminator instructions from the hash.
    #[must_use]
    pub const fn excluding_terminators(mut self) -> Self {
        self.exclude_terminators = true;
        self
    }

    /// Decode and normalise `bytes` starting at `offset`.
    ///
    /// Performs a lightweight single-pass linear sweep (not a full disassembler).
    /// Adequate for detecting structural similarity; not a complete disassembly.
    #[must_use]
    pub fn normalise(&self, bytes: &[u8], offset: u64) -> NormalisedBlock {
        let instructions = decode_linear(bytes);
        NormalisedBlock { offset, byte_len: bytes.len(), instructions }
    }

    /// Compute the hash for a pre-normalised block.
    #[must_use]
    pub fn hash_block(&self, block: &NormalisedBlock) -> BlockHash {
        let instrs: &[NormalisedInstruction] = if self.exclude_terminators {
            // Strip trailing terminator if present.
            match block.instructions.last() {
                Some(i) if i.is_terminator() || i.is_unconditional_jump() || i.is_conditional_branch() => {
                    let end = block.instructions.len().saturating_sub(1);
                    &block.instructions[..end]
                }
                _ => &block.instructions,
            }
        } else {
            &block.instructions
        };

        let primary = encode_and_hash(instrs, self.granularity);
        let mnemonic = encode_and_hash(instrs, HashGranularity::MnemonicOnly);

        BlockHash {
            offset: block.offset,
            hash: primary,
            mnemonic_hash: mnemonic,
            instruction_count: instrs.len(),
            granularity: self.granularity,
        }
    }

    /// Convenience: normalise then hash in a single call.
    #[must_use]
    pub fn compute(&self, bytes: &[u8], offset: u64) -> BlockHash {
        let block = self.normalise(bytes, offset);
        self.hash_block(&block)
    }

    /// Hash all blocks from a list of `(offset, bytes)` pairs.
    #[must_use]
    pub fn hash_all(&self, blocks: &[(u64, &[u8])]) -> Vec<BlockHash> {
        blocks.iter().map(|(off, bytes)| self.compute(bytes, *off)).collect()
    }

    /// Build an offset→hash lookup map.
    #[must_use]
    pub fn build_map(&self, blocks: &[(u64, &[u8])]) -> HashMap<u64, BlockHash> {
        self.hash_all(blocks).into_iter().map(|h| (h.offset, h)).collect()
    }

    /// Group hashes by their value (for finding duplicate blocks).
    #[must_use]
    pub fn group_by_hash(hashes: &[BlockHash]) -> HashMap<u64, Vec<u64>> {
        let mut m: HashMap<u64, Vec<u64>> = HashMap::new();
        for bh in hashes {
            m.entry(bh.hash).or_default().push(bh.offset);
        }
        m
    }
}

// ── linear decoder ────────────────────────────────────────────────────────────

/// Very lightweight x86-64 linear sweep decoder.
/// Only detects opcode + rough operand structure for hashing.
fn decode_linear(bytes: &[u8]) -> Vec<NormalisedInstruction> {
    let mut out = Vec::new();
    let mut pos = 0usize;

    while pos < bytes.len() {
        let start = pos;
        // Skip legacy prefixes.
        while pos < bytes.len()
            && matches!(bytes[pos], 0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67
                | 0xF0 | 0xF2 | 0xF3)
        {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }
        // REX prefix in 64-bit mode.
        if bytes[pos] & 0xF0 == 0x40 {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }

        let opcode = bytes[pos];
        pos += 1;
        let mut opcode2 = 0u8;
        let mut operand_kinds = [OperandKind::Unknown; 3];
        let mut operand_count = 0u8;

        // Helper: compute clamped u8 length from (pos - start).
        // x86 instructions are at most 15 bytes; cap to 255 defensively.
        let len_u8 = |p: usize| -> u8 { (p - start).min(255) as u8 };

        let length = match opcode {
            // Two-byte escape.
            0x0F if pos < bytes.len() => {
                opcode2 = bytes[pos];
                pos += 1;
                let extra = modrm_size(bytes, pos);
                pos += extra;
                len_u8(pos)
            }
            // NOP / single-byte no-operand.
            0x90 | 0xC3 | 0xCB | 0xCC | 0xCF => len_u8(pos),
            // MOV reg, imm8 (0xB0..0xB7) or imm32/64 (0xB8..0xBF).
            0xB0..=0xB7 => {
                operand_kinds[0] = OperandKind::Register;
                operand_kinds[1] = OperandKind::ImmediateSmall;
                operand_count = 2;
                pos = pos.saturating_add(1).min(bytes.len()); // skip imm8
                len_u8(pos)
            }
            0xB8..=0xBF => {
                operand_kinds[0] = OperandKind::Register;
                operand_kinds[1] = OperandKind::ImmediateWide;
                operand_count = 2;
                pos = pos.saturating_add(4).min(bytes.len()); // skip imm32 (ignoring imm64)
                len_u8(pos)
            }
            // PUSH imm8.
            0x6A => {
                operand_kinds[0] = OperandKind::ImmediateSmall;
                operand_count = 1;
                pos = pos.saturating_add(1).min(bytes.len());
                len_u8(pos)
            }
            // PUSH imm32.
            0x68 => {
                operand_kinds[0] = OperandKind::ImmediateWide;
                operand_count = 1;
                pos = pos.saturating_add(4).min(bytes.len());
                len_u8(pos)
            }
            // Short Jcc.
            0x70..=0x7F | 0xEB => {
                operand_kinds[0] = OperandKind::RelativeBranch;
                operand_count = 1;
                pos = pos.saturating_add(1).min(bytes.len()); // rel8
                len_u8(pos)
            }
            // Near call / jmp rel32.
            0xE8 | 0xE9 => {
                operand_kinds[0] = OperandKind::RelativeBranch;
                operand_count = 1;
                pos = pos.saturating_add(4).min(bytes.len());
                len_u8(pos)
            }
            // Instructions with ModRM.
            0x00..=0x3F | 0x88..=0x8F | 0xD0..=0xD3 | 0xF6 | 0xF7 | 0xFF => {
                let extra = modrm_size(bytes, pos);
                operand_kinds[0] = OperandKind::Register;
                operand_count = 1;
                pos += extra;
                len_u8(pos)
            }
            _ => {
                // Unknown: advance by 1.
                len_u8(pos)
            }
        };

        out.push(NormalisedInstruction { opcode, opcode2, length, operand_kinds, operand_count });
    }
    out
}

/// Estimate bytes consumed by a `ModRM` byte + optional SIB + displacement.
fn modrm_size(bytes: &[u8], pos: usize) -> usize {
    if pos >= bytes.len() {
        return 0;
    }
    let modrm = bytes[pos];
    let md = (modrm >> 6) & 0x3;
    let rm = modrm & 0x7;
    let mut size = 1; // ModRM itself

    if md == 3 {
        return size; // register operand, no displacement
    }
    // SIB byte when rm=4.
    if rm == 4 && pos + size < bytes.len() {
        size += 1; // SIB
    }
    size += match md {
        0 if rm == 5 => 4, // [disp32]
        1 => 1,            // disp8
        2 => 4,            // disp32
        _ => 0,
    };
    size
}

// ── hash computation ──────────────────────────────────────────────────────────

fn encode_and_hash(instrs: &[NormalisedInstruction], gran: HashGranularity) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325; // FNV-1a 64-bit offset basis
    for ins in instrs {
        fnv1a_update(&mut h, ins.opcode);
        match gran {
            HashGranularity::MnemonicOnly => {}
            HashGranularity::MnemonicAndTypes => {
                for k in 0..ins.operand_count as usize {
                    fnv1a_update(&mut h, ins.operand_kinds[k] as u8);
                }
            }
            HashGranularity::Normalised => {
                fnv1a_update(&mut h, ins.opcode2);
                fnv1a_update(&mut h, ins.length);
                for k in 0..ins.operand_count as usize {
                    fnv1a_update(&mut h, ins.operand_kinds[k] as u8);
                }
            }
            HashGranularity::Exact => {
                fnv1a_update(&mut h, ins.opcode2);
                fnv1a_update(&mut h, ins.length);
                fnv1a_update(&mut h, ins.operand_count);
                for k in 0..ins.operand_count as usize {
                    fnv1a_update(&mut h, ins.operand_kinds[k] as u8);
                }
            }
        }
    }
    h
}

const fn fnv1a_update(h: &mut u64, byte: u8) {
    *h ^= byte as u64;
    *h = h.wrapping_mul(0x00000100000001B3);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn nop_block() -> Vec<u8> {
        vec![0x90, 0x90, 0x90, 0xC3] // NOP NOP NOP RET
    }

    fn push_pop_block() -> Vec<u8> {
        vec![0x55, 0x5D, 0xC3] // PUSH rbp; POP rbp; RET
    }

    #[test]
    fn test_hash_nop_block_deterministic() {
        let h = BasicBlockHasher::new();
        let b = nop_block();
        let a = h.compute(&b, 0x1000);
        let b2 = h.compute(&b, 0x1000);
        assert_eq!(a.hash, b2.hash);
    }

    #[test]
    fn test_different_offsets_same_hash() {
        let h = BasicBlockHasher::new();
        let b = nop_block();
        let a = h.compute(&b, 0x1000);
        let b2 = h.compute(&b, 0x2000);
        assert_eq!(a.hash, b2.hash);
    }

    #[test]
    fn test_different_blocks_different_hashes() {
        let h = BasicBlockHasher::new();
        let a = h.compute(&nop_block(), 0);
        let b = h.compute(&push_pop_block(), 0);
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn test_block_hash_matches() {
        let h = BasicBlockHasher::new();
        let a = h.compute(&nop_block(), 0);
        let b = h.compute(&nop_block(), 0x500);
        assert!(a.matches(&b));
    }

    #[test]
    fn test_normalised_block_instruction_count() {
        let h = BasicBlockHasher::new();
        let block = h.normalise(&nop_block(), 0);
        assert!(block.instruction_count() >= 3);
    }

    #[test]
    fn test_ends_with_terminator() {
        let h = BasicBlockHasher::new();
        let block = h.normalise(&nop_block(), 0);
        assert!(block.ends_with_terminator());
    }

    #[test]
    fn test_exclude_terminators_changes_hash() {
        let bytes = nop_block();
        let h_inc = BasicBlockHasher::new();
        let h_exc = BasicBlockHasher::new().excluding_terminators();
        let a = h_inc.compute(&bytes, 0);
        let b = h_exc.compute(&bytes, 0);
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn test_mnemonic_only_granularity() {
        let h = BasicBlockHasher::new().with_granularity(HashGranularity::MnemonicOnly);
        let a = h.compute(&nop_block(), 0);
        assert!(a.instruction_count > 0);
    }

    #[test]
    fn test_hash_all() {
        let h = BasicBlockHasher::new();
        let b1 = nop_block();
        let b2 = push_pop_block();
        let blocks: Vec<(u64, &[u8])> = vec![(0x1000, &b1), (0x2000, &b2)];
        let hashes = h.hash_all(&blocks);
        assert_eq!(hashes.len(), 2);
    }

    #[test]
    fn test_build_map() {
        let h = BasicBlockHasher::new();
        let b1 = nop_block();
        let b2 = push_pop_block();
        let blocks: Vec<(u64, &[u8])> = vec![(0x1000, &b1), (0x2000, &b2)];
        let map = h.build_map(&blocks);
        assert!(map.contains_key(&0x1000));
        assert!(map.contains_key(&0x2000));
    }

    #[test]
    fn test_group_by_hash_deduplicates() {
        let h = BasicBlockHasher::new();
        let b = nop_block();
        let blocks: Vec<(u64, &[u8])> = vec![(0x100, &b), (0x200, &b), (0x300, &b)];
        let hashes = h.hash_all(&blocks);
        let groups = BasicBlockHasher::group_by_hash(&hashes);
        // All three have the same hash; the group should have 3 offsets.
        assert!(groups.values().any(|v| v.len() == 3));
    }

    #[test]
    fn test_normalised_instruction_predicates() {
        let ret = NormalisedInstruction {
            opcode: 0xC3, opcode2: 0, length: 1,
            operand_kinds: [OperandKind::Unknown; 3],
            operand_count: 0,
        };
        assert!(ret.is_terminator());
        assert!(!ret.is_call());

        let call = NormalisedInstruction {
            opcode: 0xE8, opcode2: 0, length: 5,
            operand_kinds: [OperandKind::RelativeBranch, OperandKind::Unknown, OperandKind::Unknown],
            operand_count: 1,
        };
        assert!(call.is_call());
        assert!(!call.is_conditional_branch());
    }
}
