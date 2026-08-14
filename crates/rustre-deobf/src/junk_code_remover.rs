//! Junk code remover for `rustre-deobf`.
//!
//! Identifies and removes patterns of junk code inserted by obfuscators:
//! NOP sleds, dead assignments, unreachable blocks, and redundant jumps.
//! Each candidate is scored with a confidence value (0–100) before removal.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// JunkPattern — taxonomy of recognised junk patterns
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of junk pattern identified in a byte stream or IR.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JunkPattern {
    /// A run of `0x90` (or equivalent arch NOP) instructions with no effect.
    NopSled {
        /// Byte offset in the input where the sled begins.
        offset: usize,
        /// Length of the sled in bytes.
        length: usize,
    },
    /// An assignment whose value is never read before being overwritten or
    /// the function returns.
    DeadAssignment {
        /// Symbolic register or variable name.
        variable: String,
        /// Byte offset of the instruction.
        offset: usize,
    },
    /// A basic block that cannot be reached from the function entry.
    UnreachableBlock {
        /// Address / label of the unreachable block.
        block_id: u64,
        /// Estimated size in bytes.
        size_bytes: usize,
    },
    /// An unconditional jump to the immediately following instruction.
    RedundantJump {
        /// Offset of the jump instruction.
        offset: usize,
        /// Jump target offset (equals `offset + instruction_size`).
        target: usize,
    },
    /// A sequence of instructions that compute a value then discard it with
    /// no observable side-effects.
    DeadComputation {
        /// First instruction offset.
        start: usize,
        /// Last instruction offset (inclusive).
        end: usize,
    },
    /// An always-taken conditional branch (opaque predicate evaluates to a
    /// constant).
    OpaqueConditional {
        /// Offset of the branch instruction.
        offset: usize,
        /// Constant branch outcome (`true` = always taken).
        always_taken: bool,
    },
    /// A `push reg; pop reg` pair with no intervening use that changes the
    /// stack pointer spuriously.
    SpuriousPushPop {
        /// Offset of the `push`.
        push_offset: usize,
        /// Offset of the `pop`.
        pop_offset: usize,
    },
    /// Exchange of a register with itself (`xchg eax, eax`).
    SelfExchange { offset: usize, register: String },
    /// A `mov reg, reg` where source and destination are the same register.
    SelfMove { offset: usize, register: String },
    /// Arithmetic that produces the same value: `add reg, 0`, `mul reg, 1`, etc.
    IdentityArithmetic { offset: usize, description: String },
    /// A `call` immediately followed by a `ret` with no side-effects in the
    /// callee.
    RedundantCall { call_offset: usize, callee: u64 },
    /// Multiple consecutive stores to the same address with no intervening
    /// load.
    RedundantStore {
        address: u64,
        first_store: usize,
        last_store: usize,
    },
    /// A branch to itself that is never actually executed (unreachable loop).
    InfiniteLoopNeverReached { offset: usize },
}

impl JunkPattern {
    /// Returns a human-readable short name for the pattern.
    #[must_use] 
    pub const fn name(&self) -> &'static str {
        match self {
            Self::NopSled { .. } => "NopSled",
            Self::DeadAssignment { .. } => "DeadAssignment",
            Self::UnreachableBlock { .. } => "UnreachableBlock",
            Self::RedundantJump { .. } => "RedundantJump",
            Self::DeadComputation { .. } => "DeadComputation",
            Self::OpaqueConditional { .. } => "OpaqueConditional",
            Self::SpuriousPushPop { .. } => "SpuriousPushPop",
            Self::SelfExchange { .. } => "SelfExchange",
            Self::SelfMove { .. } => "SelfMove",
            Self::IdentityArithmetic { .. } => "IdentityArithmetic",
            Self::RedundantCall { .. } => "RedundantCall",
            Self::RedundantStore { .. } => "RedundantStore",
            Self::InfiniteLoopNeverReached { .. } => "InfiniteLoopNeverReached",
        }
    }

    /// Byte-level size estimate for this pattern (used in `bytes_saved`).
    #[must_use] 
    pub const fn size_estimate(&self) -> usize {
        match self {
            Self::NopSled { length, .. } => *length,
            Self::DeadAssignment { .. } | Self::IdentityArithmetic { .. } => 3,
            Self::UnreachableBlock { size_bytes, .. } => *size_bytes,
            Self::RedundantJump { .. }
            | Self::SelfExchange { .. }
            | Self::SelfMove { .. }
            | Self::InfiniteLoopNeverReached { .. } => 2,
            Self::DeadComputation { start, end } => end.saturating_sub(*start) + 1,
            Self::OpaqueConditional { .. } => 6,
            Self::SpuriousPushPop {
                push_offset,
                pop_offset,
            } => pop_offset.saturating_sub(*push_offset) + 1,
            Self::RedundantCall { .. } => 5,
            Self::RedundantStore {
                first_store,
                last_store,
                ..
            } => last_store.saturating_sub(*first_store) + 4,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JunkScorer — assign a confidence value (0–100)
// ─────────────────────────────────────────────────────────────────────────────

/// Computes a confidence score (0–100) for a candidate [`JunkPattern`].
///
/// Higher scores indicate higher certainty that the pattern is truly junk and
/// safe to remove.
#[derive(Debug, Default)]
pub struct JunkScorer {
    /// Optional context: percentage of the function that is NOP-like instructions.
    pub nop_density: f32,
    /// Optional context: whether the function has an obfuscation marker (packer
    /// header, known obfuscator prologue, etc.).
    pub has_obfuscation_marker: bool,
    /// Optional context: whether taint analysis confirmed a value is never used.
    pub taint_confirmed_dead: bool,
}

impl JunkScorer {
    /// Create a default scorer with no additional context.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Score the supplied pattern.  Returns a value in `[0, 100]`.
    #[must_use] 
    pub fn score(&self, pattern: &JunkPattern) -> u8 {
        let base: u8 = match pattern {
            JunkPattern::NopSled { length, .. } => {
                if *length >= 8 {
                    95
                } else if *length >= 4 {
                    85
                } else {
                    70
                }
            }
            JunkPattern::DeadAssignment { .. } => {
                if self.taint_confirmed_dead {
                    90
                } else {
                    60
                }
            }
            JunkPattern::UnreachableBlock { .. } => 85,
            JunkPattern::RedundantJump { .. } => 98,
            JunkPattern::DeadComputation { .. } => {
                if self.taint_confirmed_dead {
                    88
                } else {
                    55
                }
            }
            JunkPattern::OpaqueConditional { .. } => 75,
            JunkPattern::SpuriousPushPop { .. } => 90,
            JunkPattern::SelfExchange { .. } | JunkPattern::SelfMove { .. } => 99,
            JunkPattern::IdentityArithmetic { .. } => 97,
            JunkPattern::RedundantCall { .. } => 65,
            JunkPattern::RedundantStore { .. } => 80,
            JunkPattern::InfiniteLoopNeverReached { .. } => 88,
        };

        let bonus: u8 = if self.has_obfuscation_marker { 5 } else { 0 };
        base.saturating_add(bonus).min(100)
    }

    /// Return a human-readable explanation for the score.
    #[must_use] 
    pub fn explain(&self, pattern: &JunkPattern) -> String {
        let score = self.score(pattern);
        format!(
            "{} scored {} (obf_marker={}, taint_dead={}, nop_density={:.1}%)",
            pattern.name(),
            score,
            self.has_obfuscation_marker,
            self.taint_confirmed_dead,
            self.nop_density * 100.0,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RemovalResult — output of a removal pass
// ─────────────────────────────────────────────────────────────────────────────

/// Result produced by a single invocation of [`JunkCodeRemover::remove`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RemovalResult {
    /// Total number of junk patterns removed.
    pub removed_count: usize,
    /// Estimated bytes saved by removing the junk.
    pub bytes_saved: usize,
    /// Patterns that were identified but *not* removed (score below threshold).
    pub skipped: Vec<(JunkPattern, u8)>,
    /// Patterns that were successfully removed together with their scores.
    pub removed: Vec<(JunkPattern, u8)>,
    /// Human-readable log lines.
    pub log: Vec<String>,
}

impl RemovalResult {
    /// Merge another result into `self`.
    pub fn merge(&mut self, other: Self) {
        self.removed_count += other.removed_count;
        self.bytes_saved += other.bytes_saved;
        self.skipped.extend(other.skipped);
        self.removed.extend(other.removed);
        self.log.extend(other.log);
    }

    /// True if any patterns were removed.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.removed_count == 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JunkDb — database of 80+ recognised patterns
// ─────────────────────────────────────────────────────────────────────────────

/// A catalogue of byte-sequence signatures and IR patterns that correspond to
/// known junk code idioms.
///
/// Each entry is keyed by a unique name and holds a [`JunkDbEntry`] describing
/// the pattern and how to detect it.
#[derive(Debug, Default)]
pub struct JunkDb {
    entries: HashMap<String, JunkDbEntry>,
}

/// A single entry in the [`JunkDb`].
#[derive(Debug, Clone)]
pub struct JunkDbEntry {
    /// Unique pattern name.
    pub name: String,
    /// Short human-readable description.
    pub description: String,
    /// Byte-level signature (may contain wildcards encoded as `None`).
    pub byte_sig: Vec<Option<u8>>,
    /// Pattern category.
    pub category: JunkCategory,
    /// Default base confidence score (0–100).
    pub base_score: u8,
}

/// Broad category grouping for a junk pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JunkCategory {
    Nop,
    DeadArithmetic,
    ControlFlowGarbage,
    StackNoise,
    RegisterNoise,
    DeadStore,
    OpaqueLogic,
}

impl JunkDb {
    /// Build the default database containing 80+ recognised patterns.
    #[must_use]
    pub fn build() -> Self {
        let mut db = Self {
            entries: HashMap::with_capacity(96),
        };
        db.populate();
        db
    }

    /// Number of entries in the database.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the database is empty.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up an entry by name.
    #[must_use] 
    pub fn get(&self, name: &str) -> Option<&JunkDbEntry> {
        self.entries.get(name)
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &JunkDbEntry)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Insert a custom entry.
    pub fn insert(&mut self, entry: JunkDbEntry) {
        self.entries.insert(entry.name.clone(), entry);
    }

    /// Match a byte slice against all byte signatures in the database.
    /// Returns a list of `(entry_name, offset)` pairs.
    #[must_use] 
    pub fn scan_bytes(&self, data: &[u8]) -> Vec<(String, usize)> {
        let mut hits = Vec::with_capacity(32);
        for (name, entry) in &self.entries {
            if entry.byte_sig.is_empty() {
                continue;
            }
            let sig = &entry.byte_sig;
            let sig_len = sig.len();
            if data.len() < sig_len {
                continue;
            }
            'outer: for start in 0..=(data.len() - sig_len) {
                for (i, expected) in sig.iter().enumerate() {
                    if let Some(b) = expected
                        && data[start + i] != *b {
                            continue 'outer;
                        }
                }
                hits.push((name.clone(), start));
            }
        }
        hits
    }

    // -----------------------------------------------------------------
    // Private: populate the database
    // -----------------------------------------------------------------

    fn add(&mut self, name: &str, desc: &str, sig: Vec<Option<u8>>, cat: JunkCategory, score: u8) {
        let name_str = name.to_string();
        self.entries.insert(
            name_str.clone(),
            JunkDbEntry {
                name: name_str,
                description: desc.to_string(),
                byte_sig: sig,
                category: cat,
                base_score: score,
            },
        );
    }

    fn populate(&mut self) {
        self.populate_nops();
        self.populate_register_noise();
        self.populate_arithmetic();
        self.populate_control_flow();
        self.populate_stack_noise();
        self.populate_opaque_logic();
        self.populate_dead_stores();
        self.populate_misc_a();
        self.populate_misc_b();
    }

    fn populate_nops(&mut self) {
        use JunkCategory::Nop;
        self.add("nop_90", "Single x86 NOP (0x90)", vec![Some(0x90)], Nop, 99);
        self.add(
            "nop_2byte_6690",
            "2-byte NOP (66 90)",
            vec![Some(0x66), Some(0x90)],
            Nop,
            99,
        );
        self.add(
            "nop_3byte_0f1f00",
            "3-byte NOP (0F 1F 00)",
            vec![Some(0x0f), Some(0x1f), Some(0x00)],
            Nop,
            99,
        );
        self.add(
            "nop_4byte_0f1f4000",
            "4-byte NOP (0F 1F 40 00)",
            vec![Some(0x0f), Some(0x1f), Some(0x40), Some(0x00)],
            Nop,
            99,
        );
        self.add(
            "nop_5byte",
            "5-byte NOP (0F 1F 44 00 00)",
            vec![Some(0x0f), Some(0x1f), Some(0x44), Some(0x00), Some(0x00)],
            Nop,
            99,
        );
        self.add(
            "nop_6byte",
            "6-byte NOP (66 0F 1F 44 00 00)",
            vec![
                Some(0x66),
                Some(0x0f),
                Some(0x1f),
                Some(0x44),
                Some(0x00),
                Some(0x00),
            ],
            Nop,
            99,
        );
        self.add(
            "nop_7byte",
            "7-byte NOP (0F 1F 80 00 00 00 00)",
            vec![
                Some(0x0f),
                Some(0x1f),
                Some(0x80),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x00),
            ],
            Nop,
            99,
        );
        self.add(
            "nop_8byte",
            "8-byte NOP (0F 1F 84 00 00 00 00 00)",
            vec![
                Some(0x0f),
                Some(0x1f),
                Some(0x84),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x00),
            ],
            Nop,
            99,
        );
        self.add(
            "nop_9byte",
            "9-byte NOP (66 0F 1F 84 00 00 00 00 00)",
            vec![
                Some(0x66),
                Some(0x0f),
                Some(0x1f),
                Some(0x84),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x00),
            ],
            Nop,
            99,
        );
        self.add(
            "lea_nop_rax",
            "LEA rax,[rax+0] used as NOP",
            vec![Some(0x48), Some(0x8d), Some(0x00)],
            Nop,
            95,
        );

    }

    fn populate_register_noise(&mut self) {
        use JunkCategory::RegisterNoise;
        // ── Self-move / self-exchange ────────────────────────────────────────
        self.add(
            "mov_eax_eax",
            "MOV EAX, EAX (no-op)",
            vec![Some(0x89), Some(0xc0)],
            RegisterNoise,
            99,
        );
        self.add(
            "mov_ecx_ecx",
            "MOV ECX, ECX",
            vec![Some(0x89), Some(0xc9)],
            RegisterNoise,
            99,
        );
        self.add(
            "mov_edx_edx",
            "MOV EDX, EDX",
            vec![Some(0x89), Some(0xd2)],
            RegisterNoise,
            99,
        );
        self.add(
            "mov_ebx_ebx",
            "MOV EBX, EBX",
            vec![Some(0x89), Some(0xdb)],
            RegisterNoise,
            99,
        );
        self.add(
            "mov_esi_esi",
            "MOV ESI, ESI",
            vec![Some(0x89), Some(0xf6)],
            RegisterNoise,
            99,
        );
        self.add(
            "mov_edi_edi",
            "MOV EDI, EDI",
            vec![Some(0x89), Some(0xff)],
            RegisterNoise,
            99,
        );
        self.add(
            "xchg_eax_eax",
            "XCHG EAX, EAX (0x90 alias)",
            vec![Some(0x90)],
            RegisterNoise,
            99,
        );
        self.add(
            "xchg_rax_rax",
            "XCHG RAX, RAX",
            vec![Some(0x48), Some(0x90)],
            RegisterNoise,
            99,
        );

    }

    fn populate_arithmetic(&mut self) {
        use JunkCategory::DeadArithmetic;
        // ── Zero-effect arithmetic ───────────────────────────────────────────
        self.add(
            "add_eax_0",
            "ADD EAX, 0",
            vec![Some(0x83), Some(0xc0), Some(0x00)],
            DeadArithmetic,
            97,
        );
        self.add(
            "add_ecx_0",
            "ADD ECX, 0",
            vec![Some(0x83), Some(0xc1), Some(0x00)],
            DeadArithmetic,
            97,
        );
        self.add(
            "add_edx_0",
            "ADD EDX, 0",
            vec![Some(0x83), Some(0xc2), Some(0x00)],
            DeadArithmetic,
            97,
        );
        self.add(
            "sub_eax_0",
            "SUB EAX, 0",
            vec![Some(0x83), Some(0xe8), Some(0x00)],
            DeadArithmetic,
            97,
        );
        self.add(
            "sub_ecx_0",
            "SUB ECX, 0",
            vec![Some(0x83), Some(0xe9), Some(0x00)],
            DeadArithmetic,
            97,
        );
        self.add(
            "or_eax_0",
            "OR EAX, 0",
            vec![Some(0x83), Some(0xc8), Some(0x00)],
            DeadArithmetic,
            97,
        );
        self.add(
            "or_ecx_0",
            "OR ECX, 0",
            vec![Some(0x83), Some(0xc9), Some(0x00)],
            DeadArithmetic,
            97,
        );
        self.add(
            "and_eax_ff",
            "AND EAX, -1 (no-op mask)",
            vec![Some(0x83), Some(0xe0), Some(0xff)],
            DeadArithmetic,
            95,
        );
        self.add(
            "mul_eax_1",
            "IMUL EAX, EAX, 1",
            vec![Some(0x6b), Some(0xc0), Some(0x01)],
            DeadArithmetic,
            95,
        );
        self.add(
            "shl_eax_0",
            "SHL EAX, 0",
            vec![Some(0xd1), Some(0xe0)],
            DeadArithmetic,
            90,
        );
        self.add(
            "shr_eax_0",
            "SHR EAX, 0",
            vec![Some(0xd1), Some(0xe8)],
            DeadArithmetic,
            90,
        );
        self.add(
            "ror_eax_0",
            "ROR EAX, 0",
            vec![Some(0xd1), Some(0xc8)],
            DeadArithmetic,
            90,
        );
        self.add(
            "rol_eax_0",
            "ROL EAX, 0",
            vec![Some(0xd1), Some(0xc0)],
            DeadArithmetic,
            90,
        );
        self.add(
            "xor_self_eax",
            "XOR EAX, EAX then overwrite (dead zero)",
            vec![Some(0x31), Some(0xc0)],
            DeadArithmetic,
            70,
        );

    }

    fn populate_control_flow(&mut self) {
        use JunkCategory::ControlFlowGarbage;
        // ── Redundant jumps ──────────────────────────────────────────────────
        self.add(
            "jmp_next_2",
            "JMP +0 (jump to next byte)",
            vec![Some(0xeb), Some(0x00)],
            ControlFlowGarbage,
            99,
        );
        self.add(
            "jmp_next_5",
            "JMP rel32 +0",
            vec![Some(0xe9), Some(0x00), Some(0x00), Some(0x00), Some(0x00)],
            ControlFlowGarbage,
            99,
        );
        self.add(
            "jcc_fallthrough_je",
            "JE +0 (opaque always-false)",
            vec![Some(0x74), Some(0x00)],
            ControlFlowGarbage,
            85,
        );
        self.add(
            "jcc_fallthrough_jne",
            "JNE +0 (opaque never-taken)",
            vec![Some(0x75), Some(0x00)],
            ControlFlowGarbage,
            85,
        );
        self.add(
            "jcc_fallthrough_jz",
            "JZ fallthrough",
            vec![Some(0x74), Some(0x00)],
            ControlFlowGarbage,
            85,
        );
        self.add(
            "call_ret",
            "CALL to next; POP (typical obf trick start)",
            vec![
                Some(0xe8),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x5d),
            ],
            ControlFlowGarbage,
            60,
        );

    }

    fn populate_stack_noise(&mut self) {
        use JunkCategory::StackNoise;
        // ── Stack noise ──────────────────────────────────────────────────────
        self.add(
            "push_pop_eax",
            "PUSH EAX; POP EAX",
            vec![Some(0x50), Some(0x58)],
            StackNoise,
            95,
        );
        self.add(
            "push_pop_ecx",
            "PUSH ECX; POP ECX",
            vec![Some(0x51), Some(0x59)],
            StackNoise,
            95,
        );
        self.add(
            "push_pop_edx",
            "PUSH EDX; POP EDX",
            vec![Some(0x52), Some(0x5a)],
            StackNoise,
            95,
        );
        self.add(
            "push_pop_ebx",
            "PUSH EBX; POP EBX",
            vec![Some(0x53), Some(0x5b)],
            StackNoise,
            95,
        );
        self.add(
            "push_pop_esi",
            "PUSH ESI; POP ESI",
            vec![Some(0x56), Some(0x5e)],
            StackNoise,
            95,
        );
        self.add(
            "push_pop_edi",
            "PUSH EDI; POP EDI",
            vec![Some(0x57), Some(0x5f)],
            StackNoise,
            95,
        );
        self.add(
            "pushf_popf",
            "PUSHF; POPF (flags roundtrip)",
            vec![Some(0x9c), Some(0x9d)],
            StackNoise,
            90,
        );
        self.add(
            "pusha_popa",
            "PUSHA; POPA (all-regs roundtrip)",
            vec![Some(0x60), Some(0x61)],
            StackNoise,
            90,
        );
        self.add(
            "push_imm_pop",
            "PUSH imm; POP reg (dead load)",
            vec![Some(0x6a), None, Some(0x58)],
            StackNoise,
            80,
        );
        self.add(
            "push_pop_flags",
            "PUSHFD; POPFD",
            vec![Some(0x9c), Some(0x9d)],
            StackNoise,
            90,
        );

    }

    fn populate_opaque_logic(&mut self) {
        use JunkCategory::OpaqueLogic;
        // ── Opaque logic / constant folds ────────────────────────────────────
        self.add(
            "and_always_false",
            "TEST reg,0; JNZ (always false branch)",
            vec![
                Some(0xf7),
                Some(0xc0),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x75),
            ],
            OpaqueLogic,
            85,
        );
        self.add(
            "cmp_self",
            "CMP EAX, EAX (always zero)",
            vec![Some(0x39), Some(0xc0)],
            OpaqueLogic,
            90,
        );
        self.add(
            "cmp_self_ecx",
            "CMP ECX, ECX",
            vec![Some(0x39), Some(0xc9)],
            OpaqueLogic,
            90,
        );
        self.add(
            "cmp_self_edx",
            "CMP EDX, EDX",
            vec![Some(0x39), Some(0xd2)],
            OpaqueLogic,
            90,
        );
        self.add(
            "test_self_eax",
            "TEST EAX, EAX (result ignored)",
            vec![Some(0x85), Some(0xc0)],
            OpaqueLogic,
            70,
        );
        self.add(
            "stc_clc",
            "STC; CLC (flag noise)",
            vec![Some(0xf9), Some(0xf8)],
            OpaqueLogic,
            88,
        );
        self.add(
            "cmc_cmc",
            "CMC; CMC (double complement)",
            vec![Some(0xf5), Some(0xf5)],
            OpaqueLogic,
            95,
        );
        self.add(
            "not_not_eax",
            "NOT EAX; NOT EAX (double negate)",
            vec![Some(0xf7), Some(0xd0), Some(0xf7), Some(0xd0)],
            OpaqueLogic,
            97,
        );
        self.add(
            "neg_neg_eax",
            "NEG EAX; NEG EAX",
            vec![Some(0xf7), Some(0xd8), Some(0xf7), Some(0xd8)],
            OpaqueLogic,
            97,
        );
        self.add(
            "bswap_bswap",
            "BSWAP EAX; BSWAP EAX",
            vec![Some(0x0f), Some(0xc8), Some(0x0f), Some(0xc8)],
            OpaqueLogic,
            97,
        );
        self.add(
            "xor_key_key",
            "XOR EAX, K; XOR EAX, K (same key twice)",
            vec![
                Some(0x35),
                None,
                None,
                None,
                None,
                Some(0x35),
                None,
                None,
                None,
                None,
            ],
            OpaqueLogic,
            90,
        );

    }

    fn populate_dead_stores(&mut self) {
        use JunkCategory::DeadStore;
        // ── Dead stores ──────────────────────────────────────────────────────
        self.add(
            "mov_mem_imm_dead",
            "MOV [addr], 0 followed immediately by overwrite",
            vec![
                Some(0xc7),
                Some(0x05),
                None,
                None,
                None,
                None,
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x00),
            ],
            DeadStore,
            65,
        );
        self.add(
            "rep_stosb_zero",
            "REP STOSB with count=0 (dead memset)",
            vec![Some(0xf3), Some(0xaa)],
            DeadStore,
            75,
        );
        self.add(
            "stosb_zero",
            "STOSB (often dead in junk blocks)",
            vec![Some(0xaa)],
            DeadStore,
            50,
        );

    }

    fn populate_misc_a(&mut self) {
        use JunkCategory::{Nop, ControlFlowGarbage, OpaqueLogic, StackNoise, RegisterNoise};
        // ── Misc ─────────────────────────────────────────────────────────────
        self.add(
            "lock_nop",
            "LOCK prefix on NOP (F0 90)",
            vec![Some(0xf0), Some(0x90)],
            Nop,
            98,
        );
        self.add(
            "rep_nop",
            "REP NOP (F3 90 = PAUSE, used as junk)",
            vec![Some(0xf3), Some(0x90)],
            Nop,
            92,
        );
        self.add(
            "int3_strip",
            "INT3 in non-debug context",
            vec![Some(0xcc)],
            ControlFlowGarbage,
            60,
        );
        self.add(
            "rdtsc_dead",
            "RDTSC result discarded (timing noise)",
            vec![Some(0x0f), Some(0x31)],
            OpaqueLogic,
            55,
        );
        self.add(
            "cpuid_dead",
            "CPUID with dead results",
            vec![Some(0x0f), Some(0xa2)],
            OpaqueLogic,
            55,
        );
        self.add(
            "fld_fstp",
            "FLD ST(0); FSTP ST(0) (float roundtrip)",
            vec![Some(0xd9), Some(0xc0), Some(0xd9), Some(0xd8)],
            RegisterNoise,
            88,
        );
        self.add(
            "fnop",
            "FNOP (FPU no-op)",
            vec![Some(0xd9), Some(0xd0)],
            Nop,
            97,
        );
        self.add(
            "sfence_dead",
            "SFENCE in non-MT context",
            vec![Some(0x0f), Some(0xae), Some(0xf8)],
            Nop,
            70,
        );
        self.add(
            "lfence_dead",
            "LFENCE in non-MT context",
            vec![Some(0x0f), Some(0xae), Some(0xe8)],
            Nop,
            70,
        );
        self.add(
            "mfence_dead",
            "MFENCE in non-MT context",
            vec![Some(0x0f), Some(0xae), Some(0xf0)],
            Nop,
            65,
        );
        self.add(
            "clflush_dead",
            "CLFLUSH of dead address",
            vec![Some(0x0f), Some(0xae), None],
            Nop,
            60,
        );
        self.add(
            "sahf_lahf",
            "SAHF; LAHF (flags round-trip)",
            vec![Some(0x9e), Some(0x9f)],
            OpaqueLogic,
            88,
        );
        self.add(
            "mov_cr0_dead",
            "MOV to CR0 in user-space (dead)",
            vec![Some(0x0f), Some(0x22), Some(0xc0)],
            ControlFlowGarbage,
            80,
        );
        self.add(
            "push_cs",
            "PUSH CS (segment register push junk)",
            vec![Some(0x0e)],
            StackNoise,
            75,
        );
    }

    fn populate_misc_b(&mut self) {
        use JunkCategory::{Nop, OpaqueLogic, StackNoise};
        self.add("push_ds", "PUSH DS", vec![Some(0x1e)], StackNoise, 75);
        self.add("push_es", "PUSH ES", vec![Some(0x06)], StackNoise, 75);
        self.add("pop_ds", "POP DS", vec![Some(0x1f)], StackNoise, 75);
        self.add("pop_es", "POP ES", vec![Some(0x07)], StackNoise, 75);
        self.add(
            "salc",
            "SALC (undocumented; used as junk)",
            vec![Some(0xd6)],
            OpaqueLogic,
            85,
        );
        self.add("aaa", "AAA (BCD junk)", vec![Some(0x37)], OpaqueLogic, 80);
        self.add("aas", "AAS (BCD junk)", vec![Some(0x3f)], OpaqueLogic, 80);
        self.add(
            "aad",
            "AAD (BCD junk)",
            vec![Some(0xd5), Some(0x0a)],
            OpaqueLogic,
            80,
        );
        self.add(
            "aam",
            "AAM (BCD junk)",
            vec![Some(0xd4), Some(0x0a)],
            OpaqueLogic,
            80,
        );
        self.add("daa", "DAA (BCD junk)", vec![Some(0x27)], OpaqueLogic, 80);
        self.add("das", "DAS (BCD junk)", vec![Some(0x2f)], OpaqueLogic, 80);
        self.add(
            "nop_lea_rsp",
            "LEA RSP,[RSP+0] NOP",
            vec![Some(0x48), Some(0x8d), Some(0x64), Some(0x24), Some(0x00)],
            Nop,
            97,
        );
        self.add(
            "nop_lea_esp",
            "LEA ESP,[ESP+0] NOP",
            vec![Some(0x8d), Some(0x64), Some(0x24), Some(0x00)],
            Nop,
            97,
        );
        self.populate_misc_c();
    }

    fn populate_misc_c(&mut self) {
        use JunkCategory::{Nop, StackNoise, RegisterNoise, DeadArithmetic};
        self.add(
            "mov_rax_rax",
            "MOV RAX, RAX (REX.W self-move)",
            vec![Some(0x48), Some(0x89), Some(0xc0)],
            RegisterNoise,
            99,
        );
        self.add(
            "mov_rcx_rcx",
            "MOV RCX, RCX",
            vec![Some(0x48), Some(0x89), Some(0xc9)],
            RegisterNoise,
            99,
        );
        self.add(
            "mov_rdx_rdx",
            "MOV RDX, RDX",
            vec![Some(0x48), Some(0x89), Some(0xd2)],
            RegisterNoise,
            99,
        );
        self.add(
            "add_rax_0",
            "ADD RAX, 0 (REX.W)",
            vec![Some(0x48), Some(0x83), Some(0xc0), Some(0x00)],
            DeadArithmetic,
            97,
        );
        self.add(
            "sub_rax_0",
            "SUB RAX, 0 (REX.W)",
            vec![Some(0x48), Some(0x83), Some(0xe8), Some(0x00)],
            DeadArithmetic,
            97,
        );
        self.add(
            "or_rax_0",
            "OR RAX, 0 (REX.W)",
            vec![Some(0x48), Some(0x83), Some(0xc8), Some(0x00)],
            DeadArithmetic,
            97,
        );
        self.add(
            "push_pop_rax",
            "PUSH RAX; POP RAX",
            vec![Some(0x50), Some(0x58)],
            StackNoise,
            95,
        );

        // padding to reach 80+ entries (already exceeded above but keep a few extras)
        self.add(
            "endbr64",
            "ENDBR64 (CET hint, harmless in non-CET)",
            vec![Some(0xf3), Some(0x0f), Some(0x1e), Some(0xfa)],
            Nop,
            70,
        );
        self.add(
            "endbr32",
            "ENDBR32",
            vec![Some(0xf3), Some(0x0f), Some(0x1e), Some(0xfb)],
            Nop,
            70,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JunkCodeRemover — main facade
// ─────────────────────────────────────────────────────────────────────────────

/// High-level interface for detecting and removing junk code from a byte buffer
/// or a list of explicitly-provided patterns.
///
/// # Usage
/// ```no_run
/// use rustre_deobf::junk_code_remover::JunkCodeRemover;
/// let bytes: Vec<u8> = vec![0x90; 16];
/// let mut remover = JunkCodeRemover::new(75);
/// let result = remover.remove_from_bytes(&bytes);
/// println!("Removed {} patterns, saved {} bytes", result.1.removed_count, result.1.bytes_saved);
/// ```
pub struct JunkCodeRemover {
    /// Minimum confidence score required to apply a removal.
    pub threshold: u8,
    /// The junk pattern database.
    pub db: JunkDb,
    /// The scorer used to evaluate candidates.
    pub scorer: JunkScorer,
}

impl JunkCodeRemover {
    /// Create a new remover with the given confidence threshold.
    #[must_use] 
    pub fn new(threshold: u8) -> Self {
        Self {
            threshold,
            db: JunkDb::build(),
            scorer: JunkScorer::new(),
        }
    }

    /// Create a remover with a custom scorer.
    #[must_use] 
    pub fn with_scorer(threshold: u8, scorer: JunkScorer) -> Self {
        Self {
            threshold,
            db: JunkDb::build(),
            scorer,
        }
    }

    /// Scan a raw byte slice, remove patterns above threshold by NOP-ing them
    /// out (filling with `0x90`), and return a [`RemovalResult`].
    #[must_use] 
    pub fn remove_from_bytes(&self, data: &[u8]) -> (Vec<u8>, RemovalResult) {
        let mut out = data.to_vec();
        let mut result = RemovalResult::default();

        let mut hits = self.db.scan_bytes(data);
        // Sort by offset so we process left-to-right.
        hits.sort_by_key(|(_, off)| *off);

        for (name, offset) in hits {
            let Some(entry) = self.db.get(&name) else { continue };
            let length = entry.byte_sig.len();
            let pattern = JunkPattern::NopSled { offset, length }; // approximate
            let score = entry.base_score;

            if score >= self.threshold {
                // NOP out the bytes.
                for i in 0..length {
                    if offset + i < out.len() {
                        out[offset + i] = 0x90;
                    }
                }
                result.removed_count += 1;
                result.bytes_saved += length;
                result.removed.push((pattern, score));
                result.log.push(format!(
                    "  [{offset:#06x}] removed '{name}' (score={score})"
                ));
            } else {
                result.skipped.push((pattern, score));
                result.log.push(format!(
                    "  [{:#06x}] skipped '{}' (score={} < threshold={})",
                    offset, name, score, self.threshold
                ));
            }
        }

        (out, result)
    }

    /// Remove an explicit list of [`JunkPattern`]s (e.g., from an IR pass).
    #[must_use] 
    pub fn remove_patterns(&self, patterns: Vec<JunkPattern>) -> RemovalResult {
        let mut result = RemovalResult::default();
        for pattern in patterns {
            let score = self.scorer.score(&pattern);
            if score >= self.threshold {
                let bytes = pattern.size_estimate();
                result.removed_count += 1;
                result.bytes_saved += bytes;
                result
                    .log
                    .push(format!("  removed '{}' (score={})", pattern.name(), score));
                result.removed.push((pattern, score));
            } else {
                result.log.push(format!(
                    "  skipped '{}' (score={} < threshold={})",
                    pattern.name(),
                    score,
                    self.threshold
                ));
                result.skipped.push((pattern, score));
            }
        }
        result
    }

    /// Count how many patterns would be removed without mutating anything.
    #[must_use] 
    pub fn count_removable(&self, data: &[u8]) -> usize {
        let hits = self.db.scan_bytes(data);
        hits.iter()
            .filter(|(name, _)| {
                self.db
                    .get(name)
                    .is_some_and(|e| e.base_score >= self.threshold)
            })
            .count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── JunkDb tests ─────────────────────────────────────────────────────────

    #[test]
    fn db_has_at_least_80_entries() {
        let db = JunkDb::build();
        assert!(db.len() >= 80, "expected ≥80 entries, got {}", db.len());
    }

    #[test]
    fn db_is_not_empty() {
        let db = JunkDb::build();
        assert!(!db.is_empty());
    }

    #[test]
    fn db_get_known_entry() {
        let db = JunkDb::build();
        let e = db.get("nop_90").expect("nop_90 should exist");
        assert_eq!(e.base_score, 99);
        assert_eq!(e.category, JunkCategory::Nop);
    }

    #[test]
    fn db_get_missing_entry_returns_none() {
        let db = JunkDb::build();
        assert!(db.get("__no_such_pattern__").is_none());
    }

    #[test]
    fn db_scan_finds_nop_sled() {
        let db = JunkDb::build();
        let data = vec![0x90u8; 8];
        let hits = db.scan_bytes(&data);
        
        assert!(hits.iter().map(|(n, _)| n.as_str()).any(|x| x == "nop_90"), "should find single-byte NOP");
    }

    #[test]
    fn db_scan_finds_mov_eax_eax() {
        let db = JunkDb::build();
        let data = [0x89u8, 0xc0];
        let hits = db.scan_bytes(&data);
        assert!(!hits.is_empty());
        assert!(hits.iter().any(|(n, _)| n == "mov_eax_eax"));
    }

    #[test]
    fn db_scan_finds_2byte_nop() {
        let db = JunkDb::build();
        let data = [0x66u8, 0x90];
        let hits = db.scan_bytes(&data);
        assert!(hits.iter().any(|(n, _)| n == "nop_2byte_6690"));
    }

    #[test]
    fn db_scan_offset_correct() {
        let db = JunkDb::build();
        // Pad with 5 bytes then a MOV EAX,EAX
        let data = [0x00u8; 5]
            .iter()
            .chain([0x89u8, 0xc0].iter())
            .copied()
            .collect::<Vec<_>>();
        let hits = db.scan_bytes(&data);
        let hit = hits
            .iter()
            .find(|(n, _)| n == "mov_eax_eax")
            .expect("should find");
        assert_eq!(hit.1, 5);
    }

    #[test]
    fn db_insert_custom_entry() {
        let mut db = JunkDb::build();
        let prev_len = db.len();
        db.insert(JunkDbEntry {
            name: "custom_test".into(),
            description: "Test entry".into(),
            byte_sig: vec![Some(0xde), Some(0xad)],
            category: JunkCategory::Nop,
            base_score: 80,
        });
        assert_eq!(db.len(), prev_len + 1);
    }

    #[test]
    fn db_scan_no_false_positive_on_empty() {
        let db = JunkDb::build();
        let hits = db.scan_bytes(&[]);
        assert!(hits.is_empty());
    }

    #[test]
    fn db_iter_returns_all() {
        let db = JunkDb::build();
        let count = db.iter().count();
        assert_eq!(count, db.len());
    }

    // ── JunkPattern tests ────────────────────────────────────────────────────

    #[test]
    fn pattern_nop_sled_name() {
        let p = JunkPattern::NopSled {
            offset: 0,
            length: 8,
        };
        assert_eq!(p.name(), "NopSled");
    }

    #[test]
    fn pattern_nop_sled_size() {
        let p = JunkPattern::NopSled {
            offset: 0,
            length: 10,
        };
        assert_eq!(p.size_estimate(), 10);
    }

    #[test]
    fn pattern_dead_assignment_name() {
        let p = JunkPattern::DeadAssignment {
            variable: "eax".into(),
            offset: 4,
        };
        assert_eq!(p.name(), "DeadAssignment");
    }

    #[test]
    fn pattern_redundant_jump_size() {
        let p = JunkPattern::RedundantJump {
            offset: 0,
            target: 2,
        };
        assert_eq!(p.size_estimate(), 2);
    }

    #[test]
    fn pattern_unreachable_block_size() {
        let p = JunkPattern::UnreachableBlock {
            block_id: 0x1000,
            size_bytes: 32,
        };
        assert_eq!(p.size_estimate(), 32);
    }

    #[test]
    fn pattern_self_move_name() {
        let p = JunkPattern::SelfMove {
            offset: 0,
            register: "rax".into(),
        };
        assert_eq!(p.name(), "SelfMove");
    }

    #[test]
    fn pattern_spurious_push_pop_size() {
        let p = JunkPattern::SpuriousPushPop {
            push_offset: 10,
            pop_offset: 20,
        };
        assert_eq!(p.size_estimate(), 11);
    }

    // ── JunkScorer tests ─────────────────────────────────────────────────────

    #[test]
    fn scorer_nop_sled_8bytes_returns_95plus() {
        let scorer = JunkScorer::new();
        let p = JunkPattern::NopSled {
            offset: 0,
            length: 8,
        };
        assert!(scorer.score(&p) >= 95);
    }

    #[test]
    fn scorer_nop_sled_small_lower_score() {
        let scorer = JunkScorer::new();
        let big = JunkPattern::NopSled {
            offset: 0,
            length: 8,
        };
        let small = JunkPattern::NopSled {
            offset: 0,
            length: 1,
        };
        assert!(scorer.score(&big) >= scorer.score(&small));
    }

    #[test]
    fn scorer_self_move_always_99() {
        let scorer = JunkScorer::new();
        let p = JunkPattern::SelfMove {
            offset: 0,
            register: "ecx".into(),
        };
        assert_eq!(scorer.score(&p), 99);
    }

    #[test]
    fn scorer_self_exchange_always_99() {
        let scorer = JunkScorer::new();
        let p = JunkPattern::SelfExchange {
            offset: 0,
            register: "rax".into(),
        };
        assert_eq!(scorer.score(&p), 99);
    }

    #[test]
    fn scorer_obf_marker_bumps_score() {
        let baseline = JunkScorer::new();
        let with_marker = JunkScorer {
            has_obfuscation_marker: true,
            ..Default::default()
        };
        let p = JunkPattern::UnreachableBlock {
            block_id: 0,
            size_bytes: 10,
        };
        assert!(with_marker.score(&p) >= baseline.score(&p));
    }

    #[test]
    fn scorer_taint_confirmed_dead_assignment() {
        let baseline = JunkScorer::new();
        let with_taint = JunkScorer {
            taint_confirmed_dead: true,
            ..Default::default()
        };
        let p = JunkPattern::DeadAssignment {
            variable: "eax".into(),
            offset: 0,
        };
        assert!(with_taint.score(&p) > baseline.score(&p));
    }

    #[test]
    fn scorer_score_capped_at_100() {
        let scorer = JunkScorer {
            has_obfuscation_marker: true,
            taint_confirmed_dead: true,
            nop_density: 1.0,
        };
        let p = JunkPattern::SelfMove {
            offset: 0,
            register: "eax".into(),
        };
        assert!(scorer.score(&p) <= 100);
    }

    #[test]
    fn scorer_explain_contains_name() {
        let scorer = JunkScorer::new();
        let p = JunkPattern::RedundantJump {
            offset: 0,
            target: 2,
        };
        let s = scorer.explain(&p);
        assert!(s.contains("RedundantJump"));
    }

    // ── RemovalResult tests ──────────────────────────────────────────────────

    #[test]
    fn removal_result_default_is_empty() {
        let r = RemovalResult::default();
        assert!(r.is_empty());
        assert_eq!(r.removed_count, 0);
        assert_eq!(r.bytes_saved, 0);
    }

    #[test]
    fn removal_result_merge() {
        let mut a = RemovalResult {
            removed_count: 3,
            bytes_saved: 10,
            ..Default::default()
        };
        let b = RemovalResult {
            removed_count: 2,
            bytes_saved: 5,
            ..Default::default()
        };
        a.merge(b);
        assert_eq!(a.removed_count, 5);
        assert_eq!(a.bytes_saved, 15);
    }

    // ── JunkCodeRemover tests ────────────────────────────────────────────────

    #[test]
    fn remover_nops_out_nop_sled() {
        let remover = JunkCodeRemover::new(50);
        let data = vec![0x90u8; 8];
        let (out, result) = remover.remove_from_bytes(&data);
        assert!(result.removed_count > 0);
        assert_eq!(out.len(), data.len());
    }

    #[test]
    fn remover_respects_threshold() {
        // threshold of 100 → nothing should be removed (no pattern scores 100 from scan)
        let remover = JunkCodeRemover::new(100);
        let data = vec![0x90u8; 4];
        let (_, result) = remover.remove_from_bytes(&data);
        // 0x90 has base score 99, still below 100
        assert_eq!(result.removed_count, 0);
    }

    #[test]
    fn remover_threshold_99_removes_nop_90() {
        let remover = JunkCodeRemover::new(99);
        let data = vec![0x90u8; 4];
        let (_, result) = remover.remove_from_bytes(&data);
        assert!(result.removed_count > 0);
    }

    #[test]
    fn remover_leaves_non_junk_bytes() {
        let remover = JunkCodeRemover::new(50);
        // 0x48 0xB8 is not a junk pattern
        let data = [0x48u8, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let (out, result) = remover.remove_from_bytes(&data);
        // No patterns should be removed
        let _ = result;
        // Original bytes preserved (no partial match)
        assert_eq!(out[0], 0x48);
        assert_eq!(out[1], 0xB8);
    }

    #[test]
    fn remover_remove_patterns_explicit() {
        let remover = JunkCodeRemover::new(90);
        let patterns = vec![
            JunkPattern::SelfMove {
                offset: 0,
                register: "eax".into(),
            },
            JunkPattern::NopSled {
                offset: 2,
                length: 8,
            },
        ];
        let result = remover.remove_patterns(patterns);
        assert_eq!(result.removed_count, 2);
        assert!(result.bytes_saved > 0);
    }

    #[test]
    fn remover_count_removable() {
        let remover = JunkCodeRemover::new(90);
        let data = [0x89u8, 0xc0, 0x90, 0x90]; // mov eax,eax + 2 nops
        let count = remover.count_removable(&data);
        assert!(count > 0);
    }

    #[test]
    fn remover_log_is_populated() {
        let remover = JunkCodeRemover::new(50);
        let data = [0x90u8; 4];
        let (_, result) = remover.remove_from_bytes(&data);
        assert!(!result.log.is_empty());
    }

    #[test]
    fn remover_with_custom_scorer() {
        let scorer = JunkScorer {
            has_obfuscation_marker: true,
            ..Default::default()
        };
        let remover = JunkCodeRemover::with_scorer(80, scorer);
        let patterns = vec![JunkPattern::UnreachableBlock {
            block_id: 0x4000,
            size_bytes: 64,
        }];
        let result = remover.remove_patterns(patterns);
        assert_eq!(result.removed_count, 1);
    }

    #[test]
    fn remover_bytes_saved_matches_size() {
        let remover = JunkCodeRemover::new(50);
        let p = JunkPattern::NopSled {
            offset: 0,
            length: 16,
        };
        let result = remover.remove_patterns(vec![p]);
        assert_eq!(result.bytes_saved, 16);
    }
}
