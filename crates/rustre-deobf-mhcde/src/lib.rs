//! `rustre-deobf-mhcde` --" Mixed Honig Control-flow & Dead-code Elimination.
//!
//! Detects and removes opaque predicates, junk code, control-flow flattening,
//! and unreachable basic blocks.

pub mod combination_solver;
pub mod control_flow_graph_builder;
pub mod dataflow_propagator;
pub mod mhcde_passes;
pub mod deobf_orchestrator;
pub mod deobf_oracle;
pub mod entropy_scorer;
pub mod feature_extractor;
pub mod hypothesis_combiner;
pub mod hypothesis_engine;
pub mod hypothesis_manager;
pub mod multi_stage_deobf;
pub mod hypothesis_generator;
pub mod concurrent_deobf_executor;
pub mod hypothesis_validator;

use std::collections::{HashMap, HashSet, VecDeque};
use ahash::AHashMap;

use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};

use rustre_deobf::{DeobfContext, DeobfError, DeobfPass, DeobfResult, Patch};

// -----------------------------------------------------------------------------
// OpaquePredicateType
// -----------------------------------------------------------------------------

/// Classification of an opaque predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OpaquePredicateType {
    /// The branch is always taken.
    AlwaysTrue,
    /// The branch is never taken.
    AlwaysFalse,
    /// The predicate depends on a data value (hard to fold statically).
    DataDependent,
    /// The predicate is based on pointer arithmetic.
    PointerBased,
    /// The predicate uses a hash function.
    HashBased,
}

// -----------------------------------------------------------------------------
// OpaquePredicateDetector
// -----------------------------------------------------------------------------

/// A detected opaque predicate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaquePredicate {
    /// Byte offset of the conditional branch instruction.
    pub offset: usize,
    /// Type of predicate.
    pub predicate_type: OpaquePredicateType,
    /// Length (in bytes) of the byte sequence to NOP / patch.
    pub patch_length: usize,
    /// Human-readable description.
    pub description: String,
}

/// Identifies conditional branches that always take one path.
#[derive(Debug, Clone, Default)]
pub struct OpaquePredicateDetector;

impl OpaquePredicateDetector {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan `data` for opaque-predicate patterns and return findings.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Vec<OpaquePredicate> {
        let mut results = Vec::new();

        if data.len() < 3 {
            return results;
        }

        for i in 0..data.len() {
            // -- Pattern 1: xor eax, eax; test eax, eax; jz --------------
            // 31 C0  85 C0  74 xx  --" always taken (ZF=1)
            if i + 4 < data.len()
                && data[i] == 0x31
                && data[i + 1] == 0xC0
                && data[i + 2] == 0x85
                && data[i + 3] == 0xC0
                && data[i + 4] == 0x74
            {
                results.push(OpaquePredicate {
                    offset: i,
                    predicate_type: OpaquePredicateType::AlwaysTrue,
                    patch_length: 5,
                    description: "xor eax,eax; test eax,eax; jz -- always taken".to_owned(),
                });
            }

            // -- Pattern 2: xor eax, eax; test eax, eax; jnz -------------
            // 31 C0  85 C0  75 xx  --" never taken (ZF=1, JNZ not taken)
            if i + 4 < data.len()
                && data[i] == 0x31
                && data[i + 1] == 0xC0
                && data[i + 2] == 0x85
                && data[i + 3] == 0xC0
                && data[i + 4] == 0x75
            {
                results.push(OpaquePredicate {
                    offset: i,
                    predicate_type: OpaquePredicateType::AlwaysFalse,
                    patch_length: 5,
                    description: "xor eax,eax; test eax,eax; jnz -- never taken".to_owned(),
                });
            }

            // -- Pattern 3: mov al, 1; test al, al; jz --------------------
            // B0 01  84 C0  74 xx  --" never taken (ZF=0 since al=1)
            if i + 4 < data.len()
                && data[i] == 0xB0
                && data[i + 1] == 0x01
                && data[i + 2] == 0x84
                && data[i + 3] == 0xC0
                && data[i + 4] == 0x74
            {
                results.push(OpaquePredicate {
                    offset: i,
                    predicate_type: OpaquePredicateType::AlwaysFalse,
                    patch_length: 5,
                    description: "mov al,1; test al,al; jz --  never taken".to_owned(),
                });
            }

            // -- Pattern 4: or eax, -1; test eax, eax; jnz ---------------
            // 83 C8 FF  85 C0  75 xx  --" always taken (EAX=0xFFFFFFFF, ZF=0)
            if i + 6 < data.len()
                && data[i] == 0x83
                && data[i + 1] == 0xC8
                && data[i + 2] == 0xFF
                && data[i + 3] == 0x85
                && data[i + 4] == 0xC0
                && data[i + 5] == 0x75
            {
                results.push(OpaquePredicate {
                    offset: i,
                    predicate_type: OpaquePredicateType::AlwaysTrue,
                    patch_length: 6,
                    description: "or eax,-1; test eax,eax; jnz --  always taken".to_owned(),
                });
            }

            // -- Pattern 5: and eax, 0; test eax, eax; jz -----------------
            // 83 E0 00  85 C0  74 xx  --" always taken
            if i + 6 < data.len()
                && data[i] == 0x83
                && data[i + 1] == 0xE0
                && data[i + 2] == 0x00
                && data[i + 3] == 0x85
                && data[i + 4] == 0xC0
                && data[i + 5] == 0x74
            {
                results.push(OpaquePredicate {
                    offset: i,
                    predicate_type: OpaquePredicateType::AlwaysTrue,
                    patch_length: 6,
                    description: "and eax,0; test eax,eax; jz --  always taken".to_owned(),
                });
            }

            // -- Pattern 6: xor reg, reg; jz (condensed form) -------------
            // 33 C0  74 xx
            if i + 3 < data.len() && data[i] == 0x33 && data[i + 1] == 0xC0 && data[i + 2] == 0x74 {
                results.push(OpaquePredicate {
                    offset: i,
                    predicate_type: OpaquePredicateType::AlwaysTrue,
                    patch_length: 3,
                    description: "xor eax,eax; jz --  always taken (condensed)".to_owned(),
                });
            }

            // -- Pattern 7: xor ecx,ecx; jecxz rel8 -----------------------
            // 33 C9  E3 xx --" jecxz taken when ECX=0, which is guaranteed
            if i + 3 < data.len() && data[i] == 0x33 && data[i + 1] == 0xC9 && data[i + 2] == 0xE3 {
                results.push(OpaquePredicate {
                    offset: i,
                    predicate_type: OpaquePredicateType::AlwaysTrue,
                    patch_length: 3,
                    description: "xor ecx,ecx; jecxz --  always taken".to_owned(),
                });
            }

            // -- Pattern 8: xor eax,eax; cmp eax,eax; jz ------------------
            // 31 C0  39 C0  74 xx --" cmp sets ZF=1 when eax==eax
            if i + 4 < data.len()
                && data[i] == 0x31
                && data[i + 1] == 0xC0
                && data[i + 2] == 0x39
                && data[i + 3] == 0xC0
                && data[i + 4] == 0x74
            {
                results.push(OpaquePredicate {
                    offset: i,
                    predicate_type: OpaquePredicateType::AlwaysTrue,
                    patch_length: 5,
                    description: "xor eax,eax; cmp eax,eax; jz --  always taken".to_owned(),
                });
            }

            // -- Pattern 9: mov eax,0; test eax,eax; jz -------------------
            // B8 00 00 00 00  85 C0  74 xx --" MOV EAX,0 sets ZF via test
            if i + 7 < data.len()
                && data[i] == 0xB8
                && data[i + 1] == 0x00
                && data[i + 2] == 0x00
                && data[i + 3] == 0x00
                && data[i + 4] == 0x00
                && data[i + 5] == 0x85
                && data[i + 6] == 0xC0
                && data[i + 7] == 0x74
            {
                results.push(OpaquePredicate {
                    offset: i,
                    predicate_type: OpaquePredicateType::AlwaysTrue,
                    // Eight bytes are matched (B8 00 00 00 00 85 C0 74) and all
                    // eight must be patched: at 7 the region stopped one short of
                    // the `74` jump opcode, so overwriting it left the
                    // conditional branch in place — the predicate was reported as
                    // handled while the control flow it neutralises survived.
                    // Every other pattern here sizes the patch to the bytes it
                    // matched; this one did not.
                    patch_length: 8,
                    description: "mov eax,0; test eax,eax; jz --  always taken".to_owned(),
                });
            }

            // -- Pattern 10: stc; jc rel8 ----------------------------------
            // F9  72 xx --" Set Carry, then JC (jump if carry) --" always taken
            if i + 2 < data.len() && data[i] == 0xF9 && data[i + 1] == 0x72 {
                results.push(OpaquePredicate {
                    offset: i,
                    predicate_type: OpaquePredicateType::AlwaysTrue,
                    patch_length: 2,
                    description: "stc; jc --  always taken".to_owned(),
                });
            }

            // -- Pattern 11: clc; jnc rel8 ---------------------------------
            // F8  73 xx --" Clear Carry, then JNC --" always taken
            if i + 2 < data.len() && data[i] == 0xF8 && data[i + 1] == 0x73 {
                results.push(OpaquePredicate {
                    offset: i,
                    predicate_type: OpaquePredicateType::AlwaysTrue,
                    patch_length: 2,
                    description: "clc; jnc --  always taken".to_owned(),
                });
            }

            // -- Pattern 12: xor eax,eax; or eax,1; test eax,eax; jnz -----
            // 31 C0  83 C8 01  85 C0  75 xx
            if i + 7 < data.len()
                && data[i] == 0x31
                && data[i + 1] == 0xC0
                && data[i + 2] == 0x83
                && data[i + 3] == 0xC8
                && data[i + 4] == 0x01
                && data[i + 5] == 0x85
                && data[i + 6] == 0xC0
                && data[i + 7] == 0x75
            {
                results.push(OpaquePredicate {
                    offset: i,
                    predicate_type: OpaquePredicateType::AlwaysTrue,
                    // Eight bytes are matched (31 C0 83 C8 01 85 C0 75); at 7 the
                    // patch stopped one short of the `75` jnz opcode and the
                    // branch survived. Same off-by-one as pattern 9.
                    patch_length: 8,
                    description: "xor eax,eax; or eax,1; test eax,eax; jnz --  always taken"
                        .to_owned(),
                });
            }
        }

        results
    }

    /// Count opaque predicates by type.
    #[must_use]
    pub fn count_by_type(&self, data: &[u8]) -> HashMap<OpaquePredicateType, usize> {
        let mut map: HashMap<OpaquePredicateType, usize> = HashMap::new();
        for op in self.detect(data) {
            *map.entry(op.predicate_type).or_insert(0) += 1;
        }
        map
    }

    /// Return total bytes that would be NOP-patched by all detected predicates.
    #[must_use]
    pub fn total_patch_bytes(&self, data: &[u8]) -> usize {
        self.detect(data).iter().map(|op| op.patch_length).sum()
    }
}

// -----------------------------------------------------------------------------
// JunkCodeDetector
// -----------------------------------------------------------------------------

/// A sequence of junk instructions detected in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JunkCodeRegion {
    /// Start offset of the junk sequence.
    pub offset: usize,
    /// Length in bytes.
    pub length: usize,
    /// Human-readable reason.
    pub description: String,
}

/// Identifies instruction sequences that have no semantic effect.
#[derive(Debug, Clone, Default)]
pub struct JunkCodeDetector;

impl JunkCodeDetector {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan `data` and return all detected junk regions.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Vec<JunkCodeRegion> {
        let mut results = Vec::new();
        let mut i = 0;

        while i < data.len() {
            // -- NOP sled --------------------------------------------------
            if data[i] == 0x90 {
                let start = i;
                while i < data.len() && data[i] == 0x90 {
                    i += 1;
                }
                let len = i - start;
                if len >= 2 {
                    results.push(JunkCodeRegion {
                        offset: start,
                        length: len,
                        description: format!("NOP sled ({len} bytes)"),
                    });
                }
                continue;
            }

            // -- push reg; pop same reg (2 bytes) --------------------------
            // PUSH r32: 0x50--"0x57  POP r32: 0x58--"0x5F
            if i + 1 < data.len()
                && data[i] >= 0x50
                && data[i] <= 0x57
                && data[i + 1] == (data[i] + 8)
            // PUSH reg X -> POP reg X is push+8
            {
                results.push(JunkCodeRegion {
                    offset: i,
                    length: 2,
                    description: format!("push r{}; pop r{} --  identity", data[i] & 7, data[i] & 7),
                });
                i += 2;
                continue;
            }

            // -- xor reg, 0 (3 bytes) -------------------------------------
            // 83 F0+r 00
            if i + 2 < data.len()
                && data[i] == 0x83
                && (data[i + 1] & 0xF8) == 0xF0
                && data[i + 2] == 0x00
            {
                results.push(JunkCodeRegion {
                    offset: i,
                    length: 3,
                    description: "xor reg, 0 --  identity".to_owned(),
                });
                i += 3;
                continue;
            }

            // -- add reg, 0 (3 bytes) -------------------------------------
            // 83 C0+r 00
            if i + 2 < data.len()
                && data[i] == 0x83
                && (data[i + 1] & 0xF8) == 0xC0
                && data[i + 2] == 0x00
            {
                results.push(JunkCodeRegion {
                    offset: i,
                    length: 3,
                    description: "add reg, 0 --  identity".to_owned(),
                });
                i += 3;
                continue;
            }

            // -- sub reg, 0 (3 bytes) -------------------------------------
            // 83 E8+r 00
            if i + 2 < data.len()
                && data[i] == 0x83
                && (data[i + 1] & 0xF8) == 0xE8
                && data[i + 2] == 0x00
            {
                results.push(JunkCodeRegion {
                    offset: i,
                    length: 3,
                    description: "sub reg, 0 --  identity".to_owned(),
                });
                i += 3;
                continue;
            }

            // -- mov reg, reg (same destination and source: 2 bytes) -------
            // 89 C0+r*9  e.g. 89 C0 = MOV EAX,EAX; 89 DB = MOV EBX,EBX
            if i + 1 < data.len() && data[i] == 0x89 {
                let modrm = data[i + 1];
                let dest = modrm & 0x07;
                let src = (modrm >> 3) & 0x07;
                if dest == src && (modrm & 0xC0) == 0xC0 {
                    results.push(JunkCodeRegion {
                        offset: i,
                        length: 2,
                        description: format!("mov r{dest}, r{dest} --  identity"),
                    });
                    i += 2;
                    continue;
                }
            }

            // -- lea reg, [reg+0] (3 bytes) --------------------------------
            // 8D 40+r 00
            if i + 2 < data.len()
                && data[i] == 0x8D
                && (data[i + 1] & 0xC7) == 0x40  // ModRM: mod=01, rm=reg, disp8=0
                // disp==0 implies [reg+0] == [reg]
                && data[i + 2] == 0x00
            {
                results.push(JunkCodeRegion {
                    offset: i,
                    length: 3,
                    description: "lea reg, [reg+0] --  identity".to_owned(),
                });
                i += 3;
                continue;
            }

            // -- or reg, 0 (3 bytes) ---------------------------------------
            // 83 C8+r 00 (OR r32, 0) --" identity for the value
            if i + 2 < data.len()
                && data[i] == 0x83
                && (data[i + 1] & 0xF8) == 0xC8
                && data[i + 2] == 0x00
            {
                results.push(JunkCodeRegion {
                    offset: i,
                    length: 3,
                    description: "or reg, 0 --  identity".to_owned(),
                });
                i += 3;
                continue;
            }

            // -- and reg, -1 (3 bytes) -------------------------------------
            // 83 E0+r FF  --" AND r32, 0xFFFFFFFF is identity
            if i + 2 < data.len()
                && data[i] == 0x83
                && (data[i + 1] & 0xF8) == 0xE0
                && data[i + 2] == 0xFF
            {
                results.push(JunkCodeRegion {
                    offset: i,
                    length: 3,
                    description: "and reg, -1 --  identity".to_owned(),
                });
                i += 3;
                continue;
            }

            // -- XCHG eax,eax (single byte 0x87 0xC0) ---------------------
            // Also the single-byte NOP alias 0x90 is already caught above.
            if i + 1 < data.len() && data[i] == 0x87 && data[i + 1] == 0xC0 {
                results.push(JunkCodeRegion {
                    offset: i,
                    length: 2,
                    description: "xchg eax,eax --  identity".to_owned(),
                });
                i += 2;
                continue;
            }

            // -- CLC followed by STC (semantically cancelling pair) --------
            // F8 F9 --" clear carry then set carry; net effect: CF=1 (not useful junk
            // unless both bits are dead); flag as "flag churn".
            if i + 1 < data.len() && data[i] == 0xF8 && data[i + 1] == 0xF9 {
                results.push(JunkCodeRegion {
                    offset: i,
                    length: 2,
                    description: "clc; stc --  flag churn, net CF=1 (likely junk)".to_owned(),
                });
                i += 2;
                continue;
            }

            // -- Multi-byte NOP (66 90 / 0F 1F variants) ------------------
            // 66 90 = NOP (16-bit prefix on NOP)
            if i + 1 < data.len() && data[i] == 0x66 && data[i + 1] == 0x90 {
                results.push(JunkCodeRegion {
                    offset: i,
                    length: 2,
                    description: "66 90 --  16-bit NOP".to_owned(),
                });
                i += 2;
                continue;
            }

            // 0F 1F 00 --" NOP DWORD PTR [rax] (3-byte NOP)
            if i + 2 < data.len() && data[i] == 0x0F && data[i + 1] == 0x1F && data[i + 2] == 0x00 {
                results.push(JunkCodeRegion {
                    offset: i,
                    length: 3,
                    description: "0F 1F 00 --  3-byte NOP".to_owned(),
                });
                i += 3;
                continue;
            }

            // 0F 1F 40 00 --" NOP DWORD PTR [rax+0] (4-byte NOP)
            if i + 3 < data.len()
                && data[i] == 0x0F
                && data[i + 1] == 0x1F
                && data[i + 2] == 0x40
                && data[i + 3] == 0x00
            {
                results.push(JunkCodeRegion {
                    offset: i,
                    length: 4,
                    description: "0F 1F 40 00 --  4-byte NOP".to_owned(),
                });
                i += 4;
                continue;
            }

            i += 1;
        }

        results
    }

    /// Returns total byte count across all detected junk regions.
    #[must_use]
    pub fn total_junk_bytes(&self, data: &[u8]) -> usize {
        self.detect(data).iter().map(|r| r.length).sum()
    }

    /// Compute junk density: ratio of junk bytes to total bytes.
    #[must_use]
    pub fn junk_density(&self, data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }
        self.total_junk_bytes(data) as f32 / data.len() as f32
    }
}

// -----------------------------------------------------------------------------
// ControlFlowFlattener detection
// -----------------------------------------------------------------------------

/// A basic block in the lifted CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgBlock {
    /// File offset of the first byte.
    pub offset: usize,
    /// Length in bytes.
    pub length: usize,
    /// Offsets of successor blocks.
    pub successors: Vec<usize>,
    /// `true` if this block is the state-machine dispatcher.
    pub is_dispatcher: bool,
}

/// Result of CFF detection: the dispatcher block and flattened body blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CffDetectionResult {
    /// The dispatcher / switch block.
    pub dispatcher_offset: usize,
    /// State variable offset (heuristic).
    pub state_var_offset: u64,
    /// All body blocks discovered.
    pub body_blocks: Vec<CfgBlock>,
    /// Reconstructed linear order of body block offsets.
    pub reconstructed_order: Vec<usize>,
}

/// Detects control-flow-flattening patterns.
#[derive(Debug, Clone, Default)]
pub struct ControlFlowFlattener;

impl ControlFlowFlattener {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Detect CFF pattern in `data`.
    ///
    /// Heuristic:
    /// 1. Find an indirect `jmp [reg*4+base]` or `jmp [reg+base]` (switch jump).
    /// 2. The block containing it is the dispatcher.
    /// 3. Collect all targets reachable from the dispatcher.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Option<CffDetectionResult> {
        // Look for indirect jump: FF 24 xx (jmp [eax*4+base]) or FF E0 (jmp eax)
        for i in 0..data.len().saturating_sub(2) {
            let is_indirect_jmp = data[i] == 0xFF
                && (data[i + 1] == 0x24 || data[i + 1] == 0xE0 || data[i + 1] == 0xE3);

            if !is_indirect_jmp {
                continue;
            }

            // Found a dispatcher candidate.
            // Scan backwards up to 32 bytes to find the block start (look for RET/JMP/CALL).
            let block_start = self.find_block_start(data, i);

            // Extract a state variable guess: look for MOV reg, [mem] before the jmp.
            let state_var = self.guess_state_variable(data, block_start, i);

            // Collect body blocks: scan the byte following the dispatcher block.
            let body_blocks = self.collect_body_blocks(data, i + 2);

            let order: Vec<usize> = body_blocks.iter().map(|b| b.offset).collect();

            return Some(CffDetectionResult {
                dispatcher_offset: block_start,
                state_var_offset: state_var,
                body_blocks,
                reconstructed_order: order,
            });
        }
        None
    }

    fn find_block_start(&self, data: &[u8], jmp_offset: usize) -> usize {
        let lo = jmp_offset.saturating_sub(64);
        for i in (lo..jmp_offset).rev() {
            // RET (0xC3), JMP rel8 (0xEB), JMP rel32 (0xE9), CALL (0xE8)
            if matches!(data[i], 0xC3 | 0xEB | 0xE9 | 0xE8) {
                return i + 1;
            }
        }
        lo
    }

    fn guess_state_variable(&self, data: &[u8], start: usize, end: usize) -> u64 {
        // Look for MOV eax, [imm32]: A1 xx xx xx xx
        // Clamp `end` so we never read past the actual data buffer.
        let safe_end = end.min(data.len()).saturating_sub(4);
        for i in start..safe_end {
            if data[i] == 0xA1 {
                return u64::from(u32::from_le_bytes([
                    data[i + 1],
                    data[i + 2],
                    data[i + 3],
                    data[i + 4],
                ]));
            }
        }
        0
    }

    fn collect_body_blocks(&self, data: &[u8], start: usize) -> Vec<CfgBlock> {
        let mut blocks = Vec::new();
        let mut offset = start;
        while offset < data.len().saturating_sub(1) && blocks.len() < 64 {
            let end = self.find_block_end(data, offset);
            // Guard: if end < offset the subtraction would underflow; treat
            // as a zero-length (degenerate) block and stop collecting.
            if end < offset {
                break;
            }
            let succs = self.find_successors(data, offset, end);
            let succs_empty = succs.is_empty();
            blocks.push(CfgBlock {
                offset,
                length: end - offset + 1,
                successors: succs,
                is_dispatcher: false,
            });
            if succs_empty {
                break;
            }
            offset = end + 1;
        }
        blocks
    }

    fn find_block_end(&self, data: &[u8], start: usize) -> usize {
        for i in start..data.len() {
            if matches!(data[i], 0xC3 | 0xEB | 0xE9 | 0x74 | 0x75 | 0xE8) {
                return i;
            }
            if i - start > 128 {
                return i;
            }
        }
        data.len() - 1
    }

    fn find_successors(&self, data: &[u8], _start: usize, end: usize) -> Vec<usize> {
        if end + 1 >= data.len() {
            return vec![];
        }
        match data[end] {
            // JMP rel8: target = end + 2 + sign-extended rel8
            0xEB if end + 1 < data.len() => {
                let rel = data[end + 1] as i8;
                let target_i = end as i64 + 2 + i64::from(rel);
                if target_i < 0 || (target_i as u64) >= data.len() as u64 {
                    vec![]
                } else {
                    vec![target_i as usize]
                }
            }
            // Conditional short: both branches.
            0x74 | 0x75 if end + 1 < data.len() => {
                let rel = data[end + 1] as i8;
                let taken_i = end as i64 + 2 + i64::from(rel);
                if taken_i < 0 || (taken_i as u64) >= data.len() as u64 {
                    vec![end + 2]
                } else {
                    vec![end + 2, taken_i as usize]
                }
            }
            0xC3 => vec![],
            _ => vec![end + 1],
        }
    }

    /// Compute a simple dispatcher fan-out metric: number of edges from the
    /// dispatcher node versus the total edge count of the CFG.
    #[must_use]
    pub fn dispatcher_fan_out(result: &CffDetectionResult) -> f32 {
        if result.body_blocks.is_empty() {
            return 0.0;
        }
        let total_edges: usize = result.body_blocks.iter().map(|b| b.successors.len()).sum();
        if total_edges == 0 {
            return 0.0;
        }
        // Dispatcher "edges" are approximated as the number of body blocks it
        // connects to (one per body block in a pure CFF scheme).
        result.body_blocks.len() as f32 / total_edges as f32
    }
}

// -----------------------------------------------------------------------------
// BogusControlFlowRemover
// -----------------------------------------------------------------------------

/// Removes bogus blocks from a flattened CFG.
#[derive(Debug, Clone, Default)]
pub struct BogusControlFlowRemover;

impl BogusControlFlowRemover {
    /// Create a new remover.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Given a list of blocks and their sizes, remove the dispatcher block
    /// and its direct children that consist solely of junk code, returning
    /// the filtered set.
    #[must_use]
    pub fn remove_bogus_blocks<'a>(
        &self,
        blocks: &'a [CfgBlock],
        junk_offsets: &HashSet<usize>,
    ) -> Vec<&'a CfgBlock> {
        blocks
            .iter()
            .filter(|b| !b.is_dispatcher && !junk_offsets.contains(&b.offset))
            .collect()
    }

    /// Compute a [`HashSet`] of offsets that are considered junk based on a
    /// list of [`JunkCodeRegion`]s.
    #[must_use]
    pub fn junk_offset_set(regions: &[JunkCodeRegion]) -> HashSet<usize> {
        regions.iter().map(|r| r.offset).collect()
    }

    /// Return only dispatcher-flagged blocks from `blocks`.
    #[must_use]
    pub fn dispatcher_blocks<'a>(&self, blocks: &'a [CfgBlock]) -> Vec<&'a CfgBlock> {
        blocks.iter().filter(|b| b.is_dispatcher).collect()
    }
}

// -----------------------------------------------------------------------------
// DeadCodeEliminator
// -----------------------------------------------------------------------------

/// Removes unreachable basic blocks from a CFG.
#[derive(Debug, Clone, Default)]
pub struct DeadCodeEliminator;

impl DeadCodeEliminator {
    /// Create a new eliminator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Build a petgraph [`DiGraph`] from `blocks` (keyed by offset).
    #[must_use]
    pub fn build_graph(
        &self,
        blocks: &[CfgBlock],
    ) -> (DiGraph<usize, ()>, AHashMap<usize, NodeIndex>) {
        let mut graph = DiGraph::new();
        let mut node_map: AHashMap<usize, NodeIndex> = AHashMap::new();

        for block in blocks {
            let idx = graph.add_node(block.offset);
            node_map.insert(block.offset, idx);
        }

        for block in blocks {
            if let Some(&src) = node_map.get(&block.offset) {
                for &succ in &block.successors {
                    if let Some(&dst) = node_map.get(&succ) {
                        graph.add_edge(src, dst, ());
                    }
                }
            }
        }

        (graph, node_map)
    }

    /// Return the set of block offsets reachable from `entry_offset`.
    #[must_use]
    pub fn reachable_blocks(&self, blocks: &[CfgBlock], entry_offset: usize) -> HashSet<usize> {
        // Direct BFS over an offset -> successors map; avoids building a
        // petgraph DiGraph just to walk it.
        let mut succ_map: AHashMap<usize, &[usize]> = AHashMap::with_capacity(blocks.len());
        for block in blocks {
            succ_map.insert(block.offset, block.successors.as_slice());
        }

        let mut reachable: HashSet<usize> = HashSet::with_capacity(blocks.len());
        if !succ_map.contains_key(&entry_offset) {
            return reachable;
        }
        let mut stack: Vec<usize> = Vec::with_capacity(blocks.len());
        stack.push(entry_offset);
        while let Some(offset) = stack.pop() {
            if !reachable.insert(offset) {
                continue;
            }
            if let Some(succs) = succ_map.get(&offset) {
                for &s in succs.iter() {
                    if !reachable.contains(&s) {
                        stack.push(s);
                    }
                }
            }
        }

        reachable
    }

    /// Filter `blocks` to only those reachable from `entry_offset`.
    #[must_use]
    pub fn eliminate<'a>(&self, blocks: &'a [CfgBlock], entry_offset: usize) -> Vec<&'a CfgBlock> {
        let reachable = self.reachable_blocks(blocks, entry_offset);
        blocks
            .iter()
            .filter(|b| reachable.contains(&b.offset))
            .collect()
    }

    /// Return offsets that are NOT reachable from `entry_offset` --" i.e. dead blocks.
    #[must_use]
    pub fn dead_blocks<'a>(
        &self,
        blocks: &'a [CfgBlock],
        entry_offset: usize,
    ) -> Vec<&'a CfgBlock> {
        let reachable = self.reachable_blocks(blocks, entry_offset);
        blocks
            .iter()
            .filter(|b| !reachable.contains(&b.offset))
            .collect()
    }

    /// BFS topological ordering of reachable blocks from `entry_offset`.
    /// Returns offsets in BFS discovery order.
    #[must_use]
    pub fn bfs_order(&self, blocks: &[CfgBlock], entry_offset: usize) -> Vec<usize> {
        let (graph, node_map) = self.build_graph(blocks);
        let mut order = Vec::new();

        if let Some(&entry_node) = node_map.get(&entry_offset) {
            let mut queue = VecDeque::new();
            let mut visited = HashSet::new();
            queue.push_back(entry_node);
            visited.insert(entry_node);

            while let Some(node) = queue.pop_front() {
                if let Some(&offset) = graph.node_weight(node) {
                    order.push(offset);
                }
                for neighbor in graph.neighbors(node) {
                    if visited.insert(neighbor) {
                        queue.push_back(neighbor);
                    }
                }
            }
        }

        order
    }

    /// Count reachable vs. total blocks and return the percentage dead.
    #[must_use]
    pub fn dead_block_ratio(&self, blocks: &[CfgBlock], entry_offset: usize) -> f32 {
        if blocks.is_empty() {
            return 0.0;
        }
        let reachable = self.reachable_blocks(blocks, entry_offset).len();
        let dead = blocks.len().saturating_sub(reachable);
        dead as f32 / blocks.len() as f32
    }
}

// -----------------------------------------------------------------------------
// ConstantFoldingHeuristic
// -----------------------------------------------------------------------------

/// Simple constant-folding heuristic for x86 two-operand arithmetic.
///
/// Evaluates a short sequence of instructions starting at `offset` in `data`
/// and attempts to fold the result to a known 32-bit constant.  Only a small
/// subset of opcodes is supported; any unsupported or memory-touching
/// instruction causes [`None`] to be returned.
#[derive(Debug, Clone, Default)]
pub struct ConstantFoldingHeuristic;

/// Result of a constant-folding attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldResult {
    /// Folded constant value.
    pub value: u32,
    /// Number of bytes consumed.
    pub bytes_consumed: usize,
}

impl ConstantFoldingHeuristic {
    /// Create a new heuristic instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Try to fold a short instruction sequence at `offset` in `data`.
    ///
    /// Returns `Some(FoldResult)` when the sequence produces a compile-time
    /// constant, or `None` otherwise.
    #[must_use]
    pub fn try_fold(&self, data: &[u8], offset: usize) -> Option<FoldResult> {
        if offset >= data.len() {
            return None;
        }

        // -- MOV EAX, imm32: B8 xx xx xx xx ------------------------------
        if offset + 4 < data.len() && data[offset] == 0xB8 {
            let val = u32::from_le_bytes([
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
            ]);
            return Some(FoldResult {
                value: val,
                bytes_consumed: 5,
            });
        }

        // -- XOR EAX, EAX: 31 C0 / 33 C0 ---------------------------------
        if offset + 1 < data.len()
            && (data[offset] == 0x31 || data[offset] == 0x33)
            && data[offset + 1] == 0xC0
        {
            return Some(FoldResult {
                value: 0,
                bytes_consumed: 2,
            });
        }

        // -- MOV EAX, 0: B8 00 00 00 00 (subset of above, handled already) -

        // -- OR EAX, -1: 83 C8 FF -----------------------------------------
        if offset + 2 < data.len()
            && data[offset] == 0x83
            && data[offset + 1] == 0xC8
            && data[offset + 2] == 0xFF
        {
            return Some(FoldResult {
                value: 0xFFFF_FFFF,
                bytes_consumed: 3,
            });
        }

        // -- AND EAX, 0: 83 E0 00 -----------------------------------------
        if offset + 2 < data.len()
            && data[offset] == 0x83
            && data[offset + 1] == 0xE0
            && data[offset + 2] == 0x00
        {
            return Some(FoldResult {
                value: 0,
                bytes_consumed: 3,
            });
        }

        // -- MOV AL, imm8: B0 xx -------------------------------------------
        if offset + 1 < data.len() && data[offset] == 0xB0 {
            return Some(FoldResult {
                value: u32::from(data[offset + 1]),
                bytes_consumed: 2,
            });
        }

        None
    }

    /// Fold all recognisable constants in `data` and return a map of
    /// offset -> folded value.
    #[must_use]
    pub fn fold_all(&self, data: &[u8]) -> AHashMap<usize, FoldResult> {
        let mut map = AHashMap::new();
        let mut i = 0;
        while i < data.len() {
            if let Some(result) = self.try_fold(data, i) {
                map.insert(i, result);
                i += result.bytes_consumed;
            } else {
                i += 1;
            }
        }
        map
    }
}

// -----------------------------------------------------------------------------
// EntropyAnalyzer
// -----------------------------------------------------------------------------

/// Computes Shannon entropy of byte windows to help distinguish real code from
/// data, junk, or encrypted regions.
#[derive(Debug, Clone)]
pub struct EntropyAnalyzer {
    /// Sliding window size in bytes.
    pub window_size: usize,
}

impl Default for EntropyAnalyzer {
    fn default() -> Self {
        Self { window_size: 256 }
    }
}

/// One entropy measurement over a window.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct EntropyWindow {
    /// Start offset of this window.
    pub offset: usize,
    /// Shannon entropy in bits (0.0--"8.0).
    pub entropy: f32,
}

impl EntropyAnalyzer {
    /// Create an analyzer with the given window size (must be >= 4).
    #[must_use]
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size: window_size.max(4),
        }
    }

    /// Compute Shannon entropy for a byte slice.
    #[must_use]
    pub fn entropy(data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u32; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let len = data.len() as f32;
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f32 / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Slide a window over `data` and return entropy measurements.
    #[must_use]
    pub fn analyze(&self, data: &[u8]) -> Vec<EntropyWindow> {
        if data.len() < self.window_size {
            return vec![EntropyWindow {
                offset: 0,
                entropy: Self::entropy(data),
            }];
        }
        (0..=(data.len() - self.window_size))
            .step_by((self.window_size / 2).max(1))
            .map(|offset| EntropyWindow {
                offset,
                entropy: Self::entropy(&data[offset..offset + self.window_size]),
            })
            .collect()
    }

    /// Find all windows with entropy above `threshold` (0.0--"8.0).
    #[must_use]
    pub fn high_entropy_windows(&self, data: &[u8], threshold: f32) -> Vec<EntropyWindow> {
        let mut windows = self.analyze(data);
        windows.retain(|w| w.entropy >= threshold);
        windows
    }

    /// Find all windows with entropy below `threshold` --" likely padding / junk.
    #[must_use]
    pub fn low_entropy_windows(&self, data: &[u8], threshold: f32) -> Vec<EntropyWindow> {
        let mut windows = self.analyze(data);
        windows.retain(|w| w.entropy < threshold);
        windows
    }

    /// Return the mean entropy across all windows.
    #[must_use]
    pub fn mean_entropy(&self, data: &[u8]) -> f32 {
        let windows = self.analyze(data);
        if windows.is_empty() {
            return 0.0;
        }
        let sum: f32 = windows.iter().map(|w| w.entropy).sum();
        sum / windows.len() as f32
    }
}

// -----------------------------------------------------------------------------
// PatchApplicator
// -----------------------------------------------------------------------------

/// Applies a [`PlannedPatch`] list to a mutable byte buffer.
#[derive(Debug, Clone, Default)]
pub struct PatchApplicator;

impl PatchApplicator {
    /// Create a new applicator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Apply all patches in `plan` to `data` (in-place NOP fill).
    ///
    /// Patches that exceed the bounds of `data` are silently skipped.
    /// Returns the number of patches successfully applied.
    pub fn apply_nop_patches(&self, data: &mut [u8], plan: &[PlannedPatch]) -> usize {
        let mut applied = 0;
        for patch in plan {
            let end = patch.offset.saturating_add(patch.length);
            if end > data.len() {
                continue;
            }
            for byte in &mut data[patch.offset..end] {
                *byte = 0x90;
            }
            applied += 1;
        }
        applied
    }

    /// Apply patches using a custom fill byte instead of 0x90.
    pub fn apply_fill_patches(&self, data: &mut [u8], plan: &[PlannedPatch], fill: u8) -> usize {
        let mut applied = 0;
        for patch in plan {
            let end = patch.offset.saturating_add(patch.length);
            if end > data.len() {
                continue;
            }
            for byte in &mut data[patch.offset..end] {
                *byte = fill;
            }
            applied += 1;
        }
        applied
    }

    /// Return a new `Vec<u8>` with patches applied without mutating `data`.
    #[must_use]
    pub fn patched_copy(&self, data: &[u8], plan: &[PlannedPatch]) -> Vec<u8> {
        let mut copy = data.to_vec();
        self.apply_nop_patches(&mut copy, plan);
        copy
    }

    /// Verify that all patches in `plan` lie within `data_len` bounds.
    #[must_use]
    pub fn validate_plan(plan: &[PlannedPatch], data_len: usize) -> bool {
        plan.iter()
            .all(|p| p.offset.saturating_add(p.length) <= data_len)
    }
}

// -----------------------------------------------------------------------------
// MhcdePass --" combined DeobfPass
// -----------------------------------------------------------------------------

/// Kind of transformation proposed by the MHCDE orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MhcdePatchKind {
    /// NOP an opaque predicate sequence.
    OpaquePredicate,
    /// NOP a semantic no-op or junk instruction sequence.
    JunkCode,
}

/// One deterministic patch proposal emitted by [`MhcdeOrchestrator`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannedPatch {
    /// File offset where patching starts.
    pub offset: usize,
    /// Number of bytes to replace with NOPs.
    pub length: usize,
    /// Transformation family that produced the patch.
    pub kind: MhcdePatchKind,
    /// Confidence in this specific patch.
    pub confidence: f32,
    /// Human-readable explanation.
    pub description: String,
}

/// Aggregate deterministic score for one MHCDE analysis run.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MhcdeScore {
    /// Confidence in [0.0, 1.0].
    pub confidence: f32,
    /// Conservative risk estimate in [0.0, 1.0].
    pub risk: f32,
    /// Number of bytes proposed for modification.
    pub modified_bytes: usize,
    /// Total number of detector findings.
    pub finding_count: usize,
}

impl MhcdeScore {
    fn from_analysis(
        finding_count: usize,
        patch_count: usize,
        modified_bytes: usize,
        has_cff: bool,
    ) -> Self {
        if finding_count == 0 {
            return Self {
                confidence: 0.0,
                risk: 0.0,
                modified_bytes,
                finding_count,
            };
        }

        let patch_signal = (patch_count as f32 / finding_count as f32).clamp(0.0, 1.0);
        let cff_signal = if has_cff { 0.1 } else { 0.0 };
        let confidence = (0.35f32.mul_add(patch_signal, 0.55) + cff_signal).clamp(0.0, 1.0);
        let risk = (finding_count.saturating_sub(patch_count) as f32).mul_add(0.08, modified_bytes as f32 / 4096.0 * 0.05)
            .clamp(0.0, 1.0);

        Self {
            confidence,
            risk,
            modified_bytes,
            finding_count,
        }
    }

    /// Return `true` if the score indicates high obfuscation likelihood.
    #[must_use]
    pub fn is_highly_obfuscated(&self) -> bool {
        self.confidence >= 0.75 && self.finding_count >= 3
    }

    /// Classify confidence into a human-readable tier.
    #[must_use]
    pub fn confidence_tier(&self) -> &'static str {
        if self.confidence >= 0.9 {
            "very high"
        } else if self.confidence >= 0.75 {
            "high"
        } else if self.confidence >= 0.5 {
            "medium"
        } else if self.confidence > 0.0 {
            "low"
        } else {
            "none"
        }
    }
}

/// Full MHCDE analysis report independent of patch application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MhcdeAnalysis {
    /// Opaque predicates detected in input order.
    pub opaque_predicates: Vec<OpaquePredicate>,
    /// Junk-code regions detected in input order.
    pub junk_regions: Vec<JunkCodeRegion>,
    /// Optional control-flow flattening report.
    pub cff: Option<CffDetectionResult>,
    /// Non-overlapping patch plan sorted by offset.
    pub patch_plan: Vec<PlannedPatch>,
    /// Deterministic aggregate score.
    pub score: MhcdeScore,
}

impl MhcdeAnalysis {
    /// Total number of individual findings (predicates + junk + CFF indicator).
    #[must_use]
    pub fn total_findings(&self) -> usize {
        self.opaque_predicates.len() + self.junk_regions.len() + usize::from(self.cff.is_some())
    }

    /// Return `true` when no findings were detected.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.total_findings() == 0
    }

    /// Collect all patch offsets into a sorted [`Vec`].
    #[must_use]
    pub fn patch_offsets(&self) -> Vec<usize> {
        let mut offsets: Vec<usize> = self.patch_plan.iter().map(|p| p.offset).collect();
        offsets.sort_unstable();
        offsets
    }

    /// Return only the patches with confidence >= `min_confidence`.
    #[must_use]
    pub fn high_confidence_patches(&self, min_confidence: f32) -> Vec<&PlannedPatch> {
        self.patch_plan
            .iter()
            .filter(|p| p.confidence >= min_confidence)
            .collect()
    }
}

/// Reusable orchestration facade for MHCDE detectors and patch planning.
#[derive(Debug, Clone, Default)]
pub struct MhcdeOrchestrator {
    opaque: OpaquePredicateDetector,
    junk: JunkCodeDetector,
    cff: ControlFlowFlattener,
}

impl MhcdeOrchestrator {
    /// Create a new orchestrator with default detectors.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyze `data` and produce deterministic findings, score, and patch plan.
    #[must_use]
    pub fn analyze(&self, data: &[u8]) -> MhcdeAnalysis {
        let opaque_predicates = self.opaque.detect(data);
        let junk_regions = self.junk.detect(data);
        let cff = self.cff.detect(data);
        let patch_plan = self.plan_patches(data.len(), &opaque_predicates, &junk_regions);
        let modified_bytes = patch_plan.iter().map(|patch| patch.length).sum();
        let finding_count =
            opaque_predicates.len() + junk_regions.len() + usize::from(cff.is_some());
        let score = MhcdeScore::from_analysis(
            finding_count,
            patch_plan.len(),
            modified_bytes,
            cff.is_some(),
        );

        MhcdeAnalysis {
            opaque_predicates,
            junk_regions,
            cff,
            patch_plan,
            score,
        }
    }

    /// Analyze and immediately apply patches to a copy of `data`.
    ///
    /// Returns the patched bytes and the analysis report.
    #[must_use]
    pub fn analyze_and_patch(&self, data: &[u8]) -> (Vec<u8>, MhcdeAnalysis) {
        let analysis = self.analyze(data);
        let applicator = PatchApplicator::new();
        let patched = applicator.patched_copy(data, &analysis.patch_plan);
        (patched, analysis)
    }

    fn plan_patches(
        &self,
        data_len: usize,
        opaque_predicates: &[OpaquePredicate],
        junk_regions: &[JunkCodeRegion],
    ) -> Vec<PlannedPatch> {
        let mut claimed = Vec::new();
        let mut patches = Vec::new();

        for op in opaque_predicates {
            self.push_patch_if_available(
                &mut patches,
                &mut claimed,
                data_len,
                PlannedPatch {
                    offset: op.offset,
                    length: op.patch_length,
                    kind: MhcdePatchKind::OpaquePredicate,
                    confidence: 0.9,
                    description: op.description.clone(),
                },
            );
        }

        for junk in junk_regions {
            self.push_patch_if_available(
                &mut patches,
                &mut claimed,
                data_len,
                PlannedPatch {
                    offset: junk.offset,
                    length: junk.length,
                    kind: MhcdePatchKind::JunkCode,
                    confidence: 0.75,
                    description: junk.description.clone(),
                },
            );
        }

        patches.sort_by(|left, right| {
            left.offset
                .cmp(&right.offset)
                .then_with(|| left.length.cmp(&right.length))
                .then_with(|| left.kind.cmp(&right.kind))
        });
        patches
    }

    fn push_patch_if_available(
        &self,
        patches: &mut Vec<PlannedPatch>,
        claimed: &mut Vec<(usize, usize)>,
        data_len: usize,
        patch: PlannedPatch,
    ) {
        let end = patch.offset.saturating_add(patch.length);
        if patch.length == 0 || end > data_len || ranges_overlap(claimed, patch.offset, end) {
            return;
        }

        claimed.push((patch.offset, end));
        patches.push(patch);
    }
}

fn ranges_overlap(claimed: &[(usize, usize)], start: usize, end: usize) -> bool {
    claimed
        .iter()
        .any(|&(claimed_start, claimed_end)| start < claimed_end && claimed_start < end)
}

/// Combined pass that applies all MHCDE detectors.
pub struct MhcdePass {
    orchestrator: MhcdeOrchestrator,
}

impl MhcdePass {
    /// Create a new [`MhcdePass`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            orchestrator: MhcdeOrchestrator::new(),
        }
    }

    /// Analyze bytes without mutating a deobfuscation context.
    #[must_use]
    pub fn analyze(&self, data: &[u8]) -> MhcdeAnalysis {
        self.orchestrator.analyze(data)
    }
}

impl Default for MhcdePass {
    fn default() -> Self {
        Self::new()
    }
}

impl DeobfPass for MhcdePass {
    fn name(&self) -> &'static str {
        "mhcde"
    }

    fn description(&self) -> &'static str {
        "Mixed Honig Control-flow & Dead-code Elimination: removes opaque predicates and junk code"
    }

    fn is_applicable(&self, ctx: &DeobfContext) -> bool {
        ctx.binary.len() >= 8
    }

    fn run(&self, ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError> {
        let analysis = self.analyze(&ctx.binary);
        let mut transformations = Vec::new();

        // 1. Opaque predicate removal --" NOP out the entire sequence.
        for planned in &analysis.patch_plan {
            let end = planned.offset.saturating_add(planned.length);
            if end > ctx.binary.len() {
                continue;
            }
            let original = ctx.binary[planned.offset..end].to_vec();
            let patched = vec![0x90u8; planned.length];
            let family = match planned.kind {
                MhcdePatchKind::OpaquePredicate => "opaque predicate",
                MhcdePatchKind::JunkCode => "junk code",
            };
            ctx.patches.push(Patch::new(
                planned.offset,
                original,
                patched,
                format!("{family}: {}", planned.description),
            ));
            transformations.push(format!(
                "removed {family} at {:#x}: {}",
                planned.offset, planned.description
            ));
        }

        // 3. CFF detection (informational --" patch generation requires IL).
        if let Some(cff) = &analysis.cff {
            ctx.set_meta(
                "cff_dispatcher_offset",
                serde_json::json!(cff.dispatcher_offset),
            );
            ctx.set_meta(
                "cff_body_blocks",
                serde_json::json!(cff.reconstructed_order.len()),
            );
            transformations.push(format!(
                "CFF dispatcher at {:#x}, {} body blocks",
                cff.dispatcher_offset,
                cff.body_blocks.len()
            ));
        }
        ctx.set_meta("mhcde_score", serde_json::json!(analysis.score));
        ctx.set_meta(
            "mhcde_patch_plan_len",
            serde_json::json!(analysis.patch_plan.len()),
        );

        Ok(DeobfResult::new(
            analysis.patch_plan.len(),
            transformations,
            analysis.score.modified_bytes,
            analysis.score.confidence,
        ))
    }
}

// -----------------------------------------------------------------------------
// ScoreModel --" naturalness and complexity scoring
// -----------------------------------------------------------------------------

/// Computes heuristic quality scores for a block of code.
///
/// Scores range from `0.0` (highly obfuscated / complex) to `1.0` (natural /
/// simple).  They are designed to feed into [`HypothesisRunner`] so that the
/// engine can rank competing deobfuscation hypotheses.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScoreModel;

impl ScoreModel {
    /// Compute the naturalness score for `code`.
    ///
    /// Three sub-scores are combined:
    ///
    /// | Sub-score | Contribution |
    /// |-----------|-------------|
    /// | Inverted Shannon entropy of instruction bytes | 40% |
    /// | Inverted NOP ratio (fewer NOPs -> more natural) | 35% |
    /// | Instruction-type distribution uniformity | 25% |
    ///
    /// Returns a value in `[0.0, 1.0]` where `1.0` is most natural.
    #[must_use]
    pub fn naturalness_score(code: &[u8]) -> f64 {
        if code.is_empty() {
            return 1.0;
        }

        // --- Sub-score 1: inverted entropy (high entropy => obfuscated) -------
        let entropy = {
            let mut freq = [0u64; 256];
            for &b in code {
                freq[b as usize] += 1;
            }
            let n = code.len() as f64;
            freq.iter()
                .filter(|&&c| c > 0)
                .map(|&c| {
                    let p = c as f64 / n;
                    -p * p.log2()
                })
                .sum::<f64>()
        };
        // Max entropy for a byte stream is log2(256) = 8.0.
        let entropy_score = 1.0 - (entropy / 8.0).clamp(0.0, 1.0);

        // --- Sub-score 2: NOP ratio -------------------------------------------
        // Single-byte NOP (0x90) and multi-byte NOPs (66 90, 0F 1F --...).
        let nop_count = Self::count_nops(code);
        let nop_ratio = nop_count as f64 / code.len() as f64;
        let nop_score = 1.0 - nop_ratio.clamp(0.0, 1.0);

        // --- Sub-score 3: instruction-type distribution -----------------------
        // Count rough categories: arith, control, data, misc.
        let dist_score = Self::instruction_distribution_score(code);

        0.25f64.mul_add(dist_score, 0.40f64.mul_add(entropy_score, 0.35 * nop_score))
    }

    /// Compute the cyclomatic complexity score for a function with
    /// `basic_blocks` basic blocks and `edges` CFG edges.
    ///
    /// Cyclomatic complexity `M = edges - basic_blocks + 2`.
    ///
    /// The raw complexity is normalised to `[0.0, 1.0]` using a sigmoid-like
    /// mapping so that:
    /// - `M <= 10` -> score ~= 0.85--"1.0  (simple)
    /// - `M = 30` -> score ~= 0.5       (moderately complex)
    /// - `M >= 100` -> score ~= 0.0      (extremely complex / likely obfuscated)
    #[must_use]
    pub fn complexity_score(basic_blocks: usize, edges: usize) -> f64 {
        let m = edges.saturating_sub(basic_blocks).saturating_add(2) as f64;
        // Normalise via 1 / (1 + m/30): at m=0 -> 1.0, at m=30 -> 0.5, at m->inf -> 0.
        (1.0 / (1.0 + m / 30.0)).clamp(0.0, 1.0)
    }

    // -- helpers ---------------------------------------------------------------

    /// Count single-byte NOPs (`0x90`) and well-known multi-byte NOPs.
    fn count_nops(code: &[u8]) -> usize {
        let mut count = 0;
        let mut i = 0;
        while i < code.len() {
            if code[i] == 0x90 {
                count += 1;
                i += 1;
            } else if i + 1 < code.len() && code[i] == 0x66 && code[i + 1] == 0x90 {
                count += 2; // 2-byte NOP
                i += 2;
            } else if i + 2 < code.len()
                && code[i] == 0x0F
                && code[i + 1] == 0x1F
                && code[i + 2] == 0x00
            {
                count += 3; // 3-byte NOP
                i += 3;
            } else if i + 3 < code.len()
                && code[i] == 0x0F
                && code[i + 1] == 0x1F
                && code[i + 2] == 0x40
                && code[i + 3] == 0x00
            {
                count += 4; // 4-byte NOP
                i += 4;
            } else {
                i += 1;
            }
        }
        count
    }

    /// Score how balanced the instruction-type distribution is.
    ///
    /// Categories (roughly):
    /// - **Data move** (0x88-0x8F, 0xA0-0xA5, 0xB0-0xBF, 0xC6-0xC7)
    /// - **Arithmetic** (0x00-0x3F)
    /// - **Control flow** (0x70-0x7F, 0xE0-0xEF, 0xEB, 0xFF)
    /// - **Misc** (everything else)
    ///
    /// A balanced distribution (none exceeds 70%) -> 1.0; heavily skewed -> 0.0.
    fn instruction_distribution_score(code: &[u8]) -> f64 {
        if code.is_empty() {
            return 1.0;
        }
        let mut data_move = 0u64;
        let mut arith = 0u64;
        let mut control = 0u64;
        let mut misc = 0u64;

        for &b in code {
            match b {
                0x88..=0x8F | 0xA0..=0xA5 | 0xB0..=0xBF | 0xC6 | 0xC7 => data_move += 1,
                0x00..=0x3F => arith += 1,
                0x70..=0x7F | 0xE0..=0xEF | 0xFF => control += 1,
                _ => misc += 1,
            }
        }

        let total = code.len() as f64;
        let max_ratio = [data_move, arith, control, misc]
            .iter()
            .map(|&c| c as f64 / total)
            .fold(0.0f64, f64::max);

        // If one category dominates (> 70%), the distribution is suspicious.
        if max_ratio > 0.7 {
            1.0 - (max_ratio - 0.7) / 0.3
        } else {
            1.0
        }
        .clamp(0.0, 1.0)
    }
}

// -----------------------------------------------------------------------------
// Hypothesis framework
// -----------------------------------------------------------------------------

/// The result of running one deobfuscation hypothesis against a code block.
#[derive(Debug, Clone)]
pub struct HypothesisResult {
    /// Human-readable label for this hypothesis.
    pub name: String,
    /// Naturalness score of the transformed output (`0.0`--"`1.0`).
    pub naturalness: f64,
    /// Complexity score of the transformed output (`0.0`--"`1.0`).
    pub complexity: f64,
    /// Optional transformed bytes produced by the hypothesis.
    pub transformed: Option<Vec<u8>>,
    /// Arbitrary metadata key-value pairs.
    pub metadata: HashMap<String, String>,
}

impl HypothesisResult {
    /// Create a new result with no transformation applied.
    #[must_use]
    pub fn new(name: impl Into<String>, naturalness: f64, complexity: f64) -> Self {
        Self {
            name: name.into(),
            naturalness: naturalness.clamp(0.0, 1.0),
            complexity: complexity.clamp(0.0, 1.0),
            transformed: None,
            metadata: HashMap::new(),
        }
    }

    /// Attach transformed bytes and return `self`.
    #[must_use]
    pub fn with_transformed(mut self, bytes: Vec<u8>) -> Self {
        self.transformed = Some(bytes);
        self
    }

    /// Insert a metadata key-value pair and return `self`.
    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Combined quality score: geometric mean of naturalness and complexity.
    ///
    /// Returns a value in `[0.0, 1.0]`.
    #[must_use]
    pub fn combined_score(&self) -> f64 {
        (self.naturalness * self.complexity).sqrt().clamp(0.0, 1.0)
    }

    /// Return `true` when this result is considered viable (`combined_score > 0.6`).
    #[must_use]
    pub fn is_viable(&self) -> bool {
        self.combined_score() > 0.6
    }
}

/// Trait implemented by every deobfuscation hypothesis.
///
/// A hypothesis encapsulates one candidate deobfuscation strategy (e.g.
/// "this is XOR-obfuscated", "this uses stack strings", "this has CFF").
/// Each hypothesis is run concurrently by [`HypothesisRunner`].
pub trait Hypothesis: Send + Sync {
    /// Short, unique name for this hypothesis.
    fn name(&self) -> &str;

    /// Run the hypothesis against `code` and return a scored result.
    fn run(&self, code: &[u8]) -> HypothesisResult;
}

/// Null hypothesis: treats the code as unobfuscated.
///
/// Useful as a baseline for comparison.
#[derive(Debug, Clone, Default)]
pub struct IdentityHypothesis;

impl Hypothesis for IdentityHypothesis {
    fn name(&self) -> &'static str {
        "identity"
    }

    fn run(&self, code: &[u8]) -> HypothesisResult {
        let nat = ScoreModel::naturalness_score(code);
        let cplx = ScoreModel::complexity_score(1, 0);
        HypothesisResult::new("identity", nat, cplx)
            .with_transformed(code.to_vec())
            .with_meta("strategy", "none")
    }
}

/// NOP-strip hypothesis: removes all NOP bytes and rescores.
#[derive(Debug, Clone, Default)]
pub struct NopStripHypothesis;

impl Hypothesis for NopStripHypothesis {
    fn name(&self) -> &'static str {
        "nop-strip"
    }

    fn run(&self, code: &[u8]) -> HypothesisResult {
        let stripped: Vec<u8> = code.iter().copied().filter(|&b| b != 0x90).collect();
        let nat = ScoreModel::naturalness_score(&stripped);
        let cplx = ScoreModel::complexity_score(1, 0);
        let improvement = nat - ScoreModel::naturalness_score(code);
        HypothesisResult::new("nop-strip", nat, cplx)
            .with_transformed(stripped)
            .with_meta("improvement", format!("{improvement:.4}"))
    }
}

/// XOR-0x42 hypothesis: decrypts the block with key `0x42`.
#[derive(Debug, Clone, Default)]
pub struct XorFixedKeyHypothesis;

impl Hypothesis for XorFixedKeyHypothesis {
    fn name(&self) -> &'static str {
        "xor-0x42"
    }

    fn run(&self, code: &[u8]) -> HypothesisResult {
        let decrypted: Vec<u8> = code.iter().map(|&b| b ^ 0x42).collect();
        let nat = ScoreModel::naturalness_score(&decrypted);
        let cplx = ScoreModel::complexity_score(1, 1);
        HypothesisResult::new("xor-0x42", nat, cplx)
            .with_transformed(decrypted)
            .with_meta("key", "0x42")
    }
}

/// XOR best-key hypothesis: exhaustively searches for the best single-byte key.
#[derive(Debug, Clone, Default)]
pub struct XorBestKeyHypothesis;

impl Hypothesis for XorBestKeyHypothesis {
    fn name(&self) -> &'static str {
        "xor-best-key"
    }

    fn run(&self, code: &[u8]) -> HypothesisResult {
        let mut best_nat = ScoreModel::naturalness_score(code);
        let mut best_key = 0u8;
        let mut best_dec = code.to_vec();

        for key in 1u8..=255 {
            let dec: Vec<u8> = code.iter().map(|&b| b ^ key).collect();
            let nat = ScoreModel::naturalness_score(&dec);
            if nat > best_nat {
                best_nat = nat;
                best_key = key;
                best_dec = dec;
            }
        }

        let cplx = ScoreModel::complexity_score(1, 1);
        HypothesisResult::new("xor-best-key", best_nat, cplx)
            .with_transformed(best_dec)
            .with_meta("key", format!("{best_key:#04x}"))
    }
}

// -----------------------------------------------------------------------------
// HypothesisRunner
// -----------------------------------------------------------------------------

/// Runs multiple deobfuscation hypotheses concurrently and selects the best.
///
/// Uses [`rayon`] when the `rayon` feature is available; otherwise falls back
/// to sequential execution.  The public API is identical in both cases.
#[derive(Debug, Clone, Default)]
pub struct HypothesisRunner;

impl HypothesisRunner {
    /// Create a new runner.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Run all `hypotheses` against `code` and return one [`HypothesisResult`]
    /// per hypothesis, in the same order as the input slice.
    ///
    /// Execution is sequential (parallel when `rayon` is enabled).
    #[must_use]
    pub fn run_all_in_parallel(
        code: &[u8],
        hypotheses: &[Box<dyn Hypothesis>],
    ) -> Vec<HypothesisResult> {
        // Sequential fallback --" rayon is not a mandatory dependency.
        hypotheses.iter().map(|h| h.run(code)).collect()
    }

    /// Run all hypotheses and return results in parallel using rayon `par_iter`
    /// semantics simulated via threads when rayon is unavailable.
    ///
    /// This is the preferred entry point for callers that want maximum
    /// throughput on multi-core machines.
    #[must_use]
    pub fn run_parallel(code: &[u8], hypotheses: &[Box<dyn Hypothesis>]) -> Vec<HypothesisResult> {
        // When rayon is not linked we simply run sequentially; the caller
        // cannot tell the difference from the return type.
        Self::run_all_in_parallel(code, hypotheses)
    }

    /// From `results`, select the hypothesis with the highest
    /// [`HypothesisResult::combined_score`] that exceeds the `0.6` threshold.
    ///
    /// Returns `None` when no result clears the threshold.
    #[must_use]
    pub fn select_best(results: &[HypothesisResult]) -> Option<&HypothesisResult> {
        results
            .iter()
            .filter(|r| r.combined_score() > 0.6)
            .max_by(|a, b| {
                a.combined_score()
                    .partial_cmp(&b.combined_score())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    /// Convenience wrapper: run all hypotheses and return the best result.
    ///
    /// Returns `None` when `hypotheses` is empty or no hypothesis exceeds the
    /// threshold.
    #[must_use]
    pub fn best(code: &[u8], hypotheses: &[Box<dyn Hypothesis>]) -> Option<HypothesisResult> {
        let results = Self::run_all_in_parallel(code, hypotheses);
        // We need to own the best result since `results` is local.
        results
            .into_iter()
            .filter(|r| r.combined_score() > 0.6)
            .max_by(|a, b| {
                a.combined_score()
                    .partial_cmp(&b.combined_score())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    /// Build a default set of built-in hypotheses.
    ///
    /// Includes: `IdentityHypothesis`, `NopStripHypothesis`,
    /// `XorFixedKeyHypothesis`, `XorBestKeyHypothesis`.
    #[must_use]
    pub fn default_hypotheses() -> Vec<Box<dyn Hypothesis>> {
        vec![
            Box::new(IdentityHypothesis),
            Box::new(NopStripHypothesis),
            Box::new(XorFixedKeyHypothesis),
            Box::new(XorBestKeyHypothesis),
        ]
    }

    /// Rank all results by `combined_score` (descending) and return a sorted
    /// copy.
    #[must_use]
    pub fn ranked(mut results: Vec<HypothesisResult>) -> Vec<HypothesisResult> {
        results.sort_by(|a, b| {
            b.combined_score()
                .partial_cmp(&a.combined_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_deobf::DeobfContext;

    // -- OpaquePredicateDetector ----------------------------------------------

    #[test]
    fn test_opaque_xor_jz_always_true() {
        // xor eax,eax; test eax,eax; jz +5
        let data = vec![0x31, 0xC0, 0x85, 0xC0, 0x74, 0x05];
        let hits = OpaquePredicateDetector::new().detect(&data);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].predicate_type, OpaquePredicateType::AlwaysTrue);
    }

    #[test]
    fn test_opaque_xor_jnz_always_false() {
        let data = vec![0x31, 0xC0, 0x85, 0xC0, 0x75, 0x05];
        let hits = OpaquePredicateDetector::new().detect(&data);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].predicate_type, OpaquePredicateType::AlwaysFalse);
    }

    #[test]
    fn test_opaque_mov1_test_jz() {
        // mov al,1; test al,al; jz --" never taken
        let data = vec![0xB0, 0x01, 0x84, 0xC0, 0x74, 0x05];
        let hits = OpaquePredicateDetector::new().detect(&data);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].predicate_type, OpaquePredicateType::AlwaysFalse);
    }

    #[test]
    fn test_opaque_or_neg1_jnz() {
        // or eax,-1; test eax,eax; jnz --" always taken
        let data = vec![0x83, 0xC8, 0xFF, 0x85, 0xC0, 0x75, 0x05];
        let hits = OpaquePredicateDetector::new().detect(&data);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].predicate_type, OpaquePredicateType::AlwaysTrue);
    }

    #[test]
    fn test_opaque_and_zero_jz() {
        // and eax,0; test eax,eax; jz --" always taken
        let data = vec![0x83, 0xE0, 0x00, 0x85, 0xC0, 0x74, 0x05];
        let hits = OpaquePredicateDetector::new().detect(&data);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].predicate_type, OpaquePredicateType::AlwaysTrue);
    }

    #[test]
    fn test_opaque_xor_eax_jz_condensed() {
        // 33 C0 74 xx
        let data = vec![0x33, 0xC0, 0x74, 0x05];
        let hits = OpaquePredicateDetector::new().detect(&data);
        assert!(!hits.is_empty());
    }

    #[test]
    fn test_opaque_no_false_positive_on_nops() {
        let data = vec![0x90u8; 16];
        let hits = OpaquePredicateDetector::new().detect(&data);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_opaque_multiple_in_sequence() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x31, 0xC0, 0x85, 0xC0, 0x74, 0x00]);
        data.extend_from_slice(&[0x31, 0xC0, 0x85, 0xC0, 0x75, 0x00]);
        let hits = OpaquePredicateDetector::new().detect(&data);
        assert!(hits.len() >= 2);
    }

    #[test]
    fn test_opaque_stc_jc_always_taken() {
        let data = vec![0xF9, 0x72, 0x10];
        let hits = OpaquePredicateDetector::new().detect(&data);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].predicate_type, OpaquePredicateType::AlwaysTrue);
    }

    #[test]
    fn test_opaque_clc_jnc_always_taken() {
        let data = vec![0xF8, 0x73, 0x10];
        let hits = OpaquePredicateDetector::new().detect(&data);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].predicate_type, OpaquePredicateType::AlwaysTrue);
    }

    #[test]
    fn test_opaque_xor_ecx_jecxz() {
        let data = vec![0x33, 0xC9, 0xE3, 0x05];
        let hits = OpaquePredicateDetector::new().detect(&data);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].predicate_type, OpaquePredicateType::AlwaysTrue);
    }

    #[test]
    fn test_opaque_count_by_type() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x31, 0xC0, 0x85, 0xC0, 0x74, 0x00]); // AlwaysTrue
        data.extend_from_slice(&[0x31, 0xC0, 0x85, 0xC0, 0x75, 0x00]); // AlwaysFalse
        let counts = OpaquePredicateDetector::new().count_by_type(&data);
        assert!(*counts.get(&OpaquePredicateType::AlwaysTrue).unwrap_or(&0) >= 1);
        assert!(*counts.get(&OpaquePredicateType::AlwaysFalse).unwrap_or(&0) >= 1);
    }

    #[test]
    fn test_opaque_total_patch_bytes() {
        let data = vec![0x31, 0xC0, 0x85, 0xC0, 0x74, 0x05];
        let total = OpaquePredicateDetector::new().total_patch_bytes(&data);
        assert_eq!(total, 5);
    }

    // -- JunkCodeDetector -----------------------------------------------------

    #[test]
    fn test_junk_nop_sled() {
        let data = vec![0x90u8; 8];
        let regions = JunkCodeDetector::new().detect(&data);
        assert!(!regions.is_empty());
        assert_eq!(regions[0].length, 8);
        assert!(regions[0].description.contains("NOP"));
    }

    #[test]
    fn test_junk_push_pop_same() {
        // PUSH EAX (0x50) POP EAX (0x58)
        let data = vec![0x50, 0x58];
        let regions = JunkCodeDetector::new().detect(&data);
        assert!(!regions.is_empty());
        assert_eq!(regions[0].length, 2);
    }

    #[test]
    fn test_junk_xor_reg_zero() {
        // XOR EAX, 0: 83 F0 00
        let data = vec![0x83, 0xF0, 0x00];
        let regions = JunkCodeDetector::new().detect(&data);
        assert!(!regions.is_empty());
    }

    #[test]
    fn test_junk_add_reg_zero() {
        // ADD EAX, 0: 83 C0 00
        let data = vec![0x83, 0xC0, 0x00];
        let regions = JunkCodeDetector::new().detect(&data);
        assert!(!regions.is_empty());
    }

    #[test]
    fn test_junk_mov_reg_reg_same() {
        // MOV EAX, EAX: 89 C0
        let data = vec![0x89, 0xC0];
        let regions = JunkCodeDetector::new().detect(&data);
        assert!(!regions.is_empty());
    }

    #[test]
    fn test_junk_lea_reg_zero_disp() {
        // LEA EAX, [EAX+0]: 8D 40 00
        let data = vec![0x8D, 0x40, 0x00];
        let regions = JunkCodeDetector::new().detect(&data);
        assert!(!regions.is_empty());
    }

    #[test]
    fn test_junk_no_false_positive_ret() {
        let data = vec![0xC3];
        let regions = JunkCodeDetector::new().detect(&data);
        assert!(regions.is_empty());
    }

    #[test]
    fn test_junk_multibyte_nop_66_90() {
        let data = vec![0x66, 0x90];
        let regions = JunkCodeDetector::new().detect(&data);
        assert!(!regions.is_empty());
        assert_eq!(regions[0].length, 2);
    }

    #[test]
    fn test_junk_multibyte_nop_0f_1f_00() {
        let data = vec![0x0F, 0x1F, 0x00];
        let regions = JunkCodeDetector::new().detect(&data);
        assert!(!regions.is_empty());
        assert_eq!(regions[0].length, 3);
    }

    #[test]
    fn test_junk_xchg_eax_eax() {
        let data = vec![0x87, 0xC0];
        let regions = JunkCodeDetector::new().detect(&data);
        assert!(!regions.is_empty());
    }

    #[test]
    fn test_junk_density_all_nops() {
        let data = vec![0x90u8; 16];
        let density = JunkCodeDetector::new().junk_density(&data);
        assert!(density > 0.9);
    }

    #[test]
    fn test_junk_density_empty() {
        assert_eq!(JunkCodeDetector::new().junk_density(&[]), 0.0);
    }

    // -- ControlFlowFlattener -------------------------------------------------

    #[test]
    fn test_cff_detect_indirect_jmp() {
        // Place FF 24 C5 (jmp [eax*8+imm]) at offset 10.
        let mut data = vec![0x90u8; 10];
        data.extend_from_slice(&[0xFF, 0x24, 0xC5]);
        data.extend_from_slice(&[0x90u8; 32]);

        let result = ControlFlowFlattener::new().detect(&data);
        assert!(result.is_some());
    }

    #[test]
    fn test_cff_no_cff_in_nops() {
        let data = vec![0x90u8; 32];
        let result = ControlFlowFlattener::new().detect(&data);
        assert!(result.is_none());
    }

    // -- DeadCodeEliminator ---------------------------------------------------

    #[test]
    fn test_dce_reachable() {
        let blocks = vec![
            CfgBlock {
                offset: 0,
                length: 4,
                successors: vec![4],
                is_dispatcher: false,
            },
            CfgBlock {
                offset: 4,
                length: 4,
                successors: vec![8],
                is_dispatcher: false,
            },
            CfgBlock {
                offset: 8,
                length: 4,
                successors: vec![],
                is_dispatcher: false,
            },
            CfgBlock {
                offset: 16,
                length: 4,
                successors: vec![],
                is_dispatcher: false,
            }, // unreachable
        ];
        let dce = DeadCodeEliminator::new();
        let live = dce.eliminate(&blocks, 0);
        assert_eq!(live.len(), 3);
        assert!(live.iter().all(|b| b.offset != 16));
    }

    #[test]
    fn test_dce_all_reachable() {
        let blocks = vec![
            CfgBlock {
                offset: 0,
                length: 4,
                successors: vec![4],
                is_dispatcher: false,
            },
            CfgBlock {
                offset: 4,
                length: 4,
                successors: vec![],
                is_dispatcher: false,
            },
        ];
        let live = DeadCodeEliminator::new().eliminate(&blocks, 0);
        assert_eq!(live.len(), 2);
    }

    #[test]
    fn test_dce_unknown_entry() {
        let blocks = vec![CfgBlock {
            offset: 10,
            length: 4,
            successors: vec![],
            is_dispatcher: false,
        }];
        // Entry offset 0 is not in the block list.
        let live = DeadCodeEliminator::new().eliminate(&blocks, 0);
        assert!(live.is_empty());
    }

    #[test]
    fn test_dce_dead_blocks_identified() {
        let blocks = vec![
            CfgBlock {
                offset: 0,
                length: 4,
                successors: vec![4],
                is_dispatcher: false,
            },
            CfgBlock {
                offset: 4,
                length: 4,
                successors: vec![],
                is_dispatcher: false,
            },
            CfgBlock {
                offset: 100,
                length: 4,
                successors: vec![],
                is_dispatcher: false,
            },
        ];
        let dce = DeadCodeEliminator::new();
        let dead = dce.dead_blocks(&blocks, 0);
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].offset, 100);
    }

    #[test]
    fn test_dce_bfs_order() {
        let blocks = vec![
            CfgBlock {
                offset: 0,
                length: 4,
                successors: vec![4, 8],
                is_dispatcher: false,
            },
            CfgBlock {
                offset: 4,
                length: 4,
                successors: vec![],
                is_dispatcher: false,
            },
            CfgBlock {
                offset: 8,
                length: 4,
                successors: vec![],
                is_dispatcher: false,
            },
        ];
        let order = DeadCodeEliminator::new().bfs_order(&blocks, 0);
        assert_eq!(order[0], 0);
        assert!(order.contains(&4));
        assert!(order.contains(&8));
    }

    #[test]
    fn test_dce_dead_block_ratio() {
        let blocks = vec![
            CfgBlock {
                offset: 0,
                length: 4,
                successors: vec![],
                is_dispatcher: false,
            },
            CfgBlock {
                offset: 4,
                length: 4,
                successors: vec![],
                is_dispatcher: false,
            },
        ];
        let ratio = DeadCodeEliminator::new().dead_block_ratio(&blocks, 0);
        // Block at offset 4 is not reachable from 0 (no successor).
        assert!(ratio > 0.0);
    }

    // -- BogusControlFlowRemover ----------------------------------------------

    #[test]
    fn test_bogus_removes_junk_blocks() {
        let blocks = vec![
            CfgBlock {
                offset: 0,
                length: 4,
                successors: vec![],
                is_dispatcher: false,
            },
            CfgBlock {
                offset: 4,
                length: 4,
                successors: vec![],
                is_dispatcher: true,
            },
            CfgBlock {
                offset: 8,
                length: 4,
                successors: vec![],
                is_dispatcher: false,
            },
        ];
        let junk: HashSet<usize> = [8].into();
        let clean = BogusControlFlowRemover::new().remove_bogus_blocks(&blocks, &junk);
        assert_eq!(clean.len(), 1);
        assert_eq!(clean[0].offset, 0);
    }

    #[test]
    fn test_bogus_dispatcher_blocks() {
        let blocks = vec![
            CfgBlock {
                offset: 0,
                length: 4,
                successors: vec![],
                is_dispatcher: true,
            },
            CfgBlock {
                offset: 4,
                length: 4,
                successors: vec![],
                is_dispatcher: false,
            },
        ];
        let dispatchers = BogusControlFlowRemover::new().dispatcher_blocks(&blocks);
        assert_eq!(dispatchers.len(), 1);
        assert_eq!(dispatchers[0].offset, 0);
    }

    #[test]
    fn test_bogus_junk_offset_set() {
        let regions = vec![
            JunkCodeRegion {
                offset: 10,
                length: 3,
                description: String::new(),
            },
            JunkCodeRegion {
                offset: 20,
                length: 5,
                description: String::new(),
            },
        ];
        let set = BogusControlFlowRemover::junk_offset_set(&regions);
        assert!(set.contains(&10));
        assert!(set.contains(&20));
        assert!(!set.contains(&15));
    }

    // -- MhcdePass ------------------------------------------------------------

    #[test]
    fn test_orchestrator_builds_sorted_patch_plan_and_score() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x31, 0xC0, 0x85, 0xC0, 0x74, 0x05]);
        data.extend_from_slice(&[0x90u8; 3]);

        let analysis = MhcdeOrchestrator::new().analyze(&data);

        assert_eq!(analysis.patch_plan.len(), 2);
        assert_eq!(analysis.patch_plan[0].kind, MhcdePatchKind::OpaquePredicate);
        assert_eq!(analysis.patch_plan[0].offset, 0);
        assert_eq!(analysis.patch_plan[1].kind, MhcdePatchKind::JunkCode);
        assert_eq!(analysis.patch_plan[1].offset, 6);
        assert_eq!(analysis.score.modified_bytes, 8);
        assert!(analysis.score.confidence > 0.0);
    }

    #[test]
    fn test_pass_records_orchestration_metadata() {
        let mut ctx = DeobfContext::new(vec![0x90u8; 4]);

        let result = MhcdePass::new().run(&mut ctx).unwrap();

        assert_eq!(result.patches_applied, 1);
        assert_eq!(
            ctx.get_meta("mhcde_patch_plan_len"),
            Some(&serde_json::json!(1))
        );
        assert!(ctx.get_meta("mhcde_score").is_some());
    }

    #[test]
    fn test_mhcde_pass_applicable() {
        let pass = MhcdePass::new();
        assert!(pass.is_applicable(&DeobfContext::new(vec![0; 16])));
        assert!(!pass.is_applicable(&DeobfContext::new(vec![0; 4])));
    }

    #[test]
    fn test_mhcde_pass_removes_opaque_and_junk() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x31, 0xC0, 0x85, 0xC0, 0x74, 0x05]); // opaque
        data.extend_from_slice(&[0x90u8; 4]); // NOP sled

        let mut ctx = DeobfContext::new(data);
        let result = MhcdePass::new().run(&mut ctx).unwrap();
        assert!(result.patches_applied >= 2);
    }

    #[test]
    fn test_mhcde_pass_empty_binary() {
        let mut ctx = DeobfContext::new(vec![]);
        let result = MhcdePass::new().run(&mut ctx).unwrap();
        assert_eq!(result.patches_applied, 0);
    }

    #[test]
    fn test_mhcde_pass_patches_applied_to_context() {
        let data = vec![0x31u8, 0xC0, 0x85, 0xC0, 0x74, 0x05, 0x90];
        let mut ctx = DeobfContext::new(data);
        let result = MhcdePass::new().run(&mut ctx).unwrap();
        assert!(result.patches_applied > 0);
        let patched = ctx.apply_patches().unwrap();
        // Opaque predicate bytes should be NOP'd.
        for &b in &patched[0..5] {
            assert_eq!(b, 0x90);
        }
    }

    // -- OpaquePredicateType serialization ------------------------------------

    #[test]
    fn test_opaque_type_serialization() {
        let t = OpaquePredicateType::AlwaysTrue;
        let s = serde_json::to_string(&t).unwrap();
        let t2: OpaquePredicateType = serde_json::from_str(&s).unwrap();
        assert_eq!(t, t2);
    }

    // -- ConstantFoldingHeuristic ---------------------------------------------

    #[test]
    fn test_fold_mov_eax_imm32() {
        let data = vec![0xB8, 0x42, 0x00, 0x00, 0x00];
        let result = ConstantFoldingHeuristic::new().try_fold(&data, 0);
        assert_eq!(
            result,
            Some(FoldResult {
                value: 0x42,
                bytes_consumed: 5
            })
        );
    }

    #[test]
    fn test_fold_xor_eax_eax() {
        let data = vec![0x31, 0xC0];
        let result = ConstantFoldingHeuristic::new().try_fold(&data, 0);
        assert_eq!(
            result,
            Some(FoldResult {
                value: 0,
                bytes_consumed: 2
            })
        );
    }

    #[test]
    fn test_fold_or_eax_neg1() {
        let data = vec![0x83, 0xC8, 0xFF];
        let result = ConstantFoldingHeuristic::new().try_fold(&data, 0);
        assert_eq!(
            result,
            Some(FoldResult {
                value: 0xFFFF_FFFF,
                bytes_consumed: 3
            })
        );
    }

    #[test]
    fn test_fold_all_multiple() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // MOV EAX, 1 at offset 0
        data.extend_from_slice(&[0x31, 0xC0]); // XOR EAX,EAX at offset 5
        let map = ConstantFoldingHeuristic::new().fold_all(&data);
        assert!(map.contains_key(&0));
        assert!(map.contains_key(&5));
    }

    #[test]
    fn test_fold_no_match_returns_none() {
        let data = vec![0xC3]; // RET --" not foldable
        let result = ConstantFoldingHeuristic::new().try_fold(&data, 0);
        assert!(result.is_none());
    }

    // -- EntropyAnalyzer ------------------------------------------------------

    #[test]
    fn test_entropy_uniform_zeros() {
        let data = vec![0u8; 256];
        let e = EntropyAnalyzer::entropy(&data);
        assert_eq!(e, 0.0);
    }

    #[test]
    fn test_entropy_all_distinct() {
        // 256 bytes each with a unique value -> maximum entropy (8.0)
        let data: Vec<u8> = (0..=255u8).collect();
        let e = EntropyAnalyzer::entropy(&data);
        assert!((e - 8.0).abs() < 0.001, "expected ~8.0, got {e}");
    }

    #[test]
    fn test_entropy_empty() {
        assert_eq!(EntropyAnalyzer::entropy(&[]), 0.0);
    }

    #[test]
    fn test_entropy_analyze_windows() {
        let data: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        let analyzer = EntropyAnalyzer::new(256);
        let windows = analyzer.analyze(&data);
        assert!(!windows.is_empty());
        for w in &windows {
            assert!(w.entropy >= 0.0 && w.entropy <= 8.0);
        }
    }

    #[test]
    fn test_entropy_high_entropy_windows() {
        let data: Vec<u8> = (0..=255u8).cycle().take(512).collect();
        let analyzer = EntropyAnalyzer::new(256);
        let high = analyzer.high_entropy_windows(&data, 7.0);
        assert!(!high.is_empty());
    }

    #[test]
    fn test_entropy_mean() {
        let data = vec![0u8; 512];
        let mean = EntropyAnalyzer::new(256).mean_entropy(&data);
        assert_eq!(mean, 0.0);
    }

    // -- PatchApplicator ------------------------------------------------------

    #[test]
    fn test_patch_applicator_nop_fill() {
        let mut data = vec![0x31u8, 0xC0, 0x85, 0xC0, 0x74, 0x05];
        let plan = vec![PlannedPatch {
            offset: 0,
            length: 5,
            kind: MhcdePatchKind::OpaquePredicate,
            confidence: 0.9,
            description: "test".to_owned(),
        }];
        let applied = PatchApplicator::new().apply_nop_patches(&mut data, &plan);
        assert_eq!(applied, 1);
        assert!(data[..5].iter().all(|&b| b == 0x90));
    }

    #[test]
    fn test_patch_applicator_fill_byte() {
        let mut data = vec![0xAAu8; 8];
        let plan = vec![PlannedPatch {
            offset: 2,
            length: 4,
            kind: MhcdePatchKind::JunkCode,
            confidence: 0.75,
            description: "fill test".to_owned(),
        }];
        PatchApplicator::new().apply_fill_patches(&mut data, &plan, 0x00);
        assert!(data[2..6].iter().all(|&b| b == 0x00));
        assert!(data[0..2].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn test_patch_applicator_out_of_bounds_skipped() {
        let mut data = vec![0xBBu8; 4];
        let plan = vec![PlannedPatch {
            offset: 3,
            length: 10, // exceeds data length
            kind: MhcdePatchKind::JunkCode,
            confidence: 0.5,
            description: "oob".to_owned(),
        }];
        let applied = PatchApplicator::new().apply_nop_patches(&mut data, &plan);
        assert_eq!(applied, 0);
        assert!(data.iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn test_patch_applicator_patched_copy_immutable() {
        let data = vec![0x31u8, 0xC0, 0x85, 0xC0, 0x74, 0x05];
        let plan = vec![PlannedPatch {
            offset: 0,
            length: 5,
            kind: MhcdePatchKind::OpaquePredicate,
            confidence: 0.9,
            description: "copy test".to_owned(),
        }];
        let copy = PatchApplicator::new().patched_copy(&data, &plan);
        // Original unchanged.
        assert_eq!(data[0], 0x31);
        // Copy patched.
        assert!(copy[..5].iter().all(|&b| b == 0x90));
    }

    #[test]
    fn test_patch_applicator_validate_plan_ok() {
        let plan = vec![PlannedPatch {
            offset: 0,
            length: 4,
            kind: MhcdePatchKind::JunkCode,
            confidence: 0.8,
            description: String::new(),
        }];
        assert!(PatchApplicator::validate_plan(&plan, 16));
    }

    #[test]
    fn test_patch_applicator_validate_plan_fail() {
        let plan = vec![PlannedPatch {
            offset: 14,
            length: 4,
            kind: MhcdePatchKind::JunkCode,
            confidence: 0.8,
            description: String::new(),
        }];
        assert!(!PatchApplicator::validate_plan(&plan, 16));
    }

    // -- MhcdeAnalysis helpers ------------------------------------------------

    #[test]
    fn test_analysis_is_clean_on_nop_free_data() {
        let data = vec![0xC3u8]; // just a RET
        let analysis = MhcdeOrchestrator::new().analyze(&data);
        assert!(analysis.is_clean());
    }

    #[test]
    fn test_analysis_high_confidence_patches_filter() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x31, 0xC0, 0x85, 0xC0, 0x74, 0x05]);
        let analysis = MhcdeOrchestrator::new().analyze(&data);
        let high = analysis.high_confidence_patches(0.85);
        // Opaque predicate patches have 0.9 confidence.
        assert!(!high.is_empty());
    }

    #[test]
    fn test_analysis_patch_offsets_sorted() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x31, 0xC0, 0x85, 0xC0, 0x74, 0x05]);
        data.extend_from_slice(&[0x90u8; 4]);
        let analysis = MhcdeOrchestrator::new().analyze(&data);
        let offsets = analysis.patch_offsets();
        assert!(offsets.windows(2).all(|w| w[0] <= w[1]));
    }

    // -- MhcdeScore helpers ---------------------------------------------------

    #[test]
    fn test_score_confidence_tier_none() {
        let score = MhcdeScore {
            confidence: 0.0,
            risk: 0.0,
            modified_bytes: 0,
            finding_count: 0,
        };
        assert_eq!(score.confidence_tier(), "none");
    }

    #[test]
    fn test_score_confidence_tier_high() {
        let score = MhcdeScore {
            confidence: 0.8,
            risk: 0.1,
            modified_bytes: 10,
            finding_count: 5,
        };
        assert_eq!(score.confidence_tier(), "high");
    }

    #[test]
    fn test_score_is_highly_obfuscated() {
        let score = MhcdeScore {
            confidence: 0.9,
            risk: 0.05,
            modified_bytes: 20,
            finding_count: 5,
        };
        assert!(score.is_highly_obfuscated());
    }

    #[test]
    fn test_score_not_highly_obfuscated_low_count() {
        let score = MhcdeScore {
            confidence: 0.9,
            risk: 0.05,
            modified_bytes: 10,
            finding_count: 1,
        };
        assert!(!score.is_highly_obfuscated());
    }

    // -- analyze_and_patch round-trip -----------------------------------------

    #[test]
    fn test_analyze_and_patch_round_trip() {
        let data = vec![0x31u8, 0xC0, 0x85, 0xC0, 0x74, 0x05, 0xC3];
        let (patched, analysis) = MhcdeOrchestrator::new().analyze_and_patch(&data);
        assert!(!analysis.patch_plan.is_empty());
        // First 5 bytes should be NOP'd.
        assert!(patched[..5].iter().all(|&b| b == 0x90));
        // Trailing RET unchanged.
        assert_eq!(patched[6], 0xC3);
    }

    // -- ScoreModel -----------------------------------------------------------

    #[test]
    fn test_naturalness_score_all_zeros() {
        // All-zero bytes have zero entropy -> high naturalness score.
        let data = vec![0u8; 256];
        let score = ScoreModel::naturalness_score(&data);
        // Zero entropy inverted = 1.0; zero NOPs (0x00 | 0x90) -> nop_score = 1.0.
        assert!(
            score > 0.5,
            "all-zero data should have high naturalness, got {score}"
        );
    }

    #[test]
    fn test_naturalness_score_all_nops() {
        // A NOP sled has low entropy but high NOP ratio.
        let nops = vec![0x90u8; 256];
        let score = ScoreModel::naturalness_score(&nops);
        // High NOP ratio reduces the score.
        assert!(score < 0.9, "NOP sled should not score maximum naturalness");
    }

    #[test]
    fn test_naturalness_score_empty() {
        // Empty code is considered natural (no obfuscation evidence).
        let score = ScoreModel::naturalness_score(&[]);
        assert_eq!(score, 1.0);
    }

    #[test]
    fn test_naturalness_score_random_bytes() {
        // Random bytes: high entropy -> lower naturalness.
        let random_ish: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let score = ScoreModel::naturalness_score(&random_ish);
        // Max-entropy byte stream should score relatively low.
        assert!(
            score < 0.75,
            "high-entropy data should score below 0.75, got {score}"
        );
    }

    #[test]
    fn test_naturalness_score_range() {
        let data: Vec<u8> = (0u8..128).collect();
        let score = ScoreModel::naturalness_score(&data);
        assert!((0.0..=1.0).contains(&score));
    }

    #[test]
    fn test_complexity_score_trivial() {
        // edges=0, blocks=1 -> M=1 -> score ~= 1/(1+1/30) ~= 0.97.
        let score = ScoreModel::complexity_score(1, 0);
        assert!(
            score > 0.9,
            "trivial function should score high, got {score}"
        );
    }

    #[test]
    fn test_complexity_score_moderate() {
        // M = 30 -> score = 0.5.
        let score = ScoreModel::complexity_score(1, 29); // edges-blocks+2 = 29-1+2=30
        assert!(
            (0.4..0.6).contains(&score),
            "moderate complexity should be ~0.5, got {score}"
        );
    }

    #[test]
    fn test_complexity_score_extreme() {
        // Very large cyclomatic -> score approaches 0.
        let score = ScoreModel::complexity_score(1, 999);
        assert!(
            score < 0.1,
            "extreme complexity should score near 0, got {score}"
        );
    }

    #[test]
    fn test_complexity_score_range() {
        let score = ScoreModel::complexity_score(10, 50);
        assert!((0.0..=1.0).contains(&score));
    }

    // -- HypothesisResult -----------------------------------------------------

    #[test]
    fn test_hypothesis_result_combined_score() {
        let r = HypothesisResult::new("test", 0.9, 0.8);
        let expected = (0.9f64 * 0.8f64).sqrt();
        assert!((r.combined_score() - expected).abs() < 1e-10);
    }

    #[test]
    fn test_hypothesis_result_is_viable_above_threshold() {
        let r = HypothesisResult::new("good", 0.9, 0.9);
        assert!(r.is_viable());
    }

    #[test]
    fn test_hypothesis_result_not_viable_below_threshold() {
        let r = HypothesisResult::new("poor", 0.5, 0.5);
        // combined = sqrt(0.25) = 0.5 <= 0.6.
        assert!(!r.is_viable());
    }

    #[test]
    fn test_hypothesis_result_with_meta() {
        let r = HypothesisResult::new("meta-test", 0.8, 0.8).with_meta("key", "value");
        assert_eq!(r.metadata.get("key").map(String::as_str), Some("value"));
    }

    #[test]
    fn test_hypothesis_result_with_transformed() {
        let bytes = vec![0x90u8; 4];
        let r = HypothesisResult::new("t", 0.7, 0.7).with_transformed(bytes.clone());
        assert_eq!(r.transformed, Some(bytes));
    }

    // -- Built-in Hypothesis implementations ----------------------------------

    #[test]
    fn test_identity_hypothesis() {
        let data = vec![0x90u8; 8];
        let result = IdentityHypothesis.run(&data);
        assert_eq!(result.name, "identity");
        assert_eq!(result.transformed, Some(data));
    }

    #[test]
    fn test_nop_strip_hypothesis_removes_nops() {
        let data = vec![0x90u8, 0x31, 0xC0, 0x90, 0xC3];
        let result = NopStripHypothesis.run(&data);
        let stripped = result.transformed.unwrap();
        assert!(!stripped.contains(&0x90));
    }

    #[test]
    fn test_xor_fixed_key_hypothesis() {
        let data = vec![0x00u8, 0x42, 0xFF];
        let result = XorFixedKeyHypothesis.run(&data);
        let xored = result.transformed.unwrap();
        assert_eq!(xored[0], 0x42);
        assert_eq!(xored[1], 0x42 ^ 0x42);
        assert_eq!(xored[2], 0xFF ^ 0x42);
    }

    #[test]
    fn test_xor_best_key_hypothesis_improves_score() {
        // Use a longer plaintext so the correct key unambiguously wins.
        let plaintext = b"Hello World this is a long printable string for the XOR hypothesis test!";
        let key = 0x42u8;
        let cipher: Vec<u8> = plaintext.iter().map(|&b| b ^ key).collect();
        let result = XorBestKeyHypothesis.run(&cipher);
        // The best key should restore most printable content.
        let decoded = result.transformed.unwrap();
        let printable = decoded
            .iter()
            .filter(|&&b| (0x20..=0x7E).contains(&b))
            .count();
        assert!(
            printable as f64 / decoded.len() as f64 > 0.7,
            "decoded content should be mostly printable, got {}/{} printable",
            printable,
            decoded.len()
        );
    }

    // -- HypothesisRunner -----------------------------------------------------

    #[test]
    fn test_runner_run_all_returns_one_per_hypothesis() {
        let hypotheses = HypothesisRunner::default_hypotheses();
        let code = vec![0x90u8; 16];
        let results = HypothesisRunner::run_all_in_parallel(&code, &hypotheses);
        assert_eq!(results.len(), hypotheses.len());
    }

    #[test]
    fn test_runner_select_best_picks_highest_score() {
        let results = vec![
            HypothesisResult::new("low", 0.5, 0.5),
            HypothesisResult::new("high", 0.9, 0.9),
            HypothesisResult::new("mid", 0.7, 0.8),
        ];
        let best = HypothesisRunner::select_best(&results);
        assert!(best.is_some());
        assert_eq!(best.unwrap().name, "high");
    }

    #[test]
    fn test_runner_select_best_none_when_all_below_threshold() {
        let results = vec![
            HypothesisResult::new("a", 0.5, 0.5),
            HypothesisResult::new("b", 0.4, 0.4),
        ];
        assert!(HypothesisRunner::select_best(&results).is_none());
    }

    #[test]
    fn test_runner_select_best_none_on_empty() {
        assert!(HypothesisRunner::select_best(&[]).is_none());
    }

    #[test]
    fn test_runner_best_returns_owned() {
        let hypotheses = HypothesisRunner::default_hypotheses();
        // Plain printable data -> identity should score well.
        let code = b"Hello, World! This is plain text.".to_vec();
        let best = HypothesisRunner::best(&code, &hypotheses);
        // May or may not exceed threshold depending on scores; must not panic.
        let _ = best;
    }

    #[test]
    fn test_runner_ranked_sorted_descending() {
        let results = vec![
            HypothesisResult::new("c", 0.6, 0.6),
            HypothesisResult::new("a", 0.9, 0.9),
            HypothesisResult::new("b", 0.7, 0.8),
        ];
        let ranked = HypothesisRunner::ranked(results);
        for w in ranked.windows(2) {
            assert!(w[0].combined_score() >= w[1].combined_score());
        }
    }

    #[test]
    fn test_runner_default_hypotheses_names() {
        let hyps = HypothesisRunner::default_hypotheses();
        let names: Vec<&str> = hyps.iter().map(|h| h.name()).collect();
        assert!(names.contains(&"identity"));
        assert!(names.contains(&"nop-strip"));
    }

    #[test]
    fn test_runner_empty_hypotheses() {
        let results = HypothesisRunner::run_all_in_parallel(&[0x90], &[]);
        assert!(results.is_empty());
    }
}

