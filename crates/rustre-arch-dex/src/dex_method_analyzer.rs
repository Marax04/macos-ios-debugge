//! DEX method analyzer: parse code items, build basic blocks, analyze
//! try-catch handlers, and compute control-flow metrics.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ParseError
// ---------------------------------------------------------------------------

/// Error type for code item parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodeItemError {
    #[error("buffer too short at offset {0}")]
    TooShort(usize),
    #[error("invalid instruction at offset {0:#x}")]
    InvalidInstruction(usize),
    #[error("branch target {0:#x} out of range")]
    BranchOutOfRange(usize),
}

// ---------------------------------------------------------------------------
// Instruction — a decoded DEX instruction
// ---------------------------------------------------------------------------

/// How a DEX instruction transfers control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DexBranchKind {
    /// `goto`, `throw`, `switch`: control always leaves via the target.
    Unconditional,
    /// `if-*`: control either takes the target or falls through.
    Conditional,
}

/// A decoded DEX instruction within a code item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexInstruction {
    /// Byte offset within the code item's instruction stream.
    pub offset: usize,
    /// Opcode byte.
    pub opcode: u8,
    /// Size in 16-bit code units.
    pub size_units: usize,
    /// Mnemonic string.
    pub mnemonic: String,
    /// How this instruction transfers control, or `None` if it does not branch.
    ///
    /// Modelled as an enum rather than a pair of `bool`s so that "conditional
    /// but not a branch" is unrepresentable.
    pub branch_kind: Option<DexBranchKind>,
    /// Whether this instruction is a return.
    pub is_return: bool,
    /// Whether this instruction is a call (invoke-*).
    pub is_call: bool,
    /// Branch target offset (relative to start of instructions, in bytes).
    /// `None` for non-branches.
    pub branch_target: Option<usize>,
    /// Whether this instruction can throw.
    pub can_throw: bool,
}

impl DexInstruction {
    /// Whether this instruction transfers control to a branch target.
    #[must_use]
    pub const fn is_branch(&self) -> bool {
        self.branch_kind.is_some()
    }

    /// Whether this instruction is a *conditional* branch.
    #[must_use]
    pub const fn is_conditional(&self) -> bool {
        matches!(self.branch_kind, Some(DexBranchKind::Conditional))
    }

    /// Byte size of this instruction.
    #[must_use]
    pub const fn byte_size(&self) -> usize {
        self.size_units * 2
    }
}

impl std::fmt::Display for DexInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#06x}: {}", self.offset, self.mnemonic)?;
        if let Some(tgt) = self.branch_target {
            write!(f, " -> {tgt:#x}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DexBasicBlock
// ---------------------------------------------------------------------------

/// A basic block in the control-flow graph of a DEX method.
///
/// A basic block is a maximal sequence of instructions with no internal
/// branches or branch targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexBasicBlock {
    /// Unique block index.
    pub id: usize,
    /// Byte offset of the first instruction in this block.
    pub start_offset: usize,
    /// Byte offset one past the last instruction in this block.
    pub end_offset: usize,
    /// Indices of successor blocks in the CFG.
    pub successors: Vec<usize>,
    /// Indices of predecessor blocks in the CFG.
    pub predecessors: Vec<usize>,
    /// Instructions in this block.
    pub instructions: Vec<DexInstruction>,
    /// Whether this block is the entry block.
    pub is_entry: bool,
    /// Whether any instruction in this block is a return.
    pub has_return: bool,
    /// Whether any instruction in this block can throw.
    pub can_throw: bool,
}

impl DexBasicBlock {
    /// Create an empty basic block.
    #[must_use]
    pub const fn new(id: usize, start_offset: usize) -> Self {
        Self {
            id,
            start_offset,
            end_offset: start_offset,
            successors: Vec::new(),
            predecessors: Vec::new(),
            instructions: Vec::new(),
            is_entry: false,
            has_return: false,
            can_throw: false,
        }
    }

    /// Number of instructions in this block.
    #[must_use]
    pub const fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Whether this block is a terminal block (no successors).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.successors.is_empty()
    }

    /// The last instruction in this block, if any.
    #[must_use]
    pub fn terminator(&self) -> Option<&DexInstruction> {
        self.instructions.last()
    }
}

impl std::fmt::Display for DexBasicBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BB#{} [{:#x}..{:#x}) {} instrs, succ={:?}",
            self.id,
            self.start_offset,
            self.end_offset,
            self.instructions.len(),
            self.successors
        )
    }
}

// ---------------------------------------------------------------------------
// TryCatchHandler
// ---------------------------------------------------------------------------

/// A single try-catch clause within a DEX code item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TryCatchHandler {
    /// Byte offset of the start of the try block.
    pub start_offset: usize,
    /// Length of the try block in bytes.
    pub length: usize,
    /// Byte offset of the handler code.
    pub handler_offset: usize,
    /// Exception type descriptor, or `None` for a catch-all handler.
    pub exception_type: Option<String>,
}

impl TryCatchHandler {
    /// Whether this handler catches any exception (catch-all).
    #[must_use]
    pub const fn is_catch_all(&self) -> bool {
        self.exception_type.is_none()
    }

    /// Whether the address `offset` falls within this try block.
    #[must_use]
    pub const fn covers_offset(&self, offset: usize) -> bool {
        offset >= self.start_offset && offset < self.start_offset + self.length
    }
}

// ---------------------------------------------------------------------------
// CodeItem — parsed DEX code item
// ---------------------------------------------------------------------------

/// A fully parsed DEX `code_item`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeItem {
    /// Number of registers used.
    pub registers_size: u16,
    /// Number of incoming argument words.
    pub ins_size: u16,
    /// Number of outgoing argument words.
    pub outs_size: u16,
    /// All decoded instructions.
    pub instructions: Vec<DexInstruction>,
    /// Try-catch handlers.
    pub try_handlers: Vec<TryCatchHandler>,
    /// Total byte size of the instruction stream.
    pub insns_byte_size: usize,
}

impl CodeItem {
    /// Parse a `code_item` from `data` at `offset`.
    ///
    /// `offset` should point to the beginning of the `code_item` structure.
    ///
    /// # Errors
    ///
    /// Returns `CodeItemError` on malformed data.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, CodeItemError> {
        if offset + 16 > data.len() {
            return Err(CodeItemError::TooShort(offset));
        }
        let registers_size = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let ins_size = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
        let outs_size = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
        let tries_size = u16::from_le_bytes([data[offset + 6], data[offset + 7]]);
        // debug_info_off at offset+8 (not used here)
        let insns_size = u32::from_le_bytes([
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);

        let insns_offset = offset + 16;
        // Guard against overflow: insns_size (u32) * 2 must not exceed usize::MAX.
        let insns_size_usize = insns_size as usize;
        let insns_byte_size = insns_size_usize
            .checked_mul(2)
            .ok_or(CodeItemError::TooShort(insns_offset))?;

        if insns_offset + insns_byte_size > data.len() {
            return Err(CodeItemError::TooShort(insns_offset));
        }

        let insns_data = &data[insns_offset..insns_offset + insns_byte_size];
        let instructions = decode_instructions(insns_data)?;

        // Parse try-catch handlers if present
        let try_handlers = if tries_size > 0 {
            // tries start after instruction stream (4-byte aligned)
            let try_start = insns_offset + insns_byte_size;
            let try_start_aligned = (try_start + 3) & !3;
            parse_try_handlers(data, try_start_aligned, tries_size as usize, insns_byte_size)?
        } else {
            Vec::new()
        };

        Ok(Self {
            registers_size,
            ins_size,
            outs_size,
            instructions,
            try_handlers,
            insns_byte_size,
        })
    }

    /// Total instruction count.
    #[must_use]
    pub const fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Number of call instructions.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.instructions.iter().filter(|i| i.is_call).count()
    }

    /// Number of branch instructions.
    #[must_use]
    pub fn branch_count(&self) -> usize {
        self.instructions.iter().filter(|i| i.is_branch()).count()
    }

    /// Return instructions by opcode.
    #[must_use]
    pub fn instructions_by_opcode(&self, opcode: u8) -> Vec<&DexInstruction> {
        self.instructions.iter().filter(|i| i.opcode == opcode).collect()
    }
}

// ---------------------------------------------------------------------------
// Instruction decoder
// ---------------------------------------------------------------------------

fn decode_instructions(bytes: &[u8]) -> Result<Vec<DexInstruction>, CodeItemError> {
    let mut instructions = Vec::new();
    let mut off = 0usize;

    while off < bytes.len() {
        // A DEX instruction stream is a whole number of 16-bit code units, so a
        // dangling odd byte is malformed rather than something to drop silently.
        if off + 1 >= bytes.len() {
            return Err(CodeItemError::TooShort(off));
        }
        let op = bytes[off];
        let hi = if off + 1 < bytes.len() { bytes[off + 1] } else { 0 };

        let (mnemonic, size_units, is_branch, is_return, is_call, is_conditional, branch_target_opt, can_throw) =
            classify_instruction(op, hi, bytes, off);

        let branch_target = branch_target_opt.and_then(|rel_units: i32| {
            // branch_target is in code units relative to instruction start
            // Signed arithmetic first: a negative `rel_units` near offset 0 must
            // fail the conversion below rather than wrap into a huge `usize`.
            let signed = i64::try_from(off).ok()?.checked_add(i64::from(rel_units) * 2)?;
            let abs_off = usize::try_from(signed).ok()?;
            if abs_off < bytes.len() { Some(abs_off) } else { None }
        });

        instructions.push(DexInstruction {
            offset: off,
            opcode: op,
            size_units,
            mnemonic,
            branch_kind: if is_branch {
                if is_conditional {
                    Some(DexBranchKind::Conditional)
                } else {
                    Some(DexBranchKind::Unconditional)
                }
            } else {
                None
            },
            is_return,
            is_call,
            branch_target,
            can_throw,
        });

        off += size_units * 2;
    }

    Ok(instructions)
}

/// Read a little-endian signed 16-bit word at `o`, or `0` if `bytes` is too short.
fn read_signed_word_at(bytes: &[u8], o: usize) -> i16 {
    if o + 1 < bytes.len() {
        i16::from_le_bytes([bytes[o], bytes[o + 1]])
    } else {
        0
    }
}

/// Read a little-endian signed 32-bit word at `o`, or `0` if `bytes` is too short.
fn read_signed_dword_at(bytes: &[u8], o: usize) -> i32 {
    if o + 3 < bytes.len() {
        i32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
    } else {
        0
    }
}

/// Returns `(mnemonic, size_units, is_branch, is_return, is_call, is_conditional, branch_rel_units, can_throw)`
fn classify_instruction(
    op: u8,
    hi: u8,
    bytes: &[u8],
    off: usize,
) -> (String, usize, bool, bool, bool, bool, Option<i32>, bool) {
    let read_word = |o: usize| read_signed_word_at(bytes, o);
    let read_signed_dword = |o: usize| read_signed_dword_at(bytes, o);

    match op {
        0x00 => ("nop".into(), 1, false, false, false, false, None, false),
        0x0e => ("return-void".into(), 1, false, true, false, false, None, false),
        0x0f => ("return".into(), 1, false, true, false, false, None, false),
        0x10 => ("return-wide".into(), 1, false, true, false, false, None, false),
        0x11 => ("return-object".into(), 1, false, true, false, false, None, false),
        0x28 => {
            let rel = hi.cast_signed();
            ("goto".into(), 1, true, false, false, false, Some(i32::from(rel)), false)
        }
        0x29 => {
            let rel = read_word(off + 2);
            ("goto/16".into(), 2, true, false, false, false, Some(i32::from(rel)), false)
        }
        0x2a => {
            let rel = read_signed_dword(off + 2);
            ("goto/32".into(), 3, true, false, false, false, Some(rel), false)
        }
        0x2b => {
            let rel = read_signed_dword(off + 2);
            ("packed-switch".into(), 3, true, false, false, false, Some(rel), false)
        }
        0x2c => {
            let rel = read_signed_dword(off + 2);
            ("sparse-switch".into(), 3, true, false, false, false, Some(rel), false)
        }
        0x32..=0x37 => {
            // if-{eq,ne,lt,ge,gt,le}
            let mnemonics = ["if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le"];
            let mnem = mnemonics[(op - 0x32) as usize];
            let rel = read_word(off + 2);
            (mnem.into(), 2, true, false, false, true, Some(i32::from(rel)), false)
        }
        0x38..=0x3d => {
            // if-{eqz,nez,ltz,gez,gtz,lez}
            let mnemonics = ["if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez"];
            let mnem = mnemonics[(op - 0x38) as usize];
            let rel = read_word(off + 2);
            (mnem.into(), 2, true, false, false, true, Some(i32::from(rel)), false)
        }
        0x6e => ("invoke-virtual".into(), 3, false, false, true, false, None, true),
        0x6f => ("invoke-super".into(), 3, false, false, true, false, None, true),
        0x70 => ("invoke-direct".into(), 3, false, false, true, false, None, true),
        0x71 => ("invoke-static".into(), 3, false, false, true, false, None, false),
        0x72 => ("invoke-interface".into(), 3, false, false, true, false, None, true),
        0x74 => ("invoke-virtual/range".into(), 3, false, false, true, false, None, true),
        0x75 => ("invoke-super/range".into(), 3, false, false, true, false, None, true),
        0x76 => ("invoke-direct/range".into(), 3, false, false, true, false, None, true),
        0x77 => ("invoke-static/range".into(), 3, false, false, true, false, None, false),
        0x78 => ("invoke-interface/range".into(), 3, false, false, true, false, None, true),
        0x27 => ("throw".into(), 1, true, false, false, false, None, true),
        0x44..=0x51 => {
            let mnemonics = [
                "aget", "aget-wide", "aget-object", "aget-boolean",
                "aget-byte", "aget-char", "aget-short",
                "aput", "aput-wide", "aput-object", "aput-boolean",
                "aput-byte", "aput-char", "aput-short",
            ];
            let mnem = mnemonics.get((op - 0x44) as usize).unwrap_or(&"aget");
            ((*mnem).into(), 2, false, false, false, false, None, true)
        }
        0x12 => {
            let reg = hi & 0x0f;
            let lit = (hi >> 4).cast_signed();
            (format!("const/4 v{reg}, #{lit}"), 1, false, false, false, false, None, false)
        }
        0x13 => {
            let lit = read_word(off + 2);
            (format!("const/16 v{hi}, #{lit}"), 2, false, false, false, false, None, false)
        }
        0x1a => {
            let idx = u16::from_le_bytes([
                if off + 2 < bytes.len() { bytes[off + 2] } else { 0 },
                if off + 3 < bytes.len() { bytes[off + 3] } else { 0 },
            ]);
            (format!("const-string v{hi}, string@{idx:#x}"), 2, false, false, false, false, None, true)
        }
        0x22 => {
            let idx = u16::from_le_bytes([
                if off + 2 < bytes.len() { bytes[off + 2] } else { 0 },
                if off + 3 < bytes.len() { bytes[off + 3] } else { 0 },
            ]);
            (format!("new-instance v{hi}, type@{idx:#x}"), 2, false, false, false, false, None, true)
        }
        _ => {
            // Generic fallback
            let size = generic_opcode_size(op);
            (format!("opcode_{op:#04x}"), size, false, false, false, false, None, false)
        }
    }
}

const GENERIC_OPCODE_SIZE_TABLE: &[(u8, u8, usize)] = &[
    (0x00, 0x0d, 1),
    (0x0e, 0x11, 1),
    (0x12, 0x12, 1),
    (0x13, 0x17, 2),
    (0x18, 0x18, 5),
    (0x19, 0x1f, 2),
    (0x20, 0x21, 1),
    (0x23, 0x26, 3),
    (0x28, 0x28, 1),
    (0x29, 0x29, 2),
    (0x2a, 0x2a, 3),
    (0x2b, 0x2c, 3),
    (0x2d, 0x31, 2),
    (0x32, 0x3d, 2),
    (0x44, 0x6d, 2),
    (0x6e, 0x78, 3),
    (0x7b, 0x8f, 1),
    (0x90, 0xaf, 2),
    (0xb0, 0xcf, 1),
    (0xd0, 0xd7, 2),
    (0xd8, 0xe2, 2),
];

const fn generic_opcode_size(op: u8) -> usize {
    let mut i = 0;
    while i < GENERIC_OPCODE_SIZE_TABLE.len() {
        let (lo, hi, v) = GENERIC_OPCODE_SIZE_TABLE[i];
        if op >= lo && op <= hi {
            return v;
        }
        i += 1;
    }
    1
}

fn parse_try_handlers(
    data: &[u8],
    start: usize,
    count: usize,
    _insns_byte_size: usize,
) -> Result<Vec<TryCatchHandler>, CodeItemError> {
    let mut handlers = Vec::new();
    let mut off = start;

    for _ in 0..count {
        if off + 8 > data.len() {
            return Err(CodeItemError::TooShort(off));
        }
        let start_off = u16::from_le_bytes([data[off], data[off + 1]]) as usize * 2;
        let length = u16::from_le_bytes([data[off + 2], data[off + 3]]) as usize * 2;
        let handler_off = u16::from_le_bytes([data[off + 4], data[off + 5]]) as usize * 2;
        let handler_count_raw = (data[off + 6]).cast_signed();
        off += 8;

        // A negative count marks "has a catch-all"; its magnitude is the real
        // count. `unsigned_abs` also handles `i8::MIN`, which `-x` would overflow.
        let actual_count = usize::from(handler_count_raw.unsigned_abs());

        for j in 0..actual_count {
            if off + 4 > data.len() {
                break;
            }
            let type_idx = u16::from_le_bytes([data[off], data[off + 1]]);
            off += 4; // type_idx(2) + handler_offset(2)
            let exc_type = if type_idx == 0xFFFF {
                None
            } else {
                Some(format!("type@{type_idx:#x}"))
            };
            handlers.push(TryCatchHandler {
                start_offset: start_off,
                length,
                handler_offset: handler_off + j * 2,
                exception_type: exc_type,
            });
        }

        // catch-all handler
        if handler_count_raw < 0 {
            handlers.push(TryCatchHandler {
                start_offset: start_off,
                length,
                handler_offset: handler_off,
                exception_type: None,
            });
        }
    }

    Ok(handlers)
}

// ---------------------------------------------------------------------------
// DexMethodAnalyzer — CFG builder
// ---------------------------------------------------------------------------

/// Analyzer for a DEX method: builds CFG from a parsed `CodeItem`.
pub struct DexMethodAnalyzer {
    code_item: CodeItem,
    /// Basic blocks in the CFG.
    pub blocks: Vec<DexBasicBlock>,
    /// Offset -> block ID for fast lookup.
    offset_to_block: BTreeMap<usize, usize>,
}

    // Maximum recursion depth guard: a DEX method cannot have more blocks
    // than instructions, and valid DEX limits code items to 65535 code units,
    // so a limit of 65536 is generous while bounding stack use.
    // Without this an adversarial CFG with depth > stack size causes a stack
    // overflow (dos-unbounded-recursion).
    const MAX_DFS_DEPTH: usize = 65536;

    fn dfs(
        id: usize,
        depth: usize,
        blocks: &[DexBasicBlock],
        visited: &mut HashSet<usize>,
        in_stack: &mut HashSet<usize>,
        count: &mut usize,
    ) {
        if depth > MAX_DFS_DEPTH {
            return;
        }
        if visited.contains(&id) {
            return;
        }
        visited.insert(id);
        in_stack.insert(id);
        if let Some(block) = blocks.get(id) {
            for &succ in &block.successors {
                if in_stack.contains(&succ) {
                    *count += 1;
                } else if !visited.contains(&succ) {
                    dfs(succ, depth + 1, blocks, visited, in_stack, count);
                }
            }
        }
        in_stack.remove(&id);
    }

impl DexMethodAnalyzer {
    /// Analyze a code item and build the CFG.
    #[must_use]
    pub fn analyze(code_item: &CodeItem) -> Self {
        let mut analyzer = Self {
            code_item: code_item.clone(),
            blocks: Vec::new(),
            offset_to_block: BTreeMap::new(),
        };
        analyzer.build_cfg(code_item);
        analyzer
    }

    fn build_cfg(&mut self, code_item: &CodeItem) {
        if code_item.instructions.is_empty() {
            return;
        }

        // Identify block leaders
        let mut leaders: HashSet<usize> = HashSet::new();
        leaders.insert(0); // entry

        for instr in &code_item.instructions {
            if instr.is_branch() {
                // Fallthrough (for conditional branches)
                let fallthrough = instr.offset + instr.byte_size();
                if fallthrough < code_item.insns_byte_size {
                    leaders.insert(fallthrough);
                }
                // Branch target
                if let Some(tgt) = instr.branch_target {
                    leaders.insert(tgt);
                }
            }
            if instr.is_return {
                let next = instr.offset + instr.byte_size();
                if next < code_item.insns_byte_size {
                    leaders.insert(next);
                }
            }
        }

        // Also make try-handler entries leaders
        for handler in &code_item.try_handlers {
            leaders.insert(handler.handler_offset);
        }

        let mut sorted_leaders: Vec<usize> = leaders.into_iter().collect();
        sorted_leaders.sort_unstable();

        // Assign instructions to blocks; the enumeration index *is* the block id.
        let n_leaders = sorted_leaders.len();
        for (li, &leader) in sorted_leaders.iter().enumerate() {
            let end_offset = if li + 1 < n_leaders {
                sorted_leaders[li + 1]
            } else {
                code_item.insns_byte_size
            };

            let block_id = li;
            let mut block = DexBasicBlock::new(block_id, leader);
            block.is_entry = block_id == 0;

            for instr in code_item.instructions.iter().filter(|i| {
                i.offset >= leader && i.offset < end_offset
            }) {
                if instr.is_return {
                    block.has_return = true;
                }
                if instr.can_throw {
                    block.can_throw = true;
                }
                block.end_offset = instr.offset + instr.byte_size();
                block.instructions.push(instr.clone());
            }

            self.offset_to_block.insert(leader, block_id);
            self.blocks.push(block);
        }

        self.wire_edges(code_item);
    }

    /// Wire successor and predecessor edges between the blocks built above.
    fn wire_edges(&mut self, code_item: &CodeItem) {
        // Wire up successors/predecessors
        let _block_starts: Vec<(usize, usize)> = self
            .blocks
            .iter()
            .map(|b| (b.start_offset, b.id))
            .collect();

        for i in 0..self.blocks.len() {
            let block_end = self.blocks[i].end_offset;
            let has_return = self.blocks[i].has_return;
            let terminator = self.blocks[i].terminator().cloned();

            let mut succs: Vec<usize> = Vec::new();

            if !has_return {
                if let Some(term) = &terminator {
                    if term.is_branch() {
                        // Branch target
                        if let Some(tgt) = term.branch_target
                            && let Some(&succ_id) = self.offset_to_block.get(&tgt) {
                                succs.push(succ_id);
                            }
                        // Fallthrough (for conditional)
                        if term.is_conditional()
                            && let Some(&succ_id) = self.offset_to_block.get(&block_end) {
                                succs.push(succ_id);
                            }
                    } else {
                        // Fallthrough
                        if let Some(&succ_id) = self.offset_to_block.get(&block_end) {
                            succs.push(succ_id);
                        }
                    }
                } else {
                    // Fallthrough
                    if let Some(&succ_id) = self.offset_to_block.get(&block_end) {
                        succs.push(succ_id);
                    }
                }
            }

            // Add try-handler successors for blocks that can throw
            let block_start = self.blocks[i].start_offset;
            let can_throw = self.blocks[i].can_throw;
            if can_throw {
                for handler in &code_item.try_handlers {
                    if handler.covers_offset(block_start)
                        && let Some(&hid) = self.offset_to_block.get(&handler.handler_offset) {
                            succs.push(hid);
                        }
                }
            }

            succs.sort_unstable();
            succs.dedup();
            self.blocks[i].successors.clone_from(&succs);
        }

        // Build predecessors from successor lists
        let all_succs: Vec<(usize, Vec<usize>)> = self
            .blocks
            .iter()
            .map(|b| (b.id, b.successors.clone()))
            .collect();
        for (id, succs) in all_succs {
            for succ_id in succs {
                if succ_id < self.blocks.len() {
                    self.blocks[succ_id].predecessors.push(id);
                }
            }
        }
    }

    /// Return the entry block.
    #[must_use]
    pub fn entry_block(&self) -> Option<&DexBasicBlock> {
        self.blocks.iter().find(|b| b.is_entry)
    }

    /// Return the block that contains `offset`.
    #[must_use]
    pub fn block_at_offset(&self, offset: usize) -> Option<&DexBasicBlock> {
        let id = *self.offset_to_block.get(&offset)?;
        self.blocks.get(id)
    }

    /// BFS ordering of all blocks reachable from the entry.
    #[must_use]
    pub fn bfs_order(&self) -> Vec<usize> {
        if self.blocks.is_empty() {
            return Vec::new();
        }
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut order = Vec::new();

        queue.push_back(0usize);
        visited.insert(0usize);

        while let Some(id) = queue.pop_front() {
            order.push(id);
            if let Some(block) = self.blocks.get(id) {
                for &succ in &block.successors {
                    if visited.insert(succ) {
                        queue.push_back(succ);
                    }
                }
            }
        }
        order
    }

    /// Compute cyclomatic complexity: E - N + 2P.
    #[must_use]
    pub fn cyclomatic_complexity(&self) -> usize {
        let n = self.blocks.len();
        let e: usize = self.blocks.iter().map(|b| b.successors.len()).sum();
        e.saturating_sub(n) + 2
    }

    /// Count back edges (potential loops) via DFS.
    #[must_use]
    pub fn back_edge_count(&self) -> usize {
        if self.blocks.is_empty() {
            return 0;
        }
        let mut visited = HashSet::new();
        let mut in_stack = HashSet::new();
        let mut count = 0usize;

        dfs(0, 0, &self.blocks, &mut visited, &mut in_stack, &mut count);
        count
    }

    /// Maximum path length from entry to any terminal block.
    #[must_use]
    pub fn max_path_length(&self) -> usize {
        if self.blocks.is_empty() {
            return 0;
        }
        let bfs = self.bfs_order();
        let mut dist: HashMap<usize, usize> = HashMap::new();
        dist.insert(0, 0);
        let mut max_d = 0usize;
        for id in bfs {
            let d = *dist.get(&id).unwrap_or(&0);
            max_d = max_d.max(d);
            if let Some(block) = self.blocks.get(id) {
                for &succ in &block.successors {
                    let entry = dist.entry(succ).or_insert(0);
                    if d + 1 > *entry {
                        *entry = d + 1;
                    }
                }
            }
        }
        max_d
    }

    /// Reference to the underlying code item.
    #[must_use]
    pub const fn code_item(&self) -> &CodeItem {
        &self.code_item
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_code_item(insns: &[u8]) -> CodeItem {
        // 16-byte header + insns
        let insns_units =
            u32::try_from(insns.len() / 2).expect("test instruction stream must fit a u32");
        let mut data = vec![0u8; 16 + insns.len()];
        data[0] = 4; // registers_size = 4
        data[2] = 2; // ins_size = 2
        data[6] = 0; // tries_size = 0
        data[12..16].copy_from_slice(&insns_units.to_le_bytes());
        data[16..16 + insns.len()].copy_from_slice(insns);
        CodeItem::parse(&data, 0).unwrap()
    }

    #[test]
    fn test_code_item_parse_nop() {
        let insns = [0x00u8, 0x00]; // nop
        let ci = make_code_item(&insns);
        assert_eq!(ci.instruction_count(), 1);
        assert_eq!(ci.instructions[0].mnemonic, "nop");
    }

    #[test]
    fn test_code_item_return_void() {
        let insns = [0x0Eu8, 0x00]; // return-void
        let ci = make_code_item(&insns);
        assert!(ci.instructions[0].is_return);
    }

    #[test]
    fn test_code_item_goto() {
        let insns = [0x28u8, 0x01]; // goto +1
        let ci = make_code_item(&insns);
        assert!(ci.instructions[0].is_branch());
        assert!(!ci.instructions[0].is_conditional());
    }

    #[test]
    fn test_cfg_single_block() {
        let insns = [0x0Eu8, 0x00]; // return-void
        let ci = make_code_item(&insns);
        let analyzer = DexMethodAnalyzer::analyze(&ci);
        assert_eq!(analyzer.blocks.len(), 1);
        assert!(analyzer.blocks[0].is_entry);
        assert!(analyzer.blocks[0].has_return);
    }

    #[test]
    fn test_cfg_conditional_branch() {
        // if-eqz v0, +2 (offset +4 bytes)
        // nop
        // return-void
        let insns = [
            0x38u8, 0x00, 0x02, 0x00, // if-eqz v0, +2
            0x00, 0x00,                // nop
            0x0e, 0x00,                // return-void
        ];
        let ci = make_code_item(&insns);
        let analyzer = DexMethodAnalyzer::analyze(&ci);
        assert!(analyzer.blocks.len() >= 2);
    }

    #[test]
    fn test_cyclomatic_complexity() {
        // Simple straight-line: complexity = 1
        let insns = [
            0x00u8, 0x00, // nop
            0x0e, 0x00,   // return-void
        ];
        let ci = make_code_item(&insns);
        let analyzer = DexMethodAnalyzer::analyze(&ci);
        let cc = analyzer.cyclomatic_complexity();
        assert!(cc >= 1);
    }

    #[test]
    fn test_try_catch_handler_covers() {
        let h = TryCatchHandler {
            start_offset: 4,
            length: 8,
            handler_offset: 20,
            exception_type: Some("Ljava/lang/Exception;".into()),
        };
        assert!(h.covers_offset(4));
        assert!(h.covers_offset(8));
        assert!(!h.covers_offset(12));
        assert!(!h.is_catch_all());
    }

    #[test]
    fn test_catch_all_handler() {
        let h = TryCatchHandler {
            start_offset: 0,
            length: 4,
            handler_offset: 10,
            exception_type: None,
        };
        assert!(h.is_catch_all());
    }

    #[test]
    fn test_invoke_static() {
        let insns = [
            0x71u8, 0x00, 0x01, 0x00, 0x00, 0x00, // invoke-static {}, method@0001
            0x0e, 0x00,                             // return-void
        ];
        let ci = make_code_item(&insns);
        assert_eq!(ci.call_count(), 1);
        assert!(ci.instructions[0].is_call);
    }

    #[test]
    fn test_bfs_order() {
        let insns = [0x0Eu8, 0x00]; // return-void
        let ci = make_code_item(&insns);
        let analyzer = DexMethodAnalyzer::analyze(&ci);
        let order = analyzer.bfs_order();
        assert!(!order.is_empty());
        assert_eq!(order[0], 0);
    }
}
