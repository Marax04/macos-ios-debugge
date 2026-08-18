//! VM bytecode lifting — decode raw bytecode into a portable lifted IR.
//!
//! [`VmBytecodeLifter`] consumes a raw bytecode buffer and an optional opcode
//! width table, and produces a sequence of [`LiftedInsn`] values that represent
//! the decoded instructions in a machine-independent form.
//!
//! The top-level entry point [`lift_vm_function`] wraps the lifter with a
//! default configuration and returns both the lifted instructions and a text
//! disassembly suitable for human inspection.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// VmBytecode — raw bytecode container
// ---------------------------------------------------------------------------

/// A raw VM bytecode buffer together with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmBytecode {
    /// The raw bytecode bytes.
    pub bytes: Vec<u8>,
    /// Virtual base address this bytecode was extracted from (for cross-references).
    pub base_address: u64,
    /// Optional name for the function or region.
    pub name: Option<String>,
}

impl VmBytecode {
    /// Create a new bytecode object.
    #[must_use]
    pub const fn new(bytes: Vec<u8>, base_address: u64) -> Self {
        Self {
            bytes,
            base_address,
            name: None,
        }
    }

    /// Attach a name to this bytecode region.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Length of the bytecode in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` when the bytecode is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Display for VmBytecode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("<unnamed>");
        write!(
            f,
            "VmBytecode '{}' base={:#x} len={}",
            name,
            self.base_address,
            self.bytes.len()
        )
    }
}

// ---------------------------------------------------------------------------
// LiftedOperand — operand of a lifted instruction
// ---------------------------------------------------------------------------

/// An operand carried by a [`LiftedInsn`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiftedOperand {
    /// An unsigned immediate constant.
    Immediate(u64),
    /// A virtual register index.
    VirtualReg(u8),
    /// A bytecode-relative offset (e.g. branch target).
    Offset(i64),
    /// A memory address expressed as a virtual register + displacement.
    MemRef { base_reg: u8, disp: i32 },
}

impl fmt::Display for LiftedOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Immediate(v) => write!(f, "{v:#x}"),
            Self::VirtualReg(r) => write!(f, "vr{r}"),
            Self::Offset(o) => {
                if *o >= 0 {
                    write!(f, "+{o:#x}")
                } else {
                    write!(f, "-{:#x}", o.unsigned_abs())
                }
            }
            Self::MemRef { base_reg, disp } => {
                if *disp == 0 {
                    write!(f, "[vr{base_reg}]")
                } else if *disp > 0 {
                    write!(f, "[vr{base_reg}+{disp:#x}]")
                } else {
                    write!(f, "[vr{}-{:#x}]", base_reg, disp.unsigned_abs())
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// LiftedOp — opcode of a lifted instruction
// ---------------------------------------------------------------------------

/// The opcode of a lifted VM instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiftedOp {
    /// Push operand[0] onto the VM stack.
    Push,
    /// Pop stack top into operand[0].
    Pop,
    /// Binary operation: `dst = src0 OP src1`.
    BinOp(BinOp),
    /// Unary operation: `dst = OP src`.
    UnaryOp(UnaryOp),
    /// Load `width` bytes from operand[0] into operand[1].
    Load { width: u8 },
    /// Store operand[0] (value) to operand[1] (address).
    Store { width: u8 },
    /// Conditional branch if operand[0] is non-zero.
    BranchIfTrue,
    /// Conditional branch if operand[0] is zero.
    BranchIfFalse,
    /// Unconditional jump to operand[0].
    Jump,
    /// Call operand[0].
    Call,
    /// Return from current VM frame.
    Return,
    /// Compare: sets VM flags from `src0 - src1`.
    Compare,
    /// No operation.
    Nop,
    /// Halts the VM interpreter.
    Halt,
    /// Unknown / unrecognised opcode.
    Unknown(u8),
}

impl fmt::Display for LiftedOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Push => write!(f, "PUSH"),
            Self::Pop => write!(f, "POP"),
            Self::BinOp(op) => write!(f, "{op}"),
            Self::UnaryOp(op) => write!(f, "{op}"),
            Self::Load { width } => write!(f, "LOAD{}", width * 8),
            Self::Store { width } => write!(f, "STORE{}", width * 8),
            Self::BranchIfTrue => write!(f, "BT"),
            Self::BranchIfFalse => write!(f, "BF"),
            Self::Jump => write!(f, "JMP"),
            Self::Call => write!(f, "CALL"),
            Self::Return => write!(f, "RET"),
            Self::Compare => write!(f, "CMP"),
            Self::Nop => write!(f, "NOP"),
            Self::Halt => write!(f, "HALT"),
            Self::Unknown(b) => write!(f, "UNK_{b:02X}"),
        }
    }
}

/// Binary arithmetic / logical operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOp {
    Add, Sub, Mul, Div, Mod,
    And, Or, Xor,
    Shl, Shr, Sar, Rol, Ror,
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Add => "ADD", Self::Sub => "SUB", Self::Mul => "MUL",
            Self::Div => "DIV", Self::Mod => "MOD",
            Self::And => "AND", Self::Or  => "OR",  Self::Xor => "XOR",
            Self::Shl => "SHL", Self::Shr => "SHR", Self::Sar => "SAR",
            Self::Rol => "ROL", Self::Ror => "ROR",
        };
        f.write_str(s)
    }
}

/// Unary operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnaryOp {
    Neg, Not,
}

impl fmt::Display for UnaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Neg => write!(f, "NEG"),
            Self::Not => write!(f, "NOT"),
        }
    }
}

// ---------------------------------------------------------------------------
// LiftedInsn — one lifted instruction
// ---------------------------------------------------------------------------

/// A single instruction in the lifted IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftedInsn {
    /// Byte offset within the original bytecode buffer.
    pub offset: usize,
    /// The raw opcode byte from the bytecode stream.
    pub raw_opcode: u8,
    /// The decoded opcode in lifted form.
    pub op: LiftedOp,
    /// Operands (0–3 items).
    pub operands: Vec<LiftedOperand>,
    /// Width of the raw encoding in bytes (opcode + operands).
    pub encoded_width: usize,
    /// Optional human-readable annotation.
    pub annotation: Option<String>,
}

impl LiftedInsn {
    /// Create a new lifted instruction.
    #[must_use]
    pub const fn new(offset: usize, raw_opcode: u8, op: LiftedOp, operands: Vec<LiftedOperand>, encoded_width: usize) -> Self {
        Self {
            offset,
            raw_opcode,
            op,
            operands,
            encoded_width,
            annotation: None,
        }
    }

    /// Attach an annotation.
    pub fn annotate(&mut self, note: impl Into<String>) {
        self.annotation = Some(note.into());
    }

    /// Returns `true` when this instruction alters control flow.
    #[must_use]
    pub const fn is_control_flow(&self) -> bool {
        matches!(
            self.op,
            LiftedOp::Jump | LiftedOp::BranchIfTrue | LiftedOp::BranchIfFalse
                | LiftedOp::Call | LiftedOp::Return | LiftedOp::Halt
        )
    }

    /// Returns `true` when this instruction accesses memory.
    #[must_use]
    pub const fn accesses_memory(&self) -> bool {
        matches!(self.op, LiftedOp::Load { .. } | LiftedOp::Store { .. })
    }
}

impl fmt::Display for LiftedInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#06x}  {:8}", self.offset, self.op.to_string())?;
        for (i, op) in self.operands.iter().enumerate() {
            if i == 0 {
                write!(f, " {op}")?;
            } else {
                write!(f, ", {op}")?;
            }
        }
        if let Some(ann) = &self.annotation {
            write!(f, "  ; {ann}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OpcodeTable — maps opcode byte → (LiftedOp, operand_bytes)
// ---------------------------------------------------------------------------

/// Maps raw opcode bytes to their lifted representation and expected operand width.
#[derive(Debug, Clone, Default)]
pub struct OpcodeTable {
    entries: HashMap<u8, (LiftedOp, usize)>,
}

impl OpcodeTable {
    /// Create an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a mapping.
    pub fn register(&mut self, opcode: u8, op: LiftedOp, operand_bytes: usize) {
        self.entries.insert(opcode, (op, operand_bytes));
    }

    /// Look up an opcode.
    #[must_use]
    pub fn lookup(&self, opcode: u8) -> Option<(&LiftedOp, usize)> {
        self.entries.get(&opcode).map(|(op, n)| (op, *n))
    }

    /// Build the default table matching the `VmLifter` encoding from `lib.rs`.
    #[must_use]
    pub fn default_lifter_table() -> Self {
        let mut t = Self::new();
        t.register(0x01, LiftedOp::BinOp(BinOp::Add), 2);
        t.register(0x02, LiftedOp::BinOp(BinOp::Sub), 2);
        t.register(0x03, LiftedOp::Push,               1);
        t.register(0x04, LiftedOp::Pop,                1);
        t.register(0x05, LiftedOp::Load  { width: 4 }, 6);
        t.register(0x06, LiftedOp::Store { width: 4 }, 6);
        t.register(0x07, LiftedOp::Halt,               0);
        t.register(0x08, LiftedOp::Load  { width: 4 }, 5);
        t.register(0x09, LiftedOp::Push,               4);
        t
    }

    /// Number of registered opcodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when no opcodes are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// LiftError
// ---------------------------------------------------------------------------

/// Errors produced by the lifter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiftError {
    /// The bytecode buffer is empty.
    EmptyBytecode,
    /// A truncated operand was encountered at the given offset.
    TruncatedOperand { offset: usize, expected: usize, got: usize },
    /// An unexpected opcode was encountered.
    UnknownOpcode { offset: usize, opcode: u8 },
}

impl fmt::Display for LiftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBytecode => write!(f, "bytecode buffer is empty"),
            Self::TruncatedOperand { offset, expected, got } => {
                write!(f, "truncated operand at {offset:#x}: need {expected} bytes, got {got}")
            }
            Self::UnknownOpcode { offset, opcode } => {
                write!(f, "unknown opcode {opcode:#04x} at offset {offset:#x}")
            }
        }
    }
}

impl std::error::Error for LiftError {}

// ---------------------------------------------------------------------------
// VmBytecodeLifter
// ---------------------------------------------------------------------------

/// Lifts a raw VM bytecode buffer into a sequence of [`LiftedInsn`] values.
///
/// The lifter consults an [`OpcodeTable`] for each byte encountered:
/// - Known opcodes are decoded with their operands.
/// - Unknown opcodes are emitted as [`LiftedOp::Unknown`] with zero operands
///   so that decoding continues.
pub struct VmBytecodeLifter {
    table: OpcodeTable,
    /// Whether to stop on unknown opcodes (false = emit and continue).
    strict: bool,
}

impl Default for VmBytecodeLifter {
    fn default() -> Self {
        Self::new()
    }
}

impl VmBytecodeLifter {
    /// Create a lifter using the default opcode table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: OpcodeTable::default_lifter_table(),
            strict: false,
        }
    }

    /// Create a lifter with a custom opcode table.
    #[must_use]
    pub const fn with_table(table: OpcodeTable) -> Self {
        Self { table, strict: false }
    }

    /// Enable strict mode: halt on the first unknown opcode.
    #[must_use]
    pub const fn strict(mut self) -> Self {
        self.strict = true;
        self
    }

    /// Lift all instructions from a [`VmBytecode`].
    ///
    /// # Errors
    /// Returns [`LiftError`] if the bytecode is empty or (in strict mode) an
    /// unknown opcode is encountered.
    pub fn lift(&self, bc: &VmBytecode) -> Result<Vec<LiftedInsn>, LiftError> {
        self.lift_bytes(&bc.bytes)
    }

    /// Lift all instructions from a raw byte slice.
    ///
    /// # Errors
    /// See [`VmBytecodeLifter::lift`].
    pub fn lift_bytes(&self, bytes: &[u8]) -> Result<Vec<LiftedInsn>, LiftError> {
        if bytes.is_empty() {
            return Err(LiftError::EmptyBytecode);
        }

        let mut insns = Vec::new();
        let mut pc = 0usize;

        while pc < bytes.len() {
            let offset = pc;
            let raw_opcode = bytes[pc];
            pc += 1;

            match self.table.lookup(raw_opcode) {
                Some((op, operand_bytes)) => {
                    let available = bytes.len() - pc;
                    if available < operand_bytes {
                        if self.strict {
                            return Err(LiftError::TruncatedOperand {
                                offset,
                                expected: operand_bytes,
                                got: available,
                            });
                        }
                        // Non-strict: emit what we can and stop.
                        insns.push(LiftedInsn::new(
                            offset,
                            raw_opcode,
                            op.clone(),
                            Vec::new(),
                            1,
                        ));
                        break;
                    }
                    let operands = decode_operands(bytes, pc, op, operand_bytes);
                    let encoded_width = 1 + operand_bytes;
                    pc += operand_bytes;
                    insns.push(LiftedInsn::new(offset, raw_opcode, op.clone(), operands, encoded_width));
                }
                None => {
                    if self.strict {
                        return Err(LiftError::UnknownOpcode { offset, opcode: raw_opcode });
                    }
                    insns.push(LiftedInsn::new(
                        offset,
                        raw_opcode,
                        LiftedOp::Unknown(raw_opcode),
                        Vec::new(),
                        1,
                    ));
                }
            }
        }
        Ok(insns)
    }

    /// Produce a human-readable disassembly text from a list of lifted instructions.
    #[must_use]
    pub fn to_text(insns: &[LiftedInsn]) -> String {
        let mut parts = Vec::with_capacity(insns.len());
        for i in insns {
            parts.push(i.to_string());
        }
        parts.join("\n")
    }

    /// Return only the control-flow instructions from a lifted sequence.
    #[must_use]
    pub fn control_flow_insns(insns: &[LiftedInsn]) -> Vec<&LiftedInsn> {
        insns.iter().filter(|i| i.is_control_flow()).collect()
    }

    /// Build a map from bytecode offset → lifted instruction index.
    #[must_use]
    pub fn offset_map(insns: &[LiftedInsn]) -> HashMap<usize, usize> {
        insns.iter().enumerate().map(|(idx, i)| (i.offset, idx)).collect()
    }
}

// ---------------------------------------------------------------------------
// Operand decoding helpers
// ---------------------------------------------------------------------------

fn decode_operands(bytes: &[u8], pc: usize, op: &LiftedOp, operand_bytes: usize) -> Vec<LiftedOperand> {
    if operand_bytes == 0 || pc >= bytes.len() {
        return Vec::new();
    }
    let available = (bytes.len() - pc).min(operand_bytes);

    match op {
        // BinOp: two 1-byte register indices
        LiftedOp::BinOp(_) if operand_bytes == 2 && available >= 2 => {
            vec![
                LiftedOperand::VirtualReg(bytes[pc]),
                LiftedOperand::VirtualReg(bytes[pc + 1]),
            ]
        }
        // Push/Pop: single 1-byte register index
        LiftedOp::Push | LiftedOp::Pop if operand_bytes == 1 && available >= 1 => {
            vec![LiftedOperand::VirtualReg(bytes[pc])]
        }
        // Push immediate: 4-byte imm
        LiftedOp::Push if operand_bytes == 4 && available >= 4 => {
            let imm = u32::from_le_bytes([bytes[pc], bytes[pc+1], bytes[pc+2], bytes[pc+3]]);
            vec![LiftedOperand::Immediate(u64::from(imm))]
        }
        // Load/Store with 6 bytes: reg_dst, reg_src, imm32
        LiftedOp::Load { .. } | LiftedOp::Store { .. } if operand_bytes == 6 && available >= 6 => {
            let dst = bytes[pc];
            let base = bytes[pc + 1];
            let disp = i32::from_le_bytes([bytes[pc+2], bytes[pc+3], bytes[pc+4], bytes[pc+5]]);
            vec![
                LiftedOperand::VirtualReg(dst),
                LiftedOperand::MemRef { base_reg: base, disp },
            ]
        }
        // Load with 5 bytes: reg_dst, imm32
        LiftedOp::Load { .. } if operand_bytes == 5 && available >= 5 => {
            let dst = bytes[pc];
            let imm = u32::from_le_bytes([bytes[pc+1], bytes[pc+2], bytes[pc+3], bytes[pc+4]]);
            vec![
                LiftedOperand::VirtualReg(dst),
                LiftedOperand::Immediate(u64::from(imm)),
            ]
        }
        _ => {
            // Generic: read as single little-endian value
            let mut raw = 0u64;
            for (i, &b) in bytes[pc..pc + available].iter().enumerate() {
                raw |= u64::from(b) << (i * 8);
            }
            vec![LiftedOperand::Immediate(raw)]
        }
    }
}

// ---------------------------------------------------------------------------
// lift_vm_function — high-level entry point
// ---------------------------------------------------------------------------

/// Result returned by [`lift_vm_function`].
pub struct LiftResult {
    /// The lifted instructions.
    pub instructions: Vec<LiftedInsn>,
    /// Human-readable disassembly.
    pub disassembly: String,
    /// Number of unknown opcodes encountered.
    pub unknown_count: usize,
    /// Offset-to-index map for cross-referencing.
    pub offset_map: HashMap<usize, usize>,
}

/// Lift a VM function from raw bytecode using the default opcode table.
///
/// # Errors
/// Returns [`LiftError`] if the bytecode is empty.
pub fn lift_vm_function(bytecode: &VmBytecode) -> Result<LiftResult, LiftError> {
    let lifter = VmBytecodeLifter::new();
    let instructions = lifter.lift(bytecode)?;
    let unknown_count = instructions.iter().filter(|i| matches!(i.op, LiftedOp::Unknown(_))).count();
    let disassembly = VmBytecodeLifter::to_text(&instructions);
    let offset_map = VmBytecodeLifter::offset_map(&instructions);
    Ok(LiftResult {
        instructions,
        disassembly,
        unknown_count,
        offset_map,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_bc(bytes: Vec<u8>) -> VmBytecode {
        VmBytecode::new(bytes, 0x1000)
    }

    #[test]
    fn test_lift_halt() {
        let bc = default_bc(vec![0x07]);
        let lifter = VmBytecodeLifter::new();
        let insns = lifter.lift(&bc).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].op, LiftedOp::Halt);
    }

    #[test]
    fn test_lift_add() {
        let bc = default_bc(vec![0x01, 0x00, 0x01]);
        let insns = VmBytecodeLifter::new().lift(&bc).unwrap();
        assert_eq!(insns[0].op, LiftedOp::BinOp(BinOp::Add));
        assert_eq!(insns[0].operands.len(), 2);
    }

    #[test]
    fn test_lift_push_imm() {
        let bc = default_bc(vec![0x09, 0x42, 0x00, 0x00, 0x00]);
        let insns = VmBytecodeLifter::new().lift(&bc).unwrap();
        assert_eq!(insns[0].op, LiftedOp::Push);
        assert_eq!(insns[0].operands[0], LiftedOperand::Immediate(0x42));
    }

    #[test]
    fn test_lift_empty_error() {
        let bc = default_bc(vec![]);
        let err = VmBytecodeLifter::new().lift(&bc);
        assert!(matches!(err, Err(LiftError::EmptyBytecode)));
    }

    #[test]
    fn test_lift_unknown_opcode_non_strict() {
        let bc = default_bc(vec![0xFF]);
        let insns = VmBytecodeLifter::new().lift(&bc).unwrap();
        assert_eq!(insns.len(), 1);
        assert!(matches!(insns[0].op, LiftedOp::Unknown(0xFF)));
    }

    #[test]
    fn test_lift_unknown_opcode_strict() {
        let bc = default_bc(vec![0xFF]);
        let err = VmBytecodeLifter::new().strict().lift(&bc);
        assert!(matches!(err, Err(LiftError::UnknownOpcode { opcode: 0xFF, .. })));
    }

    #[test]
    fn test_to_text_non_empty() {
        let bc = default_bc(vec![0x07]);
        let insns = VmBytecodeLifter::new().lift(&bc).unwrap();
        let text = VmBytecodeLifter::to_text(&insns);
        assert!(text.contains("HALT"));
    }

    #[test]
    fn test_control_flow_insns() {
        let bc = default_bc(vec![0x01, 0x00, 0x01, 0x07]);
        let insns = VmBytecodeLifter::new().lift(&bc).unwrap();
        let cf = VmBytecodeLifter::control_flow_insns(&insns);
        assert_eq!(cf.len(), 1);
        assert_eq!(cf[0].op, LiftedOp::Halt);
    }

    #[test]
    fn test_offset_map() {
        let bc = default_bc(vec![0x01, 0x00, 0x01, 0x07]);
        let insns = VmBytecodeLifter::new().lift(&bc).unwrap();
        let map = VmBytecodeLifter::offset_map(&insns);
        assert!(map.contains_key(&0));
        assert!(map.contains_key(&3));
    }

    #[test]
    fn test_lift_vm_function() {
        let bc = default_bc(vec![0x09, 0x01, 0x00, 0x00, 0x00, 0x07]);
        let result = lift_vm_function(&bc).unwrap();
        assert_eq!(result.instructions.len(), 2);
        assert_eq!(result.unknown_count, 0);
        assert!(!result.disassembly.is_empty());
    }

    #[test]
    fn test_vm_bytecode_display() {
        let bc = VmBytecode::new(vec![0x07], 0x4000).with_name("test_fn");
        let s = bc.to_string();
        assert!(s.contains("test_fn"));
        assert!(s.contains("0x4000"));
    }

    #[test]
    fn test_lifted_insn_is_control_flow() {
        let halt = LiftedInsn::new(0, 0x07, LiftedOp::Halt, vec![], 1);
        let add  = LiftedInsn::new(0, 0x01, LiftedOp::BinOp(BinOp::Add), vec![], 3);
        assert!(halt.is_control_flow());
        assert!(!add.is_control_flow());
    }

    #[test]
    fn test_lifted_insn_accesses_memory() {
        let load  = LiftedInsn::new(0, 0x05, LiftedOp::Load { width: 4 }, vec![], 7);
        let store = LiftedInsn::new(0, 0x06, LiftedOp::Store { width: 4 }, vec![], 7);
        let add   = LiftedInsn::new(0, 0x01, LiftedOp::BinOp(BinOp::Add), vec![], 3);
        assert!(load.accesses_memory());
        assert!(store.accesses_memory());
        assert!(!add.accesses_memory());
    }

    #[test]
    fn test_opcode_table_lookup() {
        let t = OpcodeTable::default_lifter_table();
        assert!(t.lookup(0x07).is_some());
        assert!(t.lookup(0xFF).is_none());
    }

    #[test]
    fn test_operand_display() {
        assert_eq!(LiftedOperand::Immediate(0xDEAD).to_string(), "0xdead");
        assert_eq!(LiftedOperand::VirtualReg(3).to_string(), "vr3");
        assert_eq!(LiftedOperand::MemRef { base_reg: 0, disp: 0 }.to_string(), "[vr0]");
        assert_eq!(LiftedOperand::MemRef { base_reg: 1, disp: 4 }.to_string(), "[vr1+0x4]");
    }
}
