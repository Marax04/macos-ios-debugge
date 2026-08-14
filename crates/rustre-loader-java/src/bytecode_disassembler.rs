//! Full JVM bytecode disassembler.
//!
//! Covers all 202 defined JVM opcodes and handles wide, tableswitch, lookupswitch.

use std::fmt;
use crate::class_file_parser::{CpEntry, ClassFile};

// ── JvmOperand ────────────────────────────────────────────────────────────────

/// A single decoded operand from a JVM instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JvmOperand {
    LocalVar(u16),
    ConstPoolRef(u16),
    BranchOffset(i32),
    Immediate(i64),
    ArrayType(u8),
    SwitchTable { default: i32, pairs: Vec<(i32, i32)> },
    LookupTable { default: i32, pairs: Vec<(i32, i32)> },
}

impl fmt::Display for JvmOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalVar(v) => write!(f, "local#{v}"),
            Self::ConstPoolRef(v) => write!(f, "cp#{v}"),
            Self::BranchOffset(v) => write!(f, "{v:+}"),
            Self::Immediate(v) => write!(f, "{v}"),
            Self::ArrayType(t) => write!(f, "atype={t}"),
            Self::SwitchTable { default, pairs } => {
                write!(f, "tableswitch default={default} entries={}", pairs.len())
            }
            Self::LookupTable { default, pairs } => {
                write!(f, "lookupswitch default={default} entries={}", pairs.len())
            }
        }
    }
}

// ── JvmInsn ───────────────────────────────────────────────────────────────────

/// A single decoded JVM instruction.
#[derive(Debug, Clone)]
pub struct JvmInsn {
    pub offset: u32,
    pub opcode: u8,
    pub mnemonic: &'static str,
    pub operands: Vec<JvmOperand>,
}

impl JvmInsn {
    #[must_use] 
    pub const fn is_return(&self) -> bool {
        matches!(self.opcode, 0xAC..=0xB1)
    }
    #[must_use] 
    pub const fn is_invoke(&self) -> bool {
        matches!(self.opcode, 0xB6..=0xBA)
    }
    #[must_use] 
    pub const fn is_branch(&self) -> bool {
        matches!(self.opcode, 0x99..=0xA7 | 0xA8..=0xA9 | 0xAA..=0xAB | 0xC6..=0xC9)
    }

    /// Resolve any [`JvmOperand::ConstPoolRef`] operand against `class` and
    /// return the constant pool entry it points at, if present.
    #[must_use] 
    pub fn resolve_cp_operand<'c>(&self, class: &'c ClassFile) -> Option<&'c CpEntry> {
        for op in &self.operands {
            if let JvmOperand::ConstPoolRef(idx) = op {
                return class.constant_pool.get(*idx as usize);
            }
        }
        None
    }
}

impl fmt::Display for JvmInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:>5}: {:<20}", self.offset, self.mnemonic)?;
        for (i, op) in self.operands.iter().enumerate() {
            if i > 0 { write!(f, ", ")?; }
            write!(f, "{op}")?;
        }
        Ok(())
    }
}

// ── TryCatchBlock ────────────────────────────────────────────────────────────

/// A try/catch region detected from the exception table.
#[derive(Debug, Clone)]
pub struct TryCatchBlock {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    pub catch_type_idx: u16,
}

// ── Opcode table ─────────────────────────────────────────────────────────────

static MNEMONICS: [&str; 256] = {
    let mut t = ["unknown"; 256];
    t[0x00] = "nop";
    t[0x01] = "aconst_null";
    t[0x02] = "iconst_m1";
    t[0x03] = "iconst_0";
    t[0x04] = "iconst_1";
    t[0x05] = "iconst_2";
    t[0x06] = "iconst_3";
    t[0x07] = "iconst_4";
    t[0x08] = "iconst_5";
    t[0x09] = "lconst_0";
    t[0x0A] = "lconst_1";
    t[0x0B] = "fconst_0";
    t[0x0C] = "fconst_1";
    t[0x0D] = "fconst_2";
    t[0x0E] = "dconst_0";
    t[0x0F] = "dconst_1";
    t[0x10] = "bipush";
    t[0x11] = "sipush";
    t[0x12] = "ldc";
    t[0x13] = "ldc_w";
    t[0x14] = "ldc2_w";
    t[0x15] = "iload";
    t[0x16] = "lload";
    t[0x17] = "fload";
    t[0x18] = "dload";
    t[0x19] = "aload";
    t[0x1A] = "iload_0";
    t[0x1B] = "iload_1";
    t[0x1C] = "iload_2";
    t[0x1D] = "iload_3";
    t[0x1E] = "lload_0";
    t[0x1F] = "lload_1";
    t[0x20] = "lload_2";
    t[0x21] = "lload_3";
    t[0x22] = "fload_0";
    t[0x23] = "fload_1";
    t[0x24] = "fload_2";
    t[0x25] = "fload_3";
    t[0x26] = "dload_0";
    t[0x27] = "dload_1";
    t[0x28] = "dload_2";
    t[0x29] = "dload_3";
    t[0x2A] = "aload_0";
    t[0x2B] = "aload_1";
    t[0x2C] = "aload_2";
    t[0x2D] = "aload_3";
    t[0x2E] = "iaload";
    t[0x2F] = "laload";
    t[0x30] = "faload";
    t[0x31] = "daload";
    t[0x32] = "aaload";
    t[0x33] = "baload";
    t[0x34] = "caload";
    t[0x35] = "saload";
    t[0x36] = "istore";
    t[0x37] = "lstore";
    t[0x38] = "fstore";
    t[0x39] = "dstore";
    t[0x3A] = "astore";
    t[0x3B] = "istore_0";
    t[0x3C] = "istore_1";
    t[0x3D] = "istore_2";
    t[0x3E] = "istore_3";
    t[0x3F] = "lstore_0";
    t[0x40] = "lstore_1";
    t[0x41] = "lstore_2";
    t[0x42] = "lstore_3";
    t[0x43] = "fstore_0";
    t[0x44] = "fstore_1";
    t[0x45] = "fstore_2";
    t[0x46] = "fstore_3";
    t[0x47] = "dstore_0";
    t[0x48] = "dstore_1";
    t[0x49] = "dstore_2";
    t[0x4A] = "dstore_3";
    t[0x4B] = "astore_0";
    t[0x4C] = "astore_1";
    t[0x4D] = "astore_2";
    t[0x4E] = "astore_3";
    t[0x4F] = "iastore";
    t[0x50] = "lastore";
    t[0x51] = "fastore";
    t[0x52] = "dastore";
    t[0x53] = "aastore";
    t[0x54] = "bastore";
    t[0x55] = "castore";
    t[0x56] = "sastore";
    t[0x57] = "pop";
    t[0x58] = "pop2";
    t[0x59] = "dup";
    t[0x5A] = "dup_x1";
    t[0x5B] = "dup_x2";
    t[0x5C] = "dup2";
    t[0x5D] = "dup2_x1";
    t[0x5E] = "dup2_x2";
    t[0x5F] = "swap";
    t[0x60] = "iadd";
    t[0x61] = "ladd";
    t[0x62] = "fadd";
    t[0x63] = "dadd";
    t[0x64] = "isub";
    t[0x65] = "lsub";
    t[0x66] = "fsub";
    t[0x67] = "dsub";
    t[0x68] = "imul";
    t[0x69] = "lmul";
    t[0x6A] = "fmul";
    t[0x6B] = "dmul";
    t[0x6C] = "idiv";
    t[0x6D] = "ldiv";
    t[0x6E] = "fdiv";
    t[0x6F] = "ddiv";
    t[0x70] = "irem";
    t[0x71] = "lrem";
    t[0x72] = "frem";
    t[0x73] = "drem";
    t[0x74] = "ineg";
    t[0x75] = "lneg";
    t[0x76] = "fneg";
    t[0x77] = "dneg";
    t[0x78] = "ishl";
    t[0x79] = "lshl";
    t[0x7A] = "ishr";
    t[0x7B] = "lshr";
    t[0x7C] = "iushr";
    t[0x7D] = "lushr";
    t[0x7E] = "iand";
    t[0x7F] = "land";
    t[0x80] = "ior";
    t[0x81] = "lor";
    t[0x82] = "ixor";
    t[0x83] = "lxor";
    t[0x84] = "iinc";
    t[0x85] = "i2l";
    t[0x86] = "i2f";
    t[0x87] = "i2d";
    t[0x88] = "l2i";
    t[0x89] = "l2f";
    t[0x8A] = "l2d";
    t[0x8B] = "f2i";
    t[0x8C] = "f2l";
    t[0x8D] = "f2d";
    t[0x8E] = "d2i";
    t[0x8F] = "d2l";
    t[0x90] = "d2f";
    t[0x91] = "i2b";
    t[0x92] = "i2c";
    t[0x93] = "i2s";
    t[0x94] = "lcmp";
    t[0x95] = "fcmpl";
    t[0x96] = "fcmpg";
    t[0x97] = "dcmpl";
    t[0x98] = "dcmpg";
    t[0x99] = "ifeq";
    t[0x9A] = "ifne";
    t[0x9B] = "iflt";
    t[0x9C] = "ifge";
    t[0x9D] = "ifgt";
    t[0x9E] = "ifle";
    t[0x9F] = "if_icmpeq";
    t[0xA0] = "if_icmpne";
    t[0xA1] = "if_icmplt";
    t[0xA2] = "if_icmpge";
    t[0xA3] = "if_icmpgt";
    t[0xA4] = "if_icmple";
    t[0xA5] = "if_acmpeq";
    t[0xA6] = "if_acmpne";
    t[0xA7] = "goto";
    t[0xA8] = "jsr";
    t[0xA9] = "ret";
    t[0xAA] = "tableswitch";
    t[0xAB] = "lookupswitch";
    t[0xAC] = "ireturn";
    t[0xAD] = "lreturn";
    t[0xAE] = "freturn";
    t[0xAF] = "dreturn";
    t[0xB0] = "areturn";
    t[0xB1] = "return";
    t[0xB2] = "getstatic";
    t[0xB3] = "putstatic";
    t[0xB4] = "getfield";
    t[0xB5] = "putfield";
    t[0xB6] = "invokevirtual";
    t[0xB7] = "invokespecial";
    t[0xB8] = "invokestatic";
    t[0xB9] = "invokeinterface";
    t[0xBA] = "invokedynamic";
    t[0xBB] = "new";
    t[0xBC] = "newarray";
    t[0xBD] = "anewarray";
    t[0xBE] = "arraylength";
    t[0xBF] = "athrow";
    t[0xC0] = "checkcast";
    t[0xC1] = "instanceof";
    t[0xC2] = "monitorenter";
    t[0xC3] = "monitorexit";
    t[0xC4] = "wide";
    t[0xC5] = "multianewarray";
    t[0xC6] = "ifnull";
    t[0xC7] = "ifnonnull";
    t[0xC8] = "goto_w";
    t[0xC9] = "jsr_w";
    t
};

// ── BytecodeDisassembler ──────────────────────────────────────────────────────

/// Full JVM bytecode disassembler.
pub struct BytecodeDisassembler {
    constant_pool: Vec<CpEntry>,
}

impl BytecodeDisassembler {
    /// Create a disassembler with an empty (stub) constant pool.
    #[must_use] 
    pub const fn new() -> Self {
        Self { constant_pool: vec![] }
    }

    /// Create a disassembler backed by a real constant pool for annotation.
    #[must_use] 
    pub const fn with_pool(constant_pool: Vec<CpEntry>) -> Self {
        Self { constant_pool }
    }

    /// Disassemble raw JVM bytecode bytes into a list of [`JvmInsn`].
    #[must_use] 
    pub fn disassemble_code(&self, code: &[u8]) -> Vec<JvmInsn> {
        let mut insns = Vec::new();
        let mut pos = 0usize;
        while pos < code.len() {
            let offset = pos as u32;
            let opcode = code[pos];
            pos += 1;
            match opcode {
                // No operands
                0x00..=0x0F | 0x1A..=0x35 | 0x3B..=0x56 | 0x57..=0x5F | 0x60..=0x83
                | 0x85..=0x98 | 0xAC..=0xB1 | 0xBE | 0xBF | 0xC2 | 0xC3 => {
                    insns.push(JvmInsn {
                        offset,
                        opcode,
                        mnemonic: MNEMONICS[opcode as usize],
                        operands: vec![],
                    });
                }
                // bipush: 1 signed byte immediate
                0x10 => {
                    if pos >= code.len() { break; }
                    let val = i64::from(code[pos] as i8);
                    pos += 1;
                    insns.push(JvmInsn { offset, opcode, mnemonic: "bipush", operands: vec![JvmOperand::Immediate(val)] });
                }
                // sipush: 2-byte signed immediate
                0x11 => {
                    if pos + 2 > code.len() { break; }
                    let val = i64::from(i16::from_be_bytes([code[pos], code[pos+1]]));
                    pos += 2;
                    insns.push(JvmInsn { offset, opcode, mnemonic: "sipush", operands: vec![JvmOperand::Immediate(val)] });
                }
                // ldc: 1-byte cp index
                0x12 => {
                    if pos >= code.len() { break; }
                    let idx = u16::from(code[pos]);
                    pos += 1;
                    insns.push(JvmInsn { offset, opcode, mnemonic: "ldc", operands: vec![JvmOperand::ConstPoolRef(idx)] });
                }
                // ldc_w, ldc2_w: 2-byte cp index
                0x13 | 0x14 => {
                    if pos + 2 > code.len() { break; }
                    let idx = u16::from_be_bytes([code[pos], code[pos+1]]);
                    pos += 2;
                    insns.push(JvmInsn { offset, opcode, mnemonic: MNEMONICS[opcode as usize], operands: vec![JvmOperand::ConstPoolRef(idx)] });
                }
                // iload lload fload dload aload: 1-byte local var
                0x15..=0x19 => {
                    if pos >= code.len() { break; }
                    let lv = u16::from(code[pos]);
                    pos += 1;
                    insns.push(JvmInsn { offset, opcode, mnemonic: MNEMONICS[opcode as usize], operands: vec![JvmOperand::LocalVar(lv)] });
                }
                // istore..astore: 1-byte local
                0x36..=0x3A => {
                    if pos >= code.len() { break; }
                    let lv = u16::from(code[pos]);
                    pos += 1;
                    insns.push(JvmInsn { offset, opcode, mnemonic: MNEMONICS[opcode as usize], operands: vec![JvmOperand::LocalVar(lv)] });
                }
                // iinc: localvar index + byte constant
                0x84 => {
                    if pos + 2 > code.len() { break; }
                    let lv = u16::from(code[pos]);
                    let c = i64::from(code[pos+1] as i8);
                    pos += 2;
                    insns.push(JvmInsn { offset, opcode, mnemonic: "iinc", operands: vec![JvmOperand::LocalVar(lv), JvmOperand::Immediate(c)] });
                }
                // Branch instructions: 2-byte signed offset
                0x99..=0xA8 | 0xC6 | 0xC7 => {
                    if pos + 2 > code.len() { break; }
                    let rel = i32::from(i16::from_be_bytes([code[pos], code[pos+1]]));
                    pos += 2;
                    insns.push(JvmInsn { offset, opcode, mnemonic: MNEMONICS[opcode as usize], operands: vec![JvmOperand::BranchOffset(rel)] });
                }
                // ret: 1-byte local var
                0xA9 => {
                    if pos >= code.len() { break; }
                    let lv = u16::from(code[pos]);
                    pos += 1;
                    insns.push(JvmInsn { offset, opcode, mnemonic: "ret", operands: vec![JvmOperand::LocalVar(lv)] });
                }
                // tableswitch
                0xAA => {
                    // align to 4 bytes from start of method
                    let aligned = (pos + 3) & !3;
                    if aligned + 12 > code.len() { break; }
                    pos = aligned;
                    let default = i32::from_be_bytes([code[pos], code[pos+1], code[pos+2], code[pos+3]]);
                    let low = i32::from_be_bytes([code[pos+4], code[pos+5], code[pos+6], code[pos+7]]);
                    let high = i32::from_be_bytes([code[pos+8], code[pos+9], code[pos+10], code[pos+11]]);
                    pos += 12;
                    let n = (i64::from(high) - i64::from(low) + 1).max(0) as usize;
                    // `n` is attacker-controlled (up to ~2^32 entries) while each
                    // entry needs 4 bytes of `code`; cap the pre-allocation by what
                    // the remaining input can actually supply so a tiny class file
                    // cannot force a multi-gigabyte reservation.
                    let mut pairs = Vec::with_capacity(n.min(code.len().saturating_sub(pos) / 4));
                    for i in 0..n {
                        if pos + 4 > code.len() { break; }
                        let off = i32::from_be_bytes([code[pos], code[pos+1], code[pos+2], code[pos+3]]);
                        pairs.push((low + i as i32, off));
                        pos += 4;
                    }
                    insns.push(JvmInsn { offset, opcode, mnemonic: "tableswitch", operands: vec![JvmOperand::SwitchTable { default, pairs }] });
                }
                // lookupswitch
                0xAB => {
                    let aligned = (pos + 3) & !3;
                    if aligned + 8 > code.len() { break; }
                    pos = aligned;
                    let default = i32::from_be_bytes([code[pos], code[pos+1], code[pos+2], code[pos+3]]);
                    let n = u32::from_be_bytes([code[pos+4], code[pos+5], code[pos+6], code[pos+7]]) as usize;
                    pos += 8;
                    // Same alloc cap as tableswitch: each pair consumes 8 bytes of
                    // `code`, so the remaining length bounds how many can exist.
                    let mut pairs = Vec::with_capacity(n.min(code.len().saturating_sub(pos) / 8));
                    for _ in 0..n {
                        if pos + 8 > code.len() { break; }
                        let key = i32::from_be_bytes([code[pos], code[pos+1], code[pos+2], code[pos+3]]);
                        let off = i32::from_be_bytes([code[pos+4], code[pos+5], code[pos+6], code[pos+7]]);
                        pairs.push((key, off));
                        pos += 8;
                    }
                    insns.push(JvmInsn { offset, opcode, mnemonic: "lookupswitch", operands: vec![JvmOperand::LookupTable { default, pairs }] });
                }
                // getstatic..invokedynamic: 2-byte cp index
                0xB2..=0xBA => {
                    if pos + 2 > code.len() { break; }
                    let idx = u16::from_be_bytes([code[pos], code[pos+1]]);
                    pos += 2;
                    // invokeinterface and invokedynamic have 2 extra bytes
                    if opcode == 0xB9 || opcode == 0xBA {
                        pos += 2; // count + 0 / 0 + 0
                    }
                    insns.push(JvmInsn { offset, opcode, mnemonic: MNEMONICS[opcode as usize], operands: vec![JvmOperand::ConstPoolRef(idx)] });
                }
                // new, anewarray, checkcast, instanceof: 2-byte cp index
                0xBB | 0xBD | 0xC0 | 0xC1 => {
                    if pos + 2 > code.len() { break; }
                    let idx = u16::from_be_bytes([code[pos], code[pos+1]]);
                    pos += 2;
                    insns.push(JvmInsn { offset, opcode, mnemonic: MNEMONICS[opcode as usize], operands: vec![JvmOperand::ConstPoolRef(idx)] });
                }
                // newarray: 1-byte array type
                0xBC => {
                    if pos >= code.len() { break; }
                    let t = code[pos];
                    pos += 1;
                    insns.push(JvmInsn { offset, opcode, mnemonic: "newarray", operands: vec![JvmOperand::ArrayType(t)] });
                }
                // wide
                0xC4 => {
                    if pos >= code.len() { break; }
                    let sub_opcode = code[pos];
                    pos += 1;
                    let mnemonic = MNEMONICS[sub_opcode as usize];
                    if sub_opcode == 0x84 {
                        // wide iinc: index + const (both 2 bytes)
                        if pos + 4 > code.len() { break; }
                        let lv = u16::from_be_bytes([code[pos], code[pos+1]]);
                        let c = i64::from(i16::from_be_bytes([code[pos+2], code[pos+3]]));
                        pos += 4;
                        insns.push(JvmInsn { offset, opcode, mnemonic, operands: vec![JvmOperand::LocalVar(lv), JvmOperand::Immediate(c)] });
                    } else {
                        if pos + 2 > code.len() { break; }
                        let lv = u16::from_be_bytes([code[pos], code[pos+1]]);
                        pos += 2;
                        insns.push(JvmInsn { offset, opcode, mnemonic, operands: vec![JvmOperand::LocalVar(lv)] });
                    }
                }
                // multianewarray: 2-byte cp + 1-byte dim count
                0xC5 => {
                    if pos + 3 > code.len() { break; }
                    let idx = u16::from_be_bytes([code[pos], code[pos+1]]);
                    let dims = i64::from(code[pos+2]);
                    pos += 3;
                    insns.push(JvmInsn { offset, opcode, mnemonic: "multianewarray", operands: vec![JvmOperand::ConstPoolRef(idx), JvmOperand::Immediate(dims)] });
                }
                // goto_w / jsr_w: 4-byte signed offset
                0xC8 | 0xC9 => {
                    if pos + 4 > code.len() { break; }
                    let rel = i32::from_be_bytes([code[pos], code[pos+1], code[pos+2], code[pos+3]]);
                    pos += 4;
                    insns.push(JvmInsn { offset, opcode, mnemonic: MNEMONICS[opcode as usize], operands: vec![JvmOperand::BranchOffset(rel)] });
                }
                _ => {
                    insns.push(JvmInsn { offset, opcode, mnemonic: "unknown", operands: vec![] });
                    break;
                }
            }
        }
        insns
    }

    /// Format an instruction with optional constant pool annotation.
    #[must_use] 
    pub fn format_instruction(&self, insn: &JvmInsn) -> String {
        let base = format!("{insn}");
        if let Some(JvmOperand::ConstPoolRef(idx)) = insn.operands.first()
            && let Some(entry) = self.constant_pool.get(*idx as usize) {
                return format!("{base}  // {entry}");
            }
        base
    }

    /// Detect try/catch blocks from a raw exception table (as returned by `CodeAttribute`).
    #[must_use] 
    pub fn detect_try_catch_blocks(
        &self,
        exc_table: &[(u16, u16, u16, u16)],
    ) -> Vec<TryCatchBlock> {
        exc_table
            .iter()
            .map(|&(start_pc, end_pc, handler_pc, catch_type_idx)| TryCatchBlock {
                start_pc,
                end_pc,
                handler_pc,
                catch_type_idx,
            })
            .collect()
    }

    /// Collect the offsets of all branch targets in the disassembly.
    #[must_use] 
    pub fn branch_targets(&self, insns: &[JvmInsn]) -> Vec<u32> {
        let mut targets = Vec::new();
        for insn in insns {
            if let Some(JvmOperand::BranchOffset(rel)) = insn.operands.first() {
                let target = (i64::from(insn.offset) + i64::from(*rel)) as u32;
                targets.push(target);
            }
        }
        targets.sort_unstable();
        targets.dedup();
        targets
    }
}

impl Default for BytecodeDisassembler {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn disasm(code: &[u8]) -> Vec<JvmInsn> {
        BytecodeDisassembler::new().disassemble_code(code)
    }

    #[test]
    fn test_nop() {
        let insns = disasm(&[0x00]);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].mnemonic, "nop");
        assert!(insns[0].operands.is_empty());
    }

    #[test]
    fn test_aconst_null() {
        let insns = disasm(&[0x01]);
        assert_eq!(insns[0].mnemonic, "aconst_null");
    }

    #[test]
    fn test_bipush() {
        let insns = disasm(&[0x10, 0x2A]); // bipush 42
        assert_eq!(insns[0].mnemonic, "bipush");
        assert_eq!(insns[0].operands[0], JvmOperand::Immediate(42));
    }

    #[test]
    fn test_sipush_negative() {
        let insns = disasm(&[0x11, 0xFF, 0xD6]); // sipush -42
        assert_eq!(insns[0].mnemonic, "sipush");
        assert_eq!(insns[0].operands[0], JvmOperand::Immediate(-42));
    }

    #[test]
    fn test_ldc() {
        let insns = disasm(&[0x12, 0x05]);
        assert_eq!(insns[0].mnemonic, "ldc");
        assert_eq!(insns[0].operands[0], JvmOperand::ConstPoolRef(5));
    }

    #[test]
    fn test_iload() {
        let insns = disasm(&[0x15, 0x03]);
        assert_eq!(insns[0].mnemonic, "iload");
        assert_eq!(insns[0].operands[0], JvmOperand::LocalVar(3));
    }

    #[test]
    fn test_istore() {
        let insns = disasm(&[0x36, 0x02]);
        assert_eq!(insns[0].mnemonic, "istore");
        assert_eq!(insns[0].operands[0], JvmOperand::LocalVar(2));
    }

    #[test]
    fn test_iinc() {
        let insns = disasm(&[0x84, 0x01, 0x05]); // iinc 1, 5
        assert_eq!(insns[0].mnemonic, "iinc");
        assert_eq!(insns[0].operands[0], JvmOperand::LocalVar(1));
        assert_eq!(insns[0].operands[1], JvmOperand::Immediate(5));
    }

    #[test]
    fn test_ifeq_branch() {
        let insns = disasm(&[0x99, 0x00, 0x0A]); // ifeq +10
        assert_eq!(insns[0].mnemonic, "ifeq");
        assert_eq!(insns[0].operands[0], JvmOperand::BranchOffset(10));
    }

    #[test]
    fn test_goto() {
        let insns = disasm(&[0xA7, 0xFF, 0xFB]); // goto -5
        assert_eq!(insns[0].mnemonic, "goto");
        assert_eq!(insns[0].operands[0], JvmOperand::BranchOffset(-5));
    }

    #[test]
    fn test_return() {
        let insns = disasm(&[0xB1]);
        assert_eq!(insns[0].mnemonic, "return");
        assert!(insns[0].is_return());
    }

    #[test]
    fn test_invokevirtual() {
        let insns = disasm(&[0xB6, 0x00, 0x07]);
        assert_eq!(insns[0].mnemonic, "invokevirtual");
        assert!(insns[0].is_invoke());
        assert_eq!(insns[0].operands[0], JvmOperand::ConstPoolRef(7));
    }

    #[test]
    fn test_newarray() {
        let insns = disasm(&[0xBC, 0x0A]); // newarray int
        assert_eq!(insns[0].mnemonic, "newarray");
        assert_eq!(insns[0].operands[0], JvmOperand::ArrayType(10));
    }

    #[test]
    fn test_goto_w() {
        let insns = disasm(&[0xC8, 0x00, 0x00, 0x01, 0x00]); // goto_w +256
        assert_eq!(insns[0].mnemonic, "goto_w");
        assert_eq!(insns[0].operands[0], JvmOperand::BranchOffset(256));
    }

    #[test]
    fn test_lookupswitch_two_pairs() {
        // lookupswitch aligned at 1 (opcode at 0)
        // bytes: [0xAB, padding to align(1+3)=4, then default(4), npairs(4), pair1(8), pair2(8)]
        // offset 0: opcode AB, pos becomes 1 → aligned = (1+3)&!3 = 4
        // We'll put the opcode right at start so offset=0, pos=1 after opcode
        // We need 3 bytes padding, then 4+4+8+8 = 24 bytes
        let mut code = vec![0xAB_u8]; // opcode at 0
        code.extend_from_slice(&[0x00, 0x00, 0x00]); // padding → pos=4
        code.extend_from_slice(&[0x00, 0x00, 0x00, 0x64]); // default = 100
        code.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // npairs = 2
        code.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0A]); // 1 → 10
        code.extend_from_slice(&[0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x14]); // 2 → 20
        let insns = disasm(&code);
        assert_eq!(insns[0].mnemonic, "lookupswitch");
        if let JvmOperand::LookupTable { default, pairs } = &insns[0].operands[0] {
            assert_eq!(*default, 100);
            assert_eq!(pairs.len(), 2);
            assert_eq!(pairs[0], (1, 10));
            assert_eq!(pairs[1], (2, 20));
        } else {
            panic!("expected LookupTable");
        }
    }

    #[test]
    fn test_multiple_instructions() {
        let code = [0x03, 0x04, 0x60, 0xAC]; // iconst_0, iconst_1, iadd, ireturn
        let insns = disasm(&code);
        assert_eq!(insns.len(), 4);
        assert_eq!(insns[0].mnemonic, "iconst_0");
        assert_eq!(insns[3].mnemonic, "ireturn");
    }

    #[test]
    fn test_offset_tracking() {
        let code = [0x10, 0x01, 0x10, 0x02]; // bipush 1, bipush 2
        let insns = disasm(&code);
        assert_eq!(insns[0].offset, 0);
        assert_eq!(insns[1].offset, 2);
    }

    #[test]
    fn test_branch_targets() {
        let d = BytecodeDisassembler::new();
        let insns = d.disassemble_code(&[0x99, 0x00, 0x05, 0xA7, 0xFF, 0xFB]);
        let targets = d.branch_targets(&insns);
        assert!(targets.contains(&5)); // ifeq +5 from offset 0
    }

    #[test]
    fn test_is_branch_flag() {
        let insns = disasm(&[0x99, 0x00, 0x00]);
        assert!(insns[0].is_branch());
    }

    #[test]
    fn test_display_format() {
        let insns = disasm(&[0x00]);
        let s = format!("{}", insns[0]);
        assert!(s.contains("nop"));
    }
}
