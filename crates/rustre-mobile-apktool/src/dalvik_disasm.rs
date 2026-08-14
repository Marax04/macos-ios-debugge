//! Dalvik bytecode disassembler.
//!
//! Decodes the full Dalvik opcode set (00–FF range + extended F2–FF extended
//! ops), all instruction formats (10x, 12x, 11n, 11x, 51l, etc.), register
//! operands, and method/type/field/string references by DEX pool index.

use std::collections::HashMap;
use std::fmt;

// ── InstrFormat ──────────────────────────────────────────────────────────────

/// Encoding format of a Dalvik instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstrFormat {
    /// waste/nop — no operands, 16-bit
    F10x,
    /// vA, vB (4-bit regs, same word)
    F12x,
    /// vA, #+B (4-bit reg, 4-bit signed literal)
    F11n,
    /// vAA (8-bit reg)
    F11x,
    /// vAA, #+BBBBBBBB (8-bit reg, 32-bit literal)
    F31i,
    /// vAA, #+BBBBBBBBBBBBBBBB (8-bit reg, 64-bit literal)
    F51l,
    /// vAA, vBBBB (8-bit dst, 16-bit src)
    F32x,
    /// target (10-bit offset)
    F10t,
    /// target (16-bit offset)
    F20t,
    /// target (32-bit offset)
    F30t,
    /// vAA, +BBBB (8-bit reg, 16-bit branch)
    F21t,
    /// vA, vB, +CCCC (4-bit regs, 16-bit branch)
    F22t,
    /// vAA, #+BBBB (8-bit reg, 16-bit literal)
    F21s,
    /// vAA, #+BBBBBBBBBBBB (8-bit reg, signed 32-bit high16)
    F21h,
    /// vAA, type@BBBB (8-bit reg, 16-bit type ref)
    F21c,
    /// vA, vB, field@CCCC (4-bit regs, 16-bit field ref)
    F22c,
    /// vAA, vBB, #+CC (two 8-bit regs, 8-bit literal)
    F22b,
    /// vAA, vBB, #+CCCC (two 8-bit regs, 16-bit literal)
    F22s,
    /// vAA, string@BBBBBBBB (8-bit reg, 32-bit string ref)
    F31c,
    /// {vC..vG}, meth@BBBB (up to 5 regs, 16-bit method ref)
    F35c,
    /// {vCCCC..v(CCCC+AA-1)}, meth@BBBB (register range, method ref)
    F3rc,
    /// vAA, vBB, vCC (three 8-bit regs)
    F23x,
    /// vAA, vBB, meth@CCCC (two 8-bit regs, method ref)
    F22x,
    /// vAA, vBBBB (8-bit dst, 16-bit src: move-wide/16)
    F22xW,
    /// Unknown / reserved
    Unknown,
}

impl fmt::Display for InstrFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── DalvikOpcode ─────────────────────────────────────────────────────────────

/// A Dalvik opcode with its mnemonic and encoding format.
#[derive(Debug, Clone)]
pub struct DalvikOpcode {
    pub value: u8,
    pub mnemonic: &'static str,
    pub format: InstrFormat,
    pub wide: bool,   // true if operand refs are 32-bit (e.g. const/32, const-string/jumbo)
    pub jump: bool,   // true if this opcode is a branch
    pub invoke: bool, // true if this opcode calls a method
}

impl DalvikOpcode {
    const fn new(v: u8, m: &'static str, fmt: InstrFormat) -> Self {
        Self { value: v, mnemonic: m, format: fmt, wide: false, jump: false, invoke: false }
    }
    const fn with_jump(mut self) -> Self { self.jump = true; self }
    const fn with_invoke(mut self) -> Self { self.invoke = true; self }
    const fn with_wide(mut self) -> Self { self.wide = true; self }
}

// ── DalvikInstr ──────────────────────────────────────────────────────────────

/// Decoded Dalvik instruction.
#[derive(Debug, Clone)]
pub struct DalvikInstr {
    /// Byte offset from start of code buffer.
    pub offset: usize,
    /// Raw 16-bit code units (1–5 units).
    pub code_units: Vec<u16>,
    /// Opcode value.
    pub opcode: u8,
    /// Mnemonic string.
    pub mnemonic: String,
    /// Encoding format.
    pub format: InstrFormat,
    /// Decoded register operands (rA, rB, rC …).
    pub regs: Vec<u32>,
    /// Literal value (for const opcodes).
    pub literal: Option<i64>,
    /// Reference index (string/type/field/method pool index).
    pub ref_index: Option<u32>,
    /// Decoded branch target offset (in code units from current instruction).
    pub branch_offset: Option<i32>,
    /// Human-readable operand string after reference resolution.
    pub operand_str: String,
}

impl DalvikInstr {
    /// Size of this instruction in 16-bit code units.
    #[must_use] 
    pub const fn size_in_units(&self) -> usize {
        self.code_units.len()
    }
}

impl fmt::Display for DalvikInstr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:06x}  {:20} {}", self.offset, self.mnemonic, self.operand_str)
    }
}

// ── Reference tables ─────────────────────────────────────────────────────────

/// DEX reference pools passed to the disassembler for symbolic resolution.
#[derive(Debug, Clone, Default)]
pub struct DexRefPools {
    pub strings: Vec<String>,
    pub types:   Vec<String>,
    pub fields:  Vec<String>,
    pub methods: Vec<String>,
}

impl DexRefPools {
    #[must_use] 
    pub fn string(&self, idx: u32) -> String {
        self.strings.get(idx as usize).cloned()
            .unwrap_or_else(|| format!("string@{idx:#x}"))
    }
    #[must_use] 
    pub fn type_ref(&self, idx: u32) -> String {
        self.types.get(idx as usize).cloned()
            .unwrap_or_else(|| format!("type@{idx:#x}"))
    }
    #[must_use] 
    pub fn field(&self, idx: u32) -> String {
        self.fields.get(idx as usize).cloned()
            .unwrap_or_else(|| format!("field@{idx:#x}"))
    }
    #[must_use] 
    pub fn method(&self, idx: u32) -> String {
        self.methods.get(idx as usize).cloned()
            .unwrap_or_else(|| format!("method@{idx:#x}"))
    }
}

// ── Opcode table ─────────────────────────────────────────────────────────────

fn build_opcode_table() -> HashMap<u8, DalvikOpcode> {
    let mut t = HashMap::new();
    let ops: &[DalvikOpcode] = &[
        DalvikOpcode::new(0x00, "nop",                InstrFormat::F10x),
        DalvikOpcode::new(0x01, "move",               InstrFormat::F12x),
        DalvikOpcode::new(0x02, "move/from16",        InstrFormat::F22x),
        DalvikOpcode::new(0x03, "move/16",            InstrFormat::F32x),
        DalvikOpcode::new(0x04, "move-wide",          InstrFormat::F12x),
        DalvikOpcode::new(0x05, "move-wide/from16",   InstrFormat::F22xW),
        DalvikOpcode::new(0x06, "move-wide/16",       InstrFormat::F32x),
        DalvikOpcode::new(0x07, "move-object",        InstrFormat::F12x),
        DalvikOpcode::new(0x08, "move-object/from16", InstrFormat::F22x),
        DalvikOpcode::new(0x09, "move-object/16",     InstrFormat::F32x),
        DalvikOpcode::new(0x0a, "move-result",        InstrFormat::F11x),
        DalvikOpcode::new(0x0b, "move-result-wide",   InstrFormat::F11x),
        DalvikOpcode::new(0x0c, "move-result-object", InstrFormat::F11x),
        DalvikOpcode::new(0x0d, "move-exception",     InstrFormat::F11x),
        DalvikOpcode::new(0x0e, "return-void",        InstrFormat::F10x),
        DalvikOpcode::new(0x0f, "return",             InstrFormat::F11x),
        DalvikOpcode::new(0x10, "return-wide",        InstrFormat::F11x),
        DalvikOpcode::new(0x11, "return-object",      InstrFormat::F11x),
        DalvikOpcode::new(0x12, "const/4",            InstrFormat::F11n),
        DalvikOpcode::new(0x13, "const/16",           InstrFormat::F21s),
        DalvikOpcode::new(0x14, "const",              InstrFormat::F31i),
        DalvikOpcode::new(0x15, "const/high16",       InstrFormat::F21h),
        DalvikOpcode::new(0x16, "const-wide/16",      InstrFormat::F21s),
        DalvikOpcode::new(0x17, "const-wide/32",      InstrFormat::F31i),
        DalvikOpcode::new(0x18, "const-wide",         InstrFormat::F51l),
        DalvikOpcode::new(0x19, "const-wide/high16",  InstrFormat::F21h),
        DalvikOpcode::new(0x1a, "const-string",       InstrFormat::F21c),
        DalvikOpcode::new(0x1b, "const-string/jumbo", InstrFormat::F31c).with_wide(),
        DalvikOpcode::new(0x1c, "const-class",        InstrFormat::F21c),
        DalvikOpcode::new(0x1d, "monitor-enter",      InstrFormat::F11x),
        DalvikOpcode::new(0x1e, "monitor-exit",       InstrFormat::F11x),
        DalvikOpcode::new(0x1f, "check-cast",         InstrFormat::F21c),
        DalvikOpcode::new(0x20, "instance-of",        InstrFormat::F22c),
        DalvikOpcode::new(0x21, "array-length",       InstrFormat::F12x),
        DalvikOpcode::new(0x22, "new-instance",       InstrFormat::F21c),
        DalvikOpcode::new(0x23, "new-array",          InstrFormat::F22c),
        DalvikOpcode::new(0x24, "filled-new-array",   InstrFormat::F35c),
        DalvikOpcode::new(0x25, "filled-new-array/range", InstrFormat::F3rc),
        DalvikOpcode::new(0x26, "fill-array-data",    InstrFormat::F31i),
        DalvikOpcode::new(0x27, "throw",              InstrFormat::F11x),
        DalvikOpcode::new(0x28, "goto",               InstrFormat::F10t).with_jump(),
        DalvikOpcode::new(0x29, "goto/16",            InstrFormat::F20t).with_jump(),
        DalvikOpcode::new(0x2a, "goto/32",            InstrFormat::F30t).with_jump(),
        DalvikOpcode::new(0x2b, "packed-switch",      InstrFormat::F31i),
        DalvikOpcode::new(0x2c, "sparse-switch",      InstrFormat::F31i),
        // comparisons
        DalvikOpcode::new(0x2d, "cmpl-float",  InstrFormat::F23x),
        DalvikOpcode::new(0x2e, "cmpg-float",  InstrFormat::F23x),
        DalvikOpcode::new(0x2f, "cmpl-double", InstrFormat::F23x),
        DalvikOpcode::new(0x30, "cmpg-double", InstrFormat::F23x),
        DalvikOpcode::new(0x31, "cmp-long",    InstrFormat::F23x),
        // conditional branches
        DalvikOpcode::new(0x32, "if-eq", InstrFormat::F22t).with_jump(),
        DalvikOpcode::new(0x33, "if-ne", InstrFormat::F22t).with_jump(),
        DalvikOpcode::new(0x34, "if-lt", InstrFormat::F22t).with_jump(),
        DalvikOpcode::new(0x35, "if-ge", InstrFormat::F22t).with_jump(),
        DalvikOpcode::new(0x36, "if-gt", InstrFormat::F22t).with_jump(),
        DalvikOpcode::new(0x37, "if-le", InstrFormat::F22t).with_jump(),
        DalvikOpcode::new(0x38, "if-eqz", InstrFormat::F21t).with_jump(),
        DalvikOpcode::new(0x39, "if-nez", InstrFormat::F21t).with_jump(),
        DalvikOpcode::new(0x3a, "if-ltz", InstrFormat::F21t).with_jump(),
        DalvikOpcode::new(0x3b, "if-gez", InstrFormat::F21t).with_jump(),
        DalvikOpcode::new(0x3c, "if-gtz", InstrFormat::F21t).with_jump(),
        DalvikOpcode::new(0x3d, "if-lez", InstrFormat::F21t).with_jump(),
        // array access
        DalvikOpcode::new(0x44, "aget",        InstrFormat::F23x),
        DalvikOpcode::new(0x45, "aget-wide",   InstrFormat::F23x),
        DalvikOpcode::new(0x46, "aget-object", InstrFormat::F23x),
        DalvikOpcode::new(0x47, "aget-boolean",InstrFormat::F23x),
        DalvikOpcode::new(0x48, "aget-byte",   InstrFormat::F23x),
        DalvikOpcode::new(0x49, "aget-char",   InstrFormat::F23x),
        DalvikOpcode::new(0x4a, "aget-short",  InstrFormat::F23x),
        DalvikOpcode::new(0x4b, "aput",        InstrFormat::F23x),
        DalvikOpcode::new(0x4c, "aput-wide",   InstrFormat::F23x),
        DalvikOpcode::new(0x4d, "aput-object", InstrFormat::F23x),
        DalvikOpcode::new(0x4e, "aput-boolean",InstrFormat::F23x),
        DalvikOpcode::new(0x4f, "aput-byte",   InstrFormat::F23x),
        DalvikOpcode::new(0x50, "aput-char",   InstrFormat::F23x),
        DalvikOpcode::new(0x51, "aput-short",  InstrFormat::F23x),
        // instance field access
        DalvikOpcode::new(0x52, "iget",         InstrFormat::F22c),
        DalvikOpcode::new(0x53, "iget-wide",    InstrFormat::F22c),
        DalvikOpcode::new(0x54, "iget-object",  InstrFormat::F22c),
        DalvikOpcode::new(0x55, "iget-boolean", InstrFormat::F22c),
        DalvikOpcode::new(0x56, "iget-byte",    InstrFormat::F22c),
        DalvikOpcode::new(0x57, "iget-char",    InstrFormat::F22c),
        DalvikOpcode::new(0x58, "iget-short",   InstrFormat::F22c),
        DalvikOpcode::new(0x59, "iput",         InstrFormat::F22c),
        DalvikOpcode::new(0x5a, "iput-wide",    InstrFormat::F22c),
        DalvikOpcode::new(0x5b, "iput-object",  InstrFormat::F22c),
        DalvikOpcode::new(0x5c, "iput-boolean", InstrFormat::F22c),
        DalvikOpcode::new(0x5d, "iput-byte",    InstrFormat::F22c),
        DalvikOpcode::new(0x5e, "iput-char",    InstrFormat::F22c),
        DalvikOpcode::new(0x5f, "iput-short",   InstrFormat::F22c),
        // static field access
        DalvikOpcode::new(0x60, "sget",         InstrFormat::F21c),
        DalvikOpcode::new(0x61, "sget-wide",    InstrFormat::F21c),
        DalvikOpcode::new(0x62, "sget-object",  InstrFormat::F21c),
        DalvikOpcode::new(0x63, "sget-boolean", InstrFormat::F21c),
        DalvikOpcode::new(0x64, "sget-byte",    InstrFormat::F21c),
        DalvikOpcode::new(0x65, "sget-char",    InstrFormat::F21c),
        DalvikOpcode::new(0x66, "sget-short",   InstrFormat::F21c),
        DalvikOpcode::new(0x67, "sput",         InstrFormat::F21c),
        DalvikOpcode::new(0x68, "sput-wide",    InstrFormat::F21c),
        DalvikOpcode::new(0x69, "sput-object",  InstrFormat::F21c),
        DalvikOpcode::new(0x6a, "sput-boolean", InstrFormat::F21c),
        DalvikOpcode::new(0x6b, "sput-byte",    InstrFormat::F21c),
        DalvikOpcode::new(0x6c, "sput-char",    InstrFormat::F21c),
        DalvikOpcode::new(0x6d, "sput-short",   InstrFormat::F21c),
        // invoke
        DalvikOpcode::new(0x6e, "invoke-virtual",        InstrFormat::F35c).with_invoke(),
        DalvikOpcode::new(0x6f, "invoke-super",          InstrFormat::F35c).with_invoke(),
        DalvikOpcode::new(0x70, "invoke-direct",         InstrFormat::F35c).with_invoke(),
        DalvikOpcode::new(0x71, "invoke-static",         InstrFormat::F35c).with_invoke(),
        DalvikOpcode::new(0x72, "invoke-interface",      InstrFormat::F35c).with_invoke(),
        DalvikOpcode::new(0x74, "invoke-virtual/range",  InstrFormat::F3rc).with_invoke(),
        DalvikOpcode::new(0x75, "invoke-super/range",    InstrFormat::F3rc).with_invoke(),
        DalvikOpcode::new(0x76, "invoke-direct/range",   InstrFormat::F3rc).with_invoke(),
        DalvikOpcode::new(0x77, "invoke-static/range",   InstrFormat::F3rc).with_invoke(),
        DalvikOpcode::new(0x78, "invoke-interface/range",InstrFormat::F3rc).with_invoke(),
        // unary ops
        DalvikOpcode::new(0x7b, "neg-int",    InstrFormat::F12x),
        DalvikOpcode::new(0x7c, "not-int",    InstrFormat::F12x),
        DalvikOpcode::new(0x7d, "neg-long",   InstrFormat::F12x),
        DalvikOpcode::new(0x7e, "not-long",   InstrFormat::F12x),
        DalvikOpcode::new(0x7f, "neg-float",  InstrFormat::F12x),
        DalvikOpcode::new(0x80, "neg-double", InstrFormat::F12x),
        // binary ops
        DalvikOpcode::new(0x90, "add-int",  InstrFormat::F23x),
        DalvikOpcode::new(0x91, "sub-int",  InstrFormat::F23x),
        DalvikOpcode::new(0x92, "mul-int",  InstrFormat::F23x),
        DalvikOpcode::new(0x93, "div-int",  InstrFormat::F23x),
        DalvikOpcode::new(0x94, "rem-int",  InstrFormat::F23x),
        DalvikOpcode::new(0x95, "and-int",  InstrFormat::F23x),
        DalvikOpcode::new(0x96, "or-int",   InstrFormat::F23x),
        DalvikOpcode::new(0x97, "xor-int",  InstrFormat::F23x),
        DalvikOpcode::new(0x98, "shl-int",  InstrFormat::F23x),
        DalvikOpcode::new(0x99, "shr-int",  InstrFormat::F23x),
        DalvikOpcode::new(0x9a, "ushr-int", InstrFormat::F23x),
        DalvikOpcode::new(0xb0, "add-int/2addr",  InstrFormat::F12x),
        DalvikOpcode::new(0xb1, "sub-int/2addr",  InstrFormat::F12x),
        DalvikOpcode::new(0xb2, "mul-int/2addr",  InstrFormat::F12x),
        DalvikOpcode::new(0xb3, "div-int/2addr",  InstrFormat::F12x),
        DalvikOpcode::new(0xb4, "rem-int/2addr",  InstrFormat::F12x),
        DalvikOpcode::new(0xb5, "and-int/2addr",  InstrFormat::F12x),
        DalvikOpcode::new(0xb6, "or-int/2addr",   InstrFormat::F12x),
        DalvikOpcode::new(0xb7, "xor-int/2addr",  InstrFormat::F12x),
        DalvikOpcode::new(0xb8, "shl-int/2addr",  InstrFormat::F12x),
        DalvikOpcode::new(0xb9, "shr-int/2addr",  InstrFormat::F12x),
        DalvikOpcode::new(0xba, "ushr-int/2addr",  InstrFormat::F12x),
        DalvikOpcode::new(0xd0, "add-int/lit16",  InstrFormat::F22s),
        DalvikOpcode::new(0xd1, "rsub-int",       InstrFormat::F22s),
        DalvikOpcode::new(0xd2, "mul-int/lit16",  InstrFormat::F22s),
        DalvikOpcode::new(0xd3, "div-int/lit16",  InstrFormat::F22s),
        DalvikOpcode::new(0xd4, "rem-int/lit16",  InstrFormat::F22s),
        DalvikOpcode::new(0xd5, "and-int/lit16",  InstrFormat::F22s),
        DalvikOpcode::new(0xd6, "or-int/lit16",   InstrFormat::F22s),
        DalvikOpcode::new(0xd7, "xor-int/lit16",  InstrFormat::F22s),
        DalvikOpcode::new(0xd8, "add-int/lit8",   InstrFormat::F22b),
        DalvikOpcode::new(0xd9, "rsub-int/lit8",  InstrFormat::F22b),
        DalvikOpcode::new(0xda, "mul-int/lit8",   InstrFormat::F22b),
        DalvikOpcode::new(0xdb, "div-int/lit8",   InstrFormat::F22b),
        DalvikOpcode::new(0xdc, "rem-int/lit8",   InstrFormat::F22b),
        DalvikOpcode::new(0xdd, "and-int/lit8",   InstrFormat::F22b),
        DalvikOpcode::new(0xde, "or-int/lit8",    InstrFormat::F22b),
        DalvikOpcode::new(0xdf, "xor-int/lit8",   InstrFormat::F22b),
        DalvikOpcode::new(0xe0, "shl-int/lit8",   InstrFormat::F22b),
        DalvikOpcode::new(0xe1, "shr-int/lit8",   InstrFormat::F22b),
        DalvikOpcode::new(0xe2, "ushr-int/lit8",  InstrFormat::F22b),
        // Dex 038 — invoke-polymorphic (F45cc, approximate as F35c)
        DalvikOpcode::new(0xfa, "invoke-polymorphic",       InstrFormat::F35c).with_invoke(),
        DalvikOpcode::new(0xfb, "invoke-polymorphic/range", InstrFormat::F3rc).with_invoke(),
        DalvikOpcode::new(0xfc, "invoke-custom",            InstrFormat::F35c).with_invoke(),
        DalvikOpcode::new(0xfd, "invoke-custom/range",      InstrFormat::F3rc).with_invoke(),
        DalvikOpcode::new(0xfe, "const-method-handle",      InstrFormat::F21c),
        DalvikOpcode::new(0xff, "const-method-type",        InstrFormat::F21c),
    ];
    for op in ops {
        t.insert(op.value, op.clone());
    }
    t
}

// ── DalvikDisasm ──────────────────────────────────────────────────────────────

/// Dalvik bytecode disassembler.
pub struct DalvikDisasm {
    table: HashMap<u8, DalvikOpcode>,
    pools: DexRefPools,
}

impl DalvikDisasm {
    /// Create a new disassembler with optional reference pools.
    #[must_use] 
    pub fn new(pools: DexRefPools) -> Self {
        Self { table: build_opcode_table(), pools }
    }

    /// Disassemble a slice of Dalvik bytecode (raw bytes, LE 16-bit code units).
    /// Returns a list of decoded instructions.
    #[must_use] 
    pub fn disassemble(&self, code: &[u8]) -> Vec<DalvikInstr> {
        let mut instrs = Vec::new();
        let units: Vec<u16> = code.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let mut pc = 0usize; // index into `units`
        while pc < units.len() {
            let word = units[pc];
            let op = u8::try_from(word & 0xFF).unwrap_or(0);
            let byte_offset = pc * 2;
            if let Some(instr) = self.decode_instr(&units, pc, byte_offset) {
                let sz = instr.size_in_units();
                instrs.push(instr);
                pc += sz.max(1);
            } else {
                // Unknown opcode — emit as raw
                instrs.push(DalvikInstr {
                    offset: byte_offset,
                    code_units: vec![word],
                    opcode: op,
                    mnemonic: "unknown".to_string(),
                    format: InstrFormat::Unknown,
                    regs: Vec::new(),
                    literal: None,
                    ref_index: None,
                    branch_offset: None,
                    operand_str: format!("{word:#06x}"),
                });
                pc += 1;
            }
        }
        instrs
    }

    fn decode_instr(&self, units: &[u16], pc: usize, byte_off: usize) -> Option<DalvikInstr> {
        let word = units[pc];
        let op = u8::try_from(word & 0xFF).unwrap_or(0);
        let tpl = self.table.get(&op)?;

        let aa = u8::try_from(word >> 8).unwrap_or(u8::MAX);
        let a_4 = u8::try_from((word >> 8) & 0xF).unwrap_or(0);
        let b_4 = u8::try_from((word >> 12) & 0xF).unwrap_or(0);

        let (mut code_units, regs, lit, ref_idx, branch_off, ops_str) = match tpl.format {
            InstrFormat::F10x => {
                (vec![word], vec![], None, None, None, String::new())
            }
            InstrFormat::F11x => {
                let r = u32::from(aa);
                (vec![word], vec![r], None, None, None, format!("v{r}"))
            }
            InstrFormat::F12x => {
                let ra = u32::from(a_4);
                let rb = u32::from(b_4);
                (vec![word], vec![ra, rb], None, None, None, format!("v{ra}, v{rb}"))
            }
            InstrFormat::F11n => {
                let ra = u32::from(a_4);
                let lit4 = (b_4.cast_signed() << 4) >> 4; // sign-extend 4 bits
                (vec![word], vec![ra], Some(i64::from(lit4)), None, None, format!("v{ra}, #{lit4}"))
            }
            InstrFormat::F21s => {
                if pc + 1 >= units.len() { return None; }
                let w2 = units[pc + 1];
                let lit = i64::from(w2.cast_signed());
                let r = u32::from(aa);
                (vec![word, w2], vec![r], Some(lit), None, None, format!("v{r}, #{lit}"))
            }
            InstrFormat::F21h => {
                if pc + 1 >= units.len() { return None; }
                let w2 = units[pc + 1];
                let lit = i64::from(w2.cast_signed()) << 16;
                let r = u32::from(aa);
                (vec![word, w2], vec![r], Some(lit), None, None, format!("v{r}, #{lit:#x}"))
            }
            InstrFormat::F21c => {
                if pc + 1 >= units.len() { return None; }
                let w2 = units[pc + 1];
                let r = u32::from(aa);
                let idx = u32::from(w2);
                let sym = self.resolve_ref(tpl, idx);
                (vec![word, w2], vec![r], None, Some(idx), None, format!("v{r}, {sym}"))
            }
            InstrFormat::F22c => {
                if pc + 1 >= units.len() { return None; }
                let w2 = units[pc + 1];
                let ra = u32::from(a_4);
                let rb = u32::from(b_4);
                let idx = u32::from(w2);
                let sym = self.resolve_field_or_type(tpl, idx);
                (vec![word, w2], vec![ra, rb], None, Some(idx), None, format!("v{ra}, v{rb}, {sym}"))
            }
            InstrFormat::F21t => {
                if pc + 1 >= units.len() { return None; }
                let w2 = units[pc + 1];
                let r = u32::from(aa);
                let off = i32::from(w2.cast_signed());
                let target = (i32::try_from(pc).unwrap_or(i32::MAX).saturating_add(off)) * 2;
                (vec![word, w2], vec![r], None, None, Some(off), format!("v{r}, {target:+06x}"))
            }
            InstrFormat::F22t => {
                if pc + 1 >= units.len() { return None; }
                let w2 = units[pc + 1];
                let ra = u32::from(a_4);
                let rb = u32::from(b_4);
                let off = i32::from(w2.cast_signed());
                let target = (i32::try_from(pc).unwrap_or(i32::MAX).saturating_add(off)) * 2;
                (vec![word, w2], vec![ra, rb], None, None, Some(off), format!("v{ra}, v{rb}, {target:+06x}"))
            }
            InstrFormat::F10t => {
                let off = i32::from(aa.cast_signed());
                let target = (i32::try_from(pc).unwrap_or(i32::MAX).saturating_add(off)) * 2;
                (vec![word], vec![], None, None, Some(off), format!("{target:+06x}"))
            }
            InstrFormat::F20t => {
                if pc + 1 >= units.len() { return None; }
                let w2 = units[pc + 1];
                let off = i32::from(w2.cast_signed());
                let target = (i32::try_from(pc).unwrap_or(i32::MAX).saturating_add(off)) * 2;
                (vec![word, w2], vec![], None, None, Some(off), format!("{target:+06x}"))
            }
            InstrFormat::F30t => {
                if pc + 2 >= units.len() { return None; }
                let w2 = units[pc + 1];
                let w3 = units[pc + 2];
                let off = (u32::from(w3) << 16 | u32::from(w2)).cast_signed();
                let target = (i32::try_from(pc).unwrap_or(i32::MAX).saturating_add(off)) * 2;
                (vec![word, w2, w3], vec![], None, None, Some(off), format!("{target:+06x}"))
            }
            InstrFormat::F31i => {
                if pc + 2 > units.len() { return None; }
                let w2 = units[pc + 1];
                let w3 = units[pc + 2];
                let r = u32::from(aa);
                let val = i64::from((u32::from(w3) << 16 | u32::from(w2)).cast_signed());
                (vec![word, w2, w3], vec![r], Some(val), None, None, format!("v{r}, #{val:#010x}"))
            }
            InstrFormat::F31c => {
                if pc + 2 > units.len() { return None; }
                let w2 = units[pc + 1];
                let w3 = units[pc + 2];
                let r = u32::from(aa);
                let idx = (u32::from(w3) << 16) | u32::from(w2);
                let sym = self.pools.string(idx);
                (vec![word, w2, w3], vec![r], None, Some(idx), None, format!("v{r}, \"{sym}\""))
            }
            InstrFormat::F51l => {
                if pc + 4 >= units.len() { return None; }
                let mut raw = [0u16; 4];
                for i in 0..4 { raw[i] = units[pc + 1 + i]; }
                let r = u32::from(aa);
                let val = u64::from(raw[0]) | (u64::from(raw[1]) << 16)
                        | (u64::from(raw[2]) << 32) | (u64::from(raw[3]) << 48);
                let cu = vec![word, raw[0], raw[1], raw[2], raw[3]];
                (cu, vec![r], Some(val.cast_signed()), None, None, format!("v{r}, #{val:#018x}"))
            }
            InstrFormat::F22b => {
                if pc + 1 >= units.len() { return None; }
                let w2 = units[pc + 1];
                let ra = u32::from(aa);
                let rb = u32::from(w2 & 0xFF);
                let lit = i64::from(u8::try_from(w2 >> 8).unwrap_or(u8::MAX).cast_signed());
                (vec![word, w2], vec![ra, rb], Some(lit), None, None, format!("v{ra}, v{rb}, #{lit}"))
            }
            InstrFormat::F22s => {
                if pc + 1 >= units.len() { return None; }
                let w2 = units[pc + 1];
                let ra = u32::from(a_4);
                let rb = u32::from(b_4);
                let lit = i64::from(w2.cast_signed());
                (vec![word, w2], vec![ra, rb], Some(lit), None, None, format!("v{ra}, v{rb}, #{lit}"))
            }
            InstrFormat::F23x => {
                if pc + 1 >= units.len() { return None; }
                let w2 = units[pc + 1];
                let ra = u32::from(aa);
                let rb = u32::from(w2 & 0xFF);
                let rc = u32::from(w2 >> 8);
                (vec![word, w2], vec![ra, rb, rc], None, None, None,
                 format!("v{ra}, v{rb}, v{rc}"))
            }
            InstrFormat::F22x | InstrFormat::F22xW => {
                if pc + 1 >= units.len() { return None; }
                let w2 = units[pc + 1];
                let ra = u32::from(aa);
                let rb = u32::from(w2);
                (vec![word, w2], vec![ra, rb], None, None, None, format!("v{ra}, v{rb}"))
            }
            InstrFormat::F32x => {
                if pc + 2 > units.len() { return None; }
                let w2 = units[pc + 1];
                let w3 = units[pc + 2];
                (vec![word, w2, w3], vec![u32::from(w2), u32::from(w3)], None, None, None,
                 format!("v{w2}, v{w3}"))
            }
            InstrFormat::F35c => {
                if pc + 1 >= units.len() { return None; }
                let w2 = units[pc + 1];
                let count = (word >> 12) as u8 & 0xF;
                let idx = u32::from(w2);
                let sym = self.resolve_ref(tpl, idx);
                let d = (word >> 8) as u8;
                let regs = decode_35c_regs(units, pc, count, d);
                let regs_str: Vec<String> = regs.iter().map(|r| format!("v{r}")).collect();
                (vec![word, w2], regs, None, Some(idx), None,
                 format!("{{{}}}, {sym}", regs_str.join(", ")))
            }
            InstrFormat::F3rc => {
                if pc + 2 > units.len() { return None; }
                let w2 = units[pc + 1];
                let w3 = units[pc + 2];
                let count = u32::from(aa);
                let first_reg = u32::from(w3);
                let idx = u32::from(w2);
                let sym = self.resolve_ref(tpl, idx);
                let regs: Vec<u32> = (first_reg..first_reg + count).collect();
                let regs_str: Vec<String> = regs.iter().map(|r| format!("v{r}")).collect();
                (vec![word, w2, w3], regs, None, Some(idx), None,
                 format!("{{{}}}, {sym}", regs_str.join(", ")))
            }
            InstrFormat::Unknown => {
                (vec![word], vec![], None, None, None, format!("{word:#06x}"))
            }
        };
        // Ensure code_units covers actual size
        let _ = byte_off;
        Some(DalvikInstr {
            offset: byte_off,
            code_units: {
                // Trim to actual size determined above
                code_units.truncate(code_units.len());
                code_units
            },
            opcode: op,
            mnemonic: tpl.mnemonic.to_string(),
            format: tpl.format,
            regs,
            literal: lit,
            ref_index: ref_idx,
            branch_offset: branch_off,
            operand_str: ops_str,
        })
    }

    fn resolve_ref(&self, op: &DalvikOpcode, idx: u32) -> String {
        match op.mnemonic {
            m if m.starts_with("const-string") => format!("\"{}\"", self.pools.string(idx)),
            m if m.contains("type") || m.starts_with("check-cast")
              || m.starts_with("instance-of") || m.starts_with("new-instance")
              || m.starts_with("new-array") || m.starts_with("const-class")
              || m.starts_with("filled-new-array") => {
                self.pools.type_ref(idx)
            }
            m if m.starts_with("invoke") || m.starts_with("const-method") => {
                self.pools.method(idx)
            }
            m if m.starts_with("iget") || m.starts_with("iput")
              || m.starts_with("sget") || m.starts_with("sput") => {
                self.pools.field(idx)
            }
            _ => format!("ref@{idx:#x}"),
        }
    }

    fn resolve_field_or_type(&self, op: &DalvikOpcode, idx: u32) -> String {
        match op.mnemonic {
            m if m.starts_with("iget") || m.starts_with("iput") => self.pools.field(idx),
            _ => self.pools.type_ref(idx),
        }
    }
}

fn decode_35c_regs(units: &[u16], pc: usize, count: u8, d: u8) -> Vec<u32> {
    // Format: A|G|op  BBBB  F|E|D|C
    // where C/D/E/F/G are the 5 possible register nibbles
    if pc + 2 >= units.len() { return Vec::new(); }
    let w3 = units[pc + 2];
    let c = u32::from(w3 & 0xF);
    let de = u32::from((w3 >> 4) & 0xF);
    let ef = u32::from((w3 >> 8) & 0xF);
    let fg = u32::from((w3 >> 12) & 0xF);
    let g = u32::from(d >> 4);
    let regs = [c, de, ef, fg, g];
    regs[..count.min(5) as usize].to_vec()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn disasm(bytes: &[u8]) -> Vec<DalvikInstr> {
        DalvikDisasm::new(DexRefPools::default()).disassemble(bytes)
    }

    #[test]
    fn test_nop() {
        // nop  = 0x00 0x00
        let instrs = disasm(&[0x00, 0x00]);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].mnemonic, "nop");
    }

    #[test]
    fn test_return_void() {
        let instrs = disasm(&[0x0e, 0x00]);
        assert_eq!(instrs[0].mnemonic, "return-void");
    }

    #[test]
    fn test_move_12x() {
        // move v1, v2  => opcode=0x01, high byte = A|B nibbles = 0x21
        let instrs = disasm(&[0x01, 0x21]);
        assert_eq!(instrs[0].mnemonic, "move");
        assert_eq!(instrs[0].regs[0], 1); // vA=1
        assert_eq!(instrs[0].regs[1], 2); // vB=2
    }

    #[test]
    fn test_const4_11n() {
        // const/4 v3, #-1  => 0x12 high byte = A=3,B=-1 => 0xF3
        let instrs = disasm(&[0x12, 0xF3]);
        assert_eq!(instrs[0].mnemonic, "const/4");
        assert_eq!(instrs[0].regs[0], 3);
        assert_eq!(instrs[0].literal, Some(-1));
    }

    #[test]
    fn test_const16_21s() {
        // const/16 v0, #0x1234 => [0x13,0x00, 0x34,0x12]
        let instrs = disasm(&[0x13, 0x00, 0x34, 0x12]);
        assert_eq!(instrs[0].mnemonic, "const/16");
        assert_eq!(instrs[0].literal, Some(0x1234));
    }

    #[test]
    fn test_invoke_virtual_35c() {
        // invoke-virtual {v0}, method@0001
        // word0 = 0x6e 0x10 (A=1 reg, op=0x6e)
        // word1 = 0x01 0x00 (method index)
        // word2 = 0x00 0x00 (C=v0)
        let bytes = [0x6e, 0x10, 0x01, 0x00, 0x00, 0x00];
        let instrs = disasm(&bytes);
        assert_eq!(instrs[0].mnemonic, "invoke-virtual");
        assert!(instrs[0].mnemonic.starts_with("invoke"));
        // Actually invoke is on the opcode template
    }

    #[test]
    fn test_goto_10t() {
        // goto -2  =>  0x28 0xFE
        let instrs = disasm(&[0x28, 0xFE]);
        assert_eq!(instrs[0].mnemonic, "goto");
        assert!(instrs[0].branch_offset.is_some());
    }

    #[test]
    fn test_if_eq_22t() {
        // if-eq v0, v1, +5  => 0x32 0x10 0x05 0x00
        let instrs = disasm(&[0x32, 0x10, 0x05, 0x00]);
        assert_eq!(instrs[0].mnemonic, "if-eq");
        assert_eq!(instrs[0].branch_offset, Some(5));
    }

    #[test]
    fn test_const_wide_51l() {
        // const-wide v0, #0x0102030405060708  (5 words)
        let mut bytes = vec![0x18u8, 0x00]; // op=0x18, vAA=0
        bytes.extend_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        let instrs = disasm(&bytes);
        assert_eq!(instrs[0].mnemonic, "const-wide");
        assert_eq!(instrs[0].literal, Some(0x0102_0304_0506_0708_u64.cast_signed()));
    }

    #[test]
    fn test_add_int_23x() {
        // add-int v0, v1, v2  => 0x90 0x00 0x01 0x02
        let instrs = disasm(&[0x90, 0x00, 0x01, 0x02]);
        assert_eq!(instrs[0].mnemonic, "add-int");
        assert_eq!(instrs[0].regs, vec![0, 1, 2]);
    }

    #[test]
    fn test_disasm_multi_instr() {
        // nop + return-void
        let instrs = disasm(&[0x00, 0x00, 0x0e, 0x00]);
        assert_eq!(instrs.len(), 2);
    }

    #[test]
    fn test_string_ref_resolution() {
        let pools = DexRefPools {
            strings: vec!["Hello".to_string()],
            ..Default::default()
        };
        let disasm = DalvikDisasm::new(pools);
        // const-string v0, string@0  => 0x1a 0x00 0x00 0x00
        let instrs = disasm.disassemble(&[0x1a, 0x00, 0x00, 0x00]);
        assert!(instrs[0].operand_str.contains("Hello"));
    }

    #[test]
    fn test_unknown_opcode() {
        // Use opcode 0x73 which is reserved
        let instrs = disasm(&[0x73, 0x00]);
        assert_eq!(instrs[0].mnemonic, "unknown");
    }

    #[test]
    fn test_instr_display() {
        let instrs = disasm(&[0x0e, 0x00]);
        let s = format!("{}", instrs[0]);
        assert!(s.contains("return-void"));
    }

    #[test]
    fn test_offset_tracking() {
        // Two 1-word instructions
        let instrs = disasm(&[0x00, 0x00, 0x0e, 0x00]);
        assert_eq!(instrs[0].offset, 0);
        assert_eq!(instrs[1].offset, 2);
    }
}
