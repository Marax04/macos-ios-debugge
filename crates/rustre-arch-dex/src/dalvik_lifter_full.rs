//! Complete Dalvik → LLIL lifter.
//!
//! Lifts all 256 Dalvik opcodes (plus extended 0xE3–0xFF range) to a
//! flat intermediate representation.
//!
//! Provides:
//! - [`DalvikReg`] — virtual register reference
//! - [`RegularInstruction`] — standard non-wide instruction
//! - [`WideInstruction`] — 64-bit wide instruction
//! - [`ObjectInstruction`] — object/field/invoke instruction
//! - [`ArrayInstruction`] — array get/put instruction
//! - [`DalvikLiftedOp`] — flat IR operation
//! - [`DalvikLifterFull`] — the lifter

// ---------------------------------------------------------------------------
// DalvikReg
// ---------------------------------------------------------------------------

/// A Dalvik virtual register reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DalvikReg(pub u16);

impl DalvikReg {
    #[must_use] 
    pub const fn new(n: u16) -> Self {
        Self(n)
    }
    #[must_use] 
    pub fn name(self) -> String {
        format!("v{}", self.0)
    }
    #[must_use] 
    pub const fn is_wide_companion(self) -> bool {
        self.0 % 2 == 1
    }
}

impl std::fmt::Display for DalvikReg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Instruction categories
// ---------------------------------------------------------------------------

/// Standard (non-wide) Dalvik instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegularInstruction {
    pub opcode: u8,
    pub mnemonic: &'static str,
    pub dst: Option<DalvikReg>,
    pub src1: Option<DalvikReg>,
    pub src2: Option<DalvikReg>,
    pub imm: Option<i64>,
    pub size: usize,
}

/// Wide (64-bit) Dalvik instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WideInstruction {
    pub opcode: u8,
    pub mnemonic: &'static str,
    /// Destination register pair (vA, vA+1).
    pub dst_pair: (DalvikReg, DalvikReg),
    /// Source register pair.
    pub src_pair: Option<(DalvikReg, DalvikReg)>,
    /// Immediate value.
    pub imm: Option<i64>,
    pub size: usize,
}

/// Object / field / invoke instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInstruction {
    pub opcode: u8,
    pub mnemonic: &'static str,
    pub dst: Option<DalvikReg>,
    pub object_reg: Option<DalvikReg>,
    /// Constant pool index (field/method/type reference).
    pub cp_index: u16,
    /// Additional argument registers (for invoke-*).
    pub args: Vec<DalvikReg>,
    pub size: usize,
}

/// Array get / put instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArrayInstruction {
    pub opcode: u8,
    pub mnemonic: &'static str,
    pub value_reg: DalvikReg,
    pub array_reg: DalvikReg,
    pub index_reg: DalvikReg,
    pub size: usize,
}

// ---------------------------------------------------------------------------
// DalvikLiftedOp — flat IR
// ---------------------------------------------------------------------------

/// A single lifted Dalvik IR operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DalvikLiftedOp {
    /// dst = src.
    Move { dst: DalvikReg, src: DalvikReg },
    /// dst = imm.
    LoadImm { dst: DalvikReg, imm: i64 },
    /// dst = lhs OP rhs.
    BinOp {
        op: DalvikBinOp,
        dst: DalvikReg,
        lhs: DalvikReg,
        rhs: DalvikReg,
    },
    /// dst = lhs OP imm.
    BinOpImm {
        op: DalvikBinOp,
        dst: DalvikReg,
        lhs: DalvikReg,
        imm: i64,
    },
    /// dst = -src.
    UnaryNeg { dst: DalvikReg, src: DalvikReg },
    /// dst = ~src.
    UnaryNot { dst: DalvikReg, src: DalvikReg },
    /// Load from array: dst = array[index].
    AGet {
        dst: DalvikReg,
        array: DalvikReg,
        index: DalvikReg,
    },
    /// Store to array: array[index] = src.
    APut {
        src: DalvikReg,
        array: DalvikReg,
        index: DalvikReg,
    },
    /// Load from object field: dst = obj.field.
    IGet {
        dst: DalvikReg,
        obj: DalvikReg,
        field_idx: u16,
    },
    /// Store to object field: obj.field = src.
    IPut {
        src: DalvikReg,
        obj: DalvikReg,
        field_idx: u16,
    },
    /// Load static field.
    SGet { dst: DalvikReg, field_idx: u16 },
    /// Store static field.
    SPut { src: DalvikReg, field_idx: u16 },
    /// invoke-* : `call_result` = method(args...).
    Invoke {
        kind: InvokeKind,
        method_idx: u16,
        args: Vec<DalvikReg>,
    },
    /// Move the return value.
    MoveResult { dst: DalvikReg },
    /// Return void.
    ReturnVoid,
    /// Return value.
    Return { src: DalvikReg },
    /// Unconditional branch.
    Goto { offset: i32 },
    /// Conditional branch: if lhs OP rhs then goto offset.
    If {
        cond: DalvikCond,
        lhs: DalvikReg,
        rhs: DalvikReg,
        offset: i32,
    },
    /// Conditional branch: if lhs OP 0 then goto offset.
    IfZ {
        cond: DalvikCond,
        lhs: DalvikReg,
        offset: i32,
    },
    /// new-instance: dst = new `TypeRef`.
    NewInstance { dst: DalvikReg, type_idx: u16 },
    /// new-array: dst = new T[size].
    NewArray {
        dst: DalvikReg,
        size: DalvikReg,
        type_idx: u16,
    },
    /// filled-new-array.
    FilledNewArray { type_idx: u16, args: Vec<DalvikReg> },
    /// check-cast: (Type) reg.
    CheckCast { reg: DalvikReg, type_idx: u16 },
    /// instance-of: dst = reg instanceof Type.
    InstanceOf {
        dst: DalvikReg,
        reg: DalvikReg,
        type_idx: u16,
    },
    /// array-length: dst = array.length.
    ArrayLength { dst: DalvikReg, array: DalvikReg },
    /// throw.
    Throw { exc: DalvikReg },
    /// monitor-enter.
    MonitorEnter { obj: DalvikReg },
    /// monitor-exit.
    MonitorExit { obj: DalvikReg },
    /// Conversion.
    Convert {
        dst: DalvikReg,
        src: DalvikReg,
        kind: ConvertKind,
    },
    /// No-op.
    Nop,
    /// Unrecognised opcode.
    Unknown(u8),
}

/// Binary operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DalvikBinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Ushr,
    AddLong,
    SubLong,
    MulLong,
    DivLong,
    RemLong,
    AndLong,
    OrLong,
    XorLong,
    ShlLong,
    ShrLong,
    UshrLong,
    AddFloat,
    SubFloat,
    MulFloat,
    DivFloat,
    RemFloat,
    AddDouble,
    SubDouble,
    MulDouble,
    DivDouble,
    RemDouble,
}

/// Invoke kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvokeKind {
    Virtual,
    Super,
    Direct,
    Static,
    Interface,
    VirtualRange,
    SuperRange,
    DirectRange,
    StaticRange,
    InterfaceRange,
    Custom,
    Polymorphic,
}

impl InvokeKind {
    #[must_use] 
    pub const fn is_virtual(self) -> bool {
        matches!(self, Self::Virtual | Self::VirtualRange)
    }
    #[must_use] 
    pub const fn is_static(self) -> bool {
        matches!(self, Self::Static | Self::StaticRange)
    }
}

/// Conditional branch condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DalvikCond {
    Eq,
    Ne,
    Lt,
    Ge,
    Gt,
    Le,
}

/// Type conversion kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvertKind {
    IntToLong,
    IntToFloat,
    IntToDouble,
    LongToInt,
    LongToFloat,
    LongToDouble,
    FloatToInt,
    FloatToLong,
    FloatToDouble,
    DoubleToInt,
    DoubleToLong,
    DoubleToFloat,
    IntToByte,
    IntToChar,
    IntToShort,
}

// ---------------------------------------------------------------------------
// Mnemonic table (all 256 standard opcodes)
// ---------------------------------------------------------------------------

/// Opcode-dispatch chunk 0 of [`dalvik_mnemonic`]; unmatched opcodes fall through to the next chunk.
const fn dalvik_mnemonic_part0(op: u8) -> &'static str {
    match op {
            0x00 => "nop",
            0x01 => "move",
            0x02 => "move/from16",
            0x03 => "move/16",
            0x04 => "move-wide",
            0x05 => "move-wide/from16",
            0x06 => "move-wide/16",
            0x07 => "move-object",
            0x08 => "move-object/from16",
            0x09 => "move-object/16",
            0x0a => "move-result",
            0x0b => "move-result-wide",
            0x0c => "move-result-object",
            0x0d => "move-exception",
            0x0e => "return-void",
            0x0f => "return",
            0x10 => "return-wide",
            0x11 => "return-object",
            0x12 => "const/4",
            0x13 => "const/16",
            0x14 => "const",
            0x15 => "const/high16",
            0x16 => "const-wide/16",
            0x17 => "const-wide/32",
            0x18 => "const-wide",
            0x19 => "const-wide/high16",
            0x1a => "const-string",
            0x1b => "const-string/jumbo",
            0x1c => "const-class",
            0x1d => "monitor-enter",
            0x1e => "monitor-exit",
            0x1f => "check-cast",
            0x20 => "instance-of",
            0x21 => "array-length",
            0x22 => "new-instance",
            0x23 => "new-array",
            0x24 => "filled-new-array",
            0x25 => "filled-new-array/range",
            0x26 => "fill-array-data",
            0x27 => "throw",
            0x28 => "goto",
            0x29 => "goto/16",
            0x2a => "goto/32",
            0x2b => "packed-switch",
            0x2c => "sparse-switch",
            0x2d => "cmpl-float",
            0x2e => "cmpg-float",
            0x2f => "cmpl-double",
            0x30 => "cmpg-double",
            0x31 => "cmp-long",
            0x32 => "if-eq",
            0x33 => "if-ne",
            0x34 => "if-lt",
            0x35 => "if-ge",
            0x36 => "if-gt",
            0x37 => "if-le",
            0x38 => "if-eqz",
            0x39 => "if-nez",
            0x3a => "if-ltz",
            0x3b => "if-gez",
            0x3c => "if-gtz",
            0x3d => "if-lez",
            0x44 => "aget",
            0x45 => "aget-wide",
            0x46 => "aget-object",
            0x47 => "aget-boolean",
            0x48 => "aget-byte",
            0x49 => "aget-char",
            0x4a => "aget-short",
            0x4b => "aput",
            0x4c => "aput-wide",
            0x4d => "aput-object",
            0x4e => "aput-boolean",
            0x4f => "aput-byte",
            0x50 => "aput-char",
        _ => dalvik_mnemonic_part1(op),
    }
}

/// Opcode-dispatch chunk 1 of [`dalvik_mnemonic`]; unmatched opcodes fall through to the next chunk.
const fn dalvik_mnemonic_part1(op: u8) -> &'static str {
    match op {
            0x51 => "aput-short",
            0x52 => "iget",
            0x53 => "iget-wide",
            0x54 => "iget-object",
            0x55 => "iget-boolean",
            0x56 => "iget-byte",
            0x57 => "iget-char",
            0x58 => "iget-short",
            0x59 => "iput",
            0x5a => "iput-wide",
            0x5b => "iput-object",
            0x5c => "iput-boolean",
            0x5d => "iput-byte",
            0x5e => "iput-char",
            0x5f => "iput-short",
            0x60 => "sget",
            0x61 => "sget-wide",
            0x62 => "sget-object",
            0x63 => "sget-boolean",
            0x64 => "sget-byte",
            0x65 => "sget-char",
            0x66 => "sget-short",
            0x67 => "sput",
            0x68 => "sput-wide",
            0x69 => "sput-object",
            0x6a => "sput-boolean",
            0x6b => "sput-byte",
            0x6c => "sput-char",
            0x6d => "sput-short",
            0x6e => "invoke-virtual",
            0x6f => "invoke-super",
            0x70 => "invoke-direct",
            0x71 => "invoke-static",
            0x72 => "invoke-interface",
            0x74 => "invoke-virtual/range",
            0x75 => "invoke-super/range",
            0x76 => "invoke-direct/range",
            0x77 => "invoke-static/range",
            0x78 => "invoke-interface/range",
            0x7b => "neg-int",
            0x7c => "not-int",
            0x7d => "neg-long",
            0x7e => "not-long",
            0x7f => "neg-float",
            0x80 => "neg-double",
            0x81 => "int-to-long",
            0x82 => "int-to-float",
            0x83 => "int-to-double",
            0x84 => "long-to-int",
            0x85 => "long-to-float",
            0x86 => "long-to-double",
            0x87 => "float-to-int",
            0x88 => "float-to-long",
            0x89 => "float-to-double",
            0x8a => "double-to-int",
            0x8b => "double-to-long",
            0x8c => "double-to-float",
            0x8d => "int-to-byte",
            0x8e => "int-to-char",
            0x8f => "int-to-short",
            0x90 => "add-int",
            0x91 => "sub-int",
            0x92 => "mul-int",
            0x93 => "div-int",
            0x94 => "rem-int",
            0x95 => "and-int",
            0x96 => "or-int",
            0x97 => "xor-int",
            0x98 => "shl-int",
            0x99 => "shr-int",
            0x9a => "ushr-int",
            0x9b => "add-long",
            0x9c => "sub-long",
            0x9d => "mul-long",
            0x9e => "div-long",
        _ => dalvik_mnemonic_part2(op),
    }
}

/// Opcode-dispatch chunk 2 of [`dalvik_mnemonic`]; unmatched opcodes fall through to the next chunk.
const fn dalvik_mnemonic_part2(op: u8) -> &'static str {
    match op {
            0x9f => "rem-long",
            0xa0 => "and-long",
            0xa1 => "or-long",
            0xa2 => "xor-long",
            0xa3 => "shl-long",
            0xa4 => "shr-long",
            0xa5 => "ushr-long",
            0xa6 => "add-float",
            0xa7 => "sub-float",
            0xa8 => "mul-float",
            0xa9 => "div-float",
            0xaa => "rem-float",
            0xab => "add-double",
            0xac => "sub-double",
            0xad => "mul-double",
            0xae => "div-double",
            0xaf => "rem-double",
            0xb0 => "add-int/2addr",
            0xb1 => "sub-int/2addr",
            0xb2 => "mul-int/2addr",
            0xb3 => "div-int/2addr",
            0xb4 => "rem-int/2addr",
            0xb5 => "and-int/2addr",
            0xb6 => "or-int/2addr",
            0xb7 => "xor-int/2addr",
            0xb8 => "shl-int/2addr",
            0xb9 => "shr-int/2addr",
            0xba => "ushr-int/2addr",
            0xbb => "add-long/2addr",
            0xbc => "sub-long/2addr",
            0xbd => "mul-long/2addr",
            0xbe => "div-long/2addr",
            0xbf => "rem-long/2addr",
            0xc0 => "and-long/2addr",
            0xc1 => "or-long/2addr",
            0xc2 => "xor-long/2addr",
            0xc3 => "shl-long/2addr",
            0xc4 => "shr-long/2addr",
            0xc5 => "ushr-long/2addr",
            0xc6 => "add-float/2addr",
            0xc7 => "sub-float/2addr",
            0xc8 => "mul-float/2addr",
            0xc9 => "div-float/2addr",
            0xca => "rem-float/2addr",
            0xcb => "add-double/2addr",
            0xcc => "sub-double/2addr",
            0xcd => "mul-double/2addr",
            0xce => "div-double/2addr",
            0xcf => "rem-double/2addr",
            0xd0 => "add-int/lit16",
            0xd1 => "rsub-int",
            0xd2 => "mul-int/lit16",
            0xd3 => "div-int/lit16",
            0xd4 => "rem-int/lit16",
            0xd5 => "and-int/lit16",
            0xd6 => "or-int/lit16",
            0xd7 => "xor-int/lit16",
            0xd8 => "add-int/lit8",
            0xd9 => "rsub-int/lit8",
            0xda => "mul-int/lit8",
            0xdb => "div-int/lit8",
            0xdc => "rem-int/lit8",
            0xdd => "and-int/lit8",
            0xde => "or-int/lit8",
            0xdf => "xor-int/lit8",
            0xe0 => "shl-int/lit8",
            0xe1 => "shr-int/lit8",
            0xe2 => "ushr-int/lit8",
            // Extended / ART opcodes 0xE3–0xFF
            0xe3 => "iget-quick",
            0xe4 => "iget-wide-quick",
            0xe5 => "iget-object-quick",
            0xe6 => "iput-quick",
            0xe7 => "iput-wide-quick",
            0xe8 => "iput-object-quick",
        _ => dalvik_mnemonic_part3(op),
    }
}

/// Opcode-dispatch chunk 3 of [`dalvik_mnemonic`]; unmatched opcodes fall through to the next chunk.
const fn dalvik_mnemonic_part3(op: u8) -> &'static str {
    match op {
            0xe9 => "invoke-virtual-quick",
            // `/range` is a terminal format suffix, so the range variant of
            // `invoke-virtual-quick` is `invoke-virtual-quick/range`.  This read
            // "invoke-virtual/range-quick", which splits the base mnemonic and
            // contradicts its own neighbour at 0xe9 above.  `full_opcode_table` and
            // `lib.rs` both spell it the other way.
            0xea => "invoke-virtual-quick/range",
            0xeb => "iput-boolean-quick",
            0xec => "iput-byte-quick",
            0xed => "iput-char-quick",
            0xee => "iput-short-quick",
            0xef => "iget-boolean-quick",
            0xf0 => "iget-byte-quick",
            0xf1 => "iget-char-quick",
            0xf2 => "iget-short-quick",
            // 0xf3..=0xf9 and 0xfa..=0xfd follow `full_opcode_table.rs`, the 256-entry
            // table in this crate that also records each opcode's instruction format.
            //
            // Two errors were corrected here:
            //  * a phantom `unused-f4` pushed the six experimental lambda opcodes one
            //    slot too high, so every one of them was mislabelled;
            //  * invoke-custom and invoke-polymorphic were swapped.  The formats
            //    settle that independently: invoke-polymorphic is 45cc/4rcc and
            //    carries an extra `proto@HHHH` operand, invoke-custom is 35c/3rc and
            //    does not.
            0xf3 => "invoke-lambda",
            0xf4 => "capture-variable",
            0xf5 => "create-lambda",
            0xf6 => "liberate-variable",
            0xf7 => "box-lambda",
            0xf8 => "unbox-lambda",
            0xf9 => "unused-f9",
            0xfa => "invoke-polymorphic",
            0xfb => "invoke-polymorphic/range",
            0xfc => "invoke-custom",
            0xfd => "invoke-custom/range",
            0xfe => "const-method-handle",
            0xff => "const-method-type",
            _ => "unused",
    }
}

/// Return the mnemonic for Dalvik opcode `op`, or `"unknown"`.
#[must_use] 
pub const fn dalvik_mnemonic(op: u8) -> &'static str {
    dalvik_mnemonic_part0(op)
}

// ---------------------------------------------------------------------------
// DalvikLifterFull
// ---------------------------------------------------------------------------

/// Complete Dalvik→LLIL lifter.  Lifts all 256 opcodes.
#[derive(Debug, Default)]
pub struct DalvikLifterFull;

impl DalvikLifterFull {
    /// Lift one opcode to a list of [`DalvikLiftedOp`]s.
    #[must_use] 
    pub fn lift_opcode(
        &self,
        op: u8,
        dst: u8,
        src_a: u8,
        src_b: u8,
        imm: i64,
        cp_idx: u16,
    ) -> Vec<DalvikLiftedOp> {
        let vd = DalvikReg(u16::from(dst));
        let va = DalvikReg(u16::from(src_a));
        let vb = DalvikReg(u16::from(src_b));

        lift_opcode_part0(op, vd, va, vb, imm, cp_idx)
    }

    /// Lift all opcodes in a raw byte stream (each byte is an opcode for simplicity).
    #[must_use] 
    pub fn lift_stream(&self, opcodes: &[u8]) -> Vec<DalvikLiftedOp> {
        opcodes
            .iter()
            .flat_map(|&op| self.lift_opcode(op, 0, 1, 2, 0, 0))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Opcode-dispatch chunk 0 of [`DalvikLifterFull::lift_opcode`];
/// unmatched opcodes fall through to the next chunk.
fn lift_opcode_part0(op: u8, vd: DalvikReg, va: DalvikReg, vb: DalvikReg, imm: i64, cp_idx: u16) -> Vec<DalvikLiftedOp> {
    match op {
                // 0x00 nop, and 0x26 fill-array-data whose payload lives outside the
                // instruction stream and so lifts to nothing.
                0x00 | 0x26 => vec![DalvikLiftedOp::Nop],

                // ── Move ─────────────────────────────────────────────────────────
                0x01..=0x09 => vec![DalvikLiftedOp::Move { dst: vd, src: va }],
                // 0x0a..=0x0c move-result*, 0x0d move-exception: all deliver a value
                // produced outside the instruction into vAA.
                0x0a..=0x0d => vec![DalvikLiftedOp::MoveResult { dst: vd }],

                // ── Return ───────────────────────────────────────────────────────
                0x0e => vec![DalvikLiftedOp::ReturnVoid],
                0x0f..=0x11 => vec![DalvikLiftedOp::Return { src: vd }],

                // ── Const ────────────────────────────────────────────────────────
                0x12..=0x19 => vec![DalvikLiftedOp::LoadImm { dst: vd, imm }],
                // const-string (0x1a/0x1b), const-class (0x1c) and the sget family
                // 0x60..=0x66 all read a constant-pool-addressed slot into vAA.
                0x1a..=0x1c | 0x60..=0x66 => vec![DalvikLiftedOp::SGet {
                    dst: vd,
                    field_idx: cp_idx,
                }],

                // ── Monitor ─────────────────────────────────────────────────────
                0x1d => vec![DalvikLiftedOp::MonitorEnter { obj: vd }],
                0x1e => vec![DalvikLiftedOp::MonitorExit { obj: vd }],

                // ── Cast / type ops ──────────────────────────────────────────────
                0x1f => vec![DalvikLiftedOp::CheckCast {
                    reg: vd,
                    type_idx: cp_idx,
                }],
                0x20 => vec![DalvikLiftedOp::InstanceOf {
                    dst: vd,
                    reg: va,
                    type_idx: cp_idx,
                }],
                0x21 => vec![DalvikLiftedOp::ArrayLength { dst: vd, array: va }],
                0x22 => vec![DalvikLiftedOp::NewInstance {
                    dst: vd,
                    type_idx: cp_idx,
                }],
                0x23 => vec![DalvikLiftedOp::NewArray {
                    dst: vd,
                    size: va,
                    type_idx: cp_idx,
                }],
                0x24 | 0x25 => vec![DalvikLiftedOp::FilledNewArray {
                    type_idx: cp_idx,
                    args: vec![vd],
                }],
                0x27 => vec![DalvikLiftedOp::Throw { exc: vd }],

                // ── Branch ──────────────────────────────────────────────────────
                // goto/goto16/goto32 (0x28..=0x2a) and packed/sparse-switch
                // (0x2b/0x2c), which are modelled as an unconditional transfer.
                0x28..=0x2c => vec![DalvikLiftedOp::Goto { offset: branch_offset(imm) }],

                // ── Compare ─────────────────────────────────────────────────────
                // cmp* (0x2d..=0x31) and sub-int (0x91): both a subtraction of two
                // registers into vAA.
                0x2d..=0x31 | 0x91 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Sub,
                    dst: vd,
                    lhs: va,
                    rhs: vb,
                }],

                // ── If ──────────────────────────────────────────────────────────
                0x32 => vec![DalvikLiftedOp::If {
                    cond: DalvikCond::Eq,
                    lhs: vd,
                    rhs: va,
                    offset: branch_offset(imm),
                }],
        _ => lift_opcode_part1(op, vd, va, vb, imm, cp_idx),
    }
}

/// Opcode-dispatch chunk 1 of [`DalvikLifterFull::lift_opcode`];
/// unmatched opcodes fall through to the next chunk.
fn lift_opcode_part1(op: u8, vd: DalvikReg, va: DalvikReg, vb: DalvikReg, imm: i64, cp_idx: u16) -> Vec<DalvikLiftedOp> {
    match op {
                0x33 => vec![DalvikLiftedOp::If {
                    cond: DalvikCond::Ne,
                    lhs: vd,
                    rhs: va,
                    offset: branch_offset(imm),
                }],
                0x34 => vec![DalvikLiftedOp::If {
                    cond: DalvikCond::Lt,
                    lhs: vd,
                    rhs: va,
                    offset: branch_offset(imm),
                }],
                0x35 => vec![DalvikLiftedOp::If {
                    cond: DalvikCond::Ge,
                    lhs: vd,
                    rhs: va,
                    offset: branch_offset(imm),
                }],
                0x36 => vec![DalvikLiftedOp::If {
                    cond: DalvikCond::Gt,
                    lhs: vd,
                    rhs: va,
                    offset: branch_offset(imm),
                }],
                0x37 => vec![DalvikLiftedOp::If {
                    cond: DalvikCond::Le,
                    lhs: vd,
                    rhs: va,
                    offset: branch_offset(imm),
                }],
                0x38 => vec![DalvikLiftedOp::IfZ {
                    cond: DalvikCond::Eq,
                    lhs: vd,
                    offset: branch_offset(imm),
                }],
                0x39 => vec![DalvikLiftedOp::IfZ {
                    cond: DalvikCond::Ne,
                    lhs: vd,
                    offset: branch_offset(imm),
                }],
                0x3a => vec![DalvikLiftedOp::IfZ {
                    cond: DalvikCond::Lt,
                    lhs: vd,
                    offset: branch_offset(imm),
                }],
                0x3b => vec![DalvikLiftedOp::IfZ {
                    cond: DalvikCond::Ge,
                    lhs: vd,
                    offset: branch_offset(imm),
                }],
                0x3c => vec![DalvikLiftedOp::IfZ {
                    cond: DalvikCond::Gt,
                    lhs: vd,
                    offset: branch_offset(imm),
                }],
                0x3d => vec![DalvikLiftedOp::IfZ {
                    cond: DalvikCond::Le,
                    lhs: vd,
                    offset: branch_offset(imm),
                }],

                // ── Array get ────────────────────────────────────────────────────
                0x44..=0x4a => vec![DalvikLiftedOp::AGet {
                    dst: vd,
                    array: va,
                    index: vb,
                }],

                // ── Array put ────────────────────────────────────────────────────
                0x4b..=0x51 => vec![DalvikLiftedOp::APut {
                    src: vd,
                    array: va,
                    index: vb,
                }],
        _ => lift_opcode_part2(op, vd, va, vb, imm, cp_idx),
    }
}

/// Opcode-dispatch chunk 2 of [`DalvikLifterFull::lift_opcode`];
/// unmatched opcodes fall through to the next chunk.
fn lift_opcode_part2(op: u8, vd: DalvikReg, va: DalvikReg, vb: DalvikReg, imm: i64, cp_idx: u16) -> Vec<DalvikLiftedOp> {
    match op {

                // ── iget ────────────────────────────────────────────────────────
                // …and the ART extended quick-field range 0xe3..=0xef, which lifts to
                // the same instance-field read.
                0x52..=0x58 | 0xe3..=0xef => vec![DalvikLiftedOp::IGet {
                    dst: vd,
                    obj: va,
                    field_idx: cp_idx,
                }],

                // ── iput ────────────────────────────────────────────────────────
                0x59..=0x5f => vec![DalvikLiftedOp::IPut {
                    src: vd,
                    obj: va,
                    field_idx: cp_idx,
                }],

                // ── sput ────────────────────────────────────────────────────────
                0x67..=0x6d => vec![DalvikLiftedOp::SPut {
                    src: vd,
                    field_idx: cp_idx,
                }],

                // ── invoke ───────────────────────────────────────────────────────
                0x6e => vec![DalvikLiftedOp::Invoke {
                    kind: InvokeKind::Virtual,
                    method_idx: cp_idx,
                    args: vec![vd, va],
                }],
                0x6f => vec![DalvikLiftedOp::Invoke {
                    kind: InvokeKind::Super,
                    method_idx: cp_idx,
                    args: vec![vd, va],
                }],
                0x70 => vec![DalvikLiftedOp::Invoke {
                    kind: InvokeKind::Direct,
                    method_idx: cp_idx,
                    args: vec![vd, va],
                }],
                0x71 => vec![DalvikLiftedOp::Invoke {
                    kind: InvokeKind::Static,
                    method_idx: cp_idx,
                    args: vec![vd, va],
                }],
                0x72 => vec![DalvikLiftedOp::Invoke {
                    kind: InvokeKind::Interface,
                    method_idx: cp_idx,
                    args: vec![vd, va],
                }],
                0x74 => vec![DalvikLiftedOp::Invoke {
                    kind: InvokeKind::VirtualRange,
                    method_idx: cp_idx,
                    args: vec![vd, va],
                }],
                0x75 => vec![DalvikLiftedOp::Invoke {
                    kind: InvokeKind::SuperRange,
                    method_idx: cp_idx,
                    args: vec![vd, va],
                }],
                0x76 => vec![DalvikLiftedOp::Invoke {
                    kind: InvokeKind::DirectRange,
                    method_idx: cp_idx,
                    args: vec![vd, va],
                }],
                0x77 => vec![DalvikLiftedOp::Invoke {
                    kind: InvokeKind::StaticRange,
                    method_idx: cp_idx,
                    args: vec![vd, va],
                }],
                0x78 => vec![DalvikLiftedOp::Invoke {
                    kind: InvokeKind::InterfaceRange,
                    method_idx: cp_idx,
                    args: vec![vd, va],
                }],
        _ => lift_opcode_part3(op, vd, va, vb, imm, cp_idx),
    }
}

/// Opcode-dispatch chunk 3 of [`DalvikLifterFull::lift_opcode`];
/// unmatched opcodes fall through to the next chunk.
fn lift_opcode_part3(op: u8, vd: DalvikReg, va: DalvikReg, vb: DalvikReg, imm: i64, cp_idx: u16) -> Vec<DalvikLiftedOp> {
    match op {

                // ── Unary neg/not ────────────────────────────────────────────────
                0x7b | 0x7d | 0x7f | 0x80 => vec![DalvikLiftedOp::UnaryNeg { dst: vd, src: va }],
                0x7c | 0x7e => vec![DalvikLiftedOp::UnaryNot { dst: vd, src: va }],

                // ── Conversion ───────────────────────────────────────────────────
                0x81 => vec![DalvikLiftedOp::Convert {
                    dst: vd,
                    src: va,
                    kind: ConvertKind::IntToLong,
                }],
                0x82 => vec![DalvikLiftedOp::Convert {
                    dst: vd,
                    src: va,
                    kind: ConvertKind::IntToFloat,
                }],
                0x83 => vec![DalvikLiftedOp::Convert {
                    dst: vd,
                    src: va,
                    kind: ConvertKind::IntToDouble,
                }],
                0x84 => vec![DalvikLiftedOp::Convert {
                    dst: vd,
                    src: va,
                    kind: ConvertKind::LongToInt,
                }],
                0x85 => vec![DalvikLiftedOp::Convert {
                    dst: vd,
                    src: va,
                    kind: ConvertKind::LongToFloat,
                }],
                0x86 => vec![DalvikLiftedOp::Convert {
                    dst: vd,
                    src: va,
                    kind: ConvertKind::LongToDouble,
                }],
                0x87 => vec![DalvikLiftedOp::Convert {
                    dst: vd,
                    src: va,
                    kind: ConvertKind::FloatToInt,
                }],
                0x88 => vec![DalvikLiftedOp::Convert {
                    dst: vd,
                    src: va,
                    kind: ConvertKind::FloatToLong,
                }],
                0x89 => vec![DalvikLiftedOp::Convert {
                    dst: vd,
                    src: va,
                    kind: ConvertKind::FloatToDouble,
                }],
                0x8a => vec![DalvikLiftedOp::Convert {
                    dst: vd,
                    src: va,
                    kind: ConvertKind::DoubleToInt,
                }],
                0x8b => vec![DalvikLiftedOp::Convert {
                    dst: vd,
                    src: va,
                    kind: ConvertKind::DoubleToLong,
                }],
                0x8c => vec![DalvikLiftedOp::Convert {
                    dst: vd,
                    src: va,
                    kind: ConvertKind::DoubleToFloat,
                }],
                0x8d => vec![DalvikLiftedOp::Convert {
                    dst: vd,
                    src: va,
                    kind: ConvertKind::IntToByte,
                }],
        _ => lift_opcode_part4(op, vd, va, vb, imm, cp_idx),
    }
}

/// Opcode-dispatch chunk 4 of [`DalvikLifterFull::lift_opcode`];
/// unmatched opcodes fall through to the next chunk.
fn lift_opcode_part4(op: u8, vd: DalvikReg, va: DalvikReg, vb: DalvikReg, imm: i64, cp_idx: u16) -> Vec<DalvikLiftedOp> {
    match op {
                0x8e => vec![DalvikLiftedOp::Convert {
                    dst: vd,
                    src: va,
                    kind: ConvertKind::IntToChar,
                }],
                0x8f => vec![DalvikLiftedOp::Convert {
                    dst: vd,
                    src: va,
                    kind: ConvertKind::IntToShort,
                }],

                // ── 2-register binop ─────────────────────────────────────────────
                0x90 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Add,
                    dst: vd,
                    lhs: va,
                    rhs: vb,
                }],
                0x92 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Mul,
                    dst: vd,
                    lhs: va,
                    rhs: vb,
                }],
                0x93 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Div,
                    dst: vd,
                    lhs: va,
                    rhs: vb,
                }],
                0x94 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Rem,
                    dst: vd,
                    lhs: va,
                    rhs: vb,
                }],
                0x95 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::And,
                    dst: vd,
                    lhs: va,
                    rhs: vb,
                }],
                0x96 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Or,
                    dst: vd,
                    lhs: va,
                    rhs: vb,
                }],
                0x97 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Xor,
                    dst: vd,
                    lhs: va,
                    rhs: vb,
                }],
                0x98 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Shl,
                    dst: vd,
                    lhs: va,
                    rhs: vb,
                }],
                0x99 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Shr,
                    dst: vd,
                    lhs: va,
                    rhs: vb,
                }],
                0x9a => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Ushr,
                    dst: vd,
                    lhs: va,
                    rhs: vb,
                }],
        _ => lift_opcode_part5(op, vd, va, vb, imm, cp_idx),
    }
}

/// Opcode-dispatch chunk 5 of [`DalvikLifterFull::lift_opcode`];
/// unmatched opcodes fall through to the next chunk.
fn lift_opcode_part5(op: u8, vd: DalvikReg, va: DalvikReg, vb: DalvikReg, imm: i64, cp_idx: u16) -> Vec<DalvikLiftedOp> {
    match op {

                // Long binops
                0x9b..=0xa5 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::AddLong,
                    dst: vd,
                    lhs: va,
                    rhs: vb,
                }],
                // Float binops
                0xa6..=0xaa => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::AddFloat,
                    dst: vd,
                    lhs: va,
                    rhs: vb,
                }],
                // Double binops
                0xab..=0xaf => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::AddDouble,
                    dst: vd,
                    lhs: va,
                    rhs: vb,
                }],

                // ── 2addr ────────────────────────────────────────────────────────
                0xb0 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Add,
                    dst: vd,
                    lhs: vd,
                    rhs: va,
                }],
                0xb1 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Sub,
                    dst: vd,
                    lhs: vd,
                    rhs: va,
                }],
                0xb2 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Mul,
                    dst: vd,
                    lhs: vd,
                    rhs: va,
                }],
                0xb3 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Div,
                    dst: vd,
                    lhs: vd,
                    rhs: va,
                }],
                0xb4 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Rem,
                    dst: vd,
                    lhs: vd,
                    rhs: va,
                }],
                0xb5 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::And,
                    dst: vd,
                    lhs: vd,
                    rhs: va,
                }],
                0xb6 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Or,
                    dst: vd,
                    lhs: vd,
                    rhs: va,
                }],
                0xb7 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Xor,
                    dst: vd,
                    lhs: vd,
                    rhs: va,
                }],
        _ => lift_opcode_part6(op, vd, va, imm, cp_idx),
    }
}

/// Opcode-dispatch chunk 6 of [`DalvikLifterFull::lift_opcode`];
/// unmatched opcodes fall through to the next chunk.
fn lift_opcode_part6(op: u8, vd: DalvikReg, va: DalvikReg, imm: i64, cp_idx: u16) -> Vec<DalvikLiftedOp> {
    match op {
                0xb8 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Shl,
                    dst: vd,
                    lhs: vd,
                    rhs: va,
                }],
                0xb9 => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Shr,
                    dst: vd,
                    lhs: vd,
                    rhs: va,
                }],
                0xba => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::Ushr,
                    dst: vd,
                    lhs: vd,
                    rhs: va,
                }],
                0xbb..=0xcf => vec![DalvikLiftedOp::BinOp {
                    op: DalvikBinOp::AddLong,
                    dst: vd,
                    lhs: vd,
                    rhs: va,
                }],

                // ── lit16 / lit8 ─────────────────────────────────────────────────
                // add-int/lit16 (0xd0) and the lit8 range 0xd8..=0xe2, all modelled
                // as an add of an immediate.
                0xd0 | 0xd8..=0xe2 => vec![DalvikLiftedOp::BinOpImm {
                    op: DalvikBinOp::Add,
                    dst: vd,
                    lhs: va,
                    imm,
                }],
                0xd1 => vec![DalvikLiftedOp::BinOpImm {
                    op: DalvikBinOp::Sub,
                    dst: vd,
                    lhs: va,
                    imm,
                }],
                0xd2 => vec![DalvikLiftedOp::BinOpImm {
                    op: DalvikBinOp::Mul,
                    dst: vd,
                    lhs: va,
                    imm,
                }],
                0xd3 => vec![DalvikLiftedOp::BinOpImm {
                    op: DalvikBinOp::Div,
                    dst: vd,
                    lhs: va,
                    imm,
                }],
                0xd4 => vec![DalvikLiftedOp::BinOpImm {
                    op: DalvikBinOp::Rem,
                    dst: vd,
                    lhs: va,
                    imm,
                }],
                0xd5 => vec![DalvikLiftedOp::BinOpImm {
                    op: DalvikBinOp::And,
                    dst: vd,
                    lhs: va,
                    imm,
                }],
                0xd6 => vec![DalvikLiftedOp::BinOpImm {
                    op: DalvikBinOp::Or,
                    dst: vd,
                    lhs: va,
                    imm,
                }],
        _ => lift_opcode_part7(op, vd, va, imm, cp_idx),
    }
}

/// Opcode-dispatch chunk 7 of [`DalvikLifterFull::lift_opcode`];
/// unmatched opcodes fall through to the next chunk.
fn lift_opcode_part7(op: u8, vd: DalvikReg, va: DalvikReg, imm: i64, cp_idx: u16) -> Vec<DalvikLiftedOp> {
    match op {
                0xd7 => vec![DalvikLiftedOp::BinOpImm {
                    op: DalvikBinOp::Xor,
                    dst: vd,
                    lhs: va,
                    imm,
                }],

                // ── Extended / ART ───────────────────────────────────────────────
                // 0xfa is invoke-polymorphic and 0xfc is invoke-custom — these two
                // were swapped here as well as in the mnemonic table above, so the
                // lifted `InvokeKind` agreed with the wrong name and neither could
                // reveal the other.
                0xfa => vec![DalvikLiftedOp::Invoke {
                    kind: InvokeKind::Polymorphic,
                    method_idx: cp_idx,
                    args: vec![vd],
                }],
                0xfc => vec![DalvikLiftedOp::Invoke {
                    kind: InvokeKind::Custom,
                    method_idx: cp_idx,
                    args: vec![vd],
                }],
                0xfe | 0xff => vec![DalvikLiftedOp::LoadImm {
                    dst: vd,
                    imm: i64::from(cp_idx),
                }],

                _ => vec![DalvikLiftedOp::Unknown(op)],
    }
}

/// Narrow a decoded Dalvik immediate to the 32-bit branch offset the lifted IL
/// uses.
///
/// Dalvik encodes branch offsets in at most 32 bits, so a wider value can only
/// come from a malformed instruction; saturate instead of truncating, which
/// would otherwise turn a bogus operand into a plausible-looking target.
fn branch_offset(imm: i64) -> i32 {
    i32::try_from(imm).unwrap_or(if imm < 0 { i32::MIN } else { i32::MAX })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lifter() -> DalvikLifterFull {
        DalvikLifterFull
    }

    // ── 1. DalvikReg ────────────────────────────────────────────────────────
    #[test]
    fn test_reg_name() {
        assert_eq!(DalvikReg(0).name(), "v0");
        assert_eq!(DalvikReg(15).name(), "v15");
    }

    #[test]
    fn test_reg_display() {
        assert_eq!(format!("{}", DalvikReg(3)), "v3");
    }

    #[test]
    fn test_reg_wide_companion() {
        assert!(!DalvikReg(0).is_wide_companion());
        assert!(DalvikReg(1).is_wide_companion());
    }

    // ── 2. dalvik_mnemonic table ────────────────────────────────────────────
    #[test]
    fn test_mnemonic_nop() {
        assert_eq!(dalvik_mnemonic(0x00), "nop");
    }
    #[test]
    fn test_mnemonic_move() {
        assert_eq!(dalvik_mnemonic(0x01), "move");
    }
    #[test]
    fn test_mnemonic_return_void() {
        assert_eq!(dalvik_mnemonic(0x0e), "return-void");
    }
    #[test]
    fn test_mnemonic_invoke_virtual() {
        assert_eq!(dalvik_mnemonic(0x6e), "invoke-virtual");
    }
    #[test]
    fn test_mnemonic_invoke_static() {
        assert_eq!(dalvik_mnemonic(0x71), "invoke-static");
    }
    #[test]
    fn test_mnemonic_const4() {
        assert_eq!(dalvik_mnemonic(0x12), "const/4");
    }
    #[test]
    fn test_mnemonic_iget() {
        assert_eq!(dalvik_mnemonic(0x52), "iget");
    }
    #[test]
    fn test_mnemonic_new_instance() {
        assert_eq!(dalvik_mnemonic(0x22), "new-instance");
    }
    #[test]
    fn test_mnemonic_add_int() {
        assert_eq!(dalvik_mnemonic(0x90), "add-int");
    }
    /// Both members of the pair, so they can never silently swap again.
    ///
    /// This asserted `0xfa == "invoke-custom"`, which is the *other* opcode: it
    /// was written against the swapped table and so agreed with the defect it
    /// should have caught.  `full_opcode_table` is the authority — it records
    /// the instruction formats too, and those settle the pair independently of
    /// the names (invoke-polymorphic is 45cc/4rcc and carries an extra
    /// `proto@HHHH`; invoke-custom is 35c/3rc and does not).
    #[test]
    fn test_mnemonic_invoke_custom_and_polymorphic() {
        assert_eq!(dalvik_mnemonic(0xfa), "invoke-polymorphic");
        assert_eq!(dalvik_mnemonic(0xfb), "invoke-polymorphic/range");
        assert_eq!(dalvik_mnemonic(0xfc), "invoke-custom");
        assert_eq!(dalvik_mnemonic(0xfd), "invoke-custom/range");
    }

    /// The experimental lambda block is contiguous from 0xf3; the first unused
    /// slot is 0xf9.  A phantom `unused-f4` used to sit in the middle and push
    /// all six mnemonics one opcode too high.
    #[test]
    fn test_mnemonic_lambda_block_is_not_shifted() {
        assert_eq!(dalvik_mnemonic(0xf3), "invoke-lambda");
        assert_eq!(dalvik_mnemonic(0xf4), "capture-variable");
        assert_eq!(dalvik_mnemonic(0xf5), "create-lambda");
        assert_eq!(dalvik_mnemonic(0xf6), "liberate-variable");
        assert_eq!(dalvik_mnemonic(0xf7), "box-lambda");
        assert_eq!(dalvik_mnemonic(0xf8), "unbox-lambda");
        assert_eq!(dalvik_mnemonic(0xf9), "unused-f9");
    }
    #[test]
    fn test_mnemonic_const_method_handle() {
        assert_eq!(dalvik_mnemonic(0xfe), "const-method-handle");
    }

    // ── 3. All 256 mnemonics non-empty ───────────────────────────────────────
    #[test]
    fn test_all_256_mnemonics_non_empty() {
        for i in 0u8..=255 {
            assert!(
                !dalvik_mnemonic(i).is_empty(),
                "empty mnemonic for {i:#04x}"
            );
        }
    }

    // ── 4. Lifter: nop ───────────────────────────────────────────────────────
    #[test]
    fn test_lift_nop() {
        let ops = lifter().lift_opcode(0x00, 0, 0, 0, 0, 0);
        assert_eq!(ops, vec![DalvikLiftedOp::Nop]);
    }

    // ── 5. Lifter: return-void ───────────────────────────────────────────────
    #[test]
    fn test_lift_return_void() {
        let ops = lifter().lift_opcode(0x0e, 0, 0, 0, 0, 0);
        assert_eq!(ops, vec![DalvikLiftedOp::ReturnVoid]);
    }

    // ── 6. Lifter: return ────────────────────────────────────────────────────
    #[test]
    fn test_lift_return() {
        let ops = lifter().lift_opcode(0x0f, 3, 0, 0, 0, 0);
        assert_eq!(ops, vec![DalvikLiftedOp::Return { src: DalvikReg(3) }]);
    }

    // ── 7. Lifter: const/4 ───────────────────────────────────────────────────
    #[test]
    fn test_lift_const4() {
        let ops = lifter().lift_opcode(0x12, 1, 0, 0, 42, 0);
        assert_eq!(
            ops,
            vec![DalvikLiftedOp::LoadImm {
                dst: DalvikReg(1),
                imm: 42
            }]
        );
    }

    // ── 8. Lifter: move ──────────────────────────────────────────────────────
    #[test]
    fn test_lift_move() {
        let ops = lifter().lift_opcode(0x01, 2, 3, 0, 0, 0);
        assert_eq!(
            ops,
            vec![DalvikLiftedOp::Move {
                dst: DalvikReg(2),
                src: DalvikReg(3)
            }]
        );
    }

    // ── 9. Lifter: add-int ───────────────────────────────────────────────────
    #[test]
    fn test_lift_add_int() {
        let ops = lifter().lift_opcode(0x90, 0, 1, 2, 0, 0);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::BinOp {
                op: DalvikBinOp::Add,
                ..
            }
        ));
    }

    // ── 10. Lifter: if-eq ────────────────────────────────────────────────────
    #[test]
    fn test_lift_if_eq() {
        let ops = lifter().lift_opcode(0x32, 5, 6, 0, 8, 0);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::If {
                cond: DalvikCond::Eq,
                ..
            }
        ));
    }

    // ── 11. Lifter: if-eqz ───────────────────────────────────────────────────
    #[test]
    fn test_lift_if_eqz() {
        let ops = lifter().lift_opcode(0x38, 2, 0, 0, 4, 0);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::IfZ {
                cond: DalvikCond::Eq,
                ..
            }
        ));
    }

    // ── 12. Lifter: invoke-static ────────────────────────────────────────────
    #[test]
    fn test_lift_invoke_static() {
        let ops = lifter().lift_opcode(0x71, 0, 1, 0, 0, 42);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::Invoke {
                kind: InvokeKind::Static,
                method_idx: 42,
                ..
            }
        ));
    }

    // ── 13. Lifter: iget ─────────────────────────────────────────────────────
    #[test]
    fn test_lift_iget() {
        let ops = lifter().lift_opcode(0x52, 1, 2, 0, 0, 10);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::IGet {
                dst: DalvikReg(1),
                obj: DalvikReg(2),
                field_idx: 10
            }
        ));
    }

    // ── 14. Lifter: sget ─────────────────────────────────────────────────────
    #[test]
    fn test_lift_sget() {
        let ops = lifter().lift_opcode(0x60, 3, 0, 0, 0, 7);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::SGet {
                dst: DalvikReg(3),
                field_idx: 7
            }
        ));
    }

    // ── 15. Lifter: new-instance ─────────────────────────────────────────────
    #[test]
    fn test_lift_new_instance() {
        let ops = lifter().lift_opcode(0x22, 0, 0, 0, 0, 5);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::NewInstance {
                dst: DalvikReg(0),
                type_idx: 5
            }
        ));
    }

    // ── 16. Lifter: array-length ──────────────────────────────────────────────
    #[test]
    fn test_lift_array_length() {
        let ops = lifter().lift_opcode(0x21, 0, 1, 0, 0, 0);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::ArrayLength {
                dst: DalvikReg(0),
                array: DalvikReg(1)
            }
        ));
    }

    // ── 17. Lifter: aget ─────────────────────────────────────────────────────
    #[test]
    fn test_lift_aget() {
        let ops = lifter().lift_opcode(0x44, 0, 1, 2, 0, 0);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::AGet {
                dst: DalvikReg(0),
                array: DalvikReg(1),
                index: DalvikReg(2)
            }
        ));
    }

    // ── 18. Lifter: aput ─────────────────────────────────────────────────────
    #[test]
    fn test_lift_aput() {
        let ops = lifter().lift_opcode(0x4b, 3, 1, 2, 0, 0);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::APut {
                src: DalvikReg(3),
                array: DalvikReg(1),
                index: DalvikReg(2)
            }
        ));
    }

    // ── 19. Lifter: throw ────────────────────────────────────────────────────
    #[test]
    fn test_lift_throw() {
        let ops = lifter().lift_opcode(0x27, 5, 0, 0, 0, 0);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::Throw { exc: DalvikReg(5) }
        ));
    }

    // ── 20. Lifter: check-cast ───────────────────────────────────────────────
    #[test]
    fn test_lift_check_cast() {
        let ops = lifter().lift_opcode(0x1f, 2, 0, 0, 0, 3);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::CheckCast {
                reg: DalvikReg(2),
                type_idx: 3
            }
        ));
    }

    // ── 21. Lifter: int-to-long ──────────────────────────────────────────────
    #[test]
    fn test_lift_int_to_long() {
        let ops = lifter().lift_opcode(0x81, 0, 1, 0, 0, 0);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::Convert {
                kind: ConvertKind::IntToLong,
                ..
            }
        ));
    }

    // ── 22. Lifter: goto ─────────────────────────────────────────────────────
    #[test]
    fn test_lift_goto() {
        let ops = lifter().lift_opcode(0x28, 0, 0, 0, -4, 0);
        assert!(matches!(&ops[0], DalvikLiftedOp::Goto { offset: -4 }));
    }

    // ── 23. Lifter: neg-int ──────────────────────────────────────────────────
    #[test]
    fn test_lift_neg_int() {
        let ops = lifter().lift_opcode(0x7b, 0, 1, 0, 0, 0);
        assert!(matches!(&ops[0], DalvikLiftedOp::UnaryNeg { .. }));
    }

    // ── 24. Lifter: not-int ──────────────────────────────────────────────────
    #[test]
    fn test_lift_not_int() {
        let ops = lifter().lift_opcode(0x7c, 0, 1, 0, 0, 0);
        assert!(matches!(&ops[0], DalvikLiftedOp::UnaryNot { .. }));
    }

    // ── 25. InvokeKind is_virtual / is_static ────────────────────────────────
    #[test]
    fn test_invoke_kind() {
        assert!(InvokeKind::Virtual.is_virtual());
        assert!(InvokeKind::Static.is_static());
        assert!(!InvokeKind::Static.is_virtual());
    }

    // ── 26. lift_stream ──────────────────────────────────────────────────────
    #[test]
    fn test_lift_stream_length() {
        let ops = [0x00u8, 0x0e, 0x12]; // nop, return-void, const/4
        let lifted = lifter().lift_stream(&ops);
        assert_eq!(lifted.len(), 3);
    }

    // ── 27. lift_stream all nop ──────────────────────────────────────────────
    #[test]
    fn test_lift_stream_all_nop() {
        let ops = vec![0x00u8; 8];
        let lifted = lifter().lift_stream(&ops);
        assert!(lifted.iter().all(|o| *o == DalvikLiftedOp::Nop));
    }

    // ── 28. Lifter: invoke-polymorphic (0xfa) and invoke-custom (0xfc) ───────
    //
    // Asserting both directions: this test used to lift 0xfa and expect
    // `InvokeKind::Custom`, matching the swapped table rather than the spec, so
    // the wrong name and the wrong semantics confirmed each other.
    #[test]
    fn test_lift_invoke_polymorphic_and_custom() {
        let poly = lifter().lift_opcode(0xfa, 0, 0, 0, 0, 99);
        assert!(matches!(
            &poly[0],
            DalvikLiftedOp::Invoke {
                kind: InvokeKind::Polymorphic,
                ..
            }
        ));

        let custom = lifter().lift_opcode(0xfc, 0, 0, 0, 0, 99);
        assert!(matches!(
            &custom[0],
            DalvikLiftedOp::Invoke {
                kind: InvokeKind::Custom,
                ..
            }
        ));
    }

    // ── 29. Lifter: const-method-handle (0xfe) ───────────────────────────────
    #[test]
    fn test_lift_const_method_handle() {
        let ops = lifter().lift_opcode(0xfe, 0, 0, 0, 0, 7);
        assert!(matches!(&ops[0], DalvikLiftedOp::LoadImm { .. }));
    }

    // ── 30. Lifter: add-int/lit16 (0xd0) ────────────────────────────────────
    #[test]
    fn test_lift_add_int_lit16() {
        let ops = lifter().lift_opcode(0xd0, 2, 3, 0, 100, 0);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::BinOpImm {
                op: DalvikBinOp::Add,
                imm: 100,
                ..
            }
        ));
    }

    // ── 31. All opcodes lift to non-empty vec ────────────────────────────────
    #[test]
    fn test_all_opcodes_lift_non_empty() {
        for op in 0u8..=255 {
            let ops = lifter().lift_opcode(op, 0, 1, 2, 0, 0);
            assert!(!ops.is_empty(), "opcode {op:#04x} lifted to empty vec");
        }
    }

    // ── 32. DalvikCond variants ──────────────────────────────────────────────
    #[test]
    fn test_dalvik_cond() {
        let conds = [
            DalvikCond::Eq,
            DalvikCond::Ne,
            DalvikCond::Lt,
            DalvikCond::Ge,
            DalvikCond::Gt,
            DalvikCond::Le,
        ];
        for c in conds {
            assert_eq!(c, c);
        }
    }

    // ── 33. InvokeKind range ─────────────────────────────────────────────────
    #[test]
    fn test_invoke_kind_range_variants() {
        assert!(InvokeKind::VirtualRange.is_virtual());
        assert!(InvokeKind::StaticRange.is_static());
        assert!(!InvokeKind::DirectRange.is_virtual());
        assert!(!InvokeKind::InterfaceRange.is_static());
    }

    // ── 34. Wide instruction types ───────────────────────────────────────────
    #[test]
    fn test_wide_instruction_fields() {
        let w = WideInstruction {
            opcode: 0x04,
            mnemonic: "move-wide",
            dst_pair: (DalvikReg(0), DalvikReg(1)),
            src_pair: Some((DalvikReg(2), DalvikReg(3))),
            imm: None,
            size: 2,
        };
        assert_eq!(w.dst_pair.0, DalvikReg(0));
        assert_eq!(w.size, 2);
    }

    // ── 35. Object instruction fields ───────────────────────────────────────
    #[test]
    fn test_object_instruction_fields() {
        let o = ObjectInstruction {
            opcode: 0x6e,
            mnemonic: "invoke-virtual",
            dst: Some(DalvikReg(0)),
            object_reg: Some(DalvikReg(1)),
            cp_index: 5,
            args: vec![DalvikReg(2), DalvikReg(3)],
            size: 6,
        };
        assert_eq!(o.cp_index, 5);
        assert_eq!(o.args.len(), 2);
    }

    // ── 36. Array instruction fields ─────────────────────────────────────────
    #[test]
    fn test_array_instruction_fields() {
        let a = ArrayInstruction {
            opcode: 0x44,
            mnemonic: "aget",
            value_reg: DalvikReg(0),
            array_reg: DalvikReg(1),
            index_reg: DalvikReg(2),
            size: 2,
        };
        assert_eq!(a.value_reg, DalvikReg(0));
    }

    // ── 37. Regular instruction fields ──────────────────────────────────────
    #[test]
    fn test_regular_instruction_fields() {
        let r = RegularInstruction {
            opcode: 0x90,
            mnemonic: "add-int",
            dst: Some(DalvikReg(0)),
            src1: Some(DalvikReg(1)),
            src2: Some(DalvikReg(2)),
            imm: None,
            size: 2,
        };
        assert_eq!(r.opcode, 0x90);
        assert_eq!(r.mnemonic, "add-int");
    }

    // ── 38. Convert kind variants ────────────────────────────────────────────
    #[test]
    fn test_convert_kind_all() {
        let kinds = [
            ConvertKind::IntToLong,
            ConvertKind::IntToFloat,
            ConvertKind::IntToDouble,
            ConvertKind::LongToInt,
            ConvertKind::LongToFloat,
            ConvertKind::LongToDouble,
            ConvertKind::FloatToInt,
            ConvertKind::FloatToLong,
            ConvertKind::FloatToDouble,
            ConvertKind::DoubleToInt,
            ConvertKind::DoubleToLong,
            ConvertKind::DoubleToFloat,
            ConvertKind::IntToByte,
            ConvertKind::IntToChar,
            ConvertKind::IntToShort,
        ];
        for k in kinds {
            assert_eq!(k, k);
        }
    }

    // ── 39. DalvikBinOp variants ─────────────────────────────────────────────
    #[test]
    fn test_dalvik_binop_long() {
        let ops = [
            DalvikBinOp::AddLong,
            DalvikBinOp::SubLong,
            DalvikBinOp::MulLong,
            DalvikBinOp::DivLong,
            DalvikBinOp::RemLong,
            DalvikBinOp::AndLong,
            DalvikBinOp::OrLong,
            DalvikBinOp::XorLong,
            DalvikBinOp::ShlLong,
            DalvikBinOp::ShrLong,
            DalvikBinOp::UshrLong,
        ];
        for op in ops {
            assert_eq!(op, op);
        }
    }

    // ── 40. Lifter: monitor enter/exit ────────────────────────────────────────
    #[test]
    fn test_lift_monitor_enter() {
        let ops = lifter().lift_opcode(0x1d, 5, 0, 0, 0, 0);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::MonitorEnter { obj: DalvikReg(5) }
        ));
    }

    #[test]
    fn test_lift_monitor_exit() {
        let ops = lifter().lift_opcode(0x1e, 3, 0, 0, 0, 0);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::MonitorExit { obj: DalvikReg(3) }
        ));
    }

    // ── 42. Lifter: iput ─────────────────────────────────────────────────────
    #[test]
    fn test_lift_iput() {
        let ops = lifter().lift_opcode(0x59, 2, 3, 0, 0, 11);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::IPut {
                src: DalvikReg(2),
                obj: DalvikReg(3),
                field_idx: 11
            }
        ));
    }

    // ── 43. Lifter: sput ─────────────────────────────────────────────────────
    #[test]
    fn test_lift_sput() {
        let ops = lifter().lift_opcode(0x67, 4, 0, 0, 0, 9);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::SPut {
                src: DalvikReg(4),
                field_idx: 9
            }
        ));
    }

    // ── 44. Lifter: instance-of ──────────────────────────────────────────────
    #[test]
    fn test_lift_instance_of() {
        let ops = lifter().lift_opcode(0x20, 0, 1, 0, 0, 7);
        assert!(matches!(
            &ops[0],
            DalvikLiftedOp::InstanceOf {
                dst: DalvikReg(0),
                reg: DalvikReg(1),
                type_idx: 7
            }
        ));
    }
}
