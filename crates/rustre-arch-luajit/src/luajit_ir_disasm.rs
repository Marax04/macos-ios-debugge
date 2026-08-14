//! LuaJIT IR (intermediate representation) disassembler.
//!
//! Decodes the LuaJIT SSA IR used internally by the JIT compiler.
//! Each IR instruction has a fixed-width encoding with a reference number,
//! opcode, type tag, and two operand fields.

use std::fmt;
use std::collections::HashMap;

// ── IrType ────────────────────────────────────────────────────────────────────

/// `LuaJIT` IR value type tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IrType {
    Nil,
    Unk,
    Ldt,
    Udt,
    Blk,
    Bot,
    Void,
    Bool,
    Int,
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    U64,
    I64,
    F32,
    F64,
    Ptr,
    Func,
    P32,
    P64,
    Num,
}

impl IrType {
    /// Return the short textual abbreviation used in listings.
    #[must_use] 
    pub const fn abbrev(self) -> &'static str {
        match self {
            Self::Nil  => "nil",
            Self::Unk  => "unk",
            Self::Ldt  => "ldt",
            Self::Udt  => "udt",
            Self::Blk  => "blk",
            Self::Bot  => "bot",
            Self::Void => "voi",
            Self::Bool => "bol",
            Self::Int  => "int",
            Self::U8   => "u8 ",
            Self::I8   => "i8 ",
            Self::U16  => "u16",
            Self::I16  => "i16",
            Self::U32  => "u32",
            Self::I32  => "i32",
            Self::U64  => "u64",
            Self::I64  => "i64",
            Self::F32  => "f32",
            Self::F64  => "f64",
            Self::Ptr  => "ptr",
            Self::Func => "fun",
            Self::P32  => "p32",
            Self::P64  => "p64",
            Self::Num  => "num",
        }
    }

    /// Byte-width of the type (0 = opaque/variable).
    #[must_use] 
    pub const fn width(self) -> u8 {
        match self {
            Self::U8 | Self::I8 | Self::Bool => 1,
            Self::U16 | Self::I16 => 2,
            Self::U32 | Self::I32 | Self::F32 | Self::P32 => 4,
            Self::U64 | Self::I64 | Self::F64 | Self::P64 | Self::Ptr | Self::Num => 8,
            _ => 0,
        }
    }

    /// Return `true` if the type is an integer kind.
    #[must_use] 
    pub const fn is_integer(self) -> bool {
        matches!(
            self,
            Self::U8 | Self::I8 | Self::U16 | Self::I16
                | Self::U32 | Self::I32 | Self::U64 | Self::I64 | Self::Int
        )
    }

    /// Return `true` if the type is a floating-point kind.
    #[must_use] 
    pub const fn is_float(self) -> bool {
        matches!(self, Self::F32 | Self::F64 | Self::Num)
    }

    /// Return `true` if the type is a pointer kind.
    #[must_use] 
    pub const fn is_pointer(self) -> bool {
        matches!(self, Self::Ptr | Self::P32 | Self::P64 | Self::Func)
    }

    /// Decode from a raw 5-bit type field.
    #[must_use] 
    pub const fn from_u8(v: u8) -> Self {
        match v & 0x1F {
            0  => Self::Nil,
            1  => Self::Unk,
            2  => Self::Ldt,
            3  => Self::Udt,
            4  => Self::Blk,
            5  => Self::Bot,
            6  => Self::Void,
            7  => Self::Bool,
            8  => Self::Int,
            9  => Self::U8,
            10 => Self::I8,
            11 => Self::U16,
            12 => Self::I16,
            13 => Self::U32,
            14 => Self::I32,
            15 => Self::U64,
            16 => Self::I64,
            17 => Self::F32,
            18 => Self::F64,
            19 => Self::Ptr,
            20 => Self::Func,
            21 => Self::P32,
            22 => Self::P64,
            _  => Self::Num,
        }
    }
}

impl fmt::Display for IrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.abbrev())
    }
}

// ── IrOp ──────────────────────────────────────────────────────────────────────

/// All `LuaJIT` IR opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IrOp {
    Nop, Base, Pval, Kpri, Kint, Kgc, Kptr, Kkptr, Knull, Knum, Kint64, Kslot,
    Bnot, Bswap,
    Band, Bor, Bxor, Bshl, Bshr, Bsar, Brol, Bror,
    Add, Sub, Mul, Div, Mod, Pow, Neg, Abs, Atan2, Ldexp, Min, Max, Fpmath,
    Tonum, Toint, Tobit, Conv, Canfold,
    Loop, Use, Phi, Rename, Snap,
    Call, Calla, Calll, Calls, Callxs, Carg,
    Cnew, Cnewi,
    Aref, Hrefk, Href, Newref, Urefo, Urefc, Fref, Strref, Lref,
    Aload, Hload, Uload, Fload, Xload, Strto, Sload, Vload,
    Astore, Hstore, Ustore, Fstore, Xstore,
    Tbar, Obar,
    Itern, Isnext, Retf, Ret, Ret0, Ret1,
    Eq, Ne, Lt, Ge, Le, Gt, Ult, Uge, Ule, Ugt, Abc,
    Frame, LjAssert,
}

impl IrOp {
    /// Return the uppercase mnemonic string.
    #[must_use] 
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Nop => "NOP", Self::Base => "BASE", Self::Pval => "PVAL",
            Self::Kpri => "KPRI", Self::Kint => "KINT", Self::Kgc => "KGC",
            Self::Kptr => "KPTR", Self::Kkptr => "KKPTR", Self::Knull => "KNULL",
            Self::Knum => "KNUM", Self::Kint64 => "KINT64", Self::Kslot => "KSLOT",
            Self::Bnot => "BNOT", Self::Bswap => "BSWAP",
            Self::Band => "BAND", Self::Bor => "BOR", Self::Bxor => "BXOR",
            Self::Bshl => "BSHL", Self::Bshr => "BSHR", Self::Bsar => "BSAR",
            Self::Brol => "BROL", Self::Bror => "BROR",
            Self::Add => "ADD", Self::Sub => "SUB", Self::Mul => "MUL",
            Self::Div => "DIV", Self::Mod => "MOD", Self::Pow => "POW",
            Self::Neg => "NEG", Self::Abs => "ABS", Self::Atan2 => "ATAN2",
            Self::Ldexp => "LDEXP", Self::Min => "MIN", Self::Max => "MAX",
            Self::Fpmath => "FPMATH",
            Self::Tonum => "TONUM", Self::Toint => "TOINT", Self::Tobit => "TOBIT",
            Self::Conv => "CONV", Self::Canfold => "CANFOLD",
            Self::Loop => "LOOP", Self::Use => "USE", Self::Phi => "PHI",
            Self::Rename => "RENAME", Self::Snap => "SNAP",
            Self::Call => "CALL", Self::Calla => "CALLA", Self::Calll => "CALLL",
            Self::Calls => "CALLS", Self::Callxs => "CALLXS", Self::Carg => "CARG",
            Self::Cnew => "CNEW", Self::Cnewi => "CNEWI",
            Self::Aref => "AREF", Self::Hrefk => "HREFK", Self::Href => "HREF",
            Self::Newref => "NEWREF", Self::Urefo => "UREFO", Self::Urefc => "UREFC",
            Self::Fref => "FREF", Self::Strref => "STRREF", Self::Lref => "LREF",
            Self::Aload => "ALOAD", Self::Hload => "HLOAD", Self::Uload => "ULOAD",
            Self::Fload => "FLOAD", Self::Xload => "XLOAD", Self::Strto => "STRTO",
            Self::Sload => "SLOAD", Self::Vload => "VLOAD",
            Self::Astore => "ASTORE", Self::Hstore => "HSTORE",
            Self::Ustore => "USTORE", Self::Fstore => "FSTORE",
            Self::Xstore => "XSTORE",
            Self::Tbar => "TBAR", Self::Obar => "OBAR",
            Self::Itern => "ITERN", Self::Isnext => "ISNEXT",
            Self::Retf => "RETF", Self::Ret => "RET",
            Self::Ret0 => "RET0", Self::Ret1 => "RET1",
            Self::Eq => "EQ", Self::Ne => "NE", Self::Lt => "LT",
            Self::Ge => "GE", Self::Le => "LE", Self::Gt => "GT",
            Self::Ult => "ULT", Self::Uge => "UGE", Self::Ule => "ULE",
            Self::Ugt => "UGT", Self::Abc => "ABC",
            Self::Frame => "FRAME", Self::LjAssert => "LJ_ASSERT",
        }
    }

    /// Return `true` if this is a constant-load opcode.
    #[must_use] 
    pub const fn is_const(self) -> bool {
        matches!(
            self,
            Self::Kpri | Self::Kint | Self::Kgc | Self::Kptr | Self::Kkptr
                | Self::Knull | Self::Knum | Self::Kint64 | Self::Kslot
        )
    }

    /// Return `true` if this opcode is a comparison (may feed a guard).
    #[must_use] 
    pub const fn is_comparison(self) -> bool {
        matches!(
            self,
            Self::Eq | Self::Ne | Self::Lt | Self::Ge | Self::Le
                | Self::Gt | Self::Ult | Self::Uge | Self::Ule | Self::Ugt | Self::Abc
        )
    }

    /// Return `true` if this opcode is a memory load.
    #[must_use] 
    pub const fn is_load(self) -> bool {
        matches!(
            self,
            Self::Aload | Self::Hload | Self::Uload | Self::Fload
                | Self::Xload | Self::Strto | Self::Sload | Self::Vload
        )
    }

    /// Return `true` if this opcode is a memory store.
    #[must_use] 
    pub const fn is_store(self) -> bool {
        matches!(
            self,
            Self::Astore | Self::Hstore | Self::Ustore | Self::Fstore | Self::Xstore
        )
    }

    /// Return `true` if this opcode has a side-effect (store, call, barrier, ret).
    #[must_use] 
    pub const fn has_side_effect(self) -> bool {
        self.is_store()
            || matches!(
                self,
                Self::Call | Self::Calla | Self::Calll | Self::Calls | Self::Callxs
                    | Self::Tbar | Self::Obar | Self::Cnew | Self::Cnewi
                    | Self::Ret | Self::Ret0 | Self::Ret1 | Self::Retf
            )
    }

    /// Decode from a u16 raw opcode value.
    #[must_use] 
    pub const fn from_u16(v: u16) -> Self {
        // Maintain a flat sequential mapping so decode is a single match.
        match v {
            1  => Self::Base,  2  => Self::Pval,
            3  => Self::Kpri,  4  => Self::Kint,  5  => Self::Kgc,
            6  => Self::Kptr,  7  => Self::Kkptr, 8  => Self::Knull,
            9  => Self::Knum,  10 => Self::Kint64,11 => Self::Kslot,
            12 => Self::Bnot,  13 => Self::Bswap,
            14 => Self::Band,  15 => Self::Bor,   16 => Self::Bxor,
            17 => Self::Bshl,  18 => Self::Bshr,  19 => Self::Bsar,
            20 => Self::Brol,  21 => Self::Bror,
            22 => Self::Add,   23 => Self::Sub,   24 => Self::Mul,
            25 => Self::Div,   26 => Self::Mod,   27 => Self::Pow,
            28 => Self::Neg,   29 => Self::Abs,   30 => Self::Atan2,
            31 => Self::Ldexp, 32 => Self::Min,   33 => Self::Max,
            34 => Self::Fpmath,
            35 => Self::Tonum, 36 => Self::Toint, 37 => Self::Tobit,
            38 => Self::Conv,  39 => Self::Canfold,
            40 => Self::Loop,  41 => Self::Use,   42 => Self::Phi,
            43 => Self::Rename,44 => Self::Snap,
            45 => Self::Call,  46 => Self::Calla, 47 => Self::Calll,
            48 => Self::Calls, 49 => Self::Callxs,50 => Self::Carg,
            51 => Self::Cnew,  52 => Self::Cnewi,
            53 => Self::Aref,  54 => Self::Hrefk, 55 => Self::Href,
            56 => Self::Newref,57 => Self::Urefo, 58 => Self::Urefc,
            59 => Self::Fref,  60 => Self::Strref,61 => Self::Lref,
            62 => Self::Aload, 63 => Self::Hload, 64 => Self::Uload,
            65 => Self::Fload, 66 => Self::Xload, 67 => Self::Strto,
            68 => Self::Sload, 69 => Self::Vload,
            70 => Self::Astore,71 => Self::Hstore,72 => Self::Ustore,
            73 => Self::Fstore,74 => Self::Xstore,
            75 => Self::Tbar,  76 => Self::Obar,
            77 => Self::Itern, 78 => Self::Isnext,
            79 => Self::Retf,  80 => Self::Ret,   81 => Self::Ret0,
            82 => Self::Ret1,
            83 => Self::Eq,    84 => Self::Ne,    85 => Self::Lt,
            86 => Self::Ge,    87 => Self::Le,    88 => Self::Gt,
            89 => Self::Ult,   90 => Self::Uge,   91 => Self::Ule,
            92 => Self::Ugt,   93 => Self::Abc,
            94 => Self::Frame, 95 => Self::LjAssert,
            _  => Self::Nop,
        }
    }
}

impl fmt::Display for IrOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.mnemonic())
    }
}

// ── IrInsn ────────────────────────────────────────────────────────────────────

/// A single decoded `LuaJIT` IR instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrInsn {
    /// SSA reference number for this instruction (e.g. 0001..FFFF).
    pub ref_: u16,
    /// Opcode.
    pub op: IrOp,
    /// Result type tag.
    pub type_: IrType,
    /// First operand reference (or literal low half when `literal` is set).
    pub op1: u16,
    /// Second operand reference (or literal high half when `literal` is set).
    pub op2: u16,
    /// Optional literal constant (used by KINT, KNUM, etc.).
    pub literal: Option<i64>,
}

impl IrInsn {
    /// Create a new instruction with the given fields.
    #[must_use] 
    pub const fn new(ref_: u16, op: IrOp, type_: IrType, op1: u16, op2: u16) -> Self {
        Self { ref_, op, type_, op1, op2, literal: None }
    }

    /// Return `true` if both operands are valid SSA references (non-zero).
    #[must_use] 
    pub const fn has_two_operands(&self) -> bool {
        self.op1 != 0 && self.op2 != 0
    }

    /// Return `true` if the instruction produces a value that can be referenced.
    #[must_use] 
    pub const fn produces_value(&self) -> bool {
        !matches!(
            self.op,
            IrOp::Nop | IrOp::Snap | IrOp::Astore | IrOp::Hstore
                | IrOp::Ustore | IrOp::Fstore | IrOp::Xstore
                | IrOp::Tbar | IrOp::Obar | IrOp::Ret | IrOp::Ret0
                | IrOp::Ret1 | IrOp::Retf
        )
    }
}

impl fmt::Display for IrInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", LuaJitIrDisasm::format_insn(self))
    }
}

// ── LuaJitIrDisasm ────────────────────────────────────────────────────────────

/// `LuaJIT` IR disassembler / pretty-printer.
///
/// Decodes a stream of raw 64-bit IR instruction words and produces
/// annotated [`IrInsn`] values along with formatted listing output.
pub struct LuaJitIrDisasm {
    /// Decoded instructions in order.
    instructions: Vec<IrInsn>,
    /// Optional map from ref_ to human-readable annotation.
    annotations: HashMap<u16, String>,
}

impl LuaJitIrDisasm {
    /// Create a new, empty disassembler.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            annotations: HashMap::new(),
        }
    }

    /// Decode a slice of 8-byte IR words (little-endian) and append to the
    /// instruction list.  The first instruction gets ref number `base_ref`.
    ///
    /// IR word layout (`LuaJIT` internal, little-endian u64):
    /// ```text
    /// bits 63-48: op2  (u16)
    /// bits 47-32: op1  (u16)
    /// bits 31-24: op   (u8)  — raw opcode
    /// bits 23-16: type (u8)  — raw type field
    /// bits 15-0:  ref_ (u16)
    /// ```
    /// # Panics
    /// Panics if the number of words exceeds `u16::MAX`.
    pub fn decode_words(&mut self, words: &[u64], base_ref: u16) {
        for (i, &w) in words.iter().enumerate() {
            let ref_  = base_ref.wrapping_add(u16::try_from(i).expect("IR word index fits in u16"));
            let raw_op   = ((w >> 24) & 0xFF) as u16;
            let raw_type = ((w >> 16) & 0xFF) as u8;
            let op1   = ((w >> 32) & 0xFFFF) as u16;
            let op2   = ((w >> 48) & 0xFFFF) as u16;
            let op    = IrOp::from_u16(raw_op);
            let type_ = IrType::from_u8(raw_type);
            let mut insn = IrInsn::new(ref_, op, type_, op1, op2);
            // For constant-loading ops, form literal from op1/op2.
            if op.is_const() {
                let lit = (i64::from(op2) << 16) | i64::from(op1);
                insn.literal = Some(lit);
            }
            self.instructions.push(insn);
        }
    }

    /// Decode from raw bytes (each 8-byte group is one IR word).
    pub fn decode_bytes(&mut self, bytes: &[u8], base_ref: u16) {
        let words: Vec<u64> = bytes
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
            .collect();
        self.decode_words(&words, base_ref);
    }

    /// Add a human-readable annotation for a reference number.
    pub fn annotate(&mut self, ref_: u16, text: impl Into<String>) {
        self.annotations.insert(ref_, text.into());
    }

    /// Return all decoded instructions.
    #[must_use] 
    pub fn instructions(&self) -> &[IrInsn] {
        &self.instructions
    }

    /// Return the instruction for a given ref number, or `None`.
    #[must_use] 
    pub fn by_ref(&self, ref_: u16) -> Option<&IrInsn> {
        self.instructions.iter().find(|i| i.ref_ == ref_)
    }

    /// Format a single instruction as a listing line.
    ///
    /// Output format:
    /// ```text
    /// ---- XXXX  type  MNEMONIC   op1  op2   ; annotation
    /// ```
    /// where `----` is a placeholder for the result when no value is produced,
    /// `XXXX` is the 4-digit hex ref number.
    #[must_use] 
    pub fn format_insn(insn: &IrInsn) -> String {
        let ref_col = if insn.produces_value() {
            format!("{:04X}", insn.ref_)
        } else {
            "----".to_string()
        };
        let op_col = format!("{:<10}", insn.op.mnemonic());
        let type_col = insn.type_.abbrev();
        let operands = Self::format_operands(insn);
        format!("{ref_col}  {type_col}  {op_col}  {operands}")
    }

    /// Format the instruction with annotation if available.
    #[must_use] 
    pub fn format_insn_annotated(&self, insn: &IrInsn) -> String {
        let base = Self::format_insn(insn);
        if let Some(ann) = self.annotations.get(&insn.ref_) {
            format!("{base}  ; {ann}")
        } else {
            base
        }
    }

    fn format_operands(insn: &IrInsn) -> String {
        if let Some(lit) = insn.literal {
            return format!("#{lit}");
        }
        match insn.op {
            IrOp::Nop | IrOp::Ret0 | IrOp::Tbar | IrOp::Obar | IrOp::Loop => String::new(),
            IrOp::Phi | IrOp::Rename
            | IrOp::Eq | IrOp::Ne | IrOp::Lt | IrOp::Ge | IrOp::Le
            | IrOp::Gt | IrOp::Ult | IrOp::Uge | IrOp::Ule | IrOp::Ugt => {
                format!("{:04X}  {:04X}", insn.op1, insn.op2)
            }
            IrOp::Snap => {
                format!("[#{}  {}]", insn.op1, insn.op2)
            }
            op if op.is_store() => {
                format!("[{:04X}] = {:04X}", insn.op1, insn.op2)
            }
            op if op.is_load() => {
                format!("[{:04X}]", insn.op1)
            }
            _ => {
                if insn.op2 != 0 {
                    format!("{:04X}  {:04X}", insn.op1, insn.op2)
                } else if insn.op1 != 0 {
                    format!("{:04X}", insn.op1)
                } else {
                    String::new()
                }
            }
        }
    }

    /// Generate a full listing of all decoded instructions.
    #[must_use] 
    pub fn listing(&self) -> String {
        self.instructions
            .iter()
            .map(|i| self.format_insn_annotated(i))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Count instructions by opcode.
    #[must_use] 
    pub fn opcode_histogram(&self) -> HashMap<IrOp, usize> {
        let mut map: HashMap<IrOp, usize> = HashMap::new();
        for insn in &self.instructions {
            *map.entry(insn.op).or_insert(0) += 1;
        }
        map
    }

    /// Return all instructions that are comparisons (potential guard sources).
    #[must_use] 
    pub fn comparison_insns(&self) -> Vec<&IrInsn> {
        self.instructions
            .iter()
            .filter(|i| i.op.is_comparison())
            .collect()
    }

    /// Return all store instructions.
    #[must_use] 
    pub fn store_insns(&self) -> Vec<&IrInsn> {
        self.instructions.iter().filter(|i| i.op.is_store()).collect()
    }

    /// Return all load instructions.
    #[must_use] 
    pub fn load_insns(&self) -> Vec<&IrInsn> {
        self.instructions.iter().filter(|i| i.op.is_load()).collect()
    }

    /// Return all call instructions.
    #[must_use] 
    pub fn call_insns(&self) -> Vec<&IrInsn> {
        self.instructions
            .iter()
            .filter(|i| {
                matches!(
                    i.op,
                    IrOp::Call | IrOp::Calla | IrOp::Calll | IrOp::Calls | IrOp::Callxs
                )
            })
            .collect()
    }

    /// Compute the use-def chain: for each ref, which instruction indices use it.
    #[must_use] 
    pub fn use_def_chain(&self) -> HashMap<u16, Vec<usize>> {
        let mut chain: HashMap<u16, Vec<usize>> = HashMap::new();
        for (idx, insn) in self.instructions.iter().enumerate() {
            if insn.op1 != 0 && insn.literal.is_none() {
                chain.entry(insn.op1).or_default().push(idx);
            }
            if insn.op2 != 0 && insn.literal.is_none() {
                chain.entry(insn.op2).or_default().push(idx);
            }
        }
        chain
    }

    /// Identify "hot" references — those used by 3 or more instructions.
    #[must_use] 
    pub fn hot_refs(&self) -> Vec<u16> {
        let chain = self.use_def_chain();
        let mut hot: Vec<u16> = chain
            .into_iter()
            .filter(|(_, uses)| uses.len() >= 3)
            .map(|(r, _)| r)
            .collect();
        hot.sort_unstable();
        hot
    }

    /// Count total instructions decoded.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Return `true` if no instructions have been decoded.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Clear all decoded instructions and annotations.
    pub fn clear(&mut self) {
        self.instructions.clear();
        self.annotations.clear();
    }
}

impl Default for LuaJitIrDisasm {
    fn default() -> Self {
        Self::new()
    }
}

// ── Formatting helpers ─────────────────────────────────────────────────────────

/// Build a synthetic IR instruction word from its fields (for testing).
#[must_use] 
pub fn make_ir_word(op: u16, type_: u8, op1: u16, op2: u16) -> u64 {
    let ref_part: u64 = 0; // ref is assigned externally
    let type_part: u64 = u64::from(type_) << 16;
    let op_part: u64   = u64::from(op) << 24;
    let arg1_part: u64  = u64::from(op1) << 32;
    let arg2_part: u64  = u64::from(op2) << 48;
    ref_part | type_part | op_part | arg1_part | arg2_part
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_disasm(words: &[u64]) -> LuaJitIrDisasm {
        let mut d = LuaJitIrDisasm::new();
        d.decode_words(words, 1);
        d
    }

    #[test]
    fn test_empty_disasm() {
        let d = LuaJitIrDisasm::new();
        assert!(d.is_empty());
        assert_eq!(d.len(), 0);
    }

    #[test]
    fn test_decode_single_add() {
        let w = make_ir_word(IrOp::Add as u16, IrType::F64 as u8, 0x0001, 0x0002);
        let d = make_disasm(&[w]);
        assert_eq!(d.len(), 1);
        let insn = &d.instructions()[0];
        assert_eq!(insn.op, IrOp::Add);
        assert_eq!(insn.type_, IrType::F64);
        assert_eq!(insn.op1, 0x0001);
        assert_eq!(insn.op2, 0x0002);
    }

    #[test]
    fn test_ref_numbering_starts_at_base() {
        let w0 = make_ir_word(IrOp::Kint as u16, IrType::Int as u8, 42, 0);
        let w1 = make_ir_word(IrOp::Add as u16, IrType::Int as u8, 0x0001, 0x0002);
        let d = make_disasm(&[w0, w1]);
        assert_eq!(d.instructions()[0].ref_, 1);
        assert_eq!(d.instructions()[1].ref_, 2);
    }

    #[test]
    fn test_kint_has_literal() {
        let w = make_ir_word(IrOp::Kint as u16, IrType::Int as u8, 100, 0);
        let d = make_disasm(&[w]);
        assert!(d.instructions()[0].literal.is_some());
    }

    #[test]
    fn test_op_is_const_recognition() {
        assert!(IrOp::Kint.is_const());
        assert!(IrOp::Knum.is_const());
        assert!(!IrOp::Add.is_const());
    }

    #[test]
    fn test_comparison_insns_filter() {
        let w_eq  = make_ir_word(IrOp::Eq as u16, IrType::Bool as u8, 1, 2);
        let w_add = make_ir_word(IrOp::Add as u16, IrType::F64 as u8, 3, 4);
        let w_lt  = make_ir_word(IrOp::Lt as u16, IrType::Bool as u8, 1, 2);
        let d = make_disasm(&[w_eq, w_add, w_lt]);
        let comps = d.comparison_insns();
        assert_eq!(comps.len(), 2);
    }

    #[test]
    fn test_store_and_load_filter() {
        let w_st = make_ir_word(IrOp::Astore as u16, IrType::Ptr as u8, 1, 2);
        let w_ld = make_ir_word(IrOp::Aload as u16, IrType::Num as u8, 3, 0);
        let w_nop = make_ir_word(IrOp::Nop as u16, IrType::Void as u8, 0, 0);
        let d = make_disasm(&[w_st, w_ld, w_nop]);
        assert_eq!(d.store_insns().len(), 1);
        assert_eq!(d.load_insns().len(), 1);
    }

    #[test]
    fn test_call_filter() {
        let w_call = make_ir_word(IrOp::Call as u16, IrType::Ptr as u8, 1, 2);
        let w_add  = make_ir_word(IrOp::Add as u16, IrType::F64 as u8, 1, 2);
        let d = make_disasm(&[w_call, w_add]);
        assert_eq!(d.call_insns().len(), 1);
    }

    #[test]
    fn test_produces_value_nop_false() {
        let w = make_ir_word(IrOp::Nop as u16, IrType::Void as u8, 0, 0);
        let d = make_disasm(&[w]);
        assert!(!d.instructions()[0].produces_value());
    }

    #[test]
    fn test_format_insn_contains_mnemonic() {
        let insn = IrInsn::new(0x0005, IrOp::Mul, IrType::F64, 2, 3);
        let s = LuaJitIrDisasm::format_insn(&insn);
        assert!(s.contains("MUL"));
    }

    #[test]
    fn test_annotation_appears_in_listing() {
        let w = make_ir_word(IrOp::Add as u16, IrType::F64 as u8, 1, 2);
        let mut d = make_disasm(&[w]);
        d.annotate(1, "result of loop add");
        let listing = d.listing();
        assert!(listing.contains("result of loop add"));
    }

    #[test]
    fn test_opcode_histogram() {
        let w1 = make_ir_word(IrOp::Add as u16, IrType::F64 as u8, 1, 2);
        let w2 = make_ir_word(IrOp::Add as u16, IrType::F64 as u8, 3, 4);
        let w3 = make_ir_word(IrOp::Mul as u16, IrType::F64 as u8, 1, 2);
        let d = make_disasm(&[w1, w2, w3]);
        let hist = d.opcode_histogram();
        assert_eq!(*hist.get(&IrOp::Add).unwrap(), 2);
        assert_eq!(*hist.get(&IrOp::Mul).unwrap(), 1);
    }

    #[test]
    fn test_use_def_chain() {
        // insn at ref=1 uses nothing; insn at ref=2 uses ref=1 twice
        let w1 = make_ir_word(IrOp::Kint as u16, IrType::Int as u8, 0, 0);
        let w2 = make_ir_word(IrOp::Add as u16, IrType::Int as u8, 1, 1);
        let d = make_disasm(&[w1, w2]);
        let chain = d.use_def_chain();
        // ref 1 used in index 1 (second instruction)
        assert!(chain.contains_key(&1));
        assert_eq!(chain[&1].len(), 2);
    }

    #[test]
    fn test_hot_refs_threshold() {
        // ref=1 used three times
        let w0 = make_ir_word(IrOp::Kint as u16, IrType::Int as u8, 0, 0);
        let w1 = make_ir_word(IrOp::Add as u16, IrType::Int as u8, 1, 1);
        let w2 = make_ir_word(IrOp::Sub as u16, IrType::Int as u8, 1, 2);
        let d = make_disasm(&[w0, w1, w2]);
        let hot = d.hot_refs();
        assert!(hot.contains(&1));
    }

    #[test]
    fn test_clear_resets_state() {
        let w = make_ir_word(IrOp::Add as u16, IrType::F64 as u8, 1, 2);
        let mut d = make_disasm(&[w]);
        d.annotate(1, "foo");
        d.clear();
        assert!(d.is_empty());
        assert!(d.by_ref(1).is_none());
    }

    #[test]
    fn test_ir_type_width() {
        assert_eq!(IrType::I32.width(), 4);
        assert_eq!(IrType::F64.width(), 8);
        assert_eq!(IrType::U8.width(), 1);
    }

    #[test]
    fn test_ir_type_categories() {
        assert!(IrType::I64.is_integer());
        assert!(IrType::F32.is_float());
        assert!(IrType::Ptr.is_pointer());
    }

    #[test]
    fn test_decode_bytes_roundtrip() {
        let w = make_ir_word(IrOp::Sub as u16, IrType::I32 as u8, 10, 20);
        let bytes: Vec<u8> = w.to_le_bytes().to_vec();
        let mut d = LuaJitIrDisasm::new();
        d.decode_bytes(&bytes, 1);
        assert_eq!(d.len(), 1);
        assert_eq!(d.instructions()[0].op, IrOp::Sub);
    }

    #[test]
    fn test_has_side_effect() {
        assert!(IrOp::Astore.has_side_effect());
        assert!(IrOp::Call.has_side_effect());
        assert!(!IrOp::Add.has_side_effect());
    }
}
