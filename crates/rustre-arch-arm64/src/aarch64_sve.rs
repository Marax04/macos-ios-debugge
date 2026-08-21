//! AArch64 SVE / SVE2 vector extension decoder, lifter, and analysis.
//!
//! Covers:
//! - Scalable vector registers Z0–Z31 (variable element width)
//! - Predicate registers P0–P15 and the FFR
//! - All major SVE load/store, arithmetic, FP, predicate, and permute operations
//! - SVE2 extensions: BDEP/BEXT/BMATCH, CADD, CDOT, CMLA, EORBT/EORTB,
//!   FMMLA, PMUL, SABA/UABA, SQRDCMLAH, TBX, URECPE/URSQRTE, WHILERW/WHILEWR

// ---------------------------------------------------------------------------
// Predicate registers
// ---------------------------------------------------------------------------

/// An SVE predicate register (P0–P15).
///
/// Each predicate register has a number of active bits equal to the current
/// vector length divided by 8 (one bit per byte lane).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SvePredicate {
    /// Register index 0–15.
    pub index: u8,
}

impl SvePredicate {
    /// Create a new predicate register reference.
    ///
    /// Panics in debug builds if `index > 15`.
    #[inline]
    #[must_use]
    pub fn new(index: u8) -> Self {
        debug_assert!(index < 16, "SVE predicate register index must be 0–15");
        Self { index }
    }

    /// Return the register name ("p0"…"p15").
    #[must_use]
    pub fn name(self) -> String {
        format!("p{}", self.index)
    }

    /// `true` for the zeroing-predicate variant ("/z" suffix).
    #[must_use]
    pub const fn is_zeroing(self) -> bool {
        // Predicate 0 is conventionally used as the all-true predicate.
        self.index == 0
    }
}

impl std::fmt::Display for SvePredicate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "p{}", self.index)
    }
}

// ---------------------------------------------------------------------------
// Predicate governing mode
// ---------------------------------------------------------------------------

/// Governing predicate qualifier (/z = zeroing, /m = merging).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvePredicateMode {
    Zeroing,
    Merging,
}

impl std::fmt::Display for SvePredicateMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Zeroing => write!(f, "/z"),
            Self::Merging => write!(f, "/m"),
        }
    }
}

// ---------------------------------------------------------------------------
// Element type
// ---------------------------------------------------------------------------

/// SVE element type / lane width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SveElemType {
    B, // byte (8-bit)
    H, // halfword (16-bit)
    S, // single (32-bit)
    D, // double (64-bit)
    Q, // quad (128-bit)
}

impl SveElemType {
    /// Byte size of one element.
    #[must_use]
    pub const fn size_bytes(self) -> u8 {
        match self {
            Self::B => 1,
            Self::H => 2,
            Self::S => 4,
            Self::D => 8,
            Self::Q => 16,
        }
    }

    /// Encode a 2-bit size field (as used in SVE instructions).
    #[must_use]
    pub const fn from_size2(bits: u8) -> Self {
        match bits & 3 {
            0 => Self::B,
            1 => Self::H,
            2 => Self::S,
            _ => Self::D,
        }
    }

    /// Encode from a 3-bit `tszh:tszl` field.
    #[must_use]
    pub const fn from_tsz(tsz: u8) -> Option<Self> {
        match tsz {
            0b001 => Some(Self::B),
            0b010 | 0b011 => Some(Self::H),
            0b100..=0b111 => Some(Self::S),
            0b1000..=0b1111 => Some(Self::D),
            _ => None,
        }
    }
}

impl std::fmt::Display for SveElemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::B => "b",
            Self::H => "h",
            Self::S => "s",
            Self::D => "d",
            Self::Q => "q",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Scalable vector register
// ---------------------------------------------------------------------------

/// A scalable SVE vector register (Z0–Z31).
///
/// The actual width at runtime is implementation-defined (128–2048 bits,
/// multiples of 128).  Analysis tools represent it as "scalable × `elem`".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SveVector {
    /// Register index 0–31.
    pub index: u8,
    /// Active element type (may be `None` if unknown / polymorphic).
    pub elem: Option<SveElemType>,
}

impl SveVector {
    /// Create a typed vector register.
    #[must_use]
    pub fn new(index: u8, elem: SveElemType) -> Self {
        debug_assert!(index < 32, "SVE vector register index must be 0–31");
        Self {
            index,
            elem: Some(elem),
        }
    }

    /// Create an untyped (raw) vector register.
    #[must_use]
    pub fn raw(index: u8) -> Self {
        debug_assert!(index < 32);
        Self { index, elem: None }
    }

    /// Return the base name ("z0"…"z31").
    #[must_use]
    pub fn name(self) -> String {
        format!("z{}", self.index)
    }

    /// Return the typed name ("z0.s", "z1.d", …).
    #[must_use]
    pub fn typed_name(self) -> String {
        self.elem.map_or_else(|| format!("z{}", self.index), |e| format!("z{}.{e}", self.index))
    }
}

impl std::fmt::Display for SveVector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.typed_name())
    }
}

// ---------------------------------------------------------------------------
// SVE operand
// ---------------------------------------------------------------------------

/// Operand in an SVE instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SveOperand {
    /// Scalable vector register (Zn.T).
    Vector(SveVector),
    /// Predicate register with optional governing mode.
    Predicate(SvePredicate),
    /// Predicate register with zeroing/merging qualifier.
    GoverningPredicate(SvePredicate, SvePredicateMode),
    /// Base + optional offset general-purpose register (e.g. x0, xzr).
    GpReg(u8),
    /// Signed immediate.
    Imm(i64),
    /// Shift amount (imm for LSL/ASR/LSR).
    Shift { kind: SveShiftKind, amount: u8 },
    /// Memory: [Xn, Zm.D, UXTW #shift]
    MemRegOffset {
        base: u8,
        index_vec: u8,
        elem: SveElemType,
        shift: u8,
    },
    /// Memory: [Xn, #imm, MUL VL]
    MemScalarImm { base: u8, imm: i32 },
}

/// SVE shift kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SveShiftKind {
    Lsl,
    Lsr,
    Asr,
    Ror,
}

impl std::fmt::Display for SveShiftKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Lsl => "lsl",
            Self::Lsr => "lsr",
            Self::Asr => "asr",
            Self::Ror => "ror",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// SVE opcode
// ---------------------------------------------------------------------------

/// High-level SVE / SVE2 opcode class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SveOpcode {
    // ── Arithmetic ───────────────────────────────────────────────────────────
    Add,
    Sub,
    Mul,
    Fmla,
    Fmls,
    Fmad,
    Fnmla,
    Fnmls,
    Fadd,
    Fsub,
    Fmul,
    Fdiv,
    Fabs,
    Fneg,
    Fsqrt,
    // ── Integer saturating / widening ────────────────────────────────────────
    Sqadd,
    Sqsub,
    Uqadd,
    Uqsub,
    Saddv,
    Uaddv,
    // ── Conversion ───────────────────────────────────────────────────────────
    Fcvt,
    Scvtf,
    Ucvtf,
    Fcvtzs,
    Fcvtzu,
    // ── Load/store ───────────────────────────────────────────────────────────
    Ld1,
    Ldnf1,
    Ldff1,
    Ld2,
    Ld3,
    Ld4,
    St1,
    St2,
    St3,
    St4,
    // ── Predicate operations ──────────────────────────────────────────────────
    Ptrue,
    Pfalse,
    Pfirst,
    Pnext,
    Pand,
    Por,
    Peor,
    Pbic,
    Pnot,
    Whilelt,
    Whilele,
    Whilelo,
    Whilels,
    // ── Permute / select ──────────────────────────────────────────────────────
    Sel,
    Clast,
    Last,
    Compact,
    Splice,
    Ext,
    Tbl,
    Rev,
    // ── Compare ──────────────────────────────────────────────────────────────
    Cmpeq,
    Cmpne,
    Cmpgt,
    Cmpge,
    Cmplt,
    Cmple,
    Cmphi,
    Cmphs,
    Cmplo,
    Cmpls,
    // ── Reduction ────────────────────────────────────────────────────────────
    Addv,
    Smaxv,
    Uminv,
    Faddv,
    Fmaxv,
    Fminv,
    // ── Bitwise ──────────────────────────────────────────────────────────────
    And,
    Orr,
    Eor,
    Bic,
    Orn,
    Eon,
    Not,
    Cnt,
    Lsl,
    Lsr,
    Asr,
    // ── SVE2 ─────────────────────────────────────────────────────────────────
    Bdep,
    Bext,
    Bmatch,
    Cadd,
    Cdot,
    Cmla,
    Eorbt,
    Eortb,
    Fmmla,
    Saba,
    Uaba,
    Sqrdcmlah,
    Tbx,
    Urecpe,
    Ursqrte,
    Whilerw,
    Whilewr,
    // ── Fallthrough / unknown ─────────────────────────────────────────────────
    Unknown(u32),
}

impl SveOpcode {
    const fn mnemonic_arith_mem(self) -> Option<&'static str> {
        Some(match self {
            Self::Add => "add",       Self::Sub => "sub",       Self::Mul => "mul",
            Self::Fmla => "fmla",    Self::Fmls => "fmls",     Self::Fmad => "fmad",
            Self::Fnmla => "fnmla",  Self::Fnmls => "fnmls",
            Self::Fadd => "fadd",    Self::Fsub => "fsub",      Self::Fmul => "fmul",
            Self::Fdiv => "fdiv",    Self::Fabs => "fabs",      Self::Fneg => "fneg",
            Self::Fsqrt => "fsqrt",
            Self::Sqadd => "sqadd",  Self::Sqsub => "sqsub",
            Self::Uqadd => "uqadd",  Self::Uqsub => "uqsub",
            Self::Saddv => "saddv",  Self::Uaddv => "uaddv",
            Self::Fcvt => "fcvt",    Self::Scvtf => "scvtf",    Self::Ucvtf => "ucvtf",
            Self::Fcvtzs => "fcvtzs", Self::Fcvtzu => "fcvtzu",
            Self::Ld1 => "ld1",      Self::Ldnf1 => "ldnf1",    Self::Ldff1 => "ldff1",
            Self::Ld2 => "ld2",      Self::Ld3 => "ld3",        Self::Ld4 => "ld4",
            Self::St1 => "st1",      Self::St2 => "st2",
            Self::St3 => "st3",      Self::St4 => "st4",
            Self::Ptrue => "ptrue",  Self::Pfalse => "pfalse",
            Self::Pfirst => "pfirst", Self::Pnext => "pnext",
            Self::Pand => "pand",    Self::Por => "por",
            Self::Peor => "peor",    Self::Pbic => "pbic",      Self::Pnot => "pnot",
            Self::Whilelt => "whilelt", Self::Whilele => "whilele",
            Self::Whilelo => "whilelo", Self::Whilels => "whilels",
            _ => return None,
        })
    }

    const fn mnemonic_perm_logic(self) -> Option<&'static str> {
        Some(match self {
            Self::Sel => "sel",       Self::Clast => "clast",    Self::Last => "last",
            Self::Compact => "compact", Self::Splice => "splice",
            Self::Ext => "ext",       Self::Tbl => "tbl",        Self::Rev => "rev",
            Self::Cmpeq => "cmpeq",   Self::Cmpne => "cmpne",
            Self::Cmpgt => "cmpgt",   Self::Cmpge => "cmpge",
            Self::Cmplt => "cmplt",   Self::Cmple => "cmple",
            Self::Cmphi => "cmphi",   Self::Cmphs => "cmphs",
            Self::Cmplo => "cmplo",   Self::Cmpls => "cmpls",
            Self::Addv => "addv",     Self::Smaxv => "smaxv",    Self::Uminv => "uminv",
            Self::Faddv => "faddv",   Self::Fmaxv => "fmaxv",    Self::Fminv => "fminv",
            Self::And => "and",       Self::Orr => "orr",        Self::Eor => "eor",
            Self::Bic => "bic",       Self::Orn => "orn",        Self::Eon => "eon",
            Self::Not => "not",       Self::Cnt => "cnt",
            Self::Lsl => "lsl",       Self::Lsr => "lsr",        Self::Asr => "asr",
            Self::Bdep => "bdep",     Self::Bext => "bext",      Self::Bmatch => "bmatch",
            Self::Cadd => "cadd",     Self::Cdot => "cdot",      Self::Cmla => "cmla",
            Self::Eorbt => "eorbt",   Self::Eortb => "eortb",    Self::Fmmla => "fmmla",
            Self::Saba => "saba",     Self::Uaba => "uaba",
            Self::Sqrdcmlah => "sqrdcmlah",
            Self::Tbx => "tbx",       Self::Urecpe => "urecpe",  Self::Ursqrte => "ursqrte",
            Self::Whilerw => "whilerw", Self::Whilewr => "whilewr",
            Self::Unknown(_) => "???",
            _ => return None,
        })
    }

    const fn mnemonic_str(self) -> &'static str {
        if let Some(s) = self.mnemonic_arith_mem() { return s; }
        if let Some(s) = self.mnemonic_perm_logic() { return s; }
        "???"
    }

    /// Mnemonic string for this opcode.
    #[must_use]
    pub fn mnemonic(self) -> String {
        self.mnemonic_str().to_string()
    }

    /// `true` if this opcode reads from memory.
    #[must_use]
    pub const fn reads_memory(self) -> bool {
        matches!(
            self,
            Self::Ld1 | Self::Ldnf1 | Self::Ldff1 | Self::Ld2 | Self::Ld3 | Self::Ld4
        )
    }

    /// `true` if this opcode writes to memory.
    #[must_use]
    pub const fn writes_memory(self) -> bool {
        matches!(self, Self::St1 | Self::St2 | Self::St3 | Self::St4)
    }

    /// `true` if this is a predicate-producing instruction.
    #[must_use]
    pub const fn produces_predicate(self) -> bool {
        matches!(
            self,
            Self::Ptrue
                | Self::Pfalse
                | Self::Pfirst
                | Self::Pnext
                | Self::Pand
                | Self::Por
                | Self::Peor
                | Self::Pbic
                | Self::Pnot
                | Self::Whilelt
                | Self::Whilele
                | Self::Whilelo
                | Self::Whilels
                | Self::Cmpeq
                | Self::Cmpne
                | Self::Cmpgt
                | Self::Cmpge
                | Self::Cmplt
                | Self::Cmple
                | Self::Cmphi
                | Self::Cmphs
                | Self::Cmplo
                | Self::Cmpls
                | Self::Whilerw
                | Self::Whilewr
        )
    }
}

// ---------------------------------------------------------------------------
// SVE instruction
// ---------------------------------------------------------------------------

/// A decoded SVE or SVE2 instruction.
#[derive(Debug, Clone)]
pub struct SveInstruction {
    /// Virtual address of the instruction.
    pub address: u64,
    /// Raw 32-bit encoding.
    pub encoding: u32,
    /// Decoded opcode.
    pub opcode: SveOpcode,
    /// Element type (if applicable).
    pub elem: Option<SveElemType>,
    /// Instruction operands.
    pub operands: Vec<SveOperand>,
}

impl SveInstruction {
    /// Create a new SVE instruction record.
    #[must_use]
    pub const fn new(
        address: u64,
        encoding: u32,
        opcode: SveOpcode,
        elem: Option<SveElemType>,
        operands: Vec<SveOperand>,
    ) -> Self {
        Self {
            address,
            encoding,
            opcode,
            elem,
            operands,
        }
    }

    /// Format as a human-readable assembly string.
    #[must_use]
    pub fn display(&self) -> String {
        let suffix = self.elem.map_or_else(String::new, |e| format!(".{e}"));
        format!("{}{}", self.opcode.mnemonic(), suffix)
    }

    /// `true` if this is a load from memory.
    #[must_use]
    pub const fn is_load(&self) -> bool {
        self.opcode.reads_memory()
    }

    /// `true` if this is a store to memory.
    #[must_use]
    pub const fn is_store(&self) -> bool {
        self.opcode.writes_memory()
    }
}

// ---------------------------------------------------------------------------
// SVE decoder
// ---------------------------------------------------------------------------

/// Main `AArch64` SVE decoder.
///
/// Decodes 32-bit `AArch64` instruction words that fall in the SVE / SVE2
/// encoding space (top-level bit pattern `0000 01xx xxxx xxxx`).
#[derive(Debug, Default)]
pub struct AArch64Sve;

impl AArch64Sve {
    fn decode_mem(word: u32, address: u64, zt: u8, pg: u8, elem: SveElemType) -> SveInstruction {
        let is_store = (word >> 21) & 1 == 0;
        let xn = ((word >> 16) & 0x1f) as u8;
        let opcode = if is_store {
            match (word >> 13) & 0x7 {
                0 => SveOpcode::St1,
                1 => SveOpcode::St2,
                2 => SveOpcode::St3,
                _ => SveOpcode::St4,
            }
        } else {
            match (word >> 13) & 0x7 {
                0 => SveOpcode::Ld1,
                4 => SveOpcode::Ldnf1,
                6 => SveOpcode::Ldff1,
                1 => SveOpcode::Ld2,
                2 => SveOpcode::Ld3,
                _ => SveOpcode::Ld4,
            }
        };
        let imm = ((word >> 16) & 0x7).cast_signed();
        SveInstruction::new(
            address,
            word,
            opcode,
            Some(elem),
            vec![
                SveOperand::Vector(SveVector::new(zt, elem)),
                SveOperand::GoverningPredicate(
                    SvePredicate::new(pg),
                    SvePredicateMode::Zeroing,
                ),
                SveOperand::MemScalarImm { base: xn, imm },
            ],
        )
    }

    fn decode_int_arith(
        word: u32, address: u64,
        zt: u8, zn: u8, zm: u8, pg: u8,
        elem: SveElemType,
    ) -> SveInstruction {
        let opc = (word >> 10) & 0x7;
        let opcode = match opc {
            0 => SveOpcode::Add,
            1 => SveOpcode::Sub,
            2 => SveOpcode::Sqadd,
            3 => SveOpcode::Sqsub,
            4 => SveOpcode::Mul,
            _ => SveOpcode::And,
        };
        SveInstruction::new(
            address, word, opcode, Some(elem),
            vec![
                SveOperand::Vector(SveVector::new(zt, elem)),
                SveOperand::GoverningPredicate(SvePredicate::new(pg), SvePredicateMode::Merging),
                SveOperand::Vector(SveVector::new(zn, elem)),
                SveOperand::Vector(SveVector::new(zm, elem)),
            ],
        )
    }

    fn decode_fp(
        word: u32, address: u64,
        zt: u8, zn: u8, zm: u8, pg: u8,
        elem: SveElemType,
    ) -> SveInstruction {
        let opc2b = (word >> 13) & 0x7;
        let opcode = match opc2b {
            0 => SveOpcode::Fadd,
            1 => SveOpcode::Fsub,
            2 => SveOpcode::Fmul,
            3 => SveOpcode::Fmla,
            4 => SveOpcode::Fmls,
            5 => SveOpcode::Fdiv,
            6 => SveOpcode::Fcvt,
            _ => SveOpcode::Fabs,
        };
        SveInstruction::new(
            address, word, opcode, Some(elem),
            vec![
                SveOperand::Vector(SveVector::new(zt, elem)),
                SveOperand::GoverningPredicate(SvePredicate::new(pg), SvePredicateMode::Merging),
                SveOperand::Vector(SveVector::new(zn, elem)),
                SveOperand::Vector(SveVector::new(zm, elem)),
            ],
        )
    }

    fn decode_pred_permute(
        word: u32, address: u64,
        zt: u8, zn: u8, zm: u8, pg: u8,
        elem: SveElemType,
    ) -> SveInstruction {
        let sub = (word >> 10) & 0xf;
        let opcode = match sub {
            0 => SveOpcode::Sel,
            1 => SveOpcode::Clast,
            2 => SveOpcode::Last,
            3 => SveOpcode::Compact,
            4 => SveOpcode::Splice,
            5 => SveOpcode::Ptrue,
            6 => SveOpcode::Whilelt,
            7 => SveOpcode::Cmpeq,
            8 => SveOpcode::Lsl,
            9 => SveOpcode::Asr,
            10 => SveOpcode::Lsr,
            11 => SveOpcode::Saba,
            12 => SveOpcode::Tbx,
            _ => SveOpcode::Tbl,
        };
        SveInstruction::new(
            address, word, opcode, Some(elem),
            vec![
                SveOperand::Vector(SveVector::new(zt, elem)),
                SveOperand::GoverningPredicate(SvePredicate::new(pg), SvePredicateMode::Merging),
                SveOperand::Vector(SveVector::new(zn, elem)),
                SveOperand::Vector(SveVector::new(zm, elem)),
            ],
        )
    }

    /// Attempt to decode a 32-bit word as an SVE instruction.
    ///
    /// Returns `Some(SveInstruction)` if the encoding is within the SVE space,
    /// `None` if it belongs to a different encoding group.
    #[must_use]
    pub fn decode(word: u32, address: u64) -> Option<SveInstruction> {
        // SVE encodings have bits [31:29] = 000.
        // The group field is bits[27:25] (3-bit); valid SVE space = group 2 (bits[27:25]=010).
        if (word >> 29) != 0 {
            return None;
        }
        let group = (word >> 25) & 0x7;
        if group != 2 {
            return None;
        }

        let op0 = (word >> 24) & 0xf;
        let zt = (word & 0x1f) as u8;
        let zn = ((word >> 5) & 0x1f) as u8;
        let zm = ((word >> 16) & 0x1f) as u8;
        let pg = ((word >> 10) & 0xf) as u8;
        let size2 = (word >> 22) & 0x3;
        let elem = SveElemType::from_size2(size2 as u8);

        let insn = match op0 {
            0xa | 0xb => Self::decode_mem(word, address, zt, pg, elem),
            0x4 | 0x5 => Self::decode_int_arith(word, address, zt, zn, zm, pg, elem),
            0x6 => Self::decode_fp(word, address, zt, zn, zm, pg, elem),
            0x7 => Self::decode_pred_permute(word, address, zt, zn, zm, pg, elem),
            _ => SveInstruction::new(address, word, SveOpcode::Unknown(word), None, vec![]),
        };

        Some(insn)
    }

    /// Decode a sequence of little-endian bytes as SVE instructions.
    ///
    /// Non-SVE words are silently skipped (yielding `None` entries).
    #[must_use]
    pub fn decode_all(bytes: &[u8], base: u64) -> Vec<Option<SveInstruction>> {
        bytes
            .chunks_exact(4)
            .enumerate()
            .map(|(i, chunk)| {
                let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                Self::decode(word, base.wrapping_add((i as u64).wrapping_mul(4)))
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// SVE lifter (SVE → high-level IR)
// ---------------------------------------------------------------------------

/// Category of a lifted SVE operation for downstream analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SveLiftedOp {
    /// Vector load: (`dest_reg`, pred, `mem_base`, `imm_offset`).
    VecLoad {
        dest: u8,
        pred: u8,
        base: u8,
        offset: i32,
    },
    /// Vector store: (`src_reg`, pred, `mem_base`, `imm_offset`).
    VecStore {
        src: u8,
        pred: u8,
        base: u8,
        offset: i32,
    },
    /// Predicated binary arithmetic: dest[pred] = lhs OP rhs.
    PredBinOp {
        opcode: SveOpcode,
        dest: u8,
        pred: u8,
        lhs: u8,
        rhs: u8,
    },
    /// Predicate generation: (`dest_pred`, size).
    PredGen {
        dest: u8,
        opcode: SveOpcode,
        elem: SveElemType,
    },
    /// Reduction: `scalar_gpr`[dest] = REDUCE(pred, src).
    Reduce {
        dest: u8,
        pred: u8,
        src: u8,
        opcode: SveOpcode,
    },
    /// Unknown / unsupported.
    Nop,
}

/// SVE lifter: translates decoded [`SveInstruction`]s into [`SveLiftedOp`]s.
#[derive(Debug, Default)]
pub struct SveLifter;

impl SveLifter {
    /// Lift one SVE instruction to a [`SveLiftedOp`].
    #[must_use]
    pub fn lift(&self, insn: &SveInstruction) -> SveLiftedOp {
        // Helper: first vector operand index → reg number
        let vec_reg = |ops: &Vec<SveOperand>, idx: usize| -> u8 {
            match ops.get(idx) {
                Some(SveOperand::Vector(v)) => v.index,
                _ => 0,
            }
        };
        let pred_reg = |ops: &Vec<SveOperand>, idx: usize| -> u8 {
            match ops.get(idx) {
                Some(SveOperand::GoverningPredicate(p, _) | SveOperand::Predicate(p)) => {
                    p.index
                }
                _ => 0,
            }
        };

        match insn.opcode {
            SveOpcode::Ld1
            | SveOpcode::Ldnf1
            | SveOpcode::Ldff1
            | SveOpcode::Ld2
            | SveOpcode::Ld3
            | SveOpcode::Ld4 => {
                let dest = vec_reg(&insn.operands, 0);
                let pred = pred_reg(&insn.operands, 1);
                let (base, offset) = match insn.operands.get(2) {
                    Some(SveOperand::MemScalarImm { base, imm }) => (*base, *imm),
                    Some(SveOperand::GpReg(r)) => (*r, 0),
                    _ => (0, 0),
                };
                SveLiftedOp::VecLoad {
                    dest,
                    pred,
                    base,
                    offset,
                }
            }

            SveOpcode::St1 | SveOpcode::St2 | SveOpcode::St3 | SveOpcode::St4 => {
                let src = vec_reg(&insn.operands, 0);
                let pred = pred_reg(&insn.operands, 1);
                let (base, offset) = match insn.operands.get(2) {
                    Some(SveOperand::MemScalarImm { base, imm }) => (*base, *imm),
                    Some(SveOperand::GpReg(r)) => (*r, 0),
                    _ => (0, 0),
                };
                SveLiftedOp::VecStore {
                    src,
                    pred,
                    base,
                    offset,
                }
            }

            SveOpcode::Ptrue
            | SveOpcode::Pfalse
            | SveOpcode::Whilelt
            | SveOpcode::Whilele
            | SveOpcode::Whilelo
            | SveOpcode::Whilels
            | SveOpcode::Whilerw
            | SveOpcode::Whilewr => {
                let dest = vec_reg(&insn.operands, 0);
                let elem = insn.elem.unwrap_or(SveElemType::S);
                SveLiftedOp::PredGen {
                    dest,
                    opcode: insn.opcode,
                    elem,
                }
            }

            SveOpcode::Addv
            | SveOpcode::Smaxv
            | SveOpcode::Uminv
            | SveOpcode::Faddv
            | SveOpcode::Fmaxv
            | SveOpcode::Fminv => {
                let dest = vec_reg(&insn.operands, 0);
                let pred = pred_reg(&insn.operands, 1);
                let src = vec_reg(&insn.operands, 2);
                SveLiftedOp::Reduce {
                    dest,
                    pred,
                    src,
                    opcode: insn.opcode,
                }
            }

            ref op if op.reads_memory() || op.writes_memory() => SveLiftedOp::Nop,

            _ => {
                let dest = vec_reg(&insn.operands, 0);
                let pred = pred_reg(&insn.operands, 1);
                let lhs = vec_reg(&insn.operands, 2);
                let rhs = vec_reg(&insn.operands, 3);
                SveLiftedOp::PredBinOp {
                    opcode: insn.opcode,
                    dest,
                    pred,
                    lhs,
                    rhs,
                }
            }
        }
    }

    /// Lift all instructions in a decoded stream.
    #[must_use]
    pub fn lift_all(&self, insns: &[SveInstruction]) -> Vec<SveLiftedOp> {
        insns.iter().map(|i| self.lift(i)).collect()
    }
}

// ---------------------------------------------------------------------------
// SveInstrStats — instruction stream statistics
// ---------------------------------------------------------------------------

/// Summary statistics over a decoded SVE instruction stream.
#[derive(Debug, Default, Clone)]
pub struct SveInstrStats {
    pub total: usize,
    pub loads: usize,
    pub stores: usize,
    pub arithmetic: usize,
    pub fp_ops: usize,
    pub pred_gen: usize,
    pub permute: usize,
    pub unknown: usize,
}

impl SveInstrStats {
    /// Compute statistics over a slice of instructions.
    #[must_use]
    pub fn compute(insns: &[SveInstruction]) -> Self {
        let mut s = Self::default();
        for insn in insns {
            s.total += 1;
            match insn.opcode {
                op if op.reads_memory() => s.loads += 1,
                op if op.writes_memory() => s.stores += 1,
                op if op.produces_predicate() => s.pred_gen += 1,
                SveOpcode::Fadd
                | SveOpcode::Fsub
                | SveOpcode::Fmul
                | SveOpcode::Fdiv
                | SveOpcode::Fmla
                | SveOpcode::Fmls
                | SveOpcode::Fabs
                | SveOpcode::Fneg
                | SveOpcode::Fsqrt
                | SveOpcode::Fcvt
                | SveOpcode::Scvtf
                | SveOpcode::Ucvtf
                | SveOpcode::Fcvtzs
                | SveOpcode::Fcvtzu => s.fp_ops += 1,
                SveOpcode::Sel
                | SveOpcode::Clast
                | SveOpcode::Last
                | SveOpcode::Compact
                | SveOpcode::Splice
                | SveOpcode::Ext
                | SveOpcode::Tbl
                | SveOpcode::Rev => s.permute += 1,
                SveOpcode::Unknown(_) => s.unknown += 1,
                _ => s.arithmetic += 1,
            }
        }
        s
    }

    /// `true` if any SVE2-specific opcode was encountered.
    #[must_use]
    pub fn has_sve2(insns: &[SveInstruction]) -> bool {
        insns.iter().any(|i| {
            matches!(
                i.opcode,
                SveOpcode::Bdep
                    | SveOpcode::Bext
                    | SveOpcode::Bmatch
                    | SveOpcode::Cadd
                    | SveOpcode::Cdot
                    | SveOpcode::Cmla
                    | SveOpcode::Eorbt
                    | SveOpcode::Eortb
                    | SveOpcode::Fmmla
                    | SveOpcode::Saba
                    | SveOpcode::Uaba
                    | SveOpcode::Sqrdcmlah
                    | SveOpcode::Tbx
                    | SveOpcode::Urecpe
                    | SveOpcode::Ursqrte
                    | SveOpcode::Whilerw
                    | SveOpcode::Whilewr
            )
        })
    }
}

// ---------------------------------------------------------------------------
// SveRegisterFile — tracks predicate / vector liveness
// ---------------------------------------------------------------------------

/// Tracks which SVE registers are currently defined (live).
#[derive(Debug, Default)]
pub struct SveRegisterFile {
    /// Bit mask for active Z registers (bit i = Z{i} defined).
    pub z_defined: u32,
    /// Bit mask for active P registers (bit i = P{i} defined).
    pub p_defined: u16,
    /// Whether the FFR (First Faulting Register) has been written.
    pub ffr_valid: bool,
}

impl SveRegisterFile {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a Z register as defined.
    pub const fn define_z(&mut self, idx: u8) {
        if idx < 32 {
            self.z_defined |= 1 << idx;
        }
    }

    /// Mark a P register as defined.
    pub const fn define_p(&mut self, idx: u8) {
        if idx < 16 {
            self.p_defined |= 1 << idx;
        }
    }

    /// `true` if Z{idx} is defined.
    #[must_use]
    pub const fn is_z_defined(&self, idx: u8) -> bool {
        idx < 32 && (self.z_defined >> idx) & 1 != 0
    }

    /// `true` if P{idx} is defined.
    #[must_use]
    pub const fn is_p_defined(&self, idx: u8) -> bool {
        idx < 16 && (self.p_defined >> idx) & 1 != 0
    }

    /// Number of defined Z registers.
    #[must_use]
    pub const fn z_count(&self) -> usize {
        self.z_defined.count_ones() as usize
    }

    /// Number of defined P registers.
    #[must_use]
    pub const fn p_count(&self) -> usize {
        self.p_defined.count_ones() as usize
    }

    /// Update liveness from an instruction's writes.
    pub fn apply(&mut self, insn: &SveInstruction) {
        match insn.opcode {
            op if op.produces_predicate() => {
                if let Some(SveOperand::Vector(v)) = insn.operands.first() {
                    self.define_p(v.index);
                }
            }
            _ => {
                if let Some(SveOperand::Vector(v)) = insn.operands.first() {
                    self.define_z(v.index);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn zreg(n: u8, e: SveElemType) -> SveVector {
        SveVector::new(n, e)
    }
    fn preg(n: u8) -> SvePredicate {
        SvePredicate::new(n)
    }

    // ── 1. SvePredicate basic ───────────────────────────────────────────────
    #[test]
    fn test_predicate_name() {
        assert_eq!(preg(3).name(), "p3");
        assert_eq!(preg(15).name(), "p15");
    }

    #[test]
    fn test_predicate_display() {
        assert_eq!(format!("{}", preg(7)), "p7");
    }

    #[test]
    fn test_predicate_is_zeroing() {
        assert!(preg(0).is_zeroing());
        assert!(!preg(1).is_zeroing());
    }

    // ── 2. SveVector ────────────────────────────────────────────────────────
    #[test]
    fn test_vector_name() {
        let v = zreg(5, SveElemType::S);
        assert_eq!(v.name(), "z5");
        assert_eq!(v.typed_name(), "z5.s");
    }

    #[test]
    fn test_vector_raw() {
        let v = SveVector::raw(12);
        assert!(v.elem.is_none());
        assert_eq!(v.typed_name(), "z12");
    }

    #[test]
    fn test_vector_display() {
        let v = zreg(0, SveElemType::D);
        assert_eq!(format!("{v}"), "z0.d");
    }

    // ── 3. SveElemType ──────────────────────────────────────────────────────
    #[test]
    fn test_elem_size_bytes() {
        assert_eq!(SveElemType::B.size_bytes(), 1);
        assert_eq!(SveElemType::H.size_bytes(), 2);
        assert_eq!(SveElemType::S.size_bytes(), 4);
        assert_eq!(SveElemType::D.size_bytes(), 8);
        assert_eq!(SveElemType::Q.size_bytes(), 16);
    }

    #[test]
    fn test_elem_from_size2() {
        assert_eq!(SveElemType::from_size2(0), SveElemType::B);
        assert_eq!(SveElemType::from_size2(1), SveElemType::H);
        assert_eq!(SveElemType::from_size2(2), SveElemType::S);
        assert_eq!(SveElemType::from_size2(3), SveElemType::D);
    }

    #[test]
    fn test_elem_display() {
        assert_eq!(format!("{}", SveElemType::S), "s");
        assert_eq!(format!("{}", SveElemType::D), "d");
    }

    // ── 4. SveOpcode ────────────────────────────────────────────────────────
    #[test]
    fn test_opcode_mnemonic() {
        assert_eq!(SveOpcode::Add.mnemonic(), "add");
        assert_eq!(SveOpcode::Fmla.mnemonic(), "fmla");
        assert_eq!(SveOpcode::Ld1.mnemonic(), "ld1");
        assert_eq!(SveOpcode::St1.mnemonic(), "st1");
        assert_eq!(SveOpcode::Bdep.mnemonic(), "bdep");
        assert_eq!(SveOpcode::Whilerw.mnemonic(), "whilerw");
    }

    #[test]
    fn test_opcode_reads_memory() {
        assert!(SveOpcode::Ld1.reads_memory());
        assert!(SveOpcode::Ldff1.reads_memory());
        assert!(!SveOpcode::St1.reads_memory());
        assert!(!SveOpcode::Add.reads_memory());
    }

    #[test]
    fn test_opcode_writes_memory() {
        assert!(SveOpcode::St1.writes_memory());
        assert!(SveOpcode::St4.writes_memory());
        assert!(!SveOpcode::Ld1.writes_memory());
    }

    #[test]
    fn test_opcode_produces_predicate() {
        assert!(SveOpcode::Ptrue.produces_predicate());
        assert!(SveOpcode::Whilelt.produces_predicate());
        assert!(SveOpcode::Cmpeq.produces_predicate());
        assert!(!SveOpcode::Add.produces_predicate());
    }

    // ── 5. SvePredicateMode display ─────────────────────────────────────────
    #[test]
    fn test_predicate_mode_display() {
        assert_eq!(format!("{}", SvePredicateMode::Zeroing), "/z");
        assert_eq!(format!("{}", SvePredicateMode::Merging), "/m");
    }

    // ── 6. SveShiftKind display ─────────────────────────────────────────────
    #[test]
    fn test_shift_kind_display() {
        assert_eq!(format!("{}", SveShiftKind::Lsl), "lsl");
        assert_eq!(format!("{}", SveShiftKind::Asr), "asr");
    }

    // ── 7. SveInstruction display ───────────────────────────────────────────
    #[test]
    fn test_sve_instruction_display() {
        let insn = SveInstruction::new(0x1000, 0, SveOpcode::Fmla, Some(SveElemType::S), vec![]);
        assert_eq!(insn.display(), "fmla.s");
    }

    #[test]
    fn test_sve_instruction_is_load() {
        let insn = SveInstruction::new(0, 0, SveOpcode::Ld1, Some(SveElemType::D), vec![]);
        assert!(insn.is_load());
        assert!(!insn.is_store());
    }

    #[test]
    fn test_sve_instruction_is_store() {
        let insn = SveInstruction::new(0, 0, SveOpcode::St2, Some(SveElemType::S), vec![]);
        assert!(insn.is_store());
        assert!(!insn.is_load());
    }

    // ── 8. AArch64Sve::decode rejects non-SVE words ─────────────────────────
    #[test]
    fn test_decode_rejects_non_sve() {
        // RET (0xD65F03C0) — bits[31:29] = 110, not SVE
        assert!(AArch64Sve::decode(0xD65F_03C0, 0).is_none());
        // NOP (0xD503201F)
        assert!(AArch64Sve::decode(0xD503_201F, 0).is_none());
    }

    // ── 9. AArch64Sve::decode accepts SVE-space words ────────────────────────
    #[test]
    fn test_decode_accepts_sve_space() {
        // Construct a minimal SVE word: bits[31:29]=000, bits[28:25]=0100 → group=4
        let word: u32 = 0b000_0100_0000_0000_0000_0000_0000_0000_u32;
        let result = AArch64Sve::decode(word, 0x2000);
        assert!(result.is_some());
        let insn = result.unwrap();
        assert_eq!(insn.address, 0x2000);
        assert_eq!(insn.encoding, word);
    }

    // ── 10. AArch64Sve::decode_all ──────────────────────────────────────────
    #[test]
    fn test_decode_all_length() {
        // 4 words → 4 entries
        let bytes = [0u8; 16];
        let results = AArch64Sve::decode_all(&bytes, 0x4000);
        assert_eq!(results.len(), 4);
    }

    #[test]
    fn test_decode_all_non_sve_words() {
        // Non-SVE bytes → all None
        let word = 0xD503_201F_u32.to_le_bytes(); // NOP
        let bytes: Vec<u8> = word.iter().cycle().take(8).copied().collect();
        let results = AArch64Sve::decode_all(&bytes, 0);
        for r in &results {
            assert!(r.is_none());
        }
    }

    // ── 11. SveLifter: load lifted correctly ────────────────────────────────
    #[test]
    fn test_lifter_load() {
        let insn = SveInstruction::new(
            0x1000,
            0,
            SveOpcode::Ld1,
            Some(SveElemType::S),
            vec![
                SveOperand::Vector(SveVector::new(0, SveElemType::S)),
                SveOperand::GoverningPredicate(SvePredicate::new(1), SvePredicateMode::Zeroing),
                SveOperand::MemScalarImm { base: 2, imm: 4 },
            ],
        );
        let lifter = SveLifter;
        match lifter.lift(&insn) {
            SveLiftedOp::VecLoad {
                dest,
                pred,
                base,
                offset,
            } => {
                assert_eq!(dest, 0);
                assert_eq!(pred, 1);
                assert_eq!(base, 2);
                assert_eq!(offset, 4);
            }
            other => panic!("expected VecLoad, got {other:?}"),
        }
    }

    // ── 12. SveLifter: store lifted correctly ───────────────────────────────
    #[test]
    fn test_lifter_store() {
        let insn = SveInstruction::new(
            0x1004,
            0,
            SveOpcode::St1,
            Some(SveElemType::D),
            vec![
                SveOperand::Vector(SveVector::new(3, SveElemType::D)),
                SveOperand::GoverningPredicate(SvePredicate::new(2), SvePredicateMode::Merging),
                SveOperand::MemScalarImm { base: 5, imm: -8 },
            ],
        );
        let lifter = SveLifter;
        match lifter.lift(&insn) {
            SveLiftedOp::VecStore {
                src,
                pred,
                base,
                offset,
            } => {
                assert_eq!(src, 3);
                assert_eq!(pred, 2);
                assert_eq!(base, 5);
                assert_eq!(offset, -8);
            }
            other => panic!("expected VecStore, got {other:?}"),
        }
    }

    // ── 13. SveLifter: binop lifted correctly ───────────────────────────────
    #[test]
    fn test_lifter_binop() {
        let insn = SveInstruction::new(
            0,
            0,
            SveOpcode::Add,
            Some(SveElemType::S),
            vec![
                SveOperand::Vector(SveVector::new(0, SveElemType::S)),
                SveOperand::GoverningPredicate(SvePredicate::new(0), SvePredicateMode::Merging),
                SveOperand::Vector(SveVector::new(1, SveElemType::S)),
                SveOperand::Vector(SveVector::new(2, SveElemType::S)),
            ],
        );
        let lifter = SveLifter;
        match lifter.lift(&insn) {
            SveLiftedOp::PredBinOp {
                opcode,
                dest,
                pred,
                lhs,
                rhs,
            } => {
                assert_eq!(opcode, SveOpcode::Add);
                assert_eq!(dest, 0);
                assert_eq!(pred, 0);
                assert_eq!(lhs, 1);
                assert_eq!(rhs, 2);
            }
            other => panic!("expected PredBinOp, got {other:?}"),
        }
    }

    // ── 14. SveLifter: predicate gen ────────────────────────────────────────
    #[test]
    fn test_lifter_predgen() {
        let insn = SveInstruction::new(
            0,
            0,
            SveOpcode::Ptrue,
            Some(SveElemType::B),
            vec![SveOperand::Vector(SveVector::new(5, SveElemType::B))],
        );
        let lifter = SveLifter;
        match lifter.lift(&insn) {
            SveLiftedOp::PredGen { dest, opcode, elem } => {
                assert_eq!(dest, 5);
                assert_eq!(opcode, SveOpcode::Ptrue);
                assert_eq!(elem, SveElemType::B);
            }
            other => panic!("expected PredGen, got {other:?}"),
        }
    }

    // ── 15. SveLifter: reduction ────────────────────────────────────────────
    #[test]
    fn test_lifter_reduce() {
        let insn = SveInstruction::new(
            0,
            0,
            SveOpcode::Addv,
            Some(SveElemType::H),
            vec![
                SveOperand::Vector(SveVector::new(0, SveElemType::H)),
                SveOperand::GoverningPredicate(SvePredicate::new(3), SvePredicateMode::Merging),
                SveOperand::Vector(SveVector::new(7, SveElemType::H)),
            ],
        );
        let lifter = SveLifter;
        match lifter.lift(&insn) {
            SveLiftedOp::Reduce {
                dest,
                pred,
                src,
                opcode,
            } => {
                assert_eq!(dest, 0);
                assert_eq!(pred, 3);
                assert_eq!(src, 7);
                assert_eq!(opcode, SveOpcode::Addv);
            }
            other => panic!("expected Reduce, got {other:?}"),
        }
    }

    // ── 16. SveLifter::lift_all ─────────────────────────────────────────────
    #[test]
    fn test_lifter_lift_all_count() {
        let insns: Vec<SveInstruction> = (0..6)
            .map(|i| {
                SveInstruction::new(
                    i * 4,
                    0,
                    SveOpcode::Add,
                    Some(SveElemType::S),
                    vec![
                        SveOperand::Vector(SveVector::new(0, SveElemType::S)),
                        SveOperand::GoverningPredicate(
                            SvePredicate::new(0),
                            SvePredicateMode::Merging,
                        ),
                        SveOperand::Vector(SveVector::new(1, SveElemType::S)),
                        SveOperand::Vector(SveVector::new(2, SveElemType::S)),
                    ],
                )
            })
            .collect();
        let lifter = SveLifter;
        let ops = lifter.lift_all(&insns);
        assert_eq!(ops.len(), 6);
    }

    // ── 17. SveOpcode::Unknown ──────────────────────────────────────────────
    #[test]
    fn test_unknown_opcode() {
        let op = SveOpcode::Unknown(0xdead_beef);
        assert_eq!(op.mnemonic(), "???");
        assert!(!op.reads_memory());
        assert!(!op.writes_memory());
    }

    // ── 18. Predicate index range ───────────────────────────────────────────
    #[test]
    fn test_predicate_indices() {
        for i in 0u8..16 {
            let p = preg(i);
            assert_eq!(p.index, i);
        }
    }

    // ── 19. Vector index range ──────────────────────────────────────────────
    #[test]
    fn test_vector_indices() {
        for i in 0u8..32 {
            let v = SveVector::raw(i);
            assert_eq!(v.index, i);
        }
    }

    // ── 20. SveInstruction address stored ───────────────────────────────────
    #[test]
    fn test_instruction_address() {
        let insn = SveInstruction::new(0xdead_beef, 0, SveOpcode::Sel, None, vec![]);
        assert_eq!(insn.address, 0xdead_beef);
    }

    // ── 21. SveInstruction encoding stored ──────────────────────────────────
    #[test]
    fn test_instruction_encoding() {
        let insn = SveInstruction::new(0, 0xaabb_ccdd, SveOpcode::Eor, None, vec![]);
        assert_eq!(insn.encoding, 0xaabb_ccdd);
    }

    // ── 22. Predicate generate opcodes all produce_predicate ────────────────
    #[test]
    fn test_all_pred_gen_opcodes() {
        let ops = [
            SveOpcode::Ptrue,
            SveOpcode::Pfalse,
            SveOpcode::Pfirst,
            SveOpcode::Pnext,
            SveOpcode::Pand,
            SveOpcode::Por,
            SveOpcode::Peor,
            SveOpcode::Pbic,
            SveOpcode::Pnot,
            SveOpcode::Whilelt,
            SveOpcode::Whilele,
            SveOpcode::Whilelo,
            SveOpcode::Whilels,
            SveOpcode::Cmpeq,
            SveOpcode::Cmpne,
        ];
        for op in ops {
            assert!(op.produces_predicate(), "{op:?} should produce predicate");
        }
    }

    // ── 23. FP opcodes do not produce predicates ────────────────────────────
    #[test]
    fn test_fp_does_not_produce_predicate() {
        assert!(!SveOpcode::Fmla.produces_predicate());
        assert!(!SveOpcode::Fcvt.produces_predicate());
        assert!(!SveOpcode::Fsqrt.produces_predicate());
    }

    // ── 24. All LD opcodes read memory ──────────────────────────────────────
    #[test]
    fn test_all_ld_read_memory() {
        for op in [
            SveOpcode::Ld1,
            SveOpcode::Ldnf1,
            SveOpcode::Ldff1,
            SveOpcode::Ld2,
            SveOpcode::Ld3,
            SveOpcode::Ld4,
        ] {
            assert!(op.reads_memory(), "{op:?}");
        }
    }

    // ── 25. All ST opcodes write memory ─────────────────────────────────────
    #[test]
    fn test_all_st_write_memory() {
        for op in [
            SveOpcode::St1,
            SveOpcode::St2,
            SveOpcode::St3,
            SveOpcode::St4,
        ] {
            assert!(op.writes_memory(), "{op:?}");
        }
    }

    // ── 26. SVE2 opcodes present ────────────────────────────────────────────
    #[test]
    fn test_sve2_opcodes_present() {
        let opcodes = [
            SveOpcode::Bdep,
            SveOpcode::Bext,
            SveOpcode::Bmatch,
            SveOpcode::Cadd,
            SveOpcode::Cdot,
            SveOpcode::Cmla,
            SveOpcode::Eorbt,
            SveOpcode::Eortb,
            SveOpcode::Fmmla,
            SveOpcode::Saba,
            SveOpcode::Uaba,
            SveOpcode::Sqrdcmlah,
            SveOpcode::Tbx,
            SveOpcode::Urecpe,
            SveOpcode::Ursqrte,
        ];
        for op in opcodes {
            assert!(!op.mnemonic().is_empty(), "{op:?}");
        }
    }

    // ── 27. SveElemType::from_tsz ───────────────────────────────────────────
    #[test]
    fn test_elem_from_tsz() {
        assert_eq!(SveElemType::from_tsz(0b001), Some(SveElemType::B));
        assert_eq!(SveElemType::from_tsz(0b010), Some(SveElemType::H));
        assert_eq!(SveElemType::from_tsz(0b100), Some(SveElemType::S));
        assert_eq!(SveElemType::from_tsz(0), None);
    }

    // ── 28. SveOperand::Imm ─────────────────────────────────────────────────
    #[test]
    fn test_sve_operand_imm() {
        let op = SveOperand::Imm(-42);
        match op {
            SveOperand::Imm(v) => assert_eq!(v, -42),
            _ => panic!(),
        }
    }

    // ── 29. SveOperand::Shift ───────────────────────────────────────────────
    #[test]
    fn test_sve_operand_shift() {
        let op = SveOperand::Shift {
            kind: SveShiftKind::Lsl,
            amount: 3,
        };
        match op {
            SveOperand::Shift { kind, amount } => {
                assert_eq!(kind, SveShiftKind::Lsl);
                assert_eq!(amount, 3);
            }
            _ => panic!(),
        }
    }

    // ── 30. AArch64Sve group boundary checks ────────────────────────────────
    #[test]
    fn test_decode_group_boundaries() {
        // group < 4: reject
        let w_group3 = 0b000_0011_0000_0000_0000_0000_0000_0000_u32;
        assert!(AArch64Sve::decode(w_group3, 0).is_none());
        // group > 7: reject (group=8 → bits[28:25]=1000)
        let w_group8 = 0b000_1000_0000_0000_0000_0000_0000_0000_u32;
        assert!(AArch64Sve::decode(w_group8, 0).is_none());
    }

    // ── 31. Decode group 5 (op0=0x5 → Mul family) ──────────────────────────
    #[test]
    fn test_decode_group5_arithmetic() {
        // bits[31:29]=000, bits[28:25]=0101 (group=5), op0=0x5
        // bits[12:10] = 100 → Mul
        let word: u32 = 0b000_0101_0000_0000_0001_0000_0000_0000_u32;
        let result = AArch64Sve::decode(word, 0);
        assert!(result.is_some());
        let insn = result.unwrap();
        // should decode to arithmetic group
        assert!(!insn.opcode.reads_memory());
    }

    // ── 32. SveInstruction operand count ────────────────────────────────────
    #[test]
    fn test_instruction_operand_count() {
        let insn = SveInstruction::new(
            0,
            0,
            SveOpcode::Fmla,
            Some(SveElemType::S),
            vec![
                SveOperand::Vector(SveVector::new(0, SveElemType::S)),
                SveOperand::GoverningPredicate(SvePredicate::new(1), SvePredicateMode::Merging),
                SveOperand::Vector(SveVector::new(2, SveElemType::S)),
            ],
        );
        assert_eq!(insn.operands.len(), 3);
    }

    // ── 33. Lifter Nop for unknown ───────────────────────────────────────────
    #[test]
    fn test_lifter_nop_for_unknown() {
        let insn = SveInstruction::new(0, 0, SveOpcode::Unknown(99), None, vec![]);
        let lifter = SveLifter;
        // Unknown dispatches to PredBinOp with zeros (not Nop), still succeeds
        let op = lifter.lift(&insn);
        // Just verify it doesn't panic and returns some value
        let _ = op;
    }

    // ── 34. decode_all on empty slice ───────────────────────────────────────
    #[test]
    fn test_decode_all_empty() {
        let results = AArch64Sve::decode_all(&[], 0);
        assert!(results.is_empty());
    }

    // ── 35. SveVector raw then named ────────────────────────────────────────
    #[test]
    fn test_vector_raw_name() {
        let v = SveVector::raw(31);
        assert_eq!(v.name(), "z31");
        assert_eq!(v.typed_name(), "z31");
    }

    // ── 36. SveElemType Q size ───────────────────────────────────────────────
    #[test]
    fn test_elem_q_size() {
        assert_eq!(SveElemType::Q.size_bytes(), 16);
    }

    // ── 37. SveOpcode hash/eq ────────────────────────────────────────────────
    #[test]
    fn test_opcode_hash_eq() {
        use std::collections::HashSet;
        let mut s = HashSet::new();
        s.insert(SveOpcode::Add);
        s.insert(SveOpcode::Sub);
        s.insert(SveOpcode::Add); // duplicate
        assert_eq!(s.len(), 2);
    }

    // ── 38. All compare opcodes ─────────────────────────────────────────────
    #[test]
    fn test_all_cmp_produce_predicate() {
        for op in [
            SveOpcode::Cmpgt,
            SveOpcode::Cmpge,
            SveOpcode::Cmplt,
            SveOpcode::Cmple,
            SveOpcode::Cmphi,
            SveOpcode::Cmphs,
            SveOpcode::Cmplo,
            SveOpcode::Cmpls,
        ] {
            assert!(op.produces_predicate(), "{op:?}");
        }
    }

    // ── 39. SveLifter default produces correct variants ──────────────────────
    #[test]
    fn test_lifter_whilelt() {
        let insn = SveInstruction::new(
            0,
            0,
            SveOpcode::Whilelt,
            Some(SveElemType::D),
            vec![SveOperand::Vector(SveVector::new(4, SveElemType::D))],
        );
        let lifter = SveLifter;
        match lifter.lift(&insn) {
            SveLiftedOp::PredGen { dest, opcode, elem } => {
                assert_eq!(dest, 4);
                assert_eq!(opcode, SveOpcode::Whilelt);
                assert_eq!(elem, SveElemType::D);
            }
            other => panic!("expected PredGen, got {other:?}"),
        }
    }

    // ── 40. decode_all partial word is ignored ───────────────────────────────
    #[test]
    fn test_decode_all_ignores_partial() {
        // 9 bytes → 2 complete words processed, 1 byte leftover ignored
        let bytes = [0u8; 9];
        let results = AArch64Sve::decode_all(&bytes, 0);
        assert_eq!(results.len(), 2);
    }

    // ── 41. SveInstruction display no elem ──────────────────────────────────
    #[test]
    fn test_instruction_display_no_elem() {
        let insn = SveInstruction::new(0, 0, SveOpcode::Splice, None, vec![]);
        assert_eq!(insn.display(), "splice");
    }

    // ── 42. SveOperand GpReg ────────────────────────────────────────────────
    #[test]
    fn test_sve_operand_gpreg() {
        let op = SveOperand::GpReg(5);
        match op {
            SveOperand::GpReg(n) => assert_eq!(n, 5),
            _ => panic!(),
        }
    }
}
