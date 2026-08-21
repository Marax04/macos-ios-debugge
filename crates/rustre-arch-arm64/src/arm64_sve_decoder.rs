//! ARM64 SVE (Scalable Vector Extension) instruction decoder.
//!
//! Implements a standalone decoder for the `AArch64` SVE and SVE2 instruction
//! sets.  Supports register naming (Z0-Z31, P0-P15, FFR), arrangement
//! specifiers, and decoding the top-level SVE encoding groups from raw 32-bit
//! instruction words.

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// SveRegister
// ─────────────────────────────────────────────────────────────────────────────

/// An SVE scalable vector register (Z0–Z31).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SveRegister {
    /// Register index (0–31).
    pub index: u8,
}

impl SveRegister {
    /// Create a new SVE register.
    ///
    /// # Panics
    /// Panics when `index` > 31.
    #[must_use]
    pub fn new(index: u8) -> Self {
        assert!(index < 32, "SVE register index must be 0..31");
        Self { index }
    }

    /// Register name string (e.g. `"Z0"`, `"Z31"`).
    #[must_use]
    pub fn name(self) -> String {
        format!("z{}", self.index)
    }
}

impl fmt::Display for SveRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "z{}", self.index)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SvePredicate
// ─────────────────────────────────────────────────────────────────────────────

/// An SVE predicate register (P0–P15) or the First-Fault Register (FFR).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SvePredicate {
    /// Named predicate register P0–P15.
    P(u8),
    /// First-Fault Register.
    Ffr,
}

impl SvePredicate {
    /// Create a predicate register.
    ///
    /// # Panics
    /// Panics when `index` > 15.
    #[must_use]
    pub fn p(index: u8) -> Self {
        assert!(index < 16, "SVE predicate index must be 0..15");
        Self::P(index)
    }

    /// Display name.
    #[must_use]
    pub fn name(self) -> String {
        match self {
            Self::P(i) => format!("p{i}"),
            Self::Ffr => "ffr".to_owned(),
        }
    }

    /// Returns `true` when this is the FFR.
    #[must_use]
    pub const fn is_ffr(self) -> bool {
        matches!(self, Self::Ffr)
    }
}

impl fmt::Display for SvePredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::P(i) => write!(f, "p{i}"),
            Self::Ffr => write!(f, "ffr"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SveElementSize
// ─────────────────────────────────────────────────────────────────────────────

/// SVE element size (arrangement specifier).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SveElementSize {
    Byte,    // .B
    Half,    // .H
    Word,    // .S  (32-bit)
    Double,  // .D  (64-bit)
    Quad,    // .Q  (128-bit, SVE2)
}

impl SveElementSize {
    /// Decode from the 2-bit `size` field used in SVE encodings.
    #[must_use]
    pub const fn from_bits2(bits: u8) -> Option<Self> {
        match bits & 3 {
            0 => Some(Self::Byte),
            1 => Some(Self::Half),
            2 => Some(Self::Word),
            3 => Some(Self::Double),
            _ => None,
        }
    }

    /// Arrangement suffix used in disassembly (e.g. `.b`, `.h`).
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Byte   => ".b",
            Self::Half   => ".h",
            Self::Word   => ".s",
            Self::Double => ".d",
            Self::Quad   => ".q",
        }
    }

    /// Element size in bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Byte   => 1,
            Self::Half   => 2,
            Self::Word   => 4,
            Self::Double => 8,
            Self::Quad   => 16,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PredicatePattern
// ─────────────────────────────────────────────────────────────────────────────

/// SVE predicate pattern operand used in certain instructions (e.g. PTRUE, PFALSE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicatePattern {
    /// POW2 — largest power-of-2 number of elements.
    Pow2,
    /// VL1 – VL256 exact vector length.
    Vl(u8),
    /// MUL4 — largest multiple of 4.
    Mul4,
    /// MUL3 — largest multiple of 3.
    Mul3,
    /// ALL — all active.
    All,
}

impl PredicatePattern {
    /// Decode from 5-bit pattern field.
    #[must_use]
    pub const fn from_bits5(bits: u8) -> Self {
        match bits & 0x1f {
            0x00 => Self::Pow2,
            0x01..=0x07 => Self::Vl(bits & 0x1f),
            0x1d => Self::Mul4,
            0x1e => Self::Mul3,
            0x1f => Self::All,
            v => Self::Vl(v),
        }
    }

    /// Assembly name.
    #[must_use]
    pub fn name(self) -> String {
        match self {
            Self::Pow2 => "pow2".to_owned(),
            Self::Vl(n) => format!("vl{n}"),
            Self::Mul4 => "mul4".to_owned(),
            Self::Mul3 => "mul3".to_owned(),
            Self::All  => "all".to_owned(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SveInsnGroup
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level SVE encoding group, decoded from bits[31:29] of the instruction word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SveInsnGroup {
    /// Integer arithmetic / logical (group 0).
    IntArith,
    /// Integer arithmetic unary, widening, and narrowing (group 1).
    IntArith2,
    /// Bitwise shift (group 2).
    BitShift,
    /// Predicate-generating and predicate-logical (group 3).
    Predicate,
    /// Memory contiguous load (group 4).
    MemLoad,
    /// Memory contiguous store (group 5).
    MemStore,
    /// Floating-point arithmetic (group 6).
    FpArith,
    /// Gather/scatter and other memory (group 7).
    MemGather,
}

impl SveInsnGroup {
    /// Decode from the top 3 bits of an SVE instruction word.
    #[must_use]
    pub const fn from_word(word: u32) -> Self {
        match (word >> 29) & 0x7 {
            0 => Self::IntArith,
            1 => Self::IntArith2,
            2 => Self::BitShift,
            3 => Self::Predicate,
            4 => Self::MemLoad,
            5 => Self::MemStore,
            6 => Self::FpArith,
            _ => Self::MemGather,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SveInsn
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded SVE instruction.
#[derive(Debug, Clone)]
pub struct SveInsn {
    /// The raw 32-bit instruction word.
    pub word: u32,
    /// Mnemonic string (lower-case).
    pub mnemonic: String,
    /// Operand string.
    pub operands: String,
    /// Top-level encoding group.
    pub group: SveInsnGroup,
    /// Destination SVE register (if applicable).
    pub zd: Option<SveRegister>,
    /// First source SVE register (if applicable).
    pub zn: Option<SveRegister>,
    /// Second source SVE register (if applicable).
    pub zm: Option<SveRegister>,
    /// Governing predicate register (if applicable).
    pub pg: Option<SvePredicate>,
    /// Element size (if applicable).
    pub elem_size: Option<SveElementSize>,
}

impl SveInsn {
    /// Returns `true` when this instruction is predicated (has a governing Pg).
    #[must_use]
    pub const fn is_predicated(&self) -> bool {
        self.pg.is_some()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SveDecoder
// ─────────────────────────────────────────────────────────────────────────────

/// Stateless SVE instruction decoder.
///
/// Call [`SveDecoder::decode`] or the free function [`decode_sve`] to decode
/// a single 32-bit instruction word.
#[derive(Debug, Clone, Copy, Default)]
pub struct SveDecoder;

impl SveDecoder {
    /// Create a new decoder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Decode a single 32-bit SVE instruction word.
    ///
    /// Returns `None` when the word does not appear to be an SVE instruction
    /// (i.e. the mandatory top-level fixed bits are absent).
    #[must_use]
    pub fn decode(&self, word: u32) -> Option<SveInsn> {
        decode_sve(word)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// decode_sve – main decoding logic
// ─────────────────────────────────────────────────────────────────────────────

/// Decode a 32-bit `AArch64` SVE instruction word.
///
/// SVE instruction words have bits[28:25] == `0010` (after the top-level
/// `AArch64` decode). This function checks that field and dispatches to
/// group-specific decoders.
///
/// Returns `None` for words that are not SVE instructions.
#[must_use]
pub fn decode_sve(word: u32) -> Option<SveInsn> {
    // AArch64 top-level: bits[28:25] = 0010 identifies SVE
    if (word >> 25) & 0xf != 0b0010 {
        return None;
    }
    let group = SveInsnGroup::from_word(word);
    match group {
        SveInsnGroup::IntArith  => decode_int_arith(word),
        SveInsnGroup::IntArith2 => decode_int_arith2(word),
        SveInsnGroup::BitShift  => decode_bit_shift(word),
        SveInsnGroup::Predicate => decode_predicate(word),
        SveInsnGroup::MemLoad   => decode_mem_load(word),
        SveInsnGroup::MemStore  => decode_mem_store(word),
        SveInsnGroup::FpArith   => decode_fp_arith(word),
        SveInsnGroup::MemGather => decode_mem_gather(word),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn zreg(idx: u32) -> SveRegister {
    SveRegister::new((idx & 0x1f) as u8)
}

fn preg(idx: u32) -> SvePredicate {
    SvePredicate::p((idx & 0xf) as u8)
}

const fn size_field(word: u32, shift: u32) -> Option<SveElementSize> {
    SveElementSize::from_bits2(((word >> shift) & 3) as u8)
}

/// The register/element operands of a decoded SVE instruction, grouped so
/// that `make_insn` takes one cohesive bundle instead of five loose slots.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SveOperandRegs {
    /// Destination vector register, when the encoding has one.
    pub zd: Option<SveRegister>,
    /// First source vector register.
    pub zn: Option<SveRegister>,
    /// Second source vector register.
    pub zm: Option<SveRegister>,
    /// Governing predicate register.
    pub pg: Option<SvePredicate>,
    /// Element size of the operation.
    pub elem_size: Option<SveElementSize>,
}

fn make_insn(
    word: u32,
    group: SveInsnGroup,
    mnemonic: &str,
    operands: String,
    regs: SveOperandRegs,
) -> SveInsn {
    SveInsn {
        word,
        mnemonic: mnemonic.to_ascii_lowercase(),
        operands,
        group,
        zd: regs.zd,
        zn: regs.zn,
        zm: regs.zm,
        pg: regs.pg,
        elem_size: regs.elem_size,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Group decoders
// ─────────────────────────────────────────────────────────────────────────────

fn decode_int_arith(word: u32) -> Option<SveInsn> {
    // SVE integer arithmetic: bits[28:24] = 0_0000 to 0_0111 (various)
    let size = size_field(word, 22)?;
    let opc = (word >> 13) & 0x7;
    let zd = zreg(word & 0x1f);
    let zn = zreg((word >> 5) & 0x1f);
    let zm = zreg((word >> 16) & 0x1f);
    let pg = preg((word >> 10) & 0x7);

    // Bits[23:22] = size, bits[20:16] = Zm, bits[12:10] = Pg, bits[9:5] = Zn, bits[4:0] = Zd
    let (mnemonic, has_pg) = match opc & 0x7 {
        0 => ("add", true),
        1 => ("sub", true),
        2 => ("mul", true),
        3 => ("sdiv", true),
        4 => ("udiv", true),
        5 => ("smax", true),
        6 => ("smin", true),
        _ => ("and", false),
    };
    let suf = size.suffix();
    let ops = if has_pg {
        format!("{zd}{suf}, {pg}/m, {zn}{suf}, {zm}{suf}")
    } else {
        format!("{zd}{suf}, {zn}{suf}, {zm}{suf}")
    };
    Some(make_insn(word, SveInsnGroup::IntArith, mnemonic, ops, SveOperandRegs { zd: Some(zd), zn: Some(zn), zm: Some(zm), pg: if has_pg { Some(pg) } else { None }, elem_size: Some(size) }))
}

fn decode_int_arith2(word: u32) -> Option<SveInsn> {
    // Wide integer / unary
    let size = size_field(word, 22)?;
    let zd = zreg(word & 0x1f);
    let zn = zreg((word >> 5) & 0x1f);
    let pg = preg((word >> 10) & 0x7);
    let opc2 = (word >> 16) & 0x3;

    let mnemonic = match opc2 {
        0 => "abs",
        1 => "neg",
        2 => "not",
        _ => "cnot",
    };
    let suf = size.suffix();
    let ops = format!("{zd}{suf}, {pg}/m, {zn}{suf}");
    Some(make_insn(word, SveInsnGroup::IntArith2, mnemonic, ops, SveOperandRegs { zd: Some(zd), zn: Some(zn), zm: None, pg: Some(pg), elem_size: Some(size) }))
}

fn decode_bit_shift(word: u32) -> Option<SveInsn> {
    let size = size_field(word, 22)?;
    let zd = zreg(word & 0x1f);
    let zn = zreg((word >> 5) & 0x1f);
    let zm = zreg((word >> 16) & 0x1f);
    let pg = preg((word >> 10) & 0x7);
    let opc = (word >> 18) & 0x3;

    let mnemonic = match opc {
        0 => "lsl",
        1 => "lsr",
        2 => "asr",
        _ => "ror",
    };
    let suf = size.suffix();
    let ops = format!("{zd}{suf}, {pg}/m, {zn}{suf}, {zm}{suf}");
    Some(make_insn(word, SveInsnGroup::BitShift, mnemonic, ops, SveOperandRegs { zd: Some(zd), zn: Some(zn), zm: Some(zm), pg: Some(pg), elem_size: Some(size) }))
}

fn decode_predicate(word: u32) -> Option<SveInsn> {
    let size = size_field(word, 22)?;
    let pd = preg(word & 0xf);
    let pn = preg((word >> 5) & 0xf);
    let pm = preg((word >> 16) & 0xf);
    let pg = preg((word >> 10) & 0xf);
    let opc = (word >> 14) & 0x3;

    let (mnemonic, ops) = match opc {
        0 => ("ptrue", format!("{pd}{}", size.suffix())),
        1 => ("pfalse", format!("{pd}{}", size.suffix())),
        2 => (
            "and",
            format!("{pd}.b, {pg}/z, {pn}.b, {pm}.b"),
        ),
        _ => (
            "eor",
            format!("{pd}.b, {pg}/z, {pn}.b, {pm}.b"),
        ),
    };
    Some(make_insn(word, SveInsnGroup::Predicate, mnemonic, ops, SveOperandRegs { zd: None, zn: None, zm: None, pg: Some(pg), elem_size: Some(size) }))
}

fn decode_mem_load(word: u32) -> Option<SveInsn> {
    let size = size_field(word, 21)?;
    let zd = zreg(word & 0x1f);
    let pg = preg((word >> 10) & 0x7);
    let rn = (word >> 5) & 0x1f;
    let rm = (word >> 16) & 0x1f;
    let suf = size.suffix();

    let ops = if rm == 31 {
        format!("{zd}{suf}, {pg}/z, [x{rn}]")
    } else {
        format!("{zd}{suf}, {pg}/z, [x{rn}, x{rm}]")
    };
    Some(make_insn(word, SveInsnGroup::MemLoad, "ld1", ops, SveOperandRegs { zd: Some(zd), zn: None, zm: None, pg: Some(pg), elem_size: Some(size) }))
}

fn decode_mem_store(word: u32) -> Option<SveInsn> {
    let size = size_field(word, 21)?;
    let zt = zreg(word & 0x1f);
    let pg = preg((word >> 10) & 0x7);
    let rn = (word >> 5) & 0x1f;
    let rm = (word >> 16) & 0x1f;
    let suf = size.suffix();

    let ops = if rm == 31 {
        format!("{zt}{suf}, {pg}, [x{rn}]")
    } else {
        format!("{zt}{suf}, {pg}, [x{rn}, x{rm}]")
    };
    Some(make_insn(word, SveInsnGroup::MemStore, "st1", ops, SveOperandRegs { zd: Some(zt), zn: None, zm: None, pg: Some(pg), elem_size: Some(size) }))
}

fn decode_fp_arith(word: u32) -> Option<SveInsn> {
    let size = size_field(word, 22)?;
    let zd = zreg(word & 0x1f);
    let zn = zreg((word >> 5) & 0x1f);
    let zm = zreg((word >> 16) & 0x1f);
    let pg = preg((word >> 10) & 0x7);
    let opc = (word >> 13) & 0x7;

    let mnemonic = match opc {
        0 => "fadd",
        1 => "fsub",
        2 => "fmul",
        3 => "fdiv",
        4 => "fmax",
        5 => "fmin",
        6 => "fmla",
        _ => "fmls",
    };
    let suf = size.suffix();
    let ops = format!("{zd}{suf}, {pg}/m, {zn}{suf}, {zm}{suf}");
    Some(make_insn(word, SveInsnGroup::FpArith, mnemonic, ops, SveOperandRegs { zd: Some(zd), zn: Some(zn), zm: Some(zm), pg: Some(pg), elem_size: Some(size) }))
}

fn decode_mem_gather(word: u32) -> Option<SveInsn> {
    let size = size_field(word, 23)?;
    let zd = zreg(word & 0x1f);
    let pg = preg((word >> 10) & 0x7);
    let rn = (word >> 5) & 0x1f;
    let zm = zreg((word >> 16) & 0x1f);
    let suf = size.suffix();

    let ops = format!("{zd}{suf}, {pg}/z, [x{rn}, {zm}{suf}]");
    Some(make_insn(word, SveInsnGroup::MemGather, "ld1", ops, SveOperandRegs { zd: Some(zd), zn: None, zm: Some(zm), pg: Some(pg), elem_size: Some(size) }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sve_register_names() {
        assert_eq!(SveRegister::new(0).name(), "z0");
        assert_eq!(SveRegister::new(31).name(), "z31");
    }

    #[test]
    fn sve_predicate_names() {
        assert_eq!(SvePredicate::p(0).name(), "p0");
        assert_eq!(SvePredicate::p(15).name(), "p15");
        assert_eq!(SvePredicate::Ffr.name(), "ffr");
        assert!(SvePredicate::Ffr.is_ffr());
        assert!(!SvePredicate::p(0).is_ffr());
    }

    #[test]
    fn element_size_from_bits() {
        assert_eq!(SveElementSize::from_bits2(0), Some(SveElementSize::Byte));
        assert_eq!(SveElementSize::from_bits2(1), Some(SveElementSize::Half));
        assert_eq!(SveElementSize::from_bits2(2), Some(SveElementSize::Word));
        assert_eq!(SveElementSize::from_bits2(3), Some(SveElementSize::Double));
    }

    #[test]
    fn element_size_suffix() {
        assert_eq!(SveElementSize::Byte.suffix(), ".b");
        assert_eq!(SveElementSize::Half.suffix(), ".h");
        assert_eq!(SveElementSize::Word.suffix(), ".s");
        assert_eq!(SveElementSize::Double.suffix(), ".d");
    }

    #[test]
    fn element_size_bytes() {
        assert_eq!(SveElementSize::Byte.bytes(), 1);
        assert_eq!(SveElementSize::Half.bytes(), 2);
        assert_eq!(SveElementSize::Word.bytes(), 4);
        assert_eq!(SveElementSize::Double.bytes(), 8);
        assert_eq!(SveElementSize::Quad.bytes(), 16);
    }

    #[test]
    fn predicate_pattern_all() {
        let p = PredicatePattern::from_bits5(0x1f);
        assert_eq!(p.name(), "all");
    }

    #[test]
    fn predicate_pattern_pow2() {
        let p = PredicatePattern::from_bits5(0);
        assert_eq!(p.name(), "pow2");
    }

    #[test]
    fn non_sve_word_returns_none() {
        // A NOP (0xD503201F) — bits[28:25] != 0010
        assert!(decode_sve(0xD503_201F).is_none());
    }

    #[test]
    fn sve_decoder_new() {
        let d = SveDecoder::new();
        // Construct a minimal SVE word: bits[28:25]=0010, bits[31:29]=001 (IntArith2)
        // We only need to check it doesn't panic
        let word = 0x0440_0000u32; // bits[28:25]=0b0010, rest zeros
        // decode_sve may return None due to invalid fields — that's fine
        let _ = d.decode(word);
    }

    #[test]
    fn sve_insn_is_predicated() {
        let insn = SveInsn {
            word: 0,
            mnemonic: "add".to_owned(),
            operands: "z0.b, p0/m, z1.b, z2.b".to_owned(),
            group: SveInsnGroup::IntArith,
            zd: Some(SveRegister::new(0)),
            zn: Some(SveRegister::new(1)),
            zm: Some(SveRegister::new(2)),
            pg: Some(SvePredicate::p(0)),
            elem_size: Some(SveElementSize::Byte),
        };
        assert!(insn.is_predicated());
    }

    #[test]
    fn sve_insn_not_predicated() {
        let insn = SveInsn {
            word: 0,
            mnemonic: "index".to_owned(),
            operands: "z0.b, x1, x2".to_owned(),
            group: SveInsnGroup::IntArith,
            zd: Some(SveRegister::new(0)),
            zn: None,
            zm: None,
            pg: None,
            elem_size: Some(SveElementSize::Byte),
        };
        assert!(!insn.is_predicated());
    }

    #[test]
    fn sve_group_from_word() {
        // bits[31:29]=000 → IntArith
        let w = 0b0010 << 25;
        assert_eq!(SveInsnGroup::from_word(w), SveInsnGroup::IntArith);
        // bits[31:29]=100 → MemLoad
        let w2 = (0b100u32 << 29) | (0b0010 << 25);
        assert_eq!(SveInsnGroup::from_word(w2), SveInsnGroup::MemLoad);
    }

    #[test]
    fn sve_register_display() {
        let r = SveRegister::new(7);
        assert_eq!(format!("{r}"), "z7");
    }

    #[test]
    fn sve_predicate_display_ffr() {
        assert_eq!(format!("{}", SvePredicate::Ffr), "ffr");
    }
}
