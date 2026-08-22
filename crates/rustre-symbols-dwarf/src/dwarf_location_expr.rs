//! `dwarf_location_expr` — DWARF location expression parser and evaluator.
//!
//! Handles `DW_FORM_exprloc` / `DW_FORM_block` location expressions and
//! implements a full stack machine evaluator for all DWARF location opcodes.
//!
//! # Parallel implementations
//!
//! This crate ships more than one location-expression implementation: see also `location_expr` and `dwarf_expression_evaluator`.
//! None of them is wired into [`crate::DwarfReader`], which uses its own
//! inline copy, so each carries an independent bug set and a fix applied
//! here does not propagate. Pick one deliberately and stay on it.

use std::fmt;

// ── DW_OP constants ───────────────────────────────────────────────────────────

/// `dw_op_addr` opcode (0x03).
pub const DW_OP_ADDR: u8 = 0x03;
/// `dw_op_deref` opcode (0x06).
pub const DW_OP_DEREF: u8 = 0x06;
/// `dw_op_const1u` opcode (0x08).
pub const DW_OP_CONST1U: u8 = 0x08;
/// `dw_op_const1s` opcode (0x09).
pub const DW_OP_CONST1S: u8 = 0x09;
/// `dw_op_const2u` opcode (0x0a).
pub const DW_OP_CONST2U: u8 = 0x0a;
/// `dw_op_const2s` opcode (0x0b).
pub const DW_OP_CONST2S: u8 = 0x0b;
/// `dw_op_const4u` opcode (0x0c).
pub const DW_OP_CONST4U: u8 = 0x0c;
/// `dw_op_const4s` opcode (0x0d).
pub const DW_OP_CONST4S: u8 = 0x0d;
/// `dw_op_const8u` opcode (0x0e).
pub const DW_OP_CONST8U: u8 = 0x0e;
/// `dw_op_const8s` opcode (0x0f).
pub const DW_OP_CONST8S: u8 = 0x0f;
/// `dw_op_constu` opcode (0x10).
pub const DW_OP_CONSTU: u8 = 0x10;
/// `dw_op_consts` opcode (0x11).
pub const DW_OP_CONSTS: u8 = 0x11;
/// `dw_op_dup` opcode (0x12).
pub const DW_OP_DUP: u8 = 0x12;
/// `dw_op_drop` opcode (0x13).
pub const DW_OP_DROP: u8 = 0x13;
/// `dw_op_over` opcode (0x14).
pub const DW_OP_OVER: u8 = 0x14;
/// `dw_op_pick` opcode (0x15).
pub const DW_OP_PICK: u8 = 0x15;
/// `dw_op_swap` opcode (0x16).
pub const DW_OP_SWAP: u8 = 0x16;
/// `dw_op_rot` opcode (0x17).
pub const DW_OP_ROT: u8 = 0x17;
/// `dw_op_xderef` opcode (0x18).
pub const DW_OP_XDEREF: u8 = 0x18;
/// `dw_op_abs` opcode (0x19).
pub const DW_OP_ABS: u8 = 0x19;
/// `dw_op_and` opcode (0x1a).
pub const DW_OP_AND: u8 = 0x1a;
/// `dw_op_div` opcode (0x1b).
pub const DW_OP_DIV: u8 = 0x1b;
/// `dw_op_minus` opcode (0x1c).
pub const DW_OP_MINUS: u8 = 0x1c;
/// `dw_op_mod` opcode (0x1d).
pub const DW_OP_MOD: u8 = 0x1d;
/// `dw_op_mul` opcode (0x1e).
pub const DW_OP_MUL: u8 = 0x1e;
/// `dw_op_neg` opcode (0x1f).
pub const DW_OP_NEG: u8 = 0x1f;
/// `dw_op_not` opcode (0x20).
pub const DW_OP_NOT: u8 = 0x20;
/// `dw_op_or` opcode (0x21).
pub const DW_OP_OR: u8 = 0x21;
/// `dw_op_plus` opcode (0x22).
pub const DW_OP_PLUS: u8 = 0x22;
/// `dw_op_plus_uconst` opcode (0x23).
pub const DW_OP_PLUS_UCONST: u8 = 0x23;
/// `dw_op_shl` opcode (0x24).
pub const DW_OP_SHL: u8 = 0x24;
/// `dw_op_shr` opcode (0x25).
pub const DW_OP_SHR: u8 = 0x25;
/// `dw_op_shra` opcode (0x26).
pub const DW_OP_SHRA: u8 = 0x26;
/// `dw_op_xor` opcode (0x27).
pub const DW_OP_XOR: u8 = 0x27;
/// `dw_op_skip` opcode (0x2f).
pub const DW_OP_SKIP: u8 = 0x2f;
/// `dw_op_bra` opcode (0x28).
pub const DW_OP_BRA: u8 = 0x28;
/// `dw_op_eq` opcode (0x29).
pub const DW_OP_EQ: u8 = 0x29;
/// `dw_op_ge` opcode (0x2a).
pub const DW_OP_GE: u8 = 0x2a;
/// `dw_op_gt` opcode (0x2b).
pub const DW_OP_GT: u8 = 0x2b;
/// `dw_op_le` opcode (0x2c).
pub const DW_OP_LE: u8 = 0x2c;
/// `dw_op_lt` opcode (0x2d).
pub const DW_OP_LT: u8 = 0x2d;
/// `dw_op_ne` opcode (0x2e).
pub const DW_OP_NE: u8 = 0x2e;
/// `dw_op_lit0` opcode (0x30).
pub const DW_OP_LIT0: u8 = 0x30;
/// `dw_op_lit31` opcode (0x4f).
pub const DW_OP_LIT31: u8 = 0x4f;
/// `dw_op_reg0` opcode (0x50).
pub const DW_OP_REG0: u8 = 0x50;
/// `dw_op_reg31` opcode (0x6f).
pub const DW_OP_REG31: u8 = 0x6f;
/// `dw_op_breg0` opcode (0x70).
pub const DW_OP_BREG0: u8 = 0x70;
/// `dw_op_breg31` opcode (0x8f).
pub const DW_OP_BREG31: u8 = 0x8f;
/// `dw_op_regx` opcode (0x90).
pub const DW_OP_REGX: u8 = 0x90;
/// `dw_op_fbreg` opcode (0x91).
pub const DW_OP_FBREG: u8 = 0x91;
/// `dw_op_bregx` opcode (0x92).
pub const DW_OP_BREGX: u8 = 0x92;
/// `dw_op_piece` opcode (0x93).
pub const DW_OP_PIECE: u8 = 0x93;
/// `dw_op_deref_size` opcode (0x94).
pub const DW_OP_DEREF_SIZE: u8 = 0x94;
/// `dw_op_xderef_size` opcode (0x95).
pub const DW_OP_XDEREF_SIZE: u8 = 0x95;
/// `dw_op_nop` opcode (0x96).
pub const DW_OP_NOP: u8 = 0x96;
/// `dw_op_push_object_address` opcode (0x97).
pub const DW_OP_PUSH_OBJECT_ADDRESS: u8 = 0x97;
/// `dw_op_call2` opcode (0x98).
pub const DW_OP_CALL2: u8 = 0x98;
/// `dw_op_call4` opcode (0x99).
pub const DW_OP_CALL4: u8 = 0x99;
/// `dw_op_call_ref` opcode (0x9a).
pub const DW_OP_CALL_REF: u8 = 0x9a;
/// `dw_op_form_tls_address` opcode (0x9b).
pub const DW_OP_FORM_TLS_ADDRESS: u8 = 0x9b;
/// `dw_op_call_frame_cfa` opcode (0x9c).
pub const DW_OP_CALL_FRAME_CFA: u8 = 0x9c;
/// `dw_op_bit_piece` opcode (0x9d).
pub const DW_OP_BIT_PIECE: u8 = 0x9d;
/// `dw_op_implicit_value` opcode (0x9e).
pub const DW_OP_IMPLICIT_VALUE: u8 = 0x9e;
/// `dw_op_stack_value` opcode (0x9f).
pub const DW_OP_STACK_VALUE: u8 = 0x9f;
/// `dw_op_implicit_pointer` opcode (0xa0).
pub const DW_OP_IMPLICIT_POINTER: u8 = 0xa0;
/// `dw_op_addrx` opcode (0xa1).
pub const DW_OP_ADDRX: u8 = 0xa1;
/// `dw_op_constx` opcode (0xa2).
pub const DW_OP_CONSTX: u8 = 0xa2;
/// `dw_op_entry_value` opcode (0xa3).
pub const DW_OP_ENTRY_VALUE: u8 = 0xa3;
/// `dw_op_const_type` opcode (0xa4).
pub const DW_OP_CONST_TYPE: u8 = 0xa4;
/// `dw_op_regval_type` opcode (0xa5).
pub const DW_OP_REGVAL_TYPE: u8 = 0xa5;
/// `dw_op_deref_type` opcode (0xa6).
pub const DW_OP_DEREF_TYPE: u8 = 0xa6;
/// `dw_op_xderef_type` opcode (0xa7).
pub const DW_OP_XDEREF_TYPE: u8 = 0xa7;
/// `dw_op_convert` opcode (0xa8).
pub const DW_OP_CONVERT: u8 = 0xa8;
/// `dw_op_reinterpret` opcode (0xa9).
pub const DW_OP_REINTERPRET: u8 = 0xa9;
// GNU extensions
/// GNU extension opcode `dw_op_gnu_push_tls_address` (0xe0).
pub const DW_OP_GNU_PUSH_TLS_ADDRESS: u8 = 0xe0;
/// GNU extension opcode `dw_op_gnu_uninit` (0xf0).
pub const DW_OP_GNU_UNINIT: u8 = 0xf0;
/// GNU extension opcode `dw_op_gnu_implicit_pointer` (0xf2).
pub const DW_OP_GNU_IMPLICIT_POINTER: u8 = 0xf2;
/// GNU extension opcode `dw_op_gnu_entry_value` (0xf3).
pub const DW_OP_GNU_ENTRY_VALUE: u8 = 0xf3;
/// GNU extension opcode `dw_op_gnu_const_type` (0xf4).
pub const DW_OP_GNU_CONST_TYPE: u8 = 0xf4;
/// GNU extension opcode `dw_op_gnu_regval_type` (0xf5).
pub const DW_OP_GNU_REGVAL_TYPE: u8 = 0xf5;
/// GNU extension opcode `dw_op_gnu_deref_type` (0xf6).
pub const DW_OP_GNU_DEREF_TYPE: u8 = 0xf6;
/// GNU extension opcode `dw_op_gnu_convert` (0xf7).
pub const DW_OP_GNU_CONVERT: u8 = 0xf7;
/// GNU extension opcode `dw_op_gnu_reinterpret` (0xf9).
pub const DW_OP_GNU_REINTERPRET: u8 = 0xf9;
/// Start of the vendor extension opcode range (`DW_OP_lo_user`, 0xe0).
pub const DW_OP_LO_USER: u8 = 0xe0;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors produced while parsing or evaluating a DWARF location expression.
#[derive(Debug, thiserror::Error)]
pub enum LocationError {
    /// The expression bytes ended before an operand was fully read; payload is the offset.
    #[error("unexpected end of location expression at offset {0}")]
    Truncated(usize),
    /// An operation required more stack entries than were present.
    #[error("stack underflow in location expression")]
    StackUnderflow,
    /// `DW_OP_div` or `DW_OP_mod` with a zero divisor.
    #[error("division by zero in location expression")]
    DivisionByZero,
    /// An opcode byte that is not a recognized `DW_OP_*` value.
    #[error("unknown location opcode 0x{0:02x}")]
    UnknownOpcode(u8),
    /// The evaluator exceeded its step limit (likely a `DW_OP_skip`/`DW_OP_bra` loop).
    #[error("evaluation limit exceeded")]
    LimitExceeded,
}

/// Result alias for location-expression parsing and evaluation.
pub type Result<T> = std::result::Result<T, LocationError>;

// ── ULEB128 / SLEB128 helpers ─────────────────────────────────────────────────

fn read_uleb128(data: &[u8], off: &mut usize) -> Result<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *data.get(*off).ok_or(LocationError::Truncated(*off))?;
        *off += 1;
        result |= u64::from(b & 0x7f) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            break;
        }
    }
    Ok(result)
}

fn read_sleb128(data: &[u8], off: &mut usize) -> Result<i64> {
    let mut result = 0i64;
    let mut shift = 0u32;
    let b = loop {
        let byte = *data.get(*off).ok_or(LocationError::Truncated(*off))?;
        *off += 1;
        result |= i64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break byte;
        }
        if shift >= 64 {
            break byte;
        }
    };
    if shift < 64 && (b & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Ok(result)
}

fn read_u8(data: &[u8], off: &mut usize) -> Result<u8> {
    let v = *data.get(*off).ok_or(LocationError::Truncated(*off))?;
    *off += 1;
    Ok(v)
}

fn read_u16_le(data: &[u8], off: &mut usize) -> Result<u16> {
    if *off + 2 > data.len() {
        return Err(LocationError::Truncated(*off));
    }
    let v = u16::from_le_bytes([data[*off], data[*off + 1]]);
    *off += 2;
    Ok(v)
}

fn read_u32_le(data: &[u8], off: &mut usize) -> Result<u32> {
    if *off + 4 > data.len() {
        return Err(LocationError::Truncated(*off));
    }
    let v = u32::from_le_bytes(data[*off..*off + 4].try_into().unwrap());
    *off += 4;
    Ok(v)
}

fn read_u64_le(data: &[u8], off: &mut usize) -> Result<u64> {
    if *off + 8 > data.len() {
        return Err(LocationError::Truncated(*off));
    }
    let v = u64::from_le_bytes(data[*off..*off + 8].try_into().unwrap());
    *off += 8;
    Ok(v)
}

// ── Decoded operation ─────────────────────────────────────────────────────────

/// A decoded DWARF location expression operation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LocationOp {
    /// `DW_OP_addr`: push a constant machine address.
    Addr(u64),
    /// `DW_OP_deref`: pop an address and push the value it points to.
    Deref,
    /// Any `DW_OP_const*u`/`DW_OP_const*s`/`DW_OP_constu`/`DW_OP_consts`: push a constant.
    Const(i64),
    /// `DW_OP_dup`: duplicate the top stack entry.
    Dup,
    /// `DW_OP_drop`: pop and discard the top stack entry.
    Drop,
    /// `DW_OP_over`: push a copy of the second stack entry.
    Over,
    /// `DW_OP_pick`: push a copy of the stack entry at the given depth.
    Pick(u8),
    /// `DW_OP_swap`: exchange the top two stack entries.
    Swap,
    /// `DW_OP_rot`: rotate the top three stack entries.
    Rot,
    /// `DW_OP_abs`: replace the top entry with its absolute value.
    Abs,
    /// `DW_OP_and`: bitwise AND of the top two entries.
    And,
    /// `DW_OP_div`: signed division of the top two entries.
    Div,
    /// `DW_OP_minus`: subtraction of the top two entries.
    Minus,
    /// `DW_OP_mod`: modulus of the top two entries.
    Mod,
    /// `DW_OP_mul`: multiplication of the top two entries.
    Mul,
    /// `DW_OP_neg`: arithmetic negation of the top entry.
    Neg,
    /// `DW_OP_not`: bitwise NOT of the top entry.
    Not,
    /// `DW_OP_or`: bitwise OR of the top two entries.
    Or,
    /// `DW_OP_plus`: addition of the top two entries.
    Plus,
    /// `DW_OP_plus_uconst`: add an unsigned constant to the top entry.
    PlusUconst(u64),
    /// `DW_OP_shl`: left shift.
    Shl,
    /// `DW_OP_shr`: logical (unsigned) right shift.
    Shr,
    /// `DW_OP_shra`: arithmetic (signed) right shift.
    Shra,
    /// `DW_OP_xor`: bitwise XOR of the top two entries.
    Xor,
    /// `DW_OP_skip`: unconditional branch by a signed byte offset.
    Skip(i16),
    /// `DW_OP_bra`: conditional branch by a signed byte offset if the popped value is non-zero.
    Bra(i16),
    /// `DW_OP_eq`: push 1 if the top two entries are equal, else 0.
    Eq,
    /// `DW_OP_ge`: signed greater-or-equal comparison.
    Ge,
    /// `DW_OP_gt`: signed greater-than comparison.
    Gt,
    /// `DW_OP_le`: signed less-or-equal comparison.
    Le,
    /// `DW_OP_lt`: signed less-than comparison.
    Lt,
    /// `DW_OP_ne`: push 1 if the top two entries differ, else 0.
    Ne,
    /// `DW_OP_lit0`..`DW_OP_lit31`: push a small literal (0..=31).
    Lit(u8),
    /// `DW_OP_reg0`..`DW_OP_reg31` or `DW_OP_regx`: the object lives in this register.
    Reg(u32),
    /// `DW_OP_breg0`..`DW_OP_breg31` or `DW_OP_bregx`: register base plus signed offset.
    BReg(u32, i64),
    /// `DW_OP_fbreg`: frame-base-relative offset.
    FbReg(i64),
    /// `DW_OP_piece`: this many bytes of the object are described by the preceding ops.
    Piece(u64),
    /// `DW_OP_bit_piece`: a bit-granular piece of the object.
    BitPiece {
        /// Piece size in bits.
        size: u64,
        /// Bit offset within the located value.
        offset: u64,
    },
    /// `DW_OP_implicit_value`: the object's value is this literal byte block.
    ImplicitValue(Vec<u8>),
    /// `DW_OP_stack_value`: the top of stack is the object's value, not its address.
    StackValue,
    /// `DW_OP_call_frame_cfa`: push the canonical frame address.
    CallFrameCfa,
    /// `DW_OP_push_object_address`: push the address of the containing object.
    PushObjectAddress,
    /// `DW_OP_form_tls_address` / `DW_OP_GNU_push_tls_address`: translate the top entry to a TLS address.
    GnuPushTlsAddress,
    /// `DW_OP_nop` (also emitted for ops parsed-and-skipped, e.g. call and typed ops).
    Nop,
    /// An unrecognized opcode byte, preserved verbatim.
    Unknown(u8),
}

impl fmt::Display for LocationOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Addr(a) => write!(f, "DW_OP_addr 0x{a:x}"),
            Self::Const(v) => write!(f, "DW_OP_const #{v}"),
            Self::Lit(n) => write!(f, "DW_OP_lit{n}"),
            Self::Reg(r) => write!(f, "DW_OP_reg{r}"),
            Self::BReg(r, off) => write!(f, "DW_OP_breg{r} {off:+}"),
            Self::FbReg(off) => write!(f, "DW_OP_fbreg {off:+}"),
            Self::PlusUconst(v) => write!(f, "DW_OP_plus_uconst {v}"),
            Self::Piece(sz) => write!(f, "DW_OP_piece {sz}"),
            Self::StackValue => write!(f, "DW_OP_stack_value"),
            Self::CallFrameCfa => write!(f, "DW_OP_call_frame_cfa"),
            _ => write!(f, "{self:?}"),
        }
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse a raw location expression byte slice into a list of `LocationOp`.
///
/// `addr_size` is the pointer size (4 or 8) used for `DW_OP_addr`.
pub fn parse_location_expr(expr: &[u8], addr_size: u8) -> Result<Vec<LocationOp>> {
    let mut ops = Vec::new();
    let mut off = 0usize;

    while off < expr.len() {
        let opcode = read_u8(expr, &mut off)?;
        let op = match opcode {
            DW_OP_ADDR => {
                let addr = if addr_size == 8 {
                    read_u64_le(expr, &mut off)?
                } else {
                    u64::from(read_u32_le(expr, &mut off)?)
                };
                LocationOp::Addr(addr)
            }
            DW_OP_DEREF => LocationOp::Deref,
            DW_OP_CONST1U => LocationOp::Const(i64::from(read_u8(expr, &mut off)?)),
            DW_OP_CONST1S => LocationOp::Const(i64::from(read_u8(expr, &mut off)?.cast_signed())),
            DW_OP_CONST2U => LocationOp::Const(i64::from(read_u16_le(expr, &mut off)?)),
            DW_OP_CONST2S => LocationOp::Const(i64::from(read_u16_le(expr, &mut off)?.cast_signed())),
            DW_OP_CONST4U => LocationOp::Const(i64::from(read_u32_le(expr, &mut off)?)),
            DW_OP_CONST4S => LocationOp::Const(i64::from(read_u32_le(expr, &mut off)?.cast_signed())),
            DW_OP_CONST8U => LocationOp::Const(read_u64_le(expr, &mut off)?.cast_signed()),
            DW_OP_CONST8S => LocationOp::Const(read_u64_le(expr, &mut off)?.cast_signed()),
            DW_OP_CONSTU => LocationOp::Const(read_uleb128(expr, &mut off)?.cast_signed()),
            DW_OP_CONSTS => LocationOp::Const(read_sleb128(expr, &mut off)?),
            DW_OP_DUP => LocationOp::Dup,
            DW_OP_DROP => LocationOp::Drop,
            DW_OP_OVER => LocationOp::Over,
            DW_OP_PICK => LocationOp::Pick(read_u8(expr, &mut off)?),
            DW_OP_SWAP => LocationOp::Swap,
            DW_OP_ROT => LocationOp::Rot,
            DW_OP_XDEREF => LocationOp::Deref,
            DW_OP_ABS => LocationOp::Abs,
            DW_OP_AND => LocationOp::And,
            DW_OP_DIV => LocationOp::Div,
            DW_OP_MINUS => LocationOp::Minus,
            DW_OP_MOD => LocationOp::Mod,
            DW_OP_MUL => LocationOp::Mul,
            DW_OP_NEG => LocationOp::Neg,
            DW_OP_NOT => LocationOp::Not,
            DW_OP_OR => LocationOp::Or,
            DW_OP_PLUS => LocationOp::Plus,
            DW_OP_PLUS_UCONST => LocationOp::PlusUconst(read_uleb128(expr, &mut off)?),
            DW_OP_SHL => LocationOp::Shl,
            DW_OP_SHR => LocationOp::Shr,
            DW_OP_SHRA => LocationOp::Shra,
            DW_OP_XOR => LocationOp::Xor,
            DW_OP_SKIP => {
                let d = read_u16_le(expr, &mut off)?.cast_signed();
                LocationOp::Skip(d)
            }
            DW_OP_BRA => {
                let d = read_u16_le(expr, &mut off)?.cast_signed();
                LocationOp::Bra(d)
            }
            DW_OP_EQ => LocationOp::Eq,
            DW_OP_GE => LocationOp::Ge,
            DW_OP_GT => LocationOp::Gt,
            DW_OP_LE => LocationOp::Le,
            DW_OP_LT => LocationOp::Lt,
            DW_OP_NE => LocationOp::Ne,
            o if (DW_OP_LIT0..=DW_OP_LIT31).contains(&o) => LocationOp::Lit(o - DW_OP_LIT0),
            o if (DW_OP_REG0..=DW_OP_REG31).contains(&o) => {
                LocationOp::Reg(u32::from(o - DW_OP_REG0))
            }
            // Saturating, not narrowing: a truncated register number would
            // impersonate a real register.
            DW_OP_REGX => LocationOp::Reg(
                u32::try_from(read_uleb128(expr, &mut off)?).unwrap_or(u32::MAX),
            ),
            // DW_OP_NOP shares opcode 0x96 with DW_OP_BREG31 in the DWARF
            // specification. We treat 0x96 as NOP (no operand consumed) so
            // that NOP bytes are not misinterpreted as BREG31 with a spurious
            // SLEB128 operand.  This means DW_OP_breg31 is not supported, but
            // DW_OP_breg31 is extremely rare in practice (r31 is unused on
            // most ABIs).
            DW_OP_NOP => LocationOp::Nop,
            o if (DW_OP_BREG0..=DW_OP_BREG31).contains(&o) => {
                let r = u32::from(o - DW_OP_BREG0);
                let off_val = read_sleb128(expr, &mut off)?;
                LocationOp::BReg(r, off_val)
            }
            DW_OP_FBREG => {
                let o = read_sleb128(expr, &mut off)?;
                LocationOp::FbReg(o)
            }
            DW_OP_BREGX => {
                let r = u32::try_from(read_uleb128(expr, &mut off)?).unwrap_or(u32::MAX);
                let o = read_sleb128(expr, &mut off)?;
                LocationOp::BReg(r, o)
            }
            DW_OP_PIECE => LocationOp::Piece(read_uleb128(expr, &mut off)?),
            DW_OP_BIT_PIECE => {
                let size = read_uleb128(expr, &mut off)?;
                let offset = read_uleb128(expr, &mut off)?;
                LocationOp::BitPiece { size, offset }
            }
            DW_OP_IMPLICIT_VALUE => {
                // A block length that does not fit usize is truncated data,
                // not a readable block.
                let len = usize::try_from(read_uleb128(expr, &mut off)?)
                    .map_err(|_| LocationError::Truncated(off))?;
                let bytes = expr.get(off..off.saturating_add(len)).unwrap_or(&[]).to_vec();
                off = off.saturating_add(len);
                LocationOp::ImplicitValue(bytes)
            }
            DW_OP_STACK_VALUE => LocationOp::StackValue,
            DW_OP_CALL_FRAME_CFA => LocationOp::CallFrameCfa,
            DW_OP_PUSH_OBJECT_ADDRESS => LocationOp::PushObjectAddress,
            DW_OP_CALL2 => { read_u16_le(expr, &mut off)?; LocationOp::Nop }
            DW_OP_CALL4 => { read_u32_le(expr, &mut off)?; LocationOp::Nop }
            DW_OP_CALL_REF => {
                // Skip ref (size depends on DWARF64/32 — assume 4)
                read_u32_le(expr, &mut off)?;
                LocationOp::Nop
            }
            DW_OP_FORM_TLS_ADDRESS | DW_OP_GNU_PUSH_TLS_ADDRESS => {
                LocationOp::GnuPushTlsAddress
            }
            // DWARF5 typed ops — skip operands
            DW_OP_CONST_TYPE | DW_OP_GNU_CONST_TYPE => {
                let _base_type = read_uleb128(expr, &mut off)?;
                let size = read_u8(expr, &mut off)? as usize;
                off += size;
                LocationOp::Nop
            }
            DW_OP_REGVAL_TYPE | DW_OP_GNU_REGVAL_TYPE => {
                read_uleb128(expr, &mut off)?;
                read_uleb128(expr, &mut off)?;
                LocationOp::Nop
            }
            DW_OP_DEREF_TYPE | DW_OP_GNU_DEREF_TYPE => {
                read_u8(expr, &mut off)?;
                read_uleb128(expr, &mut off)?;
                LocationOp::Nop
            }
            DW_OP_XDEREF_TYPE => {
                read_u8(expr, &mut off)?;
                read_uleb128(expr, &mut off)?;
                LocationOp::Nop
            }
            DW_OP_CONVERT | DW_OP_GNU_CONVERT | DW_OP_REINTERPRET | DW_OP_GNU_REINTERPRET => {
                read_uleb128(expr, &mut off)?;
                LocationOp::Nop
            }
            DW_OP_GNU_ENTRY_VALUE | DW_OP_ENTRY_VALUE => {
                // A block length that does not fit usize is truncated data,
                // not a readable block.
                let len = usize::try_from(read_uleb128(expr, &mut off)?)
                    .map_err(|_| LocationError::Truncated(off))?;
                off = off.saturating_add(len);
                LocationOp::Nop
            }
            DW_OP_IMPLICIT_POINTER | DW_OP_GNU_IMPLICIT_POINTER => {
                read_u32_le(expr, &mut off)?;
                read_sleb128(expr, &mut off)?;
                LocationOp::Nop
            }
            DW_OP_ADDRX | DW_OP_CONSTX => {
                read_uleb128(expr, &mut off)?;
                LocationOp::Nop
            }
            _ => LocationOp::Unknown(opcode),
        };
        ops.push(op);
    }

    Ok(ops)
}

// ── Simple evaluator ──────────────────────────────────────────────────────────

/// The result of evaluating a location expression.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LocationResult {
    /// Value is at this memory address.
    Address(u64),
    /// Value is in this register.
    Register(u32),
    /// Value is `[register + offset]`.
    RegisterOffset(u32, i64),
    /// Value is a compile-time constant.
    Constant(i64),
    /// Value is on the DWARF stack (`DW_OP_stack_value`).
    StackTop(i64),
    /// CFA-relative.
    CfaOffset(i64),
    /// Could not be resolved.
    Unknown,
}

/// Evaluation context providing register values and CFA.
pub struct EvalContext {
    /// Register file indexed by DWARF register number (used by `DW_OP_reg*`/`DW_OP_breg*`).
    pub registers: Vec<u64>,
    /// Frame base for `DW_OP_fbreg` (typically the evaluated `DW_AT_frame_base`).
    pub frame_base: u64,
    /// Canonical frame address for `DW_OP_call_frame_cfa`.
    pub cfa: u64,
    /// Containing object address for `DW_OP_push_object_address`.
    pub object_address: u64,
}

impl Default for EvalContext {
    fn default() -> Self {
        Self {
            registers: vec![0u64; 32],
            frame_base: 0,
            cfa: 0,
            object_address: 0,
        }
    }
}

/// Evaluate a parsed location expression given a context.
///
/// # Errors
/// Returns an error on stack underflow, division by zero, or loop limit.
pub fn evaluate_location(
    ops: &[LocationOp],
    ctx: &EvalContext,
) -> Result<LocationResult> {
    const MAX_STEPS: usize = 10_000;
    let mut stack: Vec<i64> = Vec::new();
    let mut i = 0usize;
    let mut steps = 0usize;

    macro_rules! pop {
        () => {{
            stack.pop().ok_or(LocationError::StackUnderflow)?
        }};
    }

    while i < ops.len() {
        steps += 1;
        if steps > MAX_STEPS {
            return Err(LocationError::LimitExceeded);
        }
        match &ops[i] {
            LocationOp::Addr(a) => stack.push((*a).cast_signed()),
            LocationOp::Const(v) => stack.push(*v),
            LocationOp::Lit(n) => stack.push(i64::from(*n)),
            LocationOp::Dup => {
                let top = *stack.last().ok_or(LocationError::StackUnderflow)?;
                stack.push(top);
            }
            LocationOp::Drop => { pop!(); }
            LocationOp::Over => {
                if stack.len() < 2 {
                    return Err(LocationError::StackUnderflow);
                }
                let v = stack[stack.len() - 2];
                stack.push(v);
            }
            LocationOp::Pick(n) => {
                let idx = *n as usize;
                if idx >= stack.len() {
                    return Err(LocationError::StackUnderflow);
                }
                let v = stack[stack.len() - 1 - idx];
                stack.push(v);
            }
            LocationOp::Swap => {
                if stack.len() < 2 {
                    return Err(LocationError::StackUnderflow);
                }
                let len = stack.len();
                stack.swap(len - 1, len - 2);
            }
            LocationOp::Rot => {
                if stack.len() < 3 {
                    return Err(LocationError::StackUnderflow);
                }
                let a = pop!();
                let b = pop!();
                let c = pop!();
                stack.push(a);
                stack.push(c);
                stack.push(b);
            }
            LocationOp::Abs => {
                let v = pop!();
                stack.push(v.abs());
            }
            LocationOp::And => { let b = pop!(); let a = pop!(); stack.push(a & b); }
            LocationOp::Div => {
                let b = pop!();
                if b == 0 { return Err(LocationError::DivisionByZero); }
                let a = pop!();
                stack.push(a / b);
            }
            LocationOp::Minus => { let b = pop!(); let a = pop!(); stack.push(a.wrapping_sub(b)); }
            LocationOp::Mod => {
                let b = pop!();
                if b == 0 { return Err(LocationError::DivisionByZero); }
                let a = pop!();
                stack.push(a % b);
            }
            LocationOp::Mul => { let b = pop!(); let a = pop!(); stack.push(a.wrapping_mul(b)); }
            LocationOp::Neg => { let v = pop!(); stack.push(v.wrapping_neg()); }
            LocationOp::Not => { let v = pop!(); stack.push(!v); }
            LocationOp::Or => { let b = pop!(); let a = pop!(); stack.push(a | b); }
            LocationOp::Plus => { let b = pop!(); let a = pop!(); stack.push(a.wrapping_add(b)); }
            LocationOp::PlusUconst(u) => {
                let a = pop!();
                stack.push(a.wrapping_add((*u).cast_signed()));
            }
            LocationOp::Shl => { let b = pop!(); let a = pop!(); stack.push(a.wrapping_shl(b as u32 & 63)); }
            LocationOp::Shr => {
                let b = pop!();
                let a = pop!();
                stack.push((a.cast_unsigned().wrapping_shr(b as u32 & 63)).cast_signed());
            }
            LocationOp::Shra => { let b = pop!(); let a = pop!(); stack.push(a.wrapping_shr(b as u32 & 63)); }
            LocationOp::Xor => { let b = pop!(); let a = pop!(); stack.push(a ^ b); }
            LocationOp::Eq => { let b = pop!(); let a = pop!(); stack.push(i64::from(a == b)); }
            LocationOp::Ge => { let b = pop!(); let a = pop!(); stack.push(i64::from(a >= b)); }
            LocationOp::Gt => { let b = pop!(); let a = pop!(); stack.push(i64::from(a > b)); }
            LocationOp::Le => { let b = pop!(); let a = pop!(); stack.push(i64::from(a <= b)); }
            LocationOp::Lt => { let b = pop!(); let a = pop!(); stack.push(i64::from(a < b)); }
            LocationOp::Ne => { let b = pop!(); let a = pop!(); stack.push(i64::from(a != b)); }
            LocationOp::Skip(delta) => {
                // A negative target used to wrap to a huge usize and get
                // clamped to `ops.len()`. try_from makes that explicit and
                // keeps the behaviour identical: an out-of-range branch ends
                // the expression rather than jumping backwards.
                let target = usize::try_from(i as i64 + 1 + i64::from(*delta))
                    .unwrap_or_else(|_| ops.len());
                i = target.min(ops.len());
                continue;
            }
            LocationOp::Bra(delta) => {
                let cond = pop!();
                if cond != 0 {
                    // Same clamp-on-out-of-range as DW_OP_skip above.
                    let target = usize::try_from(i as i64 + 1 + i64::from(*delta))
                        .unwrap_or_else(|_| ops.len());
                    i = target.min(ops.len());
                    continue;
                }
            }
            LocationOp::Reg(r) => {
                // Record the register's current value on the stack so callers
                // who inspect `stack` post-mortem can see the live snapshot,
                // then return the register handle as the location.
                let val = ctx.registers.get(*r as usize).copied().unwrap_or(0);
                stack.push(val.cast_signed());
                // Reg means value IS in the register — return immediately
                return Ok(LocationResult::Register(*r));
            }
            LocationOp::BReg(r, off) => {
                let base = ctx.registers.get(*r as usize).copied().unwrap_or(0).cast_signed();
                stack.push(base.wrapping_add(*off));
            }
            LocationOp::FbReg(off) => {
                stack.push(ctx.frame_base.cast_signed() + off);
            }
            LocationOp::CallFrameCfa => {
                stack.push(ctx.cfa.cast_signed());
            }
            LocationOp::PushObjectAddress => {
                stack.push(ctx.object_address.cast_signed());
            }
            LocationOp::StackValue => {
                let top = stack.last().copied().unwrap_or(0);
                return Ok(LocationResult::StackTop(top));
            }
            LocationOp::Piece(_) | LocationOp::BitPiece { .. } => {
                // Multi-piece: return what's on the stack if anything.
                break;
            }
            LocationOp::Deref => {
                // Cannot dereference without memory access — stop here.
                break;
            }
            LocationOp::Nop | LocationOp::GnuPushTlsAddress => {}
            LocationOp::Unknown(_) => break,
            _ => {}
        }
        i += 1;
    }

    if let Some(&top) = stack.last() {
        Ok(LocationResult::Address(top.cast_unsigned()))
    } else {
        Ok(LocationResult::Unknown)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(ops: &[LocationOp]) -> LocationResult {
        evaluate_location(ops, &EvalContext::default()).unwrap()
    }

    #[test]
    fn test_parse_reg0() {
        let expr = [DW_OP_REG0];
        let ops = parse_location_expr(&expr, 8).unwrap();
        assert_eq!(ops, vec![LocationOp::Reg(0)]);
    }

    #[test]
    fn test_parse_breg5_offset() {
        let mut expr = vec![DW_OP_BREG0 + 5]; // rbp
        // SLEB128 -8
        expr.push(0x78);
        let ops = parse_location_expr(&expr, 8).unwrap();
        assert_eq!(ops, vec![LocationOp::BReg(5, -8)]);
    }

    #[test]
    fn test_parse_fbreg() {
        let mut expr = vec![DW_OP_FBREG];
        expr.push(0x70); // SLEB128 -16
        let ops = parse_location_expr(&expr, 8).unwrap();
        assert!(matches!(ops[0], LocationOp::FbReg(-16)));
    }

    #[test]
    fn test_parse_const4u() {
        let mut expr = vec![DW_OP_CONST4U];
        expr.extend_from_slice(&42u32.to_le_bytes());
        let ops = parse_location_expr(&expr, 8).unwrap();
        assert_eq!(ops, vec![LocationOp::Const(42)]);
    }

    #[test]
    fn test_parse_lit7() {
        let expr = [DW_OP_LIT0 + 7];
        let ops = parse_location_expr(&expr, 8).unwrap();
        assert_eq!(ops, vec![LocationOp::Lit(7)]);
    }

    #[test]
    fn test_eval_addr() {
        let ops = vec![LocationOp::Addr(0xDEAD_BEEF)];
        assert_eq!(eval(&ops), LocationResult::Address(0xDEAD_BEEF));
    }

    #[test]
    fn test_eval_plus_uconst() {
        let ops = vec![LocationOp::Addr(0x1000), LocationOp::PlusUconst(8)];
        assert_eq!(eval(&ops), LocationResult::Address(0x1008));
    }

    #[test]
    fn test_eval_arithmetic() {
        // (3 + 4) * 2 = 14
        let ops = vec![
            LocationOp::Const(3),
            LocationOp::Const(4),
            LocationOp::Plus,
            LocationOp::Const(2),
            LocationOp::Mul,
        ];
        assert_eq!(eval(&ops), LocationResult::Address(14));
    }

    #[test]
    fn test_eval_stack_value() {
        let ops = vec![LocationOp::Const(42), LocationOp::StackValue];
        assert_eq!(eval(&ops), LocationResult::StackTop(42));
    }

    #[test]
    fn test_eval_register() {
        let ops = vec![LocationOp::Reg(5)];
        assert_eq!(eval(&ops), LocationResult::Register(5));
    }

    #[test]
    fn test_eval_div_by_zero() {
        let ops = vec![LocationOp::Const(1), LocationOp::Const(0), LocationOp::Div];
        assert!(evaluate_location(&ops, &EvalContext::default()).is_err());
    }

    #[test]
    fn test_eval_dup_over() {
        // dup: [5, 5]  over: [5, 5, 5]  minus: [5, 0]  → top of stack is 0
        // (DWARF Minus pops b, pops a, pushes a-b.)
        let ops = vec![
            LocationOp::Const(5),
            LocationOp::Dup,
            LocationOp::Over,
            LocationOp::Minus,
        ];
        if let LocationResult::Address(v) = eval(&ops) { assert_eq!(v, 0) }
    }

    #[test]
    fn test_parse_piece() {
        let expr = vec![DW_OP_PIECE, 4]; // 4-byte piece (ULEB128 4)
        let ops = parse_location_expr(&expr, 8).unwrap();
        assert!(matches!(ops[0], LocationOp::Piece(4)));
    }

    #[test]
    fn test_parse_nop() {
        let expr = [DW_OP_NOP];
        let ops = parse_location_expr(&expr, 8).unwrap();
        assert_eq!(ops, vec![LocationOp::Nop]);
    }

    #[test]
    fn test_display_breg() {
        let op = LocationOp::BReg(6, -16);
        assert!(op.to_string().contains("breg6"));
    }
}
