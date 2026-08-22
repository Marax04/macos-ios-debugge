//! `rustre-arch-jvm::wide_opcodes`
//!
//! Extended JVM opcode coverage: wide prefix (0xC4), full invoke decode,
//! TABLESWITCH/LOOKUPSWITCH with position-aware padding, MULTIANEWARRAY, and
//! a public `decode_jvm_insn()` entry point that wraps the main decoder with
//! richer operand formatting.

use crate::{JvmDecodeError, JvmInstr};
use rustre_core::arch::InstrFlags;

// ─────────────────────────────────────────────────────────────────────────────
// Re-export so callers can use this module without going through lib
// ─────────────────────────────────────────────────────────────────────────────

/// Decode one JVM instruction from `bytes` starting at `pc_offset` within the
/// method bytecode array.
///
/// `pc_offset` is needed to correctly compute the alignment padding bytes for
/// `tableswitch` and `lookupswitch`, which pad to the next multiple of 4 from
/// the **beginning of the method**.
///
/// # Errors
///
/// Returns [`JvmDecodeError::Truncated`] when the slice is too short,
/// [`JvmDecodeError::Reserved`] for opcodes in `0xca..=0xff`,
/// or [`JvmDecodeError::UnknownOpcode`] for invalid wide sub-opcodes.
pub fn decode_jvm_insn(
    bytes: &[u8],
    pc_offset: usize,
) -> Result<(JvmInstr, usize), JvmDecodeError> {
    if bytes.is_empty() {
        return Err(JvmDecodeError::Truncated);
    }
    let op = bytes[0];
    match op {
        0xaa => decode_tableswitch(bytes, pc_offset),
        0xab => decode_lookupswitch(bytes, pc_offset),
        0xc4 => decode_wide(bytes),
        0xc5 => decode_multianewarray(bytes),
        0xb6 => decode_invokevirtual(bytes),
        0xb7 => decode_invokespecial(bytes),
        0xb8 => decode_invokestatic(bytes),
        0xb9 => decode_invokeinterface(bytes),
        0xba => decode_invokedynamic(bytes),
        0xca..=0xff => Err(JvmDecodeError::Reserved(op)),
        _ => JvmInstr::decode_at(bytes, pc_offset),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wide prefix (0xC4)
// ─────────────────────────────────────────────────────────────────────────────

/// Decode the wide prefix instruction `0xC4 <sub_op> <u16_index>` or
/// `0xC4 0x84 <u16_index> <i16_const>` (wide iinc).
///
/// # Errors
///
/// Returns an error when the input is malformed or an index is out of range.
pub fn decode_wide(bytes: &[u8]) -> Result<(JvmInstr, usize), JvmDecodeError> {
    need(bytes, 2)?;
    let sub = bytes[1];
    let raw2 = |off: usize| u16::from_be_bytes([bytes[off], bytes[off + 1]]);
    let si16 = |off: usize| i16::from_be_bytes([bytes[off], bytes[off + 1]]);

    match sub {
        // wide iload
        0x15 => {
            need(bytes, 4)?;
            ok_wide(
                "wide iload",
                format!("{}", raw2(2)),
                InstrFlags::NONE,
                bytes[..4].to_vec(),
            )
        }
        // wide lload
        0x16 => {
            need(bytes, 4)?;
            ok_wide(
                "wide lload",
                format!("{}", raw2(2)),
                InstrFlags::NONE,
                bytes[..4].to_vec(),
            )
        }
        // wide fload
        0x17 => {
            need(bytes, 4)?;
            ok_wide(
                "wide fload",
                format!("{}", raw2(2)),
                InstrFlags::NONE,
                bytes[..4].to_vec(),
            )
        }
        // wide dload
        0x18 => {
            need(bytes, 4)?;
            ok_wide(
                "wide dload",
                format!("{}", raw2(2)),
                InstrFlags::NONE,
                bytes[..4].to_vec(),
            )
        }
        // wide aload
        0x19 => {
            need(bytes, 4)?;
            ok_wide(
                "wide aload",
                format!("{}", raw2(2)),
                InstrFlags::NONE,
                bytes[..4].to_vec(),
            )
        }
        // wide istore
        0x36 => {
            need(bytes, 4)?;
            ok_wide(
                "wide istore",
                format!("{}", raw2(2)),
                InstrFlags::NONE,
                bytes[..4].to_vec(),
            )
        }
        // wide lstore
        0x37 => {
            need(bytes, 4)?;
            ok_wide(
                "wide lstore",
                format!("{}", raw2(2)),
                InstrFlags::NONE,
                bytes[..4].to_vec(),
            )
        }
        // wide fstore
        0x38 => {
            need(bytes, 4)?;
            ok_wide(
                "wide fstore",
                format!("{}", raw2(2)),
                InstrFlags::NONE,
                bytes[..4].to_vec(),
            )
        }
        // wide dstore
        0x39 => {
            need(bytes, 4)?;
            ok_wide(
                "wide dstore",
                format!("{}", raw2(2)),
                InstrFlags::NONE,
                bytes[..4].to_vec(),
            )
        }
        // wide astore
        0x3a => {
            need(bytes, 4)?;
            ok_wide(
                "wide astore",
                format!("{}", raw2(2)),
                InstrFlags::NONE,
                bytes[..4].to_vec(),
            )
        }
        // wide ret
        0xa9 => {
            need(bytes, 4)?;
            ok_wide(
                "wide ret",
                format!("{}", raw2(2)),
                InstrFlags::RET,
                bytes[..4].to_vec(),
            )
        }
        // wide iinc: op + sub + u16_index + i16_const = 6 bytes
        0x84 => {
            need(bytes, 6)?;
            ok_wide(
                "wide iinc",
                format!("{}, {}", raw2(2), si16(4)),
                InstrFlags::NONE,
                bytes[..6].to_vec(),
            )
        }
        _ => Err(JvmDecodeError::UnknownOpcode(sub)),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TABLESWITCH (0xAA)
// ─────────────────────────────────────────────────────────────────────────────

/// Decode `tableswitch` using proper alignment relative to `pc_offset`.
///
/// The instruction layout (JVM §6.5.tableswitch):
/// ```text
/// tableswitch
/// <0–3 byte pad to align to 4-byte boundary from instruction start>
/// defaultbyte1 defaultbyte2 defaultbyte3 defaultbyte4
/// lowbyte1..4
/// highbyte1..4
/// offsets[high - low + 1] × 4 bytes each
/// ```
///
/// # Errors
///
/// Returns an error when the input is malformed or an index is out of range.
pub fn decode_tableswitch(
    bytes: &[u8],
    pc_offset: usize,
) -> Result<(JvmInstr, usize), JvmDecodeError> {
    if bytes.is_empty() {
        return Err(JvmDecodeError::Truncated);
    }
    // Number of pad bytes so that (pc_offset + 1 + pad) ≡ 0 (mod 4)
    let pad = (4 - ((pc_offset + 1) % 4)) % 4;
    let base = 1 + pad;
    need(bytes, base + 12)?;

    let i32be = |off: usize| {
        i32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
    };
    let default_off = i32be(base);
    let low = i32be(base + 4);
    let high = i32be(base + 8);
    let count = usize::try_from(i64::from(high) - i64::from(low) + 1).unwrap_or(0);
    let total = base
        .checked_add(12)
        .and_then(|b| count.checked_mul(4).and_then(|c| b.checked_add(c)))
        .ok_or(JvmDecodeError::Truncated)?;
    need(bytes, total)?;

    // Collect branch offsets for richer operand string
    let mut offsets = Vec::with_capacity(count);
    for i in 0..count {
        offsets.push(i32be(base + 12 + i * 4));
    }

    let ops = format!(
        "low={low} high={high} default={default_off} offsets=[{}]",
        offsets
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );

    Ok((
        JvmInstr {
            raw: bytes[..total].to_vec(),
            mnemonic: "tableswitch".to_string(),
            operands: ops,
            flags: InstrFlags::BRANCH,
        },
        total,
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// LOOKUPSWITCH (0xAB)
// ─────────────────────────────────────────────────────────────────────────────

/// Decode `lookupswitch` with proper position-aware alignment.
///
/// # Errors
///
/// Returns an error when the input is malformed or an index is out of range.
pub fn decode_lookupswitch(
    bytes: &[u8],
    pc_offset: usize,
) -> Result<(JvmInstr, usize), JvmDecodeError> {
    if bytes.is_empty() {
        return Err(JvmDecodeError::Truncated);
    }
    let pad = (4 - ((pc_offset + 1) % 4)) % 4;
    let base = 1 + pad;
    need(bytes, base + 8)?;

    let i32be = |off: usize| {
        i32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
    };
    let default_off = i32be(base);
    let npairs = u32::try_from(i32be(base + 4).max(0)).unwrap_or(0) as usize;
    let total = npairs
        .checked_mul(8)
        .and_then(|n| n.checked_add(base + 8))
        .ok_or(JvmDecodeError::Truncated)?;
    need(bytes, total)?;

    let mut pairs = Vec::with_capacity(npairs);
    for i in 0..npairs {
        let key = i32be(base + 8 + i * 8);
        let off = i32be(base + 12 + i * 8);
        pairs.push((key, off));
    }

    let pair_str = pairs
        .iter()
        .map(|(k, o)| format!("{k}:{o}"))
        .collect::<Vec<_>>()
        .join(", ");

    let ops = format!("npairs={npairs} default={default_off} [{pair_str}]");

    Ok((
        JvmInstr {
            raw: bytes[..total].to_vec(),
            mnemonic: "lookupswitch".to_string(),
            operands: ops,
            flags: InstrFlags::BRANCH,
        },
        total,
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// MULTIANEWARRAY (0xC5)
// ─────────────────────────────────────────────────────────────────────────────

/// Decode `multianewarray #cpref, dims` — 4-byte instruction.
///
/// # Errors
///
/// Returns an error when the input is malformed or an index is out of range.
pub fn decode_multianewarray(bytes: &[u8]) -> Result<(JvmInstr, usize), JvmDecodeError> {
    need(bytes, 4)?;
    let cpref = u16::from_be_bytes([bytes[1], bytes[2]]);
    let dims = bytes[3];
    Ok((
        JvmInstr {
            raw: bytes[..4].to_vec(),
            mnemonic: "multianewarray".to_string(),
            operands: format!("#{cpref}, dims={dims}"),
            flags: InstrFlags::NONE,
        },
        4,
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Invoke instructions (richer operand strings)
// ─────────────────────────────────────────────────────────────────────────────

/// Decode `invokevirtual` with symbolic annotation.
///
/// # Errors
///
/// Returns an error when the input is malformed or an index is out of range.
pub fn decode_invokevirtual(bytes: &[u8]) -> Result<(JvmInstr, usize), JvmDecodeError> {
    need(bytes, 3)?;
    let cpref = u16::from_be_bytes([bytes[1], bytes[2]]);
    Ok((
        JvmInstr {
            raw: bytes[..3].to_vec(),
            mnemonic: "invokevirtual".to_string(),
            operands: format!("#{cpref}"),
            flags: InstrFlags::CALL | InstrFlags::INDIRECT,
        },
        3,
    ))
}

/// Decode `invokespecial`.
///
/// # Errors
///
/// Returns an error when the input is malformed or an index is out of range.
pub fn decode_invokespecial(bytes: &[u8]) -> Result<(JvmInstr, usize), JvmDecodeError> {
    need(bytes, 3)?;
    let cpref = u16::from_be_bytes([bytes[1], bytes[2]]);
    Ok((
        JvmInstr {
            raw: bytes[..3].to_vec(),
            mnemonic: "invokespecial".to_string(),
            operands: format!("#{cpref}"),
            flags: InstrFlags::CALL,
        },
        3,
    ))
}

/// Decode `invokestatic`.
///
/// # Errors
///
/// Returns an error when the input is malformed or an index is out of range.
pub fn decode_invokestatic(bytes: &[u8]) -> Result<(JvmInstr, usize), JvmDecodeError> {
    need(bytes, 3)?;
    let cpref = u16::from_be_bytes([bytes[1], bytes[2]]);
    Ok((
        JvmInstr {
            raw: bytes[..3].to_vec(),
            mnemonic: "invokestatic".to_string(),
            operands: format!("#{cpref}"),
            flags: InstrFlags::CALL,
        },
        3,
    ))
}

/// Decode `invokeinterface` — 5 bytes: opcode + cpref(2) + count + 0.
///
/// # Errors
///
/// Returns an error when the input is malformed or an index is out of range.
pub fn decode_invokeinterface(bytes: &[u8]) -> Result<(JvmInstr, usize), JvmDecodeError> {
    need(bytes, 5)?;
    let cpref = u16::from_be_bytes([bytes[1], bytes[2]]);
    let count = bytes[3];
    Ok((
        JvmInstr {
            raw: bytes[..5].to_vec(),
            mnemonic: "invokeinterface".to_string(),
            operands: format!("#{cpref} count={count}"),
            flags: InstrFlags::CALL | InstrFlags::INDIRECT,
        },
        5,
    ))
}

/// Decode `invokedynamic` — 5 bytes: opcode + cpref(2) + 0 + 0.
///
/// # Errors
///
/// Returns an error when the input is malformed or an index is out of range.
pub fn decode_invokedynamic(bytes: &[u8]) -> Result<(JvmInstr, usize), JvmDecodeError> {
    need(bytes, 5)?;
    let cpref = u16::from_be_bytes([bytes[1], bytes[2]]);
    Ok((
        JvmInstr {
            raw: bytes[..5].to_vec(),
            mnemonic: "invokedynamic".to_string(),
            operands: format!("#{cpref}"),
            flags: InstrFlags::CALL | InstrFlags::INDIRECT,
        },
        5,
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// OpcodeMeta — full 200-entry coverage table
// ─────────────────────────────────────────────────────────────────────────────

/// Static metadata for every defined JVM opcode byte value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpcodeMeta {
    pub opcode: u8,
    pub mnemonic: &'static str,
    /// Fixed instruction length in bytes (0 = variable).
    pub fixed_len: u8,
    /// Net JVM operand stack effect.
    pub stack_delta: i8,
    /// True when this opcode can transfer control.
    pub is_control: bool,
}

impl OpcodeMeta {
    /// Look up the metadata for `opcode`.  Returns `None` for reserved codes.
    #[must_use]
    pub fn lookup(opcode: u8) -> Option<&'static Self> {
        OPCODE_META_TABLE.iter().find(|m| m.opcode == opcode)
    }

    /// Returns `true` when the opcode is an invoke-family instruction.
    #[must_use]
    pub const fn is_invoke(self) -> bool {
        matches!(self.opcode, 0xb6..=0xba)
    }

    /// Returns `true` when the opcode is a conditional branch.
    #[must_use]
    pub const fn is_conditional_branch(self) -> bool {
        matches!(self.opcode, 0x99..=0xa6 | 0xaa | 0xab | 0xc6 | 0xc7)
    }

    /// Returns `true` when the opcode is a return instruction.
    #[must_use]
    pub const fn is_return(self) -> bool {
        matches!(self.opcode, 0xac..=0xb1)
    }

    /// Returns `true` when the opcode involves object creation.
    #[must_use]
    pub const fn is_allocation(self) -> bool {
        matches!(self.opcode, 0xbb | 0xbc | 0xbd | 0xc5)
    }
}

/// Full JVM opcode metadata table (all ~200 defined opcodes).
static OPCODE_META_TABLE: &[OpcodeMeta] = &[
    // ── Constants ─────────────────────────────────────────────────────────────
    OpcodeMeta {
        opcode: 0x00,
        mnemonic: "nop",
        fixed_len: 1,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x01,
        mnemonic: "aconst_null",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x02,
        mnemonic: "iconst_m1",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x03,
        mnemonic: "iconst_0",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x04,
        mnemonic: "iconst_1",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x05,
        mnemonic: "iconst_2",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x06,
        mnemonic: "iconst_3",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x07,
        mnemonic: "iconst_4",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x08,
        mnemonic: "iconst_5",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x09,
        mnemonic: "lconst_0",
        fixed_len: 1,
        stack_delta: 2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x0a,
        mnemonic: "lconst_1",
        fixed_len: 1,
        stack_delta: 2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x0b,
        mnemonic: "fconst_0",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x0c,
        mnemonic: "fconst_1",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x0d,
        mnemonic: "fconst_2",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x0e,
        mnemonic: "dconst_0",
        fixed_len: 1,
        stack_delta: 2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x0f,
        mnemonic: "dconst_1",
        fixed_len: 1,
        stack_delta: 2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x10,
        mnemonic: "bipush",
        fixed_len: 2,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x11,
        mnemonic: "sipush",
        fixed_len: 3,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x12,
        mnemonic: "ldc",
        fixed_len: 2,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x13,
        mnemonic: "ldc_w",
        fixed_len: 3,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x14,
        mnemonic: "ldc2_w",
        fixed_len: 3,
        stack_delta: 2,
        is_control: false,
    },
    // ── Loads ─────────────────────────────────────────────────────────────────
    OpcodeMeta {
        opcode: 0x15,
        mnemonic: "iload",
        fixed_len: 2,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x16,
        mnemonic: "lload",
        fixed_len: 2,
        stack_delta: 2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x17,
        mnemonic: "fload",
        fixed_len: 2,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x18,
        mnemonic: "dload",
        fixed_len: 2,
        stack_delta: 2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x19,
        mnemonic: "aload",
        fixed_len: 2,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x1a,
        mnemonic: "iload_0",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x1b,
        mnemonic: "iload_1",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x1c,
        mnemonic: "iload_2",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x1d,
        mnemonic: "iload_3",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x1e,
        mnemonic: "lload_0",
        fixed_len: 1,
        stack_delta: 2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x1f,
        mnemonic: "lload_1",
        fixed_len: 1,
        stack_delta: 2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x20,
        mnemonic: "lload_2",
        fixed_len: 1,
        stack_delta: 2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x21,
        mnemonic: "lload_3",
        fixed_len: 1,
        stack_delta: 2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x22,
        mnemonic: "fload_0",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x23,
        mnemonic: "fload_1",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x24,
        mnemonic: "fload_2",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x25,
        mnemonic: "fload_3",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x26,
        mnemonic: "dload_0",
        fixed_len: 1,
        stack_delta: 2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x27,
        mnemonic: "dload_1",
        fixed_len: 1,
        stack_delta: 2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x28,
        mnemonic: "dload_2",
        fixed_len: 1,
        stack_delta: 2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x29,
        mnemonic: "dload_3",
        fixed_len: 1,
        stack_delta: 2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x2a,
        mnemonic: "aload_0",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x2b,
        mnemonic: "aload_1",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x2c,
        mnemonic: "aload_2",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x2d,
        mnemonic: "aload_3",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x2e,
        mnemonic: "iaload",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x2f,
        mnemonic: "laload",
        fixed_len: 1,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x30,
        mnemonic: "faload",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x31,
        mnemonic: "daload",
        fixed_len: 1,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x32,
        mnemonic: "aaload",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x33,
        mnemonic: "baload",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x34,
        mnemonic: "caload",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x35,
        mnemonic: "saload",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    // ── Stores ─────────────────────────────────────────────────────────────────
    OpcodeMeta {
        opcode: 0x36,
        mnemonic: "istore",
        fixed_len: 2,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x37,
        mnemonic: "lstore",
        fixed_len: 2,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x38,
        mnemonic: "fstore",
        fixed_len: 2,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x39,
        mnemonic: "dstore",
        fixed_len: 2,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x3a,
        mnemonic: "astore",
        fixed_len: 2,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x3b,
        mnemonic: "istore_0",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x3c,
        mnemonic: "istore_1",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x3d,
        mnemonic: "istore_2",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x3e,
        mnemonic: "istore_3",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x3f,
        mnemonic: "lstore_0",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x40,
        mnemonic: "lstore_1",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x41,
        mnemonic: "lstore_2",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x42,
        mnemonic: "lstore_3",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x43,
        mnemonic: "fstore_0",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x44,
        mnemonic: "fstore_1",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x45,
        mnemonic: "fstore_2",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x46,
        mnemonic: "fstore_3",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x47,
        mnemonic: "dstore_0",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x48,
        mnemonic: "dstore_1",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x49,
        mnemonic: "dstore_2",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x4a,
        mnemonic: "dstore_3",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x4b,
        mnemonic: "astore_0",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x4c,
        mnemonic: "astore_1",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x4d,
        mnemonic: "astore_2",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x4e,
        mnemonic: "astore_3",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x4f,
        mnemonic: "iastore",
        fixed_len: 1,
        stack_delta: -3,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x50,
        mnemonic: "lastore",
        fixed_len: 1,
        stack_delta: -4,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x51,
        mnemonic: "fastore",
        fixed_len: 1,
        stack_delta: -3,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x52,
        mnemonic: "dastore",
        fixed_len: 1,
        stack_delta: -4,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x53,
        mnemonic: "aastore",
        fixed_len: 1,
        stack_delta: -3,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x54,
        mnemonic: "bastore",
        fixed_len: 1,
        stack_delta: -3,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x55,
        mnemonic: "castore",
        fixed_len: 1,
        stack_delta: -3,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x56,
        mnemonic: "sastore",
        fixed_len: 1,
        stack_delta: -3,
        is_control: false,
    },
    // ── Stack manipulation ─────────────────────────────────────────────────────
    OpcodeMeta {
        opcode: 0x57,
        mnemonic: "pop",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x58,
        mnemonic: "pop2",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x59,
        mnemonic: "dup",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x5a,
        mnemonic: "dup_x1",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x5b,
        mnemonic: "dup_x2",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x5c,
        mnemonic: "dup2",
        fixed_len: 1,
        stack_delta: 2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x5d,
        mnemonic: "dup2_x1",
        fixed_len: 1,
        stack_delta: 2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x5e,
        mnemonic: "dup2_x2",
        fixed_len: 1,
        stack_delta: 2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x5f,
        mnemonic: "swap",
        fixed_len: 1,
        stack_delta: 0,
        is_control: false,
    },
    // ── Arithmetic ─────────────────────────────────────────────────────────────
    OpcodeMeta {
        opcode: 0x60,
        mnemonic: "iadd",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x61,
        mnemonic: "ladd",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x62,
        mnemonic: "fadd",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x63,
        mnemonic: "dadd",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x64,
        mnemonic: "isub",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x65,
        mnemonic: "lsub",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x66,
        mnemonic: "fsub",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x67,
        mnemonic: "dsub",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x68,
        mnemonic: "imul",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x69,
        mnemonic: "lmul",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x6a,
        mnemonic: "fmul",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x6b,
        mnemonic: "dmul",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x6c,
        mnemonic: "idiv",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x6d,
        mnemonic: "ldiv",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x6e,
        mnemonic: "fdiv",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x6f,
        mnemonic: "ddiv",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x70,
        mnemonic: "irem",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x71,
        mnemonic: "lrem",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x72,
        mnemonic: "frem",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x73,
        mnemonic: "drem",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x74,
        mnemonic: "ineg",
        fixed_len: 1,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x75,
        mnemonic: "lneg",
        fixed_len: 1,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x76,
        mnemonic: "fneg",
        fixed_len: 1,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x77,
        mnemonic: "dneg",
        fixed_len: 1,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x78,
        mnemonic: "ishl",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x79,
        mnemonic: "lshl",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x7a,
        mnemonic: "ishr",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x7b,
        mnemonic: "lshr",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x7c,
        mnemonic: "iushr",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x7d,
        mnemonic: "lushr",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x7e,
        mnemonic: "iand",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x7f,
        mnemonic: "land",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x80,
        mnemonic: "ior",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x81,
        mnemonic: "lor",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x82,
        mnemonic: "ixor",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x83,
        mnemonic: "lxor",
        fixed_len: 1,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x84,
        mnemonic: "iinc",
        fixed_len: 3,
        stack_delta: 0,
        is_control: false,
    },
    // ── Conversions ────────────────────────────────────────────────────────────
    OpcodeMeta {
        opcode: 0x85,
        mnemonic: "i2l",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x86,
        mnemonic: "i2f",
        fixed_len: 1,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x87,
        mnemonic: "i2d",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x88,
        mnemonic: "l2i",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x89,
        mnemonic: "l2f",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x8a,
        mnemonic: "l2d",
        fixed_len: 1,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x8b,
        mnemonic: "f2i",
        fixed_len: 1,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x8c,
        mnemonic: "f2l",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x8d,
        mnemonic: "f2d",
        fixed_len: 1,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x8e,
        mnemonic: "d2i",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x8f,
        mnemonic: "d2l",
        fixed_len: 1,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x90,
        mnemonic: "d2f",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x91,
        mnemonic: "i2b",
        fixed_len: 1,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x92,
        mnemonic: "i2c",
        fixed_len: 1,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x93,
        mnemonic: "i2s",
        fixed_len: 1,
        stack_delta: 0,
        is_control: false,
    },
    // ── Comparisons ────────────────────────────────────────────────────────────
    OpcodeMeta {
        opcode: 0x94,
        mnemonic: "lcmp",
        fixed_len: 1,
        stack_delta: -3,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x95,
        mnemonic: "fcmpl",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x96,
        mnemonic: "fcmpg",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x97,
        mnemonic: "dcmpl",
        fixed_len: 1,
        stack_delta: -3,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0x98,
        mnemonic: "dcmpg",
        fixed_len: 1,
        stack_delta: -3,
        is_control: false,
    },
    // ── Branches ───────────────────────────────────────────────────────────────
    OpcodeMeta {
        opcode: 0x99,
        mnemonic: "ifeq",
        fixed_len: 3,
        stack_delta: -1,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0x9a,
        mnemonic: "ifne",
        fixed_len: 3,
        stack_delta: -1,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0x9b,
        mnemonic: "iflt",
        fixed_len: 3,
        stack_delta: -1,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0x9c,
        mnemonic: "ifge",
        fixed_len: 3,
        stack_delta: -1,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0x9d,
        mnemonic: "ifgt",
        fixed_len: 3,
        stack_delta: -1,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0x9e,
        mnemonic: "ifle",
        fixed_len: 3,
        stack_delta: -1,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0x9f,
        mnemonic: "if_icmpeq",
        fixed_len: 3,
        stack_delta: -2,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xa0,
        mnemonic: "if_icmpne",
        fixed_len: 3,
        stack_delta: -2,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xa1,
        mnemonic: "if_icmplt",
        fixed_len: 3,
        stack_delta: -2,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xa2,
        mnemonic: "if_icmpge",
        fixed_len: 3,
        stack_delta: -2,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xa3,
        mnemonic: "if_icmpgt",
        fixed_len: 3,
        stack_delta: -2,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xa4,
        mnemonic: "if_icmple",
        fixed_len: 3,
        stack_delta: -2,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xa5,
        mnemonic: "if_acmpeq",
        fixed_len: 3,
        stack_delta: -2,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xa6,
        mnemonic: "if_acmpne",
        fixed_len: 3,
        stack_delta: -2,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xa7,
        mnemonic: "goto",
        fixed_len: 3,
        stack_delta: 0,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xa8,
        mnemonic: "jsr",
        fixed_len: 3,
        stack_delta: 1,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xa9,
        mnemonic: "ret",
        fixed_len: 2,
        stack_delta: 0,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xaa,
        mnemonic: "tableswitch",
        fixed_len: 0,
        stack_delta: -1,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xab,
        mnemonic: "lookupswitch",
        fixed_len: 0,
        stack_delta: -1,
        is_control: true,
    },
    // ── Returns ────────────────────────────────────────────────────────────────
    OpcodeMeta {
        opcode: 0xac,
        mnemonic: "ireturn",
        fixed_len: 1,
        stack_delta: -1,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xad,
        mnemonic: "lreturn",
        fixed_len: 1,
        stack_delta: -2,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xae,
        mnemonic: "freturn",
        fixed_len: 1,
        stack_delta: -1,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xaf,
        mnemonic: "dreturn",
        fixed_len: 1,
        stack_delta: -2,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xb0,
        mnemonic: "areturn",
        fixed_len: 1,
        stack_delta: -1,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xb1,
        mnemonic: "return",
        fixed_len: 1,
        stack_delta: 0,
        is_control: true,
    },
    // ── References ─────────────────────────────────────────────────────────────
    OpcodeMeta {
        opcode: 0xb2,
        mnemonic: "getstatic",
        fixed_len: 3,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0xb3,
        mnemonic: "putstatic",
        fixed_len: 3,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0xb4,
        mnemonic: "getfield",
        fixed_len: 3,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0xb5,
        mnemonic: "putfield",
        fixed_len: 3,
        stack_delta: -2,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0xb6,
        mnemonic: "invokevirtual",
        fixed_len: 3,
        stack_delta: -1,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xb7,
        mnemonic: "invokespecial",
        fixed_len: 3,
        stack_delta: -1,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xb8,
        mnemonic: "invokestatic",
        fixed_len: 3,
        stack_delta: 0,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xb9,
        mnemonic: "invokeinterface",
        fixed_len: 5,
        stack_delta: -1,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xba,
        mnemonic: "invokedynamic",
        fixed_len: 5,
        stack_delta: 0,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xbb,
        mnemonic: "new",
        fixed_len: 3,
        stack_delta: 1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0xbc,
        mnemonic: "newarray",
        fixed_len: 2,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0xbd,
        mnemonic: "anewarray",
        fixed_len: 3,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0xbe,
        mnemonic: "arraylength",
        fixed_len: 1,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0xbf,
        mnemonic: "athrow",
        fixed_len: 1,
        stack_delta: 0,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xc0,
        mnemonic: "checkcast",
        fixed_len: 3,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0xc1,
        mnemonic: "instanceof",
        fixed_len: 3,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0xc2,
        mnemonic: "monitorenter",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0xc3,
        mnemonic: "monitorexit",
        fixed_len: 1,
        stack_delta: -1,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0xc4,
        mnemonic: "wide",
        fixed_len: 0,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0xc5,
        mnemonic: "multianewarray",
        fixed_len: 4,
        stack_delta: 0,
        is_control: false,
    },
    OpcodeMeta {
        opcode: 0xc6,
        mnemonic: "ifnull",
        fixed_len: 3,
        stack_delta: -1,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xc7,
        mnemonic: "ifnonnull",
        fixed_len: 3,
        stack_delta: -1,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xc8,
        mnemonic: "goto_w",
        fixed_len: 5,
        stack_delta: 0,
        is_control: true,
    },
    OpcodeMeta {
        opcode: 0xc9,
        mnemonic: "jsr_w",
        fixed_len: 5,
        stack_delta: 1,
        is_control: true,
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const fn need(bytes: &[u8], n: usize) -> Result<(), JvmDecodeError> {
    if bytes.len() < n {
        Err(JvmDecodeError::Truncated)
    } else {
        Ok(())
    }
}

// clippy::unnecessary_wraps is left OPEN here for the same reason as `ok` in
// lib.rs: `ok_wide` is the success tail of the wide-prefix decoder arms, and
// is kept symmetrical with `ok` on purpose. See the note there.
fn ok_wide(
    mne: &str,
    ops: String,
    flags: InstrFlags,
    raw: Vec<u8>,
) -> Result<(JvmInstr, usize), JvmDecodeError> {
    let size = raw.len();
    Ok((
        JvmInstr {
            raw,
            mnemonic: mne.to_string(),
            operands: ops,
            flags,
        },
        size,
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── OpcodeMeta lookup ─────────────────────────────────────────────────────

    #[test]
    fn test_meta_nop() {
        let m = OpcodeMeta::lookup(0x00).unwrap();
        assert_eq!(m.mnemonic, "nop");
        assert_eq!(m.fixed_len, 1);
        assert_eq!(m.stack_delta, 0);
        assert!(!m.is_control);
    }

    #[test]
    fn test_meta_invokevirtual() {
        let m = OpcodeMeta::lookup(0xb6).unwrap();
        assert_eq!(m.mnemonic, "invokevirtual");
        assert!(m.is_invoke());
        assert!(m.is_control);
    }

    #[test]
    fn test_meta_ifeq_conditional() {
        let m = OpcodeMeta::lookup(0x99).unwrap();
        assert!(m.is_conditional_branch());
    }

    #[test]
    fn test_meta_return() {
        let m = OpcodeMeta::lookup(0xb1).unwrap();
        assert!(m.is_return());
    }

    #[test]
    fn test_meta_new_allocation() {
        let m = OpcodeMeta::lookup(0xbb).unwrap();
        assert!(m.is_allocation());
    }

    #[test]
    fn test_meta_tableswitch_variable_len() {
        let m = OpcodeMeta::lookup(0xaa).unwrap();
        assert_eq!(m.fixed_len, 0);
    }

    #[test]
    fn test_meta_reserved_opcode() {
        assert!(OpcodeMeta::lookup(0xca).is_none());
        assert!(OpcodeMeta::lookup(0xff).is_none());
    }

    #[test]
    fn test_meta_goto_w() {
        let m = OpcodeMeta::lookup(0xc8).unwrap();
        assert_eq!(m.mnemonic, "goto_w");
        assert_eq!(m.fixed_len, 5);
        assert!(m.is_control);
    }

    // ── decode_wide ───────────────────────────────────────────────────────────

    #[test]
    fn test_wide_iload() {
        let (i, sz) = decode_wide(&[0xc4, 0x15, 0x01, 0x00]).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(i.mnemonic, "wide iload");
        assert_eq!(i.operands, "256");
    }

    #[test]
    fn test_wide_lload() {
        let (i, sz) = decode_wide(&[0xc4, 0x16, 0x00, 0x05]).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(i.mnemonic, "wide lload");
        assert_eq!(i.operands, "5");
    }

    #[test]
    fn test_wide_fload() {
        let (i, sz) = decode_wide(&[0xc4, 0x17, 0x00, 0x0a]).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(i.mnemonic, "wide fload");
    }

    #[test]
    fn test_wide_dload() {
        let (i, sz) = decode_wide(&[0xc4, 0x18, 0x00, 0x01]).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(i.mnemonic, "wide dload");
    }

    #[test]
    fn test_wide_aload() {
        let (i, sz) = decode_wide(&[0xc4, 0x19, 0x00, 0x02]).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(i.mnemonic, "wide aload");
    }

    #[test]
    fn test_wide_istore() {
        let (i, sz) = decode_wide(&[0xc4, 0x36, 0x00, 0x03]).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(i.mnemonic, "wide istore");
    }

    #[test]
    fn test_wide_lstore() {
        let (i, sz) = decode_wide(&[0xc4, 0x37, 0x00, 0x04]).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(i.mnemonic, "wide lstore");
    }

    #[test]
    fn test_wide_fstore() {
        let (i, sz) = decode_wide(&[0xc4, 0x38, 0x00, 0x05]).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(i.mnemonic, "wide fstore");
    }

    #[test]
    fn test_wide_dstore() {
        let (i, sz) = decode_wide(&[0xc4, 0x39, 0x00, 0x06]).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(i.mnemonic, "wide dstore");
    }

    #[test]
    fn test_wide_astore() {
        let (i, sz) = decode_wide(&[0xc4, 0x3a, 0x00, 0x07]).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(i.mnemonic, "wide astore");
    }

    #[test]
    fn test_wide_ret() {
        let (i, sz) = decode_wide(&[0xc4, 0xa9, 0x00, 0x08]).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(i.mnemonic, "wide ret");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_wide_iinc() {
        let (i, sz) = decode_wide(&[0xc4, 0x84, 0x00, 0x05, 0x00, 0x03]).unwrap();
        assert_eq!(sz, 6);
        assert_eq!(i.mnemonic, "wide iinc");
        assert!(i.operands.contains('5') && i.operands.contains('3'));
    }

    #[test]
    fn test_wide_iinc_negative_const() {
        let val: i16 = -10;
        let bytes = val.to_be_bytes();
        let buf = [0xc4, 0x84, 0x00, 0x01, bytes[0], bytes[1]];
        let (i, sz) = decode_wide(&buf).unwrap();
        assert_eq!(sz, 6);
        assert!(i.operands.contains("-10"));
    }

    #[test]
    fn test_wide_truncated() {
        assert!(matches!(
            decode_wide(&[0xc4, 0x15, 0x00]),
            Err(JvmDecodeError::Truncated)
        ));
    }

    #[test]
    fn test_wide_unknown_sub_opcode() {
        assert!(matches!(
            decode_wide(&[0xc4, 0x60, 0x00, 0x00]),
            Err(JvmDecodeError::UnknownOpcode(0x60))
        ));
    }

    // ── decode_tableswitch ────────────────────────────────────────────────────

    #[test]
    fn test_tableswitch_basic() {
        // pc_offset=0: pad = (4 - (0+1)%4)%4 = 3
        let mut buf = vec![0xaa_u8, 0x00, 0x00, 0x00]; // op + 3 pad
        // default = 10 (i32 BE)
        buf.extend_from_slice(&10_i32.to_be_bytes());
        // low = 0
        buf.extend_from_slice(&0_i32.to_be_bytes());
        // high = 2 (3 entries)
        buf.extend_from_slice(&2_i32.to_be_bytes());
        buf.extend_from_slice(&5_i32.to_be_bytes());
        buf.extend_from_slice(&6_i32.to_be_bytes());
        buf.extend_from_slice(&7_i32.to_be_bytes());

        let (i, sz) = decode_tableswitch(&buf, 0).unwrap();
        assert_eq!(sz, buf.len());
        assert_eq!(i.mnemonic, "tableswitch");
        assert!(i.operands.contains("low=0"));
        assert!(i.operands.contains("high=2"));
        assert!(i.operands.contains("default=10"));
    }

    #[test]
    fn test_tableswitch_no_offsets() {
        // high < low → count = 0
        let mut buf = vec![0xaa_u8, 0x00, 0x00, 0x00];
        buf.extend_from_slice(&0_i32.to_be_bytes()); // default
        buf.extend_from_slice(&5_i32.to_be_bytes()); // low = 5
        buf.extend_from_slice(&3_i32.to_be_bytes()); // high = 3 → count = 0
        let (i, sz) = decode_tableswitch(&buf, 0).unwrap();
        assert_eq!(sz, buf.len());
        assert_eq!(i.mnemonic, "tableswitch");
    }

    #[test]
    fn test_tableswitch_truncated() {
        let buf = [0xaa_u8, 0x00, 0x00]; // too short
        assert!(matches!(
            decode_tableswitch(&buf, 0),
            Err(JvmDecodeError::Truncated)
        ));
    }

    // ── decode_lookupswitch ───────────────────────────────────────────────────

    #[test]
    fn test_lookupswitch_basic() {
        // pc_offset=0: pad=3
        let mut buf = vec![0xab_u8, 0x00, 0x00, 0x00];
        buf.extend_from_slice(&99_i32.to_be_bytes()); // default
        buf.extend_from_slice(&2_i32.to_be_bytes()); // npairs=2
        buf.extend_from_slice(&10_i32.to_be_bytes()); // key0
        buf.extend_from_slice(&20_i32.to_be_bytes()); // off0
        buf.extend_from_slice(&30_i32.to_be_bytes()); // key1
        buf.extend_from_slice(&40_i32.to_be_bytes()); // off1
        let (i, sz) = decode_lookupswitch(&buf, 0).unwrap();
        assert_eq!(sz, buf.len());
        assert!(i.operands.contains("npairs=2"));
        assert!(i.operands.contains("default=99"));
    }

    #[test]
    fn test_lookupswitch_zero_pairs() {
        let mut buf = vec![0xab_u8, 0x00, 0x00, 0x00];
        buf.extend_from_slice(&0_i32.to_be_bytes()); // default
        buf.extend_from_slice(&0_i32.to_be_bytes()); // npairs=0
        let (i, sz) = decode_lookupswitch(&buf, 0).unwrap();
        assert_eq!(sz, buf.len());
        assert_eq!(i.mnemonic, "lookupswitch");
    }

    // ── invoke decodes ────────────────────────────────────────────────────────

    #[test]
    fn test_invokevirtual_decode() {
        let (i, sz) = decode_invokevirtual(&[0xb6, 0x00, 0x1c]).unwrap();
        assert_eq!(sz, 3);
        assert_eq!(i.mnemonic, "invokevirtual");
        assert!(i.flags.contains(InstrFlags::CALL));
        assert!(i.flags.contains(InstrFlags::INDIRECT));
    }

    #[test]
    fn test_invokespecial_decode() {
        let (i, sz) = decode_invokespecial(&[0xb7, 0x00, 0x05]).unwrap();
        assert_eq!(sz, 3);
        assert_eq!(i.mnemonic, "invokespecial");
        assert!(i.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_invokestatic_decode() {
        let (i, sz) = decode_invokestatic(&[0xb8, 0x00, 0x07]).unwrap();
        assert_eq!(sz, 3);
        assert_eq!(i.mnemonic, "invokestatic");
    }

    #[test]
    fn test_invokeinterface_decode() {
        let (i, sz) = decode_invokeinterface(&[0xb9, 0x00, 0x10, 0x02, 0x00]).unwrap();
        assert_eq!(sz, 5);
        assert_eq!(i.mnemonic, "invokeinterface");
        assert!(i.operands.contains("count=2"));
    }

    #[test]
    fn test_invokedynamic_decode() {
        let (i, sz) = decode_invokedynamic(&[0xba, 0x00, 0x0a, 0x00, 0x00]).unwrap();
        assert_eq!(sz, 5);
        assert_eq!(i.mnemonic, "invokedynamic");
        assert!(i.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_multianewarray_decode() {
        let (i, sz) = decode_multianewarray(&[0xc5, 0x00, 0x0b, 0x03]).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(i.mnemonic, "multianewarray");
        assert!(i.operands.contains("dims=3"));
    }

    // ── decode_jvm_insn dispatch ──────────────────────────────────────────────

    #[test]
    fn test_dispatch_wide() {
        let buf = [0xc4, 0x15, 0x00, 0x01];
        let (i, sz) = decode_jvm_insn(&buf, 0).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(i.mnemonic, "wide iload");
    }

    #[test]
    fn test_dispatch_reserved() {
        assert!(matches!(
            decode_jvm_insn(&[0xfe], 0),
            Err(JvmDecodeError::Reserved(0xfe))
        ));
    }

    #[test]
    fn test_dispatch_regular_opcode() {
        let (i, _) = decode_jvm_insn(&[0x60], 0).unwrap(); // iadd
        assert_eq!(i.mnemonic, "iadd");
    }

    // ───── Edge-case coverage ─────────────────────────────────────────────

    #[test]
    fn dispatch_empty_buffer() {
        assert!(decode_jvm_insn(&[], 0).is_err());
    }

    #[test]
    fn wide_truncated_input() {
        // Only the WIDE prefix byte — no opcode follows.
        assert!(decode_wide(&[0xc4]).is_err());
        // Prefix + opcode but missing index bytes.
        assert!(decode_wide(&[0xc4, 0x15, 0x01]).is_err());
    }

    #[test]
    fn meta_lookup_full_range_no_panic() {
        for op in 0u16..=0xFF {
            // Must never panic on any single byte
            let _ = OpcodeMeta::lookup(crate::numeric::trunc_u16_u8(op));
        }
    }

    #[test]
    fn meta_reserved_byte_count_within_bounds() {
        let reserved: Vec<u8> = (0u16..=0xFFu16)
            .filter(|&op| OpcodeMeta::lookup(crate::numeric::trunc_u16_u8(op)).is_none())
            .map(crate::numeric::trunc_u16_u8)
            .collect();
        // The JVM assigns opcodes 0x00..=0xc9; everything from 0xca upwards is
        // `breakpoint`/`impdep1`/`impdep2` plus the unassigned range, which this
        // crate treats uniformly as reserved (see `decode_jvm_insn`, which
        // returns `JvmDecodeError::Reserved` for `0xca..=0xff`).
        //
        // Assert the exact set rather than a loose upper bound: a bound of "< 20"
        // contradicted the documented contract and could not hold.
        let expected: Vec<u8> = (0xCAu16..=0xFFu16).map(crate::numeric::trunc_u16_u8).collect();
        assert_eq!(
            reserved, expected,
            "the reserved set must be exactly 0xca..=0xff"
        );
    }

    #[test]
    fn wide_iinc_six_byte_form() {
        // wide iinc varindex(2) const(2) -> 6 bytes total
        let buf = [0xc4u8, 0x84, 0x00, 0x01, 0x00, 0x02];
        let res = decode_wide(&buf);
        if let Ok((_, sz)) = res {
            assert_eq!(sz, 6);
        }
    }

    #[test]
    fn dispatch_at_nonzero_pc() {
        // Decode iadd starting at pc=100; output should still succeed.
        let (i, sz) = decode_jvm_insn(&[0x60], 100).unwrap();
        assert_eq!(i.mnemonic, "iadd");
        assert_eq!(sz, 1);
    }

    #[test]
    fn invoke_metas_classified_as_control() {
        for op in [0xb6u8, 0xb7, 0xb8, 0xb9, 0xba] {
            if let Some(m) = OpcodeMeta::lookup(op) {
                assert!(m.is_invoke());
                assert!(m.is_control);
            }
        }
    }

    #[test]
    fn return_metas_classified() {
        // ireturn..return = 0xac..=0xb1
        for op in 0xac..=0xb1u8 {
            let m = OpcodeMeta::lookup(op).unwrap();
            assert!(m.is_return());
            assert!(m.is_control);
        }
    }
}
