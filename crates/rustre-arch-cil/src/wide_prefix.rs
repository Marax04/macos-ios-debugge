//! CIL `0xFE` wide-prefix instruction table.
//!
//! The `0xFE` prefix introduces a second instruction byte to encode 32 additional
//! CIL opcodes defined in ECMA-335 §III.3.  This module provides:
//! - [`WidePrefixEntry`] — static description of a wide-prefix opcode
//! - [`WIDE_PREFIX_TABLE`] — full 32-entry static table (0xFE 0x00 … 0xFE 0x1E)
//! - [`decode_wide_prefix`] — decode a 0xFE-prefixed CIL instruction from raw bytes

use crate::CilDecodeError;

/// Operand kind for a wide-prefix CIL instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WideOperand {
    /// No inline operand (2-byte instruction).
    None,
    /// One unsigned 8-bit byte operand (3-byte instruction).
    Uint8,
    /// One unsigned 16-bit integer operand (4-byte instruction).
    Uint16,
    /// One unsigned 32-bit metadata token (6-byte instruction).
    Token32,
}

impl WideOperand {
    /// Total byte size of a 0xFE-prefixed instruction with this operand kind.
    #[must_use]
    pub const fn total_size(self) -> usize {
        match self {
            Self::None => 2,
            Self::Uint8 => 3,
            Self::Uint16 => 4,
            Self::Token32 => 6,
        }
    }
}

/// Semantic category for a wide-prefix instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WideCategory {
    /// Comparison producing 0/1 on the evaluation stack.
    Compare,
    /// Load of a function pointer.
    FunctionPointer,
    /// Load of an argument or local variable by 16-bit index.
    LoadArg,
    /// Store to an argument or local variable by 16-bit index.
    StoreArg,
    /// Load address of argument/local.
    LoadAddress,
    /// Stack-allocation (localloc).
    StackAlloc,
    /// Exception handling control (endfilter, leave, rethrow).
    ExceptionHandling,
    /// Memory ordering prefix (unaligned, volatile, tail, no).
    Prefix,
    /// Object/array initialization (initobj, constrained, cpblk, initblk).
    Initialization,
    /// Type query (sizeof, refanytype).
    TypeQuery,
    /// Readonly prefix for array operations.
    Readonly,
    /// Undocumented / reserved.
    Reserved,
}

/// A static entry for one 0xFE-prefixed CIL opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WidePrefixEntry {
    /// The second byte (after 0xFE).
    pub second_byte: u8,
    /// Official CIL mnemonic.
    pub mnemonic: &'static str,
    /// Operand kind.
    pub operand: WideOperand,
    /// Semantic category.
    pub category: WideCategory,
}

impl WidePrefixEntry {
    const fn new(
        second_byte: u8,
        mnemonic: &'static str,
        operand: WideOperand,
        category: WideCategory,
    ) -> Self {
        Self {
            second_byte,
            mnemonic,
            operand,
            category,
        }
    }
}

/// Complete static table of all `0xFE xx` CIL opcodes (ECMA-335 §III.3).
pub static WIDE_PREFIX_TABLE: &[WidePrefixEntry] = &[
    WidePrefixEntry::new(0x00, "arglist", WideOperand::None, WideCategory::Reserved),
    WidePrefixEntry::new(0x01, "ceq", WideOperand::None, WideCategory::Compare),
    WidePrefixEntry::new(0x02, "cgt", WideOperand::None, WideCategory::Compare),
    WidePrefixEntry::new(0x03, "cgt.un", WideOperand::None, WideCategory::Compare),
    WidePrefixEntry::new(0x04, "clt", WideOperand::None, WideCategory::Compare),
    WidePrefixEntry::new(0x05, "clt.un", WideOperand::None, WideCategory::Compare),
    WidePrefixEntry::new(
        0x06,
        "ldftn",
        WideOperand::Token32,
        WideCategory::FunctionPointer,
    ),
    WidePrefixEntry::new(
        0x07,
        "ldvirtftn",
        WideOperand::Token32,
        WideCategory::FunctionPointer,
    ),
    // 0x08 is reserved/unassigned
    WidePrefixEntry::new(
        0x08,
        "reserved-fe08",
        WideOperand::None,
        WideCategory::Reserved,
    ),
    WidePrefixEntry::new(0x09, "ldarg", WideOperand::Uint16, WideCategory::LoadArg),
    WidePrefixEntry::new(
        0x0a,
        "ldarga",
        WideOperand::Uint16,
        WideCategory::LoadAddress,
    ),
    WidePrefixEntry::new(0x0b, "starg", WideOperand::Uint16, WideCategory::StoreArg),
    WidePrefixEntry::new(0x0c, "ldloc", WideOperand::Uint16, WideCategory::LoadArg),
    WidePrefixEntry::new(
        0x0d,
        "ldloca",
        WideOperand::Uint16,
        WideCategory::LoadAddress,
    ),
    WidePrefixEntry::new(0x0e, "stloc", WideOperand::Uint16, WideCategory::StoreArg),
    WidePrefixEntry::new(
        0x0f,
        "localloc",
        WideOperand::None,
        WideCategory::StackAlloc,
    ),
    // 0x10 is reserved
    WidePrefixEntry::new(
        0x10,
        "reserved-fe10",
        WideOperand::None,
        WideCategory::Reserved,
    ),
    WidePrefixEntry::new(
        0x11,
        "endfilter",
        WideOperand::None,
        WideCategory::ExceptionHandling,
    ),
    WidePrefixEntry::new(0x12, "unaligned", WideOperand::Uint8, WideCategory::Prefix),
    WidePrefixEntry::new(0x13, "volatile", WideOperand::None, WideCategory::Prefix),
    WidePrefixEntry::new(0x14, "tail", WideOperand::None, WideCategory::Prefix),
    WidePrefixEntry::new(
        0x15,
        "initobj",
        WideOperand::Token32,
        WideCategory::Initialization,
    ),
    WidePrefixEntry::new(
        0x16,
        "constrained",
        WideOperand::Token32,
        WideCategory::Prefix,
    ),
    WidePrefixEntry::new(
        0x17,
        "cpblk",
        WideOperand::None,
        WideCategory::Initialization,
    ),
    WidePrefixEntry::new(
        0x18,
        "initblk",
        WideOperand::None,
        WideCategory::Initialization,
    ),
    WidePrefixEntry::new(0x19, "no", WideOperand::Uint8, WideCategory::Prefix),
    WidePrefixEntry::new(
        0x1a,
        "rethrow",
        WideOperand::None,
        WideCategory::ExceptionHandling,
    ),
    // 0x1b reserved
    WidePrefixEntry::new(
        0x1b,
        "reserved-fe1b",
        WideOperand::None,
        WideCategory::Reserved,
    ),
    WidePrefixEntry::new(
        0x1c,
        "sizeof",
        WideOperand::Token32,
        WideCategory::TypeQuery,
    ),
    WidePrefixEntry::new(
        0x1d,
        "refanytype",
        WideOperand::None,
        WideCategory::TypeQuery,
    ),
    WidePrefixEntry::new(0x1e, "readonly", WideOperand::None, WideCategory::Readonly),
];

/// Look up a wide-prefix entry by its second byte.
#[must_use]
pub fn lookup_wide(second_byte: u8) -> Option<&'static WidePrefixEntry> {
    WIDE_PREFIX_TABLE
        .iter()
        .find(|e| e.second_byte == second_byte)
}

/// A decoded 0xFE-prefixed CIL instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WidePrefixInsn {
    /// The static table entry.
    pub entry: &'static WidePrefixEntry,
    /// Raw bytes (including 0xFE prefix).
    pub raw: Vec<u8>,
    /// The decoded operand value (0 if None).
    pub operand_value: u32,
    /// Total byte count.
    pub size: usize,
}

/// Decode a 0xFE-prefixed CIL instruction from `bytes`.
///
/// `bytes[0]` must equal `0xFE`.  The function reads as many bytes as needed
/// according to the operand kind in [`WIDE_PREFIX_TABLE`].
///
/// # Errors
/// Returns [`CilDecodeError::Truncated`] when the slice is too short and
/// [`CilDecodeError::UnknownPrefixedOpcode`] for second bytes `> 0x1E` or
/// for the reserved slots (0x08, 0x10, 0x1B).
pub fn decode_wide_prefix(bytes: &[u8]) -> Result<WidePrefixInsn, CilDecodeError> {
    if bytes.len() < 2 {
        return Err(CilDecodeError::Truncated);
    }
    debug_assert_eq!(
        bytes[0], 0xFE,
        "decode_wide_prefix called with non-0xFE byte"
    );
    let second = bytes[1];

    let entry = lookup_wide(second).ok_or(CilDecodeError::UnknownPrefixedOpcode(second))?;

    // Reject reserved opcodes
    if entry.category == WideCategory::Reserved {
        return Err(CilDecodeError::UnknownPrefixedOpcode(second));
    }

    let total = entry.operand.total_size();
    if bytes.len() < total {
        return Err(CilDecodeError::Truncated);
    }

    let operand_value = match entry.operand {
        WideOperand::None => 0,
        WideOperand::Uint8 => u32::from(bytes[2]),
        WideOperand::Uint16 => u32::from(u16::from_le_bytes([bytes[2], bytes[3]])),
        WideOperand::Token32 => u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
    };

    Ok(WidePrefixInsn {
        entry,
        raw: bytes[..total].to_vec(),
        operand_value,
        size: total,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_non_empty() {
        assert!(!WIDE_PREFIX_TABLE.is_empty());
    }

    #[test]
    fn test_ceq_entry() {
        let e = lookup_wide(0x01).unwrap();
        assert_eq!(e.mnemonic, "ceq");
        assert_eq!(e.operand, WideOperand::None);
        assert_eq!(e.category, WideCategory::Compare);
    }

    #[test]
    fn test_cgt_entry() {
        let e = lookup_wide(0x02).unwrap();
        assert_eq!(e.mnemonic, "cgt");
    }

    #[test]
    fn test_cgt_un_entry() {
        let e = lookup_wide(0x03).unwrap();
        assert_eq!(e.mnemonic, "cgt.un");
    }

    #[test]
    fn test_clt_entry() {
        let e = lookup_wide(0x04).unwrap();
        assert_eq!(e.mnemonic, "clt");
    }

    #[test]
    fn test_clt_un_entry() {
        let e = lookup_wide(0x05).unwrap();
        assert_eq!(e.mnemonic, "clt.un");
    }

    #[test]
    fn test_ldftn_token32() {
        let e = lookup_wide(0x06).unwrap();
        assert_eq!(e.mnemonic, "ldftn");
        assert_eq!(e.operand, WideOperand::Token32);
        assert_eq!(e.operand.total_size(), 6);
    }

    #[test]
    fn test_ldvirtftn() {
        let e = lookup_wide(0x07).unwrap();
        assert_eq!(e.mnemonic, "ldvirtftn");
    }

    #[test]
    fn test_ldarg_uint16() {
        let e = lookup_wide(0x09).unwrap();
        assert_eq!(e.mnemonic, "ldarg");
        assert_eq!(e.operand, WideOperand::Uint16);
        assert_eq!(e.operand.total_size(), 4);
    }

    #[test]
    fn test_ldarga() {
        let e = lookup_wide(0x0a).unwrap();
        assert_eq!(e.mnemonic, "ldarga");
    }

    #[test]
    fn test_starg() {
        let e = lookup_wide(0x0b).unwrap();
        assert_eq!(e.mnemonic, "starg");
    }

    #[test]
    fn test_ldloc() {
        let e = lookup_wide(0x0c).unwrap();
        assert_eq!(e.mnemonic, "ldloc");
    }

    #[test]
    fn test_ldloca() {
        let e = lookup_wide(0x0d).unwrap();
        assert_eq!(e.mnemonic, "ldloca");
    }

    #[test]
    fn test_stloc() {
        let e = lookup_wide(0x0e).unwrap();
        assert_eq!(e.mnemonic, "stloc");
    }

    #[test]
    fn test_localloc_none() {
        let e = lookup_wide(0x0f).unwrap();
        assert_eq!(e.mnemonic, "localloc");
        assert_eq!(e.operand, WideOperand::None);
    }

    #[test]
    fn test_endfilter() {
        let e = lookup_wide(0x11).unwrap();
        assert_eq!(e.mnemonic, "endfilter");
        assert_eq!(e.category, WideCategory::ExceptionHandling);
    }

    #[test]
    fn test_unaligned_uint8() {
        let e = lookup_wide(0x12).unwrap();
        assert_eq!(e.mnemonic, "unaligned");
        assert_eq!(e.operand, WideOperand::Uint8);
    }

    #[test]
    fn test_volatile() {
        let e = lookup_wide(0x13).unwrap();
        assert_eq!(e.mnemonic, "volatile");
    }

    #[test]
    fn test_tail() {
        let e = lookup_wide(0x14).unwrap();
        assert_eq!(e.mnemonic, "tail");
    }

    #[test]
    fn test_initobj() {
        let e = lookup_wide(0x15).unwrap();
        assert_eq!(e.mnemonic, "initobj");
        assert_eq!(e.operand, WideOperand::Token32);
    }

    #[test]
    fn test_constrained() {
        let e = lookup_wide(0x16).unwrap();
        assert_eq!(e.mnemonic, "constrained");
    }

    #[test]
    fn test_rethrow() {
        let e = lookup_wide(0x1a).unwrap();
        assert_eq!(e.mnemonic, "rethrow");
        assert_eq!(e.category, WideCategory::ExceptionHandling);
    }

    #[test]
    fn test_sizeof() {
        let e = lookup_wide(0x1c).unwrap();
        assert_eq!(e.mnemonic, "sizeof");
    }

    #[test]
    fn test_refanytype() {
        let e = lookup_wide(0x1d).unwrap();
        assert_eq!(e.mnemonic, "refanytype");
        assert_eq!(e.category, WideCategory::TypeQuery);
    }

    #[test]
    fn test_readonly() {
        let e = lookup_wide(0x1e).unwrap();
        assert_eq!(e.mnemonic, "readonly");
    }

    #[test]
    fn test_decode_ceq() {
        let insn = decode_wide_prefix(&[0xfe, 0x01]).unwrap();
        assert_eq!(insn.entry.mnemonic, "ceq");
        assert_eq!(insn.size, 2);
        assert_eq!(insn.operand_value, 0);
    }

    #[test]
    fn test_decode_ldarg_with_index() {
        let insn = decode_wide_prefix(&[0xfe, 0x09, 0x05, 0x00]).unwrap();
        assert_eq!(insn.entry.mnemonic, "ldarg");
        assert_eq!(insn.size, 4);
        assert_eq!(insn.operand_value, 5);
    }

    #[test]
    fn test_decode_ldftn_with_token() {
        let mut buf = vec![0xfe_u8, 0x06];
        buf.extend_from_slice(&0x0600_0003_u32.to_le_bytes());
        let insn = decode_wide_prefix(&buf).unwrap();
        assert_eq!(insn.entry.mnemonic, "ldftn");
        assert_eq!(insn.size, 6);
        assert_eq!(insn.operand_value, 0x0600_0003);
    }

    #[test]
    fn test_decode_unaligned_uint8() {
        let insn = decode_wide_prefix(&[0xfe, 0x12, 0x04]).unwrap();
        assert_eq!(insn.entry.mnemonic, "unaligned");
        assert_eq!(insn.size, 3);
        assert_eq!(insn.operand_value, 4);
    }

    #[test]
    fn test_decode_truncated() {
        let err = decode_wide_prefix(&[0xfe]).unwrap_err();
        assert!(matches!(err, CilDecodeError::Truncated));
    }

    #[test]
    fn test_decode_truncated_operand() {
        // ldarg needs 4 bytes total but only 3 available
        let err = decode_wide_prefix(&[0xfe, 0x09, 0x01]).unwrap_err();
        assert!(matches!(err, CilDecodeError::Truncated));
    }

    #[test]
    fn test_decode_reserved_rejected() {
        // 0xFE 0x08 is reserved
        let err = decode_wide_prefix(&[0xfe, 0x08]).unwrap_err();
        assert!(matches!(err, CilDecodeError::UnknownPrefixedOpcode(0x08)));
    }

    #[test]
    fn test_decode_unknown_opcode() {
        let err = decode_wide_prefix(&[0xfe, 0x7f]).unwrap_err();
        assert!(matches!(err, CilDecodeError::UnknownPrefixedOpcode(0x7f)));
    }

    #[test]
    fn test_wide_operand_sizes() {
        assert_eq!(WideOperand::None.total_size(), 2);
        assert_eq!(WideOperand::Uint8.total_size(), 3);
        assert_eq!(WideOperand::Uint16.total_size(), 4);
        assert_eq!(WideOperand::Token32.total_size(), 6);
    }

    #[test]
    fn test_lookup_none_for_high_byte() {
        assert!(lookup_wide(0xff).is_none());
    }
}
