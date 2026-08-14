//! ART (Android Runtime) optimized opcode support for DEX.
//!
//! ART uses the `0xe3`–`0xf9` range for internal optimized opcodes that replace
//! standard DEX opcodes after ahead-of-time compilation.  These opcodes are only
//! valid inside OAT/ODEX files and are never present in plain DEX bytecode.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// ArtOpcode enum
// ---------------------------------------------------------------------------

/// All ART-specific optimized opcodes in the `0xe3`–`0xf9` range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ArtOpcode {
    /// `iget-quick` — quick instance field get (opcode `0xe3`).
    IgetQuick = 0xe3,
    /// `iget-wide-quick` — quick wide field get (opcode `0xe4`).
    IgetWideQuick = 0xe4,
    /// `iget-object-quick` — quick object field get (opcode `0xe5`).
    IgetObjectQuick = 0xe5,
    /// `iput-quick` — quick instance field put (opcode `0xe6`).
    IputQuick = 0xe6,
    /// `iput-wide-quick` — quick wide field put (opcode `0xe7`).
    IputWideQuick = 0xe7,
    /// `iput-object-quick` — quick object field put (opcode `0xe8`).
    IputObjectQuick = 0xe8,
    /// `invoke-virtual-quick` — quick virtual method call (opcode `0xe9`).
    InvokeVirtualQuick = 0xe9,
    /// `invoke-virtual-quick/range` — quick virtual method call, range form (`0xea`).
    InvokeVirtualQuickRange = 0xea,
    /// `iput-boolean-quick` — quick boolean field put (`0xeb`).
    IputBooleanQuick = 0xeb,
    /// `iput-byte-quick` — quick byte field put (`0xec`).
    IputByteQuick = 0xec,
    /// `iput-char-quick` — quick char field put (`0xed`).
    IputCharQuick = 0xed,
    /// `iput-short-quick` — quick short field put (`0xee`).
    IputShortQuick = 0xee,
    /// `iget-boolean-quick` — quick boolean field get (`0xef`).
    IgetBooleanQuick = 0xef,
    /// `iget-byte-quick` — quick byte field get (`0xf0`).
    IgetByteQuick = 0xf0,
    /// `iget-char-quick` — quick char field get (`0xf1`).
    IgetCharQuick = 0xf1,
    /// `iget-short-quick` — quick short field get (`0xf2`).
    IgetShortQuick = 0xf2,
    /// `invoke-lambda` — lambda invocation (`0xf3`).
    InvokeLambda = 0xf3,
    /// `capture-variable` — lambda variable capture (`0xf4`).
    CaptureVariable = 0xf4,
    /// `create-lambda` — lambda object creation (`0xf5`).
    CreateLambda = 0xf5,
    /// `liberate-variable` — free captured variable (`0xf6`).
    LiberateVariable = 0xf6,
    /// `box-lambda` — box a lambda value (`0xf7`).
    BoxLambda = 0xf7,
    /// `unbox-lambda` — unbox a lambda value (`0xf8`).
    UnboxLambda = 0xf8,
    /// Reserved / unused (`0xf9`).
    UnusedF9 = 0xf9,
}

impl ArtOpcode {
    /// Return the numeric opcode byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// Return the canonical mnemonic string.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::IgetQuick => "iget-quick",
            Self::IgetWideQuick => "iget-wide-quick",
            Self::IgetObjectQuick => "iget-object-quick",
            Self::IputQuick => "iput-quick",
            Self::IputWideQuick => "iput-wide-quick",
            Self::IputObjectQuick => "iput-object-quick",
            Self::InvokeVirtualQuick => "invoke-virtual-quick",
            Self::InvokeVirtualQuickRange => "invoke-virtual-quick/range",
            Self::IputBooleanQuick => "iput-boolean-quick",
            Self::IputByteQuick => "iput-byte-quick",
            Self::IputCharQuick => "iput-char-quick",
            Self::IputShortQuick => "iput-short-quick",
            Self::IgetBooleanQuick => "iget-boolean-quick",
            Self::IgetByteQuick => "iget-byte-quick",
            Self::IgetCharQuick => "iget-char-quick",
            Self::IgetShortQuick => "iget-short-quick",
            Self::InvokeLambda => "invoke-lambda",
            Self::CaptureVariable => "capture-variable",
            Self::CreateLambda => "create-lambda",
            Self::LiberateVariable => "liberate-variable",
            Self::BoxLambda => "box-lambda",
            Self::UnboxLambda => "unbox-lambda",
            Self::UnusedF9 => "unused-f9",
        }
    }

    /// Try to convert a raw opcode byte to an `ArtOpcode`.
    /// Returns `None` if the byte is not in the ART range.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0xe3 => Self::IgetQuick,
            0xe4 => Self::IgetWideQuick,
            0xe5 => Self::IgetObjectQuick,
            0xe6 => Self::IputQuick,
            0xe7 => Self::IputWideQuick,
            0xe8 => Self::IputObjectQuick,
            0xe9 => Self::InvokeVirtualQuick,
            0xea => Self::InvokeVirtualQuickRange,
            0xeb => Self::IputBooleanQuick,
            0xec => Self::IputByteQuick,
            0xed => Self::IputCharQuick,
            0xee => Self::IputShortQuick,
            0xef => Self::IgetBooleanQuick,
            0xf0 => Self::IgetByteQuick,
            0xf1 => Self::IgetCharQuick,
            0xf2 => Self::IgetShortQuick,
            0xf3 => Self::InvokeLambda,
            0xf4 => Self::CaptureVariable,
            0xf5 => Self::CreateLambda,
            0xf6 => Self::LiberateVariable,
            0xf7 => Self::BoxLambda,
            0xf8 => Self::UnboxLambda,
            0xf9 => Self::UnusedF9,
            _ => return None,
        })
    }

    /// Whether this opcode is a field access (iget/iput variant).
    #[must_use]
    pub const fn is_field_access(self) -> bool {
        matches!(
            self,
            Self::IgetQuick
                | Self::IgetWideQuick
                | Self::IgetObjectQuick
                | Self::IgetBooleanQuick
                | Self::IgetByteQuick
                | Self::IgetCharQuick
                | Self::IgetShortQuick
                | Self::IputQuick
                | Self::IputWideQuick
                | Self::IputObjectQuick
                | Self::IputBooleanQuick
                | Self::IputByteQuick
                | Self::IputCharQuick
                | Self::IputShortQuick
        )
    }

    /// Whether this opcode is a virtual method invocation.
    #[must_use]
    pub const fn is_invoke(self) -> bool {
        matches!(
            self,
            Self::InvokeVirtualQuick | Self::InvokeVirtualQuickRange | Self::InvokeLambda
        )
    }

    /// Whether this opcode is a lambda-related operation.
    #[must_use]
    pub const fn is_lambda(self) -> bool {
        matches!(
            self,
            Self::InvokeLambda
                | Self::CaptureVariable
                | Self::CreateLambda
                | Self::LiberateVariable
                | Self::BoxLambda
                | Self::UnboxLambda
        )
    }

    /// Return all defined `ArtOpcode` variants in opcode order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &ART_OPCODE_TABLE
    }
}

impl std::fmt::Display for ArtOpcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#04x} ({})", self.byte(), self.mnemonic())
    }
}

// ---------------------------------------------------------------------------
// ART_OPCODE_TABLE — static array of all ART opcodes
// ---------------------------------------------------------------------------

/// Static table of all ART-optimized opcodes in ascending opcode order.
pub static ART_OPCODE_TABLE: [ArtOpcode; 23] = [
    ArtOpcode::IgetQuick,
    ArtOpcode::IgetWideQuick,
    ArtOpcode::IgetObjectQuick,
    ArtOpcode::IputQuick,
    ArtOpcode::IputWideQuick,
    ArtOpcode::IputObjectQuick,
    ArtOpcode::InvokeVirtualQuick,
    ArtOpcode::InvokeVirtualQuickRange,
    ArtOpcode::IputBooleanQuick,
    ArtOpcode::IputByteQuick,
    ArtOpcode::IputCharQuick,
    ArtOpcode::IputShortQuick,
    ArtOpcode::IgetBooleanQuick,
    ArtOpcode::IgetByteQuick,
    ArtOpcode::IgetCharQuick,
    ArtOpcode::IgetShortQuick,
    ArtOpcode::InvokeLambda,
    ArtOpcode::CaptureVariable,
    ArtOpcode::CreateLambda,
    ArtOpcode::LiberateVariable,
    ArtOpcode::BoxLambda,
    ArtOpcode::UnboxLambda,
    ArtOpcode::UnusedF9,
];

// ---------------------------------------------------------------------------
// ArtInsnInfo — decoded ART instruction
// ---------------------------------------------------------------------------

/// A decoded ART optimized instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtInsnInfo {
    /// The ART opcode.
    pub opcode: ArtOpcode,
    /// Number of 16-bit code units.
    pub size_in_code_units: usize,
    /// Destination or source register A (low 4 bits of byte 1).
    pub reg_a: u8,
    /// Source or field-offset register B (high 4 bits of byte 1).
    pub reg_b: u8,
    /// 16-bit vtable-index or field-offset operand (bytes 2–3), if present.
    pub operand: Option<u16>,
}

impl ArtInsnInfo {
    /// Format the instruction as an assembly-like string.
    #[must_use]
    pub fn display_string(&self) -> String {
        match self.operand {
            Some(op) => format!(
                "{} v{}, v{}, #{:#x}",
                self.opcode.mnemonic(),
                self.reg_a,
                self.reg_b,
                op
            ),
            None => format!(
                "{} v{}, v{}",
                self.opcode.mnemonic(),
                self.reg_a,
                self.reg_b,
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// decode_art_insn — main decoding function
// ---------------------------------------------------------------------------

/// Decode an ART optimized instruction from a byte slice.
///
/// Returns `Some(ArtInsnInfo)` if the first byte is a valid ART opcode and the
/// slice contains enough bytes.  Returns `None` otherwise.
#[must_use]
pub fn decode_art_insn(bytes: &[u8]) -> Option<ArtInsnInfo> {
    let op_byte = *bytes.first()?;
    let opcode = ArtOpcode::from_byte(op_byte)?;
    let hi = *bytes.get(1)?;
    let reg_a = hi & 0x0f;
    let reg_b = (hi >> 4) & 0x0f;

    // Quick field accesses and invoke-virtual-quick use the 22cs format
    // (2 code units: op | A|B | vtable_index_or_field_offset).
    match opcode {
        ArtOpcode::InvokeVirtualQuickRange => {
            // 3rc-like: op | count | method_idx | first_reg
            if bytes.len() < 6 {
                return None;
            }
            let method_idx = u16::from_le_bytes([bytes[2], bytes[3]]);
            Some(ArtInsnInfo {
                opcode,
                size_in_code_units: 3,
                reg_a,
                reg_b,
                operand: Some(method_idx),
            })
        }
        ArtOpcode::CaptureVariable
        | ArtOpcode::CreateLambda
        | ArtOpcode::LiberateVariable
        | ArtOpcode::BoxLambda
        | ArtOpcode::UnboxLambda
        | ArtOpcode::InvokeLambda
        | ArtOpcode::UnusedF9 => Some(ArtInsnInfo {
            opcode,
            size_in_code_units: 1,
            reg_a,
            reg_b,
            operand: None,
        }),
        _ => {
            // Quick field accesses: 22cs — 2 code units with 16-bit offset
            if bytes.len() < 4 {
                return None;
            }
            let offset = u16::from_le_bytes([bytes[2], bytes[3]]);
            Some(ArtInsnInfo {
                opcode,
                size_in_code_units: 2,
                reg_a,
                reg_b,
                operand: Some(offset),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// ArtToStandardMapper — map ART opcodes back to standard DEX equivalents
// ---------------------------------------------------------------------------

/// Maps each ART optimized opcode to the standard DEX opcode it was derived from.
pub struct ArtToStandardMapper {
    table: HashMap<ArtOpcode, u8>,
}

impl ArtToStandardMapper {
    /// Build the mapping table.
    #[must_use]
    pub fn new() -> Self {
        let mut table = HashMap::new();
        // iget family → 0x52..0x58
        table.insert(ArtOpcode::IgetQuick, 0x52u8); // iget
        table.insert(ArtOpcode::IgetWideQuick, 0x53); // iget-wide
        table.insert(ArtOpcode::IgetObjectQuick, 0x54); // iget-object
        table.insert(ArtOpcode::IgetBooleanQuick, 0x55); // iget-boolean
        table.insert(ArtOpcode::IgetByteQuick, 0x56); // iget-byte
        table.insert(ArtOpcode::IgetCharQuick, 0x57); // iget-char
        table.insert(ArtOpcode::IgetShortQuick, 0x58); // iget-short
        // iput family → 0x59..0x5f
        table.insert(ArtOpcode::IputQuick, 0x59); // iput
        table.insert(ArtOpcode::IputWideQuick, 0x5a); // iput-wide
        table.insert(ArtOpcode::IputObjectQuick, 0x5b); // iput-object
        table.insert(ArtOpcode::IputBooleanQuick, 0x5c); // iput-boolean
        table.insert(ArtOpcode::IputByteQuick, 0x5d); // iput-byte
        table.insert(ArtOpcode::IputCharQuick, 0x5e); // iput-char
        table.insert(ArtOpcode::IputShortQuick, 0x5f); // iput-short
        // invoke-virtual-quick → invoke-virtual (0x6e)
        table.insert(ArtOpcode::InvokeVirtualQuick, 0x6e);
        table.insert(ArtOpcode::InvokeVirtualQuickRange, 0x74); // invoke-virtual/range
        // Lambda → no direct standard equivalent; map to nop (0x00) as placeholder
        table.insert(ArtOpcode::InvokeLambda, 0x00);
        table.insert(ArtOpcode::CaptureVariable, 0x00);
        table.insert(ArtOpcode::CreateLambda, 0x00);
        table.insert(ArtOpcode::LiberateVariable, 0x00);
        table.insert(ArtOpcode::BoxLambda, 0x00);
        table.insert(ArtOpcode::UnboxLambda, 0x00);
        table.insert(ArtOpcode::UnusedF9, 0x00);
        Self { table }
    }

    /// Look up the standard DEX opcode byte for an ART opcode.
    /// Returns `None` for lambda and reserved opcodes.
    #[must_use]
    pub fn to_standard(&self, art: ArtOpcode) -> Option<u8> {
        let &b = self.table.get(&art)?;
        if b == 0x00 && !matches!(art, ArtOpcode::UnusedF9) {
            // Lambda opcodes have no standard equivalent
            match art {
                ArtOpcode::InvokeLambda
                | ArtOpcode::CaptureVariable
                | ArtOpcode::CreateLambda
                | ArtOpcode::LiberateVariable
                | ArtOpcode::BoxLambda
                | ArtOpcode::UnboxLambda => return None,
                _ => {}
            }
        }
        Some(b)
    }

    /// Whether the given ART opcode has a well-known standard DEX equivalent.
    #[must_use]
    pub fn has_standard_equivalent(&self, art: ArtOpcode) -> bool {
        self.to_standard(art).is_some()
    }
}

impl Default for ArtToStandardMapper {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_art_opcode_from_byte_valid() {
        assert_eq!(ArtOpcode::from_byte(0xe3), Some(ArtOpcode::IgetQuick));
        assert_eq!(
            ArtOpcode::from_byte(0xe9),
            Some(ArtOpcode::InvokeVirtualQuick)
        );
        assert_eq!(ArtOpcode::from_byte(0xf9), Some(ArtOpcode::UnusedF9));
    }

    #[test]
    fn test_art_opcode_from_byte_out_of_range() {
        assert_eq!(ArtOpcode::from_byte(0xe2), None); // last standard DEX opcode
        assert_eq!(ArtOpcode::from_byte(0xfa), None); // invoke-polymorphic
        assert_eq!(ArtOpcode::from_byte(0x00), None);
    }

    #[test]
    fn test_art_opcode_table_length() {
        assert_eq!(ART_OPCODE_TABLE.len(), 23);
    }

    #[test]
    fn test_art_opcode_table_order() {
        for window in ART_OPCODE_TABLE.windows(2) {
            assert!(window[0].byte() < window[1].byte());
        }
    }

    #[test]
    fn test_art_opcode_mnemonics_non_empty() {
        for op in ArtOpcode::all() {
            assert!(!op.mnemonic().is_empty());
        }
    }

    #[test]
    fn test_art_opcode_byte_roundtrip() {
        for op in ArtOpcode::all() {
            assert_eq!(ArtOpcode::from_byte(op.byte()), Some(*op));
        }
    }

    #[test]
    fn test_decode_art_insn_iget_quick() {
        // iget-quick v1, v2, #0x0010  → bytes: 0xe3, 0x21, 0x10, 0x00
        let bytes = [0xe3u8, 0x21, 0x10, 0x00];
        let info = decode_art_insn(&bytes).unwrap();
        assert_eq!(info.opcode, ArtOpcode::IgetQuick);
        assert_eq!(info.reg_a, 1);
        assert_eq!(info.reg_b, 2);
        assert_eq!(info.operand, Some(0x0010));
        assert_eq!(info.size_in_code_units, 2);
    }

    #[test]
    fn test_decode_art_insn_invoke_virtual_quick() {
        let bytes = [0xe9u8, 0x10, 0x05, 0x00];
        let info = decode_art_insn(&bytes).unwrap();
        assert_eq!(info.opcode, ArtOpcode::InvokeVirtualQuick);
        assert_eq!(info.operand, Some(0x0005));
    }

    #[test]
    fn test_decode_art_insn_iput_quick() {
        let bytes = [0xe6u8, 0x30, 0x08, 0x00];
        let info = decode_art_insn(&bytes).unwrap();
        assert_eq!(info.opcode, ArtOpcode::IputQuick);
        assert_eq!(info.reg_a, 0);
        assert_eq!(info.reg_b, 3);
        assert_eq!(info.operand, Some(8));
    }

    #[test]
    fn test_decode_art_insn_truncated_returns_none() {
        // iget-quick needs 4 bytes minimum
        let bytes = [0xe3u8, 0x21];
        assert!(decode_art_insn(&bytes).is_none());
    }

    #[test]
    fn test_decode_art_insn_non_art_byte() {
        let bytes = [0x6eu8, 0x10, 0x01, 0x00];
        assert!(decode_art_insn(&bytes).is_none());
    }

    #[test]
    fn test_decode_art_insn_create_lambda() {
        let bytes = [0xf5u8, 0x10, 0x00, 0x00];
        let info = decode_art_insn(&bytes).unwrap();
        assert_eq!(info.opcode, ArtOpcode::CreateLambda);
        assert_eq!(info.operand, None);
        assert_eq!(info.size_in_code_units, 1);
    }

    #[test]
    fn test_art_to_standard_mapper_iget() {
        let mapper = ArtToStandardMapper::new();
        assert_eq!(mapper.to_standard(ArtOpcode::IgetQuick), Some(0x52));
        assert_eq!(mapper.to_standard(ArtOpcode::IgetWideQuick), Some(0x53));
    }

    #[test]
    fn test_art_to_standard_mapper_iput() {
        let mapper = ArtToStandardMapper::new();
        assert_eq!(mapper.to_standard(ArtOpcode::IputQuick), Some(0x59));
        assert_eq!(mapper.to_standard(ArtOpcode::IputObjectQuick), Some(0x5b));
    }

    #[test]
    fn test_art_to_standard_mapper_invoke_virtual() {
        let mapper = ArtToStandardMapper::new();
        assert_eq!(
            mapper.to_standard(ArtOpcode::InvokeVirtualQuick),
            Some(0x6e)
        );
        assert_eq!(
            mapper.to_standard(ArtOpcode::InvokeVirtualQuickRange),
            Some(0x74)
        );
    }

    #[test]
    fn test_art_to_standard_mapper_lambda_has_no_equivalent() {
        let mapper = ArtToStandardMapper::new();
        assert!(mapper.to_standard(ArtOpcode::CreateLambda).is_none());
        assert!(mapper.to_standard(ArtOpcode::BoxLambda).is_none());
    }

    #[test]
    fn test_is_field_access() {
        assert!(ArtOpcode::IgetQuick.is_field_access());
        assert!(ArtOpcode::IputShortQuick.is_field_access());
        assert!(!ArtOpcode::InvokeVirtualQuick.is_field_access());
    }

    #[test]
    fn test_is_invoke() {
        assert!(ArtOpcode::InvokeVirtualQuick.is_invoke());
        assert!(ArtOpcode::InvokeVirtualQuickRange.is_invoke());
        assert!(!ArtOpcode::IgetQuick.is_invoke());
    }

    #[test]
    fn test_is_lambda() {
        assert!(ArtOpcode::CreateLambda.is_lambda());
        assert!(ArtOpcode::BoxLambda.is_lambda());
        assert!(!ArtOpcode::IputQuick.is_lambda());
    }

    #[test]
    fn test_art_insn_display_with_operand() {
        let info = ArtInsnInfo {
            opcode: ArtOpcode::IgetQuick,
            size_in_code_units: 2,
            reg_a: 1,
            reg_b: 2,
            operand: Some(0x10),
        };
        let s = info.display_string();
        assert!(s.contains("iget-quick"));
        assert!(s.contains("v1"));
        assert!(s.contains("v2"));
        assert!(s.contains("0x10"));
    }

    #[test]
    fn test_art_opcode_display() {
        let s = format!("{}", ArtOpcode::IgetQuick);
        assert!(s.contains("0xe3"));
        assert!(s.contains("iget-quick"));
    }
}
