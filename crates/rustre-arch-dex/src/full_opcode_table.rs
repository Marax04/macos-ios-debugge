//! Full Dalvik opcode table — all 256 standard opcodes with format, width, and mnemonic.
//!
//! Provides:
//! - [`OpcodeFormat`] — all DEX instruction format codes
//! - [`OpcodeEntry`] — static per-opcode record
//! - [`OPCODE_TABLE`] — the full 256-entry static table
//! - [`decode_dex_insn`] — decode a single DEX instruction from a byte slice

/// DEX instruction format codes as defined in the Dalvik bytecode specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpcodeFormat {
    /// op (10x): 1 code unit, no operands
    F10x,
    /// `op|v_a|v_b` (12x): 1 code unit, two 4-bit register fields
    F12x,
    /// `op|v_a|#+B` (11n): 1 code unit, 4-bit register + 4-bit literal
    F11n,
    /// op|AA (11x): 1 code unit, 8-bit register
    F11x,
    /// op|+AA (10t): 1 code unit, 8-bit signed branch offset
    F10t,
    /// op|00|+AAAA (20t): 2 code units, 16-bit branch offset
    F20t,
    /// op|AA|BBBB (20bc): 2 code units, error/debug pseudo
    F20bc,
    /// op|AA|BBBB (22x): 2 code units, 8-bit dest + 16-bit source register
    F22x,
    /// op|AA|+BBBB (21t): 2 code units, register + 16-bit branch offset
    F21t,
    /// op|AA|#+BBBB (21s): 2 code units, register + 16-bit signed literal
    F21s,
    /// op|AA|BBBB0000 (21h): 2 code units, register + high-16 literal
    F21h,
    /// op|AA|BBBB (21c): 2 code units, register + 16-bit pool index
    F21c,
    /// op|AA|BB|CC (23x): 2 code units, three 8-bit registers
    F23x,
    /// op|AA|BB|#+CC (22b): 2 code units, two 8-bit registers + 8-bit literal
    F22b,
    /// op|A|B|+CCCC (22t): 2 code units, two 4-bit registers + 16-bit offset
    F22t,
    /// op|A|B|#+CCCC (22s): 2 code units, two 4-bit registers + 16-bit literal
    F22s,
    /// op|A|B|CCCC (22c): 2 code units, two 4-bit registers + 16-bit type/field index
    F22c,
    /// op|A|B|CCCC (22cs): optimised form of 22c
    F22cs,
    /// op|00|+AAAAAAAA (30t): 3 code units, 32-bit branch offset
    F30t,
    /// op|00|AAAA|BBBB (32x): 3 code units, two 16-bit registers
    F32x,
    /// op|AA|BBBBBBBB (31i): 3 code units, register + 32-bit literal
    F31i,
    /// op|AA|+BBBBBBBB (31t): 3 code units, register + 32-bit branch offset
    F31t,
    /// op|AA|BBBBBBBB (31c): 3 code units, register + 32-bit pool index
    F31c,
    /// op|A|G|BBBB|DCFE (35c): 3 code units, up-to-5 registers + 16-bit index
    F35c,
    /// op|A|G|BBBB|DCFE (35ms): optimised 35c (virtual method)
    F35ms,
    /// op|A|G|BBBB|DCFE (35mi): optimised 35c (inline)
    F35mi,
    /// op|AA|BBBB|CCCC (3rc): 3 code units, register range + 16-bit index
    F3rc,
    /// op|AA|BBBB|CCCC (3rms): optimised 3rc (virtual method range)
    F3rms,
    /// op|AA|BBBB|CCCC (3rmi): optimised 3rc (inline range)
    F3rmi,
    /// op|A|G|BBBB|DCFE|HHHH (45cc): 4 code units, 5 registers + two 16-bit indices
    F45cc,
    /// op|AA|BBBB|CCCC|HHHH (4rcc): 4 code units, range + two 16-bit indices
    F4rcc,
    /// op|AA|BBBBBBBBBBBBBBBB (51l): 5 code units, register + 64-bit literal
    F51l,
}

impl OpcodeFormat {
    /// Return the number of 16-bit code units (words) consumed by this format.
    #[must_use]
    pub const fn code_units(self) -> usize {
        match self {
            Self::F10x | Self::F12x | Self::F11n | Self::F11x | Self::F10t => 1,
            Self::F20t
            | Self::F20bc
            | Self::F22x
            | Self::F21t
            | Self::F21s
            | Self::F21h
            | Self::F21c
            | Self::F23x
            | Self::F22b
            | Self::F22t
            | Self::F22s
            | Self::F22c
            | Self::F22cs => 2,
            Self::F30t
            | Self::F32x
            | Self::F31i
            | Self::F31t
            | Self::F31c
            | Self::F35c
            | Self::F35ms
            | Self::F35mi
            | Self::F3rc
            | Self::F3rms
            | Self::F3rmi => 3,
            Self::F45cc | Self::F4rcc => 4,
            Self::F51l => 5,
        }
    }

    /// Return the byte width of the instruction.
    #[must_use]
    pub const fn byte_width(self) -> usize {
        self.code_units() * 2
    }
}

/// A static entry describing one Dalvik opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpcodeEntry {
    /// The raw 8-bit opcode byte.
    pub opcode: u8,
    /// The official Dalvik mnemonic string.
    pub mnemonic: &'static str,
    /// The operand format.
    pub format: OpcodeFormat,
    /// Byte width (= `format.byte_width()`).
    pub width: u8,
}

impl OpcodeEntry {
    const fn new(opcode: u8, mnemonic: &'static str, format: OpcodeFormat) -> Self {
        let width = match format {
            OpcodeFormat::F10x
            | OpcodeFormat::F12x
            | OpcodeFormat::F11n
            | OpcodeFormat::F11x
            | OpcodeFormat::F10t => 2,
            OpcodeFormat::F20t
            | OpcodeFormat::F20bc
            | OpcodeFormat::F22x
            | OpcodeFormat::F21t
            | OpcodeFormat::F21s
            | OpcodeFormat::F21h
            | OpcodeFormat::F21c
            | OpcodeFormat::F23x
            | OpcodeFormat::F22b
            | OpcodeFormat::F22t
            | OpcodeFormat::F22s
            | OpcodeFormat::F22c
            | OpcodeFormat::F22cs => 4,
            OpcodeFormat::F30t
            | OpcodeFormat::F32x
            | OpcodeFormat::F31i
            | OpcodeFormat::F31t
            | OpcodeFormat::F31c
            | OpcodeFormat::F35c
            | OpcodeFormat::F35ms
            | OpcodeFormat::F35mi
            | OpcodeFormat::F3rc
            | OpcodeFormat::F3rms
            | OpcodeFormat::F3rmi => 6,
            OpcodeFormat::F45cc | OpcodeFormat::F4rcc => 8,
            OpcodeFormat::F51l => 10,
        };
        Self {
            opcode,
            mnemonic,
            format,
            width,
        }
    }
}

/// The complete 256-entry Dalvik opcode table.
///
/// Unused/reserved opcodes use `"unused"` as the mnemonic.
pub static OPCODE_TABLE: &[OpcodeEntry; 256] = &[
    OpcodeEntry::new(0x00, "nop", OpcodeFormat::F10x),
    OpcodeEntry::new(0x01, "move", OpcodeFormat::F12x),
    OpcodeEntry::new(0x02, "move/from16", OpcodeFormat::F22x),
    OpcodeEntry::new(0x03, "move/16", OpcodeFormat::F32x),
    OpcodeEntry::new(0x04, "move-wide", OpcodeFormat::F12x),
    OpcodeEntry::new(0x05, "move-wide/from16", OpcodeFormat::F22x),
    OpcodeEntry::new(0x06, "move-wide/16", OpcodeFormat::F32x),
    OpcodeEntry::new(0x07, "move-object", OpcodeFormat::F12x),
    OpcodeEntry::new(0x08, "move-object/from16", OpcodeFormat::F22x),
    OpcodeEntry::new(0x09, "move-object/16", OpcodeFormat::F32x),
    OpcodeEntry::new(0x0a, "move-result", OpcodeFormat::F11x),
    OpcodeEntry::new(0x0b, "move-result-wide", OpcodeFormat::F11x),
    OpcodeEntry::new(0x0c, "move-result-object", OpcodeFormat::F11x),
    OpcodeEntry::new(0x0d, "move-exception", OpcodeFormat::F11x),
    OpcodeEntry::new(0x0e, "return-void", OpcodeFormat::F10x),
    OpcodeEntry::new(0x0f, "return", OpcodeFormat::F11x),
    OpcodeEntry::new(0x10, "return-wide", OpcodeFormat::F11x),
    OpcodeEntry::new(0x11, "return-object", OpcodeFormat::F11x),
    OpcodeEntry::new(0x12, "const/4", OpcodeFormat::F11n),
    OpcodeEntry::new(0x13, "const/16", OpcodeFormat::F21s),
    OpcodeEntry::new(0x14, "const", OpcodeFormat::F31i),
    OpcodeEntry::new(0x15, "const/high16", OpcodeFormat::F21h),
    OpcodeEntry::new(0x16, "const-wide/16", OpcodeFormat::F21s),
    OpcodeEntry::new(0x17, "const-wide/32", OpcodeFormat::F31i),
    OpcodeEntry::new(0x18, "const-wide", OpcodeFormat::F51l),
    OpcodeEntry::new(0x19, "const-wide/high16", OpcodeFormat::F21h),
    OpcodeEntry::new(0x1a, "const-string", OpcodeFormat::F21c),
    OpcodeEntry::new(0x1b, "const-string/jumbo", OpcodeFormat::F31c),
    OpcodeEntry::new(0x1c, "const-class", OpcodeFormat::F21c),
    OpcodeEntry::new(0x1d, "monitor-enter", OpcodeFormat::F11x),
    OpcodeEntry::new(0x1e, "monitor-exit", OpcodeFormat::F11x),
    OpcodeEntry::new(0x1f, "check-cast", OpcodeFormat::F21c),
    OpcodeEntry::new(0x20, "instance-of", OpcodeFormat::F22c),
    OpcodeEntry::new(0x21, "array-length", OpcodeFormat::F12x),
    OpcodeEntry::new(0x22, "new-instance", OpcodeFormat::F21c),
    OpcodeEntry::new(0x23, "new-array", OpcodeFormat::F22c),
    OpcodeEntry::new(0x24, "filled-new-array", OpcodeFormat::F35c),
    OpcodeEntry::new(0x25, "filled-new-array/range", OpcodeFormat::F3rc),
    OpcodeEntry::new(0x26, "fill-array-data", OpcodeFormat::F31t),
    OpcodeEntry::new(0x27, "throw", OpcodeFormat::F11x),
    OpcodeEntry::new(0x28, "goto", OpcodeFormat::F10t),
    OpcodeEntry::new(0x29, "goto/16", OpcodeFormat::F20t),
    OpcodeEntry::new(0x2a, "goto/32", OpcodeFormat::F30t),
    OpcodeEntry::new(0x2b, "packed-switch", OpcodeFormat::F31t),
    OpcodeEntry::new(0x2c, "sparse-switch", OpcodeFormat::F31t),
    OpcodeEntry::new(0x2d, "cmpl-float", OpcodeFormat::F23x),
    OpcodeEntry::new(0x2e, "cmpg-float", OpcodeFormat::F23x),
    OpcodeEntry::new(0x2f, "cmpl-double", OpcodeFormat::F23x),
    OpcodeEntry::new(0x30, "cmpg-double", OpcodeFormat::F23x),
    OpcodeEntry::new(0x31, "cmp-long", OpcodeFormat::F23x),
    OpcodeEntry::new(0x32, "if-eq", OpcodeFormat::F22t),
    OpcodeEntry::new(0x33, "if-ne", OpcodeFormat::F22t),
    OpcodeEntry::new(0x34, "if-lt", OpcodeFormat::F22t),
    OpcodeEntry::new(0x35, "if-ge", OpcodeFormat::F22t),
    OpcodeEntry::new(0x36, "if-gt", OpcodeFormat::F22t),
    OpcodeEntry::new(0x37, "if-le", OpcodeFormat::F22t),
    OpcodeEntry::new(0x38, "if-eqz", OpcodeFormat::F21t),
    OpcodeEntry::new(0x39, "if-nez", OpcodeFormat::F21t),
    OpcodeEntry::new(0x3a, "if-ltz", OpcodeFormat::F21t),
    OpcodeEntry::new(0x3b, "if-gez", OpcodeFormat::F21t),
    OpcodeEntry::new(0x3c, "if-gtz", OpcodeFormat::F21t),
    OpcodeEntry::new(0x3d, "if-lez", OpcodeFormat::F21t),
    OpcodeEntry::new(0x3e, "unused-3e", OpcodeFormat::F10x),
    OpcodeEntry::new(0x3f, "unused-3f", OpcodeFormat::F10x),
    OpcodeEntry::new(0x40, "unused-40", OpcodeFormat::F10x),
    OpcodeEntry::new(0x41, "unused-41", OpcodeFormat::F10x),
    OpcodeEntry::new(0x42, "unused-42", OpcodeFormat::F10x),
    OpcodeEntry::new(0x43, "unused-43", OpcodeFormat::F10x),
    OpcodeEntry::new(0x44, "aget", OpcodeFormat::F23x),
    OpcodeEntry::new(0x45, "aget-wide", OpcodeFormat::F23x),
    OpcodeEntry::new(0x46, "aget-object", OpcodeFormat::F23x),
    OpcodeEntry::new(0x47, "aget-boolean", OpcodeFormat::F23x),
    OpcodeEntry::new(0x48, "aget-byte", OpcodeFormat::F23x),
    OpcodeEntry::new(0x49, "aget-char", OpcodeFormat::F23x),
    OpcodeEntry::new(0x4a, "aget-short", OpcodeFormat::F23x),
    OpcodeEntry::new(0x4b, "aput", OpcodeFormat::F23x),
    OpcodeEntry::new(0x4c, "aput-wide", OpcodeFormat::F23x),
    OpcodeEntry::new(0x4d, "aput-object", OpcodeFormat::F23x),
    OpcodeEntry::new(0x4e, "aput-boolean", OpcodeFormat::F23x),
    OpcodeEntry::new(0x4f, "aput-byte", OpcodeFormat::F23x),
    OpcodeEntry::new(0x50, "aput-char", OpcodeFormat::F23x),
    OpcodeEntry::new(0x51, "aput-short", OpcodeFormat::F23x),
    OpcodeEntry::new(0x52, "iget", OpcodeFormat::F22c),
    OpcodeEntry::new(0x53, "iget-wide", OpcodeFormat::F22c),
    OpcodeEntry::new(0x54, "iget-object", OpcodeFormat::F22c),
    OpcodeEntry::new(0x55, "iget-boolean", OpcodeFormat::F22c),
    OpcodeEntry::new(0x56, "iget-byte", OpcodeFormat::F22c),
    OpcodeEntry::new(0x57, "iget-char", OpcodeFormat::F22c),
    OpcodeEntry::new(0x58, "iget-short", OpcodeFormat::F22c),
    OpcodeEntry::new(0x59, "iput", OpcodeFormat::F22c),
    OpcodeEntry::new(0x5a, "iput-wide", OpcodeFormat::F22c),
    OpcodeEntry::new(0x5b, "iput-object", OpcodeFormat::F22c),
    OpcodeEntry::new(0x5c, "iput-boolean", OpcodeFormat::F22c),
    OpcodeEntry::new(0x5d, "iput-byte", OpcodeFormat::F22c),
    OpcodeEntry::new(0x5e, "iput-char", OpcodeFormat::F22c),
    OpcodeEntry::new(0x5f, "iput-short", OpcodeFormat::F22c),
    OpcodeEntry::new(0x60, "sget", OpcodeFormat::F21c),
    OpcodeEntry::new(0x61, "sget-wide", OpcodeFormat::F21c),
    OpcodeEntry::new(0x62, "sget-object", OpcodeFormat::F21c),
    OpcodeEntry::new(0x63, "sget-boolean", OpcodeFormat::F21c),
    OpcodeEntry::new(0x64, "sget-byte", OpcodeFormat::F21c),
    OpcodeEntry::new(0x65, "sget-char", OpcodeFormat::F21c),
    OpcodeEntry::new(0x66, "sget-short", OpcodeFormat::F21c),
    OpcodeEntry::new(0x67, "sput", OpcodeFormat::F21c),
    OpcodeEntry::new(0x68, "sput-wide", OpcodeFormat::F21c),
    OpcodeEntry::new(0x69, "sput-object", OpcodeFormat::F21c),
    OpcodeEntry::new(0x6a, "sput-boolean", OpcodeFormat::F21c),
    OpcodeEntry::new(0x6b, "sput-byte", OpcodeFormat::F21c),
    OpcodeEntry::new(0x6c, "sput-char", OpcodeFormat::F21c),
    OpcodeEntry::new(0x6d, "sput-short", OpcodeFormat::F21c),
    OpcodeEntry::new(0x6e, "invoke-virtual", OpcodeFormat::F35c),
    OpcodeEntry::new(0x6f, "invoke-super", OpcodeFormat::F35c),
    OpcodeEntry::new(0x70, "invoke-direct", OpcodeFormat::F35c),
    OpcodeEntry::new(0x71, "invoke-static", OpcodeFormat::F35c),
    OpcodeEntry::new(0x72, "invoke-interface", OpcodeFormat::F35c),
    OpcodeEntry::new(0x73, "unused-73", OpcodeFormat::F10x),
    OpcodeEntry::new(0x74, "invoke-virtual/range", OpcodeFormat::F3rc),
    OpcodeEntry::new(0x75, "invoke-super/range", OpcodeFormat::F3rc),
    OpcodeEntry::new(0x76, "invoke-direct/range", OpcodeFormat::F3rc),
    OpcodeEntry::new(0x77, "invoke-static/range", OpcodeFormat::F3rc),
    OpcodeEntry::new(0x78, "invoke-interface/range", OpcodeFormat::F3rc),
    OpcodeEntry::new(0x79, "unused-79", OpcodeFormat::F10x),
    OpcodeEntry::new(0x7a, "unused-7a", OpcodeFormat::F10x),
    OpcodeEntry::new(0x7b, "neg-int", OpcodeFormat::F12x),
    OpcodeEntry::new(0x7c, "not-int", OpcodeFormat::F12x),
    OpcodeEntry::new(0x7d, "neg-long", OpcodeFormat::F12x),
    OpcodeEntry::new(0x7e, "not-long", OpcodeFormat::F12x),
    OpcodeEntry::new(0x7f, "neg-float", OpcodeFormat::F12x),
    OpcodeEntry::new(0x80, "neg-double", OpcodeFormat::F12x),
    OpcodeEntry::new(0x81, "int-to-long", OpcodeFormat::F12x),
    OpcodeEntry::new(0x82, "int-to-float", OpcodeFormat::F12x),
    OpcodeEntry::new(0x83, "int-to-double", OpcodeFormat::F12x),
    OpcodeEntry::new(0x84, "long-to-int", OpcodeFormat::F12x),
    OpcodeEntry::new(0x85, "long-to-float", OpcodeFormat::F12x),
    OpcodeEntry::new(0x86, "long-to-double", OpcodeFormat::F12x),
    OpcodeEntry::new(0x87, "float-to-int", OpcodeFormat::F12x),
    OpcodeEntry::new(0x88, "float-to-long", OpcodeFormat::F12x),
    OpcodeEntry::new(0x89, "float-to-double", OpcodeFormat::F12x),
    OpcodeEntry::new(0x8a, "double-to-int", OpcodeFormat::F12x),
    OpcodeEntry::new(0x8b, "double-to-long", OpcodeFormat::F12x),
    OpcodeEntry::new(0x8c, "double-to-float", OpcodeFormat::F12x),
    OpcodeEntry::new(0x8d, "int-to-byte", OpcodeFormat::F12x),
    OpcodeEntry::new(0x8e, "int-to-char", OpcodeFormat::F12x),
    OpcodeEntry::new(0x8f, "int-to-short", OpcodeFormat::F12x),
    OpcodeEntry::new(0x90, "add-int", OpcodeFormat::F23x),
    OpcodeEntry::new(0x91, "sub-int", OpcodeFormat::F23x),
    OpcodeEntry::new(0x92, "mul-int", OpcodeFormat::F23x),
    OpcodeEntry::new(0x93, "div-int", OpcodeFormat::F23x),
    OpcodeEntry::new(0x94, "rem-int", OpcodeFormat::F23x),
    OpcodeEntry::new(0x95, "and-int", OpcodeFormat::F23x),
    OpcodeEntry::new(0x96, "or-int", OpcodeFormat::F23x),
    OpcodeEntry::new(0x97, "xor-int", OpcodeFormat::F23x),
    OpcodeEntry::new(0x98, "shl-int", OpcodeFormat::F23x),
    OpcodeEntry::new(0x99, "shr-int", OpcodeFormat::F23x),
    OpcodeEntry::new(0x9a, "ushr-int", OpcodeFormat::F23x),
    OpcodeEntry::new(0x9b, "add-long", OpcodeFormat::F23x),
    OpcodeEntry::new(0x9c, "sub-long", OpcodeFormat::F23x),
    OpcodeEntry::new(0x9d, "mul-long", OpcodeFormat::F23x),
    OpcodeEntry::new(0x9e, "div-long", OpcodeFormat::F23x),
    OpcodeEntry::new(0x9f, "rem-long", OpcodeFormat::F23x),
    OpcodeEntry::new(0xa0, "and-long", OpcodeFormat::F23x),
    OpcodeEntry::new(0xa1, "or-long", OpcodeFormat::F23x),
    OpcodeEntry::new(0xa2, "xor-long", OpcodeFormat::F23x),
    OpcodeEntry::new(0xa3, "shl-long", OpcodeFormat::F23x),
    OpcodeEntry::new(0xa4, "shr-long", OpcodeFormat::F23x),
    OpcodeEntry::new(0xa5, "ushr-long", OpcodeFormat::F23x),
    OpcodeEntry::new(0xa6, "add-float", OpcodeFormat::F23x),
    OpcodeEntry::new(0xa7, "sub-float", OpcodeFormat::F23x),
    OpcodeEntry::new(0xa8, "mul-float", OpcodeFormat::F23x),
    OpcodeEntry::new(0xa9, "div-float", OpcodeFormat::F23x),
    OpcodeEntry::new(0xaa, "rem-float", OpcodeFormat::F23x),
    OpcodeEntry::new(0xab, "add-double", OpcodeFormat::F23x),
    OpcodeEntry::new(0xac, "sub-double", OpcodeFormat::F23x),
    OpcodeEntry::new(0xad, "mul-double", OpcodeFormat::F23x),
    OpcodeEntry::new(0xae, "div-double", OpcodeFormat::F23x),
    OpcodeEntry::new(0xaf, "rem-double", OpcodeFormat::F23x),
    OpcodeEntry::new(0xb0, "add-int/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xb1, "sub-int/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xb2, "mul-int/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xb3, "div-int/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xb4, "rem-int/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xb5, "and-int/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xb6, "or-int/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xb7, "xor-int/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xb8, "shl-int/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xb9, "shr-int/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xba, "ushr-int/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xbb, "add-long/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xbc, "sub-long/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xbd, "mul-long/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xbe, "div-long/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xbf, "rem-long/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xc0, "and-long/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xc1, "or-long/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xc2, "xor-long/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xc3, "shl-long/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xc4, "shr-long/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xc5, "ushr-long/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xc6, "add-float/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xc7, "sub-float/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xc8, "mul-float/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xc9, "div-float/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xca, "rem-float/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xcb, "add-double/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xcc, "sub-double/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xcd, "mul-double/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xce, "div-double/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xcf, "rem-double/2addr", OpcodeFormat::F12x),
    OpcodeEntry::new(0xd0, "add-int/lit16", OpcodeFormat::F22s),
    OpcodeEntry::new(0xd1, "rsub-int", OpcodeFormat::F22s),
    OpcodeEntry::new(0xd2, "mul-int/lit16", OpcodeFormat::F22s),
    OpcodeEntry::new(0xd3, "div-int/lit16", OpcodeFormat::F22s),
    OpcodeEntry::new(0xd4, "rem-int/lit16", OpcodeFormat::F22s),
    OpcodeEntry::new(0xd5, "and-int/lit16", OpcodeFormat::F22s),
    OpcodeEntry::new(0xd6, "or-int/lit16", OpcodeFormat::F22s),
    OpcodeEntry::new(0xd7, "xor-int/lit16", OpcodeFormat::F22s),
    OpcodeEntry::new(0xd8, "add-int/lit8", OpcodeFormat::F22b),
    OpcodeEntry::new(0xd9, "rsub-int/lit8", OpcodeFormat::F22b),
    OpcodeEntry::new(0xda, "mul-int/lit8", OpcodeFormat::F22b),
    OpcodeEntry::new(0xdb, "div-int/lit8", OpcodeFormat::F22b),
    OpcodeEntry::new(0xdc, "rem-int/lit8", OpcodeFormat::F22b),
    OpcodeEntry::new(0xdd, "and-int/lit8", OpcodeFormat::F22b),
    OpcodeEntry::new(0xde, "or-int/lit8", OpcodeFormat::F22b),
    OpcodeEntry::new(0xdf, "xor-int/lit8", OpcodeFormat::F22b),
    OpcodeEntry::new(0xe0, "shl-int/lit8", OpcodeFormat::F22b),
    OpcodeEntry::new(0xe1, "shr-int/lit8", OpcodeFormat::F22b),
    OpcodeEntry::new(0xe2, "ushr-int/lit8", OpcodeFormat::F22b),
    // ART optimized range 0xe3..0xf9
    OpcodeEntry::new(0xe3, "iget-quick", OpcodeFormat::F22c),
    OpcodeEntry::new(0xe4, "iget-wide-quick", OpcodeFormat::F22c),
    OpcodeEntry::new(0xe5, "iget-object-quick", OpcodeFormat::F22c),
    OpcodeEntry::new(0xe6, "iput-quick", OpcodeFormat::F22c),
    OpcodeEntry::new(0xe7, "iput-wide-quick", OpcodeFormat::F22c),
    OpcodeEntry::new(0xe8, "iput-object-quick", OpcodeFormat::F22c),
    OpcodeEntry::new(0xe9, "invoke-virtual-quick", OpcodeFormat::F35ms),
    OpcodeEntry::new(0xea, "invoke-virtual-quick/range", OpcodeFormat::F3rms),
    OpcodeEntry::new(0xeb, "iput-boolean-quick", OpcodeFormat::F22cs),
    OpcodeEntry::new(0xec, "iput-byte-quick", OpcodeFormat::F22cs),
    OpcodeEntry::new(0xed, "iput-char-quick", OpcodeFormat::F22cs),
    OpcodeEntry::new(0xee, "iput-short-quick", OpcodeFormat::F22cs),
    OpcodeEntry::new(0xef, "iget-boolean-quick", OpcodeFormat::F22cs),
    OpcodeEntry::new(0xf0, "iget-byte-quick", OpcodeFormat::F22cs),
    OpcodeEntry::new(0xf1, "iget-char-quick", OpcodeFormat::F22cs),
    OpcodeEntry::new(0xf2, "iget-short-quick", OpcodeFormat::F22cs),
    OpcodeEntry::new(0xf3, "invoke-lambda", OpcodeFormat::F35c),
    OpcodeEntry::new(0xf4, "capture-variable", OpcodeFormat::F21c),
    OpcodeEntry::new(0xf5, "create-lambda", OpcodeFormat::F21c),
    OpcodeEntry::new(0xf6, "liberate-variable", OpcodeFormat::F21c),
    OpcodeEntry::new(0xf7, "box-lambda", OpcodeFormat::F22x),
    OpcodeEntry::new(0xf8, "unbox-lambda", OpcodeFormat::F22x),
    OpcodeEntry::new(0xf9, "unused-f9", OpcodeFormat::F10x),
    OpcodeEntry::new(0xfa, "invoke-polymorphic", OpcodeFormat::F45cc),
    OpcodeEntry::new(0xfb, "invoke-polymorphic/range", OpcodeFormat::F4rcc),
    OpcodeEntry::new(0xfc, "invoke-custom", OpcodeFormat::F35c),
    OpcodeEntry::new(0xfd, "invoke-custom/range", OpcodeFormat::F3rc),
    OpcodeEntry::new(0xfe, "const-method-handle", OpcodeFormat::F21c),
    OpcodeEntry::new(0xff, "const-method-type", OpcodeFormat::F21c),
];

/// Errors from [`decode_dex_insn`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The byte slice was too short for this instruction.
    Truncated { needed: usize, got: usize },
    /// The opcode is marked as unused/reserved.
    Unused(u8),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { needed, got } => write!(
                f,
                "truncated DEX instruction: need {needed} bytes, got {got}"
            ),
            Self::Unused(op) => write!(f, "unused DEX opcode 0x{op:02x}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A decoded DEX instruction with all operand fields extracted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInsn {
    /// The opcode entry from the static table.
    pub entry: &'static OpcodeEntry,
    /// Register A (destination in most formats, 4-bit for 12x/11n/22t/22s/22c).
    pub v_a: u16,
    /// Register B (source in most formats).
    pub v_b: u16,
    /// Register C (third operand in 23x/22b).
    pub v_c: u16,
    /// Literal / immediate value (sign-extended).
    pub literal: i64,
    /// Pool index (string/type/field/method).
    pub index: u32,
    /// Branch / payload offset (in 16-bit code units).
    pub offset: i32,
    /// Byte width of this instruction.
    pub width: usize,
}

/// Read a little-endian `u16` from `bytes` at `offset`.
fn ru16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

/// Read a little-endian `u32` from `bytes` at `offset`.
fn ru32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Read a little-endian `u64` from `bytes` at `offset`.
fn ru64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// Decode one Dalvik instruction from the given byte slice.
///
/// Returns the [`DecodedInsn`] on success, or a [`DecodeError`] if the bytes
/// are too short or the opcode is unused/reserved.
///
/// # Errors
/// Returns [`DecodeError::Truncated`] when fewer bytes are available than the
/// instruction format requires, and [`DecodeError::Unused`] for opcodes marked
/// `unused-*` in the standard table.
pub fn decode_dex_insn(bytes: &[u8]) -> Result<DecodedInsn, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::Truncated { needed: 2, got: 0 });
    }
    let op = bytes[0];
    let hi = if bytes.len() > 1 { bytes[1] } else { 0 };
    let entry = &OPCODE_TABLE[op as usize];

    let width = entry.width as usize;
    if bytes.len() < width {
        return Err(DecodeError::Truncated {
            needed: width,
            got: bytes.len(),
        });
    }

    // Reject unused opcodes
    if entry.mnemonic.starts_with("unused") {
        return Err(DecodeError::Unused(op));
    }

    let mut v_a: u16 = 0;
    let mut v_b: u16 = 0;
    let mut v_c: u16 = 0;
    let mut literal: i64 = 0;
    let mut index: u32 = 0;
    let mut offset: i32 = 0;

    match entry.format {
        OpcodeFormat::F10x => {}
        OpcodeFormat::F12x => {
            v_a = u16::from(hi & 0x0f);
            v_b = u16::from((hi >> 4) & 0x0f);
        }
        OpcodeFormat::F11n => {
            v_a = u16::from(hi & 0x0f);
            let raw = ((hi >> 4) & 0x0f) as i8;
            literal = if raw & 0x8 != 0 {
                i64::from(raw) | -16i64
            } else {
                i64::from(raw)
            };
        }
        OpcodeFormat::F11x => {
            v_a = u16::from(hi);
        }
        OpcodeFormat::F10t => {
            offset = i32::from(hi as i8);
        }
        OpcodeFormat::F20t => {
            let raw = ru16(bytes, 2).unwrap() as i16;
            offset = i32::from(raw);
        }
        OpcodeFormat::F20bc => {
            v_a = u16::from(hi);
            index = u32::from(ru16(bytes, 2).unwrap());
        }
        OpcodeFormat::F22x => {
            v_a = u16::from(hi);
            v_b = ru16(bytes, 2).unwrap();
        }
        OpcodeFormat::F21t => {
            v_a = u16::from(hi);
            let raw = ru16(bytes, 2).unwrap() as i16;
            offset = i32::from(raw);
        }
        OpcodeFormat::F21s => {
            v_a = u16::from(hi);
            let raw = ru16(bytes, 2).unwrap() as i16;
            literal = i64::from(raw);
        }
        OpcodeFormat::F21h => {
            v_a = u16::from(hi);
            let raw = i64::from(ru16(bytes, 2).unwrap() as i16);
            // The literal has the 16-bit value in the high bits
            literal = if op == 0x19 { raw << 48 } else { raw << 16 };
        }
        OpcodeFormat::F21c => {
            v_a = u16::from(hi);
            index = u32::from(ru16(bytes, 2).unwrap());
        }
        OpcodeFormat::F23x => {
            v_a = u16::from(hi);
            v_b = u16::from(bytes[2]);
            v_c = u16::from(bytes[3]);
        }
        OpcodeFormat::F22b => {
            v_a = u16::from(hi);
            v_b = u16::from(bytes[2]);
            literal = i64::from(bytes[3] as i8);
        }
        OpcodeFormat::F22t => {
            v_a = u16::from(hi & 0x0f);
            v_b = u16::from((hi >> 4) & 0x0f);
            let raw = ru16(bytes, 2).unwrap() as i16;
            offset = i32::from(raw);
        }
        OpcodeFormat::F22s => {
            v_a = u16::from(hi & 0x0f);
            v_b = u16::from((hi >> 4) & 0x0f);
            let raw = ru16(bytes, 2).unwrap() as i16;
            literal = i64::from(raw);
        }
        OpcodeFormat::F22c | OpcodeFormat::F22cs => {
            v_a = u16::from(hi & 0x0f);
            v_b = u16::from((hi >> 4) & 0x0f);
            index = u32::from(ru16(bytes, 2).unwrap());
        }
        OpcodeFormat::F30t => {
            let raw = ru32(bytes, 2).unwrap() as i32;
            offset = raw;
        }
        OpcodeFormat::F32x => {
            v_a = ru16(bytes, 2).unwrap();
            v_b = ru16(bytes, 4).unwrap();
        }
        OpcodeFormat::F31i => {
            v_a = u16::from(hi);
            literal = i64::from(ru32(bytes, 2).unwrap() as i32);
        }
        OpcodeFormat::F31t => {
            v_a = u16::from(hi);
            let raw = ru32(bytes, 2).unwrap() as i32;
            offset = raw;
        }
        OpcodeFormat::F31c => {
            v_a = u16::from(hi);
            index = ru32(bytes, 2).unwrap();
        }
        OpcodeFormat::F35c | OpcodeFormat::F35ms | OpcodeFormat::F35mi => {
            // count = hi[7:4], G = hi[3:0]
            let count = u16::from((hi >> 4) & 0x0f);
            v_a = count; // repurpose v_a for count
            v_c = u16::from(hi & 0x0f); // vG
            index = u32::from(ru16(bytes, 2).unwrap());
            // register nibbles packed in bytes[4..6]
            v_b = if bytes.len() > 4 {
                u16::from(bytes[4])
            } else {
                0
            };
        }
        OpcodeFormat::F3rc | OpcodeFormat::F3rms | OpcodeFormat::F3rmi => {
            v_a = u16::from(hi); // count
            index = u32::from(ru16(bytes, 2).unwrap());
            v_b = ru16(bytes, 4).unwrap(); // first register
        }
        OpcodeFormat::F45cc => {
            v_a = u16::from((hi >> 4) & 0x0f); // count
            v_c = u16::from(hi & 0x0f); // G
            index = u32::from(ru16(bytes, 2).unwrap());
            // proto_index in bytes[6..8]
            literal = i64::from(ru16(bytes, 6).unwrap());
        }
        OpcodeFormat::F4rcc => {
            v_a = u16::from(hi); // count
            index = u32::from(ru16(bytes, 2).unwrap());
            v_b = ru16(bytes, 4).unwrap(); // first register
            literal = i64::from(ru16(bytes, 6).unwrap()); // proto index
        }
        OpcodeFormat::F51l => {
            v_a = u16::from(hi);
            literal = ru64(bytes, 2).unwrap() as i64;
        }
    }

    Ok(DecodedInsn {
        entry,
        v_a,
        v_b,
        v_c,
        literal,
        index,
        offset,
        width,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_table_len() {
        assert_eq!(OPCODE_TABLE.len(), 256);
    }

    #[test]
    fn test_opcode_indices_match() {
        for (i, entry) in OPCODE_TABLE.iter().enumerate() {
            assert_eq!(entry.opcode as usize, i, "opcode mismatch at index {i}");
        }
    }

    #[test]
    fn test_nop_entry() {
        let e = &OPCODE_TABLE[0];
        assert_eq!(e.mnemonic, "nop");
        assert_eq!(e.format, OpcodeFormat::F10x);
        assert_eq!(e.width, 2);
    }

    #[test]
    fn test_return_void_entry() {
        let e = &OPCODE_TABLE[0x0e];
        assert_eq!(e.mnemonic, "return-void");
        assert_eq!(e.format, OpcodeFormat::F10x);
    }

    #[test]
    fn test_const_wide_entry() {
        let e = &OPCODE_TABLE[0x18];
        assert_eq!(e.mnemonic, "const-wide");
        assert_eq!(e.format, OpcodeFormat::F51l);
        assert_eq!(e.width, 10);
    }

    #[test]
    fn test_invoke_virtual_entry() {
        let e = &OPCODE_TABLE[0x6e];
        assert_eq!(e.mnemonic, "invoke-virtual");
        assert_eq!(e.format, OpcodeFormat::F35c);
    }

    #[test]
    fn test_add_int_entry() {
        let e = &OPCODE_TABLE[0x90];
        assert_eq!(e.mnemonic, "add-int");
        assert_eq!(e.format, OpcodeFormat::F23x);
    }

    #[test]
    fn test_const4_entry() {
        let e = &OPCODE_TABLE[0x12];
        assert_eq!(e.mnemonic, "const/4");
        assert_eq!(e.format, OpcodeFormat::F11n);
    }

    #[test]
    fn test_format_code_units() {
        assert_eq!(OpcodeFormat::F10x.code_units(), 1);
        assert_eq!(OpcodeFormat::F21c.code_units(), 2);
        assert_eq!(OpcodeFormat::F35c.code_units(), 3);
        assert_eq!(OpcodeFormat::F51l.code_units(), 5);
    }

    #[test]
    fn test_format_byte_width() {
        assert_eq!(OpcodeFormat::F10x.byte_width(), 2);
        assert_eq!(OpcodeFormat::F23x.byte_width(), 4);
        assert_eq!(OpcodeFormat::F51l.byte_width(), 10);
    }

    #[test]
    fn test_decode_nop() {
        let insn = decode_dex_insn(&[0x00, 0x00]).unwrap();
        assert_eq!(insn.entry.mnemonic, "nop");
        assert_eq!(insn.width, 2);
    }

    #[test]
    fn test_decode_move_12x() {
        // move v1, v2 → opcode=0x01, hi=0x21 (A=1, B=2)
        let insn = decode_dex_insn(&[0x01, 0x21]).unwrap();
        assert_eq!(insn.entry.mnemonic, "move");
        assert_eq!(insn.v_a, 1);
        assert_eq!(insn.v_b, 2);
    }

    #[test]
    fn test_decode_const4_11n() {
        // const/4 v0, #1 → opcode=0x12, hi=0x10 (A=0, B=1)
        let insn = decode_dex_insn(&[0x12, 0x10]).unwrap();
        assert_eq!(insn.entry.mnemonic, "const/4");
        assert_eq!(insn.v_a, 0);
        assert_eq!(insn.literal, 1);
    }

    #[test]
    fn test_decode_const4_negative() {
        // const/4 v0, #-1 → hi=0xF0
        let insn = decode_dex_insn(&[0x12, 0xF0]).unwrap();
        assert_eq!(insn.literal, -1);
    }

    #[test]
    fn test_decode_return_void_11x() {
        let insn = decode_dex_insn(&[0x0e, 0x00]).unwrap();
        assert_eq!(insn.entry.mnemonic, "return-void");
        assert_eq!(insn.width, 2);
    }

    #[test]
    fn test_decode_goto_10t() {
        // goto +4 → opcode=0x28, hi=0x04
        let insn = decode_dex_insn(&[0x28, 0x04]).unwrap();
        assert_eq!(insn.entry.mnemonic, "goto");
        assert_eq!(insn.offset, 4);
    }

    #[test]
    fn test_decode_goto16_20t() {
        let insn = decode_dex_insn(&[0x29, 0x00, 0x0a, 0x00]).unwrap();
        assert_eq!(insn.entry.mnemonic, "goto/16");
        assert_eq!(insn.offset, 10);
    }

    #[test]
    fn test_decode_const16_21s() {
        // const/16 v1, #5 → opcode=0x13, hi=0x01, [0x05,0x00]
        let insn = decode_dex_insn(&[0x13, 0x01, 0x05, 0x00]).unwrap();
        assert_eq!(insn.v_a, 1);
        assert_eq!(insn.literal, 5);
    }

    #[test]
    fn test_decode_add_int_23x() {
        // add-int v2, v3, v4
        let insn = decode_dex_insn(&[0x90, 0x02, 0x03, 0x04]).unwrap();
        assert_eq!(insn.entry.mnemonic, "add-int");
        assert_eq!(insn.v_a, 2);
        assert_eq!(insn.v_b, 3);
        assert_eq!(insn.v_c, 4);
    }

    #[test]
    fn test_decode_iget_22c() {
        let insn = decode_dex_insn(&[0x52, 0x10, 0x01, 0x00]).unwrap();
        assert_eq!(insn.entry.mnemonic, "iget");
        assert_eq!(insn.v_a, 0);
        assert_eq!(insn.v_b, 1);
        assert_eq!(insn.index, 1);
    }

    #[test]
    fn test_decode_const_wide_51l() {
        let mut buf = vec![0x18_u8, 0x00];
        buf.extend_from_slice(&0x0102030405060708_u64.to_le_bytes());
        let insn = decode_dex_insn(&buf).unwrap();
        assert_eq!(insn.entry.mnemonic, "const-wide");
        assert_eq!(insn.width, 10);
        assert_eq!(insn.literal, 0x0102030405060708_u64 as i64);
    }

    #[test]
    fn test_decode_if_eq_22t() {
        // if-eq v0, v1, +5
        let insn = decode_dex_insn(&[0x32, 0x10, 0x05, 0x00]).unwrap();
        assert_eq!(insn.entry.mnemonic, "if-eq");
        assert_eq!(insn.v_a, 0);
        assert_eq!(insn.v_b, 1);
        assert_eq!(insn.offset, 5);
    }

    #[test]
    fn test_decode_invoke_static_35c() {
        let insn = decode_dex_insn(&[0x71, 0x00, 0x05, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(insn.entry.mnemonic, "invoke-static");
        assert_eq!(insn.index, 5);
    }

    #[test]
    fn test_decode_invoke_range_3rc() {
        let insn = decode_dex_insn(&[0x74, 0x02, 0x01, 0x00, 0x03, 0x00]).unwrap();
        assert_eq!(insn.entry.mnemonic, "invoke-virtual/range");
        assert_eq!(insn.v_a, 2); // count
        assert_eq!(insn.index, 1);
        assert_eq!(insn.v_b, 3); // first register
    }

    #[test]
    fn test_decode_unused_opcode() {
        let err = decode_dex_insn(&[0x3e, 0x00]).unwrap_err();
        assert!(matches!(err, DecodeError::Unused(0x3e)));
    }

    #[test]
    fn test_decode_truncated() {
        let err = decode_dex_insn(&[0x90]).unwrap_err(); // add-int needs 4 bytes
        assert!(matches!(err, DecodeError::Truncated { .. }));
    }

    #[test]
    fn test_decode_empty() {
        let err = decode_dex_insn(&[]).unwrap_err();
        assert!(matches!(err, DecodeError::Truncated { got: 0, .. }));
    }

    #[test]
    fn test_decode_sget_21c() {
        let insn = decode_dex_insn(&[0x60, 0x01, 0x02, 0x00]).unwrap();
        assert_eq!(insn.entry.mnemonic, "sget");
        assert_eq!(insn.v_a, 1);
        assert_eq!(insn.index, 2);
    }

    #[test]
    fn test_decode_add_int_lit8_22b() {
        let insn = decode_dex_insn(&[0xd8, 0x02, 0x01, 0x05]).unwrap();
        assert_eq!(insn.entry.mnemonic, "add-int/lit8");
        assert_eq!(insn.v_a, 2);
        assert_eq!(insn.v_b, 1);
        assert_eq!(insn.literal, 5);
    }

    #[test]
    fn test_decode_const_string_21c() {
        let insn = decode_dex_insn(&[0x1a, 0x01, 0x05, 0x00]).unwrap();
        assert_eq!(insn.entry.mnemonic, "const-string");
        assert_eq!(insn.v_a, 1);
        assert_eq!(insn.index, 5);
    }

    #[test]
    fn test_all_widths_positive() {
        for entry in OPCODE_TABLE {
            assert!(entry.width >= 2, "entry {} has zero width", entry.mnemonic);
        }
    }
}
