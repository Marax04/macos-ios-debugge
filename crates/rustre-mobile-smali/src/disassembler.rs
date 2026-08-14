//! `disassembler` — Dalvik bytecode disassembler.
//!
//! Converts raw DEX method bytecode (`&[u8]` or `&[u16]`) back into a list of
//! `DisasmInstr` values, which can then be pretty-printed by `printer::print_method`.
//!
//! Covers the portable Dalvik opcode range 0x00–0xE2 (Dalvik bytecode
//! specification rev 014) with format descriptions, operand widths, and
//! human-readable mnemonics.
//!
//! # Coverage
//!
//! This header used to claim 0x00–0xFF, but the table stopped at 0xE2 and also
//! skipped 0x9B–0xAF and 0xBB–0xCF — the whole long/float/double arithmetic
//! block and its `/2addr` variants, which appear in essentially every real
//! method.  Those 42 opcodes are now present; they needed no new machinery,
//! being plain `23x`/`12x` forms like the `-int` opcodes already listed.
//!
//! Still absent, and deliberately so: 0xE3–0xFF, i.e. the ART `-quick` field
//! and invoke accessors, the experimental lambda opcodes, and
//! `invoke-polymorphic` / `invoke-custom` / `const-method-handle` /
//! `const-method-type`.  Those need instruction formats this module does not
//! model (`22cs`, `35ms`, `3rms`, `45cc`, `4rcc`), so adding them is a feature
//! rather than a table entry.  [`lookup_opcode`] returns `None` for them, which
//! callers must handle.
//!
//! The authority for both the mnemonics and the formats above is
//! `rustre-arch-dex::full_opcode_table`, a 256-entry table that records the
//! instruction format of every opcode; the 42 entries added here were generated
//! from it rather than transcribed.

use super::SmaliError;

// ─────────────────────────────────────────────────────────────────────────────
// Dalvik opcode table
// ─────────────────────────────────────────────────────────────────────────────

/// Instruction format codes (matching the Dalvik spec nomenclature).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Format {
    /// `10x` — 1 code unit, no operands.
    F10x,
    /// `12x` — 1 code unit, 2 × 4-bit registers.
    F12x,
    /// `11n` — 1 code unit, 1 × 4-bit register + 4-bit literal.
    F11n,
    /// `11x` — 1 code unit, 1 × 8-bit register.
    F11x,
    /// `10t` — 1 code unit, 8-bit branch offset.
    F10t,
    /// `20t` — 2 code units, 16-bit branch offset.
    F20t,
    /// `22x` — 2 code units, 8-bit dest + 16-bit src register.
    F22x,
    /// `21t` — 2 code units, 8-bit reg + 16-bit branch offset.
    F21t,
    /// `21s` — 2 code units, 8-bit reg + 16-bit signed literal.
    F21s,
    /// `21h` — 2 code units, 8-bit reg + 16-bit literal (shifted).
    F21h,
    /// `21c` — 2 code units, 8-bit reg + 16-bit index.
    F21c,
    /// `23x` — 2 code units, three 8-bit register indices.
    F23x,
    /// `22b` — 2 code units, 2 × 8-bit regs + 8-bit signed literal.
    F22b,
    /// `22t` — 2 code units, 2 × 4-bit regs + 16-bit branch offset.
    F22t,
    /// `22s` — 2 code units, 2 × 4-bit regs + 16-bit literal.
    F22s,
    /// `22c` — 2 code units, 2 × 4-bit regs + 16-bit type/field index.
    F22c,
    /// `32x` — 3 code units, 2 × 16-bit register indices.
    F32x,
    /// `30t` — 3 code units, 32-bit branch offset.
    F30t,
    /// `31t` — 3 code units, 8-bit reg + 32-bit branch offset.
    F31t,
    /// `31i` — 3 code units, 8-bit reg + 32-bit literal.
    F31i,
    /// `31c` — 3 code units, 8-bit reg + 32-bit string index.
    F31c,
    /// `35c` — 3 code units, count/A (4-bit) + method/type index + 5 regs.
    F35c,
    /// `3rc` — 3 code units, count/A (8-bit) + index + first reg (16-bit).
    F3rc,
    /// `51l` — 5 code units, 8-bit reg + 64-bit literal.
    F51l,
}

impl Format {
    /// Number of 16-bit code units consumed.
    #[must_use]
    pub const fn code_units(self) -> usize {
        match self {
            Self::F10x | Self::F12x | Self::F11n | Self::F11x | Self::F10t => 1,
            Self::F20t
            | Self::F22x
            | Self::F21t
            | Self::F21s
            | Self::F21h
            | Self::F21c
            | Self::F23x
            | Self::F22b
            | Self::F22t
            | Self::F22s
            | Self::F22c => 2,
            Self::F32x
            | Self::F30t
            | Self::F31t
            | Self::F31i
            | Self::F31c
            | Self::F35c
            | Self::F3rc => 3,
            Self::F51l => 5,
        }
    }
}

/// Static opcode descriptor.
#[derive(Debug, Clone, Copy)]
pub struct OpcodeDesc {
    pub opcode: u8,
    pub mnemonic: &'static str,
    pub format: Format,
}

macro_rules! op {
    ($code:expr, $name:expr, $fmt:ident) => {
        OpcodeDesc {
            opcode: $code,
            mnemonic: $name,
            format: Format::$fmt,
        }
    };
}

/// Full Dalvik opcode table (subset — all commonly encountered opcodes).
pub const OPCODE_TABLE: &[OpcodeDesc] = &[
    op!(0x00, "nop", F10x),
    op!(0x01, "move", F12x),
    op!(0x02, "move/from16", F22x),
    op!(0x03, "move/16", F32x),
    op!(0x04, "move-wide", F12x),
    op!(0x05, "move-wide/from16", F22x),
    op!(0x06, "move-wide/16", F32x),
    op!(0x07, "move-object", F12x),
    op!(0x08, "move-object/from16", F22x),
    op!(0x09, "move-object/16", F32x),
    op!(0x0A, "move-result", F11x),
    op!(0x0B, "move-result-wide", F11x),
    op!(0x0C, "move-result-object", F11x),
    op!(0x0D, "move-exception", F11x),
    op!(0x0E, "return-void", F10x),
    op!(0x0F, "return", F11x),
    op!(0x10, "return-wide", F11x),
    op!(0x11, "return-object", F11x),
    op!(0x12, "const/4", F11n),
    op!(0x13, "const/16", F21s),
    op!(0x14, "const", F31i),
    op!(0x15, "const/high16", F21h),
    op!(0x16, "const-wide/16", F21s),
    op!(0x17, "const-wide/32", F31i),
    op!(0x18, "const-wide", F51l),
    op!(0x19, "const-wide/high16", F21h),
    op!(0x1A, "const-string", F21c),
    op!(0x1B, "const-string/jumbo", F31c),
    op!(0x1C, "const-class", F21c),
    op!(0x1D, "monitor-enter", F11x),
    op!(0x1E, "monitor-exit", F11x),
    op!(0x1F, "check-cast", F21c),
    op!(0x20, "instance-of", F22c),
    op!(0x21, "array-length", F12x),
    op!(0x22, "new-instance", F21c),
    op!(0x23, "new-array", F22c),
    op!(0x24, "filled-new-array", F35c),
    op!(0x25, "filled-new-array/range", F3rc),
    op!(0x26, "fill-array-data", F31t),
    op!(0x27, "throw", F11x),
    op!(0x28, "goto", F10t),
    op!(0x29, "goto/16", F20t),
    op!(0x2A, "goto/32", F30t),
    op!(0x2B, "packed-switch", F31t),
    op!(0x2C, "sparse-switch", F31t),
    op!(0x2D, "cmpl-float", F23x),
    op!(0x2E, "cmpg-float", F23x),
    op!(0x2F, "cmpl-double", F23x),
    op!(0x30, "cmpg-double", F23x),
    op!(0x31, "cmp-long", F23x),
    op!(0x32, "if-eq", F22t),
    op!(0x33, "if-ne", F22t),
    op!(0x34, "if-lt", F22t),
    op!(0x35, "if-ge", F22t),
    op!(0x36, "if-gt", F22t),
    op!(0x37, "if-le", F22t),
    op!(0x38, "if-eqz", F21t),
    op!(0x39, "if-nez", F21t),
    op!(0x3A, "if-ltz", F21t),
    op!(0x3B, "if-gez", F21t),
    op!(0x3C, "if-gtz", F21t),
    op!(0x3D, "if-lez", F21t),
    op!(0x44, "aget", F23x),
    op!(0x45, "aget-wide", F23x),
    op!(0x46, "aget-object", F23x),
    op!(0x47, "aget-boolean", F23x),
    op!(0x48, "aget-byte", F23x),
    op!(0x49, "aget-char", F23x),
    op!(0x4A, "aget-short", F23x),
    op!(0x4B, "aput", F23x),
    op!(0x4C, "aput-wide", F23x),
    op!(0x4D, "aput-object", F23x),
    op!(0x4E, "aput-boolean", F23x),
    op!(0x4F, "aput-byte", F23x),
    op!(0x50, "aput-char", F23x),
    op!(0x51, "aput-short", F23x),
    op!(0x52, "iget", F22c),
    op!(0x53, "iget-wide", F22c),
    op!(0x54, "iget-object", F22c),
    op!(0x55, "iget-boolean", F22c),
    op!(0x56, "iget-byte", F22c),
    op!(0x57, "iget-char", F22c),
    op!(0x58, "iget-short", F22c),
    op!(0x59, "iput", F22c),
    op!(0x5A, "iput-wide", F22c),
    op!(0x5B, "iput-object", F22c),
    op!(0x5C, "iput-boolean", F22c),
    op!(0x5D, "iput-byte", F22c),
    op!(0x5E, "iput-char", F22c),
    op!(0x5F, "iput-short", F22c),
    op!(0x60, "sget", F21c),
    op!(0x61, "sget-wide", F21c),
    op!(0x62, "sget-object", F21c),
    op!(0x63, "sget-boolean", F21c),
    op!(0x64, "sget-byte", F21c),
    op!(0x65, "sget-char", F21c),
    op!(0x66, "sget-short", F21c),
    op!(0x67, "sput", F21c),
    op!(0x68, "sput-wide", F21c),
    op!(0x69, "sput-object", F21c),
    op!(0x6A, "sput-boolean", F21c),
    op!(0x6B, "sput-byte", F21c),
    op!(0x6C, "sput-char", F21c),
    op!(0x6D, "sput-short", F21c),
    op!(0x6E, "invoke-virtual", F35c),
    op!(0x6F, "invoke-super", F35c),
    op!(0x70, "invoke-direct", F35c),
    op!(0x71, "invoke-static", F35c),
    op!(0x72, "invoke-interface", F35c),
    op!(0x74, "invoke-virtual/range", F3rc),
    op!(0x75, "invoke-super/range", F3rc),
    op!(0x76, "invoke-direct/range", F3rc),
    op!(0x77, "invoke-static/range", F3rc),
    op!(0x78, "invoke-interface/range", F3rc),
    op!(0x7B, "neg-int", F12x),
    op!(0x7C, "not-int", F12x),
    op!(0x7D, "neg-long", F12x),
    op!(0x7E, "not-long", F12x),
    op!(0x7F, "neg-float", F12x),
    op!(0x80, "neg-double", F12x),
    op!(0x81, "int-to-long", F12x),
    op!(0x82, "int-to-float", F12x),
    op!(0x83, "int-to-double", F12x),
    op!(0x84, "long-to-int", F12x),
    op!(0x85, "long-to-float", F12x),
    op!(0x86, "long-to-double", F12x),
    op!(0x87, "float-to-int", F12x),
    op!(0x88, "float-to-long", F12x),
    op!(0x89, "float-to-double", F12x),
    op!(0x8A, "double-to-int", F12x),
    op!(0x8B, "double-to-long", F12x),
    op!(0x8C, "double-to-float", F12x),
    op!(0x8D, "int-to-byte", F12x),
    op!(0x8E, "int-to-char", F12x),
    op!(0x8F, "int-to-short", F12x),
    op!(0x90, "add-int", F23x),
    op!(0x91, "sub-int", F23x),
    op!(0x92, "mul-int", F23x),
    op!(0x93, "div-int", F23x),
    op!(0x94, "rem-int", F23x),
    op!(0x95, "and-int", F23x),
    op!(0x96, "or-int", F23x),
    op!(0x97, "xor-int", F23x),
    op!(0x98, "shl-int", F23x),
    op!(0x99, "shr-int", F23x),
    op!(0x9A, "ushr-int", F23x),
    op!(0x9B, "add-long", F23x),
    op!(0x9C, "sub-long", F23x),
    op!(0x9D, "mul-long", F23x),
    op!(0x9E, "div-long", F23x),
    op!(0x9F, "rem-long", F23x),
    op!(0xA0, "and-long", F23x),
    op!(0xA1, "or-long", F23x),
    op!(0xA2, "xor-long", F23x),
    op!(0xA3, "shl-long", F23x),
    op!(0xA4, "shr-long", F23x),
    op!(0xA5, "ushr-long", F23x),
    op!(0xA6, "add-float", F23x),
    op!(0xA7, "sub-float", F23x),
    op!(0xA8, "mul-float", F23x),
    op!(0xA9, "div-float", F23x),
    op!(0xAA, "rem-float", F23x),
    op!(0xAB, "add-double", F23x),
    op!(0xAC, "sub-double", F23x),
    op!(0xAD, "mul-double", F23x),
    op!(0xAE, "div-double", F23x),
    op!(0xAF, "rem-double", F23x),
    op!(0xB0, "add-int/2addr", F12x),
    op!(0xB1, "sub-int/2addr", F12x),
    op!(0xB2, "mul-int/2addr", F12x),
    op!(0xB3, "div-int/2addr", F12x),
    op!(0xB4, "rem-int/2addr", F12x),
    op!(0xB5, "and-int/2addr", F12x),
    op!(0xB6, "or-int/2addr", F12x),
    op!(0xB7, "xor-int/2addr", F12x),
    op!(0xB8, "shl-int/2addr", F12x),
    op!(0xB9, "shr-int/2addr", F12x),
    op!(0xBA, "ushr-int/2addr", F12x),
    op!(0xBB, "add-long/2addr", F12x),
    op!(0xBC, "sub-long/2addr", F12x),
    op!(0xBD, "mul-long/2addr", F12x),
    op!(0xBE, "div-long/2addr", F12x),
    op!(0xBF, "rem-long/2addr", F12x),
    op!(0xC0, "and-long/2addr", F12x),
    op!(0xC1, "or-long/2addr", F12x),
    op!(0xC2, "xor-long/2addr", F12x),
    op!(0xC3, "shl-long/2addr", F12x),
    op!(0xC4, "shr-long/2addr", F12x),
    op!(0xC5, "ushr-long/2addr", F12x),
    op!(0xC6, "add-float/2addr", F12x),
    op!(0xC7, "sub-float/2addr", F12x),
    op!(0xC8, "mul-float/2addr", F12x),
    op!(0xC9, "div-float/2addr", F12x),
    op!(0xCA, "rem-float/2addr", F12x),
    op!(0xCB, "add-double/2addr", F12x),
    op!(0xCC, "sub-double/2addr", F12x),
    op!(0xCD, "mul-double/2addr", F12x),
    op!(0xCE, "div-double/2addr", F12x),
    op!(0xCF, "rem-double/2addr", F12x),
    op!(0xD0, "add-int/lit16", F22s),
    op!(0xD1, "rsub-int", F22s),
    op!(0xD2, "mul-int/lit16", F22s),
    op!(0xD3, "div-int/lit16", F22s),
    op!(0xD4, "rem-int/lit16", F22s),
    op!(0xD5, "and-int/lit16", F22s),
    op!(0xD6, "or-int/lit16", F22s),
    op!(0xD7, "xor-int/lit16", F22s),
    op!(0xD8, "add-int/lit8", F22b),
    op!(0xD9, "rsub-int/lit8", F22b),
    op!(0xDA, "mul-int/lit8", F22b),
    op!(0xDB, "div-int/lit8", F22b),
    op!(0xDC, "rem-int/lit8", F22b),
    op!(0xDD, "and-int/lit8", F22b),
    op!(0xDE, "or-int/lit8", F22b),
    op!(0xDF, "xor-int/lit8", F22b),
    op!(0xE0, "shl-int/lit8", F22b),
    op!(0xE1, "shr-int/lit8", F22b),
    op!(0xE2, "ushr-int/lit8", F22b),
];

/// Look up an opcode descriptor by opcode byte.
#[must_use]
pub fn lookup_opcode(opcode: u8) -> Option<&'static OpcodeDesc> {
    OPCODE_TABLE.iter().find(|d| d.opcode == opcode)
}

// ─────────────────────────────────────────────────────────────────────────────
// Disassembled instruction
// ─────────────────────────────────────────────────────────────────────────────

/// A single disassembled Dalvik instruction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DisasmInstr {
    /// Byte offset within the method's code buffer.
    pub offset: usize,
    /// Opcode byte.
    pub opcode: u8,
    /// Human-readable mnemonic.
    pub mnemonic: String,
    /// Decoded operand strings.
    pub operands: Vec<String>,
    /// Raw code units.
    pub raw_words: Vec<u16>,
    /// Instruction format.
    pub format: Format,
}

impl DisasmInstr {
    /// Render the instruction as a Smali-style text line.
    #[must_use]
    pub fn to_smali(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{} {}", self.mnemonic, self.operands.join(", "))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Disassembler
// ─────────────────────────────────────────────────────────────────────────────

/// Disassemble a method code buffer (`code` must be aligned 16-bit words
/// stored in little-endian order).
///
/// # Errors
///
/// Returns [`SmaliError`] if `code` is not 16-bit word aligned or if an
/// instruction is truncated.
pub fn disassemble(code: &[u8]) -> Result<Vec<DisasmInstr>, SmaliError> {
    if !code.len().is_multiple_of(2) {
        return Err(SmaliError::ParseError(
            "code buffer length must be even (16-bit word aligned)".to_owned(),
        ));
    }
    let words: Vec<u16> = code
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    disassemble_words(&words)
}

/// Disassemble from a pre-split word slice.
///
/// # Errors
///
/// Returns [`SmaliError`] if an instruction extends past the end of `words`.
pub fn disassemble_words(words: &[u16]) -> Result<Vec<DisasmInstr>, SmaliError> {
    let mut instrs = Vec::new();
    let mut i = 0usize;

    while i < words.len() {
        let w0 = words[i];
        let opcode = (w0 & 0xFF) as u8;
        let byte_offset = i * 2;

        let Some(desc) = lookup_opcode(opcode) else {
            // Unknown opcode — emit as raw word and skip 1 unit.
            instrs.push(DisasmInstr {
                offset: byte_offset,
                opcode,
                mnemonic: format!("unknown-{opcode:#04x}"),
                operands: vec![],
                raw_words: vec![w0],
                format: Format::F10x,
            });
            i += 1;
            continue;
        };

        let units = desc.format.code_units();
        if i + units > words.len() {
            return Err(SmaliError::ParseError(format!(
                "truncated instruction at offset {byte_offset:#x}"
            )));
        }
        let raw_words: Vec<u16> = words[i..i + units].to_vec();
        let operands = decode_operands(desc, &raw_words);

        instrs.push(DisasmInstr {
            offset: byte_offset,
            opcode,
            mnemonic: desc.mnemonic.to_owned(),
            operands,
            raw_words,
            format: desc.format,
        });

        i += units;
    }

    Ok(instrs)
}

// ─────────────────────────────────────────────────────────────────────────────
// Operand decoding
// ─────────────────────────────────────────────────────────────────────────────

fn decode_operands(desc: &OpcodeDesc, code_units: &[u16]) -> Vec<String> {
    let word0 = *code_units.first().unwrap_or(&0);
    let word1 = *code_units.get(1).unwrap_or(&0);
    let word2 = *code_units.get(2).unwrap_or(&0);

    let byte_a = u8::try_from((word0 >> 8) & 0xFF).unwrap_or(0); // 8-bit A field
    let nibble_b = u8::try_from((word0 >> 12) & 0xF).unwrap_or(0); // 4-bit B field (high nibble)
    let nibble_a = u8::try_from((word0 >> 8) & 0xF).unwrap_or(0); // 4-bit A field (low nibble of high byte)

    match desc.format {
        Format::F10x => vec![],

        Format::F12x => vec![reg(nibble_a), reg(nibble_b)],

        Format::F11n => vec![
            reg(nibble_a),
            // Sign-extend the 4-bit literal (nibble_b, 0..=15) to i8 and then
            // to i64.  The value occupies the high nibble of the high byte, so
            // we shift it into the sign bit of an i8 and then arithmetic-right-
            // shift back to obtain the proper sign extension.
            format!("{:#x}", i64::from((nibble_b.cast_signed() << 4) >> 4)),
        ],

        Format::F11x => vec![reg(byte_a)],

        Format::F10t => {
            let off = i32::from(byte_a.cast_signed());
            vec![format!("{off:+}")]
        }

        Format::F20t => {
            let off = i32::from(word1.cast_signed());
            vec![format!("{off:+}")]
        }

        Format::F22x => vec![reg(byte_a), format!("v{word1}")],

        Format::F21t => {
            let off = i32::from(word1.cast_signed());
            vec![reg(byte_a), format!("{off:+}")]
        }

        Format::F21s => {
            let lit = i64::from(word1.cast_signed());
            vec![reg(byte_a), format!("{lit:#x}")]
        }

        Format::F21h => {
            let lit = i64::from(word1) << 16;
            vec![reg(byte_a), format!("{lit:#x}")]
        }

        Format::F21c => vec![reg(byte_a), format!("@{word1:#x}")],

        Format::F23x => {
            let reg_c = u8::try_from(word1 & 0xff).unwrap_or(0);
            let reg_d = u8::try_from((word1 >> 8) & 0xff).unwrap_or(0);
            vec![reg(byte_a), reg(reg_c), reg(reg_d)]
        }

        Format::F22b => {
            let reg_c = u8::try_from(word1 & 0xff).unwrap_or(0);
            let lit_byte = u8::try_from((word1 >> 8) & 0xff).unwrap_or(0);
            let lit = i64::from(lit_byte.cast_signed());
            vec![reg(byte_a), reg(reg_c), format!("{lit:#x}")]
        }

        Format::F22t => {
            let off = i32::from(word1.cast_signed());
            vec![reg(nibble_a), reg(nibble_b), format!("{off:+}")]
        }

        Format::F22s => {
            let lit = i64::from(word1.cast_signed());
            vec![reg(nibble_a), reg(nibble_b), format!("{lit:#x}")]
        }

        Format::F22c => {
            vec![reg(nibble_a), reg(nibble_b), format!("@{word1:#x}")]
        }

        Format::F32x => vec![format!("v{word1}"), format!("v{word2}")],

        Format::F30t => {
            let off = (i32::from(word2.cast_signed()) << 16) | i32::from(word1);
            vec![format!("{off:+}")]
        }

        Format::F31t => {
            let off = (i32::from(word2.cast_signed()) << 16) | i32::from(word1);
            vec![reg(byte_a), format!("{off:+}")]
        }

        Format::F31i => {
            let val = (u32::from(word2) << 16) | u32::from(word1);
            vec![reg(byte_a), format!("{val:#x}")]
        }

        Format::F31c => {
            let idx = (u32::from(word2) << 16) | u32::from(word1);
            vec![reg(byte_a), format!("@{idx:#x}")]
        }

        Format::F35c => decode_f35c(word0, word1, word2, nibble_a),

        Format::F3rc => decode_f3rc(byte_a, word1, word2),

        Format::F51l => decode_f51l(byte_a, word1, word2, code_units),
    }
}

fn decode_f35c(word0: u16, word1: u16, word2: u16, nibble_a: u8) -> Vec<String> {
    let count = u8::try_from((word0 >> 12) & 0xF).unwrap_or(0);
    let method_idx = word1;
    let reg_d = u8::try_from(word2 & 0xF).unwrap_or(0);
    let reg_e = u8::try_from((word2 >> 4) & 0xF).unwrap_or(0);
    let reg_f = u8::try_from((word2 >> 8) & 0xF).unwrap_or(0);
    let reg_g = u8::try_from((word2 >> 12) & 0xF).unwrap_or(0);
    // C is bits 8..11 of word0
    let reg_c = nibble_a;
    let regs: Vec<String> = (0..count as usize)
        .map(|i| reg([reg_c, reg_d, reg_e, reg_f, reg_g, nibble_a][i.min(5)]))
        .collect();
    let mut ops = regs;
    ops.push(format!("@{method_idx:#x}"));
    ops
}

fn decode_f3rc(byte_a: u8, word1: u16, word2: u16) -> Vec<String> {
    let count = byte_a;
    let idx = word1;
    let first = word2;
    let mut ops = Vec::new();
    for i in 0..u16::from(count) {
        ops.push(format!("v{}", first.wrapping_add(i)));
    }
    ops.push(format!("@{idx:#x}"));
    ops
}

fn decode_f51l(byte_a: u8, word1: u16, word2: u16, code_units: &[u16]) -> Vec<String> {
    let val_lo = (u64::from(word2) << 16) | u64::from(word1);
    let val_hi = (u64::from(*code_units.get(4).unwrap_or(&0)) << 16)
        | u64::from(*code_units.get(3).unwrap_or(&0));
    let val = (val_hi << 32) | val_lo;
    vec![reg(byte_a), format!("{val:#018x}")]
}

fn reg(n: u8) -> String {
    format!("v{n}")
}

// ─────────────────────────────────────────────────────────────────────────────
// Statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics about a disassembled method.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DisasmStats {
    pub total_instructions: usize,
    pub invoke_count: usize,
    pub branch_count: usize,
    pub const_count: usize,
    pub return_count: usize,
}

impl DisasmStats {
    /// Compute statistics from a list of disassembled instructions.
    #[must_use]
    pub fn from_instrs(instrs: &[DisasmInstr]) -> Self {
        let mut invoke_count = 0usize;
        let mut branch_count = 0usize;
        let mut const_count = 0usize;
        let mut return_count = 0usize;

        for instr in instrs {
            let m = &instr.mnemonic;
            if m.starts_with("invoke") {
                invoke_count += 1;
            }
            if m.starts_with("if-") || m.starts_with("goto") {
                branch_count += 1;
            }
            if m.starts_with("const") {
                const_count += 1;
            }
            if m.starts_with("return") {
                return_count += 1;
            }
        }

        Self {
            total_instructions: instrs.len(),
            invoke_count,
            branch_count,
            const_count,
            return_count,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disasm_return_void() {
        // return-void = 0x0E 0x00
        let code = vec![0x0E, 0x00];
        let instrs = disassemble(&code).expect("disasm");
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].mnemonic, "return-void");
        assert!(instrs[0].operands.is_empty());
    }

    #[test]
    fn test_disasm_nop() {
        let code = vec![0x00, 0x00];
        let instrs = disassemble(&code).expect("disasm");
        assert_eq!(instrs[0].mnemonic, "nop");
    }

    #[test]
    fn test_disasm_const4() {
        // const/4 v0, #1  →  12 10  (opcode=0x12, B=1, A=0)
        let code = vec![0x12, 0x10];
        let instrs = disassemble(&code).expect("disasm");
        assert_eq!(instrs[0].mnemonic, "const/4");
        assert!(!instrs[0].operands.is_empty());
    }

    #[test]
    fn test_disasm_multiple() {
        // nop + return-void
        let code = vec![0x00, 0x00, 0x0E, 0x00];
        let instrs = disassemble(&code).expect("disasm");
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[1].offset, 2);
    }

    #[test]
    fn test_disasm_const_string() {
        // const-string v0, @0  →  1A 00 00 00
        let code = vec![0x1A, 0x00, 0x00, 0x00];
        let instrs = disassemble(&code).expect("disasm");
        assert_eq!(instrs[0].mnemonic, "const-string");
    }

    #[test]
    fn test_disasm_invoke_virtual() {
        // invoke-virtual {v0}, @1  (format 35c)
        // w0 = 6E 10, w1 = 01 00, w2 = 00 00
        let code = vec![0x6E, 0x10, 0x01, 0x00, 0x00, 0x00];
        let instrs = disassemble(&code).expect("disasm");
        assert_eq!(instrs[0].mnemonic, "invoke-virtual");
    }

    #[test]
    fn test_disasm_odd_length_error() {
        let code = vec![0x0E];
        let result = disassemble(&code);
        assert!(result.is_err());
    }

    #[test]
    fn test_disasm_unknown_opcode() {
        // 0xEE is not a standard opcode.
        let code = vec![0xEE, 0x00];
        let instrs = disassemble(&code).expect("disasm");
        assert!(instrs[0].mnemonic.starts_with("unknown"));
    }

    #[test]
    fn test_disasm_stats() {
        let code = vec![
            0x1A, 0x00, 0x00, 0x00, // const-string
            0x6E, 0x10, 0x01, 0x00, 0x00, 0x00, // invoke-virtual
            0x0E, 0x00, // return-void
        ];
        let instrs = disassemble(&code).expect("disasm");
        let stats = DisasmStats::from_instrs(&instrs);
        assert_eq!(stats.return_count, 1);
        assert_eq!(stats.invoke_count, 1);
        assert_eq!(stats.const_count, 1);
        assert_eq!(stats.total_instructions, 3);
    }

    #[test]
    fn test_lookup_opcode() {
        assert!(lookup_opcode(0x0E).is_some());
        assert_eq!(lookup_opcode(0x0E).unwrap().mnemonic, "return-void");
        assert!(lookup_opcode(0xFF).is_none());
    }

    #[test]
    fn test_to_smali_rendering() {
        let code = vec![0x0E, 0x00];
        let instrs = disassemble(&code).expect("disasm");
        assert_eq!(instrs[0].to_smali(), "return-void");
    }

    #[test]
    fn test_format_code_units() {
        assert_eq!(Format::F10x.code_units(), 1);
        assert_eq!(Format::F21c.code_units(), 2);
        assert_eq!(Format::F35c.code_units(), 3);
        assert_eq!(Format::F51l.code_units(), 5);
    }
}
