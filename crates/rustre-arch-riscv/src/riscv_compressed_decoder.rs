//! RISC-V Compressed (C) extension decoder — RV32C / RV64C.
//!
//! The C extension encodes common instruction patterns in 16-bit words.
//! Each compressed instruction maps 1:1 to a 32-bit base instruction;
//! `expand_compressed` returns that expansion together with the decoded
//! `CompressedInsn` descriptor.

use std::fmt;

// ── Compressed register encoding ──────────────────────────────────────────────

/// Map a 3-bit "compressed" register specifier to the real GPR number.
/// CL/CS/CA/CB formats encode registers s0–a5 (x8–x15) in 3 bits.
#[inline]
const fn creg(r3: u32) -> u32 {
    r3 + 8
}

// ── Immediate helpers ──────────────────────────────────────────────────────────

/// Sign-extend `bits`-wide value in `val` to i32.
const fn sign_extend(val: u32, bits: u32) -> i32 {
    let shift = 32 - bits;
    ((val << shift).cast_signed()) >> shift
}

/// Decode the CI-format immediate for C.ADDI / C.LI / C.ANDI etc.
/// imm[5] = bit 12, imm[4:0] = bits 6:2.
fn ci_imm(word: u16) -> i32 {
    let w = u32::from(word);
    let imm = ((w >> 7) & 0x20) | ((w >> 2) & 0x1F);
    sign_extend(imm, 6)
}

/// CSS-format stack-relative store offset for C.SWSP / C.SDSP / C.SQSP.
/// C.SWSP: offset = {imm[5:2], imm[7:6]} * 4
fn css_sw_offset(word: u16) -> u32 {
    let w = u32::from(word);
    ((w >> 1) & 0xC0) | ((w >> 7) & 0x3C)
}

/// CSS-format SD offset (doubles).
fn css_sd_offset(word: u16) -> u32 {
    let w = u32::from(word);
    ((w >> 1) & 0x1C0) | ((w >> 7) & 0x38)
}

/// CL/CS load/store word offset: {imm[5:3], imm[2], imm[6]} * 4
fn cl_sw_offset(word: u16) -> u32 {
    let w = u32::from(word);
    ((w << 1) & 0x40) | ((w >> 7) & 0x38) | ((w >> 4) & 0x04)
}

/// CL/CS load/store double offset: {imm[5:3], imm[7:6]} * 8
fn cl_sd_offset(word: u16) -> u32 {
    let w = u32::from(word);
    ((w >> 7) & 0x38) | ((w << 1) & 0xC0)
}

/// CISP immediate for C.ADDI16SP: {imm[9], imm[4], imm[6], imm[8:7], imm[5]} * 16
fn addi16sp_imm(word: u16) -> i32 {
    let w = u32::from(word);
    let nzimm = ((w >> 3) & 0x200)
        | ((w >> 2) & 0x010)
        | ((w << 1) & 0x040)
        | ((w << 4) & 0x180)
        | ((w << 3) & 0x020);
    sign_extend(nzimm, 10)
}

/// CI stack-pointer-relative load for C.LWSP: {imm[5], imm[4:2], imm[7:6]}
fn lwsp_offset(word: u16) -> u32 {
    let w = u32::from(word);
    ((w >> 7) & 0x20) | ((w >> 2) & 0x1C) | ((w << 4) & 0xC0)
}

/// CI SP-relative double load for C.LDSP: {imm[5], imm[4:3], imm[8:6]}
fn ldsp_offset(word: u16) -> u32 {
    let w = u32::from(word);
    ((w >> 7) & 0x20) | ((w >> 2) & 0x18) | ((w << 4) & 0x1C0)
}

/// CB-format branch offset: {imm[8], imm[4:3], imm[7:6], imm[2:1], imm[5]}
fn cb_offset(word: u16) -> i32 {
    let w = u32::from(word);
    let off = ((w >> 4) & 0x100)
        | ((w >> 7) & 0x18)
        | ((w << 1) & 0xC0)
        | ((w >> 2) & 0x06)
        | ((w << 3) & 0x20);
    sign_extend(off, 9)
}

/// CJ-format jump offset (11 bits): {imm[11], imm[4], imm[9:8], imm[10], imm[6],
///                                    imm[7], imm[3:1], imm[5]}
fn cj_offset(word: u16) -> i32 {
    let w = u32::from(word);
    let off = ((w >> 1) & 0x800)
        | ((w << 2) & 0x400)
        | ((w >> 1) & 0x300)
        | ((w << 1) & 0x80)
        | ((w >> 1) & 0x40)
        | ((w << 3) & 0x20)
        | ((w >> 7) & 0x10)
        | ((w >> 2) & 0x0E);
    sign_extend(off, 12)
}

/// C.LUI: {imm[17], imm[16:12]}
fn clui_imm(word: u16) -> i32 {
    let w = u32::from(word);
    let nzimm = ((w >> 7) & 0x20) | ((w >> 2) & 0x1F);
    sign_extend(nzimm, 6) << 12
}

// ── Instruction descriptor ────────────────────────────────────────────────────

/// The quadrant (bits [1:0]) of a compressed instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CQuadrant {
    Q0 = 0,
    Q1 = 1,
    Q2 = 2,
}

impl fmt::Display for CQuadrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Q{}", *self as u8)
    }
}

/// Format of a compressed instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CFormat {
    CR,
    CI,
    CSS,
    CIW,
    CL,
    CS,
    CA,
    CB,
    CJ,
}

/// A decoded RV32C/RV64C compressed instruction.
#[derive(Debug, Clone)]
pub struct CompressedInsn {
    /// The raw 16-bit word.
    pub word: u16,
    /// Quadrant of the instruction.
    pub quadrant: CQuadrant,
    /// Format class.
    pub format: CFormat,
    /// Mnemonic of the *compressed* instruction (e.g., `"c.addi"`).
    pub mnemonic: String,
    /// Human-readable operand string.
    pub operands: String,
    /// The equivalent 32-bit base instruction mnemonic.
    pub base_mnemonic: String,
    /// The equivalent 32-bit base instruction operands.
    pub base_operands: String,
    /// True if this instruction is a branch or jump.
    pub is_branch: bool,
    /// True if this is a call (e.g., `c.jal`, `c.jalr`).
    pub is_call: bool,
    /// True if this is a return (`c.jr x1` or `c.jalr x1 with rs2=0`).
    pub is_return: bool,
}

impl fmt::Display for CompressedInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.mnemonic, self.operands)
    }
}

// ── Decoder ───────────────────────────────────────────────────────────────────

/// Error type returned when a 16-bit word cannot be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedDecodeError {
    pub word: u16,
    pub message: String,
}

impl fmt::Display for CompressedDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot decode compressed word 0x{:04X}: {}",
            self.word, self.message
        )
    }
}

/// Stateless decoder for RV32C/RV64C compressed instructions.
#[derive(Debug, Clone, Default)]
pub struct RiscvCompressedDecoder {
    /// When `true`, enable RV64C-specific expansions (LD/SD instead of LW/SW
    /// for the C.LD / C.SD / C.LDSP / C.SDSP variants).
    pub rv64: bool,
}

impl RiscvCompressedDecoder {
    /// Create a new decoder for the given XLEN.
    #[must_use]
    pub const fn new(rv64: bool) -> Self {
        Self { rv64 }
    }

    /// Decode a single 16-bit compressed instruction word.
    ///
    /// # Errors
    ///
    /// Returns `CompressedDecodeError` if the encoding is illegal or reserved.
    pub fn decode(&self, word: u16) -> Result<CompressedInsn, CompressedDecodeError> {
        let quadrant = word & 0x3;
        match quadrant {
            0 => self.decode_q0(word),
            1 => self.decode_q1(word),
            2 => self.decode_q2(word),
            _ => Err(CompressedDecodeError {
                word,
                message: "32-bit instruction passed to compressed decoder".to_string(),
            }),
        }
    }

    fn err(&self, word: u16, msg: &str) -> CompressedDecodeError {
        // Record which expansion mode was active: the same halfword is a valid
        // encoding in one mode and reserved in the other, so the mode is part
        // of the diagnosis.
        let mode = if self.rv64 { "rv64c" } else { "rv32c" };
        CompressedDecodeError {
            word,
            message: format!("{msg} [{mode}]"),
        }
    }

    // ── Quadrant 0 ────────────────────────────────────────────────────────────

    fn decode_q0(&self, word: u16) -> Result<CompressedInsn, CompressedDecodeError> {
        let funct3 = (word >> 13) & 0x7;
        let rd_prime = creg(u32::from((word >> 2) & 0x7));
        let rs1_prime = creg(u32::from((word >> 7) & 0x7));

        match funct3 {
            // C.ADDI4SPN — expand to ADDI rd', sp, nzuimm
            0b000 => {
                let nzuimm = u32::from(
                    ((word >> 1) & 0x3C0)
                        | ((word >> 7) & 0x30)
                        | ((word >> 2) & 0x08)
                        | ((word >> 4) & 0x04),
                );
                if nzuimm == 0 {
                    return Err(self.err(word, "C.ADDI4SPN with nzuimm=0 is reserved"));
                }
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q0,
                    format: CFormat::CIW,
                    mnemonic: "c.addi4spn".to_string(),
                    operands: format!("x{rd_prime}, {nzuimm}"),
                    base_mnemonic: "addi".to_string(),
                    base_operands: format!("x{rd_prime}, x2, {nzuimm}"),
                    is_branch: false,
                    is_call: false,
                    is_return: false,
                })
            }
            // C.FLD (RV32/64) / C.LQ (RV128) — use as C.FLD
            0b001 => {
                let offset = cl_sd_offset(word);
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q0,
                    format: CFormat::CL,
                    mnemonic: "c.fld".to_string(),
                    operands: format!("f{rd_prime}, {offset}(x{rs1_prime})"),
                    base_mnemonic: "fld".to_string(),
                    base_operands: format!("f{rd_prime}, {offset}(x{rs1_prime})"),
                    is_branch: false,
                    is_call: false,
                    is_return: false,
                })
            }
            // C.LW
            0b010 => {
                let offset = cl_sw_offset(word);
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q0,
                    format: CFormat::CL,
                    mnemonic: "c.lw".to_string(),
                    operands: format!("x{rd_prime}, {offset}(x{rs1_prime})"),
                    base_mnemonic: "lw".to_string(),
                    base_operands: format!("x{rd_prime}, {offset}(x{rs1_prime})"),
                    is_branch: false,
                    is_call: false,
                    is_return: false,
                })
            }
            // C.FLW (RV32) / C.LD (RV64)
            0b011 => {
                if self.rv64 {
                    let offset = cl_sd_offset(word);
                    Ok(CompressedInsn {
                        word,
                        quadrant: CQuadrant::Q0,
                        format: CFormat::CL,
                        mnemonic: "c.ld".to_string(),
                        operands: format!("x{rd_prime}, {offset}(x{rs1_prime})"),
                        base_mnemonic: "ld".to_string(),
                        base_operands: format!("x{rd_prime}, {offset}(x{rs1_prime})"),
                        is_branch: false,
                        is_call: false,
                        is_return: false,
                    })
                } else {
                    let offset = cl_sw_offset(word);
                    Ok(CompressedInsn {
                        word,
                        quadrant: CQuadrant::Q0,
                        format: CFormat::CL,
                        mnemonic: "c.flw".to_string(),
                        operands: format!("f{rd_prime}, {offset}(x{rs1_prime})"),
                        base_mnemonic: "flw".to_string(),
                        base_operands: format!("f{rd_prime}, {offset}(x{rs1_prime})"),
                        is_branch: false,
                        is_call: false,
                        is_return: false,
                    })
                }
            }
            // Reserved (0b100)
            0b100 => Err(self.err(word, "Q0 funct3=0b100 reserved")),
            // C.FSD
            0b101 => {
                let rs2_prime = creg(u32::from((word >> 2) & 0x7));
                let offset = cl_sd_offset(word);
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q0,
                    format: CFormat::CS,
                    mnemonic: "c.fsd".to_string(),
                    operands: format!("f{rs2_prime}, {offset}(x{rs1_prime})"),
                    base_mnemonic: "fsd".to_string(),
                    base_operands: format!("f{rs2_prime}, {offset}(x{rs1_prime})"),
                    is_branch: false,
                    is_call: false,
                    is_return: false,
                })
            }
            // C.SW
            0b110 => {
                let rs2_prime = creg(u32::from((word >> 2) & 0x7));
                let offset = cl_sw_offset(word);
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q0,
                    format: CFormat::CS,
                    mnemonic: "c.sw".to_string(),
                    operands: format!("x{rs2_prime}, {offset}(x{rs1_prime})"),
                    base_mnemonic: "sw".to_string(),
                    base_operands: format!("x{rs2_prime}, {offset}(x{rs1_prime})"),
                    is_branch: false,
                    is_call: false,
                    is_return: false,
                })
            }
            // C.FSW (RV32) / C.SD (RV64)
            0b111 => {
                let rs2_prime = creg(u32::from((word >> 2) & 0x7));
                if self.rv64 {
                    let offset = cl_sd_offset(word);
                    Ok(CompressedInsn {
                        word,
                        quadrant: CQuadrant::Q0,
                        format: CFormat::CS,
                        mnemonic: "c.sd".to_string(),
                        operands: format!("x{rs2_prime}, {offset}(x{rs1_prime})"),
                        base_mnemonic: "sd".to_string(),
                        base_operands: format!("x{rs2_prime}, {offset}(x{rs1_prime})"),
                        is_branch: false,
                        is_call: false,
                        is_return: false,
                    })
                } else {
                    let offset = cl_sw_offset(word);
                    Ok(CompressedInsn {
                        word,
                        quadrant: CQuadrant::Q0,
                        format: CFormat::CS,
                        mnemonic: "c.fsw".to_string(),
                        operands: format!("f{rs2_prime}, {offset}(x{rs1_prime})"),
                        base_mnemonic: "fsw".to_string(),
                        base_operands: format!("f{rs2_prime}, {offset}(x{rs1_prime})"),
                        is_branch: false,
                        is_call: false,
                        is_return: false,
                    })
                }
            }
            _ => Err(self.err(word, "unreachable Q0 funct3")),
        }
    }

    // ── Quadrant 1 ────────────────────────────────────────────────────────────

    fn decode_q1(&self, word: u16) -> Result<CompressedInsn, CompressedDecodeError> {
        let funct3 = (word >> 13) & 0x7;
        let rs1_rd = u32::from((word >> 7) & 0x1F);

        match funct3 {
            // C.NOP / C.ADDI
            0b000 => {
                let imm = ci_imm(word);
                if rs1_rd == 0 {
                    Ok(CompressedInsn {
                        word,
                        quadrant: CQuadrant::Q1,
                        format: CFormat::CI,
                        mnemonic: "c.nop".to_string(),
                        operands: String::new(),
                        base_mnemonic: "addi".to_string(),
                        base_operands: "x0, x0, 0".to_string(),
                        is_branch: false,
                        is_call: false,
                        is_return: false,
                    })
                } else {
                    Ok(CompressedInsn {
                        word,
                        quadrant: CQuadrant::Q1,
                        format: CFormat::CI,
                        mnemonic: "c.addi".to_string(),
                        operands: format!("x{rs1_rd}, {imm}"),
                        base_mnemonic: "addi".to_string(),
                        base_operands: format!("x{rs1_rd}, x{rs1_rd}, {imm}"),
                        is_branch: false,
                        is_call: false,
                        is_return: false,
                    })
                }
            }
            // C.JAL (RV32) / C.ADDIW (RV64)
            0b001 => {
                if self.rv64 {
                    let imm = ci_imm(word);
                    Ok(CompressedInsn {
                        word,
                        quadrant: CQuadrant::Q1,
                        format: CFormat::CI,
                        mnemonic: "c.addiw".to_string(),
                        operands: format!("x{rs1_rd}, {imm}"),
                        base_mnemonic: "addiw".to_string(),
                        base_operands: format!("x{rs1_rd}, x{rs1_rd}, {imm}"),
                        is_branch: false,
                        is_call: false,
                        is_return: false,
                    })
                } else {
                    let offset = cj_offset(word);
                    Ok(CompressedInsn {
                        word,
                        quadrant: CQuadrant::Q1,
                        format: CFormat::CJ,
                        mnemonic: "c.jal".to_string(),
                        operands: format!("{offset}"),
                        base_mnemonic: "jal".to_string(),
                        base_operands: format!("x1, {offset}"),
                        is_branch: true,
                        is_call: true,
                        is_return: false,
                    })
                }
            }
            // C.LI
            0b010 => {
                let imm = ci_imm(word);
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q1,
                    format: CFormat::CI,
                    mnemonic: "c.li".to_string(),
                    operands: format!("x{rs1_rd}, {imm}"),
                    base_mnemonic: "addi".to_string(),
                    base_operands: format!("x{rs1_rd}, x0, {imm}"),
                    is_branch: false,
                    is_call: false,
                    is_return: false,
                })
            }
            // C.ADDI16SP / C.LUI
            0b011 => {
                if rs1_rd == 2 {
                    let imm = addi16sp_imm(word);
                    Ok(CompressedInsn {
                        word,
                        quadrant: CQuadrant::Q1,
                        format: CFormat::CI,
                        mnemonic: "c.addi16sp".to_string(),
                        operands: format!("{imm}"),
                        base_mnemonic: "addi".to_string(),
                        base_operands: format!("x2, x2, {imm}"),
                        is_branch: false,
                        is_call: false,
                        is_return: false,
                    })
                } else {
                    let imm = clui_imm(word);
                    Ok(CompressedInsn {
                        word,
                        quadrant: CQuadrant::Q1,
                        format: CFormat::CI,
                        mnemonic: "c.lui".to_string(),
                        operands: format!("x{rs1_rd}, {}", imm >> 12),
                        base_mnemonic: "lui".to_string(),
                        base_operands: format!("x{rs1_rd}, {}", imm >> 12),
                        is_branch: false,
                        is_call: false,
                        is_return: false,
                    })
                }
            }
            // C.SRLI / C.SRAI / C.ANDI / C.SUB / C.XOR / C.OR / C.AND / C.SUBW / C.ADDW
            0b100 => self.decode_q1_arith(word),
            // C.J
            0b101 => {
                let offset = cj_offset(word);
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q1,
                    format: CFormat::CJ,
                    mnemonic: "c.j".to_string(),
                    operands: format!("{offset}"),
                    base_mnemonic: "jal".to_string(),
                    base_operands: format!("x0, {offset}"),
                    is_branch: true,
                    is_call: false,
                    is_return: false,
                })
            }
            // C.BEQZ
            0b110 => {
                let rs1_prime = creg(u32::from((word >> 7) & 0x7));
                let offset = cb_offset(word);
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q1,
                    format: CFormat::CB,
                    mnemonic: "c.beqz".to_string(),
                    operands: format!("x{rs1_prime}, {offset}"),
                    base_mnemonic: "beq".to_string(),
                    base_operands: format!("x{rs1_prime}, x0, {offset}"),
                    is_branch: true,
                    is_call: false,
                    is_return: false,
                })
            }
            // C.BNEZ
            0b111 => {
                let rs1_prime = creg(u32::from((word >> 7) & 0x7));
                let offset = cb_offset(word);
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q1,
                    format: CFormat::CB,
                    mnemonic: "c.bnez".to_string(),
                    operands: format!("x{rs1_prime}, {offset}"),
                    base_mnemonic: "bne".to_string(),
                    base_operands: format!("x{rs1_prime}, x0, {offset}"),
                    is_branch: true,
                    is_call: false,
                    is_return: false,
                })
            }
            _ => Err(self.err(word, "unreachable Q1 funct3")),
        }
    }

    fn decode_q1_arith(&self, word: u16) -> Result<CompressedInsn, CompressedDecodeError> {
        let funct2 = (word >> 10) & 0x3;
        let rs1_prime = creg(u32::from((word >> 7) & 0x7));
        let rs2_prime = creg(u32::from((word >> 2) & 0x7));

        match funct2 {
            // C.SRLI
            0b00 => {
                let shamt = u32::from(((word >> 7) & 0x20) | ((word >> 2) & 0x1F));
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q1,
                    format: CFormat::CB,
                    mnemonic: "c.srli".to_string(),
                    operands: format!("x{rs1_prime}, {shamt}"),
                    base_mnemonic: "srli".to_string(),
                    base_operands: format!("x{rs1_prime}, x{rs1_prime}, {shamt}"),
                    is_branch: false,
                    is_call: false,
                    is_return: false,
                })
            }
            // C.SRAI
            0b01 => {
                let shamt = u32::from(((word >> 7) & 0x20) | ((word >> 2) & 0x1F));
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q1,
                    format: CFormat::CB,
                    mnemonic: "c.srai".to_string(),
                    operands: format!("x{rs1_prime}, {shamt}"),
                    base_mnemonic: "srai".to_string(),
                    base_operands: format!("x{rs1_prime}, x{rs1_prime}, {shamt}"),
                    is_branch: false,
                    is_call: false,
                    is_return: false,
                })
            }
            // C.ANDI
            0b10 => {
                let imm = ci_imm(word);
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q1,
                    format: CFormat::CB,
                    mnemonic: "c.andi".to_string(),
                    operands: format!("x{rs1_prime}, {imm}"),
                    base_mnemonic: "andi".to_string(),
                    base_operands: format!("x{rs1_prime}, x{rs1_prime}, {imm}"),
                    is_branch: false,
                    is_call: false,
                    is_return: false,
                })
            }
            // C.SUB / C.XOR / C.OR / C.AND / (RV64: C.SUBW / C.ADDW)
            0b11 => {
                let funct2b = (word >> 5) & 0x3;
                let bit12 = (word >> 12) & 0x1;
                if bit12 == 0 {
                    let (mn, base_mn) = match funct2b {
                        0b00 => ("c.sub", "sub"),
                        0b01 => ("c.xor", "xor"),
                        0b10 => ("c.or", "or"),
                        0b11 => ("c.and", "and"),
                        _ => unreachable!(),
                    };
                    Ok(CompressedInsn {
                        word,
                        quadrant: CQuadrant::Q1,
                        format: CFormat::CA,
                        mnemonic: mn.to_string(),
                        operands: format!("x{rs1_prime}, x{rs2_prime}"),
                        base_mnemonic: base_mn.to_string(),
                        base_operands: format!("x{rs1_prime}, x{rs1_prime}, x{rs2_prime}"),
                        is_branch: false,
                        is_call: false,
                        is_return: false,
                    })
                } else if self.rv64 {
                    let (mn, base_mn) = match funct2b {
                        0b00 => ("c.subw", "subw"),
                        0b01 => ("c.addw", "addw"),
                        _ => return Err(self.err(word, "reserved CA RV64 encoding")),
                    };
                    Ok(CompressedInsn {
                        word,
                        quadrant: CQuadrant::Q1,
                        format: CFormat::CA,
                        mnemonic: mn.to_string(),
                        operands: format!("x{rs1_prime}, x{rs2_prime}"),
                        base_mnemonic: base_mn.to_string(),
                        base_operands: format!("x{rs1_prime}, x{rs1_prime}, x{rs2_prime}"),
                        is_branch: false,
                        is_call: false,
                        is_return: false,
                    })
                } else {
                    Err(self.err(word, "reserved Q1 CA bit12=1 on RV32"))
                }
            }
            _ => Err(self.err(word, "unreachable Q1 arith")),
        }
    }

    // ── Quadrant 2 ────────────────────────────────────────────────────────────

    fn decode_q2(&self, word: u16) -> Result<CompressedInsn, CompressedDecodeError> {
        let funct3 = (word >> 13) & 0x7;
        let rs1_rd = u32::from((word >> 7) & 0x1F);
        let rs2 = u32::from((word >> 2) & 0x1F);

        match funct3 {
            // C.SLLI
            0b000 => {
                let shamt = u32::from(((word >> 7) & 0x20) | ((word >> 2) & 0x1F));
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q2,
                    format: CFormat::CI,
                    mnemonic: "c.slli".to_string(),
                    operands: format!("x{rs1_rd}, {shamt}"),
                    base_mnemonic: "slli".to_string(),
                    base_operands: format!("x{rs1_rd}, x{rs1_rd}, {shamt}"),
                    is_branch: false,
                    is_call: false,
                    is_return: false,
                })
            }
            // C.FLDSP
            0b001 => {
                let offset = ldsp_offset(word);
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q2,
                    format: CFormat::CI,
                    mnemonic: "c.fldsp".to_string(),
                    operands: format!("f{rs1_rd}, {offset}(x2)"),
                    base_mnemonic: "fld".to_string(),
                    base_operands: format!("f{rs1_rd}, {offset}(x2)"),
                    is_branch: false,
                    is_call: false,
                    is_return: false,
                })
            }
            // C.LWSP
            0b010 => {
                let offset = lwsp_offset(word);
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q2,
                    format: CFormat::CI,
                    mnemonic: "c.lwsp".to_string(),
                    operands: format!("x{rs1_rd}, {offset}(x2)"),
                    base_mnemonic: "lw".to_string(),
                    base_operands: format!("x{rs1_rd}, {offset}(x2)"),
                    is_branch: false,
                    is_call: false,
                    is_return: false,
                })
            }
            // C.FLWSP (RV32) / C.LDSP (RV64)
            0b011 => {
                if self.rv64 {
                    let offset = ldsp_offset(word);
                    Ok(CompressedInsn {
                        word,
                        quadrant: CQuadrant::Q2,
                        format: CFormat::CI,
                        mnemonic: "c.ldsp".to_string(),
                        operands: format!("x{rs1_rd}, {offset}(x2)"),
                        base_mnemonic: "ld".to_string(),
                        base_operands: format!("x{rs1_rd}, {offset}(x2)"),
                        is_branch: false,
                        is_call: false,
                        is_return: false,
                    })
                } else {
                    let offset = lwsp_offset(word);
                    Ok(CompressedInsn {
                        word,
                        quadrant: CQuadrant::Q2,
                        format: CFormat::CI,
                        mnemonic: "c.flwsp".to_string(),
                        operands: format!("f{rs1_rd}, {offset}(x2)"),
                        base_mnemonic: "flw".to_string(),
                        base_operands: format!("f{rs1_rd}, {offset}(x2)"),
                        is_branch: false,
                        is_call: false,
                        is_return: false,
                    })
                }
            }
            // C.JR / C.MV / C.EBREAK / C.JALR / C.ADD
            0b100 => self.decode_q2_cr(word, rs1_rd, rs2),
            // C.FSDSP
            0b101 => {
                let offset = css_sd_offset(word);
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q2,
                    format: CFormat::CSS,
                    mnemonic: "c.fsdsp".to_string(),
                    operands: format!("f{rs2}, {offset}(x2)"),
                    base_mnemonic: "fsd".to_string(),
                    base_operands: format!("f{rs2}, {offset}(x2)"),
                    is_branch: false,
                    is_call: false,
                    is_return: false,
                })
            }
            // C.SWSP
            0b110 => {
                let offset = css_sw_offset(word);
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q2,
                    format: CFormat::CSS,
                    mnemonic: "c.swsp".to_string(),
                    operands: format!("x{rs2}, {offset}(x2)"),
                    base_mnemonic: "sw".to_string(),
                    base_operands: format!("x{rs2}, {offset}(x2)"),
                    is_branch: false,
                    is_call: false,
                    is_return: false,
                })
            }
            // C.FSWSP (RV32) / C.SDSP (RV64)
            0b111 => {
                if self.rv64 {
                    let offset = css_sd_offset(word);
                    Ok(CompressedInsn {
                        word,
                        quadrant: CQuadrant::Q2,
                        format: CFormat::CSS,
                        mnemonic: "c.sdsp".to_string(),
                        operands: format!("x{rs2}, {offset}(x2)"),
                        base_mnemonic: "sd".to_string(),
                        base_operands: format!("x{rs2}, {offset}(x2)"),
                        is_branch: false,
                        is_call: false,
                        is_return: false,
                    })
                } else {
                    let offset = css_sw_offset(word);
                    Ok(CompressedInsn {
                        word,
                        quadrant: CQuadrant::Q2,
                        format: CFormat::CSS,
                        mnemonic: "c.fswsp".to_string(),
                        operands: format!("f{rs2}, {offset}(x2)"),
                        base_mnemonic: "fsw".to_string(),
                        base_operands: format!("f{rs2}, {offset}(x2)"),
                        is_branch: false,
                        is_call: false,
                        is_return: false,
                    })
                }
            }
            _ => Err(self.err(word, "unreachable Q2 funct3")),
        }
    }

    fn decode_q2_cr(
        &self,
        word: u16,
        rs1: u32,
        rs2: u32,
    ) -> Result<CompressedInsn, CompressedDecodeError> {
        let bit12 = (word >> 12) & 0x1;
        match (bit12, rs1, rs2) {
            (0, _, 0) if rs1 != 0 => {
                // C.JR
                let is_return = rs1 == 1;
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q2,
                    format: CFormat::CR,
                    mnemonic: "c.jr".to_string(),
                    operands: format!("x{rs1}"),
                    base_mnemonic: "jalr".to_string(),
                    base_operands: format!("x0, x{rs1}, 0"),
                    is_branch: true,
                    is_call: false,
                    is_return,
                })
            }
            (0, _, _) => {
                // C.MV
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q2,
                    format: CFormat::CR,
                    mnemonic: "c.mv".to_string(),
                    operands: format!("x{rs1}, x{rs2}"),
                    base_mnemonic: "add".to_string(),
                    base_operands: format!("x{rs1}, x0, x{rs2}"),
                    is_branch: false,
                    is_call: false,
                    is_return: false,
                })
            }
            (1, 0, 0) => {
                // C.EBREAK
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q2,
                    format: CFormat::CR,
                    mnemonic: "c.ebreak".to_string(),
                    operands: String::new(),
                    base_mnemonic: "ebreak".to_string(),
                    base_operands: String::new(),
                    is_branch: false,
                    is_call: false,
                    is_return: false,
                })
            }
            (1, _, 0) => {
                // C.JALR
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q2,
                    format: CFormat::CR,
                    mnemonic: "c.jalr".to_string(),
                    operands: format!("x{rs1}"),
                    base_mnemonic: "jalr".to_string(),
                    base_operands: format!("x1, x{rs1}, 0"),
                    is_branch: true,
                    is_call: true,
                    is_return: false,
                })
            }
            (1, _, _) => {
                // C.ADD
                Ok(CompressedInsn {
                    word,
                    quadrant: CQuadrant::Q2,
                    format: CFormat::CR,
                    mnemonic: "c.add".to_string(),
                    operands: format!("x{rs1}, x{rs2}"),
                    base_mnemonic: "add".to_string(),
                    base_operands: format!("x{rs1}, x{rs1}, x{rs2}"),
                    is_branch: false,
                    is_call: false,
                    is_return: false,
                })
            }
            _ => Err(self.err(word, "unreachable Q2 CR")),
        }
    }
}

// ── Public convenience function ───────────────────────────────────────────────

/// Decode a 16-bit compressed instruction and return its 32-bit expansion.
///
/// Returns `(base_mnemonic, base_operands)` which together form the equivalent
/// uncompressed instruction.
///
/// # Errors
///
/// Returns `CompressedDecodeError` if `word` is not a valid compressed encoding.
pub fn expand_compressed(
    word: u16,
    rv64: bool,
) -> Result<(String, String), CompressedDecodeError> {
    let dec = RiscvCompressedDecoder::new(rv64);
    let insn = dec.decode(word)?;
    Ok((insn.base_mnemonic, insn.base_operands))
}

/// Batch-decode a byte stream, auto-detecting 16- vs 32-bit instructions.
///
/// Returns a `Vec` of `(offset, result)` pairs.
#[must_use]
pub fn decode_stream(bytes: &[u8], rv64: bool) -> Vec<(usize, Result<CompressedInsn, CompressedDecodeError>)> {
    let dec = RiscvCompressedDecoder::new(rv64);
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 1 < bytes.len() {
        let lo = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
        if lo & 0x3 == 0x3 {
            // 32-bit instruction — skip
            pos += 4;
            continue;
        }
        let res = dec.decode(lo);
        out.push((pos, res));
        pos += 2;
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dec32() -> RiscvCompressedDecoder { RiscvCompressedDecoder::new(false) }
    fn dec64() -> RiscvCompressedDecoder { RiscvCompressedDecoder::new(true) }

    #[test]
    fn test_c_nop() {
        // C.NOP = 0x0001
        let insn = dec32().decode(0x0001).unwrap();
        assert_eq!(insn.mnemonic, "c.nop");
        assert_eq!(insn.base_mnemonic, "addi");
    }

    #[test]
    fn test_c_addi() {
        // C.ADDI a0,1  → word with rs1_rd=10, imm=1
        // funct3=000, bit12=0, bits[6:2]=00001, bits[11:7]=01010 → 0x0505
        let insn = dec32().decode(0x0505).unwrap();
        assert_eq!(insn.mnemonic, "c.addi");
        assert_eq!(insn.base_mnemonic, "addi");
    }

    #[test]
    fn test_c_j() {
        // C.J can be identified by funct3=101, Q1
        // build a simple C.J word: funct3=101 Q1 → top 3 bits = 101, bottom 2 = 01
        // Simple offset=0: bits 12:2 all 0 for minimal offset
        // 0b101_00000000_01 = 0xA001
        let insn = dec32().decode(0xA001).unwrap();
        assert_eq!(insn.mnemonic, "c.j");
        assert!(insn.is_branch);
        assert!(!insn.is_call);
    }

    #[test]
    fn test_c_jr() {
        // C.JR ra: funct3=100, bit12=0, rs1=1, rs2=0 → 0x8082
        let insn = dec32().decode(0x8082).unwrap();
        assert_eq!(insn.mnemonic, "c.jr");
        assert!(insn.is_return);
    }

    #[test]
    fn test_c_jalr() {
        // C.JALR t0 (rs1=5): funct3=100, bit12=1, rs1=5, rs2=0
        // 0x9282
        let insn = dec32().decode(0x9282).unwrap();
        assert_eq!(insn.mnemonic, "c.jalr");
        assert!(insn.is_call);
    }

    #[test]
    fn test_c_ebreak() {
        // 0x9002
        let insn = dec32().decode(0x9002).unwrap();
        assert_eq!(insn.mnemonic, "c.ebreak");
    }

    #[test]
    fn test_c_lw() {
        // C.LW s0, 0(s0): Q0 funct3=010
        // bits[15:13]=010, rs1'=000, rd'=000, offset=0, quad=00 → 0x4000
        let insn = dec32().decode(0x4000).unwrap();
        assert_eq!(insn.mnemonic, "c.lw");
        assert_eq!(insn.base_mnemonic, "lw");
    }

    #[test]
    fn test_c_sw() {
        // C.SW: Q0 funct3=110
        let insn = dec32().decode(0xC000).unwrap();
        assert_eq!(insn.mnemonic, "c.sw");
        assert_eq!(insn.base_mnemonic, "sw");
    }

    #[test]
    fn test_c_ld_rv64() {
        // C.LD: Q0 funct3=011 with rv64=true
        let insn = dec64().decode(0x6000).unwrap();
        assert_eq!(insn.mnemonic, "c.ld");
        assert_eq!(insn.base_mnemonic, "ld");
    }

    #[test]
    fn test_c_flw_rv32() {
        let insn = dec32().decode(0x6000).unwrap();
        assert_eq!(insn.mnemonic, "c.flw");
    }

    #[test]
    fn test_c_addiw_rv64() {
        // C.ADDIW: Q1 funct3=001, rv64=true → rs1_rd nonzero
        // bits[15:13]=001, bits[11:7]=01010 (a0), bit12=0, bits[6:2]=00001 → Q1
        // 0b001_00001_0000_101_01 = word with a0=10, imm=1
        // funct3=001, rs1_rd=10, imm[5]=0, imm[4:0]=1 → 0x2509
        // Let's just build manually: funct3=001(top3), rd=01010(11:7), nzimm=00001(6:2), q=01
        // word = (0b001 << 13) | (0b01010 << 7) | (0b00001 << 2) | 0b01 = 0x2505
        let insn = dec64().decode(0x2505).unwrap();
        assert_eq!(insn.mnemonic, "c.addiw");
        assert_eq!(insn.base_mnemonic, "addiw");
    }

    #[test]
    fn test_c_jal_rv32() {
        let insn = dec32().decode(0x2001).unwrap();
        assert_eq!(insn.mnemonic, "c.jal");
        assert!(insn.is_call);
    }

    #[test]
    fn test_c_srli() {
        // C.SRLI s0, 1: Q1 funct3=100, funct2=00, rs1'=000, shamt=1
        // 0x8101
        let insn = dec32().decode(0x8101).unwrap();
        assert_eq!(insn.mnemonic, "c.srli");
        assert_eq!(insn.base_mnemonic, "srli");
    }

    #[test]
    fn test_c_srai() {
        // C.SRAI: funct2=01
        let insn = dec32().decode(0x8501).unwrap();
        assert_eq!(insn.mnemonic, "c.srai");
    }

    #[test]
    fn test_c_andi() {
        let insn = dec32().decode(0x8905).unwrap();
        assert_eq!(insn.mnemonic, "c.andi");
    }

    #[test]
    fn test_c_sub() {
        // CA format C.SUB: bit12=0, funct2=11, inner_funct2=00
        let insn = dec32().decode(0x8C01).unwrap();
        assert_eq!(insn.mnemonic, "c.sub");
        assert_eq!(insn.base_mnemonic, "sub");
    }

    #[test]
    fn test_c_and() {
        let insn = dec32().decode(0x8CF1).unwrap();
        assert_eq!(insn.mnemonic, "c.and");
    }

    #[test]
    fn test_c_slli() {
        // C.SLLI a0, 1: Q2 funct3=000
        // 0x0506
        let insn = dec32().decode(0x0506).unwrap();
        assert_eq!(insn.mnemonic, "c.slli");
        assert_eq!(insn.base_mnemonic, "slli");
    }

    #[test]
    fn test_c_lwsp() {
        // C.LWSP a0, 0(sp): Q2 funct3=010
        let insn = dec32().decode(0x4502).unwrap();
        assert_eq!(insn.mnemonic, "c.lwsp");
    }

    #[test]
    fn test_c_swsp() {
        // C.SWSP a0, 0(sp): Q2 funct3=110
        let insn = dec32().decode(0xC22A).unwrap();
        assert_eq!(insn.mnemonic, "c.swsp");
    }

    #[test]
    fn test_c_mv() {
        // C.MV a0, a1: Q2 funct3=100, bit12=0, rs1=10, rs2=11
        let insn = dec32().decode(0x852E).unwrap();
        assert_eq!(insn.mnemonic, "c.mv");
        assert_eq!(insn.base_mnemonic, "add");
    }

    #[test]
    fn test_expand_compressed() {
        let (mn, ops) = expand_compressed(0x0001, false).unwrap();
        assert_eq!(mn, "addi");
        assert_eq!(ops, "x0, x0, 0");
    }

    #[test]
    fn test_invalid_quadrant_3() {
        // 32-bit instruction has bits[1:0]=11 — should error
        let err = RiscvCompressedDecoder::new(false).decode(0x0033);
        assert!(err.is_err());
    }

    #[test]
    fn test_display() {
        let insn = dec32().decode(0x0001).unwrap();
        let s = format!("{insn}");
        assert!(s.contains("c.nop"));
    }

    #[test]
    fn test_decode_stream_skips_32bit() {
        // 32-bit instruction (bits[1:0]=11) followed by C.NOP
        let bytes = [0x13, 0x00, 0x00, 0x00, 0x01, 0x00];
        let results = decode_stream(&bytes, false);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 4);
        assert!(results[0].1.is_ok());
    }

    // ───── Edge-case coverage ─────────────────────────────────────────────

    #[test]
    fn decode_stream_empty_input() {
        let results = decode_stream(&[], false);
        assert!(results.is_empty());
    }

    #[test]
    fn decode_stream_odd_byte_does_not_panic() {
        // Buffer ends mid-word: trailing byte must not panic the decoder.
        let bytes = [0x01u8, 0x00, 0xAA];
        let results = decode_stream(&bytes, false);
        // Either the trailing byte was skipped or surfaced as an error,
        // but we must not panic.
        for (_off, r) in &results {
            let _ = r;
        }
    }

    #[test]
    fn all_zero_word_is_illegal() {
        // 0x0000 = all-zero C-extension instruction = illegal/reserved
        let r = dec32().decode(0x0000);
        assert!(r.is_err());
    }

    #[test]
    fn quadrant_3_is_always_error_both_widths() {
        for word in [0x0003u16, 0x0033, 0xFFFF, 0x1003] {
            assert!(dec32().decode(word).is_err());
            assert!(dec64().decode(word).is_err());
        }
    }

    #[test]
    fn rv32_rv64_differ_for_funct3_011_q0() {
        // 0x6000 is C.FLW in rv32 but C.LD in rv64.
        let r32 = dec32().decode(0x6000).unwrap();
        let r64 = dec64().decode(0x6000).unwrap();
        assert_ne!(r32.mnemonic, r64.mnemonic);
    }

    #[test]
    fn many_decodes_deterministic() {
        // Decoding the same word twice yields identical result.
        let a = dec32().decode(0x0001).unwrap();
        let b = dec32().decode(0x0001).unwrap();
        assert_eq!(a.mnemonic, b.mnemonic);
        assert_eq!(a.base_mnemonic, b.base_mnemonic);
    }

    #[test]
    fn c_jr_flagged_as_return_not_call() {
        let insn = dec32().decode(0x8082).unwrap();
        assert!(insn.is_return);
        assert!(!insn.is_call);
    }
}
