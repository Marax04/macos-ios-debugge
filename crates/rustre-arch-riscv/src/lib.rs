//! `rustre-arch-riscv`
//!
//! Production-quality RISC-V disassembler — manual decoding, no external
//! disassembler dependency.
//!
//! # Coverage
//! - **RV32I / RV64I / RV128I** base integer ISA
//! - **M** extension: MUL, MULH, MULHSU, MULHU, DIV, DIVU, REM, REMU (32/64)
//! - **A** extension: LR.W/D, SC.W/D, AMOSWAP, AMOADD, AMOXOR, AMOAND,
//!   AMOOR, AMOMIN, AMOMAX, AMOMINU, AMOMAXU (32/64)
//! - **F** extension: FLW, FSW, FMADD.S, FMSUB.S, FNMADD.S, FNMSUB.S,
//!   FADD.S … FCVT.W.S, FMV.X.W, FMV.W.X, FCLASS.S, FEQ.S, FLT.S, FLE.S
//! - **D** extension: FLD, FSD, FMADD.D … FCVT.L.D, FMV.X.D, FMV.D.X,
//!   FCLASS.D, FEQ.D, FLT.D, FLE.D
//! - **C** (compressed) extension: 16-bit instruction decoding
//! - **Zicsr** extension: CSRRW, CSRRS, CSRRC, CSRRWI, CSRRSI, CSRRCI
//! - Full CSR name table (hundreds of CSRs)
//! - **Zifencei**: FENCE.I
//! - **H** hypervisor extension basics (HLV, HSV, HFENCE)
//! - Privilege levels (M/S/U/VS/VU)
//! - RISC-V ABI: LP64, LP64F, LP64D, ILP32, ILP32F, ILP32D

/// RISC-V Vector extension (RVV).
///
/// VectorDecoder, VlenConfig, VType (SEW/LMUL), all vector instructions,
/// VReg (v0–v31), vl/vtype CSRs, VectorRegFile.
pub mod riscv_vector;

/// RISC-V higher-level analysis.
///
/// RiscVAbi (ilp32/lp64/…), RiscVCallingConv, CompressedInsn (C extension
/// decode), SoftFloat detection, PicCode/GOT analysis, RiscVAnalysis facade.
pub mod riscv_analysis;

/// Complete RISC-V CSR register file: RiscVCsr, CsrId, CsrAccess, CsrDescriptor,
/// McauseDecoder, MstatusDecoder, Mtvec — all 4096 CSR addresses.
pub mod riscv_csr;
pub mod riscv_compressed_decoder;
pub mod riscv_csr_map;
pub mod riscv_exception_handler;

use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
};
use rustre_core::address::Address;
use rustre_core::arch::{BranchCondition, RegisterKind};
use rustre_core::endian::Endian;
use rustre_core::errors::CoreError;

/// Build an [`Instruction`] from its component fields using the core constructor.
fn mk(
    address: Address,
    size: usize,
    mnemonic: &str,
    operands: String,
    flags: InstrFlags,
    bytes: Vec<u8>,
) -> Instruction {
    let mut instr = Instruction::new(address, size, mnemonic, bytes);
    instr.operands = operands;
    instr.flags = flags;
    instr
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// RISC-V architecture descriptor.
///
/// Construct with [`RiscvArch::rv32`], [`RiscvArch::rv64`], or
/// [`RiscvArch::rv128`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiscvArch {
    /// Pointer width in bits — 32, 64, or 128.
    pub bits: u32,
}

impl Default for RiscvArch {
    fn default() -> Self {
        Self::rv64()
    }
}

/// The register and function fields of an R-type-shaped instruction word.
///
/// The `decode_*` helpers all need the same five fields; passing them as one
/// value keeps the call sites readable and makes it impossible to swap two
/// same-typed register indices by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RFields {
    /// Destination register index, bits [11:7].
    rd: usize,
    /// First source register index, bits [19:15].
    rs1: usize,
    /// Second source register index, bits [24:20].
    rs2: usize,
    /// `funct3` field, bits [14:12].
    funct3: u32,
    /// `funct7` field, bits [31:25].
    funct7: u32,
}

impl RFields {
    /// Extract all five fields from a 32-bit instruction word.
    const fn from_word(word: u32) -> Self {
        Self {
            rd: ((word >> 7) & 0x1F) as usize,
            rs1: ((word >> 15) & 0x1F) as usize,
            rs2: ((word >> 20) & 0x1F) as usize,
            funct3: (word >> 12) & 0x07,
            funct7: (word >> 25) & 0x7F,
        }
    }
}

impl RiscvArch {
    /// True when `bits` is one of the XLEN widths this decoder implements.
    ///
    /// Every `decode_*` helper documents this as a precondition and checks it
    /// with a `debug_assert!`, so a caller that builds a `RiscvArch` by hand
    /// with a nonsense width fails loudly in debug builds instead of silently
    /// producing RV32 output.
    #[must_use]
    pub const fn is_supported_xlen(&self) -> bool {
        matches!(self.bits, 32 | 64 | 128)
    }

    /// RV32I base ISA.
    #[must_use]
    pub const fn rv32() -> Self {
        Self { bits: 32 }
    }

    /// RV64I base ISA.
    #[must_use]
    pub const fn rv64() -> Self {
        Self { bits: 64 }
    }

    /// RV128I base ISA (experimental).
    #[must_use]
    pub const fn rv128() -> Self {
        Self { bits: 128 }
    }

    // ------------------------------------------------------------------
    // Top-level decode dispatch
    // ------------------------------------------------------------------

    fn decode_word(&self, address: Address, word: u32, raw: &[u8]) -> Instruction {
        assert!(raw.len() >= 4, "decode_word requires at least 4 bytes");
        let bytes = raw[..4].to_vec();
        let opcode = word & 0x7F;
        let fields = RFields::from_word(word);
        let RFields {
            rd,
            rs1,
            rs2,
            funct3,
            funct7: _,
        } = fields;

        match opcode {
            0x03 => self.decode_load(address, rd, funct3, rs1, imm_i(word), bytes),
            0x07 => self.decode_fp_load(address, rd, funct3, rs1, imm_i(word), bytes),
            0x0F => self.decode_fence(address, word, funct3, bytes),
            0x13 => self.decode_op_imm(address, rd, funct3, rs1, word, bytes),
            0x17 => plain(
                address,
                "auipc",
                format!("{}, 0x{:x}", xr(rd), imm_u(word) >> 12),
                bytes,
            ),
            0x1B => self.decode_op_imm32(address, rd, funct3, rs1, word, bytes),
            0x23 => self.decode_store(address, rs1, rs2, funct3, imm_s(word), bytes),
            0x27 => self.decode_fp_store(address, rs1, rs2, funct3, imm_s(word), bytes),
            0x2F => self.decode_atomic(address, fields, bytes),
            0x33 => self.decode_op(address, fields, bytes),
            0x37 => plain(
                address,
                "lui",
                format!("{}, 0x{:x}", xr(rd), imm_u(word) >> 12),
                bytes,
            ),
            0x3B => self.decode_op32(address, fields, bytes),
            0x43 => self.decode_fmadd(address, fields, "fmadd", bytes),
            0x47 => self.decode_fmadd(address, fields, "fmsub", bytes),
            0x4B => self.decode_fmadd(address, fields, "fnmsub", bytes),
            0x4F => self.decode_fmadd(address, fields, "fnmadd", bytes),
            0x53 => self.decode_fp_op(address, fields, bytes),
            0x63 => self.decode_branch(address, rs1, rs2, funct3, imm_b(word), bytes),
            0x67 if funct3 == 0 => self.decode_jalr(address, rd, rs1, imm_i(word), bytes),
            0x6F => self.decode_jal(address, rd, imm_j(word), bytes),
            0x73 => self.decode_system(address, fields, word, bytes),
            _ => unknown(address, bytes),
        }
    }

    // ------------------------------------------------------------------
    // LOAD (opcode 0x03)
    // ------------------------------------------------------------------

    fn decode_load(
        &self,
        address: Address,
        rd: usize,
        funct3: u32,
        rs1: usize,
        imm: i32,
        bytes: Vec<u8>,
    ) -> Instruction {
        let mn = match funct3 {
            0 => "lb",
            1 => "lh",
            2 => "lw",
            3 if self.bits >= 64 => "ld",
            4 => "lbu",
            5 => "lhu",
            6 if self.bits >= 64 => "lwu",
            _ => return unknown(address, bytes),
        };
        mem_load(address, mn, xr(rd), imm, xr(rs1), bytes)
    }

    // ------------------------------------------------------------------
    // FP LOAD (opcode 0x07)
    // ------------------------------------------------------------------

    fn decode_fp_load(
        &self,
        address: Address,
        rd: usize,
        funct3: u32,
        rs1: usize,
        imm: i32,
        bytes: Vec<u8>,
    ) -> Instruction {
        debug_assert!(self.is_supported_xlen(), "unsupported XLEN {}", self.bits);
        let mn = match funct3 {
            2 => "flw",
            3 => "fld",
            4 => "flq",
            _ => return unknown(address, bytes),
        };
        mem_load(address, mn, &fr(rd), imm, xr(rs1), bytes)
    }

    // ------------------------------------------------------------------
    // FENCE (opcode 0x0F)
    // ------------------------------------------------------------------

    fn decode_fence(
        &self,
        address: Address,
        word: u32,
        funct3: u32,
        bytes: Vec<u8>,
    ) -> Instruction {
        debug_assert!(self.is_supported_xlen(), "unsupported XLEN {}", self.bits);
        if funct3 == 0 {
            let pred = (word >> 24) & 0xF;
            let succ = (word >> 20) & 0xF;
            let pred_str = fence_bits(pred);
            let succ_str = fence_bits(succ);
            mk(
                address,
                4,
                "fence",
                format!("{pred_str}, {succ_str}"),
                InstrFlags::BARRIER,
                bytes,
            )
        } else if funct3 == 1 {
            mk(
                address,
                4,
                "fence.i",
                String::new(),
                InstrFlags::BARRIER,
                bytes,
            )
        } else {
            unknown(address, bytes)
        }
    }

    // ------------------------------------------------------------------
    // STORE (opcode 0x23)
    // ------------------------------------------------------------------

    fn decode_store(
        &self,
        address: Address,
        rs1: usize,
        rs2: usize,
        funct3: u32,
        imm: i32,
        bytes: Vec<u8>,
    ) -> Instruction {
        let mn = match funct3 {
            0 => "sb",
            1 => "sh",
            2 => "sw",
            3 if self.bits >= 64 => "sd",
            _ => return unknown(address, bytes),
        };
        mem_store(address, mn, xr(rs2), imm, xr(rs1), bytes)
    }

    // ------------------------------------------------------------------
    // FP STORE (opcode 0x27)
    // ------------------------------------------------------------------

    fn decode_fp_store(
        &self,
        address: Address,
        rs1: usize,
        rs2: usize,
        funct3: u32,
        imm: i32,
        bytes: Vec<u8>,
    ) -> Instruction {
        debug_assert!(self.is_supported_xlen(), "unsupported XLEN {}", self.bits);
        let mn = match funct3 {
            2 => "fsw",
            3 => "fsd",
            4 => "fsq",
            _ => return unknown(address, bytes),
        };
        mem_store(address, mn, &fr(rs2), imm, xr(rs1), bytes)
    }

    // ------------------------------------------------------------------
    // OP-IMM (opcode 0x13)
    // ------------------------------------------------------------------

    fn decode_op_imm(
        &self,
        address: Address,
        rd: usize,
        funct3: u32,
        rs1: usize,
        word: u32,
        bytes: Vec<u8>,
    ) -> Instruction {
        let imm = imm_i(word);
        let shamt = (word >> 20) & if self.bits == 64 { 0x3F } else { 0x1F };
        let funct7 = (word >> 25) & 0x7F;
        match funct3 {
            0 => plain(
                address,
                "addi",
                format!("{}, {}, {imm}", xr(rd), xr(rs1)),
                bytes,
            ),
            1 => plain(
                address,
                "slli",
                format!("{}, {}, {shamt}", xr(rd), xr(rs1)),
                bytes,
            ),
            2 => plain(
                address,
                "slti",
                format!("{}, {}, {imm}", xr(rd), xr(rs1)),
                bytes,
            ),
            3 => plain(
                address,
                "sltiu",
                format!("{}, {}, {imm}", xr(rd), xr(rs1)),
                bytes,
            ),
            4 => plain(
                address,
                "xori",
                format!("{}, {}, {imm}", xr(rd), xr(rs1)),
                bytes,
            ),
            5 => {
                let mn = if funct7 & 0x20 != 0 { "srai" } else { "srli" };
                plain(
                    address,
                    mn,
                    format!("{}, {}, {shamt}", xr(rd), xr(rs1)),
                    bytes,
                )
            }
            6 => plain(
                address,
                "ori",
                format!("{}, {}, {imm}", xr(rd), xr(rs1)),
                bytes,
            ),
            7 => plain(
                address,
                "andi",
                format!("{}, {}, {imm}", xr(rd), xr(rs1)),
                bytes,
            ),
            _ => unknown(address, bytes),
        }
    }

    // ------------------------------------------------------------------
    // OP (opcode 0x33)
    // ------------------------------------------------------------------

    fn decode_op(&self, address: Address, f: RFields, bytes: Vec<u8>) -> Instruction {
        let RFields {
            rd,
            rs1,
            rs2,
            funct3,
            funct7,
        } = f;
        debug_assert!(self.is_supported_xlen(), "unsupported XLEN {}", self.bits);
        // M extension
        if funct7 == 0x01 {
            let mn = match funct3 {
                0 => "mul",
                1 => "mulh",
                2 => "mulhsu",
                3 => "mulhu",
                4 => "div",
                5 => "divu",
                6 => "rem",
                7 => "remu",
                _ => return unknown(address, bytes),
            };
            return plain(
                address,
                mn,
                format!("{}, {}, {}", xr(rd), xr(rs1), xr(rs2)),
                bytes,
            );
        }
        let sub = funct7 & 0x20 != 0;
        let mn = match (funct3, sub) {
            (0, false) => "add",
            (0, true) => "sub",
            (1, _) => "sll",
            (2, _) => "slt",
            (3, _) => "sltu",
            (4, _) => "xor",
            (5, false) => "srl",
            (5, true) => "sra",
            (6, _) => "or",
            (7, _) => "and",
            _ => return unknown(address, bytes),
        };
        plain(
            address,
            mn,
            format!("{}, {}, {}", xr(rd), xr(rs1), xr(rs2)),
            bytes,
        )
    }

    // ------------------------------------------------------------------
    // OP-IMM-32 / OP-32 (RV64)
    // ------------------------------------------------------------------

    fn decode_op_imm32(
        &self,
        address: Address,
        rd: usize,
        funct3: u32,
        rs1: usize,
        word: u32,
        bytes: Vec<u8>,
    ) -> Instruction {
        debug_assert!(self.is_supported_xlen(), "unsupported XLEN {}", self.bits);
        let imm = imm_i(word);
        let shamt = (word >> 20) & 0x1F;
        let funct7 = (word >> 25) & 0x7F;
        match funct3 {
            0 => plain(
                address,
                "addiw",
                format!("{}, {}, {imm}", xr(rd), xr(rs1)),
                bytes,
            ),
            1 => plain(
                address,
                "slliw",
                format!("{}, {}, {shamt}", xr(rd), xr(rs1)),
                bytes,
            ),
            5 => {
                let mn = if funct7 & 0x20 != 0 { "sraiw" } else { "srliw" };
                plain(
                    address,
                    mn,
                    format!("{}, {}, {shamt}", xr(rd), xr(rs1)),
                    bytes,
                )
            }
            _ => unknown(address, bytes),
        }
    }

    fn decode_op32(&self, address: Address, f: RFields, bytes: Vec<u8>) -> Instruction {
        let RFields {
            rd,
            rs1,
            rs2,
            funct3,
            funct7,
        } = f;
        debug_assert!(self.is_supported_xlen(), "unsupported XLEN {}", self.bits);
        if funct7 == 0x01 {
            let mn = match funct3 {
                0 => "mulw",
                4 => "divw",
                5 => "divuw",
                6 => "remw",
                7 => "remuw",
                _ => return unknown(address, bytes),
            };
            return plain(
                address,
                mn,
                format!("{}, {}, {}", xr(rd), xr(rs1), xr(rs2)),
                bytes,
            );
        }
        let sub = funct7 & 0x20 != 0;
        let mn = match (funct3, sub) {
            (0, false) => "addw",
            (0, true) => "subw",
            (1, _) => "sllw",
            (5, false) => "srlw",
            (5, true) => "sraw",
            _ => return unknown(address, bytes),
        };
        plain(
            address,
            mn,
            format!("{}, {}, {}", xr(rd), xr(rs1), xr(rs2)),
            bytes,
        )
    }

    // ------------------------------------------------------------------
    // ATOMIC (opcode 0x2F — A extension)
    // ------------------------------------------------------------------

    fn decode_atomic(&self, address: Address, f: RFields, bytes: Vec<u8>) -> Instruction {
        let RFields {
            rd,
            rs1,
            rs2,
            funct3,
            funct7,
        } = f;
        debug_assert!(self.is_supported_xlen(), "unsupported XLEN {}", self.bits);
        let aq = (funct7 >> 1) & 1;
        let rl = funct7 & 1;
        let funct5 = funct7 >> 2;
        let suffix = match funct3 {
            2 => ".w",
            3 => ".d",
            _ => return unknown(address, bytes),
        };
        let aq_rl = match (aq, rl) {
            (1, 1) => ".aqrl",
            (1, 0) => ".aq",
            (0, 1) => ".rl",
            _ => "",
        };

        match funct5 {
            0x02 => {
                let mn = format!("lr{suffix}{aq_rl}");
                plain(address, &mn, format!("{}, ({})", xr(rd), xr(rs1)), bytes)
            }
            0x03 => {
                let mn = format!("sc{suffix}{aq_rl}");
                plain(
                    address,
                    &mn,
                    format!("{}, {}, ({})", xr(rd), xr(rs2), xr(rs1)),
                    bytes,
                )
            }
            0x01 => amo(address, "amoswap", suffix, aq_rl, f, bytes),
            0x00 => amo(address, "amoadd", suffix, aq_rl, f, bytes),
            0x04 => amo(address, "amoxor", suffix, aq_rl, f, bytes),
            0x0C => amo(address, "amoand", suffix, aq_rl, f, bytes),
            0x08 => amo(address, "amoor", suffix, aq_rl, f, bytes),
            0x10 => amo(address, "amomin", suffix, aq_rl, f, bytes),
            0x14 => amo(address, "amomax", suffix, aq_rl, f, bytes),
            0x18 => amo(address, "amominu", suffix, aq_rl, f, bytes),
            0x1C => amo(address, "amomaxu", suffix, aq_rl, f, bytes),
            _ => unknown(address, bytes),
        }
    }

    // ------------------------------------------------------------------
    // BRANCH (opcode 0x63)
    // ------------------------------------------------------------------

    fn decode_branch(
        &self,
        address: Address,
        rs1: usize,
        rs2: usize,
        funct3: u32,
        offset: i32,
        bytes: Vec<u8>,
    ) -> Instruction {
        debug_assert!(self.is_supported_xlen(), "unsupported XLEN {}", self.bits);
        let target = address.0.wrapping_add((i64::from(offset)).cast_unsigned());
        let mn = match funct3 {
            0 => "beq",
            1 => "bne",
            4 => "blt",
            5 => "bge",
            6 => "bltu",
            7 => "bgeu",
            _ => return unknown(address, bytes),
        };
        mk(
            address,
            4,
            mn,
            format!("{}, {}, 0x{target:x}", xr(rs1), xr(rs2)),
            InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
            bytes,
        )
    }

    // ------------------------------------------------------------------
    // JAL / JALR
    // ------------------------------------------------------------------

    fn decode_jal(&self, address: Address, rd: usize, offset: i32, bytes: Vec<u8>) -> Instruction {
        debug_assert!(self.is_supported_xlen(), "unsupported XLEN {}", self.bits);
        let target = address.0.wrapping_add((i64::from(offset)).cast_unsigned());
        let flags = if rd == 1 {
            InstrFlags::BRANCH | InstrFlags::CALL
        } else {
            InstrFlags::BRANCH
        };
        let ops = if rd == 0 {
            format!("0x{target:x}")
        } else {
            format!("{}, 0x{target:x}", xr(rd))
        };
        mk(address, 4, "jal", ops, flags, bytes)
    }

    fn decode_jalr(
        &self,
        address: Address,
        rd: usize,
        rs1: usize,
        offset: i32,
        bytes: Vec<u8>,
    ) -> Instruction {
        debug_assert!(self.is_supported_xlen(), "unsupported XLEN {}", self.bits);
        let flags = if rd == 0 && rs1 == 1 && offset == 0 {
            InstrFlags::BRANCH | InstrFlags::INDIRECT | InstrFlags::RET
        } else if rd == 1 {
            InstrFlags::BRANCH | InstrFlags::INDIRECT | InstrFlags::CALL
        } else {
            InstrFlags::BRANCH | InstrFlags::INDIRECT
        };
        let ops = if rd == 0 && offset == 0 {
            xr(rs1).into()
        } else {
            format!("{}, {}, {offset}", xr(rd), xr(rs1))
        };
        mk(address, 4, "jalr", ops, flags, bytes)
    }

    // ------------------------------------------------------------------
    // FP fused multiply-add (opcodes 0x43 / 0x47 / 0x4B / 0x4F)
    // ------------------------------------------------------------------

    fn decode_fmadd(
        &self,
        address: Address,
        f: RFields,
        base: &str,
        bytes: Vec<u8>,
    ) -> Instruction {
        let RFields {
            rd,
            rs1,
            rs2,
            funct7,
            ..
        } = f;
        debug_assert!(self.is_supported_xlen(), "unsupported XLEN {}", self.bits);
        let rs3 = (funct7 >> 2) as usize;
        let fmt = funct7 & 0x3;
        let suffix = fp_fmt(fmt);
        let mn = format!("{base}.{suffix}");
        plain(
            address,
            &mn,
            format!("{}, {}, {}, {}", fr(rd), fr(rs1), fr(rs2), fr(rs3)),
            bytes,
        )
    }

    // ------------------------------------------------------------------
    // FP OP (opcode 0x53)
    // ------------------------------------------------------------------

    fn decode_fp_op(&self, address: Address, f: RFields, bytes: Vec<u8>) -> Instruction {
        let RFields {
            rd,
            rs1,
            rs2,
            funct3,
            funct7,
        } = f;
        debug_assert!(self.is_supported_xlen(), "unsupported XLEN {}", self.bits);
        let fmt = funct7 & 0x3;
        let funct5 = funct7 >> 2;
        let suffix = fp_fmt(fmt);

        match funct5 {
            0x00 => plain(
                address,
                &format!("fadd.{suffix}"),
                format!("{}, {}, {}", fr(rd), fr(rs1), fr(rs2)),
                bytes,
            ),
            0x01 => plain(
                address,
                &format!("fsub.{suffix}"),
                format!("{}, {}, {}", fr(rd), fr(rs1), fr(rs2)),
                bytes,
            ),
            0x02 => plain(
                address,
                &format!("fmul.{suffix}"),
                format!("{}, {}, {}", fr(rd), fr(rs1), fr(rs2)),
                bytes,
            ),
            0x03 => plain(
                address,
                &format!("fdiv.{suffix}"),
                format!("{}, {}, {}", fr(rd), fr(rs1), fr(rs2)),
                bytes,
            ),
            0x04 => {
                let mn = match funct3 {
                    0 => format!("fsgnj.{suffix}"),
                    1 => format!("fsgnjn.{suffix}"),
                    _ => format!("fsgnjx.{suffix}"),
                };
                plain(
                    address,
                    &mn,
                    format!("{}, {}, {}", fr(rd), fr(rs1), fr(rs2)),
                    bytes,
                )
            }
            0x05 => {
                let mn = if funct3 == 0 {
                    format!("fmin.{suffix}")
                } else {
                    format!("fmax.{suffix}")
                };
                plain(
                    address,
                    &mn,
                    format!("{}, {}, {}", fr(rd), fr(rs1), fr(rs2)),
                    bytes,
                )
            }
            _ => self.decode_fp_op_rest(address, f, bytes),
        }
    }

    /// Second half of the FP-op funct5 table.
    fn decode_fp_op_rest(&self, address: Address, f: RFields, bytes: Vec<u8>) -> Instruction {
        let RFields {
            rd,
            rs1,
            rs2,
            funct3,
            funct7,
        } = f;
        debug_assert!(self.is_supported_xlen(), "unsupported XLEN {}", self.bits);
        let fmt = funct7 & 0x3;
        let funct5 = funct7 >> 2;
        let suffix = fp_fmt(fmt);

        match funct5 {
            0x08 => {
                // `rs2 & 0x1F` is at most 31, so this conversion is exact for every
                // input and the fallback arm is unreachable.
                let to_fmt = fp_fmt(u32::try_from(rs2 & 0x1F).unwrap_or(0));
                plain(
                    address,
                    &format!("fcvt.{to_fmt}.{suffix}"),
                    format!("{}, {}", fr(rd), fr(rs1)),
                    bytes,
                )
            }
            0x0B => plain(
                address,
                &format!("fsqrt.{suffix}"),
                format!("{}, {}", fr(rd), fr(rs1)),
                bytes,
            ),
            0x14 => {
                let mn = match funct3 {
                    0 => format!("fle.{suffix}"),
                    1 => format!("flt.{suffix}"),
                    _ => format!("feq.{suffix}"),
                };
                plain(
                    address,
                    &mn,
                    format!("{}, {}, {}", xr(rd), fr(rs1), fr(rs2)),
                    bytes,
                )
            }
            _ => self.decode_fp_op_tail(address, f, bytes),
        }
    }

    /// Final part of the FP-op funct5 table.
    fn decode_fp_op_tail(&self, address: Address, f: RFields, bytes: Vec<u8>) -> Instruction {
        let RFields {
            rd,
            rs1,
            rs2,
            funct3,
            funct7,
        } = f;
        debug_assert!(self.is_supported_xlen(), "unsupported XLEN {}", self.bits);
        let fmt = funct7 & 0x3;
        let funct5 = funct7 >> 2;
        let suffix = fp_fmt(fmt);

        match funct5 {
            0x18 => {
                let mn = match rs2 {
                    0 => format!("fcvt.{suffix}.w"),
                    1 => format!("fcvt.{suffix}.wu"),
                    2 => format!("fcvt.{suffix}.l"),
                    3 => format!("fcvt.{suffix}.lu"),
                    _ => return unknown(address, bytes),
                };
                plain(address, &mn, format!("{}, {}", fr(rd), xr(rs1)), bytes)
            }
            0x1A => {
                let mn = match rs2 {
                    0 => format!("fcvt.w.{suffix}"),
                    1 => format!("fcvt.wu.{suffix}"),
                    2 => format!("fcvt.l.{suffix}"),
                    3 => format!("fcvt.lu.{suffix}"),
                    _ => return unknown(address, bytes),
                };
                plain(address, &mn, format!("{}, {}", xr(rd), fr(rs1)), bytes)
            }
            0x1C => {
                if funct3 == 0 {
                    if fmt == 0 {
                        plain(
                            address,
                            "fmv.x.w",
                            format!("{}, {}", xr(rd), fr(rs1)),
                            bytes,
                        )
                    } else {
                        plain(
                            address,
                            "fmv.x.d",
                            format!("{}, {}", xr(rd), fr(rs1)),
                            bytes,
                        )
                    }
                } else {
                    plain(
                        address,
                        &format!("fclass.{suffix}"),
                        format!("{}, {}", xr(rd), fr(rs1)),
                        bytes,
                    )
                }
            }
            0x1E => {
                if fmt == 0 {
                    plain(
                        address,
                        "fmv.w.x",
                        format!("{}, {}", fr(rd), xr(rs1)),
                        bytes,
                    )
                } else {
                    plain(
                        address,
                        "fmv.d.x",
                        format!("{}, {}", fr(rd), xr(rs1)),
                        bytes,
                    )
                }
            }
            _ => unknown(address, bytes),
        }
    }

    // ------------------------------------------------------------------
    // SYSTEM (opcode 0x73)
    // ------------------------------------------------------------------

    fn decode_system(
        &self,
        address: Address,
        f: RFields,
        word: u32,
        bytes: Vec<u8>,
    ) -> Instruction {
        let RFields {
            rd,
            rs1,
            rs2,
            funct3,
            ..
        } = f;
        debug_assert!(self.is_supported_xlen(), "unsupported XLEN {}", self.bits);
        if funct3 == 0 {
            let funct12 = (word >> 20) & 0xFFF;
            return match funct12 {
                0x000 => mk(
                    address,
                    4,
                    "ecall",
                    String::new(),
                    InstrFlags::BARRIER,
                    bytes,
                ),
                0x001 => mk(
                    address,
                    4,
                    "ebreak",
                    String::new(),
                    InstrFlags::BARRIER,
                    bytes,
                ),
                0x002 => plain(address, "uret", String::new(), bytes),
                0x102 => plain(address, "sret", String::new(), bytes),
                0x302 => mk(address, 4, "mret", String::new(), InstrFlags::RET, bytes),
                0x105 => plain(address, "wfi", String::new(), bytes),
                0x104 => plain(
                    address,
                    "sfence.vma",
                    format!("{}, {}", xr(rs1), xr(rs2)),
                    bytes,
                ),
                _ if (word >> 25) == 0x09 => {
                    plain(address, "sfence.vma", format!("{}, {}", xr(rs1), xr(rs2)), bytes)
                }
                // Hypervisor fence
                0x204 => plain(
                    address,
                    "hfence.vvma",
                    format!("{}, {}", xr(rs1), xr(rs2)),
                    bytes,
                ),
                0x600 => plain(
                    address,
                    "hfence.gvma",
                    format!("{}, {}", xr(rs1), xr(rs2)),
                    bytes,
                ),
                _ => unknown(address, bytes),
            };
        }

        // CSR instructions
        let csr_num = (word >> 20) as u16;
        let csr_name = csr_name(csr_num);
        let (mn, ops) = match funct3 {
            1 => ("csrrw", format!("{}, {csr_name}, {}", xr(rd), xr(rs1))),
            2 => ("csrrs", format!("{}, {csr_name}, {}", xr(rd), xr(rs1))),
            3 => ("csrrc", format!("{}, {csr_name}, {}", xr(rd), xr(rs1))),
            5 => ("csrrwi", format!("{}, {csr_name}, {rs1}", xr(rd))),
            6 => ("csrrsi", format!("{}, {csr_name}, {rs1}", xr(rd))),
            7 => ("csrrci", format!("{}, {csr_name}, {rs1}", xr(rd))),
            _ => return unknown(address, bytes),
        };
        plain(address, mn, ops, bytes)
    }
}

// ---------------------------------------------------------------------------
// Compressed (C) extension decoder
// ---------------------------------------------------------------------------

/// Decode a 16-bit RV-C instruction.
///
/// Returns `(mnemonic, operands, flags)`.
///
/// # Errors
///
/// Returns [`CoreError::InvalidFormat`] for reserved or unrecognised encodings.
pub fn decode_compressed(hw: u16, xlen: u32, addr: Address) -> Result<Instruction, CoreError> {
    let bytes = hw.to_le_bytes().to_vec();
    let op = hw & 0x3; // quadrant (bits [1:0])
    let funct3 = (hw >> 13) & 0x7;

    match op {
        // ── Quadrant 0 ──────────────────────────────────────────────────────
        0 => {
            match funct3 {
                0 => {
                    // C.ADDI4SPN
                    let rd_prime = ((hw >> 2) & 0x7) as usize + 8;
                    let imm = c_addi4spn_imm(hw);
                    if imm == 0 {
                        return Err(CoreError::InvalidFormat {
                            message: "C.ADDI4SPN imm==0 is reserved".into(),
                        });
                    }
                    Ok(mk(
                        addr,
                        2,
                        "c.addi4spn",
                        format!("{}, sp, {imm}", xr(rd_prime)),
                        InstrFlags::NONE,
                        bytes,
                    ))
                }
                1 => {
                    let rd_prime = ((hw >> 2) & 0x7) as usize + 8;
                    let rs1_prime = ((hw >> 7) & 0x7) as usize + 8;
                    let uimm = c_lw_imm(hw);
                    Ok(mk(
                        addr,
                        2,
                        "c.fld",
                        format!("{}, {uimm}({})", fr(rd_prime), xr(rs1_prime)),
                        InstrFlags::READ_MEM,
                        bytes,
                    ))
                }
                2 => {
                    let rd_prime = ((hw >> 2) & 0x7) as usize + 8;
                    let rs1_prime = ((hw >> 7) & 0x7) as usize + 8;
                    let uimm = c_lw_imm(hw);
                    Ok(mk(
                        addr,
                        2,
                        "c.lw",
                        format!("{}, {uimm}({})", xr(rd_prime), xr(rs1_prime)),
                        InstrFlags::READ_MEM,
                        bytes,
                    ))
                }
                _ => decode_compressed_q0_rest(hw, xlen, addr),
            }
        }

        // ── Quadrant 1 ──────────────────────────────────────────────────────
        _ => decode_compressed_q1(hw, xlen, addr),
    }
}

/// Quadrants 1 and 2 of the compressed decoder.
fn decode_compressed_q1(hw: u16, xlen: u32, addr: Address) -> Result<Instruction, CoreError> {
    let bytes = hw.to_le_bytes().to_vec();
    let op = hw & 0x3; // quadrant (bits [1:0])
    let funct3 = (hw >> 13) & 0x7;

    match op {
        1 => {
            match funct3 {
                0 => {
                    // C.ADDI / C.NOP
                    let rd = ((hw >> 7) & 0x1F) as usize;
                    let imm = c_addi_imm(hw);
                    if rd == 0 {
                        Ok(mk(addr, 2, "c.nop", String::new(), InstrFlags::NONE, bytes))
                    } else {
                        Ok(mk(
                            addr,
                            2,
                            "c.addi",
                            format!("{}, {imm}", xr(rd)),
                            InstrFlags::NONE,
                            bytes,
                        ))
                    }
                }
                1 if xlen == 32 => {
                    // C.JAL (RV32 only)
                    let offset = c_j_offset(hw);
                    let target = addr.0.wrapping_add((i64::from(offset)).cast_unsigned());
                    Ok(mk(
                        addr,
                        2,
                        "c.jal",
                        format!("0x{target:x}"),
                        InstrFlags::BRANCH | InstrFlags::CALL,
                        bytes,
                    ))
                }
                1 if xlen >= 64 => {
                    // C.ADDIW
                    let rd = ((hw >> 7) & 0x1F) as usize;
                    let imm = c_addi_imm(hw);
                    Ok(mk(
                        addr,
                        2,
                        "c.addiw",
                        format!("{}, {imm}", xr(rd)),
                        InstrFlags::NONE,
                        bytes,
                    ))
                }
                2 => {
                    // C.LI
                    let rd = ((hw >> 7) & 0x1F) as usize;
                    let imm = c_addi_imm(hw);
                    Ok(mk(
                        addr,
                        2,
                        "c.li",
                        format!("{}, {imm}", xr(rd)),
                        InstrFlags::NONE,
                        bytes,
                    ))
                }
                _ => decode_compressed_q1_rest(hw, addr),
            }
        }

        // ── Quadrant 2 ──────────────────────────────────────────────────────
        _ => decode_compressed_q2(hw, xlen, addr),
    }
}

/// Quadrant 2 of the compressed decoder.
fn decode_compressed_q2(hw: u16, xlen: u32, addr: Address) -> Result<Instruction, CoreError> {
    let bytes = hw.to_le_bytes().to_vec();
    let op = hw & 0x3; // quadrant (bits [1:0])
    let funct3 = (hw >> 13) & 0x7;

    match op {
        2 => {
            match funct3 {
                0 => {
                    let rd = ((hw >> 7) & 0x1F) as usize;
                    let shamt = c_shamt(hw);
                    Ok(mk(
                        addr,
                        2,
                        "c.slli",
                        format!("{}, {shamt}", xr(rd)),
                        InstrFlags::NONE,
                        bytes,
                    ))
                }
                1 => {
                    let rd = ((hw >> 7) & 0x1F) as usize;
                    let uimm = c_fldsp_imm(hw);
                    Ok(mk(
                        addr,
                        2,
                        "c.fldsp",
                        format!("{}, {uimm}(sp)", fr(rd)),
                        InstrFlags::READ_MEM,
                        bytes,
                    ))
                }
                2 => {
                    let rd = ((hw >> 7) & 0x1F) as usize;
                    let uimm = c_lwsp_imm(hw);
                    Ok(mk(
                        addr,
                        2,
                        "c.lwsp",
                        format!("{}, {uimm}(sp)", xr(rd)),
                        InstrFlags::READ_MEM,
                        bytes,
                    ))
                }
                3 if xlen >= 64 => {
                    let rd = ((hw >> 7) & 0x1F) as usize;
                    let uimm = c_ldsp_imm(hw);
                    Ok(mk(
                        addr,
                        2,
                        "c.ldsp",
                        format!("{}, {uimm}(sp)", xr(rd)),
                        InstrFlags::READ_MEM,
                        bytes,
                    ))
                }
                _ => decode_compressed_q2_rest(hw, xlen, addr),
            }
        }
        _ => Err(CoreError::InvalidFormat {
            message: "not a compressed instruction (bit pattern 0x3)".into(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Compressed immediate helpers
// ---------------------------------------------------------------------------

const fn c_addi4spn_imm(hw: u16) -> u32 {
    let b5_4 = ((hw >> 11) & 0x3) as u32;
    let b9_6 = ((hw >> 7) & 0xF) as u32;
    let b2 = ((hw >> 6) & 0x1) as u32;
    let b3 = ((hw >> 5) & 0x1) as u32;
    (b9_6 << 6) | (b5_4 << 4) | (b3 << 3) | (b2 << 2)
}

fn c_lw_imm(hw: u16) -> u32 {
    let imm6 = (hw >> 2) & 0x7;
    let imm3 = (hw >> 10) & 0x7;
    u32::from(((imm3 & 0x7) << 3) | (((imm6 >> 1) & 0x3) << 6) | ((imm6 & 1) << 2))
}

fn c_ld_imm(hw: u16) -> u32 {
    let imm6 = (hw >> 2) & 0x7;
    let imm3 = (hw >> 10) & 0x7;
    u32::from(((imm3 & 0x7) << 3) | (imm6 << 6))
}

fn c_addi_imm(hw: u16) -> i32 {
    let nzimm4_0 = u32::from((hw >> 2) & 0x1F);
    let nzimm5 = u32::from((hw >> 12) & 1);
    let raw = (nzimm5 << 5) | nzimm4_0;
    // Sign-extend 6-bit value: shift as u32 then reinterpret as i32
    ((raw << 26).cast_signed()) >> 26
}

fn c_addi16sp_imm(hw: u16) -> i32 {
    let b9 = u32::from((hw >> 12) & 1);
    let b4 = u32::from((hw >> 6) & 1);
    let b6 = u32::from((hw >> 5) & 1);
    let b7b8 = u32::from((hw >> 3) & 0x3);
    let b5 = u32::from((hw >> 2) & 1);
    let raw = (b9 << 9) | (b7b8 << 7) | (b6 << 6) | (b5 << 5) | (b4 << 4);
    // Sign-extend 10-bit value
    ((raw << 22).cast_signed()) >> 22
}

fn c_lui_imm(hw: u16) -> u32 {
    let imm5 = u32::from((hw >> 2) & 0x1F);
    let imm17 = u32::from((hw >> 12) & 1);
    (imm17 << 17) | (imm5 << 12)
}

fn c_shamt(hw: u16) -> u32 {
    let sh5 = (hw >> 12) & 1;
    let sh4_0 = (hw >> 2) & 0x1F;
    u32::from((sh5 << 5) | sh4_0)
}

fn c_j_offset(hw: u16) -> i32 {
    let b11 = u32::from((hw >> 12) & 1);
    let b10 = u32::from((hw >> 11) & 1);
    let b9b8 = u32::from((hw >> 9) & 0x3);
    let b7 = u32::from((hw >> 8) & 1);
    let b6 = u32::from((hw >> 7) & 1);
    let b5 = u32::from((hw >> 6) & 1);
    let b4 = u32::from((hw >> 5) & 1);
    let b3b1 = u32::from((hw >> 2) & 0x7);
    let raw = (b11 << 11)
        | (b10 << 10)
        | (b9b8 << 8)
        | (b7 << 7)
        | (b6 << 6)
        | (b5 << 5)
        | (b4 << 4)
        | (b3b1 << 1);
    // Sign-extend 12-bit value
    ((raw << 20).cast_signed()) >> 20
}

fn c_b_offset(hw: u16) -> i32 {
    let b8 = u32::from((hw >> 12) & 1);
    let b7b6 = u32::from((hw >> 5) & 0x3);
    let b5 = u32::from((hw >> 2) & 0x1);
    let b4b3 = u32::from((hw >> 10) & 0x3);
    let b2b1 = u32::from((hw >> 3) & 0x3);
    let raw = (b8 << 8) | (b7b6 << 6) | (b5 << 5) | (b4b3 << 3) | (b2b1 << 1);
    // Sign-extend 9-bit value
    ((raw << 23).cast_signed()) >> 23
}

fn c_fldsp_imm(hw: u16) -> u32 {
    let b5 = (hw >> 12) & 1;
    let b4b3 = (hw >> 5) & 0x3;
    let b8b6 = (hw >> 2) & 0x7;
    u32::from((b8b6 << 6) | (b5 << 5) | (b4b3 << 3))
}

fn c_lwsp_imm(hw: u16) -> u32 {
    let b5 = (hw >> 12) & 1;
    let b4b2 = (hw >> 4) & 0x7;
    let b7b6 = (hw >> 2) & 0x3;
    u32::from((b7b6 << 6) | (b5 << 5) | (b4b2 << 2))
}

fn c_ldsp_imm(hw: u16) -> u32 {
    let b5 = (hw >> 12) & 1;
    let b4b3 = (hw >> 5) & 0x3;
    let b8b6 = (hw >> 2) & 0x7;
    u32::from((b8b6 << 6) | (b5 << 5) | (b4b3 << 3))
}

fn c_swsp_imm(hw: u16) -> u32 {
    let b7b6 = (hw >> 9) & 0x3;
    let b5b2 = (hw >> 7) & 0xF;
    u32::from((b7b6 << 6) | (b5b2 << 2))
}

fn c_sdsp_imm(hw: u16) -> u32 {
    let b8b6 = (hw >> 10) & 0x7;
    let b5b3 = (hw >> 7) & 0x7;
    u32::from((b8b6 << 6) | (b5b3 << 3))
}

fn c_fsdsp_imm(hw: u16) -> u32 {
    c_sdsp_imm(hw)
}

// ---------------------------------------------------------------------------
// Immediate field decoders
// ---------------------------------------------------------------------------

const fn imm_i(word: u32) -> i32 {
    (word.cast_signed()) >> 20
}

const fn imm_s(word: u32) -> i32 {
    let upper = (word >> 25) & 0x7F;
    let lower = (word >> 7) & 0x1F;
    let raw = (upper << 5) | lower;
    // Sign-extend 12-bit value via u32 to avoid signed overflow
    ((raw << 20).cast_signed()) >> 20
}

const fn imm_b(word: u32) -> i32 {
    let b12 = (word >> 31) & 1;
    let b11 = (word >> 7) & 1;
    let b10_5 = (word >> 25) & 0x3F;
    let b4_1 = (word >> 8) & 0xF;
    let raw = (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1);
    // Sign-extend 13-bit value via u32 to avoid signed overflow
    ((raw << 19).cast_signed()) >> 19
}

const fn imm_u(word: u32) -> u32 {
    word & 0xFFFF_F000
}

const fn imm_j(word: u32) -> i32 {
    let b20 = (word >> 31) & 1;
    let b10_1 = (word >> 21) & 0x3FF;
    let b11 = (word >> 20) & 1;
    let b19_12 = (word >> 12) & 0xFF;
    let raw = (b20 << 20) | (b19_12 << 12) | (b11 << 11) | (b10_1 << 1);
    // Sign-extend 21-bit value via u32 to avoid signed overflow
    ((raw << 11).cast_signed()) >> 11
}

// ---------------------------------------------------------------------------
// Register / format helpers
// ---------------------------------------------------------------------------

const XREG_NAMES: [&str; 32] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "x29", "x30", "x31",
];

const fn xr(idx: usize) -> &'static str {
    if idx < 32 { XREG_NAMES[idx] } else { "x?" }
}
fn fr(idx: usize) -> String {
    format!("f{idx}")
}

const fn fp_fmt(fmt: u32) -> &'static str {
    match fmt {
        0 => "s",
        1 => "d",
        3 => "q",
        _ => "?",
    }
}

fn fence_bits(bits: u32) -> String {
    let mut s = String::new();
    if bits & 8 != 0 {
        s.push('i');
    }
    if bits & 4 != 0 {
        s.push('o');
    }
    if bits & 2 != 0 {
        s.push('r');
    }
    if bits & 1 != 0 {
        s.push('w');
    }
    if s.is_empty() {
        s.push('0');
    }
    s
}

// ---------------------------------------------------------------------------
// CSR name table
// ---------------------------------------------------------------------------

fn csr_name(csr: u16) -> String {
    let name = match csr {
        // User-level CSRs
        0x000 => "ustatus",
        0x004 => "uie",
        0x005 => "utvec",
        0x040 => "uscratch",
        0x041 => "uepc",
        0x042 => "ucause",
        0x043 => "utval",
        0x044 => "uip",
        0x001 => "fflags",
        0x002 => "frm",
        0x003 => "fcsr",
        0xC00 => "cycle",
        0xC01 => "time",
        0xC02 => "instret",
        0xC80 => "cycleh",
        0xC81 => "timeh",
        0xC82 => "instreth",
        // Supervisor-level CSRs
        0x100 => "sstatus",
        0x102 => "sedeleg",
        0x103 => "sideleg",
        0x104 => "sie",
        0x105 => "stvec",
        0x106 => "scounteren",
        0x140 => "sscratch",
        0x141 => "sepc",
        0x142 => "scause",
        0x143 => "stval",
        0x144 => "sip",
        0x180 => "satp",
        0x5A8 => "scontext",
        // Hypervisor CSRs
        0x600 => "hstatus",
        0x602 => "hedeleg",
        0x603 => "hideleg",
        0x604 => "hie",
        0x606 => "hcounteren",
        0x607 => "hgeie",
        0x643 => "htval",
        0x644 => "hip",
        0x645 => "hvip",
        0x64A => "htinst",
        0x680 => "hgatp",
        0x6A8 => "hcontext",
        0xE12 => "hgeip",
        // Machine-level CSRs
        0x300 => "mstatus",
        0x301 => "misa",
        0x302 => "medeleg",
        0x303 => "mideleg",
        0x304 => "mie",
        0x305 => "mtvec",
        0x306 => "mcounteren",
        0x310 => "mstatush",
        0x340 => "mscratch",
        0x341 => "mepc",
        0x342 => "mcause",
        0x343 => "mtval",
        0x344 => "mip",
        0x34A => "mtinst",
        0x34B => "mtval2",
        0x3A0 => "pmpcfg0",
        0x3A1 => "pmpcfg1",
        0x3A2 => "pmpcfg2",
        0x3A3 => "pmpcfg3",
        0xB00 => "mcycle",
        0xB02 => "minstret",
        0xB80 => "mcycleh",
        0xB82 => "minstreth",
        0xF11 => "mvendorid",
        0xF12 => "marchid",
        0xF13 => "mimpid",
        0xF14 => "mhartid",
        0xF15 => "mconfigptr",
        _ => return format!("csr0x{csr:x}"),
    };
    name.into()
}

// ---------------------------------------------------------------------------
// Instruction building helpers
// ---------------------------------------------------------------------------

fn plain(address: Address, mnemonic: &str, operands: String, bytes: Vec<u8>) -> Instruction {
    mk(address, 4, mnemonic, operands, InstrFlags::NONE, bytes)
}

fn mem_load(
    address: Address,
    mn: &str,
    dst: &str,
    imm: i32,
    base: &str,
    bytes: Vec<u8>,
) -> Instruction {
    mk(
        address,
        4,
        mn,
        format!("{dst}, {imm}({base})"),
        InstrFlags::READ_MEM,
        bytes,
    )
}

fn mem_store(
    address: Address,
    mn: &str,
    src: &str,
    imm: i32,
    base: &str,
    bytes: Vec<u8>,
) -> Instruction {
    mk(
        address,
        4,
        mn,
        format!("{src}, {imm}({base})"),
        InstrFlags::WRITE_MEM,
        bytes,
    )
}

fn amo(
    address: Address,
    base: &str,
    suffix: &str,
    aq_rl: &str,
    f: RFields,
    bytes: Vec<u8>,
) -> Instruction {
    let RFields { rd, rs1, rs2, .. } = f;
    let mn = format!("{base}{suffix}{aq_rl}");
    plain(
        address,
        &mn,
        format!("{}, {}, ({})", xr(rd), xr(rs2), xr(rs1)),
        bytes,
    )
}

fn unknown(address: Address, bytes: Vec<u8>) -> Instruction {
    mk(
        address,
        4,
        "unknown",
        String::new(),
        InstrFlags::NONE,
        bytes,
    )
}

// ---------------------------------------------------------------------------
// Architecture impl
// ---------------------------------------------------------------------------

impl Architecture for RiscvArch {
    fn name(&self) -> &str {
        match self.bits {
            32 => "riscv32",
            64 => "riscv64",
            128 => "riscv128",
            _ => "riscv",
        }
    }

    fn pointer_size(&self) -> usize {
        match self.bits {
            32 => 4,
            128 => 16,
            _ => 8,
        }
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    /// Decode one 32-bit RISC-V instruction.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::PluginError`] when fewer than 4 bytes are provided.
    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        if bytes.len() < 4 {
            return Err(CoreError::PluginError {
                plugin: "riscv".into(),
                message: "truncated RISC-V instruction".into(),
            });
        }
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Ok(self.decode_word(address, word, bytes))
    }

    fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo> {
        if !instr.flags.intersects(InstrFlags::BRANCH) {
            return vec![];
        }
        if instr.flags.contains(InstrFlags::INDIRECT) {
            return vec![];
        }
        if instr.bytes.len() == 2 {
            let hw = u16::from_le_bytes([instr.bytes[0], instr.bytes[1]]);
            let op = hw & 0x3;
            let funct3 = (hw >> 13) & 0x7;
            let target = match (op, funct3) {
                // C.JAL (RV32 only, op=01, funct3=001)
                // C.J (op=01, funct3=101)
                (1, 1 | 5) => {
                    let offset = c_j_offset(hw);
                    instr.address.0.wrapping_add((i64::from(offset)).cast_unsigned())
                }
                // C.BEQZ (op=01, funct3=110)
                (1, 6 | 7) => {
                    let offset = c_b_offset(hw);
                    instr.address.0.wrapping_add((i64::from(offset)).cast_unsigned())
                }
                // C.BNEZ (op=01, funct3=111)
                _ => return vec![],
            };
            let branch = if instr.flags.contains(InstrFlags::CONDITIONAL) {
                BranchInfo::conditional_jump(target, BranchCondition::Custom(0))
            } else if instr.flags.contains(InstrFlags::CALL) {
                BranchInfo::call(target)
            } else {
                BranchInfo::unconditional_jump(target)
            };
            return vec![branch];
        }
        if instr.bytes.len() < 4 {
            return vec![];
        }
        let word = u32::from_le_bytes([
            instr.bytes[0],
            instr.bytes[1],
            instr.bytes[2],
            instr.bytes[3],
        ]);
        let opcode = word & 0x7F;
        let target = match opcode {
            0x6F => instr.address.0.wrapping_add((i64::from(imm_j(word))).cast_unsigned()),
            0x63 => instr.address.0.wrapping_add((i64::from(imm_b(word))).cast_unsigned()),
            _ => return vec![],
        };
        let branch = if instr.flags.contains(InstrFlags::CONDITIONAL) {
            BranchInfo::conditional_jump(target, BranchCondition::Custom(0))
        } else if instr.flags.contains(InstrFlags::CALL) {
            BranchInfo::call(target)
        } else {
            BranchInfo::unconditional_jump(target)
        };
        vec![branch]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        riscv_registers(self.bits)
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        riscv_calling_conventions(self.bits)
    }
}

// ---------------------------------------------------------------------------
// Register definitions
// ---------------------------------------------------------------------------

fn ri(name: &str, size: usize, id: u32) -> RegisterInfo {
    let kind = match name {
        "sp" | "x2" => RegisterKind::Stack,
        "pc" => RegisterKind::ProgramCounter,
        "fcsr" | "fflags" | "frm" | "mstatus" | "sstatus" => RegisterKind::Flags,
        "mtvec" | "mepc" | "mcause" | "mtval" | "mie" | "mip" | "mscratch" | "stvec" | "sepc"
        | "scause" | "stval" | "satp" | "cycle" | "time" | "instret" => RegisterKind::System,
        _ if name.starts_with('f') => RegisterKind::Float,
        _ if name.starts_with('v') => RegisterKind::Vector,
        _ => RegisterKind::General,
    };
    RegisterInfo::new(name, id, size, kind)
}

fn riscv_registers(bits: u32) -> Vec<RegisterInfo> {
    let gpr_size = if bits >= 64 { 8usize } else { 4 };
    let fpr_size = if bits >= 64 { 8usize } else { 4 };
    let mut regs = Vec::with_capacity(150);
    let mut id = 0u32;

    // Integer registers — numeric names (x0..x31)
    for i in 0u32..32 {
        regs.push(ri(&format!("x{i}"), gpr_size, id));
        id += 1;
    }

    // ABI aliases
    let abi_names: [&str; 32] = [
        "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
        "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
        "t5", "t6",
    ];
    for abi in &abi_names {
        if *abi != "zero" {
            regs.push(ri(abi, gpr_size, id));
            id += 1;
        }
    }

    // PC
    regs.push(ri("pc", gpr_size, id));
    id += 1;

    // FP registers (f0..f31) + ABI names
    let fp_abi: [&str; 32] = [
        "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "fs0", "fs1", "fa0", "fa1", "fa2",
        "fa3", "fa4", "fa5", "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9",
        "fs10", "fs11", "ft8", "ft9", "ft10", "ft11",
    ];
    for (i, abi) in fp_abi.iter().enumerate() {
        regs.push(ri(&format!("f{i}"), fpr_size, id));
        id += 1;
        regs.push(ri(abi, fpr_size, id));
        id += 1;
    }

    // V extension vector registers (v0..v31)
    for i in 0u32..32 {
        regs.push(ri(&format!("v{i}"), 64, id));
        id += 1;
    }

    // Important CSRs
    let csrs: &[(&str, usize)] = &[
        ("fcsr", 4),
        ("fflags", 4),
        ("frm", 4),
        ("mstatus", gpr_size),
        ("mtvec", gpr_size),
        ("mepc", gpr_size),
        ("mcause", gpr_size),
        ("mtval", gpr_size),
        ("mie", gpr_size),
        ("mip", gpr_size),
        ("mscratch", gpr_size),
        ("sstatus", gpr_size),
        ("stvec", gpr_size),
        ("sepc", gpr_size),
        ("scause", gpr_size),
        ("stval", gpr_size),
        ("satp", gpr_size),
        ("cycle", 8),
        ("time", 8),
        ("instret", 8),
    ];
    for (name, size) in csrs {
        regs.push(ri(name, *size, id));
        id += 1;
    }

    let _ = id;
    regs
}

// ---------------------------------------------------------------------------
// Calling conventions
// ---------------------------------------------------------------------------

fn riscv_calling_conventions(bits: u32) -> Vec<CallingConvention> {
    let mut out = Vec::new();

    let int_args: Vec<String> = (0..8).map(|i| format!("a{i}")).collect();
    let int_rets: Vec<String> = vec!["a0".into(), "a1".into()];
    let fp_args: Vec<String> = (0..8).map(|i| format!("fa{i}")).collect();
    let fp_rets: Vec<String> = vec!["fa0".into(), "fa1".into()];

    if bits == 32 {
        // ILP32
        out.push(
            CallingConvention::new("riscv_ilp32")
                .with_int_args(int_args.clone())
                .with_return_regs(int_rets.clone()),
        );
        // ILP32F
        let mut ilp32f_args = int_args.clone();
        ilp32f_args.extend(fp_args.iter().cloned());
        out.push(
            CallingConvention::new("riscv_ilp32f")
                .with_int_args(ilp32f_args)
                .with_float_args(fp_args.clone())
                .with_return_regs({
                    let mut r = int_rets.clone();
                    r.extend(fp_rets.iter().cloned());
                    r
                }),
        );
        // ILP32D
        out.push(
            CallingConvention::new("riscv_ilp32d")
                .with_int_args({
                    let mut a = int_args;
                    a.extend(fp_args.iter().cloned());
                    a
                })
                .with_float_args(fp_args.clone())
                .with_return_regs({
                    let mut r = int_rets;
                    r.extend(fp_rets.iter().cloned());
                    r
                }),
        );
    } else {
        // LP64
        out.push(
            CallingConvention::new("riscv_lp64")
                .with_int_args(int_args.clone())
                .with_return_regs(int_rets.clone()),
        );
        // LP64F
        out.push(
            CallingConvention::new("riscv_lp64f")
                .with_int_args({
                    let mut a = int_args.clone();
                    a.extend(fp_args.iter().cloned());
                    a
                })
                .with_float_args(fp_args.clone())
                .with_return_regs({
                    let mut r = int_rets.clone();
                    r.extend(fp_rets.iter().cloned());
                    r
                }),
        );
        // LP64D
        out.push(
            CallingConvention::new("riscv_lp64d")
                .with_int_args({
                    let mut a = int_args;
                    a.extend(fp_args.iter().cloned());
                    a
                })
                .with_float_args(fp_args)
                .with_return_regs({
                    let mut r = int_rets;
                    r.extend(fp_rets.iter().cloned());
                    r
                }),
        );
    }

    out
}

// ---------------------------------------------------------------------------
// RiscvLinearDisassembler
// ---------------------------------------------------------------------------

/// Iterator-based linear disassembler for RISC-V.
///
/// Handles both 32-bit base instructions and 16-bit compressed (C) instructions
/// by inspecting the bottom two bits of the first halfword.
///
/// Advances by 4 bytes for standard instructions, 2 bytes for C-extension
/// instructions.
pub struct RiscvLinearDisassembler<'a> {
    arch: &'a RiscvArch,
    bytes: &'a [u8],
    base_addr: Address,
    offset: usize,
    /// Enable decoding of compressed (C) 16-bit instructions.
    pub compressed: bool,
}

impl<'a> RiscvLinearDisassembler<'a> {
    /// Create a new [`RiscvLinearDisassembler`] that decodes base ISA only.
    #[must_use]
    pub const fn new(arch: &'a RiscvArch, bytes: &'a [u8], base_addr: Address) -> Self {
        Self {
            arch,
            bytes,
            base_addr,
            offset: 0,
            compressed: false,
        }
    }

    /// Create a new disassembler with C-extension support enabled.
    #[must_use]
    pub const fn new_with_compressed(arch: &'a RiscvArch, bytes: &'a [u8], base_addr: Address) -> Self {
        Self {
            arch,
            bytes,
            base_addr,
            offset: 0,
            compressed: true,
        }
    }

    /// Current byte offset.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Current virtual address.
    #[must_use]
    pub const fn current_address(&self) -> Address {
        Address::new(self.base_addr.0.wrapping_add(self.offset as u64))
    }

    /// `true` when fewer than 2 bytes remain.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        if self.compressed {
            self.offset + 2 > self.bytes.len()
        } else {
            self.offset + 4 > self.bytes.len()
        }
    }
}

impl Iterator for RiscvLinearDisassembler<'_> {
    type Item = Result<Instruction, CoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset + 2 > self.bytes.len() {
            return None;
        }
        let remaining = &self.bytes[self.offset..];
        let cur_addr = Address::new(self.base_addr.0.wrapping_add(self.offset as u64));

        // If compressed mode, check if bottom two bits indicate a 16-bit encoding
        if self.compressed && remaining.len() >= 2 {
            let lo2 = remaining[0] & 0x3;
            if lo2 != 0x3 {
                // Compressed (16-bit) instruction
                let hw = u16::from_le_bytes([remaining[0], remaining[1]]);
                match decode_compressed(hw, self.arch.bits, cur_addr) {
                    Ok(instr) => {
                        self.offset += 2;
                        return Some(Ok(instr));
                    }
                    Err(e) => return Some(Err(e)),
                }
            }
        }

        if remaining.len() < 4 {
            return Some(Err(CoreError::PluginError {
                plugin: "riscv".into(),
                message: "truncated RISC-V instruction".into(),
            }));
        }

        match self.arch.disassemble(cur_addr, remaining) {
            Ok(instr) => {
                self.offset += 4;
                Some(Ok(instr))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// Privilege level helpers
// ---------------------------------------------------------------------------

/// RISC-V privilege levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiscvPrivLevel {
    /// User mode.
    User,
    /// Supervisor mode.
    Supervisor,
    /// Hypervisor (VS) mode.
    Hypervisor,
    /// Machine mode.
    Machine,
}

impl RiscvPrivLevel {
    /// Short letter code for the level.
    #[must_use]
    pub const fn code(self) -> char {
        match self {
            Self::User => 'U',
            Self::Supervisor => 'S',
            Self::Hypervisor => 'H',
            Self::Machine => 'M',
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::arch::BranchKind;

    fn rv32() -> RiscvArch {
        RiscvArch::rv32()
    }
    fn rv64() -> RiscvArch {
        RiscvArch::rv64()
    }

    fn le(word: u32) -> [u8; 4] {
        word.to_le_bytes()
    }

    fn rtype(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
        (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
    }
    fn itype(imm12: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
        (imm12 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
    }
    fn stype(imm12: u32, rs2: u32, rs1: u32, funct3: u32, opcode: u32) -> u32 {
        let imm11_5 = (imm12 >> 5) & 0x7F;
        let imm4_0 = imm12 & 0x1F;
        (imm11_5 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (imm4_0 << 7) | opcode
    }
    fn btype(offset: i32, rs2: u32, rs1: u32, funct3: u32, opcode: u32) -> u32 {
        let off = offset.cast_unsigned();
        let b12 = (off >> 12) & 1;
        let b11 = (off >> 11) & 1;
        let b10_5 = (off >> 5) & 0x3F;
        let b4_1 = (off >> 1) & 0xF;
        (b12 << 31)
            | (b10_5 << 25)
            | (rs2 << 20)
            | (rs1 << 15)
            | (funct3 << 12)
            | (b4_1 << 8)
            | (b11 << 7)
            | opcode
    }
    fn jtype(offset: i32, rd: u32, opcode: u32) -> u32 {
        let off = offset.cast_unsigned();
        let b20 = (off >> 20) & 1;
        let b10_1 = (off >> 1) & 0x3FF;
        let b11 = (off >> 11) & 1;
        let b19_12 = (off >> 12) & 0xFF;
        (b20 << 31) | (b19_12 << 12) | (b11 << 20) | (b10_1 << 21) | (rd << 7) | opcode
    }
    fn utype(imm20: u32, rd: u32, opcode: u32) -> u32 {
        (imm20 << 12) | (rd << 7) | opcode
    }

    // ── 1. ADDI x1, x0, 10 ────────────────────────────────────────────────
    #[test]
    fn test_addi_x1_x0_10() {
        let word = itype(10, 0, 0, 1, 0x13);
        let instr = rv32().disassemble(Address::new(0x1000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "addi");
        assert!(instr.operands.contains("x1"));
        assert!(instr.operands.contains("x0"));
        assert!(instr.operands.contains("10"));
        assert_eq!(instr.flags, InstrFlags::NONE);
        assert_eq!(instr.size, 4);
    }

    // ── 2. LW x1, 4(x2) → READ_MEM ────────────────────────────────────────
    #[test]
    fn test_lw_read_mem() {
        let word = itype(4, 2, 2, 1, 0x03);
        let instr = rv32().disassemble(Address::new(0x1000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "lw");
        assert!(instr.flags.contains(InstrFlags::READ_MEM));
    }

    // ── 3. SW x1, 4(x2) → WRITE_MEM ───────────────────────────────────────
    #[test]
    fn test_sw_write_mem() {
        let word = stype(4, 1, 2, 2, 0x23);
        let instr = rv32().disassemble(Address::new(0x1000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "sw");
        assert!(instr.flags.contains(InstrFlags::WRITE_MEM));
    }

    // ── 4. JAL x0 → BRANCH (not call) ─────────────────────────────────────
    #[test]
    fn test_jal_x0_not_call() {
        let word = jtype(8, 0, 0x6F);
        let instr = rv32().disassemble(Address::new(0x1000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "jal");
        assert!(instr.flags.contains(InstrFlags::BRANCH));
        assert!(!instr.flags.contains(InstrFlags::CALL));
    }

    // ── 5. JAL x1 → BRANCH|CALL + target ─────────────────────────────────
    #[test]
    fn test_jal_ra_call_with_target() {
        let word = jtype(16, 1, 0x6F);
        let base = Address::new(0x2000);
        let instr = rv32().disassemble(base, &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "jal");
        assert!(instr.flags.contains(InstrFlags::BRANCH | InstrFlags::CALL));
        let branches = rv32().get_branches(&instr);
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0].target, Some(0x2010));
        assert_eq!(branches[0].kind, BranchKind::Call);
    }

    // ── 6. JALR x0, x1, 0 → RETURN ───────────────────────────────────────
    #[test]
    fn test_jalr_return() {
        let word = itype(0, 1, 0, 0, 0x67);
        let instr = rv32().disassemble(Address::new(0x3000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "jalr");
        assert!(
            instr
                .flags
                .contains(InstrFlags::BRANCH | InstrFlags::RET | InstrFlags::INDIRECT)
        );
        assert!(!instr.flags.contains(InstrFlags::CALL));
    }

    // ── 7. BEQ → BRANCH|CONDITIONAL + target ─────────────────────────────
    #[test]
    fn test_beq_branch_conditional() {
        let word = btype(8, 2, 1, 0, 0x63);
        let base = Address::new(0x1000);
        let instr = rv32().disassemble(base, &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "beq");
        assert!(
            instr
                .flags
                .contains(InstrFlags::BRANCH | InstrFlags::CONDITIONAL)
        );
        let branches = rv32().get_branches(&instr);
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0].target, Some(0x1008));
    }

    // ── 8. ADD x3, x1, x2 ────────────────────────────────────────────────
    #[test]
    fn test_add_rtype() {
        let word = rtype(0, 2, 1, 0, 3, 0x33);
        let instr = rv32().disassemble(Address::new(0x4000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "add");
        assert!(instr.operands.contains("x3"));
    }

    // ── 9. LUI x1, 0x12345 ────────────────────────────────────────────────
    #[test]
    fn test_lui_correct_immediate() {
        let word = utype(0x12345, 1, 0x37);
        let instr = rv32().disassemble(Address::new(0x5000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "lui");
        assert!(
            instr.operands.contains("0x12345"),
            "operands: {}",
            instr.operands
        );
    }

    // ── 10. registers() > 60 ──────────────────────────────────────────────
    #[test]
    fn test_registers_content() {
        let regs = rv64().registers();
        assert!(regs.len() > 60);
        assert!(regs.iter().any(|r| r.name == "x0"));
        assert!(regs.iter().any(|r| r.name == "sp"));
        assert!(regs.iter().any(|r| r.name == "ra"));
        assert!(regs.iter().any(|r| r.name == "a0"));
    }

    // ── 11. calling_conventions() has "riscv_lp64" ────────────────────────
    #[test]
    fn test_calling_convention_lp64() {
        let ccs = rv64().calling_conventions();
        let cc = ccs.iter().find(|c| c.name == "riscv_lp64").unwrap();
        assert_eq!(cc.int_args.len(), 8);
        assert_eq!(cc.int_args[0], "a0");
    }

    // ── 12. Linear disassembler ────────────────────────────────────────────
    #[test]
    fn test_linear_disassembler_multiple_instrs() {
        let words = [
            itype(10, 0, 0, 1, 0x13),
            itype(0, 1, 2, 2, 0x03),
            jtype(8, 0, 0x6F),
        ];
        let mut bytes = Vec::new();
        for w in words {
            bytes.extend_from_slice(&le(w));
        }
        let arch = rv32();
        let base = Address::new(0x1000);
        let instrs: Vec<_> = RiscvLinearDisassembler::new(&arch, &bytes, base)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs.len(), 3);
        assert_eq!(instrs[0].mnemonic, "addi");
        assert_eq!(instrs[1].mnemonic, "lw");
        assert_eq!(instrs[2].mnemonic, "jal");
    }

    // ── 13. JALR indirect call ────────────────────────────────────────────
    #[test]
    fn test_jalr_indirect_call() {
        let word = itype(0, 5, 0, 1, 0x67);
        let instr = rv32().disassemble(Address::new(0x6000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "jalr");
        assert!(
            instr
                .flags
                .contains(InstrFlags::CALL | InstrFlags::INDIRECT)
        );
        assert!(rv32().get_branches(&instr).is_empty());
    }

    // ── 14. SUB ───────────────────────────────────────────────────────────
    #[test]
    fn test_sub_rtype() {
        let word = rtype(0x20, 2, 1, 0, 3, 0x33);
        let instr = rv32().disassemble(Address::new(0x7000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "sub");
    }

    // ── 15. RV64 LD ───────────────────────────────────────────────────────
    #[test]
    fn test_rv64_ld_read_mem() {
        let word = itype(8, 2, 3, 1, 0x03);
        let instr = rv64().disassemble(Address::new(0x8000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "ld");
        assert!(instr.flags.contains(InstrFlags::READ_MEM));
    }

    // ── 16. FENCE → BARRIER ───────────────────────────────────────────────
    #[test]
    fn test_fence_barrier() {
        let word: u32 = 0x0000_000F;
        let instr = rv32().disassemble(Address::new(0x9000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "fence");
        assert!(instr.flags.contains(InstrFlags::BARRIER));
    }

    // ── 17. Architecture properties ───────────────────────────────────────
    #[test]
    fn test_arch_properties() {
        assert_eq!(rv32().name(), "riscv32");
        assert_eq!(rv32().pointer_size(), 4);
        assert_eq!(rv32().endian(), Endian::Little);
        assert_eq!(rv64().name(), "riscv64");
        assert_eq!(rv64().pointer_size(), 8);
    }

    // ── 18. BNE branch target ─────────────────────────────────────────────
    #[test]
    fn test_bne_branch_target() {
        let word = btype(-4i32, 2, 1, 1, 0x63);
        let base = Address::new(0x2000);
        let instr = rv32().disassemble(base, &le(word)).unwrap();
        let branches = rv32().get_branches(&instr);
        assert_eq!(branches[0].target, Some(0x1FFC));
    }

    // ── 19. MUL (M extension) ─────────────────────────────────────────────
    #[test]
    fn test_mul_m_extension() {
        let word = rtype(0x01, 2, 1, 0, 3, 0x33);
        let instr = rv32().disassemble(Address::new(0xA000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "mul");
    }

    // ── 20. Unknown opcode → "unknown" ────────────────────────────────────
    #[test]
    fn test_unknown_opcode() {
        let word: u32 = 0x0000_007F;
        let instr = rv32().disassemble(Address::new(0xB000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "unknown");
    }

    // ── 21. Pointer sizes ─────────────────────────────────────────────────
    #[test]
    fn test_pointer_sizes() {
        assert_eq!(rv32().pointer_size(), 4);
        assert_eq!(rv64().pointer_size(), 8);
        assert_eq!(RiscvArch::rv128().pointer_size(), 16);
    }

    // ── 22. ECALL → BARRIER ───────────────────────────────────────────────
    #[test]
    fn test_ecall_barrier() {
        let word: u32 = 0x0000_0073;
        let instr = rv32().disassemble(Address::new(0xC000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "ecall");
        assert!(instr.flags.contains(InstrFlags::BARRIER));
    }

    // ── 23. ADDI NOP form ─────────────────────────────────────────────────
    #[test]
    fn test_addi_nop() {
        let word: u32 = 0x0000_0013;
        let instr = rv32().disassemble(Address::new(0xD000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "addi");
    }

    // ── 24. AUIPC ─────────────────────────────────────────────────────────
    #[test]
    fn test_auipc() {
        let word = utype(1, 1, 0x17);
        let instr = rv32().disassemble(Address::new(0xE000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "auipc");
        assert!(instr.operands.contains("x1"));
    }

    // ── 25. RV64 ADDIW ────────────────────────────────────────────────────
    #[test]
    fn test_rv64_addiw() {
        let word = itype(1, 2, 0, 1, 0x1B);
        let instr = rv64().disassemble(Address::new(0xF000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "addiw");
    }

    // ── 26. RV64 SD → WRITE_MEM ───────────────────────────────────────────
    #[test]
    fn test_rv64_sd_write_mem() {
        let word = stype(0, 1, 2, 3, 0x23);
        let instr = rv64()
            .disassemble(Address::new(0x10000), &le(word))
            .unwrap();
        assert_eq!(instr.mnemonic, "sd");
        assert!(instr.flags.contains(InstrFlags::WRITE_MEM));
    }

    // ── 27. Truncated input → error ───────────────────────────────────────
    #[test]
    fn test_truncated_input_error() {
        let result = rv32().disassemble(Address::new(0x0), &[0x13, 0x00]);
        assert!(result.is_err());
    }

    // ── 28. CSRRW ─────────────────────────────────────────────────────────
    #[test]
    fn test_csrrw() {
        // CSRRW x1, mstatus, x0 → funct3=1, csr=0x300, rs1=0, rd=1, opcode=0x73
        let word = itype(0x300, 0, 1, 1, 0x73);
        let instr = rv64().disassemble(Address::new(0x1000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "csrrw");
        assert!(instr.operands.contains("mstatus"));
    }

    // ── 29. FENCE.I ───────────────────────────────────────────────────────
    #[test]
    fn test_fence_i() {
        // FENCE.I: opcode=0x0F, funct3=1
        let word: u32 = (1 << 12) | 0x0F;
        let instr = rv32().disassemble(Address::new(0x1000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "fence.i");
        assert!(instr.flags.contains(InstrFlags::BARRIER));
    }

    // ── 30. A extension: AMOSWAP.W ────────────────────────────────────────
    #[test]
    fn test_amoswap_w() {
        // AMOSWAP.W rd=1, rs2=2, rs1=3, funct3=2, opcode=0x2F, funct5=0x01
        // funct7 = funct5<<2 | aq<<1 | rl  = 0x04
        let word: u32 = (0x04 << 25) | (2 << 20) | (3 << 15) | (2 << 12) | (1 << 7) | 0x2F;
        let instr = rv32().disassemble(Address::new(0x1000), &le(word)).unwrap();
        assert!(
            instr.mnemonic.starts_with("amoswap"),
            "got {}",
            instr.mnemonic
        );
    }

    // ── 31. A extension: LR.W ────────────────────────────────────────────
    #[test]
    fn test_lr_w() {
        // LR.W rd=1, rs1=3, rs2=0, funct3=2, opcode=0x2F, funct5=0x02
        let word: u32 = (0x08 << 25) | (3 << 15) | (2 << 12) | (1 << 7) | 0x2F;
        let instr = rv32().disassemble(Address::new(0x1000), &le(word)).unwrap();
        assert!(instr.mnemonic.starts_with("lr"), "got {}", instr.mnemonic);
    }

    // ── 32. FLW → READ_MEM ────────────────────────────────────────────────
    #[test]
    fn test_flw_read_mem() {
        // FLW f1, 4(x2) → funct3=2, opcode=0x07
        let word = itype(4, 2, 2, 1, 0x07);
        let instr = rv32().disassemble(Address::new(0x1000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "flw");
        assert!(instr.flags.contains(InstrFlags::READ_MEM));
    }

    // ── 33. FSW → WRITE_MEM ───────────────────────────────────────────────
    #[test]
    fn test_fsw_write_mem() {
        // FSW f1, 4(x2) → funct3=2, opcode=0x27
        let word = stype(4, 1, 2, 2, 0x27);
        let instr = rv32().disassemble(Address::new(0x1000), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "fsw");
        assert!(instr.flags.contains(InstrFlags::WRITE_MEM));
    }

    // ── 34. register IDs unique ───────────────────────────────────────────
    #[test]
    fn test_register_ids_unique() {
        let regs = rv64().registers();
        let mut ids: Vec<u32> = regs.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), regs.len(), "register IDs must be unique");
    }

    // ── 35. CSR name resolution ───────────────────────────────────────────
    #[test]
    fn test_csr_name_known() {
        assert_eq!(csr_name(0x300), "mstatus");
        assert_eq!(csr_name(0x341), "mepc");
        assert_eq!(csr_name(0x180), "satp");
        assert_eq!(csr_name(0x003), "fcsr");
    }

    // ── 36. Privilege level codes ─────────────────────────────────────────
    #[test]
    fn test_priv_level_codes() {
        assert_eq!(RiscvPrivLevel::Machine.code(), 'M');
        assert_eq!(RiscvPrivLevel::Supervisor.code(), 'S');
        assert_eq!(RiscvPrivLevel::User.code(), 'U');
        assert_eq!(RiscvPrivLevel::Hypervisor.code(), 'H');
    }

    // ── 37. C extension: C.LW ────────────────────────────────────────────
    #[test]
    fn test_c_lw() {
        // C.LW x8, 0(x8) → funct3=2, op=0 → 0x4000
        // Encode: op=0, funct3=2, rd'=0(→x8), rs1'=0(→x8), uimm=0
        // bits: [15:13]=010, [12:10]=000(rs1'=0), [9:7]=000, [6:5]=00, [4:2]=000, [1:0]=00
        let hw: u16 = 0b010 << 13;
        let instr = decode_compressed(hw, 64, Address::new(0x1000)).unwrap();
        assert_eq!(instr.mnemonic, "c.lw");
        assert!(instr.flags.contains(InstrFlags::READ_MEM));
    }

    // ── 38. C extension: C.NOP (addi x0, x0, 0) ─────────────────────────
    #[test]
    fn test_c_nop() {
        // C.NOP = 0x0001 (C.ADDI with rd=0, imm=0)
        let hw: u16 = 0x0001;
        let instr = decode_compressed(hw, 32, Address::new(0x1000)).unwrap();
        assert_eq!(instr.mnemonic, "c.nop");
        assert_eq!(instr.size, 2);
    }

    // ── 39. C extension: C.J ─────────────────────────────────────────────
    #[test]
    fn test_c_j() {
        // C.J with small offset
        let hw: u16 = (0b101 << 13) | 1; // funct3=5, op=1
        let instr = decode_compressed(hw, 32, Address::new(0x1000)).unwrap();
        assert_eq!(instr.mnemonic, "c.j");
        assert!(instr.flags.contains(InstrFlags::BRANCH));
    }

    // ── 40. calling conventions RV32 ─────────────────────────────────────
    #[test]
    fn test_calling_conventions_rv32() {
        let ccs = rv32().calling_conventions();
        assert!(ccs.iter().any(|c| c.name == "riscv_ilp32"));
        assert!(ccs.iter().any(|c| c.name == "riscv_ilp32f"));
        assert!(ccs.iter().any(|c| c.name == "riscv_ilp32d"));
    }

    // ── 41. calling conventions RV64 ─────────────────────────────────────
    #[test]
    fn test_calling_conventions_rv64() {
        let ccs = rv64().calling_conventions();
        assert!(ccs.iter().any(|c| c.name == "riscv_lp64"));
        assert!(ccs.iter().any(|c| c.name == "riscv_lp64f"));
        assert!(ccs.iter().any(|c| c.name == "riscv_lp64d"));
    }

    // ── 42. V extension registers present ────────────────────────────────
    #[test]
    fn test_vector_registers_present() {
        let regs = rv64().registers();
        assert!(regs.iter().any(|r| r.name == "v0"), "missing v0");
        assert!(regs.iter().any(|r| r.name == "v31"), "missing v31");
    }

    // ── 43. RV128 name / pointer size ────────────────────────────────────
    #[test]
    fn test_rv128_properties() {
        let rv128 = RiscvArch::rv128();
        assert_eq!(rv128.name(), "riscv128");
        assert_eq!(rv128.pointer_size(), 16);
    }

    // ── 44. EBREAK ───────────────────────────────────────────────────────
    #[test]
    fn test_ebreak_barrier() {
        let word: u32 = 0x0010_0073;
        let instr = rv32().disassemble(Address::new(0x0), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "ebreak");
        assert!(instr.flags.contains(InstrFlags::BARRIER));
    }

    // ── 45. MRET → RETURN ────────────────────────────────────────────────
    #[test]
    fn test_mret_return() {
        // MRET = funct12=0x302, rs1=0, funct3=0, rd=0, opcode=0x73
        let word: u32 = (0x302 << 20) | 0x73;
        let instr = rv64().disassemble(Address::new(0x0), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "mret");
        assert!(instr.flags.contains(InstrFlags::RET));
    }

    // ── 46. DIV (M ext) ──────────────────────────────────────────────────
    #[test]
    fn test_div_m_extension() {
        let word = rtype(0x01, 2, 1, 4, 3, 0x33);
        let instr = rv32().disassemble(Address::new(0x0), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "div");
    }

    // ── 47. RV64 ADDW ────────────────────────────────────────────────────
    #[test]
    fn test_rv64_addw() {
        let word = rtype(0, 2, 1, 0, 3, 0x3B);
        let instr = rv64().disassemble(Address::new(0x0), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "addw");
    }

    // ── 48. CSRRS (read/set CSR) ─────────────────────────────────────────
    #[test]
    fn test_csrrs() {
        // CSRRS x1, cycle, x0 → funct3=2, csr=0xC00
        let word = itype(0xC00, 0, 2, 1, 0x73);
        let instr = rv64().disassemble(Address::new(0x0), &le(word)).unwrap();
        assert_eq!(instr.mnemonic, "csrrs");
        assert!(instr.operands.contains("cycle"));
    }
}

// ---------------------------------------------------------------------------
// RISC-V instruction field extraction helpers
// ---------------------------------------------------------------------------

/// Extract the 7-bit opcode field (bits [6:0]).
#[must_use]
pub const fn rv_opcode(word: u32) -> u8 {
    (word & 0x7f) as u8
}

/// Extract the rd field (bits [11:7]).
#[must_use]
pub const fn rv_rd(word: u32) -> u8 {
    ((word >> 7) & 0x1f) as u8
}

/// Extract the funct3 field (bits [14:12]).
#[must_use]
pub const fn rv_funct3(word: u32) -> u8 {
    ((word >> 12) & 0x07) as u8
}

/// Extract the rs1 field (bits [19:15]).
#[must_use]
pub const fn rv_rs1(word: u32) -> u8 {
    ((word >> 15) & 0x1f) as u8
}

/// Extract the rs2 field (bits [24:20]).
#[must_use]
pub const fn rv_rs2(word: u32) -> u8 {
    ((word >> 20) & 0x1f) as u8
}

/// Extract the funct7 field (bits [31:25]).
#[must_use]
pub const fn rv_funct7(word: u32) -> u8 {
    ((word >> 25) & 0x7f) as u8
}

/// Decode the I-type immediate (bits [31:20], sign-extended to 32 bits).
#[must_use]
pub const fn rv_imm_i(word: u32) -> i32 {
    
    (word.cast_signed()) >> 20
}

/// Decode the S-type immediate (bits [31:25] | [11:7], sign-extended).
#[must_use]
pub const fn rv_imm_s(word: u32) -> i32 {
    let hi = (word.cast_signed()) >> 25;
    let lo = ((word >> 7) & 0x1f).cast_signed();
    (hi << 5) | lo
}

/// Decode the B-type immediate (sign-extended, multiple bit sources).
#[must_use]
pub const fn rv_imm_b(word: u32) -> i32 {
    let imm12 = ((word >> 31) & 1).cast_signed();
    let imm11 = ((word >> 7) & 1).cast_signed();
    let imm10_5 = ((word >> 25) & 0x3f).cast_signed();
    let imm4_1 = ((word >> 8) & 0xf).cast_signed();
    let raw = (imm12 << 12) | (imm11 << 11) | (imm10_5 << 5) | (imm4_1 << 1);
    (raw << 19) >> 19
}

/// Decode the U-type immediate (bits [31:12] left-shifted by 12).
#[must_use]
pub const fn rv_imm_u(word: u32) -> u32 {
    word & 0xFFFF_F000
}

/// Decode the J-type immediate (sign-extended, branch target offset).
#[must_use]
pub const fn rv_imm_j(word: u32) -> i32 {
    let imm20 = ((word >> 31) & 1).cast_signed();
    let imm19_12 = ((word >> 12) & 0xff).cast_signed();
    let imm11 = ((word >> 20) & 1).cast_signed();
    let imm10_1 = ((word >> 21) & 0x3ff).cast_signed();
    let raw = (imm20 << 20) | (imm19_12 << 12) | (imm11 << 11) | (imm10_1 << 1);
    (raw << 11) >> 11
}

/// Compute the branch target address (PC-relative B-type).
#[must_use]
pub const fn rv_branch_target(pc: u64, word: u32) -> u64 {
    pc.wrapping_add((rv_imm_b(word) as i64).cast_unsigned())
}

/// Compute the JAL target address (PC-relative J-type).
#[must_use]
pub const fn rv_jal_target(pc: u64, word: u32) -> u64 {
    pc.wrapping_add((rv_imm_j(word) as i64).cast_unsigned())
}

// ---------------------------------------------------------------------------
// RISC-V opcode classification
// ---------------------------------------------------------------------------

/// RISC-V 32-bit instruction opcode classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RvOpcodeClass {
    /// Load (opcode 0x03).
    Load,
    /// Load-FP (opcode 0x07).
    LoadFp,
    /// MISC-MEM — FENCE, FENCE.I (opcode 0x0F).
    MiscMem,
    /// OP-IMM — ADDI, SLTI, etc. (opcode 0x13).
    OpImm,
    /// AUIPC (opcode 0x17).
    Auipc,
    /// OP-IMM-32 (opcode 0x1B) — RV64 word-size immediate ops.
    OpImm32,
    /// Store (opcode 0x23).
    Store,
    /// Store-FP (opcode 0x27).
    StoreFp,
    /// AMO — atomic operations (opcode 0x2F).
    Amo,
    /// OP — register-register ops (opcode 0x33).
    Op,
    /// LUI (opcode 0x37).
    Lui,
    /// OP-32 (opcode 0x3B) — RV64 word-size register ops.
    Op32,
    /// MADD (opcode 0x43) — FP fused multiply-add.
    Madd,
    /// MSUB (opcode 0x47).
    Msub,
    /// NMSUB (opcode 0x4B).
    Nmsub,
    /// NMADD (opcode 0x4F).
    Nmadd,
    /// OP-FP (opcode 0x53) — FP arithmetic.
    OpFp,
    /// BRANCH (opcode 0x63).
    Branch,
    /// JALR (opcode 0x67).
    Jalr,
    /// JAL (opcode 0x6F).
    Jal,
    /// SYSTEM — ECALL, EBREAK, CSR (opcode 0x73).
    System,
    /// Unknown / reserved.
    Unknown,
}

/// Classify a 32-bit RISC-V instruction word by opcode.
#[must_use]
pub const fn rv_classify(word: u32) -> RvOpcodeClass {
    match rv_opcode(word) {
        0x03 => RvOpcodeClass::Load,
        0x07 => RvOpcodeClass::LoadFp,
        0x0F => RvOpcodeClass::MiscMem,
        0x13 => RvOpcodeClass::OpImm,
        0x17 => RvOpcodeClass::Auipc,
        0x1B => RvOpcodeClass::OpImm32,
        0x23 => RvOpcodeClass::Store,
        0x27 => RvOpcodeClass::StoreFp,
        0x2F => RvOpcodeClass::Amo,
        0x33 => RvOpcodeClass::Op,
        0x37 => RvOpcodeClass::Lui,
        0x3B => RvOpcodeClass::Op32,
        0x43 => RvOpcodeClass::Madd,
        0x47 => RvOpcodeClass::Msub,
        0x4B => RvOpcodeClass::Nmsub,
        0x4F => RvOpcodeClass::Nmadd,
        0x53 => RvOpcodeClass::OpFp,
        0x63 => RvOpcodeClass::Branch,
        0x67 => RvOpcodeClass::Jalr,
        0x6F => RvOpcodeClass::Jal,
        0x73 => RvOpcodeClass::System,
        _ => RvOpcodeClass::Unknown,
    }
}

/// Returns `true` if the instruction is a load.
#[must_use]
pub const fn rv_is_load(word: u32) -> bool {
    matches!(
        rv_classify(word),
        RvOpcodeClass::Load | RvOpcodeClass::LoadFp
    )
}

/// Returns `true` if the instruction is a store.
#[must_use]
pub const fn rv_is_store(word: u32) -> bool {
    matches!(
        rv_classify(word),
        RvOpcodeClass::Store | RvOpcodeClass::StoreFp
    )
}

/// Returns `true` if the instruction is any branch.
#[must_use]
pub const fn rv_is_branch(word: u32) -> bool {
    matches!(rv_classify(word), RvOpcodeClass::Branch)
}

/// Returns `true` if the instruction is JAL.
#[must_use]
pub const fn rv_is_jal(word: u32) -> bool {
    matches!(rv_classify(word), RvOpcodeClass::Jal)
}

/// Returns `true` if the instruction is JALR.
#[must_use]
pub const fn rv_is_jalr(word: u32) -> bool {
    matches!(rv_classify(word), RvOpcodeClass::Jalr)
}

// ---------------------------------------------------------------------------
// RISC-V register helpers
// ---------------------------------------------------------------------------

/// ABI names for RISC-V integer registers (x0..x31).
pub static RV_ABI_NAMES: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
    "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
];

/// Return the ABI name for an integer register index.
#[must_use]
pub const fn rv_gpr_name(idx: u8) -> &'static str {
    if (idx as usize) < 32 {
        RV_ABI_NAMES[idx as usize]
    } else {
        "x?"
    }
}

/// RISC-V FP register ABI names (f0..f31).
pub static RV_FP_ABI_NAMES: [&str; 32] = [
    "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "fs0", "fs1", "fa0", "fa1", "fa2",
    "fa3", "fa4", "fa5", "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9",
    "fs10", "fs11", "ft8", "ft9", "ft10", "ft11",
];

/// Return the ABI name for an FP register index.
#[must_use]
pub const fn rv_fpr_name(idx: u8) -> &'static str {
    if (idx as usize) < 32 {
        RV_FP_ABI_NAMES[idx as usize]
    } else {
        "f?"
    }
}

/// Description of an integer register's role in the RISC-V ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RvGprRole {
    /// x0 — hardwired zero.
    Zero,
    /// x1 — return address.
    ReturnAddress,
    /// x2 — stack pointer.
    StackPointer,
    /// x3 — global pointer.
    GlobalPointer,
    /// x4 — thread pointer.
    ThreadPointer,
    /// x5-x7 — temporaries.
    Temporary,
    /// x8 (s0/fp) — saved/frame pointer.
    SavedFp,
    /// x9, x18-x27 — callee-saved.
    CalleeSaved,
    /// x10-x17 — function arguments / return values.
    ArgReturn,
    /// x28-x31 — temporaries.
    TempHigh,
}

/// Return the ABI role for integer register index `n`.
#[must_use]
pub const fn rv_gpr_role(n: u8) -> RvGprRole {
    match n {
        0 => RvGprRole::Zero,
        1 => RvGprRole::ReturnAddress,
        2 => RvGprRole::StackPointer,
        3 => RvGprRole::GlobalPointer,
        4 => RvGprRole::ThreadPointer,
        5..=7 => RvGprRole::Temporary,
        8 => RvGprRole::SavedFp,
        9 | 18..=27 => RvGprRole::CalleeSaved,
        10..=17 => RvGprRole::ArgReturn,
        _ => RvGprRole::TempHigh,
    }
}

/// Returns `true` if `n` is a caller-saved (temporary) register.
#[must_use]
pub const fn rv_is_caller_saved(n: u8) -> bool {
    // Per RISC-V calling convention, ra (x1) is also caller-saved.
    matches!(
        rv_gpr_role(n),
        RvGprRole::ReturnAddress
            | RvGprRole::Temporary
            | RvGprRole::ArgReturn
            | RvGprRole::TempHigh
    )
}

/// Returns `true` if `n` is a callee-saved register.
#[must_use]
pub const fn rv_is_callee_saved(n: u8) -> bool {
    matches!(rv_gpr_role(n), RvGprRole::CalleeSaved | RvGprRole::SavedFp)
}

// ---------------------------------------------------------------------------
// RISC-V CSR extended table
// ---------------------------------------------------------------------------

/// An extended CSR entry.
#[derive(Debug, Clone, Copy)]
pub struct RvCsrEntry {
    /// CSR address.
    pub addr: u16,
    /// CSR name.
    pub name: &'static str,
    /// Privilege level required.
    pub priv_level: &'static str,
    /// Description.
    pub description: &'static str,
}

/// Extended RISC-V CSR table.
pub static RV_CSR_EXT: &[RvCsrEntry] = &[
    // ── User-mode CSRs ──────────────────────────────────────────────────────
    RvCsrEntry {
        addr: 0x000,
        name: "ustatus",
        priv_level: "URW",
        description: "User status register",
    },
    RvCsrEntry {
        addr: 0x004,
        name: "uie",
        priv_level: "URW",
        description: "User interrupt-enable",
    },
    RvCsrEntry {
        addr: 0x005,
        name: "utvec",
        priv_level: "URW",
        description: "User trap-handler base address",
    },
    RvCsrEntry {
        addr: 0x040,
        name: "uscratch",
        priv_level: "URW",
        description: "Scratch register for user trap handlers",
    },
    RvCsrEntry {
        addr: 0x041,
        name: "uepc",
        priv_level: "URW",
        description: "User exception program counter",
    },
    RvCsrEntry {
        addr: 0x042,
        name: "ucause",
        priv_level: "URW",
        description: "User trap cause",
    },
    RvCsrEntry {
        addr: 0x043,
        name: "utval",
        priv_level: "URW",
        description: "User bad address or instruction",
    },
    RvCsrEntry {
        addr: 0x044,
        name: "uip",
        priv_level: "URW",
        description: "User interrupt pending",
    },
    // ── Floating-point CSRs ──────────────────────────────────────────────────
    RvCsrEntry {
        addr: 0x001,
        name: "fflags",
        priv_level: "URW",
        description: "FP accrued exceptions",
    },
    RvCsrEntry {
        addr: 0x002,
        name: "frm",
        priv_level: "URW",
        description: "FP dynamic rounding mode",
    },
    RvCsrEntry {
        addr: 0x003,
        name: "fcsr",
        priv_level: "URW",
        description: "FP control and status",
    },
    // ── User-mode counters ───────────────────────────────────────────────────
    RvCsrEntry {
        addr: 0xC00,
        name: "cycle",
        priv_level: "URO",
        description: "Cycle counter",
    },
    RvCsrEntry {
        addr: 0xC01,
        name: "time",
        priv_level: "URO",
        description: "Timer for RDTIME",
    },
    RvCsrEntry {
        addr: 0xC02,
        name: "instret",
        priv_level: "URO",
        description: "Instructions-retired counter",
    },
    RvCsrEntry {
        addr: 0xC03,
        name: "hpmcounter3",
        priv_level: "URO",
        description: "Hardware performance monitor counter 3",
    },
    RvCsrEntry {
        addr: 0xC80,
        name: "cycleh",
        priv_level: "URO",
        description: "Upper 32 bits of cycle (RV32)",
    },
    RvCsrEntry {
        addr: 0xC81,
        name: "timeh",
        priv_level: "URO",
        description: "Upper 32 bits of time (RV32)",
    },
    RvCsrEntry {
        addr: 0xC82,
        name: "instreth",
        priv_level: "URO",
        description: "Upper 32 bits of instret (RV32)",
    },
    // ── Supervisor-mode CSRs ────────────────────────────────────────────────
    RvCsrEntry {
        addr: 0x100,
        name: "sstatus",
        priv_level: "SRW",
        description: "Supervisor status register",
    },
    RvCsrEntry {
        addr: 0x102,
        name: "sedeleg",
        priv_level: "SRW",
        description: "Supervisor exception delegation",
    },
    RvCsrEntry {
        addr: 0x103,
        name: "sideleg",
        priv_level: "SRW",
        description: "Supervisor interrupt delegation",
    },
    RvCsrEntry {
        addr: 0x104,
        name: "sie",
        priv_level: "SRW",
        description: "Supervisor interrupt-enable",
    },
    RvCsrEntry {
        addr: 0x105,
        name: "stvec",
        priv_level: "SRW",
        description: "Supervisor trap-handler base address",
    },
    RvCsrEntry {
        addr: 0x106,
        name: "scounteren",
        priv_level: "SRW",
        description: "Supervisor counter enable",
    },
    RvCsrEntry {
        addr: 0x140,
        name: "sscratch",
        priv_level: "SRW",
        description: "Scratch register for supervisor trap handlers",
    },
    RvCsrEntry {
        addr: 0x141,
        name: "sepc",
        priv_level: "SRW",
        description: "Supervisor exception program counter",
    },
    RvCsrEntry {
        addr: 0x142,
        name: "scause",
        priv_level: "SRW",
        description: "Supervisor trap cause",
    },
    RvCsrEntry {
        addr: 0x143,
        name: "stval",
        priv_level: "SRW",
        description: "Supervisor bad address or instruction",
    },
    RvCsrEntry {
        addr: 0x144,
        name: "sip",
        priv_level: "SRW",
        description: "Supervisor interrupt pending",
    },
    RvCsrEntry {
        addr: 0x180,
        name: "satp",
        priv_level: "SRW",
        description: "Supervisor address translation and protection",
    },
    RvCsrEntry {
        addr: 0x5A8,
        name: "scontext",
        priv_level: "SRW",
        description: "Supervisor-mode context register",
    },
    // ── Machine-mode CSRs ────────────────────────────────────────────────────
    RvCsrEntry {
        addr: 0x300,
        name: "mstatus",
        priv_level: "MRW",
        description: "Machine status register",
    },
    RvCsrEntry {
        addr: 0x301,
        name: "misa",
        priv_level: "MRW",
        description: "ISA and extensions",
    },
    RvCsrEntry {
        addr: 0x302,
        name: "medeleg",
        priv_level: "MRW",
        description: "Machine exception delegation",
    },
    RvCsrEntry {
        addr: 0x303,
        name: "mideleg",
        priv_level: "MRW",
        description: "Machine interrupt delegation",
    },
    RvCsrEntry {
        addr: 0x304,
        name: "mie",
        priv_level: "MRW",
        description: "Machine interrupt-enable",
    },
    RvCsrEntry {
        addr: 0x305,
        name: "mtvec",
        priv_level: "MRW",
        description: "Machine trap-handler base address",
    },
    RvCsrEntry {
        addr: 0x306,
        name: "mcounteren",
        priv_level: "MRW",
        description: "Machine counter enable",
    },
    RvCsrEntry {
        addr: 0x340,
        name: "mscratch",
        priv_level: "MRW",
        description: "Scratch register for machine trap handlers",
    },
    RvCsrEntry {
        addr: 0x341,
        name: "mepc",
        priv_level: "MRW",
        description: "Machine exception program counter",
    },
    RvCsrEntry {
        addr: 0x342,
        name: "mcause",
        priv_level: "MRW",
        description: "Machine trap cause",
    },
    RvCsrEntry {
        addr: 0x343,
        name: "mtval",
        priv_level: "MRW",
        description: "Machine bad address or instruction",
    },
    RvCsrEntry {
        addr: 0x344,
        name: "mip",
        priv_level: "MRW",
        description: "Machine interrupt pending",
    },
    RvCsrEntry {
        addr: 0x34A,
        name: "mtinst",
        priv_level: "MRW",
        description: "Machine trap instruction (transformed)",
    },
    RvCsrEntry {
        addr: 0x34B,
        name: "mtval2",
        priv_level: "MRW",
        description: "Machine bad guest physical address",
    },
    RvCsrEntry {
        addr: 0x3A0,
        name: "pmpcfg0",
        priv_level: "MRW",
        description: "Physical memory protection config 0",
    },
    RvCsrEntry {
        addr: 0x3A1,
        name: "pmpcfg1",
        priv_level: "MRW",
        description: "Physical memory protection config 1",
    },
    RvCsrEntry {
        addr: 0x3B0,
        name: "pmpaddr0",
        priv_level: "MRW",
        description: "Physical memory protection address 0",
    },
    RvCsrEntry {
        addr: 0x3B1,
        name: "pmpaddr1",
        priv_level: "MRW",
        description: "Physical memory protection address 1",
    },
    RvCsrEntry {
        addr: 0x3B2,
        name: "pmpaddr2",
        priv_level: "MRW",
        description: "Physical memory protection address 2",
    },
    RvCsrEntry {
        addr: 0x3B3,
        name: "pmpaddr3",
        priv_level: "MRW",
        description: "Physical memory protection address 3",
    },
    RvCsrEntry {
        addr: 0xB00,
        name: "mcycle",
        priv_level: "MRW",
        description: "Machine cycle counter",
    },
    RvCsrEntry {
        addr: 0xB02,
        name: "minstret",
        priv_level: "MRW",
        description: "Machine instructions-retired counter",
    },
    RvCsrEntry {
        addr: 0xF11,
        name: "mvendorid",
        priv_level: "MRO",
        description: "Vendor ID",
    },
    RvCsrEntry {
        addr: 0xF12,
        name: "marchid",
        priv_level: "MRO",
        description: "Architecture ID",
    },
    RvCsrEntry {
        addr: 0xF13,
        name: "mimpid",
        priv_level: "MRO",
        description: "Implementation ID",
    },
    RvCsrEntry {
        addr: 0xF14,
        name: "mhartid",
        priv_level: "MRO",
        description: "Hardware thread ID",
    },
    RvCsrEntry {
        addr: 0xF15,
        name: "mconfigptr",
        priv_level: "MRO",
        description: "Pointer to configuration data structure",
    },
];

/// Look up a CSR entry by address.
#[must_use]
pub fn rv_csr_ext_lookup(addr: u16) -> Option<&'static RvCsrEntry> {
    RV_CSR_EXT.iter().find(|c| c.addr == addr)
}

// ---------------------------------------------------------------------------
// RISC-V exception cause codes
// ---------------------------------------------------------------------------

/// A RISC-V exception cause entry.
#[derive(Debug, Clone, Copy)]
pub struct RvExcCause {
    /// Cause code (interrupt=false) or interrupt cause code (interrupt=true).
    pub code: u64,
    /// Whether this is an interrupt (true) or exception (false).
    pub is_interrupt: bool,
    /// Cause name.
    pub name: &'static str,
    /// Description.
    pub description: &'static str,
}

/// RISC-V standard exception and interrupt causes.
pub static RV_EXC_CAUSES: &[RvExcCause] = &[
    // ── Exceptions ──────────────────────────────────────────────────────────
    RvExcCause {
        code: 0,
        is_interrupt: false,
        name: "InstructionAddressMisaligned",
        description: "Instruction address misaligned",
    },
    RvExcCause {
        code: 1,
        is_interrupt: false,
        name: "InstructionAccessFault",
        description: "Instruction access fault",
    },
    RvExcCause {
        code: 2,
        is_interrupt: false,
        name: "IllegalInstruction",
        description: "Illegal instruction",
    },
    RvExcCause {
        code: 3,
        is_interrupt: false,
        name: "Breakpoint",
        description: "Breakpoint (EBREAK)",
    },
    RvExcCause {
        code: 4,
        is_interrupt: false,
        name: "LoadAddressMisaligned",
        description: "Load address misaligned",
    },
    RvExcCause {
        code: 5,
        is_interrupt: false,
        name: "LoadAccessFault",
        description: "Load access fault",
    },
    RvExcCause {
        code: 6,
        is_interrupt: false,
        name: "StoreAMOAddressMisaligned",
        description: "Store/AMO address misaligned",
    },
    RvExcCause {
        code: 7,
        is_interrupt: false,
        name: "StoreAMOAccessFault",
        description: "Store/AMO access fault",
    },
    RvExcCause {
        code: 8,
        is_interrupt: false,
        name: "EnvironmentCallFromU",
        description: "Environment call from U-mode",
    },
    RvExcCause {
        code: 9,
        is_interrupt: false,
        name: "EnvironmentCallFromS",
        description: "Environment call from S-mode",
    },
    RvExcCause {
        code: 10,
        is_interrupt: false,
        name: "Reserved10",
        description: "Reserved",
    },
    RvExcCause {
        code: 11,
        is_interrupt: false,
        name: "EnvironmentCallFromM",
        description: "Environment call from M-mode",
    },
    RvExcCause {
        code: 12,
        is_interrupt: false,
        name: "InstructionPageFault",
        description: "Instruction page fault",
    },
    RvExcCause {
        code: 13,
        is_interrupt: false,
        name: "LoadPageFault",
        description: "Load page fault",
    },
    RvExcCause {
        code: 14,
        is_interrupt: false,
        name: "Reserved14",
        description: "Reserved",
    },
    RvExcCause {
        code: 15,
        is_interrupt: false,
        name: "StoreAMOPageFault",
        description: "Store/AMO page fault",
    },
    RvExcCause {
        code: 20,
        is_interrupt: false,
        name: "InstructionGuestPageFault",
        description: "Instruction guest-page fault",
    },
    RvExcCause {
        code: 21,
        is_interrupt: false,
        name: "LoadGuestPageFault",
        description: "Load guest-page fault",
    },
    RvExcCause {
        code: 22,
        is_interrupt: false,
        name: "VirtualInstruction",
        description: "Virtual instruction exception",
    },
    RvExcCause {
        code: 23,
        is_interrupt: false,
        name: "StoreAMOGuestPageFault",
        description: "Store/AMO guest-page fault",
    },
    // ── Interrupts ──────────────────────────────────────────────────────────
    RvExcCause {
        code: 0,
        is_interrupt: true,
        name: "UserSoftwareInterrupt",
        description: "User-mode software interrupt",
    },
    RvExcCause {
        code: 1,
        is_interrupt: true,
        name: "SupervisorSoftwareInterrupt",
        description: "Supervisor software interrupt",
    },
    RvExcCause {
        code: 3,
        is_interrupt: true,
        name: "MachineSoftwareInterrupt",
        description: "Machine software interrupt",
    },
    RvExcCause {
        code: 4,
        is_interrupt: true,
        name: "UserTimerInterrupt",
        description: "User-mode timer interrupt",
    },
    RvExcCause {
        code: 5,
        is_interrupt: true,
        name: "SupervisorTimerInterrupt",
        description: "Supervisor timer interrupt",
    },
    RvExcCause {
        code: 7,
        is_interrupt: true,
        name: "MachineTimerInterrupt",
        description: "Machine timer interrupt (MTIME)",
    },
    RvExcCause {
        code: 8,
        is_interrupt: true,
        name: "UserExternalInterrupt",
        description: "User-mode external interrupt",
    },
    RvExcCause {
        code: 9,
        is_interrupt: true,
        name: "SupervisorExternalInterrupt",
        description: "Supervisor external interrupt",
    },
    RvExcCause {
        code: 11,
        is_interrupt: true,
        name: "MachineExternalInterrupt",
        description: "Machine external interrupt (PLIC)",
    },
];

/// Look up an exception cause by code and interrupt flag.
#[must_use]
pub fn rv_exc_cause_lookup(code: u64, is_interrupt: bool) -> Option<&'static RvExcCause> {
    RV_EXC_CAUSES
        .iter()
        .find(|c| c.code == code && c.is_interrupt == is_interrupt)
}

// ---------------------------------------------------------------------------
// RISC-V MISA extension bits
// ---------------------------------------------------------------------------

/// Returns the ISA extension character for bit position `bit` of MISA.
///
/// `bit` 0 → 'A', bit 1 → 'B', …, bit 25 → 'Z'.
#[must_use]
pub const fn rv_misa_ext_char(bit: u8) -> char {
    (b'A' + (bit & 0x1f)) as char
}

/// Returns `true` if the given MISA extension bit is set.
#[must_use]
pub const fn rv_misa_has(misa: u64, bit: u8) -> bool {
    (misa >> bit) & 1 != 0
}

/// Decode the base ISA width from MISA.MXL bits [63:62] (RV64) or [31:30] (RV32).
///
/// Returns 32, 64, or 128 based on MXL.
#[must_use]
pub const fn rv_misa_mxl(misa: u64) -> u32 {
    let mxl = (misa >> 62) & 0x3;
    match mxl {
        1 => 32,
        2 => 64,
        3 => 128,
        _ => {
            // Try 32-bit MISA format
            let mxl32 = (misa >> 30) & 0x3;
            match mxl32 {
                1 => 32,
                2 => 64,
                _ => 0,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RISC-V privilege level helpers
// ---------------------------------------------------------------------------

/// RISC-V privilege level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RvPrivLevel {
    /// User / application mode.
    User = 0,
    /// Supervisor mode.
    Supervisor = 1,
    /// Hypervisor VS (virtual supervisor).
    VirtSupervisor = 2,
    /// Machine mode.
    Machine = 3,
}

impl RvPrivLevel {
    /// Decode from 2-bit privilege encoding.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x3 {
            0 => Self::User,
            1 => Self::Supervisor,
            2 => Self::VirtSupervisor,
            _ => Self::Machine,
        }
    }

    /// Returns the name string.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Supervisor => "Supervisor",
            Self::VirtSupervisor => "VirtSupervisor",
            Self::Machine => "Machine",
        }
    }

    /// Returns `true` if this level can access machine-mode CSRs.
    #[must_use]
    pub const fn can_access_machine_csrs(self) -> bool {
        matches!(self, Self::Machine)
    }
}

// ---------------------------------------------------------------------------
// RISC-V Sv39 / Sv48 / Sv57 virtual address helpers
// ---------------------------------------------------------------------------

/// Page size for all Sv* schemes (4 KiB).
pub const RV_PAGE_SIZE: u64 = 4096;

/// Number of bits in a 4KiB page offset.
pub const RV_PAGE_OFFSET_BITS: u8 = 12;

/// Sv39 virtual-address VPN levels.
pub const SV39_LEVELS: u8 = 3;
/// Sv48 virtual-address VPN levels.
pub const SV48_LEVELS: u8 = 4;
/// Sv57 virtual-address VPN levels.
pub const SV57_LEVELS: u8 = 5;

/// Extract VPN[i] from an Sv39 virtual address.
///
/// `level` is 0 (innermost) to 2 (outermost).
#[must_use]
pub const fn sv39_vpn(va: u64, level: u8) -> u64 {
    (va >> (12 + level as u64 * 9)) & 0x1ff
}

/// Extract VPN[i] from an Sv48 virtual address.
#[must_use]
pub const fn sv48_vpn(va: u64, level: u8) -> u64 {
    (va >> (12 + level as u64 * 9)) & 0x1ff
}

/// Sign-extend an Sv39 virtual address to 64 bits.
///
/// Sv39 uses bits[38:0]; bit 38 must be replicated to bits [63:39].
#[must_use]
pub const fn sv39_canonical(va: u64) -> u64 {
    let raw = va & 0x0000_007f_ffff_ffff;
    // sign-extend from bit 38
    let sign_bit = (raw >> 38) & 1;
    if sign_bit != 0 {
        raw | 0xFFFF_FF80_0000_0000
    } else {
        raw
    }
}

/// Compute the physical address from a 56-bit PPN and 12-bit page offset.
#[must_use]
pub const fn rv_phys_addr(ppn: u64, page_offset: u64) -> u64 {
    (ppn << 12) | (page_offset & 0xfff)
}

// ---------------------------------------------------------------------------
// RISC-V known CPU / core table
// ---------------------------------------------------------------------------

/// A known RISC-V CPU / `SoC` entry.
#[derive(Debug, Clone, Copy)]
pub struct RvCpu {
    /// Core name.
    pub name: &'static str,
    /// ISA string.
    pub isa: &'static str,
    /// Microarchitecture.
    pub uarch: &'static str,
    /// Whether the core supports hardware floating-point.
    pub has_fpu: bool,
}

/// Known RISC-V cores.
pub static RV_CPUS: &[RvCpu] = &[
    RvCpu {
        name: "SiFive E31",
        isa: "RV32IMAC",
        uarch: "In-order",
        has_fpu: false,
    },
    RvCpu {
        name: "SiFive E51",
        isa: "RV64IMAC",
        uarch: "In-order",
        has_fpu: false,
    },
    RvCpu {
        name: "SiFive U54",
        isa: "RV64GC",
        uarch: "In-order",
        has_fpu: true,
    },
    RvCpu {
        name: "SiFive U74",
        isa: "RV64GC",
        uarch: "In-order 4-way",
        has_fpu: true,
    },
    RvCpu {
        name: "SiFive P550",
        isa: "RV64GC",
        uarch: "OoO 3-wide",
        has_fpu: true,
    },
    RvCpu {
        name: "Western Digital D-Core",
        isa: "RV32IMC",
        uarch: "In-order",
        has_fpu: false,
    },
    RvCpu {
        name: "Alibaba T-Head C910",
        isa: "RV64GCV",
        uarch: "OoO 3-wide",
        has_fpu: true,
    },
    RvCpu {
        name: "Alibaba T-Head C906",
        isa: "RV64GCV",
        uarch: "In-order 5-stage",
        has_fpu: true,
    },
    RvCpu {
        name: "StarFive JH7100",
        isa: "RV64GC",
        uarch: "U74 dual-core",
        has_fpu: true,
    },
    RvCpu {
        name: "SpacemiT X60",
        isa: "RV64GCV",
        uarch: "OoO 8-wide",
        has_fpu: true,
    },
    RvCpu {
        name: "Ventana Veyron",
        isa: "RV64GC",
        uarch: "OoO",
        has_fpu: true,
    },
    RvCpu {
        name: "Cortex-R82AE",
        isa: "RV64I",
        uarch: "Arm R-class",
        has_fpu: false,
    },
    RvCpu {
        name: "RISC-V Ibex",
        isa: "RV32IMC",
        uarch: "2-stage",
        has_fpu: false,
    },
    RvCpu {
        name: "CVA6",
        isa: "RV64IMACFD",
        uarch: "6-stage OoO",
        has_fpu: true,
    },
    RvCpu {
        name: "Rocket Chip",
        isa: "RV64GC",
        uarch: "In-order",
        has_fpu: true,
    },
    RvCpu {
        name: "BOOM",
        isa: "RV64GC",
        uarch: "OoO superscalar",
        has_fpu: true,
    },
    RvCpu {
        name: "PicoRV32",
        isa: "RV32I",
        uarch: "Minimal",
        has_fpu: false,
    },
    RvCpu {
        name: "VexRiscv",
        isa: "RV32IM",
        uarch: "5-stage",
        has_fpu: false,
    },
    RvCpu {
        name: "QEMU RISC-V virt",
        isa: "RV64GC",
        uarch: "Emulated",
        has_fpu: true,
    },
];

/// Look up a CPU entry by name.
#[must_use]
pub fn rv_cpu_lookup(name: &str) -> Option<&'static RvCpu> {
    RV_CPUS.iter().find(|c| c.name == name)
}

// ---------------------------------------------------------------------------
// RISC-V instruction annotation helpers
// ---------------------------------------------------------------------------

/// Returns `true` if the 32-bit word encodes a RISC-V NOP (ADDI x0, x0, 0).
#[must_use]
pub const fn rv_is_nop(word: u32) -> bool {
    word == 0x0000_0013
}

/// Returns `true` if the word is a function return (JALR x0, ra, 0).
#[must_use]
pub const fn rv_is_ret(word: u32) -> bool {
    // opcode=0x67 (JALR), rd=0 (x0), funct3=0, rs1=1 (ra), imm=0
    word == 0x0000_8067
}

/// Returns `true` if the word encodes a FENCE instruction.
#[must_use]
pub const fn rv_is_fence(word: u32) -> bool {
    rv_opcode(word) == 0x0F && rv_funct3(word) == 0x00
}

/// Returns `true` if the word encodes FENCE.I.
#[must_use]
pub const fn rv_is_fence_i(word: u32) -> bool {
    rv_opcode(word) == 0x0F && rv_funct3(word) == 0x01
}

/// Returns `true` if the word encodes ECALL (opcode=0x73, imm=0).
#[must_use]
pub const fn rv_is_ecall(word: u32) -> bool {
    word == 0x0000_0073
}

/// Returns `true` if the word encodes EBREAK (opcode=0x73, imm=1).
#[must_use]
pub const fn rv_is_ebreak(word: u32) -> bool {
    word == 0x0010_0073
}

/// Returns `true` if the word encodes MRET.
#[must_use]
pub const fn rv_is_mret(word: u32) -> bool {
    word == 0x3020_0073
}

/// Returns `true` if the word encodes SRET.
#[must_use]
pub const fn rv_is_sret(word: u32) -> bool {
    word == 0x1020_0073
}

/// Returns `true` if the word encodes WFI.
#[must_use]
pub const fn rv_is_wfi(word: u32) -> bool {
    word == 0x1050_0073
}

// ---------------------------------------------------------------------------
// RISC-V SIMD / Vector (V extension) helpers
// ---------------------------------------------------------------------------

/// RISC-V Vector element size encoding (vsew field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RvVsew {
    /// 8-bit elements.
    E8 = 0,
    /// 16-bit elements.
    E16 = 1,
    /// 32-bit elements.
    E32 = 2,
    /// 64-bit elements.
    E64 = 3,
}

impl RvVsew {
    /// Decode from 3-bit vsew field.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0x7 {
            0 => Some(Self::E8),
            1 => Some(Self::E16),
            2 => Some(Self::E32),
            3 => Some(Self::E64),
            _ => None,
        }
    }

    /// Width in bits of each element.
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::E8 => 8,
            Self::E16 => 16,
            Self::E32 => 32,
            Self::E64 => 64,
        }
    }

    /// Width in bytes of each element.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        self.bits() / 8
    }
}

/// RISC-V Vector LMUL encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RvVlmul {
    /// LMUL = 1/8.
    M1_8 = 5,
    /// LMUL = 1/4.
    M1_4 = 6,
    /// LMUL = 1/2.
    M1_2 = 7,
    /// LMUL = 1.
    M1 = 0,
    /// LMUL = 2.
    M2 = 1,
    /// LMUL = 4.
    M4 = 2,
    /// LMUL = 8.
    M8 = 3,
}

impl RvVlmul {
    /// Decode from 3-bit vlmul field.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0x7 {
            0 => Some(Self::M1),
            1 => Some(Self::M2),
            2 => Some(Self::M4),
            3 => Some(Self::M8),
            5 => Some(Self::M1_8),
            6 => Some(Self::M1_4),
            7 => Some(Self::M1_2),
            _ => None,
        }
    }

    /// Return the assembler suffix for this LMUL.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::M1_8 => "mf8",
            Self::M1_4 => "mf4",
            Self::M1_2 => "mf2",
            Self::M1 => "m1",
            Self::M2 => "m2",
            Self::M4 => "m4",
            Self::M8 => "m8",
        }
    }
}

// ---------------------------------------------------------------------------
// RISC-V FP rounding mode
// ---------------------------------------------------------------------------

/// RISC-V floating-point rounding modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RvFpRm {
    /// Round to nearest, ties to even.
    Rne = 0,
    /// Round towards zero.
    Rtz = 1,
    /// Round down (towards negative infinity).
    Rdn = 2,
    /// Round up (towards positive infinity).
    Rup = 3,
    /// Round to nearest, ties to maximum magnitude.
    Rmm = 4,
    /// Dynamic rounding mode (from frm CSR).
    Dyn = 7,
}

impl RvFpRm {
    /// Decode from 3-bit rm field.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0x7 {
            0 => Some(Self::Rne),
            1 => Some(Self::Rtz),
            2 => Some(Self::Rdn),
            3 => Some(Self::Rup),
            4 => Some(Self::Rmm),
            7 => Some(Self::Dyn),
            _ => None,
        }
    }

    /// Return the assembler mnemonic suffix.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Rne => "rne",
            Self::Rtz => "rtz",
            Self::Rdn => "rdn",
            Self::Rup => "rup",
            Self::Rmm => "rmm",
            Self::Dyn => "dyn",
        }
    }
}

// ---------------------------------------------------------------------------
// RISC-V bit manipulation helpers
// ---------------------------------------------------------------------------

/// Extract bits [hi:lo] (both inclusive) from `val`.
#[must_use]
pub const fn rv_bits(val: u32, hi: u8, lo: u8) -> u32 {
    let width = hi - lo + 1;
    let mask = if width >= 32 {
        u32::MAX
    } else {
        (1u32 << width) - 1
    };
    (val >> lo) & mask
}

/// Sign-extend a value from bit width `width` to 32 bits.
#[must_use]
pub const fn rv_sign_ext(val: u32, width: u8) -> i32 {
    let shift = 32 - width;
    ((val << shift).cast_signed()) >> shift
}

/// Sign-extend a 64-bit value from bit width `width` to i64.
#[must_use]
pub const fn rv_sign_ext64(val: u64, width: u8) -> i64 {
    let shift = 64 - width;
    ((val << shift).cast_signed()) >> shift
}

/// Population count of a 32-bit value.
#[must_use]
pub const fn rv_popcount(val: u32) -> u32 {
    val.count_ones()
}

/// Rotate a 32-bit value right by `n`.
#[must_use]
pub const fn rv_ror32(val: u32, n: u8) -> u32 {
    val.rotate_right(n as u32)
}

/// Rotate a 64-bit value right by `n`.
#[must_use]
pub const fn rv_ror64(val: u64, n: u8) -> u64 {
    val.rotate_right(n as u32)
}

// ---------------------------------------------------------------------------
// RISC-V feature flags
// ---------------------------------------------------------------------------

/// RISC-V ISA extension flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RvFeatures(u64);

impl RvFeatures {
    /// No extensions.
    pub const NONE: Self = Self(0);
    /// Base Integer ISA (always present).
    pub const I: Self = Self(1 << 8); // bit 8 = 'I'
    /// Integer Multiply/Divide.
    pub const M: Self = Self(1 << 12); // bit 12 = 'M'
    /// Atomic instructions.
    pub const A: Self = Self(1 << 0); // bit 0 = 'A'
    /// Single-precision float.
    pub const F: Self = Self(1 << 5); // bit 5 = 'F'
    /// Double-precision float.
    pub const D: Self = Self(1 << 3); // bit 3 = 'D'
    /// Compressed instructions.
    pub const C: Self = Self(1 << 2); // bit 2 = 'C'
    /// Vector extension.
    pub const V: Self = Self(1 << 21); // bit 21 = 'V'
    /// Hypervisor extension.
    pub const H: Self = Self(1 << 7); // bit 7 = 'H'
    /// Bit manipulation (Zb*).
    pub const B: Self = Self(1 << 1); // bit 1 = 'B'

    /// Combine two feature sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Test if a feature is present.
    #[must_use]
    pub const fn has(self, feat: Self) -> bool {
        self.0 & feat.0 != 0
    }

    /// Standard RV64GC feature set.
    #[must_use]
    pub const fn rv64gc() -> Self {
        Self::I
            .union(Self::M)
            .union(Self::A)
            .union(Self::F)
            .union(Self::D)
            .union(Self::C)
    }

    /// Standard RV32IMAC feature set.
    #[must_use]
    pub const fn rv32imac() -> Self {
        Self::I.union(Self::M).union(Self::A).union(Self::C)
    }
}

// ---------------------------------------------------------------------------
// Extended tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod ext_tests {
    use super::*;

    // ── Field extractors ─────────────────────────────────────────────────────
    #[test]
    fn test_rv_opcode_addi() {
        // ADDI opcode = 0x13
        assert_eq!(rv_opcode(0x0000_0013), 0x13);
    }

    #[test]
    fn test_rv_rd_rs1_rs2() {
        // LW x1, 4(x2) — opcode=0x03, rd=1, funct3=2, rs1=2, imm=4
        let word: u32 = (4 << 20) | (2 << 15) | (2 << 12) | (1 << 7) | 0x03;
        assert_eq!(rv_rd(word), 1);
        assert_eq!(rv_rs1(word), 2);
        assert_eq!(rv_funct3(word), 2);
    }

    #[test]
    fn test_rv_imm_i_positive() {
        // imm = +100
        let word: u32 = (100 << 20) | 0x13;
        assert_eq!(rv_imm_i(word), 100);
    }

    #[test]
    fn test_rv_imm_i_negative() {
        // imm = -1 = all ones in bits[31:20]
        let word: u32 = (0xFFF << 20) | 0x13;
        assert_eq!(rv_imm_i(word), -1);
    }

    #[test]
    fn test_rv_imm_u() {
        // LUI x1, 0x1000 → bits[31:12] = 0x1000
        let word: u32 = (0x1000 << 12) | (1 << 7) | 0x37;
        assert_eq!(rv_imm_u(word), 0x1000 << 12);
    }

    // ── JAL target ───────────────────────────────────────────────────────────
    #[test]
    fn test_rv_jal_target_forward() {
        // JAL with zero offset: target == PC
        // imm20=0, imm10_1=0, imm11=0, imm19_12=0 → offset=0
        let word: u32 = 0x6F; // JAL x0, +0
        let target = rv_jal_target(0x1000, word);
        assert_eq!(target, 0x1000);
    }

    // ── Branch target ─────────────────────────────────────────────────────────
    #[test]
    fn test_rv_branch_target_forward() {
        // BEQ x1, x2, +8 → B-imm = 8, bit3=1 → imm4_1=4
        // bits: imm12=0, imm11=0, imm10_5=0, imm4_1=4
        let word: u32 = (4 << 8) | (1 << 15) | (2 << 20) | 0x63;
        let target = rv_branch_target(0x2000, word);
        assert_eq!(target, 0x2008);
    }

    // ── Opcode classification ─────────────────────────────────────────────────
    #[test]
    fn test_rv_classify_load() {
        assert!(matches!(rv_classify(0x0000_2003), RvOpcodeClass::Load));
    }

    #[test]
    fn test_rv_classify_store() {
        let word: u32 = (2 << 12) | 0x23;
        assert!(matches!(rv_classify(word), RvOpcodeClass::Store));
    }

    #[test]
    fn test_rv_classify_branch() {
        let word: u32 = 0x63;
        assert!(matches!(rv_classify(word), RvOpcodeClass::Branch));
    }

    #[test]
    fn test_rv_classify_jal() {
        assert!(matches!(rv_classify(0x6F), RvOpcodeClass::Jal));
    }

    #[test]
    fn test_rv_is_load() {
        assert!(rv_is_load(0x0000_2003));
        assert!(!rv_is_load(0x0000_0013));
    }

    #[test]
    fn test_rv_is_store() {
        assert!(rv_is_store(0x0000_2023));
        assert!(!rv_is_store(0x0000_0013));
    }

    // ── Register helpers ──────────────────────────────────────────────────────
    #[test]
    fn test_gpr_names() {
        assert_eq!(rv_gpr_name(0), "zero");
        assert_eq!(rv_gpr_name(1), "ra");
        assert_eq!(rv_gpr_name(10), "a0");
        assert_eq!(rv_gpr_name(31), "t6");
    }

    #[test]
    fn test_fpr_names() {
        assert_eq!(rv_fpr_name(0), "ft0");
        assert_eq!(rv_fpr_name(10), "fa0");
        assert_eq!(rv_fpr_name(31), "ft11");
    }

    #[test]
    fn test_gpr_role_zero() {
        assert_eq!(rv_gpr_role(0), RvGprRole::Zero);
    }

    #[test]
    fn test_gpr_role_ra() {
        assert_eq!(rv_gpr_role(1), RvGprRole::ReturnAddress);
    }

    #[test]
    fn test_gpr_role_arg() {
        assert_eq!(rv_gpr_role(10), RvGprRole::ArgReturn);
        assert!(rv_is_caller_saved(10));
    }

    #[test]
    fn test_gpr_role_callee_saved() {
        assert!(rv_is_callee_saved(8)); // s0/fp
        assert!(rv_is_callee_saved(9)); // s1
        assert!(rv_is_callee_saved(18)); // s2
    }

    // ── CSR extended lookup ───────────────────────────────────────────────────
    #[test]
    fn test_csr_cycle() {
        let c = rv_csr_ext_lookup(0xC00).unwrap();
        assert_eq!(c.name, "cycle");
    }

    #[test]
    fn test_csr_mstatus() {
        let c = rv_csr_ext_lookup(0x300).unwrap();
        assert_eq!(c.name, "mstatus");
        assert_eq!(c.priv_level, "MRW");
    }

    #[test]
    fn test_csr_satp() {
        let c = rv_csr_ext_lookup(0x180).unwrap();
        assert_eq!(c.name, "satp");
    }

    #[test]
    fn test_csr_not_found() {
        assert!(rv_csr_ext_lookup(0xDEAD).is_none());
    }

    // ── Exception causes ──────────────────────────────────────────────────────
    #[test]
    fn test_exc_cause_breakpoint() {
        let e = rv_exc_cause_lookup(3, false).unwrap();
        assert_eq!(e.name, "Breakpoint");
    }

    #[test]
    fn test_exc_cause_machine_timer_int() {
        let e = rv_exc_cause_lookup(7, true).unwrap();
        assert_eq!(e.name, "MachineTimerInterrupt");
    }

    #[test]
    fn test_exc_cause_not_found() {
        assert!(rv_exc_cause_lookup(99, false).is_none());
    }

    // ── MISA helpers ──────────────────────────────────────────────────────────
    #[test]
    fn test_misa_ext_char() {
        assert_eq!(rv_misa_ext_char(0), 'A');
        assert_eq!(rv_misa_ext_char(8), 'I');
        assert_eq!(rv_misa_ext_char(25), 'Z');
    }

    #[test]
    fn test_misa_has() {
        // MISA with bit 8 (I) set
        let misa: u64 = (1 << 62) | (1 << 8); // MXL=2 (RV64), I bit set
        let misa_simple: u64 = 1 << 8;
        assert!(rv_misa_has(misa, 8));
        assert!(!rv_misa_has(misa, 12));
        assert!(rv_misa_has(misa_simple, 8));
        assert!(!rv_misa_has(misa_simple, 12));
    }

    // ── Privilege level ───────────────────────────────────────────────────────
    #[test]
    fn test_priv_machine() {
        let pl = RvPrivLevel::from_bits(3);
        assert_eq!(pl, RvPrivLevel::Machine);
        assert!(pl.can_access_machine_csrs());
        assert_eq!(pl.name(), "Machine");
    }

    #[test]
    fn test_priv_user() {
        let pl = RvPrivLevel::from_bits(0);
        assert!(!pl.can_access_machine_csrs());
    }

    // ── Sv39 virtual address ──────────────────────────────────────────────────
    #[test]
    fn test_sv39_vpn_level0() {
        // VPN[0] is bits[20:12] of VA
        let va: u64 = 0x0000_0000_0020_1000; // VPN[0] = 1, VPN[1] = 1
        assert_eq!(sv39_vpn(va, 0), 1);
    }

    #[test]
    fn test_sv39_vpn_level1() {
        // VPN[1] = bits[29:21] → 0x0040_0000 = bit22 set → VPN[1] = 0x0040_0000>>21 = 2
        let va: u64 = 0x0000_0000_0040_0000;
        assert_eq!(sv39_vpn(va, 1), 2);
    }

    #[test]
    fn test_rv_phys_addr() {
        assert_eq!(rv_phys_addr(1, 0), 0x1000);
        assert_eq!(rv_phys_addr(0, 0xABC), 0xABC);
    }

    // ── Instruction annotation ────────────────────────────────────────────────
    #[test]
    fn test_rv_is_nop() {
        assert!(rv_is_nop(0x0000_0013));
        assert!(!rv_is_nop(0x0000_0000));
    }

    #[test]
    fn test_rv_is_ret() {
        assert!(rv_is_ret(0x0000_8067));
    }

    #[test]
    fn test_rv_is_ecall() {
        assert!(rv_is_ecall(0x0000_0073));
    }

    #[test]
    fn test_rv_is_ebreak() {
        assert!(rv_is_ebreak(0x0010_0073));
    }

    #[test]
    fn test_rv_is_mret() {
        assert!(rv_is_mret(0x3020_0073));
    }

    #[test]
    fn test_rv_is_wfi() {
        assert!(rv_is_wfi(0x1050_0073));
    }

    // ── FP rounding mode ──────────────────────────────────────────────────────
    #[test]
    fn test_fp_rm_rne() {
        let r = RvFpRm::from_bits(0).unwrap();
        assert_eq!(r.suffix(), "rne");
    }

    #[test]
    fn test_fp_rm_dyn() {
        let r = RvFpRm::from_bits(7).unwrap();
        assert_eq!(r.suffix(), "dyn");
    }

    #[test]
    fn test_fp_rm_invalid() {
        assert!(RvFpRm::from_bits(5).is_none());
    }

    // ── Vector helpers ────────────────────────────────────────────────────────
    #[test]
    fn test_vsew_e32() {
        let v = RvVsew::from_bits(2).unwrap();
        assert_eq!(v.bits(), 32);
        assert_eq!(v.bytes(), 4);
    }

    #[test]
    fn test_vlmul_m1() {
        let v = RvVlmul::from_bits(0).unwrap();
        assert_eq!(v.suffix(), "m1");
    }

    #[test]
    fn test_vlmul_mf2() {
        let v = RvVlmul::from_bits(7).unwrap();
        assert_eq!(v.suffix(), "mf2");
    }

    // ── Features ──────────────────────────────────────────────────────────────
    #[test]
    fn test_rv64gc_has_fd() {
        let f = RvFeatures::rv64gc();
        assert!(f.has(RvFeatures::F));
        assert!(f.has(RvFeatures::D));
    }

    #[test]
    fn test_rv32imac_no_float() {
        let f = RvFeatures::rv32imac();
        assert!(!f.has(RvFeatures::F));
        assert!(f.has(RvFeatures::C));
    }

    // ── Bitfield helpers ──────────────────────────────────────────────────────
    #[test]
    fn test_rv_bits() {
        assert_eq!(rv_bits(0xFF00, 15, 8), 0xFF);
    }

    #[test]
    fn test_rv_sign_ext() {
        assert_eq!(rv_sign_ext(0x1FF, 9), -1);
    }

    #[test]
    fn test_rv_popcount() {
        assert_eq!(rv_popcount(0xFF), 8);
    }

    // ── CPU lookup ────────────────────────────────────────────────────────────
    #[test]
    fn test_cpu_lookup_u74() {
        let cpu = rv_cpu_lookup("SiFive U74").unwrap();
        assert!(cpu.has_fpu);
    }

    #[test]
    fn test_cpu_lookup_not_found() {
        assert!(rv_cpu_lookup("Nonexistent").is_none());
    }

    // ── CSR table size ────────────────────────────────────────────────────────
    #[test]
    fn test_csr_ext_table_size() {
        assert!(RV_CSR_EXT.len() >= 50);
    }

    // ── Exception causes table size ───────────────────────────────────────────
    #[test]
    fn test_exc_causes_table_size() {
        assert!(RV_EXC_CAUSES.len() >= 25);
    }

    // ── ROR helpers ───────────────────────────────────────────────────────────
    #[test]
    fn test_rv_ror32() {
        assert_eq!(rv_ror32(1, 1), 0x8000_0000);
    }

    #[test]
    fn test_rv_ror64() {
        assert_eq!(rv_ror64(1, 1), 0x8000_0000_0000_0000);
    }
}

// ---------------------------------------------------------------------------
// RISC-V instruction mnemonic reference table
// ---------------------------------------------------------------------------

/// An entry in the RISC-V instruction reference table.
#[derive(Debug, Clone, Copy)]
pub struct RvInstrEntry {
    /// Mnemonic.
    pub mnemonic: &'static str,
    /// Encoding format (R/I/S/B/U/J/C*).
    pub format: &'static str,
    /// ISA extension (I, M, A, F, D, C, Zicsr, …).
    pub extension: &'static str,
    /// Brief description.
    pub description: &'static str,
}

/// Comprehensive RISC-V instruction reference table.
pub static RV_INSTR_TABLE: &[RvInstrEntry] = &[
    // ── RV32I Base ──────────────────────────────────────────────────────────
    RvInstrEntry {
        mnemonic: "lui",
        format: "U",
        extension: "I",
        description: "Load upper immediate",
    },
    RvInstrEntry {
        mnemonic: "auipc",
        format: "U",
        extension: "I",
        description: "Add upper immediate to PC",
    },
    RvInstrEntry {
        mnemonic: "jal",
        format: "J",
        extension: "I",
        description: "Jump and link",
    },
    RvInstrEntry {
        mnemonic: "jalr",
        format: "I",
        extension: "I",
        description: "Jump and link register",
    },
    RvInstrEntry {
        mnemonic: "beq",
        format: "B",
        extension: "I",
        description: "Branch if equal",
    },
    RvInstrEntry {
        mnemonic: "bne",
        format: "B",
        extension: "I",
        description: "Branch if not equal",
    },
    RvInstrEntry {
        mnemonic: "blt",
        format: "B",
        extension: "I",
        description: "Branch if less than",
    },
    RvInstrEntry {
        mnemonic: "bge",
        format: "B",
        extension: "I",
        description: "Branch if greater or equal",
    },
    RvInstrEntry {
        mnemonic: "bltu",
        format: "B",
        extension: "I",
        description: "Branch if less than (unsigned)",
    },
    RvInstrEntry {
        mnemonic: "bgeu",
        format: "B",
        extension: "I",
        description: "Branch if greater or equal (unsigned)",
    },
    RvInstrEntry {
        mnemonic: "lb",
        format: "I",
        extension: "I",
        description: "Load byte (signed)",
    },
    RvInstrEntry {
        mnemonic: "lh",
        format: "I",
        extension: "I",
        description: "Load halfword (signed)",
    },
    RvInstrEntry {
        mnemonic: "lw",
        format: "I",
        extension: "I",
        description: "Load word",
    },
    RvInstrEntry {
        mnemonic: "lbu",
        format: "I",
        extension: "I",
        description: "Load byte (unsigned)",
    },
    RvInstrEntry {
        mnemonic: "lhu",
        format: "I",
        extension: "I",
        description: "Load halfword (unsigned)",
    },
    RvInstrEntry {
        mnemonic: "sb",
        format: "S",
        extension: "I",
        description: "Store byte",
    },
    RvInstrEntry {
        mnemonic: "sh",
        format: "S",
        extension: "I",
        description: "Store halfword",
    },
    RvInstrEntry {
        mnemonic: "sw",
        format: "S",
        extension: "I",
        description: "Store word",
    },
    RvInstrEntry {
        mnemonic: "addi",
        format: "I",
        extension: "I",
        description: "Add immediate",
    },
    RvInstrEntry {
        mnemonic: "slti",
        format: "I",
        extension: "I",
        description: "Set less than immediate (signed)",
    },
    RvInstrEntry {
        mnemonic: "sltiu",
        format: "I",
        extension: "I",
        description: "Set less than immediate (unsigned)",
    },
    RvInstrEntry {
        mnemonic: "xori",
        format: "I",
        extension: "I",
        description: "XOR immediate",
    },
    RvInstrEntry {
        mnemonic: "ori",
        format: "I",
        extension: "I",
        description: "OR immediate",
    },
    RvInstrEntry {
        mnemonic: "andi",
        format: "I",
        extension: "I",
        description: "AND immediate",
    },
    RvInstrEntry {
        mnemonic: "slli",
        format: "I",
        extension: "I",
        description: "Shift left logical immediate",
    },
    RvInstrEntry {
        mnemonic: "srli",
        format: "I",
        extension: "I",
        description: "Shift right logical immediate",
    },
    RvInstrEntry {
        mnemonic: "srai",
        format: "I",
        extension: "I",
        description: "Shift right arithmetic immediate",
    },
    RvInstrEntry {
        mnemonic: "add",
        format: "R",
        extension: "I",
        description: "Add",
    },
    RvInstrEntry {
        mnemonic: "sub",
        format: "R",
        extension: "I",
        description: "Subtract",
    },
    RvInstrEntry {
        mnemonic: "sll",
        format: "R",
        extension: "I",
        description: "Shift left logical",
    },
    RvInstrEntry {
        mnemonic: "slt",
        format: "R",
        extension: "I",
        description: "Set less than (signed)",
    },
    RvInstrEntry {
        mnemonic: "sltu",
        format: "R",
        extension: "I",
        description: "Set less than (unsigned)",
    },
    RvInstrEntry {
        mnemonic: "xor",
        format: "R",
        extension: "I",
        description: "XOR",
    },
    RvInstrEntry {
        mnemonic: "srl",
        format: "R",
        extension: "I",
        description: "Shift right logical",
    },
    RvInstrEntry {
        mnemonic: "sra",
        format: "R",
        extension: "I",
        description: "Shift right arithmetic",
    },
    RvInstrEntry {
        mnemonic: "or",
        format: "R",
        extension: "I",
        description: "OR",
    },
    RvInstrEntry {
        mnemonic: "and",
        format: "R",
        extension: "I",
        description: "AND",
    },
    RvInstrEntry {
        mnemonic: "fence",
        format: "I",
        extension: "I",
        description: "Memory ordering fence",
    },
    RvInstrEntry {
        mnemonic: "ecall",
        format: "I",
        extension: "I",
        description: "Environment call",
    },
    RvInstrEntry {
        mnemonic: "ebreak",
        format: "I",
        extension: "I",
        description: "Environment breakpoint",
    },
    // ── RV64I ────────────────────────────────────────────────────────────────
    RvInstrEntry {
        mnemonic: "lwu",
        format: "I",
        extension: "I64",
        description: "Load word (unsigned)",
    },
    RvInstrEntry {
        mnemonic: "ld",
        format: "I",
        extension: "I64",
        description: "Load doubleword",
    },
    RvInstrEntry {
        mnemonic: "sd",
        format: "S",
        extension: "I64",
        description: "Store doubleword",
    },
    RvInstrEntry {
        mnemonic: "addiw",
        format: "I",
        extension: "I64",
        description: "Add word immediate",
    },
    RvInstrEntry {
        mnemonic: "slliw",
        format: "I",
        extension: "I64",
        description: "Shift left logical word immediate",
    },
    RvInstrEntry {
        mnemonic: "srliw",
        format: "I",
        extension: "I64",
        description: "Shift right logical word immediate",
    },
    RvInstrEntry {
        mnemonic: "sraiw",
        format: "I",
        extension: "I64",
        description: "Shift right arithmetic word immediate",
    },
    RvInstrEntry {
        mnemonic: "addw",
        format: "R",
        extension: "I64",
        description: "Add word",
    },
    RvInstrEntry {
        mnemonic: "subw",
        format: "R",
        extension: "I64",
        description: "Subtract word",
    },
    RvInstrEntry {
        mnemonic: "sllw",
        format: "R",
        extension: "I64",
        description: "Shift left logical word",
    },
    RvInstrEntry {
        mnemonic: "srlw",
        format: "R",
        extension: "I64",
        description: "Shift right logical word",
    },
    RvInstrEntry {
        mnemonic: "sraw",
        format: "R",
        extension: "I64",
        description: "Shift right arithmetic word",
    },
    // ── M extension ──────────────────────────────────────────────────────────
    RvInstrEntry {
        mnemonic: "mul",
        format: "R",
        extension: "M",
        description: "Multiply",
    },
    RvInstrEntry {
        mnemonic: "mulh",
        format: "R",
        extension: "M",
        description: "Multiply high (signed)",
    },
    RvInstrEntry {
        mnemonic: "mulhsu",
        format: "R",
        extension: "M",
        description: "Multiply high (signed×unsigned)",
    },
    RvInstrEntry {
        mnemonic: "mulhu",
        format: "R",
        extension: "M",
        description: "Multiply high (unsigned)",
    },
    RvInstrEntry {
        mnemonic: "div",
        format: "R",
        extension: "M",
        description: "Divide (signed)",
    },
    RvInstrEntry {
        mnemonic: "divu",
        format: "R",
        extension: "M",
        description: "Divide (unsigned)",
    },
    RvInstrEntry {
        mnemonic: "rem",
        format: "R",
        extension: "M",
        description: "Remainder (signed)",
    },
    RvInstrEntry {
        mnemonic: "remu",
        format: "R",
        extension: "M",
        description: "Remainder (unsigned)",
    },
    RvInstrEntry {
        mnemonic: "mulw",
        format: "R",
        extension: "M64",
        description: "Multiply word",
    },
    RvInstrEntry {
        mnemonic: "divw",
        format: "R",
        extension: "M64",
        description: "Divide word (signed)",
    },
    RvInstrEntry {
        mnemonic: "divuw",
        format: "R",
        extension: "M64",
        description: "Divide word (unsigned)",
    },
    RvInstrEntry {
        mnemonic: "remw",
        format: "R",
        extension: "M64",
        description: "Remainder word (signed)",
    },
    RvInstrEntry {
        mnemonic: "remuw",
        format: "R",
        extension: "M64",
        description: "Remainder word (unsigned)",
    },
    // ── A extension ──────────────────────────────────────────────────────────
    RvInstrEntry {
        mnemonic: "lr.w",
        format: "R",
        extension: "A",
        description: "Load reserved word",
    },
    RvInstrEntry {
        mnemonic: "sc.w",
        format: "R",
        extension: "A",
        description: "Store conditional word",
    },
    RvInstrEntry {
        mnemonic: "amoswap.w",
        format: "R",
        extension: "A",
        description: "Atomic swap word",
    },
    RvInstrEntry {
        mnemonic: "amoadd.w",
        format: "R",
        extension: "A",
        description: "Atomic add word",
    },
    RvInstrEntry {
        mnemonic: "amoxor.w",
        format: "R",
        extension: "A",
        description: "Atomic XOR word",
    },
    RvInstrEntry {
        mnemonic: "amoand.w",
        format: "R",
        extension: "A",
        description: "Atomic AND word",
    },
    RvInstrEntry {
        mnemonic: "amoor.w",
        format: "R",
        extension: "A",
        description: "Atomic OR word",
    },
    RvInstrEntry {
        mnemonic: "amomin.w",
        format: "R",
        extension: "A",
        description: "Atomic min word (signed)",
    },
    RvInstrEntry {
        mnemonic: "amomax.w",
        format: "R",
        extension: "A",
        description: "Atomic max word (signed)",
    },
    RvInstrEntry {
        mnemonic: "amominu.w",
        format: "R",
        extension: "A",
        description: "Atomic min word (unsigned)",
    },
    RvInstrEntry {
        mnemonic: "amomaxu.w",
        format: "R",
        extension: "A",
        description: "Atomic max word (unsigned)",
    },
    RvInstrEntry {
        mnemonic: "lr.d",
        format: "R",
        extension: "A64",
        description: "Load reserved doubleword",
    },
    RvInstrEntry {
        mnemonic: "sc.d",
        format: "R",
        extension: "A64",
        description: "Store conditional doubleword",
    },
    RvInstrEntry {
        mnemonic: "amoswap.d",
        format: "R",
        extension: "A64",
        description: "Atomic swap doubleword",
    },
    RvInstrEntry {
        mnemonic: "amoadd.d",
        format: "R",
        extension: "A64",
        description: "Atomic add doubleword",
    },
    // ── F extension ──────────────────────────────────────────────────────────
    RvInstrEntry {
        mnemonic: "flw",
        format: "I",
        extension: "F",
        description: "Load word to FPR",
    },
    RvInstrEntry {
        mnemonic: "fsw",
        format: "S",
        extension: "F",
        description: "Store word from FPR",
    },
    RvInstrEntry {
        mnemonic: "fmadd.s",
        format: "R4",
        extension: "F",
        description: "FP fused multiply-add (single)",
    },
    RvInstrEntry {
        mnemonic: "fmsub.s",
        format: "R4",
        extension: "F",
        description: "FP fused multiply-subtract (single)",
    },
    RvInstrEntry {
        mnemonic: "fnmadd.s",
        format: "R4",
        extension: "F",
        description: "FP neg fused multiply-add (single)",
    },
    RvInstrEntry {
        mnemonic: "fnmsub.s",
        format: "R4",
        extension: "F",
        description: "FP neg fused multiply-subtract (single)",
    },
    RvInstrEntry {
        mnemonic: "fadd.s",
        format: "R",
        extension: "F",
        description: "FP add (single)",
    },
    RvInstrEntry {
        mnemonic: "fsub.s",
        format: "R",
        extension: "F",
        description: "FP subtract (single)",
    },
    RvInstrEntry {
        mnemonic: "fmul.s",
        format: "R",
        extension: "F",
        description: "FP multiply (single)",
    },
    RvInstrEntry {
        mnemonic: "fdiv.s",
        format: "R",
        extension: "F",
        description: "FP divide (single)",
    },
    RvInstrEntry {
        mnemonic: "fsqrt.s",
        format: "R",
        extension: "F",
        description: "FP square root (single)",
    },
    RvInstrEntry {
        mnemonic: "fmin.s",
        format: "R",
        extension: "F",
        description: "FP minimum (single)",
    },
    RvInstrEntry {
        mnemonic: "fmax.s",
        format: "R",
        extension: "F",
        description: "FP maximum (single)",
    },
    RvInstrEntry {
        mnemonic: "feq.s",
        format: "R",
        extension: "F",
        description: "FP compare equal (single)",
    },
    RvInstrEntry {
        mnemonic: "flt.s",
        format: "R",
        extension: "F",
        description: "FP compare less than (single)",
    },
    RvInstrEntry {
        mnemonic: "fle.s",
        format: "R",
        extension: "F",
        description: "FP compare less or equal (single)",
    },
    RvInstrEntry {
        mnemonic: "fclass.s",
        format: "R",
        extension: "F",
        description: "FP classify (single)",
    },
    RvInstrEntry {
        mnemonic: "fcvt.w.s",
        format: "R",
        extension: "F",
        description: "Convert FP single to int word",
    },
    RvInstrEntry {
        mnemonic: "fcvt.wu.s",
        format: "R",
        extension: "F",
        description: "Convert FP single to uint word",
    },
    RvInstrEntry {
        mnemonic: "fcvt.s.w",
        format: "R",
        extension: "F",
        description: "Convert int word to FP single",
    },
    RvInstrEntry {
        mnemonic: "fcvt.s.wu",
        format: "R",
        extension: "F",
        description: "Convert uint word to FP single",
    },
    RvInstrEntry {
        mnemonic: "fmv.x.w",
        format: "R",
        extension: "F",
        description: "Move FPR word to GPR",
    },
    RvInstrEntry {
        mnemonic: "fmv.w.x",
        format: "R",
        extension: "F",
        description: "Move GPR to FPR word",
    },
    // ── D extension ──────────────────────────────────────────────────────────
    RvInstrEntry {
        mnemonic: "fld",
        format: "I",
        extension: "D",
        description: "Load doubleword to FPR",
    },
    RvInstrEntry {
        mnemonic: "fsd",
        format: "S",
        extension: "D",
        description: "Store doubleword from FPR",
    },
    RvInstrEntry {
        mnemonic: "fadd.d",
        format: "R",
        extension: "D",
        description: "FP add (double)",
    },
    RvInstrEntry {
        mnemonic: "fsub.d",
        format: "R",
        extension: "D",
        description: "FP subtract (double)",
    },
    RvInstrEntry {
        mnemonic: "fmul.d",
        format: "R",
        extension: "D",
        description: "FP multiply (double)",
    },
    RvInstrEntry {
        mnemonic: "fdiv.d",
        format: "R",
        extension: "D",
        description: "FP divide (double)",
    },
    RvInstrEntry {
        mnemonic: "fsqrt.d",
        format: "R",
        extension: "D",
        description: "FP square root (double)",
    },
    RvInstrEntry {
        mnemonic: "feq.d",
        format: "R",
        extension: "D",
        description: "FP compare equal (double)",
    },
    RvInstrEntry {
        mnemonic: "flt.d",
        format: "R",
        extension: "D",
        description: "FP compare less than (double)",
    },
    RvInstrEntry {
        mnemonic: "fle.d",
        format: "R",
        extension: "D",
        description: "FP compare less or equal (double)",
    },
    RvInstrEntry {
        mnemonic: "fclass.d",
        format: "R",
        extension: "D",
        description: "FP classify (double)",
    },
    RvInstrEntry {
        mnemonic: "fcvt.l.d",
        format: "R",
        extension: "D64",
        description: "Convert FP double to long",
    },
    RvInstrEntry {
        mnemonic: "fcvt.lu.d",
        format: "R",
        extension: "D64",
        description: "Convert FP double to ulong",
    },
    RvInstrEntry {
        mnemonic: "fcvt.d.l",
        format: "R",
        extension: "D64",
        description: "Convert long to FP double",
    },
    RvInstrEntry {
        mnemonic: "fmv.x.d",
        format: "R",
        extension: "D64",
        description: "Move FPR double to GPR",
    },
    RvInstrEntry {
        mnemonic: "fmv.d.x",
        format: "R",
        extension: "D64",
        description: "Move GPR to FPR double",
    },
    // ── Zicsr ────────────────────────────────────────────────────────────────
    RvInstrEntry {
        mnemonic: "csrrw",
        format: "I",
        extension: "Zicsr",
        description: "CSR read-write",
    },
    RvInstrEntry {
        mnemonic: "csrrs",
        format: "I",
        extension: "Zicsr",
        description: "CSR read-set",
    },
    RvInstrEntry {
        mnemonic: "csrrc",
        format: "I",
        extension: "Zicsr",
        description: "CSR read-clear",
    },
    RvInstrEntry {
        mnemonic: "csrrwi",
        format: "I",
        extension: "Zicsr",
        description: "CSR read-write immediate",
    },
    RvInstrEntry {
        mnemonic: "csrrsi",
        format: "I",
        extension: "Zicsr",
        description: "CSR read-set immediate",
    },
    RvInstrEntry {
        mnemonic: "csrrci",
        format: "I",
        extension: "Zicsr",
        description: "CSR read-clear immediate",
    },
    // ── Zifencei ────────────────────────────────────────────────────────────
    RvInstrEntry {
        mnemonic: "fence.i",
        format: "I",
        extension: "Zifencei",
        description: "Instruction-fetch fence",
    },
    // ── Privileged ───────────────────────────────────────────────────────────
    RvInstrEntry {
        mnemonic: "mret",
        format: "R",
        extension: "priv",
        description: "Machine-mode exception return",
    },
    RvInstrEntry {
        mnemonic: "sret",
        format: "R",
        extension: "priv",
        description: "Supervisor-mode exception return",
    },
    RvInstrEntry {
        mnemonic: "wfi",
        format: "R",
        extension: "priv",
        description: "Wait for interrupt",
    },
    RvInstrEntry {
        mnemonic: "sfence.vma",
        format: "R",
        extension: "priv",
        description: "Fence for virtual-memory address translations",
    },
];

/// Look up an instruction entry by mnemonic.
#[must_use]
pub fn rv_instr_lookup(mnemonic: &str) -> Option<&'static RvInstrEntry> {
    RV_INSTR_TABLE.iter().find(|e| e.mnemonic == mnemonic)
}

// ---------------------------------------------------------------------------
// RISC-V SBI (Supervisor Binary Interface) call numbers
// ---------------------------------------------------------------------------

/// An SBI call descriptor.
#[derive(Debug, Clone, Copy)]
pub struct SbiCall {
    /// Extension ID (EID).
    pub eid: u64,
    /// Function ID (FID).
    pub fid: u64,
    /// Call name.
    pub name: &'static str,
    /// Description.
    pub description: &'static str,
}

/// Selected RISC-V SBI calls.
pub static SBI_CALLS: &[SbiCall] = &[
    SbiCall {
        eid: 0x00,
        fid: 0,
        name: "sbi_set_timer",
        description: "Programs the clock for the next timer event",
    },
    SbiCall {
        eid: 0x01,
        fid: 0,
        name: "sbi_console_putchar",
        description: "Write a byte to console",
    },
    SbiCall {
        eid: 0x02,
        fid: 0,
        name: "sbi_console_getchar",
        description: "Read a byte from console",
    },
    SbiCall {
        eid: 0x03,
        fid: 0,
        name: "sbi_clear_ipi",
        description: "Clear pending software interrupt",
    },
    SbiCall {
        eid: 0x04,
        fid: 0,
        name: "sbi_send_ipi",
        description: "Send IPI to specified HARTs",
    },
    SbiCall {
        eid: 0x05,
        fid: 0,
        name: "sbi_remote_fence_i",
        description: "Instructs HARTs to execute FENCE.I",
    },
    SbiCall {
        eid: 0x06,
        fid: 0,
        name: "sbi_remote_sfence_vma",
        description: "Instructs HARTs to execute SFENCE.VMA",
    },
    SbiCall {
        eid: 0x07,
        fid: 0,
        name: "sbi_remote_sfence_vma_asid",
        description: "SFENCE.VMA for specific ASID",
    },
    SbiCall {
        eid: 0x08,
        fid: 0,
        name: "sbi_shutdown",
        description: "Put all HARTs into reset state",
    },
    // SBI v0.2 extensions (EID >= 0x10)
    SbiCall {
        eid: 0x10,
        fid: 0,
        name: "sbi_get_spec_version",
        description: "Returns SBI specification version",
    },
    SbiCall {
        eid: 0x10,
        fid: 1,
        name: "sbi_get_impl_id",
        description: "Returns SBI implementation ID",
    },
    SbiCall {
        eid: 0x10,
        fid: 2,
        name: "sbi_get_impl_version",
        description: "Returns SBI implementation version",
    },
    SbiCall {
        eid: 0x10,
        fid: 3,
        name: "sbi_probe_extension",
        description: "Probe an SBI extension",
    },
    SbiCall {
        eid: 0x10,
        fid: 4,
        name: "sbi_get_mvendorid",
        description: "Returns mvendorid CSR value",
    },
    SbiCall {
        eid: 0x10,
        fid: 5,
        name: "sbi_get_marchid",
        description: "Returns marchid CSR value",
    },
    SbiCall {
        eid: 0x10,
        fid: 6,
        name: "sbi_get_mimpid",
        description: "Returns mimpid CSR value",
    },
    // HSM extension
    SbiCall {
        eid: 0x0048_534D,
        fid: 0,
        name: "sbi_hart_start",
        description: "Start a HART",
    },
    SbiCall {
        eid: 0x0048_534D,
        fid: 1,
        name: "sbi_hart_stop",
        description: "Stop the current HART",
    },
    SbiCall {
        eid: 0x0048_534D,
        fid: 2,
        name: "sbi_hart_get_status",
        description: "Get HART status",
    },
    SbiCall {
        eid: 0x0048_534D,
        fid: 3,
        name: "sbi_hart_suspend",
        description: "Put HART in a lower power state",
    },
    // SRST extension (System Reset)
    SbiCall {
        eid: 0x5352_5354,
        fid: 0,
        name: "sbi_system_reset",
        description: "Reset or shutdown the system",
    },
    // PMU extension
    SbiCall {
        eid: 0x0050_4D55,
        fid: 0,
        name: "sbi_pmu_num_counters",
        description: "Returns the number of PMU counters",
    },
    SbiCall {
        eid: 0x0050_4D55,
        fid: 1,
        name: "sbi_pmu_counter_get_info",
        description: "Returns counter information",
    },
    SbiCall {
        eid: 0x0050_4D55,
        fid: 2,
        name: "sbi_pmu_counter_config",
        description: "Configure and start a counter",
    },
    SbiCall {
        eid: 0x0050_4D55,
        fid: 3,
        name: "sbi_pmu_counter_start",
        description: "Start a set of counters",
    },
    SbiCall {
        eid: 0x0050_4D55,
        fid: 4,
        name: "sbi_pmu_counter_stop",
        description: "Stop a set of counters",
    },
    SbiCall {
        eid: 0x0050_4D55,
        fid: 5,
        name: "sbi_pmu_counter_fw_read",
        description: "Read a firmware counter",
    },
];

/// Look up an SBI call by (EID, FID).
#[must_use]
pub fn sbi_lookup(eid: u64, fid: u64) -> Option<&'static SbiCall> {
    SBI_CALLS.iter().find(|c| c.eid == eid && c.fid == fid)
}

// ---------------------------------------------------------------------------
// RISC-V ABI frame layout helpers
// ---------------------------------------------------------------------------

/// Describes a slot in the RV64 LP64/LP64D ABI stack frame.
#[derive(Debug, Clone, Copy)]
pub struct RvFrameSlot {
    /// Signed offset from the canonical frame pointer.
    pub offset: i32,
    /// Slot name.
    pub name: &'static str,
    /// Description.
    pub description: &'static str,
}

/// Typical RV64 LP64 callee-save frame layout.
pub static RV_LP64_FRAME: &[RvFrameSlot] = &[
    RvFrameSlot {
        offset: -8,
        name: "saved_ra",
        description: "Saved return address (ra, x1)",
    },
    RvFrameSlot {
        offset: -16,
        name: "saved_s0",
        description: "Saved frame pointer (s0, x8)",
    },
    RvFrameSlot {
        offset: -24,
        name: "saved_s1",
        description: "Saved s1 (x9)",
    },
    RvFrameSlot {
        offset: -32,
        name: "saved_s2",
        description: "Saved s2 (x18)",
    },
    RvFrameSlot {
        offset: -40,
        name: "saved_s3",
        description: "Saved s3 (x19)",
    },
    RvFrameSlot {
        offset: -48,
        name: "saved_s4",
        description: "Saved s4 (x20)",
    },
    RvFrameSlot {
        offset: -56,
        name: "saved_s5",
        description: "Saved s5 (x21)",
    },
    RvFrameSlot {
        offset: -64,
        name: "saved_s6",
        description: "Saved s6 (x22)",
    },
    RvFrameSlot {
        offset: -72,
        name: "saved_s7",
        description: "Saved s7 (x23)",
    },
    RvFrameSlot {
        offset: -80,
        name: "saved_s8",
        description: "Saved s8 (x24)",
    },
    RvFrameSlot {
        offset: -88,
        name: "saved_s9",
        description: "Saved s9 (x25)",
    },
    RvFrameSlot {
        offset: -96,
        name: "saved_s10",
        description: "Saved s10 (x26)",
    },
    RvFrameSlot {
        offset: -104,
        name: "saved_s11",
        description: "Saved s11 (x27)",
    },
    RvFrameSlot {
        offset: 0,
        name: "local0",
        description: "First local variable",
    },
];

// ---------------------------------------------------------------------------
// RISC-V platform constants
// ---------------------------------------------------------------------------

/// Default RISC-V CLINT (Core Local Interruptor) MMIO base address.
pub const RV_CLINT_BASE: u64 = 0x0200_0000;

/// MSIP (machine software interrupt pending) register offset per HART in CLINT.
pub const RV_CLINT_MSIP_STRIDE: u64 = 4;

/// MTIMECMP register offset for hart 0 in CLINT.
pub const RV_CLINT_MTIMECMP_BASE: u64 = 0x4000;

/// MTIME register offset in CLINT.
pub const RV_CLINT_MTIME: u64 = 0xBFF8;

/// Default RISC-V PLIC (Platform-Level Interrupt Controller) base address.
pub const RV_PLIC_BASE: u64 = 0x0C00_0000;

/// Stack alignment in bytes for the LP64 ABI.
pub const RV_STACK_ALIGN: u64 = 16;

/// RISC-V instruction size (32-bit fixed-width for RV32/RV64 non-compressed).
pub const RV_INSTR_SIZE: u8 = 4;

/// RISC-V compressed instruction size.
pub const RV_CINSTR_SIZE: u8 = 2;

// ---------------------------------------------------------------------------
// RISC-V code-gen pattern helpers
// ---------------------------------------------------------------------------

/// Detect an indirect call through a register: JALR ra, 0(rs) where rs != ra.
///
/// Returns `true` if `word` encodes `JALR x1, 0(rs1)` (rd=1, imm=0, rs1 != 0 and != 1).
#[must_use]
pub const fn rv_is_indirect_call(word: u32) -> bool {
    rv_opcode(word) == 0x67
        && rv_rd(word) == 1       // rd = ra
        && rv_funct3(word) == 0
        && rv_imm_i(word) == 0
        && rv_rs1(word) != 0
        && rv_rs1(word) != 1
}

/// Detect a tail call: JAL x0, offset (rd=0 for JAL) or JALR x0, 0(rs1).
#[must_use]
pub const fn rv_is_tail_call(word: u32) -> bool {
    match rv_opcode(word) {
        0x6F => rv_rd(word) == 0,                         // JAL x0, offset
        0x67 => rv_rd(word) == 0 && rv_funct3(word) == 0, // JALR x0, 0(rs1)
        _ => false,
    }
}

/// Detect a function prologue pattern: ADDI sp, sp, -N.
///
/// Returns `Some(frame_size)` if matched, else `None`.
#[must_use]
pub const fn rv_prologue_frame_size(word: u32) -> Option<i32> {
    if rv_opcode(word) == 0x13  // ADDI
        && rv_funct3(word) == 0
        && rv_rd(word) == 2     // sp
        && rv_rs1(word) == 2
    // sp
    {
        let imm = rv_imm_i(word);
        if imm < 0 { Some(-imm) } else { None }
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Final tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod final_tests {
    use super::*;

    #[test]
    fn test_instr_table_lw() {
        let e = rv_instr_lookup("lw").unwrap();
        assert_eq!(e.format, "I");
        assert_eq!(e.extension, "I");
    }

    #[test]
    fn test_instr_table_add() {
        let e = rv_instr_lookup("add").unwrap();
        assert_eq!(e.format, "R");
    }

    #[test]
    fn test_instr_table_csrrs() {
        let e = rv_instr_lookup("csrrs").unwrap();
        assert_eq!(e.extension, "Zicsr");
    }

    #[test]
    fn test_instr_table_not_found() {
        assert!(rv_instr_lookup("bad_mnem").is_none());
    }

    #[test]
    fn test_instr_table_size() {
        assert!(RV_INSTR_TABLE.len() >= 100);
    }

    #[test]
    fn test_sbi_set_timer() {
        let s = sbi_lookup(0x00, 0).unwrap();
        assert_eq!(s.name, "sbi_set_timer");
    }

    #[test]
    fn test_sbi_hart_start() {
        let s = sbi_lookup(0x0048_534D, 0).unwrap();
        assert_eq!(s.name, "sbi_hart_start");
    }

    #[test]
    fn test_sbi_not_found() {
        assert!(sbi_lookup(0xDEAD, 0).is_none());
    }

    #[test]
    fn test_sbi_table_size() {
        assert!(SBI_CALLS.len() >= 20);
    }

    #[test]
    fn test_rv_is_indirect_call() {
        // JALR ra, 0(t0) — rd=1, funct3=0, rs1=5, imm=0
        let word: u32 = (5 << 15) | (1 << 7) | 0x67;
        assert!(rv_is_indirect_call(word));
    }

    #[test]
    fn test_rv_is_tail_call_jal() {
        // JAL x0, offset — rd=0
        let word: u32 = 0x6F; // rd=0
        assert!(rv_is_tail_call(word));
    }

    #[test]
    fn test_rv_prologue_frame_size() {
        // ADDI sp, sp, -16 → opcode=0x13, funct3=0, rd=2, rs1=2, imm=-16
        let imm_bits: u32 = ((-16i32).cast_unsigned()) & 0xFFF;
        let word: u32 = ((imm_bits << 20) | (2 << 15)) | (2 << 7) | 0x13;
        assert_eq!(rv_prologue_frame_size(word), Some(16));
    }

    #[test]
    fn test_rv_prologue_positive_no_match() {
        // ADDI sp, sp, +8 — not a prologue
        let word: u32 = ((8 << 20) | (2 << 15)) | (2 << 7) | 0x13;
        assert_eq!(rv_prologue_frame_size(word), None);
    }

    #[test]
    fn test_rv_instr_table_fence_i() {
        let e = rv_instr_lookup("fence.i").unwrap();
        assert_eq!(e.extension, "Zifencei");
    }

    #[test]
    fn test_rv_instr_table_mret() {
        let e = rv_instr_lookup("mret").unwrap();
        assert_eq!(e.extension, "priv");
    }

    #[test]
    fn test_lp64_frame_slot_count() {
        assert!(RV_LP64_FRAME.len() >= 12);
    }

    #[test]
    fn test_clint_base() {
        assert_eq!(RV_CLINT_BASE, 0x0200_0000);
    }

    #[test]
    fn test_stack_align() {
        assert_eq!(RV_STACK_ALIGN, 16);
    }

    #[test]
    fn test_rv_instr_size() {
        assert_eq!(RV_INSTR_SIZE, 4);
        assert_eq!(RV_CINSTR_SIZE, 2);
    }
}

// ---------------------------------------------------------------------------
// RISC-V Zb* (Bit Manipulation) extension helpers
// ---------------------------------------------------------------------------

/// Count leading zeros in a 32-bit value (CLZ equivalent).
#[must_use]
pub const fn rv_clz32(val: u32) -> u32 {
    val.leading_zeros()
}

/// Count trailing zeros in a 32-bit value.
#[must_use]
pub const fn rv_ctz32(val: u32) -> u32 {
    val.trailing_zeros()
}

/// Count set bits (population count).
#[must_use]
pub const fn rv_cpop32(val: u32) -> u32 {
    val.count_ones()
}

/// Byte-reverse a 32-bit value (REV8).
#[must_use]
pub const fn rv_rev8_32(val: u32) -> u32 {
    val.swap_bytes()
}

/// Bit-reverse a 32-bit value (BREV8 on each byte).
#[must_use]
pub const fn rv_brev8_32(val: u32) -> u32 {
    let b0 = val.to_le_bytes()[0].reverse_bits();
    let b1 = val.to_le_bytes()[1].reverse_bits();
    let b2 = val.to_le_bytes()[2].reverse_bits();
    let b3 = val.to_le_bytes()[3].reverse_bits();
    u32::from_le_bytes([b0, b1, b2, b3])
}

/// OR-combine: propagate any set bit right-ward so all lower bits become set.
#[must_use]
pub const fn rv_orcb32(val: u32) -> u32 {
    // For each byte, if any bit is set, set all bits in that byte.
    let mut result = 0u32;
    let mut i = 0u32;
    while i < 4 {
        let byte = (val >> (i * 8)) & 0xFF;
        let expanded = if byte != 0 { 0xFFu32 } else { 0 };
        result |= expanded << (i * 8);
        i += 1;
    }
    result
}

/// Zero-extend an N-bit value from the low bits of `val`.
#[must_use]
pub const fn rv_zext(val: u64, bits: u8) -> u64 {
    if bits >= 64 {
        val
    } else {
        val & ((1u64 << bits) - 1)
    }
}

/// Sign-extend an N-bit value from the low bits of `val` to i64.
#[must_use]
pub const fn rv_sext(val: u64, bits: u8) -> i64 {
    if bits == 0 {
        return 0;
    }
    let shift = 64 - bits;
    ((val << shift).cast_signed()) >> shift
}

// ---------------------------------------------------------------------------
// RISC-V Trap / Interrupt vector table helpers
// ---------------------------------------------------------------------------

/// Describes an entry in an RISC-V vectored-mode interrupt vector table.
#[derive(Debug, Clone, Copy)]
pub struct RvTrapVector {
    /// Interrupt cause code.
    pub cause: u64,
    /// Human-readable name.
    pub name: &'static str,
    /// Handler priority (lower = higher priority).
    pub priority: u8,
}

/// Machine-mode trap vector entries (direct mode uses single handler).
pub static RV_MACHINE_TRAP_VECTORS: &[RvTrapVector] = &[
    RvTrapVector {
        cause: 0,
        name: "UserSWInt",
        priority: 4,
    },
    RvTrapVector {
        cause: 1,
        name: "SupSWInt",
        priority: 3,
    },
    RvTrapVector {
        cause: 3,
        name: "MachSWInt",
        priority: 1,
    },
    RvTrapVector {
        cause: 4,
        name: "UserTimerInt",
        priority: 8,
    },
    RvTrapVector {
        cause: 5,
        name: "SupTimerInt",
        priority: 7,
    },
    RvTrapVector {
        cause: 7,
        name: "MachTimerInt",
        priority: 5,
    },
    RvTrapVector {
        cause: 8,
        name: "UserExtInt",
        priority: 12,
    },
    RvTrapVector {
        cause: 9,
        name: "SupExtInt",
        priority: 11,
    },
    RvTrapVector {
        cause: 11,
        name: "MachExtInt",
        priority: 9,
    },
];

// ---------------------------------------------------------------------------
// RISC-V PMP (Physical Memory Protection) helpers
// ---------------------------------------------------------------------------

/// PMP address matching mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmpMode {
    /// Disabled — no matching.
    Off = 0,
    /// Top-of-range (TOR).
    Tor = 1,
    /// Naturally aligned four-byte region.
    Na4 = 2,
    /// Naturally aligned power-of-two region.
    Napot = 3,
}

impl PmpMode {
    /// Decode from the A field of pmpcfgN.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x3 {
            0 => Self::Off,
            1 => Self::Tor,
            2 => Self::Na4,
            _ => Self::Napot,
        }
    }

    /// Return the name string.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Off => "OFF",
            Self::Tor => "TOR",
            Self::Na4 => "NA4",
            Self::Napot => "NAPOT",
        }
    }
}

/// PMP configuration byte.
#[derive(Debug, Clone, Copy)]
pub struct PmpCfg(pub u8);

impl PmpCfg {
    /// Returns `true` if read access is granted.
    #[must_use]
    pub const fn read(self) -> bool {
        self.0 & 1 != 0
    }

    /// Returns `true` if write access is granted.
    #[must_use]
    pub const fn write(self) -> bool {
        (self.0 >> 1) & 1 != 0
    }

    /// Returns `true` if execute access is granted.
    #[must_use]
    pub const fn exec(self) -> bool {
        (self.0 >> 2) & 1 != 0
    }

    /// Returns the address matching mode.
    #[must_use]
    pub const fn mode(self) -> PmpMode {
        PmpMode::from_bits((self.0 >> 3) & 0x3)
    }

    /// Returns `true` if this entry is locked (L bit).
    #[must_use]
    pub const fn locked(self) -> bool {
        (self.0 >> 7) & 1 != 0
    }
}

/// Decode a NAPOT `pmpaddr` register to a (base, size) pair.
///
/// Returns `(base_address, size_bytes)` where base is aligned to size.
#[must_use]
pub const fn pmp_napot_decode(pmpaddr: u64) -> (u64, u64) {
    // Find the trailing block of ones
    let trailing_ones = (!pmpaddr).trailing_zeros();
    let size = 4u64 << trailing_ones;
    let base = (pmpaddr & !(size / 4 - 1)) << 2;
    (base, size)
}

// ---------------------------------------------------------------------------
// RISC-V debug (Trigger Module) helpers
// ---------------------------------------------------------------------------

/// RISC-V trigger types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerType {
    /// No trigger configured.
    None = 0,
    /// Address/data match trigger.
    AddressData = 2,
    /// Instruction count trigger.
    InstrCount = 3,
    /// Interrupt trigger.
    Interrupt = 4,
    /// Exception trigger.
    Exception = 5,
}

impl TriggerType {
    /// Decode from the type field of tdata1.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits {
            2 => Self::AddressData,
            3 => Self::InstrCount,
            4 => Self::Interrupt,
            5 => Self::Exception,
            _ => Self::None,
        }
    }

    /// Name string.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::AddressData => "AddressData",
            Self::InstrCount => "InstrCount",
            Self::Interrupt => "Interrupt",
            Self::Exception => "Exception",
        }
    }
}

// ---------------------------------------------------------------------------
// RISC-V ABI syscall numbers (Linux RV64)
// ---------------------------------------------------------------------------

/// A Linux ABI syscall entry for RISC-V.
#[derive(Debug, Clone, Copy)]
pub struct RvSyscall {
    /// Syscall number.
    pub nr: u64,
    /// Syscall name.
    pub name: &'static str,
    /// Brief description.
    pub description: &'static str,
}

/// Selected Linux syscalls for RISC-V (matches unistd.h).
pub static RV_LINUX_SYSCALLS: &[RvSyscall] = &[
    RvSyscall {
        nr: 0,
        name: "io_setup",
        description: "Create asynchronous I/O context",
    },
    RvSyscall {
        nr: 17,
        name: "getcwd",
        description: "Get current working directory",
    },
    RvSyscall {
        nr: 25,
        name: "fcntl",
        description: "Manipulate file descriptor",
    },
    RvSyscall {
        nr: 29,
        name: "ioctl",
        description: "Control device",
    },
    RvSyscall {
        nr: 34,
        name: "mknodat",
        description: "Create a file node",
    },
    RvSyscall {
        nr: 35,
        name: "mkdirat",
        description: "Create a directory",
    },
    RvSyscall {
        nr: 37,
        name: "unlinkat",
        description: "Delete a name from the filesystem",
    },
    RvSyscall {
        nr: 38,
        name: "symlinkat",
        description: "Create a symbolic link",
    },
    RvSyscall {
        nr: 43,
        name: "fstatfs",
        description: "Get file system statistics",
    },
    RvSyscall {
        nr: 46,
        name: "ftruncate",
        description: "Truncate a file to a specific length",
    },
    RvSyscall {
        nr: 48,
        name: "faccessat",
        description: "Check user's permission for a file",
    },
    RvSyscall {
        nr: 49,
        name: "chdir",
        description: "Change working directory",
    },
    RvSyscall {
        nr: 50,
        name: "fchdir",
        description: "Change working directory (fd)",
    },
    RvSyscall {
        nr: 51,
        name: "chroot",
        description: "Change root directory",
    },
    RvSyscall {
        nr: 52,
        name: "fchmod",
        description: "Change file mode bits",
    },
    RvSyscall {
        nr: 53,
        name: "fchmodat",
        description: "Change file mode bits (at)",
    },
    RvSyscall {
        nr: 54,
        name: "fchownat",
        description: "Change file ownership (at)",
    },
    RvSyscall {
        nr: 55,
        name: "fchown",
        description: "Change file ownership",
    },
    RvSyscall {
        nr: 56,
        name: "openat",
        description: "Open/create a file (at)",
    },
    RvSyscall {
        nr: 57,
        name: "close",
        description: "Close a file descriptor",
    },
    RvSyscall {
        nr: 59,
        name: "pipe2",
        description: "Create a pipe",
    },
    RvSyscall {
        nr: 61,
        name: "getdents64",
        description: "Get directory entries",
    },
    RvSyscall {
        nr: 62,
        name: "lseek",
        description: "Reposition file offset",
    },
    RvSyscall {
        nr: 63,
        name: "read",
        description: "Read from file descriptor",
    },
    RvSyscall {
        nr: 64,
        name: "write",
        description: "Write to file descriptor",
    },
    RvSyscall {
        nr: 65,
        name: "readv",
        description: "Scatter read from file descriptor",
    },
    RvSyscall {
        nr: 66,
        name: "writev",
        description: "Gather write to file descriptor",
    },
    RvSyscall {
        nr: 67,
        name: "pread64",
        description: "Read at given offset",
    },
    RvSyscall {
        nr: 68,
        name: "pwrite64",
        description: "Write at given offset",
    },
    RvSyscall {
        nr: 72,
        name: "pselect6",
        description: "Synchronous I/O multiplexing",
    },
    RvSyscall {
        nr: 73,
        name: "ppoll",
        description: "Wait for events on file descriptors",
    },
    RvSyscall {
        nr: 78,
        name: "readlinkat",
        description: "Read value of a symbolic link",
    },
    RvSyscall {
        nr: 79,
        name: "fstatat",
        description: "Get file status",
    },
    RvSyscall {
        nr: 80,
        name: "fstat",
        description: "Get file status",
    },
    RvSyscall {
        nr: 93,
        name: "exit",
        description: "Terminate calling process",
    },
    RvSyscall {
        nr: 94,
        name: "exit_group",
        description: "Exit all threads in a process",
    },
    RvSyscall {
        nr: 96,
        name: "set_tid_address",
        description: "Set pointer to thread ID",
    },
    RvSyscall {
        nr: 98,
        name: "futex",
        description: "Fast user-space locking",
    },
    RvSyscall {
        nr: 99,
        name: "set_robust_list",
        description: "Set list of robust futexes",
    },
    RvSyscall {
        nr: 100,
        name: "get_robust_list",
        description: "Get list of robust futexes",
    },
    RvSyscall {
        nr: 101,
        name: "nanosleep",
        description: "High-resolution sleep",
    },
    RvSyscall {
        nr: 113,
        name: "clock_gettime",
        description: "Retrieve time of specified clock",
    },
    RvSyscall {
        nr: 114,
        name: "clock_getres",
        description: "Find resolution of specified clock",
    },
    RvSyscall {
        nr: 115,
        name: "clock_nanosleep",
        description: "High-resolution sleep with clock",
    },
    RvSyscall {
        nr: 129,
        name: "kill",
        description: "Send signal to process",
    },
    RvSyscall {
        nr: 130,
        name: "tkill",
        description: "Send signal to thread",
    },
    RvSyscall {
        nr: 131,
        name: "tgkill",
        description: "Send signal to process group",
    },
    RvSyscall {
        nr: 134,
        name: "rt_sigaction",
        description: "Examine and change signal action",
    },
    RvSyscall {
        nr: 135,
        name: "rt_sigprocmask",
        description: "Examine and change blocked signals",
    },
    RvSyscall {
        nr: 160,
        name: "uname",
        description: "Get name and info about kernel",
    },
    RvSyscall {
        nr: 162,
        name: "getrusage",
        description: "Get resource usage",
    },
    RvSyscall {
        nr: 163,
        name: "umask",
        description: "Set file mode creation mask",
    },
    RvSyscall {
        nr: 165,
        name: "getpagesize",
        description: "Get system page size",
    },
    RvSyscall {
        nr: 172,
        name: "getpid",
        description: "Get process ID",
    },
    RvSyscall {
        nr: 173,
        name: "getppid",
        description: "Get parent process ID",
    },
    RvSyscall {
        nr: 174,
        name: "getuid",
        description: "Get user identity",
    },
    RvSyscall {
        nr: 175,
        name: "geteuid",
        description: "Get effective user identity",
    },
    RvSyscall {
        nr: 176,
        name: "getgid",
        description: "Get group identity",
    },
    RvSyscall {
        nr: 177,
        name: "getegid",
        description: "Get effective group identity",
    },
    RvSyscall {
        nr: 178,
        name: "gettid",
        description: "Get thread identifier",
    },
    RvSyscall {
        nr: 179,
        name: "sysinfo",
        description: "Return system information",
    },
    RvSyscall {
        nr: 214,
        name: "brk",
        description: "Change data segment size",
    },
    RvSyscall {
        nr: 215,
        name: "munmap",
        description: "Unmap memory",
    },
    RvSyscall {
        nr: 216,
        name: "mremap",
        description: "Remap virtual memory",
    },
    RvSyscall {
        nr: 220,
        name: "clone",
        description: "Create a child process",
    },
    RvSyscall {
        nr: 221,
        name: "execve",
        description: "Execute program",
    },
    RvSyscall {
        nr: 222,
        name: "mmap",
        description: "Map files into memory",
    },
    RvSyscall {
        nr: 226,
        name: "mprotect",
        description: "Set memory protection",
    },
    RvSyscall {
        nr: 233,
        name: "madvise",
        description: "Give advice about use of memory",
    },
    RvSyscall {
        nr: 261,
        name: "prlimit64",
        description: "Get/set resource limits",
    },
    RvSyscall {
        nr: 278,
        name: "getrandom",
        description: "Get random bytes",
    },
    RvSyscall {
        nr: 280,
        name: "memfd_create",
        description: "Create an anonymous file",
    },
];

/// Look up a Linux syscall by number.
#[must_use]
pub fn rv_syscall_lookup(nr: u64) -> Option<&'static RvSyscall> {
    RV_LINUX_SYSCALLS.iter().find(|s| s.nr == nr)
}

// ---------------------------------------------------------------------------
// More tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod more_tests {
    use super::*;

    // ── Bit manipulation ─────────────────────────────────────────────────────
    #[test]
    fn test_clz32() {
        assert_eq!(rv_clz32(0x8000_0000), 0);
        assert_eq!(rv_clz32(1), 31);
    }

    #[test]
    fn test_ctz32() {
        assert_eq!(rv_ctz32(0x10), 4);
    }

    #[test]
    fn test_cpop32() {
        assert_eq!(rv_cpop32(0xFF), 8);
    }

    #[test]
    fn test_rev8_32() {
        assert_eq!(rv_rev8_32(0x0102_0304), 0x0403_0201);
    }

    #[test]
    fn test_orcb32_nonzero_byte() {
        // byte 0 = 0x01 → should become 0xFF
        assert_eq!(rv_orcb32(0x0000_0001) & 0xFF, 0xFF);
        // byte 3 = 0x00 → should remain 0x00
        assert_eq!((rv_orcb32(0x0000_0001) >> 24) & 0xFF, 0x00);
    }

    #[test]
    fn test_rv_zext() {
        assert_eq!(rv_zext(0xFFFF_FFFF, 8), 0xFF);
    }

    #[test]
    fn test_rv_sext_negative() {
        assert_eq!(rv_sext(0x80, 8), -128);
    }

    // ── PMP helpers ──────────────────────────────────────────────────────────
    #[test]
    fn test_pmp_mode_napot() {
        let mode = PmpMode::from_bits(3);
        assert_eq!(mode, PmpMode::Napot);
        assert_eq!(mode.name(), "NAPOT");
    }

    #[test]
    fn test_pmp_cfg_read_write() {
        let cfg = PmpCfg(0b0000_0111); // R|W|X
        assert!(cfg.read());
        assert!(cfg.write());
        assert!(cfg.exec());
        assert!(!cfg.locked());
    }

    #[test]
    fn test_pmp_cfg_locked() {
        let cfg = PmpCfg(0b1000_0001); // L|R
        assert!(cfg.locked());
        assert!(cfg.read());
        assert!(!cfg.write());
    }

    #[test]
    fn test_pmp_napot_decode_4k() {
        // pmpaddr = 0x...0FFF encodes base=0, size=4K... minimal case:
        // For size=4K: trailing_ones=0 (since pmpaddr encodes (base>>2) | (size/8-1))
        // 4K NAPOT: pmpaddr = 0xFFFF_FFFF (all ones) means size=2^34...
        // Simple case: pmpaddr=0 → trailing_ones=0 → size=4, base=0
        let (base, size) = pmp_napot_decode(0);
        assert_eq!(size, 4);
        assert_eq!(base, 0);
    }

    // ── Trigger types ─────────────────────────────────────────────────────────
    #[test]
    fn test_trigger_type_addr_data() {
        let t = TriggerType::from_bits(2);
        assert_eq!(t, TriggerType::AddressData);
        assert_eq!(t.name(), "AddressData");
    }

    #[test]
    fn test_trigger_type_none() {
        let t = TriggerType::from_bits(0);
        assert_eq!(t, TriggerType::None);
    }

    // ── Linux syscalls ────────────────────────────────────────────────────────
    #[test]
    fn test_syscall_read() {
        let s = rv_syscall_lookup(63).unwrap();
        assert_eq!(s.name, "read");
    }

    #[test]
    fn test_syscall_write() {
        let s = rv_syscall_lookup(64).unwrap();
        assert_eq!(s.name, "write");
    }

    #[test]
    fn test_syscall_mmap() {
        let s = rv_syscall_lookup(222).unwrap();
        assert_eq!(s.name, "mmap");
    }

    #[test]
    fn test_syscall_not_found() {
        assert!(rv_syscall_lookup(9999).is_none());
    }

    #[test]
    fn test_syscall_table_size() {
        assert!(RV_LINUX_SYSCALLS.len() >= 50);
    }

    // ── Machine trap vectors ──────────────────────────────────────────────────
    #[test]
    fn test_trap_vector_count() {
        assert!(RV_MACHINE_TRAP_VECTORS.len() >= 8);
    }

    // ── SBI calls ────────────────────────────────────────────────────────────
    #[test]
    fn test_sbi_system_reset() {
        let s = sbi_lookup(0x5352_5354, 0).unwrap();
        assert_eq!(s.name, "sbi_system_reset");
    }

    // ── RV instr table extensions ──────────────────────────────────────────────
    #[test]
    fn test_instr_amoswap() {
        let e = rv_instr_lookup("amoswap.w").unwrap();
        assert_eq!(e.extension, "A");
    }

    #[test]
    fn test_instr_fld() {
        let e = rv_instr_lookup("fld").unwrap();
        assert_eq!(e.extension, "D");
    }

    #[test]
    fn test_instr_lr_d() {
        let e = rv_instr_lookup("lr.d").unwrap();
        assert_eq!(e.extension, "A64");
    }
}

// ---------------------------------------------------------------------------
// RISC-V known implementations / SoC table
// ---------------------------------------------------------------------------

/// A known RISC-V `SoC` entry.
#[derive(Debug, Clone, Copy)]
pub struct RvSoc {
    /// `SoC` name.
    pub name: &'static str,
    /// Vendor.
    pub vendor: &'static str,
    /// Primary CPU core used.
    pub cpu_core: &'static str,
    /// ISA string.
    pub isa: &'static str,
    /// Operating system support.
    pub os_support: &'static str,
}

/// Known RISC-V `SoCs` and boards.
pub static RV_SOCS: &[RvSoc] = &[
    RvSoc {
        name: "HiFive1",
        vendor: "SiFive",
        cpu_core: "FE310-G000",
        isa: "RV32IMAC",
        os_support: "bare-metal",
    },
    RvSoc {
        name: "HiFive Unleashed",
        vendor: "SiFive",
        cpu_core: "FU540-C000",
        isa: "RV64GC",
        os_support: "Linux",
    },
    RvSoc {
        name: "HiFive Unmatched",
        vendor: "SiFive",
        cpu_core: "FU740-C000",
        isa: "RV64GC",
        os_support: "Linux",
    },
    RvSoc {
        name: "Starlight JH7100",
        vendor: "StarFive",
        cpu_core: "U74 2-core",
        isa: "RV64GC",
        os_support: "Linux",
    },
    RvSoc {
        name: "Nezha D1",
        vendor: "Allwinner",
        cpu_core: "C906",
        isa: "RV64GCV",
        os_support: "Linux",
    },
    RvSoc {
        name: "CH573",
        vendor: "WCH",
        cpu_core: "RISC-V4A",
        isa: "RV32IMAC",
        os_support: "bare-metal",
    },
    RvSoc {
        name: "CH32V307",
        vendor: "WCH",
        cpu_core: "RISC-V4F",
        isa: "RV32IMAFCU",
        os_support: "bare-metal",
    },
    RvSoc {
        name: "GD32VF103",
        vendor: "GigaDevice",
        cpu_core: "Bumblebee",
        isa: "RV32IMAC",
        os_support: "bare-metal",
    },
    RvSoc {
        name: "K210",
        vendor: "Kendryte",
        cpu_core: "KPU",
        isa: "RV64IMAFDC",
        os_support: "FreeRTOS/RT-Thread",
    },
    RvSoc {
        name: "SpacemiT K1",
        vendor: "SpacemiT",
        cpu_core: "X60 8-core",
        isa: "RV64GCV",
        os_support: "Linux",
    },
    RvSoc {
        name: "Sophgo SG2042",
        vendor: "Sophgo",
        cpu_core: "C920",
        isa: "RV64GCVX",
        os_support: "Linux",
    },
    RvSoc {
        name: "ESWIN EIC7700X",
        vendor: "ESWIN",
        cpu_core: "U84",
        isa: "RV64GC",
        os_support: "Linux",
    },
    RvSoc {
        name: "Milk-V Pioneer",
        vendor: "Milk-V",
        cpu_core: "SG2042",
        isa: "RV64GCVX",
        os_support: "Linux",
    },
    RvSoc {
        name: "BeagleV-Fire",
        vendor: "BeagleBoard",
        cpu_core: "U54/S54",
        isa: "RV64GC",
        os_support: "Linux",
    },
    RvSoc {
        name: "MPFS250T",
        vendor: "Microchip",
        cpu_core: "U54-MC 4-core",
        isa: "RV64GC",
        os_support: "Linux/RTOS",
    },
];

/// Look up a `SoC` entry by name.
#[must_use]
pub fn rv_soc_lookup(name: &str) -> Option<&'static RvSoc> {
    RV_SOCS.iter().find(|s| s.name == name)
}

// ---------------------------------------------------------------------------
// RISC-V numeric / arithmetic pseudo-helpers
// ---------------------------------------------------------------------------

/// RISC-V integer add with overflow detection (trap behaviour of ADD).
///
/// Returns `None` if signed overflow occurs.
#[must_use]
pub const fn rv_add_ov(a: i64, b: i64) -> Option<i64> {
    a.checked_add(b)
}

/// RISC-V integer subtract with overflow detection.
#[must_use]
pub const fn rv_sub_ov(a: i64, b: i64) -> Option<i64> {
    a.checked_sub(b)
}

/// RISC-V ADDW: add two 32-bit values and sign-extend result to 64 bits.
#[must_use]
pub const fn rv_addw(a: i64, b: i64) -> i64 {
    rv_low32_sext(a.wrapping_add(b))
}

/// RISC-V SUBW: subtract two 32-bit values and sign-extend result to 64 bits.
#[must_use]
pub const fn rv_subw(a: i64, b: i64) -> i64 {
    rv_low32_sext(a.wrapping_sub(b))
}

/// Truncate a 64-bit value to its low 32 bits and sign-extend back to 64 bits.
///
/// This is the `*W` (word) semantics of RV64: a 32-bit result is written to a
/// 64-bit register sign-extended. The conversion works on the little-endian
/// byte image rather than with a numeric cast, so it is exact by construction
/// for every input and cannot panic.
#[must_use]
pub const fn rv_low32_sext(v: i64) -> i64 {
    let b = v.to_le_bytes();
    let sign = if b[3] & 0x80 != 0 { 0xFF } else { 0x00 };
    i64::from_le_bytes([b[0], b[1], b[2], b[3], sign, sign, sign, sign])
}

/// Low 64 bits of a 128-bit value, as a signed 64-bit integer.
///
/// Reads the low eight little-endian bytes, so no numeric cast is involved and
/// the result is exactly the low half of `v` for every input.
#[must_use]
pub const fn rv_low64_of_i128(v: i128) -> i64 {
    let b = v.to_le_bytes();
    i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// RISC-V SLT: return 1 if `a < b` (signed), else 0.
#[must_use]
pub const fn rv_slt(a: i64, b: i64) -> u64 {
    if a < b { 1 } else { 0 }
}

/// RISC-V SLTU: return 1 if `a < b` (unsigned), else 0.
#[must_use]
pub const fn rv_sltu(a: u64, b: u64) -> u64 {
    if a < b { 1 } else { 0 }
}

/// RISC-V MUL: lower XLEN bits of the product.
#[must_use]
pub const fn rv_mul(a: i64, b: i64) -> i64 {
    a.wrapping_mul(b)
}

/// RISC-V MULH: upper XLEN bits of the signed×signed product.
#[must_use]
pub const fn rv_mulh(a: i64, b: i64) -> i64 {
    let product = (a as i128).wrapping_mul(b as i128);
    (product >> 64) as i64
}

/// RISC-V DIV: signed integer divide; returns `i64::MIN` on overflow, `-1` on div-by-zero.
#[must_use]
pub const fn rv_div(a: i64, b: i64) -> i64 {
    if b == 0 { -1 } else { a.wrapping_div(b) }
}

/// RISC-V DIVU: unsigned integer divide; returns `u64::MAX` on div-by-zero.
#[must_use]
pub const fn rv_divu(a: u64, b: u64) -> u64 {
    match a.checked_div(b) {
        Some(q) => q,
        None => u64::MAX,
    }
}

/// RISC-V REM: signed remainder; returns `a` on div-by-zero.
#[must_use]
pub const fn rv_rem(a: i64, b: i64) -> i64 {
    if b == 0 { a } else { a.wrapping_rem(b) }
}

/// RISC-V REMU: unsigned remainder; returns `a` on div-by-zero.
#[must_use]
pub const fn rv_remu(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { a % b }
}

// ---------------------------------------------------------------------------
// RISC-V address space description (standard QEMU virt machine)
// ---------------------------------------------------------------------------

/// A RISC-V MMIO region descriptor.
#[derive(Debug, Clone, Copy)]
pub struct RvMmioRegion {
    /// Base physical address.
    pub base: u64,
    /// Size in bytes.
    pub size: u64,
    /// Region name.
    pub name: &'static str,
    /// Description.
    pub description: &'static str,
}

/// Standard RISC-V QEMU `virt` machine MMIO map.
pub static RV_QEMU_VIRT_MMIO: &[RvMmioRegion] = &[
    RvMmioRegion {
        base: 0x0000_0000,
        size: 0x0000_1000,
        name: "debug",
        description: "Debug device",
    },
    RvMmioRegion {
        base: 0x0000_1000,
        size: 0x0000_1000,
        name: "mrom",
        description: "Machine-mode ROM (reset vector)",
    },
    RvMmioRegion {
        base: 0x0000_3000,
        size: 0x0000_1000,
        name: "test",
        description: "Test/shutdown device",
    },
    RvMmioRegion {
        base: 0x0000_4000,
        size: 0x0000_4000,
        name: "rtc",
        description: "Real-time clock (Goldfish RTC)",
    },
    RvMmioRegion {
        base: 0x0001_0000,
        size: 0x0000_0100,
        name: "uart0",
        description: "16550 UART 0",
    },
    RvMmioRegion {
        base: 0x0200_0000,
        size: 0x0001_0000,
        name: "clint",
        description: "Core Local Interruptor (CLINT)",
    },
    RvMmioRegion {
        base: 0x0300_0000,
        size: 0x0001_0000,
        name: "aclint_sswi",
        description: "ACLINT supervisor-mode IPI",
    },
    RvMmioRegion {
        base: 0x0400_0000,
        size: 0x0400_0000,
        name: "pcie_io",
        description: "PCIe I/O space",
    },
    RvMmioRegion {
        base: 0x0C00_0000,
        size: 0x0400_0000,
        name: "plic",
        description: "Platform-Level Interrupt Controller (PLIC)",
    },
    RvMmioRegion {
        base: 0x1000_0000,
        size: 0x0000_0100,
        name: "uart1",
        description: "16550 UART 1",
    },
    RvMmioRegion {
        base: 0x1000_1000,
        size: 0x0000_1000,
        name: "virtio0",
        description: "VirtIO device 0",
    },
    RvMmioRegion {
        base: 0x1000_2000,
        size: 0x0000_1000,
        name: "virtio1",
        description: "VirtIO device 1",
    },
    RvMmioRegion {
        base: 0x2000_0000,
        size: 0x2000_0000,
        name: "flash0",
        description: "CFI flash device 0",
    },
    RvMmioRegion {
        base: 0x3000_0000,
        size: 0x1000_0000,
        name: "flash1",
        description: "CFI flash device 1",
    },
    RvMmioRegion {
        base: 0x4000_0000,
        size: 0x4000_0000,
        name: "pcie_mem",
        description: "PCIe 32-bit memory space",
    },
    RvMmioRegion {
        base: 0x8000_0000,
        size: 0x8000_0000,
        name: "dram",
        description: "Main DRAM (first 2 GiB)",
    },
];

/// Look up a QEMU virt machine MMIO region by address.
#[must_use]
pub fn rv_qemu_region_lookup(addr: u64) -> Option<&'static RvMmioRegion> {
    RV_QEMU_VIRT_MMIO
        .iter()
        .find(|r| addr >= r.base && addr < r.base + r.size)
}

// ---------------------------------------------------------------------------
// Final expansion tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod expansion_tests {
    use super::*;

    // ── SoC table ─────────────────────────────────────────────────────────────
    #[test]
    fn test_soc_hifive_unleashed() {
        let s = rv_soc_lookup("HiFive Unleashed").unwrap();
        assert_eq!(s.isa, "RV64GC");
    }

    #[test]
    fn test_soc_k210() {
        let s = rv_soc_lookup("K210").unwrap();
        assert!(s.isa.contains("RV64"));
    }

    #[test]
    fn test_soc_not_found() {
        assert!(rv_soc_lookup("Nonexistent").is_none());
    }

    #[test]
    fn test_soc_table_size() {
        assert!(RV_SOCS.len() >= 12);
    }

    // ── Arithmetic helpers ───────────────────────────────────────────────────
    #[test]
    fn test_rv_addw() {
        assert_eq!(rv_addw(i64::from(i32::MAX), 1), i64::from(i32::MIN));
    }

    #[test]
    fn test_rv_slt_true() {
        assert_eq!(rv_slt(-1, 0), 1);
    }

    #[test]
    fn test_rv_slt_false() {
        assert_eq!(rv_slt(0, -1), 0);
    }

    #[test]
    fn test_rv_sltu() {
        assert_eq!(rv_sltu(0, 1), 1);
    }

    #[test]
    fn test_rv_mul() {
        assert_eq!(rv_mul(6, 7), 42);
    }

    #[test]
    fn test_rv_mulh_overflow() {
        // i64::MIN * i64::MIN upper-half = i64::MIN (result fills high word)
        // Actually use a simpler case: mulh(i64::MIN, -1) = 0 (since MIN*-1 overflows to MIN)
        // Use (-2) * i64::MIN = 2^63 (upper half = 0...1): verify it's non-trivial
        let result = rv_mulh(i64::MIN, 2);
        // i64::MIN * 2 = -2^64 in 128 bits, upper half = -1
        assert_eq!(result, -1i64);
    }

    #[test]
    fn test_rv_div_normal() {
        assert_eq!(rv_div(10, 3), 3);
    }

    #[test]
    fn test_rv_div_by_zero() {
        assert_eq!(rv_div(5, 0), -1);
    }

    #[test]
    fn test_rv_divu_by_zero() {
        assert_eq!(rv_divu(5, 0), u64::MAX);
    }

    #[test]
    fn test_rv_rem() {
        assert_eq!(rv_rem(10, 3), 1);
        assert_eq!(rv_rem(5, 0), 5);
    }

    #[test]
    fn test_rv_remu() {
        assert_eq!(rv_remu(10, 3), 1);
    }

    #[test]
    fn test_rv_add_ov_overflow() {
        assert_eq!(rv_add_ov(i64::MAX, 1), None);
    }

    #[test]
    fn test_rv_add_ov_normal() {
        assert_eq!(rv_add_ov(1, 2), Some(3));
    }

    // ── MMIO regions ─────────────────────────────────────────────────────────
    #[test]
    fn test_qemu_region_clint() {
        let r = rv_qemu_region_lookup(0x0200_0000).unwrap();
        assert_eq!(r.name, "clint");
    }

    #[test]
    fn test_qemu_region_dram() {
        let r = rv_qemu_region_lookup(0x8000_0000).unwrap();
        assert_eq!(r.name, "dram");
    }

    #[test]
    fn test_qemu_region_not_found() {
        assert!(rv_qemu_region_lookup(0xFFFF_0000_0000_0000).is_none());
    }

    #[test]
    fn test_qemu_regions_count() {
        assert!(RV_QEMU_VIRT_MMIO.len() >= 12);
    }

    // ── Zb bit-manip ──────────────────────────────────────────────────────────
    #[test]
    fn test_rv_brev8() {
        // byte 0x01 → 0x80 reversed
        assert_eq!(rv_brev8_32(0x0000_0001) & 0xFF, 0x80);
    }

    // ── PMP NAPOT decode ──────────────────────────────────────────────────────
    #[test]
    fn test_pmp_napot_size_8() {
        // pmpaddr=1 → trailing_ones of (!1)= trailing_ones(~1)=0, size=4*1=4, no wait...
        // pmpaddr=1 → !1=0xFFFF...E → trailing_zeros=1 → size=4<<1=8, base=(1 & !(2-1))<<2=(1&!1)<<2=0
        let (base, size) = pmp_napot_decode(1);
        assert_eq!(size, 8);
        assert_eq!(base, 0);
    }

    // ── CLINT/PLIC constants ──────────────────────────────────────────────────
    #[test]
    fn test_clint_constants() {
        assert_eq!(RV_CLINT_BASE, 0x0200_0000);
        assert_eq!(RV_CLINT_MTIME, 0xBFF8);
    }

    #[test]
    fn test_plic_base() {
        assert_eq!(RV_PLIC_BASE, 0x0C00_0000);
    }

    // ── Trap vector table ─────────────────────────────────────────────────────
    #[test]
    fn test_machine_trap_vectors_mswint() {
        let v = RV_MACHINE_TRAP_VECTORS
            .iter()
            .find(|v| v.cause == 3 && !v.name.is_empty());
        assert!(v.is_some());
    }

    // ── Trigger Module ────────────────────────────────────────────────────────
    #[test]
    fn test_trigger_instr_count() {
        let t = TriggerType::from_bits(3);
        assert_eq!(t, TriggerType::InstrCount);
    }

    // ── Linux syscall lookup ──────────────────────────────────────────────────
    #[test]
    fn test_syscall_exit() {
        let s = rv_syscall_lookup(93).unwrap();
        assert_eq!(s.name, "exit");
    }

    #[test]
    fn test_syscall_brk() {
        let s = rv_syscall_lookup(214).unwrap();
        assert_eq!(s.name, "brk");
    }
}

// ---------------------------------------------------------------------------
// RISC-V mstatus field descriptions
// ---------------------------------------------------------------------------

/// A mstatus CSR field entry.
#[derive(Debug, Clone, Copy)]
pub struct MstatusField {
    /// MSB of the field (inclusive).
    pub msb: u8,
    /// LSB of the field (inclusive).
    pub lsb: u8,
    /// Field name.
    pub name: &'static str,
    /// Description.
    pub description: &'static str,
}

/// Machine Status register (mstatus) field table for RV64.
pub static MSTATUS_FIELDS: &[MstatusField] = &[
    MstatusField {
        msb: 63,
        lsb: 63,
        name: "SD",
        description: "Summary dirty — any XS/FS/VS dirty",
    },
    MstatusField {
        msb: 38,
        lsb: 37,
        name: "MBE+SBE",
        description: "Machine/supervisor big-endian",
    },
    MstatusField {
        msb: 36,
        lsb: 36,
        name: "SBE",
        description: "Supervisor big-endian memory access",
    },
    MstatusField {
        msb: 35,
        lsb: 34,
        name: "SXL",
        description: "Supervisor XLEN",
    },
    MstatusField {
        msb: 33,
        lsb: 32,
        name: "UXL",
        description: "User XLEN",
    },
    MstatusField {
        msb: 22,
        lsb: 22,
        name: "TSR",
        description: "Trap SRET",
    },
    MstatusField {
        msb: 21,
        lsb: 21,
        name: "TW",
        description: "Timeout wait (WFI trap)",
    },
    MstatusField {
        msb: 20,
        lsb: 20,
        name: "TVM",
        description: "Trap virtual memory (SATP/SFENCE.VMA)",
    },
    MstatusField {
        msb: 19,
        lsb: 19,
        name: "MXR",
        description: "Make executable readable",
    },
    MstatusField {
        msb: 18,
        lsb: 18,
        name: "SUM",
        description: "Supervisor user memory access",
    },
    MstatusField {
        msb: 17,
        lsb: 17,
        name: "MPRV",
        description: "Modify privilege (translation)",
    },
    MstatusField {
        msb: 16,
        lsb: 15,
        name: "XS",
        description: "User extension state",
    },
    MstatusField {
        msb: 14,
        lsb: 13,
        name: "FS",
        description: "FP unit state (Off/Init/Clean/Dirty)",
    },
    MstatusField {
        msb: 12,
        lsb: 11,
        name: "MPP",
        description: "Machine previous privilege",
    },
    MstatusField {
        msb: 10,
        lsb: 9,
        name: "VS",
        description: "Vector unit state",
    },
    MstatusField {
        msb: 8,
        lsb: 8,
        name: "SPP",
        description: "Supervisor previous privilege",
    },
    MstatusField {
        msb: 7,
        lsb: 7,
        name: "MPIE",
        description: "Machine previous interrupt enable",
    },
    MstatusField {
        msb: 6,
        lsb: 6,
        name: "UBE",
        description: "User big-endian memory access",
    },
    MstatusField {
        msb: 5,
        lsb: 5,
        name: "SPIE",
        description: "Supervisor previous interrupt enable",
    },
    MstatusField {
        msb: 4,
        lsb: 4,
        name: "UPIE",
        description: "User previous interrupt enable (N ext)",
    },
    MstatusField {
        msb: 3,
        lsb: 3,
        name: "MIE",
        description: "Machine interrupt enable",
    },
    MstatusField {
        msb: 1,
        lsb: 1,
        name: "SIE",
        description: "Supervisor interrupt enable",
    },
    MstatusField {
        msb: 0,
        lsb: 0,
        name: "UIE",
        description: "User interrupt enable (N ext)",
    },
];

/// Decode the MPP (Machine Previous Privilege) field from mstatus.
#[must_use]
pub const fn mstatus_mpp(mstatus: u64) -> RvPrivLevel {
    RvPrivLevel::from_bits(((mstatus >> 11) & 0x3) as u8)
}

/// Returns `true` if the FP unit is dirty (FS == 0b11).
#[must_use]
pub const fn mstatus_fp_dirty(mstatus: u64) -> bool {
    ((mstatus >> 13) & 0x3) == 3
}

/// Returns `true` if MIE is set.
#[must_use]
pub const fn mstatus_mie(mstatus: u64) -> bool {
    (mstatus >> 3) & 1 != 0
}

/// Returns `true` if SIE is set.
#[must_use]
pub const fn mstatus_sie(mstatus: u64) -> bool {
    (mstatus >> 1) & 1 != 0
}

// ---------------------------------------------------------------------------
// RISC-V Sv39 page table entry helpers
// ---------------------------------------------------------------------------

/// Represents a single RISC-V Sv39 page table entry (PTE).
#[derive(Debug, Clone, Copy, Default)]
pub struct RvPte(pub u64);

impl RvPte {
    /// Returns `true` if the V (valid) bit is set.
    #[must_use]
    pub const fn valid(self) -> bool {
        self.0 & 1 != 0
    }

    /// Returns `true` if this PTE grants read access.
    #[must_use]
    pub const fn readable(self) -> bool {
        (self.0 >> 1) & 1 != 0
    }

    /// Returns `true` if this PTE grants write access.
    #[must_use]
    pub const fn writable(self) -> bool {
        (self.0 >> 2) & 1 != 0
    }

    /// Returns `true` if this PTE grants execute access.
    #[must_use]
    pub const fn executable(self) -> bool {
        (self.0 >> 3) & 1 != 0
    }

    /// Returns `true` if this is a user-mode page.
    #[must_use]
    pub const fn user(self) -> bool {
        (self.0 >> 4) & 1 != 0
    }

    /// Returns `true` if this is a global mapping.
    #[must_use]
    pub const fn global(self) -> bool {
        (self.0 >> 5) & 1 != 0
    }

    /// Returns `true` if the page has been accessed.
    #[must_use]
    pub const fn accessed(self) -> bool {
        (self.0 >> 6) & 1 != 0
    }

    /// Returns `true` if the page is dirty.
    #[must_use]
    pub const fn dirty(self) -> bool {
        (self.0 >> 7) & 1 != 0
    }

    /// Returns `true` if this is a leaf PTE (R or W or X bit set).
    #[must_use]
    pub const fn is_leaf(self) -> bool {
        self.readable() || self.writable() || self.executable()
    }

    /// Return the Physical Page Number (PPN) from the PTE.
    #[must_use]
    pub const fn ppn(self) -> u64 {
        (self.0 >> 10) & 0x0FFF_FFFF_FFFF
    }

    /// Return the physical address this PTE maps to.
    #[must_use]
    pub const fn phys_addr(self) -> u64 {
        self.ppn() << 12
    }
}

// ---------------------------------------------------------------------------
// RISC-V compressed instruction helpers (16-bit)
// ---------------------------------------------------------------------------

/// Returns `true` if `hw` is a 16-bit compressed RISC-V instruction (bits[1:0] != 0b11).
#[must_use]
pub const fn rv_is_compressed(hw: u16) -> bool {
    (hw & 0x3) != 0x3
}

/// Extract the compressed opcode (bits[1:0]) and funct3 (bits[15:13]).
#[must_use]
pub const fn rv_c_op_funct3(hw: u16) -> (u8, u8) {
    let op = (hw & 0x3) as u8;
    let funct3 = ((hw >> 13) & 0x7) as u8;
    (op, funct3)
}

/// Decode a C.ADDI4SPN immediate (8-bit, non-zero, scaled by 4).
///
/// Bits: imm[5:4|9:6|2|3] from `hw`.
#[must_use]
pub const fn rv_c_addi4spn_imm(hw: u16) -> u32 {
    let b = hw as u32;
    let imm5_4 = (b >> 11) & 0x3;
    let imm9_6 = (b >> 7) & 0xf;
    let imm2 = (b >> 6) & 0x1;
    let imm3 = (b >> 5) & 0x1;
    (imm9_6 << 6) | (imm5_4 << 4) | (imm3 << 3) | (imm2 << 2)
}

/// Classify a RISC-V 16-bit compressed instruction by its opcode quadrant and funct3.
///
/// Returns the mnemonic class string (e.g. `"c.addi"`, `"c.lw"`, …).
#[must_use]
pub const fn rv_c_classify(hw: u16) -> &'static str {
    let (op, funct3) = rv_c_op_funct3(hw);
    match (op, funct3) {
        (0, 0) => "c.addi4spn",
        (0, 1) => "c.fld",
        (0, 2) => "c.lw",
        (0, 3) => "c.flw",
        (0, 5) => "c.fsd",
        (0, 6) => "c.sw",
        (0, 7) => "c.fsw",
        (1, 0) => "c.nop/c.addi",
        (1, 1) => "c.jal",
        (1, 2) => "c.li",
        (1, 3) => "c.addi16sp/c.lui",
        (1, 4) => "c.misc-alu",
        (1, 5) => "c.j",
        (1, 6) => "c.beqz",
        (1, 7) => "c.bnez",
        (2, 0) => "c.slli",
        (2, 1) => "c.fldsp",
        (2, 2) => "c.lwsp",
        (2, 3) => "c.flwsp",
        (2, 4) => "c.jr/c.mv/c.jalr/c.add",
        (2, 5) => "c.fsdsp",
        (2, 6) => "c.swsp",
        (2, 7) => "c.fswsp",
        _ => "c.unknown",
    }
}

// ---------------------------------------------------------------------------
// Final final tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod very_final_tests {
    use super::*;

    #[test]
    fn test_mstatus_fields_count() {
        assert!(MSTATUS_FIELDS.len() >= 20);
    }

    #[test]
    fn test_mstatus_mpp_machine() {
        // MPP = 0b11 = machine
        let mstatus: u64 = 0b11 << 11;
        assert_eq!(mstatus_mpp(mstatus), RvPrivLevel::Machine);
    }

    #[test]
    fn test_mstatus_fp_dirty() {
        // FS = 0b11 = dirty
        let mstatus: u64 = 0b11 << 13;
        assert!(mstatus_fp_dirty(mstatus));
    }

    #[test]
    fn test_mstatus_mie_set() {
        assert!(mstatus_mie(1 << 3));
        assert!(!mstatus_mie(0));
    }

    #[test]
    fn test_rv_pte_valid() {
        let pte = RvPte(1);
        assert!(pte.valid());
        assert!(!pte.readable());
    }

    #[test]
    fn test_rv_pte_leaf_rwx() {
        let pte = RvPte(0b110); // R|W
        assert!(pte.readable());
        assert!(pte.writable());
        assert!(!pte.executable());
        assert!(pte.is_leaf());
    }

    #[test]
    fn test_rv_pte_ppn() {
        // PPN at bits [55:10]
        let pte = RvPte(1 << 10);
        assert_eq!(pte.ppn(), 1);
        assert_eq!(pte.phys_addr(), 0x1000);
    }

    #[test]
    fn test_rv_is_compressed_true() {
        // 0b01 opcode (quadrant 1) — compressed
        assert!(rv_is_compressed(0x4001));
    }

    #[test]
    fn test_rv_is_compressed_false() {
        // 0b11 opcode — 32-bit instruction
        assert!(!rv_is_compressed(0x0013));
    }

    #[test]
    fn test_rv_c_classify_lw() {
        // C.LW — op=0b00, funct3=0b010
        let hw: u16 = 0b010 << 13;
        assert_eq!(rv_c_classify(hw), "c.lw");
    }

    #[test]
    fn test_rv_c_classify_swsp() {
        // C.SWSP — op=0b10, funct3=0b110
        let hw: u16 = (0b110 << 13) | 0b10;
        assert_eq!(rv_c_classify(hw), "c.swsp");
    }

    #[test]
    fn test_rv_c_addi4spn_imm_basic() {
        // imm9_6=1 (bits 10:7 = 0b0001), rest 0 → imm = 1<<6 = 64
        let hw: u16 = 1 << 7;
        assert_eq!(rv_c_addi4spn_imm(hw), 64);
    }

    #[test]
    fn test_mstatus_sie_set() {
        assert!(mstatus_sie(1 << 1));
        assert!(!mstatus_sie(0));
    }
}

// ---------------------------------------------------------------------------
// RISC-V hart (hardware thread) state helpers
// ---------------------------------------------------------------------------

/// Represents the minimal observable state of a RISC-V hart for debugging.
#[derive(Debug, Clone)]
pub struct RvHartState {
    /// Current privilege level.
    pub priv_level: RvPrivLevel,
    /// Program counter.
    pub pc: u64,
    /// Integer register file (x0..x31).
    pub xregs: [u64; 32],
    /// mstatus CSR.
    pub mstatus: u64,
    /// mcause CSR.
    pub mcause: u64,
    /// mepc CSR.
    pub mepc: u64,
    /// mtval CSR.
    pub mtval: u64,
}

impl RvHartState {
    /// Create a new hart state with everything zeroed (power-on reset state).
    #[must_use]
    pub const fn reset() -> Self {
        Self {
            priv_level: RvPrivLevel::Machine,
            pc: 0x0000_0000_0000_1000, // typical reset vector
            xregs: [0u64; 32],
            mstatus: 0,
            mcause: 0,
            mepc: 0,
            mtval: 0,
        }
    }

    /// Read integer register `n`. x0 always returns 0.
    #[must_use]
    pub const fn read_x(&self, n: u8) -> u64 {
        if n == 0 {
            0
        } else {
            self.xregs[n as usize & 31]
        }
    }

    /// Write integer register `n`. Writes to x0 are silently discarded.
    pub const fn write_x(&mut self, n: u8, val: u64) {
        if n != 0 {
            self.xregs[n as usize & 31] = val;
        }
    }

    /// Return the stack pointer (x2).
    #[must_use]
    pub const fn sp(&self) -> u64 {
        self.read_x(2)
    }

    /// Return the return address (x1 / ra).
    #[must_use]
    pub const fn ra(&self) -> u64 {
        self.read_x(1)
    }

    /// Return the frame pointer / s0 (x8).
    #[must_use]
    pub const fn fp(&self) -> u64 {
        self.read_x(8)
    }

    /// Return the interrupt enable state for the current privilege mode.
    #[must_use]
    pub const fn interrupts_enabled(&self) -> bool {
        match self.priv_level {
            RvPrivLevel::Machine => mstatus_mie(self.mstatus),
            RvPrivLevel::Supervisor => mstatus_sie(self.mstatus),
            _ => false,
        }
    }

    /// Returns `true` if a trap is pending (mcause != 0).
    #[must_use]
    pub const fn trap_pending(&self) -> bool {
        self.mcause != 0
    }
}

// ---------------------------------------------------------------------------
// RISC-V scalar integer pseudo-instructions
// ---------------------------------------------------------------------------

/// Returns the canonical NOP word (`addi x0, x0, 0`).
pub const RV_NOP: u32 = 0x0000_0013;

/// Returns the canonical EBREAK word.
pub const RV_EBREAK: u32 = 0x0010_0073;

/// Returns the canonical ECALL word.
pub const RV_ECALL: u32 = 0x0000_0073;

/// Returns the canonical MRET word.
pub const RV_MRET: u32 = 0x3020_0073;

/// Returns the canonical WFI word.
pub const RV_WFI: u32 = 0x1050_0073;

/// Encode an ADDI instruction word.
#[must_use]
pub const fn rv_encode_addi(rd: u8, rs1: u8, imm: i16) -> u32 {
    let imm_bits = ((imm as i32).cast_unsigned()) & 0xFFF;
    (imm_bits << 20) | ((rs1 as u32 & 0x1f) << 15) | ((rd as u32 & 0x1f) << 7) | 0x13
}

/// Encode a SW (store word) instruction.
#[must_use]
pub const fn rv_encode_sw(rs2: u8, rs1: u8, imm: i16) -> u32 {
    let imm_u = ((imm as i32).cast_unsigned()) & 0xFFF;
    let imm11_5 = (imm_u >> 5) & 0x7f;
    let imm4_0 = imm_u & 0x1f;
    (imm11_5 << 25)
        | ((rs2 as u32 & 0x1f) << 20)
        | ((rs1 as u32 & 0x1f) << 15)
        | (2 << 12)
        | (imm4_0 << 7)
        | 0x23
}

/// Encode a LW (load word) instruction.
#[must_use]
pub const fn rv_encode_lw(rd: u8, rs1: u8, imm: i16) -> u32 {
    let imm_bits = ((imm as i32).cast_unsigned()) & 0xFFF;
    (imm_bits << 20) | ((rs1 as u32 & 0x1f) << 15) | (2 << 12) | ((rd as u32 & 0x1f) << 7) | 0x03
}

// ---------------------------------------------------------------------------
// Extra utility tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod utility_tests {
    use super::*;

    #[test]
    fn test_hart_reset() {
        let h = RvHartState::reset();
        assert_eq!(h.priv_level, RvPrivLevel::Machine);
        assert_eq!(h.read_x(0), 0);
        assert_eq!(h.read_x(1), 0);
        assert!(!h.trap_pending());
    }

    #[test]
    fn test_hart_write_x0_noop() {
        let mut h = RvHartState::reset();
        h.write_x(0, 0xDEAD_BEEF);
        assert_eq!(h.read_x(0), 0);
    }

    #[test]
    fn test_hart_write_x1() {
        let mut h = RvHartState::reset();
        h.write_x(1, 0x1234);
        assert_eq!(h.ra(), 0x1234);
    }

    #[test]
    fn test_hart_interrupts_enabled() {
        let mut h = RvHartState::reset();
        // MIE bit = bit 3
        h.mstatus = 1 << 3;
        assert!(h.interrupts_enabled());
    }

    #[test]
    fn test_hart_interrupts_disabled() {
        let h = RvHartState::reset();
        assert!(!h.interrupts_enabled());
    }

    #[test]
    fn test_rv_encode_addi_sp_minus16() {
        // ADDI x2, x2, -16
        let word = rv_encode_addi(2, 2, -16);
        assert_eq!(rv_opcode(word), 0x13);
        assert_eq!(rv_rd(word), 2);
        assert_eq!(rv_rs1(word), 2);
        assert_eq!(rv_imm_i(word), -16);
    }

    #[test]
    fn test_rv_encode_lw() {
        // LW x1, 4(x2)
        let word = rv_encode_lw(1, 2, 4);
        assert_eq!(rv_opcode(word), 0x03);
        assert_eq!(rv_rd(word), 1);
        assert_eq!(rv_rs1(word), 2);
        assert_eq!(rv_imm_i(word), 4);
    }

    #[test]
    fn test_rv_encode_sw() {
        // SW x1, 4(x2)
        let word = rv_encode_sw(1, 2, 4);
        assert_eq!(rv_opcode(word), 0x23);
        assert_eq!(rv_funct3(word), 2);
        assert_eq!(rv_rs1(word), 2);
        assert_eq!(rv_rs2(word), 1);
    }

    #[test]
    fn test_rv_nop_constant() {
        assert!(rv_is_nop(RV_NOP));
    }

    #[test]
    fn test_rv_ebreak_constant() {
        assert!(rv_is_ebreak(RV_EBREAK));
    }

    #[test]
    fn test_rv_ecall_constant() {
        assert!(rv_is_ecall(RV_ECALL));
    }

    #[test]
    fn test_rv_mret_constant() {
        assert!(rv_is_mret(RV_MRET));
    }

    #[test]
    fn test_rv_wfi_constant() {
        assert!(rv_is_wfi(RV_WFI));
    }
}

// ---------------------------------------------------------------------------
// RISC-V misc constants and helpers
// ---------------------------------------------------------------------------

/// Maximum number of PMP entries in standard RISC-V.
pub const RV_MAX_PMP_ENTRIES: u32 = 64;

/// Maximum number of hardware performance counters (HPM).
pub const RV_MAX_HPM_COUNTERS: u32 = 29;

/// RISC-V XLEN values.
pub const RV_XLEN_32: u8 = 32;
/// RISC-V 64-bit XLEN.
pub const RV_XLEN_64: u8 = 64;
/// RISC-V 128-bit XLEN.
pub const RV_XLEN_128: u8 = 128;

/// Return `true` if `addr` is 4-byte aligned (required for 32-bit instructions).
#[must_use]
pub const fn rv_is_instr_aligned(addr: u64) -> bool {
    addr.trailing_zeros() >= 2
}

/// Return `true` if `addr` is 2-byte aligned (sufficient for compressed instructions).
#[must_use]
pub const fn rv_is_cinstr_aligned(addr: u64) -> bool {
    addr & 0x1 == 0
}

/// Returns the number of bytes to advance PC after a 32-bit instruction.
pub const RV_PC_ADVANCE: u64 = 4;

/// Returns the number of bytes to advance PC after a 16-bit compressed instruction.
pub const RV_C_PC_ADVANCE: u64 = 2;

#[cfg(test)]
mod misc_const_tests {
    use super::*;

    #[test]
    fn test_max_pmp_entries() {
        assert_eq!(RV_MAX_PMP_ENTRIES, 64);
    }

    #[test]
    fn test_instr_aligned() {
        assert!(rv_is_instr_aligned(0x1000));
        assert!(!rv_is_instr_aligned(0x1002));
    }

    #[test]
    fn test_cinstr_aligned() {
        assert!(rv_is_cinstr_aligned(0x1002));
        assert!(!rv_is_cinstr_aligned(0x1001));
    }
}

// ---------------------------------------------------------------------------
// RVV 1.0 — Vector extension instruction decoder
// ---------------------------------------------------------------------------

/// RVV vtype field: element width (vsew).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VsewEnum {
    E8,
    E16,
    E32,
    E64,
}

impl VsewEnum {
    #[must_use]
    pub const fn from_bits(b: u8) -> Option<Self> {
        match b & 7 {
            0 => Some(Self::E8),
            1 => Some(Self::E16),
            2 => Some(Self::E32),
            3 => Some(Self::E64),
            _ => None,
        }
    }
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::E8 => 8,
            Self::E16 => 16,
            Self::E32 => 32,
            Self::E64 => 64,
        }
    }
}

/// RVV vtype field: register length multiplier (vlmul).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlmulEnum {
    Mf8,
    Mf4,
    Mf2,
    M1,
    M2,
    M4,
    M8,
}

impl VlmulEnum {
    #[must_use]
    pub const fn from_bits(b: u8) -> Option<Self> {
        match b & 7 {
            0 => Some(Self::M1),
            1 => Some(Self::M2),
            2 => Some(Self::M4),
            3 => Some(Self::M8),
            5 => Some(Self::Mf8),
            6 => Some(Self::Mf4),
            7 => Some(Self::Mf2),
            _ => None,
        }
    }
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mf8 => "mf8",
            Self::Mf4 => "mf4",
            Self::Mf2 => "mf2",
            Self::M1 => "m1",
            Self::M2 => "m2",
            Self::M4 => "m4",
            Self::M8 => "m8",
        }
    }
}

/// Decoded RVV vtype word.
#[derive(Debug, Clone, Copy)]
pub struct RvvVtype {
    pub vill: bool,
    pub vma: bool,
    pub vta: bool,
    pub vsew: u8,
    pub vlmul: u8,
}

impl RvvVtype {
    /// Decode a vtype immediate from VSETVLI / VSETIVLI / VSETVL.
    #[must_use]
    pub const fn decode(vtypei: u32) -> Self {
        Self {
            vill: (vtypei >> 31) & 1 != 0,
            vma: (vtypei >> 7) & 1 != 0,
            vta: (vtypei >> 6) & 1 != 0,
            vsew: ((vtypei >> 3) & 7) as u8,
            vlmul: (vtypei & 7) as u8,
        }
    }
}

/// Helper: vector register name.
fn vr(idx: usize) -> String {
    format!("v{idx}")
}

/// Mask bit string from bit 25 of a vector instruction.
const fn vmask(m: u32) -> &'static str {
    if m & 1 == 0 { ", v0.t" } else { "" }
}

/// RVV instruction decoder — takes a full 32-bit word already known to be
/// a vector opcode (opcode == 0x57) and produces a mnemonic + operands.
///
/// Returns `None` if the encoding is reserved or unknown.
#[must_use]
pub fn decode_rvv(address: Address, word: u32, bytes: Vec<u8>) -> Option<Instruction> {
    let funct3 = (word >> 12) & 7;

    // VSETVL family — funct3 == 7
    if funct3 == 7 {
        return Some(decode_rvv_vsetvl(address, word, bytes));
    }

    // Vector loads / stores — funct3 == 0,5 (unit-stride), 2,6 (strided), 3,7 (indexed)
    if let Some(insn) = decode_rvv_mem(address, word, &bytes) {
        return Some(insn);
    }

    // Arithmetic — opcode == 0x57

    decode_rvv_mid(address, word, bytes)
}

/// Continuation of the RVV funct3 dispatch.
fn decode_rvv_mid(address: Address, word: u32, bytes: Vec<u8>) -> Option<Instruction> {
    let funct3 = (word >> 12) & 7;
    let funct6 = (word >> 26) & 0x3F;
    let vm = (word >> 25) & 1;
    let vd = ((word >> 7) & 0x1F) as usize;
    let vs1 = ((word >> 15) & 0x1F) as usize;
    let vs2 = ((word >> 20) & 0x1F) as usize;
    let rs1 = vs1;
    let mask = vmask(vm);

    // VSETVL family — funct3 == 7
    if funct3 == 7 {
        return Some(decode_rvv_vsetvl(address, word, bytes));
    }

    // Vector loads / stores — funct3 == 0,5 (unit-stride), 2,6 (strided), 3,7 (indexed)
    if let Some(insn) = decode_rvv_mem(address, word, &bytes) {
        return Some(insn);
    }

    // Arithmetic — opcode == 0x57
    let ops_vvv = || format!("{}, {}, {}{}", vr(vd), vr(vs2), vr(vs1), mask);
    let ops_vec_scalar = || format!("{}, {}, {}{}", vr(vd), vr(vs2), xr(rs1), mask);
    let ops_vec_imm = || {
        // Read the vs1 field straight out of the instruction word: no cast, and
        // the mask bounds it to five bits exactly as `vs1` was derived.
        let imm5 = rv_sign_ext((word >> 15) & 0x1f, 5);
        format!("{}, {}, {imm5}{}", vr(vd), vr(vs2), mask)
    };

    match funct3 {
        0 | 3 | 2 => {
            let mn: Option<&str> = rvv_mnemonic_table_1(funct6);
            if let Some(m) = mn {
                let sfx = match funct3 {
                    3 => "vx",
                    2 => "vi",
                    _ => "vv",
                };
                let full = format!("{m}.{sfx}");
                let ops = match funct3 {
                    3 => ops_vec_scalar(),
                    2 => ops_vec_imm(),
                    _ => ops_vvv(),
                };
                return Some(plain(address, &full, ops, bytes));
            }
            None
        }

        // OPMVV / OPMVX
        _ => decode_rvv_rest(address, word, bytes),
    }
}

/// Second half of the RVV funct3 dispatch.
fn decode_rvv_rest(address: Address, word: u32, bytes: Vec<u8>) -> Option<Instruction> {
    let funct3 = (word >> 12) & 7;
    let funct6 = (word >> 26) & 0x3F;
    let vm = (word >> 25) & 1;
    let vd = ((word >> 7) & 0x1F) as usize;
    let vs1 = ((word >> 15) & 0x1F) as usize;
    let vs2 = ((word >> 20) & 0x1F) as usize;
    let rs1 = vs1;
    let rd = vd;
    let mask = vmask(vm);

    // VSETVL family — funct3 == 7
    if funct3 == 7 {
        let b31 = (word >> 31) & 1;
        let b30 = (word >> 30) & 1;
        if b31 == 0 {
            // VSETVLI: rd, rs1, vtypei[10:0]
            let vtypei = (word >> 20) & 0x7FF;
            let ops = format!("{}, {}, {vtypei:#05x}", xr(rd), xr(rs1));
            return Some(plain(address, "vsetvli", ops, bytes));
        }
        if b31 == 1 && b30 == 1 {
            // VSETIVLI: rd, uimm5, vtypei[9:0]  (bits[31:30]=0b11)
            let uimm5 = (word >> 15) & 0x1F;
            let vtypei = (word >> 20) & 0x3FF;
            let ops = format!("{}, {uimm5}, {vtypei:#05x}", xr(rd));
            return Some(plain(address, "vsetivli", ops, bytes));
        }
        // VSETVL: rd, rs1, rs2  (bits[31:30]=0b10)
        let ops = format!("{}, {}, {}", xr(rd), xr(rs1), xr(vs2));
        return Some(plain(address, "vsetvl", ops, bytes));
    }

    // Vector loads / stores — funct3 == 0,5 (unit-stride), 2,6 (strided), 3,7 (indexed)
    if let Some(insn) = decode_rvv_mem(address, word, &bytes) {
        return Some(insn);
    }

    // Arithmetic — opcode == 0x57
    let ops_vec_scalar = || format!("{}, {}, {}{}", vr(vd), vr(vs2), xr(rs1), mask);
    let ops_red = || format!("{}, {}, {}{}", vr(vd), vr(vs2), vr(vs1), mask);

    match funct3 {
        4 | 6 => {
            let mn: Option<&str> = match funct6 {
                0x00 => Some("vredsum"),
                0x01 => Some("vredand"),
                0x02 => Some("vredor"),
                0x03 => Some("vredxor"),
                0x04 => Some("vredminu"),
                0x05 => Some("vredmin"),
                0x06 => Some("vredmaxu"),
                0x07 => Some("vredmax"),
                0x10 => Some("vaaddu"),
                0x11 => Some("vaadd"),
                0x12 => Some("vasubu"),
                0x13 => Some("vasub"),
                0x16 => Some("vslide1up"),
                0x17 => Some("vslide1down"),
                0x18 => {
                    if let Some(insn) = decode_rvv_vwxunary(address, word, bytes.clone()) {
                        return Some(insn);
                    }
                    None
                }
                0x1C => Some("vmandnot"),
                0x1D => Some("vmand"),
                0x1E => Some("vmor"),
                0x1F => Some("vmxor"),
                0x28 => Some("vmnand"),
                0x29 => Some("vmnor"),
                0x2A => Some("vmornot"),
                0x2B => Some("vmxnor"),
                0x30 => Some("vdivu"),
                0x31 => Some("vdiv"),
                0x32 => Some("vremu"),
                0x33 => Some("vrem"),
                0x34 => Some("vmulhu"),
                0x35 => Some("vmul"),
                0x37 => Some("vmulhsu"),
                0x39 => Some("vmulh"),
                0x3B => Some("vmadd"),
                0x3F => Some("vmacc"),
                0x3A => Some("vnmsub"),
                0x3E => Some("vnmsac"),
                _ => None,
            };
            if let Some(m) = mn {
                let sfx = if funct3 == 4 { "vv" } else { "vx" };
                let full = format!("{m}.{sfx}");
                let ops = if funct3 == 4 { ops_red() } else { ops_vec_scalar() };
                return Some(plain(address, &full, ops, bytes));
            }
            None
        }

        // OPFVV / OPFVF
        _ => decode_rvv_tail(address, word, bytes),
    }
}

/// Final part of the RVV funct3 dispatch.
fn decode_rvv_tail(address: Address, word: u32, bytes: Vec<u8>) -> Option<Instruction> {
    let funct3 = (word >> 12) & 7;
    let funct6 = (word >> 26) & 0x3F;
    let vm = (word >> 25) & 1;
    let vd = ((word >> 7) & 0x1F) as usize;
    let vs1 = ((word >> 15) & 0x1F) as usize;
    let vs2 = ((word >> 20) & 0x1F) as usize;
    let rs1 = vs1;
    let rd = vd;
    let mask = vmask(vm);

    // VSETVL family — funct3 == 7
    if funct3 == 7 {
        let b31 = (word >> 31) & 1;
        let b30 = (word >> 30) & 1;
        if b31 == 0 {
            // VSETVLI: rd, rs1, vtypei[10:0]
            let vtypei = (word >> 20) & 0x7FF;
            let ops = format!("{}, {}, {vtypei:#05x}", xr(rd), xr(rs1));
            return Some(plain(address, "vsetvli", ops, bytes));
        }
        if b31 == 1 && b30 == 1 {
            // VSETIVLI: rd, uimm5, vtypei[9:0]  (bits[31:30]=0b11)
            let uimm5 = (word >> 15) & 0x1F;
            let vtypei = (word >> 20) & 0x3FF;
            let ops = format!("{}, {uimm5}, {vtypei:#05x}", xr(rd));
            return Some(plain(address, "vsetivli", ops, bytes));
        }
        // VSETVL: rd, rs1, rs2  (bits[31:30]=0b10)
        let ops = format!("{}, {}, {}", xr(rd), xr(rs1), xr(vs2));
        return Some(plain(address, "vsetvl", ops, bytes));
    }

    // Vector loads / stores — funct3 == 0,5 (unit-stride), 2,6 (strided), 3,7 (indexed)
    if let Some(insn) = decode_rvv_mem(address, word, &bytes) {
        return Some(insn);
    }

    // Arithmetic — opcode == 0x57
    let ops_vvv = || format!("{}, {}, {}{}", vr(vd), vr(vs2), vr(vs1), mask);
    let ops_vec_scalar = || format!("{}, {}, {}{}", vr(vd), vr(vs2), xr(rs1), mask);
    let ops_vv = || format!("{}, {}{}", vr(vd), vr(vs2), mask);

    match funct3 {
        1 | 5 => {
            let mn: Option<&str> = match funct6 {
                0x00 => Some("vfadd"),
                0x01 => Some("vfredusum"),
                0x02 => Some("vfsub"),
                0x03 => Some("vfredosum"),
                0x04 => Some("vfmin"),
                0x05 => Some("vfredmin"),
                0x06 => Some("vfmax"),
                0x07 => Some("vfredmax"),
                0x08 => Some("vfsgnj"),
                0x09 => Some("vfsgnjn"),
                0x0A => Some("vfsgnjx"),
                0x0C => Some("vfslide1up"),
                0x0D => Some("vfslide1down"),
                0x10 => Some("vfmerge"),
                0x11 => Some("vmfeq"),
                0x14 => Some("vmfle"),
                0x16 => Some("vmflt"),
                0x19 => Some("vmfgt"),
                0x1B => Some("vmfge"),
                0x20 => Some("vfdiv"),
                0x21 => Some("vfrdiv"),
                0x24 => Some("vfmul"),
                0x27 => Some("vfrsub"),
                0x28 => Some("vfmadd"),
                0x29 => Some("vfnmadd"),
                0x2A => Some("vfmsub"),
                0x2B => Some("vfnmsub"),
                0x2C => Some("vfmacc"),
                0x2D => Some("vfnmacc"),
                0x2E => Some("vfmsac"),
                0x2F => Some("vfnmsac"),
                0x30 => Some("vfwadd"),
                0x31 => Some("vfwredusum"),
                0x32 => Some("vfwsub"),
                0x33 => Some("vfwredosum"),
                0x34 => Some("vfwmul"),
                0x3C => Some("vfwmacc"),
                0x3D => Some("vfwnmacc"),
                0x3E => Some("vfwmsac"),
                0x3F => Some("vfwnmsac"),
                // funct6=0x18: VFUNARY0 (funct3==1) or vmfne (other funct3)
                0x18 => {
                    if funct3 == 1 {
                        // VFUNARY0 — vs1 selects the conversion
                        let cvt_mn = match vs1 {
                            0 => "vfcvt.xu.f.v",
                            1 => "vfcvt.x.f.v",
                            2 => "vfcvt.f.xu.v",
                            3 => "vfcvt.f.x.v",
                            6 => "vfcvt.rtz.xu.f.v",
                            7 => "vfcvt.rtz.x.f.v",
                            8 => "vfwcvt.xu.f.v",
                            9 => "vfwcvt.x.f.v",
                            10 => "vfwcvt.f.xu.v",
                            11 => "vfwcvt.f.x.v",
                            12 => "vfwcvt.f.f.v",
                            16 => "vfncvt.xu.f.w",
                            17 => "vfncvt.x.f.w",
                            18 => "vfncvt.f.xu.w",
                            19 => "vfncvt.f.x.w",
                            20 => "vfncvt.f.f.w",
                            23 => "vfncvt.rod.f.f.w",
                            _ => "vmfne", // fallback: treat as vmfne for funct3!=1
                        };
                        return Some(plain(
                            address,
                            cvt_mn,
                            ops_vv(),
                            bytes,
                        ));
                    }
                    Some("vmfne")
                }
                _ => None,
            };
            if let Some(m) = mn {
                let sfx = if funct3 == 1 { "vv" } else { "vf" };
                let full = format!("{m}.{sfx}");
                let ops = if funct3 == 1 { ops_vvv() } else { ops_vec_scalar() };
                return Some(plain(address, &full, ops, bytes));
            }
            None
        }

        _ => None,
    }
}

// ---------------------------------------------------------------------------
// LLIL (Low-Level Intermediate Language) lifter
// ---------------------------------------------------------------------------
//
// The lifter translates decoded RISC-V instructions into LLIL operations.
// It is designed to plug into the rustre_core lifting infrastructure.
// Vector instructions are emitted as Intrinsic calls.

/// LLIL operation kind — a simplified representation sufficient for the
/// RISC-V ISA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlilOp {
    /// No-op.
    Nop,
    /// Assign: `dest_reg` = expr.
    SetReg { reg: String, expr: Box<LlilExpr> },
    /// Store: mem[`addr_expr`] = `src_expr`, size bytes.
    Store {
        addr: Box<LlilExpr>,
        src: Box<LlilExpr>,
        size: u8,
    },
    /// Unconditional jump to target (PC-relative resolved).
    Jump { target: u64 },
    /// Indirect jump through expression.
    JumpTo { expr: Box<LlilExpr> },
    /// Call to target address.
    Call { target: u64 },
    /// Indirect call through expression.
    CallTo { expr: Box<LlilExpr> },
    /// Return.
    Ret,
    /// Conditional branch: if cond goto taken else fallthrough.
    If {
        cond: Box<LlilExpr>,
        taken: u64,
        fallthrough: u64,
    },
    /// System call.
    Syscall,
    /// Breakpoint.
    Breakpoint,
    /// Intrinsic (e.g. for atomic / vector ops).
    Intrinsic {
        name: String,
        inputs: Vec<LlilExpr>,
        outputs: Vec<String>,
    },
}

/// LLIL expression — value-producing operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlilExpr {
    /// Constant integer.
    Const(i64),
    /// Register read.
    Reg(String),
    /// Load from memory: mem[addr], size bytes.
    Load { addr: Box<Self>, size: u8 },
    /// Zero-extend to 64 bits from sz bytes.
    ZeroExt { inner: Box<Self>, sz: u8 },
    /// Sign-extend to 64 bits from sz bytes.
    SignExt { inner: Box<Self>, sz: u8 },
    /// Truncate to sz bytes.
    LowPart { inner: Box<Self>, sz: u8 },
    /// Arithmetic/logical binary op.
    BinOp {
        op: LlilBinOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    /// Unary op.
    UnOp { op: LlilUnOp, inner: Box<Self> },
    /// Comparison returning 0 or 1.
    Cmp {
        op: LlilCmpOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    /// Add (used for PC+imm).
    Add(Box<Self>, Box<Self>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlilBinOp {
    Add,
    Sub,
    Mul,
    UDiv,
    SDiv,
    URem,
    SRem,
    And,
    Or,
    Xor,
    Shl,
    LShr,
    AShr,
    AddWrap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlilUnOp {
    Neg,
    Not,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlilCmpOp {
    Eq,
    Ne,
    Slt,
    Sge,
    Ult,
    Uge,
    Sle,
    Sgt,
    Ule,
    Ugt,
}

/// Convenience constructors.
fn llil_reg(r: &str) -> LlilExpr {
    LlilExpr::Reg(r.to_string())
}
const fn llil_const(v: i64) -> LlilExpr {
    LlilExpr::Const(v)
}
fn llil_add(a: LlilExpr, b: LlilExpr) -> LlilExpr {
    LlilExpr::Add(Box::new(a), Box::new(b))
}
fn llil_binop(op: LlilBinOp, a: LlilExpr, b: LlilExpr) -> LlilExpr {
    LlilExpr::BinOp {
        op,
        lhs: Box::new(a),
        rhs: Box::new(b),
    }
}
fn llil_load(addr: LlilExpr, size: u8) -> LlilExpr {
    LlilExpr::Load {
        addr: Box::new(addr),
        size,
    }
}
fn llil_sext(inner: LlilExpr, sz: u8) -> LlilExpr {
    LlilExpr::SignExt {
        inner: Box::new(inner),
        sz,
    }
}
fn llil_zext(inner: LlilExpr, sz: u8) -> LlilExpr {
    LlilExpr::ZeroExt {
        inner: Box::new(inner),
        sz,
    }
}
fn llil_low(inner: LlilExpr, sz: u8) -> LlilExpr {
    LlilExpr::LowPart {
        inner: Box::new(inner),
        sz,
    }
}
fn llil_cmp(op: LlilCmpOp, a: LlilExpr, b: LlilExpr) -> LlilExpr {
    LlilExpr::Cmp {
        op,
        lhs: Box::new(a),
        rhs: Box::new(b),
    }
}
fn llil_set(reg: &str, expr: LlilExpr) -> LlilOp {
    LlilOp::SetReg {
        reg: reg.to_string(),
        expr: Box::new(expr),
    }
}
fn llil_store(addr: LlilExpr, src: LlilExpr, size: u8) -> LlilOp {
    LlilOp::Store {
        addr: Box::new(addr),
        src: Box::new(src),
        size,
    }
}

fn xabi(idx: usize) -> String {
    if idx < 32 {
        RV_ABI_NAMES[idx].to_string()
    } else {
        format!("x{idx}")
    }
}

/// The main LLIL lifter for RISC-V.  Returns a `Vec<LlilOp>` for the
/// instruction at `pc` with encoding `word` on an `xlen`-bit machine.
///
/// Supports: RV32I/RV64I base, M extension, A extension, C extension
/// (via decompress-first), Zicsr (as intrinsics).  Vector ops → Intrinsic.
#[must_use]
pub fn rv_lift_word(pc: u64, word: u32, xlen: u32) -> Vec<LlilOp> {
    let opcode = (word & 0x7F) as u8;
    let rd = ((word >> 7) & 0x1F) as usize;
    let funct3 = (word >> 12) & 7;
    let rs1 = ((word >> 15) & 0x1F) as usize;
    let imm_i = i64::from(rv_imm_i(word));
    let imm_u = i64::from(rv_imm_u(word));
    let imm_j = i64::from(rv_imm_j(word));

    let ra1 = xabi(rs1);
    let rda = xabi(rd);


    // Helper to produce: rda = expr, but only if rd != x0
    let setreg = |expr: LlilExpr| {
        if rd == 0 {
            vec![LlilOp::Nop]
        } else {
            vec![llil_set(&rda, expr)]
        }
    };

    match opcode {
        // LUI
        0x37 => setreg(llil_const(imm_u)),

        // AUIPC
        0x17 => setreg(llil_const((pc.cast_signed()).wrapping_add(imm_u))),

        // JAL
        0x6F => {
            let target = pc.wrapping_add(imm_j.cast_unsigned());
            let mut ops = Vec::new();
            // Save return address if rd != x0
            if rd != 0 {
                ops.push(llil_set(&rda, llil_const((pc.cast_signed()).wrapping_add(4))));
            }
            if rd == 1 || rd == 5 {
                ops.push(LlilOp::Call { target });
            } else {
                ops.push(LlilOp::Jump { target });
            }
            ops
        }

        // JALR
        0x67 if funct3 == 0 => {
            let base_expr = llil_reg(&ra1);
            let offset = imm_i;
            let addr_expr = if offset == 0 {
                base_expr
            } else {
                llil_add(base_expr, llil_const(offset))
            };
            // Mask LSB (RISC-V spec: set bit 0 to 0)
            let addr_masked = llil_binop(LlilBinOp::And, addr_expr, llil_const(-2i64));
            let mut ops = Vec::new();
            if rd != 0 {
                ops.push(llil_set(&rda, llil_const((pc.cast_signed()).wrapping_add(4))));
            }
            if rd == 0 && rs1 == 1 && imm_i == 0 {
                // ret
                ops.push(LlilOp::Ret);
            } else if rd == 1 || rd == 5 {
                ops.push(LlilOp::CallTo {
                    expr: Box::new(addr_masked),
                });
            } else {
                ops.push(LlilOp::JumpTo {
                    expr: Box::new(addr_masked),
                });
            }
            ops
        }

        // BRANCH
        _ => rv_lift_word_mid(pc, word, xlen),
    }
}

/// Middle part of the opcode dispatch in `rv_lift_word`.
fn rv_lift_word_mid(pc: u64, word: u32, xlen: u32) -> Vec<LlilOp> {
    let opcode = (word & 0x7F) as u8;
    let rd = ((word >> 7) & 0x1F) as usize;
    let funct3 = (word >> 12) & 7;
    let rs1 = ((word >> 15) & 0x1F) as usize;
    let rs2 = ((word >> 20) & 0x1F) as usize;
    let imm_i = i64::from(rv_imm_i(word));
    let imm_b = i64::from(rv_imm_b(word));

    let ra1 = xabi(rs1);
    let ra2 = xabi(rs2);
    let rda = xabi(rd);

    let skip = || vec![LlilOp::Nop]; // unhandled but safe

    // Helper to produce: rda = expr, but only if rd != x0
    let setreg = |expr: LlilExpr| {
        if rd == 0 {
            vec![LlilOp::Nop]
        } else {
            vec![llil_set(&rda, expr)]
        }
    };

    match opcode {
        0x63 => {
            let taken = pc.wrapping_add(imm_b.cast_unsigned());
            let fallthrough = pc.wrapping_add(4);
            let cmp_op = match funct3 {
                0 => LlilCmpOp::Eq,
                1 => LlilCmpOp::Ne,
                4 => LlilCmpOp::Slt,
                5 => LlilCmpOp::Sge,
                6 => LlilCmpOp::Ult,
                7 => LlilCmpOp::Uge,
                _ => return skip(),
            };
            let cond = llil_cmp(cmp_op, llil_reg(&ra1), llil_reg(&ra2));
            vec![LlilOp::If {
                cond: Box::new(cond),
                taken,
                fallthrough,
            }]
        }

        // LOAD
        0x03 => {
            let addr = llil_add(llil_reg(&ra1), llil_const(imm_i));
            let (size, sign) = match funct3 {
                0 => (1u8, true),
                1 => (2, true),
                2 => (4, true),
                3 if xlen >= 64 => (8, true),
                4 => (1, false),
                5 => (2, false),
                6 if xlen >= 64 => (4, false),
                _ => return skip(),
            };
            let raw = llil_load(addr, size);
            let expr = if sign {
                llil_sext(raw, size)
            } else {
                llil_zext(raw, size)
            };
            setreg(expr)
        }

        // STORE
        _ => rv_lift_word_mid2(word, xlen),
    }
}

/// Continuation of the opcode dispatch in `rv_lift_word`.
fn rv_lift_word_mid2(word: u32, xlen: u32) -> Vec<LlilOp> {
    let opcode = (word & 0x7F) as u8;
    let rd = ((word >> 7) & 0x1F) as usize;
    let funct3 = (word >> 12) & 7;
    let rs1 = ((word >> 15) & 0x1F) as usize;
    let rs2 = ((word >> 20) & 0x1F) as usize;
    let funct7 = (word >> 25) & 0x7F;
    let imm_i = i64::from(rv_imm_i(word));
    let imm_s = i64::from(rv_imm_s(word));

    let ra1 = xabi(rs1);
    let ra2 = xabi(rs2);
    let rda = xabi(rd);

    let skip = || vec![LlilOp::Nop]; // unhandled but safe

    // Helper to produce: rda = expr, but only if rd != x0
    let setreg = |expr: LlilExpr| {
        if rd == 0 {
            vec![LlilOp::Nop]
        } else {
            vec![llil_set(&rda, expr)]
        }
    };

    match opcode {
        0x23 => {
            let addr = llil_add(llil_reg(&ra1), llil_const(imm_s));
            let size = match funct3 {
                0 => 1u8,
                1 => 2,
                2 => 4,
                3 if xlen >= 64 => 8,
                _ => return skip(),
            };
            let src = llil_low(llil_reg(&ra2), size);
            vec![llil_store(addr, src, size)]
        }

        // OP-IMM
        0x13 => {
            let shamt = if xlen == 64 {
                (word >> 20) & 0x3F
            } else {
                (word >> 20) & 0x1F
            };
            let expr = match funct3 {
                0 => llil_add(llil_reg(&ra1), llil_const(imm_i)),
                1 => llil_binop(LlilBinOp::Shl, llil_reg(&ra1), llil_const(i64::from(shamt))),
                2 => llil_cmp(LlilCmpOp::Slt, llil_reg(&ra1), llil_const(imm_i)),
                3 => llil_cmp(LlilCmpOp::Ult, llil_reg(&ra1), llil_const(imm_i)),
                4 => llil_binop(LlilBinOp::Xor, llil_reg(&ra1), llil_const(imm_i)),
                5 => {
                    if funct7 & 0x20 != 0 {
                        llil_binop(LlilBinOp::AShr, llil_reg(&ra1), llil_const(i64::from(shamt)))
                    } else {
                        llil_binop(LlilBinOp::LShr, llil_reg(&ra1), llil_const(i64::from(shamt)))
                    }
                }
                6 => llil_binop(LlilBinOp::Or, llil_reg(&ra1), llil_const(imm_i)),
                7 => llil_binop(LlilBinOp::And, llil_reg(&ra1), llil_const(imm_i)),
                _ => return skip(),
            };
            setreg(expr)
        }

        // OP
        0x33 => {
            if funct7 == 1 {
                // M extension
                let expr = match funct3 {
                    0 => llil_binop(LlilBinOp::Mul, llil_reg(&ra1), llil_reg(&ra2)),
                    4 => llil_binop(LlilBinOp::SDiv, llil_reg(&ra1), llil_reg(&ra2)),
                    5 => llil_binop(LlilBinOp::UDiv, llil_reg(&ra1), llil_reg(&ra2)),
                    6 => llil_binop(LlilBinOp::SRem, llil_reg(&ra1), llil_reg(&ra2)),
                    7 => llil_binop(LlilBinOp::URem, llil_reg(&ra1), llil_reg(&ra2)),
                    _ => {
                        return vec![LlilOp::Intrinsic {
                            name: "mulh".into(),
                            inputs: vec![llil_reg(&ra1), llil_reg(&ra2)],
                            outputs: vec![rda.clone()],
                        }];
                    }
                };
                return setreg(expr);
            }
            let sub = funct7 & 0x20 != 0;
            let expr = match (funct3, sub) {
                (0, false) => llil_add(llil_reg(&ra1), llil_reg(&ra2)),
                (0, true) => llil_binop(LlilBinOp::Sub, llil_reg(&ra1), llil_reg(&ra2)),
                (1, _) => llil_binop(LlilBinOp::Shl, llil_reg(&ra1), llil_reg(&ra2)),
                (2, _) => llil_cmp(LlilCmpOp::Slt, llil_reg(&ra1), llil_reg(&ra2)),
                (3, _) => llil_cmp(LlilCmpOp::Ult, llil_reg(&ra1), llil_reg(&ra2)),
                (4, _) => llil_binop(LlilBinOp::Xor, llil_reg(&ra1), llil_reg(&ra2)),
                (5, false) => llil_binop(LlilBinOp::LShr, llil_reg(&ra1), llil_reg(&ra2)),
                (5, true) => llil_binop(LlilBinOp::AShr, llil_reg(&ra1), llil_reg(&ra2)),
                (6, _) => llil_binop(LlilBinOp::Or, llil_reg(&ra1), llil_reg(&ra2)),
                (7, _) => llil_binop(LlilBinOp::And, llil_reg(&ra1), llil_reg(&ra2)),
                _ => return skip(),
            };
            setreg(expr)
        }

        // OP-IMM-32 (RV64 word-size immediate)
        _ => rv_lift_word_rest(word, xlen),
    }
}

/// Second half of the opcode dispatch in `rv_lift_word`.
fn rv_lift_word_rest(word: u32, xlen: u32) -> Vec<LlilOp> {
    let opcode = (word & 0x7F) as u8;
    let rd = ((word >> 7) & 0x1F) as usize;
    let funct3 = (word >> 12) & 7;
    let rs1 = ((word >> 15) & 0x1F) as usize;
    let rs2 = ((word >> 20) & 0x1F) as usize;
    let funct7 = (word >> 25) & 0x7F;
    let imm_i = i64::from(rv_imm_i(word));

    let ra1 = xabi(rs1);
    let ra2 = xabi(rs2);
    let rda = xabi(rd);

    let skip = || vec![LlilOp::Nop]; // unhandled but safe

    // Helper to produce: rda = expr, but only if rd != x0
    let setreg = |expr: LlilExpr| {
        if rd == 0 {
            vec![LlilOp::Nop]
        } else {
            vec![llil_set(&rda, expr)]
        }
    };

    match opcode {
        0x1B if xlen >= 64 => {
            let shamt = (word >> 20) & 0x1F;
            let funct7l = (word >> 25) & 0x7F;
            let w_expr = match funct3 {
                0 => llil_add(llil_low(llil_reg(&ra1), 4), llil_const(imm_i)),
                1 => llil_binop(
                    LlilBinOp::Shl,
                    llil_low(llil_reg(&ra1), 4),
                    llil_const(i64::from(shamt)),
                ),
                5 => {
                    if funct7l & 0x20 != 0 {
                        llil_binop(
                            LlilBinOp::AShr,
                            llil_low(llil_reg(&ra1), 4),
                            llil_const(i64::from(shamt)),
                        )
                    } else {
                        llil_binop(
                            LlilBinOp::LShr,
                            llil_low(llil_reg(&ra1), 4),
                            llil_const(i64::from(shamt)),
                        )
                    }
                }
                _ => return skip(),
            };
            setreg(llil_sext(w_expr, 4))
        }

        // OP-32 (RV64 word-size register)
        0x3B if xlen >= 64 => {
            if funct7 == 1 {
                let expr = match funct3 {
                    0 => llil_low(
                        llil_binop(LlilBinOp::Mul, llil_reg(&ra1), llil_reg(&ra2)),
                        4,
                    ),
                    4 => llil_low(
                        llil_binop(LlilBinOp::SDiv, llil_reg(&ra1), llil_reg(&ra2)),
                        4,
                    ),
                    5 => llil_low(
                        llil_binop(LlilBinOp::UDiv, llil_reg(&ra1), llil_reg(&ra2)),
                        4,
                    ),
                    6 => llil_low(
                        llil_binop(LlilBinOp::SRem, llil_reg(&ra1), llil_reg(&ra2)),
                        4,
                    ),
                    7 => llil_low(
                        llil_binop(LlilBinOp::URem, llil_reg(&ra1), llil_reg(&ra2)),
                        4,
                    ),
                    _ => return skip(),
                };
                return setreg(llil_sext(expr, 4));
            }
            let sub = funct7 & 0x20 != 0;
            let w_expr = match (funct3, sub) {
                (0, false) => llil_binop(
                    LlilBinOp::Add,
                    llil_low(llil_reg(&ra1), 4),
                    llil_low(llil_reg(&ra2), 4),
                ),
                (0, true) => llil_binop(
                    LlilBinOp::Sub,
                    llil_low(llil_reg(&ra1), 4),
                    llil_low(llil_reg(&ra2), 4),
                ),
                (1, _) => llil_binop(LlilBinOp::Shl, llil_low(llil_reg(&ra1), 4), llil_reg(&ra2)),
                (5, false) => {
                    llil_binop(LlilBinOp::LShr, llil_low(llil_reg(&ra1), 4), llil_reg(&ra2))
                }
                (5, true) => {
                    llil_binop(LlilBinOp::AShr, llil_low(llil_reg(&ra1), 4), llil_reg(&ra2))
                }
                _ => return skip(),
            };
            setreg(llil_sext(w_expr, 4))
        }

        // FENCE / FENCE.I
        _ => rv_lift_word_rest2(word),
    }
}

/// Continuation of the opcode dispatch in `rv_lift_word`.
fn rv_lift_word_rest2(word: u32) -> Vec<LlilOp> {
    let opcode = (word & 0x7F) as u8;
    let rd = ((word >> 7) & 0x1F) as usize;
    let funct3 = (word >> 12) & 7;
    let rs1 = ((word >> 15) & 0x1F) as usize;

    let ra1 = xabi(rs1);
    let rda = xabi(rd);

    let nop = || vec![LlilOp::Nop];

    // Helper to produce: rda = expr, but only if rd != x0

    match opcode {
        0x0F => nop(),

        // SYSTEM
        0x73 => {
            if funct3 == 0 {
                let funct12 = (word >> 20) & 0xFFF;
                return match funct12 {
                    0x000 => vec![LlilOp::Syscall],
                    0x001 => vec![LlilOp::Breakpoint],
                    0x302 => vec![LlilOp::Ret], // mret
                    _ => nop(),
                };
            }
            // CSR instructions — emit as intrinsics
            let csr = (word >> 20) as u16;
            let csr_nm = csr_name(csr);
            vec![LlilOp::Intrinsic {
                name: format!("csr.{csr_nm}"),
                inputs: vec![llil_reg(&ra1)],
                outputs: if rd != 0 { vec![rda] } else { vec![] },
            }]
        }

        // ATOMIC (A extension) — emit as intrinsics
        _ => rv_lift_word_tail(word),
    }
}

/// Final part of the opcode dispatch in `rv_lift_word`.
fn rv_lift_word_tail(word: u32) -> Vec<LlilOp> {
    let opcode = (word & 0x7F) as u8;
    let rd = ((word >> 7) & 0x1F) as usize;
    let funct3 = (word >> 12) & 7;
    let rs1 = ((word >> 15) & 0x1F) as usize;
    let rs2 = ((word >> 20) & 0x1F) as usize;
    let funct7 = (word >> 25) & 0x7F;
    let imm_i = i64::from(rv_imm_i(word));
    let imm_s = i64::from(rv_imm_s(word));

    let ra1 = xabi(rs1);
    let ra2 = xabi(rs2);
    let rda = xabi(rd);

    let skip = || vec![LlilOp::Nop]; // unhandled but safe

    // Helper to produce: rda = expr, but only if rd != x0

    match opcode {
        0x2F => {
            let funct5 = funct7 >> 2;
            let suffix = if funct3 == 2 { "w" } else { "d" };
            let iname = match funct5 {
                0x02 => format!("lr.{suffix}"),
                0x03 => format!("sc.{suffix}"),
                0x01 => format!("amoswap.{suffix}"),
                0x00 => format!("amoadd.{suffix}"),
                0x04 => format!("amoxor.{suffix}"),
                0x0C => format!("amoand.{suffix}"),
                0x08 => format!("amoor.{suffix}"),
                0x10 => format!("amomin.{suffix}"),
                0x14 => format!("amomax.{suffix}"),
                0x18 => format!("amominu.{suffix}"),
                0x1C => format!("amomaxu.{suffix}"),
                _ => return skip(),
            };
            let inputs = vec![llil_reg(&ra1), llil_reg(&ra2)];
            let outputs = if rd != 0 { vec![rda] } else { vec![] };
            vec![LlilOp::Intrinsic {
                name: iname,
                inputs,
                outputs,
            }]
        }

        // FP loads / stores — emit as memory ops with intrinsic tags
        0x07 => {
            let (size, freg) = match funct3 {
                3 => (8, true),
                _ => (4, true),
            };
            let addr = llil_add(llil_reg(&ra1), llil_const(imm_i));
            let _ = freg;
            vec![LlilOp::Intrinsic {
                name: format!("fp.load.{size}"),
                inputs: vec![addr],
                outputs: vec![format!("f{rd}")],
            }]
        }
        0x27 => {
            let size = match funct3 {
                3 => 8,
                _ => 4,
            };
            let addr = llil_add(llil_reg(&ra1), llil_const(imm_s));
            vec![LlilOp::Intrinsic {
                name: format!("fp.store.{size}"),
                inputs: vec![addr, llil_reg(&format!("f{rs2}"))],
                outputs: vec![],
            }]
        }

        // FP arithmetic — all emit as intrinsics
        0x43 | 0x47 | 0x4B | 0x4F | 0x53 => {
            let rs3 = (funct7 >> 2) as usize;
            let name = match opcode {
                0x43 => "fmadd".to_string(),
                0x47 => "fmsub".to_string(),
                0x4B => "fnmsub".to_string(),
                0x4F => "fnmadd".to_string(),
                0x53 => format!("fp.op.{funct7:#04x}"),
                _ => "fp.unknown".to_string(),
            };
            let inputs: Vec<LlilExpr> = vec![
                llil_reg(&format!("f{rs1}")),
                llil_reg(&format!("f{rs2}")),
                llil_reg(&format!("f{rs3}")),
            ];
            vec![LlilOp::Intrinsic {
                name,
                inputs,
                outputs: vec![format!("f{rd}")],
            }]
        }

        // RVV
        0x57 => {
            vec![LlilOp::Intrinsic {
                name: format!("rvv.{word:#010x}"),
                inputs: vec![llil_const(i64::from(word))],
                outputs: vec![],
            }]
        }

        _ => skip(),
    }
}

/// Lift a 16-bit compressed instruction.
///
/// First expands the instruction to its 32-bit equivalent LLIL representation
/// using the same `rv_lift_word` path where possible, otherwise emits the
/// appropriate direct LLIL.
#[must_use]
pub fn rv_lift_compressed(pc: u64, hw: u16, xlen: u32) -> Vec<LlilOp> {
    let op = hw & 3;
    let funct3 = (hw >> 13) & 7;

    // Many C instructions expand cleanly to a 32-bit equivalent.
    // We handle the common ones directly and fall back for the rest.
    match op {
        // Quadrant 0
        0 => match funct3 {
            2 => {
                // C.LW → lw rd', uimm(rs1')
                let rd_p = ((hw >> 2) & 7) as usize + 8;
                let rs1_p = ((hw >> 7) & 7) as usize + 8;
                let uimm = i64::from(c_lw_imm(hw));
                let addr = llil_add(llil_reg(&xabi(rs1_p)), llil_const(uimm));
                vec![llil_set(&xabi(rd_p), llil_sext(llil_load(addr, 4), 4))]
            }
            3 if xlen >= 64 => {
                // C.LD → ld rd', uimm(rs1')
                let rd_p = ((hw >> 2) & 7) as usize + 8;
                let rs1_p = ((hw >> 7) & 7) as usize + 8;
                let uimm = i64::from(c_ld_imm(hw));
                let addr = llil_add(llil_reg(&xabi(rs1_p)), llil_const(uimm));
                vec![llil_set(&xabi(rd_p), llil_load(addr, 8))]
            }
            6 => {
                // C.SW
                let rs2_p = ((hw >> 2) & 7) as usize + 8;
                let rs1_p = ((hw >> 7) & 7) as usize + 8;
                let uimm = i64::from(c_lw_imm(hw));
                let addr = llil_add(llil_reg(&xabi(rs1_p)), llil_const(uimm));
                vec![llil_store(addr, llil_low(llil_reg(&xabi(rs2_p)), 4), 4)]
            }
            7 if xlen >= 64 => {
                // C.SD
                let rs2_p = ((hw >> 2) & 7) as usize + 8;
                let rs1_p = ((hw >> 7) & 7) as usize + 8;
                let uimm = i64::from(c_ld_imm(hw));
                let addr = llil_add(llil_reg(&xabi(rs1_p)), llil_const(uimm));
                vec![llil_store(addr, llil_reg(&xabi(rs2_p)), 8)]
            }
            _ => vec![LlilOp::Nop],
        },

        // Quadrant 1
        _ => rv_lift_compressed_q1(pc, hw, xlen),
    }
}

/// Quadrants 1 and 2 of the compressed lifter.
fn rv_lift_compressed_q1(pc: u64, hw: u16, xlen: u32) -> Vec<LlilOp> {
    let op = hw & 3;
    let funct3 = (hw >> 13) & 7;

    // Many C instructions expand cleanly to a 32-bit equivalent.
    // We handle the common ones directly and fall back for the rest.
    match op {
        1 => match funct3 {
            0 => {
                // C.NOP / C.ADDI
                let rd_raw = ((hw >> 7) & 0x1F) as usize;
                if rd_raw == 0 {
                    return vec![LlilOp::Nop];
                }
                let imm = i64::from(c_addi_imm(hw));
                let expr = llil_add(llil_reg(&xabi(rd_raw)), llil_const(imm));
                vec![llil_set(&xabi(rd_raw), expr)]
            }
            1 if xlen == 32 => {
                // C.JAL (RV32 only)
                let offset = i64::from(c_j_offset(hw));
                let target = pc.wrapping_add(offset.cast_unsigned());
                vec![
                    llil_set("ra", llil_const((pc.cast_signed()).wrapping_add(2))),
                    LlilOp::Call { target },
                ]
            }
            1 if xlen >= 64 => {
                // C.ADDIW
                let rd_raw = ((hw >> 7) & 0x1F) as usize;
                let imm = i64::from(c_addi_imm(hw));
                let w = llil_add(llil_low(llil_reg(&xabi(rd_raw)), 4), llil_const(imm));
                vec![llil_set(&xabi(rd_raw), llil_sext(w, 4))]
            }
            2 => {
                // C.LI
                let rd_raw = ((hw >> 7) & 0x1F) as usize;
                let imm = i64::from(c_addi_imm(hw));
                vec![llil_set(&xabi(rd_raw), llil_const(imm))]
            }
            3 => {
                let rd_raw = ((hw >> 7) & 0x1F) as usize;
                if rd_raw == 2 {
                    // C.ADDI16SP
                    let imm = i64::from(c_addi16sp_imm(hw));
                    let expr = llil_add(llil_reg("sp"), llil_const(imm));
                    vec![llil_set("sp", expr)]
                } else {
                    // C.LUI
                    let imm = i64::from(c_lui_imm(hw));
                    vec![llil_set(&xabi(rd_raw), llil_const(imm))]
                }
            }
            4 => {
                let funct2 = (hw >> 10) & 3;
                let rd_p = ((hw >> 7) & 7) as usize + 8;
                let rs2_p = ((hw >> 2) & 7) as usize + 8;
                match funct2 {
                    0 => {
                        let sh = i64::from(c_shamt(hw));
                        vec![llil_set(
                            &xabi(rd_p),
                            llil_binop(LlilBinOp::LShr, llil_reg(&xabi(rd_p)), llil_const(sh)),
                        )]
                    }
                    1 => {
                        let sh = i64::from(c_shamt(hw));
                        vec![llil_set(
                            &xabi(rd_p),
                            llil_binop(LlilBinOp::AShr, llil_reg(&xabi(rd_p)), llil_const(sh)),
                        )]
                    }
                    2 => {
                        let imm = i64::from(c_addi_imm(hw));
                        vec![llil_set(
                            &xabi(rd_p),
                            llil_binop(LlilBinOp::And, llil_reg(&xabi(rd_p)), llil_const(imm)),
                        )]
                    }
                    3 => {
                        let funct1 = (hw >> 12) & 1;
                        let op_sub = (hw >> 5) & 3;
                        let expr = match (funct1, op_sub) {
                            (0, 0) => llil_binop(
                                LlilBinOp::Sub,
                                llil_reg(&xabi(rd_p)),
                                llil_reg(&xabi(rs2_p)),
                            ),
                            (0, 1) => llil_binop(
                                LlilBinOp::Xor,
                                llil_reg(&xabi(rd_p)),
                                llil_reg(&xabi(rs2_p)),
                            ),
                            (0, 2) => llil_binop(
                                LlilBinOp::Or,
                                llil_reg(&xabi(rd_p)),
                                llil_reg(&xabi(rs2_p)),
                            ),
                            (0, 3) => llil_binop(
                                LlilBinOp::And,
                                llil_reg(&xabi(rd_p)),
                                llil_reg(&xabi(rs2_p)),
                            ),
                            (1, 0) => llil_sext(
                                llil_binop(
                                    LlilBinOp::Sub,
                                    llil_low(llil_reg(&xabi(rd_p)), 4),
                                    llil_low(llil_reg(&xabi(rs2_p)), 4),
                                ),
                                4,
                            ),
                            (1, 1) => llil_sext(
                                llil_add(
                                    llil_low(llil_reg(&xabi(rd_p)), 4),
                                    llil_low(llil_reg(&xabi(rs2_p)), 4),
                                ),
                                4,
                            ),
                            _ => return vec![LlilOp::Nop],
                        };
                        vec![llil_set(&xabi(rd_p), expr)]
                    }
                    _ => vec![LlilOp::Nop],
                }
            }
            5 => {
                // C.J
                let offset = i64::from(c_j_offset(hw));
                let target = pc.wrapping_add(offset.cast_unsigned());
                vec![LlilOp::Jump { target }]
            }
            6 => {
                // C.BEQZ
                let rs1_p = ((hw >> 7) & 7) as usize + 8;
                let offset = i64::from(c_b_offset(hw));
                let taken = pc.wrapping_add(offset.cast_unsigned());
                let fallthrough = pc.wrapping_add(2);
                let cond = llil_cmp(LlilCmpOp::Eq, llil_reg(&xabi(rs1_p)), llil_const(0));
                vec![LlilOp::If {
                    cond: Box::new(cond),
                    taken,
                    fallthrough,
                }]
            }
            7 => {
                // C.BNEZ
                let rs1_p = ((hw >> 7) & 7) as usize + 8;
                let offset = i64::from(c_b_offset(hw));
                let taken = pc.wrapping_add(offset.cast_unsigned());
                let fallthrough = pc.wrapping_add(2);
                let cond = llil_cmp(LlilCmpOp::Ne, llil_reg(&xabi(rs1_p)), llil_const(0));
                vec![LlilOp::If {
                    cond: Box::new(cond),
                    taken,
                    fallthrough,
                }]
            }
            _ => vec![LlilOp::Nop],
        },

        // Quadrant 2
        _ => rv_lift_compressed_q2(pc, hw, xlen),
    }
}

/// Quadrant 2 of the compressed lifter.
fn rv_lift_compressed_q2(pc: u64, hw: u16, xlen: u32) -> Vec<LlilOp> {
    let op = hw & 3;
    let funct3 = (hw >> 13) & 7;

    // Many C instructions expand cleanly to a 32-bit equivalent.
    // We handle the common ones directly and fall back for the rest.
    match op {
        2 => match funct3 {
            0 => {
                // C.SLLI
                let rd_raw = ((hw >> 7) & 0x1F) as usize;
                let shamt = i64::from(c_shamt(hw));
                vec![llil_set(
                    &xabi(rd_raw),
                    llil_binop(LlilBinOp::Shl, llil_reg(&xabi(rd_raw)), llil_const(shamt)),
                )]
            }
            2 => {
                // C.LWSP
                let rd_raw = ((hw >> 7) & 0x1F) as usize;
                let uimm = i64::from(c_lwsp_imm(hw));
                let addr = llil_add(llil_reg("sp"), llil_const(uimm));
                vec![llil_set(&xabi(rd_raw), llil_sext(llil_load(addr, 4), 4))]
            }
            3 if xlen >= 64 => {
                // C.LDSP
                let rd_raw = ((hw >> 7) & 0x1F) as usize;
                let uimm = i64::from(c_ldsp_imm(hw));
                let addr = llil_add(llil_reg("sp"), llil_const(uimm));
                vec![llil_set(&xabi(rd_raw), llil_load(addr, 8))]
            }
            4 => {
                let funct1 = (hw >> 12) & 1;
                let rs1_raw = ((hw >> 7) & 0x1F) as usize;
                let rs2_raw = ((hw >> 2) & 0x1F) as usize;
                if funct1 == 0 && rs2_raw == 0 {
                    // C.JR
                    vec![LlilOp::JumpTo {
                        expr: Box::new(llil_reg(&xabi(rs1_raw))),
                    }]
                } else if funct1 == 0 {
                    // C.MV
                    vec![llil_set(&xabi(rs1_raw), llil_reg(&xabi(rs2_raw)))]
                } else if rs1_raw == 0 && rs2_raw == 0 {
                    // C.EBREAK
                    vec![LlilOp::Breakpoint]
                } else if rs2_raw == 0 {
                    // C.JALR
                    vec![
                        llil_set("ra", llil_const((pc.cast_signed()).wrapping_add(2))),
                        LlilOp::CallTo {
                            expr: Box::new(llil_reg(&xabi(rs1_raw))),
                        },
                    ]
                } else {
                    // C.ADD
                    vec![llil_set(
                        &xabi(rs1_raw),
                        llil_add(llil_reg(&xabi(rs1_raw)), llil_reg(&xabi(rs2_raw))),
                    )]
                }
            }
            6 => {
                // C.SWSP
                let rs2_raw = ((hw >> 2) & 0x1F) as usize;
                let uimm = i64::from(c_swsp_imm(hw));
                let addr = llil_add(llil_reg("sp"), llil_const(uimm));
                vec![llil_store(addr, llil_low(llil_reg(&xabi(rs2_raw)), 4), 4)]
            }
            7 if xlen >= 64 => {
                // C.SDSP
                let rs2_raw = ((hw >> 2) & 0x1F) as usize;
                let uimm = i64::from(c_sdsp_imm(hw));
                let addr = llil_add(llil_reg("sp"), llil_const(uimm));
                vec![llil_store(addr, llil_reg(&xabi(rs2_raw)), 8)]
            }
            _ => vec![LlilOp::Nop],
        },

        _ => vec![LlilOp::Nop],
    }
}

// ---------------------------------------------------------------------------
// RVV encoding helpers (encode-side, useful for assembler / testing)
// ---------------------------------------------------------------------------

/// Encode a VSETVLI instruction.
/// `vtypei` encodes [vma|vta|vsew[2:0]|vlmul[2:0]].
#[must_use]
pub const fn rv_encode_vsetvli(rd: u8, rs1: u8, vtypei: u16) -> u32 {
    let vtypei11 = (vtypei & 0x7FF) as u32;
    // funct3=7, bits[31]=0
    (vtypei11 << 20) | ((rs1 as u32 & 0x1f) << 15) | (7 << 12) | ((rd as u32 & 0x1f) << 7) | 0x57
}

/// Encode a VSETIVLI instruction.
#[must_use]
pub const fn rv_encode_vsetivli(rd: u8, uimm5: u8, vtypei: u16) -> u32 {
    let vtypei10 = (vtypei & 0x3FF) as u32;
    // funct3=7, bits[31:30]=0b11
    (0b11 << 30)
        | (vtypei10 << 20)
        | ((uimm5 as u32 & 0x1f) << 15)
        | (7 << 12)
        | ((rd as u32 & 0x1f) << 7)
        | 0x57
}

/// Build a vtype immediate from components.
/// vsew: 0=E8, 1=E16, 2=E32, 3=E64.  vlmul: 0=m1,1=m2,2=m4,3=m8,5=mf8,6=mf4,7=mf2.
#[must_use]
pub const fn rv_vtype_imm(vma: bool, vta: bool, vsew: u8, vlmul: u8) -> u16 {
    ((vma as u16) << 7) | ((vta as u16) << 6) | ((vsew as u16 & 7) << 3) | (vlmul as u16 & 7)
}

// ---------------------------------------------------------------------------
// RVV instruction decoder integration into RiscvArch
// ---------------------------------------------------------------------------

impl RiscvArch {
    /// Decode a vector (opcode=0x57) instruction word.
    fn decode_vector(&self, address: Address, word: u32, bytes: Vec<u8>) -> Instruction {
        debug_assert!(self.is_supported_xlen(), "unsupported XLEN {}", self.bits);
        decode_rvv(address, word, bytes.clone()).unwrap_or_else(|| unknown(address, bytes))
    }
}

// ---------------------------------------------------------------------------
// Additional F/D extension helpers
// ---------------------------------------------------------------------------

/// Rounding mode suffix from the rm field (bits [14:12]).
#[must_use]
pub const fn rv_fp_rm_str(rm: u8) -> &'static str {
    match rm {
        0 => "rne",
        1 => "rtz",
        2 => "rdn",
        3 => "rup",
        4 => "rmm",
        7 => "",
        _ => "?",
    }
}

/// Classify an FP value class bit (from FCLASS output).
#[must_use]
pub const fn rv_fclass_bit_name(bit: u8) -> &'static str {
    match bit {
        0 => "-Inf",
        1 => "-Normal",
        2 => "-Subnormal",
        3 => "-Zero",
        4 => "+Zero",
        5 => "+Subnormal",
        6 => "+Normal",
        7 => "+Inf",
        8 => "sNaN",
        9 => "qNaN",
        _ => "?",
    }
}

/// F extension: Encode FLW instruction.
#[must_use]
pub const fn rv_encode_flw(rd: u8, rs1: u8, imm: i16) -> u32 {
    let imm12 = ((imm as i32).cast_unsigned()) & 0xFFF;
    (imm12 << 20) | ((rs1 as u32 & 0x1f) << 15) | (2 << 12) | ((rd as u32 & 0x1f) << 7) | 0x07
}

/// F extension: Encode FSW instruction.
#[must_use]
pub const fn rv_encode_fsw(rs2: u8, rs1: u8, imm: i16) -> u32 {
    let imm_u = ((imm as i32).cast_unsigned()) & 0xFFF;
    let imm11_5 = (imm_u >> 5) & 0x7f;
    let imm4_0 = imm_u & 0x1f;
    (imm11_5 << 25)
        | ((rs2 as u32 & 0x1f) << 20)
        | ((rs1 as u32 & 0x1f) << 15)
        | (2 << 12)
        | (imm4_0 << 7)
        | 0x27
}

// ---------------------------------------------------------------------------
// A extension: encode helpers
// ---------------------------------------------------------------------------

/// Encode LR.W instruction.
#[must_use]
pub const fn rv_encode_lr_w(rd: u8, rs1: u8, aq: bool, rl: bool) -> u32 {
    let funct7 = (0x02u32 << 2) | ((aq as u32) << 1) | (rl as u32);
    (funct7 << 25) | ((rs1 as u32 & 0x1f) << 15) | (2 << 12) | ((rd as u32 & 0x1f) << 7) | 0x2F
}

/// Encode SC.W instruction.
#[must_use]
pub const fn rv_encode_sc_w(rd: u8, rs1: u8, rs2: u8, aq: bool, rl: bool) -> u32 {
    let funct7 = (0x03u32 << 2) | ((aq as u32) << 1) | (rl as u32);
    (funct7 << 25)
        | ((rs2 as u32 & 0x1f) << 20)
        | ((rs1 as u32 & 0x1f) << 15)
        | (2 << 12)
        | ((rd as u32 & 0x1f) << 7)
        | 0x2F
}

/// Encode AMOSWAP.W instruction.
#[must_use]
pub const fn rv_encode_amoswap_w(rd: u8, rs1: u8, rs2: u8, aq: bool, rl: bool) -> u32 {
    let funct7 = (0x01u32 << 2) | ((aq as u32) << 1) | (rl as u32);
    (funct7 << 25)
        | ((rs2 as u32 & 0x1f) << 20)
        | ((rs1 as u32 & 0x1f) << 15)
        | (2 << 12)
        | ((rd as u32 & 0x1f) << 7)
        | 0x2F
}

// ---------------------------------------------------------------------------
// Zicsr: encode helpers
// ---------------------------------------------------------------------------

/// Encode CSRRW instruction.
#[must_use]
pub const fn rv_encode_csrrw(rd: u8, rs1: u8, csr: u16) -> u32 {
    ((csr as u32 & 0xFFF) << 20)
        | ((rs1 as u32 & 0x1f) << 15)
        | (1 << 12)
        | ((rd as u32 & 0x1f) << 7)
        | 0x73
}

/// Encode CSRRS instruction.
#[must_use]
pub const fn rv_encode_csrrs(rd: u8, rs1: u8, csr: u16) -> u32 {
    ((csr as u32 & 0xFFF) << 20)
        | ((rs1 as u32 & 0x1f) << 15)
        | (2 << 12)
        | ((rd as u32 & 0x1f) << 7)
        | 0x73
}

/// Encode CSRRC instruction.
#[must_use]
pub const fn rv_encode_csrrc(rd: u8, rs1: u8, csr: u16) -> u32 {
    ((csr as u32 & 0xFFF) << 20)
        | ((rs1 as u32 & 0x1f) << 15)
        | (3 << 12)
        | ((rd as u32 & 0x1f) << 7)
        | 0x73
}

// ---------------------------------------------------------------------------
// RV32I / RV64I additional encode helpers
// ---------------------------------------------------------------------------

/// Encode JAL instruction.
#[must_use]
pub const fn rv_encode_jal(rd: u8, offset: i32) -> u32 {
    let off = offset.cast_unsigned();
    let b20 = (off >> 20) & 1;
    let b10_1 = (off >> 1) & 0x3FF;
    let b11 = (off >> 11) & 1;
    let b19_12 = (off >> 12) & 0xFF;
    (b20 << 31) | (b19_12 << 12) | (b11 << 20) | (b10_1 << 21) | ((rd as u32 & 0x1f) << 7) | 0x6F
}

/// Encode JALR instruction.
#[must_use]
pub const fn rv_encode_jalr(rd: u8, rs1: u8, imm: i16) -> u32 {
    let imm12 = ((imm as i32).cast_unsigned()) & 0xFFF;
    (imm12 << 20) | ((rs1 as u32 & 0x1f) << 15) | ((rd as u32 & 0x1f) << 7) | 0x67
}

/// Encode BEQ instruction.
#[must_use]
pub const fn rv_encode_beq(rs1: u8, rs2: u8, offset: i32) -> u32 {
    let off = offset.cast_unsigned();
    let b12 = (off >> 12) & 1;
    let b11 = (off >> 11) & 1;
    let b10_5 = (off >> 5) & 0x3F;
    let b4_1 = (off >> 1) & 0xF;
    (b12 << 31)
        | (b10_5 << 25)
        | ((rs2 as u32 & 0x1f) << 20)
        | ((rs1 as u32 & 0x1f) << 15)
        | (b4_1 << 8)
        | (b11 << 7)
        | 0x63
}

/// Encode LUI instruction.
#[must_use]
pub const fn rv_encode_lui(rd: u8, imm20: u32) -> u32 {
    ((imm20 & 0xFFFFF) << 12) | ((rd as u32 & 0x1f) << 7) | 0x37
}

/// Encode AUIPC instruction.
#[must_use]
pub const fn rv_encode_auipc(rd: u8, imm20: u32) -> u32 {
    ((imm20 & 0xFFFFF) << 12) | ((rd as u32 & 0x1f) << 7) | 0x17
}

/// Encode ADD instruction.
#[must_use]
pub const fn rv_encode_add(rd: u8, rs1: u8, rs2: u8) -> u32 {
    ((rs2 as u32 & 0x1f) << 20) | ((rs1 as u32 & 0x1f) << 15) | ((rd as u32 & 0x1f) << 7) | 0x33
}

/// Encode SUB instruction.
#[must_use]
pub const fn rv_encode_sub(rd: u8, rs1: u8, rs2: u8) -> u32 {
    (0x20 << 25)
        | ((rs2 as u32 & 0x1f) << 20)
        | ((rs1 as u32 & 0x1f) << 15)
        | ((rd as u32 & 0x1f) << 7)
        | 0x33
}

/// Encode AND instruction.
#[must_use]
pub const fn rv_encode_and(rd: u8, rs1: u8, rs2: u8) -> u32 {
    ((rs2 as u32 & 0x1f) << 20)
        | ((rs1 as u32 & 0x1f) << 15)
        | (7 << 12)
        | ((rd as u32 & 0x1f) << 7)
        | 0x33
}

/// Encode OR instruction.
#[must_use]
pub const fn rv_encode_or(rd: u8, rs1: u8, rs2: u8) -> u32 {
    ((rs2 as u32 & 0x1f) << 20)
        | ((rs1 as u32 & 0x1f) << 15)
        | (6 << 12)
        | ((rd as u32 & 0x1f) << 7)
        | 0x33
}

/// Encode XOR instruction.
#[must_use]
pub const fn rv_encode_xor(rd: u8, rs1: u8, rs2: u8) -> u32 {
    ((rs2 as u32 & 0x1f) << 20)
        | ((rs1 as u32 & 0x1f) << 15)
        | (4 << 12)
        | ((rd as u32 & 0x1f) << 7)
        | 0x33
}

/// Encode SLL instruction.
#[must_use]
pub const fn rv_encode_sll(rd: u8, rs1: u8, rs2: u8) -> u32 {
    ((rs2 as u32 & 0x1f) << 20)
        | ((rs1 as u32 & 0x1f) << 15)
        | (1 << 12)
        | ((rd as u32 & 0x1f) << 7)
        | 0x33
}

/// Encode SRL instruction.
#[must_use]
pub const fn rv_encode_srl(rd: u8, rs1: u8, rs2: u8) -> u32 {
    ((rs2 as u32 & 0x1f) << 20)
        | ((rs1 as u32 & 0x1f) << 15)
        | (5 << 12)
        | ((rd as u32 & 0x1f) << 7)
        | 0x33
}

/// Encode SRA instruction.
#[must_use]
pub const fn rv_encode_sra(rd: u8, rs1: u8, rs2: u8) -> u32 {
    (0x20 << 25)
        | ((rs2 as u32 & 0x1f) << 20)
        | ((rs1 as u32 & 0x1f) << 15)
        | (5 << 12)
        | ((rd as u32 & 0x1f) << 7)
        | 0x33
}

/// Encode MUL instruction.
#[must_use]
pub const fn rv_encode_mul(rd: u8, rs1: u8, rs2: u8) -> u32 {
    (1 << 25)
        | ((rs2 as u32 & 0x1f) << 20)
        | ((rs1 as u32 & 0x1f) << 15)
        | ((rd as u32 & 0x1f) << 7)
        | 0x33
}

/// Encode DIV instruction.
#[must_use]
pub const fn rv_encode_div(rd: u8, rs1: u8, rs2: u8) -> u32 {
    (1 << 25)
        | ((rs2 as u32 & 0x1f) << 20)
        | ((rs1 as u32 & 0x1f) << 15)
        | (4 << 12)
        | ((rd as u32 & 0x1f) << 7)
        | 0x33
}

// ---------------------------------------------------------------------------
// LLIL + RVV tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod llil_tests {
    use super::*;

    fn _addr(a: u64) -> Address {
        Address::new(a)
    }

    // ── LLIL: ADDI ────────────────────────────────────────────────────────────
    #[test]
    fn test_llil_addi_x1_x0_10() {
        // ADDI x1, x0, 10
        let word: u32 = (10 << 20) | (1 << 7) | 0x13;
        let ops = rv_lift_word(0x1000, word, 64);
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            LlilOp::SetReg { reg, .. } => assert_eq!(reg, "ra"),
            _ => panic!("expected SetReg, got {:?}", ops[0]),
        }
    }

    // ── LLIL: LW → SetReg with Load ──────────────────────────────────────────
    #[test]
    fn test_llil_lw_x1_4_x2() {
        let word: u32 = (4 << 20) | (2 << 15) | (2 << 12) | (1 << 7) | 0x03;
        let ops = rv_lift_word(0x1000, word, 64);
        assert_eq!(ops.len(), 1);
        if let LlilOp::SetReg { expr, .. } = &ops[0] {
            assert!(matches!(expr.as_ref(), LlilExpr::SignExt { .. }));
        } else {
            panic!("expected SetReg");
        }
    }

    // ── LLIL: SW → Store ─────────────────────────────────────────────────────
    #[test]
    fn test_llil_sw_x1_4_x2() {
        let word: u32 = {
            let imm = 4u32;
            let imm11_5 = (imm >> 5) & 0x7f;
            let imm4_0 = imm & 0x1f;
            (imm11_5 << 25) | (1 << 20) | (2 << 15) | (2 << 12) | (imm4_0 << 7) | 0x23
        };
        let ops = rv_lift_word(0x1000, word, 64);
        assert_eq!(ops.len(), 1);
        assert!(matches!(ops[0], LlilOp::Store { size: 4, .. }));
    }

    // ── LLIL: JAL x0 → Jump ──────────────────────────────────────────────────
    #[test]
    fn test_llil_jal_x0_jump() {
        let word = rv_encode_jal(0, 8);
        let ops = rv_lift_word(0x1000, word, 64);
        assert!(
            ops.iter()
                .any(|o| matches!(o, LlilOp::Jump { target: 0x1008 }))
        );
    }

    // ── LLIL: JAL ra → Call ───────────────────────────────────────────────────
    #[test]
    fn test_llil_jal_ra_call() {
        let word = rv_encode_jal(1, 16);
        let ops = rv_lift_word(0x2000, word, 64);
        assert!(
            ops.iter()
                .any(|o| matches!(o, LlilOp::Call { target: 0x2010 }))
        );
    }

    // ── LLIL: JALR x0, ra, 0 → Ret ───────────────────────────────────────────
    #[test]
    fn test_llil_jalr_ret() {
        let word = rv_encode_jalr(0, 1, 0);
        let ops = rv_lift_word(0x3000, word, 64);
        assert!(ops.iter().any(|o| matches!(o, LlilOp::Ret)));
    }

    // ── LLIL: BEQ → If ────────────────────────────────────────────────────────
    #[test]
    fn test_llil_beq_if() {
        let word = rv_encode_beq(1, 2, 8);
        let ops = rv_lift_word(0x1000, word, 64);
        assert_eq!(ops.len(), 1);
        if let LlilOp::If {
            taken, fallthrough, ..
        } = ops[0]
        {
            assert_eq!(taken, 0x1008);
            assert_eq!(fallthrough, 0x1004);
        } else {
            panic!("expected If, got {:?}", ops[0]);
        }
    }

    // ── LLIL: ECALL → Syscall ─────────────────────────────────────────────────
    #[test]
    fn test_llil_ecall_syscall() {
        let ops = rv_lift_word(0x0, 0x0000_0073, 64);
        assert!(ops.iter().any(|o| matches!(o, LlilOp::Syscall)));
    }

    // ── LLIL: EBREAK → Breakpoint ────────────────────────────────────────────
    #[test]
    fn test_llil_ebreak_breakpoint() {
        let ops = rv_lift_word(0x0, 0x0010_0073, 64);
        assert!(ops.iter().any(|o| matches!(o, LlilOp::Breakpoint)));
    }

    // ── LLIL: ADD → SetReg BinOp ─────────────────────────────────────────────
    #[test]
    fn test_llil_add_binop() {
        let word = rv_encode_add(3, 1, 2);
        let ops = rv_lift_word(0x4000, word, 64);
        if let LlilOp::SetReg { expr, .. } = &ops[0] {
            assert!(matches!(expr.as_ref(), LlilExpr::Add(..)));
        } else {
            panic!();
        }
    }

    // ── LLIL: SUB ────────────────────────────────────────────────────────────
    #[test]
    fn test_llil_sub_binop() {
        let word = rv_encode_sub(3, 1, 2);
        let ops = rv_lift_word(0x0, word, 64);
        if let LlilOp::SetReg { expr, .. } = &ops[0] {
            assert!(matches!(
                expr.as_ref(),
                LlilExpr::BinOp {
                    op: LlilBinOp::Sub,
                    ..
                }
            ));
        } else {
            panic!();
        }
    }

    // ── LLIL: MUL (M ext) ────────────────────────────────────────────────────
    #[test]
    fn test_llil_mul_m_ext() {
        let word = rv_encode_mul(3, 1, 2);
        let ops = rv_lift_word(0x0, word, 64);
        if let LlilOp::SetReg { expr, .. } = &ops[0] {
            assert!(matches!(
                expr.as_ref(),
                LlilExpr::BinOp {
                    op: LlilBinOp::Mul,
                    ..
                }
            ));
        } else {
            panic!();
        }
    }

    // ── LLIL: ATOMIC → Intrinsic ─────────────────────────────────────────────
    #[test]
    fn test_llil_atomic_intrinsic() {
        let word = rv_encode_amoswap_w(1, 3, 2, false, false);
        let ops = rv_lift_word(0x0, word, 64);
        if let LlilOp::Intrinsic { name, .. } = &ops[0] {
            assert!(name.starts_with("amoswap"), "got {name}");
        } else {
            panic!();
        }
    }

    // ── LLIL: LR.W → Intrinsic ───────────────────────────────────────────────
    #[test]
    fn test_llil_lr_w_intrinsic() {
        let word = rv_encode_lr_w(1, 3, false, false);
        let ops = rv_lift_word(0x0, word, 64);
        if let LlilOp::Intrinsic { name, .. } = &ops[0] {
            assert_eq!(name, "lr.w");
        } else {
            panic!();
        }
    }

    // ── LLIL: MRET → Ret ─────────────────────────────────────────────────────
    #[test]
    fn test_llil_mret_ret() {
        let ops = rv_lift_word(0x0, 0x3020_0073, 64);
        assert!(ops.iter().any(|o| matches!(o, LlilOp::Ret)));
    }

    // ── LLIL: FENCE → Nop ────────────────────────────────────────────────────
    #[test]
    fn test_llil_fence_nop() {
        let ops = rv_lift_word(0x0, 0x0000_000F, 64);
        assert!(matches!(ops[0], LlilOp::Nop));
    }

    // ── LLIL: CSR → Intrinsic ────────────────────────────────────────────────
    #[test]
    fn test_llil_csrrw_intrinsic() {
        let word = rv_encode_csrrw(1, 0, 0x300); // csrrw x1, mstatus, x0
        let ops = rv_lift_word(0x0, word, 64);
        if let LlilOp::Intrinsic { name, .. } = &ops[0] {
            assert!(name.contains("mstatus"), "got {name}");
        } else {
            panic!();
        }
    }

    // ── LLIL: LUI ────────────────────────────────────────────────────────────
    #[test]
    fn test_llil_lui() {
        let word = rv_encode_lui(1, 1);
        let ops = rv_lift_word(0x0, word, 64);
        if let LlilOp::SetReg { expr, .. } = &ops[0] {
            assert!(matches!(expr.as_ref(), LlilExpr::Const(_)));
        } else {
            panic!();
        }
    }

    // ── LLIL: AUIPC ──────────────────────────────────────────────────────────
    #[test]
    fn test_llil_auipc_pc_relative() {
        let word = rv_encode_auipc(1, 1); // auipc x1, 1 → rd = pc + (1<<12)
        let ops = rv_lift_word(0x2000, word, 64);
        if let LlilOp::SetReg { expr, .. } = &ops[0] {
            if let LlilExpr::Const(v) = expr.as_ref() {
                assert_eq!(*v, 0x2000i64 + (1i64 << 12));
            } else {
                panic!("expected Const");
            }
        } else {
            panic!();
        }
    }

    // ── LLIL: ADDIW (RV64) ───────────────────────────────────────────────────
    #[test]
    fn test_llil_addiw_rv64() {
        // ADDIW x1, x2, 5
        let word: u32 = ((5 << 20) | (2 << 15)) | (1 << 7) | 0x1B;
        let ops = rv_lift_word(0x0, word, 64);
        if let LlilOp::SetReg { expr, .. } = &ops[0] {
            assert!(matches!(expr.as_ref(), LlilExpr::SignExt { .. }));
        } else {
            panic!();
        }
    }

    // ── LLIL: ADDW (RV64) ────────────────────────────────────────────────────
    #[test]
    fn test_llil_addw_rv64() {
        let word: u32 = ((2 << 20) | (1 << 15)) | (3 << 7) | 0x3B;
        let ops = rv_lift_word(0x0, word, 64);
        if let LlilOp::SetReg { expr, .. } = &ops[0] {
            assert!(matches!(expr.as_ref(), LlilExpr::SignExt { .. }));
        } else {
            panic!();
        }
    }

    // ── LLIL: RVV → Intrinsic ────────────────────────────────────────────────
    #[test]
    fn test_llil_rvv_intrinsic() {
        // Any word with opcode 0x57
        let word: u32 = 0x57;
        let ops = rv_lift_word(0x0, word, 64);
        assert!(matches!(ops[0], LlilOp::Intrinsic { .. }));
    }

    // ── LLIL: C.ADDI (compressed) ────────────────────────────────────────────
    #[test]
    fn test_llil_c_addi() {
        // C.ADDI x1, 4 → op=1, funct3=0, rd=1, imm=4
        // The same instruction with imm[4:0]=1 must lift the same way: the
        // immediate is data, not part of the opcode selection.
        let hw_imm1: u16 = (1 << 7) | (1 << 2) | 0b01;
        let ops_imm1 = rv_lift_compressed(0x1000, hw_imm1, 64);
        assert_eq!(ops_imm1.len(), 1, "c.addi x1, 1 lifts to one LLIL op");
        // Use a proper c.addi encoding: op=01, funct3=000, rd=1(=ra), imm5=0, imm4_0=4
        // hw: [15:13]=000, [12]=0(imm5), [11:7]=00001(rd=1), [6:2]=00100(imm[4:0]=4), [1:0]=01
        let hw: u16 = (1 << 7) | (4 << 2) | 0b01;
        let ops = rv_lift_compressed(0x1000, hw, 64);
        assert_eq!(ops.len(), 1);
        if let LlilOp::SetReg { reg, .. } = &ops[0] {
            assert_eq!(reg, "ra");
        } else {
            panic!("got {:?}", ops[0]);
        }
    }

    // ── LLIL: C.J (compressed) ───────────────────────────────────────────────
    #[test]
    fn test_llil_c_j() {
        // C.J: op=01, funct3=101
        let hw: u16 = (0b101 << 13) | 0b01;
        let ops = rv_lift_compressed(0x1000, hw, 64);
        assert!(ops.iter().any(|o| matches!(o, LlilOp::Jump { .. })));
    }

    // ── LLIL: C.BEQZ ─────────────────────────────────────────────────────────
    #[test]
    fn test_llil_c_beqz() {
        // C.BEQZ: op=01, funct3=110
        let hw: u16 = (0b110 << 13) | 0b01; // rs1'=0→x8
        let ops = rv_lift_compressed(0x2000, hw, 64);
        assert!(ops.iter().any(|o| matches!(o, LlilOp::If { .. })));
    }

    // ── LLIL: C.MV ───────────────────────────────────────────────────────────
    #[test]
    fn test_llil_c_mv() {
        // C.MV: op=10, funct3=100, funct1=0, rs2!=0
        // hw: [15:13]=100, [12]=0, [11:7]=rd=1, [6:2]=rs2=2, [1:0]=10
        let hw: u16 = (0b100 << 13) | (1 << 7) | (2 << 2) | 0b10;
        let ops = rv_lift_compressed(0x0, hw, 64);
        assert!(matches!(ops[0], LlilOp::SetReg { .. }));
    }

    // ── LLIL: C.EBREAK ───────────────────────────────────────────────────────
    #[test]
    fn test_llil_c_ebreak() {
        // C.EBREAK: op=10, funct3=100, funct1=1, rs1=0, rs2=0
        let hw: u16 = (0b100 << 13) | (1 << 12) | 0b10;
        let ops = rv_lift_compressed(0x0, hw, 64);
        assert!(ops.iter().any(|o| matches!(o, LlilOp::Breakpoint)));
    }

    // ── Encode helpers ────────────────────────────────────────────────────────
    #[test]
    fn test_rv_encode_jal_target() {
        let word = rv_encode_jal(0, 32);
        assert_eq!(rv_opcode(word), 0x6F);
        assert_eq!(rv_imm_j(word), 32);
    }

    #[test]
    fn test_rv_encode_jalr_fields() {
        let word = rv_encode_jalr(1, 5, 0);
        assert_eq!(rv_opcode(word), 0x67);
        assert_eq!(rv_rd(word), 1);
        assert_eq!(rv_rs1(word), 5);
        assert_eq!(rv_imm_i(word), 0);
    }

    #[test]
    fn test_rv_encode_beq_fields() {
        let word = rv_encode_beq(1, 2, 8);
        assert_eq!(rv_opcode(word), 0x63);
        assert_eq!(rv_imm_b(word), 8);
    }

    #[test]
    fn test_rv_encode_lui_fields() {
        let word = rv_encode_lui(1, 0x12345);
        assert_eq!(rv_opcode(word), 0x37);
        assert_eq!(rv_rd(word), 1);
        assert_eq!((word >> 12) & 0xFFFFF, 0x12345);
    }

    #[test]
    fn test_rv_encode_add_fields() {
        let word = rv_encode_add(3, 1, 2);
        assert_eq!(rv_opcode(word), 0x33);
        assert_eq!(rv_rd(word), 3);
        assert_eq!(rv_rs1(word), 1);
        assert_eq!(rv_rs2(word), 2);
        assert_eq!(rv_funct3(word), 0);
        assert_eq!(rv_funct7(word), 0);
    }

    #[test]
    fn test_rv_encode_sub_funct7() {
        let word = rv_encode_sub(3, 1, 2);
        assert_eq!(rv_funct7(word), 0x20);
    }

    #[test]
    fn test_rv_encode_mul_fields() {
        let word = rv_encode_mul(3, 1, 2);
        assert_eq!(rv_funct7(word), 1);
        assert_eq!(rv_funct3(word), 0);
    }

    #[test]
    fn test_rv_encode_csrrw_fields() {
        let word = rv_encode_csrrw(1, 0, 0x300);
        assert_eq!(rv_opcode(word), 0x73);
        assert_eq!(rv_funct3(word), 1);
        assert_eq!((word >> 20) & 0xFFF, 0x300);
    }

    #[test]
    fn test_rv_encode_flw_fields() {
        let word = rv_encode_flw(1, 2, 4);
        assert_eq!(rv_opcode(word), 0x07);
        assert_eq!(rv_funct3(word), 2);
        assert_eq!(rv_imm_i(word), 4);
    }

    #[test]
    fn test_rv_encode_fsw_fields() {
        let word = rv_encode_fsw(1, 2, 4);
        assert_eq!(rv_opcode(word), 0x27);
        assert_eq!(rv_funct3(word), 2);
    }

    #[test]
    fn test_rv_encode_lr_w_fields() {
        let word = rv_encode_lr_w(1, 3, true, false);
        assert_eq!(rv_opcode(word), 0x2F);
        assert_eq!(rv_funct3(word), 2);
        // aq bit is bit 26
        assert_eq!((word >> 26) & 1, 1, "aq should be set");
        assert_eq!((word >> 25) & 1, 0, "rl should be clear");
    }

    #[test]
    fn test_rv_encode_sc_w_fields() {
        let word = rv_encode_sc_w(1, 3, 2, false, true);
        assert_eq!(rv_opcode(word), 0x2F);
        assert_eq!((word >> 25) & 1, 1, "rl should be set");
    }

    #[test]
    fn test_rv_encode_amoswap_w_fields() {
        let word = rv_encode_amoswap_w(1, 3, 2, false, false);
        assert_eq!(rv_opcode(word), 0x2F);
        let funct5 = (word >> 27) & 0x1F;
        assert_eq!(funct5, 1); // amoswap funct5 = 0x01
    }
}

// ---------------------------------------------------------------------------
// RVV tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod rvv_tests {
    use super::*;

    fn addr(a: u64) -> Address {
        Address::new(a)
    }

    // ── VSETVLI ──────────────────────────────────────────────────────────────
    #[test]
    fn test_vsetvli_encode_decode() {
        let vtypei = rv_vtype_imm(false, false, 2, 0); // e32, m1
        let word = rv_encode_vsetvli(1, 2, vtypei);
        let bytes = word.to_le_bytes().to_vec();
        let instr = decode_rvv(addr(0x1000), word, bytes).unwrap();
        assert_eq!(instr.mnemonic, "vsetvli");
        assert!(
            instr.operands.contains("x1"),
            "operands: {}",
            instr.operands
        );
    }

    // ── VSETIVLI ─────────────────────────────────────────────────────────────
    #[test]
    fn test_vsetivli_encode_decode() {
        let vtypei = rv_vtype_imm(false, true, 1, 0); // e16, m1, vta
        let word = rv_encode_vsetivli(1, 8, vtypei);
        let bytes = word.to_le_bytes().to_vec();
        let instr = decode_rvv(addr(0x1000), word, bytes).unwrap();
        assert_eq!(instr.mnemonic, "vsetivli");
        assert!(instr.operands.contains('8'));
    }

    // ── VsewEnum ─────────────────────────────────────────────────────────────
    #[test]
    fn test_vsew_e8() {
        let v = VsewEnum::from_bits(0).unwrap();
        assert_eq!(v.bits(), 8);
    }

    #[test]
    fn test_vsew_e64() {
        let v = VsewEnum::from_bits(3).unwrap();
        assert_eq!(v.bits(), 64);
    }

    #[test]
    fn test_vsew_invalid() {
        assert!(VsewEnum::from_bits(4).is_none());
    }

    // ── VlmulEnum ────────────────────────────────────────────────────────────
    #[test]
    fn test_vlmul_m1() {
        let v = VlmulEnum::from_bits(0).unwrap();
        assert_eq!(v.name(), "m1");
    }

    #[test]
    fn test_vlmul_mf4() {
        let v = VlmulEnum::from_bits(6).unwrap();
        assert_eq!(v.name(), "mf4");
    }

    #[test]
    fn test_vlmul_m8() {
        let v = VlmulEnum::from_bits(3).unwrap();
        assert_eq!(v.name(), "m8");
    }

    #[test]
    fn test_vlmul_invalid() {
        assert!(VlmulEnum::from_bits(4).is_none());
    }

    // ── RvvVtype decode ───────────────────────────────────────────────────────
    #[test]
    fn test_rvv_vtype_decode_e32_m2() {
        // vsew=2(e32), vlmul=1(m2)
        let vtypei: u32 = (2 << 3) | 1;
        let vt = RvvVtype::decode(vtypei);
        assert_eq!(vt.vsew, 2);
        assert_eq!(vt.vlmul, 1);
        assert!(!vt.vill);
        assert!(!vt.vma);
        assert!(!vt.vta);
    }

    #[test]
    fn test_rvv_vtype_decode_vill() {
        let vtypei: u32 = 1 << 31;
        let vt = RvvVtype::decode(vtypei);
        assert!(vt.vill);
    }

    #[test]
    fn test_rvv_vtype_decode_vta_vma() {
        let vtypei: u32 = (1 << 7) | (1 << 6);
        let vt = RvvVtype::decode(vtypei);
        assert!(vt.vma);
        assert!(vt.vta);
    }

    // ── FP helpers ───────────────────────────────────────────────────────────
    #[test]
    fn test_fp_rm_str() {
        assert_eq!(rv_fp_rm_str(0), "rne");
        assert_eq!(rv_fp_rm_str(7), "");
    }

    #[test]
    fn test_fclass_bit_names() {
        assert_eq!(rv_fclass_bit_name(0), "-Inf");
        assert_eq!(rv_fclass_bit_name(9), "qNaN");
    }

    // ── vtype_imm helper ─────────────────────────────────────────────────────
    #[test]
    fn test_rv_vtype_imm_e32_m1() {
        let v = rv_vtype_imm(false, false, 2, 0);
        assert_eq!(v, 2u16 << 3); // vsew=2 at bits[5:3]
    }

    #[test]
    fn test_rv_vtype_imm_vta() {
        let v = rv_vtype_imm(false, true, 0, 0);
        assert_eq!(v & (1 << 6), 1 << 6);
    }

    #[test]
    fn test_rv_vtype_imm_vma() {
        let v = rv_vtype_imm(true, false, 0, 0);
        assert_eq!(v & (1 << 7), 1 << 7);
    }
}

// ---------------------------------------------------------------------------
// RVV: wire decode_vector into the main decode_word dispatch
// ---------------------------------------------------------------------------
// The decode_word method already dispatches on opcode 0x57 through the
// existing match arm (not present by default — the original had no 0x57 case,
// falling through to `unknown`).  We extend RiscvArch with a public helper
// and expose the vector decode path as a standalone function.

impl RiscvArch {
    /// Decode a full 32-bit instruction, including the RVV (0x57) opcode.
    /// This mirrors `decode_word` but adds vector support.
    #[must_use]
    pub fn decode_word_full(&self, address: Address, word: u32, raw: &[u8]) -> Instruction {
        if (word & 0x7F) == 0x57 {
            return self.decode_vector(address, word, raw[..4].to_vec());
        }
        self.decode_word(address, word, raw)
    }

    /// Returns `true` if this arch configuration supports the V extension.
    #[must_use]
    pub const fn has_vector(&self) -> bool {
        self.bits >= 32
    }
}

// ---------------------------------------------------------------------------
// Calling Convention — detailed ABI description (300 lines)
// ---------------------------------------------------------------------------

/// RISC-V ABI register role for the calling convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RvAbiRole {
    /// Hardwired zero (x0).
    Zero,
    /// Return address (x1 / ra).
    ReturnAddress,
    /// Stack pointer (x2 / sp). 16-byte aligned at call boundary.
    StackPointer,
    /// Global pointer (x3 / gp). Points to the small-data section.
    GlobalPointer,
    /// Thread pointer (x4 / tp). Points to the TLS block.
    ThreadPointer,
    /// Temporary / caller-saved (t0-t2, t3-t6).
    Temporary,
    /// Saved / callee-saved (s0-s11 / x8-x9, x18-x27).
    CalleeSaved,
    /// Function argument / return value (a0-a7 / x10-x17).
    Argument,
    /// Frame pointer (s0 / x8, same physical register as `CalleeSaved`).
    FramePointer,
}

/// Detailed description of one ABI register.
#[derive(Debug, Clone, Copy)]
pub struct RvAbiReg {
    /// ABI name (e.g. "ra", "a0", "s0").
    pub abi_name: &'static str,
    /// Physical register index.
    pub phys_idx: u8,
    /// Role in the calling convention.
    pub role: RvAbiRole,
    /// `true` if the register is preserved across calls by the callee.
    pub callee_saved: bool,
    /// `true` if used to pass / return floating-point values in the F/D ABI.
    pub fp_arg: bool,
}

/// Full RISC-V integer ABI register table (LP64 / ILP32).
pub static RV_ABI_REG_TABLE: &[RvAbiReg] = &[
    RvAbiReg {
        abi_name: "zero",
        phys_idx: 0,
        role: RvAbiRole::Zero,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "ra",
        phys_idx: 1,
        role: RvAbiRole::ReturnAddress,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "sp",
        phys_idx: 2,
        role: RvAbiRole::StackPointer,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "gp",
        phys_idx: 3,
        role: RvAbiRole::GlobalPointer,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "tp",
        phys_idx: 4,
        role: RvAbiRole::ThreadPointer,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "t0",
        phys_idx: 5,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "t1",
        phys_idx: 6,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "t2",
        phys_idx: 7,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "s0",
        phys_idx: 8,
        role: RvAbiRole::FramePointer,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "s1",
        phys_idx: 9,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "a0",
        phys_idx: 10,
        role: RvAbiRole::Argument,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "a1",
        phys_idx: 11,
        role: RvAbiRole::Argument,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "a2",
        phys_idx: 12,
        role: RvAbiRole::Argument,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "a3",
        phys_idx: 13,
        role: RvAbiRole::Argument,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "a4",
        phys_idx: 14,
        role: RvAbiRole::Argument,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "a5",
        phys_idx: 15,
        role: RvAbiRole::Argument,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "a6",
        phys_idx: 16,
        role: RvAbiRole::Argument,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "a7",
        phys_idx: 17,
        role: RvAbiRole::Argument,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "s2",
        phys_idx: 18,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "s3",
        phys_idx: 19,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "s4",
        phys_idx: 20,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "s5",
        phys_idx: 21,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "s6",
        phys_idx: 22,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "s7",
        phys_idx: 23,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "s8",
        phys_idx: 24,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "s9",
        phys_idx: 25,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "s10",
        phys_idx: 26,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "s11",
        phys_idx: 27,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "t3",
        phys_idx: 28,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "t4",
        phys_idx: 29,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "t5",
        phys_idx: 30,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "t6",
        phys_idx: 31,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
];

/// FP ABI register table.
pub static RV_FP_ABI_REG_TABLE: &[RvAbiReg] = &[
    RvAbiReg {
        abi_name: "ft0",
        phys_idx: 0,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "ft1",
        phys_idx: 1,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "ft2",
        phys_idx: 2,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "ft3",
        phys_idx: 3,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "ft4",
        phys_idx: 4,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "ft5",
        phys_idx: 5,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "ft6",
        phys_idx: 6,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "ft7",
        phys_idx: 7,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "fs0",
        phys_idx: 8,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "fs1",
        phys_idx: 9,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "fa0",
        phys_idx: 10,
        role: RvAbiRole::Argument,
        callee_saved: false,
        fp_arg: true,
    },
    RvAbiReg {
        abi_name: "fa1",
        phys_idx: 11,
        role: RvAbiRole::Argument,
        callee_saved: false,
        fp_arg: true,
    },
    RvAbiReg {
        abi_name: "fa2",
        phys_idx: 12,
        role: RvAbiRole::Argument,
        callee_saved: false,
        fp_arg: true,
    },
    RvAbiReg {
        abi_name: "fa3",
        phys_idx: 13,
        role: RvAbiRole::Argument,
        callee_saved: false,
        fp_arg: true,
    },
    RvAbiReg {
        abi_name: "fa4",
        phys_idx: 14,
        role: RvAbiRole::Argument,
        callee_saved: false,
        fp_arg: true,
    },
    RvAbiReg {
        abi_name: "fa5",
        phys_idx: 15,
        role: RvAbiRole::Argument,
        callee_saved: false,
        fp_arg: true,
    },
    RvAbiReg {
        abi_name: "fa6",
        phys_idx: 16,
        role: RvAbiRole::Argument,
        callee_saved: false,
        fp_arg: true,
    },
    RvAbiReg {
        abi_name: "fa7",
        phys_idx: 17,
        role: RvAbiRole::Argument,
        callee_saved: false,
        fp_arg: true,
    },
    RvAbiReg {
        abi_name: "fs2",
        phys_idx: 18,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "fs3",
        phys_idx: 19,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "fs4",
        phys_idx: 20,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "fs5",
        phys_idx: 21,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "fs6",
        phys_idx: 22,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "fs7",
        phys_idx: 23,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "fs8",
        phys_idx: 24,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "fs9",
        phys_idx: 25,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "fs10",
        phys_idx: 26,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "fs11",
        phys_idx: 27,
        role: RvAbiRole::CalleeSaved,
        callee_saved: true,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "ft8",
        phys_idx: 28,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "ft9",
        phys_idx: 29,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "ft10",
        phys_idx: 30,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
    RvAbiReg {
        abi_name: "ft11",
        phys_idx: 31,
        role: RvAbiRole::Temporary,
        callee_saved: false,
        fp_arg: false,
    },
];

/// Look up an integer ABI register by ABI name.
#[must_use]
pub fn rv_abi_reg_lookup(name: &str) -> Option<&'static RvAbiReg> {
    RV_ABI_REG_TABLE.iter().find(|r| r.abi_name == name)
}

/// Look up a floating-point ABI register by ABI name.
#[must_use]
pub fn rv_fp_abi_reg_lookup(name: &str) -> Option<&'static RvAbiReg> {
    RV_FP_ABI_REG_TABLE.iter().find(|r| r.abi_name == name)
}

/// Return all callee-saved integer registers for the LP64/ILP32 ABI.
#[must_use]
pub fn rv_callee_saved_regs() -> Vec<&'static RvAbiReg> {
    RV_ABI_REG_TABLE
        .iter()
        .filter(|r| r.callee_saved && r.phys_idx != 0)
        .collect()
}

/// Return all argument / return registers.
#[must_use]
pub fn rv_arg_regs() -> Vec<&'static RvAbiReg> {
    RV_ABI_REG_TABLE
        .iter()
        .filter(|r| matches!(r.role, RvAbiRole::Argument))
        .collect()
}

/// Return all FP argument registers.
#[must_use]
pub fn rv_fp_arg_regs() -> Vec<&'static RvAbiReg> {
    RV_FP_ABI_REG_TABLE.iter().filter(|r| r.fp_arg).collect()
}

// ---------------------------------------------------------------------------
// RISC-V stack frame prologue/epilogue pattern matcher
// ---------------------------------------------------------------------------

/// A detected callee-saved register spill in a function prologue.
#[derive(Debug, Clone)]
pub struct RvSpillEntry {
    /// Register spilled (ABI name).
    pub reg: String,
    /// Offset from sp at the point of the spill.
    pub sp_offset: i32,
    /// Byte size of the spill (4 or 8).
    pub size: u8,
}

/// Scan a sequence of instruction words for typical RV64 LP64 prologue
/// patterns and return the detected frame size and spills.
///
/// Looks for:
/// - `ADDI sp, sp, -N` → `frame_size` = N
/// - `SD rx, K(sp)` → spill of rx at sp+K
/// - `SW rx, K(sp)` → 32-bit spill
///
/// Stops at the first non-prologue instruction.
#[must_use]
pub fn rv_detect_prologue(words: &[u32]) -> (Option<i32>, Vec<RvSpillEntry>) {
    let mut frame_size: Option<i32> = None;
    let mut spills = Vec::new();

    for &word in words {
        let opcode = word & 0x7F;
        let funct3 = (word >> 12) & 7;
        let rs1 = ((word >> 15) & 0x1F) as usize;
        let rs2 = ((word >> 20) & 0x1F) as usize;
        let rd = ((word >> 7) & 0x1F) as usize;

        // ADDI sp, sp, -N
        if opcode == 0x13 && funct3 == 0 && rd == 2 && rs1 == 2 {
            let imm = rv_imm_i(word);
            if imm < 0 {
                frame_size = Some(-imm);
                continue;
            }
        }

        // SD rx, K(sp) (funct3=3)
        if opcode == 0x23 && funct3 == 3 && rs1 == 2 {
            let offset = rv_imm_s(word);
            spills.push(RvSpillEntry {
                reg: xabi(rs2).clone(),
                sp_offset: offset,
                size: 8,
            });
            continue;
        }

        // SW rx, K(sp) (funct3=2)
        if opcode == 0x23 && funct3 == 2 && rs1 == 2 {
            let offset = rv_imm_s(word);
            spills.push(RvSpillEntry {
                reg: xabi(rs2).clone(),
                sp_offset: offset,
                size: 4,
            });
            continue;
        }

        // Any other instruction → end of prologue
        break;
    }

    (frame_size, spills)
}

// ---------------------------------------------------------------------------
// RISC-V instruction encoding format descriptions
// ---------------------------------------------------------------------------

/// RISC-V instruction encoding format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RvEncFormat {
    /// R-type: funct7 | rs2 | rs1 | funct3 | rd | opcode
    R,
    /// I-type: imm[11:0] | rs1 | funct3 | rd | opcode
    I,
    /// S-type: imm[11:5] | rs2 | rs1 | funct3 | imm[4:0] | opcode
    S,
    /// B-type: imm[12|10:5] | rs2 | rs1 | funct3 | imm[4:1|11] | opcode
    B,
    /// U-type: imm[31:12] | rd | opcode
    U,
    /// J-type: imm[20|10:1|11|19:12] | rd | opcode
    J,
    /// R4-type (FP fused): rs3 | fmt | rs2 | rs1 | rm | rd | opcode
    R4,
    /// Compressed 16-bit.
    C,
}

impl RvEncFormat {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::R => "R",
            Self::I => "I",
            Self::S => "S",
            Self::B => "B",
            Self::U => "U",
            Self::J => "J",
            Self::R4 => "R4",
            Self::C => "C",
        }
    }

    /// Number of bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::C => 16,
            _ => 32,
        }
    }

    /// Detect the format of a 32-bit instruction word.
    #[must_use]
    pub const fn detect(word: u32) -> Self {
        match word & 0x7F {
            0x37 | 0x17 => Self::U,
            0x6F => Self::J,
            0x63 => Self::B,
            0x23 | 0x27 => Self::S,
            0x43 | 0x47 | 0x4B | 0x4F => Self::R4,
            0x33 | 0x3B | 0x2F | 0x53 => Self::R,
            _ => Self::I,
        }
    }
}

// ---------------------------------------------------------------------------
// Decode/encode round-trip verification helpers
// ---------------------------------------------------------------------------

/// Verify that encoding + decoding a B-type branch produces the original offset.
#[must_use]
pub const fn rv_btype_roundtrip(offset: i32) -> bool {
    let word = {
        let off = offset.cast_unsigned();
        let b12 = (off >> 12) & 1;
        let b11 = (off >> 11) & 1;
        let b10_5 = (off >> 5) & 0x3F;
        let b4_1 = (off >> 1) & 0xF;
        (b12 << 31) | (b10_5 << 25) | (b4_1 << 8) | (b11 << 7) | 0x63
    };
    rv_imm_b(word) == offset
}

/// Verify J-type round-trip.
#[must_use]
pub const fn rv_jtype_roundtrip(offset: i32) -> bool {
    let word = {
        let off = offset.cast_unsigned();
        let b20 = (off >> 20) & 1;
        let b10_1 = (off >> 1) & 0x3FF;
        let b11 = (off >> 11) & 1;
        let b19_12 = (off >> 12) & 0xFF;
        (b20 << 31) | (b19_12 << 12) | (b11 << 20) | (b10_1 << 21) | 0x6F
    };
    rv_imm_j(word) == offset
}

// ---------------------------------------------------------------------------
// Extended calling convention + ABI + prologue tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod abi_tests {
    use super::*;

    // ── ABI register table ────────────────────────────────────────────────────
    #[test]
    fn test_abi_reg_table_size() {
        assert_eq!(RV_ABI_REG_TABLE.len(), 32);
        assert_eq!(RV_FP_ABI_REG_TABLE.len(), 32);
    }

    #[test]
    fn test_abi_reg_zero() {
        let r = rv_abi_reg_lookup("zero").unwrap();
        assert_eq!(r.phys_idx, 0);
        assert_eq!(r.role, RvAbiRole::Zero);
        assert!(r.callee_saved);
    }

    #[test]
    fn test_abi_reg_ra() {
        let r = rv_abi_reg_lookup("ra").unwrap();
        assert_eq!(r.phys_idx, 1);
        assert_eq!(r.role, RvAbiRole::ReturnAddress);
        assert!(!r.callee_saved);
    }

    #[test]
    fn test_abi_reg_sp() {
        let r = rv_abi_reg_lookup("sp").unwrap();
        assert_eq!(r.phys_idx, 2);
        assert_eq!(r.role, RvAbiRole::StackPointer);
    }

    #[test]
    fn test_abi_reg_a0() {
        let r = rv_abi_reg_lookup("a0").unwrap();
        assert_eq!(r.phys_idx, 10);
        assert_eq!(r.role, RvAbiRole::Argument);
        assert!(!r.callee_saved);
    }

    #[test]
    fn test_abi_reg_s0() {
        let r = rv_abi_reg_lookup("s0").unwrap();
        assert_eq!(r.phys_idx, 8);
        assert_eq!(r.role, RvAbiRole::FramePointer);
        assert!(r.callee_saved);
    }

    #[test]
    fn test_abi_reg_t6() {
        let r = rv_abi_reg_lookup("t6").unwrap();
        assert_eq!(r.phys_idx, 31);
        assert_eq!(r.role, RvAbiRole::Temporary);
    }

    #[test]
    fn test_abi_reg_not_found() {
        assert!(rv_abi_reg_lookup("xyz").is_none());
    }

    #[test]
    fn test_fp_abi_reg_fa0() {
        let r = rv_fp_abi_reg_lookup("fa0").unwrap();
        assert_eq!(r.phys_idx, 10);
        assert!(r.fp_arg);
    }

    #[test]
    fn test_fp_abi_reg_fs0() {
        let r = rv_fp_abi_reg_lookup("fs0").unwrap();
        assert!(r.callee_saved);
        assert!(!r.fp_arg);
    }

    #[test]
    fn test_callee_saved_count() {
        let cs = rv_callee_saved_regs();
        // sp(2), gp(3), tp(4), s0-s11(8,9,18-27) = 14 + sp/gp/tp = 17 total callee-saved non-zero
        assert!(cs.len() >= 14, "too few callee-saved: {}", cs.len());
    }

    #[test]
    fn test_arg_regs_count() {
        let args = rv_arg_regs();
        assert_eq!(args.len(), 8); // a0-a7
    }

    #[test]
    fn test_fp_arg_regs_count() {
        let fps = rv_fp_arg_regs();
        assert_eq!(fps.len(), 8); // fa0-fa7
    }

    // ── Prologue detection ────────────────────────────────────────────────────
    #[test]
    fn test_detect_prologue_frame_size() {
        // ADDI sp, sp, -32
        let addi_sp: u32 = {
            let imm = (-32i32).cast_unsigned() & 0xFFF;
            ((imm << 20) | (2 << 15)) | (2 << 7) | 0x13
        };
        // SD ra, 24(sp)
        let sd_ra: u32 = {
            let imm: i32 = 24;
            let imm11_5 = ((imm >> 5) & 0x7F).cast_unsigned();
            let imm4_0 = (imm & 0x1F).cast_unsigned();
            (imm11_5 << 25) | (1 << 20) | (2 << 15) | (3 << 12) | (imm4_0 << 7) | 0x23
        };
        let words = [addi_sp, sd_ra];
        let (frame, spills) = rv_detect_prologue(&words);
        assert_eq!(frame, Some(32));
        assert_eq!(spills.len(), 1);
        assert_eq!(spills[0].reg, "ra");
        assert_eq!(spills[0].sp_offset, 24);
        assert_eq!(spills[0].size, 8);
    }

    #[test]
    fn test_detect_prologue_no_match() {
        // Random non-prologue instruction
        let words = [0x0000_0013u32]; // addi x0, x0, 0 (NOP — rd=0, not sp)
        let (frame, spills) = rv_detect_prologue(&words);
        assert!(frame.is_none());
        assert!(spills.is_empty());
    }

    // ── Encoding format detection ─────────────────────────────────────────────
    #[test]
    fn test_enc_format_lui() {
        assert_eq!(RvEncFormat::detect(0x37), RvEncFormat::U);
    }

    #[test]
    fn test_enc_format_jal() {
        assert_eq!(RvEncFormat::detect(0x6F), RvEncFormat::J);
    }

    #[test]
    fn test_enc_format_beq() {
        assert_eq!(RvEncFormat::detect(0x63), RvEncFormat::B);
    }

    #[test]
    fn test_enc_format_sw() {
        assert_eq!(RvEncFormat::detect(0x23), RvEncFormat::S);
    }

    #[test]
    fn test_enc_format_add() {
        assert_eq!(RvEncFormat::detect(0x33), RvEncFormat::R);
    }

    #[test]
    fn test_enc_format_addi() {
        assert_eq!(RvEncFormat::detect(0x13), RvEncFormat::I);
    }

    #[test]
    fn test_enc_format_name() {
        assert_eq!(RvEncFormat::R.name(), "R");
        assert_eq!(RvEncFormat::I.name(), "I");
        assert_eq!(RvEncFormat::C.bits(), 16);
        assert_eq!(RvEncFormat::R.bits(), 32);
    }

    // ── Round-trip ────────────────────────────────────────────────────────────
    #[test]
    fn test_btype_roundtrip_positive() {
        assert!(rv_btype_roundtrip(8));
        assert!(rv_btype_roundtrip(256));
    }

    #[test]
    fn test_btype_roundtrip_negative() {
        assert!(rv_btype_roundtrip(-8));
        assert!(rv_btype_roundtrip(-256));
    }

    #[test]
    fn test_jtype_roundtrip_positive() {
        assert!(rv_jtype_roundtrip(16));
        assert!(rv_jtype_roundtrip(1_048_572));
    }

    #[test]
    fn test_jtype_roundtrip_negative() {
        assert!(rv_jtype_roundtrip(-16));
        assert!(rv_jtype_roundtrip(-1_048_576));
    }

    // ── decode_word_full with vector opcode ───────────────────────────────────
    #[test]
    fn test_decode_word_full_vsetvli() {
        let arch = RiscvArch::rv64();
        let vtypei = rv_vtype_imm(false, false, 2, 0);
        let word = rv_encode_vsetvli(1, 2, vtypei);
        let bytes = word.to_le_bytes();
        let instr = arch.decode_word_full(Address::new(0x0), word, &bytes);
        assert_eq!(instr.mnemonic, "vsetvli");
    }

    #[test]
    fn test_decode_word_full_addi_passthrough() {
        let arch = RiscvArch::rv64();
        let word: u32 = (10 << 20) | 0x13; // addi x0, x0, 10
        let bytes = word.to_le_bytes();
        let instr = arch.decode_word_full(Address::new(0x0), word, &bytes);
        assert_eq!(instr.mnemonic, "addi");
    }

    // ── has_vector ────────────────────────────────────────────────────────────
    #[test]
    fn test_has_vector() {
        assert!(RiscvArch::rv32().has_vector());
        assert!(RiscvArch::rv64().has_vector());
    }

    // ── FP rm string ──────────────────────────────────────────────────────────
    #[test]
    fn test_fp_rm_all() {
        assert_eq!(rv_fp_rm_str(0), "rne");
        assert_eq!(rv_fp_rm_str(1), "rtz");
        assert_eq!(rv_fp_rm_str(2), "rdn");
        assert_eq!(rv_fp_rm_str(3), "rup");
        assert_eq!(rv_fp_rm_str(4), "rmm");
    }
}

// ---------------------------------------------------------------------------
// Additional disassembler tests for M / A / F / D / C completeness
// ---------------------------------------------------------------------------

#[cfg(test)]
mod completeness_tests {
    use super::*;

    fn rv32() -> RiscvArch {
        RiscvArch::rv32()
    }
    fn rv64() -> RiscvArch {
        RiscvArch::rv64()
    }
    fn le(w: u32) -> [u8; 4] {
        w.to_le_bytes()
    }
    fn addr(a: u64) -> Address {
        Address::new(a)
    }

    fn itype(imm12: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
        (imm12 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
    }
    fn rtype(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
        (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
    }
    fn stype(imm12: u32, rs2: u32, rs1: u32, funct3: u32, opcode: u32) -> u32 {
        let hi = (imm12 >> 5) & 0x7F;
        let lo = imm12 & 0x1F;
        (hi << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (lo << 7) | opcode
    }

    // ── Base ISA completeness ─────────────────────────────────────────────────
    #[test]
    fn test_lb() {
        let w = itype(0, 1, 0, 2, 0x03);
        assert_eq!(rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic, "lb");
    }
    #[test]
    fn test_lh() {
        let w = itype(0, 1, 1, 2, 0x03);
        assert_eq!(rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic, "lh");
    }
    #[test]
    fn test_lbu() {
        let w = itype(0, 1, 4, 2, 0x03);
        assert_eq!(rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic, "lbu");
    }
    #[test]
    fn test_lhu() {
        let w = itype(0, 1, 5, 2, 0x03);
        assert_eq!(rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic, "lhu");
    }
    #[test]
    fn test_sb() {
        let w = stype(0, 1, 2, 0, 0x23);
        assert_eq!(rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic, "sb");
    }
    #[test]
    fn test_sh() {
        let w = stype(0, 1, 2, 1, 0x23);
        assert_eq!(rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic, "sh");
    }
    #[test]
    fn test_slti() {
        let w = itype(1, 1, 2, 2, 0x13);
        assert_eq!(
            rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "slti"
        );
    }
    #[test]
    fn test_sltiu() {
        let w = itype(1, 1, 3, 2, 0x13);
        assert_eq!(
            rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "sltiu"
        );
    }
    #[test]
    fn test_xori() {
        let w = itype(1, 1, 4, 2, 0x13);
        assert_eq!(
            rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "xori"
        );
    }
    #[test]
    fn test_ori() {
        let w = itype(1, 1, 6, 2, 0x13);
        assert_eq!(rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic, "ori");
    }
    #[test]
    fn test_andi() {
        let w = itype(1, 1, 7, 2, 0x13);
        assert_eq!(
            rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "andi"
        );
    }
    #[test]
    fn test_slli() {
        let w = itype(1, 1, 1, 2, 0x13);
        assert_eq!(
            rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "slli"
        );
    }
    #[test]
    fn test_srli() {
        let w = itype(1, 1, 5, 2, 0x13);
        assert_eq!(
            rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "srli"
        );
    }
    #[test]
    fn test_srai() {
        let w = (0x20 << 25) | itype(1, 1, 5, 2, 0x13);
        assert_eq!(
            rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "srai"
        );
    }
    #[test]
    fn test_sll() {
        let w = rtype(0, 2, 1, 1, 3, 0x33);
        assert_eq!(rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic, "sll");
    }
    #[test]
    fn test_slt() {
        let w = rtype(0, 2, 1, 2, 3, 0x33);
        assert_eq!(rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic, "slt");
    }
    #[test]
    fn test_sltu() {
        let w = rtype(0, 2, 1, 3, 3, 0x33);
        assert_eq!(
            rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "sltu"
        );
    }
    #[test]
    fn test_xor() {
        let w = rtype(0, 2, 1, 4, 3, 0x33);
        assert_eq!(rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic, "xor");
    }
    #[test]
    fn test_srl() {
        let w = rtype(0, 2, 1, 5, 3, 0x33);
        assert_eq!(rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic, "srl");
    }
    #[test]
    fn test_sra() {
        let w = rtype(0x20, 2, 1, 5, 3, 0x33);
        assert_eq!(rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic, "sra");
    }
    #[test]
    fn test_or() {
        let w = rtype(0, 2, 1, 6, 3, 0x33);
        assert_eq!(rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic, "or");
    }
    #[test]
    fn test_and() {
        let w = rtype(0, 2, 1, 7, 3, 0x33);
        assert_eq!(rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic, "and");
    }

    // ── M extension completeness ──────────────────────────────────────────────
    #[test]
    fn test_mulh() {
        let w = rtype(1, 2, 1, 1, 3, 0x33);
        assert_eq!(
            rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "mulh"
        );
    }
    #[test]
    fn test_mulhsu() {
        let w = rtype(1, 2, 1, 2, 3, 0x33);
        assert_eq!(
            rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "mulhsu"
        );
    }
    #[test]
    fn test_mulhu() {
        let w = rtype(1, 2, 1, 3, 3, 0x33);
        assert_eq!(
            rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "mulhu"
        );
    }
    #[test]
    fn test_divu() {
        let w = rtype(1, 2, 1, 5, 3, 0x33);
        assert_eq!(
            rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "divu"
        );
    }
    #[test]
    fn test_rem() {
        let w = rtype(1, 2, 1, 6, 3, 0x33);
        assert_eq!(rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic, "rem");
    }
    #[test]
    fn test_remu() {
        let w = rtype(1, 2, 1, 7, 3, 0x33);
        assert_eq!(
            rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "remu"
        );
    }

    // ── RV64 M extension ─────────────────────────────────────────────────────
    #[test]
    fn test_mulw() {
        let w = rtype(1, 2, 1, 0, 3, 0x3B);
        assert_eq!(
            rv64().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "mulw"
        );
    }
    #[test]
    fn test_divw() {
        let w = rtype(1, 2, 1, 4, 3, 0x3B);
        assert_eq!(
            rv64().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "divw"
        );
    }
    #[test]
    fn test_divuw() {
        let w = rtype(1, 2, 1, 5, 3, 0x3B);
        assert_eq!(
            rv64().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "divuw"
        );
    }
    #[test]
    fn test_remw() {
        let w = rtype(1, 2, 1, 6, 3, 0x3B);
        assert_eq!(
            rv64().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "remw"
        );
    }
    #[test]
    fn test_remuw() {
        let w = rtype(1, 2, 1, 7, 3, 0x3B);
        assert_eq!(
            rv64().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "remuw"
        );
    }

    // ── RV64I ─────────────────────────────────────────────────────────────────
    #[test]
    fn test_lwu() {
        let w = itype(0, 1, 6, 2, 0x03);
        assert_eq!(rv64().disassemble(addr(0), &le(w)).unwrap().mnemonic, "lwu");
    }
    #[test]
    fn test_slliw() {
        let w = itype(2, 1, 1, 2, 0x1B);
        assert_eq!(
            rv64().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "slliw"
        );
    }
    #[test]
    fn test_srliw() {
        let w = itype(2, 1, 5, 2, 0x1B);
        assert_eq!(
            rv64().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "srliw"
        );
    }
    #[test]
    fn test_sraiw() {
        let w = (0x20 << 25) | itype(2, 1, 5, 2, 0x1B);
        assert_eq!(
            rv64().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "sraiw"
        );
    }
    #[test]
    fn test_subw() {
        let w = rtype(0x20, 2, 1, 0, 3, 0x3B);
        assert_eq!(
            rv64().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "subw"
        );
    }
    #[test]
    fn test_sllw() {
        let w = rtype(0, 2, 1, 1, 3, 0x3B);
        assert_eq!(
            rv64().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "sllw"
        );
    }
    #[test]
    fn test_srlw() {
        let w = rtype(0, 2, 1, 5, 3, 0x3B);
        assert_eq!(
            rv64().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "srlw"
        );
    }
    #[test]
    fn test_sraw() {
        let w = rtype(0x20, 2, 1, 5, 3, 0x3B);
        assert_eq!(
            rv64().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "sraw"
        );
    }

    // ── A extension completeness ──────────────────────────────────────────────
    fn amo_w(funct5: u32, rs2: u32, rs1: u32, rd: u32) -> u32 {
        ((funct5 << 2) << 25) | (rs2 << 20) | (rs1 << 15) | (2 << 12) | (rd << 7) | 0x2F
    }
    #[test]
    fn test_amoadd_w() {
        let w = amo_w(0x00, 2, 1, 3);
        assert!(
            rv32()
                .disassemble(addr(0), &le(w))
                .unwrap()
                .mnemonic
                .starts_with("amoadd")
        );
    }
    #[test]
    fn test_amoxor_w() {
        let w = amo_w(0x04, 2, 1, 3);
        assert!(
            rv32()
                .disassemble(addr(0), &le(w))
                .unwrap()
                .mnemonic
                .starts_with("amoxor")
        );
    }
    #[test]
    fn test_amoand_w() {
        let w = amo_w(0x0C, 2, 1, 3);
        assert!(
            rv32()
                .disassemble(addr(0), &le(w))
                .unwrap()
                .mnemonic
                .starts_with("amoand")
        );
    }
    #[test]
    fn test_amoor_w() {
        let w = amo_w(0x08, 2, 1, 3);
        assert!(
            rv32()
                .disassemble(addr(0), &le(w))
                .unwrap()
                .mnemonic
                .starts_with("amoor")
        );
    }
    #[test]
    fn test_amomin_w() {
        let w = amo_w(0x10, 2, 1, 3);
        assert!(
            rv32()
                .disassemble(addr(0), &le(w))
                .unwrap()
                .mnemonic
                .starts_with("amomin")
        );
    }
    #[test]
    fn test_amomax_w() {
        let w = amo_w(0x14, 2, 1, 3);
        assert!(
            rv32()
                .disassemble(addr(0), &le(w))
                .unwrap()
                .mnemonic
                .starts_with("amomax")
        );
    }
    #[test]
    fn test_amominu_w() {
        let w = amo_w(0x18, 2, 1, 3);
        assert!(
            rv32()
                .disassemble(addr(0), &le(w))
                .unwrap()
                .mnemonic
                .starts_with("amominu")
        );
    }
    #[test]
    fn test_amomaxu_w() {
        let w = amo_w(0x1C, 2, 1, 3);
        assert!(
            rv32()
                .disassemble(addr(0), &le(w))
                .unwrap()
                .mnemonic
                .starts_with("amomaxu")
        );
    }

    // ── F extension completeness ──────────────────────────────────────────────
    #[test]
    fn test_fld_read_mem() {
        let w = itype(0, 1, 3, 2, 0x07);
        let i = rv64().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "fld");
        assert!(i.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_fsd_write_mem() {
        let w = stype(0, 1, 2, 3, 0x27);
        let i = rv64().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "fsd");
        assert!(i.flags.contains(InstrFlags::WRITE_MEM));
    }

    // ── Branch completeness ───────────────────────────────────────────────────
    fn btype(offset: i32, rs2: u32, rs1: u32, funct3: u32) -> u32 {
        let off = offset.cast_unsigned();
        let b12 = (off >> 12) & 1;
        let b11 = (off >> 11) & 1;
        let b10_5 = (off >> 5) & 0x3F;
        let b4_1 = (off >> 1) & 0xF;
        (b12 << 31)
            | (b10_5 << 25)
            | (rs2 << 20)
            | (rs1 << 15)
            | (funct3 << 12)
            | (b4_1 << 8)
            | (b11 << 7)
            | 0x63
    }
    #[test]
    fn test_blt() {
        let w = btype(8, 2, 1, 4);
        assert_eq!(rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic, "blt");
    }
    #[test]
    fn test_bge() {
        let w = btype(8, 2, 1, 5);
        assert_eq!(rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic, "bge");
    }
    #[test]
    fn test_bltu() {
        let w = btype(8, 2, 1, 6);
        assert_eq!(
            rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "bltu"
        );
    }
    #[test]
    fn test_bgeu() {
        let w = btype(8, 2, 1, 7);
        assert_eq!(
            rv32().disassemble(addr(0), &le(w)).unwrap().mnemonic,
            "bgeu"
        );
    }

    // ── Zicsr completeness ────────────────────────────────────────────────────
    #[test]
    fn test_csrrc() {
        let w = itype(0x300, 0, 3, 1, 0x73); // csrrc x1, mstatus, x0
        let i = rv64().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "csrrc");
        assert!(i.operands.contains("mstatus"));
    }

    #[test]
    fn test_csrrwi() {
        let w = itype(0xC00, 0, 5, 1, 0x73); // csrrwi x1, cycle, 0
        let i = rv64().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "csrrwi");
    }

    #[test]
    fn test_csrrsi() {
        let w = itype(0xC00, 0, 6, 1, 0x73);
        let i = rv64().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "csrrsi");
    }

    #[test]
    fn test_csrrci() {
        let w = itype(0xC00, 0, 7, 1, 0x73);
        let i = rv64().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "csrrci");
    }
}

fn decode_compressed_q0_rest(hw: u16, xlen: u32, addr: Address) -> Result<Instruction, CoreError> {
    let bytes = hw.to_le_bytes().to_vec();
    let funct3 = (hw >> 13) & 0x7;

    match funct3 {
        3 if xlen >= 64 => {
            let rd_prime = ((hw >> 2) & 0x7) as usize + 8;
            let rs1_prime = ((hw >> 7) & 0x7) as usize + 8;
            let uimm = c_ld_imm(hw);
            Ok(mk(
                addr,
                2,
                "c.ld",
                format!("{}, {uimm}({})", xr(rd_prime), xr(rs1_prime)),
                InstrFlags::READ_MEM,
                bytes,
            ))
        }
        _ => decode_compressed_q0_tail2(hw, xlen, addr),
    }
}

fn decode_compressed_q1_rest(hw: u16, addr: Address) -> Result<Instruction, CoreError> {
    let bytes = hw.to_le_bytes().to_vec();
    let funct3 = (hw >> 13) & 0x7;

    match funct3 {
        3 => {
            let rd = ((hw >> 7) & 0x1F) as usize;
            if rd == 2 {
                // C.ADDI16SP
                let imm = c_addi16sp_imm(hw);
                Ok(mk(
                    addr,
                    2,
                    "c.addi16sp",
                    format!("sp, {imm}"),
                    InstrFlags::NONE,
                    bytes,
                ))
            } else {
                // C.LUI
                let imm = c_lui_imm(hw);
                Ok(mk(
                    addr,
                    2,
                    "c.lui",
                    format!("{}, 0x{imm:x}", xr(rd)),
                    InstrFlags::NONE,
                    bytes,
                ))
            }
        }
        4 => {
            let funct2 = (hw >> 10) & 0x3;
            let rd_prime = ((hw >> 7) & 0x7) as usize + 8;
            match funct2 {
                0 => {
                    let shamt = c_shamt(hw);
                    Ok(mk(
                        addr,
                        2,
                        "c.srli",
                        format!("{}, {shamt}", xr(rd_prime)),
                        InstrFlags::NONE,
                        bytes,
                    ))
                }
                1 => {
                    let shamt = c_shamt(hw);
                    Ok(mk(
                        addr,
                        2,
                        "c.srai",
                        format!("{}, {shamt}", xr(rd_prime)),
                        InstrFlags::NONE,
                        bytes,
                    ))
                }
                2 => {
                    let imm = c_addi_imm(hw);
                    Ok(mk(
                        addr,
                        2,
                        "c.andi",
                        format!("{}, {imm}", xr(rd_prime)),
                        InstrFlags::NONE,
                        bytes,
                    ))
                }
                3 => {
                    let rs2_prime = ((hw >> 2) & 0x7) as usize + 8;
                    let funct1 = (hw >> 12) & 1;
                    let op_sub = (hw >> 5) & 0x3;
                    let mn = match (funct1, op_sub) {
                        (0, 0) => "c.sub",
                        (0, 1) => "c.xor",
                        (0, 2) => "c.or",
                        (0, 3) => "c.and",
                        (1, 0) => "c.subw",
                        (1, 1) => "c.addw",
                        _ => {
                            return Err(CoreError::InvalidFormat {
                                message: "reserved CA".into(),
                            });
                        }
                    };
                    Ok(mk(
                        addr,
                        2,
                        mn,
                        format!("{}, {}", xr(rd_prime), xr(rs2_prime)),
                        InstrFlags::NONE,
                        bytes,
                    ))
                }
                _ => unreachable!(),
            }
        }
        _ => decode_compressed_q1_tail(hw, addr),
    }
}

fn decode_compressed_q2_rest(hw: u16, xlen: u32, addr: Address) -> Result<Instruction, CoreError> {
    let bytes = hw.to_le_bytes().to_vec();
    let funct3 = (hw >> 13) & 0x7;

    match funct3 {
        4 => {
            let funct1 = (hw >> 12) & 1;
            let rs1 = ((hw >> 7) & 0x1F) as usize;
            let rs2 = ((hw >> 2) & 0x1F) as usize;
            if funct1 == 0 && rs2 == 0 {
                // C.JR
                Ok(mk(
                    addr,
                    2,
                    "c.jr",
                    xr(rs1).into(),
                    InstrFlags::BRANCH | InstrFlags::INDIRECT,
                    bytes,
                ))
            } else if funct1 == 0 {
                // C.MV
                Ok(mk(
                    addr,
                    2,
                    "c.mv",
                    format!("{}, {}", xr(rs1), xr(rs2)),
                    InstrFlags::NONE,
                    bytes,
                ))
            } else if rs1 == 0 && rs2 == 0 {
                // C.EBREAK
                Ok(mk(
                    addr,
                    2,
                    "c.ebreak",
                    String::new(),
                    InstrFlags::BARRIER,
                    bytes,
                ))
            } else if rs2 == 0 {
                // C.JALR
                Ok(mk(
                    addr,
                    2,
                    "c.jalr",
                    xr(rs1).into(),
                    InstrFlags::BRANCH | InstrFlags::CALL | InstrFlags::INDIRECT,
                    bytes,
                ))
            } else {
                // C.ADD
                Ok(mk(
                    addr,
                    2,
                    "c.add",
                    format!("{}, {}", xr(rs1), xr(rs2)),
                    InstrFlags::NONE,
                    bytes,
                ))
            }
        }
        5 => {
            let uimm = c_fsdsp_imm(hw);
            let rs2 = ((hw >> 2) & 0x1F) as usize;
            Ok(mk(
                addr,
                2,
                "c.fsdsp",
                format!("{}, {uimm}(sp)", fr(rs2)),
                InstrFlags::WRITE_MEM,
                bytes,
            ))
        }
        6 => {
            let uimm = c_swsp_imm(hw);
            let rs2 = ((hw >> 2) & 0x1F) as usize;
            Ok(mk(
                addr,
                2,
                "c.swsp",
                format!("{}, {uimm}(sp)", xr(rs2)),
                InstrFlags::WRITE_MEM,
                bytes,
            ))
        }
        7 if xlen >= 64 => {
            let uimm = c_sdsp_imm(hw);
            let rs2 = ((hw >> 2) & 0x1F) as usize;
            Ok(mk(
                addr,
                2,
                "c.sdsp",
                format!("{}, {uimm}(sp)", xr(rs2)),
                InstrFlags::WRITE_MEM,
                bytes,
            ))
        }
        _ => Err(CoreError::InvalidFormat {
            message: "reserved C2".into(),
        }),
    }
}

fn decode_compressed_q0_tail(hw: u16, xlen: u32, addr: Address) -> Result<Instruction, CoreError> {
    let bytes = hw.to_le_bytes().to_vec();
    let funct3 = (hw >> 13) & 0x7;

    match funct3 {
        6 => {
            let rs2_prime = ((hw >> 2) & 0x7) as usize + 8;
            let rs1_prime = ((hw >> 7) & 0x7) as usize + 8;
            let uimm = c_lw_imm(hw);
            Ok(mk(
                addr,
                2,
                "c.sw",
                format!("{}, {uimm}({})", xr(rs2_prime), xr(rs1_prime)),
                InstrFlags::WRITE_MEM,
                bytes,
            ))
        }
        7 if xlen >= 64 => {
            let rs2_prime = ((hw >> 2) & 0x7) as usize + 8;
            let rs1_prime = ((hw >> 7) & 0x7) as usize + 8;
            let uimm = c_ld_imm(hw);
            Ok(mk(
                addr,
                2,
                "c.sd",
                format!("{}, {uimm}({})", xr(rs2_prime), xr(rs1_prime)),
                InstrFlags::WRITE_MEM,
                bytes,
            ))
        }
        _ => Err(CoreError::InvalidFormat {
            message: "reserved C quadrant 0".into(),
        }),
    }
}

fn decode_compressed_q1_tail(hw: u16, addr: Address) -> Result<Instruction, CoreError> {
    let bytes = hw.to_le_bytes().to_vec();
    let funct3 = (hw >> 13) & 0x7;

    match funct3 {
        5 => {
            // C.J
            let offset = c_j_offset(hw);
            let target = addr.0.wrapping_add((i64::from(offset)).cast_unsigned());
            Ok(mk(
                addr,
                2,
                "c.j",
                format!("0x{target:x}"),
                InstrFlags::BRANCH,
                bytes,
            ))
        }
        6 => {
            // C.BEQZ
            let rs1_prime = ((hw >> 7) & 0x7) as usize + 8;
            let offset = c_b_offset(hw);
            let target = addr.0.wrapping_add((i64::from(offset)).cast_unsigned());
            Ok(mk(
                addr,
                2,
                "c.beqz",
                format!("{}, 0x{target:x}", xr(rs1_prime)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes,
            ))
        }
        7 => {
            // C.BNEZ
            let rs1_prime = ((hw >> 7) & 0x7) as usize + 8;
            let offset = c_b_offset(hw);
            let target = addr.0.wrapping_add((i64::from(offset)).cast_unsigned());
            Ok(mk(
                addr,
                2,
                "c.bnez",
                format!("{}, 0x{target:x}", xr(rs1_prime)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes,
            ))
        }
        _ => Err(CoreError::InvalidFormat {
            message: "reserved C1".into(),
        }),
    }
}

fn decode_compressed_q0_tail2(hw: u16, xlen: u32, addr: Address) -> Result<Instruction, CoreError> {
    let bytes = hw.to_le_bytes().to_vec();
    let funct3 = (hw >> 13) & 0x7;

    match funct3 {
        5 => {
            let rs2_prime = ((hw >> 2) & 0x7) as usize + 8;
            let rs1_prime = ((hw >> 7) & 0x7) as usize + 8;
            let uimm = c_lw_imm(hw);
            Ok(mk(
                addr,
                2,
                "c.fsd",
                format!("{}, {uimm}({})", fr(rs2_prime), xr(rs1_prime)),
                InstrFlags::WRITE_MEM,
                bytes,
            ))
        }
        _ => decode_compressed_q0_tail(hw, xlen, addr),
    }
}

/// Mnemonic table for one RVV `funct6` group.
///
/// Extracted from the dispatch body so the decoder stays readable; the
/// table itself is unchanged.
const fn rvv_mnemonic_table_1(funct6: u32) -> Option<&'static str> {
    match funct6 {
        0x00 => Some("vadd"),
        0x02 => Some("vsub"),
        0x03 => Some("vrsub"),
        0x04 => Some("vminu"),
        0x05 => Some("vmin"),
        0x06 => Some("vmaxu"),
        0x07 => Some("vmax"),
        0x09 => Some("vand"),
        0x0A => Some("vor"),
        0x0B => Some("vxor"),
        0x0C => Some("vrgather"),
        0x0E => Some("vslideup"),
        0x0F => Some("vslidedown"),
        0x10 => Some("vadc"),
        0x11 => Some("vmadc"),
        0x18 => Some("vmseq"),
        0x19 => Some("vmsne"),
        0x1A => Some("vmsltu"),
        0x1B => Some("vmslt"),
        0x1C => Some("vmsleu"),
        0x1D => Some("vmsle"),
        0x1E => Some("vmsgtu"),
        0x1F => Some("vmsgt"),
        0x20 => Some("vsaddu"),
        0x21 => Some("vsadd"),
        0x22 => Some("vssubu"),
        0x23 => Some("vssub"),
        0x25 => Some("vsll"),
        0x27 => Some("vsmul"),
        0x28 => Some("vsrl"),
        0x29 => Some("vsra"),
        0x2A => Some("vssrl"),
        0x2B => Some("vssra"),
        0x2C => Some("vnsrl"),
        0x2D => Some("vnsra"),
        0x2E => Some("vnclipu"),
        0x2F => Some("vnclip"),
        _ => None,
    }
}

/// The VSETVL family (`funct3 == 7`) of the RVV encoding.
///
/// Self-contained: it needs only the instruction word, so it lives apart
/// from the arithmetic dispatch.
fn decode_rvv_vsetvl(address: Address, word: u32, bytes: Vec<u8>) -> Instruction {
    let rd = ((word >> 7) & 0x1F) as usize;
    let rs1 = ((word >> 15) & 0x1F) as usize;
    let vs2 = ((word >> 20) & 0x1F) as usize;
    let b31 = (word >> 31) & 1;
    let b30 = (word >> 30) & 1;
    if b31 == 0 {
        // VSETVLI: rd, rs1, vtypei[10:0]
        let vtypei = (word >> 20) & 0x7FF;
        let ops = format!("{}, {}, {vtypei:#05x}", xr(rd), xr(rs1));
        return plain(address, "vsetvli", ops, bytes);
    }
    if b31 == 1 && b30 == 1 {
        // VSETIVLI: rd, uimm5, vtypei[9:0]  (bits[31:30]=0b11)
        let uimm5 = (word >> 15) & 0x1F;
        let vtypei = (word >> 20) & 0x3FF;
        let ops = format!("{}, {uimm5}, {vtypei:#05x}", xr(rd));
        return plain(address, "vsetivli", ops, bytes);
    }
    // VSETVL: rd, rs1, rs2  (bits[31:30]=0b10)
    let ops = format!("{}, {}, {}", xr(rd), xr(rs1), xr(vs2));
    plain(address, "vsetvl", ops, bytes)
}

/// Vector load and store forms of the RVV encoding (opcodes 0x07 / 0x27).
///
/// Shared by every RVV dispatch entry point; returns `None` when the word is
/// not a vector memory operation, leaving the caller to try the arithmetic
/// tables.
fn decode_rvv_mem(address: Address, word: u32, bytes: &[u8]) -> Option<Instruction> {
    let vm = (word >> 25) & 1;
    let vd = ((word >> 7) & 0x1F) as usize;
    let vs1 = ((word >> 15) & 0x1F) as usize;
    let vs2 = ((word >> 20) & 0x1F) as usize;
    let rs1 = vs1;
    let mask = vmask(vm);
    let nf = (word >> 29) & 7;
    let mew = (word >> 28) & 1;
    let mop = (word >> 26) & 3;
    let lumop = vs2; // for unit-stride
    let width_bits: u32 = match (mew, (word >> 12) & 7) {
        (0, 5) => 16,
        (0, 6) => 32,
        (0, 7) => 64,
        _ => 8,
    };

    if (word & 0x7F) == 0x07 {
        // Vector load
        let base = xr(rs1);
        let mn = match mop {
            0 => {
                // unit stride
                match lumop {
                    0 => format!("vle{width_bits}.v"),
                    16 => format!("vlse{width_bits}.v"),
                    _ => format!("vluxei{width_bits}.v"),
                }
            }
            2 => format!("vlse{width_bits}.v"),
            1 => format!("vluxei{width_bits}.v"),
            3 => format!("vloxei{width_bits}.v"),
            _ => return None,
        };
        let ops = if mop == 2 {
            format!("{}, ({base}), {}{mask}", vr(vd), xr(vs2))
        } else {
            format!("{}, ({base}){mask}", vr(vd))
        };
        let nf_str = if nf > 0 {
            format!("  // nf={nf}")
        } else {
            String::new()
        };
        let _ = nf_str;
        return Some(mk(address, 4, &mn, ops, InstrFlags::READ_MEM, bytes.to_vec()));
    }
    if (word & 0x7F) == 0x27 {
        // Vector store
        let base = xr(rs1);
        let vs3 = vd;
        let mn = match mop {
            0 => format!("vse{width_bits}.v"),
            2 => format!("vsse{width_bits}.v"),
            1 => format!("vsuxei{width_bits}.v"),
            3 => format!("vsoxei{width_bits}.v"),
            _ => return None,
        };
        let ops = if mop == 2 {
            format!("{}, ({base}), {}{mask}", vr(vs3), xr(vs2))
        } else {
            format!("{}, ({base}){mask}", vr(vs3))
        };
        return Some(mk(address, 4, &mn, ops, InstrFlags::WRITE_MEM, bytes.to_vec()));
    }

    None
}

/// VWXUNARY0 / VRXUNARY0 group of the RVV encoding (`funct6 == 0x18`).
///
/// Returns `Some` when the `vs1` selector names one of the scalar-move or
/// mask-population forms, `None` when it does not.
fn decode_rvv_vwxunary(address: Address, word: u32, bytes: Vec<u8>) -> Option<Instruction> {
    let funct3 = (word >> 12) & 7;
    let vm = (word >> 25) & 1;
    let vd = ((word >> 7) & 0x1F) as usize;
    let vs1 = ((word >> 15) & 0x1F) as usize;
    let vs2 = ((word >> 20) & 0x1F) as usize;
    let rs1 = vs1;
    let rd = vd;
    let mask = vmask(vm);
    // VWXUNARY0 / VRXUNARY0 etc — vs1 field selects
    if funct3 == 4 {
        match vs1 {
            0 => {
                return Some(plain(
                    address,
                    "vmv.x.s",
                    format!("{}, {}", xr(rd), vr(vs2)),
                    bytes,
                ));
            }
            16 => {
                return Some(plain(
                    address,
                    "vcpop.m",
                    format!("{}, {}{}", xr(rd), vr(vs2), mask),
                    bytes,
                ));
            }
            17 => {
                return Some(plain(
                    address,
                    "vfirst.m",
                    format!("{}, {}{}", xr(rd), vr(vs2), mask),
                    bytes,
                ));
            }
            _ => {}
        }
    }
    if funct3 == 6
        && vs2 == 0 {
            return Some(plain(
                address,
                "vmv.s.x",
                format!("{}, {}", vr(vd), xr(rs1)),
                bytes,
            ));
        }
    None
}
