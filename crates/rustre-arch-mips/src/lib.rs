//! `rustre-arch-mips`
//!
//! Complete MIPS I/II/III/IV/32r2/64 architecture implementation.
//! Supports big-endian (MIPSEB) and little-endian (MIPSEL), O32/N32/N64 ABIs.
//! Every branch and jump has a 1-instruction delay slot (modeled in LLIL).
//! Full FPU coprocessor 1 (COP1), COP1X fused multiply, SPECIAL2, SPECIAL3.

/// MIPS FPU (Coprocessor 1): MipsFpuState, FCSRFlags, all FPU instructions,
/// FpuCondition, and MipsFpuLifter.
pub mod mips_fpu;

/// MIPS CP0 (coprocessor 0) register catalogue with select-field awareness.
pub mod mips_cop0_registers;

/// MIPS calling conventions: O32/N32/N64 register lists, callee/caller-saved sets,
/// stack-frame layout helpers, and FPU argument registers.
pub mod mips_calling_conventions;

/// Delay-slot analysis framework: DelaySlotKind, MipsJumpOpcode, DelaySlotInsn,
/// BranchWithDelay, and DelaySlotAnalyzer.
pub mod mips_delay_slot;

/// Higher-level MIPS analysis: DelaySlotAnalyzer, GlobalPointerUsage, MipsAbi,
/// MipsExceptionHandler, MipsTlb, MipsBranchTargetTable, MipsAnalysis.
pub mod mips_analysis;

/// MIPS ABI analysis.
///
/// Includes O32Abi, N64Abi, MipsEabi, ArgPassingRules, GlobalPointerUsage,
/// GotEntry, MipsAbiAnalysis facade.
pub mod mips_abi_analysis;

use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
};
use rustre_core::address::Address;
use rustre_core::arch::{BranchCondition, RegisterKind};
use rustre_core::endian::Endian;
use rustre_core::errors::CoreError;

// ---------------------------------------------------------------------------
// Public configuration types
// ---------------------------------------------------------------------------

/// Byte-order configuration for a MIPS target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MipsEndian {
    Little,
    Big,
}

/// MIPS ABI variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MipsAbi {
    /// Classic O32 ABI — $a0-$a3 arguments, $v0-$v1 return, $t0-$t9 temporaries, $s0-$s7 saved.
    O32,
    /// N32 — ILP32 with 64-bit registers, $a0-$a7 arguments.
    N32,
    /// N64 — LP64, $a0-$a7 arguments.
    N64,
}

/// Whether an instruction occupies a branch delay slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DelaySlot {
    None,
    BranchDelay,
}

// ---------------------------------------------------------------------------
// Register numbers as named constants
// ---------------------------------------------------------------------------

pub const REG_ZERO: usize = 0;
pub const REG_AT: usize = 1;
pub const REG_V0: usize = 2;
pub const REG_V1: usize = 3;
pub const REG_A0: usize = 4;
pub const REG_A1: usize = 5;
pub const REG_A2: usize = 6;
pub const REG_A3: usize = 7;
pub const REG_T0: usize = 8;
pub const REG_T1: usize = 9;
pub const REG_T2: usize = 10;
pub const REG_T3: usize = 11;
pub const REG_T4: usize = 12;
pub const REG_T5: usize = 13;
pub const REG_T6: usize = 14;
pub const REG_T7: usize = 15;
pub const REG_S0: usize = 16;
pub const REG_S1: usize = 17;
pub const REG_S2: usize = 18;
pub const REG_S3: usize = 19;
pub const REG_S4: usize = 20;
pub const REG_S5: usize = 21;
pub const REG_S6: usize = 22;
pub const REG_S7: usize = 23;
pub const REG_T8: usize = 24;
pub const REG_T9: usize = 25;
pub const REG_K0: usize = 26;
pub const REG_K1: usize = 27;
pub const REG_GP: usize = 28;
pub const REG_SP: usize = 29;
pub const REG_FP: usize = 30;
pub const REG_RA: usize = 31;

// ---------------------------------------------------------------------------
// GPR symbolic name table
// ---------------------------------------------------------------------------

const GPR_NAMES: [&str; 32] = [
    "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3", "$t0", "$t1", "$t2", "$t3", "$t4",
    "$t5", "$t6", "$t7", "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7", "$t8", "$t9",
    "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
];

/// Symbolic name for GPR index.
#[inline]
#[must_use]
pub const fn gpr(idx: usize) -> &'static str {
    if idx < 32 { GPR_NAMES[idx] } else { "$unk" }
}

// ---------------------------------------------------------------------------
// FP condition-code names (16 IEEE conditions)
// ---------------------------------------------------------------------------

static FP_CONDITIONS: &[&str] = &[
    "f", "un", "eq", "ueq", "olt", "ult", "ole", "ule", "sf", "ngle", "seq", "ngl", "lt", "nge",
    "le", "ngt",
];

// ---------------------------------------------------------------------------
// COP0 register names
// ---------------------------------------------------------------------------

const COP0_NAMES: [&str; 32] = [
    "Index",
    "Random",
    "EntryLo0",
    "EntryLo1",
    "Context",
    "PageMask",
    "Wired",
    "HWREna",
    "BadVAddr",
    "Count",
    "EntryHi",
    "Compare",
    "Status",
    "Cause",
    "EPC",
    "PRId",
    "Config",
    "LLAddr",
    "WatchLo",
    "WatchHi",
    "XContext",
    "Reserved21",
    "Reserved22",
    "Debug",
    "DEPC",
    "PerfCnt",
    "ErrCtl",
    "CacheErr",
    "TagLo",
    "TagHi",
    "ErrorEPC",
    "DESAVE",
];

const fn cop0_name(rd: usize) -> &'static str {
    if rd < 32 { COP0_NAMES[rd] } else { "COP0??" }
}

// ---------------------------------------------------------------------------
// MipsArch
// ---------------------------------------------------------------------------

/// MIPS/MIPS64 architecture descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MipsArch {
    pub bits: u32,
    pub endian: MipsEndian,
    pub abi: MipsAbi,
}

/// Decoded register and immediate fields used by the SPECIAL / SPECIAL3 helpers.
#[derive(Debug, Clone, Copy)]
struct SpecialFields {
    word: u32,
    funct: u32,
    rs: usize,
    rt: usize,
    rd: usize,
    shamt: u32,
}

impl Default for MipsArch {
    fn default() -> Self {
        Self::mips32_le()
    }
}

impl MipsArch {
    /// MIPS32 little-endian with O32 ABI.
    #[must_use]
    pub const fn mips32_le() -> Self {
        Self {
            bits: 32,
            endian: MipsEndian::Little,
            abi: MipsAbi::O32,
        }
    }
    /// MIPS32 big-endian with O32 ABI.
    #[must_use]
    pub const fn mips32_be() -> Self {
        Self {
            bits: 32,
            endian: MipsEndian::Big,
            abi: MipsAbi::O32,
        }
    }
    /// MIPS64 little-endian with N64 ABI.
    #[must_use]
    pub const fn mips64_le() -> Self {
        Self {
            bits: 64,
            endian: MipsEndian::Little,
            abi: MipsAbi::N64,
        }
    }
    /// MIPS64 big-endian with N64 ABI.
    #[must_use]
    pub const fn mips64_be() -> Self {
        Self {
            bits: 64,
            endian: MipsEndian::Big,
            abi: MipsAbi::N64,
        }
    }
    /// Custom configuration.
    #[must_use]
    pub const fn custom(bits: u32, endian: MipsEndian, abi: MipsAbi) -> Self {
        Self { bits, endian, abi }
    }

    /// Read a 32-bit instruction word, respecting endianness.
    #[must_use]
    pub fn read_word(&self, bytes: &[u8]) -> Option<u32> {
        if bytes.len() < 4 {
            return None;
        }
        let b = [bytes[0], bytes[1], bytes[2], bytes[3]];
        Some(match self.endian {
            MipsEndian::Little => u32::from_le_bytes(b),
            MipsEndian::Big => u32::from_be_bytes(b),
        })
    }

    /// Decode one instruction word into an [`Instruction`].
    #[must_use]
    pub fn decode_word(&self, address: Address, word: u32, raw: &[u8]) -> Instruction {
        let opcode = (word >> 26) & 0x3F;
        let rs = ((word >> 21) & 0x1F) as usize;
        let rt = ((word >> 16) & 0x1F) as usize;
        let rd = ((word >> 11) & 0x1F) as usize;
        let shamt = (word >> 6) & 0x1F;
        let funct = word & 0x3F;
        let imm16 = word & 0xFFFF;
        let simm16 = i64::from(imm16 as i16);
        let target26 = word & 0x03FF_FFFF;
        // Clamp to available bytes; callers that pass a short slice get a truncated raw field
        // rather than a panic.
        let bytes = raw[..raw.len().min(4)].to_vec();

        match opcode {
            0x00 => Self::decode_special(
                address,
                SpecialFields { word, funct, rs, rt, rd, shamt },
                bytes,
            ),
            0x01 => Self::decode_regimm(address, rs, rt, simm16, bytes),

            // J-type
            0x02 => {
                let t = branch_target_j(address, target26);
                mk(address, "j", format!("0x{t:x}"), InstrFlags::BRANCH, bytes)
            }
            0x03 => {
                let t = branch_target_j(address, target26);
                mk(
                    address,
                    "jal",
                    format!("0x{t:x}"),
                    InstrFlags::BRANCH | InstrFlags::CALL,
                    bytes,
                )
            }

            // I-type branches
            0x04 => branch_i(address, "beq", rs, Some(rt), simm16, bytes),
            0x05 => branch_i(address, "bne", rs, Some(rt), simm16, bytes),
            0x06 => branch_i(address, "blez", rs, None, simm16, bytes),
            0x07 => branch_i(address, "bgtz", rs, None, simm16, bytes),

            // Arithmetic immediate
            0x08 => itype(address, "addi", gpr(rt), &rs_simm(rs, simm16), bytes),
            0x09 => itype(address, "addiu", gpr(rt), &rs_simm(rs, simm16), bytes),
            0x0A => itype(address, "slti", gpr(rt), &rs_simm(rs, simm16), bytes),
            0x0B => itype(address, "sltiu", gpr(rt), &rs_simm(rs, simm16), bytes),
            0x0C => itype(address, "andi", gpr(rt), &rs_uimm(rs, imm16), bytes),
            0x0D => itype(address, "ori", gpr(rt), &rs_uimm(rs, imm16), bytes),
            0x0E => itype(address, "xori", gpr(rt), &rs_uimm(rs, imm16), bytes),
            0x0F => itype(address, "lui", gpr(rt), &format!("0x{imm16:x}"), bytes),

            // Coprocessors
            0x10 => Self::decode_cop0(address, rs, rt, rd, word, bytes),
            0x11 => Self::decode_cop1(address, word, rs, rt, bytes),
            0x12 => Self::decode_cop2(address, word, bytes),
            0x13 => Self::decode_cop1x(address, word, bytes),

            // Branch-likely (MIPS II)
            0x14 => branch_i(address, "beql", rs, Some(rt), simm16, bytes),
            0x15 => branch_i(address, "bnel", rs, Some(rt), simm16, bytes),
            0x16 => branch_i(address, "blezl", rs, None, simm16, bytes),
            0x17 => branch_i(address, "bgtzl", rs, None, simm16, bytes),

            // MIPS64 immediate arithmetic
            0x18 => itype(address, "daddi", gpr(rt), &rs_simm(rs, simm16), bytes),
            0x19 => itype(address, "daddiu", gpr(rt), &rs_simm(rs, simm16), bytes),

            // MIPS64 unaligned load/store
            0x1A => mem_op(address, "ldl", rt, rs, simm16, InstrFlags::READ_MEM, bytes),
            0x1B => mem_op(address, "ldr", rt, rs, simm16, InstrFlags::READ_MEM, bytes),

            // SPECIAL2 and SPECIAL3
            0x1C => Self::decode_special2(address, funct, rs, rt, rd, bytes),
            0x1F => Self::decode_special3(
                address,
                SpecialFields { word, funct, rs, rt, rd, shamt },
                bytes,
            ),

            0x20..=0x3F => Self::decode_mem(address, opcode, rs, rt, simm16, bytes),

            _ => unknown(address, bytes),
        }
    }

    /// Primary opcodes `0x20..=0x3F`: every load and store, integer and
    /// coprocessor, plain and linked.
    ///
    /// Split out of `decode_word` for length only; the dispatch there is still
    /// one flat match over the primary opcode.
    fn decode_mem(
        address: Address,
        opcode: u32,
        rs: usize,
        rt: usize,
        simm16: i64,
        bytes: Vec<u8>,
    ) -> Instruction {
        match opcode {
            // Integer loads
            0x20 => mem_op(address, "lb", rt, rs, simm16, InstrFlags::READ_MEM, bytes),
            0x21 => mem_op(address, "lh", rt, rs, simm16, InstrFlags::READ_MEM, bytes),
            0x22 => mem_op(address, "lwl", rt, rs, simm16, InstrFlags::READ_MEM, bytes),
            0x23 => mem_op(address, "lw", rt, rs, simm16, InstrFlags::READ_MEM, bytes),
            0x24 => mem_op(address, "lbu", rt, rs, simm16, InstrFlags::READ_MEM, bytes),
            0x25 => mem_op(address, "lhu", rt, rs, simm16, InstrFlags::READ_MEM, bytes),
            0x26 => mem_op(address, "lwr", rt, rs, simm16, InstrFlags::READ_MEM, bytes),
            0x27 => mem_op(address, "lwu", rt, rs, simm16, InstrFlags::READ_MEM, bytes),

            // Integer stores
            0x28 => mem_op(address, "sb", rt, rs, simm16, InstrFlags::WRITE_MEM, bytes),
            0x29 => mem_op(address, "sh", rt, rs, simm16, InstrFlags::WRITE_MEM, bytes),
            0x2A => mem_op(address, "swl", rt, rs, simm16, InstrFlags::WRITE_MEM, bytes),
            0x2B => mem_op(address, "sw", rt, rs, simm16, InstrFlags::WRITE_MEM, bytes),
            0x2C => mem_op(address, "sdl", rt, rs, simm16, InstrFlags::WRITE_MEM, bytes),
            0x2D => mem_op(address, "sdr", rt, rs, simm16, InstrFlags::WRITE_MEM, bytes),
            0x2E => mem_op(address, "swr", rt, rs, simm16, InstrFlags::WRITE_MEM, bytes),
            0x2F => mk(
                address,
                "cache",
                format!("{}, {}({})", rt, simm16, gpr(rs)),
                InstrFlags::NONE,
                bytes,
            ),

            // Atomic / linked loads
            0x30 => mem_op(address, "ll", rt, rs, simm16, InstrFlags::READ_MEM, bytes),
            0x31 => mem_op_fp(address, "lwc1", rt, rs, simm16, InstrFlags::READ_MEM, bytes),
            0x32 => mem_op_fp(address, "lwc2", rt, rs, simm16, InstrFlags::READ_MEM, bytes),
            0x33 => mk(
                address,
                "pref",
                format!("{}, {}({})", rt, simm16, gpr(rs)),
                InstrFlags::NONE,
                bytes,
            ),
            0x34 => mem_op(address, "lld", rt, rs, simm16, InstrFlags::READ_MEM, bytes),
            0x35 => mem_op_fp(address, "ldc1", rt, rs, simm16, InstrFlags::READ_MEM, bytes),
            0x36 => mem_op_fp(address, "ldc2", rt, rs, simm16, InstrFlags::READ_MEM, bytes),
            0x37 => mem_op(address, "ld", rt, rs, simm16, InstrFlags::READ_MEM, bytes),

            // Atomic / linked stores
            0x38 => mem_op(address, "sc", rt, rs, simm16, InstrFlags::WRITE_MEM, bytes),
            0x39 => mem_op_fp(
                address,
                "swc1",
                rt,
                rs,
                simm16,
                InstrFlags::WRITE_MEM,
                bytes,
            ),
            0x3A => mem_op_fp(
                address,
                "swc2",
                rt,
                rs,
                simm16,
                InstrFlags::WRITE_MEM,
                bytes,
            ),
            0x3C => mem_op(address, "scd", rt, rs, simm16, InstrFlags::WRITE_MEM, bytes),
            0x3D => mem_op_fp(
                address,
                "sdc1",
                rt,
                rs,
                simm16,
                InstrFlags::WRITE_MEM,
                bytes,
            ),
            0x3E => mem_op_fp(
                address,
                "sdc2",
                rt,
                rs,
                simm16,
                InstrFlags::WRITE_MEM,
                bytes,
            ),
            0x3F => mem_op(address, "sd", rt, rs, simm16, InstrFlags::WRITE_MEM, bytes),

            _ => unknown(address, bytes),
        }
    }

    // -----------------------------------------------------------------------
    // SPECIAL (opcode == 0) — all 64 funct codes
    // -----------------------------------------------------------------------
    fn decode_special(
        address: Address,
        f: SpecialFields,
        bytes: Vec<u8>,
    ) -> Instruction {
        let SpecialFields { funct, rs, rt, rd, shamt, .. } = f;
        match funct {
            // ── Shifts by shamt ──────────────────────────────────────────
            0x00 => rtype(
                address,
                "sll",
                format!("{}, {}, {}", gpr(rd), gpr(rt), shamt),
                bytes,
            ),
            0x01 => rtype(
                address,
                "movci",
                format!("{}, {}, {}", gpr(rd), gpr(rs), (rt >> 2) & 7),
                bytes,
            ),
            0x02 => {
                // rs==1 means ROTR (MIPS32r2)
                if rs == 1 {
                    rtype(
                        address,
                        "rotr",
                        format!("{}, {}, {}", gpr(rd), gpr(rt), shamt),
                        bytes,
                    )
                } else {
                    rtype(
                        address,
                        "srl",
                        format!("{}, {}, {}", gpr(rd), gpr(rt), shamt),
                        bytes,
                    )
                }
            }
            0x03 => rtype(
                address,
                "sra",
                format!("{}, {}, {}", gpr(rd), gpr(rt), shamt),
                bytes,
            ),

            // ── Shifts by variable ───────────────────────────────────────
            0x04 => rtype(
                address,
                "sllv",
                format!("{}, {}, {}", gpr(rd), gpr(rt), gpr(rs)),
                bytes,
            ),
            0x05 => rtype(
                address,
                "lsa",
                format!("{}, {}, {}, {}", gpr(rd), gpr(rs), gpr(rt), shamt),
                bytes,
            ),
            0x06 => {
                if shamt == 1 {
                    rtype(
                        address,
                        "rotrv",
                        format!("{}, {}, {}", gpr(rd), gpr(rt), gpr(rs)),
                        bytes,
                    )
                } else {
                    rtype(
                        address,
                        "srlv",
                        format!("{}, {}, {}", gpr(rd), gpr(rt), gpr(rs)),
                        bytes,
                    )
                }
            }
            0x07 => rtype(
                address,
                "srav",
                format!("{}, {}, {}", gpr(rd), gpr(rt), gpr(rs)),
                bytes,
            ),

            0x08..=0x0F => Self::decode_special_jump_trap(address, f, bytes),

            0x10..=0x1F => Self::decode_special_muldiv(address, f, bytes),

            0x20..=0x2F => Self::decode_special_alu(address, f, bytes),

            0x30..=0x3F => Self::decode_special_high(address, f, bytes),

            _ => unknown(address, bytes),
        }
    }




    /// SPECIAL arms `0x08..=0x0F`: jumps, conditional moves, SYSCALL/BREAK/SYNC.
    ///
    /// Split out of `decode_special` for length only.
    fn decode_special_jump_trap(address: Address, f: SpecialFields, bytes: Vec<u8>) -> Instruction {
        let SpecialFields { word, funct, rs, rt, rd, shamt } = f;
        match funct {
            // ── Jumps ────────────────────────────────────────────────────
            0x08 => {
                let mut flags = InstrFlags::BRANCH | InstrFlags::INDIRECT;
                if rs == REG_RA {
                    flags |= InstrFlags::RET;
                }
                mk(address, "jr", gpr(rs).to_string(), flags, bytes)
            }
            0x09 => mk(
                address,
                "jalr",
                format!("{}, {}", gpr(rd), gpr(rs)),
                InstrFlags::BRANCH | InstrFlags::CALL | InstrFlags::INDIRECT,
                bytes,
            ),

            // ── Conditional moves (MIPS IV) ───────────────────────────────
            0x0A => rtype(
                address,
                "movz",
                format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt)),
                bytes,
            ),
            0x0B => rtype(
                address,
                "movn",
                format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt)),
                bytes,
            ),

            // ── SYSCALL / BREAK / SYNC ────────────────────────────────────
            0x0C => {
                let code20 = (word >> 6) & 0xFFFFF;
                mk(
                    address,
                    "syscall",
                    format!("0x{code20:x}"),
                    InstrFlags::CALL,
                    bytes,
                )
            }
            0x0D => {
                let code20 = (word >> 6) & 0xFFFFF;
                mk(
                    address,
                    "break",
                    format!("0x{code20:x}"),
                    InstrFlags::BARRIER,
                    bytes,
                )
            }
            0x0F => rtype(address, "sync", format!("{shamt}"), bytes),

            _ => unknown(address, bytes),
        }
    }
    /// SPECIAL arms `0x10..=0x1F`: HI/LO moves, MIPS64 variable shifts and
    /// the multiply/divide group.
    ///
    /// Split out of `decode_special` for length only.
    fn decode_special_muldiv(address: Address, f: SpecialFields, bytes: Vec<u8>) -> Instruction {
        let SpecialFields { funct, rs, rt, rd, .. } = f;
        match funct {
            // ── HI/LO transfers ──────────────────────────────────────────
            0x10 => rtype(address, "mfhi", gpr(rd).to_string(), bytes),
            0x11 => rtype(address, "mthi", gpr(rs).to_string(), bytes),
            0x12 => rtype(address, "mflo", gpr(rd).to_string(), bytes),
            0x13 => rtype(address, "mtlo", gpr(rs).to_string(), bytes),

            // ── MIPS64 variable shifts ────────────────────────────────────
            0x14 => rtype(
                address,
                "dsllv",
                format!("{}, {}, {}", gpr(rd), gpr(rt), gpr(rs)),
                bytes,
            ),
            0x16 => rtype(
                address,
                "dsrlv",
                format!("{}, {}, {}", gpr(rd), gpr(rt), gpr(rs)),
                bytes,
            ),
            0x17 => rtype(
                address,
                "dsrav",
                format!("{}, {}, {}", gpr(rd), gpr(rt), gpr(rs)),
                bytes,
            ),

            // ── Multiply / divide (HI:LO = rs * rt) ──────────────────────
            0x18 => rtype(address, "mult", format!("{}, {}", gpr(rs), gpr(rt)), bytes),
            0x19 => rtype(address, "multu", format!("{}, {}", gpr(rs), gpr(rt)), bytes),
            // DIV: LO = rs/rt, HI = rs%rt
            0x1A => rtype(address, "div", format!("{}, {}", gpr(rs), gpr(rt)), bytes),
            0x1B => rtype(address, "divu", format!("{}, {}", gpr(rs), gpr(rt)), bytes),
            // MIPS64
            0x1C => rtype(address, "dmult", format!("{}, {}", gpr(rs), gpr(rt)), bytes),
            0x1D => rtype(
                address,
                "dmultu",
                format!("{}, {}", gpr(rs), gpr(rt)),
                bytes,
            ),
            0x1E => rtype(address, "ddiv", format!("{}, {}", gpr(rs), gpr(rt)), bytes),
            0x1F => rtype(address, "ddivu", format!("{}, {}", gpr(rs), gpr(rt)), bytes),

            _ => unknown(address, bytes),
        }
    }
    /// SPECIAL arms `0x20..=0x2F`: the 32- and 64-bit integer ALU.
    ///
    /// Split out of `decode_special` for length; the dispatch above is
    /// still one flat match over `funct`.
    fn decode_special_alu(address: Address, f: SpecialFields, bytes: Vec<u8>) -> Instruction {
        let SpecialFields { funct, rs, rt, rd, .. } = f;
        match funct {
            // ── Integer ALU ───────────────────────────────────────────────
            0x20 => rtype(
                address,
                "add",
                format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt)),
                bytes,
            ),
            0x21 => rtype(
                address,
                "addu",
                format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt)),
                bytes,
            ),
            0x22 => rtype(
                address,
                "sub",
                format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt)),
                bytes,
            ),
            0x23 => rtype(
                address,
                "subu",
                format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt)),
                bytes,
            ),
            0x24 => rtype(
                address,
                "and",
                format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt)),
                bytes,
            ),
            0x25 => rtype(
                address,
                "or",
                format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt)),
                bytes,
            ),
            0x26 => rtype(
                address,
                "xor",
                format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt)),
                bytes,
            ),
            0x27 => rtype(
                address,
                "nor",
                format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt)),
                bytes,
            ),
            0x2A => rtype(
                address,
                "slt",
                format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt)),
                bytes,
            ),
            0x2B => rtype(
                address,
                "sltu",
                format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt)),
                bytes,
            ),

            // ── MIPS64 ALU ────────────────────────────────────────────────
            0x2C => rtype(
                address,
                "dadd",
                format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt)),
                bytes,
            ),
            0x2D => rtype(
                address,
                "daddu",
                format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt)),
                bytes,
            ),
            0x2E => rtype(
                address,
                "dsub",
                format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt)),
                bytes,
            ),
            0x2F => rtype(
                address,
                "dsubu",
                format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt)),
                bytes,
            ),

            _ => unknown(address, bytes),
        }
    }
    /// SPECIAL arms with `funct >= 0x30`: traps and the MIPS64 shifts.
    ///
    /// Split out of `decode_special` so neither half is an unreviewably long
    /// function; the dispatch is still one flat match over `funct`.
    fn decode_special_high(address: Address, f: SpecialFields, bytes: Vec<u8>) -> Instruction {
        let SpecialFields { funct, rs, rt, rd, shamt, .. } = f;
        match funct {
            // ── Traps ─────────────────────────────────────────────────────
            0x30 => rtype(address, "tge", format!("{}, {}", gpr(rs), gpr(rt)), bytes),
            0x31 => rtype(address, "tgeu", format!("{}, {}", gpr(rs), gpr(rt)), bytes),
            0x32 => rtype(address, "tlt", format!("{}, {}", gpr(rs), gpr(rt)), bytes),
            0x33 => rtype(address, "tltu", format!("{}, {}", gpr(rs), gpr(rt)), bytes),
            0x34 => rtype(address, "teq", format!("{}, {}", gpr(rs), gpr(rt)), bytes),
            0x36 => rtype(address, "tne", format!("{}, {}", gpr(rs), gpr(rt)), bytes),

            // ── MIPS64 shifts by shamt ────────────────────────────────────
            0x38 => rtype(
                address,
                "dsll",
                format!("{}, {}, {}", gpr(rd), gpr(rt), shamt),
                bytes,
            ),
            0x3A => rtype(
                address,
                "dsrl",
                format!("{}, {}, {}", gpr(rd), gpr(rt), shamt),
                bytes,
            ),
            0x3B => rtype(
                address,
                "dsra",
                format!("{}, {}, {}", gpr(rd), gpr(rt), shamt),
                bytes,
            ),
            0x3C => rtype(
                address,
                "dsll32",
                format!("{}, {}, {}", gpr(rd), gpr(rt), shamt),
                bytes,
            ),
            0x3E => rtype(
                address,
                "dsrl32",
                format!("{}, {}, {}", gpr(rd), gpr(rt), shamt),
                bytes,
            ),
            0x3F => rtype(
                address,
                "dsra32",
                format!("{}, {}, {}", gpr(rd), gpr(rt), shamt),
                bytes,
            ),

            _ => unknown(address, bytes),
        }
    }

    // -----------------------------------------------------------------------
    // REGIMM (opcode == 1, rt selects sub-opcode)
    // -----------------------------------------------------------------------
    fn decode_regimm(
        address: Address,
        rs: usize,
        rt: usize,
        simm16: i64,
        bytes: Vec<u8>,
    ) -> Instruction {
        let target = branch_target_i(address, simm16);
        let cb = |mn: &str| {
            mk(
                address,
                mn,
                format!("{}, 0x{target:x}", gpr(rs)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes.clone(),
            )
        };
        let cl = |mn: &str| {
            mk(
                address,
                mn,
                format!("{}, 0x{target:x}", gpr(rs)),
                InstrFlags::BRANCH | InstrFlags::CALL | InstrFlags::CONDITIONAL,
                bytes.clone(),
            )
        };
        match rt {
            0x00 => cb("bltz"),
            0x01 => cb("bgez"),
            0x02 => cb("bltzl"),
            0x03 => cb("bgezl"),
            0x08 => mk(
                address,
                "tgei",
                format!("{}, {simm16}", gpr(rs)),
                InstrFlags::NONE,
                bytes,
            ),
            0x09 => mk(
                address,
                "tgeiu",
                format!("{}, {simm16}", gpr(rs)),
                InstrFlags::NONE,
                bytes,
            ),
            0x0A => mk(
                address,
                "tlti",
                format!("{}, {simm16}", gpr(rs)),
                InstrFlags::NONE,
                bytes,
            ),
            0x0B => mk(
                address,
                "tltiu",
                format!("{}, {simm16}", gpr(rs)),
                InstrFlags::NONE,
                bytes,
            ),
            0x0C => mk(
                address,
                "teqi",
                format!("{}, {simm16}", gpr(rs)),
                InstrFlags::NONE,
                bytes,
            ),
            0x0E => mk(
                address,
                "tnei",
                format!("{}, {simm16}", gpr(rs)),
                InstrFlags::NONE,
                bytes,
            ),
            0x10 => cl("bltzal"),
            0x11 => cl("bgezal"),
            0x12 => cl("bltzall"),
            0x13 => cl("bgezall"),
            0x1F => mk(
                address,
                "synci",
                format!("{}({})", simm16, gpr(rs)),
                InstrFlags::BARRIER,
                bytes,
            ),
            _ => unknown(address, bytes),
        }
    }

    // -----------------------------------------------------------------------
    // COP0 — system coprocessor
    // -----------------------------------------------------------------------
    fn decode_cop0(
        address: Address,
        rs: usize,
        rt: usize,
        rd: usize,
        word: u32,
        bytes: Vec<u8>,
    ) -> Instruction {
        let funct = word & 0x3F;
        let sel = word & 0x7;
        match rs {
            0x00 => rtype(
                address,
                "mfc0",
                format!("{}, {} ; sel={}", gpr(rt), cop0_name(rd), sel),
                bytes,
            ),
            0x01 => rtype(
                address,
                "dmfc0",
                format!("{}, {} ; sel={}", gpr(rt), cop0_name(rd), sel),
                bytes,
            ),
            0x03 => rtype(
                address,
                "mfhc0",
                format!("{}, {} ; sel={}", gpr(rt), cop0_name(rd), sel),
                bytes,
            ),
            0x04 => rtype(
                address,
                "mtc0",
                format!("{}, {} ; sel={}", gpr(rt), cop0_name(rd), sel),
                bytes,
            ),
            0x05 => rtype(
                address,
                "dmtc0",
                format!("{}, {} ; sel={}", gpr(rt), cop0_name(rd), sel),
                bytes,
            ),
            0x07 => rtype(
                address,
                "mthc0",
                format!("{}, {} ; sel={}", gpr(rt), cop0_name(rd), sel),
                bytes,
            ),
            0x10 => match funct {
                0x01 => rtype(address, "tlbr", String::new(), bytes),
                0x02 => rtype(address, "tlbwi", String::new(), bytes),
                0x06 => rtype(address, "tlbwr", String::new(), bytes),
                0x08 => rtype(address, "tlbp", String::new(), bytes),
                0x18 => mk(address, "eret", String::new(), InstrFlags::RET, bytes),
                0x1F => rtype(address, "deret", String::new(), bytes),
                0x20 => rtype(address, "wait", String::new(), bytes),
                _ => unknown(address, bytes),
            },
            _ => unknown(address, bytes),
        }
    }

    // -----------------------------------------------------------------------
    // COP1 — FPU coprocessor
    // Supports fmt=S (single), D (double), W (word), L (long), PS (pair)
    // -----------------------------------------------------------------------
    fn decode_cop1(
        address: Address,
        word: u32,
        rs: usize,
        rt: usize,
        bytes: Vec<u8>,
    ) -> Instruction {
        let fmt = rs;
        let ft = rt;
        let fs = ((word >> 11) & 0x1F) as usize;
        let fd = ((word >> 6) & 0x1F) as usize;
        let funct = word & 0x3F;
        let cc = ((word >> 8) & 0x7) as usize;

        // Move-to/from integer registers and BC1
        match fmt {
            0x00 => return rtype(address, "mfc1", format!("{}, $f{fs}", gpr(ft)), bytes),
            0x01 => return rtype(address, "dmfc1", format!("{}, $f{fs}", gpr(ft)), bytes),
            0x02 => return rtype(address, "cfc1", format!("{}, $f{fs}", gpr(ft)), bytes),
            0x03 => return rtype(address, "mfhc1", format!("{}, $f{fs}", gpr(ft)), bytes),
            0x04 => return rtype(address, "mtc1", format!("$f{fs}, {}", gpr(ft)), bytes),
            0x05 => return rtype(address, "dmtc1", format!("$f{fs}, {}", gpr(ft)), bytes),
            0x06 => return rtype(address, "ctc1", format!("$f{fs}, {}", gpr(ft)), bytes),
            0x07 => return rtype(address, "mthc1", format!("{}, $f{fs}", gpr(ft)), bytes),
            0x08 => {
                let nd = (word >> 17) & 1;
                let tf = (word >> 16) & 1;
                let imm16 = word & 0xFFFF;
                let simm16 = i64::from(imm16 as i16);
                let target = branch_target_i(address, simm16);
                let mn = match (tf, nd) {
                    (0, 0) => "bc1f",
                    (1, 0) => "bc1t",
                    (0, 1) => "bc1fl",
                    _ => "bc1tl",
                };
                return mk(
                    address,
                    mn,
                    format!("{cc}, 0x{target:x}"),
                    InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                    bytes,
                );
            }
            _ => {}
        }

        let fmt_name = match fmt {
            0x10 => "s",
            0x11 => "d",
            0x12 => "e",
            0x13 => "q",
            0x14 => "w",
            0x15 => "l",
            0x16 => "ps",
            _ => "?",
        };

        let mn = match funct {
            0x00 => format!("add.{fmt_name}"),
            0x01 => format!("sub.{fmt_name}"),
            0x02 => format!("mul.{fmt_name}"),
            0x03 => format!("div.{fmt_name}"),
            0x04 => format!("sqrt.{fmt_name}"),
            0x05 => format!("abs.{fmt_name}"),
            0x06 => format!("mov.{fmt_name}"),
            0x07 => format!("neg.{fmt_name}"),
            0x08 => format!("round.l.{fmt_name}"),
            0x09 => format!("trunc.l.{fmt_name}"),
            0x0A => format!("ceil.l.{fmt_name}"),
            0x0B => format!("floor.l.{fmt_name}"),
            0x0C => format!("round.w.{fmt_name}"),
            0x0D => format!("trunc.w.{fmt_name}"),
            0x0E => format!("ceil.w.{fmt_name}"),
            0x0F => format!("floor.w.{fmt_name}"),
            0x11 => {
                let cc_mov = ((word >> 18) & 0x7) as usize;
                let tf = (word >> 16) & 1;
                let mn2 = if tf == 1 {
                    format!("movt.{fmt_name}")
                } else {
                    format!("movf.{fmt_name}")
                };
                return rtype(address, &mn2, format!("$f{fd}, $f{fs}, {cc_mov}"), bytes);
            }
            0x12 => format!("movz.{fmt_name}"),
            0x13 => format!("movn.{fmt_name}"),
            0x14 => format!("frsqrt.{fmt_name}"),
            0x15 => format!("recip.{fmt_name}"),
            0x16 => format!("rsqrt.{fmt_name}"),
            0x1C => format!("recip2.{fmt_name}"),
            0x1D => format!("recip1.{fmt_name}"),
            0x1E => format!("rsqrt1.{fmt_name}"),
            0x1F => format!("rsqrt2.{fmt_name}"),
            0x20 => format!("cvt.s.{fmt_name}"),
            0x21 => format!("cvt.d.{fmt_name}"),
            0x24 => format!("cvt.w.{fmt_name}"),
            0x25 => format!("cvt.l.{fmt_name}"),
            0x26 => format!("cvt.ps.{fmt_name}"),
            0x28 => "cvt.s.pl".to_string(),
            0x2C => "pll.ps".to_string(),
            0x2D => "plu.ps".to_string(),
            0x2E => "pul.ps".to_string(),
            0x2F => "puu.ps".to_string(),
            0x30..=0x3F => {
                let cond_str = FP_CONDITIONS[(funct & 0xF) as usize];
                format!("c.{cond_str}.{fmt_name}")
            }
            _ => return unknown(address, bytes),
        };
        rtype(address, &mn, format!("$f{fd}, $f{fs}, $f{ft}"), bytes)
    }

    // -----------------------------------------------------------------------
    // COP2 — application-specific coprocessor
    // -----------------------------------------------------------------------
    fn decode_cop2(address: Address, word: u32, bytes: Vec<u8>) -> Instruction {
        mk(
            address,
            "cop2",
            format!("0x{:x}", word & 0x01FF_FFFF),
            InstrFlags::NONE,
            bytes,
        )
    }

    // -----------------------------------------------------------------------
    // COP1X (opcode 0x13) — fused FP multiply-accumulate
    // -----------------------------------------------------------------------
    fn decode_cop1x(address: Address, word: u32, bytes: Vec<u8>) -> Instruction {
        let funct = word & 0x3F;
        let base = ((word >> 21) & 0x1F) as usize;
        let idx = ((word >> 16) & 0x1F) as usize;
        let fs = ((word >> 11) & 0x1F) as usize;
        let fd = ((word >> 6) & 0x1F) as usize;
        match funct {
            0x00 => rtype(
                address,
                "lwxc1",
                format!("$f{fd}, {}({})", gpr(idx), gpr(base)),
                bytes,
            ),
            0x01 => rtype(
                address,
                "ldxc1",
                format!("$f{fd}, {}({})", gpr(idx), gpr(base)),
                bytes,
            ),
            0x05 => rtype(
                address,
                "luxc1",
                format!("$f{fd}, {}({})", gpr(idx), gpr(base)),
                bytes,
            ),
            0x08 => rtype(
                address,
                "swxc1",
                format!("$f{fs}, {}({})", gpr(idx), gpr(base)),
                bytes,
            ),
            0x09 => rtype(
                address,
                "sdxc1",
                format!("$f{fs}, {}({})", gpr(idx), gpr(base)),
                bytes,
            ),
            0x0D => rtype(
                address,
                "suxc1",
                format!("$f{fs}, {}({})", gpr(idx), gpr(base)),
                bytes,
            ),
            0x0F => {
                // PREFX hint, index(base): bits 20:16 encode *both* the prefetch hint
                // value and the index GPR (they are the same field, not two independent
                // operands).  `idx` is the numeric hint; `gpr(idx)` is the index register.
                let hint = idx; // bits 20:16 — same field used as both hint and index GPR
                rtype(
                    address,
                    "prefx",
                    format!("{}, {}({})", hint, gpr(idx), gpr(base)),
                    bytes,
                )
            }
            0x1E => rtype(
                address,
                "alnv.ps",
                format!("$f{fd}, $f{fs}, $f{idx}, {}", gpr(base)),
                bytes,
            ),
            0x20..=0x3F => Self::decode_cop1x_madd(address, word, bytes),
            _ => unknown(address, bytes),
        }
    }

    /// COP1X functions `0x20..=0x3F`: the fused multiply-add family.
    ///
    /// Split out of `decode_cop1x` for length only.
    fn decode_cop1x_madd(address: Address, word: u32, bytes: Vec<u8>) -> Instruction {
        let funct = word & 0x3F;
        let fr = ((word >> 21) & 0x1F) as usize;
        let idx = ((word >> 16) & 0x1F) as usize;
        let fs = ((word >> 11) & 0x1F) as usize;
        let fd = ((word >> 6) & 0x1F) as usize;
        match funct {
            0x20 => rtype(
                address,
                "madd.s",
                format!("$f{fd}, $f{fr}, $f{fs}, $f{idx}"),
                bytes,
            ),
            0x21 => rtype(
                address,
                "madd.d",
                format!("$f{fd}, $f{fr}, $f{fs}, $f{idx}"),
                bytes,
            ),
            0x26 => rtype(
                address,
                "madd.ps",
                format!("$f{fd}, $f{fr}, $f{fs}, $f{idx}"),
                bytes,
            ),
            0x28 => rtype(
                address,
                "msub.s",
                format!("$f{fd}, $f{fr}, $f{fs}, $f{idx}"),
                bytes,
            ),
            0x29 => rtype(
                address,
                "msub.d",
                format!("$f{fd}, $f{fr}, $f{fs}, $f{idx}"),
                bytes,
            ),
            0x2E => rtype(
                address,
                "msub.ps",
                format!("$f{fd}, $f{fr}, $f{fs}, $f{idx}"),
                bytes,
            ),
            0x30 => rtype(
                address,
                "nmadd.s",
                format!("$f{fd}, $f{fr}, $f{fs}, $f{idx}"),
                bytes,
            ),
            0x31 => rtype(
                address,
                "nmadd.d",
                format!("$f{fd}, $f{fr}, $f{fs}, $f{idx}"),
                bytes,
            ),
            0x36 => rtype(
                address,
                "nmadd.ps",
                format!("$f{fd}, $f{fr}, $f{fs}, $f{idx}"),
                bytes,
            ),
            0x38 => rtype(
                address,
                "nmsub.s",
                format!("$f{fd}, $f{fr}, $f{fs}, $f{idx}"),
                bytes,
            ),
            0x39 => rtype(
                address,
                "nmsub.d",
                format!("$f{fd}, $f{fr}, $f{fs}, $f{idx}"),
                bytes,
            ),
            0x3E => rtype(
                address,
                "nmsub.ps",
                format!("$f{fd}, $f{fr}, $f{fs}, $f{idx}"),
                bytes,
            ),
            _ => unknown(address, bytes),
        }
    }

    // -----------------------------------------------------------------------
    // SPECIAL2 (opcode 0x1C) — MUL, CLZ/CLO, MADD/MSUB
    // -----------------------------------------------------------------------
    fn decode_special2(
        address: Address,
        funct: u32,
        rs: usize,
        rt: usize,
        rd: usize,
        bytes: Vec<u8>,
    ) -> Instruction {
        match funct {
            0x00 => rtype(address, "madd", format!("{}, {}", gpr(rs), gpr(rt)), bytes),
            0x01 => rtype(address, "maddu", format!("{}, {}", gpr(rs), gpr(rt)), bytes),
            0x02 => rtype(
                address,
                "mul",
                format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt)),
                bytes,
            ),
            0x04 => rtype(address, "msub", format!("{}, {}", gpr(rs), gpr(rt)), bytes),
            0x05 => rtype(address, "msubu", format!("{}, {}", gpr(rs), gpr(rt)), bytes),
            0x20 => rtype(address, "clz", format!("{}, {}", gpr(rd), gpr(rs)), bytes),
            0x21 => rtype(address, "clo", format!("{}, {}", gpr(rd), gpr(rs)), bytes),
            0x24 => rtype(address, "dclz", format!("{}, {}", gpr(rd), gpr(rs)), bytes),
            0x25 => rtype(address, "dclo", format!("{}, {}", gpr(rd), gpr(rs)), bytes),
            0x3F => mk(address, "sdbbp", String::new(), InstrFlags::BARRIER, bytes),
            _ => unknown(address, bytes),
        }
    }

    // -----------------------------------------------------------------------
    // SPECIAL3 (opcode 0x1F) — EXT/INS, BSHFL, RDHWR, MIPS64 variants
    // -----------------------------------------------------------------------
    fn decode_special3(
        address: Address,
        f: SpecialFields,
        bytes: Vec<u8>,
    ) -> Instruction {
        let SpecialFields { word: _, funct, rs, rt, rd, shamt } = f;
        match funct {
            // EXT: rd = msbd (size-1), shamt = lsb
            0x00 => rtype(
                address,
                "ext",
                format!("{}, {}, {}, {}", gpr(rt), gpr(rs), shamt, field_u32(rd) + 1),
                bytes,
            ),
            // DEXTM: 64-bit EXT with msbd >= 32
            0x01 => rtype(
                address,
                "dextm",
                format!("{}, {}, {}, {}", gpr(rt), gpr(rs), shamt, field_u32(rd) + 33),
                bytes,
            ),
            // DEXTU
            0x02 => rtype(
                address,
                "dextu",
                format!(
                    "{}, {}, {}, {}",
                    gpr(rt),
                    gpr(rs),
                    shamt + 32,
                    field_u32(rd) + 1
                ),
                bytes,
            ),
            // DEXT
            0x03 => rtype(
                address,
                "dext",
                format!("{}, {}, {}, {}", gpr(rt), gpr(rs), shamt, field_u32(rd) + 1),
                bytes,
            ),
            // INS: rd = msb, shamt = lsb; size = msb - lsb + 1.
            // Guard against malformed encodings where lsb > msb to avoid u32 underflow.
            0x04 => rtype(
                address,
                "ins",
                format!(
                    "{}, {}, {}, {}",
                    gpr(rt),
                    gpr(rs),
                    shamt,
                    field_u32(rd).saturating_sub(shamt) + 1
                ),
                bytes,
            ),
            0x05 => rtype(
                address,
                "dinsm",
                format!("{}, {}, {}, {}", gpr(rt), gpr(rs), shamt, field_u32(rd) + 33),
                bytes,
            ),
            0x06 => rtype(
                address,
                "dinsu",
                format!(
                    "{}, {}, {}, {}",
                    gpr(rt),
                    gpr(rs),
                    shamt + 32,
                    field_u32(rd) + 1
                ),
                bytes,
            ),
            0x07 => rtype(
                address,
                "dins",
                format!("{}, {}, {}, {}", gpr(rt), gpr(rs), shamt, field_u32(rd) + 1),
                bytes,
            ),

            // BSHFL — byte/halfword operations selected by shamt
            0x20 => match shamt {
                0x00 => rtype(
                    address,
                    "bitswap",
                    format!("{}, {}", gpr(rd), gpr(rt)),
                    bytes,
                ),
                0x02 => rtype(address, "wsbh", format!("{}, {}", gpr(rd), gpr(rt)), bytes),
                0x10 => rtype(address, "seb", format!("{}, {}", gpr(rd), gpr(rt)), bytes),
                0x18 => rtype(address, "seh", format!("{}, {}", gpr(rd), gpr(rt)), bytes),
                _ => unknown(address, bytes),
            },

            // DBSHFL — 64-bit byte/halfword operations
            0x24 => match shamt {
                0x00 => rtype(
                    address,
                    "dbitswap",
                    format!("{}, {}", gpr(rd), gpr(rt)),
                    bytes,
                ),
                0x02 => rtype(address, "dsbh", format!("{}, {}", gpr(rd), gpr(rt)), bytes),
                0x05 => rtype(address, "dshd", format!("{}, {}", gpr(rd), gpr(rt)), bytes),
                _ => unknown(address, bytes),
            },

            // RDHWR
            0x3B => rtype(address, "rdhwr", format!("{}, ${rd}", gpr(rt)), bytes),

            _ => unknown(address, bytes),
        }
    }
}

// ---------------------------------------------------------------------------
// Instruction builder helpers
// ---------------------------------------------------------------------------

fn mk(
    address: Address,
    mnemonic: &str,
    operands: String,
    flags: InstrFlags,
    bytes: Vec<u8>,
) -> Instruction {
    let mut instr = Instruction::new(address, 4, mnemonic, bytes);
    instr.operands = operands;
    instr.flags = flags;
    instr
}

fn rtype(address: Address, mnemonic: &str, operands: String, bytes: Vec<u8>) -> Instruction {
    mk(address, mnemonic, operands, InstrFlags::NONE, bytes)
}

fn itype(address: Address, mnemonic: &str, dst: &str, src: &str, bytes: Vec<u8>) -> Instruction {
    mk(
        address,
        mnemonic,
        format!("{dst}, {src}"),
        InstrFlags::NONE,
        bytes,
    )
}

fn branch_i(
    address: Address,
    mnemonic: &str,
    rs: usize,
    rt: Option<usize>,
    simm16: i64,
    bytes: Vec<u8>,
) -> Instruction {
    let target = branch_target_i(address, simm16);
    let operands = rt.map_or_else(
        || format!("{}, 0x{target:x}", gpr(rs)),
        |rt_idx| format!("{}, {}, 0x{target:x}", gpr(rs), gpr(rt_idx)),
    );
    mk(
        address,
        mnemonic,
        operands,
        InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
        bytes,
    )
}

fn mem_op(
    address: Address,
    mnemonic: &str,
    rt: usize,
    base: usize,
    offset: i64,
    flags: InstrFlags,
    bytes: Vec<u8>,
) -> Instruction {
    mk(
        address,
        mnemonic,
        format!("{}, {offset}({})", gpr(rt), gpr(base)),
        flags,
        bytes,
    )
}

fn mem_op_fp(
    address: Address,
    mnemonic: &str,
    ft: usize,
    base: usize,
    offset: i64,
    flags: InstrFlags,
    bytes: Vec<u8>,
) -> Instruction {
    mk(
        address,
        mnemonic,
        format!("$f{ft}, {offset}({})", gpr(base)),
        flags,
        bytes,
    )
}

fn unknown(address: Address, bytes: Vec<u8>) -> Instruction {
    mk(address, "unknown", String::new(), InstrFlags::NONE, bytes)
}

fn rs_simm(rs: usize, simm16: i64) -> String {
    format!("{}, {simm16}", gpr(rs))
}
fn rs_uimm(rs: usize, imm16: u32) -> String {
    format!("{}, 0x{imm16:x}", gpr(rs))
}

// ---------------------------------------------------------------------------
// Branch target computation
// ---------------------------------------------------------------------------

/// PC-relative target: (PC+4) + (simm16 << 2)
#[must_use]
pub const fn branch_target_i(address: Address, simm16: i64) -> u64 {
    let pc4 = address.0.wrapping_add(4);
    pc4.wrapping_add((simm16 << 2).cast_unsigned())
}

/// J-type absolute target: { (PC+4)[63:28], `instr_index`, 2'b00 }
#[must_use]
pub const fn branch_target_j(address: Address, target26: u32) -> u64 {
    let pc4 = address.0.wrapping_add(4);
    let upper = pc4 & 0xFFFF_FFFF_F000_0000u64;
    upper | ((target26 as u64) << 2)
}

// ---------------------------------------------------------------------------
// Architecture trait implementation
// ---------------------------------------------------------------------------

impl Architecture for MipsArch {
    fn name(&self) -> &str {
        match (self.bits, &self.endian) {
            (32, MipsEndian::Little) => "mips32le",
            (32, MipsEndian::Big) => "mips32be",
            (64, MipsEndian::Little) => "mips64le",
            (64, MipsEndian::Big) => "mips64be",
            _ => "mips",
        }
    }

    fn pointer_size(&self) -> usize {
        if self.bits == 64 { 8 } else { 4 }
    }

    fn endian(&self) -> Endian {
        match self.endian {
            MipsEndian::Little => Endian::Little,
            MipsEndian::Big => Endian::Big,
        }
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        let word = self
            .read_word(bytes)
            .ok_or_else(|| CoreError::PluginError {
                plugin: "mips".into(),
                message: "truncated MIPS instruction".into(),
            })?;
        Ok(self.decode_word(address, word, bytes))
    }

    fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo> {
        if !instr.flags.intersects(InstrFlags::BRANCH | InstrFlags::RET) {
            return vec![];
        }
        if instr.flags.contains(InstrFlags::INDIRECT) {
            return vec![];
        }
        let Some(word) = self.read_word(&instr.bytes) else {
            return vec![];
        };
        let opcode = (word >> 26) & 0x3F;
        let imm16 = word & 0xFFFF;
        let simm16 = i64::from(imm16 as i16);
        let target26 = word & 0x03FF_FFFF;
        let target_addr = match opcode {
            0x02 | 0x03 => branch_target_j(instr.address, target26),
            0x01 | 0x04..=0x07 | 0x14..=0x17 => branch_target_i(instr.address, simm16),
            _ => return vec![],
        };
        let branch = if instr.flags.contains(InstrFlags::CONDITIONAL) {
            BranchInfo::conditional_jump(target_addr, BranchCondition::Custom(0))
        } else if instr.flags.contains(InstrFlags::CALL) {
            BranchInfo::call(target_addr)
        } else {
            BranchInfo::unconditional_jump(target_addr)
        };
        vec![branch]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        mips_registers(self.bits)
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        mips_calling_conventions(self.bits, self.abi)
    }
}

// ---------------------------------------------------------------------------
// Register definitions
// ---------------------------------------------------------------------------

fn mips_registers(bits: u32) -> Vec<RegisterInfo> {
    let gsz = if bits == 64 { 8usize } else { 4 };
    let mut regs = Vec::with_capacity(128);
    let mut id = 0u32;

    // Numeric names r0..r31
    for i in 0u32..32 {
        let kind = if i == field_u32(REG_SP) {
            RegisterKind::Stack
        } else if i == field_u32(REG_RA) {
            RegisterKind::Link
        } else {
            RegisterKind::General
        };
        regs.push(RegisterInfo::new(format!("r{i}"), id, gsz, kind));
        id += 1;
    }

    // ABI names
    let abi_names: [&str; 32] = [
        "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
        "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp",
        "fp", "ra",
    ];
    for (i, name) in abi_names.iter().enumerate() {
        let kind = match i {
            29 => RegisterKind::Stack,
            31 => RegisterKind::Link,
            _ => RegisterKind::General,
        };
        regs.push(RegisterInfo::new(*name, id, gsz, kind));
        id += 1;
    }

    // Special integer registers
    regs.push(RegisterInfo::new("hi", id, gsz, RegisterKind::General));
    id += 1;
    regs.push(RegisterInfo::new("lo", id, gsz, RegisterKind::General));
    id += 1;
    regs.push(RegisterInfo::new(
        "pc",
        id,
        gsz,
        RegisterKind::ProgramCounter,
    ));
    id += 1;

    // FPRs f0..f31 (64-bit doubles)
    for i in 0u32..32 {
        regs.push(RegisterInfo::new(
            format!("f{i}"),
            id,
            8,
            RegisterKind::Float,
        ));
        id += 1;
    }

    // FPU control registers
    regs.push(RegisterInfo::new("fir", id, 4, RegisterKind::Flags));
    id += 1;
    regs.push(RegisterInfo::new("fccr", id, 4, RegisterKind::Flags));
    id += 1;
    regs.push(RegisterInfo::new("fcsr", id, 4, RegisterKind::Flags));
    id += 1;

    // COP0 subset
    let cop0: &[(&str, usize)] = &[
        ("index", 4),
        ("random", 4),
        ("entrylo0", gsz),
        ("entrylo1", gsz),
        ("context", gsz),
        ("pagemask", 4),
        ("wired", 4),
        ("hwrena", 4),
        ("badvaddr", gsz),
        ("count", 4),
        ("entryhi", gsz),
        ("compare", 4),
        ("status", 4),
        ("cause", 4),
        ("epc", gsz),
        ("prid", 4),
        ("config", 4),
        ("lladdr", gsz),
        ("watchlo", gsz),
        ("watchhi", 4),
    ];
    for (name, sz) in cop0 {
        regs.push(RegisterInfo::new(*name, id, *sz, RegisterKind::System));
        id += 1;
    }

    let _ = id;
    regs
}

// ---------------------------------------------------------------------------
// Calling conventions
// ---------------------------------------------------------------------------

fn mips_calling_conventions(bits: u32, abi: MipsAbi) -> Vec<CallingConvention> {
    let mut out = Vec::new();

    // O32 — 4 integer args, 2 return regs
    out.push(
        CallingConvention::new("mips_o32")
            .with_int_args(vec!["a0".into(), "a1".into(), "a2".into(), "a3".into()])
            .with_return_regs(vec!["v0".into(), "v1".into()]),
    );

    if bits == 64 || abi == MipsAbi::N64 {
        // N64 — 8 integer args
        out.push(
            CallingConvention::new("mips_n64")
                .with_int_args(vec![
                    "a0".into(),
                    "a1".into(),
                    "a2".into(),
                    "a3".into(),
                    "a4".into(),
                    "a5".into(),
                    "a6".into(),
                    "a7".into(),
                ])
                .with_return_regs(vec!["v0".into(), "v1".into()]),
        );
    }

    if abi == MipsAbi::N32 {
        out.push(
            CallingConvention::new("mips_n32")
                .with_int_args(vec![
                    "a0".into(),
                    "a1".into(),
                    "a2".into(),
                    "a3".into(),
                    "a4".into(),
                    "a5".into(),
                    "a6".into(),
                    "a7".into(),
                ])
                .with_return_regs(vec!["v0".into(), "v1".into()]),
        );
    }

    out
}

// ---------------------------------------------------------------------------
// Linear disassembler
// ---------------------------------------------------------------------------

/// Iterator-based linear disassembler. Advances 4 bytes per step.
pub struct MipsLinearDisassembler<'a> {
    arch: &'a MipsArch,
    bytes: &'a [u8],
    base_addr: Address,
    offset: usize,
    /// Tag delay-slot instructions in the output stream.
    pub annotate_delay_slots: bool,
}

impl<'a> MipsLinearDisassembler<'a> {
    #[must_use]
    pub const fn new(arch: &'a MipsArch, bytes: &'a [u8], base_addr: Address) -> Self {
        Self {
            arch,
            bytes,
            base_addr,
            offset: 0,
            annotate_delay_slots: false,
        }
    }

    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    #[must_use]
    pub const fn current_address(&self) -> Address {
        Address::new(self.base_addr.0.wrapping_add(self.offset as u64))
    }

    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.offset + 4 > self.bytes.len()
    }
}

impl Iterator for MipsLinearDisassembler<'_> {
    type Item = Result<Instruction, CoreError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset + 4 > self.bytes.len() {
            return None;
        }
        let cur_addr = Address::new(self.base_addr.0.wrapping_add(self.offset as u64));
        let result = self.arch.disassemble(cur_addr, &self.bytes[self.offset..]);
        self.offset += 4;
        Some(result)
    }
}

// ---------------------------------------------------------------------------
// Delay-slot analysis
// ---------------------------------------------------------------------------

/// Utility for classifying MIPS delay slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelaySlotAnalyzer;

impl DelaySlotAnalyzer {
    /// Returns `true` when `instr` has a mandatory 1-instruction delay slot.
    /// In classic MIPS (I through V) all branch and jump instructions have one.
    #[must_use]
    pub fn has_delay_slot(instr: &Instruction) -> bool {
        instr.flags.intersects(InstrFlags::BRANCH | InstrFlags::RET)
    }

    /// Tag which instructions sit in a delay slot.
    /// Returns a `Vec<bool>` parallel to `instrs`.
    #[must_use]
    pub fn tag_delay_slots(instrs: &[Instruction]) -> Vec<bool> {
        let mut tags = vec![false; instrs.len()];
        for i in 0..instrs.len().saturating_sub(1) {
            if Self::has_delay_slot(&instrs[i]) {
                tags[i + 1] = true;
            }
        }
        tags
    }
}

// ---------------------------------------------------------------------------
// LLIL (Low-Level Intermediate Language) lifter
// ---------------------------------------------------------------------------
// In MIPS the delay-slot instruction always executes before the branch is
// taken. The caller is responsible for emitting the delay-slot instruction
// BEFORE the branch/jump LlilOp in the final LLIL stream.

/// Arithmetic operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlilArithOp {
    Add,
    Sub,
    Mul,
    Div,
    DivU,
    And,
    Or,
    Xor,
    Nor,
    Sll,
    Srl,
    Sra,
    Slt,
    SltU,
}

/// Condition expression for a conditional jump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlilCond {
    /// Equal: a == b.
    Eq(String, String),
    /// Not equal: a != b.
    Ne(String, String),
    /// Less than zero: a < 0 (signed).
    Ltz(String),
    /// Greater or equal to zero: a >= 0 (signed).
    Gez(String),
    /// Less or equal to zero: a <= 0 (signed).
    Lez(String),
    /// Greater than zero: a > 0 (signed).
    Gtz(String),
}

/// One lifted LLIL operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlilOp {
    /// `dest = constant`
    SetRegConst { dest: String, value: i64 },
    /// `dest = src`
    SetRegReg { dest: String, src: String },
    /// `dest = lhs op rhs` (register)
    Arith {
        dest: String,
        lhs: String,
        op: LlilArithOp,
        rhs: String,
    },
    /// `dest = lhs op imm` (immediate)
    ArithConst {
        dest: String,
        lhs: String,
        op: LlilArithOp,
        rhs: i64,
    },
    /// `dest = mem[base + offset]`
    Load {
        dest: String,
        base: String,
        offset: i64,
        size: u8,
    },
    /// `mem[base + offset] = src`
    Store {
        base: String,
        offset: i64,
        src: String,
        size: u8,
    },
    /// Unconditional jump.
    Jump { target: u64 },
    /// Conditional jump.
    CondJump { cond: LlilCond, target: u64 },
    /// Direct call.
    Call { target: u64 },
    /// Indirect call (target is in a register).
    CallReg { reg: String },
    /// Return from function.
    Ret,
    /// No operation.
    Nop,
    /// System call.
    Syscall,
    /// Debug break.
    Break,
    /// Unlifted (opaque) instruction.
    Unimpl { mnemonic: String },
}

/// Lift one MIPS instruction to LLIL operations.
/// Delay-slot semantics: the caller must interleave the delay-slot instruction
/// BEFORE the branch/jump `LlilOp`.
#[must_use]
pub fn lift_to_llil(instr: &Instruction) -> Vec<LlilOp> {
    let m = instr.mnemonic.as_str();
    let ops = &instr.operands;
    let parts: Vec<&str> = ops.split(',').map(str::trim).collect();

    match m {
        // ── NOP detection ──────────────────────────────────────────────
        "sll" if ops.trim() == "$zero, $zero, 0" => return vec![LlilOp::Nop],
        "nop" => return vec![LlilOp::Nop],
        "break" => return vec![LlilOp::Break],
        "syscall" => return vec![LlilOp::Syscall],

        // ── Register-register ALU ──────────────────────────────────────
        "add" | "addu" | "dadd" | "daddu" => {
            if parts.len() >= 3 {
                return vec![LlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: LlilArithOp::Add,
                    rhs: parts[2].into(),
                }];
            }
        }
        "sub" | "subu" | "dsub" | "dsubu" => {
            if parts.len() >= 3 {
                return vec![LlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: LlilArithOp::Sub,
                    rhs: parts[2].into(),
                }];
            }
        }
        "and" => {
            if parts.len() >= 3 {
                return vec![LlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: LlilArithOp::And,
                    rhs: parts[2].into(),
                }];
            }
        }
        "or" => {
            if parts.len() >= 3 {
                if parts[1] == "$zero" && parts[2] == "$zero" {
                    return vec![LlilOp::SetRegConst {
                        dest: parts[0].into(),
                        value: 0,
                    }];
                }
                return vec![LlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: LlilArithOp::Or,
                    rhs: parts[2].into(),
                }];
            }
        }
        "xor" => {
            if parts.len() >= 3 {
                return vec![LlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: LlilArithOp::Xor,
                    rhs: parts[2].into(),
                }];
            }
        }
        "nor" => {
            if parts.len() >= 3 {
                return vec![LlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: LlilArithOp::Nor,
                    rhs: parts[2].into(),
                }];
            }
        }
        "slt" => {
            if parts.len() >= 3 {
                return vec![LlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: LlilArithOp::Slt,
                    rhs: parts[2].into(),
                }];
            }
        }
        "sltu" => {
            if parts.len() >= 3 {
                return vec![LlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: LlilArithOp::SltU,
                    rhs: parts[2].into(),
                }];
            }
        }

        // ── Immediate ALU ──────────────────────────────────────────────
        _ => {}
    }

    lift_immediate_alu(instr, m, ops, &parts)
}

/// LLIL lifting for the immediate-operand ALU and shift mnemonics.
///
/// Split out of `lift_to_llil` for length only; it is the next step of the
/// same fall-through chain.
fn lift_immediate_alu(instr: &Instruction, m: &str, ops: &str, parts: &[&str]) -> Vec<LlilOp> {
    match m {
        "addi" | "addiu" | "daddi" | "daddiu" => {
            if parts.len() >= 2 {
                let sub_joined = parts[1..].join(",");
                let sub: Vec<&str> = sub_joined.split(',').map(str::trim).collect::<Vec<_>>();
                if sub.len() >= 2 {
                    let imm = parse_imm(sub[1]);
                    return vec![LlilOp::ArithConst {
                        dest: parts[0].into(),
                        lhs: sub[0].into(),
                        op: LlilArithOp::Add,
                        rhs: imm,
                    }];
                }
            }
        }
        "andi" => {
            if parts.len() >= 2 {
                let sub_joined = parts[1..].join(",");
                let sub: Vec<&str> = sub_joined.split(',').map(str::trim).collect::<Vec<_>>();
                if sub.len() >= 2 {
                    let imm = parse_imm(sub[1]);
                    return vec![LlilOp::ArithConst {
                        dest: parts[0].into(),
                        lhs: sub[0].into(),
                        op: LlilArithOp::And,
                        rhs: imm,
                    }];
                }
            }
        }
        "ori" => {
            if parts.len() >= 2 {
                let sub_joined = parts[1..].join(",");
                let sub: Vec<&str> = sub_joined.split(',').map(str::trim).collect::<Vec<_>>();
                if sub.len() >= 2 {
                    let imm = parse_imm(sub[1]);
                    return vec![LlilOp::ArithConst {
                        dest: parts[0].into(),
                        lhs: sub[0].into(),
                        op: LlilArithOp::Or,
                        rhs: imm,
                    }];
                }
            }
        }
        "xori" => {
            if parts.len() >= 2 {
                let sub_joined = parts[1..].join(",");
                let sub: Vec<&str> = sub_joined.split(',').map(str::trim).collect::<Vec<_>>();
                if sub.len() >= 2 {
                    let imm = parse_imm(sub[1]);
                    return vec![LlilOp::ArithConst {
                        dest: parts[0].into(),
                        lhs: sub[0].into(),
                        op: LlilArithOp::Xor,
                        rhs: imm,
                    }];
                }
            }
        }
        "slti" => {
            if parts.len() >= 2 {
                let sub_joined = parts[1..].join(",");
                let sub: Vec<&str> = sub_joined.split(',').map(str::trim).collect::<Vec<_>>();
                if sub.len() >= 2 {
                    let imm = parse_imm(sub[1]);
                    return vec![LlilOp::ArithConst {
                        dest: parts[0].into(),
                        lhs: sub[0].into(),
                        op: LlilArithOp::Slt,
                        rhs: imm,
                    }];
                }
            }
        }
        "sltiu" => {
            if parts.len() >= 2 {
                let sub_joined = parts[1..].join(",");
                let sub: Vec<&str> = sub_joined.split(',').map(str::trim).collect::<Vec<_>>();
                if sub.len() >= 2 {
                    let imm = parse_imm(sub[1]);
                    return vec![LlilOp::ArithConst {
                        dest: parts[0].into(),
                        lhs: sub[0].into(),
                        op: LlilArithOp::SltU,
                        rhs: imm,
                    }];
                }
            }
        }
        _ => {}
    }

    lift_shifts(instr, m, ops, parts)
}

/// LLIL lifting for the shift-by-constant mnemonics and `lui`.
///
/// Split out of `lift_immediate_alu` for length only; same fall-through chain.
fn lift_shifts(instr: &Instruction, m: &str, ops: &str, parts: &[&str]) -> Vec<LlilOp> {
    match m {
        "sll" | "dsll" | "dsll32" => {
            if parts.len() >= 3 {
                let shamt = parts[2].parse::<i64>().unwrap_or(0);
                return vec![LlilOp::ArithConst {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: LlilArithOp::Sll,
                    rhs: shamt,
                }];
            }
        }
        "srl" | "dsrl" | "dsrl32" => {
            if parts.len() >= 3 {
                let shamt = parts[2].parse::<i64>().unwrap_or(0);
                return vec![LlilOp::ArithConst {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: LlilArithOp::Srl,
                    rhs: shamt,
                }];
            }
        }
        "sra" | "dsra" | "dsra32" => {
            if parts.len() >= 3 {
                let shamt = parts[2].parse::<i64>().unwrap_or(0);
                return vec![LlilOp::ArithConst {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: LlilArithOp::Sra,
                    rhs: shamt,
                }];
            }
        }
        "lui" => {
            if parts.len() >= 2 {
                let imm = parse_imm(parts[1]);
                return vec![LlilOp::SetRegConst {
                    dest: parts[0].into(),
                    value: imm << 16,
                }];
            }
        }

        _ => {}
    }

    lift_mem_and_control(instr, m, ops, parts)
}

/// LLIL lifting for the load/store, move and control-flow mnemonics.
///
/// Split out of `lift_to_llil` for length only. It is the tail of the same
/// dispatch: `lift_to_llil` falls through to it when its own match finds no
/// arm, and this one falls through to `LlilOp::Unimpl`.
fn lift_mem_and_control(instr: &Instruction, m: &str, ops: &str, parts: &[&str]) -> Vec<LlilOp> {
    match m {
        // ── Loads ─────────────────────────────────────────────────────
        "lb" | "lbu" | "lh" | "lhu" | "lw" | "lwu" | "ld" => {
            let sz: u8 = match m {
                "lb" | "lbu" => 1,
                "lh" | "lhu" => 2,
                "lw" | "lwu" => 4,
                _ => 8,
            };
            if let Some((dst, base_reg, offset)) = parse_mem_operand(ops) {
                return vec![LlilOp::Load {
                    dest: dst,
                    base: base_reg,
                    offset,
                    size: sz,
                }];
            }
        }

        // ── Stores ────────────────────────────────────────────────────
        "sb" | "sh" | "sw" | "sd" => {
            let sz: u8 = match m {
                "sb" => 1,
                "sh" => 2,
                "sw" => 4,
                _ => 8,
            };
            if let Some((src, base_reg, offset)) = parse_mem_operand(ops) {
                return vec![LlilOp::Store {
                    base: base_reg,
                    offset,
                    src,
                    size: sz,
                }];
            }
        }

        // ── Moves (pseudo-instructions) ────────────────────────────────
        "movz" | "movn" => {
            if parts.len() >= 2 {
                return vec![LlilOp::SetRegReg {
                    dest: parts[0].into(),
                    src: parts[1].into(),
                }];
            }
        }

        // ── Control flow ───────────────────────────────────────────────
        _ => {}
    }

    lift_control_flow(instr, m, ops, parts)
}

/// LLIL lifting for the control-flow mnemonics: jumps, calls, branches, eret.
///
/// Split out of `lift_mem_and_control` for length only; last step of the
/// fall-through chain before `LlilOp::Unimpl`.
fn lift_control_flow(instr: &Instruction, m: &str, ops: &str, parts: &[&str]) -> Vec<LlilOp> {
    match m {
        "j" => {
            return vec![LlilOp::Jump {
                target: parse_hex_target(ops),
            }];
        }
        "jal" => {
            let t = parse_hex_target(ops);
            return vec![
                LlilOp::SetRegConst {
                    dest: "$ra".into(),
                    value: (instr.address.0 + 8).cast_signed(),
                },
                LlilOp::Call { target: t },
            ];
        }
        "jr" => {
            if ops.trim() == "$ra" {
                return vec![LlilOp::Ret];
            }
            return vec![LlilOp::Jump { target: 0 }]; // indirect
        }
        "jalr" => {
            let reg = parts.last().unwrap_or(&"$ra").to_string();
            return vec![LlilOp::CallReg { reg }];
        }
        "beq" | "beql" => {
            if parts.len() >= 3 {
                let t = parse_hex_target(parts[2]);
                return vec![LlilOp::CondJump {
                    cond: LlilCond::Eq(parts[0].into(), parts[1].into()),
                    target: t,
                }];
            }
        }
        "bne" | "bnel" => {
            if parts.len() >= 3 {
                let t = parse_hex_target(parts[2]);
                return vec![LlilOp::CondJump {
                    cond: LlilCond::Ne(parts[0].into(), parts[1].into()),
                    target: t,
                }];
            }
        }
        "blez" | "blezl" => {
            if parts.len() >= 2 {
                let t = parse_hex_target(parts[1]);
                return vec![LlilOp::CondJump {
                    cond: LlilCond::Lez(parts[0].into()),
                    target: t,
                }];
            }
        }
        "bgtz" | "bgtzl" => {
            if parts.len() >= 2 {
                let t = parse_hex_target(parts[1]);
                return vec![LlilOp::CondJump {
                    cond: LlilCond::Gtz(parts[0].into()),
                    target: t,
                }];
            }
        }
        "bltz" | "bltzl" | "bltzal" | "bltzall" => {
            if parts.len() >= 2 {
                let t = parse_hex_target(parts[1]);
                return vec![LlilOp::CondJump {
                    cond: LlilCond::Ltz(parts[0].into()),
                    target: t,
                }];
            }
        }
        "bgez" | "bgezl" | "bgezal" | "bgezall" => {
            if parts.len() >= 2 {
                let t = parse_hex_target(parts[1]);
                return vec![LlilOp::CondJump {
                    cond: LlilCond::Gez(parts[0].into()),
                    target: t,
                }];
            }
        }
        "eret" => {
            return vec![LlilOp::Ret];
        }

        _ => {}
    }

    vec![LlilOp::Unimpl {
        mnemonic: m.to_string(),
    }]
}

fn parse_imm(s: &str) -> i64 {
    let s = s.trim();
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .map_or_else(
            || s.parse::<i64>().unwrap_or(0),
            |hex| i64::from_str_radix(hex, 16).unwrap_or(0),
        )
}

fn parse_hex_target(s: &str) -> u64 {
    let s = s.trim();
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .map_or_else(
            || s.parse::<u64>().unwrap_or(0),
            |hex| u64::from_str_radix(hex, 16).unwrap_or(0),
        )
}

/// Parse `reg, offset(base)` memory operand format.
fn parse_mem_operand(ops: &str) -> Option<(String, String, i64)> {
    let comma = ops.find(',')?;
    let reg = ops[..comma].trim().to_string();
    let rest = ops[comma + 1..].trim();
    let lparen = rest.find('(')?;
    let rparen = rest.find(')')?;
    let offset = rest[..lparen].trim().parse::<i64>().unwrap_or(0);
    let base = rest[lparen + 1..rparen].trim().to_string();
    Some((reg, base, offset))
}

// ---------------------------------------------------------------------------
// Basic block analysis
// ---------------------------------------------------------------------------

/// A MIPS basic block (including the delay-slot instruction after a terminator).
#[derive(Debug, Clone)]
pub struct MipsBasicBlock {
    pub start: Address,
    pub instructions: Vec<Instruction>,
}

impl MipsBasicBlock {
    /// Find basic blocks via linear sweep.
    /// Each unconditional branch/return terminates a block after its delay slot.
    #[must_use]
    pub fn find_blocks(arch: &MipsArch, bytes: &[u8], base: Address) -> Vec<Self> {
        let mut blocks = Vec::new();
        let mut current = Vec::new();
        let mut block_start = base;
        let mut offset = 0usize;
        let mut in_delay_slot = false;

        while offset + 4 <= bytes.len() {
            let addr = Address::new(base.0.wrapping_add(offset as u64));
            let Ok(instr) = arch.disassemble(addr, &bytes[offset..]) else {
                offset += 4;
                continue;
            };
            let is_uncond = instr.flags.intersects(InstrFlags::BRANCH | InstrFlags::RET)
                && !instr.flags.contains(InstrFlags::CONDITIONAL);

            current.push(instr);
            offset += 4;

            if in_delay_slot {
                blocks.push(Self {
                    start: block_start,
                    instructions: std::mem::take(&mut current),
                });
                block_start = Address::new(base.0.wrapping_add(offset as u64));
                in_delay_slot = false;
            } else if is_uncond {
                in_delay_slot = true;
            }
        }
        if !current.is_empty() {
            blocks.push(Self {
                start: block_start,
                instructions: current,
            });
        }
        blocks
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Code statistics
// ---------------------------------------------------------------------------

/// Statistics gathered from a linear sweep of MIPS bytes.
#[derive(Debug, Default, Clone)]
pub struct MipsCodeStats {
    pub total: usize,
    pub branches: usize,
    pub calls: usize,
    pub loads: usize,
    pub stores: usize,
    pub alu: usize,
    pub mul_div: usize,
    pub fp_ops: usize,
    pub syscalls: usize,
    pub unknowns: usize,
}

impl MipsCodeStats {
    /// Sweep `bytes` and categorise each instruction.
    #[must_use]
    pub fn from_bytes(arch: &MipsArch, bytes: &[u8], base: Address) -> Self {
        let mut s = Self::default();
        for instr in MipsLinearDisassembler::new(arch, bytes, base).flatten() {
            s.total += 1;
            let m = instr.mnemonic.as_str();
            if instr.flags.contains(InstrFlags::CALL) {
                s.calls += 1;
                continue;
            }
            if instr.flags.contains(InstrFlags::BRANCH) {
                s.branches += 1;
                continue;
            }
            if instr.flags.contains(InstrFlags::READ_MEM) {
                s.loads += 1;
                continue;
            }
            if instr.flags.contains(InstrFlags::WRITE_MEM) {
                s.stores += 1;
                continue;
            }
            if m == "syscall" {
                s.syscalls += 1;
                continue;
            }
            if m == "unknown" {
                s.unknowns += 1;
                continue;
            }
            if m.starts_with("mult")
                || m.starts_with("div")
                || m == "mul"
                || m.starts_with("madd")
                || m.starts_with("msub")
                || m.starts_with("dmult")
                || m.starts_with("ddiv")
            {
                s.mul_div += 1;
                continue;
            }
            if m.starts_with("add")
                || m.starts_with("sub")
                || m.starts_with("and")
                || m.starts_with("or")
                || m.starts_with("xor")
                || m.starts_with("nor")
                || m.starts_with("slt")
                || m.starts_with("sll")
                || m.starts_with("srl")
                || m.starts_with("sra")
                || m.starts_with("lui")
                || m.starts_with("clz")
                || m.starts_with("clo")
            {
                s.alu += 1;
                continue;
            }
            if m.starts_with("fadd")
                || m.starts_with("fsub")
                || m.starts_with("fmul")
                || m.starts_with("fdiv")
                || m.starts_with("cvt")
                || m.starts_with("c.")
                || m.starts_with("mov.")
                || m.starts_with("add.")
                || m.starts_with("sub.")
                || m.starts_with("mul.")
                || m.starts_with("div.")
            {
                s.fp_ops += 1;
            }
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// Encode an R-type word (opcode = 0).
#[must_use]
pub const fn encode_rtype(rs: u32, rt: u32, rd: u32, shamt: u32, funct: u32) -> u32 {
    (rs << 21) | (rt << 16) | (rd << 11) | (shamt << 6) | funct
}

/// Encode an I-type word.
#[must_use]
pub fn encode_itype(opcode: u32, rs: u32, rt: u32, imm: u16) -> u32 {
    (opcode << 26) | (rs << 21) | (rt << 16) | u32::from(imm)
}

/// Encode a J-type word.
#[must_use]
pub const fn encode_jtype(opcode: u32, target: u32) -> u32 {
    (opcode << 26) | (target & 0x03FF_FFFF)
}

/// NOP = SLL $zero, $zero, 0
#[must_use]
pub const fn encode_nop() -> u32 {
    0
}
/// ADDU rd, rs, rt
#[must_use]
pub const fn encode_addu(rd: u32, rs: u32, rt: u32) -> u32 {
    encode_rtype(rs, rt, rd, 0, 0x21)
}
/// SUBU rd, rs, rt
#[must_use]
pub const fn encode_subu(rd: u32, rs: u32, rt: u32) -> u32 {
    encode_rtype(rs, rt, rd, 0, 0x23)
}
/// AND rd, rs, rt
#[must_use]
pub const fn encode_and(rd: u32, rs: u32, rt: u32) -> u32 {
    encode_rtype(rs, rt, rd, 0, 0x24)
}
/// OR rd, rs, rt
#[must_use]
pub const fn encode_or(rd: u32, rs: u32, rt: u32) -> u32 {
    encode_rtype(rs, rt, rd, 0, 0x25)
}
/// XOR rd, rs, rt
#[must_use]
pub const fn encode_xor(rd: u32, rs: u32, rt: u32) -> u32 {
    encode_rtype(rs, rt, rd, 0, 0x26)
}
/// NOR rd, rs, rt
#[must_use]
pub const fn encode_nor(rd: u32, rs: u32, rt: u32) -> u32 {
    encode_rtype(rs, rt, rd, 0, 0x27)
}
/// SLT rd, rs, rt
#[must_use]
pub const fn encode_slt(rd: u32, rs: u32, rt: u32) -> u32 {
    encode_rtype(rs, rt, rd, 0, 0x2A)
}
/// SLTU rd, rs, rt
#[must_use]
pub const fn encode_sltu(rd: u32, rs: u32, rt: u32) -> u32 {
    encode_rtype(rs, rt, rd, 0, 0x2B)
}
/// MULT rs, rt
#[must_use]
pub const fn encode_mult(rs: u32, rt: u32) -> u32 {
    encode_rtype(rs, rt, 0, 0, 0x18)
}
/// DIV rs, rt
#[must_use]
pub const fn encode_div(rs: u32, rt: u32) -> u32 {
    encode_rtype(rs, rt, 0, 0, 0x1A)
}
/// MFHI rd
#[must_use]
pub const fn encode_mfhi(rd: u32) -> u32 {
    encode_rtype(0, 0, rd, 0, 0x10)
}
/// MFLO rd
#[must_use]
pub const fn encode_mflo(rd: u32) -> u32 {
    encode_rtype(0, 0, rd, 0, 0x12)
}
/// JR rs
#[must_use]
pub const fn encode_jr(rs: u32) -> u32 {
    encode_rtype(rs, 0, 0, 0, 0x08)
}
/// JALR rd, rs
#[must_use]
pub const fn encode_jalr(rd: u32, rs: u32) -> u32 {
    encode_rtype(rs, 0, rd, 0, 0x09)
}
/// JAL target26
#[must_use]
pub const fn encode_jal(target26: u32) -> u32 {
    encode_jtype(0x03, target26)
}
/// J target26
#[must_use]
pub const fn encode_j(target26: u32) -> u32 {
    encode_jtype(0x02, target26)
}
/// LUI rt, imm
#[must_use]
pub fn encode_lui(rt: u32, imm: u16) -> u32 {
    encode_itype(0x0F, 0, rt, imm)
}
/// ADDIU rt, rs, imm
#[must_use]
pub fn encode_addiu(rt: u32, rs: u32, imm: i16) -> u32 {
    encode_itype(0x09, rs, rt, imm.cast_unsigned())
}
/// LW rt, offset(rs)
#[must_use]
pub fn encode_lw(rt: u32, rs: u32, offset: i16) -> u32 {
    encode_itype(0x23, rs, rt, offset.cast_unsigned())
}
/// SW rt, offset(rs)
#[must_use]
pub fn encode_sw(rt: u32, rs: u32, offset: i16) -> u32 {
    encode_itype(0x2B, rs, rt, offset.cast_unsigned())
}
/// BEQ rs, rt, offset
#[must_use]
pub fn encode_beq(rs: u32, rt: u32, off: i16) -> u32 {
    encode_itype(0x04, rs, rt, off.cast_unsigned())
}
/// BNE rs, rt, offset
#[must_use]
pub fn encode_bne(rs: u32, rt: u32, off: i16) -> u32 {
    encode_itype(0x05, rs, rt, off.cast_unsigned())
}
/// SYSCALL with code
#[must_use]
pub const fn encode_syscall(code: u32) -> u32 {
    (code & 0xFFFFF) << 6 | 0x0C
}

// ---------------------------------------------------------------------------
// Tests — 55 unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::arch::BranchKind;

    fn arch32le() -> MipsArch {
        MipsArch::mips32_le()
    }
    fn arch32be() -> MipsArch {
        MipsArch::mips32_be()
    }
    fn arch64le() -> MipsArch {
        MipsArch::mips64_le()
    }

    fn le(word: u32) -> [u8; 4] {
        word.to_le_bytes()
    }
    fn be(word: u32) -> [u8; 4] {
        word.to_be_bytes()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    // 1. ADD
    #[test]
    fn test_add() {
        let w = encode_rtype(1, 2, 3, 0, 0x20);
        let i = arch32le().disassemble(addr(0x1000), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "add");
        assert!(i.operands.contains("$v1"));
        assert_eq!(i.flags, InstrFlags::NONE);
    }

    // 2. ADDU
    #[test]
    fn test_addu() {
        let w = encode_rtype(4, 5, 6, 0, 0x21);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "addu");
    }

    // 3. SUB
    #[test]
    fn test_sub() {
        let w = encode_rtype(1, 2, 3, 0, 0x22);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "sub");
    }

    // 4. SUBU
    #[test]
    fn test_subu() {
        let w = encode_rtype(1, 2, 3, 0, 0x23);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "subu");
    }

    // 5. AND
    #[test]
    fn test_and() {
        let w = encode_rtype(1, 2, 3, 0, 0x24);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "and");
    }

    // 6. OR
    #[test]
    fn test_or() {
        let w = encode_rtype(1, 2, 3, 0, 0x25);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "or");
    }

    // 7. XOR
    #[test]
    fn test_xor() {
        let w = encode_rtype(1, 2, 3, 0, 0x26);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "xor");
    }

    // 8. NOR
    #[test]
    fn test_nor() {
        let w = encode_rtype(1, 2, 3, 0, 0x27);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "nor");
    }

    // 9. SLT
    #[test]
    fn test_slt() {
        let w = encode_rtype(1, 2, 3, 0, 0x2A);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "slt");
    }

    // 10. SLTU
    #[test]
    fn test_sltu() {
        let w = encode_rtype(1, 2, 3, 0, 0x2B);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "sltu");
    }

    // 11. ADDI
    #[test]
    fn test_addi() {
        let w = encode_itype(0x08, 1, 3, 100);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "addi");
        assert!(i.operands.contains("100"));
    }

    // 12. ADDIU
    #[test]
    fn test_addiu() {
        let w = encode_itype(0x09, 1, 3, 200);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "addiu");
    }

    // 13. LUI
    #[test]
    fn test_lui() {
        let w = encode_itype(0x0F, 0, 2, 0x1234);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "lui");
        assert!(i.operands.contains("0x1234"));
    }

    // 14. ORI unsigned immediate
    #[test]
    fn test_ori() {
        let w = encode_itype(0x0D, 0, 2, 0xFF);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "ori");
        assert!(i.operands.contains("0xff"));
    }

    // 15. LW → READ_MEM
    #[test]
    fn test_lw_read_mem() {
        let w = encode_itype(0x23, 2, 1, 4);
        let i = arch32le().disassemble(addr(0x2000), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "lw");
        assert!(i.flags.contains(InstrFlags::READ_MEM));
    }

    // 16. SW → WRITE_MEM
    #[test]
    fn test_sw_write_mem() {
        let w = encode_itype(0x2B, 2, 1, 4);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "sw");
        assert!(i.flags.contains(InstrFlags::WRITE_MEM));
    }

    // 17. LB / LBU
    #[test]
    fn test_lb_lbu() {
        let a = arch32le();
        assert_eq!(
            a.disassemble(addr(0), &le(encode_itype(0x20, 4, 5, 0)))
                .unwrap()
                .mnemonic,
            "lb"
        );
        assert_eq!(
            a.disassemble(addr(0), &le(encode_itype(0x24, 4, 5, 0)))
                .unwrap()
                .mnemonic,
            "lbu"
        );
    }

    // 18. SH / LH
    #[test]
    fn test_sh_lh() {
        let a = arch32le();
        assert_eq!(
            a.disassemble(addr(0), &le(encode_itype(0x21, 4, 5, 0)))
                .unwrap()
                .mnemonic,
            "lh"
        );
        assert_eq!(
            a.disassemble(addr(0), &le(encode_itype(0x29, 4, 5, 0)))
                .unwrap()
                .mnemonic,
            "sh"
        );
    }

    // 19. SLL shamt
    #[test]
    fn test_sll_shamt() {
        let w = encode_rtype(0, 1, 2, 3, 0x00);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "sll");
        assert!(i.operands.contains('3'));
    }

    // 20. SRL
    #[test]
    fn test_srl() {
        let w = encode_rtype(0, 1, 2, 4, 0x02);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "srl");
    }

    // 21. SRA
    #[test]
    fn test_sra() {
        let w = encode_rtype(0, 1, 2, 4, 0x03);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "sra");
    }

    // 22. MULT
    #[test]
    fn test_mult() {
        let w = encode_rtype(2, 3, 0, 0, 0x18);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "mult");
    }

    // 23. DIV
    #[test]
    fn test_div() {
        let w = encode_rtype(4, 5, 0, 0, 0x1A);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "div");
    }

    // 24. MFHI / MFLO
    #[test]
    fn test_mfhi_mflo() {
        let a = arch32le();
        assert_eq!(
            a.disassemble(addr(0), &le(encode_rtype(0, 0, 2, 0, 0x10)))
                .unwrap()
                .mnemonic,
            "mfhi"
        );
        assert_eq!(
            a.disassemble(addr(0), &le(encode_rtype(0, 0, 2, 0, 0x12)))
                .unwrap()
                .mnemonic,
            "mflo"
        );
    }

    // 25. BEQ + branch target
    #[test]
    fn test_beq_target() {
        let w = encode_itype(0x04, 1, 2, 4u16);
        let i = arch32be().disassemble(addr(0x1000), &be(w)).unwrap();
        assert_eq!(i.mnemonic, "beq");
        let br = arch32be().get_branches(&i);
        assert_eq!(br.len(), 1);
        assert_eq!(br[0].target, Some(0x1014));
        assert_eq!(br[0].kind, BranchKind::ConditionalJump);
    }

    // 26. BNE
    #[test]
    fn test_bne() {
        let w = encode_itype(0x05, 1, 2, 8);
        let i = arch32le().disassemble(addr(0xA000), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "bne");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    // 27. BLEZ / BGTZ
    #[test]
    fn test_blez_bgtz() {
        let a = arch32le();
        assert_eq!(
            a.disassemble(addr(0), &le(encode_itype(0x06, 3, 0, 4)))
                .unwrap()
                .mnemonic,
            "blez"
        );
        assert_eq!(
            a.disassemble(addr(0), &le(encode_itype(0x07, 3, 0, 4)))
                .unwrap()
                .mnemonic,
            "bgtz"
        );
    }

    // 28. J + target
    #[test]
    fn test_j_target() {
        let w = encode_jtype(0x02, 0x100);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "j");
        let br = arch32le().get_branches(&i);
        assert_eq!(br[0].target, Some(0x400));
    }

    // 29. JAL call
    #[test]
    fn test_jal_call() {
        let w = encode_jtype(0x03, 0x200);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "jal");
        assert!(i.flags.contains(InstrFlags::CALL));
        let br = arch32le().get_branches(&i);
        assert_eq!(br[0].kind, BranchKind::Call);
    }

    // 30. JR $ra → RET
    #[test]
    fn test_jr_ra_ret() {
        let w = encode_rtype(31, 0, 0, 0, 0x08);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "jr");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    // 31. JR $t0 — no RET
    #[test]
    fn test_jr_no_ret() {
        let w = encode_rtype(8, 0, 0, 0, 0x08);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert!(!i.flags.contains(InstrFlags::RET));
    }

    // 32. JALR indirect call
    #[test]
    fn test_jalr_indirect() {
        let w = encode_rtype(25, 0, 31, 0, 0x09);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "jalr");
        assert!(i.flags.contains(InstrFlags::CALL | InstrFlags::INDIRECT));
        assert!(arch32le().get_branches(&i).is_empty());
    }

    // 33. SYSCALL
    #[test]
    fn test_syscall() {
        let w = encode_rtype(0, 0, 0, 0, 0x0C);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "syscall");
        assert!(i.flags.contains(InstrFlags::CALL));
    }

    // 34. NOP
    #[test]
    fn test_nop() {
        let i = arch32le().disassemble(addr(0), &le(0)).unwrap();
        assert_eq!(i.mnemonic, "sll");
        assert_eq!(i.flags, InstrFlags::NONE);
    }

    // 35. MFC0
    #[test]
    fn test_mfc0() {
        let w: u32 = (0x10 << 26) | (2 << 16) | (12 << 11);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "mfc0");
    }

    // 36. registers() ≥ 64
    #[test]
    fn test_registers_count() {
        assert!(arch32le().registers().len() >= 64);
    }

    // 37. O32 calling convention
    #[test]
    fn test_o32_cc() {
        let ccs = arch32le().calling_conventions();
        let o32 = ccs.iter().find(|c| c.name == "mips_o32").unwrap();
        assert_eq!(o32.int_args[0], "a0");
        assert_eq!(o32.return_regs[0], "v0");
    }

    // 38. N64 calling convention
    #[test]
    fn test_n64_cc() {
        let ccs = arch64le().calling_conventions();
        let n64 = ccs.iter().find(|c| c.name == "mips_n64").unwrap();
        assert_eq!(n64.int_args.len(), 8);
    }

    // 39. arch properties
    #[test]
    fn test_arch_properties() {
        let be32 = arch32be();
        assert_eq!(be32.pointer_size(), 4);
        assert_eq!(be32.name(), "mips32be");
        assert_eq!(be32.endian(), Endian::Big);
        assert_eq!(arch64le().pointer_size(), 8);
    }

    // 40. Truncated input → error
    #[test]
    fn test_truncated_error() {
        assert!(arch32le().disassemble(addr(0), &[0, 0]).is_err());
    }

    // 41. 64-bit register size
    #[test]
    fn test_64bit_reg_size() {
        let regs = arch64le().registers();
        let gp = regs.iter().find(|r| r.name == "gp").unwrap();
        assert_eq!(gp.size, 8);
    }

    // 42. MIPS64 DADD
    #[test]
    fn test_dadd() {
        let w = encode_rtype(1, 2, 3, 0, 0x2C);
        let i = arch64le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "dadd");
    }

    // 43. MIPS64 DSLL
    #[test]
    fn test_dsll() {
        let w = encode_rtype(0, 1, 2, 3, 0x38);
        let i = arch64le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "dsll");
    }

    // 44. EXT (SPECIAL3)
    #[test]
    fn test_ext() {
        let w: u32 = (0x1F << 26) | (1 << 21) | (2 << 16) | (4 << 11) | (3 << 6);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "ext");
    }

    // 45. INS (SPECIAL3)
    #[test]
    fn test_ins() {
        let w: u32 = (0x1F << 26) | (1 << 21) | (2 << 16) | (7 << 11) | (3 << 6) | 0x04;
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "ins");
    }

    // 46. SEB
    #[test]
    fn test_seb() {
        let w: u32 = (0x1F << 26) | (2 << 16) | (3 << 11) | (0x10 << 6) | 0x20;
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "seb");
    }

    // 47. SEH
    #[test]
    fn test_seh() {
        let w: u32 = (0x1F << 26) | (2 << 16) | (3 << 11) | (0x18 << 6) | 0x20;
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "seh");
    }

    // 48. WSBH
    #[test]
    fn test_wsbh() {
        let w: u32 = (0x1F << 26) | (2 << 16) | (3 << 11) | (0x02 << 6) | 0x20;
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "wsbh");
    }

    // 49. CLZ (SPECIAL2)
    #[test]
    fn test_clz() {
        let w: u32 = (0x1C << 26) | (1 << 21) | (3 << 11) | 0x20;
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "clz");
    }

    // 50. MUL (SPECIAL2)
    #[test]
    fn test_mul_special2() {
        let w: u32 = (0x1C << 26) | (1 << 21) | (2 << 16) | (3 << 11) | 0x02;
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "mul");
    }

    // 51. BLTZ / BGEZ (REGIMM)
    #[test]
    fn test_bltz_bgez() {
        let a = arch32le();
        assert_eq!(
            a.disassemble(addr(0), &le(encode_itype(0x01, 3, 0x00, 4)))
                .unwrap()
                .mnemonic,
            "bltz"
        );
        assert_eq!(
            a.disassemble(addr(0), &le(encode_itype(0x01, 3, 0x01, 4)))
                .unwrap()
                .mnemonic,
            "bgez"
        );
    }

    // 52. BEQL (branch-likely)
    #[test]
    fn test_beql() {
        let w = encode_itype(0x14, 1, 2, 4);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "beql");
    }

    // 53. Linear disassembler
    #[test]
    fn test_linear_disasm() {
        let ws = [
            encode_rtype(1, 2, 3, 0, 0x20),
            encode_itype(0x23, 2, 1, 4),
            encode_rtype(31, 0, 0, 0, 0x08),
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let arch = arch32le();
        let instrs: Vec<_> = MipsLinearDisassembler::new(&arch, &bytes, addr(0x1000))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs.len(), 3);
        assert_eq!(instrs[0].mnemonic, "add");
        assert_eq!(instrs[1].mnemonic, "lw");
        assert_eq!(instrs[2].mnemonic, "jr");
    }

    // 54. Delay slot tagging
    #[test]
    fn test_delay_slot_tagging() {
        let ws = [
            encode_jtype(0x02, 0x100),
            0u32,
            encode_rtype(1, 2, 3, 0, 0x20),
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let arch = arch32le();
        let instrs: Vec<_> = MipsLinearDisassembler::new(&arch, &bytes, addr(0))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let tags = DelaySlotAnalyzer::tag_delay_slots(&instrs);
        assert!(tags[1], "nop after J must be in delay slot");
        assert!(!tags[2]);
    }

    // 55. LLIL lifter — ADD, LUI, JAL, SYSCALL
    #[test]
    fn test_llil_various() {
        let a = arch32le();
        // ADDU
        let add_i = a
            .disassemble(addr(0), &le(encode_rtype(1, 2, 3, 0, 0x21)))
            .unwrap();
        assert!(matches!(
            lift_to_llil(&add_i)[0],
            LlilOp::Arith {
                op: LlilArithOp::Add,
                ..
            }
        ));
        // LUI
        let lui_i = a.disassemble(addr(0), &le(encode_lui(2, 0x1000))).unwrap();
        assert!(
            matches!(lift_to_llil(&lui_i)[0], LlilOp::SetRegConst { value, .. } if value == 0x1000_0000)
        );
        // JAL
        let jal_i = a.disassemble(addr(0), &le(encode_jal(0x400))).unwrap();
        let jal_ops = lift_to_llil(&jal_i);
        assert!(matches!(jal_ops.last(), Some(LlilOp::Call { .. })));
        // SYSCALL
        let sys_i = a
            .disassemble(addr(0), &le(encode_rtype(0, 0, 0, 0, 0x0C)))
            .unwrap();
        assert_eq!(lift_to_llil(&sys_i)[0], LlilOp::Syscall);
    }
}

// ===========================================================================
// Extended MIPS reference tables and utilities
// ===========================================================================

// ---------------------------------------------------------------------------
// Full MIPS instruction reference table
// ---------------------------------------------------------------------------

/// Static entry describing one MIPS instruction.
#[derive(Debug, Clone, Copy)]
pub struct MipsInstrEntry {
    pub mnemonic: &'static str,
    pub fmt: &'static str,
    pub description: &'static str,
    pub isa: &'static str,
}

/// Complete MIPS instruction reference table (MIPS I through `MIPS64r2`).
pub static MIPS_INSTR_TABLE: &[MipsInstrEntry] = &[
    // ── SPECIAL (opcode=0) ─────────────────────────────────────────────────
    MipsInstrEntry {
        mnemonic: "sll",
        fmt: "rd,rt,sa",
        description: "Shift Word Left Logical",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "movci",
        fmt: "rd,rs,cc",
        description: "Move Conditional on Floating Point Condition",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "srl",
        fmt: "rd,rt,sa",
        description: "Shift Word Right Logical",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "rotr",
        fmt: "rd,rt,sa",
        description: "Rotate Word Right",
        isa: "MIPS32r2",
    },
    MipsInstrEntry {
        mnemonic: "sra",
        fmt: "rd,rt,sa",
        description: "Shift Word Right Arithmetic",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "sllv",
        fmt: "rd,rt,rs",
        description: "Shift Word Left Logical Variable",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "lsa",
        fmt: "rd,rs,rt,sa",
        description: "Load Scaled Address",
        isa: "MIPS32r6",
    },
    MipsInstrEntry {
        mnemonic: "srlv",
        fmt: "rd,rt,rs",
        description: "Shift Word Right Logical Variable",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "rotrv",
        fmt: "rd,rt,rs",
        description: "Rotate Word Right Variable",
        isa: "MIPS32r2",
    },
    MipsInstrEntry {
        mnemonic: "srav",
        fmt: "rd,rt,rs",
        description: "Shift Word Right Arithmetic Variable",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "jr",
        fmt: "rs",
        description: "Jump Register",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "jalr",
        fmt: "rd,rs",
        description: "Jump and Link Register",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "movz",
        fmt: "rd,rs,rt",
        description: "Move Conditional on Zero",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "movn",
        fmt: "rd,rs,rt",
        description: "Move Conditional on Not Zero",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "syscall",
        fmt: "code",
        description: "System Call",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "break",
        fmt: "code",
        description: "Breakpoint",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "sync",
        fmt: "stype",
        description: "Synchronize Shared Memory",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "mfhi",
        fmt: "rd",
        description: "Move From HI Register",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "mthi",
        fmt: "rs",
        description: "Move To HI Register",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "mflo",
        fmt: "rd",
        description: "Move From LO Register",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "mtlo",
        fmt: "rs",
        description: "Move To LO Register",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "dsllv",
        fmt: "rd,rt,rs",
        description: "Doubleword Shift Left Logical Variable",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "dsrlv",
        fmt: "rd,rt,rs",
        description: "Doubleword Shift Right Logical Variable",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "dsrav",
        fmt: "rd,rt,rs",
        description: "Doubleword Shift Right Arithmetic Variable",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "mult",
        fmt: "rs,rt",
        description: "Multiply Word; HI:LO = rs * rt (signed)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "multu",
        fmt: "rs,rt",
        description: "Multiply Word Unsigned; HI:LO = rs * rt",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "div",
        fmt: "rs,rt",
        description: "Divide Word; LO=quotient, HI=remainder",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "divu",
        fmt: "rs,rt",
        description: "Divide Word Unsigned",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "dmult",
        fmt: "rs,rt",
        description: "Doubleword Multiply; HI:LO = rs * rt",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "dmultu",
        fmt: "rs,rt",
        description: "Doubleword Multiply Unsigned",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "ddiv",
        fmt: "rs,rt",
        description: "Doubleword Divide",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "ddivu",
        fmt: "rs,rt",
        description: "Doubleword Divide Unsigned",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "add",
        fmt: "rd,rs,rt",
        description: "Add Word (overflow trap)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "addu",
        fmt: "rd,rs,rt",
        description: "Add Word Unsigned (no overflow trap)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "sub",
        fmt: "rd,rs,rt",
        description: "Subtract Word (overflow trap)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "subu",
        fmt: "rd,rs,rt",
        description: "Subtract Word Unsigned",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "and",
        fmt: "rd,rs,rt",
        description: "AND",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "or",
        fmt: "rd,rs,rt",
        description: "OR",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "xor",
        fmt: "rd,rs,rt",
        description: "Exclusive OR",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "nor",
        fmt: "rd,rs,rt",
        description: "NOR",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "slt",
        fmt: "rd,rs,rt",
        description: "Set on Less Than (signed)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "sltu",
        fmt: "rd,rs,rt",
        description: "Set on Less Than Unsigned",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "dadd",
        fmt: "rd,rs,rt",
        description: "Doubleword Add (overflow trap)",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "daddu",
        fmt: "rd,rs,rt",
        description: "Doubleword Add Unsigned",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "dsub",
        fmt: "rd,rs,rt",
        description: "Doubleword Subtract (overflow trap)",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "dsubu",
        fmt: "rd,rs,rt",
        description: "Doubleword Subtract Unsigned",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "tge",
        fmt: "rs,rt",
        description: "Trap if Greater or Equal (signed)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "tgeu",
        fmt: "rs,rt",
        description: "Trap if Greater or Equal Unsigned",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "tlt",
        fmt: "rs,rt",
        description: "Trap if Less Than (signed)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "tltu",
        fmt: "rs,rt",
        description: "Trap if Less Than Unsigned",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "teq",
        fmt: "rs,rt",
        description: "Trap if Equal",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "tne",
        fmt: "rs,rt",
        description: "Trap if Not Equal",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "dsll",
        fmt: "rd,rt,sa",
        description: "Doubleword Shift Left Logical",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "dsrl",
        fmt: "rd,rt,sa",
        description: "Doubleword Shift Right Logical",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "dsra",
        fmt: "rd,rt,sa",
        description: "Doubleword Shift Right Arithmetic",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "dsll32",
        fmt: "rd,rt,sa",
        description: "Doubleword Shift Left Logical + 32",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "dsrl32",
        fmt: "rd,rt,sa",
        description: "Doubleword Shift Right Logical + 32",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "dsra32",
        fmt: "rd,rt,sa",
        description: "Doubleword Shift Right Arithmetic + 32",
        isa: "MIPS III",
    },
    // ── REGIMM (opcode=1) ──────────────────────────────────────────────────
    MipsInstrEntry {
        mnemonic: "bltz",
        fmt: "rs,offset",
        description: "Branch on Less Than Zero",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "bgez",
        fmt: "rs,offset",
        description: "Branch on Greater Than or Equal to Zero",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "bltzl",
        fmt: "rs,offset",
        description: "Branch on Less Than Zero Likely",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "bgezl",
        fmt: "rs,offset",
        description: "Branch on Greater or Equal to Zero Likely",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "tgei",
        fmt: "rs,imm",
        description: "Trap if Greater or Equal Immediate",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "tgeiu",
        fmt: "rs,imm",
        description: "Trap if Greater or Equal Immediate Unsigned",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "tlti",
        fmt: "rs,imm",
        description: "Trap if Less Than Immediate",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "tltiu",
        fmt: "rs,imm",
        description: "Trap if Less Than Immediate Unsigned",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "teqi",
        fmt: "rs,imm",
        description: "Trap if Equal Immediate",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "tnei",
        fmt: "rs,imm",
        description: "Trap if Not Equal Immediate",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "bltzal",
        fmt: "rs,offset",
        description: "Branch on Less Than Zero and Link",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "bgezal",
        fmt: "rs,offset",
        description: "Branch on Greater or Equal to Zero and Link",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "bltzall",
        fmt: "rs,offset",
        description: "Branch on Less Than Zero and Link Likely",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "bgezall",
        fmt: "rs,offset",
        description: "Branch on Greater or Equal to Zero and Link Likely",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "synci",
        fmt: "offset(rs)",
        description: "Synchronize Caches to Make Instruction Write Effective",
        isa: "MIPS32r2",
    },
    // ── J-type ─────────────────────────────────────────────────────────────
    MipsInstrEntry {
        mnemonic: "j",
        fmt: "target",
        description: "Jump",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "jal",
        fmt: "target",
        description: "Jump and Link",
        isa: "MIPS I",
    },
    // ── I-type branches ────────────────────────────────────────────────────
    MipsInstrEntry {
        mnemonic: "beq",
        fmt: "rs,rt,offset",
        description: "Branch on Equal",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "bne",
        fmt: "rs,rt,offset",
        description: "Branch on Not Equal",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "blez",
        fmt: "rs,offset",
        description: "Branch on Less Than or Equal to Zero",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "bgtz",
        fmt: "rs,offset",
        description: "Branch on Greater Than Zero",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "beql",
        fmt: "rs,rt,offset",
        description: "Branch on Equal Likely",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "bnel",
        fmt: "rs,rt,offset",
        description: "Branch on Not Equal Likely",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "blezl",
        fmt: "rs,offset",
        description: "Branch on Less Than or Equal to Zero Likely",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "bgtzl",
        fmt: "rs,offset",
        description: "Branch on Greater Than Zero Likely",
        isa: "MIPS II",
    },
    // ── Arithmetic immediate ────────────────────────────────────────────────
    MipsInstrEntry {
        mnemonic: "addi",
        fmt: "rt,rs,imm",
        description: "Add Immediate Word (overflow trap)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "addiu",
        fmt: "rt,rs,imm",
        description: "Add Immediate Word Unsigned",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "slti",
        fmt: "rt,rs,imm",
        description: "Set on Less Than Immediate",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "sltiu",
        fmt: "rt,rs,imm",
        description: "Set on Less Than Immediate Unsigned",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "andi",
        fmt: "rt,rs,imm",
        description: "AND Immediate",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "ori",
        fmt: "rt,rs,imm",
        description: "OR Immediate",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "xori",
        fmt: "rt,rs,imm",
        description: "XOR Immediate",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "lui",
        fmt: "rt,imm",
        description: "Load Upper Immediate",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "daddi",
        fmt: "rt,rs,imm",
        description: "Doubleword Add Immediate (overflow trap)",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "daddiu",
        fmt: "rt,rs,imm",
        description: "Doubleword Add Immediate Unsigned",
        isa: "MIPS III",
    },
    // ── Load / store ───────────────────────────────────────────────────────
    MipsInstrEntry {
        mnemonic: "lb",
        fmt: "rt,offset(rs)",
        description: "Load Byte",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "lh",
        fmt: "rt,offset(rs)",
        description: "Load Halfword",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "lwl",
        fmt: "rt,offset(rs)",
        description: "Load Word Left",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "lw",
        fmt: "rt,offset(rs)",
        description: "Load Word",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "lbu",
        fmt: "rt,offset(rs)",
        description: "Load Byte Unsigned",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "lhu",
        fmt: "rt,offset(rs)",
        description: "Load Halfword Unsigned",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "lwr",
        fmt: "rt,offset(rs)",
        description: "Load Word Right",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "lwu",
        fmt: "rt,offset(rs)",
        description: "Load Word Unsigned",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "sb",
        fmt: "rt,offset(rs)",
        description: "Store Byte",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "sh",
        fmt: "rt,offset(rs)",
        description: "Store Halfword",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "swl",
        fmt: "rt,offset(rs)",
        description: "Store Word Left",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "sw",
        fmt: "rt,offset(rs)",
        description: "Store Word",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "sdl",
        fmt: "rt,offset(rs)",
        description: "Store Doubleword Left",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "sdr",
        fmt: "rt,offset(rs)",
        description: "Store Doubleword Right",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "swr",
        fmt: "rt,offset(rs)",
        description: "Store Word Right",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "cache",
        fmt: "op,offset(rs)",
        description: "Perform Cache Operation",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "ll",
        fmt: "rt,offset(rs)",
        description: "Load Linked Word",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "lwc1",
        fmt: "ft,offset(rs)",
        description: "Load Word to Floating Point",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "lwc2",
        fmt: "ct,offset(rs)",
        description: "Load Word to Coprocessor 2",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "pref",
        fmt: "hint,offset(rs)",
        description: "Prefetch",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "lld",
        fmt: "rt,offset(rs)",
        description: "Load Linked Doubleword",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "ldc1",
        fmt: "ft,offset(rs)",
        description: "Load Doubleword to Floating Point",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "ldc2",
        fmt: "ct,offset(rs)",
        description: "Load Doubleword to Coprocessor 2",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "ld",
        fmt: "rt,offset(rs)",
        description: "Load Doubleword",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "sc",
        fmt: "rt,offset(rs)",
        description: "Store Conditional Word",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "swc1",
        fmt: "ft,offset(rs)",
        description: "Store Word from Floating Point",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "swc2",
        fmt: "ct,offset(rs)",
        description: "Store Word from Coprocessor 2",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "scd",
        fmt: "rt,offset(rs)",
        description: "Store Conditional Doubleword",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "sdc1",
        fmt: "ft,offset(rs)",
        description: "Store Doubleword from Floating Point",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "sdc2",
        fmt: "ct,offset(rs)",
        description: "Store Doubleword from Coprocessor 2",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "sd",
        fmt: "rt,offset(rs)",
        description: "Store Doubleword",
        isa: "MIPS III",
    },
    // ── SPECIAL2 ───────────────────────────────────────────────────────────
    MipsInstrEntry {
        mnemonic: "madd",
        fmt: "rs,rt",
        description: "Multiply and Add to HI:LO",
        isa: "MIPS32",
    },
    MipsInstrEntry {
        mnemonic: "maddu",
        fmt: "rs,rt",
        description: "Multiply and Add to HI:LO Unsigned",
        isa: "MIPS32",
    },
    MipsInstrEntry {
        mnemonic: "mul",
        fmt: "rd,rs,rt",
        description: "Multiply Low Word to GPR",
        isa: "MIPS32",
    },
    MipsInstrEntry {
        mnemonic: "msub",
        fmt: "rs,rt",
        description: "Multiply and Subtract from HI:LO",
        isa: "MIPS32",
    },
    MipsInstrEntry {
        mnemonic: "msubu",
        fmt: "rs,rt",
        description: "Multiply and Subtract from HI:LO Unsigned",
        isa: "MIPS32",
    },
    MipsInstrEntry {
        mnemonic: "clz",
        fmt: "rd,rs",
        description: "Count Leading Zeros in Word",
        isa: "MIPS32",
    },
    MipsInstrEntry {
        mnemonic: "clo",
        fmt: "rd,rs",
        description: "Count Leading Ones in Word",
        isa: "MIPS32",
    },
    MipsInstrEntry {
        mnemonic: "dclz",
        fmt: "rd,rs",
        description: "Count Leading Zeros in Doubleword",
        isa: "MIPS64",
    },
    MipsInstrEntry {
        mnemonic: "dclo",
        fmt: "rd,rs",
        description: "Count Leading Ones in Doubleword",
        isa: "MIPS64",
    },
    // ── SPECIAL3 ───────────────────────────────────────────────────────────
    MipsInstrEntry {
        mnemonic: "ext",
        fmt: "rt,rs,pos,sz",
        description: "Extract Bit Field",
        isa: "MIPS32r2",
    },
    MipsInstrEntry {
        mnemonic: "ins",
        fmt: "rt,rs,pos,sz",
        description: "Insert Bit Field",
        isa: "MIPS32r2",
    },
    MipsInstrEntry {
        mnemonic: "wsbh",
        fmt: "rd,rt",
        description: "Word Swap Bytes Within Halfwords",
        isa: "MIPS32r2",
    },
    MipsInstrEntry {
        mnemonic: "seb",
        fmt: "rd,rt",
        description: "Sign-Extend Byte",
        isa: "MIPS32r2",
    },
    MipsInstrEntry {
        mnemonic: "seh",
        fmt: "rd,rt",
        description: "Sign-Extend Halfword",
        isa: "MIPS32r2",
    },
    MipsInstrEntry {
        mnemonic: "rdhwr",
        fmt: "rt,rd",
        description: "Read Hardware Register",
        isa: "MIPS32r2",
    },
    // ── COP0 ───────────────────────────────────────────────────────────────
    MipsInstrEntry {
        mnemonic: "mfc0",
        fmt: "rt,rd",
        description: "Move from Coprocessor 0",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "dmfc0",
        fmt: "rt,rd",
        description: "Doubleword Move from Coprocessor 0",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "mtc0",
        fmt: "rt,rd",
        description: "Move to Coprocessor 0",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "dmtc0",
        fmt: "rt,rd",
        description: "Doubleword Move to Coprocessor 0",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "tlbr",
        fmt: "",
        description: "Read Indexed TLB Entry",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "tlbwi",
        fmt: "",
        description: "Write Indexed TLB Entry",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "tlbwr",
        fmt: "",
        description: "Write Random TLB Entry",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "tlbp",
        fmt: "",
        description: "Probe TLB for Matching Entry",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "eret",
        fmt: "",
        description: "Return from Exception",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "wait",
        fmt: "",
        description: "Enter Standby Mode",
        isa: "MIPS32",
    },
    // ── COP1 (FPU) ─────────────────────────────────────────────────────────
    MipsInstrEntry {
        mnemonic: "mfc1",
        fmt: "rt,fs",
        description: "Move Word from Floating Point",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "dmfc1",
        fmt: "rt,fs",
        description: "Doubleword Move from Floating Point",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "cfc1",
        fmt: "rt,fs",
        description: "Move Control Word from Floating Point",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "mtc1",
        fmt: "rt,fs",
        description: "Move Word to Floating Point",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "dmtc1",
        fmt: "rt,fs",
        description: "Doubleword Move to Floating Point",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "ctc1",
        fmt: "rt,fs",
        description: "Move Control Word to Floating Point",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "bc1f",
        fmt: "cc,offset",
        description: "Branch on FP False",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "bc1t",
        fmt: "cc,offset",
        description: "Branch on FP True",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "bc1fl",
        fmt: "cc,offset",
        description: "Branch on FP False Likely",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "bc1tl",
        fmt: "cc,offset",
        description: "Branch on FP True Likely",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "add.s",
        fmt: "fd,fs,ft",
        description: "Floating Point Add (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "add.d",
        fmt: "fd,fs,ft",
        description: "Floating Point Add (double)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "sub.s",
        fmt: "fd,fs,ft",
        description: "Floating Point Subtract (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "sub.d",
        fmt: "fd,fs,ft",
        description: "Floating Point Subtract (double)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "mul.s",
        fmt: "fd,fs,ft",
        description: "Floating Point Multiply (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "mul.d",
        fmt: "fd,fs,ft",
        description: "Floating Point Multiply (double)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "div.s",
        fmt: "fd,fs,ft",
        description: "Floating Point Divide (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "div.d",
        fmt: "fd,fs,ft",
        description: "Floating Point Divide (double)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "sqrt.s",
        fmt: "fd,fs",
        description: "Floating Point Square Root (single)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "sqrt.d",
        fmt: "fd,fs",
        description: "Floating Point Square Root (double)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "abs.s",
        fmt: "fd,fs",
        description: "Floating Point Absolute Value (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "abs.d",
        fmt: "fd,fs",
        description: "Floating Point Absolute Value (double)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "mov.s",
        fmt: "fd,fs",
        description: "Floating Point Move (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "mov.d",
        fmt: "fd,fs",
        description: "Floating Point Move (double)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "neg.s",
        fmt: "fd,fs",
        description: "Floating Point Negate (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "neg.d",
        fmt: "fd,fs",
        description: "Floating Point Negate (double)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "round.l.s",
        fmt: "fd,fs",
        description: "Floating Point Round to Long Fixed (single)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "round.l.d",
        fmt: "fd,fs",
        description: "Floating Point Round to Long Fixed (double)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "trunc.l.s",
        fmt: "fd,fs",
        description: "Floating Point Truncate to Long Fixed (single)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "trunc.l.d",
        fmt: "fd,fs",
        description: "Floating Point Truncate to Long Fixed (double)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "ceil.l.s",
        fmt: "fd,fs",
        description: "Floating Point Ceiling to Long Fixed (single)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "ceil.l.d",
        fmt: "fd,fs",
        description: "Floating Point Ceiling to Long Fixed (double)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "floor.l.s",
        fmt: "fd,fs",
        description: "Floating Point Floor to Long Fixed (single)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "floor.l.d",
        fmt: "fd,fs",
        description: "Floating Point Floor to Long Fixed (double)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "round.w.s",
        fmt: "fd,fs",
        description: "Floating Point Round to Word Fixed (single)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "round.w.d",
        fmt: "fd,fs",
        description: "Floating Point Round to Word Fixed (double)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "trunc.w.s",
        fmt: "fd,fs",
        description: "Floating Point Truncate to Word (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "trunc.w.d",
        fmt: "fd,fs",
        description: "Floating Point Truncate to Word (double)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "ceil.w.s",
        fmt: "fd,fs",
        description: "Floating Point Ceiling to Word (single)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "ceil.w.d",
        fmt: "fd,fs",
        description: "Floating Point Ceiling to Word (double)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "floor.w.s",
        fmt: "fd,fs",
        description: "Floating Point Floor to Word (single)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "floor.w.d",
        fmt: "fd,fs",
        description: "Floating Point Floor to Word (double)",
        isa: "MIPS II",
    },
    MipsInstrEntry {
        mnemonic: "movf.s",
        fmt: "fd,fs,cc",
        description: "Floating Point Move if FP False (single)",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "movt.s",
        fmt: "fd,fs,cc",
        description: "Floating Point Move if FP True (single)",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "movz.s",
        fmt: "fd,fs,rt",
        description: "Floating Point Move if Zero (single)",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "movn.s",
        fmt: "fd,fs,rt",
        description: "Floating Point Move if Not Zero (single)",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "recip.s",
        fmt: "fd,fs",
        description: "Floating Point Reciprocal (single)",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "rsqrt.s",
        fmt: "fd,fs",
        description: "Floating Point Reciprocal Square Root (single)",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "cvt.s.d",
        fmt: "fd,fs",
        description: "Convert to Single Fixed from Double",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "cvt.s.w",
        fmt: "fd,fs",
        description: "Convert to Single Fixed from Word",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "cvt.d.s",
        fmt: "fd,fs",
        description: "Convert to Double Fixed from Single",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "cvt.d.w",
        fmt: "fd,fs",
        description: "Convert to Double Fixed from Word",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "cvt.w.s",
        fmt: "fd,fs",
        description: "Convert to Word Fixed from Single",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "cvt.w.d",
        fmt: "fd,fs",
        description: "Convert to Word Fixed from Double",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "cvt.l.s",
        fmt: "fd,fs",
        description: "Convert to Long Fixed from Single",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "cvt.l.d",
        fmt: "fd,fs",
        description: "Convert to Long Fixed from Double",
        isa: "MIPS III",
    },
    MipsInstrEntry {
        mnemonic: "c.f.s",
        fmt: "cc,fs,ft",
        description: "FP Compare False (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "c.un.s",
        fmt: "cc,fs,ft",
        description: "FP Compare Unordered (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "c.eq.s",
        fmt: "cc,fs,ft",
        description: "FP Compare Equal (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "c.ueq.s",
        fmt: "cc,fs,ft",
        description: "FP Compare Unordered or Equal (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "c.olt.s",
        fmt: "cc,fs,ft",
        description: "FP Compare Ordered Less Than (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "c.ult.s",
        fmt: "cc,fs,ft",
        description: "FP Compare Unordered or Less Than (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "c.ole.s",
        fmt: "cc,fs,ft",
        description: "FP Compare Ordered Less Than or Equal (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "c.ule.s",
        fmt: "cc,fs,ft",
        description: "FP Compare Unordered or Less Than or Equal (s)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "c.sf.s",
        fmt: "cc,fs,ft",
        description: "FP Compare Signaling False (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "c.ngle.s",
        fmt: "cc,fs,ft",
        description: "FP Compare Not Ordered, Less Than, or Equal (s)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "c.seq.s",
        fmt: "cc,fs,ft",
        description: "FP Compare Signaling Equal (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "c.ngl.s",
        fmt: "cc,fs,ft",
        description: "FP Compare Not Greater Than or Less (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "c.lt.s",
        fmt: "cc,fs,ft",
        description: "FP Compare Less Than (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "c.nge.s",
        fmt: "cc,fs,ft",
        description: "FP Compare Not Greater Than or Equal (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "c.le.s",
        fmt: "cc,fs,ft",
        description: "FP Compare Less Than or Equal (single)",
        isa: "MIPS I",
    },
    MipsInstrEntry {
        mnemonic: "c.ngt.s",
        fmt: "cc,fs,ft",
        description: "FP Compare Not Greater Than (single)",
        isa: "MIPS I",
    },
    // ── COP1X (fused multiply) ─────────────────────────────────────────────
    MipsInstrEntry {
        mnemonic: "lwxc1",
        fmt: "fd,idx(base)",
        description: "Load Word Indexed to Floating Point",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "ldxc1",
        fmt: "fd,idx(base)",
        description: "Load Doubleword Indexed to Floating Point",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "swxc1",
        fmt: "fs,idx(base)",
        description: "Store Word Indexed from Floating Point",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "sdxc1",
        fmt: "fs,idx(base)",
        description: "Store Doubleword Indexed from Floating Point",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "madd.s",
        fmt: "fd,fr,fs,ft",
        description: "Floating Point Multiply Add (single)",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "madd.d",
        fmt: "fd,fr,fs,ft",
        description: "Floating Point Multiply Add (double)",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "msub.s",
        fmt: "fd,fr,fs,ft",
        description: "Floating Point Multiply Subtract (single)",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "msub.d",
        fmt: "fd,fr,fs,ft",
        description: "Floating Point Multiply Subtract (double)",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "nmadd.s",
        fmt: "fd,fr,fs,ft",
        description: "Floating Point Negative Multiply Add (single)",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "nmadd.d",
        fmt: "fd,fr,fs,ft",
        description: "Floating Point Negative Multiply Add (double)",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "nmsub.s",
        fmt: "fd,fr,fs,ft",
        description: "Floating Point Negative Multiply Subtract (s)",
        isa: "MIPS IV",
    },
    MipsInstrEntry {
        mnemonic: "nmsub.d",
        fmt: "fd,fr,fs,ft",
        description: "Floating Point Negative Multiply Subtract (d)",
        isa: "MIPS IV",
    },
];

/// Look up an instruction entry by exact mnemonic.
#[must_use]
pub fn lookup_mips_instr(mnemonic: &str) -> Option<&'static MipsInstrEntry> {
    MIPS_INSTR_TABLE.iter().find(|e| e.mnemonic == mnemonic)
}

// ---------------------------------------------------------------------------
// ABI register roles
// ---------------------------------------------------------------------------

/// Classification of a GPR in the O32/N32/N64 calling conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GprRole {
    /// Always reads as zero; writes are discarded.
    Zero,
    /// Assembler Temporary — volatile, reserved by assembler.
    At,
    /// Function return value.
    ReturnValue,
    /// Function argument (in O32: a0-a3; in N64: a0-a7).
    Argument,
    /// Caller-saved temporary (not preserved across calls).
    Temporary,
    /// Callee-saved register (preserved across calls).
    Saved,
    /// Kernel reserved (k0, k1).
    Kernel,
    /// Global pointer (gp).
    GlobalPointer,
    /// Stack pointer.
    StackPointer,
    /// Frame pointer (sometimes used as s8).
    FramePointer,
    /// Return address.
    ReturnAddress,
}

/// Widen a 5-bit instruction register/field index to `u32`.
///
/// Every caller feeds a value masked to five bits (`0..=31`) or a
/// register constant, so the conversion cannot fail; `unwrap_or` keeps
/// it total instead of panicking on a decoder fed hostile bytes.
#[must_use]
pub fn field_u32(field: usize) -> u32 {
    u32::try_from(field).unwrap_or(u32::MAX)
}

/// Take the low 32 bits of a signed 64-bit value as a `u32`.
///
/// Masking first makes the result provably in range, so this is a
/// reinterpretation of the low word, not a lossy narrowing.
#[must_use]
pub const fn low_u32_of_i64(value: i64) -> u32 {
    // Rebuild the low word from its bytes instead of narrowing with `as`:
    // the four little-endian bytes of `value` ARE its low 32 bits, so this is
    // an exact reinterpretation with no cast and no possible sign loss.
    let b = value.to_le_bytes();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Convert an element count to `f64` without precision loss.
///
/// Counts are saturated at `u32::MAX` first, so the conversion is exact
/// (every `u32` is representable in an `f64`).
#[must_use]
pub fn count_as_f64(count: usize) -> f64 {
    f64::from(u32::try_from(count).unwrap_or(u32::MAX))
}

/// Return the O32 ABI role for a given GPR number.
#[must_use]
pub const fn gpr_role_o32(reg: usize) -> GprRole {
    match reg {
        0 => GprRole::Zero,
        1 => GprRole::At,
        2 | 3 => GprRole::ReturnValue,
        4..=7 => GprRole::Argument,
        16..=23 => GprRole::Saved,
        26 | 27 => GprRole::Kernel,
        28 => GprRole::GlobalPointer,
        29 => GprRole::StackPointer,
        30 => GprRole::FramePointer,
        31 => GprRole::ReturnAddress,
        // Caller-saved temporaries (t0-t9) and any out-of-range index.
        _ => GprRole::Temporary,
    }
}

/// Return the N64 ABI role for a given GPR number.
#[must_use]
pub const fn gpr_role_n64(reg: usize) -> GprRole {
    match reg {
        0 => GprRole::Zero,
        1 => GprRole::At,
        2 | 3 => GprRole::ReturnValue,
        4..=11 => GprRole::Argument,
        16..=23 => GprRole::Saved,
        26 | 27 => GprRole::Kernel,
        28 => GprRole::GlobalPointer,
        29 => GprRole::StackPointer,
        30 => GprRole::FramePointer,
        31 => GprRole::ReturnAddress,
        // Caller-saved temporaries (t0-t9) and any out-of-range index.
        _ => GprRole::Temporary,
    }
}

// ---------------------------------------------------------------------------
// HI:LO pair semantics
// ---------------------------------------------------------------------------

/// Describes what happens to HI and LO for a multiply/divide instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HiLoEffect {
    /// HI:LO = rs * rt (signed)
    MultSigned,
    /// HI:LO = rs * rt (unsigned)
    MultUnsigned,
    /// HI = rs % rt (signed), LO = rs / rt (signed)
    DivSigned,
    /// HI = rs % rt (unsigned), LO = rs / rt (unsigned)
    DivUnsigned,
    /// HI:LO += rs * rt (signed fused multiply-add)
    MaddSigned,
    /// HI:LO += rs * rt (unsigned fused multiply-add)
    MaddUnsigned,
    /// HI:LO -= rs * rt (signed fused multiply-subtract)
    MsubSigned,
    /// HI:LO -= rs * rt (unsigned)
    MsubUnsigned,
    /// None / not applicable.
    None,
}

/// Return the HI:LO effect for a mnemonic.
#[must_use]
pub fn hi_lo_effect(mnemonic: &str) -> HiLoEffect {
    match mnemonic {
        "mult" | "dmult" => HiLoEffect::MultSigned,
        "multu" | "dmultu" => HiLoEffect::MultUnsigned,
        "div" | "ddiv" => HiLoEffect::DivSigned,
        "divu" | "ddivu" => HiLoEffect::DivUnsigned,
        "madd" => HiLoEffect::MaddSigned,
        "maddu" => HiLoEffect::MaddUnsigned,
        "msub" => HiLoEffect::MsubSigned,
        "msubu" => HiLoEffect::MsubUnsigned,
        _ => HiLoEffect::None,
    }
}

// ---------------------------------------------------------------------------
// Disassembly formatter
// ---------------------------------------------------------------------------

/// Options for the text disassembly formatter.
#[derive(Debug, Clone)]
pub struct FormatOptions {
    /// If true, use ABI register names ($a0); otherwise numeric ($4).
    pub use_abi_names: bool,
    /// If true, annotate delay-slot instructions with a comment.
    pub annotate_delay_slots: bool,
    /// If true, show the raw bytes before each instruction.
    pub show_bytes: bool,
    /// Column at which to start the operand field.
    pub operand_column: usize,
}

impl Default for FormatOptions {
    fn default() -> Self {
        Self {
            use_abi_names: true,
            annotate_delay_slots: true,
            show_bytes: false,
            operand_column: 12,
        }
    }
}

/// Format a single instruction as text.
#[must_use]
pub fn format_instruction(
    instr: &Instruction,
    in_delay_slot: bool,
    opts: &FormatOptions,
) -> String {
    let addr = instr.address.0;
    let bytes_str = if opts.show_bytes {
        use std::fmt::Write as _;
        let mut b = String::with_capacity(instr.bytes.len() * 3);
        for (i, x) in instr.bytes.iter().enumerate() {
            if i > 0 {
                b.push(' ');
            }
            let _ = write!(b, "{x:02x}");
        }
        format!("{b:20} ")
    } else {
        String::new()
    };
    let delay_marker = if in_delay_slot && opts.annotate_delay_slots {
        " ; <delay slot>"
    } else {
        ""
    };
    let pad = if instr.mnemonic.len() < opts.operand_column {
        opts.operand_column - instr.mnemonic.len()
    } else {
        1
    };
    format!(
        "{bytes_str}{addr:08x}:  {}{}{}{delay_marker}",
        instr.mnemonic,
        " ".repeat(pad),
        instr.operands
    )
}

/// Format a linear disassembly of `bytes` starting at `base`.
#[must_use]
pub fn format_disassembly(
    arch: &MipsArch,
    bytes: &[u8],
    base: Address,
    opts: &FormatOptions,
) -> String {
    let instrs: Vec<Instruction> = MipsLinearDisassembler::new(arch, bytes, base)
        .filter_map(Result::ok)
        .collect();
    let tags = DelaySlotAnalyzer::tag_delay_slots(&instrs);
    instrs
        .iter()
        .zip(tags.iter())
        .map(|(instr, &in_ds)| format_instruction(instr, in_ds, opts))
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// Prologue / epilogue detection
// ---------------------------------------------------------------------------

/// Identify a standard MIPS O32 function prologue.
///
/// The typical pattern at the very start of a function is:
///  1. `addiu $sp, $sp, -N`   — allocate stack frame
///  2. `sw $ra, X($sp)`       — save return address
///  3. `sw $fp, Y($sp)`       — save frame pointer (optional)
///
/// Returns `Some(frame_size)` if matched, else `None`.
#[must_use]
pub fn detect_mips_prologue(instrs: &[Instruction]) -> Option<i64> {
    if instrs.len() < 2 {
        return None;
    }
    let i0 = &instrs[0];
    if i0.mnemonic != "addiu" {
        return None;
    }
    let parts: Vec<&str> = i0.operands.split(',').map(str::trim).collect();
    if parts.len() < 3 {
        return None;
    }
    if parts[0] != "$sp" || parts[1] != "$sp" {
        return None;
    }
    let frame_size = parts[2].parse::<i64>().ok()?;
    if frame_size >= 0 {
        return None;
    }
    Some(-frame_size)
}

/// Identify a standard MIPS O32 function epilogue.
///
/// Typical pattern:
///  1. `lw $ra, X($sp)`       — restore return address
///  2. `addiu $sp, $sp, N`    — deallocate frame
///  3. `jr $ra`               — return
///  4. (delay slot)
///
/// Returns `true` if the slice looks like an epilogue.
#[must_use]
pub fn detect_mips_epilogue(instrs: &[Instruction]) -> bool {
    let has_lw_ra = instrs
        .iter()
        .any(|i| i.mnemonic == "lw" && i.operands.contains("$ra"));
    let has_jr_ra = instrs
        .iter()
        .any(|i| i.mnemonic == "jr" && i.operands.trim() == "$ra");
    let has_addiu = instrs
        .iter()
        .any(|i| i.mnemonic == "addiu" && i.operands.contains("$sp, $sp"));
    has_lw_ra && has_jr_ra && has_addiu
}

// ---------------------------------------------------------------------------
// MIPS32r2 extension summary
// ---------------------------------------------------------------------------

/// Human-readable description of each `MIPS32r2` addition.
pub static MIPS32R2_EXTENSIONS: &[(&str, &str)] = &[
    ("seb", "Sign-Extend Byte: rd = sign_ext(rt[7:0])"),
    ("seh", "Sign-Extend Halfword: rd = sign_ext(rt[15:0])"),
    (
        "wsbh",
        "Swap bytes within halfwords: reverse byte order in each 16-bit half",
    ),
    ("ext", "Extract Bit Field: rd = rs[pos+sz-1:pos]"),
    ("ins", "Insert Bit Field: rd[pos+sz-1:pos] = rs[sz-1:0]"),
    (
        "rdhwr",
        "Read Hardware Register (user-mode access to select HWREna-gated regs)",
    ),
    ("rotr", "Rotate Right by shamt"),
    ("rotrv", "Rotate Right Variable by rs"),
    (
        "synci",
        "Sync I-cache for instruction writes in the given region",
    ),
];

// ---------------------------------------------------------------------------
// MIPS calling convention cheat-sheet
// ---------------------------------------------------------------------------

/// One entry in the register convention table.
#[derive(Debug, Clone, Copy)]
pub struct MipsRegConvEntry {
    pub number: u8,
    pub abi_name: &'static str,
    pub o32_role: &'static str,
    pub n64_role: &'static str,
    pub preserved: bool,
}

/// Full O32 / N64 register convention table.
pub static MIPS_REG_CONV: &[MipsRegConvEntry] = &[
    MipsRegConvEntry {
        number: 0,
        abi_name: "$zero",
        o32_role: "Constant 0",
        n64_role: "Constant 0",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 1,
        abi_name: "$at",
        o32_role: "Assembler Temp",
        n64_role: "Assembler Temp",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 2,
        abi_name: "$v0",
        o32_role: "Return value",
        n64_role: "Return value",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 3,
        abi_name: "$v1",
        o32_role: "Return value (hi)",
        n64_role: "Return value (hi)",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 4,
        abi_name: "$a0",
        o32_role: "Arg 0",
        n64_role: "Arg 0",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 5,
        abi_name: "$a1",
        o32_role: "Arg 1",
        n64_role: "Arg 1",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 6,
        abi_name: "$a2",
        o32_role: "Arg 2",
        n64_role: "Arg 2",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 7,
        abi_name: "$a3",
        o32_role: "Arg 3",
        n64_role: "Arg 3",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 8,
        abi_name: "$t0",
        o32_role: "Temp",
        n64_role: "Arg 4 (n64)",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 9,
        abi_name: "$t1",
        o32_role: "Temp",
        n64_role: "Arg 5 (n64)",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 10,
        abi_name: "$t2",
        o32_role: "Temp",
        n64_role: "Arg 6 (n64)",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 11,
        abi_name: "$t3",
        o32_role: "Temp",
        n64_role: "Arg 7 (n64)",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 12,
        abi_name: "$t4",
        o32_role: "Temp",
        n64_role: "Temp",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 13,
        abi_name: "$t5",
        o32_role: "Temp",
        n64_role: "Temp",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 14,
        abi_name: "$t6",
        o32_role: "Temp",
        n64_role: "Temp",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 15,
        abi_name: "$t7",
        o32_role: "Temp",
        n64_role: "Temp",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 16,
        abi_name: "$s0",
        o32_role: "Saved",
        n64_role: "Saved",
        preserved: true,
    },
    MipsRegConvEntry {
        number: 17,
        abi_name: "$s1",
        o32_role: "Saved",
        n64_role: "Saved",
        preserved: true,
    },
    MipsRegConvEntry {
        number: 18,
        abi_name: "$s2",
        o32_role: "Saved",
        n64_role: "Saved",
        preserved: true,
    },
    MipsRegConvEntry {
        number: 19,
        abi_name: "$s3",
        o32_role: "Saved",
        n64_role: "Saved",
        preserved: true,
    },
    MipsRegConvEntry {
        number: 20,
        abi_name: "$s4",
        o32_role: "Saved",
        n64_role: "Saved",
        preserved: true,
    },
    MipsRegConvEntry {
        number: 21,
        abi_name: "$s5",
        o32_role: "Saved",
        n64_role: "Saved",
        preserved: true,
    },
    MipsRegConvEntry {
        number: 22,
        abi_name: "$s6",
        o32_role: "Saved",
        n64_role: "Saved",
        preserved: true,
    },
    MipsRegConvEntry {
        number: 23,
        abi_name: "$s7",
        o32_role: "Saved",
        n64_role: "Saved",
        preserved: true,
    },
    MipsRegConvEntry {
        number: 24,
        abi_name: "$t8",
        o32_role: "Temp",
        n64_role: "Temp",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 25,
        abi_name: "$t9",
        o32_role: "Temp / PIC fn ptr",
        n64_role: "Temp / PIC fn ptr",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 26,
        abi_name: "$k0",
        o32_role: "Kernel reserved",
        n64_role: "Kernel reserved",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 27,
        abi_name: "$k1",
        o32_role: "Kernel reserved",
        n64_role: "Kernel reserved",
        preserved: false,
    },
    MipsRegConvEntry {
        number: 28,
        abi_name: "$gp",
        o32_role: "Global pointer",
        n64_role: "Global pointer",
        preserved: true,
    },
    MipsRegConvEntry {
        number: 29,
        abi_name: "$sp",
        o32_role: "Stack pointer",
        n64_role: "Stack pointer",
        preserved: true,
    },
    MipsRegConvEntry {
        number: 30,
        abi_name: "$fp",
        o32_role: "Frame pointer / s8",
        n64_role: "Frame pointer / s8",
        preserved: true,
    },
    MipsRegConvEntry {
        number: 31,
        abi_name: "$ra",
        o32_role: "Return address",
        n64_role: "Return address",
        preserved: false,
    },
];

// ---------------------------------------------------------------------------
// FPU register conventions
// ---------------------------------------------------------------------------

/// FPU register convention entry.
#[derive(Debug, Clone, Copy)]
pub struct FprConvEntry {
    pub number: u8,
    pub name: &'static str,
    pub o32_role: &'static str,
    pub preserved: bool,
}

pub static FPR_CONV: &[FprConvEntry] = &[
    FprConvEntry {
        number: 0,
        name: "$f0",
        o32_role: "FP return value",
        preserved: false,
    },
    FprConvEntry {
        number: 1,
        name: "$f1",
        o32_role: "FP return value (pair)",
        preserved: false,
    },
    FprConvEntry {
        number: 2,
        name: "$f2",
        o32_role: "FP return value 2",
        preserved: false,
    },
    FprConvEntry {
        number: 3,
        name: "$f3",
        o32_role: "FP return value 2 (pair)",
        preserved: false,
    },
    FprConvEntry {
        number: 4,
        name: "$f4",
        o32_role: "FP temp",
        preserved: false,
    },
    FprConvEntry {
        number: 5,
        name: "$f5",
        o32_role: "FP temp",
        preserved: false,
    },
    FprConvEntry {
        number: 6,
        name: "$f6",
        o32_role: "FP temp",
        preserved: false,
    },
    FprConvEntry {
        number: 7,
        name: "$f7",
        o32_role: "FP temp",
        preserved: false,
    },
    FprConvEntry {
        number: 8,
        name: "$f8",
        o32_role: "FP temp",
        preserved: false,
    },
    FprConvEntry {
        number: 9,
        name: "$f9",
        o32_role: "FP temp",
        preserved: false,
    },
    FprConvEntry {
        number: 10,
        name: "$f10",
        o32_role: "FP temp",
        preserved: false,
    },
    FprConvEntry {
        number: 11,
        name: "$f11",
        o32_role: "FP temp",
        preserved: false,
    },
    FprConvEntry {
        number: 12,
        name: "$f12",
        o32_role: "FP arg 0",
        preserved: false,
    },
    FprConvEntry {
        number: 13,
        name: "$f13",
        o32_role: "FP arg 0 (pair)",
        preserved: false,
    },
    FprConvEntry {
        number: 14,
        name: "$f14",
        o32_role: "FP arg 1",
        preserved: false,
    },
    FprConvEntry {
        number: 15,
        name: "$f15",
        o32_role: "FP arg 1 (pair)",
        preserved: false,
    },
    FprConvEntry {
        number: 16,
        name: "$f16",
        o32_role: "FP temp",
        preserved: false,
    },
    FprConvEntry {
        number: 17,
        name: "$f17",
        o32_role: "FP temp",
        preserved: false,
    },
    FprConvEntry {
        number: 18,
        name: "$f18",
        o32_role: "FP saved",
        preserved: true,
    },
    FprConvEntry {
        number: 19,
        name: "$f19",
        o32_role: "FP saved (pair)",
        preserved: true,
    },
    FprConvEntry {
        number: 20,
        name: "$f20",
        o32_role: "FP saved",
        preserved: true,
    },
    FprConvEntry {
        number: 21,
        name: "$f21",
        o32_role: "FP saved (pair)",
        preserved: true,
    },
    FprConvEntry {
        number: 22,
        name: "$f22",
        o32_role: "FP saved",
        preserved: true,
    },
    FprConvEntry {
        number: 23,
        name: "$f23",
        o32_role: "FP saved (pair)",
        preserved: true,
    },
    FprConvEntry {
        number: 24,
        name: "$f24",
        o32_role: "FP saved",
        preserved: true,
    },
    FprConvEntry {
        number: 25,
        name: "$f25",
        o32_role: "FP saved (pair)",
        preserved: true,
    },
    FprConvEntry {
        number: 26,
        name: "$f26",
        o32_role: "FP saved",
        preserved: true,
    },
    FprConvEntry {
        number: 27,
        name: "$f27",
        o32_role: "FP saved (pair)",
        preserved: true,
    },
    FprConvEntry {
        number: 28,
        name: "$f28",
        o32_role: "FP saved",
        preserved: true,
    },
    FprConvEntry {
        number: 29,
        name: "$f29",
        o32_role: "FP saved (pair)",
        preserved: true,
    },
    FprConvEntry {
        number: 30,
        name: "$f30",
        o32_role: "FP saved",
        preserved: true,
    },
    FprConvEntry {
        number: 31,
        name: "$f31",
        o32_role: "FP saved (pair)",
        preserved: true,
    },
];

// ---------------------------------------------------------------------------
// Exception vector table
// ---------------------------------------------------------------------------

/// A MIPS exception vector entry.
#[derive(Debug, Clone, Copy)]
pub struct ExcVectorEntry {
    pub offset: u32,
    pub name: &'static str,
    pub description: &'static str,
}

/// MIPS exception vector offsets (relative to vector base = $Status.BEV).
pub static MIPS_EXC_VECTORS: &[ExcVectorEntry] = &[
    ExcVectorEntry {
        offset: 0x000,
        name: "Reset/NMI",
        description: "Reset or Non-Maskable Interrupt",
    },
    ExcVectorEntry {
        offset: 0x100,
        name: "TLBRefill",
        description: "TLB Refill exception (BEV=0)",
    },
    ExcVectorEntry {
        offset: 0x180,
        name: "General",
        description: "General exception vector",
    },
    ExcVectorEntry {
        offset: 0x200,
        name: "Interrupt",
        description: "Interrupt vector (VIntPriorityMask)",
    },
    ExcVectorEntry {
        offset: 0x280,
        name: "TLBRefillBEV",
        description: "TLB Refill exception (BEV=1)",
    },
    ExcVectorEntry {
        offset: 0x380,
        name: "GeneralBEV",
        description: "General exception vector (BEV=1)",
    },
];

// ---------------------------------------------------------------------------
// Pseudo-instruction expansion
// ---------------------------------------------------------------------------

/// A MIPS pseudo-instruction description.
#[derive(Debug, Clone)]
pub struct PseudoInstr {
    pub name: &'static str,
    pub operands: &'static str,
    pub expansion: &'static str,
}

/// Common MIPS assembler pseudo-instructions.
pub static MIPS_PSEUDOS: &[PseudoInstr] = &[
    PseudoInstr {
        name: "nop",
        operands: "",
        expansion: "sll $zero,$zero,0",
    },
    PseudoInstr {
        name: "move",
        operands: "rd,rs",
        expansion: "addu rd,$zero,rs",
    },
    PseudoInstr {
        name: "li",
        operands: "rt,imm",
        expansion: "lui rt,imm[31:16]; ori rt,rt,imm[15:0]",
    },
    PseudoInstr {
        name: "la",
        operands: "rt,sym",
        expansion: "lui rt,%hi(sym); addiu rt,rt,%lo(sym)",
    },
    PseudoInstr {
        name: "b",
        operands: "offset",
        expansion: "beq $zero,$zero,offset",
    },
    PseudoInstr {
        name: "bal",
        operands: "offset",
        expansion: "bgezal $zero,offset",
    },
    PseudoInstr {
        name: "bnez",
        operands: "rs,off",
        expansion: "bne rs,$zero,off",
    },
    PseudoInstr {
        name: "beqz",
        operands: "rs,off",
        expansion: "beq rs,$zero,off",
    },
    PseudoInstr {
        name: "not",
        operands: "rd,rs",
        expansion: "nor rd,rs,$zero",
    },
    PseudoInstr {
        name: "neg",
        operands: "rd,rs",
        expansion: "sub rd,$zero,rs",
    },
    PseudoInstr {
        name: "negu",
        operands: "rd,rs",
        expansion: "subu rd,$zero,rs",
    },
    PseudoInstr {
        name: "abs",
        operands: "rd,rs",
        expansion: "bgez rs,+8; sub rd,$zero,rs; or rd,rs,$zero",
    },
    PseudoInstr {
        name: "sge",
        operands: "rd,rs,rt",
        expansion: "slt rd,rs,rt; xori rd,rd,1",
    },
    PseudoInstr {
        name: "sgeu",
        operands: "rd,rs,rt",
        expansion: "sltu rd,rs,rt; xori rd,rd,1",
    },
    PseudoInstr {
        name: "sgt",
        operands: "rd,rs,rt",
        expansion: "slt rd,rt,rs",
    },
    PseudoInstr {
        name: "sgtu",
        operands: "rd,rs,rt",
        expansion: "sltu rd,rt,rs",
    },
    PseudoInstr {
        name: "sle",
        operands: "rd,rs,rt",
        expansion: "slt rd,rt,rs; xori rd,rd,1",
    },
    PseudoInstr {
        name: "sleu",
        operands: "rd,rs,rt",
        expansion: "sltu rd,rt,rs; xori rd,rd,1",
    },
    PseudoInstr {
        name: "rol",
        operands: "rd,rs,rt",
        expansion: "subu $at,$zero,rt; srlv $at,rs,$at; sllv rd,rs,rt; or rd,rd,$at",
    },
    PseudoInstr {
        name: "ror",
        operands: "rd,rs,rt",
        expansion: "subu $at,$zero,rt; sllv $at,rs,$at; srlv rd,rs,rt; or rd,rd,$at",
    },
    PseudoInstr {
        name: "dabs",
        operands: "rd,rs",
        expansion: "bgez rs,+8; dsub rd,$zero,rs; or rd,rs,$zero",
    },
    PseudoInstr {
        name: "dneg",
        operands: "rd,rs",
        expansion: "dsub rd,$zero,rs",
    },
    PseudoInstr {
        name: "dnegu",
        operands: "rd,rs",
        expansion: "dsubu rd,$zero,rs",
    },
    PseudoInstr {
        name: "dmove",
        operands: "rd,rs",
        expansion: "daddu rd,$zero,rs",
    },
];

// ---------------------------------------------------------------------------
// Cache operation table (CACHE instruction hint field)
// ---------------------------------------------------------------------------

/// A CACHE instruction hint entry.
#[derive(Debug, Clone, Copy)]
pub struct CacheHint {
    pub code: u8,
    pub name: &'static str,
    pub description: &'static str,
}

pub static CACHE_HINTS: &[CacheHint] = &[
    CacheHint {
        code: 0,
        name: "Index_Invalidate",
        description: "Invalidate primary I-cache line at index",
    },
    CacheHint {
        code: 1,
        name: "Index_WB_Invalidate",
        description: "Write-back and invalidate primary D-cache at index",
    },
    CacheHint {
        code: 3,
        name: "Index_StoreTag",
        description: "Store tag at index",
    },
    CacheHint {
        code: 4,
        name: "Index_LoadTag",
        description: "Load tag at index",
    },
    CacheHint {
        code: 5,
        name: "Index_WriteBack",
        description: "Write back D-cache line at index",
    },
    CacheHint {
        code: 8,
        name: "Hit_Invalidate",
        description: "Invalidate if hit in primary I-cache",
    },
    CacheHint {
        code: 9,
        name: "Hit_Writeback_Invalidate",
        description: "Write-back and invalidate if hit in primary D-cache",
    },
    CacheHint {
        code: 11,
        name: "Hit_WriteBack",
        description: "Write back D-cache line if hit",
    },
    CacheHint {
        code: 12,
        name: "Hit_Set_Virtual",
        description: "Set virtual alias in primary D-cache",
    },
    CacheHint {
        code: 13,
        name: "Fill",
        description: "Fill primary I-cache from memory",
    },
    CacheHint {
        code: 16,
        name: "Index_Invalidate_SI",
        description: "Invalidate secondary I-cache at index",
    },
    CacheHint {
        code: 17,
        name: "Index_WB_Invalidate_SD",
        description: "Write-back and invalidate secondary D-cache at index",
    },
    CacheHint {
        code: 20,
        name: "Index_LoadTag_S",
        description: "Load tag at secondary cache index",
    },
    CacheHint {
        code: 24,
        name: "Hit_Invalidate_SI",
        description: "Invalidate if hit in secondary I-cache",
    },
    CacheHint {
        code: 25,
        name: "Hit_Writeback_Invalidate_SD",
        description: "Write-back and invalidate if hit in secondary D-cache",
    },
    CacheHint {
        code: 27,
        name: "Hit_WriteBack_SD",
        description: "Write back secondary D-cache line if hit",
    },
];

// ---------------------------------------------------------------------------
// Extended tests — additional coverage
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests_extended {
    use super::*;

    fn le(word: u32) -> [u8; 4] {
        word.to_le_bytes()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }
    fn arch32le() -> MipsArch {
        MipsArch::mips32_le()
    }
    fn arch64le() -> MipsArch {
        MipsArch::mips64_le()
    }

    // ── MIPS32r2 — ROTR ─────────────────────────────────────────────────────
    #[test]
    fn test_rotr() {
        // rs=1 signals ROTR
        let w = (1u32 << 21) | (1 << 16) | (2 << 11) | (4 << 6) | 0x02;
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "rotr");
    }

    // ── DMULT ────────────────────────────────────────────────────────────────
    #[test]
    fn test_dmult() {
        let w = encode_rtype(2, 3, 0, 0, 0x1C);
        let i = arch64le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "dmult");
    }

    // ── DDIV ─────────────────────────────────────────────────────────────────
    #[test]
    fn test_ddiv() {
        let w = encode_rtype(4, 5, 0, 0, 0x1E);
        let i = arch64le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "ddiv");
    }

    // ── instr reference table has ADD ────────────────────────────────────────
    #[test]
    fn test_instr_table_lookup() {
        let entry = lookup_mips_instr("add").unwrap();
        assert_eq!(entry.isa, "MIPS I");
        assert!(entry.description.contains("overflow"));
    }

    // ── instr table has madd.d ───────────────────────────────────────────────
    #[test]
    fn test_instr_table_madd_d() {
        let entry = lookup_mips_instr("madd.d").unwrap();
        assert!(entry.description.contains("Multiply Add"));
    }

    // ── gpr_role_o32 ─────────────────────────────────────────────────────────
    #[test]
    fn test_gpr_role_o32() {
        assert_eq!(gpr_role_o32(0), GprRole::Zero);
        assert_eq!(gpr_role_o32(4), GprRole::Argument);
        assert_eq!(gpr_role_o32(16), GprRole::Saved);
        assert_eq!(gpr_role_o32(29), GprRole::StackPointer);
        assert_eq!(gpr_role_o32(31), GprRole::ReturnAddress);
    }

    // ── gpr_role_n64 ─────────────────────────────────────────────────────────
    #[test]
    fn test_gpr_role_n64() {
        assert_eq!(gpr_role_n64(8), GprRole::Argument);
        assert_eq!(gpr_role_n64(11), GprRole::Argument);
        assert_eq!(gpr_role_n64(12), GprRole::Temporary);
    }

    // ── hi_lo_effect ─────────────────────────────────────────────────────────
    #[test]
    fn test_hi_lo_effect() {
        assert_eq!(hi_lo_effect("mult"), HiLoEffect::MultSigned);
        assert_eq!(hi_lo_effect("divu"), HiLoEffect::DivUnsigned);
        assert_eq!(hi_lo_effect("madd"), HiLoEffect::MaddSigned);
        assert_eq!(hi_lo_effect("msub"), HiLoEffect::MsubSigned);
        assert_eq!(hi_lo_effect("add"), HiLoEffect::None);
    }

    // ── format_instruction ───────────────────────────────────────────────────
    #[test]
    fn test_format_instruction() {
        let arch = arch32le();
        let w = encode_rtype(1, 2, 3, 0, 0x20);
        let i = arch.disassemble(addr(0x1000), &le(w)).unwrap();
        let opts = FormatOptions::default();
        let s = format_instruction(&i, false, &opts);
        assert!(s.contains("1000"));
        assert!(s.contains("add"));
    }

    // ── detect_mips_prologue ──────────────────────────────────────────────────
    #[test]
    fn test_detect_prologue() {
        // addiu $sp,$sp,-32 then sw $ra,28($sp)
        let ws = [
            encode_itype(0x09, 29, 29, (-32i16).cast_unsigned()), // addiu $sp,$sp,-32
            encode_itype(0x2B, 29, 31, 28u16),           // sw $ra,28($sp)
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let arch = arch32le();
        let instrs: Vec<_> = MipsLinearDisassembler::new(&arch, &bytes, addr(0x1000))
            .filter_map(Result::ok)
            .collect();
        let sz = detect_mips_prologue(&instrs);
        assert_eq!(sz, Some(32));
    }

    // ── detect_mips_epilogue ──────────────────────────────────────────────────
    #[test]
    fn test_detect_epilogue() {
        let ws = [
            encode_itype(0x23, 29, 31, 28u16), // lw $ra,28($sp)
            encode_itype(0x09, 29, 29, 32u16), // addiu $sp,$sp,32
            encode_rtype(31, 0, 0, 0, 0x08),   // jr $ra
            0u32,                              // nop (delay slot)
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let arch = arch32le();
        let instrs: Vec<_> = MipsLinearDisassembler::new(&arch, &bytes, addr(0x1000))
            .filter_map(Result::ok)
            .collect();
        assert!(detect_mips_epilogue(&instrs));
    }

    // ── MIPS_REG_CONV table completeness ─────────────────────────────────────
    #[test]
    fn test_reg_conv_table() {
        assert_eq!(MIPS_REG_CONV.len(), 32);
        assert_eq!(MIPS_REG_CONV[0].abi_name, "$zero");
        assert_eq!(MIPS_REG_CONV[31].abi_name, "$ra");
        assert!(MIPS_REG_CONV[16].preserved); // $s0
    }

    // ── FPR_CONV table ───────────────────────────────────────────────────────
    #[test]
    fn test_fpr_conv_table() {
        assert_eq!(FPR_CONV.len(), 32);
        assert!(!FPR_CONV[0].preserved); // $f0 not preserved
        assert!(FPR_CONV[18].preserved); // $f18 preserved
    }

    // ── COP1 add.s decoding ──────────────────────────────────────────────────
    #[test]
    fn test_cop1_add_s() {
        // COP1, fmt=S(0x10), ft=1, fs=2, fd=3, funct=0x00 (add)
        let w: u32 = (0x11 << 26) | (0x10 << 21) | (1 << 16) | (2 << 11) | (3 << 6);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "add.s");
    }

    // ── COP1 mul.d decoding ──────────────────────────────────────────────────
    #[test]
    fn test_cop1_mul_d() {
        let w: u32 = (0x11 << 26) | (0x11 << 21) | (1 << 16) | (2 << 11) | (3 << 6) | 0x02;
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "mul.d");
    }

    // ── COP1 cvt.w.s decoding ────────────────────────────────────────────────
    #[test]
    fn test_cop1_cvt_w_s() {
        let w: u32 = (0x11 << 26) | (0x10 << 21) | (2 << 11) | (3 << 6) | 0x24;
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "cvt.w.s");
    }

    // ── COP1 c.lt.d decoding ─────────────────────────────────────────────────
    #[test]
    fn test_cop1_c_lt_d() {
        // funct = 0x3C (0x30 | 0xC = cond=12=lt)
        let w: u32 = (0x11 << 26) | (0x11 << 21) | (1 << 16) | (2 << 11) | (3 << 6) | 0x3C;
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "c.lt.d");
    }

    // ── BC1T decoding ────────────────────────────────────────────────────────
    #[test]
    fn test_bc1t() {
        // COP1, fmt=8 (BC1), tf=1 (True), nd=0, cc=0, offset=4
        let w: u32 = (0x11 << 26) | (0x08 << 21) | (1 << 16) | 4;
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "bc1t");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    // ── MFC1 / MTC1 ──────────────────────────────────────────────────────────
    #[test]
    fn test_mfc1_mtc1() {
        // MFC1 rt=2, fs=4: COP1, fmt=0, ft=2, fs=4
        let mfc1: u32 = (0x11 << 26) | (2 << 16) | (4 << 11);
        let i = arch32le().disassemble(addr(0), &le(mfc1)).unwrap();
        assert_eq!(i.mnemonic, "mfc1");
        // MTC1: fmt=4
        let word_move_to_cop1: u32 = (0x11 << 26) | (0x04 << 21) | (2 << 16) | (4 << 11);
        let j = arch32le().disassemble(addr(0), &le(word_move_to_cop1)).unwrap();
        assert_eq!(j.mnemonic, "mtc1");
    }

    // ── COP1X lwxc1 / madd.s ─────────────────────────────────────────────────
    #[test]
    fn test_cop1x_lwxc1() {
        // COP1X, base=2, idx=3, fd=4, funct=0x00
        let w: u32 = (0x13 << 26) | (2 << 21) | (3 << 16) | (4 << 6);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "lwxc1");
    }

    // ── DSLL32 ───────────────────────────────────────────────────────────────
    #[test]
    fn test_dsll32() {
        let w = encode_rtype(0, 1, 2, 5, 0x3C);
        let i = arch64le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "dsll32");
    }

    // ── MTHI / MTLO ──────────────────────────────────────────────────────────
    #[test]
    fn test_mthi_mtlo() {
        let a = arch32le();
        let mthi = encode_rtype(3, 0, 0, 0, 0x11);
        let mtlo = encode_rtype(3, 0, 0, 0, 0x13);
        assert_eq!(a.disassemble(addr(0), &le(mthi)).unwrap().mnemonic, "mthi");
        assert_eq!(a.disassemble(addr(0), &le(mtlo)).unwrap().mnemonic, "mtlo");
    }

    // ── ERET (COP0) ───────────────────────────────────────────────────────────
    #[test]
    fn test_eret() {
        let w: u32 = (0x10 << 26) | (0x10 << 21) | 0x18;
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "eret");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    // ── TLBWI / TLBWR ─────────────────────────────────────────────────────────
    #[test]
    fn test_tlb_ops() {
        let a = arch32le();
        let tlbwi: u32 = (0x10 << 26) | (0x10 << 21) | 0x02;
        let word_tlb_write_random: u32 = (0x10 << 26) | (0x10 << 21) | 0x06;
        assert_eq!(
            a.disassemble(addr(0), &le(tlbwi)).unwrap().mnemonic,
            "tlbwi"
        );
        assert_eq!(
            a.disassemble(addr(0), &le(word_tlb_write_random)).unwrap().mnemonic,
            "tlbwr"
        );
    }

    // ── LD / SD ───────────────────────────────────────────────────────────────
    #[test]
    fn test_ld_sd() {
        let a = arch64le();
        let ld = encode_itype(0x37, 4, 5, 8);
        let sd = encode_itype(0x3F, 4, 5, 8);
        assert_eq!(a.disassemble(addr(0), &le(ld)).unwrap().mnemonic, "ld");
        assert_eq!(a.disassemble(addr(0), &le(sd)).unwrap().mnemonic, "sd");
        assert!(
            a.disassemble(addr(0), &le(ld))
                .unwrap()
                .flags
                .contains(InstrFlags::READ_MEM)
        );
        assert!(
            a.disassemble(addr(0), &le(sd))
                .unwrap()
                .flags
                .contains(InstrFlags::WRITE_MEM)
        );
    }

    // ── LL / SC ───────────────────────────────────────────────────────────────
    #[test]
    fn test_ll_sc() {
        let a = arch32le();
        let ll = encode_itype(0x30, 4, 5, 0);
        let sc = encode_itype(0x38, 4, 5, 0);
        assert_eq!(a.disassemble(addr(0), &le(ll)).unwrap().mnemonic, "ll");
        assert_eq!(a.disassemble(addr(0), &le(sc)).unwrap().mnemonic, "sc");
    }

    // ── CACHE hint ────────────────────────────────────────────────────────────
    #[test]
    fn test_cache_instr() {
        let w = encode_itype(0x2F, 4, 1, 0); // CACHE op=1, base=4, offset=0
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "cache");
    }

    // ── PREF ─────────────────────────────────────────────────────────────────
    #[test]
    fn test_pref() {
        let w = encode_itype(0x33, 4, 1, 0);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "pref");
    }

    // ── SYNC ─────────────────────────────────────────────────────────────────
    #[test]
    fn test_sync() {
        let w = encode_rtype(0, 0, 0, 0, 0x0F);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "sync");
    }

    // ── code stats from mixed sequence ───────────────────────────────────────
    #[test]
    fn test_code_stats_mixed() {
        let ws = [
            encode_itype(0x23, 2, 1, 4),    // lw
            encode_itype(0x2B, 2, 1, 4),    // sw
            encode_rtype(1, 2, 3, 0, 0x20), // add
            encode_rtype(2, 3, 0, 0, 0x18), // mult
            encode_jtype(0x03, 0x400),      // jal
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let s = MipsCodeStats::from_bytes(&arch32le(), &bytes, addr(0));
        assert_eq!(s.loads, 1);
        assert_eq!(s.stores, 1);
        assert_eq!(s.alu, 1);
        assert_eq!(s.mul_div, 1);
        assert_eq!(s.calls, 1);
    }

    // ── LLIL BEQ ─────────────────────────────────────────────────────────────
    #[test]
    fn test_llil_beq() {
        let w = encode_itype(0x04, 1, 2, 4u16);
        let i = arch32le().disassemble(addr(0x1000), &le(w)).unwrap();
        let ops = lift_to_llil(&i);
        assert!(matches!(
            ops[0],
            LlilOp::CondJump {
                cond: LlilCond::Eq(..),
                ..
            }
        ));
    }

    // ── LLIL BNE ─────────────────────────────────────────────────────────────
    #[test]
    fn test_llil_bne() {
        let w = encode_itype(0x05, 1, 2, 4u16);
        let i = arch32le().disassemble(addr(0x1000), &le(w)).unwrap();
        let ops = lift_to_llil(&i);
        assert!(matches!(
            ops[0],
            LlilOp::CondJump {
                cond: LlilCond::Ne(..),
                ..
            }
        ));
    }

    // ── LLIL LW ──────────────────────────────────────────────────────────────
    #[test]
    fn test_llil_lw() {
        let w = encode_lw(3, 29, 16);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        let ops = lift_to_llil(&i);
        assert!(matches!(ops[0], LlilOp::Load { size: 4, .. }));
    }

    // ── LLIL SW ──────────────────────────────────────────────────────────────
    #[test]
    fn test_llil_sw() {
        let w = encode_sw(3, 29, 16);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        let ops = lift_to_llil(&i);
        assert!(matches!(ops[0], LlilOp::Store { size: 4, .. }));
    }

    // ── LLIL JR $ra → Ret ────────────────────────────────────────────────────
    #[test]
    fn test_llil_ret() {
        let w = encode_jr(31);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        let ops = lift_to_llil(&i);
        assert_eq!(ops[0], LlilOp::Ret);
    }

    // ── LLIL ORI ─────────────────────────────────────────────────────────────
    #[test]
    fn test_llil_ori() {
        let w = encode_itype(0x0D, 0, 2, 0x100);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        let ops = lift_to_llil(&i);
        assert!(matches!(
            ops[0],
            LlilOp::ArithConst {
                op: LlilArithOp::Or,
                ..
            }
        ));
    }
}

// ===========================================================================
// Function signature analysis
// ===========================================================================

/// Inferred function signature from a basic block analysis.
#[derive(Debug, Clone, Default)]
pub struct InferredSignature {
    /// Registers read before being written (likely arguments).
    pub arg_regs: Vec<String>,
    /// Registers written that are caller-saved (likely return value).
    pub ret_regs: Vec<String>,
    /// Registers saved and restored (likely saved registers).
    pub saved_regs: Vec<String>,
    /// Estimated stack frame size in bytes.
    pub frame_size: i64,
}

/// Heuristic: infer argument and return registers from an instruction sequence.
/// Looks at the first few instructions to find registers read without prior
/// definition (treating them as argument registers).
#[must_use]
pub fn infer_signature(arch: &MipsArch, bytes: &[u8], base: Address) -> InferredSignature {
    let mut sig = InferredSignature::default();
    let mut defined = std::collections::HashSet::<String>::new();
    let mut read = std::collections::HashSet::<String>::new();

    // Seed: $zero is always defined
    defined.insert("$zero".to_string());

    let instrs: Vec<Instruction> = MipsLinearDisassembler::new(arch, bytes, base)
        .filter_map(Result::ok)
        .take(64) // examine up to 64 instructions
        .collect();

    for instr in &instrs {
        let parts: Vec<&str> = instr.operands.split(',').map(str::trim).collect();
        let m = instr.mnemonic.as_str();

        // Identify prologue: addiu $sp,$sp,-N
        if m == "addiu" && parts.len() >= 3 && parts[0] == "$sp" && parts[1] == "$sp" {
            if let Ok(n) = parts[2].parse::<i64>()
                && n < 0
            {
                sig.frame_size = -n;
            }
            defined.insert("$sp".to_string());
            continue;
        }

        // For most instructions the first operand is the destination.
        match m {
            "add" | "addu" | "sub" | "subu" | "and" | "or" | "xor" | "nor" | "slt" | "sltu"
            | "sll" | "srl" | "sra" | "sllv" | "srlv" | "srav" | "movz" | "movn" => {
                if parts.len() >= 3 {
                    for src in &parts[1..] {
                        let s = src.trim().to_string();
                        if s.starts_with('$') && !defined.contains(&s) {
                            read.insert(s.clone());
                        }
                    }
                    if let Some(dst) = parts.first() {
                        defined.insert(dst.trim().to_string());
                    }
                }
            }
            "addi" | "addiu" | "andi" | "ori" | "xori" | "slti" | "sltiu" | "lui" => {
                if parts.len() >= 2 {
                    let sub_joined = parts[1..].join(",");
                    let sub: Vec<&str> = sub_joined.split(',').map(str::trim).collect::<Vec<_>>();
                    if !sub.is_empty() {
                        let src = sub[0].trim().to_string();
                        if src.starts_with('$') && !defined.contains(&src) {
                            read.insert(src);
                        }
                    }
                    if let Some(dst) = parts.first() {
                        defined.insert(dst.trim().to_string());
                    }
                }
            }
            "lw" | "lh" | "lb" | "lhu" | "lbu" | "lwu" | "ld" => {
                if let Some((dst, base_reg, _)) = parse_mem_operand(&instr.operands) {
                    if !defined.contains(&base_reg) {
                        read.insert(base_reg);
                    }
                    defined.insert(dst);
                }
            }
            "sw" | "sh" | "sb" | "sd" => {
                if let Some((src, base_reg, _)) = parse_mem_operand(&instr.operands) {
                    if !defined.contains(&src) {
                        read.insert(src);
                    }
                    if !defined.contains(&base_reg) {
                        read.insert(base_reg.clone());
                    }
                }
            }
            _ => {}
        }
    }

    // O32: argument regs are a0-a3
    let o32_args = ["$a0", "$a1", "$a2", "$a3"];
    sig.arg_regs = o32_args
        .iter()
        .filter(|r| read.contains(**r))
        .map(std::string::ToString::to_string)
        .collect();

    // Return value is $v0 or $v1
    let o32_ret = ["$v0", "$v1"];
    sig.ret_regs = o32_ret
        .iter()
        .filter(|r| defined.contains(**r))
        .map(std::string::ToString::to_string)
        .collect();

    // Saved regs are $s0-$s7 that appear in sw instructions at the start
    let saved_set: Vec<String> = instrs
        .iter()
        .filter(|i| i.mnemonic == "sw")
        .filter_map(|i| parse_mem_operand(&i.operands).map(|(src, base, _)| (src, base)))
        .filter(|(_, base)| base == "$sp")
        .map(|(src, _)| src)
        .filter(|r| r.starts_with("$s") || r == "$ra" || r == "$fp")
        .collect();
    sig.saved_regs = saved_set;
    sig
}

// ===========================================================================
// MIPS disassembly context (for multi-pass analysis)
// ===========================================================================

/// Context built up during a recursive-descent or linear pass.
#[derive(Debug, Default, Clone)]
pub struct MipsDisassemblyContext {
    /// Addresses identified as function entry points.
    pub functions: std::collections::BTreeSet<u64>,
    /// Addresses identified as data references.
    pub data_refs: std::collections::BTreeSet<u64>,
    /// Addresses that are definitely code.
    pub code_addrs: std::collections::BTreeSet<u64>,
    /// Inferred high/wide immediates (LUI + ORI pairs), keyed by target register.
    pub hi_imm: std::collections::HashMap<usize, u32>,
}

impl MipsDisassemblyContext {
    /// Create a new context with a known entry point.
    #[must_use]
    pub fn new(entry: u64) -> Self {
        let mut ctx = Self::default();
        ctx.functions.insert(entry);
        ctx
    }

    /// Process an instruction and update context state.
    pub fn process(&mut self, instr: &Instruction) {
        // Track function calls
        if instr.flags.contains(InstrFlags::CALL) && !instr.flags.contains(InstrFlags::INDIRECT) {
            if let Some(w) = instr.bytes.first().copied() {
                let _ = w; // we use the operand string instead
            }
            let t = parse_hex_target_from_operands(&instr.operands);
            if t != 0 {
                self.functions.insert(t);
            }
        }

        // Track code addresses
        self.code_addrs.insert(instr.address.0);

        // Track LUI for hi:lo constant reconstruction
        if instr.mnemonic == "lui" {
            let parts: Vec<&str> = instr.operands.split(',').map(str::trim).collect();
            if parts.len() >= 2 {
                let reg_idx = gpr_index(parts[0]);
                let imm = parse_imm(parts[1]);
                if let Some(r) = reg_idx {
                    self.hi_imm.insert(r, low_u32_of_i64(imm << 16));
                }
            }
        }
    }
}

fn parse_hex_target_from_operands(ops: &str) -> u64 {
    let s = ops.split(',').next_back().unwrap_or("").trim();
    parse_hex_target(s)
}

fn gpr_index(name: &str) -> Option<usize> {
    GPR_NAMES.iter().position(|&n| n == name)
}

// ===========================================================================
// MIPS function call graph
// ===========================================================================

/// An edge in the call graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CallEdge {
    pub caller: u64,
    pub callee: u64,
}

/// Build a call graph from bytes.
#[must_use]
pub fn build_call_graph(arch: &MipsArch, bytes: &[u8], base: Address) -> Vec<CallEdge> {
    let mut edges = Vec::new();
    for instr in MipsLinearDisassembler::new(arch, bytes, base).flatten() {
        if instr.flags.contains(InstrFlags::CALL) && !instr.flags.contains(InstrFlags::INDIRECT)
        {
            let callee = parse_hex_target_from_operands(&instr.operands);
            if callee != 0 {
                edges.push(CallEdge {
                    caller: instr.address.0,
                    callee,
                });
            }
        }
    }
    edges.sort();
    edges.dedup();
    edges
}

// ===========================================================================
// MIPS exception handler detection
// ===========================================================================

/// Whether an instruction sequence looks like an exception handler.
/// Heuristic: starts with MFC0 and ends with ERET.
#[must_use]
pub fn is_exception_handler(instrs: &[Instruction]) -> bool {
    let has_mfc0 = instrs.iter().any(|i| i.mnemonic == "mfc0");
    let has_eret = instrs.iter().any(|i| i.mnemonic == "eret");
    has_mfc0 && has_eret
}

// ===========================================================================
// Register liveness analysis
// ===========================================================================

/// Simple forward liveness: which registers are live at each instruction.
/// Live = may be read later before being written.
#[derive(Debug, Clone, Default)]
pub struct LiveSet {
    /// Bitmask of live GPRs (bits 0-31 = r0-r31).
    pub gpr_mask: u32,
}

impl LiveSet {
    /// Mark a register as live.
    pub const fn set_live(&mut self, reg: usize) {
        if reg < 32 {
            self.gpr_mask |= 1 << reg;
        }
    }
    /// Mark a register as dead (defined).
    pub const fn kill(&mut self, reg: usize) {
        if reg < 32 {
            self.gpr_mask &= !(1 << reg);
        }
    }
    /// Is register live?
    #[must_use]
    pub const fn is_live(&self, reg: usize) -> bool {
        reg < 32 && (self.gpr_mask >> reg) & 1 != 0
    }
    /// Number of live registers.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.gpr_mask.count_ones()
    }
}

// ===========================================================================
// ABI stack frame model
// ===========================================================================

/// Models the stack frame layout for one MIPS O32 function.
#[derive(Debug, Default, Clone)]
pub struct StackFrame {
    /// Total frame size in bytes.
    pub size: i64,
    /// Offsets of saved registers: (`reg_name`, `offset_from_sp`).
    pub saved: Vec<(String, i64)>,
    /// Offset of local variable area.
    pub locals_offset: i64,
    /// Number of outgoing argument slots.
    pub arg_slots: usize,
}

impl StackFrame {
    /// Parse a frame model by scanning the function prologue.
    #[must_use]
    pub fn from_prologue(instrs: &[Instruction]) -> Self {
        let mut frame = Self::default();

        for instr in instrs {
            let m = instr.mnemonic.as_str();
            let parts: Vec<&str> = instr.operands.split(',').map(str::trim).collect();

            // addiu $sp,$sp,-N → frame size
            if m == "addiu"
                && parts.len() >= 3
                && parts[0] == "$sp"
                && parts[1] == "$sp"
                && let Ok(n) = parts[2].parse::<i64>()
                && n < 0
            {
                frame.size = -n;
            }

            // sw $reg, offset($sp) → saved register
            if m == "sw"
                && let Some((src, base, offset)) = parse_mem_operand(&instr.operands)
                && base == "$sp"
            {
                frame.saved.push((src, offset));
            }

            // jr $ra → stop scanning prologue
            if m == "jr" && instr.operands.trim() == "$ra" {
                break;
            }
        }

        frame
    }

    /// Whether this frame is a leaf function (no sw $ra seen).
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        !self.saved.iter().any(|(r, _)| r == "$ra")
    }
}

// ===========================================================================
// MIPS instruction pattern matcher
// ===========================================================================

/// A simple pattern for matching instruction sequences.
#[derive(Debug, Clone)]
pub struct InstrPattern {
    pub mnemonic_prefix: &'static str,
    pub operand_contains: Option<&'static str>,
}

impl InstrPattern {
    #[must_use]
    pub const fn new(mnemonic_prefix: &'static str) -> Self {
        Self {
            mnemonic_prefix,
            operand_contains: None,
        }
    }

    #[must_use]
    pub const fn with_operand(mut self, s: &'static str) -> Self {
        self.operand_contains = Some(s);
        self
    }

    #[must_use]
    pub fn matches(&self, instr: &Instruction) -> bool {
        let m_ok = instr.mnemonic.starts_with(self.mnemonic_prefix);
        let o_ok = self
            .operand_contains
            .is_none_or(|s| instr.operands.contains(s));
        m_ok && o_ok
    }
}

/// Find all positions in `instrs` where the given sequence of patterns matches.
#[must_use]
pub fn find_pattern(instrs: &[Instruction], patterns: &[InstrPattern]) -> Vec<usize> {
    let mut results = Vec::new();
    if patterns.is_empty() || instrs.len() < patterns.len() {
        return results;
    }
    'outer: for start in 0..=(instrs.len() - patterns.len()) {
        for (i, pat) in patterns.iter().enumerate() {
            if !pat.matches(&instrs[start + i]) {
                continue 'outer;
            }
        }
        results.push(start);
    }
    results
}

// ===========================================================================
// MIPS32 / MIPS64 feature detection
// ===========================================================================

/// CPU feature flags, packed into a bit set.
///
/// A bit set rather than five `bool` fields: the flags are queried as a group
/// and a set can be unioned across translation units, which five independent
/// booleans cannot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MipsFeatures(u32);

impl MipsFeatures {
    /// Coprocessor 1 (hardware floating point) is used.
    pub const FPU: u32 = 1 << 0;
    /// MIPS64 doubleword instructions are used.
    pub const MIPS64: u32 = 1 << 1;
    /// MIPS32 release 2 instructions are used.
    pub const MIPS32R2: u32 = 1 << 2;
    /// DSP ASE instructions are used.
    pub const DSP: u32 = 1 << 3;
    /// MSA (SIMD) instructions are used.
    pub const MSA: u32 = 1 << 4;

    /// An empty feature set.
    #[must_use]
    pub const fn none() -> Self {
        Self(0)
    }

    /// The raw bits of the set.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// True when every bit in `mask` is present.
    #[must_use]
    pub const fn contains(self, mask: u32) -> bool {
        self.0 & mask == mask
    }

    /// Add every bit in `mask` to the set.
    pub const fn insert(&mut self, mask: u32) {
        self.0 |= mask;
    }

    /// The union of two feature sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Hardware floating point detected.
    #[must_use]
    pub const fn has_fpu(self) -> bool {
        self.contains(Self::FPU)
    }

    /// MIPS64 instructions detected.
    #[must_use]
    pub const fn has_mips64(self) -> bool {
        self.contains(Self::MIPS64)
    }

    /// `MIPS32r2` instructions detected.
    #[must_use]
    pub const fn has_mips32r2(self) -> bool {
        self.contains(Self::MIPS32R2)
    }

    /// DSP ASE instructions detected.
    #[must_use]
    pub const fn has_dsp(self) -> bool {
        self.contains(Self::DSP)
    }

    /// MSA instructions detected.
    #[must_use]
    pub const fn has_msa(self) -> bool {
        self.contains(Self::MSA)
    }
}

impl MipsFeatures {
    /// Detect features by scanning for instructions unique to each extension.
    #[must_use]
    pub fn detect(arch: &MipsArch, bytes: &[u8], base: Address) -> Self {
        let mut f = Self::default();
        for instr in MipsLinearDisassembler::new(arch, bytes, base).flatten() {
            let m = instr.mnemonic.as_str();
            if m.contains(".s")
                || m.contains(".d")
                || m == "mfc1"
                || m == "mtc1"
                || m == "lwc1"
                || m == "swc1"
                || m == "ldc1"
                || m == "sdc1"
            {
                f.insert(Self::FPU);
            }
            if m.starts_with('d')
                && (m == "dadd"
                    || m == "daddu"
                    || m == "dsub"
                    || m == "dsubu"
                    || m == "dmult"
                    || m == "dmultu"
                    || m == "ddiv"
                    || m == "ddivu"
                    || m == "dsll"
                    || m == "dsrl"
                    || m == "dsra")
            {
                f.insert(Self::MIPS64);
            }
            if m == "seb"
                || m == "seh"
                || m == "wsbh"
                || m == "ext"
                || m == "ins"
                || m == "rdhwr"
                || m == "rotr"
                || m == "rotrv"
            {
                f.insert(Self::MIPS32R2);
            }
        }
        f
    }
}

// ===========================================================================
// Extended tests — patterns, liveness, frame analysis
// ===========================================================================

#[cfg(test)]
mod tests_patterns {
    use super::*;

    fn le(word: u32) -> [u8; 4] {
        word.to_le_bytes()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }
    fn arch32le() -> MipsArch {
        MipsArch::mips32_le()
    }

    // ── find_pattern ─────────────────────────────────────────────────────────
    #[test]
    fn test_find_pattern() {
        let ws = [
            encode_lui(2, 0x1234),
            encode_itype(0x0D, 2, 2, 0x5678), // ori $v0,$v0,0x5678
            encode_rtype(31, 0, 0, 0, 0x08),  // jr $ra
            0u32,                             // nop
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let arch = arch32le();
        let instrs: Vec<_> = MipsLinearDisassembler::new(&arch, &bytes, addr(0))
            .filter_map(Result::ok)
            .collect();
        let pats = [InstrPattern::new("lui"), InstrPattern::new("ori")];
        let hits = find_pattern(&instrs, &pats);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0], 0);
    }

    // ── LiveSet ───────────────────────────────────────────────────────────────
    #[test]
    fn test_live_set() {
        let mut live = LiveSet::default();
        live.set_live(4); // $a0
        live.set_live(5); // $a1
        assert!(live.is_live(4));
        assert!(!live.is_live(6));
        assert_eq!(live.count(), 2);
        live.kill(4);
        assert!(!live.is_live(4));
        assert_eq!(live.count(), 1);
    }

    // ── StackFrame::from_prologue ─────────────────────────────────────────────
    #[test]
    fn test_stack_frame_prologue() {
        let ws = [
            encode_itype(0x09, 29, 29, (-32i16).cast_unsigned()), // addiu $sp,$sp,-32
            encode_itype(0x2B, 29, 31, 28u16),           // sw $ra,28($sp)
            encode_itype(0x2B, 29, 30, 24u16),           // sw $fp,24($sp)
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let arch = arch32le();
        let instrs: Vec<_> = MipsLinearDisassembler::new(&arch, &bytes, addr(0))
            .filter_map(Result::ok)
            .collect();
        let frame = StackFrame::from_prologue(&instrs);
        assert_eq!(frame.size, 32);
        assert!(!frame.is_leaf()); // $ra was saved
        assert_eq!(frame.saved.len(), 2);
    }

    // ── infer_signature basic ─────────────────────────────────────────────────
    #[test]
    fn test_infer_signature_basic() {
        // lw $v0, 0($a0) — reads $a0, writes $v0
        let ws = [
            encode_itype(0x23, 4, 2, 0),     // lw $v0,0($a0)
            encode_rtype(31, 0, 0, 0, 0x08), // jr $ra
            0u32,
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let sig = infer_signature(&arch32le(), &bytes, addr(0));
        assert!(sig.arg_regs.contains(&"$a0".to_string()));
    }

    // ── MipsFeatures detect ───────────────────────────────────────────────────
    #[test]
    fn test_features_detect_fpu() {
        // MFC1 instruction
        let w: u32 = (0x11 << 26) | (2 << 16) | (4 << 11);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&w.to_le_bytes());
        let f = MipsFeatures::detect(&arch32le(), &bytes, addr(0));
        assert!(f.has_fpu());
    }

    // ── call graph build ──────────────────────────────────────────────────────
    #[test]
    fn test_call_graph() {
        let ws = [
            encode_jtype(0x03, 0x100), // jal 0x400
            0u32,
            encode_jtype(0x03, 0x200), // jal 0x800
            0u32,
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let edges = build_call_graph(&arch32le(), &bytes, addr(0));
        assert_eq!(edges.len(), 2);
    }

    // ── is_exception_handler ─────────────────────────────────────────────────
    #[test]
    fn test_is_exception_handler() {
        // mfc0 $v0, Status then eret
        let ws = [
            (0x10u32 << 26) | (2 << 16) | (12 << 11), // mfc0 $v0,$12
            (0x10u32 << 26) | (0x10 << 21) | 0x18,                   // eret
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let arch = arch32le();
        let instrs: Vec<_> = MipsLinearDisassembler::new(&arch, &bytes, addr(0))
            .filter_map(Result::ok)
            .collect();
        assert!(is_exception_handler(&instrs));
    }

    // ── MIPS_EXC_VECTORS table ────────────────────────────────────────────────
    #[test]
    fn test_exc_vectors_table() {
        assert!(!MIPS_EXC_VECTORS.is_empty());
        assert_eq!(MIPS_EXC_VECTORS[0].offset, 0x000);
        assert!(MIPS_EXC_VECTORS[1].name.contains("TLB"));
    }

    // ── pseudo instruction table ──────────────────────────────────────────────
    #[test]
    fn test_pseudo_table() {
        let nop_entry = MIPS_PSEUDOS.iter().find(|e| e.name == "nop").unwrap();
        assert!(nop_entry.expansion.contains("sll"));
        let move_entry = MIPS_PSEUDOS.iter().find(|e| e.name == "move").unwrap();
        assert!(move_entry.expansion.contains("addu"));
    }

    // ── CACHE hints table ─────────────────────────────────────────────────────
    #[test]
    fn test_cache_hints() {
        assert!(!CACHE_HINTS.is_empty());
        let inv = CACHE_HINTS.iter().find(|h| h.code == 0).unwrap();
        assert!(inv.name.contains("Invalidate"));
    }

    // ── MIPS32r2 extensions table ─────────────────────────────────────────────
    #[test]
    fn test_r2_extensions_table() {
        assert!(!MIPS32R2_EXTENSIONS.is_empty());
        let seb = MIPS32R2_EXTENSIONS
            .iter()
            .find(|(k, _)| *k == "seb")
            .unwrap();
        assert!(seb.1.contains("Sign-Extend"));
    }

    // ── format_disassembly output ─────────────────────────────────────────────
    #[test]
    fn test_format_disassembly_output() {
        let ws = [
            encode_rtype(1, 2, 3, 0, 0x20),
            encode_rtype(31, 0, 0, 0, 0x08),
            0u32,
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let opts = FormatOptions::default();
        let out = format_disassembly(&arch32le(), &bytes, addr(0x4000), &opts);
        assert!(out.contains("4000"));
        assert!(out.contains("add"));
        assert!(out.contains("jr"));
    }

    // ── hi_lo_effect for all variants ─────────────────────────────────────────
    #[test]
    fn test_hi_lo_all() {
        for (mn, expected) in [
            ("mult", HiLoEffect::MultSigned),
            ("multu", HiLoEffect::MultUnsigned),
            ("div", HiLoEffect::DivSigned),
            ("divu", HiLoEffect::DivUnsigned),
            ("madd", HiLoEffect::MaddSigned),
            ("maddu", HiLoEffect::MaddUnsigned),
            ("msub", HiLoEffect::MsubSigned),
            ("msubu", HiLoEffect::MsubUnsigned),
        ] {
            assert_eq!(hi_lo_effect(mn), expected, "failed for {mn}");
        }
    }

    // ── encoding helpers round-trip ───────────────────────────────────────────
    #[test]
    fn test_encoding_helpers() {
        let arch = arch32le();
        // ADDU
        let i = arch
            .disassemble(addr(0), &le(encode_addu(3, 1, 2)))
            .unwrap();
        assert_eq!(i.mnemonic, "addu");
        // SUBU
        let i = arch
            .disassemble(addr(0), &le(encode_subu(3, 1, 2)))
            .unwrap();
        assert_eq!(i.mnemonic, "subu");
        // AND
        let i = arch.disassemble(addr(0), &le(encode_and(3, 1, 2))).unwrap();
        assert_eq!(i.mnemonic, "and");
        // OR
        let i = arch.disassemble(addr(0), &le(encode_or(3, 1, 2))).unwrap();
        assert_eq!(i.mnemonic, "or");
        // XOR
        let i = arch.disassemble(addr(0), &le(encode_xor(3, 1, 2))).unwrap();
        assert_eq!(i.mnemonic, "xor");
        // NOR
        let i = arch.disassemble(addr(0), &le(encode_nor(3, 1, 2))).unwrap();
        assert_eq!(i.mnemonic, "nor");
        // SLT
        let i = arch.disassemble(addr(0), &le(encode_slt(3, 1, 2))).unwrap();
        assert_eq!(i.mnemonic, "slt");
        // SLTU
        let i = arch
            .disassemble(addr(0), &le(encode_sltu(3, 1, 2)))
            .unwrap();
        assert_eq!(i.mnemonic, "sltu");
        // MULT
        let i = arch.disassemble(addr(0), &le(encode_mult(1, 2))).unwrap();
        assert_eq!(i.mnemonic, "mult");
        // DIV
        let i = arch.disassemble(addr(0), &le(encode_div(1, 2))).unwrap();
        assert_eq!(i.mnemonic, "div");
        // MFHI / MFLO
        let i = arch.disassemble(addr(0), &le(encode_mfhi(3))).unwrap();
        assert_eq!(i.mnemonic, "mfhi");
        let i = arch.disassemble(addr(0), &le(encode_mflo(3))).unwrap();
        assert_eq!(i.mnemonic, "mflo");
        // BEQ / BNE
        let i = arch.disassemble(addr(0), &le(encode_beq(1, 2, 4))).unwrap();
        assert_eq!(i.mnemonic, "beq");
        let i = arch.disassemble(addr(0), &le(encode_bne(1, 2, 4))).unwrap();
        assert_eq!(i.mnemonic, "bne");
        // SYSCALL
        let i = arch.disassemble(addr(0), &le(encode_syscall(42))).unwrap();
        assert_eq!(i.mnemonic, "syscall");
    }

    // ── gpr() helper ──────────────────────────────────────────────────────────
    #[test]
    fn test_gpr_helper() {
        assert_eq!(gpr(0), "$zero");
        assert_eq!(gpr(29), "$sp");
        assert_eq!(gpr(31), "$ra");
        assert_eq!(gpr(32), "$unk");
    }

    // ── MIPS_REG_CONV preserved flags ─────────────────────────────────────────
    #[test]
    fn test_reg_conv_preserved() {
        let preserved_count = MIPS_REG_CONV.iter().filter(|e| e.preserved).count();
        // $s0-$s7 (8) + $gp + $sp + $fp = 11
        assert_eq!(preserved_count, 11);
    }
}

// ===========================================================================
// MIPS Opcode class classification
// ===========================================================================

/// Broad instruction class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MipsClass {
    IntAlu,
    IntImm,
    HiLo,
    Shift,
    Branch,
    Jump,
    Load,
    Store,
    FloatArith,
    FloatConvert,
    FloatCompare,
    FloatMove,
    FloatLoad,
    FloatStore,
    Cop0,
    Trap,
    Atomic,
    Prefetch,
    Cache,
    Syscall,
    Break,
    Sync,
    Unknown,
}

impl MipsClass {
    /// Classify a mnemonic.
    #[must_use]
    pub fn from_mnemonic(m: &str) -> Self {
        // Floating-point instructions contain a dot (e.g. "add.s", "sub.d").
        // Guard integer ALU matching to exclude them.
        let is_float = m.contains('.');
        if !is_float
            && (m.starts_with("add")
                || m.starts_with("sub")
                || m == "and"
                || m == "or"
                || m == "xor"
                || m == "nor"
                || m.starts_with("slt")
                || m == "clz"
                || m == "clo"
                || m.starts_with("dadd")
                || m.starts_with("dsub")
                || m == "dclz"
                || m == "dclo"
                // "mul" (rd = rs*rt, no HI/LO) is IntAlu, but "mult"/"multu" write HI/LO
                || m == "mul"
                || m == "neg"
                || m == "move")
        {
            return Self::IntAlu;
        }

        if m == "addi"
            || m == "addiu"
            || m == "slti"
            || m == "sltiu"
            || m == "andi"
            || m == "ori"
            || m == "xori"
            || m == "lui"
            || m == "daddi"
            || m == "daddiu"
        {
            return Self::IntImm;
        }

        if m == "mult"
            || m == "multu"
            || m == "div"
            || m == "divu"
            || m == "dmult"
            || m == "dmultu"
            || m == "ddiv"
            || m == "ddivu"
            || m == "mfhi"
            || m == "mthi"
            || m == "mflo"
            || m == "mtlo"
            || m == "madd"
            || m == "maddu"
            || m == "msub"
            || m == "msubu"
        {
            return Self::HiLo;
        }

        if m == "sll"
            || m == "srl"
            || m == "sra"
            || m == "sllv"
            || m == "srlv"
            || m == "srav"
            || m == "dsll"
            || m == "dsrl"
            || m == "dsra"
            || m == "dsll32"
            || m == "dsrl32"
            || m == "dsra32"
            || m == "dsllv"
            || m == "dsrlv"
            || m == "dsrav"
            || m == "rotr"
            || m == "rotrv"
        {
            return Self::Shift;
        }

        if m == "beq"
            || m == "bne"
            || m == "blez"
            || m == "bgtz"
            || m == "bltz"
            || m == "bgez"
            || m == "beql"
            || m == "bnel"
            || m == "blezl"
            || m == "bgtzl"
            || m == "bltzl"
            || m == "bgezl"
            || m == "bltzal"
            || m == "bgezal"
            || m == "bltzall"
            || m == "bgezall"
            || m == "bc1f"
            || m == "bc1t"
            || m == "bc1fl"
            || m == "bc1tl"
        {
            return Self::Branch;
        }

        if m == "j" || m == "jal" || m == "jr" || m == "jalr" {
            return Self::Jump;
        }

        if m == "lb"
            || m == "lh"
            || m == "lw"
            || m == "lbu"
            || m == "lhu"
            || m == "lwu"
            || m == "ld"
            || m == "lwl"
            || m == "lwr"
            || m == "ldl"
            || m == "ldr"
        {
            return Self::Load;
        }

        if m == "sb"
            || m == "sh"
            || m == "sw"
            || m == "sd"
            || m == "swl"
            || m == "swr"
            || m == "sdl"
            || m == "sdr"
        {
            return Self::Store;
        }

        if m == "lwc1" || m == "ldc1" {
            return Self::FloatLoad;
        }
        if m == "swc1" || m == "sdc1" {
            return Self::FloatStore;
        }

        if m.starts_with("add.")
            || m.starts_with("sub.")
            || m.starts_with("mul.")
            || m.starts_with("div.")
            || m.starts_with("sqrt.")
            || m.starts_with("abs.")
            || m.starts_with("neg.")
            || m.starts_with("recip.")
            || m.starts_with("rsqrt.")
            || m.starts_with("madd.")
            || m.starts_with("msub.")
            || m.starts_with("nmadd.")
            || m.starts_with("nmsub.")
        {
            return Self::FloatArith;
        }

        if m.starts_with("cvt.")
            || m.starts_with("round.")
            || m.starts_with("trunc.")
            || m.starts_with("ceil.")
            || m.starts_with("floor.")
        {
            return Self::FloatConvert;
        }

        if m.starts_with("c.") {
            return Self::FloatCompare;
        }

        if m.starts_with("mov.")
            || m.starts_with("movz.")
            || m.starts_with("movn.")
            || m.starts_with("movt.")
            || m.starts_with("movf.")
            || m == "mfc1"
            || m == "mtc1"
            || m == "cfc1"
            || m == "ctc1"
            || m == "dmfc1"
            || m == "dmtc1"
            || m == "mfhc1"
            || m == "mthc1"
        {
            return Self::FloatMove;
        }

        if m == "mfc0"
            || m == "mtc0"
            || m == "dmfc0"
            || m == "dmtc0"
            || m == "tlbr"
            || m == "tlbwi"
            || m == "tlbwr"
            || m == "tlbp"
            || m == "eret"
            || m == "deret"
            || m == "wait"
        {
            return Self::Cop0;
        }

        if m == "tge"
            || m == "tgeu"
            || m == "tlt"
            || m == "tltu"
            || m == "teq"
            || m == "tne"
            || m == "tgei"
            || m == "tgeiu"
            || m == "tlti"
            || m == "tltiu"
            || m == "teqi"
            || m == "tnei"
        {
            return Self::Trap;
        }

        if m == "ll" || m == "sc" || m == "lld" || m == "scd" {
            return Self::Atomic;
        }
        if m == "pref" || m == "prefx" {
            return Self::Prefetch;
        }
        if m == "cache" {
            return Self::Cache;
        }
        if m == "syscall" {
            return Self::Syscall;
        }
        if m == "break" || m == "sdbbp" {
            return Self::Break;
        }
        if m == "sync" || m == "synci" {
            return Self::Sync;
        }

        Self::Unknown
    }

    /// Is this a memory access?
    #[must_use]
    pub const fn is_memory(self) -> bool {
        matches!(
            self,
            Self::Load | Self::Store | Self::FloatLoad | Self::FloatStore | Self::Atomic
        )
    }

    /// Is this control flow?
    #[must_use]
    pub const fn is_control(self) -> bool {
        matches!(self, Self::Branch | Self::Jump)
    }
}

// ---------------------------------------------------------------------------
// MIPS delay slot LLIL ordering
// ---------------------------------------------------------------------------
//
// In classic MIPS the instruction following a branch/jump always executes
// before the branch is taken. The canonical LLIL ordering is:
//
//   <LLIL for delay_slot_instr>
//   <LLIL for branch/jump instr>
//
// The functions below implement this reordering for a sequence of lifted ops.

/// Reorder a linear LLIL stream to respect MIPS delay-slot semantics.
/// Input: (`instr_index`, `llil_ops`) pairs.
/// Output: reordered pairs with delay-slot ops swapped before their branch.
#[must_use]
pub fn reorder_for_delay_slots(
    arch: &MipsArch,
    instrs: &[Instruction],
    lifted: &[(usize, Vec<LlilOp>)],
) -> Vec<(usize, Vec<LlilOp>)> {
    let tags = DelaySlotAnalyzer::tag_delay_slots(instrs);
    let mut out: Vec<(usize, Vec<LlilOp>)> = Vec::with_capacity(lifted.len());
    let mut i = 0;

    while i < lifted.len() {
        // If next instruction is a branch with delay slot
        if i + 1 < lifted.len()
            && i < instrs.len()
            && DelaySlotAnalyzer::has_delay_slot(&instrs[i])
            && tags.get(i + 1).copied().unwrap_or(false)
        {
            // Emit delay slot FIRST
            out.push(lifted[i + 1].clone());
            // Then emit branch
            out.push(lifted[i].clone());
            i += 2;
        } else {
            out.push(lifted[i].clone());
            i += 1;
        }
    }

    let _ = arch; // may be used for future variant-specific logic
    out
}

// ---------------------------------------------------------------------------
// MIPS register dependency analysis
// ---------------------------------------------------------------------------

/// Forward dependency between two instruction positions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegDep {
    /// Index of the defining instruction.
    pub def_idx: usize,
    /// Index of the using instruction.
    pub use_idx: usize,
    /// Register name.
    pub reg: String,
}

/// Find all read-after-write register dependencies in a sequence.
#[must_use]
pub fn find_dependencies(instrs: &[Instruction]) -> Vec<RegDep> {
    let mut deps = Vec::new();
    // Map: register name → last definition index
    let mut last_def: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for (idx, instr) in instrs.iter().enumerate() {
        let parts: Vec<&str> = instr.operands.split(',').map(str::trim).collect();
        let m = instr.mnemonic.as_str();

        // Determine which registers are read
        let reads: Vec<String> = match m {
            "add" | "addu" | "sub" | "subu" | "and" | "or" | "xor" | "nor" | "slt" | "sltu"
            | "dadd" | "daddu" | "dsub" | "dsubu" => parts
                .get(1)
                .iter()
                .chain(parts.get(2).iter())
                .filter(|s| s.starts_with('$'))
                .map(std::string::ToString::to_string)
                .collect(),
            "addi" | "addiu" | "andi" | "ori" | "xori" | "slti" | "sltiu" | "daddi" | "daddiu" => {
                if parts.len() >= 2 {
                    let sub_joined = parts[1..].join(",");
                    let sub: Vec<&str> = sub_joined.split(',').map(str::trim).collect::<Vec<_>>();
                    sub.first()
                        .filter(|s| s.starts_with('$'))
                        .map(std::string::ToString::to_string)
                        .into_iter()
                        .collect()
                } else {
                    vec![]
                }
            }
            "lw" | "lh" | "lb" | "lhu" | "lbu" | "ld" | "lwu" => {
                if let Some((_, base, _)) = parse_mem_operand(&instr.operands) {
                    vec![base]
                } else {
                    vec![]
                }
            }
            "sw" | "sh" | "sb" | "sd" => {
                if let Some((src, base, _)) = parse_mem_operand(&instr.operands) {
                    vec![src, base]
                } else {
                    vec![]
                }
            }
            "beq" | "bne" => parts
                .iter()
                .take(2)
                .filter(|s| s.starts_with('$'))
                .map(std::string::ToString::to_string)
                .collect(),
            "blez" | "bgtz" | "bltz" | "bgez" => parts
                .first()
                .filter(|s| s.starts_with('$'))
                .map(std::string::ToString::to_string)
                .into_iter()
                .collect(),
            _ => vec![],
        };

        // Record RAW dependencies
        for reg in &reads {
            if let Some(&def_i) = last_def.get(reg) {
                deps.push(RegDep {
                    def_idx: def_i,
                    use_idx: idx,
                    reg: reg.clone(),
                });
            }
        }

        // Determine which register is written (destination)
        let write: Option<String> = match m {
            "add" | "addu" | "sub" | "subu" | "and" | "or" | "xor" | "nor" | "slt" | "sltu"
            | "sll" | "srl" | "sra" | "sllv" | "srlv" | "srav" | "dadd" | "daddu" | "dsub"
            | "dsubu" | "dsll" | "dsrl" | "dsra" | "dsll32" | "dsrl32" | "dsra32" | "dsllv"
            | "dsrlv" | "dsrav" | "mul" | "clz" | "clo" | "addi" | "addiu" | "slti" | "sltiu"
            | "andi" | "ori" | "xori" | "lui" | "daddi" | "daddiu" | "lw" | "lh" | "lb" | "lhu"
            | "lbu" | "ld" | "lwu" | "mfhi" | "mflo" | "movz" | "movn" => parts
                .first()
                .filter(|s| s.starts_with('$'))
                .map(std::string::ToString::to_string),
            _ => None,
        };

        if let Some(reg) = write {
            last_def.insert(reg, idx);
        }
    }

    deps
}

// ===========================================================================
// MIPS32/64 opcode field extraction utilities
// ===========================================================================

/// Extract all fields from a 32-bit MIPS instruction word.
#[derive(Debug, Clone, Copy)]
pub struct MipsFields {
    pub opcode: u32,
    pub rs: u32,
    pub rt: u32,
    pub rd: u32,
    pub shamt: u32,
    pub funct: u32,
    pub imm16: u32,
    pub simm16: i32,
    pub target26: u32,
}

impl MipsFields {
    /// Decode all fields from a raw word.
    #[must_use]
    pub const fn decode(word: u32) -> Self {
        let imm16 = word & 0xFFFF;
        Self {
            opcode: (word >> 26) & 0x3F,
            rs: (word >> 21) & 0x1F,
            rt: (word >> 16) & 0x1F,
            rd: (word >> 11) & 0x1F,
            shamt: (word >> 6) & 0x1F,
            funct: word & 0x3F,
            imm16,
            simm16: (imm16 as i16) as i32,
            target26: word & 0x03FF_FFFF,
        }
    }
}

// ===========================================================================
// MIPS branch predictor model (simplified)
// ===========================================================================

/// Simple branch prediction model.
#[derive(Debug, Clone, Default)]
pub struct BranchPredictor {
    /// Branch history table: maps instruction address → predicted-taken count.
    /// Uses `BTreeMap` rather than `HashMap` to prevent hash-collision `DoS` when
    /// keys come from attacker-controlled binary addresses.
    table: std::collections::BTreeMap<u64, u32>,
}

impl BranchPredictor {
    /// Update prediction for a branch at `addr`.
    /// `taken` = whether the branch was taken.
    pub fn update(&mut self, addr: u64, taken: bool) {
        let entry = self.table.entry(addr).or_insert(0);
        if taken {
            *entry = entry.saturating_add(1);
        } else {
            *entry = entry.saturating_sub(1);
        }
    }

    /// Predict whether branch at `addr` will be taken.
    #[must_use]
    pub fn predict_taken(&self, addr: u64) -> bool {
        self.table.get(&addr).copied().unwrap_or(0) >= 1
    }

    /// Number of branch addresses tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

// ===========================================================================
// MIPS pipeline hazard detection
// ===========================================================================

/// MIPS pipeline hazard type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineHazard {
    /// Load-use hazard: load followed immediately by use of loaded register.
    LoadUse,
    /// Control hazard: branch without NOP delay slot.
    ControlWithoutNop,
    /// Hi/Lo not ready: MFHI/MFLO immediately after MULT/DIV.
    HiLoNotReady,
}

/// Find pipeline hazards in an instruction sequence.
#[must_use]
pub fn find_hazards(instrs: &[Instruction]) -> Vec<(usize, PipelineHazard)> {
    let mut hazards = Vec::new();

    for (i, instr) in instrs.iter().enumerate() {
        let next = instrs.get(i + 1);

        // Load-use hazard
        if (instr.mnemonic == "lw"
            || instr.mnemonic == "lb"
            || instr.mnemonic == "lh"
            || instr.mnemonic == "lbu"
            || instr.mnemonic == "lhu"
            || instr.mnemonic == "ld")
            && let Some(next_i) = next
        {
            let dst = instr
                .operands
                .split(',')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !dst.is_empty() && next_i.operands.contains(&dst) {
                hazards.push((i, PipelineHazard::LoadUse));
            }
        }

        // Hi/Lo not ready
        if (instr.mnemonic == "mult"
            || instr.mnemonic == "multu"
            || instr.mnemonic == "div"
            || instr.mnemonic == "divu")
            && let Some(next_i) = next
            && (next_i.mnemonic == "mfhi" || next_i.mnemonic == "mflo")
        {
            hazards.push((i, PipelineHazard::HiLoNotReady));
        }

        // Control hazard: branch whose delay slot is another branch
        if DelaySlotAnalyzer::has_delay_slot(instr)
            && let Some(next_i) = next
            && DelaySlotAnalyzer::has_delay_slot(next_i)
        {
            hazards.push((i + 1, PipelineHazard::ControlWithoutNop));
        }
    }

    hazards
}

// ===========================================================================
// More extended tests
// ===========================================================================

#[cfg(test)]
mod tests_advanced {
    use super::*;

    fn le(word: u32) -> [u8; 4] {
        word.to_le_bytes()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }
    fn arch32le() -> MipsArch {
        MipsArch::mips32_le()
    }

    // ── MipsClass classification ───────────────────────────────────────────
    #[test]
    fn test_mips_class() {
        assert_eq!(MipsClass::from_mnemonic("add"), MipsClass::IntAlu);
        assert_eq!(MipsClass::from_mnemonic("lw"), MipsClass::Load);
        assert_eq!(MipsClass::from_mnemonic("sw"), MipsClass::Store);
        assert_eq!(MipsClass::from_mnemonic("beq"), MipsClass::Branch);
        assert_eq!(MipsClass::from_mnemonic("j"), MipsClass::Jump);
        assert_eq!(MipsClass::from_mnemonic("mult"), MipsClass::HiLo);
        assert_eq!(MipsClass::from_mnemonic("sll"), MipsClass::Shift);
        assert_eq!(MipsClass::from_mnemonic("add.s"), MipsClass::FloatArith);
        assert_eq!(MipsClass::from_mnemonic("cvt.w.s"), MipsClass::FloatConvert);
        assert_eq!(MipsClass::from_mnemonic("c.lt.d"), MipsClass::FloatCompare);
        assert_eq!(MipsClass::from_mnemonic("mfc0"), MipsClass::Cop0);
        assert_eq!(MipsClass::from_mnemonic("ll"), MipsClass::Atomic);
        assert_eq!(MipsClass::from_mnemonic("cache"), MipsClass::Cache);
        assert_eq!(MipsClass::from_mnemonic("syscall"), MipsClass::Syscall);
        assert_eq!(MipsClass::from_mnemonic("sync"), MipsClass::Sync);
        assert_eq!(MipsClass::from_mnemonic("tge"), MipsClass::Trap);
        assert_eq!(MipsClass::from_mnemonic("unknown"), MipsClass::Unknown);
    }

    // ── MipsClass is_memory ───────────────────────────────────────────────
    #[test]
    fn test_class_is_memory() {
        assert!(MipsClass::Load.is_memory());
        assert!(MipsClass::Store.is_memory());
        assert!(MipsClass::Atomic.is_memory());
        assert!(!MipsClass::IntAlu.is_memory());
    }

    // ── MipsFields decode ─────────────────────────────────────────────────
    #[test]
    fn test_fields_decode() {
        let w = encode_rtype(3, 4, 5, 2, 0x20); // add r5, r3, r4, shamt=2
        let f = MipsFields::decode(w);
        assert_eq!(f.opcode, 0);
        assert_eq!(f.rs, 3);
        assert_eq!(f.rt, 4);
        assert_eq!(f.rd, 5);
        assert_eq!(f.shamt, 2);
        assert_eq!(f.funct, 0x20);
    }

    // ── MipsFields I-type ─────────────────────────────────────────────────
    #[test]
    fn test_fields_itype() {
        let w = encode_itype(0x09, 1, 3, 0x1234);
        let f = MipsFields::decode(w);
        assert_eq!(f.opcode, 9);
        assert_eq!(f.rs, 1);
        assert_eq!(f.rt, 3);
        assert_eq!(f.imm16, 0x1234);
    }

    // ── find_dependencies ────────────────────────────────────────────────
    #[test]
    fn test_find_dependencies() {
        // lw $v0, 0($a0)  — writes $v0
        // add $v1, $v0, $v0 — reads $v0 (RAW dependency)
        let ws = [
            encode_itype(0x23, 4, 2, 0),    // lw $v0, 0($a0)
            encode_rtype(2, 2, 3, 0, 0x20), // add $v1, $v0, $v0
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let arch = arch32le();
        let instrs: Vec<_> = MipsLinearDisassembler::new(&arch, &bytes, addr(0))
            .filter_map(Result::ok)
            .collect();
        let deps = find_dependencies(&instrs);
        assert!(!deps.is_empty());
        assert!(deps.iter().any(|d| d.def_idx == 0 && d.use_idx == 1));
    }

    // ── BranchPredictor ───────────────────────────────────────────────────
    #[test]
    fn test_branch_predictor() {
        let mut bp = BranchPredictor::default();
        bp.update(0x1000, true);
        bp.update(0x1000, true);
        assert!(bp.predict_taken(0x1000));
        bp.update(0x1000, false);
        bp.update(0x1000, false);
        // Two subs bring count below 1
        assert!(!bp.predict_taken(0x2000)); // never seen → not predicted taken
        assert_eq!(bp.len(), 1);
    }

    // ── find_hazards load-use ─────────────────────────────────────────────
    #[test]
    fn test_load_use_hazard() {
        // lw $v0, 0($a0)
        // add $v1, $v0, $v0 — immediate use of loaded $v0
        let ws = [encode_itype(0x23, 4, 2, 0), encode_rtype(2, 2, 3, 0, 0x20)];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let arch = arch32le();
        let instrs: Vec<_> = MipsLinearDisassembler::new(&arch, &bytes, addr(0))
            .filter_map(Result::ok)
            .collect();
        let hazards = find_hazards(&instrs);
        assert!(hazards.iter().any(|(_, h)| *h == PipelineHazard::LoadUse));
    }

    // ── find_hazards hi/lo not ready ──────────────────────────────────────
    #[test]
    fn test_hilo_hazard() {
        let ws = [
            encode_rtype(1, 2, 0, 0, 0x18), // mult $at, $v0
            encode_rtype(0, 0, 3, 0, 0x12), // mflo $v1
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let arch = arch32le();
        let instrs: Vec<_> = MipsLinearDisassembler::new(&arch, &bytes, addr(0))
            .filter_map(Result::ok)
            .collect();
        let hazards = find_hazards(&instrs);
        assert!(
            hazards
                .iter()
                .any(|(_, h)| *h == PipelineHazard::HiLoNotReady)
        );
    }

    // ── reorder_for_delay_slots ───────────────────────────────────────────
    #[test]
    fn test_reorder_delay_slots() {
        // j target; nop
        let ws = [encode_jtype(0x02, 0x100), 0u32];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let arch = arch32le();
        let instrs: Vec<_> = MipsLinearDisassembler::new(&arch, &bytes, addr(0))
            .filter_map(Result::ok)
            .collect();
        let lifted: Vec<(usize, Vec<LlilOp>)> = instrs
            .iter()
            .enumerate()
            .map(|(i, instr)| (i, lift_to_llil(instr)))
            .collect();
        let reordered = reorder_for_delay_slots(&arch, &instrs, &lifted);
        // After reorder: index 0 should be the nop (delay slot), then jump
        assert_eq!(reordered.len(), 2);
        // The delay slot (originally index 1) should come first
        assert_eq!(reordered[0].0, 1);
        assert_eq!(reordered[1].0, 0);
    }

    // ── MipsDisassemblyContext ─────────────────────────────────────────────
    #[test]
    fn test_disassembly_context() {
        let ws = [
            encode_jtype(0x03, 0x400), // jal
            0u32,
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let arch = arch32le();
        let mut ctx = MipsDisassemblyContext::new(0);
        for instr in MipsLinearDisassembler::new(&arch, &bytes, addr(0)).flatten() {
            ctx.process(&instr);
        }
        assert!(ctx.code_addrs.contains(&0));
        // The jal target 0x400<<2 = 0x1000 should be in functions
        assert!(!ctx.functions.is_empty());
    }

    // ── gpr_index helper ─────────────────────────────────────────────────
    #[test]
    fn test_gpr_index() {
        assert_eq!(gpr_index("$zero"), Some(0));
        assert_eq!(gpr_index("$sp"), Some(29));
        assert_eq!(gpr_index("$ra"), Some(31));
        assert_eq!(gpr_index("$xx"), None);
    }

    // ── MIPS64 DSUB / DSUBU ──────────────────────────────────────────────
    #[test]
    fn test_dsub_dsubu() {
        let arch = MipsArch::mips64_le();
        let dsub = encode_rtype(1, 2, 3, 0, 0x2E);
        let dsubu = encode_rtype(1, 2, 3, 0, 0x2F);
        assert_eq!(
            arch.disassemble(addr(0), &le(dsub)).unwrap().mnemonic,
            "dsub"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(dsubu)).unwrap().mnemonic,
            "dsubu"
        );
    }

    // ── MOVZ / MOVN conditional moves ────────────────────────────────────
    #[test]
    fn test_movz_movn() {
        let arch = arch32le();
        let movz = encode_rtype(1, 2, 3, 0, 0x0A);
        let word_move_if_nonzero = encode_rtype(1, 2, 3, 0, 0x0B);
        assert_eq!(
            arch.disassemble(addr(0), &le(movz)).unwrap().mnemonic,
            "movz"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(word_move_if_nonzero)).unwrap().mnemonic,
            "movn"
        );
    }

    // ── TGE / TGEU / TLT / TLTU / TEQ / TNE ─────────────────────────────
    #[test]
    fn test_trap_instructions() {
        let arch = arch32le();
        for (funct, name) in [
            (0x30, "tge"),
            (0x31, "tgeu"),
            (0x32, "tlt"),
            (0x33, "tltu"),
            (0x34, "teq"),
            (0x36, "tne"),
        ] {
            let w = encode_rtype(1, 2, 0, 0, funct);
            assert_eq!(
                arch.disassemble(addr(0), &le(w)).unwrap().mnemonic,
                name,
                "funct 0x{funct:x}"
            );
        }
    }

    // ── LWC1 / SWC1 / LDC1 / SDC1 ───────────────────────────────────────
    #[test]
    fn test_fp_load_store() {
        let arch = arch32le();
        let lwc1 = encode_itype(0x31, 4, 2, 0);
        let swc1 = encode_itype(0x39, 4, 2, 0);
        let word_load_double_cop1 = encode_itype(0x35, 4, 2, 0);
        let word_store_double_cop1 = encode_itype(0x3D, 4, 2, 0);
        assert_eq!(
            arch.disassemble(addr(0), &le(lwc1)).unwrap().mnemonic,
            "lwc1"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(swc1)).unwrap().mnemonic,
            "swc1"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(word_load_double_cop1)).unwrap().mnemonic,
            "ldc1"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(word_store_double_cop1)).unwrap().mnemonic,
            "sdc1"
        );
        assert!(
            arch.disassemble(addr(0), &le(lwc1))
                .unwrap()
                .flags
                .contains(InstrFlags::READ_MEM)
        );
        assert!(
            arch.disassemble(addr(0), &le(swc1))
                .unwrap()
                .flags
                .contains(InstrFlags::WRITE_MEM)
        );
    }

    // ── DEXT / DEXTM / DEXTU ─────────────────────────────────────────────
    #[test]
    fn test_dext_variants() {
        let arch = MipsArch::mips64_le();
        // dext rt=2, rs=1, pos=3, size=4 (funct=3)
        let dext: u32 = (0x1F << 26) | (1 << 21) | (2 << 16) | (3 << 11) | (3 << 6) | 0x03;
        let dextm: u32 = (0x1F << 26) | (1 << 21) | (2 << 16) | (3 << 11) | (3 << 6) | 0x01;
        let word_dext_upper: u32 = (0x1F << 26) | (1 << 21) | (2 << 16) | (3 << 11) | (3 << 6) | 0x02;
        assert_eq!(
            arch.disassemble(addr(0), &le(dext)).unwrap().mnemonic,
            "dext"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(dextm)).unwrap().mnemonic,
            "dextm"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(word_dext_upper)).unwrap().mnemonic,
            "dextu"
        );
    }

    // ── DINS / DINSM / DINSU ─────────────────────────────────────────────
    #[test]
    fn test_dins_variants() {
        let arch = MipsArch::mips64_le();
        let dins: u32 = (0x1F << 26) | (1 << 21) | (2 << 16) | (7 << 11) | (3 << 6) | 0x07;
        let dinsm: u32 = (0x1F << 26) | (1 << 21) | (2 << 16) | (7 << 11) | (3 << 6) | 0x05;
        let word_dins_upper: u32 = (0x1F << 26) | (1 << 21) | (2 << 16) | (7 << 11) | (3 << 6) | 0x06;
        assert_eq!(
            arch.disassemble(addr(0), &le(dins)).unwrap().mnemonic,
            "dins"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(dinsm)).unwrap().mnemonic,
            "dinsm"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(word_dins_upper)).unwrap().mnemonic,
            "dinsu"
        );
    }

    // ── DSBH / DSHD (DBSHFL) ─────────────────────────────────────────────
    #[test]
    fn test_dbshfl() {
        let arch = MipsArch::mips64_le();
        let dsbh: u32 = (0x1F << 26) | (2 << 16) | (3 << 11) | (0x02 << 6) | 0x24;
        let dshd: u32 = (0x1F << 26) | (2 << 16) | (3 << 11) | (0x05 << 6) | 0x24;
        assert_eq!(
            arch.disassemble(addr(0), &le(dsbh)).unwrap().mnemonic,
            "dsbh"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(dshd)).unwrap().mnemonic,
            "dshd"
        );
    }

    // ── BITSWAP (SPECIAL3 shamt=0) ────────────────────────────────────────
    #[test]
    fn test_bitswap() {
        let w: u32 = (0x1F << 26) | (2 << 16) | (3 << 11) | 0x20;
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "bitswap");
    }

    // ── MADD / MADDU / MSUB / MSUBU (SPECIAL2) ───────────────────────────
    #[test]
    fn test_special2_all() {
        let arch = arch32le();
        for (funct, name) in [(0, "madd"), (1, "maddu"), (4, "msub"), (5, "msubu")] {
            let w = (0x1Cu32 << 26) | (1 << 21) | (2 << 16) | funct;
            assert_eq!(arch.disassemble(addr(0), &le(w)).unwrap().mnemonic, name);
        }
    }

    // ── SLLV / SRAV ──────────────────────────────────────────────────────
    #[test]
    fn test_sllv_srav() {
        let arch = arch32le();
        assert_eq!(
            arch.disassemble(addr(0), &le(encode_rtype(3, 2, 1, 0, 0x04)))
                .unwrap()
                .mnemonic,
            "sllv"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(encode_rtype(3, 2, 1, 0, 0x07)))
                .unwrap()
                .mnemonic,
            "srav"
        );
    }

    // ── DSLL32 / DSRL32 / DSRA32 ─────────────────────────────────────────
    #[test]
    fn test_d_shifts32() {
        let arch = MipsArch::mips64_le();
        assert_eq!(
            arch.disassemble(addr(0), &le(encode_rtype(0, 1, 2, 4, 0x3C)))
                .unwrap()
                .mnemonic,
            "dsll32"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(encode_rtype(0, 1, 2, 4, 0x3E)))
                .unwrap()
                .mnemonic,
            "dsrl32"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(encode_rtype(0, 1, 2, 4, 0x3F)))
                .unwrap()
                .mnemonic,
            "dsra32"
        );
    }

    // ── Unknown opcode → "unknown" ────────────────────────────────────────
    #[test]
    fn test_unknown_opcode() {
        // opcode 0x3B is unassigned
        let w: u32 = 0b1110_1100_0000_0000_0000_0000_0000_0000;
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "unknown");
    }

    // ── N32 calling convention ─────────────────────────────────────────────
    #[test]
    fn test_n32_cc() {
        let arch = MipsArch::custom(32, MipsEndian::Big, MipsAbi::N32);
        let ccs = arch.calling_conventions();
        assert!(ccs.iter().any(|c| c.name == "mips_n32"));
        let n32 = ccs.iter().find(|c| c.name == "mips_n32").unwrap();
        assert_eq!(n32.int_args.len(), 8);
    }
}

// ===========================================================================
// MIPS DSP extension (MIPS32/MIPS64 DSP ASE)
// ===========================================================================
//
// The MIPS DSP Application-Specific Extension adds instructions for
// digital signal processing: SIMD operations on 16-bit and 8-bit lanes,
// accumulator-based operations, and DSPControl register management.

/// DSP ASE instruction entry.
#[derive(Debug, Clone, Copy)]
pub struct DspInstrEntry {
    pub mnemonic: &'static str,
    pub description: &'static str,
}

/// Subset of MIPS DSP ASE instructions.
pub static MIPS_DSP_INSTRS: &[DspInstrEntry] = &[
    DspInstrEntry {
        mnemonic: "absq_s.ph",
        description: "Absolute Value of Two Fractional Halfwords Saturate",
    },
    DspInstrEntry {
        mnemonic: "absq_s.qb",
        description: "Absolute Value of Four Fractional Bytes Saturate",
    },
    DspInstrEntry {
        mnemonic: "absq_s.w",
        description: "Absolute Value of Fractional Word Saturate",
    },
    DspInstrEntry {
        mnemonic: "addq.ph",
        description: "Add Two Fractional Halfwords",
    },
    DspInstrEntry {
        mnemonic: "addq_s.ph",
        description: "Add Two Fractional Halfwords Saturate",
    },
    DspInstrEntry {
        mnemonic: "addq_s.w",
        description: "Add Fractional Word Saturate",
    },
    DspInstrEntry {
        mnemonic: "addsc",
        description: "Add Unsigned Words, Set Carry",
    },
    DspInstrEntry {
        mnemonic: "addu.qb",
        description: "Add Four Unsigned Bytes Modulo",
    },
    DspInstrEntry {
        mnemonic: "addu_s.qb",
        description: "Add Four Unsigned Bytes Saturate",
    },
    DspInstrEntry {
        mnemonic: "addwc",
        description: "Add Words with Carry",
    },
    DspInstrEntry {
        mnemonic: "bitrev",
        description: "Bit Reverse",
    },
    DspInstrEntry {
        mnemonic: "bposge32",
        description: "Branch if Position Greater Than or Equal to 32",
    },
    DspInstrEntry {
        mnemonic: "cmp.eq.ph",
        description: "Compare Equal Two Fractional Halfwords",
    },
    DspInstrEntry {
        mnemonic: "cmp.lt.ph",
        description: "Compare Less Than Two Fractional Halfwords",
    },
    DspInstrEntry {
        mnemonic: "cmp.le.ph",
        description: "Compare Less Than or Equal Two Fractional Halfwords",
    },
    DspInstrEntry {
        mnemonic: "cmpgu.eq.qb",
        description: "Compare Unsigned Byte Vectors, Set GPR Bits",
    },
    DspInstrEntry {
        mnemonic: "cmpu.eq.qb",
        description: "Compare Unsigned Four Byte Vectors",
    },
    DspInstrEntry {
        mnemonic: "dpa.w.ph",
        description: "Dot Product with Accumulate",
    },
    DspInstrEntry {
        mnemonic: "dpaq_s.w.ph",
        description: "Dot Product and Accumulate Saturate",
    },
    DspInstrEntry {
        mnemonic: "dpau.h.qbl",
        description: "Dot Product and Accumulate Unsigned High",
    },
    DspInstrEntry {
        mnemonic: "dpsu.h.qbl",
        description: "Dot Product and Subtract Unsigned High",
    },
    DspInstrEntry {
        mnemonic: "extp",
        description: "Extract Accumulator to Register",
    },
    DspInstrEntry {
        mnemonic: "extpdp",
        description: "Extract Accumulator to Register with Pointer",
    },
    DspInstrEntry {
        mnemonic: "extpdpv",
        description: "Extract Accumulator to Register with Pointer Variable",
    },
    DspInstrEntry {
        mnemonic: "extpv",
        description: "Extract Accumulator to Register Variable",
    },
    DspInstrEntry {
        mnemonic: "extr.w",
        description: "Extract Accumulator to Word",
    },
    DspInstrEntry {
        mnemonic: "extr_r.w",
        description: "Extract Accumulator to Word with Rounding",
    },
    DspInstrEntry {
        mnemonic: "extr_rs.w",
        description: "Extract Accumulator to Word Saturate with Rounding",
    },
    DspInstrEntry {
        mnemonic: "extr_s.h",
        description: "Extract Accumulator to Saturated Halfword",
    },
    DspInstrEntry {
        mnemonic: "extrv.w",
        description: "Extract Accumulator to Word Variable",
    },
    DspInstrEntry {
        mnemonic: "insv",
        description: "Insert Bit Field from Variable",
    },
    DspInstrEntry {
        mnemonic: "lbux",
        description: "Load Byte Unsigned Indexed",
    },
    DspInstrEntry {
        mnemonic: "lhx",
        description: "Load Halfword Indexed",
    },
    DspInstrEntry {
        mnemonic: "lwx",
        description: "Load Word Indexed",
    },
    DspInstrEntry {
        mnemonic: "maq_s.w.phl",
        description: "Multiply and Add to Accumulator Saturate",
    },
    DspInstrEntry {
        mnemonic: "maq_sa.w.phl",
        description: "Multiply and Add to Accumulator Saturate (2)",
    },
    DspInstrEntry {
        mnemonic: "modsub",
        description: "Modular Subtract",
    },
    DspInstrEntry {
        mnemonic: "msub",
        description: "Multiply and Subtract",
    },
    DspInstrEntry {
        mnemonic: "muleq_s.w.phl",
        description: "Multiply to Accumulator",
    },
    DspInstrEntry {
        mnemonic: "muleu_s.ph.qbl",
        description: "Multiply Unsigned to Fractional Halfword",
    },
    DspInstrEntry {
        mnemonic: "mulq_rs.ph",
        description: "Multiply Fractional Halfwords with Rounding Saturate",
    },
    DspInstrEntry {
        mnemonic: "mulsaq_s.w.ph",
        description: "Multiply and Subtract Accumulate Saturate",
    },
    DspInstrEntry {
        mnemonic: "mult",
        description: "Multiply Words (DSP version sets ACChi)",
    },
    DspInstrEntry {
        mnemonic: "packrl.ph",
        description: "Pack Right-Left Halfwords",
    },
    DspInstrEntry {
        mnemonic: "pick.ph",
        description: "Pick Halfword Pairs Based on CCond",
    },
    DspInstrEntry {
        mnemonic: "pick.qb",
        description: "Pick Byte Quads Based on CCond",
    },
    DspInstrEntry {
        mnemonic: "preceq.w.phl",
        description: "Precondition Halfword to Word (left)",
    },
    DspInstrEntry {
        mnemonic: "precequ.ph.qbl",
        description: "Precondition Byte to Halfword Unsigned",
    },
    DspInstrEntry {
        mnemonic: "preceu.ph.qbl",
        description: "Precondition Byte to Halfword",
    },
    DspInstrEntry {
        mnemonic: "precr.qb.ph",
        description: "Reduce to Half Precision and Pack",
    },
    DspInstrEntry {
        mnemonic: "precrq.ph.w",
        description: "Reduce to Halfword and Pack",
    },
    DspInstrEntry {
        mnemonic: "precrq.qb.ph",
        description: "Reduce to Byte and Pack",
    },
    DspInstrEntry {
        mnemonic: "precrqu_s.qb.ph",
        description: "Reduce to Byte, Unsigned Saturate, and Pack",
    },
    DspInstrEntry {
        mnemonic: "raddu.w.qb",
        description: "Reduce Unsigned Four Bytes to Word",
    },
    DspInstrEntry {
        mnemonic: "rddsp",
        description: "Read DSPControl Register",
    },
    DspInstrEntry {
        mnemonic: "repl.ph",
        description: "Replicate Immediate in Halfwords",
    },
    DspInstrEntry {
        mnemonic: "repl.qb",
        description: "Replicate Byte",
    },
    DspInstrEntry {
        mnemonic: "replv.ph",
        description: "Replicate Variable Halfwords",
    },
    DspInstrEntry {
        mnemonic: "replv.qb",
        description: "Replicate Variable Bytes",
    },
    DspInstrEntry {
        mnemonic: "shilo",
        description: "Shift Accumulator",
    },
    DspInstrEntry {
        mnemonic: "shilov",
        description: "Shift Accumulator Variable",
    },
    DspInstrEntry {
        mnemonic: "shll.ph",
        description: "Shift Left Halfwords",
    },
    DspInstrEntry {
        mnemonic: "shll.qb",
        description: "Shift Left Bytes",
    },
    DspInstrEntry {
        mnemonic: "shll_s.ph",
        description: "Shift Left Halfwords Saturate",
    },
    DspInstrEntry {
        mnemonic: "shll_s.w",
        description: "Shift Left Word Saturate",
    },
    DspInstrEntry {
        mnemonic: "shra.ph",
        description: "Shift Right Arithmetic Halfwords",
    },
    DspInstrEntry {
        mnemonic: "shra_r.ph",
        description: "Shift Right Arithmetic Halfwords Rounding",
    },
    DspInstrEntry {
        mnemonic: "shra_r.w",
        description: "Shift Right Arithmetic Word Rounding",
    },
    DspInstrEntry {
        mnemonic: "shrl.ph",
        description: "Shift Right Logical Halfwords",
    },
    DspInstrEntry {
        mnemonic: "shrl.qb",
        description: "Shift Right Logical Bytes",
    },
    DspInstrEntry {
        mnemonic: "subq.ph",
        description: "Subtract Two Fractional Halfwords",
    },
    DspInstrEntry {
        mnemonic: "subq_s.ph",
        description: "Subtract Two Fractional Halfwords Saturate",
    },
    DspInstrEntry {
        mnemonic: "subq_s.w",
        description: "Subtract Fractional Word Saturate",
    },
    DspInstrEntry {
        mnemonic: "subu.qb",
        description: "Subtract Four Unsigned Bytes",
    },
    DspInstrEntry {
        mnemonic: "subu_s.qb",
        description: "Subtract Four Unsigned Bytes Saturate",
    },
    DspInstrEntry {
        mnemonic: "wrdsp",
        description: "Write DSPControl Register",
    },
];

// ===========================================================================
// MIPS SmartMIPS ASE
// ===========================================================================

/// `SmartMIPS` ASE instruction entry.
#[derive(Debug, Clone, Copy)]
pub struct SmartMipsEntry {
    pub mnemonic: &'static str,
    pub description: &'static str,
}

pub static SMARTMIPS_INSTRS: &[SmartMipsEntry] = &[
    SmartMipsEntry {
        mnemonic: "mflhxu",
        description: "Move From LHX Register (unsigned)",
    },
    SmartMipsEntry {
        mnemonic: "mtlhx",
        description: "Move To LHX Register",
    },
    SmartMipsEntry {
        mnemonic: "mulhi",
        description: "Multiply High (signed)",
    },
    SmartMipsEntry {
        mnemonic: "mulhiu",
        description: "Multiply High Unsigned",
    },
    SmartMipsEntry {
        mnemonic: "mulo",
        description: "Multiply with Overflow",
    },
    SmartMipsEntry {
        mnemonic: "mulou",
        description: "Multiply Unsigned with Overflow",
    },
    SmartMipsEntry {
        mnemonic: "mad",
        description: "Multiply and Add",
    },
    SmartMipsEntry {
        mnemonic: "madu",
        description: "Multiply and Add Unsigned",
    },
];

// ===========================================================================
// MIPS Virtual Machine (MIPS Hypervisor)
// ===========================================================================

/// MIPS Virtualization (VZ) ASE instruction entry.
#[derive(Debug, Clone, Copy)]
pub struct VzInstrEntry {
    pub mnemonic: &'static str,
    pub description: &'static str,
}

pub static MIPS_VZ_INSTRS: &[VzInstrEntry] = &[
    VzInstrEntry {
        mnemonic: "hypcall",
        description: "Hypervisor Call",
    },
    VzInstrEntry {
        mnemonic: "mfgc0",
        description: "Move from Guest Coprocessor 0",
    },
    VzInstrEntry {
        mnemonic: "mtgc0",
        description: "Move to Guest Coprocessor 0",
    },
    VzInstrEntry {
        mnemonic: "mfhgc0",
        description: "Move from High Guest Coprocessor 0",
    },
    VzInstrEntry {
        mnemonic: "mthgc0",
        description: "Move to High Guest Coprocessor 0",
    },
    VzInstrEntry {
        mnemonic: "tlbginvf",
        description: "Guest TLB Invalidate Flush",
    },
    VzInstrEntry {
        mnemonic: "tlbgp",
        description: "Guest TLB Probe",
    },
    VzInstrEntry {
        mnemonic: "tlbgr",
        description: "Guest TLB Read",
    },
    VzInstrEntry {
        mnemonic: "tlbgwi",
        description: "Guest TLB Write Indexed",
    },
    VzInstrEntry {
        mnemonic: "tlbgwr",
        description: "Guest TLB Write Random",
    },
    VzInstrEntry {
        mnemonic: "eret",
        description: "Return from Exception (also used in guest)",
    },
    VzInstrEntry {
        mnemonic: "eretnc",
        description: "Return from Exception No Clear",
    },
];

// ===========================================================================
// MIPS CPS (Coherent Processing System) instructions
// ===========================================================================

/// CPS instruction entry.
#[derive(Debug, Clone, Copy)]
pub struct CpsInstrEntry {
    pub mnemonic: &'static str,
    pub description: &'static str,
}

pub static MIPS_CPS_INSTRS: &[CpsInstrEntry] = &[
    CpsInstrEntry {
        mnemonic: "dvpe",
        description: "Disable Virtual Processor Element",
    },
    CpsInstrEntry {
        mnemonic: "evpe",
        description: "Enable Virtual Processor Element",
    },
    CpsInstrEntry {
        mnemonic: "dmt",
        description: "Disable Multi-Threading",
    },
    CpsInstrEntry {
        mnemonic: "emt",
        description: "Enable Multi-Threading",
    },
    CpsInstrEntry {
        mnemonic: "fork",
        description: "Fork a New Thread",
    },
    CpsInstrEntry {
        mnemonic: "yield",
        description: "Yield Thread",
    },
    CpsInstrEntry {
        mnemonic: "mftr",
        description: "Move from Thread Register",
    },
    CpsInstrEntry {
        mnemonic: "mttr",
        description: "Move to Thread Register",
    },
];

// ===========================================================================
// MIPS disassembly report
// ===========================================================================

/// A summary report from a disassembly pass.
#[derive(Debug, Default, Clone)]
pub struct DisassemblyReport {
    pub arch_name: String,
    pub base_address: u64,
    pub byte_count: usize,
    pub instr_count: usize,
    pub code_density: f64,
    pub stats: MipsCodeStats,
    pub hazard_count: usize,
    pub call_edge_count: usize,
}

impl DisassemblyReport {
    /// Generate a report from a byte slice.
    #[must_use]
    pub fn generate(arch: &MipsArch, bytes: &[u8], base: Address) -> Self {
        let stats = MipsCodeStats::from_bytes(arch, bytes, base);
        let instrs: Vec<Instruction> = MipsLinearDisassembler::new(arch, bytes, base)
            .filter_map(Result::ok)
            .collect();
        let hazards = find_hazards(&instrs);
        let call_edges = build_call_graph(arch, bytes, base);
        let code_density = if bytes.is_empty() {
            0.0
        } else {
            count_as_f64(stats.total) / (count_as_f64(bytes.len()) / 4.0)
        };

        Self {
            arch_name: arch.name().to_string(),
            base_address: base.0,
            byte_count: bytes.len(),
            instr_count: stats.total,
            code_density,
            stats,
            hazard_count: hazards.len(),
            call_edge_count: call_edges.len(),
        }
    }

    /// Return a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Arch: {} | Base: 0x{:08x} | Bytes: {} | Instrs: {} | \
             Density: {:.1}% | Loads: {} | Stores: {} | Branches: {} | \
             Calls: {} | ALU: {} | FP: {} | Hazards: {} | CallEdges: {}",
            self.arch_name,
            self.base_address,
            self.byte_count,
            self.instr_count,
            self.code_density * 100.0,
            self.stats.loads,
            self.stats.stores,
            self.stats.branches,
            self.stats.calls,
            self.stats.alu,
            self.stats.fp_ops,
            self.hazard_count,
            self.call_edge_count,
        )
    }
}

// ===========================================================================
// Final comprehensive tests
// ===========================================================================

#[cfg(test)]
mod tests_final {
    use super::*;

    fn le(word: u32) -> [u8; 4] {
        word.to_le_bytes()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }
    fn arch32le() -> MipsArch {
        MipsArch::mips32_le()
    }

    // ── DSP table has entries ──────────────────────────────────────────────
    #[test]
    fn test_dsp_table() {
        assert!(!MIPS_DSP_INSTRS.is_empty());
        let e = MIPS_DSP_INSTRS
            .iter()
            .find(|e| e.mnemonic == "rddsp")
            .unwrap();
        assert!(e.description.contains("DSPControl"));
    }

    // ── VZ instructions table ─────────────────────────────────────────────
    #[test]
    fn test_vz_table() {
        assert!(!MIPS_VZ_INSTRS.is_empty());
        let e = MIPS_VZ_INSTRS
            .iter()
            .find(|e| e.mnemonic == "hypcall")
            .unwrap();
        assert!(e.description.contains("Hypervisor"));
    }

    // ── CPS instructions table ────────────────────────────────────────────
    #[test]
    fn test_cps_table() {
        assert!(!MIPS_CPS_INSTRS.is_empty());
        assert!(MIPS_CPS_INSTRS.iter().any(|e| e.mnemonic == "dvpe"));
    }

    // ── DisassemblyReport generate ────────────────────────────────────────
    #[test]
    fn test_disassembly_report() {
        let ws = [
            encode_itype(0x23, 2, 1, 4),    // lw
            encode_itype(0x2B, 2, 1, 4),    // sw
            encode_rtype(1, 2, 3, 0, 0x20), // add
            encode_jtype(0x03, 0x400),      // jal
            0u32,                           // nop (delay slot)
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let arch = arch32le();
        let report = DisassemblyReport::generate(&arch, &bytes, addr(0x1000));
        assert_eq!(report.instr_count, 5);
        assert_eq!(report.stats.loads, 1);
        assert_eq!(report.stats.stores, 1);
        assert_eq!(report.stats.calls, 1);
        let s = report.summary();
        assert!(s.contains("mips32le"));
        assert!(s.contains('5'));
    }

    // ── MipsClass is_control ──────────────────────────────────────────────
    #[test]
    fn test_class_is_control() {
        assert!(MipsClass::Branch.is_control());
        assert!(MipsClass::Jump.is_control());
        assert!(!MipsClass::Load.is_control());
    }

    // ── BranchPredictor multiple addresses ───────────────────────────────
    #[test]
    fn test_bp_multiple() {
        let mut bp = BranchPredictor::default();
        for addr in [0x1000u64, 0x2000, 0x3000] {
            bp.update(addr, true);
        }
        assert_eq!(bp.len(), 3);
        assert!(bp.predict_taken(0x1000));
        assert!(!bp.predict_taken(0x4000));
    }

    // ── SmartMIPS table ───────────────────────────────────────────────────
    #[test]
    fn test_smartmips_table() {
        assert!(!SMARTMIPS_INSTRS.is_empty());
        assert!(SMARTMIPS_INSTRS.iter().any(|e| e.mnemonic == "mulhi"));
    }

    // ── FormatOptions with show_bytes ─────────────────────────────────────
    #[test]
    fn test_format_with_bytes() {
        let w = encode_rtype(1, 2, 3, 0, 0x20);
        let i = arch32le().disassemble(addr(0x1000), &le(w)).unwrap();
        let opts = FormatOptions {
            show_bytes: true,
            ..FormatOptions::default()
        };
        let s = format_instruction(&i, false, &opts);
        // Should contain hex bytes
        assert!(s.contains("20") || s.contains("00"));
    }

    // ── find_pattern no match ─────────────────────────────────────────────
    #[test]
    fn test_find_pattern_no_match() {
        let ws = [
            encode_rtype(1, 2, 3, 0, 0x20),
            encode_rtype(31, 0, 0, 0, 0x08),
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let arch = arch32le();
        let instrs: Vec<_> = MipsLinearDisassembler::new(&arch, &bytes, addr(0))
            .filter_map(Result::ok)
            .collect();
        let pats = [InstrPattern::new("lw")];
        assert!(find_pattern(&instrs, &pats).is_empty());
    }

    // ── DIVU ──────────────────────────────────────────────────────────────
    #[test]
    fn test_divu() {
        let w = encode_rtype(2, 3, 0, 0, 0x1B);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "divu");
    }

    // ── MULTU ─────────────────────────────────────────────────────────────
    #[test]
    fn test_multu() {
        let w = encode_rtype(2, 3, 0, 0, 0x19);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "multu");
    }

    // ── SLTI / SLTIU ─────────────────────────────────────────────────────
    #[test]
    fn test_slti_sltiu() {
        let arch = arch32le();
        let slti = encode_itype(0x0A, 1, 3, 5);
        let sltiu = encode_itype(0x0B, 1, 3, 5);
        assert_eq!(
            arch.disassemble(addr(0), &le(slti)).unwrap().mnemonic,
            "slti"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(sltiu)).unwrap().mnemonic,
            "sltiu"
        );
    }

    // ── XORI ─────────────────────────────────────────────────────────────
    #[test]
    fn test_xori() {
        let w = encode_itype(0x0E, 1, 3, 0xFF);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "xori");
    }

    // ── LDL / LDR (MIPS64) ───────────────────────────────────────────────
    #[test]
    fn test_ldl_ldr() {
        let arch = MipsArch::mips64_le();
        let ldl = encode_itype(0x1A, 4, 2, 0);
        let ldr = encode_itype(0x1B, 4, 2, 0);
        assert_eq!(arch.disassemble(addr(0), &le(ldl)).unwrap().mnemonic, "ldl");
        assert_eq!(arch.disassemble(addr(0), &le(ldr)).unwrap().mnemonic, "ldr");
    }

    // ── SDC2 / LDC2 ──────────────────────────────────────────────────────
    #[test]
    fn test_sdc2_ldc2() {
        let arch = arch32le();
        let ldc2 = encode_itype(0x36, 4, 2, 0);
        let sdc2 = encode_itype(0x3E, 4, 2, 0);
        assert_eq!(
            arch.disassemble(addr(0), &le(ldc2)).unwrap().mnemonic,
            "ldc2"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(sdc2)).unwrap().mnemonic,
            "sdc2"
        );
    }

    // ── DERET (COP0 CO) ───────────────────────────────────────────────────
    #[test]
    fn test_deret() {
        let w: u32 = (0x10 << 26) | (0x10 << 21) | 0x1F;
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "deret");
    }

    // ── WAIT (COP0 CO) ────────────────────────────────────────────────────
    #[test]
    fn test_wait() {
        let w: u32 = (0x10 << 26) | (0x10 << 21) | 0x20;
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "wait");
    }

    // ── encode_syscall round-trip ─────────────────────────────────────────
    #[test]
    fn test_encode_syscall_rt() {
        let w = encode_syscall(0);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "syscall");
    }

    // ── LWL / LWR ────────────────────────────────────────────────────────
    #[test]
    fn test_lwl_lwr() {
        let arch = arch32le();
        assert_eq!(
            arch.disassemble(addr(0), &le(encode_itype(0x22, 4, 2, 0)))
                .unwrap()
                .mnemonic,
            "lwl"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(encode_itype(0x26, 4, 2, 0)))
                .unwrap()
                .mnemonic,
            "lwr"
        );
    }

    // ── SWL / SWR ────────────────────────────────────────────────────────
    #[test]
    fn test_swl_swr() {
        let arch = arch32le();
        assert_eq!(
            arch.disassemble(addr(0), &le(encode_itype(0x2A, 4, 2, 0)))
                .unwrap()
                .mnemonic,
            "swl"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(encode_itype(0x2E, 4, 2, 0)))
                .unwrap()
                .mnemonic,
            "swr"
        );
    }

    // ── BGEZL / BLTZL (branch-likely REGIMM) ─────────────────────────────
    #[test]
    fn test_bgezl_bltzl() {
        let arch = arch32le();
        let bltzl = encode_itype(0x01, 3, 0x02, 4);
        let bgezl = encode_itype(0x01, 3, 0x03, 4);
        assert_eq!(
            arch.disassemble(addr(0), &le(bltzl)).unwrap().mnemonic,
            "bltzl"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(bgezl)).unwrap().mnemonic,
            "bgezl"
        );
    }

    // ── BLTZAL / BGEZAL ──────────────────────────────────────────────────
    #[test]
    fn test_bltzal_bgezal() {
        let arch = arch32le();
        let bltzal = encode_itype(0x01, 3, 0x10, 4);
        let bgezal = encode_itype(0x01, 3, 0x11, 4);
        let bltzall = encode_itype(0x01, 3, 0x12, 4);
        let bgezall = encode_itype(0x01, 3, 0x13, 4);
        assert_eq!(
            arch.disassemble(addr(0), &le(bltzal)).unwrap().mnemonic,
            "bltzal"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(bgezal)).unwrap().mnemonic,
            "bgezal"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(bltzall)).unwrap().mnemonic,
            "bltzall"
        );
        assert_eq!(
            arch.disassemble(addr(0), &le(bgezall)).unwrap().mnemonic,
            "bgezall"
        );
    }

    // ── SYNCI ────────────────────────────────────────────────────────────
    #[test]
    fn test_synci() {
        let w = encode_itype(0x01, 4, 0x1F, 8);
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "synci");
        assert!(i.flags.contains(InstrFlags::BARRIER));
    }

    // ── BREAK code field ─────────────────────────────────────────────────
    #[test]
    fn test_break_code() {
        let w = encode_rtype(0, 0, 0, 0, 0x0D); // break code=0
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "break");
        assert!(i.flags.contains(InstrFlags::BARRIER));
    }

    // ── COP2 ─────────────────────────────────────────────────────────────
    #[test]
    fn test_cop2() {
        let w: u32 = (0x12 << 26) | 0x1234;
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        assert_eq!(i.mnemonic, "cop2");
    }

    // ── MipsFields J-type ─────────────────────────────────────────────────
    #[test]
    fn test_fields_jtype() {
        let w = encode_jtype(0x03, 0x1234);
        let f = MipsFields::decode(w);
        assert_eq!(f.opcode, 3);
        assert_eq!(f.target26, 0x1234);
    }
}

// ===========================================================================
// MIPS memory map constants (common Linux/embedded layouts)
// ===========================================================================

/// Well-known MIPS32 memory segment constants.
pub mod mips_segments {
    /// KUSEG: user virtual address space (0x00000000–0x7FFFFFFF).
    pub const KUSEG_BASE: u32 = 0x0000_0000;
    pub const KUSEG_SIZE: u32 = 0x8000_0000;

    /// KSEG0: cached kernel (0x80000000–0x9FFFFFFF), maps to PA 0x00000000.
    pub const KSEG0_BASE: u32 = 0x8000_0000;
    pub const KSEG0_SIZE: u32 = 0x2000_0000;

    /// KSEG1: uncached kernel (0xA0000000–0xBFFFFFFF), maps to PA 0x00000000.
    pub const KSEG1_BASE: u32 = 0xA000_0000;
    pub const KSEG1_SIZE: u32 = 0x2000_0000;

    /// KSEG2: TLB-mapped kernel (0xC0000000–0xFFFFFFFF).
    pub const KSEG2_BASE: u32 = 0xC000_0000;
    pub const KSEG2_SIZE: u32 = 0x4000_0000;

    /// Convert KSEG0/1 virtual to physical address.
    #[must_use]
    pub const fn virt_to_phys(vaddr: u32) -> u32 {
        vaddr & 0x1FFF_FFFF
    }

    /// Convert physical address to KSEG0 virtual.
    #[must_use]
    pub const fn phys_to_kseg0(paddr: u32) -> u32 {
        paddr | KSEG0_BASE
    }

    /// Convert physical address to KSEG1 virtual.
    #[must_use]
    pub const fn phys_to_kseg1(paddr: u32) -> u32 {
        paddr | KSEG1_BASE
    }

    /// Determine which segment a virtual address is in.
    #[must_use]
    pub const fn segment_name(vaddr: u32) -> &'static str {
        match vaddr {
            0x0000_0000..=0x7FFF_FFFF => "KUSEG",
            0x8000_0000..=0x9FFF_FFFF => "KSEG0",
            0xA000_0000..=0xBFFF_FFFF => "KSEG1",
            _ => "KSEG2",
        }
    }
}

// ===========================================================================
// MIPS TLB model
// ===========================================================================

/// A single TLB entry in a MIPS32 TLB.
#[derive(Debug, Clone, Default)]
pub struct TlbEntry {
    pub vpn2: u32, // Virtual page number / 2
    pub asid: u8,  // Address Space ID
    pub pfn0: u32, // Physical frame number (even page)
    pub pfn1: u32, // Physical frame number (odd page)
    pub c0: u8,    // Cache attributes (even)
    pub c1: u8,    // Cache attributes (odd)
    /// Per-page dirty/valid bits for the even and odd page of the pair.
    pub flags: TlbFlags,
    pub global: bool,
}

/// The dirty and valid bit of ONE page of a TLB entry pair.
///
/// Mirrors the two writable state bits of a single `EntryLo` register.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TlbPageFlags {
    /// Page has been written to and must be written back.
    pub dirty: bool,
    /// Translation for this page is valid.
    pub valid: bool,
}

impl TlbPageFlags {
    /// A page that is both valid and dirty (writable, resident).
    #[must_use]
    pub const fn valid_dirty() -> Self {
        Self { dirty: true, valid: true }
    }

    /// A page with neither bit set (no translation).
    #[must_use]
    pub const fn none() -> Self {
        Self { dirty: false, valid: false }
    }
}

/// The dirty and valid bits of a TLB entry's even/odd page pair.
///
/// The four bits travel together in hardware (EntryLo0/EntryLo1), so they are
/// modelled as one value rather than four independent booleans.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TlbFlags(u8);

impl TlbFlags {
    /// Dirty (writable) bit of the even page.
    pub const DIRTY0: u8 = 1 << 0;
    /// Dirty (writable) bit of the odd page.
    pub const DIRTY1: u8 = 1 << 1;
    /// Valid bit of the even page.
    pub const VALID0: u8 = 1 << 2;
    /// Valid bit of the odd page.
    pub const VALID1: u8 = 1 << 3;

    /// Build a flag set from the even and the odd page's bits.
    ///
    /// The bits are grouped per PAGE rather than passed as four loose
    /// booleans, which is both how the hardware stores them (one `EntryLo`
    /// register per page) and what stops a caller from silently swapping
    /// `dirty1` with `valid0` at a call site.
    #[must_use]
    pub const fn new(even: TlbPageFlags, odd: TlbPageFlags) -> Self {
        let mut bits = 0u8;
        if even.dirty {
            bits |= Self::DIRTY0;
        }
        if odd.dirty {
            bits |= Self::DIRTY1;
        }
        if even.valid {
            bits |= Self::VALID0;
        }
        if odd.valid {
            bits |= Self::VALID1;
        }
        Self(bits)
    }

    /// Build a flag set directly from the raw bit pattern.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & (Self::DIRTY0 | Self::DIRTY1 | Self::VALID0 | Self::VALID1))
    }

    /// The raw bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// True when every bit in `mask` is present.
    #[must_use]
    pub const fn contains(self, mask: u8) -> bool {
        self.0 & mask == mask
    }

    /// Dirty bit of the even page.
    #[must_use]
    pub const fn dirty0(self) -> bool {
        self.contains(Self::DIRTY0)
    }

    /// Dirty bit of the odd page.
    #[must_use]
    pub const fn dirty1(self) -> bool {
        self.contains(Self::DIRTY1)
    }

    /// Valid bit of the even page.
    #[must_use]
    pub const fn valid0(self) -> bool {
        self.contains(Self::VALID0)
    }

    /// Valid bit of the odd page.
    #[must_use]
    pub const fn valid1(self) -> bool {
        self.contains(Self::VALID1)
    }
}

impl TlbEntry {
    /// Create a 4KB direct-mapped TLB entry.
    #[must_use]
    pub const fn map_4k(vaddr: u32, paddr: u32, asid: u8) -> Self {
        // Determine whether vaddr falls on the even or odd page of the TLB pair.
        // VPN2 covers two 4 KB pages; bit 12 of vaddr selects even (0) or odd (1).
        let odd = (vaddr >> 12) & 1 != 0;
        let pfn = paddr >> 12;
        Self {
            vpn2: vaddr >> 13,
            asid,
            pfn0: if odd { pfn.wrapping_sub(1) } else { pfn },
            pfn1: if odd { pfn } else { pfn + 1 },
            c0: 3, // cacheable, non-coherent, write-back
            c1: 3,
            flags: if odd {
                TlbFlags::new(TlbPageFlags::none(), TlbPageFlags::valid_dirty())
            } else {
                TlbFlags::new(TlbPageFlags::valid_dirty(), TlbPageFlags::none())
            },
            global: false,
        }
    }

    /// Translate a virtual address through this TLB entry.
    /// Returns `Some(paddr)` on hit, `None` on miss.
    #[must_use]
    pub const fn translate(&self, vaddr: u32, asid: u8) -> Option<u32> {
        if !self.global && self.asid != asid {
            return None;
        }
        if (vaddr >> 13) != self.vpn2 {
            return None;
        }
        let even = (vaddr >> 12) & 1 == 0;
        if even {
            if !self.flags.valid0() {
                return None;
            }
            Some((self.pfn0 << 12) | (vaddr & 0xFFF))
        } else {
            if !self.flags.valid1() {
                return None;
            }
            Some((self.pfn1 << 12) | (vaddr & 0xFFF))
        }
    }
}

// ===========================================================================
// MIPS CP0 Status Register bit fields
// ===========================================================================

/// CP0 Status register bit positions.
pub mod cp0_status {
    /// Interrupt Enable (IE) bit — enables interrupts when set.
    pub const IE: u32 = 0;
    /// Exception Level (EXL) — set when taking an exception.
    pub const EXL: u32 = 1;
    /// Error Level (ERL) — set when taking a reset/NMI.
    pub const ERL: u32 = 2;
    /// KSU mode: 0=kernel, 1=supervisor, 2=user.
    pub const KSU: u32 = 3;
    /// User mode (UM) shorthand.
    pub const UM: u32 = 4;
    /// Upper mode (R0) field start.
    pub const R0: u32 = 5;
    /// Interrupt Mask (IM) field: bits 8-15 enable hardware interrupts.
    pub const IM: u32 = 8;
    /// Soft reset (SR) bit.
    pub const SR: u32 = 20;
    /// NMI (NMI) bit.
    pub const NMI: u32 = 19;
    /// BEV — bootstrap exception vectors.
    pub const BEV: u32 = 22;
    /// FPU enable (CU1) bit.
    pub const CU1: u32 = 29;
    /// COP0 usable in user mode (CU0) bit.
    pub const CU0: u32 = 28;

    /// Test a bit in a status register value.
    #[must_use]
    pub const fn test(status: u32, bit: u32) -> bool {
        (status >> bit) & 1 != 0
    }

    /// Is the CPU in kernel mode?
    #[must_use]
    pub const fn is_kernel_mode(status: u32) -> bool {
        !test(status, UM) || test(status, EXL) || test(status, ERL)
    }
}

// ===========================================================================
// MIPS Cause register fields
// ===========================================================================

/// CP0 Cause register field helpers.
pub mod cp0_cause {
    /// Exception code field (bits 6:2).
    pub const EXC_CODE_SHIFT: u32 = 2;
    pub const EXC_CODE_MASK: u32 = 0x1F;

    /// Extract the exception code.
    #[must_use]
    pub const fn exc_code(cause: u32) -> u32 {
        (cause >> EXC_CODE_SHIFT) & EXC_CODE_MASK
    }

    /// Exception code names.
    #[must_use]
    pub const fn exc_name(code: u32) -> &'static str {
        match code {
            0 => "Int",
            1 => "Mod",
            2 => "TLBL",
            3 => "TLBS",
            4 => "AdEL",
            5 => "AdES",
            6 => "IBE",
            7 => "DBE",
            8 => "Sys",
            9 => "Bp",
            10 => "RI",
            11 => "CpU",
            12 => "Ov",
            13 => "Tr",
            14 => "MSAFPE",
            15 => "FPE",
            21 => "IS1",
            22 => "CEU",
            23 => "C2E",
            26 => "TLBRI",
            27 => "TLBXI",
            30 => "CacheErr",
            _ => "Unknown",
        }
    }

    /// Branch Delay (BD) bit — was the exception taken in a delay slot?
    pub const BD_BIT: u32 = 31;

    #[must_use]
    pub const fn in_delay_slot(cause: u32) -> bool {
        (cause >> BD_BIT) & 1 != 0
    }
}

// ===========================================================================
// Tests for memory model, TLB, and CP0 helpers
// ===========================================================================

#[cfg(test)]
mod tests_system {
    use super::*;
    use cp0_cause::*;
    use cp0_status::*;
    use mips_segments::*;

    // ── segment classification ────────────────────────────────────────────
    #[test]
    fn test_segments() {
        assert_eq!(segment_name(0x0000_1000), "KUSEG");
        assert_eq!(segment_name(0x8000_0000), "KSEG0");
        assert_eq!(segment_name(0xA000_0000), "KSEG1");
        assert_eq!(segment_name(0xC000_0000), "KSEG2");
    }

    // ── virt/phys conversion ──────────────────────────────────────────────
    #[test]
    fn test_virt_phys() {
        assert_eq!(virt_to_phys(0x8000_4000), 0x0000_4000);
        assert_eq!(virt_to_phys(0xA000_4000), 0x0000_4000);
        assert_eq!(phys_to_kseg0(0x0000_1000), 0x8000_1000);
        assert_eq!(phys_to_kseg1(0x0000_1000), 0xA000_1000);
    }

    // ── TLB entry map + translate ─────────────────────────────────────────
    #[test]
    fn test_tlb_entry() {
        let e = TlbEntry::map_4k(0x1000, 0x5000, 42);
        // Hit on the even page
        let pa = e.translate(0x1000, 42);
        assert_eq!(pa, Some(0x5000));
        // Hit with offset
        let pa2 = e.translate(0x1ABC, 42);
        assert_eq!(pa2, Some(0x5ABC));
        // ASID mismatch
        assert_eq!(e.translate(0x1000, 99), None);
        // VPN miss
        assert_eq!(e.translate(0x2000, 42), None);
    }

    // ── CP0 status helpers ────────────────────────────────────────────────
    #[test]
    fn test_cp0_status() {
        // IE=1, EXL=0, UM=0 → kernel mode
        let status: u32 = 1 << IE;
        assert!(is_kernel_mode(status));
        assert!(test(status, IE));
        assert!(!test(status, EXL));

        // UM=1, EXL=0, ERL=0 → user mode
        let status2: u32 = 1 << UM;
        assert!(!is_kernel_mode(status2));

        // BEV set
        let status3: u32 = 1 << BEV;
        assert!(test(status3, BEV));
    }

    // ── CP0 cause helpers ─────────────────────────────────────────────────
    #[test]
    fn test_cp0_cause() {
        // ExcCode = 8 (Sys), not in delay slot
        let cause: u32 = 8 << EXC_CODE_SHIFT;
        assert_eq!(exc_code(cause), 8);
        assert_eq!(exc_name(8), "Sys");
        assert!(!in_delay_slot(cause));

        // BD bit set
        let cause2 = cause | (1 << BD_BIT);
        assert!(in_delay_slot(cause2));
    }

    // ── exc_name coverage ─────────────────────────────────────────────────
    #[test]
    fn test_exc_name_coverage() {
        assert_eq!(exc_name(0), "Int");
        assert_eq!(exc_name(2), "TLBL");
        assert_eq!(exc_name(12), "Ov");
        assert_eq!(exc_name(99), "Unknown");
    }

    // ── MIPS segment boundary checks ─────────────────────────────────────
    #[test]
    fn test_segment_boundaries() {
        assert_eq!(KSEG0_BASE, 0x8000_0000);
        assert_eq!(KSEG1_BASE, 0xA000_0000);
        assert_eq!(KSEG0_SIZE, 0x2000_0000);
        assert_eq!(KSEG1_SIZE, 0x2000_0000);
        assert_eq!(KSEG2_BASE, 0xC000_0000);
    }

    // ── DisassemblyReport summary string ─────────────────────────────────
    #[test]
    fn test_report_summary_format() {
        let r = DisassemblyReport {
            arch_name: "mips32le".to_string(),
            base_address: 0x8000_0000,
            byte_count: 16,
            instr_count: 4,
            code_density: 1.0,
            stats: MipsCodeStats::default(),
            hazard_count: 0,
            call_edge_count: 0,
        };
        let s = r.summary();
        assert!(s.contains("mips32le"));
        assert!(s.contains("80000000"));
    }
}

// ===========================================================================
// MIPS instruction word validator
// ===========================================================================

/// Check whether a 32-bit word could be a valid MIPS32 instruction.
/// This is a heuristic — it rules out clearly impossible encodings.
#[must_use]
pub const fn is_valid_mips_word(word: u32) -> bool {
    let opcode = (word >> 26) & 0x3F;
    let funct = word & 0x3F;
    match opcode {
        0x00 => {
            // SPECIAL: validate funct
            matches!(
                funct,
                0x00 | 0x01
                    | 0x02
                    | 0x03
                    | 0x04
                    | 0x05
                    | 0x06
                    | 0x07
                    | 0x08
                    | 0x09
                    | 0x0A
                    | 0x0B
                    | 0x0C
                    | 0x0D
                    | 0x0F
                    | 0x10
                    | 0x11
                    | 0x12
                    | 0x13
                    | 0x14
                    | 0x16
                    | 0x17
                    | 0x18
                    | 0x19
                    | 0x1A
                    | 0x1B
                    | 0x1C
                    | 0x1D
                    | 0x1E
                    | 0x1F
                    | 0x20
                    | 0x21
                    | 0x22
                    | 0x23
                    | 0x24
                    | 0x25
                    | 0x26
                    | 0x27
                    | 0x2A
                    | 0x2B
                    | 0x2C
                    | 0x2D
                    | 0x2E
                    | 0x2F
                    | 0x30
                    | 0x31
                    | 0x32
                    | 0x33
                    | 0x34
                    | 0x36
                    | 0x38
                    | 0x3A
                    | 0x3B
                    | 0x3C
                    | 0x3E
                    | 0x3F
            )
        }
        0x01 => {
            // REGIMM: validate rt
            let rt = (word >> 16) & 0x1F;
            matches!(
                rt,
                0x00 | 0x01
                    | 0x02
                    | 0x03
                    | 0x08
                    | 0x09
                    | 0x0A
                    | 0x0B
                    | 0x0C
                    | 0x0E
                    | 0x10
                    | 0x11
                    | 0x12
                    | 0x13
                    | 0x1F
            )
        }
        // All standard opcodes 2-0x3F (with some gaps for reserved)
        0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0A | 0x0B | 0x0C | 0x0D
        | 0x0E | 0x0F | 0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x17 | 0x18 | 0x19
        | 0x1A | 0x1B | 0x1C | 0x1F | 0x20 | 0x21 | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 | 0x27
        | 0x28 | 0x29 | 0x2A | 0x2B | 0x2C | 0x2D | 0x2E | 0x2F | 0x30 | 0x31 | 0x32 | 0x33
        | 0x34 | 0x35 | 0x36 | 0x37 | 0x38 | 0x39 | 0x3A | 0x3C | 0x3D | 0x3E | 0x3F => true,
        _ => false,
    }
}

// ===========================================================================
// MIPS instruction printer (AT&T vs Intel style toggle)
// ===========================================================================

/// Print style for MIPS assembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintStyle {
    /// Standard MIPS assembly: mnemonic dst, src1, src2
    Standard,
    /// Alternate: include hex address of each instruction
    WithHexAddress,
}

/// Print one instruction.
#[must_use]
pub fn print_instr(instr: &Instruction, style: PrintStyle) -> String {
    match style {
        PrintStyle::Standard => {
            if instr.operands.is_empty() {
                instr.mnemonic.clone()
            } else {
                format!("{} {}", instr.mnemonic, instr.operands)
            }
        }
        PrintStyle::WithHexAddress => {
            if instr.operands.is_empty() {
                format!("[{:08x}] {}", instr.address.0, instr.mnemonic)
            } else {
                format!(
                    "[{:08x}] {} {}",
                    instr.address.0, instr.mnemonic, instr.operands
                )
            }
        }
    }
}

// ===========================================================================
// MIPS control flow graph node
// ===========================================================================

/// A node in the MIPS control flow graph.
#[derive(Debug, Clone)]
pub struct CfgNode {
    pub block: MipsBasicBlock,
    pub successors: Vec<u64>,
    pub predecessors: Vec<u64>,
}

impl CfgNode {
    /// Build a CFG from basic blocks.
    #[must_use]
    pub fn build_cfg(arch: &MipsArch, bytes: &[u8], base: Address) -> Vec<Self> {
        let blocks = MipsBasicBlock::find_blocks(arch, bytes, base);
        let mut nodes: Vec<Self> = blocks
            .into_iter()
            .map(|b| Self {
                block: b,
                successors: Vec::new(),
                predecessors: Vec::new(),
            })
            .collect();

        // Determine successors from the last instruction of each block
        let starts: Vec<u64> = nodes.iter().map(|n| n.block.start.0).collect();
        for __item in &mut nodes {
            let last_idx = __item.block.instructions.len().saturating_sub(1);
            if let Some(last) = __item.block.instructions.get(last_idx) {
                if last.flags.intersects(InstrFlags::BRANCH | InstrFlags::RET) {
                    // The delay slot is the second-to-last if the block has ≥2 instrs
                    let branch_idx = __item.block.instructions.len().saturating_sub(2);
                    let branch_info = __item
                        .block
                        .instructions
                        .get(branch_idx)
                        .map(|b| (b.bytes.clone(), b.address, b.flags));
                    if let Some((bytes, baddr, bflags)) = branch_info
                        && let Some(w) = arch.read_word(&bytes)
                    {
                            let opcode = (w >> 26) & 0x3F;
                            let target26 = w & 0x03FF_FFFF;
                            let imm16 = i64::from((w & 0xFFFF) as i16);
                            let target = match opcode {
                                0x02 | 0x03 => Some(branch_target_j(baddr, target26)),
                                0x04 | 0x05 | 0x06 | 0x07 | 0x14 | 0x15 | 0x16 | 0x17 => {
                                    Some(branch_target_i(baddr, imm16))
                                }
                                0x01 => Some(branch_target_i(baddr, imm16)),
                                _ => None,
                            };
                            if let Some(t) = target {
                                __item.successors.push(t);
                                // Fall-through for conditional branches
                                if bflags.contains(InstrFlags::CONDITIONAL) {
                                    let ft = __item.block.start.0
                                        + (__item.block.instructions.len() as u64 * 4);
                                    __item.successors.push(ft);
                                }
                            }
                    }
                } else {
                    // Fall-through
                    let ft =
                        __item.block.start.0 + (__item.block.instructions.len() as u64 * 4);
                    if starts.contains(&ft) {
                        __item.successors.push(ft);
                    }
                }
            }
        }

        // Fill predecessors
        let succs: Vec<(usize, Vec<u64>)> = nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (i, n.successors.clone()))
            .collect();
        for (i, succs_i) in succs {
            let pred_addr = nodes[i].block.start.0;
            for succ in succs_i {
                let pos = nodes.iter().position(|n| n.block.start.0 == succ);
                if let Some(j) = pos {
                    nodes[j].predecessors.push(pred_addr);
                }
            }
        }

        nodes
    }
}

// ===========================================================================
// Final system + CFG tests
// ===========================================================================

#[cfg(test)]
mod tests_cfg {
    use super::*;

    fn le(word: u32) -> [u8; 4] {
        word.to_le_bytes()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }
    fn arch32le() -> MipsArch {
        MipsArch::mips32_le()
    }

    // ── is_valid_mips_word ────────────────────────────────────────────────
    #[test]
    fn test_is_valid() {
        assert!(is_valid_mips_word(0)); // NOP
        assert!(is_valid_mips_word(encode_rtype(1, 2, 3, 0, 0x20))); // ADD
        assert!(is_valid_mips_word(encode_itype(0x23, 2, 1, 4))); // LW
        assert!(is_valid_mips_word(encode_jtype(0x02, 0x100))); // J
    }

    // ── print_instr standard ──────────────────────────────────────────────
    #[test]
    fn test_print_instr_standard() {
        let w = encode_rtype(1, 2, 3, 0, 0x20);
        let i = arch32le().disassemble(addr(0x1000), &le(w)).unwrap();
        let s = print_instr(&i, PrintStyle::Standard);
        assert!(s.starts_with("add"));
        assert!(!s.contains("1000"));
    }

    // ── print_instr with hex address ──────────────────────────────────────
    #[test]
    fn test_print_instr_hex() {
        let w = encode_rtype(1, 2, 3, 0, 0x20);
        let i = arch32le().disassemble(addr(0x4000), &le(w)).unwrap();
        let s = print_instr(&i, PrintStyle::WithHexAddress);
        assert!(s.contains("00004000"));
        assert!(s.contains("add"));
    }

    // ── CFG build basic ───────────────────────────────────────────────────
    #[test]
    fn test_cfg_build() {
        let ws = [
            encode_rtype(1, 2, 3, 0, 0x20), // add — block 1
            encode_jtype(0x02, 0x10),       // j — terminator
            0u32,                           // nop (delay slot)
            encode_rtype(1, 2, 3, 0, 0x21), // addu — block 2 (unreachable)
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let arch = arch32le();
        let nodes = CfgNode::build_cfg(&arch, &bytes, addr(0x1000));
        // Should have at least one block
        assert!(!nodes.is_empty());
        assert_eq!(nodes[0].block.start.0, 0x1000);
    }

    // ── is_valid rejects reserved opcode ─────────────────────────────────
    #[test]
    fn test_invalid_opcode() {
        // opcode 0x1D is unassigned
        let w: u32 = 0x7400_0000; // opcode = 0x1D
        assert!(!is_valid_mips_word(w));
    }

    // ── LiveSet edge cases ────────────────────────────────────────────────
    #[test]
    fn test_live_set_edge() {
        let mut live = LiveSet::default();
        // Out-of-range register
        live.set_live(32);
        assert!(!live.is_live(32));
        live.kill(32);
        // r0 ($zero) liveness
        live.set_live(0);
        assert!(live.is_live(0));
        live.kill(0);
        assert!(!live.is_live(0));
    }

    // ── print_instr no operands ───────────────────────────────────────────
    #[test]
    fn test_print_instr_no_operands() {
        let w = encode_rtype(0, 0, 0, 0, 0x0F); // sync
        let i = arch32le().disassemble(addr(0), &le(w)).unwrap();
        let s = print_instr(&i, PrintStyle::Standard);
        assert!(s.starts_with("sync"));
    }

    // ── StackFrame is_leaf true ───────────────────────────────────────────
    #[test]
    fn test_stack_frame_leaf() {
        // No sw $ra → leaf
        let ws = [encode_itype(0x09, 29, 29, (-16i16).cast_unsigned())]; // addiu $sp,$sp,-16
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let arch = arch32le();
        let instrs: Vec<_> = MipsLinearDisassembler::new(&arch, &bytes, addr(0))
            .filter_map(Result::ok)
            .collect();
        let frame = StackFrame::from_prologue(&instrs);
        assert_eq!(frame.size, 16);
        assert!(frame.is_leaf());
    }

    // ── MipsClass full roundtrip from real instrs ─────────────────────────
    #[test]
    fn test_class_from_real_instrs() {
        let arch = arch32le();
        let tests: &[(u32, MipsClass)] = &[
            (encode_itype(0x23, 4, 2, 0), MipsClass::Load),
            (encode_itype(0x2B, 4, 2, 0), MipsClass::Store),
            (encode_rtype(1, 2, 3, 0, 0x18), MipsClass::HiLo),
            (encode_rtype(0, 1, 2, 4, 0x00), MipsClass::Shift),
            (encode_jtype(0x02, 0x100), MipsClass::Jump),
            (encode_itype(0x04, 1, 2, 4), MipsClass::Branch),
            (encode_rtype(0, 0, 0, 0, 0x0C), MipsClass::Syscall),
            (encode_rtype(0, 0, 0, 0, 0x0F), MipsClass::Sync),
        ];
        for (word, expected_class) in tests {
            let i = arch.disassemble(addr(0), &le(*word)).unwrap();
            assert_eq!(
                MipsClass::from_mnemonic(&i.mnemonic),
                *expected_class,
                "mnemonic: {}",
                i.mnemonic
            );
        }
    }
}

// ===========================================================================
// MIPS endianness conversion helpers
// ===========================================================================

/// Swap a 32-bit word between big-endian and little-endian.
#[must_use]
pub const fn swap32(word: u32) -> u32 {
    word.swap_bytes()
}

/// Swap a 16-bit halfword between big-endian and little-endian.
#[must_use]
pub const fn swap16(hw: u16) -> u16 {
    hw.swap_bytes()
}

/// Read a 32-bit word from a byte slice at the given offset, big-endian.
#[must_use]
pub fn read_be32(bytes: &[u8], offset: usize) -> Option<u32> {
    // `offset + 4` OVERFLOWS for an offset near usize::MAX, so the guard meant
    // to prevent an out-of-range access was itself the panic. Use checked_add:
    // an overflowing offset can never be in range, so it takes the same exit.
    if offset.checked_add(4).is_none_or(|end| end > bytes.len()) {
        return None;
    }
    Some(u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}

/// Read a 32-bit word from a byte slice at the given offset, little-endian.
#[must_use]
pub fn read_le32(bytes: &[u8], offset: usize) -> Option<u32> {
    // `offset + 4` OVERFLOWS for an offset near usize::MAX, so the guard meant
    // to prevent an out-of-range access was itself the panic. Use checked_add:
    // an overflowing offset can never be in range, so it takes the same exit.
    if offset.checked_add(4).is_none_or(|end| end > bytes.len()) {
        return None;
    }
    Some(u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}

/// Write a 32-bit word into a mutable byte slice at the given offset, big-endian.
pub fn write_be32(bytes: &mut [u8], offset: usize, word: u32) {
    // `offset + 4` OVERFLOWS for an offset near usize::MAX, so the guard meant
    // to prevent an out-of-range access was itself the panic. Use checked_add:
    // an overflowing offset can never be in range, so it takes the same exit.
    if offset.checked_add(4).is_none_or(|end| end > bytes.len()) {
        return;
    }
    let b = word.to_be_bytes();
    bytes[offset..offset + 4].copy_from_slice(&b);
}

/// Write a 32-bit word into a mutable byte slice at the given offset, little-endian.
pub fn write_le32(bytes: &mut [u8], offset: usize, word: u32) {
    // `offset + 4` OVERFLOWS for an offset near usize::MAX, so the guard meant
    // to prevent an out-of-range access was itself the panic. Use checked_add:
    // an overflowing offset can never be in range, so it takes the same exit.
    if offset.checked_add(4).is_none_or(|end| end > bytes.len()) {
        return;
    }
    let b = word.to_le_bytes();
    bytes[offset..offset + 4].copy_from_slice(&b);
}

// ===========================================================================
// MIPS instruction patcher
// ===========================================================================

/// Patch a MIPS instruction in a byte buffer.
/// `endian` selects the byte order. The patch replaces the instruction at
/// `offset` with `new_word`.
pub fn patch_instr(bytes: &mut [u8], offset: usize, new_word: u32, endian: MipsEndian) {
    match endian {
        MipsEndian::Big => write_be32(bytes, offset, new_word),
        MipsEndian::Little => write_le32(bytes, offset, new_word),
    }
}

/// Patch a branch/jump at `offset` to reach `target` from `pc`.
/// Returns `Ok(new_word)` on success, `Err` if the displacement is out of range.
///
/// # Errors
///
/// Returns `Err` when `offset` lies outside `bytes`, when the word at
/// `offset` is not a branch or jump, or when `target` is out of range for
/// the encoding's displacement field.
pub fn patch_branch(
    bytes: &mut [u8],
    offset: usize,
    pc: Address,
    target: u64,
    endian: MipsEndian,
) -> Result<u32, &'static str> {
    let old_word = match endian {
        MipsEndian::Big => read_be32(bytes, offset),
        MipsEndian::Little => read_le32(bytes, offset),
    }
    .ok_or("offset out of range")?;

    let opcode = (old_word >> 26) & 0x3F;
    match opcode {
        0x02 | 0x03 => {
            // J-type: target must be in same 256MB region as PC+4
            let pc4 = pc.0.wrapping_add(4);
            if (target & 0xFFFF_FFFF_F000_0000) != (pc4 & 0xFFFF_FFFF_F000_0000) {
                return Err("J-type branch target out of region");
            }
            let instr_index = ((target >> 2) & 0x03FF_FFFF) as u32;
            let new_word = (opcode << 26) | instr_index;
            patch_instr(bytes, offset, new_word, endian);
            Ok(new_word)
        }
        0x04 | 0x05 | 0x06 | 0x07 | 0x14 | 0x15 | 0x16 | 0x17 | 0x01 => {
            // I-type: PC-relative 16-bit displacement
            let pc4 = pc.0.wrapping_add(4);
            let disp = target.cast_signed().wrapping_sub(pc4.cast_signed());
            let disp_words = disp >> 2;
            if !(-32768..=32767).contains(&disp_words) {
                return Err("I-type branch displacement out of range");
            }
            let upper = old_word & 0xFFFF_0000;
            let new_word = upper | (low_u32_of_i64(disp_words) & 0xFFFF);
            patch_instr(bytes, offset, new_word, endian);
            Ok(new_word)
        }
        _ => Err("instruction at offset is not a branch"),
    }
}

// ===========================================================================
// Tests for utilities and patcher
// ===========================================================================

#[cfg(test)]
mod tests_utils {
    use super::*;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    // ── swap helpers ─────────────────────────────────────────────────────
    #[test]
    fn test_swap32() {
        assert_eq!(swap32(0x1234_5678), 0x7856_3412);
        assert_eq!(swap32(0), 0);
        assert_eq!(swap32(0xFFFF_FFFF), 0xFFFF_FFFF);
    }

    #[test]
    fn test_swap16() {
        assert_eq!(swap16(0x1234), 0x3412);
    }

    // ── read/write BE32 ───────────────────────────────────────────────────
    #[test]
    fn test_read_write_be32() {
        let mut buf = vec![0u8; 8];
        write_be32(&mut buf, 0, 0xDEAD_BEEF);
        assert_eq!(read_be32(&buf, 0), Some(0xDEAD_BEEF));
        assert_eq!(buf[0], 0xDE);
        assert_eq!(buf[3], 0xEF);
    }

    // ── read/write LE32 ───────────────────────────────────────────────────
    #[test]
    fn test_read_write_le32() {
        let mut buf = vec![0u8; 8];
        write_le32(&mut buf, 4, 0xDEAD_BEEF);
        assert_eq!(read_le32(&buf, 4), Some(0xDEAD_BEEF));
        assert_eq!(buf[4], 0xEF); // low byte first
    }

    // ── out-of-range read returns None ────────────────────────────────────
    #[test]
    fn test_read_oob() {
        let buf = vec![0u8; 2];
        assert_eq!(read_be32(&buf, 0), None);
        assert_eq!(read_le32(&buf, 0), None);
    }

    // ── patch_instr ───────────────────────────────────────────────────────
    #[test]
    fn test_patch_instr() {
        let mut buf = vec![0u8; 8];
        patch_instr(&mut buf, 0, 0x1234_5678, MipsEndian::Big);
        assert_eq!(buf[0], 0x12);
        assert_eq!(read_be32(&buf, 0), Some(0x1234_5678));
    }

    // ── patch_branch J-type ───────────────────────────────────────────────
    #[test]
    fn test_patch_branch_j() {
        let mut buf = encode_jtype(0x02, 0x100).to_be_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 4]);
        let result = patch_branch(&mut buf, 0, addr(0x0), 0x1000, MipsEndian::Big);
        assert!(result.is_ok());
        let new_word = read_be32(&buf, 0).unwrap();
        let instr_index = new_word & 0x03FF_FFFF;
        assert_eq!(instr_index << 2, 0x1000);
    }

    // ── patch_branch I-type (BEQ) ─────────────────────────────────────────
    #[test]
    fn test_patch_branch_beq() {
        // BEQ $a0,$a1,offset (opcode=4)
        let orig = encode_beq(4, 5, 0); // offset=0
        let mut buf = orig.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 4]);
        // Target = PC+4+4*4 = 0+4+16 = 20 = 0x14
        let result = patch_branch(&mut buf, 0, addr(0x0), 0x14, MipsEndian::Big);
        assert!(result.is_ok());
        let new_word = read_be32(&buf, 0).unwrap();
        let disp = i64::from((new_word & 0xFFFF) as i16);
        assert_eq!(disp, 4); // 4 words = 16 bytes offset from PC+4
    }

    // ── patch_branch out of range ─────────────────────────────────────────
    #[test]
    fn test_patch_branch_out_of_range() {
        let orig = encode_beq(4, 5, 0);
        let mut buf = orig.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 4]);
        // Target is 256MB away — out of I-type range
        let result = patch_branch(&mut buf, 0, addr(0x0), 0x0800_0000, MipsEndian::Big);
        assert!(result.is_err());
    }

    // ── patch non-branch returns error ────────────────────────────────────
    #[test]
    fn test_patch_non_branch() {
        let add_word = encode_rtype(1, 2, 3, 0, 0x20); // ADD — not a branch
        let mut buf = add_word.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 4]);
        let result = patch_branch(&mut buf, 0, addr(0x0), 0x100, MipsEndian::Big);
        assert!(result.is_err());
    }
}

// ===========================================================================
// MIPS instruction count histogram
// ===========================================================================

/// A mnemonic-frequency histogram from a code section.
#[derive(Debug, Default, Clone)]
pub struct MipsHistogram {
    pub counts: std::collections::BTreeMap<String, usize>,
}

impl MipsHistogram {
    /// Build a histogram by disassembling `bytes`.
    #[must_use]
    pub fn build(arch: &MipsArch, bytes: &[u8], base: Address) -> Self {
        let mut h = Self::default();
        for instr in MipsLinearDisassembler::new(arch, bytes, base).flatten() {
            *h.counts.entry(instr.mnemonic.clone()).or_insert(0) += 1;
        }
        h
    }

    /// Return the top-N most frequent mnemonics.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(&str, usize)> {
        let mut v: Vec<(&str, usize)> = self.counts.iter().map(|(k, &v)| (k.as_str(), v)).collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.1));
        v.truncate(n);
        v
    }

    /// Total instructions counted.
    #[must_use]
    pub fn total(&self) -> usize {
        self.counts.values().sum()
    }

    /// Count for a specific mnemonic.
    #[must_use]
    pub fn count(&self, mnemonic: &str) -> usize {
        self.counts.get(mnemonic).copied().unwrap_or(0)
    }
}

// ===========================================================================
// MIPS constant pool scanner
// ===========================================================================

/// A candidate constant pool entry found by scanning non-instruction words.
#[derive(Debug, Clone)]
pub struct ConstantPoolEntry {
    pub address: u64,
    pub value: u32,
}

/// Scan `bytes` for 32-bit words that do NOT decode as valid MIPS instructions.
/// These are candidate constant pool entries.
#[must_use]
pub fn scan_constant_pool(arch: &MipsArch, bytes: &[u8], base: Address) -> Vec<ConstantPoolEntry> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        let Some(word) = arch.read_word(&bytes[offset..]) else {
            break;
        };
        if !is_valid_mips_word(word) {
            entries.push(ConstantPoolEntry {
                address: base.0.wrapping_add(offset as u64),
                value: word,
            });
        }
        offset += 4;
    }
    entries
}

// ===========================================================================
// Tests for histogram and constant pool
// ===========================================================================

#[cfg(test)]
mod tests_histogram {
    use super::*;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }
    fn arch32le() -> MipsArch {
        MipsArch::mips32_le()
    }
    fn le(word: u32) -> [u8; 4] {
        word.to_le_bytes()
    }

    // ── histogram build ───────────────────────────────────────────────────
    #[test]
    fn test_histogram_build() {
        let ws = [
            encode_rtype(1, 2, 3, 0, 0x20), // add
            encode_rtype(1, 2, 3, 0, 0x20), // add
            encode_itype(0x23, 2, 1, 4),    // lw
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&le(w));
        }
        let h = MipsHistogram::build(&arch32le(), &bytes, addr(0));
        assert_eq!(h.count("add"), 2);
        assert_eq!(h.count("lw"), 1);
        assert_eq!(h.total(), 3);
    }

    // ── top_n ─────────────────────────────────────────────────────────────
    #[test]
    fn test_top_n() {
        let ws = [
            encode_itype(0x23, 2, 1, 4), // lw ×3
            encode_itype(0x23, 2, 1, 4),
            encode_itype(0x23, 2, 1, 4),
            encode_rtype(1, 2, 3, 0, 0x20), // add ×1
        ];
        let mut bytes = Vec::new();
        for w in ws {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let h = MipsHistogram::build(&arch32le(), &bytes, addr(0));
        let top = h.top_n(1);
        assert_eq!(top[0].0, "lw");
        assert_eq!(top[0].1, 3);
    }

    // ── constant pool scanner ─────────────────────────────────────────────
    #[test]
    fn test_scan_constant_pool() {
        // Mix of valid instructions and an invalid word
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&encode_rtype(1, 2, 3, 0, 0x20).to_le_bytes()); // valid
        // 0x1D000000 has opcode 0x07 (BGTZ) — valid
        // Use opcode 0x1D which IS reserved:
        bytes.extend_from_slice(&(0x7400_0000u32).to_le_bytes()); // opcode=0x1D — invalid
        let arch = arch32le();
        let pool = scan_constant_pool(&arch, &bytes, addr(0));
        // The second word (0x74000000) should be flagged
        assert!(pool.iter().any(|e| e.address == 4));
    }

    // ── histogram empty ───────────────────────────────────────────────────
    #[test]
    fn test_histogram_empty() {
        let h = MipsHistogram::build(&arch32le(), &[], addr(0));
        assert_eq!(h.total(), 0);
        assert!(h.top_n(5).is_empty());
    }

    // ── histogram unknown mnemonics ───────────────────────────────────────
    #[test]
    fn test_histogram_unknown() {
        // Reserved opcode 0x3B
        let w: u32 = 0b1110_1100_0000_0000_0000_0000_0000_0000;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&w.to_le_bytes());
        let h = MipsHistogram::build(&arch32le(), &bytes, addr(0));
        assert_eq!(h.count("unknown"), 1);
    }
}

// ===========================================================================
// MIPS known-good binary patterns (ELF prologue signatures)
// ===========================================================================

/// Common MIPS function preamble patterns as byte sequences (big-endian).
/// Each entry is (name, `first_4_bytes_mask`, `first_4_bytes_value`).
pub static MIPS_PREAMBLE_PATTERNS: &[(&str, u32, u32)] = &[
    // addiu $sp,$sp,-N  (any N)
    ("O32 frame alloc", 0xFFFF_0000, 0x27BD_0000),
    // sw $ra, offset($sp) — save return address
    ("Save $ra to stack", 0xFFFF_0000, 0xAFBF_0000),
    // sw $fp, offset($sp) — save frame pointer
    ("Save $fp to stack", 0xFFFF_0000, 0xAFBE_0000),
    // lui $gp, %hi(_gp) — PIC GP setup (first of two)
    ("PIC GP setup (lui)", 0xFFFF_0000, 0x3C1C_0000),
    // MFLR r0 equivalent — mfhi $at for hi/lo prologue
    ("MFHI $at", 0xFFFF_FFFF, 0x0000_0810),
];

/// Check if `bytes` (big-endian) matches any known preamble.
#[must_use]
pub fn detect_preamble(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < 4 {
        return None;
    }
    let word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    for &(name, mask, value) in MIPS_PREAMBLE_PATTERNS {
        if word & mask == value {
            return Some(name);
        }
    }
    None
}

// ===========================================================================
// MIPS32r2 User-mode ASE: RDHWR hardware register names
// ===========================================================================

/// RDHWR hardware register descriptions.
pub static RDHWR_REGS: &[(&str, &str)] = &[
    ("$0", "CPU number (CPUNum)"),
    ("$1", "SYNCI step size (SYNCI_Step)"),
    ("$2", "Cycle counter (CC)"),
    ("$3", "Cycle counter resolution (CCRes)"),
    ("$29", "UserLocal — thread pointer register"),
];

/// Look up a RDHWR register description.
#[must_use]
pub fn rdhwr_reg_desc(reg: u32) -> &'static str {
    for &(name, desc) in RDHWR_REGS {
        let n: u32 = name.trim_start_matches('$').parse().unwrap_or(99);
        if n == reg {
            return desc;
        }
    }
    "Reserved / implementation-defined"
}

// ===========================================================================
// Final miscellaneous tests
// ===========================================================================

#[cfg(test)]
mod tests_misc {
    use super::*;

    // ── detect_preamble ───────────────────────────────────────────────────
    #[test]
    fn test_detect_preamble() {
        // addiu $sp,$sp,-32 = 0x27BD_FFE0
        let bytes = [0x27u8, 0xBD, 0xFF, 0xE0];
        let name = detect_preamble(&bytes);
        assert_eq!(name, Some("O32 frame alloc"));
    }

    // ── detect_preamble none ──────────────────────────────────────────────
    #[test]
    fn test_detect_preamble_none() {
        let bytes = [0x00u8, 0x00, 0x00, 0x00]; // NOP
        let name = detect_preamble(&bytes);
        assert_eq!(name, None);
    }

    // ── rdhwr_reg_desc ────────────────────────────────────────────────────
    #[test]
    fn test_rdhwr_reg_desc() {
        assert!(rdhwr_reg_desc(0).contains("CPU"));
        assert!(rdhwr_reg_desc(2).contains("Cycle"));
        assert!(rdhwr_reg_desc(29).contains("thread"));
        assert!(rdhwr_reg_desc(10).contains("Reserved"));
    }

    // ── MIPS_PREAMBLE_PATTERNS table ──────────────────────────────────────
    #[test]
    fn test_preamble_table() {
        assert!(!MIPS_PREAMBLE_PATTERNS.is_empty());
        assert!(
            MIPS_PREAMBLE_PATTERNS
                .iter()
                .any(|(n, _, _)| n.contains("O32"))
        );
    }

    // ── RDHWR_REGS table ──────────────────────────────────────────────────
    #[test]
    fn test_rdhwr_table() {
        assert_eq!(RDHWR_REGS.len(), 5);
    }

    // ── MipsHistogram count for zero ──────────────────────────────────────
    #[test]
    fn test_histogram_missing_zero() {
        let h = MipsHistogram::default();
        assert_eq!(h.count("lw"), 0);
    }

    // ── scan_constant_pool empty ──────────────────────────────────────────
    #[test]
    fn test_scan_pool_empty() {
        let pool = scan_constant_pool(&MipsArch::mips32_le(), &[], Address::new(0));
        assert!(pool.is_empty());
    }

    // ── patch_instr LE ────────────────────────────────────────────────────
    #[test]
    fn test_patch_instr_le() {
        let mut buf = vec![0u8; 8];
        patch_instr(&mut buf, 0, 0xABCD_1234, MipsEndian::Little);
        assert_eq!(read_le32(&buf, 0), Some(0xABCD_1234));
        assert_eq!(buf[0], 0x34); // little-endian low byte first
    }

    // ── MipsArch::read_word big-endian ────────────────────────────────────
    #[test]
    fn test_read_word_be() {
        let arch = MipsArch::mips32_be();
        let bytes = [0x12u8, 0x34, 0x56, 0x78];
        assert_eq!(arch.read_word(&bytes), Some(0x1234_5678));
    }

    // ── MipsArch::read_word little-endian ─────────────────────────────────
    #[test]
    fn test_read_word_le() {
        let arch = MipsArch::mips32_le();
        let bytes = [0x78u8, 0x56, 0x34, 0x12];
        assert_eq!(arch.read_word(&bytes), Some(0x1234_5678));
    }

    // ── encode_j / encode_jal distinction ────────────────────────────────
    #[test]
    fn test_encode_j_jal_distinct() {
        let j = encode_j(0x100);
        let jal = encode_jal(0x100);
        assert_ne!(j, jal);
        let arch = MipsArch::mips32_le();
        assert_eq!(
            arch.disassemble(Address::new(0), &j.to_le_bytes())
                .unwrap()
                .mnemonic,
            "j"
        );
        assert_eq!(
            arch.disassemble(Address::new(0), &jal.to_le_bytes())
                .unwrap()
                .mnemonic,
            "jal"
        );
    }

    // ── branch_target_i known value ────────────────────────────────────────
    #[test]
    fn test_branch_target_i_known() {
        // PC=0x1000, simm16=4 → target = 0x1004 + 4*4 = 0x1014
        let t = branch_target_i(Address::new(0x1000), 4);
        assert_eq!(t, 0x1014);
    }

    // ── branch_target_j known value ───────────────────────────────────────
    #[test]
    fn test_branch_target_j_known() {
        // PC=0x0000, target26=0x100 → { 0x0, 0x100, 00 } = 0x400
        let t = branch_target_j(Address::new(0x0000), 0x100);
        assert_eq!(t, 0x400);
    }

    // ── MipsArch::read_word short slice ───────────────────────────────────
    #[test]
    fn test_read_word_short() {
        let arch = MipsArch::mips32_be();
        assert_eq!(arch.read_word(&[0u8; 3]), None);
        assert_eq!(arch.read_word(&[]), None);
    }
}
