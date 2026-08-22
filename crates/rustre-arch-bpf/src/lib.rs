//! `rustre-arch-bpf`
//!
//! eBPF / cBPF architecture implementation for the `RustRE` Suite.
//!
//! Supports full eBPF instruction decoding: ALU32/ALU64, JMP/JMP32, memory
//! load/store, `BPF_CALL`, `BPF_EXIT`, and the double-wide `BPF_LD_DW_IMM`.
//! Also provides cBPF classic BPF decoding, a complete helper function table
//! (200+ helpers), BPF map types, BTF type info, verifier constraints,
//! XDP/socket filter program types, and a linear disassembler iterator.

/// eBPF program verifier model: BpfVerifier, VerifierState, RegisterType,
/// BoundsCheck, SafetyProperty, VerifierError, VerifierTrace.
pub mod bpf_verifier;

/// Higher-level eBPF analysis: BpfProgType, MapAccessPattern, HelperCallAnalysis,
/// BpfCfg, LoopBound, BpfSecurity, and BpfAnalysis facade.
pub mod bpf_analysis;

/// BPF CO-RE (Compile Once —" Run Everywhere) relocation: BtfType, BtfKind,
/// BtfParser, CoReReloc, CoReApplier, KernelBtf.
pub mod bpf_co_re;

/// BTF (.BTF ELF section) parser: all type kinds, string section, C type
/// reconstruction, function prototype recovery.
pub mod btf_parser;

/// BPF kernel verifier simulation: register type tracking, pointer arithmetic
/// legality, packet access bounds, helper argument checking.
pub mod bpf_verifier_sim;
pub mod ebpf_verifier;
pub mod ebpf_jit_analyzer;
pub mod cbpf_to_ebpf;

/// Checked, panic-free numeric conversions shared by the eBPF decoders.
pub mod numeric;

use std::collections::HashMap;

use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
};
use rustre_core::address::Address;
use rustre_core::arch::{BranchCondition, BranchKind, RegisterKind};
use rustre_core::endian::Endian;
use rustre_core::errors::CoreError;

// ---------------------------------------------------------------------------
// BPF instruction format constants
// ---------------------------------------------------------------------------

/// Instruction classes (bits [2:0] of opcode byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BpfClass {
    Ld = 0x00,
    Ldx = 0x01,
    St = 0x02,
    Stx = 0x03,
    Alu = 0x04,
    Jmp = 0x05,
    Alu64 = 0x07,
    Jmp32 = 0x06,
}

impl BpfClass {
    /// Decode a class from an opcode byte.
    #[must_use]
    pub const fn from_opcode(op: u8) -> Option<Self> {
        match op & 0x07 {
            0x00 => Some(Self::Ld),
            0x01 => Some(Self::Ldx),
            0x02 => Some(Self::St),
            0x03 => Some(Self::Stx),
            0x04 => Some(Self::Alu),
            0x05 => Some(Self::Jmp),
            0x06 => Some(Self::Jmp32),
            0x07 => Some(Self::Alu64),
            _ => None,
        }
    }

    /// Return the display name of this class.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ld => "BPF_LD",
            Self::Ldx => "BPF_LDX",
            Self::St => "BPF_ST",
            Self::Stx => "BPF_STX",
            Self::Alu => "BPF_ALU",
            Self::Jmp => "BPF_JMP",
            Self::Alu64 => "BPF_ALU64",
            Self::Jmp32 => "BPF_JMP32",
        }
    }
}

/// Memory size codes (bits [4:3] of opcode byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BpfSize {
    Word = 0x00,  // 4 bytes
    Half = 0x08,  // 2 bytes
    Byte = 0x10,  // 1 byte
    DWord = 0x18, // 8 bytes
}

impl BpfSize {
    /// Decode size from opcode byte.
    #[must_use]
    pub const fn from_opcode(op: u8) -> Option<Self> {
        match op & 0x18 {
            0x00 => Some(Self::Word),
            0x08 => Some(Self::Half),
            0x10 => Some(Self::Byte),
            0x18 => Some(Self::DWord),
            _ => None,
        }
    }

    /// Return the assembler suffix for this size.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Word => "w",
            Self::Half => "h",
            Self::Byte => "b",
            Self::DWord => "dw",
        }
    }

    /// Return the number of bytes this size represents.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Word => 4,
            Self::Half => 2,
            Self::Byte => 1,
            Self::DWord => 8,
        }
    }
}

/// Memory mode (bits [7:5] of opcode byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BpfMode {
    Imm = 0x00,
    Abs = 0x20,
    Ind = 0x40,
    Mem = 0x60,
    Atomic = 0xc0,
}

impl BpfMode {
    /// Decode memory mode from opcode byte.
    #[must_use]
    pub const fn from_opcode(op: u8) -> Option<Self> {
        match op & 0xe0 {
            0x00 => Some(Self::Imm),
            0x20 => Some(Self::Abs),
            0x40 => Some(Self::Ind),
            0x60 => Some(Self::Mem),
            0xc0 => Some(Self::Atomic),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// ALU operation codes
// ---------------------------------------------------------------------------

/// ALU operation codes (bits [7:4] of opcode byte, for ALU/ALU64 class).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BpfAluOp {
    Add = 0x00,
    Sub = 0x10,
    Mul = 0x20,
    Div = 0x30,
    Or = 0x40,
    And = 0x50,
    Lsh = 0x60,
    Rsh = 0x70,
    Neg = 0x80,
    Mod = 0x90,
    Xor = 0xa0,
    Mov = 0xb0,
    Arsh = 0xc0,
    End = 0xd0,
}

impl BpfAluOp {
    /// Decode ALU op from opcode byte.
    #[must_use]
    pub const fn from_opcode(op: u8) -> Option<Self> {
        match op & 0xf0 {
            0x00 => Some(Self::Add),
            0x10 => Some(Self::Sub),
            0x20 => Some(Self::Mul),
            0x30 => Some(Self::Div),
            0x40 => Some(Self::Or),
            0x50 => Some(Self::And),
            0x60 => Some(Self::Lsh),
            0x70 => Some(Self::Rsh),
            0x80 => Some(Self::Neg),
            0x90 => Some(Self::Mod),
            0xa0 => Some(Self::Xor),
            0xb0 => Some(Self::Mov),
            0xc0 => Some(Self::Arsh),
            0xd0 => Some(Self::End),
            _ => None,
        }
    }

    /// Return the mnemonic string for this ALU op.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Mul => "mul",
            Self::Div => "div",
            Self::Or => "or",
            Self::And => "and",
            Self::Lsh => "lsh",
            Self::Rsh => "rsh",
            Self::Neg => "neg",
            Self::Mod => "mod",
            Self::Xor => "xor",
            Self::Mov => "mov",
            Self::Arsh => "arsh",
            Self::End => "end",
        }
    }
}

// ---------------------------------------------------------------------------
// JMP operation codes
// ---------------------------------------------------------------------------

/// JMP operation codes (bits [7:4] of opcode byte, for JMP/JMP32 class).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BpfJmpOp {
    Ja = 0x00,
    Jeq = 0x10,
    Jgt = 0x20,
    Jge = 0x30,
    Jset = 0x40,
    Jne = 0x50,
    Jsgt = 0x60,
    Jsge = 0x70,
    Call = 0x80,
    Exit = 0x90,
    Jlt = 0xa0,
    Jle = 0xb0,
    Jslt = 0xc0,
    Jsle = 0xd0,
}

impl BpfJmpOp {
    /// Decode JMP op from opcode byte.
    #[must_use]
    pub const fn from_opcode(op: u8) -> Option<Self> {
        match op & 0xf0 {
            0x00 => Some(Self::Ja),
            0x10 => Some(Self::Jeq),
            0x20 => Some(Self::Jgt),
            0x30 => Some(Self::Jge),
            0x40 => Some(Self::Jset),
            0x50 => Some(Self::Jne),
            0x60 => Some(Self::Jsgt),
            0x70 => Some(Self::Jsge),
            0x80 => Some(Self::Call),
            0x90 => Some(Self::Exit),
            0xa0 => Some(Self::Jlt),
            0xb0 => Some(Self::Jle),
            0xc0 => Some(Self::Jslt),
            0xd0 => Some(Self::Jsle),
            _ => None,
        }
    }

    /// Return the mnemonic string for this JMP op.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Ja => "ja",
            Self::Jeq => "jeq",
            Self::Jgt => "jgt",
            Self::Jge => "jge",
            Self::Jset => "jset",
            Self::Jne => "jne",
            Self::Jsgt => "jsgt",
            Self::Jsge => "jsge",
            Self::Call => "call",
            Self::Exit => "exit",
            Self::Jlt => "jlt",
            Self::Jle => "jle",
            Self::Jslt => "jslt",
            Self::Jsle => "jsle",
        }
    }

    /// Returns true if this is a conditional jump.
    #[must_use]
    pub const fn is_conditional(self) -> bool {
        !matches!(self, Self::Ja | Self::Call | Self::Exit)
    }
}

// ---------------------------------------------------------------------------
// Decoded eBPF instruction
// ---------------------------------------------------------------------------

/// A decoded eBPF instruction (8 bytes on disk, or 16 for `BPF_LD_DW_IMM`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfInstruction {
    /// Raw bytes (8 for standard, 16 for `BPF_LD_DW_IMM`).
    pub raw: Vec<u8>,
    pub opcode: u8,
    pub dst_reg: u8,
    pub src_reg: u8,
    pub offset: i16,
    pub imm: i32,
    /// For `BPF_LD_DW_IMM`: the full 64-bit immediate (`imm_lo` | `imm_hi` << 32).
    pub wide_imm: Option<i64>,
}

impl BpfInstruction {
    /// Decode a single eBPF instruction from `bytes`.
    ///
    /// Returns the instruction and the number of bytes consumed (8 or 16).
    ///
    /// # Errors
    ///
    /// Returns [`BpfDecodeError::Truncated`] if fewer than 8 bytes are available,
    /// or fewer than 16 bytes for a wide immediate.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), BpfDecodeError> {
        if bytes.len() < 8 {
            return Err(BpfDecodeError::Truncated);
        }
        let opcode = bytes[0];
        let regs = bytes[1];
        let dst_reg = regs & 0x0f;
        let src_reg = (regs >> 4) & 0x0f;
        let offset = i16::from_le_bytes([bytes[2], bytes[3]]);
        let imm = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        // BPF_LD_DW_IMM is 0x18 = BPF_LD | BPF_DW | BPF_IMM
        if opcode == 0x18 {
            if bytes.len() < 16 {
                return Err(BpfDecodeError::Truncated);
            }
            let imm_hi = i32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
            // Mask to u32 before widening to avoid sign-extension polluting the high 32 bits.
            let wide = (i64::from(imm.cast_unsigned())) | ((i64::from(imm_hi.cast_unsigned())) << 32);
            return Ok((
                Self {
                    raw: bytes[..16].to_vec(),
                    opcode,
                    dst_reg,
                    src_reg,
                    offset,
                    imm,
                    wide_imm: Some(wide),
                },
                16,
            ));
        }

        Ok((
            Self {
                raw: bytes[..8].to_vec(),
                opcode,
                dst_reg,
                src_reg,
                offset,
                imm,
                wide_imm: None,
            },
            8,
        ))
    }

    /// Return the instruction class.
    #[must_use]
    pub const fn class(&self) -> Option<BpfClass> {
        BpfClass::from_opcode(self.opcode)
    }
}

// ---------------------------------------------------------------------------
// Decode error
// ---------------------------------------------------------------------------

/// Errors that can occur during eBPF instruction decoding.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum BpfDecodeError {
    /// The byte slice was too short to contain a complete instruction.
    #[error("truncated eBPF instruction")]
    Truncated,
    /// The opcode byte is not a recognised eBPF opcode.
    #[error("unknown opcode: {0:#04x}")]
    UnknownOpcode(u8),
}

// ---------------------------------------------------------------------------
// Disassembly helpers
// ---------------------------------------------------------------------------

/// Name a register by number.
///
/// # Panics
///
/// Does not panic; returns `"r?"` for register numbers > 10.
#[must_use]
pub const fn reg_name(reg: u8) -> &'static str {
    match reg {
        0 => "r0",
        1 => "r1",
        2 => "r2",
        3 => "r3",
        4 => "r4",
        5 => "r5",
        6 => "r6",
        7 => "r7",
        8 => "r8",
        9 => "r9",
        10 => "r10",
        _ => "r?",
    }
}

/// Disassemble a decoded `BpfInstruction` into `(mnemonic, operands, flags)`.
///
/// # Errors
///
/// Returns [`BpfDecodeError::UnknownOpcode`] for unrecognised opcode values.
pub fn disasm_instr<S: ::std::hash::BuildHasher>(
    instr: &BpfInstruction,
    helpers: &HashMap<i32, &'static str, S>,
) -> Result<(String, String, InstrFlags), BpfDecodeError> {
    let op = instr.opcode;
    let dst = reg_name(instr.dst_reg);
    let src = reg_name(instr.src_reg);
    let off = instr.offset;
    let imm = instr.imm;

    let class = BpfClass::from_opcode(op).ok_or(BpfDecodeError::UnknownOpcode(op))?;

    match class {
        BpfClass::Alu | BpfClass::Alu64 => {
            let is64 = class == BpfClass::Alu64;
            let suffix = if is64 { "" } else { "32" };
            let src_is_reg = (op & 0x08) != 0;
            let code = op & 0xf0;

            let (mne, ops) = match code {
                0x00 => (
                    "add",
                    if src_is_reg {
                        format!("{dst}, {src}")
                    } else {
                        format!("{dst}, {imm}")
                    },
                ),
                0x10 => (
                    "sub",
                    if src_is_reg {
                        format!("{dst}, {src}")
                    } else {
                        format!("{dst}, {imm}")
                    },
                ),
                0x20 => (
                    "mul",
                    if src_is_reg {
                        format!("{dst}, {src}")
                    } else {
                        format!("{dst}, {imm}")
                    },
                ),
                0x30 => (
                    "div",
                    if src_is_reg {
                        format!("{dst}, {src}")
                    } else {
                        format!("{dst}, {imm}")
                    },
                ),
                0x40 => (
                    "or",
                    if src_is_reg {
                        format!("{dst}, {src}")
                    } else {
                        format!("{dst}, {imm}")
                    },
                ),
                0x50 => (
                    "and",
                    if src_is_reg {
                        format!("{dst}, {src}")
                    } else {
                        format!("{dst}, {imm}")
                    },
                ),
                0x60 => (
                    "lsh",
                    if src_is_reg {
                        format!("{dst}, {src}")
                    } else {
                        format!("{dst}, {imm}")
                    },
                ),
                0x70 => (
                    "rsh",
                    if src_is_reg {
                        format!("{dst}, {src}")
                    } else {
                        format!("{dst}, {imm}")
                    },
                ),
                0x80 => ("neg", dst.to_string()),
                0x90 => (
                    "mod",
                    if src_is_reg {
                        format!("{dst}, {src}")
                    } else {
                        format!("{dst}, {imm}")
                    },
                ),
                0xa0 => (
                    "xor",
                    if src_is_reg {
                        format!("{dst}, {src}")
                    } else {
                        format!("{dst}, {imm}")
                    },
                ),
                0xb0 => (
                    "mov",
                    if src_is_reg {
                        format!("{dst}, {src}")
                    } else {
                        format!("{dst}, {imm}")
                    },
                ),
                0xc0 => (
                    "arsh",
                    if src_is_reg {
                        format!("{dst}, {src}")
                    } else {
                        format!("{dst}, {imm}")
                    },
                ),
                0xd0 if !is64 => {
                    let dir = if (op & 0x08) != 0 { "be" } else { "le" };
                    (dir, format!("{dst}, {imm}"))
                }
                _ => return Err(BpfDecodeError::UnknownOpcode(op)),
            };
            Ok((format!("{mne}{suffix}"), ops, InstrFlags::NONE))
        }

        BpfClass::Jmp | BpfClass::Jmp32 => {
            let is32 = class == BpfClass::Jmp32;
            let suffix = if is32 { "32" } else { "" };
            let src_is_reg = (op & 0x08) != 0;
            let code = op & 0xf0;

            match code {
                0x00 => Ok((
                    format!("ja{suffix}"),
                    format!("{off:+}"),
                    InstrFlags::BRANCH,
                )),
                0x10 => Ok((
                    format!("jeq{suffix}"),
                    if src_is_reg {
                        format!("{dst}, {src}, {off:+}")
                    } else {
                        format!("{dst}, {imm}, {off:+}")
                    },
                    InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                )),
                0x20 => Ok((
                    format!("jgt{suffix}"),
                    if src_is_reg {
                        format!("{dst}, {src}, {off:+}")
                    } else {
                        format!("{dst}, {imm}, {off:+}")
                    },
                    InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                )),
                0x30 => Ok((
                    format!("jge{suffix}"),
                    if src_is_reg {
                        format!("{dst}, {src}, {off:+}")
                    } else {
                        format!("{dst}, {imm}, {off:+}")
                    },
                    InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                )),
                0x40 => Ok((
                    format!("jset{suffix}"),
                    if src_is_reg {
                        format!("{dst}, {src}, {off:+}")
                    } else {
                        format!("{dst}, {imm}, {off:+}")
                    },
                    InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                )),
                0x50 => Ok((
                    format!("jne{suffix}"),
                    if src_is_reg {
                        format!("{dst}, {src}, {off:+}")
                    } else {
                        format!("{dst}, {imm}, {off:+}")
                    },
                    InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                )),
                0x60 => Ok((
                    format!("jsgt{suffix}"),
                    if src_is_reg {
                        format!("{dst}, {src}, {off:+}")
                    } else {
                        format!("{dst}, {imm}, {off:+}")
                    },
                    InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                )),
                0x70 => Ok((
                    format!("jsge{suffix}"),
                    if src_is_reg {
                        format!("{dst}, {src}, {off:+}")
                    } else {
                        format!("{dst}, {imm}, {off:+}")
                    },
                    InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                )),
                0x80 if !is32 => {
                    let name = helpers.get(&imm).copied().unwrap_or("unknown");
                    Ok((
                        "call".to_string(),
                        format!("{imm} <{name}>"),
                        InstrFlags::CALL,
                    ))
                }
                0x90 if !is32 => Ok(("exit".to_string(), String::new(), InstrFlags::RET)),
                0xa0 => Ok((
                    format!("jlt{suffix}"),
                    if src_is_reg {
                        format!("{dst}, {src}, {off:+}")
                    } else {
                        format!("{dst}, {imm}, {off:+}")
                    },
                    InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                )),
                0xb0 => Ok((
                    format!("jle{suffix}"),
                    if src_is_reg {
                        format!("{dst}, {src}, {off:+}")
                    } else {
                        format!("{dst}, {imm}, {off:+}")
                    },
                    InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                )),
                0xc0 => Ok((
                    format!("jslt{suffix}"),
                    if src_is_reg {
                        format!("{dst}, {src}, {off:+}")
                    } else {
                        format!("{dst}, {imm}, {off:+}")
                    },
                    InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                )),
                0xd0 => Ok((
                    format!("jsle{suffix}"),
                    if src_is_reg {
                        format!("{dst}, {src}, {off:+}")
                    } else {
                        format!("{dst}, {imm}, {off:+}")
                    },
                    InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                )),
                _ => Err(BpfDecodeError::UnknownOpcode(op)),
            }
        }

        BpfClass::Ld | BpfClass::Ldx | BpfClass::St | BpfClass::Stx => {
            let size = BpfSize::from_opcode(op).ok_or(BpfDecodeError::UnknownOpcode(op))?;
            let mode = BpfMode::from_opcode(op).ok_or(BpfDecodeError::UnknownOpcode(op))?;
            let sz = size.suffix();

            match (class, mode) {
                (BpfClass::Ld, BpfMode::Imm) if op == 0x18 => {
                    let wide = instr.wide_imm.unwrap_or(i64::from(imm));
                    Ok((
                        "lddw".to_string(),
                        format!("{dst}, {wide:#018x}"),
                        InstrFlags::NONE,
                    ))
                }
                (BpfClass::Ld, BpfMode::Abs) => Ok((
                    format!("ldabs{sz}"),
                    format!("[{imm:#x}]"),
                    InstrFlags::READ_MEM,
                )),
                (BpfClass::Ld, BpfMode::Ind) => Ok((
                    format!("ldind{sz}"),
                    format!("[{src} + {imm:#x}]"),
                    InstrFlags::READ_MEM,
                )),
                (BpfClass::Ldx, BpfMode::Mem) => Ok((
                    format!("ldx{sz}"),
                    format!("{dst}, [{src} + {off}]"),
                    InstrFlags::READ_MEM,
                )),
                (BpfClass::St, BpfMode::Mem) => Ok((
                    format!("st{sz}"),
                    format!("[{dst} + {off}], {imm}"),
                    InstrFlags::WRITE_MEM,
                )),
                (BpfClass::Stx, BpfMode::Mem) => Ok((
                    format!("stx{sz}"),
                    format!("[{dst} + {off}], {src}"),
                    InstrFlags::WRITE_MEM,
                )),
                (BpfClass::Stx, BpfMode::Atomic) => Ok((
                    format!("atomic{sz}"),
                    format!("[{dst} + {off}], {src}, op={imm:#x}"),
                    InstrFlags::WRITE_MEM,
                )),
                _ => Err(BpfDecodeError::UnknownOpcode(op)),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Known helper function database (200+ helpers)
// ---------------------------------------------------------------------------

/// Returns a `HashMap` mapping BPF helper function number to its name.
/// Contains all helpers up to the current Linux kernel.
#[must_use]
pub fn known_helpers() -> HashMap<i32, &'static str> {
    let mut m = HashMap::new();
    m.insert(0, "unspec");
    m.insert(1, "bpf_map_lookup_elem");
    m.insert(2, "bpf_map_update_elem");
    m.insert(3, "bpf_map_delete_elem");
    m.insert(4, "bpf_probe_read");
    m.insert(5, "bpf_ktime_get_ns");
    m.insert(6, "bpf_trace_printk");
    m.insert(7, "bpf_get_prandom_u32");
    m.insert(8, "bpf_get_smp_processor_id");
    m.insert(9, "bpf_skb_store_bytes");
    m.insert(10, "bpf_l3_csum_replace");
    m.insert(11, "bpf_l4_csum_replace");
    m.insert(12, "bpf_tail_call");
    m.insert(13, "bpf_clone_redirect");
    m.insert(14, "bpf_get_current_pid_tgid");
    m.insert(15, "bpf_get_current_uid_gid");
    m.insert(16, "bpf_get_current_comm");
    m.insert(17, "bpf_get_cgroup_classid");
    m.insert(18, "bpf_skb_vlan_push");
    m.insert(19, "bpf_skb_vlan_pop");
    m.insert(20, "bpf_skb_get_tunnel_key");
    m.insert(21, "bpf_skb_set_tunnel_key");
    m.insert(22, "bpf_perf_event_read");
    m.insert(23, "bpf_redirect");
    m.insert(24, "bpf_get_route_realm");
    m.insert(25, "bpf_perf_event_output");
    m.insert(26, "bpf_skb_load_bytes");
    m.insert(27, "bpf_get_stackid");
    m.insert(28, "bpf_csum_diff");
    m.insert(29, "bpf_skb_get_tunnel_opt");
    m.insert(30, "bpf_skb_set_tunnel_opt");
    m.insert(31, "bpf_skb_change_proto");
    m.insert(32, "bpf_skb_change_type");
    m.insert(33, "bpf_skb_under_cgroup");
    m.insert(34, "bpf_get_hash_recalc");
    m.insert(35, "bpf_get_current_task");
    m.insert(36, "bpf_probe_write_user");
    m.insert(37, "bpf_current_task_under_cgroup");
    m.insert(38, "bpf_skb_change_tail");
    m.insert(39, "bpf_skb_pull_data");
    m.insert(40, "bpf_csum_update");
    m.insert(41, "bpf_set_hash_invalid");
    m.insert(42, "bpf_get_numa_node_id");
    m.insert(43, "bpf_skb_change_head");
    m.insert(44, "bpf_xdp_adjust_head");
    m.insert(45, "bpf_probe_read_str");
    m.insert(46, "bpf_get_socket_cookie");
    m.insert(47, "bpf_get_socket_uid");
    m.insert(48, "bpf_set_hash");
    m.insert(49, "bpf_setsockopt");
    m.insert(50, "bpf_skb_adjust_room");
    m.insert(51, "bpf_redirect_map");
    m.insert(52, "bpf_sk_redirect_map");
    m.insert(53, "bpf_sock_map_update");
    m.insert(54, "bpf_xdp_adjust_meta");
    m.insert(55, "bpf_perf_event_read_value");
    m.insert(56, "bpf_perf_prog_read_value");
    m.insert(57, "bpf_getsockopt");
    m.insert(58, "bpf_override_return");
    m.insert(59, "bpf_sock_ops_cb_flags_set");
    m.insert(60, "bpf_msg_redirect_map");
    m.insert(61, "bpf_msg_apply_bytes");
    m.insert(62, "bpf_msg_cork_bytes");
    m.insert(63, "bpf_msg_pull_data");
    m.insert(64, "bpf_bind");
    m.insert(65, "bpf_xdp_adjust_tail");
    m.insert(66, "bpf_skb_get_xfrm_state");
    m.insert(67, "bpf_get_stack");
    m.insert(68, "bpf_skb_load_bytes_relative");
    m.insert(69, "bpf_fib_lookup");
    m.insert(70, "bpf_sock_hash_update");
    m.insert(71, "bpf_msg_redirect_hash");
    m.insert(72, "bpf_sk_redirect_hash");
    m.insert(73, "bpf_lwt_push_encap");
    m.insert(74, "bpf_lwt_seg6_store_bytes");
    m.insert(75, "bpf_lwt_seg6_adjust_srh");
    m.insert(76, "bpf_lwt_seg6_action");
    m.insert(77, "bpf_rc_repeat");
    m.insert(78, "bpf_rc_keydown");
    m.insert(79, "bpf_skb_cgroup_id");
    m.insert(80, "bpf_get_current_cgroup_id");
    m.insert(81, "bpf_get_local_storage");
    m.insert(82, "bpf_sk_select_reuseport");
    m.insert(83, "bpf_skb_ancestor_cgroup_id");
    m.insert(84, "bpf_sk_lookup_tcp");
    m.insert(85, "bpf_sk_lookup_udp");
    m.insert(86, "bpf_sk_release");
    m.insert(87, "bpf_map_push_elem");
    m.insert(88, "bpf_map_pop_elem");
    m.insert(89, "bpf_map_peek_elem");
    m.insert(90, "bpf_msg_push_data");
    m.insert(91, "bpf_msg_pop_data");
    m.insert(92, "bpf_rc_pointer_rel");
    m.insert(93, "bpf_spin_lock");
    m.insert(94, "bpf_spin_unlock");
    m.insert(95, "bpf_sk_fullsock");
    m.insert(96, "bpf_tcp_sock");
    m.insert(97, "bpf_skb_ecn_set_ce");
    m.insert(98, "bpf_get_listener_sock");
    m.insert(99, "bpf_skc_lookup_tcp");
    m.insert(100, "bpf_tcp_check_syncookie");
    m.insert(101, "bpf_sysctl_get_name");
    m.insert(102, "bpf_sysctl_get_current_value");
    m.insert(103, "bpf_sysctl_get_new_value");
    m.insert(104, "bpf_sysctl_set_new_value");
    m.insert(105, "bpf_strtol");
    m.insert(106, "bpf_strtoul");
    m.insert(107, "bpf_sk_storage_get");
    m.insert(108, "bpf_sk_storage_delete");
    m.insert(109, "bpf_send_signal");
    m.insert(110, "bpf_tcp_gen_syncookie");
    m.insert(111, "bpf_skb_output");
    m.insert(112, "bpf_probe_read_user");
    m.insert(113, "bpf_probe_read_kernel");
    m.insert(114, "bpf_probe_read_user_str");
    m.insert(115, "bpf_probe_read_kernel_str");
    m.insert(116, "bpf_tcp_send_ack");
    m.insert(117, "bpf_send_signal_thread");
    m.insert(118, "bpf_jiffies64");
    m.insert(119, "bpf_read_branch_records");
    m.insert(120, "bpf_get_ns_current_pid_tgid");
    m.insert(121, "bpf_xdp_output");
    m.insert(122, "bpf_get_netns_cookie");
    m.insert(123, "bpf_get_current_ancestor_cgroup_id");
    m.insert(124, "bpf_sk_assign");
    m.insert(125, "bpf_ktime_get_boot_ns");
    m.insert(126, "bpf_seq_printf");
    m.insert(127, "bpf_seq_write");
    m.insert(128, "bpf_sk_cgroup_id");
    m.insert(129, "bpf_sk_ancestor_cgroup_id");
    m.insert(130, "bpf_ringbuf_output");
    m.insert(131, "bpf_ringbuf_reserve");
    m.insert(132, "bpf_ringbuf_submit");
    m.insert(133, "bpf_ringbuf_discard");
    m.insert(134, "bpf_ringbuf_query");
    m.insert(135, "bpf_csum_level");
    m.insert(136, "bpf_skc_to_tcp6_sock");
    m.insert(137, "bpf_skc_to_tcp_sock");
    m.insert(138, "bpf_skc_to_tcp_timewait_sock");
    m.insert(139, "bpf_skc_to_tcp_request_sock");
    m.insert(140, "bpf_skc_to_udp6_sock");
    m.insert(141, "bpf_get_task_stack");
    m.insert(142, "bpf_load_hdr_opt");
    m.insert(143, "bpf_store_hdr_opt");
    m.insert(144, "bpf_reserve_hdr_opt");
    m.insert(145, "bpf_inode_storage_get");
    m.insert(146, "bpf_inode_storage_delete");
    m.insert(147, "bpf_d_path");
    m.insert(148, "bpf_copy_from_user");
    m.insert(149, "bpf_snprintf_btf");
    m.insert(150, "bpf_seq_printf_btf");
    m.insert(151, "bpf_skb_cgroup_classid");
    m.insert(152, "bpf_redirect_neigh");
    m.insert(153, "bpf_per_cpu_ptr");
    m.insert(154, "bpf_this_cpu_ptr");
    m.insert(155, "bpf_redirect_peer");
    m.insert(156, "bpf_task_storage_get");
    m.insert(157, "bpf_task_storage_delete");
    m.insert(158, "bpf_get_current_task_btf");
    m.insert(159, "bpf_bprm_opts_set");
    m.insert(160, "bpf_ktime_get_coarse_ns");
    m.insert(161, "bpf_ima_inode_hash");
    m.insert(162, "bpf_sock_from_file");
    m.insert(163, "bpf_check_mtu");
    m.insert(164, "bpf_for_each_map_elem");
    m.insert(165, "bpf_snprintf");
    m.insert(166, "bpf_sys_bpf");
    m.insert(167, "bpf_btf_find_by_name_kind");
    m.insert(168, "bpf_sys_close");
    m.insert(169, "bpf_timer_init");
    m.insert(170, "bpf_timer_set_callback");
    m.insert(171, "bpf_timer_start");
    m.insert(172, "bpf_timer_cancel");
    m.insert(173, "bpf_get_func_ip");
    m.insert(174, "bpf_get_attach_cookie");
    m.insert(175, "bpf_task_pt_regs");
    m.insert(176, "bpf_get_branch_snapshot");
    m.insert(177, "bpf_trace_vprintk");
    m.insert(178, "bpf_skc_to_unix_sock");
    m.insert(179, "bpf_kallsyms_lookup_name");
    m.insert(180, "bpf_find_vma");
    m.insert(181, "bpf_loop");
    m.insert(182, "bpf_strncmp");
    m.insert(183, "bpf_get_func_arg");
    m.insert(184, "bpf_get_func_ret");
    m.insert(185, "bpf_get_func_arg_cnt");
    m.insert(186, "bpf_get_retval");
    m.insert(187, "bpf_set_retval");
    m.insert(188, "bpf_xdp_get_buff_len");
    m.insert(189, "bpf_xdp_load_bytes");
    m.insert(190, "bpf_xdp_store_bytes");
    m.insert(191, "bpf_copy_from_user_task");
    m.insert(192, "bpf_skb_set_tstamp");
    m.insert(193, "bpf_ima_file_hash");
    m.insert(194, "bpf_kptr_xchg");
    m.insert(195, "bpf_map_lookup_percpu_elem");
    m.insert(196, "bpf_skc_to_mptcp_sock");
    m.insert(197, "bpf_dynptr_from_mem");
    m.insert(198, "bpf_ringbuf_reserve_dynptr");
    m.insert(199, "bpf_ringbuf_submit_dynptr");
    m.insert(200, "bpf_ringbuf_discard_dynptr");
    m.insert(201, "bpf_dynptr_read");
    m.insert(202, "bpf_dynptr_write");
    m.insert(203, "bpf_dynptr_data");
    m.insert(204, "bpf_tcp_raw_gen_syncookie_ipv4");
    m.insert(205, "bpf_tcp_raw_gen_syncookie_ipv6");
    m.insert(206, "bpf_tcp_raw_check_syncookie_ipv4");
    m.insert(207, "bpf_tcp_raw_check_syncookie_ipv6");
    m.insert(208, "bpf_ktime_get_tai_ns");
    m.insert(209, "bpf_user_ringbuf_drain");
    m.insert(210, "bpf_cgrp_storage_get");
    m.insert(211, "bpf_cgrp_storage_delete");
    m
}

// ---------------------------------------------------------------------------
// BPF Map Types
// ---------------------------------------------------------------------------

/// BPF map type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BpfMapType {
    Unspec = 0,
    Hash = 1,
    Array = 2,
    ProgArray = 3,
    PerfEventArray = 4,
    PercpuHash = 5,
    PercpuArray = 6,
    StackTrace = 7,
    CgroupArray = 8,
    LruHash = 9,
    LruPercpuHash = 10,
    LpmTrie = 11,
    ArrayOfMaps = 12,
    HashOfMaps = 13,
    Devmap = 14,
    Sockmap = 15,
    Cpumap = 16,
    Xskmap = 17,
    Sockhash = 18,
    CgroupStorage = 19,
    ReuseportSockarray = 20,
    PercpuCgroupStorage = 21,
    Queue = 22,
    Stack = 23,
    SkStorage = 24,
    DevmapHash = 25,
    StructOps = 26,
    Ringbuf = 27,
    InodeStorage = 28,
    TaskStorage = 29,
    BloomFilter = 30,
    UserRingbuf = 31,
    CgrpStorage = 32,
}

impl BpfMapType {
    /// Return the string name of this map type.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unspec => "BPF_MAP_TYPE_UNSPEC",
            Self::Hash => "BPF_MAP_TYPE_HASH",
            Self::Array => "BPF_MAP_TYPE_ARRAY",
            Self::ProgArray => "BPF_MAP_TYPE_PROG_ARRAY",
            Self::PerfEventArray => "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
            Self::PercpuHash => "BPF_MAP_TYPE_PERCPU_HASH",
            Self::PercpuArray => "BPF_MAP_TYPE_PERCPU_ARRAY",
            Self::StackTrace => "BPF_MAP_TYPE_STACK_TRACE",
            Self::CgroupArray => "BPF_MAP_TYPE_CGROUP_ARRAY",
            Self::LruHash => "BPF_MAP_TYPE_LRU_HASH",
            Self::LruPercpuHash => "BPF_MAP_TYPE_LRU_PERCPU_HASH",
            Self::LpmTrie => "BPF_MAP_TYPE_LPM_TRIE",
            Self::ArrayOfMaps => "BPF_MAP_TYPE_ARRAY_OF_MAPS",
            Self::HashOfMaps => "BPF_MAP_TYPE_HASH_OF_MAPS",
            Self::Devmap => "BPF_MAP_TYPE_DEVMAP",
            Self::Sockmap => "BPF_MAP_TYPE_SOCKMAP",
            Self::Cpumap => "BPF_MAP_TYPE_CPUMAP",
            Self::Xskmap => "BPF_MAP_TYPE_XSKMAP",
            Self::Sockhash => "BPF_MAP_TYPE_SOCKHASH",
            Self::CgroupStorage => "BPF_MAP_TYPE_CGROUP_STORAGE",
            Self::ReuseportSockarray => "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY",
            Self::PercpuCgroupStorage => "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE",
            Self::Queue => "BPF_MAP_TYPE_QUEUE",
            Self::Stack => "BPF_MAP_TYPE_STACK",
            Self::SkStorage => "BPF_MAP_TYPE_SK_STORAGE",
            Self::DevmapHash => "BPF_MAP_TYPE_DEVMAP_HASH",
            Self::StructOps => "BPF_MAP_TYPE_STRUCT_OPS",
            Self::Ringbuf => "BPF_MAP_TYPE_RINGBUF",
            Self::InodeStorage => "BPF_MAP_TYPE_INODE_STORAGE",
            Self::TaskStorage => "BPF_MAP_TYPE_TASK_STORAGE",
            Self::BloomFilter => "BPF_MAP_TYPE_BLOOM_FILTER",
            Self::UserRingbuf => "BPF_MAP_TYPE_USER_RINGBUF",
            Self::CgrpStorage => "BPF_MAP_TYPE_CGRP_STORAGE",
        }
    }

    /// Attempt to decode a map type from a numeric value.
    #[must_use]
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Unspec),
            1 => Some(Self::Hash),
            2 => Some(Self::Array),
            3 => Some(Self::ProgArray),
            4 => Some(Self::PerfEventArray),
            5 => Some(Self::PercpuHash),
            6 => Some(Self::PercpuArray),
            7 => Some(Self::StackTrace),
            8 => Some(Self::CgroupArray),
            9 => Some(Self::LruHash),
            10 => Some(Self::LruPercpuHash),
            11 => Some(Self::LpmTrie),
            12 => Some(Self::ArrayOfMaps),
            13 => Some(Self::HashOfMaps),
            14 => Some(Self::Devmap),
            15 => Some(Self::Sockmap),
            16 => Some(Self::Cpumap),
            17 => Some(Self::Xskmap),
            18 => Some(Self::Sockhash),
            19 => Some(Self::CgroupStorage),
            20 => Some(Self::ReuseportSockarray),
            21 => Some(Self::PercpuCgroupStorage),
            22 => Some(Self::Queue),
            23 => Some(Self::Stack),
            24 => Some(Self::SkStorage),
            25 => Some(Self::DevmapHash),
            26 => Some(Self::StructOps),
            27 => Some(Self::Ringbuf),
            28 => Some(Self::InodeStorage),
            29 => Some(Self::TaskStorage),
            30 => Some(Self::BloomFilter),
            31 => Some(Self::UserRingbuf),
            32 => Some(Self::CgrpStorage),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// BPF Program Types
// ---------------------------------------------------------------------------

/// BPF program type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BpfProgType {
    Unspec = 0,
    SocketFilter = 1,
    Kprobe = 2,
    SchedCls = 3,
    SchedAct = 4,
    Tracepoint = 5,
    Xdp = 6,
    PerfEvent = 7,
    CgroupSkb = 8,
    CgroupSock = 9,
    LwtIn = 10,
    LwtOut = 11,
    LwtXmit = 12,
    SockOps = 13,
    SkSkb = 14,
    CgroupDevice = 15,
    SkMsg = 16,
    RawTracepoint = 17,
    CgroupSockAddr = 18,
    LwtSeg6local = 19,
    LircMode2 = 20,
    SkReuseport = 21,
    FlowDissector = 22,
    CgroupSysctl = 23,
    RawTracepointWritable = 24,
    CgroupSockopt = 25,
    Tracing = 26,
    StructOps = 27,
    Ext = 28,
    Lsm = 29,
    SkLookup = 30,
    Syscall = 31,
}

impl BpfProgType {
    /// Return the string name of this program type.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unspec => "BPF_PROG_TYPE_UNSPEC",
            Self::SocketFilter => "BPF_PROG_TYPE_SOCKET_FILTER",
            Self::Kprobe => "BPF_PROG_TYPE_KPROBE",
            Self::SchedCls => "BPF_PROG_TYPE_SCHED_CLS",
            Self::SchedAct => "BPF_PROG_TYPE_SCHED_ACT",
            Self::Tracepoint => "BPF_PROG_TYPE_TRACEPOINT",
            Self::Xdp => "BPF_PROG_TYPE_XDP",
            Self::PerfEvent => "BPF_PROG_TYPE_PERF_EVENT",
            Self::CgroupSkb => "BPF_PROG_TYPE_CGROUP_SKB",
            Self::CgroupSock => "BPF_PROG_TYPE_CGROUP_SOCK",
            Self::LwtIn => "BPF_PROG_TYPE_LWT_IN",
            Self::LwtOut => "BPF_PROG_TYPE_LWT_OUT",
            Self::LwtXmit => "BPF_PROG_TYPE_LWT_XMIT",
            Self::SockOps => "BPF_PROG_TYPE_SOCK_OPS",
            Self::SkSkb => "BPF_PROG_TYPE_SK_SKB",
            Self::CgroupDevice => "BPF_PROG_TYPE_CGROUP_DEVICE",
            Self::SkMsg => "BPF_PROG_TYPE_SK_MSG",
            Self::RawTracepoint => "BPF_PROG_TYPE_RAW_TRACEPOINT",
            Self::CgroupSockAddr => "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
            Self::LwtSeg6local => "BPF_PROG_TYPE_LWT_SEG6LOCAL",
            Self::LircMode2 => "BPF_PROG_TYPE_LIRC_MODE2",
            Self::SkReuseport => "BPF_PROG_TYPE_SK_REUSEPORT",
            Self::FlowDissector => "BPF_PROG_TYPE_FLOW_DISSECTOR",
            Self::CgroupSysctl => "BPF_PROG_TYPE_CGROUP_SYSCTL",
            Self::RawTracepointWritable => "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
            Self::CgroupSockopt => "BPF_PROG_TYPE_CGROUP_SOCKOPT",
            Self::Tracing => "BPF_PROG_TYPE_TRACING",
            Self::StructOps => "BPF_PROG_TYPE_STRUCT_OPS",
            Self::Ext => "BPF_PROG_TYPE_EXT",
            Self::Lsm => "BPF_PROG_TYPE_LSM",
            Self::SkLookup => "BPF_PROG_TYPE_SK_LOOKUP",
            Self::Syscall => "BPF_PROG_TYPE_SYSCALL",
        }
    }
}

// ---------------------------------------------------------------------------
// cBPF Classic BPF
// ---------------------------------------------------------------------------

/// cBPF instruction opcodes (16-bit field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CbpfOpClass {
    Ld = 0x00,
    Ldx = 0x01,
    St = 0x02,
    Stx = 0x03,
    Alu = 0x04,
    Jmp = 0x05,
    Ret = 0x06,
    Misc = 0x07,
}

impl CbpfOpClass {
    /// Decode a cBPF class from an opcode word.
    #[must_use]
    pub const fn from_op(op: u16) -> Option<Self> {
        match op & 7 {
            0 => Some(Self::Ld),
            1 => Some(Self::Ldx),
            2 => Some(Self::St),
            3 => Some(Self::Stx),
            4 => Some(Self::Alu),
            5 => Some(Self::Jmp),
            6 => Some(Self::Ret),
            7 => Some(Self::Misc),
            _ => None,
        }
    }
}

/// A decoded classic BPF (cBPF) instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbpfInstruction {
    /// Opcode word (little-endian in the on-disk format).
    pub opcode: u16,
    /// Jump-true offset.
    pub jt: u8,
    /// Jump-false offset.
    pub jf: u8,
    /// Immediate value / K field.
    pub k: u32,
}

impl CbpfInstruction {
    /// Decode a single cBPF instruction from 8 bytes (little-endian).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the slice has fewer than 8 bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, BpfDecodeError> {
        if bytes.len() < 8 {
            return Err(BpfDecodeError::Truncated);
        }
        let opcode = u16::from_le_bytes([bytes[0], bytes[1]]);
        let jt = bytes[2];
        let jf = bytes[3];
        let k = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        Ok(Self { opcode, jt, jf, k })
    }

    /// Return a human-readable disassembly string.
    #[must_use]
    pub fn disasm(&self) -> String {
        let cls = self.opcode & 7;
        let misc_code = self.opcode & 0xf8;
        match cls {
            0 /* LD */  => format!("LD  k=0x{:x}", self.k),
            1 /* LDX */ => format!("LDX k=0x{:x}", self.k),
            2 /* ST */  => format!("ST  M[{}]", self.k),
            3 /* STX */ => format!("STX M[{}]", self.k),
            4 /* ALU */ => {
                let op = match self.opcode & 0xf0 {
                    0x00 => "ADD", 0x10 => "SUB", 0x20 => "MUL", 0x30 => "DIV",
                    0x40 => "OR",  0x50 => "AND", 0x60 => "LSH", 0x70 => "RSH",
                    0x80 => "NEG", 0x90 => "MOD", 0xa0 => "XOR",
                    _ => "ALU?",
                };
                let src = if self.opcode & 8 != 0 { "X".to_string() } else { format!("#{}", self.k) };
                format!("{op} {src}")
            }
            5 /* JMP */ => {
                let cond = match self.opcode & 0xf0 {
                    0x00 => "JA",  0x10 => "JEQ", 0x20 => "JGT",
                    0x30 => "JGE", 0x40 => "JSET", _ => "JMP?",
                };
                format!("{cond} jt={} jf={} k=0x{:x}", self.jt, self.jf, self.k)
            }
            6 /* RET */ => format!("RET k=0x{:x}", self.k),
            7 /* MISC */=> {
                if misc_code == 0 { "TAX".to_string() } else { "TXA".to_string() }
            }
            _ => format!("?? 0x{:04x}", self.opcode),
        }
    }
}

// ---------------------------------------------------------------------------
// BTF Type Info
// ---------------------------------------------------------------------------

/// BTF kind values from btf.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BtfKind {
    Int = 1,
    Ptr = 2,
    Array = 3,
    Struct = 4,
    Union = 5,
    Enum = 6,
    Fwd = 7,
    Typedef = 8,
    Volatile = 9,
    Const = 10,
    Restrict = 11,
    Func = 12,
    FuncProto = 13,
    Var = 14,
    DataSec = 15,
    Float = 16,
    DeclTag = 17,
    TypeTag = 18,
    Enum64 = 19,
}

impl BtfKind {
    /// Attempt to decode a BTF kind from a numeric value.
    #[must_use]
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Int),
            2 => Some(Self::Ptr),
            3 => Some(Self::Array),
            4 => Some(Self::Struct),
            5 => Some(Self::Union),
            6 => Some(Self::Enum),
            7 => Some(Self::Fwd),
            8 => Some(Self::Typedef),
            9 => Some(Self::Volatile),
            10 => Some(Self::Const),
            11 => Some(Self::Restrict),
            12 => Some(Self::Func),
            13 => Some(Self::FuncProto),
            14 => Some(Self::Var),
            15 => Some(Self::DataSec),
            16 => Some(Self::Float),
            17 => Some(Self::DeclTag),
            18 => Some(Self::TypeTag),
            19 => Some(Self::Enum64),
            _ => None,
        }
    }

    /// Return the string name of this BTF kind.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Int => "int",
            Self::Ptr => "ptr",
            Self::Array => "array",
            Self::Struct => "struct",
            Self::Union => "union",
            Self::Enum => "enum",
            Self::Fwd => "fwd",
            Self::Typedef => "typedef",
            Self::Volatile => "volatile",
            Self::Const => "const",
            Self::Restrict => "restrict",
            Self::Func => "func",
            Self::FuncProto => "func_proto",
            Self::Var => "var",
            Self::DataSec => "datasec",
            Self::Float => "float",
            Self::DeclTag => "decl_tag",
            Self::TypeTag => "type_tag",
            Self::Enum64 => "enum64",
        }
    }
}

/// A parsed BTF type header (from the wire format).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfTypeHeader {
    /// Index into the BTF string section.
    pub name_off: u32,
    /// info field: vlen | kind | `kind_flag`.
    pub info: u32,
    /// size or type reference.
    pub size_or_type: u32,
}

impl BtfTypeHeader {
    /// Decode a BTF type header from 12 bytes (little-endian).
    ///
    /// # Errors
    ///
    /// Returns `Err` if fewer than 12 bytes are provided.
    pub fn decode(bytes: &[u8]) -> Result<Self, BpfDecodeError> {
        if bytes.len() < 12 {
            return Err(BpfDecodeError::Truncated);
        }
        let name_off = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let info = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let size_or_type = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        Ok(Self {
            name_off,
            info,
            size_or_type,
        })
    }

    /// Return the BTF kind extracted from the info field.
    #[must_use]
    pub const fn kind(&self) -> Option<BtfKind> {
        BtfKind::from_u32((self.info >> 24) & 0x1f)
    }

    /// Return the vlen (number of members/params) from the info field.
    #[must_use]
    pub const fn vlen(&self) -> u32 {
        self.info & 0xffff
    }

    /// Return the `kind_flag` from the info field.
    #[must_use]
    pub const fn kind_flag(&self) -> bool {
        (self.info >> 31) & 1 != 0
    }
}

// ---------------------------------------------------------------------------
// Verifier constraint types
// ---------------------------------------------------------------------------

/// Verifier register type (simplified).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BpfRegType {
    NotInit,
    Scalar,
    PtrToCtx,
    ConstPtrToMap,
    PtrToMapValue,
    PtrToMapValueOrNull,
    PtrToStack,
    PtrToPacket,
    PtrToPacketMeta,
    PtrToPacketEnd,
    PtrToFlowKeys,
    PtrToSocket,
    PtrToSockCommon,
    PtrToTcpSock,
    PtrToXdpSock,
    PtrToBtfId,
    PtrToMem,
    PtrToFunc,
    PtrToBuf,
    Rdonly,
}

impl BpfRegType {
    /// Return the display name of this register type.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotInit => "NOT_INIT",
            Self::Scalar => "SCALAR_VALUE",
            Self::PtrToCtx => "PTR_TO_CTX",
            Self::ConstPtrToMap => "CONST_PTR_TO_MAP",
            Self::PtrToMapValue => "PTR_TO_MAP_VALUE",
            Self::PtrToMapValueOrNull => "PTR_TO_MAP_VALUE_OR_NULL",
            Self::PtrToStack => "PTR_TO_STACK",
            Self::PtrToPacket => "PTR_TO_PACKET",
            Self::PtrToPacketMeta => "PTR_TO_PACKET_META",
            Self::PtrToPacketEnd => "PTR_TO_PACKET_END",
            Self::PtrToFlowKeys => "PTR_TO_FLOW_KEYS",
            Self::PtrToSocket => "PTR_TO_SOCKET",
            Self::PtrToSockCommon => "PTR_TO_SOCK_COMMON",
            Self::PtrToTcpSock => "PTR_TO_TCP_SOCK",
            Self::PtrToXdpSock => "PTR_TO_XDP_SOCK",
            Self::PtrToBtfId => "PTR_TO_BTF_ID",
            Self::PtrToMem => "PTR_TO_MEM",
            Self::PtrToFunc => "PTR_TO_FUNC",
            Self::PtrToBuf => "PTR_TO_BUF",
            Self::Rdonly => "RDONLY",
        }
    }
}

// ---------------------------------------------------------------------------
// BpfVariant
// ---------------------------------------------------------------------------

/// eBPF vs cBPF variant selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BpfVariant {
    /// Classic BPF (cBPF) —" limited to legacy SKF filters.
    Classic,
    /// Extended BPF (eBPF) —" the modern in-kernel VM.
    Extended,
}

// ---------------------------------------------------------------------------
// BpfArch —" Architecture implementation
// ---------------------------------------------------------------------------

/// Architecture implementation for BPF.
#[derive(Debug)]
pub struct BpfArch {
    /// Whether this is classic or extended BPF.
    pub variant: BpfVariant,
    helpers: HashMap<i32, &'static str>,
}

impl BpfArch {
    /// Construct an eBPF architecture instance.
    #[must_use]
    pub fn new_ebpf() -> Self {
        Self {
            variant: BpfVariant::Extended,
            helpers: known_helpers(),
        }
    }

    /// Construct a cBPF architecture instance.
    #[must_use]
    pub fn new_cbpf() -> Self {
        Self {
            variant: BpfVariant::Classic,
            helpers: known_helpers(),
        }
    }

    /// Look up a helper function name by number.
    #[must_use]
    pub fn helper_name(&self, num: i32) -> Option<&'static str> {
        self.helpers.get(&num).copied()
    }

    /// Return the count of known helpers.
    #[must_use]
    pub fn helper_count(&self) -> usize {
        self.helpers.len()
    }

    /// Return all helpers as a sorted `Vec<(i32, &'static str)>`.
    #[must_use]
    pub fn all_helpers(&self) -> Vec<(i32, &'static str)> {
        let mut v: Vec<_> = self.helpers.iter().map(|(&k, &v)| (k, v)).collect();
        v.sort_by_key(|&(k, _)| k);
        v
    }

    /// Classify the [`BranchKind`] of a decoded instruction from its flags.
    ///
    /// Returns `None` for instructions that do not alter control flow.
    #[must_use]
    pub const fn branch_kind(&self, instr: &Instruction) -> Option<BranchKind> {
        if instr.flags.contains(InstrFlags::RET) {
            return Some(BranchKind::Return);
        }
        if instr.flags.contains(InstrFlags::CALL) {
            return Some(BranchKind::Call);
        }
        if instr.flags.contains(InstrFlags::BRANCH) {
            return Some(if instr.flags.contains(InstrFlags::CONDITIONAL) {
                BranchKind::ConditionalJump
            } else {
                BranchKind::UnconditionalJump
            });
        }
        None
    }
}

impl Default for BpfArch {
    fn default() -> Self {
        Self::new_ebpf()
    }
}

impl Architecture for BpfArch {
    fn name(&self) -> &str {
        match self.variant {
            BpfVariant::Classic => "cbpf",
            BpfVariant::Extended => "ebpf",
        }
    }

    fn pointer_size(&self) -> usize {
        8
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        let (raw_instr, consumed) =
            BpfInstruction::decode(bytes).map_err(|e| CoreError::PluginError {
                plugin: "bpf".into(),
                message: e.to_string(),
            })?;

        let (mne, ops, flags) =
            disasm_instr(&raw_instr, &self.helpers).map_err(|e| CoreError::PluginError {
                plugin: "bpf".into(),
                message: e.to_string(),
            })?;

        let mut instr = Instruction::new(address, consumed, mne, raw_instr.raw);
        instr.operands = ops;
        instr.flags = flags;
        Ok(instr)
    }

    fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo> {
        if instr.flags.contains(InstrFlags::CALL) {
            return vec![];
        }
        if instr.flags.contains(InstrFlags::BRANCH) && instr.bytes.len() >= 8 {
            let offset = i16::from_le_bytes([instr.bytes[2], instr.bytes[3]]);
            let next = instr.address + instr.size as u64;
            let target =
                Address::new(next.as_u64().wrapping_add((i64::from(offset) * 8).cast_unsigned())).as_u64();
            if instr.flags.contains(InstrFlags::CONDITIONAL) {
                return vec![BranchInfo::conditional_jump(
                    target,
                    BranchCondition::Custom(0),
                )];
            }
            return vec![BranchInfo::unconditional_jump(target)];
        }
        vec![]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        (0u32..=10u32)
            .map(|i| {
                let name = if i == 10 {
                    "fp".to_string()
                } else {
                    format!("r{i}")
                };
                RegisterInfo::new(name, i, 8, RegisterKind::General)
            })
            .collect()
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![
            CallingConvention::new("ebpf_call")
                .with_int_args(vec![
                    "r1".to_string(),
                    "r2".to_string(),
                    "r3".to_string(),
                    "r4".to_string(),
                    "r5".to_string(),
                ])
                .with_return_regs(vec!["r0".to_string()]),
        ]
    }
}

// ---------------------------------------------------------------------------
// Linear disassembler
// ---------------------------------------------------------------------------

/// Iterator that decodes eBPF bytecode linearly.
pub struct BpfLinearDisassembler<'a> {
    arch: &'a BpfArch,
    bytes: &'a [u8],
    address: Address,
    offset: usize,
}

impl<'a> BpfLinearDisassembler<'a> {
    /// Create a new disassembler starting at `base_address`.
    #[must_use]
    pub const fn new(arch: &'a BpfArch, bytes: &'a [u8], base_address: Address) -> Self {
        Self {
            arch,
            bytes,
            address: base_address,
            offset: 0,
        }
    }

    /// Return the current byte offset within the input slice.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Return the current disassembly address.
    #[must_use]
    pub const fn current_address(&self) -> Address {
        self.address
    }
}

impl Iterator for BpfLinearDisassembler<'_> {
    type Item = Result<Instruction, CoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }
        let remaining = &self.bytes[self.offset..];
        let result = self.arch.disassemble(self.address, remaining);
        if let Ok(instr) = &result {
            self.offset += instr.size;
            self.address += instr.size as u64;
        } else {
            self.offset += 1;
            self.address += 1u64;
        }
        Some(result)
    }
}

// ---------------------------------------------------------------------------
// BPF program statistics / analysis
// ---------------------------------------------------------------------------

/// Statistics gathered from a BPF program.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BpfProgramStats {
    /// Total number of instructions decoded.
    pub instruction_count: usize,
    /// Number of call instructions.
    pub call_count: usize,
    /// Number of conditional branches.
    pub conditional_branch_count: usize,
    /// Number of unconditional branches (ja).
    pub unconditional_branch_count: usize,
    /// Number of memory reads.
    pub mem_read_count: usize,
    /// Number of memory writes.
    pub mem_write_count: usize,
    /// Whether a `BPF_EXIT` was found.
    pub has_exit: bool,
}

impl BpfProgramStats {
    /// Analyse a byte slice of eBPF instructions and return statistics.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` if the byte slice is empty.
    pub fn from_bytes(arch: &BpfArch, bytes: &[u8]) -> Result<Self, CoreError> {
        let mut stats = Self::default();
        for item in BpfLinearDisassembler::new(arch, bytes, Address::new(0)) {
            let instr = item?;
            stats.instruction_count += 1;
            if instr.flags.contains(InstrFlags::CALL) {
                stats.call_count += 1;
            }
            if instr.flags.contains(InstrFlags::CONDITIONAL) {
                stats.conditional_branch_count += 1;
            } else if instr.flags.contains(InstrFlags::BRANCH) {
                stats.unconditional_branch_count += 1;
            }
            if instr.flags.contains(InstrFlags::READ_MEM) {
                stats.mem_read_count += 1;
            }
            if instr.flags.contains(InstrFlags::WRITE_MEM) {
                stats.mem_write_count += 1;
            }
            if instr.flags.contains(InstrFlags::RET) {
                stats.has_exit = true;
            }
        }
        Ok(stats)
    }
}

// ---------------------------------------------------------------------------
// XDP action codes
// ---------------------------------------------------------------------------

/// XDP action codes returned by XDP programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XdpAction {
    Aborted = 0,
    Drop = 1,
    Pass = 2,
    Tx = 3,
    Redirect = 4,
}

impl XdpAction {
    /// Attempt to decode an XDP action from a numeric value.
    #[must_use]
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Aborted),
            1 => Some(Self::Drop),
            2 => Some(Self::Pass),
            3 => Some(Self::Tx),
            4 => Some(Self::Redirect),
            _ => None,
        }
    }

    /// Return the display name of this XDP action.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aborted => "XDP_ABORTED",
            Self::Drop => "XDP_DROP",
            Self::Pass => "XDP_PASS",
            Self::Tx => "XDP_TX",
            Self::Redirect => "XDP_REDIRECT",
        }
    }
}

// ---------------------------------------------------------------------------
// Socket filter return codes
// ---------------------------------------------------------------------------

/// Socket filter action: return value interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkFilterAction {
    /// Drop the packet.
    Drop,
    /// Accept `n` bytes of the packet.
    Accept(u32),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ebpf() -> BpfArch {
        BpfArch::new_ebpf()
    }

    /// Encode a standard 8-byte eBPF instruction.
    fn enc(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> Vec<u8> {
        let mut v = vec![op, (src << 4) | (dst & 0x0f)];
        v.extend_from_slice(&off.to_le_bytes());
        v.extend_from_slice(&imm.to_le_bytes());
        v
    }

    fn addr(n: u64) -> Address {
        Address::new(n)
    }

    // --- BpfInstruction::decode ---

    #[test]
    fn test_decode_truncated_returns_error() {
        assert_eq!(
            BpfInstruction::decode(&[0x07]),
            Err(BpfDecodeError::Truncated)
        );
    }

    #[test]
    fn test_decode_add64_reg() {
        let bytes = enc(0x0f, 1, 2, 0, 0);
        let (i, sz) = BpfInstruction::decode(&bytes).unwrap();
        assert_eq!(sz, 8);
        assert_eq!(i.opcode, 0x0f);
        assert_eq!(i.dst_reg, 1);
        assert_eq!(i.src_reg, 2);
        assert!(i.wide_imm.is_none());
    }

    #[test]
    fn test_decode_add64_imm() {
        let bytes = enc(0x07, 0, 0, 0, 42);
        let (i, sz) = BpfInstruction::decode(&bytes).unwrap();
        assert_eq!(sz, 8);
        assert_eq!(i.imm, 42);
    }

    #[test]
    fn test_decode_lddw_consumes_16_bytes() {
        let mut bytes = enc(0x18, 1, 0, 0, 0xdead_i32);
        bytes.extend_from_slice(&[0x00; 4]);
        bytes.extend_from_slice(&(0xbeef_i32).to_le_bytes());
        let (i, sz) = BpfInstruction::decode(&bytes).unwrap();
        assert_eq!(sz, 16);
        assert!(i.wide_imm.is_some());
        let expected: i64 = 0xdead | (0xbeef_i64 << 32);
        assert_eq!(i.wide_imm.unwrap(), expected);
    }

    #[test]
    fn test_decode_lddw_truncated() {
        let bytes = enc(0x18, 1, 0, 0, 0);
        assert_eq!(
            BpfInstruction::decode(&bytes),
            Err(BpfDecodeError::Truncated)
        );
    }

    #[test]
    fn test_decode_class_method() {
        let bytes = enc(0x07, 0, 0, 0, 0); // add64 r0, 0
        let (i, _) = BpfInstruction::decode(&bytes).unwrap();
        assert_eq!(i.class(), Some(BpfClass::Alu64));
    }

    // --- disasm_instr ---

    #[test]
    fn test_disasm_add64_imm() {
        let arch = ebpf();
        let bytes = enc(0x07, 0, 0, 0, 5);
        let (i, _) = BpfInstruction::decode(&bytes).unwrap();
        let (mne, ops, flags) = disasm_instr(&i, &arch.helpers).unwrap();
        assert_eq!(mne, "add");
        assert!(ops.contains("r0") && ops.contains('5'));
        assert_eq!(flags, InstrFlags::NONE);
    }

    #[test]
    fn test_disasm_add64_reg() {
        let arch = ebpf();
        let bytes = enc(0x0f, 2, 3, 0, 0);
        let (i, _) = BpfInstruction::decode(&bytes).unwrap();
        let (mne, ops, _) = disasm_instr(&i, &arch.helpers).unwrap();
        assert_eq!(mne, "add");
        assert!(ops.contains("r2") && ops.contains("r3"));
    }

    #[test]
    fn test_disasm_mov64_imm() {
        let arch = ebpf();
        let bytes = enc(0xb7, 0, 0, 0, 0);
        let (i, _) = BpfInstruction::decode(&bytes).unwrap();
        let (mne, _, _) = disasm_instr(&i, &arch.helpers).unwrap();
        assert_eq!(mne, "mov");
    }

    #[test]
    fn test_disasm_exit() {
        let arch = ebpf();
        let bytes = enc(0x95, 0, 0, 0, 0);
        let (i, _) = BpfInstruction::decode(&bytes).unwrap();
        let (mne, _, flags) = disasm_instr(&i, &arch.helpers).unwrap();
        assert_eq!(mne, "exit");
        assert!(flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_disasm_call_helper() {
        let arch = ebpf();
        let bytes = enc(0x85, 0, 0, 0, 1);
        let (i, _) = BpfInstruction::decode(&bytes).unwrap();
        let (mne, ops, flags) = disasm_instr(&i, &arch.helpers).unwrap();
        assert_eq!(mne, "call");
        assert!(ops.contains("bpf_map_lookup_elem"));
        assert!(flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_disasm_call_unknown_helper() {
        let arch = ebpf();
        let bytes = enc(0x85, 0, 0, 0, 999);
        let (i, _) = BpfInstruction::decode(&bytes).unwrap();
        let (_, ops, _) = disasm_instr(&i, &arch.helpers).unwrap();
        assert!(ops.contains("unknown"));
    }

    #[test]
    fn test_disasm_jeq_imm() {
        let arch = ebpf();
        let bytes = enc(0x15, 0, 0, 3, 42);
        let (i, _) = BpfInstruction::decode(&bytes).unwrap();
        let (mne, _, flags) = disasm_instr(&i, &arch.helpers).unwrap();
        assert_eq!(mne, "jeq");
        assert!(flags.contains(InstrFlags::CONDITIONAL));
        assert!(flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_disasm_ja_unconditional() {
        let arch = ebpf();
        let bytes = enc(0x05, 0, 0, -2_i16, 0);
        let (i, _) = BpfInstruction::decode(&bytes).unwrap();
        let (mne, _, flags) = disasm_instr(&i, &arch.helpers).unwrap();
        assert_eq!(mne, "ja");
        assert!(flags.contains(InstrFlags::BRANCH));
        assert!(!flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_disasm_ldxdw() {
        let arch = ebpf();
        let bytes = enc(0x79, 1, 10, -8, 0);
        let (i, _) = BpfInstruction::decode(&bytes).unwrap();
        let (mne, ops, flags) = disasm_instr(&i, &arch.helpers).unwrap();
        assert_eq!(mne, "ldxdw");
        assert!(ops.contains("r1") && ops.contains("r10"));
        assert!(flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_disasm_stxdw() {
        let arch = ebpf();
        let bytes = enc(0x7b, 10, 1, -8, 0);
        let (i, _) = BpfInstruction::decode(&bytes).unwrap();
        let (mne, _, flags) = disasm_instr(&i, &arch.helpers).unwrap();
        assert_eq!(mne, "stxdw");
        assert!(flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_disasm_stw_imm() {
        let arch = ebpf();
        let bytes = enc(0x62, 10, 0, -4, 0);
        let (i, _) = BpfInstruction::decode(&bytes).unwrap();
        let (mne, _, flags) = disasm_instr(&i, &arch.helpers).unwrap();
        assert_eq!(mne, "stw");
        assert!(flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_disasm_lddw_wide() {
        let arch = ebpf();
        let mut bytes = enc(0x18, 1, 0, 0, 0x1234_i32);
        bytes.extend_from_slice(&[0x00; 4]);
        bytes.extend_from_slice(&(0x5678_i32).to_le_bytes());
        let (i, _) = BpfInstruction::decode(&bytes).unwrap();
        let (mne, ops, _) = disasm_instr(&i, &arch.helpers).unwrap();
        assert_eq!(mne, "lddw");
        assert!(ops.contains("r1"));
    }

    // --- Architecture trait ---

    #[test]
    fn test_arch_name_ebpf() {
        assert_eq!(ebpf().name(), "ebpf");
    }

    #[test]
    fn test_arch_name_cbpf() {
        assert_eq!(BpfArch::new_cbpf().name(), "cbpf");
    }

    #[test]
    fn test_arch_pointer_size() {
        assert_eq!(ebpf().pointer_size(), 8);
    }

    #[test]
    fn test_arch_endian() {
        assert_eq!(ebpf().endian(), Endian::Little);
    }

    #[test]
    fn test_arch_registers() {
        let regs = ebpf().registers();
        assert_eq!(regs.len(), 11);
        assert!(regs.iter().any(|r| r.name == "fp"));
        assert!(regs.iter().any(|r| r.name == "r0"));
    }

    #[test]
    fn test_arch_calling_convention() {
        let cc = ebpf().calling_conventions();
        assert_eq!(cc.len(), 1);
        assert_eq!(cc[0].name, "ebpf_call");
        assert_eq!(cc[0].int_args.len(), 5);
        assert_eq!(cc[0].return_regs[0], "r0");
    }

    #[test]
    fn test_arch_disassemble_exit() {
        let arch = ebpf();
        let bytes = enc(0x95, 0, 0, 0, 0);
        let instr = arch.disassemble(addr(0x1000), &bytes).unwrap();
        assert_eq!(instr.mnemonic, "exit");
        assert_eq!(instr.size, 8);
        assert!(instr.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_arch_disassemble_truncated() {
        let arch = ebpf();
        assert!(arch.disassemble(addr(0), &[0x07, 0x00]).is_err());
    }

    // --- get_branches ---

    #[test]
    fn test_get_branches_exit() {
        let arch = ebpf();
        let bytes = enc(0x95, 0, 0, 0, 0);
        let instr = arch.disassemble(addr(0x1000), &bytes).unwrap();
        assert!(arch.get_branches(&instr).is_empty());
    }

    #[test]
    fn test_get_branches_jeq() {
        let arch = ebpf();
        let bytes = enc(0x15, 0, 0, 2, 0);
        let instr = arch.disassemble(addr(0x1000), &bytes).unwrap();
        let branches = arch.get_branches(&instr);
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0].target, Some(0x1018));
        assert_eq!(branches[0].kind, BranchKind::ConditionalJump);
    }

    #[test]
    fn test_branch_kind_classification() {
        let arch = ebpf();
        let exit = arch
            .disassemble(addr(0x1000), &enc(0x95, 0, 0, 0, 0))
            .unwrap();
        assert_eq!(arch.branch_kind(&exit), Some(BranchKind::Return));

        let jeq = arch
            .disassemble(addr(0x1000), &enc(0x15, 0, 0, 2, 0))
            .unwrap();
        assert_eq!(arch.branch_kind(&jeq), Some(BranchKind::ConditionalJump));
    }

    // --- Linear disassembler ---

    #[test]
    fn test_linear_disassembler_simple_program() {
        let arch = ebpf();
        let mut prog = enc(0xb7, 0, 0, 0, 0);
        prog.extend_from_slice(&enc(0x95, 0, 0, 0, 0));
        let instrs: Vec<_> = BpfLinearDisassembler::new(&arch, &prog, addr(0))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[0].mnemonic, "mov");
        assert_eq!(instrs[1].mnemonic, "exit");
    }

    #[test]
    fn test_linear_disassembler_addresses() {
        let arch = ebpf();
        let mut prog = enc(0x07, 0, 0, 0, 1);
        prog.extend_from_slice(&enc(0x95, 0, 0, 0, 0));
        let instrs: Vec<_> = BpfLinearDisassembler::new(&arch, &prog, addr(0x100))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs[0].address, addr(0x100));
        assert_eq!(instrs[1].address, addr(0x108));
    }

    #[test]
    fn test_linear_disassembler_empty() {
        let arch = ebpf();
        assert_eq!(BpfLinearDisassembler::new(&arch, &[], addr(0)).count(), 0);
    }

    #[test]
    fn test_linear_disassembler_offset_tracking() {
        let arch = ebpf();
        let prog = enc(0x95, 0, 0, 0, 0);
        let mut dis = BpfLinearDisassembler::new(&arch, &prog, addr(0));
        assert_eq!(dis.offset(), 0);
        let _ = dis.next();
        assert_eq!(dis.offset(), 8);
    }

    #[test]
    fn test_known_helpers_count() {
        let h = known_helpers();
        assert!(h.len() >= 200);
        assert_eq!(h[&1], "bpf_map_lookup_elem");
        assert_eq!(h[&109], "bpf_send_signal");
    }

    #[test]
    fn test_bpf_size_bytes() {
        assert_eq!(BpfSize::DWord.bytes(), 8);
        assert_eq!(BpfSize::Word.bytes(), 4);
        assert_eq!(BpfSize::Half.bytes(), 2);
        assert_eq!(BpfSize::Byte.bytes(), 1);
    }

    #[test]
    fn test_helper_name_lookup() {
        let arch = ebpf();
        assert_eq!(arch.helper_name(6), Some("bpf_trace_printk"));
        assert_eq!(arch.helper_name(9999), None);
    }

    #[test]
    fn test_alu32_add_imm() {
        let arch = ebpf();
        let bytes = enc(0x04, 1, 0, 0, 10);
        let (i, _) = BpfInstruction::decode(&bytes).unwrap();
        let (mne, ops, _) = disasm_instr(&i, &arch.helpers).unwrap();
        assert_eq!(mne, "add32");
        assert!(ops.contains("r1") && ops.contains("10"));
    }

    #[test]
    fn test_mul64_reg() {
        let arch = ebpf();
        let bytes = enc(0x2f, 3, 4, 0, 0);
        let (i, _) = BpfInstruction::decode(&bytes).unwrap();
        let (mne, ops, _) = disasm_instr(&i, &arch.helpers).unwrap();
        assert_eq!(mne, "mul");
        assert!(ops.contains("r3") && ops.contains("r4"));
    }

    #[test]
    fn test_ldabsw() {
        let arch = ebpf();
        let bytes = enc(0x20, 0, 0, 0, 0x1c_i32);
        let (i, _) = BpfInstruction::decode(&bytes).unwrap();
        let (mne, _, flags) = disasm_instr(&i, &arch.helpers).unwrap();
        assert_eq!(mne, "ldabsw");
        assert!(flags.contains(InstrFlags::READ_MEM));
    }

    // --- BpfMapType ---

    #[test]
    fn test_map_type_from_u32() {
        assert_eq!(BpfMapType::from_u32(1), Some(BpfMapType::Hash));
        assert_eq!(BpfMapType::from_u32(27), Some(BpfMapType::Ringbuf));
        assert_eq!(BpfMapType::from_u32(0xff), None);
    }

    #[test]
    fn test_map_type_name() {
        assert_eq!(BpfMapType::Hash.name(), "BPF_MAP_TYPE_HASH");
        assert_eq!(BpfMapType::Array.name(), "BPF_MAP_TYPE_ARRAY");
    }

    // --- BtfKind ---

    #[test]
    fn test_btf_kind_from_u32() {
        assert_eq!(BtfKind::from_u32(4), Some(BtfKind::Struct));
        assert_eq!(BtfKind::from_u32(99), None);
    }

    #[test]
    fn test_btf_type_header_decode() {
        let mut buf = vec![0u8; 12];
        buf[4] = crate::numeric::trunc_i32_u8(4 << 4); // kind=4 (Struct) in info bits [28:24]
        // Actually BTF kind is in bits [28:24] of info, which is byte [7..4]
        // info = kind << 24 | vlen
        let kind: u32 = 4; // BtfKind::Struct
        let info: u32 = kind << 24;
        buf[4..8].copy_from_slice(&info.to_le_bytes());
        let hdr = BtfTypeHeader::decode(&buf).unwrap();
        assert_eq!(hdr.kind(), Some(BtfKind::Struct));
        assert_eq!(hdr.vlen(), 0);
    }

    #[test]
    fn test_btf_type_header_truncated() {
        assert_eq!(
            BtfTypeHeader::decode(&[0u8; 8]),
            Err(BpfDecodeError::Truncated)
        );
    }

    // --- CbpfInstruction ---

    #[test]
    fn test_cbpf_decode() {
        // LD #42 => opclass=0 (LD), k=42
        let bytes: Vec<u8> = {
            let op: u16 = 0x00;
            let jt = 0u8;
            let jf = 0u8;
            let k: u32 = 42;
            let mut v = op.to_le_bytes().to_vec();
            v.push(jt);
            v.push(jf);
            v.extend_from_slice(&k.to_le_bytes());
            v
        };
        let instr = CbpfInstruction::decode(&bytes).unwrap();
        assert_eq!(instr.k, 42);
        assert!(instr.disasm().contains("LD"));
    }

    #[test]
    fn test_cbpf_decode_truncated() {
        assert_eq!(
            CbpfInstruction::decode(&[0, 0, 0]),
            Err(BpfDecodeError::Truncated)
        );
    }

    #[test]
    fn test_cbpf_ret_disasm() {
        let mut buf = vec![0u8; 8];
        let op: u16 = 6; // RET class
        buf[0..2].copy_from_slice(&op.to_le_bytes());
        let instr = CbpfInstruction::decode(&buf).unwrap();
        assert!(instr.disasm().contains("RET"));
    }

    // --- BpfProgType ---

    #[test]
    fn test_prog_type_names() {
        assert_eq!(BpfProgType::Xdp.name(), "BPF_PROG_TYPE_XDP");
        assert_eq!(
            BpfProgType::SocketFilter.name(),
            "BPF_PROG_TYPE_SOCKET_FILTER"
        );
        assert_eq!(BpfProgType::Kprobe.name(), "BPF_PROG_TYPE_KPROBE");
    }

    // --- BpfProgramStats ---

    #[test]
    fn test_program_stats_simple() {
        let arch = ebpf();
        let mut prog = enc(0xb7, 0, 0, 0, 1); // mov r0, 1
        prog.extend_from_slice(&enc(0x95, 0, 0, 0, 0)); // exit
        let stats = BpfProgramStats::from_bytes(&arch, &prog).unwrap();
        assert_eq!(stats.instruction_count, 2);
        assert!(stats.has_exit);
        assert_eq!(stats.call_count, 0);
    }

    #[test]
    fn test_program_stats_mem_ops() {
        let arch = ebpf();
        let mut prog = enc(0x79, 1, 10, -8, 0); // ldxdw r1, [r10-8]
        prog.extend_from_slice(&enc(0x7b, 10, 1, -8, 0)); // stxdw [r10-8], r1
        prog.extend_from_slice(&enc(0x95, 0, 0, 0, 0));
        let stats = BpfProgramStats::from_bytes(&arch, &prog).unwrap();
        assert_eq!(stats.mem_read_count, 1);
        assert_eq!(stats.mem_write_count, 1);
    }

    // --- XdpAction ---

    #[test]
    fn test_xdp_action_names() {
        assert_eq!(XdpAction::from_u32(2), Some(XdpAction::Pass));
        assert_eq!(XdpAction::Pass.name(), "XDP_PASS");
        assert_eq!(XdpAction::Drop.name(), "XDP_DROP");
        assert_eq!(XdpAction::from_u32(99), None);
    }

    // --- BpfClass / BpfAluOp / BpfJmpOp ---

    #[test]
    fn test_bpf_class_names() {
        assert_eq!(BpfClass::Alu.name(), "BPF_ALU");
        assert_eq!(BpfClass::Alu64.name(), "BPF_ALU64");
        assert_eq!(BpfClass::Jmp.name(), "BPF_JMP");
    }

    #[test]
    fn test_bpf_alu_op_mnemonic() {
        assert_eq!(BpfAluOp::Add.mnemonic(), "add");
        assert_eq!(BpfAluOp::Mov.mnemonic(), "mov");
    }

    #[test]
    fn test_bpf_jmp_op_conditional() {
        assert!(BpfJmpOp::Jeq.is_conditional());
        assert!(!BpfJmpOp::Ja.is_conditional());
        assert!(!BpfJmpOp::Exit.is_conditional());
    }

    #[test]
    fn test_helper_count() {
        let arch = ebpf();
        assert!(arch.helper_count() >= 200);
        let all = arch.all_helpers();
        assert_eq!(all[0].0, 0);
        assert!(all.windows(2).all(|w| w[0].0 <= w[1].0));
    }

    // --- BpfRegType ---

    #[test]
    fn test_bpf_reg_type_names() {
        assert_eq!(BpfRegType::Scalar.name(), "SCALAR_VALUE");
        assert_eq!(BpfRegType::PtrToCtx.name(), "PTR_TO_CTX");
    }
}

// ---------------------------------------------------------------------------
// BpfHelper —" structured helper entry
// ---------------------------------------------------------------------------

/// A structured BPF helper function descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfHelper {
    /// Numeric helper id (matches the `BPF_FUNC`_* enum in the kernel).
    pub id: u32,
    /// C name of the helper, e.g. `"bpf_map_lookup_elem"`.
    pub name: &'static str,
    /// Textual signature (arguments), e.g. `"(map, key)"`.
    pub signature: &'static str,
}

impl BpfHelper {
    /// Create a new helper descriptor.
    #[must_use]
    pub const fn new(id: u32, name: &'static str, signature: &'static str) -> Self {
        Self {
            id,
            name,
            signature,
        }
    }
}

/// Return all known BPF helpers as a static slice.
///
/// The table covers helpers 0—"130+ matching the Linux kernel `bpf.h` numbering
/// used by `BPF_FUNC_*`.  The `signature` field mirrors the prototype comment
/// in the kernel uapi header.
#[must_use]
pub fn all_helpers() -> Vec<BpfHelper> {
    vec![
        BpfHelper::new(0, "unspec", "()"),
        BpfHelper::new(1, "bpf_map_lookup_elem", "(map, key)"),
        BpfHelper::new(2, "bpf_map_update_elem", "(map, key, value, flags)"),
        BpfHelper::new(3, "bpf_map_delete_elem", "(map, key)"),
        BpfHelper::new(4, "bpf_probe_read", "(dst, size, unsafe_ptr)"),
        BpfHelper::new(5, "bpf_ktime_get_ns", "()"),
        BpfHelper::new(6, "bpf_trace_printk", "(fmt, fmt_size, ...)"),
        BpfHelper::new(7, "bpf_get_prandom_u32", "()"),
        BpfHelper::new(8, "bpf_get_smp_processor_id", "()"),
        BpfHelper::new(9, "bpf_skb_store_bytes", "(skb, offset, from, len, flags)"),
        BpfHelper::new(10, "bpf_l3_csum_replace", "(skb, offset, from, to, size)"),
        BpfHelper::new(11, "bpf_l4_csum_replace", "(skb, offset, from, to, flags)"),
        BpfHelper::new(12, "bpf_tail_call", "(ctx, prog_array_map, index)"),
        BpfHelper::new(13, "bpf_clone_redirect", "(skb, ifindex, flags)"),
        BpfHelper::new(14, "bpf_get_current_pid_tgid", "()"),
        BpfHelper::new(15, "bpf_get_current_uid_gid", "()"),
        BpfHelper::new(16, "bpf_get_current_comm", "(buf, buf_size)"),
        BpfHelper::new(17, "bpf_get_stack", "(ctx, buf, size, flags)"),
        BpfHelper::new(18, "bpf_skb_load_bytes", "(skb, offset, to, len)"),
        BpfHelper::new(19, "bpf_get_stackid", "(ctx, map, flags)"),
        BpfHelper::new(20, "bpf_csum_diff", "(from, from_size, to, to_size, seed)"),
        BpfHelper::new(21, "bpf_skb_get_tunnel_opt", "(skb, opt, size)"),
        BpfHelper::new(22, "bpf_skb_set_tunnel_opt", "(skb, opt, size)"),
        BpfHelper::new(23, "bpf_skb_change_proto", "(skb, proto, flags)"),
        BpfHelper::new(24, "bpf_skb_change_type", "(skb, type)"),
        BpfHelper::new(25, "bpf_skb_under_cgroup", "(skb, map, index)"),
        BpfHelper::new(26, "bpf_get_hash_recalc", "(skb)"),
        BpfHelper::new(27, "bpf_get_current_task", "()"),
        BpfHelper::new(28, "bpf_probe_write_user", "(dst, src, len)"),
        BpfHelper::new(29, "bpf_current_task_under_cgroup", "(map, index)"),
        BpfHelper::new(30, "bpf_skb_change_tail", "(skb, len, flags)"),
        BpfHelper::new(31, "bpf_skb_pull_data", "(skb, len)"),
        BpfHelper::new(32, "bpf_csum_update", "(skb, csum)"),
        BpfHelper::new(33, "bpf_set_hash_invalid", "(skb)"),
        BpfHelper::new(34, "bpf_get_numa_node_id", "()"),
        BpfHelper::new(35, "bpf_skb_change_head", "(skb, len, flags)"),
        BpfHelper::new(36, "bpf_xdp_adjust_head", "(xdp_md, delta)"),
        BpfHelper::new(37, "bpf_probe_read_str", "(dst, size, unsafe_ptr)"),
        BpfHelper::new(38, "bpf_get_socket_cookie", "(ctx)"),
        BpfHelper::new(39, "bpf_get_socket_uid", "(skb)"),
        BpfHelper::new(40, "bpf_set_hash", "(skb, hash)"),
        BpfHelper::new(
            41,
            "bpf_setsockopt",
            "(bpf_socket, level, optname, optval, optlen)",
        ),
        BpfHelper::new(42, "bpf_skb_adjust_room", "(skb, len_diff, mode, flags)"),
        BpfHelper::new(43, "bpf_redirect_map", "(map, key, flags)"),
        BpfHelper::new(44, "bpf_sk_redirect_map", "(skb, map, key, flags)"),
        BpfHelper::new(45, "bpf_sock_map_update", "(skops, map, key, flags)"),
        BpfHelper::new(46, "bpf_xdp_adjust_meta", "(xdp_md, delta)"),
        BpfHelper::new(
            47,
            "bpf_perf_event_read_value",
            "(map, flags, buf, buf_size)",
        ),
        BpfHelper::new(48, "bpf_perf_prog_read_value", "(ctx, buf, buf_size)"),
        BpfHelper::new(
            49,
            "bpf_getsockopt",
            "(bpf_socket, level, optname, optval, optlen)",
        ),
        BpfHelper::new(50, "bpf_override_return", "(regs, rc)"),
        BpfHelper::new(51, "bpf_sock_ops_cb_flags_set", "(bpf_sock, argval)"),
        BpfHelper::new(52, "bpf_msg_redirect_map", "(msg, map, key, flags)"),
        BpfHelper::new(53, "bpf_msg_apply_bytes", "(msg, bytes)"),
        BpfHelper::new(54, "bpf_msg_cork_bytes", "(msg, bytes)"),
        BpfHelper::new(55, "bpf_msg_pull_data", "(msg, start, end, flags)"),
        BpfHelper::new(56, "bpf_bind", "(ctx, addr, addr_len)"),
        BpfHelper::new(57, "bpf_xdp_adjust_tail", "(xdp_md, delta)"),
        BpfHelper::new(
            58,
            "bpf_skb_get_xfrm_state",
            "(skb, index, xfrm_state, size, flags)",
        ),
        BpfHelper::new(59, "bpf_get_stack", "(ctx, buf, size, flags)"),
        BpfHelper::new(
            60,
            "bpf_skb_load_bytes_relative",
            "(skb, offset, to, len, start_header)",
        ),
        BpfHelper::new(61, "bpf_fib_lookup", "(ctx, params, plen, flags)"),
        BpfHelper::new(62, "bpf_sock_hash_update", "(skops, map, key, flags)"),
        BpfHelper::new(63, "bpf_msg_redirect_hash", "(msg, map, key, flags)"),
        BpfHelper::new(64, "bpf_sk_redirect_hash", "(skb, map, key, flags)"),
        BpfHelper::new(65, "bpf_lwt_push_encap", "(skb, type, hdr, len)"),
        BpfHelper::new(66, "bpf_lwt_seg6_store_bytes", "(skb, offset, from, len)"),
        BpfHelper::new(67, "bpf_lwt_seg6_adjust_srh", "(skb, offset, delta)"),
        BpfHelper::new(68, "bpf_lwt_seg6_action", "(skb, action, param, param_len)"),
        BpfHelper::new(69, "bpf_rc_repeat", "(ctx)"),
        BpfHelper::new(70, "bpf_rc_keydown", "(ctx, protocol, scancode, toggle)"),
        BpfHelper::new(71, "bpf_skb_cgroup_id", "(skb)"),
        BpfHelper::new(72, "bpf_get_current_cgroup_id", "()"),
        BpfHelper::new(73, "bpf_get_local_storage", "(map, flags)"),
        BpfHelper::new(74, "bpf_sk_select_reuseport", "(reuse, map, key, flags)"),
        BpfHelper::new(75, "bpf_skb_ancestor_cgroup_id", "(skb, ancestor_level)"),
        BpfHelper::new(
            76,
            "bpf_sk_lookup_tcp",
            "(ctx, tuple, tuple_size, netns, flags)",
        ),
        BpfHelper::new(
            77,
            "bpf_sk_lookup_udp",
            "(ctx, tuple, tuple_size, netns, flags)",
        ),
        BpfHelper::new(78, "bpf_sk_release", "(sock)"),
        BpfHelper::new(79, "bpf_map_push_elem", "(map, value, flags)"),
        BpfHelper::new(80, "bpf_map_pop_elem", "(map, value)"),
        BpfHelper::new(81, "bpf_map_peek_elem", "(map, value)"),
        BpfHelper::new(82, "bpf_msg_push_data", "(msg, start, len, flags)"),
        BpfHelper::new(83, "bpf_msg_pop_data", "(msg, start, cut, flags)"),
        BpfHelper::new(84, "bpf_rc_pointer_rel", "(ctx, rel_x, rel_y)"),
        BpfHelper::new(85, "bpf_spin_lock", "(lock)"),
        BpfHelper::new(86, "bpf_spin_unlock", "(lock)"),
        BpfHelper::new(87, "bpf_sk_fullsock", "(sk)"),
        BpfHelper::new(88, "bpf_tcp_sock", "(sk)"),
        BpfHelper::new(89, "bpf_skb_ecn_set_ce", "(skb)"),
        BpfHelper::new(90, "bpf_get_listener_sock", "(sk)"),
        BpfHelper::new(
            91,
            "bpf_skc_lookup_tcp",
            "(ctx, tuple, tuple_size, netns, flags)",
        ),
        BpfHelper::new(
            92,
            "bpf_tcp_check_syncookie",
            "(sk, iph, iph_len, th, th_len)",
        ),
        BpfHelper::new(93, "bpf_sysctl_get_name", "(ctx, buf, buf_len, flags)"),
        BpfHelper::new(94, "bpf_sysctl_get_current_value", "(ctx, buf, buf_len)"),
        BpfHelper::new(95, "bpf_sysctl_get_new_value", "(ctx, buf, buf_len)"),
        BpfHelper::new(96, "bpf_sysctl_set_new_value", "(ctx, buf, buf_len)"),
        BpfHelper::new(97, "bpf_strtol", "(buf, buf_len, flags, res)"),
        BpfHelper::new(98, "bpf_strtoul", "(buf, buf_len, flags, res)"),
        BpfHelper::new(99, "bpf_sk_storage_get", "(map, sk, value, flags)"),
        BpfHelper::new(100, "bpf_sk_storage_delete", "(map, sk)"),
        BpfHelper::new(101, "bpf_send_signal", "(sig)"),
        BpfHelper::new(
            102,
            "bpf_tcp_gen_syncookie",
            "(sk, iph, iph_len, th, th_len)",
        ),
        BpfHelper::new(103, "bpf_skb_output", "(ctx, map, flags, data, size)"),
        BpfHelper::new(104, "bpf_probe_read_user", "(dst, size, unsafe_ptr)"),
        BpfHelper::new(105, "bpf_probe_read_kernel", "(dst, size, unsafe_ptr)"),
        BpfHelper::new(106, "bpf_probe_read_user_str", "(dst, size, unsafe_ptr)"),
        BpfHelper::new(107, "bpf_probe_read_kernel_str", "(dst, size, unsafe_ptr)"),
        BpfHelper::new(108, "bpf_tcp_send_ack", "(tp, rcv_nxt)"),
        BpfHelper::new(109, "bpf_send_signal_thread", "(sig)"),
        BpfHelper::new(110, "bpf_jiffies64", "()"),
        BpfHelper::new(111, "bpf_read_branch_records", "(ctx, buf, size, flags)"),
        BpfHelper::new(
            112,
            "bpf_get_ns_current_pid_tgid",
            "(dev, ino, nsdata, size)",
        ),
        BpfHelper::new(113, "bpf_xdp_output", "(ctx, map, flags, data, size)"),
        BpfHelper::new(114, "bpf_get_netns_cookie", "(ctx)"),
        BpfHelper::new(
            115,
            "bpf_get_current_ancestor_cgroup_id",
            "(ancestor_level)",
        ),
        BpfHelper::new(116, "bpf_sk_assign", "(skb, sk, flags)"),
        BpfHelper::new(117, "bpf_ktime_get_boot_ns", "()"),
        BpfHelper::new(118, "bpf_seq_printf", "(m, fmt, fmt_size, data, data_len)"),
        BpfHelper::new(119, "bpf_seq_write", "(m, data, len)"),
        BpfHelper::new(120, "bpf_sk_cgroup_id", "(sk)"),
        BpfHelper::new(121, "bpf_sk_ancestor_cgroup_id", "(sk, ancestor_level)"),
        BpfHelper::new(122, "bpf_ringbuf_output", "(ringbuf, data, size, flags)"),
        BpfHelper::new(123, "bpf_ringbuf_reserve", "(ringbuf, size, flags)"),
        BpfHelper::new(124, "bpf_ringbuf_submit", "(data, flags)"),
        BpfHelper::new(125, "bpf_ringbuf_discard", "(data, flags)"),
        BpfHelper::new(126, "bpf_ringbuf_query", "(ringbuf, flags)"),
        BpfHelper::new(127, "bpf_csum_level", "(skb, level)"),
        BpfHelper::new(128, "bpf_skc_to_tcp6_sock", "(sk)"),
        BpfHelper::new(129, "bpf_skc_to_tcp_sock", "(sk)"),
        BpfHelper::new(130, "bpf_skc_to_tcp_timewait_sock", "(sk)"),
        BpfHelper::new(131, "bpf_skc_to_tcp_request_sock", "(sk)"),
        BpfHelper::new(132, "bpf_skc_to_udp6_sock", "(sk)"),
        BpfHelper::new(133, "bpf_get_task_stack", "(task, buf, size, flags)"),
        BpfHelper::new(134, "bpf_load_hdr_opt", "(skops, searchby_res, len, flags)"),
        BpfHelper::new(135, "bpf_store_hdr_opt", "(skops, from, len, flags)"),
        BpfHelper::new(136, "bpf_reserve_hdr_opt", "(skops, len, flags)"),
        BpfHelper::new(137, "bpf_inode_storage_get", "(map, inode, value, flags)"),
        BpfHelper::new(138, "bpf_inode_storage_delete", "(map, inode)"),
        BpfHelper::new(139, "bpf_d_path", "(path, buf, sz)"),
        BpfHelper::new(140, "bpf_copy_from_user", "(dst, size, user_ptr)"),
        BpfHelper::new(
            141,
            "bpf_snprintf_btf",
            "(str, str_size, ptr, btf_ptr_size, flags)",
        ),
        BpfHelper::new(142, "bpf_seq_printf_btf", "(m, ptr, ptr_size, flags)"),
        BpfHelper::new(143, "bpf_skb_cgroup_classid", "(skb)"),
        BpfHelper::new(144, "bpf_redirect_neigh", "(ifindex, params, plen, flags)"),
        BpfHelper::new(145, "bpf_per_cpu_ptr", "(percpu_ptr, cpu)"),
        BpfHelper::new(146, "bpf_this_cpu_ptr", "(percpu_ptr)"),
        BpfHelper::new(147, "bpf_redirect_peer", "(ifindex, flags)"),
        BpfHelper::new(148, "bpf_task_storage_get", "(map, task, value, flags)"),
        BpfHelper::new(149, "bpf_task_storage_delete", "(map, task)"),
        BpfHelper::new(150, "bpf_get_current_task_btf", "()"),
        BpfHelper::new(151, "bpf_bprm_opts_set", "(bprm, flags)"),
        BpfHelper::new(152, "bpf_ktime_get_coarse_ns", "()"),
        BpfHelper::new(153, "bpf_ima_inode_hash", "(inode, dst, size)"),
        BpfHelper::new(154, "bpf_sock_from_file", "(file)"),
        BpfHelper::new(
            155,
            "bpf_check_mtu",
            "(ctx, ifindex, mtu_len, len_diff, flags)",
        ),
        BpfHelper::new(
            156,
            "bpf_for_each_map_elem",
            "(map, callback_fn, callback_ctx, flags)",
        ),
        BpfHelper::new(157, "bpf_snprintf", "(out, out_size, fmt, data, data_len)"),
        BpfHelper::new(158, "bpf_sys_bpf", "(cmd, attr, attr_size)"),
        BpfHelper::new(
            159,
            "bpf_btf_find_by_name_kind",
            "(name, name_sz, kind, btf_obj_fd)",
        ),
        BpfHelper::new(160, "bpf_sys_close", "(fd)"),
        BpfHelper::new(161, "bpf_timer_init", "(timer, map, flags)"),
        BpfHelper::new(162, "bpf_timer_set_callback", "(timer, callback_fn)"),
        BpfHelper::new(163, "bpf_timer_start", "(timer, nsecs, flags)"),
        BpfHelper::new(164, "bpf_timer_cancel", "(timer)"),
        BpfHelper::new(165, "bpf_get_func_ip", "(ctx)"),
        BpfHelper::new(166, "bpf_get_attach_cookie", "(ctx)"),
        BpfHelper::new(167, "bpf_task_pt_regs", "(task)"),
        BpfHelper::new(168, "bpf_get_branch_snapshot", "(entries, size, flags)"),
        BpfHelper::new(169, "bpf_trace_vprintk", "(fmt, fmt_size, data, data_len)"),
        BpfHelper::new(170, "bpf_skc_to_unix_sock", "(sk)"),
        BpfHelper::new(
            171,
            "bpf_kallsyms_lookup_name",
            "(name, name_sz, flags, res)",
        ),
        BpfHelper::new(
            172,
            "bpf_find_vma",
            "(task, addr, callback_fn, callback_ctx, flags)",
        ),
        BpfHelper::new(
            173,
            "bpf_loop",
            "(nr_loops, callback_fn, callback_ctx, flags)",
        ),
        BpfHelper::new(174, "bpf_strncmp", "(s1, s1_sz, s2)"),
        BpfHelper::new(175, "bpf_get_func_arg", "(ctx, n, value)"),
        BpfHelper::new(176, "bpf_get_func_ret", "(ctx, value)"),
        BpfHelper::new(177, "bpf_get_func_arg_cnt", "(ctx)"),
        BpfHelper::new(178, "bpf_get_retval", "()"),
        BpfHelper::new(179, "bpf_set_retval", "(retval)"),
        BpfHelper::new(180, "bpf_xdp_get_buff_len", "(xdp_md)"),
        BpfHelper::new(181, "bpf_xdp_load_bytes", "(xdp_md, offset, buf, len)"),
        BpfHelper::new(182, "bpf_xdp_store_bytes", "(xdp_md, offset, buf, len)"),
        BpfHelper::new(
            183,
            "bpf_copy_from_user_task",
            "(dst, size, user_ptr, task, flags)",
        ),
        BpfHelper::new(184, "bpf_skb_set_tstamp", "(skb, tstamp, tstamp_type)"),
        BpfHelper::new(185, "bpf_ima_file_hash", "(file, dst, size)"),
        BpfHelper::new(186, "bpf_kptr_xchg", "(map_val, ptr)"),
        BpfHelper::new(187, "bpf_map_lookup_percpu_elem", "(map, key, cpu)"),
        BpfHelper::new(188, "bpf_skc_to_mptcp_sock", "(sk)"),
        BpfHelper::new(189, "bpf_dynptr_from_mem", "(data, size, flags, ptr)"),
        BpfHelper::new(
            190,
            "bpf_ringbuf_reserve_dynptr",
            "(ringbuf, size, flags, ptr)",
        ),
        BpfHelper::new(191, "bpf_ringbuf_submit_dynptr", "(ptr, flags)"),
        BpfHelper::new(192, "bpf_ringbuf_discard_dynptr", "(ptr, flags)"),
        BpfHelper::new(193, "bpf_dynptr_read", "(dst, len, src, offset, flags)"),
        BpfHelper::new(194, "bpf_dynptr_write", "(dst, offset, src, len, flags)"),
        BpfHelper::new(195, "bpf_dynptr_data", "(ptr, offset, len)"),
        BpfHelper::new(
            196,
            "bpf_tcp_raw_gen_syncookie_ipv4",
            "(sk, iph, iph_len, th, th_len)",
        ),
        BpfHelper::new(
            197,
            "bpf_tcp_raw_gen_syncookie_ipv6",
            "(sk, iph, iph_len, th, th_len)",
        ),
        BpfHelper::new(198, "bpf_tcp_raw_check_syncookie_ipv4", "(sk, iph, th)"),
        BpfHelper::new(199, "bpf_tcp_raw_check_syncookie_ipv6", "(sk, iph, th)"),
        BpfHelper::new(200, "bpf_ktime_get_tai_ns", "()"),
        BpfHelper::new(201, "bpf_user_ringbuf_drain", "(map, callback, ctx, flags)"),
        BpfHelper::new(202, "bpf_cgrp_storage_get", "(map, cgroup, value, flags)"),
        BpfHelper::new(203, "bpf_cgrp_storage_delete", "(map, cgroup)"),
    ]
}

// ---------------------------------------------------------------------------
// BpfProgramType (alias exposing the existing BpfProgType as BpfProgramType)
// ---------------------------------------------------------------------------

/// Type alias that exposes [`BpfProgType`] under the name `BpfProgramType`
/// required by the analyser API.
pub type BpfProgramType = BpfProgType;

// ---------------------------------------------------------------------------
// BpfMapAccess and MapOp
// ---------------------------------------------------------------------------

/// The kind of map operation observed in an instruction stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapOp {
    /// `bpf_map_lookup_elem`
    Lookup,
    /// `bpf_map_update_elem`
    Update,
    /// `bpf_map_delete_elem`
    Delete,
    /// `bpf_map_get_next_key`
    GetNextKey,
}

impl MapOp {
    /// Return the display name of this operation.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Lookup => "lookup",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::GetNextKey => "get_next_key",
        }
    }
}

/// A single BPF map access observed in the instruction stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfMapAccess {
    /// The map file-descriptor immediate seen in the preceding `lddw` instruction
    /// (or 0 when not determinable from static analysis alone).
    pub map_fd: u32,
    /// The kind of map operation.
    pub operation: MapOp,
    /// Instruction index (0-based) of the `call` that triggered this access.
    pub offset: u32,
}

// ---------------------------------------------------------------------------
// BpfProgramReport
// ---------------------------------------------------------------------------

/// Analysis report produced by [`BpfProgramAnalyzer::analyze`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfProgramReport {
    /// Total number of eBPF instructions decoded.
    pub instruction_count: u32,
    /// All helper ids called by the program (may contain duplicates).
    pub helper_calls: Vec<u32>,
    /// All map accesses inferred from helper calls.
    pub map_accesses: Vec<BpfMapAccess>,
    /// A heuristic guess at the program type based on helpers used.
    pub program_type_hint: Option<BpfProgramType>,
    /// Whether any backward branch (possible loop) was detected.
    pub uses_loops: bool,
    /// Approximate cyclomatic complexity (number of conditional branches + 1).
    pub complexity: u32,
    /// Security-relevant observations.
    pub security_notes: Vec<String>,
}

// ---------------------------------------------------------------------------
// BpfProgramAnalyzer
// ---------------------------------------------------------------------------

/// Static analyser for eBPF bytecode.
pub struct BpfProgramAnalyzer;

impl BpfProgramAnalyzer {
    /// Analyse a raw eBPF bytecode slice and return a [`BpfProgramReport`].
    ///
    /// The analysis is purely static (no emulation).  Unknown or malformed
    /// instructions are skipped gracefully.
    #[must_use]
    pub fn analyze(bytecode: &[u8]) -> BpfProgramReport {
        let mut instruction_count: u32 = 0;
        let mut helper_calls: Vec<u32> = Vec::new();
        let mut map_accesses: Vec<BpfMapAccess> = Vec::new();
        let mut uses_loops = false;
        let mut conditional_branches: u32 = 0;
        let mut security_notes: Vec<String> = Vec::new();

        // Infer map_fd from the most-recent lddw (0x18) dst=r1 value.
        let mut last_map_fd: u32 = 0;

        let mut offset = 0usize;
        let mut instr_idx: u32 = 0;

        while offset + 8 <= bytecode.len() {
            let slice = &bytecode[offset..];
            if let Ok((instr, consumed)) = BpfInstruction::decode(slice) {
                instruction_count += 1;
                let op = instr.opcode;
                let cls = op & 0x07;
                let code = op & 0xf0;

                // Detect lddw (wide immediate) used to load map fd into r1.
                if op == 0x18 && instr.dst_reg == 1 {
                    if let Some(wide) = instr.wide_imm {
                        last_map_fd = crate::numeric::trunc_i64_u32(wide);
                    } else {
                        last_map_fd = instr.imm.cast_unsigned();
                    }
                }

                // Detect helper calls: BPF_JMP | BPF_CALL (0x85).
                if cls == 0x05 && code == 0x80 {
                    let helper_id = instr.imm.cast_unsigned();
                    helper_calls.push(helper_id);

                    // Map-touching helpers.
                    let map_op = match helper_id {
                        1 => Some(MapOp::Lookup),
                        2 => Some(MapOp::Update),
                        3 => Some(MapOp::Delete),
                        4 => Some(MapOp::GetNextKey),
                        _ => None,
                    };
                    if let Some(op_kind) = map_op {
                        map_accesses.push(BpfMapAccess {
                            map_fd: last_map_fd,
                            operation: op_kind,
                            offset: instr_idx,
                        });
                    }

                    // Security-sensitive helpers.
                    match helper_id {
                        28 => security_notes.push(format!(
                            "instr {instr_idx}: bpf_probe_write_user can overwrite user-space memory"
                        )),
                        6  => security_notes.push(format!(
                            "instr {instr_idx}: bpf_trace_printk writes to trace log (may leak data)"
                        )),
                        158 => security_notes.push(format!(
                            "instr {instr_idx}: bpf_sys_bpf allows arbitrary BPF syscall invocation"
                        )),
                        _ => {}
                    }
                }

                // Detect conditional branches and backward jumps.
                if cls == 0x05 && code != 0x80 && code != 0x90 {
                    conditional_branches += 1;
                    // A negative offset means a backward branch (potential loop).
                    if instr.offset < 0 {
                        uses_loops = true;
                    }
                }

                offset += consumed;
                instr_idx += 1;
            } else {
                // Skip 8 bytes on decode failure.
                offset += 8;
                instr_idx += 1;
            }
        }

        // Heuristic program-type detection based on helpers used.
        let program_type_hint = Self::guess_program_type(&helper_calls);

        // Security notes for loop usage.
        if uses_loops {
            security_notes.push(
                "backward branch detected: potential unbounded loop (rejected by verifier in older kernels)".to_string(),
            );
        }

        BpfProgramReport {
            instruction_count,
            helper_calls,
            map_accesses,
            program_type_hint,
            uses_loops,
            complexity: conditional_branches + 1,
            security_notes,
        }
    }

    /// Heuristically guess the program type from the set of helpers called.
    fn guess_program_type(helpers: &[u32]) -> Option<BpfProgramType> {
        // XDP helpers.
        if helpers.iter().any(
            |&h| h == 36 /* xdp_adjust_head */ || h == 57, /* xdp_adjust_tail */
        ) {
            return Some(BpfProgramType::Xdp);
        }
        // Kprobe helpers.
        if helpers.iter().any(
            |&h| h == 4 /* probe_read */ || h == 19, /* get_stackid */
        ) {
            return Some(BpfProgramType::Kprobe);
        }
        // Socket filter: skb_load_bytes.
        if helpers.contains(&18 /* skb_load_bytes */) {
            return Some(BpfProgramType::SocketFilter);
        }
        // Tracepoint: perf_event_output.
        if helpers.contains(&25 /* perf_event_output */) {
            return Some(BpfProgramType::Tracepoint);
        }
        None
    }
}

// ---------------------------------------------------------------------------
// VerifierError
// ---------------------------------------------------------------------------

/// An error produced by the simplified [`BpfVerifierSimulator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierError {
    /// Instruction index (0-based) at which the error was detected.
    pub offset: usize,
    /// Human-readable explanation.
    pub message: String,
}

impl VerifierError {
    fn new(offset: usize, message: impl Into<String>) -> Self {
        Self {
            offset,
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// BpfVerifierSimulator
// ---------------------------------------------------------------------------

/// Simplified eBPF verifier that checks a small subset of verifier rules.
pub struct BpfVerifierSimulator;

impl BpfVerifierSimulator {
    /// Check a decoded instruction slice for common verifier violations.
    ///
    /// Checks performed:
    /// - No register operand > 10 (r0—"r10 are valid).
    /// - Stack pointer offset stays within Â±512 bytes when a `BPF_ST/STX`
    ///   uses `r10` as the base register.
    /// - No backward branches that would create unbounded loops (older-kernel
    ///   rule; since Linux 5.3 bounded loops are allowed but we flag them).
    /// - Program must not exceed 1 million instructions (`BPF_MAXINSNS` guard).
    #[must_use]
    pub fn check_bounds(instrs: &[BpfInstruction]) -> Vec<VerifierError> {
        let mut errors = Vec::new();

        if instrs.len() > 1_000_000 {
            errors.push(VerifierError::new(
                0,
                format!(
                    "program too large: {} instructions (limit 1 000 000)",
                    instrs.len()
                ),
            ));
        }

        for (idx, instr) in instrs.iter().enumerate() {
            let op = instr.opcode;
            let cls = op & 0x07;

            // Check register validity.
            if instr.dst_reg > 10 {
                errors.push(VerifierError::new(
                    idx,
                    format!("invalid dst register r{}", instr.dst_reg),
                ));
            }
            if instr.src_reg > 10 {
                errors.push(VerifierError::new(
                    idx,
                    format!("invalid src register r{}", instr.src_reg),
                ));
            }

            // Stack-frame bounds check: STX/ST using r10 as base.
            if (cls == 0x02 || cls == 0x03) && instr.dst_reg == 10 {
                let off = i32::from(instr.offset);
                if !(-512..=0).contains(&off) {
                    errors.push(VerifierError::new(
                        idx,
                        format!("stack access out of bounds: r10+({off}) exceeds [-512, 0]"),
                    ));
                }
            }

            // LDX using r10 as src: read from stack.
            if cls == 0x01 && instr.src_reg == 10 {
                let off = i32::from(instr.offset);
                if !(-512..=0).contains(&off) {
                    errors.push(VerifierError::new(
                        idx,
                        format!("stack read out of bounds: r10+({off}) exceeds [-512, 0]"),
                    ));
                }
            }

            // Backward branch check (potential unbounded loop).
            if cls == 0x05 {
                let code = op & 0xf0;
                if code != 0x80 && code != 0x90 && instr.offset < 0 {
                    errors.push(VerifierError::new(
                        idx,
                        format!(
                            "backward branch at instr {idx}: offset {} may cause unbounded loop",
                            instr.offset
                        ),
                    ));
                }
            }
        }

        errors
    }
}

// ---------------------------------------------------------------------------
// BpfDisassembler —" formatted text disassembly
// ---------------------------------------------------------------------------

/// Produces formatted, human-readable disassembly text from eBPF bytecode.
pub struct BpfDisassembler;

impl BpfDisassembler {
    /// Disassemble `bytecode` into a multi-line string.
    ///
    /// Each line has the form:
    /// ```text
    /// <idx>: <pretty operands>    ; <MNEMONIC> detail
    /// ```
    ///
    /// Helper calls use the name from `helpers` when available.
    #[must_use]
    pub fn disassemble(bytecode: &[u8], helpers: &[BpfHelper]) -> String {
        // Build a fast lookup map from the provided helper slice.
        let helper_map: HashMap<i32, &'static str> =
            helpers.iter().map(|h| (h.id.cast_signed(), h.name)).collect();

        let mut lines = Vec::new();
        let mut offset = 0usize;
        let mut idx = 0usize;

        while offset + 8 <= bytecode.len() {
            let slice = &bytecode[offset..];
            if let Ok((instr, consumed)) = BpfInstruction::decode(slice) {
                let line = Self::format_instr(idx, &instr, &helper_map);
                lines.push(line);
                offset += consumed;
                idx += 1;
            } else {
                lines.push(format!("{idx}: <invalid byte 0x{:02x}>", bytecode[offset]));
                offset += 8;
                idx += 1;
            }
        }

        lines.join("\n")
    }

    /// Format a single decoded instruction into a display line.
    fn format_instr(
        idx: usize,
        instr: &BpfInstruction,
        helpers: &HashMap<i32, &'static str>,
    ) -> String {
        let op = instr.opcode;
        let cls = op & 0x07;
        let dst = reg_name(instr.dst_reg);
        let src = reg_name(instr.src_reg);
        let off = instr.offset;
        let imm = instr.imm;
        let src_is_reg = (op & 0x08) != 0;

        let (pretty, comment) = match cls {
            // ALU64 / ALU32
            0x07 | 0x04 => {
                let is64 = cls == 0x07;
                let suffix = if is64 { "" } else { "32" };
                let code = op & 0xf0;
                let (sym, mne) = match code {
                    0x00 => ("+=", format!("ADD64{suffix}")),
                    0x10 => ("-=", format!("SUB64{suffix}")),
                    0x20 => ("*=", format!("MUL64{suffix}")),
                    0x30 => ("/=", format!("DIV64{suffix}")),
                    0x40 => ("|=", format!("OR64{suffix}")),
                    0x50 => ("&=", format!("AND64{suffix}")),
                    0x60 => ("<<=", format!("LSH64{suffix}")),
                    0x70 => (">>=", format!("RSH64{suffix}")),
                    0x80 => ("= -", format!("NEG64{suffix}")),
                    0x90 => ("%=", format!("MOD64{suffix}")),
                    0xa0 => ("^=", format!("XOR64{suffix}")),
                    0xb0 => ("=", format!("MOV64{suffix}")),
                    0xc0 => ("s>>=", format!("ARSH64{suffix}")),
                    _ => ("?=", "ALU?".to_string()),
                };
                if code == 0x80 {
                    (format!("{dst} {sym}{dst}"), mne)
                } else if src_is_reg {
                    (format!("{dst} {sym} {src}"), format!("{mne} {dst}, {src}"))
                } else {
                    (format!("{dst} {sym} {imm}"), format!("{mne} {dst}, {imm}"))
                }
            }

            // JMP
            0x05 => {
                let code = op & 0xf0;
                match code {
                    0x00 => (format!("goto +{off}"), format!("JA +{off}")),
                    0x10 => {
                        let rhs = if src_is_reg {
                            src.to_string()
                        } else {
                            imm.to_string()
                        };
                        (
                            format!("if {dst} == {rhs} goto +{off}"),
                            format!("JEQ {dst}, {rhs}, +{off}"),
                        )
                    }
                    0x20 => {
                        let rhs = if src_is_reg {
                            src.to_string()
                        } else {
                            imm.to_string()
                        };
                        (
                            format!("if {dst} > {rhs} goto +{off}"),
                            format!("JGT {dst}, {rhs}, +{off}"),
                        )
                    }
                    0x30 => {
                        let rhs = if src_is_reg {
                            src.to_string()
                        } else {
                            imm.to_string()
                        };
                        (
                            format!("if {dst} >= {rhs} goto +{off}"),
                            format!("JGE {dst}, {rhs}, +{off}"),
                        )
                    }
                    0x50 => {
                        let rhs = if src_is_reg {
                            src.to_string()
                        } else {
                            imm.to_string()
                        };
                        (
                            format!("if {dst} != {rhs} goto +{off}"),
                            format!("JNE {dst}, {rhs}, +{off}"),
                        )
                    }
                    0x60 => {
                        let rhs = if src_is_reg {
                            src.to_string()
                        } else {
                            imm.to_string()
                        };
                        (
                            format!("if {dst} s> {rhs} goto +{off}"),
                            format!("JSGT {dst}, {rhs}, +{off}"),
                        )
                    }
                    0x70 => {
                        let rhs = if src_is_reg {
                            src.to_string()
                        } else {
                            imm.to_string()
                        };
                        (
                            format!("if {dst} s>= {rhs} goto +{off}"),
                            format!("JSGE {dst}, {rhs}, +{off}"),
                        )
                    }
                    0x80 => {
                        let name = helpers.get(&imm).copied().unwrap_or("unknown");
                        (format!("call {name}"), format!("helper#{imm}"))
                    }
                    0x90 => ("exit".to_string(), "BPF_EXIT".to_string()),
                    0xa0 => {
                        let rhs = if src_is_reg {
                            src.to_string()
                        } else {
                            imm.to_string()
                        };
                        (
                            format!("if {dst} < {rhs} goto +{off}"),
                            format!("JLT {dst}, {rhs}, +{off}"),
                        )
                    }
                    0xb0 => {
                        let rhs = if src_is_reg {
                            src.to_string()
                        } else {
                            imm.to_string()
                        };
                        (
                            format!("if {dst} <= {rhs} goto +{off}"),
                            format!("JLE {dst}, {rhs}, +{off}"),
                        )
                    }
                    0xc0 => {
                        let rhs = if src_is_reg {
                            src.to_string()
                        } else {
                            imm.to_string()
                        };
                        (
                            format!("if {dst} s< {rhs} goto +{off}"),
                            format!("JSLT {dst}, {rhs}, +{off}"),
                        )
                    }
                    0xd0 => {
                        let rhs = if src_is_reg {
                            src.to_string()
                        } else {
                            imm.to_string()
                        };
                        (
                            format!("if {dst} s<= {rhs} goto +{off}"),
                            format!("JSLE {dst}, {rhs}, +{off}"),
                        )
                    }
                    _ => (format!("jmp? 0x{op:02x}"), "JMP?".to_string()),
                }
            }

            // LDX
            0x01 => {
                let sz = BpfSize::from_opcode(op).map_or("?", BpfSize::suffix);
                (
                    format!("{dst} = *({sz} *)({src} + {off})"),
                    format!("LDX{} {dst}, [{src}+{off}]", sz.to_uppercase()),
                )
            }

            // ST (immediate store)
            0x02 => {
                if op == 0x18 {
                    // lddw
                    let wide = instr.wide_imm.unwrap_or(i64::from(imm));
                    (
                        format!("{dst} = {wide:#018x} ll"),
                        format!("LDDW {dst}, {wide:#018x}"),
                    )
                } else {
                    let sz = BpfSize::from_opcode(op).map_or("?", BpfSize::suffix);
                    (
                        format!("*({sz} *)({dst} + {off}) = {imm}"),
                        format!("ST{} [{dst}+{off}], {imm}", sz.to_uppercase()),
                    )
                }
            }

            // STX (register store)
            0x03 => {
                let sz = BpfSize::from_opcode(op).map_or("?", BpfSize::suffix);
                (
                    format!("*({sz} *)({dst} + {off}) = {src}"),
                    format!("STX{} [{dst}+{off}], {src}", sz.to_uppercase()),
                )
            }

            // LD (abs/ind/wide)
            0x00 => {
                if op == 0x18 {
                    let wide = instr.wide_imm.unwrap_or(i64::from(imm));
                    (
                        format!("{dst} = {wide:#018x} ll"),
                        format!("LDDW {dst}, {wide:#018x}"),
                    )
                } else {
                    let mode = op & 0xe0;
                    let sz = BpfSize::from_opcode(op).map_or("?", BpfSize::suffix);
                    if mode == 0x20 {
                        (
                            format!("r0 = *({sz} *)skb[{imm:#x}]"),
                            format!("LDABS{}", sz.to_uppercase()),
                        )
                    } else {
                        (
                            format!("r0 = *({sz} *)skb[{src} + {imm:#x}]"),
                            format!("LDIND{}", sz.to_uppercase()),
                        )
                    }
                }
            }

            _ => (format!("?? 0x{op:02x}"), "UNKNOWN".to_string()),
        };

        format!("{idx}: {pretty:<40} ; {comment}")
    }
}

// ---------------------------------------------------------------------------
// BpfObject —" ELF BPF object parser
// ---------------------------------------------------------------------------

/// A parsed BPF ELF object.
#[derive(Debug, Clone, Default)]
pub struct BpfObject {
    /// BPF programs found in the object.
    pub programs: Vec<BpfProg>,
    /// BPF maps found in the object.
    pub maps: Vec<BpfMap>,
    /// Raw BTF data, if a `.BTF` section was present.
    pub btf: Option<BtfData>,
}

/// A single BPF program extracted from an ELF section.
#[derive(Debug, Clone)]
pub struct BpfProg {
    /// Name of the ELF symbol or section (without `SEC()`).
    pub name: String,
    /// Full ELF section name (e.g. `"xdp"`, `"kprobe/sys_open"`).
    pub section: String,
    /// Inferred program type based on the section name prefix.
    pub prog_type: BpfProgramType,
    /// Raw eBPF bytecode.
    pub bytecode: Vec<u8>,
}

/// A BPF map definition found in an ELF `.maps` section.
#[derive(Debug, Clone, Default)]
pub struct BpfMap {
    /// Symbol name of the map.
    pub name: String,
    /// Map type id (see [`BpfMapType`]).
    pub type_: u32,
    /// Key size in bytes.
    pub key_size: u32,
    /// Value size in bytes.
    pub value_size: u32,
    /// Maximum number of entries.
    pub max_entries: u32,
}

/// Raw BTF blob extracted from the `.BTF` ELF section.
#[derive(Debug, Clone)]
pub struct BtfData {
    /// The raw bytes of the `.BTF` section.
    pub raw: Vec<u8>,
}

/// Parse errors produced by [`BpfObjectParser`].
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum BpfObjectError {
    /// The ELF magic was not recognised.
    #[error("not an ELF file")]
    NotElf,
    /// The ELF file is truncated or internally inconsistent.
    #[error("malformed ELF: {0}")]
    MalformedElf(String),
    /// A string-table offset was out of range.
    #[error("string table offset out of range")]
    StrTabOutOfRange,
}

/// ELF BPF object parser.
///
/// Parses a minimal subset of ELF64 LE sufficient to extract BPF programs,
/// map definitions, and BTF data without pulling in a heavy ELF library.
pub struct BpfObjectParser;

impl BpfObjectParser {
    // ELF64 constants.
    const ELFMAG: &'static [u8] = b"\x7fELF";
    const ET_REL: u16 = 1;
    const EM_BPF: u16 = 247;
    const SHT_PROGBITS: u32 = 1;
    const SHT_NULL: u32 = 0;

    /// Parse an ELF64 LE BPF object file.
    ///
    /// # Errors
    ///
    /// Returns [`BpfObjectError`] if the data is not a valid ELF64 file,
    /// or if internal structures are truncated.
    pub fn parse_elf(data: &[u8]) -> Result<BpfObject, BpfObjectError> {
        // Validate ELF magic.
        if data.len() < 16 || &data[0..4] != Self::ELFMAG {
            return Err(BpfObjectError::NotElf);
        }

        // EI_CLASS must be 2 (ELF64).
        if data[4] != 2 {
            return Err(BpfObjectError::MalformedElf("not ELF64".into()));
        }
        // EI_DATA must be 1 (LE).
        if data[5] != 1 {
            return Err(BpfObjectError::MalformedElf("not little-endian ELF".into()));
        }

        // e_type (offset 16) should be ET_REL for relocatable BPF objects,
        // and e_machine (offset 18) should be EM_BPF. We surface a descriptive
        // error if either field is present but does not match the expected value.
        let e_type = Self::read_u16(data, 16)?;
        let e_machine = Self::read_u16(data, 18)?;
        if e_type != Self::ET_REL {
            return Err(BpfObjectError::MalformedElf(format!(
                "unexpected e_type {e_type} (want ET_REL={})",
                Self::ET_REL
            )));
        }
        if e_machine != Self::EM_BPF {
            return Err(BpfObjectError::MalformedElf(format!(
                "unexpected e_machine {e_machine} (want EM_BPF={})",
                Self::EM_BPF
            )));
        }

        // ELF64 header fields.
        let e_shoff = crate::numeric::u64_to_usize(Self::read_u64(data, 40)?);
        let e_shentsize = Self::read_u16(data, 58)? as usize;
        let e_shnum = Self::read_u16(data, 60)? as usize;
        let e_shstrndx = Self::read_u16(data, 62)? as usize;

        if e_shentsize < 64 {
            return Err(BpfObjectError::MalformedElf(
                "section header entry too small".into(),
            ));
        }

        // Collect section headers.
        let mut sections: Vec<(String, u32, usize, usize)> = Vec::new(); // (name, sh_type, offset, size)
        for i in 0..e_shnum {
            let sh_off = e_shoff + i * e_shentsize;
            if sh_off + 64 > data.len() {
                break;
            }
            let sh_name = Self::read_u32(data, sh_off)? as usize;
            let sh_type = Self::read_u32(data, sh_off + 4)?;
            let sh_offset = crate::numeric::u64_to_usize(Self::read_u64(data, sh_off + 24)?);
            let sh_size = crate::numeric::u64_to_usize(Self::read_u64(data, sh_off + 32)?);
            sections.push((String::new(), sh_type, sh_offset, sh_size));
            let _ = sh_name; // resolved below
        }

        // Resolve section names from the string table section.
        let strtab_data = if e_shstrndx < sections.len() {
            let (_, _, off, sz) = sections[e_shstrndx];
            if off + sz <= data.len() {
                &data[off..off + sz]
            } else {
                &[]
            }
        } else {
            &[]
        };

        // Re-parse section names.
        let mut named: Vec<(String, u32, usize, usize)> = Vec::new();
        for i in 0..e_shnum {
            let sh_off = e_shoff + i * e_shentsize;
            if sh_off + 64 > data.len() {
                break;
            }
            let sh_name_off = Self::read_u32(data, sh_off)? as usize;
            let sh_type = Self::read_u32(data, sh_off + 4)?;
            let sh_offset = crate::numeric::u64_to_usize(Self::read_u64(data, sh_off + 24)?);
            let sh_size = crate::numeric::u64_to_usize(Self::read_u64(data, sh_off + 32)?);
            let name = Self::read_cstr(strtab_data, sh_name_off);
            named.push((name, sh_type, sh_offset, sh_size));
        }

        let mut obj = BpfObject::default();

        for (name, sh_type, sh_offset, sh_size) in &named {
            if *sh_type == Self::SHT_NULL {
                continue;
            }
            let end = sh_offset.saturating_add(*sh_size);
            let section_data = if end <= data.len() {
                &data[*sh_offset..end]
            } else {
                continue;
            };

            if name == ".BTF" {
                obj.btf = Some(BtfData {
                    raw: section_data.to_vec(),
                });
                continue;
            }

            if name == ".maps" || name.starts_with("maps/") {
                // Decode map definitions: each entry is 20 bytes (type, key_size,
                // value_size, max_entries, map_flags) matching `struct bpf_map_def`.
                let entry_size = 20usize;
                let count = sh_size / entry_size;
                for i in 0..count {
                    let base = i * entry_size;
                    if base + entry_size > section_data.len() {
                        break;
                    }
                    let type_ = Self::read_u32(section_data, base).unwrap_or(0);
                    let key_size = Self::read_u32(section_data, base + 4).unwrap_or(0);
                    let value_size = Self::read_u32(section_data, base + 8).unwrap_or(0);
                    let max_entries = Self::read_u32(section_data, base + 12).unwrap_or(0);
                    obj.maps.push(BpfMap {
                        name: format!("map_{i}"),
                        type_,
                        key_size,
                        value_size,
                        max_entries,
                    });
                }
                continue;
            }

            // Treat PROGBITS sections that contain eBPF bytecode (multiples of 8 bytes).
            if *sh_type == Self::SHT_PROGBITS
                && !section_data.is_empty()
                && section_data.len() % 8 == 0
                && !name.starts_with('.')
            {
                // Validate: first byte must be a plausible eBPF opcode class.
                let first_cls = section_data[0] & 0x07;
                if first_cls <= 0x07 {
                    let prog_type = Self::prog_type_from_section(name);
                    obj.programs.push(BpfProg {
                        name: name.clone(),
                        section: name.clone(),
                        prog_type,
                        bytecode: section_data.to_vec(),
                    });
                }
            }
        }

        Ok(obj)
    }

    /// Map an ELF section name prefix to a [`BpfProgramType`].
    fn prog_type_from_section(section: &str) -> BpfProgramType {
        if section.starts_with("xdp") {
            BpfProgramType::Xdp
        } else if section.starts_with("kprobe") || section.starts_with("kretprobe") {
            BpfProgramType::Kprobe
        } else if section.starts_with("tracepoint") || section.starts_with("tp/") {
            BpfProgramType::Tracepoint
        } else if section.starts_with("socket") {
            BpfProgramType::SocketFilter
        } else if section.starts_with("sched_cls") || section.starts_with("tc") {
            BpfProgramType::SchedCls
        } else if section.starts_with("sched_act") {
            BpfProgramType::SchedAct
        } else if section.starts_with("cgroup_skb") {
            BpfProgramType::CgroupSkb
        } else if section.starts_with("sk_skb") {
            BpfProgramType::SkSkb
        } else if section.starts_with("sk_msg") {
            BpfProgramType::SkMsg
        } else if section.starts_with("raw_tracepoint") || section.starts_with("raw_tp") {
            BpfProgramType::RawTracepoint
        } else if section.starts_with("lsm") {
            BpfProgramType::Lsm
        } else if section.starts_with("perf_event") {
            BpfProgramType::PerfEvent
        } else {
            BpfProgramType::Unspec
        }
    }

    // --- ELF read helpers ---

    fn read_u16(data: &[u8], off: usize) -> Result<u16, BpfObjectError> {
        data.get(off..off + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .ok_or_else(|| BpfObjectError::MalformedElf(format!("u16 at {off:#x} truncated")))
    }

    fn read_u32(data: &[u8], off: usize) -> Result<u32, BpfObjectError> {
        data.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or_else(|| BpfObjectError::MalformedElf(format!("u32 at {off:#x} truncated")))
    }

    fn read_u64(data: &[u8], off: usize) -> Result<u64, BpfObjectError> {
        read_u64_le(data, off)
            .ok_or_else(|| BpfObjectError::MalformedElf(format!("u64 at {off:#x} truncated")))
    }

    /// Read a NUL-terminated C string from `data` at byte offset `off`.
    fn read_cstr(data: &[u8], off: usize) -> String {
        if off >= data.len() {
            return String::new();
        }
        let slice = &data[off..];
        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        String::from_utf8_lossy(&slice[..end]).into_owned()
    }
}

// ---------------------------------------------------------------------------
// BtfParser —" BPF Type Format (BTF) basic parsing
// ---------------------------------------------------------------------------

/// Basic parser for the BTF (BPF Type Format) binary format.
///
/// BTF header layout (little-endian):
/// ```text
/// u16 magic    = 0xEB9F
/// u8  version  = 1
/// u8  flags
/// u32 hdr_len
/// u32 type_off
/// u32 type_len
/// u32 str_off
/// u32 str_len
/// ```
pub struct BtfParser;

/// The BTF magic number (`0xEB9F` in LE byte order).
pub const BTF_MAGIC: u16 = 0xEB9F;
/// BTF format version supported by this parser.
pub const BTF_VERSION: u8 = 1;

impl BtfParser {
    /// Find and extract the `.BTF` section from a raw ELF file.
    ///
    /// Returns `None` if no `.BTF` section is present or the ELF is not valid.
    #[must_use]
    pub fn find_btf_section(elf_data: &[u8]) -> Option<Vec<u8>> {
        // Quick check: must be ELF.
        if elf_data.len() < 16 || &elf_data[0..4] != b"\x7fELF" {
            return None;
        }
        // Parse via BpfObjectParser; return the raw BTF blob if present.
        BpfObjectParser::parse_elf(elf_data)
            .ok()
            .and_then(|obj| obj.btf)
            .map(|b| b.raw)
    }

    /// Validate the BTF header magic and version.
    ///
    /// Returns `true` when `btf` starts with the correct magic (`0xEB9F` LE)
    /// and version byte `1`.
    #[must_use]
    pub fn is_valid(btf: &[u8]) -> bool {
        if btf.len() < 4 {
            return false;
        }
        let magic = u16::from_le_bytes([btf[0], btf[1]]);
        let version = btf[2];
        magic == BTF_MAGIC && version == BTF_VERSION
    }

    /// Count the number of type entries in a BTF blob.
    ///
    /// Parses the BTF header to find `type_off` and `type_len`, then walks
    /// the type section counting 12-byte `btf_type` structs (plus variable-length
    /// data that is skipped via the `vlen` field).
    ///
    /// Returns `0` if the blob is too short, the magic is wrong, or the header
    /// is internally inconsistent.
    #[must_use]
    pub fn count_types(btf: &[u8]) -> usize {
        if !Self::is_valid(btf) {
            return 0;
        }
        if btf.len() < 24 {
            return 0;
        }

        let hdr_len = u32::from_le_bytes([btf[4], btf[5], btf[6], btf[7]]) as usize;
        let type_off = u32::from_le_bytes([btf[8], btf[9], btf[10], btf[11]]) as usize;
        let type_len = u32::from_le_bytes([btf[12], btf[13], btf[14], btf[15]]) as usize;

        let types_start = hdr_len + type_off;
        let types_end = types_start + type_len;

        if types_end > btf.len() {
            return 0;
        }

        let type_bytes = &btf[types_start..types_end];
        let mut count = 0usize;
        let mut off = 0usize;

        while off + 12 <= type_bytes.len() {
            // Read the info word to get kind and vlen.
            let info = u32::from_le_bytes([
                type_bytes[off + 4],
                type_bytes[off + 5],
                type_bytes[off + 6],
                type_bytes[off + 7],
            ]);
            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;

            // Extra bytes that follow the 12-byte base struct, per kind.
            let extra = Self::kind_extra_bytes(kind, vlen);
            off += 12 + extra;
            count += 1;
        }

        count
    }

    /// Return the number of extra bytes that follow the 12-byte `btf_type`
    /// base struct for a given kind and vlen.
    ///
    /// See `include/uapi/linux/btf.h` for the per-kind trailing data.
    const fn kind_extra_bytes(kind: u32, vlen: usize) -> usize {
        let mut i = 0;
        while i < BTF_KIND_EXTRA_TABLE.len() {
            let (k, fixed, per_vlen) = BTF_KIND_EXTRA_TABLE[i];
            if k == kind {
                return fixed + vlen * per_vlen;
            }
            i += 1;
        }
        0
    }
}

/// Ordered `(kind, fixed_bytes, bytes_per_vlen)` rows for the trailing data
/// that follows the 12-byte `btf_type` base struct, one row per BTF kind.
///
/// See `include/uapi/linux/btf.h`. A kind with no row has no trailing data.
const BTF_KIND_EXTRA_TABLE: &[(u32, usize, usize)] = &[
    (1, 4, 0),   // BTF_KIND_INT: one u32 encoding
    (3, 12, 0),  // BTF_KIND_ARRAY: struct btf_array (3 x u32)
    (4, 0, 12),  // BTF_KIND_STRUCT: vlen x btf_member
    (5, 0, 12),  // BTF_KIND_UNION: vlen x btf_member
    (6, 0, 8),   // BTF_KIND_ENUM: vlen x btf_enum
    (13, 0, 8),  // BTF_KIND_FUNC_PROTO: vlen x btf_param
    (15, 0, 12), // BTF_KIND_DATASEC: vlen x btf_var_secinfo
    (17, 4, 0),  // BTF_KIND_DECL_TAG: one s32 component_idx
    (19, 0, 12), // BTF_KIND_ENUM64: vlen x btf_enum64
];

// ---------------------------------------------------------------------------
// BPF Helper Database
// ---------------------------------------------------------------------------

/// Metadata for a single BPF helper function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfHelperFull {
    /// Kernel-assigned helper ID (argument to `BPF_CALL`).
    pub id: u32,
    /// Helper name, e.g. `"bpf_map_lookup_elem"`.
    pub name: &'static str,
    /// C prototype string.
    pub proto: &'static str,
    /// Helper may sleep (only callable from sleepable programs).
    pub may_sleep: bool,
    /// Helper touches packet data (requires `pkt_access` privilege).
    pub pkt_access: bool,
}

/// Complete table of known BPF helpers (IDs 1—"206).
pub static HELPERS: &[BpfHelperFull] = &[
    BpfHelperFull {
        id: 1,
        name: "bpf_map_lookup_elem",
        proto: "void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 2,
        name: "bpf_map_update_elem",
        proto: "int bpf_map_update_elem(struct bpf_map *map, const void *key, const void *value, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 3,
        name: "bpf_map_delete_elem",
        proto: "int bpf_map_delete_elem(struct bpf_map *map, const void *key)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 4,
        name: "bpf_probe_read",
        proto: "int bpf_probe_read(void *dst, u32 size, const void *unsafe_ptr)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 5,
        name: "bpf_ktime_get_ns",
        proto: "u64 bpf_ktime_get_ns(void)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 6,
        name: "bpf_trace_printk",
        proto: "int bpf_trace_printk(const char *fmt, u32 fmt_size, ...)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 7,
        name: "bpf_get_prandom_u32",
        proto: "u32 bpf_get_prandom_u32(void)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 8,
        name: "bpf_get_smp_processor_id",
        proto: "u32 bpf_get_smp_processor_id(void)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 9,
        name: "bpf_skb_store_bytes",
        proto: "int bpf_skb_store_bytes(struct sk_buff *skb, u32 offset, const void *from, u32 len, u64 flags)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 10,
        name: "bpf_l3_csum_replace",
        proto: "int bpf_l3_csum_replace(struct sk_buff *skb, u32 offset, u64 from, u64 to, u64 size)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 11,
        name: "bpf_l4_csum_replace",
        proto: "int bpf_l4_csum_replace(struct sk_buff *skb, u32 offset, u64 from, u64 to, u64 flags)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 12,
        name: "bpf_tail_call",
        proto: "long bpf_tail_call(void *ctx, struct bpf_map *prog_array_map, u32 index)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 13,
        name: "bpf_clone_redirect",
        proto: "long bpf_clone_redirect(struct sk_buff *skb, u32 ifindex, u64 flags)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 14,
        name: "bpf_get_current_pid_tgid",
        proto: "u64 bpf_get_current_pid_tgid(void)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 15,
        name: "bpf_get_current_uid_gid",
        proto: "u64 bpf_get_current_uid_gid(void)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 16,
        name: "bpf_get_current_comm",
        proto: "long bpf_get_current_comm(void *buf, u32 size_of_buf)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 17,
        name: "bpf_get_cgroup_classid",
        proto: "u32 bpf_get_cgroup_classid(struct sk_buff *skb)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 18,
        name: "bpf_skb_vlan_push",
        proto: "long bpf_skb_vlan_push(struct sk_buff *skb, __be16 vlan_proto, u16 vlan_tci)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 19,
        name: "bpf_skb_vlan_pop",
        proto: "long bpf_skb_vlan_pop(struct sk_buff *skb)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 20,
        name: "bpf_skb_get_tunnel_key",
        proto: "long bpf_skb_get_tunnel_key(struct sk_buff *skb, struct bpf_tunnel_key *key, u32 size, u64 flags)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 21,
        name: "bpf_skb_set_tunnel_key",
        proto: "long bpf_skb_set_tunnel_key(struct sk_buff *skb, struct bpf_tunnel_key *key, u32 size, u64 flags)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 22,
        name: "bpf_perf_event_read",
        proto: "u64 bpf_perf_event_read(struct bpf_map *map, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 23,
        name: "bpf_redirect",
        proto: "long bpf_redirect(u32 ifindex, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 24,
        name: "bpf_get_route_realm",
        proto: "u32 bpf_get_route_realm(struct sk_buff *skb)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 25,
        name: "bpf_perf_event_output",
        proto: "long bpf_perf_event_output(void *ctx, struct bpf_map *map, u64 flags, void *data, u64 size)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 26,
        name: "bpf_skb_load_bytes",
        proto: "long bpf_skb_load_bytes(const void *skb, u32 offset, void *to, u32 len)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 27,
        name: "bpf_get_stackid",
        proto: "long bpf_get_stackid(void *ctx, struct bpf_map *map, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 28,
        name: "bpf_csum_diff",
        proto: "__wsum bpf_csum_diff(__be32 *from, u32 from_size, __be32 *to, u32 to_size, __wsum seed)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 29,
        name: "bpf_skb_get_tunnel_opt",
        proto: "long bpf_skb_get_tunnel_opt(struct sk_buff *skb, void *opt, u32 size)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 30,
        name: "bpf_skb_set_tunnel_opt",
        proto: "long bpf_skb_set_tunnel_opt(struct sk_buff *skb, void *opt, u32 size)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 31,
        name: "bpf_skb_change_proto",
        proto: "long bpf_skb_change_proto(struct sk_buff *skb, __be16 proto, u64 flags)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 32,
        name: "bpf_skb_change_type",
        proto: "long bpf_skb_change_type(struct sk_buff *skb, u32 type)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 33,
        name: "bpf_skb_under_cgroup",
        proto: "long bpf_skb_under_cgroup(struct sk_buff *skb, struct bpf_map *map, u32 index)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 34,
        name: "bpf_get_hash_recalc",
        proto: "u32 bpf_get_hash_recalc(struct sk_buff *skb)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 35,
        name: "bpf_get_current_task",
        proto: "u64 bpf_get_current_task(void)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 36,
        name: "bpf_probe_write_user",
        proto: "long bpf_probe_write_user(void *dst, const void *src, u32 len)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 37,
        name: "bpf_current_task_under_cgroup",
        proto: "long bpf_current_task_under_cgroup(struct bpf_map *map, u32 index)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 38,
        name: "bpf_skb_change_tail",
        proto: "long bpf_skb_change_tail(struct sk_buff *skb, u32 len, u64 flags)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 39,
        name: "bpf_skb_pull_data",
        proto: "long bpf_skb_pull_data(struct sk_buff *skb, u32 len)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 40,
        name: "bpf_csum_update",
        proto: "__wsum bpf_csum_update(struct sk_buff *skb, __wsum csum)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 41,
        name: "bpf_set_hash_invalid",
        proto: "void bpf_set_hash_invalid(struct sk_buff *skb)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 42,
        name: "bpf_get_numa_node_id",
        proto: "long bpf_get_numa_node_id(void)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 43,
        name: "bpf_skb_change_head",
        proto: "long bpf_skb_change_head(struct sk_buff *skb, u32 len, u64 flags)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 44,
        name: "bpf_xdp_adjust_head",
        proto: "long bpf_xdp_adjust_head(struct xdp_md *xdp_md, int delta)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 45,
        name: "bpf_probe_read_str",
        proto: "long bpf_probe_read_str(void *dst, u32 size, const void *unsafe_ptr)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 46,
        name: "bpf_get_socket_cookie",
        proto: "u64 bpf_get_socket_cookie(void *ctx)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 47,
        name: "bpf_get_socket_uid",
        proto: "u32 bpf_get_socket_uid(struct sk_buff *skb)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 48,
        name: "bpf_set_hash",
        proto: "u32 bpf_set_hash(struct sk_buff *skb, u32 hash)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 49,
        name: "bpf_setsockopt",
        proto: "long bpf_setsockopt(void *bpf_socket, int level, int optname, void *optval, int optlen)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 50,
        name: "bpf_skb_adjust_room",
        proto: "long bpf_skb_adjust_room(struct sk_buff *skb, s32 len_diff, u32 mode, u64 flags)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 51,
        name: "bpf_redirect_map",
        proto: "long bpf_redirect_map(struct bpf_map *map, u32 key, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 52,
        name: "bpf_sk_redirect_map",
        proto: "long bpf_sk_redirect_map(struct sk_buff *skb, struct bpf_map *map, u32 key, u64 flags)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 53,
        name: "bpf_sock_map_update",
        proto: "long bpf_sock_map_update(struct bpf_sock_ops *skops, struct bpf_map *map, void *key, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 54,
        name: "bpf_xdp_adjust_meta",
        proto: "long bpf_xdp_adjust_meta(struct xdp_md *xdp_md, int delta)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 55,
        name: "bpf_perf_event_read_value",
        proto: "long bpf_perf_event_read_value(struct bpf_map *map, u64 flags, struct bpf_perf_event_value *buf, u32 buf_size)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 56,
        name: "bpf_perf_prog_read_value",
        proto: "long bpf_perf_prog_read_value(struct bpf_perf_event_data *ctx, struct bpf_perf_event_value *buf, u32 buf_size)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 57,
        name: "bpf_getsockopt",
        proto: "long bpf_getsockopt(void *bpf_socket, int level, int optname, void *optval, int optlen)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 58,
        name: "bpf_override_return",
        proto: "long bpf_override_return(struct pt_regs *regs, u64 rc)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 59,
        name: "bpf_sock_ops_cb_flags_set",
        proto: "long bpf_sock_ops_cb_flags_set(struct bpf_sock_ops *bpf_sock, int argval)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 60,
        name: "bpf_msg_redirect_map",
        proto: "long bpf_msg_redirect_map(struct sk_msg_md *msg, struct bpf_map *map, u32 key, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 61,
        name: "bpf_msg_apply_bytes",
        proto: "long bpf_msg_apply_bytes(struct sk_msg_md *msg, u32 bytes)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 62,
        name: "bpf_msg_cork_bytes",
        proto: "long bpf_msg_cork_bytes(struct sk_msg_md *msg, u32 bytes)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 63,
        name: "bpf_msg_pull_data",
        proto: "long bpf_msg_pull_data(struct sk_msg_md *msg, u32 start, u32 end, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 64,
        name: "bpf_bind",
        proto: "long bpf_bind(struct bpf_sock_addr *ctx, struct sockaddr *addr, int addr_len)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 65,
        name: "bpf_xdp_adjust_tail",
        proto: "long bpf_xdp_adjust_tail(struct xdp_md *xdp_md, int delta)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 66,
        name: "bpf_skb_get_xfrm_state",
        proto: "long bpf_skb_get_xfrm_state(struct sk_buff *skb, u32 index, struct bpf_xfrm_state *xfrm_state, u32 size, u64 flags)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 67,
        name: "bpf_get_stack",
        proto: "long bpf_get_stack(void *ctx, void *buf, u32 size, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 68,
        name: "bpf_skb_load_bytes_relative",
        proto: "long bpf_skb_load_bytes_relative(const void *skb, u32 offset, void *to, u32 len, u32 start_header)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 69,
        name: "bpf_fib_lookup",
        proto: "long bpf_fib_lookup(void *ctx, struct bpf_fib_lookup *params, int plen, u32 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 70,
        name: "bpf_sock_hash_update",
        proto: "long bpf_sock_hash_update(struct bpf_sock_ops *skops, struct bpf_map *map, void *key, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 71,
        name: "bpf_msg_redirect_hash",
        proto: "long bpf_msg_redirect_hash(struct sk_msg_md *msg, struct bpf_map *map, void *key, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 72,
        name: "bpf_sk_redirect_hash",
        proto: "long bpf_sk_redirect_hash(struct sk_buff *skb, struct bpf_map *map, void *key, u64 flags)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 73,
        name: "bpf_lwt_push_encap",
        proto: "long bpf_lwt_push_encap(struct sk_buff *skb, u32 type, void *hdr, u32 len)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 74,
        name: "bpf_lwt_seg6_store_bytes",
        proto: "long bpf_lwt_seg6_store_bytes(struct sk_buff *skb, u32 offset, const void *from, u32 len)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 75,
        name: "bpf_lwt_seg6_adjust_srh",
        proto: "long bpf_lwt_seg6_adjust_srh(struct sk_buff *skb, u32 offset, s32 delta)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 76,
        name: "bpf_lwt_seg6_action",
        proto: "long bpf_lwt_seg6_action(struct sk_buff *skb, u32 action, void *param, u32 param_len)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 77,
        name: "bpf_rc_repeat",
        proto: "long bpf_rc_repeat(void *ctx)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 78,
        name: "bpf_rc_keydown",
        proto: "long bpf_rc_keydown(void *ctx, u32 protocol, u64 scancode, u32 toggle)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 79,
        name: "bpf_skb_cgroup_id",
        proto: "u64 bpf_skb_cgroup_id(struct sk_buff *skb)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 80,
        name: "bpf_get_current_cgroup_id",
        proto: "u64 bpf_get_current_cgroup_id(void)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 81,
        name: "bpf_get_local_storage",
        proto: "void *bpf_get_local_storage(void *map, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 82,
        name: "bpf_sk_select_reuseport",
        proto: "long bpf_sk_select_reuseport(struct sk_reuseport_md *reuse, struct bpf_map *map, void *key, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 83,
        name: "bpf_skb_ancestor_cgroup_id",
        proto: "u64 bpf_skb_ancestor_cgroup_id(struct sk_buff *skb, int ancestor_level)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 84,
        name: "bpf_sk_lookup_tcp",
        proto: "struct bpf_sock *bpf_sk_lookup_tcp(void *ctx, struct bpf_sock_tuple *tuple, u32 tuple_size, u64 netns, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 85,
        name: "bpf_sk_lookup_udp",
        proto: "struct bpf_sock *bpf_sk_lookup_udp(void *ctx, struct bpf_sock_tuple *tuple, u32 tuple_size, u64 netns, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 86,
        name: "bpf_sk_release",
        proto: "long bpf_sk_release(void *sock)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 87,
        name: "bpf_map_push_elem",
        proto: "long bpf_map_push_elem(struct bpf_map *map, const void *value, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 88,
        name: "bpf_map_pop_elem",
        proto: "long bpf_map_pop_elem(struct bpf_map *map, void *value)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 89,
        name: "bpf_map_peek_elem",
        proto: "long bpf_map_peek_elem(struct bpf_map *map, void *value)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 90,
        name: "bpf_msg_push_data",
        proto: "long bpf_msg_push_data(struct sk_msg_md *msg, u32 start, u32 len, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 91,
        name: "bpf_msg_pop_data",
        proto: "long bpf_msg_pop_data(struct sk_msg_md *msg, u32 start, u32 len, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 92,
        name: "bpf_rc_pointer_rel",
        proto: "long bpf_rc_pointer_rel(void *ctx, s32 rel_x, s32 rel_y)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 93,
        name: "bpf_spin_lock",
        proto: "void bpf_spin_lock(struct bpf_spin_lock *lock)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 94,
        name: "bpf_spin_unlock",
        proto: "void bpf_spin_unlock(struct bpf_spin_lock *lock)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 95,
        name: "bpf_sk_fullsock",
        proto: "struct bpf_sock *bpf_sk_fullsock(struct bpf_sock *sk)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 96,
        name: "bpf_tcp_sock",
        proto: "struct bpf_tcp_sock *bpf_tcp_sock(struct bpf_sock *sk)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 97,
        name: "bpf_skb_ecn_set_ce",
        proto: "long bpf_skb_ecn_set_ce(struct sk_buff *skb)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 98,
        name: "bpf_get_listener_sock",
        proto: "struct bpf_sock *bpf_get_listener_sock(struct bpf_sock *sk)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 99,
        name: "bpf_skc_lookup_tcp",
        proto: "struct bpf_sock *bpf_skc_lookup_tcp(void *ctx, struct bpf_sock_tuple *tuple, u32 tuple_size, u64 netns, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 100,
        name: "bpf_tcp_check_syncookie",
        proto: "long bpf_tcp_check_syncookie(void *sk, void *iph, u32 iph_len, struct tcphdr *th, u32 th_len)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 101,
        name: "bpf_sysctl_get_name",
        proto: "long bpf_sysctl_get_name(struct bpf_sysctl *ctx, char *buf, size_t buf_len, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 102,
        name: "bpf_sysctl_get_current_value",
        proto: "long bpf_sysctl_get_current_value(struct bpf_sysctl *ctx, char *buf, size_t buf_len)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 103,
        name: "bpf_sysctl_get_new_value",
        proto: "long bpf_sysctl_get_new_value(struct bpf_sysctl *ctx, char *buf, size_t buf_len)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 104,
        name: "bpf_sysctl_set_new_value",
        proto: "long bpf_sysctl_set_new_value(struct bpf_sysctl *ctx, const char *buf, size_t buf_len)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 105,
        name: "bpf_strtol",
        proto: "long bpf_strtol(const char *buf, size_t buf_len, u64 flags, long *res)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 106,
        name: "bpf_strtoul",
        proto: "long bpf_strtoul(const char *buf, size_t buf_len, u64 flags, unsigned long *res)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 107,
        name: "bpf_sk_storage_get",
        proto: "void *bpf_sk_storage_get(struct bpf_map *map, void *sk, void *value, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 108,
        name: "bpf_sk_storage_delete",
        proto: "long bpf_sk_storage_delete(struct bpf_map *map, void *sk)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 109,
        name: "bpf_send_signal",
        proto: "long bpf_send_signal(u32 sig)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 110,
        name: "bpf_tcp_gen_syncookie",
        proto: "s64 bpf_tcp_gen_syncookie(void *sk, void *iph, u32 iph_len, struct tcphdr *th, u32 th_len)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 111,
        name: "bpf_skb_output",
        proto: "long bpf_skb_output(void *ctx, struct bpf_map *map, u64 flags, void *data, u64 size)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 112,
        name: "bpf_probe_read_user",
        proto: "long bpf_probe_read_user(void *dst, u32 size, const void *unsafe_ptr)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 113,
        name: "bpf_probe_read_kernel",
        proto: "long bpf_probe_read_kernel(void *dst, u32 size, const void *unsafe_ptr)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 114,
        name: "bpf_probe_read_user_str",
        proto: "long bpf_probe_read_user_str(void *dst, u32 size, const void *unsafe_ptr)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 115,
        name: "bpf_probe_read_kernel_str",
        proto: "long bpf_probe_read_kernel_str(void *dst, u32 size, const void *unsafe_ptr)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 116,
        name: "bpf_tcp_send_ack",
        proto: "long bpf_tcp_send_ack(void *tp, u32 rcv_nxt)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 117,
        name: "bpf_send_signal_thread",
        proto: "long bpf_send_signal_thread(u32 sig)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 118,
        name: "bpf_jiffies64",
        proto: "u64 bpf_jiffies64(void)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 119,
        name: "bpf_read_branch_records",
        proto: "long bpf_read_branch_records(struct bpf_perf_event_data *ctx, void *buf, u32 size, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 120,
        name: "bpf_get_ns_current_pid_tgid",
        proto: "long bpf_get_ns_current_pid_tgid(u64 dev, u64 ino, struct bpf_pidns_info *nsdata, u32 size)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 121,
        name: "bpf_xdp_output",
        proto: "long bpf_xdp_output(void *ctx, struct bpf_map *map, u64 flags, void *data, u64 size)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 122,
        name: "bpf_get_netns_cookie",
        proto: "u64 bpf_get_netns_cookie(void *ctx)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 123,
        name: "bpf_get_current_ancestor_cgroup_id",
        proto: "u64 bpf_get_current_ancestor_cgroup_id(int ancestor_level)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 124,
        name: "bpf_sk_assign",
        proto: "long bpf_sk_assign(void *ctx, void *sk, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 125,
        name: "bpf_ktime_get_boot_ns",
        proto: "u64 bpf_ktime_get_boot_ns(void)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 126,
        name: "bpf_seq_printf",
        proto: "long bpf_seq_printf(struct seq_file *m, const char *fmt, u32 fmt_size, const void *data, u32 data_len)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 127,
        name: "bpf_seq_write",
        proto: "long bpf_seq_write(struct seq_file *m, const void *data, u32 len)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 128,
        name: "bpf_sk_cgroup_id",
        proto: "u64 bpf_sk_cgroup_id(void *sk)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 129,
        name: "bpf_sk_ancestor_cgroup_id",
        proto: "u64 bpf_sk_ancestor_cgroup_id(void *sk, int ancestor_level)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 130,
        name: "bpf_ringbuf_output",
        proto: "long bpf_ringbuf_output(void *ringbuf, void *data, u64 size, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 131,
        name: "bpf_ringbuf_reserve",
        proto: "void *bpf_ringbuf_reserve(void *ringbuf, u64 size, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 132,
        name: "bpf_ringbuf_submit",
        proto: "void bpf_ringbuf_submit(void *data, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 133,
        name: "bpf_ringbuf_discard",
        proto: "void bpf_ringbuf_discard(void *data, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 134,
        name: "bpf_ringbuf_query",
        proto: "u64 bpf_ringbuf_query(void *ringbuf, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 135,
        name: "bpf_csum_level",
        proto: "long bpf_csum_level(struct sk_buff *skb, u64 level)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 136,
        name: "bpf_skc_to_tcp6_sock",
        proto: "struct tcp6_sock *bpf_skc_to_tcp6_sock(void *sk)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 137,
        name: "bpf_skc_to_tcp_sock",
        proto: "struct tcp_sock *bpf_skc_to_tcp_sock(void *sk)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 138,
        name: "bpf_skc_to_tcp_timewait_sock",
        proto: "struct tcp_timewait_sock *bpf_skc_to_tcp_timewait_sock(void *sk)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 139,
        name: "bpf_skc_to_tcp_request_sock",
        proto: "struct tcp_request_sock *bpf_skc_to_tcp_request_sock(void *sk)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 140,
        name: "bpf_skc_to_udp6_sock",
        proto: "struct udp6_sock *bpf_skc_to_udp6_sock(void *sk)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 141,
        name: "bpf_get_task_stack",
        proto: "long bpf_get_task_stack(struct task_struct *task, void *buf, u32 size, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 142,
        name: "bpf_load_hdr_opt",
        proto: "long bpf_load_hdr_opt(struct bpf_sock_ops *skops, void *searchby_res, u32 len, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 143,
        name: "bpf_store_hdr_opt",
        proto: "long bpf_store_hdr_opt(struct bpf_sock_ops *skops, const void *from, u32 len, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 144,
        name: "bpf_reserve_hdr_opt",
        proto: "long bpf_reserve_hdr_opt(struct bpf_sock_ops *skops, u32 len, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 145,
        name: "bpf_inode_storage_get",
        proto: "void *bpf_inode_storage_get(struct bpf_map *map, void *inode, void *value, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 146,
        name: "bpf_inode_storage_delete",
        proto: "int bpf_inode_storage_delete(struct bpf_map *map, void *inode)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 147,
        name: "bpf_d_path",
        proto: "long bpf_d_path(struct path *path, char *buf, u32 sz)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 148,
        name: "bpf_copy_from_user",
        proto: "long bpf_copy_from_user(void *dst, u32 size, const void *user_ptr)",
        may_sleep: true,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 149,
        name: "bpf_snprintf_btf",
        proto: "long bpf_snprintf_btf(char *str, u32 str_size, struct btf_ptr *ptr, u32 btf_ptr_size, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 150,
        name: "bpf_seq_printf_btf",
        proto: "long bpf_seq_printf_btf(struct seq_file *m, struct btf_ptr *ptr, u32 ptr_size, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 151,
        name: "bpf_skb_cgroup_classid",
        proto: "u64 bpf_skb_cgroup_classid(struct sk_buff *skb)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 152,
        name: "bpf_redirect_neigh",
        proto: "long bpf_redirect_neigh(u32 ifindex, struct bpf_redir_neigh *params, int plen, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 153,
        name: "bpf_per_cpu_ptr",
        proto: "void *bpf_per_cpu_ptr(const void *percpu_ptr, u32 cpu)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 154,
        name: "bpf_this_cpu_ptr",
        proto: "void *bpf_this_cpu_ptr(const void *percpu_ptr)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 155,
        name: "bpf_redirect_peer",
        proto: "long bpf_redirect_peer(u32 ifindex, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 156,
        name: "bpf_task_storage_get",
        proto: "void *bpf_task_storage_get(struct bpf_map *map, struct task_struct *task, void *value, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 157,
        name: "bpf_task_storage_delete",
        proto: "long bpf_task_storage_delete(struct bpf_map *map, struct task_struct *task)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 158,
        name: "bpf_get_current_task_btf",
        proto: "struct task_struct *bpf_get_current_task_btf(void)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 159,
        name: "bpf_bprm_opts_set",
        proto: "long bpf_bprm_opts_set(struct linux_binprm *bprm, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 160,
        name: "bpf_ktime_get_coarse_ns",
        proto: "u64 bpf_ktime_get_coarse_ns(void)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 161,
        name: "bpf_ima_inode_hash",
        proto: "long bpf_ima_inode_hash(struct inode *inode, void *dst, u32 size)",
        may_sleep: true,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 162,
        name: "bpf_sock_from_file",
        proto: "struct socket *bpf_sock_from_file(struct file *file)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 163,
        name: "bpf_check_mtu",
        proto: "long bpf_check_mtu(void *ctx, u32 ifindex, u32 *mtu_len, s32 len_diff, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 164,
        name: "bpf_for_each_map_elem",
        proto: "long bpf_for_each_map_elem(struct bpf_map *map, void *callback_fn, void *callback_ctx, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 165,
        name: "bpf_snprintf",
        proto: "long bpf_snprintf(char *str, u32 str_size, const char *fmt, u64 *data, u32 data_len)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 166,
        name: "bpf_sys_bpf",
        proto: "long bpf_sys_bpf(u32 cmd, union bpf_attr *attr, u32 attr_size)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 167,
        name: "bpf_btf_find_by_name_kind",
        proto: "long bpf_btf_find_by_name_kind(char *name, int name_sz, u32 kind, int flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 168,
        name: "bpf_sys_close",
        proto: "long bpf_sys_close(u32 fd)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 169,
        name: "bpf_timer_init",
        proto: "long bpf_timer_init(struct bpf_timer *timer, struct bpf_map *map, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 170,
        name: "bpf_timer_set_callback",
        proto: "long bpf_timer_set_callback(struct bpf_timer *timer, void *callback_fn)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 171,
        name: "bpf_timer_start",
        proto: "long bpf_timer_start(struct bpf_timer *timer, u64 nsecs, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 172,
        name: "bpf_timer_cancel",
        proto: "long bpf_timer_cancel(struct bpf_timer *timer)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 173,
        name: "bpf_get_func_ip",
        proto: "u64 bpf_get_func_ip(void *ctx)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 174,
        name: "bpf_get_attach_cookie",
        proto: "u64 bpf_get_attach_cookie(void *ctx)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 175,
        name: "bpf_task_pt_regs",
        proto: "long bpf_task_pt_regs(struct task_struct *task)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 176,
        name: "bpf_get_branch_snapshot",
        proto: "long bpf_get_branch_snapshot(void *entries, u32 size, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 177,
        name: "bpf_trace_vprintk",
        proto: "long bpf_trace_vprintk(const char *fmt, u32 fmt_size, const void *data, u32 data_len)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 178,
        name: "bpf_skc_to_unix_sock",
        proto: "struct unix_sock *bpf_skc_to_unix_sock(void *sk)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 179,
        name: "bpf_kallsyms_lookup_name",
        proto: "long bpf_kallsyms_lookup_name(const char *name, int name_sz, int flags, u64 *res)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 180,
        name: "bpf_find_vma",
        proto: "long bpf_find_vma(struct task_struct *task, u64 addr, void *callback_fn, void *callback_ctx, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 181,
        name: "bpf_loop",
        proto: "long bpf_loop(u32 nr_loops, void *callback_fn, void *callback_ctx, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 182,
        name: "bpf_strncmp",
        proto: "long bpf_strncmp(const char *s1, u32 s1_sz, const char *s2)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 183,
        name: "bpf_get_func_arg",
        proto: "long bpf_get_func_arg(void *ctx, u32 n, u64 *value)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 184,
        name: "bpf_get_func_ret",
        proto: "long bpf_get_func_ret(void *ctx, u64 *value)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 185,
        name: "bpf_get_func_arg_cnt",
        proto: "long bpf_get_func_arg_cnt(void *ctx)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 186,
        name: "bpf_get_retval",
        proto: "int bpf_get_retval(void)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 187,
        name: "bpf_set_retval",
        proto: "int bpf_set_retval(int retval)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 188,
        name: "bpf_xdp_get_buff_len",
        proto: "u64 bpf_xdp_get_buff_len(struct xdp_md *xdp_md)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 189,
        name: "bpf_xdp_load_bytes",
        proto: "long bpf_xdp_load_bytes(struct xdp_md *xdp_md, u32 offset, void *buf, u32 len)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 190,
        name: "bpf_xdp_store_bytes",
        proto: "long bpf_xdp_store_bytes(struct xdp_md *xdp_md, u32 offset, void *buf, u32 len)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 191,
        name: "bpf_copy_from_user_task",
        proto: "long bpf_copy_from_user_task(void *dst, u32 size, const void *user_ptr, struct task_struct *tsk, u64 flags)",
        may_sleep: true,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 192,
        name: "bpf_skb_set_tstamp",
        proto: "long bpf_skb_set_tstamp(struct sk_buff *skb, u64 tstamp, u32 tstamp_type)",
        may_sleep: false,
        pkt_access: true,
    },
    BpfHelperFull {
        id: 193,
        name: "bpf_ima_file_hash",
        proto: "long bpf_ima_file_hash(struct file *file, void *dst, u32 size)",
        may_sleep: true,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 194,
        name: "bpf_kptr_xchg",
        proto: "void *bpf_kptr_xchg(void *map_value, void *ptr)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 195,
        name: "bpf_map_lookup_percpu_elem",
        proto: "void *bpf_map_lookup_percpu_elem(struct bpf_map *map, const void *key, u32 cpu)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 196,
        name: "bpf_skc_to_mptcp_sock",
        proto: "struct mptcp_sock *bpf_skc_to_mptcp_sock(void *sk)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 197,
        name: "bpf_dynptr_from_mem",
        proto: "long bpf_dynptr_from_mem(void *data, u32 size, u64 flags, struct bpf_dynptr *ptr)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 198,
        name: "bpf_ringbuf_reserve_dynptr",
        proto: "long bpf_ringbuf_reserve_dynptr(void *ringbuf, u32 size, u64 flags, struct bpf_dynptr *ptr)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 199,
        name: "bpf_ringbuf_submit_dynptr",
        proto: "void bpf_ringbuf_submit_dynptr(struct bpf_dynptr *ptr, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 200,
        name: "bpf_ringbuf_discard_dynptr",
        proto: "void bpf_ringbuf_discard_dynptr(struct bpf_dynptr *ptr, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 201,
        name: "bpf_dynptr_read",
        proto: "long bpf_dynptr_read(void *dst, u32 len, const struct bpf_dynptr *src, u32 offset, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 202,
        name: "bpf_dynptr_write",
        proto: "long bpf_dynptr_write(const struct bpf_dynptr *dst, u32 offset, void *src, u32 len, u64 flags)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 203,
        name: "bpf_dynptr_data",
        proto: "void *bpf_dynptr_data(const struct bpf_dynptr *ptr, u32 offset, u32 len)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 204,
        name: "bpf_tcp_raw_gen_syncookie_ipv4",
        proto: "s64 bpf_tcp_raw_gen_syncookie_ipv4(struct iphdr *iph, struct tcphdr *th, u32 th_len)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 205,
        name: "bpf_tcp_raw_gen_syncookie_ipv6",
        proto: "s64 bpf_tcp_raw_gen_syncookie_ipv6(struct ipv6hdr *iph, struct tcphdr *th, u32 th_len)",
        may_sleep: false,
        pkt_access: false,
    },
    BpfHelperFull {
        id: 206,
        name: "bpf_tcp_raw_check_syncookie_ipv4",
        proto: "long bpf_tcp_raw_check_syncookie_ipv4(struct iphdr *iph, struct tcphdr *th)",
        may_sleep: false,
        pkt_access: false,
    },
];

/// Look up a helper by its numeric ID.
///
/// Returns `None` if `id` is 0 or greater than the last known helper ID.
#[must_use]
pub fn lookup_helper(id: u32) -> Option<&'static BpfHelperFull> {
    HELPERS.iter().find(|h| h.id == id)
}

/// Look up a helper by its name string (exact match).
#[must_use]
pub fn lookup_helper_by_name(name: &str) -> Option<&'static BpfHelperFull> {
    HELPERS.iter().find(|h| h.name == name)
}

/// Return all helpers that touch packet data.
pub fn pkt_access_helpers() -> impl Iterator<Item = &'static BpfHelperFull> {
    HELPERS.iter().filter(|h| h.pkt_access)
}

/// Return all helpers that may sleep.
pub fn sleepable_helpers() -> impl Iterator<Item = &'static BpfHelperFull> {
    HELPERS.iter().filter(|h| h.may_sleep)
}

// ===========================================================================
// BTF Section Parser —" full binary BTF decoding
// ===========================================================================
//
// Reference: include/uapi/linux/btf.h
//
// BTF wire layout:
//   struct btf_header {
//     u16 magic;       // 0xEB9F
//     u8  version;     // 1
//     u8  flags;
//     u32 hdr_len;
//     u32 type_off;
//     u32 type_len;
//     u32 str_off;
//     u32 str_len;
//   };
//
// Each type entry starts with a 12-byte `btf_type`:
//   u32 name_off;      // offset into string section
//   u32 info;          // kind[28:24], kflag[31], vlen[15:0]
//   u32 size_or_type;  // size (for concrete types) or type_id (for modifiers)
//
// Followed by kind-specific extra data.

/// A struct member inside a BTF Struct or Union type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfMember {
    /// Member name string.
    pub name: String,
    /// BTF type id of this member's type.
    pub type_id: u32,
    /// Bit offset of the member within the struct/union.
    ///
    /// When `kflag` is set in the parent type's info, the upper 24 bits carry
    /// a bitfield bit size and the lower 8 bits carry the bit offset within
    /// the bitfield storage unit.  For plain members `kflag=0` and this is
    /// the simple byte offset Ã— 8.
    pub bit_offset: u32,
}

/// Metadata for a variable recorded inside a BTF `DataSec` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfVarInfo {
    /// BTF type id of the variable (should be a `BtfTypeKind::Var`).
    pub type_id: u32,
    /// Byte offset of the variable within the data section.
    pub offset: u32,
    /// Size of the variable in bytes.
    pub size: u32,
}

/// The rich, data-carrying kind of a parsed BTF type.
///
/// Mirrors the `BTF_KIND_*` constants in `btf.h` but carries all decoded
/// per-kind payload inline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtfTypeKind {
    /// Type-id 0 —" represents `void`.
    Void,
    /// `BTF_KIND_INT` —" an integer type.
    Int {
        /// Width in bits (8, 16, 32, 64, —¦).
        bits: u32,
        /// Whether the integer is signed.
        signed: bool,
        /// Raw encoding byte from the BTF int encoding word.
        ///
        /// Bits: `[7:4]` = encoding (0=plain,1=signed,2=char,3=bool),
        /// `[3:0]` = offset (always 0 for non-bitfield).
        encoding: u8,
    },
    /// `BTF_KIND_PTR` —" a pointer to another type.
    Ptr { type_id: u32 },
    /// `BTF_KIND_ARRAY` —" a fixed-size array.
    Array {
        /// Element type id.
        type_id: u32,
        /// Type id of the array index (always `u32` in practice).
        index_type: u32,
        /// Number of elements.
        nelems: u32,
    },
    /// `BTF_KIND_STRUCT` —" a C struct.
    Struct {
        members: Vec<BtfMember>,
        /// Total size in bytes.
        size: u32,
    },
    /// `BTF_KIND_UNION` —" a C union.
    Union {
        members: Vec<BtfMember>,
        /// Total size in bytes.
        size: u32,
    },
    /// `BTF_KIND_ENUM` —" a 32-bit enumeration.
    Enum {
        /// `(name, value)` pairs.
        values: Vec<(String, i32)>,
        /// Size in bytes (always 4 for 32-bit enums).
        size: u32,
    },
    /// `BTF_KIND_FWD` —" a forward-declared type (struct/union tag only).
    Fwd,
    /// `BTF_KIND_TYPEDEF` —" a type alias.
    Typedef { type_id: u32 },
    /// `BTF_KIND_VOLATILE` —" `volatile` modifier.
    Volatile { type_id: u32 },
    /// `BTF_KIND_CONST` —" `const` modifier.
    Const { type_id: u32 },
    /// `BTF_KIND_RESTRICT` —" `restrict` modifier.
    Restrict { type_id: u32 },
    /// `BTF_KIND_FUNC` —" a function symbol (not a prototype).
    Func { type_id: u32 },
    /// `BTF_KIND_FUNC_PROTO` —" a function prototype.
    FuncProto {
        /// `(param_name, type_id)` for each parameter.  The return type is
        /// stored in `size_or_type` of the base `btf_type` header.
        params: Vec<(String, u32)>,
        /// Return type id.
        return_type: u32,
    },
    /// `BTF_KIND_VAR` —" a global variable.
    Var {
        type_id: u32,
        /// Linkage: 0 = static, 1 = global-allocated.
        linkage: u32,
    },
    /// `BTF_KIND_DATASEC` —" a named data section (`.bss`, `.data`, etc.).
    DataSec {
        vars: Vec<BtfVarInfo>,
        /// Total size of the section in bytes.
        size: u32,
    },
    /// `BTF_KIND_FLOAT` —" a floating-point type.
    Float { size: u32 },
    /// `BTF_KIND_DECL_TAG` —" an attribute tag attached to a declaration.
    DeclTag { type_id: u32, component_idx: i32 },
    /// `BTF_KIND_TYPE_TAG` —" an attribute tag attached to a type.
    TypeTag { type_id: u32 },
    /// `BTF_KIND_ENUM64` —" a 64-bit enumeration (Linux 6.0+).
    Enum64 {
        /// `(name, value)` pairs (value is 64-bit).
        values: Vec<(String, i64)>,
        /// Size in bytes (always 8 for 64-bit enums).
        size: u32,
    },
}

/// A fully-decoded BTF type entry.
///
/// The BTF type space is 1-indexed: `type_id` 0 is always `void` (represented
/// by index 0 inside `BtfSection::types`).  For any `type_id` `n` the entry
/// lives at `types[n as usize]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfType {
    /// Human-readable name, if the type has one.
    pub name: Option<String>,
    /// The decoded kind and its payload.
    pub kind: BtfTypeKind,
}

/// A fully-parsed BTF section.
///
/// Holds the decoded type list (index 0 = void, index n = `type_id` n) and the
/// raw string table bytes for cheap `&str` slices via [`BtfSection::read_string`].
#[derive(Debug, Clone)]
pub struct BtfSection {
    /// Decoded types.  `types[0]` is the synthetic void entry; `types[n]` is
    /// the type with `type_id` `n`.
    pub types: Vec<BtfType>,
    /// Raw bytes of the BTF string section (NUL-terminated C strings).
    pub strings: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Internal parsing helpers
// ---------------------------------------------------------------------------

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_i32_le(data: &[u8], off: usize) -> Option<i32> {
    read_u32_le(data, off).map(u32::cast_signed)
}

fn read_u64_le(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Read a NUL-terminated string from a byte slice at the given offset.
fn cstr_at(data: &[u8], off: usize) -> &str {
    if off >= data.len() {
        return "";
    }
    let slice = &data[off..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    core::str::from_utf8(&slice[..end]).unwrap_or("")
}

fn opt_name(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_owned())
    }
}

// ---------------------------------------------------------------------------
// BtfSection implementation
// ---------------------------------------------------------------------------

impl BtfSection {
    // -----------------------------------------------------------------------
    // Constructor / parser
    // -----------------------------------------------------------------------

    /// Parse a raw BTF blob (the bytes of a `.BTF` ELF section or a standalone
    /// file) into a fully-decoded [`BtfSection`].
    ///
    /// # Errors
    ///
    /// Returns a descriptive `String` error when:
    /// - the blob is too short to hold the BTF header,
    /// - the magic bytes (`0xEB 0x9F`) are wrong,
    /// - the header-length or section offsets are out of range,
    /// - any type entry is internally truncated.
    ///
    /// # Panics
    ///
    /// Panics only if an internal invariant is violated.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        // â"€â"€ 1. Validate magic â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        if data.len() < 2 {
            return Err("BTF blob too short (< 2 bytes)".into());
        }
        // BTF stores the magic as 0xEB9F in little-endian, so bytes are
        // [0x9F, 0xEB].  The kernel header defines it as 0xEB9F but reads it
        // as a u16 LE value.
        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != 0xEB9F {
            return Err(format!("bad BTF magic: {magic:#06x} (expected 0xEB9F)"));
        }

        // â"€â"€ 2. Parse the header (20 bytes minimum) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        if data.len() < 20 {
            return Err("BTF header truncated (< 20 bytes)".into());
        }
        // version = data[2], flags = data[3]
        // Header field at offset 20 requires at least 24 bytes total.
        if data.len() < 24 {
            return Err("BTF header truncated (< 24 bytes for str_len)".into());
        }
        let hdr_len = read_u32_le(data, 4).unwrap() as usize;
        let type_off = read_u32_le(data, 8).unwrap() as usize;
        let type_len = read_u32_le(data, 12).unwrap() as usize;
        let str_off = read_u32_le(data, 16).unwrap() as usize;
        let str_len = read_u32_le(data, 20).unwrap() as usize;

        // Absolute offsets within the blob.
        let types_start = hdr_len.checked_add(type_off).ok_or("type_off overflow")?;
        let types_end = types_start
            .checked_add(type_len)
            .ok_or("type_len overflow")?;
        let strs_start = hdr_len.checked_add(str_off).ok_or("str_off overflow")?;
        let strs_end = strs_start.checked_add(str_len).ok_or("str_len overflow")?;

        if types_end > data.len() {
            return Err(format!(
                "BTF type section [{types_start:#x}, {types_end:#x}) extends past blob ({:#x})",
                data.len()
            ));
        }
        if strs_end > data.len() {
            return Err(format!(
                "BTF string section [{strs_start:#x}, {strs_end:#x}) extends past blob ({:#x})",
                data.len()
            ));
        }

        // â"€â"€ 3. Extract raw sections â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let type_bytes = &data[types_start..types_end];
        let str_bytes = data[strs_start..strs_end].to_vec();

        // â"€â"€ 4. Walk the type section â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        // types[0] = synthetic void (type_id 0 is always void in BTF).
        let mut types: Vec<BtfType> = vec![BtfType {
            name: None,
            kind: BtfTypeKind::Void,
        }];

        let mut off = 0usize;
        while off + 12 <= type_bytes.len() {
            // 12-byte btf_type header.
            let name_off = read_u32_le(type_bytes, off).unwrap();
            let info = read_u32_le(type_bytes, off + 4).unwrap();
            let size_or_type = read_u32_le(type_bytes, off + 8).unwrap();

            let kind_raw = (info >> 24) & 0x1f;
            let kflag = (info >> 31) & 1 != 0;
            let vlen = (info & 0xffff) as usize;

            let name_str = cstr_at(&str_bytes, name_off as usize);
            let name = opt_name(name_str);

            // Offset of the kind-specific data that follows the 12-byte header.
            let extra_off = off + 12;

            let kind = match kind_raw {
                // â"€â"€ BTF_KIND_INT â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                1 => {
                    if extra_off + 4 > type_bytes.len() {
                        return Err(format!("BTF_KIND_INT at +{off:#x}: truncated int encoding"));
                    }
                    let enc_word = read_u32_le(type_bytes, extra_off).unwrap();
                    // encoding bits [25:24]: 0=none,1=signed,2=char,3=bool
                    let enc_kind = ((enc_word >> 24) & 0x0f) as u8;
                    let _bits = enc_word & 0xff; // bits [7:0] = nr_bits
                    // Actually BTF int encoding: bits[23:16]=offset, bits[7:0]=nr_bits
                    let nr_bits = enc_word & 0xff;
                    let offset = (enc_word >> 16) & 0xff;
                    let _ = offset; // we expose only the total size
                    // size_or_type holds the size in bytes for INT.
                    let byte_size = size_or_type;
                    let bit_size = if nr_bits > 0 { nr_bits } else { byte_size * 8 };
                    let signed = (enc_kind & 1) != 0;
                    BtfTypeKind::Int {
                        bits: bit_size,
                        signed,
                        encoding: enc_kind,
                    }
                }

                // â"€â"€ BTF_KIND_PTR â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                2 => BtfTypeKind::Ptr {
                    type_id: size_or_type,
                },

                // â"€â"€ BTF_KIND_ARRAY â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                3 => {
                    // struct btf_array { u32 type; u32 index_type; u32 nelems; }
                    if extra_off + 12 > type_bytes.len() {
                        return Err(format!(
                            "BTF_KIND_ARRAY at +{off:#x}: truncated array descriptor"
                        ));
                    }
                    let elem_type = read_u32_le(type_bytes, extra_off).unwrap();
                    let index_type = read_u32_le(type_bytes, extra_off + 4).unwrap();
                    let nelems = read_u32_le(type_bytes, extra_off + 8).unwrap();
                    BtfTypeKind::Array {
                        type_id: elem_type,
                        index_type,
                        nelems,
                    }
                }

                // â"€â"€ BTF_KIND_STRUCT â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                4 => {
                    let members =
                        Self::parse_members(type_bytes, extra_off, vlen, &str_bytes, kflag)?;
                    BtfTypeKind::Struct {
                        members,
                        size: size_or_type,
                    }
                }

                // â"€â"€ BTF_KIND_UNION â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                5 => {
                    let members =
                        Self::parse_members(type_bytes, extra_off, vlen, &str_bytes, kflag)?;
                    BtfTypeKind::Union {
                        members,
                        size: size_or_type,
                    }
                }

                // â"€â"€ BTF_KIND_ENUM â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                6 => {
                    // struct btf_enum { u32 name_off; s32 val; }  Ã—vlen
                    let mut values = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        let base = extra_off + i * 8;
                        if base + 8 > type_bytes.len() {
                            return Err(format!(
                                "BTF_KIND_ENUM at +{off:#x}: member {i} truncated"
                            ));
                        }
                        let e_name_off = read_u32_le(type_bytes, base).unwrap();
                        let e_val = read_i32_le(type_bytes, base + 4).unwrap();
                        let e_name = cstr_at(&str_bytes, e_name_off as usize).to_owned();
                        values.push((e_name, e_val));
                    }
                    BtfTypeKind::Enum {
                        values,
                        size: size_or_type,
                    }
                }

                // â"€â"€ BTF_KIND_FWD â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                7 => BtfTypeKind::Fwd,

                // â"€â"€ BTF_KIND_TYPEDEF â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                8 => BtfTypeKind::Typedef {
                    type_id: size_or_type,
                },

                // â"€â"€ BTF_KIND_VOLATILE â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                9 => BtfTypeKind::Volatile {
                    type_id: size_or_type,
                },

                // â"€â"€ BTF_KIND_CONST â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                10 => BtfTypeKind::Const {
                    type_id: size_or_type,
                },

                // â"€â"€ BTF_KIND_RESTRICT â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                11 => BtfTypeKind::Restrict {
                    type_id: size_or_type,
                },

                // â"€â"€ BTF_KIND_FUNC â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                12 => BtfTypeKind::Func {
                    type_id: size_or_type,
                },

                // â"€â"€ BTF_KIND_FUNC_PROTO â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                13 => {
                    // struct btf_param { u32 name_off; u32 type; }  Ã—vlen
                    let mut params = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        let base = extra_off + i * 8;
                        if base + 8 > type_bytes.len() {
                            return Err(format!(
                                "BTF_KIND_FUNC_PROTO at +{off:#x}: param {i} truncated"
                            ));
                        }
                        let p_name_off = read_u32_le(type_bytes, base).unwrap();
                        let p_type_id = read_u32_le(type_bytes, base + 4).unwrap();
                        let p_name = cstr_at(&str_bytes, p_name_off as usize).to_owned();
                        params.push((p_name, p_type_id));
                    }
                    BtfTypeKind::FuncProto {
                        params,
                        return_type: size_or_type,
                    }
                }

                // â"€â"€ BTF_KIND_VAR â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                14 => {
                    // struct btf_var { u32 linkage; }
                    if extra_off + 4 > type_bytes.len() {
                        return Err(format!("BTF_KIND_VAR at +{off:#x}: truncated var linkage"));
                    }
                    let linkage = read_u32_le(type_bytes, extra_off).unwrap();
                    BtfTypeKind::Var {
                        type_id: size_or_type,
                        linkage,
                    }
                }

                // â"€â"€ BTF_KIND_DATASEC â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                15 => {
                    // struct btf_var_secinfo { u32 type; u32 offset; u32 size; }  Ã—vlen
                    let mut vars = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        let base = extra_off + i * 12;
                        if base + 12 > type_bytes.len() {
                            return Err(format!(
                                "BTF_KIND_DATASEC at +{off:#x}: var {i} truncated"
                            ));
                        }
                        let v_type_id = read_u32_le(type_bytes, base).unwrap();
                        let v_offset = read_u32_le(type_bytes, base + 4).unwrap();
                        let v_size = read_u32_le(type_bytes, base + 8).unwrap();
                        vars.push(BtfVarInfo {
                            type_id: v_type_id,
                            offset: v_offset,
                            size: v_size,
                        });
                    }
                    BtfTypeKind::DataSec {
                        vars,
                        size: size_or_type,
                    }
                }

                // â"€â"€ BTF_KIND_FLOAT â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                16 => BtfTypeKind::Float { size: size_or_type },

                // â"€â"€ BTF_KIND_DECL_TAG â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                17 => {
                    // struct btf_decl_tag { s32 component_idx; }
                    if extra_off + 4 > type_bytes.len() {
                        return Err(format!(
                            "BTF_KIND_DECL_TAG at +{off:#x}: truncated component_idx"
                        ));
                    }
                    let cidx = read_i32_le(type_bytes, extra_off).unwrap();
                    BtfTypeKind::DeclTag {
                        type_id: size_or_type,
                        component_idx: cidx,
                    }
                }

                // â"€â"€ BTF_KIND_TYPE_TAG â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                18 => BtfTypeKind::TypeTag {
                    type_id: size_or_type,
                },

                // â"€â"€ BTF_KIND_ENUM64 â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                19 => {
                    // struct btf_enum64 { u32 name_off; u32 val_lo32; u32 val_hi32; }  Ã—vlen
                    let mut values = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        let base = extra_off + i * 12;
                        if base + 12 > type_bytes.len() {
                            return Err(format!(
                                "BTF_KIND_ENUM64 at +{off:#x}: value {i} truncated"
                            ));
                        }
                        let e_name_off = read_u32_le(type_bytes, base).unwrap();
                        let val_lo = u64::from(read_u32_le(type_bytes, base + 4).unwrap());
                        let val_hi = u64::from(read_u32_le(type_bytes, base + 8).unwrap());
                        let e_val = ((val_hi << 32) | val_lo).cast_signed();
                        let e_name = cstr_at(&str_bytes, e_name_off as usize).to_owned();
                        values.push((e_name, e_val));
                    }
                    BtfTypeKind::Enum64 {
                        values,
                        size: size_or_type,
                    }
                }

                // â"€â"€ Unknown kinds —" skip gracefully â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                _ => BtfTypeKind::Void,
            };

            // Advance past the extra kind-specific bytes.
            let extra_size = BtfParser::kind_extra_bytes(kind_raw, vlen);
            off += 12 + extra_size;

            types.push(BtfType { name, kind });
        }

        Ok(Self {
            types,
            strings: str_bytes,
        })
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Parse `vlen` `btf_member` structs from `type_bytes` starting at `base`.
    fn parse_members(
        type_bytes: &[u8],
        base: usize,
        vlen: usize,
        str_bytes: &[u8],
        _kflag: bool,
    ) -> Result<Vec<BtfMember>, String> {
        let mut members = Vec::with_capacity(vlen);
        for i in 0..vlen {
            let off = base + i * 12;
            if off + 12 > type_bytes.len() {
                return Err(format!("struct/union member {i} at +{off:#x}: truncated"));
            }
            let m_name_off = read_u32_le(type_bytes, off).unwrap();
            let m_type_id = read_u32_le(type_bytes, off + 4).unwrap();
            let m_bit_off = read_u32_le(type_bytes, off + 8).unwrap();
            let m_name = cstr_at(str_bytes, m_name_off as usize).to_owned();
            members.push(BtfMember {
                name: m_name,
                type_id: m_type_id,
                bit_offset: m_bit_off,
            });
        }
        Ok(members)
    }

    // -----------------------------------------------------------------------
    // Public accessors
    // -----------------------------------------------------------------------

    /// Return a reference to the type with the given `type_id`.
    ///
    /// `Type_id` 0 is always present (void).  Returns `None` for ids beyond the
    /// end of the type table.
    #[must_use]
    pub fn get_type(&self, id: u32) -> Option<&BtfType> {
        self.types.get(id as usize)
    }

    /// Resolve a `type_id` to its human-readable name, following modifier chains
    /// (Typedef, Const, Volatile, Restrict) one level deep.
    ///
    /// Returns `None` when the type has no name and no named ancestor.
    #[must_use]
    pub fn resolve_name(&self, id: u32) -> Option<&str> {
        let t = self.get_type(id)?;
        if let Some(ref n) = t.name {
            return Some(n.as_str());
        }
        // Follow single-level modifier chain.
        let inner_id = match &t.kind {
            BtfTypeKind::Typedef { type_id }
            | BtfTypeKind::Const { type_id }
            | BtfTypeKind::Volatile { type_id }
            | BtfTypeKind::Restrict { type_id } => *type_id,
            _ => return None,
        };
        let inner = self.get_type(inner_id)?;
        inner.name.as_deref()
    }

    /// Return the byte offset of a named field within a struct type.
    ///
    /// Traverses the member list of the struct identified by `struct_id` and
    /// returns the byte offset (`bit_offset / 8`) of the first member whose
    /// name equals `field`.  Returns `None` when the type is not a struct, has
    /// no matching field, or the field is a bitfield (`bit_offset` not divisible
    /// by 8).
    #[must_use]
    pub fn get_struct_field_offset(&self, struct_id: u32, field: &str) -> Option<u32> {
        let t = self.get_type(struct_id)?;
        let members = match &t.kind {
            BtfTypeKind::Struct { members, .. } | BtfTypeKind::Union { members, .. } => members,
            _ => return None,
        };
        for m in members {
            if m.name == field {
                if m.bit_offset % 8 != 0 {
                    // Bitfield —" byte offset is not exact, skip.
                    return None;
                }
                return Some(m.bit_offset / 8);
            }
        }
        None
    }

    /// Compute the size in bytes of the type identified by `type_id`.
    ///
    /// Follows typedef/modifier chains.  Returns `None` when the size cannot be
    /// determined (void, function prototypes, forward declarations, or cycles).
    #[must_use]
    pub fn sizeof(&self, type_id: u32) -> Option<u32> {
        self.sizeof_depth(type_id, 0)
    }

    /// Internal recursive sizeof implementation with cycle-detection depth guard.
    fn sizeof_depth(&self, type_id: u32, depth: u32) -> Option<u32> {
        if depth > 64 {
            return None; // guard against pathological cycles
        }
        let t = self.get_type(type_id)?;
        match &t.kind {
            // Void, forward declarations and function prototypes have no size.
            BtfTypeKind::Void | BtfTypeKind::Fwd | BtfTypeKind::FuncProto { .. } => None,
            BtfTypeKind::Int { bits, .. } => Some((*bits).div_ceil(8)),
            BtfTypeKind::Ptr { .. } => Some(8), // all pointers are 64-bit in eBPF
            // Floats, aggregates, enums and data sections all record their own
            // size: Float, Struct, Union, Enum, Enum64, DataSec.
            BtfTypeKind::Float { size }
            | BtfTypeKind::Struct { size, .. }
            | BtfTypeKind::Union { size, .. }
            | BtfTypeKind::Enum { size, .. }
            | BtfTypeKind::Enum64 { size, .. }
            | BtfTypeKind::DataSec { size, .. } => Some(*size),
            BtfTypeKind::Array {
                type_id: elem,
                nelems,
                ..
            } => {
                let elem_sz = self.sizeof_depth(*elem, depth + 1)?;
                Some(elem_sz * nelems)
            }
            BtfTypeKind::Typedef { type_id }
            | BtfTypeKind::Const { type_id }
            | BtfTypeKind::Volatile { type_id }
            | BtfTypeKind::Restrict { type_id }
            | BtfTypeKind::Func { type_id }
            | BtfTypeKind::TypeTag { type_id }
            | BtfTypeKind::DeclTag { type_id, .. }
            | BtfTypeKind::Var { type_id, .. } => self.sizeof_depth(*type_id, depth + 1),
        }
    }

    /// Produce a C declaration string for `type_id` with the given variable name.
    ///
    /// For example, for a `type_id` that resolves to `struct sk_buff *` and
    /// `var_name = "skb"` this returns `"struct sk_buff *skb"`.
    ///
    /// The output is intended for humans (debugging / display) and may not be
    /// a 100% valid C token sequence in all edge cases.
    #[must_use]
    pub fn to_c_declaration(&self, type_id: u32, var_name: &str) -> String {
        self.c_decl_inner(type_id, var_name, 0)
    }

    fn c_decl_inner(&self, type_id: u32, var_name: &str, depth: u32) -> String {
        if depth > 32 {
            return format!("<cycle> {var_name}");
        }
        let Some(t) = self.get_type(type_id) else {
            return format!("<unknown_type_id={type_id}> {var_name}");
        };
        match &t.kind {
            BtfTypeKind::Void => format!("void {var_name}"),
            BtfTypeKind::Int { bits, signed, .. } => {
                let sign_prefix = if *signed { "" } else { "u" };
                let name = if let Some(ref n) = t.name {
                    n.as_str()
                } else {
                    match bits {
                        8 => {
                            if *signed {
                                "int8_t"
                            } else {
                                "uint8_t"
                            }
                        }
                        16 => {
                            if *signed {
                                "int16_t"
                            } else {
                                "uint16_t"
                            }
                        }
                        32 => {
                            if *signed {
                                "int32_t"
                            } else {
                                "uint32_t"
                            }
                        }
                        64 => {
                            if *signed {
                                "int64_t"
                            } else {
                                "uint64_t"
                            }
                        }
                        _ => "int",
                    }
                };
                let _ = sign_prefix;
                format!("{name} {var_name}")
            }
            BtfTypeKind::Float { size } => {
                let name = match size {
                    4 => "float",
                    8 => "double",
                    _ => "long double",
                };
                format!("{name} {var_name}")
            }
            BtfTypeKind::Ptr { type_id } => {
                let inner_decl = self.c_decl_inner(*type_id, "", depth + 1);
                format!("{inner_decl} *{var_name}").trim_start().to_owned()
            }
            BtfTypeKind::Array {
                type_id, nelems, ..
            } => {
                let inner_decl = self.c_decl_inner(*type_id, "", depth + 1);
                format!("{inner_decl} {var_name}[{nelems}]")
            }
            BtfTypeKind::Struct { .. } => {
                let name = t.name.as_deref().unwrap_or("<anon>");
                format!("struct {name} {var_name}")
            }
            BtfTypeKind::Union { .. } => {
                let name = t.name.as_deref().unwrap_or("<anon>");
                format!("union {name} {var_name}")
            }
            BtfTypeKind::Enum { .. } => {
                let name = t.name.as_deref().unwrap_or("<anon>");
                format!("enum {name} {var_name}")
            }
            BtfTypeKind::Enum64 { .. } => {
                let name = t.name.as_deref().unwrap_or("<anon>");
                format!("enum64 {name} {var_name}")
            }
            BtfTypeKind::Typedef { type_id } => {
                if let Some(ref alias) = t.name {
                    format!("{alias} {var_name}")
                } else {
                    self.c_decl_inner(*type_id, var_name, depth + 1)
                }
            }
            BtfTypeKind::Const { type_id } => {
                let inner = self.c_decl_inner(*type_id, var_name, depth + 1);
                format!("const {inner}")
            }
            BtfTypeKind::Volatile { type_id } => {
                let inner = self.c_decl_inner(*type_id, var_name, depth + 1);
                format!("volatile {inner}")
            }
            BtfTypeKind::Restrict { type_id } => {
                let inner = self.c_decl_inner(*type_id, var_name, depth + 1);
                format!("restrict {inner}")
            }
            BtfTypeKind::Func { type_id } => {
                let name = t.name.as_deref().unwrap_or(var_name);
                if let Some(inner) = self.get_type(*type_id)
                    && let BtfTypeKind::FuncProto {
                        params,
                        return_type,
                    } = &inner.kind
                {
                    let ret = self.c_decl_inner(*return_type, "", depth + 1);
                    let args = params
                        .iter()
                        .map(|(pn, pt)| self.c_decl_inner(*pt, pn, depth + 1))
                        .collect::<Vec<_>>()
                        .join(", ");
                    return format!("{ret} {name}({args})");
                }
                format!("<func> {name}")
            }
            BtfTypeKind::FuncProto {
                params,
                return_type,
            } => {
                let ret = self.c_decl_inner(*return_type, "", depth + 1);
                let args = params
                    .iter()
                    .map(|(pn, pt)| self.c_decl_inner(*pt, pn, depth + 1))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{ret} (*{var_name})({args})")
            }
            BtfTypeKind::Var { type_id, .. } => self.c_decl_inner(*type_id, var_name, depth + 1),
            BtfTypeKind::DataSec { size, .. } => {
                let name = t.name.as_deref().unwrap_or("<anon>");
                format!("/* datasec {name} size={size} */ {var_name}")
            }
            BtfTypeKind::Fwd => {
                let name = t.name.as_deref().unwrap_or("<anon>");
                format!("struct {name} /* fwd */ {var_name}")
            }
            BtfTypeKind::DeclTag { .. } | BtfTypeKind::TypeTag { .. } => {
                let tag = t.name.as_deref().unwrap_or("");
                format!("__attribute__(({tag})) {var_name}")
            }
        }
    }

    /// Read a NUL-terminated string from the BTF string section at `off`.
    ///
    /// Returns an empty string when `off` is out of range.
    #[must_use]
    pub fn read_string(&self, off: u32) -> &str {
        cstr_at(&self.strings, off as usize)
    }

    /// Return the total number of types (including the synthetic void at id 0).
    #[must_use]
    pub const fn type_count(&self) -> usize {
        self.types.len()
    }

    /// Return an iterator over all types paired with their `type_id`.
    pub fn iter_types(&self) -> impl Iterator<Item = (u32, &BtfType)> {
        self.types.iter().enumerate().map(|(i, t)| (numeric::usize_to_u32(i), t))
    }

    /// Collect all struct `type_ids` whose name equals `name`.
    #[must_use]
    pub fn find_struct_by_name(&self, name: &str) -> Vec<u32> {
        self.types
            .iter()
            .enumerate()
            .filter_map(|(i, t)| {
                if let BtfTypeKind::Struct { .. } = &t.kind
                    && t.name.as_deref() == Some(name)
                {
                    return Some(numeric::usize_to_u32(i));
                }
                None
            })
            .collect()
    }

    /// Walk the modifier chain (Const, Volatile, Restrict, Typedef) and return
    /// the first non-modifier `type_id`.
    #[must_use]
    pub fn skip_modifiers(&self, mut type_id: u32) -> u32 {
        for _ in 0..64 {
            let Some(t) = self.get_type(type_id) else {
                break;
            };
            match &t.kind {
                BtfTypeKind::Const { type_id: inner }
                | BtfTypeKind::Volatile { type_id: inner }
                | BtfTypeKind::Restrict { type_id: inner }
                | BtfTypeKind::Typedef { type_id: inner } => {
                    type_id = *inner;
                }
                _ => break,
            }
        }
        type_id
    }
}

// ===========================================================================
// CO-RE (Compile-Once, Run-Everywhere) Relocation Processing
// ===========================================================================
//
// BPF CO-RE allows programs compiled against one kernel version to be patched
// at load time to work against a different (running) kernel using BTF type
// information from both the BPF object (local) and the target kernel (target).
//
// Reference:
//   https://nakryiko.com/posts/bpf-core-reference-guide/
//   include/uapi/linux/bpf.h —" enum bpf_core_relo_kind

/// The kind of a single CO-RE relocation.
///
/// Mirrors `enum bpf_core_relo_kind` from `include/uapi/linux/bpf.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CoreRelocKind {
    /// Patch instruction immediate with the byte offset of a struct field.
    FieldByteOffset = 0,
    /// Patch instruction immediate with the byte size of a struct field.
    FieldByteSize = 1,
    /// Patch instruction immediate: 1 if field exists in target, 0 otherwise.
    FieldExists = 2,
    /// Patch instruction immediate: 1 if field is signed, 0 otherwise.
    FieldSigned = 3,
    /// Patch instruction immediate with the left-shift amount needed to
    /// position a bitfield value in a u64.
    FieldLShiftU64 = 4,
    /// Patch instruction immediate with the right-shift amount needed to
    /// extract a bitfield value from a u64.
    FieldRShiftU64 = 5,
    /// Patch instruction immediate with the local BTF type id.
    TypeIdLocal = 6,
    /// Patch instruction immediate with the target BTF type id.
    TypeIdTarget = 7,
    /// Patch instruction immediate: 1 if the type exists in target, 0 otherwise.
    TypeExists = 8,
    /// Patch instruction immediate with `sizeof(type)` in the target kernel.
    TypeSize = 9,
    /// Patch instruction immediate: 1 if the enum value exists in target.
    EnumvalExists = 10,
    /// Patch instruction immediate with the enum value in the target kernel.
    EnumvalValue = 11,
}

impl CoreRelocKind {
    /// Decode from the raw `u32` stored in the BTF ext section.
    #[must_use]
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::FieldByteOffset),
            1 => Some(Self::FieldByteSize),
            2 => Some(Self::FieldExists),
            3 => Some(Self::FieldSigned),
            4 => Some(Self::FieldLShiftU64),
            5 => Some(Self::FieldRShiftU64),
            6 => Some(Self::TypeIdLocal),
            7 => Some(Self::TypeIdTarget),
            8 => Some(Self::TypeExists),
            9 => Some(Self::TypeSize),
            10 => Some(Self::EnumvalExists),
            11 => Some(Self::EnumvalValue),
            _ => None,
        }
    }

    /// Return a human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::FieldByteOffset => "field_byte_offset",
            Self::FieldByteSize => "field_byte_size",
            Self::FieldExists => "field_exists",
            Self::FieldSigned => "field_signed",
            Self::FieldLShiftU64 => "field_lshift_u64",
            Self::FieldRShiftU64 => "field_rshift_u64",
            Self::TypeIdLocal => "type_id_local",
            Self::TypeIdTarget => "type_id_target",
            Self::TypeExists => "type_exists",
            Self::TypeSize => "type_size",
            Self::EnumvalExists => "enumval_exists",
            Self::EnumvalValue => "enumval_value",
        }
    }
}

/// A single CO-RE relocation entry decoded from `.BTF.ext`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreRelocation {
    /// Byte offset of the instruction to patch within the program section.
    ///
    /// This is a byte offset (not an instruction index); divide by 8 for the
    /// instruction index.
    pub insn_off: u32,
    /// BTF `type_id` of the root type that the access string is relative to.
    pub type_id: u32,
    /// Access string offset in the BTF string section.
    ///
    /// The actual access string (e.g. `"0:1:3"`) can be retrieved via
    /// `btf.read_string(access_str_off)`.  Call sites normally resolve this
    /// eagerly and store it in [`access_str`].
    pub access_str: String,
    /// The relocation kind.
    pub kind: CoreRelocKind,
}

/// Parse an access string of the form `"0:1:2"` and navigate the BTF type
/// graph rooted at `root_type_id`.
///
/// Returns `(final_type_id, byte_offset)` where:
/// - `final_type_id` is the BTF type of the leaf field,
/// - `byte_offset` is the total byte offset from the start of the root type.
///
/// The first component (`"0"`) always selects the root type itself (index 0 =
/// root, remaining indices select struct members by their position).
///
/// Returns `None` when:
/// - `access` is empty or cannot be parsed,
/// - any intermediate type is not a struct/union,
/// - a member index is out of range.
#[must_use]
pub fn parse_access_string(
    access: &str,
    btf: &BtfSection,
    root_type_id: u32,
) -> Option<(u32, u32)> {
    let parts: Vec<u32> = access.split(':').filter_map(|s| s.parse().ok()).collect();

    if parts.is_empty() {
        return None;
    }

    // The first component selects the root object; subsequent ones navigate
    // into struct/union members.
    let mut current_type_id = root_type_id;
    let mut byte_offset: u32 = 0;

    // Skip the first component (it is always 0 for the root type itself).
    for &idx in &parts[1..] {
        // Follow modifier chain before accessing members.
        let bare_id = btf.skip_modifiers(current_type_id);
        let t = btf.get_type(bare_id)?;

        match &t.kind {
            BtfTypeKind::Struct { members, .. } | BtfTypeKind::Union { members, .. } => {
                let m = members.get(idx as usize)?;
                // bit_offset / 8 gives the byte offset for non-bitfield members.
                byte_offset += m.bit_offset / 8;
                current_type_id = m.type_id;
            }
            BtfTypeKind::Array {
                type_id: elem_type,
                nelems,
                ..
            } => {
                if idx >= *nelems {
                    return None;
                }
                let elem_sz = btf.sizeof(*elem_type)?;
                byte_offset += elem_sz * idx;
                current_type_id = *elem_type;
            }
            _ => return None,
        }
    }

    Some((current_type_id, byte_offset))
}

/// Apply a list of CO-RE relocations to a mutable instruction slice.
///
/// For each relocation:
/// 1. The target instruction at `reloc.insn_off / 8` is located.
/// 2. Its 32-bit immediate field is patched according to the relocation kind.
///
/// Returns a `Vec<u32>` containing the instruction indices that were
/// successfully patched (in the same order as `relocs`).  Relocations that
/// cannot be resolved are silently skipped.
///
/// # Arguments
///
/// * `prog_insns`   —" the mutable instruction buffer.
/// * `relocs`       —" CO-RE relocations to apply.
/// * `local_btf`    —" BTF from the BPF object being loaded.
/// * `target_btf`   —" BTF from the running kernel (`None` = use local only).
pub fn apply_core_relocations(
    prog_insns: &mut [BpfInstruction],
    relocs: &[CoreRelocation],
    local_btf: &BtfSection,
    target_btf: Option<&BtfSection>,
) -> Vec<u32> {
    let mut patched = Vec::new();

    for reloc in relocs {
        // Instruction index (each instruction = 8 bytes).
        let insn_idx = (reloc.insn_off / 8) as usize;
        let Some(instr) = prog_insns.get_mut(insn_idx) else {
            continue;
        };

        // Choose the BTF to use for target-side lookups.
        let effective_btf = target_btf.unwrap_or(local_btf);

        let new_imm: Option<i32> = match reloc.kind {
            // â"€â"€ Field relocations â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            CoreRelocKind::FieldByteOffset => {
                parse_access_string(&reloc.access_str, effective_btf, reloc.type_id)
                    .map(|(_, off)| off.cast_signed())
            }

            CoreRelocKind::FieldByteSize => {
                parse_access_string(&reloc.access_str, effective_btf, reloc.type_id)
                    .and_then(|(ftype_id, _)| effective_btf.sizeof(ftype_id))
                    .map(u32::cast_signed)
            }

            CoreRelocKind::FieldExists => {
                // 1 if the field path resolves in the target BTF, 0 otherwise.
                let exists =
                    parse_access_string(&reloc.access_str, effective_btf, reloc.type_id).is_some();
                Some(i32::from(exists))
            }

            CoreRelocKind::FieldSigned => {
                // 1 if the leaf field type is a signed integer.
                parse_access_string(&reloc.access_str, effective_btf, reloc.type_id)
                    .and_then(|(ftype_id, _)| {
                        let bare = effective_btf.skip_modifiers(ftype_id);
                        effective_btf.get_type(bare)
                    })
                    .map(|t| match &t.kind {
                        BtfTypeKind::Int { signed, .. } => i32::from(*signed),
                        _ => 0,
                    })
            }

            CoreRelocKind::FieldLShiftU64 => {
                // For a non-bitfield, lshift = 0.  We expose 0 for all fields
                // here; a full implementation would decode bitfield bit sizes.
                Some(0)
            }

            CoreRelocKind::FieldRShiftU64 => {
                // For a non-bitfield: rshift = 64 - byte_size*8.
                parse_access_string(&reloc.access_str, effective_btf, reloc.type_id)
                    .and_then(|(ftype_id, _)| effective_btf.sizeof(ftype_id))
                    .map(|sz| (64u32.saturating_sub(sz * 8)).cast_signed())
            }

            // â"€â"€ Type relocations â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            CoreRelocKind::TypeIdLocal => Some(reloc.type_id.cast_signed()),

            CoreRelocKind::TypeIdTarget => {
                // In a real loader this looks up the matching type in the kernel
                // BTF by structural equivalence.  Here we use the local type_id
                // as a best-effort stand-in.
                Some(reloc.type_id.cast_signed())
            }

            CoreRelocKind::TypeExists => {
                let exists = effective_btf.get_type(reloc.type_id).is_some();
                Some(i32::from(exists))
            }

            CoreRelocKind::TypeSize => effective_btf.sizeof(reloc.type_id).map(u32::cast_signed),

            // â"€â"€ Enum relocations â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            CoreRelocKind::EnumvalExists => {
                // Check whether the enum value named in access_str exists.
                let exists =
                    effective_btf
                        .get_type(reloc.type_id)
                        .is_some_and(|t| match &t.kind {
                            BtfTypeKind::Enum { values, .. } => {
                                values.iter().any(|(n, _)| n == &reloc.access_str)
                            }
                            BtfTypeKind::Enum64 { values, .. } => {
                                values.iter().any(|(n, _)| n == &reloc.access_str)
                            }
                            _ => false,
                        });
                Some(i32::from(exists))
            }

            CoreRelocKind::EnumvalValue => {
                effective_btf
                    .get_type(reloc.type_id)
                    .and_then(|t| match &t.kind {
                        BtfTypeKind::Enum { values, .. } => values
                            .iter()
                            .find(|(n, _)| n == &reloc.access_str)
                            .map(|(_, v)| *v),
                        BtfTypeKind::Enum64 { values, .. } => values
                            .iter()
                            .find(|(n, _)| n == &reloc.access_str)
                            .map(|(_, v)| numeric::trunc_i64_i32(*v)),
                        _ => None,
                    })
            }
        };

        if let Some(imm) = new_imm {
            // Patch the immediate in the raw bytes and in the decoded struct.
            let imm_bytes = imm.to_le_bytes();
            if instr.raw.len() >= 8 {
                instr.raw[4] = imm_bytes[0];
                instr.raw[5] = imm_bytes[1];
                instr.raw[6] = imm_bytes[2];
                instr.raw[7] = imm_bytes[3];
            }
            instr.imm = imm;
            patched.push(numeric::usize_to_u32(insn_idx));
        }
    }

    patched
}

// ===========================================================================
// BPF Security Analysis
// ===========================================================================
//
// Static security analysis of eBPF programs.  All checks are purely syntactic
// (no symbolic execution).  The findings are advisory and should be combined
// with verifier output for a complete picture.

/// Severity level for a security finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational —" not a bug on its own.
    Info,
    /// Low severity.
    Low,
    /// Medium severity —" warrants review.
    Medium,
    /// High severity —" likely exploitable.
    High,
    /// Critical severity —" direct exploit primitive.
    Critical,
}

impl Severity {
    /// Return the display name of this severity level.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

/// A single security finding produced by [`BpfSecurityAnalysis`].
#[derive(Debug, Clone)]
pub struct SecurityFinding {
    /// Severity of this finding.
    pub severity: Severity,
    /// The instruction index (0-based) where the finding was observed.
    pub insn_offset: u32,
    /// Human-readable description of the issue.
    pub description: String,
    /// Optional CVE or CVE-like identifier string.
    pub cve_like: Option<String>,
}

impl SecurityFinding {
    fn new(severity: Severity, insn_offset: u32, desc: impl Into<String>) -> Self {
        Self {
            severity,
            insn_offset,
            description: desc.into(),
            cve_like: None,
        }
    }

    fn with_cve(mut self, cve: impl Into<String>) -> Self {
        self.cve_like = Some(cve.into());
        self
    }
}

/// Static security analyser for decoded eBPF instruction streams.
pub struct BpfSecurityAnalysis;

impl BpfSecurityAnalysis {
    /// Run all security checks on a decoded instruction stream and return all
    /// findings in order of instruction offset.
    ///
    /// # Arguments
    ///
    /// * `prog`      —" slice of decoded `BpfInstruction`s.
    /// * `prog_type` —" the BPF program type (used for context-sensitive checks).
    #[must_use]
    pub fn analyze(prog: &[BpfInstruction], prog_type: BpfProgType) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        // Per-instruction checks.
        findings.extend(Self::check_dangerous_helpers(prog));
        findings.extend(Self::check_map_value_oob(prog));
        findings.extend(Self::check_pointer_arithmetic(prog));
        findings.extend(Self::check_stack_oob(prog));
        findings.extend(Self::check_unreachable_exit(prog));

        // Whole-program checks.
        if let Some(f) = Self::check_unbounded_loop(prog) {
            findings.push(f);
        }
        if let Some(f) = Self::check_no_exit(prog) {
            findings.push(f);
        }

        // Program-type—"specific checks.
        findings.extend(Self::check_prog_type_constraints(prog, prog_type));

        // Sort by instruction offset, then by severity (highest first).
        findings.sort_by(|a, b| {
            a.insn_offset
                .cmp(&b.insn_offset)
                .then(b.severity.cmp(&a.severity))
        });

        findings
    }

    // -----------------------------------------------------------------------
    // Individual check routines
    // -----------------------------------------------------------------------

    /// Check for backward branches that may cause unbounded loops.
    ///
    /// Before Linux 5.3 the verifier rejected any backward branch.  Since 5.3
    /// bounded loops are permitted, but unbounded loops (backwards branch
    /// without an obvious loop-count register) are still rejected.  We flag
    /// any backward branch as a medium-severity finding.
    #[must_use]
    pub fn check_unbounded_loop(prog: &[BpfInstruction]) -> Option<SecurityFinding> {
        for (idx, instr) in prog.iter().enumerate() {
            let cls = instr.opcode & 0x07;
            let code = instr.opcode & 0xf0;
            // JMP class, not CALL (0x80) or EXIT (0x90), and negative offset.
            if cls == 0x05 && code != 0x80 && code != 0x90 && instr.offset < 0 {
                return Some(SecurityFinding::new(
                    Severity::Medium,
                    numeric::usize_to_u32(idx),
                    format!(
                        "backward branch at insn {idx} (offset {:+}): \
                             possible unbounded loop —  rejected by verifier on kernels < 5.3",
                        instr.offset
                    ),
                ));
            }
        }
        None
    }

    /// Detect potential map-value out-of-bounds access patterns.
    ///
    /// Looks for sequences where `r0` (the return value of a map lookup) is
    /// used as a base register in an LDX/STX instruction without an intervening
    /// null-check (`jeq r0, 0` or `jne r0, 0`).  This pattern is the root
    /// cause of several eBPF OOB vulnerabilities.
    #[must_use]
    pub fn check_map_value_oob(prog: &[BpfInstruction]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        // Track whether r0 has been null-checked since the last map lookup.
        let mut r0_checked = true;
        let mut last_lookup = 0u32;

        for (idx, instr) in prog.iter().enumerate() {
            let cls = instr.opcode & 0x07;
            let code = instr.opcode & 0xf0;

            // BPF_CALL to helper 1 (bpf_map_lookup_elem) —" result in r0.
            if cls == 0x05 && code == 0x80 && instr.imm == 1 {
                r0_checked = false;
                last_lookup = numeric::usize_to_u32(idx);
                continue;
            }

            // jeq/jne with dst_reg=r0 or src_reg=r0 against 0 —" null check.
            if cls == 0x05
                && (code == 0x10 || code == 0x50)
                && (instr.dst_reg == 0 || instr.src_reg == 0)
            {
                r0_checked = true;
                continue;
            }

            // LDX/STX using r0 as base register before null-check.
            if !r0_checked && (cls == 0x01 || cls == 0x03) && instr.src_reg == 0 {
                findings.push(
                    SecurityFinding::new(
                        Severity::High,
                        numeric::usize_to_u32(idx),
                        format!(
                            "insn {idx}: map value pointer (r0 from lookup at insn {last_lookup}) \
                             used as memory operand without prior null-check —  \
                             CVE-class: eBPF map value OOB dereference"
                        ),
                    )
                    .with_cve("CVE-class:BPF-MAP-OOB"),
                );
            }

            // Also flag STX with r0 as dst (store through unverified pointer).
            if !r0_checked && cls == 0x03 && instr.dst_reg == 0 {
                findings.push(
                    SecurityFinding::new(
                        Severity::High,
                        numeric::usize_to_u32(idx),
                        format!(
                            "insn {idx}: store through r0 (map value from insn {last_lookup}) \
                             without null-check"
                        ),
                    )
                    .with_cve("CVE-class:BPF-MAP-OOB"),
                );
            }
        }

        findings
    }

    /// Detect suspicious pointer arithmetic patterns.
    ///
    /// In early kernels (< 4.7) certain ALU operations on `PTR_TO_MAP_VALUE`
    /// registers bypassed the verifier.  We flag any large positive or negative
    /// immediate add applied to `r0` immediately after a map lookup, which is
    /// the common exploit primitive pattern.
    #[must_use]
    pub fn check_pointer_arithmetic(prog: &[BpfInstruction]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut r0_is_ptr = false;

        for (idx, instr) in prog.iter().enumerate() {
            let cls = instr.opcode & 0x07;
            let code = instr.opcode & 0xf0;

            // Map lookup sets r0 = map_value_ptr.
            if cls == 0x05 && code == 0x80 && instr.imm == 1 {
                r0_is_ptr = true;
                continue;
            }

            // Null-check clears pointer status.
            if cls == 0x05 && (code == 0x10 || code == 0x50) && instr.dst_reg == 0 {
                r0_is_ptr = false;
                continue;
            }

            // ALU operation on r0 while it might still be a pointer.
            if r0_is_ptr && (cls == 0x07 || cls == 0x04) && instr.dst_reg == 0 {
                // ADD with large immediate —" classic verifier bypass technique.
                if code == 0x00 {
                    let magnitude = instr.imm.unsigned_abs();
                    if magnitude > 0x1000 {
                        findings.push(
                            SecurityFinding::new(
                                Severity::High,
                                numeric::usize_to_u32(idx),
                                format!(
                                    "insn {idx}: large immediate arithmetic (+{imm:#x}) on r0 \
                                     (possible map value pointer) —  verifier bypass pattern",
                                    imm = instr.imm
                                ),
                            )
                            .with_cve("CVE-class:BPF-PTR-ARITH"),
                        );
                    }
                }
                // Any ALU op other than MOV on what may be a pointer is suspicious.
                if code != 0xb0
                /* MOV */
                {
                    findings.push(SecurityFinding::new(
                        Severity::Medium,
                        numeric::usize_to_u32(idx),
                        format!(
                            "insn {idx}: ALU op {code:#x} applied to r0 that may be a \
                                 map value pointer without prior null-check"
                        ),
                    ));
                }
            }

            // Any instruction clears r0_is_ptr if it writes r0 with a non-pointer.
            let writes_r0 = match cls {
                // ALU (0x07 / 0x04) and LDX (0x01) all write their dst_reg.
                0x07 | 0x04 | 0x01 => instr.dst_reg == 0,
                0x05 if code == 0x80 => true,      // CALL writes r0
                _ => false,
            };
            if writes_r0 && !(cls == 0x05 && code == 0x80 && instr.imm == 1) {
                r0_is_ptr = false;
            }
        }

        findings
    }

    /// Detect calls to security-sensitive helpers.
    fn check_dangerous_helpers(prog: &[BpfInstruction]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        for (idx, instr) in prog.iter().enumerate() {
            let cls = instr.opcode & 0x07;
            let code = instr.opcode & 0xf0;
            if cls != 0x05 || code != 0x80 {
                continue;
            }

            let finding = match instr.imm {
                // bpf_probe_write_user —" can write to arbitrary user-space addresses.
                36 => Some(
                    SecurityFinding::new(
                        Severity::Critical,
                        numeric::usize_to_u32(idx),
                        format!(
                            "insn {idx}: bpf_probe_write_user (#36) can overwrite arbitrary \
                         user-space memory —  requires CAP_SYS_ADMIN but is a strong \
                         primitive for privilege escalation"
                        ),
                    )
                    .with_cve("CVE-class:BPF-WRITE-USER"),
                ),

                // bpf_sys_bpf —" allows arbitrary BPF syscall invocation from within BPF.
                158 => Some(
                    SecurityFinding::new(
                        Severity::Critical,
                        numeric::usize_to_u32(idx),
                        format!(
                            "insn {idx}: bpf_sys_bpf (#158) allows arbitrary BPF syscall from \
                         within a BPF program —  can be used to load additional programs \
                         or create maps with escalated permissions"
                        ),
                    )
                    .with_cve("CVE-class:BPF-SYS-BPF"),
                ),

                // bpf_trace_printk —" data leak via trace log.
                6 => Some(SecurityFinding::new(
                    Severity::Low,
                    numeric::usize_to_u32(idx),
                    format!(
                        "insn {idx}: bpf_trace_printk (#6) writes to the trace log —  \
                         may leak sensitive kernel data to unprivileged readers of \
                         /sys/kernel/debug/tracing/trace_pipe"
                    ),
                )),

                // bpf_get_current_task —" raw task_struct pointer.
                35 => Some(SecurityFinding::new(
                    Severity::Medium,
                    numeric::usize_to_u32(idx),
                    format!(
                        "insn {idx}: bpf_get_current_task (#35) returns a raw \
                         task_struct pointer —  can be used to read/write kernel \
                         memory on vulnerable kernels"
                    ),
                )),

                // bpf_override_return —" alters function return value (kprobes only).
                58 => Some(SecurityFinding::new(
                    Severity::High,
                    numeric::usize_to_u32(idx),
                    format!(
                        "insn {idx}: bpf_override_return (#58) modifies the return \
                         value of a kprobed kernel function —  powerful security bypass"
                    ),
                )),

                // bpf_copy_from_user —" reads from user-space; verify size is bounded.
                148 => Some(SecurityFinding::new(
                    Severity::Low,
                    numeric::usize_to_u32(idx),
                    format!(
                        "insn {idx}: bpf_copy_from_user (#148) —  ensure size argument \
                         in r3 is statically bounded"
                    ),
                )),

                _ => None,
            };
            if let Some(f) = finding {
                findings.push(f);
            }
        }
        findings
    }

    /// Detect stack out-of-bounds access patterns.
    ///
    /// The BPF stack is `[-512, 0)` relative to `r10` (frame pointer).  Any
    /// store/load with an offset outside this range is a verifier violation.
    fn check_stack_oob(prog: &[BpfInstruction]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        for (idx, instr) in prog.iter().enumerate() {
            let cls = instr.opcode & 0x07;
            let is_stack_base = (cls == 0x02 || cls == 0x03) && instr.dst_reg == 10;
            let is_stack_read = cls == 0x01 && instr.src_reg == 10;
            if is_stack_base || is_stack_read {
                let off = i32::from(instr.offset);
                if !(-512..=0).contains(&off) {
                    findings.push(
                        SecurityFinding::new(
                            Severity::High,
                            numeric::usize_to_u32(idx),
                            format!(
                                "insn {idx}: stack access at r10+({off}) is outside the \
                             valid range [-512, 0] —  verifier will reject this program"
                            ),
                        )
                        .with_cve("CVE-class:BPF-STACK-OOB"),
                    );
                }
            }
        }
        findings
    }

    /// Check that the program contains at least one `BPF_EXIT`.
    fn check_no_exit(prog: &[BpfInstruction]) -> Option<SecurityFinding> {
        let has_exit = prog.iter().any(|i| {
            let cls = i.opcode & 0x07;
            let code = i.opcode & 0xf0;
            cls == 0x05 && code == 0x90
        });
        if !has_exit && !prog.is_empty() {
            Some(SecurityFinding::new(
                Severity::High,
                0,
                "program has no BPF_EXIT instruction —  verifier will reject".to_owned(),
            ))
        } else {
            None
        }
    }

    /// Check for instructions that can never be reached (after an unconditional
    /// forward jump with no label at the target).
    ///
    /// Heuristic only: flags instructions immediately following an unconditional
    /// `ja` that are more than `ja.offset` instructions away from any label.
    fn check_unreachable_exit(prog: &[BpfInstruction]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        // Build a set of instruction indices that are branch targets.
        let mut targets: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for (idx, instr) in prog.iter().enumerate() {
            let cls = instr.opcode & 0x07;
            let code = instr.opcode & 0xf0;
            if cls == 0x05 && code != 0x80 && code != 0x90 {
                let target =crate::numeric::usize_to_i64(idx) + 1 + i64::from(instr.offset);
                if target >= 0 {
                    targets.insert(numeric::i64_to_usize(target));
                }
            }
        }
        // Flag instructions after an unconditional ja that are not targets.
        for (idx, instr) in prog.iter().enumerate() {
            let cls = instr.opcode & 0x07;
            let code = instr.opcode & 0xf0;
            // Unconditional forward ja.
            if cls == 0x05 && code == 0x00 && instr.offset > 0 {
                let next = idx + 1;
                if next < prog.len() && !targets.contains(&next) {
                    findings.push(SecurityFinding::new(
                        Severity::Info,
                        numeric::usize_to_u32(next),
                        format!(
                            "insn {next}: possibly unreachable —  follows unconditional ja at \
                             insn {idx} and is not a known branch target"
                        ),
                    ));
                }
            }
        }
        findings
    }

    /// Check constraints specific to the given program type.
    fn check_prog_type_constraints(
        prog: &[BpfInstruction],
        prog_type: BpfProgType,
    ) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        for (idx, instr) in prog.iter().enumerate() {
            let cls = instr.opcode & 0x07;
            let code = instr.opcode & 0xf0;
            if cls != 0x05 || code != 0x80 {
                continue;
            }

            let helper_id = instr.imm.cast_unsigned();

            // XDP programs must not use socket-filter helpers.
            if prog_type == BpfProgType::Xdp {
                match helper_id {
                    // bpf_skb_* helpers are skb-based and invalid for XDP.
                    9..=13 | 18..=22 | 26 | 29..=34 | 38..=45 => {
                        findings.push(SecurityFinding::new(
                            Severity::High,
                            numeric::usize_to_u32(idx),
                            format!(
                                "insn {idx}: helper #{helper_id} is an skb-based helper \
                                 but this program is of type XDP —  verifier will reject"
                            ),
                        ));
                    }
                    _ => {}
                }
            }

            // Socket-filter programs should not use kprobe/tracing helpers.
            if prog_type == BpfProgType::SocketFilter {
                match helper_id {
                    // bpf_probe_read, bpf_probe_write_user, bpf_override_return
                    4 | 36 | 58 => {
                        findings.push(SecurityFinding::new(
                            Severity::Medium,
                            numeric::usize_to_u32(idx),
                            format!(
                                "insn {idx}: helper #{helper_id} is a tracing helper and \
                                 may not be available in socket_filter programs"
                            ),
                        ));
                    }
                    _ => {}
                }
            }
        }

        findings
    }
}

// ===========================================================================
// BPF Map Usage Extraction
// ===========================================================================
//
// Lightweight extraction of map operation calls from a decoded instruction
// stream.  Does not require BTF —" only inspects helper call immediates.

/// The kind of map operation corresponding to a helper call.
///
/// Note: [`MapOp`] already exists for [`BpfMapAccess`].  `MapUsage` is a
/// separate, lighter-weight struct oriented toward security analysis rather
/// than full program report generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapUsage {
    /// The register that holds the map pointer at the call site.
    ///
    /// For BPF helpers the first argument is always in `r1`.  This field
    /// records whichever register was most recently loaded with a map-fd via
    /// `lddw` before the call; falls back to `1` when not determinable.
    pub map_reg: u8,
    /// The map operation kind.
    pub operation: MapOp,
    /// Instruction index (0-based) of the helper call.
    pub at_insn: u32,
}

/// Scan a decoded instruction slice for BPF map helper calls.
///
/// Returns one [`MapUsage`] entry for each `BPF_CALL` instruction whose
/// immediate matches a map-touching helper:
///
/// | Helper ID | Operation    |
/// |-----------|-------------|
/// | 1         | Lookup       |
/// | 2         | Update       |
/// | 3         | Delete       |
/// | 4         | `GetNextKey`   |
///
/// The `map_reg` field records the register used to hold the map file
/// descriptor: it is `1` (r1) in the conventional BPF calling convention but
/// may differ when `lddw` instructions targeting other registers are detected.
#[must_use]
pub fn extract_map_usages(prog: &[BpfInstruction]) -> Vec<MapUsage> {
    let mut usages = Vec::new();
    // Track which register was last loaded with a map fd via lddw.
    let mut map_reg: u8 = 1;

    for (idx, instr) in prog.iter().enumerate() {
        // Detect lddw (0x18) —" wide-immediate load of a map fd.
        if instr.opcode == 0x18 {
            map_reg = instr.dst_reg;
            continue;
        }

        let cls = instr.opcode & 0x07;
        let code = instr.opcode & 0xf0;

        // BPF_CALL (class=JMP, op=CALL).
        if cls != 0x05 || code != 0x80 {
            continue;
        }

        let op = match instr.imm {
            1 => MapOp::Lookup,
            2 => MapOp::Update,
            3 => MapOp::Delete,
            4 => MapOp::GetNextKey,
            _ => continue,
        };

        usages.push(MapUsage {
            map_reg,
            operation: op,
            at_insn: numeric::usize_to_u32(idx),
        });
    }

    usages
}

// ===========================================================================
// BTF section unit tests
// ===========================================================================

#[cfg(test)]
mod btf_section_tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Minimal BTF blob builder for tests
    // -----------------------------------------------------------------------

    /// Writes a little-endian u32 into a Vec<u8>.
    fn push_u32(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_le_bytes());
    }

    fn _push_i32(v: &mut Vec<u8>, x: i32) {
        v.extend_from_slice(&x.to_le_bytes());
    }

    /// Build a minimal BTF blob with the given types and strings sections.
    fn build_btf(types_section: Vec<u8>, strings_section: Vec<u8>) -> Vec<u8> {
        // Header: magic(2) + version(1) + flags(1) + hdr_len(4)
        //       + type_off(4) + type_len(4) + str_off(4) + str_len(4) = 24 bytes
        let hdr_len: u32 = 24;
        let type_off: u32 = 0;
        let type_len = numeric::usize_to_u32(types_section.len());
        let str_off = type_len; // strings immediately after types
        let str_len = numeric::usize_to_u32(strings_section.len());

        let mut blob = Vec::new();
        // magic 0xEB9F in LE = [0x9F, 0xEB]
        blob.extend_from_slice(&0xEB9Fu16.to_le_bytes());
        blob.push(1); // version
        blob.push(0); // flags
        push_u32(&mut blob, hdr_len);
        push_u32(&mut blob, type_off);
        push_u32(&mut blob, type_len);
        push_u32(&mut blob, str_off);
        push_u32(&mut blob, str_len);
        blob.extend_from_slice(&types_section);
        blob.extend_from_slice(&strings_section);
        blob
    }

    /// Encode a single `btf_type` header.
    fn btf_type_hdr(name_off: u32, kind: u32, vlen: u32, size_or_type: u32) -> Vec<u8> {
        let info = (kind << 24) | (vlen & 0xffff);
        let mut v = Vec::new();
        push_u32(&mut v, name_off);
        push_u32(&mut v, info);
        push_u32(&mut v, size_or_type);
        v
    }

    // -----------------------------------------------------------------------
    // BtfSection::parse tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_btf_parse_bad_magic() {
        let blob = vec![
            0x00u8, 0x00, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(BtfSection::parse(&blob).is_err());
    }

    #[test]
    fn test_btf_parse_truncated() {
        let blob = vec![0x9F, 0xEB];
        assert!(BtfSection::parse(&blob).is_err());
    }

    #[test]
    fn test_btf_parse_empty_type_section() {
        // No types: just strings section with empty string at offset 0.
        let strs = vec![0u8]; // one NUL byte = empty string at offset 0
        let blob = build_btf(vec![], strs);
        let btf = BtfSection::parse(&blob).unwrap();
        // Only the synthetic void type should exist.
        assert_eq!(btf.type_count(), 1);
        assert!(matches!(btf.types[0].kind, BtfTypeKind::Void));
    }

    #[test]
    fn test_btf_parse_single_int() {
        // Build: strings = "\0u32\0", type = BTF_KIND_INT (size=4, bits=32, unsigned)
        let mut strs = Vec::new();
        strs.push(0u8); // offset 0 = ""
        let u32_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"u32\0");

        let mut types_sec = Vec::new();
        // btf_type header: name_off=1, kind=1(INT), vlen=0, size_or_type=4
        types_sec.extend_from_slice(&btf_type_hdr(u32_off, 1, 0, 4));
        // INT encoding word: bits[7:0]=32 (nr_bits), encoding=0 (unsigned)
        push_u32(&mut types_sec, 32);

        let blob = build_btf(types_sec, strs);
        let btf = BtfSection::parse(&blob).unwrap();
        assert_eq!(btf.type_count(), 2); // void + u32
        let t = btf.get_type(1).unwrap();
        assert_eq!(t.name, Some("u32".to_owned()));
        match &t.kind {
            BtfTypeKind::Int { bits, signed, .. } => {
                assert_eq!(*bits, 32);
                assert!(!signed);
            }
            _ => panic!("expected BtfTypeKind::Int"),
        }
    }

    #[test]
    fn test_btf_sizeof_int() {
        let mut strs: Vec<u8> = vec![0];
        let off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"u64\0");

        let mut types_sec = Vec::new();
        types_sec.extend_from_slice(&btf_type_hdr(off, 1, 0, 8)); // size=8
        push_u32(&mut types_sec, 64); // nr_bits=64

        let blob = build_btf(types_sec, strs);
        let btf = BtfSection::parse(&blob).unwrap();
        assert_eq!(btf.sizeof(1), Some(8));
        assert_eq!(btf.sizeof(0), None); // void
    }

    #[test]
    fn test_btf_sizeof_ptr() {
        let mut strs: Vec<u8> = vec![0];
        let void_off = numeric::usize_to_u32(strs.len());
        strs.push(0); // empty string

        let mut types_sec = Vec::new();
        // type_id 1 = PTR to void (type_id=0).
        types_sec.extend_from_slice(&btf_type_hdr(void_off, 2, 0, 0));

        let blob = build_btf(types_sec, strs);
        let btf = BtfSection::parse(&blob).unwrap();
        // Pointer is always 8 bytes in BPF.
        assert_eq!(btf.sizeof(1), Some(8));
    }

    #[test]
    fn test_btf_get_type_void() {
        let blob = build_btf(vec![], vec![0]);
        let btf = BtfSection::parse(&blob).unwrap();
        let v = btf.get_type(0).unwrap();
        assert!(matches!(v.kind, BtfTypeKind::Void));
        assert!(v.name.is_none());
    }

    #[test]
    fn test_btf_get_type_out_of_range() {
        let blob = build_btf(vec![], vec![0]);
        let btf = BtfSection::parse(&blob).unwrap();
        assert!(btf.get_type(1).is_none());
    }

    #[test]
    fn test_btf_read_string() {
        let strs = b"\0hello\0world\0";
        let blob = build_btf(vec![], strs.to_vec());
        let btf = BtfSection::parse(&blob).unwrap();
        assert_eq!(btf.read_string(0), "");
        assert_eq!(btf.read_string(1), "hello");
        assert_eq!(btf.read_string(7), "world");
    }

    #[test]
    fn test_btf_to_c_declaration_int() {
        let mut strs: Vec<u8> = vec![0];
        let off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"__u32\0");

        let mut types_sec = Vec::new();
        types_sec.extend_from_slice(&btf_type_hdr(off, 1, 0, 4));
        push_u32(&mut types_sec, 32);

        let blob = build_btf(types_sec, strs);
        let btf = BtfSection::parse(&blob).unwrap();
        let decl = btf.to_c_declaration(1, "x");
        assert!(decl.contains("__u32") && decl.contains('x'));
    }

    #[test]
    fn test_btf_to_c_declaration_void() {
        let blob = build_btf(vec![], vec![0]);
        let btf = BtfSection::parse(&blob).unwrap();
        let decl = btf.to_c_declaration(0, "p");
        assert!(decl.contains("void") && decl.contains('p'));
    }

    #[test]
    fn test_btf_struct_field_offset() {
        // Build a struct: { u32 a; u32 b; }
        // type_id 1 = u32 (INT, size=4)
        // type_id 2 = struct { a at bit_off=0, b at bit_off=32 }
        let mut strs: Vec<u8> = vec![0];
        let a_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"a\0");
        let b_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"b\0");
        let s_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"my_struct\0");
        let u32_name_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"u32\0");

        let mut types_sec = Vec::new();

        // type_id 1 = u32 (INT)
        types_sec.extend_from_slice(&btf_type_hdr(u32_name_off, 1, 0, 4));
        push_u32(&mut types_sec, 32);

        // type_id 2 = struct my_struct (kind=4, vlen=2, size=8)
        types_sec.extend_from_slice(&btf_type_hdr(s_off, 4, 2, 8));
        // member 0: a, type_id=1, bit_offset=0
        push_u32(&mut types_sec, a_off);
        push_u32(&mut types_sec, 1);
        push_u32(&mut types_sec, 0);
        // member 1: b, type_id=1, bit_offset=32
        push_u32(&mut types_sec, b_off);
        push_u32(&mut types_sec, 1);
        push_u32(&mut types_sec, 32);

        let blob = build_btf(types_sec, strs);
        let btf = BtfSection::parse(&blob).unwrap();

        assert_eq!(btf.get_struct_field_offset(2, "a"), Some(0));
        assert_eq!(btf.get_struct_field_offset(2, "b"), Some(4));
        assert_eq!(btf.get_struct_field_offset(2, "c"), None);
    }

    #[test]
    fn test_btf_sizeof_struct() {
        let mut strs: Vec<u8> = vec![0];
        let s_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"s\0");

        let mut types_sec = Vec::new();
        // struct s { }; size = 16
        types_sec.extend_from_slice(&btf_type_hdr(s_off, 4, 0, 16));

        let blob = build_btf(types_sec, strs);
        let btf = BtfSection::parse(&blob).unwrap();
        assert_eq!(btf.sizeof(1), Some(16));
    }

    #[test]
    fn test_btf_skip_modifiers() {
        // type_id 1 = INT u32
        // type_id 2 = CONST -> 1
        // type_id 3 = VOLATILE -> 2
        let mut strs: Vec<u8> = vec![0];
        let u32_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"u32\0");

        let mut types_sec = Vec::new();
        types_sec.extend_from_slice(&btf_type_hdr(u32_off, 1, 0, 4)); // id=1 INT
        push_u32(&mut types_sec, 32);
        types_sec.extend_from_slice(&btf_type_hdr(0, 10, 0, 1)); // id=2 CONST->1
        types_sec.extend_from_slice(&btf_type_hdr(0, 9, 0, 2)); // id=3 VOLATILE->2

        let blob = build_btf(types_sec, strs);
        let btf = BtfSection::parse(&blob).unwrap();

        assert_eq!(btf.skip_modifiers(3), 1);
        assert_eq!(btf.skip_modifiers(2), 1);
        assert_eq!(btf.skip_modifiers(1), 1);
    }

    #[test]
    fn test_btf_find_struct_by_name() {
        let mut strs: Vec<u8> = vec![0];
        let foo_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"foo\0");
        let bar_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"bar\0");

        let mut types_sec = Vec::new();
        types_sec.extend_from_slice(&btf_type_hdr(foo_off, 4, 0, 4)); // struct foo
        types_sec.extend_from_slice(&btf_type_hdr(bar_off, 4, 0, 8)); // struct bar

        let blob = build_btf(types_sec, strs);
        let btf = BtfSection::parse(&blob).unwrap();

        let foos = btf.find_struct_by_name("foo");
        assert_eq!(foos, vec![1]);
        let bars = btf.find_struct_by_name("bar");
        assert_eq!(bars, vec![2]);
        let none = btf.find_struct_by_name("baz");
        assert!(none.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_access_string tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_access_string_single() {
        // "0" alone â†' root type, offset 0.
        // type_id 1 = struct { u32 x; } (size=4)
        let mut strs: Vec<u8> = vec![0];
        let x_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"x\0");
        let s_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"S\0");
        let u_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"u32\0");

        let mut ts = Vec::new();
        ts.extend_from_slice(&btf_type_hdr(u_off, 1, 0, 4));
        push_u32(&mut ts, 32); // id=1 u32
        ts.extend_from_slice(&btf_type_hdr(s_off, 4, 1, 4)); // id=2 struct S { x }
        push_u32(&mut ts, x_off);
        push_u32(&mut ts, 1);
        push_u32(&mut ts, 0);

        let blob = build_btf(ts, strs);
        let btf = BtfSection::parse(&blob).unwrap();

        let res = parse_access_string("0", &btf, 2);
        assert_eq!(res, Some((2, 0)));
    }

    #[test]
    fn test_parse_access_string_nested() {
        // struct S { u32 a; u32 b; }
        // access "0:1" â†' field b at byte offset 4.
        let mut strs: Vec<u8> = vec![0];
        let a_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"a\0");
        let b_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"b\0");
        let s_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"S\0");
        let u_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"u32\0");

        let mut ts = Vec::new();
        ts.extend_from_slice(&btf_type_hdr(u_off, 1, 0, 4));
        push_u32(&mut ts, 32); // id=1 u32
        ts.extend_from_slice(&btf_type_hdr(s_off, 4, 2, 8)); // id=2 struct S
        push_u32(&mut ts, a_off);
        push_u32(&mut ts, 1);
        push_u32(&mut ts, 0); // a at 0
        push_u32(&mut ts, b_off);
        push_u32(&mut ts, 1);
        push_u32(&mut ts, 32); // b at 32 bits

        let blob = build_btf(ts, strs);
        let btf = BtfSection::parse(&blob).unwrap();

        let res = parse_access_string("0:1", &btf, 2);
        assert_eq!(res, Some((1, 4)));
    }

    #[test]
    fn test_parse_access_string_out_of_range() {
        let mut strs: Vec<u8> = vec![0];
        let s_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"S\0");

        let mut ts = Vec::new();
        ts.extend_from_slice(&btf_type_hdr(s_off, 4, 0, 0)); // id=1 struct with 0 members

        let blob = build_btf(ts, strs);
        let btf = BtfSection::parse(&blob).unwrap();

        // Access member index 5 in an empty struct â†' None.
        let res = parse_access_string("0:5", &btf, 1);
        assert!(res.is_none());
    }

    // -----------------------------------------------------------------------
    // CO-RE apply_core_relocations tests
    // -----------------------------------------------------------------------

    fn _make_call_instr(helper_id: i32) -> BpfInstruction {
        let mut raw = vec![0x85u8, 0x00, 0x00, 0x00];
        raw.extend_from_slice(&helper_id.to_le_bytes());
        BpfInstruction {
            raw,
            opcode: 0x85,
            dst_reg: 0,
            src_reg: 0,
            offset: 0,
            imm: helper_id,
            wide_imm: None,
        }
    }

    fn make_mov_imm(dst: u8, imm: i32) -> BpfInstruction {
        let op = 0xb7u8;
        let mut raw = vec![op, dst & 0x0f, 0, 0];
        raw.extend_from_slice(&imm.to_le_bytes());
        BpfInstruction {
            raw,
            opcode: op,
            dst_reg: dst,
            src_reg: 0,
            offset: 0,
            imm,
            wide_imm: None,
        }
    }

    #[test]
    fn test_core_reloc_field_byte_offset() {
        // struct S { u32 a; u32 b; }  —" offset of b = 4.
        let mut strs: Vec<u8> = vec![0];
        let a_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"a\0");
        let b_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"b\0");
        let s_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"S\0");
        let u_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"u32\0");

        let mut ts = Vec::new();
        ts.extend_from_slice(&btf_type_hdr(u_off, 1, 0, 4));
        push_u32(&mut ts, 32);
        ts.extend_from_slice(&btf_type_hdr(s_off, 4, 2, 8));
        push_u32(&mut ts, a_off);
        push_u32(&mut ts, 1);
        push_u32(&mut ts, 0);
        push_u32(&mut ts, b_off);
        push_u32(&mut ts, 1);
        push_u32(&mut ts, 32);

        let blob = build_btf(ts, strs);
        let btf = BtfSection::parse(&blob).unwrap();

        // Instruction 0 = mov r1, 0  (placeholder for offset)
        let mut prog = vec![make_mov_imm(1, 0)];
        let relocs = vec![CoreRelocation {
            insn_off: 0,
            type_id: 2,                   // struct S
            access_str: "0:1".to_owned(), // field b
            kind: CoreRelocKind::FieldByteOffset,
        }];

        let patched = apply_core_relocations(&mut prog, &relocs, &btf, None);
        assert_eq!(patched, vec![0]);
        assert_eq!(prog[0].imm, 4);
    }

    #[test]
    fn test_core_reloc_type_size() {
        let mut strs: Vec<u8> = vec![0];
        let s_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"S\0");

        let mut ts = Vec::new();
        ts.extend_from_slice(&btf_type_hdr(s_off, 4, 0, 24)); // struct S; size=24

        let blob = build_btf(ts, strs);
        let btf = BtfSection::parse(&blob).unwrap();

        let mut prog = vec![make_mov_imm(1, 0)];
        let relocs = vec![CoreRelocation {
            insn_off: 0,
            type_id: 1,
            access_str: "0".to_owned(),
            kind: CoreRelocKind::TypeSize,
        }];

        let patched = apply_core_relocations(&mut prog, &relocs, &btf, None);
        assert_eq!(patched, vec![0]);
        assert_eq!(prog[0].imm, 24);
    }

    #[test]
    fn test_core_reloc_field_exists_yes() {
        let mut strs: Vec<u8> = vec![0];
        let a_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"a\0");
        let s_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"S\0");
        let u_off = numeric::usize_to_u32(strs.len());
        strs.extend_from_slice(b"u32\0");

        let mut ts = Vec::new();
        ts.extend_from_slice(&btf_type_hdr(u_off, 1, 0, 4));
        push_u32(&mut ts, 32);
        ts.extend_from_slice(&btf_type_hdr(s_off, 4, 1, 4));
        push_u32(&mut ts, a_off);
        push_u32(&mut ts, 1);
        push_u32(&mut ts, 0);

        let blob = build_btf(ts, strs);
        let btf = BtfSection::parse(&blob).unwrap();

        let mut prog = vec![make_mov_imm(1, 99)];
        let relocs = vec![CoreRelocation {
            insn_off: 0,
            type_id: 2,
            access_str: "0:0".to_owned(),
            kind: CoreRelocKind::FieldExists,
        }];

        let patched = apply_core_relocations(&mut prog, &relocs, &btf, None);
        assert_eq!(patched, vec![0]);
        assert_eq!(prog[0].imm, 1);
    }

    #[test]
    fn test_core_reloc_type_exists() {
        let blob = build_btf(vec![], vec![0]);
        let btf = BtfSection::parse(&blob).unwrap();

        let mut prog = vec![make_mov_imm(1, 0)];
        // type_id=0 (void) always exists.
        let relocs = vec![CoreRelocation {
            insn_off: 0,
            type_id: 0,
            access_str: "0".to_owned(),
            kind: CoreRelocKind::TypeExists,
        }];
        let patched = apply_core_relocations(&mut prog, &relocs, &btf, None);
        assert_eq!(patched, vec![0]);
        assert_eq!(prog[0].imm, 1);
    }

    #[test]
    fn test_core_reloc_type_id_local() {
        let blob = build_btf(vec![], vec![0]);
        let btf = BtfSection::parse(&blob).unwrap();

        let mut prog = vec![make_mov_imm(1, 0)];
        let relocs = vec![CoreRelocation {
            insn_off: 0,
            type_id: 42,
            access_str: "0".to_owned(),
            kind: CoreRelocKind::TypeIdLocal,
        }];
        let patched = apply_core_relocations(&mut prog, &relocs, &btf, None);
        assert_eq!(patched, vec![0]);
        assert_eq!(prog[0].imm, 42);
    }

    // -----------------------------------------------------------------------
    // BpfSecurityAnalysis tests
    // -----------------------------------------------------------------------

    fn enc_instr(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> BpfInstruction {
        let mut raw = vec![op, (src << 4) | (dst & 0x0f)];
        raw.extend_from_slice(&off.to_le_bytes());
        raw.extend_from_slice(&imm.to_le_bytes());
        BpfInstruction {
            raw,
            opcode: op,
            dst_reg: dst,
            src_reg: src,
            offset: off,
            imm,
            wide_imm: None,
        }
    }

    fn call(helper: i32) -> BpfInstruction {
        enc_instr(0x85, 0, 0, 0, helper)
    }
    fn exit_instr() -> BpfInstruction {
        enc_instr(0x95, 0, 0, 0, 0)
    }
    fn ja(off: i16) -> BpfInstruction {
        enc_instr(0x05, 0, 0, off, 0)
    }
    fn jeq_r0_0(off: i16) -> BpfInstruction {
        enc_instr(0x15, 0, 0, off, 0)
    } // jeq r0, 0, off

    #[test]
    fn test_security_no_findings_simple() {
        // mov r0, 1; exit  —" no issues.
        let prog = vec![enc_instr(0xb7, 0, 0, 0, 1), exit_instr()];
        let findings = BpfSecurityAnalysis::analyze(&prog, BpfProgType::SocketFilter);
        // May have INFO-level unreachable-exit —" filter those out.
        let real: Vec<_> = findings
            .iter()
            .filter(|f| f.severity > Severity::Info)
            .collect();
        assert!(real.is_empty(), "unexpected findings: {real:?}");
    }

    #[test]
    fn test_security_no_exit() {
        let prog = vec![enc_instr(0xb7, 0, 0, 0, 1)];
        let findings = BpfSecurityAnalysis::analyze(&prog, BpfProgType::SocketFilter);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High && f.description.contains("no BPF_EXIT"))
        );
    }

    #[test]
    fn test_security_dangerous_helper_probe_write_user() {
        let prog = vec![call(36), exit_instr()];
        let findings = BpfSecurityAnalysis::analyze(&prog, BpfProgType::Kprobe);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical
                && f.description.contains("bpf_probe_write_user"))
        );
    }

    #[test]
    fn test_security_dangerous_helper_sys_bpf() {
        let prog = vec![call(158), exit_instr()];
        let findings = BpfSecurityAnalysis::analyze(&prog, BpfProgType::Tracing);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.description.contains("bpf_sys_bpf"))
        );
    }

    #[test]
    fn test_security_map_oob_no_null_check() {
        // call bpf_map_lookup_elem; ldxdw r2, [r0+0]; exit
        let prog = vec![
            call(1),                     // lookup —  r0 = map ptr (maybe null)
            enc_instr(0x79, 2, 0, 0, 0), // ldxdw r2, [r0+0] —  OOB!
            exit_instr(),
        ];
        let findings = BpfSecurityAnalysis::analyze(&prog, BpfProgType::Kprobe);
        assert!(findings.iter().any(|f| f.severity == Severity::High
            && f.cve_like.as_deref() == Some("CVE-class:BPF-MAP-OOB")));
    }

    #[test]
    fn test_security_map_oob_with_null_check() {
        // call lookup; jeq r0, 0, +1; ldxdw r2, [r0+0]; exit
        let prog = vec![
            call(1),
            jeq_r0_0(1),
            enc_instr(0x79, 2, 0, 0, 0),
            exit_instr(),
        ];
        let findings = BpfSecurityAnalysis::analyze(&prog, BpfProgType::Kprobe);
        // No HIGH OOB finding expected.
        let oob: Vec<_> = findings
            .iter()
            .filter(|f| f.cve_like.as_deref() == Some("CVE-class:BPF-MAP-OOB"))
            .collect();
        assert!(oob.is_empty(), "unexpected OOB findings: {oob:?}");
    }

    #[test]
    fn test_security_backward_branch() {
        // ja -1  (backward)
        let prog = vec![ja(-1), exit_instr()];
        let finding = BpfSecurityAnalysis::check_unbounded_loop(&prog);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::Medium);
    }

    #[test]
    fn test_security_forward_branch_ok() {
        // ja +1  (forward)
        let prog = vec![ja(1), exit_instr(), exit_instr()];
        let finding = BpfSecurityAnalysis::check_unbounded_loop(&prog);
        assert!(finding.is_none());
    }

    #[test]
    fn test_security_stack_oob() {
        // stxdw [r10 + (-600)], r1  —" out of [-512, 0]
        let prog = vec![enc_instr(0x7b, 10, 1, -600i16, 0), exit_instr()];
        let findings = BpfSecurityAnalysis::check_stack_oob(&prog);
        assert!(!findings.is_empty());
        assert!(findings[0].cve_like.as_deref() == Some("CVE-class:BPF-STACK-OOB"));
    }

    #[test]
    fn test_security_stack_in_bounds() {
        // stxdw [r10 + (-8)], r1  —" fine
        let prog = vec![enc_instr(0x7b, 10, 1, -8i16, 0), exit_instr()];
        let findings = BpfSecurityAnalysis::check_stack_oob(&prog);
        assert!(findings.is_empty());
    }

    // -----------------------------------------------------------------------
    // extract_map_usages tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_map_usages_empty() {
        let usages = extract_map_usages(&[]);
        assert!(usages.is_empty());
    }

    #[test]
    fn test_extract_map_usages_lookup() {
        // lddw r1, fd; call bpf_map_lookup_elem
        let lddw = BpfInstruction {
            raw: {
                let mut r = vec![0x18u8, 0x01, 0, 0];
                r.extend_from_slice(&3i32.to_le_bytes());
                r.extend_from_slice(&[0u8; 4]);
                r.extend_from_slice(&0i32.to_le_bytes());
                r
            },
            opcode: 0x18,
            dst_reg: 1,
            src_reg: 0,
            offset: 0,
            imm: 3,
            wide_imm: Some(3),
        };
        let prog = vec![lddw, call(1), exit_instr()];
        let usages = extract_map_usages(&prog);
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].operation, MapOp::Lookup);
        assert_eq!(usages[0].map_reg, 1);
        assert_eq!(usages[0].at_insn, 1);
    }

    #[test]
    fn test_extract_map_usages_update_and_delete() {
        let prog = vec![call(2), call(3), exit_instr()];
        let usages = extract_map_usages(&prog);
        assert_eq!(usages.len(), 2);
        assert_eq!(usages[0].operation, MapOp::Update);
        assert_eq!(usages[1].operation, MapOp::Delete);
    }

    #[test]
    fn test_extract_map_usages_get_next_key() {
        let prog = vec![call(4), exit_instr()];
        let usages = extract_map_usages(&prog);
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].operation, MapOp::GetNextKey);
    }

    #[test]
    fn test_extract_map_usages_non_map_helpers_ignored() {
        // Helpers that don't touch maps should not appear.
        let prog = vec![call(5), call(6), call(14), exit_instr()];
        let usages = extract_map_usages(&prog);
        assert!(usages.is_empty());
    }

    // -----------------------------------------------------------------------
    // CoreRelocKind tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_core_reloc_kind_round_trip() {
        for v in 0..=11u32 {
            let k = CoreRelocKind::from_u32(v);
            assert!(k.is_some(), "from_u32({v}) should succeed");
        }
        assert!(CoreRelocKind::from_u32(12).is_none());
        assert!(CoreRelocKind::from_u32(99).is_none());
    }

    #[test]
    fn test_core_reloc_kind_names() {
        assert_eq!(CoreRelocKind::FieldByteOffset.name(), "field_byte_offset");
        assert_eq!(CoreRelocKind::TypeSize.name(), "type_size");
        assert_eq!(CoreRelocKind::EnumvalValue.name(), "enumval_value");
    }

    // -----------------------------------------------------------------------
    // Severity ordering test
    // -----------------------------------------------------------------------

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_severity_labels() {
        assert_eq!(Severity::Critical.label(), "CRITICAL");
        assert_eq!(Severity::Info.label(), "INFO");
    }
}

