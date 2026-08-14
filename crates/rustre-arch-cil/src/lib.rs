//! `rustre-arch-cil`
//!
//! .NET CIL / MSIL bytecode architecture for the `RustRE` Suite.
//!
//! Decodes all ~220 CIL opcodes from ECMA-335 Partition III, including
//! two-byte `0xFE xx` prefix opcodes.  Instructions are variable-length
//! (1–6 bytes) and the runtime is a stack-based VM.
//!
//! Public API:
//! - [`CilArch`]                — implements [`Architecture`]
//! - [`CilInstr`]               — decoded instruction
//! - [`CilLinearDisassembler`]  — iterator over CIL method body bytes

pub mod cil_analyzer;
pub mod cil_decompiler;
pub mod cil_decoder;
pub mod cil_lifter;
pub mod cil_metadata;
pub mod exception_handlers;
pub mod wide_prefix;

/// CIL obfuscation detection: RenameObfuscation, ControlFlowObfuscation,
/// StringEncryption, VirtualMachineObf, ObfuscationScore, CilObfuscation.
///
pub mod cil_obfuscation;
pub mod cil_stack_tracker;
pub mod cil_branch_analyzer;
pub mod cil_call_graph;

/// CIL .NET type system: CorElementType, CilType, signature parser, CallingConv.
pub mod cil_type_system;

/// CIL abstract execution engine: EvalStack, CilValue, LocalVars, Arguments.
pub mod cil_execution_engine;

/// CIL pattern recognizer: string encryption, reflection, anti-debug, P/Invoke.
pub mod cil_pattern_recognition;

use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
};
use rustre_core::address::Address;
use rustre_core::arch::{BranchCondition, RegisterKind};
use rustre_core::endian::Endian;
use rustre_core::errors::CoreError;

// ---------------------------------------------------------------------------
// Decode error
// ---------------------------------------------------------------------------

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum CilDecodeError {
    #[error("truncated CIL instruction")]
    Truncated,
    #[error("unknown opcode: {0:#04x}")]
    UnknownOpcode(u8),
    #[error("unknown 0xFE-prefixed opcode: 0xFE {0:#04x}")]
    UnknownPrefixedOpcode(u8),
}

// ---------------------------------------------------------------------------
// Decoded CIL instruction
// ---------------------------------------------------------------------------

/// A decoded CIL instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CilInstr {
    /// Raw bytes (including opcode byte(s) and inline operand).
    pub raw: Vec<u8>,
    /// Mnemonic string (e.g., `"ldarg.0"`, `"call"`, `"ceq"`).
    pub mnemonic: String,
    /// Operand string (e.g., `"#4"`, `"+12"`, `""`).
    pub operands: String,
    /// Semantic flags.
    pub flags: InstrFlags,
}

impl CilInstr {
    /// Decode one CIL instruction from `bytes`, returning `(instr, bytes_consumed)`.
    ///
    /// # Errors
    ///
    /// Returns [`CilDecodeError::Truncated`] when the slice is too short,
    /// [`CilDecodeError::UnknownOpcode`] for unrecognized single-byte opcodes,
    /// or [`CilDecodeError::UnknownPrefixedOpcode`] for unknown `0xFE xx` forms.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), CilDecodeError> {
        if bytes.is_empty() {
            return Err(CilDecodeError::Truncated);
        }
        decode_cil(bytes)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const fn need(bytes: &[u8], n: usize) -> Result<(), CilDecodeError> {
    if bytes.len() < n {
        Err(CilDecodeError::Truncated)
    } else {
        Ok(())
    }
}

fn i8b(bytes: &[u8], off: usize) -> i8 {
    i8::from_ne_bytes([bytes[off]])
}
fn i32le(bytes: &[u8], off: usize) -> i32 {
    i32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}
fn i64le(bytes: &[u8], off: usize) -> i64 {
    i64::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
        bytes[off + 5],
        bytes[off + 6],
        bytes[off + 7],
    ])
}
fn u16le(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}
fn u32le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}
fn f32le(bytes: &[u8], off: usize) -> f32 {
    f32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}
fn f64le(bytes: &[u8], off: usize) -> f64 {
    f64::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
        bytes[off + 5],
        bytes[off + 6],
        bytes[off + 7],
    ])
}

fn simple(mne: &str, flags: InstrFlags, op: u8) -> Result<(CilInstr, usize), CilDecodeError> {
    Ok((
        CilInstr {
            raw: vec![op],
            mnemonic: mne.to_string(),
            operands: String::new(),
            flags,
        },
        1,
    ))
}

fn with_ops(
    mne: &str,
    ops: impl Into<String>,
    flags: InstrFlags,
    raw: Vec<u8>,
) -> Result<(CilInstr, usize), CilDecodeError> {
    let size = raw.len();
    Ok((
        CilInstr {
            raw,
            mnemonic: mne.to_string(),
            operands: ops.into(),
            flags,
        },
        size,
    ))
}

fn prefixed(mne: &str, flags: InstrFlags, op2: u8) -> Result<(CilInstr, usize), CilDecodeError> {
    Ok((
        CilInstr {
            raw: vec![0xfe, op2],
            mnemonic: mne.to_string(),
            operands: String::new(),
            flags,
        },
        2,
    ))
}

fn prefixed_ops(
    mne: &str,
    ops: impl Into<String>,
    flags: InstrFlags,
    raw: Vec<u8>,
) -> Result<(CilInstr, usize), CilDecodeError> {
    let size = raw.len();
    Ok((
        CilInstr {
            raw,
            mnemonic: mne.to_string(),
            operands: ops.into(),
            flags,
        },
        size,
    ))
}

// ---------------------------------------------------------------------------
// Main decode routine
// ---------------------------------------------------------------------------

fn decode_cil(bytes: &[u8]) -> Result<(CilInstr, usize), CilDecodeError> {
    let op = bytes[0];

    match op {
        // ----- nop / break -----
        0x00 => simple("nop", InstrFlags::NONE, op),
        0x01 => simple("break", InstrFlags::BARRIER, op),

        // ----- ldarg short -----
        0x02 => simple("ldarg.0", InstrFlags::NONE, op),
        0x03 => simple("ldarg.1", InstrFlags::NONE, op),
        0x04 => simple("ldarg.2", InstrFlags::NONE, op),
        0x05 => simple("ldarg.3", InstrFlags::NONE, op),

        // ----- ldloc short -----
        0x06 => simple("ldloc.0", InstrFlags::NONE, op),
        0x07 => simple("ldloc.1", InstrFlags::NONE, op),
        0x08 => simple("ldloc.2", InstrFlags::NONE, op),
        0x09 => simple("ldloc.3", InstrFlags::NONE, op),

        // ----- stloc short -----
        0x0a => simple("stloc.0", InstrFlags::NONE, op),
        0x0b => simple("stloc.1", InstrFlags::NONE, op),
        0x0c => simple("stloc.2", InstrFlags::NONE, op),
        0x0d => simple("stloc.3", InstrFlags::NONE, op),

        // ----- ldarg.s / ldarga.s / starg.s -----
        0x0e => {
            need(bytes, 2)?;
            with_ops(
                "ldarg.s",
                format!("{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        0x0f => {
            need(bytes, 2)?;
            with_ops(
                "ldarga.s",
                format!("{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        0x10 => {
            need(bytes, 2)?;
            with_ops(
                "starg.s",
                format!("{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }

        // ----- ldloc.s / ldloca.s / stloc.s -----
        0x11 => {
            need(bytes, 2)?;
            with_ops(
                "ldloc.s",
                format!("{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        0x12 => {
            need(bytes, 2)?;
            with_ops(
                "ldloca.s",
                format!("{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        0x13 => {
            need(bytes, 2)?;
            with_ops(
                "stloc.s",
                format!("{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }

        // ----- null / ldc.i4 short forms -----
        0x14 => simple("ldnull", InstrFlags::NONE, op),
        0x15 => simple("ldc.i4.m1", InstrFlags::NONE, op),
        0x16 => simple("ldc.i4.0", InstrFlags::NONE, op),
        0x17 => simple("ldc.i4.1", InstrFlags::NONE, op),
        0x18 => simple("ldc.i4.2", InstrFlags::NONE, op),
        0x19 => simple("ldc.i4.3", InstrFlags::NONE, op),
        0x1a => simple("ldc.i4.4", InstrFlags::NONE, op),
        0x1b => simple("ldc.i4.5", InstrFlags::NONE, op),
        0x1c => simple("ldc.i4.6", InstrFlags::NONE, op),
        0x1d => simple("ldc.i4.7", InstrFlags::NONE, op),
        0x1e => simple("ldc.i4.8", InstrFlags::NONE, op),

        // ldc.i4.s <int8>
        0x1f => {
            need(bytes, 2)?;
            with_ops(
                "ldc.i4.s",
                format!("{}", i8b(bytes, 1)),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        // ldc.i4 <int32>
        0x20 => {
            need(bytes, 5)?;
            with_ops(
                "ldc.i4",
                format!("{}", i32le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..5].to_vec(),
            )
        }
        // ldc.i8 <int64>
        0x21 => {
            need(bytes, 9)?;
            with_ops(
                "ldc.i8",
                format!("{}", i64le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..9].to_vec(),
            )
        }
        // ldc.r4 <float32>
        0x22 => {
            need(bytes, 5)?;
            with_ops(
                "ldc.r4",
                format!("{}", f32le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..5].to_vec(),
            )
        }
        // ldc.r8 <float64>
        0x23 => {
            need(bytes, 9)?;
            with_ops(
                "ldc.r8",
                format!("{}", f64le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..9].to_vec(),
            )
        }

        // ----- dup / pop -----
        0x25 => simple("dup", InstrFlags::NONE, op),
        0x26 => simple("pop", InstrFlags::NONE, op),

        // ----- jmp / call / calli / ret -----
        0x27 => {
            need(bytes, 5)?;
            with_ops(
                "jmp",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::BRANCH,
                bytes[..5].to_vec(),
            )
        }
        0x28 => {
            need(bytes, 5)?;
            with_ops(
                "call",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::CALL,
                bytes[..5].to_vec(),
            )
        }
        0x29 => {
            need(bytes, 5)?;
            with_ops(
                "calli",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::CALL | InstrFlags::INDIRECT,
                bytes[..5].to_vec(),
            )
        }
        0x2a => simple("ret", InstrFlags::RET, op),

        // ----- short branches (1-byte offset) -----
        0x2b => {
            need(bytes, 2)?;
            with_ops(
                "br.s",
                format!("{:+}", i8b(bytes, 1)),
                InstrFlags::BRANCH,
                bytes[..2].to_vec(),
            )
        }
        0x2c => {
            need(bytes, 2)?;
            with_ops(
                "brfalse.s",
                format!("{:+}", i8b(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..2].to_vec(),
            )
        }
        0x2d => {
            need(bytes, 2)?;
            with_ops(
                "brtrue.s",
                format!("{:+}", i8b(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..2].to_vec(),
            )
        }
        0x2e => {
            need(bytes, 2)?;
            with_ops(
                "beq.s",
                format!("{:+}", i8b(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..2].to_vec(),
            )
        }
        0x2f => {
            need(bytes, 2)?;
            with_ops(
                "bge.s",
                format!("{:+}", i8b(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..2].to_vec(),
            )
        }
        0x30 => {
            need(bytes, 2)?;
            with_ops(
                "bgt.s",
                format!("{:+}", i8b(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..2].to_vec(),
            )
        }
        0x31 => {
            need(bytes, 2)?;
            with_ops(
                "ble.s",
                format!("{:+}", i8b(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..2].to_vec(),
            )
        }
        0x32 => {
            need(bytes, 2)?;
            with_ops(
                "blt.s",
                format!("{:+}", i8b(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..2].to_vec(),
            )
        }
        0x33 => {
            need(bytes, 2)?;
            with_ops(
                "bne.un.s",
                format!("{:+}", i8b(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..2].to_vec(),
            )
        }
        0x34 => {
            need(bytes, 2)?;
            with_ops(
                "bge.un.s",
                format!("{:+}", i8b(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..2].to_vec(),
            )
        }
        0x35 => {
            need(bytes, 2)?;
            with_ops(
                "bgt.un.s",
                format!("{:+}", i8b(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..2].to_vec(),
            )
        }
        0x36 => {
            need(bytes, 2)?;
            with_ops(
                "ble.un.s",
                format!("{:+}", i8b(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..2].to_vec(),
            )
        }
        0x37 => {
            need(bytes, 2)?;
            with_ops(
                "blt.un.s",
                format!("{:+}", i8b(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..2].to_vec(),
            )
        }

        // ----- long branches (4-byte offset) -----
        0x38 => {
            need(bytes, 5)?;
            with_ops(
                "br",
                format!("{:+}", i32le(bytes, 1)),
                InstrFlags::BRANCH,
                bytes[..5].to_vec(),
            )
        }
        0x39 => {
            need(bytes, 5)?;
            with_ops(
                "brfalse",
                format!("{:+}", i32le(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..5].to_vec(),
            )
        }
        0x3a => {
            need(bytes, 5)?;
            with_ops(
                "brtrue",
                format!("{:+}", i32le(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..5].to_vec(),
            )
        }
        0x3b => {
            need(bytes, 5)?;
            with_ops(
                "beq",
                format!("{:+}", i32le(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..5].to_vec(),
            )
        }
        0x3c => {
            need(bytes, 5)?;
            with_ops(
                "bge",
                format!("{:+}", i32le(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..5].to_vec(),
            )
        }
        0x3d => {
            need(bytes, 5)?;
            with_ops(
                "bgt",
                format!("{:+}", i32le(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..5].to_vec(),
            )
        }
        0x3e => {
            need(bytes, 5)?;
            with_ops(
                "ble",
                format!("{:+}", i32le(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..5].to_vec(),
            )
        }
        0x3f => {
            need(bytes, 5)?;
            with_ops(
                "blt",
                format!("{:+}", i32le(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..5].to_vec(),
            )
        }
        0x40 => {
            need(bytes, 5)?;
            with_ops(
                "bne.un",
                format!("{:+}", i32le(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..5].to_vec(),
            )
        }
        0x41 => {
            need(bytes, 5)?;
            with_ops(
                "bge.un",
                format!("{:+}", i32le(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..5].to_vec(),
            )
        }
        0x42 => {
            need(bytes, 5)?;
            with_ops(
                "bgt.un",
                format!("{:+}", i32le(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..5].to_vec(),
            )
        }
        0x43 => {
            need(bytes, 5)?;
            with_ops(
                "ble.un",
                format!("{:+}", i32le(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..5].to_vec(),
            )
        }
        0x44 => {
            need(bytes, 5)?;
            with_ops(
                "blt.un",
                format!("{:+}", i32le(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..5].to_vec(),
            )
        }

        // ----- switch -----
        0x45 => {
            need(bytes, 5)?;
            let n = u32le(bytes, 1) as usize;
            // Guard against integer overflow when n is very large.
            let total = n.checked_mul(4)
                .and_then(|v| v.checked_add(5))
                .ok_or(CilDecodeError::Truncated)?;
            need(bytes, total)?;
            with_ops(
                "switch",
                format!("targets={n}"),
                InstrFlags::BRANCH,
                bytes[..total].to_vec(),
            )
        }

        // ----- indirect loads -----
        0x46 => simple("ldind.i1", InstrFlags::READ_MEM, op),
        0x47 => simple("ldind.u1", InstrFlags::READ_MEM, op),
        0x48 => simple("ldind.i2", InstrFlags::READ_MEM, op),
        0x49 => simple("ldind.u2", InstrFlags::READ_MEM, op),
        0x4a => simple("ldind.i4", InstrFlags::READ_MEM, op),
        0x4b => simple("ldind.u4", InstrFlags::READ_MEM, op),
        0x4c => simple("ldind.i8", InstrFlags::READ_MEM, op),
        0x4d => simple("ldind.i", InstrFlags::READ_MEM, op),
        0x4e => simple("ldind.r4", InstrFlags::READ_MEM, op),
        0x4f => simple("ldind.r8", InstrFlags::READ_MEM, op),
        0x50 => simple("ldind.ref", InstrFlags::READ_MEM, op),

        // ----- indirect stores -----
        0x51 => simple("stind.ref", InstrFlags::WRITE_MEM, op),
        0x52 => simple("stind.i1", InstrFlags::WRITE_MEM, op),
        0x53 => simple("stind.i2", InstrFlags::WRITE_MEM, op),
        0x54 => simple("stind.i4", InstrFlags::WRITE_MEM, op),
        0x55 => simple("stind.i8", InstrFlags::WRITE_MEM, op),
        0x56 => simple("stind.r4", InstrFlags::WRITE_MEM, op),
        0x57 => simple("stind.r8", InstrFlags::WRITE_MEM, op),

        // ----- arithmetic / logic -----
        0x58 => simple("add", InstrFlags::NONE, op),
        0x59 => simple("sub", InstrFlags::NONE, op),
        0x5a => simple("mul", InstrFlags::NONE, op),
        0x5b => simple("div", InstrFlags::NONE, op),
        0x5c => simple("div.un", InstrFlags::NONE, op),
        0x5d => simple("rem", InstrFlags::NONE, op),
        0x5e => simple("rem.un", InstrFlags::NONE, op),
        0x5f => simple("and", InstrFlags::NONE, op),
        0x60 => simple("or", InstrFlags::NONE, op),
        0x61 => simple("xor", InstrFlags::NONE, op),
        0x62 => simple("shl", InstrFlags::NONE, op),
        0x63 => simple("shr", InstrFlags::NONE, op),
        0x64 => simple("shr.un", InstrFlags::NONE, op),
        0x65 => simple("neg", InstrFlags::NONE, op),
        0x66 => simple("not", InstrFlags::NONE, op),

        // ----- conversions -----
        0x67 => simple("conv.i1", InstrFlags::NONE, op),
        0x68 => simple("conv.i2", InstrFlags::NONE, op),
        0x69 => simple("conv.i4", InstrFlags::NONE, op),
        0x6a => simple("conv.i8", InstrFlags::NONE, op),
        0x6b => simple("conv.r4", InstrFlags::NONE, op),
        0x6c => simple("conv.r8", InstrFlags::NONE, op),
        0x6d => simple("conv.u4", InstrFlags::NONE, op),
        0x6e => simple("conv.u8", InstrFlags::NONE, op),

        // ----- object model -----
        0x6f => {
            need(bytes, 5)?;
            with_ops(
                "callvirt",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::CALL | InstrFlags::INDIRECT,
                bytes[..5].to_vec(),
            )
        }
        0x70 => {
            need(bytes, 5)?;
            with_ops(
                "cpobj",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..5].to_vec(),
            )
        }
        0x71 => {
            need(bytes, 5)?;
            with_ops(
                "ldobj",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::READ_MEM,
                bytes[..5].to_vec(),
            )
        }
        0x72 => {
            need(bytes, 5)?;
            with_ops(
                "ldstr",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..5].to_vec(),
            )
        }
        0x73 => {
            need(bytes, 5)?;
            with_ops(
                "newobj",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::CALL,
                bytes[..5].to_vec(),
            )
        }
        0x74 => {
            need(bytes, 5)?;
            with_ops(
                "castclass",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..5].to_vec(),
            )
        }
        0x75 => {
            need(bytes, 5)?;
            with_ops(
                "isinst",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..5].to_vec(),
            )
        }
        0x76 => simple("conv.r.un", InstrFlags::NONE, op),
        0x79 => {
            need(bytes, 5)?;
            with_ops(
                "unbox",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..5].to_vec(),
            )
        }
        0x7a => simple("throw", InstrFlags::BRANCH, op),

        // ----- field access -----
        0x7b => {
            need(bytes, 5)?;
            with_ops(
                "ldfld",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::READ_MEM,
                bytes[..5].to_vec(),
            )
        }
        0x7c => {
            need(bytes, 5)?;
            with_ops(
                "ldflda",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..5].to_vec(),
            )
        }
        0x7d => {
            need(bytes, 5)?;
            with_ops(
                "stfld",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::WRITE_MEM,
                bytes[..5].to_vec(),
            )
        }
        0x7e => {
            need(bytes, 5)?;
            with_ops(
                "ldsfld",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::READ_MEM,
                bytes[..5].to_vec(),
            )
        }
        0x7f => {
            need(bytes, 5)?;
            with_ops(
                "ldsflda",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..5].to_vec(),
            )
        }
        0x80 => {
            need(bytes, 5)?;
            with_ops(
                "stsfld",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::WRITE_MEM,
                bytes[..5].to_vec(),
            )
        }
        0x81 => {
            need(bytes, 5)?;
            with_ops(
                "stobj",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::WRITE_MEM,
                bytes[..5].to_vec(),
            )
        }

        // ----- overflow conversions -----
        0x82 => simple("conv.ovf.i1.un", InstrFlags::NONE, op),
        0x83 => simple("conv.ovf.i2.un", InstrFlags::NONE, op),
        0x84 => simple("conv.ovf.i4.un", InstrFlags::NONE, op),
        0x85 => simple("conv.ovf.i8.un", InstrFlags::NONE, op),
        0x86 => simple("conv.ovf.u1.un", InstrFlags::NONE, op),
        0x87 => simple("conv.ovf.u2.un", InstrFlags::NONE, op),
        0x88 => simple("conv.ovf.u4.un", InstrFlags::NONE, op),
        0x89 => simple("conv.ovf.u8.un", InstrFlags::NONE, op),
        0x8a => simple("conv.ovf.i.un", InstrFlags::NONE, op),
        0x8b => simple("conv.ovf.u.un", InstrFlags::NONE, op),

        // ----- box / newarr / ... -----
        0x8c => {
            need(bytes, 5)?;
            with_ops(
                "box",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..5].to_vec(),
            )
        }
        0x8d => {
            need(bytes, 5)?;
            with_ops(
                "newarr",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..5].to_vec(),
            )
        }
        0x8e => simple("ldlen", InstrFlags::NONE, op),
        0x8f => {
            need(bytes, 5)?;
            with_ops(
                "ldelema",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..5].to_vec(),
            )
        }

        // ----- ldelem -----
        0x90 => simple("ldelem.i1", InstrFlags::READ_MEM, op),
        0x91 => simple("ldelem.u1", InstrFlags::READ_MEM, op),
        0x92 => simple("ldelem.i2", InstrFlags::READ_MEM, op),
        0x93 => simple("ldelem.u2", InstrFlags::READ_MEM, op),
        0x94 => simple("ldelem.i4", InstrFlags::READ_MEM, op),
        0x95 => simple("ldelem.u4", InstrFlags::READ_MEM, op),
        0x96 => simple("ldelem.i8", InstrFlags::READ_MEM, op),
        0x97 => simple("ldelem.i", InstrFlags::READ_MEM, op),
        0x98 => simple("ldelem.r4", InstrFlags::READ_MEM, op),
        0x99 => simple("ldelem.r8", InstrFlags::READ_MEM, op),
        0x9a => simple("ldelem.ref", InstrFlags::READ_MEM, op),

        // ----- stelem -----
        0x9b => simple("stelem.i", InstrFlags::WRITE_MEM, op),
        0x9c => simple("stelem.i1", InstrFlags::WRITE_MEM, op),
        0x9d => simple("stelem.i2", InstrFlags::WRITE_MEM, op),
        0x9e => simple("stelem.i4", InstrFlags::WRITE_MEM, op),
        0x9f => simple("stelem.i8", InstrFlags::WRITE_MEM, op),
        0xa0 => simple("stelem.r4", InstrFlags::WRITE_MEM, op),
        0xa1 => simple("stelem.r8", InstrFlags::WRITE_MEM, op),
        0xa2 => simple("stelem.ref", InstrFlags::WRITE_MEM, op),

        // ldelem / stelem typed
        0xa3 => {
            need(bytes, 5)?;
            with_ops(
                "ldelem",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::READ_MEM,
                bytes[..5].to_vec(),
            )
        }
        0xa4 => {
            need(bytes, 5)?;
            with_ops(
                "stelem",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::WRITE_MEM,
                bytes[..5].to_vec(),
            )
        }

        // unbox.any
        0xa5 => {
            need(bytes, 5)?;
            with_ops(
                "unbox.any",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..5].to_vec(),
            )
        }

        // ----- more conversions -----
        0xb3 => simple("conv.ovf.i1", InstrFlags::NONE, op),
        0xb4 => simple("conv.ovf.u1", InstrFlags::NONE, op),
        0xb5 => simple("conv.ovf.i2", InstrFlags::NONE, op),
        0xb6 => simple("conv.ovf.u2", InstrFlags::NONE, op),
        0xb7 => simple("conv.ovf.i4", InstrFlags::NONE, op),
        0xb8 => simple("conv.ovf.u4", InstrFlags::NONE, op),
        0xb9 => simple("conv.ovf.i8", InstrFlags::NONE, op),
        0xba => simple("conv.ovf.u8", InstrFlags::NONE, op),

        // refanyval
        0xc2 => {
            need(bytes, 5)?;
            with_ops(
                "refanyval",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..5].to_vec(),
            )
        }
        0xc3 => simple("ckfinite", InstrFlags::NONE, op),

        // mkrefany
        0xc6 => {
            need(bytes, 5)?;
            with_ops(
                "mkrefany",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..5].to_vec(),
            )
        }

        // ldtoken
        0xd0 => {
            need(bytes, 5)?;
            with_ops(
                "ldtoken",
                format!("#{:#010x}", u32le(bytes, 1)),
                InstrFlags::NONE,
                bytes[..5].to_vec(),
            )
        }

        // ----- more conversions -----
        0xd1 => simple("conv.u2", InstrFlags::NONE, op),
        0xd2 => simple("conv.u1", InstrFlags::NONE, op),
        0xd3 => simple("conv.i", InstrFlags::NONE, op),
        0xd4 => simple("conv.ovf.i", InstrFlags::NONE, op),
        0xd5 => simple("conv.ovf.u", InstrFlags::NONE, op),

        // ----- overflow arithmetic -----
        0xd6 => simple("add.ovf", InstrFlags::NONE, op),
        0xd7 => simple("add.ovf.un", InstrFlags::NONE, op),
        0xd8 => simple("mul.ovf", InstrFlags::NONE, op),
        0xd9 => simple("mul.ovf.un", InstrFlags::NONE, op),
        0xda => simple("sub.ovf", InstrFlags::NONE, op),
        0xdb => simple("sub.ovf.un", InstrFlags::NONE, op),

        // endfinally / leave / leave.s / stind.i
        0xdc => simple("endfinally", InstrFlags::RET, op),
        0xdd => {
            need(bytes, 5)?;
            with_ops(
                "leave",
                format!("{:+}", i32le(bytes, 1)),
                InstrFlags::BRANCH,
                bytes[..5].to_vec(),
            )
        }
        0xde => {
            need(bytes, 2)?;
            with_ops(
                "leave.s",
                format!("{:+}", i8b(bytes, 1)),
                InstrFlags::BRANCH,
                bytes[..2].to_vec(),
            )
        }
        0xdf => simple("stind.i", InstrFlags::WRITE_MEM, op),

        // ----- remaining conversions -----
        0xe0 => simple("conv.u", InstrFlags::NONE, op),

        // ----- 0xFE prefix opcodes -----
        0xfe => {
            need(bytes, 2)?;
            let op2 = bytes[1];
            match op2 {
                0x00 => prefixed("arglist", InstrFlags::NONE, op2),
                0x01 => prefixed("ceq", InstrFlags::NONE, op2),
                0x02 => prefixed("cgt", InstrFlags::NONE, op2),
                0x03 => prefixed("cgt.un", InstrFlags::NONE, op2),
                0x04 => prefixed("clt", InstrFlags::NONE, op2),
                0x05 => prefixed("clt.un", InstrFlags::NONE, op2),
                0x06 => {
                    need(bytes, 6)?;
                    prefixed_ops(
                        "ldftn",
                        format!("#{:#010x}", u32le(bytes, 2)),
                        InstrFlags::NONE,
                        vec![0xfe, op2, bytes[2], bytes[3], bytes[4], bytes[5]],
                    )
                }
                0x07 => {
                    need(bytes, 6)?;
                    prefixed_ops(
                        "ldvirtftn",
                        format!("#{:#010x}", u32le(bytes, 2)),
                        InstrFlags::INDIRECT,
                        vec![0xfe, op2, bytes[2], bytes[3], bytes[4], bytes[5]],
                    )
                }
                0x09 => {
                    need(bytes, 4)?;
                    prefixed_ops(
                        "ldarg",
                        format!("{}", u16le(bytes, 2)),
                        InstrFlags::NONE,
                        vec![0xfe, op2, bytes[2], bytes[3]],
                    )
                }
                0x0a => {
                    need(bytes, 4)?;
                    prefixed_ops(
                        "ldarga",
                        format!("{}", u16le(bytes, 2)),
                        InstrFlags::NONE,
                        vec![0xfe, op2, bytes[2], bytes[3]],
                    )
                }
                0x0b => {
                    need(bytes, 4)?;
                    prefixed_ops(
                        "starg",
                        format!("{}", u16le(bytes, 2)),
                        InstrFlags::NONE,
                        vec![0xfe, op2, bytes[2], bytes[3]],
                    )
                }
                0x0c => {
                    need(bytes, 4)?;
                    prefixed_ops(
                        "ldloc",
                        format!("{}", u16le(bytes, 2)),
                        InstrFlags::NONE,
                        vec![0xfe, op2, bytes[2], bytes[3]],
                    )
                }
                0x0d => {
                    need(bytes, 4)?;
                    prefixed_ops(
                        "ldloca",
                        format!("{}", u16le(bytes, 2)),
                        InstrFlags::NONE,
                        vec![0xfe, op2, bytes[2], bytes[3]],
                    )
                }
                0x0e => {
                    need(bytes, 4)?;
                    prefixed_ops(
                        "stloc",
                        format!("{}", u16le(bytes, 2)),
                        InstrFlags::NONE,
                        vec![0xfe, op2, bytes[2], bytes[3]],
                    )
                }
                0x0f => prefixed("localloc", InstrFlags::NONE, op2),
                0x11 => prefixed("endfilter", InstrFlags::RET, op2),
                0x12 => {
                    need(bytes, 3)?;
                    prefixed_ops(
                        "unaligned",
                        format!("{}", bytes[2]),
                        InstrFlags::NONE,
                        vec![0xfe, op2, bytes[2]],
                    )
                }
                0x13 => prefixed("volatile", InstrFlags::BARRIER, op2),
                0x14 => prefixed("tail", InstrFlags::NONE, op2),
                0x15 => {
                    need(bytes, 6)?;
                    prefixed_ops(
                        "initobj",
                        format!("#{:#010x}", u32le(bytes, 2)),
                        InstrFlags::NONE,
                        vec![0xfe, op2, bytes[2], bytes[3], bytes[4], bytes[5]],
                    )
                }
                0x16 => {
                    need(bytes, 6)?;
                    prefixed_ops(
                        "constrained",
                        format!("#{:#010x}", u32le(bytes, 2)),
                        InstrFlags::NONE,
                        vec![0xfe, op2, bytes[2], bytes[3], bytes[4], bytes[5]],
                    )
                }
                0x17 => prefixed("cpblk", InstrFlags::WRITE_MEM, op2),
                0x18 => prefixed("initblk", InstrFlags::WRITE_MEM, op2),
                0x19 => {
                    need(bytes, 3)?;
                    prefixed_ops(
                        "no",
                        format!("{}", bytes[2]),
                        InstrFlags::NONE,
                        vec![0xfe, op2, bytes[2]],
                    )
                }
                0x1a => prefixed("rethrow", InstrFlags::BRANCH, op2),
                0x1c => {
                    need(bytes, 6)?;
                    prefixed_ops(
                        "sizeof",
                        format!("#{:#010x}", u32le(bytes, 2)),
                        InstrFlags::NONE,
                        vec![0xfe, op2, bytes[2], bytes[3], bytes[4], bytes[5]],
                    )
                }
                0x1d => prefixed("refanytype", InstrFlags::NONE, op2),
                0x1e => prefixed("readonly", InstrFlags::NONE, op2),
                _ => Err(CilDecodeError::UnknownPrefixedOpcode(op2)),
            }
        }

        _ => Err(CilDecodeError::UnknownOpcode(op)),
    }
}

// ---------------------------------------------------------------------------
// CilArch
// ---------------------------------------------------------------------------

/// Architecture implementation for .NET CIL / MSIL bytecode.
#[derive(Debug, Clone)]
pub struct CilArch {
    /// Pointer size in bits: 32 or 64.
    pub bitness: u32,
}

impl CilArch {
    /// Create a 64-bit CIL architecture instance.
    #[must_use]
    pub const fn new_64() -> Self {
        Self { bitness: 64 }
    }

    /// Create a 32-bit CIL architecture instance.
    #[must_use]
    pub const fn new_32() -> Self {
        Self { bitness: 32 }
    }
}

impl Default for CilArch {
    fn default() -> Self {
        Self::new_64()
    }
}

/// Construct a [`BranchInfo`] for a CIL branch/call instruction at `target`.
const fn make_branch(instr: &Instruction, target: u64) -> BranchInfo {
    if instr.flags.contains(InstrFlags::CALL) {
        BranchInfo::call(target)
    } else if instr.flags.contains(InstrFlags::CONDITIONAL) {
        BranchInfo::conditional_jump(target, BranchCondition::Custom(0))
    } else {
        BranchInfo::unconditional_jump(target)
    }
}

impl Architecture for CilArch {
    fn name(&self) -> &str {
        match self.bitness {
            64 => "cil64",
            _ => "cil32",
        }
    }

    fn pointer_size(&self) -> usize {
        (self.bitness / 8) as usize
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        let (instr, consumed) = CilInstr::decode(bytes).map_err(|e| CoreError::PluginError {
            plugin: "cil".into(),
            message: e.to_string(),
        })?;

        let mut out = Instruction::new(address, consumed, instr.mnemonic, instr.raw);
        out.operands = instr.operands;
        out.flags = instr.flags;
        Ok(out)
    }

    fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo> {
        if !instr
            .flags
            .intersects(InstrFlags::BRANCH | InstrFlags::CALL)
        {
            return vec![];
        }
        // Short branch: 2-byte instruction, 1-byte signed offset after opcode.
        if instr.bytes.len() == 2 {
            let off = i8::from_ne_bytes([instr.bytes[1]]);
            let next = instr.address + instr.size as u64;
            let target = next.as_u64().wrapping_add_signed(i64::from(off));
            return vec![make_branch(instr, target)];
        }
        // Long branch / call: 5-byte instruction, 4-byte signed offset after opcode.
        if instr.bytes.len() == 5 && instr.flags.contains(InstrFlags::BRANCH) {
            let off = i32::from_le_bytes([
                instr.bytes[1],
                instr.bytes[2],
                instr.bytes[3],
                instr.bytes[4],
            ]);
            let next = instr.address + instr.size as u64;
            let target = next.as_u64().wrapping_add_signed(i64::from(off));
            return vec![make_branch(instr, target)];
        }
        vec![]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        // CIL is a stack machine; expose evaluation stack and a few arg slots.
        vec![
            RegisterInfo::new("arg0", 0, self.pointer_size(), RegisterKind::General),
            RegisterInfo::new("arg1", 1, self.pointer_size(), RegisterKind::General),
            RegisterInfo::new("arg2", 2, self.pointer_size(), RegisterKind::General),
            RegisterInfo::new("arg3", 3, self.pointer_size(), RegisterKind::General),
        ]
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        let mut cc = CallingConvention::new("cil_managed")
            .with_int_args(vec![])
            .with_return_regs(vec![]);
        cc.caller_cleans_stack = false;
        vec![cc]
    }
}

// ---------------------------------------------------------------------------
// Linear disassembler
// ---------------------------------------------------------------------------

/// Iterator that decodes CIL method body bytes linearly.
pub struct CilLinearDisassembler<'a> {
    arch: &'a CilArch,
    bytes: &'a [u8],
    address: Address,
    offset: usize,
}

impl<'a> CilLinearDisassembler<'a> {
    /// Construct a new disassembler.
    #[must_use]
    pub const fn new(arch: &'a CilArch, bytes: &'a [u8], base_address: Address) -> Self {
        Self {
            arch,
            bytes,
            address: base_address,
            offset: 0,
        }
    }
}

impl Iterator for CilLinearDisassembler<'_> {
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::arch::BranchKind;

    fn arch64() -> CilArch {
        CilArch::new_64()
    }
    fn addr(n: u64) -> Address {
        Address::new(n)
    }

    // --- decode basics ---

    #[test]
    fn test_nop() {
        let (i, sz) = CilInstr::decode(&[0x00]).unwrap();
        assert_eq!(sz, 1);
        assert_eq!(i.mnemonic, "nop");
    }

    #[test]
    fn test_break_barrier() {
        let (i, _) = CilInstr::decode(&[0x01]).unwrap();
        assert_eq!(i.mnemonic, "break");
        assert!(i.flags.contains(InstrFlags::BARRIER));
    }

    #[test]
    fn test_ldarg_0_through_3() {
        for (op, expected) in [
            (0x02_u8, "ldarg.0"),
            (0x03, "ldarg.1"),
            (0x04, "ldarg.2"),
            (0x05, "ldarg.3"),
        ] {
            let (i, sz) = CilInstr::decode(&[op]).unwrap();
            assert_eq!(sz, 1);
            assert_eq!(i.mnemonic, expected);
        }
    }

    #[test]
    fn test_ldloc_0_through_3() {
        for op in [0x06_u8, 0x07, 0x08, 0x09] {
            let (i, _) = CilInstr::decode(&[op]).unwrap();
            assert!(i.mnemonic.starts_with("ldloc."));
        }
    }

    #[test]
    fn test_ldarg_s() {
        let (i, sz) = CilInstr::decode(&[0x0e, 0x05]).unwrap();
        assert_eq!(sz, 2);
        assert_eq!(i.mnemonic, "ldarg.s");
        assert!(i.operands.contains('5'));
    }

    #[test]
    fn test_ldnull() {
        let (i, _) = CilInstr::decode(&[0x14]).unwrap();
        assert_eq!(i.mnemonic, "ldnull");
    }

    #[test]
    fn test_ldc_i4_m1() {
        let (i, sz) = CilInstr::decode(&[0x15]).unwrap();
        assert_eq!(sz, 1);
        assert_eq!(i.mnemonic, "ldc.i4.m1");
    }

    #[test]
    fn test_ldc_i4_0_through_8() {
        for (n, op) in (0..=8u8).map(|n| (n, 0x16 + n)) {
            let (i, _) = CilInstr::decode(&[op]).unwrap();
            assert_eq!(i.mnemonic, format!("ldc.i4.{n}"));
        }
    }

    #[test]
    fn test_ldc_i4_s() {
        let (i, sz) = CilInstr::decode(&[0x1f, 0xff]).unwrap();
        assert_eq!(sz, 2);
        assert_eq!(i.mnemonic, "ldc.i4.s");
        assert!(i.operands.contains("-1"));
    }

    #[test]
    fn test_ldc_i4() {
        let mut buf = vec![0x20u8];
        buf.extend_from_slice(&42_i32.to_le_bytes());
        let (i, sz) = CilInstr::decode(&buf).unwrap();
        assert_eq!(sz, 5);
        assert_eq!(i.mnemonic, "ldc.i4");
        assert!(i.operands.contains("42"));
    }

    #[test]
    fn test_ldc_i8() {
        let mut buf = vec![0x21u8];
        buf.extend_from_slice(&(-1_i64).to_le_bytes());
        let (i, sz) = CilInstr::decode(&buf).unwrap();
        assert_eq!(sz, 9);
        assert_eq!(i.mnemonic, "ldc.i8");
    }

    #[test]
    fn test_dup() {
        let (i, _) = CilInstr::decode(&[0x25]).unwrap();
        assert_eq!(i.mnemonic, "dup");
    }

    #[test]
    fn test_ret() {
        let (i, sz) = CilInstr::decode(&[0x2a]).unwrap();
        assert_eq!(sz, 1);
        assert_eq!(i.mnemonic, "ret");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_br_s() {
        let (i, sz) = CilInstr::decode(&[0x2b, 0x05]).unwrap();
        assert_eq!(sz, 2);
        assert_eq!(i.mnemonic, "br.s");
        assert!(i.flags.contains(InstrFlags::BRANCH));
        assert!(!i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_brfalse_s_conditional() {
        let (i, _) = CilInstr::decode(&[0x2c, 0x00]).unwrap();
        assert_eq!(i.mnemonic, "brfalse.s");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_beq_long() {
        let mut buf = vec![0x3b_u8];
        buf.extend_from_slice(&100_i32.to_le_bytes());
        let (i, sz) = CilInstr::decode(&buf).unwrap();
        assert_eq!(sz, 5);
        assert_eq!(i.mnemonic, "beq");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_switch() {
        let n: u32 = 3;
        let mut buf = vec![0x45u8];
        buf.extend_from_slice(&n.to_le_bytes());
        buf.extend_from_slice(&0_i32.to_le_bytes());
        buf.extend_from_slice(&4_i32.to_le_bytes());
        buf.extend_from_slice(&8_i32.to_le_bytes());
        let (i, sz) = CilInstr::decode(&buf).unwrap();
        assert_eq!(sz, 5 + 3 * 4);
        assert_eq!(i.mnemonic, "switch");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_ldind_i1_read_mem() {
        let (i, sz) = CilInstr::decode(&[0x46]).unwrap();
        assert_eq!(sz, 1);
        assert_eq!(i.mnemonic, "ldind.i1");
        assert!(i.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_stind_i4_write_mem() {
        let (i, _) = CilInstr::decode(&[0x54]).unwrap();
        assert_eq!(i.mnemonic, "stind.i4");
        assert!(i.flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_add() {
        let (i, sz) = CilInstr::decode(&[0x58]).unwrap();
        assert_eq!(sz, 1);
        assert_eq!(i.mnemonic, "add");
    }

    #[test]
    fn test_throw_branch() {
        let (i, _) = CilInstr::decode(&[0x7a]).unwrap();
        assert_eq!(i.mnemonic, "throw");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_call_5_bytes() {
        let mut buf = vec![0x28u8];
        buf.extend_from_slice(&0x06000001_u32.to_le_bytes());
        let (i, sz) = CilInstr::decode(&buf).unwrap();
        assert_eq!(sz, 5);
        assert_eq!(i.mnemonic, "call");
        assert!(i.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_callvirt_indirect() {
        let mut buf = vec![0x6f_u8];
        buf.extend_from_slice(&0x0a000002_u32.to_le_bytes());
        let (i, _) = CilInstr::decode(&buf).unwrap();
        assert_eq!(i.mnemonic, "callvirt");
        assert!(i.flags.contains(InstrFlags::INDIRECT));
    }

    #[test]
    fn test_ldfld_read_mem() {
        let mut buf = vec![0x7b_u8];
        buf.extend_from_slice(&1_u32.to_le_bytes());
        let (i, _) = CilInstr::decode(&buf).unwrap();
        assert_eq!(i.mnemonic, "ldfld");
        assert!(i.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_endfinally() {
        let (i, sz) = CilInstr::decode(&[0xdc]).unwrap();
        assert_eq!(sz, 1);
        assert_eq!(i.mnemonic, "endfinally");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    // --- 0xFE prefix opcodes ---

    #[test]
    fn test_ceq() {
        let (i, sz) = CilInstr::decode(&[0xfe, 0x01]).unwrap();
        assert_eq!(sz, 2);
        assert_eq!(i.mnemonic, "ceq");
    }

    #[test]
    fn test_cgt() {
        let (i, sz) = CilInstr::decode(&[0xfe, 0x02]).unwrap();
        assert_eq!(sz, 2);
        assert_eq!(i.mnemonic, "cgt");
    }

    #[test]
    fn test_clt_un() {
        let (i, sz) = CilInstr::decode(&[0xfe, 0x05]).unwrap();
        assert_eq!(sz, 2);
        assert_eq!(i.mnemonic, "clt.un");
    }

    #[test]
    fn test_ldftn() {
        let mut buf = vec![0xfe_u8, 0x06];
        buf.extend_from_slice(&0x06000003_u32.to_le_bytes());
        let (i, sz) = CilInstr::decode(&buf).unwrap();
        assert_eq!(sz, 6);
        assert_eq!(i.mnemonic, "ldftn");
    }

    #[test]
    fn test_initobj() {
        let mut buf = vec![0xfe_u8, 0x15];
        buf.extend_from_slice(&0x01000001_u32.to_le_bytes());
        let (i, sz) = CilInstr::decode(&buf).unwrap();
        assert_eq!(sz, 6);
        assert_eq!(i.mnemonic, "initobj");
    }

    #[test]
    fn test_sizeof() {
        let mut buf = vec![0xfe_u8, 0x1c];
        buf.extend_from_slice(&0x01000002_u32.to_le_bytes());
        let (i, sz) = CilInstr::decode(&buf).unwrap();
        assert_eq!(sz, 6);
        assert_eq!(i.mnemonic, "sizeof");
    }

    #[test]
    fn test_rethrow() {
        let (i, sz) = CilInstr::decode(&[0xfe, 0x1a]).unwrap();
        assert_eq!(sz, 2);
        assert_eq!(i.mnemonic, "rethrow");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_volatile_barrier() {
        let (i, _) = CilInstr::decode(&[0xfe, 0x13]).unwrap();
        assert_eq!(i.mnemonic, "volatile");
        assert!(i.flags.contains(InstrFlags::BARRIER));
    }

    #[test]
    fn test_unknown_opcode() {
        assert!(matches!(
            CilInstr::decode(&[0x24]),
            Err(CilDecodeError::UnknownOpcode(0x24))
        ));
    }

    #[test]
    fn test_truncated() {
        assert!(matches!(
            CilInstr::decode(&[]),
            Err(CilDecodeError::Truncated)
        ));
    }

    #[test]
    fn test_truncated_long_branch() {
        assert!(matches!(
            CilInstr::decode(&[0x38, 0x00]),
            Err(CilDecodeError::Truncated)
        ));
    }

    // --- Architecture trait ---

    #[test]
    fn test_arch_name_64() {
        assert_eq!(arch64().name(), "cil64");
    }

    #[test]
    fn test_arch_name_32() {
        assert_eq!(CilArch::new_32().name(), "cil32");
    }

    #[test]
    fn test_arch_pointer_size_64() {
        assert_eq!(arch64().pointer_size(), 8);
    }

    #[test]
    fn test_arch_pointer_size_32() {
        assert_eq!(CilArch::new_32().pointer_size(), 4);
    }

    #[test]
    fn test_arch_endian_little() {
        assert_eq!(arch64().endian(), Endian::Little);
    }

    #[test]
    fn test_arch_disassemble_nop() {
        let instr = arch64().disassemble(addr(0), &[0x00]).unwrap();
        assert_eq!(instr.mnemonic, "nop");
        assert_eq!(instr.size, 1);
    }

    #[test]
    fn test_arch_disassemble_ret() {
        let instr = arch64().disassemble(addr(0x1000), &[0x2a]).unwrap();
        assert_eq!(instr.mnemonic, "ret");
        assert!(instr.flags.contains(InstrFlags::RET));
        assert_eq!(instr.address, addr(0x1000));
    }

    #[test]
    fn test_arch_registers() {
        let regs = arch64().registers();
        assert!(!regs.is_empty());
        assert!(regs.iter().any(|r| r.name == "arg0"));
    }

    #[test]
    fn test_arch_calling_convention() {
        let cc = arch64().calling_conventions();
        assert_eq!(cc[0].name, "cil_managed");
    }

    // --- get_branches ---

    #[test]
    fn test_get_branches_br_s() {
        let arch = arch64();
        let instr = arch.disassemble(addr(0x100), &[0x2b, 0x04]).unwrap();
        let branches = arch.get_branches(&instr);
        assert_eq!(branches.len(), 1);
        // next = 0x100 + 2 = 0x102, target = 0x102 + 4 = 0x106
        assert_eq!(branches[0].target, Some(0x106));
        assert!(branches[0].kind != BranchKind::ConditionalJump);
    }

    #[test]
    fn test_get_branches_ret() {
        let arch = arch64();
        let instr = arch.disassemble(addr(0), &[0x2a]).unwrap();
        assert!(arch.get_branches(&instr).is_empty());
    }

    // --- Linear disassembler ---

    #[test]
    fn test_linear_disassembler_simple() {
        let arch = arch64();
        // ldarg.0  ldc.i4.1  add  ret
        let prog = [0x02_u8, 0x17, 0x58, 0x2a];
        let instrs: Vec<_> = CilLinearDisassembler::new(&arch, &prog, addr(0))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs.len(), 4);
        assert_eq!(instrs[0].mnemonic, "ldarg.0");
        assert_eq!(instrs[1].mnemonic, "ldc.i4.1");
        assert_eq!(instrs[2].mnemonic, "add");
        assert_eq!(instrs[3].mnemonic, "ret");
    }

    #[test]
    fn test_linear_disassembler_addresses() {
        let arch = arch64();
        let prog = [0x02_u8, 0x17, 0x2a]; // each 1 byte
        let instrs: Vec<_> = CilLinearDisassembler::new(&arch, &prog, addr(0x200))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs[0].address, addr(0x200));
        assert_eq!(instrs[1].address, addr(0x201));
        assert_eq!(instrs[2].address, addr(0x202));
    }

    #[test]
    fn test_linear_disassembler_empty() {
        let arch = arch64();
        assert_eq!(CilLinearDisassembler::new(&arch, &[], addr(0)).count(), 0);
    }

    #[test]
    fn test_add_ovf() {
        let (i, sz) = CilInstr::decode(&[0xd6]).unwrap();
        assert_eq!(sz, 1);
        assert_eq!(i.mnemonic, "add.ovf");
    }

    #[test]
    fn test_stelem_i4_write_mem() {
        let (i, _) = CilInstr::decode(&[0x9e]).unwrap();
        assert_eq!(i.mnemonic, "stelem.i4");
        assert!(i.flags.contains(InstrFlags::WRITE_MEM));
    }
}

// ---------------------------------------------------------------------------
// CIL metadata token types (ECMA-335 §II.24.2.6)
// ---------------------------------------------------------------------------

/// Metadata token type (top byte of a 4-byte metadata token).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MetadataTokenType {
    /// `0x01` — `TypeRef` table.
    TypeRef = 0x01,
    /// `0x02` — `TypeDef` table.
    TypeDef = 0x02,
    /// `0x04` — Field table.
    Field = 0x04,
    /// `0x06` — `MethodDef` table.
    MethodDef = 0x06,
    /// `0x08` — Param table.
    Param = 0x08,
    /// `0x0a` — `MemberRef` table.
    MemberRef = 0x0a,
    /// `0x0b` — Constant table.
    Constant = 0x0b,
    /// `0x11` — `StandAloneSig` table.
    StandAloneSig = 0x11,
    /// `0x1b` — `TypeSpec` table.
    TypeSpec = 0x1b,
    /// `0x2b` — `MethodSpec` table.
    MethodSpec = 0x2b,
    /// `0x70` — String heap (user string).
    UserString = 0x70,
}

impl MetadataTokenType {
    /// Decode the token type from the high byte of a metadata token.
    #[must_use]
    pub const fn from_token(token: u32) -> Option<Self> {
        match (token >> 24) as u8 {
            0x01 => Some(Self::TypeRef),
            0x02 => Some(Self::TypeDef),
            0x04 => Some(Self::Field),
            0x06 => Some(Self::MethodDef),
            0x08 => Some(Self::Param),
            0x0a => Some(Self::MemberRef),
            0x0b => Some(Self::Constant),
            0x11 => Some(Self::StandAloneSig),
            0x1b => Some(Self::TypeSpec),
            0x2b => Some(Self::MethodSpec),
            0x70 => Some(Self::UserString),
            _ => None,
        }
    }

    /// Extract the row index (RID) from a metadata token.
    #[must_use]
    pub const fn rid(token: u32) -> u32 {
        token & 0x00FF_FFFF
    }

    /// Return the table name for this token type.
    #[must_use]
    pub const fn table_name(self) -> &'static str {
        match self {
            Self::TypeRef => "TypeRef",
            Self::TypeDef => "TypeDef",
            Self::Field => "Field",
            Self::MethodDef => "MethodDef",
            Self::Param => "Param",
            Self::MemberRef => "MemberRef",
            Self::Constant => "Constant",
            Self::StandAloneSig => "StandAloneSig",
            Self::TypeSpec => "TypeSpec",
            Self::MethodSpec => "MethodSpec",
            Self::UserString => "UserString",
        }
    }
}

// ---------------------------------------------------------------------------
// CIL method header (ECMA-335 §II.25.4)
// ---------------------------------------------------------------------------

/// CIL method header variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodHeader {
    /// Tiny header: max-stack=8, no locals, no exception handlers.
    Tiny {
        /// Length of the method body in bytes.
        code_size: u32,
    },
    /// Fat header with all fields.
    Fat {
        /// Combined flags and header size word.
        flags: u16,
        /// Maximum operand stack depth.
        max_stack: u16,
        /// Length of the code in bytes.
        code_size: u32,
        /// `LocalVarSig` token, or 0 if none.
        local_var_sig_tok: u32,
    },
}

impl MethodHeader {
    /// Tiny header flag bit (`0b10`).
    pub const TINY_FLAG: u8 = 0x02;
    /// Fat header flag bit (`0b11`).
    pub const FAT_FLAG: u8 = 0x03;
    /// Fat header flag for `MoreSects` (exception handlers follow).
    pub const MORE_SECTS: u16 = 0x0008;
    /// Fat header flag for `InitLocals` (zero-init local vars).
    pub const INIT_LOCALS: u16 = 0x0010;

    /// Decode a method header from bytes.
    ///
    /// # Errors
    ///
    /// Returns `CilDecodeError::Truncated` when the slice is too short,
    /// or `CilDecodeError::UnknownOpcode` for unrecognized header formats.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), CilDecodeError> {
        if bytes.is_empty() {
            return Err(CilDecodeError::Truncated);
        }
        let first = bytes[0];
        // Tiny header: flags in bits [1:0] == 0b10, code size in bits [7:2]
        if first & 0x03 == Self::TINY_FLAG {
            let code_size = u32::from(first >> 2);
            return Ok((Self::Tiny { code_size }, 1));
        }
        // Fat header: 12 bytes
        if bytes.len() < 12 {
            return Err(CilDecodeError::Truncated);
        }
        let flags = u16::from_le_bytes([bytes[0], bytes[1]]);
        let max_stack = u16::from_le_bytes([bytes[2], bytes[3]]);
        let code_size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let local_var_sig_tok = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        Ok((
            Self::Fat {
                flags,
                max_stack,
                code_size,
                local_var_sig_tok,
            },
            12,
        ))
    }

    /// Return the code body size in bytes.
    #[must_use]
    pub const fn code_size(&self) -> u32 {
        match self {
            Self::Tiny { code_size } | Self::Fat { code_size, .. } => *code_size,
        }
    }

    /// Returns `true` when the method is a tiny-format method.
    #[must_use]
    pub const fn is_tiny(&self) -> bool {
        matches!(self, Self::Tiny { .. })
    }
}

// ---------------------------------------------------------------------------
// CIL exception handler clause types
// ---------------------------------------------------------------------------

/// Exception handler clause type for CIL SEH regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EhClauseKind {
    /// `CLAUSE_EXCEPTION` (0) — typed catch clause.
    Exception = 0,
    /// `CLAUSE_FILTER` (1) — filter with user-written condition.
    Filter = 1,
    /// `CLAUSE_FINALLY` (2) — unconditionally executed finally.
    Finally = 2,
    /// `CLAUSE_FAULT` (4) — executed on any exception, not on normal exit.
    Fault = 4,
}

impl EhClauseKind {
    /// Decode from the `Flags` field of an exception-handling clause.
    ///
    /// # Errors
    ///
    /// Returns `None` for unrecognised flag values.
    #[must_use]
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Exception),
            1 => Some(Self::Filter),
            2 => Some(Self::Finally),
            4 => Some(Self::Fault),
            _ => None,
        }
    }

    /// Return the ECMA name for this clause kind.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Exception => "catch",
            Self::Filter => "filter",
            Self::Finally => "finally",
            Self::Fault => "fault",
        }
    }
}

// ---------------------------------------------------------------------------
// CIL inline operand kind
// ---------------------------------------------------------------------------

/// The kind of inline operand that follows a CIL opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InlineOperand {
    /// No operand.
    None,
    /// 1-byte unsigned variable index.
    Var,
    /// 1-byte signed immediate.
    I,
    /// 1-byte unsigned immediate (short form).
    I8,
    /// 4-byte floating-point (inline R4).
    R,
    /// 4-byte signed integer.
    I32,
    /// 4-byte single-precision float.
    R4,
    /// 8-byte signed integer.
    I64,
    /// 8-byte double-precision float.
    R8,
    /// 4-byte metadata string token.
    String,
    /// 4-byte metadata token (type/field/method/member).
    Tok,
    /// 4-byte type token.
    Type,
    /// 4-byte field token.
    Field,
    /// 4-byte method token.
    Meth,
    /// 4-byte method token for indirect calls.
    MthTok,
    /// Variable-length switch table (n, then n×4-byte offsets).
    Switch,
}

impl InlineOperand {
    /// Fixed byte size of the inline operand, or `None` for variable-length.
    #[must_use]
    pub const fn fixed_size(self) -> Option<usize> {
        Some(match self {
            Self::None => 0,
            Self::Var | Self::I | Self::I8 => 1,
            Self::I32
            | Self::R
            | Self::R4
            | Self::String
            | Self::Tok
            | Self::Type
            | Self::Field
            | Self::Meth
            | Self::MthTok => 4,
            Self::I64 | Self::R8 => 8,
            Self::Switch => return None,
        })
    }
}

// ---------------------------------------------------------------------------
// CIL local variable flags (ECMA-335 §II.23.1.8)
// ---------------------------------------------------------------------------

bitflags::bitflags! {
    /// Flags for a local variable in a `LocalVarSig`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct LocalVarFlags: u8 {
        /// Variable is pinned (managed pointer).
        const PINNED   = 0x45;
        /// Variable is passed/returned by reference.
        const BYREF    = 0x10;
        /// Variable is a typed reference.
        const TYPEDBYREF = 0x16;
    }
}

// ---------------------------------------------------------------------------
// CIL method analysis
// ---------------------------------------------------------------------------

/// Statistics gathered from a CIL method body.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CilMethodStats {
    /// Total instruction count.
    pub instruction_count: usize,
    /// Number of `call`/`callvirt`/`calli` instructions.
    pub call_count: usize,
    /// Number of conditional branches.
    pub conditional_branch_count: usize,
    /// Number of unconditional branches.
    pub unconditional_branch_count: usize,
    /// Number of memory-load instructions.
    pub load_count: usize,
    /// Number of memory-store instructions.
    pub store_count: usize,
    /// Number of return / throw / endfinally instructions.
    pub terminator_count: usize,
    /// Number of barrier (volatile/memory-fence) instructions.
    pub barrier_count: usize,
}

impl CilMethodStats {
    /// Analyse raw CIL bytecode and return statistics.
    ///
    /// # Errors
    ///
    /// Returns `CilDecodeError` on decode failure.
    pub fn from_bytes(code: &[u8]) -> Result<Self, CilDecodeError> {
        let mut s = Self::default();
        let mut off = 0;
        while off < code.len() {
            let (instr, n) = CilInstr::decode(&code[off..])?;
            off += n;
            s.instruction_count += 1;
            if instr.flags.contains(InstrFlags::CALL) {
                s.call_count += 1;
            }
            if instr.flags.contains(InstrFlags::BRANCH) {
                if instr.flags.contains(InstrFlags::CONDITIONAL) {
                    s.conditional_branch_count += 1;
                } else {
                    s.unconditional_branch_count += 1;
                }
            }
            if instr.flags.contains(InstrFlags::RET) {
                s.terminator_count += 1;
            }
            if instr.flags.contains(InstrFlags::BARRIER) {
                s.barrier_count += 1;
            }
            if instr.flags.contains(InstrFlags::READ_MEM) {
                s.load_count += 1;
            }
            if instr.flags.contains(InstrFlags::WRITE_MEM) {
                s.store_count += 1;
            }
        }
        Ok(s)
    }
}

// ---------------------------------------------------------------------------
// CIL opcode reference table
// ---------------------------------------------------------------------------

/// A reference entry for a CIL opcode.
#[derive(Debug, Clone, Copy)]
pub struct CilOpcodeRef {
    /// Opcode byte (single-byte form; `0xFF` means use `prefix_byte`).
    pub byte1: u8,
    /// For `0xFE xx` two-byte opcodes, the second byte. `0xFF` if single-byte.
    pub byte2: u8,
    /// Mnemonic string.
    pub mnemonic: &'static str,
    /// Pop behaviour (number of values popped from eval stack).
    pub pop: i8,
    /// Push behaviour (number of values pushed, -1 = variable).
    pub push: i8,
    /// Inline operand kind.
    pub operand: InlineOperand,
    /// Raw semantic flag bits (use `flags()` for typed access).
    pub flag_bits: u32,
}

impl CilOpcodeRef {
    /// Returns `true` if this is a two-byte (`0xFE xx`) opcode.
    #[must_use]
    pub const fn is_prefixed(self) -> bool {
        self.byte1 == 0xfe
    }

    /// Returns the `InstrFlags` for this entry.
    ///
    /// The table stores `flag_bits` in a compact logical encoding
    /// (BRANCH=1, CALL=2, RET=4, CONDITIONAL=8, INDIRECT=16, `READ_MEM=32`,
    /// `WRITE_MEM=64`, BARRIER=128); this maps that encoding onto the real
    /// [`InstrFlags`] bit layout.
    #[must_use]
    pub fn flags(self) -> InstrFlags {
        let mut flags = InstrFlags::NONE;
        if self.flag_bits & 1 != 0 {
            flags |= InstrFlags::BRANCH;
        }
        if self.flag_bits & 2 != 0 {
            flags |= InstrFlags::CALL;
        }
        if self.flag_bits & 4 != 0 {
            flags |= InstrFlags::RET;
        }
        if self.flag_bits & 8 != 0 {
            flags |= InstrFlags::CONDITIONAL;
        }
        if self.flag_bits & 16 != 0 {
            flags |= InstrFlags::INDIRECT;
        }
        if self.flag_bits & 32 != 0 {
            flags |= InstrFlags::READ_MEM;
        }
        if self.flag_bits & 64 != 0 {
            flags |= InstrFlags::WRITE_MEM;
        }
        if self.flag_bits & 128 != 0 {
            flags |= InstrFlags::BARRIER;
        }
        flags
    }
}

/// Selected CIL opcode reference table (representative subset of ECMA-335 opcodes).
pub static CIL_OPCODE_REF: &[CilOpcodeRef] = &[
    CilOpcodeRef {
        byte1: 0x00,
        byte2: 0xff,
        mnemonic: "nop",
        pop: 0,
        push: 0,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x02,
        byte2: 0xff,
        mnemonic: "ldarg.0",
        pop: 0,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x03,
        byte2: 0xff,
        mnemonic: "ldarg.1",
        pop: 0,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x06,
        byte2: 0xff,
        mnemonic: "ldloc.0",
        pop: 0,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x0a,
        byte2: 0xff,
        mnemonic: "stloc.0",
        pop: 1,
        push: 0,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x14,
        byte2: 0xff,
        mnemonic: "ldnull",
        pop: 0,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x16,
        byte2: 0xff,
        mnemonic: "ldc.i4.0",
        pop: 0,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x1f,
        byte2: 0xff,
        mnemonic: "ldc.i4.s",
        pop: 0,
        push: 1,
        operand: InlineOperand::I8,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x20,
        byte2: 0xff,
        mnemonic: "ldc.i4",
        pop: 0,
        push: 1,
        operand: InlineOperand::I32,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x21,
        byte2: 0xff,
        mnemonic: "ldc.i8",
        pop: 0,
        push: 1,
        operand: InlineOperand::I64,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x22,
        byte2: 0xff,
        mnemonic: "ldc.r4",
        pop: 0,
        push: 1,
        operand: InlineOperand::R4,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x23,
        byte2: 0xff,
        mnemonic: "ldc.r8",
        pop: 0,
        push: 1,
        operand: InlineOperand::R8,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x25,
        byte2: 0xff,
        mnemonic: "dup",
        pop: 1,
        push: 2,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x26,
        byte2: 0xff,
        mnemonic: "pop",
        pop: 1,
        push: 0,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x28,
        byte2: 0xff,
        mnemonic: "call",
        pop: -1,
        push: -1,
        operand: InlineOperand::Meth,
        flag_bits: 2,
    },
    CilOpcodeRef {
        byte1: 0x29,
        byte2: 0xff,
        mnemonic: "calli",
        pop: -1,
        push: -1,
        operand: InlineOperand::MthTok,
        flag_bits: 2 | 16,
    },
    CilOpcodeRef {
        byte1: 0x2a,
        byte2: 0xff,
        mnemonic: "ret",
        pop: -1,
        push: 0,
        operand: InlineOperand::None,
        flag_bits: 4,
    },
    CilOpcodeRef {
        byte1: 0x2b,
        byte2: 0xff,
        mnemonic: "br.s",
        pop: 0,
        push: 0,
        operand: InlineOperand::I,
        flag_bits: 1,
    },
    CilOpcodeRef {
        byte1: 0x2c,
        byte2: 0xff,
        mnemonic: "brfalse.s",
        pop: 1,
        push: 0,
        operand: InlineOperand::I,
        flag_bits: 1 | 8,
    },
    CilOpcodeRef {
        byte1: 0x2d,
        byte2: 0xff,
        mnemonic: "brtrue.s",
        pop: 1,
        push: 0,
        operand: InlineOperand::I,
        flag_bits: 1 | 8,
    },
    CilOpcodeRef {
        byte1: 0x38,
        byte2: 0xff,
        mnemonic: "br",
        pop: 0,
        push: 0,
        operand: InlineOperand::I32,
        flag_bits: 1,
    },
    CilOpcodeRef {
        byte1: 0x3c,
        byte2: 0xff,
        mnemonic: "bne.un",
        pop: 2,
        push: 0,
        operand: InlineOperand::I32,
        flag_bits: 1 | 8,
    },
    CilOpcodeRef {
        byte1: 0x45,
        byte2: 0xff,
        mnemonic: "switch",
        pop: 1,
        push: 0,
        operand: InlineOperand::Switch,
        flag_bits: 1 | 16,
    },
    CilOpcodeRef {
        byte1: 0x46,
        byte2: 0xff,
        mnemonic: "ldind.i1",
        pop: 1,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 32,
    },
    CilOpcodeRef {
        byte1: 0x4a,
        byte2: 0xff,
        mnemonic: "ldind.i4",
        pop: 1,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 32,
    },
    CilOpcodeRef {
        byte1: 0x52,
        byte2: 0xff,
        mnemonic: "stind.i1",
        pop: 2,
        push: 0,
        operand: InlineOperand::None,
        flag_bits: 64,
    },
    CilOpcodeRef {
        byte1: 0x53,
        byte2: 0xff,
        mnemonic: "stind.i2",
        pop: 2,
        push: 0,
        operand: InlineOperand::None,
        flag_bits: 64,
    },
    CilOpcodeRef {
        byte1: 0x54,
        byte2: 0xff,
        mnemonic: "stind.i4",
        pop: 2,
        push: 0,
        operand: InlineOperand::None,
        flag_bits: 64,
    },
    CilOpcodeRef {
        byte1: 0x58,
        byte2: 0xff,
        mnemonic: "add",
        pop: 2,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x59,
        byte2: 0xff,
        mnemonic: "sub",
        pop: 2,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x5a,
        byte2: 0xff,
        mnemonic: "mul",
        pop: 2,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x5b,
        byte2: 0xff,
        mnemonic: "div",
        pop: 2,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x5d,
        byte2: 0xff,
        mnemonic: "rem",
        pop: 2,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x5f,
        byte2: 0xff,
        mnemonic: "and",
        pop: 2,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x60,
        byte2: 0xff,
        mnemonic: "or",
        pop: 2,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x61,
        byte2: 0xff,
        mnemonic: "xor",
        pop: 2,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x62,
        byte2: 0xff,
        mnemonic: "shl",
        pop: 2,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x63,
        byte2: 0xff,
        mnemonic: "shr",
        pop: 2,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x65,
        byte2: 0xff,
        mnemonic: "neg",
        pop: 1,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x66,
        byte2: 0xff,
        mnemonic: "not",
        pop: 1,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x6f,
        byte2: 0xff,
        mnemonic: "callvirt",
        pop: -1,
        push: -1,
        operand: InlineOperand::Meth,
        flag_bits: 2 | 16,
    },
    CilOpcodeRef {
        byte1: 0x74,
        byte2: 0xff,
        mnemonic: "castclass",
        pop: 1,
        push: 1,
        operand: InlineOperand::Type,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x75,
        byte2: 0xff,
        mnemonic: "isinst",
        pop: 1,
        push: 1,
        operand: InlineOperand::Type,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x7b,
        byte2: 0xff,
        mnemonic: "ldfld",
        pop: 1,
        push: 1,
        operand: InlineOperand::Field,
        flag_bits: 32,
    },
    CilOpcodeRef {
        byte1: 0x7d,
        byte2: 0xff,
        mnemonic: "stfld",
        pop: 2,
        push: 0,
        operand: InlineOperand::Field,
        flag_bits: 64,
    },
    CilOpcodeRef {
        byte1: 0x7e,
        byte2: 0xff,
        mnemonic: "ldsfld",
        pop: 0,
        push: 1,
        operand: InlineOperand::Field,
        flag_bits: 32,
    },
    CilOpcodeRef {
        byte1: 0x80,
        byte2: 0xff,
        mnemonic: "stsfld",
        pop: 1,
        push: 0,
        operand: InlineOperand::Field,
        flag_bits: 64,
    },
    CilOpcodeRef {
        byte1: 0x8d,
        byte2: 0xff,
        mnemonic: "newarr",
        pop: 1,
        push: 1,
        operand: InlineOperand::Type,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x8e,
        byte2: 0xff,
        mnemonic: "ldlen",
        pop: 1,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0x9a,
        byte2: 0xff,
        mnemonic: "ldelem.ref",
        pop: 2,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 32,
    },
    CilOpcodeRef {
        byte1: 0xa4,
        byte2: 0xff,
        mnemonic: "stelem.i4",
        pop: 3,
        push: 0,
        operand: InlineOperand::None,
        flag_bits: 64,
    },
    CilOpcodeRef {
        byte1: 0xa7,
        byte2: 0xff,
        mnemonic: "stelem.ref",
        pop: 3,
        push: 0,
        operand: InlineOperand::None,
        flag_bits: 64,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x01,
        mnemonic: "ceq",
        pop: 2,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x02,
        mnemonic: "cgt",
        pop: 2,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x04,
        mnemonic: "clt",
        pop: 2,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x06,
        mnemonic: "ldftn",
        pop: 0,
        push: 1,
        operand: InlineOperand::Meth,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x09,
        mnemonic: "ldarg",
        pop: 0,
        push: 1,
        operand: InlineOperand::Var,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x0a,
        mnemonic: "ldarga",
        pop: 0,
        push: 1,
        operand: InlineOperand::Var,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x0b,
        mnemonic: "starg",
        pop: 1,
        push: 0,
        operand: InlineOperand::Var,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x0c,
        mnemonic: "ldloc",
        pop: 0,
        push: 1,
        operand: InlineOperand::Var,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x0e,
        mnemonic: "stloc",
        pop: 1,
        push: 0,
        operand: InlineOperand::Var,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x0f,
        mnemonic: "localloc",
        pop: 1,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x11,
        mnemonic: "endfilter",
        pop: 1,
        push: 0,
        operand: InlineOperand::None,
        flag_bits: 4,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x16,
        mnemonic: "constrained",
        pop: 0,
        push: 0,
        operand: InlineOperand::Type,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x17,
        mnemonic: "volatile.",
        pop: 0,
        push: 0,
        operand: InlineOperand::None,
        flag_bits: 128,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x18,
        mnemonic: "tail.",
        pop: 0,
        push: 0,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x19,
        mnemonic: "initobj",
        pop: 1,
        push: 0,
        operand: InlineOperand::Type,
        flag_bits: 64,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x1d,
        mnemonic: "sizeof",
        pop: 0,
        push: 1,
        operand: InlineOperand::Type,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x1e,
        mnemonic: "refanytype",
        pop: 1,
        push: 1,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
    CilOpcodeRef {
        byte1: 0xfe,
        byte2: 0x1f,
        mnemonic: "readonly.",
        pop: 0,
        push: 0,
        operand: InlineOperand::None,
        flag_bits: 0,
    },
];

/// Look up a CIL opcode reference entry by single-byte opcode.
#[must_use]
pub fn lookup_cil_opcode(byte1: u8) -> Option<&'static CilOpcodeRef> {
    CIL_OPCODE_REF
        .iter()
        .find(|e| e.byte1 == byte1 && e.byte2 == 0xff)
}

/// Look up a CIL opcode reference entry by two-byte `0xFE xx` opcode.
#[must_use]
pub fn lookup_cil_fe_opcode(byte2: u8) -> Option<&'static CilOpcodeRef> {
    CIL_OPCODE_REF
        .iter()
        .find(|e| e.byte1 == 0xfe && e.byte2 == byte2)
}

// ---------------------------------------------------------------------------
// CIL basic block analysis
// ---------------------------------------------------------------------------

/// A basic block in a CIL method body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CilBasicBlock {
    /// Offset of first instruction in this block.
    pub start_offset: usize,
    /// Offset past the last instruction in this block.
    pub end_offset: usize,
    /// Number of instructions in this block.
    pub instr_count: usize,
}

impl CilBasicBlock {
    /// Byte length of this block.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end_offset - self.start_offset
    }

    /// Returns `true` if this block contains no instructions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instr_count == 0
    }
}

/// Split a CIL method body into basic blocks (leader-based linear scan).
///
/// # Errors
///
/// Returns `CilDecodeError` on decode failure.
pub fn cil_find_blocks(code: &[u8]) -> Result<Vec<CilBasicBlock>, CilDecodeError> {
    // Heuristic: most methods have at least one branch every ~16 bytes; preallocate.
    let mut blocks = Vec::with_capacity(code.len() / 16 + 1);
    let mut off = 0usize;
    let mut block_start = 0usize;
    let mut block_instr = 0usize;

    while off < code.len() {
        let (instr, n) = CilInstr::decode(&code[off..])?;
        off += n;
        block_instr += 1;
        let terminates = instr.flags.intersects(InstrFlags::BRANCH | InstrFlags::RET);
        if terminates {
            blocks.push(CilBasicBlock {
                start_offset: block_start,
                end_offset: off,
                instr_count: block_instr,
            });
            block_start = off;
            block_instr = 0;
        }
    }
    if block_instr > 0 {
        blocks.push(CilBasicBlock {
            start_offset: block_start,
            end_offset: off,
            instr_count: block_instr,
        });
    }
    Ok(blocks)
}

// ---------------------------------------------------------------------------
// CIL stack depth tracker
// ---------------------------------------------------------------------------

/// Tracks the evaluation stack depth through a linear scan of CIL instructions.
#[derive(Debug, Default, Clone)]
pub struct CilStackTracker {
    /// Current stack depth.
    pub depth: i32,
    /// Maximum observed stack depth.
    pub max_depth: i32,
    /// Minimum observed stack depth (may go negative on decode of indirect calls).
    pub min_depth: i32,
}

impl CilStackTracker {
    /// Create a new tracker at depth 0.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a single decoded instruction's stack effect.
    ///
    /// Pop/push values of `-1` mean variable (ignored for tracking purposes).
    pub fn apply(&mut self, entry: &CilOpcodeRef) {
        if entry.pop >= 0 {
            self.depth -= i32::from(entry.pop);
        }
        if entry.push >= 0 {
            self.depth += i32::from(entry.push);
        }
        if self.depth > self.max_depth {
            self.max_depth = self.depth;
        }
        if self.depth < self.min_depth {
            self.min_depth = self.depth;
        }
    }

    /// Reset to zero.
    pub const fn reset(&mut self) {
        self.depth = 0;
        self.max_depth = 0;
        self.min_depth = 0;
    }
}

// ---------------------------------------------------------------------------
// CIL exception handling idiom detector
// ---------------------------------------------------------------------------

/// Classifies a CIL exception-handling pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CilEhPattern {
    /// try { … } catch { … }
    TryCatch,
    /// try { … } finally { … }
    TryFinally,
    /// try { … } fault { … }
    TryFault,
    /// try { … } filter { … } catch { … }
    TryFilter,
}

impl CilEhPattern {
    /// Map an `EhClauseKind` to its corresponding pattern.
    #[must_use]
    pub const fn from_clause(kind: EhClauseKind) -> Self {
        match kind {
            EhClauseKind::Exception => Self::TryCatch,
            EhClauseKind::Finally => Self::TryFinally,
            EhClauseKind::Fault => Self::TryFault,
            EhClauseKind::Filter => Self::TryFilter,
        }
    }
    /// Returns the .NET keyword string for this pattern.
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::TryCatch => "catch",
            Self::TryFinally => "finally",
            Self::TryFault => "fault",
            Self::TryFilter => "filter",
        }
    }
}

// ---------------------------------------------------------------------------
// CIL well-known metadata constants
// ---------------------------------------------------------------------------

/// Token table indices from ECMA-335 §II.22.
pub mod cil_tables {
    /// Module table index.
    pub const MODULE: u8 = 0x00;
    /// `TypeRef` table index.
    pub const TYPE_REF: u8 = 0x01;
    /// `TypeDef` table index.
    pub const TYPE_DEF: u8 = 0x02;
    /// `FieldDef` table index.
    pub const FIELD: u8 = 0x04;
    /// `MethodDef` table index.
    pub const METHOD_DEF: u8 = 0x06;
    /// Param table index.
    pub const PARAM: u8 = 0x08;
    /// `InterfaceImpl` table index.
    pub const INTERFACE_IMPL: u8 = 0x09;
    /// `MemberRef` table index.
    pub const MEMBER_REF: u8 = 0x0A;
    /// Constant table index.
    pub const CONSTANT: u8 = 0x0B;
    /// `CustomAttribute` table index.
    pub const CUSTOM_ATTRIBUTE: u8 = 0x0C;
    /// `StandAloneSig` table index.
    pub const STAND_ALONE_SIG: u8 = 0x11;
    /// Assembly table index.
    pub const ASSEMBLY: u8 = 0x20;
    /// `AssemblyRef` table index.
    pub const ASSEMBLY_REF: u8 = 0x23;
}

// ---------------------------------------------------------------------------
// CIL calling convention decoder
// ---------------------------------------------------------------------------

/// .NET calling convention flags as encoded in a method/field signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CilCallConv {
    /// Default managed calling convention.
    Default,
    /// Unmanaged C calling convention.
    CDecl,
    /// Unmanaged stdcall.
    StdCall,
    /// Unmanaged thiscall.
    ThisCall,
    /// Unmanaged fastcall.
    FastCall,
    /// Varargs managed.
    VarArg,
    /// Generic method.
    Generic,
    /// Instance method.
    HasThis,
    /// Explicit-this instance method.
    ExplicitThis,
}

impl CilCallConv {
    /// Parse calling convention byte from a method signature blob.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b & 0x1f {
            0x00 => Some(Self::Default),
            0x01 => Some(Self::CDecl),
            0x02 => Some(Self::StdCall),
            0x03 => Some(Self::ThisCall),
            0x04 => Some(Self::FastCall),
            0x05 => Some(Self::VarArg),
            0x10 => Some(Self::Generic),
            _ => None,
        }
    }
    /// Returns `true` if this is an unmanaged calling convention.
    #[must_use]
    pub const fn is_unmanaged(self) -> bool {
        matches!(
            self,
            Self::CDecl | Self::StdCall | Self::ThisCall | Self::FastCall
        )
    }
    /// Return the ECMA-335 string name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::CDecl => "cdecl",
            Self::StdCall => "stdcall",
            Self::ThisCall => "thiscall",
            Self::FastCall => "fastcall",
            Self::VarArg => "vararg",
            Self::Generic => "generic",
            Self::HasThis => "hasthis",
            Self::ExplicitThis => "explicitthis",
        }
    }
}

// ---------------------------------------------------------------------------
// CIL element type table (signatures)
// ---------------------------------------------------------------------------

/// CIL element type codes (ECMA-335 §II.23.1.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CilElemType {
    /// End of type.
    End = 0x00,
    /// void.
    Void = 0x01,
    /// bool.
    Boolean = 0x02,
    /// char (UTF-16).
    Char = 0x03,
    /// int8.
    I1 = 0x04,
    /// uint8.
    U1 = 0x05,
    /// int16.
    I2 = 0x06,
    /// uint16.
    U2 = 0x07,
    /// int32.
    I4 = 0x08,
    /// uint32.
    U4 = 0x09,
    /// int64.
    I8 = 0x0A,
    /// uint64.
    U8 = 0x0B,
    /// float32.
    R4 = 0x0C,
    /// float64.
    R8 = 0x0D,
    /// System.String.
    String = 0x0E,
    /// Pointer type.
    Ptr = 0x0F,
    /// By-reference.
    ByRef = 0x10,
    /// Value type.
    ValueType = 0x11,
    /// Reference type.
    Class = 0x12,
    /// Variable type (generic parameter).
    Var = 0x13,
    /// Multidimensional array.
    Array = 0x14,
    /// Generic instance.
    GenericInst = 0x15,
    /// Typed reference.
    TypedByRef = 0x16,
    /// System.IntPtr.
    I = 0x18,
    /// System.UIntPtr.
    U = 0x19,
    /// Function pointer.
    FnPtr = 0x1B,
    /// System.Object.
    Object = 0x1C,
    /// Single-dimension, zero-lower-bound array.
    SzArray = 0x1D,
    /// Method generic parameter.
    MVar = 0x1E,
    /// Required modifier.
    CmodReqd = 0x1F,
    /// Optional modifier.
    CmodOpt = 0x20,
    /// Sentinel (vararg).
    Sentinel = 0x41,
    /// Pinned.
    Pinned = 0x45,
}

impl CilElemType {
    /// Decode an element type from a signature byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0x00 => Self::End,
            0x01 => Self::Void,
            0x02 => Self::Boolean,
            0x03 => Self::Char,
            0x04 => Self::I1,
            0x05 => Self::U1,
            0x06 => Self::I2,
            0x07 => Self::U2,
            0x08 => Self::I4,
            0x09 => Self::U4,
            0x0A => Self::I8,
            0x0B => Self::U8,
            0x0C => Self::R4,
            0x0D => Self::R8,
            0x0E => Self::String,
            0x0F => Self::Ptr,
            0x10 => Self::ByRef,
            0x11 => Self::ValueType,
            0x12 => Self::Class,
            0x13 => Self::Var,
            0x14 => Self::Array,
            0x15 => Self::GenericInst,
            0x16 => Self::TypedByRef,
            0x18 => Self::I,
            0x19 => Self::U,
            0x1B => Self::FnPtr,
            0x1C => Self::Object,
            0x1D => Self::SzArray,
            0x1E => Self::MVar,
            0x1F => Self::CmodReqd,
            0x20 => Self::CmodOpt,
            0x41 => Self::Sentinel,
            0x45 => Self::Pinned,
            _ => return None,
        })
    }

    /// Return the CIL keyword for primitive types.
    #[must_use]
    pub const fn keyword(self) -> Option<&'static str> {
        Some(match self {
            Self::Void => "void",
            Self::Boolean => "bool",
            Self::Char => "char",
            Self::I1 => "int8",
            Self::U1 => "uint8",
            Self::I2 => "int16",
            Self::U2 => "uint16",
            Self::I4 => "int32",
            Self::U4 => "uint32",
            Self::I8 => "int64",
            Self::U8 => "uint64",
            Self::R4 => "float32",
            Self::R8 => "float64",
            Self::String => "string",
            Self::I => "native int",
            Self::U => "native uint",
            Self::Object => "object",
            _ => return None,
        })
    }
}

// ---------------------------------------------------------------------------
// Additional tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod extended_tests {
    use super::*;

    fn addr(n: u64) -> Address {
        Address::new(n)
    }

    // --- MetadataTokenType ---

    #[test]
    fn test_token_type_methoddef() {
        let token = 0x0600_0001_u32;
        assert_eq!(
            MetadataTokenType::from_token(token),
            Some(MetadataTokenType::MethodDef)
        );
        assert_eq!(MetadataTokenType::rid(token), 1);
    }

    #[test]
    fn test_token_type_typeref() {
        let token = 0x0100_0042_u32;
        assert_eq!(
            MetadataTokenType::from_token(token),
            Some(MetadataTokenType::TypeRef)
        );
        assert_eq!(MetadataTokenType::rid(token), 0x42);
    }

    #[test]
    fn test_token_type_userstring() {
        let token = 0x7000_0005_u32;
        assert_eq!(
            MetadataTokenType::from_token(token),
            Some(MetadataTokenType::UserString)
        );
    }

    #[test]
    fn test_token_type_unknown() {
        assert!(MetadataTokenType::from_token(0x0300_0001).is_none());
    }

    #[test]
    fn test_token_table_name() {
        assert_eq!(MetadataTokenType::MethodDef.table_name(), "MethodDef");
        assert_eq!(MetadataTokenType::TypeDef.table_name(), "TypeDef");
    }

    // --- MethodHeader ---

    #[test]
    fn test_method_header_tiny() {
        // Tiny header: first byte 0b00001010 = code_size=2, flag=0b10
        let bytes = [0x0a_u8];
        let (hdr, n) = MethodHeader::decode(&bytes).unwrap();
        assert_eq!(n, 1);
        assert!(hdr.is_tiny());
        assert_eq!(hdr.code_size(), 2);
    }

    #[test]
    fn test_method_header_fat() {
        // Fat header: flags=0x0013 (fat+init_locals), max_stack=8, code_size=4, local=0
        let mut bytes = vec![0x13_u8, 0x30, 0x08, 0x00];
        bytes.extend_from_slice(&4_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        let (hdr, n) = MethodHeader::decode(&bytes).unwrap();
        assert_eq!(n, 12);
        assert!(!hdr.is_tiny());
        assert_eq!(hdr.code_size(), 4);
        if let MethodHeader::Fat { max_stack, .. } = hdr {
            assert_eq!(max_stack, 8);
        }
    }

    #[test]
    fn test_method_header_truncated() {
        assert!(matches!(
            MethodHeader::decode(&[]),
            Err(CilDecodeError::Truncated)
        ));
        // Fat: first byte signals fat but fewer than 12 bytes
        assert!(matches!(
            MethodHeader::decode(&[0x03, 0x30, 0x00]),
            Err(CilDecodeError::Truncated)
        ));
    }

    // --- EhClauseKind ---

    #[test]
    fn test_eh_clause_kind_roundtrip() {
        assert_eq!(EhClauseKind::from_u32(0), Some(EhClauseKind::Exception));
        assert_eq!(EhClauseKind::from_u32(1), Some(EhClauseKind::Filter));
        assert_eq!(EhClauseKind::from_u32(2), Some(EhClauseKind::Finally));
        assert_eq!(EhClauseKind::from_u32(4), Some(EhClauseKind::Fault));
        assert!(EhClauseKind::from_u32(3).is_none());
    }

    #[test]
    fn test_eh_clause_names() {
        assert_eq!(EhClauseKind::Exception.name(), "catch");
        assert_eq!(EhClauseKind::Finally.name(), "finally");
        assert_eq!(EhClauseKind::Fault.name(), "fault");
    }

    // --- InlineOperand ---

    #[test]
    fn test_inline_operand_sizes() {
        assert_eq!(InlineOperand::None.fixed_size(), Some(0));
        assert_eq!(InlineOperand::I8.fixed_size(), Some(1));
        assert_eq!(InlineOperand::I32.fixed_size(), Some(4));
        assert_eq!(InlineOperand::I64.fixed_size(), Some(8));
        assert_eq!(InlineOperand::R8.fixed_size(), Some(8));
        assert!(InlineOperand::Switch.fixed_size().is_none());
    }

    // --- LocalVarFlags ---

    #[test]
    fn test_local_var_flags_pinned() {
        let f = LocalVarFlags::PINNED;
        assert!(f.contains(LocalVarFlags::PINNED));
        assert!(!f.contains(LocalVarFlags::BYREF));
    }

    // --- CilMethodStats ---

    #[test]
    fn test_cil_stats_simple() {
        // ldarg.0 (0x02), ldc.i4.1 (0x17), add (0x58), ret (0x2a)
        let code = [0x02_u8, 0x17, 0x58, 0x2a];
        let s = CilMethodStats::from_bytes(&code).unwrap();
        assert_eq!(s.instruction_count, 4);
        assert_eq!(s.terminator_count, 1);
        assert_eq!(s.call_count, 0);
    }

    #[test]
    fn test_cil_stats_branch() {
        // brfalse.s (0x2c, 0x00), br.s (0x2b, 0x00)
        let code = [0x2c_u8, 0x00, 0x2b, 0x00];
        let s = CilMethodStats::from_bytes(&code).unwrap();
        assert_eq!(s.conditional_branch_count, 1);
        assert_eq!(s.unconditional_branch_count, 1);
    }

    #[test]
    fn test_cil_stats_call() {
        // call (0x28, 0x06, 0x00, 0x00, 0x01)
        let mut code = vec![0x28_u8];
        code.extend_from_slice(&0x0600_0001_u32.to_le_bytes());
        code.push(0x2a); // ret
        let s = CilMethodStats::from_bytes(&code).unwrap();
        assert_eq!(s.call_count, 1);
    }

    #[test]
    fn test_cil_stats_mem_ops() {
        // ldind.i4 (0x4a), stind.i4 (0x54)
        let code = [0x4a_u8, 0x54];
        let s = CilMethodStats::from_bytes(&code).unwrap();
        assert_eq!(s.load_count, 1);
        assert_eq!(s.store_count, 1);
    }

    // --- Additional opcode coverage ---

    #[test]
    fn test_ldarg_s() {
        let (i, sz) = CilInstr::decode(&[0x0e, 0x05]).unwrap();
        assert_eq!(sz, 2);
        assert_eq!(i.mnemonic, "ldarg.s");
    }

    #[test]
    fn test_ldloc_0_through_3() {
        for (op, expected) in [
            (0x06_u8, "ldloc.0"),
            (0x07, "ldloc.1"),
            (0x08, "ldloc.2"),
            (0x09, "ldloc.3"),
        ] {
            let (i, sz) = CilInstr::decode(&[op]).unwrap();
            assert_eq!(sz, 1);
            assert_eq!(i.mnemonic, expected);
        }
    }

    #[test]
    fn test_stloc_0_through_3() {
        for (op, expected) in [
            (0x0a_u8, "stloc.0"),
            (0x0b, "stloc.1"),
            (0x0c, "stloc.2"),
            (0x0d, "stloc.3"),
        ] {
            let (i, sz) = CilInstr::decode(&[op]).unwrap();
            assert_eq!(sz, 1);
            assert_eq!(i.mnemonic, expected);
        }
    }

    #[test]
    fn test_ldc_i4_0_through_8() {
        // CIL: 0x14=ldnull, 0x15=ldc.i4.m1, 0x16..0x1e=ldc.i4.0..ldc.i4.8
        let ops_expected = [
            (0x16_u8, "ldc.i4.0"),
            (0x17, "ldc.i4.1"),
            (0x18, "ldc.i4.2"),
            (0x19, "ldc.i4.3"),
            (0x1a, "ldc.i4.4"),
            (0x1b, "ldc.i4.5"),
            (0x1c, "ldc.i4.6"),
            (0x1d, "ldc.i4.7"),
            (0x1e, "ldc.i4.8"),
        ];
        for (op, expected) in ops_expected {
            let (i, sz) = CilInstr::decode(&[op]).unwrap();
            assert_eq!(sz, 1, "op={op:#04x}");
            assert_eq!(i.mnemonic, expected, "op={op:#04x}");
        }
    }

    #[test]
    fn test_neg_and_not() {
        let (i, _) = CilInstr::decode(&[0x65]).unwrap();
        assert_eq!(i.mnemonic, "neg");
        let (i2, _) = CilInstr::decode(&[0x66]).unwrap();
        assert_eq!(i2.mnemonic, "not");
    }

    #[test]
    fn test_conv_i4_and_r8() {
        let (i, _) = CilInstr::decode(&[0x69]).unwrap();
        assert_eq!(i.mnemonic, "conv.i4");
        let (i2, _) = CilInstr::decode(&[0x6c]).unwrap();
        assert_eq!(i2.mnemonic, "conv.r8");
    }

    #[test]
    fn test_newarr_5_bytes() {
        let mut buf = vec![0x8d_u8];
        buf.extend_from_slice(&0x0100_0001_u32.to_le_bytes());
        let (i, sz) = CilInstr::decode(&buf).unwrap();
        assert_eq!(sz, 5);
        assert_eq!(i.mnemonic, "newarr");
    }

    #[test]
    fn test_ldlen() {
        let (i, sz) = CilInstr::decode(&[0x8e]).unwrap();
        assert_eq!(sz, 1);
        assert_eq!(i.mnemonic, "ldlen");
    }

    #[test]
    fn test_fe_localloc() {
        let (i, sz) = CilInstr::decode(&[0xfe, 0x0f]).unwrap();
        assert_eq!(sz, 2);
        assert_eq!(i.mnemonic, "localloc");
    }

    #[test]
    fn test_fe_cpobj() {
        let mut buf = vec![0xfe_u8, 0x70];
        buf.extend_from_slice(&0x0100_0001_u32.to_le_bytes());
        // This should either decode or return unknown prefixed opcode
        let result = CilInstr::decode(&buf);
        assert!(result.is_ok() || matches!(result, Err(CilDecodeError::UnknownPrefixedOpcode(_))));
    }

    #[test]
    fn test_disassembler_complex() {
        let arch = CilArch::new_64();
        // ldarg.0, ldc.i4.s 10, bge.s +0, ret
        let code = [0x02_u8, 0x1f, 0x0a, 0x2f, 0x00, 0x2a];
        let instrs: Vec<_> = CilLinearDisassembler::new(&arch, &code, addr(0))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs.len(), 4);
        assert_eq!(instrs[0].mnemonic, "ldarg.0");
        assert_eq!(instrs[3].mnemonic, "ret");
    }
}

// ---------------------------------------------------------------------------
// Tests for new modules
// ---------------------------------------------------------------------------

#[cfg(test)]
mod cil_opcode_ref_tests {
    use super::*;

    #[test]
    fn test_lookup_nop() {
        let e = lookup_cil_opcode(0x00).unwrap();
        assert_eq!(e.mnemonic, "nop");
        assert_eq!(e.pop, 0);
        assert_eq!(e.push, 0);
    }

    #[test]
    fn test_lookup_ret() {
        let e = lookup_cil_opcode(0x2a).unwrap();
        assert_eq!(e.mnemonic, "ret");
        assert!(e.flags().contains(InstrFlags::RET));
    }

    #[test]
    fn test_lookup_call() {
        let e = lookup_cil_opcode(0x28).unwrap();
        assert_eq!(e.mnemonic, "call");
        assert!(e.flags().contains(InstrFlags::CALL));
    }

    #[test]
    fn test_lookup_ldfld() {
        let e = lookup_cil_opcode(0x7b).unwrap();
        assert!(e.flags().contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_lookup_stfld() {
        let e = lookup_cil_opcode(0x7d).unwrap();
        assert!(e.flags().contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_lookup_fe_ceq() {
        let e = lookup_cil_fe_opcode(0x01).unwrap();
        assert_eq!(e.mnemonic, "ceq");
        assert!(e.is_prefixed());
    }

    #[test]
    fn test_lookup_fe_localloc() {
        let e = lookup_cil_fe_opcode(0x0f).unwrap();
        assert_eq!(e.mnemonic, "localloc");
    }

    #[test]
    fn test_lookup_missing() {
        assert!(lookup_cil_opcode(0xAA).is_none());
    }

    #[test]
    fn test_opcode_ref_table_size() {
        assert!(CIL_OPCODE_REF.len() >= 40);
    }

    #[test]
    fn test_add_pop_push() {
        let e = lookup_cil_opcode(0x58).unwrap();
        assert_eq!(e.mnemonic, "add");
        assert_eq!(e.pop, 2);
        assert_eq!(e.push, 1);
    }
}

#[cfg(test)]
mod cil_block_tests {
    use super::*;

    #[test]
    fn test_find_blocks_single_ret() {
        // nop, nop, ret
        let code = [0x00_u8, 0x00, 0x2a];
        let blocks = cil_find_blocks(&code).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].instr_count, 3);
    }

    #[test]
    fn test_find_blocks_branch_splits() {
        // br.s +0, nop, ret
        let code = [0x2b_u8, 0x00, 0x00, 0x2a];
        let blocks = cil_find_blocks(&code).unwrap();
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn test_block_len() {
        let b = CilBasicBlock {
            start_offset: 4,
            end_offset: 10,
            instr_count: 3,
        };
        assert_eq!(b.len(), 6);
    }

    #[test]
    fn test_block_is_empty() {
        let b = CilBasicBlock {
            start_offset: 0,
            end_offset: 0,
            instr_count: 0,
        };
        assert!(b.is_empty());
    }

    #[test]
    fn test_find_blocks_empty() {
        let blocks = cil_find_blocks(&[]).unwrap();
        assert!(blocks.is_empty());
    }
}

#[cfg(test)]
mod cil_stack_tracker_tests {
    use super::*;

    #[test]
    fn test_stack_push_pop() {
        let mut t = CilStackTracker::new();
        // dup pushes +1 more
        let dup = lookup_cil_opcode(0x25).unwrap();
        t.apply(dup);
        assert_eq!(t.depth, 1); // net +1 (pop 1, push 2 → but start at 0, pop clamps)
    }

    #[test]
    fn test_stack_reset() {
        let mut t = CilStackTracker::new();
        t.depth = 5;
        t.max_depth = 5;
        t.reset();
        assert_eq!(t.depth, 0);
        assert_eq!(t.max_depth, 0);
    }

    #[test]
    fn test_stack_max_depth() {
        let mut t = CilStackTracker::new();
        // ldc.i4.0 pushes 1
        let ldc = lookup_cil_opcode(0x16).unwrap();
        t.apply(ldc);
        t.apply(ldc);
        assert_eq!(t.max_depth, 2);
    }
}

#[cfg(test)]
mod cil_eh_pattern_tests {
    use super::*;

    #[test]
    fn test_eh_pattern_catch() {
        let p = CilEhPattern::from_clause(EhClauseKind::Exception);
        assert_eq!(p, CilEhPattern::TryCatch);
        assert_eq!(p.keyword(), "catch");
    }

    #[test]
    fn test_eh_pattern_finally() {
        let p = CilEhPattern::from_clause(EhClauseKind::Finally);
        assert_eq!(p.keyword(), "finally");
    }

    #[test]
    fn test_eh_pattern_fault() {
        let p = CilEhPattern::from_clause(EhClauseKind::Fault);
        assert_eq!(p.keyword(), "fault");
    }

    #[test]
    fn test_eh_pattern_filter() {
        let p = CilEhPattern::from_clause(EhClauseKind::Filter);
        assert_eq!(p.keyword(), "filter");
    }
}

#[cfg(test)]
mod cil_callconv_tests {
    use super::*;

    #[test]
    fn test_callconv_default() {
        let c = CilCallConv::from_byte(0x00).unwrap();
        assert_eq!(c.name(), "default");
        assert!(!c.is_unmanaged());
    }

    #[test]
    fn test_callconv_stdcall() {
        let c = CilCallConv::from_byte(0x02).unwrap();
        assert_eq!(c.name(), "stdcall");
        assert!(c.is_unmanaged());
    }

    #[test]
    fn test_callconv_vararg() {
        let c = CilCallConv::from_byte(0x05).unwrap();
        assert_eq!(c.name(), "vararg");
    }

    #[test]
    fn test_callconv_unknown() {
        assert!(CilCallConv::from_byte(0x0F).is_none());
    }
}

#[cfg(test)]
mod cil_elem_type_tests {
    use super::*;

    #[test]
    fn test_elem_type_i4() {
        let t = CilElemType::from_byte(0x08).unwrap();
        assert_eq!(t, CilElemType::I4);
        assert_eq!(t.keyword(), Some("int32"));
    }

    #[test]
    fn test_elem_type_string() {
        let t = CilElemType::from_byte(0x0E).unwrap();
        assert_eq!(t.keyword(), Some("string"));
    }

    #[test]
    fn test_elem_type_object() {
        let t = CilElemType::from_byte(0x1C).unwrap();
        assert_eq!(t.keyword(), Some("object"));
    }

    #[test]
    fn test_elem_type_szarray_no_keyword() {
        let t = CilElemType::from_byte(0x1D).unwrap();
        assert_eq!(t, CilElemType::SzArray);
        assert!(t.keyword().is_none());
    }

    #[test]
    fn test_elem_type_unknown() {
        assert!(CilElemType::from_byte(0xFF).is_none());
    }

    #[test]
    fn test_elem_type_void() {
        let t = CilElemType::from_byte(0x01).unwrap();
        assert_eq!(t.keyword(), Some("void"));
    }

    #[test]
    fn test_cil_tables_constants() {
        assert_eq!(cil_tables::METHOD_DEF, 0x06);
        assert_eq!(cil_tables::ASSEMBLY_REF, 0x23);
    }
}

// ---------------------------------------------------------------------------
// CIL .NET well-known type references
// ---------------------------------------------------------------------------

/// A well-known .NET core type referenced in CIL analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DotNetWellKnownType {
    /// Fully-qualified type name.
    pub full_name: &'static str,
    /// Assembly short name.
    pub assembly: &'static str,
    /// CIL element type code (if primitive), or 0 for reference types.
    pub elem_type: u8,
}

/// Well-known .NET types used in CIL analysis.
pub static DOTNET_WELL_KNOWN_TYPES: &[DotNetWellKnownType] = &[
    DotNetWellKnownType {
        full_name: "System.Void",
        assembly: "mscorlib",
        elem_type: 0x01,
    },
    DotNetWellKnownType {
        full_name: "System.Boolean",
        assembly: "mscorlib",
        elem_type: 0x02,
    },
    DotNetWellKnownType {
        full_name: "System.Char",
        assembly: "mscorlib",
        elem_type: 0x03,
    },
    DotNetWellKnownType {
        full_name: "System.SByte",
        assembly: "mscorlib",
        elem_type: 0x04,
    },
    DotNetWellKnownType {
        full_name: "System.Byte",
        assembly: "mscorlib",
        elem_type: 0x05,
    },
    DotNetWellKnownType {
        full_name: "System.Int16",
        assembly: "mscorlib",
        elem_type: 0x06,
    },
    DotNetWellKnownType {
        full_name: "System.UInt16",
        assembly: "mscorlib",
        elem_type: 0x07,
    },
    DotNetWellKnownType {
        full_name: "System.Int32",
        assembly: "mscorlib",
        elem_type: 0x08,
    },
    DotNetWellKnownType {
        full_name: "System.UInt32",
        assembly: "mscorlib",
        elem_type: 0x09,
    },
    DotNetWellKnownType {
        full_name: "System.Int64",
        assembly: "mscorlib",
        elem_type: 0x0A,
    },
    DotNetWellKnownType {
        full_name: "System.UInt64",
        assembly: "mscorlib",
        elem_type: 0x0B,
    },
    DotNetWellKnownType {
        full_name: "System.Single",
        assembly: "mscorlib",
        elem_type: 0x0C,
    },
    DotNetWellKnownType {
        full_name: "System.Double",
        assembly: "mscorlib",
        elem_type: 0x0D,
    },
    DotNetWellKnownType {
        full_name: "System.String",
        assembly: "mscorlib",
        elem_type: 0x0E,
    },
    DotNetWellKnownType {
        full_name: "System.IntPtr",
        assembly: "mscorlib",
        elem_type: 0x18,
    },
    DotNetWellKnownType {
        full_name: "System.UIntPtr",
        assembly: "mscorlib",
        elem_type: 0x19,
    },
    DotNetWellKnownType {
        full_name: "System.Object",
        assembly: "mscorlib",
        elem_type: 0x1C,
    },
    DotNetWellKnownType {
        full_name: "System.Exception",
        assembly: "mscorlib",
        elem_type: 0x00,
    },
    DotNetWellKnownType {
        full_name: "System.NullReferenceException",
        assembly: "mscorlib",
        elem_type: 0x00,
    },
    DotNetWellKnownType {
        full_name: "System.ArgumentException",
        assembly: "mscorlib",
        elem_type: 0x00,
    },
    DotNetWellKnownType {
        full_name: "System.InvalidOperationException",
        assembly: "mscorlib",
        elem_type: 0x00,
    },
    DotNetWellKnownType {
        full_name: "System.OverflowException",
        assembly: "mscorlib",
        elem_type: 0x00,
    },
    DotNetWellKnownType {
        full_name: "System.IndexOutOfRangeException",
        assembly: "mscorlib",
        elem_type: 0x00,
    },
    DotNetWellKnownType {
        full_name: "System.Collections.Generic.List`1",
        assembly: "mscorlib",
        elem_type: 0x00,
    },
    DotNetWellKnownType {
        full_name: "System.Collections.Generic.Dictionary`2",
        assembly: "mscorlib",
        elem_type: 0x00,
    },
    DotNetWellKnownType {
        full_name: "System.Linq.Enumerable",
        assembly: "System.Linq",
        elem_type: 0x00,
    },
    DotNetWellKnownType {
        full_name: "System.Console",
        assembly: "mscorlib",
        elem_type: 0x00,
    },
    DotNetWellKnownType {
        full_name: "System.Math",
        assembly: "mscorlib",
        elem_type: 0x00,
    },
    DotNetWellKnownType {
        full_name: "System.Array",
        assembly: "mscorlib",
        elem_type: 0x00,
    },
    DotNetWellKnownType {
        full_name: "System.Type",
        assembly: "mscorlib",
        elem_type: 0x00,
    },
];

/// Look up a well-known type by full name.
#[must_use]
pub fn lookup_dotnet_type(full_name: &str) -> Option<&'static DotNetWellKnownType> {
    DOTNET_WELL_KNOWN_TYPES
        .iter()
        .find(|t| t.full_name == full_name)
}

// ---------------------------------------------------------------------------
// CIL attribute flags (ECMA-335 §II.23.1.4 - FieldAttributes)
// ---------------------------------------------------------------------------

bitflags::bitflags! {
    /// .NET FieldAttributes flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FieldAttributes: u16 {
        /// Member is accessible to all.
        const PUBLIC            = 0x0006;
        /// Member is accessible to subclasses and this assembly.
        const FAMILY            = 0x0004;
        /// Member is accessible to this assembly.
        const ASSEMBLY          = 0x0003;
        /// Member is not accessible outside its declaring scope.
        const PRIVATE           = 0x0001;
        /// Field is static.
        const STATIC            = 0x0010;
        /// Field is initialised at runtime.
        const INIT_ONLY         = 0x0020;
        /// Field is a compile-time literal.
        const LITERAL           = 0x0040;
        /// Field is not serialised when type is remoted.
        const NOT_SERIALIZED    = 0x0080;
        /// Field has a default value.
        const HAS_DEFAULT       = 0x8000;
        /// Field has a runtime (RVA) initialiser.
        const HAS_FIELD_RVA     = 0x0100;
    }
}

bitflags::bitflags! {
    /// .NET MethodAttributes flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MethodAttributes: u16 {
        /// Member is accessible to all.
        const PUBLIC            = 0x0006;
        /// Member is accessible to subclasses.
        const FAMILY            = 0x0004;
        /// Member is accessible to this assembly.
        const ASSEMBLY          = 0x0003;
        /// Member is not accessible outside its declaring scope.
        const PRIVATE           = 0x0001;
        /// Method is static.
        const STATIC            = 0x0010;
        /// Method is final (not overridable).
        const FINAL             = 0x0020;
        /// Method is virtual.
        const VIRTUAL           = 0x0040;
        /// Method hides a base method by name+sig.
        const HIDE_BY_SIG       = 0x0080;
        /// Method has a new slot in the vtable.
        const NEW_SLOT          = 0x0100;
        /// Method is abstract.
        const ABSTRACT          = 0x0400;
        /// Method is a special name (get_, set_, .ctor, etc.).
        const SPECIAL_NAME      = 0x0800;
        /// Method is a PInvoke.
        const PINVOKE_IMPL      = 0x2000;
        /// Method has security.
        const HAS_SECURITY      = 0x4000;
    }
}

// ---------------------------------------------------------------------------
// CIL control flow graph text formatter
// ---------------------------------------------------------------------------

/// Format a list of basic blocks as a simple text CFG summary.
#[must_use]
pub fn cil_cfg_text(blocks: &[CilBasicBlock]) -> String {
    let mut out = String::new();
    for (i, b) in blocks.iter().enumerate() {
        out.push_str(&format!(
            "BB{i}: offset={:#06x}..{:#06x} ({} instrs)\n",
            b.start_offset, b.end_offset, b.instr_count
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// CIL idiom detector
// ---------------------------------------------------------------------------

/// Recognized CIL idiom patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CilIdiom {
    /// `ldnull; brnull / brfalse` pattern (null guard).
    NullCheck,
    /// `ldloc.0 / ldarg.0 → add → stloc.0` simple increment idiom.
    LocalIncrement,
    /// `ldstr → call Console.WriteLine` print idiom.
    PrintString,
    /// `ldc.i4.0 → stloc.0` local variable zero-initialize.
    ZeroInit,
    /// `newobj → stloc` object construction.
    ObjectConstruct,
    /// Generic / unrecognized pattern.
    General,
}

/// Attempt to identify the idiom represented by a CIL instruction sequence.
///
/// This is a simple heuristic based on the first few instructions.
#[must_use]
pub fn identify_cil_idiom(instrs: &[CilInstr]) -> CilIdiom {
    if instrs.is_empty() {
        return CilIdiom::General;
    }
    match instrs[0].mnemonic.as_str() {
        "ldnull" => {
            if instrs.len() >= 2
                && (instrs[1].mnemonic == "brfalse" || instrs[1].mnemonic == "brfalse.s")
            {
                return CilIdiom::NullCheck;
            }
            CilIdiom::General
        }
        "ldc.i4.0" => {
            if instrs.len() >= 2 && instrs[1].mnemonic.starts_with("stloc") {
                return CilIdiom::ZeroInit;
            }
            CilIdiom::General
        }
        "ldstr" => {
            if instrs.len() >= 2 && instrs[1].mnemonic == "call" {
                return CilIdiom::PrintString;
            }
            CilIdiom::General
        }
        "newobj" => {
            if instrs.len() >= 2 && instrs[1].mnemonic.starts_with("stloc") {
                return CilIdiom::ObjectConstruct;
            }
            CilIdiom::General
        }
        _ => CilIdiom::General,
    }
}

// ---------------------------------------------------------------------------
// CIL stack-effect helpers
// ---------------------------------------------------------------------------

/// Compute the net stack delta for a decoded instruction.
///
/// Returns `None` if pop or push is variable (call/callvirt).
#[must_use]
pub fn cil_net_stack_delta(instr: &CilInstr) -> Option<i32> {
    // Look up by first opcode byte
    let byte1 = *instr.raw.first()?;
    if byte1 == 0xfe {
        let byte2 = *instr.raw.get(1)?;
        let e = lookup_cil_fe_opcode(byte2)?;
        if e.pop < 0 || e.push < 0 {
            return None;
        }
        Some(i32::from(e.push) - i32::from(e.pop))
    } else {
        let e = lookup_cil_opcode(byte1)?;
        if e.pop < 0 || e.push < 0 {
            return None;
        }
        Some(i32::from(e.push) - i32::from(e.pop))
    }
}

// ---------------------------------------------------------------------------
// CIL method complexity metrics
// ---------------------------------------------------------------------------

/// Complexity metrics for a CIL method body.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CilComplexityMetrics {
    /// Cyclomatic complexity (1 + conditional branches).
    pub cyclomatic: usize,
    /// Maximum linear sequence length (instructions between branches).
    pub max_linear_run: usize,
    /// Total instruction count.
    pub instruction_count: usize,
}

impl CilComplexityMetrics {
    /// Compute complexity metrics from raw CIL bytecode.
    ///
    /// # Errors
    ///
    /// Returns `CilDecodeError` on decode failure.
    pub fn from_bytes(code: &[u8]) -> Result<Self, CilDecodeError> {
        let mut m = Self {
            cyclomatic: 1,
            ..Self::default()
        };
        let mut off = 0;
        let mut run = 0usize;
        while off < code.len() {
            let (instr, n) = CilInstr::decode(&code[off..])?;
            off += n;
            m.instruction_count += 1;
            run += 1;
            if instr.flags.contains(InstrFlags::CONDITIONAL) {
                m.cyclomatic += 1;
            }
            if instr.flags.intersects(InstrFlags::BRANCH | InstrFlags::RET) {
                if run > m.max_linear_run {
                    m.max_linear_run = run;
                }
                run = 0;
            }
        }
        if run > m.max_linear_run {
            m.max_linear_run = run;
        }
        Ok(m)
    }
}

// ---------------------------------------------------------------------------
// CIL pseudo-instruction builder
// ---------------------------------------------------------------------------

/// Build raw CIL bytecode for simple method bodies.
#[derive(Debug, Default, Clone)]
pub struct CilMethodBuilder {
    buf: Vec<u8>,
}

impl CilMethodBuilder {
    /// Create a new empty method builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit a `nop` instruction.
    pub fn nop(&mut self) -> &mut Self {
        self.buf.push(0x00);
        self
    }

    /// Emit a `ret` instruction.
    pub fn ret(&mut self) -> &mut Self {
        self.buf.push(0x2a);
        self
    }

    /// Emit `ldarg.0`.
    pub fn ldarg0(&mut self) -> &mut Self {
        self.buf.push(0x02);
        self
    }

    /// Emit `ldarg.1`.
    pub fn ldarg1(&mut self) -> &mut Self {
        self.buf.push(0x03);
        self
    }

    /// Emit `ldc.i4.0`.
    pub fn ldc_i4_0(&mut self) -> &mut Self {
        self.buf.push(0x16);
        self
    }

    /// Emit `ldc.i4.1`.
    pub fn ldc_i4_1(&mut self) -> &mut Self {
        self.buf.push(0x17);
        self
    }

    /// Emit `ldc.i4.s imm8`.
    pub fn ldc_i4_s(&mut self, v: i8) -> &mut Self {
        self.buf.push(0x1f);
        self.buf.push(v as u8);
        self
    }

    /// Emit `ldc.i4 imm32`.
    pub fn ldc_i4(&mut self, v: i32) -> &mut Self {
        self.buf.push(0x20);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Emit `add`.
    pub fn add(&mut self) -> &mut Self {
        self.buf.push(0x58);
        self
    }

    /// Emit `sub`.
    pub fn sub(&mut self) -> &mut Self {
        self.buf.push(0x59);
        self
    }

    /// Emit `mul`.
    pub fn mul(&mut self) -> &mut Self {
        self.buf.push(0x5a);
        self
    }

    /// Emit `dup`.
    pub fn dup(&mut self) -> &mut Self {
        self.buf.push(0x25);
        self
    }

    /// Emit `pop`.
    pub fn pop(&mut self) -> &mut Self {
        self.buf.push(0x26);
        self
    }

    /// Emit `stloc.0`.
    pub fn stloc0(&mut self) -> &mut Self {
        self.buf.push(0x0a);
        self
    }

    /// Emit `ldloc.0`.
    pub fn ldloc0(&mut self) -> &mut Self {
        self.buf.push(0x06);
        self
    }

    /// Emit `br.s offset` (short branch).
    pub fn br_s(&mut self, offset: i8) -> &mut Self {
        self.buf.push(0x2b);
        self.buf.push(offset as u8);
        self
    }

    /// Emit `brfalse.s offset`.
    pub fn brfalse_s(&mut self, offset: i8) -> &mut Self {
        self.buf.push(0x2c);
        self.buf.push(offset as u8);
        self
    }

    /// Emit `brtrue.s offset`.
    pub fn brtrue_s(&mut self, offset: i8) -> &mut Self {
        self.buf.push(0x2d);
        self.buf.push(offset as u8);
        self
    }

    /// Emit `call methodToken`.
    pub fn call(&mut self, token: u32) -> &mut Self {
        self.buf.push(0x28);
        self.buf.extend_from_slice(&token.to_le_bytes());
        self
    }

    /// Emit `callvirt methodToken`.
    pub fn callvirt(&mut self, token: u32) -> &mut Self {
        self.buf.push(0x6f);
        self.buf.extend_from_slice(&token.to_le_bytes());
        self
    }

    /// Return the assembled bytecode.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    /// Return the current byte count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if no bytes have been emitted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CIL signature decoder helpers
// ---------------------------------------------------------------------------

/// Decode a compressed unsigned integer from a .NET signature blob.
/// Returns `(value, bytes_consumed)`.
///
/// # Errors
///
/// Returns `CilDecodeError::Truncated` if the slice is empty or too short.
pub fn decode_compressed_uint(data: &[u8]) -> Result<(u32, usize), CilDecodeError> {
    if data.is_empty() {
        return Err(CilDecodeError::Truncated);
    }
    let b0 = data[0];
    if b0 & 0x80 == 0 {
        // 1-byte: 0xxxxxxx
        return Ok((u32::from(b0 & 0x7F), 1));
    }
    if b0 & 0xC0 == 0x80 {
        // 2-byte: 10xxxxxx xxxxxxxx
        if data.len() < 2 {
            return Err(CilDecodeError::Truncated);
        }
        let val = (u32::from(b0 & 0x3F) << 8) | u32::from(data[1]);
        return Ok((val, 2));
    }
    if b0 & 0xE0 == 0xC0 {
        // 4-byte: 110xxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        if data.len() < 4 {
            return Err(CilDecodeError::Truncated);
        }
        let val = (u32::from(b0 & 0x1F) << 24)
            | (u32::from(data[1]) << 16)
            | (u32::from(data[2]) << 8)
            | u32::from(data[3]);
        return Ok((val, 4));
    }
    Err(CilDecodeError::Truncated)
}

/// Decode a compressed signed integer from a .NET signature blob.
///
/// # Errors
///
/// Returns `CilDecodeError::Truncated` if the slice is too short.
pub fn decode_compressed_int(data: &[u8]) -> Result<(i32, usize), CilDecodeError> {
    let (raw, n) = decode_compressed_uint(data)?;
    // Rotate right by 1 and sign-extend
    let signed = if raw & 1 == 0 {
        (raw >> 1) as i32
    } else {
        let shift = match n {
            1 => 6,
            2 => 13,
            _ => 28,
        };
        ((raw >> 1) as i32) | (-1_i32 << shift)
    };
    Ok((signed, n))
}

// ---------------------------------------------------------------------------
// CIL field/method visibility helper
// ---------------------------------------------------------------------------

/// Visibility tier for a .NET member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DotNetVisibility {
    /// Compiler-controlled (private scope).
    PrivateScope = 0,
    /// Private to declaring type.
    Private = 1,
    /// Family AND assembly.
    FamilyAndAssembly = 2,
    /// Assembly (internal).
    Assembly = 3,
    /// Family (protected).
    Family = 4,
    /// Family OR assembly.
    FamilyOrAssembly = 5,
    /// Public.
    Public = 6,
}

impl DotNetVisibility {
    /// Decode a 3-bit visibility mask from `MethodAttributes` or `FieldAttributes`.
    #[must_use]
    pub const fn from_bits3(bits: u8) -> Self {
        match bits & 0x07 {
            0 => Self::PrivateScope,
            1 => Self::Private,
            2 => Self::FamilyAndAssembly,
            3 => Self::Assembly,
            4 => Self::Family,
            5 => Self::FamilyOrAssembly,
            _ => Self::Public,
        }
    }

    /// Returns the C# keyword string for this visibility.
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::PrivateScope | Self::Private => "private",
            Self::FamilyAndAssembly => "private protected",
            Self::Assembly => "internal",
            Self::Family => "protected",
            Self::FamilyOrAssembly => "protected internal",
            Self::Public => "public",
        }
    }
}

// ---------------------------------------------------------------------------
// Tests for new infrastructure
// ---------------------------------------------------------------------------

#[cfg(test)]
mod cil_extra_tests {
    use super::*;

    #[test]
    fn test_well_known_int32() {
        let t = lookup_dotnet_type("System.Int32").unwrap();
        assert_eq!(t.elem_type, 0x08);
        assert_eq!(t.assembly, "mscorlib");
    }

    #[test]
    fn test_well_known_exception() {
        let t = lookup_dotnet_type("System.Exception").unwrap();
        assert_eq!(t.elem_type, 0x00);
    }

    #[test]
    fn test_well_known_missing() {
        assert!(lookup_dotnet_type("Fake.Type").is_none());
    }

    #[test]
    fn test_field_attrs_static() {
        let f = FieldAttributes::STATIC | FieldAttributes::PUBLIC;
        assert!(f.contains(FieldAttributes::STATIC));
    }

    #[test]
    fn test_method_attrs_virtual() {
        let m = MethodAttributes::VIRTUAL | MethodAttributes::PUBLIC;
        assert!(m.contains(MethodAttributes::VIRTUAL));
    }

    #[test]
    fn test_cfg_text() {
        let blocks = vec![
            CilBasicBlock {
                start_offset: 0,
                end_offset: 4,
                instr_count: 2,
            },
            CilBasicBlock {
                start_offset: 4,
                end_offset: 6,
                instr_count: 1,
            },
        ];
        let text = cil_cfg_text(&blocks);
        assert!(text.contains("BB0"));
        assert!(text.contains("BB1"));
    }

    #[test]
    fn test_idiom_null_check() {
        // ldnull, brfalse.s
        let code = [0x14_u8, 0x2c, 0x00];
        let arch = CilArch::new_32();
        use rustre_core::address::Address;
        let instrs: Vec<_> = CilLinearDisassembler::new(&arch, &code, Address::new(0))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let i: Vec<CilInstr> = instrs
            .into_iter()
            .map(|i| CilInstr {
                raw: i.bytes,
                mnemonic: i.mnemonic,
                operands: i.operands,
                flags: i.flags,
            })
            .collect();
        assert_eq!(identify_cil_idiom(&i), CilIdiom::NullCheck);
    }

    #[test]
    fn test_idiom_zero_init() {
        let code = [0x16_u8, 0x0a];
        let arch = CilArch::new_32();
        use rustre_core::address::Address;
        let instrs: Vec<_> = CilLinearDisassembler::new(&arch, &code, Address::new(0))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let i: Vec<CilInstr> = instrs
            .into_iter()
            .map(|i| CilInstr {
                raw: i.bytes,
                mnemonic: i.mnemonic,
                operands: i.operands,
                flags: i.flags,
            })
            .collect();
        assert_eq!(identify_cil_idiom(&i), CilIdiom::ZeroInit);
    }

    #[test]
    fn test_net_stack_delta_add() {
        let (instr, _) = CilInstr::decode(&[0x58]).unwrap();
        assert_eq!(cil_net_stack_delta(&instr), Some(-1)); // pop 2, push 1 → net -1
    }

    #[test]
    fn test_net_stack_delta_ldc_i4_0() {
        let (instr, _) = CilInstr::decode(&[0x16]).unwrap();
        assert_eq!(cil_net_stack_delta(&instr), Some(1)); // pop 0, push 1 → net +1
    }

    #[test]
    fn test_net_stack_delta_call_none() {
        // call has variable pop/push → None
        let (instr, _) = CilInstr::decode(&[0x28, 0x01, 0x00, 0x00, 0x0a]).unwrap();
        assert_eq!(cil_net_stack_delta(&instr), None);
    }

    #[test]
    fn test_complexity_simple() {
        // ldarg.0, ldc.i4.1, add, ret
        let code = [0x02_u8, 0x17, 0x58, 0x2a];
        let m = CilComplexityMetrics::from_bytes(&code).unwrap();
        assert_eq!(m.cyclomatic, 1);
        assert_eq!(m.instruction_count, 4);
    }

    #[test]
    fn test_complexity_with_branch() {
        // ldc.i4.0, brfalse.s 0, ldc.i4.1, ret
        let code = [0x16_u8, 0x2c, 0x00, 0x17, 0x2a];
        let m = CilComplexityMetrics::from_bytes(&code).unwrap();
        assert_eq!(m.cyclomatic, 2); // 1 base + 1 conditional
    }

    #[test]
    fn test_builder_simple() {
        let mut b = CilMethodBuilder::new();
        b.ldarg0().ldarg1().add().ret();
        let code = b.finish();
        assert_eq!(code, [0x02, 0x03, 0x58, 0x2a]);
    }

    #[test]
    fn test_builder_ldc_i4() {
        let mut b = CilMethodBuilder::new();
        b.ldc_i4(42).ret();
        let code = b.finish();
        assert_eq!(code[0], 0x20);
        assert_eq!(i32::from_le_bytes([code[1], code[2], code[3], code[4]]), 42);
    }

    #[test]
    fn test_builder_is_empty() {
        let b = CilMethodBuilder::new();
        assert!(b.is_empty());
    }

    #[test]
    fn test_builder_call() {
        let mut b = CilMethodBuilder::new();
        b.call(0x0a000001);
        let code = b.finish();
        assert_eq!(code[0], 0x28);
    }

    #[test]
    fn test_decode_compressed_uint_1byte() {
        assert_eq!(decode_compressed_uint(&[0x03]).unwrap(), (3, 1));
    }

    #[test]
    fn test_decode_compressed_uint_2byte() {
        assert_eq!(decode_compressed_uint(&[0x81, 0x00]).unwrap(), (0x100, 2));
    }

    #[test]
    fn test_decode_compressed_uint_empty() {
        assert!(decode_compressed_uint(&[]).is_err());
    }

    #[test]
    fn test_decode_compressed_int_positive() {
        // Encoded positive 3: rotate-left(3,1) = 6 → [0x06]
        let (v, n) = decode_compressed_int(&[0x06]).unwrap();
        assert_eq!(v, 3);
        assert_eq!(n, 1);
    }

    #[test]
    fn test_visibility_public() {
        assert_eq!(DotNetVisibility::from_bits3(6).keyword(), "public");
    }

    #[test]
    fn test_visibility_private() {
        assert_eq!(DotNetVisibility::from_bits3(1).keyword(), "private");
    }

    #[test]
    fn test_visibility_internal() {
        assert_eq!(DotNetVisibility::from_bits3(3).keyword(), "internal");
    }

    #[test]
    fn test_visibility_protected() {
        assert_eq!(DotNetVisibility::from_bits3(4).keyword(), "protected");
    }

    #[test]
    fn test_visibility_ordering() {
        assert!(DotNetVisibility::Public > DotNetVisibility::Private);
    }

    #[test]
    fn test_well_known_table_size() {
        assert!(DOTNET_WELL_KNOWN_TYPES.len() >= 20);
    }
}

// ---------------------------------------------------------------------------
// CIL .NET opcode category classification
// ---------------------------------------------------------------------------

/// High-level category for a CIL instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CilOpcodeCategory {
    /// Load constant or variable onto stack.
    Load,
    /// Store value from stack to local/arg.
    Store,
    /// Arithmetic or bitwise operation.
    Arithmetic,
    /// Control-flow (branch, jump, call, ret).
    ControlFlow,
    /// Object/array model operations.
    Object,
    /// Memory load (ldind, ldfld, ldsfld).
    MemLoad,
    /// Memory store (stind, stfld, stsfld).
    MemStore,
    /// Comparison (ceq, cgt, clt).
    Compare,
    /// Conversion (conv.*).
    Convert,
    /// Exception handling (throw, leave, endfinally).
    Exception,
    /// Prefix / modifier (volatile., tail., constrained.).
    Prefix,
    /// Other / unclassified.
    Other,
}

impl CilOpcodeCategory {
    /// Classify a CIL mnemonic into an opcode category.
    #[must_use]
    pub fn from_mnemonic(mne: &str) -> Self {
        if mne.starts_with("ld")
            && !mne.starts_with("ldind")
            && !mne.starts_with("ldfld")
            && !mne.starts_with("ldsfld")
            && !mne.starts_with("ldelem")
            && mne != "ldlen"
        {
            return Self::Load;
        }
        if mne.starts_with("st")
            && !mne.starts_with("stind")
            && !mne.starts_with("stfld")
            && !mne.starts_with("stsfld")
            && !mne.starts_with("stelem")
        {
            return Self::Store;
        }
        if mne.starts_with("conv.") {
            return Self::Convert;
        }
        if mne.starts_with("ldelem.") || mne == "ldelem" || mne == "ldlen" || mne == "ldelema" {
            return Self::Object;
        }
        if mne.starts_with("stelem.") || mne == "stelem" {
            return Self::Object;
        }
        match mne {
            "add" | "add.ovf" | "add.ovf.un" | "sub" | "sub.ovf" | "sub.ovf.un" | "mul"
            | "mul.ovf" | "mul.ovf.un" | "div" | "div.un" | "rem" | "rem.un" | "and" | "or"
            | "xor" | "not" | "neg" | "shl" | "shr" | "shr.un" => Self::Arithmetic,
            "call" | "callvirt" | "calli" | "jmp" | "ret" | "br" | "br.s" | "brfalse"
            | "brfalse.s" | "brtrue" | "brtrue.s" | "beq" | "beq.s" | "bne.un" | "bne.un.s"
            | "bge" | "bge.s" | "bge.un" | "bge.un.s" | "bgt" | "bgt.s" | "bgt.un" | "bgt.un.s"
            | "ble" | "ble.s" | "ble.un" | "ble.un.s" | "blt" | "blt.s" | "blt.un" | "blt.un.s"
            | "switch" => Self::ControlFlow,
            "newobj" | "initobj" | "castclass" | "isinst" | "ldtoken" | "box" | "unbox"
            | "unbox.any" | "newarr" => Self::Object,
            "ldind.i1" | "ldind.i2" | "ldind.i4" | "ldind.i8" | "ldind.u1" | "ldind.u2"
            | "ldind.u4" | "ldind.u8" | "ldind.r4" | "ldind.r8" | "ldind.ref" | "ldind.i"
            | "ldfld" | "ldsfld" | "ldflda" | "ldsflda" | "ldobj" => Self::MemLoad,
            "stind.i1" | "stind.i2" | "stind.i4" | "stind.i8" | "stind.r4" | "stind.r8"
            | "stind.ref" | "stind.i" | "stfld" | "stsfld" | "stobj" => Self::MemStore,
            "ceq" | "cgt" | "cgt.un" | "clt" | "clt.un" => Self::Compare,
            "throw" | "rethrow" | "leave" | "leave.s" | "endfinally" | "endfault" | "endfilter" => {
                Self::Exception
            }
            "volatile." | "tail." | "constrained." | "readonly." | "unaligned." => Self::Prefix,
            _ => Self::Other,
        }
    }
}

// ---------------------------------------------------------------------------
// CIL tailcall / inline candidate detector
// ---------------------------------------------------------------------------

/// Reasons a method body may be an inline candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CilInlineHint {
    /// Method is trivially inlinable (very few instructions).
    Trivial,
    /// Method is a simple property getter (ldarg + ldfld + ret).
    PropertyGetter,
    /// Method has branches – harder but possible.
    WithBranches,
    /// Method contains exception handlers – generally not inlined.
    HasExceptionHandlers,
    /// Method is too large to inline.
    TooLarge,
}

/// Heuristic inline assessment for a raw CIL method body.
///
/// # Errors
///
/// Returns `CilDecodeError` on decode failure.
pub fn cil_inline_hint(code: &[u8]) -> Result<CilInlineHint, CilDecodeError> {
    let stats = CilMethodStats::from_bytes(code)?;
    if code.len() > 256 {
        return Ok(CilInlineHint::TooLarge);
    }
    if stats.instruction_count <= 3 {
        return Ok(CilInlineHint::Trivial);
    }
    if stats.instruction_count <= 8 && stats.conditional_branch_count == 0 && stats.load_count <= 2
    {
        return Ok(CilInlineHint::PropertyGetter);
    }
    if stats.conditional_branch_count > 0 {
        return Ok(CilInlineHint::WithBranches);
    }
    Ok(CilInlineHint::Trivial)
}

// ---------------------------------------------------------------------------
// CIL assembly metadata summary
// ---------------------------------------------------------------------------

/// Summary of an assembly's CIL metadata.
#[derive(Debug, Default, Clone)]
pub struct AssemblyMetadataSummary {
    /// Assembly name.
    pub name: String,
    /// Major version.
    pub version_major: u16,
    /// Minor version.
    pub version_minor: u16,
    /// Build number.
    pub version_build: u16,
    /// Revision number.
    pub version_revision: u16,
    /// Culture string (empty = neutral).
    pub culture: String,
    /// Is this a .NET Core / 5+ assembly?
    pub is_netcore: bool,
}

impl AssemblyMetadataSummary {
    /// Return the version as a dotted string `major.minor.build.revision`.
    #[must_use]
    pub fn version_string(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.version_major, self.version_minor, self.version_build, self.version_revision
        )
    }

    /// Returns `true` if this is a neutral-culture assembly.
    #[must_use]
    pub fn is_culture_neutral(&self) -> bool {
        self.culture.is_empty() || self.culture == "neutral"
    }
}

// ---------------------------------------------------------------------------
// CIL register pressure estimator
// ---------------------------------------------------------------------------

/// Estimate local variable "register pressure" from a CIL method body.
///
/// Returns the maximum local-variable slot referenced in stloc/ldloc instructions.
///
/// # Errors
///
/// Returns `CilDecodeError` on decode failure.
pub fn cil_max_local_slot(code: &[u8]) -> Result<u8, CilDecodeError> {
    let mut max_slot: u8 = 0;
    let mut off = 0;
    while off < code.len() {
        let (instr, n) = CilInstr::decode(&code[off..])?;
        off += n;
        let slot = match instr.mnemonic.as_str() {
            "stloc.0" | "ldloc.0" => 0,
            "stloc.1" | "ldloc.1" => 1,
            "stloc.2" | "ldloc.2" => 2,
            "stloc.3" | "ldloc.3" => 3,
            "stloc.s" | "ldloc.s" => instr.operands.parse::<u8>().unwrap_or(0),
            _ => continue,
        };
        if slot > max_slot {
            max_slot = slot;
        }
    }
    Ok(max_slot)
}

// ---------------------------------------------------------------------------
// Tests for new functionality
// ---------------------------------------------------------------------------

#[cfg(test)]
mod cil_category_tests {
    use super::*;

    #[test]
    fn test_category_add() {
        assert_eq!(
            CilOpcodeCategory::from_mnemonic("add"),
            CilOpcodeCategory::Arithmetic
        );
    }

    #[test]
    fn test_category_ldarg() {
        assert_eq!(
            CilOpcodeCategory::from_mnemonic("ldarg.0"),
            CilOpcodeCategory::Load
        );
    }

    #[test]
    fn test_category_stloc() {
        assert_eq!(
            CilOpcodeCategory::from_mnemonic("stloc.0"),
            CilOpcodeCategory::Store
        );
    }

    #[test]
    fn test_category_call() {
        assert_eq!(
            CilOpcodeCategory::from_mnemonic("call"),
            CilOpcodeCategory::ControlFlow
        );
    }

    #[test]
    fn test_category_ret() {
        assert_eq!(
            CilOpcodeCategory::from_mnemonic("ret"),
            CilOpcodeCategory::ControlFlow
        );
    }

    #[test]
    fn test_category_ceq() {
        assert_eq!(
            CilOpcodeCategory::from_mnemonic("ceq"),
            CilOpcodeCategory::Compare
        );
    }

    #[test]
    fn test_category_conv() {
        assert_eq!(
            CilOpcodeCategory::from_mnemonic("conv.i4"),
            CilOpcodeCategory::Convert
        );
    }

    #[test]
    fn test_category_ldfld() {
        assert_eq!(
            CilOpcodeCategory::from_mnemonic("ldfld"),
            CilOpcodeCategory::MemLoad
        );
    }

    #[test]
    fn test_category_stfld() {
        assert_eq!(
            CilOpcodeCategory::from_mnemonic("stfld"),
            CilOpcodeCategory::MemStore
        );
    }

    #[test]
    fn test_category_throw() {
        assert_eq!(
            CilOpcodeCategory::from_mnemonic("throw"),
            CilOpcodeCategory::Exception
        );
    }

    #[test]
    fn test_category_volatile_prefix() {
        assert_eq!(
            CilOpcodeCategory::from_mnemonic("volatile."),
            CilOpcodeCategory::Prefix
        );
    }

    #[test]
    fn test_category_newobj() {
        assert_eq!(
            CilOpcodeCategory::from_mnemonic("newobj"),
            CilOpcodeCategory::Object
        );
    }
}

#[cfg(test)]
mod cil_inline_hint_tests {
    use super::*;

    #[test]
    fn test_inline_trivial() {
        // ldarg.0, ldc.i4.1, add, ret = trivial (4 instrs ≤ threshold)
        let code = [0x02_u8, 0x17, 0x58, 0x2a];
        // 4 instrs → not trivially ≤3 but simple; expect Trivial or PropertyGetter
        let h = cil_inline_hint(&code).unwrap();
        assert!(matches!(
            h,
            CilInlineHint::Trivial | CilInlineHint::PropertyGetter
        ));
    }

    #[test]
    fn test_inline_trivial_nop_ret() {
        let code = [0x00_u8, 0x2a]; // nop, ret
        assert_eq!(cil_inline_hint(&code).unwrap(), CilInlineHint::Trivial);
    }

    #[test]
    fn test_inline_with_branch() {
        // ldc.i4.0, brfalse.s 0, ldc.i4.1, ret
        let code = [0x16_u8, 0x2c, 0x00, 0x17, 0x2a];
        assert_eq!(cil_inline_hint(&code).unwrap(), CilInlineHint::WithBranches);
    }

    #[test]
    fn test_inline_too_large() {
        let code = vec![0x00_u8; 300]; // 300 nops
        assert_eq!(cil_inline_hint(&code).unwrap(), CilInlineHint::TooLarge);
    }
}

#[cfg(test)]
mod cil_assembly_meta_tests {
    use super::*;

    #[test]
    fn test_version_string() {
        let s = AssemblyMetadataSummary {
            name: "MyApp".into(),
            version_major: 1,
            version_minor: 2,
            version_build: 3,
            version_revision: 4,
            culture: String::new(),
            is_netcore: false,
        };
        assert_eq!(s.version_string(), "1.2.3.4");
    }

    #[test]
    fn test_culture_neutral() {
        let s = AssemblyMetadataSummary {
            culture: String::new(),
            ..Default::default()
        };
        assert!(s.is_culture_neutral());
    }

    #[test]
    fn test_culture_non_neutral() {
        let s = AssemblyMetadataSummary {
            culture: "en-US".into(),
            ..Default::default()
        };
        assert!(!s.is_culture_neutral());
    }
}

#[cfg(test)]
mod cil_local_slot_tests {
    use super::*;

    #[test]
    fn test_max_slot_stloc3() {
        // ldc.i4.0, stloc.3, ldc.i4.1, stloc.0, ret
        let code = [0x16_u8, 0x0d, 0x17, 0x0a, 0x2a];
        assert_eq!(cil_max_local_slot(&code).unwrap(), 3);
    }

    #[test]
    fn test_max_slot_no_locals() {
        // ldarg.0, ret (no stloc at all)
        let code = [0x02_u8, 0x2a];
        assert_eq!(cil_max_local_slot(&code).unwrap(), 0);
    }
}

// ---------------------------------------------------------------------------
// CIL constant folding helpers
// ---------------------------------------------------------------------------

/// Constant-fold two i32 operands with a CIL arithmetic mnemonic.
/// Returns `None` if the mnemonic is not a foldable integer operation.
#[must_use]
pub fn cil_fold_i32(mne: &str, a: i32, b: i32) -> Option<i32> {
    Some(match mne {
        "add" => a.wrapping_add(b),
        "sub" => a.wrapping_sub(b),
        "mul" => a.wrapping_mul(b),
        "div" => {
            if b == 0 {
                return None;
            }
            a.wrapping_div(b)
        }
        "rem" => {
            if b == 0 {
                return None;
            }
            a.wrapping_rem(b)
        }
        "and" => a & b,
        "or" => a | b,
        "xor" => a ^ b,
        "shl" => a.wrapping_shl(b as u32),
        "shr" => a >> (b as u32 & 31),
        _ => return None,
    })
}

/// Constant-fold a unary CIL mnemonic on an i32 value.
#[must_use]
pub fn cil_fold_unary_i32(mne: &str, a: i32) -> Option<i32> {
    Some(match mne {
        "neg" => a.wrapping_neg(),
        "not" => !a,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// CIL string pool helpers
// ---------------------------------------------------------------------------

/// A simple string pool that deduplicates string tokens.
#[derive(Debug, Default, Clone)]
pub struct CilStringPool {
    entries: Vec<String>,
}

impl CilStringPool {
    /// Create an empty pool.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern a string and return its index.
    pub fn intern(&mut self, s: &str) -> usize {
        if let Some(i) = self.entries.iter().position(|e| e == s) {
            return i;
        }
        let i = self.entries.len();
        self.entries.push(s.to_string());
        i
    }

    /// Look up a previously interned string by index.
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<&str> {
        self.entries.get(idx).map(String::as_str)
    }

    /// Number of interned strings.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the pool is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CIL opcode alias table
// ---------------------------------------------------------------------------

/// An alias pair for a CIL opcode (long form → short form).
#[derive(Debug, Clone, Copy)]
pub struct CilOpcodeAlias {
    /// Long-form mnemonic.
    pub long_form: &'static str,
    /// Short-form mnemonic (or preferred mnemonic).
    pub short_form: &'static str,
}

/// Common CIL opcode aliases (long ↔ short pairs).
pub static CIL_OPCODE_ALIASES: &[CilOpcodeAlias] = &[
    CilOpcodeAlias {
        long_form: "ldc.i4",
        short_form: "ldc.i4.s",
    },
    CilOpcodeAlias {
        long_form: "br",
        short_form: "br.s",
    },
    CilOpcodeAlias {
        long_form: "brfalse",
        short_form: "brfalse.s",
    },
    CilOpcodeAlias {
        long_form: "brtrue",
        short_form: "brtrue.s",
    },
    CilOpcodeAlias {
        long_form: "beq",
        short_form: "beq.s",
    },
    CilOpcodeAlias {
        long_form: "bne.un",
        short_form: "bne.un.s",
    },
    CilOpcodeAlias {
        long_form: "bge",
        short_form: "bge.s",
    },
    CilOpcodeAlias {
        long_form: "bgt",
        short_form: "bgt.s",
    },
    CilOpcodeAlias {
        long_form: "ble",
        short_form: "ble.s",
    },
    CilOpcodeAlias {
        long_form: "blt",
        short_form: "blt.s",
    },
    CilOpcodeAlias {
        long_form: "leave",
        short_form: "leave.s",
    },
    CilOpcodeAlias {
        long_form: "ldarg",
        short_form: "ldarg.s",
    },
    CilOpcodeAlias {
        long_form: "ldloc",
        short_form: "ldloc.s",
    },
    CilOpcodeAlias {
        long_form: "stloc",
        short_form: "stloc.s",
    },
];

#[cfg(test)]
mod cil_fold_tests {
    use super::*;

    #[test]
    fn test_fold_add() {
        assert_eq!(cil_fold_i32("add", 3, 4), Some(7));
    }

    #[test]
    fn test_fold_sub() {
        assert_eq!(cil_fold_i32("sub", 10, 3), Some(7));
    }

    #[test]
    fn test_fold_mul() {
        assert_eq!(cil_fold_i32("mul", 3, 4), Some(12));
    }

    #[test]
    fn test_fold_div_zero() {
        assert_eq!(cil_fold_i32("div", 5, 0), None);
    }

    #[test]
    fn test_fold_and() {
        assert_eq!(cil_fold_i32("and", 0xFF, 0x0F), Some(0x0F));
    }

    #[test]
    fn test_fold_or() {
        assert_eq!(cil_fold_i32("or", 0xF0, 0x0F), Some(0xFF));
    }

    #[test]
    fn test_fold_xor() {
        assert_eq!(cil_fold_i32("xor", 0xFF, 0xFF), Some(0));
    }

    #[test]
    fn test_fold_neg() {
        assert_eq!(cil_fold_unary_i32("neg", 5), Some(-5));
    }

    #[test]
    fn test_fold_not() {
        assert_eq!(cil_fold_unary_i32("not", 0), Some(-1));
    }

    #[test]
    fn test_fold_unknown() {
        assert_eq!(cil_fold_i32("call", 1, 2), None);
    }

    #[test]
    fn test_string_pool_intern() {
        let mut p = CilStringPool::new();
        let i1 = p.intern("hello");
        let i2 = p.intern("world");
        let i3 = p.intern("hello");
        assert_eq!(i1, i3);
        assert_ne!(i1, i2);
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn test_string_pool_get() {
        let mut p = CilStringPool::new();
        let i = p.intern("System.String");
        assert_eq!(p.get(i), Some("System.String"));
    }

    #[test]
    fn test_string_pool_empty() {
        let p = CilStringPool::new();
        assert!(p.is_empty());
    }

    #[test]
    fn test_opcode_aliases_table_size() {
        assert!(CIL_OPCODE_ALIASES.len() >= 10);
    }

    #[test]
    fn test_opcode_aliases_br() {
        let a = CIL_OPCODE_ALIASES
            .iter()
            .find(|a| a.long_form == "br")
            .unwrap();
        assert_eq!(a.short_form, "br.s");
    }
}
