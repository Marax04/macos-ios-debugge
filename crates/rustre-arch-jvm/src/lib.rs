//! `rustre-arch-jvm`
//!
//! JVM bytecode architecture implementation for the `RustRE` Suite.
//!
//! Decodes all ~200 JVM opcodes as specified in the Java Virtual Machine
//! Specification.  Instructions are variable-length (1–5 bytes) and the VM
//! is big-endian stack-based with no registers.
//!
//! Public API surface:
//! - [`JvmArch`] — implements [`Architecture`]
//! - [`JvmInstr`] — decoded instruction with opcode, mnemonic, operands and size in bytes
//! - [`JvmLinearDisassembler`] — iterator over bytecode
//! - [`wide_opcodes`] — Wide prefix / TABLESWITCH / LOOKUPSWITCH / invoke details
//! - [`jvm_lifter`] — JVM stack → virtual-register lifter

pub mod jvm_bytecode_analysis;
pub mod jvm_lifter;
pub mod wide_opcodes;

/// JVM security analysis: JavaSecurityManager, PrivilegedBlock, ClassLoaderAbuse,
/// SerializationRisk, ReflectionSecurity, JvmSecurity facade.
///
pub mod jvm_security;

/// JVM Constant Pool analysis: CpEntry, CpCategory, InternedString, CpReferences,
/// ConstantPoolOptimizer, CpStats, ConstantPoolAnalysis.
pub mod constant_pool_analysis;

/// Complete Invokedynamic handling: BootstrapMethod, MethodHandle, CallSite,
/// LambdaMetafactory, StringConcatFactory, JvmInvokeDynamic.
pub mod jvm_invoke_dynamic;
pub mod jvm_constant_pool;
pub mod jvm_attribute_parser;
pub mod jvm_bytecode_verifier;

/// Checked, panic-free numeric conversions shared by the JVM decoders.
pub mod numeric;

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
pub enum JvmDecodeError {
    #[error("truncated JVM instruction")]
    Truncated,
    #[error("unknown opcode: {0:#04x}")]
    UnknownOpcode(u8),
    #[error("reserved or implementation-defined opcode: {0:#04x}")]
    Reserved(u8),
    #[error("invalid class file magic: {0:#010x}")]
    InvalidMagic(u32),
}

// ---------------------------------------------------------------------------
// Decoded JVM instruction
// ---------------------------------------------------------------------------

/// A decoded JVM bytecode instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JvmInstr {
    /// Raw bytes including opcode and all operand bytes.
    pub raw: Vec<u8>,
    /// The instruction mnemonic (e.g., `"invokevirtual"`).
    pub mnemonic: String,
    /// Human-readable operands string.
    pub operands: String,
    /// Semantic flags.
    pub flags: InstrFlags,
}

impl JvmInstr {
    /// Decode one JVM instruction from `bytes`.
    ///
    /// Returns `(JvmInstr, bytes_consumed)`.
    ///
    /// # Errors
    ///
    /// Returns [`JvmDecodeError::Truncated`] when the slice is too short,
    /// [`JvmDecodeError::Reserved`] for implementation-defined opcodes in the
    /// range `0xca..=0xff`, or [`JvmDecodeError::UnknownOpcode`] for invalid
    /// sub-opcodes inside `Wide`.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), JvmDecodeError> {
        Self::decode_at(bytes, 0)
    }

    /// Decode one JVM instruction from `bytes` at `pc_offset` within the method
    /// bytecode array. `pc_offset` is required to compute the correct alignment
    /// padding for `tableswitch` and `lookupswitch`.
    ///
    /// # Errors
    ///
    /// Returns [`JvmDecodeError::Truncated`] when the slice is too short,
    /// [`JvmDecodeError::Reserved`] for implementation-defined opcodes, or
    /// [`JvmDecodeError::UnknownOpcode`] for invalid Wide sub-opcodes.
    pub fn decode_at(bytes: &[u8], pc_offset: usize) -> Result<(Self, usize), JvmDecodeError> {
        if bytes.is_empty() {
            return Err(JvmDecodeError::Truncated);
        }
        decode_jvm(bytes, pc_offset)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const fn need(bytes: &[u8], n: usize) -> Result<(), JvmDecodeError> {
    if bytes.len() < n {
        Err(JvmDecodeError::Truncated)
    } else {
        Ok(())
    }
}

fn u16be(bytes: &[u8], off: usize) -> u16 {
    // Callers must guard with need() first; if we get here it's a bug.
    // Return 0 rather than panicking so any future misuse is detectable.
    bytes
        .get(off..off + 2)
        .map_or(0, |s| u16::from_be_bytes([s[0], s[1]]))
}

fn i16be(bytes: &[u8], off: usize) -> i16 {
    bytes
        .get(off..off + 2)
        .map_or(0, |s| i16::from_be_bytes([s[0], s[1]]))
}

fn i32be(bytes: &[u8], off: usize) -> i32 {
    bytes
        .get(off..off + 4)
        .map_or(0, |s| i32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn ok(
    mne: &str,
    ops: impl Into<String>,
    flags: InstrFlags,
    raw: Vec<u8>,
) -> Result<(JvmInstr, usize), JvmDecodeError> {
    let size = raw.len();
    Ok((
        JvmInstr {
            raw,
            mnemonic: mne.to_string(),
            operands: ops.into(),
            flags,
        },
        size,
    ))
}

/// Core decode logic.
fn decode_jvm(bytes: &[u8], pc_offset: usize) -> Result<(JvmInstr, usize), JvmDecodeError> {
    let op = bytes[0];

    match op {
        // ----- Constants -----
        0x00 => ok("nop", "", InstrFlags::NONE, vec![op]),
        0x01 => ok("aconst_null", "", InstrFlags::NONE, vec![op]),
        0x02 => ok("iconst_m1", "", InstrFlags::NONE, vec![op]),
        0x03 => ok("iconst_0", "", InstrFlags::NONE, vec![op]),
        0x04 => ok("iconst_1", "", InstrFlags::NONE, vec![op]),
        0x05 => ok("iconst_2", "", InstrFlags::NONE, vec![op]),
        0x06 => ok("iconst_3", "", InstrFlags::NONE, vec![op]),
        0x07 => ok("iconst_4", "", InstrFlags::NONE, vec![op]),
        0x08 => ok("iconst_5", "", InstrFlags::NONE, vec![op]),
        0x09 => ok("lconst_0", "", InstrFlags::NONE, vec![op]),
        0x0a => ok("lconst_1", "", InstrFlags::NONE, vec![op]),
        0x0b => ok("fconst_0", "", InstrFlags::NONE, vec![op]),
        0x0c => ok("fconst_1", "", InstrFlags::NONE, vec![op]),
        0x0d => ok("fconst_2", "", InstrFlags::NONE, vec![op]),
        0x0e => ok("dconst_0", "", InstrFlags::NONE, vec![op]),
        0x0f => ok("dconst_1", "", InstrFlags::NONE, vec![op]),

        0x10 => {
            need(bytes, 2)?;
            ok(
                "bipush",
                format!("{}", i8::from_ne_bytes([bytes[1]])),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        0x11 => {
            need(bytes, 3)?;
            ok(
                "sipush",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::NONE,
                bytes[..3].to_vec(),
            )
        }
        0x12 => {
            need(bytes, 2)?;
            ok(
                "ldc",
                format!("#{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        0x13 => {
            need(bytes, 3)?;
            ok(
                "ldc_w",
                format!("#{}", u16be(bytes, 1)),
                InstrFlags::NONE,
                bytes[..3].to_vec(),
            )
        }
        0x14 => {
            need(bytes, 3)?;
            ok(
                "ldc2_w",
                format!("#{}", u16be(bytes, 1)),
                InstrFlags::NONE,
                bytes[..3].to_vec(),
            )
        }

        // ----- Loads -----
        0x15 => {
            need(bytes, 2)?;
            ok(
                "iload",
                format!("{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        0x16 => {
            need(bytes, 2)?;
            ok(
                "lload",
                format!("{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        0x17 => {
            need(bytes, 2)?;
            ok(
                "fload",
                format!("{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        0x18 => {
            need(bytes, 2)?;
            ok(
                "dload",
                format!("{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        0x19 => {
            need(bytes, 2)?;
            ok(
                "aload",
                format!("{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        0x1a => ok("iload_0", "", InstrFlags::NONE, vec![op]),
        0x1b => ok("iload_1", "", InstrFlags::NONE, vec![op]),
        0x1c => ok("iload_2", "", InstrFlags::NONE, vec![op]),
        0x1d => ok("iload_3", "", InstrFlags::NONE, vec![op]),
        0x1e => ok("lload_0", "", InstrFlags::NONE, vec![op]),
        0x1f => ok("lload_1", "", InstrFlags::NONE, vec![op]),
        0x20 => ok("lload_2", "", InstrFlags::NONE, vec![op]),
        0x21 => ok("lload_3", "", InstrFlags::NONE, vec![op]),
        0x22 => ok("fload_0", "", InstrFlags::NONE, vec![op]),
        0x23 => ok("fload_1", "", InstrFlags::NONE, vec![op]),
        0x24 => ok("fload_2", "", InstrFlags::NONE, vec![op]),
        0x25 => ok("fload_3", "", InstrFlags::NONE, vec![op]),
        0x26 => ok("dload_0", "", InstrFlags::NONE, vec![op]),
        0x27 => ok("dload_1", "", InstrFlags::NONE, vec![op]),
        0x28 => ok("dload_2", "", InstrFlags::NONE, vec![op]),
        0x29 => ok("dload_3", "", InstrFlags::NONE, vec![op]),
        0x2a => ok("aload_0", "", InstrFlags::NONE, vec![op]),
        0x2b => ok("aload_1", "", InstrFlags::NONE, vec![op]),
        0x2c => ok("aload_2", "", InstrFlags::NONE, vec![op]),
        0x2d => ok("aload_3", "", InstrFlags::NONE, vec![op]),
        // Array loads
        0x2e => ok("iaload", "", InstrFlags::READ_MEM, vec![op]),
        0x2f => ok("laload", "", InstrFlags::READ_MEM, vec![op]),
        0x30 => ok("faload", "", InstrFlags::READ_MEM, vec![op]),
        0x31 => ok("daload", "", InstrFlags::READ_MEM, vec![op]),
        0x32 => ok("aaload", "", InstrFlags::READ_MEM, vec![op]),
        0x33 => ok("baload", "", InstrFlags::READ_MEM, vec![op]),
        0x34 => ok("caload", "", InstrFlags::READ_MEM, vec![op]),
        0x35 => ok("saload", "", InstrFlags::READ_MEM, vec![op]),

        // ----- Stores -----
        0x36 => {
            need(bytes, 2)?;
            ok(
                "istore",
                format!("{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        0x37 => {
            need(bytes, 2)?;
            ok(
                "lstore",
                format!("{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        0x38 => {
            need(bytes, 2)?;
            ok(
                "fstore",
                format!("{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        0x39 => {
            need(bytes, 2)?;
            ok(
                "dstore",
                format!("{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        0x3a => {
            need(bytes, 2)?;
            ok(
                "astore",
                format!("{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        0x3b => ok("istore_0", "", InstrFlags::NONE, vec![op]),
        0x3c => ok("istore_1", "", InstrFlags::NONE, vec![op]),
        0x3d => ok("istore_2", "", InstrFlags::NONE, vec![op]),
        0x3e => ok("istore_3", "", InstrFlags::NONE, vec![op]),
        0x3f => ok("lstore_0", "", InstrFlags::NONE, vec![op]),
        0x40 => ok("lstore_1", "", InstrFlags::NONE, vec![op]),
        0x41 => ok("lstore_2", "", InstrFlags::NONE, vec![op]),
        0x42 => ok("lstore_3", "", InstrFlags::NONE, vec![op]),
        0x43 => ok("fstore_0", "", InstrFlags::NONE, vec![op]),
        0x44 => ok("fstore_1", "", InstrFlags::NONE, vec![op]),
        0x45 => ok("fstore_2", "", InstrFlags::NONE, vec![op]),
        0x46 => ok("fstore_3", "", InstrFlags::NONE, vec![op]),
        0x47 => ok("dstore_0", "", InstrFlags::NONE, vec![op]),
        0x48 => ok("dstore_1", "", InstrFlags::NONE, vec![op]),
        0x49 => ok("dstore_2", "", InstrFlags::NONE, vec![op]),
        0x4a => ok("dstore_3", "", InstrFlags::NONE, vec![op]),
        0x4b => ok("astore_0", "", InstrFlags::NONE, vec![op]),
        0x4c => ok("astore_1", "", InstrFlags::NONE, vec![op]),
        0x4d => ok("astore_2", "", InstrFlags::NONE, vec![op]),
        0x4e => ok("astore_3", "", InstrFlags::NONE, vec![op]),
        // Array stores
        0x4f => ok("iastore", "", InstrFlags::WRITE_MEM, vec![op]),
        0x50 => ok("lastore", "", InstrFlags::WRITE_MEM, vec![op]),
        0x51 => ok("fastore", "", InstrFlags::WRITE_MEM, vec![op]),
        0x52 => ok("dastore", "", InstrFlags::WRITE_MEM, vec![op]),
        0x53 => ok("aastore", "", InstrFlags::WRITE_MEM, vec![op]),
        0x54 => ok("bastore", "", InstrFlags::WRITE_MEM, vec![op]),
        0x55 => ok("castore", "", InstrFlags::WRITE_MEM, vec![op]),
        0x56 => ok("sastore", "", InstrFlags::WRITE_MEM, vec![op]),

        // ----- Stack manipulation -----
        0x57 => ok("pop", "", InstrFlags::NONE, vec![op]),
        0x58 => ok("pop2", "", InstrFlags::NONE, vec![op]),
        0x59 => ok("dup", "", InstrFlags::NONE, vec![op]),
        0x5a => ok("dup_x1", "", InstrFlags::NONE, vec![op]),
        0x5b => ok("dup_x2", "", InstrFlags::NONE, vec![op]),
        0x5c => ok("dup2", "", InstrFlags::NONE, vec![op]),
        0x5d => ok("dup2_x1", "", InstrFlags::NONE, vec![op]),
        0x5e => ok("dup2_x2", "", InstrFlags::NONE, vec![op]),
        0x5f => ok("swap", "", InstrFlags::NONE, vec![op]),

        // ----- Arithmetic -----
        0x60 => ok("iadd", "", InstrFlags::NONE, vec![op]),
        0x61 => ok("ladd", "", InstrFlags::NONE, vec![op]),
        0x62 => ok("fadd", "", InstrFlags::NONE, vec![op]),
        0x63 => ok("dadd", "", InstrFlags::NONE, vec![op]),
        0x64 => ok("isub", "", InstrFlags::NONE, vec![op]),
        0x65 => ok("lsub", "", InstrFlags::NONE, vec![op]),
        0x66 => ok("fsub", "", InstrFlags::NONE, vec![op]),
        0x67 => ok("dsub", "", InstrFlags::NONE, vec![op]),
        0x68 => ok("imul", "", InstrFlags::NONE, vec![op]),
        0x69 => ok("lmul", "", InstrFlags::NONE, vec![op]),
        0x6a => ok("fmul", "", InstrFlags::NONE, vec![op]),
        0x6b => ok("dmul", "", InstrFlags::NONE, vec![op]),
        0x6c => ok("idiv", "", InstrFlags::NONE, vec![op]),
        0x6d => ok("ldiv", "", InstrFlags::NONE, vec![op]),
        0x6e => ok("fdiv", "", InstrFlags::NONE, vec![op]),
        0x6f => ok("ddiv", "", InstrFlags::NONE, vec![op]),
        0x70 => ok("irem", "", InstrFlags::NONE, vec![op]),
        0x71 => ok("lrem", "", InstrFlags::NONE, vec![op]),
        0x72 => ok("frem", "", InstrFlags::NONE, vec![op]),
        0x73 => ok("drem", "", InstrFlags::NONE, vec![op]),
        0x74 => ok("ineg", "", InstrFlags::NONE, vec![op]),
        0x75 => ok("lneg", "", InstrFlags::NONE, vec![op]),
        0x76 => ok("fneg", "", InstrFlags::NONE, vec![op]),
        0x77 => ok("dneg", "", InstrFlags::NONE, vec![op]),
        0x78 => ok("ishl", "", InstrFlags::NONE, vec![op]),
        0x79 => ok("lshl", "", InstrFlags::NONE, vec![op]),
        0x7a => ok("ishr", "", InstrFlags::NONE, vec![op]),
        0x7b => ok("lshr", "", InstrFlags::NONE, vec![op]),
        0x7c => ok("iushr", "", InstrFlags::NONE, vec![op]),
        0x7d => ok("lushr", "", InstrFlags::NONE, vec![op]),
        0x7e => ok("iand", "", InstrFlags::NONE, vec![op]),
        0x7f => ok("land", "", InstrFlags::NONE, vec![op]),
        0x80 => ok("ior", "", InstrFlags::NONE, vec![op]),
        0x81 => ok("lor", "", InstrFlags::NONE, vec![op]),
        0x82 => ok("ixor", "", InstrFlags::NONE, vec![op]),
        0x83 => ok("lxor", "", InstrFlags::NONE, vec![op]),
        0x84 => {
            // Iinc  index  const
            need(bytes, 3)?;
            ok(
                "iinc",
                format!("{}, {}", bytes[1], i8::from_ne_bytes([bytes[2]])),
                InstrFlags::NONE,
                bytes[..3].to_vec(),
            )
        }

        // ----- Conversions -----
        0x85 => ok("i2l", "", InstrFlags::NONE, vec![op]),
        0x86 => ok("i2f", "", InstrFlags::NONE, vec![op]),
        0x87 => ok("i2d", "", InstrFlags::NONE, vec![op]),
        0x88 => ok("l2i", "", InstrFlags::NONE, vec![op]),
        0x89 => ok("l2f", "", InstrFlags::NONE, vec![op]),
        0x8a => ok("l2d", "", InstrFlags::NONE, vec![op]),
        0x8b => ok("f2i", "", InstrFlags::NONE, vec![op]),
        0x8c => ok("f2l", "", InstrFlags::NONE, vec![op]),
        0x8d => ok("f2d", "", InstrFlags::NONE, vec![op]),
        0x8e => ok("d2i", "", InstrFlags::NONE, vec![op]),
        0x8f => ok("d2l", "", InstrFlags::NONE, vec![op]),
        0x90 => ok("d2f", "", InstrFlags::NONE, vec![op]),
        0x91 => ok("i2b", "", InstrFlags::NONE, vec![op]),
        0x92 => ok("i2c", "", InstrFlags::NONE, vec![op]),
        0x93 => ok("i2s", "", InstrFlags::NONE, vec![op]),

        // ----- Comparisons -----
        0x94 => ok("lcmp", "", InstrFlags::NONE, vec![op]),
        0x95 => ok("fcmpl", "", InstrFlags::NONE, vec![op]),
        0x96 => ok("fcmpg", "", InstrFlags::NONE, vec![op]),
        0x97 => ok("dcmpl", "", InstrFlags::NONE, vec![op]),
        0x98 => ok("dcmpg", "", InstrFlags::NONE, vec![op]),

        // ----- Control flow -----
        0x99 => {
            need(bytes, 3)?;
            ok(
                "ifeq",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..3].to_vec(),
            )
        }
        0x9a => {
            need(bytes, 3)?;
            ok(
                "ifne",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..3].to_vec(),
            )
        }
        0x9b => {
            need(bytes, 3)?;
            ok(
                "iflt",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..3].to_vec(),
            )
        }
        0x9c => {
            need(bytes, 3)?;
            ok(
                "ifge",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..3].to_vec(),
            )
        }
        0x9d => {
            need(bytes, 3)?;
            ok(
                "ifgt",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..3].to_vec(),
            )
        }
        0x9e => {
            need(bytes, 3)?;
            ok(
                "ifle",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..3].to_vec(),
            )
        }
        0x9f => {
            need(bytes, 3)?;
            ok(
                "if_icmpeq",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..3].to_vec(),
            )
        }
        0xa0 => {
            need(bytes, 3)?;
            ok(
                "if_icmpne",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..3].to_vec(),
            )
        }
        0xa1 => {
            need(bytes, 3)?;
            ok(
                "if_icmplt",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..3].to_vec(),
            )
        }
        0xa2 => {
            need(bytes, 3)?;
            ok(
                "if_icmpge",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..3].to_vec(),
            )
        }
        0xa3 => {
            need(bytes, 3)?;
            ok(
                "if_icmpgt",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..3].to_vec(),
            )
        }
        0xa4 => {
            need(bytes, 3)?;
            ok(
                "if_icmple",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..3].to_vec(),
            )
        }
        0xa5 => {
            need(bytes, 3)?;
            ok(
                "if_acmpeq",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..3].to_vec(),
            )
        }
        0xa6 => {
            need(bytes, 3)?;
            ok(
                "if_acmpne",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..3].to_vec(),
            )
        }
        0xa7 => {
            need(bytes, 3)?;
            ok(
                "goto",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::BRANCH,
                bytes[..3].to_vec(),
            )
        }
        0xa8 => {
            need(bytes, 3)?;
            ok(
                "jsr",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::CALL,
                bytes[..3].to_vec(),
            )
        }
        0xa9 => {
            need(bytes, 2)?;
            ok(
                "ret",
                format!("{}", bytes[1]),
                InstrFlags::RET,
                bytes[..2].to_vec(),
            )
        }

        // Tableswitch
        0xaa => {
            // Padding bytes so that (pc_offset + 1 + pad) ≡ 0 (mod 4).
            // The JVM spec requires the default/low/high words to start on a
            // 4-byte boundary relative to the start of the method bytecode.
            let pad = (4 - ((pc_offset + 1) % 4)) % 4;
            let base = 1 + pad;
            need(bytes, base + 12)?;
            let default_off = i32be(bytes, base);
            let low = i32be(bytes, base + 4);
            let high = i32be(bytes, base + 8);
            let count = u32::try_from((i64::from(high) - i64::from(low) + 1).max(0)).unwrap_or(0) as usize;
            // Guard against overflow: count * 4 must fit in usize.
            let entries_bytes = count.checked_mul(4).ok_or(JvmDecodeError::Truncated)?;
            let total = (base + 12).checked_add(entries_bytes).ok_or(JvmDecodeError::Truncated)?;
            need(bytes, total)?;
            ok(
                "tableswitch",
                format!("low={low} high={high} default={default_off}"),
                InstrFlags::BRANCH,
                bytes[..total].to_vec(),
            )
        }

        // Lookupswitch
        0xab => {
            let pad = (4 - ((pc_offset + 1) % 4)) % 4;
            let base = 1 + pad;
            need(bytes, base + 8)?;
            let default_off = i32be(bytes, base);
            let npairs = u32::try_from(i32be(bytes, base + 4).max(0)).unwrap_or(0) as usize;
            // Guard against overflow: npairs * 8 must fit in usize.
            let pairs_bytes = npairs.checked_mul(8).ok_or(JvmDecodeError::Truncated)?;
            let total = (base + 8).checked_add(pairs_bytes).ok_or(JvmDecodeError::Truncated)?;
            need(bytes, total)?;
            ok(
                "lookupswitch",
                format!("npairs={npairs} default={default_off}"),
                InstrFlags::BRANCH,
                bytes[..total].to_vec(),
            )
        }

        0xac => ok("ireturn", "", InstrFlags::RET, vec![op]),
        0xad => ok("lreturn", "", InstrFlags::RET, vec![op]),
        0xae => ok("freturn", "", InstrFlags::RET, vec![op]),
        0xaf => ok("dreturn", "", InstrFlags::RET, vec![op]),
        0xb0 => ok("areturn", "", InstrFlags::RET, vec![op]),
        0xb1 => ok("return", "", InstrFlags::RET, vec![op]),

        // ----- References -----
        0xb2 => {
            need(bytes, 3)?;
            ok(
                "getstatic",
                format!("#{}", u16be(bytes, 1)),
                InstrFlags::NONE,
                bytes[..3].to_vec(),
            )
        }
        0xb3 => {
            need(bytes, 3)?;
            ok(
                "putstatic",
                format!("#{}", u16be(bytes, 1)),
                InstrFlags::NONE,
                bytes[..3].to_vec(),
            )
        }
        0xb4 => {
            need(bytes, 3)?;
            ok(
                "getfield",
                format!("#{}", u16be(bytes, 1)),
                InstrFlags::READ_MEM,
                bytes[..3].to_vec(),
            )
        }
        0xb5 => {
            need(bytes, 3)?;
            ok(
                "putfield",
                format!("#{}", u16be(bytes, 1)),
                InstrFlags::WRITE_MEM,
                bytes[..3].to_vec(),
            )
        }
        0xb6 => {
            need(bytes, 3)?;
            ok(
                "invokevirtual",
                format!("#{}", u16be(bytes, 1)),
                InstrFlags::CALL | InstrFlags::INDIRECT,
                bytes[..3].to_vec(),
            )
        }
        0xb7 => {
            need(bytes, 3)?;
            ok(
                "invokespecial",
                format!("#{}", u16be(bytes, 1)),
                InstrFlags::CALL,
                bytes[..3].to_vec(),
            )
        }
        0xb8 => {
            need(bytes, 3)?;
            ok(
                "invokestatic",
                format!("#{}", u16be(bytes, 1)),
                InstrFlags::CALL,
                bytes[..3].to_vec(),
            )
        }
        0xb9 => {
            need(bytes, 5)?;
            ok(
                "invokeinterface",
                format!("#{} count={}", u16be(bytes, 1), bytes[3]),
                InstrFlags::CALL | InstrFlags::INDIRECT,
                bytes[..5].to_vec(),
            )
        }
        0xba => {
            need(bytes, 5)?;
            ok(
                "invokedynamic",
                format!("#{}", u16be(bytes, 1)),
                InstrFlags::CALL | InstrFlags::INDIRECT,
                bytes[..5].to_vec(),
            )
        }
        0xbb => {
            need(bytes, 3)?;
            ok(
                "new",
                format!("#{}", u16be(bytes, 1)),
                InstrFlags::NONE,
                bytes[..3].to_vec(),
            )
        }
        0xbc => {
            need(bytes, 2)?;
            ok(
                "newarray",
                format!("{}", bytes[1]),
                InstrFlags::NONE,
                bytes[..2].to_vec(),
            )
        }
        0xbd => {
            need(bytes, 3)?;
            ok(
                "anewarray",
                format!("#{}", u16be(bytes, 1)),
                InstrFlags::NONE,
                bytes[..3].to_vec(),
            )
        }
        0xbe => ok("arraylength", "", InstrFlags::NONE, vec![op]),
        0xbf => ok("athrow", "", InstrFlags::BRANCH, vec![op]),
        0xc0 => {
            need(bytes, 3)?;
            ok(
                "checkcast",
                format!("#{}", u16be(bytes, 1)),
                InstrFlags::NONE,
                bytes[..3].to_vec(),
            )
        }
        0xc1 => {
            need(bytes, 3)?;
            ok(
                "instanceof",
                format!("#{}", u16be(bytes, 1)),
                InstrFlags::NONE,
                bytes[..3].to_vec(),
            )
        }
        0xc2 => ok("monitorenter", "", InstrFlags::BARRIER, vec![op]),
        0xc3 => ok("monitorexit", "", InstrFlags::BARRIER, vec![op]),

        // ----- Wide prefix -----
        0xc4 => {
            need(bytes, 2)?;
            let sub = bytes[1];
            match sub {
                0x15 | 0x16 | 0x17 | 0x18 | 0x19 | 0x36 | 0x37 | 0x38 | 0x39 | 0x3a | 0xa9 => {
                    need(bytes, 4)?;
                    let mne = match sub {
                        0x15 => "Wide Iload",
                        0x16 => "Wide Lload",
                        0x17 => "Wide Fload",
                        0x18 => "Wide Dload",
                        0x19 => "Wide Aload",
                        0x36 => "Wide Istore",
                        0x37 => "Wide Lstore",
                        0x38 => "Wide Fstore",
                        0x39 => "Wide Dstore",
                        0x3a => "Wide Astore",
                        0xa9 => "Wide Ret",
                        _ => "Wide ?",
                    };
                    ok(
                        mne,
                        format!("{}", u16be(bytes, 2)),
                        InstrFlags::NONE,
                        bytes[..4].to_vec(),
                    )
                }
                0x84 => {
                    need(bytes, 6)?;
                    ok(
                        "Wide Iinc",
                        format!("{}, {}", u16be(bytes, 2), i16be(bytes, 4)),
                        InstrFlags::NONE,
                        bytes[..6].to_vec(),
                    )
                }
                _ => Err(JvmDecodeError::UnknownOpcode(sub)),
            }
        }

        0xc5 => {
            need(bytes, 4)?;
            ok(
                "multianewarray",
                format!("#{} dims={}", u16be(bytes, 1), bytes[3]),
                InstrFlags::NONE,
                bytes[..4].to_vec(),
            )
        }
        0xc6 => {
            need(bytes, 3)?;
            ok(
                "ifnull",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..3].to_vec(),
            )
        }
        0xc7 => {
            need(bytes, 3)?;
            ok(
                "ifnonnull",
                format!("{}", i16be(bytes, 1)),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                bytes[..3].to_vec(),
            )
        }
        0xc8 => {
            need(bytes, 5)?;
            ok(
                "goto_w",
                format!("{}", i32be(bytes, 1)),
                InstrFlags::BRANCH,
                bytes[..5].to_vec(),
            )
        }
        0xc9 => {
            need(bytes, 5)?;
            ok(
                "jsr_w",
                format!("{}", i32be(bytes, 1)),
                InstrFlags::CALL,
                bytes[..5].to_vec(),
            )
        }

        // Implementation-defined / reserved
        0xca..=0xff => Err(JvmDecodeError::Reserved(op)),
    }
}

// ---------------------------------------------------------------------------
// JvmArch
// ---------------------------------------------------------------------------

/// Architecture implementation for JVM bytecode.
#[derive(Debug, Clone)]
pub struct JvmArch;

impl Architecture for JvmArch {
    fn name(&self) -> &'static str {
        "jvm"
    }

    fn pointer_size(&self) -> usize {
        // References are 4 bytes in the JVM (class file index space).
        4
    }

    fn endian(&self) -> Endian {
        // JVM is big-endian.
        Endian::Big
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        let pc_offset = crate::numeric::u64_to_usize(address.as_u64());
        let (decoded, consumed) = JvmInstr::decode_at(bytes, pc_offset).map_err(|e| CoreError::PluginError {
            plugin: "jvm".into(),
            message: e.to_string(),
        })?;

        let mut instr = Instruction::new(address, consumed, decoded.mnemonic, decoded.raw);
        instr.operands = decoded.operands;
        instr.flags = decoded.flags;
        Ok(instr)
    }

    fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo> {
        if !instr
            .flags
            .intersects(InstrFlags::BRANCH | InstrFlags::CALL)
        {
            return vec![];
        }
        let opcode = match instr.bytes.first() {
            Some(b) => *b,
            None => return vec![],
        };
        let target = match opcode {
            // goto_w / jsr_w: 4-byte signed offset at bytes[1..5]
            0xc8 | 0xc9 if instr.bytes.len() >= 5 => {
                let off = i32::from_be_bytes([
                    instr.bytes[1],
                    instr.bytes[2],
                    instr.bytes[3],
                    instr.bytes[4],
                ]);
                instr.address.as_u64().wrapping_add_signed(i64::from(off))
            }
            // tableswitch / lookupswitch: variable-length, no single branch target
            0xaa | 0xab => return vec![],
            // Standard 2-byte signed offset branches
            _ if instr.bytes.len() >= 3 => {
                let off = i16::from_be_bytes([instr.bytes[1], instr.bytes[2]]);
                instr.address.as_u64().wrapping_add_signed(i64::from(off))
            }
            _ => return vec![],
        };
        let branch = if instr.flags.contains(InstrFlags::CALL) {
            BranchInfo::call(target)
        } else if instr.flags.contains(InstrFlags::CONDITIONAL) {
            BranchInfo::conditional_jump(target, BranchCondition::Custom(0))
        } else {
            BranchInfo::unconditional_jump(target)
        };
        vec![branch]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        // JVM has no architectural registers (stack machine); expose the
        // conventional local variable slots 0-3.
        (0u32..=3u32)
            .map(|i| RegisterInfo::new(format!("local{i}"), i, 4, RegisterKind::General))
            .collect()
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        let mut cc = CallingConvention::new("jvm_invoke");
        cc.caller_cleans_stack = false;
        vec![cc]
    }
}

// ---------------------------------------------------------------------------
// Linear disassembler
// ---------------------------------------------------------------------------

/// Iterator that decodes JVM bytecode linearly.
pub struct JvmLinearDisassembler<'a> {
    arch: &'a JvmArch,
    bytes: &'a [u8],
    address: Address,
    offset: usize,
}

impl<'a> JvmLinearDisassembler<'a> {
    /// Construct a new disassembler from `bytes` starting at `base_address`.
    #[must_use]
    pub const fn new(arch: &'a JvmArch, bytes: &'a [u8], base_address: Address) -> Self {
        Self {
            arch,
            bytes,
            address: base_address,
            offset: 0,
        }
    }
}

impl Iterator for JvmLinearDisassembler<'_> {
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

    fn arch() -> JvmArch {
        JvmArch
    }

    fn addr(n: u64) -> Address {
        Address::new(n)
    }

    // --- basic decode ---

    #[test]
    fn test_nop() {
        let (i, sz) = JvmInstr::decode(&[0x00]).unwrap();
        assert_eq!(sz, 1);
        assert_eq!(i.mnemonic, "nop");
    }

    #[test]
    fn test_iconst_m1() {
        let (i, sz) = JvmInstr::decode(&[0x02]).unwrap();
        assert_eq!(sz, 1);
        assert_eq!(i.mnemonic, "iconst_m1");
    }

    #[test]
    fn test_bipush() {
        let (i, sz) = JvmInstr::decode(&[0x10, 0x7f]).unwrap();
        assert_eq!(sz, 2);
        assert_eq!(i.mnemonic, "bipush");
        assert!(i.operands.contains("127"));
    }

    #[test]
    fn test_sipush() {
        let (i, sz) = JvmInstr::decode(&[0x11, 0x01, 0x00]).unwrap();
        assert_eq!(sz, 3);
        assert_eq!(i.mnemonic, "sipush");
        assert!(i.operands.contains("256"));
    }

    #[test]
    fn test_ldc() {
        let (i, sz) = JvmInstr::decode(&[0x12, 0x05]).unwrap();
        assert_eq!(sz, 2);
        assert_eq!(i.mnemonic, "ldc");
        assert!(i.operands.contains('#'));
    }

    #[test]
    fn test_iload() {
        let (i, sz) = JvmInstr::decode(&[0x15, 0x02]).unwrap();
        assert_eq!(sz, 2);
        assert_eq!(i.mnemonic, "iload");
        assert!(i.operands.contains('2'));
    }

    #[test]
    fn test_iload_0_through_3() {
        for (op, expected) in [
            (0x1a_u8, "iload_0"),
            (0x1b, "iload_1"),
            (0x1c, "iload_2"),
            (0x1d, "iload_3"),
        ] {
            let (i, sz) = JvmInstr::decode(&[op]).unwrap();
            assert_eq!(sz, 1);
            assert_eq!(i.mnemonic, expected);
        }
    }

    #[test]
    fn test_aload_0() {
        let (i, _) = JvmInstr::decode(&[0x2a]).unwrap();
        assert_eq!(i.mnemonic, "aload_0");
    }

    #[test]
    fn test_iaload_flags() {
        let (i, _) = JvmInstr::decode(&[0x2e]).unwrap();
        assert_eq!(i.mnemonic, "iaload");
        assert!(i.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_iastore_flags() {
        let (i, _) = JvmInstr::decode(&[0x4f]).unwrap();
        assert_eq!(i.mnemonic, "iastore");
        assert!(i.flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_dup() {
        let (i, sz) = JvmInstr::decode(&[0x59]).unwrap();
        assert_eq!(sz, 1);
        assert_eq!(i.mnemonic, "dup");
    }

    #[test]
    fn test_iadd() {
        let (i, sz) = JvmInstr::decode(&[0x60]).unwrap();
        assert_eq!(sz, 1);
        assert_eq!(i.mnemonic, "iadd");
    }

    #[test]
    fn test_iinc() {
        let (i, sz) = JvmInstr::decode(&[0x84, 0x02, 0x01]).unwrap();
        assert_eq!(sz, 3);
        assert_eq!(i.mnemonic, "iinc");
        assert!(i.operands.contains('2') && i.operands.contains('1'));
    }

    #[test]
    fn test_i2l() {
        let (i, _) = JvmInstr::decode(&[0x85]).unwrap();
        assert_eq!(i.mnemonic, "i2l");
    }

    #[test]
    fn test_ifeq_branch_flags() {
        let (i, sz) = JvmInstr::decode(&[0x99, 0x00, 0x08]).unwrap();
        assert_eq!(sz, 3);
        assert_eq!(i.mnemonic, "ifeq");
        assert!(i.flags.contains(InstrFlags::BRANCH));
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_goto_branch_flag() {
        let (i, _) = JvmInstr::decode(&[0xa7, 0xff, 0xf0]).unwrap();
        assert_eq!(i.mnemonic, "goto");
        assert!(i.flags.contains(InstrFlags::BRANCH));
        assert!(!i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_ireturn() {
        let (i, sz) = JvmInstr::decode(&[0xac]).unwrap();
        assert_eq!(sz, 1);
        assert_eq!(i.mnemonic, "ireturn");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_return() {
        let (i, _) = JvmInstr::decode(&[0xb1]).unwrap();
        assert_eq!(i.mnemonic, "return");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_invokevirtual() {
        let (i, sz) = JvmInstr::decode(&[0xb6, 0x00, 0x1c]).unwrap();
        assert_eq!(sz, 3);
        assert_eq!(i.mnemonic, "invokevirtual");
        assert!(i.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_invokestatic() {
        let (i, sz) = JvmInstr::decode(&[0xb8, 0x00, 0x04]).unwrap();
        assert_eq!(sz, 3);
        assert_eq!(i.mnemonic, "invokestatic");
        assert!(i.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_invokeinterface_5_bytes() {
        let (i, sz) = JvmInstr::decode(&[0xb9, 0x00, 0x10, 0x02, 0x00]).unwrap();
        assert_eq!(sz, 5);
        assert_eq!(i.mnemonic, "invokeinterface");
    }

    #[test]
    fn test_new() {
        let (i, sz) = JvmInstr::decode(&[0xbb, 0x00, 0x0a]).unwrap();
        assert_eq!(sz, 3);
        assert_eq!(i.mnemonic, "new");
    }

    #[test]
    fn test_athrow() {
        let (i, _) = JvmInstr::decode(&[0xbf]).unwrap();
        assert_eq!(i.mnemonic, "athrow");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_monitorenter_barrier() {
        let (i, _) = JvmInstr::decode(&[0xc2]).unwrap();
        assert_eq!(i.mnemonic, "monitorenter");
        assert!(i.flags.contains(InstrFlags::BARRIER));
    }

    #[test]
    fn test_wide_iload() {
        let (i, sz) = JvmInstr::decode(&[0xc4, 0x15, 0x01, 0x00]).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(i.mnemonic, "Wide Iload");
    }

    #[test]
    fn test_wide_iinc() {
        let (i, sz) = JvmInstr::decode(&[0xc4, 0x84, 0x00, 0x05, 0x00, 0x01]).unwrap();
        assert_eq!(sz, 6);
        assert_eq!(i.mnemonic, "Wide Iinc");
    }

    #[test]
    fn test_goto_w() {
        let (i, sz) = JvmInstr::decode(&[0xc8, 0x00, 0x00, 0x00, 0x10]).unwrap();
        assert_eq!(sz, 5);
        assert_eq!(i.mnemonic, "goto_w");
    }

    #[test]
    fn test_reserved_opcode() {
        assert!(matches!(
            JvmInstr::decode(&[0xff]),
            Err(JvmDecodeError::Reserved(0xff))
        ));
    }

    #[test]
    fn test_truncated() {
        assert!(matches!(
            JvmInstr::decode(&[]),
            Err(JvmDecodeError::Truncated)
        ));
        assert!(matches!(
            JvmInstr::decode(&[0x10]),
            Err(JvmDecodeError::Truncated)
        ));
    }

    // --- Architecture trait ---

    #[test]
    fn test_arch_name() {
        assert_eq!(arch().name(), "jvm");
    }

    #[test]
    fn test_arch_endian_big() {
        assert_eq!(arch().endian(), Endian::Big);
    }

    #[test]
    fn test_arch_pointer_size() {
        assert_eq!(arch().pointer_size(), 4);
    }

    #[test]
    fn test_arch_disassemble_nop() {
        let instr = arch().disassemble(addr(0), &[0x00]).unwrap();
        assert_eq!(instr.mnemonic, "nop");
        assert_eq!(instr.size, 1);
    }

    #[test]
    fn test_arch_disassemble_error() {
        assert!(arch().disassemble(addr(0), &[]).is_err());
    }

    #[test]
    fn test_arch_registers_present() {
        assert!(!arch().registers().is_empty());
    }

    // --- Linear disassembler ---

    #[test]
    fn test_linear_disassembler_simple() {
        let a = arch();
        // Iconst1  Iadd  Ireturn
        let prog = [0x04_u8, 0x60, 0xac];
        let instrs: Vec<_> = JvmLinearDisassembler::new(&a, &prog, addr(0))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs.len(), 3);
        assert_eq!(instrs[0].mnemonic, "iconst_1");
        assert_eq!(instrs[1].mnemonic, "iadd");
        assert_eq!(instrs[2].mnemonic, "ireturn");
    }

    #[test]
    fn test_linear_disassembler_addresses() {
        let a = arch();
        let prog = [0x00_u8, 0x00, 0xb1]; // Nop, Nop, return
        let instrs: Vec<_> = JvmLinearDisassembler::new(&a, &prog, addr(0x10))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs[0].address, addr(0x10));
        assert_eq!(instrs[1].address, addr(0x11));
        assert_eq!(instrs[2].address, addr(0x12));
    }

    #[test]
    fn test_linear_disassembler_empty() {
        let a = arch();
        assert_eq!(JvmLinearDisassembler::new(&a, &[], addr(0)).count(), 0);
    }
}

// ---------------------------------------------------------------------------
// Constant pool tags (JVM class file §4.4)
// ---------------------------------------------------------------------------

/// Tag byte values for constant pool entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ConstantPoolTag {
    /// `CONSTANT_Utf8` — UTF-8 encoded string.
    Utf8 = 1,
    /// `CONSTANT_Integer` — 4-byte int.
    Integer = 3,
    /// `CONSTANT_Float` — 4-byte float.
    Float = 4,
    /// `CONSTANT_Long` — 8-byte long (occupies two slots).
    Long = 5,
    /// `CONSTANT_Double` — 8-byte double (occupies two slots).
    Double = 6,
    /// `CONSTANT_Class` — symbolic reference to a class/interface.
    Class = 7,
    /// `CONSTANT_String` — string object.
    String = 8,
    /// `CONSTANT_Fieldref` — field reference.
    Fieldref = 9,
    /// `CONSTANT_Methodref` — method reference.
    Methodref = 10,
    /// `CONSTANT_InterfaceMethodref` — interface method reference.
    InterfaceMethodref = 11,
    /// `CONSTANT_NameAndType` — name and type descriptor.
    NameAndType = 12,
    /// `CONSTANT_MethodHandle` — method handle (Java 7+).
    MethodHandle = 15,
    /// `CONSTANT_MethodType` — method type (Java 7+).
    MethodType = 16,
    /// `CONSTANT_Dynamic` — dynamically-computed constant (Java 11+).
    Dynamic = 17,
    /// `CONSTANT_InvokeDynamic` — invoke-dynamic bootstrap (Java 7+).
    InvokeDynamic = 18,
    /// `CONSTANT_Module` — module reference (Java 9+).
    Module = 19,
    /// `CONSTANT_Package` — package reference (Java 9+).
    Package = 20,
}

impl ConstantPoolTag {
    /// Decode a tag byte into a `ConstantPoolTag`.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Utf8,
            3 => Self::Integer,
            4 => Self::Float,
            5 => Self::Long,
            6 => Self::Double,
            7 => Self::Class,
            8 => Self::String,
            9 => Self::Fieldref,
            10 => Self::Methodref,
            11 => Self::InterfaceMethodref,
            12 => Self::NameAndType,
            15 => Self::MethodHandle,
            16 => Self::MethodType,
            17 => Self::Dynamic,
            18 => Self::InvokeDynamic,
            19 => Self::Module,
            20 => Self::Package,
            _ => return None,
        })
    }

    /// Return the human-readable name of the tag.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Utf8 => "CONSTANT_Utf8",
            Self::Integer => "CONSTANT_Integer",
            Self::Float => "CONSTANT_Float",
            Self::Long => "CONSTANT_Long",
            Self::Double => "CONSTANT_Double",
            Self::Class => "CONSTANT_Class",
            Self::String => "CONSTANT_String",
            Self::Fieldref => "CONSTANT_Fieldref",
            Self::Methodref => "CONSTANT_Methodref",
            Self::InterfaceMethodref => "CONSTANT_InterfaceMethodref",
            Self::NameAndType => "CONSTANT_NameAndType",
            Self::MethodHandle => "CONSTANT_MethodHandle",
            Self::MethodType => "CONSTANT_MethodType",
            Self::Dynamic => "CONSTANT_Dynamic",
            Self::InvokeDynamic => "CONSTANT_InvokeDynamic",
            Self::Module => "CONSTANT_Module",
            Self::Package => "CONSTANT_Package",
        }
    }

    /// Returns `true` for long/double entries that occupy two constant-pool slots.
    #[must_use]
    pub const fn is_wide(self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }
}

// ---------------------------------------------------------------------------
// Class file attribute types (JVM §4.7)
// ---------------------------------------------------------------------------

/// Predefined class-file attribute names as per JVM specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttributeKind {
    ConstantValue,
    Code,
    StackMapTable,
    BootstrapMethods,
    NestHost,
    NestMembers,
    PermittedSubclasses,
    Exceptions,
    InnerClasses,
    EnclosingMethod,
    Synthetic,
    Signature,
    Record,
    SourceFile,
    LineNumberTable,
    LocalVariableTable,
    LocalVariableTypeTable,
    Deprecated,
    RuntimeVisibleAnnotations,
    RuntimeInvisibleAnnotations,
    RuntimeVisibleParameterAnnotations,
    RuntimeInvisibleParameterAnnotations,
    RuntimeVisibleTypeAnnotations,
    RuntimeInvisibleTypeAnnotations,
    AnnotationDefault,
    MethodParameters,
    Module,
    ModulePackages,
    ModuleMainClass,
    SourceDebugExtension,
}

impl AttributeKind {
    /// Return the attribute name string as it appears in the class file.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConstantValue => "ConstantValue",
            Self::Code => "Code",
            Self::StackMapTable => "StackMapTable",
            Self::BootstrapMethods => "BootstrapMethods",
            Self::NestHost => "NestHost",
            Self::NestMembers => "NestMembers",
            Self::PermittedSubclasses => "PermittedSubclasses",
            Self::Exceptions => "Exceptions",
            Self::InnerClasses => "InnerClasses",
            Self::EnclosingMethod => "EnclosingMethod",
            Self::Synthetic => "Synthetic",
            Self::Signature => "Signature",
            Self::Record => "Record",
            Self::SourceFile => "SourceFile",
            Self::LineNumberTable => "LineNumberTable",
            Self::LocalVariableTable => "LocalVariableTable",
            Self::LocalVariableTypeTable => "LocalVariableTypeTable",
            Self::Deprecated => "Deprecated",
            Self::RuntimeVisibleAnnotations => "RuntimeVisibleAnnotations",
            Self::RuntimeInvisibleAnnotations => "RuntimeInvisibleAnnotations",
            Self::RuntimeVisibleParameterAnnotations => "RuntimeVisibleParameterAnnotations",
            Self::RuntimeInvisibleParameterAnnotations => "RuntimeInvisibleParameterAnnotations",
            Self::RuntimeVisibleTypeAnnotations => "RuntimeVisibleTypeAnnotations",
            Self::RuntimeInvisibleTypeAnnotations => "RuntimeInvisibleTypeAnnotations",
            Self::AnnotationDefault => "AnnotationDefault",
            Self::MethodParameters => "MethodParameters",
            Self::Module => "Module",
            Self::ModulePackages => "ModulePackages",
            Self::ModuleMainClass => "ModuleMainClass",
            Self::SourceDebugExtension => "SourceDebugExtension",
        }
    }

    /// Parse an attribute name string into an `AttributeKind`, if known.
    #[must_use]
    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "ConstantValue" => Self::ConstantValue,
            "Code" => Self::Code,
            "StackMapTable" => Self::StackMapTable,
            "BootstrapMethods" => Self::BootstrapMethods,
            "NestHost" => Self::NestHost,
            "NestMembers" => Self::NestMembers,
            "PermittedSubclasses" => Self::PermittedSubclasses,
            "Exceptions" => Self::Exceptions,
            "InnerClasses" => Self::InnerClasses,
            "EnclosingMethod" => Self::EnclosingMethod,
            "Synthetic" => Self::Synthetic,
            "Signature" => Self::Signature,
            "Record" => Self::Record,
            "SourceFile" => Self::SourceFile,
            "LineNumberTable" => Self::LineNumberTable,
            "LocalVariableTable" => Self::LocalVariableTable,
            "LocalVariableTypeTable" => Self::LocalVariableTypeTable,
            "Deprecated" => Self::Deprecated,
            "RuntimeVisibleAnnotations" => Self::RuntimeVisibleAnnotations,
            "RuntimeInvisibleAnnotations" => Self::RuntimeInvisibleAnnotations,
            "RuntimeVisibleParameterAnnotations" => Self::RuntimeVisibleParameterAnnotations,
            "RuntimeInvisibleParameterAnnotations" => Self::RuntimeInvisibleParameterAnnotations,
            "RuntimeVisibleTypeAnnotations" => Self::RuntimeVisibleTypeAnnotations,
            "RuntimeInvisibleTypeAnnotations" => Self::RuntimeInvisibleTypeAnnotations,
            "AnnotationDefault" => Self::AnnotationDefault,
            "MethodParameters" => Self::MethodParameters,
            "Module" => Self::Module,
            "ModulePackages" => Self::ModulePackages,
            "ModuleMainClass" => Self::ModuleMainClass,
            "SourceDebugExtension" => Self::SourceDebugExtension,
            _ => return None,
        })
    }
}

// ---------------------------------------------------------------------------
// Stack frame verification types (JVM §4.10.1)
// ---------------------------------------------------------------------------

/// A verification type as used in `StackMapTable` attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationType {
    /// The `Top` type (uninitialised or unused slot).
    Top,
    /// A 32-bit integer.
    Integer,
    /// A 64-bit float.
    Float,
    /// A 64-bit integer (occupies two slots).
    Long,
    /// A 64-bit double (occupies two slots).
    Double,
    /// Null reference.
    Null,
    /// `UninitializedThis` — receiver before `super.<init>` call.
    UninitializedThis,
    /// An object reference of a specific class.
    Object(u16),
    /// An uninitialised object created at the given bytecode offset.
    Uninitialized(u16),
}

impl VerificationType {
    /// Decode a verification type from the byte stream.
    ///
    /// # Errors
    ///
    /// Returns `JvmDecodeError::Truncated` when the byte slice is too short.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), JvmDecodeError> {
        if bytes.is_empty() {
            return Err(JvmDecodeError::Truncated);
        }
        Ok(match bytes[0] {
            0 => (Self::Top, 1),
            1 => (Self::Integer, 1),
            2 => (Self::Float, 1),
            3 => (Self::Double, 1),
            4 => (Self::Long, 1),
            5 => (Self::Null, 1),
            6 => (Self::UninitializedThis, 1),
            7 => {
                if bytes.len() < 3 {
                    return Err(JvmDecodeError::Truncated);
                }
                let cp_idx = u16::from_be_bytes([bytes[1], bytes[2]]);
                (Self::Object(cp_idx), 3)
            }
            8 => {
                if bytes.len() < 3 {
                    return Err(JvmDecodeError::Truncated);
                }
                let offset = u16::from_be_bytes([bytes[1], bytes[2]]);
                (Self::Uninitialized(offset), 3)
            }
            _ => return Err(JvmDecodeError::UnknownOpcode(bytes[0])),
        })
    }

    /// Return the type tag byte.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Top => 0,
            Self::Integer => 1,
            Self::Float => 2,
            Self::Double => 3,
            Self::Long => 4,
            Self::Null => 5,
            Self::UninitializedThis => 6,
            Self::Object(_) => 7,
            Self::Uninitialized(_) => 8,
        }
    }

    /// Returns `true` when this type occupies two local-variable / stack slots.
    #[must_use]
    pub const fn is_wide(&self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }
}

// ---------------------------------------------------------------------------
// JVM access flags (§4.1, §4.5, §4.6)
// ---------------------------------------------------------------------------

bitflags::bitflags! {
    /// Class, field, and method access flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AccessFlags: u16 {
        /// Declared `public`.
        const PUBLIC       = 0x0001;
        /// Declared `private`.
        const PRIVATE      = 0x0002;
        /// Declared `protected`.
        const PROTECTED    = 0x0004;
        /// Declared `static`.
        const STATIC       = 0x0008;
        /// Declared `final`.
        const FINAL        = 0x0010;
        /// Special handling by JVM superclass invocation (class); `synchronized` (method).
        const SUPER_SYNC   = 0x0020;
        /// Bridge method generated by compiler.
        const BRIDGE       = 0x0040;
        /// Variable-arity method (`varargs`).
        const VARARGS      = 0x0080;
        /// Declared `native`.
        const NATIVE       = 0x0100;
        /// Is an interface.
        const INTERFACE    = 0x0200;
        /// Declared `abstract`.
        const ABSTRACT     = 0x0400;
        /// Strict floating-point mode (`strictfp`).
        const STRICT       = 0x0800;
        /// Compiler-generated synthetic element.
        const SYNTHETIC    = 0x1000;
        /// Is an annotation type.
        const ANNOTATION   = 0x2000;
        /// Declared as an enum.
        const ENUM         = 0x4000;
        /// Module declaration (class file only).
        const MODULE       = 0x8000;
    }
}

// ---------------------------------------------------------------------------
// JVM class file header structure
// ---------------------------------------------------------------------------

/// Parsed header fields of a JVM `.class` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassFileHeader {
    /// Magic bytes — always `0xCAFEBABE`.
    pub magic: u32,
    /// Minor version of the class file format.
    pub minor_version: u16,
    /// Major version of the class file format (corresponds to Java release).
    pub major_version: u16,
    /// Number of entries in the constant pool (actual count = this value − 1).
    pub constant_pool_count: u16,
}

impl ClassFileHeader {
    /// Java magic constant `0xCAFEBABE`.
    pub const MAGIC: u32 = 0xCAFE_BABE;

    /// Decode a class-file header from the first 8 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`JvmDecodeError::Truncated`] when fewer than 8 bytes are provided,
    /// or [`JvmDecodeError::UnknownOpcode`] when the magic is invalid.
    pub fn decode(bytes: &[u8]) -> Result<Self, JvmDecodeError> {
        if bytes.len() < 10 {
            return Err(JvmDecodeError::Truncated);
        }
        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != Self::MAGIC {
            return Err(JvmDecodeError::InvalidMagic(magic));
        }
        let minor = u16::from_be_bytes([bytes[4], bytes[5]]);
        let major = u16::from_be_bytes([bytes[6], bytes[7]]);
        let cp = u16::from_be_bytes([bytes[8], bytes[9]]);
        Ok(Self {
            magic,
            minor_version: minor,
            major_version: major,
            constant_pool_count: cp,
        })
    }

    /// Return the Java release number corresponding to `major_version`.
    #[must_use]
    pub const fn java_release(&self) -> Option<u32> {
        match self.major_version {
            45 => Some(1),
            46 => Some(2),
            47 => Some(3),
            48 => Some(4),
            49 => Some(5),
            50 => Some(6),
            51 => Some(7),
            52 => Some(8),
            53 => Some(9),
            54 => Some(10),
            55 => Some(11),
            56 => Some(12),
            57 => Some(13),
            58 => Some(14),
            59 => Some(15),
            60 => Some(16),
            61 => Some(17),
            62 => Some(18),
            63 => Some(19),
            64 => Some(20),
            65 => Some(21),
            66 => Some(22),
            67 => Some(23),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// JVM type descriptor helpers
// ---------------------------------------------------------------------------

/// Parsed JVM field-type descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldDescriptor {
    /// `B` — `byte`
    Byte,
    /// `C` — `char`
    Char,
    /// `D` — `double`
    Double,
    /// `F` — `float`
    Float,
    /// `I` — `int`
    Int,
    /// `J` — `long`
    Long,
    /// `L<ClassName>;` — class or interface type.
    Object(String),
    /// `S` — `short`
    Short,
    /// `Z` — `boolean`
    Boolean,
    /// `[<desc>` — array type.
    Array(Box<Self>),
}

impl FieldDescriptor {
    /// Parse one field descriptor from a string slice.
    ///
    /// Returns `(descriptor, chars_consumed)`.
    ///
    /// # Errors
    ///
    /// Returns `None` when the descriptor string is malformed or empty.
    #[must_use]
    pub fn parse(s: &str) -> Option<(Self, usize)> {
        let mut chars = s.char_indices();
        let (_, first) = chars.next()?;
        Some(match first {
            'B' => (Self::Byte, 1),
            'C' => (Self::Char, 1),
            'D' => (Self::Double, 1),
            'F' => (Self::Float, 1),
            'I' => (Self::Int, 1),
            'J' => (Self::Long, 1),
            'S' => (Self::Short, 1),
            'Z' => (Self::Boolean, 1),
            '[' => {
                let (inner, n) = Self::parse(&s[1..])?;
                (Self::Array(Box::new(inner)), 1 + n)
            }
            'L' => {
                let end = s.find(';')?;
                let class_name = s[1..end].to_string();
                (Self::Object(class_name), end + 1)
            }
            _ => return None,
        })
    }

    /// Return the single-character JVM type code (for primitives and array prefix).
    #[must_use]
    pub const fn type_char(&self) -> char {
        match self {
            Self::Byte => 'B',
            Self::Char => 'C',
            Self::Double => 'D',
            Self::Float => 'F',
            Self::Int => 'I',
            Self::Long => 'J',
            Self::Object(_) => 'L',
            Self::Short => 'S',
            Self::Boolean => 'Z',
            Self::Array(_) => '[',
        }
    }

    /// Returns `true` when this is a category-2 computational type (long/double).
    #[must_use]
    pub const fn is_category2(&self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }
}

/// Parse a JVM method descriptor into `(parameter_types, return_type_string)`.
///
/// # Errors
///
/// Returns `None` when the descriptor is malformed.
#[must_use]
pub fn parse_method_descriptor(desc: &str) -> Option<(Vec<FieldDescriptor>, String)> {
    if !desc.starts_with('(') {
        return None;
    }
    let close = desc.find(')')?;
    let params_str = &desc[1..close];
    let ret_str = &desc[close + 1..];

    let mut params = Vec::new();
    let mut off = 0;
    while off < params_str.len() {
        let (fd, n) = FieldDescriptor::parse(&params_str[off..])?;
        params.push(fd);
        off += n;
    }
    Some((params, ret_str.to_string()))
}

// ---------------------------------------------------------------------------
// JVM opcode metadata table
// ---------------------------------------------------------------------------

/// Metadata for a single JVM opcode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpcodeInfo {
    /// Opcode byte value.
    pub opcode: u8,
    /// Canonical mnemonic.
    pub mnemonic: &'static str,
    /// Fixed instruction length in bytes (0 = variable-length).
    pub length: u8,
    /// Net stack items produced (positive = push, negative = Pop).
    pub stack_delta: i8,
    /// Whether the instruction can transfer control.
    pub is_control: bool,
}

/// Return metadata for a JVM opcode by opcode byte.
#[must_use]
pub fn opcode_info(op: u8) -> Option<OpcodeInfo> {
    let (mne, len, delta, ctrl) = OPCODE_TABLE
        .iter()
        .find(|(o, _, _, _, _)| *o == op)
        .map(|(_, m, l, d, c)| (*m, *l, *d, *c))?;
    Some(OpcodeInfo {
        opcode: op,
        mnemonic: mne,
        length: len,
        stack_delta: delta,
        is_control: ctrl,
    })
}

/// Full JVM opcode table: (opcode, mnemonic, `fixed_len`, `stack_delta`, `is_control`).
///
/// `fixed_len` == 0 means variable-length (Tableswitch, Lookupswitch, Wide).
static OPCODE_TABLE: &[(u8, &str, u8, i8, bool)] = &[
    (0x00, "nop", 1, 0, false),
    (0x01, "aconst_null", 1, 1, false),
    (0x02, "iconst_m1", 1, 1, false),
    (0x03, "iconst_0", 1, 1, false),
    (0x04, "iconst_1", 1, 1, false),
    (0x05, "iconst_2", 1, 1, false),
    (0x06, "iconst_3", 1, 1, false),
    (0x07, "iconst_4", 1, 1, false),
    (0x08, "iconst_5", 1, 1, false),
    (0x09, "lconst_0", 1, 2, false),
    (0x0a, "lconst_1", 1, 2, false),
    (0x0b, "fconst_0", 1, 1, false),
    (0x0c, "fconst_1", 1, 1, false),
    (0x0d, "fconst_2", 1, 1, false),
    (0x0e, "dconst_0", 1, 2, false),
    (0x0f, "dconst_1", 1, 2, false),
    (0x10, "bipush", 2, 1, false),
    (0x11, "sipush", 3, 1, false),
    (0x12, "ldc", 2, 1, false),
    (0x13, "ldc_w", 3, 1, false),
    (0x14, "ldc2_w", 3, 2, false),
    (0x15, "iload", 2, 1, false),
    (0x16, "lload", 2, 2, false),
    (0x17, "fload", 2, 1, false),
    (0x18, "dload", 2, 2, false),
    (0x19, "aload", 2, 1, false),
    (0x1a, "iload_0", 1, 1, false),
    (0x1b, "iload_1", 1, 1, false),
    (0x1c, "iload_2", 1, 1, false),
    (0x1d, "iload_3", 1, 1, false),
    (0x1e, "lload_0", 1, 2, false),
    (0x1f, "lload_1", 1, 2, false),
    (0x20, "lload_2", 1, 2, false),
    (0x21, "lload_3", 1, 2, false),
    (0x22, "fload_0", 1, 1, false),
    (0x23, "fload_1", 1, 1, false),
    (0x24, "fload_2", 1, 1, false),
    (0x25, "fload_3", 1, 1, false),
    (0x26, "dload_0", 1, 2, false),
    (0x27, "dload_1", 1, 2, false),
    (0x28, "dload_2", 1, 2, false),
    (0x29, "dload_3", 1, 2, false),
    (0x2a, "aload_0", 1, 1, false),
    (0x2b, "aload_1", 1, 1, false),
    (0x2c, "aload_2", 1, 1, false),
    (0x2d, "aload_3", 1, 1, false),
    (0x2e, "iaload", 1, -1, false),
    (0x2f, "laload", 1, 0, false),
    (0x30, "faload", 1, -1, false),
    (0x31, "daload", 1, 0, false),
    (0x32, "aaload", 1, -1, false),
    (0x33, "baload", 1, -1, false),
    (0x34, "caload", 1, -1, false),
    (0x35, "saload", 1, -1, false),
    (0x36, "istore", 2, -1, false),
    (0x37, "lstore", 2, -2, false),
    (0x38, "fstore", 2, -1, false),
    (0x39, "dstore", 2, -2, false),
    (0x3a, "astore", 2, -1, false),
    (0x3b, "istore_0", 1, -1, false),
    (0x3c, "istore_1", 1, -1, false),
    (0x3d, "istore_2", 1, -1, false),
    (0x3e, "istore_3", 1, -1, false),
    (0x3f, "lstore_0", 1, -2, false),
    (0x40, "lstore_1", 1, -2, false),
    (0x41, "lstore_2", 1, -2, false),
    (0x42, "lstore_3", 1, -2, false),
    (0x43, "fstore_0", 1, -1, false),
    (0x44, "fstore_1", 1, -1, false),
    (0x45, "fstore_2", 1, -1, false),
    (0x46, "fstore_3", 1, -1, false),
    (0x47, "dstore_0", 1, -2, false),
    (0x48, "dstore_1", 1, -2, false),
    (0x49, "dstore_2", 1, -2, false),
    (0x4a, "dstore_3", 1, -2, false),
    (0x4b, "astore_0", 1, -1, false),
    (0x4c, "astore_1", 1, -1, false),
    (0x4d, "astore_2", 1, -1, false),
    (0x4e, "astore_3", 1, -1, false),
    (0x4f, "iastore", 1, -3, false),
    (0x50, "lastore", 1, -4, false),
    (0x51, "fastore", 1, -3, false),
    (0x52, "dastore", 1, -4, false),
    (0x53, "aastore", 1, -3, false),
    (0x54, "bastore", 1, -3, false),
    (0x55, "castore", 1, -3, false),
    (0x56, "sastore", 1, -3, false),
    (0x57, "pop", 1, -1, false),
    (0x58, "pop2", 1, -2, false),
    (0x59, "dup", 1, 1, false),
    (0x5a, "dup_x1", 1, 1, false),
    (0x5b, "dup_x2", 1, 1, false),
    (0x5c, "dup2", 1, 2, false),
    (0x5d, "dup2_x1", 1, 2, false),
    (0x5e, "dup2_x2", 1, 2, false),
    (0x5f, "swap", 1, 0, false),
    (0x60, "iadd", 1, -1, false),
    (0x61, "ladd", 1, -2, false),
    (0x62, "fadd", 1, -1, false),
    (0x63, "dadd", 1, -2, false),
    (0x64, "isub", 1, -1, false),
    (0x65, "lsub", 1, -2, false),
    (0x66, "fsub", 1, -1, false),
    (0x67, "dsub", 1, -2, false),
    (0x68, "imul", 1, -1, false),
    (0x69, "lmul", 1, -2, false),
    (0x6a, "fmul", 1, -1, false),
    (0x6b, "dmul", 1, -2, false),
    (0x6c, "idiv", 1, -1, false),
    (0x6d, "ldiv", 1, -2, false),
    (0x6e, "fdiv", 1, -1, false),
    (0x6f, "ddiv", 1, -2, false),
    (0x70, "irem", 1, -1, false),
    (0x71, "lrem", 1, -2, false),
    (0x72, "frem", 1, -1, false),
    (0x73, "drem", 1, -2, false),
    (0x74, "ineg", 1, 0, false),
    (0x75, "lneg", 1, 0, false),
    (0x76, "fneg", 1, 0, false),
    (0x77, "dneg", 1, 0, false),
    (0x78, "ishl", 1, -1, false),
    (0x79, "lshl", 1, -1, false),
    (0x7a, "ishr", 1, -1, false),
    (0x7b, "lshr", 1, -1, false),
    (0x7c, "iushr", 1, -1, false),
    (0x7d, "lushr", 1, -1, false),
    (0x7e, "iand", 1, -1, false),
    (0x7f, "land", 1, -2, false),
    (0x80, "ior", 1, -1, false),
    (0x81, "lor", 1, -2, false),
    (0x82, "ixor", 1, -1, false),
    (0x83, "lxor", 1, -2, false),
    (0x84, "iinc", 3, 0, false),
    (0x85, "i2l", 1, 1, false),
    (0x86, "i2f", 1, 0, false),
    (0x87, "i2d", 1, 1, false),
    (0x88, "l2i", 1, -1, false),
    (0x89, "l2f", 1, -1, false),
    (0x8a, "l2d", 1, 0, false),
    (0x8b, "f2i", 1, 0, false),
    (0x8c, "f2l", 1, 1, false),
    (0x8d, "f2d", 1, 1, false),
    (0x8e, "d2i", 1, -1, false),
    (0x8f, "d2l", 1, 0, false),
    (0x90, "d2f", 1, -1, false),
    (0x91, "i2b", 1, 0, false),
    (0x92, "i2c", 1, 0, false),
    (0x93, "i2s", 1, 0, false),
    (0x94, "lcmp", 1, -3, false),
    (0x95, "fcmpl", 1, -1, false),
    (0x96, "fcmpg", 1, -1, false),
    (0x97, "dcmpl", 1, -3, false),
    (0x98, "dcmpg", 1, -3, false),
    (0x99, "ifeq", 3, -1, true),
    (0x9a, "ifne", 3, -1, true),
    (0x9b, "iflt", 3, -1, true),
    (0x9c, "ifge", 3, -1, true),
    (0x9d, "ifgt", 3, -1, true),
    (0x9e, "ifle", 3, -1, true),
    (0x9f, "if_icmpeq", 3, -2, true),
    (0xa0, "if_icmpne", 3, -2, true),
    (0xa1, "if_icmplt", 3, -2, true),
    (0xa2, "if_icmpge", 3, -2, true),
    (0xa3, "if_icmpgt", 3, -2, true),
    (0xa4, "if_icmple", 3, -2, true),
    (0xa5, "if_acmpeq", 3, -2, true),
    (0xa6, "if_acmpne", 3, -2, true),
    (0xa7, "goto", 3, 0, true),
    (0xa8, "jsr", 3, 1, true),
    (0xa9, "ret", 2, 0, true),
    (0xaa, "tableswitch", 0, -1, true),
    (0xab, "lookupswitch", 0, -1, true),
    (0xac, "ireturn", 1, -1, true),
    (0xad, "lreturn", 1, -2, true),
    (0xae, "freturn", 1, -1, true),
    (0xaf, "dreturn", 1, -2, true),
    (0xb0, "areturn", 1, -1, true),
    (0xb1, "return", 1, 0, true),
    (0xb2, "getstatic", 3, 1, false),
    (0xb3, "putstatic", 3, -1, false),
    (0xb4, "getfield", 3, 0, false),
    (0xb5, "putfield", 3, -2, false),
    (0xb6, "invokevirtual", 3, -1, true),
    (0xb7, "invokespecial", 3, -1, true),
    (0xb8, "invokestatic", 3, 0, true),
    (0xb9, "invokeinterface", 5, -1, true),
    (0xba, "invokedynamic", 5, 0, true),
    (0xbb, "new", 3, 1, false),
    (0xbc, "newarray", 2, 0, false),
    (0xbd, "anewarray", 3, 0, false),
    (0xbe, "arraylength", 1, 0, false),
    (0xbf, "athrow", 1, 0, true),
    (0xc0, "checkcast", 3, 0, false),
    (0xc1, "instanceof", 3, 0, false),
    (0xc2, "monitorenter", 1, -1, false),
    (0xc3, "monitorexit", 1, -1, false),
    (0xc4, "wide", 0, 0, false),
    (0xc5, "multianewarray", 4, 0, false),
    (0xc6, "ifnull", 3, -1, true),
    (0xc7, "ifnonnull", 3, -1, true),
    (0xc8, "goto_w", 5, 0, true),
    (0xc9, "jsr_w", 5, 1, true),
];

// ---------------------------------------------------------------------------
// `Newarray` type codes
// ---------------------------------------------------------------------------

/// Array type codes used by the `Newarray` instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NewarrayType {
    /// `T_BOOLEAN` = 4
    Boolean = 4,
    /// `T_CHAR` = 5
    Char = 5,
    /// `T_FLOAT` = 6
    Float = 6,
    /// `T_DOUBLE` = 7
    Double = 7,
    /// `T_BYTE` = 8
    Byte = 8,
    /// `T_SHORT` = 9
    Short = 9,
    /// `T_INT` = 10
    Int = 10,
    /// `T_LONG` = 11
    Long = 11,
}

impl NewarrayType {
    /// Decode from the operand byte of `Newarray`.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            4 => Self::Boolean,
            5 => Self::Char,
            6 => Self::Float,
            7 => Self::Double,
            8 => Self::Byte,
            9 => Self::Short,
            10 => Self::Int,
            11 => Self::Long,
            _ => return None,
        })
    }

    /// Return the JVM name for this array element type.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Boolean => "boolean",
            Self::Char => "char",
            Self::Float => "float",
            Self::Double => "double",
            Self::Byte => "byte",
            Self::Short => "short",
            Self::Int => "int",
            Self::Long => "long",
        }
    }
}

// ---------------------------------------------------------------------------
// Exception handler table entry
// ---------------------------------------------------------------------------

/// One row of a method's exception handler table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionHandler {
    /// First bytecode offset covered by this handler (inclusive).
    pub start_pc: u16,
    /// Bytecode offset just past the covered range (exclusive).
    pub end_pc: u16,
    /// Bytecode offset of the handler code.
    pub handler_pc: u16,
    /// Constant-pool index of the catch type, or 0 for `finally`.
    pub catch_type: u16,
}

impl ExceptionHandler {
    /// Decode an exception handler table entry from 8 bytes (big-endian).
    ///
    /// # Errors
    ///
    /// Returns `JvmDecodeError::Truncated` when fewer than 8 bytes are provided.
    pub fn decode(bytes: &[u8]) -> Result<Self, JvmDecodeError> {
        if bytes.len() < 8 {
            return Err(JvmDecodeError::Truncated);
        }
        Ok(Self {
            start_pc: u16::from_be_bytes([bytes[0], bytes[1]]),
            end_pc: u16::from_be_bytes([bytes[2], bytes[3]]),
            handler_pc: u16::from_be_bytes([bytes[4], bytes[5]]),
            catch_type: u16::from_be_bytes([bytes[6], bytes[7]]),
        })
    }

    /// Returns `true` when this handler is a `finally` clause.
    #[must_use]
    pub const fn is_finally(&self) -> bool {
        self.catch_type == 0
    }
}

// ---------------------------------------------------------------------------
// Line number table entry
// ---------------------------------------------------------------------------

/// An entry in the `LineNumberTable` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineNumberEntry {
    /// Bytecode offset of the first instruction on the source line.
    pub start_pc: u16,
    /// Corresponding source line number.
    pub line_number: u16,
}

impl LineNumberEntry {
    /// Decode one entry from 4 bytes.
    ///
    /// # Errors
    ///
    /// Returns `JvmDecodeError::Truncated` when fewer than 4 bytes are provided.
    pub fn decode(bytes: &[u8]) -> Result<Self, JvmDecodeError> {
        if bytes.len() < 4 {
            return Err(JvmDecodeError::Truncated);
        }
        Ok(Self {
            start_pc: u16::from_be_bytes([bytes[0], bytes[1]]),
            line_number: u16::from_be_bytes([bytes[2], bytes[3]]),
        })
    }
}

// ---------------------------------------------------------------------------
// Code attribute (simplified)
// ---------------------------------------------------------------------------

/// Simplified representation of a JVM `Code` attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeAttribute {
    /// Maximum number of stack slots used.
    pub max_stack: u16,
    /// Maximum number of local variable slots.
    pub max_locals: u16,
    /// Raw bytecode bytes.
    pub code: Vec<u8>,
    /// Exception handler table.
    pub exception_table: Vec<ExceptionHandler>,
}

impl CodeAttribute {
    /// Decode a `Code` attribute body (after the attribute name/length prefix).
    ///
    /// # Errors
    ///
    /// Returns `JvmDecodeError::Truncated` when the data is too short to decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, JvmDecodeError> {
        if bytes.len() < 8 {
            return Err(JvmDecodeError::Truncated);
        }
        let max_stack = u16::from_be_bytes([bytes[0], bytes[1]]);
        let max_locals = u16::from_be_bytes([bytes[2], bytes[3]]);
        let code_len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let base = 8;
        if bytes.len() < base + code_len + 2 {
            return Err(JvmDecodeError::Truncated);
        }
        let code = bytes[base..base + code_len].to_vec();
        let exc_count =
            u16::from_be_bytes([bytes[base + code_len], bytes[base + code_len + 1]]) as usize;
        let exc_base = base + code_len + 2;
        if bytes.len() < exc_base + exc_count * 8 {
            return Err(JvmDecodeError::Truncated);
        }
        let mut exception_table = Vec::with_capacity(exc_count);
        for i in 0..exc_count {
            let off = exc_base + i * 8;
            exception_table.push(ExceptionHandler::decode(&bytes[off..])?);
        }
        Ok(Self {
            max_stack,
            max_locals,
            code,
            exception_table,
        })
    }

    /// Disassemble the code bytes into a list of instructions.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` if an instruction cannot be decoded.
    #[must_use]
    pub fn disassemble(&self) -> Vec<Result<JvmInstr, JvmDecodeError>> {
        let mut result = Vec::with_capacity(self.code.len() / 2);
        let mut off = 0usize;
        while off < self.code.len() {
            match JvmInstr::decode_at(&self.code[off..], off) {
                Ok((instr, n)) => {
                    off += n;
                    result.push(Ok(instr));
                }
                Err(e) => {
                    off += 1;
                    result.push(Err(e));
                }
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// JVM program analysis utilities
// ---------------------------------------------------------------------------

/// Statistics gathered from a JVM method body.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MethodStats {
    /// Total number of instructions.
    pub instruction_count: usize,
    /// Number of method call instructions (invoke*).
    pub call_count: usize,
    /// Number of conditional branches.
    pub conditional_branch_count: usize,
    /// Number of unconditional branches (Goto / `GotoW` / Jsr / `JsrW`).
    pub unconditional_branch_count: usize,
    /// Number of array read instructions.
    pub array_read_count: usize,
    /// Number of array write instructions.
    pub array_write_count: usize,
    /// Number of field read instructions.
    pub field_read_count: usize,
    /// Number of field write instructions.
    pub field_write_count: usize,
    /// Number of return instructions.
    pub return_count: usize,
    /// Whether any `Athrow` instruction is present.
    pub has_throw: bool,
    /// Number of monitor enter/exit instructions (synchronization).
    pub monitor_count: usize,
}

impl MethodStats {
    /// Analyse a raw bytecode slice and accumulate statistics.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` on fatal decode failure.
    pub fn from_bytes(code: &[u8]) -> Result<Self, JvmDecodeError> {
        let mut s = Self::default();
        let mut off = 0;
        while off < code.len() {
            let (instr, n) = JvmInstr::decode_at(&code[off..], off)?;
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
                s.return_count += 1;
            }
            if instr.flags.contains(InstrFlags::BARRIER) {
                s.monitor_count += 1;
            }
            // Array ops
            let opcode = instr.raw.first().copied().unwrap_or(0);
            if matches!(opcode, 0x2e..=0x35) {
                s.array_read_count += 1;
            }
            if matches!(opcode, 0x4f..=0x56) {
                s.array_write_count += 1;
            }
            // Field ops
            if matches!(opcode, 0xb2 | 0xb4) {
                s.field_read_count += 1;
            }
            if matches!(opcode, 0xb3 | 0xb5) {
                s.field_write_count += 1;
            }
            if opcode == 0xbf {
                s.has_throw = true;
            }
        }
        Ok(s)
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

    // --- ConstantPoolTag ---

    #[test]
    fn test_cpt_roundtrip() {
        assert_eq!(ConstantPoolTag::from_u8(1), Some(ConstantPoolTag::Utf8));
        assert_eq!(ConstantPoolTag::from_u8(7), Some(ConstantPoolTag::Class));
        assert_eq!(
            ConstantPoolTag::from_u8(18),
            Some(ConstantPoolTag::InvokeDynamic)
        );
        assert!(ConstantPoolTag::from_u8(0).is_none());
        assert!(ConstantPoolTag::from_u8(2).is_none());
    }

    #[test]
    fn test_cpt_is_wide() {
        assert!(ConstantPoolTag::Long.is_wide());
        assert!(ConstantPoolTag::Double.is_wide());
        assert!(!ConstantPoolTag::Integer.is_wide());
    }

    #[test]
    fn test_cpt_names() {
        assert_eq!(ConstantPoolTag::Utf8.name(), "CONSTANT_Utf8");
        assert_eq!(ConstantPoolTag::Methodref.name(), "CONSTANT_Methodref");
    }

    // --- AttributeKind ---

    #[test]
    fn test_attribute_roundtrip() {
        assert_eq!(AttributeKind::from_name("Code"), Some(AttributeKind::Code));
        assert_eq!(
            AttributeKind::from_name("LineNumberTable"),
            Some(AttributeKind::LineNumberTable)
        );
        assert!(AttributeKind::from_name("Unknown").is_none());
    }

    #[test]
    fn test_attribute_as_str() {
        assert_eq!(AttributeKind::ConstantValue.as_str(), "ConstantValue");
        assert_eq!(AttributeKind::StackMapTable.as_str(), "StackMapTable");
    }

    // --- VerificationType ---

    #[test]
    fn test_vt_simple_tags() {
        let (vt, n) = VerificationType::decode(&[0]).unwrap();
        assert_eq!(n, 1);
        assert_eq!(vt, VerificationType::Top);

        let (vt2, _) = VerificationType::decode(&[4]).unwrap();
        assert_eq!(vt2, VerificationType::Long);
        assert!(vt2.is_wide());
    }

    #[test]
    fn test_vt_object() {
        let (vt, n) = VerificationType::decode(&[7, 0, 5]).unwrap();
        assert_eq!(n, 3);
        assert_eq!(vt, VerificationType::Object(5));
        assert!(!vt.is_wide());
    }

    #[test]
    fn test_vt_uninitialized() {
        let (vt, n) = VerificationType::decode(&[8, 0, 10]).unwrap();
        assert_eq!(n, 3);
        assert_eq!(vt, VerificationType::Uninitialized(10));
    }

    #[test]
    fn test_vt_truncated() {
        assert!(matches!(
            VerificationType::decode(&[7, 0]),
            Err(JvmDecodeError::Truncated)
        ));
        assert!(matches!(
            VerificationType::decode(&[]),
            Err(JvmDecodeError::Truncated)
        ));
    }

    // --- AccessFlags ---

    #[test]
    fn test_access_flags_public_static_final() {
        let flags = AccessFlags::PUBLIC | AccessFlags::STATIC | AccessFlags::FINAL;
        assert!(flags.contains(AccessFlags::PUBLIC));
        assert!(flags.contains(AccessFlags::STATIC));
        assert!(flags.contains(AccessFlags::FINAL));
        assert!(!flags.contains(AccessFlags::ABSTRACT));
    }

    // --- ClassFileHeader ---

    #[test]
    fn test_class_header_valid() {
        // Magic + minor(0) + major(55 = Java 11) + cp_count(10)
        let bytes = [0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x37, 0x00, 0x0a];
        let hdr = ClassFileHeader::decode(&bytes).unwrap();
        assert_eq!(hdr.magic, ClassFileHeader::MAGIC);
        assert_eq!(hdr.major_version, 55);
        assert_eq!(hdr.java_release(), Some(11));
    }

    #[test]
    fn test_class_header_invalid_magic() {
        let bytes = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x37, 0x00, 0x0a];
        assert!(ClassFileHeader::decode(&bytes).is_err());
    }

    #[test]
    fn test_class_header_truncated() {
        assert!(ClassFileHeader::decode(&[0xca, 0xfe]).is_err());
    }

    // --- FieldDescriptor ---

    #[test]
    fn test_field_desc_primitive() {
        let (fd, n) = FieldDescriptor::parse("I").unwrap();
        assert_eq!(fd, FieldDescriptor::Int);
        assert_eq!(n, 1);
        assert!(!fd.is_category2());
    }

    #[test]
    fn test_field_desc_long() {
        let (fd, _) = FieldDescriptor::parse("J").unwrap();
        assert!(fd.is_category2());
    }

    #[test]
    fn test_field_desc_object() {
        let (fd, n) = FieldDescriptor::parse("Ljava/lang/String;").unwrap();
        assert_eq!(n, 18);
        assert_eq!(fd.type_char(), 'L');
        if let FieldDescriptor::Object(cls) = fd {
            assert_eq!(cls, "java/lang/String");
        } else {
            panic!("expected Object");
        }
    }

    #[test]
    fn test_field_desc_array() {
        let (fd, n) = FieldDescriptor::parse("[I").unwrap();
        assert_eq!(n, 2);
        assert_eq!(fd.type_char(), '[');
    }

    #[test]
    fn test_field_desc_nested_array() {
        let (fd, n) = FieldDescriptor::parse("[[B").unwrap();
        assert_eq!(n, 3);
        if let FieldDescriptor::Array(inner) = &fd {
            assert_eq!(inner.type_char(), '[');
        }
    }

    // --- Method descriptor ---

    #[test]
    fn test_method_desc_simple() {
        let (params, ret) = parse_method_descriptor("(IJ)V").unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].type_char(), 'I');
        assert_eq!(params[1].type_char(), 'J');
        assert_eq!(ret, "V");
    }

    #[test]
    fn test_method_desc_no_params() {
        let (params, ret) = parse_method_descriptor("()Z").unwrap();
        assert!(params.is_empty());
        assert_eq!(ret, "Z");
    }

    #[test]
    fn test_method_desc_invalid() {
        assert!(parse_method_descriptor("notadesc").is_none());
    }

    // --- OpcodeInfo ---

    #[test]
    fn test_opcode_info_nop() {
        let info = opcode_info(0x00).unwrap();
        assert_eq!(info.mnemonic, "nop");
        assert_eq!(info.length, 1);
        assert!(!info.is_control);
    }

    #[test]
    fn test_opcode_info_invokevirtual() {
        let info = opcode_info(0xb6).unwrap();
        assert_eq!(info.mnemonic, "invokevirtual");
        assert!(info.is_control);
    }

    #[test]
    fn test_opcode_info_unknown() {
        assert!(opcode_info(0xff).is_none());
    }

    // --- NewarrayType ---

    #[test]
    fn test_newarray_type_roundtrip() {
        assert_eq!(NewarrayType::from_u8(10), Some(NewarrayType::Int));
        assert_eq!(NewarrayType::from_u8(11), Some(NewarrayType::Long));
        assert!(NewarrayType::from_u8(0).is_none());
        assert_eq!(NewarrayType::Int.name(), "int");
    }

    // --- ExceptionHandler ---

    #[test]
    fn test_exception_handler_decode() {
        let bytes = [0x00, 0x00, 0x00, 0x0a, 0x00, 0x0f, 0x00, 0x01];
        let eh = ExceptionHandler::decode(&bytes).unwrap();
        assert_eq!(eh.start_pc, 0);
        assert_eq!(eh.end_pc, 10);
        assert_eq!(eh.handler_pc, 15);
        assert!(!eh.is_finally());
    }

    #[test]
    fn test_exception_handler_finally() {
        let bytes = [0x00, 0x00, 0x00, 0x0a, 0x00, 0x0f, 0x00, 0x00];
        let eh = ExceptionHandler::decode(&bytes).unwrap();
        assert!(eh.is_finally());
    }

    // --- LineNumberEntry ---

    #[test]
    fn test_line_number_entry() {
        let bytes = [0x00, 0x05, 0x00, 0x2a];
        let lne = LineNumberEntry::decode(&bytes).unwrap();
        assert_eq!(lne.start_pc, 5);
        assert_eq!(lne.line_number, 42);
    }

    // --- CodeAttribute ---

    #[test]
    fn test_code_attribute_decode() {
        // max_stack=2, max_locals=1, code_len=3 [Iconst1, Iadd, Ireturn], exc_count=0
        let mut bytes = vec![0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03];
        bytes.extend_from_slice(&[0x04, 0x60, 0xac]); // code
        bytes.extend_from_slice(&[0x00, 0x00]); // exc_count=0
        let attr = CodeAttribute::decode(&bytes).unwrap();
        assert_eq!(attr.max_stack, 2);
        assert_eq!(attr.max_locals, 1);
        assert_eq!(attr.code.len(), 3);
        assert!(attr.exception_table.is_empty());
    }

    #[test]
    fn test_code_attribute_disassemble() {
        let mut bytes = vec![0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03];
        bytes.extend_from_slice(&[0x04, 0x60, 0xac]);
        bytes.extend_from_slice(&[0x00, 0x00]);
        let attr = CodeAttribute::decode(&bytes).unwrap();
        let instrs = attr.disassemble();
        assert_eq!(instrs.len(), 3);
        assert_eq!(instrs[0].as_ref().unwrap().raw[0], 0x04);
    }

    // --- MethodStats ---

    #[test]
    fn test_method_stats_simple() {
        // Iconst1, Iadd, Ireturn
        let code = [0x04_u8, 0x60, 0xac];
        let s = MethodStats::from_bytes(&code).unwrap();
        assert_eq!(s.instruction_count, 3);
        assert_eq!(s.return_count, 1);
        assert_eq!(s.call_count, 0);
    }

    #[test]
    fn test_method_stats_branch() {
        // Ifeq +3, Goto +0, return
        let code = [0x99_u8, 0x00, 0x03, 0xa7, 0x00, 0x00, 0xb1];
        let s = MethodStats::from_bytes(&code).unwrap();
        assert_eq!(s.conditional_branch_count, 1);
        assert_eq!(s.unconditional_branch_count, 1);
    }

    #[test]
    fn test_method_stats_array_ops() {
        // Iaload (2e) then Iastore (4f)
        let code = [0x2e_u8, 0x4f];
        let s = MethodStats::from_bytes(&code).unwrap();
        assert_eq!(s.array_read_count, 1);
        assert_eq!(s.array_write_count, 1);
    }

    #[test]
    fn test_method_stats_field_ops() {
        // Getstatic (b2 00 01) Putfield (b5 00 02)
        let code = [0xb2_u8, 0x00, 0x01, 0xb5, 0x00, 0x02];
        let s = MethodStats::from_bytes(&code).unwrap();
        assert_eq!(s.field_read_count, 1);
        assert_eq!(s.field_write_count, 1);
    }

    #[test]
    fn test_method_stats_throw() {
        let code = [0xbf_u8];
        let s = MethodStats::from_bytes(&code).unwrap();
        assert!(s.has_throw);
    }

    // --- Additional opcode coverage ---

    #[test]
    fn test_lconst_0_and_1() {
        for (op, expected) in [(0x09_u8, "lconst_0"), (0x0a, "lconst_1")] {
            let (i, _) = JvmInstr::decode(&[op]).unwrap();
            assert_eq!(i.mnemonic, expected);
        }
    }

    #[test]
    fn test_all_return_opcodes_have_return_flag() {
        for op in [0xac_u8, 0xad, 0xae, 0xaf, 0xb0, 0xb1] {
            let (i, _) = JvmInstr::decode(&[op]).unwrap();
            assert!(i.flags.contains(InstrFlags::RET), "op={op:#04x}");
        }
    }

    #[test]
    fn test_all_if_icmp_are_conditional_branches() {
        for op in [0x9f_u8, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4] {
            let (i, sz) = JvmInstr::decode(&[op, 0x00, 0x08]).unwrap();
            assert_eq!(sz, 3, "op={op:#04x}");
            assert!(i.flags.contains(InstrFlags::BRANCH));
            assert!(i.flags.contains(InstrFlags::CONDITIONAL));
        }
    }

    #[test]
    fn test_ldc2_w_size() {
        let (i, sz) = JvmInstr::decode(&[0x14, 0x00, 0x0a]).unwrap();
        assert_eq!(sz, 3);
        assert_eq!(i.mnemonic, "ldc2_w");
    }

    #[test]
    fn test_multianewarray_size() {
        let (i, sz) = JvmInstr::decode(&[0xc5, 0x00, 0x0a, 0x02]).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(i.mnemonic, "multianewarray");
    }

    #[test]
    fn test_ifnull_ifnonnull() {
        for (op, expected) in [(0xc6_u8, "ifnull"), (0xc7, "ifnonnull")] {
            let (i, sz) = JvmInstr::decode(&[op, 0x00, 0x04]).unwrap();
            assert_eq!(sz, 3);
            assert_eq!(i.mnemonic, expected);
            assert!(
                i.flags
                    .contains(InstrFlags::BRANCH | InstrFlags::CONDITIONAL)
            );
        }
    }

    #[test]
    fn test_disassembler_bipush_sequence() {
        let arch = JvmArch;
        // Bipush 10, Bipush 20, Iadd, Ireturn
        let code = [0x10_u8, 0x0a, 0x10, 0x14, 0x60, 0xac];
        let instrs: Vec<_> = JvmLinearDisassembler::new(&arch, &code, addr(0))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs.len(), 4);
        assert_eq!(instrs[0].mnemonic, "bipush");
        assert_eq!(instrs[2].mnemonic, "iadd");
    }

    #[test]
    fn test_wide_aload() {
        let (i, sz) = JvmInstr::decode(&[0xc4, 0x19, 0x01, 0x00]).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(i.mnemonic, "Wide Aload");
    }

    #[test]
    fn test_jsr_w() {
        let (i, sz) = JvmInstr::decode(&[0xc9, 0x00, 0x00, 0x00, 0x20]).unwrap();
        assert_eq!(sz, 5);
        assert_eq!(i.mnemonic, "jsr_w");
        assert!(i.flags.contains(InstrFlags::CALL));
    }
}

// ---------------------------------------------------------------------------
// JvmOpcode enum — complete set of 202 JVM opcodes
// ---------------------------------------------------------------------------

/// All standard JVM bytecode opcodes with their canonical discriminant values.
///
/// The discriminant value matches the opcode byte in the class file.  Opcodes
/// that share a name with a Rust keyword are suffixed with an underscore
/// (e.g. `Return`, `New`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum JvmOpcode {
    Nop = 0x00,
    AconstNull = 0x01,
    IconstM1 = 0x02,
    Iconst0 = 0x03,
    Iconst1 = 0x04,
    Iconst2 = 0x05,
    Iconst3 = 0x06,
    Iconst4 = 0x07,
    Iconst5 = 0x08,
    Lconst0 = 0x09,
    Lconst1 = 0x0a,
    Fconst0 = 0x0b,
    Fconst1 = 0x0c,
    Fconst2 = 0x0d,
    Dconst0 = 0x0e,
    Dconst1 = 0x0f,
    Bipush = 0x10,
    Sipush = 0x11,
    Ldc = 0x12,
    LdcW = 0x13,
    Ldc2W = 0x14,
    Iload = 0x15,
    Lload = 0x16,
    Fload = 0x17,
    Dload = 0x18,
    Aload = 0x19,
    Iload0 = 0x1a,
    Iload1 = 0x1b,
    Iload2 = 0x1c,
    Iload3 = 0x1d,
    Lload0 = 0x1e,
    Lload1 = 0x1f,
    Lload2 = 0x20,
    Lload3 = 0x21,
    Fload0 = 0x22,
    Fload1 = 0x23,
    Fload2 = 0x24,
    Fload3 = 0x25,
    Dload0 = 0x26,
    Dload1 = 0x27,
    Dload2 = 0x28,
    Dload3 = 0x29,
    Aload0 = 0x2a,
    Aload1 = 0x2b,
    Aload2 = 0x2c,
    Aload3 = 0x2d,
    Iaload = 0x2e,
    Laload = 0x2f,
    Faload = 0x30,
    Daload = 0x31,
    Aaload = 0x32,
    Baload = 0x33,
    Caload = 0x34,
    Saload = 0x35,
    Istore = 0x36,
    Lstore = 0x37,
    Fstore = 0x38,
    Dstore = 0x39,
    Astore = 0x3a,
    Istore0 = 0x3b,
    Istore1 = 0x3c,
    Istore2 = 0x3d,
    Istore3 = 0x3e,
    Lstore0 = 0x3f,
    Lstore1 = 0x40,
    Lstore2 = 0x41,
    Lstore3 = 0x42,
    Fstore0 = 0x43,
    Fstore1 = 0x44,
    Fstore2 = 0x45,
    Fstore3 = 0x46,
    Dstore0 = 0x47,
    Dstore1 = 0x48,
    Dstore2 = 0x49,
    Dstore3 = 0x4a,
    Astore0 = 0x4b,
    Astore1 = 0x4c,
    Astore2 = 0x4d,
    Astore3 = 0x4e,
    Iastore = 0x4f,
    Lastore = 0x50,
    Fastore = 0x51,
    Dastore = 0x52,
    Aastore = 0x53,
    Bastore = 0x54,
    Castore = 0x55,
    Sastore = 0x56,
    Pop = 0x57,
    Pop2 = 0x58,
    Dup = 0x59,
    DupX1 = 0x5a,
    DupX2 = 0x5b,
    Dup2 = 0x5c,
    Dup2X1 = 0x5d,
    Dup2X2 = 0x5e,
    Swap = 0x5f,
    Iadd = 0x60,
    Ladd = 0x61,
    Fadd = 0x62,
    Dadd = 0x63,
    Isub = 0x64,
    Lsub = 0x65,
    Fsub = 0x66,
    Dsub = 0x67,
    Imul = 0x68,
    Lmul = 0x69,
    Fmul = 0x6a,
    Dmul = 0x6b,
    Idiv = 0x6c,
    Ldiv = 0x6d,
    Fdiv = 0x6e,
    Ddiv = 0x6f,
    Irem = 0x70,
    Lrem = 0x71,
    Frem = 0x72,
    Drem = 0x73,
    Ineg = 0x74,
    Lneg = 0x75,
    Fneg = 0x76,
    Dneg = 0x77,
    Ishl = 0x78,
    Lshl = 0x79,
    Ishr = 0x7a,
    Lshr = 0x7b,
    Iushr = 0x7c,
    Lushr = 0x7d,
    Iand = 0x7e,
    Land = 0x7f,
    Ior = 0x80,
    Lor = 0x81,
    Ixor = 0x82,
    Lxor = 0x83,
    Iinc = 0x84,
    I2l = 0x85,
    I2f = 0x86,
    I2d = 0x87,
    L2i = 0x88,
    L2f = 0x89,
    L2d = 0x8a,
    F2i = 0x8b,
    F2l = 0x8c,
    F2d = 0x8d,
    D2i = 0x8e,
    D2l = 0x8f,
    D2f = 0x90,
    I2b = 0x91,
    I2c = 0x92,
    I2s = 0x93,
    Lcmp = 0x94,
    Fcmpl = 0x95,
    Fcmpg = 0x96,
    Dcmpl = 0x97,
    Dcmpg = 0x98,
    Ifeq = 0x99,
    Ifne = 0x9a,
    Iflt = 0x9b,
    Ifge = 0x9c,
    Ifgt = 0x9d,
    Ifle = 0x9e,
    IfIcmpeq = 0x9f,
    IfIcmpne = 0xa0,
    IfIcmplt = 0xa1,
    IfIcmpge = 0xa2,
    IfIcmpgt = 0xa3,
    IfIcmple = 0xa4,
    IfAcmpeq = 0xa5,
    IfAcmpne = 0xa6,
    Goto = 0xa7,
    Jsr = 0xa8,
    Ret = 0xa9,
    Tableswitch = 0xaa,
    Lookupswitch = 0xab,
    Ireturn = 0xac,
    Lreturn = 0xad,
    Freturn = 0xae,
    Dreturn = 0xaf,
    Areturn = 0xb0,
    Return = 0xb1,
    Getstatic = 0xb2,
    Putstatic = 0xb3,
    Getfield = 0xb4,
    Putfield = 0xb5,
    Invokevirtual = 0xb6,
    Invokespecial = 0xb7,
    Invokestatic = 0xb8,
    Invokeinterface = 0xb9,
    Invokedynamic = 0xba,
    New = 0xbb,
    Newarray = 0xbc,
    Anewarray = 0xbd,
    Arraylength = 0xbe,
    Athrow = 0xbf,
    Checkcast = 0xc0,
    Instanceof = 0xc1,
    Monitorenter = 0xc2,
    Monitorexit = 0xc3,
    Wide = 0xc4,
    Multianewarray = 0xc5,
    Ifnull = 0xc6,
    Ifnonnull = 0xc7,
    GotoW = 0xc8,
    JsrW = 0xc9,
}

impl JvmOpcode {
    /// Decode a raw opcode byte into a `JvmOpcode`.
    ///
    /// Returns `None` for bytes in the reserved range `0xca..=0xff`.
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        // SAFETY: the match below covers every valid variant explicitly.
        Some(match b {
            0x00 => Self::Nop,
            0x01 => Self::AconstNull,
            0x02 => Self::IconstM1,
            0x03 => Self::Iconst0,
            0x04 => Self::Iconst1,
            0x05 => Self::Iconst2,
            0x06 => Self::Iconst3,
            0x07 => Self::Iconst4,
            0x08 => Self::Iconst5,
            0x09 => Self::Lconst0,
            0x0a => Self::Lconst1,
            0x0b => Self::Fconst0,
            0x0c => Self::Fconst1,
            0x0d => Self::Fconst2,
            0x0e => Self::Dconst0,
            0x0f => Self::Dconst1,
            0x10 => Self::Bipush,
            0x11 => Self::Sipush,
            0x12 => Self::Ldc,
            0x13 => Self::LdcW,
            0x14 => Self::Ldc2W,
            0x15 => Self::Iload,
            0x16 => Self::Lload,
            0x17 => Self::Fload,
            0x18 => Self::Dload,
            0x19 => Self::Aload,
            0x1a => Self::Iload0,
            0x1b => Self::Iload1,
            0x1c => Self::Iload2,
            0x1d => Self::Iload3,
            0x1e => Self::Lload0,
            0x1f => Self::Lload1,
            0x20 => Self::Lload2,
            0x21 => Self::Lload3,
            0x22 => Self::Fload0,
            0x23 => Self::Fload1,
            0x24 => Self::Fload2,
            0x25 => Self::Fload3,
            0x26 => Self::Dload0,
            0x27 => Self::Dload1,
            0x28 => Self::Dload2,
            0x29 => Self::Dload3,
            0x2a => Self::Aload0,
            0x2b => Self::Aload1,
            0x2c => Self::Aload2,
            0x2d => Self::Aload3,
            0x2e => Self::Iaload,
            0x2f => Self::Laload,
            0x30 => Self::Faload,
            0x31 => Self::Daload,
            0x32 => Self::Aaload,
            0x33 => Self::Baload,
            0x34 => Self::Caload,
            0x35 => Self::Saload,
            0x36 => Self::Istore,
            0x37 => Self::Lstore,
            0x38 => Self::Fstore,
            0x39 => Self::Dstore,
            0x3a => Self::Astore,
            0x3b => Self::Istore0,
            0x3c => Self::Istore1,
            0x3d => Self::Istore2,
            0x3e => Self::Istore3,
            0x3f => Self::Lstore0,
            0x40 => Self::Lstore1,
            0x41 => Self::Lstore2,
            0x42 => Self::Lstore3,
            0x43 => Self::Fstore0,
            0x44 => Self::Fstore1,
            0x45 => Self::Fstore2,
            0x46 => Self::Fstore3,
            0x47 => Self::Dstore0,
            0x48 => Self::Dstore1,
            0x49 => Self::Dstore2,
            0x4a => Self::Dstore3,
            0x4b => Self::Astore0,
            0x4c => Self::Astore1,
            0x4d => Self::Astore2,
            0x4e => Self::Astore3,
            0x4f => Self::Iastore,
            0x50 => Self::Lastore,
            0x51 => Self::Fastore,
            0x52 => Self::Dastore,
            0x53 => Self::Aastore,
            0x54 => Self::Bastore,
            0x55 => Self::Castore,
            0x56 => Self::Sastore,
            0x57 => Self::Pop,
            0x58 => Self::Pop2,
            0x59 => Self::Dup,
            0x5a => Self::DupX1,
            0x5b => Self::DupX2,
            0x5c => Self::Dup2,
            0x5d => Self::Dup2X1,
            0x5e => Self::Dup2X2,
            0x5f => Self::Swap,
            0x60 => Self::Iadd,
            0x61 => Self::Ladd,
            0x62 => Self::Fadd,
            0x63 => Self::Dadd,
            0x64 => Self::Isub,
            0x65 => Self::Lsub,
            0x66 => Self::Fsub,
            0x67 => Self::Dsub,
            0x68 => Self::Imul,
            0x69 => Self::Lmul,
            0x6a => Self::Fmul,
            0x6b => Self::Dmul,
            0x6c => Self::Idiv,
            0x6d => Self::Ldiv,
            0x6e => Self::Fdiv,
            0x6f => Self::Ddiv,
            0x70 => Self::Irem,
            0x71 => Self::Lrem,
            0x72 => Self::Frem,
            0x73 => Self::Drem,
            0x74 => Self::Ineg,
            0x75 => Self::Lneg,
            0x76 => Self::Fneg,
            0x77 => Self::Dneg,
            0x78 => Self::Ishl,
            0x79 => Self::Lshl,
            0x7a => Self::Ishr,
            0x7b => Self::Lshr,
            0x7c => Self::Iushr,
            0x7d => Self::Lushr,
            0x7e => Self::Iand,
            0x7f => Self::Land,
            0x80 => Self::Ior,
            0x81 => Self::Lor,
            0x82 => Self::Ixor,
            0x83 => Self::Lxor,
            0x84 => Self::Iinc,
            0x85 => Self::I2l,
            0x86 => Self::I2f,
            0x87 => Self::I2d,
            0x88 => Self::L2i,
            0x89 => Self::L2f,
            0x8a => Self::L2d,
            0x8b => Self::F2i,
            0x8c => Self::F2l,
            0x8d => Self::F2d,
            0x8e => Self::D2i,
            0x8f => Self::D2l,
            0x90 => Self::D2f,
            0x91 => Self::I2b,
            0x92 => Self::I2c,
            0x93 => Self::I2s,
            0x94 => Self::Lcmp,
            0x95 => Self::Fcmpl,
            0x96 => Self::Fcmpg,
            0x97 => Self::Dcmpl,
            0x98 => Self::Dcmpg,
            0x99 => Self::Ifeq,
            0x9a => Self::Ifne,
            0x9b => Self::Iflt,
            0x9c => Self::Ifge,
            0x9d => Self::Ifgt,
            0x9e => Self::Ifle,
            0x9f => Self::IfIcmpeq,
            0xa0 => Self::IfIcmpne,
            0xa1 => Self::IfIcmplt,
            0xa2 => Self::IfIcmpge,
            0xa3 => Self::IfIcmpgt,
            0xa4 => Self::IfIcmple,
            0xa5 => Self::IfAcmpeq,
            0xa6 => Self::IfAcmpne,
            0xa7 => Self::Goto,
            0xa8 => Self::Jsr,
            0xa9 => Self::Ret,
            0xaa => Self::Tableswitch,
            0xab => Self::Lookupswitch,
            0xac => Self::Ireturn,
            0xad => Self::Lreturn,
            0xae => Self::Freturn,
            0xaf => Self::Dreturn,
            0xb0 => Self::Areturn,
            0xb1 => Self::Return,
            0xb2 => Self::Getstatic,
            0xb3 => Self::Putstatic,
            0xb4 => Self::Getfield,
            0xb5 => Self::Putfield,
            0xb6 => Self::Invokevirtual,
            0xb7 => Self::Invokespecial,
            0xb8 => Self::Invokestatic,
            0xb9 => Self::Invokeinterface,
            0xba => Self::Invokedynamic,
            0xbb => Self::New,
            0xbc => Self::Newarray,
            0xbd => Self::Anewarray,
            0xbe => Self::Arraylength,
            0xbf => Self::Athrow,
            0xc0 => Self::Checkcast,
            0xc1 => Self::Instanceof,
            0xc2 => Self::Monitorenter,
            0xc3 => Self::Monitorexit,
            0xc4 => Self::Wide,
            0xc5 => Self::Multianewarray,
            0xc6 => Self::Ifnull,
            0xc7 => Self::Ifnonnull,
            0xc8 => Self::GotoW,
            0xc9 => Self::JsrW,
            _ => return None,
        })
    }

    /// Return the canonical mnemonic string for this opcode.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        jvm_opcode_name(self as u8)
    }

    /// Return the fixed instruction size in bytes, or 0 for variable-length
    /// opcodes (`Tableswitch`, `Lookupswitch`, `Wide`).
    #[must_use]
    pub const fn fixed_size(self) -> usize {
        jvm_instruction_size(self as u8)
    }

    /// Returns `true` for opcodes that transfer control flow.
    #[must_use]
    pub const fn is_control(self) -> bool {
        matches!(
            self,
            Self::Ifeq
                | Self::Ifne
                | Self::Iflt
                | Self::Ifge
                | Self::Ifgt
                | Self::Ifle
                | Self::IfIcmpeq
                | Self::IfIcmpne
                | Self::IfIcmplt
                | Self::IfIcmpge
                | Self::IfIcmpgt
                | Self::IfIcmple
                | Self::IfAcmpeq
                | Self::IfAcmpne
                | Self::Goto
                | Self::Jsr
                | Self::Ret
                | Self::Tableswitch
                | Self::Lookupswitch
                | Self::Ireturn
                | Self::Lreturn
                | Self::Freturn
                | Self::Dreturn
                | Self::Areturn
                | Self::Return
                | Self::Invokevirtual
                | Self::Invokespecial
                | Self::Invokestatic
                | Self::Invokeinterface
                | Self::Invokedynamic
                | Self::Athrow
                | Self::Ifnull
                | Self::Ifnonnull
                | Self::GotoW
                | Self::JsrW
        )
    }
}

// ---------------------------------------------------------------------------
// jvm_opcode_name — canonical mnemonic look-up
// ---------------------------------------------------------------------------

/// Return the canonical JVM mnemonic for an opcode byte.
///
/// Returns `"<unknown>"` for bytes in the reserved range `0xca..=0xff`.
#[must_use]
pub const fn jvm_opcode_name(op: u8) -> &'static str {
    match op {
        0x00 => "nop",
        0x01 => "aconst_null",
        0x02 => "iconst_m1",
        0x03 => "iconst_0",
        0x04 => "iconst_1",
        0x05 => "iconst_2",
        0x06 => "iconst_3",
        0x07 => "iconst_4",
        0x08 => "iconst_5",
        0x09 => "lconst_0",
        0x0a => "lconst_1",
        0x0b => "fconst_0",
        0x0c => "fconst_1",
        0x0d => "fconst_2",
        0x0e => "dconst_0",
        0x0f => "dconst_1",
        0x10 => "bipush",
        0x11 => "sipush",
        0x12 => "ldc",
        0x13 => "ldc_w",
        0x14 => "ldc2_w",
        0x15 => "iload",
        0x16 => "lload",
        0x17 => "fload",
        0x18 => "dload",
        0x19 => "aload",
        0x1a => "iload_0",
        0x1b => "iload_1",
        0x1c => "iload_2",
        0x1d => "iload_3",
        0x1e => "lload_0",
        0x1f => "lload_1",
        0x20 => "lload_2",
        0x21 => "lload_3",
        0x22 => "fload_0",
        0x23 => "fload_1",
        0x24 => "fload_2",
        0x25 => "fload_3",
        0x26 => "dload_0",
        0x27 => "dload_1",
        0x28 => "dload_2",
        0x29 => "dload_3",
        0x2a => "aload_0",
        0x2b => "aload_1",
        0x2c => "aload_2",
        0x2d => "aload_3",
        0x2e => "iaload",
        0x2f => "laload",
        0x30 => "faload",
        0x31 => "daload",
        0x32 => "aaload",
        0x33 => "baload",
        0x34 => "caload",
        0x35 => "saload",
        0x36 => "istore",
        0x37 => "lstore",
        0x38 => "fstore",
        0x39 => "dstore",
        0x3a => "astore",
        0x3b => "istore_0",
        0x3c => "istore_1",
        0x3d => "istore_2",
        0x3e => "istore_3",
        0x3f => "lstore_0",
        0x40 => "lstore_1",
        0x41 => "lstore_2",
        0x42 => "lstore_3",
        0x43 => "fstore_0",
        0x44 => "fstore_1",
        0x45 => "fstore_2",
        0x46 => "fstore_3",
        0x47 => "dstore_0",
        0x48 => "dstore_1",
        0x49 => "dstore_2",
        0x4a => "dstore_3",
        0x4b => "astore_0",
        0x4c => "astore_1",
        0x4d => "astore_2",
        0x4e => "astore_3",
        0x4f => "iastore",
        0x50 => "lastore",
        0x51 => "fastore",
        0x52 => "dastore",
        0x53 => "aastore",
        0x54 => "bastore",
        0x55 => "castore",
        0x56 => "sastore",
        0x57 => "pop",
        0x58 => "pop2",
        0x59 => "dup",
        0x5a => "dup_x1",
        0x5b => "dup_x2",
        0x5c => "dup2",
        0x5d => "dup2_x1",
        0x5e => "dup2_x2",
        0x5f => "swap",
        0x60 => "iadd",
        0x61 => "ladd",
        0x62 => "fadd",
        0x63 => "dadd",
        0x64 => "isub",
        0x65 => "lsub",
        0x66 => "fsub",
        0x67 => "dsub",
        0x68 => "imul",
        0x69 => "lmul",
        0x6a => "fmul",
        0x6b => "dmul",
        0x6c => "idiv",
        0x6d => "ldiv",
        0x6e => "fdiv",
        0x6f => "ddiv",
        0x70 => "irem",
        0x71 => "lrem",
        0x72 => "frem",
        0x73 => "drem",
        0x74 => "ineg",
        0x75 => "lneg",
        0x76 => "fneg",
        0x77 => "dneg",
        0x78 => "ishl",
        0x79 => "lshl",
        0x7a => "ishr",
        0x7b => "lshr",
        0x7c => "iushr",
        0x7d => "lushr",
        0x7e => "iand",
        0x7f => "land",
        0x80 => "ior",
        0x81 => "lor",
        0x82 => "ixor",
        0x83 => "lxor",
        0x84 => "iinc",
        0x85 => "i2l",
        0x86 => "i2f",
        0x87 => "i2d",
        0x88 => "l2i",
        0x89 => "l2f",
        0x8a => "l2d",
        0x8b => "f2i",
        0x8c => "f2l",
        0x8d => "f2d",
        0x8e => "d2i",
        0x8f => "d2l",
        0x90 => "d2f",
        0x91 => "i2b",
        0x92 => "i2c",
        0x93 => "i2s",
        0x94 => "lcmp",
        0x95 => "fcmpl",
        0x96 => "fcmpg",
        0x97 => "dcmpl",
        0x98 => "dcmpg",
        0x99 => "ifeq",
        0x9a => "ifne",
        0x9b => "iflt",
        0x9c => "ifge",
        0x9d => "ifgt",
        0x9e => "ifle",
        0x9f => "if_icmpeq",
        0xa0 => "if_icmpne",
        0xa1 => "if_icmplt",
        0xa2 => "if_icmpge",
        0xa3 => "if_icmpgt",
        0xa4 => "if_icmple",
        0xa5 => "if_acmpeq",
        0xa6 => "if_acmpne",
        0xa7 => "goto",
        0xa8 => "jsr",
        0xa9 => "ret",
        0xaa => "tableswitch",
        0xab => "lookupswitch",
        0xac => "ireturn",
        0xad => "lreturn",
        0xae => "freturn",
        0xaf => "dreturn",
        0xb0 => "areturn",
        0xb1 => "return",
        0xb2 => "getstatic",
        0xb3 => "putstatic",
        0xb4 => "getfield",
        0xb5 => "putfield",
        0xb6 => "invokevirtual",
        0xb7 => "invokespecial",
        0xb8 => "invokestatic",
        0xb9 => "invokeinterface",
        0xba => "invokedynamic",
        0xbb => "new",
        0xbc => "newarray",
        0xbd => "anewarray",
        0xbe => "arraylength",
        0xbf => "athrow",
        0xc0 => "checkcast",
        0xc1 => "instanceof",
        0xc2 => "monitorenter",
        0xc3 => "monitorexit",
        0xc4 => "wide",
        0xc5 => "multianewarray",
        0xc6 => "ifnull",
        0xc7 => "ifnonnull",
        0xc8 => "goto_w",
        0xc9 => "jsr_w",
        _ => "<unknown>",
    }
}

// ---------------------------------------------------------------------------
// jvm_instruction_size — fixed operand-byte count look-up
// ---------------------------------------------------------------------------

/// Ordered `(lo, hi, size)` rows giving the fixed byte size of each JVM opcode
/// range. Scanned in order by [`jvm_instruction_size`]; the first row whose
/// range contains the opcode wins, so overlapping ranges are resolved by
/// listing the more specific row first.
///
/// A size of `0` marks a variable-length or reserved opcode.
const JVM_INSTRUCTION_SIZE_TABLE: &[(u8, u8, usize)] = &[
    // Nop, AconstNull, IconstM1..Iconst5, Lconst0..Dconst1: opcode only
    (0x00, 0x0f, 1),
    // Bipush: opcode + 1-byte signed immediate
    (0x10, 0x10, 2),
    // Sipush: opcode + 2-byte signed immediate
    (0x11, 0x11, 3),
    // Ldc: opcode + 1-byte cp index
    (0x12, 0x12, 2),
    // LdcW / Ldc2W: opcode + 2-byte cp index
    (0x13, 0x14, 3),
    // Iload..Aload: opcode + 1-byte local index
    (0x15, 0x19, 2),
    // Iload0..Aload3, Iaload..Saload: no operands
    (0x1a, 0x35, 1),
    // Istore..Astore: opcode + 1-byte local index
    (0x36, 0x3a, 2),
    // Istore0..Astore3, Iastore..Sastore: no operands
    (0x3b, 0x56, 1),
    // Pop..Swap: no operands
    (0x57, 0x5f, 1),
    // Iadd..Lxor: no operands
    (0x60, 0x83, 1),
    // Iinc: opcode + index(1) + const(1) = 3 bytes
    (0x84, 0x84, 3),
    // I2l..I2s, Lcmp..Dcmpg: no operands
    (0x85, 0x98, 1),
    // Ifeq..IfAcmpne: opcode + 2-byte signed branch offset = 3
    (0x99, 0xa6, 3),
    // Goto: 3, Jsr: 3
    (0xa7, 0xa8, 3),
    // Ret: opcode + 1-byte local index = 2
    (0xa9, 0xa9, 2),
    // Tableswitch, Lookupswitch: variable (alignment padding + data)
    (0xaa, 0xab, 0),
    // Ireturn..return: no operands
    (0xac, 0xb1, 1),
    // Getstatic..Putfield: opcode + 2-byte cp index = 3
    (0xb2, 0xb5, 3),
    // Invokevirtual..Invokestatic: opcode + 2-byte cp index = 3
    (0xb6, 0xb8, 3),
    // Invokeinterface: opcode + 2-byte cp index + count + 0 = 5
    // Invokedynamic:   opcode + 2-byte cp index + 0 + 0 = 5
    (0xb9, 0xba, 5),
    // new: opcode + 2-byte cp index = 3
    (0xbb, 0xbb, 3),
    // Newarray: opcode + 1-byte atype = 2
    (0xbc, 0xbc, 2),
    // Anewarray: opcode + 2-byte cp index = 3
    (0xbd, 0xbd, 3),
    // Arraylength, Athrow: no operands
    (0xbe, 0xbf, 1),
    // Checkcast, Instanceof: opcode + 2-byte cp index = 3
    (0xc0, 0xc1, 3),
    // Monitorenter, Monitorexit: no operands
    (0xc2, 0xc3, 1),
    // Wide: prefix — size depends on sub-opcode (variable)
    (0xc4, 0xc4, 0),
    // Multianewarray: opcode + 2-byte cp index + dims byte = 4
    (0xc5, 0xc5, 4),
    // Ifnull, Ifnonnull: opcode + 2-byte branch offset = 3
    (0xc6, 0xc7, 3),
    // GotoW, JsrW: opcode + 4-byte branch offset = 5
    (0xc8, 0xc9, 5),
    // Reserved / implementation-defined (0xca..=0xff): unknown size
    (0xca, 0xff, 0),
];

/// Return the total instruction size (opcode byte + operand bytes) for a JVM
/// opcode.
///
/// Returns `0` for variable-length opcodes (`Tableswitch` = 0xaa,
/// `Lookupswitch` = 0xab) and for the `Wide` prefix (0xc4), whose size
/// depends on the following sub-opcode.
///
/// Reserved opcodes (`0xca..=0xff`) also return `0`.
#[must_use]
pub const fn jvm_instruction_size(op: u8) -> usize {
    let mut i = 0;
    while i < JVM_INSTRUCTION_SIZE_TABLE.len() {
        let (lo, hi, size) = JVM_INSTRUCTION_SIZE_TABLE[i];
        if op >= lo && op <= hi {
            return size;
        }
        i += 1;
    }
    0
}

// ---------------------------------------------------------------------------
// JvmInstruction / JvmDisassembler
// ---------------------------------------------------------------------------

/// A disassembled JVM instruction produced by [`JvmDisassembler`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JvmInstruction {
    /// Byte offset from the start of the bytecode slice passed to
    /// [`JvmDisassembler::disassemble`].
    pub offset: usize,
    /// Raw opcode byte.
    pub opcode: u8,
    /// Decoded operands.  For single-operand instructions this has one entry;
    /// for two-operand instructions (e.g. `Invokeinterface`) two entries; for
    /// zero-operand instructions it is empty.
    pub operands: Vec<u32>,
}

/// Higher-level disassembler that produces [`JvmInstruction`] records instead
/// of the lower-level `JvmInstr` structs used by the architecture trait.
///
/// Unlike `JvmLinearDisassembler`, this type decodes the complete bytecode
/// slice eagerly and returns a `Vec`.
pub struct JvmDisassembler;

impl JvmDisassembler {
    /// Disassemble all instructions from a raw bytecode slice.
    ///
    /// Unknown or reserved opcodes are represented with an empty operand list
    /// and skipped over one byte at a time to maximise coverage.
    #[must_use]
    pub fn disassemble(bytecode: &[u8]) -> Vec<JvmInstruction> {
        let mut result = Vec::with_capacity(bytecode.len() / 2);
        let mut off = 0usize;

        while off < bytecode.len() {
            let op = bytecode[off];
            // Use the existing decode logic to handle variable-length ops.
            if let Ok((instr, consumed)) = JvmInstr::decode_at(&bytecode[off..], off) {
                let operands = Self::extract_operands(&instr);
                result.push(JvmInstruction {
                    offset: off,
                    opcode: op,
                    operands,
                });
                off += consumed;
            } else {
                // Emit a placeholder for undecodable bytes.
                result.push(JvmInstruction {
                    offset: off,
                    opcode: op,
                    operands: vec![],
                });
                off += 1;
            }
        }

        result
    }

    /// Extract numeric operands from a decoded [`JvmInstr`].
    fn extract_operands(instr: &JvmInstr) -> Vec<u32> {
        let raw = &instr.raw;
        if raw.is_empty() {
            return vec![];
        }
        let op = raw[0];
        match op {
            // 1-byte index/immediate
            0x10 | 0x12 | 0x15..=0x19 | 0x36..=0x3a | 0xa9 | 0xbc => {
                if raw.len() >= 2 {
                    vec![u32::from(raw[1])]
                } else {
                    vec![]
                }
            }
            // Invokeinterface: 2-byte cp index + count byte (must come before the b2..=b9 arm)
            // Multianewarray (0xc5): 2-byte cp index + dimension byte — same shape.
            0xb9 | 0xc5 => {
                if raw.len() >= 4 {
                    vec![
                        u32::from(u16::from_be_bytes([raw[1], raw[2]])),
                        u32::from(raw[3]),
                    ]
                } else {
                    vec![]
                }
            }
            // 2-byte big-endian u16 index
            0x11 | 0x13 | 0x14 | 0xb2..=0xb8 | 0xba | 0xbb | 0xbd | 0xc0 | 0xc1 | 0xc6 | 0xc7 => {
                if raw.len() >= 3 {
                    vec![u32::from(u16::from_be_bytes([raw[1], raw[2]]))]
                } else {
                    vec![]
                }
            }
            // Iinc: index + signed constant
            0x84 => {
                if raw.len() >= 3 {
                    vec![u32::from(raw[1]), u32::from(raw[2])]
                } else {
                    vec![]
                }
            }
            // 4-byte signed offset (GotoW/JsrW)
            0xc8 | 0xc9 => {
                if raw.len() >= 5 {
                    let v = i32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]);
                    vec![v.cast_unsigned()]
                } else {
                    vec![]
                }
            }
            // Tableswitch/Lookupswitch: return the default offset as the only
            // extracted operand (full table decoding via JvmInstr is preferred).
            0xaa | 0xab => {
                // Minimum: op + 3 pad + default(4) = 8
                if raw.len() >= 8 {
                    let base = 4; // 1 op + 3 pad
                    let default_off = i32::from_be_bytes([
                        raw[base],
                        raw[base + 1],
                        raw[base + 2],
                        raw[base + 3],
                    ]);
                    vec![default_off.cast_unsigned()]
                } else {
                    vec![]
                }
            }
            // Wide prefix: sub-opcode at [1], index at [2..3]
            0xc4 => {
                if raw.len() >= 4 {
                    vec![
                        u32::from(raw[1]),
                        u32::from(u16::from_be_bytes([raw[2], raw[3]])),
                    ]
                } else {
                    vec![]
                }
            }
            // No operands
            _ => vec![],
        }
    }

    /// Format a [`JvmInstruction`] as a human-readable string.
    #[must_use]
    pub fn to_text(instr: &JvmInstruction) -> String {
        let mne = jvm_opcode_name(instr.opcode);
        if instr.operands.is_empty() {
            format!("{:#06x}  {}", instr.offset, mne)
        } else {
            let ops: Vec<String> = instr.operands.iter().map(|v| format!("{v}")).collect();
            format!("{:#06x}  {} {}", instr.offset, mne, ops.join(", "))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests for JvmOpcode, jvm_opcode_name, jvm_instruction_size, JvmDisassembler
// ---------------------------------------------------------------------------

#[cfg(test)]
mod jvm_semantics_tests {
    use super::*;

    // --- JvmOpcode::from_u8 ---

    #[test]
    fn test_jvm_opcode_from_u8_nop() {
        assert_eq!(JvmOpcode::from_u8(0x00), Some(JvmOpcode::Nop));
    }

    #[test]
    fn test_jvm_opcode_from_u8_return() {
        assert_eq!(JvmOpcode::from_u8(0xb1), Some(JvmOpcode::Return));
    }

    #[test]
    fn test_jvm_opcode_from_u8_reserved() {
        assert!(JvmOpcode::from_u8(0xca).is_none());
        assert!(JvmOpcode::from_u8(0xff).is_none());
    }

    #[test]
    fn test_jvm_opcode_from_u8_all_valid() {
        // All bytes 0x00..=0xc9 must decode successfully.
        for op in 0x00u8..=0xc9 {
            assert!(
                JvmOpcode::from_u8(op).is_some(),
                "opcode 0x{op:02x} failed to decode"
            );
        }
    }

    #[test]
    fn test_jvm_opcode_mnemonic() {
        assert_eq!(JvmOpcode::Nop.mnemonic(), "nop");
        assert_eq!(JvmOpcode::Iadd.mnemonic(), "iadd");
        assert_eq!(JvmOpcode::Invokevirtual.mnemonic(), "invokevirtual");
        assert_eq!(JvmOpcode::Return.mnemonic(), "return");
    }

    #[test]
    fn test_jvm_opcode_is_control() {
        assert!(JvmOpcode::Goto.is_control());
        assert!(JvmOpcode::Ifeq.is_control());
        assert!(JvmOpcode::Invokevirtual.is_control());
        assert!(JvmOpcode::Return.is_control());
        assert!(!JvmOpcode::Iadd.is_control());
        assert!(!JvmOpcode::Nop.is_control());
    }

    // --- jvm_opcode_name ---

    #[test]
    fn test_jvm_opcode_name_spot_checks() {
        assert_eq!(jvm_opcode_name(0x00), "nop");
        assert_eq!(jvm_opcode_name(0x60), "iadd");
        assert_eq!(jvm_opcode_name(0xb6), "invokevirtual");
        assert_eq!(jvm_opcode_name(0xb9), "invokeinterface");
        assert_eq!(jvm_opcode_name(0xc8), "goto_w");
        assert_eq!(jvm_opcode_name(0xff), "<unknown>");
    }

    #[test]
    fn test_jvm_opcode_name_no_empty_for_valid() {
        for op in 0x00u8..=0xc9 {
            assert!(
                !jvm_opcode_name(op).is_empty(),
                "empty mnemonic for 0x{op:02x}"
            );
        }
    }

    // --- jvm_instruction_size ---

    #[test]
    fn test_instruction_size_nop() {
        assert_eq!(jvm_instruction_size(0x00), 1);
    }

    #[test]
    fn test_instruction_size_bipush() {
        assert_eq!(jvm_instruction_size(0x10), 2);
    }

    #[test]
    fn test_instruction_size_sipush() {
        assert_eq!(jvm_instruction_size(0x11), 3);
    }

    #[test]
    fn test_instruction_size_iinc() {
        assert_eq!(jvm_instruction_size(0x84), 3);
    }

    #[test]
    fn test_instruction_size_invokevirtual() {
        assert_eq!(jvm_instruction_size(0xb6), 3);
    }

    #[test]
    fn test_instruction_size_invokeinterface() {
        assert_eq!(jvm_instruction_size(0xb9), 5);
    }

    #[test]
    fn test_instruction_size_goto_w() {
        assert_eq!(jvm_instruction_size(0xc8), 5);
    }

    #[test]
    fn test_instruction_size_tableswitch_variable() {
        assert_eq!(jvm_instruction_size(0xaa), 0);
    }

    #[test]
    fn test_instruction_size_wide_variable() {
        assert_eq!(jvm_instruction_size(0xc4), 0);
    }

    #[test]
    fn test_instruction_size_reserved() {
        assert_eq!(jvm_instruction_size(0xff), 0);
    }

    #[test]
    fn test_instruction_size_return_family() {
        for op in [0xac_u8, 0xad, 0xae, 0xaf, 0xb0, 0xb1] {
            assert_eq!(jvm_instruction_size(op), 1, "op=0x{op:02x}");
        }
    }

    // --- JvmDisassembler::disassemble / to_text ---

    #[test]
    fn test_disassembler_nop_sequence() {
        let bytecode = [0x00_u8, 0x00, 0x00];
        let instrs = JvmDisassembler::disassemble(&bytecode);
        assert_eq!(instrs.len(), 3);
        assert_eq!(instrs[0].offset, 0);
        assert_eq!(instrs[1].offset, 1);
        assert_eq!(instrs[2].offset, 2);
    }

    #[test]
    fn test_disassembler_bipush() {
        let bytecode = [0x10_u8, 0x2a]; // Bipush 42
        let instrs = JvmDisassembler::disassemble(&bytecode);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].opcode, 0x10);
        assert_eq!(instrs[0].operands, vec![42]);
    }

    #[test]
    fn test_disassembler_invokevirtual() {
        let bytecode = [0xb6_u8, 0x00, 0x1c]; // Invokevirtual #28
        let instrs = JvmDisassembler::disassemble(&bytecode);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].operands, vec![28]);
    }

    #[test]
    fn test_disassembler_iinc_operands() {
        let bytecode = [0x84_u8, 0x02, 0x01]; // Iinc local#2, 1
        let instrs = JvmDisassembler::disassemble(&bytecode);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].operands, vec![2, 1]);
    }

    #[test]
    fn test_disassembler_invokeinterface_two_operands() {
        let bytecode = [0xb9_u8, 0x00, 0x10, 0x02, 0x00];
        let instrs = JvmDisassembler::disassemble(&bytecode);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].operands, vec![16, 2]);
    }

    #[test]
    fn test_disassembler_multianewarray_operands() {
        let bytecode = [0xc5_u8, 0x00, 0x0a, 0x02];
        let instrs = JvmDisassembler::disassemble(&bytecode);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].operands, vec![10, 2]);
    }

    #[test]
    fn test_disassembler_empty_input() {
        assert!(JvmDisassembler::disassemble(&[]).is_empty());
    }

    #[test]
    fn test_disassembler_goto_w_operand() {
        let bytecode = [0xc8_u8, 0x00, 0x00, 0x01, 0x00]; // GotoW +256
        let instrs = JvmDisassembler::disassemble(&bytecode);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].operands, vec![256]);
    }

    #[test]
    fn test_disassembler_to_text_no_operands() {
        let instr = JvmInstruction {
            offset: 0,
            opcode: 0x00,
            operands: vec![],
        };
        let text = JvmDisassembler::to_text(&instr);
        assert!(text.contains("nop"));
        assert!(text.contains("0x0000"));
    }

    #[test]
    fn test_disassembler_to_text_with_operand() {
        let instr = JvmInstruction {
            offset: 4,
            opcode: 0x10,
            operands: vec![42],
        };
        let text = JvmDisassembler::to_text(&instr);
        assert!(text.contains("bipush"));
        assert!(text.contains("42"));
        assert!(text.contains("0x0004"));
    }

    #[test]
    fn test_disassembler_to_text_two_operands() {
        let instr = JvmInstruction {
            offset: 0,
            opcode: 0x84,
            operands: vec![2, 1],
        };
        let text = JvmDisassembler::to_text(&instr);
        assert!(text.contains("iinc"));
        assert!(text.contains("2, 1") || text.contains("2,"));
    }

    #[test]
    fn test_disassembler_full_program() {
        // Iconst1  Iconst2  Iadd  Ireturn
        let bytecode = [0x04_u8, 0x05, 0x60, 0xac];
        let instrs = JvmDisassembler::disassemble(&bytecode);
        assert_eq!(instrs.len(), 4);
        assert_eq!(jvm_opcode_name(instrs[0].opcode), "iconst_1");
        assert_eq!(jvm_opcode_name(instrs[1].opcode), "iconst_2");
        assert_eq!(jvm_opcode_name(instrs[2].opcode), "iadd");
        assert_eq!(jvm_opcode_name(instrs[3].opcode), "ireturn");
    }

    #[test]
    fn test_disassembler_offsets_increment_correctly() {
        // Ldc #5 (2 bytes) + Bipush 10 (2 bytes) + Iadd (1 byte)
        let bytecode = [0x12_u8, 0x05, 0x10, 0x0a, 0x60];
        let instrs = JvmDisassembler::disassemble(&bytecode);
        assert_eq!(instrs[0].offset, 0);
        assert_eq!(instrs[1].offset, 2);
        assert_eq!(instrs[2].offset, 4);
    }

    #[test]
    fn test_jvm_opcode_discriminant_values() {
        // Spot-check that the repr(u8) discriminants match the spec.
        assert_eq!(JvmOpcode::Nop as u8, 0x00);
        assert_eq!(JvmOpcode::Iadd as u8, 0x60);
        assert_eq!(JvmOpcode::Return as u8, 0xb1);
        assert_eq!(JvmOpcode::Invokevirtual as u8, 0xb6);
        assert_eq!(JvmOpcode::GotoW as u8, 0xc8);
        assert_eq!(JvmOpcode::JsrW as u8, 0xc9);
    }

    #[test]
    fn test_disassembler_wide_iload_operands() {
        let bytecode = [0xc4_u8, 0x15, 0x01, 0x00]; // Wide Iload 256
        let instrs = JvmDisassembler::disassemble(&bytecode);
        assert_eq!(instrs.len(), 1);
        // operands: [sub-opcode, Wide-index]
        assert_eq!(instrs[0].operands[0], 0x15); // Iload sub-opcode
        assert_eq!(instrs[0].operands[1], 256);
    }
}

// ---------------------------------------------------------------------------
// JVM Constant Pool types
// ---------------------------------------------------------------------------

/// Constant pool tag values as defined in the JVM specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CpTag {
    Utf8 = 1,
    Integer = 3,
    Float = 4,
    Long = 5,
    Double = 6,
    Class = 7,
    String = 8,
    Fieldref = 9,
    Methodref = 10,
    InterfaceMethodref = 11,
    NameAndType = 12,
    MethodHandle = 15,
    MethodType = 16,
    Dynamic = 17,
    InvokeDynamic = 18,
    Module = 19,
    Package = 20,
}

impl CpTag {
    /// Parse a raw u8 tag byte into a [`CpTag`].
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Utf8,
            3 => Self::Integer,
            4 => Self::Float,
            5 => Self::Long,
            6 => Self::Double,
            7 => Self::Class,
            8 => Self::String,
            9 => Self::Fieldref,
            10 => Self::Methodref,
            11 => Self::InterfaceMethodref,
            12 => Self::NameAndType,
            15 => Self::MethodHandle,
            16 => Self::MethodType,
            17 => Self::Dynamic,
            18 => Self::InvokeDynamic,
            19 => Self::Module,
            20 => Self::Package,
            _ => return None,
        })
    }

    /// Returns `true` if this constant pool entry occupies two slots (Long/Double).
    #[must_use]
    pub const fn is_double_slot(self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }

    /// Return the expected data length in bytes (not counting the tag byte).
    /// UTF8 and variable-length entries return `None`.
    #[must_use]
    pub const fn fixed_data_len(self) -> Option<usize> {
        Some(match self {
            Self::Long | Self::Double => 8,
            Self::Class | Self::String | Self::Module | Self::Package | Self::MethodType => 2,
            // 4-byte payloads: the two 32-bit numeric constants, and every
            // entry made of two 16-bit constant-pool indices.
            Self::Integer
            | Self::Float
            | Self::Fieldref
            | Self::Methodref
            | Self::InterfaceMethodref
            | Self::NameAndType
            | Self::Dynamic
            | Self::InvokeDynamic => 4,
            Self::MethodHandle => 3,
            Self::Utf8 => return None,
        })
    }
}

/// A single entry in the JVM constant pool.
#[derive(Debug, Clone, PartialEq)]
pub enum CpEntry {
    Utf8(String),
    Integer(i32),
    Float(f32),
    Long(i64),
    Double(f64),
    Class {
        name_index: u16,
    },
    StringRef {
        string_index: u16,
    },
    Fieldref {
        class_index: u16,
        name_and_type_index: u16,
    },
    Methodref {
        class_index: u16,
        name_and_type_index: u16,
    },
    InterfaceMethodref {
        class_index: u16,
        name_and_type_index: u16,
    },
    NameAndType {
        name_index: u16,
        descriptor_index: u16,
    },
    MethodHandle {
        reference_kind: u8,
        reference_index: u16,
    },
    MethodType {
        descriptor_index: u16,
    },
    Dynamic {
        bootstrap_method_attr_index: u16,
        name_and_type_index: u16,
    },
    InvokeDynamic {
        bootstrap_method_attr_index: u16,
        name_and_type_index: u16,
    },
    Module {
        name_index: u16,
    },
    Package {
        name_index: u16,
    },
    /// Placeholder for the second slot of Long/Double entries.
    Unused,
}

/// A parsed JVM constant pool.
#[derive(Debug, Default, Clone)]
pub struct ConstantPool {
    /// Entries indexed from 1 (slot 0 is never used per JVM spec).
    entries: Vec<Option<CpEntry>>,
}

impl ConstantPool {
    /// Create an empty constant pool.
    #[must_use]
    pub fn new() -> Self {
        // Slot 0 is reserved/unused.
        Self {
            entries: vec![None],
        }
    }

    /// Push a new entry and return its 1-based index.
    pub fn push(&mut self, entry: CpEntry) -> u16 {
        let double = matches!(entry, CpEntry::Long(_) | CpEntry::Double(_));
        let idx = crate::numeric::usize_to_u16(self.entries.len());
        self.entries.push(Some(entry));
        if double {
            self.entries.push(Some(CpEntry::Unused));
        }
        idx
    }

    /// Look up an entry by its 1-based constant pool index.
    #[must_use]
    pub fn get(&self, index: u16) -> Option<&CpEntry> {
        self.entries.get(index as usize)?.as_ref()
    }

    /// Return the number of slots (including the reserved slot 0).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the pool has no entries beyond slot 0.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.len() <= 1
    }

    /// Resolve a Utf8 entry at `index` to a `&str`.
    #[must_use]
    pub fn utf8(&self, index: u16) -> Option<&str> {
        match self.get(index)? {
            CpEntry::Utf8(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Resolve the class name for a Class entry.
    #[must_use]
    pub fn class_name(&self, class_index: u16) -> Option<&str> {
        if let CpEntry::Class { name_index } = self.get(class_index)? {
            self.utf8(*name_index)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// JVM stack-effect table
// ---------------------------------------------------------------------------

/// Describes how a JVM opcode affects the operand stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JvmStackEffect {
    /// Number of stack slots consumed (popped).
    pub pops: i8,
    /// Number of stack slots produced (pushed).
    pub pushes: i8,
}

impl JvmStackEffect {
    /// Net change to the stack depth (`pushes - pops`).
    #[must_use]
    pub const fn delta(self) -> i8 {
        self.pushes - self.pops
    }
}

/// Ordered `(lo, hi, pops, pushes)` rows giving the stack effect of each JVM
/// opcode range. Scanned in order by [`jvm_stack_effect`]; an opcode matched by
/// no row has a variable or context-dependent effect and yields `None`.
const JVM_STACK_EFFECT_TABLE: &[(u8, u8, i8, i8)] = &[
    (0x00, 0x00, 0, 0), // Nop
    (0x01, 0x01, 0, 1), // AconstNull
    (0x02, 0x08, 0, 1), // IconstM1..Iconst5
    (0x09, 0x0a, 0, 2), // Lconst0, Lconst1 (long = 2 slots)
    (0x0b, 0x0d, 0, 1), // Fconst0..Fconst2
    (0x0e, 0x0f, 0, 2), // Dconst0, Dconst1
    (0x10, 0x10, 0, 1), // Bipush
    (0x11, 0x11, 0, 1), // Sipush
    (0x12, 0x12, 0, 1), // Ldc
    (0x13, 0x13, 0, 1), // LdcW
    (0x14, 0x14, 0, 2), // Ldc2W
    (0x15, 0x19, 0, 1), // *load (variable slot count simplified)
    (0x1a, 0x2d, 0, 1), // Iload0..Aload3
    (0x2e, 0x35, 2, 1), // Iaload..Saload (pop arrayref + index, push element)
    (0x36, 0x4e, 1, 0), // Istore..Astore, Istore0..Astore3
    (0x4f, 0x56, 3, 0), // Iastore..Sastore (arrayref + index + value -> void)
    (0x57, 0x57, 1, 0), // Pop
    (0x58, 0x58, 2, 0), // Pop2
    (0x59, 0x59, 1, 2), // Dup
    (0x5a, 0x5a, 2, 3), // DupX1
    (0x5b, 0x5b, 3, 4), // DupX2
    (0x5c, 0x5c, 2, 4), // Dup2
    (0x5d, 0x5d, 3, 5), // Dup2X1
    (0x5e, 0x5e, 4, 6), // Dup2X2
    (0x5f, 0x5f, 2, 2), // Swap
    (0x60, 0x84, 2, 1), // Iadd..Lxor arithmetic (simplified to net 0 for binops)
    (0x85, 0x93, 1, 1), // I2l..I2s conversions
    (0x94, 0x98, 2, 1), // Lcmp, Fcmpl, Fcmpg, Dcmpl, Dcmpg
    (0x99, 0x9e, 1, 0), // Ifeq..Ifle (pop 1, branch)
    (0x9f, 0xa6, 2, 0), // IfIcmpeq..IfAcmpne (pop 2, branch)
    (0xa7, 0xa7, 0, 0), // Goto
    (0xa8, 0xa8, 0, 1), // Jsr
    (0xa9, 0xa9, 0, 0), // Ret
    (0xac, 0xb0, 1, 0), // Ireturn..Areturn (pop return value)
    (0xb1, 0xb1, 0, 0), // return (void)
    (0xb2, 0xb2, 0, 1), // Getstatic
    (0xb3, 0xb3, 1, 0), // Putstatic
    (0xb4, 0xb4, 1, 1), // Getfield
    (0xb5, 0xb5, 2, 0), // Putfield
    (0xbe, 0xbe, 1, 1), // Arraylength
    (0xbf, 0xbf, 1, 0), // Athrow
    (0xc0, 0xc1, 1, 1), // Checkcast, Instanceof
    (0xc2, 0xc3, 1, 0), // Monitorenter, Monitorexit
    (0xc6, 0xc7, 1, 0), // Ifnull, Ifnonnull
];

/// Return the stack effect of a single-byte JVM opcode.
///
/// Returns `None` for opcodes with variable or context-dependent effects
/// (`invoke*`, `Tableswitch`, `Lookupswitch`, `Wide`, reserved).
#[must_use]
pub const fn jvm_stack_effect(op: u8) -> Option<JvmStackEffect> {
    let mut i = 0;
    while i < JVM_STACK_EFFECT_TABLE.len() {
        let (lo, hi, pops, pushes) = JVM_STACK_EFFECT_TABLE[i];
        if op >= lo && op <= hi {
            return Some(JvmStackEffect { pops, pushes });
        }
        i += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// JVM verification types
// ---------------------------------------------------------------------------

/// Abstract type used during bytecode verification (richer variant carrying
/// resolved class names and offsets, distinct from the raw [`VerificationType`]
/// used in `StackMapTable` decoding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationTypeFull {
    Top,
    Integer,
    Float,
    Long,
    Double,
    Null,
    UninitializedThis,
    Object { class_name: String },
    Uninitialized { offset: u16 },
}

impl VerificationTypeFull {
    /// Return `true` if this type is a category-2 computational type
    /// (Long or Double, which occupy two stack slots).
    #[must_use]
    pub const fn is_category2(&self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }

    /// Return a short string representation suitable for diagnostics.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Top => "top",
            Self::Integer => "int",
            Self::Float => "float",
            Self::Long => "long",
            Self::Double => "double",
            Self::Null => "null",
            Self::UninitializedThis => "uninitializedThis",
            Self::Object { .. } => "object",
            Self::Uninitialized { .. } => "uninitialized",
        }
    }

    /// Check assignability: can a value of `from` type be stored where `self` is expected?
    #[must_use]
    pub fn is_assignable_from(&self, from: &Self) -> bool {
        match (self, from) {
            (Self::Top, _) => true,
            // Identical types are always assignable — this covers
            // (Integer, Integer) and every other exact match.
            (a, b) if a == b => true,
            (Self::Object { .. }, Self::Null) => true,
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// JVM CFG builder
// ---------------------------------------------------------------------------

/// A basic block in the JVM control-flow graph.
#[derive(Debug, Clone)]
pub struct JvmBlock {
    /// Byte offset of the first instruction in this block.
    pub start: usize,
    /// Byte offset one past the last instruction byte in this block.
    pub end: usize,
    /// Offsets of successor blocks (up to 2 for conditional branches,
    /// more for switch).
    pub successors: Vec<usize>,
}

/// Build a naive linear-sweep control-flow graph from JVM bytecode.
///
/// Returns a `Vec` of [`JvmBlock`]s in program order.  Each block ends at a
/// control-transfer instruction; fall-through edges are included automatically.
#[must_use]
pub fn jvm_build_cfg(bytecode: &[u8]) -> Vec<JvmBlock> {
    let instrs = JvmDisassembler::disassemble(bytecode);
    if instrs.is_empty() {
        return vec![];
    }

    // First pass: collect all branch targets so we know block leaders.
    let mut leaders: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    leaders.insert(0);

    for instr in &instrs {
        let op = instr.opcode;
        let off = instr.offset;
        // Branch instructions: Ifeq..IfAcmpne, Goto, Jsr, Ifnull, Ifnonnull
        let is_cond_branch = matches!(op, 0x99..=0xa6 | 0xc6 | 0xc7);
        let is_uncond_branch = matches!(op, 0xa7 | 0xc8); // Goto, GotoW
        let is_return = matches!(op, 0xac..=0xb1 | 0xbf);

        if (is_cond_branch || is_uncond_branch)
            && let Some(&offset_raw) = instr.operands.first() {
                let target = crate::numeric::i64_to_usize(numeric::usize_to_i64(off) + i64::from(offset_raw.cast_signed()));
                leaders.insert(target);
            }
        if (is_cond_branch || is_return) && off + 1 < bytecode.len() {
            // Determine next instruction offset.
            let size = jvm_instruction_size(op).max(1);
            leaders.insert(off + size);
        }
    }

    let leader_vec: Vec<usize> = leaders.into_iter().collect();
    let mut blocks = Vec::with_capacity(leader_vec.len());

    for (i, &start) in leader_vec.iter().enumerate() {
        let end = if i + 1 < leader_vec.len() {
            leader_vec[i + 1]
        } else {
            bytecode.len()
        };
        let mut successors = Vec::new();

        // Find the last instruction in this block to determine edges.
        let last_instr = instrs
            .iter()
            .rev()
            .find(|ins| ins.offset >= start && ins.offset < end);
        if let Some(last) = last_instr {
            let op = last.opcode;
            let off = last.offset;
            let is_return = matches!(op, 0xac..=0xb1 | 0xbf);
            if !is_return {
                // Unconditional or conditional branch.
                if let Some(&offset_raw) = last.operands.first() {
                    let target = crate::numeric::i64_to_usize(numeric::usize_to_i64(off) + i64::from(offset_raw.cast_signed()));
                    if target < bytecode.len() {
                        successors.push(target);
                    }
                }
                // Fall-through for conditional branches.
                if matches!(op, 0x99..=0xa6 | 0xc6 | 0xc7) {
                    let sz = jvm_instruction_size(op).max(1);
                    let ft = off + sz;
                    if ft < bytecode.len() {
                        successors.push(ft);
                    }
                }
                // Fall-through for non-branch instructions.
                if !matches!(op, 0xa7 | 0xc8 | 0xa8 | 0xc9 | 0xaa | 0xab)
                    && successors.is_empty() {
                        let sz = jvm_instruction_size(op).max(1);
                        let ft = off + sz;
                        if ft < bytecode.len() {
                            successors.push(ft);
                        }
                    }
            }
        }
        blocks.push(JvmBlock {
            start,
            end,
            successors,
        });
    }

    blocks
}

// ---------------------------------------------------------------------------
// JVM descriptor parsing
// ---------------------------------------------------------------------------

/// JVM type descriptor categories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JvmTypeDesc {
    Void,
    Boolean,
    Byte,
    Char,
    Short,
    Int,
    Long,
    Float,
    Double,
    Object(String),
    Array(Box<Self>),
}

impl JvmTypeDesc {
    /// Return the JVM descriptor character(s) for a primitive type.
    #[must_use]
    pub const fn descriptor_char(&self) -> char {
        match self {
            Self::Void => 'V',
            Self::Boolean => 'Z',
            Self::Byte => 'B',
            Self::Char => 'C',
            Self::Short => 'S',
            Self::Int => 'I',
            Self::Long => 'J',
            Self::Float => 'F',
            Self::Double => 'D',
            Self::Object(_) | Self::Array(_) => 'L',
        }
    }

    /// Compute the computational category (1 or 2).
    #[must_use]
    pub const fn category(&self) -> u8 {
        match self {
            Self::Long | Self::Double => 2,
            _ => 1,
        }
    }

    /// Parse a single field descriptor character.
    #[must_use]
    pub const fn from_char(c: char) -> Option<Self> {
        Some(match c {
            'V' => Self::Void,
            'Z' => Self::Boolean,
            'B' => Self::Byte,
            'C' => Self::Char,
            'S' => Self::Short,
            'I' => Self::Int,
            'J' => Self::Long,
            'F' => Self::Float,
            'D' => Self::Double,
            _ => return None,
        })
    }
}

/// Parse a JVM method descriptor into ([`JvmTypeDesc`] parameters, return type).
///
/// This is the typed variant returning [`JvmTypeDesc`]; see
/// [`parse_method_descriptor`] for the [`FieldDescriptor`]-based variant.
///
/// Returns `None` if the descriptor is malformed.
#[must_use]
pub fn parse_method_descriptor_typed(desc: &str) -> Option<(Vec<JvmTypeDesc>, JvmTypeDesc)> {
    let bytes = desc.as_bytes();
    if bytes.first() != Some(&b'(') {
        return None;
    }
    let mut i = 1;
    let mut params = Vec::new();
    while i < bytes.len() && bytes[i] != b')' {
        let (ty, consumed) = parse_field_descriptor(&desc[i..])?;
        params.push(ty);
        i += consumed;
    }
    if bytes.get(i) != Some(&b')') {
        return None;
    }
    i += 1;
    let (ret, _) = parse_field_descriptor(&desc[i..])?;
    Some((params, ret))
}

/// Parse a single field descriptor from the start of `desc`.
/// Returns `(type, bytes_consumed)`.
fn parse_field_descriptor(desc: &str) -> Option<(JvmTypeDesc, usize)> {
    let bytes = desc.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    match bytes[0] {
        b'V' => Some((JvmTypeDesc::Void, 1)),
        b'Z' => Some((JvmTypeDesc::Boolean, 1)),
        b'B' => Some((JvmTypeDesc::Byte, 1)),
        b'C' => Some((JvmTypeDesc::Char, 1)),
        b'S' => Some((JvmTypeDesc::Short, 1)),
        b'I' => Some((JvmTypeDesc::Int, 1)),
        b'J' => Some((JvmTypeDesc::Long, 1)),
        b'F' => Some((JvmTypeDesc::Float, 1)),
        b'D' => Some((JvmTypeDesc::Double, 1)),
        b'L' => {
            let end = desc.find(';')?;
            let class_name = desc[1..end].to_string();
            Some((JvmTypeDesc::Object(class_name), end + 1))
        }
        b'[' => {
            let (inner, consumed) = parse_field_descriptor(&desc[1..])?;
            Some((JvmTypeDesc::Array(Box::new(inner)), consumed + 1))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// JVM access flags
// ---------------------------------------------------------------------------

/// Access flag constants for JVM classes, fields, and methods.
pub mod access_flags {
    pub const ACC_PUBLIC: u16 = 0x0001;
    pub const ACC_PRIVATE: u16 = 0x0002;
    pub const ACC_PROTECTED: u16 = 0x0004;
    pub const ACC_STATIC: u16 = 0x0008;
    pub const ACC_FINAL: u16 = 0x0010;
    pub const ACC_SUPER: u16 = 0x0020; // class only
    pub const ACC_SYNCHRONIZED: u16 = 0x0020; // method only
    pub const ACC_VOLATILE: u16 = 0x0040; // field only
    pub const ACC_BRIDGE: u16 = 0x0040; // method only
    pub const ACC_TRANSIENT: u16 = 0x0080; // field only
    pub const ACC_VARARGS: u16 = 0x0080; // method only
    pub const ACC_NATIVE: u16 = 0x0100;
    pub const ACC_INTERFACE: u16 = 0x0200;
    pub const ACC_ABSTRACT: u16 = 0x0400;
    pub const ACC_STRICT: u16 = 0x0800;
    pub const ACC_SYNTHETIC: u16 = 0x1000;
    pub const ACC_ANNOTATION: u16 = 0x2000;
    pub const ACC_ENUM: u16 = 0x4000;
    pub const ACC_MODULE: u16 = 0x8000;

    /// Format access flags as a human-readable string for a method context.
    #[must_use]
    pub fn method_flags_str(flags: u16) -> String {
        let mut parts = Vec::new();
        if flags & ACC_PUBLIC != 0 {
            parts.push("public");
        }
        if flags & ACC_PRIVATE != 0 {
            parts.push("private");
        }
        if flags & ACC_PROTECTED != 0 {
            parts.push("protected");
        }
        if flags & ACC_STATIC != 0 {
            parts.push("static");
        }
        if flags & ACC_FINAL != 0 {
            parts.push("final");
        }
        if flags & ACC_SYNCHRONIZED != 0 {
            parts.push("synchronized");
        }
        if flags & ACC_NATIVE != 0 {
            parts.push("native");
        }
        if flags & ACC_ABSTRACT != 0 {
            parts.push("abstract");
        }
        if flags & ACC_STRICT != 0 {
            parts.push("strictfp");
        }
        if flags & ACC_SYNTHETIC != 0 {
            parts.push("synthetic");
        }
        if flags & ACC_BRIDGE != 0 {
            parts.push("bridge");
        }
        if flags & ACC_VARARGS != 0 {
            parts.push("varargs");
        }
        parts.join(" ")
    }
}

// ---------------------------------------------------------------------------
// Newarray type codes
// ---------------------------------------------------------------------------

/// Newarray `atype` constants.
pub mod newarray_type {
    pub const T_BOOLEAN: u8 = 4;
    pub const T_CHAR: u8 = 5;
    pub const T_FLOAT: u8 = 6;
    pub const T_DOUBLE: u8 = 7;
    pub const T_BYTE: u8 = 8;
    pub const T_SHORT: u8 = 9;
    pub const T_INT: u8 = 10;
    pub const T_LONG: u8 = 11;

    /// Return the element type name for a `Newarray` atype code.
    #[must_use]
    pub const fn name(atype: u8) -> Option<&'static str> {
        Some(match atype {
            4 => "boolean",
            5 => "char",
            6 => "float",
            7 => "double",
            8 => "byte",
            9 => "short",
            10 => "int",
            11 => "long",
            _ => return None,
        })
    }
}

// ---------------------------------------------------------------------------
// JvmOpcode: repr(u8) enum covering all 202 defined opcodes
// ---------------------------------------------------------------------------
// (Already defined earlier as JvmOpcode in the file; this companion function
//  provides additional metadata not in the opcode name alone.)

/// Return whether a JVM opcode is a branch instruction (conditional or
/// unconditional, including `Jsr`/`Ret` and `Tableswitch`/`Lookupswitch`).
#[must_use]
pub const fn jvm_is_branch(op: u8) -> bool {
    matches!(
        op,
        0x99..=0xa9   // Ifeq..Ret
        | 0xaa | 0xab // Tableswitch, Lookupswitch
        | 0xc6 | 0xc7 // Ifnull, Ifnonnull
        | 0xc8 | 0xc9 // GotoW, JsrW
    )
}

/// Return `true` if the opcode is a return instruction.
#[must_use]
pub const fn jvm_is_return(op: u8) -> bool {
    matches!(op, 0xac..=0xb1 | 0xbf) // Ireturn..return, Athrow
}

/// Return `true` if the opcode invokes a method.
#[must_use]
pub const fn jvm_is_invoke(op: u8) -> bool {
    matches!(op, 0xb6..=0xba) // Invokevirtual..Invokedynamic
}

/// Return `true` if the opcode creates a new object or array.
#[must_use]
pub const fn jvm_is_alloc(op: u8) -> bool {
    matches!(op, 0xbb | 0xbc | 0xbd | 0xc5) // new, Newarray, Anewarray, Multianewarray
}

/// Return `true` if the opcode accesses a field (static or instance).
#[must_use]
pub const fn jvm_is_field_access(op: u8) -> bool {
    matches!(op, 0xb2..=0xb5) // Getstatic..Putfield
}

// ---------------------------------------------------------------------------
// JVM method analysis helpers
// ---------------------------------------------------------------------------

/// Compute the maximum stack depth reachable by linear scan (conservative,
/// ignoring loop back-edges and exception handlers).
#[must_use]
pub fn jvm_max_stack_depth(bytecode: &[u8]) -> i32 {
    let instrs = JvmDisassembler::disassemble(bytecode);
    let mut depth: i32 = 0;
    let mut max: i32 = 0;
    for instr in &instrs {
        if let Some(se) = jvm_stack_effect(instr.opcode) {
            depth += i32::from(se.delta());
            if depth > max {
                max = depth;
            }
            if depth < 0 {
                depth = 0;
            } // reset on underflow (error recovery)
        }
    }
    max
}

/// Count the number of method invocations in a bytecode slice.
#[must_use]
pub fn jvm_count_invocations(bytecode: &[u8]) -> usize {
    let instrs = JvmDisassembler::disassemble(bytecode);
    instrs.iter().filter(|i| jvm_is_invoke(i.opcode)).count()
}

/// Count the number of allocation sites in a bytecode slice.
#[must_use]
pub fn jvm_count_allocations(bytecode: &[u8]) -> usize {
    let instrs = JvmDisassembler::disassemble(bytecode);
    instrs.iter().filter(|i| jvm_is_alloc(i.opcode)).count()
}

/// Estimate the cyclomatic complexity of a JVM method from its bytecode.
///
/// Uses the formula `M = B - E + 2` where B = number of blocks and E = edges,
/// but simplified here to `1 + number_of_conditional_branches`.
#[must_use]
pub fn jvm_cyclomatic_complexity(bytecode: &[u8]) -> u32 {
    let instrs = JvmDisassembler::disassemble(bytecode);
    let cond = instrs
        .iter()
        .filter(|i| matches!(i.opcode, 0x99..=0xa6 | 0xaa | 0xab | 0xc6 | 0xc7))
        .count();
    1 + crate::numeric::usize_to_u32(cond)
}

// ---------------------------------------------------------------------------
// JVM exception table entry
// ---------------------------------------------------------------------------

/// A single entry in a method's exception table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JvmExceptionEntry {
    /// Start of the try-region (inclusive), as a bytecode offset.
    pub start_pc: u16,
    /// End of the try-region (exclusive), as a bytecode offset.
    pub end_pc: u16,
    /// Start of the handler block, as a bytecode offset.
    pub handler_pc: u16,
    /// Constant pool index of the caught exception class, or 0 for `finally`.
    pub catch_type: u16,
}

impl JvmExceptionEntry {
    /// Return `true` if this handler is a `finally` clause (`catch_type` == 0).
    #[must_use]
    pub const fn is_finally(&self) -> bool {
        self.catch_type == 0
    }

    /// Return `true` if the given PC falls within the try-region.
    #[must_use]
    pub const fn covers(&self, pc: u16) -> bool {
        pc >= self.start_pc && pc < self.end_pc
    }
}

// ---------------------------------------------------------------------------
// Additional tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod jvm_extended_tests {
    use super::*;

    // ── Constant pool tests ─────────────────────────────────────────────────

    #[test]
    fn test_cp_push_and_get() {
        let mut cp = ConstantPool::new();
        let idx = cp.push(CpEntry::Utf8("Hello".into()));
        assert_eq!(idx, 1);
        assert_eq!(cp.utf8(1), Some("Hello"));
    }

    #[test]
    fn test_cp_double_slot() {
        let mut cp = ConstantPool::new();
        let idx = cp.push(CpEntry::Long(42));
        assert_eq!(idx, 1);
        // slot 2 should be Unused
        assert!(matches!(cp.get(2), Some(CpEntry::Unused)));
        assert_eq!(cp.len(), 3); // slot 0 + slot 1 (Long) + slot 2 (Unused)
    }

    #[test]
    fn test_cp_class_name_resolution() {
        let mut cp = ConstantPool::new();
        let name_idx = cp.push(CpEntry::Utf8("java/lang/String".into()));
        let class_idx = cp.push(CpEntry::Class {
            name_index: name_idx,
        });
        assert_eq!(cp.class_name(class_idx), Some("java/lang/String"));
    }

    #[test]
    fn test_cp_is_empty() {
        let cp = ConstantPool::new();
        assert!(cp.is_empty());
    }

    #[test]
    fn test_cp_tag_from_u8_valid() {
        assert_eq!(CpTag::from_u8(1), Some(CpTag::Utf8));
        assert_eq!(CpTag::from_u8(7), Some(CpTag::Class));
        assert_eq!(CpTag::from_u8(10), Some(CpTag::Methodref));
    }

    #[test]
    fn test_cp_tag_from_u8_invalid() {
        assert!(CpTag::from_u8(0).is_none());
        assert!(CpTag::from_u8(2).is_none());
        assert!(CpTag::from_u8(255).is_none());
    }

    #[test]
    fn test_cp_tag_double_slot() {
        assert!(CpTag::Long.is_double_slot());
        assert!(CpTag::Double.is_double_slot());
        assert!(!CpTag::Integer.is_double_slot());
    }

    // ── Stack effect tests ──────────────────────────────────────────────────

    #[test]
    fn test_stack_effect_nop() {
        let se = jvm_stack_effect(0x00).unwrap();
        assert_eq!(se.pops, 0);
        assert_eq!(se.pushes, 0);
        assert_eq!(se.delta(), 0);
    }

    #[test]
    fn test_stack_effect_iconst_0() {
        let se = jvm_stack_effect(0x03).unwrap();
        assert_eq!(se.pushes, 1);
    }

    #[test]
    fn test_stack_effect_iadd() {
        let se = jvm_stack_effect(0x60).unwrap();
        assert_eq!(se.pops, 2);
        assert_eq!(se.pushes, 1);
        assert_eq!(se.delta(), -1);
    }

    #[test]
    fn test_stack_effect_pop() {
        let se = jvm_stack_effect(0x57).unwrap();
        assert_eq!(se.pops, 1);
        assert_eq!(se.pushes, 0);
    }

    #[test]
    fn test_stack_effect_dup() {
        let se = jvm_stack_effect(0x59).unwrap();
        assert_eq!(se.delta(), 1);
    }

    #[test]
    fn test_stack_effect_return() {
        let se = jvm_stack_effect(0xb1).unwrap();
        assert_eq!(se.delta(), 0);
    }

    #[test]
    fn test_stack_effect_ireturn() {
        let se = jvm_stack_effect(0xac).unwrap();
        assert_eq!(se.delta(), -1);
    }

    #[test]
    fn test_stack_effect_invoke_none() {
        // Invokevirtual has variable effect, should return None.
        assert!(jvm_stack_effect(0xb6).is_none());
    }

    // ── CFG tests ───────────────────────────────────────────────────────────

    #[test]
    fn test_cfg_single_block() {
        // Nop + return (no branches)
        let code = [0x00_u8, 0xb1];
        let blocks = jvm_build_cfg(&code);
        assert!(!blocks.is_empty());
        assert_eq!(blocks[0].start, 0);
    }

    #[test]
    fn test_cfg_conditional_branch() {
        // Ifeq +3 (jumps past return), Nop, return
        // Ifeq (0x99) offset=3, then Nop (0x00), then return (0xb1)
        let code = [0x99_u8, 0x00, 0x03, 0x00, 0xb1];
        let blocks = jvm_build_cfg(&code);
        // Should have at least 2 blocks: before branch and after.
        assert!(blocks.len() >= 2);
    }

    #[test]
    fn test_cfg_empty_input() {
        let blocks = jvm_build_cfg(&[]);
        assert!(blocks.is_empty());
    }

    // ── Descriptor parsing tests ─────────────────────────────────────────────

    #[test]
    fn test_parse_method_descriptor_simple() {
        let (params, ret) = parse_method_descriptor_typed("(I)V").unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], JvmTypeDesc::Int);
        assert_eq!(ret, JvmTypeDesc::Void);
    }

    #[test]
    fn test_parse_method_descriptor_no_params() {
        let (params, ret) = parse_method_descriptor_typed("()Ljava/lang/String;").unwrap();
        assert!(params.is_empty());
        assert!(matches!(ret, JvmTypeDesc::Object(_)));
    }

    #[test]
    fn test_parse_method_descriptor_multiple_params() {
        let (params, ret) = parse_method_descriptor_typed("(IJD)Z").unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params[0], JvmTypeDesc::Int);
        assert_eq!(params[1], JvmTypeDesc::Long);
        assert_eq!(params[2], JvmTypeDesc::Double);
        assert_eq!(ret, JvmTypeDesc::Boolean);
    }

    #[test]
    fn test_parse_method_descriptor_array_param() {
        let (params, _ret) = parse_method_descriptor_typed("([B)V").unwrap();
        assert_eq!(params.len(), 1);
        assert!(matches!(&params[0], JvmTypeDesc::Array(inner) if **inner == JvmTypeDesc::Byte));
    }

    #[test]
    fn test_parse_method_descriptor_invalid() {
        assert!(parse_method_descriptor_typed("not-a-descriptor").is_none());
        assert!(parse_method_descriptor_typed("(").is_none());
    }

    // ── Exception table tests ────────────────────────────────────────────────

    #[test]
    fn test_exception_entry_is_finally() {
        let e = JvmExceptionEntry {
            start_pc: 0,
            end_pc: 10,
            handler_pc: 20,
            catch_type: 0,
        };
        assert!(e.is_finally());
    }

    #[test]
    fn test_exception_entry_covers() {
        let e = JvmExceptionEntry {
            start_pc: 5,
            end_pc: 15,
            handler_pc: 30,
            catch_type: 7,
        };
        assert!(e.covers(5));
        assert!(e.covers(14));
        assert!(!e.covers(4));
        assert!(!e.covers(15));
    }

    // ── Opcode classification tests ──────────────────────────────────────────

    #[test]
    fn test_jvm_is_branch_goto() {
        assert!(jvm_is_branch(0xa7)); // Goto
        assert!(jvm_is_branch(0xc8)); // GotoW
        assert!(jvm_is_branch(0x99)); // Ifeq
        assert!(!jvm_is_branch(0x00)); // Nop
    }

    #[test]
    fn test_jvm_is_return_variants() {
        assert!(jvm_is_return(0xac)); // Ireturn
        assert!(jvm_is_return(0xb1)); // return
        assert!(jvm_is_return(0xbf)); // Athrow
        assert!(!jvm_is_return(0x60)); // Iadd
    }

    #[test]
    fn test_jvm_is_invoke() {
        assert!(jvm_is_invoke(0xb6)); // Invokevirtual
        assert!(jvm_is_invoke(0xb8)); // Invokestatic
        assert!(jvm_is_invoke(0xba)); // Invokedynamic
        assert!(!jvm_is_invoke(0xbb)); // new
    }

    #[test]
    fn test_jvm_is_alloc() {
        assert!(jvm_is_alloc(0xbb)); // new
        assert!(jvm_is_alloc(0xbc)); // Newarray
        assert!(jvm_is_alloc(0xbd)); // Anewarray
        assert!(!jvm_is_alloc(0xb6)); // Invokevirtual
    }

    // ── Analysis helper tests ─────────────────────────────────────────────

    #[test]
    fn test_max_stack_depth_simple() {
        // Iconst1 (push), Iconst2 (push), Iadd (Pop2, push1), Ireturn (pop1)
        let code = [0x04_u8, 0x05, 0x60, 0xac];
        let depth = jvm_max_stack_depth(&code);
        assert!(depth >= 2);
    }

    #[test]
    fn test_count_invocations_none() {
        let code = [0x04_u8, 0xac]; // Iconst1, Ireturn
        assert_eq!(jvm_count_invocations(&code), 0);
    }

    #[test]
    fn test_count_allocations_new() {
        // new #1 (0xbb, 0x00, 0x01), then return
        let code = [0xbb_u8, 0x00, 0x01, 0xb1];
        assert_eq!(jvm_count_allocations(&code), 1);
    }

    #[test]
    fn test_cyclomatic_no_branches() {
        let code = [0x03_u8, 0xac]; // Iconst0, Ireturn
        assert_eq!(jvm_cyclomatic_complexity(&code), 1);
    }

    #[test]
    fn test_newarray_type_names() {
        assert_eq!(newarray_type::name(4), Some("boolean"));
        assert_eq!(newarray_type::name(10), Some("int"));
        assert_eq!(newarray_type::name(11), Some("long"));
        assert_eq!(newarray_type::name(3), None);
    }

    #[test]
    fn test_access_flags_public_static() {
        let s = access_flags::method_flags_str(access_flags::ACC_PUBLIC | access_flags::ACC_STATIC);
        assert!(s.contains("public"));
        assert!(s.contains("static"));
    }

    #[test]
    fn test_verification_type_category2() {
        assert!(VerificationTypeFull::Long.is_category2());
        assert!(VerificationTypeFull::Double.is_category2());
        assert!(!VerificationTypeFull::Integer.is_category2());
    }

    #[test]
    fn test_verification_type_assignable() {
        let obj = VerificationTypeFull::Object {
            class_name: "Foo".into(),
        };
        assert!(obj.is_assignable_from(&VerificationTypeFull::Null));
        assert!(VerificationTypeFull::Top.is_assignable_from(&VerificationTypeFull::Integer));
    }

    #[test]
    fn test_jvm_is_field_access() {
        assert!(jvm_is_field_access(0xb2)); // Getstatic
        assert!(jvm_is_field_access(0xb4)); // Getfield
        assert!(jvm_is_field_access(0xb5)); // Putfield
        assert!(!jvm_is_field_access(0xb6)); // Invokevirtual
    }
}
