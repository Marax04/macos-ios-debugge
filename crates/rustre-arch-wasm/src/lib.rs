//! `rustre-arch-wasm`
//!
//! This crate is part of the `RustRE` Suite, a premium reverse engineering platform.
//!
//! # Architecture: WebAssembly (Wasm)
//! Implements instruction decoding for WebAssembly MVP bytecode with common extensions.
//! Wasm is a stack-based VM with LEB128-encoded variable-length instructions.

pub mod atomics;
pub mod simd_decoder;
pub mod wasm_analysis;
pub mod wasm_decompiler;
pub mod wasm_lifter;
pub mod wasm_execution_model;
pub mod wasm_import_analyzer;
pub mod wasm_memory_model;
pub mod wasm_table_model;
pub mod wasm_type_system;
pub mod wasm_validator;

use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
};
use rustre_core::arch::BranchCondition;
use rustre_core::{address::Address, endian::Endian, errors::CoreError};

/// Read an unsigned LEB128 integer from bytes at offset.
/// Returns (value, `bytes_consumed`).
pub(crate) fn read_uleb128(bytes: &[u8], offset: usize) -> Result<(u64, usize), CoreError> {
    let mut result = 0u64;
    let mut shift = 0u32;
    let mut pos = offset;
    loop {
        if pos >= bytes.len() {
            return Err(CoreError::InvalidFormat {
                message: "truncated LEB128".into(),
            });
        }
        let b = bytes[pos];
        pos += 1;
        result |= u64::from(b & 0x7f) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            return Err(CoreError::InvalidFormat {
                message: "LEB128 overflow".into(),
            });
        }
    }
    Ok((result, pos - offset))
}

/// Read a signed LEB128 integer from bytes at offset.
pub(crate) fn read_sleb128(bytes: &[u8], offset: usize) -> Result<(i64, usize), CoreError> {
    let mut result = 0i64;
    let mut shift = 0u32;
    let mut pos = offset;
    loop {
        if pos >= bytes.len() {
            return Err(CoreError::InvalidFormat {
                message: "truncated SLEB128".into(),
            });
        }
        let b = bytes[pos];
        pos += 1;
        result |= i64::from(b & 0x7f) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            if shift < 64 && (b & 0x40) != 0 {
                result |= -1i64 << shift;
            }
            break;
        }
        if shift >= 64 {
            return Err(CoreError::InvalidFormat {
                message: "SLEB128 overflow".into(),
            });
        }
    }
    Ok((result, pos - offset))
}

/// Read a valtype byte for block type encoding.
const fn valtype_str(vt: i64) -> &'static str {
    match vt {
        -1 => "i32",
        -2 => "i64",
        -3 => "f32",
        -4 => "f64",
        -0x10 => "funcref",
        -0x11 => "externref",
        0x40 => "void",
        _ => "?",
    }
}

/// Decode a Wasm instruction. Returns (mnemonic, operands, size, flags).
fn decode_wasm(bytes: &[u8]) -> Result<(String, String, usize, InstrFlags), CoreError> {
    if bytes.is_empty() {
        return Err(CoreError::InvalidFormat {
            message: "empty bytes".into(),
        });
    }

    let op = bytes[0];
    let mut pos = 1usize;

    macro_rules! uleb {
        () => {{
            let (v, n) = read_uleb128(bytes, pos)?;
            pos += n;
            v
        }};
    }
    macro_rules! sleb {
        () => {{
            let (v, n) = read_sleb128(bytes, pos)?;
            pos += n;
            v
        }};
    }

    let (mnemonic, operands, flags): (String, String, InstrFlags) = match op {
        // Control
        0x00 => ("unreachable".into(), String::new(), InstrFlags::BARRIER),
        0x01 => ("nop".into(), String::new(), InstrFlags::NONE),
        0x02 => {
            let bt = sleb!();
            ("block".into(), valtype_str(bt).into(), InstrFlags::NONE)
        }
        0x03 => {
            let bt = sleb!();
            ("loop".into(), valtype_str(bt).into(), InstrFlags::NONE)
        }
        0x04 => {
            let bt = sleb!();
            (
                "if".into(),
                valtype_str(bt).into(),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
            )
        }
        0x05 => ("else".into(), String::new(), InstrFlags::NONE),
        0x0b => ("end".into(), String::new(), InstrFlags::NONE),
        0x0c => {
            let l = uleb!();
            ("br".into(), format!("{l}"), InstrFlags::BRANCH)
        }
        0x0d => {
            let l = uleb!();
            (
                "br_if".into(),
                format!("{l}"),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
            )
        }
        0x0e => {
            // br_table: vector of labels + default
            const MAX_BR_TABLE_ENTRIES: usize = 65_536;
            let count_raw = uleb!();
            let count = usize::try_from(count_raw).unwrap_or(usize::MAX);
            if count > MAX_BR_TABLE_ENTRIES {
                return Err(CoreError::InvalidFormat {
                    message: format!("br_table count {count_raw} exceeds limit"),
                });
            }
            let mut labels = Vec::with_capacity(count + 1);
            for _ in 0..=count {
                labels.push(uleb!().to_string());
            }
            (
                "br_table".into(),
                labels.join(", "),
                InstrFlags::BRANCH | InstrFlags::INDIRECT,
            )
        }
        0x0f => ("return".into(), String::new(), InstrFlags::RET),
        0x10 => {
            let idx = uleb!();
            ("call".into(), format!("{idx}"), InstrFlags::CALL)
        }
        0x11 => {
            let type_idx = uleb!();
            let table_idx = uleb!();
            (
                "call_indirect".into(),
                format!("{type_idx}, {table_idx}"),
                InstrFlags::CALL | InstrFlags::INDIRECT,
            )
        }
        // Parametric
        0x1a => ("drop".into(), String::new(), InstrFlags::NONE),
        0x1b => ("select".into(), String::new(), InstrFlags::NONE),
        // Variable
        0x20 => {
            let idx = uleb!();
            ("local.get".into(), format!("{idx}"), InstrFlags::NONE)
        }
        0x21 => {
            let idx = uleb!();
            ("local.set".into(), format!("{idx}"), InstrFlags::NONE)
        }
        0x22 => {
            let idx = uleb!();
            ("local.tee".into(), format!("{idx}"), InstrFlags::NONE)
        }
        0x23 => {
            let idx = uleb!();
            ("global.get".into(), format!("{idx}"), InstrFlags::NONE)
        }
        0x24 => {
            let idx = uleb!();
            ("global.set".into(), format!("{idx}"), InstrFlags::NONE)
        }
        // Memory load ops
        0x28 => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i32.load".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::READ_MEM,
            )
        }
        0x29 => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i64.load".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::READ_MEM,
            )
        }
        0x2a => {
            let align = uleb!();
            let offset = uleb!();
            (
                "f32.load".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::READ_MEM,
            )
        }
        0x2b => {
            let align = uleb!();
            let offset = uleb!();
            (
                "f64.load".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::READ_MEM,
            )
        }
        0x2c => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i32.load8_s".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::READ_MEM,
            )
        }
        0x2d => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i32.load8_u".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::READ_MEM,
            )
        }
        0x2e => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i32.load16_s".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::READ_MEM,
            )
        }
        0x2f => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i32.load16_u".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::READ_MEM,
            )
        }
        0x30 => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i64.load8_s".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::READ_MEM,
            )
        }
        0x31 => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i64.load8_u".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::READ_MEM,
            )
        }
        0x32 => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i64.load16_s".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::READ_MEM,
            )
        }
        0x33 => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i64.load16_u".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::READ_MEM,
            )
        }
        0x34 => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i64.load32_s".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::READ_MEM,
            )
        }
        0x35 => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i64.load32_u".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::READ_MEM,
            )
        }
        // Memory store ops
        0x36 => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i32.store".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::WRITE_MEM,
            )
        }
        0x37 => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i64.store".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::WRITE_MEM,
            )
        }
        0x38 => {
            let align = uleb!();
            let offset = uleb!();
            (
                "f32.store".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::WRITE_MEM,
            )
        }
        0x39 => {
            let align = uleb!();
            let offset = uleb!();
            (
                "f64.store".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::WRITE_MEM,
            )
        }
        0x3a => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i32.store8".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::WRITE_MEM,
            )
        }
        0x3b => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i32.store16".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::WRITE_MEM,
            )
        }
        0x3c => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i64.store8".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::WRITE_MEM,
            )
        }
        0x3d => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i64.store16".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::WRITE_MEM,
            )
        }
        0x3e => {
            let align = uleb!();
            let offset = uleb!();
            (
                "i64.store32".into(),
                format!("align={align} offset={offset}"),
                InstrFlags::WRITE_MEM,
            )
        }
        // Memory size/grow
        0x3f => {
            let _mem = uleb!();
            ("memory.size".into(), String::new(), InstrFlags::NONE)
        }
        0x40 => {
            let _mem = uleb!();
            ("memory.grow".into(), String::new(), InstrFlags::NONE)
        }
        // Numeric constants
        0x41 => {
            let v = sleb!();
            ("i32.const".into(), format!("{v}"), InstrFlags::NONE)
        }
        0x42 => {
            let v = sleb!();
            ("i64.const".into(), format!("{v}"), InstrFlags::NONE)
        }
        0x43 => {
            if pos + 4 > bytes.len() {
                return Err(CoreError::InvalidFormat {
                    message: "truncated f32.const".into(),
                });
            }
            let bits =
                u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
            pos += 4;
            let f = f32::from_bits(bits);
            ("f32.const".into(), format!("{f}"), InstrFlags::NONE)
        }
        0x44 => {
            if pos + 8 > bytes.len() {
                return Err(CoreError::InvalidFormat {
                    message: "truncated f64.const".into(),
                });
            }
            let bits = u64::from_le_bytes([
                bytes[pos],
                bytes[pos + 1],
                bytes[pos + 2],
                bytes[pos + 3],
                bytes[pos + 4],
                bytes[pos + 5],
                bytes[pos + 6],
                bytes[pos + 7],
            ]);
            pos += 8;
            let f = f64::from_bits(bits);
            ("f64.const".into(), format!("{f}"), InstrFlags::NONE)
        }
        // i32 numeric ops (no operands)
        0x45 => ("i32.eqz".into(), String::new(), InstrFlags::NONE),
        0x46 => ("i32.eq".into(), String::new(), InstrFlags::NONE),
        0x47 => ("i32.ne".into(), String::new(), InstrFlags::NONE),
        0x48 => ("i32.lt_s".into(), String::new(), InstrFlags::NONE),
        0x49 => ("i32.lt_u".into(), String::new(), InstrFlags::NONE),
        0x4a => ("i32.gt_s".into(), String::new(), InstrFlags::NONE),
        0x4b => ("i32.gt_u".into(), String::new(), InstrFlags::NONE),
        0x4c => ("i32.le_s".into(), String::new(), InstrFlags::NONE),
        0x4d => ("i32.le_u".into(), String::new(), InstrFlags::NONE),
        0x4e => ("i32.ge_s".into(), String::new(), InstrFlags::NONE),
        0x4f => ("i32.ge_u".into(), String::new(), InstrFlags::NONE),
        // i64 compare
        0x50 => ("i64.eqz".into(), String::new(), InstrFlags::NONE),
        0x51 => ("i64.eq".into(), String::new(), InstrFlags::NONE),
        0x52 => ("i64.ne".into(), String::new(), InstrFlags::NONE),
        0x53 => ("i64.lt_s".into(), String::new(), InstrFlags::NONE),
        0x54 => ("i64.lt_u".into(), String::new(), InstrFlags::NONE),
        0x55 => ("i64.gt_s".into(), String::new(), InstrFlags::NONE),
        0x56 => ("i64.gt_u".into(), String::new(), InstrFlags::NONE),
        0x57 => ("i64.le_s".into(), String::new(), InstrFlags::NONE),
        0x58 => ("i64.le_u".into(), String::new(), InstrFlags::NONE),
        0x59 => ("i64.ge_s".into(), String::new(), InstrFlags::NONE),
        0x5a => ("i64.ge_u".into(), String::new(), InstrFlags::NONE),
        // f32 compare
        0x5b => ("f32.eq".into(), String::new(), InstrFlags::NONE),
        0x5c => ("f32.ne".into(), String::new(), InstrFlags::NONE),
        0x5d => ("f32.lt".into(), String::new(), InstrFlags::NONE),
        0x5e => ("f32.gt".into(), String::new(), InstrFlags::NONE),
        0x5f => ("f32.le".into(), String::new(), InstrFlags::NONE),
        0x60 => ("f32.ge".into(), String::new(), InstrFlags::NONE),
        // f64 compare
        0x61 => ("f64.eq".into(), String::new(), InstrFlags::NONE),
        0x62 => ("f64.ne".into(), String::new(), InstrFlags::NONE),
        0x63 => ("f64.lt".into(), String::new(), InstrFlags::NONE),
        0x64 => ("f64.gt".into(), String::new(), InstrFlags::NONE),
        0x65 => ("f64.le".into(), String::new(), InstrFlags::NONE),
        0x66 => ("f64.ge".into(), String::new(), InstrFlags::NONE),
        // i32 arithmetic
        0x67 => ("i32.clz".into(), String::new(), InstrFlags::NONE),
        0x68 => ("i32.ctz".into(), String::new(), InstrFlags::NONE),
        0x69 => ("i32.popcnt".into(), String::new(), InstrFlags::NONE),
        0x6a => ("i32.add".into(), String::new(), InstrFlags::NONE),
        0x6b => ("i32.sub".into(), String::new(), InstrFlags::NONE),
        0x6c => ("i32.mul".into(), String::new(), InstrFlags::NONE),
        0x6d => ("i32.div_s".into(), String::new(), InstrFlags::NONE),
        0x6e => ("i32.div_u".into(), String::new(), InstrFlags::NONE),
        0x6f => ("i32.rem_s".into(), String::new(), InstrFlags::NONE),
        0x70 => ("i32.rem_u".into(), String::new(), InstrFlags::NONE),
        0x71 => ("i32.and".into(), String::new(), InstrFlags::NONE),
        0x72 => ("i32.or".into(), String::new(), InstrFlags::NONE),
        0x73 => ("i32.xor".into(), String::new(), InstrFlags::NONE),
        0x74 => ("i32.shl".into(), String::new(), InstrFlags::NONE),
        0x75 => ("i32.shr_s".into(), String::new(), InstrFlags::NONE),
        0x76 => ("i32.shr_u".into(), String::new(), InstrFlags::NONE),
        0x77 => ("i32.rotl".into(), String::new(), InstrFlags::NONE),
        0x78 => ("i32.rotr".into(), String::new(), InstrFlags::NONE),
        // i64 arithmetic
        0x79 => ("i64.clz".into(), String::new(), InstrFlags::NONE),
        0x7a => ("i64.ctz".into(), String::new(), InstrFlags::NONE),
        0x7b => ("i64.popcnt".into(), String::new(), InstrFlags::NONE),
        0x7c => ("i64.add".into(), String::new(), InstrFlags::NONE),
        0x7d => ("i64.sub".into(), String::new(), InstrFlags::NONE),
        0x7e => ("i64.mul".into(), String::new(), InstrFlags::NONE),
        0x7f => ("i64.div_s".into(), String::new(), InstrFlags::NONE),
        0x80 => ("i64.div_u".into(), String::new(), InstrFlags::NONE),
        0x81 => ("i64.rem_s".into(), String::new(), InstrFlags::NONE),
        0x82 => ("i64.rem_u".into(), String::new(), InstrFlags::NONE),
        0x83 => ("i64.and".into(), String::new(), InstrFlags::NONE),
        0x84 => ("i64.or".into(), String::new(), InstrFlags::NONE),
        0x85 => ("i64.xor".into(), String::new(), InstrFlags::NONE),
        0x86 => ("i64.shl".into(), String::new(), InstrFlags::NONE),
        0x87 => ("i64.shr_s".into(), String::new(), InstrFlags::NONE),
        0x88 => ("i64.shr_u".into(), String::new(), InstrFlags::NONE),
        0x89 => ("i64.rotl".into(), String::new(), InstrFlags::NONE),
        0x8a => ("i64.rotr".into(), String::new(), InstrFlags::NONE),
        // f32 arithmetic
        0x8b => ("f32.abs".into(), String::new(), InstrFlags::NONE),
        0x8c => ("f32.neg".into(), String::new(), InstrFlags::NONE),
        0x8d => ("f32.ceil".into(), String::new(), InstrFlags::NONE),
        0x8e => ("f32.floor".into(), String::new(), InstrFlags::NONE),
        0x8f => ("f32.trunc".into(), String::new(), InstrFlags::NONE),
        0x90 => ("f32.nearest".into(), String::new(), InstrFlags::NONE),
        0x91 => ("f32.sqrt".into(), String::new(), InstrFlags::NONE),
        0x92 => ("f32.add".into(), String::new(), InstrFlags::NONE),
        0x93 => ("f32.sub".into(), String::new(), InstrFlags::NONE),
        0x94 => ("f32.mul".into(), String::new(), InstrFlags::NONE),
        0x95 => ("f32.div".into(), String::new(), InstrFlags::NONE),
        0x96 => ("f32.min".into(), String::new(), InstrFlags::NONE),
        0x97 => ("f32.max".into(), String::new(), InstrFlags::NONE),
        0x98 => ("f32.copysign".into(), String::new(), InstrFlags::NONE),
        // f64 arithmetic
        0x99 => ("f64.abs".into(), String::new(), InstrFlags::NONE),
        0x9a => ("f64.neg".into(), String::new(), InstrFlags::NONE),
        0x9b => ("f64.ceil".into(), String::new(), InstrFlags::NONE),
        0x9c => ("f64.floor".into(), String::new(), InstrFlags::NONE),
        0x9d => ("f64.trunc".into(), String::new(), InstrFlags::NONE),
        0x9e => ("f64.nearest".into(), String::new(), InstrFlags::NONE),
        0x9f => ("f64.sqrt".into(), String::new(), InstrFlags::NONE),
        0xa0 => ("f64.add".into(), String::new(), InstrFlags::NONE),
        0xa1 => ("f64.sub".into(), String::new(), InstrFlags::NONE),
        0xa2 => ("f64.mul".into(), String::new(), InstrFlags::NONE),
        0xa3 => ("f64.div".into(), String::new(), InstrFlags::NONE),
        0xa4 => ("f64.min".into(), String::new(), InstrFlags::NONE),
        0xa5 => ("f64.max".into(), String::new(), InstrFlags::NONE),
        0xa6 => ("f64.copysign".into(), String::new(), InstrFlags::NONE),
        // Conversions
        0xa7 => ("i32.wrap_i64".into(), String::new(), InstrFlags::NONE),
        0xa8 => ("i32.trunc_f32_s".into(), String::new(), InstrFlags::NONE),
        0xa9 => ("i32.trunc_f32_u".into(), String::new(), InstrFlags::NONE),
        0xaa => ("i32.trunc_f64_s".into(), String::new(), InstrFlags::NONE),
        0xab => ("i32.trunc_f64_u".into(), String::new(), InstrFlags::NONE),
        0xac => ("i64.extend_i32_s".into(), String::new(), InstrFlags::NONE),
        0xad => ("i64.extend_i32_u".into(), String::new(), InstrFlags::NONE),
        0xae => ("i64.trunc_f32_s".into(), String::new(), InstrFlags::NONE),
        0xaf => ("i64.trunc_f32_u".into(), String::new(), InstrFlags::NONE),
        0xb0 => ("i64.trunc_f64_s".into(), String::new(), InstrFlags::NONE),
        0xb1 => ("i64.trunc_f64_u".into(), String::new(), InstrFlags::NONE),
        0xb2 => ("f32.convert_i32_s".into(), String::new(), InstrFlags::NONE),
        0xb3 => ("f32.convert_i32_u".into(), String::new(), InstrFlags::NONE),
        0xb4 => ("f32.convert_i64_s".into(), String::new(), InstrFlags::NONE),
        0xb5 => ("f32.convert_i64_u".into(), String::new(), InstrFlags::NONE),
        0xb6 => ("f32.demote_f64".into(), String::new(), InstrFlags::NONE),
        0xb7 => ("f64.convert_i32_s".into(), String::new(), InstrFlags::NONE),
        0xb8 => ("f64.convert_i32_u".into(), String::new(), InstrFlags::NONE),
        0xb9 => ("f64.convert_i64_s".into(), String::new(), InstrFlags::NONE),
        0xba => ("f64.convert_i64_u".into(), String::new(), InstrFlags::NONE),
        0xbb => ("f64.promote_f32".into(), String::new(), InstrFlags::NONE),
        0xbc => (
            "i32.reinterpret_f32".into(),
            String::new(),
            InstrFlags::NONE,
        ),
        0xbd => (
            "i64.reinterpret_f64".into(),
            String::new(),
            InstrFlags::NONE,
        ),
        0xbe => (
            "f32.reinterpret_i32".into(),
            String::new(),
            InstrFlags::NONE,
        ),
        0xbf => (
            "f64.reinterpret_i64".into(),
            String::new(),
            InstrFlags::NONE,
        ),
        // Sign-extension operators (MVP extension, single byte no operands)
        0xc0 => ("i32.extend8_s".into(), String::new(), InstrFlags::NONE),
        0xc1 => ("i32.extend16_s".into(), String::new(), InstrFlags::NONE),
        0xc2 => ("i64.extend8_s".into(), String::new(), InstrFlags::NONE),
        0xc3 => ("i64.extend16_s".into(), String::new(), InstrFlags::NONE),
        0xc4 => ("i64.extend32_s".into(), String::new(), InstrFlags::NONE),
        // Reference types (proposal)
        0x25 => {
            let idx = uleb!();
            ("table.get".into(), format!("{idx}"), InstrFlags::READ_MEM)
        }
        0x26 => {
            let idx = uleb!();
            ("table.set".into(), format!("{idx}"), InstrFlags::WRITE_MEM)
        }
        0xd0 => {
            // ref.null <reftype byte>
            if pos >= bytes.len() {
                return Err(CoreError::InvalidFormat {
                    message: "truncated ref.null".into(),
                });
            }
            let rt = bytes[pos];
            pos += 1;
            let tn = match rt {
                0x70 => "funcref",
                0x6f => "externref",
                _ => "unknown",
            };
            ("ref.null".into(), tn.to_string(), InstrFlags::NONE)
        }
        0xd1 => ("ref.is_null".into(), String::new(), InstrFlags::NONE),
        0xd2 => {
            let idx = uleb!();
            ("ref.func".into(), format!("{idx}"), InstrFlags::NONE)
        }
        // Prefixed encodings — delegate to specialised decoders
        0xfc => {
            return decode_fc_prefix(bytes);
        }
        0xfd => {
            return decode_fd_prefix(bytes);
        }
        0xfe => {
            return decode_fe_prefix(bytes);
        }
        _ => {
            return Err(CoreError::InvalidFormat {
                message: format!("unknown Wasm opcode 0x{op:02x}"),
            });
        }
    };

    Ok((mnemonic, operands, pos, flags))
}

/// Architecture support for WebAssembly.
#[derive(Debug, Clone, Default)]
pub struct WasmArch;

impl WasmArch {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Architecture for WasmArch {
    fn name(&self) -> &'static str {
        "wasm"
    }

    fn pointer_size(&self) -> usize {
        4 // Wasm32
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        let (mnemonic, operands, size, flags) = decode_wasm(bytes)?;
        let mut instr = Instruction::new(
            address,
            size,
            mnemonic,
            bytes[..size.min(bytes.len())].to_vec(),
        );
        instr.operands = operands;
        instr.flags = flags;
        Ok(instr)
    }

    fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo> {
        if instr.flags.contains(InstrFlags::RET) {
            return vec![];
        }
        // Wasm branches are structured (label depths), not absolute addresses.
        // Expose as zero-target branch annotations.
        if instr.flags.contains(InstrFlags::BRANCH) {
            if instr.flags.contains(InstrFlags::INDIRECT) {
                return vec![BranchInfo::indirect_jump()];
            }
            if instr.flags.contains(InstrFlags::CALL) {
                return vec![BranchInfo::call(0)];
            }
            if instr.flags.contains(InstrFlags::CONDITIONAL) {
                return vec![BranchInfo::conditional_jump(0, BranchCondition::Custom(0))];
            }
            return vec![BranchInfo::unconditional_jump(0)];
        }
        vec![]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        // Wasm is stack-based; no architectural registers.
        vec![]
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![
            CallingConvention::new("wasm")
                .with_int_args(vec![])
                .with_return_regs(vec![]),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arch() -> WasmArch {
        WasmArch::new()
    }

    fn dis(bytes: &[u8]) -> Instruction {
        arch().disassemble(Address::new(0x100), bytes).unwrap()
    }

    #[test]
    fn test_unreachable() {
        let i = dis(&[0x00]);
        assert_eq!(i.mnemonic, "unreachable");
        assert!(i.flags.contains(InstrFlags::BARRIER));
        assert_eq!(i.size, 1);
    }

    #[test]
    fn test_nop() {
        let i = dis(&[0x01]);
        assert_eq!(i.mnemonic, "nop");
        assert_eq!(i.size, 1);
    }

    #[test]
    fn test_block() {
        // block void (0x40 as sleb = 0x40)
        let i = dis(&[0x02, 0x40]);
        assert_eq!(i.mnemonic, "block");
        assert_eq!(i.size, 2);
    }

    #[test]
    fn test_br() {
        // br 0
        let i = dis(&[0x0c, 0x00]);
        assert_eq!(i.mnemonic, "br");
        assert!(i.flags.contains(InstrFlags::BRANCH));
        assert_eq!(i.size, 2);
    }

    #[test]
    fn test_br_if() {
        let i = dis(&[0x0d, 0x01]);
        assert_eq!(i.mnemonic, "br_if");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_return() {
        let i = dis(&[0x0f]);
        assert_eq!(i.mnemonic, "return");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_call() {
        let i = dis(&[0x10, 0x05]);
        assert_eq!(i.mnemonic, "call");
        assert_eq!(i.operands, "5");
        assert!(i.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_call_indirect() {
        let i = dis(&[0x11, 0x02, 0x00]);
        assert_eq!(i.mnemonic, "call_indirect");
        assert!(i.flags.contains(InstrFlags::CALL));
        assert!(i.flags.contains(InstrFlags::INDIRECT));
    }

    #[test]
    fn test_local_get() {
        let i = dis(&[0x20, 0x03]);
        assert_eq!(i.mnemonic, "local.get");
        assert_eq!(i.operands, "3");
    }

    #[test]
    fn test_local_set() {
        let i = dis(&[0x21, 0x00]);
        assert_eq!(i.mnemonic, "local.set");
    }

    #[test]
    fn test_global_get() {
        let i = dis(&[0x23, 0x01]);
        assert_eq!(i.mnemonic, "global.get");
        assert_eq!(i.operands, "1");
    }

    #[test]
    fn test_i32_load() {
        let i = dis(&[0x28, 0x02, 0x00]);
        assert_eq!(i.mnemonic, "i32.load");
        assert!(i.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_i32_store() {
        let i = dis(&[0x36, 0x02, 0x00]);
        assert_eq!(i.mnemonic, "i32.store");
        assert!(i.flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_i32_const() {
        let i = dis(&[0x41, 0x2a]);
        assert_eq!(i.mnemonic, "i32.const");
        assert_eq!(i.operands, "42");
    }

    #[test]
    fn test_i64_const() {
        let i = dis(&[0x42, 0x01]);
        assert_eq!(i.mnemonic, "i64.const");
        assert_eq!(i.operands, "1");
    }

    #[test]
    fn test_f32_const() {
        // f32 1.0 = 0x3f800000 LE
        let i = dis(&[0x43, 0x00, 0x00, 0x80, 0x3f]);
        assert_eq!(i.mnemonic, "f32.const");
        assert_eq!(i.size, 5);
    }

    #[test]
    fn test_i32_add() {
        let i = dis(&[0x6a]);
        assert_eq!(i.mnemonic, "i32.add");
        assert_eq!(i.size, 1);
    }

    #[test]
    fn test_i32_eqz() {
        let i = dis(&[0x45]);
        assert_eq!(i.mnemonic, "i32.eqz");
    }

    #[test]
    fn test_i64_add() {
        let i = dis(&[0x7c]);
        assert_eq!(i.mnemonic, "i64.add");
    }

    #[test]
    fn test_f32_add() {
        let i = dis(&[0x92]);
        assert_eq!(i.mnemonic, "f32.add");
    }

    #[test]
    fn test_f64_add() {
        let i = dis(&[0xa0]);
        assert_eq!(i.mnemonic, "f64.add");
    }

    #[test]
    fn test_i32_wrap_i64() {
        let i = dis(&[0xa7]);
        assert_eq!(i.mnemonic, "i32.wrap_i64");
    }

    #[test]
    fn test_i64_extend_i32_s() {
        let i = dis(&[0xac]);
        assert_eq!(i.mnemonic, "i64.extend_i32_s");
    }

    #[test]
    fn test_memory_size() {
        let i = dis(&[0x3f, 0x00]);
        assert_eq!(i.mnemonic, "memory.size");
    }

    #[test]
    fn test_memory_grow() {
        let i = dis(&[0x40, 0x00]);
        assert_eq!(i.mnemonic, "memory.grow");
    }

    #[test]
    fn test_drop() {
        let i = dis(&[0x1a]);
        assert_eq!(i.mnemonic, "drop");
    }

    #[test]
    fn test_select() {
        let i = dis(&[0x1b]);
        assert_eq!(i.mnemonic, "select");
    }

    #[test]
    fn test_end() {
        let i = dis(&[0x0b]);
        assert_eq!(i.mnemonic, "end");
    }

    #[test]
    fn test_arch_name() {
        assert_eq!(arch().name(), "wasm");
    }

    #[test]
    fn test_pointer_size() {
        assert_eq!(arch().pointer_size(), 4);
    }

    #[test]
    fn test_endian() {
        assert_eq!(arch().endian(), Endian::Little);
    }

    #[test]
    fn test_no_registers() {
        assert!(arch().registers().is_empty());
    }

    #[test]
    fn test_calling_convention() {
        let cc = arch().calling_conventions();
        assert!(!cc.is_empty());
        assert_eq!(cc[0].name, "wasm");
    }

    #[test]
    fn test_uleb128_multibyte() {
        // 300 in LEB128 = 0xAC 0x02
        let i = dis(&[0x10, 0xac, 0x02]);
        assert_eq!(i.mnemonic, "call");
        assert_eq!(i.operands, "300");
        assert_eq!(i.size, 3);
    }

    #[test]
    fn test_br_table() {
        // br_table 2 targets: 0,1 + default 2
        let i = dis(&[0x0e, 0x02, 0x00, 0x01, 0x02]);
        assert_eq!(i.mnemonic, "br_table");
        assert!(i.flags.contains(InstrFlags::INDIRECT));
    }

    #[test]
    fn test_unknown_opcode() {
        let result = arch().disassemble(Address::new(0), &[0xff]);
        assert!(result.is_err());
    }

    // --- extension opcodes ---

    #[test]
    fn test_ref_null_funcref() {
        // ref.null = 0xD0, funcref type = 0x70
        let i = dis(&[0xD0, 0x70]);
        assert_eq!(i.mnemonic, "ref.null");
        assert_eq!(i.size, 2);
    }

    #[test]
    fn test_ref_is_null() {
        let i = dis(&[0xD1]);
        assert_eq!(i.mnemonic, "ref.is_null");
        assert_eq!(i.size, 1);
    }

    #[test]
    fn test_ref_func() {
        let i = dis(&[0xD2, 0x05]);
        assert_eq!(i.mnemonic, "ref.func");
        assert_eq!(i.operands, "5");
    }

    #[test]
    fn test_table_get() {
        let i = dis(&[0x25, 0x00]);
        assert_eq!(i.mnemonic, "table.get");
    }

    #[test]
    fn test_table_set() {
        let i = dis(&[0x26, 0x00]);
        assert_eq!(i.mnemonic, "table.set");
    }

    #[test]
    fn test_i32_extend8_s() {
        let i = dis(&[0xC0]);
        assert_eq!(i.mnemonic, "i32.extend8_s");
    }

    #[test]
    fn test_i32_extend16_s() {
        let i = dis(&[0xC1]);
        assert_eq!(i.mnemonic, "i32.extend16_s");
    }

    #[test]
    fn test_i64_extend8_s() {
        let i = dis(&[0xC2]);
        assert_eq!(i.mnemonic, "i64.extend8_s");
    }

    #[test]
    fn test_i64_extend16_s() {
        let i = dis(&[0xC3]);
        assert_eq!(i.mnemonic, "i64.extend16_s");
    }

    #[test]
    fn test_i64_extend32_s() {
        let i = dis(&[0xC4]);
        assert_eq!(i.mnemonic, "i64.extend32_s");
    }

    // 0xFC prefix: bulk memory / saturating trunc
    #[test]
    fn test_i32_trunc_sat_f32_s() {
        // 0xFC 0x00
        let i = dis(&[0xFC, 0x00]);
        assert_eq!(i.mnemonic, "i32.trunc_sat_f32_s");
        assert_eq!(i.size, 2);
    }

    #[test]
    fn test_memory_copy_0xfc() {
        // 0xFC 0x0A 0x00 0x00
        let i = dis(&[0xFC, 0x0A, 0x00, 0x00]);
        assert_eq!(i.mnemonic, "memory.copy");
        assert_eq!(i.size, 4);
    }

    #[test]
    fn test_memory_fill_0xfc() {
        let i = dis(&[0xFC, 0x0B, 0x00]);
        assert_eq!(i.mnemonic, "memory.fill");
        assert_eq!(i.size, 3);
    }

    // 0xFE prefix: threads / atomics
    #[test]
    fn test_memory_atomic_notify() {
        // 0xFE 0x00 align offset
        let i = dis(&[0xFE, 0x00, 0x02, 0x00]);
        assert_eq!(i.mnemonic, "memory.atomic.notify");
        assert_eq!(i.size, 4);
    }

    #[test]
    fn test_i32_atomic_load() {
        let i = dis(&[0xFE, 0x10, 0x02, 0x00]);
        assert_eq!(i.mnemonic, "i32.atomic.load");
        assert!(i.flags.contains(InstrFlags::READ_MEM));
    }

    // Binary section types
    #[test]
    fn test_section_id_roundtrip() {
        for id in 0u8..=12 {
            let _ = WasmSectionId::from_byte(id);
        }
    }

    #[test]
    fn test_value_type_names() {
        assert_eq!(WasmValueType::I32.name(), "i32");
        assert_eq!(WasmValueType::I64.name(), "i64");
        assert_eq!(WasmValueType::F32.name(), "f32");
        assert_eq!(WasmValueType::F64.name(), "f64");
        assert_eq!(WasmValueType::V128.name(), "v128");
        assert_eq!(WasmValueType::FuncRef.name(), "funcref");
        assert_eq!(WasmValueType::ExternRef.name(), "externref");
    }

    #[test]
    fn test_external_kind_names() {
        assert_eq!(WasmExternalKind::Function.name(), "func");
        assert_eq!(WasmExternalKind::Table.name(), "table");
        assert_eq!(WasmExternalKind::Memory.name(), "memory");
        assert_eq!(WasmExternalKind::Global.name(), "global");
    }

    #[test]
    fn test_wasm_magic() {
        assert_eq!(WASM_MAGIC, [0x00, 0x61, 0x73, 0x6D]);
    }

    #[test]
    fn test_wasm_version() {
        assert_eq!(WASM_VERSION, [0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_function_type_decode() {
        // 0x60 = func type, 2 params (i32=0x7f, i32=0x7f), 1 result (i32=0x7f)
        let bytes = [0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f];
        let ft = WasmFuncType::decode(&bytes).unwrap();
        assert_eq!(ft.params.len(), 2);
        assert_eq!(ft.results.len(), 1);
    }

    #[test]
    fn test_limits_decode_min_only() {
        let bytes = [0x00, 0x04]; // kind=0, min=4
        let (lim, n) = WasmLimits::decode(&bytes).unwrap();
        assert_eq!(lim.min, 4);
        assert!(lim.max.is_none());
        assert_eq!(n, 2);
    }

    #[test]
    fn test_limits_decode_min_max() {
        let bytes = [0x01, 0x02, 0x10]; // kind=1, min=2, max=16
        let (lim, n) = WasmLimits::decode(&bytes).unwrap();
        assert_eq!(lim.min, 2);
        assert_eq!(lim.max, Some(16));
        assert_eq!(n, 3);
    }

    #[test]
    fn test_module_header_valid() {
        let bytes = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        assert!(WasmModuleHeader::parse(&bytes).is_ok());
    }

    #[test]
    fn test_module_header_invalid_magic() {
        let bytes = [0xFF, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        assert!(WasmModuleHeader::parse(&bytes).is_err());
    }

    #[test]
    fn test_module_header_invalid_version() {
        let bytes = [0x00, 0x61, 0x73, 0x6D, 0x02, 0x00, 0x00, 0x00];
        assert!(WasmModuleHeader::parse(&bytes).is_err());
    }

    #[test]
    fn test_simd_v128_const() {
        // 0xFD 0x0C + 16 bytes
        let mut buf = vec![0xFDu8, 0x0C];
        buf.extend_from_slice(&[0u8; 16]);
        let i = dis(&buf);
        assert_eq!(i.mnemonic, "v128.const");
        assert_eq!(i.size, 18);
    }

    #[test]
    fn test_simd_i32x4_add() {
        // 0xFD + uleb 0xAE 0x01 (= 174 = i32x4.add)
        let i = dis(&[0xFD, 0xAE, 0x01]);
        assert_eq!(i.mnemonic, "i32x4.add");
    }
}

// ── Wasm binary format types ──────────────────────────────────────────────────

/// Wasm binary magic bytes.
pub const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];

/// Wasm binary version (MVP = 1).
pub const WASM_VERSION: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// Wasm value types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WasmValueType {
    /// 32-bit integer.
    I32,
    /// 64-bit integer.
    I64,
    /// 32-bit float.
    F32,
    /// 64-bit float.
    F64,
    /// 128-bit SIMD vector.
    V128,
    /// Function reference.
    FuncRef,
    /// External reference.
    ExternRef,
}

impl WasmValueType {
    /// Decode a value type from a byte (Wasm encoding).
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0x7F => Self::I32,
            0x7E => Self::I64,
            0x7D => Self::F32,
            0x7C => Self::F64,
            0x7B => Self::V128,
            0x70 => Self::FuncRef,
            0x6F => Self::ExternRef,
            _ => return None,
        })
    }

    /// Return the text name of this value type.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::V128 => "v128",
            Self::FuncRef => "funcref",
            Self::ExternRef => "externref",
        }
    }

    /// Return the binary encoding byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::I32 => 0x7F,
            Self::I64 => 0x7E,
            Self::F32 => 0x7D,
            Self::F64 => 0x7C,
            Self::V128 => 0x7B,
            Self::FuncRef => 0x70,
            Self::ExternRef => 0x6F,
        }
    }

    /// Returns `true` when the type is a numeric type.
    #[must_use]
    pub const fn is_numeric(self) -> bool {
        matches!(self, Self::I32 | Self::I64 | Self::F32 | Self::F64)
    }

    /// Returns `true` for reference types.
    #[must_use]
    pub const fn is_reference(self) -> bool {
        matches!(self, Self::FuncRef | Self::ExternRef)
    }
}

/// Wasm section ID bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WasmSectionId {
    Custom = 0,
    Type = 1,
    Import = 2,
    Function = 3,
    Table = 4,
    Memory = 5,
    Global = 6,
    Export = 7,
    Start = 8,
    Element = 9,
    Code = 10,
    Data = 11,
    DataCount = 12,
}

impl WasmSectionId {
    /// Decode a section ID byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Custom,
            1 => Self::Type,
            2 => Self::Import,
            3 => Self::Function,
            4 => Self::Table,
            5 => Self::Memory,
            6 => Self::Global,
            7 => Self::Export,
            8 => Self::Start,
            9 => Self::Element,
            10 => Self::Code,
            11 => Self::Data,
            12 => Self::DataCount,
            _ => return None,
        })
    }

    /// Return the name of the section.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Custom => "custom",
            Self::Type => "type",
            Self::Import => "import",
            Self::Function => "function",
            Self::Table => "table",
            Self::Memory => "memory",
            Self::Global => "global",
            Self::Export => "export",
            Self::Start => "start",
            Self::Element => "element",
            Self::Code => "code",
            Self::Data => "data",
            Self::DataCount => "datacount",
        }
    }
}

/// Wasm external kind (import/export).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WasmExternalKind {
    Function = 0,
    Table = 1,
    Memory = 2,
    Global = 3,
}

impl WasmExternalKind {
    /// Decode from a byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Function,
            1 => Self::Table,
            2 => Self::Memory,
            3 => Self::Global,
            _ => return None,
        })
    }

    /// Return the name of this external kind.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Function => "func",
            Self::Table => "table",
            Self::Memory => "memory",
            Self::Global => "global",
        }
    }
}

/// Wasm mutability for globals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WasmMutability {
    Const = 0,
    Mutable = 1,
}

impl WasmMutability {
    /// Decode from a byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Const),
            1 => Some(Self::Mutable),
            _ => None,
        }
    }
}

/// Wasm limits (for memories and tables).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmLimits {
    /// Minimum size (in pages for memory, elements for table).
    pub min: u64,
    /// Optional maximum size.
    pub max: Option<u64>,
}

impl WasmLimits {
    /// Decode limits from a byte slice.
    ///
    /// Returns `(limits, bytes_consumed)`.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` if the byte slice is truncated or malformed.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), CoreError> {
        if bytes.is_empty() {
            return Err(CoreError::InvalidFormat {
                message: "truncated limits".into(),
            });
        }
        let kind = bytes[0];
        let mut pos = 1;
        let (min, n) = read_uleb128(bytes, pos)?;
        pos += n;
        if kind == 0 {
            return Ok((Self { min, max: None }, pos));
        } else if kind == 1 {
            let (max, n2) = read_uleb128(bytes, pos)?;
            pos += n2;
            return Ok((
                Self {
                    min,
                    max: Some(max),
                },
                pos,
            ));
        }
        Err(CoreError::InvalidFormat {
            message: format!("unknown limits kind: {kind}"),
        })
    }
}

/// A Wasm function type (signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmFuncType {
    /// Parameter value types.
    pub params: Vec<WasmValueType>,
    /// Result value types.
    pub results: Vec<WasmValueType>,
}

impl WasmFuncType {
    /// Decode a function type from binary format.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` if data is truncated or a value type is unknown.
    pub fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.is_empty() || bytes[0] != 0x60 {
            return Err(CoreError::InvalidFormat {
                message: "expected functype marker 0x60".into(),
            });
        }
        // Cap at a sane limit: the Wasm spec allows up to 2^32-1 parameters in
        // theory but practical implementations cap far lower. We cap here to
        // prevent an attacker-controlled LEB128 value from causing a gigabyte
        // allocation before the per-byte bounds check can fire.
        const MAX_FUNC_PARAMS: u64 = 32_768;
        let mut pos = 1usize;
        let (param_count, n) = read_uleb128(bytes, pos)?;
        pos += n;
        if param_count > MAX_FUNC_PARAMS {
            return Err(CoreError::InvalidFormat {
                message: format!("functype param count {param_count} exceeds limit"),
            });
        }
        let mut params = Vec::new();
        for _ in 0..param_count {
            if pos >= bytes.len() {
                return Err(CoreError::InvalidFormat {
                    message: "truncated param types".into(),
                });
            }
            let vt =
                WasmValueType::from_byte(bytes[pos]).ok_or_else(|| CoreError::InvalidFormat {
                    message: format!("unknown valtype 0x{:02x}", bytes[pos]),
                })?;
            params.push(vt);
            pos += 1;
        }
        let (result_count, n2) = read_uleb128(bytes, pos)?;
        pos += n2;
        if result_count > MAX_FUNC_PARAMS {
            return Err(CoreError::InvalidFormat {
                message: format!("functype result count {result_count} exceeds limit"),
            });
        }
        let mut results = Vec::new();
        for _ in 0..result_count {
            if pos >= bytes.len() {
                return Err(CoreError::InvalidFormat {
                    message: "truncated result types".into(),
                });
            }
            let vt =
                WasmValueType::from_byte(bytes[pos]).ok_or_else(|| CoreError::InvalidFormat {
                    message: format!("unknown valtype 0x{:02x}", bytes[pos]),
                })?;
            results.push(vt);
            pos += 1;
        }
        Ok(Self { params, results })
    }

    /// Return the arity (number of params and results).
    #[must_use]
    pub const fn arity(&self) -> (usize, usize) {
        (self.params.len(), self.results.len())
    }
}

/// Parsed Wasm module header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmModuleHeader {
    /// Magic bytes.
    pub magic: [u8; 4],
    /// Version bytes.
    pub version: [u8; 4],
}

impl WasmModuleHeader {
    /// Parse a Wasm module header from the first 8 bytes.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` if the magic or version is invalid.
    pub fn parse(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() < 8 {
            return Err(CoreError::InvalidFormat {
                message: "truncated module header".into(),
            });
        }
        let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
        let version: [u8; 4] = bytes[4..8].try_into().unwrap();
        if magic != WASM_MAGIC {
            return Err(CoreError::InvalidFormat {
                message: "invalid Wasm magic".into(),
            });
        }
        if version != WASM_VERSION {
            return Err(CoreError::InvalidFormat {
                message: format!("unsupported Wasm version: {version:?}"),
            });
        }
        Ok(Self { magic, version })
    }
}

/// A Wasm global type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmGlobalType {
    /// The value type of the global.
    pub content_type: WasmValueType,
    /// Whether the global is mutable.
    pub mutability: WasmMutability,
}

impl WasmGlobalType {
    /// Decode a global type from binary format.
    ///
    /// Returns `(global_type, bytes_consumed)`.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` if the data is truncated or the type is unknown.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), CoreError> {
        if bytes.len() < 2 {
            return Err(CoreError::InvalidFormat {
                message: "truncated global type".into(),
            });
        }
        let content_type =
            WasmValueType::from_byte(bytes[0]).ok_or_else(|| CoreError::InvalidFormat {
                message: format!("unknown valtype 0x{:02x}", bytes[0]),
            })?;
        let mutability =
            WasmMutability::from_byte(bytes[1]).ok_or_else(|| CoreError::InvalidFormat {
                message: format!("unknown mutability 0x{:02x}", bytes[1]),
            })?;
        Ok((
            Self {
                content_type,
                mutability,
            },
            2,
        ))
    }
}

/// A Wasm table type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmTableType {
    /// Element type (must be a reference type).
    pub element_type: WasmValueType,
    /// Table limits.
    pub limits: WasmLimits,
}

impl WasmTableType {
    /// Decode a table type.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` for invalid data.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), CoreError> {
        if bytes.is_empty() {
            return Err(CoreError::InvalidFormat {
                message: "truncated table type".into(),
            });
        }
        let element_type =
            WasmValueType::from_byte(bytes[0]).ok_or_else(|| CoreError::InvalidFormat {
                message: "unknown ref type".into(),
            })?;
        let (limits, n) = WasmLimits::decode(&bytes[1..])?;
        Ok((
            Self {
                element_type,
                limits,
            },
            1 + n,
        ))
    }
}

/// A Wasm memory type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmMemoryType {
    /// Memory limits (in pages of 64 KiB).
    pub limits: WasmLimits,
}

impl WasmMemoryType {
    /// Decode a memory type.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` for invalid data.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), CoreError> {
        let (limits, n) = WasmLimits::decode(bytes)?;
        Ok((Self { limits }, n))
    }
}

/// Wasm import entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmImport {
    /// Module name.
    pub module: String,
    /// Field name.
    pub name: String,
    /// Import kind.
    pub kind: WasmExternalKind,
    /// Type index (for functions).
    pub index: u32,
}

/// Wasm export entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmExport {
    /// Export name.
    pub name: String,
    /// Export kind.
    pub kind: WasmExternalKind,
    /// Index into the respective section.
    pub index: u32,
}

// ── Extended decode for 0xFC, 0xFD, 0xFE prefixes ───────────────────────────

/// Decode a 0xFC-prefixed instruction (saturating truncation + bulk memory).
///
/// # Errors
///
/// Returns `CoreError` for unknown sub-opcodes or truncated input.
pub fn decode_fc_prefix(bytes: &[u8]) -> Result<(String, String, usize, InstrFlags), CoreError> {
    if bytes.len() < 2 {
        return Err(CoreError::InvalidFormat {
            message: "truncated 0xFC instruction".into(),
        });
    }
    let (sub, n) = read_uleb128(bytes, 1)?;
    let mut pos = 1 + n;

    let (mnemonic, operands, flags) = match sub {
        0 => (
            "i32.trunc_sat_f32_s".to_string(),
            String::new(),
            InstrFlags::NONE,
        ),
        1 => (
            "i32.trunc_sat_f32_u".to_string(),
            String::new(),
            InstrFlags::NONE,
        ),
        2 => (
            "i32.trunc_sat_f64_s".to_string(),
            String::new(),
            InstrFlags::NONE,
        ),
        3 => (
            "i32.trunc_sat_f64_u".to_string(),
            String::new(),
            InstrFlags::NONE,
        ),
        4 => (
            "i64.trunc_sat_f32_s".to_string(),
            String::new(),
            InstrFlags::NONE,
        ),
        5 => (
            "i64.trunc_sat_f32_u".to_string(),
            String::new(),
            InstrFlags::NONE,
        ),
        6 => (
            "i64.trunc_sat_f64_s".to_string(),
            String::new(),
            InstrFlags::NONE,
        ),
        7 => (
            "i64.trunc_sat_f64_u".to_string(),
            String::new(),
            InstrFlags::NONE,
        ),
        // memory.init seg mem
        8 => {
            let (seg, n1) = read_uleb128(bytes, pos)?;
            pos += n1;
            let (mem, n2) = read_uleb128(bytes, pos)?;
            pos += n2;
            (
                "memory.init".to_string(),
                format!("{seg} {mem}"),
                InstrFlags::WRITE_MEM,
            )
        }
        // data.drop seg
        9 => {
            let (seg, n1) = read_uleb128(bytes, pos)?;
            pos += n1;
            ("data.drop".to_string(), format!("{seg}"), InstrFlags::NONE)
        }
        // memory.copy dst src
        10 => {
            let (dst, n1) = read_uleb128(bytes, pos)?;
            pos += n1;
            let (src, n2) = read_uleb128(bytes, pos)?;
            pos += n2;
            (
                "memory.copy".to_string(),
                format!("{dst} {src}"),
                InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            )
        }
        // memory.fill mem
        11 => {
            let (mem, n1) = read_uleb128(bytes, pos)?;
            pos += n1;
            (
                "memory.fill".to_string(),
                format!("{mem}"),
                InstrFlags::WRITE_MEM,
            )
        }
        // table.init
        12 => {
            let (elem, n1) = read_uleb128(bytes, pos)?;
            pos += n1;
            let (table, n2) = read_uleb128(bytes, pos)?;
            pos += n2;
            (
                "table.init".to_string(),
                format!("{elem} {table}"),
                InstrFlags::WRITE_MEM,
            )
        }
        // elem.drop
        13 => {
            let (elem, n1) = read_uleb128(bytes, pos)?;
            pos += n1;
            ("elem.drop".to_string(), format!("{elem}"), InstrFlags::NONE)
        }
        // table.copy
        14 => {
            let (dst, n1) = read_uleb128(bytes, pos)?;
            pos += n1;
            let (src, n2) = read_uleb128(bytes, pos)?;
            pos += n2;
            (
                "table.copy".to_string(),
                format!("{dst} {src}"),
                InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            )
        }
        // table.grow
        15 => {
            let (table, n1) = read_uleb128(bytes, pos)?;
            pos += n1;
            (
                "table.grow".to_string(),
                format!("{table}"),
                InstrFlags::NONE,
            )
        }
        // table.size
        16 => {
            let (table, n1) = read_uleb128(bytes, pos)?;
            pos += n1;
            (
                "table.size".to_string(),
                format!("{table}"),
                InstrFlags::NONE,
            )
        }
        // table.fill
        17 => {
            let (table, n1) = read_uleb128(bytes, pos)?;
            pos += n1;
            (
                "table.fill".to_string(),
                format!("{table}"),
                InstrFlags::WRITE_MEM,
            )
        }
        _ => {
            return Err(CoreError::InvalidFormat {
                message: format!("unknown 0xFC sub-opcode {sub}"),
            });
        }
    };
    Ok((mnemonic, operands, pos, flags))
}

/// SIMD opcode table entry.
#[derive(Debug, Clone, Copy)]
pub struct SimdOpcodeEntry {
    /// SIMD sub-opcode value.
    pub sub_opcode: u32,
    /// Mnemonic.
    pub mnemonic: &'static str,
    /// Whether this instruction has an immediate memarg (align + offset).
    pub has_memarg: bool,
}

/// Return the mnemonic for a SIMD (0xFD) sub-opcode.
#[must_use]
pub fn simd_opcode_mnemonic(sub: u32) -> Option<&'static str> {
    SIMD_OPCODES
        .iter()
        .find(|e| e.sub_opcode == sub)
        .map(|e| e.mnemonic)
}

/// Full SIMD opcode table (sub-opcodes for 0xFD prefix).
pub static SIMD_OPCODES: &[SimdOpcodeEntry] = &[
    SimdOpcodeEntry {
        sub_opcode: 0,
        mnemonic: "v128.load",
        has_memarg: true,
    },
    SimdOpcodeEntry {
        sub_opcode: 1,
        mnemonic: "v128.load8x8_s",
        has_memarg: true,
    },
    SimdOpcodeEntry {
        sub_opcode: 2,
        mnemonic: "v128.load8x8_u",
        has_memarg: true,
    },
    SimdOpcodeEntry {
        sub_opcode: 3,
        mnemonic: "v128.load16x4_s",
        has_memarg: true,
    },
    SimdOpcodeEntry {
        sub_opcode: 4,
        mnemonic: "v128.load16x4_u",
        has_memarg: true,
    },
    SimdOpcodeEntry {
        sub_opcode: 5,
        mnemonic: "v128.load32x2_s",
        has_memarg: true,
    },
    SimdOpcodeEntry {
        sub_opcode: 6,
        mnemonic: "v128.load32x2_u",
        has_memarg: true,
    },
    SimdOpcodeEntry {
        sub_opcode: 7,
        mnemonic: "v128.load8_splat",
        has_memarg: true,
    },
    SimdOpcodeEntry {
        sub_opcode: 8,
        mnemonic: "v128.load16_splat",
        has_memarg: true,
    },
    SimdOpcodeEntry {
        sub_opcode: 9,
        mnemonic: "v128.load32_splat",
        has_memarg: true,
    },
    SimdOpcodeEntry {
        sub_opcode: 10,
        mnemonic: "v128.load64_splat",
        has_memarg: true,
    },
    SimdOpcodeEntry {
        sub_opcode: 11,
        mnemonic: "v128.store",
        has_memarg: true,
    },
    SimdOpcodeEntry {
        sub_opcode: 12,
        mnemonic: "v128.const",
        has_memarg: false,
    }, // + 16 bytes
    SimdOpcodeEntry {
        sub_opcode: 13,
        mnemonic: "i8x16.shuffle",
        has_memarg: false,
    }, // + 16 bytes
    SimdOpcodeEntry {
        sub_opcode: 14,
        mnemonic: "i8x16.swizzle",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 15,
        mnemonic: "i8x16.splat",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 16,
        mnemonic: "i16x8.splat",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 17,
        mnemonic: "i32x4.splat",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 18,
        mnemonic: "i64x2.splat",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 19,
        mnemonic: "f32x4.splat",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 20,
        mnemonic: "f64x2.splat",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 21,
        mnemonic: "i8x16.extract_lane_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 22,
        mnemonic: "i8x16.extract_lane_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 23,
        mnemonic: "i8x16.replace_lane",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 24,
        mnemonic: "i16x8.extract_lane_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 25,
        mnemonic: "i16x8.extract_lane_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 26,
        mnemonic: "i16x8.replace_lane",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 27,
        mnemonic: "i32x4.extract_lane",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 28,
        mnemonic: "i32x4.replace_lane",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 29,
        mnemonic: "i64x2.extract_lane",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 30,
        mnemonic: "i64x2.replace_lane",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 31,
        mnemonic: "f32x4.extract_lane",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 32,
        mnemonic: "f32x4.replace_lane",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 33,
        mnemonic: "f64x2.extract_lane",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 34,
        mnemonic: "f64x2.replace_lane",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 35,
        mnemonic: "i8x16.eq",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 36,
        mnemonic: "i8x16.ne",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 37,
        mnemonic: "i8x16.lt_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 38,
        mnemonic: "i8x16.lt_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 39,
        mnemonic: "i8x16.gt_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 40,
        mnemonic: "i8x16.gt_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 41,
        mnemonic: "i8x16.le_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 42,
        mnemonic: "i8x16.le_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 43,
        mnemonic: "i8x16.ge_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 44,
        mnemonic: "i8x16.ge_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 45,
        mnemonic: "i16x8.eq",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 46,
        mnemonic: "i16x8.ne",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 47,
        mnemonic: "i16x8.lt_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 48,
        mnemonic: "i16x8.lt_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 49,
        mnemonic: "i16x8.gt_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 50,
        mnemonic: "i16x8.gt_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 51,
        mnemonic: "i16x8.le_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 52,
        mnemonic: "i16x8.le_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 53,
        mnemonic: "i16x8.ge_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 54,
        mnemonic: "i16x8.ge_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 55,
        mnemonic: "i32x4.eq",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 56,
        mnemonic: "i32x4.ne",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 57,
        mnemonic: "i32x4.lt_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 58,
        mnemonic: "i32x4.lt_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 59,
        mnemonic: "i32x4.gt_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 60,
        mnemonic: "i32x4.gt_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 61,
        mnemonic: "i32x4.le_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 62,
        mnemonic: "i32x4.le_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 63,
        mnemonic: "i32x4.ge_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 64,
        mnemonic: "i32x4.ge_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 65,
        mnemonic: "f32x4.eq",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 66,
        mnemonic: "f32x4.ne",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 67,
        mnemonic: "f32x4.lt",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 68,
        mnemonic: "f32x4.gt",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 69,
        mnemonic: "f32x4.le",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 70,
        mnemonic: "f32x4.ge",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 71,
        mnemonic: "f64x2.eq",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 72,
        mnemonic: "f64x2.ne",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 73,
        mnemonic: "f64x2.lt",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 74,
        mnemonic: "f64x2.gt",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 75,
        mnemonic: "f64x2.le",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 76,
        mnemonic: "f64x2.ge",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 77,
        mnemonic: "v128.not",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 78,
        mnemonic: "v128.and",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 79,
        mnemonic: "v128.andnot",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 80,
        mnemonic: "v128.or",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 81,
        mnemonic: "v128.xor",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 82,
        mnemonic: "v128.bitselect",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 83,
        mnemonic: "v128.any_true",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 96,
        mnemonic: "i8x16.abs",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 97,
        mnemonic: "i8x16.neg",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 98,
        mnemonic: "i8x16.popcnt",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 99,
        mnemonic: "i8x16.all_true",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 100,
        mnemonic: "i8x16.bitmask",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 101,
        mnemonic: "i8x16.narrow_i16x8_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 102,
        mnemonic: "i8x16.narrow_i16x8_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 107,
        mnemonic: "i8x16.shl",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 108,
        mnemonic: "i8x16.shr_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 109,
        mnemonic: "i8x16.shr_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 110,
        mnemonic: "i8x16.add",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 111,
        mnemonic: "i8x16.add_sat_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 112,
        mnemonic: "i8x16.add_sat_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 113,
        mnemonic: "i8x16.sub",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 114,
        mnemonic: "i8x16.sub_sat_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 115,
        mnemonic: "i8x16.sub_sat_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 118,
        mnemonic: "i8x16.min_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 119,
        mnemonic: "i8x16.min_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 120,
        mnemonic: "i8x16.max_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 121,
        mnemonic: "i8x16.max_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 123,
        mnemonic: "i8x16.avgr_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 128,
        mnemonic: "i16x8.abs",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 129,
        mnemonic: "i16x8.neg",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 130,
        mnemonic: "i16x8.q15mulr_sat_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 131,
        mnemonic: "i16x8.all_true",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 132,
        mnemonic: "i16x8.bitmask",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 133,
        mnemonic: "i16x8.narrow_i32x4_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 134,
        mnemonic: "i16x8.narrow_i32x4_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 135,
        mnemonic: "i16x8.extend_low_i8x16_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 136,
        mnemonic: "i16x8.extend_high_i8x16_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 137,
        mnemonic: "i16x8.extend_low_i8x16_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 138,
        mnemonic: "i16x8.extend_high_i8x16_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 139,
        mnemonic: "i16x8.shl",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 140,
        mnemonic: "i16x8.shr_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 141,
        mnemonic: "i16x8.shr_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 142,
        mnemonic: "i16x8.add",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 143,
        mnemonic: "i16x8.add_sat_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 144,
        mnemonic: "i16x8.add_sat_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 145,
        mnemonic: "i16x8.sub",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 146,
        mnemonic: "i16x8.sub_sat_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 147,
        mnemonic: "i16x8.sub_sat_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 149,
        mnemonic: "i16x8.mul",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 150,
        mnemonic: "i16x8.min_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 151,
        mnemonic: "i16x8.min_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 152,
        mnemonic: "i16x8.max_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 153,
        mnemonic: "i16x8.max_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 155,
        mnemonic: "i16x8.avgr_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 156,
        mnemonic: "i16x8.extmul_low_i8x16_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 157,
        mnemonic: "i16x8.extmul_high_i8x16_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 158,
        mnemonic: "i16x8.extmul_low_i8x16_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 159,
        mnemonic: "i16x8.extmul_high_i8x16_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 160,
        mnemonic: "i32x4.abs",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 161,
        mnemonic: "i32x4.neg",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 163,
        mnemonic: "i32x4.all_true",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 164,
        mnemonic: "i32x4.bitmask",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 167,
        mnemonic: "i32x4.extend_low_i16x8_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 168,
        mnemonic: "i32x4.extend_high_i16x8_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 169,
        mnemonic: "i32x4.extend_low_i16x8_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 170,
        mnemonic: "i32x4.extend_high_i16x8_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 171,
        mnemonic: "i32x4.shl",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 172,
        mnemonic: "i32x4.shr_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 173,
        mnemonic: "i32x4.shr_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 174,
        mnemonic: "i32x4.add",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 177,
        mnemonic: "i32x4.sub",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 181,
        mnemonic: "i32x4.mul",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 182,
        mnemonic: "i32x4.min_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 183,
        mnemonic: "i32x4.min_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 184,
        mnemonic: "i32x4.max_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 185,
        mnemonic: "i32x4.max_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 186,
        mnemonic: "i32x4.dot_i16x8_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 188,
        mnemonic: "i32x4.extmul_low_i16x8_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 189,
        mnemonic: "i32x4.extmul_high_i16x8_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 190,
        mnemonic: "i32x4.extmul_low_i16x8_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 191,
        mnemonic: "i32x4.extmul_high_i16x8_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 192,
        mnemonic: "i64x2.abs",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 193,
        mnemonic: "i64x2.neg",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 195,
        mnemonic: "i64x2.all_true",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 196,
        mnemonic: "i64x2.bitmask",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 199,
        mnemonic: "i64x2.extend_low_i32x4_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 200,
        mnemonic: "i64x2.extend_high_i32x4_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 201,
        mnemonic: "i64x2.extend_low_i32x4_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 202,
        mnemonic: "i64x2.extend_high_i32x4_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 203,
        mnemonic: "i64x2.shl",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 204,
        mnemonic: "i64x2.shr_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 205,
        mnemonic: "i64x2.shr_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 206,
        mnemonic: "i64x2.add",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 209,
        mnemonic: "i64x2.sub",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 213,
        mnemonic: "i64x2.mul",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 214,
        mnemonic: "i64x2.eq",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 215,
        mnemonic: "i64x2.ne",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 216,
        mnemonic: "i64x2.lt_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 217,
        mnemonic: "i64x2.gt_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 218,
        mnemonic: "i64x2.le_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 219,
        mnemonic: "i64x2.ge_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 220,
        mnemonic: "i64x2.extmul_low_i32x4_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 221,
        mnemonic: "i64x2.extmul_high_i32x4_s",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 222,
        mnemonic: "i64x2.extmul_low_i32x4_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 223,
        mnemonic: "i64x2.extmul_high_i32x4_u",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 224,
        mnemonic: "f32x4.ceil",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 225,
        mnemonic: "f32x4.floor",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 226,
        mnemonic: "f32x4.trunc",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 227,
        mnemonic: "f32x4.nearest",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 228,
        mnemonic: "f64x2.ceil",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 229,
        mnemonic: "f64x2.floor",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 230,
        mnemonic: "f64x2.trunc",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 231,
        mnemonic: "f64x2.nearest",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 232,
        mnemonic: "f32x4.abs",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 233,
        mnemonic: "f32x4.neg",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 235,
        mnemonic: "f32x4.sqrt",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 236,
        mnemonic: "f32x4.add",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 237,
        mnemonic: "f32x4.sub",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 238,
        mnemonic: "f32x4.mul",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 239,
        mnemonic: "f32x4.div",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 240,
        mnemonic: "f32x4.min",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 241,
        mnemonic: "f32x4.max",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 242,
        mnemonic: "f32x4.pmin",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 243,
        mnemonic: "f32x4.pmax",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 244,
        mnemonic: "f64x2.abs",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 245,
        mnemonic: "f64x2.neg",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 247,
        mnemonic: "f64x2.sqrt",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 248,
        mnemonic: "f64x2.add",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 249,
        mnemonic: "f64x2.sub",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 250,
        mnemonic: "f64x2.mul",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 251,
        mnemonic: "f64x2.div",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 252,
        mnemonic: "f64x2.min",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 253,
        mnemonic: "f64x2.max",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 254,
        mnemonic: "f64x2.pmin",
        has_memarg: false,
    },
    SimdOpcodeEntry {
        sub_opcode: 255,
        mnemonic: "f64x2.pmax",
        has_memarg: false,
    },
];

/// Decode a 0xFD-prefixed SIMD instruction.
///
/// # Errors
///
/// Returns `CoreError` for unknown sub-opcodes or truncated input.
pub fn decode_fd_prefix(bytes: &[u8]) -> Result<(String, String, usize, InstrFlags), CoreError> {
    if bytes.is_empty() {
        return Err(CoreError::InvalidFormat {
            message: "empty 0xFD prefix".into(),
        });
    }
    let (sub, n) = read_uleb128(bytes, 1)?;
    let mut pos = 1 + n;

    let mnemonic = simd_opcode_mnemonic(u32::try_from(sub).unwrap_or(u32::MAX))
        .ok_or_else(|| CoreError::InvalidFormat {
            message: format!("unknown SIMD sub-opcode {sub}"),
        })?
        .to_string();

    let entry = SIMD_OPCODES.iter().find(|e| u64::from(e.sub_opcode) == sub);
    let flags;

    // Handle special cases with extra immediates
    let operands = if sub == 12 {
        // v128.const — 16 immediate bytes
        if bytes.len() < pos + 16 {
            return Err(CoreError::InvalidFormat {
                message: "truncated v128.const".into(),
            });
        }
        let bytes16 = &bytes[pos..pos + 16];
        pos += 16;
        flags = InstrFlags::NONE;
        format!(
            "0x{}",
            bytes16.iter().fold(String::new(), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            })
        )
    } else if sub == 13 {
        // i8x16.shuffle — 16 lane indices
        if bytes.len() < pos + 16 {
            return Err(CoreError::InvalidFormat {
                message: "truncated i8x16.shuffle".into(),
            });
        }
        let lanes = &bytes[pos..pos + 16];
        pos += 16;
        flags = InstrFlags::NONE;
        lanes
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    } else if matches!(sub, 21..=34) {
        // Lane extraction/replacement — 1 lane index byte
        if pos >= bytes.len() {
            return Err(CoreError::InvalidFormat {
                message: "truncated lane index".into(),
            });
        }
        let lane = bytes[pos];
        pos += 1;
        flags = InstrFlags::NONE;
        lane.to_string()
    } else if entry.is_some_and(|e| e.has_memarg) {
        // Memory load/store ops — align + offset
        let (align, n1) = read_uleb128(bytes, pos)?;
        pos += n1;
        let (offset, n2) = read_uleb128(bytes, pos)?;
        pos += n2;
        flags = if sub == 11 {
            InstrFlags::WRITE_MEM
        } else {
            InstrFlags::READ_MEM
        };
        format!("align={align} offset={offset}")
    } else {
        flags = InstrFlags::NONE;
        String::new()
    };

    Ok((mnemonic, operands, pos, flags))
}

/// Atomic opcode table entry.
#[derive(Debug, Clone, Copy)]
pub struct AtomicOpcodeEntry {
    /// Sub-opcode.
    pub sub_opcode: u32,
    /// Mnemonic.
    pub mnemonic: &'static str,
    /// Whether this is a load (true) or store (false) or RMW.
    pub is_load: bool,
}

/// Full atomic opcode table (sub-opcodes for 0xFE prefix).
pub static ATOMIC_OPCODES: &[AtomicOpcodeEntry] = &[
    AtomicOpcodeEntry {
        sub_opcode: 0x00,
        mnemonic: "memory.atomic.notify",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x01,
        mnemonic: "memory.atomic.wait32",
        is_load: true,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x02,
        mnemonic: "memory.atomic.wait64",
        is_load: true,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x03,
        mnemonic: "atomic.fence",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x10,
        mnemonic: "i32.atomic.load",
        is_load: true,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x11,
        mnemonic: "i64.atomic.load",
        is_load: true,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x12,
        mnemonic: "i32.atomic.load8_u",
        is_load: true,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x13,
        mnemonic: "i32.atomic.load16_u",
        is_load: true,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x14,
        mnemonic: "i64.atomic.load8_u",
        is_load: true,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x15,
        mnemonic: "i64.atomic.load16_u",
        is_load: true,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x16,
        mnemonic: "i64.atomic.load32_u",
        is_load: true,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x17,
        mnemonic: "i32.atomic.store",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x18,
        mnemonic: "i64.atomic.store",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x19,
        mnemonic: "i32.atomic.store8",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x1a,
        mnemonic: "i32.atomic.store16",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x1b,
        mnemonic: "i64.atomic.store8",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x1c,
        mnemonic: "i64.atomic.store16",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x1d,
        mnemonic: "i64.atomic.store32",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x1e,
        mnemonic: "i32.atomic.rmw.add",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x1f,
        mnemonic: "i64.atomic.rmw.add",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x20,
        mnemonic: "i32.atomic.rmw8.add_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x21,
        mnemonic: "i32.atomic.rmw16.add_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x22,
        mnemonic: "i64.atomic.rmw8.add_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x23,
        mnemonic: "i64.atomic.rmw16.add_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x24,
        mnemonic: "i64.atomic.rmw32.add_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x25,
        mnemonic: "i32.atomic.rmw.sub",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x26,
        mnemonic: "i64.atomic.rmw.sub",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x27,
        mnemonic: "i32.atomic.rmw8.sub_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x28,
        mnemonic: "i32.atomic.rmw16.sub_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x29,
        mnemonic: "i64.atomic.rmw8.sub_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x2a,
        mnemonic: "i64.atomic.rmw16.sub_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x2b,
        mnemonic: "i64.atomic.rmw32.sub_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x2c,
        mnemonic: "i32.atomic.rmw.and",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x2d,
        mnemonic: "i64.atomic.rmw.and",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x2e,
        mnemonic: "i32.atomic.rmw8.and_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x2f,
        mnemonic: "i32.atomic.rmw16.and_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x30,
        mnemonic: "i64.atomic.rmw8.and_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x31,
        mnemonic: "i64.atomic.rmw16.and_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x32,
        mnemonic: "i64.atomic.rmw32.and_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x33,
        mnemonic: "i32.atomic.rmw.or",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x34,
        mnemonic: "i64.atomic.rmw.or",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x35,
        mnemonic: "i32.atomic.rmw8.or_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x36,
        mnemonic: "i32.atomic.rmw16.or_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x37,
        mnemonic: "i64.atomic.rmw8.or_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x38,
        mnemonic: "i64.atomic.rmw16.or_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x39,
        mnemonic: "i64.atomic.rmw32.or_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x3a,
        mnemonic: "i32.atomic.rmw.xor",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x3b,
        mnemonic: "i64.atomic.rmw.xor",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x3c,
        mnemonic: "i32.atomic.rmw8.xor_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x3d,
        mnemonic: "i32.atomic.rmw16.xor_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x3e,
        mnemonic: "i64.atomic.rmw8.xor_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x3f,
        mnemonic: "i64.atomic.rmw16.xor_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x40,
        mnemonic: "i64.atomic.rmw32.xor_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x41,
        mnemonic: "i32.atomic.rmw.xchg",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x42,
        mnemonic: "i64.atomic.rmw.xchg",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x43,
        mnemonic: "i32.atomic.rmw8.xchg_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x44,
        mnemonic: "i32.atomic.rmw16.xchg_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x45,
        mnemonic: "i64.atomic.rmw8.xchg_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x46,
        mnemonic: "i64.atomic.rmw16.xchg_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x47,
        mnemonic: "i64.atomic.rmw32.xchg_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x48,
        mnemonic: "i32.atomic.rmw.cmpxchg",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x49,
        mnemonic: "i64.atomic.rmw.cmpxchg",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x4a,
        mnemonic: "i32.atomic.rmw8.cmpxchg_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x4b,
        mnemonic: "i32.atomic.rmw16.cmpxchg_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x4c,
        mnemonic: "i64.atomic.rmw8.cmpxchg_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x4d,
        mnemonic: "i64.atomic.rmw16.cmpxchg_u",
        is_load: false,
    },
    AtomicOpcodeEntry {
        sub_opcode: 0x4e,
        mnemonic: "i64.atomic.rmw32.cmpxchg_u",
        is_load: false,
    },
];

/// Decode a 0xFE-prefixed atomic instruction.
///
/// # Errors
///
/// Returns `CoreError` for unknown sub-opcodes or truncated input.
pub fn decode_fe_prefix(bytes: &[u8]) -> Result<(String, String, usize, InstrFlags), CoreError> {
    if bytes.is_empty() {
        return Err(CoreError::InvalidFormat {
            message: "empty 0xFE prefix".into(),
        });
    }
    let (sub, n) = read_uleb128(bytes, 1)?;
    let mut pos = 1 + n;

    let entry = ATOMIC_OPCODES
        .iter()
        .find(|e| u64::from(e.sub_opcode) == sub)
        .ok_or_else(|| CoreError::InvalidFormat {
            message: format!("unknown atomic sub-opcode 0x{sub:02x}"),
        })?;

    let flags = if entry.is_load {
        InstrFlags::READ_MEM
    } else if sub == 0x03 {
        InstrFlags::BARRIER
    } else {
        InstrFlags::WRITE_MEM
    };

    // atomic.fence has no memarg
    let operands = if sub == 0x03 {
        String::new()
    } else {
        let (align, n1) = read_uleb128(bytes, pos)?;
        pos += n1;
        let (offset, n2) = read_uleb128(bytes, pos)?;
        pos += n2;
        format!("align={align} offset={offset}")
    };

    Ok((entry.mnemonic.to_string(), operands, pos, flags))
}

// ── Wasm linear disassembler ─────────────────────────────────────────────────

/// Iterator that decodes Wasm bytecode linearly.
pub struct WasmLinearDisassembler<'a> {
    arch: &'a WasmArch,
    bytes: &'a [u8],
    address: Address,
    offset: usize,
}

impl<'a> WasmLinearDisassembler<'a> {
    /// Create a new disassembler starting at `base_address`.
    #[must_use]
    pub const fn new(arch: &'a WasmArch, bytes: &'a [u8], base_address: Address) -> Self {
        Self {
            arch,
            bytes,
            address: base_address,
            offset: 0,
        }
    }

    /// Return the current byte offset.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }
}

impl Iterator for WasmLinearDisassembler<'_> {
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

// ── Wasm program statistics ──────────────────────────────────────────────────

/// Statistics gathered from a Wasm function body.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WasmFunctionStats {
    /// Total instructions decoded.
    pub instruction_count: usize,
    /// Number of `call/call_indirect` instructions.
    pub call_count: usize,
    /// Number of branch instructions (br, `br_if`, `br_table`).
    pub branch_count: usize,
    /// Number of memory load instructions.
    pub load_count: usize,
    /// Number of memory store instructions.
    pub store_count: usize,
    /// Number of return instructions.
    pub return_count: usize,
    /// Number of unreachable instructions.
    pub unreachable_count: usize,
}

impl WasmFunctionStats {
    /// Analyse a byte slice of Wasm bytecode and return statistics.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` on truncated or invalid input.
    pub fn from_bytes(arch: &WasmArch, bytes: &[u8]) -> Result<Self, CoreError> {
        let mut stats = Self::default();
        for item in WasmLinearDisassembler::new(arch, bytes, Address::new(0)) {
            let instr = item?;
            stats.instruction_count += 1;
            if instr.flags.contains(InstrFlags::CALL) {
                stats.call_count += 1;
            }
            if instr.flags.contains(InstrFlags::BRANCH) {
                stats.branch_count += 1;
            }
            if instr.flags.contains(InstrFlags::READ_MEM) {
                stats.load_count += 1;
            }
            if instr.flags.contains(InstrFlags::WRITE_MEM) {
                stats.store_count += 1;
            }
            if instr.flags.contains(InstrFlags::RET) {
                stats.return_count += 1;
            }
            if instr.flags.contains(InstrFlags::BARRIER) && instr.mnemonic == "unreachable" {
                stats.unreachable_count += 1;
            }
        }
        Ok(stats)
    }
}

// ── Wasm name section helpers ────────────────────────────────────────────────

/// Name subsection types (from the Wasm name section).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameSubsectionType {
    ModuleName = 0,
    FunctionName = 1,
    LocalName = 2,
    LabelName = 3,
    TypeName = 4,
    TableName = 5,
    MemoryName = 6,
    GlobalName = 7,
    ElementName = 8,
    DataName = 9,
}

impl NameSubsectionType {
    /// Decode from a byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::ModuleName,
            1 => Self::FunctionName,
            2 => Self::LocalName,
            3 => Self::LabelName,
            4 => Self::TypeName,
            5 => Self::TableName,
            6 => Self::MemoryName,
            7 => Self::GlobalName,
            8 => Self::ElementName,
            9 => Self::DataName,
            _ => return None,
        })
    }

    /// Return the name of this subsection type.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ModuleName => "module",
            Self::FunctionName => "function",
            Self::LocalName => "local",
            Self::LabelName => "label",
            Self::TypeName => "type",
            Self::TableName => "table",
            Self::MemoryName => "memory",
            Self::GlobalName => "global",
            Self::ElementName => "element",
            Self::DataName => "data",
        }
    }
}

// ── Wasm semantic execution model ────────────────────────────────────────────

/// A typed value that can live on the Wasm operand stack.
#[derive(Debug, Clone, PartialEq)]
pub enum WasmValue {
    /// 32-bit signed integer.
    I32(i32),
    /// 64-bit signed integer.
    I64(i64),
    /// 32-bit floating-point.
    F32(f32),
    /// 64-bit floating-point.
    F64(f64),
    /// 128-bit SIMD vector stored as raw bytes (little-endian lane order).
    V128([u8; 16]),
}

impl WasmValue {
    /// Return the `WasmValueType` tag for this value.
    #[must_use]
    pub const fn value_type(&self) -> WasmValueType {
        match self {
            Self::I32(_) => WasmValueType::I32,
            Self::I64(_) => WasmValueType::I64,
            Self::F32(_) => WasmValueType::F32,
            Self::F64(_) => WasmValueType::F64,
            Self::V128(_) => WasmValueType::V128,
        }
    }

    /// Attempt to unwrap as `i32`. Returns `None` if the variant does not match.
    #[must_use]
    pub const fn as_i32(&self) -> Option<i32> {
        if let Self::I32(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Attempt to unwrap as `i64`.
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        if let Self::I64(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Attempt to unwrap as `f32`.
    #[must_use]
    pub const fn as_f32(&self) -> Option<f32> {
        if let Self::F32(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Attempt to unwrap as `f64`.
    #[must_use]
    pub const fn as_f64(&self) -> Option<f64> {
        if let Self::F64(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Attempt to unwrap as a 16-byte V128 vector.
    #[must_use]
    pub const fn as_v128(&self) -> Option<&[u8; 16]> {
        if let Self::V128(v) = self {
            Some(v)
        } else {
            None
        }
    }
}

// ── WasmStack ────────────────────────────────────────────────────────────────

/// The Wasm operand stack used by `WasmExecutor`.
#[derive(Debug, Default, Clone)]
pub struct WasmStack {
    inner: Vec<WasmValue>,
}

impl WasmStack {
    /// Construct an empty stack.
    #[must_use]
    pub const fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Push a value onto the top of the stack.
    pub fn push(&mut self, value: WasmValue) {
        self.inner.push(value);
    }

    /// Pop a value from the top of the stack.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` when the stack is empty.
    pub fn pop(&mut self) -> Result<WasmValue, CoreError> {
        self.inner.pop().ok_or_else(|| CoreError::InvalidFormat {
            message: "Wasm stack underflow".into(),
        })
    }

    /// Peek at the top of the stack without removing it.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` when the stack is empty.
    pub fn peek(&self) -> Result<&WasmValue, CoreError> {
        self.inner.last().ok_or_else(|| CoreError::InvalidFormat {
            message: "Wasm stack is empty (peek)".into(),
        })
    }

    /// Return the current depth of the stack.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.inner.len()
    }

    /// Return `true` when the stack holds no values.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Drain all values and return them in bottom-to-top order.
    pub fn drain(&mut self) -> Vec<WasmValue> {
        std::mem::take(&mut self.inner)
    }
}

// ── WasmOpcode (subset used by executor) ─────────────────────────────────────

/// A simplified Wasm opcode enum covering the instructions understood by
/// [`WasmExecutor::execute_instruction`].
#[derive(Debug, Clone, PartialEq)]
pub enum WasmOpcode {
    /// Push an i32 immediate constant.
    I32Const(i32),
    /// Push an i64 immediate constant.
    I64Const(i64),
    /// Push an f32 immediate constant.
    F32Const(f32),
    /// Push an f64 immediate constant.
    F64Const(f64),
    /// Pop two i32 values and push their sum.
    I32Add,
    /// Pop two i32 values and push `a - b` (top is subtrahend).
    I32Sub,
    /// Pop two i32 values and push their product.
    I32Mul,
    /// Pop two i32 values and push their signed quotient.
    I32DivS,
    /// Pop two i32 values and push their signed remainder.
    I32RemS,
    /// Pop two i32 values and push their bitwise AND.
    I32And,
    /// Pop two i32 values and push their bitwise OR.
    I32Or,
    /// Pop two i32 values and push their bitwise XOR.
    I32Xor,
    /// Pop the i32 address and push the 4-byte i32 at `memory[addr..]`.
    I32Load,
    /// Pop the i32 value and the i32 address; write value to `memory[addr..]`.
    I32Store,
    /// Push the local variable at index `i`.
    LocalGet(usize),
    /// Pop a value and store it in local variable at index `i`.
    LocalSet(usize),
    /// Copy the local at `i` to the stack (like `LocalGet`) and also keep it in local.
    LocalTee(usize),
    /// Push a global variable value (index).
    GlobalGet(usize),
    /// Pop a value and write it to a global variable (index).
    GlobalSet(usize),
    /// No operation.
    Nop,
    /// Unconditional trap.
    Unreachable,
    /// Discard the top stack value.
    Drop,
    /// Mark the end of a block, loop, if, or function.
    End,
    /// Branch unconditionally to depth `d`.
    Br(u32),
    /// Branch to depth `d` if the top of stack is non-zero.
    BrIf(u32),
    /// Return from the current function.
    Return,
}

// ── WasmExecutor ─────────────────────────────────────────────────────────────

/// A simple symbolic/concrete interpreter for Wasm instructions.
///
/// This is primarily intended for testing, tracing, and lightweight analysis —
/// not for full-speed production execution.
#[derive(Debug)]
pub struct WasmExecutor {
    /// The operand stack.
    pub stack: WasmStack,
    /// Local variable slots.
    pub locals: Vec<WasmValue>,
    /// Linear memory (byte-addressable).
    pub memory: Vec<u8>,
}

impl WasmExecutor {
    /// Construct a new executor with `memory_size` bytes of zeroed memory and
    /// `num_locals` local slots initialised to `I32(0)`.
    #[must_use]
    pub fn new(memory_size: usize, num_locals: usize) -> Self {
        Self {
            stack: WasmStack::new(),
            locals: vec![WasmValue::I32(0); num_locals],
            memory: vec![0u8; memory_size],
        }
    }

    /// Execute a single [`WasmOpcode`], mutating stack, locals, and memory.
    ///
    /// The `immediate` parameter carries the raw 64-bit immediate for opcodes
    /// that embed a constant (e.g. `I32Const`) when calling this through a
    /// generic dispatch layer; for the typed `WasmOpcode` enum the immediate
    /// is already embedded in the variant.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` on stack underflow, out-of-bounds memory access,
    /// division by zero, or unimplemented opcode paths.
    pub fn execute_instruction(
        &mut self,
        op: &WasmOpcode,
        _immediate: Option<u64>,
    ) -> Result<(), CoreError> {
        match op {
            WasmOpcode::Nop | WasmOpcode::End => {}

            WasmOpcode::Unreachable => {
                return Err(CoreError::InvalidFormat {
                    message: "Wasm trap: unreachable executed".into(),
                });
            }

            WasmOpcode::Drop => {
                self.stack.pop()?;
            }

            // ── Constants ────────────────────────────────────────────────────
            WasmOpcode::I32Const(v) => self.stack.push(WasmValue::I32(*v)),
            WasmOpcode::I64Const(v) => self.stack.push(WasmValue::I64(*v)),
            WasmOpcode::F32Const(v) => self.stack.push(WasmValue::F32(*v)),
            WasmOpcode::F64Const(v) => self.stack.push(WasmValue::F64(*v)),

            // ── i32 arithmetic ───────────────────────────────────────────────
            WasmOpcode::I32Add => {
                let b = self.pop_i32()?;
                let a = self.pop_i32()?;
                self.stack.push(WasmValue::I32(a.wrapping_add(b)));
            }
            WasmOpcode::I32Sub => {
                let b = self.pop_i32()?;
                let a = self.pop_i32()?;
                self.stack.push(WasmValue::I32(a.wrapping_sub(b)));
            }
            WasmOpcode::I32Mul => {
                let b = self.pop_i32()?;
                let a = self.pop_i32()?;
                self.stack.push(WasmValue::I32(a.wrapping_mul(b)));
            }
            WasmOpcode::I32DivS => {
                let b = self.pop_i32()?;
                let a = self.pop_i32()?;
                if b == 0 {
                    return Err(CoreError::InvalidFormat {
                        message: "Wasm trap: i32.div_s by zero".into(),
                    });
                }
                self.stack.push(WasmValue::I32(a.wrapping_div(b)));
            }
            WasmOpcode::I32RemS => {
                let b = self.pop_i32()?;
                let a = self.pop_i32()?;
                if b == 0 {
                    return Err(CoreError::InvalidFormat {
                        message: "Wasm trap: i32.rem_s by zero".into(),
                    });
                }
                self.stack.push(WasmValue::I32(a.wrapping_rem(b)));
            }
            WasmOpcode::I32And => {
                let b = self.pop_i32()?;
                let a = self.pop_i32()?;
                self.stack.push(WasmValue::I32(a & b));
            }
            WasmOpcode::I32Or => {
                let b = self.pop_i32()?;
                let a = self.pop_i32()?;
                self.stack.push(WasmValue::I32(a | b));
            }
            WasmOpcode::I32Xor => {
                let b = self.pop_i32()?;
                let a = self.pop_i32()?;
                self.stack.push(WasmValue::I32(a ^ b));
            }

            // ── Memory ───────────────────────────────────────────────────────
            WasmOpcode::I32Load => {
                let addr = self.pop_i32()? as usize;
                if addr + 4 > self.memory.len() {
                    return Err(CoreError::InvalidFormat {
                        message: format!("i32.load out of bounds: addr={addr}"),
                    });
                }
                let bytes = [
                    self.memory[addr],
                    self.memory[addr + 1],
                    self.memory[addr + 2],
                    self.memory[addr + 3],
                ];
                self.stack.push(WasmValue::I32(i32::from_le_bytes(bytes)));
            }
            WasmOpcode::I32Store => {
                let val = self.pop_i32()?;
                let addr = self.pop_i32()? as usize;
                if addr + 4 > self.memory.len() {
                    return Err(CoreError::InvalidFormat {
                        message: format!("i32.store out of bounds: addr={addr}"),
                    });
                }
                let bytes = val.to_le_bytes();
                self.memory[addr..addr + 4].copy_from_slice(&bytes);
            }

            // ── Locals ───────────────────────────────────────────────────────
            WasmOpcode::LocalGet(i) => {
                let v = self
                    .locals
                    .get(*i)
                    .ok_or_else(|| CoreError::InvalidFormat {
                        message: format!("local.get: index {i} out of range"),
                    })?
                    .clone();
                self.stack.push(v);
            }
            WasmOpcode::LocalSet(i) => {
                let v = self.stack.pop()?;
                if *i >= self.locals.len() {
                    return Err(CoreError::InvalidFormat {
                        message: format!("local.set: index {i} out of range"),
                    });
                }
                self.locals[*i] = v;
            }
            WasmOpcode::LocalTee(i) => {
                let v = self.stack.peek()?.clone();
                if *i >= self.locals.len() {
                    return Err(CoreError::InvalidFormat {
                        message: format!("local.tee: index {i} out of range"),
                    });
                }
                self.locals[*i] = v;
                // value remains on stack
            }

            // ── Globals (stub — no global store in executor) ──────────────────
            WasmOpcode::GlobalGet(_) => {
                self.stack.push(WasmValue::I32(0));
            }
            WasmOpcode::GlobalSet(_) => {
                self.stack.pop()?;
            }

            // ── Control (stubs — executor does not follow branches) ───────────
            WasmOpcode::Br(_) | WasmOpcode::BrIf(_) | WasmOpcode::Return => {}
        }
        Ok(())
    }

    /// Convenience: pop a value and unwrap as `i32`.
    fn pop_i32(&mut self) -> Result<i32, CoreError> {
        match self.stack.pop()? {
            WasmValue::I32(v) => Ok(v),
            other => Err(CoreError::InvalidFormat {
                message: format!(
                    "type error: expected i32, got {:?}",
                    other.value_type().name()
                ),
            }),
        }
    }

    /// Reset the executor: clear the stack, zero locals and memory.
    pub fn reset(&mut self) {
        self.stack.drain();
        for v in &mut self.locals {
            *v = WasmValue::I32(0);
        }
        self.memory.fill(0);
    }
}

// ── WasmControlFlow ───────────────────────────────────────────────────────────

/// Utilities for structured control-flow analysis over a sequence of
/// `WasmOpcode` values.
pub struct WasmControlFlow;

impl WasmControlFlow {
    /// Find the index of the `End` opcode that closes the structured block
    /// starting at `start`.  Returns `None` when no matching `End` is found.
    ///
    /// Nesting is tracked so that nested blocks are skipped correctly.
    #[must_use]
    pub fn find_block_end(instrs: &[WasmOpcode], start: usize) -> Option<usize> {
        let mut depth = 0usize;
        for (i, op) in instrs.iter().enumerate().skip(start) {
            match op {
                WasmOpcode::End => {
                    if depth == 0 {
                        return Some(i);
                    }
                    depth -= 1;
                }
                // Any opcode that opens a new nesting level increases depth.
                WasmOpcode::I32Const(_)
                | WasmOpcode::I64Const(_)
                | WasmOpcode::F32Const(_)
                | WasmOpcode::F64Const(_) => {
                    // Immediates are not block-openers — no depth change.
                }
                _ if i > start => {
                    // Generic opcodes inside the block — no depth adjustment needed.
                }
                _ => {}
            }
        }
        None
    }

    /// Partition `instrs` into basic blocks.  Each block is a half-open range
    /// `[start, end)` of indices into `instrs`.
    ///
    /// A new basic block starts immediately after any terminator opcode
    /// (`Br`, `BrIf`, `Return`, `Unreachable`, `End`).
    #[must_use]
    pub fn extract_basic_blocks(instrs: &[WasmOpcode]) -> Vec<(usize, usize)> {
        if instrs.is_empty() {
            return vec![];
        }

        let mut leaders = vec![false; instrs.len()];
        leaders[0] = true;

        for (i, op) in instrs.iter().enumerate() {
            let is_terminator = matches!(
                op,
                WasmOpcode::Br(_)
                    | WasmOpcode::BrIf(_)
                    | WasmOpcode::Return
                    | WasmOpcode::Unreachable
                    | WasmOpcode::End
            );
            if is_terminator && i + 1 < instrs.len() {
                leaders[i + 1] = true;
            }
        }

        let mut blocks = Vec::new();
        let mut block_start = 0;
        for i in 1..instrs.len() {
            if leaders[i] {
                blocks.push((block_start, i));
                block_start = i;
            }
        }
        blocks.push((block_start, instrs.len()));
        blocks
    }
}

// ── WasmValType / FuncType ────────────────────────────────────────────────────

/// A Wasm value type as decoded from a binary type section (mirrors
/// [`WasmValueType`] but uses the shorter name conventional in Wasm specs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WasmValType {
    I32,
    I64,
    F32,
    F64,
    V128,
    FuncRef,
    ExternRef,
}

/// A decoded Wasm function type (params -> results).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncType {
    /// Parameter types in order.
    pub params: Vec<WasmValType>,
    /// Result types in order.
    pub results: Vec<WasmValType>,
}

/// Decode a Wasm value-type byte into [`WasmValType`].
///
/// Returns `None` for unknown bytes.
#[must_use]
pub const fn decode_type(byte: u8) -> Option<WasmValType> {
    Some(match byte {
        0x7F => WasmValType::I32,
        0x7E => WasmValType::I64,
        0x7D => WasmValType::F32,
        0x7C => WasmValType::F64,
        0x7B => WasmValType::V128,
        0x70 => WasmValType::FuncRef,
        0x6F => WasmValType::ExternRef,
        _ => return None,
    })
}

/// Decode a Wasm function type from a binary slice.
///
/// The slice must begin with the `0x60` function-type marker followed by
/// LEB128-encoded parameter and result type vectors.
///
/// # Errors
///
/// Returns `CoreError` when the data is truncated or contains unknown types.
pub fn decode_func_type(bytes: &[u8]) -> Result<FuncType, CoreError> {
    if bytes.is_empty() || bytes[0] != 0x60 {
        return Err(CoreError::InvalidFormat {
            message: "expected functype marker 0x60".into(),
        });
    }
    let mut pos = 1usize;

    let (param_count, n) = read_uleb128(bytes, pos)?;
    pos += n;
    let mut params = Vec::new();
    for _ in 0..param_count {
        if pos >= bytes.len() {
            return Err(CoreError::InvalidFormat {
                message: "truncated param list".into(),
            });
        }
        let vt = decode_type(bytes[pos]).ok_or_else(|| CoreError::InvalidFormat {
            message: format!("unknown valtype 0x{:02x}", bytes[pos]),
        })?;
        params.push(vt);
        pos += 1;
    }

    let (result_count, n2) = read_uleb128(bytes, pos)?;
    pos += n2;
    let mut results = Vec::new();
    for _ in 0..result_count {
        if pos >= bytes.len() {
            return Err(CoreError::InvalidFormat {
                message: "truncated result list".into(),
            });
        }
        let vt = decode_type(bytes[pos]).ok_or_else(|| CoreError::InvalidFormat {
            message: format!("unknown valtype 0x{:02x}", bytes[pos]),
        })?;
        results.push(vt);
        pos += 1;
    }

    Ok(FuncType { params, results })
}

// ── Tests for the semantic execution model ────────────────────────────────────

#[cfg(test)]
mod exec_tests {
    use super::*;

    fn exec(ops: &[WasmOpcode]) -> WasmExecutor {
        let mut e = WasmExecutor::new(64, 8);
        for op in ops {
            e.execute_instruction(op, None).unwrap();
        }
        e
    }

    #[test]
    fn test_stack_push_pop_peek() {
        let mut s = WasmStack::new();
        s.push(WasmValue::I32(42));
        assert_eq!(s.peek().unwrap(), &WasmValue::I32(42));
        assert_eq!(s.depth(), 1);
        let v = s.pop().unwrap();
        assert_eq!(v, WasmValue::I32(42));
        assert!(s.is_empty());
    }

    #[test]
    fn test_stack_underflow() {
        let mut s = WasmStack::new();
        assert!(s.pop().is_err());
        assert!(s.peek().is_err());
    }

    #[test]
    fn test_stack_drain() {
        let mut s = WasmStack::new();
        s.push(WasmValue::I32(1));
        s.push(WasmValue::I32(2));
        let drained = s.drain();
        assert_eq!(drained.len(), 2);
        assert!(s.is_empty());
    }

    #[test]
    fn test_i32_const() {
        let e = exec(&[WasmOpcode::I32Const(99)]);
        assert_eq!(e.stack.peek().unwrap(), &WasmValue::I32(99));
    }

    #[test]
    fn test_i32_add() {
        let e = exec(&[
            WasmOpcode::I32Const(10),
            WasmOpcode::I32Const(32),
            WasmOpcode::I32Add,
        ]);
        assert_eq!(e.stack.peek().unwrap(), &WasmValue::I32(42));
    }

    #[test]
    fn test_i32_sub() {
        let e = exec(&[
            WasmOpcode::I32Const(50),
            WasmOpcode::I32Const(8),
            WasmOpcode::I32Sub,
        ]);
        assert_eq!(e.stack.peek().unwrap(), &WasmValue::I32(42));
    }

    #[test]
    fn test_i32_mul() {
        let e = exec(&[
            WasmOpcode::I32Const(6),
            WasmOpcode::I32Const(7),
            WasmOpcode::I32Mul,
        ]);
        assert_eq!(e.stack.peek().unwrap(), &WasmValue::I32(42));
    }

    #[test]
    fn test_i32_div_s() {
        let e = exec(&[
            WasmOpcode::I32Const(84),
            WasmOpcode::I32Const(2),
            WasmOpcode::I32DivS,
        ]);
        assert_eq!(e.stack.peek().unwrap(), &WasmValue::I32(42));
    }

    #[test]
    fn test_i32_div_by_zero() {
        let mut e = WasmExecutor::new(0, 0);
        e.execute_instruction(&WasmOpcode::I32Const(5), None)
            .unwrap();
        e.execute_instruction(&WasmOpcode::I32Const(0), None)
            .unwrap();
        assert!(e.execute_instruction(&WasmOpcode::I32DivS, None).is_err());
    }

    #[test]
    fn test_i32_rem_s() {
        let e = exec(&[
            WasmOpcode::I32Const(10),
            WasmOpcode::I32Const(3),
            WasmOpcode::I32RemS,
        ]);
        assert_eq!(e.stack.peek().unwrap(), &WasmValue::I32(1));
    }

    #[test]
    fn test_i32_and() {
        let e = exec(&[
            WasmOpcode::I32Const(0xFF),
            WasmOpcode::I32Const(0x0F),
            WasmOpcode::I32And,
        ]);
        assert_eq!(e.stack.peek().unwrap(), &WasmValue::I32(0x0F));
    }

    #[test]
    fn test_i32_or() {
        let e = exec(&[
            WasmOpcode::I32Const(0xF0),
            WasmOpcode::I32Const(0x0F),
            WasmOpcode::I32Or,
        ]);
        assert_eq!(e.stack.peek().unwrap(), &WasmValue::I32(0xFF));
    }

    #[test]
    fn test_i32_xor() {
        let e = exec(&[
            WasmOpcode::I32Const(0xFF),
            WasmOpcode::I32Const(0xFF),
            WasmOpcode::I32Xor,
        ]);
        assert_eq!(e.stack.peek().unwrap(), &WasmValue::I32(0));
    }

    #[test]
    fn test_i32_store_and_load() {
        let mut e = WasmExecutor::new(64, 0);
        // store 0xDEAD at address 0
        e.execute_instruction(&WasmOpcode::I32Const(0), None)
            .unwrap();
        e.execute_instruction(&WasmOpcode::I32Const(0x0000_DEAD_u32 as i32), None)
            .unwrap();
        e.execute_instruction(&WasmOpcode::I32Store, None).unwrap();
        // load it back
        e.execute_instruction(&WasmOpcode::I32Const(0), None)
            .unwrap();
        e.execute_instruction(&WasmOpcode::I32Load, None).unwrap();
        assert_eq!(
            e.stack.peek().unwrap(),
            &WasmValue::I32(0x0000_DEAD_u32 as i32)
        );
    }

    #[test]
    fn test_i32_load_oob() {
        let mut e = WasmExecutor::new(4, 0);
        e.execute_instruction(&WasmOpcode::I32Const(2), None)
            .unwrap();
        assert!(e.execute_instruction(&WasmOpcode::I32Load, None).is_err());
    }

    #[test]
    fn test_local_get_set() {
        let mut e = WasmExecutor::new(0, 4);
        e.execute_instruction(&WasmOpcode::I32Const(77), None)
            .unwrap();
        e.execute_instruction(&WasmOpcode::LocalSet(2), None)
            .unwrap();
        e.execute_instruction(&WasmOpcode::LocalGet(2), None)
            .unwrap();
        assert_eq!(e.stack.peek().unwrap(), &WasmValue::I32(77));
    }

    #[test]
    fn test_local_tee() {
        let mut e = WasmExecutor::new(0, 4);
        e.execute_instruction(&WasmOpcode::I32Const(55), None)
            .unwrap();
        e.execute_instruction(&WasmOpcode::LocalTee(0), None)
            .unwrap();
        assert_eq!(e.stack.depth(), 1);
        assert_eq!(e.locals[0], WasmValue::I32(55));
    }

    #[test]
    fn test_drop() {
        let mut e = WasmExecutor::new(0, 0);
        e.execute_instruction(&WasmOpcode::I32Const(1), None)
            .unwrap();
        e.execute_instruction(&WasmOpcode::Drop, None).unwrap();
        assert!(e.stack.is_empty());
    }

    #[test]
    fn test_nop_and_end() {
        let e = exec(&[WasmOpcode::Nop, WasmOpcode::End]);
        assert!(e.stack.is_empty());
    }

    #[test]
    fn test_unreachable_traps() {
        let mut e = WasmExecutor::new(0, 0);
        assert!(
            e.execute_instruction(&WasmOpcode::Unreachable, None)
                .is_err()
        );
    }

    #[test]
    fn test_reset() {
        let mut e = exec(&[WasmOpcode::I32Const(1), WasmOpcode::LocalSet(0)]);
        e.reset();
        assert!(e.stack.is_empty());
        assert_eq!(e.locals[0], WasmValue::I32(0));
    }

    #[test]
    fn test_wasm_value_types() {
        assert_eq!(WasmValue::I32(0).value_type(), WasmValueType::I32);
        assert_eq!(WasmValue::I64(0).value_type(), WasmValueType::I64);
        assert_eq!(WasmValue::F32(0.0).value_type(), WasmValueType::F32);
        assert_eq!(WasmValue::F64(0.0).value_type(), WasmValueType::F64);
        assert_eq!(WasmValue::V128([0u8; 16]).value_type(), WasmValueType::V128);
    }

    #[test]
    fn test_wasm_value_unwrap_helpers() {
        assert_eq!(WasmValue::I32(7).as_i32(), Some(7));
        assert_eq!(WasmValue::I32(7).as_i64(), None);
        assert_eq!(WasmValue::F32(1.0).as_f32(), Some(1.0));
        let v = [0xFFu8; 16];
        assert_eq!(WasmValue::V128(v).as_v128(), Some(&v));
    }

    #[test]
    fn test_extract_basic_blocks_empty() {
        assert!(WasmControlFlow::extract_basic_blocks(&[]).is_empty());
    }

    #[test]
    fn test_extract_basic_blocks_simple() {
        let ops = vec![
            WasmOpcode::I32Const(0),
            WasmOpcode::BrIf(0),
            WasmOpcode::I32Const(1),
            WasmOpcode::Return,
        ];
        let blocks = WasmControlFlow::extract_basic_blocks(&ops);
        assert!(blocks.len() >= 2);
        assert_eq!(blocks[0].0, 0);
    }

    #[test]
    fn test_find_block_end_flat() {
        let ops = vec![WasmOpcode::Nop, WasmOpcode::Nop, WasmOpcode::End];
        assert_eq!(WasmControlFlow::find_block_end(&ops, 0), Some(2));
    }

    #[test]
    fn test_decode_type_all() {
        assert_eq!(decode_type(0x7F), Some(WasmValType::I32));
        assert_eq!(decode_type(0x7E), Some(WasmValType::I64));
        assert_eq!(decode_type(0x7D), Some(WasmValType::F32));
        assert_eq!(decode_type(0x7C), Some(WasmValType::F64));
        assert_eq!(decode_type(0x7B), Some(WasmValType::V128));
        assert_eq!(decode_type(0x70), Some(WasmValType::FuncRef));
        assert_eq!(decode_type(0x6F), Some(WasmValType::ExternRef));
        assert_eq!(decode_type(0x00), None);
    }

    #[test]
    fn test_decode_func_type_two_params_one_result() {
        let bytes = [0x60u8, 0x02, 0x7F, 0x7F, 0x01, 0x7F];
        let ft = decode_func_type(&bytes).unwrap();
        assert_eq!(ft.params.len(), 2);
        assert_eq!(ft.results.len(), 1);
        assert_eq!(ft.params[0], WasmValType::I32);
        assert_eq!(ft.results[0], WasmValType::I32);
    }

    #[test]
    fn test_decode_func_type_no_params() {
        let bytes = [0x60u8, 0x00, 0x01, 0x7E];
        let ft = decode_func_type(&bytes).unwrap();
        assert!(ft.params.is_empty());
        assert_eq!(ft.results[0], WasmValType::I64);
    }

    #[test]
    fn test_decode_func_type_invalid_marker() {
        assert!(decode_func_type(&[0x61, 0x00, 0x00]).is_err());
    }

    #[test]
    fn test_wrapping_add_overflow() {
        let e = exec(&[
            WasmOpcode::I32Const(i32::MAX),
            WasmOpcode::I32Const(1),
            WasmOpcode::I32Add,
        ]);
        assert_eq!(e.stack.peek().unwrap(), &WasmValue::I32(i32::MIN));
    }

    #[test]
    fn test_global_stubs() {
        let mut e = WasmExecutor::new(0, 0);
        e.execute_instruction(&WasmOpcode::GlobalGet(0), None)
            .unwrap();
        assert_eq!(e.stack.depth(), 1);
        e.execute_instruction(&WasmOpcode::GlobalSet(0), None)
            .unwrap();
        assert!(e.stack.is_empty());
    }

    #[test]
    fn test_f32_const() {
        let e = exec(&[WasmOpcode::F32Const(3.14_f32)]);
        if let WasmValue::F32(v) = e.stack.peek().unwrap() {
            assert!((v - 3.14_f32).abs() < 1e-5);
        } else {
            panic!("expected F32");
        }
    }

    #[test]
    fn test_f64_const() {
        let e = exec(&[WasmOpcode::F64Const(2.718_281_828_f64)]);
        if let WasmValue::F64(v) = e.stack.peek().unwrap() {
            assert!((v - 2.718_281_828_f64).abs() < 1e-10);
        } else {
            panic!("expected F64");
        }
    }

    #[test]
    fn test_executor_new_sizes() {
        let e = WasmExecutor::new(1024, 16);
        assert_eq!(e.memory.len(), 1024);
        assert_eq!(e.locals.len(), 16);
    }

    #[test]
    fn test_i64_const() {
        let e = exec(&[WasmOpcode::I64Const(i64::MAX)]);
        assert_eq!(e.stack.peek().unwrap(), &WasmValue::I64(i64::MAX));
    }

    #[test]
    fn test_local_set_oob() {
        let mut e = WasmExecutor::new(0, 2);
        e.execute_instruction(&WasmOpcode::I32Const(0), None)
            .unwrap();
        assert!(
            e.execute_instruction(&WasmOpcode::LocalSet(99), None)
                .is_err()
        );
    }

    #[test]
    fn test_local_get_oob() {
        let mut e = WasmExecutor::new(0, 2);
        assert!(
            e.execute_instruction(&WasmOpcode::LocalGet(99), None)
                .is_err()
        );
    }
}

/// Crate-internal re-export of `decode_wasm` for use in `wasm_decompiler`.
pub(crate) fn decode_wasm_reexport(
    bytes: &[u8],
) -> Result<(String, String, usize, InstrFlags), CoreError> {
    decode_wasm(bytes)
}
