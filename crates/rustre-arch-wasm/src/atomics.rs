//! `atomics` — WASM Threads / Atomics proposal decoder.
//!
//! All atomic instructions are encoded with a `0xFE` prefix byte followed by a
//! LEB128 sub-opcode.  This module decodes the complete set of atomic
//! instructions defined in the WebAssembly Threads proposal:
//!
//! * `memory.atomic.notify` / `memory.atomic.wait32` / `memory.atomic.wait64`
//! * Atomic loads: `i32.atomic.load`, `i64.atomic.load`, and sign-extended
//!   variants.
//! * Atomic stores: `i32.atomic.store`, `i64.atomic.store`, and truncated
//!   variants.
//! * Atomic read-modify-write (RMW): `add`, `sub`, `and`, `or`, `xor`,
//!   `xchg` for both `i32` and `i64`.
//! * `atomic.fence` (sub-opcode `0x03`).
//! * Compare-exchange: `i32.atomic.rmw.cmpxchg`, `i64.atomic.rmw.cmpxchg`.
//!
//! # Memory ordering model
//!
//! WASM atomics always use sequential consistency (`seq_cst`).  The
//! [`MemoryOrder`] enum documents this, though only `SeqCst` is ever emitted.

use rustre_core::arch::InstrFlags;
use rustre_core::errors::CoreError;

use crate::read_uleb128;

// ─── MemoryOrder ─────────────────────────────────────────────────────────────

/// WASM Threads memory ordering.
///
/// The WASM Threads spec mandates sequential consistency for all atomic
/// operations.  This enum exists to document the model and allow future
/// extension if a relaxed-atomics proposal is ever ratified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryOrder {
    /// Sequential consistency — the only order currently required by the spec.
    SeqCst,
}

impl MemoryOrder {
    /// Return the text name of this ordering.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SeqCst => "seq_cst",
        }
    }
}

impl std::fmt::Display for MemoryOrder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─── AtomicOp ────────────────────────────────────────────────────────────────

/// Kind of atomic read-modify-write operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AtomicOp {
    /// Atomic addition.
    Add,
    /// Atomic subtraction.
    Sub,
    /// Atomic bitwise AND.
    And,
    /// Atomic bitwise OR.
    Or,
    /// Atomic bitwise XOR.
    Xor,
    /// Atomic exchange.
    Xchg,
    /// Atomic compare-and-swap.
    CmpXchg,
}

impl AtomicOp {
    /// Return the instruction suffix for this operation.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Sub => "sub",
            Self::And => "and",
            Self::Or => "or",
            Self::Xor => "xor",
            Self::Xchg => "xchg",
            Self::CmpXchg => "cmpxchg",
        }
    }
}

// ─── AtomicInstr ─────────────────────────────────────────────────────────────

/// A decoded atomic instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicInstr {
    /// Full mnemonic string, e.g. `"i32.atomic.rmw.add"`.
    pub mnemonic: String,
    /// Operand string, e.g. `"align=2 offset=0"`.
    pub operands: String,
    /// Total encoded size (including the leading `0xFE` prefix byte).
    pub size: usize,
    /// Memory ordering.
    pub order: MemoryOrder,
    /// `true` if this is a memory-fence instruction (no memarg).
    pub is_fence: bool,
}

impl AtomicInstr {
    /// Construct an `AtomicInstr`.
    #[must_use]
    pub fn new(
        mnemonic: impl Into<String>,
        operands: impl Into<String>,
        size: usize,
        is_fence: bool,
    ) -> Self {
        Self {
            mnemonic: mnemonic.into(),
            operands: operands.into(),
            size,
            order: MemoryOrder::SeqCst,
            is_fence,
        }
    }
}

impl std::fmt::Display for AtomicInstr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.operands.is_empty() {
            write!(f, "{}", self.mnemonic)
        } else {
            write!(f, "{} {}", self.mnemonic, self.operands)
        }
    }
}

// ─── decode_atomics ──────────────────────────────────────────────────────────

/// Decode a `0xFE`-prefixed WASM atomic instruction.
///
/// `full_bytes` must start with `0xFE`.
///
/// Returns `(mnemonic, operands, total_bytes_consumed, flags)`.
///
/// # Errors
///
/// Returns [`CoreError::InvalidFormat`] for truncated input or unknown
/// sub-opcodes.
pub fn decode_atomics(full_bytes: &[u8]) -> Result<(String, String, usize, InstrFlags), CoreError> {
    if full_bytes.len() < 2 {
        return Err(CoreError::InvalidFormat {
            message: "truncated atomic instruction".into(),
        });
    }

    let (sub, n) = read_uleb128(full_bytes, 1)?;
    let mut pos = 1 + n;

    /// Read a memarg (align + offset) from `full_bytes` at `pos`.
    macro_rules! memarg {
        () => {{
            let (align, n1) = read_uleb128(full_bytes, pos)?;
            let (offset, n2) = read_uleb128(full_bytes, pos + n1)?;
            pos += n1 + n2;
            format!("align={align} offset={offset}")
        }};
    }

    let (mnemonic, operands, flags): (&str, String, InstrFlags) = match sub {
        // Notify / Wait
        0x00 => (
            "memory.atomic.notify",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x01 => (
            "memory.atomic.wait32",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x02 => (
            "memory.atomic.wait64",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),

        // Fence
        0x03 => {
            // atomic.fence has a reserved byte (must be 0x00) but no memarg.
            if pos >= full_bytes.len() {
                return Err(CoreError::InvalidFormat {
                    message: "truncated atomic.fence".into(),
                });
            }
            pos += 1; // skip the reserved byte
            ("atomic.fence", String::new(), InstrFlags::NONE)
        }

        // ── Atomic loads ─────────────────────────────────────────────────────
        0x10 => (
            "i32.atomic.load",
            memarg!(),
            InstrFlags::READ_MEM,
        ),
        0x11 => (
            "i64.atomic.load",
            memarg!(),
            InstrFlags::READ_MEM,
        ),
        0x12 => (
            "i32.atomic.load8_u",
            memarg!(),
            InstrFlags::READ_MEM,
        ),
        0x13 => (
            "i32.atomic.load16_u",
            memarg!(),
            InstrFlags::READ_MEM,
        ),
        0x14 => (
            "i64.atomic.load8_u",
            memarg!(),
            InstrFlags::READ_MEM,
        ),
        0x15 => (
            "i64.atomic.load16_u",
            memarg!(),
            InstrFlags::READ_MEM,
        ),
        0x16 => (
            "i64.atomic.load32_u",
            memarg!(),
            InstrFlags::READ_MEM,
        ),

        // ── Atomic stores ────────────────────────────────────────────────────
        0x17 => (
            "i32.atomic.store",
            memarg!(),
            InstrFlags::WRITE_MEM,
        ),
        0x18 => (
            "i64.atomic.store",
            memarg!(),
            InstrFlags::WRITE_MEM,
        ),
        0x19 => (
            "i32.atomic.store8",
            memarg!(),
            InstrFlags::WRITE_MEM,
        ),
        0x1a => (
            "i32.atomic.store16",
            memarg!(),
            InstrFlags::WRITE_MEM,
        ),
        0x1b => (
            "i64.atomic.store8",
            memarg!(),
            InstrFlags::WRITE_MEM,
        ),
        0x1c => (
            "i64.atomic.store16",
            memarg!(),
            InstrFlags::WRITE_MEM,
        ),
        0x1d => (
            "i64.atomic.store32",
            memarg!(),
            InstrFlags::WRITE_MEM,
        ),

        // ── i32 RMW ops ──────────────────────────────────────────────────────
        0x1e => (
            "i32.atomic.rmw.add",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x1f => (
            "i64.atomic.rmw.add",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x20 => (
            "i32.atomic.rmw8.add_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x21 => (
            "i32.atomic.rmw16.add_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x22 => (
            "i64.atomic.rmw8.add_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x23 => (
            "i64.atomic.rmw16.add_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x24 => (
            "i64.atomic.rmw32.add_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),

        // ── sub ──────────────────────────────────────────────────────────────
        0x25 => (
            "i32.atomic.rmw.sub",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x26 => (
            "i64.atomic.rmw.sub",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x27 => (
            "i32.atomic.rmw8.sub_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x28 => (
            "i32.atomic.rmw16.sub_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x29 => (
            "i64.atomic.rmw8.sub_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x2a => (
            "i64.atomic.rmw16.sub_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x2b => (
            "i64.atomic.rmw32.sub_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),

        // ── and ──────────────────────────────────────────────────────────────
        0x2c => (
            "i32.atomic.rmw.and",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x2d => (
            "i64.atomic.rmw.and",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x2e => (
            "i32.atomic.rmw8.and_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x2f => (
            "i32.atomic.rmw16.and_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x30 => (
            "i64.atomic.rmw8.and_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x31 => (
            "i64.atomic.rmw16.and_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x32 => (
            "i64.atomic.rmw32.and_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),

        // ── or ───────────────────────────────────────────────────────────────
        0x33 => (
            "i32.atomic.rmw.or",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x34 => (
            "i64.atomic.rmw.or",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x35 => (
            "i32.atomic.rmw8.or_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x36 => (
            "i32.atomic.rmw16.or_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x37 => (
            "i64.atomic.rmw8.or_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x38 => (
            "i64.atomic.rmw16.or_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x39 => (
            "i64.atomic.rmw32.or_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),

        // ── xor ──────────────────────────────────────────────────────────────
        0x3a => (
            "i32.atomic.rmw.xor",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x3b => (
            "i64.atomic.rmw.xor",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x3c => (
            "i32.atomic.rmw8.xor_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x3d => (
            "i32.atomic.rmw16.xor_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x3e => (
            "i64.atomic.rmw8.xor_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x3f => (
            "i64.atomic.rmw16.xor_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x40 => (
            "i64.atomic.rmw32.xor_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),

        // ── xchg ─────────────────────────────────────────────────────────────
        0x41 => (
            "i32.atomic.rmw.xchg",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x42 => (
            "i64.atomic.rmw.xchg",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x43 => (
            "i32.atomic.rmw8.xchg_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x44 => (
            "i32.atomic.rmw16.xchg_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x45 => (
            "i64.atomic.rmw8.xchg_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x46 => (
            "i64.atomic.rmw16.xchg_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x47 => (
            "i64.atomic.rmw32.xchg_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),

        // ── cmpxchg ──────────────────────────────────────────────────────────
        0x48 => (
            "i32.atomic.rmw.cmpxchg",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x49 => (
            "i64.atomic.rmw.cmpxchg",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x4a => (
            "i32.atomic.rmw8.cmpxchg_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x4b => (
            "i32.atomic.rmw16.cmpxchg_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x4c => (
            "i64.atomic.rmw8.cmpxchg_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x4d => (
            "i64.atomic.rmw16.cmpxchg_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),
        0x4e => (
            "i64.atomic.rmw32.cmpxchg_u",
            memarg!(),
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        ),

        other => {
            return Err(CoreError::InvalidFormat {
                message: format!("unknown atomic sub-opcode 0x{other:02x}"),
            });
        }
    };

    Ok((mnemonic.to_string(), operands, pos, flags))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn atomic_instr(bytes: &[u8]) -> (String, String, usize, InstrFlags) {
        let mut v = vec![0xFEu8];
        v.extend_from_slice(bytes);
        decode_atomics(&v).unwrap()
    }

    fn atomic_instr_err(bytes: &[u8]) -> CoreError {
        let mut v = vec![0xFEu8];
        v.extend_from_slice(bytes);
        decode_atomics(&v).unwrap_err()
    }

    // ── MemoryOrder ─────────────────────────────────────────────────────────

    #[test]
    fn test_memory_order_name() {
        assert_eq!(MemoryOrder::SeqCst.name(), "seq_cst");
    }

    #[test]
    fn test_memory_order_display() {
        assert_eq!(MemoryOrder::SeqCst.to_string(), "seq_cst");
    }

    // ── AtomicOp ────────────────────────────────────────────────────────────

    #[test]
    fn test_atomic_op_suffixes() {
        assert_eq!(AtomicOp::Add.suffix(), "add");
        assert_eq!(AtomicOp::CmpXchg.suffix(), "cmpxchg");
        assert_eq!(AtomicOp::Xchg.suffix(), "xchg");
    }

    // ── AtomicInstr ─────────────────────────────────────────────────────────

    #[test]
    fn test_atomic_instr_display_with_ops() {
        let instr = AtomicInstr::new("i32.atomic.load", "align=2 offset=0", 4, false);
        assert_eq!(instr.to_string(), "i32.atomic.load align=2 offset=0");
    }

    #[test]
    fn test_atomic_instr_display_fence() {
        let instr = AtomicInstr::new("atomic.fence", "", 3, true);
        assert_eq!(instr.to_string(), "atomic.fence");
    }

    // ── Notify / Wait ───────────────────────────────────────────────────────

    #[test]
    fn test_memory_atomic_notify() {
        let (m, ops, size, flags) = atomic_instr(&[0x00, 0x02, 0x00]);
        assert_eq!(m, "memory.atomic.notify");
        assert!(ops.contains("align=2"));
        assert_eq!(size, 4); // 1(prefix) + 1(sub) + 1(align) + 1(offset)
        assert!(flags.contains(InstrFlags::READ_MEM));
        assert!(flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_memory_atomic_wait32() {
        let (m, _, _, _) = atomic_instr(&[0x01, 0x02, 0x00]);
        assert_eq!(m, "memory.atomic.wait32");
    }

    #[test]
    fn test_memory_atomic_wait64() {
        let (m, _, _, _) = atomic_instr(&[0x02, 0x02, 0x00]);
        assert_eq!(m, "memory.atomic.wait64");
    }

    // ── Fence ───────────────────────────────────────────────────────────────

    #[test]
    fn test_atomic_fence() {
        let (m, ops, size, flags) = atomic_instr(&[0x03, 0x00]); // sub=3 + reserved byte
        assert_eq!(m, "atomic.fence");
        assert!(ops.is_empty());
        assert_eq!(size, 3); // 1(0xFE) + 1(sub) + 1(reserved)
        assert_eq!(flags, InstrFlags::NONE);
    }

    // ── Loads ───────────────────────────────────────────────────────────────

    #[test]
    fn test_i32_atomic_load() {
        let (m, _, _, flags) = atomic_instr(&[0x10, 0x02, 0x00]);
        assert_eq!(m, "i32.atomic.load");
        assert!(flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_i64_atomic_load() {
        let (m, _, _, flags) = atomic_instr(&[0x11, 0x02, 0x00]);
        assert_eq!(m, "i64.atomic.load");
        assert!(flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_i32_atomic_load8_u() {
        let (m, _, _, _) = atomic_instr(&[0x12, 0x00, 0x00]);
        assert_eq!(m, "i32.atomic.load8_u");
    }

    #[test]
    fn test_i64_atomic_load32_u() {
        let (m, _, _, _) = atomic_instr(&[0x16, 0x02, 0x00]);
        assert_eq!(m, "i64.atomic.load32_u");
    }

    // ── Stores ──────────────────────────────────────────────────────────────

    #[test]
    fn test_i32_atomic_store() {
        let (m, _, _, flags) = atomic_instr(&[0x17, 0x02, 0x00]);
        assert_eq!(m, "i32.atomic.store");
        assert!(flags.contains(InstrFlags::WRITE_MEM));
        assert!(!flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_i64_atomic_store32() {
        let (m, _, _, _) = atomic_instr(&[0x1d, 0x02, 0x00]);
        assert_eq!(m, "i64.atomic.store32");
    }

    // ── RMW ops ─────────────────────────────────────────────────────────────

    #[test]
    fn test_i32_atomic_rmw_add() {
        let (m, ops, _, flags) = atomic_instr(&[0x1e, 0x02, 0x00]);
        assert_eq!(m, "i32.atomic.rmw.add");
        assert!(ops.contains("align=2"));
        assert!(flags.contains(InstrFlags::READ_MEM | InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_i64_atomic_rmw_sub() {
        let (m, _, _, _) = atomic_instr(&[0x26, 0x02, 0x00]);
        assert_eq!(m, "i64.atomic.rmw.sub");
    }

    #[test]
    fn test_i32_atomic_rmw_and() {
        let (m, _, _, _) = atomic_instr(&[0x2c, 0x02, 0x00]);
        assert_eq!(m, "i32.atomic.rmw.and");
    }

    #[test]
    fn test_i64_atomic_rmw_or() {
        let (m, _, _, _) = atomic_instr(&[0x34, 0x02, 0x00]);
        assert_eq!(m, "i64.atomic.rmw.or");
    }

    #[test]
    fn test_i32_atomic_rmw_xor() {
        let (m, _, _, _) = atomic_instr(&[0x3a, 0x02, 0x00]);
        assert_eq!(m, "i32.atomic.rmw.xor");
    }

    #[test]
    fn test_i32_atomic_rmw_xchg() {
        let (m, _, _, _) = atomic_instr(&[0x41, 0x02, 0x00]);
        assert_eq!(m, "i32.atomic.rmw.xchg");
    }

    #[test]
    fn test_i64_atomic_rmw_xchg() {
        let (m, _, _, _) = atomic_instr(&[0x42, 0x02, 0x00]);
        assert_eq!(m, "i64.atomic.rmw.xchg");
    }

    // ── CmpXchg ─────────────────────────────────────────────────────────────

    #[test]
    fn test_i32_atomic_rmw_cmpxchg() {
        let (m, _, _, flags) = atomic_instr(&[0x48, 0x02, 0x00]);
        assert_eq!(m, "i32.atomic.rmw.cmpxchg");
        assert!(flags.contains(InstrFlags::READ_MEM | InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_i64_atomic_rmw_cmpxchg() {
        let (m, _, _, _) = atomic_instr(&[0x49, 0x02, 0x00]);
        assert_eq!(m, "i64.atomic.rmw.cmpxchg");
    }

    #[test]
    fn test_i64_atomic_rmw32_cmpxchg_u() {
        let (m, _, _, _) = atomic_instr(&[0x4e, 0x02, 0x00]);
        assert_eq!(m, "i64.atomic.rmw32.cmpxchg_u");
    }

    // ── Error paths ─────────────────────────────────────────────────────────

    #[test]
    fn test_unknown_sub_opcode() {
        let err = atomic_instr_err(&[0xFF, 0x02, 0x00]);
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn test_truncated_instruction() {
        let v = vec![0xFEu8];
        // Empty: no sub-opcode at all.
        let result = crate::decode_fe_prefix(&v);
        assert!(result.is_err());
    }

    // ── RMW narrow variants ─────────────────────────────────────────────────

    #[test]
    fn test_i32_atomic_rmw8_add_u() {
        let (m, _, _, _) = atomic_instr(&[0x20, 0x00, 0x00]);
        assert_eq!(m, "i32.atomic.rmw8.add_u");
    }

    #[test]
    fn test_i64_atomic_rmw32_xor_u() {
        let (m, _, _, _) = atomic_instr(&[0x40, 0x02, 0x00]);
        assert_eq!(m, "i64.atomic.rmw32.xor_u");
    }

    #[test]
    fn test_i32_atomic_rmw16_sub_u() {
        let (m, _, _, _) = atomic_instr(&[0x28, 0x01, 0x00]);
        assert_eq!(m, "i32.atomic.rmw16.sub_u");
    }
}
