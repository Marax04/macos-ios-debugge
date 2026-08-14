//! MOS 6502 addressing mode decoder and effective-address calculator — **high-level layer**.
//!
//! This module provides a clean, self-contained type system for the 6502 family
//! addressing modes, covering NMOS 6502, WDC 65C02, and WDC 65816 (where noted).
//! It builds on the `AddrMode` enum already defined in the crate root but adds:
//!
//! * `Mos6502AddressMode` – a rich enum whose variants carry operand bytes,
//!   making it self-describing.
//! * `EffectiveAddress` – the resolved address (or immediate value) after
//!   applying index registers and indirection.
//! * `cycles_for_mode()` – authoritative base cycle counts per mode/opcode.
//!
//! **Intentionally distinct from [`crate::mos6502_addressing_modes`]**, which
//! is the low-level layer: string-keyed `AddressingModeInfo` metadata, raw
//! effective-address helpers that accept plain `&[u8]` memory slices, and the
//! `Mos6502MemoryModel` 64 KB address space.

use crate::AddrMode;

// ── Error type ────────────────────────────────────────────────────────────────

/// Error returned when decoding an addressing mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressModeError {
    /// The byte slice was too short to hold the required operand bytes.
    InsufficientBytes {
        /// How many bytes were needed.
        needed: usize,
        /// How many bytes were available.
        available: usize,
    },
    /// The opcode byte is not assigned to any known addressing mode.
    UnknownOpcode(u8),
}

impl std::fmt::Display for AddressModeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientBytes { needed, available } => write!(
                f,
                "need {needed} bytes for operand, only {available} available"
            ),
            Self::UnknownOpcode(b) => write!(f, "no addressing mode for opcode 0x{b:02X}"),
        }
    }
}

impl std::error::Error for AddressModeError {}

// ── Mos6502AddressMode ────────────────────────────────────────────────────────

/// A self-describing 6502 addressing mode that includes the raw operand bytes.
///
/// Unlike the lightweight [`AddrMode`] enum (which is just a tag), this type
/// carries the actual operand value decoded from the instruction stream,
/// allowing downstream code to compute effective addresses without re-reading
/// the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Mos6502AddressMode {
    /// No operand (e.g. `NOP`, `CLC`, register transfers).
    Implied,
    /// Operates on the accumulator (e.g. `ASL A`).
    Accumulator,
    /// 8-bit literal value in the instruction stream.
    Immediate(u8),
    /// 8-bit zero-page address.
    ZeroPage(u8),
    /// 8-bit zero-page address indexed by X (wraps within page 0).
    ZeroPageX(u8),
    /// 8-bit zero-page address indexed by Y (wraps within page 0).
    ZeroPageY(u8),
    /// 16-bit absolute address.
    Absolute(u16),
    /// 16-bit absolute address indexed by X.
    AbsoluteX(u16),
    /// 16-bit absolute address indexed by Y.
    AbsoluteY(u16),
    /// Indirect – the 16-bit address contains a pointer (JMP only on NMOS).
    Indirect(u16),
    /// Pre-indexed indirect: `(zp,X)` – zero-page address + X → pointer.
    IndirectX(u8),
    /// Post-indexed indirect: `(zp),Y` – pointer at zero-page addr, then +Y.
    IndirectY(u8),
    /// PC-relative signed offset (branch instructions).
    Relative(i8),
    /// 65C02: zero-page indirect `(zp)`.
    ZeroPageIndirect(u8),
    /// 65C02/65816: `(abs,X)` – absolute address + X → pointer (JMP/JSR).
    AbsoluteIndirectX(u16),
    /// 65816: 16-bit signed PC-relative offset (long branch).
    RelativeLong(i16),
    /// Illegal/undocumented opcode – no standard operand decoding.
    Illegal,
}

impl Mos6502AddressMode {
    /// Decode the addressing mode for `opcode_byte` from `bytes`.
    ///
    /// `bytes` must begin with the opcode byte itself; operand bytes follow.
    ///
    /// # Errors
    /// Returns [`AddressModeError::InsufficientBytes`] if `bytes` is too short
    /// or [`AddressModeError::UnknownOpcode`] if the opcode is undefined.
    pub fn decode(bytes: &[u8]) -> Result<Self, AddressModeError> {
        if bytes.is_empty() {
            return Err(AddressModeError::InsufficientBytes {
                needed: 1,
                available: 0,
            });
        }
        let opcode = bytes[0];
        let mode = crate::opcode_table(opcode)
            .ok_or(AddressModeError::UnknownOpcode(opcode))?
            .mode;
        Self::from_mode_and_bytes(mode, bytes)
    }

    /// Construct from a known [`AddrMode`] tag and a raw byte slice (opcode first).
    ///
    /// # Errors
    /// Returns [`AddressModeError::InsufficientBytes`] when bytes are too short.
    pub fn from_mode_and_bytes(
        mode: AddrMode,
        bytes: &[u8],
    ) -> Result<Self, AddressModeError> {
        let need = 1 + usize::from(mode.extra_bytes());
        if bytes.len() < need {
            return Err(AddressModeError::InsufficientBytes {
                needed: need,
                available: bytes.len(),
            });
        }
        let b1 = if bytes.len() > 1 { bytes[1] } else { 0 };
        let b2 = if bytes.len() > 2 { bytes[2] } else { 0 };
        let ok = match mode {
            AddrMode::Implied => Self::Implied,
            AddrMode::Accumulator => Self::Accumulator,
            AddrMode::Immediate => Self::Immediate(b1),
            AddrMode::ZeroPage => Self::ZeroPage(b1),
            AddrMode::ZeroPageX => Self::ZeroPageX(b1),
            AddrMode::ZeroPageY => Self::ZeroPageY(b1),
            AddrMode::Absolute => Self::Absolute(u16::from_le_bytes([b1, b2])),
            AddrMode::AbsoluteX => Self::AbsoluteX(u16::from_le_bytes([b1, b2])),
            AddrMode::AbsoluteY => Self::AbsoluteY(u16::from_le_bytes([b1, b2])),
            AddrMode::Indirect => Self::Indirect(u16::from_le_bytes([b1, b2])),
            AddrMode::IndirectX => Self::IndirectX(b1),
            AddrMode::IndirectY => Self::IndirectY(b1),
            AddrMode::Relative => Self::Relative(b1 as i8),
            AddrMode::ZeroPageIndirect => Self::ZeroPageIndirect(b1),
            AddrMode::AbsoluteIndirectX => Self::AbsoluteIndirectX(u16::from_le_bytes([b1, b2])),
            AddrMode::RelativeLong => Self::RelativeLong(i16::from_le_bytes([b1, b2])),
            AddrMode::Illegal => Self::Illegal,
        };
        Ok(ok)
    }

    /// Return the corresponding lightweight [`AddrMode`] tag.
    #[must_use]
    pub const fn tag(self) -> AddrMode {
        match self {
            Self::Implied => AddrMode::Implied,
            Self::Accumulator => AddrMode::Accumulator,
            Self::Immediate(_) => AddrMode::Immediate,
            Self::ZeroPage(_) => AddrMode::ZeroPage,
            Self::ZeroPageX(_) => AddrMode::ZeroPageX,
            Self::ZeroPageY(_) => AddrMode::ZeroPageY,
            Self::Absolute(_) => AddrMode::Absolute,
            Self::AbsoluteX(_) => AddrMode::AbsoluteX,
            Self::AbsoluteY(_) => AddrMode::AbsoluteY,
            Self::Indirect(_) => AddrMode::Indirect,
            Self::IndirectX(_) => AddrMode::IndirectX,
            Self::IndirectY(_) => AddrMode::IndirectY,
            Self::Relative(_) => AddrMode::Relative,
            Self::ZeroPageIndirect(_) => AddrMode::ZeroPageIndirect,
            Self::AbsoluteIndirectX(_) => AddrMode::AbsoluteIndirectX,
            Self::RelativeLong(_) => AddrMode::RelativeLong,
            Self::Illegal => AddrMode::Illegal,
        }
    }

    /// Number of operand bytes (not counting the opcode).
    #[must_use]
    pub const fn operand_bytes(self) -> u8 {
        self.tag().extra_bytes() as u8
    }

    /// Total instruction length in bytes (opcode + operands).
    #[must_use]
    pub const fn instruction_len(self) -> u8 {
        1 + self.operand_bytes()
    }

    /// Return `true` for modes that access memory (read or write).
    #[must_use]
    pub const fn accesses_memory(self) -> bool {
        !matches!(
            self,
            Self::Implied | Self::Accumulator | Self::Immediate(_) | Self::Relative(_)
                | Self::RelativeLong(_) | Self::Illegal
        )
    }

    /// Return `true` for modes that use index register X.
    #[must_use]
    pub const fn uses_x(self) -> bool {
        matches!(
            self,
            Self::ZeroPageX(_)
                | Self::AbsoluteX(_)
                | Self::IndirectX(_)
                | Self::AbsoluteIndirectX(_)
        )
    }

    /// Return `true` for modes that use index register Y.
    #[must_use]
    pub const fn uses_y(self) -> bool {
        matches!(self, Self::ZeroPageY(_) | Self::AbsoluteY(_) | Self::IndirectY(_))
    }

    /// Human-readable name for this mode variant.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.tag().name()
    }
}

// ── EffectiveAddress ──────────────────────────────────────────────────────────

/// The resolved operand after all addressing-mode arithmetic has been applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EffectiveAddress {
    /// No memory access; the instruction operates on registers only.
    None,
    /// An 8-bit literal value (Immediate mode).
    Immediate(u8),
    /// A 16-bit absolute address in the 6502 memory space.
    Memory(u16),
    /// A PC-relative branch target (already resolved to an absolute address).
    BranchTarget(u16),
}

impl EffectiveAddress {
    /// Return the memory address, if this is a `Memory` variant.
    #[must_use]
    pub const fn as_memory(self) -> Option<u16> {
        match self {
            Self::Memory(a) => Some(a),
            _ => None,
        }
    }

    /// Return the branch target address, if any.
    #[must_use]
    pub const fn as_branch_target(self) -> Option<u16> {
        match self {
            Self::BranchTarget(a) => Some(a),
            _ => None,
        }
    }

    /// Return `true` if this effective address is a zero-page address (< 0x0100).
    #[must_use]
    pub const fn is_zero_page(self) -> bool {
        match self {
            Self::Memory(a) => a < 0x0100,
            _ => false,
        }
    }
}

/// Resolve the effective address for a decoded addressing mode.
///
/// `pc` is the address of the *opcode* byte. For branch instructions the target
/// is computed as `pc + instr_len + offset`, which matches real 6502 behaviour.
///
/// Memory indirection (Indirect / IndirectX / IndirectY) cannot be resolved
/// without reading actual memory; those modes return [`EffectiveAddress::Memory`]
/// with the *pointer address*, not the final target.  Callers that need the
/// dereferenced value must read from the memory model themselves.
#[must_use]
pub fn resolve_effective_address(
    mode: Mos6502AddressMode,
    pc: u16,
    x: u8,
    y: u8,
) -> EffectiveAddress {
    match mode {
        Mos6502AddressMode::Implied
        | Mos6502AddressMode::Accumulator
        | Mos6502AddressMode::Illegal => EffectiveAddress::None,

        Mos6502AddressMode::Immediate(v) => EffectiveAddress::Immediate(v),

        Mos6502AddressMode::ZeroPage(zp) => EffectiveAddress::Memory(u16::from(zp)),
        Mos6502AddressMode::ZeroPageX(zp) => {
            EffectiveAddress::Memory(u16::from(zp.wrapping_add(x)))
        }
        Mos6502AddressMode::ZeroPageY(zp) => {
            EffectiveAddress::Memory(u16::from(zp.wrapping_add(y)))
        }

        Mos6502AddressMode::Absolute(abs) => EffectiveAddress::Memory(abs),
        Mos6502AddressMode::AbsoluteX(abs) => {
            EffectiveAddress::Memory(abs.wrapping_add(u16::from(x)))
        }
        Mos6502AddressMode::AbsoluteY(abs) => {
            EffectiveAddress::Memory(abs.wrapping_add(u16::from(y)))
        }

        // For Indirect, IndirectX, ZeroPageIndirect, AbsoluteIndirectX, we
        // return the *pointer* address.  The caller must dereference.
        Mos6502AddressMode::Indirect(ptr) => EffectiveAddress::Memory(ptr),
        Mos6502AddressMode::IndirectX(zp) => {
            let ptr = u16::from(zp.wrapping_add(x));
            EffectiveAddress::Memory(ptr)
        }
        Mos6502AddressMode::IndirectY(zp) => EffectiveAddress::Memory(u16::from(zp)),
        Mos6502AddressMode::ZeroPageIndirect(zp) => EffectiveAddress::Memory(u16::from(zp)),
        Mos6502AddressMode::AbsoluteIndirectX(abs) => {
            EffectiveAddress::Memory(abs.wrapping_add(u16::from(x)))
        }

        Mos6502AddressMode::Relative(offset) => {
            // PC points at the opcode; branch target = pc + 2 + offset.
            let target = pc
                .wrapping_add(2)
                .wrapping_add(offset as i16 as u16);
            EffectiveAddress::BranchTarget(target)
        }
        Mos6502AddressMode::RelativeLong(offset) => {
            let target = pc
                .wrapping_add(3)
                .wrapping_add(offset as u16);
            EffectiveAddress::BranchTarget(target)
        }
    }
}

// ── cycles_for_mode ───────────────────────────────────────────────────────────

/// Base cycle count for a given [`AddrMode`].
///
/// These are the *base* counts; page-crossing penalties (+1 cycle for indexed
/// and indirect-Y loads that cross a page boundary) are **not** included here.
/// Callers should add 1 if `page_crossed` is `true` for the relevant modes.
#[must_use]
pub const fn cycles_for_mode(mode: AddrMode) -> u8 {
    match mode {
        AddrMode::Implied | AddrMode::Accumulator => 2,
        AddrMode::Immediate => 2,
        AddrMode::ZeroPage => 3,
        AddrMode::ZeroPageX | AddrMode::ZeroPageY => 4,
        AddrMode::Absolute => 4,
        AddrMode::AbsoluteX | AddrMode::AbsoluteY => 4, // +1 if page crossed
        AddrMode::Indirect => 5,
        AddrMode::IndirectX => 6,
        AddrMode::IndirectY => 5, // +1 if page crossed
        AddrMode::Relative => 2,  // +1 if taken, +1 more if page crossed
        AddrMode::ZeroPageIndirect => 5,
        AddrMode::AbsoluteIndirectX => 6,
        AddrMode::RelativeLong => 4,
        AddrMode::Illegal => 2,
    }
}

/// Compute cycle penalty for a page-crossing indexed access.
///
/// Returns `1` for modes that incur a page-crossing penalty
/// (`AbsoluteX`, `AbsoluteY`, `IndirectY`, `ZeroPageIndirect`), `0` otherwise.
#[must_use]
pub const fn page_cross_penalty(mode: AddrMode) -> u8 {
    match mode {
        AddrMode::AbsoluteX
        | AddrMode::AbsoluteY
        | AddrMode::IndirectY
        | AddrMode::ZeroPageIndirect => 1,
        _ => 0,
    }
}

/// Return `true` if the instruction at `pc` with the given mode crosses a page
/// boundary when indexed by `index_byte`.
#[must_use]
pub fn crosses_page(base: u16, index: u8) -> bool {
    let indexed = base.wrapping_add(u16::from(index));
    (base & 0xFF00) != (indexed & 0xFF00)
}

// ── AddressModeDecoder ────────────────────────────────────────────────────────

/// Stateless helper for decoding addressing modes from an instruction stream.
pub struct AddressModeDecoder;

impl AddressModeDecoder {
    /// Decode the addressing mode from `bytes` (opcode first).
    ///
    /// # Errors
    /// See [`AddressModeError`].
    pub fn decode(bytes: &[u8]) -> Result<Mos6502AddressMode, AddressModeError> {
        Mos6502AddressMode::decode(bytes)
    }

    /// Return the instruction length for `opcode` without constructing the full type.
    ///
    /// Returns `None` for unknown opcodes.
    #[must_use]
    pub fn instruction_len(opcode: u8) -> Option<u8> {
        crate::opcode_table(opcode)
            .filter(|e| !e.illegal)
            .map(|e| 1 + e.mode.extra_bytes() as u8)
    }

    /// Return the base cycle count for `opcode`.
    ///
    /// Returns `None` for unknown opcodes.
    #[must_use]
    pub fn cycles(opcode: u8) -> Option<u8> {
        crate::opcode_table(opcode)
            .filter(|e| !e.illegal)
            .map(|e| e.cycles)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_implied() {
        // NOP = 0xEA, implied
        let m = Mos6502AddressMode::decode(&[0xEA]).unwrap();
        assert_eq!(m, Mos6502AddressMode::Implied);
        assert_eq!(m.instruction_len(), 1);
    }

    #[test]
    fn test_decode_immediate() {
        // LDA #$42 = 0xA9 0x42
        let m = Mos6502AddressMode::decode(&[0xA9, 0x42]).unwrap();
        assert_eq!(m, Mos6502AddressMode::Immediate(0x42));
        assert_eq!(m.operand_bytes(), 1);
    }

    #[test]
    fn test_decode_absolute() {
        // LDA $1234 = 0xAD 0x34 0x12
        let m = Mos6502AddressMode::decode(&[0xAD, 0x34, 0x12]).unwrap();
        assert_eq!(m, Mos6502AddressMode::Absolute(0x1234));
        assert_eq!(m.instruction_len(), 3);
    }

    #[test]
    fn test_decode_zero_page_x() {
        // LDA $10,X = 0xB5 0x10
        let m = Mos6502AddressMode::decode(&[0xB5, 0x10]).unwrap();
        assert_eq!(m, Mos6502AddressMode::ZeroPageX(0x10));
    }

    #[test]
    fn test_decode_relative() {
        // BNE -2 = 0xD0 0xFE
        let m = Mos6502AddressMode::decode(&[0xD0, 0xFE]).unwrap();
        assert_eq!(m, Mos6502AddressMode::Relative(-2i8));
    }

    #[test]
    fn test_decode_indirect_x() {
        // LDA ($20,X) = 0xA1 0x20
        let m = Mos6502AddressMode::decode(&[0xA1, 0x20]).unwrap();
        assert_eq!(m, Mos6502AddressMode::IndirectX(0x20));
        assert!(m.uses_x());
        assert!(!m.uses_y());
    }

    #[test]
    fn test_decode_indirect_y() {
        // LDA ($30),Y = 0xB1 0x30
        let m = Mos6502AddressMode::decode(&[0xB1, 0x30]).unwrap();
        assert_eq!(m, Mos6502AddressMode::IndirectY(0x30));
        assert!(m.uses_y());
    }

    #[test]
    fn test_insufficient_bytes() {
        // LDA abs needs 3 bytes, we only provide opcode
        let err = Mos6502AddressMode::decode(&[0xAD]).unwrap_err();
        match err {
            AddressModeError::InsufficientBytes { needed, available } => {
                assert_eq!(needed, 3);
                assert_eq!(available, 1);
            }
            _ => panic!("unexpected error"),
        }
    }

    #[test]
    fn test_effective_address_implied() {
        let ea = resolve_effective_address(Mos6502AddressMode::Implied, 0x1000, 0, 0);
        assert_eq!(ea, EffectiveAddress::None);
    }

    #[test]
    fn test_effective_address_immediate() {
        let ea = resolve_effective_address(Mos6502AddressMode::Immediate(0x55), 0x1000, 0, 0);
        assert_eq!(ea, EffectiveAddress::Immediate(0x55));
    }

    #[test]
    fn test_effective_address_zero_page_x_wrap() {
        // ZeroPageX: $FF + X=1 → $00 (wraps within page 0)
        let ea = resolve_effective_address(Mos6502AddressMode::ZeroPageX(0xFF), 0x1000, 1, 0);
        assert_eq!(ea, EffectiveAddress::Memory(0x0000));
    }

    #[test]
    fn test_effective_address_absolute_x() {
        let ea = resolve_effective_address(Mos6502AddressMode::AbsoluteX(0x1000), 0, 0x10, 0);
        assert_eq!(ea, EffectiveAddress::Memory(0x1010));
    }

    #[test]
    fn test_effective_address_relative_forward() {
        // BNE +10 at PC=0x0200 → 0x0200 + 2 + 10 = 0x020C
        let ea = resolve_effective_address(Mos6502AddressMode::Relative(10), 0x0200, 0, 0);
        assert_eq!(ea, EffectiveAddress::BranchTarget(0x020C));
    }

    #[test]
    fn test_effective_address_relative_back() {
        // BNE -4 at PC=0x0200 → 0x0200 + 2 - 4 = 0x01FE
        let ea = resolve_effective_address(Mos6502AddressMode::Relative(-4), 0x0200, 0, 0);
        assert_eq!(ea, EffectiveAddress::BranchTarget(0x01FE));
    }

    #[test]
    fn test_effective_address_is_zero_page() {
        let ea = EffectiveAddress::Memory(0x00FF);
        assert!(ea.is_zero_page());
        let ea2 = EffectiveAddress::Memory(0x0100);
        assert!(!ea2.is_zero_page());
    }

    #[test]
    fn test_cycles_for_mode_immediate() {
        assert_eq!(cycles_for_mode(AddrMode::Immediate), 2);
    }

    #[test]
    fn test_cycles_for_mode_indirect_x() {
        assert_eq!(cycles_for_mode(AddrMode::IndirectX), 6);
    }

    #[test]
    fn test_page_cross_penalty() {
        assert_eq!(page_cross_penalty(AddrMode::AbsoluteX), 1);
        assert_eq!(page_cross_penalty(AddrMode::Immediate), 0);
    }

    #[test]
    fn test_crosses_page_true() {
        assert!(crosses_page(0x10FF, 1)); // 0x10FF + 1 = 0x1100, different page
    }

    #[test]
    fn test_crosses_page_false() {
        assert!(!crosses_page(0x1000, 0xFF)); // stays within 0x10xx
    }

    #[test]
    fn test_decoder_instruction_len() {
        assert_eq!(AddressModeDecoder::instruction_len(0xEA), Some(1)); // NOP
        assert_eq!(AddressModeDecoder::instruction_len(0xAD), Some(3)); // LDA abs
        assert_eq!(AddressModeDecoder::instruction_len(0xFF), None);    // undefined
    }

    #[test]
    fn test_decoder_cycles() {
        assert_eq!(AddressModeDecoder::cycles(0xEA), Some(2)); // NOP
        assert_eq!(AddressModeDecoder::cycles(0xA1), Some(6)); // LDA (zp,X)
    }

    #[test]
    fn test_accesses_memory() {
        assert!(!Mos6502AddressMode::Implied.accesses_memory());
        assert!(!Mos6502AddressMode::Immediate(0).accesses_memory());
        assert!(Mos6502AddressMode::ZeroPage(0x10).accesses_memory());
        assert!(Mos6502AddressMode::Absolute(0x1000).accesses_memory());
    }

    #[test]
    fn test_from_mode_and_bytes_absolute_y() {
        let bytes = [0x99u8, 0x00, 0x20]; // STA $2000,Y
        let m = Mos6502AddressMode::from_mode_and_bytes(AddrMode::AbsoluteY, &bytes).unwrap();
        assert_eq!(m, Mos6502AddressMode::AbsoluteY(0x2000));
    }

    #[test]
    fn test_error_display() {
        let e = AddressModeError::UnknownOpcode(0xFF);
        assert!(e.to_string().contains("0xFF"));
        let e2 = AddressModeError::InsufficientBytes { needed: 3, available: 1 };
        assert!(e2.to_string().contains("3"));
    }
}
