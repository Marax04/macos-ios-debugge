//! `m68k_addressing_modes` — Complete Motorola 68000 effective address
//! (EA) addressing mode support for the `RustRE` Suite.
//!
//! Covers all 12 canonical M68K addressing modes including both 68000 base
//! modes and the 68020+ full-extension-word forms. Provides structured
//! [`M68kAddressingMode`] / [`EffectiveAddress`] types, a `decode_ea()`
//! function for decoding from a raw byte stream, and a `ea_cycles()` function
//! for estimating bus-cycle costs.

use serde::{Deserialize, Serialize};

use crate::{Size, Mc68kVariant};

// ─────────────────────────────────────────────────────────────────────────────
// AddressingModeKind  — the 12 canonical M68K EA modes
// ─────────────────────────────────────────────────────────────────────────────

/// All twelve Motorola 68000 / 68020 effective address modes.
///
/// The numbering follows the Motorola programmer's reference manual (M68000PM)
/// §2.2 table 2-1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AddressingModeKind {
    /// Mode 000 — Data Register Direct: Dn
    DataRegDirect,
    /// Mode 001 — Address Register Direct: An
    AddrRegDirect,
    /// Mode 010 — Address Register Indirect: (An)
    AddrRegIndirect,
    /// Mode 011 — Address Register Indirect with Post-increment: (An)+
    AddrRegIndirectPostInc,
    /// Mode 100 — Address Register Indirect with Pre-decrement: -(An)
    AddrRegIndirectPreDec,
    /// Mode 101 — Address Register Indirect with Displacement: (d16, An)
    AddrRegIndirectDisp,
    /// Mode 110 — Address Register Indirect with Index (Brief): (d8, An, Xn)
    AddrRegIndirectIndex,
    /// Mode 111 reg 000 — Absolute Short: (xxx).W
    AbsShort,
    /// Mode 111 reg 001 — Absolute Long: (xxx).L
    AbsLong,
    /// Mode 111 reg 010 — PC-relative with Displacement: (d16, PC)
    PcRelDisp,
    /// Mode 111 reg 011 — PC-relative with Index: (d8, PC, Xn)
    PcRelIndex,
    /// Mode 111 reg 100 — Immediate: #imm
    Immediate,
    // 68020+ extended modes (encoded as Mode 110 / Mode 111 with full ext word)
    /// 68020+ — Address Register Indirect with Memory Indirect Post-indexed.
    MemIndirectPostIndex,
    /// 68020+ — Address Register Indirect with Memory Indirect Pre-indexed.
    MemIndirectPreIndex,
    /// 68020+ — PC-relative Memory Indirect Post-indexed.
    PcMemIndirectPostIndex,
    /// 68020+ — PC-relative Memory Indirect Pre-indexed.
    PcMemIndirectPreIndex,
}

impl AddressingModeKind {
    /// Return the assembly-language mnemonic fragment for this mode.
    #[must_use]
    pub const fn asm_name(self) -> &'static str {
        match self {
            Self::DataRegDirect => "Dn",
            Self::AddrRegDirect => "An",
            Self::AddrRegIndirect => "(An)",
            Self::AddrRegIndirectPostInc => "(An)+",
            Self::AddrRegIndirectPreDec => "-(An)",
            Self::AddrRegIndirectDisp => "(d16,An)",
            Self::AddrRegIndirectIndex => "(d8,An,Xn)",
            Self::AbsShort => "(xxx).W",
            Self::AbsLong => "(xxx).L",
            Self::PcRelDisp => "(d16,PC)",
            Self::PcRelIndex => "(d8,PC,Xn)",
            Self::Immediate => "#imm",
            Self::MemIndirectPostIndex => "([bd,An],Xn,od)",
            Self::MemIndirectPreIndex => "([bd,An,Xn],od)",
            Self::PcMemIndirectPostIndex => "([bd,PC],Xn,od)",
            Self::PcMemIndirectPreIndex => "([bd,PC,Xn],od)",
        }
    }

    /// Return `true` if this mode can serve as a memory destination.
    #[must_use]
    pub const fn is_memory_alterable(self) -> bool {
        matches!(
            self,
            Self::AddrRegIndirect
                | Self::AddrRegIndirectPostInc
                | Self::AddrRegIndirectPreDec
                | Self::AddrRegIndirectDisp
                | Self::AddrRegIndirectIndex
                | Self::AbsShort
                | Self::AbsLong
                | Self::MemIndirectPostIndex
                | Self::MemIndirectPreIndex
        )
    }

    /// Return `true` if this mode is data-alterable (can be destination of
    /// most ALU operations).
    #[must_use]
    pub const fn is_data_alterable(self) -> bool {
        matches!(self, Self::DataRegDirect) || self.is_memory_alterable()
    }

    /// Return `true` for the PC-relative modes.
    #[must_use]
    pub const fn is_pc_relative(self) -> bool {
        matches!(
            self,
            Self::PcRelDisp
                | Self::PcRelIndex
                | Self::PcMemIndirectPostIndex
                | Self::PcMemIndirectPreIndex
        )
    }

    /// Return `true` if this mode requires extension words.
    #[must_use]
    pub const fn has_extension_words(self) -> bool {
        !matches!(
            self,
            Self::DataRegDirect
                | Self::AddrRegDirect
                | Self::AddrRegIndirect
                | Self::AddrRegIndirectPostInc
                | Self::AddrRegIndirectPreDec
        )
    }
}

impl std::fmt::Display for AddressingModeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.asm_name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IndexRegister
// ─────────────────────────────────────────────────────────────────────────────

/// An index register specifier as encoded in a 68000 brief extension word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IndexRegister {
    /// Register number (0–7).
    pub reg: u8,
    /// `true` → An, `false` → Dn.
    pub is_address: bool,
    /// `true` → use full 32-bit value; `false` → sign-extend 16-bit low word.
    pub long_size: bool,
    /// Scale factor (0 = ×1, 1 = ×2, 2 = ×4, 3 = ×8); 68020+ only.
    pub scale: u8,
}

impl IndexRegister {
    /// Parse from the high byte of a 68000 brief extension word.
    #[must_use]
    pub const fn from_brief_byte(high: u8) -> Self {
        let reg = (high >> 4) & 0x7;
        let is_address = (high & 0x80) != 0;
        let long_size = (high & 0x08) != 0;
        let scale = (high >> 1) & 0x3;
        Self {
            reg,
            is_address,
            long_size,
            scale,
        }
    }

    /// Return the register name (e.g. `"A3"` or `"D2"`).
    #[must_use]
    pub fn name(self) -> String {
        let letter = if self.is_address { 'A' } else { 'D' };
        format!("{letter}{}", self.reg)
    }

    /// Multiplier for scaled index addressing (68020+).
    #[must_use]
    pub const fn scale_factor(self) -> u8 {
        1u8 << self.scale
    }
}

impl std::fmt::Display for IndexRegister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sz = if self.long_size { ".L" } else { ".W" };
        let scale = self.scale_factor();
        if scale > 1 {
            write!(f, "{}{sz}*{scale}", self.name())
        } else {
            write!(f, "{}{sz}", self.name())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EffectiveAddress  — resolved EA with all fields decoded
// ─────────────────────────────────────────────────────────────────────────────

/// A fully decoded effective address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveAddress {
    /// The addressing mode kind.
    pub mode: AddressingModeKind,
    /// Primary register number (An or Dn depending on mode).
    pub reg: u8,
    /// 16-bit displacement (modes 101, 010 PC-rel).
    pub disp16: i16,
    /// 8-bit displacement (mode 110 brief extension).
    pub disp8: i8,
    /// 32-bit base displacement (68020+ full ext word).
    pub base_disp32: i32,
    /// 32-bit outer displacement (68020+ memory-indirect).
    pub outer_disp32: i32,
    /// Index register (modes 110, 111.011 and 68020+ indexed).
    pub index: Option<IndexRegister>,
    /// Absolute address (modes 111.000, 111.001).
    pub abs_addr: u32,
    /// Immediate value (mode 111.100).
    pub immediate: u32,
    /// Number of extension bytes consumed (not counting the opcode word).
    pub extension_bytes: usize,
}

impl EffectiveAddress {
    /// Format the EA as an assembly-language operand string.
    #[must_use]
    pub fn to_asm(&self) -> String {
        match self.mode {
            AddressingModeKind::DataRegDirect => format!("D{}", self.reg),
            AddressingModeKind::AddrRegDirect => format!("A{}", self.reg),
            AddressingModeKind::AddrRegIndirect => format!("(A{})", self.reg),
            AddressingModeKind::AddrRegIndirectPostInc => format!("(A{})+", self.reg),
            AddressingModeKind::AddrRegIndirectPreDec => format!("-(A{})", self.reg),
            AddressingModeKind::AddrRegIndirectDisp => {
                format!("({},A{})", self.disp16, self.reg)
            }
            AddressingModeKind::AddrRegIndirectIndex => {
                let idx = self
                    .index
                    .as_ref()
                    .map_or_else(|| "?".to_string(), std::string::ToString::to_string);
                format!("({},A{},{idx})", self.disp8, self.reg)
            }
            AddressingModeKind::AbsShort => format!("(${:04X}).W", self.abs_addr & 0xFFFF),
            AddressingModeKind::AbsLong => format!("(${:08X}).L", self.abs_addr),
            AddressingModeKind::PcRelDisp => format!("({},PC)", self.disp16),
            AddressingModeKind::PcRelIndex => {
                let idx = self
                    .index
                    .as_ref()
                    .map_or_else(|| "?".to_string(), std::string::ToString::to_string);
                format!("({},PC,{idx})", self.disp8)
            }
            AddressingModeKind::Immediate => format!("#${:08X}", self.immediate),
            AddressingModeKind::MemIndirectPostIndex => {
                let idx = self
                    .index
                    .as_ref()
                    .map_or_else(|| "?".to_string(), std::string::ToString::to_string);
                format!("([{},A{}],{idx},{:08X})", self.base_disp32, self.reg, self.outer_disp32)
            }
            AddressingModeKind::MemIndirectPreIndex => {
                let idx = self
                    .index
                    .as_ref()
                    .map_or_else(|| "?".to_string(), std::string::ToString::to_string);
                format!(
                    "([{},A{},{idx}],{:08X})",
                    self.base_disp32, self.reg, self.outer_disp32
                )
            }
            AddressingModeKind::PcMemIndirectPostIndex => {
                let idx = self
                    .index
                    .as_ref()
                    .map_or_else(|| "?".to_string(), std::string::ToString::to_string);
                format!("([{},PC],{idx},{:08X})", self.base_disp32, self.outer_disp32)
            }
            AddressingModeKind::PcMemIndirectPreIndex => {
                let idx = self
                    .index
                    .as_ref()
                    .map_or_else(|| "?".to_string(), std::string::ToString::to_string);
                format!("([{},PC,{idx}],{:08X})", self.base_disp32, self.outer_disp32)
            }
        }
    }
}

impl std::fmt::Display for EffectiveAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_asm())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// M68kAddressingMode  — the high-level public type
// ─────────────────────────────────────────────────────────────────────────────

/// High-level addressing mode descriptor combining a kind tag with a fully
/// decoded [`EffectiveAddress`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct M68kAddressingMode {
    /// The EA kind.
    pub kind: AddressingModeKind,
    /// Fully resolved effective address details.
    pub ea: EffectiveAddress,
}

impl M68kAddressingMode {
    /// Return `true` if this mode can be used as a destination for ALU
    /// operations on a given CPU variant.
    #[must_use]
    pub const fn is_alterable(&self, _variant: Mc68kVariant) -> bool {
        self.kind.is_data_alterable()
    }

    /// Return the number of extension bytes consumed by this mode.
    #[must_use]
    pub const fn extension_bytes(&self) -> usize {
        self.ea.extension_bytes
    }

    /// Format as assembly operand.
    #[must_use]
    pub fn to_asm(&self) -> String {
        self.ea.to_asm()
    }
}

impl std::fmt::Display for M68kAddressingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_asm())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// decode_ea()  — main entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Decode an M68K effective address from `mode`, `reg`, and the remaining
/// extension bytes `ext`, given the operand `size`.
///
/// Returns the decoded [`M68kAddressingMode`] or an error string.
///
/// The `variant` parameter enables 68020+ extended addressing modes when
/// `variant >= Mc68kVariant::M68020`.
///
/// # Errors
/// Returns a descriptive error string when the extension byte stream is too
/// short or contains an invalid encoding.
pub fn decode_ea(
    mode: u8,
    reg: u8,
    size: Size,
    ext: &[u8],
    variant: Mc68kVariant,
) -> Result<M68kAddressingMode, String> {
    let mut ea = EffectiveAddress {
        mode: AddressingModeKind::DataRegDirect,
        reg,
        disp16: 0,
        disp8: 0,
        base_disp32: 0,
        outer_disp32: 0,
        index: None,
        abs_addr: 0,
        immediate: 0,
        extension_bytes: 0,
    };

    let kind = match mode {
        0 => AddressingModeKind::DataRegDirect,
        1 => AddressingModeKind::AddrRegDirect,
        2 => AddressingModeKind::AddrRegIndirect,
        3 => AddressingModeKind::AddrRegIndirectPostInc,
        4 => AddressingModeKind::AddrRegIndirectPreDec,
        5 => {
            if ext.len() < 2 {
                return Err("EA mode 5 requires 2 displacement bytes".into());
            }
            ea.disp16 = i16::from_be_bytes([ext[0], ext[1]]);
            ea.extension_bytes = 2;
            AddressingModeKind::AddrRegIndirectDisp
        }
        6 => {
            if ext.len() < 2 {
                return Err("EA mode 6 requires 2 extension bytes".into());
            }
            let brief_hi = ext[0];
            let brief_lo = ext[1];
            // Check for 68020+ full extension word (bit 8 of hi byte set).
            if variant.is_32bit() && (brief_hi & 0x01) != 0 {
                decode_full_ext(reg, ext, &mut ea, false)?;
            } else {
                ea.disp8 = brief_lo.cast_signed();
                ea.index = Some(IndexRegister::from_brief_byte(brief_hi));
                ea.extension_bytes = 2;
            }
            AddressingModeKind::AddrRegIndirectIndex
        }
        7 => match reg {
            0 => {
                if ext.len() < 2 {
                    return Err("EA abs.W requires 2 bytes".into());
                }
                let addr = u16::from_be_bytes([ext[0], ext[1]]);
                ea.abs_addr = u32::from(addr);
                ea.extension_bytes = 2;
                AddressingModeKind::AbsShort
            }
            1 => {
                if ext.len() < 4 {
                    return Err("EA abs.L requires 4 bytes".into());
                }
                ea.abs_addr = u32::from_be_bytes([ext[0], ext[1], ext[2], ext[3]]);
                ea.extension_bytes = 4;
                AddressingModeKind::AbsLong
            }
            2 => {
                if ext.len() < 2 {
                    return Err("EA PC+disp16 requires 2 bytes".into());
                }
                ea.disp16 = i16::from_be_bytes([ext[0], ext[1]]);
                ea.extension_bytes = 2;
                AddressingModeKind::PcRelDisp
            }
            3 => {
                if ext.len() < 2 {
                    return Err("EA PC+index requires 2 extension bytes".into());
                }
                if variant.is_32bit() && (ext[0] & 0x01) != 0 {
                    decode_full_ext(0, ext, &mut ea, true)?;
                    // Return the appropriate memory-indirect subtype.
                    let kind = if ea.outer_disp32 == 0 {
                        AddressingModeKind::PcMemIndirectPreIndex
                    } else {
                        AddressingModeKind::PcMemIndirectPostIndex
                    };
                    ea.mode = kind;
                    return Ok(M68kAddressingMode { kind, ea });
                }
                ea.disp8 = ext[1].cast_signed();
                ea.index = Some(IndexRegister::from_brief_byte(ext[0]));
                ea.extension_bytes = 2;
                AddressingModeKind::PcRelIndex
            }
            4 => {
                let (val, bytes) = decode_immediate(size, ext)?;
                ea.immediate = val;
                ea.extension_bytes = bytes;
                AddressingModeKind::Immediate
            }
            _ => return Err(format!("invalid EA 7.{reg}")),
        },
        _ => return Err(format!("invalid EA mode {mode}")),
    };

    ea.mode = kind;
    Ok(M68kAddressingMode { kind, ea })
}

/// Decode a 68020+ full extension word (used in mode 110 and 111.011).
///
/// Modifies `ea` in place.
fn decode_full_ext(
    base_reg: u8,
    ext: &[u8],
    ea: &mut EffectiveAddress,
    pc_relative: bool,
) -> Result<(), String> {
    if ext.len() < 2 {
        return Err("Full ext word requires at least 2 bytes".into());
    }
    let hi = ext[0];
    let lo = ext[1];

    // Index suppressed = bit 6 of lo.
    let index_suppressed = (lo & 0x40) != 0;
    // Base suppressed = bit 7 of lo.
    let base_suppressed = (lo & 0x80) != 0;
    // Base displacement size: bits 5:4.
    let bd_size = (lo >> 4) & 0x3;
    // Outer displacement size: bits 1:0.
    let od_size = lo & 0x3;
    // Post-indexed = bit 2 set (I/IS field).
    let is_post = (lo >> 2) & 1 == 0 && !index_suppressed;

    let mut pos = 2usize;

    // Base displacement.
    let base_disp = match bd_size {
        0 | 1 => 0i32,
        2 => {
            if pos + 2 > ext.len() {
                return Err("Base displacement (16-bit) truncated".into());
            }
            let v = i32::from(i16::from_be_bytes([ext[pos], ext[pos + 1]]));
            pos += 2;
            v
        }
        _ => {
            if pos + 4 > ext.len() {
                return Err("Base displacement (32-bit) truncated".into());
            }
            let v = i32::from_be_bytes([ext[pos], ext[pos + 1], ext[pos + 2], ext[pos + 3]]);
            pos += 4;
            v
        }
    };

    // Outer displacement.
    let outer_disp = match od_size {
        0 | 1 => 0i32,
        2 => {
            if pos + 2 > ext.len() {
                return Err("Outer displacement (16-bit) truncated".into());
            }
            let v = i32::from(i16::from_be_bytes([ext[pos], ext[pos + 1]]));
            pos += 2;
            v
        }
        _ => {
            if pos + 4 > ext.len() {
                return Err("Outer displacement (32-bit) truncated".into());
            }
            let v = i32::from_be_bytes([ext[pos], ext[pos + 1], ext[pos + 2], ext[pos + 3]]);
            pos += 4;
            v
        }
    };

    ea.reg = base_reg;
    ea.base_disp32 = base_disp;
    ea.outer_disp32 = outer_disp;
    ea.extension_bytes = pos;

    if !index_suppressed {
        ea.index = Some(IndexRegister::from_brief_byte(hi));
    }

    let kind = if pc_relative {
        if is_post {
            AddressingModeKind::PcMemIndirectPostIndex
        } else {
            AddressingModeKind::PcMemIndirectPreIndex
        }
    } else if is_post {
        AddressingModeKind::MemIndirectPostIndex
    } else {
        AddressingModeKind::MemIndirectPreIndex
    };

    let _ = base_suppressed; // field is informational
    ea.mode = kind;
    Ok(())
}

/// Decode an immediate operand.
fn decode_immediate(size: Size, ext: &[u8]) -> Result<(u32, usize), String> {
    match size {
        Size::Byte => {
            if ext.len() < 2 {
                return Err("Immediate byte requires 2 extension bytes".into());
            }
            Ok((u32::from(ext[1]), 2))
        }
        Size::Word => {
            if ext.len() < 2 {
                return Err("Immediate word requires 2 extension bytes".into());
            }
            Ok((u32::from(u16::from_be_bytes([ext[0], ext[1]])), 2))
        }
        Size::Long | Size::Quad => {
            if ext.len() < 4 {
                return Err("Immediate long requires 4 extension bytes".into());
            }
            Ok((u32::from_be_bytes([ext[0], ext[1], ext[2], ext[3]]), 4))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ea_cycles()  — bus-cycle cost table
// ─────────────────────────────────────────────────────────────────────────────

/// Bus-cycle access time for each addressing mode on a base 68000.
///
/// Values are measured in clock cycles for a read access.  The 68000 needs
/// 4 cycles per bus access; extra cycles reflect additional memory fetches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressingModeCycles {
    /// Clock cycles for a read access.
    pub read: u8,
    /// Clock cycles for a write access (0 = same as read).
    pub write: u8,
    /// Clock cycles for a read-modify-write access.
    pub rmw: u8,
}

impl AddressingModeCycles {
    const fn new(read: u8, write: u8, rmw: u8) -> Self {
        Self { read, write, rmw }
    }
}

/// Return the bus-cycle cost for an effective address on the given CPU variant.
///
/// Cycle counts follow the Motorola 68000 User's Manual §4 tables.  For the
/// 68020 and later the costs are generally lower due to on-chip caches; this
/// function returns pessimistic base-case values.
#[must_use]
pub const fn ea_cycles(mode: &M68kAddressingMode, variant: Mc68kVariant) -> AddressingModeCycles {
    let base = match mode.kind {
        AddressingModeKind::DataRegDirect | AddressingModeKind::AddrRegDirect =>
            AddressingModeCycles::new(0, 0, 0),
        AddressingModeKind::AddrRegIndirect | AddressingModeKind::AddrRegIndirectPostInc =>
            AddressingModeCycles::new(4, 4, 8),
        AddressingModeKind::AddrRegIndirectPreDec => AddressingModeCycles::new(6, 6, 10),
        AddressingModeKind::AddrRegIndirectDisp
        | AddressingModeKind::AbsShort
        | AddressingModeKind::PcRelDisp => AddressingModeCycles::new(8, 8, 12),
        AddressingModeKind::AddrRegIndirectIndex | AddressingModeKind::PcRelIndex =>
            AddressingModeCycles::new(10, 10, 14),
        AddressingModeKind::AbsLong => AddressingModeCycles::new(12, 12, 16),
        AddressingModeKind::Immediate => AddressingModeCycles::new(4, 4, 0),
        // 68020+ memory indirect: pessimistic — two extra bus reads.
        AddressingModeKind::MemIndirectPostIndex
        | AddressingModeKind::MemIndirectPreIndex
        | AddressingModeKind::PcMemIndirectPostIndex
        | AddressingModeKind::PcMemIndirectPreIndex => AddressingModeCycles::new(18, 18, 22),
    };

    // The 68020 and later have on-chip caches and pipelining; roughly halve
    // the memory-cycle penalty for cached accesses.
    if variant.is_32bit() && base.read > 4 {
        AddressingModeCycles::new(base.read - 2, base.write - 2, base.rmw.saturating_sub(2))
    } else {
        base
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EaConstraints  — what modes are allowed for a given instruction role
// ─────────────────────────────────────────────────────────────────────────────

/// Set of [`AddressingModeKind`] values permitted for a given operand role.
#[derive(Debug, Clone)]
pub struct EaConstraints {
    allowed: std::collections::HashSet<AddressingModeKind>,
}

impl EaConstraints {
    /// Constraint: all data-alterable modes.
    #[must_use]
    pub fn data_alterable() -> Self {
        use AddressingModeKind::{DataRegDirect, AddrRegIndirect, AddrRegIndirectPostInc, AddrRegIndirectPreDec, AddrRegIndirectDisp, AddrRegIndirectIndex, AbsShort, AbsLong};
        Self {
            allowed: [
                DataRegDirect,
                AddrRegIndirect,
                AddrRegIndirectPostInc,
                AddrRegIndirectPreDec,
                AddrRegIndirectDisp,
                AddrRegIndirectIndex,
                AbsShort,
                AbsLong,
            ]
            .into_iter()
            .collect(),
        }
    }

    /// Constraint: all memory-alterable modes (no data register).
    #[must_use]
    pub fn memory_alterable() -> Self {
        use AddressingModeKind::{AddrRegIndirect, AddrRegIndirectPostInc, AddrRegIndirectPreDec, AddrRegIndirectDisp, AddrRegIndirectIndex, AbsShort, AbsLong};
        Self {
            allowed: [
                AddrRegIndirect,
                AddrRegIndirectPostInc,
                AddrRegIndirectPreDec,
                AddrRegIndirectDisp,
                AddrRegIndirectIndex,
                AbsShort,
                AbsLong,
            ]
            .into_iter()
            .collect(),
        }
    }

    /// Constraint: all modes that can be a source operand.
    #[must_use]
    pub fn all_source() -> Self {
        use AddressingModeKind::{DataRegDirect, AddrRegDirect, AddrRegIndirect, AddrRegIndirectPostInc, AddrRegIndirectPreDec, AddrRegIndirectDisp, AddrRegIndirectIndex, AbsShort, AbsLong, PcRelDisp, PcRelIndex, Immediate};
        Self {
            allowed: [
                DataRegDirect,
                AddrRegDirect,
                AddrRegIndirect,
                AddrRegIndirectPostInc,
                AddrRegIndirectPreDec,
                AddrRegIndirectDisp,
                AddrRegIndirectIndex,
                AbsShort,
                AbsLong,
                PcRelDisp,
                PcRelIndex,
                Immediate,
            ]
            .into_iter()
            .collect(),
        }
    }

    /// Return `true` if `mode` is in this constraint set.
    #[must_use]
    pub fn allows(&self, mode: AddressingModeKind) -> bool {
        self.allowed.contains(&mode)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_reg_direct() {
        let m = decode_ea(0, 3, Size::Long, &[], Mc68kVariant::M68000).unwrap();
        assert_eq!(m.kind, AddressingModeKind::DataRegDirect);
        assert_eq!(m.ea.reg, 3);
        assert_eq!(m.extension_bytes(), 0);
        assert_eq!(m.to_asm(), "D3");
    }

    #[test]
    fn test_addr_reg_direct() {
        let m = decode_ea(1, 5, Size::Long, &[], Mc68kVariant::M68000).unwrap();
        assert_eq!(m.kind, AddressingModeKind::AddrRegDirect);
        assert_eq!(m.to_asm(), "A5");
    }

    #[test]
    fn test_addr_reg_indirect() {
        let m = decode_ea(2, 2, Size::Word, &[], Mc68kVariant::M68000).unwrap();
        assert_eq!(m.kind, AddressingModeKind::AddrRegIndirect);
        assert_eq!(m.to_asm(), "(A2)");
    }

    #[test]
    fn test_addr_reg_indirect_post_inc() {
        let m = decode_ea(3, 0, Size::Byte, &[], Mc68kVariant::M68000).unwrap();
        assert_eq!(m.kind, AddressingModeKind::AddrRegIndirectPostInc);
        assert_eq!(m.to_asm(), "(A0)+");
    }

    #[test]
    fn test_addr_reg_indirect_pre_dec() {
        let m = decode_ea(4, 7, Size::Word, &[], Mc68kVariant::M68000).unwrap();
        assert_eq!(m.kind, AddressingModeKind::AddrRegIndirectPreDec);
        assert_eq!(m.to_asm(), "-(A7)");
    }

    #[test]
    fn test_addr_reg_disp() {
        let m = decode_ea(5, 1, Size::Long, &[0xFF, 0xF0], Mc68kVariant::M68000).unwrap();
        assert_eq!(m.kind, AddressingModeKind::AddrRegIndirectDisp);
        assert_eq!(m.ea.disp16, -16_i16);
        assert_eq!(m.extension_bytes(), 2);
    }

    #[test]
    fn test_abs_short() {
        let m = decode_ea(7, 0, Size::Word, &[0x00, 0x10], Mc68kVariant::M68000).unwrap();
        assert_eq!(m.kind, AddressingModeKind::AbsShort);
        assert_eq!(m.ea.abs_addr, 0x0010);
    }

    #[test]
    fn test_abs_long() {
        let m = decode_ea(7, 1, Size::Long, &[0x00, 0x40, 0x10, 0x00], Mc68kVariant::M68000).unwrap();
        assert_eq!(m.kind, AddressingModeKind::AbsLong);
        assert_eq!(m.ea.abs_addr, 0x0040_1000);
    }

    #[test]
    fn test_immediate_word() {
        let m = decode_ea(7, 4, Size::Word, &[0x00, 0x42], Mc68kVariant::M68000).unwrap();
        assert_eq!(m.kind, AddressingModeKind::Immediate);
        assert_eq!(m.ea.immediate, 0x42);
    }

    #[test]
    fn test_immediate_byte() {
        let m = decode_ea(7, 4, Size::Byte, &[0x00, 0xFF], Mc68kVariant::M68000).unwrap();
        assert_eq!(m.kind, AddressingModeKind::Immediate);
        assert_eq!(m.ea.immediate, 0xFF);
    }

    #[test]
    fn test_pc_rel_disp() {
        let m = decode_ea(7, 2, Size::Word, &[0x00, 0x0C], Mc68kVariant::M68000).unwrap();
        assert_eq!(m.kind, AddressingModeKind::PcRelDisp);
        assert_eq!(m.ea.disp16, 12);
    }

    #[test]
    fn test_ea_cycles_data_reg_zero() {
        let m = decode_ea(0, 0, Size::Long, &[], Mc68kVariant::M68000).unwrap();
        let cyc = ea_cycles(&m, Mc68kVariant::M68000);
        assert_eq!(cyc.read, 0);
    }

    #[test]
    fn test_ea_cycles_abs_long_slower_than_abs_short() {
        let ms = decode_ea(7, 0, Size::Word, &[0x00, 0x10], Mc68kVariant::M68000).unwrap();
        let ml = decode_ea(7, 1, Size::Long, &[0x00, 0x40, 0x10, 0x00], Mc68kVariant::M68000).unwrap();
        let cs = ea_cycles(&ms, Mc68kVariant::M68000);
        let cl = ea_cycles(&ml, Mc68kVariant::M68000);
        assert!(cl.read >= cs.read);
    }

    #[test]
    fn test_ea_constraints_data_alterable_allows_dn() {
        let c = EaConstraints::data_alterable();
        assert!(c.allows(AddressingModeKind::DataRegDirect));
        assert!(!c.allows(AddressingModeKind::AddrRegDirect));
        assert!(!c.allows(AddressingModeKind::Immediate));
    }

    #[test]
    fn test_is_memory_alterable() {
        assert!(AddressingModeKind::AddrRegIndirect.is_memory_alterable());
        assert!(!AddressingModeKind::DataRegDirect.is_memory_alterable());
        assert!(!AddressingModeKind::Immediate.is_memory_alterable());
    }

    #[test]
    fn test_is_pc_relative() {
        assert!(AddressingModeKind::PcRelDisp.is_pc_relative());
        assert!(AddressingModeKind::PcRelIndex.is_pc_relative());
        assert!(!AddressingModeKind::AbsLong.is_pc_relative());
    }

    #[test]
    fn test_invalid_mode_returns_error() {
        let result = decode_ea(8, 0, Size::Word, &[], Mc68kVariant::M68000);
        assert!(result.is_err());
    }

    #[test]
    fn test_index_register_display() {
        let idx = IndexRegister { reg: 3, is_address: false, long_size: true, scale: 2 };
        let s = idx.to_string();
        assert!(s.contains("D3"));
        assert!(s.contains('4')); // scale factor 2^2 = 4
    }
}
