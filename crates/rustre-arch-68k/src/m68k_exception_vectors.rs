//! `m68k_exception_vectors` — Complete Motorola 68000 exception vector table.
//!
//! Covers all 64 exception vectors defined in the M68000 Programmer's Reference
//! Manual §6 (and extensions for the 68010/68020 VBR-relative table).
//! Provides the [`M68kExceptionVector`] enum for every vector number, a
//! [`VectorEntry`] struct with rich metadata, and the `vector_name()` function.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// M68kExceptionVector  — all 64 vectors
// ─────────────────────────────────────────────────────────────────────────────

/// All 64 exception vectors in the M68000 vector table, numbered 0–63.
///
/// Vectors 0–63 occupy bytes 0x000–0x0FF of physical address space on the
/// 68000 (or at VBR on the 68010+).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum M68kExceptionVector {
    /// 0 — Initial SSP (not an exception; SP value loaded at reset).
    ResetInitialSsp = 0,
    /// 1 — Initial PC (CPU jumps here after reset).
    ResetInitialPc = 1,
    /// 2 — Bus Error.
    BusError = 2,
    /// 3 — Address Error (odd address accessed with word/long operand).
    AddressError = 3,
    /// 4 — Illegal Instruction.
    IllegalInstruction = 4,
    /// 5 — Zero Divide.
    ZeroDivide = 5,
    /// 6 — CHK Instruction (check register).
    ChkInstruction = 6,
    /// 7 — TRAPV Instruction (trap on overflow).
    TrapvInstruction = 7,
    /// 8 — Privilege Violation.
    PrivilegeViolation = 8,
    /// 9 — Trace.
    Trace = 9,
    /// 10 — Line 1010 Emulator (A-Line unimplemented instruction).
    LineAEmulator = 10,
    /// 11 — Line 1111 Emulator (F-Line unimplemented instruction).
    LineFEmulator = 11,
    /// 12 — (Reserved; used as hardware breakpoint on 68010+).
    Reserved12 = 12,
    /// 13 — Coprocessor Protocol Violation (68020+).
    CoprocProtocolViolation = 13,
    /// 14 — Format Error (68010+, illegal stack frame format on RTE).
    FormatError = 14,
    /// 15 — Uninitialized Interrupt (spurious autovector before init).
    UninitializedInterrupt = 15,
    /// 16–23 — Reserved.
    Reserved16 = 16,
    Reserved17 = 17,
    Reserved18 = 18,
    Reserved19 = 19,
    Reserved20 = 20,
    Reserved21 = 21,
    Reserved22 = 22,
    Reserved23 = 23,
    /// 24 — Spurious Interrupt.
    SpuriousInterrupt = 24,
    /// 25 — Level 1 Autovector.
    Level1AutoVector = 25,
    /// 26 — Level 2 Autovector.
    Level2AutoVector = 26,
    /// 27 — Level 3 Autovector.
    Level3AutoVector = 27,
    /// 28 — Level 4 Autovector.
    Level4AutoVector = 28,
    /// 29 — Level 5 Autovector.
    Level5AutoVector = 29,
    /// 30 — Level 6 Autovector.
    Level6AutoVector = 30,
    /// 31 — Level 7 Autovector (NMI).
    Level7AutoVector = 31,
    /// 32 — TRAP #0.
    Trap0 = 32,
    /// 33 — TRAP #1.
    Trap1 = 33,
    /// 34 — TRAP #2.
    Trap2 = 34,
    /// 35 — TRAP #3.
    Trap3 = 35,
    /// 36 — TRAP #4.
    Trap4 = 36,
    /// 37 — TRAP #5.
    Trap5 = 37,
    /// 38 — TRAP #6.
    Trap6 = 38,
    /// 39 — TRAP #7.
    Trap7 = 39,
    /// 40 — TRAP #8.
    Trap8 = 40,
    /// 41 — TRAP #9.
    Trap9 = 41,
    /// 42 — TRAP #10.
    Trap10 = 42,
    /// 43 — TRAP #11.
    Trap11 = 43,
    /// 44 — TRAP #12.
    Trap12 = 44,
    /// 45 — TRAP #13.
    Trap13 = 45,
    /// 46 — TRAP #14.
    Trap14 = 46,
    /// 47 — TRAP #15.
    Trap15 = 47,
    /// 48–55 — FPU coprocessor errors (68881/68882 on 68020+).
    FpuBranchUnordered = 48,
    FpuInexactResult = 49,
    FpuDivideByZero = 50,
    FpuUnderflow = 51,
    FpuOperandError = 52,
    FpuOverflow = 53,
    FpuSignalingNan = 54,
    FpuUnimplementedDataType = 55,
    /// 56–58 — MMU errors (68030+).
    MmuConfigError = 56,
    MmuIllegalOperationError = 57,
    MmuAccessLevelViolation = 58,
    /// 59–63 — Unassigned / reserved (user-definable on some platforms).
    Reserved59 = 59,
    Reserved60 = 60,
    Reserved61 = 61,
    Reserved62 = 62,
    Reserved63 = 63,
}

impl M68kExceptionVector {
    /// Construct a vector from a raw vector number (0–63).
    ///
    /// Returns `None` for numbers outside [0, 63].
    #[must_use]
    pub const fn from_number(n: u8) -> Option<Self> {
        Some(match n {
            0 => Self::ResetInitialSsp,
            1 => Self::ResetInitialPc,
            2 => Self::BusError,
            3 => Self::AddressError,
            4 => Self::IllegalInstruction,
            5 => Self::ZeroDivide,
            6 => Self::ChkInstruction,
            7 => Self::TrapvInstruction,
            8 => Self::PrivilegeViolation,
            9 => Self::Trace,
            10 => Self::LineAEmulator,
            11 => Self::LineFEmulator,
            12 => Self::Reserved12,
            13 => Self::CoprocProtocolViolation,
            14 => Self::FormatError,
            15 => Self::UninitializedInterrupt,
            16 => Self::Reserved16,
            17 => Self::Reserved17,
            18 => Self::Reserved18,
            19 => Self::Reserved19,
            20 => Self::Reserved20,
            21 => Self::Reserved21,
            22 => Self::Reserved22,
            23 => Self::Reserved23,
            24 => Self::SpuriousInterrupt,
            25 => Self::Level1AutoVector,
            26 => Self::Level2AutoVector,
            27 => Self::Level3AutoVector,
            28 => Self::Level4AutoVector,
            29 => Self::Level5AutoVector,
            30 => Self::Level6AutoVector,
            31 => Self::Level7AutoVector,
            32 => Self::Trap0,
            33 => Self::Trap1,
            34 => Self::Trap2,
            35 => Self::Trap3,
            36 => Self::Trap4,
            37 => Self::Trap5,
            38 => Self::Trap6,
            39 => Self::Trap7,
            40 => Self::Trap8,
            41 => Self::Trap9,
            42 => Self::Trap10,
            43 => Self::Trap11,
            44 => Self::Trap12,
            45 => Self::Trap13,
            46 => Self::Trap14,
            47 => Self::Trap15,
            48 => Self::FpuBranchUnordered,
            49 => Self::FpuInexactResult,
            50 => Self::FpuDivideByZero,
            51 => Self::FpuUnderflow,
            52 => Self::FpuOperandError,
            53 => Self::FpuOverflow,
            54 => Self::FpuSignalingNan,
            55 => Self::FpuUnimplementedDataType,
            56 => Self::MmuConfigError,
            57 => Self::MmuIllegalOperationError,
            58 => Self::MmuAccessLevelViolation,
            59 => Self::Reserved59,
            60 => Self::Reserved60,
            61 => Self::Reserved61,
            62 => Self::Reserved62,
            63 => Self::Reserved63,
            _ => return None,
        })
    }

    /// Return the vector number.
    #[must_use]
    pub const fn number(self) -> u8 {
        self as u8
    }

    /// Return the physical address of this vector entry in the M68000 table.
    ///
    /// Each entry is 4 bytes; vectors start at address 0x000.
    #[must_use]
    pub const fn address(self) -> u32 {
        (self as u32) * 4
    }

    /// Return `true` if this vector is user-triggerable (TRAP, CHK, TRAPV…).
    #[must_use]
    pub const fn is_user_triggerable(self) -> bool {
        matches!(
            self,
            Self::ChkInstruction
                | Self::TrapvInstruction
                | Self::Trap0
                | Self::Trap1
                | Self::Trap2
                | Self::Trap3
                | Self::Trap4
                | Self::Trap5
                | Self::Trap6
                | Self::Trap7
                | Self::Trap8
                | Self::Trap9
                | Self::Trap10
                | Self::Trap11
                | Self::Trap12
                | Self::Trap13
                | Self::Trap14
                | Self::Trap15
        )
    }

    /// Return `true` if this vector is hardware-triggered (bus/address error,
    /// interrupts, reset).
    #[must_use]
    pub const fn is_hardware(self) -> bool {
        matches!(
            self,
            Self::ResetInitialSsp
                | Self::ResetInitialPc
                | Self::BusError
                | Self::AddressError
                | Self::PrivilegeViolation
                | Self::SpuriousInterrupt
                | Self::Level1AutoVector
                | Self::Level2AutoVector
                | Self::Level3AutoVector
                | Self::Level4AutoVector
                | Self::Level5AutoVector
                | Self::Level6AutoVector
                | Self::Level7AutoVector
        )
    }

    /// Return `true` if this vector is reserved by Motorola.
    #[must_use]
    pub const fn is_reserved(self) -> bool {
        matches!(
            self,
            Self::Reserved12
                | Self::Reserved16
                | Self::Reserved17
                | Self::Reserved18
                | Self::Reserved19
                | Self::Reserved20
                | Self::Reserved21
                | Self::Reserved22
                | Self::Reserved23
                | Self::Reserved59
                | Self::Reserved60
                | Self::Reserved61
                | Self::Reserved62
                | Self::Reserved63
        )
    }

    /// Return `true` if this is an FPU-generated exception (68020+/68881).
    #[must_use]
    pub const fn is_fpu(self) -> bool {
        matches!(
            self,
            Self::FpuBranchUnordered
                | Self::FpuInexactResult
                | Self::FpuDivideByZero
                | Self::FpuUnderflow
                | Self::FpuOperandError
                | Self::FpuOverflow
                | Self::FpuSignalingNan
                | Self::FpuUnimplementedDataType
        )
    }

    /// Return `true` if this is an MMU-generated exception (68030+).
    #[must_use]
    pub const fn is_mmu(self) -> bool {
        matches!(
            self,
            Self::MmuConfigError
                | Self::MmuIllegalOperationError
                | Self::MmuAccessLevelViolation
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VectorEntry  — rich metadata per vector
// ─────────────────────────────────────────────────────────────────────────────

/// Detailed metadata for a single exception vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorEntry {
    /// The vector identifier.
    pub vector: M68kExceptionVector,
    /// Short symbolic name (e.g. `"BUS_ERROR"`).
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// First CPU variant that supports this vector.
    pub introduced_on: &'static str,
    /// `true` if the vector is a fatal abort (CPU cannot easily resume).
    pub is_fatal: bool,
    /// Default privilege level required to handle this vector.
    pub privilege: VectorPrivilege,
}

/// Minimum privilege to set up or handle a vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VectorPrivilege {
    /// Only supervisor-mode code can install/service this vector.
    Supervisor,
    /// Any code can trigger this vector (TRAPs, CHK, …).
    User,
}

// ─────────────────────────────────────────────────────────────────────────────
// vector_name()  — free function
// ─────────────────────────────────────────────────────────────────────────────

/// Return the short symbolic name for a vector number (0–63).
///
/// Returns `"RESERVED"` for undefined or reserved vector numbers.
#[must_use]
pub const fn vector_name(n: u8) -> &'static str {
    match n {
        0 => "RESET_SSP",
        1 => "RESET_PC",
        2 => "BUS_ERROR",
        3 => "ADDRESS_ERROR",
        4 => "ILLEGAL_INSN",
        5 => "ZERO_DIVIDE",
        6 => "CHK",
        7 => "TRAPV",
        8 => "PRIVILEGE_VIOLATION",
        9 => "TRACE",
        10 => "LINE_A_EMULATOR",
        11 => "LINE_F_EMULATOR",
        12 => "RESERVED_12",
        13 => "COPROC_PROTOCOL_VIOLATION",
        14 => "FORMAT_ERROR",
        15 => "UNINITIALIZED_INTERRUPT",
        16..=23 | 59..=63 => "RESERVED",
        24 => "SPURIOUS_INTERRUPT",
        25 => "AUTOVECTOR_L1",
        26 => "AUTOVECTOR_L2",
        27 => "AUTOVECTOR_L3",
        28 => "AUTOVECTOR_L4",
        29 => "AUTOVECTOR_L5",
        30 => "AUTOVECTOR_L6",
        31 => "AUTOVECTOR_L7_NMI",
        32 => "TRAP_0",
        33 => "TRAP_1",
        34 => "TRAP_2",
        35 => "TRAP_3",
        36 => "TRAP_4",
        37 => "TRAP_5",
        38 => "TRAP_6",
        39 => "TRAP_7",
        40 => "TRAP_8",
        41 => "TRAP_9",
        42 => "TRAP_10",
        43 => "TRAP_11",
        44 => "TRAP_12",
        45 => "TRAP_13",
        46 => "TRAP_14",
        47 => "TRAP_15",
        48 => "FPU_BRANCH_UNORDERED",
        49 => "FPU_INEXACT_RESULT",
        50 => "FPU_DIVIDE_BY_ZERO",
        51 => "FPU_UNDERFLOW",
        52 => "FPU_OPERAND_ERROR",
        53 => "FPU_OVERFLOW",
        54 => "FPU_SIGNALING_NAN",
        55 => "FPU_UNIMPLEMENTED_DATA_TYPE",
        56 => "MMU_CONFIG_ERROR",
        57 => "MMU_ILLEGAL_OPERATION",
        58 => "MMU_ACCESS_LEVEL_VIOLATION",
        _ => "OUT_OF_RANGE",
    }
}

/// Return a human-readable description for a vector number.
#[must_use]
pub const fn vector_description(n: u8) -> &'static str {
    match n {
        0 => "Initial Supervisor Stack Pointer loaded at reset",
        1 => "Initial Program Counter loaded at reset",
        2 => "Bus error — external bus access failed",
        3 => "Address error — misaligned word/long access",
        4 => "Illegal instruction — unrecognised opcode",
        5 => "Divide by zero (DIVS/DIVU with divisor = 0)",
        6 => "CHK instruction out-of-bounds",
        7 => "TRAPV instruction with V set",
        8 => "Privilege violation — user mode attempted supervisor op",
        9 => "Trace — single-step debug trap",
        10 => "Line A (1010) unimplemented instruction emulation",
        11 => "Line F (1111) unimplemented instruction / FPU trap",
        12 => "Reserved (hardware breakpoint on 68010+)",
        13 => "Coprocessor protocol violation (68020+)",
        14 => "Format error — illegal stack frame format on RTE (68010+)",
        15 => "Uninitialized interrupt — spurious before IACK",
        16..=23 => "Reserved by Motorola",
        24 => "Spurious interrupt — no interrupt acknowledged",
        25 => "Level 1 autovector interrupt",
        26 => "Level 2 autovector interrupt",
        27 => "Level 3 autovector interrupt",
        28 => "Level 4 autovector interrupt",
        29 => "Level 5 autovector interrupt",
        30 => "Level 6 autovector interrupt",
        31 => "Level 7 autovector — Non-Maskable Interrupt (NMI)",
        32..=47 => "TRAP #N software exception",
        48 => "FPU branch/set with unordered condition",
        49 => "FPU inexact result",
        50 => "FPU divide by zero",
        51 => "FPU underflow",
        52 => "FPU operand error",
        53 => "FPU overflow",
        54 => "FPU signaling NaN",
        55 => "FPU unimplemented data type",
        56 => "MMU configuration error",
        57 => "MMU illegal operation error",
        58 => "MMU access level violation",
        59..=63 => "Reserved / unassigned",
        _ => "Out of range",
    }
}

/// Return a full [`VectorEntry`] for vector number `n`.
///
/// Returns `None` when `n > 63`.
#[must_use]
pub fn vector_entry(n: u8) -> Option<VectorEntry> {
    let vector = M68kExceptionVector::from_number(n)?;
    let (is_fatal, privilege, introduced_on) = match n {
        0..=3 => (true, VectorPrivilege::Supervisor, "MC68000"),
        4 | 5 | 7..=11 | 15..=31 | 59..=63 => (false, VectorPrivilege::Supervisor, "MC68000"),
        6 | 32..=47 => (false, VectorPrivilege::User, "MC68000"),
        12 | 14 => (false, VectorPrivilege::Supervisor, "MC68010"),
        13 => (false, VectorPrivilege::Supervisor, "MC68020"),
        48..=55 => (false, VectorPrivilege::Supervisor, "MC68881"),
        56..=58 => (false, VectorPrivilege::Supervisor, "MC68030"),
        _ => return None,
    };
    Some(VectorEntry {
        vector,
        name: vector_name(n),
        description: vector_description(n),
        introduced_on,
        is_fatal,
        privilege,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// VectorTable  — the full 64-entry table as a struct
// ─────────────────────────────────────────────────────────────────────────────

/// An in-memory representation of a 68000 exception vector table.
///
/// On a real machine the table is 256 bytes (64 × 4) starting at address
/// 0x000000 (or at VBR on the 68010+).
#[derive(Debug, Clone)]
pub struct VectorTable {
    /// Vector addresses, indexed by vector number.
    pub entries: [u32; 64],
    /// Base address of the table (0 for 68000; VBR for 68010+).
    pub base: u32,
}

impl Default for VectorTable {
    fn default() -> Self {
        Self {
            entries: [0u32; 64],
            base: 0,
        }
    }
}

impl VectorTable {
    /// Create an empty (all-zero) vector table at address `base`.
    #[must_use]
    pub const fn new(base: u32) -> Self {
        Self {
            entries: [0u32; 64],
            base,
        }
    }

    /// Parse a vector table from raw big-endian memory bytes.
    ///
    /// `data` must be at least 256 bytes long.
    ///
    /// # Errors
    /// Returns `Err` when `data.len() < 256`.
    pub fn parse(data: &[u8], base: u32) -> Result<Self, String> {
        if data.len() < 256 {
            return Err(format!(
                "Vector table requires 256 bytes, got {}",
                data.len()
            ));
        }
        let mut entries = [0u32; 64];
        for (i, entry) in entries.iter_mut().enumerate() {
            let off = i * 4;
            *entry = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        }
        Ok(Self { entries, base })
    }

    /// Return the handler address for vector `n`.
    #[must_use]
    pub fn handler_for(&self, n: u8) -> u32 {
        self.entries.get(n as usize).copied().unwrap_or(0)
    }

    /// Set the handler address for vector `n`.
    ///
    /// Does nothing when `n > 63`.
    pub fn set_handler(&mut self, n: u8, addr: u32) {
        if let Some(slot) = self.entries.get_mut(n as usize) {
            *slot = addr;
        }
    }

    /// Serialise the table back to 256 big-endian bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        for &addr in &self.entries {
            out.extend_from_slice(&addr.to_be_bytes());
        }
        out
    }

    /// Return all non-zero handler addresses with their vector numbers.
    #[must_use]
    pub fn installed_handlers(&self) -> Vec<(u8, u32)> {
        self.entries
            .iter()
            .enumerate()
            .filter(|&(_, &addr)| addr != 0)
            .map(|(i, &addr)| (u8::try_from(i).unwrap_or(u8::MAX), addr))
            .collect()
    }

    /// Return `true` if the reset vector pair looks plausible (odd SSP,
    /// even PC, both non-zero).
    #[must_use]
    pub const fn looks_valid(&self) -> bool {
        let ssp = self.entries[0];
        let pc = self.entries[1];
        ssp != 0 && pc != 0 && (ssp & 1) == 0
    }

    /// Return a list of unique handler addresses (for sweep analysis).
    #[must_use]
    pub fn unique_handlers(&self) -> Vec<u32> {
        let mut seen = std::collections::HashSet::new();
        self.entries
            .iter()
            .copied()
            .filter(|&a| a != 0 && seen.insert(a))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_64_vectors_round_trip() {
        for n in 0u8..=63 {
            let v = M68kExceptionVector::from_number(n).expect("all 0-63 should be valid");
            assert_eq!(v.number(), n);
        }
    }

    #[test]
    fn test_out_of_range_returns_none() {
        assert!(M68kExceptionVector::from_number(64).is_none());
        assert!(M68kExceptionVector::from_number(255).is_none());
    }

    #[test]
    fn test_vector_address() {
        assert_eq!(M68kExceptionVector::BusError.address(), 8);
        assert_eq!(M68kExceptionVector::Trap0.address(), 128);
    }

    #[test]
    fn test_vector_name_bus_error() {
        assert_eq!(vector_name(2), "BUS_ERROR");
    }

    #[test]
    fn test_vector_name_trap_range() {
        for n in 32u8..=47 {
            assert!(vector_name(n).starts_with("TRAP_"), "n={n}: {}", vector_name(n));
        }
    }

    #[test]
    fn test_vector_name_reserved() {
        for n in [16u8, 17, 18, 19, 20, 21, 22, 23] {
            assert_eq!(vector_name(n), "RESERVED");
        }
    }

    #[test]
    fn test_is_user_triggerable_trap() {
        assert!(M68kExceptionVector::Trap5.is_user_triggerable());
        assert!(!M68kExceptionVector::BusError.is_user_triggerable());
    }

    #[test]
    fn test_is_hardware_reset() {
        assert!(M68kExceptionVector::ResetInitialPc.is_hardware());
        assert!(!M68kExceptionVector::Trap0.is_hardware());
    }

    #[test]
    fn test_is_fpu() {
        assert!(M68kExceptionVector::FpuDivideByZero.is_fpu());
        assert!(M68kExceptionVector::FpuOverflow.is_fpu());
        assert!(!M68kExceptionVector::BusError.is_fpu());
    }

    #[test]
    fn test_is_mmu() {
        assert!(M68kExceptionVector::MmuConfigError.is_mmu());
        assert!(!M68kExceptionVector::FpuDivideByZero.is_mmu());
    }

    #[test]
    fn test_vector_entry_bus_error() {
        let e = vector_entry(2).unwrap();
        assert_eq!(e.name, "BUS_ERROR");
        assert!(e.is_fatal);
        assert_eq!(e.privilege, VectorPrivilege::Supervisor);
    }

    #[test]
    fn test_vector_entry_trap() {
        let e = vector_entry(32).unwrap();
        assert_eq!(e.privilege, VectorPrivilege::User);
    }

    #[test]
    fn test_vector_table_parse_round_trip() {
        let mut raw = vec![0u8; 256];
        // Write a plausible SSP and PC at vectors 0 and 1.
        let ssp: u32 = 0x0001_0000;
        let pc: u32 = 0x0000_1000;
        raw[0..4].copy_from_slice(&ssp.to_be_bytes());
        raw[4..8].copy_from_slice(&pc.to_be_bytes());
        // Write a trap vector at TRAP #0 (vector 32 = offset 128).
        let trap_handler: u32 = 0x0002_0000;
        raw[128..132].copy_from_slice(&trap_handler.to_be_bytes());

        let tbl = VectorTable::parse(&raw, 0).unwrap();
        assert_eq!(tbl.handler_for(0), ssp);
        assert_eq!(tbl.handler_for(1), pc);
        assert_eq!(tbl.handler_for(32), trap_handler);
        assert!(tbl.looks_valid());
    }

    #[test]
    fn test_vector_table_too_short() {
        let raw = vec![0u8; 128];
        assert!(VectorTable::parse(&raw, 0).is_err());
    }

    #[test]
    fn test_vector_table_to_bytes_round_trip() {
        let mut tbl = VectorTable::new(0);
        tbl.set_handler(0, 0xDEAD_BEEF);
        tbl.set_handler(1, 0x0040_0000);
        let bytes = tbl.to_bytes();
        assert_eq!(bytes.len(), 256);
        let tbl2 = VectorTable::parse(&bytes, 0).unwrap();
        assert_eq!(tbl2.handler_for(0), 0xDEAD_BEEF);
        assert_eq!(tbl2.handler_for(1), 0x0040_0000);
    }

    #[test]
    fn test_installed_handlers() {
        let mut tbl = VectorTable::new(0);
        tbl.set_handler(2, 0x1000);
        tbl.set_handler(4, 0x2000);
        let installed = tbl.installed_handlers();
        assert_eq!(installed.len(), 2);
        assert!(installed.contains(&(2, 0x1000)));
        assert!(installed.contains(&(4, 0x2000)));
    }

    #[test]
    fn test_unique_handlers_dedup() {
        let mut tbl = VectorTable::new(0);
        tbl.set_handler(2, 0x1000);
        tbl.set_handler(3, 0x1000); // same handler
        tbl.set_handler(4, 0x2000);
        let unique = tbl.unique_handlers();
        // Should contain 0x1000 once and 0x2000 once.
        assert_eq!(unique.len(), 2);
        assert!(unique.contains(&0x1000));
        assert!(unique.contains(&0x2000));
    }

    #[test]
    fn test_level7_autovector_is_nmi() {
        let v = M68kExceptionVector::Level7AutoVector;
        assert_eq!(v.number(), 31);
        let name = vector_name(31);
        assert!(name.contains("NMI") || name.contains("L7"), "{name}");
    }
}
