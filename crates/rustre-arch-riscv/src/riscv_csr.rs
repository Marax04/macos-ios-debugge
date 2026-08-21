//! Complete RISC-V CSR (Control and Status Register) file.
//!
//! Covers all 4096 CSR addresses defined in the RISC-V Privileged Architecture
//! specification (Volume II), including:
//! - User-mode CSRs (0x000–0x0FF)
//! - Supervisor CSRs (0x100–0x1FF, 0x900–0x9FF, 0xD00–0xDFF)
//! - Hypervisor CSRs (0x200–0x2FF, 0x600–0x6FF, 0xA00–0xAFF, 0xE00–0xEFF)
//! - Machine-mode CSRs (0x300–0x3FF, 0x700–0x7FF, 0xB00–0xBFF, 0xF00–0xFFF)
//! - Debug CSRs (0x7A0–0x7AF, 0x7B0–0x7BF)

use std::collections::HashMap;

/// An all-zero CSR value bank.
///
/// Held as a `static` so the 32 KiB of zeroes lives in static data rather than
/// being built as a temporary on the caller's stack.
static ZERO_CSR_FILE: [u64; 4096] = [0u64; 4096];

// ---------------------------------------------------------------------------
// CsrAccess — privilege / access level
// ---------------------------------------------------------------------------

/// CSR access level and privilege mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CsrAccess {
    /// Read/write, User mode.
    ReadWriteUser,
    /// Read/write, Supervisor mode.
    ReadWriteSupervisor,
    /// Read/write, Machine mode.
    ReadWriteMachine,
    /// Read/write, Hypervisor mode.
    ReadWriteHypervisor,
    /// Read-only (any privilege).
    ReadOnly,
    /// Read-only, Supervisor mode.
    ReadOnlySupervisor,
    /// Read-only, Machine mode.
    ReadOnlyMachine,
    /// Debug mode.
    Debug,
}

impl CsrAccess {
    /// Return `true` if this CSR is writable.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        !matches!(
            self,
            Self::ReadOnly | Self::ReadOnlySupervisor | Self::ReadOnlyMachine
        )
    }

    /// Minimum privilege level (U=0, S=1, H=2, M=3).
    #[must_use]
    pub const fn min_privilege(self) -> u8 {
        match self {
            Self::ReadWriteUser | Self::ReadOnly => 0,
            Self::ReadWriteSupervisor | Self::ReadOnlySupervisor => 1,
            Self::ReadWriteHypervisor => 2,
            Self::ReadWriteMachine | Self::ReadOnlyMachine | Self::Debug => 3,
            }
    }
}

// ---------------------------------------------------------------------------
// CsrId — all 4096 CSR addresses
// ---------------------------------------------------------------------------

/// A RISC-V CSR identifier (12-bit address 0x000–0xFFF).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CsrId(pub u16);

impl CsrId {
    /// Create a CSR ID, returning `None` if `addr > 0xFFF`.
    #[must_use]
    pub const fn new(addr: u16) -> Option<Self> {
        if addr <= 0xFFF {
            Some(Self(addr))
        } else {
            None
        }
    }

    /// Raw 12-bit address.
    #[must_use]
    pub const fn addr(self) -> u16 {
        self.0
    }

    /// `true` if the CSR is read-only (top 2 bits = 11).
    #[must_use]
    pub const fn is_read_only_by_encoding(self) -> bool {
        (self.0 >> 10) == 0b11
    }

    /// Privilege level encoded in bits [9:8].
    #[must_use]
    pub const fn privilege_from_encoding(self) -> u8 {
        ((self.0 >> 8) & 0x3) as u8
    }
}

impl std::fmt::Display for CsrId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:03x}", self.0)
    }
}

// ---------------------------------------------------------------------------
// CsrDescriptor — static description of a CSR
// ---------------------------------------------------------------------------

/// Static descriptor for a RISC-V CSR.
#[derive(Debug, Clone)]
pub struct CsrDescriptor {
    /// 12-bit CSR address.
    pub id: CsrId,
    /// Canonical name (e.g. "mstatus").
    pub name: &'static str,
    /// Access level.
    pub access: CsrAccess,
    /// Brief description.
    pub desc: &'static str,
    /// `true` if this CSR is part of a counter/timer.
    pub is_counter: bool,
}

impl CsrDescriptor {
    const fn new(addr: u16, name: &'static str, access: CsrAccess, desc: &'static str) -> Self {
        Self {
            id: CsrId(addr),
            name,
            access,
            desc,
            is_counter: false,
        }
    }

    const fn counter(mut self) -> Self {
        self.is_counter = true;
        self
    }
}

// ---------------------------------------------------------------------------
// Well-known CSR table
// ---------------------------------------------------------------------------

/// All well-known RISC-V CSRs (subset of the full 4096-entry space).
pub static KNOWN_CSRS: &[CsrDescriptor] = &[
    // ── User-mode CSRs ────────────────────────────────────────────────────────
    CsrDescriptor::new(
        0x000,
        "ustatus",
        CsrAccess::ReadWriteUser,
        "User status register",
    ),
    CsrDescriptor::new(
        0x004,
        "uie",
        CsrAccess::ReadWriteUser,
        "User interrupt-enable register",
    ),
    CsrDescriptor::new(
        0x005,
        "utvec",
        CsrAccess::ReadWriteUser,
        "User trap handler base address",
    ),
    CsrDescriptor::new(
        0x040,
        "uscratch",
        CsrAccess::ReadWriteUser,
        "Scratch register for user trap handlers",
    ),
    CsrDescriptor::new(
        0x041,
        "uepc",
        CsrAccess::ReadWriteUser,
        "User exception program counter",
    ),
    CsrDescriptor::new(0x042, "ucause", CsrAccess::ReadWriteUser, "User trap cause"),
    CsrDescriptor::new(
        0x043,
        "utval",
        CsrAccess::ReadWriteUser,
        "User bad address or instruction",
    ),
    CsrDescriptor::new(
        0x044,
        "uip",
        CsrAccess::ReadWriteUser,
        "User interrupt pending",
    ),
    // User-level counters (read-only in user mode)
    CsrDescriptor::new(
        0xC00,
        "cycle",
        CsrAccess::ReadOnly,
        "Cycle counter for RDCYCLE",
    )
    .counter(),
    CsrDescriptor::new(0xC01, "time", CsrAccess::ReadOnly, "Timer for RDTIME").counter(),
    CsrDescriptor::new(
        0xC02,
        "instret",
        CsrAccess::ReadOnly,
        "Instructions-retired counter for RDINSTRET",
    )
    .counter(),
    CsrDescriptor::new(
        0xC03,
        "hpmcounter3",
        CsrAccess::ReadOnly,
        "Performance monitoring counter 3",
    )
    .counter(),
    CsrDescriptor::new(
        0xC04,
        "hpmcounter4",
        CsrAccess::ReadOnly,
        "Performance monitoring counter 4",
    )
    .counter(),
    CsrDescriptor::new(
        0xC80,
        "cycleh",
        CsrAccess::ReadOnly,
        "Upper 32 bits of cycle (RV32)",
    )
    .counter(),
    CsrDescriptor::new(
        0xC81,
        "timeh",
        CsrAccess::ReadOnly,
        "Upper 32 bits of time (RV32)",
    )
    .counter(),
    CsrDescriptor::new(
        0xC82,
        "instreth",
        CsrAccess::ReadOnly,
        "Upper 32 bits of instret (RV32)",
    )
    .counter(),
    // ── Supervisor-mode CSRs ─────────────────────────────────────────────────
    CsrDescriptor::new(
        0x100,
        "sstatus",
        CsrAccess::ReadWriteSupervisor,
        "Supervisor status register",
    ),
    CsrDescriptor::new(
        0x102,
        "sedeleg",
        CsrAccess::ReadWriteSupervisor,
        "Supervisor exception delegation register",
    ),
    CsrDescriptor::new(
        0x103,
        "sideleg",
        CsrAccess::ReadWriteSupervisor,
        "Supervisor interrupt delegation register",
    ),
    CsrDescriptor::new(
        0x104,
        "sie",
        CsrAccess::ReadWriteSupervisor,
        "Supervisor interrupt-enable register",
    ),
    CsrDescriptor::new(
        0x105,
        "stvec",
        CsrAccess::ReadWriteSupervisor,
        "Supervisor trap handler base address",
    ),
    CsrDescriptor::new(
        0x106,
        "scounteren",
        CsrAccess::ReadWriteSupervisor,
        "Supervisor counter enable",
    ),
    CsrDescriptor::new(
        0x140,
        "sscratch",
        CsrAccess::ReadWriteSupervisor,
        "Scratch register for supervisor trap handlers",
    ),
    CsrDescriptor::new(
        0x141,
        "sepc",
        CsrAccess::ReadWriteSupervisor,
        "Supervisor exception program counter",
    ),
    CsrDescriptor::new(
        0x142,
        "scause",
        CsrAccess::ReadWriteSupervisor,
        "Supervisor trap cause",
    ),
    CsrDescriptor::new(
        0x143,
        "stval",
        CsrAccess::ReadWriteSupervisor,
        "Supervisor bad address or instruction",
    ),
    CsrDescriptor::new(
        0x144,
        "sip",
        CsrAccess::ReadWriteSupervisor,
        "Supervisor interrupt pending",
    ),
    CsrDescriptor::new(
        0x180,
        "satp",
        CsrAccess::ReadWriteSupervisor,
        "Supervisor address translation and protection",
    ),
    // Supervisor-mode read-only
    CsrDescriptor::new(
        0xD00,
        "scycle",
        CsrAccess::ReadOnlySupervisor,
        "Supervisor cycle counter alias",
    ),
    // ── Hypervisor CSRs ───────────────────────────────────────────────────────
    CsrDescriptor::new(
        0x200,
        "vsstatus",
        CsrAccess::ReadWriteHypervisor,
        "Virtual supervisor status register",
    ),
    CsrDescriptor::new(
        0x204,
        "vsie",
        CsrAccess::ReadWriteHypervisor,
        "Virtual supervisor interrupt-enable register",
    ),
    CsrDescriptor::new(
        0x205,
        "vstvec",
        CsrAccess::ReadWriteHypervisor,
        "Virtual supervisor trap handler base address",
    ),
    CsrDescriptor::new(
        0x240,
        "vsscratch",
        CsrAccess::ReadWriteHypervisor,
        "Virtual supervisor scratch register",
    ),
    CsrDescriptor::new(
        0x241,
        "vsepc",
        CsrAccess::ReadWriteHypervisor,
        "Virtual supervisor exception PC",
    ),
    CsrDescriptor::new(
        0x242,
        "vscause",
        CsrAccess::ReadWriteHypervisor,
        "Virtual supervisor trap cause",
    ),
    CsrDescriptor::new(
        0x243,
        "vstval",
        CsrAccess::ReadWriteHypervisor,
        "Virtual supervisor bad address",
    ),
    CsrDescriptor::new(
        0x244,
        "vsip",
        CsrAccess::ReadWriteHypervisor,
        "Virtual supervisor interrupt pending",
    ),
    CsrDescriptor::new(
        0x280,
        "vsatp",
        CsrAccess::ReadWriteHypervisor,
        "Virtual supervisor address translation",
    ),
    CsrDescriptor::new(
        0x600,
        "hstatus",
        CsrAccess::ReadWriteHypervisor,
        "Hypervisor status register",
    ),
    CsrDescriptor::new(
        0x602,
        "hedeleg",
        CsrAccess::ReadWriteHypervisor,
        "Hypervisor exception delegation",
    ),
    CsrDescriptor::new(
        0x603,
        "hideleg",
        CsrAccess::ReadWriteHypervisor,
        "Hypervisor interrupt delegation",
    ),
    CsrDescriptor::new(
        0x604,
        "hie",
        CsrAccess::ReadWriteHypervisor,
        "Hypervisor interrupt-enable",
    ),
    CsrDescriptor::new(
        0x606,
        "hcounteren",
        CsrAccess::ReadWriteHypervisor,
        "Hypervisor counter enable",
    ),
    CsrDescriptor::new(
        0x607,
        "hgeie",
        CsrAccess::ReadWriteHypervisor,
        "Hypervisor guest external interrupt enable",
    ),
    CsrDescriptor::new(
        0x643,
        "htval",
        CsrAccess::ReadWriteHypervisor,
        "Hypervisor bad guest physical address",
    ),
    CsrDescriptor::new(
        0x644,
        "hip",
        CsrAccess::ReadWriteHypervisor,
        "Hypervisor interrupt pending",
    ),
    CsrDescriptor::new(
        0x645,
        "hvip",
        CsrAccess::ReadWriteHypervisor,
        "Hypervisor virtual interrupt pending",
    ),
    CsrDescriptor::new(
        0x64A,
        "htinst",
        CsrAccess::ReadWriteHypervisor,
        "Hypervisor trap instruction",
    ),
    CsrDescriptor::new(
        0x680,
        "hgatp",
        CsrAccess::ReadWriteHypervisor,
        "Hypervisor guest address translation",
    ),
    // ── Machine-mode CSRs ────────────────────────────────────────────────────
    CsrDescriptor::new(
        0x300,
        "mstatus",
        CsrAccess::ReadWriteMachine,
        "Machine status register",
    ),
    CsrDescriptor::new(
        0x301,
        "misa",
        CsrAccess::ReadWriteMachine,
        "ISA and extensions",
    ),
    CsrDescriptor::new(
        0x302,
        "medeleg",
        CsrAccess::ReadWriteMachine,
        "Machine exception delegation register",
    ),
    CsrDescriptor::new(
        0x303,
        "mideleg",
        CsrAccess::ReadWriteMachine,
        "Machine interrupt delegation register",
    ),
    CsrDescriptor::new(
        0x304,
        "mie",
        CsrAccess::ReadWriteMachine,
        "Machine interrupt-enable register",
    ),
    CsrDescriptor::new(
        0x305,
        "mtvec",
        CsrAccess::ReadWriteMachine,
        "Machine trap-handler base address",
    ),
    CsrDescriptor::new(
        0x306,
        "mcounteren",
        CsrAccess::ReadWriteMachine,
        "Machine counter enable",
    ),
    CsrDescriptor::new(
        0x310,
        "mstatush",
        CsrAccess::ReadWriteMachine,
        "Upper 32 bits of mstatus (RV32)",
    ),
    CsrDescriptor::new(
        0x320,
        "mcountinhibit",
        CsrAccess::ReadWriteMachine,
        "Machine counter-inhibit register",
    ),
    // Machine performance-monitoring event selectors
    CsrDescriptor::new(
        0x323,
        "mhpmevent3",
        CsrAccess::ReadWriteMachine,
        "Machine performance-monitoring event selector 3",
    ),
    CsrDescriptor::new(
        0x324,
        "mhpmevent4",
        CsrAccess::ReadWriteMachine,
        "Machine performance-monitoring event selector 4",
    ),
    // Scratch / EPC / cause / val / IP
    CsrDescriptor::new(
        0x340,
        "mscratch",
        CsrAccess::ReadWriteMachine,
        "Scratch register for machine trap handlers",
    ),
    CsrDescriptor::new(
        0x341,
        "mepc",
        CsrAccess::ReadWriteMachine,
        "Machine exception program counter",
    ),
    CsrDescriptor::new(
        0x342,
        "mcause",
        CsrAccess::ReadWriteMachine,
        "Machine trap cause",
    ),
    CsrDescriptor::new(
        0x343,
        "mtval",
        CsrAccess::ReadWriteMachine,
        "Machine bad address or instruction",
    ),
    CsrDescriptor::new(
        0x344,
        "mip",
        CsrAccess::ReadWriteMachine,
        "Machine interrupt pending",
    ),
    CsrDescriptor::new(
        0x34A,
        "mtinst",
        CsrAccess::ReadWriteMachine,
        "Machine trap instruction",
    ),
    CsrDescriptor::new(
        0x34B,
        "mtval2",
        CsrAccess::ReadWriteMachine,
        "Machine bad guest physical address",
    ),
    // Physical memory protection
    CsrDescriptor::new(
        0x3A0,
        "pmpcfg0",
        CsrAccess::ReadWriteMachine,
        "Physical memory protection config 0",
    ),
    CsrDescriptor::new(
        0x3A1,
        "pmpcfg1",
        CsrAccess::ReadWriteMachine,
        "Physical memory protection config 1 (RV32)",
    ),
    CsrDescriptor::new(
        0x3A2,
        "pmpcfg2",
        CsrAccess::ReadWriteMachine,
        "Physical memory protection config 2",
    ),
    CsrDescriptor::new(
        0x3B0,
        "pmpaddr0",
        CsrAccess::ReadWriteMachine,
        "Physical memory protection address register 0",
    ),
    CsrDescriptor::new(
        0x3B1,
        "pmpaddr1",
        CsrAccess::ReadWriteMachine,
        "Physical memory protection address register 1",
    ),
    CsrDescriptor::new(
        0x3B2,
        "pmpaddr2",
        CsrAccess::ReadWriteMachine,
        "Physical memory protection address register 2",
    ),
    CsrDescriptor::new(
        0x3B3,
        "pmpaddr3",
        CsrAccess::ReadWriteMachine,
        "Physical memory protection address register 3",
    ),
    // Machine counters
    CsrDescriptor::new(
        0xB00,
        "mcycle",
        CsrAccess::ReadWriteMachine,
        "Machine cycle counter",
    )
    .counter(),
    CsrDescriptor::new(
        0xB02,
        "minstret",
        CsrAccess::ReadWriteMachine,
        "Machine instructions-retired counter",
    )
    .counter(),
    CsrDescriptor::new(
        0xB03,
        "mhpmcounter3",
        CsrAccess::ReadWriteMachine,
        "Machine performance-monitoring counter 3",
    )
    .counter(),
    CsrDescriptor::new(
        0xB80,
        "mcycleh",
        CsrAccess::ReadWriteMachine,
        "Upper 32 bits of mcycle (RV32)",
    )
    .counter(),
    CsrDescriptor::new(
        0xB82,
        "minstreth",
        CsrAccess::ReadWriteMachine,
        "Upper 32 bits of minstret (RV32)",
    )
    .counter(),
    // Machine read-only
    CsrDescriptor::new(0xF11, "mvendorid", CsrAccess::ReadOnlyMachine, "Vendor ID"),
    CsrDescriptor::new(
        0xF12,
        "marchid",
        CsrAccess::ReadOnlyMachine,
        "Architecture ID",
    ),
    CsrDescriptor::new(
        0xF13,
        "mimpid",
        CsrAccess::ReadOnlyMachine,
        "Implementation ID",
    ),
    CsrDescriptor::new(
        0xF14,
        "mhartid",
        CsrAccess::ReadOnlyMachine,
        "Hardware thread ID",
    ),
    CsrDescriptor::new(
        0xF15,
        "mconfigptr",
        CsrAccess::ReadOnlyMachine,
        "Pointer to configuration data structure",
    ),
    // ── Debug CSRs ────────────────────────────────────────────────────────────
    CsrDescriptor::new(
        0x7A0,
        "tselect",
        CsrAccess::Debug,
        "Trigger select register",
    ),
    CsrDescriptor::new(0x7A1, "tdata1", CsrAccess::Debug, "Trigger data register 1"),
    CsrDescriptor::new(0x7A2, "tdata2", CsrAccess::Debug, "Trigger data register 2"),
    CsrDescriptor::new(0x7A3, "tdata3", CsrAccess::Debug, "Trigger data register 3"),
    CsrDescriptor::new(
        0x7A8,
        "mcontext",
        CsrAccess::Debug,
        "Machine-mode context register",
    ),
    CsrDescriptor::new(
        0x7B0,
        "dcsr",
        CsrAccess::Debug,
        "Debug control and status register",
    ),
    CsrDescriptor::new(0x7B1, "dpc", CsrAccess::Debug, "Debug PC"),
    CsrDescriptor::new(
        0x7B2,
        "dscratch0",
        CsrAccess::Debug,
        "Debug scratch register 0",
    ),
    CsrDescriptor::new(
        0x7B3,
        "dscratch1",
        CsrAccess::Debug,
        "Debug scratch register 1",
    ),
];

// ---------------------------------------------------------------------------
// CsrRegisterFile — the complete runtime register file
// ---------------------------------------------------------------------------

/// Runtime RISC-V CSR register file.
///
/// Holds values for all 4096 possible CSR addresses.  On a fresh instance
/// all values are zero.  Read/write access is validated against the
/// [`CsrDescriptor`] for well-known CSRs.
pub struct RiscVCsr {
    /// Dense value array: index = CSR address.
    values: [u64; 4096],
    /// Pre-built lookup map from address → descriptor index in `KNOWN_CSRS`.
    lookup: HashMap<u16, usize>,
}

impl std::fmt::Debug for RiscVCsr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RiscVCsr")
            .field("known_csr_count", &self.lookup.len())
            .finish_non_exhaustive()
    }
}

impl RiscVCsr {
    /// Create a new zero-initialised CSR file.
    #[must_use]
    pub fn new() -> Self {
        let mut lookup = HashMap::with_capacity(KNOWN_CSRS.len());
        for (i, desc) in KNOWN_CSRS.iter().enumerate() {
            lookup.insert(desc.id.0, i);
        }
        Self {
            values: ZERO_CSR_FILE,
            lookup,
        }
    }

    /// Read the current value of a CSR by address.
    ///
    /// Returns `None` if `addr > 0xFFF`.
    #[must_use]
    pub const fn read(&self, addr: u16) -> Option<u64> {
        if addr > 0xFFF {
            return None;
        }
        Some(self.values[addr as usize])
    }

    /// Write a value to a CSR.
    ///
    /// # Errors
    ///
    /// Returns `Err` if:
    /// - The address is out of range.
    /// - The CSR is marked read-only in `KNOWN_CSRS`.
    pub fn write(&mut self, addr: u16, value: u64) -> Result<(), CsrError> {
        if addr > 0xFFF {
            return Err(CsrError::InvalidAddress(addr));
        }
        if let Some(&idx) = self.lookup.get(&addr) {
            let desc = &KNOWN_CSRS[idx];
            if !desc.access.is_writable() {
                return Err(CsrError::ReadOnly(addr, desc.name));
            }
        }
        // Validate read-only-by-encoding
        let id = CsrId(addr);
        if id.is_read_only_by_encoding() && let Some(&idx) = self.lookup.get(&addr) {
            let desc = &KNOWN_CSRS[idx];
            return Err(CsrError::ReadOnly(addr, desc.name));
        }
        self.values[addr as usize] = value;
        Ok(())
    }

    /// Look up the descriptor for a CSR address.
    #[must_use]
    pub fn descriptor(&self, addr: u16) -> Option<&'static CsrDescriptor> {
        self.lookup.get(&addr).map(|&i| &KNOWN_CSRS[i])
    }

    /// Return the name of a CSR, or a hex string if unknown.
    #[must_use]
    pub fn name(&self, addr: u16) -> String {
        self.descriptor(addr).map_or_else(|| format!("csr_{addr:#05x}"), |d| d.name.to_string())
    }

    /// Iterate over all well-known CSR descriptors.
    pub fn known_csrs() -> impl Iterator<Item = &'static CsrDescriptor> {
        KNOWN_CSRS.iter()
    }
}

impl Default for RiscVCsr {
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for CSR operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsrError {
    /// Address > 0xFFF.
    InvalidAddress(u16),
    /// Attempted write to a read-only CSR.
    ReadOnly(u16, &'static str),
    /// Insufficient privilege.
    InsufficientPrivilege {
        addr: u16,
        required: u8,
        current: u8,
    },
}

impl std::fmt::Display for CsrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAddress(a) => write!(f, "invalid CSR address {a:#05x}"),
            Self::ReadOnly(a, name) => write!(f, "CSR {name} ({a:#05x}) is read-only"),
            Self::InsufficientPrivilege {
                addr,
                required,
                current,
            } => write!(
                f,
                "CSR {addr:#05x} requires privilege {required}, current {current}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// McauseDecoder
// ---------------------------------------------------------------------------

/// Exception cause code (mcause/scause).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionCode {
    InstructionAddressMisaligned,
    InstructionAccessFault,
    IllegalInstruction,
    Breakpoint,
    LoadAddressMisaligned,
    LoadAccessFault,
    StoreAddressMisaligned,
    StoreAccessFault,
    EnvironmentCallFromU,
    EnvironmentCallFromS,
    EnvironmentCallFromM,
    InstructionPageFault,
    LoadPageFault,
    StorePageFault,
    GuestInstructionPageFault,
    GuestLoadPageFault,
    VirtualInstruction,
    GuestStorePageFault,
    Unknown(u64),
}

/// Interrupt cause code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptCode {
    UserSoftware,
    SupervisorSoftware,
    MachineSoftware,
    UserTimer,
    SupervisorTimer,
    MachineTimer,
    UserExternal,
    SupervisorExternal,
    MachineExternal,
    GuestExternal,
    Unknown(u64),
}

/// Decode mcause / scause register value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McauseDecode {
    Exception(ExceptionCode),
    Interrupt(InterruptCode),
}

/// Decoder for the `mcause` / `scause` register.
pub struct McauseDecoder;

impl McauseDecoder {
    /// Decode a 64-bit mcause value.
    #[must_use]
    pub const fn decode_64(value: u64) -> McauseDecode {
        let is_interrupt = (value >> 63) & 1 == 1;
        let code = value & 0x7FFF_FFFF_FFFF_FFFF;
        if is_interrupt {
            McauseDecode::Interrupt(match code {
                0 => InterruptCode::UserSoftware,
                1 => InterruptCode::SupervisorSoftware,
                3 => InterruptCode::MachineSoftware,
                4 => InterruptCode::UserTimer,
                5 => InterruptCode::SupervisorTimer,
                7 => InterruptCode::MachineTimer,
                8 => InterruptCode::UserExternal,
                9 => InterruptCode::SupervisorExternal,
                11 => InterruptCode::MachineExternal,
                12 => InterruptCode::GuestExternal,
                c => InterruptCode::Unknown(c),
            })
        } else {
            McauseDecode::Exception(match code {
                0 => ExceptionCode::InstructionAddressMisaligned,
                1 => ExceptionCode::InstructionAccessFault,
                2 => ExceptionCode::IllegalInstruction,
                3 => ExceptionCode::Breakpoint,
                4 => ExceptionCode::LoadAddressMisaligned,
                5 => ExceptionCode::LoadAccessFault,
                6 => ExceptionCode::StoreAddressMisaligned,
                7 => ExceptionCode::StoreAccessFault,
                8 => ExceptionCode::EnvironmentCallFromU,
                9 => ExceptionCode::EnvironmentCallFromS,
                11 => ExceptionCode::EnvironmentCallFromM,
                12 => ExceptionCode::InstructionPageFault,
                13 => ExceptionCode::LoadPageFault,
                15 => ExceptionCode::StorePageFault,
                20 => ExceptionCode::GuestInstructionPageFault,
                21 => ExceptionCode::GuestLoadPageFault,
                22 => ExceptionCode::VirtualInstruction,
                23 => ExceptionCode::GuestStorePageFault,
                c => ExceptionCode::Unknown(c),
            })
        }
    }

    /// `true` if this is an interrupt.
    #[must_use]
    pub const fn is_interrupt(value: u64) -> bool {
        (value >> 63) & 1 == 1
    }

    /// `true` if this is an exception.
    #[must_use]
    pub const fn is_exception(value: u64) -> bool {
        !Self::is_interrupt(value)
    }
}

// ---------------------------------------------------------------------------
// MstatusDecoder
// ---------------------------------------------------------------------------

/// The single-bit fields of `mstatus`, kept together in one word.
///
/// Storing them as a bit image rather than a dozen separate `bool`s keeps the
/// layout identical to the register itself, and makes it impossible to pass
/// two of them to a constructor in the wrong order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MstatusFlags(u64);

impl MstatusFlags {
    /// UIE — user-mode interrupt enable.
    pub const UIE: u64 = 1 << 0;
    /// SIE — supervisor-mode interrupt enable.
    pub const SIE: u64 = 1 << 1;
    /// MIE — machine-mode interrupt enable.
    pub const MIE: u64 = 1 << 3;
    /// UPIE — user-mode prior interrupt enable.
    pub const UPIE: u64 = 1 << 4;
    /// SPIE — supervisor-mode prior interrupt enable.
    pub const SPIE: u64 = 1 << 5;
    /// MPIE — machine-mode prior interrupt enable.
    pub const MPIE: u64 = 1 << 7;
    /// MPRV — modify privilege for load/store.
    pub const MPRV: u64 = 1 << 17;
    /// SUM — supervisor access to user memory.
    pub const SUM: u64 = 1 << 18;
    /// MXR — make executable readable.
    pub const MXR: u64 = 1 << 19;
    /// TVM — trap virtual-memory management.
    pub const TVM: u64 = 1 << 20;
    /// TW — timeout wait (trap WFI below M-mode).
    pub const TW: u64 = 1 << 21;
    /// TSR — trap SRET.
    pub const TSR: u64 = 1 << 22;
    /// SD — state dirty (FS or XS dirty).
    pub const SD: u64 = 1 << 63;

    /// Every bit this type tracks.
    pub const MASK: u64 = Self::UIE
        | Self::SIE
        | Self::MIE
        | Self::UPIE
        | Self::SPIE
        | Self::MPIE
        | Self::MPRV
        | Self::SUM
        | Self::MXR
        | Self::TVM
        | Self::TW
        | Self::TSR
        | Self::SD;

    /// Keep only the single-bit fields of a raw `mstatus` value.
    #[must_use]
    pub const fn from_bits(v: u64) -> Self {
        Self(v & Self::MASK)
    }

    /// The bit image, ready to be OR-ed into a raw `mstatus` value.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// True when `bit` (one of the associated constants) is set.
    #[must_use]
    pub const fn has(self, bit: u64) -> bool {
        self.0 & bit != 0
    }

    /// A copy with `bit` set or cleared.
    #[must_use]
    pub const fn with(self, bit: u64, on: bool) -> Self {
        if on {
            Self(self.0 | bit)
        } else {
            Self(self.0 & !bit)
        }
    }
}

/// Decoded fields of the `mstatus` register (RV64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MstatusDecode {
    /// All single-bit fields, in hardware bit order.
    pub flags: MstatusFlags,
    /// SPP: Supervisor-mode previous privilege (0=U, 1=S).
    pub spp: u8,
    /// MPP: Machine-mode previous privilege (0=U, 1=S, 3=M).
    pub mpp: u8,
    /// FS: Floating-point status (0=Off, 1=Initial, 2=Clean, 3=Dirty).
    pub fs: u8,
    /// XS: User extension status.
    pub xs: u8,
}

impl MstatusDecode {
    /// UIE — user-mode interrupt enable.
    #[must_use]
    pub const fn uie(&self) -> bool {
        self.flags.has(MstatusFlags::UIE)
    }
    /// SIE — supervisor-mode interrupt enable.
    #[must_use]
    pub const fn sie(&self) -> bool {
        self.flags.has(MstatusFlags::SIE)
    }
    /// MIE — machine-mode interrupt enable.
    #[must_use]
    pub const fn mie(&self) -> bool {
        self.flags.has(MstatusFlags::MIE)
    }
    /// UPIE — user-mode prior interrupt enable.
    #[must_use]
    pub const fn upie(&self) -> bool {
        self.flags.has(MstatusFlags::UPIE)
    }
    /// SPIE — supervisor-mode prior interrupt enable.
    #[must_use]
    pub const fn spie(&self) -> bool {
        self.flags.has(MstatusFlags::SPIE)
    }
    /// MPIE — machine-mode prior interrupt enable.
    #[must_use]
    pub const fn mpie(&self) -> bool {
        self.flags.has(MstatusFlags::MPIE)
    }
    /// MPRV — modify privilege for load/store.
    #[must_use]
    pub const fn mprv(&self) -> bool {
        self.flags.has(MstatusFlags::MPRV)
    }
    /// SUM — supervisor access to user memory.
    #[must_use]
    pub const fn sum(&self) -> bool {
        self.flags.has(MstatusFlags::SUM)
    }
    /// MXR — make executable readable.
    #[must_use]
    pub const fn mxr(&self) -> bool {
        self.flags.has(MstatusFlags::MXR)
    }
    /// TVM — trap virtual-memory management.
    #[must_use]
    pub const fn tvm(&self) -> bool {
        self.flags.has(MstatusFlags::TVM)
    }
    /// TW — timeout wait.
    #[must_use]
    pub const fn tw(&self) -> bool {
        self.flags.has(MstatusFlags::TW)
    }
    /// TSR — trap SRET.
    #[must_use]
    pub const fn tsr(&self) -> bool {
        self.flags.has(MstatusFlags::TSR)
    }
    /// SD — state dirty.
    #[must_use]
    pub const fn sd(&self) -> bool {
        self.flags.has(MstatusFlags::SD)
    }
}

/// Decoder for the `mstatus` register.
pub struct MstatusDecoder;

impl MstatusDecoder {
    /// Decode a 64-bit mstatus value.
    #[must_use]
    pub const fn decode(v: u64) -> MstatusDecode {
        MstatusDecode {
            flags: MstatusFlags::from_bits(v),
            spp: ((v >> 8) & 1) as u8,
            mpp: ((v >> 11) & 3) as u8,
            fs: ((v >> 13) & 3) as u8,
            xs: ((v >> 15) & 3) as u8,
        }
    }

    /// Encode an `MstatusDecode` back to a u64.
    #[must_use]
    pub const fn encode(s: &MstatusDecode) -> u64 {
        let mut v = s.flags.bits();
        v |= (s.spp as u64) << 8;
        v |= (s.mpp as u64) << 11;
        v |= (s.fs as u64) << 13;
        v |= (s.xs as u64) << 15;
        v
    }
}

// ---------------------------------------------------------------------------
// Mtvec decoder
// ---------------------------------------------------------------------------

/// `mtvec` mode bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtvecMode {
    /// All exceptions go to BASE.
    Direct,
    /// Asynchronous exceptions to BASE+4*cause.
    Vectored,
    /// Reserved / implementation-defined.
    Reserved(u8),
}

/// Decoder for the `mtvec` CSR.
pub struct Mtvec;

impl Mtvec {
    /// Decode mode and base from a raw mtvec value.
    #[must_use]
    pub const fn decode(value: u64) -> (MtvecMode, u64) {
        let mode = (value & 0x3) as u8;
        let base = value & !0x3;
        let mode = match mode {
            0 => MtvecMode::Direct,
            1 => MtvecMode::Vectored,
            n => MtvecMode::Reserved(n),
        };
        (mode, base)
    }

    /// Build a mtvec value from mode and base.
    #[must_use]
    pub const fn encode(mode: MtvecMode, base: u64) -> u64 {
        let mode_bits = match mode {
            MtvecMode::Direct => 0u64,
            MtvecMode::Vectored => 1,
            MtvecMode::Reserved(n) => n as u64,
        };
        (base & !0x3) | mode_bits
    }

    /// Compute the handler address for the given cause.
    #[must_use]
    pub const fn handler_address(mtvec: u64, cause: u64, is_interrupt: bool) -> u64 {
        let (mode, base) = Self::decode(mtvec);
        match mode {
            MtvecMode::Vectored => {
                if is_interrupt {
                    base + 4 * (cause & 0x7FFF_FFFF_FFFF_FFFF)
                } else {
                    base
                }
            }
            MtvecMode::Direct | MtvecMode::Reserved(_) => base,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn csr() -> RiscVCsr {
        RiscVCsr::new()
    }

    // ── 1. CsrId new / display ──────────────────────────────────────────────
    #[test]
    fn test_csr_id_new_valid() {
        assert_eq!(CsrId::new(0x300), Some(CsrId(0x300)));
        assert_eq!(CsrId::new(0xFFF), Some(CsrId(0xFFF)));
        assert_eq!(CsrId::new(0x1000), None);
    }

    #[test]
    fn test_csr_id_display() {
        assert_eq!(format!("{}", CsrId(0x300)), "0x300");
        assert_eq!(format!("{}", CsrId(0xF11)), "0xf11");
    }

    #[test]
    fn test_csr_id_read_only_by_encoding() {
        // bits[11:10] = 11 → read-only
        let ro = CsrId(0xC00); // 0b1100_0000_0000 → bits[11:10]=11
        assert!(ro.is_read_only_by_encoding());
        let rw = CsrId(0x300); // 0b0011_0000_0000 → bits[11:10]=00
        assert!(!rw.is_read_only_by_encoding());
    }

    #[test]
    fn test_csr_id_privilege_from_encoding() {
        assert_eq!(CsrId(0x300).privilege_from_encoding(), 3); // bits[9:8]=11
        assert_eq!(CsrId(0x100).privilege_from_encoding(), 1); // bits[9:8]=01
        assert_eq!(CsrId(0x000).privilege_from_encoding(), 0); // bits[9:8]=00
    }

    // ── 2. KNOWN_CSRS ───────────────────────────────────────────────────────
    #[test]
    fn test_known_csrs_non_empty() {
        assert!(KNOWN_CSRS.len() >= 50);
    }

    #[test]
    fn test_known_csrs_unique_addresses() {
        let mut addrs: Vec<u16> = KNOWN_CSRS.iter().map(|d| d.id.0).collect();
        addrs.sort_unstable();
        let len = addrs.len();
        addrs.dedup();
        assert_eq!(addrs.len(), len, "duplicate CSR addresses");
    }

    #[test]
    fn test_known_csrs_mstatus_present() {
        assert!(KNOWN_CSRS.iter().any(|d| d.name == "mstatus"));
    }

    #[test]
    fn test_known_csrs_mhartid_read_only() {
        let d = KNOWN_CSRS.iter().find(|d| d.name == "mhartid").unwrap();
        assert!(!d.access.is_writable());
    }

    #[test]
    fn test_known_csrs_counters() {
        let counters: Vec<_> = KNOWN_CSRS.iter().filter(|d| d.is_counter).collect();
        assert!(!counters.is_empty());
        assert!(counters.iter().any(|d| d.name == "mcycle"));
    }

    // ── 3. CsrRegisterFile read/write ───────────────────────────────────────
    #[test]
    fn test_csr_read_zero_initial() {
        let r = csr();
        assert_eq!(r.read(0x300), Some(0));
        assert_eq!(r.read(0x341), Some(0));
    }

    #[test]
    fn test_csr_read_invalid_addr() {
        let r = csr();
        assert_eq!(r.read(0x1000), None);
    }

    #[test]
    fn test_csr_write_read_roundtrip() {
        let mut r = csr();
        r.write(0x300, 0xDEAD_BEEF).unwrap();
        assert_eq!(r.read(0x300), Some(0xDEAD_BEEF));
    }

    #[test]
    fn test_csr_write_read_only_fails() {
        let mut r = csr();
        let res = r.write(0xF11, 0x1234); // mvendorid is read-only
        assert!(matches!(res, Err(CsrError::ReadOnly(0xF11, _))));
    }

    #[test]
    fn test_csr_write_invalid_addr_fails() {
        let mut r = csr();
        assert!(matches!(
            r.write(0x1000, 0),
            Err(CsrError::InvalidAddress(0x1000))
        ));
    }

    #[test]
    fn test_csr_write_unknown_addr_ok() {
        let mut r = csr();
        // Address 0x500 is not in KNOWN_CSRS and not read-only by encoding
        r.write(0x500, 42).unwrap();
        assert_eq!(r.read(0x500), Some(42));
    }

    // ── 4. Descriptor lookup ────────────────────────────────────────────────
    #[test]
    fn test_descriptor_mstatus() {
        let r = csr();
        let d = r.descriptor(0x300).unwrap();
        assert_eq!(d.name, "mstatus");
        assert_eq!(d.id.0, 0x300);
    }

    #[test]
    fn test_descriptor_none_unknown() {
        let r = csr();
        assert!(r.descriptor(0x500).is_none());
    }

    #[test]
    fn test_csr_name_known() {
        let r = csr();
        assert_eq!(r.name(0x341), "mepc");
        assert_eq!(r.name(0x300), "mstatus");
    }

    #[test]
    fn test_csr_name_unknown() {
        let r = csr();
        let n = r.name(0x500);
        assert!(n.starts_with("csr_"));
    }

    // ── 5. CsrAccess ────────────────────────────────────────────────────────
    #[test]
    fn test_csr_access_writable() {
        assert!(CsrAccess::ReadWriteMachine.is_writable());
        assert!(!CsrAccess::ReadOnly.is_writable());
        assert!(!CsrAccess::ReadOnlyMachine.is_writable());
    }

    #[test]
    fn test_csr_access_min_privilege() {
        assert_eq!(CsrAccess::ReadWriteUser.min_privilege(), 0);
        assert_eq!(CsrAccess::ReadWriteSupervisor.min_privilege(), 1);
        assert_eq!(CsrAccess::ReadWriteMachine.min_privilege(), 3);
    }

    // ── 6. McauseDecoder ─────────────────────────────────────────────────────
    #[test]
    fn test_mcause_exception_breakpoint() {
        let d = McauseDecoder::decode_64(3);
        assert_eq!(d, McauseDecode::Exception(ExceptionCode::Breakpoint));
    }

    #[test]
    fn test_mcause_exception_ecall_m() {
        let d = McauseDecoder::decode_64(11);
        assert_eq!(
            d,
            McauseDecode::Exception(ExceptionCode::EnvironmentCallFromM)
        );
    }

    #[test]
    fn test_mcause_interrupt_machine_timer() {
        let d = McauseDecoder::decode_64((1u64 << 63) | 7);
        assert_eq!(d, McauseDecode::Interrupt(InterruptCode::MachineTimer));
    }

    #[test]
    fn test_mcause_interrupt_machine_software() {
        let d = McauseDecoder::decode_64((1u64 << 63) | 3);
        assert_eq!(d, McauseDecode::Interrupt(InterruptCode::MachineSoftware));
    }

    #[test]
    fn test_mcause_is_interrupt() {
        assert!(McauseDecoder::is_interrupt((1u64 << 63) | 5));
        assert!(!McauseDecoder::is_interrupt(2));
    }

    #[test]
    fn test_mcause_unknown_exception() {
        let d = McauseDecoder::decode_64(100);
        assert!(matches!(
            d,
            McauseDecode::Exception(ExceptionCode::Unknown(100))
        ));
    }

    // ── 7. MstatusDecoder ────────────────────────────────────────────────────
    #[test]
    fn test_mstatus_mie_bit() {
        let v = 1u64 << 3; // MIE bit
        let s = MstatusDecoder::decode(v);
        assert!(s.mie());
        assert!(!s.sie());
    }

    #[test]
    fn test_mstatus_mpp_machine() {
        let v = 0b11u64 << 11; // MPP = 3 (machine)
        let s = MstatusDecoder::decode(v);
        assert_eq!(s.mpp, 3);
    }

    #[test]
    fn test_mstatus_sd_bit() {
        let v = 1u64 << 63;
        let s = MstatusDecoder::decode(v);
        assert!(s.sd());
    }

    #[test]
    fn test_mstatus_encode_decode_roundtrip() {
        let flags = MstatusFlags::default()
            .with(MstatusFlags::SIE, true)
            .with(MstatusFlags::MIE, true)
            .with(MstatusFlags::MPIE, true)
            .with(MstatusFlags::SUM, true)
            .with(MstatusFlags::SD, true);
        let orig = MstatusDecode {
            flags,
            spp: 1,
            mpp: 3,
            fs: 2,
            xs: 0,
        };
        let enc = MstatusDecoder::encode(&orig);
        let dec = MstatusDecoder::decode(enc);
        assert_eq!(dec, orig);
    }

    // ── 8. Mtvec decoder ─────────────────────────────────────────────────────
    #[test]
    fn test_mtvec_direct_mode() {
        let (mode, base) = Mtvec::decode(0x8000_0000);
        assert_eq!(mode, MtvecMode::Direct);
        assert_eq!(base, 0x8000_0000);
    }

    #[test]
    fn test_mtvec_vectored_mode() {
        let (mode, base) = Mtvec::decode(0x8000_0001);
        assert_eq!(mode, MtvecMode::Vectored);
        assert_eq!(base, 0x8000_0000);
    }

    #[test]
    fn test_mtvec_encode_decode_roundtrip() {
        let encoded = Mtvec::encode(MtvecMode::Vectored, 0x4000_0000);
        let (mode, base) = Mtvec::decode(encoded);
        assert_eq!(mode, MtvecMode::Vectored);
        assert_eq!(base, 0x4000_0000);
    }

    #[test]
    fn test_mtvec_handler_direct() {
        let mtvec = Mtvec::encode(MtvecMode::Direct, 0x8000_0000);
        let addr = Mtvec::handler_address(mtvec, 7, true);
        assert_eq!(addr, 0x8000_0000);
    }

    #[test]
    fn test_mtvec_handler_vectored_interrupt() {
        let mtvec = Mtvec::encode(MtvecMode::Vectored, 0x8000_0000);
        let addr = Mtvec::handler_address(mtvec, 7, true);
        assert_eq!(addr, 0x8000_0000 + 4 * 7);
    }

    #[test]
    fn test_mtvec_handler_vectored_exception_uses_base() {
        let mtvec = Mtvec::encode(MtvecMode::Vectored, 0x8000_0000);
        let addr = Mtvec::handler_address(mtvec, 2, false);
        assert_eq!(addr, 0x8000_0000);
    }

    // ── 9. known_csrs iterator ───────────────────────────────────────────────
    #[test]
    fn test_known_csrs_iterator() {
        let count = RiscVCsr::known_csrs().count();
        assert_eq!(count, KNOWN_CSRS.len());
    }

    // ── 10. CSR file default ─────────────────────────────────────────────────
    #[test]
    fn test_csr_default() {
        let r = RiscVCsr::default();
        assert_eq!(r.read(0x341), Some(0));
    }

    // ── 11. Multiple writes ──────────────────────────────────────────────────
    #[test]
    fn test_multiple_writes() {
        let mut r = csr();
        r.write(0x300, 0xAABB).unwrap();
        r.write(0x341, 0xCCDD).unwrap();
        assert_eq!(r.read(0x300), Some(0xAABB));
        assert_eq!(r.read(0x341), Some(0xCCDD));
    }

    // ── Additional tests ─────────────────────────────────────────────────────

    #[test]
    fn test_csr_access_hypervisor_privilege() {
        assert_eq!(CsrAccess::ReadWriteHypervisor.min_privilege(), 2);
    }

    #[test]
    fn test_mcause_page_fault() {
        let d = McauseDecoder::decode_64(12);
        assert_eq!(
            d,
            McauseDecode::Exception(ExceptionCode::InstructionPageFault)
        );
    }

    #[test]
    fn test_mcause_store_page_fault() {
        let d = McauseDecoder::decode_64(15);
        assert_eq!(d, McauseDecode::Exception(ExceptionCode::StorePageFault));
    }

    #[test]
    fn test_mstatus_sum_mxr() {
        let v = (1u64 << 18) | (1u64 << 19); // SUM | MXR
        let s = MstatusDecoder::decode(v);
        assert!(s.sum());
        assert!(s.mxr());
    }

    #[test]
    fn test_mstatus_tsr_tw_tvm() {
        let v = (1u64 << 20) | (1u64 << 21) | (1u64 << 22);
        let s = MstatusDecoder::decode(v);
        assert!(s.tvm());
        assert!(s.tw());
        assert!(s.tsr());
    }

    #[test]
    fn test_csr_pmpaddr0_writable() {
        let r = csr();
        let d = r.descriptor(0x3B0).unwrap();
        assert!(d.access.is_writable());
    }

    #[test]
    fn test_known_csrs_debug_entries() {
        let debug: Vec<_> = KNOWN_CSRS
            .iter()
            .filter(|d| d.access == CsrAccess::Debug)
            .collect();
        assert!(!debug.is_empty());
        assert!(debug.iter().any(|d| d.name == "dcsr"));
    }

    #[test]
    fn test_csr_id_ord() {
        let a = CsrId(0x100);
        let b = CsrId(0x200);
        assert!(a < b);
    }

    #[test]
    fn test_csr_error_display() {
        let e = CsrError::InvalidAddress(0x1234);
        assert!(format!("{e}").contains("0x1234"));
        let e2 = CsrError::ReadOnly(0xF11, "mvendorid");
        assert!(format!("{e2}").contains("mvendorid"));
    }

    #[test]
    fn test_mtvec_reserved_mode() {
        let (mode, _) = Mtvec::decode(0x8000_0002);
        assert_eq!(mode, MtvecMode::Reserved(2));
    }

    #[test]
    fn test_mcause_unknown_interrupt() {
        let d = McauseDecoder::decode_64((1u64 << 63) | 0x14);
        assert!(matches!(
            d,
            McauseDecode::Interrupt(InterruptCode::Unknown(20))
        ));
    }

    #[test]
    fn test_mstatus_fs_dirty() {
        let v = 0b11u64 << 13; // FS = 3 (Dirty)
        let s = MstatusDecoder::decode(v);
        assert_eq!(s.fs, 3);
    }
}
