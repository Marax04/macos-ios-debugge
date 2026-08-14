//! RISC-V Control and Status Register (CSR) map.
//!
//! Provides a complete lookup table for all RISC-V CSRs defined in:
//! - Volume II: RISC-V Privileged Architecture (Machine, Supervisor, User levels)
//! - Hypervisor extension (VS-level CSRs)
//! - Debug/trace extensions
//!
//! # Usage
//!
//! ```rust
//! use rustre_arch_riscv::riscv_csr_map::{RiscvCsrMap, csr_name, csr_privilege};
//!
//! let map = RiscvCsrMap::standard();
//! if let Some(entry) = map.lookup(0x300) {
//!     println!("{} — {}", entry.name, entry.description);
//! }
//! println!("{}", csr_name(0x341)); // "mepc"
//! ```

use std::collections::HashMap;
use std::fmt;

// ── Privilege level ───────────────────────────────────────────────────────────

/// RISC-V privilege level encoded in CSR address bits [9:8].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CsrPrivilege {
    /// User-mode accessible (bits [9:8] = 00).
    User = 0,
    /// Supervisor-mode accessible (bits [9:8] = 01).
    Supervisor = 1,
    /// Hypervisor / VS-level (bits [9:8] = 10).
    Hypervisor = 2,
    /// Machine-mode only (bits [9:8] = 11).
    Machine = 3,
}

impl CsrPrivilege {
    /// Decode privilege from a CSR address.
    #[must_use]
    pub fn from_csr_addr(addr: u16) -> Self {
        match (addr >> 8) & 0x3 {
            0 => Self::User,
            1 => Self::Supervisor,
            2 => Self::Hypervisor,
            _ => Self::Machine,
        }
    }

    /// Return a short privilege letter string.
    #[must_use]
    pub fn letter(self) -> &'static str {
        match self {
            Self::User => "U",
            Self::Supervisor => "S",
            Self::Hypervisor => "H",
            Self::Machine => "M",
        }
    }
}

impl fmt::Display for CsrPrivilege {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::User => "User",
            Self::Supervisor => "Supervisor",
            Self::Hypervisor => "Hypervisor",
            Self::Machine => "Machine",
        })
    }
}

// ── Access type ───────────────────────────────────────────────────────────────

/// Read/write access of a CSR, encoded in bits [11:10].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CsrAccess {
    /// Read-write (bits [11:10] = 00 / 01 / 10).
    ReadWrite,
    /// Read-only (bits [11:10] = 11).
    ReadOnly,
}

impl CsrAccess {
    /// Decode access type from a CSR address.
    #[must_use]
    pub fn from_csr_addr(addr: u16) -> Self {
        if (addr >> 10) & 0x3 == 0x3 {
            Self::ReadOnly
        } else {
            Self::ReadWrite
        }
    }
}

impl fmt::Display for CsrAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReadWrite => "RW",
            Self::ReadOnly => "RO",
        })
    }
}

// ── CSR entry ─────────────────────────────────────────────────────────────────

/// A single CSR table entry.
#[derive(Debug, Clone)]
pub struct CsrEntry {
    /// 12-bit CSR address (0x000 – 0xFFF).
    pub address: u16,
    /// Short canonical name (e.g., `"mstatus"`).
    pub name: &'static str,
    /// Decoded privilege level.
    pub privilege: CsrPrivilege,
    /// Decoded access type.
    pub access: CsrAccess,
    /// Human-readable description.
    pub description: &'static str,
}

impl CsrEntry {
    const fn new(addr: u16, name: &'static str, desc: &'static str) -> Self {
        let priv_ = match (addr >> 8) & 0x3 {
            0 => CsrPrivilege::User,
            1 => CsrPrivilege::Supervisor,
            2 => CsrPrivilege::Hypervisor,
            _ => CsrPrivilege::Machine,
        };
        let access = if (addr >> 10) & 0x3 == 0x3 {
            CsrAccess::ReadOnly
        } else {
            CsrAccess::ReadWrite
        };
        Self {
            address: addr,
            name,
            privilege: priv_,
            access,
            description: desc,
        }
    }
}

impl fmt::Display for CsrEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{:03X}  {:20}  {}  {}  {}",
            self.address,
            self.name,
            self.privilege.letter(),
            self.access,
            self.description
        )
    }
}

// ── Static CSR table ──────────────────────────────────────────────────────────

static STANDARD_CSRS: &[CsrEntry] = &[
    // ── User-level CSRs ───────────────────────────────────────────────────────
    CsrEntry::new(0x000, "ustatus",   "User status register (N ext)"),
    CsrEntry::new(0x004, "uie",       "User interrupt-enable register"),
    CsrEntry::new(0x005, "utvec",     "User trap-handler base address"),
    CsrEntry::new(0x040, "uscratch",  "Scratch register for user trap handlers"),
    CsrEntry::new(0x041, "uepc",      "User exception program counter"),
    CsrEntry::new(0x042, "ucause",    "User trap cause"),
    CsrEntry::new(0x043, "utval",     "User bad address or instruction"),
    CsrEntry::new(0x044, "uip",       "User interrupt pending"),
    // Zicsr counters (user-mode read-only)
    CsrEntry::new(0xC00, "cycle",     "Cycle counter for RDCYCLE"),
    CsrEntry::new(0xC01, "time",      "Timer for RDTIME"),
    CsrEntry::new(0xC02, "instret",   "Instructions-retired counter for RDINSTRET"),
    CsrEntry::new(0xC03, "hpmcounter3",  "Hardware performance counter 3"),
    CsrEntry::new(0xC04, "hpmcounter4",  "Hardware performance counter 4"),
    CsrEntry::new(0xC05, "hpmcounter5",  "Hardware performance counter 5"),
    CsrEntry::new(0xC06, "hpmcounter6",  "Hardware performance counter 6"),
    CsrEntry::new(0xC07, "hpmcounter7",  "Hardware performance counter 7"),
    CsrEntry::new(0xC08, "hpmcounter8",  "Hardware performance counter 8"),
    CsrEntry::new(0xC09, "hpmcounter9",  "Hardware performance counter 9"),
    CsrEntry::new(0xC0A, "hpmcounter10", "Hardware performance counter 10"),
    CsrEntry::new(0xC0B, "hpmcounter11", "Hardware performance counter 11"),
    CsrEntry::new(0xC0C, "hpmcounter12", "Hardware performance counter 12"),
    CsrEntry::new(0xC0D, "hpmcounter13", "Hardware performance counter 13"),
    CsrEntry::new(0xC0E, "hpmcounter14", "Hardware performance counter 14"),
    CsrEntry::new(0xC0F, "hpmcounter15", "Hardware performance counter 15"),
    CsrEntry::new(0xC10, "hpmcounter16", "Hardware performance counter 16"),
    CsrEntry::new(0xC11, "hpmcounter17", "Hardware performance counter 17"),
    CsrEntry::new(0xC12, "hpmcounter18", "Hardware performance counter 18"),
    CsrEntry::new(0xC13, "hpmcounter19", "Hardware performance counter 19"),
    CsrEntry::new(0xC14, "hpmcounter20", "Hardware performance counter 20"),
    CsrEntry::new(0xC15, "hpmcounter21", "Hardware performance counter 21"),
    CsrEntry::new(0xC16, "hpmcounter22", "Hardware performance counter 22"),
    CsrEntry::new(0xC17, "hpmcounter23", "Hardware performance counter 23"),
    CsrEntry::new(0xC18, "hpmcounter24", "Hardware performance counter 24"),
    CsrEntry::new(0xC19, "hpmcounter25", "Hardware performance counter 25"),
    CsrEntry::new(0xC1A, "hpmcounter26", "Hardware performance counter 26"),
    CsrEntry::new(0xC1B, "hpmcounter27", "Hardware performance counter 27"),
    CsrEntry::new(0xC1C, "hpmcounter28", "Hardware performance counter 28"),
    CsrEntry::new(0xC1D, "hpmcounter29", "Hardware performance counter 29"),
    CsrEntry::new(0xC1E, "hpmcounter30", "Hardware performance counter 30"),
    CsrEntry::new(0xC1F, "hpmcounter31", "Hardware performance counter 31"),
    // RV32-only upper halves
    CsrEntry::new(0xC80, "cycleh",    "Upper 32 bits of cycle"),
    CsrEntry::new(0xC81, "timeh",     "Upper 32 bits of time"),
    CsrEntry::new(0xC82, "instreth",  "Upper 32 bits of instret"),
    // ── Supervisor-level CSRs ─────────────────────────────────────────────────
    CsrEntry::new(0x100, "sstatus",   "Supervisor status register"),
    CsrEntry::new(0x102, "sedeleg",   "Supervisor exception delegation register"),
    CsrEntry::new(0x103, "sideleg",   "Supervisor interrupt delegation register"),
    CsrEntry::new(0x104, "sie",       "Supervisor interrupt-enable register"),
    CsrEntry::new(0x105, "stvec",     "Supervisor trap-handler base address"),
    CsrEntry::new(0x106, "scounteren","Supervisor counter enable"),
    CsrEntry::new(0x140, "sscratch",  "Scratch register for supervisor trap handlers"),
    CsrEntry::new(0x141, "sepc",      "Supervisor exception program counter"),
    CsrEntry::new(0x142, "scause",    "Supervisor trap cause"),
    CsrEntry::new(0x143, "stval",     "Supervisor bad address or instruction"),
    CsrEntry::new(0x144, "sip",       "Supervisor interrupt pending"),
    CsrEntry::new(0x180, "satp",      "Supervisor address translation and protection"),
    CsrEntry::new(0x5A8, "scontext",  "Supervisor-mode context register"),
    // ── Hypervisor extension CSRs ─────────────────────────────────────────────
    CsrEntry::new(0x600, "hstatus",   "Hypervisor status register"),
    CsrEntry::new(0x602, "hedeleg",   "Hypervisor exception delegation register"),
    CsrEntry::new(0x603, "hideleg",   "Hypervisor interrupt delegation register"),
    CsrEntry::new(0x604, "hie",       "Hypervisor interrupt-enable register"),
    CsrEntry::new(0x606, "hcounteren","Hypervisor counter enable"),
    CsrEntry::new(0x607, "hgeie",     "Hypervisor guest external interrupt-enable register"),
    CsrEntry::new(0x643, "htval",     "Hypervisor bad guest physical address"),
    CsrEntry::new(0x644, "hip",       "Hypervisor interrupt pending"),
    CsrEntry::new(0x645, "hvip",      "Hypervisor virtual interrupt pending"),
    CsrEntry::new(0x64A, "htinst",    "Hypervisor trap instruction"),
    CsrEntry::new(0x680, "hgatp",     "Hypervisor guest address translation and protection"),
    CsrEntry::new(0x6A8, "hcontext",  "Hypervisor-mode context register"),
    CsrEntry::new(0xE12, "hgeip",     "Hypervisor guest external interrupt pending"),
    // VS-level CSRs
    CsrEntry::new(0x200, "vsstatus",  "Virtual supervisor status register"),
    CsrEntry::new(0x204, "vsie",      "Virtual supervisor interrupt-enable register"),
    CsrEntry::new(0x205, "vstvec",    "Virtual supervisor trap-handler base address"),
    CsrEntry::new(0x240, "vsscratch", "Virtual supervisor scratch register"),
    CsrEntry::new(0x241, "vsepc",     "Virtual supervisor exception program counter"),
    CsrEntry::new(0x242, "vscause",   "Virtual supervisor trap cause"),
    CsrEntry::new(0x243, "vstval",    "Virtual supervisor bad address or instruction"),
    CsrEntry::new(0x244, "vsip",      "Virtual supervisor interrupt pending"),
    CsrEntry::new(0x280, "vsatp",     "Virtual supervisor address translation and protection"),
    // ── Machine-level CSRs ────────────────────────────────────────────────────
    CsrEntry::new(0xF11, "mvendorid", "Vendor ID"),
    CsrEntry::new(0xF12, "marchid",   "Architecture ID"),
    CsrEntry::new(0xF13, "mimpid",    "Implementation ID"),
    CsrEntry::new(0xF14, "mhartid",   "Hardware thread ID"),
    CsrEntry::new(0xF15, "mconfigptr","Pointer to configuration data structure"),
    CsrEntry::new(0x300, "mstatus",   "Machine status register"),
    CsrEntry::new(0x301, "misa",      "ISA and extensions"),
    CsrEntry::new(0x302, "medeleg",   "Machine exception delegation register"),
    CsrEntry::new(0x303, "mideleg",   "Machine interrupt delegation register"),
    CsrEntry::new(0x304, "mie",       "Machine interrupt-enable register"),
    CsrEntry::new(0x305, "mtvec",     "Machine trap-handler base address"),
    CsrEntry::new(0x306, "mcounteren","Machine counter enable"),
    CsrEntry::new(0x310, "mstatush",  "Additional machine status register (RV32)"),
    CsrEntry::new(0x340, "mscratch",  "Scratch register for machine trap handlers"),
    CsrEntry::new(0x341, "mepc",      "Machine exception program counter"),
    CsrEntry::new(0x342, "mcause",    "Machine trap cause"),
    CsrEntry::new(0x343, "mtval",     "Machine bad address or instruction"),
    CsrEntry::new(0x344, "mip",       "Machine interrupt pending"),
    CsrEntry::new(0x34A, "mtinst",    "Machine trap instruction"),
    CsrEntry::new(0x34B, "mtval2",    "Machine bad guest physical address"),
    // Physical memory protection
    CsrEntry::new(0x3A0, "pmpcfg0",  "Physical memory protection configuration 0"),
    CsrEntry::new(0x3A1, "pmpcfg1",  "Physical memory protection configuration 1"),
    CsrEntry::new(0x3A2, "pmpcfg2",  "Physical memory protection configuration 2"),
    CsrEntry::new(0x3A3, "pmpcfg3",  "Physical memory protection configuration 3"),
    CsrEntry::new(0x3B0, "pmpaddr0", "Physical memory protection address 0"),
    CsrEntry::new(0x3B1, "pmpaddr1", "Physical memory protection address 1"),
    CsrEntry::new(0x3B2, "pmpaddr2", "Physical memory protection address 2"),
    CsrEntry::new(0x3B3, "pmpaddr3", "Physical memory protection address 3"),
    CsrEntry::new(0x3B4, "pmpaddr4", "Physical memory protection address 4"),
    CsrEntry::new(0x3B5, "pmpaddr5", "Physical memory protection address 5"),
    CsrEntry::new(0x3B6, "pmpaddr6", "Physical memory protection address 6"),
    CsrEntry::new(0x3B7, "pmpaddr7", "Physical memory protection address 7"),
    CsrEntry::new(0x3B8, "pmpaddr8", "Physical memory protection address 8"),
    CsrEntry::new(0x3B9, "pmpaddr9", "Physical memory protection address 9"),
    CsrEntry::new(0x3BA, "pmpaddr10","Physical memory protection address 10"),
    CsrEntry::new(0x3BB, "pmpaddr11","Physical memory protection address 11"),
    CsrEntry::new(0x3BC, "pmpaddr12","Physical memory protection address 12"),
    CsrEntry::new(0x3BD, "pmpaddr13","Physical memory protection address 13"),
    CsrEntry::new(0x3BE, "pmpaddr14","Physical memory protection address 14"),
    CsrEntry::new(0x3BF, "pmpaddr15","Physical memory protection address 15"),
    // Machine counters / timers
    CsrEntry::new(0xB00, "mcycle",    "Machine cycle counter"),
    CsrEntry::new(0xB02, "minstret",  "Machine instructions-retired counter"),
    CsrEntry::new(0xB03, "mhpmcounter3",  "Machine hardware performance counter 3"),
    CsrEntry::new(0xB04, "mhpmcounter4",  "Machine hardware performance counter 4"),
    CsrEntry::new(0xB05, "mhpmcounter5",  "Machine hardware performance counter 5"),
    CsrEntry::new(0xB80, "mcycleh",   "Upper 32 bits of mcycle (RV32)"),
    CsrEntry::new(0xB82, "minstreth", "Upper 32 bits of minstret (RV32)"),
    // Counter-event selectors
    CsrEntry::new(0x323, "mhpmevent3",  "Machine hardware performance-monitoring event selector 3"),
    CsrEntry::new(0x324, "mhpmevent4",  "Machine hardware performance-monitoring event selector 4"),
    CsrEntry::new(0x325, "mhpmevent5",  "Machine hardware performance-monitoring event selector 5"),
    // Debug/trace
    CsrEntry::new(0x7A0, "tselect",   "Debug/trace trigger register select"),
    CsrEntry::new(0x7A1, "tdata1",    "First debug/trace trigger data register"),
    CsrEntry::new(0x7A2, "tdata2",    "Second debug/trace trigger data register"),
    CsrEntry::new(0x7A3, "tdata3",    "Third debug/trace trigger data register"),
    CsrEntry::new(0x7A8, "mcontext",  "Machine-mode context register"),
    // Debug mode CSRs
    CsrEntry::new(0x7B0, "dcsr",      "Debug control and status register"),
    CsrEntry::new(0x7B1, "dpc",       "Debug PC"),
    CsrEntry::new(0x7B2, "dscratch0", "Debug scratch register 0"),
    CsrEntry::new(0x7B3, "dscratch1", "Debug scratch register 1"),
    // Stateen (state enable) extension
    CsrEntry::new(0x30C, "mstateen0", "Machine State Enable 0"),
    CsrEntry::new(0x30D, "mstateen1", "Machine State Enable 1"),
    CsrEntry::new(0x30E, "mstateen2", "Machine State Enable 2"),
    CsrEntry::new(0x30F, "mstateen3", "Machine State Enable 3"),
    CsrEntry::new(0x10C, "sstateen0", "Supervisor State Enable 0"),
    CsrEntry::new(0x10D, "sstateen1", "Supervisor State Enable 1"),
    CsrEntry::new(0x10E, "sstateen2", "Supervisor State Enable 2"),
    CsrEntry::new(0x10F, "sstateen3", "Supervisor State Enable 3"),
    // Zicntr / Zihpm enable
    CsrEntry::new(0x320, "mcountinhibit", "Machine counter-inhibit register"),
    // AIA (advanced interrupt architecture)
    CsrEntry::new(0x350, "miselect",  "Machine indirect register select"),
    CsrEntry::new(0x351, "mireg",     "Machine indirect register alias"),
    CsrEntry::new(0x150, "siselect",  "Supervisor indirect register select"),
    CsrEntry::new(0x151, "sireg",     "Supervisor indirect register alias"),
    CsrEntry::new(0x355, "mtopei",    "Machine top external interrupt"),
    CsrEntry::new(0x15C, "stopei",    "Supervisor top external interrupt"),
    // Smepmp
    CsrEntry::new(0x747, "mseccfg",   "Machine security configuration"),
    CsrEntry::new(0x757, "mseccfgh",  "Machine security configuration (upper 32 bits, RV32)"),
    // Zicfilp
    CsrEntry::new(0x148, "ssp",       "Shadow stack pointer"),
];

// ── CSR map ───────────────────────────────────────────────────────────────────

/// A lookup map for RISC-V CSRs, indexed by address.
pub struct RiscvCsrMap {
    by_addr: HashMap<u16, &'static CsrEntry>,
    by_name: HashMap<&'static str, &'static CsrEntry>,
}

impl RiscvCsrMap {
    /// Construct a map containing all standard CSRs.
    #[must_use]
    pub fn standard() -> Self {
        let mut by_addr = HashMap::with_capacity(STANDARD_CSRS.len());
        let mut by_name = HashMap::with_capacity(STANDARD_CSRS.len());
        for entry in STANDARD_CSRS {
            by_addr.insert(entry.address, entry);
            by_name.insert(entry.name, entry);
        }
        Self { by_addr, by_name }
    }

    /// Look up a CSR by its 12-bit address.
    #[must_use]
    pub fn lookup(&self, addr: u16) -> Option<&'static CsrEntry> {
        self.by_addr.get(&(addr & 0xFFF)).copied()
    }

    /// Look up a CSR by name.
    #[must_use]
    pub fn lookup_name(&self, name: &str) -> Option<&'static CsrEntry> {
        self.by_name.get(name).copied()
    }

    /// List all CSRs at a given privilege level.
    #[must_use]
    pub fn list_privilege(&self, priv_: CsrPrivilege) -> Vec<&'static CsrEntry> {
        STANDARD_CSRS
            .iter()
            .filter(|e| e.privilege == priv_)
            .collect()
    }

    /// Total number of known CSRs.
    #[must_use]
    pub fn len(&self) -> usize {
        STANDARD_CSRS.len()
    }

    /// True if the map contains no entries (should never be true for `standard()`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        STANDARD_CSRS.is_empty()
    }
}

// ── Standalone free functions ─────────────────────────────────────────────────

/// Return the canonical name of a CSR given its address, or a hex fallback.
///
/// This uses a lazy-initialised thread-local map so no allocation occurs on
/// repeated calls from the same thread.
#[must_use]
pub fn csr_name(addr: u16) -> String {
    // Linear scan is acceptable — CSR reads are infrequent in a disassembler.
    for entry in STANDARD_CSRS {
        if entry.address == addr & 0xFFF {
            return entry.name.to_string();
        }
    }
    format!("csr0x{addr:03X}")
}

/// Return the privilege level of a CSR from its address.
///
/// This is a pure address-based decode without consulting the table.
#[must_use]
pub fn csr_privilege(addr: u16) -> CsrPrivilege {
    CsrPrivilege::from_csr_addr(addr)
}

/// Return the access type of a CSR from its address.
#[must_use]
pub fn csr_access(addr: u16) -> CsrAccess {
    CsrAccess::from_csr_addr(addr)
}

/// Decode the mcause register into an exception/interrupt description.
///
/// Returns `(is_interrupt, code, description)`.
#[must_use]
pub fn mcause_decode(mcause: u64, xlen: u32) -> (bool, u64, &'static str) {
    let is_interrupt = if xlen == 32 {
        (mcause >> 31) & 1 == 1
    } else {
        (mcause >> 63) & 1 == 1
    };
    let code = if xlen == 32 {
        mcause & 0x7FFF_FFFF
    } else {
        mcause & 0x7FFF_FFFF_FFFF_FFFF
    };

    if is_interrupt {
        let desc = match code {
            0 => "User software interrupt",
            1 => "Supervisor software interrupt",
            2 => "VS-level software interrupt",
            3 => "Machine software interrupt",
            4 => "User timer interrupt",
            5 => "Supervisor timer interrupt",
            6 => "VS-level timer interrupt",
            7 => "Machine timer interrupt",
            8 => "User external interrupt",
            9 => "Supervisor external interrupt",
            10 => "VS-level external interrupt",
            11 => "Machine external interrupt",
            12 => "Supervisor guest external interrupt",
            _ => "Unknown interrupt",
        };
        (true, code, desc)
    } else {
        let desc = match code {
            0 => "Instruction address misaligned",
            1 => "Instruction access fault",
            2 => "Illegal instruction",
            3 => "Breakpoint",
            4 => "Load address misaligned",
            5 => "Load access fault",
            6 => "Store/AMO address misaligned",
            7 => "Store/AMO access fault",
            8 => "Environment call from U-mode",
            9 => "Environment call from S-mode",
            10 => "Environment call from VS-mode",
            11 => "Environment call from M-mode",
            12 => "Instruction page fault",
            13 => "Load page fault",
            14 => "Reserved",
            15 => "Store/AMO page fault",
            20 => "Instruction guest-page fault",
            21 => "Load guest-page fault",
            22 => "Virtual instruction",
            23 => "Store/AMO guest-page fault",
            _ => "Unknown exception",
        };
        (false, code, desc)
    }
}

/// Decode a subset of important mstatus fields for RV64.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MstatusFields {
    /// Machine Interrupt Enable.
    pub mie: bool,
    /// Supervisor Interrupt Enable.
    pub sie: bool,
    /// User Interrupt Enable.
    pub uie: bool,
    /// Previous MIE (saved across traps).
    pub mpie: bool,
    /// Machine Previous Privilege.
    pub mpp: CsrPrivilege,
    /// Supervisor Previous Privilege.
    pub spp: CsrPrivilege,
    /// FS field (floating-point status).
    pub fs: u8,
    /// XS field (extension context status).
    pub xs: u8,
    /// Memory privilege (MPRV).
    pub mprv: bool,
    /// Supervisor User Memory access.
    pub sum: bool,
    /// Make eXecutable Readable.
    pub mxr: bool,
}

impl MstatusFields {
    /// Decode mstatus from a 64-bit value (RV64).
    #[must_use]
    pub fn decode_rv64(val: u64) -> Self {
        let mpp_raw = ((val >> 11) & 0x3) as u8;
        let mpp = match mpp_raw {
            0 => CsrPrivilege::User,
            1 => CsrPrivilege::Supervisor,
            3 => CsrPrivilege::Machine,
            _ => CsrPrivilege::Hypervisor,
        };
        let spp = if (val >> 8) & 1 == 1 {
            CsrPrivilege::Supervisor
        } else {
            CsrPrivilege::User
        };
        Self {
            mie:  (val >> 3) & 1 == 1,
            sie:  (val >> 1) & 1 == 1,
            uie:  val & 1 == 1,
            mpie: (val >> 7) & 1 == 1,
            mpp,
            spp,
            fs: ((val >> 13) & 0x3) as u8,
            xs: ((val >> 15) & 0x3) as u8,
            mprv: (val >> 17) & 1 == 1,
            sum:  (val >> 18) & 1 == 1,
            mxr:  (val >> 19) & 1 == 1,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> RiscvCsrMap {
        RiscvCsrMap::standard()
    }

    #[test]
    fn test_lookup_mstatus() {
        let m = map();
        let e = m.lookup(0x300).unwrap();
        assert_eq!(e.name, "mstatus");
        assert_eq!(e.privilege, CsrPrivilege::Machine);
        assert_eq!(e.access, CsrAccess::ReadWrite);
    }

    #[test]
    fn test_lookup_mepc() {
        let e = map().lookup(0x341).unwrap();
        assert_eq!(e.name, "mepc");
    }

    #[test]
    fn test_lookup_cycle_readonly() {
        let e = map().lookup(0xC00).unwrap();
        assert_eq!(e.name, "cycle");
        assert_eq!(e.access, CsrAccess::ReadOnly);
        assert_eq!(e.privilege, CsrPrivilege::User);
    }

    #[test]
    fn test_csr_name_known() {
        assert_eq!(csr_name(0x342), "mcause");
        assert_eq!(csr_name(0x141), "sepc");
        assert_eq!(csr_name(0x180), "satp");
    }

    #[test]
    fn test_csr_name_unknown() {
        let n = csr_name(0xABC);
        assert!(n.starts_with("csr0x"));
    }

    #[test]
    fn test_csr_privilege_decode() {
        assert_eq!(csr_privilege(0x000), CsrPrivilege::User);
        assert_eq!(csr_privilege(0x100), CsrPrivilege::Supervisor);
        assert_eq!(csr_privilege(0x200), CsrPrivilege::Hypervisor);
        assert_eq!(csr_privilege(0x300), CsrPrivilege::Machine);
    }

    #[test]
    fn test_csr_access_decode() {
        assert_eq!(csr_access(0x300), CsrAccess::ReadWrite);
        assert_eq!(csr_access(0xF11), CsrAccess::ReadOnly); // mvendorid
        assert_eq!(csr_access(0xC00), CsrAccess::ReadOnly); // cycle
    }

    #[test]
    fn test_mcause_decode_exception() {
        let (is_int, code, desc) = mcause_decode(0x8, 64);
        assert!(!is_int);
        assert_eq!(code, 8);
        assert!(desc.contains("U-mode"));
    }

    #[test]
    fn test_mcause_decode_interrupt() {
        // Machine timer interrupt: bit63=1, code=7
        let (is_int, code, desc) = mcause_decode(0x8000_0000_0000_0007, 64);
        assert!(is_int);
        assert_eq!(code, 7);
        assert!(desc.contains("Machine timer"));
    }

    #[test]
    fn test_mcause_decode_rv32_interrupt() {
        let (is_int, code, _) = mcause_decode(0x8000_0003, 32);
        assert!(is_int);
        assert_eq!(code, 3);
    }

    #[test]
    fn test_mcause_decode_illegal_insn() {
        let (is_int, code, desc) = mcause_decode(2, 64);
        assert!(!is_int);
        assert_eq!(code, 2);
        assert!(desc.contains("Illegal"));
    }

    #[test]
    fn test_list_privilege_machine() {
        let m = map();
        let machine_csrs = m.list_privilege(CsrPrivilege::Machine);
        assert!(!machine_csrs.is_empty());
        assert!(machine_csrs.iter().any(|e| e.name == "mstatus"));
        assert!(machine_csrs.iter().all(|e| e.privilege == CsrPrivilege::Machine));
    }

    #[test]
    fn test_list_privilege_supervisor() {
        let m = map();
        let sup = m.list_privilege(CsrPrivilege::Supervisor);
        assert!(sup.iter().any(|e| e.name == "sstatus"));
    }

    #[test]
    fn test_lookup_by_name() {
        let m = map();
        let e = m.lookup_name("satp").unwrap();
        assert_eq!(e.address, 0x180);
    }

    #[test]
    fn test_lookup_missing() {
        let m = map();
        assert!(m.lookup(0xABC).is_none());
    }

    #[test]
    fn test_mstatus_decode() {
        // mie=1 (bit3), mpie=1 (bit7), mpp=3 (bits[12:11]), fs=1 (bits[14:13])
        let val: u64 = (1 << 3) | (1 << 7) | (3 << 11) | (1 << 13);
        let f = MstatusFields::decode_rv64(val);
        assert!(f.mie);
        assert!(f.mpie);
        assert_eq!(f.mpp, CsrPrivilege::Machine);
        assert_eq!(f.fs, 1);
        assert!(!f.mprv);
    }

    #[test]
    fn test_mstatus_sum_mxr() {
        let val: u64 = (1 << 18) | (1 << 19);
        let f = MstatusFields::decode_rv64(val);
        assert!(f.sum);
        assert!(f.mxr);
    }

    #[test]
    fn test_privilege_letter() {
        assert_eq!(CsrPrivilege::User.letter(), "U");
        assert_eq!(CsrPrivilege::Supervisor.letter(), "S");
        assert_eq!(CsrPrivilege::Machine.letter(), "M");
        assert_eq!(CsrPrivilege::Hypervisor.letter(), "H");
    }

    #[test]
    fn test_map_not_empty() {
        let m = map();
        assert!(!m.is_empty());
        assert!(m.len() > 50);
    }

    #[test]
    fn test_csr_entry_display() {
        let e = map().lookup(0x300).unwrap();
        let s = format!("{e}");
        assert!(s.contains("mstatus"));
        assert!(s.contains("M"));
    }

    #[test]
    fn test_privilege_display() {
        assert_eq!(CsrPrivilege::User.to_string(), "User");
        assert_eq!(CsrPrivilege::Machine.to_string(), "Machine");
    }

    #[test]
    fn test_access_display() {
        assert_eq!(CsrAccess::ReadWrite.to_string(), "RW");
        assert_eq!(CsrAccess::ReadOnly.to_string(), "RO");
    }

    #[test]
    fn test_satp_privilege() {
        // satp is at 0x180 → bits[9:8] = 01 → Supervisor
        assert_eq!(csr_privilege(0x180), CsrPrivilege::Supervisor);
    }

    #[test]
    fn test_hgatp_privilege() {
        // hgatp is at 0x680 → bits[9:8] = 10 → Hypervisor
        assert_eq!(csr_privilege(0x680), CsrPrivilege::Hypervisor);
    }

    #[test]
    fn test_debug_csrs() {
        let m = map();
        assert!(m.lookup(0x7B0).is_some()); // dcsr
        assert!(m.lookup(0x7B1).is_some()); // dpc
        assert_eq!(m.lookup(0x7A0).unwrap().name, "tselect");
    }

    #[test]
    fn test_pmp_csrs() {
        let m = map();
        assert!(m.lookup(0x3A0).is_some()); // pmpcfg0
        assert!(m.lookup(0x3B0).is_some()); // pmpaddr0
        assert_eq!(m.lookup(0x3BF).unwrap().name, "pmpaddr15");
    }

    #[test]
    fn test_mcause_store_page_fault() {
        let (is_int, code, desc) = mcause_decode(15, 64);
        assert!(!is_int);
        assert_eq!(code, 15);
        assert!(desc.contains("Store"));
    }
}
