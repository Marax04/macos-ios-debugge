//! MIPS Coprocessor 0 (CP0) system register definitions.
//!
//! CP0 provides the memory-management, exception, and system control registers
//! for MIPS CPUs.  This module defines every standard register across MIPS I
//! through MIPS64 Release 6, including select- and sub-register fields.
//!
//! References:
//! - MIPS32 Architecture for Programmers, Vol. III
//! - MIPS64 Architecture for Programmers, Vol. III

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Cop0Register — the primary type
// ---------------------------------------------------------------------------

/// A MIPS CP0 register identified by its (register, select) pair.
///
/// The MIPS architecture encodes CP0 registers as a 5-bit register number
/// (0–31) and a 3-bit select field (0–7).  Most registers use select 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cop0Register {
    /// CP0 register number (0–31).
    pub reg: u8,
    /// Select field (0–7).
    pub select: u8,
}

impl Cop0Register {
    /// Construct a new `Cop0Register`.
    #[must_use]
    pub const fn new(reg: u8, select: u8) -> Self {
        Self { reg, select }
    }

    /// Construct a select-0 register (the common case).
    #[must_use]
    pub const fn r(reg: u8) -> Self {
        Self::new(reg, 0)
    }
}

impl fmt::Display for Cop0Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.select == 0 {
            write!(f, "$c0r{}", self.reg)
        } else {
            write!(f, "$c0r{}/{}", self.reg, self.select)
        }
    }
}

// ---------------------------------------------------------------------------
// Well-known register constants
// ---------------------------------------------------------------------------

/// All well-known MIPS CP0 registers, grouped by functional area.
pub mod cop0 {
    use super::Cop0Register;

    // ── TLB / Memory Management ─────────────────────────────────────────────
    /// Index into the TLB array.
    pub const INDEX: Cop0Register = Cop0Register::r(0);
    /// Pseudo-random index for TLBWR.
    pub const RANDOM: Cop0Register = Cop0Register::r(1);
    /// TLB entry low-half (even page).
    pub const ENTRY_LO0: Cop0Register = Cop0Register::r(2);
    /// TLB entry low-half (odd page).
    pub const ENTRY_LO1: Cop0Register = Cop0Register::r(3);
    /// TLB context register.
    pub const CONTEXT: Cop0Register = Cop0Register::r(4);
    /// User-local register: CP0 register 4, select 2 (MIPS32r2+).
    ///
    /// Previously documented as `CONTEXT_CONFIG` in some vendor manuals; the
    /// MIPS32r2 architecture specification uses the name `UserLocal` for this
    /// encoding.  `CONTEXT_CONFIG` was an alias used under older revision names
    /// and has been removed to avoid duplicate-key confusion in decode lookups.
    pub const USER_LOCAL: Cop0Register = Cop0Register::new(4, 2);
    /// Page mask for variable TLB page sizes.
    pub const PAGE_MASK: Cop0Register = Cop0Register::r(5);
    /// Page grain (MIPS32r2+).
    pub const PAGE_GRAIN: Cop0Register = Cop0Register::new(5, 1);
    /// TLB wired boundary.
    pub const WIRED: Cop0Register = Cop0Register::r(6);
    /// Hardware write-enable (MIPS32r2+).
    pub const HW_RENA: Cop0Register = Cop0Register::new(7, 0);
    /// Bad virtual address (set on address exceptions).
    pub const BAD_VADDR: Cop0Register = Cop0Register::r(8);
    /// Bad instruction (MIPS32r5+).
    pub const BAD_INSN: Cop0Register = Cop0Register::new(8, 1);
    /// Count register (free-running timer).
    pub const COUNT: Cop0Register = Cop0Register::r(9);
    /// TLB entry hi-half (virtual page number + ASID).
    pub const ENTRY_HI: Cop0Register = Cop0Register::r(10);
    /// GuestCtl1 (virtualisation, MIPS32r5+).
    pub const GUEST_CTL1: Cop0Register = Cop0Register::new(10, 4);
    /// Timer compare register.
    pub const COMPARE: Cop0Register = Cop0Register::r(11);
    /// GuestCtl2 (virtualisation, MIPS32r5+).
    pub const GUEST_CTL2: Cop0Register = Cop0Register::new(11, 4);

    // ── Status / Control ────────────────────────────────────────────────────
    /// Processor status register.
    pub const STATUS: Cop0Register = Cop0Register::r(12);
    /// Integer ASE status (select 1).
    pub const INT_CTL: Cop0Register = Cop0Register::new(12, 1);
    /// SRS control (select 2).
    pub const SRS_CTL: Cop0Register = Cop0Register::new(12, 2);
    /// SRS map (select 3).
    pub const SRS_MAP: Cop0Register = Cop0Register::new(12, 3);
    /// GuestCtl0 (virtualisation, select 6).
    pub const GUEST_CTL0: Cop0Register = Cop0Register::new(12, 6);
    /// GuestCtl0Ext (select 7).
    pub const GUEST_CTL0_EXT: Cop0Register = Cop0Register::new(12, 7);
    /// Cause register (exception cause).
    pub const CAUSE: Cop0Register = Cop0Register::r(13);
    /// NestedExc (select 5).
    pub const NESTED_EXC: Cop0Register = Cop0Register::new(13, 5);
    /// Exception program counter.
    pub const EPC: Cop0Register = Cop0Register::r(14);
    /// NestedEPC (select 2).
    pub const NESTED_EPC: Cop0Register = Cop0Register::new(14, 2);

    // ── Identification ──────────────────────────────────────────────────────
    /// Processor identification register.
    pub const PRID: Cop0Register = Cop0Register::r(15);
    /// EBase (exception vector base address, MIPS32r2+).
    pub const EBASE: Cop0Register = Cop0Register::new(15, 1);
    /// CDMMBase (MIPS32r5+).
    pub const CDMM_BASE: Cop0Register = Cop0Register::new(15, 2);
    /// CMGCRBase (MIPS32r5+, select 3).
    pub const CMGCR_BASE: Cop0Register = Cop0Register::new(15, 3);

    // ── Cache / Config ──────────────────────────────────────────────────────
    /// Config0: processor configuration.
    pub const CONFIG0: Cop0Register = Cop0Register::r(16);
    /// Config1: cache sizes etc.
    pub const CONFIG1: Cop0Register = Cop0Register::new(16, 1);
    /// Config2: level-2 cache.
    pub const CONFIG2: Cop0Register = Cop0Register::new(16, 2);
    /// Config3: extended features.
    pub const CONFIG3: Cop0Register = Cop0Register::new(16, 3);
    /// Config4 (MIPS32r5+).
    pub const CONFIG4: Cop0Register = Cop0Register::new(16, 4);
    /// Config5 (MIPS32r5+).
    pub const CONFIG5: Cop0Register = Cop0Register::new(16, 5);
    /// Config6 (implementation-specific).
    pub const CONFIG6: Cop0Register = Cop0Register::new(16, 6);
    /// Config7 (implementation-specific).
    pub const CONFIG7: Cop0Register = Cop0Register::new(16, 7);
    /// Load linked address.
    pub const LLADDR: Cop0Register = Cop0Register::r(17);
    /// MAAR (memory accessibility attribute register, MIPS32r5+, sel 1).
    pub const MAAR: Cop0Register = Cop0Register::new(17, 1);
    /// MAARi (indirect access).
    pub const MAARI: Cop0Register = Cop0Register::new(17, 2);

    // ── Watchpoints ────────────────────────────────────────────────────────
    /// Watch lo (data watchpoint address low).
    pub const WATCH_LO: Cop0Register = Cop0Register::r(18);
    /// Watch hi (data watchpoint address high).
    pub const WATCH_HI: Cop0Register = Cop0Register::r(19);

    // ── MIPS64 TLB context ──────────────────────────────────────────────────
    /// XContext (64-bit context register, MIPS64).
    pub const XCONTEXT: Cop0Register = Cop0Register::r(20);

    // ── Debug ───────────────────────────────────────────────────────────────
    /// Debug control/status register (EJTAG).
    pub const DEBUG: Cop0Register = Cop0Register::r(23);
    /// Debug2 (select 6).
    pub const DEBUG2: Cop0Register = Cop0Register::new(23, 6);
    /// Debug exception PC.
    pub const DEPC: Cop0Register = Cop0Register::r(24);

    // ── Performance counters ────────────────────────────────────────────────
    /// Performance control register 0.
    pub const PERF_CTL0: Cop0Register = Cop0Register::r(25);
    /// Performance counter register 0 (select 1).
    pub const PERF_CNT0: Cop0Register = Cop0Register::new(25, 1);
    /// Performance control register 1 (select 2).
    pub const PERF_CTL1: Cop0Register = Cop0Register::new(25, 2);
    /// Performance counter register 1 (select 3).
    pub const PERF_CNT1: Cop0Register = Cop0Register::new(25, 3);

    // ── Cache / ECC ─────────────────────────────────────────────────────────
    /// Cache error register.
    pub const CACHE_ERR: Cop0Register = Cop0Register::r(27);
    /// TagLo (cache tag, select 0).
    pub const TAG_LO: Cop0Register = Cop0Register::r(28);
    /// DataLo (cache data, select 1).
    pub const DATA_LO: Cop0Register = Cop0Register::new(28, 1);
    /// TagHi (select 0).
    pub const TAG_HI: Cop0Register = Cop0Register::r(29);
    /// DataHi (select 1).
    pub const DATA_HI: Cop0Register = Cop0Register::new(29, 1);
    /// Error exception PC.
    pub const ERROR_EPC: Cop0Register = Cop0Register::r(30);
    /// DESAVE (debug scratch, EJTAG).
    pub const DESAVE: Cop0Register = Cop0Register::r(31);
}

// ---------------------------------------------------------------------------
// Cop0Entry — metadata for a register
// ---------------------------------------------------------------------------

/// Metadata associated with a CP0 register.
#[derive(Debug, Clone)]
pub struct Cop0Entry {
    /// Architectural register.
    pub reg: Cop0Register,
    /// Short symbolic name (e.g. `"Status"`).
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Minimum MIPS revision that introduced this register.
    pub introduced_in: MipsRevision,
    /// Whether the register is writable.
    pub writable: bool,
    /// Whether the register is readable.
    pub readable: bool,
}

/// MIPS architecture revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MipsRevision {
    Mips1,
    Mips2,
    Mips3,
    Mips4,
    Mips32,
    Mips32r2,
    Mips32r5,
    Mips32r6,
    Mips64,
    Mips64r2,
    Mips64r6,
}

impl fmt::Display for MipsRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Mips1 => "MIPS I",
            Self::Mips2 => "MIPS II",
            Self::Mips3 => "MIPS III",
            Self::Mips4 => "MIPS IV",
            Self::Mips32 => "MIPS32",
            Self::Mips32r2 => "MIPS32r2",
            Self::Mips32r5 => "MIPS32r5",
            Self::Mips32r6 => "MIPS32r6",
            Self::Mips64 => "MIPS64",
            Self::Mips64r2 => "MIPS64r2",
            Self::Mips64r6 => "MIPS64r6",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// cop0_name — canonical name lookup
// ---------------------------------------------------------------------------

/// Return the canonical symbolic name of a CP0 register, or `None` if
/// unrecognised.
///
/// # Examples
///
/// ```rust,ignore
/// assert_eq!(cop0_name(Cop0Register::r(12)), Some("Status"));
/// assert_eq!(cop0_name(Cop0Register::new(12, 1)), Some("IntCtl"));
/// ```
#[must_use]
pub fn cop0_name(reg: Cop0Register) -> Option<&'static str> {
    CP0_NAME_TABLE.get(&reg).copied()
}

/// Return the description for a CP0 register, or a generic placeholder.
#[must_use]
pub fn cop0_description(reg: Cop0Register) -> &'static str {
    CP0_DESC_TABLE.get(&reg).copied().unwrap_or("Unknown CP0 register")
}

// ---------------------------------------------------------------------------
// Standard CP0 register database
// ---------------------------------------------------------------------------

/// Build the full standard CP0 entry database.
#[must_use]
pub fn standard_cop0_entries() -> Vec<Cop0Entry> {
    use cop0::*;
    vec![
        Cop0Entry { reg: INDEX,         name: "Index",      description: "TLB index",                         introduced_in: MipsRevision::Mips1,   writable: true,  readable: true },
        Cop0Entry { reg: RANDOM,        name: "Random",     description: "Pseudo-random TLB index",           introduced_in: MipsRevision::Mips1,   writable: false, readable: true },
        Cop0Entry { reg: ENTRY_LO0,     name: "EntryLo0",   description: "TLB entry low (even page)",         introduced_in: MipsRevision::Mips3,   writable: true,  readable: true },
        Cop0Entry { reg: ENTRY_LO1,     name: "EntryLo1",   description: "TLB entry low (odd page)",          introduced_in: MipsRevision::Mips3,   writable: true,  readable: true },
        Cop0Entry { reg: CONTEXT,       name: "Context",    description: "TLB context pointer",               introduced_in: MipsRevision::Mips1,   writable: true,  readable: true },
        Cop0Entry { reg: PAGE_MASK,     name: "PageMask",   description: "Variable TLB page size mask",       introduced_in: MipsRevision::Mips3,   writable: true,  readable: true },
        Cop0Entry { reg: PAGE_GRAIN,    name: "PageGrain",  description: "Fine-grained page attributes",      introduced_in: MipsRevision::Mips32r2,writable: true,  readable: true },
        Cop0Entry { reg: WIRED,         name: "Wired",      description: "TLB wired boundary",                introduced_in: MipsRevision::Mips3,   writable: true,  readable: true },
        Cop0Entry { reg: BAD_VADDR,     name: "BadVAddr",   description: "Faulting virtual address",          introduced_in: MipsRevision::Mips1,   writable: false, readable: true },
        Cop0Entry { reg: COUNT,         name: "Count",      description: "Free-running processor timer",      introduced_in: MipsRevision::Mips32,  writable: true,  readable: true },
        Cop0Entry { reg: ENTRY_HI,      name: "EntryHi",    description: "TLB entry hi (VPN2 + ASID)",        introduced_in: MipsRevision::Mips1,   writable: true,  readable: true },
        Cop0Entry { reg: COMPARE,       name: "Compare",    description: "Timer compare / interrupt trigger",  introduced_in: MipsRevision::Mips32,  writable: true,  readable: true },
        Cop0Entry { reg: STATUS,        name: "Status",     description: "Processor status register",         introduced_in: MipsRevision::Mips1,   writable: true,  readable: true },
        Cop0Entry { reg: INT_CTL,       name: "IntCtl",     description: "Interrupt control (Status sel 1)",  introduced_in: MipsRevision::Mips32r2,writable: true,  readable: true },
        Cop0Entry { reg: SRS_CTL,       name: "SRSCtl",     description: "Shadow register set control",       introduced_in: MipsRevision::Mips32r2,writable: true,  readable: true },
        Cop0Entry { reg: SRS_MAP,       name: "SRSMap",     description: "Shadow register set map",           introduced_in: MipsRevision::Mips32r2,writable: true,  readable: true },
        Cop0Entry { reg: CAUSE,         name: "Cause",      description: "Exception cause register",          introduced_in: MipsRevision::Mips1,   writable: true,  readable: true },
        Cop0Entry { reg: EPC,           name: "EPC",        description: "Exception program counter",         introduced_in: MipsRevision::Mips1,   writable: true,  readable: true },
        Cop0Entry { reg: PRID,          name: "PRId",       description: "Processor revision identifier",     introduced_in: MipsRevision::Mips1,   writable: false, readable: true },
        Cop0Entry { reg: EBASE,         name: "EBase",      description: "Exception vector base address",     introduced_in: MipsRevision::Mips32r2,writable: true,  readable: true },
        Cop0Entry { reg: CONFIG0,       name: "Config0",    description: "Processor configuration",           introduced_in: MipsRevision::Mips32,  writable: true,  readable: true },
        Cop0Entry { reg: CONFIG1,       name: "Config1",    description: "Cache sizes and coprocessors",      introduced_in: MipsRevision::Mips32,  writable: false, readable: true },
        Cop0Entry { reg: CONFIG2,       name: "Config2",    description: "Level-2 cache configuration",       introduced_in: MipsRevision::Mips32,  writable: true,  readable: true },
        Cop0Entry { reg: CONFIG3,       name: "Config3",    description: "Extended feature configuration",    introduced_in: MipsRevision::Mips32r2,writable: false, readable: true },
        Cop0Entry { reg: CONFIG4,       name: "Config4",    description: "Extended feature config (r5+)",     introduced_in: MipsRevision::Mips32r5,writable: true,  readable: true },
        Cop0Entry { reg: CONFIG5,       name: "Config5",    description: "Extended feature config (r5+)",     introduced_in: MipsRevision::Mips32r5,writable: true,  readable: true },
        Cop0Entry { reg: LLADDR,        name: "LLAddr",     description: "Load linked address",               introduced_in: MipsRevision::Mips32,  writable: true,  readable: true },
        Cop0Entry { reg: WATCH_LO,      name: "WatchLo",    description: "Watchpoint address (low)",          introduced_in: MipsRevision::Mips32,  writable: true,  readable: true },
        Cop0Entry { reg: WATCH_HI,      name: "WatchHi",    description: "Watchpoint address (high)",         introduced_in: MipsRevision::Mips32,  writable: true,  readable: true },
        Cop0Entry { reg: XCONTEXT,      name: "XContext",   description: "64-bit TLB context (MIPS64)",       introduced_in: MipsRevision::Mips64,  writable: true,  readable: true },
        Cop0Entry { reg: DEBUG,         name: "Debug",      description: "EJTAG debug control/status",        introduced_in: MipsRevision::Mips32,  writable: true,  readable: true },
        Cop0Entry { reg: DEPC,          name: "DEPC",       description: "Debug exception PC",                introduced_in: MipsRevision::Mips32,  writable: true,  readable: true },
        Cop0Entry { reg: PERF_CTL0,     name: "PerfCtl0",   description: "Performance counter control 0",     introduced_in: MipsRevision::Mips32,  writable: true,  readable: true },
        Cop0Entry { reg: PERF_CNT0,     name: "PerfCnt0",   description: "Performance counter 0",             introduced_in: MipsRevision::Mips32,  writable: true,  readable: true },
        Cop0Entry { reg: CACHE_ERR,     name: "CacheErr",   description: "Cache error register",              introduced_in: MipsRevision::Mips32,  writable: false, readable: true },
        Cop0Entry { reg: TAG_LO,        name: "TagLo",      description: "Cache tag (low)",                   introduced_in: MipsRevision::Mips32,  writable: true,  readable: true },
        Cop0Entry { reg: TAG_HI,        name: "TagHi",      description: "Cache tag (high)",                  introduced_in: MipsRevision::Mips32,  writable: true,  readable: true },
        Cop0Entry { reg: ERROR_EPC,     name: "ErrorEPC",   description: "Error exception program counter",   introduced_in: MipsRevision::Mips32,  writable: true,  readable: true },
        Cop0Entry { reg: DESAVE,        name: "DESAVE",     description: "Debug scratch register (EJTAG)",    introduced_in: MipsRevision::Mips32,  writable: true,  readable: true },
    ]
}

// Lazy static tables for O(1) name and description lookups.
static CP0_NAME_TABLE_ONCE: std::sync::OnceLock<HashMap<Cop0Register, &'static str>> =
    std::sync::OnceLock::new();
static CP0_DESC_TABLE_ONCE: std::sync::OnceLock<HashMap<Cop0Register, &'static str>> =
    std::sync::OnceLock::new();

fn build_name_table() -> HashMap<Cop0Register, &'static str> {
    use cop0::*;
    let mut m = HashMap::new();
    m.insert(INDEX,       "Index");
    m.insert(RANDOM,      "Random");
    m.insert(ENTRY_LO0,   "EntryLo0");
    m.insert(ENTRY_LO1,   "EntryLo1");
    m.insert(CONTEXT,     "Context");
    m.insert(PAGE_MASK,   "PageMask");
    m.insert(PAGE_GRAIN,  "PageGrain");
    m.insert(WIRED,       "Wired");
    m.insert(BAD_VADDR,   "BadVAddr");
    m.insert(COUNT,       "Count");
    m.insert(ENTRY_HI,    "EntryHi");
    m.insert(COMPARE,     "Compare");
    m.insert(STATUS,      "Status");
    m.insert(INT_CTL,     "IntCtl");
    m.insert(SRS_CTL,     "SRSCtl");
    m.insert(SRS_MAP,     "SRSMap");
    m.insert(CAUSE,       "Cause");
    m.insert(EPC,         "EPC");
    m.insert(PRID,        "PRId");
    m.insert(EBASE,       "EBase");
    m.insert(CONFIG0,     "Config0");
    m.insert(CONFIG1,     "Config1");
    m.insert(CONFIG2,     "Config2");
    m.insert(CONFIG3,     "Config3");
    m.insert(CONFIG4,     "Config4");
    m.insert(CONFIG5,     "Config5");
    m.insert(CONFIG6,     "Config6");
    m.insert(CONFIG7,     "Config7");
    m.insert(LLADDR,      "LLAddr");
    m.insert(WATCH_LO,    "WatchLo");
    m.insert(WATCH_HI,    "WatchHi");
    m.insert(XCONTEXT,    "XContext");
    m.insert(DEBUG,       "Debug");
    m.insert(DEPC,        "DEPC");
    m.insert(PERF_CTL0,   "PerfCtl0");
    m.insert(PERF_CNT0,   "PerfCnt0");
    m.insert(PERF_CTL1,   "PerfCtl1");
    m.insert(PERF_CNT1,   "PerfCnt1");
    m.insert(CACHE_ERR,   "CacheErr");
    m.insert(TAG_LO,      "TagLo");
    m.insert(TAG_HI,      "TagHi");
    m.insert(ERROR_EPC,   "ErrorEPC");
    m.insert(DESAVE,      "DESAVE");
    m
}

fn build_desc_table() -> HashMap<Cop0Register, &'static str> {
    use cop0::*;
    let mut m = HashMap::new();
    m.insert(INDEX,     "TLB index");
    m.insert(RANDOM,    "Pseudo-random TLB index");
    m.insert(STATUS,    "Processor status register");
    m.insert(CAUSE,     "Exception cause register");
    m.insert(EPC,       "Exception program counter");
    m.insert(COUNT,     "Free-running processor timer");
    m.insert(COMPARE,   "Timer compare / interrupt trigger");
    m.insert(CONFIG0,   "Processor configuration");
    m.insert(BAD_VADDR, "Faulting virtual address");
    m
}

fn cp0_name_table() -> &'static HashMap<Cop0Register, &'static str> {
    CP0_NAME_TABLE_ONCE.get_or_init(build_name_table)
}

fn cp0_desc_table() -> &'static HashMap<Cop0Register, &'static str> {
    CP0_DESC_TABLE_ONCE.get_or_init(build_desc_table)
}

/// Return the canonical name of a CP0 register, or `None` if unknown.
pub fn get_cp0_name(reg: Cop0Register) -> Option<&'static str> {
    cp0_name_table().get(&reg).copied()
}

/// Return the description of a CP0 register or a generic placeholder.
pub fn get_cp0_desc(reg: Cop0Register) -> &'static str {
    cp0_desc_table().get(&reg).copied().unwrap_or("Unknown CP0 register")
}

// Re-export via the public API functions
static CP0_NAME_TABLE: std::sync::LazyLock<HashMap<Cop0Register, &'static str>> =
    std::sync::LazyLock::new(build_name_table);
static CP0_DESC_TABLE: std::sync::LazyLock<HashMap<Cop0Register, &'static str>> =
    std::sync::LazyLock::new(build_desc_table);

// ---------------------------------------------------------------------------
// Cop0RegisterDb — searchable database
// ---------------------------------------------------------------------------

/// A searchable database of CP0 registers.
#[derive(Debug, Default)]
pub struct Cop0RegisterDb {
    entries: Vec<Cop0Entry>,
}

impl Cop0RegisterDb {
    /// Build the standard database.
    #[must_use]
    pub fn standard() -> Self {
        Self { entries: standard_cop0_entries() }
    }

    /// Look up an entry by register.
    #[must_use]
    pub fn lookup(&self, reg: Cop0Register) -> Option<&Cop0Entry> {
        self.entries.iter().find(|e| e.reg == reg)
    }

    /// Look up an entry by name (case-insensitive).
    #[must_use]
    pub fn lookup_by_name(&self, name: &str) -> Option<&Cop0Entry> {
        self.entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(name))
    }

    /// All registers introduced in `rev` or earlier.
    #[must_use]
    pub fn available_in(&self, rev: MipsRevision) -> Vec<&Cop0Entry> {
        self.entries
            .iter()
            .filter(|e| e.introduced_in <= rev)
            .collect()
    }

    /// All writable registers.
    #[must_use]
    pub fn writable(&self) -> Vec<&Cop0Entry> {
        self.entries.iter().filter(|e| e.writable).collect()
    }

    /// Total number of entries.
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

// ---------------------------------------------------------------------------
// Status register field helpers
// ---------------------------------------------------------------------------

/// Parsed fields of the MIPS Status CP0 register.
#[derive(Debug, Clone)]
pub struct StatusFields {
    /// Raw register value.
    pub raw: u32,
}

impl StatusFields {
    /// Wrap a raw Status register value.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self { raw }
    }

    /// Interrupt Enable (bit 0).
    #[must_use]
    pub const fn ie(&self) -> bool { self.raw & 0x1 != 0 }
    /// Exception Level (bit 1).
    #[must_use]
    pub const fn exl(&self) -> bool { self.raw & 0x2 != 0 }
    /// Error Level (bit 2).
    #[must_use]
    pub const fn erl(&self) -> bool { self.raw & 0x4 != 0 }
    /// Kernel/User mode (bit 3; 0 = kernel).
    #[must_use]
    pub const fn ksu(&self) -> u8 { ((self.raw >> 3) & 0x3) as u8 }
    /// User Extension Enable (bit 5, MIPS32r2+).
    #[must_use]
    pub const fn ux(&self) -> bool { self.raw & 0x20 != 0 }
    /// Supervisor Extension Enable (bit 6).
    #[must_use]
    pub const fn sx(&self) -> bool { self.raw & 0x40 != 0 }
    /// Kernel 64-bit addressing enable (bit 7).
    #[must_use]
    pub const fn kx(&self) -> bool { self.raw & 0x80 != 0 }
    /// Interrupt mask (bits 8–15).
    #[must_use]
    pub const fn im(&self) -> u8 { ((self.raw >> 8) & 0xFF) as u8 }
    /// Floating-point enable (bit 29).
    #[must_use]
    pub const fn cu1(&self) -> bool { self.raw & (1 << 29) != 0 }
    /// COP0 usable in user mode (bit 28).
    #[must_use]
    pub const fn cu0(&self) -> bool { self.raw & (1 << 28) != 0 }

    /// Returns a human-readable summary of the status flags.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "IE={} EXL={} ERL={} KSU={} IM={:#04x} CU1(FPU)={} CU0={}",
            u8::from(self.ie()),
            u8::from(self.exl()),
            u8::from(self.erl()),
            self.ksu(),
            self.im(),
            u8::from(self.cu1()),
            u8::from(self.cu0()),
        )
    }
}

// ---------------------------------------------------------------------------
// Cause register field helpers
// ---------------------------------------------------------------------------

/// Parsed fields of the MIPS Cause CP0 register.
#[derive(Debug, Clone)]
pub struct CauseFields {
    /// Raw register value.
    pub raw: u32,
}

impl CauseFields {
    /// Wrap a raw Cause register value.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self { raw }
    }

    /// Exception code (bits 2–6).
    #[must_use]
    pub const fn exc_code(&self) -> u8 {
        ((self.raw >> 2) & 0x1F) as u8
    }

    /// Interrupt pending (bits 8–15).
    #[must_use]
    pub const fn ip(&self) -> u8 {
        ((self.raw >> 8) & 0xFF) as u8
    }

    /// Whether the exception was in a branch delay slot (bit 31).
    #[must_use]
    pub const fn bd(&self) -> bool {
        self.raw & (1 << 31) != 0
    }

    /// Coprocessor unit number for CpU exceptions (bits 28–29).
    #[must_use]
    pub const fn ce(&self) -> u8 {
        ((self.raw >> 28) & 0x3) as u8
    }

    /// Human-readable exception code name.
    #[must_use]
    pub fn exc_name(&self) -> &'static str {
        match self.exc_code() {
            0 => "Int",
            1 => "MOD",
            2 => "TLBL",
            3 => "TLBS",
            4 => "AdEL",
            5 => "AdES",
            6 => "IBE",
            7 => "DBE",
            8 => "Sys",
            9 => "Bp",
            10 => "RI",
            11 => "CpU",
            12 => "Ov",
            13 => "Tr",
            14 => "MSAFPE",
            15 => "FPE",
            16 => "IS1",
            17 => "IS2",
            22 => "MDMX",
            23 => "WATCH",
            24 => "MCheck",
            25 => "Thread",
            26 => "DSPDis",
            29 => "CacheErr",
            _ => "Unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cop0_name_status() {
        assert_eq!(cop0_name(cop0::STATUS), Some("Status"));
    }

    #[test]
    fn cop0_name_epc() {
        assert_eq!(cop0_name(cop0::EPC), Some("EPC"));
    }

    #[test]
    fn cop0_name_unknown() {
        assert_eq!(cop0_name(Cop0Register::new(21, 0)), None);
    }

    #[test]
    fn db_lookup_by_name() {
        let db = Cop0RegisterDb::standard();
        let entry = db.lookup_by_name("status").unwrap();
        assert_eq!(entry.reg, cop0::STATUS);
    }

    #[test]
    fn db_available_in_mips1() {
        let db = Cop0RegisterDb::standard();
        let avail = db.available_in(MipsRevision::Mips1);
        // Index, Random, Context, BadVAddr, EntryHi, Status, Cause, EPC, PRId
        assert!(!avail.is_empty());
        // EBase should NOT be available (requires MIPS32r2)
        assert!(!avail.iter().any(|e| e.name == "EBase"));
    }

    #[test]
    fn status_fields_ie_set() {
        let s = StatusFields::new(0x0000_0001);
        assert!(s.ie());
        assert!(!s.exl());
    }

    #[test]
    fn cause_exc_code() {
        // ExcCode=8 (Sys) in bits 2-6 → value (8 << 2) = 32 = 0x20
        let c = CauseFields::new(0x0000_0020);
        assert_eq!(c.exc_code(), 8);
        assert_eq!(c.exc_name(), "Sys");
    }

    #[test]
    fn cause_bd_bit() {
        let c = CauseFields::new(1u32 << 31);
        assert!(c.bd());
    }

    #[test]
    fn cop0_register_display() {
        let r = Cop0Register::new(12, 0);
        assert_eq!(r.to_string(), "$c0r12");
        let r2 = Cop0Register::new(12, 1);
        assert_eq!(r2.to_string(), "$c0r12/1");
    }
}
