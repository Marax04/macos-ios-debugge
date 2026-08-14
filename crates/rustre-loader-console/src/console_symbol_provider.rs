//! Well-known symbol provider for classic console platforms.
//!
//! Provides [`ConsoleSymbolProvider`], [`ConsoleSymbol`], [`WellKnownSymbol`]
//! and [`known_symbols`].  Covers NES, SNES, Game Boy, GBA, and Genesis.

use std::collections::HashMap;
use std::fmt;

// ── SymbolKind ────────────────────────────────────────────────────────────────

/// The nature of a symbol's value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// CPU interrupt / exception vector.
    Vector,
    /// Memory-mapped I/O register.
    Register,
    /// Constant / enumeration value.
    Constant,
    /// Known subroutine entry point.
    Function,
    /// Data structure or table.
    Data,
    /// ROM header field.
    Header,
}

impl SymbolKind {
    /// One-letter tag used in display.
    #[must_use]
    pub const fn tag(&self) -> char {
        match self {
            Self::Vector => 'V',
            Self::Register => 'R',
            Self::Constant => 'C',
            Self::Function => 'F',
            Self::Data => 'D',
            Self::Header => 'H',
        }
    }
}

impl fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.tag())
    }
}

// ── ConsolePlatform ───────────────────────────────────────────────────────────

/// Platform tag used to scope symbol namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsolePlatform {
    Nes,
    Snes,
    GameBoy,
    Gba,
    Genesis,
}

impl ConsolePlatform {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nes => "nes",
            Self::Snes => "snes",
            Self::GameBoy => "gameboy",
            Self::Gba => "gba",
            Self::Genesis => "genesis",
        }
    }
}

impl fmt::Display for ConsolePlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── WellKnownSymbol ───────────────────────────────────────────────────────────

/// A platform-independent descriptor for a well-known symbol.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WellKnownSymbol {
    /// Canonical name.
    pub name: &'static str,
    /// Virtual address on the target platform.
    pub address: u64,
    /// Symbol nature.
    pub kind: SymbolKind,
    /// Short description.
    pub description: &'static str,
    /// The platform this symbol belongs to.
    pub platform: ConsolePlatform,
}

impl WellKnownSymbol {
    #[must_use]
    const fn new(
        name: &'static str,
        address: u64,
        kind: SymbolKind,
        description: &'static str,
        platform: ConsolePlatform,
    ) -> Self {
        Self { name, address, kind, description, platform }
    }
}

impl fmt::Display for WellKnownSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {:#010x} {} ({})", self.kind, self.address, self.name, self.description)
    }
}

// ── ConsoleSymbol ─────────────────────────────────────────────────────────────

/// A resolved symbol, potentially enriched with runtime information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleSymbol {
    /// Symbol name.
    pub name: String,
    /// Virtual address.
    pub address: u64,
    /// Symbol kind.
    pub kind: SymbolKind,
    /// Human-readable description.
    pub description: String,
    /// Platform this symbol belongs to.
    pub platform: ConsolePlatform,
    /// Whether this symbol was user-defined (`true`) or auto-detected.
    pub user_defined: bool,
}

impl ConsoleSymbol {
    /// Create a symbol from a well-known entry.
    #[must_use]
    pub fn from_well_known(wk: &WellKnownSymbol) -> Self {
        Self {
            name: wk.name.to_string(),
            address: wk.address,
            kind: wk.kind.clone(),
            description: wk.description.to_string(),
            platform: wk.platform,
            user_defined: false,
        }
    }

    /// Create a user-defined symbol.
    #[must_use]
    pub fn user(
        name: impl Into<String>,
        address: u64,
        kind: SymbolKind,
        description: impl Into<String>,
        platform: ConsolePlatform,
    ) -> Self {
        Self {
            name: name.into(),
            address,
            kind,
            description: description.into(),
            platform,
            user_defined: true,
        }
    }

    /// Return a short representation: `name @ address`.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{} @ {:#010x}", self.name, self.address)
    }
}

impl fmt::Display for ConsoleSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}][{}] {:#010x} {}{}",
            self.platform,
            self.kind,
            self.address,
            self.name,
            if self.user_defined { "*" } else { "" }
        )
    }
}

// ── Known symbol databases ────────────────────────────────────────────────────

static NES_SYMBOLS: &[WellKnownSymbol] = &[
    WellKnownSymbol::new("VEC_NMI",  0xFFFA, SymbolKind::Vector,   "NMI vector",           ConsolePlatform::Nes),
    WellKnownSymbol::new("VEC_RST",  0xFFFC, SymbolKind::Vector,   "Reset vector",         ConsolePlatform::Nes),
    WellKnownSymbol::new("VEC_IRQ",  0xFFFE, SymbolKind::Vector,   "IRQ/BRK vector",       ConsolePlatform::Nes),
    WellKnownSymbol::new("PPU_CTRL", 0x2000, SymbolKind::Register, "PPU control register 1", ConsolePlatform::Nes),
    WellKnownSymbol::new("PPU_MASK", 0x2001, SymbolKind::Register, "PPU control register 2", ConsolePlatform::Nes),
    WellKnownSymbol::new("PPU_STAT", 0x2002, SymbolKind::Register, "PPU status register",  ConsolePlatform::Nes),
    WellKnownSymbol::new("OAM_ADDR", 0x2003, SymbolKind::Register, "OAM address",          ConsolePlatform::Nes),
    WellKnownSymbol::new("OAM_DATA", 0x2004, SymbolKind::Register, "OAM data",             ConsolePlatform::Nes),
    WellKnownSymbol::new("PPU_SCRL", 0x2005, SymbolKind::Register, "PPU scroll",           ConsolePlatform::Nes),
    WellKnownSymbol::new("PPU_ADDR", 0x2006, SymbolKind::Register, "PPU address",          ConsolePlatform::Nes),
    WellKnownSymbol::new("PPU_DATA", 0x2007, SymbolKind::Register, "PPU data",             ConsolePlatform::Nes),
    WellKnownSymbol::new("OAM_DMA",  0x4014, SymbolKind::Register, "OAM DMA",              ConsolePlatform::Nes),
    WellKnownSymbol::new("APU_SQ1V", 0x4000, SymbolKind::Register, "APU Pulse 1 volume",   ConsolePlatform::Nes),
    WellKnownSymbol::new("APU_SQ2V", 0x4004, SymbolKind::Register, "APU Pulse 2 volume",   ConsolePlatform::Nes),
    WellKnownSymbol::new("APU_TRIV", 0x4008, SymbolKind::Register, "APU Triangle volume",  ConsolePlatform::Nes),
    WellKnownSymbol::new("APU_NZEV", 0x400C, SymbolKind::Register, "APU Noise envelope",   ConsolePlatform::Nes),
    WellKnownSymbol::new("APU_STAT", 0x4015, SymbolKind::Register, "APU status",           ConsolePlatform::Nes),
    WellKnownSymbol::new("JOY1",     0x4016, SymbolKind::Register, "Joypad 1",             ConsolePlatform::Nes),
    WellKnownSymbol::new("JOY2",     0x4017, SymbolKind::Register, "Joypad 2",             ConsolePlatform::Nes),
];

static SNES_SYMBOLS: &[WellKnownSymbol] = &[
    WellKnownSymbol::new("INIDISP",  0x0000_2100, SymbolKind::Register, "Screen display",       ConsolePlatform::Snes),
    WellKnownSymbol::new("OBJSEL",   0x0000_2101, SymbolKind::Register, "Object size & data",   ConsolePlatform::Snes),
    WellKnownSymbol::new("OAMADDL", 0x0000_2102, SymbolKind::Register, "OAM address (low)",    ConsolePlatform::Snes),
    WellKnownSymbol::new("OAMADDH", 0x0000_2103, SymbolKind::Register, "OAM address (high)",   ConsolePlatform::Snes),
    WellKnownSymbol::new("OAMDATA", 0x0000_2104, SymbolKind::Register, "OAM data write",       ConsolePlatform::Snes),
    WellKnownSymbol::new("BGMODE",  0x0000_2105, SymbolKind::Register, "BG mode and tile size", ConsolePlatform::Snes),
    WellKnownSymbol::new("MOSAIC",  0x0000_2106, SymbolKind::Register, "Mosaic size & enable", ConsolePlatform::Snes),
    WellKnownSymbol::new("NMITIMEN",0x0000_4200, SymbolKind::Register, "NMI/IRQ/joypad enable",ConsolePlatform::Snes),
    WellKnownSymbol::new("WRIO",    0x0000_4201, SymbolKind::Register, "Writable I/O port",    ConsolePlatform::Snes),
    WellKnownSymbol::new("RDNMI",   0x0000_4210, SymbolKind::Register, "V-blank NMI flag",     ConsolePlatform::Snes),
    WellKnownSymbol::new("TIMEUP",  0x0000_4211, SymbolKind::Register, "H/V timer IRQ flag",   ConsolePlatform::Snes),
    WellKnownSymbol::new("HVBJOY",  0x0000_4212, SymbolKind::Register, "H/V blank & joy flags",ConsolePlatform::Snes),
    WellKnownSymbol::new("JOY1L",   0x0000_4218, SymbolKind::Register, "Joypad 1 low",         ConsolePlatform::Snes),
    WellKnownSymbol::new("JOY1H",   0x0000_4219, SymbolKind::Register, "Joypad 1 high",        ConsolePlatform::Snes),
    WellKnownSymbol::new("VEC_RESET",0x0000_FFFC, SymbolKind::Vector,  "Native mode reset",    ConsolePlatform::Snes),
    WellKnownSymbol::new("VEC_NMI", 0x0000_FFEA, SymbolKind::Vector,   "Native mode NMI",      ConsolePlatform::Snes),
    WellKnownSymbol::new("VEC_IRQ", 0x0000_FFEE, SymbolKind::Vector,   "Native mode IRQ",      ConsolePlatform::Snes),
];

static GB_SYMBOLS: &[WellKnownSymbol] = &[
    WellKnownSymbol::new("RST_00",  0x0000, SymbolKind::Vector,   "RST $00 handler",      ConsolePlatform::GameBoy),
    WellKnownSymbol::new("RST_08",  0x0008, SymbolKind::Vector,   "RST $08 handler",      ConsolePlatform::GameBoy),
    WellKnownSymbol::new("RST_10",  0x0010, SymbolKind::Vector,   "RST $10 handler",      ConsolePlatform::GameBoy),
    WellKnownSymbol::new("RST_18",  0x0018, SymbolKind::Vector,   "RST $18 handler",      ConsolePlatform::GameBoy),
    WellKnownSymbol::new("RST_20",  0x0020, SymbolKind::Vector,   "RST $20 handler",      ConsolePlatform::GameBoy),
    WellKnownSymbol::new("RST_28",  0x0028, SymbolKind::Vector,   "RST $28 handler",      ConsolePlatform::GameBoy),
    WellKnownSymbol::new("RST_30",  0x0030, SymbolKind::Vector,   "RST $30 handler",      ConsolePlatform::GameBoy),
    WellKnownSymbol::new("RST_38",  0x0038, SymbolKind::Vector,   "RST $38 handler",      ConsolePlatform::GameBoy),
    WellKnownSymbol::new("INT_VBL", 0x0040, SymbolKind::Vector,   "V-blank interrupt",    ConsolePlatform::GameBoy),
    WellKnownSymbol::new("INT_LCD", 0x0048, SymbolKind::Vector,   "LCD STAT interrupt",   ConsolePlatform::GameBoy),
    WellKnownSymbol::new("INT_TIM", 0x0050, SymbolKind::Vector,   "Timer interrupt",      ConsolePlatform::GameBoy),
    WellKnownSymbol::new("INT_SER", 0x0058, SymbolKind::Vector,   "Serial interrupt",     ConsolePlatform::GameBoy),
    WellKnownSymbol::new("INT_JOY", 0x0060, SymbolKind::Vector,   "Joypad interrupt",     ConsolePlatform::GameBoy),
    WellKnownSymbol::new("ENTRY",   0x0100, SymbolKind::Function, "Cartridge entry point",ConsolePlatform::GameBoy),
    WellKnownSymbol::new("LCDC",    0xFF40, SymbolKind::Register, "LCD control",          ConsolePlatform::GameBoy),
    WellKnownSymbol::new("STAT",    0xFF41, SymbolKind::Register, "LCD status",           ConsolePlatform::GameBoy),
    WellKnownSymbol::new("SCY",     0xFF42, SymbolKind::Register, "Scroll Y",             ConsolePlatform::GameBoy),
    WellKnownSymbol::new("SCX",     0xFF43, SymbolKind::Register, "Scroll X",             ConsolePlatform::GameBoy),
    WellKnownSymbol::new("LY",      0xFF44, SymbolKind::Register, "LCD Y coordinate",     ConsolePlatform::GameBoy),
    WellKnownSymbol::new("LYC",     0xFF45, SymbolKind::Register, "LY compare",           ConsolePlatform::GameBoy),
    WellKnownSymbol::new("DMA",     0xFF46, SymbolKind::Register, "OAM DMA source",       ConsolePlatform::GameBoy),
    WellKnownSymbol::new("BGP",     0xFF47, SymbolKind::Register, "BG palette",           ConsolePlatform::GameBoy),
    WellKnownSymbol::new("OBP0",    0xFF48, SymbolKind::Register, "OBJ palette 0",        ConsolePlatform::GameBoy),
    WellKnownSymbol::new("OBP1",    0xFF49, SymbolKind::Register, "OBJ palette 1",        ConsolePlatform::GameBoy),
    WellKnownSymbol::new("WY",      0xFF4A, SymbolKind::Register, "Window Y",             ConsolePlatform::GameBoy),
    WellKnownSymbol::new("WX",      0xFF4B, SymbolKind::Register, "Window X",             ConsolePlatform::GameBoy),
    WellKnownSymbol::new("IE",      0xFFFF, SymbolKind::Register, "Interrupt enable",     ConsolePlatform::GameBoy),
    WellKnownSymbol::new("IF",      0xFF0F, SymbolKind::Register, "Interrupt flag",       ConsolePlatform::GameBoy),
    WellKnownSymbol::new("P1",      0xFF00, SymbolKind::Register, "Joypad / input",       ConsolePlatform::GameBoy),
    WellKnownSymbol::new("DIV",     0xFF04, SymbolKind::Register, "Divider register",     ConsolePlatform::GameBoy),
    WellKnownSymbol::new("TIMA",    0xFF05, SymbolKind::Register, "Timer counter",        ConsolePlatform::GameBoy),
    WellKnownSymbol::new("TMA",     0xFF06, SymbolKind::Register, "Timer modulo",         ConsolePlatform::GameBoy),
    WellKnownSymbol::new("TAC",     0xFF07, SymbolKind::Register, "Timer control",        ConsolePlatform::GameBoy),
];

static GBA_SYMBOLS: &[WellKnownSymbol] = &[
    WellKnownSymbol::new("ENTRY",       0x0800_0000, SymbolKind::Function, "ROM entry point (ARM branch)", ConsolePlatform::Gba),
    WellKnownSymbol::new("DISPCNT",     0x0400_0000, SymbolKind::Register, "LCD control",                  ConsolePlatform::Gba),
    WellKnownSymbol::new("DISPSTAT",    0x0400_0004, SymbolKind::Register, "General LCD status",           ConsolePlatform::Gba),
    WellKnownSymbol::new("VCOUNT",      0x0400_0006, SymbolKind::Register, "Vertical counter",             ConsolePlatform::Gba),
    WellKnownSymbol::new("BGCNT0",      0x0400_0008, SymbolKind::Register, "BG0 control",                  ConsolePlatform::Gba),
    WellKnownSymbol::new("BGCNT1",      0x0400_000A, SymbolKind::Register, "BG1 control",                  ConsolePlatform::Gba),
    WellKnownSymbol::new("BGCNT2",      0x0400_000C, SymbolKind::Register, "BG2 control",                  ConsolePlatform::Gba),
    WellKnownSymbol::new("BGCNT3",      0x0400_000E, SymbolKind::Register, "BG3 control",                  ConsolePlatform::Gba),
    WellKnownSymbol::new("KEYINPUT",    0x0400_0130, SymbolKind::Register, "Key status",                   ConsolePlatform::Gba),
    WellKnownSymbol::new("KEYCNT",      0x0400_0132, SymbolKind::Register, "Key interrupt control",        ConsolePlatform::Gba),
    WellKnownSymbol::new("IE",          0x0400_0200, SymbolKind::Register, "Interrupt enable",             ConsolePlatform::Gba),
    WellKnownSymbol::new("IF",          0x0400_0202, SymbolKind::Register, "Interrupt request flags",      ConsolePlatform::Gba),
    WellKnownSymbol::new("WAITCNT",     0x0400_0204, SymbolKind::Register, "Waitstate control",            ConsolePlatform::Gba),
    WellKnownSymbol::new("IME",         0x0400_0208, SymbolKind::Register, "Interrupt master enable",      ConsolePlatform::Gba),
    WellKnownSymbol::new("VEC_IRQ",     0x0000_0018, SymbolKind::Vector,   "IRQ vector (BIOS)",            ConsolePlatform::Gba),
    WellKnownSymbol::new("SWI_SOFTRST", 0x0000_0000, SymbolKind::Constant, "SWI 0x00 SoftReset",          ConsolePlatform::Gba),
    WellKnownSymbol::new("SWI_VBLANKINTRWAIT", 0x0000_0005, SymbolKind::Constant, "SWI 0x05 VBlankIntrWait", ConsolePlatform::Gba),
    WellKnownSymbol::new("SOUNDCNT_H", 0x0400_0082, SymbolKind::Register, "Sound control",                ConsolePlatform::Gba),
    WellKnownSymbol::new("DMA0SAD",    0x0400_00B0, SymbolKind::Register, "DMA 0 source address",         ConsolePlatform::Gba),
    WellKnownSymbol::new("DMA3CNT_H",  0x0400_00DE, SymbolKind::Register, "DMA 3 control high",           ConsolePlatform::Gba),
];

static GENESIS_SYMBOLS: &[WellKnownSymbol] = &[
    WellKnownSymbol::new("VEC_RESET",   0x0000_0000, SymbolKind::Vector,   "Initial stack pointer",        ConsolePlatform::Genesis),
    WellKnownSymbol::new("VEC_ENTRY",   0x0000_0004, SymbolKind::Vector,   "Initial program counter",      ConsolePlatform::Genesis),
    WellKnownSymbol::new("VEC_BUS_ERR", 0x0000_0008, SymbolKind::Vector,   "Bus error",                    ConsolePlatform::Genesis),
    WellKnownSymbol::new("VEC_ADDR_ERR",0x0000_000C, SymbolKind::Vector,   "Address error",                ConsolePlatform::Genesis),
    WellKnownSymbol::new("VEC_ILLEGAL", 0x0000_0010, SymbolKind::Vector,   "Illegal instruction",          ConsolePlatform::Genesis),
    WellKnownSymbol::new("VEC_VINT",    0x0000_0078, SymbolKind::Vector,   "V-blank interrupt (level 6)",  ConsolePlatform::Genesis),
    WellKnownSymbol::new("VDP_DATA",    0x00C0_0000, SymbolKind::Register, "VDP data port",                ConsolePlatform::Genesis),
    WellKnownSymbol::new("VDP_CTRL",    0x00C0_0004, SymbolKind::Register, "VDP control/status port",      ConsolePlatform::Genesis),
    WellKnownSymbol::new("VDP_HVCOUNT", 0x00C0_0008, SymbolKind::Register, "H/V counter",                  ConsolePlatform::Genesis),
    WellKnownSymbol::new("Z80_BUS_REQ", 0x00A1_1100, SymbolKind::Register, "Z80 bus request",              ConsolePlatform::Genesis),
    WellKnownSymbol::new("Z80_RESET",   0x00A1_1200, SymbolKind::Register, "Z80 reset",                    ConsolePlatform::Genesis),
    WellKnownSymbol::new("ROM_HEADER",  0x0000_0100, SymbolKind::Header,   "ROM header region",            ConsolePlatform::Genesis),
    WellKnownSymbol::new("TMSS_REG",    0x00A1_4000, SymbolKind::Register, "TMSS register",                ConsolePlatform::Genesis),
];

// ── known_symbols ─────────────────────────────────────────────────────────────

/// Return all well-known symbols for `platform`.
#[must_use]
pub fn known_symbols(platform: ConsolePlatform) -> &'static [WellKnownSymbol] {
    match platform {
        ConsolePlatform::Nes => NES_SYMBOLS,
        ConsolePlatform::Snes => SNES_SYMBOLS,
        ConsolePlatform::GameBoy => GB_SYMBOLS,
        ConsolePlatform::Gba => GBA_SYMBOLS,
        ConsolePlatform::Genesis => GENESIS_SYMBOLS,
    }
}

// ── ConsoleSymbolProvider ─────────────────────────────────────────────────────

/// A symbol provider that merges well-known platform symbols with
/// user-defined overrides.
///
/// Lookups by address use a [`HashMap`].  When a user symbol overlaps a
/// well-known symbol at the same address, the user symbol wins.
#[derive(Debug, Clone)]
pub struct ConsoleSymbolProvider {
    /// The target platform.
    pub platform: ConsolePlatform,
    /// All symbols indexed by address.
    by_address: HashMap<u64, ConsoleSymbol>,
    /// All symbols indexed by name.
    by_name: HashMap<String, u64>,
}

impl ConsoleSymbolProvider {
    /// Create a provider for `platform`, pre-loaded with all well-known
    /// symbols for that platform.
    #[must_use]
    pub fn for_platform(platform: ConsolePlatform) -> Self {
        let mut provider = Self {
            platform,
            by_address: HashMap::new(),
            by_name: HashMap::new(),
        };
        for wk in known_symbols(platform) {
            let sym = ConsoleSymbol::from_well_known(wk);
            provider.insert_symbol(sym);
        }
        provider
    }

    /// Create an empty provider that accepts only user-defined symbols.
    #[must_use]
    pub fn empty(platform: ConsolePlatform) -> Self {
        Self { platform, by_address: HashMap::new(), by_name: HashMap::new() }
    }

    /// Insert or replace a symbol.  User-defined symbols overwrite
    /// well-known symbols at the same address.
    pub fn insert_symbol(&mut self, sym: ConsoleSymbol) {
        let addr = sym.address;
        let name = sym.name.clone();
        self.by_address.insert(addr, sym);
        self.by_name.insert(name, addr);
    }

    /// Look up a symbol by address.
    #[must_use]
    pub fn lookup_address(&self, addr: u64) -> Option<&ConsoleSymbol> {
        self.by_address.get(&addr)
    }

    /// Look up a symbol by name (case-sensitive).
    #[must_use]
    pub fn lookup_name(&self, name: &str) -> Option<&ConsoleSymbol> {
        let addr = self.by_name.get(name)?;
        self.by_address.get(addr)
    }

    /// Return all symbols of the given kind.
    #[must_use]
    pub fn symbols_of_kind(&self, kind: &SymbolKind) -> Vec<&ConsoleSymbol> {
        let mut v: Vec<&ConsoleSymbol> = self.by_address.values()
            .filter(|s| &s.kind == kind)
            .collect();
        v.sort_by_key(|s| s.address);
        v
    }

    /// Return all symbols sorted by address.
    #[must_use]
    pub fn all_sorted(&self) -> Vec<&ConsoleSymbol> {
        let mut v: Vec<&ConsoleSymbol> = self.by_address.values().collect();
        v.sort_by_key(|s| s.address);
        v
    }

    /// Total symbol count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_address.len()
    }

    /// Return `true` if no symbols are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }

    /// Remove a symbol by address.  Returns the removed symbol if present.
    pub fn remove_address(&mut self, addr: u64) -> Option<ConsoleSymbol> {
        if let Some(sym) = self.by_address.remove(&addr) {
            self.by_name.remove(&sym.name);
            Some(sym)
        } else {
            None
        }
    }

    /// Annotate `addr` with the best available symbol name.
    /// Returns `"sub_<addr>"` style name if not found.
    #[must_use]
    pub fn name_for_address(&self, addr: u64) -> String {
        self.lookup_address(addr).map_or_else(|| format!("sub_{addr:08X}"), |sym| sym.name.clone())
    }

    /// Merge another provider's symbols into this one.  Symbols from `other`
    /// overwrite existing entries at the same address.
    pub fn merge_from(&mut self, other: &Self) {
        for sym in other.by_address.values() {
            self.insert_symbol(sym.clone());
        }
    }

    /// Return symbols within the address range `[start, end]`.
    #[must_use]
    pub fn symbols_in_range(&self, start: u64, end: u64) -> Vec<&ConsoleSymbol> {
        let mut v: Vec<&ConsoleSymbol> = self.by_address.values()
            .filter(|s| s.address >= start && s.address <= end)
            .collect();
        v.sort_by_key(|s| s.address);
        v
    }

    /// Return user-defined symbols only.
    #[must_use]
    pub fn user_symbols(&self) -> Vec<&ConsoleSymbol> {
        let mut v: Vec<&ConsoleSymbol> = self.by_address.values()
            .filter(|s| s.user_defined)
            .collect();
        v.sort_by_key(|s| s.address);
        v
    }

    /// Export all symbols as `address,name,kind,description` CSV lines.
    #[must_use]
    /// Quote a value for a CSV row, per RFC 4180.
    ///
    /// Symbol names are not tame text: a demangled C++ name carries commas as a
    /// matter of course (`std::pair<int, int>`), and unquoted each one shifts
    /// every later column of that row, so a reader silently attributes the kind
    /// and description to the wrong symbol. Descriptions are free text too.
    ///
    /// Quoting is minimal — a value containing none of `,` `"` CR LF comes back
    /// untouched — so rows that were already well formed are unchanged. Same
    /// helper as `csv_field` in `rustre-sysinternals`.
    fn csv_field(value: &str) -> String {
        if value.contains([',', '"', '\r', '\n']) {
            format!("\"{}\"", value.replace('"', "\"\""))
        } else {
            value.to_owned()
        }
    }

    pub fn export_csv(&self) -> String {
        let mut lines = Vec::with_capacity(self.by_address.len() + 1);
        lines.push("address,name,kind,description,user_defined".to_string());
        for sym in self.all_sorted() {
            lines.push(format!(
                "{:#010x},{},{:?},{},{}",
                sym.address,
                Self::csv_field(&sym.name),
                sym.kind,
                Self::csv_field(&sym.description),
                sym.user_defined
            ));
        }
        lines.join("\n")
    }
}

impl fmt::Display for ConsoleSymbolProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConsoleSymbolProvider[{}] ({} symbols)", self.platform, self.len())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_symbols_nonempty() {
        for &platform in &[
            ConsolePlatform::Nes,
            ConsolePlatform::Snes,
            ConsolePlatform::GameBoy,
            ConsolePlatform::Gba,
            ConsolePlatform::Genesis,
        ] {
            let syms = known_symbols(platform);
            assert!(!syms.is_empty(), "{platform} should have symbols");
        }
    }

    #[test]
    fn test_well_known_symbol_display() {
        let wk = &NES_SYMBOLS[0];
        let s = wk.to_string();
        assert!(s.contains("VEC_NMI"));
    }

    #[test]
    fn test_provider_for_platform_nes() {
        let p = ConsoleSymbolProvider::for_platform(ConsolePlatform::Nes);
        assert!(!p.is_empty());
        let sym = p.lookup_address(0x2000).unwrap();
        assert_eq!(sym.name, "PPU_CTRL");
    }

    #[test]
    fn test_provider_lookup_name() {
        let p = ConsoleSymbolProvider::for_platform(ConsolePlatform::GameBoy);
        let sym = p.lookup_name("LCDC").unwrap();
        assert_eq!(sym.address, 0xFF40);
    }

    #[test]
    fn test_provider_user_override() {
        let mut p = ConsoleSymbolProvider::for_platform(ConsolePlatform::Nes);
        let user = ConsoleSymbol::user(
            "MY_PPU_CTRL", 0x2000, SymbolKind::Register, "override", ConsolePlatform::Nes,
        );
        p.insert_symbol(user);
        let sym = p.lookup_address(0x2000).unwrap();
        assert_eq!(sym.name, "MY_PPU_CTRL");
        assert!(sym.user_defined);
    }

    #[test]
    fn test_provider_symbols_of_kind_vectors() {
        let p = ConsoleSymbolProvider::for_platform(ConsolePlatform::Nes);
        let vectors = p.symbols_of_kind(&SymbolKind::Vector);
        assert_eq!(vectors.len(), 3);
        for v in &vectors {
            assert_eq!(v.kind, SymbolKind::Vector);
        }
    }

    #[test]
    fn test_provider_all_sorted() {
        let p = ConsoleSymbolProvider::for_platform(ConsolePlatform::Gba);
        let all = p.all_sorted();
        let addrs: Vec<u64> = all.iter().map(|s| s.address).collect();
        let mut sorted = addrs.clone();
        sorted.sort_unstable();
        assert_eq!(addrs, sorted);
    }

    #[test]
    fn test_provider_remove() {
        let mut p = ConsoleSymbolProvider::for_platform(ConsolePlatform::Nes);
        let before = p.len();
        let removed = p.remove_address(0x2000);
        assert!(removed.is_some());
        assert_eq!(p.len(), before - 1);
        assert!(p.lookup_address(0x2000).is_none());
    }

    #[test]
    fn test_provider_symbols_in_range() {
        let p = ConsoleSymbolProvider::for_platform(ConsolePlatform::Nes);
        let syms = p.symbols_in_range(0x2000, 0x2007);
        assert!(!syms.is_empty());
        for s in &syms {
            assert!(s.address >= 0x2000 && s.address <= 0x2007);
        }
    }

    #[test]
    fn test_provider_merge() {
        let p1 = ConsoleSymbolProvider::for_platform(ConsolePlatform::Nes);
        let mut p2 = ConsoleSymbolProvider::empty(ConsolePlatform::Nes);
        p2.merge_from(&p1);
        assert_eq!(p2.len(), p1.len());
    }

    #[test]
    fn test_provider_name_for_address_fallback() {
        let p = ConsoleSymbolProvider::for_platform(ConsolePlatform::Nes);
        let name = p.name_for_address(0xDEAD);
        assert!(name.starts_with("sub_"));
    }

    #[test]
    fn test_provider_name_for_address_known() {
        let p = ConsoleSymbolProvider::for_platform(ConsolePlatform::Nes);
        let name = p.name_for_address(0xFFFA);
        assert_eq!(name, "VEC_NMI");
    }

    #[test]
    fn test_export_csv_header() {
        let p = ConsoleSymbolProvider::for_platform(ConsolePlatform::Nes);
        let csv = p.export_csv();
        assert!(csv.starts_with("address,name,kind"));
    }

    /// A symbol name is not tame text — a demangled C++ name carries commas as
    /// a matter of course. Unquoted, each one shifted every later column, so the
    /// kind and description were read against the wrong symbol.
    #[test]
    fn test_export_csv_quotes_names_containing_delimiters() {
        let mut p = ConsoleSymbolProvider::for_platform(ConsolePlatform::Nes);
        p.insert_symbol(ConsoleSymbol::user(
            "std::pair<int, int>",
            0x8000,
            SymbolKind::Function,
            "says \"hello\"",
            ConsolePlatform::Nes,
        ));
        let csv = p.export_csv();
        let row = csv
            .lines()
            .find(|l| l.contains("std::pair"))
            .expect("the symbol must be exported");

        // The name is one quoted field, so its comma cannot split the row.
        assert!(
            row.contains("\"std::pair<int, int>\""),
            "name was not quoted: {row:?}"
        );
        // Embedded quotes are doubled, per RFC 4180.
        assert!(row.contains("\"\"hello\"\""), "quotes were not doubled: {row:?}");
        // And the record still occupies exactly one line.
        assert_eq!(row.lines().count(), 1);
    }

    #[test]
    fn test_console_symbol_label() {
        let s = ConsoleSymbol::user("RESET", 0x8000, SymbolKind::Function, "desc", ConsolePlatform::Nes);
        let l = s.label();
        assert!(l.contains("RESET"));
        assert!(l.contains("0x00008000") || l.contains("8000"));
    }

    #[test]
    fn test_symbol_kind_tags() {
        assert_eq!(SymbolKind::Vector.tag(), 'V');
        assert_eq!(SymbolKind::Register.tag(), 'R');
        assert_eq!(SymbolKind::Function.tag(), 'F');
    }

    #[test]
    fn test_provider_display() {
        let p = ConsoleSymbolProvider::for_platform(ConsolePlatform::Genesis);
        let s = p.to_string();
        assert!(s.contains("genesis"));
    }
}
