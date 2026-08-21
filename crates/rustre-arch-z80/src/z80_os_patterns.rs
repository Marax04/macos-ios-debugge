//! `z80_os_patterns` —  Z80 OS and platform pattern analysis.
//!
//! Provides:
//! * [`CpMBiosCall`]        —" CP/M BIOS call detection (JMP table at 0x0000)
//! * [`Z80BdosCall`]          —" CP/M BDOS call detection (CALL 5 / RST 5)
//! * [`ZxSpectrumPatterns`] —" ZX Spectrum ROM call and I/O patterns
//! * [`Z80BootloaderDetector`]—" Z80 bootloader heuristics
//! * [`Z80SelfModifying`]     —" self-modifying code detection
//! * [`Z80OsPatterns`]        —" top-level facade

use std::collections::HashSet;

pub use std::collections::HashMap;
pub use std::fmt;

// ---------------------------------------------------------------------------
// CP/M BIOS calls
// ---------------------------------------------------------------------------

/// CP/M BIOS function numbers and their names.
const BIOS_FUNCTION_NAMES: &[(u8, &str)] = &[
    (0, "BOOT"),
    (1, "WBOOT"),
    (2, "CONST"),
    (3, "CONIN"),
    (4, "CONOUT"),
    (5, "LIST"),
    (6, "PUNCH"),
    (7, "READER"),
    (8, "HOME"),
    (9, "SELDSK"),
    (10, "SETTRK"),
    (11, "SETSEC"),
    (12, "SETDMA"),
    (13, "READ"),
    (14, "WRITE"),
    (15, "LISTST"),
    (16, "SECTRN"),
];

/// A detected CP/M BIOS call.
#[derive(Debug, Clone)]
pub struct BiosCallRecord {
    /// Address of the calling instruction.
    pub address: u64,
    /// BIOS function number.
    pub function: u8,
    /// BIOS function name.
    pub name: &'static str,
}

/// CP/M BIOS call detector.
///
/// In CP/M, the BIOS is accessed via a jump table at the BIOS base address.
/// Each entry is a 3-byte JMP instruction. Function 0 = BOOT, 1 = WBOOT, —¦
///
/// The BIOS base is typically at `BIOS_BASE = CCP_BASE + 0x800`.
/// A JP (`BIOS_BASE` + function * 3) is the standard call pattern.
#[derive(Debug, Clone)]
pub struct CpMBiosCall {
    /// BIOS base address (default 0xE400 for standard 64K CP/M).
    pub bios_base: u64,
    /// Detected BIOS calls.
    pub calls: Vec<BiosCallRecord>,
    /// Set of function numbers called.
    pub called_functions: HashSet<u8>,
}

impl Default for CpMBiosCall {
    fn default() -> Self {
        Self::new(0xE400)
    }
}

impl CpMBiosCall {
    /// Create a BIOS call detector.
    #[must_use]
    pub fn new(bios_base: u64) -> Self {
        Self {
            bios_base,
            calls: Vec::new(),
            called_functions: HashSet::new(),
        }
    }

    /// Compute the BIOS entry address for a function number.
    #[must_use]
    pub fn entry_address(&self, function: u8) -> u64 {
        self.bios_base + u64::from(function) * 3
    }

    /// Check whether `target` is a BIOS entry point jump.
    #[must_use]
    pub const fn is_bios_jump(&self, target: u64) -> Option<u8> {
        if target < self.bios_base {
            return None;
        }
        let offset = target - self.bios_base;
        if offset.is_multiple_of(3) {
            let func_u64 = offset / 3;
            // Guard against truncation: cast only after confirming the value
            // fits in u8 AND is within the known BIOS function table.
            if func_u64 < BIOS_FUNCTION_NAMES.len() as u64 {
                // Guarded above: func_u64 < BIOS_FUNCTION_NAMES.len(), far below 256,
                // so the low byte IS the value. `to_le_bytes` is exact and const.
                return Some(func_u64.to_le_bytes()[0]);
            }
        }
        None
    }

    /// Record a jump to a BIOS entry point.
    pub fn record_call(&mut self, address: u64, target: u64) {
        if let Some(func) = self.is_bios_jump(target) {
            let name = BIOS_FUNCTION_NAMES[func as usize].1;
            self.called_functions.insert(func);
            self.calls.push(BiosCallRecord {
                address,
                function: func,
                name,
            });
        }
    }

    /// Look up BIOS function name by number.
    #[must_use]
    pub fn function_name(function: u8) -> Option<&'static str> {
        BIOS_FUNCTION_NAMES
            .iter()
            .find(|(n, _)| *n == function)
            .map(|(_, name)| *name)
    }

    /// Whether the program uses any BIOS calls.
    #[must_use]
    pub const fn has_bios_calls(&self) -> bool {
        !self.calls.is_empty()
    }

    /// Whether BIOS CONIN (console input) is used.
    #[must_use]
    pub fn uses_conin(&self) -> bool {
        self.called_functions.contains(&3)
    }

    /// Whether BIOS CONOUT (console output) is used.
    #[must_use]
    pub fn uses_conout(&self) -> bool {
        self.called_functions.contains(&4)
    }
}

// ---------------------------------------------------------------------------
// CP/M BDOS calls
// ---------------------------------------------------------------------------

/// CP/M BDOS function names.
const BDOS_FUNCTION_NAMES: &[(u8, &str)] = &[
    (0, "P_TERMCPM"),
    (1, "C_READ"),
    (2, "C_WRITE"),
    (3, "A_READ"),
    (4, "A_WRITE"),
    (5, "L_WRITE"),
    (6, "DC_IO"),
    (7, "A_STATIN"),
    (8, "A_STATOUT"),
    (9, "C_WRITESTR"),
    (10, "C_READSTR"),
    (11, "C_STAT"),
    (12, "S_BDOSVER"),
    (13, "DRV_ALLRESET"),
    (14, "DRV_SET"),
    (15, "F_OPEN"),
    (16, "F_CLOSE"),
    (17, "F_SFIRST"),
    (18, "F_SNEXT"),
    (19, "F_DELETE"),
    (20, "F_READ"),
    (21, "F_WRITE"),
    (22, "F_MAKE"),
    (23, "F_RENAME"),
    (24, "DRV_LOGINVEC"),
    (25, "DRV_GET"),
    (26, "F_DMAOFF"),
];

/// A detected BDOS call record.
#[derive(Debug, Clone)]
pub struct BdosCallRecord {
    /// Address of the CALL/RST instruction.
    pub address: u64,
    /// BDOS function number (loaded into C register before call).
    pub function: u8,
    /// Function name.
    pub name: &'static str,
}

/// CP/M BDOS call detector.
///
/// Standard pattern: `LD C, <func>` then `CALL 5` (or `RST 5` at 0x0028).
#[derive(Debug, Clone, Default)]
pub struct Z80BdosCall {
    /// Detected BDOS calls.
    pub calls: Vec<BdosCallRecord>,
    /// Set of BDOS function numbers used.
    pub functions_used: HashSet<u8>,
    /// Number of `CALL 5` instructions detected.
    pub call5_count: usize,
    /// Number of `RST 5` instructions detected (0xEF).
    pub rst5_count: usize,
}

impl Z80BdosCall {
    /// Create a new BDOS call detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a BDOS function name.
    #[must_use]
    pub fn function_name(function: u8) -> Option<&'static str> {
        BDOS_FUNCTION_NAMES
            .iter()
            .find(|(n, _)| *n == function)
            .map(|(_, name)| *name)
    }

    /// Record a CALL 5 instruction at `address` with `c_reg` value.
    pub fn record_call5(&mut self, address: u64, c_reg: u8) {
        self.call5_count += 1;
        self.functions_used.insert(c_reg);
        let name = Self::function_name(c_reg).unwrap_or("unknown");
        self.calls.push(BdosCallRecord {
            address,
            function: c_reg,
            name,
        });
    }

    /// Record an RST 5 instruction.
    pub fn record_rst5(&mut self, address: u64, c_reg: u8) {
        self.rst5_count += 1;
        self.functions_used.insert(c_reg);
        let name = Self::function_name(c_reg).unwrap_or("unknown");
        self.calls.push(BdosCallRecord {
            address,
            function: c_reg,
            name,
        });
    }

    /// Whether the program does any console I/O.
    #[must_use]
    pub fn has_console_io(&self) -> bool {
        self.functions_used.contains(&1) // C_READ
            || self.functions_used.contains(&2) // C_WRITE
            || self.functions_used.contains(&9) // C_WRITESTR
    }

    /// Whether the program does file I/O.
    #[must_use]
    pub fn has_file_io(&self) -> bool {
        (15..=22_u8).any(|f| self.functions_used.contains(&f))
    }

    /// Total BDOS call count.
    #[must_use]
    pub const fn total_calls(&self) -> usize {
        self.calls.len()
    }
}

// ---------------------------------------------------------------------------
// ZX Spectrum patterns
// ---------------------------------------------------------------------------

/// A ZX Spectrum ROM routine address.
#[derive(Debug, Clone)]
pub struct SpectrumRomEntry {
    /// Address.
    pub address: u16,
    /// Routine name.
    pub name: &'static str,
    /// Brief description.
    pub description: &'static str,
}

/// Common ZX Spectrum ROM entry points.
const SPECTRUM_ROM_ENTRIES: &[SpectrumRomEntry] = &[
    SpectrumRomEntry {
        address: 0x0010,
        name: "PRINT_A_0",
        description: "Print character in A",
    },
    SpectrumRomEntry {
        address: 0x0016,
        name: "PRINT_A_2",
        description: "Print character (alt)",
    },
    SpectrumRomEntry {
        address: 0x0018,
        name: "GET_CHAR",
        description: "Get character from keyboard",
    },
    SpectrumRomEntry {
        address: 0x001C,
        name: "TEST_CHAR",
        description: "Test for character",
    },
    SpectrumRomEntry {
        address: 0x0D6B,
        name: "CLS",
        description: "Clear screen",
    },
    SpectrumRomEntry {
        address: 0x0DD9,
        name: "PRINT_OUT",
        description: "Print output to channel",
    },
    SpectrumRomEntry {
        address: 0x1601,
        name: "BEEPER",
        description: "Sound beeper",
    },
    SpectrumRomEntry {
        address: 0x0E9B,
        name: "INT_WORK",
        description: "Interrupt work",
    },
    SpectrumRomEntry {
        address: 0x0803,
        name: "BEEP",
        description: "BEEP command",
    },
    SpectrumRomEntry {
        address: 0x04C6,
        name: "KEY_SCAN",
        description: "Scan keyboard",
    },
    SpectrumRomEntry {
        address: 0x0562,
        name: "KEY_TEST",
        description: "Test a key",
    },
    SpectrumRomEntry {
        address: 0x2D3B,
        name: "OPEN_CHAN",
        description: "Open channel",
    },
];

/// ZX Spectrum I/O port identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpectrumPort {
    /// ULA port (0xFE) —" keyboard, border, beeper.
    Ula,
    /// Kempston joystick (0x1F).
    Kempston,
    /// AY sound chip data (0xFFFD on 128K).
    AyData,
    /// AY register select (0xBFFD on 128K).
    AyReg,
    /// Other port.
    Other(u8),
}

impl SpectrumPort {
    #[must_use]
    pub const fn from_port(port: u8) -> Self {
        match port {
            0xFE => Self::Ula,
            0x1F => Self::Kempston,
            _ => Self::Other(port),
        }
    }
}

/// ZX Spectrum pattern detector.
#[derive(Debug, Clone, Default)]
pub struct ZxSpectrumPatterns {
    /// ROM calls detected: (address, `rom_entry_address`).
    pub rom_calls: Vec<(u64, u16)>,
    /// I/O port accesses: (address, port, `is_write`).
    pub io_accesses: Vec<(u64, SpectrumPort, bool)>,
    /// ULA port read count.
    pub ula_reads: usize,
    /// ULA port write count.
    pub ula_writes: usize,
}

impl ZxSpectrumPatterns {
    /// Create a new ZX Spectrum pattern detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a ROM entry by address.
    #[must_use]
    pub fn lookup_rom(address: u16) -> Option<&'static SpectrumRomEntry> {
        SPECTRUM_ROM_ENTRIES.iter().find(|e| e.address == address)
    }

    /// Record a CALL or JP to a ROM address.
    pub fn record_rom_call(&mut self, from: u64, target: u16) {
        if Self::lookup_rom(target).is_some() {
            self.rom_calls.push((from, target));
        }
    }

    /// Record an I/O port access.
    pub fn record_io(&mut self, address: u64, port: u8, is_write: bool) {
        let sp = SpectrumPort::from_port(port);
        if sp == SpectrumPort::Ula {
            if is_write {
                self.ula_writes += 1;
            } else {
                self.ula_reads += 1;
            }
        }
        self.io_accesses.push((address, sp, is_write));
    }

    /// Whether any ROM calls were detected.
    #[must_use]
    pub const fn has_rom_calls(&self) -> bool {
        !self.rom_calls.is_empty()
    }

    /// Whether ULA port is accessed (border/beeper/keyboard).
    #[must_use]
    pub const fn uses_ula(&self) -> bool {
        self.ula_reads > 0 || self.ula_writes > 0
    }

    /// Whether Kempston joystick port is read.
    #[must_use]
    pub fn uses_kempston(&self) -> bool {
        self.io_accesses
            .iter()
            .any(|(_, p, _)| *p == SpectrumPort::Kempston)
    }
}

// ---------------------------------------------------------------------------
// Z80 Bootloader Detector
// ---------------------------------------------------------------------------

/// Z80 bootloader pattern type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootloaderPattern {
    /// Code starts at 0x0000 with a JP instruction.
    ResetVector,
    /// Stack pointer initialized near top of RAM.
    SpInit,
    /// Self-copying routine (LDIR from ROM to RAM).
    LdirCopy,
    /// Interrupt mode set (IM 0/1/2).
    IntModeSet,
    /// Port-based hardware initialization.
    HardwareInit,
}

/// Z80 bootloader detection.
#[derive(Debug, Clone, Default)]
pub struct Z80BootloaderDetector {
    /// Detected patterns.
    pub patterns: Vec<(u64, BootloaderPattern)>,
    /// Whether a reset vector was detected at 0x0000.
    pub has_reset_vector: bool,
    /// Whether SP was initialized.
    pub sp_initialized: bool,
    /// Initial SP value if detected.
    pub initial_sp: Option<u16>,
}

impl Z80BootloaderDetector {
    /// Create a new bootloader detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record detection of a bootloader pattern.
    pub fn record(&mut self, address: u64, pattern: BootloaderPattern) {
        if pattern == BootloaderPattern::ResetVector {
            self.has_reset_vector = true;
        }
        if pattern == BootloaderPattern::SpInit {
            self.sp_initialized = true;
        }
        self.patterns.push((address, pattern));
    }

    /// Record SP initialization.
    pub fn record_sp_init(&mut self, address: u64, sp_value: u16) {
        self.initial_sp = Some(sp_value);
        self.sp_initialized = true;
        self.patterns.push((address, BootloaderPattern::SpInit));
    }

    /// Check whether bytes at 0x0000 look like a reset vector (JP nn).
    /// `JP nn` = `0xC3 lo hi`.
    #[must_use]
    pub fn check_reset_vector(bytes: &[u8]) -> Option<u16> {
        if bytes.len() < 3 {
            return None;
        }
        if bytes[0] == 0xC3 {
            let target = u16::from_le_bytes([bytes[1], bytes[2]]);
            return Some(target);
        }
        None
    }

    /// Bootloader confidence score (0—"100).
    #[must_use]
    pub fn confidence(&self) -> u8 {
        let score: u8 = self
            .patterns
            .iter()
            .map(|(_, p)| match p {
                BootloaderPattern::ResetVector => 30,
                BootloaderPattern::SpInit => 25,
                BootloaderPattern::LdirCopy => 20,
                BootloaderPattern::IntModeSet => 15,
                BootloaderPattern::HardwareInit => 10,
            })
            .sum::<u8>()
            .min(100);
        score
    }

    /// Whether this looks like a bootloader.
    #[must_use]
    pub fn is_bootloader(&self) -> bool {
        self.confidence() >= 30
    }
}

// ---------------------------------------------------------------------------
// Z80 Self-Modifying Code Detection
// ---------------------------------------------------------------------------

/// A detected self-modification site.
#[derive(Debug, Clone)]
pub struct SelfModSite {
    /// Address where the write occurs.
    pub write_address: u64,
    /// Target of the write (if computable).
    pub target: Option<u64>,
    /// Kind of self-modification.
    pub kind: SelfModKind,
}

/// Self-modification kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfModKind {
    /// LD (nn), A —" write byte to code region.
    DirectStore,
    /// LD (HL), r —" indexed write to code region.
    IndexedStore,
    /// LDIR or LDDR that covers a code region.
    BlockCopy,
    /// RST patch —" common Z80 self-patching trick.
    RstPatch,
    /// NOP slide —" replacing instructions with NOPs.
    NopSlide,
}

/// Z80 self-modifying code detector.
#[derive(Debug, Clone, Default)]
pub struct Z80SelfModifying {
    /// Detected self-modification sites.
    pub sites: Vec<SelfModSite>,
    /// Code regions (base, length) registered for monitoring.
    code_regions: Vec<(u64, usize)>,
}

impl Z80SelfModifying {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a code region to monitor for self-modification.
    pub fn add_code_region(&mut self, base: u64, len: usize) {
        self.code_regions.push((base, len));
    }

    /// Check whether `address` falls within a registered code region.
    #[must_use]
    pub fn is_code_address(&self, address: u64) -> bool {
        self.code_regions
            .iter()
            .any(|(base, len)| address >= *base && address < base + *len as u64)
    }

    /// Record a potential self-modification at `write_address`.
    pub fn record_write(&mut self, write_address: u64, target: Option<u64>, kind: SelfModKind) {
        self.sites.push(SelfModSite {
            write_address,
            target,
            kind,
        });
    }

    /// Whether any self-modification was detected.
    #[must_use]
    pub const fn has_self_mod(&self) -> bool {
        !self.sites.is_empty()
    }

    /// Sites of a specific kind.
    #[must_use]
    pub fn sites_of_kind(&self, kind: SelfModKind) -> Vec<&SelfModSite> {
        self.sites.iter().filter(|s| s.kind == kind).collect()
    }
}

// ---------------------------------------------------------------------------
// Top-level facade
// ---------------------------------------------------------------------------

/// A Z80 OS pattern analysis finding.
#[derive(Debug, Clone)]
pub struct Z80Finding {
    pub address: u64,
    pub message: String,
}

/// Top-level Z80 OS pattern analysis facade.
#[derive(Debug, Clone)]
pub struct Z80OsPatterns {
    /// CP/M BIOS call detector.
    pub bios: CpMBiosCall,
    /// CP/M BDOS call detector.
    pub bdos: Z80BdosCall,
    /// ZX Spectrum pattern detector.
    pub spectrum: ZxSpectrumPatterns,
    /// Bootloader detector.
    pub bootloader: Z80BootloaderDetector,
    /// Self-modifying code detector.
    pub self_mod: Z80SelfModifying,
    /// Findings.
    pub findings: Vec<Z80Finding>,
    /// Total instructions analyzed.
    pub total_instructions: usize,
}

impl Default for Z80OsPatterns {
    fn default() -> Self {
        Self::new()
    }
}

impl Z80OsPatterns {
    /// Create a new Z80 OS patterns analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bios: CpMBiosCall::default(),
            bdos: Z80BdosCall::new(),
            spectrum: ZxSpectrumPatterns::new(),
            bootloader: Z80BootloaderDetector::new(),
            self_mod: Z80SelfModifying::new(),
            findings: Vec::new(),
            total_instructions: 0,
        }
    }

    /// Create an analyzer tuned for CP/M binaries.
    #[must_use]
    pub fn for_cpm(bios_base: u64) -> Self {
        Self {
            bios: CpMBiosCall::new(bios_base),
            ..Self::new()
        }
    }

    /// Record a CALL 5 (BDOS call) at `address` with C register = `func`.
    pub fn record_bdos_call(&mut self, address: u64, func: u8) {
        self.bdos.record_call5(address, func);
        let name = Z80BdosCall::function_name(func).unwrap_or("?");
        self.findings.push(Z80Finding {
            address,
            message: format!("BDOS {name}"),
        });
    }

    /// Record a jump to a potential BIOS entry point.
    pub fn record_bios_jump(&mut self, address: u64, target: u64) {
        self.bios.record_call(address, target);
        if let Some(func) = self.bios.is_bios_jump(target) {
            let name = CpMBiosCall::function_name(func).unwrap_or("?");
            self.findings.push(Z80Finding {
                address,
                message: format!("BIOS {name}"),
            });
        }
    }

    /// Record a ZX Spectrum ROM call.
    pub fn record_spectrum_rom_call(&mut self, from: u64, target: u16) {
        self.spectrum.record_rom_call(from, target);
        if let Some(e) = ZxSpectrumPatterns::lookup_rom(target) {
            self.findings.push(Z80Finding {
                address: from,
                message: format!("Spectrum ROM {}", e.name),
            });
        }
    }

    /// Record a Z80 I/O port access.
    pub fn record_io(&mut self, address: u64, port: u8, is_write: bool) {
        self.spectrum.record_io(address, port, is_write);
    }

    /// Whether this looks like a CP/M binary.
    #[must_use]
    pub const fn is_cpm(&self) -> bool {
        self.bios.has_bios_calls() || self.bdos.total_calls() > 0
    }

    /// Whether this looks like a ZX Spectrum program.
    #[must_use]
    pub const fn is_spectrum(&self) -> bool {
        self.spectrum.has_rom_calls() || self.spectrum.uses_ula()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // â"€â"€ CpMBiosCall â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_bios_entry_address() {
        let bios = CpMBiosCall::new(0xE400);
        assert_eq!(bios.entry_address(0), 0xE400);
        assert_eq!(bios.entry_address(1), 0xE403);
        assert_eq!(bios.entry_address(4), 0xE40C);
    }

    #[test]
    fn test_bios_is_bios_jump_valid() {
        let bios = CpMBiosCall::new(0xE400);
        assert_eq!(bios.is_bios_jump(0xE400), Some(0));
        assert_eq!(bios.is_bios_jump(0xE403), Some(1));
        assert_eq!(bios.is_bios_jump(0xE40C), Some(4));
    }

    #[test]
    fn test_bios_is_bios_jump_invalid() {
        let bios = CpMBiosCall::new(0xE400);
        assert!(bios.is_bios_jump(0x1000).is_none());
        assert!(bios.is_bios_jump(0xE401).is_none()); // not aligned to 3
    }

    #[test]
    fn test_bios_record_call() {
        let mut bios = CpMBiosCall::new(0xE400);
        bios.record_call(0x0100, 0xE40C); // CONOUT
        assert!(bios.has_bios_calls());
        assert!(bios.uses_conout());
    }

    #[test]
    fn test_bios_function_name() {
        assert_eq!(CpMBiosCall::function_name(0), Some("BOOT"));
        assert_eq!(CpMBiosCall::function_name(4), Some("CONOUT"));
        assert_eq!(CpMBiosCall::function_name(200), None);
    }

    #[test]
    fn test_bios_uses_conin() {
        let mut bios = CpMBiosCall::new(0xE400);
        bios.record_call(0x100, bios.entry_address(3)); // CONIN
        assert!(bios.uses_conin());
    }

    // â"€â"€ Z80BdosCall â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_bdos_function_name() {
        assert_eq!(Z80BdosCall::function_name(9), Some("C_WRITESTR"));
        assert_eq!(Z80BdosCall::function_name(20), Some("F_READ"));
    }

    #[test]
    fn test_bdos_record_call5() {
        let mut bdos = Z80BdosCall::new();
        bdos.record_call5(0x0105, 9); // C_WRITESTR
        assert_eq!(bdos.total_calls(), 1);
        assert_eq!(bdos.call5_count, 1);
        assert!(bdos.has_console_io());
    }

    #[test]
    fn test_bdos_record_rst5() {
        let mut bdos = Z80BdosCall::new();
        bdos.record_rst5(0x200, 15); // F_OPEN
        assert_eq!(bdos.rst5_count, 1);
        assert!(bdos.has_file_io());
    }

    #[test]
    fn test_bdos_has_file_io() {
        let mut bdos = Z80BdosCall::new();
        bdos.record_call5(0, 21); // F_WRITE
        assert!(bdos.has_file_io());
    }

    #[test]
    fn test_bdos_no_console_initially() {
        let bdos = Z80BdosCall::new();
        assert!(!bdos.has_console_io());
    }

    // â"€â"€ ZxSpectrumPatterns â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_spectrum_lookup_rom() {
        assert!(ZxSpectrumPatterns::lookup_rom(0x0010).is_some());
        assert!(ZxSpectrumPatterns::lookup_rom(0x0016).is_some());
        assert!(ZxSpectrumPatterns::lookup_rom(0xFFFF).is_none());
    }

    #[test]
    fn test_spectrum_record_rom_call() {
        let mut sp = ZxSpectrumPatterns::new();
        sp.record_rom_call(0x8000, 0x0010); // PRINT_A_0
        assert!(sp.has_rom_calls());
        assert_eq!(sp.rom_calls.len(), 1);
    }

    #[test]
    fn test_spectrum_record_unknown_rom_call() {
        let mut sp = ZxSpectrumPatterns::new();
        sp.record_rom_call(0x8000, 0x0001); // Not in table
        assert!(!sp.has_rom_calls()); // Should not record unknown
    }

    #[test]
    fn test_spectrum_ula_read() {
        let mut sp = ZxSpectrumPatterns::new();
        sp.record_io(0x8000, 0xFE, false);
        assert!(sp.uses_ula());
        assert_eq!(sp.ula_reads, 1);
    }

    #[test]
    fn test_spectrum_ula_write() {
        let mut sp = ZxSpectrumPatterns::new();
        sp.record_io(0x8000, 0xFE, true);
        assert_eq!(sp.ula_writes, 1);
    }

    #[test]
    fn test_spectrum_kempston() {
        let mut sp = ZxSpectrumPatterns::new();
        sp.record_io(0x8000, 0x1F, false);
        assert!(sp.uses_kempston());
    }

    // â"€â"€ Z80BootloaderDetector â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_bootloader_check_reset_vector() {
        let bytes = [0xC3, 0x00, 0x80]; // JP 0x8000
        assert_eq!(
            Z80BootloaderDetector::check_reset_vector(&bytes),
            Some(0x8000)
        );
    }

    #[test]
    fn test_bootloader_check_not_jp() {
        let bytes2 = [0x00u8, 0x00, 0x00]; // NOP, not JP
        assert!(Z80BootloaderDetector::check_reset_vector(&bytes2).is_none());
    }

    #[test]
    fn test_bootloader_confidence_empty() {
        let bd = Z80BootloaderDetector::new();
        assert_eq!(bd.confidence(), 0);
        assert!(!bd.is_bootloader());
    }

    #[test]
    fn test_bootloader_record_sp_init() {
        let mut bd = Z80BootloaderDetector::new();
        bd.record_sp_init(0x0003, 0xFFFF);
        assert!(bd.sp_initialized);
        assert_eq!(bd.initial_sp, Some(0xFFFF));
    }

    #[test]
    fn test_bootloader_confidence_with_patterns() {
        let mut bd = Z80BootloaderDetector::new();
        bd.record(0x0000, BootloaderPattern::ResetVector);
        bd.record(0x0003, BootloaderPattern::SpInit);
        assert!(bd.confidence() >= 30);
        assert!(bd.is_bootloader());
    }

    // â"€â"€ Z80SelfModifying â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_selfmod_add_code_region() {
        let mut sm = Z80SelfModifying::new();
        sm.add_code_region(0x8000, 0x1000);
        assert!(sm.is_code_address(0x8000));
        assert!(sm.is_code_address(0x8FFF));
        assert!(!sm.is_code_address(0x9000));
    }

    #[test]
    fn test_selfmod_record_write() {
        let mut sm = Z80SelfModifying::new();
        sm.record_write(0x8100, Some(0x8100), SelfModKind::DirectStore);
        assert!(sm.has_self_mod());
        assert_eq!(sm.sites.len(), 1);
    }

    #[test]
    fn test_selfmod_sites_of_kind() {
        let mut sm = Z80SelfModifying::new();
        sm.record_write(0x100, None, SelfModKind::NopSlide);
        sm.record_write(0x200, None, SelfModKind::DirectStore);
        assert_eq!(sm.sites_of_kind(SelfModKind::NopSlide).len(), 1);
        assert_eq!(sm.sites_of_kind(SelfModKind::DirectStore).len(), 1);
        assert_eq!(sm.sites_of_kind(SelfModKind::BlockCopy).len(), 0);
    }

    #[test]
    fn test_selfmod_no_self_mod_default() {
        let sm = Z80SelfModifying::new();
        assert!(!sm.has_self_mod());
    }

    // â"€â"€ Z80OsPatterns â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_os_patterns_record_bdos() {
        let mut os = Z80OsPatterns::new();
        os.record_bdos_call(0x0105, 9);
        assert!(os.is_cpm());
        assert_eq!(os.findings.len(), 1);
    }

    #[test]
    fn test_os_patterns_record_bios() {
        let mut os = Z80OsPatterns::for_cpm(0xE400);
        os.record_bios_jump(0x100, 0xE40C);
        assert!(os.is_cpm());
    }

    #[test]
    fn test_os_patterns_spectrum() {
        let mut os = Z80OsPatterns::new();
        os.record_spectrum_rom_call(0x8000, 0x0010);
        assert!(os.is_spectrum());
    }

    #[test]
    fn test_os_patterns_not_cpm_initially() {
        let os = Z80OsPatterns::new();
        assert!(!os.is_cpm());
        assert!(!os.is_spectrum());
    }

    // â"€â"€ Additional coverage â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_bios_multiple_calls_counted() {
        let mut bios = CpMBiosCall::new(0xE400);
        bios.record_call(0x100, 0xE400); // BOOT
        bios.record_call(0x104, 0xE403); // WBOOT
        bios.record_call(0x108, 0xE40C); // CONOUT
        assert_eq!(bios.calls.len(), 3);
    }

    #[test]
    fn test_bdos_multiple_functions() {
        let mut bdos = Z80BdosCall::new();
        bdos.record_call5(0x100, 1); // C_READ
        bdos.record_call5(0x104, 2); // C_WRITE
        bdos.record_call5(0x108, 9); // C_WRITESTR
        assert_eq!(bdos.functions_used.len(), 3);
        assert!(bdos.has_console_io());
    }

    #[test]
    fn test_selfmod_multiple_regions() {
        let mut sm = Z80SelfModifying::new();
        sm.add_code_region(0x1000, 0x100);
        sm.add_code_region(0x2000, 0x200);
        assert!(sm.is_code_address(0x1050));
        assert!(sm.is_code_address(0x2100));
        assert!(!sm.is_code_address(0x3000));
    }

    #[test]
    fn test_bootloader_int_mode_pattern() {
        let mut bd = Z80BootloaderDetector::new();
        bd.record(0x0006, BootloaderPattern::IntModeSet);
        assert!(!bd.has_reset_vector);
        // 15 points < 30 threshold → not a bootloader
        assert_eq!(bd.confidence(), 15);
        assert!(!bd.is_bootloader());
    }

    #[test]
    fn test_bootloader_full_pattern() {
        let mut bd = Z80BootloaderDetector::new();
        bd.record(0x0000, BootloaderPattern::ResetVector);
        bd.record(0x0003, BootloaderPattern::SpInit);
        bd.record(0x0006, BootloaderPattern::LdirCopy);
        bd.record(0x0010, BootloaderPattern::IntModeSet);
        assert!(bd.is_bootloader());
        assert_eq!(bd.confidence(), 90); // 30+25+20+15 = 90
    }

    #[test]
    fn test_os_patterns_io_recorded() {
        let mut os = Z80OsPatterns::new();
        os.record_io(0x1000, 0xFE, true); // ULA write
        os.record_io(0x1001, 0x1F, false); // Kempston read
        assert_eq!(os.spectrum.io_accesses.len(), 2);
        assert!(os.is_spectrum());
    }

    #[test]
    fn test_bios_read_function_name() {
        assert_eq!(CpMBiosCall::function_name(13), Some("READ"));
        assert_eq!(CpMBiosCall::function_name(14), Some("WRITE"));
    }

    #[test]
    fn test_bdos_file_read_write() {
        let mut bdos = Z80BdosCall::new();
        bdos.record_call5(0, 15); // F_OPEN
        bdos.record_call5(4, 20); // F_READ
        bdos.record_call5(8, 21); // F_WRITE
        assert!(bdos.has_file_io());
        assert_eq!(bdos.total_calls(), 3);
    }
}
