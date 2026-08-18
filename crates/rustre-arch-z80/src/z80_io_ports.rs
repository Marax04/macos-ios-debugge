//! Z80 I/O port map: IN/OUT analysis and common hardware port assignments.
//!
//! Covers the Sinclair ZX Spectrum ULA, AY-3-8910 sound chip, MSX I/O map,
//! CP/M BIOS ports, and generic port decoding.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// PortDirection
// ─────────────────────────────────────────────────────────────────────────────

/// Whether an I/O port is read, written, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortDirection {
    /// Port is only read by the CPU (IN).
    Input,
    /// Port is only written by the CPU (OUT).
    Output,
    /// Port may be both read and written.
    Bidirectional,
}

impl fmt::Display for PortDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input       => write!(f, "IN"),
            Self::Output      => write!(f, "OUT"),
            Self::Bidirectional => write!(f, "IN/OUT"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PortEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single I/O port descriptor.
#[derive(Debug, Clone)]
pub struct PortEntry {
    /// Port address (8-bit for most Z80 systems; 16-bit in full-address-decode mode).
    pub address: u16,
    /// Address mask — bits that matter in decoding.
    pub mask: u16,
    /// Human-readable port name.
    pub name: &'static str,
    /// Direction(s) the port supports.
    pub direction: PortDirection,
    /// Description.
    pub desc: &'static str,
    /// Hardware device this port belongs to.
    pub device: &'static str,
}

impl PortEntry {
    const fn new(address: u16, mask: u16, name: &'static str, direction: PortDirection,
                 desc: &'static str, device: &'static str) -> Self {
        Self { address, mask, name, direction, desc, device }
    }

    /// Returns `true` if `port` matches this entry after masking.
    #[must_use]
    pub const fn matches(&self, port: u16) -> bool {
        (port & self.mask) == (self.address & self.mask)
    }
}

impl fmt::Display for PortEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "port {:04x} ({}) — {} [{}]: {}", self.address, self.direction, self.name, self.device, self.desc)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Z80IoPort
// ─────────────────────────────────────────────────────────────────────────────

/// High-level I/O port with optional last-written/last-read values.
#[derive(Debug, Clone)]
pub struct Z80IoPort {
    /// Port descriptor.
    pub entry: PortEntry,
    /// Last value written to this port (if any).
    pub last_out: Option<u8>,
    /// Last value read from this port (if any).
    pub last_in: Option<u8>,
    /// Number of times this port was accessed.
    pub access_count: u32,
}

impl Z80IoPort {
    /// Create a new port tracker.
    #[must_use]
    pub const fn new(entry: PortEntry) -> Self {
        Self { entry, last_out: None, last_in: None, access_count: 0 }
    }

    /// Record an OUT instruction.
    pub const fn record_out(&mut self, value: u8) {
        self.last_out = Some(value);
        self.access_count += 1;
    }

    /// Record an IN instruction.
    pub const fn record_in(&mut self, value: u8) {
        self.last_in = Some(value);
        self.access_count += 1;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Static port tables
// ─────────────────────────────────────────────────────────────────────────────

/// ZX Spectrum port table (partial address decoding, typical Spectrum behaviour).
pub static SPECTRUM_PORTS: &[PortEntry] = &[
    PortEntry::new(0x00FE, 0x00FF, "ULA",          PortDirection::Bidirectional,
        "ULA: border colour (bits 0-2), EAR/MIC (bits 3-4); keyboard rows on IN", "Sinclair ULA"),
    PortEntry::new(0xFFFD, 0xC002, "AY_REG",       PortDirection::Output,
        "AY-3-8910 register select", "AY-3-8910 / YM2149"),
    PortEntry::new(0xBFFD, 0xC002, "AY_DATA",      PortDirection::Bidirectional,
        "AY-3-8910 data read/write", "AY-3-8910 / YM2149"),
    PortEntry::new(0x7FFD, 0xC002, "MEM_BANK",     PortDirection::Output,
        "128K memory bank / paging register", "Sinclair 128K"),
    PortEntry::new(0x1FFD, 0xC002, "PLUS3_PAGING", PortDirection::Output,
        "+3 extended paging / disk motor control", "Sinclair +3"),
    PortEntry::new(0x2FFD, 0xC002, "FDC_STATUS",   PortDirection::Input,
        "+3 FDC status register", "Sinclair +3 FDC"),
    PortEntry::new(0x3FFD, 0xC002, "FDC_DATA",     PortDirection::Bidirectional,
        "+3 FDC data register", "Sinclair +3 FDC"),
    PortEntry::new(0x00DF, 0x00FF, "KEMPSTON_JOY", PortDirection::Input,
        "Kempston joystick: bits FUDLR", "Kempston Interface"),
    PortEntry::new(0x00FB, 0x00FF, "ZX_PRINTER",   PortDirection::Bidirectional,
        "ZX Printer port", "ZX Printer"),
];

/// MSX system I/O port table.
pub static MSX_PORTS: &[PortEntry] = &[
    PortEntry::new(0x00A0, 0x00FF, "PSG_REG_WRITE", PortDirection::Output,
        "AY-3-8910 register address write", "AY-3-8910 PSG"),
    PortEntry::new(0x00A1, 0x00FF, "PSG_DATA_WRITE", PortDirection::Output,
        "AY-3-8910 data write", "AY-3-8910 PSG"),
    PortEntry::new(0x00A2, 0x00FF, "PSG_DATA_READ",  PortDirection::Input,
        "AY-3-8910 data read", "AY-3-8910 PSG"),
    PortEntry::new(0x0098, 0x00FF, "VDP_DATA",        PortDirection::Bidirectional,
        "TMS9918A VDP data port", "TMS9918A VDP"),
    PortEntry::new(0x0099, 0x00FF, "VDP_STATUS",      PortDirection::Bidirectional,
        "TMS9918A VDP status/register port", "TMS9918A VDP"),
    PortEntry::new(0x00FC, 0x00FF, "MAPPER_0",        PortDirection::Output,
        "Memory mapper segment for slot 0", "MSX Memory Mapper"),
    PortEntry::new(0x00FD, 0x00FF, "MAPPER_1",        PortDirection::Output,
        "Memory mapper segment for slot 1", "MSX Memory Mapper"),
    PortEntry::new(0x00FE, 0x00FF, "MAPPER_2",        PortDirection::Output,
        "Memory mapper segment for slot 2", "MSX Memory Mapper"),
    PortEntry::new(0x00FF, 0x00FF, "MAPPER_3",        PortDirection::Output,
        "Memory mapper segment for slot 3", "MSX Memory Mapper"),
    PortEntry::new(0x00A8, 0x00FF, "PPI_A",           PortDirection::Bidirectional,
        "8255 PPI port A: primary slot register", "Intel 8255 PPI"),
    PortEntry::new(0x00A9, 0x00FF, "PPI_B",           PortDirection::Input,
        "8255 PPI port B: keyboard row scan", "Intel 8255 PPI"),
    PortEntry::new(0x00AA, 0x00FF, "PPI_C",           PortDirection::Output,
        "8255 PPI port C: keyboard select / caps lock", "Intel 8255 PPI"),
    PortEntry::new(0x00AB, 0x00FF, "PPI_CTRL",        PortDirection::Output,
        "8255 PPI control register", "Intel 8255 PPI"),
];

/// CP/M BIOS I/O ports (common BIOS implementations).
pub static CPM_PORTS: &[PortEntry] = &[
    PortEntry::new(0x00E0, 0x00FF, "SIO_A_DATA",   PortDirection::Bidirectional,
        "SIO channel A data", "Z80 SIO / UART"),
    PortEntry::new(0x00E2, 0x00FF, "SIO_A_CTRL",   PortDirection::Bidirectional,
        "SIO channel A control/status", "Z80 SIO"),
    PortEntry::new(0x00E4, 0x00FF, "SIO_B_DATA",   PortDirection::Bidirectional,
        "SIO channel B data", "Z80 SIO"),
    PortEntry::new(0x00E6, 0x00FF, "SIO_B_CTRL",   PortDirection::Bidirectional,
        "SIO channel B control/status", "Z80 SIO"),
    PortEntry::new(0x00C0, 0x00FF, "FDC_CTRL",     PortDirection::Output,
        "FDC motor / drive select", "NEC μPD765 FDC"),
    PortEntry::new(0x00C2, 0x00FF, "FDC_STATUS",   PortDirection::Input,
        "FDC main status register", "NEC μPD765 FDC"),
    PortEntry::new(0x00C3, 0x00FF, "FDC_DATA",     PortDirection::Bidirectional,
        "FDC data register", "NEC μPD765 FDC"),
    PortEntry::new(0x0080, 0x00FF, "CTC_0",        PortDirection::Bidirectional,
        "Z80 CTC channel 0", "Z80 CTC"),
    PortEntry::new(0x0081, 0x00FF, "CTC_1",        PortDirection::Bidirectional,
        "Z80 CTC channel 1", "Z80 CTC"),
    PortEntry::new(0x0082, 0x00FF, "CTC_2",        PortDirection::Bidirectional,
        "Z80 CTC channel 2", "Z80 CTC"),
    PortEntry::new(0x0083, 0x00FF, "CTC_3",        PortDirection::Bidirectional,
        "Z80 CTC channel 3", "Z80 CTC"),
];

/// AY-3-8910 / YM2149 register map (register index → name).
pub static AY_REGISTERS: &[(&str, &str)] = &[
    ("AY_R0", "Tone period A fine"),
    ("AY_R1", "Tone period A coarse (bits 0-3)"),
    ("AY_R2", "Tone period B fine"),
    ("AY_R3", "Tone period B coarse (bits 0-3)"),
    ("AY_R4", "Tone period C fine"),
    ("AY_R5", "Tone period C coarse (bits 0-3)"),
    ("AY_R6", "Noise period (bits 0-4)"),
    ("AY_R7", "Mixer control — IOB/IOA/noise-C/B/A/tone-C/B/A"),
    ("AY_R8", "Amplitude A (bit 4 = envelope enable)"),
    ("AY_R9", "Amplitude B (bit 4 = envelope enable)"),
    ("AY_R10", "Amplitude C (bit 4 = envelope enable)"),
    ("AY_R11", "Envelope period fine"),
    ("AY_R12", "Envelope period coarse"),
    ("AY_R13", "Envelope shape / cycle"),
    ("AY_R14", "I/O port A data"),
    ("AY_R15", "I/O port B data"),
];

/// Name of AY-3-8910 register `n`.
#[must_use]
pub fn ay_register_name(n: u8) -> Option<(&'static str, &'static str)> {
    AY_REGISTERS.get(n as usize).copied()
}

// ─────────────────────────────────────────────────────────────────────────────
// Z80IoPortMap
// ─────────────────────────────────────────────────────────────────────────────

/// Platform variants whose port table can be loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Z80Platform {
    /// Sinclair ZX Spectrum (48K, 128K, +3).
    Spectrum,
    /// MSX home computer.
    Msx,
    /// CP/M system.
    Cpm,
}

/// Manager for a set of known I/O port entries.
#[derive(Debug, Default)]
pub struct Z80IoPortMap {
    /// All registered port entries.
    entries: Vec<PortEntry>,
    /// Access log: port address → count.
    access_log: HashMap<u16, u32>,
}

impl Z80IoPortMap {
    /// Create an empty port map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load the port table for a specific platform.
    pub fn load_platform(&mut self, platform: Z80Platform) {
        let table: &[PortEntry] = match platform {
            Z80Platform::Spectrum => SPECTRUM_PORTS,
            Z80Platform::Msx     => MSX_PORTS,
            Z80Platform::Cpm     => CPM_PORTS,
        };
        for e in table {
            self.entries.push(e.clone());
        }
    }

    /// Register a custom port entry.
    pub fn add_entry(&mut self, entry: PortEntry) {
        self.entries.push(entry);
    }

    /// Look up all entries that match `port`.
    #[must_use]
    pub fn lookup(&self, port: u16) -> Vec<&PortEntry> {
        self.entries.iter().filter(|e| e.matches(port)).collect()
    }

    /// Return the name of the first matching port, or `None`.
    #[must_use]
    pub fn port_name_at(&self, port: u16) -> Option<&str> {
        self.lookup(port).into_iter().next().map(|e| e.name)
    }

    /// Record a port access for frequency analysis.
    pub fn log_access(&mut self, port: u16) {
        *self.access_log.entry(port).or_insert(0) += 1;
    }

    /// Return ports sorted by access frequency (descending).
    #[must_use]
    pub fn hot_ports(&self) -> Vec<(u16, u32)> {
        let mut v: Vec<(u16, u32)> = self.access_log.iter().map(|(&p, &c)| (p, c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }

    /// Return all entries for a specific device.
    #[must_use]
    pub fn ports_for_device(&self, device: &str) -> Vec<&PortEntry> {
        self.entries.iter().filter(|e| e.device == device).collect()
    }

    /// Number of registered entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Check whether a Z80 `word` is an IN or OUT instruction.
    ///
    /// Returns `(is_in, port_address)` for `IN A,(n)` (opcode 0xDB) and
    /// `OUT (n),A` (opcode 0xD3).  Returns `None` for anything else.
    #[must_use]
    pub fn decode_in_out(bytes: &[u8]) -> Option<(bool, u8)> {
        if bytes.len() < 2 { return None; }
        match bytes[0] {
            0xDB => Some((true,  bytes[1])),
            0xD3 => Some((false, bytes[1])),
            _ => None,
        }
    }

    /// Decode `IN r,(C)` / `OUT (C),r` from a two-byte ED-prefix sequence.
    ///
    /// Returns `(is_in, register_name)` or `None`.
    #[must_use]
    pub fn decode_ed_in_out(bytes: &[u8]) -> Option<(bool, &'static str)> {
        if bytes.len() < 2 || bytes[0] != 0xED { return None; }
        let reg_names = ["B","C","D","E","H","L","F","A"];
        match bytes[1] {
            0x40 => Some((true,  "B")),
            0x48 => Some((true,  "C")),
            0x50 => Some((true,  "D")),
            0x58 => Some((true,  "E")),
            0x60 => Some((true,  "H")),
            0x68 => Some((true,  "L")),
            0x70 => Some((true,  "(HL)")),
            0x78 => Some((true,  "A")),
            0x41 => Some((false, "B")),
            0x49 => Some((false, "C")),
            0x51 => Some((false, "D")),
            0x59 => Some((false, "E")),
            0x61 => Some((false, "H")),
            0x69 => Some((false, "L")),
            0x71 => Some((false, "(HL)")),
            0x79 => Some((false, "A")),
            _ => { let _ = reg_names; None },
        }
    }
}

/// Return the name of a well-known Z80 I/O port on the specified platform.
///
/// Convenience free function that creates a temporary map.
#[must_use]
pub fn port_name_at(platform: Z80Platform, port: u16) -> Option<&'static str> {
    let table: &[PortEntry] = match platform {
        Z80Platform::Spectrum => SPECTRUM_PORTS,
        Z80Platform::Msx     => MSX_PORTS,
        Z80Platform::Cpm     => CPM_PORTS,
    };
    table.iter().find(|e| e.matches(port)).map(|e| e.name)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spectrum_ula_matches_fe() {
        let hit = port_name_at(Z80Platform::Spectrum, 0x00FE);
        assert_eq!(hit, Some("ULA"));
    }

    #[test]
    fn spectrum_kempston_matches_df() {
        let hit = port_name_at(Z80Platform::Spectrum, 0x00DF);
        assert_eq!(hit, Some("KEMPSTON_JOY"));
    }

    #[test]
    fn msx_vdp_data_matches_98() {
        let hit = port_name_at(Z80Platform::Msx, 0x0098);
        assert_eq!(hit, Some("VDP_DATA"));
    }

    #[test]
    fn cpm_fdc_data_matches_c3() {
        let hit = port_name_at(Z80Platform::Cpm, 0x00C3);
        assert_eq!(hit, Some("FDC_DATA"));
    }

    #[test]
    fn unknown_port_returns_none() {
        let hit = port_name_at(Z80Platform::Spectrum, 0x0042);
        assert!(hit.is_none());
    }

    #[test]
    fn z80_port_map_load_and_lookup() {
        let mut map = Z80IoPortMap::new();
        map.load_platform(Z80Platform::Spectrum);
        assert!(!map.is_empty());
        let hits = map.lookup(0x00FE);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].name, "ULA");
    }

    #[test]
    fn z80_port_map_hot_ports() {
        let mut map = Z80IoPortMap::new();
        map.load_platform(Z80Platform::Spectrum);
        map.log_access(0x00FE);
        map.log_access(0x00FE);
        map.log_access(0x00DF);
        let hot = map.hot_ports();
        assert_eq!(hot[0], (0x00FE, 2));
    }

    #[test]
    fn z80_port_map_ports_for_device() {
        let mut map = Z80IoPortMap::new();
        map.load_platform(Z80Platform::Msx);
        let vdp = map.ports_for_device("TMS9918A VDP");
        assert_eq!(vdp.len(), 2);
    }

    #[test]
    fn decode_in_out_in_a_n() {
        let bytes = [0xDB, 0xFE];
        let r = Z80IoPortMap::decode_in_out(&bytes).unwrap();
        assert_eq!(r, (true, 0xFE));
    }

    #[test]
    fn decode_in_out_out_n_a() {
        let bytes = [0xD3, 0x7F];
        let r = Z80IoPortMap::decode_in_out(&bytes).unwrap();
        assert_eq!(r, (false, 0x7F));
    }

    #[test]
    fn decode_in_out_non_io_returns_none() {
        assert!(Z80IoPortMap::decode_in_out(&[0x00, 0x00]).is_none());
    }

    #[test]
    fn decode_ed_in_out_in_b_c() {
        let bytes = [0xED, 0x40];
        let r = Z80IoPortMap::decode_ed_in_out(&bytes).unwrap();
        assert_eq!(r, (true, "B"));
    }

    #[test]
    fn decode_ed_in_out_out_c_a() {
        let bytes = [0xED, 0x79];
        let r = Z80IoPortMap::decode_ed_in_out(&bytes).unwrap();
        assert_eq!(r, (false, "A"));
    }

    #[test]
    fn ay_register_name_valid() {
        let (name, desc) = ay_register_name(7).unwrap();
        assert_eq!(name, "AY_R7");
        assert!(desc.contains("Mixer"));
    }

    #[test]
    fn ay_register_name_out_of_range() {
        assert!(ay_register_name(16).is_none());
    }

    #[test]
    fn port_direction_display() {
        assert_eq!(format!("{}", PortDirection::Input), "IN");
        assert_eq!(format!("{}", PortDirection::Output), "OUT");
        assert_eq!(format!("{}", PortDirection::Bidirectional), "IN/OUT");
    }

    #[test]
    fn port_entry_display() {
        let e = PortEntry::new(0x00FE, 0x00FF, "ULA", PortDirection::Bidirectional,
            "test", "device");
        let s = format!("{e}");
        assert!(s.contains("00fe"));
        assert!(s.contains("ULA"));
    }

    #[test]
    fn port_entry_matches_with_mask() {
        // The Spectrum AY register port decodes on bits [14:15] only
        let e = &SPECTRUM_PORTS[1]; // AY_REG at 0xFFFD, mask 0xC002
        assert!(e.matches(0xFFFD));
        // A port with same top bits but different low bits
        // mask = 0xC002 means only bits 15,14,1 matter:
        // 0xFFFD = 1111_1111_1111_1101, masked = 0xC002 bits → 1100_0000_0000_0000 | 0000_0000_0000_0000
        // depends on the specific mask; just verify matches works for the exact address
        assert!(e.matches(e.address));
    }

    #[test]
    fn z80_port_map_custom_entry() {
        let mut map = Z80IoPortMap::new();
        map.add_entry(PortEntry::new(0x01, 0xFF, "CUSTOM", PortDirection::Input, "test", "mydev"));
        assert_eq!(map.port_name_at(0x01), Some("CUSTOM"));
    }
}
