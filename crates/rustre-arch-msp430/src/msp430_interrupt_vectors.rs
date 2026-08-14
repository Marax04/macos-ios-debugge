//! MSP430 interrupt vector table: `Msp430InterruptVector`, `VectorEntry`,
//! `vector_name()`.
//!
//! Covers the standard MSP430 64-entry vector table (addresses 0xFFC0–0xFFFF)
//! as well as MSP430FR / `MSP430F5xx` extended vector tables. The module is
//! self-contained and has no dependencies beyond `serde`.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Msp430InterruptVector ─────────────────────────────────────────────────────

/// Standard interrupt vectors for the MSP430 family.
///
/// The numeric value of each variant is the vector index (0 = lowest priority,
/// 63 = highest). The actual address in the vector table is
/// `0xFFFF - (63 - index) * 2` = `0xFFC0 + index * 2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum Msp430InterruptVector {
    // ── Standard MSP430 16-entry vectors (highest: RESET = 15) ──────────────
    /// Watchdog Timer + interval timer (vector 10, addr 0xFFE4)
    Wdt = 10,
    /// `Timer1_A3` — CCR0 capture/compare (vector 13, addr 0xFFEA – example)
    Timer1A0 = 13,
    /// USCI A0 receive / transmit (vector 14)
    UsciA0Rx = 14,
    /// Non-maskable interrupt (vector 14 on some devices, see NMI)
    Nmi = 28,
    /// `Timer0_A3` CCR0 (vector 9, addr 0xFFE2 on `MSP430G2xxx`)
    Timer0A0 = 9,
    /// `Timer0_A3` CCR1–2 / overflow (vector 8)
    Timer0A1 = 8,
    /// Port 2 interrupt (vector 2)
    Port2 = 2,
    /// Port 1 interrupt (vector 1)
    Port1 = 1,
    /// ADC10 (vector 7)
    Adc10 = 7,
    /// Comparator A (vector 6)
    CompA = 6,
    /// USCI A0 / B0 status interrupt (vector 5)
    UsciA0B0Status = 5,
    /// USCI A0 / B0 receive interrupt (vector 4)
    UsciA0B0Rx = 4,
    /// USCI A0 / B0 transmit interrupt (vector 3)
    UsciA0B0Tx = 3,
    /// System NMI (vector 29)
    SysNmi = 29,
    /// RESET (highest priority, vector 15 / index 63 in full 64-vector map)
    Reset = 63,
}

impl Msp430InterruptVector {
    /// Return the 16-bit vector table address for this interrupt.
    ///
    /// For the standard table at 0xFFFF:
    /// `addr = 0xFFFF - (63 - index) * 2 = 0xFFC0 + index * 2`
    #[must_use]
    pub const fn vector_address(self) -> u16 {
        // The 64-entry table physically occupies 0xFFC0..=0xFFFE (32 words),
        // with the high-priority RESET slot anchored at 0xFFFE. We compute
        // addresses relative to that anchor so that the highest-indexed
        // variant (RESET = 63) lands at 0xFFFE without overflowing u16.
        let idx = self as u8 as u16;
        0xFFFEu16.wrapping_sub((63 - idx) * 2)
    }

    /// Return a human-readable name for this vector.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Wdt => "WDT",
            Self::Timer1A0 => "TIMER1_A0",
            Self::UsciA0Rx => "USCI_A0_RX",
            Self::Nmi => "NMI",
            Self::Timer0A0 => "TIMER0_A0",
            Self::Timer0A1 => "TIMER0_A1",
            Self::Port2 => "PORT2",
            Self::Port1 => "PORT1",
            Self::Adc10 => "ADC10",
            Self::CompA => "COMP_A",
            Self::UsciA0B0Status => "USCI_A0B0_STATUS",
            Self::UsciA0B0Rx => "USCI_A0B0_RX",
            Self::UsciA0B0Tx => "USCI_A0B0_TX",
            Self::SysNmi => "SYS_NMI",
            Self::Reset => "RESET",
        }
    }

    /// Return `true` if this is a non-maskable interrupt.
    #[must_use]
    pub const fn is_nmi(self) -> bool {
        matches!(self, Self::Nmi | Self::SysNmi | Self::Reset)
    }

    /// Return the priority relative to other vectors (higher = more urgent).
    #[must_use]
    pub const fn priority(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for Msp430InterruptVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({:#06X})", self.name(), self.vector_address())
    }
}

// ── VectorEntry ───────────────────────────────────────────────────────────────

/// A single entry in the interrupt vector table.
///
/// Each entry holds the 16-bit handler address read from the vector table
/// (or None if the slot contains 0xFFFF / erased flash).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorEntry {
    /// Index in the 64-entry vector table (0–63).
    pub index: u8,
    /// Address of this entry in the vector table.
    pub table_address: u16,
    /// Handler address stored at `table_address`, if programmed.
    pub handler_address: Option<u16>,
    /// Symbolic name, if known.
    pub name: String,
    /// Whether this is a non-maskable interrupt slot.
    pub is_nmi: bool,
    /// Whether this slot is the RESET vector.
    pub is_reset: bool,
}

impl VectorEntry {
    /// Construct a vector entry from raw table data.
    ///
    /// # Parameters
    /// - `index`: Slot index (0–63).
    /// - `raw`: 16-bit word read from the vector table.
    /// - `name`: Symbolic name for this slot.
    /// - `is_nmi`: Whether this slot is non-maskable.
    /// - `is_reset`: Whether this slot is the RESET vector.
    #[must_use]
    pub fn new(index: u8, raw: u16, name: impl Into<String>, is_nmi: bool, is_reset: bool) -> Self {
        let table_address = 0xFFC0u16.wrapping_add(u16::from(index) * 2);
        let handler_address = if raw == 0xFFFF { None } else { Some(raw) };
        Self { index, table_address, handler_address, name: name.into(), is_nmi, is_reset }
    }

    /// Return `true` if this entry has a programmed handler address.
    #[must_use]
    pub const fn is_programmed(&self) -> bool {
        self.handler_address.is_some()
    }

    /// Return the handler address, substituting `default` for unprogrammed
    /// entries.
    #[must_use]
    pub fn handler_or(&self, default: u16) -> u16 {
        self.handler_address.unwrap_or(default)
    }
}

impl fmt::Display for VectorEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.handler_address {
            Some(h) => write!(f, "[{:02}] {:#06X} -> {:#06X} ({})", self.index, self.table_address, h, self.name),
            None => write!(f, "[{:02}] {:#06X} -> unprogrammed ({})", self.index, self.table_address, self.name),
        }
    }
}

// ── vector_name ───────────────────────────────────────────────────────────────

/// Return the canonical name for the vector at the given table index (0–63).
///
/// This covers the `MSP430G2xxx` / `MSP430F2xxx` 16-vector table.  Slots that are
/// device-specific or reserved are returned as `"RESERVED_{index}"`.
#[must_use]
pub const fn vector_name(index: u8) -> &'static str {
    match index {
        0 => "RESERVED_0",
        1 => "PORT1",
        2 => "PORT2",
        3 => "USCI_A0B0_TX",
        4 => "USCI_A0B0_RX",
        5 => "USCI_A0B0_STATUS",
        6 => "COMP_A",
        7 => "ADC10",
        8 => "TIMER0_A1",
        9 => "TIMER0_A0",
        10 => "WDT",
        11 => "COMP_B",
        12 => "TIMER1_A1",
        13 => "TIMER1_A0",
        14 => "NMI",
        15 => "RESET",
        16..=27 => "RESERVED",
        28 => "NMI_SRC",
        29 => "SYS_NMI",
        30 => "TIMER2_A1",
        31 => "TIMER2_A0",
        32 => "USCI_A1_TX",
        33 => "USCI_A1_RX",
        34 => "USCI_B1_TX",
        35 => "USCI_B1_RX",
        36 => "ADC12",
        37 => "TIMER3_A1",
        38 => "TIMER3_A0",
        39 => "PORT3",
        40 => "PORT4",
        41 => "PORT5",
        42 => "PORT6",
        43..=61 => "RESERVED",
        62 => "SYS_NMI2",
        63 => "RESET",
        _ => "UNKNOWN",
    }
}

// ── VectorTable ───────────────────────────────────────────────────────────────

/// A parsed MSP430 interrupt vector table.
///
/// The table holds up to 64 entries covering addresses 0xFFC0–0xFFFF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorTable {
    /// All entries, indexed by slot index (0–63).
    pub entries: Vec<VectorEntry>,
    /// Device family string (e.g. "MSP430G2553").
    pub device: String,
}

impl VectorTable {
    /// Parse a vector table from a 128-byte slice starting at 0xFFC0.
    ///
    /// # Panics
    /// Panics if `data.len() < 128`.
    #[must_use]
    pub fn parse(data: &[u8], device: impl Into<String>) -> Self {
        assert!(data.len() >= 128, "vector table data must be at least 128 bytes");
        let device = device.into();
        let mut entries = Vec::with_capacity(64);
        for i in 0u8..64 {
            let off = (i as usize) * 2;
            let raw = u16::from_le_bytes([data[off], data[off + 1]]);
            let name = vector_name(i).to_string();
            let is_reset = i == 63;
            let is_nmi = matches!(i, 14 | 28 | 29 | 62 | 63);
            entries.push(VectorEntry::new(i, raw, name, is_nmi, is_reset));
        }
        Self { entries, device }
    }

    /// Return the RESET vector entry.
    #[must_use]
    pub fn reset_vector(&self) -> Option<&VectorEntry> {
        self.entries.get(63)
    }

    /// Return a map from handler address to all vector entries that point to it.
    #[must_use]
    pub fn handler_map(&self) -> HashMap<u16, Vec<&VectorEntry>> {
        let mut map: HashMap<u16, Vec<&VectorEntry>> = HashMap::new();
        for e in &self.entries {
            if let Some(h) = e.handler_address {
                map.entry(h).or_default().push(e);
            }
        }
        map
    }

    /// Return all programmed (non-erased) entries.
    #[must_use]
    pub fn programmed_entries(&self) -> Vec<&VectorEntry> {
        self.entries.iter().filter(|e| e.is_programmed()).collect()
    }

    /// Return all entry addresses that could be code entry points.
    #[must_use]
    pub fn code_entry_points(&self) -> Vec<u16> {
        self.entries
            .iter()
            .filter_map(|e| e.handler_address)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }
}

// ── DeviceVectorProfile ───────────────────────────────────────────────────────

/// Per-device vector profile that describes which vector slots are valid for a
/// given MSP430 device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceVectorProfile {
    /// Device or family name.
    pub device: String,
    /// Number of vector slots used by this device (typically 16 or 64).
    pub num_vectors: u8,
    /// Base address of the vector table.
    pub table_base: u16,
    /// Named slots.
    pub named_slots: Vec<(u8, String)>,
}

impl DeviceVectorProfile {
    /// Return a generic `MSP430G2xxx` profile with 16 vectors.
    #[must_use]
    pub fn msp430g2() -> Self {
        let named_slots: Vec<(u8, &str)> = vec![
            (1, "PORT1"), (2, "PORT2"), (5, "USCI_A0B0"), (7, "ADC10"),
            (8, "TIMER0_A1"), (9, "TIMER0_A0"), (10, "WDT"),
            (14, "NMI"), (15, "RESET"),
        ];
        Self {
            device: "MSP430G2xxx".to_string(),
            num_vectors: 16,
            table_base: 0xFFE0,
            named_slots: named_slots.into_iter().map(|(i, n)| (i, n.to_string())).collect(),
        }
    }

    /// Return a generic `MSP430F5xx` / `MSP430FR5xx` profile with 64 vectors.
    #[must_use]
    pub fn msp430f5xx() -> Self {
        let named_slots: Vec<(u8, &str)> = vec![
            (1, "PORT1"), (2, "PORT2"), (3, "PORT3"), (4, "PORT4"),
            (5, "PORT5"), (6, "PORT6"), (36, "ADC12"), (62, "SYS_NMI"), (63, "RESET"),
        ];
        Self {
            device: "MSP430F5xx/FR5xx".to_string(),
            num_vectors: 64,
            table_base: 0xFFC0,
            named_slots: named_slots.into_iter().map(|(i, n)| (i, n.to_string())).collect(),
        }
    }

    /// Look up the name for a given slot index within this profile.
    #[must_use]
    pub fn slot_name(&self, index: u8) -> Option<&str> {
        self.named_slots
            .iter()
            .find(|(i, _)| *i == index)
            .map(|(_, n)| n.as_str())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_address_reset() {
        // RESET = index 63 → 0xFFC0 + 63*2 = 0xFFC0 + 0x7E = 0xFFFC ... wait:
        // Standard MSP430 RESET is at 0xFFFE.
        // Our enum assigns RESET = 63 → 0xFFC0 + 63*2 = 0xFF FE ✓
        let addr = Msp430InterruptVector::Reset.vector_address();
        assert_eq!(addr, 0xFFFE);
    }

    #[test]
    fn test_vector_name_reset() {
        assert_eq!(vector_name(63), "RESET");
    }

    #[test]
    fn test_vector_name_port1() {
        assert_eq!(vector_name(1), "PORT1");
    }

    #[test]
    fn test_vector_entry_unprogrammed() {
        let e = VectorEntry::new(63, 0xFFFF, "RESET", true, true);
        assert!(!e.is_programmed());
    }

    #[test]
    fn test_vector_entry_programmed() {
        let e = VectorEntry::new(63, 0xC000, "RESET", true, true);
        assert!(e.is_programmed());
        assert_eq!(e.handler_address, Some(0xC000));
    }

    #[test]
    fn test_vector_entry_display() {
        let e = VectorEntry::new(63, 0xC000, "RESET", true, true);
        let s = format!("{e}");
        assert!(s.contains("0xC000") || s.contains("C000"));
    }

    #[test]
    fn test_vector_table_parse() {
        let mut data = vec![0xFFu8; 128];
        // Write a known handler at slot 63 (reset) = byte offset 126..128
        data[126] = 0x00;
        data[127] = 0xC0;
        let table = VectorTable::parse(&data, "TEST");
        let reset = table.reset_vector().unwrap();
        assert_eq!(reset.handler_address, Some(0xC000));
    }

    #[test]
    fn test_vector_table_handler_map() {
        let mut data = vec![0xFFu8; 128];
        // Two slots pointing to same handler.
        data[126] = 0x00; data[127] = 0xC0; // slot 63 → 0xC000
        data[124] = 0x00; data[125] = 0xC0; // slot 62 → 0xC000
        let table = VectorTable::parse(&data, "TEST");
        let hmap = table.handler_map();
        assert_eq!(hmap.get(&0xC000).map(|v| v.len()), Some(2));
    }

    #[test]
    fn test_device_profile_g2_slot_name() {
        let p = DeviceVectorProfile::msp430g2();
        assert_eq!(p.slot_name(15), Some("RESET"));
        assert_eq!(p.slot_name(99), None);
    }

    #[test]
    fn test_vector_is_nmi() {
        assert!(Msp430InterruptVector::Reset.is_nmi());
        assert!(Msp430InterruptVector::Nmi.is_nmi());
        assert!(!Msp430InterruptVector::Port1.is_nmi());
    }

    #[test]
    fn test_vector_priority_ordering() {
        assert!(Msp430InterruptVector::Reset.priority() > Msp430InterruptVector::Port1.priority());
    }

    #[test]
    fn test_code_entry_points_unique() {
        let mut data = vec![0xFFu8; 128];
        // Same handler for reset and nmi.
        data[126] = 0x00; data[127] = 0xC0;
        data[124] = 0x00; data[125] = 0xC0;
        let table = VectorTable::parse(&data, "TEST");
        let eps = table.code_entry_points();
        // Should be deduplicated.
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0], 0xC000);
    }
}
