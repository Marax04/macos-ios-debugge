//! MSP430 Special Function Register (SFR) address map.
//!
//! Provides a comprehensive, device-independent SFR address catalogue for
//! the MSP430 family.  Covers peripheral memory-mapped registers from the
//! base family (SFR, Timer_A, USART/USCI, ADC, WDT, Flash controller, DMA,
//! port I/O, comparator, and system clock modules).
//!
//! The catalogue is intentionally flat: it maps a 16-bit address to a
//! `SfrEntry` containing the register name, parent peripheral kind, bit
//! width, and whether the register is read-only, write-only, or read-write.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// PeripheralKind
// ---------------------------------------------------------------------------

/// Top-level category for an MSP430 peripheral.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeripheralKind {
    /// Special Function Registers (SFR) — interrupt enable/flag at 0x00–0x1F.
    Sfr,
    /// Port I/O registers (P1, P2 … P8).
    PortIo,
    /// `Timer_A` module.
    TimerA,
    /// `Timer_B` module.
    TimerB,
    /// USART / USCI serial interface.
    Usci,
    /// ADC10 analogue-to-digital converter.
    Adc10,
    /// ADC12 analogue-to-digital converter.
    Adc12,
    /// DAC12 digital-to-analogue converter.
    Dac12,
    /// Watchdog timer.
    Watchdog,
    /// Flash / FRAM controller.
    Flash,
    /// Basic Clock Module / Unified Clock System.
    Clock,
    /// DMA controller.
    Dma,
    /// `Comparator_A` / `Comparator_B`.
    Comparator,
    /// Hardware multiplier.
    Multiplier,
    /// Real-Time Clock (`RTC_A` / `RTC_B`).
    Rtc,
    /// LCD controller.
    Lcd,
    /// Brown-out reset / supply voltage supervisor.
    Svs,
    /// USB controller.
    Usb,
    /// System module (SYSCTL, etc.).
    System,
    /// Unknown / uncategorised.
    Unknown,
}

impl PeripheralKind {
    /// Return the short mnemonic for this peripheral kind.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Sfr => "SFR",
            Self::PortIo => "PORT",
            Self::TimerA => "TA",
            Self::TimerB => "TB",
            Self::Usci => "USCI",
            Self::Adc10 => "ADC10",
            Self::Adc12 => "ADC12",
            Self::Dac12 => "DAC12",
            Self::Watchdog => "WDT",
            Self::Flash => "FLASH",
            Self::Clock => "CLK",
            Self::Dma => "DMA",
            Self::Comparator => "COMP",
            Self::Multiplier => "MPY",
            Self::Rtc => "RTC",
            Self::Lcd => "LCD",
            Self::Svs => "SVS",
            Self::Usb => "USB",
            Self::System => "SYS",
            Self::Unknown => "?",
        }
    }
}

impl std::fmt::Display for PeripheralKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mnemonic())
    }
}

// ---------------------------------------------------------------------------
// SfrAccess
// ---------------------------------------------------------------------------

/// Access mode for a register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SfrAccess {
    /// Read-write.
    Rw,
    /// Read-only.
    R,
    /// Write-only.
    W,
    /// Set-only (writing 0 has no effect).
    Set,
    /// Clear-on-read.
    Rc,
}

impl std::fmt::Display for SfrAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Rw => "R/W",
            Self::R => "R",
            Self::W => "W",
            Self::Set => "SET",
            Self::Rc => "RC",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// SfrEntry
// ---------------------------------------------------------------------------

/// A single SFR map entry.
#[derive(Debug, Clone)]
pub struct SfrEntry {
    /// 16-bit memory-mapped address.
    pub address: u16,
    /// Short register name (e.g. "IE1", "TACTL").
    pub name: &'static str,
    /// Long description.
    pub description: &'static str,
    /// Parent peripheral category.
    pub kind: PeripheralKind,
    /// Register width in bits (8 or 16).
    pub width_bits: u8,
    /// Access mode.
    pub access: SfrAccess,
    /// Whether the register must be accessed with a password/unlock sequence.
    pub password_protected: bool,
}

impl SfrEntry {
    /// Create a standard 8-bit R/W register entry.
    const fn byte_rw(
        address: u16,
        name: &'static str,
        description: &'static str,
        kind: PeripheralKind,
    ) -> Self {
        Self {
            address,
            name,
            description,
            kind,
            width_bits: 8,
            access: SfrAccess::Rw,
            password_protected: false,
        }
    }

    /// Create a standard 16-bit R/W register entry.
    const fn word_rw(
        address: u16,
        name: &'static str,
        description: &'static str,
        kind: PeripheralKind,
    ) -> Self {
        Self {
            address,
            name,
            description,
            kind,
            width_bits: 16,
            access: SfrAccess::Rw,
            password_protected: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Static SFR table
// ---------------------------------------------------------------------------

/// The static SFR table for the MSP430 base family.
static SFR_TABLE: &[SfrEntry] = &[
    // ── Special Function Registers (0x0000–0x001F) ────────────────────────
    SfrEntry::byte_rw(0x0000, "IE1",   "Interrupt Enable 1",  PeripheralKind::Sfr),
    SfrEntry::byte_rw(0x0001, "IE2",   "Interrupt Enable 2",  PeripheralKind::Sfr),
    SfrEntry::byte_rw(0x0002, "IFG1",  "Interrupt Flag 1",    PeripheralKind::Sfr),
    SfrEntry::byte_rw(0x0003, "IFG2",  "Interrupt Flag 2",    PeripheralKind::Sfr),
    SfrEntry::byte_rw(0x0004, "ME1",   "Module Enable 1",     PeripheralKind::Sfr),
    SfrEntry::byte_rw(0x0005, "ME2",   "Module Enable 2",     PeripheralKind::Sfr),
    // ── Port 1 (0x0020–0x002F) ────────────────────────────────────────────
    SfrEntry::byte_rw(0x0020, "P1IN",  "Port 1 Input",        PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x0021, "P1OUT", "Port 1 Output",       PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x0022, "P1DIR", "Port 1 Direction",    PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x0023, "P1IFG", "Port 1 Interrupt Flag", PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x0024, "P1IES", "Port 1 Int Edge Select", PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x0025, "P1IE",  "Port 1 Interrupt Enable", PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x0026, "P1SEL", "Port 1 Function Select", PeripheralKind::PortIo),
    // ── Port 2 (0x0028–0x002F) ────────────────────────────────────────────
    SfrEntry::byte_rw(0x0028, "P2IN",  "Port 2 Input",        PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x0029, "P2OUT", "Port 2 Output",       PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x002A, "P2DIR", "Port 2 Direction",    PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x002B, "P2IFG", "Port 2 Interrupt Flag", PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x002C, "P2IES", "Port 2 Int Edge Select", PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x002D, "P2IE",  "Port 2 Interrupt Enable", PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x002E, "P2SEL", "Port 2 Function Select", PeripheralKind::PortIo),
    // ── Port 3–4 (0x0018–0x001F) ─────────────────────────────────────────
    SfrEntry::byte_rw(0x0018, "P3IN",  "Port 3 Input",        PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x0019, "P3OUT", "Port 3 Output",       PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x001A, "P3DIR", "Port 3 Direction",    PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x001B, "P3SEL", "Port 3 Function Select", PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x001C, "P4IN",  "Port 4 Input",        PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x001D, "P4OUT", "Port 4 Output",       PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x001E, "P4DIR", "Port 4 Direction",    PeripheralKind::PortIo),
    SfrEntry::byte_rw(0x001F, "P4SEL", "Port 4 Function Select", PeripheralKind::PortIo),
    // ── Watchdog Timer (0x0120) ───────────────────────────────────────────
    SfrEntry { address: 0x0120, name: "WDTCTL", description: "Watchdog Timer Control",
               kind: PeripheralKind::Watchdog, width_bits: 16,
               access: SfrAccess::Rw, password_protected: true },
    // ── Flash Controller (0x0128–0x012E) ─────────────────────────────────
    SfrEntry::word_rw(0x0128, "FCTL1", "Flash Control 1",    PeripheralKind::Flash),
    SfrEntry::word_rw(0x012A, "FCTL2", "Flash Control 2",    PeripheralKind::Flash),
    SfrEntry::word_rw(0x012C, "FCTL3", "Flash Control 3",    PeripheralKind::Flash),
    // ── Basic Clock Module (0x0053–0x0057) ───────────────────────────────
    SfrEntry::byte_rw(0x0053, "DCOCTL",  "DCO Control",        PeripheralKind::Clock),
    SfrEntry::byte_rw(0x0056, "BCSCTL1", "Basic Clock Control 1", PeripheralKind::Clock),
    SfrEntry::byte_rw(0x0057, "BCSCTL2", "Basic Clock Control 2", PeripheralKind::Clock),
    SfrEntry::byte_rw(0x0058, "BCSCTL3", "Basic Clock Control 3", PeripheralKind::Clock),
    // ── Timer_A (0x0160–0x018E) ───────────────────────────────────────────
    SfrEntry::word_rw(0x0160, "TACTL",   "Timer_A Control",    PeripheralKind::TimerA),
    SfrEntry::word_rw(0x0162, "TACCTL0", "Capture/Compare Control 0", PeripheralKind::TimerA),
    SfrEntry::word_rw(0x0164, "TACCTL1", "Capture/Compare Control 1", PeripheralKind::TimerA),
    SfrEntry::word_rw(0x0166, "TACCTL2", "Capture/Compare Control 2", PeripheralKind::TimerA),
    SfrEntry::word_rw(0x0170, "TAR",     "Timer_A Counter",    PeripheralKind::TimerA),
    SfrEntry::word_rw(0x0172, "TACCR0",  "Capture/Compare 0",  PeripheralKind::TimerA),
    SfrEntry::word_rw(0x0174, "TACCR1",  "Capture/Compare 1",  PeripheralKind::TimerA),
    SfrEntry::word_rw(0x0176, "TACCR2",  "Capture/Compare 2",  PeripheralKind::TimerA),
    SfrEntry { address: 0x018E, name: "TAIV", description: "Timer_A Interrupt Vector",
               kind: PeripheralKind::TimerA, width_bits: 16,
               access: SfrAccess::R, password_protected: false },
    // ── USCI_A0 (0x0060–0x006F) ──────────────────────────────────────────
    SfrEntry::byte_rw(0x0060, "UCA0CTL0",  "USCI_A0 Control 0",  PeripheralKind::Usci),
    SfrEntry::byte_rw(0x0061, "UCA0CTL1",  "USCI_A0 Control 1",  PeripheralKind::Usci),
    SfrEntry::byte_rw(0x0062, "UCA0BR0",   "USCI_A0 Baud Rate 0", PeripheralKind::Usci),
    SfrEntry::byte_rw(0x0063, "UCA0BR1",   "USCI_A0 Baud Rate 1", PeripheralKind::Usci),
    SfrEntry::byte_rw(0x0064, "UCA0MCTL",  "USCI_A0 Modulation Control", PeripheralKind::Usci),
    SfrEntry { address: 0x0065, name: "UCA0STAT", description: "USCI_A0 Status",
               kind: PeripheralKind::Usci, width_bits: 8,
               access: SfrAccess::Rw, password_protected: false },
    SfrEntry { address: 0x0066, name: "UCA0RXBUF", description: "USCI_A0 Receive Buffer",
               kind: PeripheralKind::Usci, width_bits: 8,
               access: SfrAccess::R, password_protected: false },
    SfrEntry { address: 0x0067, name: "UCA0TXBUF", description: "USCI_A0 Transmit Buffer",
               kind: PeripheralKind::Usci, width_bits: 8,
               access: SfrAccess::W, password_protected: false },
    // ── USCI_B0 (0x0068–0x006F) ──────────────────────────────────────────
    SfrEntry::byte_rw(0x0068, "UCB0CTL0",  "USCI_B0 Control 0",  PeripheralKind::Usci),
    SfrEntry::byte_rw(0x0069, "UCB0CTL1",  "USCI_B0 Control 1",  PeripheralKind::Usci),
    SfrEntry::byte_rw(0x006A, "UCB0BR0",   "USCI_B0 Baud Rate 0", PeripheralKind::Usci),
    SfrEntry::byte_rw(0x006B, "UCB0BR1",   "USCI_B0 Baud Rate 1", PeripheralKind::Usci),
    // ── ADC10 (0x004A–0x004F) ────────────────────────────────────────────
    SfrEntry::byte_rw(0x004A, "ADC10DTC0", "ADC10 Data Transfer Control 0", PeripheralKind::Adc10),
    SfrEntry::byte_rw(0x004B, "ADC10DTC1", "ADC10 Data Transfer Control 1", PeripheralKind::Adc10),
    SfrEntry::byte_rw(0x004C, "ADC10AE0",  "ADC10 Analog Enable 0", PeripheralKind::Adc10),
    SfrEntry::word_rw(0x01B0, "ADC10CTL0", "ADC10 Control 0",    PeripheralKind::Adc10),
    SfrEntry::word_rw(0x01B2, "ADC10CTL1", "ADC10 Control 1",    PeripheralKind::Adc10),
    SfrEntry { address: 0x01B4, name: "ADC10MEM", description: "ADC10 Memory",
               kind: PeripheralKind::Adc10, width_bits: 16,
               access: SfrAccess::R, password_protected: false },
    SfrEntry::word_rw(0x01B8, "ADC10SA",   "ADC10 Data Transfer Start Address", PeripheralKind::Adc10),
    // ── Hardware Multiplier (0x0130–0x013E) ───────────────────────────────
    SfrEntry::word_rw(0x0130, "MPY",    "Operand 1 (unsigned multiply)", PeripheralKind::Multiplier),
    SfrEntry::word_rw(0x0132, "MPYS",   "Operand 1 (signed multiply)",   PeripheralKind::Multiplier),
    SfrEntry::word_rw(0x0134, "MAC",    "Operand 1 (unsigned MAC)",      PeripheralKind::Multiplier),
    SfrEntry::word_rw(0x0136, "MACS",   "Operand 1 (signed MAC)",        PeripheralKind::Multiplier),
    SfrEntry::word_rw(0x0138, "OP2",    "Operand 2",                     PeripheralKind::Multiplier),
    SfrEntry { address: 0x013A, name: "RESLO",  description: "Result Low Word",   kind: PeripheralKind::Multiplier, width_bits: 16, access: SfrAccess::R, password_protected: false },
    SfrEntry { address: 0x013C, name: "RESHI",  description: "Result High Word",  kind: PeripheralKind::Multiplier, width_bits: 16, access: SfrAccess::R, password_protected: false },
    SfrEntry { address: 0x013E, name: "SUMEXT", description: "Sum Extend",        kind: PeripheralKind::Multiplier, width_bits: 16, access: SfrAccess::R, password_protected: false },
    // ── Comparator_A (0x0059–0x005A) ─────────────────────────────────────
    SfrEntry::byte_rw(0x0059, "CACTL1", "Comparator_A Control 1", PeripheralKind::Comparator),
    SfrEntry::byte_rw(0x005A, "CACTL2", "Comparator_A Control 2", PeripheralKind::Comparator),
    SfrEntry::byte_rw(0x005B, "CAPD",   "Comparator_A Port Disable", PeripheralKind::Comparator),
];

// ---------------------------------------------------------------------------
// Msp430PeripheralMap
// ---------------------------------------------------------------------------

/// Indexed map from SFR address to `SfrEntry`.
pub struct Msp430PeripheralMap {
    /// Address → index into `SFR_TABLE`.
    index: HashMap<u16, usize>,
}

impl Msp430PeripheralMap {
    /// Build the map from the static SFR table.
    #[must_use]
    pub fn new() -> Self {
        let mut index = HashMap::with_capacity(SFR_TABLE.len());
        for (i, entry) in SFR_TABLE.iter().enumerate() {
            index.insert(entry.address, i);
        }
        Self { index }
    }

    /// Look up the SFR entry at `address`.
    ///
    /// Returns `None` if the address is not a known SFR.
    #[must_use]
    pub fn entry_at(&self, address: u16) -> Option<&'static SfrEntry> {
        self.index.get(&address).map(|&i| &SFR_TABLE[i])
    }

    /// Look up the name of the SFR at `address`.
    ///
    /// Returns `None` if the address is not a known SFR.
    #[must_use]
    pub fn name_at(&self, address: u16) -> Option<&'static str> {
        self.entry_at(address).map(|e| e.name)
    }

    /// Return all entries for a given peripheral kind.
    #[must_use]
    pub fn entries_for_kind(&self, kind: PeripheralKind) -> Vec<&'static SfrEntry> {
        SFR_TABLE
            .iter()
            .filter(|e| e.kind == kind)
            .collect()
    }

    /// Return all known SFR entries.
    #[must_use]
    pub fn all_entries(&self) -> &'static [SfrEntry] {
        SFR_TABLE
    }

    /// Total number of mapped SFR addresses.
    #[must_use]
    pub fn len(&self) -> usize {
        SFR_TABLE.len()
    }

    /// Return `true` if no entries are mapped.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        SFR_TABLE.is_empty()
    }

    /// Check whether `address` is a known SFR.
    #[must_use]
    pub fn is_sfr(&self, address: u16) -> bool {
        self.index.contains_key(&address)
    }

    /// Check whether `address` is a known password-protected register.
    #[must_use]
    pub fn is_password_protected(&self, address: u16) -> bool {
        self.entry_at(address)
            .is_some_and(|e| e.password_protected)
    }

    /// Search entries by partial name match (case-insensitive).
    #[must_use]
    pub fn search_by_name(&self, query: &str) -> Vec<&'static SfrEntry> {
        let q = query.to_uppercase();
        SFR_TABLE
            .iter()
            .filter(|e| e.name.to_uppercase().contains(&q))
            .collect()
    }
}

impl Default for Msp430PeripheralMap {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Free function: sfr_name_at
// ---------------------------------------------------------------------------

/// Return the name of the SFR at `address`, or `None`.
///
/// This is a convenience wrapper around `Msp430PeripheralMap` for one-off
/// lookups where constructing a full map is not needed.  The lookup is
/// performed via a linear scan of the static table and is O(n).
#[must_use]
pub fn sfr_name_at(address: u16) -> Option<&'static str> {
    SFR_TABLE
        .iter()
        .find(|e| e.address == address)
        .map(|e| e.name)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> Msp430PeripheralMap {
        Msp430PeripheralMap::new()
    }

    #[test]
    fn test_map_not_empty() {
        assert!(!map().is_empty());
    }

    #[test]
    fn test_name_at_wdtctl() {
        assert_eq!(map().name_at(0x0120), Some("WDTCTL"));
    }

    #[test]
    fn test_name_at_tactl() {
        assert_eq!(map().name_at(0x0160), Some("TACTL"));
    }

    #[test]
    fn test_name_at_ie1() {
        assert_eq!(map().name_at(0x0000), Some("IE1"));
    }

    #[test]
    fn test_name_at_unknown() {
        assert!(map().name_at(0xFFFF).is_none());
    }

    #[test]
    fn test_sfr_name_at_free_fn() {
        assert_eq!(sfr_name_at(0x0000), Some("IE1"));
    }

    #[test]
    fn test_sfr_name_at_unknown_free_fn() {
        assert!(sfr_name_at(0xAAAA).is_none());
    }

    #[test]
    fn test_is_sfr_known() {
        assert!(map().is_sfr(0x0160));
    }

    #[test]
    fn test_is_sfr_unknown() {
        assert!(!map().is_sfr(0xBEEF));
    }

    #[test]
    fn test_is_password_protected() {
        assert!(map().is_password_protected(0x0120)); // WDTCTL
    }

    #[test]
    fn test_not_password_protected() {
        assert!(!map().is_password_protected(0x0000)); // IE1
    }

    #[test]
    fn test_entries_for_kind_timer_a() {
        let entries = map().entries_for_kind(PeripheralKind::TimerA);
        assert!(!entries.is_empty());
        assert!(entries.iter().all(|e| e.kind == PeripheralKind::TimerA));
    }

    #[test]
    fn test_entries_for_kind_port_io() {
        let entries = map().entries_for_kind(PeripheralKind::PortIo);
        assert!(!entries.is_empty());
    }

    #[test]
    fn test_search_by_name_p1() {
        let entries = map().search_by_name("P1");
        assert!(!entries.is_empty());
        assert!(entries.iter().all(|e| e.name.contains("P1")));
    }

    #[test]
    fn test_entry_at_width() {
        let e = map().entry_at(0x0160).unwrap(); // TACTL
        assert_eq!(e.width_bits, 16);
    }

    #[test]
    fn test_entry_at_byte_width() {
        let e = map().entry_at(0x0000).unwrap(); // IE1
        assert_eq!(e.width_bits, 8);
    }

    #[test]
    fn test_read_only_register() {
        let e = map().entry_at(0x018E).unwrap(); // TAIV
        assert_eq!(e.access, SfrAccess::R);
    }

    #[test]
    fn test_write_only_register() {
        let e = map().entry_at(0x0067).unwrap(); // UCA0TXBUF
        assert_eq!(e.access, SfrAccess::W);
    }

    #[test]
    fn test_adc10_mem_read_only() {
        let e = map().entry_at(0x01B4).unwrap(); // ADC10MEM
        assert_eq!(e.access, SfrAccess::R);
    }

    #[test]
    fn test_multiplier_reslo() {
        let e = map().entry_at(0x013A).unwrap(); // RESLO
        assert_eq!(e.kind, PeripheralKind::Multiplier);
        assert_eq!(e.access, SfrAccess::R);
    }

    #[test]
    fn test_peripheral_kind_mnemonic() {
        assert_eq!(PeripheralKind::TimerA.mnemonic(), "TA");
        assert_eq!(PeripheralKind::Watchdog.mnemonic(), "WDT");
    }

    #[test]
    fn test_all_entries_count() {
        let m = map();
        assert!(m.len() >= 50);
    }

    #[test]
    fn test_all_entries_ref() {
        let m = map();
        assert!(!m.all_entries().is_empty());
    }
}
