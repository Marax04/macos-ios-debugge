//! MSP430 peripheral / SFR map: `Msp430PeripheralMap`, `Peripheral`,
//! `PeripheralRegister`, `sfr_name()`.
//!
//! Provides a comprehensive, data-driven model of the MSP430 special-function
//! register space. The SFR address range is 0x0000–0x01FF (byte-addressable)
//! on the original MSP430 and extended to 0x0FFF on MSP430FR devices.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── PeripheralRegister ────────────────────────────────────────────────────────

/// A single register within a peripheral.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeripheralRegister {
    /// Byte offset from the peripheral base address.
    pub offset: u16,
    /// Canonical register name (e.g. `"TA0CTL"`).
    pub name: String,
    /// Optional short description.
    pub description: String,
    /// Register width in bytes (1 or 2).
    pub width: u8,
    /// Whether this register is read-only.
    pub read_only: bool,
    /// Whether this register is write-only.
    pub write_only: bool,
    /// Bitmask of reserved bits (writing 1 to these causes undefined behaviour).
    pub reserved_mask: u16,
    /// Reset / power-on value.
    pub reset_value: u16,
}

impl PeripheralRegister {
    /// Construct a standard read-write 16-bit register.
    #[must_use]
    pub fn rw16(offset: u16, name: impl Into<String>, desc: impl Into<String>) -> Self {
        Self {
            offset,
            name: name.into(),
            description: desc.into(),
            width: 2,
            read_only: false,
            write_only: false,
            reserved_mask: 0,
            reset_value: 0,
        }
    }

    /// Construct a standard read-write 8-bit register.
    #[must_use]
    pub fn rw8(offset: u16, name: impl Into<String>, desc: impl Into<String>) -> Self {
        Self { width: 1, ..Self::rw16(offset, name, desc) }
    }

    /// Construct a read-only register.
    #[must_use]
    pub fn ro16(offset: u16, name: impl Into<String>, desc: impl Into<String>) -> Self {
        Self { read_only: true, ..Self::rw16(offset, name, desc) }
    }

    /// Return the absolute address given the peripheral base.
    #[must_use]
    pub const fn address(&self, base: u16) -> u16 {
        base.wrapping_add(self.offset)
    }
}

impl fmt::Display for PeripheralRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rw = match (self.read_only, self.write_only) {
            (true, _) => "RO",
            (_, true) => "WO",
            _ => "RW",
        };
        write!(f, "{:+04X} {} [{}{}] {}", self.offset, self.name, rw, self.width * 8, self.description)
    }
}

// ── Peripheral ────────────────────────────────────────────────────────────────

/// A named MSP430 peripheral covering a contiguous address range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peripheral {
    /// Peripheral name (e.g. `"TIMER_A0"`).
    pub name: String,
    /// Base address of this peripheral.
    pub base_address: u16,
    /// Size of the peripheral address window in bytes.
    pub size: u16,
    /// Short description.
    pub description: String,
    /// Registers within this peripheral, sorted by offset.
    pub registers: Vec<PeripheralRegister>,
}

impl Peripheral {
    /// Construct a new peripheral.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        base_address: u16,
        size: u16,
        description: impl Into<String>,
        registers: Vec<PeripheralRegister>,
    ) -> Self {
        let mut regs = registers;
        regs.sort_by_key(|r| r.offset);
        Self { name: name.into(), base_address, size, description: description.into(), registers: regs }
    }

    /// Return the inclusive address range `[base, base+size)`.
    #[must_use]
    pub const fn address_range(&self) -> (u16, u16) {
        (self.base_address, self.base_address.wrapping_add(self.size))
    }

    /// Return `true` if the given address falls within this peripheral.
    #[must_use]
    pub const fn contains_address(&self, addr: u16) -> bool {
        let (lo, hi) = self.address_range();
        addr >= lo && addr < hi
    }

    /// Look up a register by its offset within this peripheral.
    #[must_use]
    pub fn register_at_offset(&self, offset: u16) -> Option<&PeripheralRegister> {
        self.registers.iter().find(|r| r.offset == offset)
    }

    /// Look up a register by its absolute address.
    #[must_use]
    pub fn register_at_address(&self, addr: u16) -> Option<&PeripheralRegister> {
        if addr < self.base_address {
            return None;
        }
        self.register_at_offset(addr - self.base_address)
    }

    /// Look up a register by name (case-insensitive).
    #[must_use]
    pub fn register_by_name(&self, name: &str) -> Option<&PeripheralRegister> {
        let upper = name.to_ascii_uppercase();
        self.registers.iter().find(|r| r.name.to_ascii_uppercase() == upper)
    }
}

impl fmt::Display for Peripheral {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} @ {:#06X}+{:#04X} — {}", self.name, self.base_address, self.size, self.description)
    }
}

// ── sfr_name ──────────────────────────────────────────────────────────────────

/// Return the canonical SFR name for a well-known MSP430 register address.
///
/// Covers the most common registers across the MSP430 family. Returns
/// `None` for addresses not in the SFR map.
#[must_use]
pub const fn sfr_name(addr: u16) -> Option<&'static str> {
    match addr {
        // ── Special Function Registers (0x0000–0x000F) ──────────────────────
        0x0000 => Some("IE1"),
        0x0001 => Some("IE2"),
        0x0002 => Some("IFG1"),
        0x0003 => Some("IFG2"),
        0x0004 => Some("ME1"),
        0x0005 => Some("ME2"),
        // ── Port 1 (0x0020–0x002F) ─────────────────────────────────────────
        0x0020 => Some("P1IN"),
        0x0021 => Some("P1OUT"),
        0x0022 => Some("P1DIR"),
        0x0023 => Some("P1IFG"),
        0x0024 => Some("P1IES"),
        0x0025 => Some("P1IE"),
        0x0026 => Some("P1SEL"),
        0x0027 => Some("P1SEL2"),
        // ── Port 2 (0x0028–0x002F) ─────────────────────────────────────────
        0x0028 => Some("P2IN"),
        0x0029 => Some("P2OUT"),
        0x002A => Some("P2DIR"),
        0x002B => Some("P2IFG"),
        0x002C => Some("P2IES"),
        0x002D => Some("P2IE"),
        0x002E => Some("P2SEL"),
        0x002F => Some("P2SEL2"),
        // ── Port 3 (0x0018–0x001F) ─────────────────────────────────────────
        0x0018 => Some("P3IN"),
        0x0019 => Some("P3OUT"),
        0x001A => Some("P3DIR"),
        0x001B => Some("P3SEL"),
        // ── ADC10 (0x0048–0x005F) ──────────────────────────────────────────
        0x0048 => Some("ADC10DTC0"),
        0x0049 => Some("ADC10DTC1"),
        0x004A => Some("ADC10AE0"),
        0x004B => Some("ADC10AE1"),
        0x01B0 => Some("ADC10CTL0"),
        0x01B2 => Some("ADC10CTL1"),
        0x01B4 => Some("ADC10MEM"),
        0x01B8 => Some("ADC10SA"),
        // ── USCI A0 / B0 (0x005D–0x00FF) ──────────────────────────────────
        0x0060 => Some("UCA0CTL0"),
        0x0061 => Some("UCA0CTL1"),
        0x0062 => Some("UCA0BR0"),
        0x0063 => Some("UCA0BR1"),
        0x0064 => Some("UCA0MCTL"),
        0x0065 => Some("UCA0STAT"),
        0x0066 => Some("UCA0RXBUF"),
        0x0067 => Some("UCA0TXBUF"),
        0x0068 => Some("UCB0CTL0"),
        0x0069 => Some("UCB0CTL1"),
        0x006A => Some("UCB0BR0"),
        0x006B => Some("UCB0BR1"),
        0x006C => Some("UCB0I2CIE"),
        0x006D => Some("UCB0STAT"),
        0x006E => Some("UCB0RXBUF"),
        0x006F => Some("UCB0TXBUF"),
        // ── Timer A0 (0x0160–0x018F) ───────────────────────────────────────
        0x0160 => Some("TA0CTL"),
        0x0162 => Some("TA0CCTL0"),
        0x0164 => Some("TA0CCTL1"),
        0x0166 => Some("TA0CCTL2"),
        0x0170 => Some("TA0R"),
        0x0172 => Some("TA0CCR0"),
        0x0174 => Some("TA0CCR1"),
        0x0176 => Some("TA0CCR2"),
        0x017E => Some("TA0IV"),
        // ── Timer A1 (0x0180–0x01AF) ───────────────────────────────────────
        0x0180 => Some("TA1CTL"),
        0x0182 => Some("TA1CCTL0"),
        0x0184 => Some("TA1CCTL1"),
        0x0186 => Some("TA1CCTL2"),
        0x0190 => Some("TA1R"),
        0x0192 => Some("TA1CCR0"),
        0x0194 => Some("TA1CCR1"),
        0x0196 => Some("TA1CCR2"),
        0x019E => Some("TA1IV"),
        // ── Watchdog Timer (0x0120) ─────────────────────────────────────────
        0x0120 => Some("WDTCTL"),
        // ── Basic Clock (0x0052–0x0057) ─────────────────────────────────────
        0x0052 => Some("DCOCTL"),
        0x0053 => Some("BCSCTL1"),
        0x0054 => Some("BCSCTL2"),
        0x0057 => Some("BCSCTL3"),
        // ── Flash Controller (0x0128–0x012F) ────────────────────────────────
        0x0128 => Some("FCTL1"),
        0x012A => Some("FCTL2"),
        0x012C => Some("FCTL3"),
        // ── System module (0x0180 / FR devices) ─────────────────────────────
        0x0100 => Some("SYSCTL"),
        0x0102 => Some("SYSBSLC"),
        0x0108 => Some("SYSIV"),
        // ── Comparator A+ (0x0058–0x005B) ───────────────────────────────────
        0x0059 => Some("CACTL1"),
        0x005A => Some("CACTL2"),
        0x005B => Some("CAPD"),
        _ => None,
    }
}

// ── Msp430PeripheralMap ───────────────────────────────────────────────────────

/// A complete map of MSP430 peripherals for a specific device.
///
/// The map indexes peripherals both by base address and by name, providing
/// fast lookup in both dimensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Msp430PeripheralMap {
    /// Device or family name.
    pub device: String,
    /// Peripherals indexed by base address.
    pub by_address: BTreeMap<u16, Peripheral>,
    /// Peripheral names indexed by base address (for fast name lookup).
    name_index: BTreeMap<String, u16>,
}

impl Msp430PeripheralMap {
    /// Construct an empty peripheral map for `device`.
    #[must_use]
    pub fn new(device: impl Into<String>) -> Self {
        Self { device: device.into(), by_address: BTreeMap::new(), name_index: BTreeMap::new() }
    }

    /// Insert a peripheral into the map.
    pub fn insert(&mut self, peripheral: Peripheral) {
        let base = peripheral.base_address;
        self.name_index.insert(peripheral.name.clone(), base);
        self.by_address.insert(base, peripheral);
    }

    /// Look up the peripheral that contains `addr`.
    #[must_use]
    pub fn peripheral_at(&self, addr: u16) -> Option<&Peripheral> {
        // Find the largest base address ≤ addr.
        self.by_address
            .range(..=addr)
            .next_back()
            .map(|(_, p)| p)
            .filter(|p| p.contains_address(addr))
    }

    /// Look up a peripheral by name (exact, case-insensitive).
    #[must_use]
    pub fn peripheral_by_name(&self, name: &str) -> Option<&Peripheral> {
        let upper = name.to_ascii_uppercase();
        self.name_index
            .get(&upper)
            .or_else(|| {
                // Linear search for case-insensitive match.
                self.name_index
                    .iter()
                    .find(|(k, _)| k.to_ascii_uppercase() == upper)
                    .map(|(_, v)| v)
            })
            .and_then(|base| self.by_address.get(base))
    }

    /// Look up the register name at `addr`, if any.
    #[must_use]
    pub fn register_name_at(&self, addr: u16) -> Option<&str> {
        // First try the fast SFR table.
        if let Some(n) = sfr_name(addr) {
            return Some(n);
        }
        // Then search the structured peripheral map.
        self.peripheral_at(addr)
            .and_then(|p| p.register_at_address(addr))
            .map(|r| r.name.as_str())
    }

    /// Return an iterator over all peripherals sorted by base address.
    pub fn peripherals(&self) -> impl Iterator<Item = &Peripheral> {
        self.by_address.values()
    }

    /// Return the number of peripherals registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_address.len()
    }

    /// Return `true` if no peripherals have been registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }

    /// Build a default peripheral map for the MSP430G2553 device.
    #[must_use]
    pub fn msp430g2553() -> Self {
        let mut map = Self::new("MSP430G2553");

        // Port 1
        map.insert(Peripheral::new("PORT1", 0x0020, 0x08, "8-bit I/O Port 1 with interrupts", vec![
            PeripheralRegister::ro16(0x00, "P1IN",   "Port 1 input register"),
            PeripheralRegister::rw8( 0x01, "P1OUT",  "Port 1 output register"),
            PeripheralRegister::rw8( 0x02, "P1DIR",  "Port 1 direction register"),
            PeripheralRegister::rw8( 0x03, "P1IFG",  "Port 1 interrupt flag"),
            PeripheralRegister::rw8( 0x04, "P1IES",  "Port 1 interrupt edge select"),
            PeripheralRegister::rw8( 0x05, "P1IE",   "Port 1 interrupt enable"),
            PeripheralRegister::rw8( 0x06, "P1SEL",  "Port 1 function select"),
            PeripheralRegister::rw8( 0x07, "P1SEL2", "Port 1 function select 2"),
        ]));

        // Port 2
        map.insert(Peripheral::new("PORT2", 0x0028, 0x08, "8-bit I/O Port 2 with interrupts", vec![
            PeripheralRegister::ro16(0x00, "P2IN",   "Port 2 input register"),
            PeripheralRegister::rw8( 0x01, "P2OUT",  "Port 2 output register"),
            PeripheralRegister::rw8( 0x02, "P2DIR",  "Port 2 direction register"),
            PeripheralRegister::rw8( 0x03, "P2IFG",  "Port 2 interrupt flag"),
            PeripheralRegister::rw8( 0x04, "P2IES",  "Port 2 interrupt edge select"),
            PeripheralRegister::rw8( 0x05, "P2IE",   "Port 2 interrupt enable"),
            PeripheralRegister::rw8( 0x06, "P2SEL",  "Port 2 function select"),
            PeripheralRegister::rw8( 0x07, "P2SEL2", "Port 2 function select 2"),
        ]));

        // Timer A0
        map.insert(Peripheral::new("TIMER_A0", 0x0160, 0x20, "16-bit Timer A0", vec![
            PeripheralRegister::rw16(0x00, "TA0CTL",   "Timer A0 control"),
            PeripheralRegister::rw16(0x02, "TA0CCTL0", "Timer A0 capture/compare control 0"),
            PeripheralRegister::rw16(0x04, "TA0CCTL1", "Timer A0 capture/compare control 1"),
            PeripheralRegister::rw16(0x06, "TA0CCTL2", "Timer A0 capture/compare control 2"),
            PeripheralRegister::rw16(0x10, "TA0R",     "Timer A0 counter register"),
            PeripheralRegister::rw16(0x12, "TA0CCR0",  "Timer A0 CCR0"),
            PeripheralRegister::rw16(0x14, "TA0CCR1",  "Timer A0 CCR1"),
            PeripheralRegister::rw16(0x16, "TA0CCR2",  "Timer A0 CCR2"),
            PeripheralRegister::ro16(0x1E, "TA0IV",    "Timer A0 interrupt vector"),
        ]));

        // Watchdog Timer
        map.insert(Peripheral::new("WDT", 0x0120, 0x02, "Watchdog Timer+", vec![
            PeripheralRegister::rw16(0x00, "WDTCTL", "Watchdog timer control"),
        ]));

        // Basic Clock
        map.insert(Peripheral::new("BCM", 0x0052, 0x06, "Basic Clock Module", vec![
            PeripheralRegister::rw8(0x00, "DCOCTL",  "DCO control"),
            PeripheralRegister::rw8(0x01, "BCSCTL1", "Basic clock system control 1"),
            PeripheralRegister::rw8(0x02, "BCSCTL2", "Basic clock system control 2"),
            PeripheralRegister::rw8(0x05, "BCSCTL3", "Basic clock system control 3"),
        ]));

        // USCI A0
        map.insert(Peripheral::new("USCI_A0", 0x0060, 0x10, "USCI A0 (UART/SPI)", vec![
            PeripheralRegister::rw8(0x00, "UCA0CTL0",  "USCI A0 control 0"),
            PeripheralRegister::rw8(0x01, "UCA0CTL1",  "USCI A0 control 1"),
            PeripheralRegister::rw8(0x02, "UCA0BR0",   "USCI A0 baud rate 0"),
            PeripheralRegister::rw8(0x03, "UCA0BR1",   "USCI A0 baud rate 1"),
            PeripheralRegister::rw8(0x04, "UCA0MCTL",  "USCI A0 modulation control"),
            PeripheralRegister::rw8(0x05, "UCA0STAT",  "USCI A0 status"),
            PeripheralRegister::ro16(0x06, "UCA0RXBUF", "USCI A0 receive buffer"),
            PeripheralRegister::rw8(0x07, "UCA0TXBUF", "USCI A0 transmit buffer"),
        ]));

        // ADC10
        map.insert(Peripheral::new("ADC10", 0x01B0, 0x0A, "10-bit ADC", vec![
            PeripheralRegister::rw16(0x00, "ADC10CTL0", "ADC10 control 0"),
            PeripheralRegister::rw16(0x02, "ADC10CTL1", "ADC10 control 1"),
            PeripheralRegister::ro16(0x04, "ADC10MEM",  "ADC10 memory"),
            PeripheralRegister::rw16(0x08, "ADC10SA",   "ADC10 data transfer start address"),
        ]));

        map
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sfr_name_p1in() {
        assert_eq!(sfr_name(0x0020), Some("P1IN"));
    }

    #[test]
    fn test_sfr_name_wdtctl() {
        assert_eq!(sfr_name(0x0120), Some("WDTCTL"));
    }

    #[test]
    fn test_sfr_name_unknown() {
        assert_eq!(sfr_name(0x8000), None);
    }

    #[test]
    fn test_peripheral_register_rw16() {
        let r = PeripheralRegister::rw16(0x00, "TA0CTL", "Timer control");
        assert_eq!(r.width, 2);
        assert!(!r.read_only);
    }

    #[test]
    fn test_peripheral_contains_address() {
        let p = Peripheral::new("P1", 0x0020, 0x08, "Port 1", vec![]);
        assert!(p.contains_address(0x0020));
        assert!(p.contains_address(0x0027));
        assert!(!p.contains_address(0x0028));
    }

    #[test]
    fn test_peripheral_register_lookup() {
        let p = Peripheral::new("TIMER", 0x0160, 0x20, "Timer", vec![
            PeripheralRegister::rw16(0x00, "TA0CTL", "Control"),
            PeripheralRegister::rw16(0x10, "TA0R",   "Counter"),
        ]);
        let r = p.register_at_address(0x0160);
        assert_eq!(r.map(|x| x.name.as_str()), Some("TA0CTL"));
        let r2 = p.register_at_address(0x0170);
        assert_eq!(r2.map(|x| x.name.as_str()), Some("TA0R"));
    }

    #[test]
    fn test_peripheral_map_g2553_port1() {
        let map = Msp430PeripheralMap::msp430g2553();
        let p = map.peripheral_at(0x0020).unwrap();
        assert_eq!(p.name, "PORT1");
    }

    #[test]
    fn test_peripheral_map_register_name_at() {
        let map = Msp430PeripheralMap::msp430g2553();
        // Via SFR table.
        assert_eq!(map.register_name_at(0x0120), Some("WDTCTL"));
        // Via structured map.
        assert!(map.register_name_at(0x0160).is_some());
    }

    #[test]
    fn test_peripheral_map_by_name() {
        let map = Msp430PeripheralMap::msp430g2553();
        let p = map.peripheral_by_name("WDT");
        assert!(p.is_some());
        assert_eq!(p.unwrap().base_address, 0x0120);
    }

    #[test]
    fn test_peripheral_map_len() {
        let map = Msp430PeripheralMap::msp430g2553();
        assert!(map.len() >= 5);
    }

    #[test]
    fn test_peripheral_display() {
        let p = Peripheral::new("P1", 0x0020, 8, "Port 1", vec![]);
        let s = format!("{p}");
        assert!(s.contains("PORT1") || s.contains("P1"));
    }

    #[test]
    fn test_register_address() {
        let r = PeripheralRegister::rw16(0x10, "TA0R", "Counter");
        assert_eq!(r.address(0x0160), 0x0170);
    }

    #[test]
    fn test_peripheral_register_by_name() {
        let p = Peripheral::new("TIMER", 0x0160, 0x20, "Timer", vec![
            PeripheralRegister::rw16(0x00, "TA0CTL", "Control"),
        ]);
        assert!(p.register_by_name("ta0ctl").is_some());
    }
}
