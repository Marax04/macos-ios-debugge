//! `avr_io_registers` — Comprehensive AVR I/O register database.
//!
//! AVR microcontrollers map peripheral control registers into the I/O address
//! space (0x00–0x3F for `IN`/`OUT`; 0x20–0xFF in the data address space).
//! This module provides a typed database of I/O register entries for common
//! variants, lookup functions, and rich metadata.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// IoRegisterAccess — read/write permissions
// ─────────────────────────────────────────────────────────────────────────────

/// Read/write access class of an I/O register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IoRegisterAccess {
    /// Readable and writable.
    ReadWrite,
    /// Read-only (writing has no effect or is reserved).
    ReadOnly,
    /// Write-only (reading returns 0 or undefined).
    WriteOnly,
    /// Readable and writable, but some bits are read-only.
    ReadWriteMixed,
}

impl IoRegisterAccess {
    /// Returns a compact string representation (`"R/W"`, `"R"`, `"W"`, `"R/W*"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadWrite => "R/W",
            Self::ReadOnly => "R",
            Self::WriteOnly => "W",
            Self::ReadWriteMixed => "R/W*",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IoRegBitField — individual bit or bit-field within a register
// ─────────────────────────────────────────────────────────────────────────────

/// A named bit or bit-field within an I/O register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoRegBitField {
    /// Field name (e.g. `"TOV0"`, `"WGM01"`).
    pub name: String,
    /// LSB position (0–7).
    pub lsb: u8,
    /// Width in bits (1–8).
    pub width: u8,
    /// Short description.
    pub description: String,
}

impl IoRegBitField {
    /// Return the bit mask for this field within a byte.
    #[must_use]
    pub const fn mask(&self) -> u8 {
        let full = if self.width >= 8 { 0xFF_u8 } else { (1u8 << self.width) - 1 };
        full << self.lsb
    }

    /// Extract the field value from a raw register byte.
    #[must_use]
    pub const fn extract(&self, reg_val: u8) -> u8 {
        (reg_val & self.mask()) >> self.lsb
    }

    /// Insert `value` into `reg_val`, returning the new byte.
    #[must_use]
    pub const fn insert(&self, reg_val: u8, value: u8) -> u8 {
        (reg_val & !self.mask()) | ((value << self.lsb) & self.mask())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IoRegEntry — one register entry in the database
// ─────────────────────────────────────────────────────────────────────────────

/// A single AVR I/O register entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoRegEntry {
    /// Register mnemonic (e.g. `"TCCR0A"`, `"PORTB"`).
    pub name: String,
    /// I/O address (0x00–0x3F for `IN`/`OUT` instructions).
    pub io_addr: u8,
    /// Data memory address (= `io_addr` + 0x20 for classic AVR).
    pub data_addr: u16,
    /// Read/write access class.
    pub access: IoRegisterAccess,
    /// Reset (power-on) value.
    pub reset_value: u8,
    /// Named bit-fields.
    pub bits: Vec<IoRegBitField>,
    /// Short description of this register's function.
    pub description: String,
    /// Peripheral that owns this register (e.g. `"Timer0"`, `"SPI"`).
    pub peripheral: String,
}

impl IoRegEntry {
    /// Look up a bit-field by name (case-insensitive).
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&IoRegBitField> {
        let lower = name.to_lowercase();
        self.bits.iter().find(|b| b.name.to_lowercase() == lower)
    }

    /// Decode a raw register value into a `(field_name, value)` map.
    #[must_use]
    pub fn decode(&self, raw: u8) -> HashMap<&str, u8> {
        self.bits
            .iter()
            .map(|b| (b.name.as_str(), b.extract(raw)))
            .collect()
    }

    /// Returns `true` if this register can be accessed using `IN`/`OUT` (`io_addr` < 0x40).
    #[must_use]
    pub const fn is_io_accessible(&self) -> bool {
        self.io_addr < 0x40
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AvrIoRegister — top-level public type
// ─────────────────────────────────────────────────────────────────────────────

/// A rich representation of an AVR I/O register backed by [`IoRegEntry`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvrIoRegister {
    pub entry: IoRegEntry,
}

impl AvrIoRegister {
    /// Create from an `IoRegEntry`.
    #[must_use]
    pub const fn new(entry: IoRegEntry) -> Self {
        Self { entry }
    }

    /// Return the standard name (e.g. `"TCCR0A"`).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.entry.name
    }

    /// Return the I/O address.
    #[must_use]
    pub const fn io_addr(&self) -> u8 {
        self.entry.io_addr
    }

    /// Return the data memory address (= `io_addr` + 0x20 for classic AVR).
    #[must_use]
    pub const fn data_addr(&self) -> u16 {
        self.entry.data_addr
    }

    /// Decode a raw byte using this register's bit-field map.
    #[must_use]
    pub fn decode(&self, raw: u8) -> HashMap<&str, u8> {
        self.entry.decode(raw)
    }

    /// Return a human-readable description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.entry.description
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Database builders
// ─────────────────────────────────────────────────────────────────────────────

fn bit(name: &str, lsb: u8, desc: &str) -> IoRegBitField {
    IoRegBitField {
        name: name.to_owned(),
        lsb,
        width: 1,
        description: desc.to_owned(),
    }
}

fn field(name: &str, lsb: u8, width: u8, desc: &str) -> IoRegBitField {
    IoRegBitField {
        name: name.to_owned(),
        lsb,
        width,
        description: desc.to_owned(),
    }
}

fn reg(name: &str, io: u8, access: IoRegisterAccess, reset: u8, bits: Vec<IoRegBitField>, desc: &str, periph: &str) -> IoRegEntry {
    IoRegEntry {
        name: name.to_owned(),
        io_addr: io,
        data_addr: u16::from(io) + 0x20,
        access,
        reset_value: reset,
        bits,
        description: desc.to_owned(),
        peripheral: periph.to_owned(),
    }
}

/// Build the `ATmega328P` I/O register map.
#[must_use]
pub fn atmega328p_io_map() -> Vec<AvrIoRegister> {
    use IoRegisterAccess::{ReadOnly, ReadWrite, ReadWriteMixed};
    vec![
        // General I/O Ports
        AvrIoRegister::new(reg("PINB",  0x03, ReadOnly,  0x00, vec![field("PINB", 0, 8, "Port B Input")],                     "Port B Input Pins",             "PortB")),
        AvrIoRegister::new(reg("DDRB",  0x04, ReadWrite, 0x00, vec![field("DDRB", 0, 8, "Data Direction Port B")],             "Port B Data Direction",         "PortB")),
        AvrIoRegister::new(reg("PORTB", 0x05, ReadWrite, 0x00, vec![field("PORTB", 0, 8, "Port B Output")],                    "Port B Output",                 "PortB")),
        AvrIoRegister::new(reg("PINC",  0x06, ReadOnly,  0x00, vec![field("PINC", 0, 7, "Port C Input")],                     "Port C Input Pins",             "PortC")),
        AvrIoRegister::new(reg("DDRC",  0x07, ReadWrite, 0x00, vec![field("DDRC", 0, 7, "Data Direction Port C")],             "Port C Data Direction",         "PortC")),
        AvrIoRegister::new(reg("PORTC", 0x08, ReadWrite, 0x00, vec![field("PORTC", 0, 7, "Port C Output")],                   "Port C Output",                 "PortC")),
        AvrIoRegister::new(reg("PIND",  0x09, ReadOnly,  0x00, vec![field("PIND", 0, 8, "Port D Input")],                     "Port D Input Pins",             "PortD")),
        AvrIoRegister::new(reg("DDRD",  0x0A, ReadWrite, 0x00, vec![field("DDRD", 0, 8, "Data Direction Port D")],             "Port D Data Direction",         "PortD")),
        AvrIoRegister::new(reg("PORTD", 0x0B, ReadWrite, 0x00, vec![field("PORTD", 0, 8, "Port D Output")],                   "Port D Output",                 "PortD")),

        // Timer/Counter 0
        AvrIoRegister::new(reg("TIFR0",  0x15, ReadWriteMixed, 0x00,
            vec![bit("TOV0", 0, "Timer 0 Overflow Flag"), bit("OCF0A", 1, "Output Compare A Flag"), bit("OCF0B", 2, "Output Compare B Flag")],
            "Timer/Counter 0 Interrupt Flag Register", "Timer0")),
        AvrIoRegister::new(reg("TIFR1",  0x16, ReadWriteMixed, 0x00,
            vec![bit("TOV1", 0, "Timer 1 Overflow Flag"), bit("OCF1A", 1, "OC1A Flag"), bit("OCF1B", 2, "OC1B Flag"), bit("ICF1", 5, "Input Capture Flag")],
            "Timer/Counter 1 Interrupt Flag Register", "Timer1")),
        AvrIoRegister::new(reg("TIFR2",  0x17, ReadWriteMixed, 0x00,
            vec![bit("TOV2", 0, "Timer 2 Overflow Flag"), bit("OCF2A", 1, "OC2A Flag"), bit("OCF2B", 2, "OC2B Flag")],
            "Timer/Counter 2 Interrupt Flag Register", "Timer2")),

        // External Interrupts
        AvrIoRegister::new(reg("PCIFR", 0x1B, ReadWriteMixed, 0x00,
            vec![bit("PCIF0", 0, "Pin Change IRQ Flag 0"), bit("PCIF1", 1, "Pin Change IRQ Flag 1"), bit("PCIF2", 2, "Pin Change IRQ Flag 2")],
            "Pin Change Interrupt Flag Register", "Ext-Int")),
        AvrIoRegister::new(reg("EIFR",  0x1C, ReadWriteMixed, 0x00,
            vec![bit("INTF0", 0, "External IRQ 0 Flag"), bit("INTF1", 1, "External IRQ 1 Flag")],
            "External Interrupt Flag Register", "Ext-Int")),
        AvrIoRegister::new(reg("EIMSK", 0x1D, ReadWrite, 0x00,
            vec![bit("INT0", 0, "Enable External IRQ 0"), bit("INT1", 1, "Enable External IRQ 1")],
            "External Interrupt Mask Register", "Ext-Int")),

        // GPIO
        AvrIoRegister::new(reg("GPIOR0", 0x1E, ReadWrite, 0x00, vec![], "General Purpose I/O Register 0", "GPIO")),
        AvrIoRegister::new(reg("GPIOR1", 0x2A, ReadWrite, 0x00, vec![], "General Purpose I/O Register 1", "GPIO")),
        AvrIoRegister::new(reg("GPIOR2", 0x2B, ReadWrite, 0x00, vec![], "General Purpose I/O Register 2", "GPIO")),

        // EEPROM
        AvrIoRegister::new(reg("EECR",  0x1F, ReadWriteMixed, 0x00,
            vec![bit("EERE", 0, "EEPROM Read Enable"), bit("EEPE", 1, "EEPROM Program Enable"), bit("EEMPE", 2, "EEPROM Master Program Enable"), bit("EERIE", 3, "EEPROM Ready IRQ Enable"), field("EEPM", 4, 2, "EEPROM Programming Mode")],
            "EEPROM Control Register", "EEPROM")),
        AvrIoRegister::new(reg("EEDR",  0x20, ReadWrite, 0x00, vec![field("EEDR", 0, 8, "EEPROM Data")], "EEPROM Data Register", "EEPROM")),

        // Timer Control
        AvrIoRegister::new(reg("TCCR0A", 0x24, ReadWrite, 0x00,
            vec![field("WGM0", 0, 2, "Waveform Generation Mode"), field("COM0B", 4, 2, "Compare Output Mode B"), field("COM0A", 6, 2, "Compare Output Mode A")],
            "Timer/Counter 0 Control A", "Timer0")),
        AvrIoRegister::new(reg("TCCR0B", 0x25, ReadWrite, 0x00,
            vec![field("CS0", 0, 3, "Clock Select"), bit("WGM02", 3, "WGM02"), bit("FOC0B", 6, "Force Output Compare B"), bit("FOC0A", 7, "Force Output Compare A")],
            "Timer/Counter 0 Control B", "Timer0")),
        AvrIoRegister::new(reg("TCNT0",  0x26, ReadWrite, 0x00, vec![field("TCNT0", 0, 8, "Timer Counter")], "Timer/Counter 0", "Timer0")),
        AvrIoRegister::new(reg("OCR0A",  0x27, ReadWrite, 0x00, vec![field("OCR0A", 0, 8, "Output Compare A")], "Output Compare Register 0A", "Timer0")),
        AvrIoRegister::new(reg("OCR0B",  0x28, ReadWrite, 0x00, vec![field("OCR0B", 0, 8, "Output Compare B")], "Output Compare Register 0B", "Timer0")),

        // SPI
        AvrIoRegister::new(reg("SPCR",   0x2C, ReadWrite, 0x00,
            vec![field("SPR", 0, 2, "SPI Clock Rate"), bit("CPHA", 2, "Clock Phase"), bit("CPOL", 3, "Clock Polarity"), bit("MSTR", 4, "Master/Slave Select"), bit("DORD", 5, "Data Order"), bit("SPE", 6, "SPI Enable"), bit("SPIE", 7, "SPI Interrupt Enable")],
            "SPI Control Register", "SPI")),
        AvrIoRegister::new(reg("SPSR",   0x2D, ReadWriteMixed, 0x00,
            vec![bit("SPI2X", 0, "Double SPI Speed"), bit("WCOL", 6, "Write Collision"), bit("SPIF", 7, "SPI Interrupt Flag")],
            "SPI Status Register", "SPI")),
        AvrIoRegister::new(reg("SPDR",   0x2E, ReadWrite, 0x00, vec![field("SPDR", 0, 8, "SPI Data")], "SPI Data Register", "SPI")),

        // USART0
        AvrIoRegister::new(reg("UCSR0A", 0x40, ReadWriteMixed, 0x20,
            vec![bit("MPCM0", 0, "Multi-proc Comm Mode"), bit("U2X0", 1, "Double Speed"), bit("UPE0", 2, "Parity Error"), bit("DOR0", 3, "Data Overrun"), bit("FE0", 4, "Frame Error"), bit("UDRE0", 5, "Data Register Empty"), bit("TXC0", 6, "TX Complete"), bit("RXC0", 7, "RX Complete")],
            "USART0 Control & Status A", "USART0")),
        AvrIoRegister::new(reg("UCSR0B", 0x41, ReadWrite, 0x00,
            vec![bit("TXB80", 0, "Transmit Bit 8"), bit("RXB80", 1, "Receive Bit 8"), bit("UCSZ02", 2, "Character Size 2"), bit("TXEN0", 3, "TX Enable"), bit("RXEN0", 4, "RX Enable"), bit("UDRIE0", 5, "Data Register Empty IRQ Enable"), bit("TXCIE0", 6, "TX Complete IRQ Enable"), bit("RXCIE0", 7, "RX Complete IRQ Enable")],
            "USART0 Control & Status B", "USART0")),
        AvrIoRegister::new(reg("UCSR0C", 0x42, ReadWrite, 0x06,
            vec![field("UCPOL0", 0, 1, "Clock Polarity"), field("UCSZ0", 1, 2, "Character Size"), bit("USBS0", 3, "Stop Bit Select"), field("UPM0", 4, 2, "Parity Mode"), bit("UMSEL00", 6, "USART Mode 0"), bit("UMSEL01", 7, "USART Mode 1")],
            "USART0 Control & Status C", "USART0")),
        AvrIoRegister::new(reg("UDR0",   0x46, ReadWrite, 0x00, vec![field("UDR0", 0, 8, "USART Data")], "USART0 Data Register", "USART0")),

        // ADC
        AvrIoRegister::new(reg("ADCSRA", 0x7A, ReadWrite, 0x00,
            vec![field("ADPS", 0, 3, "ADC Prescaler Select"), bit("ADIE", 3, "ADC IRQ Enable"), bit("ADIF", 4, "ADC IRQ Flag"), bit("ADATE", 5, "Auto Trigger Enable"), bit("ADSC", 6, "ADC Start Conversion"), bit("ADEN", 7, "ADC Enable")],
            "ADC Control & Status A", "ADC")),
        AvrIoRegister::new(reg("ADMUX",  0x7C, ReadWrite, 0x00,
            vec![field("MUX", 0, 4, "Analog Channel Selection"), bit("ADLAR", 5, "ADC Left Adjust Result"), field("REFS", 6, 2, "Reference Selection")],
            "ADC Multiplexer Selection", "ADC")),

        // Watchdog
        AvrIoRegister::new(reg("WDTCSR", 0x60, ReadWrite, 0x00,
            vec![field("WDP", 0, 3, "Watchdog Timer Prescaler"), bit("WDE", 3, "Watchdog System Reset Enable"), bit("WDCE", 4, "Watchdog Change Enable"), bit("WDP3", 5, "WDP3"), bit("WDIE", 6, "Watchdog Interrupt Enable"), bit("WDIF", 7, "Watchdog Interrupt Flag")],
            "Watchdog Timer Control", "Watchdog")),

        // Status / MCU
        AvrIoRegister::new(reg("SREG",   0x3F, ReadWrite, 0x00,
            vec![bit("C", 0, "Carry"), bit("Z", 1, "Zero"), bit("N", 2, "Negative"), bit("V", 3, "Overflow"), bit("S", 4, "Sign"), bit("H", 5, "Half Carry"), bit("T", 6, "Bit Copy"), bit("I", 7, "Global IRQ Enable")],
            "Status Register", "Core")),
        AvrIoRegister::new(reg("SPL",    0x3D, ReadWrite, 0xFF, vec![field("SP", 0, 8, "Stack Pointer Low")], "Stack Pointer Low", "Core")),
        AvrIoRegister::new(reg("SPH",    0x3E, ReadWrite, 0x08, vec![field("SP", 0, 3, "Stack Pointer High")], "Stack Pointer High", "Core")),
        AvrIoRegister::new(reg("MCUSR",  0x54, ReadWriteMixed, 0x00,
            vec![bit("PORF", 0, "Power-On Reset"), bit("EXTRF", 1, "External Reset"), bit("BORF", 2, "Brown-Out Reset"), bit("WDRF", 3, "Watchdog Reset")],
            "MCU Status Register", "Core")),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Public lookup API
// ─────────────────────────────────────────────────────────────────────────────

/// Return the register name for a given I/O address in the `ATmega328P` map.
///
/// Returns `None` if the address is not in the database.
#[must_use]
pub fn io_reg_name(io_addr: u8) -> Option<&'static str> {
    // We build a static lookup at first call.
    use std::sync::OnceLock;
    static MAP: OnceLock<HashMap<u8, &'static str>> = OnceLock::new();
    // Note: for a truly static map we'd use phf; here we accept a small
    // allocation on first use and a &'static str via a leaked box.
    let _ = MAP; // avoids unused warning in simple builds
    // Fallback: linear scan over the runtime map.
    avr_io_map()
        .into_iter()
        .find(|r| r.io_addr() == io_addr)
        .map(|r| {
            // Leak the name so it has 'static lifetime.
            let s: &'static str = Box::leak(r.name().to_owned().into_boxed_str());
            s
        })
}

/// Return the full `ATmega328P` I/O register map.
#[must_use]
pub fn avr_io_map() -> Vec<AvrIoRegister> {
    atmega328p_io_map()
}

/// Build a fast address → entry lookup map.
#[must_use]
pub fn avr_io_map_by_addr() -> HashMap<u8, AvrIoRegister> {
    avr_io_map().into_iter().map(|r| (r.io_addr(), r)).collect()
}

/// Build a fast name → entry lookup map.
#[must_use]
pub fn avr_io_map_by_name() -> HashMap<String, AvrIoRegister> {
    avr_io_map().into_iter().map(|r| (r.name().to_owned(), r)).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_non_empty() {
        assert!(!avr_io_map().is_empty());
    }

    #[test]
    fn test_sreg_found() {
        let by_name = avr_io_map_by_name();
        assert!(by_name.contains_key("SREG"));
    }

    #[test]
    fn test_sreg_io_addr() {
        let by_name = avr_io_map_by_name();
        let sreg = &by_name["SREG"];
        assert_eq!(sreg.io_addr(), 0x3F);
    }

    #[test]
    fn test_sreg_data_addr() {
        let by_name = avr_io_map_by_name();
        let sreg = &by_name["SREG"];
        assert_eq!(sreg.data_addr(), 0x5F);
    }

    #[test]
    fn test_bit_field_mask() {
        let f = IoRegBitField { name: "C".into(), lsb: 0, width: 1, description: String::new() };
        assert_eq!(f.mask(), 0x01);
    }

    #[test]
    fn test_bit_field_extract() {
        let f = IoRegBitField { name: "Z".into(), lsb: 1, width: 1, description: String::new() };
        assert_eq!(f.extract(0b0000_0010), 1);
        assert_eq!(f.extract(0b0000_0001), 0);
    }

    #[test]
    fn test_bit_field_insert() {
        let f = IoRegBitField { name: "I".into(), lsb: 7, width: 1, description: String::new() };
        let v = f.insert(0x00, 1);
        assert_eq!(v, 0x80);
    }

    #[test]
    fn test_decode_sreg() {
        let by_name = avr_io_map_by_name();
        let sreg = &by_name["SREG"];
        let decoded = sreg.decode(0b0000_0011); // C=1, Z=1
        assert_eq!(decoded.get("C").copied(), Some(1));
        assert_eq!(decoded.get("Z").copied(), Some(1));
        assert_eq!(decoded.get("I").copied(), Some(0));
    }

    #[test]
    fn test_portb_in_map() {
        let by_name = avr_io_map_by_name();
        assert!(by_name.contains_key("PORTB"));
        assert!(by_name.contains_key("DDRB"));
        assert!(by_name.contains_key("PINB"));
    }

    #[test]
    fn test_access_str() {
        assert_eq!(IoRegisterAccess::ReadWrite.as_str(), "R/W");
        assert_eq!(IoRegisterAccess::ReadOnly.as_str(), "R");
        assert_eq!(IoRegisterAccess::WriteOnly.as_str(), "W");
    }

    #[test]
    fn test_is_io_accessible() {
        let by_name = avr_io_map_by_name();
        let sreg = &by_name["SREG"];
        assert!(sreg.entry.is_io_accessible());
    }

    #[test]
    fn test_field_lookup() {
        let by_name = avr_io_map_by_name();
        let sreg = &by_name["SREG"];
        assert!(sreg.entry.field("C").is_some());
        assert!(sreg.entry.field("NONEXISTENT").is_none());
    }

    #[test]
    fn test_spi_registers() {
        let by_name = avr_io_map_by_name();
        assert!(by_name.contains_key("SPCR"));
        assert!(by_name.contains_key("SPSR"));
        assert!(by_name.contains_key("SPDR"));
    }

    #[test]
    fn test_usart_registers() {
        let by_name = avr_io_map_by_name();
        assert!(by_name.contains_key("UCSR0A"));
        assert!(by_name.contains_key("UDR0"));
    }

    #[test]
    fn test_by_addr_lookup() {
        let by_addr = avr_io_map_by_addr();
        assert!(by_addr.contains_key(&0x3F)); // SREG
    }

    #[test]
    fn test_field_mask_multi_bit() {
        let f = field("WGM0", 0, 2, "");
        assert_eq!(f.mask(), 0x03);
    }

    #[test]
    fn test_watchdog_register() {
        let by_name = avr_io_map_by_name();
        assert!(by_name.contains_key("WDTCSR"));
        let wdt = &by_name["WDTCSR"];
        assert!(wdt.entry.field("WDE").is_some());
    }
}
