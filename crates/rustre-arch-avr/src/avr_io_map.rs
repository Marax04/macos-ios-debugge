/// AVR I/O register map: port addresses, named registers, per-device tables.
use std::collections::HashMap;

// ── I/O Register descriptor ───────────────────────────────────────────────────

/// Access permissions for an I/O register.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum IoAccess {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

/// Category of an I/O register.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum IoCategory {
    Gpio,
    Timer,
    Uart,
    Spi,
    I2c,
    Adc,
    Interrupt,
    Cpu,
    Power,
    AnalogComp,
    Watchdog,
    Clock,
    Dma,
    Unknown,
}

/// Description of a single bit within an I/O register.
#[derive(Clone, Debug)]
pub struct RegBitDef {
    /// Bit position (0-7).
    pub bit: u8,
    /// Short name (e.g., "RXEN0").
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
}

/// Descriptor for a single AVR I/O register.
#[derive(Clone, Debug)]
pub struct IoRegister {
    /// I/O address (0x00–0x3F for IN/OUT; up to 0x1FF for memory-mapped).
    pub io_addr: u16,
    /// SRAM address (`io_addr` + 0x20 for classic AVR, or direct for XMEGA).
    pub mem_addr: u16,
    /// Short register name (e.g., "PORTB").
    pub name: &'static str,
    /// Full description.
    pub description: &'static str,
    /// Access type.
    pub access: IoAccess,
    /// Functional category.
    pub category: IoCategory,
    /// Per-bit documentation.
    pub bits: Vec<RegBitDef>,
    /// Reset/default value.
    pub reset_value: u8,
}

impl IoRegister {
    /// Create a new I/O register descriptor with no bit info.
    #[must_use]
    pub const fn new(
        io_addr: u16,
        name: &'static str,
        description: &'static str,
        access: IoAccess,
        category: IoCategory,
    ) -> Self {
        Self {
            io_addr,
            mem_addr: io_addr + 0x20,
            name,
            description,
            access,
            category,
            bits: Vec::new(),
            reset_value: 0,
        }
    }

    /// Builder: set reset value.
    #[must_use]
    pub const fn with_reset(mut self, v: u8) -> Self { self.reset_value = v; self }

    /// Builder: set SRAM address explicitly (for XMEGA/mapped-only registers).
    #[must_use]
    pub const fn with_mem_addr(mut self, addr: u16) -> Self { self.mem_addr = addr; self }

    /// Builder: add a bit definition.
    #[must_use]
    pub fn with_bit(mut self, bit: u8, name: &'static str, desc: &'static str) -> Self {
        self.bits.push(RegBitDef { bit, name, description: desc });
        self
    }

    /// True if accessible via `IN`/`OUT` instructions (address <= 0x3F).
    #[must_use]
    pub const fn is_io_accessible(&self) -> bool { self.io_addr <= 0x3F }

    /// True if also accessible via `LDS`/`STS` via the mapped address.
    #[must_use]
    pub const fn is_mem_mapped(&self) -> bool { true }

    /// Look up a bit definition by position.
    #[must_use]
    pub fn bit_def(&self, bit: u8) -> Option<&RegBitDef> {
        self.bits.iter().find(|b| b.bit == bit)
    }
}

// ── I/O access record (runtime) ───────────────────────────────────────────────

/// Records a single observed I/O register access.
#[derive(Clone, Debug)]
pub struct IoRegAccess {
    /// Program counter (byte address) of the accessing instruction.
    pub pc: u32,
    /// I/O address accessed.
    pub io_addr: u16,
    /// True = write, False = read.
    pub is_write: bool,
    /// Bitmask of bits that were written/read (0xFF if unknown).
    pub bit_mask: u8,
}

impl IoRegAccess {
    #[must_use]
    pub const fn read(pc: u32, io_addr: u16) -> Self {
        Self { pc, io_addr, is_write: false, bit_mask: 0xFF }
    }
    #[must_use]
    pub const fn write(pc: u32, io_addr: u16) -> Self {
        Self { pc, io_addr, is_write: true, bit_mask: 0xFF }
    }
    #[must_use]
    pub const fn bit_read(pc: u32, io_addr: u16, bit: u8) -> Self {
        Self { pc, io_addr, is_write: false, bit_mask: 1 << bit }
    }
    #[must_use]
    pub const fn bit_write(pc: u32, io_addr: u16, bit: u8) -> Self {
        Self { pc, io_addr, is_write: true, bit_mask: 1 << bit }
    }
}

// ── Device identifier ─────────────────────────────────────────────────────────

/// Supported AVR device families / specific parts.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AvrDevice {
    /// Generic classic AVR (`ATmega` core).
    Generic,
    /// `ATmega328P` — the most common 8-bit AVR.
    ATmega328P,
    /// `ATmega2560` — 256 KB flash, extended address.
    ATmega2560,
    /// `ATmega16` — 16 KB flash.
    ATmega16,
    /// `ATmega8` — small 8 KB flash device.
    ATmega8,
    /// `ATtiny85` — minimal 8-pin device.
    ATtiny85,
    /// `ATtiny2313` — small I/O-heavy device.
    ATtiny2313,
    /// `ATmega32U4` — USB device.
    ATmega32U4,
    /// `AT90USB1287` — full-speed USB.
    AT90USB1287,
    /// Xmega A1 — XMEGA core.
    ATxmega128A1,
    /// Custom device with user-supplied I/O map.
    Custom(&'static str),
}

impl AvrDevice {
    /// Human-readable part name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Generic         => "Generic AVR",
            Self::ATmega328P      => "ATmega328P",
            Self::ATmega2560      => "ATmega2560",
            Self::ATmega16        => "ATmega16",
            Self::ATmega8         => "ATmega8",
            Self::ATtiny85        => "ATtiny85",
            Self::ATtiny2313      => "ATtiny2313",
            Self::ATmega32U4      => "ATmega32U4",
            Self::AT90USB1287     => "AT90USB1287",
            Self::ATxmega128A1    => "ATxmega128A1",
            Self::Custom(n)       => n,
        }
    }

    /// Flash size in bytes.
    #[must_use]
    pub const fn flash_bytes(self) -> u32 {
        match self {
            Self::ATmega328P | Self::ATmega32U4 | Self::Generic | Self::Custom(_) => 32_768,
            Self::ATmega2560   => 262_144,
            Self::ATmega16     => 16_384,
            Self::ATmega8 | Self::ATtiny85 => 8_192,
            Self::ATtiny2313   => 2_048,
            Self::AT90USB1287 | Self::ATxmega128A1 => 131_072,
        }
    }

    /// SRAM size in bytes (not including registers and I/O space).
    #[must_use]
    pub const fn sram_bytes(self) -> u32 {
        match self {
            Self::ATmega328P | Self::Generic | Self::Custom(_) => 2_048,
            Self::ATmega2560 | Self::AT90USB1287 | Self::ATxmega128A1 => 8_192,
            Self::ATmega16 | Self::ATmega8 => 1_024,
            Self::ATtiny85     => 512,
            Self::ATtiny2313   => 128,
            Self::ATmega32U4   => 2_560,
        }
    }

    /// Whether the device has 22-bit PC (flash > 128 KB → 3-byte return address).
    #[must_use]
    pub const fn has_22bit_pc(self) -> bool {
        matches!(self, Self::ATmega2560 | Self::AT90USB1287 | Self::ATxmega128A1)
    }

    /// Whether `SPH` exists (devices with > 256 bytes of SRAM).
    #[must_use]
    pub const fn has_sph(self) -> bool {
        !matches!(self, Self::ATtiny85 | Self::ATtiny2313)
    }

    /// Whether the device has the `ELPM` / `RAMPZ` registers.
    #[must_use]
    pub const fn has_elpm(self) -> bool {
        matches!(self, Self::ATmega2560 | Self::AT90USB1287 | Self::ATxmega128A1)
    }
}

// ── I/O map entry (indexing) ──────────────────────────────────────────────────

/// Lightweight index entry used by [`IoRegMap`] for fast lookup.
#[derive(Clone, Debug)]
pub struct IoMapEntry {
    pub io_addr: u16,
    pub name: &'static str,
    pub category: IoCategory,
    pub access: IoAccess,
}

// ── IoRegMap: per-device register map ────────────────────────────────────────

/// Complete I/O register map for a specific AVR device.
pub struct IoRegMap {
    pub device: AvrDevice,
    registers: Vec<IoRegister>,
    by_io_addr: HashMap<u16, usize>,
    by_name: HashMap<&'static str, usize>,
}

impl IoRegMap {
    /// Build the I/O map for a device.
    #[must_use]
    pub fn for_device(device: AvrDevice) -> Self {
        let registers = build_register_list(device);
        let mut by_io_addr = HashMap::new();
        let mut by_name = HashMap::new();
        for (i, r) in registers.iter().enumerate() {
            by_io_addr.insert(r.io_addr, i);
            by_name.insert(r.name, i);
        }
        Self { device, registers, by_io_addr, by_name }
    }

    /// Look up a register by I/O address.
    #[must_use]
    pub fn by_io_addr(&self, addr: u16) -> Option<&IoRegister> {
        self.by_io_addr.get(&addr).map(|&i| &self.registers[i])
    }

    /// Look up a register by name (exact, case-sensitive).
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&IoRegister> {
        self.by_name.get(name).map(|&i| &self.registers[i])
    }

    /// Look up a register by SRAM address.
    #[must_use]
    pub fn by_mem_addr(&self, addr: u16) -> Option<&IoRegister> {
        self.registers.iter().find(|r| r.mem_addr == addr)
    }

    /// All registers in address order.
    #[must_use]
    pub fn all(&self) -> &[IoRegister] { &self.registers }

    /// Registers in a given category.
    pub fn by_category(&self, cat: IoCategory) -> impl Iterator<Item=&IoRegister> {
        self.registers.iter().filter(move |r| r.category == cat)
    }

    /// Return a human-readable name for an I/O address, or a hex fallback.
    #[must_use]
    pub fn name_or_hex(&self, addr: u16) -> String {
        self.by_io_addr(addr)
            .map_or_else(|| format!("0x{addr:02x}"), |r| r.name.to_owned())
    }

    /// Annotate an access record with the register name.
    #[must_use]
    pub fn annotate(&self, acc: &IoRegAccess) -> String {
        let reg_name = self.name_or_hex(acc.io_addr);
        let dir = if acc.is_write { "WRITE" } else { "READ" };
        if acc.bit_mask == 0xFF {
            format!("0x{:06x}: {} {}", acc.pc, dir, reg_name)
        } else {
            let bit = u8::try_from(acc.bit_mask.trailing_zeros()).unwrap_or(u8::MAX);
            if let Some(bd) = self.by_io_addr(acc.io_addr).and_then(|r| r.bit_def(bit)) {
                return format!("0x{:06x}: {} {}.{}", acc.pc, dir, reg_name, bd.name);
            }
            format!("0x{:06x}: {} {}.bit{bit}", acc.pc, dir, reg_name)
        }
    }

    /// Number of registers in the map.
    #[must_use]
    pub const fn len(&self) -> usize { self.registers.len() }

    /// True if no registers are present.
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.registers.is_empty() }
}

// ── Register list builders ────────────────────────────────────────────────────

fn build_register_list(device: AvrDevice) -> Vec<IoRegister> {
    // ── CPU / Core registers present on all classic devices ──────────────────
    let mut regs: Vec<IoRegister> = vec![
        IoRegister::new(0x3F, "SREG", "Status Register", IoAccess::ReadWrite, IoCategory::Cpu)
            .with_bit(0, "C", "Carry Flag")
            .with_bit(1, "Z", "Zero Flag")
            .with_bit(2, "N", "Negative Flag")
            .with_bit(3, "V", "Overflow Flag")
            .with_bit(4, "S", "Sign Flag")
            .with_bit(5, "H", "Half Carry Flag")
            .with_bit(6, "T", "Bit Copy Storage")
            .with_bit(7, "I", "Global Interrupt Enable"),
        IoRegister::new(0x3E, "SPH", "Stack Pointer High", IoAccess::ReadWrite, IoCategory::Cpu),
        IoRegister::new(0x3D, "SPL", "Stack Pointer Low",  IoAccess::ReadWrite, IoCategory::Cpu),
        // ── GPIO Port B ──────────────────────────────────────────────────────
        IoRegister::new(0x05, "PORTB", "Port B Data Register",      IoAccess::ReadWrite, IoCategory::Gpio),
        IoRegister::new(0x04, "DDRB",  "Port B Data Direction",     IoAccess::ReadWrite, IoCategory::Gpio),
        IoRegister::new(0x03, "PINB",  "Port B Input Pins Address", IoAccess::ReadOnly,  IoCategory::Gpio),
        // ── GPIO Port C ──────────────────────────────────────────────────────
        IoRegister::new(0x08, "PORTC", "Port C Data Register",      IoAccess::ReadWrite, IoCategory::Gpio),
        IoRegister::new(0x07, "DDRC",  "Port C Data Direction",     IoAccess::ReadWrite, IoCategory::Gpio),
        IoRegister::new(0x06, "PINC",  "Port C Input Pins Address", IoAccess::ReadOnly,  IoCategory::Gpio),
        // ── GPIO Port D ──────────────────────────────────────────────────────
        IoRegister::new(0x0B, "PORTD", "Port D Data Register",      IoAccess::ReadWrite, IoCategory::Gpio),
        IoRegister::new(0x0A, "DDRD",  "Port D Data Direction",     IoAccess::ReadWrite, IoCategory::Gpio),
        IoRegister::new(0x09, "PIND",  "Port D Input Pins Address", IoAccess::ReadOnly,  IoCategory::Gpio),
        // ── Timer/Counter 0 ──────────────────────────────────────────────────
        IoRegister::new(0x26, "TIFR0",  "Timer/Counter 0 Interrupt Flag Register", IoAccess::ReadWrite, IoCategory::Timer),
        IoRegister::new(0x44, "TCCR0A", "Timer/Counter 0 Control Register A",      IoAccess::ReadWrite, IoCategory::Timer)
            .with_mem_addr(0x64),
        IoRegister::new(0x45, "TCCR0B", "Timer/Counter 0 Control Register B",      IoAccess::ReadWrite, IoCategory::Timer)
            .with_mem_addr(0x65),
        IoRegister::new(0x46, "TCNT0",  "Timer/Counter 0 Value",                   IoAccess::ReadWrite, IoCategory::Timer)
            .with_mem_addr(0x66),
        IoRegister::new(0x47, "OCR0A",  "Timer/Counter 0 Output Compare A",        IoAccess::ReadWrite, IoCategory::Timer)
            .with_mem_addr(0x67),
        IoRegister::new(0x48, "OCR0B",  "Timer/Counter 0 Output Compare B",        IoAccess::ReadWrite, IoCategory::Timer)
            .with_mem_addr(0x68),
        IoRegister::new(0x6E, "TIMSK0", "Timer/Counter 0 Interrupt Mask Register", IoAccess::ReadWrite, IoCategory::Timer)
            .with_mem_addr(0x6E),
    ];

    // ── USART0 (present on ATmega328P, ATmega16, ATmega2560 ...) ─────────────
    match device {
        AvrDevice::ATtiny85 | AvrDevice::ATtiny2313 => {}
        _ => {
            regs.push(IoRegister::new(0x00, "UCSR0A", "USART0 Control/Status A", IoAccess::ReadWrite, IoCategory::Uart)
                .with_mem_addr(0xC0)
                .with_bit(7, "RXC0",  "Receive Complete")
                .with_bit(6, "TXC0",  "Transmit Complete")
                .with_bit(5, "UDRE0", "Data Register Empty")
                .with_bit(4, "FE0",   "Frame Error")
                .with_bit(3, "DOR0",  "Data OverRun")
                .with_bit(2, "UPE0",  "Parity Error")
                .with_bit(1, "U2X0",  "Double Speed")
                .with_bit(0, "MPCM0", "Multi-processor Comm Mode"));
            regs.push(IoRegister::new(0x00, "UCSR0B", "USART0 Control/Status B", IoAccess::ReadWrite, IoCategory::Uart)
                .with_mem_addr(0xC1)
                .with_bit(7, "RXCIE0", "RX Complete Interrupt Enable")
                .with_bit(6, "TXCIE0", "TX Complete Interrupt Enable")
                .with_bit(5, "UDRIE0", "Data Register Empty Interrupt Enable")
                .with_bit(4, "RXEN0",  "Receiver Enable")
                .with_bit(3, "TXEN0",  "Transmitter Enable"));
            regs.push(IoRegister::new(0x00, "UCSR0C", "USART0 Control/Status C", IoAccess::ReadWrite, IoCategory::Uart)
                .with_mem_addr(0xC2));
            regs.push(IoRegister::new(0x00, "UBRR0L", "USART0 Baud Rate Low",    IoAccess::ReadWrite, IoCategory::Uart)
                .with_mem_addr(0xC4));
            regs.push(IoRegister::new(0x00, "UBRR0H", "USART0 Baud Rate High",   IoAccess::ReadWrite, IoCategory::Uart)
                .with_mem_addr(0xC5));
            regs.push(IoRegister::new(0x00, "UDR0",   "USART0 Data Register",    IoAccess::ReadWrite, IoCategory::Uart)
                .with_mem_addr(0xC6));
        }
    }

    // ── SPI ──────────────────────────────────────────────────────────────────
    regs.push(IoRegister::new(0x2C, "SPCR", "SPI Control Register", IoAccess::ReadWrite, IoCategory::Spi)
        .with_bit(7, "SPIE", "SPI Interrupt Enable")
        .with_bit(6, "SPE",  "SPI Enable")
        .with_bit(5, "DORD", "Data Order")
        .with_bit(4, "MSTR", "Master/Slave Select")
        .with_bit(3, "CPOL", "Clock Polarity")
        .with_bit(2, "CPHA", "Clock Phase"));
    regs.push(IoRegister::new(0x2D, "SPSR", "SPI Status Register", IoAccess::ReadWrite, IoCategory::Spi)
        .with_bit(7, "SPIF",  "SPI Interrupt Flag")
        .with_bit(6, "WCOL",  "Write Collision")
        .with_bit(0, "SPI2X", "Double SPI Speed"));
    regs.push(IoRegister::new(0x2E, "SPDR", "SPI Data Register", IoAccess::ReadWrite, IoCategory::Spi));

    // ── ADC ──────────────────────────────────────────────────────────────────
    if device != AvrDevice::ATtiny2313 {
        regs.push(IoRegister::new(0x24, "ADCSRB", "ADC Control/Status B",  IoAccess::ReadWrite, IoCategory::Adc).with_mem_addr(0x7B));
        regs.push(IoRegister::new(0x26, "ADCSRA", "ADC Control/Status A",  IoAccess::ReadWrite, IoCategory::Adc).with_mem_addr(0x7A)
            .with_bit(7, "ADEN",  "ADC Enable")
            .with_bit(6, "ADSC",  "ADC Start Conversion")
            .with_bit(5, "ADATE", "ADC Auto Trigger Enable")
            .with_bit(4, "ADIF",  "ADC Interrupt Flag")
            .with_bit(3, "ADIE",  "ADC Interrupt Enable"));
        regs.push(IoRegister::new(0x24, "ADMUX",  "ADC Multiplexer",        IoAccess::ReadWrite, IoCategory::Adc).with_mem_addr(0x7C));
        regs.push(IoRegister::new(0x24, "ADCL",   "ADC Data Low",           IoAccess::ReadOnly,  IoCategory::Adc).with_mem_addr(0x78));
        regs.push(IoRegister::new(0x25, "ADCH",   "ADC Data High",          IoAccess::ReadOnly,  IoCategory::Adc).with_mem_addr(0x79));
    }

    // ── Watchdog ─────────────────────────────────────────────────────────────
    regs.push(IoRegister::new(0x21, "WDTCSR", "Watchdog Timer Control", IoAccess::ReadWrite, IoCategory::Watchdog)
        .with_mem_addr(0x60)
        .with_bit(7, "WDIF", "Watchdog Interrupt Flag")
        .with_bit(6, "WDIE", "Watchdog Interrupt Enable")
        .with_bit(4, "WDCE", "Watchdog Change Enable")
        .with_bit(3, "WDE",  "Watchdog Enable"));

    // ── Interrupt control ─────────────────────────────────────────────────────
    regs.push(IoRegister::new(0x1D, "EIFR",  "External Interrupt Flag Register",   IoAccess::ReadWrite, IoCategory::Interrupt));
    regs.push(IoRegister::new(0x1C, "EIMSK", "External Interrupt Mask Register",   IoAccess::ReadWrite, IoCategory::Interrupt));
    regs.push(IoRegister::new(0x35, "EICRA", "External Interrupt Control Register",IoAccess::ReadWrite, IoCategory::Interrupt)
        .with_mem_addr(0x69));

    // ── RAMPZ / EIND (extended address devices) ───────────────────────────────
    if device.has_elpm() {
        regs.push(IoRegister::new(0x3B, "RAMPZ", "RAM Page Z Select Register", IoAccess::ReadWrite, IoCategory::Cpu));
        regs.push(IoRegister::new(0x3C, "EIND",  "Extended Indirect Register",  IoAccess::ReadWrite, IoCategory::Cpu));
    }

    regs.sort_by_key(|r| r.io_addr);
    regs
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_contains_sreg() {
        let map = IoRegMap::for_device(AvrDevice::ATmega328P);
        let sreg = map.by_io_addr(0x3F).expect("SREG must exist");
        assert_eq!(sreg.name, "SREG");
        assert_eq!(sreg.category, IoCategory::Cpu);
        let c_bit = sreg.bit_def(0).expect("bit 0 defined");
        assert_eq!(c_bit.name, "C");
    }

    #[test]
    fn map_by_name() {
        let map = IoRegMap::for_device(AvrDevice::ATmega328P);
        assert!(map.by_name("PORTB").is_some());
        assert!(map.by_name("SPCR").is_some());
        assert!(map.by_name("NONEXISTENT").is_none());
    }

    #[test]
    fn no_rampz_on_tiny() {
        let map = IoRegMap::for_device(AvrDevice::ATtiny85);
        assert!(map.by_name("RAMPZ").is_none());
    }

    #[test]
    fn rampz_on_mega2560() {
        let map = IoRegMap::for_device(AvrDevice::ATmega2560);
        assert!(map.by_name("RAMPZ").is_some());
    }

    #[test]
    fn device_properties() {
        assert!(AvrDevice::ATmega2560.has_22bit_pc());
        assert!(!AvrDevice::ATmega328P.has_22bit_pc());
        assert!(!AvrDevice::ATtiny85.has_sph());
        assert!(AvrDevice::ATmega328P.has_sph());
        assert_eq!(AvrDevice::ATmega328P.flash_bytes(), 32_768);
        assert_eq!(AvrDevice::ATtiny85.sram_bytes(), 512);
    }

    #[test]
    fn io_access_record() {
        let acc = IoRegAccess::write(0x1234, 0x2E);
        assert!(acc.is_write);
        assert_eq!(acc.pc, 0x1234);
        let map = IoRegMap::for_device(AvrDevice::ATmega328P);
        let annotated = map.annotate(&acc);
        assert!(annotated.contains("SPDR") || annotated.contains("0x2e"));
    }

    #[test]
    fn bit_access_annotation() {
        let map = IoRegMap::for_device(AvrDevice::ATmega328P);
        let acc = IoRegAccess::bit_write(0x0200, 0x3F, 7);
        let s = map.annotate(&acc);
        assert!(s.contains("SREG"));
        assert!(s.contains('I'));
    }

    #[test]
    fn by_category_gpio() {
        let map = IoRegMap::for_device(AvrDevice::ATmega328P);
        let count = map.by_category(IoCategory::Gpio).count();
        assert!(count >= 6, "expect PORTB/DDRB/PINB + PORTC/DDRC/PINC at least");
    }

    #[test]
    fn name_or_hex_unknown() {
        let map = IoRegMap::for_device(AvrDevice::ATmega328P);
        let s = map.name_or_hex(0xFE);
        assert_eq!(s, "0xfe");
    }

    #[test]
    fn io_register_accessible() {
        let r = IoRegister::new(0x05, "PORTB", "test", IoAccess::ReadWrite, IoCategory::Gpio);
        assert!(r.is_io_accessible());
        let r2 = IoRegister::new(0x100, "BIGADDR", "test", IoAccess::ReadWrite, IoCategory::Gpio);
        assert!(!r2.is_io_accessible());
    }
}
