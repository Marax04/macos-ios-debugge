//! AVR device database: flash/SRAM/EEPROM sizes, SFR map, interrupt vectors,
//! fuse bits, bootloader areas for ATmega328P, ATmega2560, ATtiny85,
//! ATtiny13, and ATxmega256A3U.

// ── Device descriptor ─────────────────────────────────────────────────────────

/// Complete description of an AVR device.
#[derive(Debug, Clone)]
pub struct AvrDevice {
    /// Device name string (e.g. `ATmega328P`).
    pub name: &'static str,
    /// Flash size in bytes.
    pub flash_bytes: u32,
    /// SRAM size in bytes.
    pub sram_bytes: u32,
    /// EEPROM size in bytes.
    pub eeprom_bytes: u32,
    /// SRAM start address (data memory space).
    pub sram_start: u16,
    /// I/O register base address (usually 0x20 for classic AVR).
    pub io_base: u16,
    /// Number of I/O registers (classic range).
    pub io_count: u16,
    /// Address of first interrupt vector (word address × 2 = byte address).
    pub ivt_byte_addr: u16,
    /// Number of interrupt vectors.
    pub ivt_count: u8,
    /// Bootloader section start byte address (None if no bootloader).
    pub bootloader_start: Option<u32>,
    /// Bootloader section size in bytes (None if no bootloader).
    pub bootloader_size: Option<u32>,
    /// Fuse bytes layout.
    pub fuses: &'static [FuseByte],
    /// SFR register map.
    pub sfrs: &'static [SfrEntry],
    /// Interrupt vector table.
    pub ivt: &'static [IvtEntry],
}

/// A single fuse byte with named bits.
#[derive(Debug, Clone, Copy)]
pub struct FuseByte {
    pub name: &'static str,
    pub default_value: u8,
    pub bits: &'static [FuseBit],
}

/// A single fuse bit.
#[derive(Debug, Clone, Copy)]
pub struct FuseBit {
    pub bit: u8,
    pub name: &'static str,
    pub description: &'static str,
    /// Effect when bit is 0 (programmed) vs 1 (unprogrammed).
    pub active_low: bool,
}

/// A Special Function Register entry.
#[derive(Debug, Clone, Copy)]
pub struct SfrEntry {
    /// SFR address in data memory space.
    pub addr: u16,
    /// I/O address (addr - 0x20 for addr < 0x60, else extended I/O).
    pub io_addr: u16,
    pub name: &'static str,
    pub description: &'static str,
    pub bits: &'static [SfrBit],
}

/// A single named bit within an SFR.
#[derive(Debug, Clone, Copy)]
pub struct SfrBit {
    pub bit: u8,
    pub name: &'static str,
    pub description: &'static str,
}

/// An interrupt vector table entry.
#[derive(Debug, Clone, Copy)]
pub struct IvtEntry {
    pub vector: u8,
    /// Byte address of the vector.
    pub byte_addr: u16,
    pub name: &'static str,
    pub description: &'static str,
}

// ── ATmega328P ────────────────────────────────────────────────────────────────

static MEGA328P_FUSE_LFUSE_BITS: &[FuseBit] = &[
    FuseBit { bit: 7, name: "CKDIV8",  description: "Divide clock by 8",                        active_low: true  },
    FuseBit { bit: 6, name: "CKOUT",   description: "Clock output on PORTB0",                   active_low: true  },
    FuseBit { bit: 5, name: "SUT1",    description: "Select start-up time bit 1",               active_low: false },
    FuseBit { bit: 4, name: "SUT0",    description: "Select start-up time bit 0",               active_low: false },
    FuseBit { bit: 3, name: "CKSEL3",  description: "Clock select bit 3",                       active_low: false },
    FuseBit { bit: 2, name: "CKSEL2",  description: "Clock select bit 2",                       active_low: false },
    FuseBit { bit: 1, name: "CKSEL1",  description: "Clock select bit 1",                       active_low: false },
    FuseBit { bit: 0, name: "CKSEL0",  description: "Clock select bit 0 (0010=internal 8MHz)",  active_low: false },
];

static MEGA328P_FUSE_HFUSE_BITS: &[FuseBit] = &[
    FuseBit { bit: 7, name: "RSTDISBL", description: "External reset disabled",           active_low: true  },
    FuseBit { bit: 6, name: "DWEN",     description: "debugWIRE enable",                 active_low: true  },
    FuseBit { bit: 5, name: "SPIEN",    description: "SPI programming enabled",          active_low: true  },
    FuseBit { bit: 4, name: "WDTON",    description: "Watchdog always on",               active_low: true  },
    FuseBit { bit: 3, name: "EESAVE",   description: "Preserve EEPROM on chip erase",   active_low: true  },
    FuseBit { bit: 2, name: "BOOTSZ1",  description: "Boot size bit 1",                  active_low: false },
    FuseBit { bit: 1, name: "BOOTSZ0",  description: "Boot size bit 0",                  active_low: false },
    FuseBit { bit: 0, name: "BOOTRST",  description: "Boot reset vector enabled",        active_low: true  },
];

static MEGA328P_FUSE_EFUSE_BITS: &[FuseBit] = &[
    FuseBit { bit: 2, name: "BODLEVEL2", description: "Brown-out level bit 2", active_low: false },
    FuseBit { bit: 1, name: "BODLEVEL1", description: "Brown-out level bit 1", active_low: false },
    FuseBit { bit: 0, name: "BODLEVEL0", description: "Brown-out level bit 0", active_low: false },
];

static MEGA328P_FUSES: &[FuseByte] = &[
    FuseByte { name: "LFUSE", default_value: 0x62, bits: MEGA328P_FUSE_LFUSE_BITS },
    FuseByte { name: "HFUSE", default_value: 0xD9, bits: MEGA328P_FUSE_HFUSE_BITS },
    FuseByte { name: "EFUSE", default_value: 0xFF, bits: MEGA328P_FUSE_EFUSE_BITS },
];

static MEGA328P_TCCR0A_BITS: &[SfrBit] = &[
    SfrBit { bit: 7, name: "COM0A1", description: "Compare Output Mode A bit 1" },
    SfrBit { bit: 6, name: "COM0A0", description: "Compare Output Mode A bit 0" },
    SfrBit { bit: 5, name: "COM0B1", description: "Compare Output Mode B bit 1" },
    SfrBit { bit: 4, name: "COM0B0", description: "Compare Output Mode B bit 0" },
    SfrBit { bit: 1, name: "WGM01",  description: "Waveform Generation Mode bit 1" },
    SfrBit { bit: 0, name: "WGM00",  description: "Waveform Generation Mode bit 0" },
];

static MEGA328P_SREG_BITS: &[SfrBit] = &[
    SfrBit { bit: 7, name: "I", description: "Global Interrupt Enable" },
    SfrBit { bit: 6, name: "T", description: "Bit Copy Storage" },
    SfrBit { bit: 5, name: "H", description: "Half Carry Flag" },
    SfrBit { bit: 4, name: "S", description: "Sign Bit" },
    SfrBit { bit: 3, name: "V", description: "Two's Complement Overflow" },
    SfrBit { bit: 2, name: "N", description: "Negative Flag" },
    SfrBit { bit: 1, name: "Z", description: "Zero Flag" },
    SfrBit { bit: 0, name: "C", description: "Carry Flag" },
];

static MEGA328P_SFRS: &[SfrEntry] = &[
    SfrEntry { addr: 0x23, io_addr: 0x03, name: "PINB",   description: "Port B Input Pins",                 bits: &[] },
    SfrEntry { addr: 0x24, io_addr: 0x04, name: "DDRB",   description: "Port B Data Direction",             bits: &[] },
    SfrEntry { addr: 0x25, io_addr: 0x05, name: "PORTB",  description: "Port B Data Register",              bits: &[] },
    SfrEntry { addr: 0x26, io_addr: 0x06, name: "PINC",   description: "Port C Input Pins",                 bits: &[] },
    SfrEntry { addr: 0x27, io_addr: 0x07, name: "DDRC",   description: "Port C Data Direction",             bits: &[] },
    SfrEntry { addr: 0x28, io_addr: 0x08, name: "PORTC",  description: "Port C Data Register",              bits: &[] },
    SfrEntry { addr: 0x29, io_addr: 0x09, name: "PIND",   description: "Port D Input Pins",                 bits: &[] },
    SfrEntry { addr: 0x2A, io_addr: 0x0A, name: "DDRD",   description: "Port D Data Direction",             bits: &[] },
    SfrEntry { addr: 0x2B, io_addr: 0x0B, name: "PORTD",  description: "Port D Data Register",              bits: &[] },
    SfrEntry { addr: 0x35, io_addr: 0x15, name: "TIFR0",  description: "Timer/Counter 0 Interrupt Flag",    bits: &[] },
    SfrEntry { addr: 0x36, io_addr: 0x16, name: "TIFR1",  description: "Timer/Counter 1 Interrupt Flag",    bits: &[] },
    SfrEntry { addr: 0x37, io_addr: 0x17, name: "TIFR2",  description: "Timer/Counter 2 Interrupt Flag",    bits: &[] },
    SfrEntry { addr: 0x3B, io_addr: 0x1B, name: "PCIFR",  description: "Pin Change Interrupt Flag",         bits: &[] },
    SfrEntry { addr: 0x3C, io_addr: 0x1C, name: "EIFR",   description: "External Interrupt Flag",           bits: &[] },
    SfrEntry { addr: 0x3D, io_addr: 0x1D, name: "EIMSK",  description: "External Interrupt Mask",           bits: &[] },
    SfrEntry { addr: 0x3F, io_addr: 0x1F, name: "EECR",   description: "EEPROM Control Register",           bits: &[] },
    SfrEntry { addr: 0x40, io_addr: 0x20, name: "EEDR",   description: "EEPROM Data Register",              bits: &[] },
    SfrEntry { addr: 0x41, io_addr: 0x21, name: "EEARL",  description: "EEPROM Address Register Low",       bits: &[] },
    SfrEntry { addr: 0x42, io_addr: 0x22, name: "EEARH",  description: "EEPROM Address Register High",      bits: &[] },
    SfrEntry { addr: 0x43, io_addr: 0x23, name: "GTCCR",  description: "General Timer/Counter Control",     bits: &[] },
    SfrEntry { addr: 0x44, io_addr: 0x24, name: "TCCR0A", description: "TC0 Control Register A",            bits: MEGA328P_TCCR0A_BITS },
    SfrEntry { addr: 0x45, io_addr: 0x25, name: "TCCR0B", description: "TC0 Control Register B",            bits: &[] },
    SfrEntry { addr: 0x46, io_addr: 0x26, name: "TCNT0",  description: "TC0 Counter Value",                 bits: &[] },
    SfrEntry { addr: 0x47, io_addr: 0x27, name: "OCR0A",  description: "TC0 Output Compare Register A",     bits: &[] },
    SfrEntry { addr: 0x48, io_addr: 0x28, name: "OCR0B",  description: "TC0 Output Compare Register B",     bits: &[] },
    SfrEntry { addr: 0x4C, io_addr: 0x2C, name: "SPCR",   description: "SPI Control Register",              bits: &[] },
    SfrEntry { addr: 0x4D, io_addr: 0x2D, name: "SPSR",   description: "SPI Status Register",               bits: &[] },
    SfrEntry { addr: 0x4E, io_addr: 0x2E, name: "SPDR",   description: "SPI Data Register",                 bits: &[] },
    SfrEntry { addr: 0x50, io_addr: 0x30, name: "ACSR",   description: "Analog Comparator Control/Status",  bits: &[] },
    SfrEntry { addr: 0x53, io_addr: 0x33, name: "SMCR",   description: "Sleep Mode Control Register",       bits: &[] },
    SfrEntry { addr: 0x54, io_addr: 0x34, name: "MCUSR",  description: "MCU Status Register",               bits: &[] },
    SfrEntry { addr: 0x55, io_addr: 0x35, name: "MCUCR",  description: "MCU Control Register",              bits: &[] },
    SfrEntry { addr: 0x57, io_addr: 0x37, name: "SPMCSR", description: "SPM Control/Status Register",       bits: &[] },
    SfrEntry { addr: 0x5D, io_addr: 0x3D, name: "SPL",    description: "Stack Pointer Low",                 bits: &[] },
    SfrEntry { addr: 0x5E, io_addr: 0x3E, name: "SPH",    description: "Stack Pointer High",                bits: &[] },
    SfrEntry { addr: 0x5F, io_addr: 0x3F, name: "SREG",   description: "CPU Status Register",               bits: MEGA328P_SREG_BITS },
    // Extended I/O (addr >= 0x60)
    SfrEntry { addr: 0x60, io_addr: 0xFF, name: "WDTCSR", description: "Watchdog Timer Control Register",   bits: &[] },
    SfrEntry { addr: 0x61, io_addr: 0xFF, name: "CLKPR",  description: "Clock Prescale Register",           bits: &[] },
    SfrEntry { addr: 0x64, io_addr: 0xFF, name: "PRR",    description: "Power Reduction Register",          bits: &[] },
    SfrEntry { addr: 0x66, io_addr: 0xFF, name: "OSCCAL", description: "Oscillator Calibration Register",   bits: &[] },
    SfrEntry { addr: 0x68, io_addr: 0xFF, name: "PCICR",  description: "Pin Change Interrupt Control",      bits: &[] },
    SfrEntry { addr: 0x69, io_addr: 0xFF, name: "EICRA",  description: "External Interrupt Control A",      bits: &[] },
    SfrEntry { addr: 0x6B, io_addr: 0xFF, name: "PCMSK0", description: "Pin Change Mask 0",                 bits: &[] },
    SfrEntry { addr: 0x6C, io_addr: 0xFF, name: "PCMSK1", description: "Pin Change Mask 1",                 bits: &[] },
    SfrEntry { addr: 0x6D, io_addr: 0xFF, name: "PCMSK2", description: "Pin Change Mask 2",                 bits: &[] },
    SfrEntry { addr: 0x6E, io_addr: 0xFF, name: "TIMSK0", description: "TC0 Interrupt Mask",                bits: &[] },
    SfrEntry { addr: 0x6F, io_addr: 0xFF, name: "TIMSK1", description: "TC1 Interrupt Mask",                bits: &[] },
    SfrEntry { addr: 0x70, io_addr: 0xFF, name: "TIMSK2", description: "TC2 Interrupt Mask",                bits: &[] },
    // ADC
    SfrEntry { addr: 0x78, io_addr: 0xFF, name: "ADCL",   description: "ADC Data Register Low",             bits: &[] },
    SfrEntry { addr: 0x79, io_addr: 0xFF, name: "ADCH",   description: "ADC Data Register High",            bits: &[] },
    SfrEntry { addr: 0x7A, io_addr: 0xFF, name: "ADCSRA", description: "ADC Control/Status A",              bits: &[] },
    SfrEntry { addr: 0x7B, io_addr: 0xFF, name: "ADCSRB", description: "ADC Control/Status B",              bits: &[] },
    SfrEntry { addr: 0x7C, io_addr: 0xFF, name: "ADMUX",  description: "ADC Multiplexer Selection",         bits: &[] },
    SfrEntry { addr: 0x7D, io_addr: 0xFF, name: "DIDR0",  description: "Digital Input Disable Register 0",  bits: &[] },
    SfrEntry { addr: 0x7E, io_addr: 0xFF, name: "DIDR1",  description: "Digital Input Disable Register 1",  bits: &[] },
    // TC1
    SfrEntry { addr: 0x80, io_addr: 0xFF, name: "TCCR1A", description: "TC1 Control Register A",            bits: &[] },
    SfrEntry { addr: 0x81, io_addr: 0xFF, name: "TCCR1B", description: "TC1 Control Register B",            bits: &[] },
    SfrEntry { addr: 0x82, io_addr: 0xFF, name: "TCCR1C", description: "TC1 Control Register C",            bits: &[] },
    SfrEntry { addr: 0x84, io_addr: 0xFF, name: "TCNT1L", description: "TC1 Counter Low",                   bits: &[] },
    SfrEntry { addr: 0x85, io_addr: 0xFF, name: "TCNT1H", description: "TC1 Counter High",                  bits: &[] },
    SfrEntry { addr: 0x86, io_addr: 0xFF, name: "ICR1L",  description: "TC1 Input Capture Low",             bits: &[] },
    SfrEntry { addr: 0x87, io_addr: 0xFF, name: "ICR1H",  description: "TC1 Input Capture High",            bits: &[] },
    SfrEntry { addr: 0x88, io_addr: 0xFF, name: "OCR1AL", description: "TC1 Output Compare A Low",          bits: &[] },
    SfrEntry { addr: 0x89, io_addr: 0xFF, name: "OCR1AH", description: "TC1 Output Compare A High",         bits: &[] },
    SfrEntry { addr: 0x8A, io_addr: 0xFF, name: "OCR1BL", description: "TC1 Output Compare B Low",          bits: &[] },
    SfrEntry { addr: 0x8B, io_addr: 0xFF, name: "OCR1BH", description: "TC1 Output Compare B High",         bits: &[] },
    // TC2
    SfrEntry { addr: 0xB0, io_addr: 0xFF, name: "TCCR2A", description: "TC2 Control Register A",            bits: &[] },
    SfrEntry { addr: 0xB1, io_addr: 0xFF, name: "TCCR2B", description: "TC2 Control Register B",            bits: &[] },
    SfrEntry { addr: 0xB2, io_addr: 0xFF, name: "TCNT2",  description: "TC2 Counter Value",                 bits: &[] },
    SfrEntry { addr: 0xB3, io_addr: 0xFF, name: "OCR2A",  description: "TC2 Output Compare A",              bits: &[] },
    SfrEntry { addr: 0xB4, io_addr: 0xFF, name: "OCR2B",  description: "TC2 Output Compare B",              bits: &[] },
    // USART
    SfrEntry { addr: 0xC0, io_addr: 0xFF, name: "UCSR0A", description: "USART0 Control/Status A",           bits: &[] },
    SfrEntry { addr: 0xC1, io_addr: 0xFF, name: "UCSR0B", description: "USART0 Control/Status B",           bits: &[] },
    SfrEntry { addr: 0xC2, io_addr: 0xFF, name: "UCSR0C", description: "USART0 Control/Status C",           bits: &[] },
    SfrEntry { addr: 0xC4, io_addr: 0xFF, name: "UBRR0L", description: "USART0 Baud Rate Low",              bits: &[] },
    SfrEntry { addr: 0xC5, io_addr: 0xFF, name: "UBRR0H", description: "USART0 Baud Rate High",             bits: &[] },
    SfrEntry { addr: 0xC6, io_addr: 0xFF, name: "UDR0",   description: "USART0 I/O Data Register",          bits: &[] },
    // TWI
    SfrEntry { addr: 0xB8, io_addr: 0xFF, name: "TWBR",   description: "TWI Bit Rate Register",             bits: &[] },
    SfrEntry { addr: 0xB9, io_addr: 0xFF, name: "TWSR",   description: "TWI Status Register",               bits: &[] },
    SfrEntry { addr: 0xBA, io_addr: 0xFF, name: "TWAR",   description: "TWI (Slave) Address Register",      bits: &[] },
    SfrEntry { addr: 0xBB, io_addr: 0xFF, name: "TWDR",   description: "TWI Data Register",                 bits: &[] },
    SfrEntry { addr: 0xBC, io_addr: 0xFF, name: "TWCR",   description: "TWI Control Register",              bits: &[] },
    SfrEntry { addr: 0xBD, io_addr: 0xFF, name: "TWAMR",  description: "TWI (Slave) Address Mask Register", bits: &[] },
];

static MEGA328P_IVT: &[IvtEntry] = &[
    IvtEntry { vector:  0, byte_addr: 0x0000, name: "RESET",         description: "Reset" },
    IvtEntry { vector:  1, byte_addr: 0x0002, name: "INT0",          description: "External Interrupt 0" },
    IvtEntry { vector:  2, byte_addr: 0x0004, name: "INT1",          description: "External Interrupt 1" },
    IvtEntry { vector:  3, byte_addr: 0x0006, name: "PCINT0",        description: "Pin Change Interrupt 0" },
    IvtEntry { vector:  4, byte_addr: 0x0008, name: "PCINT1",        description: "Pin Change Interrupt 1" },
    IvtEntry { vector:  5, byte_addr: 0x000A, name: "PCINT2",        description: "Pin Change Interrupt 2" },
    IvtEntry { vector:  6, byte_addr: 0x000C, name: "WDT",           description: "Watchdog Time-out" },
    IvtEntry { vector:  7, byte_addr: 0x000E, name: "TIMER2_COMPA",  description: "Timer/Counter2 Compare A" },
    IvtEntry { vector:  8, byte_addr: 0x0010, name: "TIMER2_COMPB",  description: "Timer/Counter2 Compare B" },
    IvtEntry { vector:  9, byte_addr: 0x0012, name: "TIMER2_OVF",    description: "Timer/Counter2 Overflow" },
    IvtEntry { vector: 10, byte_addr: 0x0014, name: "TIMER1_CAPT",   description: "Timer/Counter1 Capture" },
    IvtEntry { vector: 11, byte_addr: 0x0016, name: "TIMER1_COMPA",  description: "Timer/Counter1 Compare A" },
    IvtEntry { vector: 12, byte_addr: 0x0018, name: "TIMER1_COMPB",  description: "Timer/Counter1 Compare B" },
    IvtEntry { vector: 13, byte_addr: 0x001A, name: "TIMER1_OVF",    description: "Timer/Counter1 Overflow" },
    IvtEntry { vector: 14, byte_addr: 0x001C, name: "TIMER0_COMPA",  description: "Timer/Counter0 Compare A" },
    IvtEntry { vector: 15, byte_addr: 0x001E, name: "TIMER0_COMPB",  description: "Timer/Counter0 Compare B" },
    IvtEntry { vector: 16, byte_addr: 0x0020, name: "TIMER0_OVF",    description: "Timer/Counter0 Overflow" },
    IvtEntry { vector: 17, byte_addr: 0x0022, name: "SPI_STC",       description: "SPI Transfer Complete" },
    IvtEntry { vector: 18, byte_addr: 0x0024, name: "USART_RX",      description: "USART Receive Complete" },
    IvtEntry { vector: 19, byte_addr: 0x0026, name: "USART_UDRE",    description: "USART Data Register Empty" },
    IvtEntry { vector: 20, byte_addr: 0x0028, name: "USART_TX",      description: "USART Transmit Complete" },
    IvtEntry { vector: 21, byte_addr: 0x002A, name: "ADC",           description: "ADC Conversion Complete" },
    IvtEntry { vector: 22, byte_addr: 0x002C, name: "EE_READY",      description: "EEPROM Ready" },
    IvtEntry { vector: 23, byte_addr: 0x002E, name: "ANALOG_COMP",   description: "Analog Comparator" },
    IvtEntry { vector: 24, byte_addr: 0x0030, name: "TWI",           description: "Two-Wire Interface" },
    IvtEntry { vector: 25, byte_addr: 0x0032, name: "SPM_READY",     description: "Store Program Memory Ready" },
];

/// `ATmega328P` device descriptor.
pub static ATMEGA328P: AvrDevice = AvrDevice {
    name:             "ATmega328P",
    flash_bytes:      32_768,
    sram_bytes:       2_048,
    eeprom_bytes:     1_024,
    sram_start:       0x0100,
    io_base:          0x0020,
    io_count:         64,
    ivt_byte_addr:    0x0000,
    ivt_count:        26,
    bootloader_start: Some(0x7800),
    bootloader_size:  Some(0x0800),
    fuses:            MEGA328P_FUSES,
    sfrs:             MEGA328P_SFRS,
    ivt:              MEGA328P_IVT,
};

// ── ATmega2560 ────────────────────────────────────────────────────────────────

static MEGA2560_IVT: &[IvtEntry] = &[
    IvtEntry { vector:  0, byte_addr: 0x0000, name: "RESET",        description: "Reset" },
    IvtEntry { vector:  1, byte_addr: 0x0004, name: "INT0",         description: "External Interrupt 0" },
    IvtEntry { vector:  2, byte_addr: 0x0008, name: "INT1",         description: "External Interrupt 1" },
    IvtEntry { vector:  3, byte_addr: 0x000C, name: "INT2",         description: "External Interrupt 2" },
    IvtEntry { vector:  4, byte_addr: 0x0010, name: "INT3",         description: "External Interrupt 3" },
    IvtEntry { vector:  5, byte_addr: 0x0014, name: "INT4",         description: "External Interrupt 4" },
    IvtEntry { vector:  6, byte_addr: 0x0018, name: "INT5",         description: "External Interrupt 5" },
    IvtEntry { vector:  7, byte_addr: 0x001C, name: "INT6",         description: "External Interrupt 6" },
    IvtEntry { vector:  8, byte_addr: 0x0020, name: "INT7",         description: "External Interrupt 7" },
    IvtEntry { vector:  9, byte_addr: 0x0024, name: "PCINT0",       description: "Pin Change Interrupt 0" },
    IvtEntry { vector: 10, byte_addr: 0x0028, name: "PCINT1",       description: "Pin Change Interrupt 1" },
    IvtEntry { vector: 11, byte_addr: 0x002C, name: "PCINT2",       description: "Pin Change Interrupt 2" },
    IvtEntry { vector: 12, byte_addr: 0x0030, name: "WDT",          description: "Watchdog Time-out" },
    IvtEntry { vector: 13, byte_addr: 0x0034, name: "TIMER2_COMPA", description: "Timer/Counter2 Compare A" },
    IvtEntry { vector: 14, byte_addr: 0x0038, name: "TIMER2_COMPB", description: "Timer/Counter2 Compare B" },
    IvtEntry { vector: 15, byte_addr: 0x003C, name: "TIMER2_OVF",   description: "Timer/Counter2 Overflow" },
    IvtEntry { vector: 16, byte_addr: 0x0040, name: "TIMER1_CAPT",  description: "Timer/Counter1 Capture" },
    IvtEntry { vector: 17, byte_addr: 0x0044, name: "TIMER1_COMPA", description: "Timer/Counter1 Compare A" },
    IvtEntry { vector: 18, byte_addr: 0x0048, name: "TIMER1_COMPB", description: "Timer/Counter1 Compare B" },
    IvtEntry { vector: 19, byte_addr: 0x004C, name: "TIMER1_COMPC", description: "Timer/Counter1 Compare C" },
    IvtEntry { vector: 20, byte_addr: 0x0050, name: "TIMER1_OVF",   description: "Timer/Counter1 Overflow" },
    IvtEntry { vector: 21, byte_addr: 0x0054, name: "TIMER0_COMPA", description: "Timer/Counter0 Compare A" },
    IvtEntry { vector: 22, byte_addr: 0x0058, name: "TIMER0_COMPB", description: "Timer/Counter0 Compare B" },
    IvtEntry { vector: 23, byte_addr: 0x005C, name: "TIMER0_OVF",   description: "Timer/Counter0 Overflow" },
    IvtEntry { vector: 24, byte_addr: 0x0060, name: "SPI_STC",      description: "SPI Transfer Complete" },
    IvtEntry { vector: 25, byte_addr: 0x0064, name: "USART0_RX",    description: "USART0 Receive Complete" },
    IvtEntry { vector: 26, byte_addr: 0x0068, name: "USART0_UDRE",  description: "USART0 Data Register Empty" },
    IvtEntry { vector: 27, byte_addr: 0x006C, name: "USART0_TX",    description: "USART0 Transmit Complete" },
    IvtEntry { vector: 28, byte_addr: 0x0070, name: "ANALOG_COMP",  description: "Analog Comparator" },
    IvtEntry { vector: 29, byte_addr: 0x0074, name: "ADC",          description: "ADC Conversion Complete" },
    IvtEntry { vector: 30, byte_addr: 0x0078, name: "EE_READY",     description: "EEPROM Ready" },
    IvtEntry { vector: 31, byte_addr: 0x007C, name: "TIMER3_CAPT",  description: "Timer/Counter3 Capture" },
    IvtEntry { vector: 32, byte_addr: 0x0080, name: "TIMER3_COMPA", description: "Timer/Counter3 Compare A" },
    IvtEntry { vector: 33, byte_addr: 0x0084, name: "TIMER3_COMPB", description: "Timer/Counter3 Compare B" },
    IvtEntry { vector: 34, byte_addr: 0x0088, name: "TIMER3_COMPC", description: "Timer/Counter3 Compare C" },
    IvtEntry { vector: 35, byte_addr: 0x008C, name: "TIMER3_OVF",   description: "Timer/Counter3 Overflow" },
    IvtEntry { vector: 36, byte_addr: 0x0090, name: "USART1_RX",    description: "USART1 Receive Complete" },
    IvtEntry { vector: 37, byte_addr: 0x0094, name: "USART1_UDRE",  description: "USART1 Data Register Empty" },
    IvtEntry { vector: 38, byte_addr: 0x0098, name: "USART1_TX",    description: "USART1 Transmit Complete" },
    IvtEntry { vector: 39, byte_addr: 0x009C, name: "TWI",          description: "Two-Wire Interface" },
    IvtEntry { vector: 40, byte_addr: 0x00A0, name: "SPM_READY",    description: "Store Program Memory Ready" },
    IvtEntry { vector: 41, byte_addr: 0x00A4, name: "TIMER4_CAPT",  description: "Timer/Counter4 Capture" },
    IvtEntry { vector: 42, byte_addr: 0x00A8, name: "TIMER4_COMPA", description: "Timer/Counter4 Compare A" },
    IvtEntry { vector: 43, byte_addr: 0x00AC, name: "TIMER4_COMPB", description: "Timer/Counter4 Compare B" },
    IvtEntry { vector: 44, byte_addr: 0x00B0, name: "TIMER4_COMPC", description: "Timer/Counter4 Compare C" },
    IvtEntry { vector: 45, byte_addr: 0x00B4, name: "TIMER4_OVF",   description: "Timer/Counter4 Overflow" },
    IvtEntry { vector: 46, byte_addr: 0x00B8, name: "TIMER5_CAPT",  description: "Timer/Counter5 Capture" },
    IvtEntry { vector: 47, byte_addr: 0x00BC, name: "TIMER5_COMPA", description: "Timer/Counter5 Compare A" },
    IvtEntry { vector: 48, byte_addr: 0x00C0, name: "TIMER5_COMPB", description: "Timer/Counter5 Compare B" },
    IvtEntry { vector: 49, byte_addr: 0x00C4, name: "TIMER5_COMPC", description: "Timer/Counter5 Compare C" },
    IvtEntry { vector: 50, byte_addr: 0x00C8, name: "TIMER5_OVF",   description: "Timer/Counter5 Overflow" },
    IvtEntry { vector: 51, byte_addr: 0x00CC, name: "USART2_RX",    description: "USART2 Receive Complete" },
    IvtEntry { vector: 52, byte_addr: 0x00D0, name: "USART2_UDRE",  description: "USART2 Data Register Empty" },
    IvtEntry { vector: 53, byte_addr: 0x00D4, name: "USART2_TX",    description: "USART2 Transmit Complete" },
    IvtEntry { vector: 54, byte_addr: 0x00D8, name: "USART3_RX",    description: "USART3 Receive Complete" },
    IvtEntry { vector: 55, byte_addr: 0x00DC, name: "USART3_UDRE",  description: "USART3 Data Register Empty" },
    IvtEntry { vector: 56, byte_addr: 0x00E0, name: "USART3_TX",    description: "USART3 Transmit Complete" },
];

/// `ATmega2560` device descriptor.
pub static ATMEGA2560: AvrDevice = AvrDevice {
    name:             "ATmega2560",
    flash_bytes:      262_144,
    sram_bytes:       8_192,
    eeprom_bytes:     4_096,
    sram_start:       0x0200,
    io_base:          0x0020,
    io_count:         64,
    ivt_byte_addr:    0x0000,
    ivt_count:        57,
    bootloader_start: Some(0x3E000),
    bootloader_size:  Some(0x2000),
    fuses:            MEGA328P_FUSES, // same structure, different defaults
    sfrs:             MEGA328P_SFRS,  // superset; abbreviated
    ivt:              MEGA2560_IVT,
};

// ── ATtiny85 ─────────────────────────────────────────────────────────────────

static ATTINY85_IVT: &[IvtEntry] = &[
    IvtEntry { vector: 0, byte_addr: 0x0000, name: "RESET",        description: "Reset" },
    IvtEntry { vector: 1, byte_addr: 0x0002, name: "INT0",         description: "External Interrupt 0" },
    IvtEntry { vector: 2, byte_addr: 0x0004, name: "PCINT0",       description: "Pin Change Interrupt 0" },
    IvtEntry { vector: 3, byte_addr: 0x0006, name: "TIMER1_COMPA", description: "Timer/Counter1 Compare A" },
    IvtEntry { vector: 4, byte_addr: 0x0008, name: "TIMER1_OVF",   description: "Timer/Counter1 Overflow" },
    IvtEntry { vector: 5, byte_addr: 0x000A, name: "TIMER0_OVF",   description: "Timer/Counter0 Overflow" },
    IvtEntry { vector: 6, byte_addr: 0x000C, name: "EE_READY",     description: "EEPROM Ready" },
    IvtEntry { vector: 7, byte_addr: 0x000E, name: "ANA_COMP",     description: "Analog Comparator" },
    IvtEntry { vector: 8, byte_addr: 0x0010, name: "ADC",          description: "ADC Conversion Complete" },
    IvtEntry { vector: 9, byte_addr: 0x0012, name: "TIMER1_COMPB", description: "Timer/Counter1 Compare B" },
    IvtEntry { vector: 10,byte_addr: 0x0014, name: "TIMER0_COMPA", description: "Timer/Counter0 Compare A" },
    IvtEntry { vector: 11,byte_addr: 0x0016, name: "TIMER0_COMPB", description: "Timer/Counter0 Compare B" },
    IvtEntry { vector: 12,byte_addr: 0x0018, name: "WDT",          description: "Watchdog Time-out" },
    IvtEntry { vector: 13,byte_addr: 0x001A, name: "USI_START",    description: "USI Start" },
    IvtEntry { vector: 14,byte_addr: 0x001C, name: "USI_OVF",      description: "USI Overflow" },
];

/// `ATtiny85` device descriptor.
pub static ATTINY85: AvrDevice = AvrDevice {
    name:             "ATtiny85",
    flash_bytes:      8_192,
    sram_bytes:       512,
    eeprom_bytes:     512,
    sram_start:       0x0060,
    io_base:          0x0020,
    io_count:         64,
    ivt_byte_addr:    0x0000,
    ivt_count:        15,
    bootloader_start: None,
    bootloader_size:  None,
    fuses:            MEGA328P_FUSES, // same bit names, different defaults
    sfrs:             &[],            // abbreviated
    ivt:              ATTINY85_IVT,
};

// ── ATtiny13 ─────────────────────────────────────────────────────────────────

static ATTINY13_IVT: &[IvtEntry] = &[
    IvtEntry { vector: 0, byte_addr: 0x0000, name: "RESET",      description: "Reset" },
    IvtEntry { vector: 1, byte_addr: 0x0002, name: "INT0",       description: "External Interrupt 0" },
    IvtEntry { vector: 2, byte_addr: 0x0004, name: "PCINT0",     description: "Pin Change Interrupt 0" },
    IvtEntry { vector: 3, byte_addr: 0x0006, name: "TIM0_OVF",   description: "Timer/Counter0 Overflow" },
    IvtEntry { vector: 4, byte_addr: 0x0008, name: "EE_RDY",     description: "EEPROM Ready" },
    IvtEntry { vector: 5, byte_addr: 0x000A, name: "ANA_COMP",   description: "Analog Comparator" },
    IvtEntry { vector: 6, byte_addr: 0x000C, name: "TIM0_COMPA", description: "Timer/Counter Compare A" },
    IvtEntry { vector: 7, byte_addr: 0x000E, name: "TIM0_COMPB", description: "Timer/Counter Compare B" },
    IvtEntry { vector: 8, byte_addr: 0x0010, name: "WDT",        description: "Watchdog Time-out" },
    IvtEntry { vector: 9, byte_addr: 0x0012, name: "ADC",        description: "ADC Conversion Complete" },
];

/// `ATtiny13` device descriptor (512B flash, 64B SRAM).
pub static ATTINY13: AvrDevice = AvrDevice {
    name:             "ATtiny13",
    flash_bytes:      1_024,
    sram_bytes:       64,
    eeprom_bytes:     64,
    sram_start:       0x0060,
    io_base:          0x0020,
    io_count:         32,
    ivt_byte_addr:    0x0000,
    ivt_count:        10,
    bootloader_start: None,
    bootloader_size:  None,
    fuses:            &[],
    sfrs:             &[],
    ivt:              ATTINY13_IVT,
};

// ── ATxmega256A3U ─────────────────────────────────────────────────────────────

/// `ATxmega256A3U` — XMEGA family.
/// Notable differences from classic AVR:
/// - 16-bit SP in general-purpose register space
/// - Event system, DMA, CRC, AES, etc.
/// - I/O registers are word-wide, base at 0x0000 in I/O space
/// - No dedicated I/O instructions; uses ST/LD with STS/LDS
/// - Flash uses application section + application table + boot section
pub static ATXMEGA256A3U: AvrDevice = AvrDevice {
    name:             "ATxmega256A3U",
    flash_bytes:      270_336, // 256KB + 4KB application table + 4KB boot
    sram_bytes:       16_384,
    eeprom_bytes:     4_096,
    sram_start:       0x2000,
    io_base:          0x0000,
    io_count:         0x1000, // I/O space is 4KB mapped at 0x0000
    ivt_byte_addr:    0x0000,
    ivt_count:        100, // approximate; many peripherals each have up to 4 vectors
    bootloader_start: Some(0x40000),
    bootloader_size:  Some(0x2000),
    fuses:            &[],  // XMEGA uses NVM fuses, different structure
    sfrs:             &[],
    ivt:              &[],
};

// ── Lookup utilities ──────────────────────────────────────────────────────────

/// All known AVR devices.
pub static ALL_DEVICES: &[&AvrDevice] = &[
    &ATMEGA328P,
    &ATMEGA2560,
    &ATTINY85,
    &ATTINY13,
    &ATXMEGA256A3U,
];

/// Look up a device by name.
#[must_use]
pub fn find_device(name: &str) -> Option<&'static AvrDevice> {
    ALL_DEVICES.iter().copied().find(|d| d.name.eq_ignore_ascii_case(name))
}

/// Look up an SFR by address within a device.
#[must_use]
pub fn find_sfr(device: &AvrDevice, addr: u16) -> Option<&'static SfrEntry> {
    device.sfrs.iter().find(|s| s.addr == addr)
}

/// Look up an interrupt vector by byte address within a device.
#[must_use]
pub fn find_ivt_entry(device: &AvrDevice, byte_addr: u16) -> Option<&'static IvtEntry> {
    device.ivt.iter().find(|v| v.byte_addr == byte_addr)
}

/// Determine if a given byte address is inside the bootloader section.
#[must_use]
pub const fn is_bootloader_address(device: &AvrDevice, byte_addr: u32) -> bool {
    match (device.bootloader_start, device.bootloader_size) {
        (Some(start), Some(size)) => byte_addr >= start && byte_addr < start + size,
        _ => false,
    }
}

/// Bootloader size table for `ATmega328P` (`BOOTSZ` fuses, active-low bits).
/// (BOOTSZ1, BOOTSZ0) → (boot flash size pages, boot reset addr)
pub static MEGA328P_BOOT_SIZES: &[(u8, u8, u16, &str)] = &[
    (1, 1, 0x7E00, "128 words / 256 bytes — BOOT section at 0x7E00"),
    (1, 0, 0x7C00, "256 words / 512 bytes — BOOT section at 0x7C00"),
    (0, 1, 0x7800, "512 words / 1024 bytes — BOOT section at 0x7800"),
    (0, 0, 0x7000, "1024 words / 2048 bytes — BOOT section at 0x7000"),
];

/// Decode `BOOTSZ` fuse bits to boot section start address (for `ATmega328P`).
#[must_use]
pub fn decode_bootsz(bootsz1: bool, bootsz0: bool) -> Option<&'static (u8, u8, u16, &'static str)> {
    let b1 = u8::from(bootsz1);
    let b0 = u8::from(bootsz0);
    MEGA328P_BOOT_SIZES.iter().find(|e| e.0 == b1 && e.1 == b0)
}
