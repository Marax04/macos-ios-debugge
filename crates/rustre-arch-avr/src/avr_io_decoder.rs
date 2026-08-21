//! AVR I/O decoder: translate IN/OUT address operands to named SFR registers
//! with bit-field descriptions, per-device.

use std::fmt::Write as FmtWrite;
use crate::avr_devices::AvrDevice;

// ── I/O address lookup ────────────────────────────────────────────────────────

/// Result of decoding an IN/OUT I/O address.
#[derive(Debug, Clone)]
pub struct IoDecodeResult {
    /// The raw I/O address (0x00–0x3F for classic IN/OUT range).
    pub io_addr: u8,
    /// The data-memory address (`io_addr` + 0x20).
    pub mem_addr: u16,
    /// Register name if known.
    pub name: Option<&'static str>,
    /// Register description if known.
    pub description: Option<&'static str>,
    /// Named bit fields if known.
    pub bits: Vec<BitFieldInfo>,
    /// Whether this address is in the extended I/O range (only accessible via STS/LDS, not IN/OUT).
    pub extended: bool,
}

/// One named bit within an SFR.
#[derive(Debug, Clone)]
pub struct BitFieldInfo {
    pub bit: u8,
    pub name: String,
    pub description: String,
}

/// Decode an I/O address (from IN/OUT instruction) for a given device.
#[must_use]
pub fn decode_io_addr(io_addr: u8, device: &'static AvrDevice) -> IoDecodeResult {
    // Classic IN/OUT range: I/O 0x00-0x3F → mem 0x20-0x5F
    // Extended I/O (XMEGA/mega): I/O 0x40-0xFF → mem 0x60-0xFF, only via STS/LDS
    let mem_addr = u16::from(io_addr) + 0x20;
    let extended = io_addr >= 0x40;

    let sfr = device.sfrs.iter().find(|s| s.io_addr == u16::from(io_addr));
    sfr.map_or_else(|| {
        // Fall back to the static common table
        let (name, desc) = common_io_name(io_addr, device);
        IoDecodeResult {
            io_addr,
            mem_addr,
            name,
            description: desc,
            bits: vec![],
            extended,
        }
    }, |s| {
        let bits = s.bits.iter().map(|b| BitFieldInfo {
            bit: b.bit,
            name: b.name.to_string(),
            description: b.description.to_string(),
        }).collect();
        IoDecodeResult {
            io_addr,
            mem_addr,
            name: Some(s.name),
            description: Some(s.description),
            bits,
            extended,
        }
    })
}

/// Common I/O register name from the built-in `ATmega328P` table.
/// Used as fallback for devices without a full SFR list.
const fn common_io_name(io_addr: u8, _device: &AvrDevice) -> (Option<&'static str>, Option<&'static str>) {
    match io_addr {
        0x00 => (Some("PINB"),   Some("Port B Input Pins")),
        0x01 => (Some("DDRB"),   Some("Port B Data Direction")),
        0x02 => (Some("PORTB"),  Some("Port B Data Register")),
        0x03 => (Some("PINC"),   Some("Port C Input Pins")),
        0x04 => (Some("DDRC"),   Some("Port C Data Direction")),
        0x05 => (Some("PORTC"),  Some("Port C Data Register")),
        0x06 => (Some("PIND"),   Some("Port D Input Pins")),
        0x07 => (Some("DDRD"),   Some("Port D Data Direction")),
        0x08 => (Some("PORTD"),  Some("Port D Data Register")),
        0x15 => (Some("TIFR0"),  Some("Timer/Counter 0 Interrupt Flag Register")),
        0x16 => (Some("TIFR1"),  Some("Timer/Counter 1 Interrupt Flag Register")),
        0x17 => (Some("TIFR2"),  Some("Timer/Counter 2 Interrupt Flag Register")),
        0x1B => (Some("PCIFR"),  Some("Pin Change Interrupt Flag Register")),
        0x1C => (Some("EIFR"),   Some("External Interrupt Flag Register")),
        0x1D => (Some("EIMSK"),  Some("External Interrupt Mask Register")),
        0x1E => (Some("GPIOR0"), Some("General Purpose I/O Register 0")),
        0x1F => (Some("EECR"),   Some("EEPROM Control Register")),
        0x20 => (Some("EEDR"),   Some("EEPROM Data Register")),
        0x21 => (Some("EEARL"),  Some("EEPROM Address Register Low")),
        0x22 => (Some("EEARH"),  Some("EEPROM Address Register High")),
        0x23 => (Some("GTCCR"),  Some("General Timer/Counter Control Register")),
        0x24 => (Some("TCCR0A"), Some("Timer/Counter Control Register A")),
        0x25 => (Some("TCCR0B"), Some("Timer/Counter Control Register B")),
        0x26 => (Some("TCNT0"),  Some("Timer/Counter 0 Register")),
        0x27 => (Some("OCR0A"),  Some("Output Compare Register 0A")),
        0x28 => (Some("OCR0B"),  Some("Output Compare Register 0B")),
        0x2A => (Some("GPIOR1"), Some("General Purpose I/O Register 1")),
        0x2B => (Some("GPIOR2"), Some("General Purpose I/O Register 2")),
        0x2C => (Some("SPCR"),   Some("SPI Control Register")),
        0x2D => (Some("SPSR"),   Some("SPI Status Register")),
        0x2E => (Some("SPDR"),   Some("SPI Data Register")),
        0x30 => (Some("ACSR"),   Some("Analog Comparator Control and Status Register")),
        0x33 => (Some("SMCR"),   Some("Sleep Mode Control Register")),
        0x34 => (Some("MCUSR"),  Some("MCU Status Register")),
        0x35 => (Some("MCUCR"),  Some("MCU Control Register")),
        0x37 => (Some("SPMCSR"), Some("Store Program Memory Control Register")),
        0x3B => (Some("RAMPZ"),  Some("Extended Z-pointer Register")),
        0x3C => (Some("SPL"),    Some("Stack Pointer Low")),
        0x3D => (Some("SPH"),    Some("Stack Pointer High")),
        0x3E => (Some("RAMPZ"),  Some("Extended Z-pointer Register (alias)")),
        0x3F => (Some("SREG"),   Some("CPU Status Register")),
        _    => (None, None),
    }
}

// ── Comprehensive per-register bit annotation ─────────────────────────────────

/// Annotate an I/O register operand with the full bit-level description.
/// Returns a multi-line human-readable string.
#[must_use]
pub fn annotate_io_reg(io_addr: u8, value: Option<u8>, device: &'static AvrDevice) -> String {
    let r = decode_io_addr(io_addr, device);
    let mut out = String::with_capacity(512);

    let name    = r.name.unwrap_or("UNKNOWN");
    let desc    = r.description.unwrap_or("Unknown register");
    let ext     = if r.extended { " [extended I/O — STS/LDS only]" } else { "" };

    let _ = writeln!(out, "I/O 0x{:02X} / MEM 0x{:04X}: {name} — {desc}{ext}", io_addr, r.mem_addr);

    if let Some(val) = value {
        let _ = writeln!(out, "  Value: 0x{val:02X} ({val:08b}b)");
    }

    if r.bits.is_empty() {
        // Generate generic bit names
        for bit in (0..8).rev() {
            let set = value.map(|v| (v >> bit) & 1 != 0);
            let state = match set {
                Some(true)  => "1",
                Some(false) => "0",
                None        => "?",
            };
            let _ = writeln!(out, "  [{state}] bit{bit}");
        }
    } else {
        for bf in &r.bits {
            let set = value.map(|v| (v >> bf.bit) & 1 != 0);
            let state = match set {
                Some(true)  => "1",
                Some(false) => "0",
                None        => "?",
            };
            let _ = writeln!(out, "  [{state}] bit{}: {} — {}", bf.bit, bf.name, bf.description);
        }
    }

    out
}

// ── SREG flag decoder ─────────────────────────────────────────────────────────

/// The AVR SREG (status register) byte, decoded in hardware bit order.
///
/// The value stored *is* the SREG byte (`I T H S V N Z C`, bit 7 down to
/// bit 0); the accessors read bits rather than eight separate `bool` fields
/// that a caller could fill in the wrong order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SregFlags(u8);

impl SregFlags {
    /// Global interrupt enable.
    pub const I: u8 = 0x80;
    /// Bit copy storage.
    pub const T: u8 = 0x40;
    /// Half carry.
    pub const H: u8 = 0x20;
    /// Sign.
    pub const S: u8 = 0x10;
    /// Two's complement overflow.
    pub const V: u8 = 0x08;
    /// Negative.
    pub const N: u8 = 0x04;
    /// Zero.
    pub const Z: u8 = 0x02;
    /// Carry.
    pub const C: u8 = 0x01;

    /// No flag set.
    pub const NONE: Self = Self(0);

    /// Decode a raw SREG byte.
    #[must_use]
    pub const fn from_byte(sreg: u8) -> Self { Self(sreg) }

    /// The raw SREG byte.
    #[must_use]
    pub const fn bits(self) -> u8 { self.0 }

    /// True when `bit` (one of the associated constants) is set.
    #[must_use]
    pub const fn has(self, bit: u8) -> bool { self.0 & bit != 0 }

    /// A copy with `bit` set (`on`) or cleared.
    #[must_use]
    pub const fn with(self, bit: u8, on: bool) -> Self {
        if on { Self(self.0 | bit) } else { Self(self.0 & !bit) }
    }

    /// Global interrupt enable (I).
    #[must_use]
    pub const fn i(self) -> bool { self.has(Self::I) }
    /// Bit copy storage (T).
    #[must_use]
    pub const fn t(self) -> bool { self.has(Self::T) }
    /// Half carry (H).
    #[must_use]
    pub const fn h(self) -> bool { self.has(Self::H) }
    /// Sign (S).
    #[must_use]
    pub const fn s(self) -> bool { self.has(Self::S) }
    /// Two's complement overflow (V).
    #[must_use]
    pub const fn v(self) -> bool { self.has(Self::V) }
    /// Negative (N).
    #[must_use]
    pub const fn n(self) -> bool { self.has(Self::N) }
    /// Zero (Z).
    #[must_use]
    pub const fn z(self) -> bool { self.has(Self::Z) }
    /// Carry (C).
    #[must_use]
    pub const fn c(self) -> bool { self.has(Self::C) }
}

impl core::ops::BitOr for SregFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
}

impl std::fmt::Display for SregFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "I={} T={} H={} S={} V={} N={} Z={} C={}",
            u8::from(self.i()), u8::from(self.t()), u8::from(self.h()), u8::from(self.s()),
            u8::from(self.v()), u8::from(self.n()), u8::from(self.z()), u8::from(self.c()),
        )
    }
}

// ── TCCR decoder ──────────────────────────────────────────────────────────────

/// Timer/Counter prescaler clock source from TCCR bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerPrescaler {
    Stopped,
    Div1,
    Div8,
    Div64,
    Div256,
    Div1024,
    ExternalFalling,
    ExternalRising,
}

impl TimerPrescaler {
    /// Decode from CS2:CS0 bits (3-bit value for TC0/TC1 on `ATmega328P`).
    #[must_use]
    pub const fn from_cs3(cs: u8) -> Self {
        match cs & 7 {
            0 => Self::Stopped,
            1 => Self::Div1,
            2 => Self::Div8,
            3 => Self::Div64,
            4 => Self::Div256,
            5 => Self::Div1024,
            6 => Self::ExternalFalling,
            _ => Self::ExternalRising,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stopped         => "stopped",
            Self::Div1            => "clk/1",
            Self::Div8            => "clk/8",
            Self::Div64           => "clk/64",
            Self::Div256          => "clk/256",
            Self::Div1024         => "clk/1024",
            Self::ExternalFalling => "T0/T1 pin (falling edge)",
            Self::ExternalRising  => "T0/T1 pin (rising edge)",
        }
    }
}

/// Waveform generation mode from WGM bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgmMode {
    Normal,
    PwmPhaseCorrect,
    Ctc,
    FastPwm,
    PwmPhaseCorrectOcr,
    FastPwmOcr,
    Unknown(u8),
}

impl WgmMode {
    /// Decode from 2-bit WGM (TC0: bits WGM01, WGM00).
    #[must_use]
    pub const fn from_wgm2(wgm: u8) -> Self {
        match wgm & 3 {
            0 => Self::Normal,
            1 => Self::PwmPhaseCorrect,
            2 => Self::Ctc,
            _ => Self::FastPwm,
        }
    }
    /// Decode from combined WGM[1:0] in TCCR0A + WGM[2] in TCCR0B.
    #[must_use]
    pub const fn from_wgm3(wgm: u8) -> Self {
        match wgm & 7 {
            0 => Self::Normal,
            1 => Self::PwmPhaseCorrect,
            2 => Self::Ctc,
            3 => Self::FastPwm,
            4 => Self::Unknown(4),
            5 => Self::PwmPhaseCorrectOcr,
            6 => Self::Unknown(6),
            _ => Self::FastPwmOcr,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Normal              => "Normal",
            Self::PwmPhaseCorrect     => "PWM, Phase Correct (TOP=0xFF)",
            Self::Ctc                 => "CTC (clear on compare match)",
            Self::FastPwm             => "Fast PWM (TOP=0xFF)",
            Self::PwmPhaseCorrectOcr  => "PWM, Phase Correct (TOP=OCRnA)",
            Self::FastPwmOcr          => "Fast PWM (TOP=OCRnA)",
            Self::Unknown(v)          => { let _ = v; "Reserved/Unknown" }
        }
    }
}

/// Decode TCCR0A and TCCR0B registers together.
#[derive(Debug, Clone)]
pub struct Timer0Config {
    pub com0a: u8,
    pub com0b: u8,
    pub wgm_mode: WgmMode,
    pub force_oca: bool,
    pub force_ocb: bool,
    pub prescaler: TimerPrescaler,
}

impl Timer0Config {
    #[must_use]
    pub const fn decode(tccr0a: u8, tccr0_b: u8) -> Self {
        let com0a = (tccr0a >> 6) & 3;
        let com_0b = (tccr0a >> 4) & 3;
        let wgm_lo = tccr0a & 3;
        let wgm_hi = (tccr0_b >> 3) & 1;
        let wgm = wgm_lo | (wgm_hi << 2);
        let foca = (tccr0_b >> 7) & 1 != 0;
        let foc_b = (tccr0_b >> 6) & 1 != 0;
        let cs = tccr0_b & 7;

        Self {
            com0a,
            com0b: com_0b,
            wgm_mode: WgmMode::from_wgm3(wgm),
            force_oca: foca,
            force_ocb: foc_b,
            prescaler: TimerPrescaler::from_cs3(cs),
        }
    }

    #[must_use]
    pub fn describe(&self) -> String {
        let com_desc = |com: u8| match com {
            0 => "normal (OC disconnected)",
            1 => "toggle OC on compare match",
            2 => "clear OC on compare match (non-inverting PWM)",
            _ => "set OC on compare match (inverting PWM)",
        };
        format!(
            "Timer0: WGM={} CS={} COM0A={} COM0B={}",
            self.wgm_mode.name(),
            self.prescaler.name(),
            com_desc(self.com0a),
            com_desc(self.com0b),
        )
    }
}

// ── USART baud rate decoder ───────────────────────────────────────────────────

/// Decode USART baud rate registers to actual baud rate.
///
/// `ubrr` = UBRR0H:UBRR0L (12-bit value)
/// `u2x` = UCSR0A bit U2X0 (double speed)
/// `cpu_hz` = CPU clock frequency in Hz
#[must_use]
pub fn decode_baud(ubrr: u16, u2x: bool, cpu_hz: u32) -> u32 {
    let div = if u2x { 8 } else { 16 };
    cpu_hz / (div * (u32::from(ubrr) + 1))
}

/// Common baud rate presets for 16 MHz CPU.
pub static COMMON_BAUDS_16MHZ: &[(u32, u16, bool, &str)] = &[
    // (baud, UBRR, U2X, note)
    (9_600,    103, false, "9600 baud — UBRR=103"),
    (19_200,   51,  false, "19200 baud — UBRR=51"),
    (38_400,   25,  false, "38400 baud — UBRR=25 (0.2% error)"),
    (57_600,   16,  false, "57600 baud — UBRR=16 (2.1% error)"),
    (115_200,  8,   false, "115200 baud — UBRR=8 (2.1% error)"),
    (115_200,  16,  true,  "115200 baud U2X — UBRR=16 (1% error)"),
    (250_000,  7,   false, "250000 baud — UBRR=7"),
    (1_000_000,1,   false, "1 Mbaud — UBRR=1"),
];

/// Given a UBRR value and U2X flag, find the closest standard baud rate preset.
#[must_use]
pub fn match_baud_preset(ubrr: u16, u2x: bool, cpu_hz: u32) -> String {
    let actual = decode_baud(ubrr, u2x, cpu_hz);
    let mut best_err = u32::MAX;
    let mut best_desc = format!("{actual} baud (custom)");

    for &(baud, _, _, desc) in COMMON_BAUDS_16MHZ {
        let err = actual.abs_diff(baud);
        if err < best_err {
            best_err = err;
            best_desc = desc.to_string();
        }
    }
    best_desc
}

// ── ADC channel decoder ───────────────────────────────────────────────────────

/// ADC channel multiplexer selection for `ATmega328P` (ADMUX[3:0]).
#[must_use]
pub const fn decode_admux_channel(mux: u8) -> &'static str {
    match mux & 0x0F {
        0x00 => "ADC0 (PC0)",
        0x01 => "ADC1 (PC1)",
        0x02 => "ADC2 (PC2)",
        0x03 => "ADC3 (PC3)",
        0x04 => "ADC4 (PC4)",
        0x05 => "ADC5 (PC5)",
        0x06 => "ADC6",
        0x07 => "ADC7",
        0x08 => "Internal temperature sensor",
        0x0E => "Internal 1.1V bandgap reference",
        0x0F => "GND (0V)",
        _    => "Reserved",
    }
}

/// ADC reference voltage selection from ADMUX[7:6].
#[must_use]
pub const fn decode_admux_ref(refs: u8) -> &'static str {
    match refs & 3 {
        0 => "AREF, Internal Vref off",
        1 => "AVcc with external cap on AREF pin",
        2 => "Reserved",
        _ => "Internal 1.1V reference with cap on AREF",
    }
}

// ── SPI control decoder ───────────────────────────────────────────────────────

/// The SPCR boolean control bits, packed in hardware bit order.
///
/// Bit positions match SPCR itself: SPE (6), DORD (5), MSTR (4), CPOL (3),
/// CPHA (2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpiFlags(u8);

impl SpiFlags {
    /// SPE — SPI enable.
    pub const ENABLED: u8 = 1 << 6;
    /// DORD — data order, LSB first when set.
    pub const DORD_LSB_FIRST: u8 = 1 << 5;
    /// MSTR — master mode select.
    pub const MASTER: u8 = 1 << 4;
    /// CPOL — clock polarity.
    pub const CPOL: u8 = 1 << 3;
    /// CPHA — clock phase.
    pub const CPHA: u8 = 1 << 2;

    /// Every bit this type tracks.
    pub const MASK: u8 = Self::ENABLED | Self::DORD_LSB_FIRST | Self::MASTER | Self::CPOL | Self::CPHA;

    /// No bit set.
    pub const NONE: Self = Self(0);

    /// Keep only the control bits of a raw SPCR byte.
    #[must_use]
    pub const fn from_spcr(spcr: u8) -> Self { Self(spcr & Self::MASK) }

    /// The raw bit image.
    #[must_use]
    pub const fn bits(self) -> u8 { self.0 }

    /// True when `bit` (one of the associated constants) is set.
    #[must_use]
    pub const fn has(self, bit: u8) -> bool { self.0 & bit != 0 }

    /// A copy with `bit` set (`on`) or cleared.
    #[must_use]
    pub const fn with(self, bit: u8, on: bool) -> Self {
        if on { Self(self.0 | (bit & Self::MASK)) } else { Self(self.0 & !bit) }
    }

    /// SPI enabled.
    #[must_use]
    pub const fn enabled(self) -> bool { self.has(Self::ENABLED) }
    /// Data order is LSB first.
    #[must_use]
    pub const fn dord_lsb_first(self) -> bool { self.has(Self::DORD_LSB_FIRST) }
    /// Master mode.
    #[must_use]
    pub const fn master(self) -> bool { self.has(Self::MASTER) }
    /// Clock polarity.
    #[must_use]
    pub const fn cpol(self) -> bool { self.has(Self::CPOL) }
    /// Clock phase.
    #[must_use]
    pub const fn cpha(self) -> bool { self.has(Self::CPHA) }
}

impl core::ops::BitOr for SpiFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
}

/// Decoded SPI configuration (SPCR).
#[derive(Debug, Clone)]
pub struct SpiConfig {
    /// The SPCR control bits, in hardware bit order.
    pub flags: SpiFlags,
    /// SPI mode number, `(CPOL << 1) | CPHA`.
    pub spi_mode: u8,
    /// Human-readable SCK divider.
    pub clock_div: &'static str,
}

impl SpiConfig {
    /// SPI enabled.
    #[must_use]
    pub const fn enabled(&self) -> bool { self.flags.enabled() }
    /// Data order is LSB first.
    #[must_use]
    pub const fn dord_lsb_first(&self) -> bool { self.flags.dord_lsb_first() }
    /// Master mode.
    #[must_use]
    pub const fn master(&self) -> bool { self.flags.master() }
    /// Clock polarity.
    #[must_use]
    pub const fn cpol(&self) -> bool { self.flags.cpol() }
    /// Clock phase.
    #[must_use]
    pub const fn cpha(&self) -> bool { self.flags.cpha() }
}

impl SpiConfig {
    #[must_use]
    pub fn decode(spcr: u8, spi_sr: u8) -> Self {
        let spe   = (spcr >> 6) & 1 != 0;
        let dord  = (spcr >> 5) & 1 != 0;
        let mstr  = (spcr >> 4) & 1 != 0;
        let cpol  = (spcr >> 3) & 1 != 0;
        let cpha  = (spcr >> 2) & 1 != 0;
        let spr_bits = (spcr & 3) | ((spi_sr & 1) << 2); // SPI2X in SPSR
        let mode  = (u8::from(cpol) << 1) | u8::from(cpha);
        let clk   = match spr_bits & 7 {
            0 => "fosc/4",
            1 => "fosc/16",
            2 => "fosc/64",
            3 => "fosc/128",
            4 => "fosc/2 (SPI2X)",
            5 => "fosc/8 (SPI2X)",
            6 => "fosc/32 (SPI2X)",
            _ => "fosc/64 (SPI2X)",
        };
        Self {
            flags: SpiFlags::NONE
                .with(SpiFlags::ENABLED, spe)
                .with(SpiFlags::DORD_LSB_FIRST, dord)
                .with(SpiFlags::MASTER, mstr)
                .with(SpiFlags::CPOL, cpol)
                .with(SpiFlags::CPHA, cpha),
            spi_mode: mode,
            clock_div: clk,
        }
    }
}

// ── TWI (I2C) address decoder ────────────────────────────────────────────────

/// Decode a TWI slave address register (TWAR).
#[must_use]
pub const fn decode_twar(twar: u8) -> (u8, bool) {
    let addr    = (twar >> 1) & 0x7F;
    let gcall   = twar & 1 != 0;
    (addr, gcall)
}

/// Decode TWI status code from TWSR (after masking prescaler bits).
#[must_use]
pub const fn decode_twsr(twsr: u8) -> &'static str {
    let status = twsr & 0xF8;
    match status {
        0x08 => "START transmitted",
        0x10 => "Repeated START transmitted",
        0x18 => "SLA+W transmitted, ACK received",
        0x20 => "SLA+W transmitted, NACK received",
        0x28 | 0xB8 => "Data byte transmitted, ACK received",
        0x30 | 0xC0 => "Data byte transmitted, NACK received",
        0x38 => "Arbitration lost in SLA+W or data",
        0x40 => "SLA+R transmitted, ACK received",
        0x48 => "SLA+R transmitted, NACK received",
        0x50 => "Data byte received, ACK returned",
        0x58 => "Data byte received, NACK returned",
        0x60 => "Own SLA+W received, ACK returned",
        0x68 => "Arbitration lost; own SLA+W received, ACK returned",
        0x70 => "General call received, ACK returned",
        0x78 => "Arbitration lost; general call received, ACK returned",
        0x80 => "Previously addressed, data received, ACK returned",
        0x88 => "Previously addressed, data received, NACK returned",
        0x90 => "General call, data received, ACK returned",
        0x98 => "General call, data received, NACK returned",
        0xA0 => "STOP or repeated START received while addressed",
        0xA8 => "Own SLA+R received, ACK returned",
        0xB0 => "Arbitration lost; own SLA+R received, ACK returned",
        0xC8 => "Last data byte transmitted, ACK received",
        0xF8 => "No relevant state information — TWINT=0",
        0x00 => "Bus error — illegal START or STOP",
        _    => "Unknown TWI status",
    }
}

// ── Disassembly annotation helper ─────────────────────────────────────────────

/// Annotate an IN/OUT instruction operand with its I/O register name.
///
/// `io_addr_str` is the hex string from the instruction (e.g. "0x3F").
/// Returns a comment string.
#[must_use]
pub fn comment_for_io_instr(mnemonic: &str, io_addr: u8, reg: u8,
                             device: &'static AvrDevice) -> String {
    let r = decode_io_addr(io_addr, device);
    let name = r.name.unwrap_or("UNKNOWN");
    let desc = r.description.unwrap_or("?");

    if mnemonic == "IN" {
        format!("R{reg} ← {name} ({desc})")
    } else {
        format!("{name} ← R{reg} ({desc})")
    }
}

/// Batch-annotate all IN/OUT instructions in a disassembly listing.
///
/// Returns a `Vec<(line_index, comment)>` for lines that contain IN or OUT
/// instructions referencing known I/O registers.
#[must_use]
pub fn annotate_io_in_listing(
    lines: &[&str],
    device: &'static AvrDevice,
) -> Vec<(usize, String)> {
    let mut result = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        // Parse lines like: "0x0100  IN  R24,$3F"
        let upper = line.to_uppercase();
        let (is_in, is_out) = (upper.contains("  IN  ") || upper.contains("\tIN\t"),
                                upper.contains("  OUT  ") || upper.contains("\tOUT\t"));
        if !is_in && !is_out {
            continue;
        }
        // Extract the I/O address and register
        if let Some(io) = parse_io_addr_from_line(line) {
            let reg = parse_reg_from_line(line).unwrap_or(0);
            let mn  = if is_in { "IN" } else { "OUT" };
            let comment = comment_for_io_instr(mn, io, reg, device);
            result.push((i, comment));
        }
    }
    result
}

fn parse_io_addr_from_line(line: &str) -> Option<u8> {
    // Look for $XX or 0xXX pattern
    for part in line.split_whitespace() {
        let hex_str = part.trim_start_matches('$').trim_start_matches("0x");
        if (hex_str.len() == 2 || hex_str.len() == 1)
            && let Ok(v) = u8::from_str_radix(hex_str, 16) {
            return Some(v);
        }
    }
    None
}

fn parse_reg_from_line(line: &str) -> Option<u8> {
    for part in line.split_whitespace() {
        let upper = part.to_uppercase();
        if let Some(stripped) = upper.strip_prefix('R') {
            let clean: String = stripped.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(v) = clean.parse::<u8>()
                && v < 32 {
                return Some(v);
            }
        }
    }
    None
}

// ── Device-aware IN/OUT semantics ─────────────────────────────────────────────

/// Determine whether a given I/O address is readable via IN on the given device.
#[must_use]
pub const fn is_readable_via_in(io_addr: u8, _device: &AvrDevice) -> bool {
    io_addr < 0x40
}

/// Determine whether a given I/O address is writable via OUT on the given device.
#[must_use]
pub const fn is_writable_via_out(io_addr: u8, _device: &AvrDevice) -> bool {
    io_addr < 0x40
}

/// For `ATmega2560`, ports A-L exist.  Map port name to PINX/DDRX/PORTX I/O addresses.
pub static MEGA2560_PORT_IO: &[(&str, u8, u8, u8)] = &[
    // (port, PIN, DDR, PORT)
    ("A", 0x00, 0x01, 0x02),
    ("B", 0x03, 0x04, 0x05),
    ("C", 0x06, 0x07, 0x08),
    ("D", 0x09, 0x0A, 0x0B),
    ("E", 0x0C, 0x0D, 0x0E),
    ("F", 0x0F, 0x10, 0x11),
    ("G", 0x12, 0x13, 0x14),
];

/// Look up `ATmega2560` port I/O addresses.
#[must_use]
pub fn mega2560_port(port: &str) -> Option<(u8, u8, u8)> {
    MEGA2560_PORT_IO
        .iter()
        .find(|e| e.0.eq_ignore_ascii_case(port))
        .map(|e| (e.1, e.2, e.3))
}

/// Device-specific known I/O register map wrapper.
pub struct IoRegMap {
    pub device: &'static AvrDevice,
}

impl IoRegMap {
    #[must_use]
    pub const fn new(device: &'static AvrDevice) -> Self {
        Self { device }
    }

    /// Decode an I/O address.
    #[must_use]
    pub fn decode(&self, io_addr: u8) -> IoDecodeResult {
        decode_io_addr(io_addr, self.device)
    }

    /// All known I/O register names for this device.
    #[must_use]
    pub fn all_names(&self) -> Vec<(&'static str, u8)> {
        self.device.sfrs.iter()
            .filter(|s| s.io_addr < 0x40)
            .map(|s| (s.name, u8::try_from(s.io_addr).unwrap_or(u8::MAX)))
            .collect()
    }

    /// Render a full I/O map table.
    #[must_use]
    pub fn render_table(&self) -> String {
        let mut out = format!("I/O Register Map for {}\n", self.device.name);
        let _ = writeln!(out, "{:-<50}", "");
        out.push_str("I/O Addr  Mem Addr  Name       Description\n");
        let _ = writeln!(out, "{:-<50}", "");
        for sfr in self.device.sfrs {
            if sfr.io_addr < 0x40 {
                let _ = writeln!(
                    out,
                    "0x{:02X}      0x{:04X}    {:<10} {}",
                    sfr.io_addr, sfr.addr, sfr.name, sfr.description,
                );
            }
        }
        out
    }
}
