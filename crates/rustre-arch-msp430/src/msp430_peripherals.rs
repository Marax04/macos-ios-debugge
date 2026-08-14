//! `msp430_peripherals` — MSP430 peripheral model for RustRE.
//!
//! Provides a [`Peripheral`] trait and implementations for Timer_A, USCI,
//! ADC10/ADC12, WatchdogTimer, PortRegisters (P1-P8), FlashController,
//! and a [`PeripheralBus`] that dispatches read/write operations.

pub use std::collections::HashMap;
use std::fmt;

// ── Peripheral trait ──────────────────────────────────────────────────────────

/// Error type for peripheral operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeripheralError {
    /// Address not handled by this peripheral.
    NotMapped(u16),
    /// Read-only register was written.
    ReadOnly(u16),
    /// Write-only register was read.
    WriteOnly(u16),
    /// Invalid value for a configuration register.
    InvalidValue {
        addr: u16,
        value: u16,
        reason: &'static str,
    },
}

impl fmt::Display for PeripheralError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotMapped(a) => write!(f, "address 0x{a:04X} not mapped"),
            Self::ReadOnly(a) => write!(f, "register 0x{a:04X} is read-only"),
            Self::WriteOnly(a) => write!(f, "register 0x{a:04X} is write-only"),
            Self::InvalidValue {
                addr,
                value,
                reason,
            } => write!(
                f,
                "invalid value 0x{value:04X} for register 0x{addr:04X}: {reason}"
            ),
        }
    }
}

impl std::error::Error for PeripheralError {}

/// A hardware peripheral that can be read from and written to.
pub trait Peripheral: fmt::Debug {
    /// Human-readable name.
    fn name(&self) -> &str;

    /// Base address of the peripheral's register block.
    fn base_address(&self) -> u16;

    /// Size of the register block in bytes.
    fn address_range(&self) -> usize;

    /// Return true if `addr` falls within this peripheral's address range.
    fn handles(&self, addr: u16) -> bool {
        let base = self.base_address() as usize;
        let end = base + self.address_range();
        (addr as usize) >= base && (addr as usize) < end
    }

    /// Read a byte from `addr`.
    fn read8(&self, addr: u16) -> Result<u8, PeripheralError>;

    /// Read a word (16-bit) from `addr`.
    fn read16(&self, addr: u16) -> Result<u16, PeripheralError> {
        let lo = u16::from(self.read8(addr)?);
        let hi = u16::from(self.read8(addr + 1)?);
        Ok(lo | (hi << 8))
    }

    /// Write a byte to `addr`.
    fn write8(&mut self, addr: u16, value: u8) -> Result<(), PeripheralError>;

    /// Write a word (16-bit) to `addr`.
    fn write16(&mut self, addr: u16, value: u16) -> Result<(), PeripheralError> {
        self.write8(addr, (value & 0xFF) as u8)?;
        self.write8(addr + 1, (value >> 8) as u8)
    }

    /// Advance the peripheral by one CPU clock cycle.
    fn tick(&mut self) {}

    /// Reset the peripheral to its power-on state.
    fn reset(&mut self);

    /// Pending interrupt vector (or `None`).
    fn interrupt_vector(&self) -> Option<u16> {
        None
    }
}

// ── Timer_A ──────────────────────────────────────────────────────────────────

/// MSP430 `Timer_A` registers and state.
///
/// Register layout (base = configurable, 3 CCRs assumed):
/// - +0x00: TACTL  (Timer A Control)
/// - +0x02: TACCTL0 (Capture/Compare Control 0)
/// - +0x04: TACCTL1
/// - +0x06: TACCTL2
/// - +0x10: TAR   (Timer A counter)
/// - +0x12: TACCR0
/// - +0x14: TACCR1
/// - +0x16: TACCR2
#[derive(Debug, Clone)]
pub struct TimerA {
    base: u16,
    /// TACTL register.
    pub tactl: u16,
    /// TAR counter register.
    pub tar: u16,
    /// TACCTL[0..3]
    pub tacctl: [u16; 3],
    /// TACCR[0..3]
    pub taccr: [u16; 3],
    /// Whether the timer is halted.
    pub halted: bool,
    /// Interrupt pending flag.
    pub taifg: bool,
}

impl TimerA {
    pub const TACTL_OFFSET: u16 = 0x00;
    pub const TACCTL0_OFFSET: u16 = 0x02;
    pub const TAR_OFFSET: u16 = 0x10;
    pub const TACCR0_OFFSET: u16 = 0x12;

    /// Look up the symbolic name of a `Timer_A` register by its byte offset
    /// from `base`.  Returns `None` if the offset does not correspond to a
    /// known `Timer_A` register.
    #[must_use]
    pub const fn register_name(offset: u16) -> Option<&'static str> {
        match offset {
            Self::TACTL_OFFSET => Some("TACTL"),
            Self::TACCTL0_OFFSET => Some("TACCTL0"),
            Self::TAR_OFFSET => Some("TAR"),
            Self::TACCR0_OFFSET => Some("TACCR0"),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn new(base: u16) -> Self {
        Self {
            base,
            tactl: 0,
            tar: 0,
            tacctl: [0; 3],
            taccr: [0; 3],
            halted: true,
            taifg: false,
        }
    }

    /// Return the TASSEL bits (clock source select, bits 9:8).
    #[must_use]
    pub const fn clock_source(&self) -> u8 {
        ((self.tactl >> 8) & 0x3) as u8
    }

    /// Return the ID bits (input divider, bits 7:6).
    #[must_use]
    pub const fn input_divider(&self) -> u8 {
        ((self.tactl >> 6) & 0x3) as u8
    }

    /// Return the MC bits (mode control, bits 5:4): 0=stop, 1=up, 2=cont, 3=updown.
    #[must_use]
    pub const fn mode(&self) -> u8 {
        ((self.tactl >> 4) & 0x3) as u8
    }

    /// Count up one timer step.
    pub const fn step(&mut self) {
        if self.halted {
            return;
        }
        match self.mode() {
            0 => {} // stopped
            1 => {
                // up to TACCR0
                self.tar = self.tar.wrapping_add(1);
                if self.tar >= self.taccr[0] {
                    self.tar = 0;
                    self.taifg = true;
                }
            }
            2 => {
                // continuous
                self.tar = self.tar.wrapping_add(1);
                if self.tar == 0xFFFF {
                    self.taifg = true;
                }
            }
            3 => {
                // up-down
                self.tar = self.tar.wrapping_add(1);
                if self.tar >= self.taccr[0] {
                    self.tar = self.taccr[0];
                    self.taifg = true;
                }
            }
            _ => {}
        }
    }
}

impl Peripheral for TimerA {
    fn name(&self) -> &'static str {
        "Timer_A"
    }
    fn base_address(&self) -> u16 {
        self.base
    }
    fn address_range(&self) -> usize {
        0x20
    }

    fn read8(&self, addr: u16) -> Result<u8, PeripheralError> {
        let off = addr.wrapping_sub(self.base);
        let word = match off {
            0x00 | 0x01 => self.tactl,
            0x02 | 0x03 => self.tacctl[0],
            0x04 | 0x05 => self.tacctl[1],
            0x06 | 0x07 => self.tacctl[2],
            0x10 | 0x11 => self.tar,
            0x12 | 0x13 => self.taccr[0],
            0x14 | 0x15 => self.taccr[1],
            0x16 | 0x17 => self.taccr[2],
            _ => return Err(PeripheralError::NotMapped(addr)),
        };
        Ok(if off & 1 == 0 {
            (word & 0xFF) as u8
        } else {
            (word >> 8) as u8
        })
    }

    fn write8(&mut self, addr: u16, value: u8) -> Result<(), PeripheralError> {
        let off = addr.wrapping_sub(self.base);
        let is_hi = off & 1 != 0;
        macro_rules! merge {
            ($reg:expr) => {
                if is_hi {
                    $reg = ($reg & 0x00FF) | ((value as u16) << 8);
                } else {
                    $reg = ($reg & 0xFF00) | (value as u16);
                }
            };
        }
        match off & !1 {
            0x00 => {
                merge!(self.tactl);
                self.halted = self.mode() == 0;
            }
            0x02 => merge!(self.tacctl[0]),
            0x04 => merge!(self.tacctl[1]),
            0x06 => merge!(self.tacctl[2]),
            0x10 => merge!(self.tar),
            0x12 => merge!(self.taccr[0]),
            0x14 => merge!(self.taccr[1]),
            0x16 => merge!(self.taccr[2]),
            _ => return Err(PeripheralError::NotMapped(addr)),
        }
        Ok(())
    }

    fn tick(&mut self) {
        self.step();
    }

    fn reset(&mut self) {
        self.tactl = 0;
        self.tar = 0;
        self.tacctl = [0; 3];
        self.taccr = [0; 3];
        self.halted = true;
        self.taifg = false;
    }

    fn interrupt_vector(&self) -> Option<u16> {
        if self.taifg { Some(0xFFF2) } else { None }
    }
}

// ── USCI (UART/SPI/I2C) ───────────────────────────────────────────────────────

/// USCI operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsciMode {
    Uart,
    Spi,
    I2c,
}

/// MSP430 USCI peripheral (simplified).
#[derive(Debug, Clone)]
pub struct Usci {
    base: u16,
    pub mode: UsciMode,
    /// `UCAxCTL0` / `UCBxCTL0`
    pub ctl0: u8,
    /// `UCAxCTL1` / `UCBxCTL1`
    pub ctl1: u8,
    /// Baud rate control low.
    pub br0: u8,
    /// Baud rate control high.
    pub br1: u8,
    /// Modulation control (UART mode).
    pub mctl: u8,
    /// Status register.
    pub stat: u8,
    /// RX buffer.
    pub rxbuf: u8,
    /// TX buffer.
    pub txbuf: u8,
    /// I2C address.
    pub i2coa: u16,
    /// RX interrupt enabled.
    pub rxie: bool,
    /// TX interrupt enabled.
    pub txie: bool,
    /// TX shift register (internal).
    tx_shift: u8,
    rx_queue: std::collections::VecDeque<u8>,
}

impl Usci {
    #[must_use] 
    pub const fn new(base: u16, mode: UsciMode) -> Self {
        Self {
            base,
            mode,
            ctl0: 0,
            ctl1: 0x01, // SWRST asserted on reset
            br0: 0,
            br1: 0,
            mctl: 0,
            stat: 0,
            rxbuf: 0,
            txbuf: 0,
            i2coa: 0,
            rxie: false,
            txie: false,
            tx_shift: 0,
            rx_queue: std::collections::VecDeque::new(),
        }
    }

    /// Enqueue a byte for the RX buffer (simulate received data).
    pub fn receive(&mut self, byte: u8) {
        self.rx_queue.push_back(byte);
    }

    /// Return true if there is data to receive.
    #[must_use]
    pub fn rx_ready(&self) -> bool {
        !self.rx_queue.is_empty()
    }

    /// Return true if the SWRST bit is clear (module active).
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.ctl1 & 0x01 == 0
    }
}

impl Peripheral for Usci {
    fn name(&self) -> &str {
        match self.mode {
            UsciMode::Uart => "USCI_UART",
            UsciMode::Spi => "USCI_SPI",
            UsciMode::I2c => "USCI_I2C",
        }
    }
    fn base_address(&self) -> u16 {
        self.base
    }
    fn address_range(&self) -> usize {
        16
    }

    fn read8(&self, addr: u16) -> Result<u8, PeripheralError> {
        match addr.wrapping_sub(self.base) {
            0 => Ok(self.ctl0),
            1 => Ok(self.ctl1),
            2 => Ok(self.br0),
            3 => Ok(self.br1),
            4 => Ok(self.mctl),
            5 => Ok(self.stat),
            6 => Ok(self.rxbuf),
            7 => Ok(self.txbuf),
            _ => Err(PeripheralError::NotMapped(addr)),
        }
    }

    fn write8(&mut self, addr: u16, value: u8) -> Result<(), PeripheralError> {
        match addr.wrapping_sub(self.base) {
            0 => self.ctl0 = value,
            1 => self.ctl1 = value,
            2 => self.br0 = value,
            3 => self.br1 = value,
            4 => self.mctl = value,
            5 => self.stat = value,
            6 => return Err(PeripheralError::ReadOnly(addr)), // RXBUF read-only
            7 => {
                self.txbuf = value;
                self.tx_shift = value;
            }
            _ => return Err(PeripheralError::NotMapped(addr)),
        }
        Ok(())
    }

    fn tick(&mut self) {
        if !self.rx_queue.is_empty() {
            self.rxbuf = self.rx_queue.pop_front().unwrap();
            self.stat |= 0x01; // RXIFG
        }
    }

    fn reset(&mut self) {
        self.ctl0 = 0;
        self.ctl1 = 0x01;
        self.br0 = 0;
        self.br1 = 0;
        self.mctl = 0;
        self.stat = 0;
        self.rxbuf = 0;
        self.txbuf = 0;
        self.rxie = false;
        self.txie = false;
        self.rx_queue.clear();
    }
}

// ── ADC10 ─────────────────────────────────────────────────────────────────────

/// MSP430 ADC10 peripheral.
#[derive(Debug, Clone)]
pub struct Adc10 {
    base: u16,
    pub ctl0: u16,
    pub ctl1: u16,
    pub mem: u16,
    channels: [u16; 8],
    converting: bool,
    result: u16,
}

impl Adc10 {
    #[must_use] 
    pub const fn new(base: u16) -> Self {
        Self {
            base,
            ctl0: 0,
            ctl1: 0,
            mem: 0,
            channels: [0; 8],
            converting: false,
            result: 0,
        }
    }

    /// Set a simulated input voltage (0–1023) for channel `ch`.
    pub const fn set_channel(&mut self, ch: usize, value: u16) {
        if ch < 8 {
            self.channels[ch] = value & 0x3FF;
        }
    }

    /// Return the selected channel index (bits 14:12 of CTL1).
    #[must_use]
    pub const fn selected_channel(&self) -> usize {
        ((self.ctl1 >> 12) & 0x7) as usize
    }

    /// Return true if ADC is busy.
    #[must_use]
    pub const fn is_busy(&self) -> bool {
        self.converting
    }
}

impl Peripheral for Adc10 {
    fn name(&self) -> &'static str {
        "ADC10"
    }
    fn base_address(&self) -> u16 {
        self.base
    }
    fn address_range(&self) -> usize {
        8
    }

    fn read8(&self, addr: u16) -> Result<u8, PeripheralError> {
        let off = addr.wrapping_sub(self.base);
        let w = match off & !1 {
            0 => self.ctl0,
            2 => self.ctl1,
            4 => self.mem,
            _ => return Err(PeripheralError::NotMapped(addr)),
        };
        Ok(if off & 1 == 0 {
            (w & 0xFF) as u8
        } else {
            (w >> 8) as u8
        })
    }

    fn write8(&mut self, addr: u16, value: u8) -> Result<(), PeripheralError> {
        let off = addr.wrapping_sub(self.base);
        let is_hi = off & 1 != 0;
        macro_rules! m {
            ($r:expr) => {
                if is_hi {
                    $r = ($r & 0x00FF) | ((value as u16) << 8);
                } else {
                    $r = ($r & 0xFF00) | (value as u16);
                }
            };
        }
        match off & !1 {
            0 => {
                m!(self.ctl0);
                // ENC bit (bit 1 of CTL0) starts conversion.
                if self.ctl0 & 0x02 != 0 {
                    self.converting = true;
                    let ch = self.selected_channel();
                    self.result = self.channels[ch];
                }
            }
            2 => m!(self.ctl1),
            4 => return Err(PeripheralError::ReadOnly(addr)), // MEM read-only
            _ => return Err(PeripheralError::NotMapped(addr)),
        }
        Ok(())
    }

    fn tick(&mut self) {
        if self.converting {
            self.mem = self.result;
            self.ctl0 |= 0x01; // ADC10IFG
            self.converting = false;
        }
    }

    fn reset(&mut self) {
        self.ctl0 = 0;
        self.ctl1 = 0;
        self.mem = 0;
        self.channels = [0; 8];
        self.converting = false;
        self.result = 0;
    }

    fn interrupt_vector(&self) -> Option<u16> {
        if self.ctl0 & 0x01 != 0 {
            Some(0xFFDA)
        } else {
            None
        }
    }
}

// ── ADC12 ─────────────────────────────────────────────────────────────────────

/// MSP430 ADC12 peripheral (12-bit, 16-channel).
#[derive(Debug, Clone)]
pub struct Adc12 {
    base: u16,
    pub ctl0: u16,
    pub ctl1: u16,
    pub ifg: u16,
    pub ie: u16,
    pub iv: u16,
    pub mctl: [u8; 16],
    pub mem: [u16; 16],
    channels: [u16; 16],
    busy: bool,
}

impl Adc12 {
    #[must_use] 
    pub const fn new(base: u16) -> Self {
        Self {
            base,
            ctl0: 0,
            ctl1: 0,
            ifg: 0,
            ie: 0,
            iv: 0,
            mctl: [0; 16],
            mem: [0; 16],
            channels: [0; 16],
            busy: false,
        }
    }

    pub const fn set_channel(&mut self, ch: usize, val: u16) {
        if ch < 16 {
            self.channels[ch] = val & 0xFFF;
        }
    }
}

impl Peripheral for Adc12 {
    fn name(&self) -> &'static str {
        "ADC12"
    }
    fn base_address(&self) -> u16 {
        self.base
    }
    fn address_range(&self) -> usize {
        0x60
    }

    fn read8(&self, addr: u16) -> Result<u8, PeripheralError> {
        let off = addr.wrapping_sub(self.base) as usize;
        match off {
            0 => Ok((self.ctl0 & 0xFF) as u8),
            1 => Ok((self.ctl0 >> 8) as u8),
            2 => Ok((self.ctl1 & 0xFF) as u8),
            3 => Ok((self.ctl1 >> 8) as u8),
            4 => Ok((self.ifg & 0xFF) as u8),
            5 => Ok((self.ifg >> 8) as u8),
            6 => Ok((self.ie & 0xFF) as u8),
            7 => Ok((self.ie >> 8) as u8),
            8 => Ok((self.iv & 0xFF) as u8),
            9 => Ok((self.iv >> 8) as u8),
            o @ 0x10..=0x1F => Ok(self.mctl[o - 0x10]),
            o @ 0x20..=0x3F => {
                let idx = (o - 0x20) / 2;
                let w = self.mem[idx];
                Ok(if (o & 1) == 0 {
                    (w & 0xFF) as u8
                } else {
                    (w >> 8) as u8
                })
            }
            _ => Err(PeripheralError::NotMapped(addr)),
        }
    }

    fn write8(&mut self, addr: u16, value: u8) -> Result<(), PeripheralError> {
        let off = addr.wrapping_sub(self.base) as usize;
        match off {
            0 => {
                self.ctl0 = (self.ctl0 & 0xFF00) | u16::from(value);
            }
            1 => {
                self.ctl0 = (self.ctl0 & 0x00FF) | (u16::from(value) << 8);
            }
            2 => {
                self.ctl1 = (self.ctl1 & 0xFF00) | u16::from(value);
            }
            3 => {
                self.ctl1 = (self.ctl1 & 0x00FF) | (u16::from(value) << 8);
            }
            o @ 0x10..=0x1F => {
                self.mctl[o - 0x10] = value;
            }
            _ => return Err(PeripheralError::NotMapped(addr)),
        }
        Ok(())
    }

    fn tick(&mut self) {
        if self.ctl0 & 0x04 != 0 {
            // ADC12ENC
            for i in 0..16usize {
                let ch = (self.mctl[i] & 0x0F) as usize;
                self.mem[i] = self.channels[ch];
            }
            self.ifg = 0xFFFF;
            self.ctl0 &= !0x04; // clear ENC
        }
    }

    fn reset(&mut self) {
        self.ctl0 = 0;
        self.ctl1 = 0;
        self.ifg = 0;
        self.ie = 0;
        self.iv = 0;
        self.mctl = [0; 16];
        self.mem = [0; 16];
        self.busy = false;
    }
}

// ── WatchdogTimer ─────────────────────────────────────────────────────────────

/// MSP430 Watchdog Timer.
#[derive(Debug, Clone)]
pub struct WatchdogTimer {
    base: u16,
    pub wdtctl: u16,
    counter: u32,
    pub fired: bool,
}

impl WatchdogTimer {
    const WDTPW: u16 = 0x5A00; // password
    const WDTHOLD: u16 = 0x0080; // hold bit

    #[must_use] 
    pub const fn new(base: u16) -> Self {
        Self {
            base,
            wdtctl: Self::WDTHOLD,
            counter: 0,
            fired: false,
        }
    }

    #[must_use]
    pub const fn is_held(&self) -> bool {
        self.wdtctl & Self::WDTHOLD != 0
    }

    /// Return the clock select bits (bits 1:0).
    #[must_use]
    pub const fn clock_select(&self) -> u8 {
        (self.wdtctl & 0x03) as u8
    }

    /// Return the expiry count for the current clock selection.
    #[must_use]
    pub const fn expiry(&self) -> u32 {
        match self.clock_select() {
            0 => 32768,
            1 => 8192,
            2 => 512,
            _ => 64,
        }
    }
}

impl Peripheral for WatchdogTimer {
    fn name(&self) -> &'static str {
        "WDT+"
    }
    fn base_address(&self) -> u16 {
        self.base
    }
    fn address_range(&self) -> usize {
        2
    }

    fn read8(&self, addr: u16) -> Result<u8, PeripheralError> {
        match addr.wrapping_sub(self.base) {
            0 => Ok((self.wdtctl & 0xFF) as u8),
            1 => Ok((self.wdtctl >> 8) as u8),
            _ => Err(PeripheralError::NotMapped(addr)),
        }
    }

    fn write8(&mut self, addr: u16, value: u8) -> Result<(), PeripheralError> {
        match addr.wrapping_sub(self.base) {
            0 => {
                // Check password in high byte.
                if self.wdtctl >> 8 != Self::WDTPW >> 8 {
                    // If password mismatch → typically causes reset; here flag it.
                    self.fired = true;
                }
                self.wdtctl = (self.wdtctl & 0xFF00) | u16::from(value);
                if self.wdtctl & Self::WDTHOLD != 0 {
                    self.counter = 0;
                }
            }
            1 => {
                if u16::from(value) != Self::WDTPW >> 8 {
                    self.fired = true;
                }
                self.wdtctl = (self.wdtctl & 0x00FF) | (u16::from(value) << 8);
            }
            _ => return Err(PeripheralError::NotMapped(addr)),
        }
        Ok(())
    }

    fn tick(&mut self) {
        if self.is_held() {
            return;
        }
        self.counter += 1;
        if self.counter >= self.expiry() {
            self.counter = 0;
            self.fired = true;
        }
    }

    fn reset(&mut self) {
        self.wdtctl = Self::WDTHOLD;
        self.counter = 0;
        self.fired = false;
    }

    fn interrupt_vector(&self) -> Option<u16> {
        if self.fired { Some(0xFFE0) } else { None }
    }
}

// ── PortRegisters ─────────────────────────────────────────────────────────────

/// MSP430 GPIO port registers (P1 through P8).
///
/// Each port has: `PxIN`, `PxOUT`, `PxDIR`, `PxIFG`, `PxIES`, `PxIE`, `PxSEL`, `PxREN`.
#[derive(Debug, Clone)]
pub struct PortRegisters {
    base: u16,
    pub port_num: u8,
    pub pin_in: u8,  // PxIN (read-only, reflects external state)
    pub pin_out: u8, // PxOUT
    pub pin_dir: u8, // PxDIR (0=input, 1=output)
    pub pin_ifg: u8, // PxIFG (interrupt flags)
    pub pin_ies: u8, // PxIES (interrupt edge select)
    pub pin_ie: u8,  // PxIE (interrupt enable)
    pub pin_sel: u8, // PxSEL (function select)
    pub pin_ren: u8, // PxREN (pull-up/down enable)
    pub pin_ds: u8,  // PxDS (drive strength, some devices)
}

impl PortRegisters {
    /// Create port `n` (1–8) at a given base address.
    #[must_use] 
    pub const fn new(port_num: u8, base: u16) -> Self {
        Self {
            base,
            port_num,
            pin_in: 0,
            pin_out: 0,
            pin_dir: 0,
            pin_ifg: 0,
            pin_ies: 0,
            pin_ie: 0,
            pin_sel: 0,
            pin_ren: 0,
            pin_ds: 0,
        }
    }

    /// Drive a pin externally (simulates external signal).
    pub const fn set_external_pin(&mut self, pin: u8, high: bool) {
        if pin < 8 {
            if high {
                self.pin_in |= 1 << pin;
            } else {
                self.pin_in &= !(1 << pin);
            }
        }
    }

    /// Read the effective output on a pin (OUT if DIR=output, IN if DIR=input).
    #[must_use]
    pub const fn read_pin(&self, pin: u8) -> bool {
        let mask = 1u8 << pin;
        if self.pin_dir & mask != 0 {
            self.pin_out & mask != 0
        } else {
            self.pin_in & mask != 0
        }
    }
}

impl Peripheral for PortRegisters {
    fn name(&self) -> &'static str {
        "GPIO_Port"
    }
    fn base_address(&self) -> u16 {
        self.base
    }
    fn address_range(&self) -> usize {
        8
    }

    fn read8(&self, addr: u16) -> Result<u8, PeripheralError> {
        match addr.wrapping_sub(self.base) {
            0 => Ok(self.pin_in),
            1 => Ok(self.pin_out),
            2 => Ok(self.pin_dir),
            3 => Ok(self.pin_ifg),
            4 => Ok(self.pin_ies),
            5 => Ok(self.pin_ie),
            6 => Ok(self.pin_sel),
            7 => Ok(self.pin_ren),
            _ => Err(PeripheralError::NotMapped(addr)),
        }
    }

    fn write8(&mut self, addr: u16, value: u8) -> Result<(), PeripheralError> {
        match addr.wrapping_sub(self.base) {
            0 => return Err(PeripheralError::ReadOnly(addr)), // PxIN read-only
            1 => self.pin_out = value,
            2 => self.pin_dir = value,
            3 => self.pin_ifg = value,
            4 => self.pin_ies = value,
            5 => self.pin_ie = value,
            6 => self.pin_sel = value,
            7 => self.pin_ren = value,
            _ => return Err(PeripheralError::NotMapped(addr)),
        }
        Ok(())
    }

    fn reset(&mut self) {
        self.pin_in = 0;
        self.pin_out = 0;
        self.pin_dir = 0;
        self.pin_ifg = 0;
        self.pin_ies = 0;
        self.pin_ie = 0;
        self.pin_sel = 0;
        self.pin_ren = 0;
        self.pin_ds = 0;
    }

    fn interrupt_vector(&self) -> Option<u16> {
        if self.pin_ie & self.pin_ifg != 0 {
            // P1 = 0xFFE4, P2 = 0xFFE8 (simplified)
            let vec = 0xFFE0 + (u16::from(self.port_num) - 1) * 4;
            Some(vec)
        } else {
            None
        }
    }
}

// ── FlashController ───────────────────────────────────────────────────────────

/// MSP430 Flash Memory Controller.
#[derive(Debug, Clone)]
pub struct FlashController {
    base: u16,
    pub fctl1: u16,
    pub fctl2: u16,
    pub fctl3: u16,
    pub busy: bool,
    pub locked: bool,
}

impl FlashController {
    const FCTL_PW: u16 = 0xA500; // password
    const LOCK_BIT: u16 = 0x0010; // LOCK bit in FCTL3

    #[must_use] 
    pub const fn new(base: u16) -> Self {
        Self {
            base,
            fctl1: 0,
            fctl2: Self::FCTL_PW | 0x40,           // SMCLK, ÷2
            fctl3: Self::FCTL_PW | Self::LOCK_BIT, // locked
            busy: false,
            locked: true,
        }
    }

    #[must_use]
    pub const fn is_locked(&self) -> bool {
        self.fctl3 & Self::LOCK_BIT != 0
    }

    /// Unlock the flash controller (write LOCK=0 with correct password).
    pub const fn unlock(&mut self) {
        self.fctl3 = Self::FCTL_PW | (self.fctl3 & !Self::LOCK_BIT);
        self.locked = false;
    }

    /// Lock the flash controller.
    pub const fn lock(&mut self) {
        self.fctl3 = Self::FCTL_PW | (self.fctl3 | Self::LOCK_BIT);
        self.locked = true;
    }
}

impl Peripheral for FlashController {
    fn name(&self) -> &'static str {
        "Flash_Controller"
    }
    fn base_address(&self) -> u16 {
        self.base
    }
    fn address_range(&self) -> usize {
        6
    }

    fn read8(&self, addr: u16) -> Result<u8, PeripheralError> {
        let off = addr.wrapping_sub(self.base);
        let w = match off & !1 {
            0 => self.fctl1,
            2 => self.fctl2,
            4 => self.fctl3,
            _ => return Err(PeripheralError::NotMapped(addr)),
        };
        Ok(if off & 1 == 0 {
            (w & 0xFF) as u8
        } else {
            (w >> 8) as u8
        })
    }

    fn write8(&mut self, addr: u16, value: u8) -> Result<(), PeripheralError> {
        let off = addr.wrapping_sub(self.base);
        let is_hi = off & 1 != 0;
        macro_rules! m {
            ($r:expr) => {
                if is_hi {
                    $r = ($r & 0x00FF) | ((value as u16) << 8);
                } else {
                    $r = ($r & 0xFF00) | (value as u16);
                }
            };
        }
        match off & !1 {
            0 => m!(self.fctl1),
            2 => m!(self.fctl2),
            4 => {
                m!(self.fctl3);
                self.locked = self.fctl3 & Self::LOCK_BIT != 0;
            }
            _ => return Err(PeripheralError::NotMapped(addr)),
        }
        Ok(())
    }

    fn reset(&mut self) {
        self.fctl1 = 0;
        self.fctl2 = Self::FCTL_PW | 0x40;
        self.fctl3 = Self::FCTL_PW | Self::LOCK_BIT;
        self.busy = false;
        self.locked = true;
    }
}

// ── PeripheralBus ─────────────────────────────────────────────────────────────

/// A bus that dispatches memory reads/writes to registered peripherals.
pub struct PeripheralBus {
    peripherals: Vec<Box<dyn Peripheral>>,
}

impl PeripheralBus {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            peripherals: Vec::new(),
        }
    }

    /// Register a peripheral.
    pub fn add<P: Peripheral + 'static>(&mut self, p: P) {
        self.peripherals.push(Box::new(p));
    }

    /// Read a byte from address `addr`.
    pub fn read8(&self, addr: u16) -> Result<u8, PeripheralError> {
        for p in &self.peripherals {
            if p.handles(addr) {
                return p.read8(addr);
            }
        }
        Err(PeripheralError::NotMapped(addr))
    }

    /// Write a byte to address `addr`.
    pub fn write8(&mut self, addr: u16, value: u8) -> Result<(), PeripheralError> {
        for p in &mut self.peripherals {
            if p.handles(addr) {
                return p.write8(addr, value);
            }
        }
        Err(PeripheralError::NotMapped(addr))
    }

    /// Read a word from address `addr`.
    pub fn read16(&self, addr: u16) -> Result<u16, PeripheralError> {
        for p in &self.peripherals {
            if p.handles(addr) {
                return p.read16(addr);
            }
        }
        Err(PeripheralError::NotMapped(addr))
    }

    /// Write a word to address `addr`.
    pub fn write16(&mut self, addr: u16, value: u16) -> Result<(), PeripheralError> {
        for p in &mut self.peripherals {
            if p.handles(addr) {
                return p.write16(addr, value);
            }
        }
        Err(PeripheralError::NotMapped(addr))
    }

    /// Tick all peripherals.
    pub fn tick(&mut self) {
        for p in &mut self.peripherals {
            p.tick();
        }
    }

    /// Reset all peripherals.
    pub fn reset_all(&mut self) {
        for p in &mut self.peripherals {
            p.reset();
        }
    }

    /// Collect all pending interrupt vectors.
    #[must_use]
    pub fn pending_interrupts(&self) -> Vec<u16> {
        self.peripherals
            .iter()
            .filter_map(|p| p.interrupt_vector())
            .collect()
    }

    /// Number of registered peripherals.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peripherals.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peripherals.is_empty()
    }
}

impl Default for PeripheralBus {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PeripheralBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<_> = self.peripherals.iter().map(|p| p.name()).collect();
        write!(
            f,
            "PeripheralBus {{ {} peripherals: {:?} }}",
            self.peripherals.len(),
            names
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Timer_A ───────────────────────────────────────────────────────────────

    #[test]
    fn test_timer_a_new() {
        let t = TimerA::new(0x0160);
        assert_eq!(t.base_address(), 0x0160);
        assert!(t.halted);
        assert_eq!(t.tar, 0);
    }

    #[test]
    fn test_timer_a_handles_range() {
        let t = TimerA::new(0x0160);
        assert!(t.handles(0x0160));
        assert!(t.handles(0x0170));
        assert!(t.handles(0x017F));
        assert!(!t.handles(0x0180));
        assert!(!t.handles(0x015F));
    }

    #[test]
    fn test_timer_a_write_tactl_start() {
        let mut t = TimerA::new(0x0160);
        // Write MC=1 (up mode) with TASSEL=SMCLK
        t.write16(0x0160, 0x0210).unwrap(); // TASSEL_2 | MC_1
        assert!(!t.halted);
        assert_eq!(t.mode(), 1);
    }

    #[test]
    fn test_timer_a_write_taccr0() {
        let mut t = TimerA::new(0x0160);
        t.write16(0x0172, 1000).unwrap();
        assert_eq!(t.taccr[0], 1000);
    }

    #[test]
    fn test_timer_a_read_tar() {
        let mut t = TimerA::new(0x0160);
        t.tar = 0x1234;
        let lo = t.read8(0x0170).unwrap();
        let hi = t.read8(0x0171).unwrap();
        assert_eq!(lo, 0x34);
        assert_eq!(hi, 0x12);
    }

    #[test]
    fn test_timer_a_reset() {
        let mut t = TimerA::new(0x0160);
        t.tar = 0x5678;
        t.tactl = 0x02;
        t.reset();
        assert_eq!(t.tar, 0);
        assert_eq!(t.tactl, 0);
        assert!(t.halted);
    }

    #[test]
    fn test_timer_a_up_mode_counts() {
        let mut t = TimerA::new(0x0160);
        t.taccr[0] = 3;
        t.tactl = 0x10; // MC=1
        t.halted = false;
        t.step();
        assert_eq!(t.tar, 1);
        t.step();
        assert_eq!(t.tar, 2);
        t.step();
        assert_eq!(t.tar, 0); // wraps at taccr[0]
        assert!(t.taifg);
    }

    #[test]
    fn test_timer_a_interrupt_vector() {
        let mut t = TimerA::new(0x0160);
        t.taifg = true;
        assert_eq!(t.interrupt_vector(), Some(0xFFF2));
        t.taifg = false;
        assert_eq!(t.interrupt_vector(), None);
    }

    // ── USCI ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_usci_new() {
        let u = Usci::new(0x0060, UsciMode::Uart);
        assert_eq!(u.base_address(), 0x0060);
        assert_eq!(u.mode, UsciMode::Uart);
        assert!(!u.is_active()); // SWRST asserted
    }

    #[test]
    fn test_usci_write_and_read_ctl1() {
        let mut u = Usci::new(0x0060, UsciMode::Uart);
        // Clear SWRST (write 0 to CTL1)
        u.write8(0x0061, 0x00).unwrap();
        assert!(u.is_active());
    }

    #[test]
    fn test_usci_rxbuf_readonly() {
        let mut u = Usci::new(0x0060, UsciMode::Uart);
        let result = u.write8(0x0066, 0xFF); // RXBUF
        assert!(matches!(result, Err(PeripheralError::ReadOnly(_))));
    }

    #[test]
    fn test_usci_receive_queue() {
        let mut u = Usci::new(0x0060, UsciMode::Uart);
        u.receive(0xAB);
        assert!(u.rx_ready());
        u.tick();
        assert_eq!(u.rxbuf, 0xAB);
    }

    #[test]
    fn test_usci_reset() {
        let mut u = Usci::new(0x0060, UsciMode::Uart);
        u.br0 = 52;
        u.reset();
        assert_eq!(u.br0, 0);
        assert!(!u.is_active()); // SWRST re-asserted
    }

    #[test]
    fn test_usci_not_mapped() {
        let u = Usci::new(0x0060, UsciMode::Uart);
        assert!(matches!(
            u.read8(0x006F),
            Err(PeripheralError::NotMapped(_))
        ));
    }

    // ── ADC10 ────────────────────────────────────────────────────────────────

    #[test]
    fn test_adc10_new() {
        let a = Adc10::new(0x01B0);
        assert_eq!(a.base_address(), 0x01B0);
        assert!(!a.is_busy());
    }

    #[test]
    fn test_adc10_set_channel() {
        let mut a = Adc10::new(0x01B0);
        a.set_channel(3, 512);
        assert_eq!(a.channels[3], 512);
    }

    #[test]
    fn test_adc10_conversion() {
        let mut a = Adc10::new(0x01B0);
        a.set_channel(0, 750);
        // Write ENC bit to start conversion.
        a.write8(0x01B0, 0x02).unwrap();
        a.tick();
        assert_eq!(a.mem, 750);
    }

    #[test]
    fn test_adc10_reset() {
        let mut a = Adc10::new(0x01B0);
        a.ctl0 = 0xFF;
        a.reset();
        assert_eq!(a.ctl0, 0);
    }

    // ── WatchdogTimer ─────────────────────────────────────────────────────────

    #[test]
    fn test_wdt_new_held() {
        let w = WatchdogTimer::new(0x0120);
        assert!(w.is_held());
        assert!(!w.fired);
    }

    #[test]
    fn test_wdt_tick_when_held_does_nothing() {
        let mut w = WatchdogTimer::new(0x0120);
        for _ in 0..100 {
            w.tick();
        }
        assert!(!w.fired);
    }

    #[test]
    fn test_wdt_fires_after_expiry() {
        let mut w = WatchdogTimer::new(0x0120);
        w.wdtctl = 0x5A00 | 0x03; // WDTPW, no HOLD, fastest clock (÷64)
        // expiry = 64
        for _ in 0..64 {
            w.tick();
        }
        assert!(w.fired);
    }

    #[test]
    fn test_wdt_interrupt_vector() {
        let mut w = WatchdogTimer::new(0x0120);
        w.fired = true;
        assert_eq!(w.interrupt_vector(), Some(0xFFE0));
    }

    #[test]
    fn test_wdt_reset() {
        let mut w = WatchdogTimer::new(0x0120);
        w.fired = true;
        w.reset();
        assert!(!w.fired);
        assert!(w.is_held());
    }

    // ── PortRegisters ─────────────────────────────────────────────────────────

    #[test]
    fn test_port_pin_in_readonly() {
        let mut p = PortRegisters::new(1, 0x0020);
        let result = p.write8(0x0020, 0xFF); // PxIN read-only
        assert!(matches!(result, Err(PeripheralError::ReadOnly(_))));
    }

    #[test]
    fn test_port_write_dir() {
        let mut p = PortRegisters::new(1, 0x0020);
        p.write8(0x0022, 0xFF).unwrap(); // all outputs
        assert_eq!(p.pin_dir, 0xFF);
    }

    #[test]
    fn test_port_write_out() {
        let mut p = PortRegisters::new(1, 0x0020);
        p.write8(0x0021, 0xA5).unwrap();
        assert_eq!(p.pin_out, 0xA5);
    }

    #[test]
    fn test_port_set_external_pin() {
        let mut p = PortRegisters::new(1, 0x0020);
        p.set_external_pin(3, true);
        assert_eq!(p.pin_in & (1 << 3), (1 << 3));
        p.set_external_pin(3, false);
        assert_eq!(p.pin_in & (1 << 3), 0);
    }

    #[test]
    fn test_port_read_pin_input() {
        let mut p = PortRegisters::new(1, 0x0020);
        p.pin_dir = 0; // all inputs
        p.set_external_pin(2, true);
        assert!(p.read_pin(2));
    }

    #[test]
    fn test_port_read_pin_output() {
        let mut p = PortRegisters::new(1, 0x0020);
        p.pin_dir = 0xFF; // all outputs
        p.pin_out = 0b00001000; // pin 3 high
        assert!(p.read_pin(3));
        assert!(!p.read_pin(0));
    }

    #[test]
    fn test_port_interrupt_vector() {
        let mut p = PortRegisters::new(1, 0x0020);
        p.pin_ie = 0x01;
        p.pin_ifg = 0x01;
        assert!(p.interrupt_vector().is_some());
        p.pin_ie = 0;
        assert!(p.interrupt_vector().is_none());
    }

    // ── FlashController ───────────────────────────────────────────────────────

    #[test]
    fn test_flash_new_locked() {
        let f = FlashController::new(0x0128);
        assert!(f.is_locked());
    }

    #[test]
    fn test_flash_unlock() {
        let mut f = FlashController::new(0x0128);
        f.unlock();
        assert!(!f.is_locked());
    }

    #[test]
    fn test_flash_lock() {
        let mut f = FlashController::new(0x0128);
        f.unlock();
        f.lock();
        assert!(f.is_locked());
    }

    #[test]
    fn test_flash_reset() {
        let mut f = FlashController::new(0x0128);
        f.unlock();
        f.reset();
        assert!(f.is_locked());
    }

    // ── PeripheralBus ─────────────────────────────────────────────────────────

    #[test]
    fn test_bus_add_and_len() {
        let mut bus = PeripheralBus::new();
        bus.add(TimerA::new(0x0160));
        bus.add(WatchdogTimer::new(0x0120));
        assert_eq!(bus.len(), 2);
    }

    #[test]
    fn test_bus_read_write_dispatch() {
        let mut bus = PeripheralBus::new();
        bus.add(PortRegisters::new(1, 0x0020));
        bus.write8(0x0022, 0xFF).unwrap(); // P1DIR = all outputs
        let dir = bus.read8(0x0022).unwrap();
        assert_eq!(dir, 0xFF);
    }

    #[test]
    fn test_bus_not_mapped() {
        let bus = PeripheralBus::new();
        assert!(matches!(
            bus.read8(0x1234),
            Err(PeripheralError::NotMapped(_))
        ));
    }

    #[test]
    fn test_bus_tick_all() {
        let mut bus = PeripheralBus::new();
        bus.add(TimerA::new(0x0160));
        bus.add(Adc10::new(0x01B0));
        bus.tick(); // should not panic
    }

    #[test]
    fn test_bus_reset_all() {
        let mut bus = PeripheralBus::new();
        bus.add(PortRegisters::new(1, 0x0020));
        bus.write8(0x0021, 0xAB).unwrap();
        bus.reset_all();
        let out = bus.read8(0x0021).unwrap();
        assert_eq!(out, 0);
    }

    #[test]
    fn test_bus_pending_interrupts() {
        let mut bus = PeripheralBus::new();
        let mut t = TimerA::new(0x0160);
        t.taifg = true;
        bus.add(t);
        let ints = bus.pending_interrupts();
        assert!(ints.contains(&0xFFF2));
    }

    #[test]
    fn test_bus_word_read_write() {
        let mut bus = PeripheralBus::new();
        bus.add(TimerA::new(0x0160));
        // Write TACCR0
        bus.write16(0x0172, 1000).unwrap();
        let val = bus.read16(0x0172).unwrap();
        assert_eq!(val, 1000);
    }

    #[test]
    fn test_peripheral_error_display() {
        assert!(
            PeripheralError::NotMapped(0x1234)
                .to_string()
                .contains("1234")
        );
        assert!(
            PeripheralError::ReadOnly(0x0020)
                .to_string()
                .contains("read-only")
        );
        assert!(
            PeripheralError::WriteOnly(0x0020)
                .to_string()
                .contains("write-only")
        );
    }

    #[test]
    fn test_adc12_new() {
        let a = Adc12::new(0x01A0);
        assert_eq!(a.base_address(), 0x01A0);
        assert_eq!(a.ctl0, 0);
    }

    #[test]
    fn test_usci_spi_name() {
        let u = Usci::new(0x0040, UsciMode::Spi);
        assert_eq!(u.name(), "USCI_SPI");
    }

    #[test]
    fn test_usci_i2c_name() {
        let u = Usci::new(0x0068, UsciMode::I2c);
        assert_eq!(u.name(), "USCI_I2C");
    }

    #[test]
    fn test_bus_default() {
        let bus = PeripheralBus::default();
        assert!(bus.is_empty());
    }
}
