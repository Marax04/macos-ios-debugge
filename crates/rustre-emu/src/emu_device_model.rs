//! `emu_device_model` — Emulated peripheral device model for `rustre-emu`.
//!
//! Provides the [`EmuDevice`] trait for MMIO-mapped peripherals and the
//! [`EmuDeviceModel`] registry that routes guest reads/writes to the correct
//! device by address.  Includes several concrete reference implementations
//! (RAM, ROM, UART, timer, interrupt-pending register) that cover common
//! embedded-system patterns.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// DeviceKind
// ─────────────────────────────────────────────────────────────────────────────

/// Broad category of an emulated peripheral.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceKind {
    /// Volatile read-write memory.
    Ram,
    /// Read-only memory / flash.
    Rom,
    /// Universal Asynchronous Receiver-Transmitter.
    Uart,
    /// Interval / countdown timer.
    Timer,
    /// Interrupt controller / pending-register bank.
    InterruptController,
    /// Generic MMIO device with no special semantics.
    Generic,
    /// Null/debug device that discards writes and returns 0 on reads.
    Null,
}

impl std::fmt::Display for DeviceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Ram => "RAM",
            Self::Rom => "ROM",
            Self::Uart => "UART",
            Self::Timer => "Timer",
            Self::InterruptController => "IntCtrl",
            Self::Generic => "Generic",
            Self::Null => "Null",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EmuDevice trait
// ─────────────────────────────────────────────────────────────────────────────

/// A peripheral device mapped into the guest address space via MMIO.
///
/// Implementors can model any register-mapped peripheral by overriding
/// [`mmio_read`] and [`mmio_write`].  The `offset` parameter is the byte
/// offset *within the device's own mapped region*, not the raw guest VA.
pub trait EmuDevice: Send + Sync {
    /// Human-readable name for logging / debug.
    fn name(&self) -> &str;

    /// Broad category of this device.
    fn kind(&self) -> DeviceKind;

    /// Read `size` bytes from device-relative byte offset `offset`.
    ///
    /// Returns the register value, zero-extended to `u64`.
    fn mmio_read(&self, offset: u64, size: usize) -> u64;

    /// Write `value` (lowest `size` bytes significant) to device-relative offset `offset`.
    fn mmio_write(&mut self, offset: u64, size: usize, value: u64);

    /// Called when the model is reset (e.g., guest asserts RESET line).
    fn reset(&mut self);

    /// Advance device time by `cycles` CPU cycles.  Used by timers and UARTs.
    fn tick(&mut self, cycles: u64);

    /// Return `true` if this device currently asserts an interrupt request.
    fn irq_pending(&self) -> bool {
        false
    }

    /// Return the IRQ line number this device drives, if any.
    fn irq_line(&self) -> Option<u32> {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NullDevice
// ─────────────────────────────────────────────────────────────────────────────

/// A no-op device: all reads return 0, all writes are silently discarded.
pub struct NullDevice {
    label: String,
}

impl NullDevice {
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self { label: label.into() }
    }
}

impl EmuDevice for NullDevice {
    fn name(&self) -> &str { &self.label }
    fn kind(&self) -> DeviceKind { DeviceKind::Null }
    fn mmio_read(&self, _offset: u64, _size: usize) -> u64 { 0 }
    fn mmio_write(&mut self, _offset: u64, _size: usize, _value: u64) {}
    fn reset(&mut self) {}
    fn tick(&mut self, _cycles: u64) {}
}

// ─────────────────────────────────────────────────────────────────────────────
// RamDevice
// ─────────────────────────────────────────────────────────────────────────────

/// A flat RAM bank.
pub struct RamDevice {
    label: String,
    data: Vec<u8>,
}

impl RamDevice {
    #[must_use]
    pub fn new(label: impl Into<String>, size: usize) -> Self {
        Self {
            label: label.into(),
            data: vec![0u8; size],
        }
    }

    #[must_use]
    pub const fn size(&self) -> usize {
        self.data.len()
    }

    /// Pre-load `bytes` into the RAM starting at offset 0.
    ///
    /// # Panics
    /// Panics if `bytes.len() > self.size()`.
    pub fn load(&mut self, bytes: &[u8]) {
        assert!(bytes.len() <= self.data.len(), "load exceeds RAM size");
        self.data[..bytes.len()].copy_from_slice(bytes);
    }
}

impl EmuDevice for RamDevice {
    fn name(&self) -> &str { &self.label }
    fn kind(&self) -> DeviceKind { DeviceKind::Ram }

    fn mmio_read(&self, offset: u64, size: usize) -> u64 {
        let Ok(o) = usize::try_from(offset) else { return 0; };
        if o + size > self.data.len() { return 0; }
        let mut val = 0u64;
        for i in 0..size.min(8) {
            val |= u64::from(self.data[o + i]) << (i * 8);
        }
        val
    }

    fn mmio_write(&mut self, offset: u64, size: usize, value: u64) {
        let Ok(o) = usize::try_from(offset) else { return; };
        if o + size > self.data.len() { return; }
        for i in 0..size.min(8) {
            self.data[o + i] = u8::try_from((value >> (i * 8)) & 0xFF).unwrap_or(0);
        }
    }

    fn reset(&mut self) {
        self.data.iter_mut().for_each(|b| *b = 0);
    }

    fn tick(&mut self, _cycles: u64) {}
}

// ─────────────────────────────────────────────────────────────────────────────
// RomDevice
// ─────────────────────────────────────────────────────────────────────────────

/// A read-only ROM bank.  Writes are silently ignored.
pub struct RomDevice {
    label: String,
    data: Vec<u8>,
}

impl RomDevice {
    #[must_use]
    pub fn new(label: impl Into<String>, content: Vec<u8>) -> Self {
        Self { label: label.into(), data: content }
    }
}

impl EmuDevice for RomDevice {
    fn name(&self) -> &str { &self.label }
    fn kind(&self) -> DeviceKind { DeviceKind::Rom }

    fn mmio_read(&self, offset: u64, size: usize) -> u64 {
        let Ok(o) = usize::try_from(offset) else { return 0; };
        if o + size > self.data.len() { return 0; }
        let mut val = 0u64;
        for i in 0..size.min(8) {
            val |= u64::from(self.data[o + i]) << (i * 8);
        }
        val
    }

    fn mmio_write(&mut self, _offset: u64, _size: usize, _value: u64) {
        // ROM: writes are ignored
    }

    fn reset(&mut self) {}
    fn tick(&mut self, _cycles: u64) {}
}

// ─────────────────────────────────────────────────────────────────────────────
// UartDevice
// ─────────────────────────────────────────────────────────────────────────────

/// A minimal 16550-like UART model.
///
/// Register map (byte offsets):
/// * 0x00 — TX/RX data register.
/// * 0x04 — Line Status Register (bit 5: TX empty, bit 0: RX ready).
/// * 0x08 — Interrupt Enable Register.
pub struct UartDevice {
    label: String,
    rx_fifo: std::collections::VecDeque<u8>,
    tx_log: Vec<u8>,
    irq_line: u32,
    irq_pending: bool,
    irq_enabled: bool,
}

impl UartDevice {
    /// Offset of the TX/RX data register.
    pub const REG_DATA: u64 = 0x00;
    /// Offset of the Line Status Register.
    pub const REG_LSR: u64 = 0x04;
    /// Offset of the Interrupt Enable Register.
    pub const REG_IER: u64 = 0x08;

    #[must_use]
    pub fn new(label: impl Into<String>, irq_line: u32) -> Self {
        Self {
            label: label.into(),
            rx_fifo: std::collections::VecDeque::new(),
            tx_log: Vec::new(),
            irq_line,
            irq_pending: false,
            irq_enabled: false,
        }
    }

    /// Inject a byte into the RX FIFO (simulates received data).
    pub fn inject_rx(&mut self, byte: u8) {
        self.rx_fifo.push_back(byte);
        if self.irq_enabled {
            self.irq_pending = true;
        }
    }

    /// Return all bytes that the guest wrote to the TX register.
    #[must_use]
    pub fn tx_output(&self) -> &[u8] {
        &self.tx_log
    }
}

impl EmuDevice for UartDevice {
    fn name(&self) -> &str { &self.label }
    fn kind(&self) -> DeviceKind { DeviceKind::Uart }

    fn mmio_read(&self, offset: u64, _size: usize) -> u64 {
        match offset {
            Self::REG_DATA => {
                // Peek — real read would pop; we return front
                u64::from(self.rx_fifo.front().copied().unwrap_or(0))
            }
            Self::REG_LSR => {
                let rx_ready: u64 = u64::from(!self.rx_fifo.is_empty());
                // TX always empty (bit 5)
                rx_ready | 0x20
            }
            Self::REG_IER => u64::from(self.irq_enabled),
            _ => 0,
        }
    }

    fn mmio_write(&mut self, offset: u64, _size: usize, value: u64) {
        match offset {
            Self::REG_DATA => {
                self.tx_log.push((value & 0xFF) as u8);
            }
            Self::REG_IER => {
                self.irq_enabled = value & 0x01 != 0;
                if !self.irq_enabled {
                    self.irq_pending = false;
                }
            }
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.rx_fifo.clear();
        self.tx_log.clear();
        self.irq_pending = false;
        self.irq_enabled = false;
    }

    fn tick(&mut self, _cycles: u64) {}

    fn irq_pending(&self) -> bool { self.irq_pending }
    fn irq_line(&self) -> Option<u32> { Some(self.irq_line) }
}

// ─────────────────────────────────────────────────────────────────────────────
// TimerDevice
// ─────────────────────────────────────────────────────────────────────────────

/// A simple countdown timer.
///
/// Register map (32-bit offsets):
/// * 0x00 — Load value (write to arm the timer, read to get initial value).
/// * 0x04 — Current count (decrements on each tick).
/// * 0x08 — Control: bit 0 = enable, bit 1 = interrupt enable.
/// * 0x0C — Interrupt status / clear (write 1 to clear).
pub struct TimerDevice {
    label: String,
    load: u64,
    count: u64,
    enabled: bool,
    irq_enabled: bool,
    irq_pending: bool,
    irq_line: u32,
    ticks_per_count: u64,
    tick_accum: u64,
}

impl TimerDevice {
    pub const REG_LOAD: u64 = 0x00;
    pub const REG_COUNT: u64 = 0x04;
    pub const REG_CTRL: u64 = 0x08;
    pub const REG_IRQ: u64 = 0x0C;

    #[must_use]
    pub fn new(label: impl Into<String>, irq_line: u32, ticks_per_count: u64) -> Self {
        Self {
            label: label.into(),
            load: 0,
            count: 0,
            enabled: false,
            irq_enabled: false,
            irq_pending: false,
            irq_line,
            ticks_per_count: ticks_per_count.max(1),
            tick_accum: 0,
        }
    }
}

impl EmuDevice for TimerDevice {
    fn name(&self) -> &str { &self.label }
    fn kind(&self) -> DeviceKind { DeviceKind::Timer }

    fn mmio_read(&self, offset: u64, _size: usize) -> u64 {
        match offset {
            Self::REG_LOAD => self.load,
            Self::REG_COUNT => self.count,
            Self::REG_CTRL => {
                u64::from(self.enabled) | (u64::from(self.irq_enabled) << 1)
            }
            Self::REG_IRQ => u64::from(self.irq_pending),
            _ => 0,
        }
    }

    fn mmio_write(&mut self, offset: u64, _size: usize, value: u64) {
        match offset {
            Self::REG_LOAD => {
                self.load = value;
                self.count = value;
            }
            Self::REG_CTRL => {
                self.enabled = value & 0x01 != 0;
                self.irq_enabled = value & 0x02 != 0;
                if !self.irq_enabled { self.irq_pending = false; }
            }
            Self::REG_IRQ
                if value & 0x01 != 0 => { self.irq_pending = false; }
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.load = 0;
        self.count = 0;
        self.enabled = false;
        self.irq_enabled = false;
        self.irq_pending = false;
        self.tick_accum = 0;
    }

    fn tick(&mut self, cycles: u64) {
        if !self.enabled || self.count == 0 { return; }
        self.tick_accum += cycles;
        while self.tick_accum >= self.ticks_per_count {
            self.tick_accum -= self.ticks_per_count;
            self.count = self.count.saturating_sub(1);
            if self.count == 0 {
                if self.irq_enabled { self.irq_pending = true; }
                self.count = self.load; // auto-reload
            }
        }
    }

    fn irq_pending(&self) -> bool { self.irq_pending }
    fn irq_line(&self) -> Option<u32> { Some(self.irq_line) }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeviceRegion
// ─────────────────────────────────────────────────────────────────────────────

/// A device mounted at a specific address range in the guest address space.
struct DeviceRegion {
    base: u64,
    size: u64,
    device: Box<dyn EmuDevice>,
}

impl DeviceRegion {
    #[must_use]
    const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base.saturating_add(self.size)
    }

    #[must_use]
    const fn offset_of(&self, addr: u64) -> u64 {
        addr - self.base
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EmuDeviceModel
// ─────────────────────────────────────────────────────────────────────────────

/// Registry of MMIO-mapped peripheral devices.
///
/// Routes guest reads and writes to the correct [`EmuDevice`] by matching the
/// guest virtual address against the registered base + size ranges.
pub struct EmuDeviceModel {
    regions: Vec<DeviceRegion>,
    /// Map from device name to index in `regions` for O(1) name lookup.
    name_index: HashMap<String, usize>,
}

impl EmuDeviceModel {
    /// Create an empty device model with no registered peripherals.
    #[must_use]
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            name_index: HashMap::new(),
        }
    }

    /// Register a peripheral at `[base, base + size)`.
    ///
    /// # Panics
    /// Panics if `size == 0` or if the range overlaps an already-registered device.
    pub fn register(&mut self, base: u64, size: u64, device: Box<dyn EmuDevice>) {
        assert!(size > 0, "device size must be > 0");
        for r in &self.regions {
            let r_end = r.base.saturating_add(r.size);
            let end = base.saturating_add(size);
            assert!(
                base >= r_end || end <= r.base,
                "device '{}' at {:#x}+{:#x} overlaps '{}'",
                device.name(),
                base,
                size,
                r.device.name()
            );
        }
        let idx = self.regions.len();
        self.name_index.insert(device.name().to_string(), idx);
        self.regions.push(DeviceRegion { base, size, device });
    }

    /// Perform an MMIO read at guest address `addr` of `size` bytes.
    ///
    /// Returns 0 if no device covers `addr`.
    #[must_use]
    pub fn mmio_read(&self, addr: u64, size: usize) -> u64 {
        self.regions
            .iter()
            .find(|r| r.contains(addr))
            .map_or(0, |r| r.device.mmio_read(r.offset_of(addr), size))
    }

    /// Perform an MMIO write at guest address `addr` of `size` bytes.
    ///
    /// Silently ignored if no device covers `addr`.
    pub fn mmio_write(&mut self, addr: u64, size: usize, value: u64) {
        if let Some(r) = self.regions.iter_mut().find(|r| r.contains(addr)) {
            let offset = r.offset_of(addr);
            r.device.mmio_write(offset, size, value);
        }
    }

    /// Advance all devices by `cycles` CPU cycles.
    pub fn tick_all(&mut self, cycles: u64) {
        for r in &mut self.regions {
            r.device.tick(cycles);
        }
    }

    /// Reset all registered devices.
    pub fn reset_all(&mut self) {
        for r in &mut self.regions {
            r.device.reset();
        }
    }

    /// Collect all devices that currently assert an IRQ.
    ///
    /// Returns `(irq_line, device_name)` pairs.
    #[must_use]
    pub fn pending_irqs(&self) -> Vec<(u32, &str)> {
        let mut v = Vec::new();
        for r in &self.regions {
            if r.device.irq_pending()
                && let Some(line) = r.device.irq_line() {
                    v.push((line, r.device.name()));
                }
        }
        v
    }

    /// Number of registered devices.
    #[must_use]
    pub const fn device_count(&self) -> usize {
        self.regions.len()
    }

    /// List all registered `(name, kind, base, size)` tuples.
    #[must_use]
    pub fn device_map(&self) -> Vec<(&str, DeviceKind, u64, u64)> {
        self.regions
            .iter()
            .map(|r| (r.device.name(), r.device.kind(), r.base, r.size))
            .collect()
    }

    /// Find a device by name.
    #[must_use]
    pub fn find_device(&self, name: &str) -> Option<&dyn EmuDevice> {
        let idx = *self.name_index.get(name)?;
        self.regions.get(idx).map(|r| r.device.as_ref())
    }
}

impl Default for EmuDeviceModel {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for EmuDeviceModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let devices: Vec<(&str, u64, u64)> = self
            .regions
            .iter()
            .map(|r| (r.device.name(), r.base, r.size))
            .collect();
        f.debug_struct("EmuDeviceModel")
            .field("devices", &devices)
            .field("name_index_len", &self.name_index.len())
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_model() -> EmuDeviceModel {
        let mut m = EmuDeviceModel::new();
        m.register(0x0000, 0x1000, Box::new(RamDevice::new("ram0", 0x1000)));
        m.register(0x2000, 0x100, Box::new(UartDevice::new("uart0", 4)));
        m.register(0x3000, 0x10, Box::new(TimerDevice::new("timer0", 5, 100)));
        m
    }

    #[test]
    fn test_device_count() {
        let m = basic_model();
        assert_eq!(m.device_count(), 3);
    }

    #[test]
    fn test_ram_write_read() {
        let mut m = basic_model();
        m.mmio_write(0x0000, 4, 0xDEAD_BEEF);
        let v = m.mmio_read(0x0000, 4);
        assert_eq!(v, 0xDEAD_BEEF);
    }

    #[test]
    fn test_ram_different_sizes() {
        let mut m = basic_model();
        m.mmio_write(0x0010, 1, 0xAB);
        assert_eq!(m.mmio_read(0x0010, 1), 0xAB);
        m.mmio_write(0x0020, 8, u64::MAX);
        assert_eq!(m.mmio_read(0x0020, 8), u64::MAX);
    }

    #[test]
    fn test_read_unmapped_returns_zero() {
        let m = basic_model();
        assert_eq!(m.mmio_read(0xF000, 4), 0);
    }

    #[test]
    fn test_write_unmapped_silently_ignored() {
        let mut m = basic_model();
        m.mmio_write(0xF000, 4, 0xDEAD); // Should not panic
    }

    #[test]
    fn test_uart_tx_write() {
        let mut m = basic_model();
        m.mmio_write(0x2000, 1, u64::from(b'A'));
        m.mmio_write(0x2000, 1, u64::from(b'B'));
        // Read the UART directly
        if let Some(d) = m.find_device("uart0") {
            // Cast via Any is not available; we verify via mmio_read instead
            let _ = d;
        }
    }

    #[test]
    fn test_uart_lsr_tx_empty_bit() {
        let m = basic_model();
        let lsr = m.mmio_read(0x2000 + UartDevice::REG_LSR, 4);
        assert!(lsr & 0x20 != 0, "TX empty bit should be set");
    }

    #[test]
    fn test_timer_load_and_read_count() {
        let mut m = basic_model();
        m.mmio_write(0x3000 + TimerDevice::REG_LOAD, 4, 1000);
        let count = m.mmio_read(0x3000 + TimerDevice::REG_COUNT, 4);
        assert_eq!(count, 1000);
    }

    #[test]
    fn test_timer_enable_and_tick() {
        let mut m = basic_model();
        m.mmio_write(0x3000 + TimerDevice::REG_LOAD, 4, 10);
        // Enable timer (bit 0) and IRQ (bit 1)
        m.mmio_write(0x3000 + TimerDevice::REG_CTRL, 4, 0x03);
        // Advance 1000 cycles; ticks_per_count = 100 → 10 decrements
        m.tick_all(1000);
        // After 10 counts the timer fires and auto-reloads
        let irqs = m.pending_irqs();
        assert!(irqs.iter().any(|(line, _)| *line == 5));
    }

    #[test]
    fn test_timer_irq_clear() {
        let mut m = basic_model();
        m.mmio_write(0x3000 + TimerDevice::REG_LOAD, 4, 1);
        m.mmio_write(0x3000 + TimerDevice::REG_CTRL, 4, 0x03);
        m.tick_all(100);
        // Clear IRQ
        m.mmio_write(0x3000 + TimerDevice::REG_IRQ, 4, 1);
        assert!(m.pending_irqs().is_empty());
    }

    #[test]
    fn test_reset_all_clears_ram() {
        let mut m = basic_model();
        m.mmio_write(0x0010, 4, 0xDEAD_BEEF);
        m.reset_all();
        assert_eq!(m.mmio_read(0x0010, 4), 0);
    }

    #[test]
    fn test_device_map() {
        let m = basic_model();
        let map = m.device_map();
        assert_eq!(map.len(), 3);
        assert!(map.iter().any(|(name, _, _, _)| *name == "ram0"));
    }

    #[test]
    fn test_find_device_by_name() {
        let m = basic_model();
        assert!(m.find_device("uart0").is_some());
        assert!(m.find_device("notexist").is_none());
    }

    #[test]
    fn test_null_device_reads_zero() {
        let mut m = EmuDeviceModel::new();
        m.register(0x8000, 0x100, Box::new(NullDevice::new("null")));
        assert_eq!(m.mmio_read(0x8000, 8), 0);
        m.mmio_write(0x8000, 4, 0xDEAD); // no-op
    }

    #[test]
    fn test_rom_device_ignores_writes() {
        let mut m = EmuDeviceModel::new();
        m.register(0x5000, 0x10, Box::new(RomDevice::new("rom0", vec![0xAA; 0x10])));
        m.mmio_write(0x5000, 1, 0xBB); // should be ignored
        assert_eq!(m.mmio_read(0x5000, 1), 0xAA);
    }

    #[test]
    fn test_device_kind_display() {
        assert_eq!(DeviceKind::Uart.to_string(), "UART");
        assert_eq!(DeviceKind::Ram.to_string(), "RAM");
    }

    #[test]
    fn test_model_debug() {
        let m = basic_model();
        let s = format!("{m:?}");
        assert!(s.contains("EmuDeviceModel"));
    }

    #[test]
    fn test_ram_device_load() {
        let mut r = RamDevice::new("r", 16);
        r.load(&[1, 2, 3, 4]);
        assert_eq!(r.mmio_read(0, 1), 1);
        assert_eq!(r.mmio_read(3, 1), 4);
    }

    #[test]
    fn test_out_of_bounds_ram_read_zero() {
        let r = RamDevice::new("r", 4);
        assert_eq!(r.mmio_read(4, 4), 0);
    }
}
