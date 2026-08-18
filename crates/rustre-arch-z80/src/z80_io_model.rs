//! Z80 I/O port model: device trait, null device, and a 256-port router.
//!
//! The Z80 has a separate 8-bit I/O address space with 256 ports.
//! `IN A,(n)` and `OUT (n),A` instructions route through [`Z80IoMap`].

// ── Z80IoDevice trait ─────────────────────────────────────────────────────────

/// A device that can be mapped into the Z80's 8-bit I/O port space.
pub trait Z80IoDevice: Send + Sync {
    /// Read one byte from the device at `port`.
    fn read_port(&mut self, port: u8) -> u8;

    /// Write `value` to the device at `port`.
    fn write_port(&mut self, port: u8, value: u8);

    /// Human-readable name for debug output.
    fn name(&self) -> &str;
}

// ── NullIoDevice ──────────────────────────────────────────────────────────────

/// A null I/O device: reads always return 0xFF (floating bus), writes are ignored.
#[derive(Debug, Clone, Default)]
pub struct NullIoDevice;

impl Z80IoDevice for NullIoDevice {
    fn read_port(&mut self, _port: u8) -> u8 {
        0xFF
    }

    fn write_port(&mut self, _port: u8, _value: u8) {
        // discard
    }

    fn name(&self) -> &str {
        "null"
    }
}

// ── SimpleRamIoDevice ─────────────────────────────────────────────────────────

/// An I/O device backed by a 256-byte register file.  Useful for testing.
pub struct SimpleRamIoDevice {
    registers: [u8; 256],
    label: String,
}

impl SimpleRamIoDevice {
    /// Create a new all-zeros register device.
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            registers: [0u8; 256],
            label: label.into(),
        }
    }

    /// Direct access to the register backing array (for tests).
    #[must_use]
    pub const fn registers(&self) -> &[u8; 256] {
        &self.registers
    }
}

impl Z80IoDevice for SimpleRamIoDevice {
    fn read_port(&mut self, port: u8) -> u8 {
        self.registers[port as usize]
    }

    fn write_port(&mut self, port: u8, value: u8) {
        self.registers[port as usize] = value;
    }

    fn name(&self) -> &str {
        &self.label
    }
}

// ── CountingIoDevice ──────────────────────────────────────────────────────────

/// An I/O device that counts reads and writes per port for testing.
pub struct CountingIoDevice {
    pub read_counts: [u32; 256],
    pub write_counts: [u32; 256],
    pub last_written: [u8; 256],
}

impl CountingIoDevice {
    /// Create with all counters zeroed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            read_counts: [0u32; 256],
            write_counts: [0u32; 256],
            last_written: [0u8; 256],
        }
    }
}

impl Default for CountingIoDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl Z80IoDevice for CountingIoDevice {
    fn read_port(&mut self, port: u8) -> u8 {
        self.read_counts[port as usize] += 1;
        self.last_written[port as usize]
    }

    fn write_port(&mut self, port: u8, value: u8) {
        self.write_counts[port as usize] += 1;
        self.last_written[port as usize] = value;
    }

    fn name(&self) -> &str {
        "counter"
    }
}

// ── Z80IoMap ──────────────────────────────────────────────────────────────────

/// Routes Z80 I/O port accesses to registered [`Z80IoDevice`]s.
///
/// At construction time every port maps to a [`NullIoDevice`]. Call
/// [`Z80IoMap::map_device`] to attach a real device to a port range.
pub struct Z80IoMap {
    devices: Vec<Option<Box<dyn Z80IoDevice>>>,
    null: NullIoDevice,
}

impl Z80IoMap {
    /// Create a new I/O map with all 256 ports unoccupied (null device).
    #[must_use]
    pub fn new() -> Self {
        let mut devices: Vec<Option<Box<dyn Z80IoDevice>>> = Vec::with_capacity(256);
        for _ in 0..256 {
            devices.push(None);
        }
        Self {
            devices,
            null: NullIoDevice,
        }
    }

    /// Map `device` to `port`.  Any previous device at that port is dropped.
    pub fn map_device(&mut self, port: u8, device: Box<dyn Z80IoDevice>) {
        self.devices[port as usize] = Some(device);
    }

    /// Unmap the device at `port`, restoring the null device.
    pub fn unmap_device(&mut self, port: u8) {
        self.devices[port as usize] = None;
    }

    /// Read one byte from `port`.
    pub fn read_port(&mut self, port: u8) -> u8 {
        if let Some(dev) = &mut self.devices[port as usize] {
            dev.read_port(port)
        } else {
            self.null.read_port(port)
        }
    }

    /// Write `value` to `port`.
    pub fn write_port(&mut self, port: u8, value: u8) {
        if let Some(dev) = &mut self.devices[port as usize] {
            dev.write_port(port, value);
        }
        // else: null device, discard
    }

    /// Return `true` if a (non-null) device is mapped at `port`.
    #[must_use]
    pub fn is_mapped(&self, port: u8) -> bool {
        self.devices[port as usize].is_some()
    }

    /// Return the name of the device at `port` (`"null"` if unmapped).
    #[must_use]
    pub fn device_name(&self, port: u8) -> &str {
        if let Some(dev) = &self.devices[port as usize] {
            dev.name()
        } else {
            "null"
        }
    }

    /// Return the list of all occupied ports.
    #[must_use]
    pub fn occupied_ports(&self) -> Vec<u8> {
        (0u16..256)
            .filter(|&p| self.devices[p as usize].is_some())
            .map(|p| p as u8)
            .collect()
    }
}

impl Default for Z80IoMap {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_device_reads_0xff() {
        let mut dev = NullIoDevice;
        assert_eq!(dev.read_port(0x00), 0xFF);
        assert_eq!(dev.read_port(0xFE), 0xFF);
    }

    #[test]
    fn test_null_device_ignores_writes() {
        let mut dev = NullIoDevice;
        dev.write_port(0x10, 0xAB); // should not panic
        assert_eq!(dev.read_port(0x10), 0xFF); // still 0xFF
    }

    #[test]
    fn test_simple_ram_device_round_trip() {
        let mut dev = SimpleRamIoDevice::new("test_ram");
        dev.write_port(0x42, 0xDE);
        assert_eq!(dev.read_port(0x42), 0xDE);
        assert_eq!(dev.name(), "test_ram");
    }

    #[test]
    fn test_counting_device_counts_reads_writes() {
        let mut dev = CountingIoDevice::new();
        dev.write_port(0x10, 0xAA);
        dev.write_port(0x10, 0xBB);
        let _ = dev.read_port(0x10);
        assert_eq!(dev.write_counts[0x10], 2);
        assert_eq!(dev.read_counts[0x10], 1);
        assert_eq!(dev.last_written[0x10], 0xBB);
    }

    #[test]
    fn test_io_map_null_read() {
        let mut map = Z80IoMap::new();
        // No device mapped — should return 0xFF
        assert_eq!(map.read_port(0x00), 0xFF);
    }

    #[test]
    fn test_io_map_map_and_read() {
        let mut map = Z80IoMap::new();
        let dev = Box::new(SimpleRamIoDevice::new("test"));
        map.map_device(0xFE, dev);
        assert!(map.is_mapped(0xFE));
        assert!(!map.is_mapped(0xFD));
        map.write_port(0xFE, 0x55);
        assert_eq!(map.read_port(0xFE), 0x55);
    }

    #[test]
    fn test_io_map_unmap_restores_null() {
        let mut map = Z80IoMap::new();
        map.map_device(0x01, Box::new(SimpleRamIoDevice::new("r")));
        map.write_port(0x01, 0x77);
        map.unmap_device(0x01);
        assert!(!map.is_mapped(0x01));
        assert_eq!(map.read_port(0x01), 0xFF);
    }

    #[test]
    fn test_io_map_occupied_ports() {
        let mut map = Z80IoMap::new();
        map.map_device(0x10, Box::new(NullIoDevice));
        map.map_device(0x20, Box::new(NullIoDevice));
        let ports = map.occupied_ports();
        assert!(ports.contains(&0x10));
        assert!(ports.contains(&0x20));
        assert_eq!(ports.len(), 2);
    }

    #[test]
    fn test_io_map_device_name() {
        let mut map = Z80IoMap::new();
        map.map_device(0x30, Box::new(SimpleRamIoDevice::new("uart")));
        assert_eq!(map.device_name(0x30), "uart");
        assert_eq!(map.device_name(0x31), "null");
    }

    #[test]
    fn test_io_map_all_256_ports_default() {
        let map = Z80IoMap::new();
        assert_eq!(map.occupied_ports().len(), 0);
    }
}
