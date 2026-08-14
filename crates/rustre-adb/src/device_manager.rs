//! ADB device manager.
//!
//! Enumerates ADB devices over TCP, maintains their state machine, and
//! provides device selection for subsequent commands.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum DeviceManagerError {
    #[error("no devices found")]
    NoDevices,
    #[error("device not found: {0}")]
    NotFound(String),
    #[error("ambiguous: {count} devices match")]
    Ambiguous { count: usize },
    #[error("device offline: {0}")]
    DeviceOffline(String),
    #[error("device unauthorised: {0}")]
    DeviceUnauthorised(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("poll error: {0}")]
    Poll(String),
}

pub type ManagerResult<T> = Result<T, DeviceManagerError>;

// ─── Device State ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceState {
    Online,
    Offline,
    Unauthorized,
    Bootloader,
    Recovery,
    Sideload,
    Connecting,
    Unknown(String),
}

impl DeviceState {
    #[must_use]
    pub fn parse_str(s: &str) -> Self {
        match s.trim() {
            "device" => Self::Online,
            "offline" => Self::Offline,
            "unauthorized" => Self::Unauthorized,
            "bootloader" => Self::Bootloader,
            "recovery" => Self::Recovery,
            "sideload" => Self::Sideload,
            "connecting" => Self::Connecting,
            other => Self::Unknown(other.to_string()),
        }
    }

    #[must_use]
    pub const fn is_usable(&self) -> bool {
        matches!(self, Self::Online)
    }
}

impl fmt::Display for DeviceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Online => write!(f, "device"),
            Self::Offline => write!(f, "offline"),
            Self::Unauthorized => write!(f, "unauthorized"),
            Self::Bootloader => write!(f, "bootloader"),
            Self::Recovery => write!(f, "recovery"),
            Self::Sideload => write!(f, "sideload"),
            Self::Connecting => write!(f, "connecting"),
            Self::Unknown(s) => write!(f, "{s}"),
        }
    }
}

// ─── Device Info ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub serial: String,
    pub state: DeviceState,
    pub product: String,
    pub model: String,
    pub device: String,
    pub transport_id: u64,
    pub usb: Option<String>,
    pub ip: Option<String>,
    pub features: Vec<String>,
    pub first_seen_ts: u64,
    pub last_seen_ts: u64,
}

impl DeviceInfo {
    pub fn new(serial: impl Into<String>, state: DeviceState) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            serial: serial.into(),
            state,
            product: String::new(),
            model: String::new(),
            device: String::new(),
            transport_id: 0,
            usb: None,
            ip: None,
            features: Vec::new(),
            first_seen_ts: now,
            last_seen_ts: now,
        }
    }

    #[must_use]
    pub fn is_network(&self) -> bool {
        self.serial.contains(':') || self.ip.is_some()
    }

    #[must_use]
    pub fn is_emulator(&self) -> bool {
        self.serial.starts_with("emulator-")
    }

    #[must_use]
    pub fn is_usb(&self) -> bool {
        !self.is_network() && !self.is_emulator()
    }

    pub fn touch(&mut self) {
        self.last_seen_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
}

impl fmt::Display for DeviceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\t{}", self.serial, self.state)?;
        if !self.product.is_empty() {
            write!(f, "\tproduct:{}", self.product)?;
        }
        if !self.model.is_empty() {
            write!(f, "\tmodel:{}", self.model)?;
        }
        if !self.device.is_empty() {
            write!(f, "\tdevice:{}", self.device)?;
        }
        Ok(())
    }
}

// ─── Parser for `adb devices -l` output ────────────────────────────────────

pub fn parse_devices_long(output: &str) -> Vec<DeviceInfo> {
    let mut devices = Vec::new();
    for line in output.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let serial = match parts.next() {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => continue,
        };
        let rest = parts.next().unwrap_or("").trim();
        let (state_str, attrs) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        let state = DeviceState::parse_str(state_str);
        let mut info = DeviceInfo::new(serial, state);

        for attr in attrs.split_whitespace() {
            if let Some((k, v)) = attr.split_once(':') {
                match k {
                    "product" => info.product = v.to_string(),
                    "model" => info.model = v.to_string(),
                    "device" => info.device = v.to_string(),
                    "transport_id" => {
                        if let Ok(n) = v.parse() {
                            info.transport_id = n;
                        }
                    }
                    _ => {}
                }
            }
        }
        devices.push(info);
    }
    devices
}

// ─── Device Manager ──────────────────────────────────────────────────────────

/// Manages a registry of known ADB devices.
pub struct DeviceManager {
    devices: RwLock<HashMap<String, DeviceInfo>>,
    selected: Mutex<Option<String>>,
    poll_running: AtomicBool,
    event_seq: AtomicU64,
    pub adb_host: String,
    pub adb_port: u16,
}

impl DeviceManager {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            devices: RwLock::new(HashMap::new()),
            selected: Mutex::new(None),
            poll_running: AtomicBool::new(false),
            event_seq: AtomicU64::new(0),
            adb_host: "127.0.0.1".to_string(),
            adb_port: 5037,
        })
    }

    /// Returns true if a background poll loop has marked itself running.
    pub fn is_poll_running(&self) -> bool {
        self.poll_running.load(Ordering::Relaxed)
    }

    /// Mark the background poll loop as running/stopped.
    pub fn set_poll_running(&self, running: bool) {
        self.poll_running.store(running, Ordering::Relaxed);
    }

    pub fn with_server(host: impl Into<String>, port: u16) -> Arc<Self> {
        Arc::new(Self {
            devices: RwLock::new(HashMap::new()),
            selected: Mutex::new(None),
            poll_running: AtomicBool::new(false),
            event_seq: AtomicU64::new(0),
            adb_host: host.into(),
            adb_port: port,
        })
    }

    #[must_use]
    pub fn adb_addr(&self) -> String {
        format!("{}:{}", self.adb_host, self.adb_port)
    }

    /// Update the device registry from raw `adb devices -l` output.
    pub fn update_from_devices_output(&self, output: &str) {
        let parsed = parse_devices_long(output);
        let seen: std::collections::HashSet<String> =
            parsed.iter().map(|d| d.serial.clone()).collect();
        let mut map = self.devices.write();
        // Remove devices no longer present.
        map.retain(|k, _| seen.contains(k));

        for dev in parsed {
            let entry = map.entry(dev.serial.clone()).or_insert_with(|| dev.clone());
            entry.state = dev.state;
            entry.touch();
        }
        drop(map);
        self.event_seq.fetch_add(1, Ordering::Relaxed);
    }

    /// Register a device directly (e.g. after connecting over TCP).
    pub fn register(&self, info: DeviceInfo) {
        {
            let mut map = self.devices.write();
            map.insert(info.serial.clone(), info);
        }
        self.event_seq.fetch_add(1, Ordering::Relaxed);
    }

    /// Remove a device by serial.
    pub fn unregister(&self, serial: &str) {
        let mut map = self.devices.write();
        map.remove(serial);
    }

    /// List all known devices.
    pub fn list(&self) -> Vec<DeviceInfo> {
        self.devices.read().values().cloned().collect()
    }

    /// List online devices only.
    pub fn online_devices(&self) -> Vec<DeviceInfo> {
        self.devices
            .read()
            .values()
            .filter(|d| d.state.is_usable())
            .cloned()
            .collect()
    }

    /// Get a device by serial.
    ///
    /// # Errors
    /// Returns `DeviceManagerError::NotFound` if the serial is unknown.
    pub fn get(&self, serial: &str) -> ManagerResult<DeviceInfo> {
        self.devices
            .read()
            .get(serial)
            .cloned()
            .ok_or_else(|| DeviceManagerError::NotFound(serial.to_string()))
    }

    /// Select a device for subsequent operations.
    ///
    /// # Errors
    /// Returns `DeviceManagerError::NotFound` if the serial is unknown,
    /// or `DeviceManagerError::DeviceOffline` if the device is not usable.
    pub fn select(&self, serial: impl Into<String>) -> ManagerResult<()> {
        let serial = serial.into();
        let map = self.devices.read();
        if !map.contains_key(&serial) {
            return Err(DeviceManagerError::NotFound(serial));
        }
        let dev = &map[&serial];
        if !dev.state.is_usable() {
            return Err(DeviceManagerError::DeviceOffline(serial));
        }
        drop(map);
        *self.selected.lock() = Some(serial);
        Ok(())
    }

    /// Return the currently selected device, or the only online device.
    ///
    /// # Errors
    /// Returns `NoDevices` if none are online, `Ambiguous` if multiple are
    /// online and no selection is set, or propagates errors from `get`.
    ///
    /// # Panics
    /// Panics only on internal logic error if the verified `len == 1`
    /// element is missing.
    pub fn selected_device(&self) -> ManagerResult<DeviceInfo> {
        if let Some(serial) = &*self.selected.lock() {
            return self.get(serial);
        }
        let online = self.online_devices();
        match online.len() {
            0 => Err(DeviceManagerError::NoDevices),
            1 => Ok(online.into_iter().next().unwrap()),
            n => Err(DeviceManagerError::Ambiguous { count: n }),
        }
    }

    pub fn deselect(&self) {
        *self.selected.lock() = None;
    }

    #[must_use]
    pub fn device_count(&self) -> usize {
        self.devices.read().len()
    }

    #[must_use]
    pub fn event_sequence(&self) -> u64 {
        self.event_seq.load(Ordering::Relaxed)
    }
}

impl Default for DeviceManager {
    fn default() -> Self {
        Arc::try_unwrap(Self::new()).unwrap_or_else(|arc| {
            // This path is unreachable immediately after creation.
            Arc::try_unwrap(arc).unwrap_or_else(|_| panic!("DeviceManager in use"))
        })
    }
}

// ─── Device Poller ───────────────────────────────────────────────────────────

/// Periodic device state refresher.
pub struct DevicePoller {
    manager: Arc<DeviceManager>,
    interval: Duration,
    running: AtomicBool,
}

impl DevicePoller {
    #[must_use]
    pub const fn new(manager: Arc<DeviceManager>, interval: Duration) -> Self {
        Self { manager, interval, running: AtomicBool::new(false) }
    }

    /// Perform a single poll: query `adb devices -l` via subprocess.
    ///
    /// # Errors
    /// Returns errors from the underlying device manager calls; the current
    /// in-memory simulation always succeeds.
    pub fn poll_once(&self) -> ManagerResult<usize> {
        // In a real implementation this would invoke the `adb` subprocess.
        // Here we simulate by returning the current device count.
        let count = self.manager.device_count();
        Ok(count)
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Polling interval configured at construction time.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

// ─── Device Selector ─────────────────────────────────────────────────────────

/// Helper that resolves a device from CLI-style arguments.
pub struct DeviceSelector<'a> {
    manager: &'a DeviceManager,
}

impl<'a> DeviceSelector<'a> {
    #[must_use]
    pub const fn new(manager: &'a DeviceManager) -> Self {
        Self { manager }
    }

    /// Resolve: serial > -d (USB only) > -e (emulator only) > single online device.
    ///
    /// # Errors
    /// Returns errors from device lookup or selection logic.
    ///
    /// # Panics
    /// Panics only on internal logic errors when filtered iteration yields
    /// no element after a length check confirmed exactly one.
    pub fn resolve(
        &self,
        serial: Option<&str>,
        prefer_usb: bool,
        prefer_emulator: bool,
    ) -> ManagerResult<DeviceInfo> {
        if let Some(s) = serial {
            return self.manager.get(s);
        }
        let online = self.manager.online_devices();
        if online.is_empty() {
            return Err(DeviceManagerError::NoDevices);
        }
        if prefer_usb {
            let usb: Vec<_> = online.iter().filter(|d| d.is_usb()).collect();
            return match usb.len() {
                0 => Err(DeviceManagerError::NotFound("no USB devices".into())),
                1 => Ok(usb[0].clone()),
                n => Err(DeviceManagerError::Ambiguous { count: n }),
            };
        }
        if prefer_emulator {
            let emu: Vec<_> = online.iter().filter(|d| d.serial.starts_with("emulator")).collect();
            return match emu.len() {
                0 => Err(DeviceManagerError::NotFound("no emulators".into())),
                1 => Ok(emu[0].clone()),
                n => Err(DeviceManagerError::Ambiguous { count: n }),
            };
        }
        match online.len() {
            1 => Ok(online.into_iter().next().unwrap()),
            n => Err(DeviceManagerError::Ambiguous { count: n }),
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICES_OUTPUT: &str = "List of devices attached\n\
        abc123\tdevice\tproduct:walleye model:Pixel_2 device:walleye transport_id:1\n\
        def456\toffline\tproduct:unknown model:Unknown transport_id:2\n\
        emulator-5554\tdevice\tproduct:sdk_gphone transport_id:3\n";

    #[test]
    fn test_parse_devices_long() {
        let devs = parse_devices_long(DEVICES_OUTPUT);
        assert_eq!(devs.len(), 3);
        assert_eq!(devs[0].serial, "abc123");
        assert_eq!(devs[0].state, DeviceState::Online);
        assert_eq!(devs[0].model, "Pixel_2");
        assert_eq!(devs[1].state, DeviceState::Offline);
    }

    #[test]
    fn test_register_and_list() {
        let mgr = DeviceManager::new();
        let dev = DeviceInfo::new("test001", DeviceState::Online);
        mgr.register(dev);
        assert_eq!(mgr.device_count(), 1);
        let list = mgr.list();
        assert_eq!(list[0].serial, "test001");
    }

    #[test]
    fn test_select_device() {
        let mgr = DeviceManager::new();
        mgr.register(DeviceInfo::new("serial1", DeviceState::Online));
        mgr.select("serial1").unwrap();
        let selected = mgr.selected_device().unwrap();
        assert_eq!(selected.serial, "serial1");
    }

    #[test]
    fn test_select_nonexistent() {
        let mgr = DeviceManager::new();
        let result = mgr.select("nope");
        assert!(matches!(result, Err(DeviceManagerError::NotFound(_))));
    }

    #[test]
    fn test_ambiguous_error() {
        let mgr = DeviceManager::new();
        mgr.register(DeviceInfo::new("d1", DeviceState::Online));
        mgr.register(DeviceInfo::new("d2", DeviceState::Online));
        let result = mgr.selected_device();
        assert!(matches!(result, Err(DeviceManagerError::Ambiguous { .. })));
    }

    #[test]
    fn test_update_from_output() {
        let mgr = DeviceManager::new();
        mgr.update_from_devices_output(DEVICES_OUTPUT);
        assert_eq!(mgr.device_count(), 3);
        let online = mgr.online_devices();
        assert_eq!(online.len(), 2);
    }

    #[test]
    fn test_device_state_display() {
        assert_eq!(DeviceState::Online.to_string(), "device");
        assert_eq!(DeviceState::Unauthorized.to_string(), "unauthorized");
    }

    #[test]
    fn test_device_is_network() {
        let net = DeviceInfo::new("192.168.1.100:5555", DeviceState::Online);
        assert!(net.is_network());
        let usb = DeviceInfo::new("abc123", DeviceState::Online);
        assert!(usb.is_usb());
    }

    #[test]
    fn test_selector_prefer_usb() {
        let mgr = DeviceManager::default();
        mgr.register(DeviceInfo::new("usb001", DeviceState::Online));
        mgr.register(DeviceInfo::new("emulator-5554", DeviceState::Online));
        let selector = DeviceSelector::new(&mgr);
        let dev = selector.resolve(None, true, false).unwrap();
        assert_eq!(dev.serial, "usb001");
    }

    #[test]
    fn test_selector_prefer_emulator() {
        let mgr = DeviceManager::default();
        mgr.register(DeviceInfo::new("usb001", DeviceState::Online));
        mgr.register(DeviceInfo::new("emulator-5554", DeviceState::Online));
        let selector = DeviceSelector::new(&mgr);
        let dev = selector.resolve(None, false, true).unwrap();
        assert_eq!(dev.serial, "emulator-5554");
    }

    #[test]
    fn test_unregister() {
        let mgr = DeviceManager::new();
        mgr.register(DeviceInfo::new("gone", DeviceState::Online));
        mgr.unregister("gone");
        assert_eq!(mgr.device_count(), 0);
    }
}
