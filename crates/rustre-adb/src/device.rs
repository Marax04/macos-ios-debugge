//! # device.rs — ADB Device Management
//!
//! Provides richer device tracking than the basic `AdbDevice` struct in
//! `lib.rs`.  Key additions:
//!
//! - `TransportType` (USB / TCP / emulator)
//! - `DeviceList` with filtering helpers
//! - `DeviceMonitor` for polling device-state changes
//! - Device fingerprint parsing from `getprop` output

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{AdbDevice, AdbError, DeviceState, Result};

// ─── TransportType ────────────────────────────────────────────────────────────

/// How the device is physically (or virtually) connected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportType {
    /// Connected via USB cable.
    Usb,
    /// Connected over TCP/IP (tcpip mode).
    Tcp {
        /// IP address of the device.
        address: String,
        /// Port (default 5555).
        port: u16,
    },
    /// An AVD emulator.
    Emulator {
        /// AVD console port (5554, 5556, …).
        port: u16,
    },
}

impl TransportType {
    /// Infer transport type from a device serial string.
    ///
    /// - `emulator-NNNN` → `Emulator { port: NNNN }`
    /// - `A.B.C.D:PORT` or `[IPv6]:PORT` → `Tcp { … }`
    /// - Everything else → `Usb`
    #[must_use]
    pub fn from_serial(serial: &str) -> Self {
        if let Some(port_str) = serial.strip_prefix("emulator-")
            && let Ok(port) = port_str.parse::<u16>()
        {
            return Self::Emulator { port };
        }
        // IPv4/IPv6 with port suffix
        if let Some(colon) = serial.rfind(':') {
            let address = serial[..colon].to_owned();
            if let Ok(port) = serial[colon + 1..].parse::<u16>() {
                return Self::Tcp { address, port };
            }
        }
        Self::Usb
    }

    /// Return a short label for display purposes.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Usb => "usb",
            Self::Tcp { .. } => "tcp",
            Self::Emulator { .. } => "emulator",
        }
    }

    /// Return `true` if this transport represents a virtual device.
    #[must_use]
    pub const fn is_virtual(&self) -> bool {
        matches!(self, Self::Emulator { .. })
    }
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usb => write!(f, "usb"),
            Self::Tcp { address, port } => write!(f, "tcp:{address}:{port}"),
            Self::Emulator { port } => write!(f, "emulator:{port}"),
        }
    }
}

// ─── DeviceInfo — enriched device record ─────────────────────────────────────

/// Enriched device record combining the basic `AdbDevice` fields with
/// transport metadata and optional device properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Core ADB device fields (serial, state, model, …).
    pub device: AdbDevice,
    /// How the device is connected.
    pub transport: TransportType,
    /// Additional properties fetched via `getprop` (may be empty until
    /// `populate_properties()` is called).
    pub properties: HashMap<String, String>,
    /// When this record was last updated (Unix timestamp seconds).
    pub last_seen_ts: u64,
}

impl DeviceInfo {
    /// Create a `DeviceInfo` from a basic `AdbDevice`, inferring transport.
    #[must_use]
    pub fn from_device(device: AdbDevice) -> Self {
        let transport = TransportType::from_serial(&device.serial);
        Self {
            transport,
            device,
            properties: HashMap::new(),
            last_seen_ts: unix_now(),
        }
    }

    /// Shorthand for the serial number.
    #[must_use]
    pub fn serial(&self) -> &str {
        &self.device.serial
    }

    /// Shorthand for the device state.
    #[must_use]
    pub const fn state(&self) -> &DeviceState {
        &self.device.state
    }

    /// Return `true` if the device can accept ADB commands.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.device.is_ready()
    }

    /// Insert or update a single property.
    pub fn set_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.properties.insert(key.into(), value.into());
    }

    /// Look up a property by key.
    #[must_use]
    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(std::string::String::as_str)
    }

    /// Convenience: return `ro.product.model` or `"unknown"`.
    #[must_use]
    pub fn model(&self) -> &str {
        self.get_property("ro.product.model")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                if self.device.model.is_empty() {
                    "unknown"
                } else {
                    &self.device.model
                }
            })
    }

    /// Convenience: return `ro.build.version.release` (Android version).
    #[must_use]
    pub fn android_version(&self) -> &str {
        self.get_property("ro.build.version.release")
            .unwrap_or("unknown")
    }

    /// Convenience: return `ro.build.version.sdk`.
    #[must_use]
    pub fn sdk_version(&self) -> Option<u32> {
        self.get_property("ro.build.version.sdk")
            .and_then(|s| s.parse().ok())
    }

    /// Convenience: `ro.product.cpu.abi`.
    #[must_use]
    pub fn abi(&self) -> &str {
        self.get_property("ro.product.cpu.abi").unwrap_or("unknown")
    }

    /// Parse and store properties from raw `getprop` output.
    pub fn populate_properties_from_getprop(&mut self, getprop_output: &str) {
        for line in getprop_output.lines() {
            let line = line.trim();
            if line.starts_with('[')
                && let Some(colon_idx) = line.find("]: [")
            {
                let key = line[1..colon_idx].to_owned();
                let val_start = colon_idx + 4;
                let value = if line.ends_with(']') {
                    line[val_start..line.len() - 1].to_owned()
                } else {
                    line[val_start..].to_owned()
                };
                self.properties.insert(key, value);
            }
        }
        self.last_seen_ts = unix_now();
    }
}

// ─── DeviceList ───────────────────────────────────────────────────────────────

/// A snapshot of all devices known to the ADB server, with filtering helpers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceList {
    pub devices: Vec<DeviceInfo>,
}

impl DeviceList {
    /// Construct from a `Vec<AdbDevice>` (as returned by `AdbClient::list_devices`).
    pub fn from_adb_devices(devices: Vec<AdbDevice>) -> Self {
        Self {
            devices: devices.into_iter().map(DeviceInfo::from_device).collect(),
        }
    }

    /// Return all devices that are in a usable state.
    #[must_use]
    pub fn online(&self) -> Vec<&DeviceInfo> {
        self.devices.iter().filter(|d| d.is_usable()).collect()
    }

    /// Return all USB devices.
    #[must_use]
    pub fn usb_devices(&self) -> Vec<&DeviceInfo> {
        self.devices
            .iter()
            .filter(|d| matches!(d.transport, TransportType::Usb))
            .collect()
    }

    /// Return all TCP/IP devices.
    #[must_use]
    pub fn tcp_devices(&self) -> Vec<&DeviceInfo> {
        self.devices
            .iter()
            .filter(|d| matches!(d.transport, TransportType::Tcp { .. }))
            .collect()
    }

    /// Return all emulator devices.
    #[must_use]
    pub fn emulators(&self) -> Vec<&DeviceInfo> {
        self.devices
            .iter()
            .filter(|d| matches!(d.transport, TransportType::Emulator { .. }))
            .collect()
    }

    /// Find a device by exact serial number.
    #[must_use]
    pub fn find_by_serial(&self, serial: &str) -> Option<&DeviceInfo> {
        self.devices.iter().find(|d| d.serial() == serial)
    }

    /// Find all devices whose model contains `query` (case-insensitive).
    #[must_use]
    pub fn find_by_model(&self, query: &str) -> Vec<&DeviceInfo> {
        let lower = query.to_lowercase();
        self.devices
            .iter()
            .filter(|d| d.model().to_lowercase().contains(&lower))
            .collect()
    }

    /// Return devices in the `Unauthorized` state (need user confirmation).
    #[must_use]
    pub fn unauthorized(&self) -> Vec<&DeviceInfo> {
        self.devices
            .iter()
            .filter(|d| *d.state() == DeviceState::Unauthorized)
            .collect()
    }

    /// Return devices in Bootloader / Fastboot mode.
    #[must_use]
    pub fn in_bootloader(&self) -> Vec<&DeviceInfo> {
        self.devices
            .iter()
            .filter(|d| *d.state() == DeviceState::Bootloader)
            .collect()
    }

    /// Return the single online device, or an error if there are 0 or >1.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn single_online(&self) -> Result<&DeviceInfo> {
        let online = self.online();
        match online.len() {
            0 => Err(AdbError::DeviceNotFound {
                serial: "<any>".into(),
            }),
            1 => Ok(online[0]),
            _ => Err(AdbError::Protocol(format!(
                "multiple online devices ({}); specify a serial",
                online.len()
            ))),
        }
    }

    /// Total number of devices.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.devices.len()
    }

    /// Return `true` if the list is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Produce a summary line per device.
    #[must_use]
    pub fn summary(&self) -> Vec<String> {
        self.devices
            .iter()
            .map(|d| {
                format!(
                    "{:<20} {:<12} {:<10} {}",
                    d.serial(),
                    d.state(),
                    d.transport.label(),
                    d.model()
                )
            })
            .collect()
    }
}

// ─── DeviceEvent ─────────────────────────────────────────────────────────────

/// Events emitted by the `DeviceMonitor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceEvent {
    /// A new device appeared.
    Connected(DeviceInfo),
    /// An existing device's state changed.
    StateChanged {
        serial: String,
        old_state: DeviceState,
        new_state: DeviceState,
    },
    /// A device disappeared entirely.
    Disconnected { serial: String },
}

impl fmt::Display for DeviceEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connected(d) => write!(f, "[+] {} connected ({})", d.serial(), d.state()),
            Self::StateChanged {
                serial,
                old_state,
                new_state,
            } => write!(f, "[~] {serial}: {old_state} → {new_state}"),
            Self::Disconnected { serial } => write!(f, "[-] {serial} disconnected"),
        }
    }
}

// ─── DeviceMonitor ────────────────────────────────────────────────────────────

/// Polls the ADB server at a configurable interval and emits `DeviceEvent`s
/// by comparing successive `DeviceList` snapshots.
///
/// # Example (sketch)
/// ```no_run
/// # use rustre_adb::{AdbClient, device::DeviceMonitor};
/// # use std::time::Duration;
/// # async fn run() {
/// let client = AdbClient::default();
/// let monitor = DeviceMonitor::new(client, Duration::from_secs(2));
/// let mut rx = monitor.subscribe();
/// tokio::spawn(monitor.run());
/// // `broadcast::Receiver::recv` yields `Result`, not `Option`: it ends on
/// // `Closed` and reports `Lagged` when the receiver falls behind.
/// while let Ok(event) = rx.recv().await {
///     println!("{event}");
/// }
/// # }
/// ```
pub struct DeviceMonitor {
    client: crate::AdbClient,
    interval: Duration,
    tx: tokio::sync::broadcast::Sender<DeviceEvent>,
}

impl DeviceMonitor {
    /// Create a monitor that polls `client` every `interval`.
    #[must_use]
    pub fn new(client: crate::AdbClient, interval: Duration) -> Self {
        let (tx, _rx) = tokio::sync::broadcast::channel(128);
        Self {
            client,
            interval,
            tx,
        }
    }

    /// Subscribe to the event stream.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<DeviceEvent> {
        self.tx.subscribe()
    }

    /// Run the monitor loop (cancel by dropping the future or using a token).
    ///
    /// Sends `DeviceEvent`s to all subscribers whenever the device list changes.
    pub async fn run(self) {
        let mut prev_map: HashMap<String, DeviceState> = HashMap::new();
        let mut ticker = tokio::time::interval(self.interval);
        loop {
            ticker.tick().await;
            let Ok(devices) = self.client.list_devices().await else {
                continue;
            };
            let list = DeviceList::from_adb_devices(devices);
            let mut curr_map: HashMap<String, DeviceState> = HashMap::new();

            for dev in &list.devices {
                curr_map.insert(dev.serial().to_owned(), dev.state().clone());
                if let Some(prev_state) = prev_map.get(dev.serial()) {
                    if prev_state != dev.state() {
                        let _ = self.tx.send(DeviceEvent::StateChanged {
                            serial: dev.serial().to_owned(),
                            old_state: prev_state.clone(),
                            new_state: dev.state().clone(),
                        });
                    }
                } else {
                    let _ = self.tx.send(DeviceEvent::Connected(dev.clone()));
                }
            }

            for serial in prev_map.keys() {
                if !curr_map.contains_key(serial) {
                    let _ = self.tx.send(DeviceEvent::Disconnected {
                        serial: serial.clone(),
                    });
                }
            }

            prev_map = curr_map;
        }
    }
}

// ─── DeviceSelector ──────────────────────────────────────────────────────────

/// How to select a target device when multiple are connected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceSelector {
    /// Use the device with this exact serial.
    BySerial(String),
    /// Use the only connected device (error if 0 or >1).
    Any,
    /// Use the first emulator found.
    FirstEmulator,
    /// Use the first USB device found.
    FirstUsb,
    /// Use the device at this TCP address.
    ByTcpAddress { address: String, port: u16 },
}

impl DeviceSelector {
    /// Resolve the selector against a `DeviceList`, returning the serial.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn resolve<'a>(&self, list: &'a DeviceList) -> Result<&'a DeviceInfo> {
        match self {
            Self::BySerial(s) => list
                .find_by_serial(s)
                .ok_or_else(|| AdbError::DeviceNotFound { serial: s.clone() }),
            Self::Any => list.single_online(),
            Self::FirstEmulator => list
                .emulators()
                .into_iter()
                .find(|d| d.is_usable())
                .ok_or_else(|| AdbError::DeviceNotFound {
                    serial: "emulator".into(),
                }),
            Self::FirstUsb => list
                .usb_devices()
                .into_iter()
                .find(|d| d.is_usable())
                .ok_or_else(|| AdbError::DeviceNotFound {
                    serial: "usb-device".into(),
                }),
            Self::ByTcpAddress { address, port } => {
                let serial = format!("{address}:{port}");
                list.find_by_serial(&serial)
                    .ok_or(AdbError::DeviceNotFound { serial })
            }
        }
    }
}

// ─── Shared device registry (Arc<Mutex<DeviceList>>) ─────────────────────────

/// A thread-safe, shared snapshot of the device list.
pub type SharedDeviceList = Arc<Mutex<DeviceList>>;

/// Create an empty shared device list.
#[must_use]
pub fn new_shared_device_list() -> SharedDeviceList {
    Arc::new(Mutex::new(DeviceList::default()))
}

// ─── Utility ─────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse an ADB `devices -l` output block into a `DeviceList`.
pub fn parse_devices_output(output: &str) -> DeviceList {
    let devices: Vec<AdbDevice> = output
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with("List of"))
        .filter_map(AdbDevice::parse)
        .collect();
    DeviceList::from_adb_devices(devices)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceState;

    fn make_device(serial: &str, state: DeviceState) -> AdbDevice {
        AdbDevice {
            serial: serial.into(),
            state,
            product: "product".into(),
            model: "model".into(),
            device: "device".into(),
            transport_id: None,
        }
    }

    // TransportType

    #[test]
    fn test_transport_from_serial_usb() {
        let t = TransportType::from_serial("R3CN90ABCDE");
        assert_eq!(t, TransportType::Usb);
        assert_eq!(t.label(), "usb");
    }

    #[test]
    fn test_transport_from_serial_emulator() {
        let t = TransportType::from_serial("emulator-5554");
        assert_eq!(t, TransportType::Emulator { port: 5554 });
        assert!(t.is_virtual());
    }

    #[test]
    fn test_transport_from_serial_tcp() {
        let t = TransportType::from_serial("192.168.1.100:5555");
        assert_eq!(
            t,
            TransportType::Tcp {
                address: "192.168.1.100".into(),
                port: 5555
            }
        );
        assert_eq!(t.label(), "tcp");
    }

    #[test]
    fn test_transport_display() {
        assert_eq!(TransportType::Usb.to_string(), "usb");
        assert_eq!(
            TransportType::Tcp {
                address: "10.0.0.1".into(),
                port: 5555
            }
            .to_string(),
            "tcp:10.0.0.1:5555"
        );
        assert_eq!(
            TransportType::Emulator { port: 5554 }.to_string(),
            "emulator:5554"
        );
    }

    // DeviceInfo

    #[test]
    fn test_device_info_from_device() {
        let d = make_device("emulator-5554", DeviceState::Device);
        let info = DeviceInfo::from_device(d);
        assert!(matches!(
            info.transport,
            TransportType::Emulator { port: 5554 }
        ));
        assert!(info.is_usable());
    }

    #[test]
    fn test_device_info_properties() {
        let d = make_device("abc", DeviceState::Device);
        let mut info = DeviceInfo::from_device(d);
        info.set_property("ro.product.model", "Pixel 5");
        assert_eq!(info.model(), "Pixel 5");
    }

    #[test]
    fn test_device_info_android_version_unknown() {
        let d = make_device("abc", DeviceState::Device);
        let info = DeviceInfo::from_device(d);
        assert_eq!(info.android_version(), "unknown");
    }

    #[test]
    fn test_device_info_sdk_version_parsed() {
        let d = make_device("abc", DeviceState::Device);
        let mut info = DeviceInfo::from_device(d);
        info.set_property("ro.build.version.sdk", "30");
        assert_eq!(info.sdk_version(), Some(30));
    }

    #[test]
    fn test_device_info_populate_properties() {
        let d = make_device("abc", DeviceState::Device);
        let mut info = DeviceInfo::from_device(d);
        let getprop = "[ro.product.model]: [TestPhone]\n[ro.build.version.release]: [12]\n";
        info.populate_properties_from_getprop(getprop);
        assert_eq!(info.model(), "TestPhone");
        assert_eq!(info.android_version(), "12");
    }

    // DeviceList

    #[test]
    fn test_device_list_empty() {
        let list = DeviceList::default();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        assert!(list.online().is_empty());
    }

    #[test]
    fn test_device_list_online_filter() {
        let devices = vec![
            make_device("d1", DeviceState::Device),
            make_device("d2", DeviceState::Offline),
            make_device("d3", DeviceState::Recovery),
        ];
        let list = DeviceList::from_adb_devices(devices);
        let online = list.online();
        assert_eq!(online.len(), 2);
    }

    #[test]
    fn test_device_list_usb_and_emulator_split() {
        let devices = vec![
            make_device("emulator-5554", DeviceState::Device),
            make_device("ABC123", DeviceState::Device),
        ];
        let list = DeviceList::from_adb_devices(devices);
        assert_eq!(list.emulators().len(), 1);
        assert_eq!(list.usb_devices().len(), 1);
    }

    #[test]
    fn test_device_list_find_by_serial() {
        let devices = vec![make_device("target123", DeviceState::Device)];
        let list = DeviceList::from_adb_devices(devices);
        assert!(list.find_by_serial("target123").is_some());
        assert!(list.find_by_serial("nope").is_none());
    }

    #[test]
    fn test_device_list_single_online_ok() {
        let devices = vec![make_device("solo", DeviceState::Device)];
        let list = DeviceList::from_adb_devices(devices);
        assert_eq!(list.single_online().unwrap().serial(), "solo");
    }

    #[test]
    fn test_device_list_single_online_err_none() {
        let devices = vec![make_device("d1", DeviceState::Offline)];
        let list = DeviceList::from_adb_devices(devices);
        assert!(list.single_online().is_err());
    }

    #[test]
    fn test_device_list_single_online_err_multiple() {
        let devices = vec![
            make_device("d1", DeviceState::Device),
            make_device("d2", DeviceState::Device),
        ];
        let list = DeviceList::from_adb_devices(devices);
        assert!(list.single_online().is_err());
    }

    #[test]
    fn test_device_list_summary_format() {
        let devices = vec![make_device("emulator-5554", DeviceState::Device)];
        let list = DeviceList::from_adb_devices(devices);
        let summary = list.summary();
        assert_eq!(summary.len(), 1);
        assert!(summary[0].contains("emulator-5554"));
    }

    #[test]
    fn test_device_list_unauthorized() {
        let devices = vec![
            make_device("auth_needed", DeviceState::Unauthorized),
            make_device("ok_device", DeviceState::Device),
        ];
        let list = DeviceList::from_adb_devices(devices);
        assert_eq!(list.unauthorized().len(), 1);
    }

    #[test]
    fn test_device_list_in_bootloader() {
        let devices = vec![make_device("d1", DeviceState::Bootloader)];
        let list = DeviceList::from_adb_devices(devices);
        assert_eq!(list.in_bootloader().len(), 1);
    }

    // DeviceSelector

    #[test]
    fn test_selector_by_serial_found() {
        let devices = vec![make_device("mydev", DeviceState::Device)];
        let list = DeviceList::from_adb_devices(devices);
        let sel = DeviceSelector::BySerial("mydev".into());
        assert!(sel.resolve(&list).is_ok());
    }

    #[test]
    fn test_selector_by_serial_not_found() {
        let list = DeviceList::default();
        let sel = DeviceSelector::BySerial("ghost".into());
        assert!(sel.resolve(&list).is_err());
    }

    #[test]
    fn test_selector_any_single() {
        let devices = vec![make_device("only", DeviceState::Device)];
        let list = DeviceList::from_adb_devices(devices);
        assert_eq!(DeviceSelector::Any.resolve(&list).unwrap().serial(), "only");
    }

    #[test]
    fn test_selector_first_emulator() {
        let devices = vec![
            make_device("USB123", DeviceState::Device),
            make_device("emulator-5554", DeviceState::Device),
        ];
        let list = DeviceList::from_adb_devices(devices);
        let sel = DeviceSelector::FirstEmulator;
        let resolved = sel.resolve(&list).unwrap();
        assert!(resolved.serial().starts_with("emulator"));
    }

    #[test]
    fn test_selector_first_usb() {
        let devices = vec![
            make_device("emulator-5554", DeviceState::Device),
            make_device("USB123", DeviceState::Device),
        ];
        let list = DeviceList::from_adb_devices(devices);
        let sel = DeviceSelector::FirstUsb;
        let resolved = sel.resolve(&list).unwrap();
        assert_eq!(resolved.serial(), "USB123");
    }

    // parse_devices_output

    #[test]
    fn test_parse_devices_output() {
        let output = "List of devices attached\n\
                      emulator-5554\tdevice product:sdk_gphone model:sdk_gphone device:generic transport_id:1\n\
                      R3CN90\toffline\n";
        let list = parse_devices_output(output);
        assert_eq!(list.len(), 2);
        assert_eq!(list.online().len(), 1);
    }

    #[test]
    fn test_parse_devices_output_empty() {
        let list = parse_devices_output("List of devices attached\n");
        assert!(list.is_empty());
    }

    // DeviceEvent Display

    #[test]
    fn test_device_event_display_connected() {
        let d = make_device("test123", DeviceState::Device);
        let info = DeviceInfo::from_device(d);
        let evt = DeviceEvent::Connected(info);
        assert!(evt.to_string().contains("test123"));
        assert!(evt.to_string().contains('['));
    }

    #[test]
    fn test_device_event_display_state_changed() {
        let evt = DeviceEvent::StateChanged {
            serial: "abc".into(),
            old_state: DeviceState::Unauthorized,
            new_state: DeviceState::Device,
        };
        let s = evt.to_string();
        assert!(s.contains("abc"));
        assert!(s.contains("unauthorized"));
        assert!(s.contains("device"));
    }

    #[test]
    fn test_device_event_display_disconnected() {
        let evt = DeviceEvent::Disconnected {
            serial: "gone123".into(),
        };
        assert!(evt.to_string().contains("gone123"));
    }
}
