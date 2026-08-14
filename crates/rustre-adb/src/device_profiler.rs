//! `device_profiler` — Profile an Android device over ADB.
//!
//! Gathers hardware info, battery state, running processes, storage,
//! screen state, and network interfaces from `getprop`, `dumpsys`, and `ps`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Lossy cast from `i32` to `f32` for display-only temperature math.
const fn i32_to_f32_lossy(n: i32) -> f32 {
    n as f32
}

// ─────────────────────────────────────────────────────────────────────────────
// BatteryState
// ─────────────────────────────────────────────────────────────────────────────

/// Battery charge status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChargeStatus {
    Unknown,
    Charging,
    Discharging,
    NotCharging,
    Full,
}

impl ChargeStatus {
    /// Parse a `status:` value from `dumpsys battery`.
    #[must_use]
    pub fn from_dumpsys(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "charging" | "2" => Self::Charging,
            "discharging" | "3" => Self::Discharging,
            "not charging" | "4" => Self::NotCharging,
            "full" | "5" => Self::Full,
            _ => Self::Unknown,
        }
    }
}

impl std::fmt::Display for ChargeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Unknown => "unknown",
            Self::Charging => "charging",
            Self::Discharging => "discharging",
            Self::NotCharging => "not charging",
            Self::Full => "full",
        };
        write!(f, "{s}")
    }
}

/// Battery health indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatteryHealth {
    Unknown,
    Good,
    Overheat,
    Dead,
    OverVoltage,
    UnspecifiedFailure,
    Cold,
}

impl BatteryHealth {
    #[must_use]
    pub fn from_dumpsys(s: &str) -> Self {
        match s.trim() {
            "2" | "good" => Self::Good,
            "3" | "overheat" => Self::Overheat,
            "4" | "dead" => Self::Dead,
            "5" | "over voltage" => Self::OverVoltage,
            "7" | "cold" => Self::Cold,
            _ => Self::Unknown,
        }
    }
}

/// Battery state snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatteryState {
    /// Charge level, 0–100.
    pub level: u8,
    /// Charge status.
    pub status: ChargeStatus,
    /// Battery health.
    pub health: BatteryHealth,
    /// Temperature in tenths of a degree Celsius.
    pub temperature: i32,
    /// Voltage in mV.
    pub voltage: u32,
    /// Whether AC power is connected.
    pub ac_powered: bool,
    /// Whether USB power is connected.
    pub usb_powered: bool,
    /// Whether wireless charging is connected.
    pub wireless_powered: bool,
    /// Battery technology string (e.g. "Li-ion").
    pub technology: String,
}

impl Default for BatteryState {
    fn default() -> Self {
        Self {
            level: 0,
            status: ChargeStatus::Unknown,
            health: BatteryHealth::Unknown,
            temperature: 0,
            voltage: 0,
            ac_powered: false,
            usb_powered: false,
            wireless_powered: false,
            technology: String::new(),
        }
    }
}

impl BatteryState {
    /// Parse `dumpsys battery` output.
    #[must_use]
    pub fn from_dumpsys(text: &str) -> Self {
        let mut b = Self::default();
        for line in text.lines() {
            let line = line.trim();
            if let Some(v) = strip_key(line, "level:") {
                b.level = v.parse().unwrap_or(0);
            } else if let Some(v) = strip_key(line, "status:") {
                b.status = ChargeStatus::from_dumpsys(v);
            } else if let Some(v) = strip_key(line, "health:") {
                b.health = BatteryHealth::from_dumpsys(v);
            } else if let Some(v) = strip_key(line, "temperature:") {
                b.temperature = v.parse().unwrap_or(0);
            } else if let Some(v) = strip_key(line, "voltage:") {
                b.voltage = v.parse().unwrap_or(0);
            } else if let Some(v) = strip_key(line, "AC powered:") {
                b.ac_powered = v == "true";
            } else if let Some(v) = strip_key(line, "USB powered:") {
                b.usb_powered = v == "true";
            } else if let Some(v) = strip_key(line, "Wireless powered:") {
                b.wireless_powered = v == "true";
            } else if let Some(v) = strip_key(line, "technology:") {
                v.clone_into(&mut b.technology);
            }
        }
        b
    }

    /// Temperature in degrees Celsius (float).
    #[must_use]
    pub fn temperature_celsius(&self) -> f32 {
        i32_to_f32_lossy(self.temperature) / 10.0
    }

    /// Returns `true` if the device is plugged in.
    #[must_use]
    pub const fn is_plugged(&self) -> bool {
        self.ac_powered || self.usb_powered || self.wireless_powered
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProcessInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Info about a running process on the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// User name that owns the process.
    pub user: String,
    /// Virtual size in bytes.
    pub vsz: u64,
    /// Resident set size in bytes.
    pub rss: u64,
    /// Process state character (S = sleeping, R = running, Z = zombie, …).
    pub state: char,
    /// Process name / command.
    pub name: String,
}

impl ProcessInfo {
    /// Parse a line from `ps -A` (Android-style).
    ///
    /// Format: `USER PID PPID VSIZE RSS WCHAN PC STATUS NAME`
    #[must_use]
    pub fn from_ps_line(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 8 {
            return None;
        }
        let user = parts[0].to_owned();
        let pid: u32 = parts[1].parse().ok()?;
        let parent_pid: u32 = parts[2].parse().ok()?;
        let vsz: u64 = parts[3].parse().unwrap_or(0);
        let rss: u64 = parts[4].parse().unwrap_or(0);
        let state = parts[7].chars().next().unwrap_or('?');
        let name = parts.last()?.to_string();
        Some(Self {
            pid,
            ppid: parent_pid,
            user,
            vsz,
            rss,
            state,
            name,
        })
    }

    /// Returns `true` if this process is a zombie.
    #[must_use]
    pub const fn is_zombie(&self) -> bool {
        self.state == 'Z'
    }

    /// Returns `true` if this is a system process (user starts with `system`).
    #[must_use]
    pub fn is_system(&self) -> bool {
        self.user.starts_with("system") || self.user == "root"
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeviceInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Hardware and software metadata for a connected Android device.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device serial number.
    pub serial: String,
    /// Device manufacturer.
    pub manufacturer: String,
    /// Device model.
    pub model: String,
    /// Product name (e.g. `"redfin"`).
    pub product: String,
    /// Android version string (e.g. `"13"`).
    pub android_version: String,
    /// SDK integer level (e.g. `33`).
    pub sdk_level: u32,
    /// CPU ABI (e.g. `"arm64-v8a"`).
    pub cpu_abi: String,
    /// Total RAM in kB.
    pub total_ram_kb: u64,
    /// Number of CPU cores.
    pub cpu_cores: u32,
    /// Screen density (dpi).
    pub screen_density: u32,
    /// Screen resolution string.
    pub screen_resolution: String,
    /// Current screen-on state.
    pub screen_on: bool,
    /// Build fingerprint.
    pub build_fingerprint: String,
    /// Security patch level string.
    pub security_patch: String,
    /// Whether the device is rooted (heuristic).
    pub is_rooted: bool,
    /// Kernel version string.
    pub kernel_version: String,
}

impl DeviceInfo {
    /// Populate fields from a `getprop` map.
    #[must_use]
    pub fn from_props(props: &HashMap<String, String>) -> Self {
        let get = |key: &str| props.get(key).cloned().unwrap_or_default();
        let sdk_level: u32 = get("ro.build.version.sdk").parse().unwrap_or(0);
        let cpu_cores: u32 = get("ro.product.cpu.cores").parse().unwrap_or(0);
        let screen_density: u32 = get("ro.sf.lcd_density").parse().unwrap_or(0);
        let total_ram_kb: u64 = get("ro.totalram").parse().unwrap_or(0);
        Self {
            serial: String::new(),
            manufacturer: get("ro.product.manufacturer"),
            model: get("ro.product.model"),
            product: get("ro.product.name"),
            android_version: get("ro.build.version.release"),
            sdk_level,
            cpu_abi: get("ro.product.cpu.abi"),
            total_ram_kb,
            cpu_cores,
            screen_density,
            screen_resolution: String::new(),
            screen_on: false,
            build_fingerprint: get("ro.build.fingerprint"),
            security_patch: get("ro.build.version.security_patch"),
            is_rooted: false,
            kernel_version: String::new(),
        }
    }

    /// Returns `true` if the device appears to be an emulator.
    #[must_use]
    pub fn is_emulator(&self) -> bool {
        self.product.contains("generic")
            || self.product.contains("sdk")
            || self.model.contains("Emulator")
            || self.model.contains("Android SDK")
            || self.build_fingerprint.contains("generic")
    }

    /// Human-readable device description.
    #[must_use]
    pub fn description(&self) -> String {
        format!(
            "{} {} (Android {}, SDK {}) — CPU: {} cores {}",
            self.manufacturer,
            self.model,
            self.android_version,
            self.sdk_level,
            self.cpu_cores,
            self.cpu_abi,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NetworkInterface
// ─────────────────────────────────────────────────────────────────────────────

/// A network interface on the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub mac_address: Option<String>,
    pub is_up: bool,
}

impl NetworkInterface {
    /// Parse `ip addr show` output into a list of interfaces.
    #[must_use]
    pub fn parse_ip_addr(output: &str) -> Vec<Self> {
        let mut ifaces: Vec<Self> = Vec::new();
        let mut current: Option<Self> = None;

        for line in output.lines() {
            let line = line.trim();
            // New interface block: `N: <name>: <flags>`
            if line.starts_with(|c: char| c.is_ascii_digit()) && line.contains(':') {
                if let Some(iface) = current.take() {
                    ifaces.push(iface);
                }
                let parts: Vec<&str> = line.splitn(3, ':').collect();
                if parts.len() >= 2 {
                    let name = parts[1].trim().to_owned();
                    let flags = parts.get(2).copied().unwrap_or("");
                    let is_up = flags.contains("UP");
                    current = Some(Self {
                        name,
                        ipv4_address: None,
                        ipv6_address: None,
                        mac_address: None,
                        is_up,
                    });
                }
            } else if let Some(ref mut iface) = current {
                if line.starts_with("inet ") && !line.starts_with("inet6") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(addr) = parts.get(1) {
                        iface.ipv4_address = Some(addr.to_string());
                    }
                } else if line.starts_with("inet6 ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(addr) = parts.get(1) {
                        iface.ipv6_address = Some(addr.to_string());
                    }
                } else if line.starts_with("link/ether") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(mac) = parts.get(1) {
                        iface.mac_address = Some(mac.to_string());
                    }
                }
            }
        }
        if let Some(iface) = current {
            ifaces.push(iface);
        }
        ifaces
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StorageInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Storage partition info parsed from `df`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageInfo {
    pub filesystem: String,
    pub total_kb: u64,
    pub used_kb: u64,
    pub available_kb: u64,
    pub use_percent: u8,
    pub mount_point: String,
}

impl StorageInfo {
    /// Parse `df` output into a list of [`StorageInfo`] records.
    #[must_use]
    pub fn parse_df(output: &str) -> Vec<Self> {
        let mut results = Vec::new();
        for line in output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }
            let filesystem = parts[0].to_owned();
            let total_kb: u64 = parse_kb_value(parts[1]);
            let used_kb: u64 = parse_kb_value(parts[2]);
            let available_kb: u64 = parse_kb_value(parts[3]);
            let use_percent: u8 = parts[4].trim_end_matches('%').parse().unwrap_or(0);
            let mount_point = parts[5].to_owned();
            results.push(Self {
                filesystem,
                total_kb,
                used_kb,
                available_kb,
                use_percent,
                mount_point,
            });
        }
        results
    }

    /// Returns `true` if the partition is more than 90% full.
    #[must_use]
    pub const fn is_nearly_full(&self) -> bool {
        self.use_percent >= 90
    }
}

fn parse_kb_value(s: &str) -> u64 {
    let s = s.trim_end_matches(|c: char| !c.is_ascii_digit());
    s.parse().unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// DeviceProfiler
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregates device profile data from multiple ADB shell commands.
#[derive(Debug, Default)]
pub struct DeviceProfiler {
    /// Last collected device info.
    pub device_info: DeviceInfo,
    /// Last collected battery state.
    pub battery: BatteryState,
    /// Last collected process list.
    pub processes: Vec<ProcessInfo>,
    /// Last collected network interfaces.
    pub network_interfaces: Vec<NetworkInterface>,
    /// Last collected storage info.
    pub storage: Vec<StorageInfo>,
    /// Raw `getprop` key-value pairs.
    pub properties: HashMap<String, String>,
}

impl DeviceProfiler {
    /// Create an empty profiler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate device info from a `getprop` output string.
    pub fn load_props_from_output(&mut self, getprop_output: &str) {
        self.properties = parse_getprop_output(getprop_output);
        self.device_info = DeviceInfo::from_props(&self.properties);
    }

    /// Populate battery state from `dumpsys battery` output.
    pub fn load_battery_from_output(&mut self, dumpsys_output: &str) {
        self.battery = BatteryState::from_dumpsys(dumpsys_output);
    }

    /// Populate processes from `ps -A` output.
    pub fn load_processes_from_output(&mut self, ps_output: &str) {
        self.processes = ps_output
            .lines()
            .skip(1) // header
            .filter_map(ProcessInfo::from_ps_line)
            .collect();
    }

    /// Populate network interfaces from `ip addr show` output.
    pub fn load_network_from_output(&mut self, ip_addr_output: &str) {
        self.network_interfaces = NetworkInterface::parse_ip_addr(ip_addr_output);
    }

    /// Populate storage from `df` output.
    pub fn load_storage_from_output(&mut self, df_output: &str) {
        self.storage = StorageInfo::parse_df(df_output);
    }

    /// Return processes belonging to the given user.
    #[must_use]
    pub fn processes_by_user(&self, user: &str) -> Vec<&ProcessInfo> {
        self.processes
            .iter()
            .filter(|p| p.user == user)
            .collect()
    }

    /// Return processes whose name contains `substr`.
    #[must_use]
    pub fn find_processes(&self, substr: &str) -> Vec<&ProcessInfo> {
        let lower = substr.to_ascii_lowercase();
        self.processes
            .iter()
            .filter(|p| p.name.to_ascii_lowercase().contains(&lower))
            .collect()
    }

    /// Return all zombie processes.
    #[must_use]
    pub fn zombie_processes(&self) -> Vec<&ProcessInfo> {
        self.processes.iter().filter(|p| p.is_zombie()).collect()
    }

    /// Return a compact JSON profile.
    ///
    /// # Errors
    ///
    /// Returns a serde error on serialisation failure.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let v = serde_json::json!({
            "device": &self.device_info,
            "battery": &self.battery,
            "process_count": self.processes.len(),
            "network_interface_count": self.network_interfaces.len(),
            "storage_partitions": self.storage.len(),
        });
        serde_json::to_string_pretty(&v)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn strip_key<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.strip_prefix(key).map(str::trim)
}

/// Parse `getprop` output: `[key]: [value]` lines.
#[must_use]
pub fn parse_getprop_output(output: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in output.lines() {
        let line = line.trim();
        if !line.starts_with('[') {
            continue;
        }
        if let Some(colon) = line.find("]: [") {
            let key = line[1..colon].to_owned();
            let val_start = colon + 4;
            let val = if line.ends_with(']') {
                line[val_start..line.len() - 1].to_owned()
            } else {
                line[val_start..].to_owned()
            };
            map.insert(key, val);
        }
    }
    map
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_battery_from_dumpsys() {
        let text = "\
Current Battery Service state:
  AC powered: false
  USB powered: true
  Wireless powered: false
  status: 2
  health: 2
  level: 85
  voltage: 4200
  temperature: 250
  technology: Li-ion
";
        let b = BatteryState::from_dumpsys(text);
        assert_eq!(b.level, 85);
        assert_eq!(b.status, ChargeStatus::Charging);
        assert_eq!(b.health, BatteryHealth::Good);
        assert_eq!(b.voltage, 4200);
        assert!((b.temperature_celsius() - 25.0).abs() < 0.01);
        assert!(b.usb_powered);
        assert!(!b.ac_powered);
        assert!(b.is_plugged());
    }

    #[test]
    fn test_battery_default_unknown() {
        let b = BatteryState::default();
        assert_eq!(b.status, ChargeStatus::Unknown);
        assert!(!b.is_plugged());
    }

    #[test]
    fn test_process_info_parse() {
        let line = "root 1 0 12345 678 fg 0000000 S init";
        let p = ProcessInfo::from_ps_line(line).unwrap();
        assert_eq!(p.pid, 1);
        assert_eq!(p.ppid, 0);
        assert_eq!(p.user, "root");
        assert_eq!(p.state, 'S');
        assert_eq!(p.name, "init");
    }

    #[test]
    fn test_process_info_zombie() {
        let line = "nobody 999 1 0 0 bg 0000 Z zombie_proc";
        let p = ProcessInfo::from_ps_line(line).unwrap();
        assert!(p.is_zombie());
    }

    #[test]
    fn test_process_info_short_line() {
        assert!(ProcessInfo::from_ps_line("root 1").is_none());
    }

    #[test]
    fn test_device_info_from_props() {
        let mut props = HashMap::new();
        props.insert("ro.product.manufacturer".to_string(), "Google".to_string());
        props.insert("ro.product.model".to_string(), "Pixel 7".to_string());
        props.insert("ro.build.version.release".to_string(), "13".to_string());
        props.insert("ro.build.version.sdk".to_string(), "33".to_string());
        props.insert("ro.product.cpu.abi".to_string(), "arm64-v8a".to_string());
        let info = DeviceInfo::from_props(&props);
        assert_eq!(info.manufacturer, "Google");
        assert_eq!(info.model, "Pixel 7");
        assert_eq!(info.sdk_level, 33);
        assert!(!info.is_emulator());
    }

    #[test]
    fn test_device_info_emulator_detection() {
        let mut props = HashMap::new();
        props.insert("ro.product.name".to_string(), "sdk_gphone64_x86_64".to_string());
        props.insert("ro.product.model".to_string(), "Android SDK Built for x86_64".to_string());
        let info = DeviceInfo::from_props(&props);
        assert!(info.is_emulator());
    }

    #[test]
    fn test_parse_getprop_output() {
        let output = "[ro.product.model]: [Pixel 7]\n[ro.build.version.sdk]: [33]\n";
        let map = parse_getprop_output(output);
        assert_eq!(map.get("ro.product.model").map(String::as_str), Some("Pixel 7"));
        assert_eq!(map.get("ro.build.version.sdk").map(String::as_str), Some("33"));
    }

    #[test]
    fn test_storage_info_parse() {
        let df = "\
Filesystem     1K-blocks    Used Available Use% Mounted on
/dev/block/dm-3  5120000 2560000   2560000  50% /system\n";
        let storage = StorageInfo::parse_df(df);
        assert_eq!(storage.len(), 1);
        assert_eq!(storage[0].use_percent, 50);
        assert_eq!(storage[0].mount_point, "/system");
        assert!(!storage[0].is_nearly_full());
    }

    #[test]
    fn test_storage_nearly_full() {
        let s = StorageInfo {
            filesystem: "/dev/sda1".to_string(),
            total_kb: 1000,
            used_kb: 950,
            available_kb: 50,
            use_percent: 95,
            mount_point: "/data".to_string(),
        };
        assert!(s.is_nearly_full());
    }

    #[test]
    fn test_network_interface_parse() {
        let ip_output = "\
1: lo: <LOOPBACK,UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: wlan0: <BROADCAST,MULTICAST,UP> mtu 1500
    link/ether 02:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.100/24 brd 192.168.1.255 scope global wlan0
";
        let ifaces = NetworkInterface::parse_ip_addr(ip_output);
        assert_eq!(ifaces.len(), 2);
        let lo = ifaces.iter().find(|i| i.name == "lo").unwrap();
        assert_eq!(lo.ipv4_address.as_deref(), Some("127.0.0.1/8"));
        let wlan = ifaces.iter().find(|i| i.name == "wlan0").unwrap();
        assert!(wlan.mac_address.is_some());
    }

    #[test]
    fn test_device_profiler_load_props() {
        let getprop = "[ro.product.model]: [Test Device]\n[ro.build.version.sdk]: [30]\n";
        let mut profiler = DeviceProfiler::new();
        profiler.load_props_from_output(getprop);
        assert_eq!(profiler.device_info.model, "Test Device");
        assert_eq!(profiler.device_info.sdk_level, 30);
    }

    #[test]
    fn test_device_profiler_load_processes() {
        let ps = "USER PID PPID VSIZE RSS WCHAN PC S NAME\nroot 1 0 100 50 fg 0 S init\n";
        let mut profiler = DeviceProfiler::new();
        profiler.load_processes_from_output(ps);
        assert!(!profiler.processes.is_empty());
    }

    #[test]
    fn test_device_profiler_find_processes() {
        let ps = "USER PID PPID VSIZE RSS WCHAN PC S NAME\nroot 1 0 100 50 fg 0 S com.example.app\n";
        let mut profiler = DeviceProfiler::new();
        profiler.load_processes_from_output(ps);
        let found = profiler.find_processes("example");
        assert!(!found.is_empty());
    }

    #[test]
    fn test_device_profiler_to_json() {
        let profiler = DeviceProfiler::new();
        let json = profiler.to_json().unwrap();
        assert!(json.contains("battery"));
        assert!(json.contains("device"));
    }

    #[test]
    fn test_charge_status_display() {
        assert_eq!(ChargeStatus::Charging.to_string(), "charging");
        assert_eq!(ChargeStatus::Full.to_string(), "full");
    }
}
