//! `android_shell` — High-level Android shell utilities built on top of ADB.
//!
//! Provides structured access to `pm list packages`, `ps`, logcat capture,
//! `getprop`, network info, storage info, and a fluent `ShellCommand` builder.

use std::collections::HashMap;
use std::fmt;
pub use std::str::FromStr;

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AndroidShellError {
    CommandFailed {
        cmd: String,
        exit_code: i32,
        stderr: String,
    },
    ParseError {
        context: String,
        raw: String,
    },
    DeviceNotConnected,
    PermissionDenied(String),
    Timeout(u64),
}

impl fmt::Display for AndroidShellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandFailed {
                cmd,
                exit_code,
                stderr,
            } => {
                write!(f, "command '{cmd}' failed (exit {exit_code}): {stderr}")
            }
            Self::ParseError { context, raw } => {
                write!(f, "parse error in '{context}': {raw:?}")
            }
            Self::DeviceNotConnected => write!(f, "no Android device connected"),
            Self::PermissionDenied(msg) => write!(f, "permission denied: {msg}"),
            Self::Timeout(ms) => write!(f, "command timed out after {ms}ms"),
        }
    }
}

impl std::error::Error for AndroidShellError {}

// ─── InstalledApp ────────────────────────────────────────────────────────────

/// Metadata about an installed Android application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledApp {
    /// Package name (e.g. "com.example.app").
    pub package: String,
    /// APK path on the device.
    pub apk_path: Option<String>,
    /// Version name (human-readable string).
    pub version_name: Option<String>,
    /// Version code (integer).
    pub version_code: Option<u64>,
    /// Whether it is a system app.
    pub is_system: bool,
    /// Whether it is a debuggable app.
    pub is_debuggable: bool,
    /// Declared permissions.
    pub permissions: Vec<String>,
    /// Target SDK version.
    pub target_sdk: Option<u32>,
    /// Minimum SDK version.
    pub min_sdk: Option<u32>,
    /// Data directory on device.
    pub data_dir: Option<String>,
    /// User ID owning the app.
    pub uid: Option<u32>,
}

impl InstalledApp {
    pub fn new(package: impl Into<String>) -> Self {
        Self {
            package: package.into(),
            apk_path: None,
            version_name: None,
            version_code: None,
            is_system: false,
            is_debuggable: false,
            permissions: Vec::new(),
            target_sdk: None,
            min_sdk: None,
            data_dir: None,
            uid: None,
        }
    }
}

// ─── PackageList ─────────────────────────────────────────────────────────────

/// Result of parsing `pm list packages` output.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PackageList {
    pub packages: Vec<String>,
}

impl PackageList {
    /// Parse output of `pm list packages` (or `-f` for paths).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn parse(output: &str) -> Result<Self, AndroidShellError> {
        let mut packages = Vec::new();
        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Format: "package:<pkg_name>" or "package:<apk_path>=<pkg_name>"
            if let Some(rest) = line.strip_prefix("package:") {
                let pkg = rest.find('=').map_or_else(
                    || rest.trim().to_string(),
                    |eq_pos| rest[eq_pos + 1..].trim().to_string(),
                );
                packages.push(pkg);
            }
        }
        Ok(Self { packages })
    }

    /// Filter packages matching a name fragment.
    #[must_use]
    pub fn filter(&self, fragment: &str) -> Vec<&str> {
        self.packages
            .iter()
            .filter(|p| p.contains(fragment))
            .map(std::string::String::as_str)
            .collect()
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.packages.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }
}

// ─── ProcessEntry ────────────────────────────────────────────────────────────

/// A single process from `ps` output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub user: String,
    pub pid: u32,
    pub ppid: u32,
    pub vsize: u64,
    pub rss: u64,
    pub name: String,
    pub state: char,
}

/// Result of parsing `ps` output.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProcessList {
    pub processes: Vec<ProcessEntry>,
}

impl ProcessList {
    /// Parse `ps -A` or `ps -ef` style output from Android.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn parse(output: &str) -> Result<Self, AndroidShellError> {
        let mut processes = Vec::new();
        let mut first_line = true;
        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if first_line {
                first_line = false;
                // Skip header.
                if line.starts_with("USER") || line.starts_with("UID") {
                    continue;
                }
            }
            // Android `ps` columns: USER PID PPID VSIZE RSS [WCHAN] [ADDR] S NAME
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }
            let pid = parts[1].parse::<u32>().unwrap_or(0);
            let parent_pid = parts[2].parse::<u32>().unwrap_or(0);
            let vsize = parts[3].parse::<u64>().unwrap_or(0);
            let rss = parts[4].parse::<u64>().unwrap_or(0);
            // State is usually the last one-char field before the name.
            let state_char = parts
                .get(parts.len().saturating_sub(2))
                .and_then(|s| s.chars().next())
                .unwrap_or('?');
            let name = parts.last().copied().unwrap_or("?").to_string();
            processes.push(ProcessEntry {
                user: parts[0].to_string(),
                pid,
                ppid: parent_pid,
                vsize,
                rss,
                name,
                state: state_char,
            });
        }
        Ok(Self { processes })
    }

    /// Find processes by name (substring match).
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Vec<&ProcessEntry> {
        self.processes
            .iter()
            .filter(|p| p.name.contains(name))
            .collect()
    }

    /// Find process by exact PID.
    #[must_use]
    pub fn find_by_pid(&self, pid: u32) -> Option<&ProcessEntry> {
        self.processes.iter().find(|p| p.pid == pid)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.processes.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.processes.is_empty()
    }
}

// ─── LogcatEntry ─────────────────────────────────────────────────────────────

/// Log level for a logcat entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LogLevel {
    Verbose,
    Debug,
    Info,
    Warning,
    Error,
    Fatal,
    Silent,
}

impl LogLevel {
    #[must_use]
    pub const fn from_char(c: char) -> Self {
        match c {
            // 'V' was reaching `Verbose` only through the catch-all, which hid
            // the fact that the same arm also swallows every unknown character.
            'V' => Self::Verbose,
            'D' => Self::Debug,
            'I' => Self::Info,
            'W' => Self::Warning,
            'E' => Self::Error,
            'F' => Self::Fatal,
            'S' => Self::Silent,
            // NOTE: an unrecognised character still becomes `Verbose` — the
            // enum has no `Unknown` variant and this fn is total. The twin in
            // `lib.rs` picks `Info` for the same case, so the two disagree.
            _ => Self::Verbose,
        }
    }

    #[must_use]
    pub const fn as_char(self) -> char {
        match self {
            Self::Verbose => 'V',
            Self::Debug => 'D',
            Self::Info => 'I',
            Self::Warning => 'W',
            Self::Error => 'E',
            Self::Fatal => 'F',
            Self::Silent => 'S',
        }
    }
}

/// A single line from logcat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogcatEntry {
    pub timestamp: String,
    pub pid: u32,
    pub tid: u32,
    pub level: LogLevel,
    pub tag: String,
    pub message: String,
}

/// Accumulated logcat output with filtering capabilities.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LogcatCapture {
    pub entries: Vec<LogcatEntry>,
}

impl LogcatCapture {
    /// Parse threadtime format: `MM-DD HH:MM:SS.mmm  PID  TID LEVEL TAG: message`
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn parse_threadtime(output: &str) -> Result<Self, AndroidShellError> {
        let mut entries = Vec::new();
        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("-----") {
                continue;
            }
            // Minimal parser — split on whitespace, handling multiple spaces.
            // Format: MM-DD HH:MM:SS.mmm  PID  TID LEVEL TAG: message
            let mut sw = line.split_ascii_whitespace();
            let date = match sw.next() { Some(v) => v, None => continue };
            let time = match sw.next() { Some(v) => v, None => continue };
            let pid_str = match sw.next() { Some(v) => v, None => continue };
            let tid_str = match sw.next() { Some(v) => v, None => continue };
            let level_str = match sw.next() { Some(v) => v, None => continue };
            // Find where level_str ends in the original line and take the remainder.
            let level_end = level_str.as_ptr() as usize + level_str.len()
                - line.as_ptr() as usize;
            let rest = line[level_end..].trim_start();
            if rest.is_empty() { continue; }
            let timestamp = format!("{} {}", date, time);
            let pid = pid_str.parse::<u32>().unwrap_or(0);
            let tid = tid_str.parse::<u32>().unwrap_or(0);
            let level = LogLevel::from_char(level_str.chars().next().unwrap_or('V'));
            let (tag, message) = rest
                .find(": ")
                .map_or((rest, ""), |colon| (&rest[..colon], &rest[colon + 2..]));
            entries.push(LogcatEntry {
                timestamp,
                pid,
                tid,
                level,
                tag: tag.trim().to_string(),
                message: message.to_string(),
            });
        }
        Ok(Self { entries })
    }

    /// Filter entries by minimum log level.
    #[must_use]
    pub fn filter_level(&self, min: LogLevel) -> Vec<&LogcatEntry> {
        self.entries.iter().filter(|e| e.level >= min).collect()
    }

    /// Filter entries by tag (exact match).
    #[must_use]
    pub fn filter_tag(&self, tag: &str) -> Vec<&LogcatEntry> {
        self.entries.iter().filter(|e| e.tag == tag).collect()
    }

    /// Filter entries whose message contains the given substring.
    #[must_use]
    pub fn search_message(&self, needle: &str) -> Vec<&LogcatEntry> {
        self.entries
            .iter()
            .filter(|e| e.message.contains(needle))
            .collect()
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─── PropertyReader ──────────────────────────────────────────────────────────

/// Parsed Android system properties from `getprop`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PropertyReader {
    pub props: HashMap<String, String>,
}

impl PropertyReader {
    /// Parse output of `getprop` (format: `[key]: [value]`).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn parse(output: &str) -> Result<Self, AndroidShellError> {
        let mut props = HashMap::new();
        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Format: [ro.build.version.sdk]: [33]
            if let (Some(k_start), Some(k_end)) = (line.find('['), line.find("]: [")) {
                let key = &line[k_start + 1..k_end];
                let val_start = k_end + 4;
                let val_end = line.rfind(']').unwrap_or(line.len());
                let val = &line[val_start..val_end];
                props.insert(key.to_string(), val.to_string());
            }
        }
        Ok(Self { props })
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.props.get(key).map(std::string::String::as_str)
    }

    #[must_use]
    pub fn android_version(&self) -> Option<&str> {
        self.get("ro.build.version.release")
    }

    #[must_use]
    pub fn sdk_version(&self) -> Option<u32> {
        self.get("ro.build.version.sdk")
            .and_then(|v| v.parse().ok())
    }

    #[must_use]
    pub fn device_model(&self) -> Option<&str> {
        self.get("ro.product.model")
    }

    #[must_use]
    pub fn manufacturer(&self) -> Option<&str> {
        self.get("ro.product.manufacturer")
    }

    #[must_use]
    pub fn build_fingerprint(&self) -> Option<&str> {
        self.get("ro.build.fingerprint")
    }

    #[must_use]
    pub fn is_rooted(&self) -> bool {
        self.get("ro.debuggable") == Some("1")
    }
}

// ─── NetworkInfo ─────────────────────────────────────────────────────────────

/// A single network interface parsed from `ip addr` or `ifconfig`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub mac: Option<String>,
    pub is_up: bool,
}

/// Parsed network information.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub interfaces: Vec<NetworkInterface>,
}

impl NetworkInfo {
    /// Parse `ip addr show` output (simplified).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn parse_ip_addr(output: &str) -> Result<Self, AndroidShellError> {
        let mut interfaces = Vec::new();
        let mut current: Option<NetworkInterface> = None;

        for line in output.lines() {
            let line = line.trim();
            // Interface line: "2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> ..."
            if line.starts_with(|c: char| c.is_ascii_digit()) {
                if let Some(iface) = current.take() {
                    interfaces.push(iface);
                }
                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                if parts.len() >= 2 {
                    let name = parts[1].trim_end_matches(':').to_string();
                    let is_up = line.contains("UP");
                    current = Some(NetworkInterface {
                        name,
                        ipv4: None,
                        ipv6: None,
                        mac: None,
                        is_up,
                    });
                }
            } else if let Some(ref mut iface) = current {
                if line.starts_with("inet ")
                    && let Some(addr) = line.split_whitespace().nth(1)
                {
                    // Strip prefix length (/24).
                    let ip = addr.split('/').next().unwrap_or(addr);
                    iface.ipv4 = Some(ip.to_string());
                } else if line.starts_with("inet6 ")
                    && let Some(addr) = line.split_whitespace().nth(1)
                {
                    iface.ipv6 = Some(addr.to_string());
                } else if line.starts_with("link/ether ")
                    && let Some(mac) = line.split_whitespace().nth(1)
                {
                    iface.mac = Some(mac.to_string());
                }
            }
        }
        if let Some(iface) = current {
            interfaces.push(iface);
        }
        Ok(Self { interfaces })
    }

    #[must_use]
    pub fn find_interface(&self, name: &str) -> Option<&NetworkInterface> {
        self.interfaces.iter().find(|i| i.name == name)
    }

    #[must_use]
    pub fn up_interfaces(&self) -> Vec<&NetworkInterface> {
        self.interfaces.iter().filter(|i| i.is_up).collect()
    }
}

// ─── StorageInfo ─────────────────────────────────────────────────────────────

/// A single filesystem entry from `df`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemEntry {
    pub filesystem: String,
    pub size_kb: u64,
    pub used_kb: u64,
    pub available_kb: u64,
    pub use_percent: u8,
    pub mount_point: String,
}

impl FilesystemEntry {
    #[must_use]
    pub const fn free_percent(&self) -> u8 {
        100u8.saturating_sub(self.use_percent)
    }
}

/// Parsed storage information from `df`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StorageInfo {
    pub entries: Vec<FilesystemEntry>,
}

impl StorageInfo {
    /// Parse `df -k` output.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn parse(output: &str) -> Result<Self, AndroidShellError> {
        let mut entries = Vec::new();
        let mut first = true;
        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if first {
                first = false;
                if line.starts_with("Filesystem") {
                    continue;
                }
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }
            let size_kb = parts[1].trim_end_matches('K').parse::<u64>().unwrap_or(0);
            let used_kb = parts[2].trim_end_matches('K').parse::<u64>().unwrap_or(0);
            let available_kb = parts[3].trim_end_matches('K').parse::<u64>().unwrap_or(0);
            let use_str = parts[4].trim_end_matches('%');
            let use_percent = use_str.parse::<u8>().unwrap_or(0);
            entries.push(FilesystemEntry {
                filesystem: parts[0].to_string(),
                size_kb,
                used_kb,
                available_kb,
                use_percent,
                mount_point: parts[5].to_string(),
            });
        }
        Ok(Self { entries })
    }

    #[must_use]
    pub fn find_mount(&self, mount: &str) -> Option<&FilesystemEntry> {
        self.entries.iter().find(|e| e.mount_point == mount)
    }

    #[must_use]
    pub fn total_used_kb(&self) -> u64 {
        self.entries.iter().map(|e| e.used_kb).sum()
    }
}

// ─── ShellCommand ─────────────────────────────────────────────────────────────

/// A builder for Android shell commands.
#[derive(Debug, Clone)]
pub struct ShellCommand {
    program: String,
    args: Vec<String>,
    as_root: bool,
    timeout_ms: Option<u64>,
    env: HashMap<String, String>,
}

impl ShellCommand {
    /// Start building a command.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            as_root: false,
            timeout_ms: None,
            env: HashMap::new(),
        }
    }

    /// Add an argument.
    #[must_use]
    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    /// Add multiple arguments.
    #[must_use]
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args
            .extend(args.into_iter().map(std::convert::Into::into));
        self
    }

    /// Run the command as root via `su`.
    #[must_use]
    pub const fn as_root(mut self) -> Self {
        self.as_root = true;
        self
    }

    /// Set a timeout.
    #[must_use]
    pub const fn timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = Some(ms);
        self
    }

    /// Set an environment variable.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.env.insert(key.into(), val.into());
        self
    }

    /// Render the full command string (suitable for `adb shell`).
    #[must_use]
    pub fn render(&self) -> String {
        let mut parts = Vec::new();
        if self.as_root {
            parts.push("su -c".to_string());
        }
        parts.push(shell_escape(&self.program));
        for a in &self.args {
            parts.push(shell_escape(a));
        }
        parts.join(" ")
    }

    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    #[must_use]
    pub fn args_slice(&self) -> &[String] {
        &self.args
    }

    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.as_root
    }
}

/// Shell-escape a string for use in `adb shell`.
#[must_use]
pub fn shell_escape(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_alphanumeric() || "._/-=".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

// ─── AndroidShell ────────────────────────────────────────────────────────────

/// High-level Android shell helper (command factory + parsers).
///
/// Note: This is a logic/parsing layer. Actual execution goes via the ADB
/// `ShellSession` in the `shell` module.
pub struct AndroidShell;

impl AndroidShell {
    /// Build the command to list packages.
    #[must_use]
    pub fn list_packages_cmd(system_only: bool, third_party_only: bool) -> ShellCommand {
        let mut cmd = ShellCommand::new("pm").arg("list").arg("packages");
        if system_only {
            cmd = cmd.arg("-s");
        } else if third_party_only {
            cmd = cmd.arg("-3");
        }
        cmd
    }

    /// Build the command to list running processes.
    #[must_use]
    pub fn list_processes_cmd() -> ShellCommand {
        ShellCommand::new("ps").arg("-A")
    }

    /// Build the command to read a system property.
    #[must_use]
    pub fn getprop_cmd(key: Option<&str>) -> ShellCommand {
        let mut cmd = ShellCommand::new("getprop");
        if let Some(k) = key {
            cmd = cmd.arg(k);
        }
        cmd
    }

    /// Build the command to capture logcat.
    #[must_use]
    pub fn logcat_cmd(tag_filter: Option<&str>, level: Option<LogLevel>) -> ShellCommand {
        let mut cmd = ShellCommand::new("logcat")
            .arg("-d")
            .arg("-v")
            .arg("threadtime");
        if let Some(tag) = tag_filter {
            let level_char = level.unwrap_or(LogLevel::Verbose).as_char();
            cmd = cmd.arg(format!("{tag}:{level_char}"));
        }
        cmd
    }

    /// Build `ip addr show` command.
    #[must_use]
    pub fn network_cmd() -> ShellCommand {
        ShellCommand::new("ip").arg("addr").arg("show")
    }

    /// Build `df -k` command.
    #[must_use]
    pub fn storage_cmd() -> ShellCommand {
        ShellCommand::new("df").arg("-k")
    }

    /// Build command to dump APK info via `dumpsys`.
    #[must_use]
    pub fn dumpsys_package_cmd(package: &str) -> ShellCommand {
        ShellCommand::new("dumpsys").arg("package").arg(package)
    }

    /// Build command to start an activity.
    #[must_use]
    pub fn start_activity_cmd(package: &str, activity: &str) -> ShellCommand {
        ShellCommand::new("am")
            .arg("start")
            .arg("-n")
            .arg(format!("{package}/{activity}"))
    }

    /// Build command to force-stop a package.
    #[must_use]
    pub fn force_stop_cmd(package: &str) -> ShellCommand {
        ShellCommand::new("am").arg("force-stop").arg(package)
    }

    /// Build command to clear application data.
    #[must_use]
    pub fn clear_data_cmd(package: &str) -> ShellCommand {
        ShellCommand::new("pm").arg("clear").arg(package)
    }

    /// Build a `cat` command for a file.
    #[must_use]
    pub fn cat_cmd(path: &str) -> ShellCommand {
        ShellCommand::new("cat").arg(path)
    }

    /// Build a `chmod` command.
    #[must_use]
    pub fn chmod_cmd(mode: &str, path: &str) -> ShellCommand {
        ShellCommand::new("chmod").arg(mode).arg(path)
    }

    /// Parse package list output.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn parse_packages(output: &str) -> Result<PackageList, AndroidShellError> {
        PackageList::parse(output)
    }

    /// Parse process list output.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn parse_processes(output: &str) -> Result<ProcessList, AndroidShellError> {
        ProcessList::parse(output)
    }

    /// Parse logcat output.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn parse_logcat(output: &str) -> Result<LogcatCapture, AndroidShellError> {
        LogcatCapture::parse_threadtime(output)
    }

    /// Parse getprop output.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn parse_properties(output: &str) -> Result<PropertyReader, AndroidShellError> {
        PropertyReader::parse(output)
    }

    /// Parse ip addr output.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn parse_network(output: &str) -> Result<NetworkInfo, AndroidShellError> {
        NetworkInfo::parse_ip_addr(output)
    }

    /// Parse df output.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn parse_storage(output: &str) -> Result<StorageInfo, AndroidShellError> {
        StorageInfo::parse(output)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const PM_OUTPUT: &str = "\
package:com.android.settings
package:com.google.android.gms
package:com.example.app
";

    const PM_OUTPUT_WITH_PATH: &str = "\
package:/system/app/Settings.apk=com.android.settings
package:/data/app/com.example.app.apk=com.example.app
";

    const PS_OUTPUT: &str = "\
USER       PID  PPID     VSIZE    RSS WCHAN            ADDR S NAME
root         1     0     2992    672 0                 0 S /init
u0_a100   1234   567   120000  30000 0                 0 S com.example.app
system     456   123    50000  10000 0                 0 R system_server
";

    const GETPROP_OUTPUT: &str = "\
[ro.build.version.sdk]: [33]
[ro.build.version.release]: [13]
[ro.product.model]: [Pixel 7]
[ro.product.manufacturer]: [Google]
[ro.debuggable]: [0]
";

    const LOGCAT_OUTPUT: &str = "\
06-01 12:00:00.000  1234  5678 I ActivityManager: START u0 {act=android.intent.action.MAIN}
06-01 12:00:01.000  1234  5679 E ExampleApp: NullPointerException at MainActivity.java:42
06-01 12:00:02.000   456   789 W System: some warning message
";

    const DF_OUTPUT: &str = "\
Filesystem           1K-blocks    Used Available Use% Mounted on
/dev/block/dm-0       5242880 3145728   2097152  60% /system
/data                52428800 26214400  26214400  50% /data
";

    const IP_ADDR_OUTPUT: &str = "\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.100/24 brd 192.168.1.255 scope global wlan0
    inet6 fe80::1/64 scope link
";

    #[test]
    fn parse_package_list_basic() {
        let list = PackageList::parse(PM_OUTPUT).unwrap();
        assert_eq!(list.len(), 3);
        assert!(list.packages.contains(&"com.android.settings".to_string()));
        assert!(list.packages.contains(&"com.example.app".to_string()));
    }

    #[test]
    fn parse_package_list_with_paths() {
        let list = PackageList::parse(PM_OUTPUT_WITH_PATH).unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.packages.contains(&"com.android.settings".to_string()));
    }

    #[test]
    fn package_list_filter() {
        let list = PackageList::parse(PM_OUTPUT).unwrap();
        let filtered = list.filter("google");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], "com.google.android.gms");
    }

    #[test]
    fn package_list_empty() {
        let list = PackageList::parse("").unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn parse_process_list() {
        let procs = ProcessList::parse(PS_OUTPUT).unwrap();
        assert!(!procs.is_empty());
    }

    #[test]
    fn process_list_find_by_name() {
        let procs = ProcessList::parse(PS_OUTPUT).unwrap();
        let found = procs.find_by_name("com.example.app");
        assert!(!found.is_empty());
        assert_eq!(found[0].pid, 1234);
    }

    #[test]
    fn process_list_find_by_pid() {
        let procs = ProcessList::parse(PS_OUTPUT).unwrap();
        let proc = procs.find_by_pid(456);
        assert!(proc.is_some());
        assert_eq!(proc.unwrap().name, "system_server");
    }

    #[test]
    fn parse_getprop() {
        let props = PropertyReader::parse(GETPROP_OUTPUT).unwrap();
        assert_eq!(props.sdk_version(), Some(33));
        assert_eq!(props.android_version(), Some("13"));
        assert_eq!(props.device_model(), Some("Pixel 7"));
        assert_eq!(props.manufacturer(), Some("Google"));
        assert!(!props.is_rooted());
    }

    #[test]
    fn parse_logcat() {
        let capture = LogcatCapture::parse_threadtime(LOGCAT_OUTPUT).unwrap();
        assert_eq!(capture.len(), 3);
    }

    #[test]
    fn logcat_filter_level() {
        let capture = LogcatCapture::parse_threadtime(LOGCAT_OUTPUT).unwrap();
        let errors = capture.filter_level(LogLevel::Error);
        assert!(!errors.is_empty());
        for e in &errors {
            assert!(e.level >= LogLevel::Error);
        }
    }

    #[test]
    fn logcat_filter_tag() {
        let capture = LogcatCapture::parse_threadtime(LOGCAT_OUTPUT).unwrap();
        let tagged = capture.filter_tag("ExampleApp");
        assert!(!tagged.is_empty());
    }

    #[test]
    fn logcat_search_message() {
        let capture = LogcatCapture::parse_threadtime(LOGCAT_OUTPUT).unwrap();
        let found = capture.search_message("NullPointer");
        assert!(!found.is_empty());
    }

    #[test]
    fn parse_storage_info() {
        let info = StorageInfo::parse(DF_OUTPUT).unwrap();
        assert_eq!(info.entries.len(), 2);
        let data = info.find_mount("/data").unwrap();
        assert_eq!(data.use_percent, 50);
    }

    #[test]
    fn storage_info_total_used() {
        let info = StorageInfo::parse(DF_OUTPUT).unwrap();
        assert!(info.total_used_kb() > 0);
    }

    #[test]
    fn parse_network_info() {
        let net = NetworkInfo::parse_ip_addr(IP_ADDR_OUTPUT).unwrap();
        assert!(!net.interfaces.is_empty());
    }

    #[test]
    fn network_info_wlan0() {
        let net = NetworkInfo::parse_ip_addr(IP_ADDR_OUTPUT).unwrap();
        let wlan = net.find_interface("wlan0");
        assert!(wlan.is_some());
        assert!(wlan.unwrap().is_up);
    }

    #[test]
    fn network_info_up_interfaces() {
        let net = NetworkInfo::parse_ip_addr(IP_ADDR_OUTPUT).unwrap();
        let up = net.up_interfaces();
        assert!(!up.is_empty());
    }

    #[test]
    fn shell_command_render_simple() {
        let cmd = ShellCommand::new("ls").arg("/data/local/tmp");
        let rendered = cmd.render();
        assert!(rendered.contains("ls"));
        assert!(rendered.contains("/data/local/tmp"));
    }

    #[test]
    fn shell_command_render_as_root() {
        let cmd = ShellCommand::new("cat").arg("/proc/1/maps").as_root();
        let rendered = cmd.render();
        assert!(rendered.starts_with("su -c"));
    }

    #[test]
    fn shell_command_with_spaces_escaped() {
        let cmd = ShellCommand::new("echo").arg("hello world");
        let rendered = cmd.render();
        assert!(rendered.contains('\''));
    }

    #[test]
    fn shell_escape_simple() {
        assert_eq!(shell_escape("ls"), "ls");
        assert_eq!(shell_escape("/data/local/tmp"), "/data/local/tmp");
    }

    #[test]
    fn shell_escape_with_spaces() {
        let escaped = shell_escape("hello world");
        assert!(escaped.starts_with('\''));
        assert!(escaped.ends_with('\''));
    }

    #[test]
    fn android_shell_list_packages_cmd() {
        let cmd = AndroidShell::list_packages_cmd(false, true);
        assert!(cmd.args_slice().contains(&"-3".to_string()));
    }

    #[test]
    fn android_shell_list_processes_cmd() {
        let cmd = AndroidShell::list_processes_cmd();
        assert_eq!(cmd.program(), "ps");
    }

    #[test]
    fn android_shell_logcat_cmd_with_filter() {
        let cmd = AndroidShell::logcat_cmd(Some("MyApp"), Some(LogLevel::Error));
        let rendered = cmd.render();
        assert!(rendered.contains("MyApp"));
    }

    #[test]
    fn log_level_from_char() {
        assert_eq!(LogLevel::from_char('E'), LogLevel::Error);
        assert_eq!(LogLevel::from_char('V'), LogLevel::Verbose);
    }

    #[test]
    fn log_level_as_char() {
        assert_eq!(LogLevel::Warning.as_char(), 'W');
        assert_eq!(LogLevel::Info.as_char(), 'I');
    }

    #[test]
    fn log_level_ordering() {
        assert!(LogLevel::Error > LogLevel::Warning);
        assert!(LogLevel::Warning > LogLevel::Info);
        assert!(LogLevel::Info > LogLevel::Debug);
    }

    #[test]
    fn filesystem_entry_free_percent() {
        let entry = FilesystemEntry {
            filesystem: "/dev/sda".into(),
            size_kb: 10000,
            used_kb: 6000,
            available_kb: 4000,
            use_percent: 60,
            mount_point: "/".into(),
        };
        assert_eq!(entry.free_percent(), 40);
    }

    #[test]
    fn android_shell_error_display() {
        let e = AndroidShellError::Timeout(5000);
        assert!(e.to_string().contains("5000ms"));
    }

    #[test]
    fn installed_app_new() {
        let app = InstalledApp::new("com.test.app");
        assert_eq!(app.package, "com.test.app");
        assert!(!app.is_system);
        assert!(app.permissions.is_empty());
    }
}
