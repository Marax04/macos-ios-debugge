//! ADB shell command execution.
//!
//! Provides streaming execution of shell commands over an ADB connection,
//! including timeout handling, return code detection, and pm/am wrappers.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ShellError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("command timed out after {0:?}")]
    Timeout(Duration),
    #[error("device disconnected during execution")]
    Disconnected,
    #[error("command failed with exit code {0}")]
    ExitCode(i32),
    #[error("invalid output encoding")]
    Encoding,
    #[error("adb protocol error: {0}")]
    Protocol(String),
}

pub type ShellResult<T> = Result<T, ShellError>;

// ─── Shell Output ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub elapsed: Duration,
    pub truncated: bool,
}

impl ShellOutput {
    #[must_use]
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).to_string()
    }

    #[must_use]
    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).to_string()
    }

    #[must_use]
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }

    #[must_use]
    pub fn combined_output(&self) -> String {
        let mut out = self.stdout_str();
        if !self.stderr.is_empty() {
            out.push_str(&self.stderr_str());
        }
        out
    }
}

impl fmt::Display for ShellOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.stdout_str())
    }
}

// ─── Shell Executor Config ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellConfig {
    /// Maximum time to wait for a command.
    pub timeout: Duration,
    /// Maximum bytes of output to capture (0 = unlimited).
    pub max_output_bytes: usize,
    /// Use shell v2 protocol (separate stdout/stderr + exit code).
    pub shell_v2: bool,
    /// Whether to strip trailing newlines from output.
    pub trim_output: bool,
    /// Environment variables to set before running the command.
    pub env: HashMap<String, String>,
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_output_bytes: 4 * 1024 * 1024,
            shell_v2: true,
            trim_output: false,
            env: HashMap::new(),
        }
    }
}

impl ShellConfig {
    #[must_use]
    pub const fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    #[must_use]
    pub const fn with_max_output(mut self, n: usize) -> Self {
        self.max_output_bytes = n;
        self
    }

    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.env.insert(key.into(), val.into());
        self
    }
}

// ─── Shell V2 Message Types ───────────────────────────────────────────────────

/// Shell v2 stdin/stdout/stderr multiplexing over a single ADB stream.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellV2MessageType {
    Stdin = 0,
    Stdout = 1,
    Stderr = 2,
    ExitCode = 3,
    CloseStdin = 4,
    WindowSizeChange = 5,
    Invalid = 255,
}

impl ShellV2MessageType {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Stdin,
            1 => Self::Stdout,
            2 => Self::Stderr,
            3 => Self::ExitCode,
            4 => Self::CloseStdin,
            5 => Self::WindowSizeChange,
            _ => Self::Invalid,
        }
    }
}

/// A single shell v2 frame: 1-byte type + 4-byte LE length + payload.
#[derive(Debug, Clone)]
pub struct ShellV2Frame {
    pub msg_type: ShellV2MessageType,
    pub data: Vec<u8>,
}

/// Truncating cast `usize` → `u32`.
fn len_to_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

impl ShellV2Frame {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + self.data.len());
        out.push(self.msg_type as u8);
        let len = len_to_u32(self.data.len());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    #[must_use]
    pub fn decode_from(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 5 {
            return None;
        }
        let msg_type = ShellV2MessageType::from_byte(buf[0]);
        let len = u32::from_le_bytes(buf[1..5].try_into().ok()?) as usize;
        if buf.len() < 5 + len {
            return None;
        }
        let data = buf[5..5 + len].to_vec();
        Some((Self { msg_type, data }, 5 + len))
    }
}

// ─── Shell V2 Parser ─────────────────────────────────────────────────────────

/// Parses a complete shell v2 byte stream into stdout/stderr/`exit_code`.
#[must_use]
pub fn parse_shell_v2_output(raw: &[u8], max_bytes: usize) -> ShellOutput {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code: Option<i32> = None;
    let mut truncated = false;
    let mut pos = 0;

    while pos < raw.len() {
        match ShellV2Frame::decode_from(&raw[pos..]) {
            None => break,
            Some((frame, consumed)) => {
                pos += consumed;
                match frame.msg_type {
                    ShellV2MessageType::Stdout => {
                        if max_bytes == 0 || stdout.len() < max_bytes {
                            stdout.extend_from_slice(&frame.data);
                            if max_bytes > 0 && stdout.len() >= max_bytes {
                                truncated = true;
                            }
                        }
                    }
                    ShellV2MessageType::Stderr => {
                        if max_bytes == 0 || stderr.len() < max_bytes {
                            stderr.extend_from_slice(&frame.data);
                        }
                    }
                    ShellV2MessageType::ExitCode => {
                        if !frame.data.is_empty() {
                            exit_code = Some(i32::from(frame.data[0]));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    ShellOutput {
        stdout,
        stderr,
        exit_code,
        elapsed: Duration::ZERO,
        truncated,
    }
}

// ─── Shell Executor ──────────────────────────────────────────────────────────

/// In-memory shell executor that processes pre-captured raw output.
/// In a real deployment this would drive an `AdbConnection`.
pub struct ShellExecutor {
    pub config: ShellConfig,
    pub device_serial: String,
}

impl ShellExecutor {
    pub fn new(serial: impl Into<String>) -> Self {
        Self { config: ShellConfig::default(), device_serial: serial.into() }
    }

    #[must_use]
    pub fn with_config(mut self, cfg: ShellConfig) -> Self {
        self.config = cfg;
        self
    }

    /// Build the shell command string, prepending any env overrides.
    #[must_use]
    pub fn build_command(&self, cmd: &str) -> String {
        if self.config.env.is_empty() {
            return cmd.to_string();
        }
        let env_prefix: String = self
            .config
            .env
            .iter()
            .map(|(k, v)| format!("{k}={}", shell_quote(v)))
            .collect::<Vec<_>>()
            .join(" ");
        format!("{env_prefix} {cmd}")
    }

    /// Process a raw output buffer (as would be received from ADB).
    #[must_use]
    pub fn process_output(&self, raw: &[u8], elapsed: Duration) -> ShellOutput {
        let mut out = if self.config.shell_v2 {
            parse_shell_v2_output(raw, self.config.max_output_bytes)
        } else {
            // Legacy shell: no framing.
            let mut stdout = raw.to_vec();
            if self.config.max_output_bytes > 0 && stdout.len() > self.config.max_output_bytes {
                stdout.truncate(self.config.max_output_bytes);
            }
            ShellOutput {
                stdout,
                stderr: Vec::new(),
                exit_code: None,
                elapsed,
                truncated: false,
            }
        };

        if self.config.trim_output {
            while out.stdout.last() == Some(&b'\n') || out.stdout.last() == Some(&b'\r') {
                out.stdout.pop();
            }
        }
        out.elapsed = elapsed;
        out
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ─── Package Manager Commands ─────────────────────────────────────────────────

/// Android `pm` (package manager) command builder.
pub struct PmCommand;

impl PmCommand {
    #[must_use]
    pub fn list_packages(flags: &[&str]) -> String {
        format!("pm list packages {}", flags.join(" "))
    }

    #[must_use]
    pub fn install(path: &str, flags: &[&str]) -> String {
        format!("pm install {} {}", flags.join(" "), crate::shell::shell_escape(path))
    }

    #[must_use]
    pub fn uninstall(package: &str, keep_data: bool) -> String {
        if keep_data {
            format!("pm uninstall -k {}", crate::shell::shell_escape(package))
        } else {
            format!("pm uninstall {}", crate::shell::shell_escape(package))
        }
    }

    #[must_use]
    pub fn clear(package: &str) -> String {
        format!("pm clear {}", crate::shell::shell_escape(package))
    }

    #[must_use]
    pub fn enable(package: &str) -> String {
        format!("pm enable {}", crate::shell::shell_escape(package))
    }

    #[must_use]
    pub fn disable(package: &str) -> String {
        format!("pm disable-user --user 0 {}", crate::shell::shell_escape(package))
    }

    #[must_use]
    pub fn grant(package: &str, permission: &str) -> String {
        format!(
            "pm grant {} {}",
            crate::shell::shell_escape(package),
            crate::shell::shell_escape(permission)
        )
    }

    #[must_use]
    pub fn revoke(package: &str, permission: &str) -> String {
        format!(
            "pm revoke {} {}",
            crate::shell::shell_escape(package),
            crate::shell::shell_escape(permission)
        )
    }

    #[must_use]
    pub fn dump(package: &str) -> String {
        format!("pm dump {package}")
    }

    #[must_use]
    pub fn path(package: &str) -> String {
        format!("pm path {package}")
    }

    #[must_use]
    pub fn list_permissions(group: Option<&str>) -> String {
        group.map_or_else(
            || "pm list permissions".to_string(),
            |g| format!("pm list permissions -g {g}"),
        )
    }
}

// ─── Activity Manager Commands ────────────────────────────────────────────────

/// Android `am` (activity manager) command builder.
pub struct AmCommand;

impl AmCommand {
    #[must_use]
    pub fn start_activity(intent: &Intent) -> String {
        format!("am start {intent}")
    }

    #[must_use]
    pub fn start_service(intent: &Intent) -> String {
        format!("am startservice {intent}")
    }

    #[must_use]
    pub fn stop_service(package: &str, service: &str) -> String {
        format!("am stopservice {package}/{service}")
    }

    #[must_use]
    pub fn broadcast(intent: &Intent) -> String {
        format!("am broadcast {intent}")
    }

    #[must_use]
    pub fn force_stop(package: &str) -> String {
        format!("am force-stop {package}")
    }

    #[must_use]
    pub fn kill(package: &str) -> String {
        format!("am kill {package}")
    }

    #[must_use]
    pub fn instrument(package: &str, runner: &str, args: &[(&str, &str)]) -> String {
        use std::fmt::Write as _;
        let mut cmd = String::from("am instrument -w -r -e debug false");
        for (k, v) in args {
            let _ = write!(cmd, " -e {k} {v}");
        }
        let _ = write!(cmd, " {package}/{runner}");
        cmd
    }

    #[must_use]
    pub fn dumpheap(package: &str, path: &str) -> String {
        format!("am dumpheap {package} {path}")
    }

    #[must_use]
    pub fn profile(package: &str, path: &str, start: bool) -> String {
        if start {
            format!("am profile {package} start {path}")
        } else {
            format!("am profile {package} stop")
        }
    }
}

/// A simplified Android Intent representation.
#[derive(Debug, Clone, Default)]
pub struct Intent {
    pub action: Option<String>,
    pub package: Option<String>,
    pub component: Option<String>,
    pub data_uri: Option<String>,
    pub mime_type: Option<String>,
    pub categories: Vec<String>,
    pub extras: Vec<(String, String)>,
    pub flags: Vec<String>,
}

impl Intent {
    #[must_use]
    pub fn action(a: impl Into<String>) -> Self {
        Self { action: Some(a.into()), ..Default::default() }
    }

    #[must_use]
    pub fn component(pkg: impl Into<String>, cls: impl Into<String>) -> Self {
        Self {
            component: Some(format!("{}/{}", pkg.into(), cls.into())),
            ..Default::default()
        }
    }

    #[must_use]
    pub fn with_extra_string(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.extras.push((key.into(), val.into()));
        self
    }

    #[must_use]
    pub fn with_flag(mut self, flag: impl Into<String>) -> Self {
        self.flags.push(flag.into());
        self
    }
}

impl fmt::Display for Intent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(a) = &self.action {
            write!(f, "-a {a} ")?;
        }
        if let Some(c) = &self.component {
            write!(f, "-n {c} ")?;
        }
        if let Some(d) = &self.data_uri {
            write!(f, "-d {d} ")?;
        }
        if let Some(t) = &self.mime_type {
            write!(f, "-t {t} ")?;
        }
        for cat in &self.categories {
            write!(f, "-c {cat} ")?;
        }
        for flag in &self.flags {
            write!(f, "--{flag} ")?;
        }
        for (k, v) in &self.extras {
            write!(f, "--es {k} {} ", shell_quote(v))?;
        }
        Ok(())
    }
}

// ─── Output Parser Utilities ─────────────────────────────────────────────────

/// Parse the output of `pm list packages` into a list of package names.
#[must_use]
pub fn parse_pm_list_packages(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|l| l.trim().strip_prefix("package:"))
        .map(|s| s.trim().to_string())
        .collect()
}

/// Parse the output of `getprop` into a map.
#[must_use]
pub fn parse_getprop(output: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in output.lines() {
        let line = line.trim();
        if !line.starts_with('[') {
            continue;
        }
        // Format: [key]: [value]
        if let Some(bracket_end) = line.find("]: [") {
            let key = line[1..bracket_end].to_string();
            let value_start = bracket_end + 4;
            if line.ends_with(']') && value_start < line.len() {
                let value = line[value_start..line.len() - 1].to_string();
                map.insert(key, value);
            }
        }
    }
    map
}

/// Parse `ps -A` output into a list of process info maps.
#[must_use]
pub fn parse_ps_output(output: &str) -> Vec<HashMap<String, String>> {
    let mut result = Vec::new();
    let mut lines = output.lines();
    let Some(header_line) = lines.next() else {
        return result;
    };
    // ADB `ps` header: USER PID PPID VSZ RSS WCHAN ADDR S NAME
    let headers: Vec<&str> = header_line.split_whitespace().collect();
    for line in lines {
        let parts: Vec<&str> = line.splitn(headers.len(), char::is_whitespace).collect();
        let mut row = HashMap::new();
        for (i, col) in parts.iter().enumerate() {
            if i < headers.len() {
                row.insert(headers[i].to_string(), col.trim().to_string());
            }
        }
        result.push(row);
    }
    result
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_v2_frame(msg_type: ShellV2MessageType, data: &[u8]) -> Vec<u8> {
        let frame = ShellV2Frame { msg_type, data: data.to_vec() };
        frame.encode()
    }

    fn make_v2_stream(stdout: &[u8], stderr: &[u8], exit: u8) -> Vec<u8> {
        let mut buf = Vec::new();
        if !stdout.is_empty() {
            buf.extend(make_v2_frame(ShellV2MessageType::Stdout, stdout));
        }
        if !stderr.is_empty() {
            buf.extend(make_v2_frame(ShellV2MessageType::Stderr, stderr));
        }
        buf.extend(make_v2_frame(ShellV2MessageType::ExitCode, &[exit]));
        buf
    }

    #[test]
    fn test_parse_shell_v2_success() {
        let raw = make_v2_stream(b"hello output\n", b"", 0);
        let out = parse_shell_v2_output(&raw, 0);
        assert_eq!(out.stdout_str().trim(), "hello output");
        assert_eq!(out.exit_code, Some(0));
        assert!(out.success());
    }

    #[test]
    fn test_parse_shell_v2_stderr() {
        let raw = make_v2_stream(b"out", b"error msg", 1);
        let out = parse_shell_v2_output(&raw, 0);
        assert_eq!(out.exit_code, Some(1));
        assert_eq!(out.stderr_str(), "error msg");
    }

    #[test]
    fn test_parse_shell_v2_truncated() {
        let big_stdout = vec![b'A'; 100];
        let raw = make_v2_stream(&big_stdout, b"", 0);
        let out = parse_shell_v2_output(&raw, 50);
        assert!(out.truncated);
        assert!(out.stdout.len() <= 100);
    }

    #[test]
    fn test_build_command_no_env() {
        let exec = ShellExecutor::new("dev");
        let cmd = exec.build_command("ls /data");
        assert_eq!(cmd, "ls /data");
    }

    #[test]
    fn test_build_command_with_env() {
        let exec = ShellExecutor::new("dev")
            .with_config(ShellConfig::default().with_env("TERM", "dumb"));
        let cmd = exec.build_command("ls");
        assert!(cmd.contains("TERM="));
        assert!(cmd.ends_with("ls"));
    }

    #[test]
    fn test_pm_list_packages() {
        let output = "package:com.example.app1\npackage:com.example.app2\n";
        let pkgs = parse_pm_list_packages(output);
        assert_eq!(pkgs, vec!["com.example.app1", "com.example.app2"]);
    }

    #[test]
    fn test_parse_getprop() {
        let output = "[ro.product.model]: [Pixel 6]\n[ro.build.version.release]: [12]\n";
        let props = parse_getprop(output);
        assert_eq!(props.get("ro.product.model").unwrap(), "Pixel 6");
        assert_eq!(props.get("ro.build.version.release").unwrap(), "12");
    }

    #[test]
    fn test_pm_install_command() {
        let cmd = PmCommand::install("/data/local/tmp/app.apk", &["-r", "-t"]);
        assert!(cmd.contains("pm install"));
        assert!(cmd.contains("-r"));
        assert!(cmd.contains("app.apk"));
    }

    #[test]
    fn test_am_start_activity() {
        let intent = Intent::action("android.intent.action.MAIN");
        let cmd = AmCommand::start_activity(&intent);
        assert!(cmd.contains("am start"));
        assert!(cmd.contains("android.intent.action.MAIN"));
    }

    #[test]
    fn test_am_broadcast() {
        let intent = Intent::action("com.example.BROADCAST").with_extra_string("key", "value");
        let cmd = AmCommand::broadcast(&intent);
        assert!(cmd.contains("am broadcast"));
        assert!(cmd.contains("--es key"));
    }

    #[test]
    fn test_shell_v2_frame_roundtrip() {
        let frame = ShellV2Frame { msg_type: ShellV2MessageType::Stdout, data: b"test data".to_vec() };
        let encoded = frame.encode();
        let (decoded, consumed) = ShellV2Frame::decode_from(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.data, b"test data");
        assert!(matches!(decoded.msg_type, ShellV2MessageType::Stdout));
    }

    #[test]
    fn test_shell_output_combined() {
        let out = ShellOutput {
            stdout: b"out".to_vec(),
            stderr: b"err".to_vec(),
            exit_code: Some(0),
            elapsed: Duration::ZERO,
            truncated: false,
        };
        let combined = out.combined_output();
        assert!(combined.contains("out"));
        assert!(combined.contains("err"));
    }
}
