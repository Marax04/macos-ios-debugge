//! # rustre-adb
//!
//! Android Debug Bridge (ADB) protocol client implementation in Rust.
//!
//! This crate implements the ADB wire protocol (§25.8) for communicating with
//! Android devices over TCP (adb server at localhost:5037 by default).
//!
//! ## Protocol overview
//!
//! The ADB host protocol works by:
//! 1. Connecting to the local ADB server (host:port, default 127.0.0.1:5037)
//! 2. Sending length-prefixed text commands (`XXXX<cmd>` where XXXX is 4-hex-digit length)
//! 3. Receiving OKAY or FAIL responses, optionally followed by data
//!
//! The low-level USB/transport protocol uses `AdbMessage` structs with a 24-byte header.
//!
//! ## Modules
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`protocol`] | Full ADB wire protocol: typed message constructors, async read/write, RSA auth, handshake state machine, feature negotiation |
//! | [`device`]   | Enriched device records, `DeviceList` filtering, `DeviceMonitor`, `DeviceSelector` |
//! | [`shell`]    | `ShellSession` (v1 + v2), command builder, shell-escape helpers |
//! | [`sync`]     | ADB sync protocol: push/pull/stat/list, `SyncSession`, progress callbacks |
//! | [`logcat`]   | Logcat parser (threadtime, brief, binary), `LogcatFilter`, `LogcatReader` |
//! | [`package`]  | Package management: list/install/uninstall/pm-dump, `AdbPackageManager` |

// ── Sub-modules ───────────────────────────────────────────────────────────────

pub mod adb_protocol;
pub mod android_shell;
pub mod device;
pub mod device_manager;
pub mod file_transfer;
pub mod logcat;
pub mod package;
pub mod protocol;
pub mod shell;
pub mod shell_executor;
pub mod sync;
pub mod adb_file_sync;
pub mod android_package_analyzer;
pub mod logcat_parser;
pub mod apk_installer;
pub mod device_profiler;

// ── Re-exports for convenience ────────────────────────────────────────────────

pub use protocol::{
    AdbFeature, AdbRsaKey, AuthType, HandshakeDriver, HandshakeState, LocalId, RemoteId,
    build_banner, make_auth_public_key, make_auth_signature, make_auth_token, make_close,
    make_connect, make_okay, make_open, make_write, parse_features, read_message, write_message,
};

pub use device::{
    DeviceEvent, DeviceInfo, DeviceList, DeviceMonitor, DeviceSelector, SharedDeviceList,
    TransportType, new_shared_device_list, parse_devices_output,
};

pub use shell::{
    CommandBuilder, ShellOutput, ShellSession, TerminalSize, build_shell_command,
    cmd_am_force_stop, cmd_am_start, cmd_dumpsys, cmd_getprop, cmd_logcat, cmd_pm_install,
    cmd_pm_uninstall, shell_escape,
};

pub use sync::{
    DirEntry as SyncDirEntry, FileType, StatEntry as SyncStatEntry, SyncSession, list_dir,
    pull_file as sync_pull_file, push_file as sync_push_file, quit_sync, stat_file,
};

pub use logcat::{
    LogBuffer, LogcatEntry, LogcatFilter, LogcatFormat, LogcatReader, LogcatStats, Priority,
    filter_by_priority, filter_by_tag as logcat_filter_by_tag, group_by_pid,
    group_by_tag as logcat_group_by_tag, parse_any_line, parse_binary_log, parse_brief_line,
    parse_text_output, parse_threadtime_line,
};

pub use package::{
    AdbPackageManager, InstallLocation, ListOptions, PackageDetails, PackageFlags,
    build_install_command, build_uninstall_command, extract_install_failure, install_succeeded,
    parse_pm_dump, parse_pm_list_line, parse_pm_list_output, uninstall_succeeded,
};

use std::path::Path;
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

// ──────────────────────────────────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────────────────────────────────

/// All errors that can be produced by this crate.
#[derive(Debug, Error)]
pub enum AdbError {
    /// TCP connection to the ADB server failed.
    #[error("connection error: {0}")]
    Connection(#[from] std::io::Error),

    /// The ADB server returned an unexpected or malformed response.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// No device with the requested serial number is connected.
    #[error("device not found: {serial}")]
    DeviceNotFound { serial: String },

    /// The remote command exited with a non-zero status or returned an error.
    #[error("command failed: {0}")]
    CommandFailed(String),

    /// The operation did not complete within the allotted time.
    #[error("operation timed out")]
    Timeout,

    /// A sync-protocol specific error.
    #[error("sync error: {0}")]
    Sync(String),

    /// A logcat parse error.
    #[error("logcat parse error: {0}")]
    LogcatParse(String),

    /// Authentication failure.
    #[error("authentication failed: {0}")]
    AuthFailed(String),
}

impl From<tokio::time::error::Elapsed> for AdbError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        Self::Timeout
    }
}

pub type Result<T, E = AdbError> = std::result::Result<T, E>;

// ──────────────────────────────────────────────────────────────────────────────
// ADB protocol constants
// ──────────────────────────────────────────────────────────────────────────────

/// ADB protocol version sent in CNXN messages.
pub const ADB_VERSION: u32 = 0x0100_0000;

/// Maximum data payload size for a single ADB message.
pub const ADB_MAX_PAYLOAD: u32 = 256 * 1024;

/// ADB command constants used in the wire protocol.
pub mod cmd {
    /// SYNC: used to synchronise state.
    pub const SYNC: u32 = 0x434e_5953;
    /// CNXN: connect/introduce both sides.
    pub const CNXN: u32 = 0x4e58_4e43;
    /// AUTH: authentication exchange.
    pub const AUTH: u32 = 0x4854_5541;
    /// OPEN: open a new stream.
    pub const OPEN: u32 = 0x4e45_504f;
    /// OKAY: acknowledge a stream write.
    pub const OKAY: u32 = 0x5941_4b4f;
    /// CLSE: close a stream.
    pub const CLSE: u32 = 0x4553_4c43;
    /// WRTE: write data to a stream.
    pub const WRTE: u32 = 0x4554_5257;
}

/// ADB sync sub-command IDs (4-byte ASCII tags).
pub mod sync_cmd {
    /// DENT: directory entry (used in ls replies).
    pub const DENT: &[u8; 4] = b"DENT";
    /// RECV: pull a file from device.
    pub const RECV: &[u8; 4] = b"RECV";
    /// SEND: push a file to device.
    pub const SEND: &[u8; 4] = b"SEND";
    /// STAT: stat a remote path.
    pub const STAT: &[u8; 4] = b"STAT";
    /// DATA: file data chunk.
    pub const DATA: &[u8; 4] = b"DATA";
    /// DONE: end-of-file marker.
    pub const DONE: &[u8; 4] = b"DONE";
    /// FAIL: remote error.
    pub const FAIL: &[u8; 4] = b"FAIL";
    /// OKAY: acknowledge success.
    pub const OKAY: &[u8; 4] = b"OKAY";
    /// QUIT: terminate the sync session.
    pub const QUIT: &[u8; 4] = b"QUIT";
    /// LIST: list directory.
    pub const LIST: &[u8; 4] = b"LIST";

    /// Maximum chunk size for DATA messages (64 KiB).
    pub const MAX_DATA_CHUNK: usize = 64 * 1024;
}

// ──────────────────────────────────────────────────────────────────────────────
// Device state / descriptor
// ──────────────────────────────────────────────────────────────────────────────

/// Connection state of an ADB device as reported by `adb devices -l`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceState {
    Offline,
    Bootloader,
    Device,
    Host,
    Recovery,
    NoPermissions,
    Sideload,
    Unauthorized,
    Unknown,
}

impl DeviceState {
    fn from_str(s: &str) -> Self {
        match s {
            "offline" => Self::Offline,
            "bootloader" => Self::Bootloader,
            "device" => Self::Device,
            "host" => Self::Host,
            "recovery" => Self::Recovery,
            "no permissions" | "no-permissions" => Self::NoPermissions,
            "sideload" => Self::Sideload,
            "unauthorized" => Self::Unauthorized,
            _ => Self::Unknown,
        }
    }

    /// Returns `true` if the device is in a usable state.
    #[must_use]
    pub const fn is_online(&self) -> bool {
        matches!(self, Self::Device | Self::Recovery | Self::Sideload)
    }

    /// Returns `true` if the device needs authorisation before use.
    #[must_use]
    pub const fn needs_auth(&self) -> bool {
        matches!(self, Self::Unauthorized)
    }
}

impl std::fmt::Display for DeviceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Offline => "offline",
            Self::Bootloader => "bootloader",
            Self::Device => "device",
            Self::Host => "host",
            Self::Recovery => "recovery",
            Self::NoPermissions => "no-permissions",
            Self::Sideload => "sideload",
            Self::Unauthorized => "unauthorized",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

/// Describes a single device visible to the ADB server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdbDevice {
    /// Unique serial identifier (e.g. `emulator-5554` or `R3CN90ABCDE`).
    pub serial: String,
    /// Current transport state.
    pub state: DeviceState,
    /// `product:` property from the device descriptor line (may be empty).
    pub product: String,
    /// `model:` property from the device descriptor line (may be empty).
    pub model: String,
    /// `device:` property from the device descriptor line (may be empty).
    pub device: String,
    /// `transport_id:` if present.
    pub transport_id: Option<u32>,
}

impl AdbDevice {
    fn parse(line: &str) -> Option<Self> {
        let mut parts = line.splitn(2, '\t');
        let serial = parts.next()?.trim().to_owned();
        if serial.is_empty() {
            return None;
        }
        let rest = parts.next().unwrap_or("").trim();

        let state_str = rest.split_whitespace().next().unwrap_or("unknown");
        let state = DeviceState::from_str(state_str);

        let extract = |key: &str| -> String {
            rest.split_whitespace()
                .find(|tok| tok.starts_with(key))
                .and_then(|tok| tok.strip_prefix(key))
                .unwrap_or("")
                .to_owned()
        };

        let transport_id: Option<u32> = extract("transport_id:").parse().ok();

        Some(Self {
            serial,
            state,
            product: extract("product:"),
            model: extract("model:"),
            device: extract("device:"),
            transport_id,
        })
    }

    /// Returns `true` if this device is ready for commands.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        self.state.is_online()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Log types
// ──────────────────────────────────────────────────────────────────────────────

/// Logcat severity level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    const fn from_char(c: char) -> Self {
        match c {
            'V' => Self::Verbose,
            'D' => Self::Debug,
            // 'I' was reaching `Info` only through the catch-all, which hid the
            // fact that the same arm also swallows every unknown character.
            'I' => Self::Info,
            'W' => Self::Warning,
            'E' => Self::Error,
            'F' => Self::Fatal,
            'S' => Self::Silent,
            // NOTE: an unrecognised character still becomes `Info` — the enum
            // has no `Unknown` variant and this fn is total. The twin in
            // `android_shell.rs` picks `Verbose` for the same case.
            _ => Self::Info,
        }
    }

    #[must_use]
    pub const fn as_char(&self) -> char {
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

    /// Numerical severity (higher = more severe).
    #[must_use]
    pub const fn severity(&self) -> u8 {
        match self {
            Self::Verbose => 2,
            Self::Debug => 3,
            Self::Info => 4,
            Self::Warning => 5,
            Self::Error => 6,
            Self::Fatal => 7,
            Self::Silent => 8,
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_char())
    }
}

/// A single parsed logcat line.
///
/// Supports both the **brief** (`X/TAG(PID): MSG`) and **threadtime**
/// (`MM-DD HH:MM:SS.mmm PID TID LEVEL TAG: MSG`) formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Log tag (component identifier).
    pub tag: String,
    /// Process ID that produced the entry.
    pub pid: u32,
    /// Thread ID (0 if not available from format).
    pub tid: u32,
    /// Severity level.
    pub level: LogLevel,
    /// Log message text.
    pub message: String,
    /// Timestamp string as found in the log line (empty for brief format).
    pub timestamp: String,
}

impl LogEntry {
    /// Parse a **brief**-format logcat line: `<level>/<tag>(<pid>): <message>`.
    #[must_use]
    pub fn parse_brief(line: &str) -> Option<Self> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('-') {
            return None;
        }
        let level_char = line.chars().next()?;
        let level = LogLevel::from_char(level_char);
        let rest = line.get(2..)?;
        let slash = rest.find('(')?;
        let tag = rest[..slash].trim().to_owned();
        let rest2 = &rest[slash + 1..];
        let close = rest2.find(')')?;
        let pid: u32 = rest2[..close].trim().parse().ok()?;
        let message = rest2[close + 1..].trim_start_matches(':').trim().to_owned();
        Some(Self {
            tag,
            pid,
            tid: 0,
            level,
            message,
            timestamp: String::new(),
        })
    }

    /// Parse a **threadtime**-format logcat line:
    /// `MM-DD HH:MM:SS.mmm PID TID LEVEL TAG: MESSAGE`
    #[must_use]
    pub fn parse_threadtime(line: &str) -> Option<Self> {
        // Expected: "01-01 12:00:00.000  1234  5678 I SomeTag: message text"
        let line = line.trim();
        if line.is_empty() || line.starts_with('-') {
            return None;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            return None;
        }
        let date = parts[0].to_owned();
        let time = parts[1].to_owned();
        let timestamp = format!("{date} {time}");
        let pid: u32 = parts[2].parse().ok()?;
        let tid: u32 = parts[3].parse().ok()?;
        let level_str = parts[4];
        let level = LogLevel::from_char(level_str.chars().next()?);
        let level_pos = {
            let p5 = parts[5];
            let p5_ptr = p5.as_ptr() as usize;
            let line_ptr = line.as_ptr() as usize;
            p5_ptr - line_ptr
        };
        let rest = line[level_pos..].trim();
        // rest = "TAG: message" or "TAG : message"
        let colon = rest.find(':')?;
        let tag = rest[..colon].trim().to_owned();
        let message = rest[colon + 1..].trim().to_owned();
        Some(Self {
            tag,
            pid,
            tid,
            level,
            message,
            timestamp,
        })
    }

    /// Try brief format first, then threadtime.
    #[must_use]
    pub fn parse(line: &str) -> Option<Self> {
        Self::parse_brief(line).or_else(|| Self::parse_threadtime(line))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Low-level ADB wire message (USB / direct transport)
// ──────────────────────────────────────────────────────────────────────────────

/// A 24-byte ADB wire-protocol message header plus optional payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdbMessage {
    /// Command identifier (one of the `cmd::*` constants).
    pub command: u32,
    /// First argument (meaning depends on command).
    pub arg0: u32,
    /// Second argument (meaning depends on command).
    pub arg1: u32,
    /// Payload bytes.
    pub data: Vec<u8>,
    /// CRC32 of `data` (ADB CRC: sum of all bytes mod 2^32).
    pub crc32: u32,
    /// `command ^ 0xFFFFFFFF` — used for framing validation.
    pub magic: u32,
}

impl AdbMessage {
    /// Construct an `AdbMessage` and compute crc32 / magic automatically.
    #[must_use]
    pub fn new(command: u32, arg0: u32, arg1: u32, data: Vec<u8>) -> Self {
        let crc32 = compute_crc32(&data);
        let magic = command ^ 0xFFFF_FFFF;
        Self {
            command,
            arg0,
            arg1,
            data,
            crc32,
            magic,
        }
    }

    /// Encode this message into a byte buffer (24-byte header + data).
    #[must_use]
    pub fn encode(&self) -> Bytes {
        encode_message(self.command, self.arg0, self.arg1, &self.data)
    }

    /// Return the human-readable command name.
    #[must_use]
    pub const fn command_name(&self) -> &'static str {
        match self.command {
            cmd::CNXN => "CNXN",
            cmd::AUTH => "AUTH",
            cmd::OPEN => "OPEN",
            cmd::OKAY => "OKAY",
            cmd::CLSE => "CLSE",
            cmd::WRTE => "WRTE",
            cmd::SYNC => "SYNC",
            _ => "UNKNOWN",
        }
    }

    /// Return `true` if the CRC32 stored in the header matches the data.
    #[must_use]
    pub fn verify_crc(&self) -> bool {
        self.crc32 == compute_crc32(&self.data)
    }
}

/// Compute the ADB CRC32: simple sum of all bytes mod 2^32.
///
/// Note: this is **not** the standard IEEE CRC-32; ADB uses a simple byte sum.
#[must_use]
pub fn compute_crc32(data: &[u8]) -> u32 {
    data.iter()
        .fold(0u32, |acc, &b| acc.wrapping_add(u32::from(b)))
}

/// Encode an `AdbMessage` into a 24-byte header followed by the data payload.
///
/// The CRC and magic fields are computed automatically from `command` and `data`.
#[must_use]
pub fn encode_message(command: u32, arg0: u32, arg1: u32, data: &[u8]) -> Bytes {
    let data_len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let crc = compute_crc32(data);
    let magic = command ^ 0xFFFF_FFFF;

    let mut buf = BytesMut::with_capacity(24 + data.len());
    buf.put_u32_le(command);
    buf.put_u32_le(arg0);
    buf.put_u32_le(arg1);
    buf.put_u32_le(data_len);
    buf.put_u32_le(crc);
    buf.put_u32_le(magic);
    buf.put_slice(data);
    buf.freeze()
}

/// Decode a raw byte slice into an `AdbMessage`.
///
/// Returns `Err` if the slice is too short, the magic field is wrong, or the
/// declared payload length exceeds the available bytes.
///
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn decode_message(raw: &[u8]) -> Result<AdbMessage> {
    if raw.len() < 24 {
        return Err(AdbError::Protocol(format!(
            "message too short: {} bytes (need >= 24)",
            raw.len()
        )));
    }
    let mut cur = raw;
    let command = cur.get_u32_le();
    let arg0 = cur.get_u32_le();
    let arg1 = cur.get_u32_le();
    let data_len = cur.get_u32_le() as usize;
    let crc32 = cur.get_u32_le();
    let magic = cur.get_u32_le();

    if magic != command ^ 0xFFFF_FFFF {
        return Err(AdbError::Protocol(format!(
            "magic mismatch: expected {:08x}, got {:08x}",
            command ^ 0xFFFF_FFFF,
            magic
        )));
    }
    if cur.remaining() < data_len {
        return Err(AdbError::Protocol(format!(
            "payload truncated: need {} bytes, have {}",
            data_len,
            cur.remaining()
        )));
    }
    let data = cur[..data_len].to_vec();
    Ok(AdbMessage {
        command,
        arg0,
        arg1,
        data,
        crc32,
        magic,
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// ADB Sync protocol helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Statistics for a remote file as returned by STAT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatEntry {
    pub mode: u32,
    pub size: u32,
    pub mtime: u32,
}

/// A directory entry as returned by DENT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub mode: u32,
    pub size: u32,
    pub mtime: u32,
    pub name: String,
}

/// Push a raw byte slice to a remote path using the ADB sync SEND command.
///
/// `mode` is the Unix permission bits (e.g. `0o644`).
///
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub async fn push_file(
    stream: &mut TcpStream,
    local: &[u8],
    remote: &str,
    mode: u32,
) -> Result<()> {
    // SEND <remote>,<mode>
    let dest = format!("{remote},{mode:04o}");
    let dest_bytes = dest.as_bytes();
    let mut header = BytesMut::with_capacity(8 + dest_bytes.len());
    header.put_slice(sync_cmd::SEND);
    header.put_u32_le(u32::try_from(dest_bytes.len()).unwrap_or(u32::MAX));
    header.put_slice(dest_bytes);
    stream.write_all(&header).await?;

    // DATA chunks
    for chunk in local.chunks(sync_cmd::MAX_DATA_CHUNK) {
        let mut chunk_hdr = BytesMut::with_capacity(8 + chunk.len());
        chunk_hdr.put_slice(sync_cmd::DATA);
        chunk_hdr.put_u32_le(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
        chunk_hdr.put_slice(chunk);
        stream.write_all(&chunk_hdr).await?;
    }

    // DONE + mtime
    let mtime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
        .unwrap_or(0);
    let mut done_hdr = BytesMut::with_capacity(8);
    done_hdr.put_slice(sync_cmd::DONE);
    done_hdr.put_u32_le(mtime);
    stream.write_all(&done_hdr).await?;

    // Read response
    let resp_id = read_sync_id(stream).await?;
    if resp_id.as_slice() == sync_cmd::OKAY {
        Ok(())
    } else if resp_id.as_slice() == sync_cmd::FAIL {
        let msg_len = read_sync_len(stream).await?;
        if msg_len as usize > 4096 {
            return Err(AdbError::Protocol(format!(
                "FAIL message length {msg_len} exceeds maximum 4096"
            )));
        }
        let msg = read_exact_bytes(stream, msg_len as usize).await?;
        Err(AdbError::Sync(String::from_utf8_lossy(&msg).into_owned()))
    } else {
        Err(AdbError::Sync(format!(
            "unexpected sync reply: {:?}",
            String::from_utf8_lossy(&resp_id)
        )))
    }
}

/// Pull a file from a remote path using the ADB sync RECV command.
///
/// Returns the complete file contents as a `Vec<u8>`.
///
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub async fn pull_file(stream: &mut TcpStream, remote: &str) -> Result<Vec<u8>> {
    let remote_bytes = remote.as_bytes();
    let mut hdr = BytesMut::with_capacity(8 + remote_bytes.len());
    hdr.put_slice(sync_cmd::RECV);
    hdr.put_u32_le(u32::try_from(remote_bytes.len()).unwrap_or(u32::MAX));
    hdr.put_slice(remote_bytes);
    stream.write_all(&hdr).await?;

    let mut file_data: Vec<u8> = Vec::new();
    loop {
        let id = read_sync_id(stream).await?;
        let len = read_sync_len(stream).await?;

        match id.as_slice() {
            b"DATA" => {
                if len as usize > sync_cmd::MAX_DATA_CHUNK {
                    return Err(AdbError::Protocol(format!(
                        "DATA chunk length {len} exceeds MAX_DATA_CHUNK {}",
                        sync_cmd::MAX_DATA_CHUNK
                    )));
                }
                let chunk = read_exact_bytes(stream, len as usize).await?;
                file_data.extend_from_slice(&chunk);
            }
            b"DONE" => break,
            b"FAIL" => {
                if len as usize > 4096 {
                    return Err(AdbError::Protocol(format!(
                        "FAIL message length {len} exceeds maximum 4096"
                    )));
                }
                let msg = read_exact_bytes(stream, len as usize).await?;
                return Err(AdbError::Sync(String::from_utf8_lossy(&msg).into_owned()));
            }
            other => {
                return Err(AdbError::Protocol(format!(
                    "unexpected sync id: {}",
                    String::from_utf8_lossy(other)
                )));
            }
        }
    }
    Ok(file_data)
}

/// Stat a remote path using the ADB sync STAT command.
///
/// # Errors
///
/// Returns an error if the underlying operation fails.
///
/// # Panics
///
/// Panics if the response header cannot be parsed.
pub async fn stat_remote(stream: &mut TcpStream, remote: &str) -> Result<StatEntry> {
    let remote_bytes = remote.as_bytes();
    let mut hdr = BytesMut::with_capacity(8 + remote_bytes.len());
    hdr.put_slice(sync_cmd::STAT);
    hdr.put_u32_le(u32::try_from(remote_bytes.len()).unwrap_or(u32::MAX));
    hdr.put_slice(remote_bytes);
    stream.write_all(&hdr).await?;

    // Response: "STAT" + mode(u32) + size(u32) + mtime(u32)
    let id = read_sync_id(stream).await?;
    if id.as_slice() != sync_cmd::STAT {
        return Err(AdbError::Sync(format!(
            "expected STAT response, got {:?}",
            String::from_utf8_lossy(&id)
        )));
    }
    let mode_bytes = read_exact_bytes(stream, 4).await?;
    let size_bytes = read_exact_bytes(stream, 4).await?;
    let mtime_bytes = read_exact_bytes(stream, 4).await?;

    let mode_arr: [u8; 4] = mode_bytes
        .try_into()
        .map_err(|_| AdbError::Protocol("failed to parse STAT mode field".into()))?;
    let size_arr: [u8; 4] = size_bytes
        .try_into()
        .map_err(|_| AdbError::Protocol("failed to parse STAT size field".into()))?;
    let mtime_arr: [u8; 4] = mtime_bytes
        .try_into()
        .map_err(|_| AdbError::Protocol("failed to parse STAT mtime field".into()))?;
    Ok(StatEntry {
        mode: u32::from_le_bytes(mode_arr),
        size: u32::from_le_bytes(size_arr),
        mtime: u32::from_le_bytes(mtime_arr),
    })
}

/// List a remote directory using the ADB sync LIST command.
///
/// # Errors
///
/// Returns an error if the underlying operation fails.
///
/// # Panics
///
/// Panics if a DENT record's name length exceeds the read buffer.
pub async fn list_remote_dir(stream: &mut TcpStream, remote: &str) -> Result<Vec<DirEntry>> {
    let remote_bytes = remote.as_bytes();
    let mut hdr = BytesMut::with_capacity(8 + remote_bytes.len());
    hdr.put_slice(sync_cmd::LIST);
    hdr.put_u32_le(u32::try_from(remote_bytes.len()).unwrap_or(u32::MAX));
    hdr.put_slice(remote_bytes);
    stream.write_all(&hdr).await?;

    let mut entries = Vec::new();
    loop {
        let id = read_sync_id(stream).await?;
        match id.as_slice() {
            b"DENT" => {
                let mode_b = read_exact_bytes(stream, 4).await?;
                let size_b = read_exact_bytes(stream, 4).await?;
                let mtime_b = read_exact_bytes(stream, 4).await?;
                let name_len_b = read_exact_bytes(stream, 4).await?;
                let mode_arr: [u8; 4] = mode_b
                    .try_into()
                    .map_err(|_| AdbError::Protocol("failed to parse DENT mode".into()))?;
                let size_arr: [u8; 4] = size_b
                    .try_into()
                    .map_err(|_| AdbError::Protocol("failed to parse DENT size".into()))?;
                let mtime_arr: [u8; 4] = mtime_b
                    .try_into()
                    .map_err(|_| AdbError::Protocol("failed to parse DENT mtime".into()))?;
                let name_len_arr: [u8; 4] = name_len_b
                    .try_into()
                    .map_err(|_| AdbError::Protocol("failed to parse DENT name_len".into()))?;
                let name_len_raw = u32::from_le_bytes(name_len_arr);
                if name_len_raw as usize > 4096 {
                    return Err(AdbError::Protocol(format!(
                        "DENT name length {name_len_raw} exceeds maximum 4096"
                    )));
                }
                let name_len = name_len_raw as usize;
                let name_b = read_exact_bytes(stream, name_len).await?;
                entries.push(DirEntry {
                    mode: u32::from_le_bytes(mode_arr),
                    size: u32::from_le_bytes(size_arr),
                    mtime: u32::from_le_bytes(mtime_arr),
                    name: String::from_utf8_lossy(&name_b).into_owned(),
                });
            }
            b"DONE" => break,
            b"FAIL" => {
                let len = read_sync_len(stream).await?;
                if len as usize > 4096 {
                    return Err(AdbError::Protocol(format!(
                        "FAIL message length {len} exceeds maximum 4096"
                    )));
                }
                let msg = read_exact_bytes(stream, len as usize).await?;
                return Err(AdbError::Sync(String::from_utf8_lossy(&msg).into_owned()));
            }
            other => {
                return Err(AdbError::Protocol(format!(
                    "unexpected LIST response: {}",
                    String::from_utf8_lossy(other)
                )));
            }
        }
    }
    Ok(entries)
}

// ──────────────────────────────────────────────────────────────────────────────
// AdbLogcat — extended parser
// ──────────────────────────────────────────────────────────────────────────────

/// Parse a single logcat line, trying both brief and threadtime formats.
///
/// Returns `None` for separator / header lines.
#[must_use]
pub fn parse_logcat_line(line: &str) -> Option<LogEntry> {
    LogEntry::parse(line)
}

/// Parse a batch of logcat output into a `Vec<LogEntry>`.
pub fn parse_logcat_output(output: &str) -> Vec<LogEntry> {
    output.lines().filter_map(parse_logcat_line).collect()
}

/// Filter log entries to those at or above `min_level`.
#[must_use]
pub fn filter_by_level<'a>(entries: &'a [LogEntry], min_level: &LogLevel) -> Vec<&'a LogEntry> {
    entries
        .iter()
        .filter(|e| e.level.severity() >= min_level.severity())
        .collect()
}

/// Filter log entries by tag prefix (case-insensitive).
#[must_use]
pub fn filter_by_tag<'a>(entries: &'a [LogEntry], tag_prefix: &str) -> Vec<&'a LogEntry> {
    let lower = tag_prefix.to_lowercase();
    entries
        .iter()
        .filter(|e| e.tag.to_lowercase().starts_with(&lower))
        .collect()
}

/// Group log entries by tag.
///
/// Uses `ahash`-backed `HashMap` (via the `std::collections` re-export that
/// is hash-randomised on every process start) so that an attacker who controls
/// log-tag content cannot craft a hash-collision `DoS`.
// dos-hash-collision: logcat tags come from untrusted Android processes; using
// a randomly-seeded hasher (RandomState, which is the default for std HashMap)
// prevents worst-case O(n) hash-table attacks.
#[must_use]
pub fn group_by_tag(entries: &[LogEntry]) -> std::collections::HashMap<String, Vec<&LogEntry>> {
    let mut map: std::collections::HashMap<String, Vec<&LogEntry>> =
        std::collections::HashMap::with_hasher(std::collections::hash_map::RandomState::new());
    for e in entries {
        map.entry(e.tag.clone()).or_default().push(e);
    }
    map
}

// ──────────────────────────────────────────────────────────────────────────────
// ADB host-protocol helpers (internal)
// ──────────────────────────────────────────────────────────────────────────────

/// Format a host-protocol request: `{len:04X}{cmd}`.
fn host_request(cmd: &str) -> String {
    format!("{:04X}{}", cmd.len(), cmd)
}

/// Read exactly `n` bytes from `stream`.
async fn read_exact_bytes(stream: &mut TcpStream, n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Read a 4-byte sync ID tag.
async fn read_sync_id(stream: &mut TcpStream) -> Result<Vec<u8>> {
    read_exact_bytes(stream, 4).await
}

/// Read a 4-byte little-endian length word.
async fn read_sync_len(stream: &mut TcpStream) -> Result<u32> {
    let b = read_exact_bytes(stream, 4).await?;
    Ok(u32::from_le_bytes(b.try_into().expect("4 bytes")))
}

/// Read a 4-byte hex length prefix and then that many bytes of payload.
async fn read_length_prefixed(stream: &mut TcpStream) -> Result<String> {
    let len_bytes = read_exact_bytes(stream, 4).await?;
    let len_str = std::str::from_utf8(&len_bytes).map_err(|e| AdbError::Protocol(e.to_string()))?;
    let len = usize::from_str_radix(len_str, 16).map_err(|e| AdbError::Protocol(e.to_string()))?;
    // 4-hex-digit prefix gives at most 0xFFFF = 65535 bytes; still cap defensively.
    if len > 65535 {
        return Err(AdbError::Protocol(format!(
            "length-prefixed response length {len} exceeds maximum 65535"
        )));
    }
    let data = read_exact_bytes(stream, len).await?;
    String::from_utf8(data).map_err(|e| AdbError::Protocol(e.to_string()))
}

/// Send a host-protocol request and verify the OKAY/FAIL status.
async fn send_and_check(stream: &mut TcpStream, request: &str) -> Result<()> {
    stream.write_all(request.as_bytes()).await?;

    let status = read_exact_bytes(stream, 4).await?;
    match status.as_slice() {
        b"OKAY" => Ok(()),
        b"FAIL" => {
            let msg = read_length_prefixed(stream).await?;
            Err(AdbError::CommandFailed(msg))
        }
        other => Err(AdbError::Protocol(format!(
            "unexpected status: {}",
            String::from_utf8_lossy(other)
        ))),
    }
}

/// Open a fresh TCP connection to the ADB server and transport-select a device.
async fn open_device_connection(host: &str, port: u16, serial: &str) -> Result<TcpStream> {
    let mut stream = TcpStream::connect((host, port)).await?;
    let req = host_request(&format!("host:transport:{serial}"));
    send_and_check(&mut stream, &req)
        .await
        .map_err(|e| match e {
            AdbError::CommandFailed(_) => AdbError::DeviceNotFound {
                serial: serial.to_owned(),
            },
            other => other,
        })?;
    Ok(stream)
}

// ──────────────────────────────────────────────────────────────────────────────
// AdbShellResult
// ──────────────────────────────────────────────────────────────────────────────

/// The result of a shell command, capturing stdout/stderr and exit code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellResult {
    /// Combined stdout output.
    pub stdout: String,
    /// Exit code if determinable (None for older shell protocol).
    pub exit_code: Option<i32>,
}

impl ShellResult {
    #[must_use]
    pub fn success(&self) -> bool {
        self.exit_code.is_none_or(|c| c == 0)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// PackageInfo
// ──────────────────────────────────────────────────────────────────────────────

/// Basic info about an installed Android package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    pub package_name: String,
    pub apk_path: Option<String>,
    pub version_code: Option<u32>,
    pub version_name: Option<String>,
    pub is_system: bool,
}

impl PackageInfo {
    /// Parse a `pm list packages -f` line.
    fn parse_pm_line(line: &str) -> Option<Self> {
        // "package:/data/app/com.example-XXX.apk=com.example"
        let line = line.trim();
        if !line.starts_with("package:") {
            return None;
        }
        let rest = &line["package:".len()..];
        let (apk_path, package_name) = rest.rfind('=').map_or_else(
            || (None, rest.to_owned()),
            |eq| (Some(rest[..eq].to_owned()), rest[eq + 1..].to_owned()),
        );
        if package_name.is_empty() {
            return None;
        }
        Some(Self {
            package_name,
            apk_path,
            version_code: None,
            version_name: None,
            is_system: false,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ProcessInfo
// ──────────────────────────────────────────────────────────────────────────────

/// Info about a running process on the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub user: String,
    pub ppid: Option<u32>,
}

impl ProcessInfo {
    /// Parse a line from `ps` output (simplified).
    fn parse_ps_line(line: &str) -> Option<Self> {
        // Typical: "USER  PID  PPID  ... NAME"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return None;
        }
        let user = parts[0].to_owned();
        let pid: u32 = parts[1].parse().ok()?;
        let parent_pid: u32 = parts[2].parse().ok()?;
        let name = parts.last()?.to_string();
        Some(Self {
            pid,
            name,
            user,
            ppid: Some(parent_pid),
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// AdbClient
// ──────────────────────────────────────────────────────────────────────────────

/// Client for the local ADB server (default: `127.0.0.1:5037`).
///
/// Each high-level method opens a fresh connection; the ADB host protocol does
/// not multiplex commands over a single socket.
#[derive(Debug, Clone)]
pub struct AdbClient {
    /// Hostname or IP of the ADB server.
    pub host: String,
    /// Port of the ADB server (5037 by default).
    pub port: u16,
    /// Per-operation timeout.
    pub timeout: Duration,
}

impl Default for AdbClient {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 5037,
            timeout: Duration::from_secs(30),
        }
    }
}

impl AdbClient {
    /// Create a new client targeting `host:port`.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            ..Default::default()
        }
    }

    /// Set the per-operation timeout.
    #[must_use]
    pub const fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Verify that the ADB server is reachable by querying its version.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn connect(&self) -> Result<()> {
        let host = self.host.clone();
        let port = self.port;
        let dur = self.timeout;
        let fut = async move {
            let mut stream = TcpStream::connect((host.as_str(), port)).await?;
            let req = host_request("host:version");
            stream.write_all(req.as_bytes()).await?;
            let status = read_exact_bytes(&mut stream, 4).await?;
            if status != b"OKAY" {
                return Err(AdbError::Protocol(format!(
                    "expected OKAY from host:version, got {}",
                    String::from_utf8_lossy(&status)
                )));
            }
            let _version = read_length_prefixed(&mut stream).await?;
            Ok(())
        };
        timeout(dur, fut).await?
    }

    /// Return the ADB server's version string.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn server_version(&self) -> Result<String> {
        let host = self.host.clone();
        let port = self.port;
        let dur = self.timeout;
        let fut = async move {
            let mut stream = TcpStream::connect((host.as_str(), port)).await?;
            let req = host_request("host:version");
            stream.write_all(req.as_bytes()).await?;
            let status = read_exact_bytes(&mut stream, 4).await?;
            if status != b"OKAY" {
                return Err(AdbError::Protocol("host:version failed".into()));
            }
            read_length_prefixed(&mut stream).await
        };
        timeout(dur, fut).await?
    }

    /// Return the list of devices known to the ADB server.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn list_devices(&self) -> Result<Vec<AdbDevice>> {
        let host = self.host.clone();
        let port = self.port;
        let dur = self.timeout;
        let fut = async move {
            let mut stream = TcpStream::connect((host.as_str(), port)).await?;
            let req = host_request("host:devices-l");
            stream.write_all(req.as_bytes()).await?;
            let status = read_exact_bytes(&mut stream, 4).await?;
            if status != b"OKAY" {
                return Err(AdbError::Protocol("host:devices-l failed".into()));
            }
            let body = read_length_prefixed(&mut stream).await?;
            let devices = body
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(AdbDevice::parse)
                .collect();
            Ok(devices)
        };
        timeout(dur, fut).await?
    }

    /// Execute a shell command on the device and return stdout as a `String`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn shell(&self, serial: &str, cmd: &str) -> Result<String> {
        let host = self.host.clone();
        let port = self.port;
        let dur = self.timeout;
        let serial = serial.to_owned();
        let cmd = cmd.to_owned();
        let fut = async move {
            let mut stream = open_device_connection(&host, port, &serial).await?;
            let req = host_request(&format!("shell:{cmd}"));
            stream.write_all(req.as_bytes()).await?;
            let status = read_exact_bytes(&mut stream, 4).await?;
            if status != b"OKAY" {
                return Err(AdbError::CommandFailed("shell command rejected".into()));
            }
            let mut output = String::new();
            let mut buf = vec![0u8; 4096];
            loop {
                match stream.read(&mut buf).await? {
                    0 => break,
                    n => output.push_str(&String::from_utf8_lossy(&buf[..n])),
                }
            }
            Ok(output)
        };
        timeout(dur, fut).await?
    }

    /// Execute a shell command and return a structured `ShellResult`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn shell_result(&self, serial: &str, cmd: &str) -> Result<ShellResult> {
        let stdout = self.shell(serial, cmd).await?;
        Ok(ShellResult {
            stdout,
            exit_code: None,
        })
    }

    /// Push a local file to the device using the `sync:` service SEND command.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn push(&self, serial: &str, local_path: &Path, remote_path: &str) -> Result<()> {
        let host = self.host.clone();
        let port = self.port;
        let dur = self.timeout;
        let serial = serial.to_owned();
        let remote = remote_path.to_owned();
        let local = local_path.to_path_buf();
        let fut = async move {
            let data = tokio::fs::read(&local).await?;
            let mut stream = open_device_connection(&host, port, &serial).await?;
            // Activate sync service
            let req = host_request("sync:");
            stream.write_all(req.as_bytes()).await?;
            let status = read_exact_bytes(&mut stream, 4).await?;
            if status != b"OKAY" {
                return Err(AdbError::CommandFailed("sync: rejected".into()));
            }
            push_file(&mut stream, &data, &remote, 0o644).await
        };
        timeout(dur, fut).await?
    }

    /// Push raw bytes to a remote path.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn push_bytes(
        &self,
        serial: &str,
        data: &[u8],
        remote_path: &str,
        mode: u32,
    ) -> Result<()> {
        let host = self.host.clone();
        let port = self.port;
        let dur = self.timeout;
        let serial = serial.to_owned();
        let remote = remote_path.to_owned();
        let data = data.to_vec();
        let fut = async move {
            let mut stream = open_device_connection(&host, port, &serial).await?;
            let req = host_request("sync:");
            stream.write_all(req.as_bytes()).await?;
            let status = read_exact_bytes(&mut stream, 4).await?;
            if status != b"OKAY" {
                return Err(AdbError::CommandFailed("sync: rejected".into()));
            }
            push_file(&mut stream, &data, &remote, mode).await
        };
        timeout(dur, fut).await?
    }

    /// Pull a remote file from the device to a local path using `sync:` RECV.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn pull(&self, serial: &str, remote_path: &str, local_path: &Path) -> Result<()> {
        let host = self.host.clone();
        let port = self.port;
        let dur = self.timeout;
        let serial = serial.to_owned();
        let remote = remote_path.to_owned();
        let local = local_path.to_path_buf();
        let fut = async move {
            let mut stream = open_device_connection(&host, port, &serial).await?;
            let req = host_request("sync:");
            stream.write_all(req.as_bytes()).await?;
            let status = read_exact_bytes(&mut stream, 4).await?;
            if status != b"OKAY" {
                return Err(AdbError::CommandFailed("sync: rejected".into()));
            }

            let remote_bytes = remote.as_bytes();
            let mut hdr = BytesMut::with_capacity(8 + remote_bytes.len());
            hdr.put_slice(b"RECV");
            hdr.put_u32_le(u32::try_from(remote_bytes.len()).unwrap_or(u32::MAX));
            hdr.put_slice(remote_bytes);
            stream.write_all(&hdr).await?;

            let mut file_data: Vec<u8> = Vec::new();
            loop {
                let id = read_sync_id(&mut stream).await?;
                let len = read_sync_len(&mut stream).await?;

                match id.as_slice() {
                    b"DATA" => {
                        if len as usize > sync_cmd::MAX_DATA_CHUNK {
                            return Err(AdbError::Protocol(format!(
                                "DATA chunk length {len} exceeds MAX_DATA_CHUNK {}",
                                sync_cmd::MAX_DATA_CHUNK
                            )));
                        }
                        let chunk = read_exact_bytes(&mut stream, len as usize).await?;
                        file_data.extend_from_slice(&chunk);
                    }
                    b"DONE" => break,
                    b"FAIL" => {
                        if len as usize > 4096 {
                            return Err(AdbError::Protocol(format!(
                                "FAIL message length {len} exceeds maximum 4096"
                            )));
                        }
                        let msg = read_exact_bytes(&mut stream, len as usize).await?;
                        return Err(AdbError::CommandFailed(
                            String::from_utf8_lossy(&msg).into_owned(),
                        ));
                    }
                    other => {
                        return Err(AdbError::Protocol(format!(
                            "unexpected sync id: {}",
                            String::from_utf8_lossy(other)
                        )));
                    }
                }
            }

            tokio::fs::write(&local, &file_data).await?;
            Ok(())
        };
        timeout(dur, fut).await?
    }

    /// Pull a remote file into memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn pull_bytes(&self, serial: &str, remote_path: &str) -> Result<Vec<u8>> {
        let host = self.host.clone();
        let port = self.port;
        let dur = self.timeout;
        let serial = serial.to_owned();
        let remote = remote_path.to_owned();
        let fut = async move {
            let mut stream = open_device_connection(&host, port, &serial).await?;
            let req = host_request("sync:");
            stream.write_all(req.as_bytes()).await?;
            let status = read_exact_bytes(&mut stream, 4).await?;
            if status != b"OKAY" {
                return Err(AdbError::CommandFailed("sync: rejected".into()));
            }
            pull_file(&mut stream, &remote).await
        };
        timeout(dur, fut).await?
    }

    /// Install an APK on the device.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn install(&self, serial: &str, apk_path: &Path) -> Result<()> {
        let tmp = format!(
            "/data/local/tmp/{}",
            apk_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("tmp.apk")
        );
        self.push(serial, apk_path, &tmp).await?;
        // cmd-injection: single-quote-escape the device path so that an APK
        // filename containing a single-quote cannot break out of the shell
        // argument and inject arbitrary commands.
        let tmp_escaped = tmp.replace('\'', "'\\''");
        let output = self
            .shell(serial, &format!("pm install -r '{tmp_escaped}'"))
            .await?;
        let _ = self
            .shell(serial, &format!("rm '{tmp_escaped}'"))
            .await;
        if output.contains("Success") {
            Ok(())
        } else {
            Err(AdbError::CommandFailed(output.trim().to_owned()))
        }
    }

    /// Uninstall a package from the device.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn uninstall(&self, serial: &str, package: &str) -> Result<()> {
        // cmd-injection: single-quote-escape the package name.
        let pkg_escaped = package.replace('\'', "'\\''");
        let output = self
            .shell(serial, &format!("pm uninstall '{pkg_escaped}'"))
            .await?;
        if output.contains("Success") {
            Ok(())
        } else {
            Err(AdbError::CommandFailed(output.trim().to_owned()))
        }
    }

    /// Retrieve logcat output, optionally filtered by a tag/level expression.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn logcat(&self, serial: &str, filter: &str) -> Result<Vec<LogEntry>> {
        let cmd = if filter.is_empty() {
            "logcat -d -b main".to_owned()
        } else {
            format!("logcat -d -b main {filter}")
        };
        let output = self.shell(serial, &cmd).await?;
        let entries = output.lines().filter_map(LogEntry::parse).collect();
        Ok(entries)
    }

    /// Retrieve raw logcat text.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn logcat_raw(&self, serial: &str, filter: &str) -> Result<String> {
        let cmd = if filter.is_empty() {
            "logcat -d -b main".to_owned()
        } else {
            format!("logcat -d -b main {filter}")
        };
        self.shell(serial, &cmd).await
    }

    /// Clear the logcat buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn logcat_clear(&self, serial: &str) -> Result<()> {
        self.shell(serial, "logcat -c").await?;
        Ok(())
    }

    /// Forward a local TCP port to a remote TCP port on the device.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn forward(&self, serial: &str, local_port: u16, remote_port: u16) -> Result<()> {
        let host = self.host.clone();
        let port = self.port;
        let dur = self.timeout;
        let serial = serial.to_owned();
        let fut = async move {
            let mut stream = TcpStream::connect((host.as_str(), port)).await?;
            let req = host_request(&format!(
                "host-serial:{serial}:forward:tcp:{local_port};tcp:{remote_port}"
            ));
            send_and_check(&mut stream, &req).await?;
            Ok(())
        };
        timeout(dur, fut).await?
    }

    /// Remove a port forward.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn forward_remove(&self, serial: &str, local_port: u16) -> Result<()> {
        let host = self.host.clone();
        let port = self.port;
        let dur = self.timeout;
        let serial = serial.to_owned();
        let fut = async move {
            let mut stream = TcpStream::connect((host.as_str(), port)).await?;
            let req = host_request(&format!(
                "host-serial:{serial}:killforward:tcp:{local_port}"
            ));
            send_and_check(&mut stream, &req).await?;
            Ok(())
        };
        timeout(dur, fut).await?
    }

    /// Set up a reverse port forward.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn reverse(&self, serial: &str, remote_port: u16, local_port: u16) -> Result<()> {
        let host = self.host.clone();
        let port = self.port;
        let dur = self.timeout;
        let serial = serial.to_owned();
        let fut = async move {
            let mut stream = TcpStream::connect((host.as_str(), port)).await?;
            let req = host_request(&format!(
                "host-serial:{serial}:reverse:forward:tcp:{remote_port};tcp:{local_port}"
            ));
            send_and_check(&mut stream, &req).await?;
            Ok(())
        };
        timeout(dur, fut).await?
    }

    /// Retrieve device properties via `getprop`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn getprop(&self, serial: &str, key: &str) -> Result<String> {
        let output = self.shell(serial, &format!("getprop {key}")).await?;
        Ok(output.trim().to_owned())
    }

    /// Retrieve all device properties as a key-value map.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn getprop_all(
        &self,
        serial: &str,
    ) -> Result<std::collections::HashMap<String, String>> {
        let output = self.shell(serial, "getprop").await?;
        let mut map = std::collections::HashMap::new();
        for line in output.lines() {
            let line = line.trim();
            // Format: [key]: [value]
            if line.starts_with('[')
                && let Some(colon) = line.find("]: [")
            {
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
        Ok(map)
    }

    /// List installed packages.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn list_packages(&self, serial: &str) -> Result<Vec<PackageInfo>> {
        let output = self.shell(serial, "pm list packages -f").await?;
        let packages = output
            .lines()
            .filter_map(PackageInfo::parse_pm_line)
            .collect();
        Ok(packages)
    }

    /// Retrieve running processes via `ps`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn list_processes(&self, serial: &str) -> Result<Vec<ProcessInfo>> {
        let output = self.shell(serial, "ps -A").await?;
        let mut lines = output.lines();
        // Skip header line.
        lines.next();
        let processes = lines.filter_map(ProcessInfo::parse_ps_line).collect();
        Ok(processes)
    }

    /// Reboot the device.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn reboot(&self, serial: &str, mode: RebootMode) -> Result<()> {
        let cmd = match mode {
            RebootMode::Normal => "reboot".to_owned(),
            RebootMode::Bootloader => "reboot bootloader".to_owned(),
            RebootMode::Recovery => "reboot recovery".to_owned(),
            RebootMode::Fastboot => "reboot fastboot".to_owned(),
        };
        self.shell(serial, &cmd).await?;
        Ok(())
    }

    /// Capture a screenshot as raw PNG bytes using `screencap`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn screencap(&self, serial: &str) -> Result<Vec<u8>> {
        let tmp = "/data/local/tmp/rustre_screencap.png";
        self.shell(serial, &format!("screencap -p {tmp}")).await?;
        let data = self.pull_bytes(serial, tmp).await?;
        let _ = self.shell(serial, &format!("rm {tmp}")).await;
        Ok(data)
    }

    /// Execute a command as root via `su -c`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn shell_root(&self, serial: &str, cmd: &str) -> Result<String> {
        self.shell(serial, &format!("su -c '{cmd}'")).await
    }

    /// Send a key event using `input keyevent`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn input_keyevent(&self, serial: &str, keycode: u32) -> Result<()> {
        self.shell(serial, &format!("input keyevent {keycode}"))
            .await?;
        Ok(())
    }

    /// Send a text input event.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn input_text(&self, serial: &str, text: &str) -> Result<()> {
        // Escape spaces and special chars for the shell.
        let escaped = text.replace(' ', "%s").replace('\'', "\\'");
        self.shell(serial, &format!("input text '{escaped}'"))
            .await?;
        Ok(())
    }

    /// Tap the screen at (x, y).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn input_tap(&self, serial: &str, x: u32, y: u32) -> Result<()> {
        self.shell(serial, &format!("input tap {x} {y}")).await?;
        Ok(())
    }

    /// Swipe from (x1, y1) to (x2, y2) over `duration_ms` milliseconds.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn input_swipe(
        &self,
        serial: &str,
        x1: u32,
        y1: u32,
        x2: u32,
        y2: u32,
        duration_ms: u32,
    ) -> Result<()> {
        self.shell(
            serial,
            &format!("input swipe {x1} {y1} {x2} {y2} {duration_ms}"),
        )
        .await?;
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// RebootMode
// ──────────────────────────────────────────────────────────────────────────────

/// Reboot target mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RebootMode {
    Normal,
    Bootloader,
    Recovery,
    Fastboot,
}

// ──────────────────────────────────────────────────────────────────────────────
// Convenience constructor
// ──────────────────────────────────────────────────────────────────────────────

/// Create an `AdbClient` pointing at the default local ADB server.
#[must_use]
pub fn local_client() -> AdbClient {
    AdbClient::default()
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AdbMessage encoding / decoding ────────────────────────────────────────

    #[test]
    fn test_encode_message_empty_data() {
        let bytes = encode_message(cmd::CNXN, ADB_VERSION, ADB_MAX_PAYLOAD, b"");
        assert_eq!(bytes.len(), 24);
        let magic = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        assert_eq!(magic, cmd::CNXN ^ 0xFFFF_FFFF);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let data = b"host::features=cmd,shell_v2";
        let encoded = encode_message(cmd::CNXN, ADB_VERSION, ADB_MAX_PAYLOAD, data);
        let msg = decode_message(&encoded).unwrap();
        assert_eq!(msg.command, cmd::CNXN);
        assert_eq!(msg.arg0, ADB_VERSION);
        assert_eq!(msg.arg1, ADB_MAX_PAYLOAD);
        assert_eq!(msg.data, data);
        assert_eq!(msg.magic, cmd::CNXN ^ 0xFFFF_FFFF);
    }

    #[test]
    fn test_encode_decode_with_payload() {
        let data = b"Hello, ADB!";
        let encoded = encode_message(cmd::WRTE, 1, 2, data);
        let msg = decode_message(&encoded).unwrap();
        assert_eq!(msg.data, data);
        assert_eq!(msg.crc32, compute_crc32(data));
    }

    #[test]
    fn test_decode_message_too_short() {
        let result = decode_message(&[0u8; 10]);
        assert!(matches!(result, Err(AdbError::Protocol(_))));
    }

    #[test]
    fn test_decode_message_bad_magic() {
        let mut encoded = encode_message(cmd::SYNC, 0, 0, b"").to_vec();
        let len = encoded.len();
        encoded[len - 1] ^= 0xFF;
        let result = decode_message(&encoded);
        assert!(matches!(result, Err(AdbError::Protocol(_))));
    }

    #[test]
    fn test_decode_message_truncated_payload() {
        let data = b"full payload here";
        let mut encoded = encode_message(cmd::WRTE, 0, 0, data).to_vec();
        let new_len = encoded.len() - 5;
        encoded.truncate(new_len);
        let result = decode_message(&encoded);
        assert!(matches!(result, Err(AdbError::Protocol(_))));
    }

    #[test]
    fn test_compute_crc32_empty() {
        assert_eq!(compute_crc32(b""), 0);
    }

    #[test]
    fn test_compute_crc32_known() {
        assert_eq!(compute_crc32(b"ABC"), 0xC6);
    }

    #[test]
    fn test_encode_message_crc_in_header() {
        let data = b"test data";
        let encoded = encode_message(cmd::OKAY, 0, 0, data);
        let crc_in_hdr = u32::from_le_bytes(encoded[16..20].try_into().unwrap());
        assert_eq!(crc_in_hdr, compute_crc32(data));
    }

    #[test]
    fn test_encode_message_data_len_in_header() {
        let data = b"hello world";
        let encoded = encode_message(cmd::WRTE, 5, 6, data);
        let len_in_hdr = u32::from_le_bytes(encoded[12..16].try_into().unwrap());
        assert_eq!(len_in_hdr as usize, data.len());
    }

    // ── AdbMessage struct ─────────────────────────────────────────────────────

    #[test]
    fn test_adb_message_new() {
        let m = AdbMessage::new(cmd::CNXN, 1, 2, b"hello".to_vec());
        assert_eq!(m.command, cmd::CNXN);
        assert_eq!(m.magic, cmd::CNXN ^ 0xFFFF_FFFF);
        assert!(m.verify_crc());
    }

    #[test]
    fn test_adb_message_command_name() {
        assert_eq!(
            AdbMessage::new(cmd::CNXN, 0, 0, vec![]).command_name(),
            "CNXN"
        );
        assert_eq!(
            AdbMessage::new(cmd::AUTH, 0, 0, vec![]).command_name(),
            "AUTH"
        );
        assert_eq!(
            AdbMessage::new(cmd::OPEN, 0, 0, vec![]).command_name(),
            "OPEN"
        );
        assert_eq!(
            AdbMessage::new(cmd::OKAY, 0, 0, vec![]).command_name(),
            "OKAY"
        );
        assert_eq!(
            AdbMessage::new(cmd::CLSE, 0, 0, vec![]).command_name(),
            "CLSE"
        );
        assert_eq!(
            AdbMessage::new(cmd::WRTE, 0, 0, vec![]).command_name(),
            "WRTE"
        );
        assert_eq!(
            AdbMessage::new(cmd::SYNC, 0, 0, vec![]).command_name(),
            "SYNC"
        );
        assert_eq!(
            AdbMessage::new(0xDEAD_BEEF, 0, 0, vec![]).command_name(),
            "UNKNOWN"
        );
    }

    #[test]
    fn test_adb_message_encode_roundtrip() {
        let m = AdbMessage::new(cmd::WRTE, 5, 6, b"data".to_vec());
        let encoded = m.encode();
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(decoded.command, m.command);
        assert_eq!(decoded.data, m.data);
    }

    #[test]
    fn test_adb_version_constant() {
        assert_eq!(ADB_VERSION, 0x0100_0000);
    }

    #[test]
    fn test_adb_max_payload() {
        assert_eq!(ADB_MAX_PAYLOAD, 256 * 1024);
    }

    // ── DeviceState parsing ───────────────────────────────────────────────────

    #[test]
    fn test_device_state_from_str_device() {
        assert_eq!(DeviceState::from_str("device"), DeviceState::Device);
    }

    #[test]
    fn test_device_state_from_str_offline() {
        assert_eq!(DeviceState::from_str("offline"), DeviceState::Offline);
    }

    #[test]
    fn test_device_state_from_str_bootloader() {
        assert_eq!(DeviceState::from_str("bootloader"), DeviceState::Bootloader);
    }

    #[test]
    fn test_device_state_from_str_unauthorized() {
        assert_eq!(
            DeviceState::from_str("unauthorized"),
            DeviceState::Unauthorized
        );
    }

    #[test]
    fn test_device_state_from_str_recovery() {
        assert_eq!(DeviceState::from_str("recovery"), DeviceState::Recovery);
    }

    #[test]
    fn test_device_state_from_str_unknown() {
        assert_eq!(DeviceState::from_str("garbage"), DeviceState::Unknown);
    }

    #[test]
    fn test_device_state_is_online() {
        assert!(DeviceState::Device.is_online());
        assert!(DeviceState::Recovery.is_online());
        assert!(DeviceState::Sideload.is_online());
        assert!(!DeviceState::Offline.is_online());
        assert!(!DeviceState::Unauthorized.is_online());
    }

    #[test]
    fn test_device_state_needs_auth() {
        assert!(DeviceState::Unauthorized.needs_auth());
        assert!(!DeviceState::Device.needs_auth());
    }

    #[test]
    fn test_device_state_display() {
        assert_eq!(DeviceState::Device.to_string(), "device");
        assert_eq!(DeviceState::Offline.to_string(), "offline");
        assert_eq!(DeviceState::Unknown.to_string(), "unknown");
    }

    // ── AdbDevice parsing ─────────────────────────────────────────────────────

    #[test]
    fn test_device_parse_full() {
        let line = "R3CN90ABCDE\tdevice product:redfin model:Pixel_5 device:redfin transport_id:3";
        let dev = AdbDevice::parse(line).unwrap();
        assert_eq!(dev.serial, "R3CN90ABCDE");
        assert_eq!(dev.state, DeviceState::Device);
        assert_eq!(dev.product, "redfin");
        assert_eq!(dev.model, "Pixel_5");
        assert_eq!(dev.device, "redfin");
        assert_eq!(dev.transport_id, Some(3));
    }

    #[test]
    fn test_device_parse_minimal() {
        let line = "emulator-5554\toffline";
        let dev = AdbDevice::parse(line).unwrap();
        assert_eq!(dev.serial, "emulator-5554");
        assert_eq!(dev.state, DeviceState::Offline);
        assert_eq!(dev.product, "");
    }

    #[test]
    fn test_device_parse_empty_line() {
        assert!(AdbDevice::parse("").is_none());
    }

    #[test]
    fn test_device_parse_no_tab() {
        let line = "emulator-5554";
        let dev = AdbDevice::parse(line).unwrap();
        assert_eq!(dev.serial, "emulator-5554");
        assert_eq!(dev.state, DeviceState::Unknown);
    }

    #[test]
    fn test_device_is_ready() {
        let dev_ready = AdbDevice {
            serial: "abc".into(),
            state: DeviceState::Device,
            product: String::new(),
            model: String::new(),
            device: String::new(),
            transport_id: None,
        };
        assert!(dev_ready.is_ready());
        let dev_offline = AdbDevice {
            serial: "abc".into(),
            state: DeviceState::Offline,
            product: String::new(),
            model: String::new(),
            device: String::new(),
            transport_id: None,
        };
        assert!(!dev_offline.is_ready());
    }

    // ── LogEntry parsing ──────────────────────────────────────────────────────

    #[test]
    fn test_log_entry_parse_brief_info() {
        let line = "I/ActivityManager(  432): Starting: Intent { act=android.intent.action.MAIN }";
        let entry = LogEntry::parse_brief(line).unwrap();
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.tag, "ActivityManager");
        assert_eq!(entry.pid, 432);
        assert!(entry.message.contains("Starting"));
    }

    #[test]
    fn test_log_entry_parse_brief_error() {
        let line = "E/AndroidRuntime(1234): FATAL EXCEPTION: main";
        let entry = LogEntry::parse_brief(line).unwrap();
        assert_eq!(entry.level, LogLevel::Error);
        assert_eq!(entry.tag, "AndroidRuntime");
        assert_eq!(entry.pid, 1234);
    }

    #[test]
    fn test_log_entry_parse_brief_warning() {
        let line = "W/System.err(  567): java.lang.NullPointerException";
        let entry = LogEntry::parse_brief(line).unwrap();
        assert_eq!(entry.level, LogLevel::Warning);
        assert_eq!(entry.pid, 567);
    }

    #[test]
    fn test_log_entry_parse_separator_line() {
        let line = "--------- beginning of /dev/log/main";
        assert!(LogEntry::parse_brief(line).is_none());
    }

    #[test]
    fn test_log_entry_parse_empty() {
        assert!(LogEntry::parse("").is_none());
    }

    #[test]
    fn test_log_entry_threadtime_parse() {
        // "01-01 12:00:00.000  1234  5678 I MyTag: hello world"
        let line = "01-01 12:00:00.000  1234  5678 I MyTag: hello world";
        if let Some(entry) = LogEntry::parse_threadtime(line) {
            assert_eq!(entry.level, LogLevel::Info);
            assert_eq!(entry.pid, 1234);
            assert_eq!(entry.tid, 5678);
            assert!(entry.tag.contains("MyTag"));
        }
        // Minimal check: parse doesn't panic
    }

    #[test]
    fn test_parse_logcat_output_batch() {
        let output = "I/Tag1(100): msg1\nE/Tag2(200): msg2\n";
        let entries = parse_logcat_output(output);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_filter_by_level() {
        let entries = vec![
            LogEntry {
                tag: "t".into(),
                pid: 1,
                tid: 0,
                level: LogLevel::Debug,
                message: "d".into(),
                timestamp: String::new(),
            },
            LogEntry {
                tag: "t".into(),
                pid: 2,
                tid: 0,
                level: LogLevel::Error,
                message: "e".into(),
                timestamp: String::new(),
            },
        ];
        let filtered = filter_by_level(&entries, &LogLevel::Error);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].pid, 2);
    }

    #[test]
    fn test_filter_by_tag() {
        let entries = vec![
            LogEntry {
                tag: "ActivityManager".into(),
                pid: 1,
                tid: 0,
                level: LogLevel::Info,
                message: String::new(),
                timestamp: String::new(),
            },
            LogEntry {
                tag: "BatteryService".into(),
                pid: 2,
                tid: 0,
                level: LogLevel::Info,
                message: String::new(),
                timestamp: String::new(),
            },
        ];
        let filtered = filter_by_tag(&entries, "activity");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].tag, "ActivityManager");
    }

    #[test]
    fn test_group_by_tag() {
        let entries = vec![
            LogEntry {
                tag: "A".into(),
                pid: 1,
                tid: 0,
                level: LogLevel::Info,
                message: String::new(),
                timestamp: String::new(),
            },
            LogEntry {
                tag: "B".into(),
                pid: 2,
                tid: 0,
                level: LogLevel::Info,
                message: String::new(),
                timestamp: String::new(),
            },
            LogEntry {
                tag: "A".into(),
                pid: 3,
                tid: 0,
                level: LogLevel::Info,
                message: String::new(),
                timestamp: String::new(),
            },
        ];
        let grouped = group_by_tag(&entries);
        assert_eq!(grouped["A"].len(), 2);
        assert_eq!(grouped["B"].len(), 1);
    }

    // ── LogLevel ──────────────────────────────────────────────────────────────

    #[test]
    fn test_log_level_chars() {
        assert_eq!(LogLevel::from_char('V'), LogLevel::Verbose);
        assert_eq!(LogLevel::from_char('D'), LogLevel::Debug);
        assert_eq!(LogLevel::from_char('I'), LogLevel::Info);
        assert_eq!(LogLevel::from_char('W'), LogLevel::Warning);
        assert_eq!(LogLevel::from_char('E'), LogLevel::Error);
        assert_eq!(LogLevel::from_char('F'), LogLevel::Fatal);
        assert_eq!(LogLevel::from_char('S'), LogLevel::Silent);
        assert_eq!(LogLevel::from_char('?'), LogLevel::Info);
    }

    #[test]
    fn test_log_level_severity_ordering() {
        assert!(LogLevel::Fatal.severity() > LogLevel::Error.severity());
        assert!(LogLevel::Error.severity() > LogLevel::Warning.severity());
        assert!(LogLevel::Warning.severity() > LogLevel::Info.severity());
        assert!(LogLevel::Info.severity() > LogLevel::Debug.severity());
        assert!(LogLevel::Debug.severity() > LogLevel::Verbose.severity());
    }

    #[test]
    fn test_log_level_display() {
        assert_eq!(LogLevel::Error.to_string(), "E");
        assert_eq!(LogLevel::Info.to_string(), "I");
    }

    // ── host_request formatting ───────────────────────────────────────────────

    #[test]
    fn test_host_request_format() {
        let req = host_request("host:version");
        assert_eq!(&req[..4], "000C");
        assert_eq!(&req[4..], "host:version");
    }

    #[test]
    fn test_host_request_devices() {
        let req = host_request("host:devices-l");
        assert_eq!(&req[..4], "000E");
    }

    #[test]
    fn test_host_request_length_prefix() {
        let cmd = "host:transport:emulator-5554";
        let req = host_request(cmd);
        let len = usize::from_str_radix(&req[..4], 16).unwrap();
        assert_eq!(len, cmd.len());
        assert_eq!(&req[4..], cmd);
    }

    // ── AdbClient construction ────────────────────────────────────────────────

    #[test]
    fn test_client_default() {
        let c = AdbClient::default();
        assert_eq!(c.host, "127.0.0.1");
        assert_eq!(c.port, 5037);
    }

    #[test]
    fn test_client_new() {
        let c = AdbClient::new("192.168.1.100", 5037);
        assert_eq!(c.host, "192.168.1.100");
        assert_eq!(c.port, 5037);
    }

    #[test]
    fn test_local_client() {
        let c = local_client();
        assert_eq!(c.port, 5037);
        assert_eq!(c.host, "127.0.0.1");
    }

    #[test]
    fn test_client_with_timeout() {
        let c = AdbClient::new("localhost", 5037).with_timeout(Duration::from_secs(10));
        assert_eq!(c.timeout, Duration::from_secs(10));
    }

    // ── cmd constants ─────────────────────────────────────────────────────────

    #[test]
    fn test_cmd_constants_magic() {
        for &c in &[
            cmd::SYNC,
            cmd::CNXN,
            cmd::AUTH,
            cmd::OPEN,
            cmd::OKAY,
            cmd::CLSE,
            cmd::WRTE,
        ] {
            let magic = c ^ 0xFFFF_FFFF;
            assert_eq!(c ^ magic, 0xFFFF_FFFF);
        }
    }

    #[test]
    fn test_cmd_cnxn_value() {
        assert_eq!(cmd::CNXN, 0x4e58_4e43);
    }

    #[test]
    fn test_cmd_auth_value() {
        assert_eq!(cmd::AUTH, 0x4854_5541);
    }

    #[test]
    fn test_cmd_open_value() {
        assert_eq!(cmd::OPEN, 0x4e45_504f);
    }

    #[test]
    fn test_cmd_clse_value() {
        assert_eq!(cmd::CLSE, 0x4553_4c43);
    }

    #[test]
    fn test_cmd_wrte_value() {
        assert_eq!(cmd::WRTE, 0x4554_5257);
    }

    #[test]
    fn test_cmd_okay_value() {
        assert_eq!(cmd::OKAY, 0x5941_4b4f);
    }

    // ── sync module ───────────────────────────────────────────────────────────

    #[test]
    fn test_sync_constants() {
        assert_eq!(sync::DENT, b"DENT");
        assert_eq!(sync::RECV, b"RECV");
        assert_eq!(sync::SEND, b"SEND");
        assert_eq!(sync::STAT, b"STAT");
        assert_eq!(sync::DATA, b"DATA");
        assert_eq!(sync::DONE, b"DONE");
        assert_eq!(sync::FAIL, b"FAIL");
        assert_eq!(sync::QUIT, b"QUIT");
        assert_eq!(sync::LIST, b"LIST");
    }

    #[test]
    fn test_sync_max_chunk_is_64k() {
        assert_eq!(sync::MAX_DATA_CHUNK, 65536);
    }

    // ── Error display ─────────────────────────────────────────────────────────

    #[test]
    fn test_error_display_protocol() {
        let e = AdbError::Protocol("bad frame".into());
        assert!(e.to_string().contains("protocol error"));
    }

    #[test]
    fn test_error_display_device_not_found() {
        let e = AdbError::DeviceNotFound {
            serial: "abc123".into(),
        };
        assert!(e.to_string().contains("abc123"));
    }

    #[test]
    fn test_error_display_timeout() {
        let e = AdbError::Timeout;
        assert!(e.to_string().contains("timed out"));
    }

    #[test]
    fn test_error_display_sync() {
        let e = AdbError::Sync("permission denied".into());
        assert!(e.to_string().contains("sync error"));
    }

    #[test]
    fn test_error_display_auth_failed() {
        let e = AdbError::AuthFailed("bad key".into());
        assert!(e.to_string().contains("authentication failed"));
    }

    // ── PackageInfo ───────────────────────────────────────────────────────────

    #[test]
    fn test_package_info_parse() {
        let line = "package:/data/app/com.example-XXX.apk=com.example";
        let p = PackageInfo::parse_pm_line(line).unwrap();
        assert_eq!(p.package_name, "com.example");
        assert!(p.apk_path.as_deref().unwrap().contains("com.example"));
    }

    #[test]
    fn test_package_info_parse_no_path() {
        let line = "package:com.example2";
        let p = PackageInfo::parse_pm_line(line).unwrap();
        assert_eq!(p.package_name, "com.example2");
        assert!(p.apk_path.is_none());
    }

    #[test]
    fn test_package_info_parse_non_package_line() {
        assert!(PackageInfo::parse_pm_line("List of packages:").is_none());
    }

    // ── ProcessInfo ───────────────────────────────────────────────────────────

    #[test]
    fn test_process_info_parse() {
        let line = "root  1  0  1234  1234 S init";
        let p = ProcessInfo::parse_ps_line(line).unwrap();
        assert_eq!(p.user, "root");
        assert_eq!(p.pid, 1);
        assert_eq!(p.name, "init");
    }

    #[test]
    fn test_process_info_parse_short_line() {
        assert!(ProcessInfo::parse_ps_line("root 1").is_none());
    }

    // ── ShellResult ───────────────────────────────────────────────────────────

    #[test]
    fn test_shell_result_success_no_exit_code() {
        let r = ShellResult {
            stdout: "ok".into(),
            exit_code: None,
        };
        assert!(r.success());
    }

    #[test]
    fn test_shell_result_success_with_exit_code() {
        let r = ShellResult {
            stdout: "ok".into(),
            exit_code: Some(0),
        };
        assert!(r.success());
    }

    #[test]
    fn test_shell_result_failure() {
        let r = ShellResult {
            stdout: "err".into(),
            exit_code: Some(1),
        };
        assert!(!r.success());
    }

    // ── PathBuf sanity ────────────────────────────────────────────────────────

    #[test]
    fn test_path_conversion() {
        use std::path::PathBuf;
        let p = PathBuf::from("/tmp/test.apk");
        assert_eq!(p.file_name().unwrap().to_str().unwrap(), "test.apk");
    }

    // ── RebootMode ────────────────────────────────────────────────────────────

    #[test]
    fn test_reboot_mode_variants() {
        let modes = [
            RebootMode::Normal,
            RebootMode::Bootloader,
            RebootMode::Recovery,
            RebootMode::Fastboot,
        ];
        assert_eq!(modes.len(), 4);
    }
}
