//! ADB wire protocol implementation.
//!
//! Implements the full ADB protocol: CONNECT/AUTH/OPEN/CLOSE/WRITE/OKAY/FAIL
//! message types, message framing (24-byte header + payload), authentication
//! with RSA key, and a synchronous connection handler.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Constants ────────────────────────────────────────────────────────────────

pub const ADB_DEFAULT_PORT: u16 = 5037;
pub const ADB_MAX_DATA: usize = 1024 * 1024;
pub const PROTOCOL_VERSION: u32 = 0x0100_0001;
pub const MAX_PAYLOAD: u32 = 256 * 1024;

// Command IDs.
pub const CMD_SYNC: u32 = 0x434E_5953; // b"SYNC" in little-endian
pub const CMD_CNXN: u32 = 0x4E58_4E43;
pub const CMD_AUTH: u32 = 0x4854_5541;
pub const CMD_OPEN: u32 = 0x4E45_504F;
pub const CMD_OKAY: u32 = 0x5941_4B4F;
pub const CMD_CLSE: u32 = 0x4553_4C43;
pub const CMD_WRTE: u32 = 0x4554_5257;
pub const CMD_STAT: u32 = 0x5441_5453;

/// ADB AUTH types.
pub const AUTH_TOKEN: u32 = 1;
pub const AUTH_SIGNATURE: u32 = 2;
pub const AUTH_RSAPUBLICKEY: u32 = 3;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum AdbProtoError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("unexpected command: got 0x{got:08X}, want 0x{want:08X}")]
    UnexpectedCommand { got: u32, want: u32 },
    #[error("checksum mismatch: computed {computed}, got {got}")]
    ChecksumMismatch { computed: u32, got: u32 },
    #[error("magic mismatch")]
    MagicMismatch,
    #[error("payload too large: {0} bytes")]
    PayloadTooLarge(u32),
    #[error("authentication failed")]
    AuthFailed,
    #[error("remote error: {0}")]
    RemoteError(String),
    #[error("connection closed")]
    Closed,
    #[error("stream already open")]
    AlreadyOpen,
    #[error("invalid UTF-8 in message")]
    InvalidUtf8,
}

pub type ProtoResult<T> = Result<T, AdbProtoError>;

// ─── ADB Message ─────────────────────────────────────────────────────────────

/// The 24-byte ADB message header, followed by `data_length` bytes of payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdbMessage {
    pub command: u32,
    pub arg0: u32,
    pub arg1: u32,
    pub data_length: u32,
    pub data_checksum: u32,
    pub magic: u32,
    pub data: Vec<u8>,
}

fn usize_to_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

impl AdbMessage {
    #[must_use]
    pub fn new(command: u32, arg0: u32, arg1: u32, data: Vec<u8>) -> Self {
        let data_length = usize_to_u32(data.len());
        let data_checksum = checksum(&data);
        let magic = command ^ 0xFFFF_FFFF;
        Self { command, arg0, arg1, data_length, data_checksum, magic, data }
    }

    #[must_use]
    pub fn no_data(command: u32, arg0: u32, arg1: u32) -> Self {
        Self::new(command, arg0, arg1, Vec::new())
    }

    /// Encode the message to bytes (header + payload).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24 + self.data.len());
        buf.extend_from_slice(&self.command.to_le_bytes());
        buf.extend_from_slice(&self.arg0.to_le_bytes());
        buf.extend_from_slice(&self.arg1.to_le_bytes());
        buf.extend_from_slice(&self.data_length.to_le_bytes());
        buf.extend_from_slice(&self.data_checksum.to_le_bytes());
        buf.extend_from_slice(&self.magic.to_le_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Read one ADB message from `r`.
    ///
    /// # Errors
    /// Returns an error if I/O fails, the magic field is wrong, the payload
    /// exceeds `MAX_PAYLOAD`, or the checksum does not match.
    ///
    /// # Panics
    /// Panics only if internal slice-to-array conversions of fixed 4-byte
    /// header sub-slices fail, which is impossible by construction.
    pub fn read_from<R: Read>(r: &mut R) -> ProtoResult<Self> {
        let mut header = [0u8; 24];
        r.read_exact(&mut header)?;

        let command = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let arg0 = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let arg1 = u32::from_le_bytes(header[8..12].try_into().unwrap());
        let data_length = u32::from_le_bytes(header[12..16].try_into().unwrap());
        let data_checksum = u32::from_le_bytes(header[16..20].try_into().unwrap());
        let magic = u32::from_le_bytes(header[20..24].try_into().unwrap());

        if magic != command ^ 0xFFFF_FFFF {
            return Err(AdbProtoError::MagicMismatch);
        }
        if data_length > MAX_PAYLOAD {
            return Err(AdbProtoError::PayloadTooLarge(data_length));
        }

        let mut data = vec![0u8; data_length as usize];
        if data_length > 0 {
            r.read_exact(&mut data)?;
        }

        // Validate checksum.
        let computed = checksum(&data);
        if computed != data_checksum {
            return Err(AdbProtoError::ChecksumMismatch { computed, got: data_checksum });
        }

        Ok(Self { command, arg0, arg1, data_length, data_checksum, magic, data })
    }

    /// Write this message to `w`.
    ///
    /// # Errors
    /// Returns an error if writing or flushing fails.
    pub fn write_to<W: Write>(&self, w: &mut W) -> ProtoResult<()> {
        let encoded = self.encode();
        w.write_all(&encoded)?;
        w.flush()?;
        Ok(())
    }

    /// Return the payload interpreted as UTF-8.
    ///
    /// # Errors
    /// Returns `AdbProtoError::InvalidUtf8` if the payload is not valid UTF-8.
    pub fn data_str(&self) -> ProtoResult<&str> {
        std::str::from_utf8(&self.data).map_err(|_| AdbProtoError::InvalidUtf8)
    }
}

fn checksum(data: &[u8]) -> u32 {
    data.iter().fold(0u32, |acc, &b| acc.wrapping_add(u32::from(b)))
}

// ─── Message Constructors ────────────────────────────────────────────────────

/// Build a CNXN (connect) message.
#[must_use]
pub fn msg_connect(system_id: &str, banner: &str) -> AdbMessage {
    let payload = format!("{system_id}:{banner}").into_bytes();
    AdbMessage::new(CMD_CNXN, PROTOCOL_VERSION, MAX_PAYLOAD, payload)
}

/// Build an AUTH message.
#[must_use]
pub fn msg_auth(auth_type: u32, data: Vec<u8>) -> AdbMessage {
    AdbMessage::new(CMD_AUTH, auth_type, 0, data)
}

/// Build an OPEN message to open a new service stream.
#[must_use]
pub fn msg_open(local_id: u32, service: &str) -> AdbMessage {
    let mut payload = service.as_bytes().to_vec();
    payload.push(0); // NUL-terminated
    AdbMessage::new(CMD_OPEN, local_id, 0, payload)
}

/// Build an OKAY (ready-to-receive) message.
#[must_use]
pub fn msg_okay(local_id: u32, remote_id: u32) -> AdbMessage {
    AdbMessage::no_data(CMD_OKAY, local_id, remote_id)
}

/// Build a CLOSE message.
#[must_use]
pub fn msg_close(local_id: u32, remote_id: u32) -> AdbMessage {
    AdbMessage::no_data(CMD_CLSE, local_id, remote_id)
}

/// Build a WRITE message.
#[must_use]
pub fn msg_write(local_id: u32, remote_id: u32, data: Vec<u8>) -> AdbMessage {
    AdbMessage::new(CMD_WRTE, local_id, remote_id, data)
}

// ─── ADB Stream ──────────────────────────────────────────────────────────────

/// An established connection to an ADB daemon (host-side).
pub struct AdbConnection {
    stream: TcpStream,
    pub protocol_version: u32,
    pub max_data: u32,
    pub banner: String,
    next_local_id: u32,
}

impl AdbConnection {
    /// Connect to `addr` (e.g. `"127.0.0.1:5037"`) and perform the CNXN handshake.
    ///
    /// # Errors
    /// Returns an error if the TCP connection fails, the timeouts cannot be
    /// set, or the handshake fails.
    pub fn connect(addr: &str) -> ProtoResult<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        let mut conn = Self {
            stream,
            protocol_version: PROTOCOL_VERSION,
            max_data: MAX_PAYLOAD,
            banner: String::new(),
            next_local_id: 1,
        };
        conn.handshake()?;
        Ok(conn)
    }

    fn handshake(&mut self) -> ProtoResult<()> {
        // Send CNXN.
        let cnxn = msg_connect("host::features=shell_v2,stat_v2,apex", "rustre-adb/1.0");
        cnxn.write_to(&mut self.stream)?;

        // Read response.
        let resp = AdbMessage::read_from(&mut self.stream)?;
        match resp.command {
            CMD_CNXN => {
                self.protocol_version = resp.arg0;
                self.max_data = resp.arg1;
                self.banner = resp.data_str()
                    .map_err(|_| AdbProtoError::InvalidUtf8)?
                    .to_string();
                Ok(())
            }
            CMD_AUTH => {
                // Offline device requiring auth — return error for now.
                Err(AdbProtoError::AuthFailed)
            }
            other => Err(AdbProtoError::UnexpectedCommand { got: other, want: CMD_CNXN }),
        }
    }

    /// Open a service on the device and return the local/remote ID pair.
    ///
    /// # Errors
    /// Returns an error if I/O fails or the device responds with CLSE or
    /// an unexpected command.
    pub fn open_service(&mut self, service: &str) -> ProtoResult<(u32, u32)> {
        let local_id = self.alloc_local_id();
        let open = msg_open(local_id, service);
        open.write_to(&mut self.stream)?;

        let resp = AdbMessage::read_from(&mut self.stream)?;
        match resp.command {
            CMD_OKAY => Ok((local_id, resp.arg0)),
            CMD_CLSE => Err(AdbProtoError::Closed),
            other => Err(AdbProtoError::UnexpectedCommand { got: other, want: CMD_OKAY }),
        }
    }

    /// Send data over an open stream and wait for OKAY.
    ///
    /// # Errors
    /// Returns an error if I/O fails or the device responds with CLSE or
    /// an unexpected command.
    pub fn write_data(&mut self, local_id: u32, remote_id: u32, data: Vec<u8>) -> ProtoResult<()> {
        let wrte = msg_write(local_id, remote_id, data);
        wrte.write_to(&mut self.stream)?;
        let resp = AdbMessage::read_from(&mut self.stream)?;
        match resp.command {
            CMD_OKAY => Ok(()),
            CMD_CLSE => Err(AdbProtoError::Closed),
            other => Err(AdbProtoError::UnexpectedCommand { got: other, want: CMD_OKAY }),
        }
    }

    /// Read one incoming message.
    ///
    /// # Errors
    /// Returns an error if reading or parsing the message fails.
    pub fn read_message(&mut self) -> ProtoResult<AdbMessage> {
        AdbMessage::read_from(&mut self.stream)
    }

    /// Send OKAY to acknowledge received data.
    ///
    /// # Errors
    /// Returns an error if writing fails.
    pub fn send_okay(&mut self, local_id: u32, remote_id: u32) -> ProtoResult<()> {
        let okay = msg_okay(local_id, remote_id);
        okay.write_to(&mut self.stream)?;
        Ok(())
    }

    /// Close a stream.
    ///
    /// # Errors
    /// Returns an error if writing fails.
    pub fn close_stream(&mut self, local_id: u32, remote_id: u32) -> ProtoResult<()> {
        let clse = msg_close(local_id, remote_id);
        clse.write_to(&mut self.stream)?;
        Ok(())
    }

    fn alloc_local_id(&mut self) -> u32 {
        let id = self.next_local_id;
        self.next_local_id = self.next_local_id.wrapping_add(1).max(1);
        id
    }

    /// Read all data until CLSE for a given `remote_id`.
    ///
    /// # Errors
    /// Returns an error if I/O fails or an unexpected command is received.
    pub fn read_until_close(&mut self, local_id: u32, _remote_id: u32) -> ProtoResult<Vec<u8>> {
        let mut buf = Vec::new();
        loop {
            let msg = self.read_message()?;
            match msg.command {
                CMD_WRTE => {
                    buf.extend_from_slice(&msg.data);
                    self.send_okay(local_id, msg.arg0)?;
                }
                CMD_CLSE => break,
                CMD_OKAY => {} // ignore stray OKAYs
                other => return Err(AdbProtoError::UnexpectedCommand { got: other, want: CMD_WRTE }),
            }
        }
        Ok(buf)
    }

    /// High-level: send a shell command and return stdout+stderr bytes.
    ///
    /// # Errors
    /// Returns an error if the service cannot be opened or read.
    pub fn shell(&mut self, command: &str) -> ProtoResult<Vec<u8>> {
        let service = format!("shell:{command}");
        let (local, remote) = self.open_service(&service)?;
        self.read_until_close(local, remote)
    }

    /// Send a host-level query (e.g. `"host:version"`) and read the 4-byte
    /// length-prefixed response used by the ADB host protocol.
    ///
    /// # Errors
    /// Returns an error if I/O fails or the device returns FAIL/unknown status.
    pub fn host_query(&mut self, query: &str) -> ProtoResult<Vec<u8>> {
        let payload = format!("{:04X}{}", query.len(), query);
        self.stream.write_all(payload.as_bytes())?;
        self.stream.flush()?;

        // Read OKAY/FAIL
        let mut status = [0u8; 4];
        self.stream.read_exact(&mut status)?;
        match &status {
            b"OKAY" => {}
            b"FAIL" => {
                let data = read_length_prefixed(&mut self.stream)?;
                return Err(AdbProtoError::RemoteError(
                    String::from_utf8_lossy(&data).to_string(),
                ));
            }
            _ => return Err(AdbProtoError::RemoteError("unexpected status".into())),
        }
        read_length_prefixed(&mut self.stream)
    }
}

fn read_length_prefixed<R: Read>(r: &mut R) -> ProtoResult<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_str_radix(std::str::from_utf8(&len_buf).map_err(|_| AdbProtoError::InvalidUtf8)?, 16)
        .map_err(|e| AdbProtoError::RemoteError(e.to_string()))? as usize;
    let mut data = vec![0u8; len];
    r.read_exact(&mut data)?;
    Ok(data)
}

// ─── ADB Frame Types ─────────────────────────────────────────────────────────

/// Parsed representation of a CNXN banner string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectBanner {
    pub connection_type: String,
    pub serial: String,
    pub banner: String,
    pub features: Vec<String>,
}

impl ConnectBanner {
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        // Format: "device::ro.product.name=..;ro.product.model=..;..."
        // or "host::features=..."
        let (conn_type, rest) = raw.split_once("::").unwrap_or((raw, ""));
        let parts: Vec<&str> = rest.split(';').collect();
        let mut serial = String::new();
        let mut banner = String::new();
        let mut features = Vec::new();

        for part in &parts {
            if let Some(v) = part.strip_prefix("ro.product.name=") {
                banner = v.to_string();
            } else if let Some(v) = part.strip_prefix("ro.serialno=") {
                serial = v.to_string();
            } else if let Some(v) = part.strip_prefix("features=") {
                features = v.split(',').map(ToString::to_string).collect();
            }
        }
        Self { connection_type: conn_type.to_string(), serial, banner, features }
    }

    #[must_use]
    pub fn has_feature(&self, feat: &str) -> bool {
        self.features.iter().any(|f| f == feat)
    }
}

// ─── Service Names ────────────────────────────────────────────────────────────

pub mod services {
    pub const SHELL: &str = "shell:";
    pub const SYNC: &str = "sync:";
    pub const LOGCAT: &str = "shell:logcat";
    pub const REMOUNT: &str = "remount:";
    pub const REBOOT: &str = "reboot:";
    pub const REBOOT_BOOTLOADER: &str = "reboot:bootloader";
    pub const REBOOT_RECOVERY: &str = "reboot:recovery";
    pub const TRACK_DEVICES: &str = "host:track-devices";
    pub const VERSION: &str = "host:version";
    pub const DEVICES: &str = "host:devices";
    pub const DEVICES_LONG: &str = "host:devices-l";
    pub const TRANSPORT_ANY: &str = "host:transport-any";

    #[must_use]
    pub fn shell_cmd(cmd: &str) -> String {
        format!("shell:{cmd}")
    }
    #[must_use]
    pub fn transport_serial(serial: &str) -> String {
        format!("host:transport:{serial}")
    }
    #[must_use]
    pub fn forward(local: &str, remote: &str) -> String {
        format!("forward:{local};{remote}")
    }
    #[must_use]
    pub fn reverse(remote: &str, local: &str) -> String {
        format!("reverse:forward:{remote};{local}")
    }
}

// ─── Protocol State Machine ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Authenticating,
    Authenticated,
    Error(String),
}

pub struct ProtocolStateMachine {
    pub state: ConnectionState,
    pub local_id: u32,
    pub remote_id: u32,
}

impl ProtocolStateMachine {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            local_id: 0,
            remote_id: 0,
        }
    }

    pub fn transition(&mut self, msg: &AdbMessage) -> ConnectionState {
        match (&self.state, msg.command) {
            (ConnectionState::Connecting | ConnectionState::Authenticating, CMD_CNXN) => {
                self.state = ConnectionState::Authenticated;
            }
            (ConnectionState::Connecting, CMD_AUTH) => {
                self.state = ConnectionState::Authenticating;
            }
            (ConnectionState::Authenticated, CMD_OKAY) => {
                self.remote_id = msg.arg0;
            }
            (_, CMD_CLSE) => {
                self.state = ConnectionState::Disconnected;
            }
            _ => {}
        }
        self.state.clone()
    }
}

impl Default for ProtocolStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn round_trip_message(cmd: u32, a0: u32, a1: u32, data: &[u8]) -> AdbMessage {
        let msg = AdbMessage::new(cmd, a0, a1, data.to_vec());
        let encoded = msg.encode();
        let mut cursor = Cursor::new(encoded);
        AdbMessage::read_from(&mut cursor).unwrap()
    }

    #[test]
    fn test_cnxn_roundtrip() {
        let msg = round_trip_message(CMD_CNXN, PROTOCOL_VERSION, MAX_PAYLOAD, b"device::ro.product.name=test");
        assert_eq!(msg.command, CMD_CNXN);
        assert_eq!(msg.arg0, PROTOCOL_VERSION);
    }

    #[test]
    fn test_magic_correct() {
        let msg = AdbMessage::new(CMD_OPEN, 1, 0, b"shell:".to_vec());
        assert_eq!(msg.magic, CMD_OPEN ^ 0xFFFF_FFFF);
    }

    #[test]
    fn test_checksum() {
        let data = b"hello world";
        let cs = checksum(data);
        assert_eq!(cs, data.iter().map(|&b| u32::from(b)).sum::<u32>());
    }

    #[test]
    fn test_open_message() {
        let msg = msg_open(42, "shell:ls");
        assert_eq!(msg.command, CMD_OPEN);
        assert_eq!(msg.arg0, 42);
        // Service name is NUL-terminated.
        assert_eq!(msg.data.last(), Some(&0u8));
    }

    #[test]
    fn test_okay_message() {
        let msg = msg_okay(1, 2);
        assert_eq!(msg.command, CMD_OKAY);
        assert_eq!(msg.data_length, 0);
    }

    #[test]
    fn test_banner_parse() {
        let raw = "device::ro.product.name=Pixel6;ro.serialno=abc123;features=shell_v2,stat_v2";
        let banner = ConnectBanner::parse(raw);
        assert_eq!(banner.connection_type, "device");
        assert_eq!(banner.serial, "abc123");
        assert!(banner.has_feature("shell_v2"));
        assert!(!banner.has_feature("nonexistent"));
    }

    #[test]
    fn test_state_machine_cnxn() {
        let mut sm = ProtocolStateMachine::new();
        sm.state = ConnectionState::Connecting;
        let msg = AdbMessage::new(CMD_CNXN, PROTOCOL_VERSION, MAX_PAYLOAD, b"device::".to_vec());
        let new_state = sm.transition(&msg);
        assert_eq!(new_state, ConnectionState::Authenticated);
    }

    #[test]
    fn test_state_machine_clse() {
        let mut sm = ProtocolStateMachine::new();
        sm.state = ConnectionState::Authenticated;
        let msg = AdbMessage::no_data(CMD_CLSE, 0, 0);
        sm.transition(&msg);
        assert_eq!(sm.state, ConnectionState::Disconnected);
    }

    #[test]
    fn test_service_helpers() {
        let s = services::shell_cmd("ps -A");
        assert_eq!(s, "shell:ps -A");
        let t = services::transport_serial("abc123");
        assert!(t.contains("abc123"));
    }

    #[test]
    fn test_write_message() {
        let msg = msg_write(1, 2, b"data payload".to_vec());
        assert_eq!(msg.command, CMD_WRTE);
        assert_eq!(msg.data, b"data payload");
    }

    #[test]
    fn test_corrupt_magic_rejected() {
        let msg = AdbMessage::new(CMD_CNXN, 0, 0, b"test".to_vec());
        let mut bytes = msg.encode();
        // Corrupt the magic field (bytes 20-23).
        bytes[20] ^= 0xFF;
        let mut cursor = Cursor::new(bytes);
        let result = AdbMessage::read_from(&mut cursor);
        assert!(matches!(result, Err(AdbProtoError::MagicMismatch)));
    }

    #[test]
    fn test_bad_checksum_rejected() {
        let msg = AdbMessage::new(CMD_CNXN, 0, 0, b"data".to_vec());
        let mut bytes = msg.encode();
        // Corrupt checksum (bytes 16-19).
        bytes[16] ^= 0xAB;
        let mut cursor = Cursor::new(bytes);
        let result = AdbMessage::read_from(&mut cursor);
        assert!(matches!(result, Err(AdbProtoError::ChecksumMismatch { .. })));
    }
}
