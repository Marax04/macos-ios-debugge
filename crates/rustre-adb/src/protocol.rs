//! # protocol.rs — Complete ADB Wire Protocol
//!
//! Implements the ADB binary transport layer (24-byte header + payload) used
//! for USB-direct and raw TCP connections that bypass the host ADB server.
//!
//! ## Message layout
//! ```text
//! ┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────┐
//! │ command  │  arg0    │  arg1    │ data_len │  crc32   │  magic   │
//! │  (u32le) │  (u32le) │  (u32le) │  (u32le) │  (u32le) │  (u32le) │
//! └──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘
//!  <─────────────────────── 24 bytes ──────────────────────────────>
//!  <────────────── followed by data_len bytes of payload ─────────>
//! ```
//!
//! The magic field is always `command ^ 0xFFFF_FFFF`.
//! The CRC32 is a simple byte-sum (not IEEE CRC-32).

use std::io;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

use crate::{ADB_MAX_PAYLOAD, ADB_VERSION, AdbError, Result, cmd};

// ─── Minimal Base64 encoder ───────────────────────────────────────────────────
// Avoids a hard dependency on the `base64` crate for the single public-key
// formatting call that needs it.

const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 2 < data.len() {
        let b0 = data[i] as usize;
        let b1 = data[i + 1] as usize;
        let b2 = data[i + 2] as usize;
        out.push(B64_TABLE[(b0 >> 2) & 0x3F]);
        out.push(B64_TABLE[((b0 << 4) | (b1 >> 4)) & 0x3F]);
        out.push(B64_TABLE[((b1 << 2) | (b2 >> 6)) & 0x3F]);
        out.push(B64_TABLE[b2 & 0x3F]);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let b0 = data[i] as usize;
        out.push(B64_TABLE[(b0 >> 2) & 0x3F]);
        out.push(B64_TABLE[(b0 << 4) & 0x3F]);
        out.push(b'=');
        out.push(b'=');
    } else if rem == 2 {
        let b0 = data[i] as usize;
        let b1 = data[i + 1] as usize;
        out.push(B64_TABLE[(b0 >> 2) & 0x3F]);
        out.push(B64_TABLE[((b0 << 4) | (b1 >> 4)) & 0x3F]);
        out.push(B64_TABLE[(b1 << 2) & 0x3F]);
        out.push(b'=');
    }
    String::from_utf8(out).expect("base64 output is always ASCII")
}

// ─── Auth token types ─────────────────────────────────────────────────────────

/// ADB AUTH subtypes sent in arg0 of AUTH messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum AuthType {
    /// Server sends a random token for the client to sign.
    Token = 1,
    /// Client sends RSA signature of the token.
    Signature = 2,
    /// Client sends its RSA public key (plain text) for the user to accept.
    RsaPublicKey = 3,
}

impl AuthType {
    /// Convert from raw u32, returning `None` for unknown values.
    #[must_use]
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Token),
            2 => Some(Self::Signature),
            3 => Some(Self::RsaPublicKey),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

// ─── StreamId / transport identifiers ────────────────────────────────────────

/// A local stream identifier (arg0 in OPEN/OKAY/CLSE/WRTE from host side).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LocalId(pub u32);

/// A remote stream identifier (arg1 in OKAY/CLSE/WRTE from device side).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RemoteId(pub u32);

// ─── Typed message constructors ───────────────────────────────────────────────

/// Build a CNXN (Connect) message from the host side.
///
/// `system_type` is typically `"host"` from a PC; the device sends back its
/// own `"device::ro.product.name=…;ro.product.model=…"` banner.
///
/// ```
/// use rustre_adb::protocol::make_connect;
/// let msg = make_connect("host", "RustRE/1.0");
/// assert_eq!(msg.command, rustre_adb::cmd::CNXN);
/// ```
#[must_use]
pub fn make_connect(system_type: &str, banner: &str) -> crate::AdbMessage {
    // Payload: "<system_type>::<banner>\0"
    let payload = format!("{system_type}::{banner}\0");
    crate::AdbMessage::new(
        cmd::CNXN,
        ADB_VERSION,
        ADB_MAX_PAYLOAD,
        payload.into_bytes(),
    )
}

/// Build a CNXN reply that a device sends back after receiving a host CNXN.
#[must_use]
pub fn make_connect_device(serial: &str, model: &str) -> crate::AdbMessage {
    let banner = format!(
        "device::ro.product.name={serial};ro.product.model={model};ro.product.device={serial}"
    );
    crate::AdbMessage::new(cmd::CNXN, ADB_VERSION, ADB_MAX_PAYLOAD, banner.into_bytes())
}

/// Build an AUTH TOKEN message (device → host, arg0 = 1).
#[must_use]
pub fn make_auth_token(token: Vec<u8>) -> crate::AdbMessage {
    crate::AdbMessage::new(cmd::AUTH, AuthType::Token.as_u32(), 0, token)
}

/// Build an AUTH SIGNATURE message (host → device, arg0 = 2).
#[must_use]
pub fn make_auth_signature(signature: Vec<u8>) -> crate::AdbMessage {
    crate::AdbMessage::new(cmd::AUTH, AuthType::Signature.as_u32(), 0, signature)
}

/// Build an AUTH RSAPUBLICKEY message (host → device, arg0 = 3).
#[must_use]
pub fn make_auth_public_key(public_key_pem: &str) -> crate::AdbMessage {
    let mut payload = public_key_pem.as_bytes().to_vec();
    payload.push(0); // NUL terminator
    crate::AdbMessage::new(cmd::AUTH, AuthType::RsaPublicKey.as_u32(), 0, payload)
}

/// Build an OPEN message opening stream `local_id` to the named service.
///
/// `service` examples: `"shell:ls -la"`, `"sync:"`, `"tcp:8080"`.
#[must_use]
pub fn make_open(local_id: LocalId, service: &str) -> crate::AdbMessage {
    let mut payload = service.as_bytes().to_vec();
    payload.push(0); // NUL terminator required by protocol
    crate::AdbMessage::new(cmd::OPEN, local_id.0, 0, payload)
}

/// Build an OKAY message acknowledging a stream write or opening.
#[must_use]
pub fn make_okay(local_id: LocalId, remote_id: RemoteId) -> crate::AdbMessage {
    crate::AdbMessage::new(cmd::OKAY, local_id.0, remote_id.0, vec![])
}

/// Build a CLSE message closing a stream.
#[must_use]
pub fn make_close(local_id: LocalId, remote_id: RemoteId) -> crate::AdbMessage {
    crate::AdbMessage::new(cmd::CLSE, local_id.0, remote_id.0, vec![])
}

/// Build a WRTE message carrying `data` for a stream.
///
/// # Panics
///
/// Panics if `data.len() > ADB_MAX_PAYLOAD as usize`.
#[must_use]
pub fn make_write(local_id: LocalId, remote_id: RemoteId, data: Vec<u8>) -> crate::AdbMessage {
    assert!(
        data.len() <= ADB_MAX_PAYLOAD as usize,
        "WRTE payload exceeds ADB_MAX_PAYLOAD ({} > {})",
        data.len(),
        ADB_MAX_PAYLOAD
    );
    crate::AdbMessage::new(cmd::WRTE, local_id.0, remote_id.0, data)
}

// ─── Codec — async read/write helpers ────────────────────────────────────────

/// Write a fully-formed `AdbMessage` to a `tokio::io::AsyncWrite` sink.
///
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub async fn write_message<W>(writer: &mut W, msg: &crate::AdbMessage) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let bytes = msg.encode();
    writer.write_all(&bytes).await.map_err(AdbError::Connection)
}

/// Read a single `AdbMessage` from a `tokio::io::AsyncRead` source.
///
/// Reads the 24-byte header first, then the payload declared in the header.
///
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub async fn read_message<R>(reader: &mut R) -> Result<crate::AdbMessage>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut header = [0u8; 24];
    reader.read_exact(&mut header).await.map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            AdbError::Protocol("connection closed while reading header".into())
        } else {
            AdbError::Connection(e)
        }
    })?;

    // Parse header fields
    let mut cur = &header[..];
    let command = cur.get_u32_le();
    let arg0 = cur.get_u32_le();
    let arg1 = cur.get_u32_le();
    let data_len = cur.get_u32_le() as usize;
    let crc32 = cur.get_u32_le();
    let magic = cur.get_u32_le();

    // Validate magic
    if magic != command ^ 0xFFFF_FFFF {
        return Err(AdbError::Protocol(format!(
            "magic mismatch in header: command={command:#010x} magic={magic:#010x}"
        )));
    }

    // Validate payload size
    if data_len > ADB_MAX_PAYLOAD as usize {
        return Err(AdbError::Protocol(format!(
            "declared payload {data_len} exceeds ADB_MAX_PAYLOAD"
        )));
    }

    let data = if data_len > 0 {
        let mut buf = vec![0u8; data_len];
        reader
            .read_exact(&mut buf)
            .await
            .map_err(AdbError::Connection)?;
        buf
    } else {
        vec![]
    };

    // Verify CRC
    let actual_crc = crate::compute_crc32(&data);
    if actual_crc != crc32 {
        return Err(AdbError::Protocol(format!(
            "CRC mismatch: header={crc32:#010x} computed={actual_crc:#010x}"
        )));
    }

    Ok(crate::AdbMessage {
        command,
        arg0,
        arg1,
        data,
        crc32,
        magic,
    })
}

// ─── RSA key stub ─────────────────────────────────────────────────────────────

/// A minimal RSA key stub for ADB authentication.
///
/// Full RSA operations require an external crypto library (e.g. `rsa`, `ring`).
/// This stub provides the data layout and placeholder methods so the rest of
/// the codebase compiles without pulling in heavy crypto dependencies.
#[derive(Debug, Clone)]
pub struct AdbRsaKey {
    /// DER-encoded public key bytes.
    pub public_key_der: Vec<u8>,
    /// DER-encoded private key bytes (empty if public-key-only).
    pub private_key_der: Vec<u8>,
    /// Display name embedded in the ADB public-key packet.
    pub display_name: String,
}

impl AdbRsaKey {
    /// Create a key from raw DER blobs.
    #[must_use]
    pub fn from_der(public_key_der: Vec<u8>, private_key_der: Vec<u8>, name: &str) -> Self {
        Self {
            public_key_der,
            private_key_der,
            display_name: name.to_owned(),
        }
    }

    /// Load an existing key pair from PEM files (stub — reads raw bytes only).
    ///
    /// A real implementation would decode the PEM and validate the key.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn load_from_pem(public_pem: &str, private_pem: &str, name: &str) -> Result<Self> {
        // Stub: just store the raw PEM as bytes.
        Ok(Self {
            public_key_der: public_pem.as_bytes().to_vec(),
            private_key_der: private_pem.as_bytes().to_vec(),
            display_name: name.to_owned(),
        })
    }

    /// Generate a stub placeholder key (not cryptographically secure!).
    ///
    /// Replace with `rsa::RsaPrivateKey::new(&mut rng, 2048)` in production.
    #[must_use]
    pub fn generate_stub(name: &str) -> Self {
        // Placeholder zero-filled 2048-bit key structure.
        Self {
            public_key_der: vec![0u8; 294], // 2048-bit RSA public key DER size
            private_key_der: vec![0u8; 1218],
            display_name: name.to_owned(),
        }
    }

    /// Format the public key as an ADB-style base64 string with display name.
    ///
    /// ADB expects: `base64(<public_key_bytes>) <display_name>\n`.
    #[must_use]
    pub fn public_key_adb_format(&self) -> String {
        let b64 = base64_encode(&self.public_key_der);
        format!("{b64} {}\n", self.display_name)
    }

    /// Sign a token with the private key (stub — returns zeroed signature).
    ///
    /// Replace with real RSA-SHA1-PKCS#1 v1.5 signing in production.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn sign_token(&self, _token: &[u8]) -> Result<Vec<u8>> {
        if self.private_key_der.is_empty() {
            return Err(AdbError::AuthFailed("no private key available".into()));
        }
        // Stub: return 256 bytes of zeros (real 2048-bit RSA signature length).
        Ok(vec![0u8; 256])
    }

    /// Return `true` if a private key is loaded.
    #[must_use]
    pub const fn has_private_key(&self) -> bool {
        !self.private_key_der.is_empty()
    }
}

// ─── Handshake sequencer ──────────────────────────────────────────────────────

/// State machine for the ADB connection handshake.
///
/// Sequence (host initiates):
/// ```text
/// Host  → CNXN(version, max_data, "host::banner")
/// Device → CNXN(version, max_data, "device::props")      (already authorised)
///       OR
/// Device → AUTH(TOKEN, token)
/// Host  → AUTH(SIGNATURE, sign(token))
/// Device → CNXN(...)                                       (success)
///       OR
/// Device → AUTH(TOKEN, new_token)                          (sig rejected)
/// Host  → AUTH(RSAPUBLICKEY, pubkey)
/// Device → CNXN(...)                                       (user accepted)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeState {
    /// Waiting to send CNXN.
    Initial,
    /// CNXN sent, waiting for device reply.
    WaitingForResponse,
    /// Received AUTH TOKEN, waiting for us to sign and send back.
    AuthRequired { token: Vec<u8> },
    /// Signature sent, waiting for CNXN or another AUTH.
    WaitingForConnectAfterAuth,
    /// Public key sent, waiting for user accept.
    WaitingForConnectAfterPubkey,
    /// Handshake complete.
    Connected { device_banner: String },
    /// Terminal failure.
    Failed { reason: String },
}

/// Drive the ADB handshake.
///
/// Call `next_message()` to get the message to send, feed received messages
/// back with `handle_message()`.
pub struct HandshakeDriver {
    state: HandshakeState,
    key: Option<AdbRsaKey>,
    banner: String,
    pub attempts: u32,
}

impl HandshakeDriver {
    /// Create a driver that will use `key` for authentication.
    #[must_use]
    pub fn new(banner: &str, key: Option<AdbRsaKey>) -> Self {
        Self {
            state: HandshakeState::Initial,
            key,
            banner: banner.to_owned(),
            attempts: 0,
        }
    }

    /// Return the initial CNXN message to send.
    ///
    /// # Panics
    ///
    /// Panics if called a second time (state-machine-double-enter: re-calling
    /// `start()` after a handshake is already in progress would silently reset
    /// the negotiated state and corrupt the connection).
    pub fn start(&mut self) -> crate::AdbMessage {
        assert!(
            self.state == HandshakeState::Initial,
            "HandshakeDriver::start() called in non-Initial state {:?}; \
             construct a new HandshakeDriver for each connection",
            self.state
        );
        self.state = HandshakeState::WaitingForResponse;
        make_connect("host", &self.banner)
    }

    /// Handle a received `AdbMessage` and return the optional reply to send.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn handle_message(&mut self, msg: &crate::AdbMessage) -> Result<Option<crate::AdbMessage>> {
        match self.state.clone() {
            HandshakeState::WaitingForResponse
            | HandshakeState::WaitingForConnectAfterAuth
            | HandshakeState::WaitingForConnectAfterPubkey => {
                if msg.command == cmd::CNXN {
                    let banner = String::from_utf8_lossy(&msg.data).into_owned();
                    self.state = HandshakeState::Connected {
                        device_banner: banner,
                    };
                    return Ok(None);
                }
                if msg.command == cmd::AUTH {
                    let auth_type = AuthType::from_u32(msg.arg0);
                    if auth_type == Some(AuthType::Token) {
                        let token = msg.data.clone();
                        if let Some(key) = &self.key {
                            if key.has_private_key() {
                                let sig = key.sign_token(&token)?;
                                self.state = HandshakeState::WaitingForConnectAfterAuth;
                                self.attempts += 1;
                                return Ok(Some(make_auth_signature(sig)));
                            }
                            // No private key — send public key instead.
                            let pk = key.public_key_adb_format();
                            self.state = HandshakeState::WaitingForConnectAfterPubkey;
                            return Ok(Some(make_auth_public_key(&pk)));
                        }
                        // No key at all
                        self.state = HandshakeState::Failed {
                            reason: "AUTH required but no key configured".into(),
                        };
                        return Err(AdbError::AuthFailed(
                            "no RSA key configured for authentication".into(),
                        ));
                    }
                    self.state = HandshakeState::AuthRequired {
                        token: msg.data.clone(),
                    };
                    return Ok(None);
                }
                Err(AdbError::Protocol(format!(
                    "unexpected command during handshake: {:#010x}",
                    msg.command
                )))
            }
            HandshakeState::Connected { .. } => {
                // Already connected — caller shouldn't drive us anymore.
                Ok(None)
            }
            HandshakeState::Failed { ref reason } => Err(AdbError::AuthFailed(reason.clone())),
            _ => Err(AdbError::Protocol("handshake in unexpected state".into())),
        }
    }

    /// Return `true` if the handshake completed successfully.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        matches!(self.state, HandshakeState::Connected { .. })
    }

    /// Return the device banner string after a successful connection.
    #[must_use]
    pub fn device_banner(&self) -> Option<&str> {
        if let HandshakeState::Connected { ref device_banner } = self.state {
            Some(device_banner)
        } else {
            None
        }
    }

    /// Extract device properties from the banner string.
    ///
    /// Banner format: `device::ro.product.name=X;ro.product.model=Y;...`
    #[must_use]
    pub fn parse_device_properties(&self) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        if let Some(banner) = self.device_banner() {
            // Strip leading "device::" or "host::" prefix
            let props_str = banner.split("::").nth(1).unwrap_or(banner);
            for kv in props_str.split(';') {
                if let Some(eq) = kv.find('=') {
                    map.insert(kv[..eq].to_owned(), kv[eq + 1..].to_owned());
                }
            }
        }
        map
    }
}

// ─── Feature negotiation ──────────────────────────────────────────────────────

/// Known ADB feature flags that appear in CNXN banners.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdbFeature {
    /// Shell v2 protocol (structured exit codes, stderr separation).
    ShellV2,
    /// cmd service (run Activity Manager commands directly).
    Cmd,
    /// `stat_v2` in sync protocol (64-bit fields).
    StatV2,
    /// `ls_v2` in sync protocol (extended directory entries).
    LsV2,
    /// Fixed push mkdir (creates intermediate directories).
    FixedPushMkdir,
    /// apex (Android Pony `EXpress` packages).
    Apex,
    /// abb (Android Binder Bridge) service.
    Abb,
    /// `push_sync_send_v2` (`DATA_V2` frames with more info).
    PushSyncSendV2,
    /// Opaque unknown feature.
    Other(String),
}

impl AdbFeature {
    /// Parse a feature tag string.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "shell_v2" => Self::ShellV2,
            "cmd" => Self::Cmd,
            "stat_v2" => Self::StatV2,
            "ls_v2" => Self::LsV2,
            "fixed_push_mkdir" => Self::FixedPushMkdir,
            "apex" => Self::Apex,
            "abb" => Self::Abb,
            "push_sync_send_v2" => Self::PushSyncSendV2,
            other => Self::Other(other.to_owned()),
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::ShellV2 => "shell_v2",
            Self::Cmd => "cmd",
            Self::StatV2 => "stat_v2",
            Self::LsV2 => "ls_v2",
            Self::FixedPushMkdir => "fixed_push_mkdir",
            Self::Apex => "apex",
            Self::Abb => "abb",
            Self::PushSyncSendV2 => "push_sync_send_v2",
            Self::Other(s) => s.as_str(),
        }
    }
}

/// Parse the feature list from a CNXN banner string.
///
/// Banner may contain: `"host::features=shell_v2,cmd,stat_v2"`.
#[must_use]
pub fn parse_features(banner: &str) -> Vec<AdbFeature> {
    // Look for "features=..." segment
    for segment in banner.split("::").skip(1) {
        for kv in segment.split(';') {
            if let Some(features_str) = kv.strip_prefix("features=") {
                return features_str
                    .split(',')
                    .map(|s| AdbFeature::parse(s.trim()))
                    .collect();
            }
        }
    }
    vec![]
}

/// Build a CNXN banner string advertising a set of features.
#[must_use]
pub fn build_banner(system_type: &str, name: &str, features: &[AdbFeature]) -> String {
    if features.is_empty() {
        return format!("{system_type}::{name}");
    }
    let feat_str: Vec<&str> = features.iter().map(AdbFeature::as_str).collect();
    format!("{system_type}::{name};features={}", feat_str.join(","))
}

// ─── Frame fragmentation helpers ─────────────────────────────────────────────

/// Split `data` into chunks no larger than `max_chunk` bytes, returning a
/// `Vec<Bytes>`.  Used to fragment large payloads into multiple WRTE frames.
#[must_use]
pub fn fragment_payload(data: &[u8], max_chunk: usize) -> Vec<Bytes> {
    data.chunks(max_chunk)
        .map(|chunk| {
            let mut b = BytesMut::with_capacity(chunk.len());
            b.put_slice(chunk);
            b.freeze()
        })
        .collect()
}

/// Returns `true` if the given byte slice looks like a valid ADB message
/// header (i.e. magic matches command ^ `0xFFFF_FFFF`).
///
/// # Panics
///
/// Will not panic in practice; the inner `try_into()` is on fixed-size slices.
#[must_use]
pub fn is_valid_header(header: &[u8; 24]) -> bool {
    let command = u32::from_le_bytes(header[0..4].try_into().unwrap());
    let magic = u32::from_le_bytes(header[20..24].try_into().unwrap());
    magic == command ^ 0xFFFF_FFFF
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd;

    #[test]
    fn test_make_connect_command() {
        let msg = make_connect("host", "RustRE/1.0");
        assert_eq!(msg.command, cmd::CNXN);
        assert_eq!(msg.arg0, ADB_VERSION);
        assert_eq!(msg.arg1, ADB_MAX_PAYLOAD);
        let payload = String::from_utf8(msg.data).unwrap();
        assert!(payload.contains("host"));
        assert!(payload.contains("RustRE/1.0"));
    }

    #[test]
    fn test_make_auth_token() {
        let token = vec![1u8, 2, 3, 4];
        let msg = make_auth_token(token.clone());
        assert_eq!(msg.command, cmd::AUTH);
        assert_eq!(msg.arg0, AuthType::Token.as_u32());
        assert_eq!(msg.data, token);
    }

    #[test]
    fn test_make_auth_signature() {
        let sig = vec![0xABu8; 256];
        let msg = make_auth_signature(sig.clone());
        assert_eq!(msg.command, cmd::AUTH);
        assert_eq!(msg.arg0, AuthType::Signature.as_u32());
        assert_eq!(msg.data, sig);
    }

    #[test]
    fn test_make_auth_public_key() {
        let key = "AAAAB3NzaC1yc2E=";
        let msg = make_auth_public_key(key);
        assert_eq!(msg.command, cmd::AUTH);
        assert_eq!(msg.arg0, AuthType::RsaPublicKey.as_u32());
        // payload ends with NUL
        assert_eq!(*msg.data.last().unwrap(), 0u8);
    }

    #[test]
    fn test_make_open_nul_terminated() {
        let msg = make_open(LocalId(1), "shell:ls");
        assert_eq!(msg.command, cmd::OPEN);
        assert_eq!(msg.arg0, 1);
        assert_eq!(*msg.data.last().unwrap(), 0u8);
    }

    #[test]
    fn test_make_okay() {
        let msg = make_okay(LocalId(5), RemoteId(7));
        assert_eq!(msg.command, cmd::OKAY);
        assert_eq!(msg.arg0, 5);
        assert_eq!(msg.arg1, 7);
        assert!(msg.data.is_empty());
    }

    #[test]
    fn test_make_close() {
        let msg = make_close(LocalId(3), RemoteId(4));
        assert_eq!(msg.command, cmd::CLSE);
    }

    #[test]
    fn test_make_write() {
        let data = b"hello device".to_vec();
        let msg = make_write(LocalId(1), RemoteId(2), data.clone());
        assert_eq!(msg.command, cmd::WRTE);
        assert_eq!(msg.data, data);
    }

    #[test]
    #[should_panic(expected = "WRTE payload exceeds ADB_MAX_PAYLOAD")]
    fn test_make_write_too_large_panics() {
        let data = vec![0u8; (ADB_MAX_PAYLOAD + 1) as usize];
        drop(make_write(LocalId(1), RemoteId(2), data));
    }

    #[test]
    fn test_auth_type_roundtrip() {
        for (n, expected) in [
            (1, AuthType::Token),
            (2, AuthType::Signature),
            (3, AuthType::RsaPublicKey),
        ] {
            assert_eq!(AuthType::from_u32(n), Some(expected));
            assert_eq!(expected.as_u32(), n);
        }
        assert!(AuthType::from_u32(99).is_none());
    }

    #[test]
    fn test_parse_features_empty_banner() {
        let features = parse_features("host::RustRE");
        assert!(features.is_empty());
    }

    #[test]
    fn test_parse_features_with_features() {
        let banner = "host::RustRE;features=shell_v2,cmd,stat_v2";
        let features = parse_features(banner);
        assert!(features.contains(&AdbFeature::ShellV2));
        assert!(features.contains(&AdbFeature::Cmd));
        assert!(features.contains(&AdbFeature::StatV2));
    }

    #[test]
    fn test_build_banner_no_features() {
        let b = build_banner("host", "name", &[]);
        assert_eq!(b, "host::name");
    }

    #[test]
    fn test_build_banner_with_features() {
        let b = build_banner("device", "mydev", &[AdbFeature::ShellV2, AdbFeature::Cmd]);
        assert!(b.contains("shell_v2"));
        assert!(b.contains("cmd"));
    }

    #[test]
    fn test_fragment_payload_small() {
        let data = b"hello";
        let chunks = fragment_payload(data, 4);
        assert_eq!(chunks.len(), 2);
        assert_eq!(&chunks[0][..], b"hell");
        assert_eq!(&chunks[1][..], b"o");
    }

    #[test]
    fn test_fragment_payload_exact_fit() {
        let data = vec![0u8; 8];
        let chunks = fragment_payload(&data, 8);
        assert_eq!(chunks.len(), 1);
    }

    #[test]
    fn test_fragment_payload_empty() {
        let chunks = fragment_payload(b"", 64);
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_is_valid_header_roundtrip() {
        let bytes = crate::encode_message(cmd::CNXN, ADB_VERSION, ADB_MAX_PAYLOAD, b"");
        let mut header = [0u8; 24];
        header.copy_from_slice(&bytes[..24]);
        assert!(is_valid_header(&header));
    }

    #[test]
    fn test_is_valid_header_bad_magic() {
        let bytes = crate::encode_message(cmd::CNXN, 0, 0, b"");
        let mut header = [0u8; 24];
        header.copy_from_slice(&bytes[..24]);
        header[23] ^= 0xFF; // corrupt magic
        assert!(!is_valid_header(&header));
    }

    #[test]
    fn test_handshake_driver_start() {
        let mut driver = HandshakeDriver::new("RustRE", None);
        let msg = driver.start();
        assert_eq!(msg.command, cmd::CNXN);
        assert_eq!(driver.state, HandshakeState::WaitingForResponse);
    }

    #[test]
    fn test_handshake_driver_direct_cnxn() {
        let mut driver = HandshakeDriver::new("RustRE", None);
        driver.start();
        let cnxn = make_connect_device("emulator-5554", "sdk_gphone");
        let result = driver.handle_message(&cnxn).unwrap();
        assert!(result.is_none());
        assert!(driver.is_connected());
        assert!(driver.device_banner().unwrap().contains("device"));
    }

    #[test]
    fn test_handshake_driver_auth_no_key() {
        let mut driver = HandshakeDriver::new("RustRE", None);
        driver.start();
        let auth_token = make_auth_token(vec![0xDEu8; 20]);
        let result = driver.handle_message(&auth_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_rsa_key_stub_sign() {
        let key = AdbRsaKey::generate_stub("test");
        let sig = key.sign_token(b"token_data").unwrap();
        assert_eq!(sig.len(), 256);
    }

    #[test]
    fn test_rsa_key_public_format() {
        let key = AdbRsaKey::generate_stub("mydevice");
        let formatted = key.public_key_adb_format();
        assert!(formatted.contains("mydevice"));
        assert!(formatted.ends_with('\n'));
    }

    #[test]
    fn test_rsa_key_no_private_key_error() {
        let key = AdbRsaKey::from_der(vec![1, 2, 3], vec![], "nopriv");
        assert!(!key.has_private_key());
        assert!(key.sign_token(b"token").is_err());
    }

    #[test]
    fn test_parse_device_properties() {
        let mut driver = HandshakeDriver::new("host", None);
        driver.start();
        let cnxn = crate::AdbMessage::new(
            cmd::CNXN,
            ADB_VERSION,
            ADB_MAX_PAYLOAD,
            b"device::ro.product.name=emu;ro.product.model=sdk;ro.product.device=emu\0".to_vec(),
        );
        let _ = driver.handle_message(&cnxn);
        let props = driver.parse_device_properties();
        assert_eq!(
            props
                .get("ro.product.model")
                .map(std::string::String::as_str),
            Some("sdk")
        );
    }

    #[tokio::test]
    async fn test_write_read_message_roundtrip() {
        use tokio::io::duplex;
        let (mut client, mut server) = duplex(4096);
        let original = make_connect("host", "test");
        write_message(&mut client, &original).await.unwrap();
        // read_message reads from `server` side
        drop(client); // close write end so server reader sees EOF after the message
        let decoded = read_message(&mut server).await.unwrap();
        assert_eq!(decoded.command, original.command);
        assert_eq!(decoded.data, original.data);
    }
}
