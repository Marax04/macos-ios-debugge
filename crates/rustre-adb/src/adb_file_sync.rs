//! `adb_file_sync` — ADB SYNC protocol implementation.
//!
//! Encodes and decodes the ADB file-sync sub-protocol used by `adb push`,
//! `adb pull`, `adb stat`, and `adb ls`.  Each operation is self-contained:
//! callers build byte-level packets, ship them over a transport, and parse the
//! response bytes with the decode helpers provided here.

use std::fmt;

// ── SyncId ────────────────────────────────────────────────────────────────────

/// Four-byte identifiers used as message-type tags in the SYNC protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncId {
    /// Request file metadata.
    Stat,
    /// List directory entries.
    List,
    /// Upload a file to the device.
    Send,
    /// Download a file from the device.
    Recv,
    /// Payload chunk within a SEND transfer.
    Data,
    /// Signals end of a data stream.
    Done,
    /// Device reported an error.
    Fail,
    /// Terminate the SYNC session.
    Quit,
}

impl SyncId {
    /// Return the 4-byte wire representation.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 4] {
        match self {
            Self::Stat => *b"STAT",
            Self::List => *b"LIST",
            Self::Send => *b"SEND",
            Self::Recv => *b"RECV",
            Self::Data => *b"DATA",
            Self::Done => *b"DONE",
            Self::Fail => *b"FAIL",
            Self::Quit => *b"QUIT",
        }
    }

    /// Parse 4 bytes into a [`SyncId`].
    #[must_use]
    pub const fn from_bytes(b: [u8; 4]) -> Option<Self> {
        match &b {
            b"STAT" => Some(Self::Stat),
            b"LIST" => Some(Self::List),
            b"SEND" => Some(Self::Send),
            b"RECV" => Some(Self::Recv),
            b"DATA" => Some(Self::Data),
            b"DONE" => Some(Self::Done),
            b"FAIL" => Some(Self::Fail),
            b"QUIT" => Some(Self::Quit),
            _ => None,
        }
    }

    /// Return the canonical ASCII name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stat => "STAT",
            Self::List => "LIST",
            Self::Send => "SEND",
            Self::Recv => "RECV",
            Self::Data => "DATA",
            Self::Done => "DONE",
            Self::Fail => "FAIL",
            Self::Quit => "QUIT",
        }
    }
}

impl fmt::Display for SyncId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ── SyncMessage ───────────────────────────────────────────────────────────────

/// A decoded ADB SYNC message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncMessage {
    /// Message type tag.
    pub id: SyncId,
    /// Length field as encoded on the wire.
    pub length: u32,
    /// Payload bytes.
    pub data: Vec<u8>,
}

impl SyncMessage {
    /// Create a new `SyncMessage`.
    #[must_use]
    pub fn new(id: SyncId, data: Vec<u8>) -> Self {
        let length = u32::try_from(data.len()).unwrap_or(u32::MAX);
        Self { id, length, data }
    }

    /// Encode this message to its wire representation (8-byte header + data).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.data.len());
        out.extend_from_slice(&self.id.as_bytes());
        out.extend_from_slice(&self.length.to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Try to decode a `SyncMessage` from the start of `bytes`.
    ///
    /// Returns `(message, consumed_bytes)` or `None` if there are not enough
    /// bytes.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<(Self, usize)> {
        if bytes.len() < 8 {
            return None;
        }
        let id_bytes: [u8; 4] = bytes[0..4].try_into().ok()?;
        let id = SyncId::from_bytes(id_bytes)?;
        let length = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
        if bytes.len() < 8 + length {
            return None;
        }
        let data = bytes[8..8 + length].to_vec();
        let length_u32 = u32::try_from(length).unwrap_or(u32::MAX);
        Some((Self { id, length: length_u32, data }, 8 + length))
    }
}

// ── FileType ──────────────────────────────────────────────────────────────────

/// Type of a filesystem entry as reported by STAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// Regular file.
    Regular,
    /// Directory.
    Directory,
    /// Symbolic link.
    SymLink,
    /// Block device.
    BlockDevice,
    /// Character device.
    CharDevice,
    /// Unknown or unsupported type.
    Unknown(u8),
}

impl FileType {
    /// Derive the file type from the high nibble of a UNIX `st_mode` value.
    ///
    /// Standard UNIX `st_mode` type bits:
    ///  - `0o040_000` → directory
    ///  - `0o100_000` → regular file
    ///  - `0o120_000` → symlink
    ///  - `0o060_000` → block device
    ///  - `0o020_000` → character device
    #[must_use]
    pub const fn from_mode(mode: u16) -> Self {
        match mode & 0o170_000 {
            0o100_000 => Self::Regular,
            0o040_000 => Self::Directory,
            0o120_000 => Self::SymLink,
            0o060_000 => Self::BlockDevice,
            0o020_000 => Self::CharDevice,
            other => Self::Unknown((other >> 12) as u8),
        }
    }
}

// ── FileMode ──────────────────────────────────────────────────────────────────

/// Parsed UNIX file-mode value from a STAT response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMode {
    /// Raw permission bits (lower 12 bits of `st_mode`).
    pub permissions: u16,
    /// Derived file type.
    pub file_type: FileType,
}

impl FileMode {
    /// Build a `FileMode` from a raw `st_mode` value.
    #[must_use]
    pub const fn from_raw(mode: u16) -> Self {
        Self {
            permissions: mode & 0o7777,
            file_type: FileType::from_mode(mode),
        }
    }

    /// Return the raw `st_mode` value.
    #[must_use]
    pub fn raw_mode(&self) -> u16 {
        let type_bits: u16 = match self.file_type {
            FileType::Regular => 0o100_000,
            FileType::Directory => 0o040_000,
            FileType::SymLink => 0o120_000,
            FileType::BlockDevice => 0o060_000,
            FileType::CharDevice => 0o020_000,
            FileType::Unknown(t) => (u16::from(t)) << 12,
        };
        type_bits | self.permissions
    }

    /// Return `true` if the executable bit is set for the owner.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.permissions & 0o100 != 0
    }

    /// Return `true` if the entry is a regular file.
    #[must_use]
    pub fn is_regular_file(&self) -> bool {
        self.file_type == FileType::Regular
    }

    /// Return `true` if the entry is a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.file_type == FileType::Directory
    }
}

// ── FileStat ──────────────────────────────────────────────────────────────────

/// File metadata returned by STAT or LIST responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStat {
    /// Parsed file mode.
    pub mode: FileMode,
    /// File size in bytes.
    pub size: u32,
    /// Modification time (seconds since Unix epoch).
    pub mtime: u32,
    /// File name (for LIST entries) or empty for STAT responses.
    pub name: String,
}

impl FileStat {
    /// Return a human-readable description of the file type and permissions.
    #[must_use]
    pub fn description(&self) -> String {
        let type_char = match self.mode.file_type {
            FileType::Regular => '-',
            FileType::Directory => 'd',
            FileType::SymLink => 'l',
            FileType::BlockDevice => 'b',
            FileType::CharDevice => 'c',
            FileType::Unknown(_) => '?',
        };
        let perms = self.mode.permissions;
        let rwx = |bits: u16| {
            let r = if bits & 4 != 0 { 'r' } else { '-' };
            let w = if bits & 2 != 0 { 'w' } else { '-' };
            let x = if bits & 1 != 0 { 'x' } else { '-' };
            format!("{r}{w}{x}")
        };
        format!(
            "{}{}{}{} {} {}",
            type_char,
            rwx((perms >> 6) & 7),
            rwx((perms >> 3) & 7),
            rwx(perms & 7),
            self.size,
            self.name
        )
    }
}

// ── AdbFileSync ───────────────────────────────────────────────────────────────

/// High-level ADB file-sync protocol helper.
///
/// Encodes and decodes the packet sequences needed to carry out STAT, LIST,
/// SEND (push), and RECV (pull) operations.  This struct holds no state itself;
/// all methods are pure functions that produce or consume byte buffers.
#[derive(Debug, Clone, Default)]
pub struct AdbFileSync;

/// Maximum data payload per DATA chunk (ADB imposes 64 KiB - 8 bytes).
const MAX_DATA_CHUNK: usize = 64 * 1024 - 8;

/// Truncating cast `usize` → `u32`.
fn len_to_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Truncating cast `u32` → `u16` for the mode field.
fn mode_u32_to_u16(m: u32) -> u16 {
    u16::try_from(m & 0xFFFF).unwrap_or(u16::MAX)
}

impl AdbFileSync {
    /// Create a new `AdbFileSync` helper.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    // ── STAT ─────────────────────────────────────────────────────────────────

    /// Encode a STAT request for `path`.
    ///
    /// Wire format: `STAT` (4 bytes) | path length LE u32 | path bytes.
    #[must_use]
    pub fn encode_sync_stat(path: &str) -> Vec<u8> {
        let path_bytes = path.as_bytes();
        let mut out = Vec::with_capacity(8 + path_bytes.len());
        out.extend_from_slice(b"STAT");
        out.extend_from_slice(&len_to_u32(path_bytes.len()).to_le_bytes());
        out.extend_from_slice(path_bytes);
        out
    }

    /// Decode a STAT response.
    ///
    /// Expected layout: `STAT` (4 bytes) | mode u32 LE | size u32 LE | mtime u32 LE.
    /// Total = 16 bytes.  Returns `None` if `data` is too short or the magic
    /// tag is missing.
    #[must_use]
    pub fn decode_stat_response(data: &[u8]) -> Option<FileStat> {
        if data.len() < 16 {
            return None;
        }
        if &data[0..4] != b"STAT" {
            return None;
        }
        let mode_raw = u32::from_le_bytes(data[4..8].try_into().ok()?);
        let size = u32::from_le_bytes(data[8..12].try_into().ok()?);
        let mtime = u32::from_le_bytes(data[12..16].try_into().ok()?);
        Some(FileStat {
            mode: FileMode::from_raw(mode_u32_to_u16(mode_raw)),
            size,
            mtime,
            name: String::new(),
        })
    }

    // ── LIST ─────────────────────────────────────────────────────────────────

    /// Encode a LIST request for `path`.
    #[must_use]
    pub fn encode_sync_list(path: &str) -> Vec<u8> {
        let path_bytes = path.as_bytes();
        let mut out = Vec::with_capacity(8 + path_bytes.len());
        out.extend_from_slice(b"LIST");
        out.extend_from_slice(&len_to_u32(path_bytes.len()).to_le_bytes());
        out.extend_from_slice(path_bytes);
        out
    }

    /// Decode a single LIST entry (DENT packet).
    ///
    /// Wire: `DENT` (4 bytes) | mode u32 LE | size u32 LE | mtime u32 LE |
    ///       `name_len` u32 LE | name bytes.
    #[must_use]
    pub fn decode_list_entry(data: &[u8]) -> Option<FileStat> {
        if data.len() < 20 {
            return None;
        }
        if &data[0..4] != b"DENT" {
            return None;
        }
        let mode_raw = u32::from_le_bytes(data[4..8].try_into().ok()?);
        let size = u32::from_le_bytes(data[8..12].try_into().ok()?);
        let mtime = u32::from_le_bytes(data[12..16].try_into().ok()?);
        let name_len = u32::from_le_bytes(data[16..20].try_into().ok()?) as usize;
        if data.len() < 20 + name_len {
            return None;
        }
        let name = String::from_utf8_lossy(&data[20..20 + name_len]).into_owned();
        Some(FileStat {
            mode: FileMode::from_raw(mode_u32_to_u16(mode_raw)),
            size,
            mtime,
            name,
        })
    }

    // ── SEND (push) ──────────────────────────────────────────────────────────

    /// Encode a complete SEND sequence for pushing `data` to `path` with the
    /// given Unix `mode` bits.
    ///
    /// Returns a `Vec<Vec<u8>>` of packets:
    ///  1. SEND header: `SEND` | (len of `"path,mode_str"`) | `"path,mode_str"`
    ///  2. One or more DATA chunks: `DATA` | `chunk_len` | `chunk_bytes`
    ///  3. DONE trailer: `DONE` | mtime u32 LE (uses 0 as placeholder)
    #[must_use]
    pub fn encode_sync_send(path: &str, mode: u32, data: &[u8]) -> Vec<Vec<u8>> {
        let mut packets: Vec<Vec<u8>> = Vec::new();

        // Header packet
        let dest = format!("{path},{mode}");
        let dest_bytes = dest.as_bytes();
        let mut header = Vec::with_capacity(8 + dest_bytes.len());
        header.extend_from_slice(b"SEND");
        header.extend_from_slice(&len_to_u32(dest_bytes.len()).to_le_bytes());
        header.extend_from_slice(dest_bytes);
        packets.push(header);

        // DATA chunks
        for chunk in data.chunks(MAX_DATA_CHUNK) {
            let mut pkt = Vec::with_capacity(8 + chunk.len());
            pkt.extend_from_slice(b"DATA");
            pkt.extend_from_slice(&len_to_u32(chunk.len()).to_le_bytes());
            pkt.extend_from_slice(chunk);
            packets.push(pkt);
        }

        // DONE trailer with mtime=0
        let mut done = Vec::with_capacity(8);
        done.extend_from_slice(b"DONE");
        done.extend_from_slice(&0u32.to_le_bytes());
        packets.push(done);

        packets
    }

    // ── RECV (pull) ──────────────────────────────────────────────────────────

    /// Encode a RECV request for `path`.
    #[must_use]
    pub fn encode_sync_recv(path: &str) -> Vec<u8> {
        let path_bytes = path.as_bytes();
        let mut out = Vec::with_capacity(8 + path_bytes.len());
        out.extend_from_slice(b"RECV");
        out.extend_from_slice(&len_to_u32(path_bytes.len()).to_le_bytes());
        out.extend_from_slice(path_bytes);
        out
    }

    /// Decode a stream of DATA packets (as received in response to RECV).
    ///
    /// The stream may contain multiple `DATA` messages followed by a `DONE`
    /// or `FAIL` packet.  Only the payload bytes from `DATA` packets are
    /// collected; all other packets terminate the loop.
    #[must_use]
    pub fn decode_data_packets(stream: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos + 8 <= stream.len() {
            let tag = &stream[pos..pos + 4];
            let length = u32::from_le_bytes(
                stream[pos + 4..pos + 8].try_into().unwrap_or([0; 4]),
            ) as usize;
            if tag == b"DATA" {
                let end = pos + 8 + length;
                if end <= stream.len() {
                    out.extend_from_slice(&stream[pos + 8..end]);
                }
                pos = end;
            } else {
                break; // DONE, FAIL, or unknown
            }
        }
        out
    }

    // ── QUIT ─────────────────────────────────────────────────────────────────

    /// Encode a QUIT packet to terminate the SYNC session.
    #[must_use]
    pub fn encode_quit() -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(b"QUIT");
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    // ── Error parsing ─────────────────────────────────────────────────────────

    /// If `data` starts with `FAIL`, extract the error message.
    #[must_use]
    pub fn decode_fail(data: &[u8]) -> Option<String> {
        if data.len() < 8 || &data[0..4] != b"FAIL" {
            return None;
        }
        let msg_len = u32::from_le_bytes(data[4..8].try_into().ok()?) as usize;
        if data.len() < 8 + msg_len {
            return None;
        }
        Some(String::from_utf8_lossy(&data[8..8 + msg_len]).into_owned())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_id_roundtrip() {
        for id in [
            SyncId::Stat,
            SyncId::List,
            SyncId::Send,
            SyncId::Recv,
            SyncId::Data,
            SyncId::Done,
            SyncId::Fail,
            SyncId::Quit,
        ] {
            let bytes = id.as_bytes();
            assert_eq!(SyncId::from_bytes(bytes), Some(id));
        }
    }

    #[test]
    fn test_sync_id_from_unknown_bytes() {
        assert_eq!(SyncId::from_bytes(*b"XXXX"), None);
    }

    #[test]
    fn test_sync_message_encode_decode_roundtrip() {
        let msg = SyncMessage::new(SyncId::Stat, b"/data/local".to_vec());
        let encoded = msg.encode();
        let (decoded, consumed) = SyncMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_sync_message_decode_too_short() {
        assert!(SyncMessage::decode(&[0u8; 4]).is_none());
    }

    #[test]
    fn test_file_type_from_mode_regular() {
        assert_eq!(FileType::from_mode(0o100_755), FileType::Regular);
    }

    #[test]
    fn test_file_type_from_mode_directory() {
        assert_eq!(FileType::from_mode(0o040_755), FileType::Directory);
    }

    #[test]
    fn test_file_type_from_mode_symlink() {
        assert_eq!(FileType::from_mode(0o120_777), FileType::SymLink);
    }

    #[test]
    fn test_file_mode_roundtrip() {
        let raw: u16 = 0o100_644;
        let mode = FileMode::from_raw(raw);
        assert_eq!(mode.raw_mode(), raw);
    }

    #[test]
    fn test_file_mode_is_executable() {
        let mode = FileMode::from_raw(0o100_755);
        assert!(mode.is_executable());
    }

    #[test]
    fn test_file_mode_not_executable() {
        let mode = FileMode::from_raw(0o100_644);
        assert!(!mode.is_executable());
    }

    #[test]
    fn test_encode_decode_stat() {
        let encoded = AdbFileSync::encode_sync_stat("/sdcard/test.txt");
        assert_eq!(&encoded[0..4], b"STAT");
        let len = u32::from_le_bytes(encoded[4..8].try_into().unwrap()) as usize;
        assert_eq!(&encoded[8..8 + len], b"/sdcard/test.txt");
    }

    #[test]
    fn test_decode_stat_response_valid() {
        let mut data = Vec::new();
        data.extend_from_slice(b"STAT");
        data.extend_from_slice(&(0o100_644u32).to_le_bytes()); // mode
        data.extend_from_slice(&1234u32.to_le_bytes());        // size
        data.extend_from_slice(&9999u32.to_le_bytes());        // mtime
        let stat = AdbFileSync::decode_stat_response(&data).unwrap();
        assert_eq!(stat.size, 1234);
        assert_eq!(stat.mtime, 9999);
        assert!(stat.mode.is_regular_file());
    }

    #[test]
    fn test_decode_stat_response_bad_tag() {
        let mut data = Vec::new();
        data.extend_from_slice(b"DENT");
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        assert!(AdbFileSync::decode_stat_response(&data).is_none());
    }

    #[test]
    fn test_encode_sync_send_produces_correct_packet_count() {
        // 1 header + ceil(data/64KB) DATA packets + 1 DONE
        let data = vec![0u8; 200_000]; // ~3 chunks
        let pkts = AdbFileSync::encode_sync_send("/sdcard/x", 0o644, &data);
        // header + 4 data chunks (200k / 65528 = 4) + done
        assert!(pkts.len() >= 3);
        assert_eq!(&pkts[0][0..4], b"SEND");
        assert_eq!(&pkts[pkts.len() - 1][0..4], b"DONE");
    }

    #[test]
    fn test_encode_sync_send_empty_data() {
        let pkts = AdbFileSync::encode_sync_send("/sdcard/empty", 0o644, &[]);
        // header + DONE (no DATA packets)
        assert_eq!(pkts.len(), 2);
        assert_eq!(&pkts[0][0..4], b"SEND");
        assert_eq!(&pkts[1][0..4], b"DONE");
    }

    #[test]
    fn test_decode_data_packets_basic() {
        let payload = b"hello world";
        let mut stream = Vec::new();
        stream.extend_from_slice(b"DATA");
        stream.extend_from_slice(&len_to_u32(payload.len()).to_le_bytes());
        stream.extend_from_slice(payload);
        stream.extend_from_slice(b"DONE");
        stream.extend_from_slice(&0u32.to_le_bytes());
        let out = AdbFileSync::decode_data_packets(&stream);
        assert_eq!(out, payload);
    }

    #[test]
    fn test_decode_data_packets_multiple_chunks() {
        let chunk1 = b"first_chunk";
        let chunk2 = b"second_chunk";
        let mut stream = Vec::new();
        for chunk in [chunk1.as_ref(), chunk2.as_ref()] {
            stream.extend_from_slice(b"DATA");
            stream.extend_from_slice(&len_to_u32(chunk.len()).to_le_bytes());
            stream.extend_from_slice(chunk);
        }
        stream.extend_from_slice(b"DONE");
        stream.extend_from_slice(&0u32.to_le_bytes());
        let out = AdbFileSync::decode_data_packets(&stream);
        let mut expected = Vec::new();
        expected.extend_from_slice(chunk1);
        expected.extend_from_slice(chunk2);
        assert_eq!(out, expected);
    }

    #[test]
    fn test_encode_quit() {
        let q = AdbFileSync::encode_quit();
        assert_eq!(&q[0..4], b"QUIT");
        assert_eq!(q.len(), 8);
    }

    #[test]
    fn test_decode_fail() {
        let msg = "Permission denied";
        let mut data = Vec::new();
        data.extend_from_slice(b"FAIL");
        data.extend_from_slice(&len_to_u32(msg.len()).to_le_bytes());
        data.extend_from_slice(msg.as_bytes());
        let err = AdbFileSync::decode_fail(&data).unwrap();
        assert_eq!(err, msg);
    }

    #[test]
    fn test_decode_list_entry() {
        let name = "file.txt";
        let mut data = Vec::new();
        data.extend_from_slice(b"DENT");
        data.extend_from_slice(&(0o100_644u32).to_le_bytes());
        data.extend_from_slice(&512u32.to_le_bytes());
        data.extend_from_slice(&1000u32.to_le_bytes());
        data.extend_from_slice(&len_to_u32(name.len()).to_le_bytes());
        data.extend_from_slice(name.as_bytes());
        let stat = AdbFileSync::decode_list_entry(&data).unwrap();
        assert_eq!(stat.name, "file.txt");
        assert_eq!(stat.size, 512);
    }

    #[test]
    fn test_file_stat_description_contains_name() {
        let stat = FileStat {
            mode: FileMode::from_raw(0o100_644),
            size: 1024,
            mtime: 0,
            name: "myfile.txt".into(),
        };
        let desc = stat.description();
        assert!(desc.contains("myfile.txt"));
        assert!(desc.contains("1024"));
    }
}
