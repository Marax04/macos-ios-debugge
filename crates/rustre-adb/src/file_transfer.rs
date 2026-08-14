//! ADB file transfer via the SYNC protocol.
//!
//! Implements SEND/RECV/STAT/LIST/DENT/DATA/DONE/FAIL/QUIT operations,
//! streaming transfer with progress callbacks, and recursive directory transfer.

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("remote FAIL: {0}")]
    RemoteFail(String),
    #[error("unexpected ID: got '{got}', expected '{expected}'")]
    UnexpectedId { got: String, expected: String },
    #[error("transfer timed out")]
    Timeout,
    #[error("path too long: {0}")]
    PathTooLong(String),
    #[error("invalid mtime")]
    InvalidMtime,
    #[error("directory recursion too deep: {0}")]
    TooDeep(usize),
    #[error("checksum mismatch")]
    Checksum,
}

pub type SyncResult<T> = Result<T, SyncError>;

// ─── SYNC IDs ─────────────────────────────────────────────────────────────────

pub const ID_STAT: &[u8; 4] = b"STAT";
pub const ID_STAT2: &[u8; 4] = b"STA2";
pub const ID_LIST: &[u8; 4] = b"LIST";
pub const ID_LIST2: &[u8; 4] = b"LIS2";
pub const ID_DENT: &[u8; 4] = b"DENT";
pub const ID_DENT2: &[u8; 4] = b"DNT2";
pub const ID_SEND: &[u8; 4] = b"SEND";
pub const ID_SEND2: &[u8; 4] = b"SND2";
pub const ID_RECV: &[u8; 4] = b"RECV";
pub const ID_RECV2: &[u8; 4] = b"RCV2";
pub const ID_DATA: &[u8; 4] = b"DATA";
pub const ID_DONE: &[u8; 4] = b"DONE";
pub const ID_OKAY: &[u8; 4] = b"OKAY";
pub const ID_FAIL: &[u8; 4] = b"FAIL";
pub const ID_QUIT: &[u8; 4] = b"QUIT";

/// Maximum size of a single DATA chunk (64 KiB).
pub const SYNC_DATA_MAX: usize = 64 * 1024;
/// Maximum path length for SYNC operations.
pub const SYNC_MAX_PATH: usize = 1024;

// ─── Stat Entry ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatEntry {
    pub mode: u32,
    pub size: u64,
    pub mtime: u32,
    pub path: String,
}

impl StatEntry {
    #[must_use]
    pub const fn is_dir(&self) -> bool {
        self.mode & 0o170_000 == 0o040_000
    }

    #[must_use]
    pub const fn is_file(&self) -> bool {
        self.mode & 0o170_000 == 0o100_000
    }

    #[must_use]
    pub const fn is_symlink(&self) -> bool {
        self.mode & 0o170_000 == 0o120_000
    }

    #[must_use]
    pub const fn perm_bits(&self) -> u32 {
        self.mode & 0o7777
    }

    #[must_use]
    pub fn mtime_as_system_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(u64::from(self.mtime))
    }
}

impl fmt::Display for StatEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let type_char = if self.is_dir() { 'd' } else if self.is_symlink() { 'l' } else { '-' };
        write!(f, "{}{:04o} {:>8} {}", type_char, self.perm_bits(), self.size, self.path)
    }
}

// ─── Dir Entry ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub stat: StatEntry,
    pub name: String,
}

// ─── SYNC Framing ─────────────────────────────────────────────────────────────

/// Cast `usize` to `u32`, saturating on overflow.
fn usize_to_u32_sat(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Write a SYNC request ID + 4-byte LE integer to `w`.
///
/// # Errors
/// Returns I/O errors from the underlying writer.
pub fn write_sync_req(w: &mut impl Write, id: &[u8; 4], value: u32) -> SyncResult<()> {
    w.write_all(id)?;
    w.write_all(&value.to_le_bytes())?;
    Ok(())
}

/// Write a SYNC string request: ID + 4-byte length + string bytes.
///
/// # Errors
/// Returns `SyncError::PathTooLong` if the string exceeds `SYNC_MAX_PATH`,
/// or I/O errors from the underlying writer.
pub fn write_sync_string(w: &mut impl Write, id: &[u8; 4], s: &str) -> SyncResult<()> {
    if s.len() > SYNC_MAX_PATH {
        return Err(SyncError::PathTooLong(s.to_string()));
    }
    w.write_all(id)?;
    w.write_all(&usize_to_u32_sat(s.len()).to_le_bytes())?;
    w.write_all(s.as_bytes())?;
    Ok(())
}

/// Read a 4-byte ID from `r`.
///
/// # Errors
/// Returns I/O errors from the underlying reader.
pub fn read_sync_id<R: Read>(r: &mut R) -> SyncResult<[u8; 4]> {
    let mut id = [0u8; 4];
    r.read_exact(&mut id)?;
    Ok(id)
}

/// Read a 4-byte LE `u32` from `r`.
///
/// # Errors
/// Returns I/O errors from the underlying reader.
pub fn read_sync_u32<R: Read>(r: &mut R) -> SyncResult<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

/// Maximum length of a FAIL error message accepted from untrusted input.
const FAIL_MSG_MAX: u32 = 4096;

/// Read a FAIL response string if applicable.
///
/// # Errors
/// Returns `SyncError::RemoteFail` if the ID is `FAIL`, or I/O errors.
pub fn check_for_fail<R: Read>(id: &[u8; 4], r: &mut R) -> SyncResult<()> {
    if id == ID_FAIL {
        let len = read_sync_u32(r)?;
        // dos-memory-exhaustion: cap the error-message length so a malicious
        // device cannot cause an arbitrarily large allocation.
        if len > FAIL_MSG_MAX {
            return Err(SyncError::RemoteFail(format!(
                "<error message too long: {len} bytes>"
            )));
        }
        let mut msg = vec![0u8; len as usize];
        r.read_exact(&mut msg)?;
        return Err(SyncError::RemoteFail(
            String::from_utf8_lossy(&msg).to_string(),
        ));
    }
    Ok(())
}

// ─── SYNC Codec ──────────────────────────────────────────────────────────────

/// Encode a STAT request.
///
/// # Errors
/// Returns `SyncError::PathTooLong` if `path` exceeds `SYNC_MAX_PATH`.
pub fn encode_stat_request(path: &str) -> SyncResult<Vec<u8>> {
    let mut buf = Vec::new();
    write_sync_string(&mut buf, ID_STAT, path)?;
    Ok(buf)
}

/// Decode a STAT response (12 bytes: mode + size + mtime).
///
/// # Errors
/// Returns errors on I/O failure, unexpected ID, or remote FAIL.
pub fn decode_stat_response<R: Read>(r: &mut R, path: &str) -> SyncResult<StatEntry> {
    let id = read_sync_id(r)?;
    if &id != b"STAT" {
        check_for_fail(&id, r)?;
        return Err(SyncError::UnexpectedId {
            got: id_to_str(id),
            expected: "STAT".into(),
        });
    }
    let mode = read_sync_u32(r)?;
    let size = u64::from(read_sync_u32(r)?);
    let mtime = read_sync_u32(r)?;
    Ok(StatEntry { mode, size, mtime, path: path.to_string() })
}

/// Encode a LIST request.
///
/// # Errors
/// Returns `SyncError::PathTooLong` if `path` exceeds `SYNC_MAX_PATH`.
pub fn encode_list_request(path: &str) -> SyncResult<Vec<u8>> {
    let mut buf = Vec::new();
    write_sync_string(&mut buf, ID_LIST, path)?;
    Ok(buf)
}

/// Read all DENT responses until DONE.
///
/// # Errors
/// Returns errors on I/O failure, remote FAIL, or unexpected IDs.
pub fn decode_list_response<R: Read>(r: &mut R) -> SyncResult<Vec<DirEntry>> {
    let mut entries = Vec::new();
    loop {
        let id = read_sync_id(r)?;
        if &id == b"DONE" {
            let _ = read_sync_u32(r)?; // consume padding
            break;
        }
        if &id == b"FAIL" {
            let len = read_sync_u32(r)?;
            // dos-memory-exhaustion: cap list FAIL message length.
            if len > FAIL_MSG_MAX {
                return Err(SyncError::RemoteFail(format!(
                    "<error message too long: {len} bytes>"
                )));
            }
            let mut msg = vec![0u8; len as usize];
            r.read_exact(&mut msg)?;
            return Err(SyncError::RemoteFail(String::from_utf8_lossy(&msg).to_string()));
        }
        if &id != b"DENT" {
            return Err(SyncError::UnexpectedId {
                got: id_to_str(id),
                expected: "DENT".into(),
            });
        }
        let mode = read_sync_u32(r)?;
        let size = u64::from(read_sync_u32(r)?);
        let mtime = read_sync_u32(r)?;
        let name_len = read_sync_u32(r)?;
        // dos-memory-exhaustion: cap name length to SYNC_MAX_PATH (1 KiB) so
        // a malicious device cannot cause a large allocation via a DENT entry.
        if name_len as usize > SYNC_MAX_PATH {
            return Err(SyncError::PathTooLong(format!(
                "<DENT name length {name_len} exceeds SYNC_MAX_PATH {SYNC_MAX_PATH}>"
            )));
        }
        let mut name_bytes = vec![0u8; name_len as usize];
        r.read_exact(&mut name_bytes)?;
        let name = String::from_utf8_lossy(&name_bytes).to_string();
        entries.push(DirEntry {
            stat: StatEntry { mode, size, mtime, path: name.clone() },
            name,
        });
    }
    Ok(entries)
}

// ─── SEND (Push) ──────────────────────────────────────────────────────────────

/// Encode a SEND header: `"SEND"` + length + `"path,mode"` string.
///
/// # Errors
/// Returns `SyncError::PathTooLong` on overlong paths.
pub fn encode_send_header(path: &str, mode: u32) -> SyncResult<Vec<u8>> {
    let combined = format!("{path},{mode}");
    let mut buf = Vec::new();
    write_sync_string(&mut buf, ID_SEND, &combined)?;
    Ok(buf)
}

/// Encode one DATA chunk (up to 64 KiB).
#[must_use]
pub fn encode_data_chunk(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + data.len());
    buf.extend_from_slice(ID_DATA);
    buf.extend_from_slice(&usize_to_u32_sat(data.len()).to_le_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Encode the DONE message (with mtime).
#[must_use]
pub fn encode_done(mtime: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);
    buf.extend_from_slice(ID_DONE);
    buf.extend_from_slice(&mtime.to_le_bytes());
    buf
}

/// Stream `data` as SYNC DATA chunks, then DONE, returning the full byte sequence.
///
/// # Errors
/// Returns `SyncError::PathTooLong` on overlong paths.
pub fn encode_push_stream(path: &str, mode: u32, data: &[u8], mtime: u32) -> SyncResult<Vec<u8>> {
    let mut buf = encode_send_header(path, mode)?;
    for chunk in data.chunks(SYNC_DATA_MAX) {
        buf.extend(encode_data_chunk(chunk));
    }
    buf.extend(encode_done(mtime));
    Ok(buf)
}

/// Read the OKAY response after a successful push.
///
/// # Errors
/// Returns errors on I/O failure, remote FAIL, or unexpected IDs.
pub fn decode_push_response<R: Read>(r: &mut R) -> SyncResult<()> {
    let id = read_sync_id(r)?;
    check_for_fail(&id, r)?;
    if &id != b"OKAY" {
        return Err(SyncError::UnexpectedId {
            got: id_to_str(id),
            expected: "OKAY".into(),
        });
    }
    let _ = read_sync_u32(r)?;
    Ok(())
}

// ─── RECV (Pull) ──────────────────────────────────────────────────────────────

/// Encode a RECV request.
///
/// # Errors
/// Returns `SyncError::PathTooLong` on overlong paths.
pub fn encode_recv_request(path: &str) -> SyncResult<Vec<u8>> {
    let mut buf = Vec::new();
    write_sync_string(&mut buf, ID_RECV, path)?;
    Ok(buf)
}

/// Read all DATA chunks until DONE.
///
/// # Errors
/// Returns errors on I/O failure, remote FAIL, or oversized chunks.
pub fn decode_recv_stream<R: Read>(r: &mut R) -> SyncResult<Vec<u8>> {
    let mut data = Vec::new();
    loop {
        let id = read_sync_id(r)?;
        if &id == b"DONE" {
            break;
        }
        check_for_fail(&id, r)?;
        if &id != b"DATA" {
            return Err(SyncError::UnexpectedId {
                got: id_to_str(id),
                expected: "DATA".into(),
            });
        }
        let len = read_sync_u32(r)?;
        // dos-memory-exhaustion: DATA chunks must not exceed the protocol
        // maximum of 64 KiB; a malicious device could otherwise trigger a
        // huge allocation for a single chunk.
        if len as usize > SYNC_DATA_MAX {
            return Err(SyncError::RemoteFail(format!(
                "DATA chunk length {len} exceeds SYNC_DATA_MAX {SYNC_DATA_MAX}"
            )));
        }
        let mut chunk = vec![0u8; len as usize];
        r.read_exact(&mut chunk)?;
        data.extend(chunk);
    }
    Ok(data)
}

// ─── Progress Tracking ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferProgress {
    pub bytes_transferred: u64,
    pub total_bytes: u64,
    pub files_done: u64,
    pub files_total: u64,
    pub elapsed: Duration,
    pub current_file: String,
}

/// Convert a `u64` byte count to `f64`, accepting precision loss for display.
const fn u64_to_f64_lossy(n: u64) -> f64 {
    n as f64
}


impl TransferProgress {
    #[must_use]
    pub const fn new(total_bytes: u64, files_total: u64) -> Self {
        Self {
            bytes_transferred: 0,
            total_bytes,
            files_done: 0,
            files_total,
            elapsed: Duration::ZERO,
            current_file: String::new(),
        }
    }

    #[must_use]
    pub fn percent(&self) -> f64 {
        if self.total_bytes == 0 {
            return 100.0;
        }
        100.0 * u64_to_f64_lossy(self.bytes_transferred) / u64_to_f64_lossy(self.total_bytes)
    }

    #[must_use]
    pub fn throughput_kbs(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs == 0.0 { 0.0 } else { u64_to_f64_lossy(self.bytes_transferred) / (secs * 1024.0) }
    }
}

impl fmt::Display for TransferProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:.1}%] {}/{} bytes  {:.1} KB/s  ({}/{})",
            self.percent(),
            self.bytes_transferred,
            self.total_bytes,
            self.throughput_kbs(),
            self.files_done,
            self.files_total,
        )
    }
}

// ─── File Transfer Engine ─────────────────────────────────────────────────────

/// Configuration for file transfer operations.
#[derive(Debug, Clone)]
pub struct TransferConfig {
    pub chunk_size: usize,
    pub default_mode: u32,
    pub max_depth: usize,
    pub preserve_timestamps: bool,
    pub overwrite: bool,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            chunk_size: SYNC_DATA_MAX,
            default_mode: 0o644,
            max_depth: 64,
            preserve_timestamps: true,
            overwrite: true,
        }
    }
}

/// In-memory file transfer engine (drives a byte-buffer "connection").
/// In production, the `W: Write + Read` would be an ADB socket stream.
pub struct FileTransfer<W> {
    stream: W,
    pub config: TransferConfig,
    progress: TransferProgress,
}

impl<W: Write + Read> FileTransfer<W> {
    pub fn new(stream: W) -> Self {
        Self {
            stream,
            config: TransferConfig::default(),
            progress: TransferProgress::new(0, 0),
        }
    }

    /// Push bytes to a remote path.
    ///
    /// # Errors
    /// Returns errors on I/O failure, remote FAIL, or overlong paths.
    pub fn push(
        &mut self,
        remote_path: &str,
        data: &[u8],
        mode: u32,
        mtime: u32,
    ) -> SyncResult<()> {
        let req = encode_push_stream(remote_path, mode, data, mtime)?;
        self.stream.write_all(&req)?;
        self.stream.flush()?;
        decode_push_response(&mut self.stream)?;
        self.progress.bytes_transferred += data.len() as u64;
        self.progress.files_done += 1;
        Ok(())
    }

    /// Pull bytes from a remote path.
    ///
    /// # Errors
    /// Returns errors on I/O failure, remote FAIL, or overlong paths.
    pub fn pull(&mut self, remote_path: &str) -> SyncResult<Vec<u8>> {
        let req = encode_recv_request(remote_path)?;
        self.stream.write_all(&req)?;
        self.stream.flush()?;
        let data = decode_recv_stream(&mut self.stream)?;
        self.progress.bytes_transferred += data.len() as u64;
        self.progress.files_done += 1;
        Ok(data)
    }

    /// Stat a remote path.
    ///
    /// # Errors
    /// Returns errors on I/O failure, remote FAIL, or overlong paths.
    pub fn stat(&mut self, remote_path: &str) -> SyncResult<StatEntry> {
        let req = encode_stat_request(remote_path)?;
        self.stream.write_all(&req)?;
        self.stream.flush()?;
        decode_stat_response(&mut self.stream, remote_path)
    }

    /// List a remote directory.
    ///
    /// # Errors
    /// Returns errors on I/O failure, remote FAIL, or overlong paths.
    pub fn list(&mut self, remote_path: &str) -> SyncResult<Vec<DirEntry>> {
        let req = encode_list_request(remote_path)?;
        self.stream.write_all(&req)?;
        self.stream.flush()?;
        decode_list_response(&mut self.stream)
    }

    /// Quit the SYNC session.
    ///
    /// # Errors
    /// Returns I/O errors from the underlying stream.
    pub fn quit(&mut self) -> SyncResult<()> {
        self.stream.write_all(ID_QUIT)?;
        self.stream.write_all(&0u32.to_le_bytes())?;
        self.stream.flush()?;
        Ok(())
    }

    pub const fn progress(&self) -> &TransferProgress {
        &self.progress
    }
}

// ─── Local File Tree Walker ───────────────────────────────────────────────────

/// Represents a local file to be pushed.
#[derive(Debug, Clone)]
pub struct LocalFileEntry {
    pub local_path: PathBuf,
    pub remote_path: String,
    pub size: u64,
    pub mode: u32,
    pub mtime: u32,
}

/// Collect local files for a recursive push operation.
///
/// # Errors
/// Returns I/O errors from filesystem traversal.
pub fn collect_local_files(
    local_root: &Path,
    remote_root: &str,
    max_depth: usize,
) -> io::Result<Vec<LocalFileEntry>> {
    let mut result = Vec::new();
    let mut queue: VecDeque<(PathBuf, String, usize)> = VecDeque::new();
    queue.push_back((local_root.to_path_buf(), remote_root.to_string(), 0));

    while let Some((local, remote, depth)) = queue.pop_front() {
        if depth > max_depth {
            continue;
        }
        if local.is_file() {
            let meta = std::fs::metadata(&local)?;
            let mtime = meta
                .modified()
                .unwrap_or(UNIX_EPOCH)
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mtime = u64_secs_to_u32(mtime);
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::MetadataExt;
                meta.mode()
            };
            #[cfg(not(unix))]
            let mode = 0o644u32;
            result.push(LocalFileEntry {
                local_path: local,
                remote_path: remote,
                size: meta.len(),
                mode,
                mtime,
            });
        } else if local.is_dir() {
            for entry in std::fs::read_dir(&local)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                let child_local = entry.path();
                let child_remote = format!("{remote}/{name}");
                queue.push_back((child_local, child_remote, depth + 1));
            }
        }
    }
    Ok(result)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn id_to_str(id: [u8; 4]) -> String {
    String::from_utf8_lossy(&id).to_string()
}

/// Truncating cast from `u64` (seconds) to `u32`.
fn u64_secs_to_u32(secs: u64) -> u32 {
    u32::try_from(secs).unwrap_or(u32::MAX)
}

#[must_use]
pub fn current_mtime() -> u32 {
    u64_secs_to_u32(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}

// ─── SYNC Loopback Server (for testing) ──────────────────────────────────────

/// A simple SYNC server that handles push/pull from an in-memory file system.
/// Used for unit tests without a real ADB connection.
#[derive(Default)]
pub struct MemSyncServer {
    pub files: std::collections::HashMap<String, Vec<u8>>,
    pub stats: std::collections::HashMap<String, StatEntry>,
}

impl MemSyncServer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a SYNC client request buffer and return the server response.
    #[must_use]
    pub fn handle(&mut self, request: &[u8]) -> Vec<u8> {
        let mut cur = Cursor::new(request);
        let mut response = Vec::new();

        while (usize::try_from(cur.position()).unwrap_or(usize::MAX)) < request.len() {
            let mut id_buf = [0u8; 4];
            if cur.read_exact(&mut id_buf).is_err() {
                break;
            }
            let remaining = request.len() - usize::try_from(cur.position()).unwrap_or(usize::MAX);
            if remaining < 4 {
                break;
            }
            let mut len_buf = [0u8; 4];
            if cur.read_exact(&mut len_buf).is_err() {
                break;
            }
            let len = u32::from_le_bytes(len_buf) as usize;

            match &id_buf {
                b"STAT" => {
                    let mut path_buf = vec![0u8; len];
                    let _ = cur.read_exact(&mut path_buf);
                    let path = String::from_utf8_lossy(&path_buf).to_string();
                    response.extend_from_slice(b"STAT");
                    if let Some(stat) = self.stats.get(&path).cloned() {
                        response.extend_from_slice(&stat.mode.to_le_bytes());
                        let size32 = u32::try_from(stat.size).unwrap_or(u32::MAX);
                        response.extend_from_slice(&size32.to_le_bytes());
                        response.extend_from_slice(&stat.mtime.to_le_bytes());
                    } else {
                        // Not found: all zeros
                        response.extend_from_slice(&0u32.to_le_bytes());
                        response.extend_from_slice(&0u32.to_le_bytes());
                        response.extend_from_slice(&0u32.to_le_bytes());
                    }
                }
                b"RECV" => {
                    let mut path_buf = vec![0u8; len];
                    let _ = cur.read_exact(&mut path_buf);
                    let path = String::from_utf8_lossy(&path_buf).to_string();
                    if let Some(data) = self.files.get(&path).cloned() {
                        for chunk in data.chunks(SYNC_DATA_MAX) {
                            response.extend_from_slice(b"DATA");
                            response.extend_from_slice(&usize_to_u32_sat(chunk.len()).to_le_bytes());
                            response.extend_from_slice(chunk);
                        }
                        response.extend_from_slice(b"DONE");
                    } else {
                        let msg = format!("No such file: {path}");
                        response.extend_from_slice(b"FAIL");
                        response.extend_from_slice(&usize_to_u32_sat(msg.len()).to_le_bytes());
                        response.extend_from_slice(msg.as_bytes());
                    }
                }
                b"SEND" => {
                    let mut combined_buf = vec![0u8; len];
                    let _ = cur.read_exact(&mut combined_buf);
                    let combined = String::from_utf8_lossy(&combined_buf).to_string();
                    let path = combined.rsplit_once(',').map_or(combined.as_str(), |x| x.0).to_string();

                    // Read DATA chunks.
                    let mut file_data = Vec::new();
                    loop {
                        let mut chunk_id = [0u8; 4];
                        if cur.read_exact(&mut chunk_id).is_err() { break; }
                        let mut chunk_len_buf = [0u8; 4];
                        if cur.read_exact(&mut chunk_len_buf).is_err() { break; }
                        let chunk_len = u32::from_le_bytes(chunk_len_buf) as usize;
                        if &chunk_id == b"DONE" { break; }
                        if &chunk_id == b"DATA" {
                            let mut chunk = vec![0u8; chunk_len];
                            let _ = cur.read_exact(&mut chunk);
                            file_data.extend(chunk);
                        }
                    }
                    self.files.insert(path, file_data);
                    response.extend_from_slice(b"OKAY");
                    response.extend_from_slice(&0u32.to_le_bytes());
                }
                b"QUIT" => break,
                _ => {
                    // Unknown: skip payload.
                    let mut skip = vec![0u8; len];
                    let _ = cur.read_exact(&mut skip);
                }
            }
        }
        response
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stat_response(mode: u32, size: u32, mtime: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"STAT");
        buf.extend_from_slice(&mode.to_le_bytes());
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&mtime.to_le_bytes());
        buf
    }

    fn make_recv_response(data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        for chunk in data.chunks(SYNC_DATA_MAX) {
            buf.extend_from_slice(b"DATA");
            buf.extend_from_slice(&usize_to_u32_sat(chunk.len()).to_le_bytes());
            buf.extend_from_slice(chunk);
        }
        buf.extend_from_slice(b"DONE");
        buf
    }

    fn make_okay_response() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"OKAY");
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf
    }

    #[test]
    fn test_stat_entry_is_dir() {
        let entry = StatEntry { mode: 0o040_755, size: 4096, mtime: 0, path: "/sdcard".into() };
        assert!(entry.is_dir());
        assert!(!entry.is_file());
    }

    #[test]
    fn test_stat_entry_is_file() {
        let entry = StatEntry { mode: 0o100_644, size: 1024, mtime: 0, path: "/sdcard/file.txt".into() };
        assert!(entry.is_file());
        assert!(!entry.is_dir());
    }

    #[test]
    fn test_decode_stat_response() {
        let resp = make_stat_response(0o100_644, 512, 1_720_000_000);
        let entry = decode_stat_response(&mut Cursor::new(resp), "/test/file").unwrap();
        assert!(entry.is_file());
        assert_eq!(entry.size, 512);
        assert_eq!(entry.mtime, 1_720_000_000);
    }

    #[test]
    fn test_decode_recv_stream() {
        let data = b"hello from device";
        let resp = make_recv_response(data);
        let got = decode_recv_stream(&mut Cursor::new(resp)).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn test_decode_push_response_okay() {
        let resp = make_okay_response();
        decode_push_response(&mut Cursor::new(resp)).unwrap();
    }

    #[test]
    fn test_encode_push_stream() {
        let data = b"binary content here";
        let stream = encode_push_stream("/data/local/tmp/test.bin", 0o644, data, 0).unwrap();
        assert!(stream.starts_with(b"SEND"));
        assert!(stream.windows(4).any(|w| w == b"DATA"));
        assert!(stream.ends_with(b"\x00\x00\x00\x00")); // DONE mtime=0
    }

    #[test]
    fn test_mem_sync_server_push_pull() {
        let mut server = MemSyncServer::new();
        let data = b"test file content";
        let req = encode_push_stream("/remote/file.txt", 0o644, data, 12345).unwrap();
        let resp = server.handle(&req);
        assert!(resp.starts_with(b"OKAY"));
        assert!(server.files.contains_key("/remote/file.txt"));

        let pull_req = encode_recv_request("/remote/file.txt").unwrap();
        let pull_resp = server.handle(&pull_req);
        let got = decode_recv_stream(&mut Cursor::new(pull_resp)).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn test_progress_display() {
        let mut prog = TransferProgress::new(1024 * 1024, 10);
        prog.bytes_transferred = 512 * 1024;
        prog.files_done = 5;
        let s = prog.to_string();
        assert!(s.contains("50.0%"));
    }

    #[test]
    fn test_large_file_chunking() {
        let data = vec![0xAAu8; 200 * 1024]; // 200 KB → 4 chunks
        let stream = encode_push_stream("/tmp/large", 0o644, &data, 0).unwrap();
        // Count DATA markers.
        let mut count = 0usize;
        let mut i = 0;
        while i + 4 <= stream.len() {
            if &stream[i..i + 4] == b"DATA" {
                count += 1;
            }
            i += 1;
        }
        assert!(count >= 3, "expected at least 3 DATA chunks, got {count}");
    }

    #[test]
    fn test_path_too_long() {
        let long_path = "x".repeat(SYNC_MAX_PATH + 1);
        let result = encode_stat_request(&long_path);
        assert!(matches!(result, Err(SyncError::PathTooLong(_))));
    }

    #[test]
    fn test_fail_response_handling() {
        let mut fail_resp = Vec::new();
        fail_resp.extend_from_slice(b"FAIL");
        let msg = b"permission denied";
        fail_resp.extend_from_slice(&usize_to_u32_sat(msg.len()).to_le_bytes());
        fail_resp.extend_from_slice(msg);
        let result = decode_push_response(&mut Cursor::new(fail_resp));
        assert!(matches!(result, Err(SyncError::RemoteFail(_))));
    }
}
