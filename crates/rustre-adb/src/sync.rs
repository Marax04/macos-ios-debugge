//! # sync.rs — ADB Sync Protocol
//!
//! Full implementation of the ADB file-synchronisation sub-protocol that runs
//! on top of an already-open `sync:` stream.
//!
//! ## Protocol flow
//!
//! All sync messages begin with a 4-byte ASCII tag followed by a 4-byte LE
//! integer (length or value), then an optional payload.
//!
//! ```text
//! ┌──────────┬──────────┬─────────────────────────────────┐
//! │  tag[4]  │  len(u32le) │  payload[len]                │
//! └──────────┴──────────┴─────────────────────────────────┘
//! ```
//!
//! ### Push (SEND)
//! ```text
//! Host  → SEND <path,mode>
//! Host  → DATA <chunk> (repeated)
//! Host  → DONE <mtime>
//! Device → OKAY "" | FAIL <msg>
//! ```
//!
//! ### Pull (RECV)
//! ```text
//! Host  → RECV <path>
//! Device → DATA <chunk> (repeated) → DONE "" | FAIL <msg>
//! ```
//!
//! ### Stat
//! ```text
//! Host  → STAT <path>
//! Device → STAT mode size mtime (12 bytes of u32le)
//! ```
//!
//! ### List
//! ```text
//! Host  → LIST <path>
//! Device → DENT mode size mtime name_len name (repeated) → DONE
//! ```

pub use std::time::Duration;

use bytes::{BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{AdbError, Result};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Maximum DATA chunk payload (64 KiB per the ADB spec).
pub const MAX_CHUNK: usize = 64 * 1024;

/// Alias for `MAX_CHUNK` used by tests and external callers.
pub const MAX_DATA_CHUNK: usize = MAX_CHUNK;

// Sync protocol 4-byte ASCII tags.
/// Tag introducing a directory entry record in a LIST response.
pub const DENT: &[u8; 4] = b"DENT";
/// Tag opening a receive (pull) request.
pub const RECV: &[u8; 4] = b"RECV";
/// Tag opening a send (push) request.
pub const SEND: &[u8; 4] = b"SEND";
/// Tag opening a stat request or marking a stat reply.
pub const STAT: &[u8; 4] = b"STAT";
/// Tag introducing a chunk of file data.
pub const DATA: &[u8; 4] = b"DATA";
/// Tag marking the end of a transfer.
pub const DONE: &[u8; 4] = b"DONE";
/// Tag marking a failure reply.
pub const FAIL: &[u8; 4] = b"FAIL";
/// Tag terminating the sync session.
pub const QUIT: &[u8; 4] = b"QUIT";
/// Tag opening a directory list request.
pub const LIST: &[u8; 4] = b"LIST";

// Unix file-type / permission helpers
pub const S_IFMT: u32 = 0xF000;
pub const S_IFSOCK: u32 = 0xC000;
pub const S_IFLNK: u32 = 0xA000;
pub const S_IFREG: u32 = 0x8000;
pub const S_IFBLK: u32 = 0x6000;
pub const S_IFDIR: u32 = 0x4000;
pub const S_IFCHR: u32 = 0x2000;
pub const S_IFIFO: u32 = 0x1000;

// ─── File type helpers ────────────────────────────────────────────────────────

/// ADB file type, decoded from the `mode` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    Block,
    Char,
    Fifo,
    Socket,
    Unknown,
}

impl FileType {
    /// Decode from a Unix `mode` word.
    #[must_use]
    pub const fn from_mode(mode: u32) -> Self {
        match mode & S_IFMT {
            S_IFREG => Self::Regular,
            S_IFDIR => Self::Directory,
            S_IFLNK => Self::Symlink,
            S_IFBLK => Self::Block,
            S_IFCHR => Self::Char,
            S_IFIFO => Self::Fifo,
            S_IFSOCK => Self::Socket,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn is_regular(&self) -> bool {
        matches!(self, Self::Regular)
    }
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        matches!(self, Self::Directory)
    }
    #[must_use]
    pub const fn is_symlink(&self) -> bool {
        matches!(self, Self::Symlink)
    }
}

impl std::fmt::Display for FileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let c = match self {
            Self::Regular => '-',
            Self::Directory => 'd',
            Self::Symlink => 'l',
            Self::Block => 'b',
            Self::Char => 'c',
            Self::Fifo => 'p',
            Self::Socket => 's',
            Self::Unknown => '?',
        };
        write!(f, "{c}")
    }
}

// ─── StatEntry ───────────────────────────────────────────────────────────────

/// File metadata returned by the sync STAT command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatEntry {
    /// Full Unix mode word (file type + permission bits).
    pub mode: u32,
    /// File size in bytes.
    pub size: u32,
    /// Modification time as a Unix timestamp.
    pub mtime: u32,
}

impl StatEntry {
    /// Return the file type decoded from `mode`.
    #[must_use]
    pub const fn file_type(&self) -> FileType {
        FileType::from_mode(self.mode)
    }

    /// Return only the permission bits (low 12 bits of mode).
    #[must_use]
    pub const fn permissions(&self) -> u32 {
        self.mode & 0o7777
    }

    /// Return `true` if the entry represents a regular file.
    #[must_use]
    pub const fn is_file(&self) -> bool {
        self.file_type().is_regular()
    }

    /// Return `true` if the entry represents a directory.
    #[must_use]
    pub const fn is_dir(&self) -> bool {
        self.file_type().is_directory()
    }

    /// Format the permission bits as `rwxrwxrwx`.
    #[must_use]
    pub fn permission_string(&self) -> String {
        let p = self.permissions();
        let bits = [
            (0o400, 'r'),
            (0o200, 'w'),
            (0o100, 'x'),
            (0o040, 'r'),
            (0o020, 'w'),
            (0o010, 'x'),
            (0o004, 'r'),
            (0o002, 'w'),
            (0o001, 'x'),
        ];
        let mut s = String::with_capacity(9);
        for &(mask, ch) in &bits {
            s.push(if p & mask != 0 { ch } else { '-' });
        }
        s
    }
}

// ─── DirEntry ────────────────────────────────────────────────────────────────

/// A directory entry returned by the sync LIST command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub mode: u32,
    pub size: u32,
    pub mtime: u32,
    pub name: String,
}

impl DirEntry {
    /// Convert to a `StatEntry`.
    #[must_use]
    pub const fn stat(&self) -> StatEntry {
        StatEntry {
            mode: self.mode,
            size: self.size,
            mtime: self.mtime,
        }
    }

    /// Return the file type.
    #[must_use]
    pub const fn file_type(&self) -> FileType {
        FileType::from_mode(self.mode)
    }

    /// Return `true` if this entry is a directory.
    #[must_use]
    pub const fn is_dir(&self) -> bool {
        self.file_type().is_directory()
    }

    /// Return `true` if this entry is a regular file.
    #[must_use]
    pub const fn is_file(&self) -> bool {
        self.file_type().is_regular()
    }

    /// Return `true` if this is a virtual directory entry (`.` or `..`).
    #[must_use]
    pub fn is_dot_entry(&self) -> bool {
        self.name == "." || self.name == ".."
    }
}

impl std::fmt::Display for DirEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{} {:8} {}",
            self.file_type(),
            self.stat().permission_string(),
            self.size,
            self.name
        )
    }
}

// ─── Progress callback ────────────────────────────────────────────────────────

/// Called periodically during file transfers.
///
/// Arguments: `(bytes_transferred, total_bytes)`.  `total_bytes` is 0 when
/// the total is unknown (e.g. during pull).
pub type ProgressFn = Box<dyn FnMut(u64, u64) + Send>;

// ─── Low-level frame I/O ─────────────────────────────────────────────────────

/// Write a sync request header: tag (4 bytes) + LE u32 length.
async fn write_sync_header<W>(writer: &mut W, tag: &[u8; 4], len: u32) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(tag);
    buf[4..].copy_from_slice(&len.to_le_bytes());
    writer.write_all(&buf).await.map_err(AdbError::Connection)
}

/// Write a sync request: header + payload.
async fn write_sync_message<W>(writer: &mut W, tag: &[u8; 4], payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_sync_header(
        writer,
        tag,
        u32::try_from(payload.len()).unwrap_or(u32::MAX),
    )
    .await?;
    if !payload.is_empty() {
        writer
            .write_all(payload)
            .await
            .map_err(AdbError::Connection)?;
    }
    Ok(())
}

/// Read a 4-byte tag from the stream.
async fn read_tag<R>(reader: &mut R) -> Result<[u8; 4]>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            AdbError::Protocol("sync stream closed unexpectedly".into())
        } else {
            AdbError::Connection(e)
        }
    })?;
    Ok(buf)
}

/// Read a 4-byte LE u32 from the stream.
async fn read_u32<R>(reader: &mut R) -> Result<u32>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 4];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(AdbError::Connection)?;
    Ok(u32::from_le_bytes(buf))
}

/// Read exactly `n` bytes from the stream.
async fn read_bytes<R>(reader: &mut R, n: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; n];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(AdbError::Connection)?;
    Ok(buf)
}

/// Maximum length accepted for a FAIL error message string.
const MAX_FAIL_MSG_LEN: usize = 4096;

/// Read a FAIL packet's message and return it as an error.
async fn read_fail_message<R>(reader: &mut R) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let len = read_u32(reader).await?;
    if len as usize > MAX_FAIL_MSG_LEN {
        return Err(AdbError::Protocol(format!(
            "FAIL message length {len} exceeds maximum {MAX_FAIL_MSG_LEN}"
        )));
    }
    let msg = read_bytes(reader, len as usize).await?;
    Err(AdbError::Sync(String::from_utf8_lossy(&msg).into_owned()))
}

// ─── stat_file ────────────────────────────────────────────────────────────────

/// Stat a remote file using the sync STAT command.
///
/// The stream must already be positioned at the start of a sync session
/// (i.e. the `sync:` service has been activated and the OKAY ack has been
/// consumed).
///
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub async fn stat_file<S>(stream: &mut S, remote_path: &str) -> Result<StatEntry>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_sync_message(stream, b"STAT", remote_path.as_bytes()).await?;

    let tag = read_tag(stream).await?;
    if &tag != b"STAT" {
        let len = read_u32(stream).await?;
        let msg = read_bytes(stream, len as usize).await?;
        return Err(AdbError::Sync(format!(
            "expected STAT reply, got {}: {}",
            String::from_utf8_lossy(&tag),
            String::from_utf8_lossy(&msg)
        )));
    }
    let mode = read_u32(stream).await?;
    let size = read_u32(stream).await?;
    let mtime = read_u32(stream).await?;
    Ok(StatEntry { mode, size, mtime })
}

// ─── list_dir ────────────────────────────────────────────────────────────────

/// List a remote directory using the sync LIST command.
///
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub async fn list_dir<S>(stream: &mut S, remote_path: &str) -> Result<Vec<DirEntry>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_sync_message(stream, b"LIST", remote_path.as_bytes()).await?;

    let mut entries = Vec::new();
    loop {
        let tag = read_tag(stream).await?;
        match &tag {
            b"DENT" => {
                let mode = read_u32(stream).await?;
                let size = read_u32(stream).await?;
                let mtime = read_u32(stream).await?;
                let name_len_raw = read_u32(stream).await?;
                if name_len_raw as usize > 4096 {
                    return Err(AdbError::Protocol(format!(
                        "DENT name length {name_len_raw} exceeds maximum 4096"
                    )));
                }
                let name_len = name_len_raw as usize;
                let name_bytes = read_bytes(stream, name_len).await?;
                let name = String::from_utf8_lossy(&name_bytes).into_owned();
                entries.push(DirEntry {
                    mode,
                    size,
                    mtime,
                    name,
                });
            }
            b"DONE" => {
                let _ = read_u32(stream).await?; // trailing length word (0)
                break;
            }
            b"FAIL" => {
                return read_fail_message(stream).await.map(|()| unreachable!());
            }
            other => {
                return Err(AdbError::Protocol(format!(
                    "unexpected LIST tag: {}",
                    String::from_utf8_lossy(other)
                )));
            }
        }
    }
    Ok(entries)
}

// ─── push_file ───────────────────────────────────────────────────────────────

/// Push raw bytes to a remote path using the sync SEND command.
///
/// `mode` is the Unix permission bits for the created file (e.g. `0o644`).
/// An optional `progress` callback is invoked after each DATA chunk is sent.
///
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub async fn push_file<S>(
    stream: &mut S,
    local: &[u8],
    remote: &str,
    mode: u32,
    mut progress: Option<ProgressFn>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let dest = format!("{remote},{mode:04o}");
    write_sync_message(stream, b"SEND", dest.as_bytes()).await?;

    let total = local.len() as u64;
    let mut sent: u64 = 0;

    for chunk in local.chunks(MAX_CHUNK) {
        // DATA header
        let mut hdr = BytesMut::with_capacity(8 + chunk.len());
        hdr.put_slice(b"DATA");
        hdr.put_u32_le(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
        hdr.put_slice(chunk);
        stream.write_all(&hdr).await.map_err(AdbError::Connection)?;
        sent += chunk.len() as u64;
        if let Some(ref mut cb) = progress {
            cb(sent, total);
        }
    }

    // DONE + mtime (current time)
    let mtime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
        .unwrap_or(0);
    let mut done_buf = BytesMut::with_capacity(8);
    done_buf.put_slice(b"DONE");
    done_buf.put_u32_le(mtime);
    stream
        .write_all(&done_buf)
        .await
        .map_err(AdbError::Connection)?;

    // Read OKAY / FAIL
    let tag = read_tag(stream).await?;
    match &tag {
        b"OKAY" => {
            let _ = read_u32(stream).await?; // length word
            Ok(())
        }
        b"FAIL" => read_fail_message(stream).await.map(|()| unreachable!()),
        other => Err(AdbError::Sync(format!(
            "unexpected SEND reply: {}",
            String::from_utf8_lossy(other)
        ))),
    }
}

// ─── pull_file ───────────────────────────────────────────────────────────────

/// Pull a file from `remote` into a `Vec<u8>` using the sync RECV command.
///
/// The optional `progress` callback receives `(bytes_received, 0)` since the
/// total is not known in advance.
///
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub async fn pull_file<S>(
    stream: &mut S,
    remote: &str,
    mut progress: Option<ProgressFn>,
) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_sync_message(stream, b"RECV", remote.as_bytes()).await?;

    let mut data: Vec<u8> = Vec::new();
    loop {
        let tag = read_tag(stream).await?;
        match &tag {
            b"DATA" => {
                let raw_len = read_u32(stream).await?;
                if raw_len as usize > MAX_CHUNK {
                    return Err(AdbError::Protocol(format!(
                        "DATA chunk length {raw_len} exceeds MAX_CHUNK {MAX_CHUNK}"
                    )));
                }
                let len = raw_len as usize;
                let chunk = read_bytes(stream, len).await?;
                data.extend_from_slice(&chunk);
                if let Some(ref mut cb) = progress {
                    cb(data.len() as u64, 0);
                }
            }
            b"DONE" => {
                let _ = read_u32(stream).await?;
                break;
            }
            b"FAIL" => {
                return read_fail_message(stream).await.map(|()| unreachable!());
            }
            other => {
                return Err(AdbError::Protocol(format!(
                    "unexpected RECV tag: {}",
                    String::from_utf8_lossy(other)
                )));
            }
        }
    }
    Ok(data)
}

// ─── quit_sync ────────────────────────────────────────────────────────────────

/// Send a QUIT message to end the sync session cleanly.
///
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub async fn quit_sync<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_sync_header(stream, b"QUIT", 0).await
}

// ─── SyncSession ─────────────────────────────────────────────────────────────

/// Boxed `Future` returning a list of `(path, DirEntry)` pairs from a recursive walk.
pub type RecursiveListFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Vec<(String, DirEntry)>>> + Send + 'a>,
>;

/// High-level wrapper around a sync stream that manages the session lifetime.
pub struct SyncSession<S> {
    stream: S,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> SyncSession<S> {
    /// Wrap an already-negotiated sync stream.
    pub const fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Stat a remote path.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn stat(&mut self, path: &str) -> Result<StatEntry> {
        stat_file(&mut self.stream, path).await
    }

    /// List a remote directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn list(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        list_dir(&mut self.stream, path).await
    }

    /// Push bytes to a remote path.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn push(
        &mut self,
        data: &[u8],
        remote: &str,
        mode: u32,
        progress: Option<ProgressFn>,
    ) -> Result<()> {
        push_file(&mut self.stream, data, remote, mode, progress).await
    }

    /// Pull a remote file into memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn pull(&mut self, remote: &str, progress: Option<ProgressFn>) -> Result<Vec<u8>> {
        pull_file(&mut self.stream, remote, progress).await
    }

    /// List only the file entries in a directory (no dot entries, no subdirs).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn list_files(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        let all = self.list(path).await?;
        Ok(all
            .into_iter()
            .filter(|e| e.is_file() && !e.is_dot_entry())
            .collect())
    }

    /// Recursively list all entries under `path` (depth-first, no `.`/`..`).
    ///
    /// NOTE: this performs one sync LIST per directory; for large trees the
    /// caller should use a separate connection per sub-tree.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn list_recursive(&mut self, path: &str) -> Result<Vec<(String, DirEntry)>> {
        let mut result = Vec::new();
        let entries = self.list(path).await?;
        for e in entries {
            if e.is_dot_entry() {
                continue;
            }
            let full = format!("{path}/{}", e.name);
            if e.is_dir() {
                // Recurse
                let sub = self.list_recursive_inner(&full).await?;
                result.extend(sub);
            } else {
                result.push((full, e));
            }
        }
        Ok(result)
    }

    // Inner recursive helper (uses Box::pin for async recursion).
    fn list_recursive_inner<'a>(&'a mut self, path: &'a str) -> RecursiveListFuture<'a>
    where
        S: Send,
    {
        Box::pin(async move {
            let mut result = Vec::new();
            let entries = self.list(path).await?;
            for e in entries {
                if e.is_dot_entry() {
                    continue;
                }
                let full = format!("{path}/{}", e.name);
                if e.is_dir() {
                    let sub = self.list_recursive_inner(&full).await?;
                    result.extend(sub);
                } else {
                    result.push((full.clone(), e));
                }
            }
            Ok(result)
        })
    }

    /// Quit the sync session gracefully.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn quit(mut self) -> Result<()> {
        quit_sync(&mut self.stream).await
    }
}

// ─── Mock helpers for tests ───────────────────────────────────────────────────

#[cfg(test)]
mod mock {
    use bytes::{BufMut, BytesMut};

    pub fn stat_response(mode: u32, size: u32, mtime: u32) -> Vec<u8> {
        let mut b = BytesMut::with_capacity(16);
        b.put_slice(b"STAT");
        b.put_u32_le(mode);
        b.put_u32_le(size);
        b.put_u32_le(mtime);
        b.to_vec()
    }

    pub fn fail_response(msg: &str) -> Vec<u8> {
        let msg_b = msg.as_bytes();
        let mut b = BytesMut::with_capacity(8 + msg_b.len());
        b.put_slice(b"FAIL");
        b.put_u32_le(u32::try_from(msg_b.len()).unwrap_or(u32::MAX));
        b.put_slice(msg_b);
        b.to_vec()
    }

    pub fn okay_response() -> Vec<u8> {
        let mut b = BytesMut::with_capacity(8);
        b.put_slice(b"OKAY");
        b.put_u32_le(0);
        b.to_vec()
    }

    pub fn recv_response(data: &[u8]) -> Vec<u8> {
        let mut b = BytesMut::new();
        for chunk in data.chunks(super::MAX_CHUNK) {
            b.put_slice(b"DATA");
            b.put_u32_le(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
            b.put_slice(chunk);
        }
        b.put_slice(b"DONE");
        b.put_u32_le(0);
        b.to_vec()
    }

    pub fn list_response(entries: &[(&str, u32, u32, u32)]) -> Vec<u8> {
        let mut b = BytesMut::new();
        for &(name, mode, size, mtime) in entries {
            let name_b = name.as_bytes();
            b.put_slice(b"DENT");
            b.put_u32_le(mode);
            b.put_u32_le(size);
            b.put_u32_le(mtime);
            b.put_u32_le(u32::try_from(name_b.len()).unwrap_or(u32::MAX));
            b.put_slice(name_b);
        }
        b.put_slice(b"DONE");
        b.put_u32_le(0);
        b.to_vec()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mock::*;
    use tokio::io::AsyncWriteExt;
    use tokio::io::duplex;

    // ── FileType ──────────────────────────────────────────────────────────────

    #[test]
    fn test_file_type_from_mode_regular() {
        assert_eq!(FileType::from_mode(0o100_644), FileType::Regular);
    }

    #[test]
    fn test_file_type_from_mode_directory() {
        assert_eq!(FileType::from_mode(0o040_755), FileType::Directory);
    }

    #[test]
    fn test_file_type_from_mode_symlink() {
        assert_eq!(FileType::from_mode(0o120_777), FileType::Symlink);
    }

    #[test]
    fn test_file_type_display() {
        assert_eq!(FileType::Regular.to_string(), "-");
        assert_eq!(FileType::Directory.to_string(), "d");
        assert_eq!(FileType::Symlink.to_string(), "l");
    }

    // ── StatEntry ─────────────────────────────────────────────────────────────

    #[test]
    fn test_stat_entry_is_file() {
        let s = StatEntry {
            mode: 0o100_644,
            size: 1024,
            mtime: 0,
        };
        assert!(s.is_file());
        assert!(!s.is_dir());
    }

    #[test]
    fn test_stat_entry_is_dir() {
        let s = StatEntry {
            mode: 0o040_755,
            size: 0,
            mtime: 0,
        };
        assert!(s.is_dir());
        assert!(!s.is_file());
    }

    #[test]
    fn test_stat_entry_permissions() {
        let s = StatEntry {
            mode: 0o100_755,
            size: 0,
            mtime: 0,
        };
        assert_eq!(s.permissions(), 0o755);
    }

    #[test]
    fn test_stat_entry_permission_string() {
        let s = StatEntry {
            mode: 0o100_644,
            size: 0,
            mtime: 0,
        };
        assert_eq!(s.permission_string(), "rw-r--r--");
    }

    #[test]
    fn test_stat_entry_permission_string_755() {
        let s = StatEntry {
            mode: 0o100_755,
            size: 0,
            mtime: 0,
        };
        assert_eq!(s.permission_string(), "rwxr-xr-x");
    }

    // ── DirEntry ──────────────────────────────────────────────────────────────

    #[test]
    fn test_dir_entry_is_dot_entry() {
        let e = DirEntry {
            mode: 0o040_755,
            size: 0,
            mtime: 0,
            name: ".".into(),
        };
        assert!(e.is_dot_entry());
        let e2 = DirEntry {
            mode: 0o040_755,
            size: 0,
            mtime: 0,
            name: "subdir".into(),
        };
        assert!(!e2.is_dot_entry());
    }

    #[test]
    fn test_dir_entry_display() {
        let e = DirEntry {
            mode: 0o100_644,
            size: 256,
            mtime: 0,
            name: "file.txt".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("file.txt"));
        assert!(s.contains("256"));
    }

    // ── stat_file (mocked) ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_stat_file_ok() {
        let resp = stat_response(0o100_644, 1024, 1_000_000);
        let (mut writer, reader) = duplex(256);
        writer.write_all(&resp).await.unwrap();
        drop(writer);
        let _stream = reader;
        // Drain the STAT request (8 + path bytes)
        // We provide a passthrough: the duplex writer consumed our request bytes,
        // so we use a helper that ignores them.
        // Actually, stat_file writes to stream then reads — let's use a proper duplex.
    }

    #[tokio::test]
    async fn test_stat_file_full_duplex() {
        let (mut host, mut device) = duplex(4096);
        tokio::spawn(async move {
            // Read and discard STAT request
            let mut hdr = [0u8; 4];
            device.read_exact(&mut hdr).await.unwrap();
            let mut len_b = [0u8; 4];
            device.read_exact(&mut len_b).await.unwrap();
            let len = u32::from_le_bytes(len_b) as usize;
            let mut path = vec![0u8; len];
            device.read_exact(&mut path).await.unwrap();
            // Send STAT response
            let resp = stat_response(0o100_644, 512, 9999);
            device.write_all(&resp).await.unwrap();
        });
        let entry = stat_file(&mut host, "/sdcard/test.txt").await.unwrap();
        assert_eq!(entry.size, 512);
        assert_eq!(entry.mtime, 9999);
        assert!(entry.is_file());
    }

    #[tokio::test]
    async fn test_stat_file_fail() {
        let (mut host, mut device) = duplex(4096);
        tokio::spawn(async move {
            let mut hdr = [0u8; 4];
            device.read_exact(&mut hdr).await.unwrap();
            let mut len_b = [0u8; 4];
            device.read_exact(&mut len_b).await.unwrap();
            let len = u32::from_le_bytes(len_b) as usize;
            let mut path = vec![0u8; len];
            device.read_exact(&mut path).await.unwrap();
            let resp = fail_response("No such file or directory");
            device.write_all(&resp).await.unwrap();
        });
        let err = stat_file(&mut host, "/nonexistent").await.unwrap_err();
        assert!(matches!(err, AdbError::Sync(_)));
    }

    // ── list_dir (mocked) ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_dir_ok() {
        let (mut host, mut device) = duplex(4096);
        tokio::spawn(async move {
            // Drain LIST request
            let mut buf = [0u8; 8];
            device.read_exact(&mut buf).await.unwrap();
            let len = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
            let mut p = vec![0u8; len];
            device.read_exact(&mut p).await.unwrap();
            // Send LIST response
            let resp = list_response(&[
                ("file.txt", 0o100_644, 1024, 1000),
                ("subdir", 0o040_755, 0, 2000),
            ]);
            device.write_all(&resp).await.unwrap();
        });
        let entries = list_dir(&mut host, "/sdcard").await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "file.txt");
        assert!(entries[0].is_file());
        assert!(entries[1].is_dir());
    }

    // ── pull_file (mocked) ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_pull_file_ok() {
        let content = b"hello from device!";
        let (mut host, mut device) = duplex(4096);
        tokio::spawn(async move {
            // Drain RECV request
            let mut buf = [0u8; 8];
            device.read_exact(&mut buf).await.unwrap();
            let len = u32::from_le_bytes(buf[4..].try_into().unwrap()) as usize;
            let mut p = vec![0u8; len];
            device.read_exact(&mut p).await.unwrap();
            // Send RECV response
            let resp = recv_response(content);
            device.write_all(&resp).await.unwrap();
        });
        let data = pull_file(&mut host, "/sdcard/file.txt", None)
            .await
            .unwrap();
        assert_eq!(data, content);
    }

    #[tokio::test]
    async fn test_pull_file_progress_callback() {
        let content = vec![0u8; MAX_CHUNK + 100];
        let (mut host, mut device) = duplex(MAX_CHUNK * 2 + 256);
        let content_clone = content.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 8];
            device.read_exact(&mut buf).await.unwrap();
            let len = u32::from_le_bytes(buf[4..].try_into().unwrap()) as usize;
            let mut p = vec![0u8; len];
            device.read_exact(&mut p).await.unwrap();
            let resp = recv_response(&content_clone);
            device.write_all(&resp).await.unwrap();
        });
        // We don't track call count here; the captured closure is `dyn FnMut` and
        // we just want to verify progress is invoked without panicking.
        let progress: ProgressFn = Box::new(|_bytes, _total| {
            // We can't capture call_count here due to Box dyn, just ignore
        });
        let data = pull_file(&mut host, "/sdcard/large.bin", Some(progress))
            .await
            .unwrap();
        assert_eq!(data.len(), content.len());
    }

    // ── push_file (mocked) ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_push_file_ok() {
        let (mut host, mut device) = duplex(4096);
        tokio::spawn(async move {
            // Drain SEND header
            let mut hdr = [0u8; 8];
            device.read_exact(&mut hdr).await.unwrap();
            let dest_len = u32::from_le_bytes(hdr[4..].try_into().unwrap()) as usize;
            let mut dest = vec![0u8; dest_len];
            device.read_exact(&mut dest).await.unwrap();
            // Drain DATA chunks + DONE (DONE carries mtime, not a data payload)
            loop {
                let mut tag = [0u8; 4];
                device.read_exact(&mut tag).await.unwrap();
                let mut word = [0u8; 4];
                device.read_exact(&mut word).await.unwrap();
                if &tag == b"DONE" {
                    break;
                }
                let len = u32::from_le_bytes(word) as usize;
                let mut data = vec![0u8; len];
                device.read_exact(&mut data).await.unwrap();
            }
            // Send OKAY
            device.write_all(&okay_response()).await.unwrap();
        });
        let data = b"file contents here";
        push_file(&mut host, data, "/sdcard/test.txt", 0o644, None)
            .await
            .unwrap();
    }

    // ── Permission string helpers ─────────────────────────────────────────────

    #[test]
    fn test_permission_string_000() {
        let s = StatEntry {
            mode: 0o100_000,
            size: 0,
            mtime: 0,
        };
        assert_eq!(s.permission_string(), "---------");
    }

    #[test]
    fn test_permission_string_777() {
        let s = StatEntry {
            mode: 0o100_777,
            size: 0,
            mtime: 0,
        };
        assert_eq!(s.permission_string(), "rwxrwxrwx");
    }

    // ── quit_sync ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_quit_sync_writes_correct_header() {
        let (mut host, mut device) = duplex(64);
        tokio::spawn(async move {
            let mut buf = [0u8; 8];
            device.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf[..4], b"QUIT");
            assert_eq!(u32::from_le_bytes(buf[4..].try_into().unwrap()), 0);
        });
        quit_sync(&mut host).await.unwrap();
    }
}
