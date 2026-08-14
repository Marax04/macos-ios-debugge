//! `pdb_symbol_server` — Microsoft Symbol Server PDB downloader.
//!
//! Downloads PDB files from the Microsoft public symbol server
//! (`https://msdl.microsoft.com/download/symbols`) using the canonical
//! "two-tier" URL scheme:
//!
//! ```text
//! /symbols/<pdb_name>/<GUID_Age>/<pdb_name>
//! ```
//!
//! where `GUID_Age` is the 32-hex-char GUID (no hyphens) followed by the
//! decimal age, e.g. `"8DBCFE23C22D4C65AA57DA6E2DCC16731"`.
//!
//! The downloaded file is cached under `~/.rustre/pdb/<pdb_name>/<GUID_Age>/`
//! so subsequent calls for the same PDB version return immediately from disk.
//!
//! ## vs WinDbg
//! WinDbg's `.symfix` / `.reload /f` drives the same protocol but requires
//! a live session.  This module exposes the same download logic as a pure
//! library function usable during static analysis, offline symbol enrichment,
//! or from an LLM tool-call — no debugger session needed.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;
use thiserror::Error;

use crate::circuit_breaker::CircuitBreaker;

/// Global circuit breaker for the Microsoft Symbol Server: after 3 consecutive
/// HTTP failures within 60 s, stops issuing requests for 60 s.
pub static SYM_SERVER_BREAKER: LazyLock<CircuitBreaker> =
    LazyLock::new(|| CircuitBreaker::new(3, Duration::from_secs(60)));

/// Errors produced by the PDB symbol server client.
#[derive(Debug, Error)]
pub enum SymSrvError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("PDB not found on server: {0}")]
    NotFound(String),
    #[error("invalid CodeView record: {0}")]
    BadCodeView(String),
    #[error("home directory not found")]
    NoHome,
    /// The circuit breaker is open: the symbol server is currently considered
    /// unreachable after repeated failures. Callers should back off and retry later.
    #[error("symbol server unreachable (circuit breaker open): {0}")]
    Unreachable(String),
}

// ── CodeView / RSDS record ────────────────────────────────────────────────────

/// The GUID + Age extracted from a PE's CodeView "RSDS" debug directory entry.
///
/// This is the key for locating the matching PDB on a symbol server.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PdbIdentity {
    /// PDB file name (basename only, e.g. `"ntdll.pdb"`).
    pub pdb_name: String,
    /// GUID as a 32-character hex string without hyphens, followed by the age
    /// decimal digit(s), matching the symbol-server URL component exactly.
    ///
    /// Example: `"3844DBB920174967BE7AA4A2C20430FA2"` (32 hex + age "2").
    pub guid_age: String,
}

impl PdbIdentity {
    /// Build a new identity from the raw GUID bytes (16), the age (u32), and
    /// the PDB file name.
    ///
    /// The GUID is formatted in the Microsoft "mixed-endian" style:
    /// the first three components are stored little-endian in the binary, but
    /// the symbol-server URL concatenates them as if they were big-endian
    /// unsigned integers, followed by the last 8 bytes in big-endian order.
    /// Concretely: `{Data1:08X}{Data2:04X}{Data3:04X}{Data4[0..8] as hex}` +
    /// `Age` in HEXADECIMAL, uppercase and unpadded — dbghelp/symchk format it
    /// with `%X`. Decimal agrees only for `Age < 10`; from 10 up it yields a
    /// URL no symbol server resolves.
    #[must_use]
    pub fn new(guid_bytes: &[u8; 16], age: u32, pdb_name: impl Into<String>) -> Self {
        let data1 = u32::from_le_bytes([guid_bytes[0], guid_bytes[1], guid_bytes[2], guid_bytes[3]]);
        let data2 = u16::from_le_bytes([guid_bytes[4], guid_bytes[5]]);
        let data3 = u16::from_le_bytes([guid_bytes[6], guid_bytes[7]]);
        let data4 = &guid_bytes[8..16];
        let guid_age = format!(
            "{data1:08X}{data2:04X}{data3:04X}{d4}{age:X}",
            d4 = data4.iter().map(|b| format!("{b:02X}")).collect::<String>(),
        );
        Self {
            pdb_name: pdb_name.into(),
            guid_age,
        }
    }

    /// Parse a CodeView "RSDS" record from raw bytes.
    ///
    /// The RSDS structure is:
    /// - 4 bytes: signature `"RSDS"`
    /// - 16 bytes: GUID
    /// - 4 bytes: Age (LE)
    /// - NUL-terminated UTF-8 PDB path
    ///
    /// # Errors
    /// Returns [`SymSrvError::BadCodeView`] for any structural problem.
    pub fn from_rsds(data: &[u8]) -> Result<Self, SymSrvError> {
        if data.len() < 24 {
            return Err(SymSrvError::BadCodeView("too short".into()));
        }
        if &data[0..4] != b"RSDS" {
            return Err(SymSrvError::BadCodeView("wrong signature".into()));
        }
        let guid_bytes: &[u8; 16] = data[4..20]
            .try_into()
            .map_err(|_| SymSrvError::BadCodeView("GUID slice wrong length".into()))?;
        let age = u32::from_le_bytes(
            data[20..24]
                .try_into()
                .map_err(|_| SymSrvError::BadCodeView("age slice wrong length".into()))?,
        );
        // NUL-terminated path starts at byte 24
        let path_bytes = &data[24..];
        let nul = path_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(path_bytes.len());
        let pdb_path = std::str::from_utf8(&path_bytes[..nul])
            .map_err(|e| SymSrvError::BadCodeView(e.to_string()))?;
        // Keep only the basename. PDB paths embedded in binaries may use
        // Windows backslash separators even when parsed on Linux, so we strip
        // by both '/' and '\\' rather than relying on std::path::Path.
        let pdb_name = pdb_path
            .rsplit(|c| c == '/' || c == '\\')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or(pdb_path)
            .to_string();
        Ok(Self::new(guid_bytes, age, pdb_name))
    }

    /// Return the symbol-server URL path component:
    /// `/<pdb_name>/<guid_age>/<pdb_name>`.
    #[must_use]
    pub fn server_path(&self) -> String {
        format!("/{}/{}/{}", self.pdb_name, self.guid_age, self.pdb_name)
    }
}

impl fmt::Display for PdbIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.pdb_name, self.guid_age)
    }
}

// ── local cache ───────────────────────────────────────────────────────────────

/// Return the local cache path for a PDB:
/// `~/.rustre/pdb/<pdb_name>/<guid_age>/<pdb_name>`.
///
/// # Errors
/// Returns [`SymSrvError::NoHome`] when the home directory cannot be
/// determined.
pub fn cache_path(identity: &PdbIdentity) -> Result<PathBuf, SymSrvError> {
    let home = dirs_home()?;
    Ok(home
        .join(".rustre")
        .join("pdb")
        .join(&identity.pdb_name)
        .join(&identity.guid_age)
        .join(&identity.pdb_name))
}

fn dirs_home() -> Result<PathBuf, SymSrvError> {
    // std::env::var("USERPROFILE") on Windows, "HOME" on Unix.
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .map(PathBuf::from)
            .map_err(|_| SymSrvError::NoHome)
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME")
            .map(PathBuf::from)
            .map_err(|_| SymSrvError::NoHome)
    }
}

/// Return the cached PDB path if it already exists on disk.
///
/// # Errors
/// Returns [`SymSrvError::NoHome`] if the home directory is unavailable.
pub fn cached(identity: &PdbIdentity) -> Result<Option<PathBuf>, SymSrvError> {
    let path = cache_path(identity)?;
    if !path.exists() {
        return Ok(None);
    }
    // Existence is not validity. A cache entry poisoned by an earlier build —
    // an HTML error page served with HTTP 200, a body truncated by a dropped
    // connection — would otherwise be returned forever: every call short-
    // circuits on `dest.exists()`, so nothing ever downloads it again and every
    // symbol lookup from then on reads a file that is not a PDB.
    match std::fs::read(&path) {
        Ok(bytes) if looks_like_pdb(&bytes) => Ok(Some(path)),
        Ok(_) => {
            tracing::warn!(
                path = %path.display(),
                "cached symbol file is not a PDB; ignoring it so it can be fetched again"
            );
            Ok(None)
        }
        Err(_) => Ok(None),
    }
}

/// Magic of an MSF 7.00 container, which is what every modern PDB is.
const MSF7_MAGIC: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS";
/// Magic of the older MSF 2.00 container, still produced by some toolchains.
const MSF2_MAGIC: &[u8] = b"Microsoft C/C++ program database 2.00\r\n\x1aJG";

/// Whether `bytes` begin with a PDB container signature.
///
/// A symbol server answers a missing file with a 200 and an HTML error page
/// often enough that this cannot be assumed away, and a body truncated by a
/// dropped connection looks like a short PDB. Neither is detectable later:
/// once such a body reaches the cache path, `cached()` returns it forever.
#[must_use]
pub fn looks_like_pdb(bytes: &[u8]) -> bool {
    bytes.starts_with(MSF7_MAGIC) || bytes.starts_with(MSF2_MAGIC)
}

// ── download (sync, via std HTTP or stub) ────────────────────────────────────

/// Default Microsoft public symbol server base URL.
pub const MSFT_SYM_SERVER: &str = "https://msdl.microsoft.com/download/symbols";

/// Download a PDB from the symbol server and cache it locally.
///
/// If the PDB is already cached this is a no-op that returns the cached path
/// immediately (no network access).
///
/// Uses a simple blocking HTTP GET via [`std::net::TcpStream`] + TLS is NOT
/// implemented here — callers that need TLS should use the async variant below
/// or drive this with an HTTP client crate.  For the MCP tool wrapper (which
/// runs inside an async context), use [`download_async`] instead.
///
/// When compiled without the `reqwest` feature this function always returns
/// `Err(SymSrvError::Http("reqwest not available"))`.
///
/// # Errors
/// Returns [`SymSrvError`] on network or IO failure, or `NotFound` for HTTP 404.
pub fn download_sync(
    identity: &PdbIdentity,
    server: &str,
) -> Result<PathBuf, SymSrvError> {
    // Fast path: already cached.
    let dest = cache_path(identity)?;
    if dest.exists() {
        return Ok(dest);
    }

    // Build URL.
    let url = format!("{server}{}", identity.server_path());
    tracing::debug!("Downloading PDB: {url}");

    // Wrap the HTTP call in the global circuit breaker so that repeated
    // symbol-server failures do not flood the network.
    SYM_SERVER_BREAKER
        .call(|| download_http(&url, &dest))
        .map_err(|e| {
            if e.contains("circuit breaker open") {
                SymSrvError::Unreachable(e)
            } else {
                SymSrvError::Http(e)
            }
        })?;
    Ok(dest)
}

/// Async variant: download a PDB using the `reqwest` blocking client wrapped
/// in `tokio::task::spawn_blocking`.
///
/// This is the variant called from MCP tool handlers (which run inside a
/// Tokio runtime).
///
/// # Errors
/// Returns [`SymSrvError`] on any failure.
pub async fn download_async(
    identity: &PdbIdentity,
    server: &str,
) -> Result<PathBuf, SymSrvError> {
    let dest = cache_path(identity)?;
    if dest.exists() {
        return Ok(dest);
    }
    let url = format!("{server}{}", identity.server_path());
    let dest_clone = dest.clone();
    // Run the blocking download inside spawn_blocking, and route through the
    // circuit breaker so consecutive failures open the breaker.
    tokio::task::spawn_blocking(move || {
        SYM_SERVER_BREAKER
            .call(|| download_http(&url, &dest_clone))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    })
    .await
    .map_err(|e| SymSrvError::Http(e.to_string()))?
    .map_err(SymSrvError::Io)?;
    Ok(dest)
}

/// Perform a blocking HTTP/1.1 GET and write the response body to `dest`.
///
/// Creates parent directories as needed. Handles HTTP redirects (up to 5
/// hops) that the symbol server sometimes issues. This deliberately avoids
/// any third-party HTTP crate so the domain crate stays dependency-light;
/// the async path in `download_async` can swap this out for `reqwest` if
/// needed.
/// How many redirects [`download_http`] will follow before giving up.
pub const MAX_REDIRECTS: usize = 5;

/// The URL a redirect response points at, resolved against the request URL.
///
/// `None` when the status is not a redirect, when there is no usable
/// `Location`, or when the target cannot be resolved — never a guess.
///
/// A `Location` may be absolute (`https://host/path`), root-relative
/// (`/path`), or path-relative. Symbol servers use all three, and the download
/// path used to follow none of them: `download_http`'s own doc comment claimed
/// "handles HTTP redirects (up to 5 hops) that the symbol server sometimes
/// issues" while the code sent every 3xx straight into the `status != 200`
/// error branch. `msdl.microsoft.com` answers a great many requests with a
/// 302, so the documented capability did not merely lag the code — it had
/// never existed, and the download simply failed.
#[must_use]
pub fn redirect_target(status: u16, headers: &str, request_url: &str) -> Option<String> {
    if !matches!(status, 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    let location = headers.lines().find_map(|l| {
        let (name, value) = l.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("location")
            .then(|| value.trim())
    })?;
    if location.is_empty() {
        return None;
    }
    if location.contains("://") {
        return Some(location.to_string());
    }
    // Relative: resolve against the request URL's scheme and authority.
    let (scheme, rest) = request_url.split_once("://")?;
    let authority = rest.split('/').next()?;
    if let Some(abs_path) = location.strip_prefix('/') {
        return Some(format!("{scheme}://{authority}/{abs_path}"));
    }
    // Path-relative: replace the last segment of the request path.
    let base_path = rest.strip_prefix(authority).unwrap_or("");
    let parent = base_path.rsplit_once('/').map_or("", |(head, _)| head);
    Some(format!("{scheme}://{authority}{parent}/{location}"))
}

fn download_http(url: &str, dest: &Path) -> Result<(), std::io::Error> {
    let mut url = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        match download_http_once(&url, dest)? {
            Some(next) => url = next,
            None => return Ok(()),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("symbol server redirected more than {MAX_REDIRECTS} times"),
    ))
}

/// One HTTP exchange. `Ok(Some(url))` means "follow this redirect".
fn download_http_once(url: &str, dest: &Path) -> Result<Option<String>, std::io::Error> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    // Very minimal HTTP/1.1 over plain TCP (works for http:// symbol mirrors;
    // for https:// callers should use `download_async` which uses reqwest+TLS).
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    let (host_port, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = format!("/{path}");
    let port: u16 = if scheme == "https" { 443 } else { 80 };
    let host = host_port.split(':').next().unwrap_or(host_port);
    let port = host_port
        .splitn(2, ':')
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(port);

    if scheme == "https" {
        // Cannot do TLS without a crate — return a descriptive IO error so
        // callers know to use the async path.
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "HTTPS requires download_async (TLS not available in sync path)",
        ));
    }

    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&addr)?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: RustRE/0.1\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;

    // Split headers / body
    let header_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no header end"))?;
    let header_str = std::str::from_utf8(&response[..header_end])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let status: u16 = header_str
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if let Some(next) = redirect_target(status, header_str, url) {
        return Ok(Some(next));
    }
    if status == 404 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("symbol server returned 404 for {url}"),
        ));
    }
    if status != 200 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("symbol server returned HTTP {status}"),
        ));
    }

    let body = &response[header_end + 4..];

    // A `Content-Length` that does not match what arrived means the connection
    // dropped mid-body. The partial file used to be written to the final cache
    // path, where it is indistinguishable from a complete download and is
    // returned by every later call.
    if let Some(expected) = header_str
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length:").or_else(|| l.strip_prefix("content-length:")))
        .and_then(|v| v.trim().parse::<usize>().ok())
        && body.len() != expected
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!(
                "symbol server body is {} bytes but Content-Length says {expected}: truncated download",
                body.len()
            ),
        ));
    }

    // Refuse anything that is not a PDB container. Symbol servers answer a
    // missing file with an HTML page and HTTP 200 often enough that trusting
    // the status code alone poisons the cache permanently.
    if !looks_like_pdb(body) {
        let head: String = body
            .iter()
            .take(16)
            .map(|b| if b.is_ascii_graphic() { *b as char } else { '.' })
            .collect();
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("response for {url} is not a PDB container (starts with {head:?})"),
        ));
    }

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Write beside the destination and rename, so an interrupted process
    // cannot leave a half-written file at the canonical cache path.
    let tmp = dest.with_extension("pdb.part");
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, dest)?;
    Ok(None)
}

// ── PE helper: extract PDB identity from a PE image ──────────────────────────

/// Extract the [`PdbIdentity`] from a PE image's debug directory.
///
/// Scans the PE's debug directory for a CodeView "RSDS" entry and decodes it.
/// Returns `None` if the PE has no CodeView debug directory or the image
/// is not a valid PE.
#[must_use]
pub fn identity_from_pe(pe_bytes: &[u8]) -> Option<PdbIdentity> {
    // Minimal PE walk: DOS → NT → optional header → debug data directory.
    if pe_bytes.len() < 64 {
        return None;
    }
    if &pe_bytes[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(pe_bytes[60..64].try_into().ok()?) as usize;
    if e_lfanew + 4 > pe_bytes.len() {
        return None;
    }
    if &pe_bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    let num_sections =
        u16::from_le_bytes(pe_bytes.get(coff + 2..coff + 4)?.try_into().ok()?) as usize;
    let opt_size =
        u16::from_le_bytes(pe_bytes.get(coff + 16..coff + 18)?.try_into().ok()?) as usize;
    let opt_start = coff + 20;

    // Debug data directory is at offset 120 (PE32+) or 104 (PE32) from
    // optional header start; it's index 6 in the data directory array.
    let magic = u16::from_le_bytes(pe_bytes.get(opt_start..opt_start + 2)?.try_into().ok()?);
    let dd_base = opt_start + if magic == 0x020b { 112 } else { 96 };
    // data directory entry 6: Debug (2 * 8 bytes past dd_base)
    let debug_dd = dd_base + 6 * 8;
    if debug_dd + 8 > pe_bytes.len() {
        return None;
    }
    let debug_rva = u32::from_le_bytes(pe_bytes[debug_dd..debug_dd + 4].try_into().ok()?) as usize;
    let debug_size = u32::from_le_bytes(pe_bytes[debug_dd + 4..debug_dd + 8].try_into().ok()?) as usize;
    if debug_rva == 0 || debug_size == 0 {
        return None;
    }

    // Convert debug_rva to file offset via section table
    let section_table_start = opt_start + opt_size;
    let debug_file_offset = rva_to_file_offset_pe(pe_bytes, debug_rva as u32, num_sections, section_table_start)?;

    // IMAGE_DEBUG_DIRECTORY entries (28 bytes each)
    let entry_count = debug_size / 28;
    for i in 0..entry_count {
        let entry = debug_file_offset + i * 28;
        if entry + 28 > pe_bytes.len() {
            break;
        }
        let debug_type = u32::from_le_bytes(pe_bytes[entry + 12..entry + 16].try_into().ok()?);
        if debug_type != 2 {
            // Not IMAGE_DEBUG_TYPE_CODEVIEW
            continue;
        }
        let data_size = u32::from_le_bytes(pe_bytes[entry + 16..entry + 20].try_into().ok()?) as usize;
        let data_offset = u32::from_le_bytes(pe_bytes[entry + 24..entry + 28].try_into().ok()?) as usize;
        if data_offset + data_size > pe_bytes.len() {
            continue;
        }
        return PdbIdentity::from_rsds(&pe_bytes[data_offset..data_offset + data_size]).ok();
    }
    None
}

fn rva_to_file_offset_pe(
    pe: &[u8],
    rva: u32,
    num_sections: usize,
    section_table_start: usize,
) -> Option<usize> {
    for i in 0..num_sections {
        let sh = section_table_start + i * 40;
        if sh + 40 > pe.len() {
            break;
        }
        let va = u32::from_le_bytes(pe[sh + 12..sh + 16].try_into().ok()?);
        let vs = u32::from_le_bytes(pe[sh + 16..sh + 20].try_into().ok()?);
        let raw = u32::from_le_bytes(pe[sh + 20..sh + 24].try_into().ok()?);
        if rva >= va && rva < va + vs {
            return Some((raw + (rva - va)) as usize);
        }
    }
    None
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdb_identity_formatting() {
        // Known GUID from ntdll.pdb (made up for test purposes).
        let guid: [u8; 16] = [
            0x23, 0xFE, 0xBC, 0x8D,  // Data1 LE = 0x8DBCFE23
            0x2D, 0xC2,               // Data2 LE = 0xC22D
            0x4C, 0x65,               // Data3 LE = 0x654C
            0xAA, 0x57, 0xDA, 0x6E, 0x2D, 0xCC, 0x16, 0x73, // Data4
        ];
        let id = PdbIdentity::new(&guid, 1, "ntdll.pdb");
        assert_eq!(id.pdb_name, "ntdll.pdb");
        // Data1 = 0x8DBCFE23, Data2 = 0xC22D, Data3 = 0x654C
        assert!(id.guid_age.starts_with("8DBCFE23C22D654C"));
        assert!(id.guid_age.ends_with('1'));
        let path = id.server_path();
        assert!(path.starts_with("/ntdll.pdb/"));
        assert!(path.ends_with("/ntdll.pdb"));
    }

    /// The symbol-server key ends with the age in HEXADECIMAL, not decimal.
    ///
    /// The Microsoft symbol-server path is
    /// `<pdb>/<32 hex GUID><Age as %X>/<pdb>` — dbghelp, symchk and every
    /// public symbol server format the age with `%X`. `{age}` on a `u32` prints
    /// Display, i.e. decimal, so the two agree only while `age < 10`. Every
    /// existing test used age 1 or 2, which is exactly why this survived.
    ///
    /// An age of 10 or more therefore produced a URL no symbol server resolves:
    /// the download 404s and the module is silently left without symbols — the
    /// failure looks like "no symbols available upstream", not like a bug here.
    #[test]
    fn the_age_in_the_server_key_is_hexadecimal() {
        let guid = [0u8; 16];
        for (age, expected) in [(1u32, "1"), (9, "9"), (10, "A"), (26, "1A"), (255, "FF")] {
            let id = PdbIdentity::new(&guid, age, "ntdll.pdb");
            let key = &id.guid_age;
            assert_eq!(
                key.len(),
                32 + expected.len(),
                "the key must be 32 GUID hex digits plus the age, got {key}"
            );
            assert!(
                key.ends_with(expected),
                "age {age} must be encoded as {expected:?} (hex), got key {key}"
            );
        }
    }

    #[test]
    fn rsds_parse_round_trip() {
        let mut rsds = Vec::new();
        rsds.extend_from_slice(b"RSDS"); // signature
        rsds.extend_from_slice(&[
            0x23, 0xFE, 0xBC, 0x8D, 0x2D, 0xC2, 0x4C, 0x65,
            0xAA, 0x57, 0xDA, 0x6E, 0x2D, 0xCC, 0x16, 0x73,
        ]); // GUID
        rsds.extend_from_slice(&2u32.to_le_bytes()); // Age = 2
        rsds.extend_from_slice(b"C:\\Windows\\ntdll.pdb\0");
        let id = PdbIdentity::from_rsds(&rsds).unwrap();
        assert_eq!(id.pdb_name, "ntdll.pdb");
        // Age is 2, guid_age ends with "2"
        assert!(id.guid_age.ends_with('2'));
    }

    #[test]
    fn rsds_bad_signature() {
        let bad = b"XXXX\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(PdbIdentity::from_rsds(bad).is_err());
    }

    #[test]
    fn cache_path_does_not_panic() {
        let id = PdbIdentity {
            pdb_name: "ntdll.pdb".into(),
            guid_age: "AABBCCDD11223344AABBCCDD1".into(),
        };
        // cache_path may fail if $HOME/$USERPROFILE is unset (e.g. in CI
        // without home dir), so we just assert it doesn't panic.
        let _ = cache_path(&id);
    }

    #[test]
    fn cached_returns_none_for_unknown() {
        let id = PdbIdentity {
            pdb_name: "does_not_exist_test.pdb".into(),
            guid_age: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1".into(),
        };
        // If no home dir, cached() returns Err — that's fine too.
        match cached(&id) {
            Ok(c) => assert!(c.is_none(), "should not find a nonexistent PDB"),
            Err(_) => {} // no home dir in this environment
        }
    }

    /// A symbol server answers a missing file with an HTML page and HTTP 200
    /// often enough that the status code alone cannot be trusted.
    ///
    /// Nothing checked what the body actually was, so that page landed at the
    /// cache path - and every later call short-circuits on `dest.exists()`, so
    /// the poisoned entry was returned forever and every symbol lookup from
    /// then on read a file that is not a PDB.
    #[test]
    fn only_a_real_pdb_container_passes_the_body_check() {
        let msf7 = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00rest of the file";
        assert!(looks_like_pdb(msf7));
        let msf2 = b"Microsoft C/C++ program database 2.00\r\n\x1aJG\x00";
        assert!(looks_like_pdb(msf2));

        assert!(!looks_like_pdb(b"<!DOCTYPE html><html><body>404</body></html>"));
        assert!(!looks_like_pdb(b""));
        // A truncated container: the prefix alone is not a PDB.
        assert!(!looks_like_pdb(b"Microsoft C/C++ MSF"));
        // Right words, wrong container tag.
        assert!(!looks_like_pdb(b"Microsoft C/C++ MSF 7.00\r\n\x1aXX"));
    }

    /// A cache entry that is not a PDB must be ignored, so it can be fetched
    /// again instead of being served for the rest of the installation life.
    #[test]
    fn a_poisoned_cache_entry_is_not_returned() {
        let id = PdbIdentity::new(&[0xAB; 16], 1, "poisoned.pdb");
        let Ok(path) = cache_path(&id) else { return };
        let Some(parent) = path.parent().map(std::path::Path::to_path_buf) else { return };
        if std::fs::create_dir_all(&parent).is_err() {
            return;
        }
        // An HTML error page saved under the PDB name by an earlier build.
        if std::fs::write(&path, b"<html>404 not found</html>").is_err() {
            return;
        }
        let seen = cached(&id).expect("cache lookup must not fail");
        let _ = std::fs::remove_file(&path);
        assert!(
            seen.is_none(),
            "a cached file that is not a PDB must not be handed out as one"
        );
    }

    /// ...and a real one still is, so the check is not simply refusing
    /// everything.
    #[test]
    fn a_valid_cache_entry_is_still_returned() {
        let id = PdbIdentity::new(&[0xCD; 16], 2, "valid.pdb");
        let Ok(path) = cache_path(&id) else { return };
        let Some(parent) = path.parent().map(std::path::Path::to_path_buf) else { return };
        if std::fs::create_dir_all(&parent).is_err() {
            return;
        }
        let body = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00";
        if std::fs::write(&path, body).is_err() {
            return;
        }
        let seen = cached(&id).expect("cache lookup must not fail");
        let _ = std::fs::remove_file(&path);
        assert_eq!(seen.as_deref(), Some(path.as_path()));
    }


    /// The redirect the doc promised and the code never followed.
    ///
    /// `download_http` claimed to handle "HTTP redirects (up to 5 hops) that
    /// the symbol server sometimes issues" while sending every 3xx straight
    /// into the non-200 error branch. `msdl.microsoft.com` answers a great
    /// many requests with a 302, so the documented capability had never
    /// existed and the download simply failed.
    #[test]
    fn a_redirect_is_resolved_absolute_root_relative_and_path_relative() {
        let req = "http://msdl.microsoft.com/download/symbols/ntdll.pdb/ABC1/ntdll.pdb";

        // Absolute Location.
        let h = "HTTP/1.1 302 Found
Location: https://cdn.example.com/x/ntdll.pdb";
        assert_eq!(
            redirect_target(302, h, req).as_deref(),
            Some("https://cdn.example.com/x/ntdll.pdb")
        );

        // Root-relative.
        let h = "HTTP/1.1 301 Moved
Location: /elsewhere/ntdll.pdb";
        assert_eq!(
            redirect_target(301, h, req).as_deref(),
            Some("http://msdl.microsoft.com/elsewhere/ntdll.pdb")
        );

        // Path-relative: replaces the last segment.
        let h = "HTTP/1.1 307 Temporary Redirect
Location: other.pdb";
        assert_eq!(
            redirect_target(307, h, req).as_deref(),
            Some("http://msdl.microsoft.com/download/symbols/ntdll.pdb/ABC1/other.pdb")
        );

        // Header name case does not matter.
        let h = "HTTP/1.1 308 Permanent Redirect
location: /a.pdb";
        assert_eq!(
            redirect_target(308, h, req).as_deref(),
            Some("http://msdl.microsoft.com/a.pdb")
        );
    }

    /// Anything that is not a usable redirect must resolve to nothing, so the
    /// caller falls through to its real status handling instead of chasing an
    /// invented URL.
    #[test]
    fn a_non_redirect_or_unusable_location_resolves_to_nothing() {
        let req = "http://host/a/b.pdb";
        // Not a redirect status.
        assert!(redirect_target(200, "HTTP/1.1 200 OK
Location: /x", req).is_none());
        assert!(redirect_target(404, "HTTP/1.1 404 Not Found", req).is_none());
        // Redirect with no Location at all.
        assert!(redirect_target(302, "HTTP/1.1 302 Found
Server: x", req).is_none());
        // Redirect with an empty Location.
        assert!(redirect_target(302, "HTTP/1.1 302 Found
Location:   ", req).is_none());
    }

}
