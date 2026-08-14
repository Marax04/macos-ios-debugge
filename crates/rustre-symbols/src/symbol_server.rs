//! Microsoft symbol-server PDB download with a transparent local cache.
//!
//! Implements the `symsrv` URL scheme used by msdl.microsoft.com:
//!
//! ```text
//! <server>/<pdbname>/<GUID32-uppercase-hex><AGE-uppercase-hex>/<pdbname>
//! ```
//!
//! The local cache mirrors the same layout under a cache root
//! (`<cache>/<pdbname>/<KEY>/<pdbname>`), so a hit never touches the network.
//! Network access is fully injectable through the [`SymbolFetcher`] trait —
//! tests run offline with [`MockFetcher`]; production can use
//! [`HttpCommandFetcher`] (shells out to `curl`, no extra crate deps).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

use rustre_loader_pe::PeInfo;

/// Default Microsoft public symbol server.
pub const MSDL_SERVER: &str = "https://msdl.microsoft.com/download/symbols";

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors raised while constructing symbol-server URLs or fetching PDBs.
#[derive(Debug, Error)]
pub enum SymSrvError {
    /// The provided GUID string was malformed.
    #[error("invalid GUID: {0}")]
    InvalidGuid(String),
    /// The provided PDB file name was invalid.
    #[error("invalid PDB name: {0}")]
    InvalidPdbName(String),
    /// A network fetch for the given URL failed.
    #[error("fetch failed for {url}: {msg}")]
    FetchFailed {
        /// The URL that was being fetched.
        url: String,
        /// Human-readable failure reason.
        msg: String,
    },
    /// The requested symbol file was not present on the server.
    #[error("not found on server: {0}")]
    NotFound(String),
    /// The binary contained no `CodeView` PDB reference to key the lookup on.
    #[error("binary has no CodeView PDB record")]
    NoCodeView,
    /// An I/O error occurred (e.g. writing to the local cache).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience result alias for symbol-server operations.
pub type SymSrvResult<T> = std::result::Result<T, SymSrvError>;

// ── Key / URL construction ────────────────────────────────────────────────────

/// Normalize a GUID string (dashed, braced or bare hex) into the 32-char
/// uppercase-hex form used by the symbol server, then append the age in
/// uppercase hex (no padding).
///
/// # Errors
///
/// Returns [`SymSrvError::InvalidGuid`] if the string does not contain exactly
/// 32 hex digits after stripping `-`, `{`, `}` and whitespace.
pub fn symbol_server_key(guid: &str, age: u32) -> SymSrvResult<String> {
    let hex: String = guid
        .chars()
        .filter(|c| !matches!(c, '-' | '{' | '}') && !c.is_whitespace())
        .collect();
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SymSrvError::InvalidGuid(guid.to_string()));
    }
    Ok(format!("{}{:X}", hex.to_ascii_uppercase(), age))
}

/// Validate a PDB file name (no path separators, non-empty, `.pdb`-ish).
fn validate_pdb_name(name: &str) -> SymSrvResult<()> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || name.contains(':')
    {
        return Err(SymSrvError::InvalidPdbName(name.to_string()));
    }
    Ok(())
}

/// Build the full download URL for a PDB on `server`.
///
/// # Errors
///
/// Returns an error for an invalid GUID or PDB name.
pub fn pdb_url(server: &str, pdb_name: &str, guid: &str, age: u32) -> SymSrvResult<String> {
    validate_pdb_name(pdb_name)?;
    let key = symbol_server_key(guid, age)?;
    Ok(format!(
        "{}/{pdb_name}/{key}/{pdb_name}",
        server.trim_end_matches('/')
    ))
}

/// Build the msdl.microsoft.com download URL for a PDB.
///
/// # Errors
///
/// Returns an error for an invalid GUID or PDB name.
pub fn msdl_url(pdb_name: &str, guid: &str, age: u32) -> SymSrvResult<String> {
    pdb_url(MSDL_SERVER, pdb_name, guid, age)
}

// ── Fetcher abstraction ───────────────────────────────────────────────────────

/// Injectable network layer. Implementations fetch a URL and return the body.
pub trait SymbolFetcher: Send + Sync {
    /// Fetch `url`, returning the raw response body.
    ///
    /// # Errors
    ///
    /// [`SymSrvError::NotFound`] for a 404, [`SymSrvError::FetchFailed`] for
    /// any other failure.
    fn fetch_url(&self, url: &str) -> SymSrvResult<Vec<u8>>;
}

/// Offline mock fetcher backed by a URL → bytes map. Used in tests.
#[derive(Debug, Default)]
pub struct MockFetcher {
    responses: HashMap<String, Vec<u8>>,
    /// Number of fetch calls made (interior-mutability-free: use `fetch_count()`).
    calls: std::sync::atomic::AtomicUsize,
}

impl MockFetcher {
    /// Create an empty mock fetcher.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Register a canned response `body` for requests to `url`.
    pub fn insert(&mut self, url: impl Into<String>, body: impl Into<Vec<u8>>) {
        self.responses.insert(url.into(), body.into());
    }
    /// Number of fetch calls made so far.
    #[must_use]
    pub fn fetch_count(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl SymbolFetcher for MockFetcher {
    fn fetch_url(&self, url: &str) -> SymSrvResult<Vec<u8>> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.responses
            .get(url)
            .cloned()
            .ok_or_else(|| SymSrvError::NotFound(url.to_string()))
    }
}

/// Real network fetcher that shells out to `curl` (present on Windows 10+
/// and virtually all Unix systems). Keeps the crate free of HTTP deps.
#[derive(Debug, Default)]
pub struct HttpCommandFetcher;

impl SymbolFetcher for HttpCommandFetcher {
    fn fetch_url(&self, url: &str) -> SymSrvResult<Vec<u8>> {
        let out = std::process::Command::new("curl")
            .args(["-sSL", "--fail", "--max-time", "120", url])
            .output()
            .map_err(|e| SymSrvError::FetchFailed {
                url: url.to_string(),
                msg: format!("failed to spawn curl: {e}"),
            })?;
        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
            if msg.contains("404") {
                return Err(SymSrvError::NotFound(url.to_string()));
            }
            return Err(SymSrvError::FetchFailed {
                url: url.to_string(),
                msg,
            });
        }
        Ok(out.stdout)
    }
}

// ── SymbolServerClient ────────────────────────────────────────────────────────

/// Downloads PDBs from a symbol server with a transparent local cache.
pub struct SymbolServerClient {
    server_url: String,
    cache_dir: PathBuf,
    fetcher: Box<dyn SymbolFetcher>,
}

impl std::fmt::Debug for SymbolServerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymbolServerClient")
            .field("server_url", &self.server_url)
            .field("cache_dir", &self.cache_dir)
            .finish_non_exhaustive()
    }
}

impl SymbolServerClient {
    /// Create a client for the Microsoft public symbol server using the real
    /// network fetcher.
    pub fn msdl(cache_dir: impl Into<PathBuf>) -> Self {
        Self::new(MSDL_SERVER, cache_dir, Box::new(HttpCommandFetcher))
    }

    /// Fully injectable constructor (server URL, cache dir, fetcher).
    pub fn new(
        server_url: impl Into<String>,
        cache_dir: impl Into<PathBuf>,
        fetcher: Box<dyn SymbolFetcher>,
    ) -> Self {
        Self {
            server_url: server_url.into(),
            cache_dir: cache_dir.into(),
            fetcher,
        }
    }

    /// The local directory downloaded symbol files are cached in.
    #[must_use]
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Path a given PDB would occupy in the local cache.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid GUID or PDB name.
    pub fn cache_path(&self, pdb_name: &str, guid: &str, age: u32) -> SymSrvResult<PathBuf> {
        validate_pdb_name(pdb_name)?;
        let key = symbol_server_key(guid, age)?;
        Ok(self.cache_dir.join(pdb_name).join(key).join(pdb_name))
    }

    /// Return `true` if the PDB is already cached locally.
    #[must_use]
    pub fn is_cached(&self, pdb_name: &str, guid: &str, age: u32) -> bool {
        self.cache_path(pdb_name, guid, age)
            .map(|p| p.is_file())
            .unwrap_or(false)
    }

    /// Fetch a PDB: cache-first, then the symbol server. Returns the local
    /// path of the (now-cached) PDB file.
    ///
    /// # Errors
    ///
    /// GUID/name validation errors, fetch errors, or I/O errors writing the cache.
    pub fn fetch_pdb(&self, pdb_name: &str, guid: &str, age: u32) -> SymSrvResult<PathBuf> {
        let local = self.cache_path(pdb_name, guid, age)?;
        if local.is_file() {
            return Ok(local);
        }
        let url = pdb_url(&self.server_url, pdb_name, guid, age)?;
        let body = self.fetcher.fetch_url(&url)?;
        if let Some(parent) = local.parent() {
            fs::create_dir_all(parent)?;
        }
        // Write atomically: temp file then rename.
        let tmp = local.with_extension("pdb.part");
        fs::write(&tmp, &body)?;
        fs::rename(&tmp, &local)?;
        Ok(local)
    }

    /// Convenience: fetch the PDB matching a loaded PE image using its
    /// embedded `CodeView` RSDS record (GUID + age + PDB path).
    ///
    /// # Errors
    ///
    /// [`SymSrvError::NoCodeView`] if the PE lacks a `CodeView` record, plus any
    /// fetch/validation error.
    pub fn fetch_pdb_for_pe(&self, pe: &PeInfo) -> SymSrvResult<PathBuf> {
        self.fetch_pdb_for_debug_info(&pe.debug_info)
    }

    /// Same as [`Self::fetch_pdb_for_pe`] but takes the debug-directory summary
    /// directly (usable without a full `PeInfo`).
    ///
    /// # Errors
    ///
    /// [`SymSrvError::NoCodeView`] if GUID/age/path are missing, plus any
    /// fetch/validation error.
    pub fn fetch_pdb_for_debug_info(
        &self,
        di: &rustre_loader_pe::DebugInfo,
    ) -> SymSrvResult<PathBuf> {
        let guid = di.pdb_guid.as_deref().ok_or(SymSrvError::NoCodeView)?;
        let age = di.pdb_age.ok_or(SymSrvError::NoCodeView)?;
        let pdb_path = di.pdb_path.as_deref().ok_or(SymSrvError::NoCodeView)?;
        // Use just the file name — the embedded path is a build-machine path.
        let name = Path::new(pdb_path.trim_end_matches(['/', '\\']))
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| SymSrvError::InvalidPdbName(pdb_path.to_string()))?;
        self.fetch_pdb(name, guid, age)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const GUID: &str = "497b72f6-390a-44fc-878e-5a2d63b6cc4b";
    const KEY: &str = "497B72F6390A44FC878E5A2D63B6CC4B1";

    #[test]
    fn key_from_dashed_guid() {
        assert_eq!(symbol_server_key(GUID, 1).unwrap(), KEY);
    }

    #[test]
    fn key_from_braced_guid() {
        let braced = format!("{{{GUID}}}");
        assert_eq!(symbol_server_key(&braced, 1).unwrap(), KEY);
    }

    #[test]
    fn key_age_hex_uppercase_unpadded() {
        let k = symbol_server_key(GUID, 0x1a).unwrap();
        assert!(k.ends_with("1A"));
        assert_eq!(k.len(), 34);
    }

    #[test]
    fn key_invalid_guid_rejected() {
        assert!(symbol_server_key("nothex", 1).is_err());
        assert!(symbol_server_key("497b72f6", 1).is_err());
    }

    #[test]
    fn msdl_url_scheme() {
        let url = msdl_url("ntdll.pdb", GUID, 1).unwrap();
        assert_eq!(
            url,
            format!("https://msdl.microsoft.com/download/symbols/ntdll.pdb/{KEY}/ntdll.pdb")
        );
    }

    #[test]
    fn pdb_name_traversal_rejected() {
        assert!(pdb_url(MSDL_SERVER, "../evil.pdb", GUID, 1).is_err());
        assert!(pdb_url(MSDL_SERVER, "a/b.pdb", GUID, 1).is_err());
        assert!(pdb_url(MSDL_SERVER, "", GUID, 1).is_err());
    }

    fn mock_client(dir: &Path, body: &[u8]) -> SymbolServerClient {
        let mut mock = MockFetcher::new();
        mock.insert(msdl_url("foo.pdb", GUID, 2).unwrap(), body.to_vec());
        SymbolServerClient::new(MSDL_SERVER, dir, Box::new(mock))
    }

    #[test]
    fn fetch_downloads_and_caches() {
        let dir = tempfile::tempdir().unwrap();
        let client = mock_client(dir.path(), b"PDBDATA");
        assert!(!client.is_cached("foo.pdb", GUID, 2));
        let path = client.fetch_pdb("foo.pdb", GUID, 2).unwrap();
        assert!(path.is_file());
        assert_eq!(fs::read(&path).unwrap(), b"PDBDATA");
        // Cache layout: <cache>/foo.pdb/<KEY>/foo.pdb
        let expected_key = symbol_server_key(GUID, 2).unwrap();
        assert!(path.ends_with(Path::new("foo.pdb").join(&expected_key).join("foo.pdb")));
        assert!(client.is_cached("foo.pdb", GUID, 2));
    }

    #[test]
    fn fetch_cache_hit_skips_network() {
        let dir = tempfile::tempdir().unwrap();
        // Pre-seed cache, then use a fetcher with NO responses: any network
        // call would error.
        let key = symbol_server_key(GUID, 2).unwrap();
        let cached = dir.path().join("foo.pdb").join(&key).join("foo.pdb");
        fs::create_dir_all(cached.parent().unwrap()).unwrap();
        fs::write(&cached, b"CACHED").unwrap();
        let client =
            SymbolServerClient::new(MSDL_SERVER, dir.path(), Box::new(MockFetcher::new()));
        let path = client.fetch_pdb("foo.pdb", GUID, 2).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"CACHED");
    }

    #[test]
    fn fetch_not_found_propagates() {
        let dir = tempfile::tempdir().unwrap();
        let client =
            SymbolServerClient::new(MSDL_SERVER, dir.path(), Box::new(MockFetcher::new()));
        assert!(matches!(
            client.fetch_pdb("missing.pdb", GUID, 1),
            Err(SymSrvError::NotFound(_))
        ));
    }

    #[test]
    fn fetch_pdb_for_debug_info_no_codeview() {
        let dir = tempfile::tempdir().unwrap();
        let client =
            SymbolServerClient::new(MSDL_SERVER, dir.path(), Box::new(MockFetcher::new()));
        let di = rustre_loader_pe::DebugInfo::default();
        assert!(matches!(
            client.fetch_pdb_for_debug_info(&di),
            Err(SymSrvError::NoCodeView)
        ));
    }

    #[test]
    fn fetch_pdb_for_debug_info_uses_embedded_rsds() {
        let dir = tempfile::tempdir().unwrap();
        let mut mock = MockFetcher::new();
        mock.insert(msdl_url("app.pdb", GUID, 3).unwrap(), b"BODY".to_vec());
        let client = SymbolServerClient::new(MSDL_SERVER, dir.path(), Box::new(mock));
        let mut di = rustre_loader_pe::DebugInfo::default();
        di.pdb_guid = Some(GUID.to_string());
        di.pdb_age = Some(3);
        di.pdb_path = Some(r"C:\build\out\app.pdb".to_string());
        let path = client.fetch_pdb_for_debug_info(&di).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"BODY");
        assert!(path.to_string_lossy().contains("app.pdb"));
    }
}
