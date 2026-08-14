//! Dynamic library loader for the `RustRE` plugin host.
//!
//! Provides platform-aware stubs for `dlopen`/`LoadLibrary`-style loading.
//! On real hardware these would call OS APIs; here the types and contracts
//! are fully defined so that plugin code can be written against them.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the dynamic loader.
#[derive(Debug, thiserror::Error)]
pub enum DynLoadError {
    #[error("library not found: {0}")]
    NotFound(PathBuf),
    #[error("failed to load: {0}: {1}")]
    LoadFailed(PathBuf, String),
    #[error("symbol not found: {0}")]
    SymbolNotFound(String),
    #[error("invalid plugin magic: expected 0x{expected:08x}, got 0x{got:08x}")]
    InvalidMagic { expected: u32, got: u32 },
    #[error("ABI version mismatch: host={host}, plugin={plugin}")]
    AbiMismatch { host: u32, plugin: u32 },
    #[error("invalid plugin manifest: {0}")]
    InvalidManifest(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

// ─────────────────────────────────────────────────────────────────────────────
// Platform detection
// ─────────────────────────────────────────────────────────────────────────────

/// Platform the host is running on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    Linux,
    Windows,
    MacOs,
    Unknown,
}

impl Default for Platform {
    fn default() -> Self {
        Self::current()
    }
}

impl Platform {
    /// Detect the current compilation target.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Unknown
        }
    }

    /// Default shared library extension for this platform.
    #[must_use]
    pub const fn lib_extension(self) -> &'static str {
        match self {
            Self::Linux => "so",
            Self::Windows => "dll",
            Self::MacOs => "dylib",
            Self::Unknown => "so",
        }
    }

    /// Plugin search directories for this platform.
    #[must_use]
    pub fn search_paths(self) -> Vec<PathBuf> {
        match self {
            Self::Windows => {
                let mut paths = vec![PathBuf::from("C:\\ProgramData\\RustRE\\plugins")];
                if let Ok(appdata) = std::env::var("APPDATA") {
                    paths.push(PathBuf::from(appdata).join("RustRE").join("plugins"));
                }
                paths
            }
            _ => vec![
                PathBuf::from("/usr/lib/rustre/plugins"),
                PathBuf::from("/usr/local/lib/rustre/plugins"),
                dirs_home()
                    .map(|h| h.join(".rustre").join("plugins"))
                    .unwrap_or_default(),
            ],
        }
    }
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| std::env::var("USERPROFILE").ok().map(PathBuf::from))
}

// ─────────────────────────────────────────────────────────────────────────────
// PLUGIN_MAGIC + ABI descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// The expected magic number at the start of every `RustRE` plugin descriptor.
pub const PLUGIN_MAGIC: u32 = 0x52_53_54_52; // "RSTR"

/// Version of the plugin ABI that the host currently supports.
pub const HOST_ABI_VERSION: u32 = 1;

/// Plugin manifest written into the shared library.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginAbiDescriptor {
    /// Must equal [`PLUGIN_MAGIC`].
    pub magic: u32,
    /// Plugin ABI version.
    pub abi_version: u32,
    /// Plugin name (null-terminated in real code, here a String).
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// Minimum host version required.
    pub min_host_version: u32,
}

impl PluginAbiDescriptor {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            magic: PLUGIN_MAGIC,
            abi_version: HOST_ABI_VERSION,
            name: name.into(),
            version: version.into(),
            min_host_version: HOST_ABI_VERSION,
        }
    }

    /// Validate.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    ///
    pub const fn validate(&self) -> Result<(), DynLoadError> {
        if self.magic != PLUGIN_MAGIC {
            return Err(DynLoadError::InvalidMagic {
                expected: PLUGIN_MAGIC,
                got: self.magic,
            });
        }
        if self.abi_version != HOST_ABI_VERSION {
            return Err(DynLoadError::AbiMismatch {
                host: HOST_ABI_VERSION,
                plugin: self.abi_version,
            });
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A function pointer loaded from a shared library.
///
/// In production code this would be a raw `*const ()` obtained via
/// `dlsym`/`GetProcAddress`. Here it wraps a boxed function for testability.
pub struct PluginEntry {
    pub symbol_name: String,
    pub addr: usize,
}

impl fmt::Debug for PluginEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PluginEntry {{ symbol: {:?}, addr: 0x{:x} }}",
            self.symbol_name, self.addr
        )
    }
}

impl PluginEntry {
    pub fn new(symbol: impl Into<String>, addr: usize) -> Self {
        Self {
            symbol_name: symbol.into(),
            addr,
        }
    }

    /// Whether the entry point address is non-null.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.addr != 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DylibHandle
// ─────────────────────────────────────────────────────────────────────────────

/// A handle to a loaded shared library.
///
/// The actual OS handle (`void*` / `HMODULE`) is represented as a `usize`
/// to avoid `unsafe` imports in this stub.
#[derive(Debug)]
pub struct DylibHandle {
    pub path: PathBuf,
    handle: usize,
    symbols: HashMap<String, usize>,
}

impl DylibHandle {
    #[must_use]
    pub fn new(path: PathBuf, handle: usize) -> Self {
        Self {
            path,
            handle,
            symbols: HashMap::new(),
        }
    }

    /// Register a symbol address (used in testing stubs).
    pub fn register_symbol(&mut self, name: impl Into<String>, addr: usize) {
        self.symbols.insert(name.into(), addr);
    }

    /// Get symbol.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Look up a symbol by name.
    pub fn get_symbol(&self, name: &str) -> Result<PluginEntry, DynLoadError> {
        self.symbols
            .get(name)
            .map(|&addr| PluginEntry::new(name, addr))
            .ok_or_else(|| DynLoadError::SymbolNotFound(name.to_string()))
    }

    /// Raw handle value (for FFI).
    #[must_use]
    pub const fn raw(&self) -> usize {
        self.handle
    }

    /// Platform path of the loaded library.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SharedLibrary
// ─────────────────────────────────────────────────────────────────────────────

/// High-level shared library wrapper: load / unload / `get_symbol`.
pub struct SharedLibrary {
    pub handle: DylibHandle,
    pub descriptor: Option<PluginAbiDescriptor>,
    pub is_loaded: bool,
}

impl fmt::Debug for SharedLibrary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedLibrary")
            .field("path", &self.handle.path)
            .field("is_loaded", &self.is_loaded)
            .finish_non_exhaustive()
    }
}

impl SharedLibrary {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            handle: DylibHandle::new(path, 0),
            descriptor: None,
            is_loaded: false,
        }
    }

    /// Load.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Simulate loading the library (real impl would call dlopen).
    pub fn load(&mut self) -> Result<(), DynLoadError> {
        if !self.handle.path.exists() {
            return Err(DynLoadError::NotFound(self.handle.path.clone()));
        }
        self.is_loaded = true;
        self.handle.handle = 0xcafe_babe; // stub handle
        Ok(())
    }

    /// Unload the library.
    pub const fn unload(&mut self) {
        self.is_loaded = false;
        self.handle.handle = 0;
    }

    /// Get symbol.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Get a symbol by name.
    pub fn get_symbol(&self, name: &str) -> Result<PluginEntry, DynLoadError> {
        if !self.is_loaded {
            return Err(DynLoadError::LoadFailed(
                self.handle.path.clone(),
                "library not loaded".into(),
            ));
        }
        self.handle.get_symbol(name)
    }

    /// Has symbol.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Check if a symbol exists.
    #[must_use]
    pub fn has_symbol(&self, name: &str) -> bool {
        self.handle.get_symbol(name).is_ok()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginManifestReader
// ─────────────────────────────────────────────────────────────────────────────

/// Reads and validates the [`PluginAbiDescriptor`] from a (real or stub) library.
pub struct PluginManifestReader;

impl PluginManifestReader {
    /// Read from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Try to read the plugin manifest from a raw bytes slice.
    ///
    /// In production this would call `get_symbol("RUSTRE_PLUGIN_DESCRIPTOR")`.
    pub fn read_from_bytes(data: &[u8]) -> Result<PluginAbiDescriptor, DynLoadError> {
        // Check for PLUGIN_MAGIC at byte offset 0 (little-endian u32).
        if data.len() < 8 {
            return Err(DynLoadError::InvalidMagic {
                expected: PLUGIN_MAGIC,
                got: 0,
            });
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != PLUGIN_MAGIC {
            return Err(DynLoadError::InvalidMagic {
                expected: PLUGIN_MAGIC,
                got: magic,
            });
        }
        let abi_version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if abi_version != HOST_ABI_VERSION {
            return Err(DynLoadError::AbiMismatch {
                host: HOST_ABI_VERSION,
                plugin: abi_version,
            });
        }
        // Rest is JSON-encoded for testability.
        let json_part = std::str::from_utf8(&data[8..])
            .map_err(|e| DynLoadError::InvalidManifest(e.to_string()))?;
        let partial: HashMap<String, String> = serde_json::from_str(json_part)
            .map_err(|e| DynLoadError::InvalidManifest(e.to_string()))?;
        Ok(PluginAbiDescriptor {
            magic,
            abi_version,
            name: partial.get("name").cloned().unwrap_or_default(),
            version: partial.get("version").cloned().unwrap_or_default(),
            min_host_version: HOST_ABI_VERSION,
        })
    }

    /// Read from lib.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Read from a [`SharedLibrary`] by looking up the well-known symbol.
    pub fn read_from_lib(
        lib: &SharedLibrary,
        descriptor_sym: &str,
    ) -> Result<PluginAbiDescriptor, DynLoadError> {
        let _entry = lib.get_symbol(descriptor_sym)?;
        // In a real impl, dereference the pointer. Here we return a stub descriptor.
        Ok(PluginAbiDescriptor::new("unknown_plugin", "0.0.0"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DylibLoader
// ─────────────────────────────────────────────────────────────────────────────

/// Central loader that manages multiple shared libraries.
#[derive(Default)]
pub struct DylibLoader {
    pub platform: Platform,
    loaded: HashMap<PathBuf, SharedLibrary>,
    handle_counter: usize,
}

impl DylibLoader {
    #[must_use]
    pub fn new() -> Self {
        Self {
            platform: Platform::current(),
            loaded: HashMap::new(),
            handle_counter: 1,
        }
    }

    /// Load.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    /// Load a shared library. Returns a reference to the loaded library.
    pub fn load(&mut self, path: &Path) -> Result<&SharedLibrary, DynLoadError> {
        if !path.exists() {
            return Err(DynLoadError::NotFound(path.to_path_buf()));
        }
        let pb = path.to_path_buf();
        if !self.loaded.contains_key(&pb) {
            let handle = self.handle_counter;
            self.handle_counter += 1;
            let mut lib = SharedLibrary::new(pb.clone());
            lib.handle.handle = handle;
            lib.is_loaded = true;
            self.loaded.insert(pb, lib);
        }
        Ok(self.loaded.get(path).unwrap())
    }

    /// Unload a library.
    pub fn unload(&mut self, path: &Path) {
        if let Some(lib) = self.loaded.get_mut(path) {
            lib.unload();
        }
        self.loaded.remove(path);
    }

    /// Check whether a path is currently loaded.
    #[must_use]
    pub fn is_loaded(&self, path: &Path) -> bool {
        self.loaded.get(path).is_some_and(|l| l.is_loaded)
    }

    /// Number of loaded libraries.
    #[must_use]
    pub fn loaded_count(&self) -> usize {
        self.loaded.len()
    }

    /// All loaded library paths.
    #[must_use]
    pub fn loaded_paths(&self) -> Vec<&Path> {
        self.loaded
            .keys()
            .map(std::path::PathBuf::as_path)
            .collect()
    }

    /// Find a plugin on the search path given just its name.
    #[must_use]
    pub fn find_plugin(&self, name: &str) -> Option<PathBuf> {
        let ext = self.platform.lib_extension();
        for dir in self.platform.search_paths() {
            let candidate = dir.join(format!("{name}.{ext}"));
            if candidate.exists() {
                return Some(candidate);
            }
        }
        None
    }
}

impl fmt::Debug for DylibLoader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DylibLoader")
            .field("platform", &self.platform)
            .field("loaded_count", &self.loaded.len())
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_lib(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(name);
        fs::write(&p, b"placeholder").unwrap();
        p
    }

    // --- Platform ---

    #[test]
    fn platform_current_is_valid() {
        let p = Platform::current();
        assert!(matches!(
            p,
            Platform::Linux | Platform::Windows | Platform::MacOs | Platform::Unknown
        ));
    }

    #[test]
    fn platform_lib_extension_windows() {
        assert_eq!(Platform::Windows.lib_extension(), "dll");
    }

    #[test]
    fn platform_lib_extension_linux() {
        assert_eq!(Platform::Linux.lib_extension(), "so");
    }

    #[test]
    fn platform_search_paths_not_empty() {
        assert!(!Platform::current().search_paths().is_empty());
    }

    // --- PluginAbiDescriptor ---

    #[test]
    fn abi_descriptor_validate_ok() {
        let d = PluginAbiDescriptor::new("test", "1.0.0");
        assert!(d.validate().is_ok());
    }

    #[test]
    fn abi_descriptor_wrong_magic() {
        let d = PluginAbiDescriptor {
            magic: 0xdeadbeef,
            ..PluginAbiDescriptor::new("x", "1")
        };
        assert!(d.validate().is_err());
    }

    #[test]
    fn abi_descriptor_wrong_abi_version() {
        let d = PluginAbiDescriptor {
            abi_version: 99,
            ..PluginAbiDescriptor::new("x", "1")
        };
        assert!(d.validate().is_err());
    }

    // --- PluginEntry ---

    #[test]
    fn plugin_entry_valid() {
        let e = PluginEntry::new("rustre_plugin_init", 0x1234);
        assert!(e.is_valid());
    }

    #[test]
    fn plugin_entry_null_invalid() {
        let e = PluginEntry::new("rustre_plugin_init", 0);
        assert!(!e.is_valid());
    }

    // --- DylibHandle ---

    #[test]
    fn dylib_handle_symbol_found() {
        let mut h = DylibHandle::new(PathBuf::from("foo.so"), 1);
        h.register_symbol("init", 0x1000);
        assert!(h.get_symbol("init").is_ok());
    }

    #[test]
    fn dylib_handle_symbol_not_found() {
        let h = DylibHandle::new(PathBuf::from("foo.so"), 1);
        assert!(h.get_symbol("missing").is_err());
    }

    // --- SharedLibrary ---

    #[test]
    fn shared_library_load_missing_file() {
        let mut lib = SharedLibrary::new(PathBuf::from("/no/such/file.so"));
        assert!(lib.load().is_err());
    }

    #[test]
    fn shared_library_load_existing_file() {
        let path = temp_lib("test_rustre_plugin_host_dynlib.so");
        let mut lib = SharedLibrary::new(path.clone());
        let result = lib.load();
        fs::remove_file(&path).ok();
        assert!(result.is_ok());
        assert!(lib.is_loaded);
    }

    #[test]
    fn shared_library_unload() {
        let path = temp_lib("test_rustre_plugin_host_unload.so");
        let mut lib = SharedLibrary::new(path.clone());
        lib.load().ok();
        lib.unload();
        fs::remove_file(&path).ok();
        assert!(!lib.is_loaded);
    }

    #[test]
    fn shared_library_get_symbol_not_loaded() {
        let lib = SharedLibrary::new(PathBuf::from("foo.so"));
        assert!(lib.get_symbol("init").is_err());
    }

    // --- PluginManifestReader ---

    #[test]
    fn manifest_reader_valid_magic() {
        let mut data = PLUGIN_MAGIC.to_le_bytes().to_vec();
        data.extend_from_slice(&HOST_ABI_VERSION.to_le_bytes());
        let json = r#"{"name":"myplugin","version":"1.2.3"}"#;
        data.extend_from_slice(json.as_bytes());
        let desc = PluginManifestReader::read_from_bytes(&data).unwrap();
        assert_eq!(desc.name, "myplugin");
        assert_eq!(desc.version, "1.2.3");
    }

    #[test]
    fn manifest_reader_wrong_magic() {
        let mut data = 0xdeadbeefu32.to_le_bytes().to_vec();
        data.extend_from_slice(&HOST_ABI_VERSION.to_le_bytes());
        assert!(PluginManifestReader::read_from_bytes(&data).is_err());
    }

    #[test]
    fn manifest_reader_too_short() {
        let data = [0u8; 3];
        assert!(PluginManifestReader::read_from_bytes(&data).is_err());
    }

    // --- DylibLoader ---

    #[test]
    fn dylib_loader_load_missing() {
        let mut loader = DylibLoader::new();
        assert!(loader.load(Path::new("/no/such.so")).is_err());
    }

    #[test]
    fn dylib_loader_load_existing() {
        let path = temp_lib("test_rustre_dynloader_load.so");
        let mut loader = DylibLoader::new();
        let result = loader.load(&path);
        fs::remove_file(&path).ok();
        assert!(result.is_ok());
    }

    #[test]
    fn dylib_loader_loaded_count() {
        let p1 = temp_lib("test_rustre_dynloader_count1.so");
        let p2 = temp_lib("test_rustre_dynloader_count2.so");
        let mut loader = DylibLoader::new();
        loader.load(&p1).ok();
        loader.load(&p2).ok();
        let count = loader.loaded_count();
        fs::remove_file(&p1).ok();
        fs::remove_file(&p2).ok();
        assert_eq!(count, 2);
    }

    #[test]
    fn dylib_loader_is_loaded() {
        let path = temp_lib("test_rustre_dynloader_is_loaded.so");
        let mut loader = DylibLoader::new();
        assert!(!loader.is_loaded(&path));
        loader.load(&path).ok();
        assert!(loader.is_loaded(&path));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn dylib_loader_unload() {
        let path = temp_lib("test_rustre_dynloader_unload.so");
        let mut loader = DylibLoader::new();
        loader.load(&path).ok();
        loader.unload(&path);
        fs::remove_file(&path).ok();
        assert!(!loader.is_loaded(&path));
    }
}
