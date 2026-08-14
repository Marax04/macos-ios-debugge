//! Emulated Windows API resolver.
//!
//! Provides [`ApiResolverEmu`], [`PebWalker`], [`ApiHashResolver`], and
//! [`ResolvedApi`].

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ApiResolveError {
    #[error("PEB walk failed: {0}")]
    PebWalkFailed(String),
    #[error("module not found: {0}")]
    ModuleNotFound(String),
    #[error("export not found: {0}")]
    ExportNotFound(String),
    #[error("hash collision: multiple functions match hash {0:#x}")]
    HashCollision(u32),
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("memory read error at {0:#x}")]
    MemoryReadError(u64),
}

// ─────────────────────────────────────────────────────────────────────────────
// HashAlgorithm
// ─────────────────────────────────────────────────────────────────────────────

/// Hash algorithm used to identify API functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// Metasploit ROR13 hash.
    Ror13,
    /// CRC32.
    Crc32,
    /// DJB2.
    Djb2,
    /// SDBM.
    Sdbm,
    /// FNV-1a (32-bit).
    Fnv1a32,
    /// Simple add hash.
    AddHash,
    /// XOR rotate hash.
    XorRotate,
    /// User-defined.
    Custom(u32),
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ror13 => write!(f, "ROR13"),
            Self::Crc32 => write!(f, "CRC32"),
            Self::Djb2 => write!(f, "DJB2"),
            Self::Sdbm => write!(f, "SDBM"),
            Self::Fnv1a32 => write!(f, "FNV1a32"),
            Self::AddHash => write!(f, "AddHash"),
            Self::XorRotate => write!(f, "XorRotate"),
            Self::Custom(id) => write!(f, "Custom({id:#x})"),
        }
    }
}

/// Compute a hash of an API name using the given algorithm.
#[must_use]
pub fn hash_api_name(name: &str, algo: HashAlgorithm) -> u32 {
    match algo {
        HashAlgorithm::Ror13 => ror13_hash(name),
        HashAlgorithm::Crc32 => crc32_hash(name),
        HashAlgorithm::Djb2 => djb2_hash(name),
        HashAlgorithm::Sdbm => sdbm_hash(name),
        HashAlgorithm::Fnv1a32 => fnv1a32_hash(name),
        HashAlgorithm::AddHash => add_hash(name),
        HashAlgorithm::XorRotate => xor_rotate_hash(name),
        HashAlgorithm::Custom(_) => 0,
    }
}

fn ror13_hash(name: &str) -> u32 {
    let mut h = 0u32;
    for b in name.bytes() {
        h = h.rotate_right(13).wrapping_add(u32::from(b));
    }
    h
}

fn crc32_hash(name: &str) -> u32 {
    let poly: u32 = 0xEDB88320;
    let mut crc = 0xFFFFFFFFu32;
    for b in name.bytes() {
        crc ^= u32::from(b);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFFFFFF
}

fn djb2_hash(name: &str) -> u32 {
    let mut h: u32 = 5381;
    for b in name.bytes() {
        h = h.wrapping_mul(33).wrapping_add(u32::from(b));
    }
    h
}

fn sdbm_hash(name: &str) -> u32 {
    let mut h: u32 = 0;
    for b in name.bytes() {
        h = u32::from(b)
            .wrapping_add(h.wrapping_shl(6))
            .wrapping_add(h.wrapping_shl(16))
            .wrapping_sub(h);
    }
    h
}

fn fnv1a32_hash(name: &str) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for b in name.bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x01000193);
    }
    h
}

fn add_hash(name: &str) -> u32 {
    name.bytes().map(u32::from).sum()
}

fn xor_rotate_hash(name: &str) -> u32 {
    let mut h: u32 = 0;
    for b in name.bytes() {
        h = h.rotate_left(5) ^ u32::from(b);
    }
    h
}

// ─────────────────────────────────────────────────────────────────────────────
// ModuleExport
// ─────────────────────────────────────────────────────────────────────────────

/// A known export from a Windows module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleExport {
    pub module: String,
    pub name: String,
    pub ordinal: u32,
    /// Simulated base address in the emulated process.
    pub address: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolvedApi
// ─────────────────────────────────────────────────────────────────────────────

/// A successfully resolved Windows API function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedApi {
    pub name: String,
    pub module: String,
    pub address: u64,
    pub hash: u32,
    pub algorithm: HashAlgorithm,
}

// ─────────────────────────────────────────────────────────────────────────────
// PebWalker — simulates PEB → LDR → InLoadOrderLinks walk
// ─────────────────────────────────────────────────────────────────────────────

/// Simulates a Windows PEB walk to enumerate loaded modules.
pub struct PebWalker {
    /// Simulated loaded modules: module name → base address.
    modules: HashMap<String, u64>,
    /// All exports: module name → exports.
    exports: HashMap<String, Vec<ModuleExport>>,
    /// Next free address to assign.
    next_addr: u64,
}

impl PebWalker {
    /// Create a walker with the default set of Windows modules.
    #[must_use]
    pub fn new() -> Self {
        let mut w = Self {
            modules: HashMap::new(),
            exports: HashMap::new(),
            next_addr: 0x7FF00000_00001000,
        };
        w.populate_defaults();
        w
    }

    /// Add a module with its exports.
    pub fn add_module(&mut self, name: &str, exports: &[&str]) {
        let base = self.next_addr;
        self.next_addr += 0x10000;
        self.modules.insert(name.to_lowercase(), base);
        let exps: Vec<ModuleExport> = exports
            .iter()
            .enumerate()
            .map(|(i, &n)| ModuleExport {
                module: name.to_lowercase(),
                name: n.to_owned(),
                ordinal: i as u32 + 1,
                address: base + 0x100 + i as u64 * 0x10,
            })
            .collect();
        self.exports.insert(name.to_lowercase(), exps);
    }

    /// Look up a module base address.
    #[must_use]
    pub fn module_base(&self, name: &str) -> Option<u64> {
        self.modules.get(&name.to_lowercase()).copied()
    }

    /// Enumerate all exports.
    #[must_use]
    pub fn all_exports(&self) -> Vec<&ModuleExport> {
        self.exports.values().flat_map(|v| v.iter()).collect()
    }

    /// Find an export by name.
    #[must_use]
    pub fn find_export(&self, name: &str) -> Option<&ModuleExport> {
        for exports in self.exports.values() {
            if let Some(e) = exports.iter().find(|e| e.name == name) {
                return Some(e);
            }
        }
        None
    }

    fn populate_defaults(&mut self) {
        self.add_module(
            "kernel32.dll",
            &[
                "CreateFileA",
                "CreateFileW",
                "ReadFile",
                "WriteFile",
                "CloseHandle",
                "GetModuleHandleA",
                "GetProcAddress",
                "LoadLibraryA",
                "LoadLibraryW",
                "VirtualAlloc",
                "VirtualFree",
                "VirtualProtect",
                "GetTickCount",
                "GetTickCount64",
                "CreateProcessA",
                "CreateProcessW",
                "TerminateProcess",
                "GetCurrentProcess",
                "GetCurrentProcessId",
                "GetCurrentThread",
                "CreateThread",
                "ExitThread",
                "WaitForSingleObject",
                "HeapAlloc",
                "HeapFree",
                "HeapCreate",
                "IsDebuggerPresent",
                "CheckRemoteDebuggerPresent",
                "OutputDebugStringA",
                "DebugBreak",
                "GetSystemInfo",
                "GetComputerNameA",
                "CreateMutexA",
                "OpenMutexA",
            ],
        );
        self.add_module(
            "ntdll.dll",
            &[
                "NtAllocateVirtualMemory",
                "NtFreeVirtualMemory",
                "NtProtectVirtualMemory",
                "NtWriteVirtualMemory",
                "NtReadVirtualMemory",
                "NtCreateFile",
                "NtOpenFile",
                "NtReadFile",
                "NtWriteFile",
                "NtClose",
                "NtQueryInformationProcess",
                "NtSetInformationProcess",
                "LdrLoadDll",
                "LdrGetProcedureAddress",
                "RtlAllocateHeap",
                "RtlFreeHeap",
                "NtCreateThread",
                "NtTerminateProcess",
                "DbgBreakPoint",
                "DbgPrint",
            ],
        );
        self.add_module(
            "ws2_32.dll",
            &[
                "socket",
                "bind",
                "listen",
                "accept",
                "connect",
                "send",
                "recv",
                "closesocket",
                "WSAStartup",
                "WSACleanup",
                "WSASocket",
                "WSAConnect",
                "WSARecv",
                "WSASend",
                "getaddrinfo",
                "gethostbyname",
                "htons",
                "htonl",
                "inet_addr",
            ],
        );
        self.add_module(
            "user32.dll",
            &[
                "MessageBoxA",
                "MessageBoxW",
                "GetDesktopWindow",
                "FindWindowA",
                "CreateWindowExA",
            ],
        );
        self.add_module(
            "advapi32.dll",
            &[
                "RegOpenKeyExA",
                "RegQueryValueExA",
                "RegSetValueExA",
                "RegCloseKey",
                "OpenSCManagerA",
                "CreateServiceA",
                "StartServiceA",
                "CryptAcquireContextA",
                "CryptGenKey",
                "CryptEncrypt",
                "CryptDecrypt",
                "LookupPrivilegeValueA",
                "AdjustTokenPrivileges",
            ],
        );
        self.add_module(
            "wininet.dll",
            &[
                "InternetOpenA",
                "InternetConnectA",
                "HttpOpenRequestA",
                "HttpSendRequestA",
                "InternetReadFile",
                "InternetCloseHandle",
            ],
        );
        self.add_module("urlmon.dll", &["URLDownloadToFileA", "URLDownloadToFileW"]);
    }
}

impl Default for PebWalker {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ApiHashResolver
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves a Windows API hash to its name + address by brute-forcing.
pub struct ApiHashResolver {
    walker: PebWalker,
    /// Cache: hash → resolved API (per algorithm).
    cache: HashMap<(HashAlgorithm, u32), ResolvedApi>,
}

impl ApiHashResolver {
    /// Create with a default `PebWalker`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            walker: PebWalker::new(),
            cache: HashMap::new(),
        }
    }

    /// Create with a custom `PebWalker`.
    #[must_use]
    pub fn with_walker(walker: PebWalker) -> Self {
        Self {
            walker,
            cache: HashMap::new(),
        }
    }

    /// Resolve a hash using a specific algorithm.
    ///
    /// # Errors
    /// Returns [`ApiResolveError`] if the hash cannot be resolved.
    pub fn resolve(
        &mut self,
        hash: u32,
        algo: HashAlgorithm,
    ) -> Result<ResolvedApi, ApiResolveError> {
        if let Some(cached) = self.cache.get(&(algo, hash)) {
            return Ok(cached.clone());
        }

        let mut candidates: Vec<ResolvedApi> = Vec::new();

        for export in self.walker.all_exports() {
            let computed = hash_api_name(&export.name, algo);
            if computed == hash {
                candidates.push(ResolvedApi {
                    name: export.name.clone(),
                    module: export.module.clone(),
                    address: export.address,
                    hash,
                    algorithm: algo,
                });
            }
        }

        match candidates.len() {
            0 => Err(ApiResolveError::ExportNotFound(format!(
                "{hash:#010x} ({algo})"
            ))),
            1 => {
                self.cache.insert((algo, hash), candidates[0].clone());
                Ok(candidates.remove(0))
            }
            _ => Err(ApiResolveError::HashCollision(hash)),
        }
    }

    /// Try all supported algorithms for a given hash, return first match.
    ///
    /// # Errors
    /// Returns [`ApiResolveError::ExportNotFound`] if no algorithm matches.
    pub fn resolve_any(&mut self, hash: u32) -> Result<ResolvedApi, ApiResolveError> {
        let algos = [
            HashAlgorithm::Ror13,
            HashAlgorithm::Crc32,
            HashAlgorithm::Djb2,
            HashAlgorithm::Sdbm,
            HashAlgorithm::Fnv1a32,
            HashAlgorithm::AddHash,
            HashAlgorithm::XorRotate,
        ];
        for algo in algos {
            if let Ok(resolved) = self.resolve(hash, algo) {
                return Ok(resolved);
            }
        }
        Err(ApiResolveError::ExportNotFound(format!("{hash:#010x}")))
    }

    /// Pre-compute a hash lookup table for all known exports using `algo`.
    #[must_use]
    pub fn build_lookup_table(&self, algo: HashAlgorithm) -> HashMap<u32, String> {
        self.walker
            .all_exports()
            .into_iter()
            .map(|e| (hash_api_name(&e.name, algo), e.name.clone()))
            .collect()
    }
}

impl Default for ApiHashResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ApiResolverEmu
// ─────────────────────────────────────────────────────────────────────────────

/// High-level API resolver for shellcode emulation.
///
/// Combines PEB walking, hash resolution, and a stub return-value database.
pub struct ApiResolverEmu {
    resolver: ApiHashResolver,
    /// Stub return values: API name → simulated return value.
    stub_returns: HashMap<String, u64>,
    /// Resolved API log.
    resolution_log: Vec<ResolvedApi>,
}

impl ApiResolverEmu {
    /// Create a new resolver with default stubs.
    #[must_use]
    pub fn new() -> Self {
        let mut emu = Self {
            resolver: ApiHashResolver::new(),
            stub_returns: HashMap::new(),
            resolution_log: Vec::new(),
        };
        emu.populate_stubs();
        emu
    }

    /// Resolve an API by hash, trying all algorithms.
    ///
    /// # Errors
    /// Returns [`ApiResolveError`] if the hash cannot be resolved.
    pub fn resolve_hash(&mut self, hash: u32) -> Result<ResolvedApi, ApiResolveError> {
        let r = self.resolver.resolve_any(hash)?;
        self.resolution_log.push(r.clone());
        Ok(r)
    }

    /// Resolve an API by name directly.
    ///
    /// # Errors
    /// Returns [`ApiResolveError::ExportNotFound`] if not found.
    pub fn resolve_name(&mut self, name: &str) -> Result<ResolvedApi, ApiResolveError> {
        let export = self
            .resolver
            .walker
            .find_export(name)
            .ok_or_else(|| ApiResolveError::ExportNotFound(name.to_owned()))?;
        let r = ResolvedApi {
            name: export.name.clone(),
            module: export.module.clone(),
            address: export.address,
            hash: ror13_hash(name),
            algorithm: HashAlgorithm::Ror13,
        };
        self.resolution_log.push(r.clone());
        Ok(r)
    }

    /// Return the stub return value for an API name.
    #[must_use]
    pub fn stub_return(&self, name: &str) -> u64 {
        self.stub_returns.get(name).copied().unwrap_or(1)
    }

    /// Return all previously resolved APIs.
    #[must_use]
    pub fn resolution_log(&self) -> &[ResolvedApi] {
        &self.resolution_log
    }

    /// Add a custom stub return value.
    pub fn add_stub(&mut self, name: impl Into<String>, value: u64) {
        self.stub_returns.insert(name.into(), value);
    }

    fn populate_stubs(&mut self) {
        let stubs = [
            ("IsDebuggerPresent", 0u64),
            ("CheckRemoteDebuggerPresent", 0),
            ("VirtualAlloc", 0x10000),
            ("VirtualFree", 1),
            ("VirtualProtect", 1),
            ("HeapAlloc", 0x20000),
            ("CreateFileA", 0x100), // fake handle
            ("CreateFileW", 0x100),
            ("ReadFile", 1),
            ("WriteFile", 1),
            ("CloseHandle", 1),
            ("GetCurrentProcess", 0xFFFFFFFF_FFFFFFFF),
            ("GetCurrentProcessId", 1234),
            ("WSAStartup", 0),
            ("socket", 0x200), // fake socket fd
            ("connect", 0),
            ("send", 1),
            ("recv", 0),
            ("closesocket", 0),
        ];
        for (name, val) in stubs {
            self.stub_returns.insert(name.to_owned(), val);
        }
    }
}

impl Default for ApiResolverEmu {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- Hash algorithms -----------------------------------------------------

    #[test]
    fn test_ror13_hash_consistent() {
        let h1 = hash_api_name("VirtualAlloc", HashAlgorithm::Ror13);
        let h2 = hash_api_name("VirtualAlloc", HashAlgorithm::Ror13);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_ror13_different_names() {
        let h1 = hash_api_name("CreateFile", HashAlgorithm::Ror13);
        let h2 = hash_api_name("CloseHandle", HashAlgorithm::Ror13);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_crc32_hash() {
        let h = hash_api_name("LoadLibraryA", HashAlgorithm::Crc32);
        assert_ne!(h, 0);
    }

    #[test]
    fn test_djb2_hash() {
        let h = hash_api_name("GetProcAddress", HashAlgorithm::Djb2);
        assert_ne!(h, 0);
    }

    #[test]
    fn test_fnv1a32_hash() {
        let h = hash_api_name("WSASocket", HashAlgorithm::Fnv1a32);
        assert_ne!(h, 0);
    }

    #[test]
    fn test_add_hash_empty() {
        assert_eq!(hash_api_name("", HashAlgorithm::AddHash), 0);
    }

    #[test]
    fn test_hash_algorithm_display() {
        assert_eq!(HashAlgorithm::Ror13.to_string(), "ROR13");
        assert_eq!(HashAlgorithm::Custom(0xDEAD).to_string(), "Custom(0xdead)");
    }

    // -- PebWalker -----------------------------------------------------------

    #[test]
    fn test_peb_walker_module_base() {
        let w = PebWalker::new();
        assert!(w.module_base("kernel32.dll").is_some());
        assert!(w.module_base("ntdll.dll").is_some());
    }

    #[test]
    fn test_peb_walker_case_insensitive() {
        let w = PebWalker::new();
        assert_eq!(w.module_base("KERNEL32.DLL"), w.module_base("kernel32.dll"));
    }

    #[test]
    fn test_peb_walker_all_exports_not_empty() {
        let w = PebWalker::new();
        assert!(!w.all_exports().is_empty());
    }

    #[test]
    fn test_peb_walker_find_export() {
        let w = PebWalker::new();
        let e = w.find_export("VirtualAlloc");
        assert!(e.is_some());
        assert_eq!(e.unwrap().module, "kernel32.dll");
    }

    #[test]
    fn test_peb_walker_find_export_missing() {
        let w = PebWalker::new();
        assert!(w.find_export("NonExistentFunction").is_none());
    }

    #[test]
    fn test_peb_walker_add_module() {
        let mut w = PebWalker::new();
        w.add_module("custom.dll", &["MyFunc1", "MyFunc2"]);
        assert!(w.module_base("custom.dll").is_some());
        assert!(w.find_export("MyFunc1").is_some());
    }

    // -- ApiHashResolver -----------------------------------------------------

    #[test]
    fn test_resolve_ror13_virtual_alloc() {
        let mut r = ApiHashResolver::new();
        let hash = hash_api_name("VirtualAlloc", HashAlgorithm::Ror13);
        let resolved = r.resolve(hash, HashAlgorithm::Ror13).unwrap();
        assert_eq!(resolved.name, "VirtualAlloc");
    }

    #[test]
    fn test_resolve_not_found() {
        let mut r = ApiHashResolver::new();
        let err = r.resolve(0xDEADBEEF, HashAlgorithm::Ror13).unwrap_err();
        assert!(matches!(err, ApiResolveError::ExportNotFound(_)));
    }

    #[test]
    fn test_resolve_any_finds_djb2() {
        let mut r = ApiHashResolver::new();
        let hash = hash_api_name("CreateFileA", HashAlgorithm::Djb2);
        // resolve_any will try DJB2 and succeed.
        let result = r.resolve(hash, HashAlgorithm::Djb2).unwrap();
        assert_eq!(result.name, "CreateFileA");
    }

    #[test]
    fn test_build_lookup_table() {
        let r = ApiHashResolver::new();
        let table = r.build_lookup_table(HashAlgorithm::Ror13);
        let va_hash = hash_api_name("VirtualAlloc", HashAlgorithm::Ror13);
        assert!(table.contains_key(&va_hash));
    }

    #[test]
    fn test_resolver_cache() {
        let mut r = ApiHashResolver::new();
        let hash = hash_api_name("CloseHandle", HashAlgorithm::Crc32);
        let _ = r.resolve(hash, HashAlgorithm::Crc32);
        // Second call should use cache.
        let result = r.resolve(hash, HashAlgorithm::Crc32).unwrap();
        assert_eq!(result.name, "CloseHandle");
    }

    // -- ApiResolverEmu ------------------------------------------------------

    #[test]
    fn test_emu_stub_return_is_debugger_present() {
        let emu = ApiResolverEmu::new();
        assert_eq!(emu.stub_return("IsDebuggerPresent"), 0);
    }

    #[test]
    fn test_emu_stub_return_virtual_alloc() {
        let emu = ApiResolverEmu::new();
        assert!(emu.stub_return("VirtualAlloc") > 0);
    }

    #[test]
    fn test_emu_stub_return_unknown() {
        let emu = ApiResolverEmu::new();
        // Unknown APIs return 1 by default.
        assert_eq!(emu.stub_return("SomeFakeFunction"), 1);
    }

    #[test]
    fn test_emu_add_stub() {
        let mut emu = ApiResolverEmu::new();
        emu.add_stub("MyApi", 0xCAFEBABE);
        assert_eq!(emu.stub_return("MyApi"), 0xCAFEBABE);
    }

    #[test]
    fn test_emu_resolve_name() {
        let mut emu = ApiResolverEmu::new();
        let r = emu.resolve_name("LoadLibraryA").unwrap();
        assert_eq!(r.name, "LoadLibraryA");
    }

    #[test]
    fn test_emu_resolve_name_not_found() {
        let mut emu = ApiResolverEmu::new();
        assert!(emu.resolve_name("FakeFunctionXYZ").is_err());
    }

    #[test]
    fn test_emu_resolution_log() {
        let mut emu = ApiResolverEmu::new();
        emu.resolve_name("VirtualAlloc").unwrap();
        emu.resolve_name("CreateFileA").unwrap();
        assert_eq!(emu.resolution_log().len(), 2);
    }

    #[test]
    fn test_emu_resolve_hash_ror13() {
        let mut emu = ApiResolverEmu::new();
        let hash = hash_api_name("LoadLibraryA", HashAlgorithm::Ror13);
        let r = emu.resolve_hash(hash).unwrap();
        assert_eq!(r.name, "LoadLibraryA");
    }
}
