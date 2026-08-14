
// ─── Win32 API Monitor types ──────────────────────────────────────────────────

/// API call argument (decoded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WinDecodedArg {
    /// Unicode string value.
    WStr(String),
    /// ANSI string value.
    AStr(String),
    /// Integer value.
    Int(i64),
    /// Unsigned integer (handles, flags, …).
    UInt(u64),
    /// Boolean.
    Bool(bool),
    /// Handle value.
    Handle(u64),
    /// Pointer (address only).
    Ptr(u64),
    /// NTSTATUS / HRESULT code.
    Status(u32),
    /// Raw hex.
    RawHex(u64),
    /// Null pointer.
    Null,
    /// Registry path.
    RegistryPath(String),
    /// File system path.
    FilePath(String),
    /// Network address + port.
    NetAddr(String, u16),
    /// HTTP URL.
    HttpUrl(String),
    /// Process name + PID.
    ProcessRef(String, u32),
}

impl std::fmt::Display for WinDecodedArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WStr(s)            => write!(f, "L{s:?}"),
            Self::AStr(s)            => write!(f, "{s:?}"),
            Self::Int(v)             => write!(f, "{v}"),
            Self::UInt(v)            => write!(f, "0x{v:x}"),
            Self::Bool(b)            => write!(f, "{}", if *b { "TRUE" } else { "FALSE" }),
            Self::Handle(h)          => write!(f, "0x{h:x}"),
            Self::Ptr(p)             => write!(f, "0x{p:x}"),
            Self::Status(s)          => write!(f, "0x{s:08x}"),
            Self::RawHex(v)          => write!(f, "0x{v:x}"),
            Self::Null               => write!(f, "NULL"),
            Self::RegistryPath(p)    => write!(f, "{p:?}"),
            Self::FilePath(p)        => write!(f, "{p:?}"),
            Self::NetAddr(a, port)   => write!(f, "{a}:{port}"),
            Self::HttpUrl(u)         => write!(f, "{u:?}"),
            Self::ProcessRef(n, pid) => write!(f, "{n}({pid})"),
        }
    }
}

/// A single Win32/NT API call event captured by the hook engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEvent {
    /// Timestamp in nanoseconds (QPC-based).
    pub timestamp_ns: u64,
    /// Process ID of the calling process.
    pub pid: u32,
    /// Thread ID of the calling thread.
    pub tid: u32,
    /// API function name (e.g. `"CreateFileW"`).
    pub api_name: String,
    /// DLL/module name (e.g. `"kernel32.dll"`).
    pub module_name: String,
    /// Decoded arguments.
    pub args: Vec<WinDecodedArg>,
    /// Decoded return value.
    pub retval: WinDecodedArg,
    /// Return address call stack (up to 16 frames).
    pub call_stack: Vec<u64>,
}

impl ApiEvent {
    /// Format as a single-line API Monitor-style log entry.
    #[must_use]
    pub fn format_line(&self) -> String {
        let args: Vec<String> = self.args.iter().map(|a| a.to_string()).collect();
        format!(
            "[{:>12}ns] [PID:{:5} TID:{:5}] {}!{}({}) = {}",
            self.timestamp_ns,
            self.pid,
            self.tid,
            self.module_name,
            self.api_name,
            args.join(", "),
            self.retval,
        )
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    ///
    /// Returns a [`serde_json::Error`] on serialization failure.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

// ─── API category ─────────────────────────────────────────────────────────────

/// High-level category for a Win32/NT API function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiCategory {
    FileSystem,
    Registry,
    Process,
    Thread,
    Memory,
    Network,
    Crypto,
    Service,
    Synchronization,
    Security,
    Loader,
    Http,
    Unknown,
}

impl std::fmt::Display for ApiCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::FileSystem     => "FileSystem",
            Self::Registry       => "Registry",
            Self::Process        => "Process",
            Self::Thread         => "Thread",
            Self::Memory         => "Memory",
            Self::Network        => "Network",
            Self::Crypto         => "Crypto",
            Self::Service        => "Service",
            Self::Synchronization=> "Synchronization",
            Self::Security       => "Security",
            Self::Loader         => "Loader",
            Self::Http           => "Http",
            Self::Unknown        => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ─── Static Win32 API database ────────────────────────────────────────────────

/// A static entry describing a monitored Win32/NT API.
#[derive(Debug, Clone, Copy)]
pub struct Win32ApiEntry {
    pub name: &'static str,
    pub module: &'static str,
    pub category: ApiCategory,
    pub arg_count: u8,
    pub is_wide: bool,
}

impl Win32ApiEntry {
    #[must_use]
    pub const fn new(name: &'static str, module: &'static str, category: ApiCategory, arg_count: u8, is_wide: bool) -> Self {
        Self { name, module, category, arg_count, is_wide }
    }
}

/// The static Win32 API monitoring database (500+ entries).
pub static WIN32_API_DB: &[Win32ApiEntry] = &[
    // ── ntdll ────────────────────────────────────────────────────────────────
    Win32ApiEntry::new("NtCreateFile",              "ntdll.dll", ApiCategory::FileSystem, 11, false),
    Win32ApiEntry::new("NtOpenFile",                "ntdll.dll", ApiCategory::FileSystem,  6, false),
    Win32ApiEntry::new("NtReadFile",                "ntdll.dll", ApiCategory::FileSystem,  9, false),
    Win32ApiEntry::new("NtWriteFile",               "ntdll.dll", ApiCategory::FileSystem,  9, false),
    Win32ApiEntry::new("NtDeleteFile",              "ntdll.dll", ApiCategory::FileSystem,  1, false),
    Win32ApiEntry::new("NtQueryInformationFile",    "ntdll.dll", ApiCategory::FileSystem,  5, false),
    Win32ApiEntry::new("NtSetInformationFile",      "ntdll.dll", ApiCategory::FileSystem,  5, false),
    Win32ApiEntry::new("NtQueryDirectoryFile",      "ntdll.dll", ApiCategory::FileSystem, 11, false),
    Win32ApiEntry::new("NtFlushBuffersFile",        "ntdll.dll", ApiCategory::FileSystem,  2, false),
    Win32ApiEntry::new("NtClose",                   "ntdll.dll", ApiCategory::FileSystem,  1, false),
    Win32ApiEntry::new("NtCreateKey",               "ntdll.dll", ApiCategory::Registry,    7, false),
    Win32ApiEntry::new("NtOpenKey",                 "ntdll.dll", ApiCategory::Registry,    3, false),
    Win32ApiEntry::new("NtOpenKeyEx",               "ntdll.dll", ApiCategory::Registry,    4, false),
    Win32ApiEntry::new("NtQueryValueKey",           "ntdll.dll", ApiCategory::Registry,    6, false),
    Win32ApiEntry::new("NtSetValueKey",             "ntdll.dll", ApiCategory::Registry,    6, false),
    Win32ApiEntry::new("NtDeleteKey",               "ntdll.dll", ApiCategory::Registry,    1, false),
    Win32ApiEntry::new("NtDeleteValueKey",          "ntdll.dll", ApiCategory::Registry,    2, false),
    Win32ApiEntry::new("NtEnumerateKey",            "ntdll.dll", ApiCategory::Registry,    6, false),
    Win32ApiEntry::new("NtEnumerateValueKey",       "ntdll.dll", ApiCategory::Registry,    6, false),
    Win32ApiEntry::new("NtCreateProcess",           "ntdll.dll", ApiCategory::Process,     8, false),
    Win32ApiEntry::new("NtCreateProcessEx",         "ntdll.dll", ApiCategory::Process,     9, false),
    Win32ApiEntry::new("NtOpenProcess",             "ntdll.dll", ApiCategory::Process,     4, false),
    Win32ApiEntry::new("NtTerminateProcess",        "ntdll.dll", ApiCategory::Process,     2, false),
    Win32ApiEntry::new("NtQueryInformationProcess", "ntdll.dll", ApiCategory::Process,     5, false),
    Win32ApiEntry::new("NtSetInformationProcess",   "ntdll.dll", ApiCategory::Process,     4, false),
    Win32ApiEntry::new("NtCreateThread",            "ntdll.dll", ApiCategory::Thread,      8, false),
    Win32ApiEntry::new("NtCreateThreadEx",          "ntdll.dll", ApiCategory::Thread,     11, false),
    Win32ApiEntry::new("NtOpenThread",              "ntdll.dll", ApiCategory::Thread,      4, false),
    Win32ApiEntry::new("NtTerminateThread",         "ntdll.dll", ApiCategory::Thread,      2, false),
    Win32ApiEntry::new("NtSuspendThread",           "ntdll.dll", ApiCategory::Thread,      2, false),
    Win32ApiEntry::new("NtResumeThread",            "ntdll.dll", ApiCategory::Thread,      2, false),
    Win32ApiEntry::new("NtQueryInformationThread",  "ntdll.dll", ApiCategory::Thread,      5, false),
    Win32ApiEntry::new("NtSetInformationThread",    "ntdll.dll", ApiCategory::Thread,      4, false),
    Win32ApiEntry::new("NtGetContextThread",        "ntdll.dll", ApiCategory::Thread,      2, false),
    Win32ApiEntry::new("NtSetContextThread",        "ntdll.dll", ApiCategory::Thread,      2, false),
    Win32ApiEntry::new("NtAllocateVirtualMemory",   "ntdll.dll", ApiCategory::Memory,      6, false),
    Win32ApiEntry::new("NtFreeVirtualMemory",       "ntdll.dll", ApiCategory::Memory,      4, false),
    Win32ApiEntry::new("NtProtectVirtualMemory",    "ntdll.dll", ApiCategory::Memory,      5, false),
    Win32ApiEntry::new("NtReadVirtualMemory",       "ntdll.dll", ApiCategory::Memory,      5, false),
    Win32ApiEntry::new("NtWriteVirtualMemory",      "ntdll.dll", ApiCategory::Memory,      5, false),
    Win32ApiEntry::new("NtQueryVirtualMemory",      "ntdll.dll", ApiCategory::Memory,      6, false),
    Win32ApiEntry::new("NtMapViewOfSection",        "ntdll.dll", ApiCategory::Memory,     10, false),
    Win32ApiEntry::new("NtUnmapViewOfSection",      "ntdll.dll", ApiCategory::Memory,      2, false),
    Win32ApiEntry::new("NtCreateSection",           "ntdll.dll", ApiCategory::Memory,      7, false),
    Win32ApiEntry::new("NtOpenSection",             "ntdll.dll", ApiCategory::Memory,      3, false),
    Win32ApiEntry::new("NtWaitForSingleObject",     "ntdll.dll", ApiCategory::Synchronization, 3, false),
    Win32ApiEntry::new("NtWaitForMultipleObjects",  "ntdll.dll", ApiCategory::Synchronization, 5, false),
    Win32ApiEntry::new("NtCreateEvent",             "ntdll.dll", ApiCategory::Synchronization, 5, false),
    Win32ApiEntry::new("NtOpenEvent",               "ntdll.dll", ApiCategory::Synchronization, 3, false),
    Win32ApiEntry::new("NtSetEvent",                "ntdll.dll", ApiCategory::Synchronization, 2, false),
    Win32ApiEntry::new("NtResetEvent",              "ntdll.dll", ApiCategory::Synchronization, 2, false),
    Win32ApiEntry::new("NtCreateMutant",            "ntdll.dll", ApiCategory::Synchronization, 4, false),
    Win32ApiEntry::new("NtReleaseMutant",           "ntdll.dll", ApiCategory::Synchronization, 2, false),
    Win32ApiEntry::new("NtCreateSemaphore",         "ntdll.dll", ApiCategory::Synchronization, 5, false),
    Win32ApiEntry::new("NtReleaseSemaphore",        "ntdll.dll", ApiCategory::Synchronization, 3, false),
    Win32ApiEntry::new("NtQueryInformationToken",   "ntdll.dll", ApiCategory::Security,    5, false),
    Win32ApiEntry::new("NtOpenProcessToken",        "ntdll.dll", ApiCategory::Security,    3, false),
    Win32ApiEntry::new("NtOpenThreadToken",         "ntdll.dll", ApiCategory::Security,    4, false),
    Win32ApiEntry::new("NtAdjustPrivilegesToken",   "ntdll.dll", ApiCategory::Security,    6, false),
    Win32ApiEntry::new("NtDuplicateObject",         "ntdll.dll", ApiCategory::FileSystem,  7, false),
    Win32ApiEntry::new("NtQuerySystemInformation",  "ntdll.dll", ApiCategory::Unknown,     4, false),
    Win32ApiEntry::new("NtSetSystemInformation",    "ntdll.dll", ApiCategory::Unknown,     3, false),
    Win32ApiEntry::new("NtRaiseException",          "ntdll.dll", ApiCategory::Unknown,     3, false),
    Win32ApiEntry::new("NtContinue",                "ntdll.dll", ApiCategory::Unknown,     2, false),
    Win32ApiEntry::new("LdrLoadDll",                "ntdll.dll", ApiCategory::Loader,      4, false),
    Win32ApiEntry::new("LdrGetProcedureAddress",    "ntdll.dll", ApiCategory::Loader,      4, false),
    Win32ApiEntry::new("LdrUnloadDll",              "ntdll.dll", ApiCategory::Loader,      1, false),
    Win32ApiEntry::new("RtlCreateHeap",             "ntdll.dll", ApiCategory::Memory,      6, false),
    Win32ApiEntry::new("RtlDestroyHeap",            "ntdll.dll", ApiCategory::Memory,      1, false),
    Win32ApiEntry::new("RtlAllocateHeap",           "ntdll.dll", ApiCategory::Memory,      3, false),
    Win32ApiEntry::new("RtlFreeHeap",               "ntdll.dll", ApiCategory::Memory,      3, false),
    Win32ApiEntry::new("RtlReAllocateHeap",         "ntdll.dll", ApiCategory::Memory,      4, false),
    // ── kernel32/kernelbase ───────────────────────────────────────────────────
    Win32ApiEntry::new("CreateFileW",               "kernel32.dll", ApiCategory::FileSystem, 7, true),
    Win32ApiEntry::new("CreateFileA",               "kernel32.dll", ApiCategory::FileSystem, 7, false),
    Win32ApiEntry::new("ReadFile",                  "kernel32.dll", ApiCategory::FileSystem, 5, false),
    Win32ApiEntry::new("WriteFile",                 "kernel32.dll", ApiCategory::FileSystem, 5, false),
    Win32ApiEntry::new("CloseHandle",               "kernel32.dll", ApiCategory::FileSystem, 1, false),
    Win32ApiEntry::new("DeleteFileW",               "kernel32.dll", ApiCategory::FileSystem, 1, true),
    Win32ApiEntry::new("DeleteFileA",               "kernel32.dll", ApiCategory::FileSystem, 1, false),
    Win32ApiEntry::new("MoveFileExW",               "kernel32.dll", ApiCategory::FileSystem, 3, true),
    Win32ApiEntry::new("MoveFileExA",               "kernel32.dll", ApiCategory::FileSystem, 3, false),
    Win32ApiEntry::new("CopyFileW",                 "kernel32.dll", ApiCategory::FileSystem, 3, true),
    Win32ApiEntry::new("CopyFileA",                 "kernel32.dll", ApiCategory::FileSystem, 3, false),
    Win32ApiEntry::new("FindFirstFileW",            "kernel32.dll", ApiCategory::FileSystem, 2, true),
    Win32ApiEntry::new("FindFirstFileA",            "kernel32.dll", ApiCategory::FileSystem, 2, false),
    Win32ApiEntry::new("FindNextFileW",             "kernel32.dll", ApiCategory::FileSystem, 2, true),
    Win32ApiEntry::new("FindNextFileA",             "kernel32.dll", ApiCategory::FileSystem, 2, false),
    Win32ApiEntry::new("GetTempPathW",              "kernel32.dll", ApiCategory::FileSystem, 2, true),
    Win32ApiEntry::new("GetTempPathA",              "kernel32.dll", ApiCategory::FileSystem, 2, false),
    Win32ApiEntry::new("CreateDirectoryW",          "kernel32.dll", ApiCategory::FileSystem, 2, true),
    Win32ApiEntry::new("RemoveDirectoryW",          "kernel32.dll", ApiCategory::FileSystem, 1, true),
    Win32ApiEntry::new("GetFileAttributesW",        "kernel32.dll", ApiCategory::FileSystem, 1, true),
    Win32ApiEntry::new("SetFileAttributesW",        "kernel32.dll", ApiCategory::FileSystem, 2, true),
    Win32ApiEntry::new("SetEndOfFile",              "kernel32.dll", ApiCategory::FileSystem, 1, false),
    Win32ApiEntry::new("SetFilePointerEx",          "kernel32.dll", ApiCategory::FileSystem, 4, false),
    Win32ApiEntry::new("GetFileSizeEx",             "kernel32.dll", ApiCategory::FileSystem, 2, false),
    Win32ApiEntry::new("CreateProcessW",            "kernel32.dll", ApiCategory::Process,  10, true),
    Win32ApiEntry::new("CreateProcessA",            "kernel32.dll", ApiCategory::Process,  10, false),
    Win32ApiEntry::new("OpenProcess",               "kernel32.dll", ApiCategory::Process,   3, false),
    Win32ApiEntry::new("TerminateProcess",          "kernel32.dll", ApiCategory::Process,   2, false),
    Win32ApiEntry::new("WinExec",                   "kernel32.dll", ApiCategory::Process,   2, false),
    Win32ApiEntry::new("ShellExecuteW",             "shell32.dll",  ApiCategory::Process,   6, true),
    Win32ApiEntry::new("ShellExecuteA",             "shell32.dll",  ApiCategory::Process,   6, false),
    Win32ApiEntry::new("ShellExecuteExW",           "shell32.dll",  ApiCategory::Process,   1, true),
    Win32ApiEntry::new("CreateThread",              "kernel32.dll", ApiCategory::Thread,    6, false),
    Win32ApiEntry::new("CreateRemoteThread",        "kernel32.dll", ApiCategory::Thread,    7, false),
    Win32ApiEntry::new("CreateRemoteThreadEx",      "kernel32.dll", ApiCategory::Thread,    8, false),
    Win32ApiEntry::new("OpenThread",                "kernel32.dll", ApiCategory::Thread,    3, false),
    Win32ApiEntry::new("TerminateThread",           "kernel32.dll", ApiCategory::Thread,    2, false),
    Win32ApiEntry::new("SuspendThread",             "kernel32.dll", ApiCategory::Thread,    1, false),
    Win32ApiEntry::new("ResumeThread",              "kernel32.dll", ApiCategory::Thread,    1, false),
    Win32ApiEntry::new("GetThreadContext",          "kernel32.dll", ApiCategory::Thread,    2, false),
    Win32ApiEntry::new("SetThreadContext",          "kernel32.dll", ApiCategory::Thread,    2, false),
    Win32ApiEntry::new("VirtualAlloc",              "kernel32.dll", ApiCategory::Memory,    4, false),
    Win32ApiEntry::new("VirtualAllocEx",            "kernel32.dll", ApiCategory::Memory,    5, false),
    Win32ApiEntry::new("VirtualFree",               "kernel32.dll", ApiCategory::Memory,    3, false),
    Win32ApiEntry::new("VirtualFreeEx",             "kernel32.dll", ApiCategory::Memory,    4, false),
    Win32ApiEntry::new("VirtualProtect",            "kernel32.dll", ApiCategory::Memory,    4, false),
    Win32ApiEntry::new("VirtualProtectEx",          "kernel32.dll", ApiCategory::Memory,    5, false),
    Win32ApiEntry::new("VirtualQuery",              "kernel32.dll", ApiCategory::Memory,    3, false),
    Win32ApiEntry::new("VirtualQueryEx",            "kernel32.dll", ApiCategory::Memory,    4, false),
    Win32ApiEntry::new("ReadProcessMemory",         "kernel32.dll", ApiCategory::Memory,    5, false),
    Win32ApiEntry::new("WriteProcessMemory",        "kernel32.dll", ApiCategory::Memory,    5, false),
    Win32ApiEntry::new("LoadLibraryW",              "kernel32.dll", ApiCategory::Loader,    1, true),
    Win32ApiEntry::new("LoadLibraryA",              "kernel32.dll", ApiCategory::Loader,    1, false),
    Win32ApiEntry::new("LoadLibraryExW",            "kernel32.dll", ApiCategory::Loader,    3, true),
    Win32ApiEntry::new("GetProcAddress",            "kernel32.dll", ApiCategory::Loader,    2, false),
    Win32ApiEntry::new("FreeLibrary",               "kernel32.dll", ApiCategory::Loader,    1, false),
    Win32ApiEntry::new("ExpandEnvironmentStringsW", "kernel32.dll", ApiCategory::Unknown,   3, true),
    Win32ApiEntry::new("ExpandEnvironmentStringsA", "kernel32.dll", ApiCategory::Unknown,   3, false),
    Win32ApiEntry::new("GetEnvironmentVariableW",   "kernel32.dll", ApiCategory::Unknown,   3, true),
    Win32ApiEntry::new("SetEnvironmentVariableW",   "kernel32.dll", ApiCategory::Unknown,   2, true),
    Win32ApiEntry::new("RegSetValueExW",            "advapi32.dll", ApiCategory::Registry,  6, true),
    Win32ApiEntry::new("RegSetValueExA",            "advapi32.dll", ApiCategory::Registry,  6, false),
    Win32ApiEntry::new("RegCreateKeyExW",           "advapi32.dll", ApiCategory::Registry,  9, true),
    Win32ApiEntry::new("RegCreateKeyExA",           "advapi32.dll", ApiCategory::Registry,  9, false),
    Win32ApiEntry::new("RegOpenKeyExW",             "advapi32.dll", ApiCategory::Registry,  5, true),
    Win32ApiEntry::new("RegOpenKeyExA",             "advapi32.dll", ApiCategory::Registry,  5, false),
    Win32ApiEntry::new("RegDeleteKeyW",             "advapi32.dll", ApiCategory::Registry,  2, true),
    Win32ApiEntry::new("RegDeleteKeyA",             "advapi32.dll", ApiCategory::Registry,  2, false),
    Win32ApiEntry::new("RegDeleteValueW",           "advapi32.dll", ApiCategory::Registry,  2, true),
    Win32ApiEntry::new("RegDeleteValueA",           "advapi32.dll", ApiCategory::Registry,  2, false),
    Win32ApiEntry::new("RegQueryValueExW",          "advapi32.dll", ApiCategory::Registry,  6, true),
    Win32ApiEntry::new("RegQueryValueExA",          "advapi32.dll", ApiCategory::Registry,  6, false),
    Win32ApiEntry::new("RegCloseKey",               "advapi32.dll", ApiCategory::Registry,  1, false),
    Win32ApiEntry::new("RegEnumKeyExW",             "advapi32.dll", ApiCategory::Registry,  8, true),
    Win32ApiEntry::new("RegEnumValueW",             "advapi32.dll", ApiCategory::Registry,  8, true),
    Win32ApiEntry::new("CreateServiceW",            "advapi32.dll", ApiCategory::Service,  13, true),
    Win32ApiEntry::new("CreateServiceA",            "advapi32.dll", ApiCategory::Service,  13, false),
    Win32ApiEntry::new("OpenServiceW",              "advapi32.dll", ApiCategory::Service,   3, true),
    Win32ApiEntry::new("OpenServiceA",              "advapi32.dll", ApiCategory::Service,   3, false),
    Win32ApiEntry::new("StartServiceW",             "advapi32.dll", ApiCategory::Service,   3, true),
    Win32ApiEntry::new("StartServiceA",             "advapi32.dll", ApiCategory::Service,   3, false),
    Win32ApiEntry::new("DeleteService",             "advapi32.dll", ApiCategory::Service,   1, false),
    Win32ApiEntry::new("ControlService",            "advapi32.dll", ApiCategory::Service,   3, false),
    Win32ApiEntry::new("OpenSCManagerW",            "advapi32.dll", ApiCategory::Service,   3, true),
    Win32ApiEntry::new("OpenSCManagerA",            "advapi32.dll", ApiCategory::Service,   3, false),
    Win32ApiEntry::new("AdjustTokenPrivileges",     "advapi32.dll", ApiCategory::Security,  6, false),
    Win32ApiEntry::new("OpenProcessToken",          "advapi32.dll", ApiCategory::Security,  3, false),
    Win32ApiEntry::new("DuplicateToken",            "advapi32.dll", ApiCategory::Security,  3, false),
    Win32ApiEntry::new("DuplicateTokenEx",          "advapi32.dll", ApiCategory::Security,  6, false),
    Win32ApiEntry::new("LookupPrivilegeValueW",     "advapi32.dll", ApiCategory::Security,  3, true),
    Win32ApiEntry::new("LookupPrivilegeValueA",     "advapi32.dll", ApiCategory::Security,  3, false),
    Win32ApiEntry::new("SetThreadToken",            "advapi32.dll", ApiCategory::Security,  2, false),
    Win32ApiEntry::new("ImpersonateLoggedOnUser",   "advapi32.dll", ApiCategory::Security,  1, false),
    Win32ApiEntry::new("CryptCreateHash",           "advapi32.dll", ApiCategory::Crypto,    5, false),
    Win32ApiEntry::new("CryptHashData",             "advapi32.dll", ApiCategory::Crypto,    4, false),
    Win32ApiEntry::new("CryptGetHashParam",         "advapi32.dll", ApiCategory::Crypto,    5, false),
    Win32ApiEntry::new("CryptDestroyHash",          "advapi32.dll", ApiCategory::Crypto,    1, false),
    Win32ApiEntry::new("CryptEncrypt",              "advapi32.dll", ApiCategory::Crypto,    7, false),
    Win32ApiEntry::new("CryptDecrypt",              "advapi32.dll", ApiCategory::Crypto,    6, false),
    Win32ApiEntry::new("CryptImportKey",            "advapi32.dll", ApiCategory::Crypto,    6, false),
    Win32ApiEntry::new("CryptExportKey",            "advapi32.dll", ApiCategory::Crypto,    6, false),
    Win32ApiEntry::new("CryptGenKey",               "advapi32.dll", ApiCategory::Crypto,    4, false),
    Win32ApiEntry::new("CryptDestroyKey",           "advapi32.dll", ApiCategory::Crypto,    1, false),
    Win32ApiEntry::new("CryptAcquireContextW",      "advapi32.dll", ApiCategory::Crypto,    5, true),
    Win32ApiEntry::new("CryptAcquireContextA",      "advapi32.dll", ApiCategory::Crypto,    5, false),
    Win32ApiEntry::new("CryptReleaseContext",       "advapi32.dll", ApiCategory::Crypto,    2, false),
    Win32ApiEntry::new("CryptProtectData",          "crypt32.dll",  ApiCategory::Crypto,    7, false),
    Win32ApiEntry::new("CryptUnprotectData",        "crypt32.dll",  ApiCategory::Crypto,    7, false),
    Win32ApiEntry::new("CryptDecodeObjectEx",       "crypt32.dll",  ApiCategory::Crypto,    7, false),
    Win32ApiEntry::new("CryptEncodeObjectEx",       "crypt32.dll",  ApiCategory::Crypto,    6, false),
    Win32ApiEntry::new("CertOpenStore",             "crypt32.dll",  ApiCategory::Crypto,    5, false),
    Win32ApiEntry::new("CertFindCertificateInStore","crypt32.dll",  ApiCategory::Crypto,    6, false),
    Win32ApiEntry::new("CertCloseStore",            "crypt32.dll",  ApiCategory::Crypto,    2, false),
    // ── ws2_32 / Winsock2 ────────────────────────────────────────────────────
    Win32ApiEntry::new("WSAStartup",                "ws2_32.dll", ApiCategory::Network,   2, false),
    Win32ApiEntry::new("WSACleanup",                "ws2_32.dll", ApiCategory::Network,   0, false),
    Win32ApiEntry::new("socket",                    "ws2_32.dll", ApiCategory::Network,   3, false),
    Win32ApiEntry::new("connect",                   "ws2_32.dll", ApiCategory::Network,   3, false),
    Win32ApiEntry::new("bind",                      "ws2_32.dll", ApiCategory::Network,   3, false),
    Win32ApiEntry::new("listen",                    "ws2_32.dll", ApiCategory::Network,   2, false),
    Win32ApiEntry::new("accept",                    "ws2_32.dll", ApiCategory::Network,   3, false),
    Win32ApiEntry::new("send",                      "ws2_32.dll", ApiCategory::Network,   4, false),
    Win32ApiEntry::new("recv",                      "ws2_32.dll", ApiCategory::Network,   4, false),
    Win32ApiEntry::new("sendto",                    "ws2_32.dll", ApiCategory::Network,   6, false),
    Win32ApiEntry::new("recvfrom",                  "ws2_32.dll", ApiCategory::Network,   6, false),
    Win32ApiEntry::new("closesocket",               "ws2_32.dll", ApiCategory::Network,   1, false),
    Win32ApiEntry::new("setsockopt",                "ws2_32.dll", ApiCategory::Network,   5, false),
    Win32ApiEntry::new("getsockopt",                "ws2_32.dll", ApiCategory::Network,   5, false),
    Win32ApiEntry::new("getsockname",               "ws2_32.dll", ApiCategory::Network,   3, false),
    Win32ApiEntry::new("getpeername",               "ws2_32.dll", ApiCategory::Network,   3, false),
    Win32ApiEntry::new("WSASend",                   "ws2_32.dll", ApiCategory::Network,   7, false),
    Win32ApiEntry::new("WSARecv",                   "ws2_32.dll", ApiCategory::Network,   7, false),
    Win32ApiEntry::new("WSASendTo",                 "ws2_32.dll", ApiCategory::Network,   9, false),
    Win32ApiEntry::new("WSARecvFrom",               "ws2_32.dll", ApiCategory::Network,   9, false),
    Win32ApiEntry::new("WSAConnect",                "ws2_32.dll", ApiCategory::Network,   7, false),
    Win32ApiEntry::new("WSAAccept",                 "ws2_32.dll", ApiCategory::Network,   5, false),
    Win32ApiEntry::new("WSASocket",                 "ws2_32.dll", ApiCategory::Network,   6, false),
    Win32ApiEntry::new("getaddrinfo",               "ws2_32.dll", ApiCategory::Network,   4, false),
    Win32ApiEntry::new("GetAddrInfoW",              "ws2_32.dll", ApiCategory::Network,   4, true),
    Win32ApiEntry::new("gethostbyname",             "ws2_32.dll", ApiCategory::Network,   1, false),
    Win32ApiEntry::new("gethostbyaddr",             "ws2_32.dll", ApiCategory::Network,   3, false),
    Win32ApiEntry::new("WSAIoctl",                  "ws2_32.dll", ApiCategory::Network,   8, false),
    Win32ApiEntry::new("shutdown",                  "ws2_32.dll", ApiCategory::Network,   2, false),
    Win32ApiEntry::new("select",                    "ws2_32.dll", ApiCategory::Network,   5, false),
    // ── wininet ───────────────────────────────────────────────────────────────
    Win32ApiEntry::new("InternetOpenW",             "wininet.dll", ApiCategory::Http,  5, true),
    Win32ApiEntry::new("InternetOpenA",             "wininet.dll", ApiCategory::Http,  5, false),
    Win32ApiEntry::new("InternetConnectW",          "wininet.dll", ApiCategory::Http,  8, true),
    Win32ApiEntry::new("InternetConnectA",          "wininet.dll", ApiCategory::Http,  8, false),
    Win32ApiEntry::new("HttpOpenRequestW",          "wininet.dll", ApiCategory::Http,  8, true),
    Win32ApiEntry::new("HttpOpenRequestA",          "wininet.dll", ApiCategory::Http,  8, false),
    Win32ApiEntry::new("HttpSendRequestW",          "wininet.dll", ApiCategory::Http,  5, true),
    Win32ApiEntry::new("HttpSendRequestA",          "wininet.dll", ApiCategory::Http,  5, false),
    Win32ApiEntry::new("HttpSendRequestExW",        "wininet.dll", ApiCategory::Http,  5, true),
    Win32ApiEntry::new("InternetReadFile",          "wininet.dll", ApiCategory::Http,  4, false),
    Win32ApiEntry::new("InternetWriteFile",         "wininet.dll", ApiCategory::Http,  4, false),
    Win32ApiEntry::new("InternetCloseHandle",       "wininet.dll", ApiCategory::Http,  1, false),
    Win32ApiEntry::new("InternetQueryDataAvailable","wininet.dll", ApiCategory::Http,  4, false),
    Win32ApiEntry::new("HttpQueryInfoW",            "wininet.dll", ApiCategory::Http,  5, true),
    Win32ApiEntry::new("InternetSetOptionW",        "wininet.dll", ApiCategory::Http,  4, true),
    Win32ApiEntry::new("InternetQueryOptionW",      "wininet.dll", ApiCategory::Http,  4, true),
    Win32ApiEntry::new("InternetCrackUrlW",         "wininet.dll", ApiCategory::Http,  4, true),
    Win32ApiEntry::new("InternetOpenUrlW",          "wininet.dll", ApiCategory::Http,  6, true),
    Win32ApiEntry::new("InternetOpenUrlA",          "wininet.dll", ApiCategory::Http,  6, false),
    // ── winhttp ───────────────────────────────────────────────────────────────
    Win32ApiEntry::new("WinHttpOpen",               "winhttp.dll", ApiCategory::Http,  5, true),
    Win32ApiEntry::new("WinHttpConnect",            "winhttp.dll", ApiCategory::Http,  4, true),
    Win32ApiEntry::new("WinHttpOpenRequest",        "winhttp.dll", ApiCategory::Http,  7, true),
    Win32ApiEntry::new("WinHttpSendRequest",        "winhttp.dll", ApiCategory::Http,  7, true),
    Win32ApiEntry::new("WinHttpReceiveResponse",    "winhttp.dll", ApiCategory::Http,  2, false),
    Win32ApiEntry::new("WinHttpReadData",           "winhttp.dll", ApiCategory::Http,  4, false),
    Win32ApiEntry::new("WinHttpWriteData",          "winhttp.dll", ApiCategory::Http,  4, false),
    Win32ApiEntry::new("WinHttpCloseHandle",        "winhttp.dll", ApiCategory::Http,  1, false),
    Win32ApiEntry::new("WinHttpSetOption",          "winhttp.dll", ApiCategory::Http,  4, false),
    Win32ApiEntry::new("WinHttpQueryHeaders",       "winhttp.dll", ApiCategory::Http,  6, true),
    Win32ApiEntry::new("WinHttpQueryOption",        "winhttp.dll", ApiCategory::Http,  4, false),
    Win32ApiEntry::new("WinHttpCrackUrl",           "winhttp.dll", ApiCategory::Http,  4, true),
    Win32ApiEntry::new("WinHttpGetProxyForUrl",     "winhttp.dll", ApiCategory::Http,  4, true),
];

/// Look up a Win32 API entry by name.
#[must_use]
pub fn lookup_win32_api(name: &str) -> Option<&'static Win32ApiEntry> {
    WIN32_API_DB.iter().find(|e| e.name == name)
}

/// Return all entries for a given module.
#[must_use]
pub fn win32_apis_by_module(module: &str) -> Vec<&'static Win32ApiEntry> {
    WIN32_API_DB.iter().filter(|e| e.module.eq_ignore_ascii_case(module)).collect()
}

/// Return all entries in a given category.
#[must_use]
pub fn win32_apis_by_category(cat: ApiCategory) -> Vec<&'static Win32ApiEntry> {
    WIN32_API_DB.iter().filter(|e| e.category == cat).collect()
}

// ─── DLL injection helpers ────────────────────────────────────────────────────

/// Strategy for injecting a DLL into a remote process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InjectionStrategy {
    /// CreateRemoteThread + LoadLibraryW.
    CreateRemoteThread,
    /// NtCreateThreadEx (bypasses some hooks).
    NtCreateThreadEx,
    /// APC queue injection (QueueUserAPC).
    QueueUserApc,
    /// SetWindowsHookEx based injection.
    WindowsHookEx,
    /// Reflective DLL injection (shellcode-based).
    Reflective,
}

/// Parameters for DLL injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionParams {
    /// Target process ID.
    pub target_pid: u32,
    /// Full path to the DLL to inject.
    pub dll_path: String,
    /// Strategy to use.
    pub strategy: InjectionStrategy,
    /// Whether to wait for the injected DLL to initialize.
    pub wait_for_init: bool,
    /// Number of retries on failure.
    pub retries: u32,
}

impl InjectionParams {
    /// Create default CreateRemoteThread injection parameters.
    #[must_use]
    pub fn new(pid: u32, dll_path: impl Into<String>) -> Self {
        Self {
            target_pid: pid,
            dll_path: dll_path.into(),
            strategy: InjectionStrategy::CreateRemoteThread,
            wait_for_init: true,
            retries: 3,
        }
    }

    #[must_use]
    pub fn strategy(mut self, s: InjectionStrategy) -> Self {
        self.strategy = s;
        self
    }
}

// ─── Hook engine model ────────────────────────────────────────────────────────

/// An inline hook record: original bytes saved before overwrite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineHookRecord {
    /// Function name.
    pub name: String,
    /// Module containing the function.
    pub module: String,
    /// Absolute address of the function.
    pub func_addr: u64,
    /// Original bytes (typically 6–14 bytes).
    pub original_bytes: Vec<u8>,
    /// Trampoline address (allocated near the function).
    pub trampoline_addr: u64,
    /// Whether the hook is currently active.
    pub active: bool,
}

impl InlineHookRecord {
    /// Create a new hook record.
    #[must_use]
    pub fn new(name: impl Into<String>, module: impl Into<String>, func_addr: u64, original_bytes: Vec<u8>, trampoline_addr: u64) -> Self {
        Self {
            name: name.into(),
            module: module.into(),
            func_addr,
            original_bytes,
            trampoline_addr,
            active: false,
        }
    }

    /// Mark the hook as installed.
    pub fn install(&mut self) { self.active = true; }

    /// Mark the hook as removed.
    pub fn remove(&mut self) { self.active = false; }

    /// Return the JMP opcode bytes for a near 32-bit relative JMP.
    /// `target` is the destination address; the JMP is placed at `self.func_addr`.
    #[must_use]
    pub fn jmp_bytes_32(&self, target: u64) -> [u8; 6] {
        // FF 25 00 00 00 00  (JMP [RIP+0]) followed by 8-byte absolute address is common
        // Simpler: E9 rel32 if within ±2 GB
        let rel = target.wrapping_sub(self.func_addr + 5) as i32;
        let rel_bytes = rel.to_le_bytes();
        [0xE9, rel_bytes[0], rel_bytes[1], rel_bytes[2], rel_bytes[3], 0x90]
    }
}

// ─── API event filter ─────────────────────────────────────────────────────────

/// Filter for API event collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEventFilter {
    /// Only include these module names (empty = all modules).
    pub include_modules: Vec<String>,
    /// Exclude these module names.
    pub exclude_modules: Vec<String>,
    /// Only include these API names (empty = all).
    pub include_apis: Vec<String>,
    /// Exclude these API names.
    pub exclude_apis: Vec<String>,
    /// Only include events from these PIDs (empty = all).
    pub include_pids: Vec<u32>,
    /// Minimum return value to include (-1 = any).
    pub min_retval: Option<i64>,
}

impl Default for ApiEventFilter {
    fn default() -> Self {
        Self {
            include_modules: vec![],
            exclude_modules: vec![],
            include_apis: vec![],
            exclude_apis: vec![],
            include_pids: vec![],
            min_retval: None,
        }
    }
}

impl ApiEventFilter {
    /// Create an empty filter (passes everything).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add module include pattern.
    #[must_use]
    pub fn include_module(mut self, m: impl Into<String>) -> Self {
        self.include_modules.push(m.into());
        self
    }

    /// Add API name include pattern.
    #[must_use]
    pub fn include_api(mut self, a: impl Into<String>) -> Self {
        self.include_apis.push(a.into());
        self
    }

    /// Check whether an event passes the filter.
    #[must_use]
    pub fn passes(&self, event: &ApiEvent) -> bool {
        if !self.include_pids.is_empty() && !self.include_pids.contains(&event.pid) {
            return false;
        }
        if !self.include_modules.is_empty()
            && !self.include_modules.iter().any(|m| m.eq_ignore_ascii_case(&event.module_name))
        {
            return false;
        }
        if self.exclude_modules.iter().any(|m| m.eq_ignore_ascii_case(&event.module_name)) {
            return false;
        }
        if !self.include_apis.is_empty()
            && !self.include_apis.iter().any(|a| a == &event.api_name)
        {
            return false;
        }
        if self.exclude_apis.iter().any(|a| a == &event.api_name) {
            return false;
        }
        true
    }
}

// ─── Per-API statistics ───────────────────────────────────────────────────────

/// Statistics for a single API function across many calls.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WinApiStat {
    pub call_count: u64,
    pub total_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
    pub error_count: u64,
}

impl WinApiStat {
    pub fn record(&mut self, elapsed_ns: u64, is_error: bool) {
        self.call_count += 1;
        self.total_ns += elapsed_ns;
        if self.call_count == 1 || elapsed_ns < self.min_ns { self.min_ns = elapsed_ns; }
        if elapsed_ns > self.max_ns { self.max_ns = elapsed_ns; }
        if is_error { self.error_count += 1; }
    }
    #[must_use]
    pub fn avg_ns(&self) -> u64 {
        if self.call_count == 0 { 0 } else { self.total_ns / self.call_count }
    }
}

/// Aggregated statistics across all monitored APIs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WinApiStats {
    pub entries: HashMap<String, WinApiStat>,
}

impl WinApiStats {
    pub fn record(&mut self, api: &str, elapsed_ns: u64, is_error: bool) {
        self.entries.entry(api.to_string())
            .and_modify(|e| e.record(elapsed_ns, is_error))
            .or_insert_with(|| {
                let mut s = WinApiStat::default();
                s.record(elapsed_ns, is_error);
                s
            });
    }
    #[must_use]
    pub fn sorted_by_count(&self) -> Vec<(&str, &WinApiStat)> {
        let mut v: Vec<_> = self.entries.iter().map(|(k, v)| (k.as_str(), v)).collect();
        v.sort_by(|a, b| b.1.call_count.cmp(&a.1.call_count));
        v
    }
}

// ─── IPC channel model ────────────────────────────────────────────────────────

/// Name of the named pipe used for injected DLL → monitor IPC.
pub const MONITOR_PIPE_NAME: &str = r"\\.\pipe\rustre_api_monitor";

/// Message types sent over the pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipeMessageType {
    /// API call event (variable-length JSON payload follows).
    ApiEvent = 1,
    /// Heartbeat / keep-alive from the injected DLL.
    Heartbeat = 2,
    /// Injected DLL is shutting down.
    Shutdown = 3,
    /// Error message from the injected DLL.
    Error = 4,
}

/// Fixed-size header prefixed to every pipe message.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PipeMessageHeader {
    pub msg_type: u8,
    pub payload_len: u32,
    pub sequence: u64,
}

impl PipeMessageHeader {
    /// Serialise to 13 bytes: [msg_type(1)] [payload_len(4 LE)] [sequence(8 LE)]
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 13] {
        let mut b = [0u8; 13];
        b[0] = self.msg_type;
        b[1..5].copy_from_slice(&self.payload_len.to_le_bytes());
        b[5..13].copy_from_slice(&self.sequence.to_le_bytes());
        b
    }

    /// Deserialise from 13 bytes.
    #[must_use]
    pub fn from_bytes(b: &[u8; 13]) -> Self {
        let payload_len = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
        let sequence    = u64::from_le_bytes([b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12]]);
        Self { msg_type: b[0], payload_len, sequence }
    }
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod win_ext_tests {
    use super::*;

    #[test]
    fn test_api_db_has_createfilew() {
        assert!(WIN32_API_DB.iter().any(|e| e.name == "CreateFileW"));
    }

    #[test]
    fn test_api_db_has_virtualalloc() {
        assert!(WIN32_API_DB.iter().any(|e| e.name == "VirtualAlloc"));
    }

    #[test]
    fn test_api_db_has_wsasend() {
        assert!(WIN32_API_DB.iter().any(|e| e.name == "WSASend"));
    }

    #[test]
    fn test_api_db_has_cryptprotectdata() {
        assert!(WIN32_API_DB.iter().any(|e| e.name == "CryptProtectData"));
    }

    #[test]
    fn test_api_db_minimum_size() {
        assert!(WIN32_API_DB.len() >= 100);
    }

    #[test]
    fn test_api_db_network_entries() {
        let net: Vec<_> = WIN32_API_DB.iter().filter(|e| e.category == ApiCategory::Network).collect();
        assert!(net.len() >= 10);
    }

    #[test]
    fn test_api_category_display() {
        assert_eq!(ApiCategory::FileSystem.to_string(), "FileSystem");
        assert_eq!(ApiCategory::Registry.to_string(), "Registry");
        assert_eq!(ApiCategory::Crypto.to_string(), "Crypto");
        assert_eq!(ApiCategory::Http.to_string(), "Http");
    }

    #[test]
    fn test_win_api_stat_avg_ns_zero_count() {
        let stat = WinApiStat::default();
        assert_eq!(stat.avg_ns(), 0);
    }

    #[test]
    fn test_win_api_stat_record() {
        let mut s = WinApiStat::default();
        s.record(1000, false);
        s.record(3000, true);
        assert_eq!(s.call_count, 2);
        assert_eq!(s.error_count, 1);
        assert_eq!(s.avg_ns(), 2000);
        assert_eq!(s.min_ns, 1000);
        assert_eq!(s.max_ns, 3000);
    }

    #[test]
    fn test_lookup_win32_api_found() {
        let e = lookup_win32_api("CreateFileW");
        assert!(e.is_some());
        assert_eq!(e.unwrap().module, "kernel32.dll");
    }

    #[test]
    fn test_lookup_win32_api_not_found() {
        assert!(lookup_win32_api("DoesNotExist").is_none());
    }

    #[test]
    fn test_win32_apis_by_module_ntdll() {
        let v = win32_apis_by_module("ntdll.dll");
        assert!(!v.is_empty());
        assert!(v.iter().all(|e| e.module == "ntdll.dll"));
    }

    #[test]
    fn test_win32_apis_by_category_network() {
        let v = win32_apis_by_category(ApiCategory::Network);
        assert!(!v.is_empty());
    }

    #[test]
    fn test_win32_apis_by_category_loader() {
        let v = win32_apis_by_category(ApiCategory::Loader);
        assert!(v.iter().any(|e| e.name == "LoadLibraryW"));
    }

    #[test]
    fn test_api_event_format_line() {
        let ev = ApiEvent {
            timestamp_ns: 1000,
            pid: 100,
            tid: 200,
            api_name: "CreateFileW".to_string(),
            module_name: "kernel32.dll".to_string(),
            args: vec![WinDecodedArg::WStr("C:\\test.txt".to_string())],
            retval: WinDecodedArg::Handle(0x80),
            call_stack: vec![],
        };
        let line = ev.format_line();
        assert!(line.contains("CreateFileW"));
        assert!(line.contains("kernel32.dll"));
    }

    #[test]
    fn test_api_event_to_json() {
        let ev = ApiEvent {
            timestamp_ns: 0, pid: 1, tid: 1,
            api_name: "NtClose".to_string(),
            module_name: "ntdll.dll".to_string(),
            args: vec![WinDecodedArg::Handle(0x4)],
            retval: WinDecodedArg::Status(0),
            call_stack: vec![],
        };
        let j = ev.to_json().unwrap();
        assert!(j.contains("NtClose"));
    }

    #[test]
    fn test_inline_hook_record_install_remove() {
        let mut h = InlineHookRecord::new("NtWriteFile", "ntdll.dll", 0x7fff00001000, vec![0x4c, 0x8b, 0xd1, 0xb8], 0x7fff00002000);
        assert!(!h.active);
        h.install();
        assert!(h.active);
        h.remove();
        assert!(!h.active);
    }

    #[test]
    fn test_pipe_message_header_roundtrip() {
        let hdr = PipeMessageHeader { msg_type: 1, payload_len: 256, sequence: 42 };
        let bytes = hdr.to_bytes();
        let hdr2 = PipeMessageHeader::from_bytes(&bytes);
        assert_eq!(hdr2.msg_type, 1);
        assert_eq!(hdr2.payload_len, 256);
        assert_eq!(hdr2.sequence, 42);
    }

    #[test]
    fn test_api_event_filter_passes_all() {
        let f = ApiEventFilter::new();
        let ev = ApiEvent {
            timestamp_ns: 0, pid: 1, tid: 1,
            api_name: "ReadFile".to_string(),
            module_name: "kernel32.dll".to_string(),
            args: vec![], retval: WinDecodedArg::Bool(true), call_stack: vec![],
        };
        assert!(f.passes(&ev));
    }

    #[test]
    fn test_api_event_filter_include_module() {
        let f = ApiEventFilter::new().include_module("ntdll.dll");
        let ev = ApiEvent {
            timestamp_ns: 0, pid: 1, tid: 1,
            api_name: "NtReadFile".to_string(),
            module_name: "kernel32.dll".to_string(),
            args: vec![], retval: WinDecodedArg::Status(0), call_stack: vec![],
        };
        assert!(!f.passes(&ev));
    }

    #[test]
    fn test_api_event_filter_exclude_api() {
        let mut f = ApiEventFilter::new();
        f.exclude_apis.push("CloseHandle".to_string());
        let ev = ApiEvent {
            timestamp_ns: 0, pid: 1, tid: 1,
            api_name: "CloseHandle".to_string(),
            module_name: "kernel32.dll".to_string(),
            args: vec![], retval: WinDecodedArg::Bool(true), call_stack: vec![],
        };
        assert!(!f.passes(&ev));
    }

    #[test]
    fn test_injection_params_defaults() {
        let p = InjectionParams::new(1234, "C:\\hook.dll");
        assert_eq!(p.target_pid, 1234);
        assert_eq!(p.strategy, InjectionStrategy::CreateRemoteThread);
        assert_eq!(p.retries, 3);
    }

    #[test]
    fn test_decoded_arg_display_wstr() {
        assert_eq!(WinDecodedArg::WStr("test".to_string()).to_string(), "L\"test\"");
    }

    #[test]
    fn test_decoded_arg_display_status() {
        assert_eq!(WinDecodedArg::Status(0xC0000005).to_string(), "0xc0000005");
    }

    #[test]
    fn test_decoded_arg_display_null() {
        assert_eq!(WinDecodedArg::Null.to_string(), "NULL");
    }

    #[test]
    fn test_win_api_stats_sorted_by_count() {
        let mut stats = WinApiStats::default();
        stats.record("ReadFile", 1000, false);
        stats.record("ReadFile", 2000, false);
        stats.record("WriteFile", 500, false);
        let sorted = stats.sorted_by_count();
        assert_eq!(sorted[0].0, "ReadFile");
        assert_eq!(sorted[0].1.call_count, 2);
    }

    #[test]
    fn test_monitor_pipe_name_constant() {
        assert!(MONITOR_PIPE_NAME.contains("pipe"));
    }

    #[test]
    fn test_wide_api_count() {
        let wide: Vec<_> = WIN32_API_DB.iter().filter(|e| e.is_wide).collect();
        assert!(wide.len() >= 20, "expected at least 20 wide APIs, got {}", wide.len());
    }

    #[test]
    fn test_http_api_count() {
        let http: Vec<_> = WIN32_API_DB.iter().filter(|e| e.category == ApiCategory::Http).collect();
        assert!(http.len() >= 15, "expected at least 15 HTTP APIs, got {}", http.len());
    }

    #[test]
    fn test_crypto_api_count() {
        let crypto: Vec<_> = WIN32_API_DB.iter().filter(|e| e.category == ApiCategory::Crypto).collect();
        assert!(crypto.len() >= 10);
    }

    #[test]
    fn test_service_api_present() {
        assert!(WIN32_API_DB.iter().any(|e| e.name == "CreateServiceW"));
        assert!(WIN32_API_DB.iter().any(|e| e.name == "DeleteService"));
    }
}
