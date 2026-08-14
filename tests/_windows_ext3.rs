
// ─── Windows x86 syscall table ────────────────────────────────────────────────

fn build_x86() -> Vec<WinNtSyscall> {
    let mut v = vec![
        nt(0x0000, "NtReadFile",                   vec![pi("FileHandle","HANDLE"), poi("Event","HANDLE"), poi("ApcRoutine","PIO_APC_ROUTINE"), poi("ApcContext","PVOID"), po("IoStatusBlock","PIO_STATUS_BLOCK"), po("Buffer","PVOID"), pi("Length","ULONG"), poi("ByteOffset","PLARGE_INTEGER"), poi("Key","PULONG")]),
        nt(0x0001, "NtWriteFile",                  vec![pi("FileHandle","HANDLE"), poi("Event","HANDLE"), poi("ApcRoutine","PIO_APC_ROUTINE"), poi("ApcContext","PVOID"), po("IoStatusBlock","PIO_STATUS_BLOCK"), pi("Buffer","PVOID"), pi("Length","ULONG"), poi("ByteOffset","PLARGE_INTEGER"), poi("Key","PULONG")]),
        nt(0x0002, "NtClose",                      vec![pi("Handle","HANDLE")]),
        nt(0x0003, "NtQueryInformationProcess",    vec![pi("ProcessHandle","HANDLE"), pi("ProcessInformationClass","PROCESSINFOCLASS"), po("ProcessInformation","PVOID"), pi("ProcessInformationLength","ULONG"), poo("ReturnLength","PULONG")]),
        nt(0x0004, "NtQueryInformationThread",     vec![pi("ThreadHandle","HANDLE"), pi("ThreadInformationClass","THREADINFOCLASS"), po("ThreadInformation","PVOID"), pi("ThreadInformationLength","ULONG"), poo("ReturnLength","PULONG")]),
        nt(0x0005, "NtSetInformationProcess",      vec![pi("ProcessHandle","HANDLE"), pi("ProcessInformationClass","PROCESSINFOCLASS"), pi("ProcessInformation","PVOID"), pi("ProcessInformationLength","ULONG")]),
        nt(0x0006, "NtSetInformationThread",       vec![pi("ThreadHandle","HANDLE"), pi("ThreadInformationClass","THREADINFOCLASS"), pi("ThreadInformation","PVOID"), pi("ThreadInformationLength","ULONG")]),
        nt(0x0007, "NtTerminateProcess",           vec![poi("ProcessHandle","HANDLE"), pi("ExitStatus","NTSTATUS")]),
        nt(0x0008, "NtTerminateThread",            vec![poi("ThreadHandle","HANDLE"), pi("ExitStatus","NTSTATUS")]),
        nt(0x0009, "NtSuspendThread",              vec![pi("ThreadHandle","HANDLE"), poo("PreviousSuspendCount","PULONG")]),
        nt(0x000A, "NtResumeThread",               vec![pi("ThreadHandle","HANDLE"), poo("PreviousSuspendCount","PULONG")]),
        nt(0x000B, "NtOpenProcess",                vec![po("ProcessHandle","PHANDLE"), pi("DesiredAccess","ACCESS_MASK"), pi("ObjectAttributes","POBJECT_ATTRIBUTES"), poi("ClientId","PCLIENT_ID")]),
        nt(0x000C, "NtAllocateVirtualMemory",      vec![pi("ProcessHandle","HANDLE"), pio("BaseAddress","PVOID *"), pi("ZeroBits","ULONG_PTR"), pio("RegionSize","PSIZE_T"), pi("AllocationType","ULONG"), pi("Protect","ULONG")]),
        nt(0x000D, "NtFreeVirtualMemory",          vec![pi("ProcessHandle","HANDLE"), pio("BaseAddress","PVOID *"), pio("RegionSize","PSIZE_T"), pi("FreeType","ULONG")]),
        nt(0x000E, "NtProtectVirtualMemory",       vec![pi("ProcessHandle","HANDLE"), pio("BaseAddress","PVOID *"), pio("RegionSize","PSIZE_T"), pi("NewProtect","ULONG"), po("OldProtect","PULONG")]),
        nt(0x000F, "NtReadVirtualMemory",          vec![pi("ProcessHandle","HANDLE"), poi("BaseAddress","PVOID"), po("Buffer","PVOID"), pi("BufferSize","SIZE_T"), poo("NumberOfBytesRead","PSIZE_T")]),
        nt(0x0010, "NtWriteVirtualMemory",         vec![pi("ProcessHandle","HANDLE"), poi("BaseAddress","PVOID"), pi("Buffer","PVOID"), pi("BufferSize","SIZE_T"), poo("NumberOfBytesWritten","PSIZE_T")]),
        nt(0x0011, "NtCreateKey",                  vec![po("KeyHandle","PHANDLE"), pi("DesiredAccess","ACCESS_MASK"), pi("ObjectAttributes","POBJECT_ATTRIBUTES"), pi("TitleIndex","ULONG"), poi("Class","PUNICODE_STRING"), pi("CreateOptions","ULONG"), poo("Disposition","PULONG")]),
        nt(0x0012, "NtOpenKey",                    vec![po("KeyHandle","PHANDLE"), pi("DesiredAccess","ACCESS_MASK"), pi("ObjectAttributes","POBJECT_ATTRIBUTES")]),
        nt(0x0013, "NtSetValueKey",                vec![pi("KeyHandle","HANDLE"), pi("ValueName","PUNICODE_STRING"), pi("TitleIndex","ULONG"), pi("Type","ULONG"), poi("Data","PVOID"), pi("DataSize","ULONG")]),
        nt(0x0014, "NtQueryValueKey",              vec![pi("KeyHandle","HANDLE"), pi("ValueName","PUNICODE_STRING"), pi("KeyValueInformationClass","KEY_VALUE_INFORMATION_CLASS"), po("KeyValueInformation","PVOID"), pi("Length","ULONG"), po("ResultLength","PULONG")]),
        nt(0x0015, "NtDeleteKey",                  vec![pi("KeyHandle","HANDLE")]),
        nt(0x0016, "NtCreateFile",                 vec![po("FileHandle","PHANDLE"), pi("DesiredAccess","ACCESS_MASK"), pi("ObjectAttributes","POBJECT_ATTRIBUTES"), po("IoStatusBlock","PIO_STATUS_BLOCK"), poi("AllocationSize","PLARGE_INTEGER"), pi("FileAttributes","ULONG"), pi("ShareAccess","ULONG"), pi("CreateDisposition","ULONG"), pi("CreateOptions","ULONG"), poi("EaBuffer","PVOID"), pi("EaLength","ULONG")]),
        nt(0x0017, "NtOpenFile",                   vec![po("FileHandle","PHANDLE"), pi("DesiredAccess","ACCESS_MASK"), pi("ObjectAttributes","POBJECT_ATTRIBUTES"), po("IoStatusBlock","PIO_STATUS_BLOCK"), pi("ShareAccess","ULONG"), pi("OpenOptions","ULONG")]),
        nt(0x0018, "NtQueryInformationFile",       vec![pi("FileHandle","HANDLE"), po("IoStatusBlock","PIO_STATUS_BLOCK"), po("FileInformation","PVOID"), pi("Length","ULONG"), pi("FileInformationClass","FILE_INFORMATION_CLASS")]),
        nt(0x0019, "NtSetInformationFile",         vec![pi("FileHandle","HANDLE"), po("IoStatusBlock","PIO_STATUS_BLOCK"), pi("FileInformation","PVOID"), pi("Length","ULONG"), pi("FileInformationClass","FILE_INFORMATION_CLASS")]),
        nt(0x001A, "NtWaitForSingleObject",        vec![pi("Handle","HANDLE"), pi("Alertable","BOOLEAN"), poi("Timeout","PLARGE_INTEGER")]),
        nt(0x001B, "NtCreateEvent",                vec![po("EventHandle","PHANDLE"), pi("DesiredAccess","ACCESS_MASK"), poi("ObjectAttributes","POBJECT_ATTRIBUTES"), pi("EventType","EVENT_TYPE"), pi("InitialState","BOOLEAN")]),
        nt(0x001C, "NtSetEvent",                   vec![pi("EventHandle","HANDLE"), poo("PreviousState","PLONG")]),
        nt(0x001D, "NtResetEvent",                 vec![pi("EventHandle","HANDLE"), poo("PreviousState","PLONG")]),
        nt(0x001E, "NtCreateMutant",               vec![po("MutantHandle","PHANDLE"), pi("DesiredAccess","ACCESS_MASK"), poi("ObjectAttributes","POBJECT_ATTRIBUTES"), pi("InitialOwner","BOOLEAN")]),
        nt(0x001F, "NtReleaseMutant",              vec![pi("MutantHandle","HANDLE"), poo("PreviousCount","PLONG")]),
        nt(0x0020, "NtQuerySystemInformation",     vec![pi("SystemInformationClass","SYSTEM_INFORMATION_CLASS"), po("SystemInformation","PVOID"), pi("SystemInformationLength","ULONG"), poo("ReturnLength","PULONG")]),
        nt(0x0021, "NtDelayExecution",             vec![pi("Alertable","BOOLEAN"), pi("DelayInterval","PLARGE_INTEGER")]),
    ];
    v.sort_by_key(|s| s.ssn);
    v
}

// ─── Malware-relevant API pattern detection ───────────────────────────────────

/// Known suspicious API call sequences (simplified patterns).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuspiciousPattern {
    /// Process injection: VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
    ProcessInjection,
    /// DLL side-loading: LoadLibraryA/W with a suspicious path
    DllSideloading,
    /// Credential harvesting: OpenProcessToken + ReadProcessMemory on lsass
    CredentialHarvesting,
    /// Ransomware crypto: CryptGenKey + loop of EncryptFile
    CryptoRansomware,
    /// Persistence via Run key
    PersistenceRunKey,
    /// Service installation persistence
    PersistenceService,
    /// Network reconnaissance: getaddrinfo + multiple connect calls
    NetworkRecon,
    /// Anti-analysis: calls to IsDebuggerPresent / NtQueryInformationProcess(debug)
    AntiAnalysis,
}

impl std::fmt::Display for SuspiciousPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessInjection    => write!(f, "PROCESS_INJECTION"),
            Self::DllSideloading      => write!(f, "DLL_SIDELOADING"),
            Self::CredentialHarvesting=> write!(f, "CREDENTIAL_HARVESTING"),
            Self::CryptoRansomware    => write!(f, "CRYPTO_RANSOMWARE"),
            Self::PersistenceRunKey   => write!(f, "PERSISTENCE_RUN_KEY"),
            Self::PersistenceService  => write!(f, "PERSISTENCE_SERVICE"),
            Self::NetworkRecon        => write!(f, "NETWORK_RECON"),
            Self::AntiAnalysis        => write!(f, "ANTI_ANALYSIS"),
        }
    }
}

/// Simple sliding-window pattern detector for API event streams.
#[derive(Debug, Default)]
pub struct PatternDetector {
    recent: Vec<String>,
    window: usize,
}

impl PatternDetector {
    #[must_use]
    pub fn new(window: usize) -> Self {
        Self { recent: Vec::new(), window }
    }

    /// Push a new API name and return any detected patterns.
    pub fn push(&mut self, api: &str) -> Vec<SuspiciousPattern> {
        self.recent.push(api.to_string());
        if self.recent.len() > self.window {
            self.recent.remove(0);
        }
        self.check()
    }

    fn check(&self) -> Vec<SuspiciousPattern> {
        let mut found = Vec::new();
        let apis: Vec<&str> = self.recent.iter().map(String::as_str).collect();

        // Process injection: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
        if self.has_all(&apis, &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]) {
            found.push(SuspiciousPattern::ProcessInjection);
        }
        // Persistence run key
        if self.has_sequence(&apis, &["RegOpenKeyExW", "RegSetValueExW"]) {
            found.push(SuspiciousPattern::PersistenceRunKey);
        }
        // Service persistence
        if apis.contains(&"CreateServiceW") || apis.contains(&"CreateServiceA") {
            found.push(SuspiciousPattern::PersistenceService);
        }
        // DLL sideloading
        if apis.contains(&"LoadLibraryW") || apis.contains(&"LoadLibraryA") {
            found.push(SuspiciousPattern::DllSideloading);
        }
        // Network recon
        if self.has_all(&apis, &["getaddrinfo", "connect"]) {
            found.push(SuspiciousPattern::NetworkRecon);
        }
        found
    }

    fn has_all(&self, apis: &[&str], targets: &[&str]) -> bool {
        targets.iter().all(|t| apis.contains(t))
    }

    fn has_sequence(&self, apis: &[&str], seq: &[&str]) -> bool {
        if seq.is_empty() { return true; }
        let mut si = 0;
        for api in apis {
            if *api == seq[si] {
                si += 1;
                if si == seq.len() { return true; }
            }
        }
        false
    }
}

// ─── Handle table ─────────────────────────────────────────────────────────────

/// Information about a Windows handle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleInfo {
    pub handle: u64,
    pub object_type: String,
    pub path: String,
    pub access: u32,
    pub pid: u32,
}

/// Per-process handle table tracker.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HandleTable {
    map: HashMap<u64, HandleInfo>,
}

impl HandleTable {
    pub fn open(&mut self, info: HandleInfo) {
        self.map.insert(info.handle, info);
    }
    pub fn close(&mut self, handle: u64) -> Option<HandleInfo> {
        self.map.remove(&handle)
    }
    pub fn get(&self, handle: u64) -> Option<&HandleInfo> {
        self.map.get(&handle)
    }
    #[must_use] pub fn len(&self) -> usize { self.map.len() }
    #[must_use] pub fn is_empty(&self) -> bool { self.map.is_empty() }
    #[must_use]
    pub fn by_type(&self, obj_type: &str) -> Vec<&HandleInfo> {
        self.map.values().filter(|h| h.object_type == obj_type).collect()
    }
}

// ─── Additional tests (part 3) ────────────────────────────────────────────────

#[cfg(test)]
mod win_ext3_tests {
    use super::*;

    #[test]
    fn test_build_x86_has_entries() {
        let v = build_x86();
        assert!(!v.is_empty());
        assert!(v.iter().any(|e| e.name == "NtCreateFile"));
    }

    #[test]
    fn test_suspicious_pattern_display() {
        assert_eq!(SuspiciousPattern::ProcessInjection.to_string(), "PROCESS_INJECTION");
        assert_eq!(SuspiciousPattern::PersistenceRunKey.to_string(), "PERSISTENCE_RUN_KEY");
    }

    #[test]
    fn test_pattern_detector_process_injection() {
        let mut d = PatternDetector::new(20);
        d.push("VirtualAllocEx");
        d.push("WriteProcessMemory");
        let p = d.push("CreateRemoteThread");
        assert!(p.contains(&SuspiciousPattern::ProcessInjection));
    }

    #[test]
    fn test_pattern_detector_service_persistence() {
        let mut d = PatternDetector::new(10);
        let p = d.push("CreateServiceW");
        assert!(p.contains(&SuspiciousPattern::PersistenceService));
    }

    #[test]
    fn test_pattern_detector_dll_sideloading() {
        let mut d = PatternDetector::new(10);
        let p = d.push("LoadLibraryA");
        assert!(p.contains(&SuspiciousPattern::DllSideloading));
    }

    #[test]
    fn test_pattern_detector_no_match() {
        let mut d = PatternDetector::new(10);
        d.push("NtClose");
        let p = d.push("NtReadFile");
        assert!(p.is_empty());
    }

    #[test]
    fn test_handle_table_open_close() {
        let mut t = HandleTable::default();
        t.open(HandleInfo { handle: 0x4, object_type: "File".to_string(), path: "C:\\test.txt".to_string(), access: 0x80000000, pid: 1 });
        assert_eq!(t.len(), 1);
        let removed = t.close(0x4);
        assert!(removed.is_some());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn test_handle_table_by_type() {
        let mut t = HandleTable::default();
        t.open(HandleInfo { handle: 0x4, object_type: "File".to_string(), path: "/a".to_string(), access: 0, pid: 1 });
        t.open(HandleInfo { handle: 0x8, object_type: "Key".to_string(), path: "HKLM\\Software".to_string(), access: 0, pid: 1 });
        t.open(HandleInfo { handle: 0xC, object_type: "File".to_string(), path: "/b".to_string(), access: 0, pid: 1 });
        let files = t.by_type("File");
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_handle_table_get() {
        let mut t = HandleTable::default();
        t.open(HandleInfo { handle: 0x10, object_type: "Thread".to_string(), path: String::new(), access: 0x1FFFFF, pid: 100 });
        let h = t.get(0x10).unwrap();
        assert_eq!(h.object_type, "Thread");
    }

    #[test]
    fn test_ntstatus_logon_failure() {
        assert_eq!(ntstatus_name(0xC000006D), Some("STATUS_LOGON_FAILURE"));
    }

    #[test]
    fn test_ntstatus_object_name_not_found() {
        assert_eq!(ntstatus_name(0xC0000034), Some("STATUS_OBJECT_NAME_NOT_FOUND"));
    }

    #[test]
    fn test_ntstatus_buffer_overflow() {
        assert_eq!(ntstatus_name(0x80000005), Some("STATUS_BUFFER_OVERFLOW"));
    }

    #[test]
    fn test_decode_alloc_large_pages() {
        let s = decode_alloc_type(0x20000000);
        assert!(s.contains("MEM_LARGE_PAGES"));
    }

    #[test]
    fn test_decode_file_access_delete() {
        let s = decode_file_access(0x00010000);
        assert!(s.contains("DELETE"));
    }

    #[test]
    fn test_win_api_db_service_count() {
        let svc: Vec<_> = WIN32_API_DB.iter().filter(|e| e.category == ApiCategory::Service).collect();
        assert!(svc.len() >= 5);
    }

    #[test]
    fn test_win_api_db_security_count() {
        let sec: Vec<_> = WIN32_API_DB.iter().filter(|e| e.category == ApiCategory::Security).collect();
        assert!(sec.len() >= 5);
    }

    #[test]
    fn test_win_taint_summary_multiple_flags() {
        let mut t = WinTaintFlags::default();
        t.injected_dll = true;
        t.spawned_remote_thread = true;
        t.loaded_crypto = true;
        let s = t.summary();
        assert!(s.contains(&"DLL_INJECTION"));
        assert!(s.contains(&"REMOTE_THREAD"));
        assert!(s.contains(&"CRYPTO_USAGE"));
    }

    #[test]
    fn test_nt_to_win32_path_unchanged() {
        let p = nt_to_win32_path("C:\\Windows\\notepad.exe");
        assert_eq!(p, "C:\\Windows\\notepad.exe");
    }

    #[test]
    fn test_version_ssn_table_has_ntreadfile() {
        let tbl = build_version_ssn_table();
        assert!(tbl.iter().any(|e| e.name == "NtReadFile"));
    }

    #[test]
    fn test_version_ssn_ntclose_win10() {
        let tbl = build_version_ssn_table();
        let entry = tbl.iter().find(|e| e.name == "NtClose").unwrap();
        let ssn = entry.ssn_for(WinVersion::Windows10).unwrap();
        assert_eq!(ssn, 0x000F);
    }
}
