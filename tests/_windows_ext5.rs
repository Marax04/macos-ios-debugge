
// ─── Windows token privilege constants ────────────────────────────────────────

/// Well-known Windows privilege names.
pub static WINDOWS_PRIVILEGES: &[&str] = &[
    "SeAssignPrimaryTokenPrivilege",
    "SeAuditPrivilege",
    "SeBackupPrivilege",
    "SeChangeNotifyPrivilege",
    "SeCreateGlobalPrivilege",
    "SeCreatePagefilePrivilege",
    "SeCreatePermanentPrivilege",
    "SeCreateSymbolicLinkPrivilege",
    "SeCreateTokenPrivilege",
    "SeDebugPrivilege",
    "SeEnableDelegationPrivilege",
    "SeImpersonatePrivilege",
    "SeIncreaseBasePriorityPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeIncreaseWorkingSetPrivilege",
    "SeLoadDriverPrivilege",
    "SeLockMemoryPrivilege",
    "SeMachineAccountPrivilege",
    "SeManageVolumePrivilege",
    "SeNetworkLogonRight",
    "SeProfileSingleProcessPrivilege",
    "SeRelabelPrivilege",
    "SeRemoteInteractiveLogonRight",
    "SeRemoteShutdownPrivilege",
    "SeRestorePrivilege",
    "SeSecurityPrivilege",
    "SeShutdownPrivilege",
    "SeSyncAgentPrivilege",
    "SeSystemEnvironmentPrivilege",
    "SeSystemProfilePrivilege",
    "SeSystemtimePrivilege",
    "SeTakeOwnershipPrivilege",
    "SeTcbPrivilege",
    "SeTimeZonePrivilege",
    "SeTrustedCredManAccessPrivilege",
    "SeUndockPrivilege",
    "SeUnsolicitedInputPrivilege",
];

/// Return `true` if a privilege name is considered high-risk for abuse.
#[must_use]
pub fn is_dangerous_privilege(name: &str) -> bool {
    matches!(name,
        "SeDebugPrivilege"
        | "SeImpersonatePrivilege"
        | "SeTcbPrivilege"
        | "SeCreateTokenPrivilege"
        | "SeTakeOwnershipPrivilege"
        | "SeLoadDriverPrivilege"
        | "SeRestorePrivilege"
        | "SeBackupPrivilege"
        | "SeAssignPrimaryTokenPrivilege"
    )
}

// ─── Windows registry path helpers ────────────────────────────────────────────

/// Convert an NT registry key path to a Win32 path.
#[must_use]
pub fn nt_to_win32_reg_path(nt_path: &str) -> String {
    let p = nt_path.trim_start_matches('\\');
    if let Some(rest) = p.strip_prefix("REGISTRY\\MACHINE\\") {
        return format!("HKLM\\{rest}");
    }
    if let Some(rest) = p.strip_prefix("REGISTRY\\USER\\") {
        return format!("HKU\\{rest}");
    }
    if let Some(rest) = p.strip_prefix("REGISTRY\\") {
        return rest.to_string();
    }
    nt_path.to_string()
}

/// Return `true` if the registry key path is a known persistence location.
#[must_use]
pub fn is_persistence_registry_key(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("\\run\\")
        || p.contains("\\runonce\\")
        || p.contains("\\runonceex\\")
        || p.contains("\\services\\")
        || p.contains("\\winlogon\\")
        || p.contains("\\image file execution options\\")
        || p.contains("\\appinit_dlls")
        || p.contains("\\browser helper objects\\")
        || p.contains("\\shell service object delay load")
        || p.contains("\\wbem\\")
        || p.contains("\\scheduled tasks")
}

// ─── Windows socket error codes ───────────────────────────────────────────────

/// Decode a Winsock error code to a name.
#[must_use]
pub fn winsock_error_name(code: i32) -> Option<&'static str> {
    match code {
        6       => Some("WSA_INVALID_HANDLE"),
        8       => Some("WSA_NOT_ENOUGH_MEMORY"),
        87      => Some("WSA_INVALID_PARAMETER"),
        258     => Some("WSA_WAIT_TIMEOUT"),
        995     => Some("WSA_OPERATION_ABORTED"),
        996     => Some("WSA_IO_INCOMPLETE"),
        997     => Some("WSA_IO_PENDING"),
        10004   => Some("WSAEINTR"),
        10009   => Some("WSAEBADF"),
        10013   => Some("WSAEACCES"),
        10014   => Some("WSAEFAULT"),
        10022   => Some("WSAEINVAL"),
        10024   => Some("WSAEMFILE"),
        10035   => Some("WSAEWOULDBLOCK"),
        10036   => Some("WSAEINPROGRESS"),
        10037   => Some("WSAEALREADY"),
        10038   => Some("WSAENOTSOCK"),
        10039   => Some("WSAEDESTADDRREQ"),
        10040   => Some("WSAEMSGSIZE"),
        10041   => Some("WSAEPROTOTYPE"),
        10042   => Some("WSAENOPROTOOPT"),
        10043   => Some("WSAEPROTONOSUPPORT"),
        10044   => Some("WSAESOCKTNOSUPPORT"),
        10045   => Some("WSAEOPNOTSUPP"),
        10046   => Some("WSAEPFNOSUPPORT"),
        10047   => Some("WSAEAFNOSUPPORT"),
        10048   => Some("WSAEADDRINUSE"),
        10049   => Some("WSAEADDRNOTAVAIL"),
        10050   => Some("WSAENETDOWN"),
        10051   => Some("WSAENETUNREACH"),
        10052   => Some("WSAENETRESET"),
        10053   => Some("WSAECONNABORTED"),
        10054   => Some("WSAECONNRESET"),
        10055   => Some("WSAENOBUFS"),
        10056   => Some("WSAEISCONN"),
        10057   => Some("WSAENOTCONN"),
        10058   => Some("WSAESHUTDOWN"),
        10060   => Some("WSAETIMEDOUT"),
        10061   => Some("WSAECONNREFUSED"),
        10064   => Some("WSAEHOSTDOWN"),
        10065   => Some("WSAEHOSTUNREACH"),
        10067   => Some("WSAEPROCLIM"),
        10091   => Some("WSASYSNOTREADY"),
        10092   => Some("WSAVERNOTSUPPORTED"),
        10093   => Some("WSANOTINITIALISED"),
        10101   => Some("WSAEDISCON"),
        11001   => Some("WSAHOST_NOT_FOUND"),
        11002   => Some("WSATRY_AGAIN"),
        11003   => Some("WSANO_RECOVERY"),
        11004   => Some("WSANO_DATA"),
        _       => None,
    }
}

// ─── Additional tests (part 5) ────────────────────────────────────────────────

#[cfg(test)]
mod win_ext5_tests {
    use super::*;

    #[test]
    fn test_privileges_list_not_empty() {
        assert!(!WINDOWS_PRIVILEGES.is_empty());
        assert!(WINDOWS_PRIVILEGES.len() >= 30);
    }

    #[test]
    fn test_is_dangerous_privilege_debug() {
        assert!(is_dangerous_privilege("SeDebugPrivilege"));
    }

    #[test]
    fn test_is_dangerous_privilege_impersonate() {
        assert!(is_dangerous_privilege("SeImpersonatePrivilege"));
    }

    #[test]
    fn test_is_dangerous_privilege_benign() {
        assert!(!is_dangerous_privilege("SeShutdownPrivilege"));
    }

    #[test]
    fn test_nt_to_win32_reg_path_hklm() {
        let p = nt_to_win32_reg_path("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft");
        assert_eq!(p, "HKLM\\SOFTWARE\\Microsoft");
    }

    #[test]
    fn test_nt_to_win32_reg_path_hku() {
        let p = nt_to_win32_reg_path("\\REGISTRY\\USER\\S-1-5-21\\Software");
        assert_eq!(p, "HKU\\S-1-5-21\\Software");
    }

    #[test]
    fn test_is_persistence_reg_key_run() {
        assert!(is_persistence_registry_key("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\malware"));
    }

    #[test]
    fn test_is_persistence_reg_key_services() {
        assert!(is_persistence_registry_key("HKLM\\SYSTEM\\CurrentControlSet\\Services\\evil"));
    }

    #[test]
    fn test_is_persistence_reg_key_benign() {
        assert!(!is_persistence_registry_key("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\notepad.exe"));
    }

    #[test]
    fn test_winsock_error_connrefused() {
        assert_eq!(winsock_error_name(10061), Some("WSAECONNREFUSED"));
    }

    #[test]
    fn test_winsock_error_timedout() {
        assert_eq!(winsock_error_name(10060), Some("WSAETIMEDOUT"));
    }

    #[test]
    fn test_winsock_error_addrinuse() {
        assert_eq!(winsock_error_name(10048), Some("WSAEADDRINUSE"));
    }

    #[test]
    fn test_winsock_error_unknown() {
        assert!(winsock_error_name(99999).is_none());
    }

    #[test]
    fn test_win_api_db_loader_entries() {
        let loader: Vec<_> = WIN32_API_DB.iter().filter(|e| e.category == ApiCategory::Loader).collect();
        assert!(loader.len() >= 4);
        assert!(loader.iter().any(|e| e.name == "GetProcAddress"));
    }

    #[test]
    fn test_win_api_db_process_entries() {
        let procs: Vec<_> = WIN32_API_DB.iter().filter(|e| e.category == ApiCategory::Process).collect();
        assert!(procs.iter().any(|e| e.name == "CreateProcessW"));
        assert!(procs.iter().any(|e| e.name == "TerminateProcess"));
    }

    #[test]
    fn test_win_api_db_total_count() {
        assert!(WIN32_API_DB.len() >= 150, "expected >= 150 entries, got {}", WIN32_API_DB.len());
    }

    #[test]
    fn test_hook_analysis_is_hooked_false() {
        let h = HookAnalysis { name: "NtReadFile".to_string(), ssn: 0, kind: HookKind::Clean, stub_bytes: vec![] };
        assert!(!h.is_hooked());
    }

    #[test]
    fn test_hook_analysis_is_hooked_true() {
        let h = HookAnalysis { name: "NtReadFile".to_string(), ssn: 0, kind: HookKind::InlineHook, stub_bytes: vec![0xE9] };
        assert!(h.is_hooked());
    }

    #[test]
    fn test_object_attributes_flags() {
        let mut oa = ObjectAttributes::new("\\Device\\Test");
        oa.attributes = 0x202; // OBJ_INHERIT | OBJ_KERNEL_HANDLE
        assert!(oa.is_inherit());
        assert!(oa.is_kernel_handle());
        assert!(!oa.is_open_if());
    }

    #[test]
    fn test_memory_basic_information_states() {
        let mbi = MemoryBasicInformation {
            base_address: 0x1000, allocation_base: 0x1000,
            allocation_protect: 0x04, region_size: 0x1000,
            state: 0x1000, protect: 0x40, mem_type: 0x20000,
        };
        assert!(mbi.is_committed());
        assert!(mbi.is_rwx());
        assert!(!mbi.is_free());
        assert_eq!(mbi.type_name(), "MEM_PRIVATE");
    }

    #[test]
    fn test_peb_debug_flags() {
        let peb = Peb {
            image_base: 0, ldr: 0, process_parameters: 0,
            being_debugged: true, nt_global_flags: 0x70, heap_count: 1,
        };
        assert!(peb.is_debugged());
        assert!(peb.has_heap_debug_flags());
    }

    #[test]
    fn test_unicode_string_from_str() {
        let us = UnicodeString::from_str("hello");
        assert_eq!(us.decoded, "hello");
        assert_eq!(us.length, 10); // 5 chars * 2 bytes
    }

    #[test]
    fn test_win_version_ssn_for() {
        let tbl = build_version_ssn_table();
        let e = tbl.iter().find(|e| e.name == "NtAllocateVirtualMemory").unwrap();
        assert_eq!(e.ssn_for(WinVersion::Windows10), Some(0x0018));
        assert_eq!(e.ssn_for(WinVersion::WindowsXP),  Some(0x0011));
    }
}
