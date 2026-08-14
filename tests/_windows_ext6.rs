
// ─── Windows process ancestry tracker ────────────────────────────────────────

/// Entry in a process ancestry chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub command_line: String,
    pub create_time_ns: u64,
    pub integrity_level: IntegrityLevel,
}

/// Windows integrity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IntegrityLevel {
    Untrusted = 0,
    Low       = 1,
    Medium    = 2,
    High      = 3,
    System    = 4,
}

impl std::fmt::Display for IntegrityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Untrusted => write!(f, "Untrusted"),
            Self::Low       => write!(f, "Low"),
            Self::Medium    => write!(f, "Medium"),
            Self::High      => write!(f, "High"),
            Self::System    => write!(f, "System"),
        }
    }
}

/// Simple in-memory process tree tracker.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessTree {
    pub processes: Vec<ProcessEntry>,
}

impl ProcessTree {
    pub fn add(&mut self, entry: ProcessEntry) {
        self.processes.push(entry);
    }

    pub fn remove(&mut self, pid: u32) {
        self.processes.retain(|p| p.pid != pid);
    }

    #[must_use]
    pub fn find(&self, pid: u32) -> Option<&ProcessEntry> {
        self.processes.iter().find(|p| p.pid == pid)
    }

    /// Return all direct children of `ppid`.
    #[must_use]
    pub fn children(&self, ppid: u32) -> Vec<&ProcessEntry> {
        self.processes.iter().filter(|p| p.ppid == ppid).collect()
    }

    /// Return the full ancestry chain for `pid` (from pid up to root).
    #[must_use]
    pub fn ancestry(&self, pid: u32) -> Vec<&ProcessEntry> {
        let mut chain = Vec::new();
        let mut current = pid;
        let mut seen = std::collections::HashSet::new();
        loop {
            if !seen.insert(current) { break; }
            if let Some(e) = self.find(current) {
                chain.push(e);
                current = e.ppid;
            } else {
                break;
            }
        }
        chain
    }
}

// ─── Named pipe IPC model (for injected DLL → monitor) ───────────────────────

/// Direction of a named pipe operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipeDirection { Inbound, Outbound, Duplex }

/// Metadata for a named pipe handle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedPipeInfo {
    pub name: String,
    pub direction: PipeDirection,
    pub max_instances: u32,
    pub out_buf_size: u32,
    pub in_buf_size: u32,
    pub default_timeout_ms: u32,
}

impl NamedPipeInfo {
    #[must_use]
    pub fn monitor_pipe() -> Self {
        Self {
            name: MONITOR_PIPE_NAME.to_string(),
            direction: PipeDirection::Inbound,
            max_instances: 16,
            out_buf_size: 65536,
            in_buf_size: 65536,
            default_timeout_ms: 5000,
        }
    }
}

// ─── Additional tests (part 6) ────────────────────────────────────────────────

#[cfg(test)]
mod win_ext6_tests {
    use super::*;

    #[test]
    fn test_integrity_level_ordering() {
        assert!(IntegrityLevel::System > IntegrityLevel::High);
        assert!(IntegrityLevel::High   > IntegrityLevel::Medium);
        assert!(IntegrityLevel::Medium > IntegrityLevel::Low);
    }

    #[test]
    fn test_integrity_level_display() {
        assert_eq!(IntegrityLevel::System.to_string(), "System");
        assert_eq!(IntegrityLevel::Medium.to_string(), "Medium");
    }

    #[test]
    fn test_process_tree_add_find() {
        let mut tree = ProcessTree::default();
        tree.add(ProcessEntry { pid: 4, ppid: 0, name: "System".to_string(), command_line: String::new(), create_time_ns: 0, integrity_level: IntegrityLevel::System });
        tree.add(ProcessEntry { pid: 100, ppid: 4, name: "svchost.exe".to_string(), command_line: String::new(), create_time_ns: 0, integrity_level: IntegrityLevel::System });
        assert_eq!(tree.find(100).unwrap().name, "svchost.exe");
    }

    #[test]
    fn test_process_tree_children() {
        let mut tree = ProcessTree::default();
        tree.add(ProcessEntry { pid: 1, ppid: 0, name: "root".to_string(), command_line: String::new(), create_time_ns: 0, integrity_level: IntegrityLevel::High });
        tree.add(ProcessEntry { pid: 2, ppid: 1, name: "child1".to_string(), command_line: String::new(), create_time_ns: 0, integrity_level: IntegrityLevel::Medium });
        tree.add(ProcessEntry { pid: 3, ppid: 1, name: "child2".to_string(), command_line: String::new(), create_time_ns: 0, integrity_level: IntegrityLevel::Medium });
        let children = tree.children(1);
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn test_process_tree_ancestry() {
        let mut tree = ProcessTree::default();
        tree.add(ProcessEntry { pid: 1, ppid: 0, name: "a".to_string(), command_line: String::new(), create_time_ns: 0, integrity_level: IntegrityLevel::High });
        tree.add(ProcessEntry { pid: 2, ppid: 1, name: "b".to_string(), command_line: String::new(), create_time_ns: 0, integrity_level: IntegrityLevel::Medium });
        tree.add(ProcessEntry { pid: 3, ppid: 2, name: "c".to_string(), command_line: String::new(), create_time_ns: 0, integrity_level: IntegrityLevel::Low });
        let chain = tree.ancestry(3);
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].pid, 3);
        assert_eq!(chain[1].pid, 2);
        assert_eq!(chain[2].pid, 1);
    }

    #[test]
    fn test_process_tree_remove() {
        let mut tree = ProcessTree::default();
        tree.add(ProcessEntry { pid: 42, ppid: 0, name: "test".to_string(), command_line: String::new(), create_time_ns: 0, integrity_level: IntegrityLevel::Medium });
        assert!(tree.find(42).is_some());
        tree.remove(42);
        assert!(tree.find(42).is_none());
    }

    #[test]
    fn test_named_pipe_info_monitor() {
        let p = NamedPipeInfo::monitor_pipe();
        assert!(p.name.contains("pipe"));
        assert_eq!(p.direction, PipeDirection::Inbound);
        assert_eq!(p.max_instances, 16);
    }

    #[test]
    fn test_win_event_record_level_info() {
        let r = WinEventRecord {
            event_id: 4624, provider: "Security".to_string(), channel: "Security".to_string(),
            level: WinEventLevel::Info, timestamp_ns: 0, pid: 4, tid: 8,
            message: "An account was successfully logged on.".to_string(), keywords: 0,
        };
        assert_eq!(r.event_id, 4624);
        assert_eq!(r.level, WinEventLevel::Info);
    }

    #[test]
    fn test_is_persistence_reg_key_appinit() {
        assert!(is_persistence_registry_key("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppInit_DLLs"));
    }

    #[test]
    fn test_is_persistence_reg_key_winlogon() {
        assert!(is_persistence_registry_key("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit"));
    }

    #[test]
    fn test_nt_to_win32_reg_path_passthrough() {
        let p = nt_to_win32_reg_path("HKLM\\SOFTWARE\\test");
        assert_eq!(p, "HKLM\\SOFTWARE\\test");
    }

    #[test]
    fn test_winsock_error_host_not_found() {
        assert_eq!(winsock_error_name(11001), Some("WSAHOST_NOT_FOUND"));
    }

    #[test]
    fn test_winsock_error_wsaeinval() {
        assert_eq!(winsock_error_name(10022), Some("WSAEINVAL"));
    }

    #[test]
    fn test_privileges_contains_debug() {
        assert!(WINDOWS_PRIVILEGES.contains(&"SeDebugPrivilege"));
    }

    #[test]
    fn test_privileges_contains_tcb() {
        assert!(WINDOWS_PRIVILEGES.contains(&"SeTcbPrivilege"));
    }

    #[test]
    fn test_all_dangerous_privileges_in_list() {
        let dangerous = ["SeDebugPrivilege", "SeImpersonatePrivilege", "SeTcbPrivilege"];
        for p in dangerous {
            assert!(is_dangerous_privilege(p), "{p} should be dangerous");
        }
    }

    #[test]
    fn test_win_api_db_ntdll_entries() {
        let ntdll: Vec<_> = WIN32_API_DB.iter().filter(|e| e.module == "ntdll.dll").collect();
        assert!(ntdll.len() >= 30, "expected >= 30 ntdll entries, got {}", ntdll.len());
    }

    #[test]
    fn test_win_api_db_winhttp_entries() {
        let wh: Vec<_> = WIN32_API_DB.iter().filter(|e| e.module == "winhttp.dll").collect();
        assert!(wh.len() >= 5, "expected >= 5 winhttp entries, got {}", wh.len());
    }

    #[test]
    fn test_win_syscall_resolver_ssn_for_version() {
        let r = WinSyscallResolver::new();
        let ssn = r.ssn_for_version("NtCreateFile", WinVersion::Windows10);
        assert!(ssn.is_some(), "expected SSN for NtCreateFile on Win10");
    }

    #[test]
    fn test_categorize_nt_file() {
        use super::categorize_nt;
        assert_eq!(categorize_nt("NtCreateFile"), NtSyscallCategory::FileSystem);
    }

    #[test]
    fn test_categorize_nt_registry() {
        use super::categorize_nt;
        assert_eq!(categorize_nt("NtCreateKey"), NtSyscallCategory::Registry);
    }

    #[test]
    fn test_categorize_nt_process() {
        use super::categorize_nt;
        assert_eq!(categorize_nt("NtOpenProcess"), NtSyscallCategory::Process);
    }

    #[test]
    fn test_categorize_nt_memory() {
        use super::categorize_nt;
        assert_eq!(categorize_nt("NtAllocateVirtualMemory"), NtSyscallCategory::Memory);
    }
}
