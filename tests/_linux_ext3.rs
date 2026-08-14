
// ─── seccomp BPF helpers ──────────────────────────────────────────────────────

/// seccomp action values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeccompAction {
    Kill      = 0x00000000,
    KillThread= 0x00000000,
    Trap      = 0x00030000,
    Errno     = 0x00050000,
    Trace     = 0x7ff00000,
    Log       = 0x7ffc0000,
    Allow     = 0x7fff0000,
}

impl SeccompAction {
    #[must_use]
    pub fn from_u32(v: u32) -> Self {
        match v & 0xFFFF0000 {
            0x00000000 => Self::Kill,
            0x00030000 => Self::Trap,
            0x00050000 => Self::Errno,
            0x7ff00000 => Self::Trace,
            0x7ffc0000 => Self::Log,
            0x7fff0000 => Self::Allow,
            _ => Self::Kill,
        }
    }
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kill | Self::KillThread => "SECCOMP_RET_KILL",
            Self::Trap    => "SECCOMP_RET_TRAP",
            Self::Errno   => "SECCOMP_RET_ERRNO",
            Self::Trace   => "SECCOMP_RET_TRACE",
            Self::Log     => "SECCOMP_RET_LOG",
            Self::Allow   => "SECCOMP_RET_ALLOW",
        }
    }
}

// ─── procfs parser helpers ────────────────────────────────────────────────────

/// Minimal parsed entry from `/proc/<pid>/maps`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapsEntry {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub offset: u64,
    pub dev: String,
    pub inode: u64,
    pub pathname: String,
}

impl MapsEntry {
    #[must_use]
    pub fn is_executable(&self) -> bool { self.perms.contains('x') }
    #[must_use]
    pub fn is_writable(&self) -> bool   { self.perms.contains('w') }
    #[must_use]
    pub fn is_readable(&self) -> bool   { self.perms.contains('r') }
    #[must_use]
    pub fn is_private(&self) -> bool    { self.perms.contains('p') }
    #[must_use]
    pub fn is_shared(&self) -> bool     { self.perms.contains('s') }
    #[must_use]
    pub fn is_anon(&self) -> bool       { self.pathname.is_empty() || self.pathname == "[heap]" || self.pathname == "[stack]" }
    #[must_use]
    pub fn size(&self) -> u64           { self.end.saturating_sub(self.start) }
}

/// Parse the content of `/proc/<pid>/maps` (or any string with the same format).
#[must_use]
pub fn parse_proc_maps(content: &str) -> Vec<MapsEntry> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let mut parts = line.splitn(6, ' ');
        let addr_range = parts.next().unwrap_or("");
        let perms      = parts.next().unwrap_or("").to_string();
        let offset_str = parts.next().unwrap_or("0");
        let dev        = parts.next().unwrap_or("").to_string();
        let inode_str  = parts.next().unwrap_or("0");
        let pathname   = parts.next().unwrap_or("").trim().to_string();

        let mut addr_parts = addr_range.splitn(2, '-');
        let start = u64::from_str_radix(addr_parts.next().unwrap_or("0"), 16).unwrap_or(0);
        let end   = u64::from_str_radix(addr_parts.next().unwrap_or("0"), 16).unwrap_or(0);
        let offset = u64::from_str_radix(offset_str, 16).unwrap_or(0);
        let inode  = inode_str.trim().parse().unwrap_or(0);

        entries.push(MapsEntry { start, end, perms, offset, dev, inode, pathname });
    }
    entries
}

/// A parsed line from `/proc/<pid>/status`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcStatus {
    pub name: String,
    pub pid: u32,
    pub ppid: u32,
    pub state: String,
    pub uid: u32,
    pub gid: u32,
    pub vm_rss_kb: u64,
    pub vm_size_kb: u64,
    pub threads: u32,
    pub fdsize: u32,
}

/// Parse `/proc/<pid>/status` content.
#[must_use]
pub fn parse_proc_status(content: &str) -> ProcStatus {
    let mut s = ProcStatus::default();
    for line in content.lines() {
        if let Some((key, val)) = line.split_once(':') {
            let v = val.trim();
            match key.trim() {
                "Name"    => s.name = v.to_string(),
                "Pid"     => s.pid = v.parse().unwrap_or(0),
                "PPid"    => s.ppid = v.parse().unwrap_or(0),
                "State"   => s.state = v.to_string(),
                "Uid"     => s.uid = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0),
                "Gid"     => s.gid = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0),
                "VmRSS"   => s.vm_rss_kb = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0),
                "VmSize"  => s.vm_size_kb = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0),
                "Threads" => s.threads = v.parse().unwrap_or(0),
                "FDSize"  => s.fdsize = v.parse().unwrap_or(0),
                _ => {}
            }
        }
    }
    s
}

// ─── Additional tests (part 3) ────────────────────────────────────────────────

#[cfg(test)]
mod strace_ext3_tests {
    use super::*;

    #[test]
    fn test_seccomp_action_allow() {
        assert_eq!(SeccompAction::from_u32(0x7fff0000).as_str(), "SECCOMP_RET_ALLOW");
    }

    #[test]
    fn test_seccomp_action_kill() {
        assert_eq!(SeccompAction::from_u32(0).as_str(), "SECCOMP_RET_KILL");
    }

    #[test]
    fn test_seccomp_action_errno() {
        assert_eq!(SeccompAction::from_u32(0x00050001).as_str(), "SECCOMP_RET_ERRNO");
    }

    #[test]
    fn test_parse_proc_maps_single_line() {
        let content = "7f1234560000-7f1234570000 r-xp 00000000 fd:01 12345 /usr/lib/libc.so.6\n";
        let entries = parse_proc_maps(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].start, 0x7f1234560000);
        assert_eq!(entries[0].end,   0x7f1234570000);
        assert!(entries[0].is_executable());
        assert!(entries[0].is_readable());
        assert!(!entries[0].is_writable());
        assert_eq!(entries[0].pathname, "/usr/lib/libc.so.6");
    }

    #[test]
    fn test_parse_proc_maps_anon() {
        let content = "7fff00000000-7fff00010000 rwxp 00000000 00:00 0 \n";
        let entries = parse_proc_maps(content);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_executable());
        assert!(entries[0].is_writable());
        assert!(entries[0].is_anon());
    }

    #[test]
    fn test_maps_entry_size() {
        let e = MapsEntry {
            start: 0x1000, end: 0x3000,
            perms: "r-xp".to_string(),
            offset: 0, dev: "fd:01".to_string(), inode: 0, pathname: String::new(),
        };
        assert_eq!(e.size(), 0x2000);
    }

    #[test]
    fn test_parse_proc_status() {
        let content = "\
Name:\tbash\nPid:\t1234\nPPid:\t1000\nState:\tS (sleeping)\n\
Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\n\
VmRSS:\t4096 kB\nVmSize:\t32768 kB\nThreads:\t1\nFDSize:\t256\n";
        let s = parse_proc_status(content);
        assert_eq!(s.name, "bash");
        assert_eq!(s.pid, 1234);
        assert_eq!(s.ppid, 1000);
        assert_eq!(s.uid, 1000);
        assert_eq!(s.vm_rss_kb, 4096);
        assert_eq!(s.vm_size_kb, 32768);
        assert_eq!(s.threads, 1);
    }

    #[test]
    fn test_parse_proc_maps_multiple_entries() {
        let content = "\
55a000000000-55a000001000 r--p 00000000 fd:01 100 /bin/ls\n\
55a000001000-55a000002000 r-xp 00001000 fd:01 100 /bin/ls\n\
7fff00000000-7fff00010000 rw-p 00000000 00:00 0 [stack]\n";
        let entries = parse_proc_maps(content);
        assert_eq!(entries.len(), 3);
        assert!(entries[2].pathname == "[stack]");
        assert!(!entries[2].is_anon()); // [stack] is NOT anon by our definition
    }

    #[test]
    fn test_resolve_fd_negative_bad() {
        let s = resolve_fd(1, -5);
        assert!(s.contains("bad fd"));
    }

    #[test]
    fn test_resolve_fd_at_fdcwd() {
        let s = resolve_fd(1, AT_FDCWD);
        assert_eq!(s, "AT_FDCWD");
    }

    #[test]
    fn test_signal_all_core_signals() {
        for sig in 1u32..=31 {
            // All standard signals should have names
            if sig != 9 && sig != 19 { // 9=SIGKILL, 19=SIGSTOP are handled
                let _ = signal_name(sig);
            }
        }
        assert_eq!(signal_name(9), Some("SIGKILL"));
        assert_eq!(signal_name(15), Some("SIGTERM"));
        assert_eq!(signal_name(19), Some("SIGSTOP"));
    }

    #[test]
    fn test_format_open_flags_cloexec() {
        let flags = 0o2 | 0o2000000u64; // O_RDWR | O_CLOEXEC
        let s = format_open_flags(flags);
        assert!(s.contains("O_RDWR"), "got: {s}");
        assert!(s.contains("O_CLOEXEC"), "got: {s}");
    }

    #[test]
    fn test_summary_total_calls_zero() {
        let s = SyscallSummary::default();
        assert_eq!(s.total_calls(), 0);
        assert_eq!(s.total_ns(), 0);
    }

    #[test]
    fn test_summary_sorted_by_count() {
        let mut s = SyscallSummary::default();
        for _ in 0..5 { s.record("read",  100, 0); }
        for _ in 0..2 { s.record("write", 200, 0); }
        let v = s.sorted_by_count();
        assert_eq!(v[0].name, "read");
        assert_eq!(v[0].count, 5);
    }

    #[test]
    fn test_x86_64_table_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for s in X86_64_SYSCALLS {
            assert!(seen.insert(s.nr), "duplicate nr {}", s.nr);
        }
    }

    #[test]
    fn test_aarch64_table_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for s in AARCH64_SPECIFIC_SYSCALLS {
            assert!(seen.insert(s.nr), "duplicate nr {}", s.nr);
        }
    }

    #[test]
    fn test_decode_flags_clone_thread_vm() {
        let flags = 0x00010100u64; // CLONE_THREAD | CLONE_VM
        let s = decode_flags(flags, CLONE_FLAGS);
        assert!(s.contains("CLONE_VM"),     "got: {s}");
        assert!(s.contains("CLONE_THREAD"), "got: {s}");
    }

    #[test]
    fn test_at_flags_symlink_nofollow() {
        let s = decode_flags(0x100, AT_FLAGS);
        assert!(s.contains("AT_SYMLINK_NOFOLLOW"));
    }

    #[test]
    fn test_epoll_epollet() {
        let s = decode_flags(0x80000000, EPOLL_EVENTS);
        assert!(s.contains("EPOLLET"));
    }

    #[test]
    fn test_sock_nonblock() {
        let s = decode_flags(0x800, SOCK_FLAGS);
        assert!(s.contains("SOCK_NONBLOCK"));
    }

    #[test]
    fn test_ptrace_event_str() {
        assert_eq!(PtraceEvent::Clone.as_str(), "PTRACE_EVENT_CLONE");
        assert_eq!(PtraceEvent::Exit.as_str(),  "PTRACE_EVENT_EXIT");
    }

    #[test]
    fn test_seccomp_action_trace() {
        assert_eq!(SeccompAction::Trace.as_str(), "SECCOMP_RET_TRACE");
    }

    #[test]
    fn test_ioctl_tiocgwinsz() {
        assert_eq!(ioctl_name(0x5413), Some("TIOCGWINSZ"));
    }

    #[test]
    fn test_errno_einval() {
        assert_eq!(errno_name(22), Some("EINVAL"));
    }
}
