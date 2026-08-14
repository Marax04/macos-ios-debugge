
// ─── Wait status decoder ──────────────────────────────────────────────────────

/// A decoded wait status from waitpid/wait4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WaitStatus {
    /// Process exited normally with the given exit code.
    Exited(i32),
    /// Process was killed by a signal.
    Signaled { signal: u32, coredump: bool },
    /// Process was stopped by a signal.
    Stopped(u32),
    /// Process resumed (SIGCONT).
    Continued,
    /// ptrace event stop.
    PtraceEvent { signal: u32, event: u32 },
}

impl WaitStatus {
    /// Decode a raw `wstatus` value as returned by `wait4`.
    #[must_use]
    pub fn decode(wstatus: i32) -> Self {
        let w = wstatus as u32;
        if w & 0x7F == 0 {
            // Exited normally
            Self::Exited(((w >> 8) & 0xFF) as i32)
        } else if w & 0xFF == 0x7F {
            // Stopped
            let sig = (w >> 8) & 0xFF;
            let event = (w >> 16) & 0xFF;
            if event != 0 {
                Self::PtraceEvent { signal: sig, event }
            } else {
                Self::Stopped(sig)
            }
        } else if w == 0xFFFF {
            Self::Continued
        } else {
            // Signaled
            let signal = w & 0x7F;
            let coredump = (w & 0x80) != 0;
            Self::Signaled { signal, coredump }
        }
    }

    /// Format in strace style.
    #[must_use]
    pub fn format_strace(&self) -> String {
        match self {
            Self::Exited(code) => format!("{{WIFEXITED(s) && WEXITSTATUS(s) == {code}}}"),
            Self::Signaled { signal, coredump } => {
                let name = signal_name(*signal).unwrap_or("SIG?");
                let core = if *coredump { " (core dumped)" } else { "" };
                format!("{{WIFSIGNALED(s) && WTERMSIG(s) == {name}{core}}}")
            }
            Self::Stopped(sig) => {
                let name = signal_name(*sig).unwrap_or("SIG?");
                format!("{{WIFSTOPPED(s) && WSTOPSIG(s) == {name}}}")
            }
            Self::Continued => "{{WIFCONTINUED(s)}}".to_string(),
            Self::PtraceEvent { signal, event } => {
                let ev = PtraceEvent::from_u32(*event);
                format!("{{WIFSTOPPED(s) && WSTOPSIG(s) == SIGTRAP | {} << 8}}", ev.as_str())
            }
        }
    }
}

// ─── Socket option decoder ────────────────────────────────────────────────────

/// Decode a `setsockopt`/`getsockopt` level+optname pair.
#[must_use]
pub fn sockopt_name(level: i32, optname: i32) -> &'static str {
    match (level, optname) {
        (1,  1) => "SO_DEBUG",
        (1,  2) => "SO_REUSEADDR",
        (1,  3) => "SO_TYPE",
        (1,  4) => "SO_ERROR",
        (1,  5) => "SO_DONTROUTE",
        (1,  6) => "SO_BROADCAST",
        (1,  7) => "SO_SNDBUF",
        (1,  8) => "SO_RCVBUF",
        (1,  9) => "SO_KEEPALIVE",
        (1, 10) => "SO_OOBINLINE",
        (1, 11) => "SO_NO_CHECK",
        (1, 12) => "SO_PRIORITY",
        (1, 13) => "SO_LINGER",
        (1, 14) => "SO_BSDCOMPAT",
        (1, 15) => "SO_REUSEPORT",
        (1, 20) => "SO_RCVLOWAT",
        (1, 21) => "SO_SNDLOWAT",
        (1, 22) => "SO_RCVTIMEO",
        (1, 23) => "SO_SNDTIMEO",
        (1, 29) => "SO_TIMESTAMPNS",
        (1, 41) => "SO_ATTACH_BPF",
        (6,  1) => "TCP_NODELAY",
        (6,  2) => "TCP_MAXSEG",
        (6,  3) => "TCP_CORK",
        (6,  4) => "TCP_KEEPIDLE",
        (6,  5) => "TCP_KEEPINTVL",
        (6,  6) => "TCP_KEEPCNT",
        (6,  7) => "TCP_SYNCNT",
        (6,  8) => "TCP_LINGER2",
        (6,  9) => "TCP_DEFER_ACCEPT",
        (6, 10) => "TCP_WINDOW_CLAMP",
        (6, 11) => "TCP_INFO",
        (6, 12) => "TCP_QUICKACK",
        (6, 23) => "TCP_FASTOPEN",
        (6, 24) => "TCP_TIMESTAMP",
        (6, 25) => "TCP_NOTSENT_LOWAT",
        (17, 1) => "UDP_CORK",
        (17, 100) => "UDP_SEGMENT",
        _       => "UNKNOWN_SOCKOPT",
    }
}

// ─── Address family name ──────────────────────────────────────────────────────

#[must_use]
pub fn af_name(family: u16) -> &'static str {
    match family {
        0  => "AF_UNSPEC",
        1  => "AF_UNIX",
        2  => "AF_INET",
        3  => "AF_AX25",
        4  => "AF_IPX",
        5  => "AF_APPLETALK",
        6  => "AF_NETROM",
        7  => "AF_BRIDGE",
        8  => "AF_ATMPVC",
        9  => "AF_X25",
        10 => "AF_INET6",
        11 => "AF_ROSE",
        12 => "AF_DECnet",
        13 => "AF_NETBEUI",
        14 => "AF_SECURITY",
        15 => "AF_KEY",
        16 => "AF_NETLINK",
        17 => "AF_PACKET",
        18 => "AF_ASH",
        19 => "AF_ECONET",
        20 => "AF_ATMSVC",
        22 => "AF_SNA",
        23 => "AF_IRDA",
        24 => "AF_PPPOX",
        25 => "AF_WANPIPE",
        26 => "AF_LLC",
        29 => "AF_CAN",
        30 => "AF_TIPC",
        31 => "AF_BLUETOOTH",
        32 => "AF_IUCV",
        33 => "AF_RXRPC",
        34 => "AF_ISDN",
        35 => "AF_PHONET",
        36 => "AF_IEEE802154",
        37 => "AF_CAIF",
        38 => "AF_ALG",
        39 => "AF_NFC",
        40 => "AF_VSOCK",
        _  => "AF_UNKNOWN",
    }
}

// ─── JSON event log writer ────────────────────────────────────────────────────

/// Buffer collecting JSON-formatted syscall event lines.
#[derive(Debug, Default)]
pub struct JsonEventLog {
    lines: Vec<String>,
}

impl JsonEventLog {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Append an event as a JSON line.
    pub fn append(&mut self, event: &SyscallEvent) {
        match event.to_json() {
            Ok(j) => self.lines.push(j),
            Err(e) => self.lines.push(format!("{{\"error\":{e:?}}}"))
        }
    }

    /// Return the full log as a NDJSON string.
    #[must_use]
    pub fn to_ndjson(&self) -> String {
        self.lines.join("\n")
    }

    /// Number of events recorded.
    #[must_use]
    pub fn len(&self) -> usize { self.lines.len() }

    /// Returns `true` if no events have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.lines.is_empty() }

    /// Clear all events.
    pub fn clear(&mut self) { self.lines.clear(); }
}

// ─── CSV event log writer ─────────────────────────────────────────────────────

/// Buffer collecting CSV-formatted syscall event rows.
#[derive(Debug)]
pub struct CsvEventLog {
    rows: Vec<String>,
}

impl CsvEventLog {
    #[must_use]
    pub fn new() -> Self {
        let header = "timestamp_ns,pid,tid,name,retval,elapsed_ns".to_string();
        Self { rows: vec![header] }
    }

    /// Append an event as a CSV row.
    pub fn append(&mut self, event: &SyscallEvent) {
        self.rows.push(event.to_csv_row());
    }

    /// Return the full CSV as a string.
    #[must_use]
    pub fn to_csv(&self) -> String {
        self.rows.join("\n")
    }

    /// Number of data rows (excluding header).
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.rows.len().saturating_sub(1)
    }
}

impl Default for CsvEventLog {
    fn default() -> Self { Self::new() }
}

// ─── Additional tests (part 4) ────────────────────────────────────────────────

#[cfg(test)]
mod strace_ext4_tests {
    use super::*;

    #[test]
    fn test_wait_status_exited_0() {
        let ws = WaitStatus::decode(0); // WIFEXITED(0) = true, WEXITSTATUS = 0
        match ws {
            WaitStatus::Exited(c) => assert_eq!(c, 0),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_wait_status_exited_1() {
        let ws = WaitStatus::decode(0x0100); // exit code = 1
        match ws {
            WaitStatus::Exited(c) => assert_eq!(c, 1),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_wait_status_signaled_sigsegv() {
        let ws = WaitStatus::decode(11); // WIFSIGNALED, signal=SIGSEGV
        match ws {
            WaitStatus::Signaled { signal, coredump } => {
                assert_eq!(signal, 11);
                assert!(!coredump);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_wait_status_stopped() {
        let ws = WaitStatus::decode(0x137F); // stopped by signal 19
        match ws {
            WaitStatus::Stopped(s) => assert_eq!(s, 19),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_wait_status_format_exited() {
        let s = WaitStatus::Exited(0).format_strace();
        assert!(s.contains("WIFEXITED"));
    }

    #[test]
    fn test_wait_status_format_signaled() {
        let s = WaitStatus::Signaled { signal: 11, coredump: false }.format_strace();
        assert!(s.contains("WIFSIGNALED") && s.contains("SIGSEGV"));
    }

    #[test]
    fn test_wait_status_format_stopped() {
        let s = WaitStatus::Stopped(19).format_strace();
        assert!(s.contains("WIFSTOPPED") && s.contains("SIGSTOP"));
    }

    #[test]
    fn test_sockopt_tcp_nodelay() {
        assert_eq!(sockopt_name(6, 1), "TCP_NODELAY");
    }

    #[test]
    fn test_sockopt_so_keepalive() {
        assert_eq!(sockopt_name(1, 9), "SO_KEEPALIVE");
    }

    #[test]
    fn test_sockopt_unknown() {
        assert_eq!(sockopt_name(99, 99), "UNKNOWN_SOCKOPT");
    }

    #[test]
    fn test_af_name_inet() {
        assert_eq!(af_name(2), "AF_INET");
    }

    #[test]
    fn test_af_name_inet6() {
        assert_eq!(af_name(10), "AF_INET6");
    }

    #[test]
    fn test_af_name_unix() {
        assert_eq!(af_name(1), "AF_UNIX");
    }

    #[test]
    fn test_af_name_packet() {
        assert_eq!(af_name(17), "AF_PACKET");
    }

    #[test]
    fn test_af_name_unknown() {
        assert_eq!(af_name(200), "AF_UNKNOWN");
    }

    #[test]
    fn test_json_event_log_append() {
        let mut log = JsonEventLog::new();
        let ev = SyscallEvent {
            timestamp_ns: 100, pid: 1, tid: 1, nr: 0,
            name: "read".to_string(), args: vec![],
            retval: DecodedArg::Int(10), elapsed_ns: 50, is_entry: false,
        };
        log.append(&ev);
        assert_eq!(log.len(), 1);
        assert!(log.to_ndjson().contains("read"));
    }

    #[test]
    fn test_json_event_log_clear() {
        let mut log = JsonEventLog::new();
        let ev = SyscallEvent {
            timestamp_ns: 0, pid: 1, tid: 1, nr: 1,
            name: "write".to_string(), args: vec![],
            retval: DecodedArg::Int(4), elapsed_ns: 0, is_entry: false,
        };
        log.append(&ev);
        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn test_csv_event_log_header() {
        let log = CsvEventLog::new();
        assert_eq!(log.row_count(), 0);
        assert!(log.to_csv().starts_with("timestamp_ns,pid,tid,name,retval,elapsed_ns"));
    }

    #[test]
    fn test_csv_event_log_append() {
        let mut log = CsvEventLog::new();
        let ev = SyscallEvent {
            timestamp_ns: 123, pid: 2, tid: 2, nr: 1,
            name: "write".to_string(), args: vec![],
            retval: DecodedArg::Int(8), elapsed_ns: 77, is_entry: false,
        };
        log.append(&ev);
        assert_eq!(log.row_count(), 1);
        assert!(log.to_csv().contains("write"));
    }

    #[test]
    fn test_x86_64_exit_group_nr231() {
        assert_eq!(x86_64_syscall_name(231), Some("exit_group"));
    }

    #[test]
    fn test_x86_64_getrandom_nr318() {
        assert_eq!(x86_64_syscall_name(318), Some("getrandom"));
    }

    #[test]
    fn test_x86_64_bpf_nr321() {
        assert_eq!(x86_64_syscall_name(321), Some("bpf"));
    }

    #[test]
    fn test_x86_64_statx_nr332() {
        assert_eq!(x86_64_syscall_name(332), Some("statx"));
    }

    #[test]
    fn test_output_format_variants() {
        // Just ensure the variants exist and are copyable
        let _f1 = OutputFormat::Strace;
        let _f2 = OutputFormat::Json;
        let _f3 = OutputFormat::Csv;
    }

    #[test]
    fn test_fd_table_get_mut() {
        let mut t = FdTable::default();
        t.insert(10, FdInfo::file("/dev/urandom", 0));
        let info = t.get_mut(10).unwrap();
        info.offset = 42;
        assert_eq!(t.get(10).unwrap().offset, 42);
    }

    #[test]
    fn test_fd_table_all_sorted() {
        let mut t = FdTable::default();
        t.insert(5, FdInfo::file("/a", 0));
        t.insert(1, FdInfo::file("/b", 0));
        t.insert(3, FdInfo::file("/c", 0));
        let all = t.all();
        assert_eq!(all[0].0, 1);
        assert_eq!(all[1].0, 3);
        assert_eq!(all[2].0, 5);
    }
}
