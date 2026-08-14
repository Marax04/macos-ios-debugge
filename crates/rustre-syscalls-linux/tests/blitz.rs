//! Exhaustive integration tests targeting public APIs of rustre-syscalls-linux.
//! Goal: surface bugs in parsing, decoding, edge cases, and state tracking.

use rustre_syscalls::SyscallArch;
use rustre_syscalls_linux::*;
use rustre_syscalls_linux::linux_syscall_table_x86_64 as table;
use rustre_syscalls_linux::seccomp_profile_generator as scg;
use rustre_syscalls_linux::syscall_intercept as si;
use rustre_syscalls_linux::syscall_statistics as ss;
use rustre_syscalls_linux::ptrace_syscall_tracer as pst;

// ─── Resolver / DB ─────────────────────────────────────────────────────────

#[test]
fn resolver_lookup_read_x86_64() {
    let r = SyscallResolver::new();
    let s = r.lookup(SyscallArch::X86_64, 0).unwrap();
    assert_eq!(s.name, "read");
}

#[test]
fn resolver_lookup_missing_returns_none() {
    let r = SyscallResolver::new();
    assert!(r.lookup(SyscallArch::X86_64, 9_999_999).is_none());
}

#[test]
fn resolver_lookup_by_name() {
    let r = SyscallResolver::new();
    assert_eq!(r.lookup_by_name(SyscallArch::X86_64, "execve").unwrap().number, 59);
}

#[test]
fn resolver_all_for_arch_nonempty() {
    let r = SyscallResolver::new();
    assert!(!r.all_for_arch(SyscallArch::X86_64).is_empty());
    assert!(!r.all_for_arch(SyscallArch::Arm64).is_empty());
    assert!(!r.all_for_arch(SyscallArch::Arm32).is_empty());
    assert!(!r.all_for_arch(SyscallArch::X86).is_empty());
}

#[test]
fn resolver_all_for_arch_unsupported_empty() {
    let r = SyscallResolver::new();
    assert!(r.all_for_arch(SyscallArch::Mips).is_empty());
    assert!(r.all_for_arch(SyscallArch::Riscv64).is_empty());
}

#[test]
fn db_arch_count_consistent_with_slice() {
    let db = LinuxSyscallDb::new();
    let n = db.arch_count(SyscallArch::X86_64);
    assert_eq!(n, db.all_for_arch(SyscallArch::X86_64).unwrap().len());
}

#[test]
fn db_lookup_sorted_by_number() {
    let db = LinuxSyscallDb::new();
    let v = db.all_for_arch(SyscallArch::X86_64).unwrap();
    for win in v.windows(2) {
        assert!(win[0].number <= win[1].number);
    }
}

// ─── SyscallParam / LinuxSyscall constructors ─────────────────────────────

#[test]
fn syscall_param_new() {
    let p = SyscallParam::new("fd", "int");
    assert_eq!(p.name, "fd");
    assert_eq!(p.ty, "int");
}

#[test]
fn linux_syscall_new_round_trip_json() {
    let s = LinuxSyscall::new(123, "foo", vec![SyscallParam::new("a", "int")], "long");
    let j = serde_json::to_string(&s).unwrap();
    let d: LinuxSyscall = serde_json::from_str(&j).unwrap();
    assert_eq!(d.number, 123);
    assert_eq!(d.name, "foo");
    assert_eq!(d.params.len(), 1);
}

// ─── Category / severity ───────────────────────────────────────────────────

#[test]
fn category_execve_is_process() {
    assert_eq!(syscall_category("execve"), SyscallCategory::Process);
}

#[test]
fn category_unknown_is_unknown() {
    assert_eq!(syscall_category("xyzzy_does_not_exist"), SyscallCategory::Unknown);
}

#[test]
fn category_display_strings() {
    assert_eq!(SyscallCategory::FileSystem.to_string(), "filesystem");
    assert_eq!(SyscallCategory::Memory.to_string(), "memory");
    assert_eq!(SyscallCategory::Unknown.to_string(), "unknown");
}

#[test]
fn severity_ordering() {
    assert!(SecuritySeverity::Critical > SecuritySeverity::High);
    assert!(SecuritySeverity::High > SecuritySeverity::Medium);
    assert!(SecuritySeverity::Medium > SecuritySeverity::Low);
    assert!(SecuritySeverity::Low > SecuritySeverity::Benign);
}

#[test]
fn severity_execve_critical() {
    assert_eq!(syscall_security_severity("execve"), SecuritySeverity::Critical);
}

#[test]
fn severity_unknown_benign() {
    assert_eq!(syscall_security_severity("nope_nope"), SecuritySeverity::Benign);
}

// ─── SyscallStore (SQLite) ────────────────────────────────────────────────

#[test]
fn store_open_and_count_zero() {
    let s = SyscallStore::open_memory().unwrap();
    assert_eq!(s.count().unwrap(), 0);
}

#[test]
fn store_insert_and_find() {
    let s = SyscallStore::open_memory().unwrap();
    let sc = LinuxSyscall::new(0, "read", vec![SyscallParam::new("fd", "int")], "ssize_t");
    s.insert(SyscallArch::X86_64, &sc).unwrap();
    assert_eq!(s.count().unwrap(), 1);
    let row = s.find_by_number(SyscallArch::X86_64, 0).unwrap().unwrap();
    assert_eq!(row.0, "read");
}

#[test]
fn store_insert_duplicate_ignored() {
    let s = SyscallStore::open_memory().unwrap();
    let sc = LinuxSyscall::new(0, "read", vec![], "ssize_t");
    s.insert(SyscallArch::X86_64, &sc).unwrap();
    s.insert(SyscallArch::X86_64, &sc).unwrap();
    assert_eq!(s.count().unwrap(), 1);
}

#[test]
fn store_bulk_insert() {
    let s = SyscallStore::open_memory().unwrap();
    let db = LinuxSyscallDb::new();
    let n = s.bulk_insert(SyscallArch::X86_64, &db).unwrap();
    assert!(n > 0);
    assert_eq!(usize::try_from(s.count().unwrap()).unwrap(), n);
}

#[test]
fn store_find_by_category() {
    let s = SyscallStore::open_memory().unwrap();
    let db = LinuxSyscallDb::new();
    s.bulk_insert(SyscallArch::X86_64, &db).unwrap();
    let net = s.find_by_category(SyscallArch::X86_64, SyscallCategory::Network).unwrap();
    assert!(net.iter().any(|(_, n)| n == "socket"));
}

#[test]
fn store_find_by_min_severity_critical() {
    let s = SyscallStore::open_memory().unwrap();
    let db = LinuxSyscallDb::new();
    s.bulk_insert(SyscallArch::X86_64, &db).unwrap();
    let crit = s.find_by_min_severity(SyscallArch::X86_64, SecuritySeverity::Critical).unwrap();
    assert!(crit.iter().any(|(_, n, _)| n == "execve"));
    // All returned should be critical
    for (_, _, sev) in &crit {
        assert_eq!(sev, "critical");
    }
}

#[test]
fn store_list_all_ordered() {
    let s = SyscallStore::open_memory().unwrap();
    let db = LinuxSyscallDb::new();
    s.bulk_insert(SyscallArch::X86_64, &db).unwrap();
    let all = s.list_all().unwrap();
    assert!(!all.is_empty());
}

// ─── lookup_x86_64_entry (static index-based) ──────────────────────────────

#[test]
fn lookup_x86_64_entry_read() {
    let e = lookup_x86_64_entry(0).unwrap();
    assert_eq!(e.name, "read");
}

#[test]
fn lookup_x86_64_entry_out_of_range() {
    assert!(lookup_x86_64_entry(99_999).is_none());
}

// ─── SyscallEvent / SyscallTrace ───────────────────────────────────────────

#[test]
fn syscall_event_negative_retval_sets_errno() {
    let e = SyscallEvent::new(0, 1, 0, "read", vec![], -2, 0);
    assert_eq!(e.errno, Some(2));
}

#[test]
fn syscall_event_positive_retval_no_errno() {
    let e = SyscallEvent::new(0, 1, 0, "read", vec![], 4, 0);
    assert_eq!(e.errno, None);
}

#[test]
fn syscall_trace_push_len_empty() {
    let mut t = SyscallTrace::new();
    assert!(t.is_empty());
    t.push(SyscallEvent::new(0, 1, 0, "x", vec![], 0, 0));
    assert_eq!(t.len(), 1);
    assert!(!t.is_empty());
}

#[test]
fn syscall_trace_interesting_events_execve() {
    let mut t = SyscallTrace::new();
    t.push(SyscallEvent::new(0, 1, 59, "execve", vec![], 0, 0));
    t.push(SyscallEvent::new(0, 1, 1, "write", vec![], 1, 0));
    let v = t.interesting_events();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].name, "execve");
}

// ─── Flag decoders ─────────────────────────────────────────────────────────

#[test]
fn decode_open_flags_rdonly_only() {
    assert_eq!(decode_open_flags(0), "O_RDONLY");
}

#[test]
fn decode_open_flags_wronly_creat_trunc() {
    let s = decode_open_flags(0o1 | 0x40 | 0x200);
    assert!(s.contains("O_WRONLY"));
    assert!(s.contains("O_CREAT"));
    assert!(s.contains("O_TRUNC"));
}

#[test]
fn decode_mmap_prot_none() {
    assert_eq!(decode_mmap_prot(0), "PROT_NONE");
}

#[test]
fn decode_mmap_prot_rwx() {
    let s = decode_mmap_prot(7);
    assert!(s.contains("PROT_READ") && s.contains("PROT_WRITE") && s.contains("PROT_EXEC"));
}

#[test]
fn decode_mmap_flags_private_anon() {
    let s = decode_mmap_flags(0x22);
    assert!(s.contains("MAP_PRIVATE"));
    assert!(s.contains("MAP_ANONYMOUS"));
}

// ─── errno ─────────────────────────────────────────────────────────────────

#[test]
fn errno_name_eperm() {
    assert_eq!(errno_name(1), "EPERM");
}

#[test]
fn errno_name_unknown() {
    assert_eq!(errno_name(99999), "EUNKNOWN");
}

#[test]
fn errno_name_v2_einval() {
    assert_eq!(errno_name_v2(22), Some("EINVAL"));
}

#[test]
fn errno_name_v2_unknown() {
    assert!(errno_name_v2(9999).is_none());
}

#[test]
fn format_retval_positive() {
    assert_eq!(format_retval(42), "42");
}

#[test]
fn format_retval_negative_known() {
    let s = format_retval(-22);
    assert!(s.contains("EINVAL"));
}

// ─── SyscallTraceFilter ────────────────────────────────────────────────────

#[test]
fn filter_interesting_execve() {
    let e = SyscallEvent::new(0, 1, 59, "execve", vec![], 0, 0);
    assert!(SyscallTraceFilter::interesting_for_malware(&e));
}

#[test]
fn filter_mmap_exec_only_when_prot_exec() {
    let e_no = SyscallEvent::new(0, 1, 9, "mmap", vec![0, 4096, 3], 0, 0);
    let e_yes = SyscallEvent::new(0, 1, 9, "mmap", vec![0, 4096, 5], 0, 0);
    assert!(!SyscallTraceFilter::interesting_for_malware(&e_no));
    assert!(SyscallTraceFilter::interesting_for_malware(&e_yes));
}

#[test]
fn filter_clone_namespace_flag() {
    let e = SyscallEvent::new(0, 1, 56, "clone", vec![0x8004_0000], 0, 0);
    assert!(SyscallTraceFilter::interesting_for_malware(&e));
    let e2 = SyscallEvent::new(0, 1, 56, "clone", vec![0x100], 0, 0);
    assert!(!SyscallTraceFilter::interesting_for_malware(&e2));
}

#[test]
fn filter_is_sensitive_file_access() {
    assert!(SyscallTraceFilter::is_sensitive_file_access("/etc/passwd"));
    assert!(SyscallTraceFilter::is_sensitive_file_access("/proc/1/maps"));
    assert!(!SyscallTraceFilter::is_sensitive_file_access("/home/user/file.txt"));
}

#[test]
fn filter_is_network_connect() {
    let e = SyscallEvent::new(0, 1, 42, "connect", vec![], 0, 0);
    assert!(SyscallTraceFilter::is_network_connect(&e));
}

#[test]
fn filter_is_privilege_escalation_setuid() {
    let e = SyscallEvent::new(0, 1, 0, "setuid", vec![0], 0, 0);
    assert!(SyscallTraceFilter::is_privilege_escalation(&e));
}

#[test]
fn filter_is_exec_memory_mprotect() {
    let e = SyscallEvent::new(0, 1, 10, "mprotect", vec![0, 4096, 5], 0, 0);
    assert!(SyscallTraceFilter::is_exec_memory(&e));
}

// ─── PtraceOptions builder ─────────────────────────────────────────────────

#[test]
fn ptrace_options_attach() {
    let o = PtraceOptions::attach(1234);
    assert_eq!(o.attach_pid, Some(1234));
}

#[test]
fn ptrace_options_spawn() {
    let o = PtraceOptions::spawn("/bin/ls");
    assert_eq!(o.command, vec!["/bin/ls"]);
}

#[test]
fn ptrace_options_include_exclude_filters() {
    let o = PtraceOptions::default()
        .include(["read", "write"])
        .exclude(["brk"]);
    assert_eq!(o.include_filter, vec!["read", "write"]);
    assert_eq!(o.exclude_filter, vec!["brk"]);
}

#[test]
fn ptrace_options_default_decode_strings_true() {
    assert!(PtraceOptions::default().decode_strings);
    assert!(PtraceOptions::default().follow_forks);
}

// ─── SyscallSummary ────────────────────────────────────────────────────────

#[test]
fn summary_from_empty_trace() {
    let s = SyscallSummary::from_trace(&SyscallTrace::new());
    assert_eq!(s.total_events, 0);
    assert_eq!(s.total_wall_ns, 0);
    assert!(s.per_name.is_empty());
}

#[test]
fn summary_from_trace_aggregates() {
    let mut t = SyscallTrace::new();
    t.push(SyscallEvent::new(100, 1, 0, "read", vec![], 0, 50));
    t.push(SyscallEvent::new(200, 1, 0, "read", vec![], -1, 100));
    let s = SyscallSummary::from_trace(&t);
    assert_eq!(s.total_events, 2);
    assert_eq!(s.total_wall_ns, 100);
    let st = &s.per_name["read"];
    assert_eq!(st.count, 2);
    assert_eq!(st.total_ns, 150);
    assert_eq!(st.error_count, 1);
    assert_eq!(st.min_ns, 50);
    assert_eq!(st.max_ns, 100);
}

#[test]
fn syscall_stat_avg_zero_count() {
    let s = SyscallStat::default();
    assert_eq!(s.avg_ns(), 0);
}

#[test]
fn summary_top_by_time_truncates() {
    let mut t = SyscallTrace::new();
    t.push(SyscallEvent::new(0, 1, 0, "a", vec![], 0, 100));
    t.push(SyscallEvent::new(1, 1, 0, "b", vec![], 0, 200));
    t.push(SyscallEvent::new(2, 1, 0, "c", vec![], 0, 50));
    let s = SyscallSummary::from_trace(&t);
    let top = s.top_by_time(2);
    assert_eq!(top.len(), 2);
    assert_eq!(top[0].0, "b");
}

#[test]
fn summary_render_table_has_total() {
    let mut t = SyscallTrace::new();
    t.push(SyscallEvent::new(0, 1, 0, "read", vec![], 0, 1_000_000));
    let s = SyscallSummary::from_trace(&t);
    let r = s.render_table();
    assert!(r.contains("total"));
    assert!(r.contains("read"));
}

// ─── FdTracker / ChildTracker / TraceSession ───────────────────────────────

#[test]
fn fdtracker_insert_lookup_remove() {
    let mut t = FdTracker::new();
    t.insert(1, 3, FdKind::File("/x".into()));
    assert!(t.lookup(1, 3).is_some());
    t.remove(1, 3);
    assert!(t.lookup(1, 3).is_none());
}

#[test]
fn fdtracker_update_from_open() {
    let mut t = FdTracker::new();
    let e = SyscallEvent::new(0, 1, 2, "open", vec![0, 0], 5, 0);
    t.update_from_event(&e);
    assert!(matches!(t.lookup(1, 5), Some(FdKind::File(_))));
}

#[test]
fn fdtracker_update_dup_copies_kind() {
    let mut t = FdTracker::new();
    t.insert(1, 3, FdKind::File("/etc/passwd".into()));
    let dup = SyscallEvent::new(0, 1, 32, "dup", vec![3], 7, 0);
    t.update_from_event(&dup);
    match t.lookup(1, 7) {
        Some(FdKind::File(p)) => assert_eq!(p, "/etc/passwd"),
        o => panic!("{o:?}"),
    }
}

#[test]
fn fdtracker_close_removes() {
    let mut t = FdTracker::new();
    t.insert(1, 5, FdKind::Pipe);
    let close = SyscallEvent::new(0, 1, 3, "close", vec![5], 0, 0);
    t.update_from_event(&close);
    assert!(t.lookup(1, 5).is_none());
}

#[test]
fn fdkind_display() {
    assert_eq!(FdKind::Pipe.to_string(), "pipe");
    assert_eq!(FdKind::Epoll.to_string(), "epoll");
    assert_eq!(FdKind::File("/x".into()).to_string(), "file:/x");
}

#[test]
fn childtracker_records_fork_and_descendants() {
    let mut c = ChildTracker::new();
    c.record_fork(1, 2);
    c.record_fork(2, 3);
    c.record_fork(2, 4);
    assert_eq!(c.parent_of(2), Some(1));
    assert_eq!(c.children_of(2).len(), 2);
    let desc: std::collections::HashSet<u32> = c.descendants_of(1).into_iter().collect();
    assert!(desc.contains(&2));
    assert!(desc.contains(&3));
    assert!(desc.contains(&4));
}

#[test]
fn childtracker_update_from_fork_event() {
    let mut c = ChildTracker::new();
    let e = SyscallEvent::new(0, 1, 57, "fork", vec![], 42, 0);
    c.update_from_event(&e);
    assert_eq!(c.parent_of(42), Some(1));
}

#[test]
fn trace_session_push_updates_trackers() {
    let mut sess = TraceSession::new();
    sess.push_syscall(SyscallEvent::new(0, 1, 57, "fork", vec![], 99, 0));
    sess.push_syscall(SyscallEvent::new(1, 1, 2, "open", vec![0, 0], 3, 0));
    assert_eq!(sess.children.parent_of(99), Some(1));
    assert!(sess.fds.lookup(1, 3).is_some());
}

#[test]
fn trace_session_to_json_roundtrip() {
    let mut sess = TraceSession::new();
    sess.push_syscall(SyscallEvent::new(0, 1, 0, "read", vec![3, 0, 256], 256, 100));
    sess.push_signal(SignalEvent::new(50, 1, 11));
    let json = sess.to_json().unwrap();
    assert!(json.contains("read"));
    assert!(json.contains("SIGSEGV"));
}

#[test]
fn signal_event_resolves_name() {
    let s = SignalEvent::new(0, 1, 11);
    assert_eq!(s.signame, "SIGSEGV");
}

#[test]
fn signal_name_sigkill() {
    assert_eq!(signal_name(9), "SIGKILL");
}

#[test]
fn signal_name_unknown() {
    assert_eq!(signal_name(200), "SIGUNKNOWN");
}

// ─── aarch64 ───────────────────────────────────────────────────────────────

#[test]
fn aarch64_name_basic() {
    assert_eq!(aarch64_syscall_name(63), Some("read"));
    assert_eq!(aarch64_syscall_name(64), Some("write"));
}

#[test]
fn aarch64_name_v2_basic() {
    assert_eq!(aarch64_syscall_name_v2(63), Some("read"));
}

#[test]
fn aarch64_nr_lookup() {
    assert_eq!(aarch64_syscall_nr("read"), Some(63));
}

// ─── ArgType / FlagBit / decode_flags ──────────────────────────────────────

#[test]
fn argtype_c_names() {
    assert_eq!(ArgType::Int.c_name(), "int");
    assert_eq!(ArgType::Str.c_name(), "const char *");
}

#[test]
fn flagbit_new() {
    let b = FlagBit::new(1, "X");
    assert_eq!(b.value, 1);
    assert_eq!(b.name, "X");
}

#[test]
fn decode_flags_zero_returns_zero_string() {
    assert_eq!(decode_flags(0, O_FLAGS), "0");
}

#[test]
fn decode_flags_unknown_appended() {
    let bits = [FlagBit::new(1, "A")];
    let s = decode_flags(0b11, &bits);
    assert!(s.contains('A'));
    assert!(s.contains("unknown"));
}

#[test]
fn decode_flags_by_name_unknown_set_hex() {
    let s = decode_flags_by_name("WHO_KNOWS", 0x42);
    assert!(s.contains("0x42"));
}

#[test]
fn decode_flags_by_name_prot_rwx() {
    let s = decode_flags_by_name("PROT_FLAGS", 0x7);
    assert!(s.contains("PROT_READ"));
    assert!(s.contains("PROT_EXEC"));
}

// ─── sockaddr / hex_dump ────────────────────────────────────────────────────

#[test]
fn hex_dump_under_max() {
    let d = [0xab, 0xcd];
    let s = hex_dump_ext(&d, 16);
    assert_eq!(s, "ab cd");
}

#[test]
fn hex_dump_truncates() {
    let d: Vec<u8> = (0..20).collect();
    let s = hex_dump_ext(&d, 4);
    assert!(s.contains("16 more bytes"));
}

#[test]
fn decode_sockaddr_too_short() {
    let s = decode_sockaddr(&[]);
    assert!(matches!(s, DecodedSockaddr::Raw { .. }));
}

#[test]
fn decode_sockaddr_inet() {
    let mut d = vec![2u8, 0, 0x00, 0x50, 192, 168, 1, 1];
    let _ = &mut d;
    let s = decode_sockaddr(&d);
    match s {
        DecodedSockaddr::Inet { addr, port } => {
            assert_eq!(addr, "192.168.1.1");
            assert_eq!(port, 80);
        }
        o => panic!("{o:?}"),
    }
}

#[test]
fn decode_sockaddr_unix() {
    let mut d = vec![1u8, 0];
    d.extend_from_slice(b"/run/foo\0");
    match decode_sockaddr(&d) {
        DecodedSockaddr::Unix { path } => assert_eq!(path, "/run/foo"),
        o => panic!("{o:?}"),
    }
}

#[test]
fn decoded_sockaddr_display_inet() {
    let s = DecodedSockaddr::Inet { addr: "127.0.0.1".into(), port: 80 };
    assert_eq!(s.to_string(), "127.0.0.1:80");
}

// ─── DecodedArg / FdTable / SyscallEventV2 ─────────────────────────────────

#[test]
fn decoded_arg_display_variants() {
    assert_eq!(DecodedArg::Int(-1).to_string(), "-1");
    assert_eq!(DecodedArg::Null.to_string(), "NULL");
    assert_eq!(DecodedArg::Addr(0xdead).to_string(), "0xdead");
    assert_eq!(DecodedArg::Fd(3, String::new()).to_string(), "3");
    assert_eq!(DecodedArg::Errno(-2).to_string(), "-1 /* errno=2 */");
}

#[test]
fn fdtable_dup() {
    let mut t = FdTable::default();
    t.insert(3, FdInfo::file("/etc/p", 0));
    t.dup(3, 4);
    assert_eq!(t.get(4).unwrap().path, "/etc/p");
}

#[test]
fn fdtable_all_sorted_by_fd() {
    let mut t = FdTable::default();
    t.insert(7, FdInfo::file("/a", 0));
    t.insert(2, FdInfo::file("/b", 0));
    let all = t.all();
    assert_eq!(all[0].0, 2);
    assert_eq!(all[1].0, 7);
}

#[test]
fn fdtable_remove_returns() {
    let mut t = FdTable::default();
    t.insert(1, FdInfo::file("/x", 0));
    assert!(t.remove(1).is_some());
    assert!(t.remove(1).is_none());
}

// ─── PtraceOptionsV2 filter ────────────────────────────────────────────────

#[test]
fn ptrace_v2_no_filter_passes_all() {
    let o = PtraceOptionsV2::spawn("ls");
    assert!(o.passes_filter("read"));
    assert!(o.passes_filter("anything"));
}

#[test]
fn ptrace_v2_include_only_listed() {
    let o = PtraceOptionsV2::spawn("ls").include(["read"]);
    assert!(o.passes_filter("read"));
    assert!(!o.passes_filter("write"));
}

#[test]
fn ptrace_v2_exclude_skips() {
    let o = PtraceOptionsV2::spawn("ls").exclude(["brk"]);
    assert!(!o.passes_filter("brk"));
    assert!(o.passes_filter("read"));
}

// ─── ThreadSyscallState ────────────────────────────────────────────────────

#[test]
fn thread_state_entry_exit_elapsed() {
    let mut s = ThreadSyscallState::default();
    s.on_entry(0, [1, 2, 3, 4, 5, 6, 7], 1_000);
    assert_eq!(s.in_syscall, Some(0));
    assert!(s.stopped);
    let (nr, el) = s.on_exit(1_500);
    assert_eq!(nr, Some(0));
    assert_eq!(el, 500);
    assert!(!s.stopped);
}

#[test]
fn thread_state_exit_saturating() {
    let mut s = ThreadSyscallState::default();
    s.on_entry(0, [0; 7], 1000);
    let (_, el) = s.on_exit(500); // exit ts < entry ts
    assert_eq!(el, 0); // saturating sub
}

// ─── resolve_fd ─────────────────────────────────────────────────────────────

#[test]
fn resolve_fd_at_fdcwd() {
    assert_eq!(resolve_fd(1, AT_FDCWD), "AT_FDCWD");
}

#[test]
fn resolve_fd_negative() {
    let s = resolve_fd(1, -42);
    assert!(s.contains("bad fd"));
}

// ─── format_signal_delivery / format_exit_event ────────────────────────────

#[test]
fn format_signal_delivery_segv() {
    let s = format_signal_delivery(11, 1, 0xcafe);
    assert!(s.contains("SIGSEGV"));
    assert!(s.contains("SEGV_MAPERR"));
}

#[test]
fn format_exit_event_normal() {
    assert!(format_exit_event(1, 7, None).contains('7'));
}

#[test]
fn format_exit_event_killed_by_signal() {
    assert!(format_exit_event(1, 0, Some(9)).contains("SIGKILL"));
}

// ─── x86_64 static table ───────────────────────────────────────────────────

#[test]
fn x86_64_nr_to_name_basic() {
    assert_eq!(x86_64_syscall_name(0), Some("read"));
    assert_eq!(x86_64_syscall_name(1), Some("write"));
    assert_eq!(x86_64_syscall_name(59), Some("execve"));
}

#[test]
fn x86_64_name_to_nr_basic() {
    assert_eq!(x86_64_syscall_nr("read"), Some(0));
    assert_eq!(x86_64_syscall_nr("execve"), Some(59));
}

#[test]
fn x86_64_nr_unknown() {
    assert!(x86_64_syscall_name(99_999).is_none());
    assert!(x86_64_syscall_nr("not_a_syscall_xx").is_none());
}

#[test]
fn x86_64_table_no_duplicate_nrs() {
    let mut seen = std::collections::HashSet::new();
    for s in X86_64_SYSCALLS {
        assert!(seen.insert(s.nr), "dup nr={}", s.nr);
    }
}

// ─── ioctl / ptrace_request / PtraceEvent ──────────────────────────────────

#[test]
fn ioctl_name_known() {
    assert_eq!(ioctl_name(0x5401), Some("TCGETS"));
}

#[test]
fn ioctl_name_unknown() {
    assert!(ioctl_name(0xdead_beef).is_none());
}

#[test]
fn ptrace_request_name_known() {
    assert_eq!(ptrace_request_name(16), Some("PTRACE_ATTACH"));
    assert_eq!(ptrace_request_name(0x4202), Some("PTRACE_SEIZE"));
}

#[test]
fn ptrace_event_from_u32_known() {
    assert_eq!(PtraceEvent::from_u32(1), PtraceEvent::Fork);
    assert_eq!(PtraceEvent::from_u32(4), PtraceEvent::Exec);
}

#[test]
fn ptrace_event_from_u32_unknown_preserves_value() {
    assert_eq!(PtraceEvent::from_u32(99), PtraceEvent::Unknown(99));
}

// ─── format_mmap_args / format_open_flags ──────────────────────────────────

#[test]
fn format_mmap_args_includes_both() {
    let s = format_mmap_args(0x7, 0x22);
    assert!(s.contains("PROT_READ"));
    assert!(s.contains("MAP_PRIVATE"));
}

#[test]
fn format_open_flags_rdwr() {
    let s = format_open_flags(0o2);
    assert!(s.starts_with("O_RDWR"));
}

// ─── TaintFlags ─────────────────────────────────────────────────────────────

#[test]
fn taint_flags_default_not_suspicious() {
    let t = TaintFlags::default();
    assert!(!t.is_suspicious());
    assert!(!t.used_ptrace());
}

#[test]
fn taint_flags_update_ptrace_sets_used() {
    let mut t = TaintFlags::default();
    let ev = SyscallEventV2 {
        timestamp_ns: 0, pid: 1, tid: 1, nr: 101,
        name: "ptrace".into(),
        args: vec![],
        retval: DecodedArg::Int(0),
        elapsed_ns: 0, is_entry: false,
    };
    t.update_from_event(&ev);
    assert!(t.used_ptrace());
    assert!(t.is_suspicious());
}

#[test]
fn taint_flags_update_socket_sets_network() {
    let mut t = TaintFlags::default();
    let ev = SyscallEventV2 {
        timestamp_ns: 0, pid: 1, tid: 1, nr: 41,
        name: "socket".into(),
        args: vec![], retval: DecodedArg::Int(3),
        elapsed_ns: 0, is_entry: false,
    };
    t.update_from_event(&ev);
    assert!(t.opened_network_socket());
}

#[test]
fn taint_flags_clone_spawns_child() {
    let mut t = TaintFlags::default();
    let ev = SyscallEventV2 {
        timestamp_ns: 0, pid: 1, tid: 1, nr: 56,
        name: "clone".into(),
        args: vec![], retval: DecodedArg::Int(99),
        elapsed_ns: 0, is_entry: false,
    };
    t.update_from_event(&ev);
    assert!(t.spawned_child());
}

// ─── SeccompAction (lib-level) ─────────────────────────────────────────────

#[test]
fn seccomp_action_from_allow_word() {
    assert_eq!(SeccompAction::from_u32(0x7fff_0000), SeccompAction::Allow);
}

#[test]
fn seccomp_action_kill_default() {
    // Anything not matching upper word → Kill
    assert_eq!(SeccompAction::from_u32(0xdead_0000), SeccompAction::Kill);
}

// ─── procfs parsers ────────────────────────────────────────────────────────

#[test]
fn parse_proc_maps_empty_returns_empty() {
    assert!(parse_proc_maps("").is_empty());
}

#[test]
fn parse_proc_maps_one_entry() {
    let s = "0000-1000 r-xp 00000000 fd:01 1 /usr/bin/foo\n";
    let v = parse_proc_maps(s);
    assert_eq!(v.len(), 1);
    assert!(v[0].is_executable());
    assert_eq!(v[0].pathname, "/usr/bin/foo");
}

#[test]
fn maps_entry_size_correct() {
    let e = MapsEntry {
        start: 0x1000, end: 0x5000,
        perms: "rwxp".into(), offset: 0,
        dev: "00:00".into(), inode: 0, pathname: String::new(),
    };
    assert_eq!(e.size(), 0x4000);
    assert!(e.is_anon());
}

#[test]
fn parse_proc_status_basic() {
    let s = parse_proc_status("Name:\tfoo\nPid:\t10\nThreads:\t4\n");
    assert_eq!(s.name, "foo");
    assert_eq!(s.pid, 10);
    assert_eq!(s.threads, 4);
}

#[test]
fn parse_proc_status_missing_fields_zero() {
    let s = parse_proc_status("");
    assert_eq!(s.pid, 0);
    assert_eq!(s.name, "");
}

// ─── WaitStatus ─────────────────────────────────────────────────────────────

#[test]
fn wait_status_decode_exit_code_5() {
    match WaitStatus::decode(5 << 8) {
        WaitStatus::Exited(c) => assert_eq!(c, 5),
        o => panic!("{o:?}"),
    }
}

#[test]
fn wait_status_decode_signaled() {
    let ws = WaitStatus::decode(11);
    match ws {
        WaitStatus::Signaled { signal, coredump } => {
            assert_eq!(signal, 11);
            assert!(!coredump);
        }
        o => panic!("{o:?}"),
    }
}

#[test]
fn wait_status_decode_signaled_coredump() {
    match WaitStatus::decode(11 | 0x80) {
        WaitStatus::Signaled { signal, coredump } => {
            assert_eq!(signal, 11);
            assert!(coredump);
        }
        o => panic!("{o:?}"),
    }
}

#[test]
fn wait_status_format_continued() {
    let s = WaitStatus::Continued.format_strace();
    assert!(s.contains("WIFCONTINUED"));
}

// ─── sockopt / af ──────────────────────────────────────────────────────────

#[test]
fn sockopt_name_so_error() {
    assert_eq!(sockopt_name(1, 4), "SO_ERROR");
}

#[test]
fn af_name_inet_inet6_unknown() {
    assert_eq!(af_name(2), "AF_INET");
    assert_eq!(af_name(10), "AF_INET6");
    assert_eq!(af_name(9999), "AF_UNKNOWN");
}

// ─── JsonEventLog / CsvEventLog ────────────────────────────────────────────

#[test]
fn json_event_log_lifecycle() {
    let mut log = JsonEventLog::new();
    assert!(log.is_empty());
    let ev = SyscallEventV2 {
        timestamp_ns: 0, pid: 1, tid: 1, nr: 0,
        name: "x".into(), args: vec![], retval: DecodedArg::Int(0),
        elapsed_ns: 0, is_entry: false,
    };
    log.append(&ev);
    log.append(&ev);
    assert_eq!(log.len(), 2);
    log.clear();
    assert!(log.is_empty());
}

#[test]
fn csv_event_log_row_count_excludes_header() {
    let mut l = CsvEventLog::new();
    assert_eq!(l.row_count(), 0);
    let ev = SyscallEventV2 {
        timestamp_ns: 0, pid: 1, tid: 1, nr: 0,
        name: "y".into(), args: vec![], retval: DecodedArg::Int(0),
        elapsed_ns: 0, is_entry: false,
    };
    l.append(&ev);
    assert_eq!(l.row_count(), 1);
}

// ─── linux_syscall_table_x86_64 module ────────────────────────────────────

#[test]
fn table_lookup_by_number_known() {
    let s = table::syscall_by_number(0).unwrap();
    assert_eq!(s.name, "read");
}

#[test]
fn table_lookup_by_name_known() {
    let s = table::syscall_by_name("execve").unwrap();
    assert_eq!(s.number, 59);
}

#[test]
fn table_search_by_name_case_insensitive() {
    let v = table::search_by_name("READ");
    assert!(v.iter().any(|s| s.name == "read"));
}

#[test]
fn table_by_arg_count_six() {
    let v = table::by_arg_count(6);
    assert!(v.iter().any(|s| s.name == "mmap"));
}

#[test]
fn table_build_number_index() {
    let idx = table::build_number_index();
    assert_eq!(idx[&0].name, "read");
}

#[test]
fn table_build_name_index() {
    let idx = table::build_name_index();
    assert!(idx.contains_key("ptrace"));
}

#[test]
fn syscallarg_display_strings() {
    assert_eq!(table::SyscallArg::Fd.to_string(), "fd");
    assert_eq!(table::SyscallArg::Ptr.to_string(), "ptr");
    assert_eq!(table::SyscallArg::Unused.to_string(), "_");
}

// ─── seccomp_profile_generator ────────────────────────────────────────────

#[test]
fn arg_filter_eq_ne() {
    assert!(scg::ArgFilter::Eq(5).matches(5));
    assert!(scg::ArgFilter::Ne(5).matches(4));
    assert!(!scg::ArgFilter::Ne(5).matches(5));
}

#[test]
fn arg_filter_lt_le_gt_ge() {
    assert!(scg::ArgFilter::Lt(10).matches(9));
    assert!(scg::ArgFilter::Le(10).matches(10));
    assert!(scg::ArgFilter::Gt(10).matches(11));
    assert!(scg::ArgFilter::Ge(10).matches(10));
}

#[test]
fn arg_filter_masked_eq() {
    let f = scg::ArgFilter::MaskedEq { mask: 0xff, value: 0x42 };
    assert!(f.matches(0xff00_0042));
    assert!(!f.matches(0xff00_0041));
}

#[test]
fn arg_filter_any_bit() {
    let f = scg::ArgFilter::AnyBit(0xf0);
    assert!(f.matches(0x80));
    assert!(!f.matches(0x0f));
}

#[test]
fn arg_filter_to_bpf_expr() {
    let s = scg::ArgFilter::Eq(0x10).to_bpf_expr(2);
    assert!(s.contains("args[2]"));
    assert!(s.contains("0x10"));
}

#[test]
fn seccomp_rule_matches_with_arg() {
    let r = scg::SeccompRule::allow(0).with_arg(0, scg::ArgFilter::Eq(3));
    assert!(r.matches(0, &[3, 0, 0, 0, 0, 0]));
    assert!(!r.matches(0, &[4, 0, 0, 0, 0, 0]));
}

#[test]
fn seccomp_rule_does_not_match_wrong_nr() {
    let r = scg::SeccompRule::allow(0);
    assert!(!r.matches(1, &[0; 6]));
}

#[test]
fn seccomp_simulate_allowlist_kills_unlisted() {
    let mut g = scg::SeccompProfileGenerator::new(scg::PolicyKind::Allowlist);
    g.allow(0);
    assert_eq!(g.simulate(99, &[0; 6]), scg::SeccompAction::KillProcess);
}

#[test]
fn seccomp_simulate_denylist_allows_unlisted() {
    let mut g = scg::SeccompProfileGenerator::new(scg::PolicyKind::Denylist);
    g.deny(101);
    assert_eq!(g.simulate(0, &[0; 6]), scg::SeccompAction::Allow);
}

#[test]
fn seccomp_covered_syscall_numbers_dedup_sort() {
    let mut g = scg::SeccompProfileGenerator::new(scg::PolicyKind::Allowlist);
    g.allow(5);
    g.allow(3);
    g.allow(5);
    assert_eq!(g.covered_syscall_numbers(), vec![3, 5]);
}

#[test]
fn seccomp_minimal_sandbox_includes_read_write() {
    let g = scg::minimal_sandbox_profile();
    assert!(g.is_covered(0));
    assert!(g.is_covered(1));
}

#[test]
fn seccomp_anti_debug_blocks_ptrace() {
    let g = scg::anti_debug_profile();
    assert_eq!(g.simulate(101, &[0; 6]), scg::SeccompAction::KillProcess);
}

#[test]
fn seccomp_generate_filter_has_default_action() {
    let g = scg::SeccompProfileGenerator::new(scg::PolicyKind::Allowlist);
    let f = g.generate();
    assert_eq!(f.default_action, scg::SeccompAction::KillProcess);
}

#[test]
fn seccomp_policy_kind_display() {
    assert_eq!(scg::PolicyKind::Allowlist.to_string(), "allowlist");
    assert_eq!(scg::PolicyKind::Denylist.to_string(), "denylist");
}

#[test]
fn seccomp_action_display() {
    assert_eq!(scg::SeccompAction::Allow.to_string(), "ALLOW");
    assert_eq!(scg::SeccompAction::Errno(5).to_string(), "ERRNO(5)");
}

#[test]
fn seccomp_rule_statistics_counts() {
    let mut g = scg::SeccompProfileGenerator::new(scg::PolicyKind::Allowlist);
    g.allow(0);
    g.allow(1);
    g.deny(2);
    let stats = g.rule_statistics();
    assert_eq!(stats["ALLOW"], 2);
    assert_eq!(stats["KILL_PROCESS"], 1);
}

// ─── syscall_intercept ────────────────────────────────────────────────────

fn mk_sc(nr: u32, name: &str) -> LinuxSyscall {
    LinuxSyscall::new(nr, name, vec![], "long")
}

#[test]
fn intercept_point_includes() {
    assert!(si::InterceptPoint::Pre.includes_pre());
    assert!(!si::InterceptPoint::Pre.includes_post());
    assert!(si::InterceptPoint::Both.includes_pre());
    assert!(si::InterceptPoint::Both.includes_post());
}

#[test]
fn syscall_filter_range_inverted_returns_false() {
    let sc = mk_sc(5, "x");
    let f = si::SyscallFilter::NumberRange { lo: 10, hi: 5 };
    // Per source: if lo > hi return false (no panic, despite doc).
    assert!(!f.matches(&sc));
}

#[test]
fn syscall_filter_range_inclusive_bounds() {
    let sc_lo = mk_sc(10, "x");
    let sc_hi = mk_sc(20, "x");
    let f = si::SyscallFilter::NumberRange { lo: 10, hi: 20 };
    assert!(f.matches(&sc_lo));
    assert!(f.matches(&sc_hi));
}

#[test]
fn intercept_action_chain_blocking() {
    let chain = si::InterceptAction::Chain(vec![
        si::InterceptAction::Log,
        si::InterceptAction::Block { error_code: -1 },
    ]);
    assert!(chain.is_blocking());
}

#[test]
fn intercept_action_label() {
    assert_eq!(si::InterceptAction::Log.label(), "log");
    assert_eq!(si::InterceptAction::Redirect { to_syscall: 1 }.label(), "redirect");
}

#[test]
fn interceptor_add_evaluate_logs_event() {
    let mut ic = si::SyscallInterceptor::new();
    ic.add_log_all();
    let sc = mk_sc(0, "read");
    let evs = ic.evaluate(&sc, SyscallArch::X86_64, &[3, 0, 0], None, si::InterceptPoint::Pre);
    assert_eq!(evs.len(), 1);
    assert!(!evs[0].was_blocked);
    assert_eq!(ic.event_count(), 1);
}

#[test]
fn interceptor_block_event_marked_blocked() {
    let mut ic = si::SyscallInterceptor::new();
    ic.add_block_number(59, -1);
    let sc = mk_sc(59, "execve");
    let evs = ic.evaluate(&sc, SyscallArch::X86_64, &[], None, si::InterceptPoint::Pre);
    assert!(evs[0].was_blocked);
}

#[test]
fn interceptor_disabled_rule_skipped() {
    let mut ic = si::SyscallInterceptor::new();
    let id = ic.add_log_all();
    ic.set_rule_enabled(id, false);
    let sc = mk_sc(0, "read");
    let evs = ic.evaluate(&sc, SyscallArch::X86_64, &[], None, si::InterceptPoint::Pre);
    assert!(evs.is_empty());
}

#[test]
fn interceptor_remove_rule() {
    let mut ic = si::SyscallInterceptor::new();
    let id = ic.add_log_all();
    assert!(ic.remove_rule(id));
    assert!(!ic.remove_rule(id));
}

#[test]
fn interceptor_for_arch_sets_arch() {
    let ic = si::SyscallInterceptor::for_arch(SyscallArch::X86_64);
    assert_eq!(ic.arch, Some(SyscallArch::X86_64));
}

#[test]
fn interceptor_rules_by_tag() {
    let mut ic = si::SyscallInterceptor::new();
    let _ = ic.add_log_all();
    // Edit tag manually via direct push won't work; instead create via add_rule then
    // inspect rules vector via with_tag through new InterceptRule and push? add_rule
    // doesn't set tag, so rules_by_tag should be empty.
    assert!(ic.rules_by_tag("nope").is_empty());
}

// ─── syscall_statistics ────────────────────────────────────────────────────

#[test]
fn syscall_sample_is_error() {
    let s = ss::SyscallSample::new(0, 0, 0, -1, 1);
    assert!(s.is_error());
    let s2 = ss::SyscallSample::new(0, 0, 0, 0, 1);
    assert!(!s2.is_error());
}

#[test]
fn per_syscall_stats_min_max() {
    let mut s = ss::PerSyscallStats::new(0, "read");
    s.record(&ss::SyscallSample::new(0, 0, 100, 0, 1));
    s.record(&ss::SyscallSample::new(0, 1, 50, 0, 1));
    s.record(&ss::SyscallSample::new(0, 2, 200, 0, 1));
    assert_eq!(s.min_elapsed_ns, 50);
    assert_eq!(s.max_elapsed_ns, 200);
    assert_eq!(s.avg_elapsed_ns(), 350 / 3);
}

#[test]
fn per_syscall_stats_error_pct_bp() {
    let mut s = ss::PerSyscallStats::new(0, "x");
    s.record(&ss::SyscallSample::new(0, 0, 0, -1, 1));
    s.record(&ss::SyscallSample::new(0, 1, 0, 0, 1));
    s.record(&ss::SyscallSample::new(0, 2, 0, -1, 1));
    s.record(&ss::SyscallSample::new(0, 3, 0, 0, 1));
    assert_eq!(s.error_pct_bp(), 5000); // 50%
}

#[test]
fn timeline_window_bounds_inclusive() {
    let mut t = ss::Timeline::new();
    t.push(ss::SyscallSample::new(0, 100, 0, 0, 1));
    t.push(ss::SyscallSample::new(0, 200, 0, 0, 1));
    t.push(ss::SyscallSample::new(0, 300, 0, 0, 1));
    assert_eq!(t.window(100, 300).len(), 3);
    assert_eq!(t.window(101, 299).len(), 1);
}

#[test]
fn syscall_pattern_new_fields() {
    let p = ss::SyscallPattern::new(vec![0, 1, 2], 5, "desc");
    assert_eq!(p.occurrences, 5);
    assert_eq!(p.sequence, vec![0, 1, 2]);
    assert_eq!(p.description, "desc");
}

#[test]
fn statistics_record_resolves_known_name() {
    let mut st = ss::SyscallStatistics::new(SyscallArch::X86_64);
    st.record(ss::SyscallSample::new(0, 0, 10, 0, 1));
    let pst = st.get(0).unwrap();
    assert_eq!(pst.name, "read");
}

#[test]
fn statistics_record_unknown_synthesized_name() {
    let mut st = ss::SyscallStatistics::new(SyscallArch::X86_64);
    st.record(ss::SyscallSample::new(9999, 0, 10, 0, 1));
    let pst = st.get(9999).unwrap();
    assert_eq!(pst.name, "syscall_9999");
}

#[test]
fn statistics_hot_by_time_topn() {
    let mut st = ss::SyscallStatistics::new(SyscallArch::X86_64);
    st.record(ss::SyscallSample::new(0, 0, 1000, 0, 1));
    st.record(ss::SyscallSample::new(1, 1, 500, 0, 1));
    let top = st.hot_by_time(1);
    assert_eq!(top.len(), 1);
    assert_eq!(top[0].nr, 0);
}

#[test]
fn statistics_detect_patterns_basic() {
    let mut st = ss::SyscallStatistics::new(SyscallArch::X86_64);
    for i in 0..6u64 {
        st.record(ss::SyscallSample::new((i % 2) as u32, i, 0, 0, 1));
    }
    // sequence is [0,1,0,1,0,1], window=2 → [0,1] appears 3, [1,0] 2 times
    let patterns = st.detect_patterns(2, 2);
    assert!(patterns.iter().any(|p| p.sequence == vec![0, 1] && p.occurrences == 3));
}

#[test]
fn statistics_detect_patterns_zero_window_empty() {
    let st = ss::SyscallStatistics::new(SyscallArch::X86_64);
    assert!(st.detect_patterns(0, 1).is_empty());
}

#[test]
fn statistics_total_elapsed_sum() {
    let mut st = ss::SyscallStatistics::new(SyscallArch::X86_64);
    st.record(ss::SyscallSample::new(0, 0, 100, 0, 1));
    st.record(ss::SyscallSample::new(1, 1, 200, 0, 1));
    assert_eq!(st.total_elapsed_ns(), 300);
}

#[test]
fn statistics_distinct_syscalls() {
    let mut st = ss::SyscallStatistics::new(SyscallArch::X86_64);
    st.record(ss::SyscallSample::new(0, 0, 1, 0, 1));
    st.record(ss::SyscallSample::new(0, 1, 1, 0, 1));
    st.record(ss::SyscallSample::new(1, 2, 1, 0, 1));
    assert_eq!(st.distinct_syscalls(), 2);
}

#[test]
fn statistics_strace_formatter_renders() {
    let mut st = ss::SyscallStatistics::new(SyscallArch::X86_64);
    st.record(ss::SyscallSample::new(0, 0, 1_000_000, 0, 1));
    let fmt = st.strace_formatter();
    let out = fmt.render();
    assert!(out.contains("read"));
    assert!(out.contains("total"));
}

// ─── ptrace_syscall_tracer module ─────────────────────────────────────────

#[test]
fn syscall_args_from_array_get() {
    let a = pst::SyscallArgs::from_array([1, 2, 3, 4, 5, 6]);
    assert_eq!(a.get(0), Some(1));
    assert_eq!(a.get(5), Some(6));
    assert_eq!(a.get(6), None);
}

#[test]
fn syscall_args_iter() {
    let a = pst::SyscallArgs::from_array([10, 20, 30, 40, 50, 60]);
    let v: Vec<(usize, u64)> = a.iter().collect();
    assert_eq!(v.len(), 6);
    assert_eq!(v[2], (2, 30));
}

#[test]
fn args_from_regs_layout() {
    let a = pst::args_from_regs(1, 2, 3, 4, 5, 6);
    assert_eq!(a.arg0, 1);
    assert_eq!(a.arg3, 4); // r10
}

#[test]
fn is_error_return_classification() {
    assert!(pst::is_error_return((-1i64).cast_unsigned()));
    assert!(pst::is_error_return((-4095i64).cast_unsigned()));
    assert!(!pst::is_error_return((-4096i64).cast_unsigned()));
    assert!(!pst::is_error_return(0));
    assert!(!pst::is_error_return(42));
}

#[test]
fn syscall_number_from_orig_rax_passthrough() {
    assert_eq!(pst::syscall_number_from_orig_rax(59), 59);
}

#[test]
fn ptrace_tracer_enter_exit_pair() {
    let mut t = pst::PtraceSyscallTracer::new();
    let args = pst::SyscallArgs::from_array([0; 6]);
    t.on_syscall_enter(1, 1, 0, args, 0xdead, 100);
    t.on_syscall_exit(1, 1, 0, 5, 200);
    assert_eq!(t.records().len(), 1);
    assert!(t.records()[0].is_complete());
    assert_eq!(t.records()[0].exit.as_ref().unwrap().return_value, 5);
}

#[test]
fn ptrace_tracer_pending_records() {
    let mut t = pst::PtraceSyscallTracer::new();
    let args = pst::SyscallArgs::from_array([0; 6]);
    t.on_syscall_enter(1, 1, 0, args, 0, 100);
    assert_eq!(t.pending_records().len(), 1);
    assert_eq!(t.completed_records().len(), 0);
}

#[test]
fn ptrace_tracer_records_for_pid() {
    let mut t = pst::PtraceSyscallTracer::new();
    let args = pst::SyscallArgs::from_array([0; 6]);
    t.on_syscall_enter(1, 1, 0, args, 0, 100);
    t.on_syscall_enter(2, 2, 1, args, 0, 100);
    assert_eq!(t.records_for_pid(1).len(), 1);
    assert_eq!(t.records_for_pid(2).len(), 1);
}

#[test]
fn ptrace_tracer_call_counts() {
    let mut t = pst::PtraceSyscallTracer::new();
    let args = pst::SyscallArgs::from_array([0; 6]);
    t.on_syscall_enter(1, 1, 0, args, 0, 0);
    t.on_syscall_exit(1, 1, 0, 0, 0);
    t.on_syscall_enter(1, 1, 0, args, 0, 0);
    t.on_syscall_exit(1, 1, 0, 0, 0);
    let cc = t.call_counts();
    assert_eq!(cc[&0], 2);
}

#[test]
fn ptrace_tracer_error_counts() {
    let mut t = pst::PtraceSyscallTracer::new();
    let args = pst::SyscallArgs::from_array([0; 6]);
    t.on_syscall_enter(1, 1, 2, args, 0, 0);
    t.on_syscall_exit(1, 1, 2, -1, 0);
    t.on_syscall_enter(1, 1, 2, args, 0, 0);
    t.on_syscall_exit(1, 1, 2, 3, 0);
    let ec = t.error_counts();
    assert_eq!(ec[&2], 1);
}

#[test]
fn ptrace_tracer_reset() {
    let mut t = pst::PtraceSyscallTracer::new();
    let args = pst::SyscallArgs::from_array([0; 6]);
    t.on_syscall_enter(1, 1, 0, args, 0, 0);
    t.reset();
    assert_eq!(t.total_calls(), 0);
}

#[test]
fn ptrace_tracer_name_resolver() {
    let t = pst::PtraceSyscallTracer::new()
        .with_name_resolver(|nr| if nr == 0 { Some("read".into()) } else { None });
    let mut t = t;
    let args = pst::SyscallArgs::from_array([0; 6]);
    t.on_syscall_enter(1, 1, 0, args, 0, 0);
    assert_eq!(t.records()[0].entry.name.as_deref(), Some("read"));
}

#[test]
fn syscall_exit_errno() {
    let e = pst::SyscallExit::new(1, 1, 1, 0, -22);
    assert!(e.is_error());
    assert_eq!(e.errno(), Some(22));
}

#[test]
fn syscall_record_elapsed_ns_when_both_set() {
    let mut e = pst::SyscallEntry::new(1, 1, 1, 0, pst::SyscallArgs::default());
    e.timestamp_ns = 1000;
    let mut r = pst::SyscallRecord::pending(e);
    let mut x = pst::SyscallExit::new(1, 1, 1, 0, 0);
    x.timestamp_ns = 1500;
    r.complete(x);
    assert_eq!(r.elapsed_ns(), Some(500));
}

#[test]
fn syscall_record_elapsed_none_when_zero_ts() {
    let e = pst::SyscallEntry::new(1, 1, 1, 0, pst::SyscallArgs::default());
    let mut r = pst::SyscallRecord::pending(e);
    let x = pst::SyscallExit::new(1, 1, 1, 0, 0);
    r.complete(x);
    assert!(r.elapsed_ns().is_none());
}
