//! Exhaustive blitz tests for rustre-syscalls public API (lib.rs surface).

use rustre_syscalls::{
    ArgDirection, CallPrefix, DecodedArg, OsFamily, RiskLevel, SeccompAction, SeccompPolicy,
    SeccompRule, Syscall, SyscallArch, SyscallArg, SyscallBuilder, SyscallCall, SyscallCategory,
    SyscallDatabase, SyscallFilter, SyscallFormatter, SyscallStore, SyscallTable, SyscallTarget,
    SyscallTrace, SyscallType, UNKNOWN_SYSCALL, categorize_by_name, clock_id_name,
    decode_arg_value, errno_name, estimate_risk, sa_family_name, signal_name,
};

// ── Helpers ─────────────────────────────────────────────────────────────────
fn open_syscall() -> Syscall {
    SyscallBuilder::new(2, "open", OsFamily::Linux, SyscallArch::X86_64)
        .arg("pathname", SyscallType::String, ArgDirection::In)
        .arg("flags", SyscallType::Int, ArgDirection::In)
        .opt_arg("mode", SyscallType::Mode, ArgDirection::In)
        .returns(SyscallType::Fd)
        .category(SyscallCategory::FileSystem)
        .description("open file")
        .build()
}

const fn ret0_call(s: Syscall, args: Vec<u64>, ret: i64, ts: u64, pid: u32) -> SyscallCall {
    SyscallCall::new(s, args, ret, ts, pid, pid)
}

// ── Display impls ───────────────────────────────────────────────────────────
#[test]
fn display_os_family_all() {
    assert_eq!(OsFamily::Linux.to_string(), "linux");
    assert_eq!(OsFamily::Windows.to_string(), "windows");
    assert_eq!(OsFamily::MacOs.to_string(), "macos");
    assert_eq!(OsFamily::FreeBsd.to_string(), "freebsd");
    assert_eq!(OsFamily::OpenBsd.to_string(), "openbsd");
}

#[test]
fn display_arch_all() {
    assert_eq!(SyscallArch::X86.to_string(), "x86");
    assert_eq!(SyscallArch::X86_64.to_string(), "x86_64");
    assert_eq!(SyscallArch::Arm32.to_string(), "arm32");
    assert_eq!(SyscallArch::Arm64.to_string(), "arm64");
    assert_eq!(SyscallArch::Mips.to_string(), "mips");
    assert_eq!(SyscallArch::Riscv64.to_string(), "riscv64");
}

#[test]
fn display_arg_direction_all() {
    assert_eq!(ArgDirection::In.to_string(), "in");
    assert_eq!(ArgDirection::Out.to_string(), "out");
    assert_eq!(ArgDirection::InOut.to_string(), "inout");
}

#[test]
fn display_category_all() {
    for (c, s) in [
        (SyscallCategory::FileSystem, "filesystem"),
        (SyscallCategory::Memory, "memory"),
        (SyscallCategory::Process, "process"),
        (SyscallCategory::Thread, "thread"),
        (SyscallCategory::Network, "network"),
        (SyscallCategory::Ipc, "ipc"),
        (SyscallCategory::Signal, "signal"),
        (SyscallCategory::Time, "time"),
        (SyscallCategory::Device, "device"),
        (SyscallCategory::Security, "security"),
        (SyscallCategory::System, "system"),
        (SyscallCategory::Unknown, "unknown"),
    ] {
        assert_eq!(c.to_string(), s);
    }
}

#[test]
fn display_risk_all() {
    assert_eq!(RiskLevel::Benign.to_string(), "benign");
    assert_eq!(RiskLevel::Low.to_string(), "low");
    assert_eq!(RiskLevel::Medium.to_string(), "medium");
    assert_eq!(RiskLevel::High.to_string(), "high");
    assert_eq!(RiskLevel::Critical.to_string(), "critical");
}

#[test]
fn risk_level_ord() {
    assert!(RiskLevel::Benign < RiskLevel::Low);
    assert!(RiskLevel::Low < RiskLevel::Medium);
    assert!(RiskLevel::Medium < RiskLevel::High);
    assert!(RiskLevel::High < RiskLevel::Critical);
}

// ── decode_arg_value ────────────────────────────────────────────────────────
#[test]
fn decode_bool_zero_and_nonzero() {
    assert_eq!(decode_arg_value(&SyscallType::Bool, 0).display, "false");
    assert_eq!(decode_arg_value(&SyscallType::Bool, 1).display, "true");
    assert_eq!(decode_arg_value(&SyscallType::Bool, 42).display, "true");
}

#[test]
fn decode_fd_named_streams() {
    assert!(decode_arg_value(&SyscallType::Fd, 0).display.contains("stdin"));
    assert!(decode_arg_value(&SyscallType::Fd, 1).display.contains("stdout"));
    assert!(decode_arg_value(&SyscallType::Fd, 2).display.contains("stderr"));
    assert_eq!(decode_arg_value(&SyscallType::Fd, 5).display, "5");
}

#[test]
fn decode_fd_negative() {
    // -1 in low32 — raw value: 0xFFFFFFFF
    let d = decode_arg_value(&SyscallType::Fd, 0xFFFF_FFFF);
    assert!(d.display.contains("bad fd"), "got {}", d.display);
}

#[test]
fn decode_pid_zero_negative_positive() {
    assert!(decode_arg_value(&SyscallType::Pid, 0).display.contains("self"));
    assert!(decode_arg_value(&SyscallType::Pid, 0xFFFF_FFFF).display.contains("process group"));
    assert_eq!(decode_arg_value(&SyscallType::Pid, 1234).display, "1234");
}

#[test]
fn decode_signal_known_and_unknown() {
    assert_eq!(decode_arg_value(&SyscallType::Signal, 9).display, "SIGKILL");
    assert_eq!(decode_arg_value(&SyscallType::Signal, 15).display, "SIGTERM");
    // Unknown signal falls back to numeric
    let d = decode_arg_value(&SyscallType::Signal, 999);
    assert_eq!(d.display, "999");
}

#[test]
fn decode_ptr_null_vs_addr() {
    let d = decode_arg_value(&SyscallType::Ptr, 0);
    assert!(d.is_null);
    assert_eq!(d.display, "NULL");
    let d2 = decode_arg_value(&SyscallType::Ptr, 0xdead_beef);
    assert!(!d2.is_null);
    assert!(d2.display.contains("0x"));
}

#[test]
fn decode_userptr_kernelptr_buffer_null_and_addr() {
    for ty in [
        SyscallType::UserPtr,
        SyscallType::KernelPtr,
        SyscallType::Buffer { size_arg: Some(1) },
    ] {
        assert!(decode_arg_value(&ty, 0).is_null);
        assert!(!decode_arg_value(&ty, 0x1000).is_null);
    }
}

#[test]
fn decode_string_null_and_addr() {
    assert!(decode_arg_value(&SyscallType::String, 0).is_null);
    assert!(!decode_arg_value(&SyscallType::WString, 0xabcd).is_null);
}

#[test]
fn decode_int_errno_negative_and_positive() {
    let pos = decode_arg_value(&SyscallType::Int, 7);
    assert_eq!(pos.display, "7");
    // -2 (ENOENT) in low32
    let neg = decode_arg_value(&SyscallType::Errno, 0xFFFF_FFFE);
    assert!(neg.display.contains("ENOENT"), "got {}", neg.display);
}

#[test]
fn decode_long_ssize_offset_signed() {
    let d = decode_arg_value(&SyscallType::Long, u64::MAX); // -1 i64
    assert_eq!(d.display, "-1");
    let d2 = decode_arg_value(&SyscallType::SSize, 100);
    assert_eq!(d2.display, "100");
}

#[test]
fn decode_mode_octal() {
    let d = decode_arg_value(&SyscallType::Mode, 0o755);
    assert_eq!(d.display, "0o0755");
}

#[test]
fn decode_clockid_known_unknown() {
    assert_eq!(decode_arg_value(&SyscallType::ClockId, 0).display, "CLOCK_REALTIME");
    assert_eq!(decode_arg_value(&SyscallType::ClockId, 9999).display, "CLOCK_UNKNOWN");
}

#[test]
fn decode_safamily_known_unknown() {
    assert_eq!(decode_arg_value(&SyscallType::SaFamily, 2).display, "AF_INET");
    assert_eq!(decode_arg_value(&SyscallType::SaFamily, 10).display, "AF_INET6");
    assert_eq!(decode_arg_value(&SyscallType::SaFamily, 60000).display, "AF_UNKNOWN");
}

#[test]
fn decode_socklen_low32() {
    let d = decode_arg_value(&SyscallType::Socklen, 0xFFFF_FFFF_0000_0010);
    assert_eq!(d.display, "16");
}

#[test]
fn decode_ipaddr_format() {
    // 127.0.0.1 little endian = 0x0100007F
    let d = decode_arg_value(&SyscallType::IpAddr, 0x0100_007F);
    assert_eq!(d.display, "127.0.0.1");
}

#[test]
fn decode_default_branch_numeric() {
    // Void / UInt / Size / Handle fall through to numeric
    assert_eq!(decode_arg_value(&SyscallType::Void, 42).display, "42");
    assert_eq!(decode_arg_value(&SyscallType::Size, 42).display, "42");
    assert_eq!(decode_arg_value(&SyscallType::Handle, 42).display, "42");
}

// ── signal/errno/clockid/sa_family tables ───────────────────────────────────
#[test]
fn signal_name_known() {
    assert_eq!(signal_name(1), Some("SIGHUP"));
    assert_eq!(signal_name(31), Some("SIGSYS"));
    assert_eq!(signal_name(0), None);
    assert_eq!(signal_name(64), None);
}

#[test]
fn errno_name_known() {
    assert_eq!(errno_name(1), Some("EPERM"));
    assert_eq!(errno_name(38), Some("ENOSYS"));
    assert_eq!(errno_name(0), None);
    assert_eq!(errno_name(9999), None);
}

#[test]
fn clock_id_known() {
    assert_eq!(clock_id_name(0), Some("CLOCK_REALTIME"));
    assert_eq!(clock_id_name(9), Some("CLOCK_BOOTTIME_ALARM"));
    assert_eq!(clock_id_name(99), None);
}

#[test]
fn sa_family_known() {
    assert_eq!(sa_family_name(0), Some("AF_UNSPEC"));
    assert_eq!(sa_family_name(2), Some("AF_INET"));
    assert_eq!(sa_family_name(41), Some("AF_VSOCK"));
    assert_eq!(sa_family_name(60000), None);
}

// ── SyscallArg / Syscall ────────────────────────────────────────────────────
#[test]
fn syscall_arg_optional_default_false() {
    let a = SyscallArg::new("x", SyscallType::Int, ArgDirection::In);
    assert!(!a.optional);
    let a2 = a.optional();
    assert!(a2.optional);
}

#[test]
fn syscall_decode_args_pads_missing() {
    let s = open_syscall();
    // pass only 1 arg though syscall has 3 — missing get 0
    let decoded = s.decode_args(&[0xdead]);
    assert_eq!(decoded.len(), 3);
    assert!(decoded[1].display == "0" || decoded[1].display == "false" || decoded[1].display.contains('0'));
}

#[test]
fn syscall_decode_args_extras_ignored() {
    let s = open_syscall();
    let decoded = s.decode_args(&[1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(decoded.len(), 3);
}

#[test]
fn syscall_prototype_contains_name_and_args() {
    let s = open_syscall();
    let p = s.prototype();
    assert!(p.contains("open"));
    assert!(p.contains("pathname"));
    assert!(p.contains("flags"));
    assert!(p.contains("mode"));
}

#[test]
fn syscall_has_output_args() {
    let s = open_syscall();
    assert!(!s.has_output_args());
    let s2 = SyscallBuilder::new(0, "read", OsFamily::Linux, SyscallArch::X86_64)
        .arg("buf", SyscallType::Ptr, ArgDirection::Out)
        .build();
    assert!(s2.has_output_args());
}

#[test]
fn syscall_input_arg_count() {
    let s = open_syscall();
    assert_eq!(s.input_arg_count(), 3);
    let s2 = SyscallBuilder::new(0, "x", OsFamily::Linux, SyscallArch::X86_64)
        .arg("a", SyscallType::Int, ArgDirection::In)
        .arg("b", SyscallType::Int, ArgDirection::Out)
        .arg("c", SyscallType::Int, ArgDirection::InOut)
        .build();
    assert_eq!(s2.input_arg_count(), 1);
}

#[test]
fn syscall_target_new() {
    let t = SyscallTarget::new(OsFamily::Linux, SyscallArch::Arm64);
    assert_eq!(t.os, OsFamily::Linux);
    assert_eq!(t.arch, SyscallArch::Arm64);
    let s = Syscall::new(
        100,
        "foo",
        t,
        vec![],
        SyscallType::Void,
        SyscallCategory::System,
        "desc",
    );
    assert_eq!(s.number, 100);
    assert_eq!(s.os, OsFamily::Linux);
    assert_eq!(s.arch, SyscallArch::Arm64);
}

// ── SyscallDatabase ─────────────────────────────────────────────────────────
#[test]
fn database_empty_len_and_lookup() {
    let db = SyscallDatabase::new();
    assert!(db.is_empty());
    assert_eq!(db.len(), 0);
    assert!(db.lookup(OsFamily::Linux, SyscallArch::X86_64, 0).is_none());
    assert!(db.lookup_by_name(OsFamily::Linux, SyscallArch::X86_64, "x").is_none());
}

#[test]
fn database_alias_lookup() {
    let mut db = SyscallDatabase::new();
    let s = SyscallBuilder::new(2, "open", OsFamily::Linux, SyscallArch::X86_64)
        .alias("open64")
        .build();
    db.insert(s);
    let by_alias = db.lookup_by_name(OsFamily::Linux, SyscallArch::X86_64, "open64");
    assert!(by_alias.is_some(), "alias lookup failed");
    assert_eq!(by_alias.unwrap().name, "open");
}

#[test]
fn database_arch_isolation() {
    let mut db = SyscallDatabase::new();
    db.insert(SyscallBuilder::new(0, "read", OsFamily::Linux, SyscallArch::X86_64).build());
    assert!(db.lookup(OsFamily::Linux, SyscallArch::Arm64, 0).is_none());
    assert!(db.lookup_by_name(OsFamily::Windows, SyscallArch::X86_64, "read").is_none());
}

#[test]
fn database_stats_breakdowns() {
    let mut db = SyscallDatabase::new();
    db.insert(SyscallBuilder::new(0, "a", OsFamily::Linux, SyscallArch::X86_64)
        .category(SyscallCategory::FileSystem).build());
    db.insert(SyscallBuilder::new(1, "b", OsFamily::Linux, SyscallArch::X86_64)
        .category(SyscallCategory::FileSystem).risk(RiskLevel::High).build());
    let stats = db.stats();
    assert_eq!(stats.total, 2);
    assert_eq!(stats.by_category.get(&SyscallCategory::FileSystem), Some(&2));
    assert_eq!(stats.by_risk.get("high"), Some(&1));
}

// ── SyscallTable ────────────────────────────────────────────────────────────
#[test]
fn table_static_linux_x86_64_lookups() {
    assert_eq!(SyscallTable::number_to_name(0, "x86_64"), "read");
    assert_eq!(SyscallTable::number_to_name(1, "x86_64"), "write");
    assert_eq!(SyscallTable::number_to_name(2, "X86_64"), "open"); // case-insensitive
    assert_eq!(SyscallTable::number_to_name(329, "x86_64"), "pkey_mprotect");
    assert_eq!(SyscallTable::number_to_name(99999, "x86_64"), UNKNOWN_SYSCALL);
    assert_eq!(SyscallTable::number_to_name(0, "bogus_arch"), UNKNOWN_SYSCALL);
}

#[test]
fn table_static_arm64_and_windows() {
    assert_eq!(SyscallTable::number_to_name(63, "arm64"), "read");
    assert_eq!(SyscallTable::number_to_name(64, "aarch64"), "write");
    assert_eq!(SyscallTable::number_to_name(0, "windows_x64"), "NtReadFile");
    assert_eq!(SyscallTable::number_to_name(0, "win_x64"), "NtReadFile");
    assert_eq!(SyscallTable::number_to_name(0, "x64"), "NtReadFile");
}

#[test]
fn table_name_to_number_roundtrip() {
    let n = SyscallTable::name_to_number("write", "x86_64").unwrap();
    assert_eq!(n, 1);
    assert_eq!(SyscallTable::number_to_name(n, "x86_64"), "write");
    assert_eq!(SyscallTable::name_to_number("nosuch_syscall_zzz", "x86_64"), None);
    assert_eq!(SyscallTable::name_to_number("read", "bogus"), None);
}

#[test]
fn table_factory_linux_x86_64() {
    let t = SyscallTable::linux_x86_64();
    assert!(!t.is_empty());
    assert_eq!(t.os, OsFamily::Linux);
    assert_eq!(t.arch, SyscallArch::X86_64);
    let e = t.lookup(0).unwrap();
    assert_eq!(e.name, "read");
    assert_eq!(t.max_number(), 329);
}

#[test]
fn table_factory_windows_category_system() {
    let t = SyscallTable::windows_x64();
    let e = t.lookup(0).unwrap();
    assert_eq!(e.category, SyscallCategory::System);
}

#[test]
fn table_tsv_header_and_rows() {
    let t = SyscallTable::linux_x86_64();
    let tsv = t.to_tsv();
    assert!(tsv.starts_with("number\tname\tcategory\trisk\tparams\n"));
    assert!(tsv.contains("\tread\t"));
}

#[test]
fn table_lookup_by_name_and_filters() {
    let t = SyscallTable::linux_x86_64();
    assert!(t.lookup_by_name("read").is_some());
    assert!(t.lookup_by_name("__nope__").is_none());
    // Factory entries are Low risk; min_risk High → empty
    assert!(t.by_risk(RiskLevel::High).is_empty());
}

// ── SyscallCall ─────────────────────────────────────────────────────────────
#[test]
fn syscall_call_is_error() {
    let c = ret0_call(open_syscall(), vec![], -1, 100, 1);
    assert!(c.is_error());
    let c2 = ret0_call(open_syscall(), vec![], 3, 100, 1);
    assert!(!c2.is_error());
}

#[test]
fn syscall_call_elapsed_us_saturating() {
    let c = ret0_call(open_syscall(), vec![], 0, 1_000_000, 1);
    assert_eq!(c.elapsed_us(0), 1_000); // 1ms = 1000us
    // base ahead of call timestamp → saturates to 0
    assert_eq!(c.elapsed_us(2_000_000), 0);
}

#[test]
fn syscall_call_tag() {
    let mut c = ret0_call(open_syscall(), vec![], 0, 0, 1);
    c.tag("suspicious");
    assert_eq!(c.tags, vec!["suspicious".to_string()]);
}

#[test]
fn syscall_call_decoded_args() {
    let c = ret0_call(open_syscall(), vec![0xdead, 0, 0o644], 3, 0, 1);
    let d = c.decoded_args();
    assert_eq!(d.len(), 3);
    assert!(d[0].display.contains("0x"));
    assert_eq!(d[2].display, "0o0644");
}

// ── SyscallTrace ────────────────────────────────────────────────────────────
fn build_trace() -> SyscallTrace {
    let mut t = SyscallTrace::new();
    t.push(ret0_call(open_syscall(), vec![0, 0, 0], 3, 1_000, 100));
    t.push(ret0_call(open_syscall(), vec![0, 0, 0], -1, 2_000, 100));
    t.push(ret0_call(open_syscall(), vec![0, 0, 0], 4, 3_000, 200));
    t
}

#[test]
fn trace_push_and_len() {
    let t = build_trace();
    assert_eq!(t.len(), 3);
    assert!(!t.is_empty());
}

#[test]
fn trace_error_rate_and_calls() {
    let t = build_trace();
    let err = t.error_calls();
    assert_eq!(err.len(), 1);
    let r = t.error_rate();
    assert!((r - (1.0 / 3.0)).abs() < 1e-6, "got {r}");
}

#[test]
fn trace_error_rate_empty_zero() {
    let t = SyscallTrace::new();
    assert_eq!(t.error_rate(), 0.0);
}

#[test]
fn trace_for_pid_and_split() {
    let t = build_trace();
    assert_eq!(t.for_pid(100).len(), 2);
    assert_eq!(t.for_pid(200).len(), 1);
    let split = t.split_by_pid();
    assert_eq!(split.len(), 2);
    assert_eq!(split[&100].len(), 2);
}

#[test]
fn trace_unique_pids_sorted() {
    let t = build_trace();
    assert_eq!(t.unique_pids(), vec![100, 200]);
}

#[test]
fn trace_duration_ns() {
    let t = build_trace();
    assert_eq!(t.duration_ns(), 2_000);
}

#[test]
fn trace_call_and_category_counts() {
    let t = build_trace();
    assert_eq!(t.call_counts().get("open"), Some(&3));
    assert_eq!(t.category_counts().get(&SyscallCategory::FileSystem), Some(&3));
}

#[test]
fn trace_top_calls_truncates() {
    let t = build_trace();
    let top = t.top_calls(1);
    assert_eq!(top.len(), 1);
    assert_eq!(top[0].0, "open");
    assert_eq!(top[0].1, 3);
}

#[test]
fn trace_summary_nonempty() {
    let t = build_trace();
    let s = t.summary();
    assert!(s.contains("Trace:"));
    assert!(s.contains("open"));
}

#[test]
fn trace_filter_predicate() {
    let t = build_trace();
    let only_err = t.filter(rustre_syscalls::SyscallCall::is_error);
    assert_eq!(only_err.len(), 1);
}

#[test]
fn trace_apply_filter_errors_only() {
    let t = build_trace();
    let filt = SyscallFilter::new().errors_only();
    let out = t.apply_filter(&filt);
    assert_eq!(out.len(), 1);
}

// ── SyscallFilter ───────────────────────────────────────────────────────────
#[test]
fn filter_default_passes_everything() {
    let c = ret0_call(open_syscall(), vec![], 0, 0, 1);
    assert!(SyscallFilter::new().matches(&c));
}

#[test]
fn filter_category() {
    let c = ret0_call(open_syscall(), vec![], 0, 0, 1);
    assert!(SyscallFilter::new().with_category(SyscallCategory::FileSystem).matches(&c));
    assert!(!SyscallFilter::new().with_category(SyscallCategory::Memory).matches(&c));
}

#[test]
fn filter_name_pattern_substring() {
    let c = ret0_call(open_syscall(), vec![], 0, 0, 1);
    assert!(SyscallFilter::new().with_name_pattern("ope").matches(&c));
    assert!(!SyscallFilter::new().with_name_pattern("xyz").matches(&c));
}

#[test]
fn filter_name_exclude_exact() {
    let c = ret0_call(open_syscall(), vec![], 0, 0, 1);
    assert!(!SyscallFilter::new().with_name_exclude("open").matches(&c));
    assert!(SyscallFilter::new().with_name_exclude("close").matches(&c));
}

#[test]
fn filter_arg_range() {
    let c = ret0_call(open_syscall(), vec![5, 0, 0], 0, 0, 1);
    assert!(SyscallFilter::new().with_arg_range(0, 0..=10).matches(&c));
    assert!(!SyscallFilter::new().with_arg_range(0, 100..=200).matches(&c));
    // Index out of range: filter docs say it's used only if Some(v)
    assert!(SyscallFilter::new().with_arg_range(99, 0..=1).matches(&c));
}

#[test]
fn filter_pid_tid() {
    let c = ret0_call(open_syscall(), vec![], 0, 0, 42);
    assert!(SyscallFilter::new().with_pid(42).matches(&c));
    assert!(!SyscallFilter::new().with_pid(7).matches(&c));
    assert!(SyscallFilter::new().with_tid(42).matches(&c));
    assert!(!SyscallFilter::new().with_tid(99).matches(&c));
}

#[test]
fn filter_min_risk() {
    let s = SyscallBuilder::new(0, "x", OsFamily::Linux, SyscallArch::X86_64)
        .risk(RiskLevel::High).build();
    let c = ret0_call(s, vec![], 0, 0, 1);
    assert!(SyscallFilter::new().with_min_risk(RiskLevel::Medium).matches(&c));
    assert!(SyscallFilter::new().with_min_risk(RiskLevel::High).matches(&c));
    assert!(!SyscallFilter::new().with_min_risk(RiskLevel::Critical).matches(&c));
}

#[test]
fn filter_errors_only() {
    let ok = ret0_call(open_syscall(), vec![], 0, 0, 1);
    let bad = ret0_call(open_syscall(), vec![], -1, 0, 1);
    let f = SyscallFilter::new().errors_only();
    assert!(!f.matches(&ok));
    assert!(f.matches(&bad));
}

// ── SyscallFormatter ────────────────────────────────────────────────────────
#[test]
fn formatter_default_basic() {
    let c = ret0_call(open_syscall(), vec![0xdead, 0, 0o644], 3, 0, 1);
    let s = SyscallFormatter::new().format(&c);
    assert!(s.starts_with("open("));
    assert!(s.contains("= 3"));
}

#[test]
fn formatter_pid_and_timestamp_prefix() {
    let c = ret0_call(open_syscall(), vec![0, 0, 0], 0, 12345, 7);
    let s = SyscallFormatter::new().with_pid().with_timestamp().format(&c);
    assert!(s.contains("[pid"));
    assert!(s.contains("12345"));
}

#[test]
fn formatter_decode_changes_output() {
    let c = ret0_call(open_syscall(), vec![0, 0, 0o644], 3, 0, 1);
    let dec = SyscallFormatter::new().with_decode().format(&c);
    // With decoding the Mode arg should be 0o0644
    assert!(dec.contains("0o0644"));
    // decoded_args path also surfaces is_null markers via DecodedArg.display
    let c_null = ret0_call(open_syscall(), vec![0, 0, 0], 0, 0, 1);
    let dec_null = SyscallFormatter::new().with_decode().format(&c_null);
    assert!(dec_null.contains("NULL"));
}

#[test]
fn formatter_prototype_comment() {
    let c = ret0_call(open_syscall(), vec![], 0, 0, 1);
    let s = SyscallFormatter::new().with_prototype().format(&c);
    assert!(s.contains("/*"));
    assert!(s.contains("open"));
}

#[test]
fn formatter_error_ret_renders_errno() {
    let c = ret0_call(open_syscall(), vec![], -2, 0, 1);
    let s = SyscallFormatter::new().format(&c);
    assert!(s.contains("ENOENT"), "got: {s}");
}

#[test]
fn formatter_format_trace_multi_line() {
    let t = build_trace();
    let s = SyscallFormatter::new().format_trace(&t);
    assert_eq!(s.lines().count(), 3);
}

#[test]
fn call_prefix_show_flags() {
    assert!(!CallPrefix::None.show_pid());
    assert!(!CallPrefix::None.show_timestamp());
    assert!(CallPrefix::Pid.show_pid());
    assert!(!CallPrefix::Pid.show_timestamp());
    assert!(!CallPrefix::Timestamp.show_pid());
    assert!(CallPrefix::Timestamp.show_timestamp());
    assert!(CallPrefix::Both.show_pid());
    assert!(CallPrefix::Both.show_timestamp());
}

#[test]
fn formatter_format_arg_static() {
    assert_eq!(SyscallFormatter::format_arg(&SyscallType::Bool, 1), "true");
    assert_eq!(SyscallFormatter::format_arg(&SyscallType::Mode, 0o755), "0o0755");
}

// ── Seccomp ─────────────────────────────────────────────────────────────────
#[test]
fn seccomp_action_display() {
    assert_eq!(SeccompAction::Allow.to_string(), "ALLOW");
    assert_eq!(SeccompAction::Kill.to_string(), "KILL");
    assert_eq!(SeccompAction::Trap.to_string(), "TRAP");
    assert_eq!(SeccompAction::Log.to_string(), "LOG");
    assert_eq!(SeccompAction::Errno(13).to_string(), "ERRNO(13)");
    assert_eq!(SeccompAction::Trace(7).to_string(), "TRACE(7)");
}

#[test]
fn seccomp_policy_default_action() {
    let p = SeccompPolicy::new("p", SeccompAction::Kill);
    assert_eq!(p.evaluate(0, SyscallArch::X86_64), SeccompAction::Kill);
}

#[test]
fn seccomp_policy_rule_match_and_arch() {
    let mut p = SeccompPolicy::new("p", SeccompAction::Kill);
    p.add_rule(SeccompRule::new(1, SeccompAction::Allow, SyscallArch::X86_64, ""));
    assert_eq!(p.evaluate(1, SyscallArch::X86_64), SeccompAction::Allow);
    // Different arch — falls through to default
    assert_eq!(p.evaluate(1, SyscallArch::Arm64), SeccompAction::Kill);
    assert!(p.would_allow(1, SyscallArch::X86_64));
    assert!(!p.would_allow(1, SyscallArch::Arm64));
}

#[test]
fn seccomp_allowed_and_denied() {
    let mut p = SeccompPolicy::new("p", SeccompAction::Allow);
    p.add_rule(SeccompRule::new(1, SeccompAction::Allow, SyscallArch::X86_64, ""));
    p.add_rule(SeccompRule::new(2, SeccompAction::Kill, SyscallArch::X86_64, ""));
    p.add_rule(SeccompRule::new(3, SeccompAction::Errno(13), SyscallArch::X86_64, ""));
    assert_eq!(p.allowed_syscalls(), vec![1]);
    let denied = p.denied_syscalls();
    assert!(denied.contains(&2));
    assert!(denied.contains(&3));
}

#[test]
fn seccomp_rule_counts() {
    let mut p = SeccompPolicy::new("p", SeccompAction::Allow);
    p.add_rule(SeccompRule::new(1, SeccompAction::Allow, SyscallArch::X86_64, ""));
    p.add_rule(SeccompRule::new(2, SeccompAction::Allow, SyscallArch::X86_64, ""));
    p.add_rule(SeccompRule::new(3, SeccompAction::Kill, SyscallArch::X86_64, ""));
    let c = p.rule_counts();
    assert_eq!(c.get("ALLOW"), Some(&2));
    assert_eq!(c.get("KILL"), Some(&1));
}

// ── categorize_by_name / estimate_risk ──────────────────────────────────────
#[test]
fn categorize_filesystem_terms() {
    assert_eq!(categorize_by_name("open"), SyscallCategory::FileSystem);
    assert_eq!(categorize_by_name("read"), SyscallCategory::FileSystem);
    assert_eq!(categorize_by_name("ioctl"), SyscallCategory::FileSystem);
}

#[test]
fn categorize_memory_terms() {
    assert_eq!(categorize_by_name("mmap"), SyscallCategory::Memory);
    assert_eq!(categorize_by_name("mprotect"), SyscallCategory::Memory);
}

#[test]
fn categorize_process_thread_etc() {
    assert_eq!(categorize_by_name("fork"), SyscallCategory::Process);
    assert_eq!(categorize_by_name("futex"), SyscallCategory::Thread);
    assert_eq!(categorize_by_name("socket"), SyscallCategory::Network);
    assert_eq!(categorize_by_name("pipe"), SyscallCategory::Ipc);
    assert_eq!(categorize_by_name("rt_sigaction"), SyscallCategory::Signal);
    assert_eq!(categorize_by_name("nanosleep"), SyscallCategory::Time);
    assert_eq!(categorize_by_name("tty"), SyscallCategory::Device);
    assert_eq!(categorize_by_name("setuid"), SyscallCategory::Security);
    assert_eq!(categorize_by_name("uname"), SyscallCategory::System);
    assert_eq!(categorize_by_name("zzzzz_unknown"), SyscallCategory::Unknown);
}

#[test]
fn estimate_risk_critical_and_high() {
    assert_eq!(estimate_risk("ptrace", SyscallCategory::Process), RiskLevel::Critical);
    assert_eq!(estimate_risk("kexec_load", SyscallCategory::System), RiskLevel::Critical);
    assert_eq!(estimate_risk("execve", SyscallCategory::Process), RiskLevel::High);
    assert_eq!(estimate_risk("mprotect", SyscallCategory::Memory), RiskLevel::High);
}

#[test]
fn estimate_risk_medium_default() {
    assert_eq!(estimate_risk("recv", SyscallCategory::Network), RiskLevel::Medium);
    assert_eq!(estimate_risk("pipe", SyscallCategory::Ipc), RiskLevel::Medium);
    assert_eq!(estimate_risk("getpid", SyscallCategory::Process), RiskLevel::Medium);
    assert_eq!(estimate_risk("foo", SyscallCategory::FileSystem), RiskLevel::Low);
}

// ── SyscallStore (in-memory sqlite) ─────────────────────────────────────────
#[test]
fn store_sqlite_roundtrip() {
    let store = SyscallStore::open_sqlite(":memory:").expect("open");
    let c = ret0_call(open_syscall(), vec![1, 2, 3], 7, 1_500_000, 100);
    store.save(&c).unwrap();
    assert_eq!(store.count().unwrap(), 1);
    let rows = store.query_by_pid(100).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].pid, 100);
    assert_eq!(rows[0].ret, 7);
    assert_eq!(rows[0].name, "open");
    let by_name = store.query_by_name("ope").unwrap();
    assert_eq!(by_name.len(), 1);
    let by_time = store.query_by_time_range(0, 2_000_000).unwrap();
    assert_eq!(by_time.len(), 1);
    let outside = store.query_by_time_range(10, 100).unwrap();
    assert_eq!(outside.len(), 0);
    store.clear().unwrap();
    assert_eq!(store.count().unwrap(), 0);
}

#[test]
fn store_save_trace_persists_all() {
    let store = SyscallStore::open_sqlite(":memory:").unwrap();
    let t = build_trace();
    store.save_trace(&t).unwrap();
    assert_eq!(store.count().unwrap(), 3);
}

#[test]
fn store_mysql_invalid_dsn_errors() {
    // Should fail fast on bad DSN (not panic)
    let r = SyscallStore::open_mysql("not a valid dsn ://");
    assert!(r.is_err());
}

// ── DecodedArg Display & Eq ─────────────────────────────────────────────────
#[test]
fn decoded_arg_display_and_eq() {
    let d = DecodedArg::new(5, "five", false);
    assert_eq!(d.to_string(), "five");
    let d2 = DecodedArg::new(5, "five", false);
    assert_eq!(d, d2);
}
