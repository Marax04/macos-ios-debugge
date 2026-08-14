//! blitz2 — deep adversarial coverage for rustre-syscalls public API.

use rustre_syscalls::*;

// ─── Deterministic seeded LCG ────────────────────────────────────────────────
struct Lcg(u64);
impl Lcg {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

fn mk_open() -> Syscall {
    SyscallBuilder::new(2, "open", OsFamily::Linux, SyscallArch::X86_64)
        .arg("pathname", SyscallType::String, ArgDirection::In)
        .arg("flags", SyscallType::Flags("int".into()), ArgDirection::In)
        .opt_arg("mode", SyscallType::Mode, ArgDirection::In)
        .returns(SyscallType::Fd)
        .category(SyscallCategory::FileSystem)
        .description("open")
        .build()
}

fn mk_read() -> Syscall {
    SyscallBuilder::new(0, "read", OsFamily::Linux, SyscallArch::X86_64)
        .arg("fd", SyscallType::Fd, ArgDirection::In)
        .arg(
            "buf",
            SyscallType::Buffer { size_arg: Some(2) },
            ArgDirection::Out,
        )
        .arg("count", SyscallType::Size, ArgDirection::In)
        .returns(SyscallType::SSize)
        .category(SyscallCategory::FileSystem)
        .build()
}

fn mk_mprotect() -> Syscall {
    SyscallBuilder::new(10, "mprotect", OsFamily::Linux, SyscallArch::X86_64)
        .arg("addr", SyscallType::UserPtr, ArgDirection::In)
        .arg("len", SyscallType::Size, ArgDirection::In)
        .arg("prot", SyscallType::Flags("int".into()), ArgDirection::In)
        .returns(SyscallType::Long)
        .category(SyscallCategory::Memory)
        .risk(RiskLevel::High)
        .build()
}

fn mk_call(s: Syscall, pid: u32, ret: i64, ts: u64) -> SyscallCall {
    SyscallCall::new(s, vec![0x100, 0, 0], ret, ts, pid, pid)
}

// ─── 1. decode_arg_value never panics on LCG fuzz ───────────────────────────
#[test]
fn fuzz_decode_arg_never_panics() {
    let mut g = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    let tys = [
        SyscallType::Void,
        SyscallType::Int,
        SyscallType::UInt,
        SyscallType::Long,
        SyscallType::ULong,
        SyscallType::Ptr,
        SyscallType::Handle,
        SyscallType::Bool,
        SyscallType::Fd,
        SyscallType::Pid,
        SyscallType::Tid,
        SyscallType::Size,
        SyscallType::SSize,
        SyscallType::Errno,
        SyscallType::Buffer { size_arg: Some(1) },
        SyscallType::String,
        SyscallType::WString,
        SyscallType::Struct("foo".into()),
        SyscallType::Enum("foo".into()),
        SyscallType::Flags("foo".into()),
        SyscallType::UserPtr,
        SyscallType::KernelPtr,
        SyscallType::SaFamily,
        SyscallType::Offset,
        SyscallType::Mode,
        SyscallType::Signal,
        SyscallType::ClockId,
        SyscallType::FdArray,
        SyscallType::Socklen,
        SyscallType::IpAddr,
    ];
    for _ in 0..200 {
        for t in &tys {
            let raw = g.next();
            let d = decode_arg_value(t, raw);
            assert_eq!(d.raw, raw);
            assert!(!d.display.is_empty());
        }
    }
}

// ─── 2. Boundary decoding values ─────────────────────────────────────────────
#[test]
fn decode_boundary_zero_and_max() {
    let zero = decode_arg_value(&SyscallType::Ptr, 0);
    assert!(zero.is_null);
    let max = decode_arg_value(&SyscallType::Ptr, u64::MAX);
    assert!(!max.is_null);
    let int_max = decode_arg_value(&SyscallType::Int, u64::from(u32::MAX));
    // u32::MAX as i32 = -1 -> errno
    assert!(int_max.display.contains("-1"));
}

#[test]
fn decode_fd_special_values() {
    assert!(decode_arg_value(&SyscallType::Fd, 0).display.contains("stdin"));
    assert!(decode_arg_value(&SyscallType::Fd, 1).display.contains("stdout"));
    assert!(decode_arg_value(&SyscallType::Fd, 2).display.contains("stderr"));
    let bad = decode_arg_value(&SyscallType::Fd, u64::from(u32::MAX)); // -1 as i32
    assert!(bad.display.contains("bad"));
}

#[test]
fn decode_pid_self_and_group() {
    assert!(decode_arg_value(&SyscallType::Pid, 0).display.contains("self"));
    let neg = decode_arg_value(&SyscallType::Pid, u64::from(u32::MAX));
    assert!(neg.display.contains("group") || neg.display.contains("-1"));
}

#[test]
fn decode_signal_known_and_unknown() {
    assert!(decode_arg_value(&SyscallType::Signal, 9).display.contains("SIGKILL"));
    let unk = decode_arg_value(&SyscallType::Signal, 9999);
    // Unknown signal falls back to number
    assert!(!unk.display.is_empty());
}

#[test]
fn decode_mode_format() {
    let d = decode_arg_value(&SyscallType::Mode, 0o7777);
    assert!(d.display.starts_with("0o"));
    let d = decode_arg_value(&SyscallType::Mode, 0o100_644);
    // masked to 0o7777
    assert!(d.display.contains("0644"));
}

#[test]
fn decode_ip_addr_format() {
    let raw = 0x0100_007f_u64;
    let d = decode_arg_value(&SyscallType::IpAddr, raw);
    assert_eq!(d.display, "127.0.0.1");
}

#[test]
fn decode_sa_family_known() {
    assert_eq!(
        decode_arg_value(&SyscallType::SaFamily, 2).display,
        "AF_INET"
    );
    assert_eq!(
        decode_arg_value(&SyscallType::SaFamily, 10).display,
        "AF_INET6"
    );
}

#[test]
fn decode_clock_id_known_and_unknown() {
    assert!(decode_arg_value(&SyscallType::ClockId, 0)
        .display
        .contains("CLOCK_REALTIME"));
    assert!(decode_arg_value(&SyscallType::ClockId, 9999)
        .display
        .contains("UNKNOWN"));
}

// ─── 3. signal_name / errno_name / clock_id_name / sa_family_name ────────────
#[test]
fn helper_lookups_total() {
    let mut g = Lcg::new(1);
    for _ in 0..500 {
        let n = (g.next() & 0xFFFF) as u32;
        let _ = signal_name(n);
        let _ = errno_name(n);
        let _ = clock_id_name(n);
        let _ = sa_family_name(n as u16);
    }
    assert_eq!(signal_name(0), None);
    assert_eq!(errno_name(0), None);
}

#[test]
fn signal_name_range() {
    for i in 1..=31u32 {
        assert!(signal_name(i).is_some(), "signal {i}");
    }
    assert!(signal_name(32).is_none());
}

// ─── 4. Display round-trip / consistency ─────────────────────────────────────
#[test]
fn os_family_display_unique() {
    let all = [
        OsFamily::Linux,
        OsFamily::Windows,
        OsFamily::MacOs,
        OsFamily::FreeBsd,
        OsFamily::OpenBsd,
    ];
    let mut seen = std::collections::HashSet::new();
    for o in all {
        assert!(seen.insert(o.to_string()));
    }
}

#[test]
fn arch_display_unique() {
    let all = [
        SyscallArch::X86,
        SyscallArch::X86_64,
        SyscallArch::Arm32,
        SyscallArch::Arm64,
        SyscallArch::Mips,
        SyscallArch::Riscv64,
    ];
    let mut seen = std::collections::HashSet::new();
    for a in all {
        assert!(seen.insert(a.to_string()));
    }
}

#[test]
fn risk_level_ord_total() {
    let levels = [
        RiskLevel::Benign,
        RiskLevel::Low,
        RiskLevel::Medium,
        RiskLevel::High,
        RiskLevel::Critical,
    ];
    for w in levels.windows(2) {
        assert!(w[0] < w[1]);
    }
}

#[test]
fn category_display_unique() {
    let all = [
        SyscallCategory::FileSystem,
        SyscallCategory::Memory,
        SyscallCategory::Process,
        SyscallCategory::Thread,
        SyscallCategory::Network,
        SyscallCategory::Ipc,
        SyscallCategory::Signal,
        SyscallCategory::Time,
        SyscallCategory::Device,
        SyscallCategory::Security,
        SyscallCategory::System,
        SyscallCategory::Unknown,
    ];
    let mut seen = std::collections::HashSet::new();
    for c in all {
        assert!(seen.insert(c.to_string()));
    }
}

// ─── 5. Hash/Eq consistency ───────────────────────────────────────────────────
#[test]
fn os_arch_hash_eq_consistency() {
    use std::collections::HashMap;
    let mut m: HashMap<(OsFamily, SyscallArch), u32> = HashMap::new();
    for _ in 0..30 {
        m.insert((OsFamily::Linux, SyscallArch::X86_64), 1);
    }
    assert_eq!(m.len(), 1);
    m.insert((OsFamily::Linux, SyscallArch::Arm64), 2);
    m.insert((OsFamily::Windows, SyscallArch::X86_64), 3);
    assert_eq!(m.len(), 3);
}

#[test]
fn risk_level_hash_eq() {
    use std::collections::HashSet;
    let mut s: HashSet<RiskLevel> = HashSet::new();
    for _ in 0..30 {
        s.insert(RiskLevel::High);
        s.insert(RiskLevel::Low);
    }
    assert_eq!(s.len(), 2);
}

// ─── 6. Database invariants ──────────────────────────────────────────────────
#[test]
fn database_lookup_round_trip_50() {
    let mut db = SyscallDatabase::new();
    for i in 0..50u64 {
        let s = SyscallBuilder::new(
            i,
            format!("sys{i}"),
            OsFamily::Linux,
            SyscallArch::X86_64,
        )
        .build();
        db.insert(s);
    }
    for i in 0..50u64 {
        let r = db.lookup(OsFamily::Linux, SyscallArch::X86_64, i).unwrap();
        assert_eq!(r.number, i);
        assert_eq!(r.name, format!("sys{i}"));
        let by_name = db
            .lookup_by_name(OsFamily::Linux, SyscallArch::X86_64, &format!("sys{i}"))
            .unwrap();
        assert_eq!(by_name.number, i);
    }
}

#[test]
fn database_lookup_wrong_os_arch_misses() {
    let mut db = SyscallDatabase::new();
    db.insert(mk_open());
    assert!(db.lookup(OsFamily::Windows, SyscallArch::X86_64, 2).is_none());
    assert!(db.lookup(OsFamily::Linux, SyscallArch::Arm64, 2).is_none());
}

#[test]
fn database_alias_lookup() {
    let mut db = SyscallDatabase::new();
    let s = SyscallBuilder::new(2, "open", OsFamily::Linux, SyscallArch::X86_64)
        .alias("open64")
        .alias("__open")
        .build();
    db.insert(s);
    assert!(db
        .lookup_by_name(OsFamily::Linux, SyscallArch::X86_64, "open64")
        .is_some());
    assert!(db
        .lookup_by_name(OsFamily::Linux, SyscallArch::X86_64, "__open")
        .is_some());
}

#[test]
fn database_merge_overwrite() {
    let mut a = SyscallDatabase::new();
    a.insert(mk_open());
    let mut b = SyscallDatabase::new();
    b.insert(mk_read());
    a.merge(b);
    assert_eq!(a.len(), 2);
    assert!(!a.is_empty());
}

#[test]
fn database_all_for_sorted_invariant() {
    let mut db = SyscallDatabase::new();
    for n in [9u64, 3, 7, 0, 5] {
        db.insert(
            SyscallBuilder::new(n, format!("s{n}"), OsFamily::Linux, SyscallArch::X86_64).build(),
        );
    }
    let v = db.all_for(OsFamily::Linux, SyscallArch::X86_64);
    let nums: Vec<u64> = v.iter().map(|s| s.number).collect();
    assert_eq!(nums, vec![0, 3, 5, 7, 9]);
}

#[test]
fn database_category_filter() {
    let mut db = SyscallDatabase::new();
    db.insert(mk_open());
    db.insert(mk_read());
    db.insert(mk_mprotect());
    let fs = db.all_for_category(
        OsFamily::Linux,
        SyscallArch::X86_64,
        SyscallCategory::FileSystem,
    );
    assert_eq!(fs.len(), 2);
    let mem = db.all_for_category(
        OsFamily::Linux,
        SyscallArch::X86_64,
        SyscallCategory::Memory,
    );
    assert_eq!(mem.len(), 1);
}

#[test]
fn database_high_risk_threshold() {
    let mut db = SyscallDatabase::new();
    db.insert(mk_open()); // Low
    db.insert(mk_mprotect()); // High
    assert_eq!(
        db.high_risk(OsFamily::Linux, SyscallArch::X86_64, RiskLevel::High)
            .len(),
        1
    );
    assert_eq!(
        db.high_risk(OsFamily::Linux, SyscallArch::X86_64, RiskLevel::Low)
            .len(),
        2
    );
    assert_eq!(
        db.high_risk(OsFamily::Linux, SyscallArch::X86_64, RiskLevel::Critical)
            .len(),
        0
    );
}

#[test]
fn database_stats_totals() {
    let mut db = SyscallDatabase::new();
    db.insert(mk_open());
    db.insert(mk_read());
    db.insert(mk_mprotect());
    let s = db.stats();
    assert_eq!(s.total, 3);
    let cat_total: usize = s.by_category.values().sum();
    assert_eq!(cat_total, 3);
}

// ─── 7. SyscallTable ─────────────────────────────────────────────────────────
#[test]
fn table_linux_x86_64_factory() {
    let t = SyscallTable::linux_x86_64();
    assert!(!t.is_empty());
    assert_eq!(t.os, OsFamily::Linux);
    assert_eq!(t.arch, SyscallArch::X86_64);
    let entry = t.lookup(0).unwrap();
    assert_eq!(entry.name, "read");
    let entry = t.lookup(2).unwrap();
    assert_eq!(entry.name, "open");
}

#[test]
fn table_lookup_round_trip_50() {
    let t = SyscallTable::linux_x86_64();
    for n in 0..50u64 {
        let e = t.lookup(n).unwrap();
        let again = t.lookup_by_name(&e.name).unwrap();
        assert_eq!(again.number, n);
    }
}

#[test]
fn table_lookup_missing() {
    let t = SyscallTable::linux_x86_64();
    assert!(t.lookup(u64::MAX).is_none());
    assert!(t.lookup_by_name("definitely_not_a_syscall").is_none());
}

#[test]
fn table_max_number_consistency() {
    let t = SyscallTable::linux_x86_64();
    let max = t.max_number();
    assert!(t.lookup(max).is_some());
}

#[test]
fn table_number_to_name_static() {
    assert_eq!(SyscallTable::number_to_name(0, "x86_64"), "read");
    assert_eq!(SyscallTable::number_to_name(0, "X86_64"), "read");
    assert_eq!(SyscallTable::number_to_name(0, "linux_x86_64"), "read");
    assert_eq!(SyscallTable::number_to_name(0, "arm64"), "io_setup");
    assert_eq!(SyscallTable::number_to_name(0, "bogus"), UNKNOWN_SYSCALL);
    assert_eq!(
        SyscallTable::number_to_name(u64::MAX, "x86_64"),
        UNKNOWN_SYSCALL
    );
}

#[test]
fn table_name_to_number_static() {
    assert_eq!(SyscallTable::name_to_number("read", "x86_64"), Some(0));
    assert_eq!(SyscallTable::name_to_number("read", "x86_64"), Some(0));
    assert_eq!(SyscallTable::name_to_number("read", "bogus"), None);
    assert_eq!(SyscallTable::name_to_number("no_such", "x86_64"), None);
}

#[test]
fn table_number_to_name_round_trip_fuzz() {
    let mut g = Lcg::new(7);
    for _ in 0..200 {
        let n = g.next() % 330;
        let name = SyscallTable::number_to_name(n, "x86_64");
        if name != UNKNOWN_SYSCALL {
            assert_eq!(SyscallTable::name_to_number(name, "x86_64"), Some(n));
        }
    }
}

#[test]
fn table_windows_x64_factory() {
    let t = SyscallTable::windows_x64();
    assert!(!t.is_empty());
    let entry = t.lookup(0).unwrap();
    assert_eq!(entry.name, "NtReadFile");
}

#[test]
fn table_tsv_lines() {
    let t = SyscallTable::linux_x86_64();
    let tsv = t.to_tsv();
    let lines = tsv.lines().count();
    // header + one per entry
    assert_eq!(lines, t.len() + 1);
}

// ─── 8. Syscall methods ──────────────────────────────────────────────────────
#[test]
fn syscall_prototype_format() {
    let p = mk_open().prototype();
    assert!(p.starts_with("int open("));
    assert!(p.contains("const char * pathname"));
}

#[test]
fn syscall_has_output_args_distinguishes() {
    assert!(mk_read().has_output_args());
    assert!(!mk_open().has_output_args());
}

#[test]
fn syscall_decode_args_handles_short_input() {
    let s = mk_open(); // 3 args
    // empty raw_args → all decoded as zero
    let d = s.decode_args(&[]);
    assert_eq!(d.len(), 3);
    for x in &d {
        assert_eq!(x.raw, 0);
    }
}

#[test]
fn syscall_decode_args_round_trip_fuzz() {
    let s = mk_open();
    let mut g = Lcg::new(2);
    for _ in 0..50 {
        let raw = vec![g.next(), g.next(), g.next()];
        let d = s.decode_args(&raw);
        assert_eq!(d.len(), 3);
        for (a, b) in raw.iter().zip(d.iter()) {
            assert_eq!(*a, b.raw);
        }
    }
}

// ─── 9. SyscallCall ──────────────────────────────────────────────────────────
#[test]
fn syscall_call_is_error_boundary() {
    let c0 = mk_call(mk_open(), 1, 0, 0);
    let cn1 = mk_call(mk_open(), 1, -1, 0);
    let cp1 = mk_call(mk_open(), 1, 1, 0);
    assert!(!c0.is_error());
    assert!(cn1.is_error());
    assert!(!cp1.is_error());
}

#[test]
fn syscall_call_elapsed_us_saturates() {
    let c = mk_call(mk_open(), 1, 0, 1_000_000);
    assert_eq!(c.elapsed_us(0), 1_000);
    // base > timestamp should saturate to 0, not underflow
    assert_eq!(c.elapsed_us(u64::MAX), 0);
}

#[test]
fn syscall_call_tag_pushes() {
    let mut c = mk_call(mk_open(), 1, 0, 0);
    c.tag("a");
    c.tag("b");
    assert_eq!(c.tags, vec!["a".to_string(), "b".to_string()]);
}

// ─── 10. SyscallTrace ────────────────────────────────────────────────────────
#[test]
fn trace_push_invariants() {
    let mut t = SyscallTrace::new();
    assert!(t.is_empty());
    for i in 0..50u64 {
        t.push(mk_call(mk_open(), 1, 3, i * 1000));
    }
    assert_eq!(t.len(), 50);
    assert!(!t.is_empty());
    assert_eq!(t.calls().len(), 50);
}

#[test]
fn trace_error_rate_boundary() {
    let empty = SyscallTrace::new();
    assert_eq!(empty.error_rate(), 0.0);
    let mut t = SyscallTrace::new();
    for _ in 0..4 {
        t.push(mk_call(mk_open(), 1, -1, 0));
    }
    assert!((t.error_rate() - 1.0).abs() < 1e-9);
}

#[test]
fn trace_duration_ns_saturates() {
    let t = SyscallTrace::new();
    assert_eq!(t.duration_ns(), 0);
    let mut t = SyscallTrace::new();
    t.push(mk_call(mk_open(), 1, 0, 100));
    t.push(mk_call(mk_open(), 1, 0, 50)); // backward time — should saturate
    assert_eq!(t.duration_ns(), 0);
}

#[test]
fn trace_top_calls_ordering() {
    let mut t = SyscallTrace::new();
    for _ in 0..3 {
        t.push(mk_call(mk_open(), 1, 0, 0));
    }
    for _ in 0..5 {
        t.push(mk_call(mk_read(), 1, 0, 0));
    }
    let top = t.top_calls(2);
    assert_eq!(top[0].0, "read");
    assert_eq!(top[0].1, 5);
    assert_eq!(top[1].0, "open");
    assert_eq!(top[1].1, 3);
}

#[test]
fn trace_per_pid_counts_and_split() {
    let mut t = SyscallTrace::new();
    for &pid in &[1u32, 2, 1, 3, 2, 1] {
        t.push(mk_call(mk_open(), pid, 0, 0));
    }
    let counts = t.per_pid_counts();
    assert_eq!(counts[&1], 3);
    assert_eq!(counts[&2], 2);
    assert_eq!(counts[&3], 1);
    let split = t.split_by_pid();
    assert_eq!(split[&1].len(), 3);
}

#[test]
fn trace_unique_pids_sorted() {
    let mut t = SyscallTrace::new();
    for &pid in &[5u32, 1, 5, 3, 1] {
        t.push(mk_call(mk_open(), pid, 0, 0));
    }
    assert_eq!(t.unique_pids(), vec![1, 3, 5]);
}

// ─── 11. SyscallFilter ───────────────────────────────────────────────────────
#[test]
fn filter_default_matches_all() {
    let f = SyscallFilter::new();
    assert!(f.matches(&mk_call(mk_open(), 1, 0, 0)));
    assert!(f.matches(&mk_call(mk_mprotect(), 99, -1, 0)));
}

#[test]
fn filter_combined_constraints() {
    let f = SyscallFilter::new()
        .with_pid(42)
        .with_category(SyscallCategory::FileSystem)
        .errors_only();
    let ok = mk_call(mk_open(), 42, -1, 0);
    assert!(f.matches(&ok));
    // wrong pid
    assert!(!f.matches(&mk_call(mk_open(), 99, -1, 0)));
    // wrong category
    assert!(!f.matches(&mk_call(mk_mprotect(), 42, -1, 0)));
    // not an error
    assert!(!f.matches(&mk_call(mk_open(), 42, 3, 0)));
}

#[test]
fn filter_arg_range() {
    let f = SyscallFilter::new().with_arg_range(0, 0x100..=0x100);
    let c = mk_call(mk_open(), 1, 0, 0); // args[0] = 0x100
    assert!(f.matches(&c));
    let f2 = SyscallFilter::new().with_arg_range(0, 0..=10);
    assert!(!f2.matches(&c));
}

#[test]
fn filter_tid_only() {
    let f = SyscallFilter::new().with_tid(7);
    assert!(!f.matches(&mk_call(mk_open(), 1, 0, 0))); // tid = pid = 1
    assert!(f.matches(&mk_call(mk_open(), 7, 0, 0)));
}

// ─── 12. SyscallFormatter ────────────────────────────────────────────────────
#[test]
fn formatter_prefix_state_machine() {
    let f = SyscallFormatter::new().with_pid().with_timestamp();
    assert!(f.prefix.show_pid());
    assert!(f.prefix.show_timestamp());
    let f2 = SyscallFormatter::new().with_timestamp().with_pid();
    assert!(f2.prefix.show_pid());
    assert!(f2.prefix.show_timestamp());
}

#[test]
fn formatter_trace_one_per_line() {
    let mut t = SyscallTrace::new();
    for _ in 0..5 {
        t.push(mk_call(mk_open(), 1, 3, 0));
    }
    let s = SyscallFormatter::new().format_trace(&t);
    assert_eq!(s.lines().count(), 5);
}

#[test]
fn formatter_decode_args_mode() {
    let f = SyscallFormatter::new().with_decode();
    let s = f.format(&mk_call(mk_open(), 1, 3, 0));
    assert!(s.contains("open("));
}

#[test]
fn formatter_errno_naming() {
    // -2 -> ENOENT
    let s = SyscallFormatter::new().format(&mk_call(mk_open(), 1, -2, 0));
    assert!(s.contains("ENOENT"));
}

// ─── 13. Seccomp policy state machine ─────────────────────────────────────────
#[test]
fn seccomp_rule_evaluation_order() {
    let mut p = SeccompPolicy::new("p", SeccompAction::Kill);
    p.add_rule(SeccompRule::new(
        1,
        SeccompAction::Allow,
        SyscallArch::X86_64,
        "first",
    ));
    p.add_rule(SeccompRule::new(
        1,
        SeccompAction::Errno(13),
        SyscallArch::X86_64,
        "second",
    ));
    // First match wins
    assert_eq!(p.evaluate(1, SyscallArch::X86_64), SeccompAction::Allow);
    // default for unknown
    assert_eq!(p.evaluate(99, SyscallArch::X86_64), SeccompAction::Kill);
    // wrong arch → default
    assert_eq!(p.evaluate(1, SyscallArch::Arm64), SeccompAction::Kill);
}

#[test]
fn seccomp_action_display_round_trip() {
    let cases = [
        (SeccompAction::Allow, "ALLOW"),
        (SeccompAction::Kill, "KILL"),
        (SeccompAction::Trap, "TRAP"),
        (SeccompAction::Errno(7), "ERRNO(7)"),
        (SeccompAction::Trace(3), "TRACE(3)"),
        (SeccompAction::Log, "LOG"),
    ];
    for (a, s) in cases {
        assert_eq!(a.to_string(), s);
    }
}

#[test]
fn seccomp_allowed_denied_disjoint() {
    let mut p = SeccompPolicy::new("p", SeccompAction::Allow);
    for n in 0..10u32 {
        let a = if n % 2 == 0 {
            SeccompAction::Allow
        } else {
            SeccompAction::Kill
        };
        p.add_rule(SeccompRule::new(n, a, SyscallArch::X86_64, "x"));
    }
    let allow = p.allowed_syscalls();
    let deny = p.denied_syscalls();
    assert_eq!(allow.len(), 5);
    assert_eq!(deny.len(), 5);
    for d in &deny {
        assert!(!allow.contains(d));
    }
}

#[test]
fn seccomp_rule_counts() {
    let mut p = SeccompPolicy::new("p", SeccompAction::Allow);
    p.add_rule(SeccompRule::new(
        1,
        SeccompAction::Allow,
        SyscallArch::X86_64,
        "",
    ));
    p.add_rule(SeccompRule::new(
        2,
        SeccompAction::Allow,
        SyscallArch::X86_64,
        "",
    ));
    p.add_rule(SeccompRule::new(
        3,
        SeccompAction::Kill,
        SyscallArch::X86_64,
        "",
    ));
    let c = p.rule_counts();
    assert_eq!(c["ALLOW"], 2);
    assert_eq!(c["KILL"], 1);
}

// ─── 14. Categorization ──────────────────────────────────────────────────────
#[test]
fn categorize_by_name_covers_all_groups() {
    assert_eq!(categorize_by_name("openat"), SyscallCategory::FileSystem);
    assert_eq!(categorize_by_name("mmap"), SyscallCategory::Memory);
    assert_eq!(categorize_by_name("execve"), SyscallCategory::Process);
    assert_eq!(categorize_by_name("futex"), SyscallCategory::Thread);
    assert_eq!(categorize_by_name("socket"), SyscallCategory::Network);
    assert_eq!(categorize_by_name("shmget"), SyscallCategory::Ipc);
    assert_eq!(categorize_by_name("rt_sigaction"), SyscallCategory::Signal);
    assert_eq!(categorize_by_name("clock_gettime"), SyscallCategory::Time);
    assert_eq!(
        categorize_by_name("xyzzyqwertydoesnotexist"),
        SyscallCategory::Unknown
    );
}

#[test]
fn estimate_risk_levels() {
    assert_eq!(
        estimate_risk("ptrace", SyscallCategory::Process),
        RiskLevel::Critical
    );
    assert_eq!(
        estimate_risk("mmap", SyscallCategory::Memory),
        RiskLevel::High
    );
    assert_eq!(
        estimate_risk("foo", SyscallCategory::Network),
        RiskLevel::Medium
    );
    assert_eq!(
        estimate_risk("foo", SyscallCategory::Unknown),
        RiskLevel::Low
    );
}

#[test]
fn estimate_risk_fuzz_never_panics() {
    let mut g = Lcg::new(99);
    let cats = [
        SyscallCategory::FileSystem,
        SyscallCategory::Memory,
        SyscallCategory::Process,
        SyscallCategory::Thread,
        SyscallCategory::Network,
        SyscallCategory::Ipc,
        SyscallCategory::Signal,
        SyscallCategory::Time,
        SyscallCategory::Device,
        SyscallCategory::Security,
        SyscallCategory::System,
        SyscallCategory::Unknown,
    ];
    for _ in 0..200 {
        let n = format!("name{}", g.next());
        let c = cats[usize::try_from(g.next()).unwrap_or(usize::MAX) % cats.len()];
        let _ = estimate_risk(&n, c);
        let _ = categorize_by_name(&n);
    }
}

// ─── 15. Persistent store (SQLite) ───────────────────────────────────────────
#[test]
fn store_round_trip_50() {
    let store = SyscallStore::open_sqlite(":memory:").unwrap();
    for i in 0..50u64 {
        store
            .save(&mk_call(mk_open(), 7, 3, i * 1000))
            .unwrap();
    }
    assert_eq!(store.count().unwrap(), 50);
    let rows = store.query_by_pid(7).unwrap();
    assert_eq!(rows.len(), 50);
    let rows = store.query_by_name("open").unwrap();
    assert_eq!(rows.len(), 50);
    let rows = store.query_by_time_range(0, 10_000).unwrap();
    assert_eq!(rows.len(), 11);
    store.clear().unwrap();
    assert_eq!(store.count().unwrap(), 0);
}

#[test]
fn store_query_misses_return_empty() {
    let store = SyscallStore::open_sqlite(":memory:").unwrap();
    assert_eq!(store.query_by_pid(0).unwrap().len(), 0);
    assert_eq!(store.query_by_name("nope").unwrap().len(), 0);
}

// ─── 16. Send+Sync threaded stress ───────────────────────────────────────────
#[test]
fn syscalltable_send_sync_threaded() {
    use std::sync::Arc;
    use std::thread;
    let t = Arc::new(SyscallTable::linux_x86_64());
    let mut handles = vec![];
    for tid in 0..4u64 {
        let t = Arc::clone(&t);
        handles.push(thread::spawn(move || {
            let mut g = Lcg::new(tid.wrapping_add(1).wrapping_mul(0x00AB_CDEF));
            for _ in 0..100 {
                let n = g.next() % 330;
                let _ = t.lookup(n);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn syscall_send_sync_threaded_decode() {
    use std::sync::Arc;
    use std::thread;
    let s = Arc::new(mk_open());
    let mut handles = vec![];
    for tid in 0..4u64 {
        let s = Arc::clone(&s);
        handles.push(thread::spawn(move || {
            let mut g = Lcg::new(tid.wrapping_add(7).wrapping_mul(0x0123_4567));
            for _ in 0..100 {
                let raw = vec![g.next(), g.next(), g.next()];
                let d = s.decode_args(&raw);
                assert_eq!(d.len(), 3);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── 17. Serde round-trip on key types ───────────────────────────────────────
#[test]
fn serde_round_trip_syscall() {
    let s = mk_open();
    let j = serde_json::to_string(&s).unwrap();
    let back: Syscall = serde_json::from_str(&j).unwrap();
    assert_eq!(back.number, s.number);
    assert_eq!(back.name, s.name);
    assert_eq!(back.args.len(), s.args.len());
}

#[test]
fn serde_round_trip_trace() {
    let mut t = SyscallTrace::new();
    for i in 0..10u64 {
        t.push(mk_call(mk_open(), 1, 3, i * 100));
    }
    let j = serde_json::to_string(&t).unwrap();
    let back: SyscallTrace = serde_json::from_str(&j).unwrap();
    assert_eq!(back.len(), t.len());
}

#[test]
fn serde_round_trip_seccomp_policy() {
    let mut p = SeccompPolicy::new("test", SeccompAction::Kill);
    p.add_rule(SeccompRule::new(
        1,
        SeccompAction::Allow,
        SyscallArch::X86_64,
        "x",
    ));
    let j = serde_json::to_string(&p).unwrap();
    let back: SeccompPolicy = serde_json::from_str(&j).unwrap();
    assert_eq!(back.rules.len(), 1);
    assert_eq!(back.name, "test");
}

// ─── 18. SyscallTarget ───────────────────────────────────────────────────────
#[test]
fn syscall_target_construction() {
    let t = SyscallTarget::new(OsFamily::Linux, SyscallArch::X86_64);
    assert_eq!(t.os, OsFamily::Linux);
    assert_eq!(t.arch, SyscallArch::X86_64);
}

// ─── 19. DecodedArg Display & equality ───────────────────────────────────────
#[test]
fn decoded_arg_display_and_eq() {
    let a = DecodedArg::new(42, "forty-two", false);
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(format!("{a}"), "forty-two");
}
