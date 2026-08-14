//! Deep adversarial test suite for rustre-syscalls-linux.

use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

use rustre_syscalls::SyscallArch;
use rustre_syscalls_linux::seccomp_profile_generator::{
    anti_debug_profile, minimal_sandbox_profile, ArgFilter, BpfFilter, PolicyKind,
    SeccompAction, SeccompProfileGenerator, SeccompRule,
};
use rustre_syscalls_linux::syscall_statistics::{
    PerSyscallStats, SyscallSample, SyscallStatistics, Timeline,
};
use rustre_syscalls_linux::{LinuxSyscallDb, LinuxSyscallError, SyscallParam, SyscallResolver};

// ─── LCG ──────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    const fn new(seed: u64) -> Self { Self(seed) }
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

const ARCHS: &[SyscallArch] = &[
    SyscallArch::X86_64,
    SyscallArch::X86,
    SyscallArch::Arm32,
    SyscallArch::Arm64,
];

// ─── Database / Resolver tests ────────────────────────────────────────────────

#[test]
fn db_default_populates_all_archs() {
    let db = LinuxSyscallDb::default();
    for a in ARCHS {
        assert!(db.arch_count(*a) > 0, "arch {a:?} empty");
    }
}

#[test]
fn db_all_for_arch_sorted_by_number() {
    let db = LinuxSyscallDb::new();
    for a in ARCHS {
        let table = db.all_for_arch(*a).expect("arch present");
        for w in table.windows(2) {
            assert!(w[0].number <= w[1].number, "table not sorted on {a:?}");
        }
    }
}

#[test]
fn db_lookup_by_known_number_succeeds() {
    let db = LinuxSyscallDb::new();
    let s = db.lookup(SyscallArch::X86_64, 0).expect("read=0");
    assert_eq!(s.name, "read");
}

#[test]
fn db_lookup_by_name_succeeds() {
    let db = LinuxSyscallDb::new();
    let s = db.lookup_by_name(SyscallArch::X86_64, "write").expect("write");
    assert_eq!(s.number, 1);
}

#[test]
fn db_lookup_unknown_number_returns_none() {
    let db = LinuxSyscallDb::new();
    assert!(db.lookup(SyscallArch::X86_64, u32::MAX).is_none());
}

#[test]
fn db_lookup_unknown_name_returns_none() {
    let db = LinuxSyscallDb::new();
    assert!(db.lookup_by_name(SyscallArch::X86_64, "definitely_not_a_syscall").is_none());
}

#[test]
fn db_lookup_by_number_then_name_round_trip() {
    let db = LinuxSyscallDb::new();
    for a in ARCHS {
        let table = db.all_for_arch(*a).unwrap();
        // Take first 50 entries
        for sc in table.iter().take(50) {
            let by_nr = db.lookup(*a, sc.number).unwrap();
            let by_name = db.lookup_by_name(*a, &sc.name).unwrap();
            assert_eq!(by_nr.number, sc.number);
            assert_eq!(by_name.name, sc.name);
        }
    }
}

#[test]
fn db_fuzz_lookup_never_panics() {
    let db = LinuxSyscallDb::new();
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..200 {
        let n = (lcg.next() & 0xFFFF) as u32;
        let arch = ARCHS[(lcg.next() % 4) as usize];
        let _ = db.lookup(arch, n);
    }
}

#[test]
fn db_arch_count_consistent_with_slice_len() {
    let db = LinuxSyscallDb::new();
    for a in ARCHS {
        let n = db.arch_count(*a);
        let slice_len = db.all_for_arch(*a).unwrap().len();
        assert_eq!(n, slice_len);
    }
}

#[test]
fn db_serde_round_trip() {
    let db = LinuxSyscallDb::new();
    let json = serde_json::to_string(&db).unwrap();
    let db2: LinuxSyscallDb = serde_json::from_str(&json).unwrap();
    for a in ARCHS {
        assert_eq!(db.arch_count(*a), db2.arch_count(*a));
    }
}

#[test]
fn resolver_new_matches_default() {
    let r1 = SyscallResolver::new();
    let r2 = SyscallResolver::default();
    assert_eq!(r1.all_for_arch(SyscallArch::X86_64).len(),
               r2.all_for_arch(SyscallArch::X86_64).len());
}

#[test]
fn resolver_with_db_preserves_lookups() {
    let db = LinuxSyscallDb::new();
    let r = SyscallResolver::with_db(db);
    assert!(r.lookup(SyscallArch::X86_64, 0).is_some());
    assert!(r.lookup_by_name(SyscallArch::X86_64, "read").is_some());
}

#[test]
fn resolver_all_for_arch_never_returns_empty_for_supported() {
    let r = SyscallResolver::new();
    for a in ARCHS {
        assert!(!r.all_for_arch(*a).is_empty());
    }
}

#[test]
fn resolver_db_accessor() {
    let r = SyscallResolver::new();
    assert!(r.db().arch_count(SyscallArch::X86_64) > 0);
}

#[test]
fn syscall_param_new_stores_fields() {
    let p = SyscallParam::new("fd", "int");
    assert_eq!(p.name, "fd");
    assert_eq!(p.ty, "int");
}

#[test]
fn linux_syscall_error_display_unsupported() {
    let e = LinuxSyscallError::UnsupportedArch(SyscallArch::X86_64);
    let msg = format!("{e}");
    assert!(msg.contains("unsupported"));
}

#[test]
fn linux_syscall_error_display_notfound() {
    let e = LinuxSyscallError::NotFound { arch: SyscallArch::X86_64, number: 999 };
    let msg = format!("{e}");
    assert!(msg.contains("999"));
}

// ─── ArgFilter tests ──────────────────────────────────────────────────────────

#[test]
fn arg_filter_eq_ne_boundaries() {
    assert!(ArgFilter::Eq(0).matches(0));
    assert!(!ArgFilter::Eq(0).matches(1));
    assert!(ArgFilter::Ne(0).matches(1));
    assert!(!ArgFilter::Ne(0).matches(0));
    assert!(ArgFilter::Eq(u64::MAX).matches(u64::MAX));
}

#[test]
fn arg_filter_ordering() {
    assert!(ArgFilter::Lt(10).matches(9));
    assert!(!ArgFilter::Lt(10).matches(10));
    assert!(ArgFilter::Le(10).matches(10));
    assert!(ArgFilter::Gt(10).matches(11));
    assert!(!ArgFilter::Gt(10).matches(10));
    assert!(ArgFilter::Ge(10).matches(10));
}

#[test]
fn arg_filter_masked_eq() {
    let f = ArgFilter::MaskedEq { mask: 0xff, value: 0x42 };
    assert!(f.matches(0xdead_dd42));
    assert!(!f.matches(0xdead_dd43));
}

#[test]
fn arg_filter_anybit() {
    assert!(ArgFilter::AnyBit(0x1).matches(0xff));
    assert!(!ArgFilter::AnyBit(0x1).matches(0xfe));
    assert!(!ArgFilter::AnyBit(0).matches(u64::MAX));
}

#[test]
fn arg_filter_to_bpf_expr_contains_index() {
    let s = ArgFilter::Eq(0xabc).to_bpf_expr(3);
    assert!(s.contains("args[3]"));
    assert!(s.contains("0xabc"));
}

#[test]
fn arg_filter_display_uses_index_zero() {
    let s = format!("{}", ArgFilter::Eq(5));
    assert!(s.contains("args[0]"));
}

#[test]
fn arg_filter_fuzz_never_panics() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..200 {
        let v = lcg.next();
        let arg = lcg.next();
        let filters = [
            ArgFilter::Eq(v),
            ArgFilter::Ne(v),
            ArgFilter::Lt(v),
            ArgFilter::Le(v),
            ArgFilter::Gt(v),
            ArgFilter::Ge(v),
            ArgFilter::MaskedEq { mask: v, value: arg },
            ArgFilter::AnyBit(v),
        ];
        for f in &filters {
            let _ = f.matches(arg);
            let _ = f.to_bpf_expr(0);
        }
    }
}

// ─── SeccompRule / Generator ──────────────────────────────────────────────────

#[test]
fn rule_allow_default_action() {
    let r = SeccompRule::allow(7);
    assert_eq!(r.syscall_nr, 7);
    assert_eq!(r.action, SeccompAction::Allow);
}

#[test]
fn rule_deny_default_action() {
    let r = SeccompRule::deny(7);
    assert_eq!(r.action, SeccompAction::KillProcess);
}

#[test]
fn rule_with_name_and_comment() {
    let r = SeccompRule::allow(1).with_name("write").with_comment("trusted");
    assert_eq!(r.syscall_name.as_deref(), Some("write"));
    assert_eq!(r.comment.as_deref(), Some("trusted"));
}

#[test]
fn rule_matches_requires_nr_and_filters() {
    let r = SeccompRule::allow(5).with_arg(0, ArgFilter::Eq(3));
    assert!(r.matches(5, &[3, 0, 0, 0, 0, 0]));
    assert!(!r.matches(6, &[3, 0, 0, 0, 0, 0]));
    assert!(!r.matches(5, &[4, 0, 0, 0, 0, 0]));
}

#[test]
fn rule_invalid_arg_index_never_matches() {
    let r = SeccompRule::allow(5).with_arg(99, ArgFilter::Eq(0));
    assert!(!r.matches(5, &[0; 6]));
}

#[test]
fn rule_display_includes_nr_and_action() {
    let r = SeccompRule::allow(42).with_name("x").with_comment("c")
        .with_arg(0, ArgFilter::Eq(1));
    let s = format!("{r}");
    assert!(s.contains("nr=42"));
    assert!(s.contains("Allow"));
    assert!(s.contains('c'));
}

#[test]
fn generator_default_actions_per_policy() {
    let gen_a = SeccompProfileGenerator::new(PolicyKind::Allowlist);
    let gen_d = SeccompProfileGenerator::new(PolicyKind::Denylist);
    let gen_aa = SeccompProfileGenerator::new(PolicyKind::AuditAllowlist);
    let gen_audit_den = SeccompProfileGenerator::new(PolicyKind::AuditDenylist);
    assert_eq!(gen_a.effective_default_action(), SeccompAction::KillProcess);
    assert_eq!(gen_d.effective_default_action(), SeccompAction::Allow);
    assert_eq!(gen_aa.effective_default_action(), SeccompAction::KillProcess);
    assert_eq!(gen_audit_den.effective_default_action(), SeccompAction::Allow);
}

#[test]
fn generator_default_action_override() {
    let g = SeccompProfileGenerator::new(PolicyKind::Allowlist)
        .with_default_action(SeccompAction::Errno(13));
    assert_eq!(g.effective_default_action(), SeccompAction::Errno(13));
}

#[test]
fn generator_simulate_first_match_wins() {
    let mut g = SeccompProfileGenerator::new(PolicyKind::Denylist);
    g.add_rule(SeccompRule::deny(0));
    g.add_rule(SeccompRule::allow(0));
    assert_eq!(g.simulate(0, &[0; 6]), SeccompAction::KillProcess);
}

#[test]
fn generator_generate_includes_rules() {
    let mut g = SeccompProfileGenerator::new(PolicyKind::Allowlist);
    g.allow_named(0, "read");
    g.allow_named(1, "write");
    let f = g.generate();
    assert_eq!(f.rule_count, 2);
    let joined = f.instructions.join("\n");
    assert!(joined.contains("read"));
    assert!(joined.contains("write"));
}

#[test]
fn generator_covered_dedup_sorted() {
    let mut g = SeccompProfileGenerator::new(PolicyKind::Allowlist);
    g.allow(10);
    g.allow(5);
    g.allow(10);
    let nrs = g.covered_syscall_numbers();
    assert_eq!(nrs, vec![5, 10]);
}

#[test]
fn generator_is_covered() {
    let mut g = SeccompProfileGenerator::new(PolicyKind::Allowlist);
    g.allow(7);
    assert!(g.is_covered(7));
    assert!(!g.is_covered(8));
}

#[test]
fn generator_rule_statistics_counts_actions() {
    let mut g = SeccompProfileGenerator::new(PolicyKind::Denylist);
    g.deny(1);
    g.deny(2);
    g.allow(3);
    let stats = g.rule_statistics();
    assert_eq!(*stats.get("KILL_PROCESS").unwrap(), 2);
    assert_eq!(*stats.get("ALLOW").unwrap(), 1);
}

#[test]
fn generator_bpf_filter_display_has_header() {
    let mut g = SeccompProfileGenerator::new(PolicyKind::Allowlist);
    g.allow_named(0, "read");
    let s = format!("{}", g.generate());
    assert!(s.contains("seccomp BPF filter"));
    assert!(s.contains("default action"));
}

#[test]
fn minimal_sandbox_covers_basics() {
    let g = minimal_sandbox_profile();
    assert!(g.is_covered(0));
    assert!(g.is_covered(1));
    assert!(g.is_covered(60));
    assert!(g.is_covered(231));
}

#[test]
fn anti_debug_blocks_ptrace_allows_unrelated() {
    let g = anti_debug_profile();
    assert_eq!(g.simulate(101, &[0; 6]), SeccompAction::KillProcess);
    assert_eq!(g.simulate(0, &[0; 6]), SeccompAction::Allow);
}

#[test]
fn seccomp_action_display_all_variants() {
    let variants = [
        SeccompAction::Allow,
        SeccompAction::KillThread,
        SeccompAction::KillProcess,
        SeccompAction::Errno(5),
        SeccompAction::Trap,
        SeccompAction::Log,
        SeccompAction::Notify,
    ];
    for v in &variants {
        let s = format!("{v}");
        assert!(!s.is_empty());
    }
}

#[test]
fn policy_kind_display_all() {
    let p = [PolicyKind::Allowlist, PolicyKind::Denylist,
        PolicyKind::AuditAllowlist, PolicyKind::AuditDenylist];
    let names: HashSet<_> = p.iter().map(|x| format!("{x}")).collect();
    assert_eq!(names.len(), 4);
}

#[test]
fn generator_simulate_fuzz_returns_some_action() {
    let mut g = SeccompProfileGenerator::new(PolicyKind::Allowlist);
    for nr in 0..20u64 {
        g.allow(nr);
    }
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..200 {
        let nr = lcg.next() % 30;
        let args = [lcg.next(), lcg.next(), lcg.next(), lcg.next(), lcg.next(), lcg.next()];
        let a = g.simulate(nr, &args);
        if nr < 20 {
            assert_eq!(a, SeccompAction::Allow);
        } else {
            assert_eq!(a, SeccompAction::KillProcess);
        }
    }
}

// ─── Hash/Eq consistency ──────────────────────────────────────────────────────

#[test]
fn arg_filter_eq_consistent() {
    let pairs = [
        (ArgFilter::Eq(1), ArgFilter::Eq(1), true),
        (ArgFilter::Eq(1), ArgFilter::Eq(2), false),
        (ArgFilter::Ne(1), ArgFilter::Ne(1), true),
        (ArgFilter::Lt(0), ArgFilter::Lt(0), true),
        (ArgFilter::Le(u64::MAX), ArgFilter::Le(u64::MAX), true),
        (ArgFilter::Gt(5), ArgFilter::Gt(6), false),
        (ArgFilter::Ge(5), ArgFilter::Ge(5), true),
        (ArgFilter::AnyBit(0xf), ArgFilter::AnyBit(0xf), true),
        (ArgFilter::AnyBit(0xf), ArgFilter::AnyBit(0x10), false),
        (ArgFilter::MaskedEq { mask: 1, value: 2 }, ArgFilter::MaskedEq { mask: 1, value: 2 }, true),
    ];
    for (a, b, expected) in pairs {
        assert_eq!(a == b, expected);
    }
}

#[test]
fn policy_kind_hash_consistent() {
    use std::collections::HashMap;
    let mut m: HashMap<PolicyKind, i32> = HashMap::new();
    m.insert(PolicyKind::Allowlist, 1);
    m.insert(PolicyKind::Denylist, 2);
    assert_eq!(m.get(&PolicyKind::Allowlist), Some(&1));
    assert_eq!(m.get(&PolicyKind::Denylist), Some(&2));
}

#[test]
fn seccomp_action_hash_eq_pairs() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    for a in [SeccompAction::Allow, SeccompAction::KillThread, SeccompAction::KillProcess,
              SeccompAction::Errno(1), SeccompAction::Errno(2), SeccompAction::Trap,
              SeccompAction::Log, SeccompAction::Notify] {
        set.insert(a);
    }
    assert_eq!(set.len(), 8);
    assert!(set.contains(&SeccompAction::Errno(1)));
}

// ─── Statistics tests ─────────────────────────────────────────────────────────

const fn samp(nr: u32, ts: u64, el: u64, ret: i64) -> SyscallSample {
    SyscallSample::new(nr, ts, el, ret, 1)
}

#[test]
fn sample_is_error_only_for_negative() {
    assert!(samp(0, 0, 0, -1).is_error());
    assert!(samp(0, 0, 0, i64::MIN).is_error());
    assert!(!samp(0, 0, 0, 0).is_error());
    assert!(!samp(0, 0, 0, i64::MAX).is_error());
}

#[test]
fn per_syscall_record_min_max_correct() {
    let mut p = PerSyscallStats::new(0, "read");
    p.record(&samp(0, 0, 100, 0));
    p.record(&samp(0, 1, 50, 0));
    p.record(&samp(0, 2, 200, 0));
    assert_eq!(p.min_elapsed_ns, 50);
    assert_eq!(p.max_elapsed_ns, 200);
    assert_eq!(p.total_elapsed_ns, 350);
    assert_eq!(p.count, 3);
}

#[test]
fn per_syscall_error_pct_bp_bounds() {
    let mut p = PerSyscallStats::new(0, "x");
    for _ in 0..3 { p.record(&samp(0, 0, 0, -1)); }
    p.record(&samp(0, 0, 0, 0));
    // 3 errors / 4 calls = 75%
    assert_eq!(p.error_pct_bp(), 7500);
}

#[test]
fn per_syscall_avg_zero_for_empty() {
    let p = PerSyscallStats::new(0, "x");
    assert_eq!(p.avg_elapsed_ns(), 0);
    assert_eq!(p.error_pct_bp(), 0);
}

#[test]
fn timeline_window_inclusive_boundaries() {
    let mut t = Timeline::new();
    t.push(samp(0, 100, 0, 0));
    t.push(samp(0, 200, 0, 0));
    t.push(samp(0, 300, 0, 0));
    let w = t.window(100, 300);
    assert_eq!(w.len(), 3);
    let w = t.window(150, 250);
    assert_eq!(w.len(), 1);
}

#[test]
fn timeline_empty_state() {
    let t = Timeline::new();
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert!(t.nr_sequence().is_empty());
}

#[test]
fn stats_record_resolves_known_name() {
    let mut st = SyscallStatistics::new(SyscallArch::X86_64);
    st.record(samp(0, 0, 10, 0));
    let p = st.get(0).unwrap();
    assert_eq!(p.name, "read");
}

#[test]
fn stats_record_unknown_uses_fallback() {
    let mut st = SyscallStatistics::new(SyscallArch::X86_64);
    st.record(samp(99999, 0, 10, 0));
    let p = st.get(99999).unwrap();
    assert!(p.name.contains("99999"));
}

#[test]
fn stats_all_by_count_descending() {
    let mut st = SyscallStatistics::new(SyscallArch::X86_64);
    for _ in 0..3 { st.record(samp(1, 0, 0, 0)); }
    for _ in 0..5 { st.record(samp(0, 0, 0, 0)); }
    let v = st.all_by_count();
    assert_eq!(v[0].nr, 0);
    assert_eq!(v[1].nr, 1);
}

#[test]
fn stats_hot_by_count_limit() {
    let mut st = SyscallStatistics::new(SyscallArch::X86_64);
    for nr in 0_i32..5 {
        for _ in 0..=nr { st.record(samp(nr.cast_unsigned(), 0, 10, 0)); }
    }
    let hot = st.hot_by_count(3);
    assert_eq!(hot.len(), 3);
    // Top must be nr=4 (5 calls)
    assert_eq!(hot[0].nr, 4);
}

#[test]
fn stats_pattern_detection_zero_window() {
    let st = SyscallStatistics::new(SyscallArch::X86_64);
    assert!(st.detect_patterns(0, 1).is_empty());
}

#[test]
fn stats_pattern_detection_min_occurrences_filters() {
    let mut st = SyscallStatistics::new(SyscallArch::X86_64);
    st.record(samp(0, 0, 0, 0));
    st.record(samp(1, 0, 0, 0));
    let p = st.detect_patterns(2, 5);
    assert!(p.is_empty());
}

#[test]
fn stats_strace_formatter_renders_total() {
    let mut st = SyscallStatistics::new(SyscallArch::X86_64);
    st.record(samp(0, 0, 1_000, 0));
    st.record(samp(1, 1, 500, -1));
    let s = st.strace_formatter().render();
    assert!(s.contains("total"));
}

#[test]
fn stats_fuzz_record_never_panics() {
    let mut st = SyscallStatistics::new(SyscallArch::X86_64);
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..300 {
        let nr = (lcg.next() & 0xFF) as u32;
        let ts = lcg.next();
        let el = lcg.next() & 0xFFFF;
        let ret = lcg.next().cast_signed();
        st.record(samp(nr, ts, el, ret));
    }
    assert_eq!(st.total_samples(), 300);
}

// ─── Send/Sync threaded stress ────────────────────────────────────────────────

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn types_are_send_sync() {
    assert_send_sync::<LinuxSyscallDb>();
    assert_send_sync::<SyscallResolver>();
    assert_send_sync::<SeccompProfileGenerator>();
    assert_send_sync::<BpfFilter>();
}

#[test]
fn db_concurrent_lookups_4x100() {
    let db = Arc::new(LinuxSyscallDb::new());
    let mut handles = vec![];
    for t in 0..4 {
        let db = db.clone();
        handles.push(thread::spawn(move || {
            let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE ^ u64::from(u32::try_from(t).unwrap()));
            for _ in 0..100 {
                let n = (lcg.next() & 0xFFFF) as u32;
                let _ = db.lookup(SyscallArch::X86_64, n);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn generator_concurrent_simulate_4x100() {
    let mut g = SeccompProfileGenerator::new(PolicyKind::Allowlist);
    for nr in 0..10u64 { g.allow(nr); }
    let g = Arc::new(g);
    let mut handles = vec![];
    for t in 0..4 {
        let g = g.clone();
        handles.push(thread::spawn(move || {
            let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE ^ u64::from(u32::try_from(t).unwrap()));
            for _ in 0..100 {
                let nr = lcg.next() % 20;
                let args = [lcg.next(); 6];
                let _ = g.simulate(nr, &args);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}
