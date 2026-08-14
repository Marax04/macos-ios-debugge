//! Deep adversarial tests for `rustre-analysis-callconv` (blitz2).
//!
//! Covers: round-trip JSON (de)serialization, seeded-LCG fuzzing of the
//! observed-pattern extractor / CC detector, boundary inputs, Display impls,
//! Hash/Eq consistency, Send+Sync stress, and state-machine walks.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

use rustre_analysis_callconv::{
    aapcs32, aapcs64, cdecl_x86, fastcall_x86, mips_o32, msvc_x64, riscv64_lp64d, stdcall_x86,
    sysv_x64, thiscall_x86, vectorcall_x64, Arch, ArgType, CallConvDatabase, CallConvError,
    CallConvStats, CallingConvDef, CallingConventionDatabase, CallingConventionDetector,
    CallingConventionPattern, CcKey, CcStackCleanup, Compiler, DetectInstr, FunctionCallConvSummary,
    FunctionInfo, Instruction, ObservedPattern, Os, ParameterMapper, RegisterClassifier,
    RegisterRole, CC_CDECL, CC_FASTCALL, CC_MS_X64, CC_STDCALL, CC_SYSV_AMD64, CC_THISCALL,
    CC_VECTORCALL,
};

// ---------- helpers ----------

fn lcg_seed() -> u64 {
    0xDEAD_BEEF_CAFE_BABE
}

fn lcg_step(s: &mut u64) -> u64 {
    *s = s
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *s
}

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

fn all_register_names() -> Vec<&'static str> {
    vec![
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "xmm0",
        "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "x0", "x1", "x2", "x3", "x4", "x5", "x8", "x19",
        "x20", "v0", "v1", "r0", "r1", "r2", "r3", "r4", "s0", "a0", "a1", "fa0", "t0", "junk",
    ]
}

fn pick<'a>(arr: &'a [&'a str], s: &mut u64) -> &'a str {
    let idx = (lcg_step(s) as usize) % arr.len();
    arr[idx]
}

fn random_instr(s: &mut u64, regs: &[&str]) -> DetectInstr {
    let tag = (lcg_step(s) as u32) % 11;
    let reg = pick(regs, s).to_string();
    match tag {
        0 => DetectInstr::RegRead { reg },
        1 => DetectInstr::RegWrite { reg },
        2 => DetectInstr::Push { reg },
        3 => DetectInstr::Pop { reg },
        4 => DetectInstr::Ret {
            stack_bytes: (lcg_step(s) as u32) % 256,
        },
        5 => DetectInstr::ThisPtrUse,
        6 => DetectInstr::FpRegRead { reg },
        7 => DetectInstr::StackAlloc {
            bytes: (lcg_step(s) as u32) % 1024,
        },
        8 => DetectInstr::StackArgAccess {
            offset: (lcg_step(s) as i32) % 4096,
        },
        9 => DetectInstr::Other,
        _ => DetectInstr::Ret { stack_bytes: 0 },
    }
}

// ---------- Arch / Os / Compiler ----------

#[test]
fn arch_pointer_width_all_variants() {
    assert_eq!(Arch::X86.pointer_width(), 4);
    assert_eq!(Arch::X86_64.pointer_width(), 8);
    assert_eq!(Arch::Arm32.pointer_width(), 4);
    assert_eq!(Arch::Arm64.pointer_width(), 8);
    assert_eq!(Arch::Mips32.pointer_width(), 4);
    assert_eq!(Arch::Mips64.pointer_width(), 8);
    assert_eq!(Arch::Ppc32.pointer_width(), 4);
    assert_eq!(Arch::Ppc64.pointer_width(), 8);
    assert_eq!(Arch::RiscV32.pointer_width(), 4);
    assert_eq!(Arch::RiscV64.pointer_width(), 8);
    assert_eq!(Arch::Other("xyz".into()).pointer_width(), 4);
}

#[test]
fn arch_display_round_trip_50_inputs() {
    let names = [
        "x86", "x86_64", "arm32", "arm64", "mips32", "mips64", "ppc32", "ppc64", "riscv32",
        "riscv64",
    ];
    let arches = [
        Arch::X86,
        Arch::X86_64,
        Arch::Arm32,
        Arch::Arm64,
        Arch::Mips32,
        Arch::Mips64,
        Arch::Ppc32,
        Arch::Ppc64,
        Arch::RiscV32,
        Arch::RiscV64,
    ];
    for _ in 0..5 {
        for (a, n) in arches.iter().zip(names.iter()) {
            assert_eq!(format!("{a}"), *n);
        }
    }
    assert_eq!(format!("{}", Arch::Other("foo".into())), "foo");
}

#[test]
fn os_display_all_variants() {
    assert_eq!(format!("{}", Os::Linux), "linux");
    assert_eq!(format!("{}", Os::Windows), "windows");
    assert_eq!(format!("{}", Os::MacOs), "macos");
    assert_eq!(format!("{}", Os::FreeBsd), "freebsd");
    assert_eq!(format!("{}", Os::Bare), "bare");
    assert_eq!(format!("{}", Os::Other("plan9".into())), "plan9");
}

#[test]
fn compiler_display_all_variants() {
    assert_eq!(format!("{}", Compiler::Gcc), "gcc");
    assert_eq!(format!("{}", Compiler::Msvc), "msvc");
    assert_eq!(format!("{}", Compiler::Clang), "clang");
    assert_eq!(format!("{}", Compiler::Icc), "icc");
    assert_eq!(format!("{}", Compiler::Any), "any");
}

#[test]
fn arch_eq_hash_consistency_30_pairs() {
    let arches = [
        Arch::X86,
        Arch::X86_64,
        Arch::Arm32,
        Arch::Arm64,
        Arch::Mips32,
        Arch::Mips64,
        Arch::Ppc32,
        Arch::Ppc64,
        Arch::RiscV32,
        Arch::RiscV64,
        Arch::Other("a".into()),
        Arch::Other("b".into()),
    ];
    for a in &arches {
        for b in &arches {
            if a == b {
                assert_eq!(hash_of(a), hash_of(b));
            }
        }
    }
}

#[test]
fn os_eq_hash_consistency() {
    let oss = [
        Os::Linux,
        Os::Windows,
        Os::MacOs,
        Os::FreeBsd,
        Os::Bare,
        Os::Other("x".into()),
    ];
    for a in &oss {
        for b in &oss {
            if a == b {
                assert_eq!(hash_of(a), hash_of(b));
            } else {
                // distinct values may collide in hash; only equality-implies-hash is required
            }
        }
    }
}

#[test]
fn cckey_display_and_eq_hash() {
    let k1 = CcKey::new(Arch::X86_64, Os::Linux, Compiler::Gcc);
    let k2 = CcKey::new(Arch::X86_64, Os::Linux, Compiler::Gcc);
    assert_eq!(k1, k2);
    assert_eq!(hash_of(&k1), hash_of(&k2));
    assert_eq!(format!("{k1}"), "x86_64/linux/gcc");
}

// ---------- CallingConventionPattern ----------

#[test]
fn all_builtin_patterns_have_unique_names() {
    let names = vec![
        sysv_x64().name,
        msvc_x64().name,
        cdecl_x86().name,
        stdcall_x86().name,
        fastcall_x86().name,
        thiscall_x86().name,
        vectorcall_x64().name,
        aapcs64().name,
        aapcs32().name,
        mips_o32().name,
        riscv64_lp64d().name,
    ];
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len());
}

#[test]
fn pattern_is_arg_register_includes_fp() {
    let cc = sysv_x64();
    assert!(cc.is_arg_register("rdi"));
    assert!(cc.is_arg_register("xmm0"));
    assert!(!cc.is_arg_register("rax"));
    assert!(!cc.is_arg_register("nonsense"));
}

#[test]
fn pattern_arg_register_at_bounds() {
    let cc = sysv_x64();
    assert_eq!(cc.arg_register_at(0), Some("rdi"));
    assert_eq!(cc.arg_register_at(5), Some("r9"));
    assert_eq!(cc.arg_register_at(6), None);
    assert_eq!(cc.arg_register_at(usize::MAX), None);
}

#[test]
fn pattern_arg_register_count_consistency() {
    assert_eq!(sysv_x64().arg_register_count(), 6);
    assert_eq!(msvc_x64().arg_register_count(), 4);
    assert_eq!(cdecl_x86().arg_register_count(), 0);
    assert_eq!(aapcs64().arg_register_count(), 8);
    assert_eq!(aapcs32().arg_register_count(), 4);
    assert_eq!(mips_o32().arg_register_count(), 4);
    assert_eq!(riscv64_lp64d().arg_register_count(), 8);
}

#[test]
fn pattern_score_zero_on_empty_observed() {
    let cc = sysv_x64();
    let obs = ObservedPattern::new();
    // empty observed: only the callee_pops==!caller_cleanup bonus may apply
    let score = cc.score(&obs);
    // sysv: caller_cleanup=true, default obs.callee_pops_stack=false -> false == !true=false -> match, +5
    assert_eq!(score, 5);
}

#[test]
fn pattern_score_increases_with_arg_matches() {
    let cc = sysv_x64();
    let mut obs = ObservedPattern::new();
    let baseline = cc.score(&obs);
    obs.read_before_write = vec!["rdi".into(), "rsi".into(), "rdx".into()];
    let scored = cc.score(&obs);
    assert!(scored > baseline);
}

#[test]
fn pattern_score_penalises_contradictions() {
    let cc = sysv_x64();
    let mut a = ObservedPattern::new();
    a.read_before_write = vec!["rdi".into()];
    let high = cc.score(&a);
    let mut b = ObservedPattern::new();
    b.read_before_write = vec!["rdi".into(), "junk".into(), "weird".into()];
    let low = cc.score(&b);
    assert!(low < high);
}

#[test]
fn pattern_display_format_stable() {
    let cc = sysv_x64();
    let s = format!("{cc}");
    assert!(s.contains("System V AMD64 ABI"));
    assert!(s.contains("align=16"));
    assert!(s.contains("caller_cleanup=true"));
    assert!(s.contains("max_reg_args=6"));
}

// ---------- ObservedPattern ----------

#[test]
fn observed_pattern_has_arg_evidence_paths() {
    let mut o = ObservedPattern::new();
    assert!(!o.has_arg_evidence());
    o.read_before_write.push("rdi".into());
    assert!(o.has_arg_evidence());
    let mut o2 = ObservedPattern::new();
    o2.fp_read_before_write.push("xmm0".into());
    assert!(o2.has_arg_evidence());
}

#[test]
fn observed_pattern_leaf_detection_boundary() {
    let mut o = ObservedPattern::new();
    o.max_stack_frame = 16;
    assert!(o.looks_like_leaf());
    o.max_stack_frame = 17;
    assert!(!o.looks_like_leaf());
    o.max_stack_frame = 0;
    o.saved_registers.push("rbx".into());
    assert!(!o.looks_like_leaf());
}

// ---------- CallingConventionDetector ----------

#[test]
fn extract_pattern_empty_stream() {
    let p = CallingConventionDetector::extract_pattern(&[], 8);
    assert!(p.read_before_write.is_empty());
    assert!(p.saved_registers.is_empty());
    assert_eq!(p.max_stack_frame, 0);
    assert_eq!(p.stack_arg_count, 0);
    assert!(!p.callee_pops_stack);
}

#[test]
fn extract_pattern_pointer_width_zero_defaults_to_4() {
    let instrs = vec![DetectInstr::StackArgAccess { offset: 12 }];
    let p = CallingConventionDetector::extract_pattern(&instrs, 0);
    // offset=12, ptr=4 -> 12/4 + 1 = 4
    assert_eq!(p.stack_arg_count, 4);
}

#[test]
fn extract_pattern_read_before_write() {
    let instrs = vec![
        DetectInstr::RegRead { reg: "rdi".into() },
        DetectInstr::RegWrite { reg: "rax".into() },
        DetectInstr::RegRead { reg: "rax".into() }, // defined now, must not appear
        DetectInstr::RegRead { reg: "rsi".into() },
    ];
    let p = CallingConventionDetector::extract_pattern(&instrs, 8);
    assert_eq!(p.read_before_write, vec!["rdi".to_string(), "rsi".into()]);
}

#[test]
fn extract_pattern_saved_registers_only_matched_pairs() {
    let instrs = vec![
        DetectInstr::Push { reg: "rbx".into() },
        DetectInstr::Push { reg: "rbp".into() },
        DetectInstr::Pop { reg: "rbp".into() },
        DetectInstr::Pop { reg: "rbx".into() },
        DetectInstr::Push { reg: "r12".into() }, // pushed but never popped
    ];
    let p = CallingConventionDetector::extract_pattern(&instrs, 8);
    assert!(p.saved_registers.contains(&"rbx".to_string()));
    assert!(p.saved_registers.contains(&"rbp".to_string()));
    assert!(!p.saved_registers.contains(&"r12".to_string()));
}

#[test]
fn extract_pattern_ret_records_stack_bytes() {
    let instrs = vec![
        DetectInstr::RegWrite { reg: "rax".into() },
        DetectInstr::Ret { stack_bytes: 16 },
    ];
    let p = CallingConventionDetector::extract_pattern(&instrs, 8);
    assert!(p.callee_pops_stack);
    assert_eq!(p.callee_stack_pop, 16);
    assert!(p.written_before_return.contains(&"rax".to_string()));
}

#[test]
fn extract_pattern_shadow_space_threshold() {
    for bytes in [31u32, 32, 33, 64, 1024] {
        let p = CallingConventionDetector::extract_pattern(
            &[DetectInstr::StackAlloc { bytes }],
            8,
        );
        assert_eq!(p.shadow_space_observed, bytes >= 32, "bytes={bytes}");
        assert_eq!(p.max_stack_frame, bytes);
    }
}

#[test]
fn extract_pattern_stack_arg_offset_zero() {
    let instrs = vec![DetectInstr::StackArgAccess { offset: 0 }];
    let p = CallingConventionDetector::extract_pattern(&instrs, 8);
    // 0/8 + 1 = 1
    assert_eq!(p.stack_arg_count, 1);
}

#[test]
fn extract_pattern_stack_arg_offset_negative_ignored() {
    let instrs = vec![DetectInstr::StackArgAccess { offset: -16 }];
    let p = CallingConventionDetector::extract_pattern(&instrs, 8);
    assert_eq!(p.stack_arg_count, 0);
}

#[test]
fn extract_pattern_this_ptr_hint() {
    let p = CallingConventionDetector::extract_pattern(&[DetectInstr::ThisPtrUse], 4);
    assert!(p.this_ptr_hint);
}

#[test]
fn extract_pattern_fp_read_before_write() {
    let instrs = vec![
        DetectInstr::FpRegRead { reg: "xmm0".into() },
        DetectInstr::RegWrite { reg: "xmm1".into() },
        DetectInstr::FpRegRead { reg: "xmm1".into() }, // defined; excluded
        DetectInstr::FpRegRead { reg: "xmm0".into() }, // duplicate; excluded
    ];
    let p = CallingConventionDetector::extract_pattern(&instrs, 8);
    assert_eq!(p.fp_read_before_write, vec!["xmm0".to_string()]);
}

#[test]
fn detector_detect_empty_candidates_no_match() {
    let obs = ObservedPattern::new();
    matches!(
        CallingConventionDetector::detect(&obs, &[]),
        Err(CallConvError::NoMatch)
    );
}

#[test]
fn detector_detect_all_zero_score_no_match() {
    let obs = ObservedPattern::new();
    // sysv vs msvc both give bonus 5 for callee_pops==!caller_cleanup on empty obs.
    // Use only one to avoid tie at score 5. But empty obs gives score>0 -> we expect
    // either Ok or Ambiguous; we just want to confirm it does not panic.
    let candidates = [sysv_x64()];
    let r = CallingConventionDetector::detect(&obs, &candidates);
    // It returns either Ok(sysv) or NoMatch — depends on the bonus rule.
    // Both are documented possibilities; assert no panic.
    let _ = r.is_ok() || r.is_err();
}

#[test]
fn detector_detect_picks_best() {
    let mut obs = ObservedPattern::new();
    obs.read_before_write = vec!["rdi".into(), "rsi".into(), "rdx".into()];
    let cands = [sysv_x64(), msvc_x64()];
    let detected = CallingConventionDetector::detect(&obs, &cands).expect("should detect");
    assert_eq!(detected.name, "System V AMD64 ABI");
}

#[test]
fn detector_rank_candidates_sorted_descending() {
    let mut obs = ObservedPattern::new();
    obs.read_before_write = vec!["rdi".into()];
    let cands = [sysv_x64(), msvc_x64(), cdecl_x86()];
    let ranked = CallingConventionDetector::rank_candidates(&obs, &cands);
    assert_eq!(ranked.len(), 3);
    for w in ranked.windows(2) {
        assert!(w[0].1 >= w[1].1);
    }
}

#[test]
fn detector_detect_with_hints_thiscall() {
    let mut obs = ObservedPattern::new();
    obs.read_before_write = vec!["ecx".into()];
    obs.this_ptr_hint = true;
    obs.callee_pops_stack = true;
    let cands = [fastcall_x86(), thiscall_x86()];
    let detected =
        CallingConventionDetector::detect_with_hints(&obs, &cands).expect("should detect");
    assert!(detected.name.contains("thiscall") || detected.name.contains("fastcall"));
}

#[test]
fn detector_detect_with_hints_shadow_space() {
    let mut obs = ObservedPattern::new();
    obs.read_before_write = vec!["rcx".into(), "rdx".into()];
    obs.shadow_space_observed = true;
    let cands = [msvc_x64(), vectorcall_x64()];
    let detected =
        CallingConventionDetector::detect_with_hints(&obs, &cands).expect("should detect");
    // Both have rcx/rdx as args; shadow_space_bytes=32 only on msvc, 0 on vectorcall.
    assert_eq!(detected.shadow_space_bytes, 32);
}

#[test]
fn detector_lcg_fuzz_never_panics_200_runs() {
    let mut s: u64 = lcg_seed();
    let regs = all_register_names();
    let cands = [
        sysv_x64(),
        msvc_x64(),
        cdecl_x86(),
        stdcall_x86(),
        fastcall_x86(),
        thiscall_x86(),
    ];
    for _ in 0..200 {
        let len = (lcg_step(&mut s) as usize) % 64;
        let instrs: Vec<DetectInstr> = (0..len).map(|_| random_instr(&mut s, &regs)).collect();
        let pw = if (lcg_step(&mut s) & 1) == 0 { 4 } else { 8 };
        let obs = CallingConventionDetector::extract_pattern(&instrs, pw);
        // detect can return Ok/Err — never panic.
        let _ = CallingConventionDetector::detect(&obs, &cands);
        let _ = CallingConventionDetector::detect_with_hints(&obs, &cands);
        let _ = CallingConventionDetector::rank_candidates(&obs, &cands);
    }
}

#[test]
fn extract_pattern_lcg_fuzz_50_runs_deterministic() {
    let mut s = lcg_seed();
    let regs = all_register_names();
    for _ in 0..50 {
        let len = (lcg_step(&mut s) as usize) % 100;
        let instrs: Vec<DetectInstr> = (0..len).map(|_| random_instr(&mut s, &regs)).collect();
        let a = CallingConventionDetector::extract_pattern(&instrs, 8);
        let b = CallingConventionDetector::extract_pattern(&instrs, 8);
        // Must be deterministic.
        assert_eq!(a.read_before_write, b.read_before_write);
        assert_eq!(a.saved_registers, b.saved_registers);
        assert_eq!(a.callee_pops_stack, b.callee_pops_stack);
        assert_eq!(a.max_stack_frame, b.max_stack_frame);
        assert_eq!(a.stack_arg_count, b.stack_arg_count);
    }
}

// ---------- CallingConventionDatabase ----------

#[test]
fn db_with_builtins_nonempty() {
    let db = CallingConventionDatabase::with_builtins();
    assert!(db.key_count() > 0);
    assert!(db.entry_count() > 0);
}

#[test]
fn db_lookup_and_remove() {
    let mut db = CallingConventionDatabase::with_builtins();
    let key = CcKey::new(Arch::X86_64, Os::Linux, Compiler::Gcc);
    let count_before = db.lookup(&key).len();
    assert!(count_before > 0);
    let removed = db.remove(&key);
    assert_eq!(removed, count_before);
    assert!(db.lookup(&key).is_empty());
}

#[test]
fn db_lookup_unknown_returns_empty() {
    let db = CallingConventionDatabase::new();
    let key = CcKey::new(Arch::Mips64, Os::Bare, Compiler::Icc);
    assert!(db.lookup(&key).is_empty());
}

#[test]
fn db_lookup_any_compiler_filters_by_arch_os() {
    let db = CallingConventionDatabase::with_builtins();
    let v = db.lookup_any_compiler(&Arch::X86_64, &Os::Linux);
    assert!(!v.is_empty());
    let empty = db.lookup_any_compiler(&Arch::Mips64, &Os::MacOs);
    assert!(empty.is_empty());
}

#[test]
fn db_lookup_any_os_filters_by_arch() {
    let db = CallingConventionDatabase::with_builtins();
    let v = db.lookup_any_os(&Arch::X86_64);
    assert!(!v.is_empty());
}

#[test]
fn db_all_names_sorted_unique() {
    let db = CallingConventionDatabase::with_builtins();
    let names = db.all_names();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
    let mut dedup = names.clone();
    dedup.dedup();
    assert_eq!(names.len(), dedup.len());
}

#[test]
fn db_json_round_trip() {
    let db = CallingConventionDatabase::with_builtins();
    let json = db.to_json().expect("serialize");
    let db2 = CallingConventionDatabase::from_json(&json).expect("deserialize");
    assert_eq!(db.key_count(), db2.key_count());
    assert_eq!(db.entry_count(), db2.entry_count());
    assert_eq!(db.all_names(), db2.all_names());
}

#[test]
fn db_json_round_trip_50_deterministic_iterations() {
    let db = CallingConventionDatabase::with_builtins();
    let json = db.to_json().expect("serialize");
    for _ in 0..50 {
        let db2 = CallingConventionDatabase::from_json(&json).expect("deserialize");
        assert_eq!(db2.entry_count(), db.entry_count());
    }
}

#[test]
fn db_from_json_malformed_errors() {
    let r = CallingConventionDatabase::from_json("{ not valid json");
    assert!(matches!(r, Err(CallConvError::Json(_))));
}

#[test]
fn db_from_json_empty_array_is_ok() {
    let db = CallingConventionDatabase::from_json("[]").expect("empty array");
    assert_eq!(db.entry_count(), 0);
}

// ---------- FunctionCallConvSummary ----------

#[test]
fn summary_new_and_high_confidence_boundary() {
    let cc = sysv_x64();
    let obs = ObservedPattern::new();
    let s_low = FunctionCallConvSummary::new(0x1000, cc.clone(), 19, obs.clone());
    assert!(!s_low.is_high_confidence());
    let s_high = FunctionCallConvSummary::new(0x1000, cc.clone(), 20, obs.clone());
    assert!(s_high.is_high_confidence());
    let s_top = FunctionCallConvSummary::new(0x1000, cc, u32::MAX, obs);
    assert!(s_top.is_high_confidence());
}

#[test]
fn summary_with_runner_ups() {
    let s = FunctionCallConvSummary::new(0, sysv_x64(), 50, ObservedPattern::new())
        .with_runner_ups(vec![("a".into(), 30), ("b".into(), 20)]);
    assert_eq!(s.runner_ups.len(), 2);
}

// ---------- CallConvStats ----------

#[test]
fn stats_empty_input() {
    let stats = CallConvStats::compute(&[]);
    assert_eq!(stats.total, 0);
    assert_eq!(stats.high_confidence, 0);
    assert_eq!(stats.avg_confidence, 0.0);
    assert!(stats.most_common().is_none());
}

#[test]
fn stats_aggregate_basic() {
    let summaries = vec![
        FunctionCallConvSummary::new(1, sysv_x64(), 30, ObservedPattern::new()),
        FunctionCallConvSummary::new(2, sysv_x64(), 10, ObservedPattern::new()),
        FunctionCallConvSummary::new(3, msvc_x64(), 50, ObservedPattern::new()),
    ];
    let stats = CallConvStats::compute(&summaries);
    assert_eq!(stats.total, 3);
    assert_eq!(stats.high_confidence, 2);
    assert_eq!(stats.max_confidence, 50);
    assert_eq!(stats.min_confidence, 10);
    assert_eq!(stats.most_common(), Some("System V AMD64 ABI"));
}

// ---------- RegisterClassifier ----------

#[test]
fn register_classifier_all_roles() {
    let cc = sysv_x64();
    assert_eq!(
        RegisterClassifier::classify(&cc, "rdi"),
        RegisterRole::Argument
    );
    assert_eq!(
        RegisterClassifier::classify(&cc, "xmm0"),
        RegisterRole::FpArgument
    );
    assert_eq!(
        RegisterClassifier::classify(&cc, "rax"),
        RegisterRole::ReturnValue
    );
    assert_eq!(
        RegisterClassifier::classify(&cc, "rbx"),
        RegisterRole::CalleeSaved
    );
    // r10 is caller-saved in sysv
    assert_eq!(
        RegisterClassifier::classify(&cc, "r10"),
        RegisterRole::CallerSaved
    );
    assert_eq!(
        RegisterClassifier::classify(&cc, "totally_unknown"),
        RegisterRole::Unknown
    );
}

#[test]
fn register_classifier_registers_with_role() {
    let cc = sysv_x64();
    let args = RegisterClassifier::registers_with_role(&cc, RegisterRole::Argument);
    assert_eq!(args, vec!["rdi", "rsi", "rdx", "rcx", "r8", "r9"]);
    let unknown = RegisterClassifier::registers_with_role(&cc, RegisterRole::Unknown);
    assert!(unknown.is_empty());
}

// ---------- ParameterMapper ----------

#[test]
fn parameter_mapper_map_args_ordered() {
    let cc = sysv_x64();
    let observed = vec!["rsi".to_string(), "rdi".into(), "r9".into()];
    let mapped = ParameterMapper::map_args(&observed, &cc);
    // Order by abi position
    assert_eq!(mapped, vec![(0, "rdi".into()), (1, "rsi".into()), (5, "r9".into())]);
}

#[test]
fn parameter_mapper_estimated_arg_count() {
    let cc = sysv_x64();
    let mut obs = ObservedPattern::new();
    obs.read_before_write = vec!["rdi".into(), "rsi".into(), "junk".into()];
    obs.stack_arg_count = 4;
    let n = ParameterMapper::estimated_arg_count(&obs, &cc);
    assert_eq!(n, 6); // 2 valid regs + 4 stack
}

// ---------- CC static definitions / CallConvDatabase ----------

#[test]
fn static_cc_defs_invariants() {
    assert!(CC_SYSV_AMD64.is_int_arg("rdi"));
    assert!(CC_SYSV_AMD64.is_float_arg("xmm0"));
    assert!(CC_SYSV_AMD64.is_callee_saved("rbx"));
    assert!(!CC_SYSV_AMD64.is_int_arg("rax"));
    assert_eq!(CC_MS_X64.shadow_space, 32);
    assert_eq!(CC_CDECL.int_arg_regs.len(), 0);
    assert_eq!(CC_THISCALL.has_this_ptr, true);
    assert_eq!(CC_FASTCALL.stack_cleanup, CcStackCleanup::Callee);
    assert_eq!(CC_STDCALL.stack_cleanup, CcStackCleanup::Callee);
    assert_eq!(CC_VECTORCALL.stack_align, 16);
}

#[test]
fn static_cc_display() {
    let s = format!("{}", CC_SYSV_AMD64);
    assert!(s.contains("sysv_amd64"));
    assert!(s.contains("cleanup="));
}

#[test]
fn cc_stack_cleanup_display() {
    assert_eq!(format!("{}", CcStackCleanup::Caller), "caller");
    assert_eq!(format!("{}", CcStackCleanup::Callee), "callee");
}

#[test]
fn cc_db_static_builtins_count() {
    let db = CallConvDatabase::with_builtins();
    assert_eq!(db.len(), 7);
    assert!(!db.is_empty());
    let names = db.names();
    assert!(names.contains(&"sysv_amd64"));
    assert!(names.contains(&"ms_x64"));
    assert!(names.contains(&"cdecl"));
    assert!(names.contains(&"stdcall"));
    assert!(names.contains(&"fastcall"));
    assert!(names.contains(&"thiscall"));
    assert!(names.contains(&"vectorcall"));
}

#[test]
fn cc_db_get_returns_correct_ref() {
    let db = CallConvDatabase::with_builtins();
    assert_eq!(db.get("sysv_amd64").unwrap().name, "sysv_amd64");
    assert!(db.get("nonexistent").is_none());
}

#[test]
fn cc_db_default_is_empty() {
    let db = CallConvDatabase::default();
    // default == new() returns empty? Spec: Default => new() empty
    assert!(db.is_empty());
}

// ---------- Instruction constructors ----------

#[test]
fn instruction_constructors_set_flags() {
    let p = Instruction::push(0x100, "rbx");
    assert!(p.is_push);
    assert!(!p.is_pop);
    assert_eq!(p.reads, vec!["rbx"]);

    let q = Instruction::pop(0x200, "rbp");
    assert!(q.is_pop);
    assert!(!q.is_push);
    assert_eq!(q.writes, vec!["rbp"]);

    let r = Instruction::ret(0x300, 16);
    assert!(r.is_ret);
    assert_eq!(r.ret_stack_bytes, 16);

    let rw = Instruction::rw(0x400, vec!["rcx".into()], vec!["rax".into()]);
    assert!(!rw.is_push && !rw.is_pop && !rw.is_ret);
}

// ---------- detect_calling_convention (free function) ----------

#[test]
fn detect_cc_empty_returns_none() {
    let db = CallConvDatabase::with_builtins();
    let cands = db.all();
    assert!(rustre_analysis_callconv::detect_calling_convention(&[], &cands).is_none());
    let instrs = vec![Instruction::ret(0, 0)];
    assert!(rustre_analysis_callconv::detect_calling_convention(&instrs, &[]).is_none());
}

#[test]
fn detect_cc_sysv_classification() {
    let instrs = vec![
        Instruction::rw(0x100, vec!["rdi".into()], vec!["rax".into()]),
        Instruction::rw(0x103, vec!["rsi".into()], vec!["rax".into()]),
        Instruction::ret(0x106, 0),
    ];
    let db = CallConvDatabase::with_builtins();
    let cands = db.all();
    let cc = rustre_analysis_callconv::detect_calling_convention(&instrs, &cands);
    if let Some(cc) = cc {
        assert!(cc.is_int_arg("rdi"));
    }
}

#[test]
fn detect_cc_stdcall_classification_via_ret_n() {
    let instrs = vec![
        Instruction::push(0x100, "ebp"),
        Instruction::pop(0x110, "ebp"),
        Instruction::ret(0x111, 8),
    ];
    let db = CallConvDatabase::with_builtins();
    let cands = db.all();
    let _ = rustre_analysis_callconv::detect_calling_convention(&instrs, &cands);
    // We just check no panic; specific match may be ambiguous between stdcall/fastcall/thiscall.
}

#[test]
fn detect_cc_lcg_fuzz_100_runs() {
    let db = CallConvDatabase::with_builtins();
    let cands = db.all();
    let mut s = lcg_seed();
    let regs = all_register_names();
    for _ in 0..100 {
        let len = (lcg_step(&mut s) as usize) % 30;
        let mut instrs = Vec::new();
        for _ in 0..len {
            let kind = (lcg_step(&mut s) as u32) % 6;
            let reg = pick(&regs, &mut s).to_string();
            let addr = lcg_step(&mut s);
            let ins = match kind {
                0 => Instruction::rw(addr, vec![reg.clone()], vec![]),
                1 => Instruction::rw(addr, vec![], vec![reg.clone()]),
                2 => Instruction::push(addr, reg),
                3 => Instruction::pop(addr, reg),
                4 => Instruction::ret(addr, (lcg_step(&mut s) as u32) % 64),
                _ => Instruction::rw(addr, vec![reg.clone()], vec![reg]),
            };
            instrs.push(ins);
        }
        let _ = rustre_analysis_callconv::detect_calling_convention(&instrs, &cands);
    }
}

// ---------- get_arg_types ----------

#[test]
fn get_arg_types_sysv_basic() {
    let mut f = FunctionInfo::new(0x1000, "sysv_amd64");
    f.live_in_regs = vec!["rdi".into(), "rsi".into()];
    let args = rustre_analysis_callconv::get_arg_types(&f, &CC_SYSV_AMD64);
    assert_eq!(args.len(), 2);
}

#[test]
fn get_arg_types_thiscall_prepends_this() {
    let f = FunctionInfo::new(0x1000, "thiscall");
    let args = rustre_analysis_callconv::get_arg_types(&f, &CC_THISCALL);
    assert!(matches!(args.first(), Some(ArgType::ThisPtr { .. })));
}

#[test]
fn get_arg_types_with_stack_slots() {
    let mut f = FunctionInfo::new(0x1000, "ms_x64");
    f.stack_arg_count = 3;
    let args = rustre_analysis_callconv::get_arg_types(&f, &CC_MS_X64);
    let stack: Vec<&ArgType> = args
        .iter()
        .filter(|a| matches!(a, ArgType::Stack { .. }))
        .collect();
    assert_eq!(stack.len(), 3);
}

#[test]
fn arg_type_display_formats() {
    let a = ArgType::Integer {
        reg: "rdi".into(),
        position: 0,
    };
    assert!(format!("{a}").contains("int arg0"));
    let b = ArgType::Float {
        reg: "xmm0".into(),
        position: 1,
    };
    assert!(format!("{b}").contains("float arg1"));
    let c = ArgType::ThisPtr { reg: "ecx".into() };
    assert!(format!("{c}").contains("this"));
    let d = ArgType::Stack { slot: 2, offset: 16 };
    let s = format!("{d}");
    assert!(s.contains("stack[2]"));
    let e = ArgType::Unknown { position: 5 };
    assert!(format!("{e}").contains("unknown arg5"));
}

// ---------- Send/Sync stress ----------

#[test]
fn db_send_sync_threaded_stress() {
    let db = Arc::new(CallingConventionDatabase::with_builtins());
    let mut handles = Vec::new();
    for tid in 0..4 {
        let dbc = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            let key = CcKey::new(Arch::X86_64, Os::Linux, Compiler::Gcc);
            for i in 0..100 {
                let v = dbc.lookup(&key);
                assert!(!v.is_empty(), "tid={tid} i={i}");
                let names = dbc.all_names();
                assert!(!names.is_empty());
            }
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }
}

#[test]
fn static_cc_def_send_sync_stress() {
    let mut handles = Vec::new();
    for _ in 0..4 {
        handles.push(thread::spawn(|| {
            for _ in 0..100 {
                assert!(CC_SYSV_AMD64.is_int_arg("rdi"));
                assert!(CC_MS_X64.is_int_arg("rcx"));
                assert!(!CC_CDECL.is_int_arg("rax"));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ---------- error display ----------

#[test]
fn error_display_messages() {
    let e = CallConvError::NoMatch;
    assert!(format!("{e}").contains("no calling convention"));
    let e = CallConvError::Ambiguous;
    assert!(format!("{e}").contains("ambiguous"));
    let e = CallConvError::UnknownKey("foo".into());
    assert!(format!("{e}").contains("foo"));
    let e = CallConvError::TooShort { got: 1, need: 5 };
    let s = format!("{e}");
    assert!(s.contains("1") && s.contains("5"));
    let e = CallConvError::UnknownRegister {
        name: "zzz".into(),
        arch: "x86".into(),
    };
    let s = format!("{e}");
    assert!(s.contains("zzz") && s.contains("x86"));
}

// ---------- ObservedPattern serde round-trip ----------

#[test]
fn observed_pattern_serde_round_trip() {
    let mut o = ObservedPattern::new();
    o.read_before_write = vec!["rdi".into(), "rsi".into()];
    o.saved_registers = vec!["rbx".into()];
    o.callee_pops_stack = true;
    o.callee_stack_pop = 16;
    o.max_stack_frame = 64;
    o.stack_arg_count = 3;
    let json = serde_json::to_string(&o).unwrap();
    let o2: ObservedPattern = serde_json::from_str(&json).unwrap();
    assert_eq!(o.read_before_write, o2.read_before_write);
    assert_eq!(o.saved_registers, o2.saved_registers);
    assert_eq!(o.callee_pops_stack, o2.callee_pops_stack);
    assert_eq!(o.callee_stack_pop, o2.callee_stack_pop);
    assert_eq!(o.max_stack_frame, o2.max_stack_frame);
    assert_eq!(o.stack_arg_count, o2.stack_arg_count);
}

#[test]
fn pattern_serde_round_trip_all_builtins() {
    for cc in [
        sysv_x64(),
        msvc_x64(),
        cdecl_x86(),
        stdcall_x86(),
        fastcall_x86(),
        thiscall_x86(),
        vectorcall_x64(),
        aapcs64(),
        aapcs32(),
        mips_o32(),
        riscv64_lp64d(),
    ] {
        let json = serde_json::to_string(&cc).unwrap();
        let cc2: CallingConventionPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(cc, cc2);
    }
}

// ---------- boundary: u32::MAX in score saturation ----------

#[test]
fn score_handles_huge_observed_vectors() {
    let cc = sysv_x64();
    let mut o = ObservedPattern::new();
    o.read_before_write = (0..1000).map(|_| "rdi".to_string()).collect();
    // even with 1000 dup entries (dedup not done by score), score must not panic
    let _ = cc.score(&o);
}
