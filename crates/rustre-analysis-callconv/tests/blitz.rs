//! Exhaustive blitz tests for `rustre-analysis-callconv` public API.

use rustre_analysis_callconv::*;

// ───────────────────────── Arch / Os / Compiler ─────────────────────────

#[test]
fn arch_pointer_width_32bit() {
    assert_eq!(Arch::X86.pointer_width(), 4);
    assert_eq!(Arch::Arm32.pointer_width(), 4);
    assert_eq!(Arch::Mips32.pointer_width(), 4);
    assert_eq!(Arch::Ppc32.pointer_width(), 4);
    assert_eq!(Arch::RiscV32.pointer_width(), 4);
}

#[test]
fn arch_pointer_width_64bit() {
    assert_eq!(Arch::X86_64.pointer_width(), 8);
    assert_eq!(Arch::Arm64.pointer_width(), 8);
    assert_eq!(Arch::Mips64.pointer_width(), 8);
    assert_eq!(Arch::Ppc64.pointer_width(), 8);
    assert_eq!(Arch::RiscV64.pointer_width(), 8);
}

#[test]
fn arch_pointer_width_other_default() {
    assert_eq!(Arch::Other("wasm32".into()).pointer_width(), 4);
}

#[test]
fn arch_display() {
    assert_eq!(Arch::X86.to_string(), "x86");
    assert_eq!(Arch::X86_64.to_string(), "x86_64");
    assert_eq!(Arch::Arm32.to_string(), "arm32");
    assert_eq!(Arch::Arm64.to_string(), "arm64");
    assert_eq!(Arch::Mips32.to_string(), "mips32");
    assert_eq!(Arch::Mips64.to_string(), "mips64");
    assert_eq!(Arch::Ppc32.to_string(), "ppc32");
    assert_eq!(Arch::Ppc64.to_string(), "ppc64");
    assert_eq!(Arch::RiscV32.to_string(), "riscv32");
    assert_eq!(Arch::RiscV64.to_string(), "riscv64");
    assert_eq!(Arch::Other("custom".into()).to_string(), "custom");
}

#[test]
fn os_display() {
    assert_eq!(Os::Linux.to_string(), "linux");
    assert_eq!(Os::Windows.to_string(), "windows");
    assert_eq!(Os::MacOs.to_string(), "macos");
    assert_eq!(Os::FreeBsd.to_string(), "freebsd");
    assert_eq!(Os::Bare.to_string(), "bare");
    assert_eq!(Os::Other("redox".into()).to_string(), "redox");
}

#[test]
fn compiler_display() {
    assert_eq!(Compiler::Gcc.to_string(), "gcc");
    assert_eq!(Compiler::Msvc.to_string(), "msvc");
    assert_eq!(Compiler::Clang.to_string(), "clang");
    assert_eq!(Compiler::Icc.to_string(), "icc");
    assert_eq!(Compiler::Any.to_string(), "any");
}

#[test]
fn arch_eq_and_hash_consistency() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(Arch::X86_64);
    s.insert(Arch::X86_64);
    assert_eq!(s.len(), 1);
    assert_ne!(Arch::X86, Arch::X86_64);
}

// ───────────────────────── CallingConventionPattern ─────────────────────────

#[test]
fn sysv_x64_basic_fields() {
    let cc = sysv_x64();
    assert_eq!(cc.arg_registers, vec!["rdi", "rsi", "rdx", "rcx", "r8", "r9"]);
    assert_eq!(cc.max_reg_args, 6);
    assert_eq!(cc.shadow_space_bytes, 0);
    assert!(cc.caller_cleanup);
    assert!(!cc.hidden_this_ptr);
    assert!(cc.supports_variadic);
}

#[test]
fn msvc_x64_basic_fields() {
    let cc = msvc_x64();
    assert_eq!(cc.arg_registers, vec!["rcx", "rdx", "r8", "r9"]);
    assert_eq!(cc.shadow_space_bytes, 32);
    assert_eq!(cc.max_reg_args, 4);
}

#[test]
fn thiscall_has_hidden_this() {
    let cc = thiscall_x86();
    assert!(cc.hidden_this_ptr);
    assert_eq!(cc.arg_registers, vec!["ecx"]);
    assert!(!cc.caller_cleanup);
}

#[test]
fn cdecl_no_register_args() {
    let cc = cdecl_x86();
    assert!(cc.arg_registers.is_empty());
    assert_eq!(cc.max_reg_args, 0);
    assert!(cc.caller_cleanup);
}

#[test]
fn stdcall_callee_cleans() {
    let cc = stdcall_x86();
    assert!(!cc.caller_cleanup);
    assert!(cc.arg_registers.is_empty());
}

#[test]
fn pattern_is_arg_register() {
    let cc = sysv_x64();
    assert!(cc.is_arg_register("rdi"));
    assert!(cc.is_arg_register("xmm0"));
    assert!(!cc.is_arg_register("rbx"));
    assert!(!cc.is_arg_register("nonexistent"));
}

#[test]
fn pattern_is_callee_saved() {
    let cc = sysv_x64();
    assert!(cc.is_callee_saved("rbx"));
    assert!(cc.is_callee_saved("r12"));
    assert!(!cc.is_callee_saved("rax"));
}

#[test]
fn pattern_is_retval_register() {
    let cc = sysv_x64();
    assert!(cc.is_retval_register("rax"));
    assert!(cc.is_retval_register("rdx"));
    assert!(!cc.is_retval_register("rbx"));
}

#[test]
fn pattern_arg_register_at() {
    let cc = sysv_x64();
    assert_eq!(cc.arg_register_at(0), Some("rdi"));
    assert_eq!(cc.arg_register_at(5), Some("r9"));
    assert_eq!(cc.arg_register_at(6), None);
    assert_eq!(cc.arg_register_at(usize::MAX), None);
}

#[test]
fn pattern_arg_register_count() {
    assert_eq!(sysv_x64().arg_register_count(), 6);
    assert_eq!(msvc_x64().arg_register_count(), 4);
    assert_eq!(cdecl_x86().arg_register_count(), 0);
    assert_eq!(aapcs64().arg_register_count(), 8);
}

#[test]
fn pattern_display() {
    let s = sysv_x64().to_string();
    assert!(s.contains("System V"));
    assert!(s.contains("align=16"));
}

// ───────────────────────── ObservedPattern ─────────────────────────

#[test]
fn observed_pattern_default_empty() {
    let o = ObservedPattern::new();
    assert!(!o.has_arg_evidence());
    assert!(o.looks_like_leaf());
    assert_eq!(o.callee_stack_pop, 0);
}

#[test]
fn observed_pattern_has_arg_evidence() {
    let mut o = ObservedPattern::new();
    o.read_before_write.push("rdi".into());
    assert!(o.has_arg_evidence());
}

#[test]
fn observed_pattern_fp_arg_evidence() {
    let mut o = ObservedPattern::new();
    o.fp_read_before_write.push("xmm0".into());
    assert!(o.has_arg_evidence());
}

#[test]
fn observed_pattern_looks_like_leaf_threshold() {
    let mut o = ObservedPattern::new();
    o.max_stack_frame = 16;
    assert!(o.looks_like_leaf());
    o.max_stack_frame = 17;
    assert!(!o.looks_like_leaf());
}

#[test]
fn observed_pattern_not_leaf_with_saves() {
    let mut o = ObservedPattern::new();
    o.saved_registers.push("rbx".into());
    assert!(!o.looks_like_leaf());
}

// ───────────────────────── Score ─────────────────────────

#[test]
fn score_zero_for_empty_observed() {
    let cc = sysv_x64();
    let o = ObservedPattern::new();
    // Empty observed should still get the +5 callee_pops match bonus
    // (callee_pops_stack=false and caller_cleanup=true => false == !true)
    assert_eq!(cc.score(&o), 5);
}

#[test]
fn score_increases_with_arg_match() {
    let cc = sysv_x64();
    let mut o = ObservedPattern::new();
    o.read_before_write.push("rdi".into());
    let s1 = cc.score(&o);
    o.read_before_write.push("rsi".into());
    let s2 = cc.score(&o);
    assert!(s2 > s1);
}

#[test]
fn score_penalty_for_contradicting_args() {
    let cc = sysv_x64();
    let mut o = ObservedPattern::new();
    // r99 is not arg/fp_arg/caller_saved/callee_saved for sysv_x64
    o.read_before_write.push("zzz_made_up".into());
    // Score = 0 + 5 (callee_pops) - 2 (penalty) = 3
    assert_eq!(cc.score(&o), 3);
}

// ───────────────────────── CallingConventionDetector ─────────────────────────

#[test]
fn extract_pattern_empty_input() {
    let o = CallingConventionDetector::extract_pattern(&[], 8);
    assert!(o.read_before_write.is_empty());
    assert_eq!(o.max_stack_frame, 0);
}

#[test]
fn extract_pattern_read_before_write() {
    let instrs = vec![
        DetectInstr::RegRead { reg: "rdi".into() },
        DetectInstr::RegRead { reg: "rsi".into() },
        DetectInstr::RegWrite { reg: "rax".into() },
    ];
    let o = CallingConventionDetector::extract_pattern(&instrs, 8);
    assert_eq!(o.read_before_write, vec!["rdi", "rsi"]);
}

#[test]
fn extract_pattern_write_then_read_not_arg() {
    let instrs = vec![
        DetectInstr::RegWrite { reg: "rax".into() },
        DetectInstr::RegRead { reg: "rax".into() },
    ];
    let o = CallingConventionDetector::extract_pattern(&instrs, 8);
    assert!(o.read_before_write.is_empty());
}

#[test]
fn extract_pattern_dedup_reads() {
    let instrs = vec![
        DetectInstr::RegRead { reg: "rdi".into() },
        DetectInstr::RegRead { reg: "rdi".into() },
        DetectInstr::RegRead { reg: "rdi".into() },
    ];
    let o = CallingConventionDetector::extract_pattern(&instrs, 8);
    assert_eq!(o.read_before_write, vec!["rdi"]);
}

#[test]
fn extract_pattern_saved_registers() {
    let instrs = vec![
        DetectInstr::Push { reg: "rbx".into() },
        DetectInstr::Push { reg: "r12".into() },
        DetectInstr::Pop { reg: "r12".into() },
        DetectInstr::Pop { reg: "rbx".into() },
    ];
    let o = CallingConventionDetector::extract_pattern(&instrs, 8);
    assert!(o.saved_registers.contains(&"rbx".to_string()));
    assert!(o.saved_registers.contains(&"r12".to_string()));
}

#[test]
fn extract_pattern_pushed_only_not_saved() {
    let instrs = vec![DetectInstr::Push { reg: "rbx".into() }];
    let o = CallingConventionDetector::extract_pattern(&instrs, 8);
    assert!(o.saved_registers.is_empty());
}

#[test]
fn extract_pattern_callee_pops_via_ret_n() {
    let instrs = vec![DetectInstr::Ret { stack_bytes: 16 }];
    let o = CallingConventionDetector::extract_pattern(&instrs, 4);
    assert!(o.callee_pops_stack);
    assert_eq!(o.callee_stack_pop, 16);
}

#[test]
fn extract_pattern_ret_zero_means_caller_cleanup() {
    let instrs = vec![DetectInstr::Ret { stack_bytes: 0 }];
    let o = CallingConventionDetector::extract_pattern(&instrs, 4);
    assert!(!o.callee_pops_stack);
}

#[test]
fn extract_pattern_shadow_space() {
    let instrs = vec![DetectInstr::StackAlloc { bytes: 32 }];
    let o = CallingConventionDetector::extract_pattern(&instrs, 8);
    assert!(o.shadow_space_observed);
    assert_eq!(o.max_stack_frame, 32);
}

#[test]
fn extract_pattern_no_shadow_space_under_32() {
    let instrs = vec![DetectInstr::StackAlloc { bytes: 16 }];
    let o = CallingConventionDetector::extract_pattern(&instrs, 8);
    assert!(!o.shadow_space_observed);
}

#[test]
fn extract_pattern_max_stack_frame_tracks_max() {
    let instrs = vec![
        DetectInstr::StackAlloc { bytes: 16 },
        DetectInstr::StackAlloc { bytes: 64 },
        DetectInstr::StackAlloc { bytes: 8 },
    ];
    let o = CallingConventionDetector::extract_pattern(&instrs, 8);
    assert_eq!(o.max_stack_frame, 64);
}

#[test]
fn extract_pattern_this_ptr_hint() {
    let instrs = vec![DetectInstr::ThisPtrUse];
    let o = CallingConventionDetector::extract_pattern(&instrs, 4);
    assert!(o.this_ptr_hint);
}

#[test]
fn extract_pattern_stack_arg_count_64bit() {
    let instrs = vec![
        DetectInstr::StackArgAccess { offset: 0 },
        DetectInstr::StackArgAccess { offset: 8 },
        DetectInstr::StackArgAccess { offset: 16 },
    ];
    let o = CallingConventionDetector::extract_pattern(&instrs, 8);
    // max offset 16 / pw 8 = 2, +1 = 3
    assert_eq!(o.stack_arg_count, 3);
}

#[test]
fn extract_pattern_stack_arg_count_32bit() {
    let instrs = vec![DetectInstr::StackArgAccess { offset: 8 }];
    let o = CallingConventionDetector::extract_pattern(&instrs, 4);
    // 8 / 4 = 2, +1 = 3
    assert_eq!(o.stack_arg_count, 3);
}

#[test]
fn extract_pattern_pointer_width_zero_defaults_to_4() {
    let instrs = vec![DetectInstr::StackArgAccess { offset: 4 }];
    let o = CallingConventionDetector::extract_pattern(&instrs, 0);
    // 4/4 + 1 = 2
    assert_eq!(o.stack_arg_count, 2);
}

#[test]
fn extract_pattern_no_stack_args_no_offset() {
    let instrs: Vec<DetectInstr> = vec![DetectInstr::Other];
    let o = CallingConventionDetector::extract_pattern(&instrs, 8);
    assert_eq!(o.stack_arg_count, 0);
}

#[test]
fn extract_pattern_fp_read_before_write() {
    let instrs = vec![
        DetectInstr::FpRegRead { reg: "xmm0".into() },
        DetectInstr::FpRegRead { reg: "xmm0".into() }, // dup
        DetectInstr::FpRegRead { reg: "xmm1".into() },
    ];
    let o = CallingConventionDetector::extract_pattern(&instrs, 8);
    assert_eq!(o.fp_read_before_write, vec!["xmm0", "xmm1"]);
}

#[test]
fn extract_pattern_written_before_return_captures_recent() {
    let instrs = vec![
        DetectInstr::RegWrite { reg: "rax".into() },
        DetectInstr::Ret { stack_bytes: 0 },
    ];
    let o = CallingConventionDetector::extract_pattern(&instrs, 8);
    assert!(o.written_before_return.contains(&"rax".to_string()));
}

// ───────────────────────── detect / detect_with_hints ─────────────────────────

#[test]
fn detect_empty_candidates_is_nomatch() {
    let o = ObservedPattern::new();
    let r = CallingConventionDetector::detect(&o, &[]);
    assert!(matches!(r, Err(CallConvError::NoMatch)));
}

#[test]
fn detect_picks_best() {
    let mut o = ObservedPattern::new();
    o.read_before_write = vec!["rdi".into(), "rsi".into(), "rdx".into()];
    let candidates = vec![sysv_x64(), msvc_x64()];
    let r = CallingConventionDetector::detect(&o, &candidates).unwrap();
    assert_eq!(r.name, "System V AMD64 ABI");
}

#[test]
fn detect_msvc_picks_msvc() {
    let mut o = ObservedPattern::new();
    o.read_before_write = vec!["rcx".into(), "rdx".into(), "r8".into(), "r9".into()];
    o.shadow_space_observed = true;
    let candidates = vec![sysv_x64(), msvc_x64()];
    let r = CallingConventionDetector::detect_with_hints(&o, &candidates).unwrap();
    assert_eq!(r.name, "Microsoft x64");
}

#[test]
fn detect_with_hints_empty_is_nomatch() {
    let o = ObservedPattern::new();
    let r = CallingConventionDetector::detect_with_hints(&o, &[]);
    assert!(matches!(r, Err(CallConvError::NoMatch)));
}

#[test]
fn detect_with_hints_thiscall_via_this_hint() {
    let mut o = ObservedPattern::new();
    o.read_before_write = vec!["ecx".into()];
    o.this_ptr_hint = true;
    o.callee_pops_stack = true;
    // fastcall and thiscall both have ecx; thiscall has hidden_this
    let candidates = vec![fastcall_x86(), thiscall_x86()];
    let r = CallingConventionDetector::detect_with_hints(&o, &candidates).unwrap();
    assert_eq!(r.name, "thiscall (x86)");
}

#[test]
fn rank_candidates_sorted_desc() {
    let mut o = ObservedPattern::new();
    o.read_before_write = vec!["rdi".into(), "rsi".into()];
    let candidates = vec![msvc_x64(), sysv_x64(), cdecl_x86()];
    let ranked = CallingConventionDetector::rank_candidates(&o, &candidates);
    assert_eq!(ranked.len(), 3);
    for w in ranked.windows(2) {
        assert!(w[0].1 >= w[1].1);
    }
    assert_eq!(ranked[0].0.name, "System V AMD64 ABI");
}

#[test]
fn rank_candidates_empty_input() {
    let o = ObservedPattern::new();
    let ranked = CallingConventionDetector::rank_candidates(&o, &[]);
    assert!(ranked.is_empty());
}

// ───────────────────────── CcKey & CallingConventionDatabase ─────────────────────────

#[test]
fn cckey_display() {
    let k = CcKey::new(Arch::X86_64, Os::Linux, Compiler::Gcc);
    assert_eq!(k.to_string(), "x86_64/linux/gcc");
}

#[test]
fn cckey_eq_hash() {
    use std::collections::HashMap;
    let mut m = HashMap::new();
    m.insert(CcKey::new(Arch::X86, Os::Windows, Compiler::Msvc), 1);
    assert_eq!(
        m.get(&CcKey::new(Arch::X86, Os::Windows, Compiler::Msvc)),
        Some(&1)
    );
}

#[test]
fn db_new_empty() {
    let db = CallingConventionDatabase::new();
    assert_eq!(db.key_count(), 0);
    assert_eq!(db.entry_count(), 0);
    assert!(db.all_names().is_empty());
}

#[test]
fn db_with_builtins_nonempty() {
    let db = CallingConventionDatabase::with_builtins();
    assert!(db.key_count() > 0);
    assert!(db.entry_count() > 0);
    let names = db.all_names();
    assert!(names.iter().any(|n| n.contains("System V")));
    assert!(names.iter().any(|n| n.contains("Microsoft x64")));
    assert!(names.iter().any(|n| n.contains("cdecl")));
}

#[test]
fn db_lookup_known_key() {
    let db = CallingConventionDatabase::with_builtins();
    let k = CcKey::new(Arch::X86_64, Os::Linux, Compiler::Gcc);
    let ccs = db.lookup(&k);
    assert!(!ccs.is_empty());
    assert!(ccs.iter().any(|c| c.name.contains("System V")));
}

#[test]
fn db_lookup_unknown_key_returns_empty() {
    let db = CallingConventionDatabase::with_builtins();
    let k = CcKey::new(Arch::Other("nonexistent".into()), Os::Bare, Compiler::Icc);
    assert!(db.lookup(&k).is_empty());
}

#[test]
fn db_register_and_lookup() {
    let mut db = CallingConventionDatabase::new();
    let k = CcKey::new(Arch::X86, Os::Linux, Compiler::Gcc);
    db.register(k.clone(), cdecl_x86());
    assert_eq!(db.lookup(&k).len(), 1);
    db.register(k.clone(), stdcall_x86());
    assert_eq!(db.lookup(&k).len(), 2);
}

#[test]
fn db_lookup_any_compiler() {
    let db = CallingConventionDatabase::with_builtins();
    let v = db.lookup_any_compiler(&Arch::X86_64, &Os::Linux);
    assert!(!v.is_empty());
}

#[test]
fn db_lookup_any_os() {
    let db = CallingConventionDatabase::with_builtins();
    let v = db.lookup_any_os(&Arch::Arm64);
    assert!(!v.is_empty());
}

#[test]
fn db_remove() {
    let mut db = CallingConventionDatabase::new();
    let k = CcKey::new(Arch::X86, Os::Linux, Compiler::Gcc);
    db.register(k.clone(), cdecl_x86());
    db.register(k.clone(), stdcall_x86());
    assert_eq!(db.remove(&k), 2);
    assert_eq!(db.remove(&k), 0);
}

#[test]
fn db_json_roundtrip() {
    let db = CallingConventionDatabase::with_builtins();
    let json = db.to_json().unwrap();
    let db2 = CallingConventionDatabase::from_json(&json).unwrap();
    assert_eq!(db.entry_count(), db2.entry_count());
    assert_eq!(db.key_count(), db2.key_count());
}

#[test]
fn db_from_json_malformed() {
    let r = CallingConventionDatabase::from_json("not json");
    assert!(matches!(r, Err(CallConvError::Json(_))));
}

#[test]
fn db_from_json_empty_array() {
    let db = CallingConventionDatabase::from_json("[]").unwrap();
    assert_eq!(db.key_count(), 0);
}

// ───────────────────────── FunctionCallConvSummary ─────────────────────────

#[test]
fn summary_new_no_runner_ups() {
    let s = FunctionCallConvSummary::new(0x1000, sysv_x64(), 50, ObservedPattern::new());
    assert_eq!(s.function_address, 0x1000);
    assert_eq!(s.confidence, 50);
    assert!(s.runner_ups.is_empty());
    assert!(s.is_high_confidence());
}

#[test]
fn summary_low_confidence() {
    let s = FunctionCallConvSummary::new(0, sysv_x64(), 19, ObservedPattern::new());
    assert!(!s.is_high_confidence());
}

#[test]
fn summary_high_confidence_boundary() {
    let s = FunctionCallConvSummary::new(0, sysv_x64(), 20, ObservedPattern::new());
    assert!(s.is_high_confidence());
}

#[test]
fn summary_with_runner_ups() {
    let s = FunctionCallConvSummary::new(0, sysv_x64(), 50, ObservedPattern::new())
        .with_runner_ups(vec![("ms_x64".into(), 30)]);
    assert_eq!(s.runner_ups.len(), 1);
}

// ───────────────────────── BulkCallConvAnalyzer ─────────────────────────

#[test]
fn bulk_analyze_unknown_key_errors() {
    let db = CallingConventionDatabase::new();
    let k = CcKey::new(Arch::X86_64, Os::Linux, Compiler::Gcc);
    let a = BulkCallConvAnalyzer::new(db, k);
    let r = a.analyse_function(0, &[]);
    assert!(matches!(r, Err(CallConvError::UnknownKey(_))));
}

#[test]
fn bulk_analyze_sysv_function() {
    let db = CallingConventionDatabase::with_builtins();
    let k = CcKey::new(Arch::X86_64, Os::Linux, Compiler::Gcc);
    let a = BulkCallConvAnalyzer::new(db, k);
    let instrs = vec![
        DetectInstr::RegRead { reg: "rdi".into() },
        DetectInstr::RegRead { reg: "rsi".into() },
        DetectInstr::Push { reg: "rbx".into() },
        DetectInstr::Pop { reg: "rbx".into() },
        DetectInstr::RegWrite { reg: "rax".into() },
        DetectInstr::Ret { stack_bytes: 0 },
    ];
    let s = a.analyse_function(0x400000, &instrs).unwrap();
    assert_eq!(s.function_address, 0x400000);
    assert!(s.confidence > 0);
}

#[test]
fn bulk_analyze_all_filters_failures() {
    let db = CallingConventionDatabase::with_builtins();
    let k = CcKey::new(Arch::X86_64, Os::Linux, Compiler::Gcc);
    let a = BulkCallConvAnalyzer::new(db, k);
    let fns = vec![
        (
            0x1000u64,
            vec![DetectInstr::RegRead { reg: "rdi".into() }],
        ),
        (0x2000u64, vec![]),
    ];
    let out = a.analyse_all(&fns);
    // first should succeed; second has no evidence
    assert!(!out.is_empty());
}

// ───────────────────────── CallConvStats ─────────────────────────

#[test]
fn stats_empty() {
    let s = CallConvStats::compute(&[]);
    assert_eq!(s.total, 0);
    assert_eq!(s.high_confidence, 0);
    assert_eq!(s.max_confidence, 0);
    assert_eq!(s.min_confidence, 0);
    assert!(s.most_common().is_none());
}

#[test]
fn stats_compute_basic() {
    let summaries = vec![
        FunctionCallConvSummary::new(0, sysv_x64(), 30, ObservedPattern::new()),
        FunctionCallConvSummary::new(1, sysv_x64(), 50, ObservedPattern::new()),
        FunctionCallConvSummary::new(2, msvc_x64(), 10, ObservedPattern::new()),
    ];
    let s = CallConvStats::compute(&summaries);
    assert_eq!(s.total, 3);
    assert_eq!(s.high_confidence, 2);
    assert_eq!(s.max_confidence, 50);
    assert_eq!(s.min_confidence, 10);
    assert!((s.avg_confidence - 30.0).abs() < 1e-9);
    assert_eq!(s.most_common(), Some("System V AMD64 ABI"));
}

// ───────────────────────── RegisterClassifier ─────────────────────────

#[test]
fn classifier_argument() {
    let cc = sysv_x64();
    assert_eq!(
        RegisterClassifier::classify(&cc, "rdi"),
        RegisterRole::Argument
    );
}

#[test]
fn classifier_fp_argument() {
    let cc = sysv_x64();
    assert_eq!(
        RegisterClassifier::classify(&cc, "xmm0"),
        RegisterRole::FpArgument
    );
}

#[test]
fn classifier_return_value() {
    let cc = msvc_x64();
    assert_eq!(
        RegisterClassifier::classify(&cc, "rax"),
        RegisterRole::ReturnValue
    );
}

#[test]
fn classifier_callee_saved() {
    let cc = sysv_x64();
    assert_eq!(
        RegisterClassifier::classify(&cc, "rbx"),
        RegisterRole::CalleeSaved
    );
}

#[test]
fn classifier_caller_saved() {
    let cc = sysv_x64();
    // r10/r11 are caller-saved only (not arg, not retval, not callee-saved)
    assert_eq!(
        RegisterClassifier::classify(&cc, "r10"),
        RegisterRole::CallerSaved
    );
}

#[test]
fn classifier_unknown() {
    let cc = sysv_x64();
    assert_eq!(
        RegisterClassifier::classify(&cc, "xyz999"),
        RegisterRole::Unknown
    );
}

#[test]
fn classifier_registers_with_role() {
    let cc = sysv_x64();
    let args = RegisterClassifier::registers_with_role(&cc, RegisterRole::Argument);
    assert_eq!(args.len(), 6);
    let unk = RegisterClassifier::registers_with_role(&cc, RegisterRole::Unknown);
    assert!(unk.is_empty());
}

// ───────────────────────── ParameterMapper ─────────────────────────

#[test]
fn mapper_map_args_preserves_abi_order() {
    let cc = sysv_x64();
    let reads = vec!["rdx".into(), "rdi".into()];
    let m = ParameterMapper::map_args(&reads, &cc);
    // ABI order: rdi (0), rdx (2)
    assert_eq!(m, vec![(0, "rdi".into()), (2, "rdx".into())]);
}

#[test]
fn mapper_estimated_arg_count() {
    let cc = sysv_x64();
    let mut o = ObservedPattern::new();
    o.read_before_write = vec!["rdi".into(), "rsi".into()];
    o.stack_arg_count = 3;
    assert_eq!(ParameterMapper::estimated_arg_count(&o, &cc), 5);
}

// ───────────────────────── CallingConvDef static defs ─────────────────────────

#[test]
fn cc_def_is_int_arg() {
    assert!(CC_SYSV_AMD64.is_int_arg("rdi"));
    assert!(!CC_SYSV_AMD64.is_int_arg("rbx"));
    assert!(CC_MS_X64.is_int_arg("rcx"));
    assert!(!CC_MS_X64.is_int_arg("rdi"));
}

#[test]
fn cc_def_is_float_arg() {
    assert!(CC_SYSV_AMD64.is_float_arg("xmm0"));
    assert!(!CC_CDECL.is_float_arg("xmm0"));
}

#[test]
fn cc_def_is_callee_saved() {
    assert!(CC_SYSV_AMD64.is_callee_saved("rbx"));
    assert!(CC_MS_X64.is_callee_saved("rdi"));
    assert!(!CC_SYSV_AMD64.is_callee_saved("rdi"));
}

#[test]
fn cc_def_display() {
    let s = CC_SYSV_AMD64.to_string();
    assert!(s.contains("sysv_amd64"));
    assert!(s.contains("caller"));
}

#[test]
fn cc_stack_cleanup_display() {
    assert_eq!(CcStackCleanup::Caller.to_string(), "caller");
    assert_eq!(CcStackCleanup::Callee.to_string(), "callee");
}

// ───────────────────────── CallConvDatabase (static) ─────────────────────────

#[test]
fn ccdb_with_builtins_has_seven() {
    let db = CallConvDatabase::with_builtins();
    assert_eq!(db.len(), 7);
    assert!(!db.is_empty());
}

#[test]
fn ccdb_get_by_name() {
    let db = CallConvDatabase::with_builtins();
    assert_eq!(db.get("sysv_amd64").map(|c| c.name), Some("sysv_amd64"));
    assert!(db.get("does_not_exist").is_none());
}

#[test]
fn ccdb_new_empty() {
    let db = CallConvDatabase::new();
    assert!(db.is_empty());
    assert_eq!(db.len(), 0);
}

#[test]
fn ccdb_names_sorted() {
    let db = CallConvDatabase::with_builtins();
    let names = db.names();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted);
}

#[test]
fn ccdb_all_returns_seven() {
    let db = CallConvDatabase::with_builtins();
    assert_eq!(db.all().len(), 7);
}

#[test]
fn ccdb_default_is_empty() {
    let db = CallConvDatabase::default();
    assert!(db.is_empty());
}

// ───────────────────────── Instruction constructors ─────────────────────────

#[test]
fn instruction_rw() {
    let i = Instruction::rw(0x1000, vec!["rdi".into()], vec!["rax".into()]);
    assert_eq!(i.address, 0x1000);
    assert!(!i.is_push && !i.is_pop && !i.is_ret && !i.is_call);
}

#[test]
fn instruction_push() {
    let i = Instruction::push(0x10, "rbx");
    assert!(i.is_push);
    assert_eq!(i.reads, vec!["rbx"]);
    assert!(i.writes.is_empty());
}

#[test]
fn instruction_pop() {
    let i = Instruction::pop(0x20, "rbx");
    assert!(i.is_pop);
    assert_eq!(i.writes, vec!["rbx"]);
    assert!(i.reads.is_empty());
}

#[test]
fn instruction_ret() {
    let i = Instruction::ret(0x30, 12);
    assert!(i.is_ret);
    assert_eq!(i.ret_stack_bytes, 12);
}

// ───────────────────────── detect_calling_convention ─────────────────────────

#[test]
fn dcc_empty_instructions() {
    let r = detect_calling_convention(&[], &[&CC_SYSV_AMD64]);
    assert!(r.is_none());
}

#[test]
fn dcc_empty_candidates() {
    let instrs = vec![Instruction::rw(0, vec!["rdi".into()], vec![])];
    let r = detect_calling_convention(&instrs, &[]);
    assert!(r.is_none());
}

#[test]
fn dcc_detects_sysv() {
    let instrs = vec![
        Instruction::push(0x0, "rbx"),
        Instruction::rw(0x1, vec!["rdi".into(), "rsi".into()], vec![]),
        Instruction::pop(0x2, "rbx"),
        Instruction::ret(0x3, 0),
    ];
    let r = detect_calling_convention(&instrs, &[&CC_SYSV_AMD64, &CC_MS_X64]);
    assert_eq!(r.map(|c| c.name), Some("sysv_amd64"));
}

#[test]
fn dcc_detects_msvc_x64() {
    // Use rsi as callee-saved push in MSVC (also caller-saved in SysV, which is
    // why we pick it: it gives MSVC the +6 callee_saved bonus without polluting
    // SysV's int_arg overlap). Reads use rcx/rdx/r8/r9 which are int args in
    // both ABIs, but MSVC's preserved-set bonus tips the balance.
    // Use a shadow-space stack allocation (>= 32) to give MSVC the +10 hint
    // edge that SysV doesn't qualify for (shadow_space=0).
    let mut alloc = Instruction::rw(0x0, vec![], vec![]);
    alloc.stack_alloc = 32;
    let instrs = vec![
        alloc,
        Instruction::rw(
            0x1,
            vec!["rcx".into(), "rdx".into(), "r8".into(), "r9".into()],
            vec![],
        ),
        Instruction::ret(0x2, 0),
    ];
    let r = detect_calling_convention(&instrs, &[&CC_SYSV_AMD64, &CC_MS_X64]);
    assert_eq!(r.map(|c| c.name), Some("ms_x64"));
}

#[test]
fn dcc_detects_stdcall_via_callee_pop() {
    let instrs = vec![
        Instruction::push(0x0, "ebx"),
        Instruction::pop(0x1, "ebx"),
        Instruction::ret(0x2, 8),
    ];
    let r = detect_calling_convention(&instrs, &[&CC_CDECL, &CC_STDCALL]);
    assert_eq!(r.map(|c| c.name), Some("stdcall"));
}

#[test]
fn dcc_thiscall_with_hint() {
    let mut this_use = Instruction::rw(0x0, vec!["ecx".into()], vec![]);
    this_use.is_this_ptr_use = true;
    let instrs = vec![
        this_use,
        Instruction::push(0x1, "ebx"),
        Instruction::pop(0x2, "ebx"),
        Instruction::ret(0x3, 4),
    ];
    let r = detect_calling_convention(&instrs, &[&CC_FASTCALL, &CC_THISCALL]);
    assert_eq!(r.map(|c| c.name), Some("thiscall"));
}

// ───────────────────────── get_arg_types / CallConvAnalysisResult ─────────────────────────

#[test]
fn get_arg_types_sysv_two_int_args() {
    let mut fi = FunctionInfo::new(0x100, "sysv_amd64");
    fi.live_in_regs = vec!["rdi".into(), "rsi".into()];
    let args = get_arg_types(&fi, &CC_SYSV_AMD64);
    assert_eq!(args.len(), 2);
    assert!(matches!(args[0], ArgType::Integer { ref reg, position: 0 } if reg == "rdi"));
    assert!(matches!(args[1], ArgType::Integer { ref reg, position: 1 } if reg == "rsi"));
}

#[test]
fn get_arg_types_thiscall_emits_this() {
    let mut fi = FunctionInfo::new(0x100, "thiscall");
    fi.live_in_regs = vec!["ecx".into()];
    fi.has_this_ptr = true;
    let args = get_arg_types(&fi, &CC_THISCALL);
    assert!(matches!(args[0], ArgType::ThisPtr { ref reg } if reg == "ecx"));
}

#[test]
fn get_arg_types_with_stack_args() {
    let mut fi = FunctionInfo::new(0x100, "cdecl");
    fi.stack_arg_count = 2;
    let args = get_arg_types(&fi, &CC_CDECL);
    assert_eq!(args.len(), 2);
    assert!(matches!(args[0], ArgType::Stack { slot: 0, .. }));
    assert!(matches!(args[1], ArgType::Stack { slot: 1, .. }));
}

#[test]
fn get_arg_types_float_args() {
    let mut fi = FunctionInfo::new(0x100, "sysv_amd64");
    fi.live_in_fp_regs = vec!["xmm0".into(), "xmm1".into()];
    let args = get_arg_types(&fi, &CC_SYSV_AMD64);
    assert!(args.iter().any(|a| matches!(a, ArgType::Float { reg, .. } if reg == "xmm0")));
}

#[test]
fn argtype_display() {
    let a = ArgType::Integer {
        reg: "rdi".into(),
        position: 0,
    };
    assert!(a.to_string().contains("rdi"));
    let s = ArgType::Stack {
        slot: 1,
        offset: 0x10,
    };
    assert!(s.to_string().contains("0x10"));
    let u = ArgType::Unknown { position: 3 };
    assert!(u.to_string().contains("3"));
}

#[test]
fn analysis_result_no_match_when_empty() {
    let r = CallConvAnalysisResult::analyze(0x100, &[], &[&CC_SYSV_AMD64]);
    assert!(r.cc.is_none());
    assert!(r.args.is_empty());
}

#[test]
fn analysis_result_full_pipeline() {
    let instrs = vec![
        Instruction::push(0x0, "rbx"),
        Instruction::rw(0x1, vec!["rdi".into()], vec![]),
        Instruction::pop(0x2, "rbx"),
        Instruction::ret(0x3, 0),
    ];
    let r = CallConvAnalysisResult::analyze(
        0x400,
        &instrs,
        &[&CC_SYSV_AMD64, &CC_MS_X64],
    );
    assert_eq!(r.address, 0x400);
    assert!(r.cc.is_some());
    assert!(r.live_in.contains(&"rdi".to_string()));
    assert!(r.preserved.contains(&"rbx".to_string()));
    assert!(!r.callee_cleans_stack);
}

// ───────────────────────── CallingConventionPass ─────────────────────────

#[test]
fn pass_default_and_new() {
    let _p1 = CallingConventionPass::new();
    let _p2 = CallingConventionPass::default();
    let s = format!("{:?}", CallingConventionPass);
    assert!(s.contains("CallingConventionPass"));
}

// ───────────────────────── Error type ─────────────────────────

#[test]
fn error_display_messages() {
    assert!(CallConvError::NoMatch.to_string().contains("no calling convention"));
    assert!(CallConvError::Ambiguous.to_string().contains("ambiguous"));
    assert!(
        CallConvError::UnknownKey("x".into())
            .to_string()
            .contains("unknown")
    );
    let e = CallConvError::TooShort { got: 1, need: 5 };
    let s = e.to_string();
    assert!(s.contains("1") && s.contains("5"));
}

// ───────────────────────── Re-exports from heuristics & cc_database ─────────────────────────

#[test]
fn heuristics_default_callee_saved_smoke() {
    // Just exercise the re-exported function; should not panic.
    let _saved = default_callee_saved(&Arch::X86_64);
}

#[test]
fn heuristics_classify_stack_cleanup_smoke() {
    // Re-exported function; smoke test.
    let _v = classify_stack_cleanup(&[DetectInstr::Ret { stack_bytes: 0 }]);
    let _v2 = classify_stack_cleanup(&[DetectInstr::Ret { stack_bytes: 16 }]);
}

#[test]
fn cc_database_reexports_exist() {
    // Touch a few static CC defs from the cc_database module to ensure they exist.
    let _ = CC_SYSV_AMD64_DB;
    let _ = CC_MS_X64_DB;
    let _ = CC_CDECL_X86;
    let _ = CC_STDCALL_X86;
    let _ = CC_FASTCALL_X86;
    let _ = CC_THISCALL_X86;
    let _ = CC_VECTORCALL_X64;
}

#[test]
fn cc_registry_smoke() {
    // CcRegistry is re-exported; ensure constructible if it has a Default or new.
    // If not, the symbol existence test above suffices.
    let _ = std::any::type_name::<CcRegistry>();
}
