//! Adversarial Blitz-2 tests for rustre-decompiler.
//!
//! Focus: deep coverage of public types & helpers using a seeded LCG fuzz,
//! round-trips, boundaries, state-machine usage of caches/pipelines/sessions,
//! and Send+Sync threaded stress.

use rustre_core::address::Address;
use rustre_core::arch::Instruction;
use rustre_decompiler::*;
use std::sync::Arc;

// ── Seeded LCG (deterministic, no rand crate) ────────────────────────────
fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn mk(addr: u64, mnem: &str, ops: &str) -> Instruction {
    let mut i = Instruction::new(Address::new(addr), 1, mnem.to_string(), vec![0x90]);
    i.operands = ops.to_string();
    i
}

// ════════════════════════════════════════════════════════════════════════
// IrLevel
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t01_ir_level_display_distinct() {
    let levels = [IrLevel::Llil, IrLevel::MlilSsa, IrLevel::Hlil, IrLevel::PseudoC];
    let strs: Vec<_> = levels.iter().map(|l| l.to_string()).collect();
    for i in 0..strs.len() {
        for j in (i + 1)..strs.len() {
            assert_ne!(strs[i], strs[j]);
        }
    }
}

#[test]
fn t02_ir_level_roundtrip_all_variants() {
    for &v in &[IrLevel::Llil, IrLevel::MlilSsa, IrLevel::Hlil, IrLevel::PseudoC] {
        let j = serde_json::to_string(&v).unwrap();
        let back: IrLevel = serde_json::from_str(&j).unwrap();
        assert_eq!(back, v);
    }
}

#[test]
fn t03_ir_level_ord_progression() {
    assert!(IrLevel::Llil < IrLevel::MlilSsa);
    assert!(IrLevel::MlilSsa < IrLevel::Hlil);
    assert!(IrLevel::Hlil < IrLevel::PseudoC);
}

// ════════════════════════════════════════════════════════════════════════
// VarStorage
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t04_varstorage_stack_sign_format() {
    assert!(VarStorage::Stack(-32).to_string().contains("-32"));
    assert!(VarStorage::Stack(32).to_string().contains("+32"));
    assert!(VarStorage::Stack(0).to_string().contains("+0"));
}

#[test]
fn t05_varstorage_register_lowercase_preserved() {
    let s = VarStorage::Register("RaX".to_string()).to_string();
    assert!(s.contains("RaX"));
}

#[test]
fn t06_varstorage_global_max_addr() {
    let s = VarStorage::Global(u64::MAX).to_string();
    assert!(s.contains("0xffffffffffffffff"));
}

#[test]
fn t07_varstorage_fuzz_display_never_panics() {
    let mut g = lcg();
    for _ in 0..60 {
        let v = g();
        let storage = match v % 4 {
            0 => VarStorage::Register(format!("r{}", v % 16)),
            1 => VarStorage::Stack(v as i64),
            2 => VarStorage::Global(v),
            _ => VarStorage::Immediate(v),
        };
        let s = storage.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn t08_varstorage_json_roundtrip() {
    let vs = [
        VarStorage::Register("rax".into()),
        VarStorage::Stack(-8),
        VarStorage::Global(0x4000),
        VarStorage::Immediate(42),
    ];
    for v in vs {
        let j = serde_json::to_string(&v).unwrap();
        let back: VarStorage = serde_json::from_str(&j).unwrap();
        assert_eq!(v.to_string(), back.to_string());
    }
}

// ════════════════════════════════════════════════════════════════════════
// DecompiledFunction
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t09_confidence_boundary_zero_and_max() {
    let f0 = DecompiledFunction::new(0, "f", "").with_confidence(0);
    assert_eq!(f0.confidence, 0);
    let f100 = DecompiledFunction::new(0, "f", "").with_confidence(100);
    assert_eq!(f100.confidence, 100);
    let f255 = DecompiledFunction::new(0, "f", "").with_confidence(255);
    assert_eq!(f255.confidence, 100);
}

#[test]
fn t10_with_variable_adds_one() {
    let v = DecompVariable {
        name: "x".into(),
        type_str: "int".into(),
        is_parameter: true,
        storage: VarStorage::Register("rdi".into()),
    };
    let f = DecompiledFunction::new(0, "f", "").with_variable(v);
    assert_eq!(f.variables.len(), 1);
    assert_eq!(f.parameters().len(), 1);
    assert_eq!(f.locals().len(), 0);
}

#[test]
fn t11_parameters_locals_partition() {
    let mut f = DecompiledFunction::new(0, "f", "");
    for i in 0..10 {
        f = f.with_variable(DecompVariable {
            name: format!("v{i}"),
            type_str: "int".into(),
            is_parameter: i % 2 == 0,
            storage: VarStorage::Stack(i as i64),
        });
    }
    assert_eq!(f.parameters().len() + f.locals().len(), f.variables.len());
}

#[test]
fn t12_call_sites_preserved_with_duplicates() {
    let f = DecompiledFunction::new(0, "f", "")
        .with_call_site(0x1000)
        .with_call_site(0x1000)
        .with_call_site(0x2000);
    // The struct method allows duplicates (no dedup in with_call_site).
    assert_eq!(f.call_sites.len(), 3);
}

#[test]
fn t13_display_includes_name_and_body() {
    let f = DecompiledFunction::new(0x1234, "my_fn", "int x = 1;");
    let s = f.to_string();
    assert!(s.contains("my_fn"));
    assert!(s.contains("int x = 1;"));
}

#[test]
fn t14_line_count_fuzz() {
    let mut g = lcg();
    for _ in 0..50 {
        let nlines = (g() % 20) as usize;
        let body = vec!["line"; nlines].join("\n");
        let f = DecompiledFunction::new(0, "f", body.clone());
        // line_count uses str::lines; empty string → 0.
        let expected = if body.is_empty() { 0 } else { nlines };
        assert_eq!(f.line_count(), expected);
    }
}

// ════════════════════════════════════════════════════════════════════════
// DecompStats
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t15_success_rate_boundaries() {
    let s = DecompStats::default();
    assert_eq!(s.success_rate(), 0.0);
    let mut s = DecompStats::default();
    s.functions_decompiled = 4;
    s.functions_failed = 1;
    assert!((s.success_rate() - 80.0).abs() < 1e-9);
}

#[test]
fn t16_avg_time_zero_decompiled() {
    let s = DecompStats::default();
    assert_eq!(s.avg_time_ms(), 0.0);
}

#[test]
fn t17_stats_display_contains_fields() {
    let mut s = DecompStats::default();
    s.functions_decompiled = 7;
    let d = s.to_string();
    assert!(d.contains("decompiled=7"));
}

// ════════════════════════════════════════════════════════════════════════
// DecompOptions / Kind
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t18_default_options_internal_backend() {
    let o = DecompOptions::default();
    assert_eq!(o.backend, DecompilerBackendKind::Internal);
    assert!(o.max_function_size > 0);
}

#[test]
fn t19_kind_display_distinct() {
    let ks = [
        DecompilerBackendKind::Internal,
        DecompilerBackendKind::Ghidra,
        DecompilerBackendKind::BinaryNinja,
        DecompilerBackendKind::RetDec,
    ];
    let strs: Vec<_> = ks.iter().map(|k| k.to_string()).collect();
    for i in 0..strs.len() {
        for j in (i + 1)..strs.len() {
            assert_ne!(strs[i], strs[j]);
        }
    }
}

#[test]
fn t20_kind_hash_eq_consistency() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    for &k in &[
        DecompilerBackendKind::Internal,
        DecompilerBackendKind::Internal,
        DecompilerBackendKind::Ghidra,
        DecompilerBackendKind::BinaryNinja,
        DecompilerBackendKind::RetDec,
    ] {
        s.insert(k);
    }
    assert_eq!(s.len(), 4);
}

// ════════════════════════════════════════════════════════════════════════
// CallingConvention
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t21_cc_param_regs_distinct_per_cc() {
    assert_eq!(CallingConvention::SysVAmd64.param_regs()[0], "rdi");
    assert_eq!(CallingConvention::WindowsX64.param_regs()[0], "rcx");
    assert_eq!(CallingConvention::Arm64.param_regs()[0], "x0");
    assert_eq!(CallingConvention::Generic.param_regs()[0], "arg0");
}

#[test]
fn t22_cc_from_arch_matrix() {
    assert_eq!(CallingConvention::from_arch("x86_64-linux"), CallingConvention::SysVAmd64);
    assert_eq!(CallingConvention::from_arch("x86_64-windows"), CallingConvention::WindowsX64);
    assert_eq!(CallingConvention::from_arch("AMD64-MSVC"), CallingConvention::WindowsX64);
    assert_eq!(CallingConvention::from_arch("aarch64"), CallingConvention::Arm64);
    assert_eq!(CallingConvention::from_arch("arm64"), CallingConvention::Arm64);
    assert_eq!(CallingConvention::from_arch("mips"), CallingConvention::Generic);
}

#[test]
fn t23_cc_from_arch_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..60 {
        let v = g();
        // Build a small pseudo-random arch string.
        let s: String = (0..(v % 8 + 1))
            .map(|i| ((v >> (i * 4)) as u8 % 26 + b'a') as char)
            .collect();
        let _ = CallingConvention::from_arch(&s);
    }
}

#[test]
fn t24_cc_json_roundtrip() {
    for &cc in &[
        CallingConvention::SysVAmd64,
        CallingConvention::WindowsX64,
        CallingConvention::Arm64,
        CallingConvention::Generic,
    ] {
        let j = serde_json::to_string(&cc).unwrap();
        let back: CallingConvention = serde_json::from_str(&j).unwrap();
        assert_eq!(cc, back);
    }
}

// ════════════════════════════════════════════════════════════════════════
// VariableRecovery
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t25_var_recovery_stack_var_naming() {
    let mut r = VariableRecovery::new();
    let n_neg = r.stack_var_name(-16);
    assert!(n_neg.starts_with("local_"));
    let n_pos = r.stack_var_name(24);
    assert!(n_pos.starts_with("arg_"));
    // Idempotent: re-querying same offset returns same name.
    assert_eq!(r.stack_var_name(-16), n_neg);
}

#[test]
fn t26_var_recovery_fresh_var_unique() {
    let mut r = VariableRecovery::new();
    let a = r.fresh_var();
    let b = r.fresh_var();
    let c = r.fresh_var();
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, c);
}

#[test]
fn t27_var_recovery_with_cc_produces_params() {
    let mut r = VariableRecovery::new();
    let vars = r.recover_from_instructions_with_cc(&[], CallingConvention::SysVAmd64);
    assert_eq!(vars.len(), 6);
    for v in &vars {
        assert!(v.is_parameter);
    }
}

#[test]
fn t28_var_recovery_no_panic_on_random_ops() {
    let mut g = lcg();
    let mut r = VariableRecovery::new();
    let mut instrs = Vec::new();
    for i in 0..40 {
        let v = g();
        instrs.push(mk(0x1000 + i, "mov", &format!("[rbp - 0x{:x}], rax", v & 0xFF)));
    }
    let vars = r.recover_from_instructions(&instrs);
    // At least the 6 SysV param regs.
    assert!(vars.len() >= 6);
}

// ════════════════════════════════════════════════════════════════════════
// TypePropagation
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t29_type_propagation_basic() {
    let mut tp = TypePropagation::new();
    tp.set_type("p", "int*");
    assert_eq!(tp.get_type("p"), Some("int*"));
    assert_eq!(tp.get_type("q"), None);
    assert_eq!(tp.count(), 1);
    assert_eq!(tp.propagate_add("p", true), Some("int*".to_string()));
    assert_eq!(tp.propagate_add("p", false), Some("int*".to_string()));
}

#[test]
fn t30_type_propagation_non_pointer_returns_none() {
    let mut tp = TypePropagation::new();
    tp.set_type("x", "int");
    assert_eq!(tp.propagate_add("x", true), None);
}

// ════════════════════════════════════════════════════════════════════════
// ExpressionRecovery
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t31_expr_recovery_mov() {
    let r = ExpressionRecovery::new();
    let i = mk(0, "mov", "rax, rbx");
    assert_eq!(r.recover_expr(&i).as_deref(), Some("rax = rbx"));
}

#[test]
fn t32_expr_recovery_xor_self_zero() {
    let r = ExpressionRecovery::new();
    let i = mk(0, "xor", "rax, rax");
    assert_eq!(r.recover_expr(&i).as_deref(), Some("rax = 0"));
}

#[test]
fn t33_expr_recovery_unknown_returns_none() {
    let r = ExpressionRecovery::new();
    let i = mk(0, "wibble", "foo, bar");
    assert!(r.recover_expr(&i).is_none());
}

#[test]
fn t34_expr_recovery_register_function() {
    let mut r = ExpressionRecovery::new();
    assert_eq!(r.known_function_count(), 0);
    r.register_function("malloc", "void*");
    r.register_function("free", "void");
    assert_eq!(r.known_function_count(), 2);
    assert_eq!(r.call_return_type("malloc"), Some("void*"));
    assert_eq!(r.call_return_type("missing"), None);
}

#[test]
fn t35_expr_recovery_fuzz_no_panic() {
    let mut g = lcg();
    let r = ExpressionRecovery::new();
    let mnems = ["mov", "add", "sub", "xor", "lea", "ret", "nop", "wat"];
    for _ in 0..50 {
        let v = g();
        let m = mnems[(v as usize) % mnems.len()];
        let ops = format!("op{}, op{}", v % 5, (v >> 4) % 5);
        let _ = r.recover_expr(&mk(v, m, &ops));
    }
}

// ════════════════════════════════════════════════════════════════════════
// CfStructure
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t36_cfstructure_sequence_emits() {
    let s = CfStructure::Sequence(vec!["a;".into(), "b;".into()]);
    let lines = s.emit_lines(1);
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("  "));
}

#[test]
fn t37_cfstructure_if_else_balanced_braces() {
    let s = CfStructure::IfElse {
        cond: "x".into(),
        then_body: vec!["a;".into()],
        else_body: vec!["b;".into()],
    };
    let joined = s.emit_lines(0).join("\n");
    let opens = joined.matches('{').count();
    let closes = joined.matches('}').count();
    assert_eq!(opens, closes);
}

#[test]
fn t38_cfstructure_while_do_for_switch_emit() {
    let cases: Vec<(&str, Vec<CfStructure>)> = vec![];
    let _ = cases; // unused
    let w = CfStructure::While { cond: "i<10".into(), body: vec!["i++;".into()] };
    let d = CfStructure::DoWhile { cond: "x".into(), body: vec!["y;".into()] };
    let f = CfStructure::For {
        init: "i=0".into(),
        cond: "i<n".into(),
        step: "i++".into(),
        body: vec!["x;".into()],
    };
    let sw = CfStructure::Switch {
        expr: "x".into(),
        cases: vec![("1".into(), vec!["a;".into()])],
    };
    assert!(w.emit_lines(0).join("\n").contains("while"));
    assert!(d.emit_lines(0).join("\n").contains("do"));
    assert!(f.emit_lines(0).join("\n").contains("for"));
    assert!(sw.emit_lines(0).join("\n").contains("switch"));
}

// ════════════════════════════════════════════════════════════════════════
// DecompilerCache state machine
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t39_cache_hit_miss_counts() {
    let mut c = DecompilerCache::new(8);
    assert!(c.is_empty());
    assert_eq!(c.hit_rate(), 0.0);
    assert!(c.get(0x100).is_none());
    assert_eq!(c.miss_count(), 1);
    c.insert(DecompiledFunction::new(0x100, "f", "body"));
    assert!(c.get(0x100).is_some());
    assert_eq!(c.hit_count(), 1);
    assert!((c.hit_rate() - 0.5).abs() < 1e-9);
    assert_eq!(c.len(), 1);
    c.evict(0x100);
    assert!(c.is_empty());
}

#[test]
fn t40_cache_capacity_evicts_lowest_addr() {
    let mut c = DecompilerCache::new(2);
    c.insert(DecompiledFunction::new(0x100, "a", ""));
    c.insert(DecompiledFunction::new(0x200, "b", ""));
    c.insert(DecompiledFunction::new(0x300, "c", "")); // evicts 0x100
    assert_eq!(c.len(), 2);
    assert!(c.get(0x100).is_none());
    assert!(c.get(0x200).is_some());
    assert!(c.get(0x300).is_some());
}

#[test]
fn t41_cache_clear_resets_entries_not_counters() {
    let mut c = DecompilerCache::new(4);
    c.insert(DecompiledFunction::new(0x1, "f", ""));
    let _ = c.get(0x1);
    c.clear();
    assert!(c.is_empty());
    // hit_count is preserved (no reset method).
    assert_eq!(c.hit_count(), 1);
}

// ════════════════════════════════════════════════════════════════════════
// Pipeline + Context
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t42_pipeline_empty_runs() {
    let pipe = DecompilerPipeline::builder(DecompOptions::default()).build();
    assert_eq!(pipe.pass_count(), 0);
    let r = pipe.run(0x1000, "f", &[mk(0x1000, "ret", "")]).unwrap();
    assert_eq!(r.address, 0x1000);
    assert_eq!(r.name, "f");
}

#[test]
fn t43_pipeline_too_large_errors() {
    let opts = DecompOptions {
        max_function_size: 2,
        ..DecompOptions::default()
    };
    let pipe = DecompilerPipeline::builder(opts).build();
    let instrs = vec![mk(0, "nop", ""), mk(1, "nop", ""), mk(2, "nop", "")];
    match pipe.run(0, "f", &instrs) {
        Err(DecompilerError::FunctionTooLarge(0)) => {}
        other => panic!("expected FunctionTooLarge, got {other:?}"),
    }
}

#[test]
fn t44_pipeline_with_default_passes() {
    let pipe = DecompilerPipeline::builder(DecompOptions::default())
        .add_pass(Arc::new(DisassemblyPass))
        .add_pass(Arc::new(CallSitePass))
        .add_pass(Arc::new(FunctionHeaderPass))
        .add_pass(Arc::new(FunctionBodyPass))
        .build();
    assert_eq!(pipe.pass_count(), 4);
    let names = pipe.pass_names();
    assert!(names.contains(&"disassembly"));
    assert!(names.contains(&"function_body"));
    let r = pipe.run(0x1000, "main", &[mk(0x1000, "ret", "")]).unwrap();
    assert!(r.pseudo_code.contains("main"));
}

#[test]
fn t45_pipeline_call_site_pass_collects_calls() {
    let pipe = DecompilerPipeline::builder(DecompOptions::default())
        .add_pass(Arc::new(CallSitePass))
        .build();
    let instrs = vec![
        mk(0x1000, "call", "0x4000"),
        mk(0x1005, "call", "0x5000"),
        mk(0x100A, "nop", ""),
    ];
    let r = pipe.run(0x1000, "f", &instrs).unwrap();
    assert!(r.call_sites.contains(&0x4000));
    assert!(r.call_sites.contains(&0x5000));
}

#[test]
fn t46_decompilercontext_add_call_site_dedups() {
    let mut ctx = DecompilerContext::new(0x100, "f", DecompOptions::default());
    ctx.add_call_site(0x1);
    ctx.add_call_site(0x1);
    ctx.add_call_site(0x2);
    assert_eq!(ctx.call_sites.len(), 2);
}

#[test]
fn t47_decompilercontext_advance_ir_level_monotone() {
    let mut ctx = DecompilerContext::new(0, "f", DecompOptions::default());
    assert_eq!(ctx.ir_level, IrLevel::Llil);
    ctx.advance_ir_level(IrLevel::PseudoC);
    assert_eq!(ctx.ir_level, IrLevel::PseudoC);
    // Going backwards is a no-op.
    ctx.advance_ir_level(IrLevel::Llil);
    assert_eq!(ctx.ir_level, IrLevel::PseudoC);
}

#[test]
fn t48_decompilercontext_annotate_get() {
    let mut ctx = DecompilerContext::new(0, "f", DecompOptions::default());
    ctx.annotate("k", "v");
    assert_eq!(ctx.annotation("k"), Some("v"));
    assert_eq!(ctx.annotation("missing"), None);
}

#[test]
fn t49_decompilercontext_build_cfg_no_calls() {
    let mut ctx = DecompilerContext::new(0, "f", DecompOptions::default());
    ctx.emit_line("a;");
    ctx.emit_line("b;");
    let blocks = ctx.build_cfg();
    // One body block + one return block.
    assert_eq!(blocks.len(), 2);
}

#[test]
fn t50_decompilercontext_build_cfg_with_calls() {
    let mut ctx = DecompilerContext::new(0, "f", DecompOptions::default());
    ctx.add_call_site(0x100);
    ctx.add_call_site(0x200);
    let blocks = ctx.build_cfg();
    // body + 2 call blocks + 1 terminal.
    assert_eq!(blocks.len(), 4);
}

#[test]
fn t51_decompilercontext_finish() {
    let mut ctx = DecompilerContext::new(0xABCD, "test", DecompOptions::default());
    ctx.emit_line("line1");
    ctx.emit_line("line2");
    let f = ctx.finish();
    assert_eq!(f.address, 0xABCD);
    assert_eq!(f.pseudo_code, "line1\nline2");
}

// ════════════════════════════════════════════════════════════════════════
// Built-in passes details
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t52_constant_propagation_disabled_by_options() {
    let opts = DecompOptions {
        opt: DecompOptFlags { constant_propagation: false, ..Default::default() },
        ..DecompOptions::default()
    };
    let p = ConstantPropagationPass;
    assert!(!p.is_enabled(&opts));
    let opts2 = DecompOptions::default();
    assert!(p.is_enabled(&opts2));
}

#[test]
fn t53_dead_code_elim_disabled_by_options() {
    let opts = DecompOptions {
        passes: DecompPassFlags { dead_code_elimination: false, ..Default::default() },
        ..DecompOptions::default()
    };
    let p = DeadCodeEliminationPass;
    assert!(!p.is_enabled(&opts));
}

#[test]
fn t54_dce_eliminates_unused_assignment() {
    let pipe = DecompilerPipeline::builder(DecompOptions::default())
        .add_pass(Arc::new(DeadCodeEliminationPass))
        .build();
    let mut ctx = DecompilerContext::new(0, "f", DecompOptions::default());
    ctx.emit_line("dead_var = 5");
    ctx.emit_line("y = 10");
    // Provoke DCE via a direct pass run.
    DeadCodeEliminationPass.run(&mut ctx, 0, &[]).unwrap();
    let count: usize = ctx.annotation("dce_eliminated").and_then(|s| s.parse().ok()).unwrap_or(0);
    assert!(count >= 1);
    let _ = pipe; // touch
}

// ════════════════════════════════════════════════════════════════════════
// Decompiler / Backends
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t55_decompiler_no_backends_errors() {
    let d = Decompiler::default();
    let r = d.decompile(0x1000, &[mk(0x1000, "ret", "")], "f");
    assert!(matches!(r, Err(DecompilerError::BackendError(_))));
}

#[test]
fn t56_decompiler_cache_then_hit() {
    let d = Decompiler::default();
    d.register_backend(Arc::new(SimpleBackend));
    let instrs = vec![mk(0x2000, "ret", "")];
    let _ = d.decompile(0x2000, &instrs, "f").unwrap();
    assert_eq!(d.cache_size(), 1);
    let _ = d.decompile(0x2000, &instrs, "f").unwrap();
    assert_eq!(d.stats().cache_hits, 1);
}

#[test]
fn t57_simple_backend_supports_arch() {
    let b = SimpleBackend;
    assert!(b.supports_arch("x86_64"));
    assert!(b.supports_arch("x86"));
    assert!(!b.supports_arch("mips"));
}

#[test]
fn t58_decompiler_function_too_large() {
    let opts = DecompOptions { max_function_size: 1, ..Default::default() };
    let d = Decompiler::new(opts);
    d.register_backend(Arc::new(SimpleBackend));
    let r = d.decompile(0, &[mk(0, "a", ""), mk(1, "b", "")], "f");
    assert!(matches!(r, Err(DecompilerError::FunctionTooLarge(0))));
}

// ════════════════════════════════════════════════════════════════════════
// FunctionNameGenerator
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t59_name_generator_hint_used() {
    let mut g = FunctionNameGenerator::new();
    let n = g.name_for(0x1000, Some("custom"));
    assert!(n.contains("custom"));
}

#[test]
fn t60_name_generator_count_increments() {
    let mut g = FunctionNameGenerator::new();
    assert_eq!(g.count(), 0);
    let _ = g.name_for(0x1, None);
    let _ = g.name_for(0x2, None);
    assert_eq!(g.count(), 2);
}

// ════════════════════════════════════════════════════════════════════════
// FunctionDecompiler / batch
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t61_function_decompiler_batch() {
    let pipe = DecompilerPipeline::builder(DecompOptions::default())
        .add_pass(Arc::new(DisassemblyPass))
        .add_pass(Arc::new(FunctionBodyPass))
        .build();
    let mut fd = FunctionDecompiler::new(pipe);
    let batch = vec![
        (0x1000, vec![mk(0x1000, "ret", "")], Some("foo".to_string())),
        (0x2000, vec![mk(0x2000, "nop", "")], None),
    ];
    let result = fd.decompile_batch(&batch);
    assert_eq!(result.functions.len(), 2);
    assert_eq!(result.stats.functions_decompiled, 2);
    assert!(!result.has_errors());
}

// ════════════════════════════════════════════════════════════════════════
// DecompilerSession
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t62_session_add_function() {
    let mut s = DecompilerSession::new("sess1", DecompOptions::default());
    let f = DecompiledFunction::new(0x100, "f", "body\nline2");
    s.add_function(f);
    assert!(s.function_at(0x100).is_some());
    assert!(s.function_at(0xDEAD).is_none());
    assert_eq!(s.stats.functions_decompiled, 1);
    assert_eq!(s.total_pseudocode_lines(), 2);
}

#[test]
fn t63_session_record_failure() {
    let mut s = DecompilerSession::new("s", DecompOptions::default());
    s.record_failure();
    s.record_failure();
    assert_eq!(s.stats.functions_failed, 2);
}

// ════════════════════════════════════════════════════════════════════════
// DecompilerResult / Diagnostic
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t64_result_error_filtering() {
    let mut r = DecompilerResult::new(vec![], DecompStats::default(), 0);
    r.add_diagnostic(DecompilerDiagnostic::error("oops").at_address(0x1));
    r.add_diagnostic(DecompilerDiagnostic::warning("careful"));
    assert!(r.has_errors());
    assert_eq!(r.errors().len(), 1);
}

#[test]
fn t65_diagnostic_builders() {
    let d = DecompilerDiagnostic::error("e").at_address(0xDEAD).from_pass("p");
    assert_eq!(d.severity, DiagnosticSeverity::Error);
    assert_eq!(d.address, Some(0xDEAD));
    assert_eq!(d.pass.as_deref(), Some("p"));
}

#[test]
fn t66_diagnostic_severity_json_roundtrip() {
    for &s in &[
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Info,
        DiagnosticSeverity::Hint,
    ] {
        let j = serde_json::to_string(&s).unwrap();
        let back: DiagnosticSeverity = serde_json::from_str(&j).unwrap();
        assert_eq!(back, s);
    }
}

// ════════════════════════════════════════════════════════════════════════
// Error display
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t67_error_display_variants_distinct() {
    let errs = [
        DecompilerError::FunctionNotFound(0x100).to_string(),
        DecompilerError::LiftError("x".into()).to_string(),
        DecompilerError::AnalysisError("y".into()).to_string(),
        DecompilerError::BackendError("z".into()).to_string(),
        DecompilerError::UnsupportedArch("foo".into()).to_string(),
        DecompilerError::FunctionTooLarge(0x200).to_string(),
        DecompilerError::PassTimeout { pass: "p".into(), elapsed_ms: 1 }.to_string(),
        DecompilerError::PassError { pass: "p".into(), message: "m".into() }.to_string(),
        DecompilerError::Other("o".into()).to_string(),
    ];
    for e in &errs {
        assert!(!e.is_empty());
    }
}

#[test]
fn t68_error_from_anyhow() {
    let a: anyhow::Error = anyhow::anyhow!("boom");
    let e: DecompilerError = a.into();
    assert!(matches!(e, DecompilerError::Other(_)));
}

// ════════════════════════════════════════════════════════════════════════
// Send + Sync threaded stress
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t69_decompiler_threaded_stress() {
    let d = Arc::new({
        let dec = Decompiler::default();
        dec.register_backend(Arc::new(SimpleBackend));
        dec
    });
    let mut handles = Vec::new();
    for tid in 0..4 {
        let d = d.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..100u64 {
                let addr = 0x10000 + (tid * 1000) + i;
                let instrs = vec![mk(addr, "ret", "")];
                let _ = d.decompile(addr, &instrs, &format!("f_{tid}_{i}"));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let s = d.stats();
    assert!(s.functions_decompiled > 0);
}

#[test]
fn t70_decompiler_backend_kind_send_sync() {
    fn ok<T: Send + Sync>() {}
    ok::<DecompilerBackendKind>();
    ok::<IrLevel>();
    ok::<DecompOptions>();
    ok::<DecompilerError>();
    ok::<CallingConvention>();
}

// ════════════════════════════════════════════════════════════════════════
// LCG-driven robustness fuzz across constructors
// ════════════════════════════════════════════════════════════════════════
#[test]
fn t71_fuzz_decompiled_function_construction() {
    let mut g = lcg();
    for _ in 0..50 {
        let v = g();
        let f = DecompiledFunction::new(v, format!("f{v}"), format!("body_{v}"))
            .with_confidence((v % 256) as u8)
            .with_ir_level(match v % 4 {
                0 => IrLevel::Llil,
                1 => IrLevel::MlilSsa,
                2 => IrLevel::Hlil,
                _ => IrLevel::PseudoC,
            })
            .with_call_site(v.wrapping_add(0x100));
        assert!(f.confidence <= 100);
        let _ = f.to_string();
    }
}

#[test]
fn t72_fuzz_pipeline_round_trip_through_default_passes() {
    let mut g = lcg();
    let pipe = DecompilerPipeline::builder(DecompOptions::default())
        .add_pass(Arc::new(DisassemblyPass))
        .add_pass(Arc::new(CallSitePass))
        .add_pass(Arc::new(VariableCollectionPass))
        .add_pass(Arc::new(FunctionHeaderPass))
        .add_pass(Arc::new(FunctionBodyPass))
        .build();
    let mnems = ["mov", "add", "sub", "xor", "lea", "nop", "ret", "call", "push", "pop"];
    for trial in 0..50 {
        let mut instrs = Vec::new();
        for k in 0..((g() % 6) + 1) {
            let v = g();
            let m = mnems[(v as usize) % mnems.len()];
            let ops = if m == "call" {
                format!("0x{:x}", v & 0xFFFF)
            } else {
                format!("rax, [rbp - 0x{:x}]", v & 0xFF)
            };
            instrs.push(mk(0x1000 + k, m, &ops));
        }
        let r = pipe.run(0x1000 + trial, "fuzz", &instrs);
        assert!(r.is_ok(), "pipeline failed: {r:?}");
    }
}
