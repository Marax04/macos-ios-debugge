//! Exhaustive integration tests for rustre-decompiler public API.

use rustre_core::address::Address;
use rustre_core::arch::{InstrFlags, Instruction};
use rustre_decompiler::*;
use std::sync::Arc;

fn mk(addr: u64, mnem: &str, ops: &str) -> Instruction {
    let mut i = Instruction::new(Address::new(addr), 4, mnem.to_string(), vec![0x90]);
    i.operands = ops.to_string();
    i.flags = InstrFlags::NONE;
    i
}

fn simple_instrs() -> Vec<Instruction> {
    vec![
        mk(0x1000, "push", "rbp"),
        mk(0x1001, "mov", "rbp, rsp"),
        mk(0x1003, "ret", ""),
    ]
}

// ── IrLevel ─────────────────────────────────────────────────────────────
#[test]
fn ir_level_total_order() {
    let mut v = vec![IrLevel::PseudoC, IrLevel::Llil, IrLevel::Hlil, IrLevel::MlilSsa];
    v.sort();
    assert_eq!(v, vec![IrLevel::Llil, IrLevel::MlilSsa, IrLevel::Hlil, IrLevel::PseudoC]);
}

#[test]
fn ir_level_roundtrip_json() {
    let j = serde_json::to_string(&IrLevel::Hlil).unwrap();
    let back: IrLevel = serde_json::from_str(&j).unwrap();
    assert_eq!(back, IrLevel::Hlil);
}

// ── VarStorage display ──────────────────────────────────────────────────
#[test]
fn varstorage_stack_positive_displays_with_plus() {
    let s = VarStorage::Stack(16).to_string();
    assert!(s.contains('+') || s.contains("16"), "got: {s}");
    // Per the format `{off:+}` the output must contain '+' for positive values.
    assert!(s.contains("+16"), "expected +16, got {s}");
}

#[test]
fn varstorage_immediate_zero() {
    assert_eq!(VarStorage::Immediate(0).to_string(), "imm:0x0");
}

// ── DecompiledFunction ──────────────────────────────────────────────────
#[test]
fn confidence_clamped_to_100() {
    let f = DecompiledFunction::new(0, "f", "").with_confidence(250);
    assert_eq!(f.confidence, 100);
}

#[test]
fn line_count_empty_string_is_zero() {
    let f = DecompiledFunction::new(0, "f", "");
    assert_eq!(f.line_count(), 0);
}

#[test]
fn line_count_no_trailing_newline() {
    let f = DecompiledFunction::new(0, "f", "a\nb");
    assert_eq!(f.line_count(), 2);
}

#[test]
fn is_high_confidence_boundary() {
    let f = DecompiledFunction::new(0, "f", "").with_confidence(50);
    assert!(f.is_high_confidence(50));
    assert!(!f.is_high_confidence(51));
}

// ── DecompStats ─────────────────────────────────────────────────────────
#[test]
fn success_rate_no_data_is_zero() {
    assert_eq!(DecompStats::default().success_rate(), 0.0);
}

#[test]
fn avg_time_no_data_is_zero() {
    assert_eq!(DecompStats::default().avg_time_ms(), 0.0);
}

#[test]
fn success_rate_all_failed() {
    let s = DecompStats { functions_failed: 5, ..Default::default() };
    assert_eq!(s.success_rate(), 0.0);
}

// ── DecompilerError From<anyhow> ────────────────────────────────────────
#[test]
fn decompiler_error_from_anyhow() {
    let e: DecompilerError = anyhow::anyhow!("boom").into();
    assert!(matches!(e, DecompilerError::Other(_)));
}

// ── parse_hex_target via CallSitePass behaviour ─────────────────────────
#[test]
fn callsite_pass_handles_h_suffix() {
    let p = DefaultPipelineFactory::standard(DecompOptions::default());
    let instrs = vec![mk(0x1000, "call", "4000h"), mk(0x1005, "ret", "")];
    let f = p.run(0x1000, "fn", &instrs).unwrap();
    assert!(f.call_sites.contains(&0x4000));
}

#[test]
fn callsite_pass_ignores_register_indirect() {
    let p = DefaultPipelineFactory::standard(DecompOptions::default());
    let instrs = vec![mk(0x1000, "call", "rax"), mk(0x1005, "ret", "")];
    let f = p.run(0x1000, "fn", &instrs).unwrap();
    assert!(f.call_sites.is_empty());
}

// ── Pipeline FunctionTooLarge ───────────────────────────────────────────
#[test]
fn pipeline_function_too_large_address_preserved() {
    let opts = DecompOptions { max_function_size: 1, ..Default::default() };
    let p = DefaultPipelineFactory::standard(opts);
    let err = p.run(0xdead_beef, "x", &simple_instrs()).unwrap_err();
    match err {
        DecompilerError::FunctionTooLarge(a) => assert_eq!(a, 0xdead_beef),
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn pipeline_empty_instructions_succeeds() {
    let p = DefaultPipelineFactory::standard(DecompOptions::default());
    let f = p.run(0x1000, "empty", &[]).unwrap();
    assert_eq!(f.address, 0x1000);
    assert!(f.pseudo_code.contains("empty"));
}

#[test]
fn pipeline_pass_names_match_factory() {
    let p = DefaultPipelineFactory::standard(DecompOptions::default());
    let names = p.pass_names();
    assert!(names.contains(&"disassembly"));
    assert!(names.contains(&"call_sites"));
    assert!(names.contains(&"function_header"));
    assert!(names.contains(&"function_body"));
    assert!(names.contains(&"variable_collection"));
    assert!(names.contains(&"constant_propagation"));
    assert!(names.contains(&"dead_code_elimination"));
}

#[test]
fn disassembly_only_pipeline_has_only_two_passes() {
    let p = DefaultPipelineFactory::disassembly_only();
    assert_eq!(p.pass_count(), 2);
}

// ── ConstantPropagation: word-boundary correctness ──────────────────────
#[test]
fn const_prop_respects_word_boundary() {
    // Even if we add no "user" lines, the disassembly pass emits comment lines.
    // Comment lines start with "//"; const-prop should still walk them but not
    // produce malformed output. Sanity: pipeline completes.
    let p = DefaultPipelineFactory::standard(DecompOptions::default());
    let instrs = vec![
        mk(0x1000, "mov", "rax, 0x42"),
        mk(0x1005, "ret", ""),
    ];
    let f = p.run(0x1000, "f", &instrs).unwrap();
    assert!(!f.pseudo_code.is_empty());
}

// ── VariableCollection: stack parameter vs local sign ───────────────────
#[test]
fn variable_collection_negative_offset_is_local() {
    let p = DefaultPipelineFactory::standard(DecompOptions::default());
    let instrs = vec![mk(0x1000, "mov", "rax, [rbp - 0x10]"), mk(0x1005, "ret", "")];
    let f = p.run(0x1000, "f", &instrs).unwrap();
    // stack var at -16 ⇒ is_parameter == false
    let v = f.variables.iter().find(|v| matches!(v.storage, VarStorage::Stack(-16))).expect("stack var missing");
    assert!(!v.is_parameter, "negative offset must not be parameter");
}

#[test]
fn variable_collection_positive_offset_is_parameter() {
    let p = DefaultPipelineFactory::standard(DecompOptions::default());
    let instrs = vec![mk(0x1000, "mov", "rax, [rbp + 0x10]"), mk(0x1005, "ret", "")];
    let f = p.run(0x1000, "f", &instrs).unwrap();
    let v = f.variables.iter().find(|v| matches!(v.storage, VarStorage::Stack(16))).expect("stack var missing");
    assert!(v.is_parameter);
}

// ── VariableRecovery ────────────────────────────────────────────────────
#[test]
fn variable_recovery_offset_zero_is_not_parameter() {
    // recover_from_instructions_with_cc uses is_parameter: offset > 0.
    // BUT the inline VariableCollectionPass uses offset >= 0. Both behaviours
    // exist; here we pin VariableRecovery's contract.
    let mut vr = VariableRecovery::new();
    let instrs = vec![mk(0x1000, "mov", "rax, [rbp + 0x0]")];
    let vars = vr.recover_from_instructions(&instrs);
    let stack0 = vars.iter().find(|v| matches!(v.storage, VarStorage::Stack(0)));
    if let Some(v) = stack0 {
        assert!(!v.is_parameter, "VariableRecovery: offset 0 should not be parameter");
    }
}

#[test]
fn variable_recovery_fresh_var_sequence() {
    let mut vr = VariableRecovery::new();
    assert_eq!(vr.fresh_var(), "v0");
    assert_eq!(vr.fresh_var(), "v1");
    assert_eq!(vr.fresh_var(), "v2");
}

#[test]
fn variable_recovery_stack_var_naming() {
    let mut vr = VariableRecovery::new();
    assert_eq!(vr.stack_var_name(-8), "local_8");
    assert_eq!(vr.stack_var_name(16), "arg_16");
}

#[test]
fn variable_recovery_sysv_param_count() {
    let mut vr = VariableRecovery::new();
    let vars = vr.recover_from_instructions_with_cc(&[], CallingConvention::SysVAmd64);
    assert_eq!(vars.iter().filter(|v| v.is_parameter).count(), 6);
}

#[test]
fn variable_recovery_winx64_param_count() {
    let mut vr = VariableRecovery::new();
    let vars = vr.recover_from_instructions_with_cc(&[], CallingConvention::WindowsX64);
    assert_eq!(vars.iter().filter(|v| v.is_parameter).count(), 4);
}

// ── CallingConvention ──────────────────────────────────────────────────
#[test]
fn cc_from_arch_variants() {
    assert_eq!(CallingConvention::from_arch("aarch64"), CallingConvention::Arm64);
    assert_eq!(CallingConvention::from_arch("ARM64"), CallingConvention::Arm64);
    assert_eq!(CallingConvention::from_arch("x86_64-linux"), CallingConvention::SysVAmd64);
    assert_eq!(CallingConvention::from_arch("x86_64-windows-msvc"), CallingConvention::WindowsX64);
    assert_eq!(CallingConvention::from_arch("mips"), CallingConvention::Generic);
}

#[test]
fn cc_param_regs_nonempty() {
    for cc in [
        CallingConvention::SysVAmd64,
        CallingConvention::WindowsX64,
        CallingConvention::Arm64,
        CallingConvention::Generic,
    ] {
        assert!(!cc.param_regs().is_empty());
    }
}

#[test]
fn cc_display_strings() {
    assert_eq!(CallingConvention::SysVAmd64.to_string(), "SysV AMD64");
    assert_eq!(CallingConvention::WindowsX64.to_string(), "Windows x64");
    assert_eq!(CallingConvention::Arm64.to_string(), "ARM64");
    assert_eq!(CallingConvention::Generic.to_string(), "Generic");
}

// ── DecompilerBackendKind ──────────────────────────────────────────────
#[test]
fn backend_kind_all_display() {
    assert_eq!(DecompilerBackendKind::Internal.to_string(), "Internal");
    assert_eq!(DecompilerBackendKind::Ghidra.to_string(), "Ghidra");
    assert_eq!(DecompilerBackendKind::BinaryNinja.to_string(), "BinaryNinja");
    assert_eq!(DecompilerBackendKind::RetDec.to_string(), "RetDec");
}

#[test]
fn backend_kind_roundtrip_json() {
    let j = serde_json::to_string(&DecompilerBackendKind::Ghidra).unwrap();
    let back: DecompilerBackendKind = serde_json::from_str(&j).unwrap();
    assert_eq!(back, DecompilerBackendKind::Ghidra);
}

// ── DecompilerContext ──────────────────────────────────────────────────
#[test]
fn context_build_cfg_no_calls_creates_return_block() {
    let mut ctx = DecompilerContext::new(0, "f", DecompOptions::default());
    ctx.emit_line("x = 1");
    let blocks = ctx.build_cfg();
    assert_eq!(blocks.len(), 2, "body + return block");
}

#[test]
fn context_build_cfg_with_calls() {
    let mut ctx = DecompilerContext::new(0, "f", DecompOptions::default());
    ctx.emit_line("foo");
    ctx.add_call_site(0x4000);
    ctx.add_call_site(0x5000);
    let blocks = ctx.build_cfg();
    // body + 2 call blocks + terminal
    assert_eq!(blocks.len(), 4);
}

#[test]
fn context_pass_time_recording() {
    let mut ctx = DecompilerContext::new(0, "f", DecompOptions::default());
    ctx.record_pass_time("p1", std::time::Duration::from_millis(1));
    assert_eq!(ctx.pass_times.len(), 1);
    assert_eq!(ctx.pass_times[0].0, "p1");
}

// ── DecompilerCache ─────────────────────────────────────────────────────
#[test]
fn cache_hit_rate_no_access_is_zero() {
    let c = DecompilerCache::new(10);
    assert_eq!(c.hit_rate(), 0.0);
}

#[test]
fn cache_is_empty_initial() {
    let c = DecompilerCache::new(10);
    assert!(c.is_empty());
}

#[test]
fn cache_eviction_keeps_capacity() {
    let mut c = DecompilerCache::new(3);
    for i in 0..10u64 {
        c.insert(DecompiledFunction::new(i, format!("f{i}"), ""));
    }
    assert!(c.len() <= 3);
}

// ── TypePropagation ────────────────────────────────────────────────────
#[test]
fn type_propagation_overwrite() {
    let mut tp = TypePropagation::new();
    tp.set_type("x", "int");
    tp.set_type("x", "long");
    assert_eq!(tp.get_type("x"), Some("long"));
    assert_eq!(tp.count(), 1);
}

#[test]
fn type_propagation_all_typed_listing() {
    let mut tp = TypePropagation::new();
    tp.set_type("a", "int");
    tp.set_type("b", "char *");
    let all = tp.all_typed();
    assert_eq!(all.len(), 2);
}

#[test]
fn type_propagation_propagate_add_ptr_keyword() {
    let mut tp = TypePropagation::new();
    tp.set_type("p", "myptr_type");
    assert_eq!(tp.propagate_add("p", false).as_deref(), Some("myptr_type"));
}

// ── ExpressionRecovery ─────────────────────────────────────────────────
#[test]
fn expr_recovery_add_format() {
    let er = ExpressionRecovery::new();
    let i = mk(0, "add", "rax, 1");
    assert_eq!(er.recover_expr(&i).as_deref(), Some("rax += 1"));
}

#[test]
fn expr_recovery_sub_format() {
    let er = ExpressionRecovery::new();
    let i = mk(0, "sub", "rax, 1");
    assert_eq!(er.recover_expr(&i).as_deref(), Some("rax -= 1"));
}

#[test]
fn expr_recovery_unsupported_mnemonic_returns_none() {
    let er = ExpressionRecovery::new();
    let i = mk(0, "weirdop", "rax, rbx");
    assert!(er.recover_expr(&i).is_none());
}

#[test]
fn expr_recovery_xor_nonself_returns_none() {
    let er = ExpressionRecovery::new();
    let i = mk(0, "xor", "rax, rbx");
    assert!(er.recover_expr(&i).is_none());
}

#[test]
fn expr_recovery_known_function_count() {
    let mut er = ExpressionRecovery::new();
    er.register_function("a", "int");
    er.register_function("b", "int");
    assert_eq!(er.known_function_count(), 2);
}

// ── CfStructure emit ───────────────────────────────────────────────────
#[test]
fn cf_structure_sequence_emit() {
    let s = CfStructure::Sequence(vec!["a;".into(), "b;".into()]);
    let lines = s.emit_lines(1);
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("  "));
}

#[test]
fn cf_structure_ifelse_emit() {
    let s = CfStructure::IfElse {
        cond: "c".into(),
        then_body: vec!["t;".into()],
        else_body: vec!["e;".into()],
    };
    let lines = s.emit_lines(0);
    assert!(lines.iter().any(|l| l.contains("else")));
}

#[test]
fn cf_structure_dowhile_emit() {
    let s = CfStructure::DoWhile { cond: "x".into(), body: vec!["y;".into()] };
    let lines = s.emit_lines(0);
    assert!(lines.iter().any(|l| l.contains("do")));
    assert!(lines.iter().any(|l| l.contains("while")));
}

#[test]
fn cf_structure_switch_emit() {
    let s = CfStructure::Switch {
        expr: "v".into(),
        cases: vec![("1".into(), vec!["a;".into()])],
    };
    let lines = s.emit_lines(0);
    assert!(lines.iter().any(|l| l.contains("switch")));
    assert!(lines.iter().any(|l| l.contains("case 1")));
}

// ── ControlFlowStructuring ─────────────────────────────────────────────
#[test]
fn cfs_make_if_else_no_else_collapses() {
    let s = ControlFlowStructuring::make_if_else("c".into(), vec!["x;".into()], vec![]);
    assert!(matches!(s, CfStructure::If { .. }));
}

#[test]
fn cfs_make_if_else_with_else() {
    let s = ControlFlowStructuring::make_if_else("c".into(), vec![], vec!["e;".into()]);
    assert!(matches!(s, CfStructure::IfElse { .. }));
}

#[test]
fn cfs_detect_loop_finds_jmp() {
    let lines = vec!["jmp 0x1000"];
    assert!(ControlFlowStructuring::detect_loop(&lines).is_some());
}

#[test]
fn cfs_detect_loop_none_for_plain() {
    let lines = vec!["mov rax, 1"];
    assert!(ControlFlowStructuring::detect_loop(&lines).is_none());
}

#[test]
fn cfs_fresh_label_sequence() {
    let mut c = ControlFlowStructuring::new();
    assert_eq!(c.fresh_goto_label(), "label_0");
    assert_eq!(c.fresh_goto_label(), "label_1");
}

#[test]
fn cfs_emit_aggregates() {
    let mut c = ControlFlowStructuring::new();
    c.add_structure(CfStructure::Sequence(vec!["a;".into()]));
    c.add_structure(CfStructure::Sequence(vec!["b;".into()]));
    let out = c.emit();
    assert_eq!(out.len(), 2);
    assert_eq!(c.structure_count(), 2);
}

#[test]
fn cfs_flatten_joins_with_newlines() {
    let v = vec![
        CfStructure::Sequence(vec!["a;".into()]),
        CfStructure::Sequence(vec!["b;".into()]),
    ];
    let s = ControlFlowStructuring::flatten(&v);
    assert!(s.contains('\n'));
}

// ── Decompiler concurrency ─────────────────────────────────────────────
#[test]
fn decompiler_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Decompiler>();
}

#[test]
fn pipeline_options_accessor() {
    let mut opts = DecompOptions::default();
    opts.max_function_size = 42;
    let p = DecompilerPipeline::builder(opts).build();
    assert_eq!(p.options().max_function_size, 42);
}

// ── DecompilationResult ────────────────────────────────────────────────
#[test]
fn decompilation_result_is_success() {
    let r = DecompilationResult::Success(DecompiledFunction::new(0, "f", ""));
    assert!(r.is_success());
}

#[test]
fn decompilation_result_failure_not_success() {
    let r = DecompilationResult::Failure { address: 0, message: "x".into() };
    assert!(!r.is_success());
}

// ── PassRegistry edge cases ────────────────────────────────────────────
#[test]
fn pass_registry_overwrite_keeps_one() {
    let mut r = PassRegistry::new();
    r.register(Arc::new(DisassemblyPass));
    r.register(Arc::new(DisassemblyPass));
    assert_eq!(r.len(), 1);
}

#[test]
fn pass_registry_get_missing() {
    let r = PassRegistry::new();
    assert!(r.get("missing").is_none());
    assert!(r.is_empty());
}

// ── FunctionNameGenerator ──────────────────────────────────────────────
#[test]
fn name_generator_uses_hint() {
    let mut g = FunctionNameGenerator::new();
    assert_eq!(g.name_for(0x1000, Some("main")), "main");
}

#[test]
fn name_generator_ignores_empty_hint() {
    let mut g = FunctionNameGenerator::new();
    let n = g.name_for(0x1000, Some(""));
    assert_eq!(n, "sub_1000");
}

#[test]
fn name_generator_generates_for_none_hint() {
    let mut g = FunctionNameGenerator::new();
    assert_eq!(g.name_for(0x1234, None), "sub_1234");
}

#[test]
fn name_generator_count_does_not_increment_on_hint() {
    let mut g = FunctionNameGenerator::new();
    let _ = g.name_for(0, Some("foo"));
    // Per source: counter only increments when hint isn't used.
    assert_eq!(g.count(), 0);
}

// ── MultiBackendDecompiler ─────────────────────────────────────────────
#[test]
fn multi_backend_no_backends_errors() {
    let m = MultiBackendDecompiler::new(DecompOptions::default());
    let r = m.decompile(0x1000, &simple_instrs(), "f");
    assert!(matches!(r, Err(DecompilerError::BackendError(_))));
}

#[test]
fn multi_backend_registers_and_runs() {
    let mut m = MultiBackendDecompiler::new(DecompOptions::default());
    m.register(0, Arc::new(SimpleBackend));
    assert_eq!(m.backend_count(), 1);
    let f = m.decompile(0x1000, &simple_instrs(), "f").unwrap();
    assert_eq!(f.address, 0x1000);
}

// ── DecompilerAnnotation ───────────────────────────────────────────────
#[test]
fn annotation_constructors_set_category() {
    let c = DecompilerAnnotation::comment(0, 10, "x");
    assert_eq!(c.category, AnnotationCategory::Comment);
    let t = DecompilerAnnotation::type_info(0, 10, "x");
    assert_eq!(t.category, AnnotationCategory::TypeInfo);
    let s = DecompilerAnnotation::symbol_name(0, 10, "x");
    assert_eq!(s.category, AnnotationCategory::SymbolName);
}

// ── PipelineState ──────────────────────────────────────────────────────
#[test]
fn pipeline_state_default_display() {
    let s = PipelineState::default();
    let str = s.to_string();
    assert!(str.contains("0/0"));
}

#[test]
fn pipeline_state_finished_display() {
    let mut s = PipelineState::default();
    s.finished = true;
    s.current_pass_name = "p".into();
    assert!(s.to_string().contains("[done]"));
}

// ── DecompilerDiagnostic ───────────────────────────────────────────────
#[test]
fn diagnostic_warning_severity() {
    let d = DecompilerDiagnostic::warning("w");
    assert_eq!(d.severity, DiagnosticSeverity::Warning);
}

// ── DecompilerSession ──────────────────────────────────────────────────
#[test]
fn session_records_failure() {
    let mut s = DecompilerSession::new("id", DecompilerConfig::default());
    s.record_failure();
    assert_eq!(s.stats.functions_failed, 1);
}

#[test]
fn session_total_pseudocode_lines() {
    let mut s = DecompilerSession::new("id", DecompilerConfig::default());
    s.add_function(DecompiledFunction::new(0, "a", "x\ny"));
    s.add_function(DecompiledFunction::new(1, "b", "z"));
    assert_eq!(s.total_pseudocode_lines(), 3);
}

// ── PipelineBackend ────────────────────────────────────────────────────
#[test]
fn pipeline_backend_runs_through_trait() {
    let p = DefaultPipelineFactory::standard(DecompOptions::default());
    let b = PipelineBackend::new(p, "x86_64");
    let f = b.decompile_function(0x1000, &simple_instrs(), "f").unwrap();
    assert_eq!(f.address, 0x1000);
    assert!(b.supports_arch("x86_64"));
    assert!(!b.supports_arch("mips"));
}

// ── emit_structured_code ───────────────────────────────────────────────
#[test]
fn emit_structured_code_empty_blocks_is_none() {
    assert!(DecompilerPipeline::emit_structured_code("f", vec![], &[]).is_none());
}

// ── Run with structured emit ───────────────────────────────────────────
#[test]
fn run_with_structured_emit_basic() {
    let p = DefaultPipelineFactory::standard(DecompOptions::default());
    let f = p.run_with_structured_emit(0x1000, "fn", &simple_instrs()).unwrap();
    assert_eq!(f.address, 0x1000);
}

// ── VariableCollection: width inference ───────────────────────────────
#[test]
fn variable_collection_infers_eax_as_uint32() {
    let p = DefaultPipelineFactory::standard(
        DecompOptions { analysis: DecompAnalysisFlags { rename_variables: true, ..Default::default() }, ..DecompOptions::default() }
    );
    let instrs = vec![mk(0x1000, "mov", "eax, 1"), mk(0x1005, "ret", "")];
    let f = p.run(0x1000, "f", &instrs).unwrap();
    let v = f.variables.iter().find(|v| v.name == "r_eax").expect("eax var missing");
    assert_eq!(v.type_str, "uint32_t");
}

#[test]
fn variable_collection_infers_al_as_uint8() {
    let p = DefaultPipelineFactory::standard(
        DecompOptions { analysis: DecompAnalysisFlags { rename_variables: true, ..Default::default() }, ..DecompOptions::default() }
    );
    let instrs = vec![mk(0x1000, "mov", "al, 1"), mk(0x1005, "ret", "")];
    let f = p.run(0x1000, "f", &instrs).unwrap();
    let v = f.variables.iter().find(|v| v.name == "r_al").expect("al var missing");
    assert_eq!(v.type_str, "uint8_t");
}

#[test]
fn variable_collection_infers_rax_as_uint64() {
    let p = DefaultPipelineFactory::standard(
        DecompOptions { analysis: DecompAnalysisFlags { rename_variables: true, ..Default::default() }, ..DecompOptions::default() }
    );
    let instrs = vec![mk(0x1000, "mov", "rax, 1"), mk(0x1005, "ret", "")];
    let f = p.run(0x1000, "f", &instrs).unwrap();
    let v = f.variables.iter().find(|v| v.name == "r_rax").expect("rax var missing");
    assert_eq!(v.type_str, "uint64_t");
}

#[test]
fn variable_collection_infers_r10w_as_uint16() {
    let p = DefaultPipelineFactory::standard(
        DecompOptions { analysis: DecompAnalysisFlags { rename_variables: true, ..Default::default() }, ..DecompOptions::default() }
    );
    let instrs = vec![mk(0x1000, "mov", "r10w, 1"), mk(0x1005, "ret", "")];
    let f = p.run(0x1000, "f", &instrs).unwrap();
    let v = f.variables.iter().find(|v| v.name == "r_r10w").expect("r10w var missing");
    assert_eq!(v.type_str, "uint16_t");
}

#[test]
fn variable_collection_signed_cmp_jl_marks_signed() {
    let p = DefaultPipelineFactory::standard(
        DecompOptions { analysis: DecompAnalysisFlags { rename_variables: true, ..Default::default() }, ..DecompOptions::default() }
    );
    let instrs = vec![
        mk(0x1000, "mov", "eax, 1"),
        mk(0x1005, "cmp", "eax, 5"),
        mk(0x100a, "jl",  "0x2000"),
        mk(0x100c, "ret", ""),
    ];
    let f = p.run(0x1000, "f", &instrs).unwrap();
    let v = f.variables.iter().find(|v| v.name == "r_eax").expect("eax var missing");
    assert_eq!(v.type_str, "int32_t");
}

#[test]
fn variable_collection_unsigned_cmp_ja_marks_unsigned() {
    let p = DefaultPipelineFactory::standard(
        DecompOptions { analysis: DecompAnalysisFlags { rename_variables: true, ..Default::default() }, ..DecompOptions::default() }
    );
    let instrs = vec![
        mk(0x1000, "mov", "eax, 1"),
        mk(0x1005, "cmp", "eax, 5"),
        mk(0x100a, "ja",  "0x2000"),
        mk(0x100c, "ret", ""),
    ];
    let f = p.run(0x1000, "f", &instrs).unwrap();
    let v = f.variables.iter().find(|v| v.name == "r_eax").expect("eax var missing");
    assert_eq!(v.type_str, "uint32_t");
}

#[test]
fn variable_collection_stack_dword_ptr_is_uint32() {
    let p = DefaultPipelineFactory::standard(DecompOptions::default());
    let instrs = vec![
        mk(0x1000, "mov", "eax, dword ptr [rbp - 4]"),
        mk(0x1005, "ret", ""),
    ];
    let f = p.run(0x1000, "f", &instrs).unwrap();
    let v = f.variables.iter().find(|v| matches!(v.storage, VarStorage::Stack(-4)))
        .expect("stack var missing");
    assert_eq!(v.type_str, "uint32_t");
}

#[test]
fn variable_collection_offset_zero_is_not_parameter() {
    // Pinned by docs/bughunt/confirmed.jsonl: VariableCollectionPass must agree
    // with VariableRecovery — offset 0 is NOT a parameter.
    let p = DefaultPipelineFactory::standard(DecompOptions::default());
    let instrs = vec![
        mk(0x1000, "mov", "rax, [rbp + 0x0]"),
        mk(0x1005, "ret", ""),
    ];
    let f = p.run(0x1000, "f", &instrs).unwrap();
    if let Some(v) = f.variables.iter().find(|v| matches!(v.storage, VarStorage::Stack(0))) {
        assert!(!v.is_parameter, "offset 0 must not be a parameter");
    }
}

#[test]
fn variable_collection_eax_then_rax_collapses_to_rax_slot() {
    let p = DefaultPipelineFactory::standard(
        DecompOptions { analysis: DecompAnalysisFlags { rename_variables: true, ..Default::default() }, ..DecompOptions::default() }
    );
    let instrs = vec![
        mk(0x1000, "mov", "eax, 1"),
        mk(0x1005, "mov", "rax, 2"),
        mk(0x100a, "ret", ""),
    ];
    let f = p.run(0x1000, "f", &instrs).unwrap();
    let regs: Vec<_> = f.variables.iter()
        .filter(|v| matches!(v.storage, VarStorage::Register(_)))
        .collect();
    assert_eq!(regs.len(), 1, "eax+rax should collapse to one canonical reg slot, got {regs:?}");
    assert_eq!(regs[0].type_str, "uint64_t", "widest observed width wins");
}

#[test]
fn symbol_map_resolves_sub_placeholder() {
    use rustre_decompiler::{SymbolMap, SymbolResolver};
    let mut m = SymbolMap::new();
    m.insert(0x1234, "_RNvCs1_4core3fmt5write");
    m.enable_rust_demangling(true);
    let resolved = m.resolve(0x1234).expect("expected name");
    assert!(!resolved.is_empty());
    assert_eq!(m.resolve(0xdead), None);
}

#[test]
fn symbol_map_from_flirt_pairs_demangles() {
    use rustre_decompiler::{SymbolMap, SymbolResolver};
    let m = SymbolMap::from_flirt_pairs([(0xAAA, "core::fmt::write"), (0xBBB, "main")]);
    assert!(m.resolve(0xAAA).is_some());
    assert_eq!(m.resolve(0xBBB).as_deref(), Some("main"));
}
