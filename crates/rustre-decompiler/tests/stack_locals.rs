//! Integration tests for Gap E: stack-frame variable recovery.

use rustre_decompiler::pass_pipeline::{
    DecompilerPass as PassTrait, PassContext, VariableRecoveryPass,
};
use rustre_decompiler::stack_locals::{AddressedInsn, build_report, mask_epilogue, mask_prologue};
use rustre_decompiler::variable_recovery_engine::{
    CallingConvention, InsnSummary, VariableRecoveryEngine,
};

fn ins(addr: u64, m: &str, ops: &str) -> AddressedInsn {
    AddressedInsn { addr, mnemonic: m.into(), operands: ops.into() }
}

#[test]
fn var_n_naming_is_monotonic() {
    let mut eng = VariableRecoveryEngine::new(CallingConvention::SysVAmd64);
    eng.record_stack_access(-8, 8, 0x10, true);
    eng.record_stack_access(-16, 4, 0x14, true);
    eng.record_stack_access(-32, 8, 0x18, true);

    let prog = vec![ins(0x10, "ret", "")];
    let rep = build_report(&eng, &prog);
    assert_eq!(rep.locals.len(), 3);
    assert_eq!(rep.locals[0].name, "var_0");
    assert_eq!(rep.locals[1].name, "var_1");
    assert_eq!(rep.locals[2].name, "var_2");
    // Most-negative offset gets var_0.
    assert_eq!(rep.locals[0].offset, -32);
    assert_eq!(rep.locals[2].offset, -8);
}

#[test]
fn multi_width_access_widens_slot_and_struct() {
    let mut eng = VariableRecoveryEngine::new(CallingConvention::Generic);
    eng.record_stack_access(-16, 1, 0x10, true);
    eng.record_stack_access(-16, 4, 0x14, false);
    eng.record_stack_access(-16, 8, 0x18, false);

    let prog = vec![ins(0x10, "ret", "")];
    let rep = build_report(&eng, &prog);
    assert_eq!(rep.locals.len(), 1);
    assert_eq!(rep.locals[0].max_width, 8);
    assert_eq!(rep.locals[0].observed_widths, vec![1, 4, 8]);
    assert_eq!(rep.struct_candidates.len(), 1);
    let cand = &rep.struct_candidates[0];
    assert_eq!(cand.base_offset, -16);
    // Three distinct widths -> three field entries at sub=0.
    assert_eq!(cand.fields.len(), 3);
}

#[test]
fn prologue_epilogue_masked() {
    let prog = vec![
        ins(0x4000, "push", "rbp"),
        ins(0x4001, "mov", "rbp, rsp"),
        ins(0x4004, "sub", "rsp, 0x20"),
        ins(0x4008, "mov", "[rbp-8], rdi"),
        ins(0x400c, "add", "rsp, 0x20"),
        ins(0x4010, "pop", "rbp"),
        ins(0x4011, "ret", ""),
    ];
    let pro = mask_prologue(&prog);
    let epi = mask_epilogue(&prog);
    assert_eq!(pro.start, 0x4000);
    assert_eq!(pro.end, 0x4005);
    assert_eq!(epi.start, 0x400c);
    assert_eq!(epi.end, 0x4012);
}

#[test]
fn variable_recovery_pass_rewrites_stack_operands() {
    let mut ctx = PassContext::new(0x4000, "test_fn");
    ctx.calling_convention = Some("SysV_AMD64".to_string());
    ctx.raw_mnemonics = vec![
        (0x4000, "push".into(), "rbp".into()),
        (0x4001, "mov".into(), "rbp, rsp".into()),
        (0x4004, "sub".into(), "rsp, 0x20".into()),
        (0x4008, "mov".into(), "[rbp-8], rdi".into()),
        (0x400c, "ret".into(), "".into()),
    ];
    ctx.raw_insns = vec![
        InsnSummary {
            addr: 0x4008,
            mnemonic: "mov".into(),
            dst_reg: None,
            src_regs: vec!["rdi".into()],
            stack_offset: Some(-8),
            access_size: 8,
            is_def: true,
            global_addr: None,
        },
    ];
    ctx.emit("// 0x4000: push rbp");
    ctx.emit("// 0x4001: mov rbp, rsp");
    ctx.emit("// 0x4004: sub rsp, 0x20");
    ctx.emit("mov [rbp-8], rdi");
    ctx.emit("// 0x400c: ret");

    let pass = VariableRecoveryPass;
    let findings = pass.run(&mut ctx);
    assert!(findings.iter().any(|f| f.contains("var_0")));
    // Operand rewritten.
    let joined = ctx.lines.join("\n");
    assert!(joined.contains("mov var_0, rdi"), "expected rewritten line, got:\n{joined}");
    // Prologue lines suppressed.
    assert!(!joined.contains("push rbp"));
    assert!(!joined.contains("sub rsp"));
    // Annotations populated.
    assert_eq!(ctx.get("recovered_locals"), Some("1"));
    assert_eq!(ctx.get("frame_size"), Some("32"));
    assert!(ctx.prologue_range.is_some());
}
