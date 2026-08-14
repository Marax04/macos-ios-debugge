//! Integration tests for `rustre-il-lift`.
//!
//! These tests exercise the full x86 lifting pipeline end-to-end:
//!
//!   1. Raw bytes → `iced-x86` decode
//!   2. `X86LifterV2::lift_bytes` → `Vec<LiftedInstr>`
//!   3. `x86_eval::exec_effects` → `X86CpuState`
//!   4. State assertions
//!
//! They also exercise the analysis, optimizer, pseudo, type recovery and
//! pretty-printing modules on the resulting IR.
//!
//! The byte sequences used here are well-known x86-64 encodings and
//! intentionally minimal — each test targets one specific behaviour.

use rustre_il_lift::x86_analysis::{
    StreamStats, build_def_use_map, collect_mem_accesses, extract_call_sites,
};
use rustre_il_lift::x86_eval::{EvalValue, X86CpuState, exec_effects};
use rustre_il_lift::x86_insn_db::InsnDb;
use rustre_il_lift::x86_lifter_v2::X86LifterV2;
use rustre_il_lift::x86_optimizer::optimise_effects;
use rustre_il_lift::x86_pattern_match::{EffectPat, ExprPat, scan_sequence};
use rustre_il_lift::x86_pretty_print::{PrintOptions, render_block};
use rustre_il_lift::x86_pseudo::scan_pseudos;
use rustre_il_lift::x86_type_recovery::recover_types;
use rustre_il_lift::{ArchLifter, Effect, IrExpr, LiftLevel};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn lifter64() -> X86LifterV2 {
    X86LifterV2::new_64()
}

/// Lift bytes and return only the successfully lifted instructions.
fn lift(bytes: &[u8]) -> Vec<rustre_il_lift::LiftedInstr> {
    let (instrs, _errors) = lifter64().lift_bytes(bytes, 0x1000);
    instrs
}

/// Lift bytes, run all effects through the evaluator, return final state.
fn lift_eval(bytes: &[u8], init: &[(&str, u64)]) -> X86CpuState {
    let instrs = lift(bytes);
    let mut state = X86CpuState::with_gp_regs(init);
    for li in &instrs {
        exec_effects(&li.effects, &mut state);
    }
    state
}

// ─────────────────────────────────────────────────────────────────────────────
// Single-instruction smoke tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn nop_does_nothing() {
    let s = lift_eval(&[0x90], &[("rax", 42)]);
    s.assert_reg("rax", 42);
}

#[test]
fn nop_produces_one_instr() {
    let instrs = lift(&[0x90]);
    assert_eq!(instrs.len(), 1);
    assert_eq!(instrs[0].il_level, LiftLevel::Llil);
}

#[test]
fn ret_produces_return_effect() {
    let instrs = lift(&[0xc3]);
    let has_ret = instrs[0]
        .effects
        .iter()
        .any(|e| matches!(e, Effect::Return { .. }));
    assert!(has_ret, "RET should produce Return effect");
}

// MOV rax, rbx  (48 89 D8)
#[test]
fn mov_rax_rbx() {
    let s = lift_eval(&[0x48, 0x89, 0xd8], &[("rbx", 0xdeadbeef)]);
    assert_eq!(s.get_reg("rax"), EvalValue::Concrete(0xdeadbeef));
}

// MOV rax, 0x42  (48 C7 C0 42 00 00 00)
#[test]
fn mov_rax_imm32() {
    let s = lift_eval(&[0x48, 0xc7, 0xc0, 0x42, 0x00, 0x00, 0x00], &[]);
    s.assert_reg("rax", 0x42);
}

// ADD rax, 10  (48 83 C0 0A)
#[test]
fn add_rax_10_from_5() {
    let s = lift_eval(&[0x48, 0x83, 0xc0, 0x0a], &[("rax", 5)]);
    s.assert_reg("rax", 15);
}

// SUB rax, 3  (48 83 E8 03)
#[test]
fn sub_rax_3() {
    let s = lift_eval(&[0x48, 0x83, 0xe8, 0x03], &[("rax", 10)]);
    s.assert_reg("rax", 7);
}

// INC rax  (48 FF C0)
#[test]
fn inc_rax() {
    let s = lift_eval(&[0x48, 0xff, 0xc0], &[("rax", 41)]);
    s.assert_reg("rax", 42);
}

// DEC rax  (48 FF C8)
#[test]
fn dec_rax() {
    let s = lift_eval(&[0x48, 0xff, 0xc8], &[("rax", 43)]);
    s.assert_reg("rax", 42);
}

// NOT rax  (48 F7 D0)
#[test]
fn not_rax_all_zeros() {
    let s = lift_eval(&[0x48, 0xf7, 0xd0], &[("rax", 0)]);
    s.assert_reg("rax", u64::MAX);
}

// AND rax, 0x0f  (48 83 E0 0F)
#[test]
fn and_rax_mask() {
    let s = lift_eval(&[0x48, 0x83, 0xe0, 0x0f], &[("rax", 0xff)]);
    s.assert_reg("rax", 0x0f);
}

// OR rax, 0xf0  (48 83 C8 F0)
// The imm8 0xf0 is sign-extended to the 64-bit operand (0xFFFF_FFFF_FFFF_FFF0),
// so OR-ing it with 0x0f yields all ones — this is correct x86 semantics.
#[test]
fn or_rax_mask() {
    let s = lift_eval(&[0x48, 0x83, 0xc8, 0xf0u8], &[("rax", 0x0f)]);
    s.assert_reg("rax", 0xffff_ffff_ffff_ffff);
}

// XOR eax, eax  (31 C0)
#[test]
fn xor_eax_eax_zeroes() {
    let s = lift_eval(&[0x31, 0xc0], &[("eax", 0x12345678)]);
    let v = s.get_reg("eax");
    assert!(v == EvalValue::Concrete(0) || v.is_unknown());
}

// SHL rax, 3  (48 C1 E0 03)
#[test]
fn shl_rax_by_3() {
    let s = lift_eval(&[0x48, 0xc1, 0xe0, 0x03], &[("rax", 1)]);
    s.assert_reg("rax", 8);
}

// SHR rax, 2  (48 C1 E8 02)
#[test]
fn shr_rax_by_2() {
    let s = lift_eval(&[0x48, 0xc1, 0xe8, 0x02], &[("rax", 16)]);
    s.assert_reg("rax", 4);
}

// PUSH rbp  (55)
#[test]
fn push_rbp_decrements_rsp() {
    let instrs = lift(&[0x55]);
    let dec_sp = instrs[0].effects.iter().any(|e| {
        matches!(e, Effect::RegWrite { reg, value: IrExpr::Sub(_, b) }
                 if reg == "rsp" && matches!(**b, IrExpr::Const(8)))
    });
    assert!(dec_sp, "PUSH should decrement RSP by 8");
}

// CALL rel32  (E8 00 00 00 00)
#[test]
fn call_emits_call_effect() {
    let instrs = lift(&[0xe8, 0x00, 0x00, 0x00, 0x00]);
    let has_call = instrs[0]
        .effects
        .iter()
        .any(|e| matches!(e, Effect::Call { .. }));
    assert!(has_call);
}

// JE rel8  (74 10) — conditional branch on ZF=1
#[test]
fn je_branches_when_zf_one() {
    let instrs = lift(&[0x74, 0x10]);
    let mut s = X86CpuState::with_gp_regs(&[("zf", 1)]);
    let results = exec_effects(&instrs[0].effects, &mut s);
    let branched = results.iter().any(|r| {
        matches!(
            r,
            rustre_il_lift::x86_eval::ExecResult::Branch {
                target: Some(_),
                ..
            }
        )
    });
    assert!(branched, "JE should branch when ZF=1");
}

// JNE rel8  (75 10) — falls through when ZF=1
#[test]
fn jne_does_not_branch_when_zf_one() {
    let instrs = lift(&[0x75, 0x10]);
    let mut s = X86CpuState::with_gp_regs(&[("zf", 1)]);
    let results = exec_effects(&instrs[0].effects, &mut s);
    let branched = results.iter().any(|r| {
        matches!(
            r,
            rustre_il_lift::x86_eval::ExecResult::Branch {
                target: Some(_),
                ..
            }
        )
    });
    assert!(!branched, "JNE should not branch when ZF=1");
}

// SYSCALL  (0F 05)
#[test]
fn syscall_emits_syscall_effect() {
    let instrs = lift(&[0x0f, 0x05]);
    let has_sc = instrs[0]
        .effects
        .iter()
        .any(|e| matches!(e, Effect::Syscall { .. }));
    assert!(has_sc, "SYSCALL should emit Syscall effect");
}

// CPUID  (0F A2)
#[test]
fn cpuid_emits_intrinsic() {
    let instrs = lift(&[0x0f, 0xa2]);
    let has_intr = instrs[0]
        .effects
        .iter()
        .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name.contains("cpuid")));
    assert!(has_intr, "CPUID should emit x86.cpuid intrinsic");
}

// UD2  (0F 0B)
#[test]
fn ud2_emits_ud_trap() {
    let instrs = lift(&[0x0f, 0x0b]);
    let has_ud = instrs[0]
        .effects
        .iter()
        .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name.contains("ud")));
    assert!(has_ud, "UD2 should emit x86.ud_trap intrinsic");
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-instruction sequences
// ─────────────────────────────────────────────────────────────────────────────

// Function prologue: PUSH rbp  (55) + MOV rbp, rsp  (48 89 E5)
#[test]
fn prologue_two_instrs() {
    let bytes = [0x55u8, 0x48, 0x89, 0xe5];
    let instrs = lift(&bytes);
    assert_eq!(instrs.len(), 2);
}

// ADD then SUB cancel each other.
#[test]
fn add_then_sub_cancel() {
    let bytes = [
        0x48, 0x83, 0xc0, 0x0a, // ADD rax, 10
        0x48, 0x83, 0xe8, 0x0a, // SUB rax, 10
    ];
    let s = lift_eval(&bytes, &[("rax", 100)]);
    s.assert_reg("rax", 100);
}

// Three NOPs then RET.
#[test]
fn three_nops_then_ret() {
    let bytes = [0x90, 0x90, 0x90, 0xc3];
    let instrs = lift(&bytes);
    assert_eq!(instrs.len(), 4);
    assert!(
        instrs
            .last()
            .unwrap()
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Return { .. }))
    );
}

// INC then DEC cancel.
#[test]
fn inc_then_dec_cancel() {
    let bytes = [
        0x48, 0xff, 0xc0, // INC rax
        0x48, 0xff, 0xc8, // DEC rax
    ];
    let s = lift_eval(&bytes, &[("rax", 42)]);
    s.assert_reg("rax", 42);
}

// XOR eax, eax sets ZF=1.
#[test]
fn xor_self_sets_zf() {
    let bytes = [0x31, 0xc0]; // XOR eax, eax
    let s = lift_eval(&bytes, &[("eax", 0xffff)]);
    s.assert_reg("zf", 1);
}

// CMP rax, 5 sets ZF when rax==5.
#[test]
fn cmp_sets_zf_when_equal() {
    let bytes = [0x48, 0x83, 0xf8, 0x05]; // CMP rax, 5
    let s = lift_eval(&bytes, &[("rax", 5)]);
    s.assert_reg("zf", 1);
}

// CMP does not write destination.
#[test]
fn cmp_does_not_write_rax() {
    let bytes = [0x48, 0x83, 0xf8, 0x05];
    let instrs = lift(&bytes);
    let writes_rax = instrs[0]
        .effects
        .iter()
        .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rax"));
    assert!(!writes_rax, "CMP must not modify rax");
}

// ─────────────────────────────────────────────────────────────────────────────
// Flag semantics
// ─────────────────────────────────────────────────────────────────────────────

// AND clears CF and OF.
#[test]
fn and_clears_cf_and_of() {
    let bytes = [0x48, 0x83, 0xe0, 0x01]; // AND rax, 1
    let instrs = lift(&bytes);
    let cf_zero = instrs[0]
        .effects
        .iter()
        .any(|e| matches!(e, Effect::RegWrite { reg, value: IrExpr::Const(0) } if reg == "cf"));
    let of_zero = instrs[0]
        .effects
        .iter()
        .any(|e| matches!(e, Effect::RegWrite { reg, value: IrExpr::Const(0) } if reg == "of"));
    assert!(cf_zero, "AND must clear CF");
    assert!(of_zero, "AND must clear OF");
}

// ADD always emits six flag effects.
#[test]
fn add_emits_six_flags() {
    let bytes = [0x48, 0x83, 0xc0, 0x01]; // ADD rax, 1
    let instrs = lift(&bytes);
    let flag_regs: Vec<&str> = instrs[0]
        .effects
        .iter()
        .filter_map(|e| {
            if let Effect::RegWrite { reg, .. } = e {
                if ["cf", "pf", "af", "zf", "sf", "of"].contains(&reg.as_str()) {
                    Some(reg.as_str())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();
    for f in ["cf", "pf", "af", "zf", "sf", "of"] {
        assert!(flag_regs.contains(&f), "ADD must emit flag: {f}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Analysis pipeline
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stream_stats_counts_correctly() {
    let bytes = [0x90u8, 0x90, 0xc3]; // NOP NOP RET
    let instrs = lift(&bytes);
    let stats = StreamStats::from_instrs(&instrs);
    assert_eq!(stats.total_instructions, 3);
}

#[test]
fn def_use_map_built() {
    let bytes = [0x48, 0x89, 0xd8]; // MOV rax, rbx
    let instrs = lift(&bytes);
    let du = build_def_use_map(&instrs);
    assert!(
        du.contains_key("rax"),
        "rax should be in def-use map (written)"
    );
}

#[test]
fn call_site_extracted() {
    let bytes = [0xe8, 0x00, 0x00, 0x00, 0x00]; // CALL +0
    let instrs = lift(&bytes);
    let calls = extract_call_sites(&instrs);
    assert!(
        !calls.is_empty(),
        "CALL instruction should produce a call site"
    );
}

#[test]
fn mem_access_detected_in_push() {
    let bytes = [0x55]; // PUSH rbp
    let instrs = lift(&bytes);
    let accesses = collect_mem_accesses(&instrs);
    assert!(!accesses.is_empty(), "PUSH should produce a memory access");
    assert!(accesses[0].is_write, "PUSH is a write");
}

// ─────────────────────────────────────────────────────────────────────────────
// Optimiser
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn optimiser_keeps_observable_effects() {
    // MOV rax, rbx — observable.
    let bytes = [0x48, 0x89, 0xd8];
    let instrs = lift(&bytes);
    let opt = optimise_effects(&instrs[0].effects);
    let rax_write = opt
        .iter()
        .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rax"));
    assert!(rax_write, "optimiser must not remove observable reg write");
}

// ─────────────────────────────────────────────────────────────────────────────
// Pseudo-instruction scanner
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn xor_self_detected_as_pseudo() {
    let bytes = [0x31, 0xc0]; // XOR eax, eax
    let instrs = lift(&bytes);
    let pseudos = scan_pseudos(&instrs);
    let xor_zero = pseudos.iter().any(|m| {
        matches!(
            &m.kind,
            rustre_il_lift::x86_pseudo::PseudoKind::XorZero { .. }
        )
    });
    assert!(
        xor_zero,
        "XOR eax,eax should be detected as xor_zero pseudo"
    );
}

#[test]
fn prologue_detected_in_lifted_code() {
    let bytes = [0x55u8, 0x48, 0x89, 0xe5]; // PUSH rbp + MOV rbp, rsp
    let instrs = lift(&bytes);
    let pseudos = scan_pseudos(&instrs);
    let prologue = pseudos.iter().any(|m| {
        matches!(
            &m.kind,
            rustre_il_lift::x86_pseudo::PseudoKind::PrologueStandard
        )
    });
    assert!(prologue, "should detect standard prologue pattern");
}

// ─────────────────────────────────────────────────────────────────────────────
// Type recovery
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn type_recovery_runs_without_panic() {
    let bytes = [0x90u8, 0x90, 0xc3];
    let instrs = lift(&bytes);
    let (env, _) = recover_types(&instrs, 64);
    // ZF is in the builtin env — should always be Bool.
    let zf = env.get("zf");
    if let Some(ann) = zf {
        assert_eq!(
            ann.ty,
            rustre_il_lift::x86_type_recovery::RecoveredType::Bool
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pretty-printer
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn render_text_does_not_panic() {
    let bytes = [0x90u8, 0xc3];
    let instrs = lift(&bytes);
    let s = render_block(&instrs, &PrintOptions::default());
    assert!(!s.is_empty(), "render should produce non-empty output");
}

#[test]
fn render_contains_address() {
    let bytes = [0x90];
    let instrs = lift(&bytes);
    let s = render_block(&instrs, &PrintOptions::default());
    assert!(
        s.contains("0x00001000"),
        "render should show instruction address"
    );
}

#[test]
fn render_contains_mnemonic() {
    let bytes = [0x90]; // NOP
    let instrs = lift(&bytes);
    let s = render_block(&instrs, &PrintOptions::default());
    assert!(s.contains("nop"), "render should show mnemonic");
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern matching on lifted IR
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pattern_matches_ret_in_lifted_code() {
    let bytes = [0xc3]; // RET
    let instrs = lift(&bytes);
    let all_effects: Vec<Effect> = instrs.iter().flat_map(|li| li.effects.clone()).collect();
    let patterns = vec![EffectPat::Return];
    let result = scan_sequence(&all_effects, &patterns);
    assert!(
        result.is_some(),
        "should find Return effect in RET instruction"
    );
}

#[test]
fn pattern_finds_flag_write() {
    let bytes = [0x48, 0x83, 0xc0, 0x01]; // ADD rax, 1
    let instrs = lift(&bytes);
    let all_effects: Vec<Effect> = instrs.iter().flat_map(|li| li.effects.clone()).collect();
    let patterns = vec![EffectPat::RegWrite {
        reg: ExprPat::Reg("zf".into()),
        value: ExprPat::Any,
    }];
    let result = scan_sequence(&all_effects, &patterns);
    assert!(result.is_some(), "should find ZF write in ADD instruction");
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction DB
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn insn_db_lookup_add() {
    let db = InsnDb::new();
    let i = db.get("add");
    assert_eq!(
        i.category,
        rustre_il_lift::x86_insn_db::InsnCategory::Arithmetic
    );
    assert!(i.modifies_flags());
}

#[test]
fn insn_db_lookup_nop() {
    let db = InsnDb::new();
    let i = db.get("nop");
    assert!(!i.modifies_flags());
    assert!(!i.is_terminator);
}

#[test]
fn insn_db_lookup_jmp_is_terminator() {
    let db = InsnDb::new();
    assert!(db.get("jmp").is_terminator);
}

#[test]
fn insn_db_coverage() {
    let db = InsnDb::new();
    // We should have at least the core instructions.
    assert!(db.len() >= 50, "DB should have at least 50 entries");
}

// ─────────────────────────────────────────────────────────────────────────────
// Edge cases and robustness
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lift_empty_bytes_returns_nothing() {
    let (instrs, errors) = X86LifterV2::new_64().lift_bytes(&[], 0x1000);
    assert!(instrs.is_empty());
    assert!(errors.is_empty());
}

#[test]
fn lift_multiple_instructions_sequential_addresses() {
    let bytes = [0x90u8, 0x90, 0x90]; // 3 NOPs
    let (instrs, _) = X86LifterV2::new_64().lift_bytes(&bytes, 0x2000);
    assert_eq!(instrs.len(), 3);
    assert_eq!(instrs[0].address, 0x2000);
    assert_eq!(instrs[1].address, 0x2001);
    assert_eq!(instrs[2].address, 0x2002);
}

#[test]
fn lifter_32bit_mode() {
    let lifter = X86LifterV2::new_32();
    assert_eq!(lifter.arch_name(), "x86_32_v2");
    let (instrs, _) = lifter.lift_bytes(&[0x90], 0x1000);
    assert_eq!(instrs.len(), 1);
}

#[test]
fn error_recovery_handles_unimplemented_gracefully() {
    let lifter = X86LifterV2::new(64, true); // recovery enabled
    // RDTSCP (0F 01 F9) — should not panic even if less-common.
    let (instrs, _) = lifter.lift_bytes(&[0x0f, 0x01, 0xf9], 0x1000);
    assert_eq!(instrs.len(), 1);
}

#[test]
fn eval_wrapping_arithmetic() {
    // ADD rax, 1 where rax = u64::MAX — should wrap.
    let s = lift_eval(&[0x48, 0x83, 0xc0, 0x01], &[("rax", u64::MAX)]);
    s.assert_reg("rax", 0);
}

#[test]
fn lifted_instr_is_terminator_for_ret() {
    let bytes = [0xc3];
    let instrs = lift(&bytes);
    assert!(instrs[0].is_terminator(), "RET should be a terminator");
}

#[test]
fn lifted_instr_not_terminator_for_nop() {
    let bytes = [0x90];
    let instrs = lift(&bytes);
    assert!(!instrs[0].is_terminator(), "NOP should not be a terminator");
}

#[test]
fn lifted_instr_has_side_effects_for_call() {
    let bytes = [0xe8, 0x00, 0x00, 0x00, 0x00];
    let instrs = lift(&bytes);
    assert!(
        instrs[0].has_side_effects(),
        "CALL should have side effects"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Robustness / semantic fuzzing (spec: "Fuzzing Semantico Isolato")
//
// The lifter must never panic on adversarial or malformed input — the kind of
// bytes produced by packed/obfuscated malware. These tests drive the full
// `decode → lift → eval` pipeline over a large, *deterministic* pseudo-random
// corpus (a fixed-seed LCG, so any failure reproduces exactly) and assert the
// whole pipeline completes without panicking. No external fuzz harness or
// crate is required; the corpus is self-contained.
// ─────────────────────────────────────────────────────────────────────────────

/// Small deterministic LCG (Knuth MMIX constants). Reproducible across runs.
struct Lcg(u64);
impl Lcg {
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

fn fuzz_pipeline(bits: u8, seed: u64, iterations: usize) {
    let lifter = match bits {
        64 => X86LifterV2::new_64(),
        32 => X86LifterV2::new_32(),
        _ => X86LifterV2::new_16(),
    };
    let mut rng = Lcg(seed);
    // Silence the default panic hook for the duration so a (hypothetical)
    // panic does not spam stderr before catch_unwind reports it cleanly.
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut first_panic: Option<(usize, Vec<u8>, u64)> = None;
    for i in 0..iterations {
        let len = 1 + (rng.next() % 15) as usize;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push((rng.next() >> 33) as u8);
        }
        let addr = rng.next();
        let bytes_for_panic = bytes.clone();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (lifted, _errors) = lifter.lift_bytes(&bytes, addr);
            // Also exercise the evaluator over every lifted instruction so the
            // expression interpreter and the lazy-flag intrinsics are fuzzed.
            let mut state = X86CpuState::new();
            for li in &lifted {
                let _ = exec_effects(&li.effects, &mut state);
            }
        }));
        if outcome.is_err() {
            first_panic = Some((i, bytes_for_panic, addr));
            break;
        }
    }
    std::panic::set_hook(prev);
    assert!(
        first_panic.is_none(),
        "decode→lift→eval panicked at iteration {first_panic:?}"
    );
}

#[test]
fn fuzz_lift_eval_never_panics_64bit() {
    fuzz_pipeline(64, 0x0bad_c0de_dead_beef, 50_000);
}

#[test]
fn fuzz_lift_eval_never_panics_32bit() {
    fuzz_pipeline(32, 0x1234_5678_9abc_def1, 50_000);
}

#[test]
fn fuzz_lift_eval_never_panics_16bit() {
    fuzz_pipeline(16, 0xfeed_face_cafe_babe, 30_000);
}

// ─────────────────────────────────────────────────────────────────────────────
// Semantic equivalence (differential) testing against an independent oracle.
//
// The spec calls for verifying the lifter's flag semantics against a reference
// (unicorn). Here the reference is a small, obviously-correct native-Rust model
// of the x86 ADD/SUB flag algebra; we cross-check the lifter+evaluator against
// it over thousands of random operands at every operand width. Fully in-module
// and deterministic — no emulator dependency.
// ─────────────────────────────────────────────────────────────────────────────

/// Reference flag model for `a + b` at `w` bits. Returns [cf, of, af, sf, zf, pf].
fn ref_add_flags(a: u64, b: u64, w: u32) -> [u64; 6] {
    let mask = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
    let (aw, bw) = (a & mask, b & mask);
    let full = u128::from(aw) + u128::from(bw);
    let res = (full as u64) & mask;
    let cf = ((full >> w) & 1) as u64;
    let sf = (res >> (w - 1)) & 1;
    let zf = u64::from(res == 0);
    let pf = u64::from((res & 0xff).count_ones().is_multiple_of(2));
    let af = u64::from((aw & 0xf) + (bw & 0xf) > 0xf);
    let of = ((!(aw ^ bw)) & (aw ^ res)) >> (w - 1) & 1;
    [cf, of, af, sf, zf, pf]
}

/// Reference flag model for `a - b` at `w` bits. Returns [cf, of, af, sf, zf, pf].
fn ref_sub_flags(a: u64, b: u64, w: u32) -> [u64; 6] {
    let mask = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
    let (aw, bw) = (a & mask, b & mask);
    let res = aw.wrapping_sub(bw) & mask;
    let cf = u64::from(aw < bw);
    let sf = (res >> (w - 1)) & 1;
    let zf = u64::from(res == 0);
    let pf = u64::from((res & 0xff).count_ones() % 2 == 0);
    let af = u64::from((aw & 0xf) < (bw & 0xf));
    let of = ((aw ^ bw) & (aw ^ res)) >> (w - 1) & 1;
    [cf, of, af, sf, zf, pf]
}

#[test]
fn semantic_diff_add_sub_flags_vs_reference() {
    let lifter = X86LifterV2::new_64();
    // (width, ADD r/m,r bytes, SUB r/m,r bytes, dst reg, src reg)
    type AddSubForm<'a> = (u32, &'a [u8], &'a [u8], &'a str, &'a str);
    let forms: [AddSubForm<'_>; 4] = [
        (8, &[0x00, 0xd8], &[0x28, 0xd8], "al", "bl"),
        (16, &[0x66, 0x01, 0xd8], &[0x66, 0x29, 0xd8], "ax", "bx"),
        (32, &[0x01, 0xd8], &[0x29, 0xd8], "eax", "ebx"),
        (64, &[0x48, 0x01, 0xd8], &[0x48, 0x29, 0xd8], "rax", "rbx"),
    ];

    let flags = |s: &X86CpuState| -> [u64; 6] {
        ["cf", "of", "af", "sf", "zf", "pf"].map(|f| {
            s.get_reg(f)
                .as_concrete()
                .unwrap_or_else(|| panic!("flag {f} was not concrete — lazy-flag eval gap"))
        })
    };

    let mut rng = Lcg(0x00c0_ffee_1234_5678);
    for _ in 0..4000 {
        let a = rng.next();
        let b = rng.next();
        for (w, add_bytes, sub_bytes, dst, src) in forms {
            // ADD
            let (lifted, errs) = lifter.lift_bytes(add_bytes, 0x1000);
            assert!(
                errs.is_empty() && lifted.len() == 1,
                "ADD w{w} failed to lift"
            );
            let mut s = X86CpuState::with_gp_regs(&[(dst, a), (src, b)]);
            exec_effects(&lifted[0].effects, &mut s);
            assert_eq!(
                flags(&s),
                ref_add_flags(a, b, w),
                "ADD w{w}: a={a:#x} b={b:#x}"
            );

            // SUB
            let (lifted, errs) = lifter.lift_bytes(sub_bytes, 0x1000);
            assert!(
                errs.is_empty() && lifted.len() == 1,
                "SUB w{w} failed to lift"
            );
            let mut s = X86CpuState::with_gp_regs(&[(dst, a), (src, b)]);
            exec_effects(&lifted[0].effects, &mut s);
            assert_eq!(
                flags(&s),
                ref_sub_flags(a, b, w),
                "SUB w{w}: a={a:#x} b={b:#x}"
            );
        }
    }
}

/// Categorical coverage: one representative real encoding per priority handler
/// family (spec §"Priorità di implementazione"). Each must lift to exactly one
/// instruction with no error, and produce effects unless it is a true no-op.
/// This locks dispatch coverage so a refactor cannot silently drop a family.
#[test]
fn coverage_all_priority_categories_lift() {
    // (label, bytes, expects_effects)
    let cases: &[(&str, &[u8], bool)] = &[
        ("mov rax,rbx", &[0x48, 0x89, 0xd8], true),
        ("movzx rax,bl", &[0x48, 0x0f, 0xb6, 0xc3], true),
        ("movsx rax,bl", &[0x48, 0x0f, 0xbe, 0xc3], true),
        ("lea rax,[rax]", &[0x48, 0x8d, 0x00], true),
        ("add rax,rbx", &[0x48, 0x01, 0xd8], true),
        ("sub rax,rbx", &[0x48, 0x29, 0xd8], true),
        ("cmp rax,rbx", &[0x48, 0x39, 0xd8], true),
        ("inc rax", &[0x48, 0xff, 0xc0], true),
        ("neg rax", &[0x48, 0xf7, 0xd8], true),
        ("mul rbx", &[0x48, 0xf7, 0xe3], true),
        ("and rax,rbx", &[0x48, 0x21, 0xd8], true),
        ("or rax,rbx", &[0x48, 0x09, 0xd8], true),
        ("xor rax,rbx", &[0x48, 0x31, 0xd8], true),
        ("not rax", &[0x48, 0xf7, 0xd0], true),
        ("test rax,rax", &[0x48, 0x85, 0xc0], true),
        ("shl rax,1", &[0x48, 0xd1, 0xe0], true),
        ("shr rax,1", &[0x48, 0xd1, 0xe8], true),
        ("sar rax,1", &[0x48, 0xd1, 0xf8], true),
        ("rol rax,1", &[0x48, 0xd1, 0xc0], true),
        ("jmp rel8", &[0xeb, 0x00], true),
        ("je rel8", &[0x74, 0x00], true),
        ("call rel32", &[0xe8, 0x00, 0x00, 0x00, 0x00], true),
        ("ret", &[0xc3], true),
        ("push rax", &[0x50], true),
        ("pop rax", &[0x58], true),
        ("leave", &[0xc9], true),
        ("sete al", &[0x0f, 0x94, 0xc0], true),
        ("setne al", &[0x0f, 0x95, 0xc0], true),
        ("bsf rax,rbx", &[0x48, 0x0f, 0xbc, 0xc3], true),
        ("bswap rax", &[0x48, 0x0f, 0xc8], true),
        ("popcnt rax,rbx", &[0xf3, 0x48, 0x0f, 0xb8, 0xc3], true),
        ("movsb", &[0xa4], true),
        ("stosb", &[0xaa], true),
        ("syscall", &[0x0f, 0x05], true),
        ("cpuid", &[0x0f, 0xa2], true),
        ("rdtsc", &[0x0f, 0x31], true),
        ("cld", &[0xfc], true),
        ("stc", &[0xf9], true),
        ("movaps xmm0,xmm1", &[0x0f, 0x28, 0xc1], true),
        ("xorps xmm0,xmm0", &[0x0f, 0x57, 0xc0], true),
        ("nop", &[0x90], false),
    ];

    let lifter = X86LifterV2::new_64();
    let mut missing = Vec::new();
    for (label, bytes, expects_effects) in cases {
        let (lifted, errors) = lifter.lift_bytes(bytes, 0x1000);
        if !errors.is_empty() {
            missing.push(format!("{label}: lift error {errors:?}"));
            continue;
        }
        if lifted.len() != 1 {
            missing.push(format!("{label}: expected 1 instr, got {}", lifted.len()));
            continue;
        }
        let has_fx = !lifted[0].effects.is_empty();
        if has_fx != *expects_effects {
            missing.push(format!(
                "{label}: effects={has_fx}, expected {expects_effects}"
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "coverage gaps:\n  {}",
        missing.join("\n  ")
    );
}

/// Targeted corpus of long instructions exercising prefixes (REX/operand-size/
/// segment/REP) and SIB/ModRM combinations, which stress the operand decoder.
#[test]
fn fuzz_prefixed_streams_never_panic() {
    let prefixes: [&[u8]; 8] = [
        &[0x66],
        &[0x67],
        &[0xf2],
        &[0xf3],
        &[0x48],
        &[0x4c],
        &[0x64],
        &[0x65],
    ];
    let lifter = X86LifterV2::new_64();
    let mut rng = Lcg(0xa5a5_5a5a_0f0f_f0f0);
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut panicked = false;
    'outer: for _ in 0..20_000 {
        let mut bytes = Vec::new();
        let np = (rng.next() % 3) as usize;
        for _ in 0..np {
            let p = prefixes[(rng.next() as usize) % prefixes.len()];
            bytes.extend_from_slice(p);
        }
        let body = 1 + (rng.next() % 8) as usize;
        for _ in 0..body {
            bytes.push((rng.next() >> 40) as u8);
        }
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (lifted, _e) = lifter.lift_bytes(&bytes, 0x4000);
            let mut st = X86CpuState::new();
            for li in &lifted {
                let _ = exec_effects(&li.effects, &mut st);
            }
        }));
        if r.is_err() {
            panicked = true;
            break 'outer;
        }
    }
    std::panic::set_hook(prev);
    assert!(!panicked, "prefixed-stream fuzzing panicked");
}
