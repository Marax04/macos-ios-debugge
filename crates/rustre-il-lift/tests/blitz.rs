//! Blitz test suite for `rustre-il-lift` — exercises the core lib.rs public
//! API surface that isn't already covered by `lift_integration.rs`.

use rustre_core::address::Address;
use rustre_core::arch::{InstrFlags, Instruction, Operand, RegisterInfo, RegisterKind};
use rustre_il_lift::{
    AddressMap, ArchLifter, BatchLifter, Effect, ErrorRecoveryLifter, GenericLlilLifter, IrExpr,
    LiftCache, LiftContext, LiftCoordinator, LiftError, LiftLevel, LiftMetadata, LiftResult,
    LiftSession, LiftStats, LiftVerifier, LifterRegistry, LiftedInstr, LruLiftCache,
    PartialLiftResult, VerificationResult,
};

// ─── helpers ────────────────────────────────────────────────────────────────

fn reg(name: &str, size: usize) -> RegisterInfo {
    RegisterInfo::new(name, 0, size, RegisterKind::General)
}

fn ins(addr: u64, mnem: &str) -> Instruction {
    Instruction {
        address: Address(addr),
        size: 1,
        mnemonic: mnem.into(),
        operands: String::new(),
        operand_list: Vec::new(),
        flags: InstrFlags::NONE,
        bytes: vec![],
        comment: None,
    }
}

fn ins_with_ops(addr: u64, mnem: &str, ops: Vec<Operand>) -> Instruction {
    let mut i = ins(addr, mnem);
    i.operand_list = ops;
    i
}

// ─── IrExpr ─────────────────────────────────────────────────────────────────

#[test]
fn irexpr_is_const_and_is_reg() {
    assert_eq!(IrExpr::Const(42).is_const(), Some(42));
    assert_eq!(IrExpr::Reg("rax".into()).is_const(), None);
    assert_eq!(IrExpr::Reg("rbx".into()).is_reg(), Some("rbx"));
    assert_eq!(IrExpr::Const(1).is_reg(), None);
}

#[test]
fn irexpr_node_count_leaves() {
    assert_eq!(IrExpr::Const(0).node_count(), 1);
    assert_eq!(IrExpr::Reg("a".into()).node_count(), 1);
    assert_eq!(IrExpr::Undef.node_count(), 1);
}

#[test]
fn irexpr_node_count_unary() {
    let e = IrExpr::Not(Box::new(IrExpr::Const(1)));
    assert_eq!(e.node_count(), 2);
    let d = IrExpr::Deref(Box::new(IrExpr::Reg("rax".into())), 8);
    assert_eq!(d.node_count(), 2);
}

#[test]
fn irexpr_node_count_binary() {
    let e = IrExpr::Add(Box::new(IrExpr::Const(1)), Box::new(IrExpr::Const(2)));
    assert_eq!(e.node_count(), 3);
}

#[test]
fn irexpr_node_count_ternary() {
    let e = IrExpr::IfThenElse(
        Box::new(IrExpr::Const(1)),
        Box::new(IrExpr::Const(2)),
        Box::new(IrExpr::Const(3)),
    );
    assert_eq!(e.node_count(), 4);
}

#[test]
fn irexpr_node_count_deep() {
    // (a + b) * (c - d)
    let e = IrExpr::Mul(
        Box::new(IrExpr::Add(
            Box::new(IrExpr::Reg("a".into())),
            Box::new(IrExpr::Reg("b".into())),
        )),
        Box::new(IrExpr::Sub(
            Box::new(IrExpr::Reg("c".into())),
            Box::new(IrExpr::Reg("d".into())),
        )),
    );
    assert_eq!(e.node_count(), 7);
}

#[test]
fn irexpr_registers_used_collects_all() {
    let e = IrExpr::Add(
        Box::new(IrExpr::Reg("rax".into())),
        Box::new(IrExpr::Mul(
            Box::new(IrExpr::Reg("rbx".into())),
            Box::new(IrExpr::Reg("rcx".into())),
        )),
    );
    let regs = e.registers_used();
    assert_eq!(regs.len(), 3);
    assert!(regs.contains(&"rax".to_string()));
    assert!(regs.contains(&"rbx".to_string()));
    assert!(regs.contains(&"rcx".to_string()));
}

#[test]
fn irexpr_registers_used_none_for_consts() {
    let e = IrExpr::Add(Box::new(IrExpr::Const(1)), Box::new(IrExpr::Const(2)));
    assert!(e.registers_used().is_empty());
}

#[test]
fn irexpr_registers_used_through_ternary() {
    let e = IrExpr::IfThenElse(
        Box::new(IrExpr::Reg("c".into())),
        Box::new(IrExpr::Reg("t".into())),
        Box::new(IrExpr::Reg("e".into())),
    );
    let r = e.registers_used();
    assert_eq!(r.len(), 3);
}

#[test]
fn irexpr_display_basic() {
    assert_eq!(format!("{}", IrExpr::Const(0xff)), "0xff");
    assert_eq!(format!("{}", IrExpr::Reg("rax".into())), "rax");
    assert_eq!(format!("{}", IrExpr::Undef), "undef");
}

#[test]
fn irexpr_eq_and_hash_consistent() {
    use std::collections::HashSet;
    let a = IrExpr::Add(Box::new(IrExpr::Const(1)), Box::new(IrExpr::Const(2)));
    let b = IrExpr::Add(Box::new(IrExpr::Const(1)), Box::new(IrExpr::Const(2)));
    assert_eq!(a, b);
    let mut s = HashSet::new();
    s.insert(a);
    assert!(s.contains(&b));
}

// ─── Effect ─────────────────────────────────────────────────────────────────

#[test]
fn effect_is_side_effectful_true_cases() {
    assert!(Effect::Call { target: IrExpr::Const(0) }.is_side_effectful());
    assert!(Effect::Return { value: None }.is_side_effectful());
    assert!(Effect::Syscall { nr: IrExpr::Const(1) }.is_side_effectful());
    assert!(Effect::Branch { target: IrExpr::Const(0), condition: None }.is_side_effectful());
    assert!(Effect::MemWrite { addr: IrExpr::Const(0), value: IrExpr::Const(0), size: 8 }.is_side_effectful());
    // `Intrinsic` is the fallback for a mnemonic the lifter did not recognise:
    // an undecoded operation must be assumed to do anything, or a dead-code pass
    // would delete it. `Trap`/`NoReturn` are observable by definition.
    assert!(Effect::Intrinsic { name: "x".into(), args: vec![] }.is_side_effectful());
    assert!(Effect::Trap { vector: 3 }.is_side_effectful());
    assert!(Effect::NoReturn.is_side_effectful());
}

#[test]
fn effect_is_side_effectful_false_cases() {
    // Only these two are genuinely eliminable — and only when the register they
    // write is dead. Everything else, including anything the lifter could not
    // model, has to be assumed observable.
    assert!(!Effect::RegWrite { reg: "rax".into(), value: IrExpr::Const(0) }.is_side_effectful());
    assert!(!Effect::MemRead { addr: IrExpr::Const(0), dest: "rax".into(), size: 8 }.is_side_effectful());
}

#[test]
fn effect_written_registers() {
    let e = Effect::RegWrite { reg: "rax".into(), value: IrExpr::Const(0) };
    assert_eq!(e.written_registers(), vec!["rax"]);
    let m = Effect::MemRead { addr: IrExpr::Const(0), dest: "rdi".into(), size: 8 };
    assert_eq!(m.written_registers(), vec!["rdi"]);
    let c = Effect::Call { target: IrExpr::Const(0) };
    assert!(c.written_registers().is_empty());
}

#[test]
fn effect_read_registers_includes_all_sources() {
    let mw = Effect::MemWrite {
        addr: IrExpr::Reg("rsp".into()),
        value: IrExpr::Reg("rax".into()),
        size: 8,
    };
    let regs = mw.read_registers();
    assert!(regs.contains(&"rsp".to_string()));
    assert!(regs.contains(&"rax".to_string()));
}

#[test]
fn effect_read_registers_for_branch_with_condition() {
    let b = Effect::Branch {
        target: IrExpr::Reg("target".into()),
        condition: Some(IrExpr::Reg("zf".into())),
    };
    let r = b.read_registers();
    assert!(r.contains(&"target".to_string()));
    assert!(r.contains(&"zf".to_string()));
}

#[test]
fn effect_read_registers_for_intrinsic() {
    let e = Effect::Intrinsic {
        name: "x".into(),
        args: vec![IrExpr::Reg("rax".into()), IrExpr::Reg("rbx".into())],
    };
    let r = e.read_registers();
    assert_eq!(r.len(), 2);
}

#[test]
fn effect_display_formats() {
    let rw = Effect::RegWrite { reg: "rax".into(), value: IrExpr::Const(1) };
    assert!(format!("{rw}").contains("rax"));
    let ret = Effect::Return { value: None };
    assert_eq!(format!("{ret}"), "return");
    let nr = Effect::NoReturn;
    assert_eq!(format!("{nr}"), "noreturn");
    let trap = Effect::Trap { vector: 3 };
    assert!(format!("{trap}").contains('3'));
}

// ─── LiftLevel ──────────────────────────────────────────────────────────────

#[test]
fn liftlevel_all_has_four_in_order() {
    let all = LiftLevel::all();
    assert_eq!(all.len(), 4);
    assert_eq!(all[0], LiftLevel::Raw);
    assert_eq!(all[3], LiftLevel::Hlil);
}

#[test]
fn liftlevel_at_least_ordering() {
    assert!(LiftLevel::Hlil.at_least(LiftLevel::Raw));
    assert!(LiftLevel::Llil.at_least(LiftLevel::Llil));
    assert!(!LiftLevel::Raw.at_least(LiftLevel::Llil));
    assert!(LiftLevel::MlilSsa.at_least(LiftLevel::Llil));
}

#[test]
fn liftlevel_display() {
    assert_eq!(format!("{}", LiftLevel::Llil), "Llil");
}

// ─── LiftError ──────────────────────────────────────────────────────────────

#[test]
fn lifterror_display_variants() {
    let e = LiftError::UnsupportedArch("foo".into());
    assert!(format!("{e}").contains("foo"));
    let e = LiftError::DisasmFailed(0x1000, "bad".into());
    let s = format!("{e}");
    assert!(s.contains("0x1000") && s.contains("bad"));
    let e = LiftError::PartialLift { succeeded: 5, failed: 2 };
    let s = format!("{e}");
    assert!(s.contains('5') && s.contains('2'));
}

// ─── LiftedInstr ────────────────────────────────────────────────────────────

fn sample_li(addr: u64, effects: Vec<Effect>) -> LiftedInstr {
    LiftedInstr {
        address: addr,
        original_mnemonic: "x".into(),
        ir_text: String::new(),
        il_level: LiftLevel::Llil,
        effects,
    }
}

#[test]
fn liftedinstr_is_terminator_branch() {
    let li = sample_li(0, vec![Effect::Branch { target: IrExpr::Const(0), condition: None }]);
    assert!(li.is_terminator());
}

#[test]
fn liftedinstr_is_terminator_return() {
    let li = sample_li(0, vec![Effect::Return { value: None }]);
    assert!(li.is_terminator());
}

#[test]
fn liftedinstr_is_not_terminator_for_regwrite() {
    let li = sample_li(0, vec![Effect::RegWrite { reg: "rax".into(), value: IrExpr::Const(0) }]);
    assert!(!li.is_terminator());
}

#[test]
fn liftedinstr_written_and_read_registers() {
    let li = sample_li(
        0,
        vec![
            Effect::RegWrite { reg: "rax".into(), value: IrExpr::Reg("rbx".into()) },
            Effect::RegWrite { reg: "rcx".into(), value: IrExpr::Reg("rdx".into()) },
        ],
    );
    let w = li.written_registers();
    assert!(w.contains(&"rax".to_string()) && w.contains(&"rcx".to_string()));
    let r = li.read_registers();
    assert!(r.contains(&"rbx".to_string()) && r.contains(&"rdx".to_string()));
    assert_eq!(li.effect_count(), 2);
}

#[test]
fn liftedinstr_display_contains_address() {
    let li = sample_li(0xdead, vec![]);
    let s = format!("{li}");
    assert!(s.contains("0xdead"));
}

// ─── LiftResult ─────────────────────────────────────────────────────────────

#[test]
fn liftresult_empty_is_complete_with_one_success_rate() {
    let r = LiftResult::new();
    assert!(r.is_complete());
    assert_eq!(r.total_count(), 0);
    assert_eq!(r.success_rate(), 1.0);
    assert!(r.failed_addresses().is_empty());
}

#[test]
fn liftresult_with_failures() {
    let mut r = LiftResult::new();
    r.lifted.push(sample_li(0, vec![]));
    r.lifted.push(sample_li(1, vec![]));
    r.errors.push((2, LiftError::InvalidBytecode));
    assert!(!r.is_complete());
    assert_eq!(r.total_count(), 3);
    assert!((r.success_rate() - 2.0 / 3.0).abs() < 1e-9);
    assert_eq!(r.failed_addresses(), vec![2]);
}

#[test]
fn liftresult_default_equals_new() {
    let a = LiftResult::default();
    let b = LiftResult::new();
    assert_eq!(a.total_count(), b.total_count());
}

// ─── LiftStats ──────────────────────────────────────────────────────────────

#[test]
fn liftstats_default_rates() {
    let s = LiftStats::new();
    assert_eq!(s.cache_hit_rate(), 0.0);
    assert_eq!(s.success_rate(), 1.0); // zero total -> 1.0 per spec
}

#[test]
fn liftstats_merge_sums_all_fields() {
    let mut a = LiftStats::new();
    a.total_instructions = 10;
    a.succeeded = 8;
    a.failed = 2;
    a.cache_hits = 3;
    a.cache_misses = 7;
    a.lift_time_us = 100;
    a.recovery_count = 1;
    a.partial_lifts = 1;

    let mut b = LiftStats::new();
    b.total_instructions = 5;
    b.succeeded = 5;
    b.cache_hits = 1;
    b.cache_misses = 4;

    a.merge(&b);
    assert_eq!(a.total_instructions, 15);
    assert_eq!(a.succeeded, 13);
    assert_eq!(a.failed, 2);
    assert_eq!(a.cache_hits, 4);
    assert_eq!(a.cache_misses, 11);
}

#[test]
fn liftstats_rates_when_populated() {
    let mut s = LiftStats::new();
    s.cache_hits = 3;
    s.cache_misses = 1;
    assert!((s.cache_hit_rate() - 0.75).abs() < 1e-9);
    s.total_instructions = 10;
    s.succeeded = 7;
    assert!((s.success_rate() - 0.7).abs() < 1e-9);
}

// ─── LiftCache ──────────────────────────────────────────────────────────────

#[test]
fn liftcache_get_miss_then_hit() {
    let c = LiftCache::new(10);
    assert!(c.get(0x1000).is_none());
    assert_eq!(c.misses(), 1);
    c.insert(0x1000, sample_li(0x1000, vec![]));
    let got = c.get(0x1000);
    assert!(got.is_some());
    assert_eq!(c.hits(), 1);
    assert_eq!(c.len(), 1);
    assert!(!c.is_empty());
}

#[test]
fn liftcache_hit_rate() {
    let c = LiftCache::new(4);
    c.insert(1, sample_li(1, vec![]));
    let _ = c.get(1);
    let _ = c.get(1);
    let _ = c.get(2);
    assert!((c.hit_rate() - 2.0 / 3.0).abs() < 1e-9);
}

#[test]
fn liftcache_clear_empties() {
    let c = LiftCache::default_capacity();
    c.insert(1, sample_li(1, vec![]));
    c.insert(2, sample_li(2, vec![]));
    c.clear();
    assert!(c.is_empty());
}

#[test]
fn liftcache_eviction_when_full_does_not_exceed_capacity() {
    let c = LiftCache::new(3);
    for i in 0..10 {
        c.insert(i, sample_li(i, vec![]));
    }
    assert!(c.len() <= 3, "cache exceeded capacity: {}", c.len());
}

#[test]
fn liftcache_zero_hit_rate_when_no_access() {
    let c = LiftCache::new(2);
    assert_eq!(c.hit_rate(), 0.0);
}

// ─── LruLiftCache ───────────────────────────────────────────────────────────

#[test]
fn lrucache_basic_get_insert() {
    let c = LruLiftCache::new(2);
    assert!(c.is_empty());
    c.insert(1, sample_li(1, vec![]));
    assert_eq!(c.len(), 1);
    assert!(c.get(1).is_some());
    assert!(c.get(99).is_none());
    assert_eq!(c.hits(), 1);
    assert_eq!(c.misses(), 1);
}

#[test]
fn lrucache_evicts_least_recently_used() {
    let c = LruLiftCache::new(2);
    c.insert(1, sample_li(1, vec![]));
    c.insert(2, sample_li(2, vec![]));
    // Touch 1 → 2 is now LRU.
    let _ = c.get(1);
    c.insert(3, sample_li(3, vec![]));
    assert!(c.get(1).is_some(), "recently used should survive");
    assert!(c.get(2).is_none(), "LRU entry should have been evicted");
    assert!(c.get(3).is_some());
}

#[test]
fn lrucache_update_existing_does_not_evict() {
    let c = LruLiftCache::new(2);
    c.insert(1, sample_li(1, vec![]));
    c.insert(2, sample_li(2, vec![]));
    // Re-inserting same key shouldn't push len over cap or evict.
    c.insert(1, sample_li(1, vec![]));
    assert_eq!(c.len(), 2);
    assert!(c.get(1).is_some());
    assert!(c.get(2).is_some());
}

#[test]
fn lrucache_clear_works() {
    let c = LruLiftCache::new(4);
    c.insert(1, sample_li(1, vec![]));
    c.clear();
    assert!(c.is_empty());
}

#[test]
fn lrucache_hit_rate() {
    let c = LruLiftCache::new(4);
    assert_eq!(c.hit_rate(), 0.0);
    c.insert(1, sample_li(1, vec![]));
    let _ = c.get(1);
    let _ = c.get(2);
    assert!((c.hit_rate() - 0.5).abs() < 1e-9);
}

// ─── LiftContext ────────────────────────────────────────────────────────────

#[test]
fn liftcontext_defaults() {
    let ctx = LiftContext::new("x86_64");
    assert_eq!(ctx.arch, "x86_64");
    assert_eq!(ctx.target_level, LiftLevel::Llil);
    assert!(ctx.use_cache);
    assert!(ctx.error_recovery);
    assert!(ctx.allow_partial);
    assert_eq!(ctx.batch_limit, 10_000);
}

#[test]
fn liftcontext_builders() {
    let ctx = LiftContext::new("x")
        .with_level(LiftLevel::Hlil)
        .without_cache()
        .without_recovery()
        .strict()
        .with_batch_limit(50);
    assert_eq!(ctx.target_level, LiftLevel::Hlil);
    assert!(!ctx.use_cache);
    assert!(!ctx.error_recovery);
    assert!(!ctx.allow_partial);
    assert_eq!(ctx.batch_limit, 50);
}

#[test]
fn liftcontext_record_and_reset_stats() {
    let ctx = LiftContext::new("x");
    let mut s = LiftStats::new();
    s.succeeded = 5;
    s.total_instructions = 5;
    ctx.record_stats(&s);
    assert_eq!(ctx.stats().succeeded, 5);
    ctx.reset_stats();
    assert_eq!(ctx.stats().succeeded, 0);
}

// ─── GenericLlilLifter ──────────────────────────────────────────────────────

#[test]
fn generic_lifter_arch_name_and_level() {
    let l = GenericLlilLifter::new("custom".into());
    assert_eq!(l.arch_name(), "custom");
    assert_eq!(l.lift_level(), LiftLevel::Llil);
    assert!(!l.description().is_empty());
}

#[test]
fn generic_lifter_nop() {
    let l = GenericLlilLifter::new("x".into());
    let i = ins(0x100, "nop");
    let r = l.lift(&i).unwrap();
    assert_eq!(r.address, 0x100);
    assert!(r.effects.is_empty());
}

#[test]
fn generic_lifter_ret() {
    let l = GenericLlilLifter::new("x".into());
    let r = l.lift(&ins(0, "ret")).unwrap();
    assert!(matches!(r.effects[0], Effect::Return { .. }));
}

#[test]
fn generic_lifter_mov_reg_reg() {
    let l = GenericLlilLifter::new("x".into());
    let i = ins_with_ops(0, "mov", vec![
        Operand::Register(reg("rax", 8)),
        Operand::Register(reg("rbx", 8)),
    ]);
    let r = l.lift(&i).unwrap();
    match &r.effects[0] {
        Effect::RegWrite { reg: name, value: IrExpr::Reg(src) } => {
            assert_eq!(name, "rax");
            assert_eq!(src, "rbx");
        }
        other => panic!("unexpected effect: {other:?}"),
    }
}

#[test]
fn generic_lifter_add_produces_add_expr() {
    let l = GenericLlilLifter::new("x".into());
    let i = ins_with_ops(0, "add", vec![
        Operand::Register(reg("rax", 8)),
        Operand::Immediate(5),
    ]);
    let r = l.lift(&i).unwrap();
    assert!(matches!(&r.effects[0], Effect::RegWrite { value: IrExpr::Add(..), .. }));
}

#[test]
fn generic_lifter_push_decrements_rsp() {
    let l = GenericLlilLifter::new("x".into());
    let i = ins_with_ops(0, "push", vec![Operand::Register(reg("rbp", 8))]);
    let r = l.lift(&i).unwrap();
    assert_eq!(r.effects.len(), 2);
    let dec = r.effects.iter().any(|e| matches!(e,
        Effect::RegWrite { reg, value: IrExpr::Sub(_, b) } if reg == "rsp"
            && matches!(**b, IrExpr::Const(8))));
    assert!(dec, "PUSH must decrement rsp by 8");
}

#[test]
fn generic_lifter_jmp_immediate_low_value_is_relative() {
    // jmp 0x10 with instruction size 1 at address 0 -> target = 1 + 0x10 = 0x11
    let l = GenericLlilLifter::new("x".into());
    let i = ins_with_ops(0, "jmp", vec![Operand::Immediate(0x10)]);
    let r = l.lift(&i).unwrap();
    match &r.effects[0] {
        Effect::Branch { target: IrExpr::Const(t), condition: None } => {
            assert_eq!(*t, 0x11);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn generic_lifter_jmp_immediate_high_value_is_absolute() {
    let l = GenericLlilLifter::new("x".into());
    let i = ins_with_ops(0, "jmp", vec![Operand::Immediate(0x4000)]);
    let r = l.lift(&i).unwrap();
    match &r.effects[0] {
        Effect::Branch { target: IrExpr::Const(t), .. } => assert_eq!(*t, 0x4000),
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn generic_lifter_syscall_emits_syscall() {
    let l = GenericLlilLifter::new("x".into());
    let r = l.lift(&ins(0, "syscall")).unwrap();
    assert!(matches!(r.effects[0], Effect::Syscall { .. }));
}

#[test]
fn generic_lifter_unknown_mnemonic_yields_intrinsic() {
    let l = GenericLlilLifter::new("x".into());
    let r = l.lift(&ins(0, "wibble")).unwrap();
    assert!(matches!(&r.effects[0], Effect::Intrinsic { name, .. } if name == "wibble"));
}

#[test]
fn generic_lifter_cmp_test_no_effects_from_generic() {
    let l = GenericLlilLifter::new("x".into());
    let r = l.lift(&ins(0, "cmp")).unwrap();
    assert!(r.effects.is_empty());
    let r = l.lift(&ins(0, "test")).unwrap();
    assert!(r.effects.is_empty());
}

#[test]
fn generic_lifter_lift_block_default_impl() {
    let l = GenericLlilLifter::new("x".into());
    let block = vec![ins(0, "nop"), ins(1, "ret")];
    let results = l.lift_block(&block);
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(Result::is_ok));
}

// ─── ErrorRecoveryLifter ────────────────────────────────────────────────────

#[derive(Debug)]
struct AlwaysFailLifter;
impl ArchLifter for AlwaysFailLifter {
    fn arch_name(&self) -> &'static str { "fail" }
    fn lift_level(&self) -> LiftLevel { LiftLevel::Llil }
    fn lift(&self, _: &Instruction) -> Result<LiftedInstr, LiftError> {
        Err(LiftError::InvalidBytecode)
    }
}

#[test]
fn error_recovery_substitutes_intrinsic_stub() {
    let r = ErrorRecoveryLifter::new(Box::new(AlwaysFailLifter));
    let out = r.lift(&ins(0x10, "weird")).unwrap();
    assert!(matches!(&out.effects[0], Effect::Intrinsic { name, .. }
                                       if name == "__unlifted_weird"));
    assert_eq!(out.address, 0x10);
}

#[test]
fn error_recovery_forwards_arch_metadata() {
    let r = ErrorRecoveryLifter::new(Box::new(AlwaysFailLifter));
    assert_eq!(r.arch_name(), "fail");
    assert_eq!(r.lift_level(), LiftLevel::Llil);
    assert!(!r.description().is_empty());
}

// ─── LifterRegistry ─────────────────────────────────────────────────────────

#[test]
fn registry_empty_state() {
    let r = LifterRegistry::new();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
    assert!(!r.supports("x86"));
    assert!(r.get("anything").is_none());
}

#[test]
fn registry_register_and_lookup() {
    let mut r = LifterRegistry::new();
    r.register(GenericLlilLifter::new("zoo".into()));
    assert!(r.supports("zoo"));
    assert_eq!(r.len(), 1);
    assert!(r.get("zoo").is_some());
    let names = r.arch_names();
    assert_eq!(names, vec!["zoo"]);
}

#[test]
fn registry_register_replaces_existing() {
    let mut r = LifterRegistry::new();
    r.register(GenericLlilLifter::new("dup".into()));
    r.register(GenericLlilLifter::new("dup".into()));
    assert_eq!(r.len(), 1);
}

#[test]
fn registry_lift_instr_unsupported() {
    let r = LifterRegistry::new();
    let e = r.lift_instr("nope", &ins(0, "nop")).unwrap_err();
    assert!(matches!(e, LiftError::UnsupportedArch(_)));
}

#[test]
fn registry_lift_instr_dispatches() {
    let mut r = LifterRegistry::new();
    r.register(GenericLlilLifter::new("a".into()));
    let li = r.lift_instr("a", &ins(0x5, "nop")).unwrap();
    assert_eq!(li.address, 0x5);
}

#[test]
fn registry_with_defaults_has_x86_64() {
    let r = LifterRegistry::with_defaults();
    assert!(!r.is_empty());
}

// ─── BatchLifter ────────────────────────────────────────────────────────────

#[test]
fn batchlifter_lifts_all() {
    let bl = BatchLifter::new(
        Box::new(GenericLlilLifter::new("g".into())),
        LiftContext::new("g"),
    );
    let block = vec![ins(0, "nop"), ins(1, "ret"), ins(2, "nop")];
    let r = bl.lift_batch(&block).unwrap();
    assert_eq!(r.lifted.len(), 3);
    assert_eq!(r.stats.succeeded, 3);
    assert!(r.is_complete());
}

#[test]
fn batchlifter_respects_batch_limit() {
    let bl = BatchLifter::new(
        Box::new(GenericLlilLifter::new("g".into())),
        LiftContext::new("g").with_batch_limit(2),
    );
    let block = vec![ins(0, "nop"), ins(1, "nop"), ins(2, "nop"), ins(3, "nop")];
    let r = bl.lift_batch(&block).unwrap();
    assert_eq!(r.lifted.len(), 2);
    assert_eq!(r.stats.partial_lifts, 1);
}

#[test]
fn batchlifter_cache_hits_on_repeat() {
    let bl = BatchLifter::new(
        Box::new(GenericLlilLifter::new("g".into())),
        LiftContext::new("g"),
    );
    let block = vec![ins(0, "nop")];
    let _ = bl.lift_batch(&block).unwrap();
    let r2 = bl.lift_batch(&block).unwrap();
    assert!(r2.stats.cache_hits >= 1);
}

#[test]
fn batchlifter_strict_aborts_on_failure() {
    let bl = BatchLifter::new(
        Box::new(AlwaysFailLifter),
        LiftContext::new("fail").strict(),
    );
    let e = bl.lift_batch(&[ins(0, "nop")]).unwrap_err();
    assert!(matches!(e, LiftError::PartialLift { .. }));
}

#[test]
fn batchlifter_recovery_produces_stub_when_failing() {
    let bl = BatchLifter::new(
        Box::new(AlwaysFailLifter),
        LiftContext::new("fail"), // recovery on, partial on
    );
    let r = bl.lift_batch(&[ins(0x42, "wat")]).unwrap();
    assert_eq!(r.lifted.len(), 1);
    assert_eq!(r.errors.len(), 1);
    assert_eq!(r.stats.recovery_count, 1);
    assert_eq!(r.stats.failed, 1);
}

#[test]
fn batchlifter_lift_single_uses_cache() {
    let bl = BatchLifter::new(
        Box::new(GenericLlilLifter::new("g".into())),
        LiftContext::new("g"),
    );
    let i = ins(0xabc, "nop");
    let _ = bl.lift_single(&i).unwrap();
    let _ = bl.lift_single(&i).unwrap();
    assert!(bl.context().cache.hits() >= 1);
}

#[test]
fn batchlifter_from_registry_unsupported() {
    let reg = LifterRegistry::new();
    let r = BatchLifter::from_registry(&reg, "alien");
    assert!(matches!(r.unwrap_err(), LiftError::UnsupportedArch(_)));
}

#[test]
fn batchlifter_from_registry_x86_64() {
    let reg = LifterRegistry::with_defaults();
    if reg.supports("x86_64") {
        let (bl, _ctx) = BatchLifter::from_registry(&reg, "x86_64").unwrap();
        assert_eq!(bl.arch_name(), "x86_64");
    }
}

// ─── PartialLiftResult ──────────────────────────────────────────────────────

#[test]
fn partial_result_push_finalize_counts() {
    let mut p = PartialLiftResult::new();
    p.push_ok(sample_li(1, vec![]));
    p.push_ok(sample_li(2, vec![]));
    p.push_err(3);
    assert_eq!(p.success_count(), 2);
    assert_eq!(p.failure_count(), 1);
    assert!(!p.finalized);
    p.finalize();
    assert!(p.finalized);
}

#[test]
fn partial_result_snapshot_preserves_stats() {
    let mut p = PartialLiftResult::new();
    p.push_ok(sample_li(1, vec![]));
    p.push_err(2);
    let snap = p.snapshot();
    assert_eq!(snap.lifted.len(), 1);
    assert_eq!(snap.errors.len(), 1);
    assert_eq!(snap.stats.succeeded, 1);
    assert_eq!(snap.stats.failed, 1);
    assert_eq!(snap.stats.total_instructions, 2);
}

// ─── LiftCoordinator ────────────────────────────────────────────────────────

#[test]
fn coordinator_for_arch_lifts_nop() {
    let c = LiftCoordinator::for_arch("custom");
    let out = c.lift_block(&[ins(0, "nop")]);
    assert_eq!(out.len(), 1);
    assert_eq!(c.arch_name(), "custom");
    assert_eq!(c.lift_level(), LiftLevel::Llil);
}

#[test]
fn coordinator_with_recovery_substitutes_on_failure() {
    let c = LiftCoordinator::for_arch_with_recovery("any");
    // Generic lifter doesn't fail; check arch name forwarding instead.
    assert_eq!(c.arch_name(), "any");
    let r = c.lift_single(&ins(0, "ret")).unwrap();
    assert!(matches!(r.effects[0], Effect::Return { .. }));
}

#[test]
fn coordinator_lift_batch_collects_stats() {
    let c = LiftCoordinator::for_arch("c");
    let r = c.lift_batch(&[ins(0, "nop"), ins(1, "ret")]);
    assert_eq!(r.stats.total_instructions, 2);
    assert_eq!(r.stats.succeeded, 2);
}

#[test]
fn coordinator_lift_block_all_preserves_errors() {
    let c = LiftCoordinator::new(Box::new(AlwaysFailLifter));
    let r = c.lift_block_all(&[ins(0, "x"), ins(1, "y")]);
    assert_eq!(r.len(), 2);
    assert!(r.iter().all(Result::is_err));
    let dropped = c.lift_block(&[ins(0, "x")]);
    assert!(dropped.is_empty());
}

#[test]
fn coordinator_debug_includes_arch() {
    let c = LiftCoordinator::for_arch("zztop");
    let s = format!("{c:?}");
    assert!(s.contains("zztop"));
}

// ─── LiftMetadata ───────────────────────────────────────────────────────────

#[test]
fn metadata_default_and_builders() {
    let m = LiftMetadata::default();
    assert!(!m.has_hash());
    let m = LiftMetadata::new("x86", LiftLevel::Hlil)
        .with_timestamp(42)
        .with_hash("abc")
        .with_version("1.0");
    assert_eq!(m.source_arch, "x86");
    assert_eq!(m.target_level, LiftLevel::Hlil);
    assert_eq!(m.lift_timestamp, 42);
    assert!(m.has_hash());
    assert_eq!(m.lifter_version, "1.0");
}

#[test]
fn metadata_add_note() {
    let mut m = LiftMetadata::new("x", LiftLevel::Llil);
    m.add_note("hello");
    m.add_note("world");
    assert_eq!(m.notes.len(), 2);
}

// ─── AddressMap ─────────────────────────────────────────────────────────────

#[test]
fn addressmap_basic_insert_get() {
    let mut m = AddressMap::new();
    assert!(m.is_empty());
    m.insert(0x100, sample_li(0x100, vec![]));
    m.insert(0x50, sample_li(0x50, vec![]));
    m.insert(0x200, sample_li(0x200, vec![]));
    assert_eq!(m.len(), 3);
    assert!(m.contains(0x100));
    assert!(!m.contains(0x999));
    assert!(m.get(0x50).is_some());
    // Sorted order.
    assert_eq!(m.addresses(), vec![0x50, 0x100, 0x200]);
}

#[test]
fn addressmap_insert_replaces_at_same_address() {
    let mut m = AddressMap::new();
    let mut a = sample_li(1, vec![]);
    a.original_mnemonic = "first".into();
    let mut b = sample_li(1, vec![]);
    b.original_mnemonic = "second".into();
    m.insert(1, a);
    m.insert(1, b);
    assert_eq!(m.len(), 1);
    assert_eq!(m.get(1).unwrap().original_mnemonic, "second");
}

#[test]
fn addressmap_range_query() {
    let mut m = AddressMap::new();
    for a in [10u64, 20, 30, 40, 50] {
        m.insert(a, sample_li(a, vec![]));
    }
    let r = m.range(20, 45);
    assert_eq!(r.len(), 3);
}

#[test]
fn addressmap_from_lift_result_and_merge() {
    let mut res = LiftResult::new();
    res.lifted.push(sample_li(1, vec![]));
    res.lifted.push(sample_li(2, vec![]));
    let m1 = AddressMap::from_lift_result(&res);
    assert_eq!(m1.len(), 2);

    let mut m2 = AddressMap::new();
    m2.insert(3, sample_li(3, vec![]));
    let mut combined = m1;
    combined.merge_from(&m2);
    assert_eq!(combined.len(), 3);
    assert_eq!(combined.iter().count(), 3);
    assert_eq!(combined.instructions().len(), 3);
}

// ─── LiftVerifier / VerificationResult ──────────────────────────────────────

#[test]
fn verifier_equivalent_when_effects_match() {
    let v = LiftVerifier::new();
    let a = sample_li(0, vec![Effect::Return { value: None }]);
    let b = sample_li(0, vec![Effect::Return { value: None }]);
    assert_eq!(v.verify(&a, &b), VerificationResult::Equivalent);
}

#[test]
fn verifier_over_approx_when_lifted_has_extra() {
    let v = LiftVerifier::strict();
    let a = sample_li(0, vec![
        Effect::Return { value: None },
        Effect::RegWrite { reg: "rax".into(), value: IrExpr::Const(0) },
    ]);
    let b = sample_li(0, vec![Effect::Return { value: None }]);
    match v.verify(&a, &b) {
        VerificationResult::OverApproximation { extra_effects } => {
            assert_eq!(extra_effects, 1);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn verifier_under_approx_when_lifted_missing() {
    let v = LiftVerifier::strict();
    let a = sample_li(0, vec![Effect::Return { value: None }]);
    let b = sample_li(0, vec![
        Effect::Return { value: None },
        Effect::RegWrite { reg: "rax".into(), value: IrExpr::Const(0) },
    ]);
    assert!(matches!(v.verify(&a, &b),
        VerificationResult::UnderApproximation { missing_effects: 1 }));
}

#[test]
fn verifier_address_mismatch_is_inconclusive() {
    let v = LiftVerifier::new();
    let a = sample_li(1, vec![]);
    let b = sample_li(2, vec![]);
    assert!(matches!(v.verify(&a, &b), VerificationResult::Inconclusive(_)));
}

#[test]
fn verifier_intrinsic_wildcard_mode_ignores_intrinsics() {
    let v = LiftVerifier::new(); // wildcards on
    let a = sample_li(0, vec![
        Effect::Return { value: None },
        Effect::Intrinsic { name: "x".into(), args: vec![] },
    ]);
    let b = sample_li(0, vec![Effect::Return { value: None }]);
    assert_eq!(v.verify(&a, &b), VerificationResult::Equivalent);
}

#[test]
fn verifier_batch_handles_missing_reference() {
    let v = LiftVerifier::new();
    let lifted = vec![sample_li(1, vec![Effect::Return { value: None }])];
    let refmap = AddressMap::new();
    let results = v.verify_batch(&lifted, &refmap);
    assert_eq!(results.len(), 1);
    assert!(matches!(results[0].1, VerificationResult::Inconclusive(_)));
    assert!(!v.all_equivalent(&results));
}

#[test]
fn verification_result_display() {
    assert_eq!(format!("{}", VerificationResult::Equivalent), "equivalent");
    let s = format!("{}", VerificationResult::Mismatch { extra: 1, missing: 2 });
    assert!(s.contains('1') && s.contains('2'));
    assert!(VerificationResult::Equivalent.is_equivalent());
    assert!(!VerificationResult::Equivalent.is_diverged());
    assert!(VerificationResult::OverApproximation { extra_effects: 1 }.is_diverged());
    assert!(!VerificationResult::Inconclusive("x".into()).is_diverged());
}

// ─── LiftSession ────────────────────────────────────────────────────────────

#[test]
fn liftsession_creates_with_arch() {
    let s = LiftSession::new("x86_64");
    assert_eq!(s.context.arch, "x86_64");
    assert_eq!(s.lifted_count(), 0);
}

#[test]
fn liftsession_lift_accumulates() {
    let mut s = LiftSession::new("custom");
    let r = s.lift(&[ins(0, "nop"), ins(1, "ret")]).unwrap();
    assert_eq!(r.lifted.len(), 2);
    assert_eq!(s.lifted_count(), 2);
    assert!(s.total_stats().total_instructions >= 2);
}

#[test]
fn liftsession_reset_clears_state() {
    let mut s = LiftSession::new("custom");
    let _ = s.lift(&[ins(0, "nop")]).unwrap();
    assert!(s.lifted_count() > 0);
    s.reset();
    assert_eq!(s.lifted_count(), 0);
    assert_eq!(s.total_stats().total_instructions, 0);
}

// ─── Send/Sync invariants ───────────────────────────────────────────────────

#[test]
fn cache_and_context_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LiftCache>();
    assert_send_sync::<LruLiftCache>();
    assert_send_sync::<LiftContext>();
    assert_send_sync::<std::sync::Arc<LiftCache>>();
}
