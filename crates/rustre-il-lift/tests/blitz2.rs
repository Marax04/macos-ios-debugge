//! blitz2: adversarial deep tests for `rustre-il-lift` core API.

use rustre_core::address::Address;
use rustre_core::arch::{InstrFlags, Instruction, Operand, RegisterInfo, RegisterKind};
use rustre_il_lift::{
    ArchLifter, Effect, ErrorRecoveryLifter, GenericLlilLifter, IrExpr, LiftCache, LiftContext,
    LiftError, LiftLevel, LiftResult, LiftStats, LiftedInstr,
};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

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

fn ins_ops(addr: u64, mnem: &str, ops: Vec<Operand>) -> Instruction {
    let mut i = ins(addr, mnem);
    i.operand_list = ops;
    i.size = 4;
    i
}

fn lcg_seed() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

// ─── IrExpr deep property tests ────────────────────────────────────────────

#[test]
fn irexpr_const_round_trip_50_values() {
    let mut g = lcg_seed();
    for _ in 0..50 {
        let v = g();
        let e = IrExpr::Const(v);
        assert_eq!(e.is_const(), Some(v));
        assert!(e.is_reg().is_none());
        assert_eq!(e.node_count(), 1);
        assert!(e.registers_used().is_empty());
    }
}

#[test]
fn irexpr_reg_name_round_trip() {
    for name in ["rax", "rbx", "r0", "x29", "sp", "v15", "fp7"] {
        let e = IrExpr::Reg(name.to_string());
        assert_eq!(e.is_reg(), Some(name));
        assert_eq!(e.is_const(), None);
        assert_eq!(e.registers_used(), vec![name.to_string()]);
        assert_eq!(e.node_count(), 1);
    }
}

#[test]
fn irexpr_undef_has_no_regs_or_const() {
    let e = IrExpr::Undef;
    assert!(e.is_const().is_none());
    assert!(e.is_reg().is_none());
    assert!(e.registers_used().is_empty());
    assert_eq!(e.node_count(), 1);
}

#[test]
fn irexpr_node_count_caps_at_recursion_depth() {
    // Build a deep right-skewed tree well beyond 1024.
    let mut e = IrExpr::Const(0);
    for _ in 0..2000 {
        e = IrExpr::Not(Box::new(e));
    }
    // node_count should not panic or stack overflow; it caps at depth.
    let n = e.node_count();
    assert!((1..=2001).contains(&n));
}

#[test]
fn irexpr_registers_used_caps_recursion() {
    let mut e = IrExpr::Reg("r0".into());
    for _ in 0..2000 {
        e = IrExpr::Not(Box::new(e));
    }
    let regs = e.registers_used();
    // either capped at 0 or 1 depending on depth limit
    assert!(regs.len() <= 1);
}

#[test]
fn irexpr_binary_node_count_correct() {
    let e = IrExpr::Add(
        Box::new(IrExpr::Const(1)),
        Box::new(IrExpr::Reg("rax".into())),
    );
    assert_eq!(e.node_count(), 3);
}

#[test]
fn irexpr_ternary_node_count_correct() {
    let e = IrExpr::IfThenElse(
        Box::new(IrExpr::Reg("zf".into())),
        Box::new(IrExpr::Const(1)),
        Box::new(IrExpr::Const(0)),
    );
    assert_eq!(e.node_count(), 4);
}

#[test]
fn irexpr_registers_used_dedup_not_required_but_present() {
    let e = IrExpr::Add(
        Box::new(IrExpr::Reg("rax".into())),
        Box::new(IrExpr::Reg("rax".into())),
    );
    let regs = e.registers_used();
    assert_eq!(regs.len(), 2); // both occurrences listed
    assert!(regs.iter().all(|r| r == "rax"));
}

#[test]
fn irexpr_eq_hash_consistency_30_pairs() {
    let mut g = lcg_seed();
    for _ in 0..30 {
        let v = g();
        let a = IrExpr::Const(v);
        let b = IrExpr::Const(v);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
        let c = IrExpr::Const(v.wrapping_add(1));
        assert_ne!(a, c);
    }
}

#[test]
fn irexpr_eq_hash_for_composite() {
    let a = IrExpr::Add(
        Box::new(IrExpr::Reg("r1".into())),
        Box::new(IrExpr::Const(5)),
    );
    let b = IrExpr::Add(
        Box::new(IrExpr::Reg("r1".into())),
        Box::new(IrExpr::Const(5)),
    );
    assert_eq!(a, b);
    assert_eq!(hash_of(&a), hash_of(&b));
}

#[test]
fn irexpr_display_const_uses_hex() {
    let s = format!("{}", IrExpr::Const(0xdead));
    assert_eq!(s, "0xdead");
}

#[test]
fn irexpr_display_full_grammar() {
    assert_eq!(format!("{}", IrExpr::Reg("rax".into())), "rax");
    assert_eq!(format!("{}", IrExpr::Undef), "undef");
    let nested = IrExpr::Add(
        Box::new(IrExpr::Reg("r0".into())),
        Box::new(IrExpr::Const(1)),
    );
    assert_eq!(format!("{nested}"), "(r0 + 0x1)");
    let n = IrExpr::Not(Box::new(IrExpr::Reg("zf".into())));
    assert_eq!(format!("{n}"), "(!zf)");
    let d = IrExpr::Deref(Box::new(IrExpr::Reg("rsp".into())), 8);
    assert_eq!(format!("{d}"), "*rsp:8");
    let p = IrExpr::Parity(Box::new(IrExpr::Reg("al".into())));
    assert_eq!(format!("{p}"), "parity(al)");
}

#[test]
fn irexpr_boundary_const_values() {
    for v in [0u64, 1, u64::MAX, u64::MAX - 1, 1 << 63, (1u64 << 32) - 1] {
        let e = IrExpr::Const(v);
        assert_eq!(e.is_const(), Some(v));
        // display must not panic
        let _ = format!("{e}");
    }
}

// ─── Effect tests ──────────────────────────────────────────────────────────

#[test]
fn effect_side_effect_classification() {
    let rw = Effect::RegWrite {
        reg: "rax".into(),
        value: IrExpr::Const(0),
    };
    assert!(!rw.is_side_effectful());
    let mw = Effect::MemWrite {
        addr: IrExpr::Reg("rsp".into()),
        value: IrExpr::Const(0),
        size: 8,
    };
    assert!(mw.is_side_effectful());
    let mr = Effect::MemRead {
        addr: IrExpr::Reg("rsp".into()),
        dest: "rax".into(),
        size: 8,
    };
    assert!(!mr.is_side_effectful());
    let call = Effect::Call {
        target: IrExpr::Const(0x1000),
    };
    assert!(call.is_side_effectful());
    let br = Effect::Branch {
        target: IrExpr::Const(0x100),
        condition: None,
    };
    assert!(br.is_side_effectful());
    let ret = Effect::Return { value: None };
    assert!(ret.is_side_effectful());
    let sc = Effect::Syscall {
        nr: IrExpr::Reg("rax".into()),
    };
    assert!(sc.is_side_effectful());
    // An `Intrinsic` is what a lifter emits for a mnemonic it did not recognise,
    // and it reports no written registers: if it were also effect-free, a
    // dead-code pass would delete every instruction the lifter failed to model.
    let intr = Effect::Intrinsic {
        name: "foo".into(),
        args: vec![],
    };
    assert!(intr.is_side_effectful());
    // Removing an `int3`/`brk`/`ud2` changes what the program does.
    let trap = Effect::Trap { vector: 3 };
    assert!(trap.is_side_effectful());
    // `NoReturn` marks that control does not continue: dropping it would lose a
    // control-flow fact, so it counts as observable too.
    let nor = Effect::NoReturn;
    assert!(nor.is_side_effectful());
}

#[test]
fn effect_written_registers_complete() {
    let rw = Effect::RegWrite {
        reg: "rax".into(),
        value: IrExpr::Const(0),
    };
    assert_eq!(rw.written_registers(), vec!["rax"]);
    let mr = Effect::MemRead {
        addr: IrExpr::Reg("rsp".into()),
        dest: "rbx".into(),
        size: 8,
    };
    assert_eq!(mr.written_registers(), vec!["rbx"]);
    let mw = Effect::MemWrite {
        addr: IrExpr::Reg("rsp".into()),
        value: IrExpr::Const(0),
        size: 8,
    };
    assert!(mw.written_registers().is_empty());
}

#[test]
fn effect_read_registers_covers_all_variants() {
    let br = Effect::Branch {
        target: IrExpr::Reg("rip".into()),
        condition: Some(IrExpr::Reg("zf".into())),
    };
    let regs = br.read_registers();
    assert!(regs.iter().any(|r| r == "rip"));
    assert!(regs.iter().any(|r| r == "zf"));

    let intr = Effect::Intrinsic {
        name: "x".into(),
        args: vec![IrExpr::Reg("a".into()), IrExpr::Reg("b".into())],
    };
    let regs = intr.read_registers();
    assert_eq!(regs.len(), 2);

    let ret_v = Effect::Return {
        value: Some(IrExpr::Reg("rax".into())),
    };
    assert_eq!(ret_v.read_registers(), vec!["rax"]);

    let ret_n = Effect::Return { value: None };
    assert!(ret_n.read_registers().is_empty());

    let ct = Effect::ConditionalTrap {
        condition: IrExpr::Reg("of".into()),
        vector: 4,
    };
    assert_eq!(ct.read_registers(), vec!["of"]);

    let trap = Effect::Trap { vector: 3 };
    assert!(trap.read_registers().is_empty());

    let nor = Effect::NoReturn;
    assert!(nor.read_registers().is_empty());
}

#[test]
fn effect_display_no_panic_for_all_variants() {
    let effs = vec![
        Effect::RegWrite {
            reg: "r0".into(),
            value: IrExpr::Const(1),
        },
        Effect::MemWrite {
            addr: IrExpr::Const(0),
            value: IrExpr::Const(0),
            size: 4,
        },
        Effect::MemRead {
            addr: IrExpr::Const(0),
            dest: "r0".into(),
            size: 4,
        },
        Effect::Call {
            target: IrExpr::Const(0x1000),
        },
        Effect::Branch {
            target: IrExpr::Const(0x100),
            condition: None,
        },
        Effect::Branch {
            target: IrExpr::Const(0x100),
            condition: Some(IrExpr::Reg("zf".into())),
        },
        Effect::Return { value: None },
        Effect::Return {
            value: Some(IrExpr::Const(0)),
        },
        Effect::Syscall {
            nr: IrExpr::Const(60),
        },
        Effect::Intrinsic {
            name: "cpuid".into(),
            args: vec![],
        },
        Effect::Trap { vector: 3 },
        Effect::ConditionalTrap {
            condition: IrExpr::Reg("of".into()),
            vector: 4,
        },
        Effect::NoReturn,
    ];
    for e in &effs {
        let s = format!("{e}");
        assert!(!s.is_empty());
    }
}

// ─── LiftLevel ────────────────────────────────────────────────────────────

#[test]
fn liftlevel_ordering_monotonic() {
    let all = LiftLevel::all();
    assert_eq!(all.len(), 4);
    for w in all.windows(2) {
        assert!(w[0] < w[1]);
    }
}

#[test]
fn liftlevel_at_least_matrix() {
    assert!(LiftLevel::Hlil.at_least(LiftLevel::Llil));
    assert!(LiftLevel::MlilSsa.at_least(LiftLevel::Llil));
    assert!(LiftLevel::Llil.at_least(LiftLevel::Llil));
    assert!(!LiftLevel::Llil.at_least(LiftLevel::Hlil));
    assert!(!LiftLevel::Raw.at_least(LiftLevel::Llil));
}

#[test]
fn liftlevel_display_round_trip_through_debug() {
    for &l in LiftLevel::all() {
        let s = format!("{l}");
        assert!(!s.is_empty());
    }
}

#[test]
fn liftlevel_hash_eq() {
    let mut set: HashSet<LiftLevel> = HashSet::new();
    for &l in LiftLevel::all() {
        set.insert(l);
    }
    assert_eq!(set.len(), 4);
}

// ─── LiftError ────────────────────────────────────────────────────────────

#[test]
fn lifterror_display_all_variants() {
    let errs = vec![
        LiftError::UnsupportedArch("foo".into()),
        LiftError::DisasmFailed(0x1000, "bad".into()),
        LiftError::LiftFailed(0x2000, "x".into()),
        LiftError::InvalidBytecode,
        LiftError::UnsupportedLevel("Hlil".into()),
        LiftError::PartialLift {
            succeeded: 5,
            failed: 3,
        },
        LiftError::CacheError("oom".into()),
        LiftError::Other("?".into()),
    ];
    for e in &errs {
        assert!(!format!("{e}").is_empty());
    }
}

#[test]
fn lifterror_clone_preserves() {
    let e = LiftError::DisasmFailed(0x1234, "msg".into());
    let c = e.clone();
    assert_eq!(format!("{e}"), format!("{c}"));
}

// ─── LiftedInstr ──────────────────────────────────────────────────────────

fn li(addr: u64, mnem: &str, effects: Vec<Effect>) -> LiftedInstr {
    LiftedInstr {
        address: addr,
        original_mnemonic: mnem.into(),
        ir_text: String::new(),
        il_level: LiftLevel::Llil,
        effects,
    }
}

#[test]
fn liftedinstr_terminator_and_side_effects() {
    let term = li(
        0,
        "ret",
        vec![Effect::Return { value: None }],
    );
    assert!(term.is_terminator());
    assert!(term.has_side_effects());

    let nonterm = li(
        0,
        "mov",
        vec![Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Const(0),
        }],
    );
    assert!(!nonterm.is_terminator());
    assert!(!nonterm.has_side_effects());

    let br = li(
        0,
        "jmp",
        vec![Effect::Branch {
            target: IrExpr::Const(0x100),
            condition: None,
        }],
    );
    assert!(br.is_terminator());
    assert!(br.has_side_effects());
}

#[test]
fn liftedinstr_register_aggregation() {
    let l = li(
        0,
        "add",
        vec![Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Add(
                Box::new(IrExpr::Reg("rax".into())),
                Box::new(IrExpr::Reg("rbx".into())),
            ),
        }],
    );
    let w = l.written_registers();
    let r = l.read_registers();
    assert_eq!(w, vec!["rax"]);
    assert!(r.contains(&"rax".to_string()));
    assert!(r.contains(&"rbx".to_string()));
    assert_eq!(l.effect_count(), 1);
}

#[test]
fn liftedinstr_display_contains_address_hex() {
    let mut l = li(0x4000, "nop", vec![]);
    l.ir_text = "nop".into();
    let s = format!("{l}");
    assert!(s.contains("0x4000"));
    assert!(s.contains("nop"));
}

// ─── LiftResult ───────────────────────────────────────────────────────────

#[test]
fn liftresult_empty_invariants() {
    let r = LiftResult::new();
    assert!(r.is_complete());
    assert_eq!(r.total_count(), 0);
    assert_eq!(r.success_rate(), 1.0);
    assert!(r.failed_addresses().is_empty());
}

#[test]
fn liftresult_with_mixed_outcomes() {
    let mut r = LiftResult::new();
    r.lifted.push(li(0, "nop", vec![]));
    r.lifted.push(li(1, "nop", vec![]));
    r.errors.push((0x2000, LiftError::InvalidBytecode));
    assert!(!r.is_complete());
    assert_eq!(r.total_count(), 3);
    assert!((r.success_rate() - 2.0 / 3.0).abs() < 1e-9);
    assert_eq!(r.failed_addresses(), vec![0x2000]);
}

#[test]
fn liftresult_default_equals_new_invariants() {
    let r: LiftResult = Default::default();
    assert!(r.is_complete());
    assert_eq!(r.success_rate(), 1.0);
}

// ─── LiftStats ────────────────────────────────────────────────────────────

#[test]
fn liftstats_default_zero_rates() {
    let s = LiftStats::new();
    assert_eq!(s.cache_hit_rate(), 0.0);
    assert_eq!(s.success_rate(), 1.0);
}

#[test]
fn liftstats_merge_50_random() {
    let mut g = lcg_seed();
    let mut acc = LiftStats::new();
    let mut total = 0u64;
    let mut succ = 0u64;
    for _ in 0..50 {
        let t = g() % 1000;
        let s = g() % (t + 1);
        let mut o = LiftStats::new();
        o.total_instructions = t;
        o.succeeded = s;
        o.failed = t - s;
        acc.merge(&o);
        total += t;
        succ += s;
    }
    assert_eq!(acc.total_instructions, total);
    assert_eq!(acc.succeeded, succ);
}

#[test]
fn liftstats_rates_correct() {
    let mut s = LiftStats::new();
    s.cache_hits = 75;
    s.cache_misses = 25;
    s.total_instructions = 200;
    s.succeeded = 150;
    assert!((s.cache_hit_rate() - 0.75).abs() < 1e-9);
    assert!((s.success_rate() - 0.75).abs() < 1e-9);
}

#[test]
fn liftstats_boundary_overflow_safe() {
    let mut a = LiftStats::new();
    a.total_instructions = u64::MAX - 1;
    a.succeeded = u64::MAX - 1;
    // success_rate must not panic (f64 cast)
    let _ = a.success_rate();
    let _ = a.cache_hit_rate();
}

// ─── LiftCache ────────────────────────────────────────────────────────────

#[test]
fn liftcache_insert_get_50_random() {
    let cache = LiftCache::new(1000);
    let mut g = lcg_seed();
    for _ in 0..50 {
        let a = g();
        let l = li(a, "nop", vec![]);
        cache.insert(a, l.clone());
        let got = cache.get(a).expect("cached");
        assert_eq!(got.address, a);
    }
    assert!(cache.hits() >= 50);
}

#[test]
fn liftcache_eviction_respects_capacity() {
    let cache = LiftCache::new(8);
    for i in 0..32u64 {
        cache.insert(i, li(i, "nop", vec![]));
    }
    assert!(cache.len() <= 8);
}

#[test]
fn liftcache_clear_resets_entries_not_counters() {
    let cache = LiftCache::new(4);
    cache.insert(1, li(1, "nop", vec![]));
    let _ = cache.get(1);
    let _ = cache.get(999);
    cache.clear();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
    // hits/misses are not necessarily cleared — at least don't panic
    let _ = cache.hits();
    let _ = cache.misses();
}

#[test]
fn liftcache_miss_increments() {
    let cache = LiftCache::new(4);
    assert!(cache.get(42).is_none());
    assert!(cache.misses() >= 1);
    assert_eq!(cache.hit_rate(), 0.0);
}

#[test]
fn liftcache_zero_capacity_does_not_panic() {
    let cache = LiftCache::new(0);
    cache.insert(0, li(0, "nop", vec![]));
    // implementation may or may not store; must not panic
    let _ = cache.get(0);
}

#[test]
fn liftcache_threaded_stress_4x100() {
    let cache = Arc::new(LiftCache::new(256));
    let mut handles = Vec::new();
    for tid in 0..4u64 {
        let c = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            for i in 0..100u64 {
                let a = tid * 1000 + i;
                c.insert(a, li(a, "nop", vec![]));
                let _ = c.get(a);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // Cache must remain bounded.
    assert!(cache.len() <= 256);
}

// ─── LiftContext ──────────────────────────────────────────────────────────

#[test]
fn liftcontext_defaults_and_builders() {
    let c = LiftContext::new("x86_64");
    assert_eq!(c.arch, "x86_64");
    assert_eq!(c.target_level, LiftLevel::Llil);
    assert!(c.use_cache);
    assert!(c.error_recovery);
    assert!(c.allow_partial);
    assert_eq!(c.batch_limit, 10_000);

    let c = LiftContext::new("arm64")
        .with_level(LiftLevel::Hlil)
        .without_cache()
        .without_recovery()
        .strict()
        .with_batch_limit(42);
    assert_eq!(c.target_level, LiftLevel::Hlil);
    assert!(!c.use_cache);
    assert!(!c.error_recovery);
    assert!(!c.allow_partial);
    assert_eq!(c.batch_limit, 42);
}

#[test]
fn liftcontext_record_and_reset_stats() {
    let c = LiftContext::new("x86");
    let mut s = LiftStats::new();
    s.total_instructions = 10;
    s.succeeded = 8;
    c.record_stats(&s);
    c.record_stats(&s);
    let snap = c.stats();
    assert_eq!(snap.total_instructions, 20);
    c.reset_stats();
    assert_eq!(c.stats().total_instructions, 0);
}

#[test]
fn liftcontext_send_sync_threaded_stress() {
    let ctx = Arc::new(LiftContext::new("x86_64"));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let c = Arc::clone(&ctx);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let mut s = LiftStats::new();
                s.total_instructions = 1;
                s.succeeded = 1;
                c.record_stats(&s);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(ctx.stats().total_instructions, 400);
}

// ─── GenericLlilLifter ────────────────────────────────────────────────────

#[test]
fn generic_lifter_arch_and_level() {
    let l = GenericLlilLifter::new("x86_64".into());
    assert_eq!(l.arch_name(), "x86_64");
    assert_eq!(l.lift_level(), LiftLevel::Llil);
    assert!(l.supports_mnemonic("mov"));
}

#[test]
fn generic_lifter_nop_no_effects() {
    let l = GenericLlilLifter::new("x86_64".into());
    let i = ins(0x1000, "nop");
    let r = l.lift(&i).expect("nop lifts");
    assert!(r.effects.is_empty());
    assert_eq!(r.address, 0x1000);
}

#[test]
fn generic_lifter_ret_returns() {
    let l = GenericLlilLifter::new("x86_64".into());
    let i = ins(0x1000, "ret");
    let r = l.lift(&i).expect("ret lifts");
    assert!(r.is_terminator());
    assert!(matches!(r.effects[0], Effect::Return { .. }));
}

#[test]
fn generic_lifter_push_pop_pair_rsp_adjusted() {
    let l = GenericLlilLifter::new("x86_64".into());
    let rax = Operand::Register(reg("rax", 8));
    let push = ins_ops(0x1000, "push", vec![rax.clone()]);
    let pop = ins_ops(0x1001, "pop", vec![rax]);
    let p1 = l.lift(&push).unwrap();
    let p2 = l.lift(&pop).unwrap();
    // push: rsp -= 8, MemWrite
    let has_rsp_sub = p1.effects.iter().any(|e| matches!(e,
        Effect::RegWrite { reg, .. } if reg == "rsp"));
    let has_memw = p1.effects.iter().any(|e| matches!(e, Effect::MemWrite { .. }));
    assert!(has_rsp_sub && has_memw);
    // pop: MemRead, rsp += 8
    let has_memr = p2.effects.iter().any(|e| matches!(e, Effect::MemRead { .. }));
    let has_rsp_add = p2.effects.iter().any(|e| matches!(e,
        Effect::RegWrite { reg, .. } if reg == "rsp"));
    assert!(has_memr && has_rsp_add);
}

#[test]
fn generic_lifter_arithmetic_round_trip() {
    let l = GenericLlilLifter::new("x86_64".into());
    let rax = Operand::Register(reg("rax", 8));
    let imm = Operand::Immediate(1);
    for mnem in ["add", "sub", "and", "or", "xor", "imul"] {
        let i = ins_ops(0x1000, mnem, vec![rax.clone(), imm.clone()]);
        let r = l.lift(&i).expect(mnem);
        assert_eq!(r.effects.len(), 1);
        assert!(matches!(r.effects[0], Effect::RegWrite { .. }));
    }
}

#[test]
fn generic_lifter_jmp_unconditional() {
    let l = GenericLlilLifter::new("x86_64".into());
    let i = ins_ops(0x1000, "jmp", vec![Operand::Label(0x2000)]);
    let r = l.lift(&i).unwrap();
    assert!(matches!(
        &r.effects[0],
        Effect::Branch { condition: None, .. }
    ));
}

#[test]
fn generic_lifter_conditional_branches_all_have_cond() {
    let l = GenericLlilLifter::new("x86_64".into());
    let label = Operand::Label(0x2000);
    for mnem in [
        "je", "jne", "jl", "jg", "jb", "jae", "jbe", "ja", "js", "jns", "jo", "jno", "jp", "jnp",
        "jge", "jle",
    ] {
        let i = ins_ops(0x1000, mnem, vec![label.clone()]);
        let r = l.lift(&i).unwrap_or_else(|_| panic!("{mnem} lift failed"));
        let has_cond = r
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Branch { condition: Some(_), .. }));
        assert!(has_cond, "mnemonic {mnem} should produce conditional branch");
    }
}

#[test]
fn generic_lifter_call_emits_call_effect() {
    let l = GenericLlilLifter::new("x86_64".into());
    let i = ins_ops(0x1000, "call", vec![Operand::Label(0x4000)]);
    let r = l.lift(&i).unwrap();
    assert!(r.effects.iter().any(|e| matches!(e, Effect::Call { .. })));
}

#[test]
fn generic_lifter_syscall_emits_syscall() {
    let l = GenericLlilLifter::new("x86_64".into());
    let i = ins(0x1000, "syscall");
    let r = l.lift(&i).unwrap();
    assert!(r.effects.iter().any(|e| matches!(e, Effect::Syscall { .. })));
    assert!(r.is_terminator());
}

#[test]
fn generic_lifter_fuzz_random_mnemonics_never_panic() {
    let l = GenericLlilLifter::new("x86_64".into());
    let mut g = lcg_seed();
    let mnems = [
        "mov", "add", "sub", "xor", "and", "or", "shl", "shr", "not", "neg", "inc", "dec", "lea",
        "xchg", "push", "pop", "call", "ret", "jmp", "je", "jne", "nop", "syscall", "weird_op",
        "??", "",
    ];
    for _ in 0..100 {
        let mnem = mnems[(g() as usize) % mnems.len()];
        let addr = g();
        let i = ins(addr, mnem);
        // Lift may succeed or fail with structured error; must never panic.
        let _ = l.lift(&i);
    }
}

#[test]
fn generic_lifter_lift_block_default() {
    let l = GenericLlilLifter::new("x86".into());
    let instrs = vec![ins(0, "nop"), ins(1, "ret"), ins(2, "nop")];
    let results = l.lift_block(&instrs);
    assert_eq!(results.len(), 3);
    assert!(results.iter().all(std::result::Result::is_ok));
}

// ─── ErrorRecoveryLifter ──────────────────────────────────────────────────

#[derive(Debug)]
struct AlwaysFailLifter;
impl ArchLifter for AlwaysFailLifter {
    fn arch_name(&self) -> &'static str {
        "fail"
    }
    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }
    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        Err(LiftError::LiftFailed(instr.address.0, "always".into()))
    }
}

#[test]
fn error_recovery_substitutes_intrinsic() {
    let r = ErrorRecoveryLifter::new(Box::new(AlwaysFailLifter));
    let i = ins(0x1234, "bogus");
    let out = r.lift(&i).expect("recovery returns Ok");
    assert_eq!(out.address, 0x1234);
    assert!(matches!(out.effects[0], Effect::Intrinsic { .. }));
}

#[test]
fn error_recovery_inherits_inner_metadata() {
    let r = ErrorRecoveryLifter::new(Box::new(AlwaysFailLifter));
    assert_eq!(r.arch_name(), "fail");
    assert_eq!(r.lift_level(), LiftLevel::Llil);
}

#[test]
fn error_recovery_fuzz_never_returns_err() {
    let r = ErrorRecoveryLifter::new(Box::new(AlwaysFailLifter));
    let mut g = lcg_seed();
    for _ in 0..50 {
        let i = ins(g(), "x");
        assert!(r.lift(&i).is_ok());
    }
}

// ─── Send+Sync threaded lifting stress ───────────────────────────────────

#[test]
fn lifter_send_sync_4x100_concurrent() {
    let l: Arc<dyn ArchLifter> = Arc::new(GenericLlilLifter::new("x86_64".into()));
    let mut handles = Vec::new();
    for tid in 0..4u64 {
        let l = Arc::clone(&l);
        handles.push(thread::spawn(move || {
            let mut ok = 0usize;
            for i in 0..100u64 {
                let inst = ins(tid * 10_000 + i, if i % 2 == 0 { "nop" } else { "ret" });
                if l.lift(&inst).is_ok() {
                    ok += 1;
                }
            }
            ok
        }));
    }
    let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(total, 400);
}
