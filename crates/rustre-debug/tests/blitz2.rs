//! blitz2: deep adversarial tests for rustre-debug.
#![allow(clippy::needless_range_loop)]

use rustre_debug::*;
use rustre_core::address::Address;
use std::sync::Arc;
use std::thread;

const fn lcg_seed() -> u64 { 0xDEAD_BEEF_CAFE_BABE }
const fn lcg_next(s: &mut u64) -> u64 {
    *s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
    *s
}

fn regs_with(pc: u64, sp: u64) -> RegisterSet {
    let mut r = RegisterSet::new();
    r.pc = pc;
    r.sp = sp;
    r.set("rax", 0x10);
    r.set("rbx", 0x20);
    r.set("rcx", 0x30);
    r
}

// ───────── tokenise ─────────

#[test]
fn tokenise_empty() {
    let t = tokenise("").unwrap();
    assert!(t.is_empty());
}

#[test]
fn tokenise_decimal() {
    let t = tokenise("123").unwrap();
    assert_eq!(t, vec![ExprToken::Number(123)]);
}

#[test]
fn tokenise_hex() {
    let t = tokenise("0xDEAD").unwrap();
    assert_eq!(t, vec![ExprToken::Number(0xDEAD)]);
}

#[test]
fn tokenise_octal() {
    let t = tokenise("0755").unwrap();
    assert_eq!(t, vec![ExprToken::Number(0o755)]);
}

#[test]
fn tokenise_ident() {
    let t = tokenise("rax").unwrap();
    assert_eq!(t, vec![ExprToken::Ident("rax".into())]);
}

#[test]
fn tokenise_all_ops() {
    let t = tokenise("+ - * / ( ) [ ] & | ^ ~ << >>").unwrap();
    assert_eq!(t.len(), 14);
}

#[test]
fn tokenise_reject_bad_char() {
    assert!(matches!(tokenise("?"), Err(ExprError::UnexpectedChar('?'))));
}

#[test]
fn tokenise_reject_single_lt() {
    assert!(matches!(tokenise("<"), Err(ExprError::UnexpectedChar('<'))));
}

#[test]
fn tokenise_reject_single_gt() {
    assert!(matches!(tokenise(">"), Err(ExprError::UnexpectedChar('>'))));
}

#[test]
fn tokenise_fuzz_never_panics() {
    let mut s = lcg_seed();
    let charset: &[u8] = b"0123456789abcdef+-*/() []&|^~<>xX_ \t";
    for _ in 0..60 {
        let len = (lcg_next(&mut s) % 32) as usize;
        let mut buf = String::new();
        for _ in 0..len {
            let c = charset[(lcg_next(&mut s) as usize) % charset.len()];
            buf.push(c as char);
        }
        let _ = tokenise(&buf);
    }
}

// ───────── eval_expr ─────────

#[test]
fn eval_simple_add() {
    let r = RegisterSet::new();
    assert_eq!(eval_expr("1 + 2", &r).unwrap(), 3);
}

#[test]
fn eval_precedence() {
    let r = RegisterSet::new();
    assert_eq!(eval_expr("2 + 3 * 4", &r).unwrap(), 14);
}

#[test]
fn eval_paren() {
    let r = RegisterSet::new();
    assert_eq!(eval_expr("(2 + 3) * 4", &r).unwrap(), 20);
}

#[test]
fn eval_register() {
    let r = regs_with(0xFF, 0);
    assert_eq!(eval_expr("rax + rbx", &r).unwrap(), 0x30);
}

#[test]
fn eval_pc_sp_shortcuts() {
    let r = regs_with(0xABCD, 0x1234);
    assert_eq!(eval_expr("pc", &r).unwrap(), 0xABCD);
    assert_eq!(eval_expr("sp", &r).unwrap(), 0x1234);
}

#[test]
fn eval_div_by_zero() {
    let r = RegisterSet::new();
    assert!(matches!(eval_expr("1 / 0", &r), Err(ExprError::DivisionByZero)));
}

#[test]
fn eval_unknown_ident() {
    let r = RegisterSet::new();
    assert!(matches!(eval_expr("foobar", &r), Err(ExprError::UnknownIdent(_))));
}

#[test]
fn eval_shifts() {
    let r = RegisterSet::new();
    assert_eq!(eval_expr("1 << 4", &r).unwrap(), 16);
    assert_eq!(eval_expr("256 >> 2", &r).unwrap(), 64);
}

#[test]
fn eval_bitwise() {
    let r = RegisterSet::new();
    assert_eq!(eval_expr("0xF0 | 0x0F", &r).unwrap(), 0xFF);
    assert_eq!(eval_expr("0xFF & 0x0F", &r).unwrap(), 0x0F);
    assert_eq!(eval_expr("0xFF ^ 0x0F", &r).unwrap(), 0xF0);
    assert_eq!(eval_expr("~0", &r).unwrap(), u64::MAX);
}

#[test]
fn eval_unary_minus_wrapping() {
    let r = RegisterSet::new();
    assert_eq!(eval_expr("-1", &r).unwrap(), u64::MAX);
}

#[test]
fn eval_trailing_tokens_err() {
    let r = RegisterSet::new();
    assert!(eval_expr("1 2", &r).is_err());
}

#[test]
fn eval_unmatched_paren_err() {
    let r = RegisterSet::new();
    assert!(eval_expr("(1 + 2", &r).is_err());
}

#[test]
fn eval_fuzz_no_panic() {
    let mut s = lcg_seed();
    let r = regs_with(0, 0);
    let charset: &[u8] = b"0123456789+-*/() &|^~<>";
    for _ in 0..80 {
        let len = (lcg_next(&mut s) % 24) as usize;
        let mut buf = String::new();
        for _ in 0..len {
            let c = charset[(lcg_next(&mut s) as usize) % charset.len()];
            buf.push(c as char);
        }
        let _ = eval_expr(&buf, &r);
    }
}

// ───────── ExprEvaluator with memory ─────────

#[test]
fn eval_memory_deref() {
    let r = RegisterSet::new();
    let data: Vec<u8> = (0u64..8).map(|i| i as u8).collect();
    let val_expected: u64 = u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]);
    let reader = |_addr: u64, sz: usize| -> Result<Vec<u8>, String> { Ok(data[..sz].to_vec()) };
    let mut ev = ExprEvaluator::new("[0x1000]", &r).unwrap().with_mem_reader(&reader);
    assert_eq!(ev.evaluate().unwrap(), val_expected);
}

#[test]
fn eval_memory_no_reader_errs() {
    let r = RegisterSet::new();
    let mut ev = ExprEvaluator::new("[0x1000]", &r).unwrap();
    assert!(matches!(ev.evaluate(), Err(ExprError::MemoryRead(_, _))));
}

// ───────── RegisterSet ─────────

#[test]
fn register_set_get_set() {
    let mut r = RegisterSet::new();
    r.set("eax", 42);
    assert_eq!(r.get("eax"), Some(42));
    assert_eq!(r.get("nope"), None);
}

#[test]
fn register_set_all_names_sorted() {
    let mut r = RegisterSet::new();
    for n in &["zzz", "aaa", "mmm"] { r.set(n, 0); }
    let names = r.all_names();
    assert_eq!(names, vec!["aaa", "mmm", "zzz"]);
}

// ───────── AdvancedBreakpoint / Registry ─────────

#[test]
fn advbp_should_fire_when_disabled() {
    let mut bp = AdvancedBreakpoint::new_stop(0, 0x1000);
    bp.enabled = false;
    assert!(!bp.should_fire(&RegisterSet::new()));
}

#[test]
fn advbp_ignore_count() {
    // Documented semantics: record_hit increments first, then checks hit_count < ignore_count.
    let mut bp = AdvancedBreakpoint::new_stop(0, 0x1000).with_ignore_count(2);
    let r = RegisterSet::new();
    assert!(!bp.record_hit(&r)); // 1<2 → skip
    assert!(bp.record_hit(&r));  // 2<2 false → fires
    assert!(bp.record_hit(&r));
}

#[test]
fn advbp_condition_zero_no_fire() {
    let bp = AdvancedBreakpoint::new_stop(0, 0x1000).with_condition("0");
    assert!(!bp.should_fire(&RegisterSet::new()));
}

#[test]
fn advbp_condition_nonzero_fires() {
    let bp = AdvancedBreakpoint::new_stop(0, 0x1000).with_condition("1");
    assert!(bp.should_fire(&RegisterSet::new()));
}

#[test]
fn advbp_condition_err_no_fire() {
    let bp = AdvancedBreakpoint::new_stop(0, 0x1000).with_condition("unknown_reg");
    assert!(!bp.should_fire(&RegisterSet::new()));
}

#[test]
fn bp_registry_add_remove_lookup() {
    let mut reg = BreakpointRegistry::new();
    assert!(reg.is_empty());
    let id0 = reg.add_stop(0x1000);
    let id1 = reg.add_stop(0x2000);
    assert_eq!(reg.len(), 2);
    assert!(id0 != id1);
    assert!(reg.get(id0).is_some());
    assert!(reg.remove(id0));
    assert!(!reg.remove(id0));
    assert_eq!(reg.len(), 1);
}

#[test]
fn bp_registry_at_address() {
    let mut reg = BreakpointRegistry::new();
    reg.add_stop(0x1000);
    reg.add_stop(0x1000);
    reg.add_stop(0x2000);
    assert_eq!(reg.at_address(0x1000).len(), 2);
    assert_eq!(reg.at_address(0x2000).len(), 1);
    assert_eq!(reg.at_address(0x3000).len(), 0);
}

#[test]
fn bp_registry_enable_disable() {
    let mut reg = BreakpointRegistry::new();
    let id = reg.add_stop(0x1000);
    assert!(reg.disable(id));
    assert!(!reg.get(id).unwrap().enabled);
    assert!(reg.enable(id));
    assert!(reg.get(id).unwrap().enabled);
    assert!(!reg.disable(999));
}

#[test]
fn bp_registry_json_roundtrip_for_logs() {
    let mut reg = BreakpointRegistry::new();
    reg.add_log(0x1000, "pc");
    let json = reg.to_json().unwrap();
    assert!(json.contains("0x1000") || json.contains("4096"));
}

// ───────── Watchpoint ─────────

#[test]
fn watchpoint_change_fires_on_first() {
    let w = Watchpoint::new(0, 0x1000, 4, WatchpointKind::Change);
    assert!(w.should_fire_on_value(&[1, 2, 3, 4]));
}

#[test]
fn watchpoint_change_skips_same() {
    let mut w = Watchpoint::new(0, 0x1000, 4, WatchpointKind::Change);
    w.record_hit(vec![1, 2, 3, 4]);
    assert!(!w.should_fire_on_value(&[1, 2, 3, 4]));
    assert!(w.should_fire_on_value(&[1, 2, 3, 5]));
}

#[test]
fn watchpoint_disabled_no_fire() {
    let mut w = Watchpoint::new(0, 0x1000, 4, WatchpointKind::Write);
    w.enabled = false;
    assert!(!w.should_fire_on_value(&[0]));
}

#[test]
fn watchpoint_kind_display() {
    assert_eq!(format!("{}", WatchpointKind::Read), "read");
    assert_eq!(format!("{}", WatchpointKind::Write), "write");
    assert_eq!(format!("{}", WatchpointKind::ReadWrite), "read/write");
    assert_eq!(format!("{}", WatchpointKind::Change), "change");
}

#[test]
fn watchpoint_registry_overlap() {
    let mut r = WatchpointRegistry::new();
    r.add(0x1000, 8, WatchpointKind::Write);
    r.add(0x2000, 8, WatchpointKind::Read);
    assert_eq!(r.covering(0x1004, 1).len(), 1);
    // [0x1FFC,0x200C) overlaps only with [0x2000,0x2008), not [0x1000,0x1008)
    assert_eq!(r.covering(0x1FFC, 16).len(), 1);
    // Span both
    assert_eq!(r.covering(0x1000, 0x1010).len(), 2);
    assert_eq!(r.covering(0x3000, 16).len(), 0);
}

#[test]
fn watchpoint_registry_remove() {
    let mut r = WatchpointRegistry::new();
    let id = r.add(0x1000, 4, WatchpointKind::Write);
    assert!(r.remove(id));
    assert!(!r.remove(id));
    assert!(r.is_empty());
}

// ───────── Memory search ─────────

#[test]
fn search_literal_basic() {
    let hay = b"abcabcabc";
    assert_eq!(search_bytes_literal(hay, b"abc"), vec![0, 3, 6]);
}

#[test]
fn search_literal_empty_needle() {
    assert!(search_bytes_literal(b"abc", b"").is_empty());
}

#[test]
fn search_literal_needle_too_long() {
    assert!(search_bytes_literal(b"ab", b"abc").is_empty());
}

#[test]
fn search_masked_wildcards() {
    let hay = b"\x01\x02\x03\x01\xFF\x03";
    let pat = b"\x01\x00\x03";
    let mask = b"\x00\xFF\x00";
    let res = search_bytes_masked(hay, pat, mask);
    assert_eq!(res, vec![0, 3]);
}

#[test]
fn search_int_le_vs_be() {
    let v: u32 = 0x1122_3344;
    let mut hay = Vec::new();
    hay.extend_from_slice(&v.to_le_bytes());
    hay.extend_from_slice(&v.to_be_bytes());
    assert_eq!(search_int(&hay, u64::from(v), IntWidth::U32Le), vec![0]);
    assert_eq!(search_int(&hay, u64::from(v), IntWidth::U32Be), vec![4]);
}

#[test]
fn search_int_widths() {
    let hay: Vec<u8> = vec![0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05];
    assert_eq!(search_int(&hay, 0xAB, IntWidth::U8), vec![0]);
    let u16le: u16 = u16::from_le_bytes([0xAB, 0xCD]);
    assert_eq!(search_int(&hay, u64::from(u16le), IntWidth::U16Le), vec![0]);
}

#[test]
fn search_fuzz_no_panic() {
    let mut s = lcg_seed();
    for _ in 0..50 {
        let hlen = (lcg_next(&mut s) % 64) as usize;
        let nlen = (lcg_next(&mut s) % 8) as usize;
        let hay: Vec<u8> = (0..hlen).map(|_| lcg_next(&mut s) as u8).collect();
        let nee: Vec<u8> = (0..nlen).map(|_| lcg_next(&mut s) as u8).collect();
        let _ = search_bytes_literal(&hay, &nee);
    }
}

// ───────── SessionState transitions ─────────

#[test]
fn session_state_valid_transitions() {
    use SessionState::*;
    assert!(Idle.transition(Stopped).is_ok());
    assert!(Stopped.transition(Running).is_ok());
    assert!(Stopped.transition(Stepping).is_ok());
    assert!(Stopped.transition(Detaching).is_ok());
    assert!(Stopped.transition(Terminated).is_ok());
    assert!(Running.transition(Stopped).is_ok());
    assert!(Running.transition(Terminated).is_ok());
    assert!(Stepping.transition(Stopped).is_ok());
    assert!(Detaching.transition(Idle).is_ok());
}

#[test]
fn session_state_invalid_transitions() {
    use SessionState::*;
    assert!(Idle.transition(Running).is_err());
    assert!(Idle.transition(Stepping).is_err());
    assert!(Running.transition(Stepping).is_err());
    assert!(Terminated.transition(Stopped).is_err());
    assert!(Stepping.transition(Running).is_err());
}

#[test]
fn session_state_predicates() {
    use SessionState::*;
    assert!(Stopped.can_command());
    assert!(Stepping.can_command());
    assert!(!Running.can_command());
    assert!(!Idle.is_live());
    assert!(!Terminated.is_live());
    assert!(Running.is_live());
}

#[test]
fn session_state_display() {
    assert_eq!(format!("{}", SessionState::Idle), "idle");
    assert_eq!(format!("{}", SessionState::Stopped), "stopped");
}

// ───────── MemoryPermissions ─────────

#[test]
fn memperm_roundtrip_unix_str() {
    let cases = ["rwx", "r-x", "rw-", "r--", "---"];
    for s in cases {
        let p = MemoryPermissions::from_unix_str(s);
        assert_eq!(p.to_unix_str(), s);
    }
}

#[test]
fn memperm_constants() {
    assert!(MemoryPermissions::read_only().is_readable());
    assert!(!MemoryPermissions::read_only().is_writable());
    assert!(MemoryPermissions::all().is_executable());
    assert_eq!(MemoryPermissions::none().to_unix_str(), "---");
}

// ───────── MemoryRegionInfo / RegionMap ─────────

#[test]
fn region_map_basic() {
    let mut m = RegionMap::new();
    m.add(MemoryRegionInfo::new(0x2000, 0x1000, MemoryPermissions::read_exec()));
    m.add(MemoryRegionInfo::new(0x1000, 0x1000, MemoryPermissions::read_write()));
    assert_eq!(m.len(), 2);
    assert_eq!(m.all()[0].base, 0x1000); // sorted
    assert_eq!(m.find(0x1500).len(), 1);
    assert_eq!(m.find(0x9999).len(), 0);
    assert_eq!(m.executable_regions().len(), 1);
    assert_eq!(m.writable_regions().len(), 1);
    assert_eq!(m.total_size(), 0x2000);
}

#[test]
fn region_contains_boundaries() {
    let r = MemoryRegionInfo::new(0x1000, 0x100, MemoryPermissions::all());
    assert!(r.contains(0x1000));
    assert!(r.contains(0x10FF));
    assert!(!r.contains(0x1100));
    assert!(!r.contains(0x0FFF));
}

// ───────── ConditionExpr ─────────

#[test]
fn condition_expr_basic_ops() {
    let mut r = RegisterSet::new();
    r.set("rax", 5);
    assert!(ConditionExpr::RegEq { reg: "rax".into(), value: 5 }.evaluate(&r));
    assert!(ConditionExpr::RegNe { reg: "rax".into(), value: 4 }.evaluate(&r));
    assert!(ConditionExpr::RegGt { reg: "rax".into(), value: 4 }.evaluate(&r));
    assert!(ConditionExpr::RegLt { reg: "rax".into(), value: 6 }.evaluate(&r));
    assert!(!ConditionExpr::RegEq { reg: "missing".into(), value: 0 }.evaluate(&r));
}

#[test]
fn condition_expr_compound() {
    let mut r = RegisterSet::new();
    r.set("a", 1);
    let e = ConditionExpr::And(
        Box::new(ConditionExpr::True),
        Box::new(ConditionExpr::RegEq { reg: "a".into(), value: 1 }),
    );
    assert!(e.evaluate(&r));
    let e2 = ConditionExpr::Or(Box::new(ConditionExpr::False), Box::new(ConditionExpr::True));
    assert!(e2.evaluate(&r));
    let e3 = ConditionExpr::Not(Box::new(ConditionExpr::True));
    assert!(!e3.evaluate(&r));
}

// ───────── Symbol / SymbolTable ─────────

#[test]
fn symbol_contains_zero_size() {
    let s = Symbol::new("main", 0x1000);
    assert!(s.contains(0x1000));
    assert!(!s.contains(0x1001));
}

#[test]
fn symbol_contains_sized() {
    let mut s = Symbol::new("foo", 0x1000);
    s.size = 0x100;
    assert!(s.contains(0x1000));
    assert!(s.contains(0x10FF));
    assert!(!s.contains(0x1100));
}

#[test]
fn symbol_table_lookup_and_search() {
    let mut t = SymbolTable::new();
    let mut s = Symbol::new("MyFunc", 0x1000);
    s.size = 0x20;
    t.add(s);
    t.add(Symbol::new("Other", 0x2000));
    assert_eq!(t.len(), 2);
    assert!(t.by_name("MyFunc").is_some());
    assert!(t.by_name("nope").is_none());
    assert_eq!(t.resolve(0x1010).map(|s| s.name.as_str()), Some("MyFunc"));
    assert_eq!(t.search("func").len(), 1); // case-insensitive
}

// ───────── DisasmListing render/at ─────────

#[test]
fn disasm_at_and_render() {
    let mut l = DisasmListing::new();
    l.lines.push(DisasmLine {
        address: 0x1000,
        bytes: vec![0x90],
        mnemonic: "nop".into(),
        operands: String::new(),
        category: InsnCategory::Other,
        has_breakpoint: false,
        is_current_pc: false,
        symbol: None,
    });
    assert!(l.at(0x1000).is_some());
    assert!(l.at(0x2000).is_none());
    let out = l.render(0x1000, &[0x1000]);
    assert!(out.contains("→"));
    assert!(out.contains("●"));
}

#[test]
fn disasm_line_display() {
    let mut dl = DisasmLine {
        address: 0,
        bytes: vec![0x90],
        mnemonic: "nop".into(),
        operands: String::new(),
        category: InsnCategory::Other,
        has_breakpoint: false,
        is_current_pc: false,
        symbol: None,
    };
    assert_eq!(dl.display(), "nop");
    dl.operands = "rax".into();
    assert!(dl.display().contains("rax"));
}

// ───────── SourceFile ─────────

#[test]
fn source_file_line_snippet() {
    let mut sf = SourceFile::new("/tmp/x.rs");
    sf.lines = vec!["a".into(), "b".into(), "c".into(), "d".into()];
    assert_eq!(sf.line(1), Some("a"));
    assert_eq!(sf.line(4), Some("d"));
    assert_eq!(sf.line(5), None);
    assert_eq!(sf.line(0), Some("a")); // saturating_sub
    let snip = sf.snippet(2, 3);
    assert_eq!(snip, vec![(2, "b"), (3, "c")]);
    assert_eq!(sf.line_count(), 4);
}

// ───────── SourceBreakpoint ─────────

#[test]
fn source_bp_resolve() {
    let mut bp = SourceBreakpoint::new(7, "/tmp/x.rs", 10);
    assert!(!bp.resolved);
    bp.resolve(0xABCD);
    assert!(bp.resolved);
    assert_eq!(bp.address, Some(0xABCD));
}

// ───────── DebugEventFilter ─────────

#[test]
fn event_filter_pass_all() {
    let f = DebugEventFilter::pass_all();
    let ev = DebugEvent::new(
        ProcessId(1), ThreadId(2),
        StopReason::SingleStep { address: Address::new(0x1000) },
    );
    assert!(f.accepts(&ev));
}

#[test]
fn event_filter_pid_filter() {
    let f = DebugEventFilter::for_pid(42);
    let ev = DebugEvent::new(
        ProcessId(1), ThreadId(2),
        StopReason::SingleStep { address: Address::new(0x1000) },
    );
    assert!(!f.accepts(&ev));
    let ev2 = DebugEvent::new(
        ProcessId(42), ThreadId(2),
        StopReason::SingleStep { address: Address::new(0x1000) },
    );
    assert!(f.accepts(&ev2));
}

#[test]
fn event_filter_breakpoints_only() {
    let mut f = DebugEventFilter::pass_all();
    f.pass_all = false;
    f.breakpoints_only = true;
    let bp = Breakpoint::new_software(Address::new(0x1000));
    let ev_bp = DebugEvent::new(
        ProcessId(1), ThreadId(2),
        StopReason::Breakpoint { address: Address::new(0x1000), bp },
    );
    assert!(f.accepts(&ev_bp));
    let ev_ss = DebugEvent::new(
        ProcessId(1), ThreadId(2),
        StopReason::SingleStep { address: Address::new(0x1000) },
    );
    assert!(!f.accepts(&ev_ss));
}

// ───────── ProcessId / ThreadId ordering & display ─────────

#[test]
fn pid_tid_display_and_hash() {
    assert_eq!(format!("{}", ProcessId(7)), "PID(7)");
    assert_eq!(format!("{}", ThreadId(3)), "TID(3)");
    use std::collections::HashSet;
    let mut s: HashSet<ProcessId> = HashSet::new();
    for i in 0..30u32 {
        s.insert(ProcessId(i));
    }
    assert_eq!(s.len(), 30);
}

#[test]
fn pid_ord() {
    assert!(ProcessId(1) < ProcessId(2));
    assert!(ThreadId(5) > ThreadId(4));
}

// ───────── EventDispatcher Send+Sync threaded stress ─────────

#[test]
fn event_dispatcher_threaded_stress() {
    let disp = Arc::new(EventDispatcher::new());
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c2 = counter.clone();
    disp.subscribe(Box::new(move |_ev| {
        c2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let d = disp.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let ev = DebugEvent::new(
                    ProcessId(1), ThreadId(2),
                    StopReason::SingleStep { address: Address::new(0x1000) },
                );
                d.dispatch(&ev);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 400);
}

#[test]
fn event_dispatcher_subscriber_count() {
    let d = EventDispatcher::new();
    assert_eq!(d.subscriber_count(), 0);
    d.subscribe(Box::new(|_| {}));
    d.subscribe(Box::new(|_| {}));
    assert_eq!(d.subscriber_count(), 2);
}

// ───────── DebugSnapshot JSON roundtrip ─────────

#[test]
fn debug_snapshot_roundtrip() {
    let mut snap = DebugSnapshot::new(42, "manual");
    snap.add_module(SnapshotModule { name: "main".into(), base: 0x1000, size: 0x100 });
    snap.add_memory_region(SnapshotMemoryRegion {
        base: 0x2000, data: vec![1, 2, 3, 4], flags: "rx".into(),
    });
    let json = snap.to_json().unwrap();
    let back = DebugSnapshot::from_json(&json).unwrap();
    assert_eq!(back.pid, 42);
    assert_eq!(back.modules.len(), 1);
    assert_eq!(back.total_memory_bytes(), 4);
}

#[test]
fn debug_snapshot_thread_lookup() {
    let mut snap = DebugSnapshot::new(1, "x");
    snap.add_thread(ThreadSnapshot {
        tid: 7, registers: Default::default(),
        pc: 0, sp: 0, fp: None, frames: vec![],
    });
    assert!(snap.thread(7).is_some());
    assert!(snap.thread(8).is_none());
}

// ───────── FramePointerUnwinder ─────────

#[test]
fn fp_unwinder_terminates_on_zero_fp() {
    let mut regs = RegisterSet::new();
    regs.pc = 0x4000;
    regs.sp = 0x7000;
    regs.fp = Some(0);
    let frames = FramePointerUnwinder.unwind(&regs, &[]).unwrap();
    assert_eq!(frames.len(), 1);
}

#[test]
fn fp_unwinder_one_frame() {
    // build a synthetic stack: at fp 0x8000 → saved_fp=0, ret=0x4100
    let mut data = vec![0u8; 32];
    data[0..8].copy_from_slice(&0u64.to_le_bytes());          // saved fp
    data[8..16].copy_from_slice(&0x4100u64.to_le_bytes());    // ret
    let mem = vec![(0x8000u64, data)];
    let mut regs = RegisterSet::new();
    regs.pc = 0x4000;
    regs.sp = 0x7000;
    regs.fp = Some(0x8000);
    let frames = FramePointerUnwinder.unwind(&regs, &mem).unwrap();
    assert!(frames.len() >= 2);
    assert_eq!(frames[1].pc.as_u64(), 0x4100);
}

#[test]
fn unwind_strategy_display() {
    assert_eq!(format!("{}", UnwindStrategy::Dwarf), "dwarf");
    assert_eq!(format!("{}", UnwindStrategy::Auto), "auto");
}

// ───────── StopReason Display ─────────

#[test]
fn stop_reason_display_variants() {
    let s = format!("{}", StopReason::SingleStep { address: Address::new(0x1234) });
    assert!(s.contains("single step"));
    let s = format!("{}", StopReason::ProcessExit { exit_code: 0 });
    assert!(s.to_lowercase().contains("exit"));
}

// ───────── MemoryMatch eq ─────────

#[test]
fn memory_match_equality() {
    let m1 = MemoryMatch { address: 1, bytes: vec![1, 2] };
    let m2 = MemoryMatch { address: 1, bytes: vec![1, 2] };
    let m3 = MemoryMatch { address: 2, bytes: vec![1, 2] };
    assert_eq!(m1, m2);
    assert_ne!(m1, m3);
}

// ───────── Boundary fuzz over BreakpointRegistry ─────────

#[test]
fn bp_registry_seeded_ops() {
    let mut s = lcg_seed();
    let mut reg = BreakpointRegistry::new();
    let mut ids = Vec::new();
    for _ in 0..60 {
        let op = lcg_next(&mut s) % 4;
        match op {
            0 => { let id = reg.add_stop(lcg_next(&mut s)); ids.push(id); }
            1 => {
                if !ids.is_empty() {
                    let idx = (lcg_next(&mut s) as usize) % ids.len();
                    let id = ids.remove(idx);
                    assert!(reg.remove(id));
                }
            }
            2 => {
                if !ids.is_empty() {
                    let id = ids[(lcg_next(&mut s) as usize) % ids.len()];
                    reg.disable(id);
                }
            }
            _ => {
                if !ids.is_empty() {
                    let id = ids[(lcg_next(&mut s) as usize) % ids.len()];
                    reg.enable(id);
                }
            }
        }
    }
    // sanity: lengths line up
    assert_eq!(reg.len(), ids.len());
}
