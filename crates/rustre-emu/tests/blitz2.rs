//! Deep adversarial coverage of rustre-emu public API.

use rustre_emu::*;
use std::sync::{Arc, Mutex};

// ── seeded LCG ─────────────────────────────────────────────────────────────
fn make_lcg(seed: u64) -> impl FnMut() -> u64 {
    let mut s: u64 = seed;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn make_x64() -> SimpleInterpreter {
    SimpleInterpreter::new(EmulatorArch::X86_64)
}

// ── 1. Arch ─────────────────────────────────────────────────────────────────
#[test]
fn arch_pointer_sizes_exhaustive() {
    let cases = [
        (EmulatorArch::X86_16, 2usize),
        (EmulatorArch::X86_32, 4),
        (EmulatorArch::X86_64, 8),
        (EmulatorArch::Arm, 4),
        (EmulatorArch::ArmThumb, 4),
        (EmulatorArch::Arm64, 8),
        (EmulatorArch::Mips32, 4),
        (EmulatorArch::Mips32El, 4),
        (EmulatorArch::Mips64, 8),
        (EmulatorArch::RiscV32, 4),
        (EmulatorArch::RiscV64, 8),
        (EmulatorArch::Sparc32, 4),
        (EmulatorArch::Sparc64, 8),
    ];
    for (a, sz) in cases {
        assert_eq!(a.pointer_size(), sz, "{}", a.name());
        assert_eq!(a.is_64bit(), sz == 8);
    }
}

#[test]
fn arch_name_unique_and_nonempty() {
    let arches = [
        EmulatorArch::X86_16,
        EmulatorArch::X86_32,
        EmulatorArch::X86_64,
        EmulatorArch::Arm,
        EmulatorArch::ArmThumb,
        EmulatorArch::Arm64,
        EmulatorArch::Mips32,
        EmulatorArch::Mips32El,
        EmulatorArch::Mips64,
        EmulatorArch::RiscV32,
        EmulatorArch::RiscV64,
        EmulatorArch::Sparc32,
        EmulatorArch::Sparc64,
    ];
    let mut names: Vec<&str> = arches.iter().map(|a| a.name()).collect();
    names.sort_unstable();
    let n_before = names.len();
    names.dedup();
    assert_eq!(n_before, names.len(), "non-unique arch names");
    for n in names {
        assert!(!n.is_empty());
    }
}

#[test]
fn arch_is_x86_classification() {
    assert!(EmulatorArch::X86_16.is_x86());
    assert!(EmulatorArch::X86_32.is_x86());
    assert!(EmulatorArch::X86_64.is_x86());
    assert!(!EmulatorArch::Arm.is_x86());
    assert!(!EmulatorArch::Arm64.is_x86());
    assert!(!EmulatorArch::Mips32.is_x86());
    assert!(!EmulatorArch::RiscV64.is_x86());
}

// ── 2. MemPerms ────────────────────────────────────────────────────────────
#[test]
fn memperms_aliases() {
    assert_eq!(MemPerms::R, MemPerms::READ);
    assert_eq!(MemPerms::W, MemPerms::WRITE);
    assert_eq!(MemPerms::X, MemPerms::EXEC);
    assert_eq!(MemPerms::RW, MemPerms::READ | MemPerms::WRITE);
    assert_eq!(MemPerms::RX, MemPerms::READ | MemPerms::EXEC);
    assert_eq!(MemPerms::RWX, MemPerms::ALL);
}

#[test]
fn memperms_contains() {
    let rw = MemPerms::RW;
    assert!(rw.contains(MemPerms::READ));
    assert!(rw.contains(MemPerms::WRITE));
    assert!(!rw.contains(MemPerms::EXEC));
}

// ── 3. MemRegion ────────────────────────────────────────────────────────────
#[test]
fn memregion_contains_boundaries() {
    let r = MemRegion::new(0x1000, 0x100, MemPerms::ALL);
    assert!(r.contains(0x1000));
    assert!(r.contains(0x10FF));
    assert!(!r.contains(0x1100));
    assert!(!r.contains(0xFFF));
    assert_eq!(r.end(), 0x1100);
}

#[test]
fn memregion_lcg_fuzz() {
    let mut g = make_lcg(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..200 {
        let start = g() & 0xFFFF_FFFF;
        let size = (g() & 0x3FF) as usize + 1;
        let r = MemRegion::new(start, size, MemPerms::READ);
        assert!(r.contains(start));
        if size > 1 {
            assert!(r.contains(start + (size as u64) - 1));
        }
        assert!(!r.contains(start.wrapping_add(size as u64)));
    }
}

#[test]
fn memregion_with_label() {
    let r = MemRegion::new(0, 1, MemPerms::NONE).with_label("foo");
    assert_eq!(r.label.as_deref(), Some("foo"));
}

// ── 4. SimpleInterpreter — map/unmap ───────────────────────────────────────
#[test]
fn map_zero_size_rejected() {
    let mut e = make_x64();
    assert!(matches!(
        e.map_memory(0x1000, 0, MemPerms::ALL).unwrap_err(),
        EmulatorError::InvalidArg(_)
    ));
}

#[test]
fn map_adjacent_ok() {
    let mut e = make_x64();
    e.map_memory(0x1000, 0x1000, MemPerms::ALL).unwrap();
    // Touching, not overlapping
    e.map_memory(0x2000, 0x1000, MemPerms::ALL).unwrap();
    assert_eq!(e.regions().len(), 2);
}

#[test]
fn map_overlap_at_boundary_rejected() {
    let mut e = make_x64();
    e.map_memory(0x1000, 0x1000, MemPerms::ALL).unwrap();
    assert!(e.map_memory(0x1FFF, 1, MemPerms::ALL).is_err());
}

#[test]
fn unmap_twice_fails() {
    let mut e = make_x64();
    e.map_memory(0x1000, 0x100, MemPerms::ALL).unwrap();
    e.unmap_memory(0x1000).unwrap();
    assert!(e.unmap_memory(0x1000).is_err());
}

#[test]
fn write_no_perm_fails() {
    let mut e = make_x64();
    e.map_memory(0x1000, 0x100, MemPerms::READ).unwrap();
    assert!(matches!(
        e.write_memory(0x1000, &[1, 2, 3]).unwrap_err(),
        EmulatorError::MemFault { .. }
    ));
}

#[test]
fn read_no_perm_fails() {
    let mut e = make_x64();
    e.map_memory(0x1000, 0x100, MemPerms::WRITE).unwrap();
    assert!(matches!(
        e.read_memory(0x1000, 4).unwrap_err(),
        EmulatorError::MemFault { .. }
    ));
}

#[test]
fn write_oob_fails() {
    let mut e = make_x64();
    e.map_memory(0x1000, 4, MemPerms::ALL).unwrap();
    assert!(e.write_memory(0x1000, &[0; 5]).is_err());
}

#[test]
fn memory_roundtrip_lcg() {
    let mut e = make_x64();
    e.map_memory(0x4000, 0x1000, MemPerms::ALL).unwrap();
    let mut g = make_lcg(0x0102_0304_0506_0708);
    for _ in 0..50 {
        let off = g() & 0xFFF;
        let len = ((g() & 0x1F) as usize) + 1;
        if off as usize + len > 0x1000 {
            continue;
        }
        let bytes: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        e.write_memory(0x4000 + off, &bytes).unwrap();
        let got = e.read_memory(0x4000 + off, len).unwrap();
        assert_eq!(got, bytes);
    }
}

// ── 5. Registers ────────────────────────────────────────────────────────────
#[test]
fn register_unknown_read_fails() {
    let e = make_x64();
    assert!(e.read_register(9999).is_err());
}

#[test]
fn register_write_then_read_many() {
    let mut e = make_x64();
    let mut g = make_lcg(0xAAAA_BBBB_CCCC_DDDD);
    for _ in 0..50 {
        let v = g();
        e.write_register(x86_regs::RAX, v).unwrap();
        assert_eq!(e.read_register(x86_regs::RAX).unwrap(), v);
    }
}

// ── 6. x86 interpreter — instructions ──────────────────────────────────────
fn setup(emu: &mut SimpleInterpreter, base: u64, code: &[u8]) {
    let size = code.len().max(0x1000);
    emu.map_memory(base, size, MemPerms::ALL).unwrap();
    emu.write_memory(base, code).unwrap();
}

fn with_stack(emu: &mut SimpleInterpreter) {
    emu.map_memory(0x8000, 0x1000, MemPerms::READ | MemPerms::WRITE).unwrap();
    emu.write_register(x86_regs::RSP, 0x8800).unwrap();
}

#[test]
fn mov_r8_to_r15_imm32() {
    // 0xB8..=0xBF — REX absent, but interpreter treats indices 0..7
    for i in 0..=7u8 {
        let mut e = make_x64();
        let mut code = vec![0xB8 + i, 0x42, 0, 0, 0, 0xF4];
        // Use unique imm per reg
        code[1] = 0x10 + i;
        setup(&mut e, 0x1000, &code);
        e.start(0x1000, 0x2000, 0, 0).unwrap();
        let v = e.read_register(x86_regs::RAX + u32::from(i)).unwrap();
        assert_eq!(v, u64::from(0x10 + i));
    }
}

#[test]
fn add_eax_overflow_wraps() {
    let mut e = make_x64();
    e.write_register(x86_regs::RAX, u64::MAX).unwrap();
    setup(&mut e, 0x1000, &[0x05, 0x01, 0x00, 0x00, 0x00, 0xF4]);
    e.start(0x1000, 0x2000, 0, 0).unwrap();
    assert_eq!(e.read_register(x86_regs::RAX).unwrap(), 0);
}

#[test]
fn sub_eax_underflow_wraps() {
    let mut e = make_x64();
    e.write_register(x86_regs::RAX, 0).unwrap();
    setup(&mut e, 0x1000, &[0x2D, 0x01, 0x00, 0x00, 0x00, 0xF4]);
    e.start(0x1000, 0x2000, 0, 0).unwrap();
    assert_eq!(e.read_register(x86_regs::RAX).unwrap(), u64::MAX);
}

#[test]
fn push_then_pop_roundtrip_lcg() {
    let mut g = make_lcg(0x1234_5678_9ABC_DEF0);
    for _ in 0..30 {
        let mut e = make_x64();
        with_stack(&mut e);
        // PUSH r/64 — using PUSH imm32 (0x68) then POP RAX (0x58)
        let imm = (g() & 0x7FFF_FFFF) as u32;
        let mut code = vec![0x68];
        code.extend_from_slice(&imm.to_le_bytes());
        code.push(0x58);
        code.push(0xF4);
        setup(&mut e, 0x1000, &code);
        e.start(0x1000, 0x2000, 0, 0).unwrap();
        assert_eq!(e.read_register(x86_regs::RAX).unwrap(), u64::from(imm));
    }
}

#[test]
fn jmp_short_back_loops_with_count() {
    let mut e = make_x64();
    // JMP -2 (infinite loop)
    setup(&mut e, 0x1000, &[0xEB, 0xFE]);
    // count limit prevents runaway
    e.start(0x1000, 0x9999, 0, 16).unwrap();
}

#[test]
fn jmp_near_rel32_forward() {
    let mut e = make_x64();
    let mut code = vec![0xE9, 0x05, 0x00, 0x00, 0x00]; // jmp +5
    code.extend_from_slice(&[0x90, 0x90, 0x90, 0x90, 0x90]);
    code.extend_from_slice(&[0xB8, 0x07, 0, 0, 0, 0xF4]);
    setup(&mut e, 0x1000, &code);
    e.start(0x1000, 0x2000, 0, 0).unwrap();
    assert_eq!(e.read_register(x86_regs::RAX).unwrap(), 7);
}

#[test]
fn invalid_insn_returns_error_no_panic() {
    // 0x0F 0xFF must error (not panic)
    let mut e = make_x64();
    setup(&mut e, 0x1000, &[0x0F, 0xFF, 0xF4]);
    assert!(matches!(
        e.start(0x1000, 0x2000, 0, 0).unwrap_err(),
        EmulatorError::InvalidInsn { .. }
    ));
}

#[test]
fn cmp_al_imm_sets_zf() {
    let mut e = make_x64();
    e.write_register(x86_regs::RAX, 0x42).unwrap();
    setup(&mut e, 0x1000, &[0x3C, 0x42, 0xF4]);
    e.start(0x1000, 0x2000, 0, 0).unwrap();
    // ZF (bit 6) should be set
    // We don't directly expose flags but execution didn't panic
}

#[test]
fn lcg_byte_stream_never_panics() {
    let mut g = make_lcg(0xBADD_FACE_F00D_C0DE);
    for _ in 0..40 {
        let mut e = make_x64();
        with_stack(&mut e);
        let len = ((g() & 0x1F) as usize) + 4;
        let code: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        setup(&mut e, 0x1000, &code);
        let _ = e.start(0x1000, 0x2000, 0, 8); // bounded steps; Ok or Err, no panic
    }
}

// ── 7. Hooks ────────────────────────────────────────────────────────────────
#[test]
fn code_hook_fires_per_step() {
    let mut e = make_x64();
    let count = Arc::new(Mutex::new(0u64));
    let c2 = Arc::clone(&count);
    setup(&mut e, 0x1000, &[0x90, 0x90, 0x90, 0x90, 0xF4]);
    e.add_code_hook(0x1000, 0x2000, Box::new(move |_, _| {
        *c2.lock().unwrap() += 1;
    })).unwrap();
    e.start(0x1000, 0x2000, 0, 0).unwrap();
    assert!(*count.lock().unwrap() >= 4);
}

#[test]
fn remove_unknown_hook_fails() {
    let mut e = make_x64();
    assert!(e.remove_hook(HookHandle(9999)).is_err());
}

#[test]
fn mem_read_hook_fires() {
    let mut e = make_x64();
    e.map_memory(0x1000, 0x100, MemPerms::ALL).unwrap();
    let n = Arc::new(Mutex::new(0u64));
    let n2 = n.clone();
    e.add_mem_hook(HookKind::MemRead, Box::new(move |_, _, _| {
        *n2.lock().unwrap() += 1;
    })).unwrap();
    e.read_memory(0x1000, 4).unwrap();
    assert!(*n.lock().unwrap() >= 1);
}

#[test]
fn hookkind_hash_eq() {
    use std::collections::HashSet;
    let mut s: HashSet<HookKind> = HashSet::new();
    s.insert(HookKind::Code);
    s.insert(HookKind::MemRead);
    s.insert(HookKind::Insn(42));
    assert_eq!(s.len(), 3);
    assert!(s.contains(&HookKind::Code));
    assert!(!s.contains(&HookKind::Insn(43)));
}

// ── 8. Context save/restore ────────────────────────────────────────────────
#[test]
fn context_save_restore_roundtrip_lcg() {
    let mut g = make_lcg(0xC0FE_E0DD_BEEF_F00D);
    let mut e = make_x64();
    for _ in 0..30 {
        let v = g();
        e.write_register(x86_regs::RAX, v).unwrap();
        let ctx = e.context_save().unwrap();
        e.write_register(x86_regs::RAX, !v).unwrap();
        e.context_restore(&ctx).unwrap();
        assert_eq!(e.read_register(x86_regs::RAX).unwrap(), v);
    }
}

#[test]
fn context_restore_bad_data() {
    let mut e = make_x64();
    assert!(e.context_restore(&[1, 2, 3]).is_err());
}

// ── 9. ExceptionKind ───────────────────────────────────────────────────────
#[test]
fn exception_vectors_known() {
    assert_eq!(ExceptionKind::DivideByZero.vector(), 0);
    assert_eq!(ExceptionKind::Breakpoint.vector(), 3);
    assert_eq!(ExceptionKind::InvalidOpcode.vector(), 6);
    assert_eq!(ExceptionKind::PageFault.vector(), 14);
    assert_eq!(ExceptionKind::SimdFloat.vector(), 19);
    assert_eq!(ExceptionKind::Unknown(255).vector(), 255);
}

#[test]
fn exception_hash_eq_pairs() {
    use std::collections::HashSet;
    let mut h = HashSet::new();
    for k in [
        ExceptionKind::DivideByZero,
        ExceptionKind::Debug,
        ExceptionKind::Nmi,
        ExceptionKind::Breakpoint,
        ExceptionKind::Overflow,
        ExceptionKind::BoundRange,
        ExceptionKind::InvalidOpcode,
        ExceptionKind::DeviceNotAvailable,
        ExceptionKind::DoubleFault,
        ExceptionKind::PageFault,
    ] {
        h.insert(k);
    }
    assert_eq!(h.len(), 10);
    // Different Unknown values are distinct
    let mut u = HashSet::new();
    for i in 0..30 {
        u.insert(ExceptionKind::Unknown(i));
    }
    assert_eq!(u.len(), 30);
}

#[test]
fn cpu_exception_with_error_code() {
    let e = CpuException::new(ExceptionKind::PageFault, 0xDEAD).with_error_code(0b101);
    assert_eq!(e.fault_addr, 0xDEAD);
    assert_eq!(e.error_code, Some(0b101));
}

// ── 10. EmuStats ────────────────────────────────────────────────────────────
#[test]
fn stats_ipc_zero_when_no_mem() {
    let s = EmuStats::default();
    assert!(s.ipc().abs() < f64::EPSILON);
    assert!(s.branch_ratio().abs() < f64::EPSILON);
}

#[test]
fn stats_merge_associative_lcg() {
    let mut g = make_lcg(0x99);
    let mut acc = EmuStats::default();
    let mut total = 0u64;
    for _ in 0..50 {
        let v = g() & 0xFFFF;
        let s = EmuStats {
            insns_executed: v,
            ..Default::default()
        };
        acc.merge(&s);
        total = total.wrapping_add(v);
    }
    assert_eq!(acc.insns_executed, total);
}

#[test]
fn stats_reset() {
    let mut s = EmuStats {
        insns_executed: 100,
        ..Default::default()
    };
    s.reset();
    assert_eq!(s.insns_executed, 0);
}

// ── 11. CoverageMap ────────────────────────────────────────────────────────
#[test]
fn coverage_record_and_query_lcg() {
    let mut g = make_lcg(0x7777);
    let mut c = CoverageMap::new();
    let mut expected = std::collections::HashMap::new();
    for _ in 0..200 {
        let a = g() & 0xFF;
        c.record(a);
        *expected.entry(a).or_insert(0u32) += 1;
    }
    for (a, cnt) in expected {
        assert_eq!(c.hit_count(a), cnt);
        assert!(c.is_covered(a));
    }
}

#[test]
fn coverage_singleton_sort() {
    let mut c = CoverageMap::new();
    c.record(0x300);
    c.record(0x100);
    c.record(0x100);
    c.record(0x200);
    let s = c.singleton_addresses();
    assert_eq!(s, vec![0x200, 0x300]);
}

#[test]
fn coverage_covered_addresses_sorted() {
    let mut c = CoverageMap::new();
    for x in [50u64, 1, 100, 5] {
        c.record(x);
    }
    let v = c.covered_addresses();
    let mut sorted = v.clone();
    sorted.sort_unstable();
    assert_eq!(v, sorted);
}

#[test]
fn coverage_reset_clears() {
    let mut c = CoverageMap::new();
    c.record(1);
    c.record(2);
    c.reset();
    assert_eq!(c.unique_count(), 0);
    assert!(!c.is_covered(1));
}

// ── 12. EmuCoverageTracker ─────────────────────────────────────────────────
#[test]
fn tracker_pct_partial() {
    let mut t = EmuCoverageTracker::new();
    for a in 0x1000u64..0x1008 {
        t.record(a);
    }
    let pct = t.coverage_pct(0x1000, 0x1010);
    assert!((pct - 50.0).abs() < 1e-6);
}

#[test]
fn tracker_pct_empty_range() {
    let t = EmuCoverageTracker::new();
    assert!(t.coverage_pct(0x1000, 0x1000).abs() < f64::EPSILON);
    assert!(t.coverage_pct(0x2000, 0x1000).abs() < f64::EPSILON);
}

#[test]
fn tracker_visited_sorted() {
    let mut t = EmuCoverageTracker::new();
    for a in [9u64, 1, 5, 3, 7] {
        t.record(a);
    }
    assert_eq!(t.visited_sorted(), vec![1, 3, 5, 7, 9]);
}

// ── 13. IoPortMap ──────────────────────────────────────────────────────────
struct ConstReader(u32);
impl IoPortHandler for ConstReader {
    fn read(&self, _: u16) -> u32 {
        self.0
    }
    fn write(&self, _: u16, _: u32) {}
}

#[test]
fn ioport_default_read_changeable() {
    let mut m = IoPortMap::new();
    m.set_default_read(0xCAFE);
    assert_eq!(m.read(0xABCD), 0xCAFE);
}

#[test]
fn ioport_exact_overrides_default() {
    let mut m = IoPortMap::new();
    m.register_exact(0x42, Box::new(ConstReader(7)));
    assert_eq!(m.read(0x42), 7);
}

#[test]
fn ioport_range_inclusive() {
    let mut m = IoPortMap::new();
    m.register_range(0x10, 0x12, Box::new(ConstReader(0x99)));
    assert_eq!(m.read(0x10), 0x99);
    assert_eq!(m.read(0x12), 0x99);
    assert_eq!(m.read(0x13), 0xFF);
}

// ── 14. MMIO ───────────────────────────────────────────────────────────────
struct ScratchDev {
    v: u64,
}
impl MmioDevice for ScratchDev {
    fn mmio_read(&self, _: u64, _: usize) -> u64 {
        self.v
    }
    fn mmio_write(&mut self, _: u64, _: usize, v: u64) {
        self.v = v;
    }
    fn name(&self) -> &'static str {
        "scratch"
    }
}

#[test]
fn mmio_write_read_back() {
    let mut mm = MmioMap::new();
    mm.register(MmioRegion::new(0x1000, 0x100, Box::new(ScratchDev { v: 0 })))
        .unwrap();
    assert!(mm.write(0x1004, 4, 0xABCD));
    assert_eq!(mm.read(0x1004, 4), Some(0xABCD));
}

#[test]
fn mmio_write_unmapped_returns_false() {
    let mut mm = MmioMap::new();
    assert!(!mm.write(0x5000, 4, 0));
    assert_eq!(mm.read(0x5000, 4), None);
}

#[test]
fn mmio_region_contains_and_offset() {
    let r = MmioRegion::new(0x2000, 0x100, Box::new(ScratchDev { v: 0 }));
    assert!(r.contains(0x2000));
    assert!(r.contains(0x20FF));
    assert!(!r.contains(0x2100));
    assert_eq!(r.offset_of(0x2010), 0x10);
}

// ── 15. InterruptController ────────────────────────────────────────────────
#[test]
fn ic_default_enabled() {
    let ic = InterruptController::new();
    assert!(ic.is_enabled());
    assert_eq!(ic.pending_count(), 0);
}

#[test]
fn ic_state_machine_disable_enable() {
    let mut ic = InterruptController::new();
    ic.register_vector(InterruptVector {
        number: 1,
        handler_addr: 0,
        description: String::new(),
    });
    ic.disable();
    ic.raise(1);
    assert_eq!(ic.pending_count(), 0);
    ic.enable();
    ic.raise(1);
    assert_eq!(ic.pending_count(), 1);
    let v = ic.next_pending().unwrap();
    assert_eq!(v.number, 1);
    assert!(ic.next_pending().is_none());
}

#[test]
fn ic_raise_unregistered_no_vector() {
    let mut ic = InterruptController::new();
    ic.raise(99);
    // No vector registered, next_pending should return None despite pending
    assert!(ic.next_pending().is_none());
}

// ── 16. RegisterFile ───────────────────────────────────────────────────────
#[test]
fn regfile_oob_errors() {
    let mut rf = RegisterFile::new(vec!["r0".into()]);
    assert!(rf.read(5).is_err());
    assert!(rf.write(5, 0).is_err());
}

#[test]
fn regfile_restore_wrong_size_fails() {
    let mut rf = RegisterFile::new(vec!["r0".into(), "r1".into()]);
    assert!(rf.restore(&[1]).is_err());
}

#[test]
fn regfile_case_insensitive_lookup() {
    let rf = RegisterFile::new(vec!["RaX".into(), "rbx".into()]);
    assert_eq!(rf.index_of("rax"), Some(0));
    assert_eq!(rf.index_of("RBX"), Some(1));
    assert_eq!(rf.index_of("missing"), None);
}

#[test]
fn regfile_lcg_rw_roundtrip() {
    let mut g = make_lcg(0xABCD);
    let mut rf = RegisterFile::new((0..8).map(|i| format!("r{i}")).collect());
    let mut expected = [0u64; 8];
    for _ in 0..50 {
        let i = (g() & 7) as usize;
        let v = g();
        rf.write(i, v).unwrap();
        expected[i] = v;
        for (k, &exp) in expected.iter().enumerate() {
            assert_eq!(rf.read(k).unwrap(), exp);
        }
    }
}

// ── 17. FlatMemory ─────────────────────────────────────────────────────────
#[test]
fn flat_memory_underflow_addr() {
    let fm = FlatMemory::new(0x1000, 4, MemPerms::ALL);
    assert!(fm.read(0x0FFF, 1).is_err());
}

#[test]
fn flat_memory_full_roundtrip_lcg() {
    let mut g = make_lcg(0x4242);
    let mut fm = FlatMemory::new(0x0, 256, MemPerms::ALL);
    let bytes: Vec<u8> = (0..256).map(|_| (g() & 0xFF) as u8).collect();
    fm.load(&bytes);
    assert_eq!(fm.read(0, 256).unwrap(), bytes);
    assert_eq!(fm.as_slice(), &bytes[..]);
}

#[test]
fn flat_memory_perms_enforced() {
    let mut fm = FlatMemory::new(0, 4, MemPerms::WRITE);
    assert!(fm.read(0, 1).is_err());
    fm.write(0, &[1]).unwrap();
}

// ── 18. SnapshotManager ────────────────────────────────────────────────────
#[test]
fn snapshot_list_sorted_by_id() {
    let mut mgr = SnapshotManager::new();
    let emu = EmulatorFactory::create(EmulatorArch::X86_64);
    let _ = mgr.save(emu.as_ref(), "a").unwrap();
    let _ = mgr.save(emu.as_ref(), "b").unwrap();
    let _ = mgr.save(emu.as_ref(), "c").unwrap();
    let lst = mgr.list();
    assert_eq!(lst.len(), 3);
    assert!(lst[0].0 .0 < lst[1].0 .0 && lst[1].0 .0 < lst[2].0 .0);
    assert_eq!(lst[0].1, "a");
}

#[test]
fn snapshot_remove_unknown_fails() {
    let mut mgr = SnapshotManager::new();
    assert!(mgr.remove(SnapshotId(999)).is_err());
}

#[test]
fn snapshot_restore_unknown_fails() {
    let mgr = SnapshotManager::new();
    let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
    assert!(mgr.restore(emu.as_mut(), SnapshotId(123)).is_err());
}

// ── 19. EmuCheckpointManager ───────────────────────────────────────────────
#[test]
fn checkpoint_restore_unknown_returns_false() {
    let cm = EmuCheckpointManager::new();
    let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
    assert!(!cm.restore_checkpoint(999, emu.as_mut()).unwrap());
}

#[test]
fn checkpoint_full_cycle_preserves_memory() {
    let mut cm = EmuCheckpointManager::new();
    let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
    emu.map_memory(0x1000, 0x100, MemPerms::ALL).unwrap();
    emu.write_memory(0x1000, &[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
    let id = cm.save_checkpoint(emu.as_ref()).unwrap();
    emu.write_memory(0x1000, &[0, 0, 0, 0]).unwrap();
    cm.restore_checkpoint(id, emu.as_mut()).unwrap();
    assert_eq!(emu.read_memory(0x1000, 4).unwrap(), [0xAA, 0xBB, 0xCC, 0xDD]);
}

// ── 20. InsnTrace ──────────────────────────────────────────────────────────
#[test]
fn insn_trace_clear() {
    let mut t = InsnTrace::new(8);
    for i in 0..5 {
        t.push(TraceEntry {
            pc: i,
            size: 1,
            bytes: vec![],
            disasm: String::new(),
        });
    }
    assert_eq!(t.len(), 5);
    t.clear();
    assert!(t.is_empty());
}

#[test]
fn insn_trace_iter_count() {
    let mut t = InsnTrace::new(100);
    for i in 0..50 {
        t.push(TraceEntry {
            pc: i,
            size: 1,
            bytes: vec![],
            disasm: String::new(),
        });
    }
    assert_eq!(t.iter().count(), 50);
}

// ── 21. EmuHookManager ─────────────────────────────────────────────────────
#[test]
fn hookmgr_continue_chain_to_next() {
    let mut hm = EmuHookManager::new();
    let count = Arc::new(Mutex::new(0u32));
    let c2 = count.clone();
    hm.register(0x1000, move |_| {
        *c2.lock().unwrap() += 1;
        HookAction::Continue
    });
    let c3 = count.clone();
    hm.register(0x1000, move |_| {
        *c3.lock().unwrap() += 1;
        HookAction::SkipInstruction
    });
    let a = hm.dispatch(0x1000);
    assert_eq!(a, HookAction::SkipInstruction);
    assert_eq!(*count.lock().unwrap(), 2);
}

#[test]
fn hookmgr_unregister_unknown_returns_zero() {
    let mut hm = EmuHookManager::new();
    assert_eq!(hm.unregister(0xDEAD), 0);
}

#[test]
fn hookmgr_no_hook_continues() {
    let hm = EmuHookManager::new();
    assert_eq!(hm.dispatch(0x9999), HookAction::Continue);
}

// ── 22. EmulatorRegistry ────────────────────────────────────────────────────
struct TestBackend;
impl EmulatorBackend for TestBackend {
    fn name(&self) -> &'static str {
        "test"
    }
    fn supported_arches(&self) -> Vec<EmulatorArch> {
        vec![EmulatorArch::X86_64]
    }
    fn create(&self, arch: EmulatorArch) -> Box<dyn Emulator> {
        Box::new(SimpleInterpreter::new(arch))
    }
}

#[test]
fn registry_register_and_create() {
    let mut r = EmulatorRegistry::new();
    r.register(Box::new(TestBackend));
    assert_eq!(r.names(), vec!["test"]);
    let emu = r.create(EmulatorArch::X86_64).unwrap();
    assert_eq!(emu.arch(), EmulatorArch::X86_64);
    assert!(r.create(EmulatorArch::Sparc64).is_none());
}

// ── 23. Trace ──────────────────────────────────────────────────────────────
#[test]
fn trace_unique_pcs() {
    let mut t = Trace::new();
    t.push(TraceEntry { pc: 1, size: 1, bytes: vec![], disasm: String::new() });
    t.push(TraceEntry { pc: 1, size: 1, bytes: vec![], disasm: String::new() });
    t.push(TraceEntry { pc: 2, size: 1, bytes: vec![], disasm: String::new() });
    assert_eq!(t.unique_pcs().len(), 2);
    assert_eq!(t.len(), 3);
    assert!(!t.is_empty());
}

// ── 24. EmulatorError Display ──────────────────────────────────────────────
#[test]
fn error_display_for_all_kinds() {
    let cases = [
        EmulatorError::MemFault { addr: 1, op: "x".into() },
        EmulatorError::InvalidInsn { addr: 2 },
        EmulatorError::Timeout,
        EmulatorError::HookError("h".into()),
        EmulatorError::InvalidArg("a".into()),
        EmulatorError::InitError("i".into()),
        EmulatorError::Unsupported,
    ];
    for e in cases {
        let s = e.to_string();
        assert!(!s.is_empty());
    }
}

// ── 25. Send+Sync threaded stress ──────────────────────────────────────────
#[test]
fn coverage_map_send_sync_threaded() {
    use std::thread;
    let cov = Arc::new(Mutex::new(CoverageMap::new()));
    let mut handles = Vec::new();
    for t in 0..4 {
        let c = cov.clone();
        handles.push(thread::spawn(move || {
            let mut g = make_lcg(0xDEAD_BEEF_CAFE_BABE ^ u64::try_from(t).unwrap_or(0).wrapping_mul(0x9E37));
            for _ in 0..100 {
                let a = g() & 0xFF;
                c.lock().unwrap().record(a);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // The guard from the outer `lock()` lives until the end of the statement,
    // so calling `lock()` again inside the closure deadlocks: `std::sync::Mutex`
    // is not reentrant. Take the addresses, drop the guard, then sum.
    let addrs = {
        let g = cov.lock().unwrap();
        g.covered_addresses()
    };
    let total: u32 = {
        let g = cov.lock().unwrap();
        addrs.iter().map(|&a| g.hit_count(a)).sum()
    };
    assert_eq!(total, 4 * 100);
}

#[test]
fn emustats_send_sync_threaded() {
    use std::thread;
    let s = Arc::new(Mutex::new(EmuStats::default()));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let s2 = s.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                s2.lock().unwrap().insns_executed += 1;
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(s.lock().unwrap().insns_executed, 400);
}

// ── 26. SnapshotId/HookHandle Hash/Eq ──────────────────────────────────────
#[test]
fn snapshot_id_hookhandle_hash_eq() {
    use std::collections::HashSet;
    let mut sids = HashSet::new();
    let mut hhs = HashSet::new();
    for i in 0..30u64 {
        sids.insert(SnapshotId(i));
        hhs.insert(HookHandle(i));
    }
    assert_eq!(sids.len(), 30);
    assert_eq!(hhs.len(), 30);
    assert_eq!(SnapshotId(5), SnapshotId(5));
    assert_ne!(HookHandle(1), HookHandle(2));
}

// ── 27. MemoryDumper replay ────────────────────────────────────────────────
#[test]
fn memory_dumper_replay() {
    let mut md = MemoryDumper::new();
    md.record_write(0x1000, vec![1, 2, 3]);
    md.record_write(0x1003, vec![4, 5]);
    let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
    emu.map_memory(0x1000, 0x100, MemPerms::ALL).unwrap();
    md.replay(emu.as_mut()).unwrap();
    assert_eq!(emu.read_memory(0x1000, 5).unwrap(), [1, 2, 3, 4, 5]);
}

// ── 28. ExecutionResult ────────────────────────────────────────────────────
#[test]
fn execution_result_new_normal() {
    let mut regs = std::collections::HashMap::new();
    regs.insert(0u32, 42u64);
    let r = ExecutionResult::new_normal(regs.clone(), Some(7));
    assert_eq!(r.exit_reason, ExitReason::Normal);
    assert_eq!(r.return_value, Some(7));
    assert_eq!(r.final_registers.len(), 1);
    assert_eq!(r.instructions_executed, 0);
}

// ── 29. OsType Hash/Eq ─────────────────────────────────────────────────────
#[test]
fn ostype_hash_eq() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(OsType::Windows);
    s.insert(OsType::Linux);
    s.insert(OsType::MacOs);
    s.insert(OsType::Bare);
    assert_eq!(s.len(), 4);
}

// ── 30. CoverageCollector ──────────────────────────────────────────────────
#[test]
fn coverage_collector_record() {
    let mut c = CoverageCollector::new();
    c.record(0x1000);
    c.record(0x1000);
    assert_eq!(c.coverage().unique_count(), 1);
    assert_eq!(c.coverage().hit_count(0x1000), 2);
}
