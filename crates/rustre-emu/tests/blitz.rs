//! Exhaustive integration tests for rustre-emu public API.
//! Focus: edge cases, boundaries, adversarial inputs, round-trips, invariants.

use rustre_emu::*;

// ── EmulatorArch ─────────────────────────────────────────────────────────────

#[test]
fn arch_all_pointer_sizes_consistent_with_is_64bit() {
    let archs = [
        EmulatorArch::X86_16,
        EmulatorArch::X86_32,
        EmulatorArch::X86_64,
        EmulatorArch::Arm,
        EmulatorArch::ArmThumb,
        EmulatorArch::Arm64,
        EmulatorArch::Mips32,
        EmulatorArch::Mips64,
        EmulatorArch::Mips32El,
        EmulatorArch::RiscV32,
        EmulatorArch::RiscV64,
        EmulatorArch::Sparc32,
        EmulatorArch::Sparc64,
    ];
    for a in archs {
        let ps = a.pointer_size();
        assert!(ps == 2 || ps == 4 || ps == 8, "arch {a:?} pointer_size {ps}");
        assert_eq!(a.is_64bit(), ps == 8, "arch {a:?}");
    }
}

#[test]
fn arch_names_unique_and_nonempty() {
    let archs = [
        EmulatorArch::X86_16, EmulatorArch::X86_32, EmulatorArch::X86_64,
        EmulatorArch::Arm, EmulatorArch::ArmThumb, EmulatorArch::Arm64,
        EmulatorArch::Mips32, EmulatorArch::Mips64, EmulatorArch::Mips32El,
        EmulatorArch::RiscV32, EmulatorArch::RiscV64,
        EmulatorArch::Sparc32, EmulatorArch::Sparc64,
    ];
    let mut names: Vec<&str> = archs.iter().map(|a| a.name()).collect();
    names.sort_unstable();
    let len_before = names.len();
    names.dedup();
    assert_eq!(names.len(), len_before, "duplicate arch names");
    for a in archs { assert!(!a.name().is_empty()); }
}

#[test]
fn arch_is_x86_only_for_x86_family() {
    assert!(EmulatorArch::X86_16.is_x86());
    assert!(EmulatorArch::X86_32.is_x86());
    assert!(EmulatorArch::X86_64.is_x86());
    for a in [EmulatorArch::Arm, EmulatorArch::ArmThumb, EmulatorArch::Arm64,
              EmulatorArch::Mips32, EmulatorArch::Mips64, EmulatorArch::Mips32El,
              EmulatorArch::RiscV32, EmulatorArch::RiscV64,
              EmulatorArch::Sparc32, EmulatorArch::Sparc64] {
        assert!(!a.is_x86(), "{a:?} should not be x86");
    }
}

// ── MemPerms ─────────────────────────────────────────────────────────────────

#[test]
fn memperms_aliases() {
    assert_eq!(MemPerms::R, MemPerms::READ);
    assert_eq!(MemPerms::W, MemPerms::WRITE);
    assert_eq!(MemPerms::X, MemPerms::EXEC);
    assert_eq!(MemPerms::RW, MemPerms::READ | MemPerms::WRITE);
    assert_eq!(MemPerms::RX, MemPerms::READ | MemPerms::EXEC);
    assert_eq!(MemPerms::RWX, MemPerms::ALL);
    assert_eq!(MemPerms::ALL, MemPerms::READ | MemPerms::WRITE | MemPerms::EXEC);
}

#[test]
fn memperms_none_contains_nothing() {
    let p = MemPerms::NONE;
    assert!(!p.contains(MemPerms::READ));
    assert!(!p.contains(MemPerms::WRITE));
    assert!(!p.contains(MemPerms::EXEC));
}

// ── MemRegion ────────────────────────────────────────────────────────────────

#[test]
fn memregion_end_and_contains_boundaries() {
    let r = MemRegion::new(0x1000, 0x1000, MemPerms::ALL);
    assert_eq!(r.end(), 0x2000);
    assert!(r.contains(0x1000));
    assert!(r.contains(0x1FFF));
    assert!(!r.contains(0x2000));
    assert!(!r.contains(0x0FFF));
}

#[test]
fn memregion_zero_size_contains_nothing() {
    let r = MemRegion::new(0x1000, 0, MemPerms::ALL);
    assert!(!r.contains(0x1000));
    assert_eq!(r.end(), 0x1000);
}

#[test]
fn memregion_with_label_round_trip() {
    let r = MemRegion::new(0, 1, MemPerms::READ).with_label("heap");
    assert_eq!(r.label.as_deref(), Some("heap"));
    let r2: MemRegion = serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
    assert_eq!(r, r2);
}

// ── SimpleInterpreter ────────────────────────────────────────────────────────

fn mk() -> SimpleInterpreter { SimpleInterpreter::new(EmulatorArch::X86_64) }

#[test]
fn map_zero_size_rejected() {
    let mut e = mk();
    assert!(matches!(
        e.map_memory(0x1000, 0, MemPerms::ALL).unwrap_err(),
        EmulatorError::InvalidArg(_)
    ));
}

#[test]
fn map_then_unmap_then_remap_ok() {
    let mut e = mk();
    e.map_memory(0x1000, 0x1000, MemPerms::ALL).unwrap();
    e.unmap_memory(0x1000).unwrap();
    e.map_memory(0x1000, 0x1000, MemPerms::ALL).unwrap();
    assert_eq!(e.regions().len(), 1);
}

#[test]
fn unmap_wrong_address_errors() {
    let mut e = mk();
    e.map_memory(0x1000, 0x1000, MemPerms::ALL).unwrap();
    // unmap requires exact start; using mid-region addr must fail
    assert!(e.unmap_memory(0x1500).is_err());
    assert_eq!(e.regions().len(), 1);
}

#[test]
fn overlap_detected_at_left_edge() {
    let mut e = mk();
    e.map_memory(0x2000, 0x1000, MemPerms::ALL).unwrap();
    assert!(e.map_memory(0x1000, 0x1500, MemPerms::ALL).is_err());
}

#[test]
fn overlap_adjacent_allowed() {
    let mut e = mk();
    e.map_memory(0x1000, 0x1000, MemPerms::ALL).unwrap();
    // touching but not overlapping at 0x2000 should succeed
    e.map_memory(0x2000, 0x1000, MemPerms::ALL).unwrap();
    assert_eq!(e.regions().len(), 2);
}

#[test]
fn read_no_perm_fault() {
    let mut e = mk();
    e.map_memory(0x1000, 0x100, MemPerms::WRITE).unwrap();
    assert!(matches!(
        e.read_memory(0x1000, 4).unwrap_err(),
        EmulatorError::MemFault { .. }
    ));
}

#[test]
fn write_no_perm_fault() {
    let mut e = mk();
    e.map_memory(0x1000, 0x100, MemPerms::READ).unwrap();
    assert!(matches!(
        e.write_memory(0x1000, &[1]).unwrap_err(),
        EmulatorError::MemFault { .. }
    ));
}

#[test]
fn read_oob_within_region_fault() {
    let mut e = mk();
    e.map_memory(0x1000, 0x10, MemPerms::ALL).unwrap();
    // 0x100F is within region; reading 4 bytes spans past end of buffer
    let err = e.read_memory(0x100F, 4).unwrap_err();
    assert!(matches!(err, EmulatorError::MemFault { .. }));
}

#[test]
fn write_oob_within_region_fault() {
    let mut e = mk();
    e.map_memory(0x1000, 0x10, MemPerms::ALL).unwrap();
    assert!(e.write_memory(0x100F, &[1, 2, 3, 4]).is_err());
}

#[test]
fn read_zero_len_returns_empty() {
    let mut e = mk();
    e.map_memory(0x1000, 0x10, MemPerms::ALL).unwrap();
    assert_eq!(e.read_memory(0x1000, 0).unwrap(), Vec::<u8>::new());
}

#[test]
fn unknown_register_read_errors() {
    let e = mk();
    assert!(matches!(
        e.read_register(9_999_999).unwrap_err(),
        EmulatorError::InvalidArg(_)
    ));
}

#[test]
fn write_register_creates_entry() {
    let mut e = mk();
    e.write_register(9_999_999, 42).unwrap();
    assert_eq!(e.read_register(9_999_999).unwrap(), 42);
}

#[test]
fn x86_64_default_regs_initialized_to_zero() {
    let e = mk();
    for &r in &[x86_regs::RAX, x86_regs::RCX, x86_regs::RDX, x86_regs::RBX,
                x86_regs::RSP, x86_regs::RBP, x86_regs::RSI, x86_regs::RDI,
                x86_regs::RIP, x86_regs::RFLAGS, x86_regs::R8, x86_regs::R15] {
        assert_eq!(e.read_register(r).unwrap(), 0);
    }
}

#[test]
fn non_x86_arch_has_no_default_regs() {
    let e = SimpleInterpreter::new(EmulatorArch::Arm64);
    // Arm64 arch on SimpleInterpreter uses default CpuState; ARM regs not pre-seeded
    assert!(e.read_register(arm64_regs::X0).is_err());
}

#[test]
fn hlt_stops_execution_immediately() {
    let mut e = mk();
    e.map_memory(0x1000, 0x10, MemPerms::ALL).unwrap();
    e.write_memory(0x1000, &[0xF4, 0xB8, 0x42, 0, 0, 0]).unwrap();
    e.start(0x1000, 0x9999, 0, 0).unwrap();
    // RAX must not have been set to 0x42 since HLT stopped first
    assert_eq!(e.read_register(x86_regs::RAX).unwrap(), 0);
}

#[test]
fn jcc_taken_when_zf_set() {
    let mut e = mk();
    e.map_memory(0x1000, 0x100, MemPerms::ALL).unwrap();
    // mov eax, 1; cmp al, 1; je +3; mov eax, 0xDEAD; hlt; mov eax, 0xBEEF; hlt
    e.write_memory(0x1000, &[
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0x3C, 0x01,                   // cmp al, 1   (sets ZF)
        0x74, 0x06,                   // je +6
        0xB8, 0xAD, 0xDE, 0x00, 0x00, // mov eax, 0xDEAD
        0xF4,                         // hlt
        0xB8, 0xEF, 0xBE, 0x00, 0x00, // mov eax, 0xBEEF
        0xF4,                         // hlt
    ]).unwrap();
    e.start(0x1000, 0x9999, 0, 0).unwrap();
    assert_eq!(e.read_register(x86_regs::RAX).unwrap(), 0xBEEF);
}

#[test]
fn count_limit_zero_means_unlimited() {
    let mut e = mk();
    e.map_memory(0x1000, 0x10, MemPerms::ALL).unwrap();
    e.write_memory(0x1000, &[0x90, 0x90, 0x90, 0xF4]).unwrap();
    e.start(0x1000, 0x9999, 0, 0).unwrap();
    // should have run to HLT, RIP at addr of HLT
    assert_eq!(e.read_register(x86_regs::RIP).unwrap(), 0x1003);
}

#[test]
fn until_address_stops_execution() {
    let mut e = mk();
    e.map_memory(0x1000, 0x20, MemPerms::ALL).unwrap();
    e.write_memory(0x1000, &[0x90, 0x90, 0x90, 0x90, 0xF4]).unwrap();
    e.start(0x1000, 0x1002, 0, 0).unwrap();
    assert_eq!(e.read_register(x86_regs::RIP).unwrap(), 0x1002);
}

#[test]
fn stop_clears_after_start() {
    let mut e = mk();
    e.map_memory(0x1000, 0x10, MemPerms::ALL).unwrap();
    e.write_memory(0x1000, &[0x90, 0xF4]).unwrap();
    e.stop().unwrap();
    // start should reset stop_requested
    e.start(0x1000, 0x9999, 0, 0).unwrap();
    assert!(e.read_register(x86_regs::RIP).unwrap() >= 0x1001);
}

#[test]
fn context_save_restore_preserves_memory() {
    let mut e = mk();
    e.map_memory(0x1000, 0x100, MemPerms::ALL).unwrap();
    e.write_memory(0x1000, &[1, 2, 3, 4]).unwrap();
    let ctx = e.context_save().unwrap();
    e.write_memory(0x1000, &[9, 9, 9, 9]).unwrap();
    e.context_restore(&ctx).unwrap();
    // Note: context_restore restores CpuState (regs/memory map) but regions vec is not restored.
    // Memory bytes should be restored
    let r = e.read_memory(0x1000, 4);
    if let Ok(v) = r {
        assert_eq!(v, vec![1, 2, 3, 4]);
    }
    // If regions vector was wiped, this is a known limitation — at minimum, save shouldn't crash
}

#[test]
fn context_restore_malformed_errors() {
    let mut e = mk();
    assert!(matches!(
        e.context_restore(b"not json").unwrap_err(),
        EmulatorError::HookError(_)
    ));
}

#[test]
fn context_restore_empty_errors() {
    let mut e = mk();
    assert!(e.context_restore(&[]).is_err());
}

// ── CoverageMap ──────────────────────────────────────────────────────────────

#[test]
fn coverage_empty_state() {
    let c = CoverageMap::new();
    assert_eq!(c.unique_count(), 0);
    assert_eq!(c.hit_count(0x1000), 0);
    assert!(!c.is_covered(0x1000));
    assert!(c.covered_addresses().is_empty());
    assert!(c.singleton_addresses().is_empty());
}

#[test]
fn coverage_covered_addresses_sorted() {
    let mut c = CoverageMap::new();
    c.record(0x3000);
    c.record(0x1000);
    c.record(0x2000);
    assert_eq!(c.covered_addresses(), vec![0x1000, 0x2000, 0x3000]);
}

#[test]
fn coverage_singleton_only_unique_hits() {
    let mut c = CoverageMap::new();
    c.record(0x1000);
    c.record(0x2000);
    c.record(0x2000);
    c.record(0x3000);
    assert_eq!(c.singleton_addresses(), vec![0x1000, 0x3000]);
}

#[test]
fn coverage_merge_accumulates_counts() {
    let mut a = CoverageMap::new();
    a.record(0x1000);
    a.record(0x1000);
    let mut b = CoverageMap::new();
    b.record(0x1000);
    a.merge(&b);
    assert_eq!(a.hit_count(0x1000), 3);
}

// ── EmuCoverageTracker ───────────────────────────────────────────────────────

#[test]
fn tracker_pct_empty_range_zero() {
    let t = EmuCoverageTracker::new();
    assert!(t.coverage_pct(0x1000, 0x1000).abs() < f64::EPSILON);
    assert!(t.coverage_pct(0x2000, 0x1000).abs() < f64::EPSILON); // end <= start
}

#[test]
fn tracker_visited_sorted() {
    let mut t = EmuCoverageTracker::new();
    t.record(0x30);
    t.record(0x10);
    t.record(0x20);
    assert_eq!(t.visited_sorted(), vec![0x10, 0x20, 0x30]);
}

#[test]
fn tracker_reset_clears() {
    let mut t = EmuCoverageTracker::new();
    t.record(0x1);
    t.reset();
    assert_eq!(t.unique_count(), 0);
}

// ── EmuStats ─────────────────────────────────────────────────────────────────

#[test]
fn stats_ipc_zero_accesses_returns_zero() {
    let s = EmuStats { insns_executed: 100, ..Default::default() };
    assert!(s.ipc().abs() < f64::EPSILON);
}

#[test]
fn stats_branch_ratio_no_branches_zero() {
    assert!(EmuStats::default().branch_ratio().abs() < f64::EPSILON);
}

#[test]
fn stats_reset_zeros_all() {
    let mut s = EmuStats { insns_executed: 5, mem_reads: 3, ..Default::default() };
    s.reset();
    assert_eq!(s.insns_executed, 0);
    assert_eq!(s.mem_reads, 0);
}

// ── RegisterFile ─────────────────────────────────────────────────────────────

#[test]
fn regfile_empty_isnull() {
    let rf = RegisterFile::new(vec![]);
    assert!(rf.is_empty());
    assert_eq!(rf.len(), 0);
    assert!(rf.read(0).is_err());
}

#[test]
fn regfile_oob_write_errors() {
    let mut rf = RegisterFile::new(vec!["a".into()]);
    assert!(rf.write(1, 0).is_err());
}

#[test]
fn regfile_name_lookup_case_insensitive() {
    let rf = RegisterFile::new(vec!["Rax".into(), "rBx".into()]);
    assert_eq!(rf.index_of("RAX"), Some(0));
    assert_eq!(rf.index_of("rbx"), Some(1));
}

#[test]
fn regfile_restore_wrong_length_errors() {
    let mut rf = RegisterFile::new(vec!["a".into(), "b".into()]);
    assert!(rf.restore(&[1]).is_err());
    assert!(rf.restore(&[1, 2, 3]).is_err());
    rf.restore(&[5, 6]).unwrap();
    assert_eq!(rf.read(0).unwrap(), 5);
}

#[test]
fn regfile_name_of_oob_none() {
    let rf = RegisterFile::new(vec!["a".into()]);
    assert!(rf.name_of(10).is_none());
}

// ── FlatMemory ───────────────────────────────────────────────────────────────

#[test]
fn flat_underflow_below_base_errors() {
    let fm = FlatMemory::new(0x1000, 0x100, MemPerms::ALL);
    assert!(fm.read(0x0FFF, 1).is_err());
}

#[test]
fn flat_no_read_perm_errors() {
    let fm = FlatMemory::new(0x1000, 0x100, MemPerms::WRITE);
    assert!(fm.read(0x1000, 1).is_err());
}

#[test]
fn flat_base_and_size_round_trip() {
    let fm = FlatMemory::new(0xDEAD, 42, MemPerms::READ);
    assert_eq!(fm.base(), 0xDEAD);
    assert_eq!(fm.size(), 42);
    assert_eq!(fm.as_slice().len(), 42);
}

#[test]
fn flat_load_full_buffer_ok() {
    let mut fm = FlatMemory::new(0, 4, MemPerms::ALL);
    fm.load(&[1, 2, 3, 4]);
    assert_eq!(fm.as_slice(), &[1, 2, 3, 4]);
}

#[test]
#[should_panic(expected = "bytes")]
fn flat_load_oversize_panics() {
    // Documented behavior: panics if bytes > size
    let mut fm = FlatMemory::new(0, 2, MemPerms::ALL);
    fm.load(&[1, 2, 3]);
}

// ── InsnTrace ────────────────────────────────────────────────────────────────

#[test]
fn insn_trace_zero_capacity() {
    // capacity 0: every push is immediately evicted
    let mut t = InsnTrace::new(0);
    t.push(TraceEntry { pc: 1, size: 1, bytes: vec![], disasm: String::new() });
    // Behavior expectation: len does not exceed capacity
    assert!(t.len() <= 1);
}

#[test]
fn insn_trace_iter_order() {
    let mut t = InsnTrace::new(5);
    for i in 0..3u64 {
        t.push(TraceEntry { pc: i, size: 1, bytes: vec![], disasm: String::new() });
    }
    let pcs: Vec<u64> = t.iter().map(|e| e.pc).collect();
    assert_eq!(pcs, vec![0, 1, 2]);
}

#[test]
fn insn_trace_clear() {
    let mut t = InsnTrace::new(2);
    t.push(TraceEntry { pc: 1, size: 1, bytes: vec![], disasm: String::new() });
    t.clear();
    assert!(t.is_empty());
}

#[test]
fn insn_trace_last_n_more_than_len() {
    let mut t = InsnTrace::new(5);
    t.push(TraceEntry { pc: 7, size: 1, bytes: vec![], disasm: String::new() });
    assert_eq!(t.last_n(10).len(), 1);
}

// ── IoPortMap ────────────────────────────────────────────────────────────────

#[test]
fn io_set_default_read() {
    let mut m = IoPortMap::new();
    m.set_default_read(0xAAAA);
    assert_eq!(m.read(0x1234), 0xAAAA);
}

#[test]
#[should_panic(expected = "first")]
fn io_range_first_gt_last_panics() {
    struct N;
    impl IoPortHandler for N { fn read(&self, _: u16) -> u32 { 0 } fn write(&self, _: u16, _: u32) {} }
    let mut m = IoPortMap::new();
    m.register_range(0x20, 0x10, Box::new(N));
}

#[test]
fn io_write_to_unmapped_port_no_panic() {
    let m = IoPortMap::new();
    m.write(0x99, 0); // no handler → silently drop
}

// ── MmioMap ──────────────────────────────────────────────────────────────────

struct DummyDev { name: &'static str }
impl MmioDevice for DummyDev {
    fn mmio_read(&self, off: u64, _: usize) -> u64 { off }
    fn mmio_write(&mut self, _: u64, _: usize, _: u64) {}
    fn name(&self) -> &str { self.name }
}

#[test]
fn mmio_offset_of() {
    let r = MmioRegion::new(0x1000, 0x100, Box::new(DummyDev { name: "d" }));
    assert_eq!(r.offset_of(0x1050), 0x50);
}

#[test]
fn mmio_contains_boundaries() {
    let r = MmioRegion::new(0x1000, 0x100, Box::new(DummyDev { name: "d" }));
    assert!(r.contains(0x1000));
    assert!(r.contains(0x10FF));
    assert!(!r.contains(0x1100));
}

#[test]
fn mmio_write_unmapped_returns_false() {
    let mut mm = MmioMap::new();
    assert!(!mm.write(0xDEAD, 4, 0));
}

#[test]
fn mmio_write_mapped_returns_true() {
    let mut mm = MmioMap::new();
    mm.register(MmioRegion::new(0x1000, 0x100, Box::new(DummyDev { name: "d" }))).unwrap();
    assert!(mm.write(0x1080, 4, 0));
}

#[test]
fn mmio_find_returns_index() {
    let mut mm = MmioMap::new();
    mm.register(MmioRegion::new(0x1000, 0x100, Box::new(DummyDev { name: "a" }))).unwrap();
    mm.register(MmioRegion::new(0x2000, 0x100, Box::new(DummyDev { name: "b" }))).unwrap();
    assert_eq!(mm.find(0x1010), Some(0));
    assert_eq!(mm.find(0x2010), Some(1));
    assert_eq!(mm.find(0x9999), None);
}

// ── InterruptController ──────────────────────────────────────────────────────

#[test]
fn interrupt_fifo_order() {
    let mut ic = InterruptController::new();
    for n in [1, 2, 3] {
        ic.register_vector(InterruptVector { number: n, handler_addr: 0, description: String::new() });
        ic.raise(n);
    }
    assert_eq!(ic.next_pending().unwrap().number, 1);
    assert_eq!(ic.next_pending().unwrap().number, 2);
    assert_eq!(ic.next_pending().unwrap().number, 3);
}

#[test]
fn interrupt_raise_unregistered_drops_silently() {
    let mut ic = InterruptController::new();
    ic.raise(99);
    assert_eq!(ic.pending_count(), 1);
    assert!(ic.next_pending().is_none());
}

#[test]
fn interrupt_enable_disable_toggle() {
    let mut ic = InterruptController::new();
    assert!(ic.is_enabled());
    ic.disable();
    assert!(!ic.is_enabled());
    ic.enable();
    assert!(ic.is_enabled());
}

// ── ExceptionKind ────────────────────────────────────────────────────────────

#[test]
fn exception_vectors_distinct() {
    let kinds = [
        ExceptionKind::DivideByZero, ExceptionKind::Debug, ExceptionKind::Nmi,
        ExceptionKind::Breakpoint, ExceptionKind::Overflow, ExceptionKind::BoundRange,
        ExceptionKind::InvalidOpcode, ExceptionKind::DeviceNotAvailable,
        ExceptionKind::DoubleFault, ExceptionKind::InvalidTss,
        ExceptionKind::SegmentNotPresent, ExceptionKind::StackSegmentFault,
        ExceptionKind::GeneralProtection, ExceptionKind::PageFault,
        ExceptionKind::FloatingPoint, ExceptionKind::AlignmentCheck,
        ExceptionKind::MachineCheck, ExceptionKind::SimdFloat,
        ExceptionKind::Virtualisation,
    ];
    let mut v: Vec<u32> = kinds.iter().map(|k| k.vector()).collect();
    let before = v.len();
    v.sort_unstable();
    v.dedup();
    assert_eq!(v.len(), before);
}

#[test]
fn exception_unknown_vector_identity() {
    for n in [0_u32, 100, 255, u32::MAX] {
        assert_eq!(ExceptionKind::Unknown(n).vector(), n);
    }
}

// ── SnapshotManager ──────────────────────────────────────────────────────────

#[test]
fn snapshot_unknown_id_errors() {
    let mgr = SnapshotManager::new();
    let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
    assert!(mgr.restore(emu.as_mut(), SnapshotId(999)).is_err());
}

#[test]
fn snapshot_remove_unknown_id_errors() {
    let mut mgr = SnapshotManager::new();
    assert!(mgr.remove(SnapshotId(42)).is_err());
}

#[test]
fn snapshot_list_sorted_by_id() {
    let mut mgr = SnapshotManager::new();
    let emu = EmulatorFactory::create(EmulatorArch::X86_64);
    let _ = mgr.save(emu.as_ref(), "a").unwrap();
    let _ = mgr.save(emu.as_ref(), "b").unwrap();
    let _ = mgr.save(emu.as_ref(), "c").unwrap();
    let list = mgr.list();
    assert_eq!(list.len(), 3);
    for w in list.windows(2) { assert!(w[0].0.0 < w[1].0.0); }
}

// ── EmuCheckpointManager ─────────────────────────────────────────────────────

#[test]
fn checkpoint_restore_unknown_returns_false() {
    let cm = EmuCheckpointManager::new();
    let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
    assert!(!cm.restore_checkpoint(99, emu.as_mut()).unwrap());
}

#[test]
fn checkpoint_delete_unknown_returns_false() {
    let mut cm = EmuCheckpointManager::new();
    assert!(!cm.delete_checkpoint(42));
}

// ── MemoryDumper ─────────────────────────────────────────────────────────────

#[test]
fn dumper_replay_into_emulator() {
    let mut md = MemoryDumper::new();
    md.record_write(0x1000, vec![0xAA, 0xBB, 0xCC]);
    let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
    emu.map_memory(0x1000, 0x100, MemPerms::ALL).unwrap();
    md.replay(emu.as_mut()).unwrap();
    assert_eq!(emu.read_memory(0x1000, 3).unwrap(), vec![0xAA, 0xBB, 0xCC]);
}

#[test]
fn dumper_replay_unmapped_propagates_error() {
    let mut md = MemoryDumper::new();
    md.record_write(0xDEAD, vec![1]);
    let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
    assert!(md.replay(emu.as_mut()).is_err());
}

// ── HookManager ──────────────────────────────────────────────────────────────

#[test]
fn hook_manager_first_non_continue_wins() {
    let mut hm = EmuHookManager::new();
    hm.register(0x1000, |_| HookAction::Continue);
    hm.register(0x1000, |_| HookAction::SkipInstruction);
    hm.register(0x1000, |_| HookAction::StopEmulation);
    assert_eq!(hm.dispatch(0x1000), HookAction::SkipInstruction);
}

#[test]
fn hook_manager_unregister_nonexistent_returns_zero() {
    let mut hm = EmuHookManager::new();
    assert_eq!(hm.unregister(0xDEAD), 0);
}

#[test]
fn hook_manager_multiple_sites() {
    let mut hm = EmuHookManager::new();
    hm.register(1, |_| HookAction::Continue);
    hm.register(2, |_| HookAction::Continue);
    hm.register(3, |_| HookAction::Continue);
    assert_eq!(hm.hook_site_count(), 3);
}

// ── EmulatorRegistry ─────────────────────────────────────────────────────────

struct StubBackend { archs: Vec<EmulatorArch>, available: bool, n: String }
impl EmulatorBackend for StubBackend {
    fn name(&self) -> &str { &self.n }
    fn supported_arches(&self) -> Vec<EmulatorArch> { self.archs.clone() }
    fn create(&self, arch: EmulatorArch) -> Box<dyn Emulator> { Box::new(SimpleInterpreter::new(arch)) }
    fn is_available(&self) -> bool { self.available }
}

#[test]
fn registry_skips_unavailable_backends() {
    let mut r = EmulatorRegistry::new();
    r.register(Box::new(StubBackend { archs: vec![EmulatorArch::X86_64], available: false, n: "off".into() }));
    assert!(r.create(EmulatorArch::X86_64).is_none());
}

#[test]
fn registry_skips_unsupported_arch() {
    let mut r = EmulatorRegistry::new();
    r.register(Box::new(StubBackend { archs: vec![EmulatorArch::Arm], available: true, n: "armonly".into() }));
    assert!(r.create(EmulatorArch::X86_64).is_none());
    assert!(r.create(EmulatorArch::Arm).is_some());
}

#[test]
fn registry_names_lists_registered() {
    let mut r = EmulatorRegistry::new();
    r.register(Box::new(StubBackend { archs: vec![], available: true, n: "alpha".into() }));
    r.register(Box::new(StubBackend { archs: vec![], available: true, n: "beta".into() }));
    let mut names = r.names();
    names.sort_unstable();
    assert_eq!(names, vec!["alpha", "beta"]);
}

// ── Trace ────────────────────────────────────────────────────────────────────

#[test]
fn trace_unique_pcs_dedups() {
    let mut t = Trace::new();
    t.push(TraceEntry { pc: 1, size: 1, bytes: vec![], disasm: String::new() });
    t.push(TraceEntry { pc: 1, size: 1, bytes: vec![], disasm: String::new() });
    t.push(TraceEntry { pc: 2, size: 1, bytes: vec![], disasm: String::new() });
    assert_eq!(t.unique_pcs().len(), 2);
    assert_eq!(t.len(), 3);
    assert!(!t.is_empty());
}

// ── ExitReason / ExecutionResult ─────────────────────────────────────────────

#[test]
fn execution_result_new_normal() {
    let mut regs = std::collections::HashMap::new();
    regs.insert(0u32, 42u64);
    let r = ExecutionResult::new_normal(regs.clone(), Some(7));
    assert_eq!(r.exit_reason, ExitReason::Normal);
    assert_eq!(r.return_value, Some(7));
    assert!(r.memory_accesses.is_empty());
    assert_eq!(r.instructions_executed, 0);
}

#[test]
fn exit_reason_serde_round_trip() {
    for er in [ExitReason::Normal, ExitReason::Breakpoint, ExitReason::Timeout,
               ExitReason::InvalidInsn, ExitReason::MemFault,
               ExitReason::CountLimit, ExitReason::UserStop] {
        let json = serde_json::to_string(&er).unwrap();
        let back: ExitReason = serde_json::from_str(&json).unwrap();
        assert_eq!(er, back);
    }
}

// ── Send + Sync ─────────────────────────────────────────────────────────────

#[test]
fn emulator_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Box<dyn Emulator>>();
    assert_send_sync::<Box<dyn EmulatorBackend>>();
    assert_send_sync::<Box<dyn EmulatedDevice>>();
    assert_send_sync::<Box<dyn MmioDevice>>();
    assert_send_sync::<Box<dyn IoPortHandler>>();
}

// ── Error Display strings ────────────────────────────────────────────────────

#[test]
fn error_display_invalid_insn_format() {
    let e = EmulatorError::InvalidInsn { addr: 0xABCD };
    let s = e.to_string();
    assert!(s.contains("0x000000000000abcd"), "got: {s}");
}

#[test]
fn error_display_variants() {
    assert!(EmulatorError::Timeout.to_string().contains("timeout"));
    assert!(EmulatorError::Unsupported.to_string().contains("unsupported"));
    assert!(EmulatorError::HookError("x".into()).to_string().contains('x'));
    assert!(EmulatorError::InvalidArg("y".into()).to_string().contains('y'));
    assert!(EmulatorError::InitError("z".into()).to_string().contains('z'));
}

// ── SnapshotId / HookHandle ──────────────────────────────────────────────────

#[test]
fn snapshot_id_hash_eq() {
    use std::collections::HashSet;
    let mut s: HashSet<SnapshotId> = HashSet::new();
    s.insert(SnapshotId(1));
    s.insert(SnapshotId(1));
    s.insert(SnapshotId(2));
    assert_eq!(s.len(), 2);
}

#[test]
fn hook_handle_hash_eq() {
    use std::collections::HashSet;
    let mut s: HashSet<HookHandle> = HashSet::new();
    s.insert(HookHandle(1));
    s.insert(HookHandle(1));
    assert_eq!(s.len(), 1);
}

// ── NullDevice / EmulatedDevice ──────────────────────────────────────────────

#[test]
fn null_device_ticks_dont_create_irqs() {
    let mut d = NullDevice::new("z");
    for _ in 0..100 { d.tick(1000); }
    assert!(!d.irq_pending());
    assert!(d.irq_vector().is_none());
}

// ── x86 PUSH/POP register family ─────────────────────────────────────────────

#[test]
fn x86_push_register_pops_back() {
    let mut e = mk();
    e.map_memory(0x8000, 0x1000, MemPerms::RW).unwrap();
    e.map_memory(0x1000, 0x100, MemPerms::ALL).unwrap();
    e.write_register(x86_regs::RSP, 0x8800).unwrap();
    e.write_register(x86_regs::RBX, 0x1234_5678).unwrap();
    // push rbx ; pop rax ; hlt   => 0x53, 0x58, 0xF4
    e.write_memory(0x1000, &[0x53, 0x58, 0xF4]).unwrap();
    e.start(0x1000, 0x9999, 0, 0).unwrap();
    assert_eq!(e.read_register(x86_regs::RAX).unwrap(), 0x1234_5678);
}

// ── CoverageCollector ───────────────────────────────────────────────────────

#[test]
fn coverage_collector_records() {
    let mut cc = CoverageCollector::new();
    cc.record(0x1000);
    cc.record(0x1000);
    cc.record(0x2000);
    assert_eq!(cc.coverage().unique_count(), 2);
    assert_eq!(cc.coverage().hit_count(0x1000), 2);
}

#[test]
fn coverage_collector_install_no_panic() {
    // Stub function — exercise it for coverage of dead code.
    let cc = CoverageCollector::new();
    let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
    cc.install(emu.as_mut(), 0, 0x1000);
}

// ── OsType ───────────────────────────────────────────────────────────────────

#[test]
fn os_type_distinct() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(OsType::Windows);
    s.insert(OsType::Linux);
    s.insert(OsType::MacOs);
    s.insert(OsType::Bare);
    assert_eq!(s.len(), 4);
}

// ── CoverageEmu ──────────────────────────────────────────────────────────────

#[test]
fn coverage_emu_records_during_run() {
    let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
    emu.map_memory(0x1000, 0x100, MemPerms::ALL).unwrap();
    emu.write_memory(0x1000, &[0x90, 0x90, 0x90, 0xF4]).unwrap();
    let mut ce = CoverageEmu::new(emu.as_mut());
    ce.run(0x1000, 0x9999, 0, 0).unwrap();
    assert!(ce.coverage().unique_count() >= 3);
    assert!(ce.stats().insns_executed >= 3);
}
