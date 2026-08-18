//! Adversarial deep tests for rustre-arch (blitz2).
//!
//! Focus: deterministic LCG fuzzing on detectors, exhaustive boundary tests,
//! property checks (round-trip, monotonicity), Send+Sync threaded stress on
//! the global registry, hash/eq consistency, integer-overflow paths, and state
//! machine walks on `LiftContext`.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

use rustre_arch::{
    detect_arch_from_bytes, detect_from_elf, detect_from_macho, detect_from_pe, disassemble_linear,
    disassemble_recursive, global_registry, register_all_builtins, Address, ArchMetadata,
    ArchMode, ArchRegistry, Architecture, BranchInfo, CallingConvention, DecodeError, DisasmCache,
    DisasmFilter, DisassemblyResult, EncodeError, Endian, ExtendedInstrStats, InstrFlags,
    InstrStats, InstrStream, Instruction, LiftContext, LiftError, LinearDisassembler,
    ModeDetector, RecursiveDisassembler, RegisterFile, RegisterInfo,
};
use rustre_core::CoreError;

// ─── LCG ─────────────────────────────────────────────────────────────────────

fn lcg(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// ─── Stub Architecture ───────────────────────────────────────────────────────

#[derive(Debug)]
struct StubArch {
    name: &'static str,
}

impl Architecture for StubArch {
    fn name(&self) -> &str {
        self.name
    }
    fn pointer_size(&self) -> usize {
        8
    }
    fn endian(&self) -> Endian {
        Endian::Little
    }
    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        if bytes.is_empty() {
            return Err(CoreError::InvalidFormat {
                message: "empty".into(),
            });
        }
        let b = bytes[0];
        if b == 0xFF {
            return Err(CoreError::InvalidFormat {
                message: "bad".into(),
            });
        }
        let flags = match b {
            0xE8 => InstrFlags::CALL,
            0xC3 => InstrFlags::RET,
            0xEB => InstrFlags::BRANCH,
            0x74 => InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
            0x8B => InstrFlags::READ_MEM,
            _ => InstrFlags::NONE,
        };
        let mut i = Instruction::new(address, 1, format!("op_{b:02x}"), vec![b]);
        i.flags = flags;
        Ok(i)
    }
    fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo> {
        use rustre_core::arch::{BranchCondition, BranchKind};
        if instr.flags.contains(InstrFlags::CALL) {
            vec![BranchInfo {
                target: Some(instr.address.0.wrapping_add(0x20)),
                kind: BranchKind::Call,
                condition: BranchCondition::Always,
            }]
        } else if instr.flags.contains(InstrFlags::BRANCH) {
            let (kind, cond) = if instr.flags.contains(InstrFlags::CONDITIONAL) {
                (BranchKind::ConditionalJump, BranchCondition::Equal)
            } else {
                (BranchKind::UnconditionalJump, BranchCondition::Always)
            };
            vec![BranchInfo {
                target: Some(instr.address.0.wrapping_add(0x10)),
                kind,
                condition: cond,
            }]
        } else {
            vec![]
        }
    }
    fn registers(&self) -> Vec<RegisterInfo> {
        use rustre_core::arch::RegisterKind;
        vec![
            RegisterInfo::new("r0", 0, 8, RegisterKind::General),
            RegisterInfo::new("r1", 1, 8, RegisterKind::General),
        ]
    }
    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![CallingConvention::new("stub_cc")]
    }
}

fn stub() -> Arc<StubArch> {
    Arc::new(StubArch { name: "stub_blitz2" })
}

fn mk_instr(addr: u64, flags: InstrFlags) -> Instruction {
    let mut i = Instruction::new(Address::new(addr), 1, "t", vec![0]);
    i.flags = flags;
    i
}

// ────────────────────────────────────────────────────────────────────────────
// 1. detect_arch_from_bytes — deterministic LCG fuzzing, never panics
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn fuzz_detect_arch_from_bytes_never_panics() {
    let mut g = lcg(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..500 {
        let n = usize::try_from(g()).expect("fits in usize") % 64;
        let mut buf = Vec::with_capacity(n);
        for _ in 0..n {
            buf.push((g() & 0xFF) as u8);
        }
        let _ = detect_arch_from_bytes(&buf);
        let _ = detect_from_elf(&buf);
        let _ = detect_from_pe(&buf);
        let _ = detect_from_macho(&buf);
    }
}

#[test]
fn fuzz_detect_with_elf_magic_never_panics() {
    let mut g = lcg(0x1234_5678_9ABC_DEF0);
    for _ in 0..200 {
        let n = 4 + usize::try_from(g()).expect("fits in usize") % 100;
        let mut buf = vec![0u8; n];
        buf[0] = 0x7f;
        buf[1] = b'E';
        buf[2] = b'L';
        buf[3] = b'F';
        for b in buf.iter_mut().skip(4) {
            *b = (g() & 0xFF) as u8;
        }
        let _ = detect_arch_from_bytes(&buf);
    }
}

#[test]
fn fuzz_detect_with_pe_magic_never_panics() {
    let mut g = lcg(0xAAAA_BBBB_CCCC_DDDD);
    for _ in 0..200 {
        let n = 4 + usize::try_from(g()).expect("fits in usize") % 200;
        let mut buf = vec![0u8; n];
        buf[0] = b'M';
        buf[1] = b'Z';
        for b in buf.iter_mut().skip(2) {
            *b = (g() & 0xFF) as u8;
        }
        let _ = detect_arch_from_bytes(&buf);
    }
}

#[test]
fn detect_returns_none_for_short_inputs() {
    for n in 0..4usize {
        let buf = vec![0u8; n];
        assert!(detect_arch_from_bytes(&buf).is_none());
    }
}

#[test]
fn detect_from_elf_short_input_none() {
    let buf = vec![0u8; 10];
    assert!(detect_from_elf(&buf).is_none());
}

#[test]
fn detect_from_pe_short_input_none() {
    let buf = vec![b'M', b'Z'];
    assert!(detect_from_pe(&buf).is_none());
}

#[test]
fn detect_from_macho_short_input_none() {
    let buf = vec![0xFE, 0xED, 0xFA, 0xCE];
    // 4 bytes — too short.
    assert!(detect_from_macho(&buf).is_none());
}

// ────────────────────────────────────────────────────────────────────────────
// 2. ELF detection — known machine values
// ────────────────────────────────────────────────────────────────────────────

fn make_elf(class: u8, data: u8, machine: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 52];
    buf[0] = 0x7f;
    buf[1] = b'E';
    buf[2] = b'L';
    buf[3] = b'F';
    buf[4] = class;
    buf[5] = data;
    let m = if data == 2 {
        machine.to_be_bytes()
    } else {
        machine.to_le_bytes()
    };
    buf[18] = m[0];
    buf[19] = m[1];
    buf
}

#[test]
fn detect_elf_known_machines() {
    let cases = [
        (3u16, "x86"),
        (62, "x86_64"),
        (40, "arm"),
        (183, "arm64"),
        (8, "mips"),
        (20, "ppc"),
        (21, "ppc64"),
        (2, "sparc"),
        (18, "sparc64"),
        (220, "msp430"),
        (83, "avr"),
    ];
    for (m, name) in cases {
        let buf = make_elf(1, 1, m);
        assert_eq!(detect_from_elf(&buf).as_deref(), Some(name), "machine={m}");
    }
}

#[test]
fn detect_elf_riscv_classes() {
    let buf32 = make_elf(1, 1, 243);
    assert_eq!(detect_from_elf(&buf32).as_deref(), Some("riscv32"));
    let buf64 = make_elf(2, 1, 243);
    assert_eq!(detect_from_elf(&buf64).as_deref(), Some("riscv64"));
}

#[test]
fn detect_elf_big_endian() {
    let buf = make_elf(2, 2, 21); // ppc64 BE
    assert_eq!(detect_from_elf(&buf).as_deref(), Some("ppc64"));
}

#[test]
fn detect_elf_unknown_machine() {
    let buf = make_elf(1, 1, 0xFFFF);
    assert!(detect_from_elf(&buf).is_none());
}

// ────────────────────────────────────────────────────────────────────────────
// 3. PE detection
// ────────────────────────────────────────────────────────────────────────────

fn make_pe(machine: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 0x100];
    buf[0] = b'M';
    buf[1] = b'Z';
    let pe_offset: u32 = 0x80;
    buf[0x3c..0x40].copy_from_slice(&pe_offset.to_le_bytes());
    buf[0x80] = b'P';
    buf[0x81] = b'E';
    buf[0x82] = 0;
    buf[0x83] = 0;
    let m = machine.to_le_bytes();
    buf[0x84] = m[0];
    buf[0x85] = m[1];
    buf
}

#[test]
fn detect_pe_known_machines() {
    let cases = [
        (0x014cu16, "x86"),
        (0x8664, "x86_64"),
        (0x01c0, "arm"),
        (0xaa64, "arm64"),
        (0x01f0, "ppc"),
        (0x0162, "mips"),
    ];
    for (m, name) in cases {
        let buf = make_pe(m);
        assert_eq!(detect_from_pe(&buf).as_deref(), Some(name), "m={m:#x}");
    }
}

#[test]
fn detect_pe_unknown_machine_returns_none() {
    let buf = make_pe(0xDEAD);
    assert!(detect_from_pe(&buf).is_none());
}

#[test]
fn detect_pe_missing_signature() {
    let mut buf = make_pe(0x8664);
    buf[0x80] = b'X'; // corrupt signature
    assert!(detect_from_pe(&buf).is_none());
}

#[test]
fn detect_pe_offset_out_of_bounds() {
    let mut buf = vec![0u8; 0x40];
    buf[0] = b'M';
    buf[1] = b'Z';
    let off: u32 = 0xFFFF_FFF0;
    buf[0x3c..0x40].copy_from_slice(&off.to_le_bytes());
    assert!(detect_from_pe(&buf).is_none());
}

// ────────────────────────────────────────────────────────────────────────────
// 4. Mach-O detection
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn detect_macho_be_x86_64() {
    let mut buf = vec![0u8; 8];
    buf[0..4].copy_from_slice(&0xFEED_FACFu32.to_be_bytes());
    buf[4..8].copy_from_slice(&0x0100_0007u32.to_be_bytes());
    assert_eq!(detect_from_macho(&buf).as_deref(), Some("x86_64"));
}

#[test]
fn detect_macho_le_arm64() {
    let mut buf = vec![0u8; 8];
    buf[0..4].copy_from_slice(&0xFEED_FACFu32.to_le_bytes());
    buf[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes());
    assert_eq!(detect_from_macho(&buf).as_deref(), Some("arm64"));
}

#[test]
fn detect_macho_unknown_cputype() {
    let mut buf = vec![0u8; 8];
    buf[0..4].copy_from_slice(&0xFEED_FACEu32.to_be_bytes());
    buf[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    assert!(detect_from_macho(&buf).is_none());
}

// ────────────────────────────────────────────────────────────────────────────
// 5. LiftContext state machine + overflow boundary
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn lift_context_push_pop_roundtrip() {
    let mut ctx = LiftContext::new();
    for _ in 0..100 {
        ctx.push().unwrap();
    }
    assert_eq!(ctx.depth, 100);
    assert_eq!(ctx.max_depth, 100);
    for _ in 0..100 {
        ctx.pop();
    }
    assert_eq!(ctx.depth, 0);
    assert_eq!(ctx.max_depth, 100, "max_depth must not decrease");
}

#[test]
fn lift_context_overflow_at_4096() {
    let mut ctx = LiftContext::new();
    for i in 0..4096 {
        assert!(ctx.push().is_ok(), "push {i}");
    }
    assert!(matches!(ctx.push(), Err(LiftError::StackOverflow)));
    // After overflow, depth unchanged.
    assert_eq!(ctx.depth, 4096);
}

#[test]
fn lift_context_pop_saturates() {
    let mut ctx = LiftContext::new();
    for _ in 0..50 {
        ctx.pop(); // never panics
    }
    assert_eq!(ctx.depth, 0);
}

#[test]
fn lift_context_temps_roundtrip() {
    let mut g = lcg(0xF00D_F00D_F00D_F00D);
    let mut ctx = LiftContext::new();
    let mut expected = Vec::new();
    for i in 0..50 {
        let v = g();
        let name = format!("t{i}");
        ctx.set_temp(&name, v);
        expected.push((name, v));
    }
    for (n, v) in &expected {
        assert_eq!(ctx.get_temp(n), Some(*v));
    }
    assert_eq!(ctx.get_temp("nonexistent"), None);
}

// ────────────────────────────────────────────────────────────────────────────
// 6. ArchMetadata invariants
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn arch_metadata_fixed_invariants() {
    for sz in [1usize, 2, 4, 8, 16] {
        let m = ArchMetadata::fixed_width(sz, &[0u8; 1], "x");
        assert_eq!(m.min_instr_size, sz);
        assert_eq!(m.max_instr_size, sz);
        assert!(!m.variable_length);
    }
}

#[test]
fn arch_metadata_variable_invariants() {
    for (a, b) in [(1usize, 15), (1, 2), (2, 16), (4, 8)] {
        let m = ArchMetadata::variable_width(a, b, &[0x90], "v");
        assert_eq!(m.min_instr_size, a);
        assert_eq!(m.max_instr_size, b);
        assert!(m.variable_length);
        assert_eq!(m.nop_bytes, vec![0x90]);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 7. ArchRegistry — concurrency / threaded stress (Send+Sync)
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn arch_registry_thread_stress() {
    let reg = Arc::new(ArchRegistry::new());
    reg.register(stub());
    let mut handles = vec![];
    for tid in 0..4 {
        let r = Arc::clone(&reg);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                assert!(r.find("stub_blitz2").is_some(), "thread {tid} iter {i}");
                let _ = r.names();
                let _ = r.len();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(reg.len(), 1);
}

#[test]
fn arch_registry_remove_idempotent() {
    let reg = ArchRegistry::new();
    reg.register(stub());
    assert!(reg.remove("stub_blitz2"));
    assert!(!reg.remove("stub_blitz2"));
    assert!(!reg.remove("never_existed"));
}

#[test]
fn arch_registry_register_with_meta_lookup() {
    let reg = ArchRegistry::new();
    let m = ArchMetadata::fixed_width(4, &[0], "Stub");
    reg.register_with_meta(stub(), m);
    assert!(reg.metadata("stub_blitz2").is_some());
    assert!(reg.metadata("xyz").is_none());
}

#[test]
fn arch_registry_find_for_binary_pe_x86_64() {
            // The local type is declared BEFORE the first statement: an item
        // after a statement is confusing because items exist from the start
        // of the scope regardless of where they are written.
    #[derive(Debug)]
    struct A;
    impl Architecture for A {
        fn name(&self) -> &'static str {
            "x86_64"
        }
        fn pointer_size(&self) -> usize {
            8
        }
        fn endian(&self) -> Endian {
            Endian::Little
        }
        fn disassemble(&self, _: Address, _: &[u8]) -> Result<Instruction, CoreError> {
            Err(CoreError::unsupported("x"))
        }
        fn get_branches(&self, _: &Instruction) -> Vec<BranchInfo> {
            vec![]
        }
        fn registers(&self) -> Vec<RegisterInfo> {
            vec![]
        }
        fn calling_conventions(&self) -> Vec<CallingConvention> {
            vec![]
        }
    }
        let reg = ArchRegistry::new();
    reg.register(Arc::new(A));
    let buf = make_pe(0x8664);
    assert!(reg.find_for_binary(&buf).is_some());
}

// ────────────────────────────────────────────────────────────────────────────
// 8. global_registry + register_all_builtins
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn global_registry_register_all_builtins() {
    register_all_builtins();
    let g = global_registry();
    for name in [
        "x86", "x86_64", "arm", "arm64", "mips", "mips64", "ppc", "ppc64", "riscv32", "riscv64",
        "sparc", "sparc64", "msp430", "avr", "6502", "z80", "68k", "bpf", "wasm", "jvm", "cil",
        "luajit", "dex",
    ] {
        assert!(g.contains_key(name), "{name}");
    }
}

#[test]
fn global_registry_idempotent_register() {
    register_all_builtins();
    let n1 = global_registry().len();
    register_all_builtins();
    let n2 = global_registry().len();
    assert_eq!(n1, n2);
}

// ────────────────────────────────────────────────────────────────────────────
// 9. InstrStats accumulator properties
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn instr_stats_total_invariant() {
    let mut g = lcg(0x00C0_FFEE_C0FF_EE42_u64);
    for n in [0usize, 1, 10, 100, 500] {
        let instrs: Vec<Instruction> = (0..n)
            .map(|i| {
                let flag_bits = (g() & 0x3F) as u32;
                let flags = InstrFlags::from_bits_truncate(flag_bits);
                mk_instr(i as u64, flags)
            })
            .collect();
        let s = InstrStats::from_slice(&instrs);
        assert_eq!(s.total, n);
        assert!(s.branches <= s.total);
        assert!(s.calls <= s.total);
        assert!(s.returns <= s.total);
        let bd = s.branch_density();
        assert!((0.0..=1.0).contains(&bd));
    }
}

#[test]
fn instr_stats_empty_density_zero() {
    let s = InstrStats::default();
    assert_eq!(s.branch_density().to_bits(), 0.0_f64.to_bits());
}

#[test]
fn extended_instr_stats_total_invariant() {
    let mut g = lcg(0x9999_AAAA_BBBB_CCCC);
    for n in [0usize, 1, 50, 200] {
        let instrs: Vec<Instruction> = (0..n)
            .map(|i| {
                let bits = (g() & 0xFF) as u32;
                mk_instr(i as u64, InstrFlags::from_bits_truncate(bits))
            })
            .collect();
        let s = ExtendedInstrStats::compute(&instrs);
        assert_eq!(s.total as usize, n);
        for v in [
            s.calls,
            s.branches,
            s.returns,
            s.syscalls,
            s.nops,
            s.memory_reads,
            s.memory_writes,
            s.privileged,
        ] {
            assert!(v <= s.total);
        }
        let md = s.memory_density();
        assert!(md.is_finite() && md >= 0.0);
    }
}

#[test]
fn extended_stats_display_contains_total() {
    let s = ExtendedInstrStats::compute(&[mk_instr(0, InstrFlags::CALL)]);
    let d = format!("{s}");
    assert!(d.contains("total=1"));
    assert!(d.contains("calls=1"));
}

// ────────────────────────────────────────────────────────────────────────────
// 10. RegisterFile properties
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn register_file_write_read_roundtrip() {
    let mut g = lcg(0x1111_2222_3333_4444);
    let mut rf = RegisterFile::new("x");
    let mut pairs = vec![];
    for i in 0..50 {
        let v = g();
        rf.write(i, v);
        pairs.push((i, v));
    }
    for (id, v) in &pairs {
        assert_eq!(rf.read(*id), *v);
        assert!(rf.has(*id));
    }
    assert_eq!(rf.read(9999), 0);
    assert!(!rf.has(9999));
}

#[test]
fn register_file_zero_all_keeps_keys() {
    let mut rf = RegisterFile::new("x");
    rf.write(0, 7);
    rf.write(1, 9);
    let len = rf.len();
    rf.zero_all();
    assert_eq!(rf.len(), len);
    assert_eq!(rf.read(0), 0);
    assert_eq!(rf.read(1), 0);
    assert!(rf.has(0));
}

#[test]
fn register_file_zeroed_from_arch() {
    let s = StubArch { name: "x" };
    let rf = RegisterFile::zeroed(&s);
    assert_eq!(rf.len(), 2);
    assert_eq!(rf.read(0), 0);
    assert_eq!(rf.read(1), 0);
    assert_eq!(rf.arch_name(), "x");
}

// ────────────────────────────────────────────────────────────────────────────
// 11. Linear disassembly — boundary + fuzz
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn linear_disasm_empty() {
    let d = LinearDisassembler::new(stub());
    let s = d.disassemble(Address::new(0), &[]);
    assert!(s.is_empty());
    assert!(s.errors.is_empty());
}

#[test]
fn linear_disasm_all_errors_non_strict() {
    let d = LinearDisassembler::new(stub());
    let s = d.disassemble(Address::new(0), &[0xFF; 10]);
    assert!(s.instructions.is_empty());
    assert_eq!(s.errors.len(), 10);
}

#[test]
fn linear_disasm_count_zero_decodes_nothing() {
    let d = LinearDisassembler::new(stub());
    let s = d.disassemble_count(Address::new(0), &[0u8; 5], 0);
    assert_eq!(s.len(), 0);
}

#[test]
fn linear_disasm_fuzz_random_bytes_no_panic() {
    let d = LinearDisassembler::new(stub());
    let mut g = lcg(0x7777_8888_9999_AAAA);
    for _ in 0..50 {
        let n = usize::try_from(g()).expect("fits in usize") % 128;
        let mut buf = Vec::with_capacity(n);
        for _ in 0..n {
            buf.push((g() & 0xFF) as u8);
        }
        let s = d.disassemble(Address::new(0x1000), &buf);
        assert!(s.len() + s.errors.len() >= n.min(1));
    }
}

#[test]
fn disassemble_linear_free_fn_addr_wraps() {
    let s = stub();
    // base near u64::MAX so offset wraps.
    let r = disassemble_linear(&*s, &[0x00, 0x00], u64::MAX - 1, 0);
    assert_eq!(r.instructions.len(), 2);
    assert_eq!(r.instructions[0].address.0, u64::MAX - 1);
    assert_eq!(r.instructions[1].address.0, u64::MAX);
}

#[test]
fn disassemble_linear_max_instrs_zero_means_unlimited() {
    let s = stub();
    let r = disassemble_linear(&*s, &[0x00; 32], 0, 0);
    assert_eq!(r.instructions.len(), 32);
}

#[test]
fn disassemble_linear_total_bytes_consistency() {
    let s = stub();
    let r = disassemble_linear(&*s, &[0x00; 16], 0, 0);
    let bytes: usize = r.instructions.iter().map(|i| i.size).sum();
    assert_eq!(r.total_bytes, bytes);
}

// ────────────────────────────────────────────────────────────────────────────
// 12. Recursive disassembly — boundary + fuzz
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn recursive_disasm_entry_out_of_range() {
    let d = RecursiveDisassembler::new(stub());
    let s = d.disassemble(Address::new(0), &[0u8; 4], Address::new(100));
    assert!(s.instructions.is_empty());
    assert_eq!(s.errors.len(), 1);
}

#[test]
fn recursive_disasm_empty_bytes() {
    let d = RecursiveDisassembler::new(stub());
    let s = d.disassemble(Address::new(0), &[], Address::new(0));
    assert!(s.is_empty());
}

#[test]
fn recursive_disasm_max_instrs_respected() {
    let mut d = RecursiveDisassembler::new(stub());
    d.max_instrs = 5;
    let s = d.disassemble(Address::new(0), &[0u8; 100], Address::new(0));
    assert!(s.len() <= 5);
}

#[test]
fn disassemble_recursive_free_fn_below_base() {
    let s = stub();
    let r = disassemble_recursive(&*s, &[0u8; 8], 100, 50);
    assert!(r.instructions.is_empty());
    assert!(!r.errors.is_empty());
}

#[test]
fn disassemble_recursive_sorts_instrs_by_addr() {
    let s = stub();
    let r = disassemble_recursive(&*s, &[0x00; 16], 0x1000, 0x1000);
    let mut prev = 0u64;
    for i in &r.instructions {
        assert!(i.address.0 >= prev);
        prev = i.address.0;
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 13. DisasmFilter
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn disasm_filter_accept_all_matches_everything() {
    let f = DisasmFilter::accept_all();
    for flags in [InstrFlags::NONE, InstrFlags::CALL, InstrFlags::BRANCH] {
        assert!(f.matches(&mk_instr(0, flags)));
    }
}

#[test]
fn disasm_filter_branches_only() {
    let f = DisasmFilter::branches_only();
    assert!(f.matches(&mk_instr(0, InstrFlags::BRANCH)));
    assert!(!f.matches(&mk_instr(0, InstrFlags::NONE)));
    assert!(!f.matches(&mk_instr(0, InstrFlags::CALL)));
}

#[test]
fn disasm_filter_calls_only() {
    let f = DisasmFilter::calls_only();
    assert!(f.matches(&mk_instr(0, InstrFlags::CALL)));
    assert!(!f.matches(&mk_instr(0, InstrFlags::BRANCH)));
}

#[test]
fn disasm_filter_excluded_flags() {
    let mut f = DisasmFilter::accept_all();
    f.excluded_flags = Some(InstrFlags::RET);
    assert!(!f.matches(&mk_instr(0, InstrFlags::RET)));
    assert!(f.matches(&mk_instr(0, InstrFlags::CALL)));
}

#[test]
fn disasm_filter_mnemonic_contains() {
    let mut f = DisasmFilter::accept_all();
    f.mnemonic_contains = Some("e8".into());
    let s = stub();
    let i = s.disassemble(Address::new(0), &[0xE8]).unwrap();
    assert!(f.matches(&i));
    let i2 = s.disassemble(Address::new(0), &[0x00]).unwrap();
    assert!(!f.matches(&i2));
}

#[test]
fn disasm_filter_apply_preserves_errors() {
    let mut stream = InstrStream::new();
    stream
        .instructions
        .push(mk_instr(0, InstrFlags::BRANCH));
    stream.instructions.push(mk_instr(1, InstrFlags::NONE));
    stream.errors.push((Address::new(2), "x".into()));
    let f = DisasmFilter::branches_only();
    let out = f.apply(&stream);
    assert_eq!(out.instructions.len(), 1);
    assert_eq!(out.errors.len(), 1);
}

// ────────────────────────────────────────────────────────────────────────────
// 14. DisasmCache thread stress
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn disasm_cache_basic_roundtrip() {
    let c = DisasmCache::new();
    assert!(c.is_empty());
    let i = mk_instr(0x100, InstrFlags::CALL);
    c.insert(i);
    assert!(c.contains(0x100));
    assert_eq!(c.get(0x100).map(|x| x.address.0), Some(0x100));
    assert_eq!(c.len(), 1);
    c.clear();
    assert!(c.is_empty());
}

#[test]
fn disasm_cache_thread_stress() {
    let c = Arc::new(DisasmCache::new());
    let mut handles = vec![];
    for t in 0..4 {
        let c = Arc::clone(&c);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let addr = u64::from(u32::try_from(t * 10_000 + i).unwrap());
                c.insert(mk_instr(addr, InstrFlags::NONE));
                assert!(c.contains(addr));
                assert!(c.get(addr).is_some());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(c.len(), 400);
}

// ────────────────────────────────────────────────────────────────────────────
// 15. ModeDetector — Thumb-bit conventions
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn mode_detector_thumb_bit_addr_is_thumb() {
    let m = ModeDetector::detect_arm_mode(&[], 0x1001, &[]);
    assert_eq!(m, ArchMode::Thumb);
}

#[test]
fn mode_detector_even_addr_default() {
    let m = ModeDetector::detect_arm_mode(&[], 0x1000, &[]);
    assert_eq!(m, ArchMode::Default);
}

#[test]
fn mode_detector_symbol_table_thumb_flag() {
    let st = vec![(0x1001u64, "f".to_string())];
    let m = ModeDetector::detect_arm_mode(&[], 0x1000, &st);
    assert_eq!(m, ArchMode::Thumb);
}

#[test]
fn mode_detector_code_addr_strips_bit() {
    assert_eq!(ModeDetector::code_addr(0x1001), 0x1000);
    assert_eq!(ModeDetector::code_addr(0x1000), 0x1000);
    assert_eq!(ModeDetector::thumb_symbol_value(0x1000), 0x1001);
    assert_eq!(ModeDetector::thumb_symbol_value(0x1001), 0x1001);
}

#[test]
fn mode_detector_is_thumb_helper() {
    assert!(ModeDetector::is_thumb(0x1001, &[]));
    assert!(!ModeDetector::is_thumb(0x1000, &[]));
}

#[test]
fn mode_detector_thumb_roundtrip_property() {
    let mut g = lcg(0xAABB_CCDD_EE11_2233);
    for _ in 0..50 {
        let code = g() & !1u64;
        let sym = ModeDetector::thumb_symbol_value(code);
        assert_eq!(ModeDetector::code_addr(sym), code);
        assert!(ModeDetector::is_thumb(sym, &[]));
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 16. DecodeError/EncodeError/LiftError equality and hash
// ────────────────────────────────────────────────────────────────────────────

fn hash_one<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

#[test]
fn decode_error_eq_consistency() {
    let pairs = [
        (DecodeError::Invalid, DecodeError::Invalid),
        (DecodeError::Truncated, DecodeError::Truncated),
        (
            DecodeError::Other("x".into()),
            DecodeError::Other("x".into()),
        ),
    ];
    for (a, b) in &pairs {
        assert_eq!(a, b);
    }
    assert_ne!(DecodeError::Invalid, DecodeError::Truncated);
}

#[test]
fn encode_error_eq_consistency() {
    assert_eq!(EncodeError::InvalidOperand, EncodeError::InvalidOperand);
    assert_eq!(EncodeError::Unsupported, EncodeError::Unsupported);
    assert_ne!(EncodeError::InvalidOperand, EncodeError::Unsupported);
    assert_eq!(
        EncodeError::Other("a".into()),
        EncodeError::Other("a".into())
    );
}

#[test]
fn lift_error_eq_consistency() {
    assert_eq!(LiftError::Unsupported, LiftError::Unsupported);
    assert_eq!(LiftError::StackOverflow, LiftError::StackOverflow);
    assert_ne!(LiftError::Unsupported, LiftError::StackOverflow);
}

// ────────────────────────────────────────────────────────────────────────────
// 17. InstrStats: Hash/Eq consistency on 30+ pairs
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn address_hash_eq_consistency() {
    let mut g = lcg(0x4242_4242_4242_4242);
    let mut seen: HashSet<u64> = HashSet::new();
    for _ in 0..30 {
        let v = g();
        let a = Address::new(v);
        let b = Address::new(v);
        assert_eq!(a, b);
        assert_eq!(hash_one(&a), hash_one(&b));
        seen.insert(hash_one(&a));
    }
    assert!(seen.len() > 1, "lcg should yield distinct hashes");
}

#[test]
fn instr_stats_eq_clone_consistency() {
    let mut next_rand = lcg(0x9999_1111_2222_3333);
    for _ in 0..30 {
        let instr_count = usize::try_from(next_rand() & 0xF).expect("masked to 4 bits");
        let instrs: Vec<Instruction> = (0..instr_count)
            .map(|idx| {
                mk_instr(
                    idx as u64,
                    InstrFlags::from_bits_truncate(
                        u32::try_from(next_rand() & 0xFF).expect("masked to 8 bits"),
                    ),
                )
            })
            .collect();
        let a = InstrStats::from_slice(&instrs);
        let b = a.clone();
        assert_eq!(a, b);
        let c = ExtendedInstrStats::compute(&instrs);
        let d = c.clone();
        assert_eq!(c, d);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 18. InstrStream
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn instr_stream_default_new_consistent() {
    let a = InstrStream::new();
    let b = InstrStream::default();
    assert_eq!(a.len(), b.len());
    assert!(a.is_empty() && b.is_empty());
}

#[test]
fn instr_stream_stats_matches_from_slice() {
    let mut s = InstrStream::new();
    s.instructions.push(mk_instr(0, InstrFlags::BRANCH));
    s.instructions.push(mk_instr(1, InstrFlags::CALL));
    let st = s.stats();
    let direct = InstrStats::from_slice(&s.instructions);
    assert_eq!(st, direct);
}

// ────────────────────────────────────────────────────────────────────────────
// 19. DisassemblyResult
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn disassembly_result_default_invariants() {
    let r = DisassemblyResult::new();
    assert_eq!(r.len(), 0);
    assert!(r.is_empty());
    assert_eq!(r.total_bytes, 0);
}
