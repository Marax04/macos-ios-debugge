//! Exhaustive integration tests for rustre-arch.
//!
//! These tests exercise the public API via integration boundaries (no `super::`
//! access), targeting boundaries, error paths, format detection, parser
//! adversarial inputs, and dead-code public functions.

use std::sync::Arc;

use rustre_arch::arch_meta::{
    ArchMetadata as MetaRich, EncodeContext, FixupKind, IsaExtension, MemoryModel, PointerModel,
};
use rustre_arch::{
    Address, ArchMetadata, ArchMode, ArchRegistry, Architecture, BranchInfo, CallingConvention,
    DecodeError, DisasmCache, DisasmFilter, DisassemblyResult, EncodeError, Endian,
    ExtendedInstrStats, InstrFlags, InstrStats, InstrStream, Instruction, LiftContext, LiftError,
    LinearDisassembler, ModeDetector, RecursiveDisassembler, RegisterFile, RegisterInfo,
    detect_arch_from_bytes, detect_from_elf, detect_from_macho, detect_from_pe,
    disassemble_linear, disassemble_recursive, global_registry, register_all_builtins,
};
use rustre_core::CoreError;

// ─── Stub architecture ───────────────────────────────────────────────────────

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
            0x89 => InstrFlags::WRITE_MEM,
            0x90 => InstrFlags::NOP,
            0x0F => InstrFlags::SYSCALL,
            0xFA => InstrFlags::PRIVILEGED,
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
            let kind = if instr.flags.contains(InstrFlags::CONDITIONAL) {
                BranchKind::ConditionalJump
            } else {
                BranchKind::UnconditionalJump
            };
            let cond = if instr.flags.contains(InstrFlags::CONDITIONAL) {
                BranchCondition::Equal
            } else {
                BranchCondition::Always
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
        vec![CallingConvention::new("stub")]
    }
}

fn stub() -> Arc<dyn Architecture> {
    Arc::new(StubArch { name: "stub" })
}
fn named(n: &'static str) -> Arc<dyn Architecture> {
    Arc::new(StubArch { name: n })
}
fn instr(addr: u64, flags: InstrFlags) -> Instruction {
    let mut i = Instruction::new(Address::new(addr), 1, "x", vec![0]);
    i.flags = flags;
    i
}

// ─── DecodeError / EncodeError / LiftError ───────────────────────────────────

#[test]
fn decode_error_variants_distinct() {
    assert_ne!(DecodeError::Invalid, DecodeError::Truncated);
    assert_eq!(DecodeError::Invalid, DecodeError::Invalid);
    let cloned = DecodeError::Other("x".into());
    assert_eq!(cloned, DecodeError::Other("x".into()));
}

#[test]
fn encode_error_display_strings() {
    assert_eq!(EncodeError::InvalidOperand.to_string(), "invalid operand");
    assert_eq!(EncodeError::Unsupported.to_string(), "unsupported instruction");
    assert!(EncodeError::Other("z".into()).to_string().contains('z'));
}

#[test]
fn lift_error_eq_and_clone() {
    let a = LiftError::StackOverflow;
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(LiftError::Unsupported, LiftError::StackOverflow);
}

// ─── LiftContext ─────────────────────────────────────────────────────────────

#[test]
fn lift_context_default_state() {
    let c = LiftContext::new();
    assert_eq!(c.depth, 0);
    assert_eq!(c.max_depth, 0);
    assert!(c.temps.is_empty());
    assert!(!c.has_warnings());
}

#[test]
fn lift_context_overflow_exact_boundary() {
    let mut c = LiftContext::new();
    for _ in 0..4096 {
        c.push().unwrap();
    }
    assert_eq!(c.depth, 4096);
    assert_eq!(c.push(), Err(LiftError::StackOverflow));
    assert_eq!(c.max_depth, 4096);
}

#[test]
fn lift_context_pop_below_zero_clamps() {
    let mut c = LiftContext::new();
    for _ in 0..10 {
        c.pop();
    }
    assert_eq!(c.depth, 0);
}

#[test]
fn lift_context_temp_overwrite() {
    let mut c = LiftContext::new();
    c.set_temp("a", 1);
    c.set_temp("a", 99);
    assert_eq!(c.get_temp("a"), Some(99));
}

#[test]
fn lift_context_warnings_accumulate() {
    let mut c = LiftContext::new();
    c.warn("a");
    c.warn("b");
    assert_eq!(c.warnings, vec!["a".to_string(), "b".to_string()]);
}

// ─── ArchMetadata (lib.rs simple version) ────────────────────────────────────

#[test]
fn lib_arch_metadata_fixed_width() {
    let m = ArchMetadata::fixed_width(4, &[0, 0, 0, 0], "Risc");
    assert_eq!(m.min_instr_size, m.max_instr_size);
    assert!(!m.variable_length);
    assert_eq!(m.nop_bytes.len(), 4);
    assert_eq!(m.description, "Risc");
}

#[test]
fn lib_arch_metadata_variable_width() {
    let m = ArchMetadata::variable_width(1, 15, &[0x90], "x86");
    assert!(m.variable_length);
    assert_eq!(m.min_instr_size, 1);
    assert_eq!(m.max_instr_size, 15);
}

// ─── ArchRegistry ────────────────────────────────────────────────────────────

#[test]
fn registry_empty_state() {
    let r = ArchRegistry::new();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
    assert!(r.find("anything").is_none());
    assert!(r.metadata("anything").is_none());
    assert!(r.names().is_empty());
}

#[test]
fn registry_register_multiple_and_lookup() {
    let r = ArchRegistry::new();
    r.register(named("a"));
    r.register(named("b"));
    r.register(named("c"));
    assert_eq!(r.len(), 3);
    assert!(r.find("a").is_some());
    assert!(r.find("b").is_some());
    assert!(r.find("c").is_some());
    let names = r.names();
    assert!(names.contains(&"a".to_string()));
    assert!(names.contains(&"c".to_string()));
}

#[test]
fn registry_remove_returns_bool_and_shrinks() {
    let r = ArchRegistry::new();
    r.register(named("a"));
    r.register(named("b"));
    assert!(r.remove("a"));
    assert_eq!(r.len(), 1);
    assert!(!r.remove("a"));
}

#[test]
fn registry_metadata_only_when_registered_with_meta() {
    let r = ArchRegistry::new();
    r.register(named("plain"));
    r.register_with_meta(
        named("rich"),
        ArchMetadata::fixed_width(4, &[0], "rich"),
    );
    assert!(r.metadata("plain").is_none());
    assert!(r.metadata("rich").is_some());
}

#[test]
fn registry_find_for_binary_uses_detection() {
    let r = ArchRegistry::new();
    r.register(named("x86_64"));
    // Minimal ELF64 LE x86_64 header (20 bytes is enough for detect_from_elf).
    let mut elf = vec![0u8; 20];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // 64-bit
    elf[5] = 1; // little-endian
    elf[18] = 62;
    elf[19] = 0;
    assert!(r.find_for_binary(&elf).is_some());
}

#[test]
fn registry_register_global_inserts_into_singleton() {
    let r = ArchRegistry::new();
    let a = named("unique-test-arch-blitz");
    r.register_global(a);
    assert!(global_registry().contains_key("unique-test-arch-blitz"));
    assert!(r.find("unique-test-arch-blitz").is_some());
}

#[test]
fn registry_iter_names_matches_names() {
    let r = ArchRegistry::new();
    r.register(named("q"));
    r.register(named("w"));
    let mut a = r.names();
    let mut b = r.iter_names();
    a.sort();
    b.sort();
    assert_eq!(a, b);
}

#[test]
fn registry_debug_includes_count() {
    let r = ArchRegistry::new();
    r.register(named("x"));
    r.register(named("y"));
    let s = format!("{r:?}");
    assert!(s.contains("ArchRegistry"));
    assert!(s.contains('2'));
}

// ─── InstrStats / ExtendedInstrStats ─────────────────────────────────────────

#[test]
fn instr_stats_zero_total_density_zero() {
    let s = InstrStats::default();
    assert_eq!(s.total, 0);
    assert_eq!(s.branch_density().to_bits(), 0.0_f64.to_bits());
}

#[test]
fn instr_stats_from_slice_counts_all_flags() {
    let items = vec![
        instr(0, InstrFlags::BRANCH),
        instr(1, InstrFlags::CALL),
        instr(2, InstrFlags::RET),
        instr(3, InstrFlags::READ_MEM),
        instr(4, InstrFlags::WRITE_MEM),
        instr(5, InstrFlags::BRANCH | InstrFlags::CONDITIONAL),
    ];
    let s = InstrStats::from_slice(&items);
    assert_eq!(s.total, 6);
    assert_eq!(s.branches, 2);
    assert_eq!(s.calls, 1);
    assert_eq!(s.returns, 1);
    assert_eq!(s.conditionals, 1);
    assert_eq!(s.memory_ops, 2);
}

#[test]
fn instr_stats_display_contains_fields() {
    let s = InstrStats::from_slice(&[instr(0, InstrFlags::BRANCH)]);
    let d = s.to_string();
    for needle in ["total=", "branches=", "calls=", "returns=", "memory_ops="] {
        assert!(d.contains(needle), "missing {needle} in {d}");
    }
}

#[test]
fn extended_stats_all_categories() {
    let items = vec![
        instr(0, InstrFlags::CALL),
        instr(1, InstrFlags::BRANCH),
        instr(2, InstrFlags::RET),
        instr(3, InstrFlags::SYSCALL),
        instr(4, InstrFlags::NOP),
        instr(5, InstrFlags::READ_MEM),
        instr(6, InstrFlags::WRITE_MEM),
        instr(7, InstrFlags::PRIVILEGED),
    ];
    let s = ExtendedInstrStats::compute(&items);
    assert_eq!(s.total, 8);
    assert_eq!(s.calls, 1);
    assert_eq!(s.branches, 1);
    assert_eq!(s.returns, 1);
    assert_eq!(s.syscalls, 1);
    assert_eq!(s.nops, 1);
    assert_eq!(s.memory_reads, 1);
    assert_eq!(s.memory_writes, 1);
    assert_eq!(s.privileged, 1);
}

#[test]
fn extended_stats_densities_empty_safe() {
    let s = ExtendedInstrStats::default();
    assert_eq!(s.call_density().to_bits(), 0.0_f64.to_bits());
    assert_eq!(s.branch_density().to_bits(), 0.0_f64.to_bits());
    assert_eq!(s.return_density().to_bits(), 0.0_f64.to_bits());
    assert_eq!(s.nop_density().to_bits(), 0.0_f64.to_bits());
    assert_eq!(s.memory_density().to_bits(), 0.0_f64.to_bits());
}

#[test]
fn extended_stats_densities_compute() {
    let items = vec![
        instr(0, InstrFlags::CALL),
        instr(1, InstrFlags::CALL),
        instr(2, InstrFlags::NONE),
        instr(3, InstrFlags::NONE),
    ];
    let s = ExtendedInstrStats::compute(&items);
    assert!((s.call_density() - 0.5).abs() < 1e-9);
}

#[test]
fn extended_stats_display_has_all_fields() {
    let d = ExtendedInstrStats::default().to_string();
    for needle in [
        "total=", "calls=", "branches=", "returns=", "syscalls=", "nops=", "mem_reads=",
        "mem_writes=", "privileged=",
    ] {
        assert!(d.contains(needle), "missing {needle}");
    }
}

// ─── RegisterFile ────────────────────────────────────────────────────────────

#[test]
fn register_file_unknown_reads_zero() {
    let rf = RegisterFile::new("a");
    assert_eq!(rf.read(0), 0);
    assert_eq!(rf.read(u32::MAX), 0);
    assert!(rf.is_empty());
    assert_eq!(rf.len(), 0);
    assert_eq!(rf.arch_name(), "a");
}

#[test]
fn register_file_write_then_has() {
    let mut rf = RegisterFile::new("a");
    rf.write(7, 0xCAFE);
    assert!(rf.has(7));
    assert!(!rf.has(8));
    assert_eq!(rf.read(7), 0xCAFE);
    assert_eq!(rf.len(), 1);
}

#[test]
fn register_file_zeroed_populates_from_arch() {
    let rf = RegisterFile::zeroed(&*stub());
    assert_eq!(rf.len(), 2);
    assert!(rf.has(0));
    assert!(rf.has(1));
}

#[test]
fn register_file_overwrite_value() {
    let mut rf = RegisterFile::new("a");
    rf.write(0, 1);
    rf.write(0, 2);
    assert_eq!(rf.read(0), 2);
    assert_eq!(rf.len(), 1);
}

#[test]
fn register_file_zero_all_keeps_keys() {
    let mut rf = RegisterFile::new("a");
    rf.write(1, 11);
    rf.write(2, 22);
    rf.zero_all();
    assert!(rf.has(1));
    assert!(rf.has(2));
    assert_eq!(rf.read(1), 0);
    assert_eq!(rf.read(2), 0);
}

// ─── InstrStream ─────────────────────────────────────────────────────────────

#[test]
fn instr_stream_new_is_empty() {
    let s = InstrStream::new();
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
    assert_eq!(s.stats().total, 0);
}

#[test]
fn instr_stream_default_eq_new() {
    let a = InstrStream::default();
    let b = InstrStream::new();
    assert_eq!(a.len(), b.len());
}

// ─── LinearDisassembler ──────────────────────────────────────────────────────

#[test]
fn linear_disasm_empty_input() {
    let d = LinearDisassembler::new(stub());
    let s = d.disassemble(Address::new(0), &[]);
    assert!(s.is_empty());
}

#[test]
fn linear_disasm_all_bad_bytes_non_strict() {
    let d = LinearDisassembler::new(stub());
    let s = d.disassemble(Address::new(0), &[0xFF, 0xFF, 0xFF]);
    assert_eq!(s.errors.len(), 3);
    assert!(s.is_empty());
}

#[test]
fn linear_disasm_strict_records_only_one_error() {
    let mut d = LinearDisassembler::new(stub());
    d.strict = true;
    let s = d.disassemble(Address::new(0), &[0xFF, 0xFF]);
    assert_eq!(s.errors.len(), 1);
    assert!(s.is_empty());
}

#[test]
fn linear_disasm_count_zero_decodes_nothing_or_one() {
    // count=0 means: stream.len() < 0 is false → no iterations.
    let d = LinearDisassembler::new(stub());
    let s = d.disassemble_count(Address::new(0), &[0x00, 0x00], 0);
    assert_eq!(s.len(), 0);
}

#[test]
fn linear_disasm_count_more_than_available() {
    let d = LinearDisassembler::new(stub());
    let s = d.disassemble_count(Address::new(0), &[0x00, 0x00], 100);
    assert_eq!(s.len(), 2);
}

#[test]
fn linear_disasm_address_wraps_safely() {
    let d = LinearDisassembler::new(stub());
    let s = d.disassemble(Address::new(u64::MAX), &[0x00, 0x00]);
    // Both bytes decode; the address calculation must not panic.
    assert_eq!(s.len(), 2);
}

// ─── RecursiveDisassembler ───────────────────────────────────────────────────

#[test]
fn recursive_disasm_starts_at_entry() {
    let d = RecursiveDisassembler::new(stub());
    let s = d.disassemble(Address::new(0x1000), &[0x00; 4], Address::new(0x1000));
    assert!(!s.is_empty());
    assert_eq!(d.arch_name(), "stub");
}

#[test]
fn recursive_disasm_entry_below_base() {
    let d = RecursiveDisassembler::new(stub());
    // entry < base → arithmetic wraps; the rel >= len check filters it out.
    let s = d.disassemble(Address::new(0x1000), &[0x00; 4], Address::new(0x500));
    assert!(s.is_empty());
    assert_eq!(s.errors.len(), 1);
}

#[test]
fn recursive_disasm_respects_max_instrs() {
    let mut d = RecursiveDisassembler::new(stub());
    d.max_instrs = 2;
    let s = d.disassemble(Address::new(0), &[0x00; 100], Address::new(0));
    assert!(s.len() <= 2);
}

#[test]
fn recursive_disasm_visits_branch_target() {
    let d = RecursiveDisassembler::new(stub());
    // Buffer big enough to contain target = entry + 0x10.
    let mut bytes = vec![0x00; 0x40];
    bytes[0] = 0xEB; // unconditional branch from stub → target = 0x10
    let s = d.disassemble(Address::new(0), &bytes, Address::new(0));
    // Should have visited address 0 and 0x10 at minimum.
    assert!(s.instructions.iter().any(|i| i.address.0 == 0x10));
}

// ─── DisasmFilter ────────────────────────────────────────────────────────────

#[test]
fn filter_excluded_flags_drops_matching() {
    let f = DisasmFilter {
        excluded_flags: Some(InstrFlags::BRANCH),
        ..Default::default()
    };
    assert!(!f.matches(&instr(0, InstrFlags::BRANCH)));
    assert!(f.matches(&instr(0, InstrFlags::NONE)));
}

#[test]
fn filter_required_and_excluded_combined() {
    let f = DisasmFilter {
        required_flags: Some(InstrFlags::BRANCH),
        excluded_flags: Some(InstrFlags::CONDITIONAL),
        ..Default::default()
    };
    assert!(f.matches(&instr(0, InstrFlags::BRANCH)));
    assert!(!f.matches(&instr(0, InstrFlags::BRANCH | InstrFlags::CONDITIONAL)));
}

#[test]
fn filter_apply_preserves_errors() {
    let mut stream = InstrStream::new();
    stream.errors.push((Address::new(0), "boom".into()));
    stream.instructions.push(instr(0, InstrFlags::BRANCH));
    stream.instructions.push(instr(1, InstrFlags::NONE));
    let filtered = DisasmFilter::branches_only().apply(&stream);
    assert_eq!(filtered.instructions.len(), 1);
    assert_eq!(filtered.errors.len(), 1);
}

// ─── DisasmCache ─────────────────────────────────────────────────────────────

#[test]
fn cache_overwrite_same_address() {
    let c = DisasmCache::new();
    c.insert(instr(0x10, InstrFlags::NONE));
    c.insert(instr(0x10, InstrFlags::BRANCH));
    assert_eq!(c.len(), 1);
    assert!(c.get(0x10).unwrap().flags.contains(InstrFlags::BRANCH));
}

#[test]
fn cache_clear_empties() {
    let c = DisasmCache::new();
    c.insert(instr(1, InstrFlags::NONE));
    c.insert(instr(2, InstrFlags::NONE));
    assert_eq!(c.len(), 2);
    c.clear();
    assert!(c.is_empty());
}

#[test]
fn cache_get_missing_returns_none() {
    let c = DisasmCache::new();
    assert!(c.get(0xDEAD).is_none());
    assert!(!c.contains(0xDEAD));
}

// ─── Binary format detection ─────────────────────────────────────────────────

#[test]
fn detect_returns_none_when_too_short() {
    assert_eq!(detect_arch_from_bytes(&[]), None);
    assert_eq!(detect_arch_from_bytes(&[0x7f, b'E', b'L']), None);
}

#[test]
fn detect_elf_x86_64_le() {
    let mut e = vec![0u8; 20];
    e[..4].copy_from_slice(b"\x7fELF");
    e[4] = 2;
    e[5] = 1;
    e[18] = 62;
    e[19] = 0;
    assert_eq!(detect_arch_from_bytes(&e).as_deref(), Some("x86_64"));
}

#[test]
fn detect_elf_arm64() {
    let mut e = vec![0u8; 20];
    e[..4].copy_from_slice(b"\x7fELF");
    e[4] = 2;
    e[5] = 1;
    e[18] = 183;
    assert_eq!(detect_from_elf(&e).as_deref(), Some("arm64"));
}

#[test]
fn detect_elf_riscv_class_dependent() {
    let mut e = vec![0u8; 20];
    e[..4].copy_from_slice(b"\x7fELF");
    e[5] = 1;
    e[18] = 243;
    e[4] = 1;
    assert_eq!(detect_from_elf(&e).as_deref(), Some("riscv32"));
    e[4] = 2;
    assert_eq!(detect_from_elf(&e).as_deref(), Some("riscv64"));
}

#[test]
fn detect_elf_big_endian_field() {
    let mut e = vec![0u8; 20];
    e[..4].copy_from_slice(b"\x7fELF");
    e[4] = 2;
    e[5] = 2; // BE
    // e_machine = 62 (x86_64) encoded BE → bytes 0x00, 0x3E.
    e[18] = 0;
    e[19] = 62;
    assert_eq!(detect_from_elf(&e).as_deref(), Some("x86_64"));
}

#[test]
fn detect_elf_unknown_machine() {
    let mut e = vec![0u8; 20];
    e[..4].copy_from_slice(b"\x7fELF");
    e[4] = 2;
    e[5] = 1;
    e[18] = 0xAA;
    e[19] = 0xAA;
    assert!(detect_from_elf(&e).is_none());
}

#[test]
fn detect_elf_too_short() {
    assert!(detect_from_elf(&[0u8; 10]).is_none());
}

#[test]
fn detect_pe_x86_64() {
    let mut pe = vec![0u8; 0x100];
    pe[0] = b'M';
    pe[1] = b'Z';
    let off: u32 = 0x80;
    pe[0x3c..0x40].copy_from_slice(&off.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    assert_eq!(detect_from_pe(&pe).as_deref(), Some("x86_64"));
    assert_eq!(detect_arch_from_bytes(&pe).as_deref(), Some("x86_64"));
}

#[test]
fn detect_pe_invalid_signature() {
    let mut pe = vec![0u8; 0x100];
    pe[0] = b'M';
    pe[1] = b'Z';
    let off: u32 = 0x80;
    pe[0x3c..0x40].copy_from_slice(&off.to_le_bytes());
    // No "PE\0\0" written.
    assert!(detect_from_pe(&pe).is_none());
}

#[test]
fn detect_pe_unknown_machine() {
    let mut pe = vec![0u8; 0x100];
    pe[0] = b'M';
    pe[1] = b'Z';
    let off: u32 = 0x80;
    pe[0x3c..0x40].copy_from_slice(&off.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x84..0x86].copy_from_slice(&0x9999u16.to_le_bytes());
    assert!(detect_from_pe(&pe).is_none());
}

#[test]
fn detect_pe_offset_overflow_safe() {
    let mut pe = vec![0u8; 0x40];
    pe[0] = b'M';
    pe[1] = b'Z';
    let off: u32 = u32::MAX;
    pe[0x3c..0x40].copy_from_slice(&off.to_le_bytes());
    assert!(detect_from_pe(&pe).is_none());
}

#[test]
fn detect_pe_too_short() {
    assert!(detect_from_pe(b"MZ").is_none());
}

#[test]
fn detect_macho_be_x86_64() {
    let mut m = vec![0u8; 8];
    m[..4].copy_from_slice(&0xFEED_FACFu32.to_be_bytes());
    m[4..8].copy_from_slice(&0x0100_0007u32.to_be_bytes());
    assert_eq!(detect_from_macho(&m).as_deref(), Some("x86_64"));
}

#[test]
fn detect_macho_le_arm64() {
    let mut m = vec![0u8; 8];
    m[..4].copy_from_slice(&0xFEED_FACFu32.to_le_bytes());
    m[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes());
    assert_eq!(detect_from_macho(&m).as_deref(), Some("arm64"));
}

#[test]
fn detect_macho_unknown_cputype() {
    let mut m = vec![0u8; 8];
    m[..4].copy_from_slice(&0xFEED_FACEu32.to_be_bytes());
    m[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    assert!(detect_from_macho(&m).is_none());
}

#[test]
fn detect_macho_too_short() {
    assert!(detect_from_macho(&[0u8; 4]).is_none());
}

#[test]
fn detect_arch_unknown_magic() {
    let d = vec![0u8; 32];
    assert!(detect_arch_from_bytes(&d).is_none());
}

// ─── disassemble_linear / disassemble_recursive (free fns) ───────────────────

#[test]
fn free_disasm_linear_unlimited() {
    let a = stub();
    let r = disassemble_linear(&*a, &[0x00; 5], 0x1000, 0);
    assert_eq!(r.len(), 5);
    assert_eq!(r.total_bytes, 5);
    assert!(r.errors.is_empty());
}

#[test]
fn free_disasm_linear_caps_at_max() {
    let a = stub();
    let r = disassemble_linear(&*a, &[0x00; 10], 0, 3);
    assert_eq!(r.len(), 3);
}

#[test]
fn free_disasm_linear_skips_bad_bytes() {
    let a = stub();
    let r = disassemble_linear(&*a, &[0x00, 0xFF, 0x00], 0, 0);
    assert_eq!(r.len(), 2);
    assert_eq!(r.errors.len(), 1);
}

#[test]
fn free_disasm_recursive_basic_flow() {
    let a = stub();
    let r = disassemble_recursive(&*a, &[0x00; 8], 0, 0);
    assert!(!r.instructions.is_empty());
    // Instructions are sorted by address.
    let mut prev = 0;
    for i in &r.instructions {
        assert!(i.address.0 >= prev);
        prev = i.address.0;
    }
}

#[test]
fn free_disasm_recursive_entry_out_of_range() {
    let a = stub();
    let r = disassemble_recursive(&*a, &[0x00; 4], 0, 0x1_0000);
    assert!(r.instructions.is_empty());
    assert!(!r.errors.is_empty());
}

#[test]
fn free_disasm_recursive_entry_below_base() {
    let a = stub();
    let r = disassemble_recursive(&*a, &[0x00; 4], 0x1000, 0x500);
    assert!(r.instructions.is_empty());
    assert!(!r.errors.is_empty());
}

#[test]
fn disassembly_result_default_and_stats() {
    let r = DisassemblyResult::new();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
    assert_eq!(r.stats().total, 0);
}

// ─── Global registry / builtins ──────────────────────────────────────────────

#[test]
fn register_all_builtins_populates_canonical_names() {
    register_all_builtins();
    let g = global_registry();
    for n in ["x86", "x86_64", "arm", "arm64", "mips", "riscv32", "riscv64", "bpf", "wasm"] {
        assert!(g.contains_key(n), "missing {n}");
    }
}

#[test]
fn register_all_builtins_does_not_overwrite_existing() {
    // Insert a named arch that overlaps a builtin name.
    let g = global_registry();
    g.insert("x86_64".to_string(), named("x86_64"));
    let original_ptr = Arc::as_ptr(&g.get("x86_64").unwrap().clone());
    register_all_builtins();
    let after = g.get("x86_64").unwrap().clone();
    assert_eq!(Arc::as_ptr(&after), original_ptr);
}

// ─── ModeDetector ────────────────────────────────────────────────────────────

#[test]
fn mode_detector_raw_thumb_bit() {
    assert_eq!(
        ModeDetector::detect_arm_mode(&[], 0x1001, &[]),
        ArchMode::Thumb
    );
}

#[test]
fn mode_detector_even_address_default() {
    assert_eq!(
        ModeDetector::detect_arm_mode(&[], 0x1000, &[]),
        ArchMode::Default
    );
}

#[test]
fn mode_detector_thumb_symbol_lookup() {
    // Even address but symbol table marks it as Thumb (sym value = addr|1).
    let symtab = vec![(0x2001u64, "foo".to_string())];
    assert_eq!(
        ModeDetector::detect_arm_mode(&[], 0x2000, &symtab),
        ArchMode::Thumb
    );
    assert!(ModeDetector::is_thumb(0x2000, &symtab));
}

#[test]
fn mode_detector_code_addr_and_thumb_value() {
    assert_eq!(ModeDetector::code_addr(0x1001), 0x1000);
    assert_eq!(ModeDetector::code_addr(0x1000), 0x1000);
    assert_eq!(ModeDetector::thumb_symbol_value(0x1000), 0x1001);
    assert_eq!(ModeDetector::thumb_symbol_value(0x1001), 0x1001);
}

#[test]
fn mode_detector_is_thumb_for_odd() {
    assert!(ModeDetector::is_thumb(0x3001, &[]));
    assert!(!ModeDetector::is_thumb(0x3000, &[]));
}

// ─── arch_meta module ────────────────────────────────────────────────────────

#[test]
fn pointer_model_bit_widths() {
    assert_eq!(PointerModel::Ilp32.pointer_bits(), 32);
    assert_eq!(PointerModel::Lp64.pointer_bits(), 64);
    assert_eq!(PointerModel::Llp64.pointer_bits(), 64);
    assert_eq!(PointerModel::Ilp64.pointer_bits(), 64);
    assert_eq!(PointerModel::Ip16.pointer_bits(), 16);
    assert_eq!(
        PointerModel::Custom {
            ptr_bits: 24,
            int_bits: 16,
            long_bits: 24
        }
        .pointer_bits(),
        24
    );
}

#[test]
fn pointer_model_int_long_bits() {
    assert_eq!(PointerModel::Ilp32.int_bits(), 32);
    assert_eq!(PointerModel::Ilp64.int_bits(), 64);
    assert_eq!(PointerModel::Ip16.int_bits(), 16);
    assert_eq!(PointerModel::Llp64.long_bits(), 32);
    assert_eq!(PointerModel::Lp64.long_bits(), 64);
    assert_eq!(PointerModel::Ip16.long_bits(), 16);
}

#[test]
fn pointer_model_display_custom() {
    let s = PointerModel::Custom {
        ptr_bits: 24,
        int_bits: 16,
        long_bits: 24,
    }
    .to_string();
    assert!(s.contains("Custom"));
    assert!(s.contains("ptr=24"));
}

#[test]
fn memory_model_display_strings() {
    assert_eq!(MemoryModel::Tso.to_string(), "TSO");
    assert_eq!(MemoryModel::Weak.to_string(), "Weak");
    assert_eq!(MemoryModel::VeryWeak.to_string(), "VeryWeak");
    assert_eq!(MemoryModel::SeqCst.to_string(), "SeqCst");
}

#[test]
fn isa_extension_display_known() {
    assert_eq!(IsaExtension::Sse2.to_string(), "SSE2");
    assert_eq!(IsaExtension::Avx.to_string(), "AVX");
    assert_eq!(IsaExtension::Neon.to_string(), "NEON");
    assert_eq!(IsaExtension::Custom("MYEXT".into()).to_string(), "MYEXT");
}

#[test]
fn isa_extension_hash_eq() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(IsaExtension::Sse2);
    s.insert(IsaExtension::Sse2);
    assert_eq!(s.len(), 1);
    s.insert(IsaExtension::Custom("a".into()));
    s.insert(IsaExtension::Custom("a".into()));
    assert_eq!(s.len(), 2);
}

#[test]
fn meta_rich_x86_64_defaults() {
    let m = MetaRich::x86_64();
    assert_eq!(m.name, "x86_64");
    assert!(m.is_64bit());
    assert!(!m.is_32bit());
    assert!(m.has_extension(&IsaExtension::Sse2));
    assert_eq!(m.syscall_numbers.get("exit").copied(), Some(60));
    assert_eq!(m.pointer_bits(), 64);
}

#[test]
fn meta_rich_aarch64_fixed_width() {
    let m = MetaRich::aarch64();
    assert_eq!(m.min_instr_size, 4);
    assert_eq!(m.max_instr_size, 4);
    assert!(!m.is_variable_length_isa());
    assert!(m.has_extension(&IsaExtension::Neon));
}

#[test]
fn meta_rich_mips32() {
    let m = MetaRich::mips32();
    assert!(m.is_32bit());
    assert_eq!(m.instruction_alignment, 4);
    assert!(!m.is_variable_length_isa());
}

#[test]
fn meta_rich_builders() {
    let m = MetaRich::new("foo")
        .with_pointer_model(PointerModel::Ilp32)
        .with_memory_model(MemoryModel::SeqCst)
        .big_endian()
        .with_extension(IsaExtension::Custom("bar".into()))
        .with_syscall("nop", 999);
    assert!(!m.is_little_endian);
    assert_eq!(m.pointer_bits(), 32);
    assert_eq!(m.memory_model, MemoryModel::SeqCst);
    assert_eq!(m.syscall_numbers.get("nop").copied(), Some(999));
    assert!(m.has_extension(&IsaExtension::Custom("bar".into())));
}

#[test]
fn meta_rich_variable_length_iff_min_neq_max() {
    let mut m = MetaRich::new("x");
    m.min_instr_size = 1;
    m.max_instr_size = 1;
    assert!(!m.is_variable_length_isa());
    m.max_instr_size = 4;
    assert!(m.is_variable_length_isa());
}

// ─── EncodeContext ───────────────────────────────────────────────────────────

#[test]
fn encode_context_label_define_resolve() {
    let mut c = EncodeContext::new("x86_64", 0x1000, true, 64);
    c.define_label("start");
    c.current_address = 0x1010;
    c.define_label("mid");
    assert_eq!(c.resolve_label("start"), Some(0x1000));
    assert_eq!(c.resolve_label("mid"), Some(0x1010));
    assert_eq!(c.resolve_label("missing"), None);
}

#[test]
fn encode_context_fixups_accumulate() {
    let mut c = EncodeContext::new("a", 0, true, 64);
    c.add_fixup(0, "L", FixupKind::Rel32);
    c.add_fixup(8, "L", FixupKind::Abs64);
    assert_eq!(c.pending_fixups.len(), 2);
    assert_eq!(c.pending_fixups[0].kind, FixupKind::Rel32);
    assert_eq!(c.pending_fixups[1].kind, FixupKind::Abs64);
}

#[test]
fn fixup_kind_eq() {
    assert_eq!(FixupKind::Rel16, FixupKind::Rel16);
    assert_ne!(FixupKind::Rel16, FixupKind::Rel26);
}
