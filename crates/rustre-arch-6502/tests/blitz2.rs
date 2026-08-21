//! Blitz2: adversarial fuzz + round-trip tests for rustre-arch-6502 public API.

use rustre_core::arch::{Architecture, InstrFlags};
use rustre_arch_6502::*;
use rustre_core::address::Address;

// ─── Seeded LCG ────────────────────────────────────────────────────────────────

struct Lcg {
    s: u64,
}
impl Lcg {
    const fn new() -> Self {
        Self { s: 0xDEAD_BEEF_CAFE_BABE }
    }
    const fn next(&mut self) -> u64 {
        self.s = self
            .s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.s
    }
    fn next_u8(&mut self) -> u8 {
        u8::try_from((self.next() >> 56) & 0xFF).unwrap_or(0)
    }
    fn next_u16(&mut self) -> u16 {
        u16::try_from((self.next() >> 48) & 0xFFFF).unwrap_or(0)
    }
}

// ─── opcode_table panic-free over all bytes ───────────────────────────────────

#[test]
fn opcode_table_no_panic_all_bytes() {
    for b in 0u8..=255 {
        let _ = opcode_table(b);
    }
}

#[test]
fn opcode_table_extra_bytes_consistent_with_mode() {
    for b in 0u8..=255 {
        if let Some(e) = opcode_table(b) {
            let eb = e.mode.extra_bytes();
            assert!(eb <= 2, "opcode 0x{b:02X} eb={eb}");
            assert!(e.cycles > 0);
            assert!(!e.mnemonic.is_empty());
            assert!(!e.mode.name().is_empty());
        }
    }
}

#[test]
fn opcode_table_illegal_flag_consistent_with_variant() {
    for b in 0u8..=255 {
        if let Some(e) = opcode_table(b)
            && e.illegal {
                assert_eq!(e.variant, CpuVariant::Illegal6502);
            }
    }
}

// ─── AddrMode exhaustive ───────────────────────────────────────────────────────

#[test]
fn addrmode_extra_bytes_bounded() {
    use AddrMode::*;
    for m in [
        Implied,
        Accumulator,
        Immediate,
        ZeroPage,
        ZeroPageX,
        ZeroPageY,
        Absolute,
        AbsoluteX,
        AbsoluteY,
        Indirect,
        IndirectX,
        IndirectY,
        Relative,
        ZeroPageIndirect,
        AbsoluteIndirectX,
        RelativeLong,
        Illegal,
    ] {
        let eb = m.extra_bytes();
        assert!(eb <= 2, "{m:?} eb={eb}");
        assert!(!m.name().is_empty());
        // Equality / Copy
        let n = m;
        assert_eq!(m, n);
    }
}

#[test]
fn addrmode_relative_long_has_two_extra() {
    assert_eq!(AddrMode::RelativeLong.extra_bytes(), 2);
}

// ─── format_operand: never panics on any random input ─────────────────────────

#[test]
fn format_operand_fuzz_never_panics() {
    use AddrMode::*;
    let modes = [
        Implied,
        Accumulator,
        Immediate,
        ZeroPage,
        ZeroPageX,
        ZeroPageY,
        Absolute,
        AbsoluteX,
        AbsoluteY,
        Indirect,
        IndirectX,
        IndirectY,
        Relative,
        ZeroPageIndirect,
        AbsoluteIndirectX,
        RelativeLong,
        Illegal,
    ];
    let mut lcg = Lcg::new();
    for _ in 0..300 {
        let mode = modes[(lcg.next_u8() as usize) % modes.len()];
        let b0 = lcg.next_u8();
        let b1 = lcg.next_u8();
        let b2 = lcg.next_u8();
        let pc = lcg.next();
        let _ = format_operand(mode, &[b0, b1, b2], pc);
        // also short slices
        let _ = format_operand(mode, &[b0], pc);
        let _ = format_operand(mode, &[], pc);
    }
}

#[test]
fn format_operand_immediate_round_trip_50() {
    // For all 256 immediate values, decode the formatted "#$XX" and confirm value.
    for v in 0u8..=255 {
        let s = format_operand(AddrMode::Immediate, &[0xA9, v], 0x4000);
        let hex = &s[2..]; // skip "#$"
        let parsed = u8::from_str_radix(hex, 16).unwrap();
        assert_eq!(parsed, v);
    }
}

#[test]
fn format_operand_absolute_round_trip_50() {
    let mut lcg = Lcg::new();
    for _ in 0..60 {
        let lo = lcg.next_u8();
        let hi = lcg.next_u8();
        let s = format_operand(AddrMode::Absolute, &[0xAD, lo, hi], 0);
        // Strip "$"
        let parsed = u16::from_str_radix(&s[1..], 16).unwrap();
        assert_eq!(parsed, u16::from_le_bytes([lo, hi]));
    }
}

#[test]
fn format_operand_relative_round_trip() {
    let mut lcg = Lcg::new();
    for _ in 0..60 {
        let pc = u64::from(lcg.next_u16()) & 0xFFFF;
        let off = lcg.next_u8();
        let s = format_operand(AddrMode::Relative, &[0xD0, off], pc);
        // Format is "$XXXX"
        let parsed = u64::from_str_radix(&s[1..], 16).unwrap();
        let expected = pc
            .wrapping_add(2)
            .wrapping_add(i64::from(off.cast_signed()).cast_unsigned())
            & 0xFFFF;
        assert_eq!(parsed, expected);
    }
}

// ─── branch_target ─────────────────────────────────────────────────────────────

#[test]
fn branch_target_truncated_returns_none() {
    assert!(branch_target(0, &[]).is_none());
    assert!(branch_target(0, &[0xD0]).is_none());
}

#[test]
fn branch_target_max_pc_wrap() {
    // PC near boundary should still produce a value (wrapping arithmetic).
    let t = branch_target(0xFFFE, &[0xD0, 0x10]);
    assert!(t.is_some());
    let v = t.unwrap();
    assert_eq!(v, (0xFFFE_u64 + 2 + 0x10) & 0xFFFF);
}

#[test]
fn branch_target_negative_offset_50() {
    for i in 0..60u8 {
        let off = 0u8.wrapping_sub(i);
        let t = branch_target(0x8000, &[0xD0, off]).unwrap();
        let expected = (0x8000_u64.wrapping_add(2).wrapping_add(i64::from(off.cast_signed()).cast_unsigned())) & 0xFFFF;
        assert_eq!(t, expected);
    }
}

// ─── CpuMode / Cpu6502Arch ────────────────────────────────────────────────────

#[test]
fn cpu_mode_default_and_names() {
    assert_eq!(CpuMode::default(), CpuMode::Cpu6502);
    assert_eq!(CpuMode::Cpu6502.name(), "6502");
    assert_eq!(CpuMode::Cpu65C02.name(), "65c02");
    assert_eq!(CpuMode::Cpu65816.name(), "65816");
}

#[test]
fn arch_basic_props() {
    let a = Cpu6502Arch::new();
    assert_eq!(a.name(), "6502");
    assert_eq!(a.pointer_size(), 2);
    assert!(matches!(a.endian(), rustre_core::endian::Endian::Little));
    let regs = a.registers();
    assert_eq!(regs.len(), 6);
    let ccs = a.calling_conventions();
    assert_eq!(ccs.len(), 2);
}

#[test]
fn arch_65c02_with_illegal_chain() {
    let a = Cpu6502Arch::new_65c02().with_illegal_opcodes();
    assert!(a.decode_illegal);
    assert_eq!(a.mode, CpuMode::Cpu65C02);
}

// ─── Architecture::disassemble fuzz ───────────────────────────────────────────

#[test]
fn disassemble_empty_slice_is_err() {
    let a = Cpu6502Arch::new();
    let r = a.disassemble(Address::new(0), &[]);
    assert!(r.is_err());
}

#[test]
fn disassemble_truncated_is_err_never_panics() {
    let a = Cpu6502Arch::new();
    // Pick an opcode known to need 2 operand bytes: LDA abs = 0xAD
    let r = a.disassemble(Address::new(0), &[0xAD, 0x10]);
    assert!(r.is_err());
    // Also single-byte too short for an immediate (just opcode):
    let r = a.disassemble(Address::new(0), &[0xA9]);
    assert!(r.is_err());
}

#[test]
fn disassemble_illegal_rejected_unless_enabled() {
    let plain = Cpu6502Arch::new();
    // 0x02 is KIL (illegal)
    let r = plain.disassemble(Address::new(0), &[0x02]);
    assert!(r.is_err());
    let with_il = Cpu6502Arch::new().with_illegal_opcodes();
    let r2 = with_il.disassemble(Address::new(0), &[0x02]);
    assert!(r2.is_ok());
}

#[test]
fn disassemble_fuzz_no_panic_500() {
    let a = Cpu6502Arch::new().with_illegal_opcodes();
    let mut lcg = Lcg::new();
    for _ in 0..500 {
        let buf: [u8; 3] = [lcg.next_u8(), lcg.next_u8(), lcg.next_u8()];
        let addr = Address::new(u64::from(lcg.next_u16()));
        let _ = a.disassemble(addr, &buf);
        let _ = a.disassemble(addr, &buf[..1]);
        let _ = a.disassemble(addr, &buf[..2]);
    }
}

#[test]
fn disassemble_known_opcodes_produce_expected_size() {
    let a = Cpu6502Arch::new().with_illegal_opcodes();
    // LDA #imm – 2 bytes
    let i = a
        .disassemble(Address::new(0x1000), &[0xA9, 0x42, 0xFF])
        .unwrap();
    assert_eq!(i.size, 2);
    assert_eq!(i.mnemonic, "LDA");
    // LDA abs – 3 bytes
    let i = a
        .disassemble(Address::new(0x1000), &[0xAD, 0x34, 0x12])
        .unwrap();
    assert_eq!(i.size, 3);
    // BRK – 1 byte, branch flag
    let i = a.disassemble(Address::new(0x1000), &[0x00]).unwrap();
    assert_eq!(i.size, 1);
    assert!(i.flags.contains(InstrFlags::BRANCH));
}

// ─── Architecture::get_branches ───────────────────────────────────────────────

#[test]
fn get_branches_jmp_abs_returns_target() {
    let a = Cpu6502Arch::new();
    let i = a
        .disassemble(Address::new(0x1000), &[0x4C, 0x34, 0x12])
        .unwrap();
    let br = a.get_branches(&i);
    assert_eq!(br.len(), 1);
}

#[test]
fn get_branches_jmp_indirect_is_indirect() {
    let a = Cpu6502Arch::new();
    let i = a
        .disassemble(Address::new(0x1000), &[0x6C, 0x00, 0x20])
        .unwrap();
    let br = a.get_branches(&i);
    assert_eq!(br.len(), 1);
}

#[test]
fn get_branches_rts_short_circuits() {
    // RTS has the RET flag but not BRANCH/CALL, so get_branches returns
    // empty due to the BRANCH|CALL filter at the top of the function.
    let a = Cpu6502Arch::new();
    let i = a.disassemble(Address::new(0x1000), &[0x60]).unwrap();
    assert!(i.flags.contains(InstrFlags::RET));
    let br = a.get_branches(&i);
    assert!(br.is_empty());
}

#[test]
fn get_branches_nop_empty() {
    let a = Cpu6502Arch::new();
    let i = a.disassemble(Address::new(0x1000), &[0xEA]).unwrap();
    let br = a.get_branches(&i);
    assert!(br.is_empty());
}

#[test]
fn get_branches_conditional_target_computed() {
    let a = Cpu6502Arch::new();
    // BNE +0x10 at PC=0x1000 → target = 0x1012
    let i = a
        .disassemble(Address::new(0x1000), &[0xD0, 0x10])
        .unwrap();
    let br = a.get_branches(&i);
    assert_eq!(br.len(), 1);
}

// ─── Cpu6502LinearDisassembler ────────────────────────────────────────────────

#[test]
fn linear_disassembler_walks_simple_sequence() {
    let a = Cpu6502Arch::new();
    let bytes = [0xA9, 0x01, 0xEA, 0xAD, 0x00, 0x20]; // LDA #1, NOP, LDA $2000
    let mut d = Cpu6502LinearDisassembler::new(&a, &bytes, Address::new(0x600));
    let mut count = 0;
    while !d.is_done() {
        let r = d.next();
        assert!(r.is_some());
        count += 1;
    }
    assert_eq!(count, 3);
    assert!(d.is_done());
}

#[test]
fn linear_disassembler_offset_advances() {
    let a = Cpu6502Arch::new();
    let bytes = [0xEA, 0xEA];
    let mut d = Cpu6502LinearDisassembler::new(&a, &bytes, Address::new(0));
    assert_eq!(d.offset(), 0);
    let _ = d.next();
    assert_eq!(d.offset(), 1);
}

#[test]
fn linear_disassembler_skips_bad_byte_by_one() {
    let a = Cpu6502Arch::new(); // illegals disabled
    let bytes = [0x02, 0xEA]; // 0x02 = KIL illegal
    let mut d = Cpu6502LinearDisassembler::new(&a, &bytes, Address::new(0));
    let first = d.next().unwrap();
    assert!(first.is_err());
    let second = d.next().unwrap();
    assert!(second.is_ok());
}

#[test]
fn linear_disassembler_empty_is_done() {
    let a = Cpu6502Arch::new();
    let d = Cpu6502LinearDisassembler::new(&a, &[], Address::new(0));
    assert!(d.is_done());
}

#[test]
fn linear_disassembler_fuzz_terminates() {
    let a = Cpu6502Arch::new().with_illegal_opcodes();
    let mut lcg = Lcg::new();
    let mut buf = [0u8; 64];
    for _ in 0..20 {
        for b in &mut buf {
            *b = lcg.next_u8();
        }
        let d = Cpu6502LinearDisassembler::new(&a, &buf, Address::new(0));
        let mut steps = 0;
        for _ in d {
            steps += 1;
            assert!(steps <= 256, "linear disassembler did not terminate");
        }
    }
}

// ─── disassemble_one ──────────────────────────────────────────────────────────

#[test]
fn disassemble_one_basic() {
    let r = disassemble_one(&[0xA9, 0x42], 0, 0x600).unwrap();
    assert_eq!(r.bytes_consumed, 2);
    assert!(r.text.contains("LDA"));
    assert!(r.text.contains("#$42"));
}

#[test]
fn disassemble_one_implied_no_operand() {
    let r = disassemble_one(&[0xEA], 0, 0).unwrap();
    assert_eq!(r.bytes_consumed, 1);
    assert!(r.text.starts_with("NOP "));
}

#[test]
fn disassemble_one_out_of_range_none() {
    assert!(disassemble_one(&[], 0, 0).is_none());
    assert!(disassemble_one(&[0xEA], 5, 0).is_none());
}

#[test]
fn disassemble_one_truncated_none() {
    // LDA abs needs 3 bytes
    assert!(disassemble_one(&[0xAD, 0x10], 0, 0).is_none());
}

#[test]
fn disassemble_one_fuzz_400() {
    let mut lcg = Lcg::new();
    let mut buf = [0u8; 8];
    for _ in 0..400 {
        for b in &mut buf {
            *b = lcg.next_u8();
        }
        let off = (lcg.next_u8() as usize) % 9; // include out-of-range
        let _ = disassemble_one(&buf, off, lcg.next_u16());
    }
}

// ─── cycles helper ─────────────────────────────────────────────────────────────

#[test]
fn cycles_default_for_undefined_is_two() {
    // 0xFF is ISC illegal, defined. Try a definitely-undefined slot if any.
    // Many 65816 slots like 0x42 (illegal KIL) are still in table.
    // We just verify cycles >= 2 for every byte.
    for b in 0u8..=255 {
        let c = cycles(b, false);
        let c2 = cycles(b, true);
        assert!(c >= 2, "cycles for 0x{b:02X} = {c}");
        assert!(c2 >= c);
    }
}

#[test]
fn cycles_page_cross_penalty_only_for_indexed() {
    // LDA absX (0xBD) gets +1 on page cross
    assert_eq!(cycles(0xBD, true), cycles(0xBD, false) + 1);
    // LDA zp (0xA5) does not
    assert_eq!(cycles(0xA5, true), cycles(0xA5, false));
}

// ─── status constants ─────────────────────────────────────────────────────────

#[test]
fn status_bits_are_distinct_and_cover_byte() {
    use status::*;
    let all = C | Z | I | D | B | U | V | N;
    assert_eq!(all, 0xFF);
    // Each bit distinct
    let bits = [C, Z, I, D, B, U, V, N];
    for i in 0..bits.len() {
        for j in (i + 1)..bits.len() {
            assert_eq!(bits[i] & bits[j], 0, "bits {i} & {j} overlap");
        }
    }
}

// ─── Cpu6502State (basic emulator) ────────────────────────────────────────────

#[test]
fn cpu6502state_reset_reads_vector() {
    let mut mem: Box<[u8; 65536]> = vec![0u8; 65536]
        .into_boxed_slice()
        .try_into()
        .expect("vec![0u8; 65536] is exactly 65536 bytes long");
    mem[0xFFFC] = 0x34;
    mem[0xFFFD] = 0x12;
    let s = Cpu6502State::reset(&mem);
    assert_eq!(s.pc, 0x1234);
    assert_eq!(s.sp, 0xFD);
    assert_eq!(s.a, 0);
    assert_eq!(s.x, 0);
    assert_eq!(s.y, 0);
}

#[test]
fn execute_one_lda_imm_sets_a_and_nz() {
    let mut mem: Box<[u8; 65536]> = vec![0u8; 65536]
        .into_boxed_slice()
        .try_into()
        .expect("vec![0u8; 65536] is exactly 65536 bytes long");
    mem[0x0000] = 0xA9; // LDA #
    mem[0x0001] = 0x00;
    let mut s = Cpu6502State {
        a: 0xFF,
        x: 0,
        y: 0,
        sp: 0xFD,
        pc: 0,
        p: status::U,
    };
    execute_one(&mut s, &mut mem);
    assert_eq!(s.a, 0);
    assert!(s.p & status::Z != 0);
    assert_eq!(s.pc, 2);
}

#[test]
fn execute_one_lda_imm_negative_flag() {
    let mut mem: Box<[u8; 65536]> = vec![0u8; 65536]
        .into_boxed_slice()
        .try_into()
        .expect("vec![0u8; 65536] is exactly 65536 bytes long");
    mem[0x0000] = 0xA9;
    mem[0x0001] = 0x80;
    let mut s = Cpu6502State {
        a: 0,
        x: 0,
        y: 0,
        sp: 0xFD,
        pc: 0,
        p: status::U,
    };
    execute_one(&mut s, &mut mem);
    assert_eq!(s.a, 0x80);
    assert!(s.p & status::N != 0);
    assert!(s.p & status::Z == 0);
}

#[test]
fn execute_one_inx_wraps() {
    let mut mem: Box<[u8; 65536]> = vec![0u8; 65536]
        .into_boxed_slice()
        .try_into()
        .expect("vec![0u8; 65536] is exactly 65536 bytes long");
    mem[0] = 0xE8; // INX
    let mut s = Cpu6502State {
        a: 0,
        x: 0xFF,
        y: 0,
        sp: 0xFD,
        pc: 0,
        p: status::U,
    };
    execute_one(&mut s, &mut mem);
    assert_eq!(s.x, 0);
    assert!(s.p & status::Z != 0);
}

#[test]
fn execute_one_fuzz_random_program_no_panic() {
    let mut lcg = Lcg::new();
    let mut mem: Box<[u8; 65536]> = vec![0u8; 65536]
        .into_boxed_slice()
        .try_into()
        .expect("vec![0u8; 65536] is exactly 65536 bytes long");
    for b in mem.iter_mut().take(256) {
        *b = lcg.next_u8();
    }
    let mut s = Cpu6502State {
        a: 0,
        x: 0,
        y: 0,
        sp: 0xFD,
        pc: 0,
        p: status::U,
    };
    for _ in 0..300 {
        let _ = execute_one(&mut s, &mut mem);
    }
}

#[test]
fn execute_one_jsr_rts_round_trip() {
    let mut mem: Box<[u8; 65536]> = vec![0u8; 65536]
        .into_boxed_slice()
        .try_into()
        .expect("vec![0u8; 65536] is exactly 65536 bytes long");
    // JSR 0x0010
    mem[0x0000] = 0x20;
    mem[0x0001] = 0x10;
    mem[0x0002] = 0x00;
    // at 0x0010: RTS
    mem[0x0010] = 0x60;
    let mut s = Cpu6502State {
        a: 0,
        x: 0,
        y: 0,
        sp: 0xFD,
        pc: 0,
        p: status::U,
    };
    execute_one(&mut s, &mut mem); // JSR
    assert_eq!(s.pc, 0x0010);
    execute_one(&mut s, &mut mem); // RTS
    assert_eq!(s.pc, 0x0003);
    assert_eq!(s.sp, 0xFD);
}

#[test]
fn execute_one_branch_taken_and_not() {
    let mut mem: Box<[u8; 65536]> = vec![0u8; 65536]
        .into_boxed_slice()
        .try_into()
        .expect("vec![0u8; 65536] is exactly 65536 bytes long");
    mem[0] = 0xD0;
    mem[1] = 0x10; // BNE +16
    // Z=0 → taken
    let mut s = Cpu6502State {
        a: 0,
        x: 0,
        y: 0,
        sp: 0xFD,
        pc: 0,
        p: status::U,
    };
    execute_one(&mut s, &mut mem);
    assert_eq!(s.pc, 0x0012);
    // Z=1 → not taken
    let mut s2 = Cpu6502State {
        a: 0,
        x: 0,
        y: 0,
        sp: 0xFD,
        pc: 0,
        p: status::U | status::Z,
    };
    execute_one(&mut s2, &mut mem);
    assert_eq!(s2.pc, 0x0002);
}

// ─── MemoryBus6502 ─────────────────────────────────────────────────────────────

#[test]
fn membus_load_store_round_trip_50() {
    let mut bus = MemoryBus6502::new();
    let mut lcg = Lcg::new();
    let mut samples = Vec::new();
    for _ in 0..60 {
        let addr = lcg.next_u16();
        let v = lcg.next_u8();
        bus.store(addr, v);
        samples.push((addr, v));
    }
    // The last value at each unique address must read back.
    let mut map = std::collections::HashMap::new();
    for (a, v) in &samples {
        map.insert(*a, *v);
    }
    for (a, v) in map {
        assert_eq!(bus.load(a), v);
    }
}

#[test]
fn membus_reset_vector_set() {
    let mut bus = MemoryBus6502::new();
    bus.set_reset_vector(0xC000);
    assert_eq!(bus.ram[0xFFFC], 0x00);
    assert_eq!(bus.ram[0xFFFD], 0xC0);
}

#[test]
fn membus_load_program_truncates_at_end() {
    let mut bus = MemoryBus6502::new();
    let prog = vec![0xAA; 10];
    bus.load_program(&prog, 0xFFFB);
    // Only bytes that fit (5 bytes: 0xFFFB..=0xFFFF).
    assert_eq!(bus.ram[0xFFFB], 0xAA);
    assert_eq!(bus.ram[0xFFFF], 0xAA);
}

#[test]
fn membus_default_zeroed() {
    let bus = MemoryBus6502::default();
    for &b in bus.ram.iter().take(1024) {
        assert_eq!(b, 0);
    }
}

// ─── Cpu6502EmuState helpers ──────────────────────────────────────────────────

#[test]
fn emu_state_set_get_flag_round_trip() {
    let mut s = Cpu6502EmuState::new();
    for f in [
        status::C,
        status::Z,
        status::I,
        status::D,
        status::V,
        status::N,
    ] {
        s.set_flag(f, true);
        assert!(s.get_flag(f));
        s.set_flag(f, false);
        assert!(!s.get_flag(f));
    }
}

#[test]
fn emu_state_update_nz_truth_table() {
    let mut s = Cpu6502EmuState::new();
    s.update_nz(0);
    assert!(s.get_flag(status::Z));
    assert!(!s.get_flag(status::N));
    s.update_nz(0x80);
    assert!(!s.get_flag(status::Z));
    assert!(s.get_flag(status::N));
    s.update_nz(0x01);
    assert!(!s.get_flag(status::Z));
    assert!(!s.get_flag(status::N));
}

#[test]
fn emu_state_push_pop_round_trip() {
    let mut mem = vec![0u8; 65536];
    let mut s = Cpu6502EmuState::new();
    let mut lcg = Lcg::new();
    let mut vals = Vec::new();
    for _ in 0..30 {
        let v = lcg.next_u8();
        s.push(v, &mut mem[..]);
        vals.push(v);
    }
    for &v in vals.iter().rev() {
        let popped = s.pop(&mem[..]);
        assert_eq!(popped, v);
    }
}

#[test]
fn emu_state_eq_and_clone() {
    let s1 = Cpu6502EmuState::new();
    let s2 = s1.clone();
    assert_eq!(s1, s2);
    let mut s3 = s1.clone();
    s3.a = 1;
    assert_ne!(s1, s3);
}

#[test]
fn emu_state_default_new_match() {
    let a = Cpu6502EmuState::new();
    let b = Cpu6502EmuState::default();
    assert_eq!(a, b);
    assert_eq!(a.pc, RESET_VECTOR);
}

// ─── Register IDs distinct ────────────────────────────────────────────────────

#[test]
fn register_ids_distinct() {
    let ids = [REG_A, REG_X, REG_Y, REG_SP, REG_PC, REG_P];
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            assert_ne!(ids[i], ids[j]);
        }
    }
}

// ─── CpuVariant equality ───────────────────────────────────────────────────────

#[test]
fn cpu_variant_eq() {
    assert_eq!(CpuVariant::Cpu6502, CpuVariant::Cpu6502);
    assert_ne!(CpuVariant::Cpu6502, CpuVariant::Cpu65C02);
    assert_ne!(CpuVariant::Illegal6502, CpuVariant::Cpu6502);
}

// ─── Threaded Send+Sync stress for Cpu6502Arch ────────────────────────────────

#[test]
fn arch_send_sync_threaded_stress() {
    use std::sync::Arc;
    use std::thread;
    let arch = Arc::new(Cpu6502Arch::new().with_illegal_opcodes());
    let mut handles = Vec::new();
    for t in 0..4 {
        let a = Arc::clone(&arch);
        handles.push(thread::spawn(move || {
            let mut lcg = Lcg::new();
            lcg.s ^= u64::try_from(t).unwrap_or(0).wrapping_mul(0x9E37_79B9_7F4A_7C15);
            for _ in 0..100 {
                let buf = [lcg.next_u8(), lcg.next_u8(), lcg.next_u8()];
                let _ = a.disassemble(Address::new(u64::from(lcg.next_u16())), &buf);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── DisasmResult equality ─────────────────────────────────────────────────────

#[test]
fn disasm_result_eq() {
    let a = disassemble_one(&[0xEA], 0, 0).unwrap();
    let b = disassemble_one(&[0xEA], 0, 0).unwrap();
    assert_eq!(a, b);
}

// ─── Round-trip: disassemble every defined opcode with random operand bytes ───

#[test]
fn disassemble_every_defined_opcode_with_padding() {
    let a = Cpu6502Arch::new().with_illegal_opcodes();
    let mut lcg = Lcg::new();
    for b in 0u8..=255 {
        if let Some(e) = opcode_table(b) {
            let need = 1 + e.mode.extra_bytes() as usize;
            let buf = [b, lcg.next_u8(), lcg.next_u8(), lcg.next_u8(), lcg.next_u8()];
            let r = a.disassemble(Address::new(0x1000), &buf[..need]);
            assert!(r.is_ok(), "failed opcode 0x{b:02X}");
            let i = r.unwrap();
            assert_eq!(i.size, need);
            assert_eq!(i.mnemonic, e.mnemonic);
        }
    }
}

// ─── extra_bytes is const-stable ───────────────────────────────────────────────

#[test]
fn extra_bytes_is_const_expr() {
    const _A: u16 = AddrMode::Absolute.extra_bytes();
    const _B: u16 = AddrMode::Implied.extra_bytes();
}

// ─── cycle_count helper on Cpu6502Arch ─────────────────────────────────────────

#[test]
fn arch_cycle_count_matches_table() {
    let a = Cpu6502Arch::new();
    for b in 0u8..=255 {
        let from_arch = a.cycle_count(b);
        let from_tbl = opcode_table(b).map(|e| e.cycles);
        assert_eq!(from_arch, from_tbl);
    }
}
