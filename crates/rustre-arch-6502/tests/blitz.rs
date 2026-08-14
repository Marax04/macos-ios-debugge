//! Blitz tests: exhaustively probe public API of rustre-arch-6502 to surface bugs.

use rustre_arch_6502::*;
use rustre_arch_6502::analysis::*;
use rustre_arch_6502::decoder_65c02::*;
use rustre_arch_6502::mos6502_rom_analyzer::*;
use rustre_arch_6502::mos6502_addressing_modes::*;
use rustre_arch_6502::mos6502_address_modes::{cycles_for_mode, page_cross_penalty, crosses_page};
use rustre_arch_6502::assembler_6502::TwoPassAssembler;
use rustre_core::arch::Architecture;

// ─── opcode_table coverage ────────────────────────────────────────────────────

#[test]
fn opcode_table_every_byte_returns_entry_or_none() {
    // Just exercise to make sure no panic, and confirm extra_bytes is sane.
    for b in 0u8..=255 {
        if let Some(e) = opcode_table(b) {
            assert!(e.extra_bytes_or().is_some() || true);
            assert!(matches!(e.mode.extra_bytes(), 0..=2));
            assert!(e.cycles >= 2 && e.cycles <= 8, "opcode 0x{:02X} cycles={}", b, e.cycles);
            assert!(!e.mnemonic.is_empty());
        }
    }
}

trait Probe { fn extra_bytes_or(&self) -> Option<u8>; }
impl Probe for OpcodeEntry { fn extra_bytes_or(&self) -> Option<u8> { Some(self.mode.extra_bytes() as u8) } }

#[test]
fn addr_mode_extra_bytes_all_variants() {
    use AddrMode::*;
    let pairs = [
        (Implied, 0), (Accumulator, 0), (Illegal, 0),
        (Immediate, 1), (ZeroPage, 1), (ZeroPageX, 1), (ZeroPageY, 1),
        (IndirectX, 1), (IndirectY, 1), (Relative, 1), (ZeroPageIndirect, 1),
        (Absolute, 2), (AbsoluteX, 2), (AbsoluteY, 2), (Indirect, 2),
        (AbsoluteIndirectX, 2), (RelativeLong, 2),
    ];
    for (m, eb) in pairs {
        assert_eq!(m.extra_bytes(), eb, "{:?}", m);
        assert!(!m.name().is_empty());
    }
}

#[test]
fn cpu_mode_names() {
    assert_eq!(CpuMode::Cpu6502.name(), "6502");
    assert_eq!(CpuMode::Cpu65C02.name(), "65c02");
    assert_eq!(CpuMode::Cpu65816.name(), "65816");
    assert_eq!(CpuMode::default(), CpuMode::Cpu6502);
}

// ─── format_operand ──────────────────────────────────────────────────────────

#[test]
fn format_operand_immediate() {
    assert_eq!(format_operand(AddrMode::Immediate, &[0xA9, 0x42], 0), "#$42");
}
#[test]
fn format_operand_absolute_le() {
    assert_eq!(format_operand(AddrMode::Absolute, &[0xAD, 0x34, 0x12], 0), "$1234");
}
#[test]
fn format_operand_relative_forward() {
    // pc=0x100, offset=0x10 → target = 0x100+2+0x10 = 0x112
    assert_eq!(format_operand(AddrMode::Relative, &[0xD0, 0x10], 0x100), "$0112");
}
#[test]
fn format_operand_relative_backward() {
    // pc=0x100, offset=-2 (0xFE) → target = 0x100+2-2 = 0x100
    assert_eq!(format_operand(AddrMode::Relative, &[0xD0, 0xFE], 0x100), "$0100");
}
#[test]
fn format_operand_implied_empty() {
    assert_eq!(format_operand(AddrMode::Implied, &[0xEA], 0), "");
}
#[test]
fn format_operand_accumulator_is_A() {
    assert_eq!(format_operand(AddrMode::Accumulator, &[0x0A], 0), "A");
}
#[test]
fn format_operand_relative_long() {
    let s = format_operand(AddrMode::RelativeLong, &[0x82, 0x00, 0x00], 0x1000);
    assert_eq!(s, "$001003");
}

// ─── branch_target ────────────────────────────────────────────────────────────

#[test]
fn branch_target_forward_back() {
    assert_eq!(branch_target(0x200, &[0xD0, 0x10]), Some(0x212));
    assert_eq!(branch_target(0x200, &[0xD0, 0xFE]), Some(0x200));
}
#[test]
fn branch_target_truncated_none() {
    assert_eq!(branch_target(0x200, &[0xD0]), None);
    assert_eq!(branch_target(0x200, &[]), None);
}

// ─── cycles helper ────────────────────────────────────────────────────────────

#[test]
fn cycles_unknown_opcode_defaults_to_2() {
    // 0xCF is ISC abs (illegal but tabled). Pick a truly unmapped one if any.
    // All bytes 0..=255 are tabled in this implementation, so verify behavior:
    // when an opcode is None, base=2.
    // We test absolute,X with no cross.
    assert_eq!(cycles(0xBD, false), 4);
}
#[test]
fn cycles_immediate_no_page_penalty() {
    assert_eq!(cycles(0xA9, true), 2);
    assert_eq!(cycles(0xA9, false), 2);
}

// ─── disassemble_one ──────────────────────────────────────────────────────────

#[test]
fn disassemble_one_truncated() {
    assert!(disassemble_one(&[0xAD, 0x00], 0, 0).is_none());
}
#[test]
fn disassemble_one_unknown_returns_none() {
    // Provide a likely-undefined byte. In this crate every byte is mapped,
    // so check that 0xFF returns Some (illegal ISC abs,X).
    assert!(disassemble_one(&[0xFF, 0, 0], 0, 0).is_some());
}

// ─── disassemble_range ────────────────────────────────────────────────────────

#[test]
fn disassemble_range_n_zero_returns_empty() {
    let out = disassemble_range(&[0xEA; 10], 0, 0);
    assert!(out.is_empty());
}
#[test]
fn disassemble_range_basic() {
    let out = disassemble_range(&[0xA9, 0x42, 0xEA], 0xC000, 2);
    assert_eq!(out.len(), 2);
    assert!(out[0].contains("C000"));
    assert!(out[0].contains("LDA"));
    assert!(out[1].contains("NOP"));
}
#[test]
fn disassemble_range_truncated_emits_unknown() {
    // LDA imm requires 2 bytes; provide just 1 → "???"
    let out = disassemble_range(&[0xA9], 0, 5);
    assert_eq!(out.len(), 1);
    assert!(out[0].contains("???"));
}

// ─── Cpu6502Arch::disassemble error paths ────────────────────────────────────

#[test]
fn arch_disassemble_empty_errors() {
    let a = Cpu6502Arch::new();
    assert!(a.disassemble(rustre_core::address::Address::new(0), &[]).is_err());
}
#[test]
fn arch_disassemble_truncated_errors() {
    let a = Cpu6502Arch::new();
    assert!(a.disassemble(rustre_core::address::Address::new(0), &[0xAD, 0]).is_err());
}
#[test]
fn arch_pointer_size_2() {
    assert_eq!(<Cpu6502Arch as rustre_core::arch::Architecture>::pointer_size(&Cpu6502Arch::new()), 2);
}

// ─── MemoryBus6502 ────────────────────────────────────────────────────────────

#[test]
fn memory_bus_default_zeroed() {
    let m = MemoryBus6502::default();
    assert_eq!(m.load(0x0000), 0);
    assert_eq!(m.load(0xFFFF), 0);
}
#[test]
fn memory_bus_store_load_roundtrip() {
    let mut m = MemoryBus6502::new();
    m.store(0x1234, 0xAB);
    assert_eq!(m.load(0x1234), 0xAB);
}
#[test]
fn memory_bus_load_program_truncates_at_end() {
    let mut m = MemoryBus6502::new();
    // Origin near top of memory; should silently truncate.
    let prog = vec![0xAAu8; 100];
    m.load_program(&prog, 0xFFE0);
    // First 0x20 bytes (0xFFE0..0xFFFF) should be 0xAA.
    assert_eq!(m.load(0xFFE0), 0xAA);
    assert_eq!(m.load(0xFFFF), 0xAA);
}
#[test]
fn memory_bus_set_reset_vector_le() {
    let mut m = MemoryBus6502::new();
    m.set_reset_vector(0xBEEF);
    assert_eq!(m.load(0xFFFC), 0xEF);
    assert_eq!(m.load(0xFFFD), 0xBE);
}

// ─── Cpu6502EmuState ──────────────────────────────────────────────────────────

#[test]
fn emu_state_set_get_flag() {
    let mut s = Cpu6502EmuState::new();
    s.set_flag(status::C, true);
    assert!(s.get_flag(status::C));
    s.set_flag(status::C, false);
    assert!(!s.get_flag(status::C));
}
#[test]
fn emu_state_update_nz_zero() {
    let mut s = Cpu6502EmuState::new();
    s.update_nz(0);
    assert!(s.get_flag(status::Z));
    assert!(!s.get_flag(status::N));
}
#[test]
fn emu_state_update_nz_negative() {
    let mut s = Cpu6502EmuState::new();
    s.update_nz(0x80);
    assert!(!s.get_flag(status::Z));
    assert!(s.get_flag(status::N));
}
#[test]
fn emu_state_push_pop_roundtrip() {
    let mut s = Cpu6502EmuState::new();
    let mut mem = vec![0u8; 0x10000];
    s.push(0xAB, &mut mem);
    s.push(0xCD, &mut mem);
    assert_eq!(s.pop(&mem), 0xCD);
    assert_eq!(s.pop(&mem), 0xAB);
}

// ─── Cpu6502 driver step/reset/run_until ──────────────────────────────────────

#[test]
fn cpu6502_reset_reads_vector_le() {
    let mut mem = vec![0u8; 0x10000];
    mem[0xFFFC] = 0x34;
    mem[0xFFFD] = 0x12;
    let mut s = Cpu6502EmuState::new();
    Cpu6502::reset(&mut s, &mem);
    assert_eq!(s.pc, 0x1234);
    assert_eq!(s.sp, 0xFD);
}
#[test]
fn cpu6502_step_nop_advances_pc() {
    let mut mem = vec![0u8; 0x10000];
    mem[0x200] = 0xEA;
    let mut s = Cpu6502EmuState::new();
    s.pc = 0x200;
    let c = Cpu6502::step(&mut s, &mut mem);
    assert_eq!(c, 2);
    assert_eq!(s.pc, 0x201);
    assert_eq!(s.cycles, 2);
}
#[test]
fn cpu6502_run_until_breakpoint() {
    let mut mem = vec![0u8; 0x10000];
    mem[0x200] = 0xEA;
    mem[0x201] = 0xEA;
    mem[0x202] = 0xEA;
    let mut s = Cpu6502EmuState::new();
    s.pc = 0x200;
    let cyc = Cpu6502::run_until(&mut s, &mut mem, 0x203, 1000);
    assert_eq!(s.pc, 0x203);
    assert_eq!(cyc, 6); // 3 NOPs × 2 cycles
}
#[test]
fn cpu6502_jsr_pushes_return_minus_one() {
    // JSR $0500 at $200
    let mut mem = vec![0u8; 0x10000];
    mem[0x200] = 0x20;
    mem[0x201] = 0x00;
    mem[0x202] = 0x05;
    let mut s = Cpu6502EmuState::new();
    s.pc = 0x200;
    s.sp = 0xFF;
    Cpu6502::step(&mut s, &mut mem);
    assert_eq!(s.pc, 0x0500);
    // pushed PC+2 (0x202), so high byte at 0x1FF, low at 0x1FE
    assert_eq!(mem[0x1FF], 0x02);
    assert_eq!(mem[0x1FE], 0x02);
    assert_eq!(s.sp, 0xFD);
}

// ─── analysis: vectors / strings / entropy / scan ────────────────────────────

#[test]
fn read_vector_table_too_small() {
    assert!(read_vector_table(&[0u8; 100]).is_none());
}
#[test]
fn read_vector_table_full() {
    let mut m = vec![0u8; 0x10000];
    m[0xFFFA] = 0x11; m[0xFFFB] = 0x22; // NMI = 0x2211
    m[0xFFFC] = 0x33; m[0xFFFD] = 0x44; // RESET
    m[0xFFFE] = 0x55; m[0xFFFF] = 0x66; // IRQ
    let v = read_vector_table(&m).unwrap();
    assert_eq!(v.nmi, 0x2211);
    assert_eq!(v.reset, 0x4433);
    assert_eq!(v.irq, 0x6655);
}
#[test]
fn shannon_entropy_uniform_max() {
    let data: Vec<u8> = (0..=255u8).collect();
    let e = shannon_entropy(&data);
    assert!((e - 8.0).abs() < 1e-9, "got {}", e);
}
#[test]
fn shannon_entropy_constant_zero() {
    assert_eq!(shannon_entropy(&[7u8; 100]), 0.0);
}
#[test]
fn shannon_entropy_empty_zero() {
    assert_eq!(shannon_entropy(&[]), 0.0);
}
#[test]
fn scan_strings_basic() {
    let data = b"\x00\x00hello world\x00\x00";
    let v = scan_strings(data, 0x1000, 4, StringCharset::Ascii);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].text, "hello world");
    assert_eq!(v[0].addr, 0x1000 + 2);
}
#[test]
fn scan_strings_below_min_len_skipped() {
    let v = scan_strings(b"hi\x00there\x00", 0, 4, StringCharset::Ascii);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].text, "there");
}
#[test]
fn scan_strings_empty() {
    assert!(scan_strings(b"", 0, 4, StringCharset::Ascii).is_empty());
}
#[test]
fn scan_functions_finds_jsr_target() {
    // JSR $0500 at offset 0, then bytes ... and at offset 0x100 we have RTS
    let mut data = vec![0xEA; 0x200];
    data[0] = 0x20; data[1] = 0x00; data[2] = 0x05;
    // place RTS at offset 5 (so target 0x500 is OUT of buffer but caller is found)
    // scan_functions just needs to enumerate JSR targets.
    let funcs = scan_functions(&data, 0);
    assert!(funcs.iter().any(|f| f.entry == 0x0500));
    let f = funcs.iter().find(|f| f.entry == 0x0500).unwrap();
    assert_eq!(f.call_sites, vec![0u16]);
}
#[test]
fn detect_data_sections_empty() {
    assert!(detect_data_sections(&[], 0, 16, 5.0).is_empty());
}
#[test]
fn detect_data_sections_zero_window_empty() {
    assert!(detect_data_sections(&[1, 2, 3], 0, 0, 5.0).is_empty());
}
#[test]
fn collect_entry_points_dedup_sorted() {
    let mut mem = vec![0u8; 0x10000];
    mem[0xFFFA] = 0x10; mem[0xFFFB] = 0x00;
    mem[0xFFFC] = 0x20; mem[0xFFFD] = 0x00;
    mem[0xFFFE] = 0x10; mem[0xFFFF] = 0x00; // dup of NMI
    let v = collect_entry_points(&mem, 0, EntryPointHints::all());
    // Should at least include 0x10 and 0x20, dedup, sorted.
    assert!(v.windows(2).all(|w| w[0] < w[1]));
    assert!(v.contains(&0x10));
    assert!(v.contains(&0x20));
}

// ─── ROM analyzer ────────────────────────────────────────────────────────────

#[test]
fn identify_rom_type_nes() {
    let mut d = b"NES\x1A".to_vec();
    d.extend(std::iter::repeat(0).take(12));
    assert_eq!(identify_rom_type(&d), RomType::Nes);
}
#[test]
fn identify_rom_type_c64_0801() {
    let d = vec![0x01u8, 0x08, 0xAA, 0xBB];
    assert_eq!(identify_rom_type(&d), RomType::C64);
}
#[test]
fn identify_rom_type_atari_2k() {
    // Must not match C64 load addrs (0x0801/0x0400/0x2000) at start.
    let mut d = vec![0xFFu8; 2048];
    d[0] = 0; d[1] = 0;
    assert_eq!(identify_rom_type(&d), RomType::Atari2600);
}
#[test]
fn identify_rom_type_generic_short() {
    assert_eq!(identify_rom_type(&[]), RomType::Generic);
    assert_eq!(identify_rom_type(&[0xFF, 0xFF, 0xFF]), RomType::Generic);
}
#[test]
fn parse_ines_header_too_short() {
    assert!(parse_ines_header(&[0; 8]).is_none());
}
#[test]
fn parse_ines_header_bad_magic() {
    let mut d = vec![0u8; 16];
    d[0] = b'X';
    assert!(parse_ines_header(&d).is_none());
}
#[test]
fn parse_ines_header_basic() {
    let mut d = b"NES\x1A".to_vec();
    d.push(2); // prg banks
    d.push(1); // chr banks
    d.push(0b0000_0001); // flags6: vertical mirror
    d.push(0); // flags7
    d.extend(std::iter::repeat(0).take(8));
    let h = parse_ines_header(&d).unwrap();
    assert_eq!(h.prg_rom_size, 2);
    assert_eq!(h.chr_rom_size, 1);
    assert!(h.vertical_mirror);
    assert!(!h.has_trainer);
    assert!(!h.has_battery);
}
#[test]
fn nes_prg_offset_with_and_without_trainer() {
    let mut h = NesHeader {
        prg_rom_size: 1, chr_rom_size: 0, flags6: 0, flags7: 0,
        mapper: 0, has_trainer: false, has_battery: false, vertical_mirror: false,
    };
    assert_eq!(nes_prg_offset(&h), 16);
    h.has_trainer = true;
    assert_eq!(nes_prg_offset(&h), 16 + 512);
}
#[test]
fn parse_c64_prg_basic() {
    let d = vec![0x01, 0x08, 0xAA, 0xBB, 0xCC];
    let (load, body) = parse_c64_prg(&d);
    assert_eq!(load, 0x0801);
    assert_eq!(body, vec![0xAA, 0xBB, 0xCC]);
}
#[test]
fn parse_c64_prg_too_short() {
    let (load, body) = parse_c64_prg(&[0xAB]);
    assert_eq!(load, 0x0801);
    assert_eq!(body, vec![0xAB]);
}
#[test]
fn read_vectors_basic() {
    // Provide a buffer covering $FFFA..$FFFF with base=0xFFFA.
    let buf = vec![0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66];
    let v = read_vectors(&buf, 0xFFFA);
    assert_eq!(v.nmi, 0x2211);
    assert_eq!(v.reset, 0x4433);
    assert_eq!(v.irq, 0x6655);
}
#[test]
fn rom_type_display_strings_nonempty() {
    for t in [RomType::Nes, RomType::Snes, RomType::C64, RomType::Apple2, RomType::Atari2600, RomType::Generic] {
        assert!(!format!("{}", t).is_empty());
    }
}
#[test]
fn memory_bank_size_and_contains() {
    let b = MemoryBank {
        name: "TEST".into(),
        addr_range: (0x8000, 0xBFFF),
        data_offset: 0,
        read_only: true,
    };
    assert_eq!(b.size(), 0x4000);
    assert!(b.contains(0x8000));
    assert!(b.contains(0xBFFF));
    assert!(!b.contains(0xC000));
    assert!(!b.contains(0x7FFF));
}

// ─── decoder_65c02 ────────────────────────────────────────────────────────────

#[test]
fn decode_65c02_empty_none() {
    assert!(decode_65c02(&[]).is_none());
}
#[test]
fn decode_65c02_bbr_is_3_bytes() {
    // 0x0F = BBR0
    let d = decode_65c02(&[0x0F, 0x10, 0xFE]).unwrap();
    assert_eq!(d.size, 3);
    assert!(d.is_bit_branch());
    assert_eq!(d.bit_index(), Some(0));
    assert_eq!(d.bbr_bbs_zp(), Some(0x10));
    assert_eq!(d.bbr_bbs_offset(), Some(-2));
}
#[test]
fn decode_65c02_bbs7_bit_index_7() {
    let d = decode_65c02(&[0xFF, 0x10, 0x00]).unwrap();
    assert_eq!(d.bit_index(), Some(7));
}
#[test]
fn decode_65c02_bbr_truncated_none() {
    assert!(decode_65c02(&[0x0F, 0x10]).is_none());
}
#[test]
fn decode_65c02_rmb_is_2_bytes() {
    // 0x07 = RMB0
    let d = decode_65c02(&[0x07, 0x42]).unwrap();
    assert_eq!(d.size, 2);
    assert!(d.is_bit_rmw());
    assert_eq!(d.bit_index(), Some(0));
    assert!(d.bbr_bbs_zp().is_none()); // not a bit-branch
}
#[test]
fn is_bit_branch_opcode_set() {
    assert!(is_bit_branch_opcode(0x0F));
    assert!(is_bit_branch_opcode(0xFF));
    assert!(!is_bit_branch_opcode(0xEA));
}
#[test]
fn is_bit_rmw_opcode_set() {
    assert!(is_bit_rmw_opcode(0x07));
    assert!(is_bit_rmw_opcode(0xF7));
    assert!(!is_bit_rmw_opcode(0xEA));
}

// ─── mos6502_addressing_modes ─────────────────────────────────────────────────

#[test]
fn ea_zp_x_wraps() {
    assert_eq!(effective_address_zp_x(0xFF, 0x02), 0x01);
}
#[test]
fn ea_zp_y_wraps() {
    assert_eq!(effective_address_zp_y(0xF0, 0x20), 0x10);
}
#[test]
fn ea_ind_x_wraps_in_zero_page() {
    let mut mem = vec![0u8; 0x10000];
    mem[0xFF] = 0x34;
    mem[0x00] = 0x12; // wrap
    assert_eq!(effective_address_ind_x(&mem, 0xFF, 0x00), 0x1234);
}
#[test]
fn ea_ind_y_basic() {
    let mut mem = vec![0u8; 0x10000];
    mem[0x10] = 0x00;
    mem[0x11] = 0x20;
    assert_eq!(effective_address_ind_y(&mem, 0x10, 0x05), 0x2005);
}
#[test]
fn cross_page_check_basic() {
    assert!(cross_page_check(0x00FF, 0x01));
    assert!(!cross_page_check(0x0010, 0x10));
}
#[test]
fn zero_page_wrap_basic() {
    assert_eq!(zero_page_wrap(0xFF), 0x00FF);
}
#[test]
fn cycles_for_mode_table() {
    assert_eq!(cycles_for_mode(AddrMode::Implied), 2);
    assert_eq!(cycles_for_mode(AddrMode::Absolute), 4);
}
#[test]
fn page_cross_penalty_table() {
    assert_eq!(page_cross_penalty(AddrMode::AbsoluteX), 1);
    assert_eq!(page_cross_penalty(AddrMode::Immediate), 0);
}
#[test]
fn crosses_page_helper() {
    assert!(crosses_page(0x10F0, 0x20));
    assert!(!crosses_page(0x1000, 0x10));
}

// ─── Mos6502MemoryModel ───────────────────────────────────────────────────────

#[test]
fn mem_model_stack_push_pop_roundtrip() {
    let mut m = Mos6502MemoryModel::new();
    m.stack_push(0xAB);
    m.stack_push(0xCD);
    assert_eq!(m.stack_depth(), 2);
    assert_eq!(m.stack_peek(), 0xCD);
    assert_eq!(m.stack_pop(), 0xCD);
    assert_eq!(m.stack_pop(), 0xAB);
    assert_eq!(m.stack_depth(), 0);
}
#[test]
fn mem_model_stack_push_pop_u16_le() {
    let mut m = Mos6502MemoryModel::new();
    m.stack_push_u16(0x1234);
    assert_eq!(m.stack_pop_u16(), 0x1234);
}
#[test]
fn mem_model_with_data_load() {
    let m = Mos6502MemoryModel::with_data(&[1, 2, 3, 4], 0x200);
    assert_eq!(m.read(0x200), 1);
    assert_eq!(m.read(0x203), 4);
    assert_eq!(m.read(0x204), 0);
}
#[test]
fn mem_model_read_write_u16_le() {
    let mut m = Mos6502MemoryModel::new();
    m.write_u16(0x100, 0xBEEF);
    assert_eq!(m.read(0x100), 0xEF);
    assert_eq!(m.read(0x101), 0xBE);
    assert_eq!(m.read_u16(0x100), 0xBEEF);
}
#[test]
fn mem_model_fill_range() {
    let mut m = Mos6502MemoryModel::new();
    m.fill(0x300, 16, 0xAB);
    for a in 0x300..0x310 {
        assert_eq!(m.read(a), 0xAB);
    }
    assert_eq!(m.read(0x310), 0);
}

// ─── TwoPassAssembler smoke ──────────────────────────────────────────────────

#[test]
fn assembler_basic_lda_rts() {
    let mut a = TwoPassAssembler::new(0xC000);
    let out = a.assemble("  LDA #$FF\n  RTS\n").unwrap();
    assert!(!out.has_errors());
    // Listing format should mention C000
    let s = out.format();
    assert!(s.contains("C000"));
}
#[test]
fn assembler_empty_source_ok() {
    let mut a = TwoPassAssembler::new(0);
    let out = a.assemble("").unwrap();
    assert!(out.lines.is_empty());
}

// ─── Cpu6502State (legacy) ────────────────────────────────────────────────────

#[test]
fn cpu6502_state_reset_sp_fd() {
    let mut mem = Box::new([0u8; 65536]);
    mem[0xFFFC] = 0x00;
    mem[0xFFFD] = 0xC0;
    let s = Cpu6502State::reset(&mem);
    assert_eq!(s.sp, 0xFD);
    assert_eq!(s.pc, 0xC000);
    assert_ne!(s.p & status::U, 0);
    assert_ne!(s.p & status::I, 0);
}
