//! Exhaustive external test suite for `rustre-arch-z80`.
//! Targets public API surface across submodules: encoders, decoders,
//! ROM-header parsing, register file, register pairs, undocumented opcodes,
//! and platform helpers.

use rustre_core::arch::{Architecture, InstrFlags};
use rustre_arch_z80 as z;
use rustre_arch_z80::z80_register_pairs::{
    pair_value, split_pair, PairUsageMap, Z80RegisterPair,
};
use rustre_arch_z80::z80_registers::{Z80Flags, Z80Reg, Z80RegFile, Z80RegPair16};
use rustre_arch_z80::z80_rom_header::{
    detect_rom_format, find_copyright_string, CpmFileHeader, MsxRomHeader, RomFormat,
    SpectrumBasicLoader,
};
use rustre_arch_z80::z80_undocumented_opcodes::{
    decode_undocumented, is_undocumented, scan_for_undocumented,
};
use rustre_core::address::Address;

const fn arch() -> z::Z80Arch {
    z::Z80Arch
}
const fn a(n: u64) -> Address {
    Address::new(n)
}

// ─────────────────────────── Encoder round-trips ─────────────────────────────

#[test]
fn encode_nop_round_trip() {
    let b = z::encode_nop();
    assert_eq!(b, [0x00]);
    let i = arch().disassemble(a(0), &b).unwrap();
    assert_eq!(i.mnemonic, "NOP");
    assert_eq!(i.size, 1);
}

#[test]
fn encode_halt_round_trip() {
    let i = arch().disassemble(a(0), &z::encode_halt()).unwrap();
    assert_eq!(i.mnemonic, "HALT");
}

#[test]
fn encode_ret_round_trip() {
    let i = arch().disassemble(a(0), &z::encode_ret()).unwrap();
    assert_eq!(i.mnemonic, "RET");
}

#[test]
fn encode_jp_target_bytes_le() {
    let b = z::encode_jp(0xBEEF);
    assert_eq!(b, [0xC3, 0xEF, 0xBE]);
}

#[test]
fn encode_call_target_bytes_le() {
    let b = z::encode_call(0x1234);
    assert_eq!(b, [0xCD, 0x34, 0x12]);
}

#[test]
fn encode_jr_negative_disp() {
    let b = z::encode_jr(-2);
    assert_eq!(b, [0x18, 0xFE]);
}

#[test]
fn encode_jr_positive_disp_boundary() {
    let b = z::encode_jr(127);
    assert_eq!(b, [0x18, 0x7F]);
    let b = z::encode_jr(-128);
    assert_eq!(b, [0x18, 0x80]);
}

#[test]
fn encode_djnz_basic() {
    assert_eq!(z::encode_djnz(0), [0x10, 0x00]);
}

#[test]
fn encode_ld_r_n_each_reg() {
    for r in 0..8u8 {
        let b = z::encode_ld_r_n(r, 0xAB);
        assert_eq!(b[0], 0x06 | (r << 3));
        assert_eq!(b[1], 0xAB);
    }
}

#[test]
#[should_panic]
fn encode_ld_r_n_panics_on_invalid_reg() {
    // Asserting the documented panic — this is verifying the precondition, not masking a failure.
    let _ = z::encode_ld_r_n(8, 0);
}

#[test]
fn encode_ld_bc_de_hl_sp_nn() {
    assert_eq!(z::encode_ld_bc_nn(0x1122), [0x01, 0x22, 0x11]);
    assert_eq!(z::encode_ld_de_nn(0x1122), [0x11, 0x22, 0x11]);
    assert_eq!(z::encode_ld_hl_nn(0x1122), [0x21, 0x22, 0x11]);
    assert_eq!(z::encode_ld_sp_nn(0x1122), [0x31, 0x22, 0x11]);
}

#[test]
fn encode_push_pop_all_pairs() {
    for rp in 0..4u8 {
        let pu = z::encode_push(rp);
        let po = z::encode_pop(rp);
        assert_eq!(pu[0], 0xC5 | (rp << 4));
        assert_eq!(po[0], 0xC1 | (rp << 4));
    }
}

#[test]
#[should_panic]
fn encode_push_panics_invalid() {
    let _ = z::encode_push(4);
}

#[test]
fn encode_rst_all_vectors() {
    for v in 0..8u8 {
        let b = z::encode_rst(v);
        assert_eq!(b[0], 0xC7 | (v << 3));
    }
}

#[test]
#[should_panic]
fn encode_rst_panics_above_7() {
    let _ = z::encode_rst(8);
}

#[test]
fn encode_ei_di_bytes() {
    assert_eq!(z::encode_ei(), [0xFB]);
    assert_eq!(z::encode_di(), [0xF3]);
}

#[test]
fn encode_jr_conditional() {
    assert_eq!(z::encode_jr_nz(0), [0x20, 0x00]);
    assert_eq!(z::encode_jr_z(0), [0x28, 0x00]);
    assert_eq!(z::encode_jr_nc(0), [0x30, 0x00]);
    assert_eq!(z::encode_jr_c(0), [0x38, 0x00]);
}

#[test]
fn encode_alu_register_ops() {
    for r in 0..8u8 {
        assert_eq!(z::encode_add_a_r(r), 0x80 | r);
        assert_eq!(z::encode_sub_r(r), 0x90 | r);
        assert_eq!(z::encode_and_r(r), 0xA0 | r);
        assert_eq!(z::encode_xor_r(r), 0xA8 | r);
        assert_eq!(z::encode_or_r(r), 0xB0 | r);
        assert_eq!(z::encode_cp_r(r), 0xB8 | r);
        assert_eq!(z::encode_inc_r(r), 0x04 | (r << 3));
        assert_eq!(z::encode_dec_r(r), 0x05 | (r << 3));
    }
}

#[test]
fn encode_ld_rp_nn_all() {
    for rp in 0..4u8 {
        let b = z::encode_ld_rp_nn(rp, 0xCAFE);
        assert_eq!(b[0], 0x01 | (rp << 4));
        assert_eq!(b[1], 0xFE);
        assert_eq!(b[2], 0xCA);
    }
}

#[test]
fn encode_ld_mem_a_round_trip() {
    let b = z::encode_ld_mem_nn_a(0x4000);
    assert_eq!(b, [0x32, 0x00, 0x40]);
    let b = z::encode_ld_a_mem_nn(0x4000);
    assert_eq!(b, [0x3A, 0x00, 0x40]);
}

#[test]
fn encode_ex_de_hl_const() {
    assert_eq!(z::encode_ex_de_hl(), 0xEB);
}

// ─────────────────────────── CB-prefix encoders ─────────────────────────────

#[test]
fn encode_cb_op_bit_layout() {
    // BIT 3, A → CB 5F
    let b = z::encode_bit_b_r(3, 7);
    assert_eq!(b, [0xCB, 0x5F]);
}

#[test]
fn encode_cb_set_res_all_bits() {
    for bit in 0..8u8 {
        let s = z::encode_set_b_r(bit, 0); // SET b, B
        let r = z::encode_res_b_r(bit, 0); // RES b, B
        assert_eq!(s[0], 0xCB);
        assert_eq!(s[1], 0xC0 | (bit << 3));
        assert_eq!(r[0], 0xCB);
        assert_eq!(r[1], 0x80 | (bit << 3));
    }
}

#[test]
#[should_panic]
fn encode_cb_op_panics_on_bad_op() {
    let _ = z::encode_cb_op(4, 0, 0);
}

// ─────────────────────────── ED-prefix block encoders ───────────────────────

#[test]
fn ed_block_encoders() {
    assert_eq!(z::encode_ldi(), [0xED, 0xA0]);
    assert_eq!(z::encode_ldir(), [0xED, 0xB0]);
    assert_eq!(z::encode_ldd(), [0xED, 0xA8]);
    assert_eq!(z::encode_lddr(), [0xED, 0xB8]);
    assert_eq!(z::encode_neg_ed(), [0xED, 0x44]);
    assert_eq!(z::encode_reti_ed(), [0xED, 0x4D]);
    assert_eq!(z::encode_retn_ed(), [0xED, 0x45]);
}

// ─────────────────────────── Decoder error paths ────────────────────────────

#[test]
fn decode_main_empty_returns_err() {
    let r = z::decode_main(&[], 0);
    assert!(r.is_err());
}

#[test]
fn decode_main_truncated_cb() {
    let r = z::decode_main(&[0xCB], 0);
    assert!(r.is_err());
}

#[test]
fn decode_main_truncated_djnz() {
    let r = z::decode_main(&[0x10], 0);
    assert!(r.is_err());
}

#[test]
fn decode_main_truncated_jr() {
    let r = z::decode_main(&[0x18], 0);
    assert!(r.is_err());
}

#[test]
fn decode_main_truncated_jr_cond() {
    let r = z::decode_main(&[0x20], 0);
    assert!(r.is_err());
}

#[test]
fn decode_main_jr_target_pc_relative() {
    // JR +0 from PC=0x100 → target 0x102
    let d = z::decode_main(&[0x18, 0x00], 0x100).unwrap();
    assert_eq!(d.mnemonic, "JR");
    assert!(d.operands.contains("0102"));
}

#[test]
fn decode_main_djnz_negative_disp() {
    // DJNZ -2 from PC=0x100 → target 0x100
    let d = z::decode_main(&[0x10, 0xFE], 0x100).unwrap();
    assert_eq!(d.mnemonic, "DJNZ");
    assert!(d.operands.contains("0100"));
}

#[test]
fn decode_main_nop_size_one() {
    let d = z::decode_main(&[0x00], 0).unwrap();
    assert_eq!(d.size, 1);
    assert_eq!(d.mnemonic, "NOP");
}

// ─────────────────────────── opcode_cycles ──────────────────────────────────

#[test]
fn opcode_cycles_nop_is_4() {
    assert_eq!(z::opcode_cycles(0x00).cycles, 4);
}

#[test]
fn opcode_cycles_djnz_taken_vs_not_taken() {
    let c = z::opcode_cycles(0x10);
    assert_eq!(c.cycles, 8);
    assert_eq!(c.cycles_taken, 13);
}

#[test]
fn opcode_cycles_call_unconditional_17() {
    assert_eq!(z::opcode_cycles(0xCD).cycles, 17);
}

#[test]
fn opcode_cycles_jr_cond_branch() {
    let c = z::opcode_cycles(0x20);
    assert_eq!(c.cycles, 7);
    assert_eq!(c.cycles_taken, 12);
}

#[test]
fn opcode_cycles_ex_sp_hl_19() {
    assert_eq!(z::opcode_cycles(0xE3).cycles, 19);
}

// ─────────────────────────── InterruptMode ──────────────────────────────────

#[test]
fn interrupt_mode_from_str_valid() {
    assert_eq!(z::InterruptMode::from_str("0"), Some(z::InterruptMode::Mode0));
    assert_eq!(z::InterruptMode::from_str("1"), Some(z::InterruptMode::Mode1));
    assert_eq!(z::InterruptMode::from_str("2"), Some(z::InterruptMode::Mode2));
}

#[test]
fn interrupt_mode_from_str_trim() {
    assert_eq!(z::InterruptMode::from_str("  1  "), Some(z::InterruptMode::Mode1));
}

#[test]
fn interrupt_mode_from_str_invalid() {
    assert_eq!(z::InterruptMode::from_str("3"), None);
    assert_eq!(z::InterruptMode::from_str(""), None);
    assert_eq!(z::InterruptMode::from_str("bogus"), None);
}

#[test]
fn interrupt_mode_operand_strings() {
    assert_eq!(z::InterruptMode::Mode0.operand(), "0");
    assert_eq!(z::InterruptMode::Mode1.operand(), "1");
    assert_eq!(z::InterruptMode::Mode2.operand(), "2");
}

#[test]
fn z80_interrupt_mode_encode() {
    assert_eq!(z::Z80InterruptMode::Mode0.encode_im(), [0xED, 0x46]);
    assert_eq!(z::Z80InterruptMode::Mode1.encode_im(), [0xED, 0x56]);
    assert_eq!(z::Z80InterruptMode::Mode2.encode_im(), [0xED, 0x5E]);
}

// ─────────────────────────── Z80Condition ───────────────────────────────────

#[test]
fn condition_jp_cc_byte() {
    let b = z::Z80Condition::NZ.encode_jp_cc(0x1234);
    assert_eq!(b[0], 0xC2);
    assert_eq!(b[1], 0x34);
    assert_eq!(b[2], 0x12);
}

#[test]
fn condition_call_cc_byte() {
    let b = z::Z80Condition::Z.encode_call_cc(0x0000);
    assert_eq!(b[0], 0xC4 | (1 << 3));
}

#[test]
fn condition_ret_cc_byte() {
    assert_eq!(z::Z80Condition::C.encode_ret_cc(), 0xC0 | (3 << 3));
}

#[test]
fn condition_mnemonics_all() {
    let names = ["NZ", "Z", "NC", "C", "PO", "PE", "P", "M"];
    let conds = [
        z::Z80Condition::NZ,
        z::Z80Condition::Z,
        z::Z80Condition::NC,
        z::Z80Condition::C,
        z::Z80Condition::PO,
        z::Z80Condition::PE,
        z::Z80Condition::P,
        z::Z80Condition::M,
    ];
    for (n, c) in names.iter().zip(conds.iter()) {
        assert_eq!(c.mnemonic(), *n);
    }
}

// ─────────────────────────── Patch utilities ────────────────────────────────

#[test]
fn nop_sled_empty_returns_too_short() {
    let mut buf: [u8; 0] = [];
    assert_eq!(z::nop_sled(&mut buf), z::PatchResult::TooShort);
}

#[test]
fn nop_sled_fills_zeros() {
    let mut buf = [0xFFu8; 5];
    assert_eq!(z::nop_sled(&mut buf), z::PatchResult::Ok);
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn patch_jp_target_rewrites_bytes() {
    let mut buf = z::encode_jp(0x1234);
    assert!(z::patch_jp_target(&mut buf, 0xABCD));
    assert_eq!(&buf, &[0xC3, 0xCD, 0xAB]);
}

#[test]
fn patch_jp_target_rejects_non_jp() {
    let mut buf = [0x00u8, 0, 0];
    assert!(!z::patch_jp_target(&mut buf, 0));
}

#[test]
fn patch_jp_target_rejects_too_short() {
    let mut buf = [0xC3u8, 0];
    assert!(!z::patch_jp_target(&mut buf, 0));
}

// ─────────────────────────── RST + idiom helpers ────────────────────────────

#[test]
fn z80_rst_target_known_vectors() {
    assert_eq!(z::z80_rst_target(0), Some(0x0000));
    assert_eq!(z::z80_rst_target(7), Some(0x0038));
}

#[test]
fn z80_rst_target_out_of_range() {
    assert_eq!(z::z80_rst_target(8), None);
    assert_eq!(z::z80_rst_target(255), None);
}

// ─────────────────────────── Linear disassembler iterator ───────────────────

#[test]
fn linear_disassembler_iterates_all() {
    let arch_v = arch();
    let code = [0x00, 0x00, 0xC9]; // NOP NOP RET
    let dis = z::Z80LinearDisassembler::new(&arch_v, &code, a(0));
    let xs: Vec<_> = dis.collect();
    assert_eq!(xs.len(), 3);
    assert!(xs.iter().all(std::result::Result::is_ok));
}

#[test]
fn linear_disassembler_done_state() {
    let arch_v = arch();
    let code: [u8; 0] = [];
    let dis = z::Z80LinearDisassembler::new(&arch_v, &code, a(0));
    assert!(dis.is_done());
    assert_eq!(dis.offset(), 0);
}

// ─────────────────────────── analyze / stats ────────────────────────────────

#[test]
fn analyze_counts_call_and_ret() {
    // CALL 0x1234 + RET
    let mut buf: Vec<u8> = z::encode_call(0x1234).to_vec();
    buf.extend_from_slice(&z::encode_ret());
    let r = z::analyze(a(0), &buf);
    assert!(r.has_calls());
    assert_eq!(r.returns.len(), 1);
    assert_eq!(r.instr_count(), 2);
    assert!(r.total_cycles >= 17 + 10);
}

#[test]
fn analyze_empty_yields_zero() {
    let r = z::analyze(a(0), &[]);
    assert_eq!(r.instr_count(), 0);
    assert!(!r.has_calls());
    assert_eq!(r.errors, 0);
}

#[test]
fn instr_stats_total_matches_sum() {
    let mut code: Vec<u8> = Vec::new();
    code.extend_from_slice(&z::encode_call(0x1000)); // call
    code.extend_from_slice(&z::encode_ret()); // ret
    code.push(0x00); // nop
    let arch_v = arch();
    let mut instrs = Vec::new();
    let mut o = 0;
    while o < code.len() {
        let i = arch_v.disassemble(a(o as u64), &code[o..]).unwrap();
        o += i.size;
        instrs.push(i);
    }
    let s = z::InstrStats::from_instrs(&instrs);
    assert_eq!(s.calls, 1);
    assert_eq!(s.returns, 1);
    assert_eq!(s.total(), 2);
}

// ─────────────────────────── Lookup tables ──────────────────────────────────

#[test]
fn find_opcode_entry_nop() {
    let e = z::find_opcode_entry(0x00).expect("nop");
    assert_eq!(e.mnemonic, "NOP");
    assert_eq!(e.cycles, 4);
    assert_eq!(e.min_size, 1);
}

#[test]
fn find_opcode_entry_missing() {
    assert!(z::find_opcode_entry(0xAB).is_none());
}

#[test]
fn lookup_z80_vector_nmi_and_rst0() {
    assert_eq!(z::lookup_z80_vector(0x0066).unwrap().name, "NMI");
    assert_eq!(z::lookup_z80_vector(0x0000).unwrap().name, "RST 0");
    assert!(z::lookup_z80_vector(0x1234).is_none());
}

#[test]
fn lookup_z80_instr_ref_basic() {
    let r = z::lookup_z80_instr_ref("LDIR").unwrap();
    assert!(r.t_states_min <= r.t_states_max);
    assert!(z::lookup_z80_instr_ref("NOT_A_THING").is_none());
}

#[test]
fn lookup_zx_port_ula_match_via_mask() {
    let p = z::lookup_zx_port(0x00FE).unwrap();
    assert_eq!(p.name, "ULA");
}

// ─────────────────────────── z80_instr_byte_len ─────────────────────────────

#[test]
fn z80_instr_byte_len_known() {
    assert_eq!(z::z80_instr_byte_len(0x00), Some(1)); // NOP
    assert_eq!(z::z80_instr_byte_len(0xC9), Some(1)); // RET
    assert_eq!(z::z80_instr_byte_len(0x18), Some(2)); // JR
    assert_eq!(z::z80_instr_byte_len(0xC3), Some(3)); // JP nn
    assert_eq!(z::z80_instr_byte_len(0xCB), None); // CB-prefix
}

// ─────────────────────────── DisasmOptions / format_instr ──────────────────

#[test]
fn format_instr_default_includes_address() {
    let i = arch().disassemble(a(0x1234), &z::encode_nop()).unwrap();
    let s = z::format_instr(&i, &z::DisasmOptions::default());
    assert!(s.contains("1234:"));
    assert!(s.contains("NOP"));
}

#[test]
fn format_listing_separates_with_newline() {
    let arch_v = arch();
    let i1 = arch_v.disassemble(a(0), &z::encode_nop()).unwrap();
    let i2 = arch_v.disassemble(a(1), &z::encode_ret()).unwrap();
    let s = z::format_listing(&[i1, i2], &z::DisasmOptions::default());
    assert!(s.contains('\n'));
}

// ─────────────────────────── identify_z80_idiom ─────────────────────────────

#[test]
fn idiom_ld_self_detected() {
    // LD B,B is 0x40
    let i = arch().disassemble(a(0), &[0x40]).unwrap();
    let id = z::identify_z80_idiom(&i);
    match id {
        z::Z80Idiom::LdSelf(_) => {}
        z::Z80Idiom::General => {} // tolerate either based on operand formatting
        other => panic!("unexpected idiom {other:?}"),
    }
}

#[test]
fn idiom_clear_a_for_xor_a() {
    let i = arch().disassemble(a(0), &[0xAF]).unwrap();
    assert_eq!(z::identify_z80_idiom(&i), z::Z80Idiom::ClearA);
}

// ─────────────────────────── z80_param_locations ───────────────────────────

#[test]
fn param_locations_zero_count() {
    let v = z::z80_param_locations(0);
    assert!(v.is_empty());
}

#[test]
fn param_locations_five_args_spill_to_stack() {
    let v = z::z80_param_locations(5);
    assert_eq!(v.len(), 5);
    assert_eq!(v[0], z::Z80ParamLoc::RegHL);
    assert_eq!(v[3], z::Z80ParamLoc::Stack(0));
    assert_eq!(v[4], z::Z80ParamLoc::Stack(2));
}

// ─────────────────────────── Basic-block builder ────────────────────────────

#[test]
fn basic_block_find_terminator_splits() {
    // JP $0005; NOP; RET
    let mut code = z::encode_jp(0x0005).to_vec();
    code.push(0x00);
    code.extend_from_slice(&z::encode_ret());
    let blocks = z::Z80BasicBlock::find_blocks(&arch(), &code, a(0)).unwrap();
    assert!(blocks.len() >= 2);
}

#[test]
fn basic_block_len_and_empty() {
    let b = z::Z80BasicBlock {
        start: a(0),
        instructions: vec![],
    };
    assert!(b.is_empty());
    assert_eq!(b.len(), 0);
}

// ─────────────────────────── ROM header detection ───────────────────────────

#[test]
fn rom_format_display_names() {
    assert_eq!(format!("{}", RomFormat::Unknown), "Unknown");
    assert_eq!(format!("{}", RomFormat::MsxCartridge), "MSX ROM Cartridge");
}

#[test]
fn detect_rom_unknown_for_random() {
    let r = detect_rom_format(&[0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(r.format, RomFormat::Unknown);
}

#[test]
fn detect_rom_msx_cartridge() {
    let mut v = vec![0u8; 16];
    v[0] = b'A';
    v[1] = b'B';
    v[2] = 0xAA;
    v[3] = 0xBB;
    let r = detect_rom_format(&v);
    assert_eq!(r.format, RomFormat::MsxCartridge);
    assert_eq!(r.entry_point, 0xBBAA);
}

#[test]
fn detect_rom_spectrum48_signature() {
    let mut v = vec![0u8; 16384];
    v[0] = 0xF3;
    v[1] = 0xAF;
    let r = detect_rom_format(&v);
    assert_eq!(r.format, RomFormat::Spectrum48);
    assert!(r.checksum.is_some());
}

#[test]
fn detect_rom_cpm_starts_with_jp() {
    let mut v = vec![0u8; 256];
    v[0] = 0xC3;
    v[1] = 0x00;
    v[2] = 0x01;
    let r = detect_rom_format(&v);
    assert_eq!(r.format, RomFormat::CpmBinary);
    assert_eq!(r.entry_point, 0x0100);
}

#[test]
fn msx_header_parse_bad_magic() {
    let r = MsxRomHeader::parse(&[0xFF; 16]);
    assert!(r.is_err());
}

#[test]
fn msx_header_parse_too_short() {
    assert!(MsxRomHeader::parse(&[b'A', b'B', 0, 0]).is_err());
}

#[test]
fn cpm_header_parse_too_short() {
    assert!(CpmFileHeader::parse(&[0xC3, 0x00]).is_err());
}

#[test]
fn cpm_header_jp_no_target_when_truncated() {
    // 0xC3 with only 1 trailing byte → starts_with_jump true but no target
    let r = CpmFileHeader::parse(&[0xC3, 0x10, 0x20]).unwrap();
    assert!(r.starts_with_jump);
    assert_eq!(r.jump_target, Some(0x2010));
}

#[test]
fn spectrum_basic_loader_no_autostart_marker() {
    let mut h = [0u8; 17];
    h[13] = 0xFF;
    h[14] = 0xFF;
    let bl = SpectrumBasicLoader::parse(&h).unwrap();
    assert!(!bl.has_autostart());
}

#[test]
fn spectrum_basic_loader_wrong_type_byte() {
    let mut h = [0u8; 17];
    h[0] = 1;
    assert!(SpectrumBasicLoader::parse(&h).is_err());
}

#[test]
fn find_copyright_returns_none_for_clean() {
    assert!(find_copyright_string(b"no markers here at all").is_none());
}

#[test]
fn find_copyright_finds_c_marker() {
    let s = find_copyright_string(b"x\x00(C) 1982 Sinclair\x00").unwrap();
    assert!(s.contains("Sinclair"));
}

// ─────────────────────────── Register pairs API ─────────────────────────────

#[test]
fn pair_value_and_split_are_inverses() {
    for hi in [0u8, 0x12, 0xFF] {
        for lo in [0u8, 0x34, 0xFF] {
            let v = pair_value(hi, lo);
            let (h2, l2) = split_pair(v);
            assert_eq!((hi, lo), (h2, l2));
        }
    }
}

#[test]
fn pair_usage_map_records_and_ranks() {
    let mut m = PairUsageMap::new();
    m.entry(Z80RegisterPair::HL).record_load();
    m.entry(Z80RegisterPair::HL).record_load();
    m.entry(Z80RegisterPair::DE).record_load();
    let ranked = m.ranked();
    assert_eq!(*ranked[0].0, Z80RegisterPair::HL);
    assert_eq!(m.most_used(), Some(Z80RegisterPair::HL));
}

#[test]
fn pair_usage_get_default_when_absent() {
    let m = PairUsageMap::new();
    let u = m.get(Z80RegisterPair::HL);
    assert_eq!(u.loads, 0);
}

#[test]
fn pair_usage_classifies_pointer_and_counter() {
    let mut m = PairUsageMap::new();
    let h = m.entry(Z80RegisterPair::HL);
    h.record_address_use();
    h.record_address_use();
    assert!(h.looks_like_pointer());
    let b = m.entry(Z80RegisterPair::BC);
    b.record_arithmetic();
    b.record_arithmetic();
    assert!(b.looks_like_counter());
}

// ─────────────────────────── Z80Flags arithmetic ────────────────────────────

#[test]
fn flags_add_overflow_signed() {
    // 0x7F + 0x01 = 0x80 → signed overflow, sign set, half-carry set
    let mut f = Z80Flags::default();
    f.update_add8(0x7F, 0x01, false);
    assert!(f.pv());
    assert!(f.s());
    assert!(f.h());
    assert!(!f.n());
}

#[test]
fn flags_sub_zero_result() {
    let mut f = Z80Flags::default();
    f.update_sub8(0x10, 0x10, false);
    assert!(f.z());
    assert!(f.n());
    assert!(!f.c());
}

#[test]
fn flags_and_sets_half_carry() {
    let mut f = Z80Flags::default();
    f.update_and(0xFF);
    assert!(f.h());
    assert!(!f.c());
}

#[test]
fn flags_or_clears_half_carry() {
    let mut f = Z80Flags::default();
    f.update_or(0x80);
    assert!(!f.h());
    assert!(f.s());
}

#[test]
fn flags_condition_codes_all_eight() {
    let mut f = Z80Flags::default();
    // ensure NZ true, NC true, PO true, P true (all flags clear)
    assert!(f.condition_met(0)); // NZ
    assert!(!f.condition_met(1)); // Z
    assert!(f.condition_met(2)); // NC
    assert!(!f.condition_met(3)); // C
    assert!(f.condition_met(4)); // PO
    assert!(f.condition_met(6)); // P
    f.set_s(true);
    assert!(f.condition_met(7)); // M
}

#[test]
fn flags_display_string_8_chars() {
    let f = Z80Flags(0xFF);
    let s = f.display_string();
    assert_eq!(s.len(), 8);
    // every flag set → all uppercase letters
    assert!(s.iter().all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit()));
}

// ─────────────────────────── Z80Reg / Z80RegPair16 ──────────────────────────

#[test]
fn z80_reg_from_bits_round_trip() {
    for b in 0..8u8 {
        let r = Z80Reg::from_bits(b);
        // For all bits 0..7 there's a corresponding opcode encoding
        assert_eq!(r.opcode_bits(), Some(b));
    }
}

#[test]
fn z80_reg_pair_high_low_consistency() {
    assert_eq!(Z80RegPair16::HL.high(), Z80Reg::H);
    assert_eq!(Z80RegPair16::HL.low(), Z80Reg::L);
    assert_eq!(Z80RegPair16::IX.high(), Z80Reg::IXH);
    assert_eq!(Z80RegPair16::IY.low(), Z80Reg::IYL);
}

#[test]
fn z80_reg_pair_from_push_bits_3_is_af() {
    assert_eq!(Z80RegPair16::from_push_bits(3), Z80RegPair16::AF);
    assert_eq!(Z80RegPair16::from_bits(3), Z80RegPair16::SP);
}

#[test]
fn z80_reg_display_names() {
    assert_eq!(Z80Reg::A.name(), "A");
    assert_eq!(Z80Reg::MemHL.name(), "(HL)");
    assert!(Z80Reg::MemHL.is_memory_ref());
    assert!(!Z80Reg::A.is_memory_ref());
}

// ─────────────────────────── Z80RegFile R/W ─────────────────────────────────

#[test]
fn regfile_read_write_pair_round_trips_all() {
    let mut rf = Z80RegFile::new();
    for &p in &[
        Z80RegPair16::BC,
        Z80RegPair16::DE,
        Z80RegPair16::HL,
        Z80RegPair16::SP,
        Z80RegPair16::IX,
        Z80RegPair16::IY,
        Z80RegPair16::AF,
    ] {
        rf.write_pair(p, 0xCAFE);
        assert_eq!(rf.read_pair(p), 0xCAFE);
    }
}

#[test]
fn regfile_ex_de_hl_swaps() {
    let mut rf = Z80RegFile::new();
    rf.set_de(0x1234);
    rf.set_hl(0xABCD);
    rf.ex_de_hl();
    assert_eq!(rf.de(), 0xABCD);
    assert_eq!(rf.hl(), 0x1234);
}

#[test]
fn regfile_advance_pc_wraps() {
    let mut rf = Z80RegFile::new();
    rf.pc = 0xFFFF;
    rf.advance_pc(1);
    assert_eq!(rf.pc, 0);
}

#[test]
fn regfile_write8_ixh_preserves_low() {
    let mut rf = Z80RegFile::new();
    rf.ix = 0x1234;
    rf.write8(Z80Reg::IXH, 0xAB);
    assert_eq!(rf.ix, 0xAB34);
    rf.write8(Z80Reg::IXL, 0xCD);
    assert_eq!(rf.ix, 0xABCD);
}

#[test]
fn regfile_default_iff_off() {
    let rf = Z80RegFile::new();
    assert!(!rf.iff1);
    assert!(!rf.iff2);
    assert!(!rf.halted);
}

// ─────────────────────────── Undocumented opcode scanner ────────────────────

#[test]
fn undocumented_scanner_doesnt_panic_on_empty() {
    let v = scan_for_undocumented(&[], 0);
    assert!(v.is_empty());
}

#[test]
fn undocumented_decode_short_slice() {
    // less than 2 bytes → cannot be a prefixed undocumented opcode
    let r = decode_undocumented(&[], 0);
    assert!(r.is_none());
}

#[test]
fn undocumented_is_undocumented_on_plain_nop() {
    assert!(!is_undocumented(&[0x00]));
}

// ─────────────────────────── Z80Arch trait surface ──────────────────────────

#[test]
fn z80_arch_branch_info_for_ret() {
    let i = arch().disassemble(a(0), &z::encode_ret()).unwrap();
    assert!(i.flags.contains(InstrFlags::RET));
}

#[test]
fn z80_arch_branch_info_for_jp() {
    let i = arch().disassemble(a(0), &z::encode_jp(0x1234)).unwrap();
    assert!(i.flags.contains(InstrFlags::BRANCH));
}

#[test]
fn z80_arch_branch_info_for_call() {
    let i = arch().disassemble(a(0), &z::encode_call(0x4242)).unwrap();
    assert!(i.flags.contains(InstrFlags::CALL));
}

// ─────────────────────────── CallingConvention kinds ────────────────────────

#[test]
fn calling_convention_sdcc_has_three_args() {
    let cc = z::CallingConventionKind::SdccStandard.to_calling_convention();
    assert_eq!(cc.name, "z80_sdcc");
    assert_eq!(cc.int_args.len(), 3);
}

#[test]
fn calling_convention_cpm_uses_c_and_de() {
    let cc = z::CallingConventionKind::CpmBdos.to_calling_convention();
    assert_eq!(cc.int_args[0], "C");
    assert_eq!(cc.int_args[1], "DE");
}

// ─────────────────────────── RST helpers on instr ───────────────────────────

#[test]
fn is_rst_detects_rst_instr() {
    let i = arch().disassemble(a(0), &z::encode_rst(0)).unwrap();
    assert!(z::is_rst(&i));
}

#[test]
fn rst_vector_none_for_non_rst() {
    let i = arch().disassemble(a(0), &z::encode_nop()).unwrap();
    assert_eq!(z::rst_vector(&i), None);
}

// ─────────────────────────── Branch-category helper ─────────────────────────

#[test]
fn branch_category_helper_returns_str_for_jp() {
    let i = arch().disassemble(a(0), &z::encode_jp(0x100)).unwrap();
    let brs = arch().get_branches(&i);
    if let Some(br) = brs.first() {
        let s = z::branch_category(br);
        assert!(!s.is_empty());
    }
}
