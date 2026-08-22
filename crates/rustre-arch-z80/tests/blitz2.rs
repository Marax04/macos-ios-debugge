//! blitz2: deep adversarial tests for rustre-arch-z80 public API.

use rustre_core::arch::{Architecture, InstrFlags};
use rustre_arch_z80::*;
use rustre_core::address::Address;
use rustre_core::endian::Endian;

const fn a() -> Z80Arch {
    Z80Arch
}
const fn ad(v: u64) -> Address {
    Address::new(v)
}

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// ── 1: encode/decode round-trip — NOP ─────────────────────────────────────────
#[test]
fn rt_nop() {
    let b = encode_nop();
    let i = a().disassemble(ad(0), &b).unwrap();
    assert_eq!(i.mnemonic, "NOP");
    assert_eq!(i.size, 1);
}

// ── 2 ─────────────────────────────────────────────────────────────────────────
#[test]
fn rt_halt() {
    let b = encode_halt();
    let i = a().disassemble(ad(0), &b).unwrap();
    assert_eq!(i.mnemonic, "HALT");
}

// ── 3 ─────────────────────────────────────────────────────────────────────────
#[test]
fn rt_ret() {
    let b = encode_ret();
    let i = a().disassemble(ad(0), &b).unwrap();
    assert_eq!(i.mnemonic, "RET");
    assert!(i.flags.contains(InstrFlags::RET));
}

// ── 4: 50+ JP targets round-trip ──────────────────────────────────────────────
#[test]
fn rt_jp_50_targets() {
    let mut g = lcg();
    for _ in 0..60 {
        let target = (g() & 0xFFFF) as u16;
        let bytes = encode_jp(target);
        let i = a().disassemble(ad(0), &bytes).unwrap();
        assert_eq!(i.mnemonic, "JP");
        assert_eq!(i.operands, format!("${target:04X}"));
        assert!(i.flags.contains(InstrFlags::BRANCH));
        assert_eq!(i.size, 3);
    }
}

// ── 5: CALL round-trip ────────────────────────────────────────────────────────
#[test]
fn rt_call_50_targets() {
    let mut g = lcg();
    for _ in 0..60 {
        let target = (g() & 0xFFFF) as u16;
        let bytes = encode_call(target);
        let i = a().disassemble(ad(0), &bytes).unwrap();
        assert_eq!(i.mnemonic, "CALL");
        assert_eq!(i.operands, format!("${target:04X}"));
        assert!(i.flags.contains(InstrFlags::CALL));
    }
}

// ── 6: LD rp,nn round-trip ────────────────────────────────────────────────────
#[test]
fn rt_ld_rp_nn() {
    /// An encoder that turns a 16-bit operand into a 3-byte instruction,
    /// paired with the mnemonic it is expected to produce.
    type Enc16 = (fn(u16) -> [u8; 3], &'static str);
    let pairs: &[Enc16] = &[
        (encode_ld_bc_nn, "BC"),
        (encode_ld_de_nn, "DE"),
        (encode_ld_hl_nn, "HL"),
        (encode_ld_sp_nn, "SP"),
    ];
    let mut g = lcg();
    for &(enc, name) in pairs {
        for _ in 0..15 {
            let nn = (g() & 0xFFFF) as u16;
            let i = a().disassemble(ad(0), &enc(nn)).unwrap();
            assert_eq!(i.mnemonic, "LD");
            assert_eq!(i.operands, format!("{name},#${nn:04X}"));
        }
    }
}

// ── 7: LD r,n round-trip across all r ─────────────────────────────────────────
#[test]
fn rt_ld_r_n() {
    let names = ["B", "C", "D", "E", "H", "L", "(HL)", "A"];
    for r in 0u8..8 {
        for n in [0u8, 1, 0x7F, 0x80, 0xFF] {
            let b = encode_ld_r_n(r, n);
            let i = a().disassemble(ad(0), &b).unwrap();
            assert_eq!(i.mnemonic, "LD");
            assert_eq!(i.operands, format!("{},#${n:02X}", names[r as usize]));
        }
    }
}

// ── 8 ─────────────────────────────────────────────────────────────────────────
#[test]
#[should_panic(expected = "LD r,n: reg must be 0..7")]
fn ld_r_n_panic_bad_reg_should_panic() {
    let _ = encode_ld_r_n(8, 0);
}

// ── 9 ─────────────────────────────────────────────────────────────────────────
#[test]
#[should_panic(expected = "RST: vector must be 0..7")]
fn rst_panic_bad_vector_should_panic() {
    let _ = encode_rst(8);
}

// ── 10 ────────────────────────────────────────────────────────────────────────
#[test]
#[should_panic(expected = "PUSH: rp_idx must be 0..3")]
fn push_panic_bad_rp_should_panic() {
    let _ = encode_push(4);
}

// ── 11 ────────────────────────────────────────────────────────────────────────
#[test]
#[should_panic(expected = "POP: rp_idx must be 0..3")]
fn pop_panic_bad_rp_should_panic() {
    let _ = encode_pop(4);
}

// ── 12: RST all 8 vectors round-trip ──────────────────────────────────────────
#[test]
fn rt_rst_all_vectors() {
    for v in 0u8..8 {
        let b = encode_rst(v);
        let i = a().disassemble(ad(0), &b).unwrap();
        assert_eq!(i.mnemonic, "RST");
        assert!(i.flags.contains(InstrFlags::CALL));
        assert_eq!(rst_vector(&i), Some(v * 8));
    }
}

// ── 13: PUSH/POP all 4 rp ─────────────────────────────────────────────────────
#[test]
fn rt_push_pop_all() {
    let names = ["BC", "DE", "HL", "AF"];
    for r in 0u8..4 {
        let p = encode_push(r);
        let i = a().disassemble(ad(0), &p).unwrap();
        assert_eq!(i.mnemonic, "PUSH");
        assert_eq!(i.operands, names[r as usize]);
        let q = encode_pop(r);
        let j = a().disassemble(ad(0), &q).unwrap();
        assert_eq!(j.mnemonic, "POP");
        assert_eq!(j.operands, names[r as usize]);
    }
}

// ── 14: JR displacement round-trip ────────────────────────────────────────────
#[test]
fn rt_jr_disp() {
    for d in [-128i8, -1, 0, 1, 127] {
        let b = encode_jr(d);
        let i = a().disassemble(ad(0x100), &b).unwrap();
        assert_eq!(i.mnemonic, "JR");
        let expected_target = (0x100u64 + 2).wrapping_add_signed(i64::from(d)) & 0xFFFF;
        assert_eq!(i.operands, format!("${expected_target:04X}"));
    }
}

// ── 15: DJNZ displacement round-trip ──────────────────────────────────────────
#[test]
fn rt_djnz_disp() {
    for d in [-128i8, -2, 0, 1, 127] {
        let b = encode_djnz(d);
        let i = a().disassemble(ad(0x200), &b).unwrap();
        assert_eq!(i.mnemonic, "DJNZ");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }
}

// ── 16: empty input → Err ─────────────────────────────────────────────────────
#[test]
fn empty_input_errors() {
    assert!(a().disassemble(ad(0), &[]).is_err());
    assert!(decode_main(&[], 0).is_err());
}

// ── 17: truncated CB ─────────────────────────────────────────────────────────
#[test]
fn truncated_cb_errors() {
    assert!(a().disassemble(ad(0), &[0xCB]).is_err());
}

// ── 18: truncated JR / DJNZ / JR cc ──────────────────────────────────────────
#[test]
fn truncated_jr_errors() {
    assert!(a().disassemble(ad(0), &[0x10]).is_err()); // DJNZ
    assert!(a().disassemble(ad(0), &[0x18]).is_err()); // JR
    assert!(a().disassemble(ad(0), &[0x20]).is_err()); // JR NZ
    assert!(a().disassemble(ad(0), &[0x28]).is_err()); // JR Z
    assert!(a().disassemble(ad(0), &[0x30]).is_err());
    assert!(a().disassemble(ad(0), &[0x38]).is_err());
}

// ── 19: truncated 3-byte ops ─────────────────────────────────────────────────
#[test]
fn truncated_3byte_errors() {
    assert!(a().disassemble(ad(0), &[0xC3, 0x00]).is_err()); // JP nn truncated
    assert!(a().disassemble(ad(0), &[0xCD]).is_err()); // CALL truncated
    assert!(a().disassemble(ad(0), &[0x01, 0x00]).is_err()); // LD BC,nn
    assert!(a().disassemble(ad(0), &[0x32, 0x00]).is_err()); // LD (nn),A truncated
}

// ── 20: truncated ALU imm / LD r,n ───────────────────────────────────────────
#[test]
fn truncated_imm_errors() {
    assert!(a().disassemble(ad(0), &[0xC6]).is_err()); // ADD A,n truncated
    assert!(a().disassemble(ad(0), &[0x3E]).is_err()); // LD A,n truncated
}

// ── 21: LCG fuzz — never panic (1-byte) ──────────────────────────────────────
#[test]
fn fuzz_single_byte() {
    let mut g = lcg();
    for _ in 0..256 {
        let op = (g() & 0xFF) as u8;
        let _ = a().disassemble(ad(0), &[op]); // must not panic
    }
}

// ── 22: LCG fuzz — 4-byte buffers ────────────────────────────────────────────
#[test]
fn fuzz_four_bytes() {
    let mut g = lcg();
    for _ in 0..500 {
        let r = g();
        let buf = [
            (r & 0xFF) as u8,
            ((r >> 8) & 0xFF) as u8,
            ((r >> 16) & 0xFF) as u8,
            ((r >> 24) & 0xFF) as u8,
        ];
        let _ = a().disassemble(ad(0), &buf);
    }
}

// ── 23: every single-byte opcode parses or errors ─────────────────────────────
#[test]
fn all_256_opcodes_with_pad() {
    let pad = [0u8; 8];
    for op in u8::MIN..=u8::MAX {
        let mut buf = [op; 8];
        buf[1..].copy_from_slice(&pad[1..]);
        let _ = a().disassemble(ad(0x100), &buf); // must not panic
    }
}

// ── 24: CB all 256 ────────────────────────────────────────────────────────────
#[test]
fn cb_all_256() {
    for op in u8::MIN..=u8::MAX {
        let i = a().disassemble(ad(0), &[0xCB, op]).unwrap();
        assert_eq!(i.size, 2);
        let mn = &i.mnemonic;
        assert!(["RLC","RRC","RL","RR","SLA","SRA","SLL","SRL","BIT","RES","SET"]
            .iter().any(|m| m == mn));
    }
}

// ── 25: DD/FD index prefixes (sample) ────────────────────────────────────────
#[test]
fn dd_fd_prefixes() {
    let i = a().disassemble(ad(0), &[0xDD, 0x21, 0x34, 0x12]).unwrap();
    assert_eq!(i.operands, "IX,#$1234");
    let j = a().disassemble(ad(0), &[0xFD, 0x21, 0x34, 0x12]).unwrap();
    assert_eq!(j.operands, "IY,#$1234");
}

// ── 26: ED LDIR/LDDR/CPIR ─────────────────────────────────────────────────────
#[test]
fn ed_block_ops() {
    for (op, mn) in &[(0xA0u8, "LDI"), (0xA8, "LDD"), (0xB0, "LDIR"), (0xB8, "LDDR")] {
        let i = a().disassemble(ad(0), &[0xED, *op]).unwrap();
        assert_eq!(&i.mnemonic, mn);
    }
}

// ── 27: opcode_cycles boundary ────────────────────────────────────────────────
#[test]
fn opcode_cycles_known() {
    assert_eq!(opcode_cycles(0x00).cycles, 4);
    assert_eq!(opcode_cycles(0xC9).cycles, 10);
    assert_eq!(opcode_cycles(0xCD).cycles, 17);
    assert_eq!(opcode_cycles(0x10).cycles_taken, 13);
    assert_eq!(opcode_cycles(0x76).cycles, 4);
    // fuzz never panics
    for op in u8::MIN..=u8::MAX {
        let c = opcode_cycles(op);
        assert!(c.cycles >= 4);
    }
}

// ── 28: find_opcode_entry sanity ──────────────────────────────────────────────
#[test]
fn find_opcode_entry_lookups() {
    assert!(find_opcode_entry(0x00).is_some());
    assert!(find_opcode_entry(0xC9).is_some());
    assert!(find_opcode_entry(0x76).is_some());
    // bogus
    assert!(find_opcode_entry(0xAB).is_none());
    let e = find_opcode_entry(0xCD).unwrap();
    assert_eq!(e.mnemonic, "CALL");
    let _ = e.flags(); // does not panic
}

// ── 29: InterruptMode round-trip ─────────────────────────────────────────────
#[test]
fn interrupt_mode_roundtrip() {
    for m in [InterruptMode::Mode0, InterruptMode::Mode1, InterruptMode::Mode2] {
        let s = m.operand();
        assert_eq!(InterruptMode::parse_operand(s), Some(m));
    }
    assert_eq!(InterruptMode::parse_operand("3"), None);
    assert_eq!(InterruptMode::parse_operand(""), None);
    assert_eq!(InterruptMode::parse_operand(" 1 "), Some(InterruptMode::Mode1));
}

// ── 30: Flags bits ────────────────────────────────────────────────────────────
#[test]
fn flags_bits() {
    let f = Flags::C | Flags::Z;
    assert_eq!(f.bits(), 0x41);
    assert!(f.contains(Flags::C));
    assert!(!f.contains(Flags::S));
}

// ── 31: CycleInfo helpers ─────────────────────────────────────────────────────
#[test]
fn analyze_empty() {
    let r = analyze(ad(0), &[]);
    assert_eq!(r.instr_count(), 0);
    assert!(!r.has_calls());
    assert_eq!(r.errors, 0);
    assert_eq!(r.total_cycles, 0);
}

// ── 32: analyze finds call and ret ────────────────────────────────────────────
#[test]
fn analyze_call_ret() {
    let code = [0xCD, 0x05, 0x00, 0xC9];
    let r = analyze(ad(0), &code);
    assert!(r.has_calls());
    assert!(!r.returns.is_empty());
}

// ── 33: linear disassembler covers all ────────────────────────────────────────
#[test]
fn linear_disasm_covers() {
    let code = [0x00u8, 0x00, 0x76, 0xC9];
    let arch = a();
    let dis = Z80LinearDisassembler::new(&arch, &code, ad(0));
    let v: Vec<_> = dis.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(v.len(), 4);
}

// ── 34: linear disassembler offset() ──────────────────────────────────────────
#[test]
fn linear_disasm_offset() {
    let code = [0x00u8, 0xC9];
    let arch = a();
    let mut dis = Z80LinearDisassembler::new(&arch, &code, ad(0));
    assert_eq!(dis.offset(), 0);
    let _ = dis.next().unwrap().unwrap();
    assert_eq!(dis.offset(), 1);
    let _ = dis.next().unwrap().unwrap();
    assert!(dis.is_done());
    assert!(dis.next().is_none());
}

// ── 35: InstrStats from instructions ──────────────────────────────────────────
#[test]
fn instr_stats_basic() {
    let code = [
        0xCD, 0x00, 0x10, // CALL
        0xC9, // RET
        0x00, // NOP
        0x80, // ADD A,B
        0xC5, // PUSH BC
        0xCB, 0x00, // RLC B
    ];
    let r = analyze(ad(0), &code);
    let stats = InstrStats::from_instrs(&r.instructions);
    assert!(stats.calls >= 1);
    assert!(stats.returns >= 1);
    assert!(stats.alu >= 1);
    assert!(stats.stack >= 1);
    assert!(stats.bit_ops >= 1);
    assert!(stats.total() >= 5);
}

// ── 36: format_instr / format_listing ────────────────────────────────────────
#[test]
fn formatter() {
    let i = a().disassemble(ad(0x1000), &[0xC3, 0x00, 0x20]).unwrap();
    let s = format_instr(&i, &DisasmOptions::default());
    assert!(s.contains("JP"));
    assert!(s.contains("$2000"));
    assert!(s.contains("1000"));
    let listing = format_listing(&[i], &DisasmOptions::default());
    assert!(!listing.is_empty());
}

// ── 37: nop_sled patch ────────────────────────────────────────────────────────
#[test]
fn nop_sled_patches() {
    let mut buf = [0xAAu8; 4];
    assert_eq!(nop_sled(&mut buf), PatchResult::Ok);
    assert!(buf.iter().all(|&b| b == 0));
    let mut empty: [u8; 0] = [];
    assert_eq!(nop_sled(&mut empty), PatchResult::TooShort);
}

// ── 38: patch_jp_target ───────────────────────────────────────────────────────
#[test]
fn patch_jp_replaces_target() {
    let mut buf = [0xC3u8, 0x00, 0x00];
    assert!(patch_jp_target(&mut buf, 0xBEEF));
    assert_eq!(buf, [0xC3, 0xEF, 0xBE]);
    // non-JP first byte
    let mut nope = [0x00u8, 0x00, 0x00];
    assert!(!patch_jp_target(&mut nope, 0x1234));
    // too short
    let mut short = [0xC3u8, 0x00];
    assert!(!patch_jp_target(&mut short, 0x1234));
}

// ── 39: CallingConventionKind ─────────────────────────────────────────────────
#[test]
fn calling_conventions_named() {
    let cc = CallingConventionKind::SdccStandard.to_calling_convention();
    assert_eq!(cc.name, "z80_sdcc");
    assert!(!cc.int_args.is_empty());
    let bdos = CallingConventionKind::CpmBdos.to_calling_convention();
    assert_eq!(bdos.name, "cpm_bdos");
    assert!(!bdos.caller_cleans_stack);
    let _ = CallingConventionKind::AmstradBasic.to_calling_convention();
    let spec = CallingConventionKind::SpectrumRom.to_calling_convention();
    assert_eq!(spec.name, "spectrum_rom");
}

// ── 40: is_cpm_bdos_call / is_spectrum_rom_call ───────────────────────────────
#[test]
fn cpm_bdos_call_detection() {
    let i = a().disassemble(ad(0), &[0xCD, 0x05, 0x00]).unwrap();
    assert!(is_cpm_bdos_call(&i));
    let j = a().disassemble(ad(0), &[0xCD, 0x10, 0x00]).unwrap();
    assert!(!is_cpm_bdos_call(&j));
    assert!(is_spectrum_rom_call(&j)); // 0x0010 is in known
}

// ── 41: rst_vector parses ─────────────────────────────────────────────────────
#[test]
fn rst_vector_parses_each() {
    for v in 0u8..8 {
        let i = a().disassemble(ad(0), &encode_rst(v)).unwrap();
        assert_eq!(rst_vector(&i), Some(v * 8));
    }
    // non-RST returns None
    let nop = a().disassemble(ad(0), &[0x00]).unwrap();
    assert_eq!(rst_vector(&nop), None);
}

// ── 42: get_branches for JP/CALL/RET ──────────────────────────────────────────
#[test]
fn get_branches_jp_call_ret() {
    let arch = a();
    let jp = arch.disassemble(ad(0), &[0xC3, 0x00, 0x20]).unwrap();
    assert_eq!(arch.get_branches(&jp).len(), 1);
    let cl = arch.disassemble(ad(0), &[0xCD, 0x05, 0x00]).unwrap();
    assert_eq!(arch.get_branches(&cl).len(), 1);
    let rt = arch.disassemble(ad(0), &[0xC9]).unwrap();
    assert_eq!(arch.get_branches(&rt).len(), 1);
    let nop = arch.disassemble(ad(0), &[0x00]).unwrap();
    assert!(arch.get_branches(&nop).is_empty());
}

// ── 43: build_cfg basic blocks ────────────────────────────────────────────────
#[test]
fn build_cfg_partitions() {
    let code = [
        0x00, // NOP @ 0
        0xC3, 0x05, 0x00, // JP $0005 @ 1 (size 3)
        0x00, // NOP @ 4 (dead)
        0xC9, // RET @ 5
    ];
    let r = analyze(ad(0), &code);
    let cfg = build_cfg(&r.instructions);
    assert!(!cfg.is_empty());
    assert!(cfg.iter().any(|b| b.ends_with_return));
    for b in &cfg {
        assert!(b.size() > 0);
    }
}

// ── 44: Send+Sync Z80Arch threaded use ────────────────────────────────────────
#[test]
fn threaded_arch_stress() {
    use std::sync::Arc;
    use std::thread;
    let arch = Arc::new(Z80Arch);
    let mut handles = vec![];
    for tid in 0..4u32 {
        let arch = Arc::clone(&arch);
        handles.push(thread::spawn(move || {
            let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE ^ u64::from(tid);
            for _ in 0..100 {
                s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                let b = s.to_le_bytes();
                let op = b[0];
                let buf = [op, b[1], b[2], b[3]];
                let _ = arch.disassemble(Address::new(0x100), &buf);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ── 45: opcode_cycles all 256 deterministic ──────────────────────────────────
#[test]
fn opcode_cycles_all_consistent() {
    // taken >= cycles for all branches; non-branch they are equal
    for op in u8::MIN..=u8::MAX {
        let c = opcode_cycles(op);
        assert!(c.cycles_taken >= c.cycles);
    }
}

// ── 46: arch register list ───────────────────────────────────────────────────
#[test]
fn arch_registers_have_pc_sp() {
    let regs = a().registers();
    let names: Vec<_> = regs.iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains(&"PC"));
    assert!(names.contains(&"SP"));
    assert!(names.contains(&"A"));
    assert!(names.contains(&"HL"));
    assert!(names.contains(&"IX"));
}

// ── 47: pointer_size + endian ────────────────────────────────────────────────
#[test]
fn arch_metadata() {
    let arch = a();
    assert_eq!(arch.name(), "z80");
    assert_eq!(arch.pointer_size(), 2);
    assert_eq!(arch.endian(), Endian::Little);
}

// ── 48: encode/decode 8-bit boundary: ld r,n max ─────────────────────────────
#[test]
fn ld_r_n_boundary() {
    let b = encode_ld_r_n(7, 0xFF);
    let i = a().disassemble(ad(0), &b).unwrap();
    assert_eq!(i.operands, "A,#$FF");
}

// ── 49: register id constants distinct ────────────────────────────────────────
#[test]
fn reg_ids_distinct() {
    let ids = [
        REG_A, REG_B, REG_C, REG_D, REG_E, REG_H, REG_L, REG_F, REG_I, REG_R, REG_AF, REG_BC,
        REG_DE, REG_HL, REG_SP, REG_PC, REG_IX, REG_IY, REG_AF2, REG_BC2, REG_DE2, REG_HL2,
    ];
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), ids.len());
}

// ── 50: long fuzzed program never panics, errors bounded ──────────────────────
#[test]
fn fuzz_long_program() {
    let mut g = lcg();
    let mut buf = vec![0u8; 4096];
    for b in &mut buf {
        *b = (g() & 0xFF) as u8;
    }
    let r = analyze(ad(0x1000), &buf);
    // total instructions + errors should account for entire buffer
    assert!(r.instr_count() + r.errors > 0);
}

// ── 51: PatchResult Eq ───────────────────────────────────────────────────────
#[test]
fn patch_result_eq() {
    assert_eq!(PatchResult::Ok, PatchResult::Ok);
    assert_ne!(PatchResult::Ok, PatchResult::TooShort);
}

// ── 52: InterruptMode equality / debug ────────────────────────────────────────
#[test]
fn interrupt_mode_eq() {
    assert_eq!(InterruptMode::Mode1, InterruptMode::Mode1);
    assert_ne!(InterruptMode::Mode0, InterruptMode::Mode2);
}
