//! blitz2 — deep adversarial integration tests for rustre-arch-avr.
//!
//! Strategy: only exercise public API confirmed in lib.rs. Use a seeded LCG
//! (no rand / no std::time) for fuzz-style coverage. Every test asserts
//! a no-panic / well-formed-Ok-or-Err contract.

use rustre_core::arch::{Architecture, InstrFlags};
use rustre_arch_avr::{
    avr_format, avr_format_with_addr, disassemble_annotated, encode_adc, encode_add,
    encode_and, encode_andi, encode_asr, encode_com, encode_cp, encode_cpc, encode_cpi,
    encode_cpse, encode_dec, encode_eor, encode_inc, encode_ldi, encode_lsr, encode_mov, encode_neg,
    encode_nop, encode_or, encode_ori, encode_pop, encode_push, encode_rcall, encode_ret,
    encode_reti, encode_rjmp, encode_ror, encode_sbci, encode_sleep, encode_sub, encode_subi,
    encode_swap, lookup_io_reg, lookup_reg_role, lookup_vector, AnnotatedAvrInstr, AvrArch,
    AvrBasicBlock, AvrCodeStats, AvrFuncPattern, AvrInstrKind, AvrLinearDisassembler, AvrSregBit,
    AvrVariant, ATMEGA328P_IO_MAP, ATMEGA328P_VECTORS, AVR_REG_ROLES,
};
use rustre_core::address::Address;
use rustre_core::endian::Endian;

// ── LCG fuzz helper ──────────────────────────────────────────────────────────
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn next_u16(&mut self) -> u16 {
        self.next_u64() as u16
    }
    fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }
}

fn arch() -> AvrArch {
    AvrArch::default()
}

fn addr(v: u64) -> Address {
    Address::new(v)
}

fn enc_le(word: u16) -> [u8; 2] {
    word.to_le_bytes()
}

// ── 1. Round-trip: encode → disassemble (50+ deterministic inputs) ──────────

#[test]
fn rt_nop_encode_decode() {
    let bytes = enc_le(encode_nop());
    let i = arch().disassemble(addr(0), &bytes).unwrap();
    assert_eq!(i.mnemonic, "NOP");
}

#[test]
fn rt_ret_reti() {
    let r = arch().disassemble(addr(0), &enc_le(encode_ret())).unwrap();
    assert_eq!(r.mnemonic, "RET");
    let ri = arch().disassemble(addr(0), &enc_le(encode_reti())).unwrap();
    assert_eq!(ri.mnemonic, "RETI");
}

#[test]
fn rt_sleep() {
    let s = arch().disassemble(addr(0), &enc_le(encode_sleep())).unwrap();
    assert_eq!(s.mnemonic, "SLEEP");
}

#[test]
fn rt_mov_all_register_pairs() {
    // 32×32 = 1024 pairs; verify mnemonic is always MOV and operands mention both regs.
    let a = arch();
    for d in 0u8..32 {
        for r in 0u8..32 {
            let w = encode_mov(d, r);
            let instr = a.disassemble(addr(0), &enc_le(w)).unwrap();
            assert_eq!(instr.mnemonic, "MOV", "MOV d={d} r={r} got {}", instr.mnemonic);
            assert!(instr.operands.contains(&format!("R{d}")));
            assert!(instr.operands.contains(&format!("R{r}")));
            assert_eq!(instr.size, 2);
        }
    }
}

#[test]
fn rt_add_all_pairs() {
    let a = arch();
    for d in 0u8..32 {
        for r in 0u8..32 {
            let w = encode_add(d, r);
            let i = a.disassemble(addr(0), &enc_le(w)).unwrap();
            assert_eq!(i.mnemonic, "ADD");
        }
    }
}

#[test]
fn rt_adc_sub_and_or_eor_cp_cpc_cpse() {
    let a = arch();
    let cases: &[(fn(u8, u8) -> u16, &str)] = &[
        (encode_adc, "ADC"),
        (encode_sub, "SUB"),
        (encode_and, "AND"),
        (encode_or, "OR"),
        (encode_eor, "EOR"),
        (encode_cp, "CP"),
        (encode_cpc, "CPC"),
        (encode_cpse, "CPSE"),
    ];
    for (enc, mn) in cases {
        for d in [0u8, 1, 15, 16, 17, 30, 31] {
            for r in [0u8, 1, 15, 16, 17, 30, 31] {
                let w = enc(d, r);
                let i = a.disassemble(addr(0), &enc_le(w)).unwrap();
                assert_eq!(&i.mnemonic, mn, "{mn} d={d} r={r}");
            }
        }
    }
}

#[test]
fn rt_ldi_all_combos() {
    let a = arch();
    for d in 16u8..=31 {
        for k in [0u8, 1, 0x0F, 0x10, 0x7F, 0x80, 0xFE, 0xFF] {
            let w = encode_ldi(d, k);
            let i = a.disassemble(addr(0), &enc_le(w)).unwrap();
            assert_eq!(i.mnemonic, "LDI");
            assert!(i.operands.contains(&format!("R{d}")));
        }
    }
}

#[test]
fn rt_subi_sbci_andi_ori_cpi() {
    let a = arch();
    let cases: &[(fn(u8, u8) -> u16, &str)] = &[
        (encode_subi, "SUBI"),
        (encode_sbci, "SBCI"),
        (encode_andi, "ANDI"),
        (encode_ori, "ORI"),
        (encode_cpi, "CPI"),
    ];
    for (enc, mn) in cases {
        for d in 16u8..=31 {
            for k in [0u8, 0x55, 0xAA, 0xFF] {
                let w = enc(d, k);
                let i = a.disassemble(addr(0), &enc_le(w)).unwrap();
                assert_eq!(&i.mnemonic, mn);
            }
        }
    }
}

#[test]
fn rt_inc_dec_neg_com_lsr_asr_ror_swap() {
    let a = arch();
    let cases: &[(fn(u8) -> u16, &str)] = &[
        (encode_inc, "INC"),
        (encode_dec, "DEC"),
        (encode_neg, "NEG"),
        (encode_com, "COM"),
        (encode_lsr, "LSR"),
        (encode_asr, "ASR"),
        (encode_ror, "ROR"),
        (encode_swap, "SWAP"),
    ];
    for (enc, mn) in cases {
        for d in 0u8..32 {
            let w = enc(d);
            let i = a.disassemble(addr(0), &enc_le(w)).unwrap();
            assert_eq!(&i.mnemonic, mn, "{mn} d={d}");
        }
    }
}

#[test]
fn rt_push_pop() {
    let a = arch();
    for r in 0u8..32 {
        let pw = encode_push(r);
        let i = a.disassemble(addr(0), &enc_le(pw)).unwrap();
        assert_eq!(i.mnemonic, "PUSH");
        let popw = encode_pop(r);
        let p = a.disassemble(addr(0), &enc_le(popw)).unwrap();
        assert_eq!(p.mnemonic, "POP");
    }
}

#[test]
fn rt_rjmp_boundary_displacements() {
    let a = arch();
    for k in [-2048i16, -1024, -2, -1, 0, 1, 2, 1024, 2047] {
        let w = encode_rjmp(k);
        let i = a.disassemble(addr(0x100), &enc_le(w)).unwrap();
        assert_eq!(i.mnemonic, "RJMP");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }
}

#[test]
fn rt_rcall_boundary_displacements() {
    let a = arch();
    for k in [-2048i16, 0, 2047] {
        let w = encode_rcall(k);
        let i = a.disassemble(addr(0x100), &enc_le(w)).unwrap();
        assert_eq!(i.mnemonic, "RCALL");
        assert!(i.flags.contains(InstrFlags::CALL));
    }
}

// ── 2. Panic-path tests (encoder out-of-range) ──────────────────────────────

#[test]
#[should_panic]
fn encode_rjmp_too_high_panics() {
    let _ = encode_rjmp(2048);
}

#[test]
#[should_panic]
fn encode_rjmp_too_low_panics() {
    let _ = encode_rjmp(-2049);
}

#[test]
#[should_panic]
fn encode_rcall_too_high_panics() {
    let _ = encode_rcall(2048);
}

#[test]
#[should_panic]
fn encode_mov_bad_reg_panics() {
    let _ = encode_mov(32, 0);
}

#[test]
#[should_panic]
fn encode_ldi_bad_reg_panics() {
    let _ = encode_ldi(15, 0);
}

// ── 3. Seeded LCG fuzz: never panic on arbitrary input ─────────────────────

#[test]
fn fuzz_disassemble_random_words() {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mut g = || {
        s = s.wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    };
    let a = arch();
    for _ in 0..5000 {
        let v = g();
        let bytes = v.to_le_bytes();
        // 2- and 4-byte slices
        for take in [2usize, 4] {
            let pc = (g() >> 1) & 0x3F_FFFF;
            let result = a.disassemble(addr(pc), &bytes[..take]);
            match result {
                Ok(instr) => {
                    assert!(instr.size == 2 || instr.size == 4);
                    assert!(!instr.mnemonic.is_empty());
                    assert!(instr.size <= take);
                }
                Err(_) => {} // CoreError ok
            }
        }
    }
}

#[test]
fn fuzz_disassemble_4byte_no_panic() {
    let mut s: u64 = 0x1234_5678_9ABC_DEF0;
    let mut g = || {
        s = s.wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    };
    let a = arch();
    for _ in 0..4000 {
        let v = g();
        let bytes = v.to_le_bytes();
        let pc = (g() >> 1) & 0xFFFF;
        let _ = a.disassemble(addr(pc), &bytes[..2]);
        let _ = a.disassemble(addr(pc), &bytes[..4]);
    }
}

#[test]
fn fuzz_linear_disassembler_random_stream() {
    let mut s: u64 = 0xAAAA_BBBB_CCCC_DDDD;
    let mut g = || {
        s = s.wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    };
    let a = arch();
    for _ in 0..50 {
        let mut buf = Vec::with_capacity(128);
        for _ in 0..64 {
            buf.push(g() as u8);
        }
        let mut count = 0;
        for r in AvrLinearDisassembler::new(&a, &buf, addr(0)) {
            count += 1;
            if let Ok(instr) = r {
                assert!(instr.size == 2 || instr.size == 4);
            }
            if count > 200 {
                panic!("linear sweep ran away");
            }
        }
        assert!(count > 0);
    }
}

#[test]
fn fuzz_code_stats_never_panic() {
    let mut s: u64 = 0x9999_8888_7777_6666;
    let mut g = || {
        s = s.wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    };
    let a = arch();
    for _ in 0..20 {
        let mut buf = Vec::with_capacity(256);
        for _ in 0..128 {
            buf.push(g() as u8);
        }
        let stats = AvrCodeStats::from_bytes(&a, &buf, addr(0));
        // total + errors must be > 0 (stream non-empty)
        let class_sum = stats.nops
            + stats.arithmetic
            + stats.logic
            + stats.shifts
            + stats.compares
            + stats.transfers
            + stats.loads
            + stats.stores
            + stats.io_ops
            + stats.stack_ops
            + stats.cond_branches
            + stats.branches
            + stats.calls
            + stats.returns
            + stats.bit_ops
            + stats.system;
        // sum of classified+unknown == total
        assert!(class_sum <= stats.total);
    }
}

#[test]
fn fuzz_basic_blocks_never_panic() {
    let mut s: u64 = 0x1111_2222_3333_4444;
    let mut g = || {
        s = s.wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    };
    let a = arch();
    for _ in 0..20 {
        let mut buf = Vec::with_capacity(64);
        for _ in 0..32 {
            buf.push(g() as u8);
        }
        // Errors propagate as Err; either Ok with vec or Err — neither panic.
        let _ = AvrBasicBlock::find_blocks(&a, &buf, addr(0));
    }
}

// ── 4. Boundary inputs ───────────────────────────────────────────────────────

#[test]
fn boundary_empty_disasm_returns_err() {
    let a = arch();
    assert!(a.disassemble(addr(0), &[]).is_err());
}

#[test]
fn boundary_single_byte_disasm_returns_err() {
    let a = arch();
    assert!(a.disassemble(addr(0), &[0x00]).is_err());
}

#[test]
fn boundary_truncated_jmp_returns_err() {
    // JMP encoding word = 0x940C; with only 2 bytes -> error.
    let a = arch();
    let r = a.disassemble(addr(0), &[0x0C, 0x94]);
    assert!(r.is_err());
}

#[test]
fn boundary_truncated_call_returns_err() {
    let a = arch();
    assert!(a.disassemble(addr(0), &[0x0E, 0x94]).is_err());
}

#[test]
fn boundary_truncated_lds_returns_err() {
    let a = arch();
    assert!(a.disassemble(addr(0), &[0x00, 0x90]).is_err());
}

#[test]
fn boundary_truncated_sts_returns_err() {
    let a = arch();
    assert!(a.disassemble(addr(0), &[0x00, 0x92]).is_err());
}

#[test]
fn boundary_oversize_input_ok() {
    let a = arch();
    let bytes = [0x00u8, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let i = a.disassemble(addr(0), &bytes).unwrap();
    assert_eq!(i.mnemonic, "NOP");
    assert_eq!(i.size, 2);
}

#[test]
fn boundary_pc_max_no_panic() {
    let a = arch();
    let _ = a.disassemble(addr(u64::MAX), &[0x00, 0xC0]);
    let _ = a.disassemble(addr(u64::MAX - 1), &[0xFF, 0xCF]);
}

#[test]
fn boundary_pc_zero() {
    let a = arch();
    let i = a.disassemble(addr(0), &enc_le(encode_nop())).unwrap();
    assert_eq!(i.mnemonic, "NOP");
}

// ── 5. Architecture trait invariants ─────────────────────────────────────────

#[test]
fn arch_endian_little() {
    assert_eq!(arch().endian(), Endian::Little);
}

#[test]
fn arch_pointer_size_is_two() {
    assert_eq!(arch().pointer_size(), 2);
}

#[test]
fn arch_variants_names_distinct() {
    let a = AvrArch::new(AvrVariant::Attiny);
    let m = AvrArch::new(AvrVariant::Atmega);
    let x = AvrArch::new(AvrVariant::Xmega);
    assert_eq!(a.name(), "avr-tiny");
    assert_eq!(m.name(), "avr-mega");
    assert_eq!(x.name(), "avr-xmega");
    assert_ne!(a.name(), m.name());
    assert_ne!(m.name(), x.name());
}

#[test]
fn arch_registers_have_pc_sp_sreg() {
    let regs = arch().registers();
    assert!(regs.iter().any(|r| r.name == "PC"));
    assert!(regs.iter().any(|r| r.name == "SP"));
    assert!(regs.iter().any(|r| r.name == "SREG"));
    assert!(regs.iter().any(|r| r.name == "R0"));
    assert!(regs.iter().any(|r| r.name == "R31"));
}

#[test]
fn arch_branches_extract_target_for_rjmp() {
    let a = arch();
    let w = encode_rjmp(3);
    let instr = a.disassemble(addr(0x200), &enc_le(w)).unwrap();
    let br = a.get_branches(&instr);
    assert!(!br.is_empty());
    assert!(br[0].target.is_some());
}

#[test]
fn arch_branches_empty_for_nop() {
    let a = arch();
    let instr = a.disassemble(addr(0), &enc_le(encode_nop())).unwrap();
    assert!(a.get_branches(&instr).is_empty());
}

// ── 6. State machine: linear sweep over mix ─────────────────────────────────

#[test]
fn linear_sweep_size_advance_invariant() {
    let a = arch();
    // mixed stream: NOP, JMP 0x000100, NOP, RET
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&enc_le(encode_nop()));
    bytes.extend_from_slice(&[0x0C, 0x94, 0x00, 0x01]); // JMP 0x100
    bytes.extend_from_slice(&enc_le(encode_nop()));
    bytes.extend_from_slice(&enc_le(encode_ret()));
    let mut total = 0;
    for r in AvrLinearDisassembler::new(&a, &bytes, addr(0)) {
        let i = r.unwrap();
        total += i.size;
    }
    assert_eq!(total, bytes.len());
}

#[test]
fn linear_sweep_terminates_on_truncated_last_byte() {
    let a = arch();
    let bytes = [0x00u8, 0x00, 0x00]; // NOP + leftover 1 byte
    let mut count = 0;
    for _ in AvrLinearDisassembler::new(&a, &bytes, addr(0)) {
        count += 1;
        if count > 5 {
            panic!("did not terminate");
        }
    }
}

// ── 7. AvrInstrKind classification consistency ──────────────────────────────

#[test]
fn kind_classification_all_known_mnemonics() {
    let mnemonics_kinds: &[(&str, AvrInstrKind)] = &[
        ("NOP", AvrInstrKind::Nop),
        ("ADD", AvrInstrKind::Arithmetic),
        ("SUB", AvrInstrKind::Arithmetic),
        ("MUL", AvrInstrKind::Arithmetic),
        ("AND", AvrInstrKind::Logic),
        ("OR", AvrInstrKind::Logic),
        ("EOR", AvrInstrKind::Logic),
        ("LSR", AvrInstrKind::Shift),
        ("CP", AvrInstrKind::Compare),
        ("MOV", AvrInstrKind::Transfer),
        ("LDI", AvrInstrKind::Transfer),
        ("LD", AvrInstrKind::Load),
        ("ST", AvrInstrKind::Store),
        ("IN", AvrInstrKind::Io),
        ("OUT", AvrInstrKind::Io),
        ("PUSH", AvrInstrKind::Stack),
        ("POP", AvrInstrKind::Stack),
        ("BRNE", AvrInstrKind::CondBranch),
        ("BREQ", AvrInstrKind::CondBranch),
        ("RJMP", AvrInstrKind::Branch),
        ("JMP", AvrInstrKind::Branch),
        ("RCALL", AvrInstrKind::Call),
        ("CALL", AvrInstrKind::Call),
        ("RET", AvrInstrKind::Return),
        ("RETI", AvrInstrKind::Return),
        ("SLEEP", AvrInstrKind::System),
        ("WDR", AvrInstrKind::System),
        ("BREAK", AvrInstrKind::System),
        ("SEI", AvrInstrKind::BitOp),
        ("CLI", AvrInstrKind::BitOp),
        ("UNKNOWN_XYZ", AvrInstrKind::Unknown),
    ];
    for (mn, kind) in mnemonics_kinds {
        let got = AvrInstrKind::from_mnemonic(mn);
        assert_eq!(&got, kind, "mnemonic {mn}");
    }
}

#[test]
fn kind_helpers() {
    assert!(AvrInstrKind::Branch.is_control_flow());
    assert!(AvrInstrKind::CondBranch.is_control_flow());
    assert!(AvrInstrKind::Call.is_control_flow());
    assert!(AvrInstrKind::Return.is_control_flow());
    assert!(!AvrInstrKind::Arithmetic.is_control_flow());
    assert!(AvrInstrKind::Load.is_memory());
    assert!(AvrInstrKind::Store.is_memory());
    assert!(!AvrInstrKind::Logic.is_memory());
    assert!(AvrInstrKind::Io.is_io());
    assert!(!AvrInstrKind::Load.is_io());
}

// ── 8. Static tables sanity ─────────────────────────────────────────────────

#[test]
fn io_map_no_duplicate_addrs() {
    let mut seen = [false; 256];
    for r in ATMEGA328P_IO_MAP {
        assert!(!seen[r.addr as usize], "dup addr {:#X}", r.addr);
        seen[r.addr as usize] = true;
        assert!(!r.name.is_empty());
    }
}

#[test]
fn io_map_lookup_round_trip() {
    for r in ATMEGA328P_IO_MAP {
        let found = lookup_io_reg(r.addr).unwrap();
        assert_eq!(found.name, r.name);
    }
}

#[test]
fn io_map_lookup_unknown_addr_none() {
    // 0xFF is unused in the static table.
    assert!(lookup_io_reg(0xFF).is_none());
}

#[test]
fn vectors_no_duplicate_numbers_and_offset_progression() {
    let mut seen = [false; 256];
    let mut last_off: i32 = -1;
    for v in ATMEGA328P_VECTORS {
        assert!(!seen[v.number as usize]);
        seen[v.number as usize] = true;
        assert!(i32::from(v.byte_offset) > last_off);
        last_off = i32::from(v.byte_offset);
    }
}

#[test]
fn vectors_lookup_round_trip() {
    for v in ATMEGA328P_VECTORS {
        let f = lookup_vector(v.number).unwrap();
        assert_eq!(f.name, v.name);
        assert_eq!(f.byte_offset, v.byte_offset);
    }
}

#[test]
fn vectors_lookup_unknown_returns_none() {
    assert!(lookup_vector(255).is_none());
    assert!(lookup_vector(100).is_none());
}

#[test]
fn reg_roles_all_32_present_no_dup() {
    assert_eq!(AVR_REG_ROLES.len(), 32);
    let mut seen = [false; 32];
    for r in AVR_REG_ROLES {
        assert!((r.number as usize) < 32);
        assert!(!seen[r.number as usize]);
        seen[r.number as usize] = true;
        let f = lookup_reg_role(r.number).unwrap();
        assert_eq!(f.name, r.name);
    }
}

#[test]
fn reg_roles_param_indices_consistent() {
    // R24:R25 = param 0, R22:R23 = param 1, R20:R21 = param 2.
    assert_eq!(lookup_reg_role(24).unwrap().param_index, Some(0));
    assert_eq!(lookup_reg_role(25).unwrap().param_index, Some(0));
    assert_eq!(lookup_reg_role(22).unwrap().param_index, Some(1));
    assert_eq!(lookup_reg_role(23).unwrap().param_index, Some(1));
    assert_eq!(lookup_reg_role(20).unwrap().param_index, Some(2));
    assert_eq!(lookup_reg_role(21).unwrap().param_index, Some(2));
    assert_eq!(lookup_reg_role(0).unwrap().param_index, None);
}

#[test]
fn reg_role_lookup_out_of_range() {
    assert!(lookup_reg_role(32).is_none());
    assert!(lookup_reg_role(255).is_none());
}

// ── 9. SREG bits ─────────────────────────────────────────────────────────────

#[test]
fn sreg_masks_powers_of_two() {
    for bit in [
        AvrSregBit::C,
        AvrSregBit::Z,
        AvrSregBit::N,
        AvrSregBit::V,
        AvrSregBit::S,
        AvrSregBit::H,
        AvrSregBit::T,
        AvrSregBit::I,
    ] {
        let m = bit.mask();
        assert!(m != 0 && (m & m.wrapping_sub(1)) == 0, "mask {m:#X} not pow2");
        assert!(!bit.name().is_empty());
    }
}

#[test]
fn sreg_bits_distinct_masks() {
    let bits = [
        AvrSregBit::C,
        AvrSregBit::Z,
        AvrSregBit::N,
        AvrSregBit::V,
        AvrSregBit::S,
        AvrSregBit::H,
        AvrSregBit::T,
        AvrSregBit::I,
    ];
    let mut union: u8 = 0;
    for b in bits {
        assert_eq!(union & b.mask(), 0, "overlap with {}", b.name());
        union |= b.mask();
    }
    assert_eq!(union, 0xFF);
}

// ── 10. Formatting / patterns ────────────────────────────────────────────────

#[test]
fn format_no_operand_is_just_mnemonic() {
    let i = arch().disassemble(addr(0), &enc_le(encode_nop())).unwrap();
    assert_eq!(avr_format(&i), "NOP");
}

#[test]
fn format_with_addr_contains_addr_and_mnemonic() {
    let i = arch().disassemble(addr(0x1234), &enc_le(encode_nop())).unwrap();
    let s = avr_format_with_addr(&i);
    assert!(s.contains("001234"));
    assert!(s.contains("NOP"));
}

#[test]
fn pattern_push_pop_ret() {
    let a = arch();
    let push = a.disassemble(addr(0), &enc_le(encode_push(28))).unwrap();
    assert!(matches!(
        AvrFuncPattern::from_instr(&push),
        AvrFuncPattern::SaveReg(_)
    ));
    let pop = a.disassemble(addr(0), &enc_le(encode_pop(28))).unwrap();
    assert!(matches!(
        AvrFuncPattern::from_instr(&pop),
        AvrFuncPattern::RestoreReg(_)
    ));
    let ret = a.disassemble(addr(0), &enc_le(encode_ret())).unwrap();
    assert_eq!(AvrFuncPattern::from_instr(&ret), AvrFuncPattern::FuncReturn);
    let none = a.disassemble(addr(0), &enc_le(encode_nop())).unwrap();
    assert_eq!(AvrFuncPattern::from_instr(&none), AvrFuncPattern::None);
}

#[test]
fn annotated_disasm_pairs_kinds_correctly() {
    let a = arch();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&enc_le(encode_nop()));
    bytes.extend_from_slice(&enc_le(encode_add(1, 2)));
    bytes.extend_from_slice(&enc_le(encode_ret()));
    let ann: Vec<AnnotatedAvrInstr> =
        disassemble_annotated(&a, &bytes, addr(0)).unwrap();
    assert_eq!(ann.len(), 3);
    assert_eq!(ann[0].kind, AvrInstrKind::Nop);
    assert_eq!(ann[1].kind, AvrInstrKind::Arithmetic);
    assert_eq!(ann[2].kind, AvrInstrKind::Return);
}

// ── 11. Basic block construction ─────────────────────────────────────────────

#[test]
fn basic_blocks_single_block_no_terminator() {
    let a = arch();
    let bytes = [0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00]; // 3 NOPs
    let bb = AvrBasicBlock::find_blocks(&a, &bytes, addr(0)).unwrap();
    assert_eq!(bb.len(), 1);
    assert_eq!(bb[0].len(), 3);
    assert!(!bb[0].is_empty());
}

#[test]
fn basic_blocks_ret_terminates() {
    let a = arch();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&enc_le(encode_nop()));
    bytes.extend_from_slice(&enc_le(encode_ret()));
    bytes.extend_from_slice(&enc_le(encode_nop()));
    let bb = AvrBasicBlock::find_blocks(&a, &bytes, addr(0)).unwrap();
    assert_eq!(bb.len(), 2);
}

// ── 12. Integer overflow / wrap paths ───────────────────────────────────────

#[test]
fn pc_wrap_arithmetic_no_panic() {
    let a = arch();
    // RJMP near u64::MAX must not panic.
    let high = u64::MAX - 100;
    let _ = a.disassemble(addr(high), &[0xFF, 0xCF]);
    let _ = a.disassemble(addr(high), &[0x00, 0xC0]);
    let _ = a.disassemble(addr(high), &[0xFF, 0xCF]);
}

#[test]
fn rjmp_negative_displacement_no_panic_at_zero() {
    let a = arch();
    // Decode RJMP with k=-1 at pc=0 — wrap result is irrelevant; mustn't panic.
    let w = encode_rjmp(-1);
    let _ = a.disassemble(addr(0), &enc_le(w)).unwrap();
}

// ── 13. Calling convention ──────────────────────────────────────────────────

#[test]
fn calling_conv_present_and_has_r24() {
    let cc = arch().calling_conventions();
    assert!(!cc.is_empty());
    assert_eq!(cc[0].name, "avr_gcc");
    assert!(cc[0].return_regs.iter().any(|r| r == "R24"));
}

// ── 14. Display ↔ classification consistency for decoded instrs ─────────────

#[test]
fn decoded_mnemonic_classified_to_known_kind() {
    let mut s: u64 = 0xFFFF_0000_AAAA_5555;
    let mut g = || {
        s = s.wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    };
    let a = arch();
    for _ in 0..2000 {
        let bytes = (g() as u32).to_le_bytes();
        if let Ok(instr) = a.disassemble(addr(0), &bytes) {
            // from_mnemonic must produce a defined variant — never panic.
            let _ = AvrInstrKind::from_mnemonic(&instr.mnemonic);
        }
    }
}

// ── 15. Send + Sync threaded stress for AvrArch ─────────────────────────────

#[test]
fn arch_send_sync_4_threads_100_ops() {
    use std::sync::Arc;
    use std::thread;
    let arc = Arc::new(AvrArch::default());
    let mut handles = Vec::new();
    for t in 0..4u64 {
        let arc2 = Arc::clone(&arc);
        handles.push(thread::spawn(move || {
            let mut s: u64 = 0xCAFE_BABE ^ (t * 0x9E37_79B9);
            let mut g = || {
                s = s.wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                s
            };
            for _ in 0..100 {
                let w = g() as u16;
                let bytes = w.to_le_bytes();
                let _ = arc2.disassemble(addr(0), &bytes);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ── LCG-driven fuzz: ensure disassemble never panics on seeded random words ─
//
// Wires in the seeded `Lcg` helper declared at the top of this file. The
// fuzzer is deterministic (fixed seeds) so failures are reproducible without
// depending on `rand` or wall-clock time.
#[test]
fn fuzz_disassemble_never_panics_lcg() {
    let a = arch();
    for seed in [0x0123_4567_89ab_cdef_u64, 0xDEAD_BEEF_CAFE_BABE, 1, 42] {
        let mut rng = Lcg::new(seed);
        for _ in 0..4096 {
            let word = rng.next_u16();
            let bytes = enc_le(word);
            // Must either return Ok or Err — never panic.
            let _ = a.disassemble(addr(u64::from(rng.next_u8())), &bytes);
            // Two-byte prefix sanity: also exercise next_u8 path directly.
            let pair = [rng.next_u8(), rng.next_u8()];
            let _ = a.disassemble(addr(0), &pair);
        }
    }
}
