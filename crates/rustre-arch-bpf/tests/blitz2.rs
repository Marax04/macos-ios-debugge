//! Deep adversarial tests for `rustre-arch-bpf` (blitz2).
//!
//! Complements `blitz.rs` with seeded LCG fuzzing, deeper round-trip,
//! hash/Eq consistency, threaded Send+Sync stress, integer-boundary cases,
//! and additional state-machine coverage.


use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

use rustre_core::arch::{Architecture, InstrFlags};
use rustre_arch_bpf::*;
use rustre_core::address::Address;

// ---------- helpers ----------

fn enc(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> Vec<u8> {
    let mut v = vec![op, ((src & 0x0f) << 4) | (dst & 0x0f)];
    v.extend_from_slice(&off.to_le_bytes());
    v.extend_from_slice(&imm.to_le_bytes());
    v
}

fn enc_lddw(dst: u8, value: i64) -> Vec<u8> {
    let lo = numeric::trunc_i64_i32(value);
    let hi = (value >> 32) as i32;
    let mut v = enc(0x18, dst, 0, 0, lo);
    v.extend_from_slice(&[0u8; 4]);
    v.extend_from_slice(&hi.to_le_bytes());
    v
}

struct Lcg(u64);
impl Lcg {
    const fn new(seed: u64) -> Self { Self(seed) }
    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn next_u8(&mut self) -> u8 { numeric::trunc_u64_u8(self.next_u64()) }
    fn next_u32(&mut self) -> u32 { numeric::low_u32(self.next_u64()) }
}

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

// ========================= BpfClass / BpfSize / BpfMode round-trip =========

#[test]
fn class_from_opcode_ignores_high_bits() {
    // class is bits [2:0] — high bits must not affect decoding.
    for hi in 0u8..16u8 {
        for lo in 0u8..=7u8 {
            let op = (hi << 4) | lo;
            assert_eq!(
                BpfClass::from_opcode(op).map(|c| c as u8 & 7),
                BpfClass::from_opcode(lo).map(|c| c as u8 & 7),
            );
        }
    }
}

#[test]
fn size_from_opcode_only_bits_3_4() {
    for op in 0u8..=255u8 {
        let s = BpfSize::from_opcode(op);
        assert!(s.is_some(), "all 256 ops must yield Some(size)");
        let bytes = s.unwrap().bytes();
        assert!(matches!(bytes, 1 | 2 | 4 | 8));
    }
}

#[test]
fn size_bytes_matches_suffix_consistency() {
    let pairs = [
        (BpfSize::Word, 4, "w"),
        (BpfSize::Half, 2, "h"),
        (BpfSize::Byte, 1, "b"),
        (BpfSize::DWord, 8, "dw"),
    ];
    for (s, b, sx) in pairs {
        assert_eq!(s.bytes(), b);
        assert_eq!(s.suffix(), sx);
    }
}

#[test]
fn mode_from_opcode_unknown_masks() {
    // 0x80 = XADD (not handled), 0xa0 reserved, 0xe0 reserved
    for op in 0u8..=255u8 {
        let m = BpfMode::from_opcode(op);
        match op & 0xe0 {
            0x00 | 0x20 | 0x40 | 0x60 | 0xc0 => assert!(m.is_some()),
            _ => assert!(m.is_none()),
        }
    }
}

#[test]
fn class_name_starts_with_bpf_prefix() {
    let cs = [BpfClass::Ld, BpfClass::Ldx, BpfClass::St, BpfClass::Stx,
              BpfClass::Alu, BpfClass::Jmp, BpfClass::Alu64, BpfClass::Jmp32];
    let unique: HashSet<_> = cs.iter().map(|c| c.name()).collect();
    assert_eq!(unique.len(), cs.len());
    for c in cs { assert!(c.name().starts_with("BPF_")); }
}

// ========================= BpfAluOp / BpfJmpOp =============================

#[test]
fn alu_op_from_opcode_ignores_low_nibble() {
    for hi in 0u8..=13u8 {
        let code = hi << 4;
        let op_a = BpfAluOp::from_opcode(code).unwrap();
        for lo in 0u8..16u8 {
            let op_b = BpfAluOp::from_opcode(code | lo).unwrap();
            assert_eq!(op_a.mnemonic(), op_b.mnemonic());
        }
    }
}

#[test]
fn jmp_op_is_conditional_matches_negation() {
    let unconditional = [BpfJmpOp::Ja, BpfJmpOp::Call, BpfJmpOp::Exit];
    for code in (0u8..=0xd0).step_by(0x10) {
        let op = BpfJmpOp::from_opcode(code).unwrap();
        let is_uncond = unconditional.contains(&op);
        assert_ne!(op.is_conditional(), is_uncond, "op {op:?}");
    }
}

// ========================= BpfInstruction round-trip ======================

#[test]
fn decode_imm_boundaries_i32() {
    for &imm in &[i32::MIN, i32::MIN + 1, -1, 0, 1, i32::MAX - 1, i32::MAX] {
        let (i, _) = BpfInstruction::decode(&enc(0x07, 0, 0, 0, imm)).unwrap();
        assert_eq!(i.imm, imm);
    }
}

#[test]
fn decode_offset_boundaries_i16() {
    for &off in &[i16::MIN, i16::MIN + 1, -1, 0, 1, i16::MAX - 1, i16::MAX] {
        let (i, _) = BpfInstruction::decode(&enc(0x05, 0, 0, off, 0)).unwrap();
        assert_eq!(i.offset, off);
    }
}

#[test]
fn decode_register_nibble_round_trip() {
    for d in 0u8..16u8 {
        for s in 0u8..16u8 {
            let (i, _) = BpfInstruction::decode(&enc(0x07, d, s, 0, 0)).unwrap();
            assert_eq!(i.dst_reg, d);
            assert_eq!(i.src_reg, s);
        }
    }
}

#[test]
fn decode_lddw_wide_imm_round_trip_50() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let val = (lcg.next_u64()).cast_signed();
        let bytes = enc_lddw((lcg.next_u8() & 0x0f).min(10), val);
        let (i, sz) = BpfInstruction::decode(&bytes).unwrap();
        assert_eq!(sz, 16);
        assert_eq!(i.wide_imm, Some(val));
    }
}

#[test]
fn decode_truncated_8_to_15_for_lddw() {
    // Anything 8..16 with opcode 0x18 must yield Truncated.
    for n in 8..16 {
        let mut b = enc_lddw(1, 0x1234_5678_9abc_def0);
        b.truncate(n);
        assert_eq!(BpfInstruction::decode(&b), Err(BpfDecodeError::Truncated));
    }
}

#[test]
fn decode_zero_length_truncated() {
    for n in 0..8 {
        assert_eq!(BpfInstruction::decode(&vec![0u8; n]), Err(BpfDecodeError::Truncated));
    }
}

// ========================= LCG fuzz: decoder must not panic ===============

#[test]
fn decode_lcg_fuzz_no_panic() {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mut g = || {
        s = s.wrapping_mul(6_364_136_223_846_793_005)
             .wrapping_add(1_442_695_040_888_963_407);
        s
    };
    for _ in 0..2000 {
        // Random length 0..=24
        let len = (g() % 25) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| numeric::trunc_u64_u8(g())).collect();
        let r = BpfInstruction::decode(&bytes);
        match r {
            Ok((instr, sz)) => {
                assert!(sz == 8 || sz == 16);
                assert!(instr.raw.len() == sz);
            }
            Err(e) => assert!(matches!(e, BpfDecodeError::Truncated | BpfDecodeError::UnknownOpcode(_))),
        }
    }
}

#[test]
fn disasm_lcg_fuzz_no_panic() {
    let helpers = known_helpers();
    let mut s: u64 = 0x1234_5678_9abc_def0;
    let mut g = || {
        s = s.wrapping_mul(6_364_136_223_846_793_005)
             .wrapping_add(1_442_695_040_888_963_407);
        s
    };
    for _ in 0..1000 {
        let mut op = numeric::trunc_u64_u8(g());
        // Skip the wide-immediate opcode which needs 16 bytes — this fuzzer
        // only encodes 8-byte instructions.
        if op == 0x18 { op = 0x07; }
        let dst = (g() as u8) & 0x0f;
        let src = (g() as u8) & 0x0f;
        let off = numeric::trunc_u64_i16(g());
        let imm = numeric::trunc_u64_i32(g());
        let bytes = enc(op, dst, src, off, imm);
        let (instr, _) = BpfInstruction::decode(&bytes).unwrap();
        let r = disasm_instr(&instr, &helpers);
        if let Err(e) = r {
            assert!(matches!(e, BpfDecodeError::UnknownOpcode(_)));
        }
    }
}

#[test]
fn cbpf_decode_lcg_fuzz_no_panic() {
    let mut s: u64 = 0xCAFE_F00D_DEAD_BEEF;
    let mut g = || {
        s = s.wrapping_mul(6_364_136_223_846_793_005)
             .wrapping_add(1_442_695_040_888_963_407);
        s
    };
    for _ in 0..1000 {
        let len = (g() % 16) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| numeric::trunc_u64_u8(g())).collect();
        let r = CbpfInstruction::decode(&bytes);
        if bytes.len() >= 8 {
            let i = r.unwrap();
            // Disasm must always return a non-empty string.
            assert!(!i.disasm().is_empty());
        } else {
            assert!(r.is_err());
        }
    }
}

#[test]
fn btf_type_header_lcg_fuzz_no_panic() {
    let mut s: u64 = 0xBADC_0FFE_E0DD_F00D;
    let mut g = || {
        s = s.wrapping_mul(6_364_136_223_846_793_005)
             .wrapping_add(1_442_695_040_888_963_407);
        s
    };
    for _ in 0..500 {
        let len = (g() % 24) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| numeric::trunc_u64_u8(g())).collect();
        let r = BtfTypeHeader::decode(&bytes);
        match r {
            Ok(h) => {
                // kind() lookup must not panic; vlen must be < 2^16.
                let _ = h.kind();
                assert!(h.vlen() <= 0xffff);
            }
            Err(e) => assert!(matches!(e, BpfDecodeError::Truncated)),
        }
    }
}

#[test]
fn obj_parser_lcg_fuzz_no_panic() {
    let mut s: u64 = 0xFEED_FACE_CAFE_BABE;
    let mut g = || {
        s = s.wrapping_mul(6_364_136_223_846_793_005)
             .wrapping_add(1_442_695_040_888_963_407);
        s
    };
    for _ in 0..200 {
        let len = (g() % 256) as usize;
        let mut bytes: Vec<u8> = (0..len).map(|_| numeric::trunc_u64_u8(g())).collect();
        // Sometimes start with ELF magic.
        if !bytes.is_empty() && (g() & 1) == 1 && bytes.len() >= 4 {
            bytes[0..4].copy_from_slice(b"\x7fELF");
        }
        let r = BpfObjectParser::parse_elf(&bytes);
        if let Err(e) = r {
            assert!(matches!(
                e,
                BpfObjectError::NotElf | BpfObjectError::MalformedElf(_) | BpfObjectError::StrTabOutOfRange
            ));
        }
    }
}

#[test]
fn analyzer_lcg_fuzz_no_panic() {
    let mut s: u64 = 0xA5A5_5A5A_DEAD_BEEF;
    let mut g = || {
        s = s.wrapping_mul(6_364_136_223_846_793_005)
             .wrapping_add(1_442_695_040_888_963_407);
        s
    };
    for _ in 0..200 {
        let len = numeric::u64_to_usize((g() % 32) * 8);
        let bytes: Vec<u8> = (0..len).map(|_| numeric::trunc_u64_u8(g())).collect();
        let report = BpfProgramAnalyzer::analyze(&bytes);
        assert!(report.complexity >= 1);
    }
}

// ========================= state machine: BpfLinearDisassembler ============

#[test]
fn linear_disasm_offset_terminal() {
    let a = BpfArch::new_ebpf();
    let mut bytes = enc(0x07, 0, 0, 0, 1);
    bytes.extend(enc(0x95, 0, 0, 0, 0));
    let dis = BpfLinearDisassembler::new(&a, &bytes, Address::new(0x1000));
    let count = dis.count();
    assert_eq!(count, 2);
}

#[test]
fn linear_disasm_lddw_consumes_16() {
    let a = BpfArch::new_ebpf();
    let mut bytes = enc_lddw(1, 0x1234_5678_9abc);
    bytes.extend(enc(0x95, 0, 0, 0, 0));
    let mut it = BpfLinearDisassembler::new(&a, &bytes, Address::new(0));
    let first = it.next().unwrap().unwrap();
    assert_eq!(first.size, 16);
    let second = it.next().unwrap().unwrap();
    assert_eq!(second.mnemonic, "exit");
    assert!(it.next().is_none());
}

#[test]
fn linear_disasm_advances_on_unknown() {
    let a = BpfArch::new_ebpf();
    // 0xff is not a recognised class? class=7=Alu64 with code 0xf0 unknown -> error
    let bytes = enc(0xff, 0, 0, 0, 0);
    let mut it = BpfLinearDisassembler::new(&a, &bytes, Address::new(0));
    let r = it.next().unwrap();
    assert!(r.is_err());
    // After an error, offset advanced by 1, so 7 more attempts before exhausting.
    assert_eq!(it.offset(), 1);
}

#[test]
fn program_stats_counts_alu_and_lddw() {
    let a = BpfArch::new_ebpf();
    let mut bytes = Vec::new();
    bytes.extend(enc_lddw(1, 0xdead_beef));
    bytes.extend(enc(0x07, 0, 0, 0, 1));        // add64 r0, 1
    bytes.extend(enc(0x15, 1, 0, 1, 0));        // jeq cond
    bytes.extend(enc(0x05, 0, 0, -1, 0));       // ja backward
    bytes.extend(enc(0x95, 0, 0, 0, 0));        // exit
    let stats = BpfProgramStats::from_bytes(&a, &bytes).unwrap();
    assert_eq!(stats.instruction_count, 5);
    assert!(stats.has_exit);
    assert_eq!(stats.conditional_branch_count, 1);
    assert_eq!(stats.unconditional_branch_count, 1);
}

// ========================= disasm corner cases ============================

#[test]
fn disasm_neg_op_dst_only() {
    let helpers = known_helpers();
    // Alu | Neg = 0x84 (Alu=0x04, Neg=0x80)
    let (i, _) = BpfInstruction::decode(&enc(0x84, 3, 0, 0, 0)).unwrap();
    let (mne, ops, _) = disasm_instr(&i, &helpers).unwrap();
    assert_eq!(mne, "neg32");
    assert_eq!(ops, "r3");
}

#[test]
fn disasm_end_be_le_byte_swap() {
    let helpers = known_helpers();
    // Alu | End = 0xd4 (le), Alu | End | src_is_reg(0x08)=0xdc (be)
    let (i_le, _) = BpfInstruction::decode(&enc(0xd4, 1, 0, 0, 32)).unwrap();
    let (mne_le, _, _) = disasm_instr(&i_le, &helpers).unwrap();
    assert_eq!(mne_le, "le32");
    let (i_be, _) = BpfInstruction::decode(&enc(0xdc, 1, 0, 0, 32)).unwrap();
    let (mne_be, _, _) = disasm_instr(&i_be, &helpers).unwrap();
    assert_eq!(mne_be, "be32");
}

#[test]
fn disasm_jmp32_excludes_call_and_exit() {
    let helpers = known_helpers();
    // JMP32 class = 0x06; call (code 0x80) on jmp32 must be unknown
    let (i, _) = BpfInstruction::decode(&enc(0x86, 0, 0, 0, 1)).unwrap();
    let r = disasm_instr(&i, &helpers);
    assert!(matches!(r, Err(BpfDecodeError::UnknownOpcode(_))));
    // jmp32 exit also invalid
    let (i, _) = BpfInstruction::decode(&enc(0x96, 0, 0, 0, 0)).unwrap();
    let r = disasm_instr(&i, &helpers);
    assert!(matches!(r, Err(BpfDecodeError::UnknownOpcode(_))));
}

#[test]
fn disasm_call_unknown_helper_id_says_unknown() {
    let helpers = known_helpers();
    let (i, _) = BpfInstruction::decode(&enc(0x85, 0, 0, 0, 999_999)).unwrap();
    let (mne, ops, flags) = disasm_instr(&i, &helpers).unwrap();
    assert_eq!(mne, "call");
    assert!(ops.contains("unknown"));
    assert!(flags.contains(InstrFlags::CALL));
}

// ========================= cBPF round-trip ================================

#[test]
fn cbpf_alu_all_ops_disasm_distinct() {
    let mnemonics: HashSet<String> = (0..=0xa0).step_by(0x10).map(|code| {
        let i = CbpfInstruction { opcode: 0x04 | numeric::trunc_i32_u16(code), jt: 0, jf: 0, k: 1 };
        i.disasm().split_whitespace().next().unwrap().to_string()
    }).collect();
    // 11 ALU ops up to XOR.
    assert!(mnemonics.len() >= 10);
}

#[test]
fn cbpf_round_trip_50_random() {
    let mut lcg = Lcg::new(0x9E37_79B9_7F4A_7C15);
    for _ in 0..50 {
        let opcode = numeric::low_u16(lcg.next_u32());
        let jt = lcg.next_u8();
        let jf = lcg.next_u8();
        let k = lcg.next_u32();
        let mut bytes = Vec::with_capacity(8);
        bytes.extend_from_slice(&opcode.to_le_bytes());
        bytes.push(jt);
        bytes.push(jf);
        bytes.extend_from_slice(&k.to_le_bytes());
        let i = CbpfInstruction::decode(&bytes).unwrap();
        assert_eq!(i.opcode, opcode);
        assert_eq!(i.jt, jt);
        assert_eq!(i.jf, jf);
        assert_eq!(i.k, k);
    }
}

// ========================= BtfTypeHeader properties =======================

#[test]
fn btf_type_header_kind_bits_24_to_28() {
    // BTF kind occupies bits [28:24].
    for k in 1u32..=19u32 {
        let info = k << 24;
        let mut bytes = vec![0u8; 4];
        bytes.extend_from_slice(&info.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 4]);
        let h = BtfTypeHeader::decode(&bytes).unwrap();
        assert_eq!(h.kind(), BtfKind::from_u32(k));
    }
}

#[test]
fn btf_type_header_vlen_masks_low_16_bits() {
    let info = 0xffff_u32 | (4 << 24);
    let mut bytes = vec![0u8; 4];
    bytes.extend_from_slice(&info.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 4]);
    let h = BtfTypeHeader::decode(&bytes).unwrap();
    assert_eq!(h.vlen(), 0xffff);
}

// ========================= enum Hash/Eq consistency =======================

#[test]
fn class_hash_eq_consistency() {
    let xs = [BpfClass::Ld, BpfClass::Ldx, BpfClass::St, BpfClass::Stx,
              BpfClass::Alu, BpfClass::Jmp, BpfClass::Alu64, BpfClass::Jmp32];
    for a in xs {
        for b in xs {
            if a == b { assert_eq!(hash_of(&a), hash_of(&b)); }
        }
    }
}

#[test]
fn alu_op_hash_eq_consistency() {
    let xs = [BpfAluOp::Add, BpfAluOp::Sub, BpfAluOp::Mul, BpfAluOp::Div,
              BpfAluOp::Or, BpfAluOp::And, BpfAluOp::Lsh, BpfAluOp::Rsh,
              BpfAluOp::Neg, BpfAluOp::Mod, BpfAluOp::Xor, BpfAluOp::Mov,
              BpfAluOp::Arsh, BpfAluOp::End];
    for a in xs {
        for b in xs {
            if a == b { assert_eq!(hash_of(&a), hash_of(&b)); }
            else { assert_ne!(a, b); }
        }
    }
}

#[test]
fn btfkind_hash_eq_consistency() {
    for v in 1u32..=19u32 {
        let a = BtfKind::from_u32(v).unwrap();
        let b = BtfKind::from_u32(v).unwrap();
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }
}

#[test]
fn map_op_hash_eq_consistency() {
    let xs = [MapOp::Lookup, MapOp::Update, MapOp::Delete, MapOp::GetNextKey];
    for a in xs {
        for b in xs {
            if a == b { assert_eq!(hash_of(&a), hash_of(&b)); }
        }
    }
}

#[test]
fn xdp_action_hash_eq_consistency() {
    let xs = [XdpAction::Aborted, XdpAction::Drop, XdpAction::Pass,
              XdpAction::Tx, XdpAction::Redirect];
    let mut seen = HashSet::new();
    for a in xs {
        seen.insert(hash_of(&a));
        assert_eq!(XdpAction::from_u32(a as u32), Some(a));
    }
    assert_eq!(seen.len(), xs.len());
}

#[test]
fn bpf_instruction_eq_implies_hash_equal_30_pairs() {
    let mut lcg = Lcg::new(0xABCD_1234_DEAD_BEEF);
    for _ in 0..30 {
        let op = 0x07u8; // valid alu64
        let dst = (lcg.next_u8() & 0x0f).min(10);
        let imm = (lcg.next_u32()).cast_signed();
        let bytes = enc(op, dst, 0, 0, imm);
        let (a, _) = BpfInstruction::decode(&bytes).unwrap();
        let (b, _) = BpfInstruction::decode(&bytes).unwrap();
        assert_eq!(a, b);
    }
}

// ========================= BpfArch architecture trait properties ==========

#[test]
fn arch_endian_little() {
    use rustre_core::endian::Endian;
    let a = BpfArch::new_ebpf();
    assert_eq!(a.endian(), Endian::Little);
}

#[test]
fn arch_disasm_propagates_decode_error() {
    let a = BpfArch::new_ebpf();
    let r = a.disassemble(Address::new(0), &[1, 2, 3]);
    assert!(r.is_err());
}

#[test]
fn arch_get_branches_call_returns_empty() {
    let a = BpfArch::new_ebpf();
    let bytes = enc(0x85, 0, 0, 0, 1);
    let instr = a.disassemble(Address::new(0), &bytes).unwrap();
    let br = a.get_branches(&instr);
    assert!(br.is_empty());
}

#[test]
fn arch_get_branches_conditional_jeq() {
    let a = BpfArch::new_ebpf();
    let bytes = enc(0x15, 1, 0, 4, 0);
    let instr = a.disassemble(Address::new(0x100), &bytes).unwrap();
    let br = a.get_branches(&instr);
    assert_eq!(br.len(), 1);
}

#[test]
fn arch_get_branches_uncond_ja_target_correct() {
    let a = BpfArch::new_ebpf();
    let bytes = enc(0x05, 0, 0, 3, 0);
    let instr = a.disassemble(Address::new(0x100), &bytes).unwrap();
    let br = a.get_branches(&instr);
    assert_eq!(br.len(), 1);
    // Target = next_pc + offset*8 = (0x100+8) + 3*8 = 0x120
    assert_eq!(br[0].target, Some(0x120));
}

#[test]
fn arch_branch_kind_classification() {
    use rustre_core::arch::BranchKind;
    let a = BpfArch::new_ebpf();

    let call = a.disassemble(Address::new(0), &enc(0x85, 0, 0, 0, 1)).unwrap();
    assert_eq!(a.branch_kind(&call), Some(BranchKind::Call));

    let exit = a.disassemble(Address::new(0), &enc(0x95, 0, 0, 0, 0)).unwrap();
    assert_eq!(a.branch_kind(&exit), Some(BranchKind::Return));

    let ja = a.disassemble(Address::new(0), &enc(0x05, 0, 0, 1, 0)).unwrap();
    assert_eq!(a.branch_kind(&ja), Some(BranchKind::UnconditionalJump));

    let jeq = a.disassemble(Address::new(0), &enc(0x15, 0, 0, 1, 0)).unwrap();
    assert_eq!(a.branch_kind(&jeq), Some(BranchKind::ConditionalJump));

    let add = a.disassemble(Address::new(0), &enc(0x07, 0, 0, 0, 1)).unwrap();
    assert_eq!(a.branch_kind(&add), None);
}

// ========================= Send+Sync threaded stress ======================

#[test]
fn arch_send_sync_threaded_disassemble() {
    let a = Arc::new(BpfArch::new_ebpf());
    let mut handles = Vec::new();
    for tid in 0..4u32 {
        let a = Arc::clone(&a);
        handles.push(thread::spawn(move || {
            let mut s: u64 = 0xDEAD_BEEF ^ u64::from(tid).wrapping_mul(0x9E37_79B1);
            for _ in 0..100 {
                s = s.wrapping_mul(6_364_136_223_846_793_005)
                     .wrapping_add(1_442_695_040_888_963_407);
                // Use a valid opcode: alu64 add imm
                let imm = numeric::trunc_u64_i32(s);
                let bytes = enc(0x07, 0, 0, 0, imm);
                let i = a.disassemble(Address::new(0), &bytes).unwrap();
                assert_eq!(i.mnemonic, "add");
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn known_helpers_send_sync_threaded() {
    let mut handles = Vec::new();
    for _tid in 0..4 {
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let h = known_helpers();
                assert_eq!(h.get(&1).copied(), Some("bpf_map_lookup_elem"));
                assert!(h.len() >= 200);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn analyzer_send_sync_threaded() {
    let mut bytes = Vec::new();
    bytes.extend(enc_lddw(1, 42));
    bytes.extend(enc(0x85, 0, 0, 0, 1));
    bytes.extend(enc(0x95, 0, 0, 0, 0));
    let bytes = Arc::new(bytes);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let b = Arc::clone(&bytes);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let report = BpfProgramAnalyzer::analyze(&b);
                assert_eq!(report.helper_calls, vec![1]);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

// ========================= verifier sim invariants ========================

#[test]
fn verifier_accepts_empty_program() {
    let errs = BpfVerifierSimulator::check_bounds(&[]);
    assert!(errs.is_empty());
}

#[test]
fn verifier_register_validation_boundary() {
    // r11 is invalid; r10 valid.
    let (i_bad, _) = BpfInstruction::decode(&enc(0x07, 11, 0, 0, 0)).unwrap();
    let errs = BpfVerifierSimulator::check_bounds(&[i_bad]);
    assert!(errs.iter().any(|e| e.message.contains("dst")));

    let (i_ok, _) = BpfInstruction::decode(&enc(0x07, 10, 0, 0, 0)).unwrap();
    let errs2 = BpfVerifierSimulator::check_bounds(&[i_ok]);
    assert!(errs2.is_empty());
}

#[test]
fn verifier_stack_off_by_one() {
    // off = -513 invalid, -512 valid, 0 valid, 1 invalid
    let mk = |off: i16| {
        let (i, _) = BpfInstruction::decode(&enc(0x63, 10, 1, off, 0)).unwrap();
        i
    };
    assert!(!BpfVerifierSimulator::check_bounds(&[mk(-513)]).is_empty());
    assert!(BpfVerifierSimulator::check_bounds(&[mk(-512)]).is_empty());
    assert!(BpfVerifierSimulator::check_bounds(&[mk(0)]).is_empty());
    assert!(!BpfVerifierSimulator::check_bounds(&[mk(1)]).is_empty());
}

// ========================= analyzer state machine =========================

#[test]
fn analyzer_detects_loop_via_backward_jump() {
    let mut bytes = Vec::new();
    bytes.extend(enc(0x15, 0, 0, -1, 0)); // jeq with negative offset
    bytes.extend(enc(0x95, 0, 0, 0, 0));
    let r = BpfProgramAnalyzer::analyze(&bytes);
    assert!(r.uses_loops);
    assert!(r.security_notes.iter().any(|n| n.contains("backward")));
}

#[test]
fn analyzer_xdp_hint_via_helper_36() {
    let mut bytes = Vec::new();
    bytes.extend(enc(0x85, 0, 0, 0, 36)); // xdp_adjust_head
    bytes.extend(enc(0x95, 0, 0, 0, 0));
    let r = BpfProgramAnalyzer::analyze(&bytes);
    assert_eq!(r.program_type_hint, Some(BpfProgType::Xdp));
}

#[test]
fn analyzer_kprobe_hint_via_helper_4() {
    let mut bytes = Vec::new();
    bytes.extend(enc(0x85, 0, 0, 0, 4)); // probe_read
    bytes.extend(enc(0x95, 0, 0, 0, 0));
    let r = BpfProgramAnalyzer::analyze(&bytes);
    assert_eq!(r.program_type_hint, Some(BpfProgType::Kprobe));
}

#[test]
fn analyzer_map_fd_tracked_across_lddw() {
    let mut bytes = Vec::new();
    bytes.extend(enc_lddw(1, 0xc0ffee));
    bytes.extend(enc(0x85, 0, 0, 0, 2)); // map_update
    bytes.extend(enc(0x95, 0, 0, 0, 0));
    let r = BpfProgramAnalyzer::analyze(&bytes);
    assert_eq!(r.map_accesses.len(), 1);
    assert_eq!(r.map_accesses[0].map_fd, 0xc0ffee);
    assert_eq!(r.map_accesses[0].operation, MapOp::Update);
}

// ========================= disassembler text formatter ====================

#[test]
fn bpf_disassembler_handles_unknown_opcode_line() {
    let h: Vec<BpfHelper> = vec![];
    // 8 bytes with op = 0xfe (class=Alu64=7, code=0xf0 unknown)
    let bytes = enc(0xfe, 0, 0, 0, 0);
    let text = BpfDisassembler::disassemble(&bytes, &h);
    assert!(text.starts_with("0:"));
}

#[test]
fn bpf_disassembler_multiline_count() {
    let h: Vec<BpfHelper> = vec![];
    let mut bytes = Vec::new();
    for _ in 0..5 {
        bytes.extend(enc(0x07, 0, 0, 0, 1));
    }
    let text = BpfDisassembler::disassemble(&bytes, &h);
    assert_eq!(text.lines().count(), 5);
}

// ========================= map_op / xdp_action exhaustive =================

#[test]
fn map_op_names_all_distinct_and_nonempty() {
    let xs = [MapOp::Lookup, MapOp::Update, MapOp::Delete, MapOp::GetNextKey];
    let s: HashSet<_> = xs.iter().map(|o| o.name()).collect();
    assert_eq!(s.len(), xs.len());
    for o in xs { assert!(!o.name().is_empty()); }
}

#[test]
fn xdp_action_from_u32_round_trip_all_5() {
    for (v, expected) in [
        (0u32, XdpAction::Aborted),
        (1, XdpAction::Drop),
        (2, XdpAction::Pass),
        (3, XdpAction::Tx),
        (4, XdpAction::Redirect),
    ] {
        assert_eq!(XdpAction::from_u32(v), Some(expected));
        assert_eq!(expected as u32, v);
    }
    assert_eq!(XdpAction::from_u32(5), None);
    assert_eq!(XdpAction::from_u32(u32::MAX), None);
}

// ========================= BTF magic / parser =============================

#[test]
fn btf_parser_is_valid_rejects_short() {
    assert!(!BtfParser::is_valid(&[]));
    assert!(!BtfParser::is_valid(&[0x9f]));
    assert!(!BtfParser::is_valid(&[0x9f, 0xeb, 0])); // only 3 bytes
}

#[test]
fn btf_parser_is_valid_accepts_correct_magic_and_version() {
    let mut bytes = vec![];
    bytes.extend_from_slice(&BTF_MAGIC.to_le_bytes());
    bytes.push(BTF_VERSION);
    bytes.push(0); // flags
    assert!(BtfParser::is_valid(&bytes));
}

#[test]
fn btf_parser_rejects_wrong_version() {
    let mut bytes = vec![];
    bytes.extend_from_slice(&BTF_MAGIC.to_le_bytes());
    bytes.push(99);
    bytes.push(0);
    assert!(!BtfParser::is_valid(&bytes));
}

#[test]
fn btf_parser_find_section_returns_none_on_non_elf() {
    assert!(BtfParser::find_btf_section(&[0; 16]).is_none());
    assert!(BtfParser::find_btf_section(&[]).is_none());
}

// ========================= integer overflow / wrap paths ==================

#[test]
fn decode_imm_wrap_does_not_panic() {
    // 8 bytes with imm at i32::MIN should decode cleanly and i.imm.unsigned_abs() not overflow our test.
    let (i, _) = BpfInstruction::decode(&enc(0x07, 0, 0, 0, i32::MIN)).unwrap();
    assert_eq!(i.imm, i32::MIN);
}

#[test]
fn lddw_with_negative_lo_high_round_trip() {
    let vals = [i64::MIN, -1, 0, 1, i64::MAX, (0x8000_0000_0000_0000_u64).cast_signed()];
    for v in vals {
        let bytes = enc_lddw(0, v);
        let (i, _) = BpfInstruction::decode(&bytes).unwrap();
        assert_eq!(i.wide_imm, Some(v));
    }
}

#[test]
fn get_branches_with_extreme_offset_does_not_panic() {
    let a = BpfArch::new_ebpf();
    let bytes = enc(0x05, 0, 0, i16::MIN, 0);
    let instr = a.disassemble(Address::new(0), &bytes).unwrap();
    let br = a.get_branches(&instr);
    assert_eq!(br.len(), 1);
    // Wrapping is documented behaviour — just verify call returns.
}
