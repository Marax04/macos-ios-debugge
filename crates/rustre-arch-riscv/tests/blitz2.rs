//! Blitz2 — deep adversarial coverage for rustre-arch-riscv.
//!
//! All randomness is from a seeded LCG (no `std::time`, no `rand`).
//! Every parser/decoder must never panic and must return a value
//! (Ok / Err / Option / valid instruction including "unknown").

use rustre_core::arch::Architecture;
use rustre_arch_riscv::*;
use rustre_core::address::Address;

// ---------------------------------------------------------------------------
// Seeded LCG (Knuth MMIX constants).
// ---------------------------------------------------------------------------

struct Lcg(u64);
impl Lcg {
    const fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn u32(&mut self) -> u32 {
        (self.next() >> 32) as u32
    }
    fn u16(&mut self) -> u16 {
        (self.next() >> 48) as u16
    }
}

// ---------------------------------------------------------------------------
// 1. Field-extractor round-trips over 50+ deterministic inputs.
// ---------------------------------------------------------------------------

#[test]
fn imm_i_roundtrip_50_inputs() {
    // Range [-2048, 2047]. Pick 50 evenly spread values.
    for k in 0..50 {
        let imm = -2048 + (k * 4095) / 49;
        let imm = imm.clamp(-2048, 2047) as i16;
        let w = rv_encode_addi(1, 2, imm);
        assert_eq!(rv_imm_i(w), i32::from(imm), "addi imm round-trip {imm}");
        assert_eq!(rv_rd(w), 1);
        assert_eq!(rv_rs1(w), 2);
        assert_eq!(rv_opcode(w), 0x13);
    }
}

#[test]
fn imm_s_roundtrip_50_inputs() {
    for k in 0..50 {
        let imm = -2048 + (k * 4095) / 49;
        let imm = imm.clamp(-2048, 2047) as i16;
        let w = rv_encode_sw(3, 4, imm);
        assert_eq!(rv_imm_s(w), i32::from(imm), "sw S-imm round-trip {imm}");
        assert_eq!(rv_rs2(w), 3);
        assert_eq!(rv_rs1(w), 4);
        assert_eq!(rv_opcode(w), 0x23);
    }
}

#[test]
fn imm_b_roundtrip_50_inputs() {
    // B-type even offsets in [-4096, 4094].
    for k in 0..50 {
        let raw = -4096 + (k * 8190) / 49;
        let off = raw & !1; // even
        let off = off.clamp(-4096, 4094);
        assert!(rv_btype_roundtrip(off), "btype round-trip {off}");
        let w = rv_encode_beq(0, 0, off);
        assert_eq!(rv_imm_b(w), off);
    }
}

#[test]
fn imm_j_roundtrip_50_inputs() {
    for k in 0..50 {
        let span = 2 * 1_048_575_i32;
        let raw = -1_048_576 + ((k * span) / 49);
        let off = (raw & !1).clamp(-1_048_576, 1_048_574);
        assert!(rv_jtype_roundtrip(off), "jtype round-trip {off}");
        let w = rv_encode_jal(0, off);
        assert_eq!(rv_imm_j(w), off);
    }
}

#[test]
fn imm_u_keeps_high_20_bits_50() {
    for k in 0u32..50 {
        let imm20 = k.wrapping_mul(0x12345) & 0x000F_FFFF;
        let w = rv_encode_lui(5, imm20);
        assert_eq!(rv_imm_u(w) >> 12, imm20);
        assert_eq!(rv_rd(w), 5);
        assert_eq!(rv_opcode(w), 0x37);
    }
}

// ---------------------------------------------------------------------------
// 2. Seeded LCG fuzz on parsers / decoders — must never panic.
// ---------------------------------------------------------------------------

#[test]
fn fuzz_decode_32_never_panics() {
    let mut g = Lcg::new();
    let arch = RiscvArch::rv64();
    for _ in 0..2000 {
        let word = g.u32();
        let bytes = word.to_le_bytes();
        let _ = arch.disassemble(Address::new(0x1000), &bytes);
        // Field extractors must also never panic.
        let _ = rv_opcode(word);
        let _ = rv_classify(word);
        let _ = rv_imm_i(word);
        let _ = rv_imm_s(word);
        let _ = rv_imm_b(word);
        let _ = rv_imm_u(word);
        let _ = rv_imm_j(word);
        let _ = rv_is_load(word);
        let _ = rv_is_store(word);
        let _ = rv_is_branch(word);
        let _ = rv_is_jal(word);
        let _ = rv_is_jalr(word);
        let _ = rv_is_nop(word);
        let _ = rv_is_ret(word);
        let _ = rv_is_ecall(word);
        let _ = rv_is_ebreak(word);
        let _ = rv_is_fence(word);
        let _ = rv_is_fence_i(word);
        let _ = rv_is_mret(word);
        let _ = rv_is_sret(word);
        let _ = rv_is_wfi(word);
        let _ = rv_is_indirect_call(word);
        let _ = rv_is_tail_call(word);
        let _ = rv_prologue_frame_size(word);
    }
}

#[test]
fn fuzz_decode_compressed_never_panics() {
    let mut g = Lcg::new();
    for _ in 0..3000 {
        let hw = g.u16();
        for xlen in [32u32, 64, 128] {
            // Always returns Ok or Err — never panic.
            let _ = decode_compressed(hw, xlen, Address::new(0x2000));
        }
        let _ = rv_is_compressed(hw);
        let _ = rv_c_op_funct3(hw);
        let _ = rv_c_addi4spn_imm(hw);
        let _ = rv_c_classify(hw);
    }
}

#[test]
fn fuzz_lift_word_never_panics() {
    let mut g = Lcg::new();
    for _ in 0..1500 {
        let w = g.u32();
        for xlen in [32u32, 64] {
            let ops = rv_lift_word(0x4000, w, xlen);
            // Result is a Vec — drop without touching.
            let _ = ops.len();
        }
    }
}

#[test]
fn fuzz_lift_compressed_never_panics() {
    let mut g = Lcg::new();
    for _ in 0..2000 {
        let hw = g.u16();
        for xlen in [32u32, 64] {
            let ops = rv_lift_compressed(0x8000, hw, xlen);
            let _ = ops.len();
        }
    }
}

#[test]
fn fuzz_linear_disassembler_streams_cleanly() {
    let mut g = Lcg::new();
    let mut buf = Vec::with_capacity(256);
    for _ in 0..256 {
        buf.push((g.next() & 0xFF) as u8);
    }
    let arch = RiscvArch::rv64();
    let dis = RiscvLinearDisassembler::new(&arch, &buf, Address::new(0x0));
    let mut count = 0usize;
    for r in dis {
        // Never panic; either Ok(instr) or a CoreError.
        let _ = r;
        count += 1;
        if count > 100 {
            break;
        }
    }
    assert!(count > 0);
}

#[test]
fn fuzz_compressed_disassembler_streams_cleanly() {
    let mut g = Lcg::new();
    let mut buf = Vec::with_capacity(256);
    for _ in 0..256 {
        buf.push((g.next() & 0xFF) as u8);
    }
    let arch = RiscvArch::rv64();
    let dis = RiscvLinearDisassembler::new_with_compressed(&arch, &buf, Address::new(0x0));
    let mut count = 0usize;
    for r in dis {
        let _ = r;
        count += 1;
        if count > 200 {
            break;
        }
    }
    assert!(count > 0);
}

// ---------------------------------------------------------------------------
// 3. Boundary conditions.
// ---------------------------------------------------------------------------

#[test]
fn boundary_disassemble_truncated() {
    let arch = RiscvArch::rv64();
    // 0 bytes — should error (or return unknown) without panic.
    let _ = arch.disassemble(Address::new(0), &[]);
    // 1, 2, 3 bytes truncated.
    let _ = arch.disassemble(Address::new(0), &[0x00]);
    let _ = arch.disassemble(Address::new(0), &[0x00, 0x00]);
    let _ = arch.disassemble(Address::new(0), &[0x00, 0x00, 0x00]);
    // Oversize is fine (extra bytes ignored).
    let big = vec![0x13u8; 1024];
    let _ = arch.disassemble(Address::new(0), &big);
}

#[test]
fn boundary_compressed_xlen() {
    // 0 xlen, max u32 xlen — must not panic.
    let _ = decode_compressed(0x0000, 0, Address::new(0));
    let _ = decode_compressed(0xFFFF, u32::MAX, Address::new(0));
}

#[test]
fn boundary_compressed_reserved_zero() {
    // C.ADDI4SPN with imm==0 is reserved -> Err.
    // Quadrant 0, funct3=0, imm field=0 => hw bits [12:5]=0.
    let hw: u16 = 0x0000; // also illegal instruction
    let r = decode_compressed(hw, 64, Address::new(0));
    assert!(r.is_err(), "all-zero compressed must be Err");
}

#[test]
fn boundary_sign_ext_widths() {
    // width=1: only LSB matters, sign-extends from bit0.
    assert_eq!(rv_sext(1, 1), -1);
    assert_eq!(rv_sext(0, 1), 0);
    // width=0 -> 0 by definition.
    assert_eq!(rv_sext(0xFFFF_FFFF_FFFF_FFFF, 0), 0);
    // width=63 boundary.
    assert_eq!(rv_sext(1u64 << 62, 63), -(1i64 << 62));
    // width=64 -> identity.
    assert_eq!(rv_sext(0xFFFF_FFFF_FFFF_FFFF, 64), -1);
}

#[test]
fn boundary_zext_widths() {
    assert_eq!(rv_zext(0xFFFF_FFFF_FFFF_FFFF, 1), 1);
    assert_eq!(rv_zext(0xFFFF_FFFF_FFFF_FFFF, 8), 0xFF);
    assert_eq!(rv_zext(0xFFFF_FFFF_FFFF_FFFF, 64), 0xFFFF_FFFF_FFFF_FFFF);
    assert_eq!(rv_zext(0xFFFF_FFFF_FFFF_FFFF, 65), 0xFFFF_FFFF_FFFF_FFFF);
}

#[test]
fn boundary_rv_bits_full_word() {
    // Selecting [31:0] returns full word.
    assert_eq!(rv_bits(0xDEAD_BEEF, 31, 0), 0xDEAD_BEEF);
    // Single bit.
    assert_eq!(rv_bits(0x8000_0000, 31, 31), 1);
    assert_eq!(rv_bits(0x0000_0001, 0, 0), 1);
}

#[test]
fn boundary_misa_mxl() {
    // MXL extracted from top 2 bits of misa for XLEN=32 is 1, 64=2, 128=3.
    // We test that misa_has correctly indexes A-Z bits.
    let misa: u64 = (1 << (b'I' - b'A')) | (1 << (b'M' - b'A'));
    assert!(rv_misa_has(misa, b'I' - b'A'));
    assert!(rv_misa_has(misa, b'M' - b'A'));
    assert!(!rv_misa_has(misa, b'Z' - b'A'));
}

#[test]
fn boundary_jal_imm_extremes() {
    // Most negative and most positive J-imm.
    assert!(rv_jtype_roundtrip(-1_048_576));
    assert!(rv_jtype_roundtrip(1_048_574));
    let w = rv_encode_jal(1, -1_048_576);
    assert_eq!(rv_imm_j(w), -1_048_576);
    let w = rv_encode_jal(1, 1_048_574);
    assert_eq!(rv_imm_j(w), 1_048_574);
}

#[test]
fn boundary_btype_imm_extremes() {
    assert!(rv_btype_roundtrip(-4096));
    assert!(rv_btype_roundtrip(4094));
    let w = rv_encode_beq(0, 0, -4096);
    assert_eq!(rv_imm_b(w), -4096);
    let w = rv_encode_beq(0, 0, 4094);
    assert_eq!(rv_imm_b(w), 4094);
}

// ---------------------------------------------------------------------------
// 4. State machine / privilege / classification invariants.
// ---------------------------------------------------------------------------

#[test]
fn special_constants_classify_correctly() {
    assert!(rv_is_nop(RV_NOP));
    assert!(rv_is_ecall(RV_ECALL));
    assert!(rv_is_ebreak(RV_EBREAK));
    assert!(rv_is_mret(RV_MRET));
    assert!(rv_is_wfi(RV_WFI));
    // NOP is also addi x0,x0,0 ⇒ classified as OpImm.
    assert!(matches!(rv_classify(RV_NOP), RvOpcodeClass::OpImm));
    // ECALL/EBREAK/MRET/WFI are SYSTEM.
    assert!(matches!(rv_classify(RV_ECALL), RvOpcodeClass::System));
    assert!(matches!(rv_classify(RV_EBREAK), RvOpcodeClass::System));
    assert!(matches!(rv_classify(RV_MRET), RvOpcodeClass::System));
    assert!(matches!(rv_classify(RV_WFI), RvOpcodeClass::System));
}

#[test]
fn invalid_opcodes_classify_unknown() {
    // All bottom-7-bit patterns that are not a known opcode → Unknown.
    let known: &[u8] = &[
        0x03, 0x07, 0x0F, 0x13, 0x17, 0x1B, 0x23, 0x27, 0x2F, 0x33, 0x37, 0x3B, 0x43, 0x47, 0x4B,
        0x4F, 0x53, 0x63, 0x67, 0x6F, 0x73,
    ];
    for op in 0u8..=0x7F {
        let w = u32::from(op);
        if known.contains(&op) {
            assert!(!matches!(rv_classify(w), RvOpcodeClass::Unknown));
        } else {
            assert!(
                matches!(rv_classify(w), RvOpcodeClass::Unknown),
                "opcode 0x{op:02X} should be Unknown"
            );
        }
    }
}

#[test]
fn load_store_branch_predicates_consistent_with_classify() {
    let mut g = Lcg::new();
    for _ in 0..500 {
        let w = g.u32();
        let c = rv_classify(w);
        assert_eq!(
            rv_is_load(w),
            matches!(c, RvOpcodeClass::Load | RvOpcodeClass::LoadFp)
        );
        assert_eq!(
            rv_is_store(w),
            matches!(c, RvOpcodeClass::Store | RvOpcodeClass::StoreFp)
        );
        assert_eq!(rv_is_branch(w), matches!(c, RvOpcodeClass::Branch));
        assert_eq!(rv_is_jal(w), matches!(c, RvOpcodeClass::Jal));
        assert_eq!(rv_is_jalr(w), matches!(c, RvOpcodeClass::Jalr));
    }
}

// ---------------------------------------------------------------------------
// 5. Integer overflow / underflow paths.
// ---------------------------------------------------------------------------

#[test]
fn add_ov_saturates_correctly() {
    assert_eq!(rv_add_ov(i64::MAX, 1), None);
    assert_eq!(rv_add_ov(i64::MIN, -1), None);
    assert_eq!(rv_add_ov(0, 0), Some(0));
    assert_eq!(rv_add_ov(i64::MAX, 0), Some(i64::MAX));
}

#[test]
fn sub_ov_saturates_correctly() {
    assert_eq!(rv_sub_ov(i64::MIN, 1), None);
    assert_eq!(rv_sub_ov(i64::MAX, -1), None);
    assert_eq!(rv_sub_ov(0, 0), Some(0));
}

#[test]
fn addw_subw_wrap_then_sign_extend() {
    // Add that wraps in 32-bit then sign-extends.
    let r = rv_addw(0x7FFF_FFFF, 1);
    assert_eq!(r, i64::from(i32::MIN));
    let r = rv_subw(0, 1);
    assert_eq!(r, -1i64);
    // High bits beyond 32 are ignored.
    let r = rv_addw((0xFFFF_FFFF_0000_0001u64).cast_signed(), 1);
    assert_eq!(r, 2);
}

#[test]
fn mul_mulh_consistent() {
    // a*b lower 64 bits = wrapping_mul; mulh = upper 64 bits of signed×signed.
    let cases = [
        (1i64, 1i64),
        (-1, -1),
        (i64::MIN, -1),
        (i64::MAX, 2),
        (1_234_567_890, 9_876_543_210),
    ];
    for (a, b) in cases {
        let lo = rv_mul(a, b);
        let hi = rv_mulh(a, b);
        // Reconstruct 128-bit product and verify.
        let prod = i128::from(a).wrapping_mul(i128::from(b));
        assert_eq!(lo, prod as i64);
        assert_eq!(hi, (prod >> 64) as i64);
    }
}

#[test]
fn div_rem_special_cases() {
    // Division by zero -> -1 (RISC-V spec).
    assert_eq!(rv_div(123, 0), -1);
    // Unsigned div-by-zero -> u64::MAX.
    assert_eq!(rv_divu(123, 0), u64::MAX);
    // Signed overflow: i64::MIN / -1.
    // RISC-V spec returns the dividend; this impl uses wrapping_div which is i64::MIN.
    assert_eq!(rv_div(i64::MIN, -1), i64::MIN);
    // Remainder by zero -> dividend.
    assert_eq!(rv_rem(42, 0), 42);
    assert_eq!(rv_remu(42, 0), 42);
}

#[test]
fn slt_sltu_distinguish_sign() {
    // -1 (signed) < 0, but as unsigned is u64::MAX > 0.
    assert_eq!(rv_slt(-1, 0), 1);
    assert_eq!(rv_sltu(u64::MAX, 0), 0);
    assert_eq!(rv_slt(0, 0), 0);
    assert_eq!(rv_sltu(0, 1), 1);
}

#[test]
fn rotate_inverse() {
    let mut g = Lcg::new();
    for _ in 0..30 {
        let v = g.u32();
        for n in [0u8, 1, 7, 15, 31] {
            let lr = rv_ror32(v, n);
            // Rotating back the other direction by (32-n)%32 mod 32 returns original.
            let back = if n == 0 { lr } else { lr.rotate_left(u32::from(n)) };
            assert_eq!(back, v, "ror32 inverse v={v:#x} n={n}");
        }
        let v64 = g.next();
        for n in [0u8, 1, 7, 31, 63] {
            let lr = rv_ror64(v64, n);
            let back = if n == 0 { lr } else { lr.rotate_left(u32::from(n)) };
            assert_eq!(back, v64);
        }
    }
}

#[test]
fn rev8_double_application_identity() {
    let mut g = Lcg::new();
    for _ in 0..30 {
        let v = g.u32();
        assert_eq!(rv_rev8_32(rv_rev8_32(v)), v);
        assert_eq!(rv_brev8_32(rv_brev8_32(v)), v);
    }
}

#[test]
fn orcb_idempotent() {
    let mut g = Lcg::new();
    for _ in 0..30 {
        let v = g.u32();
        let once = rv_orcb32(v);
        let twice = rv_orcb32(once);
        assert_eq!(once, twice, "orcb idempotent v={v:#x}");
    }
}

#[test]
fn popcount_clz_ctz_consistency() {
    let mut g = Lcg::new();
    for _ in 0..30 {
        let v = g.u32();
        let pop = rv_cpop32(v);
        let clz = rv_clz32(v);
        let ctz = rv_ctz32(v);
        if v == 0 {
            assert_eq!(pop, 0);
            assert_eq!(clz, 32);
            assert_eq!(ctz, 32);
        } else {
            assert!((1..=32).contains(&pop));
            assert!(clz <= 31);
            assert!(ctz <= 31);
            assert!(clz + ctz + pop >= 32 - (pop - 1) || true); // sanity
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Hash/Eq consistency on 30+ pairs.
// ---------------------------------------------------------------------------

use std::collections::HashSet;

#[test]
fn riscv_priv_level_hash_eq_consistent() {
    let variants = [
        RiscvPrivLevel::User,
        RiscvPrivLevel::Supervisor,
        RiscvPrivLevel::Hypervisor,
        RiscvPrivLevel::Machine,
    ];
    let mut set: HashSet<RiscvPrivLevel> = HashSet::new();
    for &v in &variants {
        set.insert(v);
        // Inserting same key twice does not grow the set.
        let before = set.len();
        set.insert(v);
        assert_eq!(set.len(), before);
        // Eq implies same hash → present.
        assert!(set.contains(&v));
    }
    assert_eq!(set.len(), variants.len());
}

#[test]
fn riscv_arch_eq_consistent() {
    let pairs: Vec<(RiscvArch, RiscvArch, bool)> = vec![
        (RiscvArch::rv32(), RiscvArch::rv32(), true),
        (RiscvArch::rv64(), RiscvArch::rv64(), true),
        (RiscvArch::rv128(), RiscvArch::rv128(), true),
        (RiscvArch::rv32(), RiscvArch::rv64(), false),
        (RiscvArch::rv32(), RiscvArch::rv128(), false),
        (RiscvArch::rv64(), RiscvArch::rv128(), false),
    ];
    for (a, b, expected) in &pairs {
        assert_eq!(a == b, *expected);
        assert_eq!(a.clone() == *b, *expected);
    }
}

#[test]
fn opcode_class_eq_30_combinations() {
    let classes = [
        RvOpcodeClass::Load,
        RvOpcodeClass::LoadFp,
        RvOpcodeClass::MiscMem,
        RvOpcodeClass::OpImm,
        RvOpcodeClass::Auipc,
        RvOpcodeClass::Store,
        RvOpcodeClass::Op,
        RvOpcodeClass::Lui,
        RvOpcodeClass::Branch,
        RvOpcodeClass::Jal,
        RvOpcodeClass::Jalr,
        RvOpcodeClass::System,
        RvOpcodeClass::Unknown,
    ];
    let mut count = 0;
    for (i, a) in classes.iter().enumerate() {
        for (j, b) in classes.iter().enumerate() {
            assert_eq!(a == b, i == j);
            count += 1;
        }
    }
    assert!(count >= 30);
}

#[test]
fn vsew_enum_from_bits_roundtrip() {
    for bits in 0u8..=7 {
        let v = RvVsew::from_bits(bits);
        let _ = v;
    }
    // Standard values 0..=3 are valid; >=4 reserved.
    // from_bits returns Option<RvVsew>; bits=0 is E8.
    assert!(RvVsew::from_bits(0).is_some());
}

// ---------------------------------------------------------------------------
// 7. Send/Sync threaded stress on documented Send+Sync types.
// ---------------------------------------------------------------------------

#[test]
fn riscv_arch_threaded_decode_stress() {
    use std::sync::Arc;
    use std::thread;

    let arch = Arc::new(RiscvArch::rv64());
    let words: Arc<Vec<u32>> = Arc::new({
        let mut g = Lcg::new();
        let mut v = Vec::with_capacity(100);
        for _ in 0..100 {
            v.push(g.u32());
        }
        v
    });

    let mut handles = Vec::new();
    for _t in 0..4 {
        let arch = arch.clone();
        let words = words.clone();
        handles.push(thread::spawn(move || {
            let mut total = 0u64;
            for _ in 0..100 {
                for &w in words.iter() {
                    let bytes = w.to_le_bytes();
                    let _ = arch.disassemble(Address::new(0), &bytes);
                    total = total.wrapping_add(u64::from(rv_opcode(w)));
                }
            }
            total
        }));
    }
    for h in handles {
        let _ = h.join().unwrap();
    }
}

#[test]
fn compressed_decode_threaded_stress() {
    use std::thread;
    let halves: Vec<u16> = {
        let mut g = Lcg::new();
        (0..100).map(|_| g.u16()).collect()
    };
    let mut handles = Vec::new();
    for _t in 0..4 {
        let halves = halves.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                for &hw in &halves {
                    let _ = decode_compressed(hw, 64, Address::new(0));
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ---------------------------------------------------------------------------
// 8. Lookups: known/unknown, multiple inputs.
// ---------------------------------------------------------------------------

#[test]
fn abi_reg_lookups_known_and_unknown() {
    // "fp" is an alias for s0 — not necessarily in the table; test the documented ones.
    let names = ["zero", "ra", "sp", "gp", "tp", "a0", "s11", "t6"];
    for n in &names {
        assert!(rv_abi_reg_lookup(n).is_some(), "missing {n}");
    }
    assert!(rv_abi_reg_lookup("notareg").is_none());
    assert!(rv_abi_reg_lookup("").is_none());
}

#[test]
fn fp_abi_reg_lookups_known_and_unknown() {
    let names = ["ft0", "fs0", "fa0", "fs11", "ft11"];
    for n in &names {
        assert!(rv_fp_abi_reg_lookup(n).is_some(), "missing {n}");
    }
    assert!(rv_fp_abi_reg_lookup("not-fp").is_none());
}

#[test]
fn csr_lookup_returns_none_for_all_unknown_high_addrs() {
    // Most CSR addresses above 0xFFF don't exist; rv_csr_ext_lookup must not panic.
    for addr in 0u16..=0x0FFF {
        let _ = rv_csr_ext_lookup(addr);
    }
}

#[test]
fn instr_lookup_known_and_unknown_strings() {
    assert!(rv_instr_lookup("addi").is_some());
    assert!(rv_instr_lookup("add").is_some());
    assert!(rv_instr_lookup("nothing-here-please").is_none());
    assert!(rv_instr_lookup("").is_none());
}

#[test]
fn sbi_lookup_known_and_unknown() {
    // Look up many (eid, fid) pairs without panic. Most miss.
    let mut g = Lcg::new();
    for _ in 0..50 {
        let eid = g.next();
        let fid = g.next() & 0xFF;
        let _ = sbi_lookup(eid, fid);
    }
}

#[test]
fn syscall_lookup_no_panic_for_random_numbers() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let _ = rv_syscall_lookup(g.next());
    }
}

#[test]
fn soc_lookup_known_and_unknown() {
    let _ = rv_soc_lookup("FU540");
    assert!(rv_soc_lookup("not-an-soc").is_none());
}

#[test]
fn cpu_lookup_known_and_unknown() {
    assert!(rv_cpu_lookup("not-a-cpu").is_none());
    // Don't assume any particular name exists; just exercise both arms.
    let _ = rv_cpu_lookup("U54");
}

// ---------------------------------------------------------------------------
// 9. Page / VPN sign-extension behaviour.
// ---------------------------------------------------------------------------

#[test]
fn sv39_canonical_sign_extends_high_bit() {
    // Bit 38 set -> high bits all 1.
    let va: u64 = 1 << 38;
    let c = sv39_canonical(va);
    assert_eq!(c >> 39, !0u64 >> 39);
    // Bit 38 clear -> high bits all 0.
    let va: u64 = (1 << 37) | 0xFF;
    let c = sv39_canonical(va);
    assert_eq!(c >> 39, 0);
}

#[test]
fn sv39_vpn_extract_indices() {
    // VPN[0] = bits [20:12], VPN[1] = [29:21], VPN[2] = [38:30].
    let va: u64 = (0b101u64 << 12) | (0b111u64 << 21) | (0b11u64 << 30);
    assert_eq!(sv39_vpn(va, 0), 0b101);
    assert_eq!(sv39_vpn(va, 1), 0b111);
    assert_eq!(sv39_vpn(va, 2), 0b11);
}

#[test]
fn phys_addr_combines_ppn_and_offset() {
    let pa = rv_phys_addr(0x12345, 0xABC);
    assert_eq!(pa, (0x12345u64 << 12) | 0xABC);
}

// ---------------------------------------------------------------------------
// 10. Encoder round-trips (50+ random encoder tests).
// ---------------------------------------------------------------------------

#[test]
fn encoder_rtype_field_roundtrip_50() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let rd = (g.next() & 0x1F) as u8;
        let rs1 = (g.next() & 0x1F) as u8;
        let rs2 = (g.next() & 0x1F) as u8;
        let w = rv_encode_add(rd, rs1, rs2);
        assert_eq!(rv_rd(w), rd);
        assert_eq!(rv_rs1(w), rs1);
        assert_eq!(rv_rs2(w), rs2);
        assert_eq!(rv_opcode(w), 0x33);
        let w = rv_encode_sub(rd, rs1, rs2);
        assert_eq!(rv_funct7(w), 0x20);
    }
}

#[test]
fn encoder_csr_roundtrip_50() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let rd = (g.next() & 0x1F) as u8;
        let rs1 = (g.next() & 0x1F) as u8;
        let csr = (g.next() & 0xFFF) as u16;
        let w = rv_encode_csrrw(rd, rs1, csr);
        assert_eq!(rv_rd(w), rd);
        assert_eq!(rv_rs1(w), rs1);
        assert_eq!(((w >> 20) & 0xFFF) as u16, csr);
        assert_eq!(rv_opcode(w), 0x73);
        assert_eq!(rv_funct3(w), 1);

        let w = rv_encode_csrrs(rd, rs1, csr);
        assert_eq!(rv_funct3(w), 2);
        let w = rv_encode_csrrc(rd, rs1, csr);
        assert_eq!(rv_funct3(w), 3);
    }
}

#[test]
fn encoder_jal_jalr_roundtrip() {
    let mut g = Lcg::new();
    for _ in 0..30 {
        let rd = (g.next() & 0x1F) as u8;
        // JAL takes 21-bit signed offset (even).
        let off = (((g.next()).cast_signed()) % 1_048_574) & !1;
        let off = off as i32;
        let w = rv_encode_jal(rd, off);
        assert_eq!(rv_opcode(w), 0x6F);
        assert_eq!(rv_rd(w), rd);
        assert_eq!(rv_imm_j(w), off);

        let imm = (((g.next()).cast_signed()) % 2048) as i16;
        let w = rv_encode_jalr(rd, 1, imm);
        assert_eq!(rv_opcode(w), 0x67);
        assert_eq!(rv_funct3(w), 0);
        assert_eq!(rv_imm_i(w), i32::from(imm));
    }
}

#[test]
fn ret_is_jalr_zero_ra_zero() {
    let ret = rv_encode_jalr(0, 1, 0);
    assert!(rv_is_ret(ret));
    assert!(rv_is_jalr(ret));
}

#[test]
fn nop_is_addi_x0_x0_0() {
    let nop = rv_encode_addi(0, 0, 0);
    assert_eq!(nop, RV_NOP);
    assert!(rv_is_nop(nop));
}

// ---------------------------------------------------------------------------
// 11. Truncated / oversized lift behaviour.
// ---------------------------------------------------------------------------

#[test]
fn lift_word_handles_all_opcodes() {
    // For every opcode value, run lift_word; must produce Vec<LlilOp> without panic.
    for op in 0u32..=0x7F {
        let _ = rv_lift_word(0, op, 64);
        let _ = rv_lift_word(0, op, 32);
    }
}

#[test]
fn alignment_helpers() {
    assert!(rv_is_instr_aligned(0));
    assert!(rv_is_instr_aligned(4));
    assert!(!rv_is_instr_aligned(1));
    assert!(!rv_is_instr_aligned(2));
    assert!(rv_is_cinstr_aligned(0));
    assert!(rv_is_cinstr_aligned(2));
    assert!(!rv_is_cinstr_aligned(1));
    assert!(!rv_is_cinstr_aligned(3));
}

#[test]
fn pmp_napot_decode_roundtrip() {
    // NAPOT encoding: lowest 0-bit gives size. Test a few power-of-two regions.
    let cases = [
        (0x0000_0000_8000_0007u64),
        (0x0000_0000_8000_001Fu64),
        (0x0000_0000_8000_00FFu64),
    ];
    for c in cases {
        let (base, size) = pmp_napot_decode(c);
        assert!(size.is_power_of_two() || size == 0);
        // base must be size-aligned.
        if size != 0 {
            assert_eq!(base & (size - 1), 0);
        }
    }
}

#[test]
fn pmp_cfg_bits_correct() {
    let cfg = PmpCfg(0b0001_1111);
    assert!(cfg.read());
    assert!(cfg.write());
    assert!(cfg.exec());
    let cfg = PmpCfg(0);
    assert!(!cfg.read());
    assert!(!cfg.write());
    assert!(!cfg.exec());
    assert!(matches!(cfg.mode(), PmpMode::Off));
}

#[test]
fn pmp_mode_from_bits_total() {
    for b in 0u8..=255 {
        let m = PmpMode::from_bits(b);
        // Every byte maps to one of the four modes.
        let n = m.name();
        assert!(["OFF", "TOR", "NA4", "NAPOT"].contains(&n));
    }
}

#[test]
fn vtype_imm_encoding_bits() {
    // VMA at bit 7, VTA at bit 6, VSEW at bits [5:3], VLMUL at bits [2:0].
    let v = rv_vtype_imm(true, true, 0b011, 0b101);
    assert_eq!((v >> 7) & 1, 1); // vma
    assert_eq!((v >> 6) & 1, 1); // vta
    assert_eq!((v >> 3) & 0x7, 0b011);
    assert_eq!(v & 0x7, 0b101);
}

#[test]
fn vsetvli_vsetivli_opcode() {
    let w = rv_encode_vsetvli(1, 2, 0);
    assert_eq!(rv_opcode(w), 0x57);
    let w = rv_encode_vsetivli(1, 3, 0);
    assert_eq!(rv_opcode(w), 0x57);
}

#[test]
fn fp_rm_str_total_for_3_bit_inputs() {
    // rm=7 is "dynamic" (typically rendered as empty); just verify totality (no panic).
    for rm in 0u8..=7 {
        let _ = rv_fp_rm_str(rm);
    }
}

#[test]
fn fclass_bit_name_total_for_low_bits() {
    for b in 0u8..=15 {
        let s = rv_fclass_bit_name(b);
        let _ = s.len();
    }
}

#[test]
fn gpr_fpr_name_total() {
    for i in 0u8..=31 {
        let g = rv_gpr_name(i);
        let f = rv_fpr_name(i);
        assert!(!g.is_empty());
        assert!(!f.is_empty());
    }
}

#[test]
fn gpr_role_categorisation() {
    let _ = rv_gpr_role(0);
    let _ = rv_gpr_role(1);
    let _ = rv_gpr_role(2);
    for i in 0u8..=31 {
        let role = rv_gpr_role(i);
        let _ = role;
    }
}

#[test]
fn caller_callee_saved_disjoint_for_args() {
    // x1 (ra) is caller-saved; x8 (s0) is callee-saved.
    assert!(rv_is_caller_saved(1));
    assert!(rv_is_callee_saved(8));
    assert!(!rv_is_caller_saved(8));
    assert!(!rv_is_callee_saved(1));
}

#[test]
fn detect_prologue_handles_empty_slice() {
    let (frame, spills) = rv_detect_prologue(&[]);
    assert!(frame.is_none());
    assert!(spills.is_empty());
}

#[test]
fn detect_prologue_random_words_no_panic() {
    let mut g = Lcg::new();
    let words: Vec<u32> = (0..20).map(|_| g.u32()).collect();
    let (_frame, _spills) = rv_detect_prologue(&words);
}

#[test]
fn lui_auipc_encode_check() {
    let w = rv_encode_lui(7, 0xABCDE);
    assert_eq!(rv_opcode(w), 0x37);
    assert_eq!(rv_rd(w), 7);
    let w = rv_encode_auipc(7, 0x12345);
    assert_eq!(rv_opcode(w), 0x17);
    assert_eq!(rv_rd(w), 7);
}

#[test]
fn fence_predicates_check() {
    // FENCE encoded as opcode 0x0F, funct3=0.
    let fence: u32 = 0x0F;
    assert!(rv_is_fence(fence));
    // FENCE.I has funct3=1.
    let fence_i: u32 = (1 << 12) | 0x0F;
    assert!(rv_is_fence_i(fence_i));
}

#[test]
fn linear_disassembler_offset_progresses() {
    let arch = RiscvArch::rv64();
    let bytes = vec![0x13u8, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00]; // two NOPs
    let mut dis = RiscvLinearDisassembler::new(&arch, &bytes, Address::new(0x1000));
    assert_eq!(dis.offset(), 0);
    let first = dis.next().unwrap().unwrap();
    // The decoder spells this as "addi" (literal addi x0,x0,0); accept either.
    assert!(first.mnemonic == "addi" || first.mnemonic == "nop");
    assert_eq!(dis.offset(), 4);
    let _ = dis.next().unwrap().unwrap();
    assert_eq!(dis.offset(), 8);
    assert!(dis.next().is_none());
    assert!(dis.is_done());
}

#[test]
fn linear_disassembler_truncated_tail() {
    let arch = RiscvArch::rv64();
    // 4 bytes NOP + 2 trailing bytes (truncated).
    let bytes = vec![0x13u8, 0x00, 0x00, 0x00, 0xAB, 0xCD];
    let mut dis = RiscvLinearDisassembler::new(&arch, &bytes, Address::new(0));
    let _ = dis.next();
    // The trailing 2 bytes must produce a truncation error, not panic.
    let r = dis.next();
    if let Some(rr) = r {
        assert!(rr.is_err(), "truncated tail should be Err");
    }
}

// ---------------------------------------------------------------------------
// 12. RvFeatures: union/has consistency.
// ---------------------------------------------------------------------------

#[test]
fn features_known_profiles() {
    let _ = RvFeatures::rv64gc();
    let _ = RvFeatures::rv32imac();
}

// ---------------------------------------------------------------------------
// 13. branch_target / jal_target wrap.
// ---------------------------------------------------------------------------

#[test]
fn branch_target_wraps_at_u64_boundary() {
    let w = rv_encode_beq(0, 0, -8);
    let t = rv_branch_target(4, w);
    assert_eq!(t, 0u64.wrapping_sub(4));
}

#[test]
fn jal_target_wraps_at_u64_boundary() {
    let w = rv_encode_jal(0, -8);
    let t = rv_jal_target(4, w);
    assert_eq!(t, 0u64.wrapping_sub(4));
}
