//! Deep adversarial tests for rustre-arch-cil.

use rustre_core::arch::{Architecture, InstrFlags};
use rustre_arch_cil::{CilArch, CilDecodeError, CilInstr, CilLinearDisassembler};
use rustre_core::address::Address;
use rustre_core::endian::Endian;

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        s
    }
}

// =========================================================================
// 1. Simple-opcode round-trip: decode emits raw == input slice
// =========================================================================

#[test]
fn rt_nop_raw_matches() {
    let (i, sz) = CilInstr::decode(&[0x00]).unwrap();
    assert_eq!(sz, 1);
    assert_eq!(i.raw, vec![0x00]);
}

#[test]
fn rt_all_simple_singleton_opcodes_roundtrip() {
    // Walks every single-byte opcode known to be SIMPLE (no operand). For
    // each: decode then re-decode raw, must produce identical CilInstr.
    let simples: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x25, 0x26, 0x2a, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
        0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65,
        0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x76, 0x7a, 0x82, 0x83, 0x84, 0x85,
        0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8e, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xb3, 0xb4, 0xb5, 0xb6,
        0xb7, 0xb8, 0xb9, 0xba, 0xc3, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
        0xdb, 0xdc, 0xdf, 0xe0,
    ];
    for &op in simples {
        let (i, sz) = CilInstr::decode(&[op]).unwrap_or_else(|e| panic!("op {op:#04x}: {e}"));
        assert_eq!(sz, 1, "op {op:#04x} should be 1 byte");
        assert_eq!(i.raw, vec![op]);
        assert!(i.operands.is_empty(), "op {op:#04x} should have no operands");
        // Re-decode raw, must match.
        let (i2, sz2) = CilInstr::decode(&i.raw).unwrap();
        assert_eq!(sz, sz2);
        assert_eq!(i, i2);
    }
}

#[test]
fn rt_ldc_i4_short_negative_and_positive() {
    for v in [i8::MIN, -50, -1, 0, 1, 50, i8::MAX] {
        let buf = [0x1f, v as u8];
        let (i, sz) = CilInstr::decode(&buf).unwrap();
        assert_eq!(sz, 2);
        assert_eq!(i.mnemonic, "ldc.i4.s");
        assert!(i.operands.contains(&v.to_string()));
    }
}

#[test]
fn rt_ldc_i4_boundary_values() {
    for v in [i32::MIN, -1, 0, 1, i32::MAX, 0x7FFF_FFFE] {
        let mut buf = vec![0x20u8];
        buf.extend_from_slice(&v.to_le_bytes());
        let (i, sz) = CilInstr::decode(&buf).unwrap();
        assert_eq!(sz, 5);
        assert_eq!(i.mnemonic, "ldc.i4");
        assert!(i.operands.contains(&v.to_string()));
    }
}

#[test]
fn rt_ldc_i8_boundary_values() {
    for v in [i64::MIN, -1, 0, 1, i64::MAX] {
        let mut buf = vec![0x21u8];
        buf.extend_from_slice(&v.to_le_bytes());
        let (i, sz) = CilInstr::decode(&buf).unwrap();
        assert_eq!(sz, 9);
        assert_eq!(i.mnemonic, "ldc.i8");
        assert!(i.operands.contains(&v.to_string()));
    }
}

#[test]
fn rt_ldc_r4_finite_values() {
    for v in [0.0f32, -0.0, 1.5, -3.14, f32::MIN, f32::MAX] {
        let mut buf = vec![0x22u8];
        buf.extend_from_slice(&v.to_le_bytes());
        let (i, sz) = CilInstr::decode(&buf).unwrap();
        assert_eq!(sz, 5);
        assert_eq!(i.mnemonic, "ldc.r4");
    }
}

#[test]
fn rt_ldc_r8_finite_values() {
    for v in [0.0f64, -0.0, 2.71828, f64::MIN, f64::MAX] {
        let mut buf = vec![0x23u8];
        buf.extend_from_slice(&v.to_le_bytes());
        let (i, sz) = CilInstr::decode(&buf).unwrap();
        assert_eq!(sz, 9);
        assert_eq!(i.mnemonic, "ldc.r8");
    }
}

// =========================================================================
// 2. Short branches: 1-byte signed offset
// =========================================================================

#[test]
fn short_branches_all_off_values() {
    let ops: &[(u8, &str)] = &[
        (0x2b, "br.s"),
        (0x2c, "brfalse.s"),
        (0x2d, "brtrue.s"),
        (0x2e, "beq.s"),
        (0x2f, "bge.s"),
        (0x30, "bgt.s"),
        (0x31, "ble.s"),
        (0x32, "blt.s"),
        (0x33, "bne.un.s"),
        (0x34, "bge.un.s"),
        (0x35, "bgt.un.s"),
        (0x36, "ble.un.s"),
        (0x37, "blt.un.s"),
        (0xde, "leave.s"),
    ];
    for &(op, mne) in ops {
        for off in [i8::MIN, -1, 0, 1, i8::MAX] {
            let buf = [op, off as u8];
            let (i, sz) = CilInstr::decode(&buf).unwrap();
            assert_eq!(sz, 2);
            assert_eq!(i.mnemonic, mne);
            assert!(i.flags.contains(InstrFlags::BRANCH));
            if op != 0x2b && op != 0xde {
                assert!(i.flags.contains(InstrFlags::CONDITIONAL), "{mne} cond");
            }
        }
    }
}

#[test]
fn long_branches_all_kinds_decode() {
    let ops: &[(u8, &str, bool)] = &[
        (0x38, "br", false),
        (0x39, "brfalse", true),
        (0x3a, "brtrue", true),
        (0x3b, "beq", true),
        (0x3c, "bge", true),
        (0x3d, "bgt", true),
        (0x3e, "ble", true),
        (0x3f, "blt", true),
        (0x40, "bne.un", true),
        (0x41, "bge.un", true),
        (0x42, "bgt.un", true),
        (0x43, "ble.un", true),
        (0x44, "blt.un", true),
        (0xdd, "leave", false),
    ];
    for &(op, mne, cond) in ops {
        for off in [i32::MIN, -1, 0, 1, i32::MAX] {
            let mut buf = vec![op];
            buf.extend_from_slice(&off.to_le_bytes());
            let (i, sz) = CilInstr::decode(&buf).unwrap();
            assert_eq!(sz, 5);
            assert_eq!(i.mnemonic, mne);
            assert!(i.flags.contains(InstrFlags::BRANCH));
            assert_eq!(i.flags.contains(InstrFlags::CONDITIONAL), cond);
        }
    }
}

// =========================================================================
// 3. Truncation handling — every length-bearing opcode
// =========================================================================

#[test]
fn truncated_empty() {
    assert_eq!(CilInstr::decode(&[]), Err(CilDecodeError::Truncated));
}

#[test]
fn truncated_short_form_opcodes() {
    // All opcodes that need a 1-byte operand after them.
    for op in [0x0e_u8, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x1f, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0xde]
    {
        assert_eq!(
            CilInstr::decode(&[op]),
            Err(CilDecodeError::Truncated),
            "op {op:#04x}"
        );
    }
}

#[test]
fn truncated_5_byte_opcodes() {
    for op in [0x20_u8, 0x22, 0x27, 0x28, 0x29, 0x38, 0x39, 0x3a, 0x6f, 0x70, 0x71, 0x72, 0x73,
        0x74, 0x75, 0x79, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x8c, 0x8d, 0x8f, 0xa3, 0xa4,
        0xa5, 0xc2, 0xc6, 0xd0, 0xdd]
    {
        for short in 1..5 {
            let buf = vec![op; short];
            assert!(
                matches!(CilInstr::decode(&buf), Err(CilDecodeError::Truncated)),
                "op {op:#04x} short {short}"
            );
        }
    }
}

#[test]
fn truncated_9_byte_opcodes() {
    for op in [0x21_u8, 0x23] {
        for short in 1..9 {
            let buf = vec![op; short];
            assert!(matches!(CilInstr::decode(&buf), Err(CilDecodeError::Truncated)));
        }
    }
}

#[test]
fn truncated_switch_no_targets() {
    // 0x45 needs 5 + n*4 bytes
    let mut buf = vec![0x45u8];
    buf.extend_from_slice(&3u32.to_le_bytes());
    // Only 1 of 3 target slots provided.
    buf.extend_from_slice(&0i32.to_le_bytes());
    assert!(matches!(CilInstr::decode(&buf), Err(CilDecodeError::Truncated)));
}

#[test]
fn truncated_fe_prefix_alone() {
    assert!(matches!(CilInstr::decode(&[0xfe]), Err(CilDecodeError::Truncated)));
}

#[test]
fn truncated_fe_prefix_6byte() {
    for op2 in [0x06_u8, 0x07, 0x15, 0x16, 0x1c] {
        for short in 2..6 {
            let mut buf = vec![0xfe_u8, op2];
            buf.extend(std::iter::repeat_n(0u8, short - 2));
            assert!(
                matches!(CilInstr::decode(&buf), Err(CilDecodeError::Truncated)),
                "fe {op2:#04x} short {short}"
            );
        }
    }
}

#[test]
fn truncated_fe_prefix_4byte() {
    for op2 in [0x09_u8, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e] {
        let buf = vec![0xfe_u8, op2, 0u8];
        assert!(matches!(CilInstr::decode(&buf), Err(CilDecodeError::Truncated)));
    }
}

#[test]
fn truncated_fe_prefix_3byte() {
    for op2 in [0x12_u8, 0x19] {
        let buf = vec![0xfe_u8, op2];
        assert!(matches!(CilInstr::decode(&buf), Err(CilDecodeError::Truncated)));
    }
}

// =========================================================================
// 4. Unknown opcodes report correct error
// =========================================================================

#[test]
fn unknown_opcode_returns_specific_error() {
    for op in [0x24_u8, 0x77, 0x78, 0xab, 0xac, 0xc0, 0xc1, 0xff] {
        match CilInstr::decode(&[op]) {
            Err(CilDecodeError::UnknownOpcode(o)) => assert_eq!(o, op),
            other => panic!("op {op:#04x} returned {other:?}"),
        }
    }
}

#[test]
fn unknown_fe_prefix_returns_specific_error() {
    // 0xFE 0x08 is unassigned
    for op2 in [0x08_u8, 0x10, 0x1b, 0x1f, 0xfe, 0xff] {
        let buf = [0xfe, op2];
        match CilInstr::decode(&buf) {
            Err(CilDecodeError::UnknownPrefixedOpcode(o)) => assert_eq!(o, op2),
            other => panic!("fe {op2:#04x} returned {other:?}"),
        }
    }
}

// =========================================================================
// 5. Switch boundaries / overflow
// =========================================================================

#[test]
fn switch_zero_targets_is_5_bytes() {
    let mut buf = vec![0x45u8];
    buf.extend_from_slice(&0u32.to_le_bytes());
    let (i, sz) = CilInstr::decode(&buf).unwrap();
    assert_eq!(sz, 5);
    assert_eq!(i.mnemonic, "switch");
    assert!(i.flags.contains(InstrFlags::BRANCH));
}

#[test]
fn switch_one_target_is_9_bytes() {
    let mut buf = vec![0x45u8];
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&42i32.to_le_bytes());
    let (i, sz) = CilInstr::decode(&buf).unwrap();
    assert_eq!(sz, 9);
    assert_eq!(i.mnemonic, "switch");
}

#[test]
fn switch_huge_count_triggers_truncated_not_panic() {
    // Use a huge count that would overflow usize on 32-bit but not 64-bit;
    // either way truncated since slice is tiny.
    let mut buf = vec![0x45u8];
    buf.extend_from_slice(&u32::MAX.to_le_bytes());
    let r = CilInstr::decode(&buf);
    assert!(matches!(r, Err(CilDecodeError::Truncated)));
}

// =========================================================================
// 6. LCG fuzz — never panic
// =========================================================================

#[test]
fn fuzz_random_single_byte_never_panics() {
    let mut g = lcg();
    for _ in 0..2000 {
        let b = (g() & 0xff) as u8;
        let _ = CilInstr::decode(&[b]);
    }
}

#[test]
fn fuzz_random_long_input_never_panics() {
    let mut g = lcg();
    for _ in 0..500 {
        let len = ((g() % 32) + 1) as usize;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push((g() & 0xff) as u8);
        }
        let _ = CilInstr::decode(&buf);
    }
}

#[test]
fn fuzz_fe_prefix_inputs_never_panic() {
    let mut g = lcg();
    for _ in 0..500 {
        let len = ((g() % 8) + 2) as usize;
        let mut buf = vec![0xfeu8];
        for _ in 1..len {
            buf.push((g() & 0xff) as u8);
        }
        let _ = CilInstr::decode(&buf);
    }
}

#[test]
fn fuzz_switch_inputs_never_panic() {
    let mut g = lcg();
    for _ in 0..200 {
        let n = (g() % 16) as u32;
        let mut buf = vec![0x45u8];
        buf.extend_from_slice(&n.to_le_bytes());
        for _ in 0..n {
            let t = g() as u32;
            buf.extend_from_slice(&t.to_le_bytes());
        }
        let r = CilInstr::decode(&buf);
        // Either Ok with correct length or specific error.
        match r {
            Ok((i, sz)) => {
                assert_eq!(i.mnemonic, "switch");
                assert_eq!(sz, 5 + (n as usize) * 4);
            }
            Err(CilDecodeError::Truncated) => {}
            Err(e) => panic!("unexpected switch error {e}"),
        }
    }
}

#[test]
fn fuzz_arch_disassemble_never_panics() {
    let mut g = lcg();
    let arch = CilArch::new_64();
    for _ in 0..500 {
        let len = ((g() % 16) + 1) as usize;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push((g() & 0xff) as u8);
        }
        let _ = arch.disassemble(Address::new(0x1000), &buf);
    }
}

// =========================================================================
// 7. Equality / Hash consistency  (CilInstr is Eq, not Hash, so just Eq.)
// =========================================================================

#[test]
fn eq_reflexive_for_decoded_instructions() {
    let inputs: &[&[u8]] = &[
        &[0x00],
        &[0x14],
        &[0x1f, 5],
        &[0x20, 1, 2, 3, 4],
        &[0xfe, 0x01],
    ];
    for &inp in inputs {
        let (a, _) = CilInstr::decode(inp).unwrap();
        let (b, _) = CilInstr::decode(inp).unwrap();
        assert_eq!(a, b);
    }
}

#[test]
fn ne_for_different_opcodes() {
    let (a, _) = CilInstr::decode(&[0x00]).unwrap();
    let (b, _) = CilInstr::decode(&[0x01]).unwrap();
    assert_ne!(a, b);
}

#[test]
fn decode_error_eq_works() {
    assert_eq!(CilDecodeError::Truncated, CilDecodeError::Truncated);
    assert_eq!(
        CilDecodeError::UnknownOpcode(0x24),
        CilDecodeError::UnknownOpcode(0x24)
    );
    assert_ne!(
        CilDecodeError::UnknownOpcode(0x24),
        CilDecodeError::UnknownOpcode(0x25)
    );
}

// =========================================================================
// 8. Architecture trait
// =========================================================================

#[test]
fn arch_name_and_pointer_size() {
    let a32 = CilArch::new_32();
    let a64 = CilArch::new_64();
    assert_eq!(a32.name(), "cil32");
    assert_eq!(a64.name(), "cil64");
    assert_eq!(a32.pointer_size(), 4);
    assert_eq!(a64.pointer_size(), 8);
}

#[test]
fn arch_endian_is_little() {
    assert_eq!(CilArch::new_64().endian(), Endian::Little);
}

#[test]
fn arch_disassemble_basic_nop() {
    let arch = CilArch::new_64();
    let instr = arch.disassemble(Address::new(0x100), &[0x00]).unwrap();
    assert_eq!(instr.mnemonic, "nop");
    assert_eq!(instr.size, 1);
}

#[test]
fn arch_disassemble_unknown_propagates_error() {
    let arch = CilArch::new_64();
    assert!(arch.disassemble(Address::new(0x100), &[0x24]).is_err());
}

#[test]
fn arch_disassemble_truncated_propagates_error() {
    let arch = CilArch::new_64();
    assert!(arch.disassemble(Address::new(0x100), &[]).is_err());
}

#[test]
fn arch_registers_present() {
    let regs = CilArch::new_64().registers();
    assert_eq!(regs.len(), 4);
    assert_eq!(regs[0].name, "arg0");
    assert_eq!(regs[3].name, "arg3");
}

#[test]
fn arch_calling_conventions_present() {
    let cc = CilArch::new_64().calling_conventions();
    assert_eq!(cc.len(), 1);
    assert_eq!(cc[0].name, "cil_managed");
    assert!(!cc[0].caller_cleans_stack);
}

#[test]
fn get_branches_short_branch_target() {
    let arch = CilArch::new_64();
    // br.s +5 at address 0x100 -> next=0x102, target=0x107
    let instr = arch.disassemble(Address::new(0x100), &[0x2b, 0x05]).unwrap();
    let b = arch.get_branches(&instr);
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].target, Some(0x107));
}

#[test]
fn get_branches_short_branch_negative_target() {
    let arch = CilArch::new_64();
    // br.s -2 at address 0x100 -> next=0x102, target=0x100
    let instr = arch.disassemble(Address::new(0x100), &[0x2b, 0xfeu8]).unwrap();
    let b = arch.get_branches(&instr);
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].target, Some(0x100));
}

#[test]
fn get_branches_long_branch_target() {
    let arch = CilArch::new_64();
    let mut buf = vec![0x38u8];
    buf.extend_from_slice(&100i32.to_le_bytes());
    let instr = arch.disassemble(Address::new(0x1000), &buf).unwrap();
    let b = arch.get_branches(&instr);
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].target, Some(0x1000 + 5 + 100));
}

#[test]
fn get_branches_nop_is_empty() {
    let arch = CilArch::new_64();
    let instr = arch.disassemble(Address::new(0x100), &[0x00]).unwrap();
    assert!(arch.get_branches(&instr).is_empty());
}

#[test]
fn get_branches_ret_is_empty() {
    let arch = CilArch::new_64();
    // ret has RET flag, no BRANCH / CALL flag — so get_branches returns empty
    let instr = arch.disassemble(Address::new(0x100), &[0x2a]).unwrap();
    assert!(arch.get_branches(&instr).is_empty());
}

#[test]
fn get_branches_short_branch_all_offsets() {
    let arch = CilArch::new_64();
    let base = 0x1000u64;
    for off in [i8::MIN, -10, -1, 0, 1, 10, i8::MAX] {
        let instr = arch
            .disassemble(Address::new(base), &[0x2b, off as u8])
            .unwrap();
        let b = arch.get_branches(&instr);
        assert_eq!(b.len(), 1);
        let expected = (base + 2).wrapping_add_signed(off as i64);
        assert_eq!(b[0].target, Some(expected));
    }
}

// =========================================================================
// 9. Linear disassembler
// =========================================================================

#[test]
fn linear_disasm_advances_past_unknown_byte() {
    let arch = CilArch::new_64();
    // 0x24 unknown, then nop.
    let bytes = [0x24, 0x00];
    let dis = CilLinearDisassembler::new(&arch, &bytes, Address::new(0));
    let results: Vec<_> = dis.collect();
    assert_eq!(results.len(), 2);
    assert!(results[0].is_err());
    assert!(results[1].is_ok());
    assert_eq!(results[1].as_ref().unwrap().mnemonic, "nop");
}

#[test]
fn linear_disasm_consumes_all_simple_bytes() {
    let arch = CilArch::new_64();
    let bytes = [0x00, 0x14, 0x25, 0x26, 0x2a];
    let dis = CilLinearDisassembler::new(&arch, &bytes, Address::new(0));
    let results: Vec<_> = dis.collect();
    assert_eq!(results.len(), 5);
    for r in &results {
        assert!(r.is_ok());
    }
    let mnes: Vec<&str> = results.iter().map(|r| r.as_ref().unwrap().mnemonic.as_str()).collect();
    assert_eq!(mnes, vec!["nop", "ldnull", "dup", "pop", "ret"]);
}

#[test]
fn linear_disasm_handles_multibyte() {
    let arch = CilArch::new_64();
    let mut bytes = vec![0x20u8];
    bytes.extend_from_slice(&7i32.to_le_bytes()); // ldc.i4 7
    bytes.push(0x2a); // ret
    let dis = CilLinearDisassembler::new(&arch, &bytes, Address::new(0x100));
    let results: Vec<_> = dis.collect();
    assert_eq!(results.len(), 2);
    let r0 = results[0].as_ref().unwrap();
    let r1 = results[1].as_ref().unwrap();
    assert_eq!(r0.address.as_u64(), 0x100);
    assert_eq!(r0.size, 5);
    assert_eq!(r1.address.as_u64(), 0x105);
    assert_eq!(r1.mnemonic, "ret");
}

#[test]
fn linear_disasm_empty_input_yields_nothing() {
    let arch = CilArch::new_64();
    let dis = CilLinearDisassembler::new(&arch, &[], Address::new(0));
    assert_eq!(dis.count(), 0);
}

#[test]
fn linear_disasm_truncated_tail_returns_error() {
    let arch = CilArch::new_64();
    // ldc.i4 needs 5 bytes; only 3 provided, all unknown opcode bytes.
    // 0x20 truncated, then 0x24 (unknown), then 0x24 (unknown).
    let bytes = [0x20u8, 0x24, 0x24];
    let dis = CilLinearDisassembler::new(&arch, &bytes, Address::new(0));
    let results: Vec<_> = dis.collect();
    // Each step advances by 1 on error; should produce 3 errors.
    assert_eq!(results.len(), 3);
    assert!(results.iter().all(|r| r.is_err()));
}

#[test]
fn linear_disasm_fuzz_random_bytes_never_panics() {
    let mut g = lcg();
    let arch = CilArch::new_64();
    for _ in 0..200 {
        let len = ((g() % 64) + 1) as usize;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push((g() & 0xff) as u8);
        }
        let dis = CilLinearDisassembler::new(&arch, &buf, Address::new(0));
        let _: Vec<_> = dis.collect();
    }
}

// =========================================================================
// 10. Send/Sync — CilArch is Send+Sync (no interior mutability) — threaded stress
// =========================================================================

#[test]
fn cil_arch_threaded_stress() {
    use std::sync::Arc;
    use std::thread;
    let arch = Arc::new(CilArch::new_64());
    let mut handles = vec![];
    for t in 0..4 {
        let arch = Arc::clone(&arch);
        handles.push(thread::spawn(move || {
            for i in 0..100u64 {
                let bytes = [0x00u8];
                let instr = arch.disassemble(Address::new(t * 1000 + i), &bytes).unwrap();
                assert_eq!(instr.mnemonic, "nop");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// =========================================================================
// 11. Default and Clone
// =========================================================================

#[test]
fn cil_arch_default_is_64bit() {
    let a: CilArch = Default::default();
    assert_eq!(a.bitness, 64);
}

#[test]
fn cil_arch_clone_independent() {
    let a = CilArch::new_64();
    let b = a.clone();
    assert_eq!(a.bitness, b.bitness);
}

#[test]
fn cil_instr_clone_eq() {
    let (i, _) = CilInstr::decode(&[0x00]).unwrap();
    let j = i.clone();
    assert_eq!(i, j);
}

// =========================================================================
// 12. Flag semantics
// =========================================================================

#[test]
fn call_opcodes_have_call_flag() {
    // call, calli, newobj, callvirt — all CALL
    let calls: &[(u8, &str)] = &[(0x28, "call"), (0x29, "calli"), (0x73, "newobj"), (0x6f, "callvirt")];
    for &(op, mne) in calls {
        let mut buf = vec![op];
        buf.extend_from_slice(&0u32.to_le_bytes());
        let (i, _) = CilInstr::decode(&buf).unwrap();
        assert_eq!(i.mnemonic, mne);
        assert!(i.flags.contains(InstrFlags::CALL), "{mne} CALL");
    }
}

#[test]
fn calli_and_callvirt_are_indirect() {
    for &(op, mne) in &[(0x29u8, "calli"), (0x6f, "callvirt")] {
        let mut buf = vec![op];
        buf.extend_from_slice(&0u32.to_le_bytes());
        let (i, _) = CilInstr::decode(&buf).unwrap();
        assert_eq!(i.mnemonic, mne);
        assert!(i.flags.contains(InstrFlags::INDIRECT));
    }
}

#[test]
fn ldind_family_has_read_mem() {
    for op in 0x46u8..=0x50 {
        let (i, _) = CilInstr::decode(&[op]).unwrap();
        assert!(i.flags.contains(InstrFlags::READ_MEM), "op {op:#04x}");
    }
}

#[test]
fn stind_family_has_write_mem() {
    for op in 0x51u8..=0x57 {
        let (i, _) = CilInstr::decode(&[op]).unwrap();
        assert!(i.flags.contains(InstrFlags::WRITE_MEM), "op {op:#04x}");
    }
}

#[test]
fn ret_endfinally_have_ret_flag() {
    for op in [0x2au8, 0xdc] {
        let (i, _) = CilInstr::decode(&[op]).unwrap();
        assert!(i.flags.contains(InstrFlags::RET));
    }
}

#[test]
fn break_has_barrier_flag() {
    let (i, _) = CilInstr::decode(&[0x01]).unwrap();
    assert!(i.flags.contains(InstrFlags::BARRIER));
}

#[test]
fn volatile_prefix_has_barrier_flag() {
    let (i, _) = CilInstr::decode(&[0xfe, 0x13]).unwrap();
    assert!(i.flags.contains(InstrFlags::BARRIER));
}

#[test]
fn fe_prefix_ldarg_starg_4byte_consumed() {
    for &(op2, mne) in &[
        (0x09_u8, "ldarg"),
        (0x0a, "ldarga"),
        (0x0b, "starg"),
        (0x0c, "ldloc"),
        (0x0d, "ldloca"),
        (0x0e, "stloc"),
    ] {
        let buf = [0xfe, op2, 0x34, 0x12];
        let (i, sz) = CilInstr::decode(&buf).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(i.mnemonic, mne);
        assert!(i.operands.contains("4660")); // 0x1234
    }
}

#[test]
fn fe_prefix_ldftn_ldvirtftn_6byte_consumed() {
    for &(op2, mne) in &[(0x06_u8, "ldftn"), (0x07, "ldvirtftn")] {
        let mut buf = vec![0xfe, op2];
        buf.extend_from_slice(&0xCAFEBABE_u32.to_le_bytes());
        let (i, sz) = CilInstr::decode(&buf).unwrap();
        assert_eq!(sz, 6);
        assert_eq!(i.mnemonic, mne);
    }
}

#[test]
fn raw_bytes_match_input_slice_after_decode() {
    // For multi-byte instructions, raw must equal the consumed prefix.
    let mut g = lcg();
    let arch = CilArch::new_64();
    let mut count_ok = 0;
    for _ in 0..1000 {
        let len = 16usize;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push((g() & 0xff) as u8);
        }
        if let Ok(instr) = arch.disassemble(Address::new(0), &buf) {
            assert_eq!(&instr.bytes[..], &buf[..instr.size]);
            count_ok += 1;
        }
    }
    assert!(count_ok > 0, "expected some successful decodes from fuzzing");
}
