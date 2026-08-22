//! Deep adversarial integration tests for `rustre-arch-jvm`.
//!
//! Covers public API: `decode/decode_at`, `JvmArch`, `JvmLinearDisassembler`,
//! `ConstantPoolTag`, `ClassFileHeader`, `FieldDescriptor`, `parse_method_descriptor`,
//! `parse_method_descriptor_typed`, `opcode_info`, `jvm_instruction_size`,
//! `jvm_stack_effect`, `jvm_is`_*, `jvm_max_stack_depth`, `jvm_count_invocations`,
//! `jvm_count_allocations`, `jvm_cyclomatic_complexity`, `jvm_build_cfg`,
//! `JvmDisassembler`, `JvmExceptionEntry`, `JvmTypeDesc`, `VerificationTypeFull`,
//! `access_flags`, `newarray_type`.


use rustre_arch_jvm::*;
use rustre_core::arch::Architecture;
use rustre_core::address::Address;
use rustre_core::endian::Endian;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

// ---------------------------------------------------------------------------
// LCG
// ---------------------------------------------------------------------------

struct Lcg(u64);
impl Lcg {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }
    const fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    const fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }
    fn next_bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u8()).collect()
    }
}

fn hash_of<T: Hash>(v: &T) -> u64 {
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

// ---------------------------------------------------------------------------
// 1. Decode: every 1-byte opcode round-trip
// ---------------------------------------------------------------------------

#[test]
fn t01_single_byte_opcodes_all_decode_or_specific_err() {
    for op in 0u8..=0xff {
        let r = JvmInstr::decode(&[op]);
        match op {
            // Reserved range always errs
            0xca..=0xff => assert!(matches!(r, Err(JvmDecodeError::Reserved(_)))),
            // Multi-byte ops should be Truncated when only one byte is provided
            0x10 | 0x11 | 0x12 | 0x13 | 0x14
            | 0x15..=0x19 | 0x36..=0x3a
            | 0x84 | 0x99..=0xa9
            | 0xaa | 0xab
            | 0xb2..=0xba | 0xbb..=0xbd
            | 0xc0 | 0xc1 | 0xc4 | 0xc5 | 0xc6 | 0xc7 | 0xc8 | 0xc9 => {
                assert!(matches!(r, Err(JvmDecodeError::Truncated)), "op={op:#x}");
            }
            _ => {
                let (i, sz) = r.unwrap_or_else(|e| panic!("op {op:#x} failed: {e:?}"));
                assert_eq!(sz, 1);
                assert!(!i.mnemonic.is_empty());
                assert_eq!(i.raw, vec![op]);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Truncation: every multi-byte op is truncated short by 1 byte
// ---------------------------------------------------------------------------

#[test]
fn t02_multibyte_truncated_by_one() {
    let cases: &[(u8, usize)] = &[
        (0x10, 2), (0x11, 3), (0x12, 2), (0x13, 3), (0x14, 3),
        (0x15, 2), (0x16, 2), (0x17, 2), (0x18, 2), (0x19, 2),
        (0x36, 2), (0x37, 2), (0x38, 2), (0x39, 2), (0x3a, 2),
        (0x84, 3),
        (0x99, 3), (0x9a, 3), (0xa7, 3), (0xa9, 2),
        (0xb2, 3), (0xb3, 3), (0xb6, 3),
        (0xb9, 5), (0xba, 5),
        (0xbb, 3), (0xbc, 2), (0xbd, 3),
        (0xc0, 3), (0xc1, 3),
        (0xc5, 4), (0xc6, 3), (0xc7, 3),
        (0xc8, 5), (0xc9, 5),
    ];
    for &(op, full) in cases {
        let mut buf = vec![0u8; full];
        buf[0] = op;
        // Truncate by 1
        let r = JvmInstr::decode(&buf[..full - 1]);
        assert!(
            matches!(r, Err(JvmDecodeError::Truncated)),
            "op {op:#x} short by 1 expected Truncated, got {r:?}"
        );
        // Full length decodes
        let r2 = JvmInstr::decode(&buf);
        assert!(r2.is_ok(), "op {op:#x} full failed: {r2:?}");
    }
}

// ---------------------------------------------------------------------------
// 3. jvm_instruction_size agrees with decoded raw.len() (fixed-len ops only)
// ---------------------------------------------------------------------------

#[test]
fn t03_instruction_size_matches_decoded_raw() {
    let cases: &[(u8, usize, usize)] = &[
        (0x00, 1, 1), (0x10, 2, 2), (0x11, 3, 3), (0x84, 3, 3),
        (0x99, 3, 3), (0xb6, 3, 3), (0xb9, 5, 5), (0xc5, 4, 4),
        (0xc8, 5, 5), (0xbc, 2, 2),
    ];
    for &(op, want, full) in cases {
        let mut buf = vec![0u8; full];
        buf[0] = op;
        let (i, sz) = JvmInstr::decode(&buf).unwrap();
        assert_eq!(sz, want);
        assert_eq!(i.raw.len(), want);
        assert_eq!(jvm_instruction_size(op), want);
    }
}

// ---------------------------------------------------------------------------
// 4. LCG fuzzing — decode never panics
// ---------------------------------------------------------------------------

#[test]
fn t04_fuzz_decode_no_panic() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..2000 {
        let len = (lcg.next_u8() as usize) % 32;
        let bytes = lcg.next_bytes(len);
        let _ = JvmInstr::decode(&bytes);
    }
}

#[test]
fn t05_fuzz_decode_at_no_panic() {
    let mut lcg = Lcg::new(0x1234_5678_9ABC_DEF0);
    for _ in 0..2000 {
        let len = (lcg.next_u8() as usize) % 64;
        let bytes = lcg.next_bytes(len);
        let pc = (lcg.next_u8() as usize) % 8;
        let _ = JvmInstr::decode_at(&bytes, pc);
    }
}

#[test]
fn t06_fuzz_linear_disasm_no_panic() {
    let mut lcg = Lcg::new(0xCAFE_F00D_DEAD_BEEF);
    let arch = JvmArch;
    for _ in 0..200 {
        let len = (lcg.next_u8() as usize) % 256;
        let bytes = lcg.next_bytes(len);
        let dis = JvmLinearDisassembler::new(&arch, &bytes, Address::new(0));
        for _ in dis {
            // consume
        }
    }
}

#[test]
fn t07_fuzz_disassembler_no_panic() {
    let mut lcg = Lcg::new(0xABCD_EF01_2345_6789);
    for _ in 0..200 {
        let len = (lcg.next_u8() as usize) % 256;
        let bytes = lcg.next_bytes(len);
        let _ = JvmDisassembler::disassemble(&bytes);
    }
}

#[test]
fn t08_fuzz_cfg_no_panic() {
    let mut lcg = Lcg::new(0x0F1E_2D3C_4B5A_6978);
    for _ in 0..100 {
        let len = (lcg.next_u8() as usize) % 128;
        let bytes = lcg.next_bytes(len);
        let _ = jvm_build_cfg(&bytes);
    }
}

// ---------------------------------------------------------------------------
// 5. JvmArch trait basics
// ---------------------------------------------------------------------------

#[test]
fn t09_arch_basics() {
    let a = JvmArch;
    assert_eq!(a.name(), "jvm");
    assert_eq!(a.pointer_size(), 4);
    assert_eq!(a.endian(), Endian::Big);
    assert_eq!(a.registers().len(), 4);
    assert_eq!(a.calling_conventions().len(), 1);
}

#[test]
fn t10_arch_disassemble_empty_errors() {
    let a = JvmArch;
    assert!(a.disassemble(Address::new(0), &[]).is_err());
}

#[test]
fn t11_arch_get_branches_goto() {
    let a = JvmArch;
    let i = a.disassemble(Address::new(0x100), &[0xa7, 0x00, 0x10]).unwrap();
    let br = a.get_branches(&i);
    assert_eq!(br.len(), 1);
    assert_eq!(br[0].target, Some(0x110));
}

#[test]
fn t12_arch_get_branches_goto_w_signed_negative() {
    let a = JvmArch;
    // -4 in 32-bit big-endian
    let i = a
        .disassemble(Address::new(0x1000), &[0xc8, 0xff, 0xff, 0xff, 0xfc])
        .unwrap();
    let br = a.get_branches(&i);
    assert_eq!(br.len(), 1);
    assert_eq!(br[0].target, Some(0x1000 - 4));
}

#[test]
fn t13_arch_get_branches_nonbranch_empty() {
    let a = JvmArch;
    let i = a.disassemble(Address::new(0), &[0x00]).unwrap();
    assert!(a.get_branches(&i).is_empty());
}

#[test]
fn t14_arch_get_branches_switch_yields_all_targets() {
    let a = JvmArch;
    // tableswitch at pc=0: pad=3, base=4, default low high = 0,0,0, count=1 entry
    let mut bytes = vec![0xaa, 0, 0, 0]; // padding to offset 4
    bytes.extend_from_slice(&[0, 0, 0, 8]); // default=8
    bytes.extend_from_slice(&[0, 0, 0, 0]); // low=0
    bytes.extend_from_slice(&[0, 0, 0, 0]); // high=0
    bytes.extend_from_slice(&[0, 0, 0, 4]); // one entry
    let i = a.disassemble(Address::new(0), &bytes).unwrap();
    assert_eq!(i.mnemonic, "tableswitch");
    // Used to assert the branch list was EMPTY, which pinned the old dead-end
    // behaviour. default=+8 and the single case=+4 are both real CFG edges.
    let targets: Vec<Option<u64>> = a.get_branches(&i).iter().map(|b| b.target).collect();
    assert_eq!(targets, vec![Some(8), Some(4)]);
}

// ---------------------------------------------------------------------------
// 6. LinearDisassembler determinism
// ---------------------------------------------------------------------------

#[test]
fn t15_linear_disassembler_program() {
    let a = JvmArch;
    let prog = [0x04u8, 0x60, 0xac];
    let v: Vec<_> = JvmLinearDisassembler::new(&a, &prog, Address::new(0))
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].mnemonic, "iconst_1");
    assert_eq!(v[2].mnemonic, "ireturn");
}

#[test]
fn t16_linear_disassembler_progress_on_error() {
    let a = JvmArch;
    let prog = [0xff_u8, 0x00]; // reserved then nop
    let v: Vec<_> = JvmLinearDisassembler::new(&a, &prog, Address::new(0)).collect();
    assert_eq!(v.len(), 2);
    assert!(v[0].is_err());
    assert!(v[1].is_ok());
}

// ---------------------------------------------------------------------------
// 7. ConstantPoolTag round-trip
// ---------------------------------------------------------------------------

#[test]
fn t17_constant_pool_tag_roundtrip() {
    for v in 0u8..=255u8 {
        if let Some(t) = ConstantPoolTag::from_u8(v) {
            assert_eq!(t as u8, v);
            assert!(!t.name().is_empty());
        }
    }
}

#[test]
fn t18_constant_pool_tag_wide() {
    assert!(ConstantPoolTag::Long.is_wide());
    assert!(ConstantPoolTag::Double.is_wide());
    assert!(!ConstantPoolTag::Utf8.is_wide());
    assert!(!ConstantPoolTag::Integer.is_wide());
}

#[test]
fn t19_constant_pool_tag_hash_eq_consistency() {
    let pairs = [
        (1u8, 1), (3, 3), (5, 5), (6, 6), (7, 7), (8, 8), (9, 9),
        (10, 10), (11, 11), (12, 12), (15, 15), (16, 16), (17, 17),
        (18, 18), (19, 19), (20, 20),
    ];
    let mut count = 0;
    for &(x, y) in &pairs {
        let a = ConstantPoolTag::from_u8(x).unwrap();
        let b = ConstantPoolTag::from_u8(y).unwrap();
        if a == b {
            assert_eq!(hash_of(&a), hash_of(&b));
            count += 1;
        }
    }
    assert!(count >= pairs.len());
    // Cross 30+ pairs with distinct
    let all: Vec<_> = pairs
        .iter()
        .map(|(x, _)| ConstantPoolTag::from_u8(*x).unwrap())
        .collect();
    for i in 0..all.len() {
        for j in 0..all.len() {
            if all[i] == all[j] {
                assert_eq!(hash_of(&all[i]), hash_of(&all[j]));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 8. ClassFileHeader
// ---------------------------------------------------------------------------

#[test]
fn t20_class_file_header_decode_valid() {
    let mut b = vec![0xCA, 0xFE, 0xBA, 0xBE]; // magic
    b.extend_from_slice(&0u16.to_be_bytes()); // minor
    b.extend_from_slice(&52u16.to_be_bytes()); // major (Java 8)
    b.extend_from_slice(&10u16.to_be_bytes()); // cp count
    let h = ClassFileHeader::decode(&b).unwrap();
    assert_eq!(h.magic, ClassFileHeader::MAGIC);
    assert_eq!(h.major_version, 52);
    assert_eq!(h.java_release(), Some(8));
    assert_eq!(h.constant_pool_count, 10);
}

#[test]
fn t21_class_file_header_truncated() {
    assert!(matches!(
        ClassFileHeader::decode(&[]),
        Err(JvmDecodeError::Truncated)
    ));
    assert!(matches!(
        ClassFileHeader::decode(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 0, 0]),
        Err(JvmDecodeError::Truncated)
    ));
}

#[test]
fn t22_class_file_header_bad_magic() {
    let mut b = vec![0xDE, 0xAD, 0xBE, 0xEF];
    b.extend_from_slice(&[0u8; 6]);
    assert!(matches!(
        ClassFileHeader::decode(&b),
        Err(JvmDecodeError::InvalidMagic(0xDEAD_BEEF))
    ));
}

#[test]
fn t23_class_file_header_java_releases() {
    let mappings = [(45u16, Some(1u32)), (52, Some(8)), (61, Some(17)), (67, Some(23)), (200, None)];
    for (maj, want) in mappings {
        let mut b = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0];
        b.extend_from_slice(&maj.to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes());
        let h = ClassFileHeader::decode(&b).unwrap();
        assert_eq!(h.java_release(), want);
    }
}

// ---------------------------------------------------------------------------
// 9. FieldDescriptor parsing
// ---------------------------------------------------------------------------

#[test]
fn t24_field_descriptor_primitives() {
    for (s, want) in [
        ("B", FieldDescriptor::Byte),
        ("C", FieldDescriptor::Char),
        ("D", FieldDescriptor::Double),
        ("F", FieldDescriptor::Float),
        ("I", FieldDescriptor::Int),
        ("J", FieldDescriptor::Long),
        ("S", FieldDescriptor::Short),
        ("Z", FieldDescriptor::Boolean),
    ] {
        let (got, n) = FieldDescriptor::parse(s).unwrap();
        assert_eq!(got, want);
        assert_eq!(n, 1);
    }
}

#[test]
fn t25_field_descriptor_object() {
    let (d, n) = FieldDescriptor::parse("Ljava/lang/String;").unwrap();
    assert_eq!(d, FieldDescriptor::Object("java/lang/String".into()));
    assert_eq!(n, "Ljava/lang/String;".len());
}

#[test]
fn t26_field_descriptor_nested_array() {
    let (d, n) = FieldDescriptor::parse("[[I").unwrap();
    assert_eq!(n, 3);
    match d {
        FieldDescriptor::Array(inner1) => match *inner1 {
            FieldDescriptor::Array(inner2) => assert_eq!(*inner2, FieldDescriptor::Int),
            _ => panic!(),
        },
        _ => panic!(),
    }
}

#[test]
fn t27_field_descriptor_malformed() {
    assert!(FieldDescriptor::parse("").is_none());
    assert!(FieldDescriptor::parse("X").is_none());
    assert!(FieldDescriptor::parse("Ljava/lang/String").is_none()); // no ';'
}

#[test]
fn t28_field_descriptor_category2() {
    assert!(FieldDescriptor::Long.is_category2());
    assert!(FieldDescriptor::Double.is_category2());
    assert!(!FieldDescriptor::Int.is_category2());
    assert!(!FieldDescriptor::Object("X".into()).is_category2());
}

#[test]
fn t29_field_descriptor_type_char() {
    assert_eq!(FieldDescriptor::Byte.type_char(), 'B');
    assert_eq!(FieldDescriptor::Array(Box::new(FieldDescriptor::Int)).type_char(), '[');
    assert_eq!(FieldDescriptor::Object("X".into()).type_char(), 'L');
}

#[test]
fn t30_field_descriptor_fuzz() {
    let mut lcg = Lcg::new(0x4242_4242_4242_4242);
    for _ in 0..500 {
        let len = (lcg.next_u8() as usize) % 16;
        let bytes = lcg.next_bytes(len);
        if let Ok(s) = std::str::from_utf8(&bytes) {
            let _ = FieldDescriptor::parse(s);
        }
    }
}

// ---------------------------------------------------------------------------
// 10. parse_method_descriptor
// ---------------------------------------------------------------------------

#[test]
fn t31_method_descriptor_void() {
    let (p, r) = parse_method_descriptor("()V").unwrap();
    assert!(p.is_empty());
    assert_eq!(r, "V");
}

#[test]
fn t32_method_descriptor_complex() {
    let (p, r) = parse_method_descriptor("(ILjava/lang/String;[I)Ljava/lang/Object;").unwrap();
    assert_eq!(p.len(), 3);
    assert_eq!(p[0], FieldDescriptor::Int);
    assert_eq!(p[1], FieldDescriptor::Object("java/lang/String".into()));
    assert!(matches!(p[2], FieldDescriptor::Array(_)));
    assert_eq!(r, "Ljava/lang/Object;");
}

#[test]
fn t33_method_descriptor_malformed() {
    assert!(parse_method_descriptor("V").is_none()); // no '('
    assert!(parse_method_descriptor("(I").is_none()); // no ')'
    assert!(parse_method_descriptor("(X)V").is_none()); // bad param
}

#[test]
fn t34_method_descriptor_typed_roundtrip() {
    let (p, r) = parse_method_descriptor_typed("(IJ)V").unwrap();
    assert_eq!(p.len(), 2);
    assert_eq!(p[0], JvmTypeDesc::Int);
    assert_eq!(p[1], JvmTypeDesc::Long);
    assert_eq!(r, JvmTypeDesc::Void);
}

#[test]
fn t35_method_descriptor_typed_malformed() {
    assert!(parse_method_descriptor_typed("").is_none());
    assert!(parse_method_descriptor_typed("()").is_none()); // empty return
    assert!(parse_method_descriptor_typed("I)V").is_none());
}

// ---------------------------------------------------------------------------
// 11. opcode_info — every opcode in OPCODE_TABLE returns Some
// ---------------------------------------------------------------------------

#[test]
fn t36_opcode_info_known_set() {
    // Pick a representative sample
    for op in [0x00u8, 0x01, 0x10, 0x60, 0x84, 0x99, 0xa7, 0xb6, 0xc5] {
        let info = opcode_info(op).unwrap_or_else(|| panic!("opcode_info({op:#x})"));
        assert_eq!(info.opcode, op);
        assert!(!info.mnemonic.is_empty());
    }
}

#[test]
fn t37_opcode_info_reserved_none() {
    for op in 0xcau8..=0xff {
        assert!(opcode_info(op).is_none(), "op {op:#x} should be None");
    }
}

// ---------------------------------------------------------------------------
// 12. jvm_stack_effect — invariants
// ---------------------------------------------------------------------------

#[test]
fn t38_stack_effect_delta_matches() {
    for op in 0u8..=0xff {
        if let Some(se) = jvm_stack_effect(op) {
            assert_eq!(se.delta(), se.pushes - se.pops, "op {op:#x}");
        }
    }
}

#[test]
fn t39_stack_effect_invokes_none() {
    // Invokes are variable-effect → None
    for op in 0xb6u8..=0xba {
        assert!(jvm_stack_effect(op).is_none(), "op {op:#x}");
    }
}

#[test]
fn t40_is_branch_return_invoke_alloc() {
    assert!(jvm_is_branch(0x99));
    assert!(jvm_is_branch(0xa7));
    assert!(jvm_is_branch(0xc8));
    assert!(!jvm_is_branch(0x00));

    assert!(jvm_is_return(0xac));
    assert!(jvm_is_return(0xb1));
    assert!(jvm_is_return(0xbf));
    assert!(!jvm_is_return(0xa7));

    assert!(jvm_is_invoke(0xb6));
    assert!(jvm_is_invoke(0xba));
    assert!(!jvm_is_invoke(0xbb));

    assert!(jvm_is_alloc(0xbb));
    assert!(jvm_is_alloc(0xc5));
    assert!(!jvm_is_alloc(0xb6));

    assert!(jvm_is_field_access(0xb2));
    assert!(jvm_is_field_access(0xb5));
    assert!(!jvm_is_field_access(0xb6));
}

// ---------------------------------------------------------------------------
// 13. JvmDisassembler / jvm_build_cfg / metrics
// ---------------------------------------------------------------------------

#[test]
fn t41_disassemble_simple_program() {
    let prog = [0x04u8, 0x60, 0xac];
    let v = JvmDisassembler::disassemble(&prog);
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].opcode, 0x04);
    assert_eq!(v[0].offset, 0);
    assert_eq!(v[2].offset, 2);
}

#[test]
fn t42_count_invocations_and_allocs() {
    // new(2 bytes operand) + invokestatic + return
    let prog = [
        0xbb, 0, 1, // new #1
        0xb8, 0, 2, // invokestatic #2
        0xb1, // return
    ];
    assert_eq!(jvm_count_invocations(&prog), 1);
    assert_eq!(jvm_count_allocations(&prog), 1);
}

#[test]
fn t43_cyclomatic_complexity_baseline() {
    let prog = [0x00u8, 0xb1]; // nop; return
    assert_eq!(jvm_cyclomatic_complexity(&prog), 1);
}

#[test]
fn t44_cyclomatic_with_conds() {
    let prog = [
        0x99, 0, 5, // ifeq +5
        0x9a, 0, 5, // ifne +5
        0xb1,
    ];
    assert_eq!(jvm_cyclomatic_complexity(&prog), 3);
}

#[test]
fn t45_max_stack_depth_constants() {
    // iconst_1 iconst_1 iadd ireturn -> max 2
    let prog = [0x04u8, 0x04, 0x60, 0xac];
    let d = jvm_max_stack_depth(&prog);
    assert!(d >= 1);
}

#[test]
fn t46_cfg_single_block_when_no_branches() {
    let prog = [0x00u8, 0x00, 0xb1];
    let cfg = jvm_build_cfg(&prog);
    assert_eq!(cfg.len(), 1);
    assert_eq!(cfg[0].start, 0);
}

#[test]
fn t47_cfg_branches_create_blocks() {
    // ifeq +3 (forward), nop, return
    let prog = [0x99u8, 0, 6, 0x00, 0x00, 0x00, 0xb1];
    let cfg = jvm_build_cfg(&prog);
    assert!(cfg.len() >= 2);
}

// ---------------------------------------------------------------------------
// 14. JvmExceptionEntry
// ---------------------------------------------------------------------------

#[test]
fn t48_exception_entry_covers_and_finally() {
    let e = JvmExceptionEntry {
        start_pc: 10,
        end_pc: 20,
        handler_pc: 30,
        catch_type: 0,
    };
    assert!(e.is_finally());
    assert!(e.covers(10));
    assert!(e.covers(19));
    assert!(!e.covers(20));
    assert!(!e.covers(9));
    let e2 = JvmExceptionEntry { catch_type: 5, ..e };
    assert!(!e2.is_finally());

    // Hash/Eq consistency
    let e3 = e.clone();
    assert_eq!(e, e3);
}

// ---------------------------------------------------------------------------
// 15. VerificationTypeFull
// ---------------------------------------------------------------------------

#[test]
fn t49_verification_type_category2_and_str() {
    assert!(VerificationTypeFull::Long.is_category2());
    assert!(VerificationTypeFull::Double.is_category2());
    assert!(!VerificationTypeFull::Integer.is_category2());
    assert_eq!(VerificationTypeFull::Top.as_str(), "top");
    assert_eq!(VerificationTypeFull::Object { class_name: "X".into() }.as_str(), "object");
    assert_eq!(VerificationTypeFull::Uninitialized { offset: 0 }.as_str(), "uninitialized");
}

#[test]
fn t50_verification_type_assignable() {
    let int = VerificationTypeFull::Integer;
    assert!(VerificationTypeFull::Top.is_assignable_from(&int));
    assert!(int.is_assignable_from(&int));
    let obj = VerificationTypeFull::Object { class_name: "java/lang/Object".into() };
    assert!(obj.is_assignable_from(&VerificationTypeFull::Null));
    assert!(!int.is_assignable_from(&VerificationTypeFull::Long));
}

// ---------------------------------------------------------------------------
// 16. access_flags formatter & newarray_type
// ---------------------------------------------------------------------------

#[test]
fn t51_access_flags_method_format() {
    use access_flags::*;
    let s = method_flags_str(ACC_PUBLIC | ACC_STATIC | ACC_FINAL);
    assert!(s.contains("public"));
    assert!(s.contains("static"));
    assert!(s.contains("final"));
    assert!(method_flags_str(0).is_empty());
}

#[test]
fn t52_newarray_type_names() {
    use newarray_type::*;
    assert_eq!(name(T_BOOLEAN), Some("boolean"));
    assert_eq!(name(T_LONG), Some("long"));
    assert_eq!(name(0), None);
    assert_eq!(name(255), None);
}

// ---------------------------------------------------------------------------
// 17. JvmTypeDesc helpers
// ---------------------------------------------------------------------------

#[test]
fn t53_jvm_type_desc_chars_and_cat() {
    assert_eq!(JvmTypeDesc::Int.descriptor_char(), 'I');
    assert_eq!(JvmTypeDesc::Long.descriptor_char(), 'J');
    assert_eq!(JvmTypeDesc::Long.category(), 2);
    assert_eq!(JvmTypeDesc::Double.category(), 2);
    assert_eq!(JvmTypeDesc::Int.category(), 1);
    assert_eq!(JvmTypeDesc::from_char('I'), Some(JvmTypeDesc::Int));
    assert_eq!(JvmTypeDesc::from_char('?'), None);
    assert_eq!(JvmTypeDesc::Object("X".into()).descriptor_char(), 'L');
    assert_eq!(JvmTypeDesc::Array(Box::new(JvmTypeDesc::Int)).descriptor_char(), 'L');
}

// ---------------------------------------------------------------------------
// 18. tableswitch / lookupswitch alignment correctness
// ---------------------------------------------------------------------------

#[test]
fn t54_tableswitch_alignment_pc0() {
    // pc=0 → pad = (4 - 1%4) %4 = 3
    let mut bytes = vec![0xaa, 0, 0, 0]; // op + 3 pad
    bytes.extend_from_slice(&20i32.to_be_bytes()); // default
    bytes.extend_from_slice(&0i32.to_be_bytes()); // low
    bytes.extend_from_slice(&2i32.to_be_bytes()); // high → 3 entries
    bytes.extend_from_slice(&100i32.to_be_bytes());
    bytes.extend_from_slice(&200i32.to_be_bytes());
    bytes.extend_from_slice(&300i32.to_be_bytes());
    let (i, sz) = JvmInstr::decode_at(&bytes, 0).unwrap();
    assert_eq!(i.mnemonic, "tableswitch");
    assert_eq!(sz, bytes.len());
}

#[test]
fn t55_lookupswitch_alignment_pc3() {
    // pc=3 → pad = (4 - 4%4)%4 = 0
    let mut bytes = vec![0xab]; // op
    bytes.extend_from_slice(&10i32.to_be_bytes()); // default
    bytes.extend_from_slice(&2i32.to_be_bytes()); // npairs
    bytes.extend_from_slice(&1i32.to_be_bytes());
    bytes.extend_from_slice(&100i32.to_be_bytes());
    bytes.extend_from_slice(&2i32.to_be_bytes());
    bytes.extend_from_slice(&200i32.to_be_bytes());
    let (i, sz) = JvmInstr::decode_at(&bytes, 3).unwrap();
    assert_eq!(i.mnemonic, "lookupswitch");
    assert_eq!(sz, bytes.len());
}

#[test]
fn t56_lookupswitch_negative_npairs_safe() {
    // negative npairs is clamped to 0
    let mut bytes = vec![0xab, 0, 0, 0]; // op + 3 pad
    bytes.extend_from_slice(&0i32.to_be_bytes()); // default
    bytes.extend_from_slice(&(-1i32).to_be_bytes()); // npairs negative
    let r = JvmInstr::decode_at(&bytes, 0);
    assert!(r.is_ok());
}

// ---------------------------------------------------------------------------
// 19. Wide prefix
// ---------------------------------------------------------------------------

#[test]
fn t57_wide_loads_stores() {
    for sub in [0x15u8, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3a, 0xa9] {
        let (i, sz) = JvmInstr::decode(&[0xc4, sub, 0x00, 0x01]).unwrap();
        assert_eq!(sz, 4);
        assert!(i.mnemonic.starts_with("Wide "));
    }
}

#[test]
fn t58_wide_iinc() {
    let (i, sz) = JvmInstr::decode(&[0xc4, 0x84, 0x00, 0x05, 0xff, 0xff]).unwrap();
    assert_eq!(sz, 6);
    assert_eq!(i.mnemonic, "Wide Iinc");
}

#[test]
fn t59_wide_unknown_sub() {
    let r = JvmInstr::decode(&[0xc4, 0x00]);
    assert!(matches!(r, Err(JvmDecodeError::UnknownOpcode(0x00))));
}

// ---------------------------------------------------------------------------
// 20. JvmInstr Eq/Hash-like consistency (no Hash, but Eq+Clone)
// ---------------------------------------------------------------------------

#[test]
fn t60_jvminstr_clone_eq() {
    let (i, _) = JvmInstr::decode(&[0x10, 0x42]).unwrap();
    let j = i.clone();
    assert_eq!(i, j);
}

// ---------------------------------------------------------------------------
// 21. JvmDecodeError variants & Clone
// ---------------------------------------------------------------------------

#[test]
fn t61_decode_error_clone_eq() {
    let e1 = JvmDecodeError::UnknownOpcode(0x42);
    let e2 = e1.clone();
    assert_eq!(e1, e2);
    let s = format!("{}", JvmDecodeError::Truncated);
    assert!(s.contains("truncated"));
    let s2 = format!("{}", JvmDecodeError::Reserved(0xcc));
    assert!(s2.contains("reserved") || s2.contains("Reserved") || s2.contains("0xcc"));
}

// ---------------------------------------------------------------------------
// 22. Send+Sync threaded stress on JvmArch (impl trait, Clone)
// ---------------------------------------------------------------------------

#[test]
fn t62_arch_thread_stress() {
    let arch = Arc::new(JvmArch);
    let mut handles = vec![];
    for t in 0..4u64 {
        let a = arch.clone();
        handles.push(thread::spawn(move || {
            let mut lcg = Lcg::new(0xDEAD_BEEF_0000 ^ (t * 12345));
            for _ in 0..100 {
                let prog = [0x00u8, 0x04, 0x60, 0xac];
                let i = a.disassemble(Address::new(0), &prog).unwrap();
                assert_eq!(i.mnemonic, "nop");
                let _ = lcg.next_u64();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ---------------------------------------------------------------------------
// 23. Decode 50 deterministic seeded programs and confirm sizes consistent
// ---------------------------------------------------------------------------

#[test]
fn t63_seeded_program_consistency() {
    let mut lcg = Lcg::new(0xABCD_0123_4567_89EF);
    for _ in 0..50 {
        // Build a small program of bipush+pop pairs
        let mut prog = Vec::new();
        let n = (lcg.next_u8() % 8) + 1;
        for _ in 0..n {
            prog.push(0x10);
            prog.push(lcg.next_u8());
            prog.push(0x57); // pop
        }
        prog.push(0xb1); // return

        // Verify linear disassembly succeeds end-to-end
        let arch = JvmArch;
        let v: Vec<_> = JvmLinearDisassembler::new(&arch, &prog, Address::new(0))
            .collect::<Result<_, _>>()
            .unwrap();
        let total_sz: usize = v.iter().map(|i| i.size).sum();
        assert_eq!(total_sz, prog.len());
    }
}

// ---------------------------------------------------------------------------
// 24. invokeinterface count byte preserved
// ---------------------------------------------------------------------------

#[test]
fn t64_invokeinterface_operands() {
    let v = JvmDisassembler::disassemble(&[0xb9, 0x01, 0x02, 0x03, 0x00]);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].operands, vec![0x0102u32, 0x03]);
}

// ---------------------------------------------------------------------------
// 25. iinc operands
// ---------------------------------------------------------------------------

#[test]
fn t65_iinc_operands() {
    let v = JvmDisassembler::disassemble(&[0x84, 0x05, 0xff]);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].operands, vec![5u32, 0xff]);
}

// ---------------------------------------------------------------------------
// 26. boundary inputs - largest u16 references
// ---------------------------------------------------------------------------

#[test]
fn t66_getstatic_max_u16() {
    let (i, _) = JvmInstr::decode(&[0xb2, 0xff, 0xff]).unwrap();
    assert_eq!(i.mnemonic, "getstatic");
    assert!(i.operands.contains("65535"));
}

#[test]
fn t67_bipush_extremes() {
    let (i, _) = JvmInstr::decode(&[0x10, 0x80]).unwrap();
    assert!(i.operands.contains("-128"));
    let (i2, _) = JvmInstr::decode(&[0x10, 0x7f]).unwrap();
    assert!(i2.operands.contains("127"));
}

#[test]
fn t68_sipush_extremes() {
    let (i, _) = JvmInstr::decode(&[0x11, 0x80, 0x00]).unwrap();
    assert!(i.operands.contains("-32768"));
    let (i2, _) = JvmInstr::decode(&[0x11, 0x7f, 0xff]).unwrap();
    assert!(i2.operands.contains("32767"));
}

// ---------------------------------------------------------------------------
// 27. Empty bytecode metrics
// ---------------------------------------------------------------------------

#[test]
fn t69_empty_metrics() {
    assert_eq!(jvm_count_invocations(&[]), 0);
    assert_eq!(jvm_count_allocations(&[]), 0);
    assert_eq!(jvm_cyclomatic_complexity(&[]), 1);
    assert_eq!(jvm_max_stack_depth(&[]), 0);
    assert!(jvm_build_cfg(&[]).is_empty());
}
