//! Exhaustive blitz tests for `rustre-arch-jvm`.
//!
//! These integration tests exercise the public surface of the crate
//! (decoder, constant pool, attribute parser, security facade, lifter, etc).
//! Failing tests are intentionally left failing when they expose a real bug
//! in the production code.

use rustre_core::arch::Architecture;
use rustre_arch_jvm::jvm_constant_pool::{ConstantEntry, ConstantTag, CpParseError, JvmConstantPool};
use rustre_arch_jvm::{JvmArch, JvmDecodeError, JvmInstr, JvmLinearDisassembler};
use rustre_core::address::Address;
use rustre_core::endian::Endian;

fn arch() -> JvmArch {
    JvmArch
}

// ---------------------------------------------------------------------------
// Decode — happy paths across every opcode family
// ---------------------------------------------------------------------------

#[test]
fn decode_nop_size_and_mnemonic() {
    let (i, sz) = JvmInstr::decode(&[0x00]).unwrap();
    assert_eq!(sz, 1);
    assert_eq!(i.mnemonic, "nop");
    assert_eq!(i.raw, vec![0x00]);
}

#[test]
fn decode_aconst_null_through_dconst_1() {
    let mnes = [
        (0x01u8, "aconst_null"),
        (0x02, "iconst_m1"),
        (0x03, "iconst_0"),
        (0x04, "iconst_1"),
        (0x05, "iconst_2"),
        (0x06, "iconst_3"),
        (0x07, "iconst_4"),
        (0x08, "iconst_5"),
        (0x09, "lconst_0"),
        (0x0a, "lconst_1"),
        (0x0b, "fconst_0"),
        (0x0c, "fconst_1"),
        (0x0d, "fconst_2"),
        (0x0e, "dconst_0"),
        (0x0f, "dconst_1"),
    ];
    for (op, expected) in mnes {
        let (i, sz) = JvmInstr::decode(&[op]).unwrap();
        assert_eq!(sz, 1, "op {:#x}", op);
        assert_eq!(i.mnemonic, expected, "op {:#x}", op);
    }
}

#[test]
fn decode_bipush_negative_value() {
    let (i, _) = JvmInstr::decode(&[0x10, 0xff]).unwrap();
    assert_eq!(i.mnemonic, "bipush");
    assert!(i.operands.contains("-1"), "expected -1, got {}", i.operands);
}

#[test]
fn decode_bipush_extremes() {
    let (i_min, _) = JvmInstr::decode(&[0x10, 0x80]).unwrap();
    assert!(i_min.operands.contains("-128"), "got {}", i_min.operands);
    let (i_max, _) = JvmInstr::decode(&[0x10, 0x7f]).unwrap();
    assert!(i_max.operands.contains("127"), "got {}", i_max.operands);
}

#[test]
fn decode_sipush_negative() {
    let (i, sz) = JvmInstr::decode(&[0x11, 0xff, 0xff]).unwrap();
    assert_eq!(sz, 3);
    assert!(i.operands.contains("-1"), "got {}", i.operands);
}

#[test]
fn decode_sipush_extremes() {
    let (i_min, _) = JvmInstr::decode(&[0x11, 0x80, 0x00]).unwrap();
    assert!(i_min.operands.contains("-32768"));
    let (i_max, _) = JvmInstr::decode(&[0x11, 0x7f, 0xff]).unwrap();
    assert!(i_max.operands.contains("32767"));
}

#[test]
fn decode_ldc_w_index() {
    let (i, sz) = JvmInstr::decode(&[0x13, 0x01, 0x02]).unwrap();
    assert_eq!(sz, 3);
    assert_eq!(i.mnemonic, "ldc_w");
    assert!(i.operands.contains("258"));
}

#[test]
fn decode_ldc2_w_index() {
    let (i, sz) = JvmInstr::decode(&[0x14, 0xff, 0xff]).unwrap();
    assert_eq!(sz, 3);
    assert_eq!(i.mnemonic, "ldc2_w");
    assert!(i.operands.contains("65535"));
}

#[test]
fn decode_iinc_negative_const() {
    let (i, sz) = JvmInstr::decode(&[0x84, 0x03, 0xff]).unwrap();
    assert_eq!(sz, 3);
    assert_eq!(i.mnemonic, "iinc");
    assert!(i.operands.contains("-1"), "got {}", i.operands);
}

// ---------------------------------------------------------------------------
// Truncation errors
// ---------------------------------------------------------------------------

#[test]
fn decode_empty_is_truncated() {
    assert_eq!(JvmInstr::decode(&[]), Err(JvmDecodeError::Truncated));
}

#[test]
fn decode_bipush_missing_operand() {
    assert_eq!(JvmInstr::decode(&[0x10]), Err(JvmDecodeError::Truncated));
}

#[test]
fn decode_sipush_missing_one_byte() {
    assert_eq!(JvmInstr::decode(&[0x11, 0x00]), Err(JvmDecodeError::Truncated));
}

#[test]
fn decode_invokeinterface_needs_5_bytes() {
    assert_eq!(
        JvmInstr::decode(&[0xb9, 0x00, 0x10, 0x02]),
        Err(JvmDecodeError::Truncated)
    );
}

#[test]
fn decode_goto_w_needs_5_bytes() {
    assert_eq!(
        JvmInstr::decode(&[0xc8, 0x00, 0x00, 0x00]),
        Err(JvmDecodeError::Truncated)
    );
}

#[test]
fn decode_wide_iload_needs_4_bytes() {
    assert_eq!(
        JvmInstr::decode(&[0xc4, 0x15, 0x00]),
        Err(JvmDecodeError::Truncated)
    );
}

#[test]
fn decode_wide_iinc_needs_6_bytes() {
    assert_eq!(
        JvmInstr::decode(&[0xc4, 0x84, 0x00, 0x01, 0x00]),
        Err(JvmDecodeError::Truncated)
    );
}

#[test]
fn decode_wide_unknown_sub_opcode() {
    // 0x00 (nop) is not a valid wide sub-opcode.
    let r = JvmInstr::decode(&[0xc4, 0x00]);
    assert!(matches!(r, Err(JvmDecodeError::UnknownOpcode(0x00))), "{:?}", r);
}

#[test]
fn decode_reserved_opcodes_all() {
    for op in 0xca..=0xffu16 {
        let r = JvmInstr::decode(&[op as u8]);
        assert!(
            matches!(r, Err(JvmDecodeError::Reserved(b)) if b == op as u8),
            "op {:#x}: {:?}",
            op,
            r
        );
    }
}

#[test]
fn decode_multianewarray_dims() {
    let (i, sz) = JvmInstr::decode(&[0xc5, 0x00, 0x05, 0x03]).unwrap();
    assert_eq!(sz, 4);
    assert_eq!(i.mnemonic, "multianewarray");
    assert!(i.operands.contains("dims=3"));
}

// ---------------------------------------------------------------------------
// Tableswitch / Lookupswitch
// ---------------------------------------------------------------------------

#[test]
fn decode_tableswitch_aligned_at_pc0() {
    // pc=0: opcode at 0, padding = (4 - 1) % 4 = 3 bytes
    let mut buf = vec![0xaa, 0, 0, 0]; // opcode + 3 pad
    buf.extend_from_slice(&0i32.to_be_bytes()); // default
    buf.extend_from_slice(&0i32.to_be_bytes()); // low=0
    buf.extend_from_slice(&1i32.to_be_bytes()); // high=1 -> 2 entries
    buf.extend_from_slice(&10i32.to_be_bytes());
    buf.extend_from_slice(&20i32.to_be_bytes());
    let (i, sz) = JvmInstr::decode_at(&buf, 0).unwrap();
    assert_eq!(i.mnemonic, "tableswitch");
    assert_eq!(sz, buf.len());
}

#[test]
fn decode_tableswitch_truncated_in_jumps() {
    let mut buf = vec![0xaa, 0, 0, 0];
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf.extend_from_slice(&5i32.to_be_bytes()); // 6 entries needed
    // only one jump provided
    buf.extend_from_slice(&10i32.to_be_bytes());
    assert!(matches!(JvmInstr::decode_at(&buf, 0), Err(JvmDecodeError::Truncated)));
}

#[test]
fn decode_lookupswitch_aligned_pc0() {
    let mut buf = vec![0xab, 0, 0, 0];
    buf.extend_from_slice(&0i32.to_be_bytes()); // default
    buf.extend_from_slice(&2i32.to_be_bytes()); // npairs
    // 2 pairs (8 bytes each)
    buf.extend_from_slice(&1i32.to_be_bytes());
    buf.extend_from_slice(&100i32.to_be_bytes());
    buf.extend_from_slice(&2i32.to_be_bytes());
    buf.extend_from_slice(&200i32.to_be_bytes());
    let (i, sz) = JvmInstr::decode_at(&buf, 0).unwrap();
    assert_eq!(i.mnemonic, "lookupswitch");
    assert!(i.operands.contains("npairs=2"));
    assert_eq!(sz, buf.len());
}

#[test]
fn decode_lookupswitch_truncated() {
    let buf = vec![0xab, 0, 0, 0]; // no default/npairs
    assert!(matches!(JvmInstr::decode_at(&buf, 0), Err(JvmDecodeError::Truncated)));
}

#[test]
fn decode_tableswitch_padding_varies_with_pc() {
    // pc=3: padding = (4 - (3+1)%4)%4 = 0
    let mut buf = Vec::new();
    buf.push(0xaa);
    buf.extend_from_slice(&0i32.to_be_bytes()); // default
    buf.extend_from_slice(&0i32.to_be_bytes()); // low
    buf.extend_from_slice(&0i32.to_be_bytes()); // high (=low → 1 entry)
    buf.extend_from_slice(&0i32.to_be_bytes());
    let (i, sz) = JvmInstr::decode_at(&buf, 3).unwrap();
    assert_eq!(i.mnemonic, "tableswitch");
    // 1 (op) + 0 pad + 12 (default/low/high) + 4 (one jump) = 17
    assert_eq!(sz, 17);
}

// ---------------------------------------------------------------------------
// Architecture trait
// ---------------------------------------------------------------------------

#[test]
fn arch_name_endian_ptr() {
    let a = arch();
    assert_eq!(a.name(), "jvm");
    assert_eq!(a.endian(), Endian::Big);
    assert_eq!(a.pointer_size(), 4);
}

#[test]
fn arch_registers_returns_local0_through_3() {
    let regs = arch().registers();
    assert_eq!(regs.len(), 4);
    assert_eq!(regs[0].name, "local0");
    assert_eq!(regs[3].name, "local3");
}

#[test]
fn arch_calling_conventions_one_and_callee_cleans() {
    let cc = arch().calling_conventions();
    assert_eq!(cc.len(), 1);
    assert_eq!(cc[0].name, "jvm_invoke");
    assert!(!cc[0].caller_cleans_stack);
}

#[test]
fn arch_disassemble_basic() {
    let i = arch().disassemble(Address::new(0), &[0x00]).unwrap();
    assert_eq!(i.mnemonic, "nop");
    assert_eq!(i.size, 1);
}

#[test]
fn arch_disassemble_empty_errors() {
    assert!(arch().disassemble(Address::new(0), &[]).is_err());
}

#[test]
fn arch_disassemble_reserved_errors() {
    assert!(arch().disassemble(Address::new(0), &[0xff]).is_err());
}

#[test]
fn arch_get_branches_for_goto() {
    // goto -3: pc=10, target = 10 + (-3) = 7
    let i = arch()
        .disassemble(Address::new(10), &[0xa7, 0xff, 0xfd])
        .unwrap();
    let br = arch().get_branches(&i);
    assert_eq!(br.len(), 1);
    assert_eq!(br[0].target, Some(7));
}

#[test]
fn arch_get_branches_for_goto_w() {
    let mut bytes = vec![0xc8];
    bytes.extend_from_slice(&(-5i32).to_be_bytes());
    let i = arch().disassemble(Address::new(100), &bytes).unwrap();
    let br = arch().get_branches(&i);
    assert_eq!(br.len(), 1);
    assert_eq!(br[0].target, Some(95));
}

#[test]
fn arch_get_branches_for_tableswitch_is_empty() {
    let mut buf = vec![0xaa, 0, 0, 0];
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes());
    let i = arch().disassemble(Address::new(0), &buf).unwrap();
    assert_eq!(arch().get_branches(&i).len(), 0);
}

#[test]
fn arch_get_branches_for_nonbranch_is_empty() {
    let i = arch().disassemble(Address::new(0), &[0x00]).unwrap();
    assert!(arch().get_branches(&i).is_empty());
}

#[test]
fn arch_get_branches_conditional_for_ifeq() {
    let i = arch()
        .disassemble(Address::new(50), &[0x99, 0x00, 0x05])
        .unwrap();
    let br = arch().get_branches(&i);
    assert_eq!(br.len(), 1);
    assert_eq!(br[0].target, Some(55));
}

// ---------------------------------------------------------------------------
// Linear disassembler
// ---------------------------------------------------------------------------

#[test]
fn linear_disasm_walks_three_nops() {
    let a = arch();
    let dis = JvmLinearDisassembler::new(&a, &[0x00, 0x00, 0x00], Address::new(0));
    let res: Vec<_> = dis.collect();
    assert_eq!(res.len(), 3);
    for r in res {
        assert_eq!(r.unwrap().mnemonic, "nop");
    }
}

#[test]
fn linear_disasm_mixes_sizes() {
    // nop (1) + bipush 5 (2) + ireturn (1) = 4 bytes
    let bytes = [0x00, 0x10, 0x05, 0xac];
    let a = arch();
    let dis = JvmLinearDisassembler::new(&a, &bytes, Address::new(0));
    let res: Vec<_> = dis.map(|r| r.unwrap()).collect();
    assert_eq!(res.len(), 3);
    assert_eq!(res[0].mnemonic, "nop");
    assert_eq!(res[1].mnemonic, "bipush");
    assert_eq!(res[2].mnemonic, "ireturn");
    assert_eq!(res[2].address.as_u64(), 3);
}

#[test]
fn linear_disasm_recovers_after_error_advancing_one() {
    let bytes = [0xff, 0x00]; // reserved, then nop
    let a = arch();
    let dis = JvmLinearDisassembler::new(&a, &bytes, Address::new(0));
    let res: Vec<_> = dis.collect();
    assert_eq!(res.len(), 2);
    assert!(res[0].is_err());
    assert_eq!(res[1].as_ref().unwrap().mnemonic, "nop");
}

#[test]
fn linear_disasm_empty_yields_nothing() {
    let a = arch();
    let mut dis = JvmLinearDisassembler::new(&a, &[], Address::new(0));
    assert!(dis.next().is_none());
}

// ---------------------------------------------------------------------------
// JvmInstr equality & clone
// ---------------------------------------------------------------------------

#[test]
fn jvminstr_clone_eq() {
    let (i, _) = JvmInstr::decode(&[0x10, 0x05]).unwrap();
    let j = i.clone();
    assert_eq!(i, j);
}

#[test]
fn jvm_decode_error_display() {
    let e = JvmDecodeError::Reserved(0xff);
    assert!(format!("{}", e).contains("0xff"));
    let e2 = JvmDecodeError::UnknownOpcode(0x01);
    assert!(format!("{}", e2).contains("0x01"));
    let e3 = JvmDecodeError::Truncated;
    assert!(format!("{}", e3).to_lowercase().contains("truncated"));
}

// ---------------------------------------------------------------------------
// Constant pool — happy paths
// ---------------------------------------------------------------------------

fn utf8_entry(s: &str) -> Vec<u8> {
    let mut v = vec![1u8];
    v.extend_from_slice(&(s.len() as u16).to_be_bytes());
    v.extend_from_slice(s.as_bytes());
    v
}

#[test]
fn cp_parse_two_utf8() {
    let mut bytes = utf8_entry("Hello");
    bytes.extend(utf8_entry("World"));
    let (cp, consumed) = JvmConstantPool::parse(&bytes, 3).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(cp.resolve_utf8(1).unwrap(), "Hello");
    assert_eq!(cp.resolve_utf8(2).unwrap(), "World");
    assert_eq!(cp.len(), 3);
}

#[test]
fn cp_parse_integer() {
    let mut v = vec![3u8];
    v.extend_from_slice(&(-42i32).to_be_bytes());
    let (cp, _) = JvmConstantPool::parse(&v, 2).unwrap();
    assert_eq!(cp.get(1), Some(&ConstantEntry::Integer(-42)));
}

#[test]
fn cp_parse_float() {
    let val: f32 = 3.5;
    let mut v = vec![4u8];
    v.extend_from_slice(&val.to_bits().to_be_bytes());
    let (cp, _) = JvmConstantPool::parse(&v, 2).unwrap();
    match cp.get(1).unwrap() {
        ConstantEntry::Float(f) => assert!((*f - 3.5).abs() < f32::EPSILON),
        e => panic!("expected Float, got {:?}", e),
    }
}

#[test]
fn cp_parse_long_takes_two_slots() {
    let mut v = vec![5u8];
    v.extend_from_slice(&12345i64.to_be_bytes());
    let (cp, _) = JvmConstantPool::parse(&v, 3).unwrap();
    assert_eq!(cp.get(1), Some(&ConstantEntry::Long(12345)));
    assert_eq!(cp.get(2), Some(&ConstantEntry::Unusable));
}

#[test]
fn cp_parse_double_takes_two_slots() {
    let val: f64 = 2.5;
    let mut v = vec![6u8];
    v.extend_from_slice(&val.to_bits().to_be_bytes());
    let (cp, _) = JvmConstantPool::parse(&v, 3).unwrap();
    match cp.get(1).unwrap() {
        ConstantEntry::Double(d) => assert!((*d - 2.5).abs() < f64::EPSILON),
        e => panic!("got {:?}", e),
    }
    assert_eq!(cp.get(2), Some(&ConstantEntry::Unusable));
}

#[test]
fn cp_parse_class_resolves_name() {
    let mut v = vec![7u8];
    v.extend_from_slice(&2u16.to_be_bytes());
    v.extend(utf8_entry("java/lang/Object"));
    let (mut cp, _) = JvmConstantPool::parse(&v, 3).unwrap();
    assert_eq!(cp.resolve_class(1).unwrap(), "java/lang/Object");
    // Second call hits cache.
    assert_eq!(cp.resolve_class(1).unwrap(), "java/lang/Object");
}

#[test]
fn cp_parse_name_and_type_resolves() {
    // cp#1 = NameAndType(#2, #3), cp#2 = "name", cp#3 = "I"
    let mut v = vec![12u8];
    v.extend_from_slice(&2u16.to_be_bytes());
    v.extend_from_slice(&3u16.to_be_bytes());
    v.extend(utf8_entry("name"));
    v.extend(utf8_entry("I"));
    let (cp, _) = JvmConstantPool::parse(&v, 4).unwrap();
    let (n, d) = cp.resolve_name_and_type(1).unwrap();
    assert_eq!(n, "name");
    assert_eq!(d, "I");
}

#[test]
fn cp_parse_method_handle() {
    let mut v = vec![15u8, 6, 0x12, 0x34];
    let _ = &mut v;
    let (cp, _) = JvmConstantPool::parse(&v, 2).unwrap();
    assert_eq!(cp.get(1), Some(&ConstantEntry::MethodHandle(6, 0x1234)));
}

#[test]
fn cp_parse_unknown_tag_errors() {
    let v = vec![99u8];
    let r = JvmConstantPool::parse(&v, 2);
    assert!(matches!(r, Err(CpParseError::UnknownTag { tag: 99, index: 1 })));
}

#[test]
fn cp_parse_truncated_utf8_length() {
    let v = vec![1u8, 0x00]; // tag + 1 byte of 2-byte length
    let r = JvmConstantPool::parse(&v, 2);
    assert!(matches!(r, Err(CpParseError::Truncated { .. })));
}

#[test]
fn cp_parse_truncated_utf8_body() {
    let mut v = vec![1u8];
    v.extend_from_slice(&10u16.to_be_bytes()); // claims 10 bytes
    v.extend_from_slice(b"abc"); // only 3 provided
    let r = JvmConstantPool::parse(&v, 2);
    assert!(matches!(r, Err(CpParseError::Truncated { .. })));
}

#[test]
fn cp_parse_invalid_utf8() {
    let mut v = vec![1u8];
    v.extend_from_slice(&2u16.to_be_bytes());
    v.extend_from_slice(&[0xff, 0xfe]); // not valid UTF-8
    let r = JvmConstantPool::parse(&v, 2);
    assert!(matches!(r, Err(CpParseError::InvalidUtf8 { index: 1 })));
}

#[test]
fn cp_parse_count_zero_returns_empty_pool() {
    let (cp, consumed) = JvmConstantPool::parse(&[], 0).unwrap();
    assert_eq!(consumed, 0);
    assert!(cp.is_empty());
    assert_eq!(cp.len(), 1); // index-0 placeholder
}

#[test]
fn cp_parse_count_one_means_no_entries() {
    let (cp, consumed) = JvmConstantPool::parse(&[], 1).unwrap();
    assert_eq!(consumed, 0);
    assert!(cp.is_empty());
}

#[test]
fn cp_resolve_utf8_zero_index_errors() {
    let bytes = utf8_entry("x");
    let (cp, _) = JvmConstantPool::parse(&bytes, 2).unwrap();
    assert_eq!(cp.resolve_utf8(0), Err(CpParseError::ZeroIndex));
}

#[test]
fn cp_resolve_utf8_out_of_range_errors() {
    let bytes = utf8_entry("x");
    let (cp, _) = JvmConstantPool::parse(&bytes, 2).unwrap();
    assert!(matches!(
        cp.resolve_utf8(99),
        Err(CpParseError::InvalidIndex { .. })
    ));
}

#[test]
fn cp_resolve_utf8_wrong_kind_errors() {
    let mut v = vec![3u8];
    v.extend_from_slice(&1i32.to_be_bytes());
    let (cp, _) = JvmConstantPool::parse(&v, 2).unwrap();
    assert!(matches!(
        cp.resolve_utf8(1),
        Err(CpParseError::InvalidIndex { .. })
    ));
}

#[test]
fn cp_resolve_class_wrong_kind_errors() {
    let bytes = utf8_entry("x");
    let (mut cp, _) = JvmConstantPool::parse(&bytes, 2).unwrap();
    assert!(matches!(
        cp.resolve_class(1),
        Err(CpParseError::InvalidIndex { .. })
    ));
}

#[test]
fn cp_all_utf8_returns_only_utf8() {
    let mut bytes = utf8_entry("a");
    bytes.push(3u8);
    bytes.extend_from_slice(&7i32.to_be_bytes());
    bytes.extend(utf8_entry("b"));
    let (cp, _) = JvmConstantPool::parse(&bytes, 4).unwrap();
    let all = cp.all_utf8();
    assert_eq!(all.len(), 2);
    assert!(all.iter().any(|(_, s)| *s == "a"));
    assert!(all.iter().any(|(_, s)| *s == "b"));
}

#[test]
fn cp_tag_counts() {
    let mut bytes = utf8_entry("a");
    bytes.extend(utf8_entry("b"));
    let (cp, _) = JvmConstantPool::parse(&bytes, 3).unwrap();
    let counts = cp.tag_counts();
    assert_eq!(counts.get("Utf8").copied().unwrap_or(0), 2);
}

#[test]
fn constant_tag_from_u8_round_trip() {
    for v in [1u8, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15, 16, 17, 18, 19, 20] {
        let t = ConstantTag::from_u8(v).unwrap_or_else(|| panic!("tag {} should map", v));
        assert_eq!(t as u8, v);
    }
}

#[test]
fn constant_tag_from_u8_invalid_returns_none() {
    assert_eq!(ConstantTag::from_u8(0), None);
    assert_eq!(ConstantTag::from_u8(2), None);
    assert_eq!(ConstantTag::from_u8(13), None);
    assert_eq!(ConstantTag::from_u8(14), None);
    assert_eq!(ConstantTag::from_u8(255), None);
}

#[test]
fn constant_tag_is_wide() {
    assert!(ConstantTag::Long.is_wide());
    assert!(ConstantTag::Double.is_wide());
    assert!(!ConstantTag::Integer.is_wide());
    assert!(!ConstantTag::Utf8.is_wide());
}

#[test]
fn constant_tag_display_matches_name() {
    assert_eq!(ConstantTag::Utf8.to_string(), "Utf8");
    assert_eq!(ConstantTag::InterfaceMethodref.to_string(), "InterfaceMethodref");
}

#[test]
fn constant_entry_tag_for_unusable_is_none() {
    assert_eq!(ConstantEntry::Unusable.tag(), None);
}

#[test]
fn constant_entry_tag_for_various() {
    assert_eq!(ConstantEntry::Integer(0).tag(), Some(ConstantTag::Integer));
    assert_eq!(ConstantEntry::Long(0).tag(), Some(ConstantTag::Long));
    assert_eq!(ConstantEntry::Class(0).tag(), Some(ConstantTag::Class));
    assert_eq!(
        ConstantEntry::NameAndType(0, 0).tag(),
        Some(ConstantTag::NameAndType)
    );
}

#[test]
fn constant_entry_display() {
    let s = format!("{}", ConstantEntry::Integer(5));
    assert!(s.contains('5'));
    let s2 = format!("{}", ConstantEntry::Utf8("hi".into()));
    assert!(s2.contains("hi"));
    let s3 = format!("{}", ConstantEntry::Unusable);
    assert!(s3.contains("unusable"));
}

#[test]
fn cp_parse_error_display() {
    assert!(format!("{}", CpParseError::ZeroIndex).contains("reserved"));
    assert!(format!("{}", CpParseError::Truncated { at: 7 }).contains('7'));
    let s = format!("{}", CpParseError::UnknownTag { tag: 99, index: 4 });
    // Display uses hex for the tag (0x63 == 99) and decimal for the index.
    assert!(s.contains("63") && s.contains('4'), "got {}", s);
}

#[test]
fn cp_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<JvmConstantPool>();
    assert_send_sync::<ConstantEntry>();
    assert_send_sync::<ConstantTag>();
    assert_send_sync::<CpParseError>();
    assert_send_sync::<JvmDecodeError>();
}

// ---------------------------------------------------------------------------
// Decoder fuzz-ish: every defined opcode should decode given enough bytes,
// every reserved one should fail with Reserved.
// ---------------------------------------------------------------------------

#[test]
fn decoder_classifies_every_byte() {
    // Buffer big enough for the longest fixed-size instruction (multianewarray = 4,
    // invokeinterface/invokedynamic/goto_w/jsr_w = 5, wide_iinc = 6).
    // tableswitch/lookupswitch (0xaa/0xab) are variable; we don't fuzz those here.
    let pad: Vec<u8> = vec![0; 32];
    for op in 0..=0xff_u16 {
        let op = op as u8;
        if op == 0xaa || op == 0xab {
            continue; // exercised elsewhere
        }
        let mut bytes = vec![op];
        bytes.extend_from_slice(&pad);
        // Wide prefix needs a sub-opcode in [1] that's valid; supply 0x15 (iload).
        if op == 0xc4 {
            bytes[1] = 0x15;
        }
        let r = JvmInstr::decode(&bytes);
        match op {
            0xca..=0xff => assert!(
                matches!(r, Err(JvmDecodeError::Reserved(b)) if b == op),
                "op {:#x}",
                op
            ),
            _ => assert!(r.is_ok(), "op {:#x} should decode: {:?}", op, r),
        }
    }
}
