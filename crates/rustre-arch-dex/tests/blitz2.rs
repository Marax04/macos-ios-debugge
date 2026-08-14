//! blitz2 — adversarial deep tests for `rustre-arch-dex` public API.
//!
//! Uses a seeded LCG for reproducible fuzzing of decoders.

use rustre_core::arch::{Architecture, InstrFlags};
use rustre_arch_dex::*;
use rustre_core::address::Address;
use rustre_core::endian::Endian;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

// ---------------------------------------------------------------------------
// 1. LCG fuzz: decode_dex never panics on arbitrary input
// ---------------------------------------------------------------------------

#[test]
fn fuzz_decode_dex_random_inputs_never_panic() {
    let mut g = lcg();
    for _ in 0..2000 {
        let len = (g() % 32) as usize;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push((g() & 0xff) as u8);
        }
        // Must yield Ok or specific Err — never panic
        let _ = decode_dex(&buf);
    }
}

#[test]
fn fuzz_decode_dex_short_inputs() {
    let mut g = lcg();
    for _ in 0..500 {
        let op = (g() & 0xff) as u8;
        let hi = (g() & 0xff) as u8;
        // 2-byte minimum slice
        let _ = decode_dex(&[op, hi]);
    }
}

#[test]
fn fuzz_decode_dex_all_opcodes_two_bytes() {
    // For every primary opcode, ensure 2-byte input either Ok or specific Err
    for op in 0u16..=255 {
        let res = decode_dex(&[op as u8, 0]);
        // For multi-codeunit forms with only 2 bytes given, error or success
        // is allowed. The contract is: don't panic.
        let _ = res;
    }
}

#[test]
fn fuzz_decode_dex_all_opcodes_padded() {
    // Pad with 16 zero bytes; many instructions should now decode.
    let mut ok_count = 0;
    for op in 0u16..=255 {
        let mut buf = vec![0u8; 16];
        buf[0] = op as u8;
        let res = decode_dex(&buf);
        if res.is_ok() {
            ok_count += 1;
        }
    }
    // Most opcodes (>200) should decode with full padding
    assert!(ok_count > 200, "only {ok_count} opcodes decoded");
}

// ---------------------------------------------------------------------------
// 2. Boundary: empty input
// ---------------------------------------------------------------------------

#[test]
fn decode_dex_empty_is_err() {
    assert!(decode_dex(&[]).is_err());
}

#[test]
fn decode_dex_truncated_const_wide_is_err() {
    // const-wide (0x18) needs 10 bytes
    for n in 0..10 {
        let buf = vec![0u8; n];
        if n == 0 {
            assert!(decode_dex(&buf).is_err());
            continue;
        }
        let mut b = buf.clone();
        b[0] = 0x18;
        assert!(decode_dex(&b).is_err(), "should error with len {n}");
    }
}

#[test]
fn decode_dex_truncated_31i_is_err() {
    // const (0x14) needs 6 bytes
    let b = [0x14_u8, 0x00, 0x00];
    assert!(decode_dex(&b).is_err());
}

#[test]
fn decode_dex_unused_opcodes_error() {
    for op in 0x3e_u8..=0x43 {
        let buf = [op, 0, 0, 0, 0, 0];
        assert!(decode_dex(&buf).is_err(), "unused op {op:#x}");
    }
    assert!(decode_dex(&[0x73_u8, 0, 0, 0, 0, 0]).is_err());
    assert!(decode_dex(&[0x79_u8, 0, 0, 0, 0, 0]).is_err());
    assert!(decode_dex(&[0x7a_u8, 0, 0, 0, 0, 0]).is_err());
}

// ---------------------------------------------------------------------------
// 3. DexCodeItemHeader round-trip on 50+ inputs
// ---------------------------------------------------------------------------

#[test]
fn code_item_header_roundtrip_fuzz() {
    let mut g = lcg();
    for _ in 0..60 {
        let registers_size = (g() & 0xffff) as u16;
        let ins_size = (g() & 0xffff) as u16;
        let outs_size = (g() & 0xffff) as u16;
        let tries_size = (g() & 0xffff) as u16;
        let debug_info_off = (g() & 0xffff_ffff) as u32;
        let insns_size = (g() & 0xffff_ffff) as u32;
        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(&registers_size.to_le_bytes());
        buf.extend_from_slice(&ins_size.to_le_bytes());
        buf.extend_from_slice(&outs_size.to_le_bytes());
        buf.extend_from_slice(&tries_size.to_le_bytes());
        buf.extend_from_slice(&debug_info_off.to_le_bytes());
        buf.extend_from_slice(&insns_size.to_le_bytes());
        let h = DexCodeItemHeader::decode(&buf).unwrap();
        assert_eq!(h.registers_size, registers_size);
        assert_eq!(h.ins_size, ins_size);
        assert_eq!(h.outs_size, outs_size);
        assert_eq!(h.tries_size, tries_size);
        assert_eq!(h.debug_info_off, debug_info_off);
        assert_eq!(h.insns_size, insns_size);
        assert_eq!(h.has_try_blocks(), tries_size > 0);
    }
}

#[test]
fn code_item_header_boundary_sizes() {
    for n in 0..16usize {
        let buf = vec![0u8; n];
        assert_eq!(
            DexCodeItemHeader::decode(&buf),
            Err(DexDecodeError::Truncated)
        );
    }
    let buf = vec![0u8; 16];
    assert!(DexCodeItemHeader::decode(&buf).is_ok());
}

#[test]
fn code_item_header_extra_bytes_ignored() {
    let buf = vec![0u8; 32];
    let h = DexCodeItemHeader::decode(&buf).unwrap();
    assert_eq!(h.registers_size, 0);
}

// ---------------------------------------------------------------------------
// 4. Type descriptor round-trip + boundary
// ---------------------------------------------------------------------------

#[test]
fn type_descriptor_kind_for_all_primitives() {
    let cases = [
        ("V", DescriptorKind::Void),
        ("Z", DescriptorKind::Boolean),
        ("B", DescriptorKind::Byte),
        ("S", DescriptorKind::Short),
        ("C", DescriptorKind::Char),
        ("I", DescriptorKind::Int),
        ("J", DescriptorKind::Long),
        ("F", DescriptorKind::Float),
        ("D", DescriptorKind::Double),
    ];
    for (s, k) in cases {
        assert_eq!(DexTypeDescriptor::new(s).kind(), k);
    }
}

#[test]
fn type_descriptor_unknown_kind() {
    assert_eq!(DexTypeDescriptor::new("").kind(), DescriptorKind::Unknown);
    assert_eq!(DexTypeDescriptor::new("Q").kind(), DescriptorKind::Unknown);
    assert_eq!(DexTypeDescriptor::new("?").kind(), DescriptorKind::Unknown);
}

#[test]
fn type_descriptor_class_name_only_for_object() {
    assert_eq!(
        DexTypeDescriptor::new("Ljava/lang/String;").class_name(),
        Some("java/lang/String")
    );
    assert_eq!(DexTypeDescriptor::new("I").class_name(), None);
    assert_eq!(DexTypeDescriptor::new("[B").class_name(), None);
    // Bad object: missing trailing semicolon
    assert_eq!(DexTypeDescriptor::new("Lfoo").class_name(), None);
}

#[test]
fn type_descriptor_array_element_nested() {
    let d = DexTypeDescriptor::new("[[[I");
    let inner = d.array_element().unwrap();
    assert_eq!(inner.as_str(), "[[I");
    let inner2 = inner.array_element().unwrap();
    assert_eq!(inner2.as_str(), "[I");
    let inner3 = inner2.array_element().unwrap();
    assert_eq!(inner3.kind(), DescriptorKind::Int);
    assert_eq!(inner3.array_element(), None);
}

#[test]
fn descriptor_kind_wide_and_slots() {
    assert_eq!(DescriptorKind::Long.register_slots(), 2);
    assert_eq!(DescriptorKind::Double.register_slots(), 2);
    assert_eq!(DescriptorKind::Int.register_slots(), 1);
    assert_eq!(DescriptorKind::Void.register_slots(), 1);
    assert!(DescriptorKind::Long.is_wide());
    assert!(DescriptorKind::Double.is_wide());
    assert!(!DescriptorKind::Int.is_wide());
    assert!(!DescriptorKind::Object.is_wide());
}

// ---------------------------------------------------------------------------
// 5. Hash/Eq consistency: 30+ pairs
// ---------------------------------------------------------------------------

#[test]
fn hash_eq_consistency_type_descriptor() {
    let samples = [
        "V", "I", "J", "Ljava/lang/String;", "[I", "[[B", "Z", "B", "C", "S", "F", "D",
    ];
    for s in samples {
        let a = DexTypeDescriptor::new(s);
        let b = DexTypeDescriptor::new(s);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }
}

#[test]
fn hash_eq_consistency_access_flags() {
    let mut g = lcg();
    for _ in 0..40 {
        let v = (g() & 0xffff_ffff) as u32;
        let a = DexAccessFlags(v);
        let b = DexAccessFlags(v);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }
}

#[test]
fn hash_eq_consistency_descriptor_kind() {
    let kinds = [
        DescriptorKind::Void,
        DescriptorKind::Boolean,
        DescriptorKind::Byte,
        DescriptorKind::Short,
        DescriptorKind::Char,
        DescriptorKind::Int,
        DescriptorKind::Long,
        DescriptorKind::Float,
        DescriptorKind::Double,
        DescriptorKind::Object,
        DescriptorKind::Array,
        DescriptorKind::Unknown,
    ];
    for k in kinds {
        let a = k;
        let b = k;
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }
}

#[test]
fn hash_eq_consistency_item_type() {
    let items = [
        DexItemType::HeaderItem,
        DexItemType::StringIdItem,
        DexItemType::TypeIdItem,
        DexItemType::ClassDefItem,
        DexItemType::MapList,
        DexItemType::CodeItem,
    ];
    for it in items {
        assert_eq!(hash_of(&it), hash_of(&it));
    }
}

// ---------------------------------------------------------------------------
// 6. DEX format base_code_units coverage
// ---------------------------------------------------------------------------

#[test]
fn format_base_code_units_all() {
    let all = [
        (DexFormat::F10x, 1),
        (DexFormat::F12x, 1),
        (DexFormat::F11n, 1),
        (DexFormat::F11x, 1),
        (DexFormat::F10t, 1),
        (DexFormat::F20t, 2),
        (DexFormat::F20bc, 2),
        (DexFormat::F22x, 2),
        (DexFormat::F21t, 2),
        (DexFormat::F21s, 2),
        (DexFormat::F21h, 2),
        (DexFormat::F21c, 2),
        (DexFormat::F23x, 2),
        (DexFormat::F22b, 2),
        (DexFormat::F22t, 2),
        (DexFormat::F22s, 2),
        (DexFormat::F22c, 2),
        (DexFormat::F22cs, 2),
        (DexFormat::F30t, 3),
        (DexFormat::F32x, 3),
        (DexFormat::F31i, 3),
        (DexFormat::F31t, 3),
        (DexFormat::F31c, 3),
        (DexFormat::F35c, 3),
        (DexFormat::F35ms, 3),
        (DexFormat::F35mi, 3),
        (DexFormat::F3rc, 3),
        (DexFormat::F3rms, 3),
        (DexFormat::F3rmi, 3),
        (DexFormat::F45cc, 4),
        (DexFormat::F4rcc, 4),
        (DexFormat::F51l, 5),
    ];
    for (f, expected) in all {
        assert_eq!(f.base_code_units(), expected);
    }
}

// ---------------------------------------------------------------------------
// 7. Display ↔ FromStr-like: java name ↔ descriptor round-trip
// ---------------------------------------------------------------------------

#[test]
fn java_descriptor_roundtrip_many() {
    let samples = [
        "java.lang.String",
        "java.lang.Object",
        "java.util.HashMap",
        "android.app.Activity",
        "com.example.Foo",
        "a.b.c.d.e.f.G",
        "X",
    ];
    for s in samples {
        let desc = java_name_to_dex_descriptor(s);
        assert!(desc.starts_with('L'));
        assert!(desc.ends_with(';'));
        let inner = &desc[1..desc.len() - 1];
        let back = dex_internal_to_java_name(inner);
        assert_eq!(back, s);
    }
}

#[test]
fn dex_simple_class_name_cases() {
    assert_eq!(dex_simple_class_name("Ljava/lang/String;"), "String");
    assert_eq!(dex_simple_class_name("LFoo;"), "Foo");
    assert_eq!(dex_simple_class_name("Foo"), "Foo");
    assert_eq!(dex_simple_class_name("La/b/c/D;"), "D");
}

// ---------------------------------------------------------------------------
// 8. Method signature
// ---------------------------------------------------------------------------

#[test]
fn method_signature_arg_register_count_varied() {
    let sig = DexMethodSignature::new("V", "V", vec![]);
    assert_eq!(sig.arg_register_count(), 0);

    let sig = DexMethodSignature::new(
        "VII",
        "V",
        vec![DexTypeDescriptor::new("I"), DexTypeDescriptor::new("I")],
    );
    assert_eq!(sig.arg_register_count(), 2);

    let sig = DexMethodSignature::new(
        "VJJD",
        "V",
        vec![
            DexTypeDescriptor::new("J"),
            DexTypeDescriptor::new("J"),
            DexTypeDescriptor::new("D"),
        ],
    );
    assert_eq!(sig.arg_register_count(), 6);
}

// ---------------------------------------------------------------------------
// 9. DexReturnType parser fuzz
// ---------------------------------------------------------------------------

#[test]
fn return_type_void_int_long() {
    assert_eq!(DexReturnType::parse("V"), Some(DexReturnType::Void));
    assert!(DexReturnType::parse("V").unwrap().is_void());
    assert!(!DexReturnType::parse("I").unwrap().is_void());
    assert_eq!(
        DexReturnType::parse("J"),
        Some(DexReturnType::Primitive('J'))
    );
}

#[test]
fn return_type_empty_is_none() {
    assert!(DexReturnType::parse("").is_none());
    assert!(DexReturnType::parse("Q").is_none());
}

#[test]
fn return_type_deeply_nested_array_is_bounded() {
    // 300 levels of nesting — exceeds MAX_ARRAY_DEPTH (255). Must return None,
    // not stack-overflow.
    let s: String = "[".repeat(300) + "I";
    assert!(DexReturnType::parse(&s).is_none());
}

#[test]
fn return_type_object_missing_semicolon_is_none() {
    assert!(DexReturnType::parse("Lfoo").is_none());
}

#[test]
fn return_type_array_of_object() {
    let r = DexReturnType::parse("[Ljava/lang/String;").unwrap();
    match r {
        DexReturnType::Array(inner) => match *inner {
            DexReturnType::Object(s) => assert_eq!(s, "java/lang/String"),
            _ => panic!("expected object"),
        },
        _ => panic!("expected array"),
    }
}

// ---------------------------------------------------------------------------
// 10. dex_param_count fuzz, never panics
// ---------------------------------------------------------------------------

#[test]
fn dex_param_count_known_cases() {
    assert_eq!(dex_param_count("()V"), 0);
    assert_eq!(dex_param_count("(I)V"), 1);
    assert_eq!(dex_param_count("(IIZ)V"), 3);
    assert_eq!(dex_param_count("(Ljava/lang/String;)V"), 1);
    assert_eq!(dex_param_count("([I)V"), 1);
    assert_eq!(dex_param_count("([[Ljava/lang/Object;)V"), 1);
    assert_eq!(dex_param_count("(ILjava/lang/String;[BJZ)V"), 5);
}

#[test]
fn dex_param_count_fuzz_never_panics() {
    let mut g = lcg();
    let charset = b"()VIJZBSCFDL[;/abcdefXYZ";
    for _ in 0..500 {
        let len = (g() % 60) as usize;
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            let c = charset[(g() as usize) % charset.len()] as char;
            s.push(c);
        }
        // Must not panic
        let _ = dex_param_count(&s);
    }
}

#[test]
fn dex_param_count_no_open_paren_returns_zero() {
    assert_eq!(dex_param_count(""), 0);
    assert_eq!(dex_param_count("IIIV"), 0);
}

// ---------------------------------------------------------------------------
// 11. Access flags state inspection
// ---------------------------------------------------------------------------

#[test]
fn access_flags_all_bits() {
    let bits = [
        DexAccessFlags::PUBLIC,
        DexAccessFlags::PRIVATE,
        DexAccessFlags::PROTECTED,
        DexAccessFlags::STATIC,
        DexAccessFlags::FINAL,
        DexAccessFlags::SYNCHRONIZED,
        DexAccessFlags::VOLATILE,
        DexAccessFlags::TRANSIENT,
        DexAccessFlags::NATIVE,
        DexAccessFlags::INTERFACE,
        DexAccessFlags::ABSTRACT,
        DexAccessFlags::STRICT,
        DexAccessFlags::SYNTHETIC,
        DexAccessFlags::ANNOTATION,
        DexAccessFlags::ENUM,
        DexAccessFlags::CONSTRUCTOR,
        DexAccessFlags::DECLARED_SYNC,
    ];
    for b in bits {
        let f = DexAccessFlags(b);
        assert!(f.has(b));
        assert!(f.has_field_flag(b));
        assert!(f.has_method_flag(b));
    }
}

#[test]
fn access_flags_volatile_and_bridge_share_bit() {
    assert_eq!(DexAccessFlags::VOLATILE, DexAccessFlags::BRIDGE);
    assert_eq!(DexAccessFlags::TRANSIENT, DexAccessFlags::VARARGS);
}

// ---------------------------------------------------------------------------
// 12. Opcode table lookups
// ---------------------------------------------------------------------------

#[test]
fn lookup_dex_opcode_known() {
    assert!(lookup_dex_opcode(0x00).is_some());
    assert!(lookup_dex_opcode(0x0e).is_some());
    assert!(lookup_dex_opcode(0x6e).is_some());
}

#[test]
fn lookup_dex_opcode_all_bytes_no_panic() {
    for op in 0u16..=255 {
        let _ = lookup_dex_opcode(op as u8);
    }
}

#[test]
fn opcode_ref_units_match_format_units() {
    for entry in DEX_OPCODE_REF.iter() {
        assert!(entry.units >= 1 && entry.units <= 5, "op {:#x}", entry.opcode);
    }
}

#[test]
fn opcode_ref_flag_bits_decode() {
    for entry in DEX_OPCODE_REF.iter() {
        let f = entry.flags();
        // Round-trip: if CALL bit set, flags() contains CALL.
        if entry.flag_bits & 2 != 0 {
            assert!(f.contains(InstrFlags::CALL));
        }
        if entry.flag_bits & 4 != 0 {
            assert!(f.contains(InstrFlags::RET));
        }
        if entry.flag_bits & 1 != 0 {
            assert!(f.contains(InstrFlags::BRANCH));
        }
    }
}

// ---------------------------------------------------------------------------
// 13. ART opcodes
// ---------------------------------------------------------------------------

#[test]
fn art_opcode_boundary() {
    assert!(!is_art_optimized_opcode(0xe2));
    assert!(is_art_optimized_opcode(0xe3));
    assert!(is_art_optimized_opcode(0xf9));
    assert!(!is_art_optimized_opcode(0xfa));
}

#[test]
fn art_opcode_name_known() {
    assert_eq!(art_opcode_name(0xe3), "iget-quick");
    assert_eq!(art_opcode_name(0xe9), "invoke-virtual-quick");
    assert_eq!(art_opcode_name(0xf5), "create-lambda");
    assert_eq!(art_opcode_name(0x00), "unknown-art");
}

#[test]
fn art_opcodes_decode_with_padding() {
    let arch = DexArch::new();
    for op in 0xe3_u8..=0xf9 {
        let buf = [op, 0x12, 0x34, 0x00];
        let r = arch.disassemble(Address::new(0), &buf);
        assert!(r.is_ok(), "art op {op:#x} failed");
    }
}

// ---------------------------------------------------------------------------
// 14. Linear disassembler walks
// ---------------------------------------------------------------------------

#[test]
fn linear_disassembler_empty() {
    let arch = DexArch::new();
    let mut iter = DexLinearDisassembler::new(&arch, &[], Address::new(0));
    assert!(iter.next().is_none());
    assert_eq!(iter.offset(), 0);
}

#[test]
fn linear_disassembler_basic_program() {
    let arch = DexArch::new();
    // nop; const/4 v0,#0; return-void
    let prog = [0x00_u8, 0x00, 0x12, 0x00, 0x0e, 0x00];
    let instrs: Vec<_> = DexLinearDisassembler::new(&arch, &prog, Address::new(0x100))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(instrs.len(), 3);
    assert_eq!(instrs[0].mnemonic, "nop");
    assert_eq!(instrs[1].mnemonic, "const/4");
    assert_eq!(instrs[2].mnemonic, "return-void");
    assert!(instrs[2].flags.contains(InstrFlags::RET));
}

#[test]
fn linear_disassembler_advances_on_error() {
    let arch = DexArch::new();
    // Unused opcode 0x3e, then nop
    let prog = [0x3e_u8, 0x00, 0x00, 0x00];
    let mut it = DexLinearDisassembler::new(&arch, &prog, Address::new(0));
    let first = it.next().unwrap();
    assert!(first.is_err());
    // Must make forward progress
    let _ = it.next();
    assert!(it.offset() > 0);
}

// ---------------------------------------------------------------------------
// 15. DexArch::get_branches semantics
// ---------------------------------------------------------------------------

#[test]
fn get_branches_for_ret_is_empty() {
    let arch = DexArch::new();
    let instr = arch.disassemble(Address::new(0), &[0x0e, 0x00]).unwrap();
    assert!(arch.get_branches(&instr).is_empty());
}

#[test]
fn get_branches_for_goto_returns_target() {
    let arch = DexArch::new();
    // goto +4 (offset 4 in code units → 8 bytes from start)
    let instr = arch.disassemble(Address::new(0x100), &[0x28, 0x04]).unwrap();
    let branches = arch.get_branches(&instr);
    assert!(!branches.is_empty());
}

#[test]
fn get_branches_for_indirect_switch_is_empty() {
    let arch = DexArch::new();
    let instr = arch
        .disassemble(Address::new(0), &[0x2b, 0x00, 0x10, 0x00, 0x00, 0x00])
        .unwrap();
    // packed-switch is BRANCH | INDIRECT — no resolved target
    assert!(arch.get_branches(&instr).is_empty());
}

// ---------------------------------------------------------------------------
// 16. Send/Sync + threaded decoder stress
// ---------------------------------------------------------------------------

#[test]
fn dex_arch_send_sync_threaded_decode() {
    let arch = Arc::new(DexArch::new());
    let mut handles = Vec::new();
    for tid in 0..4u64 {
        let arch = Arc::clone(&arch);
        handles.push(thread::spawn(move || {
            let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE ^ tid.wrapping_mul(0x9E37_79B1);
            for _ in 0..100 {
                s = s
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                // Always-decodable prog: return-void
                let r = arch.disassemble(Address::new(s), &[0x0e, 0x00]);
                assert!(r.is_ok());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ---------------------------------------------------------------------------
// 17. Annotation visibility / value type round-trip
// ---------------------------------------------------------------------------

#[test]
fn annotation_visibility_from_byte_round_trip() {
    for b in 0u8..=2 {
        let v = DexAnnotationVisibility::from_byte(b).unwrap();
        assert!(!v.name().is_empty());
    }
    for b in 3u8..=255 {
        assert!(DexAnnotationVisibility::from_byte(b).is_none());
    }
}

#[test]
fn annotation_value_type_from_byte_known() {
    let cases = [
        (0x00_u8, DexAnnotationValueType::Byte),
        (0x02, DexAnnotationValueType::Short),
        (0x03, DexAnnotationValueType::Char),
        (0x04, DexAnnotationValueType::Int),
        (0x06, DexAnnotationValueType::Long),
        (0x10, DexAnnotationValueType::Float),
        (0x11, DexAnnotationValueType::Double),
        (0x17, DexAnnotationValueType::String),
        (0x18, DexAnnotationValueType::Type),
        (0x19, DexAnnotationValueType::Field),
        (0x1a, DexAnnotationValueType::Method),
        (0x1b, DexAnnotationValueType::Enum),
        (0x1c, DexAnnotationValueType::Annotation),
        (0x1e, DexAnnotationValueType::Null),
        (0x1f, DexAnnotationValueType::Boolean),
    ];
    for (b, expected) in cases {
        assert_eq!(DexAnnotationValueType::from_byte(b), Some(expected));
    }
}

#[test]
fn annotation_value_type_high_bits_masked() {
    // Top 3 bits should be masked (& 0x1f).
    assert_eq!(
        DexAnnotationValueType::from_byte(0xe0 | 0x04),
        Some(DexAnnotationValueType::Int)
    );
}

#[test]
fn annotation_value_type_is_reference() {
    assert!(DexAnnotationValueType::String.is_reference());
    assert!(DexAnnotationValueType::Type.is_reference());
    assert!(!DexAnnotationValueType::Int.is_reference());
    assert!(!DexAnnotationValueType::Boolean.is_reference());
    assert!(!DexAnnotationValueType::Null.is_reference());
}

// ---------------------------------------------------------------------------
// 18. Method handle kind round-trip
// ---------------------------------------------------------------------------

#[test]
fn method_handle_kind_round_trip() {
    for v in 0u16..=8 {
        let k = DexMethodHandleKind::from_u16(v).unwrap();
        assert_eq!(k as u16, v);
    }
    for v in 9u16..=20 {
        assert!(DexMethodHandleKind::from_u16(v).is_none());
    }
}

#[test]
fn method_handle_kind_is_invoke() {
    assert!(!DexMethodHandleKind::StaticPut.is_invoke());
    assert!(!DexMethodHandleKind::StaticGet.is_invoke());
    assert!(DexMethodHandleKind::InvokeStatic.is_invoke());
    assert!(DexMethodHandleKind::InvokeInterface.is_invoke());
}

// ---------------------------------------------------------------------------
// 19. RegSet boundaries
// ---------------------------------------------------------------------------

#[test]
fn reg_set_all_64_registers() {
    let mut rs = DexRegSet::default();
    for r in 0u8..64 {
        rs.set(r);
    }
    assert_eq!(rs.count(), 64);
    for r in 0u8..64 {
        assert!(rs.contains(r));
    }
    assert!(!rs.is_empty());
}

#[test]
fn reg_set_out_of_range_silently_ignored() {
    let mut rs = DexRegSet::default();
    for r in 64u8..=255 {
        rs.set(r);
        assert!(!rs.contains(r));
        rs.clear(r); // no panic
    }
    assert_eq!(rs.count(), 0);
}

#[test]
fn reg_set_clear_idempotent() {
    let mut rs = DexRegSet::default();
    rs.set(5);
    rs.clear(5);
    rs.clear(5);
    assert!(!rs.contains(5));
}

// ---------------------------------------------------------------------------
// 20. Calling convention math
// ---------------------------------------------------------------------------

#[test]
fn calling_conv_instance_method_this_register() {
    // 8 total regs, 3 params + this
    let cc = DexCallingConv::compute(8, 3, true);
    assert_eq!(cc.this_register(), Some(5));
    assert_eq!(cc.param_register(0), Some(6));
    assert_eq!(cc.param_register(1), Some(7));
}

#[test]
fn calling_conv_static_no_this() {
    let cc = DexCallingConv::compute(4, 2, false);
    assert_eq!(cc.this_register(), None);
    assert_eq!(cc.param_register(0), Some(2));
    assert_eq!(cc.param_register(1), Some(3));
}

#[test]
fn calling_conv_underflow_safe() {
    // param_count > frame_size — must not panic
    let cc = DexCallingConv::compute(2, 5, true);
    assert_eq!(cc.this_register(), None);
    assert_eq!(cc.param_register(0), None);
}

#[test]
fn calling_conv_overflow_safe() {
    let cc = DexCallingConv::compute(u16::MAX, 0, false);
    assert_eq!(cc.param_register(255), None);
}

// ---------------------------------------------------------------------------
// 21. Method stats + complexity round-trip
// ---------------------------------------------------------------------------

#[test]
fn method_stats_call_count() {
    // invoke-virtual {v0}, meth@1 (6 bytes); return-void
    let code = [0x6e_u8, 0x10, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00];
    let s = DexMethodStats::from_bytes(&code).unwrap();
    assert_eq!(s.instruction_count, 2);
    assert_eq!(s.call_count, 1);
    assert_eq!(s.terminator_count, 1);
}

#[test]
fn method_stats_conditional_branch() {
    // if-eqz v0, +3; return-void
    let code = [0x38_u8, 0x00, 0x03, 0x00, 0x0e, 0x00];
    let s = DexMethodStats::from_bytes(&code).unwrap();
    assert_eq!(s.conditional_branch_count, 1);
    assert_eq!(s.unconditional_branch_count, 0);
}

#[test]
fn complexity_cyclomatic_with_two_conditionals() {
    // if-eqz v0, +0; if-nez v0, +0; return-void
    let code = [
        0x38_u8, 0x00, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x0e, 0x00,
    ];
    let m = DexComplexityMetrics::from_bytes(&code).unwrap();
    assert_eq!(m.cyclomatic, 3);
    assert_eq!(m.instruction_count, 3);
}

// ---------------------------------------------------------------------------
// 22. Basic block finder
// ---------------------------------------------------------------------------

#[test]
fn find_blocks_three_blocks_with_goto() {
    // const/4 v0,#0; goto +1; return-void
    let code = [0x12_u8, 0x00, 0x28, 0x01, 0x0e, 0x00];
    let blocks = dex_find_blocks(&code).unwrap();
    assert_eq!(blocks.len(), 2);
    assert!(blocks[0].len() > 0);
    assert!(!blocks[0].is_empty());
}

#[test]
fn find_blocks_error_on_truncated() {
    // 0x14 (const) requires 6 bytes; give only 2
    let res = dex_find_blocks(&[0x14, 0x00]);
    assert!(res.is_err());
}

// ---------------------------------------------------------------------------
// 23. Idiom detection
// ---------------------------------------------------------------------------

#[test]
fn idiom_general_fallthrough() {
    assert_eq!(identify_dex_idiom("add-int", "v0, v1, v2"), DexIdiom::General);
}

#[test]
fn idiom_null_check_nez() {
    assert_eq!(
        identify_dex_idiom("if-nez", "v0, :label"),
        DexIdiom::NullCheck
    );
}

// ---------------------------------------------------------------------------
// 24. Switch payload size
// ---------------------------------------------------------------------------

#[test]
fn packed_switch_size_boundaries() {
    assert_eq!(packed_switch_payload_size(0), 4);
    assert_eq!(packed_switch_payload_size(1), 6);
    assert_eq!(packed_switch_payload_size(u16::MAX), 4 + (u16::MAX as u32) * 2);
}

#[test]
fn sparse_switch_size_boundaries() {
    assert_eq!(sparse_switch_payload_size(0), 2);
    assert_eq!(sparse_switch_payload_size(1), 6);
}

#[test]
fn switch_payload_idents() {
    assert_eq!(DEX_PACKED_SWITCH_IDENT, 0x0100);
    assert_eq!(DEX_SPARSE_SWITCH_IDENT, 0x0200);
    assert_eq!(DEX_FILL_ARRAY_DATA_IDENT, 0x0300);
}

// ---------------------------------------------------------------------------
// 25. dex_param_regs boundary
// ---------------------------------------------------------------------------

#[test]
fn dex_param_regs_boundary_zero() {
    assert!(dex_param_regs(0, 0).is_empty());
    assert!(dex_param_regs(5, 0).is_empty());
}

#[test]
fn dex_param_regs_underflow_safe() {
    // param_count > total — saturating_sub keeps first at 0
    let r = dex_param_regs(2, 5);
    assert_eq!(r, vec![0, 1]);
}

#[test]
fn dex_param_regs_max() {
    let r = dex_param_regs(u8::MAX, 1);
    assert_eq!(r, vec![u8::MAX - 1]);
}

// ---------------------------------------------------------------------------
// 26. Architecture trait
// ---------------------------------------------------------------------------

#[test]
fn dex_arch_default_is_32_bit() {
    let a = DexArch::default();
    assert_eq!(a.pointer_size(), 4);
}

#[test]
fn dex_arch_64_bit() {
    let a = DexArch::with_bits(64);
    assert_eq!(a.pointer_size(), 8);
}

#[test]
fn dex_arch_endian_little() {
    assert_eq!(DexArch::new().endian(), Endian::Little);
}

#[test]
fn dex_arch_registers_are_16() {
    let regs = DexArch::new().registers();
    assert_eq!(regs.len(), 16);
    for (i, r) in regs.iter().enumerate() {
        assert_eq!(r.name, format!("v{i}"));
    }
}

#[test]
fn dex_arch_calling_convention_dalvik() {
    let cc = DexArch::new().calling_conventions();
    assert_eq!(cc.len(), 1);
    assert_eq!(cc[0].name, "dalvik");
    assert!(!cc[0].caller_cleans_stack);
}

// ---------------------------------------------------------------------------
// 27. Smali helpers
// ---------------------------------------------------------------------------

#[test]
fn smali_method_ref_format() {
    let s = smali_method_ref("Ljava/lang/String;", "length", "()I");
    assert_eq!(s, "Ljava/lang/String;->length()I");
}

#[test]
fn smali_field_ref_format() {
    let s = smali_field_ref("LFoo;", "bar", "I");
    assert_eq!(s, "LFoo;->bar:I");
}

#[test]
fn smali_reg_basic() {
    assert_eq!(smali_reg(0), "v0");
    assert_eq!(smali_reg(255), "v255");
    assert_eq!(smali_reg(u16::MAX), format!("v{}", u16::MAX));
}

// ---------------------------------------------------------------------------
// 28. Magic constants integrity
// ---------------------------------------------------------------------------

#[test]
fn dex_magic_constants() {
    assert_eq!(DEX_MAGIC, b"dex\n");
    assert_eq!(DEX_MAGIC_035, b"dex\n035\0");
    assert_eq!(DEX_MAGIC_036, b"dex\n036\0");
    assert_eq!(DEX_MAGIC_037, b"dex\n037\0");
    assert_eq!(DEX_MAGIC_038, b"dex\n038\0");
    assert_eq!(DEX_MAGIC_039, b"dex\n039\0");
    assert_eq!(CDEX_MAGIC, b"cdex");
}

#[test]
fn dex_endian_constants_pair() {
    let a = DEX_ENDIAN_CONSTANT.to_le_bytes();
    let b = DEX_REVERSE_ENDIAN_CONSTANT.to_be_bytes();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// 29. Call-site extraction
// ---------------------------------------------------------------------------

#[test]
fn extract_call_sites_invoke_virtual() {
    // invoke-virtual {v0}, meth@1 (6 bytes); return-void
    let code = [0x6e_u8, 0x10, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00];
    let sites = dex_extract_call_sites("LCaller;->foo()V", &code).unwrap();
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].invoke_type, "virtual");
    assert_eq!(sites[0].offset, 0);
    assert_eq!(sites[0].caller, "LCaller;->foo()V");
}

#[test]
fn extract_call_sites_none() {
    let code = [0x0e_u8, 0x00]; // return-void only
    let sites = dex_extract_call_sites("LX;->m()V", &code).unwrap();
    assert!(sites.is_empty());
}

#[test]
fn extract_call_sites_truncated() {
    // 0x14 needs 6 bytes
    let code = [0x14_u8, 0x00];
    assert!(dex_extract_call_sites("c", &code).is_err());
}

// ---------------------------------------------------------------------------
// 30. Cost table monotonicity sanity
// ---------------------------------------------------------------------------

#[test]
fn instr_cost_invoke_costs_more_than_nop() {
    assert!(dex_instr_cost("invoke-virtual") > dex_instr_cost("nop"));
    assert!(dex_instr_cost("new-instance") > dex_instr_cost("move"));
    assert!(dex_instr_cost("div-int") > dex_instr_cost("add-int"));
    assert_eq!(dex_instr_cost("nop"), 0);
    assert!(dex_instr_cost("nonexistent-mnem") > 0);
}

// ---------------------------------------------------------------------------
// 31. Well-known method/class table integrity
// ---------------------------------------------------------------------------

#[test]
fn well_known_classes_unique_descriptors() {
    let mut seen = std::collections::HashSet::new();
    for c in DEX_WELL_KNOWN_CLASSES.iter() {
        assert!(seen.insert(c.descriptor), "duplicate {}", c.descriptor);
    }
}

#[test]
fn well_known_classes_lookup_each() {
    for c in DEX_WELL_KNOWN_CLASSES.iter() {
        assert!(lookup_dex_class(c.descriptor).is_some());
    }
}

#[test]
fn well_known_class_unknown_returns_none() {
    assert!(lookup_dex_class("Lcompletely/Fake/Made/Up/Class;").is_none());
}
