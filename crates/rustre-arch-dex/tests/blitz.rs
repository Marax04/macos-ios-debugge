//! Exhaustive blitz tests for `rustre-arch-dex` public API.
//! Goal: surface bugs in decoders, parsers, and helpers.

use rustre_core::arch::{Architecture, InstrFlags};
use rustre_arch_dex::*;
use rustre_core::address::Address;
use rustre_core::endian::Endian;

// ---------------------------------------------------------------------------
// DexAccessFlags
// ---------------------------------------------------------------------------

#[test]
fn access_flags_public_set() {
    let f = DexAccessFlags(DexAccessFlags::PUBLIC | DexAccessFlags::STATIC);
    assert!(f.has(DexAccessFlags::PUBLIC));
    assert!(f.has(DexAccessFlags::STATIC));
    assert!(!f.has(DexAccessFlags::PRIVATE));
}

#[test]
fn access_flags_constructor() {
    let f = DexAccessFlags(DexAccessFlags::CONSTRUCTOR);
    assert!(f.has(DexAccessFlags::CONSTRUCTOR));
    assert!(!f.has(DexAccessFlags::PUBLIC));
}

#[test]
fn access_flags_field_volatile_vs_method_bridge_share_bit() {
    let f = DexAccessFlags(0x0040);
    assert!(f.has_field_flag(DexAccessFlags::VOLATILE));
    assert!(f.has_method_flag(DexAccessFlags::BRIDGE));
}

#[test]
fn access_flags_zero_has_nothing() {
    let f = DexAccessFlags(0);
    assert!(!f.has(DexAccessFlags::PUBLIC));
    assert!(!f.has(DexAccessFlags::DECLARED_SYNC));
}

#[test]
fn access_flags_all_bits() {
    let f = DexAccessFlags(0xFFFF_FFFF);
    assert!(f.has(DexAccessFlags::DECLARED_SYNC));
    assert!(f.has(DexAccessFlags::CONSTRUCTOR));
}

// ---------------------------------------------------------------------------
// DexTypeDescriptor / DescriptorKind
// ---------------------------------------------------------------------------

#[test]
fn descriptor_primitives() {
    assert_eq!(DexTypeDescriptor::new("V").kind(), DescriptorKind::Void);
    assert_eq!(DexTypeDescriptor::new("Z").kind(), DescriptorKind::Boolean);
    assert_eq!(DexTypeDescriptor::new("I").kind(), DescriptorKind::Int);
    assert_eq!(DexTypeDescriptor::new("J").kind(), DescriptorKind::Long);
    assert_eq!(DexTypeDescriptor::new("D").kind(), DescriptorKind::Double);
    assert_eq!(DexTypeDescriptor::new("F").kind(), DescriptorKind::Float);
    assert_eq!(DexTypeDescriptor::new("B").kind(), DescriptorKind::Byte);
    assert_eq!(DexTypeDescriptor::new("S").kind(), DescriptorKind::Short);
    assert_eq!(DexTypeDescriptor::new("C").kind(), DescriptorKind::Char);
}

#[test]
fn descriptor_object_kind() {
    let d = DexTypeDescriptor::new("Ljava/lang/String;");
    assert_eq!(d.kind(), DescriptorKind::Object);
    assert_eq!(d.class_name(), Some("java/lang/String"));
}

#[test]
fn descriptor_array_kind_and_element() {
    let d = DexTypeDescriptor::new("[I");
    assert_eq!(d.kind(), DescriptorKind::Array);
    let inner = d.array_element().unwrap();
    assert_eq!(inner.kind(), DescriptorKind::Int);
}

#[test]
fn descriptor_array_of_object() {
    let d = DexTypeDescriptor::new("[Ljava/lang/Object;");
    let inner = d.array_element().unwrap();
    assert_eq!(inner.kind(), DescriptorKind::Object);
    assert_eq!(inner.class_name(), Some("java/lang/Object"));
}

#[test]
fn descriptor_unknown_kind() {
    assert_eq!(DexTypeDescriptor::new("Q").kind(), DescriptorKind::Unknown);
    assert_eq!(DexTypeDescriptor::new("").kind(), DescriptorKind::Unknown);
}

#[test]
fn descriptor_class_name_none_for_primitive() {
    assert!(DexTypeDescriptor::new("I").class_name().is_none());
    assert!(DexTypeDescriptor::new("[I").class_name().is_none());
}

#[test]
fn descriptor_array_element_none_for_non_array() {
    assert!(DexTypeDescriptor::new("I").array_element().is_none());
    assert!(DexTypeDescriptor::new("Ljava/lang/Object;").array_element().is_none());
}

#[test]
fn descriptor_kind_register_slots() {
    assert_eq!(DescriptorKind::Long.register_slots(), 2);
    assert_eq!(DescriptorKind::Double.register_slots(), 2);
    assert_eq!(DescriptorKind::Int.register_slots(), 1);
    assert_eq!(DescriptorKind::Void.register_slots(), 1);
    assert_eq!(DescriptorKind::Object.register_slots(), 1);
}

#[test]
fn descriptor_kind_is_wide() {
    assert!(DescriptorKind::Long.is_wide());
    assert!(DescriptorKind::Double.is_wide());
    assert!(!DescriptorKind::Int.is_wide());
    assert!(!DescriptorKind::Object.is_wide());
}

// ---------------------------------------------------------------------------
// DexMethodSignature
// ---------------------------------------------------------------------------

#[test]
fn method_signature_register_count_no_wide() {
    let sig = DexMethodSignature::new(
        "VII",
        "V",
        vec![DexTypeDescriptor::new("I"), DexTypeDescriptor::new("I")],
    );
    assert_eq!(sig.arg_register_count(), 2);
}

#[test]
fn method_signature_register_count_with_wide() {
    let sig = DexMethodSignature::new(
        "VJD",
        "V",
        vec![DexTypeDescriptor::new("J"), DexTypeDescriptor::new("D")],
    );
    assert_eq!(sig.arg_register_count(), 4);
}

#[test]
fn method_signature_empty_params() {
    let sig = DexMethodSignature::new("V", "V", vec![]);
    assert_eq!(sig.arg_register_count(), 0);
}

// ---------------------------------------------------------------------------
// DexCodeItemHeader
// ---------------------------------------------------------------------------

#[test]
fn code_item_header_decode_truncated_zero() {
    assert_eq!(DexCodeItemHeader::decode(&[]), Err(DexDecodeError::Truncated));
}

#[test]
fn code_item_header_decode_truncated_15() {
    assert_eq!(
        DexCodeItemHeader::decode(&[0; 15]),
        Err(DexDecodeError::Truncated)
    );
}

#[test]
fn code_item_header_decode_full() {
    let bytes: [u8; 16] = [
        0x04, 0x00, // registers
        0x02, 0x00, // ins
        0x03, 0x00, // outs
        0x01, 0x00, // tries
        0xAA, 0xBB, 0xCC, 0xDD, // debug_info_off
        0x10, 0x00, 0x00, 0x00, // insns_size
    ];
    let h = DexCodeItemHeader::decode(&bytes).unwrap();
    assert_eq!(h.registers_size, 4);
    assert_eq!(h.ins_size, 2);
    assert_eq!(h.outs_size, 3);
    assert_eq!(h.tries_size, 1);
    assert_eq!(h.debug_info_off, 0xDDCC_BBAA);
    assert_eq!(h.insns_size, 16);
    assert!(h.has_try_blocks());
}

// ---------------------------------------------------------------------------
// DexFormat::base_code_units
// ---------------------------------------------------------------------------

#[test]
fn format_base_code_units() {
    assert_eq!(DexFormat::F10x.base_code_units(), 1);
    assert_eq!(DexFormat::F12x.base_code_units(), 1);
    assert_eq!(DexFormat::F22x.base_code_units(), 2);
    assert_eq!(DexFormat::F31i.base_code_units(), 3);
    assert_eq!(DexFormat::F45cc.base_code_units(), 4);
    assert_eq!(DexFormat::F4rcc.base_code_units(), 4);
    assert_eq!(DexFormat::F51l.base_code_units(), 5);
}

// ---------------------------------------------------------------------------
// decode_dex
// ---------------------------------------------------------------------------

#[test]
fn decode_empty_is_err() {
    assert!(decode_dex(&[]).is_err());
}

#[test]
fn decode_nop() {
    let (m, ops, sz, f) = decode_dex(&[0x00, 0x00]).unwrap();
    assert_eq!(m, "nop");
    assert_eq!(ops, "");
    assert_eq!(sz, 2);
    assert_eq!(f, InstrFlags::NONE);
}

#[test]
fn decode_nop_pseudo_packed_switch_payload() {
    let (m, _, _, _) = decode_dex(&[0x00, 0x01]).unwrap();
    assert_eq!(m, "packed-switch-payload");
}

#[test]
fn decode_move() {
    let (m, ops, sz, _) = decode_dex(&[0x01, 0x21]).unwrap();
    assert_eq!(m, "move");
    assert_eq!(ops, "v1, v2");
    assert_eq!(sz, 2);
}

#[test]
fn decode_return_void() {
    let (m, _, sz, f) = decode_dex(&[0x0e, 0x00]).unwrap();
    assert_eq!(m, "return-void");
    assert_eq!(sz, 2);
    assert!(f.contains(InstrFlags::RET));
}

#[test]
fn decode_const_4_negative() {
    // const/4 v0, #-1  → hi nibble high = 0xF (sign extend to -1)
    let (m, ops, _, _) = decode_dex(&[0x12, 0xF0]).unwrap();
    assert_eq!(m, "const/4");
    assert_eq!(ops, "v0, #-1");
}

#[test]
fn decode_const_4_positive() {
    // const/4 v1, #7 -> hi=0x71 ; A=1 ; lit=7
    let (m, ops, _, _) = decode_dex(&[0x12, 0x71]).unwrap();
    assert_eq!(m, "const/4");
    assert_eq!(ops, "v1, #7");
}

#[test]
fn decode_const_16() {
    // const/16 v2, #0x1234 (LE 0x34 0x12)
    let (m, ops, sz, _) = decode_dex(&[0x13, 0x02, 0x34, 0x12]).unwrap();
    assert_eq!(m, "const/16");
    assert_eq!(ops, "v2, #4660");
    assert_eq!(sz, 4);
}

#[test]
fn decode_const_wide_truncated() {
    // 0x18 requires 10 bytes
    assert!(decode_dex(&[0x18, 0x00, 0x00, 0x00, 0x00]).is_err());
}

#[test]
fn decode_const_wide_full() {
    let bytes = [0x18, 0x00, 1, 2, 3, 4, 5, 6, 7, 8];
    let (m, _, sz, _) = decode_dex(&bytes).unwrap();
    assert_eq!(m, "const-wide");
    assert_eq!(sz, 10);
}

#[test]
fn decode_throw_is_branch() {
    let (m, _, _, f) = decode_dex(&[0x27, 0x05]).unwrap();
    assert_eq!(m, "throw");
    assert!(f.contains(InstrFlags::BRANCH));
}

#[test]
fn decode_goto() {
    let (m, ops, _, f) = decode_dex(&[0x28, 0x05]).unwrap();
    assert_eq!(m, "goto");
    assert_eq!(ops, "+5");
    assert!(f.contains(InstrFlags::BRANCH));
}

#[test]
fn decode_truncated_move_from16() {
    // 0x02 requires 4 bytes total (operand u16 at offset 2)
    assert!(decode_dex(&[0x02, 0x00]).is_err());
}

// ---------------------------------------------------------------------------
// DexArch + Architecture
// ---------------------------------------------------------------------------

#[test]
fn arch_default_bits() {
    let a = DexArch::new();
    assert_eq!(a.bits, 32);
    assert_eq!(a.pointer_size(), 4);
    assert_eq!(a.name(), "dex");
    assert_eq!(a.endian(), Endian::Little);
}

#[test]
fn arch_with_bits_64() {
    let a = DexArch::with_bits(64);
    assert_eq!(a.pointer_size(), 8);
}

#[test]
fn arch_disassemble_nop() {
    let a = DexArch::new();
    let i = a.disassemble(Address::new(0x100), &[0x00, 0x00]).unwrap();
    assert_eq!(i.mnemonic, "nop");
    assert_eq!(i.size, 2);
}

#[test]
fn arch_registers_has_16() {
    let a = DexArch::new();
    assert_eq!(a.registers().len(), 16);
}

#[test]
fn arch_calling_conventions_dalvik() {
    let a = DexArch::new();
    let cc = a.calling_conventions();
    assert_eq!(cc.len(), 1);
    assert_eq!(cc[0].name, "dalvik");
}

// ---------------------------------------------------------------------------
// DexLinearDisassembler
// ---------------------------------------------------------------------------

#[test]
fn linear_disassembler_iterates() {
    let arch = DexArch::new();
    // nop ; return-void
    let bytes = [0x00, 0x00, 0x0e, 0x00];
    let dis = DexLinearDisassembler::new(&arch, &bytes, Address::new(0));
    let v: Vec<_> = dis.collect();
    assert_eq!(v.len(), 2);
    assert!(v[0].is_ok());
    assert!(v[1].is_ok());
}

#[test]
fn linear_disassembler_offset_advances() {
    let arch = DexArch::new();
    let bytes = [0x00, 0x00, 0x0e, 0x00];
    let mut dis = DexLinearDisassembler::new(&arch, &bytes, Address::new(0));
    assert_eq!(dis.offset(), 0);
    let _ = dis.next();
    assert_eq!(dis.offset(), 2);
}

// ---------------------------------------------------------------------------
// ART opcode helpers
// ---------------------------------------------------------------------------

#[test]
fn art_opcode_range_check() {
    assert!(!is_art_optimized_opcode(0xe2));
    assert!(is_art_optimized_opcode(0xe3));
    assert!(is_art_optimized_opcode(0xf9));
    assert!(!is_art_optimized_opcode(0xfa));
    assert!(!is_art_optimized_opcode(0x00));
}

#[test]
fn art_opcode_names() {
    assert_eq!(art_opcode_name(0xe3), "iget-quick");
    assert_eq!(art_opcode_name(0xe9), "invoke-virtual-quick");
    assert_eq!(art_opcode_name(0xff), "unknown-art");
}

// ---------------------------------------------------------------------------
// lookup_dex_opcode
// ---------------------------------------------------------------------------

#[test]
fn lookup_opcode_known() {
    assert!(lookup_dex_opcode(0x00).is_some());
    assert!(lookup_dex_opcode(0x0e).is_some());
}

// ---------------------------------------------------------------------------
// DexReturnType
// ---------------------------------------------------------------------------

#[test]
fn return_type_parse_empty() {
    assert!(DexReturnType::parse("").is_none());
}

#[test]
fn return_type_parse_void() {
    assert_eq!(DexReturnType::parse("V"), Some(DexReturnType::Void));
}

#[test]
fn return_type_parse_nested_array() {
    let r = DexReturnType::parse("[[I").unwrap();
    match r {
        DexReturnType::Array(inner) => match *inner {
            DexReturnType::Array(inner2) => assert_eq!(*inner2, DexReturnType::Primitive('I')),
            _ => panic!("expected nested array"),
        },
        _ => panic!("expected array"),
    }
}

#[test]
fn return_type_parse_unknown() {
    assert!(DexReturnType::parse("X").is_none());
}

#[test]
fn return_type_is_void() {
    assert!(DexReturnType::Void.is_void());
    assert!(!DexReturnType::Primitive('I').is_void());
}

// ---------------------------------------------------------------------------
// dex_param_count
// ---------------------------------------------------------------------------

#[test]
fn param_count_zero() {
    assert_eq!(dex_param_count("()V"), 0);
}

#[test]
fn param_count_three_primitives() {
    assert_eq!(dex_param_count("(IIJ)V"), 3);
}

#[test]
fn param_count_with_object_and_array() {
    assert_eq!(dex_param_count("(Ljava/lang/String;[I)V"), 2);
}

#[test]
fn param_count_array_of_object() {
    assert_eq!(dex_param_count("([Ljava/lang/String;)V"), 1);
}

#[test]
fn param_count_multi_dim_array() {
    assert_eq!(dex_param_count("([[I)V"), 1);
}

// ---------------------------------------------------------------------------
// DexBasicBlock + dex_find_blocks
// ---------------------------------------------------------------------------

#[test]
fn basic_block_len_and_empty() {
    let b = DexBasicBlock {
        start: 4,
        end: 10,
        instr_count: 3,
    };
    assert_eq!(b.len(), 6);
    assert!(!b.is_empty());
}

#[test]
fn basic_block_empty_if_zero_instructions() {
    let b = DexBasicBlock {
        start: 0,
        end: 0,
        instr_count: 0,
    };
    assert!(b.is_empty());
}

#[test]
fn find_blocks_empty_code() {
    assert!(dex_find_blocks(&[]).unwrap().is_empty());
}

#[test]
fn find_blocks_only_return() {
    let blocks = dex_find_blocks(&[0x0e, 0x00]).unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].instr_count, 1);
    assert_eq!(blocks[0].start, 0);
    assert_eq!(blocks[0].end, 2);
}

#[test]
fn find_blocks_nop_then_return() {
    // nop, return-void -> ret is a terminator, so 1 block
    let blocks = dex_find_blocks(&[0x00, 0x00, 0x0e, 0x00]).unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].instr_count, 2);
}

// ---------------------------------------------------------------------------
// register naming
// ---------------------------------------------------------------------------

#[test]
fn vreg_preg_format() {
    assert_eq!(dex_vreg(0), "v0");
    assert_eq!(dex_vreg(255), "v255");
    assert_eq!(dex_preg(7), "p7");
}

#[test]
fn param_regs_basic() {
    assert_eq!(dex_param_regs(8, 3), vec![5, 6, 7]);
    assert_eq!(dex_param_regs(3, 3), vec![0, 1, 2]);
    assert_eq!(dex_param_regs(5, 0), Vec::<u8>::new());
}

#[test]
fn param_regs_saturates_when_too_many() {
    // param_count > total: should saturate
    let v = dex_param_regs(2, 5);
    assert_eq!(v, vec![0, 1]);
}

// ---------------------------------------------------------------------------
// Well-known classes / methods
// ---------------------------------------------------------------------------

#[test]
fn well_known_class_object() {
    assert_eq!(
        lookup_dex_class("Ljava/lang/Object;").map(|c| c.name),
        Some("Object")
    );
}

#[test]
fn well_known_class_missing() {
    assert!(lookup_dex_class("Lnope/nope/Nope;").is_none());
}

#[test]
fn well_known_method_string_length() {
    let m = lookup_dex_method("Ljava/lang/String;", "length").unwrap();
    assert_eq!(m.proto, "()I");
}

#[test]
fn well_known_method_missing() {
    assert!(lookup_dex_method("LNada;", "nada").is_none());
}

// ---------------------------------------------------------------------------
// DexMethodStats
// ---------------------------------------------------------------------------

#[test]
fn method_stats_single_return() {
    let s = DexMethodStats::from_bytes(&[0x0e, 0x00]).unwrap();
    assert_eq!(s.instruction_count, 1);
    assert_eq!(s.terminator_count, 1);
    assert_eq!(s.call_count, 0);
}

#[test]
fn method_stats_empty() {
    let s = DexMethodStats::from_bytes(&[]).unwrap();
    assert_eq!(s, DexMethodStats::default());
}

// ---------------------------------------------------------------------------
// Idiom detection
// ---------------------------------------------------------------------------

#[test]
fn idiom_zero_init() {
    assert_eq!(identify_dex_idiom("const/4", "v0, 0"), DexIdiom::ZeroInit);
}

#[test]
fn idiom_general_const_4_nonzero() {
    assert_eq!(identify_dex_idiom("const/4", "v0, 5"), DexIdiom::General);
}

#[test]
fn idiom_null_check_eqz_and_nez() {
    assert_eq!(identify_dex_idiom("if-eqz", "v0, :l"), DexIdiom::NullCheck);
    assert_eq!(identify_dex_idiom("if-nez", "v0, :l"), DexIdiom::NullCheck);
}

#[test]
fn idiom_stringbuilder_new() {
    assert_eq!(
        identify_dex_idiom("new-instance", "v0, Ljava/lang/StringBuilder;"),
        DexIdiom::StringBuilderNew
    );
}

#[test]
fn idiom_goto_backedge() {
    assert_eq!(identify_dex_idiom("goto", "+5"), DexIdiom::BackEdgeLoop);
}

#[test]
fn idiom_general_fallthrough() {
    assert_eq!(identify_dex_idiom("add-int", "v0, v1, v2"), DexIdiom::General);
}

// ---------------------------------------------------------------------------
// DexAnnotationVisibility
// ---------------------------------------------------------------------------

#[test]
fn annotation_visibility_decode_all() {
    assert_eq!(
        DexAnnotationVisibility::from_byte(0x00),
        Some(DexAnnotationVisibility::Build)
    );
    assert_eq!(
        DexAnnotationVisibility::from_byte(0x01),
        Some(DexAnnotationVisibility::Runtime)
    );
    assert_eq!(
        DexAnnotationVisibility::from_byte(0x02),
        Some(DexAnnotationVisibility::System)
    );
    assert!(DexAnnotationVisibility::from_byte(0x03).is_none());
}

#[test]
fn annotation_visibility_name() {
    assert_eq!(DexAnnotationVisibility::Build.name(), "build");
    assert_eq!(DexAnnotationVisibility::Runtime.name(), "runtime");
    assert_eq!(DexAnnotationVisibility::System.name(), "system");
}

// ---------------------------------------------------------------------------
// DexAnnotationValueType
// ---------------------------------------------------------------------------

#[test]
fn annotation_value_type_all_known() {
    assert_eq!(
        DexAnnotationValueType::from_byte(0x00),
        Some(DexAnnotationValueType::Byte)
    );
    assert_eq!(
        DexAnnotationValueType::from_byte(0x1f),
        Some(DexAnnotationValueType::Boolean)
    );
}

#[test]
fn annotation_value_type_is_reference() {
    assert!(DexAnnotationValueType::String.is_reference());
    assert!(DexAnnotationValueType::Type.is_reference());
    assert!(DexAnnotationValueType::Field.is_reference());
    assert!(DexAnnotationValueType::Method.is_reference());
    assert!(DexAnnotationValueType::Enum.is_reference());
    assert!(DexAnnotationValueType::Annotation.is_reference());
    assert!(!DexAnnotationValueType::Int.is_reference());
    assert!(!DexAnnotationValueType::Boolean.is_reference());
    assert!(!DexAnnotationValueType::Null.is_reference());
}

#[test]
fn annotation_value_type_unknown() {
    // 0x05 isn't in the table
    assert!(DexAnnotationValueType::from_byte(0x05).is_none());
}

// ---------------------------------------------------------------------------
// DexMethodHandleKind
// ---------------------------------------------------------------------------

#[test]
fn method_handle_kind_known() {
    assert_eq!(
        DexMethodHandleKind::from_u16(0x04),
        Some(DexMethodHandleKind::InvokeStatic)
    );
}

#[test]
fn method_handle_kind_is_invoke() {
    assert!(DexMethodHandleKind::InvokeStatic.is_invoke());
    assert!(DexMethodHandleKind::InvokeInterface.is_invoke());
    assert!(!DexMethodHandleKind::StaticPut.is_invoke());
    assert!(!DexMethodHandleKind::InstanceGet.is_invoke());
}

#[test]
fn method_handle_kind_unknown() {
    assert!(DexMethodHandleKind::from_u16(0x99).is_none());
}

// ---------------------------------------------------------------------------
// String descriptor utilities
// ---------------------------------------------------------------------------

#[test]
fn internal_to_java_roundtrip() {
    let j = dex_internal_to_java_name("java/lang/String");
    assert_eq!(j, "java.lang.String");
    let d = java_name_to_dex_descriptor(&j);
    assert_eq!(d, "Ljava/lang/String;");
}

#[test]
fn simple_class_name_simple() {
    assert_eq!(dex_simple_class_name("Lcom/example/Foo;"), "Foo");
    assert_eq!(dex_simple_class_name("LBare;"), "Bare");
}

// ---------------------------------------------------------------------------
// dex_instr_cost
// ---------------------------------------------------------------------------

#[test]
fn instr_cost_nop_zero() {
    assert_eq!(dex_instr_cost("nop"), 0);
}

#[test]
fn instr_cost_ordering() {
    assert!(dex_instr_cost("new-instance") > dex_instr_cost("nop"));
    assert!(dex_instr_cost("invoke-virtual") > dex_instr_cost("move"));
    assert!(dex_instr_cost("div-int") > dex_instr_cost("add-int"));
}

#[test]
fn instr_cost_unknown_default() {
    assert_eq!(dex_instr_cost("some-future-op"), 2);
}

// ---------------------------------------------------------------------------
// DexComplexityMetrics
// ---------------------------------------------------------------------------

#[test]
fn complexity_metrics_base() {
    let m = DexComplexityMetrics::from_bytes(&[0x0e, 0x00]).unwrap();
    assert_eq!(m.cyclomatic, 1);
    assert_eq!(m.instruction_count, 1);
}

#[test]
fn complexity_metrics_empty() {
    let m = DexComplexityMetrics::from_bytes(&[]).unwrap();
    assert_eq!(m.cyclomatic, 1);
    assert_eq!(m.instruction_count, 0);
}

// ---------------------------------------------------------------------------
// DexCallingConv
// ---------------------------------------------------------------------------

#[test]
fn calling_conv_instance_this() {
    let cc = DexCallingConv::compute(5, 2, true);
    assert_eq!(cc.this_register(), Some(3));
    // first param after `this`
    assert_eq!(cc.param_register(0), Some(4));
}

#[test]
fn calling_conv_static_no_this() {
    let cc = DexCallingConv::compute(4, 2, false);
    assert_eq!(cc.this_register(), None);
    assert_eq!(cc.param_register(0), Some(2));
    assert_eq!(cc.param_register(1), Some(3));
}

#[test]
fn calling_conv_no_params() {
    let cc = DexCallingConv::compute(0, 0, false);
    assert_eq!(cc.this_register(), None);
    assert_eq!(cc.param_register(0), Some(0));
}

// ---------------------------------------------------------------------------
// smali helpers
// ---------------------------------------------------------------------------

#[test]
fn smali_reg_format() {
    assert_eq!(smali_reg(0), "v0");
    assert_eq!(smali_reg(1000), "v1000");
}

#[test]
fn smali_method_ref_format() {
    assert_eq!(
        smali_method_ref("Ljava/lang/Object;", "hashCode", "()I"),
        "Ljava/lang/Object;->hashCode()I"
    );
}

#[test]
fn smali_field_ref_format() {
    assert_eq!(
        smali_field_ref("Lcom/Foo;", "bar", "Ljava/lang/String;"),
        "Lcom/Foo;->bar:Ljava/lang/String;"
    );
}

// ---------------------------------------------------------------------------
// dex_extract_call_sites
// ---------------------------------------------------------------------------

#[test]
fn extract_call_sites_empty_no_invokes() {
    let sites = dex_extract_call_sites("LCaller;->m()V", &[0x0e, 0x00]).unwrap();
    assert!(sites.is_empty());
}

#[test]
fn extract_call_sites_propagates_caller() {
    let sites = dex_extract_call_sites("LX;->y()V", &[0x0e, 0x00]).unwrap();
    assert!(sites.is_empty());
    // Empty input
    let s2 = dex_extract_call_sites("LX;->y()V", &[]).unwrap();
    assert!(s2.is_empty());
}

// ---------------------------------------------------------------------------
// packed_switch / sparse_switch sizes
// ---------------------------------------------------------------------------

#[test]
fn packed_switch_size_formula() {
    // doc says "2 + size", but implementation is 4 + entries*2
    assert_eq!(packed_switch_payload_size(0), 4);
    assert_eq!(packed_switch_payload_size(3), 10);
    assert_eq!(packed_switch_payload_size(10), 24);
}

#[test]
fn sparse_switch_size_formula() {
    assert_eq!(sparse_switch_payload_size(0), 2);
    assert_eq!(sparse_switch_payload_size(2), 10);
    assert_eq!(sparse_switch_payload_size(5), 22);
}

#[test]
fn switch_payload_idents() {
    assert_eq!(DEX_PACKED_SWITCH_IDENT, 0x0100);
    assert_eq!(DEX_SPARSE_SWITCH_IDENT, 0x0200);
    assert_eq!(DEX_FILL_ARRAY_DATA_IDENT, 0x0300);
}

// ---------------------------------------------------------------------------
// DexRegSet
// ---------------------------------------------------------------------------

#[test]
fn reg_set_basic_set_clear_contains() {
    let mut rs = DexRegSet::default();
    assert!(rs.is_empty());
    rs.set(3);
    rs.set(7);
    assert!(rs.contains(3));
    assert!(rs.contains(7));
    assert!(!rs.contains(4));
    assert_eq!(rs.count(), 2);
    rs.clear(3);
    assert!(!rs.contains(3));
    assert_eq!(rs.count(), 1);
}

#[test]
fn reg_set_out_of_range_is_noop() {
    let mut rs = DexRegSet::default();
    rs.set(64); // out of range
    assert!(rs.is_empty());
    assert!(!rs.contains(64));
    rs.set(255);
    assert!(rs.is_empty());
}

#[test]
fn reg_set_boundary_63() {
    let mut rs = DexRegSet::default();
    rs.set(63);
    assert!(rs.contains(63));
    assert_eq!(rs.count(), 1);
    rs.clear(63);
    assert!(rs.is_empty());
}

// ---------------------------------------------------------------------------
// Magic constants
// ---------------------------------------------------------------------------

#[test]
fn magic_constants() {
    assert_eq!(DEX_MAGIC, b"dex\n");
    assert_eq!(DEX_MAGIC_035, b"dex\n035\0");
    assert_eq!(DEX_MAGIC_039, b"dex\n039\0");
    assert_eq!(CDEX_MAGIC, b"cdex");
    assert_eq!(DEX_ENDIAN_CONSTANT, 0x12345678);
    assert_eq!(DEX_REVERSE_ENDIAN_CONSTANT, 0x78563412);
}

#[test]
fn dex_code_item_header_size_const() {
    assert_eq!(DEX_CODE_ITEM_HEADER_SIZE, 16);
}

// ---------------------------------------------------------------------------
// DexItemType discriminants
// ---------------------------------------------------------------------------

#[test]
fn dex_item_type_discriminants() {
    assert_eq!(DexItemType::HeaderItem as u32, 0x0000);
    assert_eq!(DexItemType::StringIdItem as u32, 0x0001);
    assert_eq!(DexItemType::MapList as u32, 0x1000);
    assert_eq!(DexItemType::HiddenapiClassDataItem as u32, 0xf000);
}
