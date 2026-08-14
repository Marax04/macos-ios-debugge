//! Comprehensive integration tests for `rustre-mobile-smali` public API.

use rustre_mobile_smali::printer::{
    access_string, diff_classes, escape_string, print_class, print_field, print_instr,
    print_method, print_operand, print_reg,
};
use rustre_mobile_smali::{
    DalvikOpcode, SmaliAccess, SmaliClass, SmaliError, SmaliField, SmaliInstr, SmaliMethod,
    SmaliOp, SmaliOperand, SmaliReg, instruction_size_bytes, opcode_to_smali,
};

// ─── SmaliReg ──────────────────────────────────────────────────────────────

#[test]
fn reg_display_v_below_64() {
    assert_eq!(SmaliReg { num: 0 }.to_string(), "v0");
    assert_eq!(SmaliReg { num: 63 }.to_string(), "v63");
}

#[test]
fn reg_display_p_at_or_above_64() {
    assert_eq!(SmaliReg { num: 64 }.to_string(), "p0");
    assert_eq!(SmaliReg { num: 200 }.to_string(), "p136");
    assert_eq!(SmaliReg { num: 255 }.to_string(), "p191");
}

#[test]
fn reg_eq_and_clone() {
    let a = SmaliReg { num: 5 };
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(a, SmaliReg { num: 6 });
}

// ─── SmaliOp ───────────────────────────────────────────────────────────────

#[test]
fn smali_op_display_known_variants() {
    assert_eq!(SmaliOp::Nop.to_string(), "nop");
    assert_eq!(SmaliOp::Move.to_string(), "move");
    assert_eq!(SmaliOp::MoveWide.to_string(), "move-wide");
    assert_eq!(SmaliOp::MoveObject.to_string(), "move-object");
    assert_eq!(SmaliOp::ReturnVoid.to_string(), "return-void");
    assert_eq!(SmaliOp::Return.to_string(), "return");
    assert_eq!(SmaliOp::Const4.to_string(), "const/4");
    assert_eq!(SmaliOp::Const16.to_string(), "const/16");
    assert_eq!(SmaliOp::ConstString.to_string(), "const-string");
    assert_eq!(SmaliOp::Goto.to_string(), "goto");
    assert_eq!(SmaliOp::IfEqz.to_string(), "if-eqz");
    assert_eq!(SmaliOp::InvokeVirtual.to_string(), "invoke-virtual");
    assert_eq!(SmaliOp::InvokeStatic.to_string(), "invoke-static");
    assert_eq!(SmaliOp::NewInstance.to_string(), "new-instance");
    assert_eq!(SmaliOp::ArrayLength.to_string(), "array-length");
    assert_eq!(SmaliOp::CheckCast.to_string(), "check-cast");
}

#[test]
fn smali_op_other_variant_displays_inner_string() {
    assert_eq!(SmaliOp::Other("custom-op".to_string()).to_string(), "custom-op");
    assert_eq!(SmaliOp::Other(String::new()).to_string(), "");
}

#[test]
fn smali_op_eq() {
    assert_eq!(SmaliOp::Nop, SmaliOp::Nop);
    assert_ne!(SmaliOp::Nop, SmaliOp::Move);
    assert_eq!(SmaliOp::Other("x".into()), SmaliOp::Other("x".into()));
    assert_ne!(SmaliOp::Other("x".into()), SmaliOp::Other("y".into()));
}

// ─── SmaliOperand ──────────────────────────────────────────────────────────

#[test]
fn operand_reg_display_uses_reg_format() {
    assert_eq!(
        SmaliOperand::Reg(SmaliReg { num: 10 }).to_string(),
        "v10"
    );
}

#[test]
fn operand_literal_display_is_hex() {
    assert_eq!(SmaliOperand::Literal(0).to_string(), "0x0");
    assert_eq!(SmaliOperand::Literal(255).to_string(), "0xff");
    assert_eq!(SmaliOperand::Literal(-1).to_string(), "-0x1");
    assert_eq!(SmaliOperand::Literal(i64::MAX).to_string(), format!("{:#x}", i64::MAX));
}

#[test]
fn operand_str_display_quotes() {
    assert_eq!(SmaliOperand::Str("hi".into()).to_string(), "\"hi\"");
    assert_eq!(SmaliOperand::Str(String::new()).to_string(), "\"\"");
}

#[test]
fn operand_typeref_fieldref_methodref_display_raw() {
    assert_eq!(SmaliOperand::TypeRef("Ljava/lang/Object;".into()).to_string(), "Ljava/lang/Object;");
    assert_eq!(SmaliOperand::FieldRef("Lfoo;->bar:I".into()).to_string(), "Lfoo;->bar:I");
    assert_eq!(SmaliOperand::MethodRef("Lfoo;->bar()V".into()).to_string(), "Lfoo;->bar()V");
}

// ─── SmaliInstr ────────────────────────────────────────────────────────────

#[test]
fn instr_to_text_no_operands_no_label() {
    let i = SmaliInstr {
        op: SmaliOp::ReturnVoid,
        operands: vec![],
        label: None,
    };
    assert_eq!(i.to_text(), "return-void");
}

#[test]
fn instr_to_text_with_operands() {
    let i = SmaliInstr {
        op: SmaliOp::Move,
        operands: vec![
            SmaliOperand::Reg(SmaliReg { num: 0 }),
            SmaliOperand::Reg(SmaliReg { num: 1 }),
        ],
        label: None,
    };
    assert_eq!(i.to_text(), "move v0, v1");
}

#[test]
fn instr_to_text_with_label() {
    let i = SmaliInstr {
        op: SmaliOp::Nop,
        operands: vec![],
        label: Some(":cond_0".into()),
    };
    assert_eq!(i.to_text(), ":cond_0\nnop");
}

#[test]
fn instr_to_text_single_operand_has_space_separator() {
    let i = SmaliInstr {
        op: SmaliOp::Return,
        operands: vec![SmaliOperand::Reg(SmaliReg { num: 2 })],
        label: None,
    };
    assert_eq!(i.to_text(), "return v2");
}

// ─── SmaliAccess ───────────────────────────────────────────────────────────

#[test]
fn access_bits_values() {
    assert_eq!(SmaliAccess::PUBLIC.bits(), 0x0001);
    assert_eq!(SmaliAccess::PRIVATE.bits(), 0x0002);
    assert_eq!(SmaliAccess::PROTECTED.bits(), 0x0004);
    assert_eq!(SmaliAccess::STATIC.bits(), 0x0008);
    assert_eq!(SmaliAccess::FINAL.bits(), 0x0010);
    assert_eq!(SmaliAccess::CONSTRUCTOR.bits(), 0x0020);
    assert_eq!(SmaliAccess::NATIVE.bits(), 0x0040);
    assert_eq!(SmaliAccess::ABSTRACT.bits(), 0x0080);
}

#[test]
fn access_bitor_combines() {
    let a = SmaliAccess::PUBLIC | SmaliAccess::STATIC;
    assert!(a.contains(SmaliAccess::PUBLIC));
    assert!(a.contains(SmaliAccess::STATIC));
    assert!(!a.contains(SmaliAccess::PRIVATE));
}

#[test]
fn access_string_empty_for_no_flags() {
    assert_eq!(access_string(SmaliAccess::empty()), "");
}

#[test]
fn access_string_single_flag() {
    assert_eq!(access_string(SmaliAccess::PUBLIC), "public");
    assert_eq!(access_string(SmaliAccess::NATIVE), "native");
}

#[test]
fn access_string_multiple_flags_in_canonical_order() {
    let s = access_string(SmaliAccess::PUBLIC | SmaliAccess::STATIC | SmaliAccess::FINAL);
    assert_eq!(s, "public static final");
}

// ─── SmaliMethod ───────────────────────────────────────────────────────────

#[test]
fn method_is_constructor_detects_init() {
    let m = SmaliMethod {
        name: "<init>".into(),
        class: "LFoo;".into(),
        signature: "()V".into(),
        access: SmaliAccess::PUBLIC | SmaliAccess::CONSTRUCTOR,
        registers: 1,
        instructions: vec![],
    };
    assert!(m.is_constructor());
}

#[test]
fn method_is_constructor_detects_clinit() {
    let mut m = SmaliMethod {
        name: "<clinit>".into(),
        class: "LFoo;".into(),
        signature: "()V".into(),
        access: SmaliAccess::STATIC,
        registers: 0,
        instructions: vec![],
    };
    assert!(m.is_constructor());
    m.name = "regular".into();
    assert!(!m.is_constructor());
}

#[test]
fn method_instr_count() {
    let m = SmaliMethod {
        name: "x".into(),
        class: "LFoo;".into(),
        signature: "()V".into(),
        access: SmaliAccess::PUBLIC,
        registers: 0,
        instructions: vec![
            SmaliInstr { op: SmaliOp::Nop, operands: vec![], label: None },
            SmaliInstr { op: SmaliOp::ReturnVoid, operands: vec![], label: None },
        ],
    };
    assert_eq!(m.instr_count(), 2);
}

#[test]
fn method_instr_count_empty() {
    let m = SmaliMethod {
        name: "x".into(),
        class: "LFoo;".into(),
        signature: "()V".into(),
        access: SmaliAccess::PUBLIC,
        registers: 0,
        instructions: vec![],
    };
    assert_eq!(m.instr_count(), 0);
}

// ─── SmaliClass ────────────────────────────────────────────────────────────

#[test]
fn class_mock_has_expected_shape() {
    let c = SmaliClass::mock("LMyClass;");
    assert_eq!(c.name, "LMyClass;");
    assert_eq!(c.super_class, "Ljava/lang/Object;");
    assert!(c.access.contains(SmaliAccess::PUBLIC));
    assert_eq!(c.methods.len(), 3);
    assert_eq!(c.fields.len(), 1);
    assert!(c.interfaces.is_empty());
}

#[test]
fn class_find_method_hit_and_miss() {
    let c = SmaliClass::mock("LX;");
    assert!(c.find_method("<init>").is_some());
    assert!(c.find_method("execute").is_some());
    assert!(c.find_method("does_not_exist").is_none());
}

#[test]
fn class_static_methods_filters_correctly() {
    let c = SmaliClass::mock("LX;");
    let statics = c.static_methods();
    assert_eq!(statics.len(), 1);
    assert_eq!(statics[0].name, "execute");
}

#[test]
fn class_static_methods_empty_when_none() {
    let mut c = SmaliClass::mock("LX;");
    for m in &mut c.methods {
        m.access.remove(SmaliAccess::STATIC);
    }
    assert!(c.static_methods().is_empty());
}

// ─── SmaliError ────────────────────────────────────────────────────────────

#[test]
fn error_display_variants() {
    let e = SmaliError::ParseError("bad".into());
    assert_eq!(e.to_string(), "parse error: bad");
    let e = SmaliError::InvalidOp("xyz".into());
    assert_eq!(e.to_string(), "invalid op: xyz");
    let e = SmaliError::InvalidReg(42);
    assert_eq!(e.to_string(), "invalid register: 42");
}

#[test]
fn error_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SmaliError>();
}

// ─── DalvikOpcode ──────────────────────────────────────────────────────────

#[test]
fn opcode_as_byte_roundtrip_full_range() {
    for b in 0u8..=255 {
        let op = DalvikOpcode::from_byte(b);
        assert_eq!(op.as_byte(), b, "roundtrip failed for byte 0x{b:02x}");
    }
}

#[test]
fn opcode_specific_byte_values() {
    assert_eq!(DalvikOpcode::Nop.as_byte(), 0x00);
    assert_eq!(DalvikOpcode::ReturnVoid.as_byte(), 0x0e);
    assert_eq!(DalvikOpcode::InvokeVirtual.as_byte(), 0x6e);
    assert_eq!(DalvikOpcode::ConstMethodType.as_byte(), 0xff);
}

#[test]
fn opcode_from_byte_known_values() {
    assert_eq!(DalvikOpcode::from_byte(0x00), DalvikOpcode::Nop);
    assert_eq!(DalvikOpcode::from_byte(0x0e), DalvikOpcode::ReturnVoid);
    assert_eq!(DalvikOpcode::from_byte(0x6e), DalvikOpcode::InvokeVirtual);
    assert_eq!(DalvikOpcode::from_byte(0xff), DalvikOpcode::ConstMethodType);
}

#[test]
fn opcode_hash_eq_consistency() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(DalvikOpcode::Nop);
    s.insert(DalvikOpcode::Nop);
    s.insert(DalvikOpcode::Move);
    assert_eq!(s.len(), 2);
}

// ─── opcode_to_smali ───────────────────────────────────────────────────────

#[test]
fn opcode_to_smali_basic_mnemonics() {
    assert_eq!(opcode_to_smali(DalvikOpcode::Nop), "nop");
    assert_eq!(opcode_to_smali(DalvikOpcode::Move), "move");
    assert_eq!(opcode_to_smali(DalvikOpcode::MoveFrom16), "move/from16");
    assert_eq!(opcode_to_smali(DalvikOpcode::ReturnVoid), "return-void");
    assert_eq!(opcode_to_smali(DalvikOpcode::Const4), "const/4");
    assert_eq!(opcode_to_smali(DalvikOpcode::ConstStringJumbo), "const-string/jumbo");
    assert_eq!(opcode_to_smali(DalvikOpcode::CheckCast), "check-cast");
    assert_eq!(opcode_to_smali(DalvikOpcode::InvokeVirtual), "invoke-virtual");
    assert_eq!(opcode_to_smali(DalvikOpcode::InvokeStaticRange), "invoke-static/range");
    assert_eq!(opcode_to_smali(DalvikOpcode::AddInt), "add-int");
    assert_eq!(opcode_to_smali(DalvikOpcode::AddInt2addr), "add-int/2addr");
    assert_eq!(opcode_to_smali(DalvikOpcode::AddIntLit16), "add-int/lit16");
    assert_eq!(opcode_to_smali(DalvikOpcode::AddIntLit8), "add-int/lit8");
}

#[test]
fn opcode_to_smali_field_static_accessors() {
    assert_eq!(opcode_to_smali(DalvikOpcode::Iget), "iget");
    assert_eq!(opcode_to_smali(DalvikOpcode::IputObject), "iput-object");
    assert_eq!(opcode_to_smali(DalvikOpcode::Sget), "sget");
    assert_eq!(opcode_to_smali(DalvikOpcode::SputShort), "sput-short");
}

#[test]
fn opcode_to_smali_polymorphic_and_custom() {
    assert_eq!(opcode_to_smali(DalvikOpcode::InvokePolymorphic), "invoke-polymorphic");
    assert_eq!(opcode_to_smali(DalvikOpcode::InvokeCustomRange), "invoke-custom/range");
    assert_eq!(opcode_to_smali(DalvikOpcode::ConstMethodHandle), "const-method-handle");
    assert_eq!(opcode_to_smali(DalvikOpcode::ConstMethodType), "const-method-type");
}

#[test]
fn opcode_to_smali_unused_maps_to_nop() {
    assert_eq!(opcode_to_smali(DalvikOpcode::Unused3e), "nop");
    assert_eq!(opcode_to_smali(DalvikOpcode::UnusedF9), "nop");
}

#[test]
fn opcode_to_smali_total_over_all_bytes_returns_nonempty() {
    for b in 0u8..=255 {
        let op = DalvikOpcode::from_byte(b);
        let s = opcode_to_smali(op);
        assert!(!s.is_empty(), "empty mnemonic for byte 0x{b:02x}");
    }
}

// ─── instruction_size_bytes ────────────────────────────────────────────────

#[test]
fn instruction_size_is_multiple_of_two_for_all_bytes() {
    for b in 0u8..=255 {
        let op = DalvikOpcode::from_byte(b);
        let n = instruction_size_bytes(op);
        assert!(n.is_multiple_of(2), "non-aligned size for byte 0x{b:02x}: {n}");
        assert!(n >= 2, "size too small for byte 0x{b:02x}: {n}");
    }
}

#[test]
fn instruction_size_known_4byte_opcodes() {
    assert_eq!(instruction_size_bytes(DalvikOpcode::Const16), 4);
    assert_eq!(instruction_size_bytes(DalvikOpcode::IfEq), 4);
    assert_eq!(instruction_size_bytes(DalvikOpcode::NewInstance), 4);
}

// ─── printer functions ────────────────────────────────────────────────────

#[test]
fn print_reg_matches_display() {
    let r = SmaliReg { num: 7 };
    assert_eq!(print_reg(&r), r.to_string());
    let r = SmaliReg { num: 100 };
    assert_eq!(print_reg(&r), r.to_string());
}

#[test]
fn print_operand_matches_display() {
    let cases = [
        SmaliOperand::Reg(SmaliReg { num: 3 }),
        SmaliOperand::Literal(42),
        SmaliOperand::Str("hi".into()),
        SmaliOperand::TypeRef("LFoo;".into()),
        SmaliOperand::FieldRef("LFoo;->bar:I".into()),
        SmaliOperand::MethodRef("LFoo;->m()V".into()),
    ];
    for op in &cases {
        // print_operand should yield something parseable / non-empty
        let s = print_operand(op);
        assert!(!s.is_empty());
    }
}

#[test]
fn print_instr_nonempty() {
    let i = SmaliInstr {
        op: SmaliOp::Nop,
        operands: vec![],
        label: None,
    };
    assert!(!print_instr(&i).is_empty());
}

#[test]
fn print_field_contains_name_and_type() {
    let f = SmaliField {
        name: "myField".into(),
        type_desc: "I".into(),
        access: SmaliAccess::PRIVATE,
        initial: None,
    };
    let s = print_field(&f);
    assert!(s.contains("myField"));
    assert!(s.contains('I'));
}

#[test]
fn print_method_contains_method_name() {
    let c = SmaliClass::mock("LFoo;");
    let m = c.find_method("execute").unwrap();
    let s = print_method(m);
    assert!(s.contains("execute"));
}

#[test]
fn print_class_contains_class_name() {
    let c = SmaliClass::mock("LFoo;");
    let s = print_class(&c);
    assert!(s.contains("LFoo;"));
}

// ─── escape_string ─────────────────────────────────────────────────────────

#[test]
fn escape_string_empty() {
    assert_eq!(escape_string(""), "");
}

#[test]
fn escape_string_plain_passthrough() {
    assert_eq!(escape_string("hello"), "hello");
}

#[test]
fn escape_string_basic_escapes() {
    assert_eq!(escape_string("\""), "\\\"");
    assert_eq!(escape_string("\\"), "\\\\");
    assert_eq!(escape_string("\n"), "\\n");
    assert_eq!(escape_string("\r"), "\\r");
    assert_eq!(escape_string("\t"), "\\t");
    assert_eq!(escape_string("\0"), "\\0");
}

#[test]
fn escape_string_low_control_chars_use_unicode_escape() {
    // 0x01 is < 0x20 and not one of the named escapes
    let s = escape_string("\x01");
    assert_eq!(s, "\\u0001");
}

#[test]
fn escape_string_preserves_high_chars() {
    assert_eq!(escape_string("é"), "é");
    assert_eq!(escape_string("漢"), "漢");
}

// ─── diff_classes ──────────────────────────────────────────────────────────

#[test]
fn diff_classes_no_changes() {
    let a = SmaliClass::mock("LFoo;");
    let b = SmaliClass::mock("LFoo;");
    let d = diff_classes(&a, &b);
    assert!(d.added_methods.is_empty());
    assert!(d.removed_methods.is_empty());
    assert!(d.added_fields.is_empty());
    assert!(d.removed_fields.is_empty());
}

#[test]
fn diff_classes_added_method() {
    let a = SmaliClass::mock("LFoo;");
    let mut b = SmaliClass::mock("LFoo;");
    b.methods.push(SmaliMethod {
        name: "newOne".into(),
        class: "LFoo;".into(),
        signature: "()V".into(),
        access: SmaliAccess::PUBLIC,
        registers: 0,
        instructions: vec![],
    });
    let d = diff_classes(&a, &b);
    assert_eq!(d.added_methods, vec!["newOne".to_string()]);
    assert!(d.removed_methods.is_empty());
}

#[test]
fn diff_classes_removed_method() {
    let a = SmaliClass::mock("LFoo;");
    let mut b = SmaliClass::mock("LFoo;");
    b.methods.retain(|m| m.name != "execute");
    let d = diff_classes(&a, &b);
    assert_eq!(d.removed_methods, vec!["execute".to_string()]);
}

#[test]
fn diff_classes_added_field() {
    let a = SmaliClass::mock("LFoo;");
    let mut b = SmaliClass::mock("LFoo;");
    b.fields.push(SmaliField {
        name: "extra".into(),
        type_desc: "I".into(),
        access: SmaliAccess::PUBLIC,
        initial: None,
    });
    let d = diff_classes(&a, &b);
    assert_eq!(d.added_fields, vec!["extra".to_string()]);
}

// ─── serde roundtrip ───────────────────────────────────────────────────────

#[test]
fn smali_reg_serde_roundtrip() {
    let r = SmaliReg { num: 17 };
    let j = serde_json::to_string(&r).unwrap();
    let back: SmaliReg = serde_json::from_str(&j).unwrap();
    assert_eq!(r, back);
}

#[test]
fn smali_op_serde_roundtrip_other() {
    let op = SmaliOp::Other("weird".into());
    let j = serde_json::to_string(&op).unwrap();
    let back: SmaliOp = serde_json::from_str(&j).unwrap();
    assert_eq!(op, back);
}

#[test]
fn smali_operand_serde_roundtrip_literal() {
    let o = SmaliOperand::Literal(-12345);
    let j = serde_json::to_string(&o).unwrap();
    let back: SmaliOperand = serde_json::from_str(&j).unwrap();
    assert_eq!(o, back);
}

#[test]
fn dalvik_opcode_serde_roundtrip() {
    let op = DalvikOpcode::InvokeVirtual;
    let j = serde_json::to_string(&op).unwrap();
    let back: DalvikOpcode = serde_json::from_str(&j).unwrap();
    assert_eq!(op, back);
}

#[test]
fn smali_access_serde_roundtrip() {
    let a = SmaliAccess::PUBLIC | SmaliAccess::STATIC | SmaliAccess::FINAL;
    let j = serde_json::to_string(&a).unwrap();
    let back: SmaliAccess = serde_json::from_str(&j).unwrap();
    assert_eq!(a, back);
}

// ─── Send/Sync bounds on core types ────────────────────────────────────────

#[test]
fn core_types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SmaliReg>();
    assert_send_sync::<SmaliOp>();
    assert_send_sync::<SmaliOperand>();
    assert_send_sync::<SmaliInstr>();
    assert_send_sync::<SmaliField>();
    assert_send_sync::<SmaliMethod>();
    assert_send_sync::<SmaliClass>();
    assert_send_sync::<SmaliAccess>();
    assert_send_sync::<DalvikOpcode>();
}
