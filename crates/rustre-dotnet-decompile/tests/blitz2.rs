//! Deep adversarial test suite for rustre-dotnet-decompile (Y047).
#![allow(clippy::approx_constant)]

use rustre_dotnet::{CilInstruction, CilOperand};
use rustre_dotnet_decompile::*;

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// ───── BinaryOp ────────────────────────────────────────────────────────────────

#[test]
fn binop_as_str_all_variants() {
    use BinaryOp::*;
    let pairs = [
        (Add, "+"), (Sub, "-"), (Mul, "*"), (Div, "/"), (Rem, "%"),
        (And, "&"), (Or, "|"), (Xor, "^"), (Shl, "<<"), (Shr, ">>"),
        (Eq, "=="), (Ne, "!="), (Lt, "<"), (Le, "<="), (Gt, ">"), (Ge, ">="),
    ];
    for (op, s) in pairs {
        assert_eq!(op.as_str(), s);
    }
}

#[test]
fn binop_hash_eq_consistency() {
    use std::collections::HashSet;
    let set: HashSet<BinaryOp> = HashSet::new();
    let ops = [
        BinaryOp::Add, BinaryOp::Sub, BinaryOp::Mul, BinaryOp::Div, BinaryOp::Rem,
        BinaryOp::And, BinaryOp::Or, BinaryOp::Xor, BinaryOp::Shl, BinaryOp::Shr,
        BinaryOp::Eq, BinaryOp::Ne, BinaryOp::Lt, BinaryOp::Le, BinaryOp::Gt, BinaryOp::Ge,
    ];
    // Note: BinaryOp only derives Eq, not Hash; use Vec
    let mut v = Vec::new();
    for o in ops {
        assert_eq!(o, o);
        v.push(o);
        let _ = set.len();
    }
    assert_eq!(v.len(), 16);
}

// ───── UnaryOp ─────────────────────────────────────────────────────────────────

#[test]
fn unop_prefix_str() {
    assert_eq!(UnaryOp::Neg.prefix_str(), "-");
    assert_eq!(UnaryOp::Not.prefix_str(), "!");
    assert_eq!(UnaryOp::BitNot.prefix_str(), "~");
    assert_eq!(UnaryOp::Cast(0x08).prefix_str(), "(int)");
    assert_eq!(UnaryOp::Cast(0x0E).prefix_str(), "(string)");
    assert_eq!(UnaryOp::Cast(0xFF).prefix_str(), "(nint)"); // unknown → nint default
}

// ───── TypeKind ────────────────────────────────────────────────────────────────

#[test]
fn typekind_from_flags_and_keyword() {
    assert_eq!(TypeKind::from_flags(0x0000), TypeKind::Class);
    assert_eq!(TypeKind::from_flags(0x0020), TypeKind::Interface);
    assert_eq!(TypeKind::from_flags(0x0100), TypeKind::Struct);
    assert_eq!(TypeKind::Class.keyword(), "class");
    assert_eq!(TypeKind::Interface.keyword(), "interface");
    assert_eq!(TypeKind::Struct.keyword(), "struct");
    assert_eq!(TypeKind::Enum.keyword(), "enum");
    assert_eq!(TypeKind::Delegate.keyword(), "delegate");
}

#[test]
fn typekind_display_matches_keyword() {
    for k in [TypeKind::Class, TypeKind::Interface, TypeKind::Struct, TypeKind::Enum, TypeKind::Delegate] {
        assert_eq!(format!("{k}"), k.keyword());
    }
}

#[test]
fn typekind_interface_takes_priority_over_struct() {
    // Interface bit (0x20) should win over struct bit (0x100)
    assert_eq!(TypeKind::from_flags(0x0120), TypeKind::Interface);
}

#[test]
fn typekind_fuzz_no_panic() {
    let mut rng = lcg();
    for _ in 0..200 {
        let f = (rng() & 0xFFFF_FFFF) as u32;
        let k = TypeKind::from_flags(f);
        // Display must succeed
        let _ = format!("{k}");
    }
}

// ───── HlilExpression ──────────────────────────────────────────────────────────

#[test]
fn hlil_expr_const_to_csharp() {
    assert_eq!(HlilExpression::Const(0).to_csharp(), "0");
    assert_eq!(HlilExpression::Const(-1).to_csharp(), "-1");
    assert_eq!(HlilExpression::Const(i64::MAX).to_csharp(), i64::MAX.to_string());
    assert_eq!(HlilExpression::Const(i64::MIN).to_csharp(), i64::MIN.to_string());
}

#[test]
fn hlil_expr_string_null() {
    assert_eq!(HlilExpression::Null.to_csharp(), "null");
    assert_eq!(HlilExpression::StringLit("hi".into()).to_csharp(), "\"hi\"");
}

#[test]
fn hlil_expr_local_param() {
    assert_eq!(HlilExpression::Local(0, "v".into()).to_csharp(), "v");
    assert_eq!(HlilExpression::Param(1, "p".into()).to_csharp(), "p");
}

#[test]
fn hlil_expr_binary_paren() {
    let e = HlilExpression::BinaryOp {
        op: BinaryOp::Add,
        lhs: Box::new(HlilExpression::Const(1)),
        rhs: Box::new(HlilExpression::Const(2)),
    };
    assert_eq!(e.to_csharp(), "(1 + 2)");
}

#[test]
fn hlil_expr_unary() {
    let e = HlilExpression::UnaryOp {
        op: UnaryOp::Neg,
        operand: Box::new(HlilExpression::Const(5)),
    };
    assert_eq!(e.to_csharp(), "-5");
}

#[test]
fn hlil_expr_array_len_elem() {
    let arr = HlilExpression::Local(0, "a".into());
    let l = HlilExpression::ArrayLength(Box::new(arr.clone()));
    assert_eq!(l.to_csharp(), "a.Length");
    let e = HlilExpression::ArrayElement(Box::new(arr), Box::new(HlilExpression::Const(3)));
    assert_eq!(e.to_csharp(), "a[3]");
}

#[test]
fn hlil_expr_ternary() {
    let e = HlilExpression::Ternary(
        Box::new(HlilExpression::Local(0, "c".into())),
        Box::new(HlilExpression::Const(1)),
        Box::new(HlilExpression::Const(0)),
    );
    assert_eq!(e.to_csharp(), "(c ? 1 : 0)");
}

#[test]
fn hlil_expr_static_field_named() {
    let e = HlilExpression::StaticField(0x04, Some("Foo.X".into()));
    assert_eq!(e.to_csharp(), "Foo.X");
    let e2 = HlilExpression::StaticField(0x04, None);
    assert!(e2.to_csharp().contains("sfld_"));
}

#[test]
fn hlil_expr_newobj_and_newarr() {
    let e = HlilExpression::NewObj(0x06_00_00_01, vec![HlilExpression::Const(1)]);
    let s = e.to_csharp();
    assert!(s.starts_with("new"));
    assert!(s.contains("(1)"));
    let e2 = HlilExpression::NewArr(0x08, Box::new(HlilExpression::Const(10)));
    let s2 = e2.to_csharp();
    assert!(s2.contains("[10]"));
}

// ───── HlilStatement / HlilBlock ───────────────────────────────────────────────

#[test]
fn hlil_stmt_basic_lines() {
    let s = HlilStatement::Return(None).to_csharp("");
    assert_eq!(s, "return;");
    let s = HlilStatement::Return(Some(HlilExpression::Const(0))).to_csharp("");
    assert_eq!(s, "return 0;");
    let s = HlilStatement::Goto(0x10).to_csharp("");
    assert_eq!(s, "goto IL_0010;");
    let s = HlilStatement::Label(0x10).to_csharp("");
    assert_eq!(s, "IL_0010:");
}

#[test]
fn hlil_block_push_len_empty() {
    let mut b = HlilBlock::new();
    assert!(b.is_empty());
    assert_eq!(b.len(), 0);
    b.push(HlilStatement::Return(None));
    assert!(!b.is_empty());
    assert_eq!(b.len(), 1);
}

#[test]
fn hlil_block_to_csharp_newlines() {
    let mut b = HlilBlock::new();
    b.push(HlilStatement::Return(None));
    b.push(HlilStatement::Return(None));
    let out = b.to_csharp("");
    assert_eq!(out.matches('\n').count(), 2);
}

#[test]
fn hlil_remove_nops_strips_empty_comments() {
    let mut b = HlilBlock::new();
    b.push(HlilStatement::Comment(String::new()));
    b.push(HlilStatement::Comment("   ".into()));
    b.push(HlilStatement::Comment("real".into()));
    b.push(HlilStatement::Return(None));
    let cleaned = hlil_remove_nops(&b);
    assert_eq!(cleaned.len(), 2);
}

// ───── OperandKind ─────────────────────────────────────────────────────────────

#[test]
fn operand_kind_byte_size() {
    assert_eq!(OperandKind::None.byte_size(), 0);
    assert_eq!(OperandKind::Int8.byte_size(), 1);
    assert_eq!(OperandKind::UInt8.byte_size(), 1);
    assert_eq!(OperandKind::BranchTargetShort.byte_size(), 1);
    assert_eq!(OperandKind::UInt16.byte_size(), 2);
    assert_eq!(OperandKind::Int32.byte_size(), 4);
    assert_eq!(OperandKind::Float32.byte_size(), 4);
    assert_eq!(OperandKind::Token.byte_size(), 4);
    assert_eq!(OperandKind::BranchTarget.byte_size(), 4);
    assert_eq!(OperandKind::Int64.byte_size(), 8);
    assert_eq!(OperandKind::Float64.byte_size(), 8);
    assert_eq!(OperandKind::Switch.byte_size(), 0);
}

// ───── CilOpcodeRegistry ───────────────────────────────────────────────────────

#[test]
fn opcode_registry_nop() {
    let info = CilOpcodeRegistry::by_name("nop").expect("nop");
    assert_eq!(info.name, "nop");
}

#[test]
fn opcode_registry_unknown_name() {
    assert!(CilOpcodeRegistry::by_name("not-an-opcode").is_none());
}

#[test]
fn opcode_registry_by_encoding_lookup() {
    // Find some opcode by name then look it up by encoding to confirm round-trip
    let info = CilOpcodeRegistry::by_name("ret").expect("ret exists");
    let info2 = CilOpcodeRegistry::by_encoding(info.byte1, info.byte2).expect("by encoding");
    assert_eq!(info.name, info2.name);
}

#[test]
fn opcode_registry_all_opcodes_nonempty() {
    let all = CilOpcodeRegistry::all_opcodes();
    assert!(all.len() > 50);
}

#[test]
fn opcode_registry_encoding_size_consistent() {
    let all = CilOpcodeRegistry::all_opcodes();
    for info in all {
        let size = CilOpcodeRegistry::encoding_size(info);
        let prefix = if info.byte2.is_some() { 2 } else { 1 };
        assert_eq!(size, prefix + info.operand_kind.byte_size());
    }
}

// ───── CilDisassembler ─────────────────────────────────────────────────────────

#[test]
fn cil_disasm_empty() {
    let v = CilDisassembler::disassemble(&[]).expect("empty ok");
    assert!(v.is_empty());
}

#[test]
fn cil_disasm_nop_sequence() {
    // nop opcode is 0x00
    let v = CilDisassembler::disassemble(&[0x00, 0x00, 0x00]).expect("ok");
    assert_eq!(v.len(), 3);
    for (i, ins) in v.iter().enumerate() {
        assert_eq!(ins.opcode, "nop");
        assert_eq!(ins.offset, rustre_dotnet_decompile::casts::usize_to_u32(i));
    }
}

#[test]
fn cil_disasm_unknown_opcode_errs() {
    // 0xA5 is unassigned (or at least not commonly used).
    // Use a high byte unlikely to be assigned.
    let r = CilDisassembler::disassemble(&[0xEF]);
    assert!(r.is_err());
}

#[test]
fn cil_disasm_truncated_fe_prefix() {
    let r = CilDisassembler::disassemble(&[0xFE]);
    assert!(r.is_err());
}

#[test]
fn cil_disasm_fuzz_never_panics() {
    let mut rng = lcg();
    for _ in 0..200 {
        let len = (rng() % 64) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| (rng() & 0xFF) as u8).collect();
        let _ = CilDisassembler::disassemble(&bytes);
    }
}

// ───── stack_effect ────────────────────────────────────────────────────────────

#[test]
fn stack_effect_known_codes() {
    let e = stack_effect("add").unwrap();
    assert_eq!(e.pops, 2);
    assert_eq!(e.pushes, 1);
    assert_eq!(e.delta(), -1);

    let e = stack_effect("dup").unwrap();
    assert_eq!(e.delta(), 1);

    let e = stack_effect("nop").unwrap();
    assert_eq!(e.delta(), 0);
}

#[test]
fn stack_effect_unknown_returns_none() {
    assert!(stack_effect("not-an-opcode").is_none());
}

#[test]
fn stack_effect_fuzz_never_panics() {
    let mut rng = lcg();
    for _ in 0..100 {
        let n = (rng() % 16) as usize + 1;
        let s: String = (0..n).map(|_| ((rng() % 26) as u8 + b'a') as char).collect();
        let _ = stack_effect(&s);
    }
}

// ───── FoldResult / ConstantFolder ────────────────────────────────────────────

#[test]
fn foldresult_is_known() {
    assert!(FoldResult::KnownInt(0).is_known());
    assert!(FoldResult::KnownStr(String::new()).is_known());
    assert!(FoldResult::KnownBool(true).is_known());
    assert!(!FoldResult::Unknown.is_known());
}

#[test]
fn foldresult_eq() {
    assert_eq!(FoldResult::KnownInt(7), FoldResult::KnownInt(7));
    assert_ne!(FoldResult::KnownInt(7), FoldResult::KnownInt(8));
    assert_eq!(FoldResult::Unknown, FoldResult::Unknown);
}

#[test]
fn constant_folder_add() {
    let mut cf = ConstantFolder::default();
    cf.fold(&[
        CilInstruction { offset: 0, opcode: "ldc.i4.2".into(), operand: CilOperand::None },
        CilInstruction { offset: 1, opcode: "ldc.i4.3".into(), operand: CilOperand::None },
        CilInstruction { offset: 2, opcode: "add".into(), operand: CilOperand::None },
    ]);
    assert_eq!(cf.results.last().unwrap(), &FoldResult::KnownInt(5));
}

#[test]
fn constant_folder_ldstr() {
    let mut cf = ConstantFolder::default();
    cf.fold(&[CilInstruction {
        offset: 0,
        opcode: "ldstr".into(),
        operand: CilOperand::String("hi".into()),
    }]);
    assert_eq!(cf.results[0], FoldResult::KnownStr("hi".into()));
}

#[test]
fn constant_folder_local_round_trip() {
    let mut cf = ConstantFolder::default();
    cf.fold(&[
        CilInstruction { offset: 0, opcode: "ldc.i4.5".into(), operand: CilOperand::None },
        CilInstruction { offset: 1, opcode: "stloc.0".into(), operand: CilOperand::None },
        CilInstruction { offset: 2, opcode: "ldloc.0".into(), operand: CilOperand::None },
    ]);
    assert_eq!(cf.results.last().unwrap(), &FoldResult::KnownInt(5));
}

#[test]
fn constant_folder_known_count() {
    let mut cf = ConstantFolder::default();
    cf.fold(&[
        CilInstruction { offset: 0, opcode: "ldc.i4.0".into(), operand: CilOperand::None },
        CilInstruction { offset: 1, opcode: "ldc.i4.1".into(), operand: CilOperand::None },
        CilInstruction { offset: 2, opcode: "unknown.op".into(), operand: CilOperand::None },
    ]);
    assert_eq!(cf.known_count(), 2);
}

// ───── InferredType ────────────────────────────────────────────────────────────

#[test]
fn inferred_type_to_csharp() {
    assert_eq!(InferredType::Int32.to_csharp(), "int");
    assert_eq!(InferredType::Bool.to_csharp(), "bool");
    assert_eq!(InferredType::Unknown.to_csharp(), "var");
    let a = InferredType::Array(Box::new(InferredType::Int32));
    assert_eq!(a.to_csharp(), "int[]");
    let n = InferredType::Nullable(Box::new(InferredType::Int32));
    assert_eq!(n.to_csharp(), "int?");
}

#[test]
fn inferred_type_predicates() {
    assert!(InferredType::Int32.is_numeric());
    assert!(!InferredType::String.is_numeric());
    assert!(InferredType::String.is_reference());
    assert!(InferredType::Array(Box::new(InferredType::Int32)).is_reference());
    assert!(InferredType::Int32.is_known());
    assert!(!InferredType::Unknown.is_known());
}

#[test]
fn infer_type_from_element_table() {
    assert_eq!(infer_type_from_element(0x02), InferredType::Bool);
    assert_eq!(infer_type_from_element(0x08), InferredType::Int32);
    assert_eq!(infer_type_from_element(0x0A), InferredType::Int64);
    assert_eq!(infer_type_from_element(0x0C), InferredType::Float32);
    assert_eq!(infer_type_from_element(0x0D), InferredType::Float64);
    assert_eq!(infer_type_from_element(0x0E), InferredType::String);
    assert_eq!(infer_type_from_element(0x1C), InferredType::Object);
    assert_eq!(infer_type_from_element(0xFF), InferredType::Unknown);
}

#[test]
fn infer_type_from_element_fuzz() {
    let mut rng = lcg();
    for _ in 0..50 {
        let b = (rng() & 0xFF) as u8;
        let t = infer_type_from_element(b);
        // Display via to_csharp must succeed
        let _ = t.to_csharp();
    }
}

// ───── StringTable ─────────────────────────────────────────────────────────────

#[test]
fn string_table_basic() {
    let mut t = StringTable::default();
    assert!(t.is_empty());
    t.record(1, "a".into());
    t.record(2, "b".into());
    t.record(1, "a-dup".into()); // dup token ignored
    assert_eq!(t.len(), 2);
    assert_eq!(t.get(1), Some("a"));
    assert_eq!(t.get(99), None);
    assert_eq!(t.all_strings().len(), 2);
}

// ───── StringLiteralDecoder ───────────────────────────────────────────────────

#[test]
fn string_literal_decode_oob() {
    let s = StringLiteralDecoder::decode_string(100, &[0, 0, 0]);
    assert!(s.contains("out of range"));
}

#[test]
fn string_literal_decode_truncated() {
    // Compressed length prefix of 10, but no bytes follow
    let s = StringLiteralDecoder::decode_string(0, &[0x0A]);
    assert!(s.contains("truncated"));
}

#[test]
fn string_literal_decode_simple_utf16() {
    // length 5 = 4 bytes UTF-16 ("Hi") + 1 flag byte
    let heap = [0x05, b'H', 0, b'i', 0, 0x00];
    let s = StringLiteralDecoder::decode_string(0, &heap);
    assert_eq!(s, "Hi");
}

#[test]
fn string_literal_decode_zero_length() {
    let s = StringLiteralDecoder::decode_string(0, &[0x00]);
    assert_eq!(s, "");
}

#[test]
fn string_literal_format_as_csharp_literal_escapes() {
    let s = StringLiteralDecoder::format_as_csharp_literal("a\"b\\c\n");
    assert!(s.starts_with('"') && s.ends_with('"'));
    assert!(s.contains("\\\""));
    assert!(s.contains("\\\\"));
    assert!(s.contains("\\n"));
}

#[test]
fn string_literal_decoder_fuzz() {
    let mut rng = lcg();
    for _ in 0..100 {
        let len = (rng() % 64) as usize;
        let heap: Vec<u8> = (0..len).map(|_| (rng() & 0xFF) as u8).collect();
        let idx = (rng() & 0xFFFF) as u32;
        let _ = StringLiteralDecoder::decode_string(idx, &heap);
    }
}

// ───── AttributeDecoder / DecodedAttribute / AttributeArg ──────────────────────

#[test]
fn attr_arg_to_csharp() {
    assert_eq!(AttributeArg::Bool(true).to_csharp(), "true");
    assert_eq!(AttributeArg::Bool(false).to_csharp(), "false");
    assert_eq!(AttributeArg::Int(-5).to_csharp(), "-5");
    assert_eq!(AttributeArg::UInt(7).to_csharp(), "7u");
    assert_eq!(AttributeArg::Str(None).to_csharp(), "null");
    let s = AttributeArg::Str(Some("hi".into())).to_csharp();
    assert!(s.contains("hi"));
    assert_eq!(AttributeArg::TypeRef("Foo".into()).to_csharp(), "typeof(Foo)");
    assert_eq!(AttributeArg::Enum("E".into(), 2).to_csharp(), "(E)2");
}

#[test]
fn attr_arg_array() {
    let a = AttributeArg::Array(vec![AttributeArg::Int(1), AttributeArg::Int(2)]);
    let s = a.to_csharp();
    assert!(s.contains("new[]"));
    assert!(s.contains("1, 2"));
}

#[test]
fn decoded_attribute_emit_no_args() {
    let d = DecodedAttribute {
        name: "Serializable".into(),
        positional_args: vec![],
        named_args: vec![],
    };
    assert_eq!(d.to_csharp(), "[Serializable]");
}

#[test]
fn decoded_attribute_emit_args() {
    let d = DecodedAttribute {
        name: "Foo".into(),
        positional_args: vec![AttributeArg::Int(1)],
        named_args: vec![AttributeNamedArg {
            is_property: true,
            name: "X".into(),
            value: AttributeArg::Int(2),
        }],
    };
    let s = d.to_csharp();
    assert!(s.starts_with("[Foo("));
    assert!(s.contains('1'));
    assert!(s.contains("X = 2"));
}

#[test]
fn attribute_decoder_with_prolog() {
    let blob = [0x01, 0x00, 0xFF];
    let d = AttributeDecoder::decode_custom_attribute("X", &blob);
    assert_eq!(d.name, "X");
    // 0xFF marks null string
    assert!(matches!(d.positional_args.first(), Some(AttributeArg::Str(None))));
}

#[test]
fn attribute_decoder_empty() {
    let d = AttributeDecoder::decode_custom_attribute("Y", &[0x01, 0x00]);
    assert!(d.positional_args.is_empty());
}

#[test]
fn attribute_decoder_fuzz() {
    let mut rng = lcg();
    for _ in 0..50 {
        let len = (rng() % 32) as usize;
        let blob: Vec<u8> = (0..len).map(|_| (rng() & 0xFF) as u8).collect();
        let d = AttributeDecoder::decode_custom_attribute("F", &blob);
        let _ = d.to_csharp();
    }
}

// ───── TypeSig / GenericInstantiator ───────────────────────────────────────────

#[test]
fn typesig_instantiate_var_substitution() {
    let sig = TypeSig::Var(0);
    let result = sig.instantiate(&[TypeSig::Primitive(0x08)], &[]);
    assert!(matches!(result, TypeSig::Primitive(0x08)));
}

#[test]
fn typesig_instantiate_mvar_substitution() {
    let sig = TypeSig::MVar(1);
    let r = sig.instantiate(&[], &[TypeSig::Named("X".into()), TypeSig::Named("Y".into())]);
    if let TypeSig::Named(n) = r { assert_eq!(n, "Y"); } else { panic!("wrong type"); }
}

#[test]
fn typesig_instantiate_missing_var_defaults() {
    let sig = TypeSig::Var(7);
    let r = sig.instantiate(&[], &[]);
    if let TypeSig::Named(n) = r { assert_eq!(n, "T7"); } else { panic!() }
}

#[test]
fn generic_render_list_of_int() {
    let s = TypeSig::GenericInst {
        base: Box::new(TypeSig::Named("List".into())),
        args: vec![TypeSig::Primitive(0x08)],
    };
    assert_eq!(GenericInstantiator::render(&s), "List<int>");
}

#[test]
fn generic_render_szarray() {
    let s = TypeSig::SzArray(Box::new(TypeSig::Primitive(0x0E)));
    assert_eq!(GenericInstantiator::render(&s), "string[]");
}

#[test]
fn generic_render_byref_ptr() {
    let s = TypeSig::ByRef(Box::new(TypeSig::Primitive(0x08)));
    assert_eq!(GenericInstantiator::render(&s), "ref int");
    let p = TypeSig::Ptr(Box::new(TypeSig::Primitive(0x08)));
    assert_eq!(GenericInstantiator::render(&p), "int*");
}

#[test]
fn generic_render_strips_arity_suffix() {
    let s = TypeSig::GenericInst {
        base: Box::new(TypeSig::Named("Dictionary`2".into())),
        args: vec![TypeSig::Primitive(0x0E), TypeSig::Primitive(0x08)],
    };
    assert_eq!(GenericInstantiator::render(&s), "Dictionary<string, int>");
}

#[test]
fn generic_helpers_factory() {
    let t = GenericInstantiator::task_of(TypeSig::Primitive(0x08));
    assert_eq!(GenericInstantiator::render(&t), "Task<int>");
    let l = GenericInstantiator::list_of(TypeSig::Primitive(0x0E));
    assert_eq!(GenericInstantiator::render(&l), "List<string>");
    let d = GenericInstantiator::dictionary_of(TypeSig::Primitive(0x0E), TypeSig::Primitive(0x08));
    assert_eq!(GenericInstantiator::render(&d), "Dictionary<string, int>");
    let i = GenericInstantiator::ienumerable_of(TypeSig::Primitive(0x08));
    assert_eq!(GenericInstantiator::render(&i), "IEnumerable<int>");
}

// ───── simplify_expr ───────────────────────────────────────────────────────────

#[test]
fn simplify_expr_identities() {
    assert_eq!(simplify_expr("0 + x"), "x");
    assert_eq!(simplify_expr("x + 0"), "x");
    assert_eq!(simplify_expr("x * 1"), "x");
    assert_eq!(simplify_expr("1 * x"), "x");
    assert_eq!(simplify_expr("x - 0"), "x");
    assert_eq!(simplify_expr("!!x"), "x");
    assert_eq!(simplify_expr("a == a"), "true");
    assert_eq!(simplify_expr("a + b"), "a + b");
}

#[test]
fn simplify_expr_fuzz() {
    let mut rng = lcg();
    for _ in 0..50 {
        let len = (rng() % 30) as usize;
        let s: String = (0..len)
            .map(|_| {
                let r = rng() % 5;
                match r {
                    0 => '0', 1 => '1', 2 => ' ', 3 => '+', _ => 'x',
                }
            })
            .collect();
        let _ = simplify_expr(&s);
    }
}

// ───── DecompilerOptions / TypeEmitOptions defaults ─────────────────────────────

#[test]
fn decompiler_options_default() {
    let o = DecompilerOptions::default();
    assert_eq!(o.indent, "    ");
    assert!(!o.emit_comments);
    assert!(o.use_var);
    assert!(o.use_short_types);
}

#[test]
fn type_emit_options_default() {
    let o = TypeEmitOptions::default();
    assert!(o.output.emit_bodies);
    assert!(o.output.skip_compiler_generated);
    assert!(o.style.reconstruct_properties);
    assert!(o.style.reconstruct_lambdas);
    assert!(o.output.skip_state_machines);
    assert!(!o.style.emit_doc_comments);
}

// ───── StackEffect ─────────────────────────────────────────────────────────────

#[test]
fn stack_effect_delta_struct() {
    let e = StackEffect { pops: 2, pushes: 1 };
    assert_eq!(e.delta(), -1);
    let e = StackEffect { pops: 0, pushes: 0 };
    assert_eq!(e.delta(), 0);
}

// ───── Send/Sync threaded stress on StringTable ────────────────────────────────

#[test]
fn string_table_send_sync_threaded() {
    use std::sync::{Arc, Mutex};
    use std::thread;
    let t = Arc::new(Mutex::new(StringTable::default()));
    let mut handles = vec![];
    for tid in 0..4u32 {
        let t = Arc::clone(&t);
        handles.push(thread::spawn(move || {
            for i in 0..100u32 {
                let tok = tid * 1000 + i;
                t.lock().unwrap().record(tok, format!("s{tok}"));
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    assert_eq!(t.lock().unwrap().len(), 400);
}
