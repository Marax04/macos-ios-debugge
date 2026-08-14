//! Exhaustive blitz tests for `rustre-dotnet-decompile`.
//!
//! Aims to surface bugs across the decompiler's public API surface:
//! opcode registry, CIL disassembler, stack/CFG analyses, HLIL types,
//! constant folder, SSA builder, decompiler pipeline, and emitters.

use rustre_dotnet::{
    CilInstruction, CilOperand, DotnetMethod, DotnetType, DotnetTypeKind, LocalVar, MethodBody,
    MethodSignature,
};
use rustre_dotnet_decompile::*;

// ─── helpers ──────────────────────────────────────────────────────────────────

fn simple(off: u32, op: &str) -> CilInstruction {
    CilInstruction { offset: off, opcode: op.into(), operand: CilOperand::None }
}
fn br(off: u32, op: &str, target: u32) -> CilInstruction {
    CilInstruction { offset: off, opcode: op.into(), operand: CilOperand::Branch(target) }
}
fn ldc_i4(off: u32, v: i32) -> CilInstruction {
    CilInstruction { offset: off, opcode: "ldc.i4".into(), operand: CilOperand::Int32(v) }
}
fn void_method(name: &str, instrs: Vec<CilInstruction>) -> DotnetMethod {
    DotnetMethod {
        name: name.into(),
        signature: MethodSignature { return_type: "void".into(), ..Default::default() },
        body: Some(MethodBody { instructions: instrs, ..Default::default() }),
        flags: 0x06,
        ..Default::default()
    }
}

// ─── DecompilerOptions ────────────────────────────────────────────────────────

#[test]
fn decompiler_options_defaults() {
    let o = DecompilerOptions::default();
    assert_eq!(o.indent, "    ");
    assert!(!o.emit_comments);
    assert!(o.use_var);
    assert!(o.use_short_types);
}

// ─── OperandKind::byte_size ──────────────────────────────────────────────────

#[test]
fn operand_kind_byte_sizes() {
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

// ─── CilOpcodeRegistry ────────────────────────────────────────────────────────

#[test]
fn opcode_registry_has_entries() {
    assert!(CilOpcodeRegistry::count() > 50);
    assert!(!CilOpcodeRegistry::all_opcodes().is_empty());
}

#[test]
fn opcode_registry_by_name_nop_and_ret() {
    let nop = CilOpcodeRegistry::by_name("nop").expect("nop must exist");
    assert_eq!(nop.byte1, 0x00);
    assert_eq!(nop.byte2, None);
    let ret = CilOpcodeRegistry::by_name("ret").expect("ret must exist");
    assert!(ret.is_terminator || ret.name == "ret");
}

#[test]
fn opcode_registry_by_name_unknown_returns_none() {
    assert!(CilOpcodeRegistry::by_name("definitely_not_an_opcode").is_none());
}

#[test]
fn opcode_registry_by_encoding_nop() {
    let info = CilOpcodeRegistry::by_encoding(0x00, None).expect("0x00=nop");
    assert_eq!(info.name, "nop");
}

#[test]
fn opcode_registry_by_encoding_unknown() {
    // FF/None is not a defined one-byte opcode in the table.
    assert!(CilOpcodeRegistry::by_encoding(0xFF, None).is_none());
}

#[test]
fn opcode_registry_encoding_size_single_byte() {
    let info = CilOpcodeRegistry::by_name("nop").unwrap();
    assert_eq!(CilOpcodeRegistry::encoding_size(info), 1);
}

// ─── stack_effect ─────────────────────────────────────────────────────────────

#[test]
fn stack_effect_known_opcodes() {
    assert_eq!(stack_effect("nop").unwrap().delta(), 0);
    assert_eq!(stack_effect("ldc.i4.0").unwrap().delta(), 1);
    assert_eq!(stack_effect("pop").unwrap().delta(), -1);
    assert_eq!(stack_effect("dup").unwrap().delta(), 1);
    assert_eq!(stack_effect("add").unwrap().delta(), -1);
    let beq = stack_effect("beq").unwrap();
    assert_eq!(beq.pops, 2);
    assert_eq!(beq.pushes, 0);
}

#[test]
fn stack_effect_unknown_returns_none() {
    assert!(stack_effect("bogus_opcode_name").is_none());
}

// ─── TypeKind ────────────────────────────────────────────────────────────────

#[test]
fn typekind_from_flags() {
    assert_eq!(TypeKind::from_flags(0), TypeKind::Class);
    assert_eq!(TypeKind::from_flags(0x0020), TypeKind::Interface);
    assert_eq!(TypeKind::from_flags(0x0100), TypeKind::Struct);
}

#[test]
fn typekind_keyword_and_display() {
    assert_eq!(TypeKind::Class.keyword(), "class");
    assert_eq!(TypeKind::Interface.keyword(), "interface");
    assert_eq!(TypeKind::Struct.keyword(), "struct");
    assert_eq!(TypeKind::Enum.keyword(), "enum");
    assert_eq!(TypeKind::Delegate.keyword(), "delegate");
    assert_eq!(format!("{}", TypeKind::Class), "class");
}

// ─── BinaryOp / UnaryOp ───────────────────────────────────────────────────────

#[test]
fn binaryop_as_str() {
    assert_eq!(BinaryOp::Add.as_str(), "+");
    assert_eq!(BinaryOp::Eq.as_str(), "==");
    assert_eq!(BinaryOp::Shl.as_str(), "<<");
}

#[test]
fn unaryop_prefix_str() {
    assert_eq!(UnaryOp::Neg.prefix_str(), "-");
    assert_eq!(UnaryOp::Not.prefix_str(), "!");
    assert_eq!(UnaryOp::BitNot.prefix_str(), "~");
    assert_eq!(UnaryOp::Cast(0x08).prefix_str(), "(int)");
    assert_eq!(UnaryOp::Cast(0x0E).prefix_str(), "(string)");
}

// ─── HlilExpression / HlilBlock / HlilMethod / HlilStatement ──────────────────

#[test]
fn hlil_expr_to_csharp_basic() {
    assert_eq!(HlilExpression::Const(42).to_csharp(), "42");
    assert_eq!(HlilExpression::Null.to_csharp(), "null");
    assert_eq!(HlilExpression::StringLit("hi".into()).to_csharp(), "\"hi\"");
    assert_eq!(
        HlilExpression::Local(0, "x".into()).to_csharp(),
        "x"
    );
}

#[test]
fn hlil_expr_binary_and_unary_round() {
    let e = HlilExpression::BinaryOp {
        op: BinaryOp::Add,
        lhs: Box::new(HlilExpression::Const(1)),
        rhs: Box::new(HlilExpression::Const(2)),
    };
    assert_eq!(e.to_csharp(), "(1 + 2)");
    let u = HlilExpression::UnaryOp {
        op: UnaryOp::Neg,
        operand: Box::new(HlilExpression::Const(5)),
    };
    assert_eq!(u.to_csharp(), "-5");
}

#[test]
fn hlil_block_basics() {
    let mut b = HlilBlock::new();
    assert!(b.is_empty());
    assert_eq!(b.len(), 0);
    b.push(HlilStatement::Return(None));
    assert_eq!(b.len(), 1);
    assert!(!b.is_empty());
    let text = b.to_csharp("");
    assert!(text.contains("return"));
}

// ─── hlil_remove_nops ─────────────────────────────────────────────────────────

#[test]
fn hlil_remove_nops_strips_empty_comments_only() {
    let mut b = HlilBlock::new();
    b.push(HlilStatement::Comment(String::new()));
    b.push(HlilStatement::Comment("keep me".into()));
    b.push(HlilStatement::Return(None));
    let out = hlil_remove_nops(&b);
    assert_eq!(out.len(), 2);
}

// ─── simplify_expr ────────────────────────────────────────────────────────────

#[test]
fn simplify_expr_arithmetic_identities() {
    assert_eq!(simplify_expr("0 + x"), "x");
    assert_eq!(simplify_expr("x + 0"), "x");
    assert_eq!(simplify_expr("1 * y"), "y");
    assert_eq!(simplify_expr("y * 1"), "y");
    assert_eq!(simplify_expr("y - 0"), "y");
    assert_eq!(simplify_expr("!!q"), "q");
    assert_eq!(simplify_expr("a == a"), "true");
}

#[test]
fn simplify_expr_no_change() {
    assert_eq!(simplify_expr("x + y"), "x + y");
}

// ─── InferredType ─────────────────────────────────────────────────────────────

#[test]
fn inferred_type_to_csharp() {
    assert_eq!(InferredType::Int32.to_csharp(), "int");
    assert_eq!(InferredType::Int64.to_csharp(), "long");
    assert_eq!(InferredType::Bool.to_csharp(), "bool");
    assert_eq!(InferredType::String.to_csharp(), "string");
    assert_eq!(InferredType::Unknown.to_csharp(), "var");
    assert_eq!(
        InferredType::Array(Box::new(InferredType::Int32)).to_csharp(),
        "int[]"
    );
    assert_eq!(
        InferredType::Nullable(Box::new(InferredType::Bool)).to_csharp(),
        "bool?"
    );
    assert_eq!(InferredType::Ref("Foo".into()).to_csharp(), "Foo");
}

#[test]
fn inferred_type_predicates() {
    assert!(InferredType::Int32.is_known());
    assert!(!InferredType::Unknown.is_known());
    assert!(InferredType::Int32.is_numeric());
    assert!(!InferredType::Bool.is_numeric());
    assert!(InferredType::String.is_reference());
    assert!(!InferredType::Int32.is_reference());
    assert!(InferredType::Array(Box::new(InferredType::Int32)).is_reference());
}

#[test]
fn infer_type_from_element_known_and_unknown() {
    assert_eq!(infer_type_from_element(0x02), InferredType::Bool);
    assert_eq!(infer_type_from_element(0x08), InferredType::Int32);
    assert_eq!(infer_type_from_element(0x0A), InferredType::Int64);
    assert_eq!(infer_type_from_element(0x0C), InferredType::Float32);
    assert_eq!(infer_type_from_element(0x0D), InferredType::Float64);
    assert_eq!(infer_type_from_element(0x0E), InferredType::String);
    assert_eq!(infer_type_from_element(0x1C), InferredType::Object);
    assert_eq!(infer_type_from_element(0xFF), InferredType::Unknown);
}

// ─── StringTable ──────────────────────────────────────────────────────────────

#[test]
fn string_table_record_and_lookup() {
    let mut t = StringTable::default();
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    t.record(1, "hello".into());
    t.record(2, "world".into());
    t.record(1, "duplicate ignored".into());
    assert_eq!(t.len(), 2);
    assert_eq!(t.get(1), Some("hello"));
    assert_eq!(t.get(99), None);
    let mut all: Vec<&str> = t.all_strings();
    all.sort_unstable();
    assert_eq!(all, vec!["hello", "world"]);
}

// ─── SsaBuilder ───────────────────────────────────────────────────────────────

#[test]
fn ssa_builder_fresh_increments_versions() {
    let mut s = SsaBuilder::new();
    let n0 = s.fresh(0, 0, "v0");
    let n1 = s.fresh(0, 1, "v1");
    let n2 = s.fresh(1, 2, "v2");
    assert_eq!(n0, "s0_0");
    assert_eq!(n1, "s0_1");
    assert_eq!(n2, "s1_0");
    assert_eq!(s.def_count(), 3);
    assert_eq!(s.current(0), "s0_1");
    assert_eq!(s.current(1), "s1_0");
    assert_eq!(s.current(7), "s7_undef");
}

// ─── FoldResult / ConstantFolder ──────────────────────────────────────────────

#[test]
fn fold_result_is_known() {
    assert!(FoldResult::KnownInt(1).is_known());
    assert!(FoldResult::KnownBool(true).is_known());
    assert!(FoldResult::KnownStr("x".into()).is_known());
    assert!(!FoldResult::Unknown.is_known());
}

#[test]
fn constant_folder_basic_arithmetic() {
    let mut cf = ConstantFolder::default();
    cf.fold(&[
        simple(0, "ldc.i4.1"),
        simple(1, "ldc.i4.2"),
        simple(2, "add"),
    ]);
    let last = cf.results.last().unwrap();
    match last {
        FoldResult::KnownInt(v) => assert_eq!(*v, 3),
        _ => panic!("expected KnownInt(3), got {last:?}"),
    }
    assert!(cf.known_count() >= 3);
}

#[test]
fn constant_folder_sub_and_mul_via_ldc_i4_operand() {
    let mut cf = ConstantFolder::default();
    cf.fold(&[
        ldc_i4(0, 3),
        ldc_i4(1, 2),
        simple(2, "sub"),
    ]);
    assert!(matches!(cf.results.last(), Some(FoldResult::KnownInt(1))));
    let mut cf2 = ConstantFolder::default();
    cf2.fold(&[
        ldc_i4(0, 4),
        ldc_i4(1, 5),
        simple(2, "mul"),
    ]);
    assert!(matches!(cf2.results.last(), Some(FoldResult::KnownInt(20))));
}

/// BUG: `ConstantFolder::fold_one` only special-cases `ldc.i4.0`, `ldc.i4.1`,
/// `ldc.i4.2`, and `ldc.i4.m1`. The short-form constants `ldc.i4.3` through
/// `ldc.i4.8` are not handled and fall through to the `Unknown` branch,
/// silently dropping known-constant information.
#[test]
fn constant_folder_short_form_3_through_8_should_be_known() {
    for op in &["ldc.i4.3", "ldc.i4.4", "ldc.i4.5", "ldc.i4.6", "ldc.i4.7", "ldc.i4.8"] {
        let mut cf = ConstantFolder::default();
        cf.fold(&[simple(0, op)]);
        assert!(
            matches!(cf.results[0], FoldResult::KnownInt(_)),
            "{op} should fold to a known integer, but got {:?}",
            cf.results[0]
        );
    }
}

#[test]
fn constant_folder_ceq_equal_and_unequal() {
    let mut cf = ConstantFolder::default();
    cf.fold(&[
        simple(0, "ldc.i4.1"),
        simple(1, "ldc.i4.1"),
        simple(2, "ceq"),
    ]);
    assert!(matches!(cf.results.last(), Some(FoldResult::KnownBool(true))));
    let mut cf2 = ConstantFolder::default();
    cf2.fold(&[
        simple(0, "ldc.i4.1"),
        simple(1, "ldc.i4.2"),
        simple(2, "ceq"),
    ]);
    assert!(matches!(cf2.results.last(), Some(FoldResult::KnownBool(false))));
}

#[test]
fn constant_folder_unknown_opcode_remains_unknown() {
    let mut cf = ConstantFolder::default();
    cf.fold(&[simple(0, "totally_unknown_thing")]);
    assert!(matches!(cf.results[0], FoldResult::Unknown));
}

#[test]
fn constant_folder_local_round_trip() {
    let mut cf = ConstantFolder::default();
    cf.fold(&[
        ldc_i4(0, 7),
        simple(1, "stloc.0"),
        simple(2, "ldloc.0"),
    ]);
    assert!(matches!(cf.results.last(), Some(FoldResult::KnownInt(7))));
}

// ─── CilDisassembler ──────────────────────────────────────────────────────────

#[test]
fn disassemble_empty_is_empty() {
    let v = CilDisassembler::disassemble(&[]).unwrap();
    assert!(v.is_empty());
}

#[test]
fn disassemble_nop_ret() {
    // nop = 0x00, ret = 0x2A
    let v = CilDisassembler::disassemble(&[0x00, 0x2A]).unwrap();
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].opcode, "nop");
    assert_eq!(v[1].opcode, "ret");
    assert_eq!(v[0].offset, 0);
    assert_eq!(v[1].offset, 1);
}

#[test]
fn disassemble_unknown_byte_errors() {
    // 0xFF is not in the one-byte table.
    let r = CilDisassembler::disassemble(&[0xFF]);
    assert!(r.is_err());
}

#[test]
fn disassemble_truncated_fe_prefix_errors() {
    // 0xFE alone is truncated.
    let r = CilDisassembler::disassemble(&[0xFE]);
    assert!(r.is_err());
}

#[test]
fn disassemble_truncated_operand_errors() {
    // ldc.i4 = 0x20 with 4-byte int operand; provide only 2 bytes.
    let r = CilDisassembler::disassemble(&[0x20, 0x01, 0x02]);
    assert!(r.is_err());
}

#[test]
fn disassemble_ldc_i4_value() {
    // ldc.i4 0x12345678 little-endian
    let v = CilDisassembler::disassemble(&[0x20, 0x78, 0x56, 0x34, 0x12]).unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].opcode, "ldc.i4");
    match &v[0].operand {
        CilOperand::Int32(n) => assert_eq!(*n, 0x1234_5678),
        o => panic!("expected Int32, got {o:?}"),
    }
}

#[test]
fn disassemble_with_stack_never_negative() {
    // pop with empty stack should clamp to 0.
    let bytes = &[0x26u8, 0x2A]; // pop, ret
    let v = CilDisassembler::disassemble_with_stack(bytes).unwrap();
    assert_eq!(v.len(), 2);
    for (_, depth) in &v {
        assert!(*depth >= 0);
    }
}

// ─── StackAnalysis ────────────────────────────────────────────────────────────

#[test]
fn stack_analysis_max_depth_simple() {
    let instrs = vec![
        simple(0, "ldc.i4.1"),
        simple(1, "ldc.i4.2"),
        simple(2, "add"),
        simple(3, "pop"),
    ];
    let max = StackAnalysis::max_stack_depth(&instrs);
    assert_eq!(max, 2);
}

#[test]
fn stack_analysis_branch_targets() {
    let instrs = vec![br(0, "br", 10), simple(5, "ret")];
    let targets = StackAnalysis::branch_target_offsets(&instrs);
    assert!(targets.contains(&10));
}

// ─── ControlFlowGraph ─────────────────────────────────────────────────────────

#[test]
fn cfg_empty() {
    let cfg = ControlFlowGraph::build(&[]).unwrap();
    assert_eq!(cfg.block_count(), 0);
}

#[test]
fn cfg_single_terminated_block() {
    let instrs = vec![simple(0, "ldarg.0"), simple(1, "ret")];
    let cfg = ControlFlowGraph::build(&instrs).unwrap();
    assert_eq!(cfg.block_count(), 1);
    assert!(cfg.blocks[0].is_terminated());
    assert_eq!(cfg.blocks[0].len(), 2);
    assert!(!cfg.blocks[0].is_empty());
}

#[test]
fn cfg_unconditional_branch_makes_edge() {
    let instrs = vec![br(0, "br", 5), simple(5, "ret")];
    let cfg = ControlFlowGraph::build(&instrs).unwrap();
    assert_eq!(cfg.block_count(), 2);
    assert_eq!(cfg.blocks[0].successors[0].1, CfgEdgeKind::Unconditional);
}

#[test]
fn cfg_block_at_lookup() {
    let instrs = vec![br(0, "br", 5), simple(5, "ret")];
    let cfg = ControlFlowGraph::build(&instrs).unwrap();
    assert!(cfg.block_at(0).is_some());
    assert!(cfg.block_at(5).is_some());
    assert!(cfg.block_at(123).is_none());
}

// ─── PatternRecogniser ────────────────────────────────────────────────────────

#[test]
fn pattern_recogniser_foreach() {
    let instrs = vec![
        simple(0, "callvirt"),
        simple(1, "brfalse"),
        simple(2, "callvirt"),
    ];
    assert!(PatternRecogniser::detect_foreach(&instrs));
}

#[test]
fn pattern_recogniser_foreach_negative() {
    let instrs = vec![simple(0, "nop"), simple(1, "ret")];
    assert!(!PatternRecogniser::detect_foreach(&instrs));
}

#[test]
fn pattern_recogniser_using_requires_finally() {
    let instrs = vec![simple(0, "callvirt")];
    assert!(!PatternRecogniser::detect_using(&instrs, false));
    assert!(PatternRecogniser::detect_using(&instrs, true));
}

#[test]
fn pattern_recogniser_string_concat() {
    let instrs = vec![
        simple(0, "ldstr"),
        simple(1, "ldstr"),
        simple(2, "call"),
    ];
    assert!(PatternRecogniser::detect_string_concat(&instrs));
    let no = vec![simple(0, "ldstr"), simple(1, "call")];
    assert!(!PatternRecogniser::detect_string_concat(&no));
}

// ─── CSharpDecompiler / pipeline ──────────────────────────────────────────────

#[test]
fn decompile_method_no_body_emits_notimpl() {
    let m = DotnetMethod {
        name: "Foo".into(),
        signature: MethodSignature { return_type: "void".into(), ..Default::default() },
        body: None,
        flags: 0x06,
        ..Default::default()
    };
    let dc = CSharpDecompiler::default();
    let src = dc.decompile_method(&m).unwrap();
    assert!(src.contains("Foo"));
    assert!(src.contains("NotImplementedException"));
}

#[test]
fn decompile_method_with_body_contains_name_and_braces() {
    let m = void_method("Bar", vec![simple(0, "nop"), simple(1, "ret")]);
    let dc = CSharpDecompiler::default();
    let src = dc.decompile_method(&m).unwrap();
    assert!(src.contains("Bar"));
    assert!(src.contains('{'));
    assert!(src.contains('}'));
}

#[test]
fn decompile_method_property_accessor_marked() {
    let m = void_method("get_X", vec![simple(0, "ret")]);
    let dc = CSharpDecompiler::default();
    let src = dc.decompile_method(&m).unwrap();
    assert!(src.contains("property accessor"));
}

#[test]
fn decompile_type_class_empty() {
    let t = DotnetType {
        name: "MyClass".into(),
        namespace: "Ns".into(),
        full_name: "Ns.MyClass".into(),
        base_type: None,
        interfaces: vec![],
        methods: vec![],
        fields: vec![],
        properties: vec![],
        events: vec![],
        nested_types: vec![],
        custom_attributes: vec![],
        generic_params: vec![],
        // The five is_* booleans were folded into a single discriminant.
        kind_tag: DotnetTypeKind::Class,
        flags: 0x01,
        layout: None,
    };
    let dc = CSharpDecompiler::default();
    let src = dc.decompile_type(&t).unwrap();
    assert!(src.contains("namespace Ns"));
    assert!(src.contains("class MyClass"));
}

#[test]
fn decompile_type_local_with_default_assignment() {
    let m = DotnetMethod {
        name: "F".into(),
        signature: MethodSignature { return_type: "void".into(), ..Default::default() },
        body: Some(MethodBody {
            locals: vec![LocalVar::new(0, "System.Int32")],
            instructions: vec![simple(0, "ret")],
            ..Default::default()
        }),
        flags: 0x06,
        ..Default::default()
    };
    let dc = CSharpDecompiler::default();
    let src = dc.decompile_method(&m).unwrap();
    assert!(src.contains("local0 = default;"));
    assert!(src.contains("int"));
}

#[test]
fn pipeline_decompile_method_matches_inner() {
    let m = void_method("Pip", vec![simple(0, "ret")]);
    let pl = DecompilationPipeline::new();
    let dc = CSharpDecompiler::default();
    assert_eq!(
        pl.decompile_method(&m).unwrap(),
        dc.decompile_method(&m).unwrap()
    );
}

#[test]
fn pipeline_lift_to_hlil_keeps_locals() {
    let m = DotnetMethod {
        name: "F".into(),
        signature: MethodSignature { return_type: "void".into(), ..Default::default() },
        body: Some(MethodBody {
            locals: vec![LocalVar::new(0, "int"), LocalVar::new(1, "string")],
            instructions: vec![simple(0, "ret")],
            ..Default::default()
        }),
        flags: 0x06 | 0x0010,
        ..Default::default()
    };
    let pl = DecompilationPipeline::new();
    let hlil = pl.lift_to_hlil(&m);
    assert_eq!(hlil.name, "F");
    assert_eq!(hlil.locals.len(), 2);
    assert!(hlil.is_static);
}

// ─── CSharpEmitter ───────────────────────────────────────────────────────────

#[test]
fn emitter_using_directives() {
    let u = CSharpEmitter::emit_using("System");
    assert_eq!(u, "using System;\n");
    let std = CSharpEmitter::emit_standard_usings();
    assert!(std.contains("using System;"));
    assert!(std.contains("using System.Linq;"));
}

#[test]
fn emitter_namespace_block_empty_ns_returns_body() {
    let body = "class X {}";
    assert_eq!(CSharpEmitter::emit_namespace_block("", body), body);
    let wrapped = CSharpEmitter::emit_namespace_block("N", body);
    assert!(wrapped.starts_with("namespace N"));
    assert!(wrapped.contains(body));
}

#[test]
fn emitter_misc_helpers() {
    assert!(CSharpEmitter::emit_region("R", "x").starts_with("#region R"));
    assert_eq!(CSharpEmitter::emit_comment("c"), "// c\n");
    assert!(CSharpEmitter::emit_doc_comment("s").contains("<summary>"));
    assert_eq!(CSharpEmitter::emit_return(Some("x")), "return x;\n");
    assert_eq!(CSharpEmitter::emit_return(None), "return;\n");
    assert_eq!(CSharpEmitter::emit_throw("e"), "throw e;\n");
    assert_eq!(CSharpEmitter::emit_goto("L"), "goto L;\n");
    assert_eq!(CSharpEmitter::emit_label("L"), "L:\n");
    assert_eq!(
        CSharpEmitter::emit_local_decl("int", "x", Some("0")),
        "int x = 0;\n"
    );
    assert_eq!(
        CSharpEmitter::emit_local_decl("int", "x", None),
        "int x;\n"
    );
    assert_eq!(CSharpEmitter::emit_assign("a", "b"), "a = b;\n");
    assert_eq!(CSharpEmitter::emit_call_stmt("F()"), "F();\n");
    assert_eq!(CSharpEmitter::emit_attribute("X"), "[X]\n");
}

// ─── StackDelta ───────────────────────────────────────────────────────────────

#[test]
fn stack_delta_net() {
    assert_eq!(StackDelta::Fixed { pop: 2, push: 1 }.net(), Some(-1));
    assert_eq!(StackDelta::Fixed { pop: 0, push: 0 }.net(), Some(0));
    assert_eq!(StackDelta::Variable.net(), None);
}

// ─── detect_yield_return / detect_async ───────────────────────────────────────

#[test]
fn detect_yield_return_needs_movenext_and_switch() {
    let m = void_method("MoveNext", vec![simple(0, "switch")]);
    assert!(detect_yield_return(&m));
    let m2 = void_method("Other", vec![simple(0, "switch")]);
    assert!(!detect_yield_return(&m2));
    let m3 = void_method("MoveNext", vec![simple(0, "nop")]);
    assert!(!detect_yield_return(&m3));
}

#[test]
fn detect_async_requires_movenext_in_name() {
    let m = void_method("Foo_MoveNext", vec![simple(0, "call"), simple(1, "ret")]);
    assert!(detect_async(&m));
    let m2 = void_method("Foo", vec![simple(0, "call"), simple(1, "ret")]);
    assert!(!detect_async(&m2));
}

// ─── DecompilerMetrics ────────────────────────────────────────────────────────

#[test]
fn decompiler_metrics_summary_format() {
    let hlil = HlilMethod {
        name: "M".into(),
        return_type: "void".into(),
        params: vec![],
        is_static: true,
        modifiers: vec!["public".into(), "static".into()],
        locals: vec![],
        body: HlilBlock::new(),
    };
    let metrics = DecompilerMetrics::from_hlil(&hlil);
    assert_eq!(metrics.statement_count, 0);
    assert_eq!(metrics.cyclomatic_complexity, 1);
    let s = metrics.summary();
    assert!(s.contains("stmts=0"));
    assert!(s.contains("cc=1"));
}

// ─── csharp_patterns module ──────────────────────────────────────────────────

#[test]
fn pattern_confidence_display_order() {
    use rustre_dotnet_decompile::csharp_patterns::*;
    assert_eq!(format!("{}", PatternConfidence::High), "high");
    assert_eq!(format!("{}", PatternConfidence::Medium), "medium");
    assert_eq!(format!("{}", PatternConfidence::Low), "low");
    // Ordering: Low < Medium < High (semantics: High is the strongest confidence,
    // matching `with_min_confidence` filtering and the lib unit test).
    assert!(PatternConfidence::High > PatternConfidence::Medium);
    assert!(PatternConfidence::Medium > PatternConfidence::Low);
}

#[test]
fn pattern_location_span_saturates() {
    use rustre_dotnet_decompile::csharp_patterns::*;
    let p = PatternLocation::new(10, 25);
    assert_eq!(p.span(), 15);
    // Saturating subtraction guards underflow.
    let q = PatternLocation::new(50, 10);
    assert_eq!(q.span(), 0);
}

#[test]
fn linq_operator_display() {
    use rustre_dotnet_decompile::csharp_patterns::*;
    assert_eq!(format!("{}", LinqOperator::Where), "Where");
    assert_eq!(format!("{}", LinqOperator::SelectMany), "SelectMany");
}

#[test]
fn linq_pattern_is_terminal_and_format() {
    use rustre_dotnet_decompile::csharp_patterns::*;
    let mut p = LinqPattern::new("xs", PatternLocation::new(0, 1));
    p.operators.push(LinqOperator::Where);
    assert!(!p.is_terminal());
    assert_eq!(p.format_chain(), "xs.Where");
    p.operators.push(LinqOperator::ToList);
    assert!(p.is_terminal());
}

#[test]
fn delegate_pattern_is_closure() {
    use rustre_dotnet_decompile::csharp_patterns::*;
    let mut d = DelegatePattern::new("Action", PatternLocation::new(0, 1));
    assert!(!d.is_closure());
    d.captured_variables.push(("x".into(), "int".into()));
    assert!(d.is_closure());
}

#[test]
fn anonymous_class_format_empty_and_filled() {
    use rustre_dotnet_decompile::csharp_patterns::*;
    let empty = AnonymousClass::new("<>f__AnonymousType0", PatternLocation::new(0, 1));
    assert_eq!(empty.format(), "new {  }");
    let mut c = AnonymousClass::new("<>A", PatternLocation::new(0, 1));
    c.properties.push(("Name".into(), "string".into()));
    c.properties.push(("Age".into(), "int".into()));
    let s = c.format();
    assert!(s.contains("Name: string"));
    assert!(s.contains("Age: int"));
}

// ─── linq_recovery module ─────────────────────────────────────────────────────

#[test]
fn linq_recovery_is_closure_class() {
    use rustre_dotnet_decompile::linq_recovery::is_closure_class;
    assert!(is_closure_class("<>c__DisplayClass1"));
    assert!(is_closure_class("<>c"));
    assert!(!is_closure_class("MyClass"));
}

#[test]
fn linq_recovery_extract_captures() {
    use rustre_dotnet_decompile::linq_recovery::{extract_captures, ClosureField};
    let fields = vec![
        ClosureField { name: "x".into(), ty: "int".into() },
        ClosureField { name: "y".into(), ty: "string".into() },
    ];
    let caps = extract_captures(&fields);
    assert_eq!(caps.len(), 2);
}

#[test]
fn linq_recovery_mock_lambda_and_call() {
    use rustre_dotnet_decompile::linq_recovery::*;
    let lam = mock_lambda("x", LambdaExprNode::Var("x".into()), "int");
    assert_eq!(lam.params.len(), 1);
    let call = mock_linq_call("Where", lam, "IEnumerable<int>");
    assert_eq!(call.method, "Where");
}

// ─── async_recovery module ────────────────────────────────────────────────────

#[test]
fn async_recovery_mock_state_machine() {
    use rustre_dotnet_decompile::async_recovery::*;
    let sm = mock_state_machine("MyAsync", 3);
    // The state field should be present.
    assert!(find_state_field(&sm).is_some());
}

#[test]
fn async_recovery_mock_async_method_has_attr() {
    use rustre_dotnet_decompile::async_recovery::*;
    let m = mock_async_method("Foo", "Task");
    let attr = find_state_machine_attribute(&m);
    assert!(attr.is_some(), "mock_async_method should carry AsyncStateMachineAttribute");
}
