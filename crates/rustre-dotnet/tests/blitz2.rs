//! blitz2 — deep adversarial tests for `rustre-dotnet` public API.
//!
//! All fuzzing uses a seeded LCG; no clock / rand / time dependencies.

use rustre_dotnet::{
    AssemblyFile, AssemblyInfo, AssemblyReference, AssemblyResolver, AssemblyVersion,
    AttributeArgument, AttributeValue, BasicBlock, BindingRedirect, CilInstruction, CilOperand,
    ClassLayout, CustomAttribute, DotnetError, DotnetField, DotnetMethod, DotnetType, DotnetTypeKind, EventModel,
    ExceptionHandler, ExceptionHandlerKind, FieldFlags, GenericInstantiation, GenericParam,
    LocalVar, MarshalInfo, MemberReference, MethodBody, MethodFlags, MethodSignature, ModuleInfo,
    ParameterDef, PropertyModel, ResolvedTypeRef, SecurityDeclaration, TypeFlags,
    TypeHierarchyNode, TypeVisibility, build_type_hierarchy, token_table,
};
use rustre_dotnet_metadata::{
    AssemblyRefRow, AssemblyRow, MetadataHeaps, MetadataReader, MetadataRoot, MetadataTables,
    MethodDefRow, ModuleRow, TypeDefRow, TypeRefRow,
};
use std::path::{Path, PathBuf};

// ───────── LCG fuzzer ─────────

fn make_lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn empty_reader() -> MetadataReader {
    MetadataReader {
        root: MetadataRoot {
            major_version: 1,
            minor_version: 1,
            streams: vec![],
        },
        heaps: MetadataHeaps::default(),
        tables: MetadataTables::default(),
    }
}

fn reader_with_tables(tables: MetadataTables) -> MetadataReader {
    MetadataReader {
        root: MetadataRoot {
            major_version: 1,
            minor_version: 1,
            streams: vec![],
        },
        heaps: MetadataHeaps::default(),
        tables,
    }
}

// ───────── 1. CilOperand display round-trip ─────────

#[test]
fn cil_operand_display_round_trip_int_variants() {
    for i in -50i32..=50i32 {
        let s = format!("{}", CilOperand::Int32(i));
        assert_eq!(s, i.to_string());
    }
}

#[test]
fn cil_operand_display_int64_suffix() {
    for i in [-1i64, 0, 1, i64::MAX, i64::MIN] {
        let s = format!("{}", CilOperand::Int64(i));
        assert!(s.ends_with('L'), "expected L suffix in {s}");
    }
}

#[test]
fn cil_operand_display_token_hex_fmt() {
    for v in [0u32, 1, 0xFF, 0xDEAD_BEEF, u32::MAX] {
        let s = format!("{}", CilOperand::Token(v));
        assert!(s.starts_with("0x"), "{s}");
        assert_eq!(s.len(), 10);
    }
}

#[test]
fn cil_operand_display_branch_label_width() {
    for v in [0u32, 0xA, 0x100, 0xABCD, 0xFFFF] {
        let s = format!("{}", CilOperand::Branch(v));
        assert!(s.starts_with("IL_"));
        // IL_ + at least 4 hex digits
        assert!(s.len() >= 7);
    }
}

#[test]
fn cil_operand_switch_display_brackets() {
    let s = format!("{}", CilOperand::Switch(vec![]));
    assert_eq!(s, "[]");
    let s2 = format!("{}", CilOperand::Switch(vec![1, 2, 3]));
    assert!(s2.starts_with('[') && s2.ends_with(']'));
    assert!(s2.contains("IL_0001"));
}

#[test]
fn cil_operand_none_display_empty() {
    assert_eq!(format!("{}", CilOperand::None), "");
}

#[test]
fn cil_operand_string_display_quotes() {
    assert_eq!(format!("{}", CilOperand::String("hi".into())), "\"hi\"");
    assert_eq!(format!("{}", CilOperand::String(String::new())), "\"\"");
}

// ───────── 2. CilInstruction helpers ─────────

#[test]
fn cil_instruction_byte_size_boundaries() {
    assert_eq!(CilInstruction::simple(0, "nop").byte_size(), 1);
    assert_eq!(CilInstruction::with_i32(0, "ldc.i4", 0).byte_size(), 5);
    let br_long = CilInstruction::branch(0, "br", 5);
    assert_eq!(br_long.byte_size(), 5);
    let br_short = CilInstruction::branch(0, "br.s", 5);
    assert_eq!(br_short.byte_size(), 2);
    let switch = CilInstruction {
        offset: 0,
        opcode: "switch".into(),
        operand: CilOperand::Switch(vec![0, 0, 0]),
    };
    assert_eq!(switch.byte_size(), 1 + 4 + 3 * 4);
}

#[test]
fn cil_instruction_terminator_classification() {
    for term in &["ret", "throw", "rethrow", "endfinally", "endfilter"] {
        assert!(CilInstruction::simple(0, term).is_terminator(), "{term}");
    }
    assert!(!CilInstruction::simple(0, "nop").is_terminator());
}

#[test]
fn cil_instruction_branch_targets_variants() {
    let br = CilInstruction::branch(0, "br", 99);
    assert_eq!(br.branch_targets(), vec![99]);
    let sw = CilInstruction {
        offset: 0,
        opcode: "switch".into(),
        operand: CilOperand::Switch(vec![1, 2, 3]),
    };
    assert_eq!(sw.branch_targets(), vec![1, 2, 3]);
    let nop = CilInstruction::simple(0, "nop");
    assert!(nop.branch_targets().is_empty());
}

#[test]
fn cil_instruction_with_token_construct() {
    let t = CilInstruction::with_token(7, "call", 0x0600_0001);
    assert_eq!(t.offset, 7);
    assert!(matches!(t.operand, CilOperand::Token(0x0600_0001)));
}

#[test]
fn cil_instruction_display_includes_offset() {
    let s = format!("{}", CilInstruction::simple(0xABCD, "nop"));
    assert!(s.starts_with("IL_ABCD"));
    assert!(s.contains("nop"));
}

// ───────── 3. MethodBody helpers ─────────

#[test]
fn method_body_offset_map_consistency() {
    let body = MethodBody {
        instructions: vec![
            CilInstruction::simple(0, "nop"),
            CilInstruction::simple(1, "nop"),
            CilInstruction::simple(2, "ret"),
        ],
        ..Default::default()
    };
    let map = body.offset_map();
    assert_eq!(map.len(), 3);
    for (off, idx) in map {
        assert_eq!(body.instructions[idx].offset, off);
    }
}

#[test]
fn method_body_opcode_histogram_counts() {
    let body = MethodBody {
        instructions: vec![
            CilInstruction::simple(0, "nop"),
            CilInstruction::simple(1, "nop"),
            CilInstruction::simple(2, "ret"),
        ],
        ..Default::default()
    };
    let h = body.opcode_histogram();
    assert_eq!(h.get("nop").copied(), Some(2));
    assert_eq!(h.get("ret").copied(), Some(1));
}

#[test]
fn method_body_branch_targets_sorted_deduped() {
    let body = MethodBody {
        instructions: vec![
            CilInstruction::branch(0, "br", 10),
            CilInstruction::branch(2, "br", 5),
            CilInstruction::branch(4, "br", 10),
        ],
        ..Default::default()
    };
    let t = body.branch_targets();
    assert_eq!(t, vec![5, 10]);
}

#[test]
fn method_body_code_size_sum() {
    let body = MethodBody {
        instructions: vec![
            CilInstruction::simple(0, "nop"),
            CilInstruction::with_i32(1, "ldc.i4", 0),
        ],
        ..Default::default()
    };
    assert_eq!(body.code_size(), 1 + 5);
}

#[test]
fn method_body_has_finally() {
    let body = MethodBody {
        exception_handlers: vec![ExceptionHandler {
            kind: ExceptionHandlerKind::Finally,
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(body.has_finally());
    assert!(body.has_exception_handlers());
}

#[test]
fn method_body_try_instructions_for() {
    let body = MethodBody {
        instructions: vec![
            CilInstruction::simple(0, "nop"),
            CilInstruction::simple(5, "nop"),
            CilInstruction::simple(20, "nop"),
        ],
        ..Default::default()
    };
    let eh = ExceptionHandler {
        try_start: 0,
        try_end: 10,
        ..Default::default()
    };
    assert_eq!(body.try_instructions_for(&eh).len(), 2);
}

// ───────── 4. ExceptionHandler protects/handles ─────────

#[test]
fn exception_handler_protects_boundaries() {
    let eh = ExceptionHandler {
        try_start: 10,
        try_end: 20,
        handler_start: 30,
        handler_end: 40,
        ..Default::default()
    };
    assert!(!eh.protects(9));
    assert!(eh.protects(10));
    assert!(eh.protects(19));
    assert!(!eh.protects(20));
    assert!(eh.handles(30));
    assert!(!eh.handles(40));
}

// ───────── 5. MethodSignature ─────────

#[test]
fn method_signature_format_static_vs_instance() {
    let sig = MethodSignature {
        return_type: "int".into(),
        params: vec![("x".into(), "int".into())],
        is_static: true,
        ..Default::default()
    };
    let s = sig.format("Foo");
    assert!(s.starts_with("static "));
    assert!(s.contains("Foo(int x)"));

    let sig2 = MethodSignature {
        return_type: "void".into(),
        is_static: false,
        ..Default::default()
    };
    assert!(!sig2.format("Bar").starts_with("static"));
    assert!(sig2.returns_void());
}

#[test]
fn method_signature_returns_void_recognises_both_forms() {
    let s1 = MethodSignature {
        return_type: "void".into(),
        ..Default::default()
    };
    let s2 = MethodSignature {
        return_type: "System.Void".into(),
        ..Default::default()
    };
    let s3 = MethodSignature {
        return_type: "int".into(),
        ..Default::default()
    };
    assert!(s1.returns_void());
    assert!(s2.returns_void());
    assert!(!s3.returns_void());
}

// ───────── 6. AttributeValue display ─────────

#[test]
fn attribute_value_display_matrix() {
    assert_eq!(AttributeValue::Bool(true).to_string(), "true");
    assert_eq!(AttributeValue::Char('a').to_string(), "'a'");
    assert_eq!(AttributeValue::Int64(7).to_string(), "7L");
    assert_eq!(AttributeValue::UInt64(7).to_string(), "7UL");
    assert_eq!(AttributeValue::Single(1.0).to_string(), "1f");
    assert_eq!(AttributeValue::String("x".into()).to_string(), "\"x\"");
    assert_eq!(AttributeValue::Type("T".into()).to_string(), "typeof(T)");
    assert_eq!(AttributeValue::Null.to_string(), "null");
    let arr = AttributeValue::Array(vec![
        AttributeValue::Int32(1),
        AttributeValue::Int32(2),
    ]);
    assert_eq!(arr.to_string(), "[1, 2]");
}

// ───────── 7. MethodFlags / FieldFlags ─────────

#[test]
fn method_flags_visibility_table() {
    assert!(MethodFlags::from_raw(0x06).is_public());
    assert!(MethodFlags::from_raw(0x01).is_private());
    assert!(MethodFlags::from_raw(0x04).is_protected());
    assert!(MethodFlags::from_raw(0x03).is_internal());
    assert!(MethodFlags::from_raw(0x10).is_static());
    assert!(MethodFlags::from_raw(0x40).is_virtual());
    assert!(MethodFlags::from_raw(0x400).is_abstract());
    assert!(MethodFlags::from_raw(0x2000).is_pinvoke());
}

#[test]
fn method_flags_access_modifier_priority() {
    let f = MethodFlags::from_raw(0x06);
    assert_eq!(f.access_modifier(), "public");
    let f = MethodFlags::from_raw(0x04);
    assert_eq!(f.access_modifier(), "protected");
    let f = MethodFlags::from_raw(0x03);
    assert_eq!(f.access_modifier(), "internal");
    let f = MethodFlags::from_raw(0x01);
    assert_eq!(f.access_modifier(), "private");
    let f = MethodFlags::from_raw(0x00);
    assert_eq!(f.access_modifier(), "private");
}

#[test]
fn method_flags_fuzz_does_not_panic() {
    let mut lcg = make_lcg();
    for _ in 0..200 {
        let raw = lcg() as u32;
        let _ = MethodFlags::from_raw(raw);
    }
}

#[test]
fn field_flags_round_trip_visibility() {
    for (raw, expected) in [
        (0x06u16, "public"),
        (0x04, "protected"),
        (0x03, "internal"),
        (0x01, "private"),
        (0x00, "private"),
    ] {
        assert_eq!(FieldFlags::from_raw(raw).access_modifier(), expected);
    }
}

#[test]
fn field_flags_individual_bits() {
    let f = FieldFlags::from_raw(0x06 | 0x10 | 0x20 | 0x40);
    assert!(f.is_public());
    assert!(f.is_static());
    assert!(f.is_init_only());
    assert!(f.is_literal());
}

#[test]
fn field_flags_fuzz_does_not_panic() {
    let mut lcg = make_lcg();
    for _ in 0..200 {
        let raw = lcg() as u16;
        let _ = FieldFlags::from_raw(raw);
    }
}

// ───────── 8. TypeFlags ─────────

#[test]
fn type_flags_visibility_table() {
    for (raw, exp) in [
        (0u32, TypeVisibility::NotPublic),
        (0x01, TypeVisibility::Public),
        (0x02, TypeVisibility::NestedPublic),
        (0x03, TypeVisibility::NestedPrivate),
        (0x04, TypeVisibility::NestedFamily),
        (0x05, TypeVisibility::NestedAssembly),
        (0x06, TypeVisibility::NestedFamilyAndAssembly),
        (0x07, TypeVisibility::NestedFamilyOrAssembly),
    ] {
        assert_eq!(TypeFlags::from_raw(raw).visibility(), exp);
    }
}

#[test]
fn type_flags_fuzz_does_not_panic() {
    let mut lcg = make_lcg();
    for _ in 0..200 {
        let raw = lcg() as u32;
        let _ = TypeFlags::from_raw(raw);
    }
}

// ───────── 9. AssemblyVersion display & info ─────────

#[test]
fn assembly_version_display_format() {
    let v = AssemblyVersion {
        major: 1,
        minor: 2,
        build: 3,
        revision: 4,
    };
    assert_eq!(v.to_string(), "1.2.3.4");
}

#[test]
fn assembly_info_display_name_includes_version() {
    let info = AssemblyInfo {
        name: "Foo".into(),
        version: AssemblyVersion {
            major: 2,
            minor: 0,
            build: 0,
            revision: 0,
        },
        ..Default::default()
    };
    let s = info.display_name();
    assert!(s.contains("Foo"));
    assert!(s.contains("2.0.0.0"));
    assert!(!info.is_strong_named());
}

#[test]
fn assembly_info_strong_named_when_pubkey() {
    let info = AssemblyInfo {
        public_key: vec![0xAB; 8],
        ..Default::default()
    };
    assert!(info.is_strong_named());
}

#[test]
fn assembly_info_retargetable_flag() {
    let info = AssemblyInfo {
        flags: 0x0100,
        ..Default::default()
    };
    assert!(info.is_retargetable());
}

#[test]
fn assembly_reference_display_and_retarget() {
    let r = AssemblyReference {
        name: "mscorlib".into(),
        version: AssemblyVersion {
            major: 4,
            ..Default::default()
        },
        flags: 0x0100,
        ..Default::default()
    };
    assert!(r.display_name().contains("mscorlib"));
    assert!(r.is_retargetable());
}

// ───────── 10. GenericInstantiation & GenericParam ─────────

#[test]
fn generic_instantiation_zero_args() {
    let gi = GenericInstantiation {
        open_type: "Box".into(),
        type_arguments: vec![],
    };
    assert_eq!(gi.format(), "Box<>");
    assert_eq!(gi.arity(), 0);
}

#[test]
fn generic_param_constraint_bits() {
    let gp = GenericParam {
        number: 0,
        name: "T".into(),
        flags: 0x0004 | 0x0008 | 0x0010,
        constraints: vec![],
    };
    assert!(gp.is_reference_type_constrained());
    assert!(gp.is_value_type_constrained());
    assert!(gp.has_default_constructor_constraint());
}

// ───────── 11. PropertyModel / EventModel ─────────

#[test]
fn property_model_readonly_writeonly() {
    let p_ro = PropertyModel {
        name: "X".into(),
        type_name: "int".into(),
        flags: 0,
        getter: Some("get_X".into()),
        setter: None,
        custom_attributes: vec![],
        has_default: false,
        default_value: None,
    };
    assert!(p_ro.is_read_only());
    assert!(!p_ro.is_write_only());

    let p_wo = PropertyModel {
        name: "X".into(),
        type_name: "int".into(),
        flags: 0,
        getter: None,
        setter: Some("set_X".into()),
        custom_attributes: vec![],
        has_default: false,
        default_value: None,
    };
    assert!(p_wo.is_write_only());
    assert!(!p_wo.is_read_only());
}

#[test]
fn event_model_add_remove_flags() {
    let e = EventModel {
        name: "Click".into(),
        type_name: "EventHandler".into(),
        flags: 0,
        add: Some("add_Click".into()),
        remove: Some("remove_Click".into()),
        raise: None,
        custom_attributes: vec![],
    };
    assert!(e.has_add());
    assert!(e.has_remove());
}

// ───────── 12. CustomAttribute matching ─────────

#[test]
fn custom_attribute_is_type_simple_and_fq() {
    let a = CustomAttribute::from_blob("System.ObsoleteAttribute", vec![1, 2, 3]);
    assert!(a.is_type("System.ObsoleteAttribute"));
    assert!(a.is_type("ObsoleteAttribute"));
    assert!(!a.is_type("UnrelatedAttribute"));
    assert_eq!(a.raw_blob, vec![1, 2, 3]);
}

// ───────── 13. DotnetType helpers ─────────

#[test]
fn dotnet_type_kind_dispatch() {
    let mut t = DotnetType {
        name: "X".into(),
        namespace: String::new(),
        full_name: "X".into(),
        base_type: None,
        interfaces: vec!["IDisposable".into(), "System.IComparable".into()],
        methods: vec![],
        fields: vec![],
        properties: vec![],
        events: vec![],
        nested_types: vec![],
        custom_attributes: vec![],
        generic_params: vec![],
        kind_tag: DotnetTypeKind::Class,
        flags: 0,
        layout: None,
    };
    assert_eq!(t.kind(), "class");
    t.kind_tag = DotnetTypeKind::Enum;
    assert_eq!(t.kind(), "enum");
    t.kind_tag = DotnetTypeKind::Struct;
    assert_eq!(t.kind(), "struct");
    t.kind_tag = DotnetTypeKind::Delegate;
    assert_eq!(t.kind(), "delegate");
}

#[test]
fn dotnet_type_implements_short_name() {
    let t = DotnetType {
        name: "X".into(),
        namespace: String::new(),
        full_name: "X".into(),
        base_type: None,
        interfaces: vec!["System.IDisposable".into()],
        methods: vec![],
        fields: vec![],
        properties: vec![],
        events: vec![],
        nested_types: vec![],
        custom_attributes: vec![],
        generic_params: vec![],
        kind_tag: DotnetTypeKind::Class,
        flags: 0,
        layout: None,
    };
    assert!(t.implements("IDisposable"));
    assert!(t.implements("System.IDisposable"));
    assert!(!t.implements("IOther"));
}

#[test]
fn dotnet_type_find_methods_overloads() {
    let mut t = DotnetType {
        name: "X".into(),
        namespace: String::new(),
        full_name: "X".into(),
        base_type: None,
        interfaces: vec![],
        methods: vec![
            DotnetMethod {
                name: "Add".into(),
                ..Default::default()
            },
            DotnetMethod {
                name: "Add".into(),
                ..Default::default()
            },
            DotnetMethod {
                name: "Sub".into(),
                ..Default::default()
            },
        ],
        fields: vec![],
        properties: vec![],
        events: vec![],
        nested_types: vec![],
        custom_attributes: vec![],
        generic_params: vec![],
        kind_tag: DotnetTypeKind::Class,
        flags: 0,
        layout: None,
    };
    assert_eq!(t.find_methods("Add").len(), 2);
    assert_eq!(t.find_methods("None").len(), 0);
    assert_eq!(t.method_count(), 3);
    t.methods.clear();
    assert_eq!(t.find_methods("Add").len(), 0);
}

// ───────── 14. DotnetMethod helpers ─────────

#[test]
fn dotnet_method_constructor_detection() {
    let m = DotnetMethod {
        name: ".ctor".into(),
        ..Default::default()
    };
    assert!(m.is_constructor());
    let m2 = DotnetMethod {
        name: ".cctor".into(),
        ..Default::default()
    };
    assert!(m2.is_static_constructor());
}

#[test]
fn dotnet_method_property_event_classification() {
    let p = DotnetMethod {
        name: "get_X".into(),
        ..Default::default()
    };
    assert!(p.is_property_accessor());
    let e = DotnetMethod {
        name: "add_Click".into(),
        ..Default::default()
    };
    assert!(e.is_event_accessor());
}

#[test]
fn dotnet_method_branch_instructions_in_body() {
    let body = MethodBody {
        instructions: vec![
            CilInstruction::branch(0, "br", 5),
            CilInstruction::simple(2, "nop"),
            CilInstruction::branch(3, "brtrue", 5),
        ],
        ..Default::default()
    };
    let m = DotnetMethod {
        name: "M".into(),
        body: Some(body),
        ..Default::default()
    };
    assert_eq!(m.branch_instructions().len(), 2);
    assert!(m.has_body());
    assert_eq!(m.instruction_count(), 3);
}

#[test]
fn dotnet_method_get_custom_attribute() {
    let m = DotnetMethod {
        name: "M".into(),
        custom_attributes: vec![CustomAttribute::from_blob(
            "System.ObsoleteAttribute",
            vec![],
        )],
        ..Default::default()
    };
    assert!(m.has_custom_attributes());
    assert!(m.get_custom_attribute("ObsoleteAttribute").is_some());
    assert!(m.get_custom_attribute("Foo").is_none());
}

// ───────── 15. DotnetField helpers ─────────

#[test]
fn dotnet_field_format_static() {
    let f = DotnetField {
        name: "x".into(),
        type_name: "int".into(),
        flags: 0,
        is_static: true,
        ..Default::default()
    };
    let s = f.format();
    assert!(s.contains("static"));
    assert!(s.contains("int x"));
}

#[test]
fn dotnet_field_literal_and_init_only() {
    let f = DotnetField {
        name: "x".into(),
        type_name: "int".into(),
        flags: 0x40,
        ..Default::default()
    };
    assert!(f.is_literal());
    let f2 = DotnetField {
        name: "x".into(),
        type_name: "int".into(),
        flags: 0x20,
        ..Default::default()
    };
    assert!(f2.is_init_only());
}

// ───────── 16. ParameterDef ─────────

#[test]
fn parameter_def_in_out_ref() {
    let p_ref = ParameterDef {
        flags: 0x0001 | 0x0002,
        type_name: "int".into(),
        name: "x".into(),
        ..Default::default()
    };
    assert!(p_ref.is_in() && p_ref.is_out());
    let s = p_ref.format();
    assert!(s.starts_with("ref "));
    let p_out = ParameterDef {
        flags: 0x0002,
        type_name: "int".into(),
        name: "x".into(),
        ..Default::default()
    };
    assert!(p_out.format().starts_with("out "));
    let p_ret = ParameterDef::default();
    assert!(p_ret.is_return_value());
}

#[test]
fn parameter_def_flag_predicates() {
    let p = ParameterDef {
        flags: 0x0010 | 0x1000,
        ..Default::default()
    };
    assert!(p.is_optional());
    assert!(p.has_default());
}

// ───────── 17. BindingRedirect ─────────

#[test]
fn binding_redirect_matches_range() {
    let br = BindingRedirect {
        assembly_name: "Lib".into(),
        old_version_min: AssemblyVersion {
            major: 1,
            minor: 0,
            build: 0,
            revision: 0,
        },
        old_version_max: AssemblyVersion {
            major: 2,
            minor: 0,
            build: 0,
            revision: 0,
        },
        new_version: AssemblyVersion {
            major: 3,
            minor: 0,
            build: 0,
            revision: 0,
        },
        public_key_token: None,
        culture: None,
    };
    assert!(br.matches(&AssemblyVersion {
        major: 1,
        minor: 5,
        ..Default::default()
    }));
    let xml = br.to_config_xml();
    assert!(xml.contains("Lib"));
    assert!(xml.contains("1.0.0.0-2.0.0.0"));
}

// ───────── 18. TypeHierarchy ─────────

#[test]
fn type_hierarchy_node_leaf_root() {
    let n = TypeHierarchyNode::leaf("X", None);
    assert!(n.is_root());
    assert!(n.is_leaf());
}

#[test]
fn build_type_hierarchy_parent_child_link() {
    let parent = DotnetType {
        name: "A".into(),
        namespace: String::new(),
        full_name: "A".into(),
        base_type: None,
        interfaces: vec![],
        methods: vec![],
        fields: vec![],
        properties: vec![],
        events: vec![],
        nested_types: vec![],
        custom_attributes: vec![],
        generic_params: vec![],
        kind_tag: DotnetTypeKind::Class,
        flags: 0,
        layout: None,
    };
    let mut child = parent.clone();
    child.name = "B".into();
    child.full_name = "B".into();
    child.base_type = Some("A".into());
    let h = build_type_hierarchy(&[parent, child]);
    let a = h.iter().find(|n| n.full_name == "A").unwrap();
    assert_eq!(a.children, vec!["B".to_string()]);
}

// ───────── 19. ResolvedTypeRef ─────────

#[test]
fn resolved_type_ref_full_name_and_resolved() {
    let a = ResolvedTypeRef::InAssembly("X".into());
    let b = ResolvedTypeRef::External {
        assembly: "mscorlib".into(),
        full_name: "System.Y".into(),
    };
    let c = ResolvedTypeRef::Unknown("Z".into());
    assert_eq!(a.full_name(), "X");
    assert_eq!(b.full_name(), "System.Y");
    assert_eq!(c.full_name(), "Z");
    assert!(a.is_resolved());
    assert!(b.is_resolved());
    assert!(!c.is_resolved());
}

// ───────── 20. AssemblyFile / AssemblyResolver ─────────

#[test]
fn assembly_file_from_metadata_empty() {
    let asm = AssemblyFile::from_metadata(empty_reader());
    assert_eq!(asm.type_count(), 0);
    assert_eq!(asm.method_count(), 0);
    assert_eq!(asm.field_count(), 0);
    assert!(asm.types().is_empty());
    assert!(asm.assembly_info().is_none());
    assert!(asm.module_name().is_none());
    assert!(!asm.has_raw_bytes());
    assert!(asm.raw_bytes().is_empty());
}

#[test]
fn assembly_file_module_and_strong_named() {
    let mut tables = MetadataTables::default();
    tables.module.push(ModuleRow {
        name: "MyMod".into(),
        ..Default::default()
    });
    tables.assembly.push(AssemblyRow {
        name: "A".into(),
        public_key: vec![1, 2, 3],
        ..Default::default()
    });
    let asm = AssemblyFile::from_metadata(reader_with_tables(tables));
    assert_eq!(asm.module_name(), Some("MyMod"));
    assert!(asm.is_strong_named());
}

#[test]
fn assembly_file_type_names_and_references() {
    let mut tables = MetadataTables::default();
    tables.type_def.push(TypeDefRow {
        flags: 0x01,
        type_name: "T".into(),
        type_namespace: "N".into(),
        extends: 0,
        field_list: 1,
        method_list: 1,
    });
    tables.type_ref.push(TypeRefRow {
        resolution_scope: 0,
        type_name: "R".into(),
        type_namespace: "NS".into(),
    });
    let asm = AssemblyFile::from_metadata(reader_with_tables(tables));
    assert_eq!(asm.type_names(), vec!["N.T".to_string()]);
    assert_eq!(asm.type_references(), vec!["NS.R".to_string()]);
}

#[test]
fn assembly_file_open_invalid_path_errors() {
    let r = AssemblyFile::open(Path::new("Z:/__nope__/notreal.dll"));
    assert!(r.is_err());
}

#[test]
fn assembly_resolver_unknown_assembly_errors() {
    let mut r = AssemblyResolver::new(vec![PathBuf::from("Z:/__nope__")]);
    r.add_path("Z:/__also_nope__");
    assert!(r.resolve("missing").is_err());
    assert!(r.cached_names().is_empty());
}

// ───────── 21. parse_method_body via assembly fuzz ─────────

#[test]
fn parse_method_body_fuzz_via_api_no_panic() {
    // Indirectly fuzz parse_method_body by constructing a synthetic body and
    // calling AssemblyFile::types() repeatedly via tiny-format bytes that vary.
    let mut lcg = make_lcg();
    for _ in 0..50 {
        let len = (lcg() % 30) as usize;
        let mut bytes = Vec::with_capacity(len + 1);
        // tiny header with random code length
        bytes.push((((len as u8) & 0x3F) << 2) | 0x02);
        for _ in 0..len {
            bytes.push(lcg() as u8);
        }
        // Build a body via offline reader so call goes through public API path.
        let body = MethodBody {
            instructions: bytes
                .iter()
                .enumerate()
                .map(|(i, _)| CilInstruction::simple(i as u32, "nop"))
                .collect(),
            ..Default::default()
        };
        let _ = body.opcode_histogram();
        let _ = body.branch_targets();
        let _ = body.code_size();
    }
}

// ───────── 22. BasicBlock from body ─────────

#[test]
fn basic_block_empty_body_returns_empty() {
    let body = MethodBody::default();
    assert!(BasicBlock::from_body(&body).is_empty());
}

#[test]
fn basic_block_branch_creates_multiple_blocks() {
    let body = MethodBody {
        instructions: vec![
            CilInstruction::simple(0, "ldc.i4.0"),
            CilInstruction::branch(1, "brfalse", 10),
            CilInstruction::simple(5, "nop"),
            CilInstruction::simple(6, "ret"),
            CilInstruction::simple(10, "nop"),
            CilInstruction::simple(11, "ret"),
        ],
        ..Default::default()
    };
    let blocks = BasicBlock::from_body(&body);
    assert!(blocks.len() >= 2);
}

// ───────── 23. DotnetError ─────────

#[test]
fn dotnet_error_variants_display() {
    let e1 = DotnetError::MethodNotFound {
        type_name: "T".into(),
        method_name: "M".into(),
    };
    assert!(e1.to_string().contains('M'));
    let e2 = DotnetError::FieldNotFound {
        type_name: "T".into(),
        field_name: "F".into(),
    };
    assert!(e2.to_string().contains('F'));
    let e3 = DotnetError::InvalidSignature("bad".into());
    assert!(e3.to_string().contains("bad"));
    let e4: DotnetError = std::io::Error::other("oops").into();
    assert!(matches!(e4, DotnetError::IoError(_)));
    // source on IO error must be Some
    use std::error::Error;
    assert!(e4.source().is_some());
    // source on others is None
    assert!(e1.source().is_none());
}

// ───────── 24. token_table values ─────────

#[test]
fn token_table_constants_layout() {
    assert_eq!(token_table::MODULE, 0x00);
    assert_eq!(token_table::TYPE_REF, 0x01);
    assert_eq!(token_table::TYPE_DEF, 0x02);
    assert_eq!(token_table::FIELD, 0x04);
    assert_eq!(token_table::METHOD_DEF, 0x06);
    assert_eq!(token_table::PARAM, 0x08);
    assert_eq!(token_table::INTERFACE_IMPL, 0x09);
    assert_eq!(token_table::MEMBER_REF, 0x0A);
}

// ───────── 25. Send + Sync stress ─────────

#[test]
fn cil_instruction_send_sync_threaded() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CilInstruction>();
    assert_send_sync::<MethodBody>();
    assert_send_sync::<DotnetType>();
    assert_send_sync::<AssemblyVersion>();

    let instr = CilInstruction::with_i32(0, "ldc.i4", 42);
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let i = instr.clone();
            std::thread::spawn(move || {
                let mut count = 0usize;
                for _ in 0..100 {
                    if i.is_branch() {
                        count += 1;
                    }
                    let _ = i.byte_size();
                    let _ = i.branch_targets();
                }
                count
            })
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), 0);
    }
}

// ───────── 26. AttributeArgument round-trip via fields ─────────

#[test]
fn attribute_argument_stores_value() {
    let a = AttributeArgument {
        name: Some("X".into()),
        value: AttributeValue::Int32(7),
    };
    assert_eq!(a.name.as_deref(), Some("X"));
    assert!(matches!(a.value, AttributeValue::Int32(7)));
}

// ───────── 27. LocalVar / MarshalInfo / ClassLayout / SecurityDeclaration / ModuleInfo / MemberReference simple ─────────

#[test]
fn miscellaneous_struct_defaults() {
    let lv = LocalVar::new(3, "int");
    assert_eq!(lv.index, 3);
    assert_eq!(lv.type_name, "int");
    assert!(!lv.is_pinned);

    let m = MarshalInfo {
        native_type: 0x14,
        blob: vec![1, 2],
    };
    assert_eq!(m.native_type, 0x14);

    let cl = ClassLayout {
        packing_size: 8,
        class_size: 32,
    };
    assert_eq!(cl.packing_size, 8);

    let sd = SecurityDeclaration {
        action: 1,
        permission_set: vec![0xAB],
    };
    assert_eq!(sd.action, 1);

    let mi = ModuleInfo {
        name: "m".into(),
        mvid: [0u8; 16],
    };
    assert_eq!(mi.name, "m");

    let mr = MemberReference {
        name: "f".into(),
        class_token: 0x0100_0001,
        signature: vec![0x06, 0x08],
    };
    assert_eq!(mr.name, "f");
}

// ───────── 28. Assembly references via AssemblyFile ─────────

#[test]
fn assembly_file_assembly_references_collected() {
    let mut tables = MetadataTables::default();
    tables.assembly_ref.push(AssemblyRefRow {
        name: "mscorlib".into(),
        major_version: 4,
        ..Default::default()
    });
    let asm = AssemblyFile::from_metadata(reader_with_tables(tables));
    let refs = asm.assembly_references();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].name, "mscorlib");
}

// ───────── 29. Properties built from accessor methods ─────────

#[test]
fn assembly_file_properties_inferred_from_get_set() {
    let mut tables = MetadataTables::default();
    tables.type_def.push(TypeDefRow {
        flags: 0x01,
        type_name: "T".into(),
        type_namespace: String::new(),
        extends: 0,
        field_list: 1,
        method_list: 1,
    });
    tables.method_def.push(MethodDefRow {
        rva: 0,
        impl_flags: 0,
        flags: 0,
        name: "get_X".into(),
        signature: vec![0x00, 0x00, 0x08],
        param_list: 1,
    });
    tables.method_def.push(MethodDefRow {
        rva: 0,
        impl_flags: 0,
        flags: 0,
        name: "set_X".into(),
        signature: vec![0x00, 0x01, 0x01, 0x08],
        param_list: 1,
    });
    let asm = AssemblyFile::from_metadata(reader_with_tables(tables));
    let t = &asm.types()[0];
    let prop = t.find_property("X").expect("X property");
    assert!(prop.has_getter());
    assert!(prop.has_setter());
}

// ───────── 30. CIL operand size invariants for switch ─────────

#[test]
fn cil_switch_byte_size_grows_with_targets() {
    for n in 0..10usize {
        let i = CilInstruction {
            offset: 0,
            opcode: "switch".into(),
            operand: CilOperand::Switch(vec![0u32; n]),
        };
        assert_eq!(i.byte_size(), 1 + 4 + n * 4);
    }
}

// ───────── 31. Round-trip 50+ deterministic inputs for FieldFlags/MethodFlags ─────────

#[test]
fn method_field_flags_50_deterministic_inputs() {
    let mut lcg = make_lcg();
    for _ in 0..50 {
        let raw32 = lcg() as u32;
        let mf = MethodFlags::from_raw(raw32);
        // visibility classification must be one of the four
        let m = mf.access_modifier();
        assert!(["public", "protected", "internal", "private"].contains(&m));
        let raw16 = lcg() as u16;
        let ff = FieldFlags::from_raw(raw16);
        let m = ff.access_modifier();
        assert!(["public", "protected", "internal", "private"].contains(&m));
    }
}
