//! Blitz test suite for rustre-dotnet public API.
//! Goal: surface bugs by exercising boundaries, malformed inputs, and invariants.

use rustre_dotnet::*;

// ─────────────────────────── CilOperand / Display ──────────────────────────

#[test]
fn cil_operand_display_none_is_empty() {
    assert_eq!(format!("{}", CilOperand::None), "");
}

#[test]
fn cil_operand_display_int8() {
    assert_eq!(format!("{}", CilOperand::Int8(-5)), "-5");
}

#[test]
fn cil_operand_display_int32() {
    assert_eq!(format!("{}", CilOperand::Int32(42)), "42");
}

#[test]
fn cil_operand_display_int64_has_l_suffix() {
    assert_eq!(format!("{}", CilOperand::Int64(7)), "7L");
}

#[test]
fn cil_operand_display_float32_has_f() {
    assert_eq!(format!("{}", CilOperand::Float32(1.5)), "1.5f");
}

#[test]
fn cil_operand_display_token_hex() {
    assert_eq!(format!("{}", CilOperand::Token(0xDEAD)), "0x0000DEAD");
}

#[test]
fn cil_operand_display_branch() {
    assert_eq!(format!("{}", CilOperand::Branch(0xAB)), "IL_00AB");
}

#[test]
fn cil_operand_display_switch_empty() {
    assert_eq!(format!("{}", CilOperand::Switch(vec![])), "[]");
}

#[test]
fn cil_operand_display_switch_multi() {
    let s = format!("{}", CilOperand::Switch(vec![1, 2, 3]));
    assert_eq!(s, "[IL_0001, IL_0002, IL_0003]");
}

#[test]
fn cil_operand_display_string() {
    assert_eq!(format!("{}", CilOperand::String("hi".into())), "\"hi\"");
}

// ─────────────────────────── CilInstruction ────────────────────────────────

#[test]
fn cil_instruction_simple_has_none_operand() {
    let i = CilInstruction::simple(0, "nop");
    assert_eq!(i.operand, CilOperand::None);
    assert_eq!(i.opcode, "nop");
}

#[test]
fn cil_instruction_branch_operand_is_branch() {
    let i = CilInstruction::branch(0, "br", 99);
    assert_eq!(i.operand, CilOperand::Branch(99));
}

#[test]
fn cil_instruction_with_token() {
    let i = CilInstruction::with_token(0, "call", 0x0600_0001);
    assert_eq!(i.operand, CilOperand::Token(0x0600_0001));
}

#[test]
fn cil_instruction_with_i32() {
    let i = CilInstruction::with_i32(0, "ldc.i4", -1);
    assert_eq!(i.operand, CilOperand::Int32(-1));
}

#[test]
fn cil_instruction_is_unconditional_branch_set() {
    for op in &["br", "br.s", "jmp", "leave", "leave.s"] {
        assert!(CilInstruction::simple(0, op).is_unconditional_branch(), "{op}");
    }
}

#[test]
fn cil_instruction_is_unconditional_branch_negative() {
    assert!(!CilInstruction::simple(0, "brtrue").is_unconditional_branch());
    assert!(!CilInstruction::simple(0, "ret").is_unconditional_branch());
}

#[test]
fn cil_instruction_is_branch_covers_conditionals() {
    for op in &["brtrue", "brfalse", "beq", "bne.un", "switch", "ble.un.s"] {
        assert!(CilInstruction::simple(0, op).is_branch(), "{op}");
    }
}

#[test]
fn cil_instruction_is_terminator_includes_throw_ret() {
    for op in &["ret", "throw", "rethrow", "endfinally", "endfilter", "br"] {
        assert!(CilInstruction::simple(0, op).is_terminator(), "{op}");
    }
    assert!(!CilInstruction::simple(0, "nop").is_terminator());
    assert!(!CilInstruction::simple(0, "add").is_terminator());
}

#[test]
fn cil_instruction_branch_targets_single() {
    let i = CilInstruction::branch(0, "br", 7);
    assert_eq!(i.branch_targets(), vec![7]);
}

#[test]
fn cil_instruction_branch_targets_switch() {
    let i = CilInstruction {
        offset: 0,
        opcode: "switch".into(),
        operand: CilOperand::Switch(vec![3, 4, 5]),
    };
    assert_eq!(i.branch_targets(), vec![3, 4, 5]);
}

#[test]
fn cil_instruction_branch_targets_none() {
    assert!(CilInstruction::simple(0, "nop").branch_targets().is_empty());
}

#[test]
fn cil_instruction_byte_size_none() {
    assert_eq!(CilInstruction::simple(0, "nop").byte_size(), 1);
}

#[test]
fn cil_instruction_byte_size_branch_short() {
    let i = CilInstruction {
        offset: 0,
        opcode: "br.s".into(),
        operand: CilOperand::Branch(2),
    };
    assert_eq!(i.byte_size(), 2); // 1 + 1
}

#[test]
fn cil_instruction_byte_size_branch_long() {
    let i = CilInstruction {
        offset: 0,
        opcode: "br".into(),
        operand: CilOperand::Branch(2),
    };
    assert_eq!(i.byte_size(), 5); // 1 + 4
}

#[test]
fn cil_instruction_byte_size_switch() {
    let i = CilInstruction {
        offset: 0,
        opcode: "switch".into(),
        operand: CilOperand::Switch(vec![1, 2, 3]),
    };
    // 1 opcode + 4 (count) + 3*4 (targets) = 17
    assert_eq!(i.byte_size(), 1 + 4 + 12);
}

#[test]
fn cil_instruction_byte_size_int64() {
    let i = CilInstruction {
        offset: 0,
        opcode: "ldc.i8".into(),
        operand: CilOperand::Int64(0),
    };
    assert_eq!(i.byte_size(), 9);
}

#[test]
fn cil_instruction_display_with_offset() {
    let i = CilInstruction::with_i32(0x10, "ldc.i4", 5);
    let s = format!("{i}");
    assert!(s.starts_with("IL_0010:"));
    assert!(s.contains("ldc.i4"));
    assert!(s.contains('5'));
}

#[test]
fn cil_instruction_display_no_operand_no_trailing_space() {
    let i = CilInstruction::simple(0, "nop");
    let s = format!("{i}");
    assert_eq!(s, "IL_0000: nop");
}

// ─────────────────────────── LocalVar / ExceptionHandler ───────────────────

#[test]
fn local_var_new_defaults_pinned_false() {
    let lv = LocalVar::new(3, "int32");
    assert_eq!(lv.index, 3);
    assert_eq!(lv.type_name, "int32");
    assert!(!lv.is_pinned);
}

#[test]
fn exception_handler_protects_inclusive_start_exclusive_end() {
    let eh = ExceptionHandler {
        try_start: 10,
        try_end: 20,
        ..Default::default()
    };
    assert!(!eh.protects(9));
    assert!(eh.protects(10));
    assert!(eh.protects(19));
    assert!(!eh.protects(20));
}

#[test]
fn exception_handler_handles_inclusive_start_exclusive_end() {
    let eh = ExceptionHandler {
        handler_start: 30,
        handler_end: 40,
        ..Default::default()
    };
    assert!(eh.handles(30));
    assert!(eh.handles(39));
    assert!(!eh.handles(40));
}

#[test]
fn exception_handler_kind_display() {
    assert_eq!(ExceptionHandlerKind::Catch.to_string(), "catch");
    assert_eq!(ExceptionHandlerKind::Filter.to_string(), "filter");
    assert_eq!(ExceptionHandlerKind::Finally.to_string(), "finally");
    assert_eq!(ExceptionHandlerKind::Fault.to_string(), "fault");
}

// ─────────────────────────── MethodBody ────────────────────────────────────

#[test]
fn method_body_instruction_at_missing_returns_none() {
    let b = MethodBody::default();
    assert!(b.instruction_at(0).is_none());
}

#[test]
fn method_body_instruction_at_found() {
    let b = MethodBody {
        instructions: vec![CilInstruction::simple(5, "nop")],
        ..Default::default()
    };
    assert!(b.instruction_at(5).is_some());
    assert!(b.instruction_at(0).is_none());
}

#[test]
fn method_body_branch_targets_sorted_unique() {
    let b = MethodBody {
        instructions: vec![
            CilInstruction::branch(0, "br", 10),
            CilInstruction::branch(2, "br", 5),
            CilInstruction::branch(4, "br", 10), // duplicate
        ],
        ..Default::default()
    };
    assert_eq!(b.branch_targets(), vec![5, 10]);
}

#[test]
fn method_body_has_finally_true() {
    let b = MethodBody {
        exception_handlers: vec![ExceptionHandler {
            kind: ExceptionHandlerKind::Finally,
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(b.has_finally());
    assert!(b.has_exception_handlers());
}

#[test]
fn method_body_has_finally_false_with_catch() {
    let b = MethodBody {
        exception_handlers: vec![ExceptionHandler::default()],
        ..Default::default()
    };
    assert!(!b.has_finally());
    assert!(b.has_exception_handlers());
}

#[test]
fn method_body_opcode_histogram_counts() {
    let b = MethodBody {
        instructions: vec![
            CilInstruction::simple(0, "nop"),
            CilInstruction::simple(1, "nop"),
            CilInstruction::simple(2, "ret"),
        ],
        ..Default::default()
    };
    let h = b.opcode_histogram();
    assert_eq!(h["nop"], 2);
    assert_eq!(h["ret"], 1);
}

#[test]
fn method_body_code_size_sums_byte_sizes() {
    let b = MethodBody {
        instructions: vec![
            CilInstruction::simple(0, "nop"),                  // 1
            CilInstruction::with_i32(1, "ldc.i4", 0),          // 5
        ],
        ..Default::default()
    };
    assert_eq!(b.code_size(), 6);
}

#[test]
fn method_body_try_instructions_for_filters() {
    let b = MethodBody {
        instructions: vec![
            CilInstruction::simple(0, "nop"),
            CilInstruction::simple(5, "nop"),
            CilInstruction::simple(15, "nop"),
        ],
        ..Default::default()
    };
    let eh = ExceptionHandler {
        try_start: 0,
        try_end: 10,
        ..Default::default()
    };
    let got = b.try_instructions_for(&eh);
    assert_eq!(got.len(), 2);
}

// ─────────────────────────── MethodSignature ───────────────────────────────

#[test]
fn method_signature_format_static() {
    let sig = MethodSignature {
        return_type: "void".into(),
        params: vec![("a".into(), "int".into())],
        is_static: true,
        ..Default::default()
    };
    assert_eq!(sig.format("Foo"), "static void Foo(int a)");
}

#[test]
fn method_signature_format_instance() {
    let sig = MethodSignature {
        return_type: "int".into(),
        params: vec![("x".into(), "int".into()), ("y".into(), "int".into())],
        ..Default::default()
    };
    assert_eq!(sig.format("Add"), "int Add(int x, int y)");
}

#[test]
fn method_signature_returns_void_system_void_too() {
    let s1 = MethodSignature { return_type: "System.Void".into(), ..Default::default() };
    assert!(s1.returns_void());
    let s2 = MethodSignature { return_type: "int".into(), ..Default::default() };
    assert!(!s2.returns_void());
}

#[test]
fn method_signature_param_count() {
    let sig = MethodSignature {
        params: vec![("a".into(), "int".into()), ("b".into(), "int".into())],
        ..Default::default()
    };
    assert_eq!(sig.param_count(), 2);
}

// ─────────────────────────── GenericParam flags ────────────────────────────

#[test]
fn generic_param_constraints() {
    let gp = GenericParam {
        number: 0,
        name: "T".into(),
        flags: 0x0004 | 0x0010,
        constraints: vec![],
    };
    assert!(gp.is_reference_type_constrained());
    assert!(!gp.is_value_type_constrained());
    assert!(gp.has_default_constructor_constraint());
}

// ─────────────────────────── GenericInstantiation ──────────────────────────

#[test]
fn generic_inst_format_arity() {
    let gi = GenericInstantiation {
        open_type: "Dict".into(),
        type_arguments: vec!["string".into(), "int".into()],
    };
    assert_eq!(gi.format(), "Dict<string, int>");
    assert_eq!(gi.arity(), 2);
}

#[test]
fn generic_inst_empty_arity() {
    let gi = GenericInstantiation { open_type: "X".into(), type_arguments: vec![] };
    assert_eq!(gi.arity(), 0);
    assert_eq!(gi.format(), "X<>");
}

// ─────────────────────────── AttributeValue Display ────────────────────────

#[test]
fn attribute_value_display_bool() {
    assert_eq!(AttributeValue::Bool(true).to_string(), "true");
}

#[test]
fn attribute_value_display_char() {
    assert_eq!(AttributeValue::Char('a').to_string(), "'a'");
}

#[test]
fn attribute_value_display_int64_with_l_suffix() {
    assert_eq!(AttributeValue::Int64(5).to_string(), "5L");
}

#[test]
fn attribute_value_display_uint64_with_ul_suffix() {
    assert_eq!(AttributeValue::UInt64(5).to_string(), "5UL");
}

#[test]
fn attribute_value_display_string_quoted() {
    assert_eq!(AttributeValue::String("hi".into()).to_string(), "\"hi\"");
}

#[test]
fn attribute_value_display_type_typeof() {
    assert_eq!(AttributeValue::Type("Foo".into()).to_string(), "typeof(Foo)");
}

#[test]
fn attribute_value_display_null() {
    assert_eq!(AttributeValue::Null.to_string(), "null");
}

#[test]
fn attribute_value_display_array() {
    let v = AttributeValue::Array(vec![
        AttributeValue::Int32(1),
        AttributeValue::Int32(2),
    ]);
    assert_eq!(v.to_string(), "[1, 2]");
}

// ─────────────────────────── CustomAttribute ────────────────────────────────

#[test]
fn custom_attribute_is_type_exact_match() {
    let a = CustomAttribute::from_blob("Foo", vec![]);
    assert!(a.is_type("Foo"));
}

#[test]
fn custom_attribute_is_type_dot_suffix() {
    let a = CustomAttribute::from_blob("System.ObsoleteAttribute", vec![]);
    assert!(a.is_type("ObsoleteAttribute"));
}

#[test]
fn custom_attribute_is_type_colon_suffix() {
    let a = CustomAttribute::from_blob("Foo::Bar", vec![]);
    assert!(a.is_type("Bar"));
}

#[test]
fn custom_attribute_is_type_no_match() {
    let a = CustomAttribute::from_blob("Foo", vec![]);
    assert!(!a.is_type("Bar"));
}

#[test]
fn custom_attribute_blob_preserved() {
    let a = CustomAttribute::from_blob("X", vec![1, 2, 3]);
    assert_eq!(a.raw_blob, vec![1, 2, 3]);
}

// ─────────────────────────── PropertyModel ─────────────────────────────────

fn make_prop(get: Option<&str>, set: Option<&str>) -> PropertyModel {
    PropertyModel {
        name: "P".into(),
        type_name: "int".into(),
        flags: 0,
        getter: get.map(str::to_string),
        setter: set.map(str::to_string),
        custom_attributes: vec![],
        has_default: false,
        default_value: None,
    }
}

#[test]
fn property_read_only() {
    let p = make_prop(Some("get_P"), None);
    assert!(p.is_read_only());
    assert!(!p.is_write_only());
}

#[test]
fn property_write_only() {
    let p = make_prop(None, Some("set_P"));
    assert!(p.is_write_only());
    assert!(!p.is_read_only());
}

#[test]
fn property_rw_neither_readonly_nor_writeonly() {
    let p = make_prop(Some("g"), Some("s"));
    assert!(!p.is_read_only());
    assert!(!p.is_write_only());
}

#[test]
fn property_signature_get_set() {
    let p = make_prop(Some("g"), Some("s"));
    assert!(p.signature().contains("{ get; set; }"));
}

#[test]
fn property_signature_get_only() {
    let p = make_prop(Some("g"), None);
    assert!(p.signature().contains("{ get; }"));
}

#[test]
fn property_signature_set_only() {
    let p = make_prop(None, Some("s"));
    assert!(p.signature().contains("{ set; }"));
}

#[test]
fn property_signature_none() {
    let p = make_prop(None, None);
    assert!(p.signature().contains("{ }"));
}

// ─────────────────────────── EventModel ────────────────────────────────────

#[test]
fn event_has_add_remove() {
    let e = EventModel {
        name: "E".into(),
        type_name: "Handler".into(),
        flags: 0,
        add: Some("add_E".into()),
        remove: None,
        raise: None,
        custom_attributes: vec![],
    };
    assert!(e.has_add());
    assert!(!e.has_remove());
}

// ─────────────────────────── MethodFlags ───────────────────────────────────

#[test]
fn method_flags_public() {
    let f = MethodFlags::from_raw(0x06);
    assert!(f.is_public());
    assert_eq!(f.access_modifier(), "public");
}

#[test]
fn method_flags_private() {
    let f = MethodFlags::from_raw(0x01);
    assert!(f.is_private());
    assert_eq!(f.access_modifier(), "private");
}

#[test]
fn method_flags_static_virtual_abstract() {
    let f = MethodFlags::from_raw(0x06 | 0x10 | 0x40 | 0x400);
    assert!(f.is_static());
    assert!(f.is_virtual());
    assert!(f.is_abstract());
}

#[test]
fn method_flags_sealed_and_final_share_bit() {
    let f = MethodFlags::from_raw(0x20);
    assert!(f.is_sealed());
    assert!(f.is_final());
}

#[test]
fn method_flags_pinvoke() {
    let f = MethodFlags::from_raw(0x2000);
    assert!(f.is_pinvoke());
}

#[test]
fn method_flags_internal_modifier() {
    let f = MethodFlags::from_raw(0x03);
    assert_eq!(f.access_modifier(), "internal");
}

#[test]
fn method_flags_protected_modifier() {
    let f = MethodFlags::from_raw(0x04);
    assert_eq!(f.access_modifier(), "protected");
}

// ─────────────────────────── DotnetMethod helpers ──────────────────────────

fn make_method(name: &str, flags: u32) -> DotnetMethod {
    DotnetMethod {
        name: name.into(),
        flags,
        ..Default::default()
    }
}

#[test]
fn dotnet_method_constructor_detection() {
    assert!(make_method(".ctor", 0).is_constructor());
    assert!(!make_method(".ctor", 0).is_static_constructor());
    assert!(make_method(".cctor", 0).is_static_constructor());
    assert!(!make_method("Foo", 0).is_constructor());
}

#[test]
fn dotnet_method_property_accessor() {
    assert!(make_method("get_Name", 0).is_property_accessor());
    assert!(make_method("set_Name", 0).is_property_accessor());
    assert!(!make_method("Name", 0).is_property_accessor());
}

#[test]
fn dotnet_method_event_accessor() {
    assert!(make_method("add_E", 0).is_event_accessor());
    assert!(make_method("remove_E", 0).is_event_accessor());
    assert!(make_method("raise_E", 0).is_event_accessor());
    assert!(!make_method("E", 0).is_event_accessor());
}

#[test]
fn dotnet_method_static_virtual_abstract() {
    assert!(make_method("F", 0x10).is_static());
    assert!(make_method("F", 0x40).is_virtual());
    assert!(make_method("F", 0x400).is_abstract());
    assert!(!make_method("F", 0).is_static());
}

#[test]
fn dotnet_method_has_body_false_default() {
    assert!(!make_method("F", 0).has_body());
    assert_eq!(make_method("F", 0).instruction_count(), 0);
}

#[test]
fn dotnet_method_has_body_true_with_body() {
    let mut m = make_method("F", 0);
    m.body = Some(MethodBody {
        instructions: vec![CilInstruction::simple(0, "nop")],
        ..Default::default()
    });
    assert!(m.has_body());
    assert_eq!(m.instruction_count(), 1);
}

#[test]
fn dotnet_method_branch_instructions_empty_when_no_body() {
    assert!(make_method("F", 0).branch_instructions().is_empty());
}

#[test]
fn dotnet_method_branch_instructions_filters() {
    let mut m = make_method("F", 0);
    m.body = Some(MethodBody {
        instructions: vec![
            CilInstruction::simple(0, "nop"),
            CilInstruction::branch(1, "br", 5),
        ],
        ..Default::default()
    });
    assert_eq!(m.branch_instructions().len(), 1);
}

#[test]
fn dotnet_method_get_custom_attribute() {
    let mut m = make_method("F", 0);
    m.custom_attributes
        .push(CustomAttribute::from_blob("System.ObsoleteAttribute", vec![]));
    assert!(m.has_custom_attributes());
    assert!(m.get_custom_attribute("ObsoleteAttribute").is_some());
    assert!(m.get_custom_attribute("Missing").is_none());
}

// ─────────────────────────── FieldFlags / DotnetField ──────────────────────

#[test]
fn field_flags_literal_init_only() {
    let f = FieldFlags::from_raw(0x40);
    assert!(f.is_literal());
    let g = FieldFlags::from_raw(0x20);
    assert!(g.is_init_only());
}

#[test]
fn field_flags_visibility_modifiers() {
    assert_eq!(FieldFlags::from_raw(0x06).access_modifier(), "public");
    assert_eq!(FieldFlags::from_raw(0x01).access_modifier(), "private");
    assert_eq!(FieldFlags::from_raw(0x04).access_modifier(), "protected");
    assert_eq!(FieldFlags::from_raw(0x03).access_modifier(), "internal");
}

#[test]
fn dotnet_field_format_static() {
    let f = DotnetField {
        name: "X".into(),
        type_name: "int".into(),
        is_static: true,
        ..Default::default()
    };
    assert_eq!(f.format(), "public static int X;");
}

#[test]
fn dotnet_field_format_instance() {
    let f = DotnetField {
        name: "X".into(),
        type_name: "int".into(),
        ..Default::default()
    };
    assert_eq!(f.format(), "public int X;");
}

#[test]
fn dotnet_field_is_literal_via_flags() {
    let f = DotnetField {
        flags: 0x40,
        ..Default::default()
    };
    assert!(f.is_literal());
    assert!(!f.is_init_only());
}

// ─────────────────────────── TypeFlags ─────────────────────────────────────

#[test]
fn type_flags_public_visibility() {
    let f = TypeFlags::from_raw(0x01);
    assert_eq!(f.visibility(), TypeVisibility::Public);
}

#[test]
fn type_flags_nested_visibilities() {
    assert_eq!(TypeFlags::from_raw(0x02).visibility(), TypeVisibility::NestedPublic);
    assert_eq!(TypeFlags::from_raw(0x03).visibility(), TypeVisibility::NestedPrivate);
    assert_eq!(TypeFlags::from_raw(0x04).visibility(), TypeVisibility::NestedFamily);
    assert_eq!(TypeFlags::from_raw(0x05).visibility(), TypeVisibility::NestedAssembly);
    assert_eq!(TypeFlags::from_raw(0x06).visibility(), TypeVisibility::NestedFamilyAndAssembly);
    assert_eq!(TypeFlags::from_raw(0x07).visibility(), TypeVisibility::NestedFamilyOrAssembly);
}

#[test]
fn type_flags_sealed_abstract_interface() {
    let f = TypeFlags::from_raw(0x0100 | 0x0080 | 0x0020);
    assert!(f.is_sealed());
    assert!(f.is_abstract());
    assert!(f.is_interface());
}

#[test]
fn type_flags_explicit_layout() {
    let f = TypeFlags::from_raw(0x0010);
    assert!(f.is_explicit_layout());
    assert!(!f.is_sequential_layout());
}

#[test]
fn type_flags_sequential_layout() {
    let f = TypeFlags::from_raw(0x0008);
    assert!(f.is_sequential_layout());
    assert!(!f.is_explicit_layout());
}

// ─────────────────────────── DotnetType helpers ────────────────────────────

fn make_type() -> DotnetType {
    DotnetType {
        name: "T".into(),
        namespace: "N".into(),
        full_name: "N.T".into(),
        base_type: None,
        interfaces: vec!["System.IDisposable".into(), "IFoo".into()],
        methods: vec![
            make_method(".ctor", 0),
            make_method(".cctor", 0x10),
            make_method("get_X", 0),
            make_method("DoThing", 0x10),       // static
            make_method("VirtMethod", 0x40),    // virtual
            make_method("AbsMethod", 0x400),    // abstract
        ],
        fields: vec![
            DotnetField { name: "a".into(), is_static: true, flags: 0x40, ..Default::default() },
            DotnetField { name: "b".into(), is_static: false, ..Default::default() },
        ],
        properties: vec![],
        events: vec![],
        nested_types: vec![],
        custom_attributes: vec![CustomAttribute::from_blob("Attr", vec![])],
        generic_params: vec![],
        kind_tag: DotnetTypeKind::Class,
        flags: 0x01 | 0x0100, // public + sealed
        layout: None,
    }
}

#[test]
fn dotnet_type_kind_class() {
    let t = make_type();
    assert_eq!(t.kind(), "class");
}

#[test]
fn dotnet_type_kind_interface_struct_enum_delegate() {
    let mut t = make_type();
    t.kind_tag = DotnetTypeKind::Interface;
    assert_eq!(t.kind(), "interface");
    t.kind_tag = DotnetTypeKind::Enum;
    assert_eq!(t.kind(), "enum");
    t.kind_tag = DotnetTypeKind::Struct;
    assert_eq!(t.kind(), "struct");
    t.kind_tag = DotnetTypeKind::Delegate;
    assert_eq!(t.kind(), "delegate");
}

#[test]
fn dotnet_type_is_sealed_abstract() {
    let t = make_type();
    assert!(t.is_sealed());
    assert!(!t.is_abstract());
}

#[test]
fn dotnet_type_access_modifier_public() {
    let t = make_type();
    assert_eq!(t.access_modifier(), "public");
}

#[test]
fn dotnet_type_find_method_present() {
    let t = make_type();
    assert!(t.find_method("DoThing").is_some());
    assert!(t.find_method("Missing").is_none());
}

#[test]
fn dotnet_type_find_methods_overloads() {
    let mut t = make_type();
    t.methods.push(make_method("DoThing", 0));
    assert_eq!(t.find_methods("DoThing").len(), 2);
}

#[test]
fn dotnet_type_constructors_and_static_ctor() {
    let t = make_type();
    assert_eq!(t.constructors().len(), 1);
    assert!(t.static_constructor().is_some());
}

#[test]
fn dotnet_type_static_methods_includes_cctor() {
    let t = make_type();
    // .cctor has flags 0x10 (static); DoThing is also static
    assert!(t.static_methods().len() >= 2);
}

#[test]
fn dotnet_type_instance_methods_excludes_ctors_and_static() {
    let t = make_type();
    let im = t.instance_methods();
    for m in &im {
        assert!(!m.is_static());
        assert!(!m.is_constructor());
        assert!(!m.is_static_constructor());
    }
}

#[test]
fn dotnet_type_virtual_methods_filter() {
    let t = make_type();
    assert!(t.virtual_methods().iter().any(|m| m.name == "VirtMethod"));
}

#[test]
fn dotnet_type_abstract_methods_filter() {
    let t = make_type();
    assert!(t.abstract_methods().iter().any(|m| m.name == "AbsMethod"));
}

#[test]
fn dotnet_type_static_instance_constant_fields() {
    let t = make_type();
    assert_eq!(t.static_fields().len(), 1);
    assert_eq!(t.instance_fields().len(), 1);
    assert_eq!(t.constant_fields().len(), 1); // 'a' has 0x40 literal flag
}

#[test]
fn dotnet_type_implements_interface() {
    let t = make_type();
    assert!(t.implements("IFoo"));
    assert!(t.implements("IDisposable")); // matches via .Suffix
    assert!(!t.implements("IBar"));
}

#[test]
fn dotnet_type_method_and_field_count() {
    let t = make_type();
    assert_eq!(t.method_count(), 6);
    assert_eq!(t.field_count(), 2);
}

#[test]
fn dotnet_type_custom_attr_lookup() {
    let t = make_type();
    assert!(t.has_custom_attributes());
    assert!(t.get_custom_attribute("Attr").is_some());
}

// ─────────────────────────── AssemblyVersion / Info ────────────────────────

#[test]
fn assembly_version_display() {
    let v = AssemblyVersion { major: 1, minor: 2, build: 3, revision: 4 };
    assert_eq!(v.to_string(), "1.2.3.4");
}

#[test]
fn assembly_info_strong_named_and_retargetable() {
    let mut a = AssemblyInfo::default();
    assert!(!a.is_strong_named());
    a.public_key = vec![1, 2];
    assert!(a.is_strong_named());
    a.flags = 0x0100;
    assert!(a.is_retargetable());
}

#[test]
fn assembly_info_display_name() {
    let a = AssemblyInfo {
        name: "X".into(),
        version: AssemblyVersion { major: 1, minor: 0, build: 0, revision: 0 },
        ..Default::default()
    };
    assert_eq!(a.display_name(), "X, Version=1.0.0.0");
}

#[test]
fn assembly_reference_display_and_retargetable() {
    let mut r = AssemblyReference::default();
    r.name = "Y".into();
    r.version = AssemblyVersion { major: 2, minor: 0, build: 0, revision: 0 };
    assert_eq!(r.display_name(), "Y, Version=2.0.0.0");
    assert!(!r.is_retargetable());
    r.flags = 0x0100;
    assert!(r.is_retargetable());
}

// ─────────────────────────── DotnetError ───────────────────────────────────

#[test]
fn dotnet_error_display_variants() {
    assert!(DotnetError::TypeNotFound("F".into()).to_string().contains('F'));
    let e = DotnetError::MethodNotFound {
        type_name: "T".into(),
        method_name: "M".into(),
    };
    let s = e.to_string();
    assert!(s.contains('T') && s.contains('M'));

    let e2 = DotnetError::FieldNotFound {
        type_name: "T".into(),
        field_name: "f".into(),
    };
    assert!(e2.to_string().contains('f'));

    let e3 = DotnetError::InvalidSignature("bad".into());
    assert!(e3.to_string().contains("bad"));
}

#[test]
fn dotnet_error_io_from_conversion() {
    let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
    let e: DotnetError = io.into();
    match e {
        DotnetError::IoError(_) => {}
        _ => panic!("wrong variant"),
    }
}

#[test]
fn dotnet_error_source_for_io_some() {
    use std::error::Error;
    let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
    let e: DotnetError = io.into();
    assert!(e.source().is_some());
}

#[test]
fn dotnet_error_source_for_others_none() {
    use std::error::Error;
    let e = DotnetError::TypeNotFound("x".into());
    assert!(e.source().is_none());
}

// ─────────────────────────── AssemblyResolver ──────────────────────────────

#[test]
fn assembly_resolver_new_cached_names_empty() {
    let r = AssemblyResolver::new(vec![]);
    assert!(r.cached_names().is_empty());
}

#[test]
fn assembly_resolver_add_path_does_not_panic() {
    let mut r = AssemblyResolver::new(vec![]);
    r.add_path("/tmp");
    assert!(r.cached_names().is_empty());
}

#[test]
fn assembly_resolver_resolve_missing_errors() {
    let mut r = AssemblyResolver::new(vec![std::path::PathBuf::from("/no/such/dir")]);
    assert!(r.resolve("NonExistent").is_err());
}

// ─────────────────────────── AssemblyFile::open errors ─────────────────────

#[test]
fn assembly_file_open_missing() {
    let p = std::path::Path::new("/definitely/does/not/exist/blitz.dll");
    assert!(AssemblyFile::open(p).is_err());
}

// ─────────────────────────── BasicBlock ────────────────────────────────────

#[test]
fn basic_block_empty_body_returns_empty() {
    let body = MethodBody::default();
    assert!(BasicBlock::from_body(&body).is_empty());
}

#[test]
fn basic_block_single_block_straight_line() {
    let body = MethodBody {
        instructions: vec![
            CilInstruction::simple(0, "nop"),
            CilInstruction::simple(1, "ldc.i4.0"),
            CilInstruction::simple(2, "ret"),
        ],
        ..Default::default()
    };
    let bbs = BasicBlock::from_body(&body);
    assert_eq!(bbs.len(), 1);
    assert_eq!(bbs[0].start_offset, 0);
    assert!(bbs[0].successors.is_empty()); // ret has no successor
}

#[test]
fn basic_block_split_at_branch_target() {
    let body = MethodBody {
        instructions: vec![
            CilInstruction::branch(0, "br", 2),
            CilInstruction::simple(1, "nop"),
            CilInstruction::simple(2, "ret"),
        ],
        ..Default::default()
    };
    let bbs = BasicBlock::from_body(&body);
    // Leaders: 0 (first), 1 (after terminator), 2 (target & after term)
    assert!(bbs.len() >= 2);
}

#[test]
fn basic_block_unconditional_branch_no_fallthrough() {
    let body = MethodBody {
        instructions: vec![
            CilInstruction::branch(0, "br", 10),
            CilInstruction::simple(5, "ret"),
            CilInstruction::simple(10, "ret"),
        ],
        ..Default::default()
    };
    let bbs = BasicBlock::from_body(&body);
    // The br block should only have branch target as successor, not the next leader
    let first = bbs.iter().find(|b| b.start_offset == 0).expect("first block");
    assert_eq!(first.successors, vec![10]);
}

// ─────────────────────────── ParameterDef ──────────────────────────────────

#[test]
fn parameter_def_in_out_optional() {
    let p = ParameterDef {
        flags: 0x0001 | 0x0002 | 0x0010,
        ..Default::default()
    };
    assert!(p.is_in());
    assert!(p.is_out());
    assert!(p.is_optional());
}

#[test]
fn parameter_def_has_default_via_flag() {
    let p = ParameterDef { flags: 0x1000, ..Default::default() };
    assert!(p.has_default());
}

#[test]
fn parameter_def_is_return_value_index_zero() {
    let p = ParameterDef { index: 0, ..Default::default() };
    assert!(p.is_return_value());
    let p2 = ParameterDef { index: 1, ..Default::default() };
    assert!(!p2.is_return_value());
}

#[test]
fn parameter_def_format_ref_when_in_and_out() {
    let p = ParameterDef {
        flags: 0x0001 | 0x0002,
        type_name: "int".into(),
        name: "x".into(),
        ..Default::default()
    };
    assert_eq!(p.format(), "ref int x");
}

#[test]
fn parameter_def_format_out_only() {
    let p = ParameterDef {
        flags: 0x0002,
        type_name: "int".into(),
        name: "x".into(),
        ..Default::default()
    };
    assert_eq!(p.format(), "out int x");
}

#[test]
fn parameter_def_format_plain() {
    let p = ParameterDef {
        flags: 0,
        type_name: "int".into(),
        name: "x".into(),
        ..Default::default()
    };
    assert_eq!(p.format(), "int x");
}

// ─────────────────────────── BindingRedirect ───────────────────────────────

#[test]
fn binding_redirect_matches_in_range() {
    let br = BindingRedirect {
        assembly_name: "X".into(),
        old_version_min: AssemblyVersion { major: 1, minor: 0, build: 0, revision: 0 },
        old_version_max: AssemblyVersion { major: 2, minor: 5, build: 0, revision: 0 },
        new_version: AssemblyVersion { major: 3, minor: 0, build: 0, revision: 0 },
        public_key_token: None,
        culture: None,
    };
    assert!(br.matches(&AssemblyVersion { major: 1, minor: 5, build: 0, revision: 0 }));
    assert!(br.matches(&AssemblyVersion { major: 2, minor: 0, build: 0, revision: 0 }));
    assert!(!br.matches(&AssemblyVersion { major: 0, minor: 9, build: 0, revision: 0 }));
    assert!(!br.matches(&AssemblyVersion { major: 2, minor: 6, build: 0, revision: 0 }));
}

#[test]
fn binding_redirect_xml_contains_fields() {
    let br = BindingRedirect {
        assembly_name: "Lib".into(),
        old_version_min: AssemblyVersion { major: 1, minor: 0, build: 0, revision: 0 },
        old_version_max: AssemblyVersion { major: 1, minor: 9, build: 0, revision: 0 },
        new_version: AssemblyVersion { major: 2, minor: 0, build: 0, revision: 0 },
        public_key_token: None,
        culture: None,
    };
    let xml = br.to_config_xml();
    assert!(xml.contains("Lib"));
    assert!(xml.contains("oldVersion=\"1.0.0.0-1.9.0.0\""));
    assert!(xml.contains("newVersion=\"2.0.0.0\""));
}

// ─────────────────────────── TypeHierarchyNode ─────────────────────────────

#[test]
fn type_hierarchy_node_leaf_root() {
    let n = TypeHierarchyNode::leaf("X", None);
    assert!(n.is_root());
    assert!(n.is_leaf());
}

#[test]
fn type_hierarchy_node_not_root_with_base() {
    let n = TypeHierarchyNode::leaf("X", Some("Y".into()));
    assert!(!n.is_root());
}

#[test]
fn build_type_hierarchy_links_children() {
    let parent = DotnetType {
        name: "P".into(), namespace: String::new(), full_name: "P".into(),
        base_type: None, interfaces: vec![], methods: vec![], fields: vec![],
        properties: vec![], events: vec![], nested_types: vec![],
        custom_attributes: vec![], generic_params: vec![],
        kind_tag: DotnetTypeKind::Class, flags: 0, layout: None,
    };
    let child = DotnetType {
        name: "C".into(), namespace: String::new(), full_name: "C".into(),
        base_type: Some("P".into()), interfaces: vec![], methods: vec![], fields: vec![],
        properties: vec![], events: vec![], nested_types: vec![],
        custom_attributes: vec![], generic_params: vec![],
        kind_tag: DotnetTypeKind::Class, flags: 0, layout: None,
    };
    let h = build_type_hierarchy(&[parent, child]);
    let p_node = h.iter().find(|n| n.full_name == "P").unwrap();
    assert!(p_node.children.contains(&"C".to_string()));
    let c_node = h.iter().find(|n| n.full_name == "C").unwrap();
    assert_eq!(c_node.base.as_deref(), Some("P"));
}

// ─────────────────────────── ResolvedTypeRef ───────────────────────────────

#[test]
fn resolved_type_ref_full_name_and_is_resolved() {
    let a = ResolvedTypeRef::InAssembly("A".into());
    assert_eq!(a.full_name(), "A");
    assert!(a.is_resolved());

    let b = ResolvedTypeRef::External { assembly: "x".into(), full_name: "B".into() };
    assert_eq!(b.full_name(), "B");
    assert!(b.is_resolved());

    let c = ResolvedTypeRef::Unknown("C".into());
    assert_eq!(c.full_name(), "C");
    assert!(!c.is_resolved());
}

// ─────────────────────────── token_table sanity ────────────────────────────

#[test]
fn token_table_known_constants() {
    use rustre_dotnet::token_table;
    assert_eq!(token_table::MODULE, 0x00);
    assert_eq!(token_table::TYPE_REF, 0x01);
    assert_eq!(token_table::TYPE_DEF, 0x02);
    assert_eq!(token_table::FIELD, 0x04);
    assert_eq!(token_table::METHOD_DEF, 0x06);
}
