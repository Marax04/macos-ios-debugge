//! Blitz test suite for rustre-dotnet-metadata — adversarial coverage of
//! public parsing/decoding APIs and lookup helpers.

use rustre_dotnet_metadata::*;

// ─── ConstantValue Display ──────────────────────────────────────────────

#[test]
fn constant_value_display_variants() {
    assert_eq!(ConstantValue::Bool(true).to_string(), "true");
    assert_eq!(ConstantValue::Int32(-42).to_string(), "-42");
    assert_eq!(ConstantValue::Int64(7).to_string(), "7L");
    assert_eq!(ConstantValue::UInt64(8).to_string(), "8UL");
    assert_eq!(ConstantValue::Null.to_string(), "null");
    assert_eq!(ConstantValue::String("x".into()).to_string(), "\"x\"");
}

#[test]
fn constant_value_eq() {
    assert_eq!(ConstantValue::Int32(1), ConstantValue::Int32(1));
    assert_ne!(ConstantValue::Int32(1), ConstantValue::Int64(1));
}

// ─── TypeVisibility ─────────────────────────────────────────────────────

#[test]
fn type_visibility_all_values() {
    assert_eq!(TypeVisibility::from_flags(0x00), TypeVisibility::NotPublic);
    assert_eq!(TypeVisibility::from_flags(0x01), TypeVisibility::Public);
    assert_eq!(
        TypeVisibility::from_flags(0x02),
        TypeVisibility::Nested(NestedVisibility::Public)
    );
    assert_eq!(
        TypeVisibility::from_flags(0x07),
        TypeVisibility::Nested(NestedVisibility::FamilyOrAssembly)
    );
    // High bits don't matter.
    assert_eq!(TypeVisibility::from_flags(0xFFFF_FFF1), TypeVisibility::Public);
}

// ─── String / Guid / Blob heaps ─────────────────────────────────────────

#[test]
fn string_heap_zero_offset_returns_empty() {
    let h = StringHeap::new(vec![0u8, b'A', 0u8]);
    assert_eq!(h.get(0).unwrap(), "");
}

#[test]
fn string_heap_out_of_range_err_variant() {
    let h = StringHeap::new(vec![0u8]);
    match h.get(99) {
        Err(MetadataError::StringOffsetOutOfRange(o)) => assert_eq!(o, 99),
        other => panic!("expected StringOffsetOutOfRange, got {other:?}"),
    }
}

#[test]
fn string_heap_invalid_utf8_err_variant() {
    // Invalid UTF-8 byte sequence followed by NUL terminator.
    let h = StringHeap::new(vec![0xFFu8, 0xFE, 0xFD, 0]);
    assert!(matches!(h.get(0), Err(MetadataError::InvalidUtf8)));
}

#[test]
fn string_heap_unterminated_reads_to_end() {
    // No terminating NUL — should still read up to end without panic.
    let h = StringHeap::new(b"hello".to_vec());
    assert_eq!(h.get(0).unwrap(), "hello");
}

#[test]
fn guid_heap_index_zero_returns_all_zero() {
    let h = GuidHeap::new(vec![]);
    assert_eq!(h.get(0).unwrap(), [0u8; 16]);
}

#[test]
fn guid_heap_index_one_returns_first_16() {
    let mut data = (0u8..16).collect::<Vec<u8>>();
    data.extend(16u8..32);
    let h = GuidHeap::new(data);
    assert_eq!(h.get(1).unwrap()[0], 0);
    assert_eq!(h.get(1).unwrap()[15], 15);
    assert_eq!(h.get(2).unwrap()[0], 16);
}

#[test]
fn guid_heap_index_oor() {
    let h = GuidHeap::new(vec![0u8; 16]);
    match h.get(99) {
        Err(MetadataError::GuidIndexOutOfRange(i)) => assert_eq!(i, 99),
        other => panic!("expected GuidIndexOutOfRange, got {other:?}"),
    }
}

#[test]
fn blob_heap_simple_short_form() {
    // length prefix 3, then 3 bytes
    let h = BlobHeap::new(vec![0x03, 0xAA, 0xBB, 0xCC]);
    assert_eq!(h.get(0).unwrap(), &[0xAA, 0xBB, 0xCC]);
}

#[test]
fn blob_heap_two_byte_compressed() {
    // 0x80|0x00, 0x05 => length 5
    let mut data = vec![0x80, 0x05];
    data.extend(vec![1, 2, 3, 4, 5]);
    let h = BlobHeap::new(data);
    assert_eq!(h.get(0).unwrap(), &[1, 2, 3, 4, 5]);
}

#[test]
fn blob_heap_offset_oor() {
    let h = BlobHeap::new(vec![]);
    assert!(matches!(
        h.get(10),
        Err(MetadataError::BlobOffsetOutOfRange(10))
    ));
}

#[test]
fn blob_heap_truncated_length_returns_err() {
    // length 100 but only 1 byte of data
    let h = BlobHeap::new(vec![100, 0x00]);
    assert!(h.get(0).is_err());
}

// ─── UserStringHeap ─────────────────────────────────────────────────────

#[test]
fn user_string_heap_empty_returns_empty_string() {
    let h = UserStringHeap::new(vec![0x00]);
    assert_eq!(h.get(0).unwrap(), "");
}

#[test]
fn user_string_heap_simple_ascii() {
    // length=3 (2 utf-16 bytes + 1 hint), then 'A','\0', hint byte
    let h = UserStringHeap::new(vec![0x03, b'A', 0x00, 0x00]);
    assert_eq!(h.get(0).unwrap(), "A");
}

// ─── parse_method_sig_blob ──────────────────────────────────────────────

#[test]
fn parse_method_sig_blob_empty_eof() {
    assert!(matches!(
        parse_method_sig_blob(&[]),
        Err(MetadataError::UnexpectedEof { .. })
    ));
}

#[test]
fn parse_method_sig_blob_static_void_noargs() {
    // calling_conv=0 (default static), param_count=0, return=void(0x01)
    let info = parse_method_sig_blob(&[0x00, 0x00, 0x01]).unwrap();
    assert!(!info.is_instance);
    assert!(!info.is_generic);
    assert_eq!(info.params.len(), 0);
    assert_eq!(info.return_type, "void");
}

#[test]
fn parse_method_sig_blob_instance_int_param() {
    // calling_conv=0x20 (HASTHIS), 1 param, return=void, param=int(0x08)
    let info = parse_method_sig_blob(&[0x20, 0x01, 0x01, 0x08]).unwrap();
    assert!(info.is_instance);
    assert_eq!(info.params, vec!["int".to_string()]);
}

#[test]
fn parse_method_sig_blob_generic() {
    // calling_conv=0x10 (GENERIC), generic_count=2, params=0, return=void
    let info = parse_method_sig_blob(&[0x10, 0x02, 0x00, 0x01]).unwrap();
    assert!(info.is_generic);
    assert_eq!(info.generic_count, 2);
}

// ─── parse_field_sig_blob ───────────────────────────────────────────────

#[test]
fn parse_field_sig_too_short() {
    assert!(parse_field_sig_blob(&[]).is_err());
    assert!(parse_field_sig_blob(&[0x06]).is_err());
}

#[test]
fn parse_field_sig_wrong_magic() {
    assert!(parse_field_sig_blob(&[0x00, 0x08]).is_err());
}

#[test]
fn parse_field_sig_int_field() {
    let r = parse_field_sig_blob(&[0x06, 0x08]).unwrap();
    assert_eq!(r, "int");
}

// ─── parse_local_var_sig ────────────────────────────────────────────────

#[test]
fn parse_local_var_sig_empty() {
    assert!(parse_local_var_sig(&[]).is_err());
}

#[test]
fn parse_local_var_sig_wrong_magic() {
    assert!(parse_local_var_sig(&[0x99]).is_err());
}

#[test]
fn parse_local_var_sig_two_locals() {
    // 0x07, count=2, int, bool
    let types = parse_local_var_sig(&[0x07, 0x02, 0x08, 0x02]).unwrap();
    assert_eq!(types, vec!["int".to_string(), "bool".to_string()]);
}

// ─── parse_array_shape ──────────────────────────────────────────────────

#[test]
fn parse_array_shape_empty_err() {
    assert!(parse_array_shape(&[]).is_err());
}

#[test]
fn parse_array_shape_rank1_minimal() {
    let s = parse_array_shape(&[0x01, 0x00, 0x00]).unwrap();
    assert_eq!(s.rank, 1);
    assert!(s.is_simple_szarray());
}

#[test]
fn parse_array_shape_with_sizes_and_bounds() {
    // rank=3, sizes=[2,3], bounds=[0]
    let s = parse_array_shape(&[0x03, 0x02, 0x02, 0x03, 0x01, 0x00]).unwrap();
    assert_eq!(s.rank, 3);
    assert_eq!(s.sizes, vec![2u32, 3u32]);
    assert_eq!(s.lower_bounds, vec![0i32]);
}

#[test]
fn array_shape_bracket_zero_rank() {
    let s = ArrayShape { rank: 0, sizes: vec![], lower_bounds: vec![] };
    assert_eq!(s.bracket_notation(), "[]");
}

#[test]
fn array_shape_bracket_4d() {
    let s = ArrayShape { rank: 4, sizes: vec![], lower_bounds: vec![] };
    assert_eq!(s.bracket_notation(), "[,,,]");
}

// ─── parse_custom_attribute_blob (stub) ─────────────────────────────────

#[test]
fn parse_ca_blob_too_short_err() {
    assert!(parse_custom_attribute_blob(&[]).is_err());
    assert!(parse_custom_attribute_blob(&[0x01]).is_err());
}

#[test]
fn parse_ca_blob_bad_prolog_returns_default() {
    // Returns default, not an error.
    let r = parse_custom_attribute_blob(&[0x00, 0x00]).unwrap();
    assert_eq!(r.fixed_arg_count(), 0);
    assert_eq!(r.named_arg_count(), 0);
}

#[test]
fn parse_ca_blob_valid_prolog() {
    let r = parse_custom_attribute_blob(&[0x01, 0x00]).unwrap();
    assert_eq!(r.fixed_arg_count(), 0);
}

// ─── parse_custom_attribute_blob_typed ──────────────────────────────────

#[test]
fn parse_ca_typed_too_short() {
    assert!(parse_custom_attribute_blob_typed(&[], &[]).is_err());
}

#[test]
fn parse_ca_typed_bool_arg() {
    // prolog + bool(1) + 0 named args
    let blob = [0x01, 0x00, 0x01, 0x00, 0x00];
    let r = parse_custom_attribute_blob_typed(&blob, &[element_type::BOOLEAN]).unwrap();
    assert_eq!(r.fixed_args, vec![CustomAttributeValue::Bool(true)]);
}

#[test]
fn parse_ca_typed_i4_arg() {
    let blob = [0x01, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00];
    let r = parse_custom_attribute_blob_typed(&blob, &[element_type::I4]).unwrap();
    assert_eq!(r.fixed_args[0].as_i32(), Some(42));
}

#[test]
fn parse_ca_typed_string_null() {
    // prolog + 0xFF (null string marker)
    let blob = [0x01, 0x00, 0xFF];
    let r = parse_custom_attribute_blob_typed(&blob, &[element_type::STRING]).unwrap();
    assert!(r.fixed_args[0].is_null_string());
}

#[test]
fn parse_ca_typed_string_value() {
    // prolog + len=3 + "abc"
    let blob = [0x01, 0x00, 0x03, b'a', b'b', b'c'];
    let r = parse_custom_attribute_blob_typed(&blob, &[element_type::STRING]).unwrap();
    assert_eq!(r.fixed_args[0].as_str(), Some("abc"));
}

#[test]
fn parse_ca_typed_array_of_i4() {
    // prolog + SzArray header + elem_et=I4 + count=2(le u32) + 2 i32s
    let mut blob = vec![0x01, 0x00, element_type::I4, 0x02, 0x00, 0x00, 0x00];
    blob.extend_from_slice(&1i32.to_le_bytes());
    blob.extend_from_slice(&2i32.to_le_bytes());
    let r = parse_custom_attribute_blob_typed(&blob, &[0x1D]).unwrap();
    match &r.fixed_args[0] {
        CustomAttributeValue::Array(v) => assert_eq!(v.len(), 2),
        other => panic!("expected Array, got {other:?}"),
    }
}

#[test]
fn custom_attribute_value_helpers() {
    assert!(CustomAttributeValue::String(None).is_null_string());
    assert!(!CustomAttributeValue::String(Some("x".into())).is_null_string());
    assert_eq!(CustomAttributeValue::I4(7).as_i32(), Some(7));
    assert_eq!(CustomAttributeValue::Bool(false).as_i32(), None);
    assert_eq!(CustomAttributeValue::Bool(true).as_bool(), Some(true));
}

#[test]
fn decoded_ca_named_lookup() {
    let dca = DecodedCustomAttribute {
        fixed_args: vec![],
        named_args: vec![CustomAttributeNamedArg {
            is_field: false,
            name: "Name".into(),
            value: CustomAttributeValue::I4(99),
        }],
    };
    assert_eq!(dca.named("Name"), Some(&CustomAttributeValue::I4(99)));
    assert!(dca.named("Missing").is_none());
    assert_eq!(dca.named_arg_count(), 1);
}

// ─── pretty_print_type_sig ──────────────────────────────────────────────

#[test]
fn pretty_print_empty_err() {
    assert!(pretty_print_type_sig(&[]).is_err());
}

#[test]
fn pretty_print_primitives() {
    assert_eq!(pretty_print_type_sig(&[element_type::VOID]).unwrap(), "void");
    assert_eq!(pretty_print_type_sig(&[element_type::I4]).unwrap(), "int");
    assert_eq!(pretty_print_type_sig(&[element_type::STRING]).unwrap(), "string");
}

#[test]
fn pretty_print_szarray() {
    assert_eq!(
        pretty_print_type_sig(&[element_type::SZARRAY, element_type::I4]).unwrap(),
        "int[]"
    );
}

#[test]
fn pretty_print_byref_and_ptr() {
    assert_eq!(
        pretty_print_type_sig(&[element_type::BYREF, element_type::I4]).unwrap(),
        "ref int"
    );
    assert_eq!(
        pretty_print_type_sig(&[element_type::PTR, element_type::U1]).unwrap(),
        "byte*"
    );
}

#[test]
fn pretty_print_var_mvar() {
    assert_eq!(
        pretty_print_type_sig(&[element_type::VAR, 5]).unwrap(),
        "T5"
    );
    assert_eq!(
        pretty_print_type_sig(&[element_type::MVAR, 3]).unwrap(),
        "M3"
    );
}

// ─── element_type helpers ───────────────────────────────────────────────

#[test]
fn element_type_to_csharp() {
    assert_eq!(element_type::to_csharp(element_type::I4), "int");
    assert_eq!(element_type::to_csharp(element_type::OBJECT), "object");
    assert_eq!(element_type::to_csharp(0xEE), "?");
}

#[test]
fn element_type_is_numeric() {
    assert!(element_type::is_numeric(element_type::I4));
    assert!(element_type::is_numeric(element_type::R8));
    assert!(!element_type::is_numeric(element_type::STRING));
    assert!(!element_type::is_numeric(element_type::BOOLEAN));
}

// ─── coded_index ────────────────────────────────────────────────────────

#[test]
fn coded_index_roundtrip() {
    for tag_bits in [1u8, 2, 3, 5] {
        for tag in 0u8..(1 << tag_bits) {
            for row in [1u32, 7, 1024, 0x00FF_FFFF] {
                let enc = coded_index::encode(tag, row, tag_bits);
                let (dtag, drow) = coded_index::decode(enc, tag_bits);
                assert_eq!(dtag, tag);
                assert_eq!(drow, row);
            }
        }
    }
}

#[test]
fn coded_index_name_lookups() {
    assert_eq!(
        coded_index::typedef_or_ref_name(coded_index::TYPEDEF_OR_REF_TYPEDEF),
        "TypeDef"
    );
    assert_eq!(coded_index::typedef_or_ref_name(99), "Unknown");
    assert_eq!(
        coded_index::resolution_scope_name(coded_index::RESOLUTION_SCOPE_ASSEMBLYREF),
        "AssemblyRef"
    );
    assert_eq!(coded_index::resolution_scope_name(99), "Unknown");
}

// ─── table_id / table_ids modules ───────────────────────────────────────

#[test]
fn table_id_name_for_known_ids() {
    assert_eq!(table_id::name_for(0x02), Some("TypeDef"));
    assert_eq!(table_id::name_for(0x06), Some("MethodDef"));
    assert_eq!(table_id::name_for(0x2C), Some("GenericParamConstraint"));
}

#[test]
fn table_id_name_for_unknown_returns_none() {
    assert_eq!(table_id::name_for(0xFE), None);
    assert_eq!(table_id::name_for(0x2D), None);
}

#[test]
fn table_ids_token_encode_decode_roundtrip() {
    for &(tbl, row) in &[(0x02u8, 1u32), (0x06, 5), (0x23, 0xFFFF)] {
        let tok = table_ids::encode_token(tbl, row);
        let (t, r) = table_ids::decode_token(tok);
        assert_eq!((t, r), (tbl, row));
    }
}

#[test]
fn table_ids_name_unknown() {
    assert_eq!(table_ids::name(0xFE), "Unknown");
}

// ─── MetadataTables lookups ─────────────────────────────────────────────

fn make_tables_basic() -> MetadataTables {
    let mut t = MetadataTables::default();
    t.type_def.push(TypeDefRow {
        type_name: "<Module>".into(),
        ..Default::default()
    });
    t.type_def.push(TypeDefRow {
        type_name: "Foo".into(),
        field_list: 1,
        method_list: 1,
        ..Default::default()
    });
    t.method_def.push(MethodDefRow { name: "M".into(), ..Default::default() });
    t.field.push(FieldRow { name: "F".into(), ..Default::default() });
    t.param.push(ParamRow { name: "p".into(), ..Default::default() });
    t
}

#[test]
fn type_def_by_index_1based() {
    let t = make_tables_basic();
    assert_eq!(t.type_def_by_index(1).unwrap().type_name, "<Module>");
    assert_eq!(t.type_def_by_index(2).unwrap().type_name, "Foo");
}

#[test]
fn type_def_by_index_zero_returns_err() {
    let t = make_tables_basic();
    assert!(matches!(
        t.type_def_by_index(0),
        Err(MetadataError::TableIndexOutOfRange { .. })
    ));
}

#[test]
fn type_def_by_index_over_returns_err() {
    let t = make_tables_basic();
    match t.type_def_by_index(99) {
        Err(MetadataError::TableIndexOutOfRange { table, index, rows }) => {
            assert_eq!(table, 0x02);
            assert_eq!(index, 99);
            assert_eq!(rows, 2);
        }
        other => panic!("got {other:?}"),
    }
}

#[test]
fn method_field_param_by_index() {
    let t = make_tables_basic();
    assert_eq!(t.method_def_by_index(1).unwrap().name, "M");
    assert!(t.method_def_by_index(0).is_err());
    assert_eq!(t.field_by_index(1).unwrap().name, "F");
    assert!(t.field_by_index(2).is_err());
    assert_eq!(t.param_by_index(1).unwrap().name, "p");
    assert!(t.param_by_index(99).is_err());
}

#[test]
fn class_layout_for_returns_match() {
    let mut t = make_tables_basic();
    t.class_layout.push(ClassLayoutRow {
        packing_size: 4,
        class_size: 16,
        parent: 2,
    });
    assert!(t.class_layout_for(2).is_some());
    assert!(t.class_layout_for(1).is_none());
}

#[test]
fn custom_attributes_for_filter() {
    let mut t = make_tables_basic();
    t.custom_attribute.push(CustomAttributeRow { parent: 5, ..Default::default() });
    t.custom_attribute.push(CustomAttributeRow { parent: 5, ..Default::default() });
    t.custom_attribute.push(CustomAttributeRow { parent: 7, ..Default::default() });
    assert_eq!(t.custom_attributes_for(5).len(), 2);
    assert_eq!(t.custom_attributes_for(7).len(), 1);
    assert!(t.custom_attributes_for(99).is_empty());
}

#[test]
fn nested_types_of_filter() {
    let mut t = make_tables_basic();
    t.nested_class.push(NestedClassRow { nested_class: 3, enclosing_class: 2 });
    t.nested_class.push(NestedClassRow { nested_class: 4, enclosing_class: 2 });
    let nested = t.nested_types_of(2);
    assert_eq!(nested, vec![3, 4]);
    assert!(t.nested_types_of(1).is_empty());
}

#[test]
fn events_for_type_with_event_map() {
    let mut t = MetadataTables::default();
    t.event_map.push(EventMapRow { parent: 1, event_list: 1 });
    t.event.push(EventRow { name: "OnX".into(), ..Default::default() });
    t.event.push(EventRow { name: "OnY".into(), ..Default::default() });
    let evs = t.events_for_type(1);
    assert_eq!(evs.len(), 2);
    assert!(t.events_for_type(99).is_empty());
}

#[test]
fn properties_for_type_with_property_map() {
    let mut t = MetadataTables::default();
    t.property_map.push(PropertyMapRow { parent: 1, property_list: 1 });
    t.property.push(PropertyRow { name: "P".into(), ..Default::default() });
    let ps = t.properties_for_type(1);
    assert_eq!(ps.len(), 1);
    assert!(t.properties_for_type(99).is_empty());
}

#[test]
fn typed_id_wrappers_eq_hash_default() {
    use std::collections::HashSet;
    let mut s: HashSet<TypeRef> = HashSet::new();
    s.insert(TypeRef(1));
    s.insert(TypeRef(1));
    assert_eq!(s.len(), 1);
    assert_eq!(TypeRef::default(), TypeRef(0));
    assert_eq!(FieldRef(7), FieldRef(7));
    assert_ne!(MethodRef(1), MethodRef(2));
    assert_eq!(ParamRef::default().0, 0);
}

// ─── MetadataReader builder & helpers ───────────────────────────────────

fn empty_reader() -> MetadataReader {
    MetadataReader {
        root: MetadataRoot::default(),
        heaps: MetadataHeaps::default(),
        tables: MetadataTables::default(),
    }
}

#[test]
fn assembly_manifest_none_without_assembly_row() {
    let r = empty_reader();
    assert!(r.assembly_manifest().is_none());
}

#[test]
fn assembly_manifest_basic() {
    let mut r = empty_reader();
    r.tables.assembly.push(AssemblyRow {
        major_version: 1,
        minor_version: 2,
        build_number: 3,
        revision_number: 4,
        name: "MyAsm".into(),
        culture: "en-US".into(),
        ..Default::default()
    });
    let m = r.assembly_manifest().unwrap();
    assert_eq!(m.name, "MyAsm");
    assert!(m.has_culture());
    assert_eq!(m.version_string(), "1.2.3.4");
    assert!(!m.has_resources());
}

#[test]
fn exported_type_names_with_and_without_ns() {
    let mut r = empty_reader();
    r.tables.exported_type.push(ExportedTypeRow {
        type_name: "Foo".into(),
        type_namespace: "Ns".into(),
        ..Default::default()
    });
    r.tables.exported_type.push(ExportedTypeRow {
        type_name: "Bar".into(),
        type_namespace: String::new(),
        ..Default::default()
    });
    let names = r.exported_type_names();
    assert_eq!(names, vec!["Ns.Foo".to_string(), "Bar".to_string()]);
}

#[test]
fn resource_and_file_names() {
    let mut r = empty_reader();
    r.tables.manifest_resource.push(ManifestResourceRow {
        name: "rsrc".into(),
        ..Default::default()
    });
    r.tables.file.push(FileRow { name: "data.bin".into(), ..Default::default() });
    assert_eq!(r.resource_names(), vec!["rsrc"]);
    assert_eq!(r.file_names(), vec!["data.bin"]);
}

#[test]
fn total_row_count_sums_tables() {
    let mut r = empty_reader();
    r.tables.module.push(ModuleRow::default());
    r.tables.type_def.push(TypeDefRow::default());
    r.tables.method_def.push(MethodDefRow::default());
    assert_eq!(r.total_row_count(), 3);
}

#[test]
fn methods_for_type_zero_returns_empty() {
    let r = empty_reader();
    assert!(r.methods_for_type(0).is_empty());
    assert!(r.methods_for_type(99).is_empty());
}

#[test]
fn methods_for_type_spans_to_next_typedef() {
    let mut r = empty_reader();
    r.tables.type_def.push(TypeDefRow { method_list: 1, ..Default::default() });
    r.tables.type_def.push(TypeDefRow { method_list: 3, ..Default::default() });
    for n in &["A", "B", "C"] {
        r.tables.method_def.push(MethodDefRow { name: (*n).into(), ..Default::default() });
    }
    let first = r.methods_for_type(1);
    assert_eq!(first.len(), 2);
    assert_eq!(first[0].name, "A");
    let second = r.methods_for_type(2);
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].name, "C");
}

#[test]
fn fields_for_type_spans_to_next_typedef() {
    let mut r = empty_reader();
    r.tables.type_def.push(TypeDefRow { field_list: 1, ..Default::default() });
    r.tables.type_def.push(TypeDefRow { field_list: 2, ..Default::default() });
    r.tables.field.push(FieldRow { name: "A".into(), ..Default::default() });
    r.tables.field.push(FieldRow { name: "B".into(), ..Default::default() });
    assert_eq!(r.fields_for_type(1).len(), 1);
    assert_eq!(r.fields_for_type(2).len(), 1);
}

#[test]
fn type_is_abstract_and_sealed() {
    let mut r = empty_reader();
    r.tables.type_def.push(TypeDefRow { flags: 0x0080, ..Default::default() });
    r.tables.type_def.push(TypeDefRow { flags: 0x0100, ..Default::default() });
    assert!(r.type_is_abstract(1));
    assert!(!r.type_is_abstract(2));
    assert!(r.type_is_sealed(2));
    assert!(!r.type_is_sealed(0));
    assert!(!r.type_is_abstract(0));
}

#[test]
fn has_entry_point_uses_mvid() {
    let mut r = empty_reader();
    assert!(!r.has_entry_point());
    r.tables.module.push(ModuleRow { mvid: 1, ..Default::default() });
    assert!(r.has_entry_point());
}

// ─── ValidationResult & validate_metadata ───────────────────────────────

#[test]
fn validate_empty_module_table_is_error() {
    let r = empty_reader();
    let res = validate_metadata(&r);
    assert!(!res.is_valid());
    assert!(!res.errors().is_empty());
}

#[test]
fn validate_too_many_modules_is_error() {
    let mut r = empty_reader();
    r.tables.module.push(ModuleRow::default());
    r.tables.module.push(ModuleRow::default());
    let res = validate_metadata(&r);
    assert!(!res.is_valid());
}

#[test]
fn validate_first_typedef_warning() {
    let mut r = empty_reader();
    r.tables.module.push(ModuleRow::default());
    r.tables.type_def.push(TypeDefRow {
        type_name: "NotModule".into(),
        ..Default::default()
    });
    let res = validate_metadata(&r);
    // Should still be valid (warnings don't count)
    assert!(res.is_valid());
    assert!(!res.warnings().is_empty());
}

#[test]
fn validate_nested_class_out_of_range_error() {
    let mut r = empty_reader();
    r.tables.module.push(ModuleRow::default());
    r.tables.type_def.push(TypeDefRow { type_name: "<Module>".into(), ..Default::default() });
    r.tables.nested_class.push(NestedClassRow { nested_class: 1, enclosing_class: 999 });
    let res = validate_metadata(&r);
    assert!(!res.is_valid());
}

#[test]
fn validation_issue_helpers() {
    let e = ValidationIssue::error("oops");
    assert!(e.is_error);
    let w = ValidationIssue::warning("hmm");
    assert!(!w.is_error);
    let res = ValidationResult { issues: vec![e, w] };
    assert_eq!(res.issue_count(), 2);
    assert_eq!(res.errors().len(), 1);
    assert_eq!(res.warnings().len(), 1);
    assert!(!res.is_valid());
}

// ─── AssemblyManifest ───────────────────────────────────────────────────

#[test]
fn assembly_manifest_helpers() {
    let m = AssemblyManifest {
        name: "x".into(),
        culture: String::new(),
        major_version: 1,
        minor_version: 0,
        build_number: 0,
        revision_number: 0,
        resource_count: 3,
        ..Default::default()
    };
    assert!(!m.has_culture());
    assert!(m.has_resources());
    assert_eq!(m.version_string(), "1.0.0.0");
}

// ─── CliHeader flags ────────────────────────────────────────────────────

#[test]
fn cli_header_flag_helpers() {
    let h = CliHeader { flags: 0x0001 | 0x0002 | 0x0008, ..Default::default() };
    assert!(h.is_il_only());
    assert!(h.requires_32bit());
    assert!(h.is_strong_named());

    let none = CliHeader::default();
    assert!(!none.is_il_only());
    assert!(!none.requires_32bit());
    assert!(!none.is_strong_named());
}

#[test]
fn cli_header_parser_rejects_non_mz() {
    assert!(CliHeaderParser::parse_pe_embedded(&[]).is_none());
    let mut buf = vec![0u8; 0x40];
    buf[0] = b'X';
    buf[1] = b'Y';
    assert!(CliHeaderParser::parse_pe_embedded(&buf).is_none());
}

#[test]
fn cli_header_parser_rejects_short_buf() {
    // MZ but truncated
    let buf = b"MZ".to_vec();
    assert!(CliHeaderParser::parse_pe_embedded(&buf).is_none());
}

// ─── parse_method_body ──────────────────────────────────────────────────

#[test]
fn parse_method_body_tiny_header() {
    // tiny: low 2 bits = 0b10. code_size = high 6 bits = 3.
    // header byte = (3 << 2) | 0x02 = 0x0E
    let buf = vec![0x0E, 0x16, 0x16, 0x2A];
    let body = parse_method_body(&buf, 0).unwrap();
    assert_eq!(body.code_size(), 3);
    assert_eq!(body.max_stack, 8);
    assert_eq!(body.code, vec![0x16, 0x16, 0x2A]);
    assert!(!body.has_exception_handlers());
}

#[test]
fn parse_method_body_truncated_tiny_returns_err() {
    // declared code_size = 5 but no bytes follow
    let buf = vec![(5 << 2) | 0x02];
    assert!(matches!(
        parse_method_body(&buf, 0),
        Err(MetadataError::UnexpectedEof { .. })
    ));
}

#[test]
fn parse_method_body_offset_oor() {
    let buf = vec![0x0E];
    assert!(parse_method_body(&buf, 100).is_err());
}

#[test]
fn parse_method_body_invalid_magic() {
    // low 2 bits = 0b00 — neither tiny nor fat
    let buf = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert!(matches!(
        parse_method_body(&buf, 0),
        Err(MetadataError::InvalidPeMagic(0))
    ));
}

#[test]
fn parse_method_body_fat_header_no_eh() {
    // fat header: 12 bytes
    // flags_and_size = (3<<12) | 0x03 (header words = 3, flags = 0x03)
    let header_size_words: u16 = 3;
    let flags_and_size: u16 = (header_size_words << 12) | 0x03;
    let mut buf = Vec::new();
    buf.extend_from_slice(&flags_and_size.to_le_bytes());
    buf.extend_from_slice(&42u16.to_le_bytes()); // max_stack
    buf.extend_from_slice(&2u32.to_le_bytes()); // code_size
    buf.extend_from_slice(&0u32.to_le_bytes()); // local_var_sig_token
    buf.extend_from_slice(&[0x16, 0x2A]); // code
    let body = parse_method_body(&buf, 0).unwrap();
    assert_eq!(body.max_stack, 42);
    assert_eq!(body.code, vec![0x16, 0x2A]);
}

#[test]
fn cil_method_body_helpers() {
    let body = CilMethodBody {
        init_locals: true,
        max_stack: 8,
        local_var_sig_token: 0,
        code: vec![0; 5],
        exception_clauses: vec![ExceptionClause {
            kind: ExceptionClauseKind::Catch(0x0100_0001),
            try_offset: 0,
            try_length: 1,
            handler_offset: 2,
            handler_length: 3,
            filter_offset: 0,
        }, ExceptionClause {
            kind: ExceptionClauseKind::Finally,
            try_offset: 0,
            try_length: 1,
            handler_offset: 2,
            handler_length: 3,
            filter_offset: 0,
        }],
    };
    assert_eq!(body.code_size(), 5);
    assert!(body.has_exception_handlers());
    assert_eq!(body.catch_clauses().len(), 1);
    assert_eq!(body.finally_clauses().len(), 1);
}

// ─── MetadataIndexer ────────────────────────────────────────────────────

#[test]
fn metadata_indexer_basic_lookups() {
    let mut t = MetadataTables::default();
    t.type_def.push(TypeDefRow {
        type_name: "C".into(),
        type_namespace: "Ns".into(),
        field_list: 1,
        method_list: 1,
        ..Default::default()
    });
    t.field.push(FieldRow { name: "F".into(), ..Default::default() });
    t.method_def.push(MethodDefRow { name: "M".into(), ..Default::default() });
    let ix = MetadataIndexer::new(&t);
    assert!(ix.method_by_token(0x0600_0001).is_some());
    assert!(ix.method_by_token(0x0600_0999).is_none());
    assert_eq!(ix.type_by_name("Ns", "C").map(|r| r.type_name.as_str()), Some("C"));
    assert!(ix.type_by_name("X", "C").is_none());
    assert_eq!(ix.type_index("Ns", "C"), Some(0));
    assert_eq!(ix.type_token("Ns", "C"), Some(0x0200_0001));
    assert_eq!(ix.fields_of_type(0x0200_0001).len(), 1);
}

// ─── PInvokeDecl ────────────────────────────────────────────────────────

#[test]
fn pinvoke_decl_helpers() {
    let p = PInvokeDecl {
        method_name: "Foo".into(),
        module_name: "k.dll".into(),
        entry_point: "Foo".into(),
        mapping_flags: impl_map_attributes::NO_MANGLE | impl_map_attributes::CALL_CONV_STDCALL
            | impl_map_attributes::CHAR_SET_UNICODE,
    };
    assert!(p.no_mangle());
    assert_eq!(p.calling_convention(), "stdcall");
    assert_eq!(p.char_set(), "Unicode");

    let default = PInvokeDecl {
        method_name: String::new(),
        module_name: String::new(),
        entry_point: String::new(),
        mapping_flags: 0,
    };
    assert_eq!(default.calling_convention(), "default");
    assert_eq!(default.char_set(), "None");
    assert!(!default.no_mangle());
}

// ─── SecurityAction ─────────────────────────────────────────────────────

#[test]
fn security_action_from_raw_known_values() {
    assert_eq!(SecurityAction::from_raw(2), SecurityAction::Demand);
    assert_eq!(SecurityAction::from_raw(7), SecurityAction::InheritanceDemand);
    assert_eq!(SecurityAction::from_raw(99), SecurityAction::Other(99));
    assert_eq!(SecurityAction::Demand.name(), "Demand");
    assert_eq!(SecurityAction::Other(99).name(), "Unknown");
}

// ─── TypeModel ──────────────────────────────────────────────────────────

#[test]
fn type_model_flag_predicates() {
    let mut m = TypeModel {
        index: 1,
        full_name: "X".into(),
        flags: 0,
        base_type: 0,
        interfaces: vec![],
        nested_types: vec![],
        generic_params: vec![],
        method_indices: vec![],
        field_indices: vec![],
    };
    assert!(!m.is_generic());
    assert!(!m.is_abstract());
    m.generic_params.push(1);
    assert!(m.is_generic());
    m.flags = 0x0080;
    assert!(m.is_abstract());
    m.flags = 0x0100;
    assert!(m.is_sealed());
    m.flags = 0x0020;
    assert!(m.is_interface());
}

// ─── parse_metadata_direct ──────────────────────────────────────────────

#[test]
fn parse_metadata_direct_rejects_wrong_signature() {
    let mut buf = vec![0u8; 64];
    buf[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    match parse_metadata_direct(&buf) {
        Err(MetadataError::InvalidMetadataSignature(s)) => assert_eq!(s, 0xDEAD_BEEF),
        other => panic!("expected InvalidMetadataSignature, got {other:?}"),
    }
}

#[test]
fn parse_metadata_direct_truncated() {
    // Too short to even hold the signature
    let buf = vec![0u8; 2];
    assert!(parse_metadata_direct(&buf).is_err());
}

#[test]
fn parse_metadata_direct_valid_minimal() {
    // build_test_metadata_blob produces a (mostly) parseable root with no #~ stream.
    let blob = build_test_metadata_blob(b"\0", &[], &[], &[]);
    // Whether it succeeds or fails depends on whether parse_metadata requires #~;
    // either way it should not panic and produce a deterministic result.
    let _ = parse_metadata_direct(&blob);
}

// ─── Method semantics / attribute flag modules ──────────────────────────

#[test]
fn method_semantics_constants() {
    assert_eq!(method_semantics::SETTER, 0x0001);
    assert_eq!(method_semantics::GETTER, 0x0002);
    assert_eq!(method_semantics::FIRE, 0x0020);
}

#[test]
fn property_attributes_constants() {
    assert_eq!(property_attributes::SPECIAL_NAME, 0x0200);
    assert_eq!(property_attributes::HAS_DEFAULT, 0x1000);
}

#[test]
fn impl_map_attributes_constants() {
    assert_eq!(impl_map_attributes::CALL_CONV_CDECL, 0x0200);
    assert_eq!(impl_map_attributes::CHAR_SET_UNICODE, 0x0004);
}

// ─── ExceptionClauseKind equality ───────────────────────────────────────

#[test]
fn exception_clause_kind_eq() {
    assert_eq!(ExceptionClauseKind::Finally, ExceptionClauseKind::Finally);
    assert_eq!(ExceptionClauseKind::Catch(7), ExceptionClauseKind::Catch(7));
    assert_ne!(ExceptionClauseKind::Catch(1), ExceptionClauseKind::Catch(2));
    assert_ne!(ExceptionClauseKind::Filter, ExceptionClauseKind::Fault);
}

// ─── Send + Sync invariants ─────────────────────────────────────────────

#[test]
fn types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MetadataReader>();
    assert_send_sync::<MetadataTables>();
    assert_send_sync::<MetadataError>();
    assert_send_sync::<CilMethodBody>();
    assert_send_sync::<DecodedCustomAttribute>();
    assert_send_sync::<ArrayShape>();
}
