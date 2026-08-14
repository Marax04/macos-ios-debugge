//! Blitz2 — adversarial round-trip / fuzz / boundary tests.
//!
//! Complements blitz.rs. Uses a deterministic LCG (no rand / no time).

use rustre_dotnet_metadata::*;
use std::collections::{HashMap, HashSet};

// ─── Deterministic LCG ─────────────────────────────────────────────────
fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// Truncating helpers — intentional narrowing of random bits in fuzz inputs.
#[inline] const fn lo_u8(v: u64) -> u8 { v.to_le_bytes()[0] }
#[inline] const fn lo_u32(v: u64) -> u32 {
    let b = v.to_le_bytes();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
#[inline] const fn lo_i32(v: u64) -> i32 {
    let b = v.to_le_bytes();
    i32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
#[inline] const fn lo_usize(v: u64) -> usize { lo_u32(v) as usize }

// ─── 1. coded_index round-trip fuzz ────────────────────────────────────

#[test]
fn coded_index_encode_decode_fuzz_50_inputs() {
    let mut g = lcg();
    for _ in 0..50 {
        let tag_bits = ((g() % 5) as u8) + 1; // 1..=5
        let tag = (lo_u8(g())) & ((1 << tag_bits) - 1);
        let row = (lo_u32(g())) >> tag_bits; // ensure fits
        let enc = coded_index::encode(tag, row, tag_bits);
        let (dt, dr) = coded_index::decode(enc, tag_bits);
        assert_eq!(dt, tag, "tag mismatch tag_bits={tag_bits}");
        assert_eq!(dr, row, "row mismatch tag_bits={tag_bits}");
    }
}

// ─── 2. token encode/decode round-trip ─────────────────────────────────

#[test]
fn token_encode_decode_fuzz_60_inputs() {
    let mut g = lcg();
    for _ in 0..60 {
        let table = lo_u8(g());
        let row = (lo_u32(g())) & 0x00FF_FFFF;
        let tok = table_ids::encode_token(table, row);
        let (t, r) = table_ids::decode_token(tok);
        assert_eq!(t, table);
        assert_eq!(r, row);
    }
}

// ─── 3. Boundary: table_id::name_for ───────────────────────────────────

#[test]
fn table_id_name_for_full_sweep() {
    // Every byte must either return Some(&str) or None — never panic.
    for id in 0u8..=255 {
        let _ = table_id::name_for(id);
    }
    // Selected known values:
    assert_eq!(table_id::name_for(0x00), Some("Module"));
    assert_eq!(table_id::name_for(0x2C), Some("GenericParamConstraint"));
    assert_eq!(table_id::name_for(0x2D), None);
    assert_eq!(table_id::name_for(0xFF), None);
}

#[test]
fn table_ids_name_full_sweep() {
    for id in 0u8..=255 {
        let n = table_ids::name(id);
        // never empty
        assert!(!n.is_empty());
    }
}

// ─── 4. StringHeap fuzz ────────────────────────────────────────────────

#[test]
fn string_heap_fuzz_random_offsets_never_panic() {
    let mut g = lcg();
    let data: Vec<u8> = (0..200u32).map(|_| (g() & 0x7F) as u8).collect();
    let h = StringHeap::new(data);
    for _ in 0..60 {
        let off = (lo_u32(g())) % 400;
        let _ = h.get(off);
    }
}

#[test]
fn string_heap_boundary_offsets() {
    let h = StringHeap::new(b"hi\0there\0".to_vec());
    assert_eq!(h.get(0).unwrap(), "hi");
    assert_eq!(h.get(3).unwrap(), "there");
    // exactly at len -> out of range
    assert!(matches!(
        h.get(9),
        Err(MetadataError::StringOffsetOutOfRange(_))
    ));
    // u32::MAX out of range
    assert!(h.get(u32::MAX).is_err());
}

// ─── 5. BlobHeap fuzz ──────────────────────────────────────────────────

#[test]
fn blob_heap_fuzz_random_offsets_never_panic() {
    let mut g = lcg();
    let data: Vec<u8> = (0..256u32).map(|_| lo_u8(g())).collect();
    let h = BlobHeap::new(data);
    for _ in 0..60 {
        let off = (lo_u32(g())) % 300;
        let _ = h.get(off);
    }
}

#[test]
fn blob_heap_max_short_length() {
    // 0x7F = 127 single-byte length
    let mut data = vec![0x7F];
    data.extend(std::iter::repeat_n(0xAB, 127));
    let h = BlobHeap::new(data);
    let b = h.get(0).unwrap();
    assert_eq!(b.len(), 127);
    assert!(b.iter().all(|&x| x == 0xAB));
}

#[test]
fn blob_heap_u32_max_offset_oor() {
    let h = BlobHeap::new(vec![1, 0xFF]);
    assert!(h.get(u32::MAX).is_err());
}

// ─── 6. GuidHeap boundaries ────────────────────────────────────────────

#[test]
fn guid_heap_boundary_exact_fit() {
    let mut data = vec![0u8; 32];
    data[16] = 0xCC;
    let h = GuidHeap::new(data);
    let g1 = h.get(1).unwrap();
    assert_eq!(g1[0], 0);
    let g2 = h.get(2).unwrap();
    assert_eq!(g2[0], 0xCC);
    // exactly past end:
    assert!(h.get(3).is_err());
}

#[test]
fn guid_heap_fuzz_inputs() {
    let mut g = lcg();
    let data: Vec<u8> = (0..160u32).map(|_| lo_u8(g())).collect();
    let h = GuidHeap::new(data);
    for i in 0..30 {
        let _ = h.get(i);
    }
    // Index 0 always returns all-zeros regardless of data.
    assert_eq!(h.get(0).unwrap(), [0u8; 16]);
}

// ─── 7. UserStringHeap edge cases ──────────────────────────────────────

#[test]
fn user_string_heap_fuzz_offsets_never_panic() {
    let mut g = lcg();
    let data: Vec<u8> = (0..200u32).map(|_| lo_u8(g())).collect();
    let h = UserStringHeap::new(data);
    for _ in 0..40 {
        let off = (lo_u32(g())) % 300;
        let _ = h.get(off);
    }
}

// ─── 8. parse_method_sig_blob fuzz ─────────────────────────────────────

#[test]
fn parse_method_sig_blob_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..60 {
        let len = usize::try_from(g() % 16).unwrap();
        let blob: Vec<u8> = (0..len).map(|_| lo_u8(g())).collect();
        let _ = parse_method_sig_blob(&blob);
    }
}

#[test]
fn parse_method_sig_blob_empty_eof_specific() {
    match parse_method_sig_blob(&[]) {
        Err(MetadataError::UnexpectedEof { need: 1, have: 0, .. }) => {}
        other => panic!("got {other:?}"),
    }
}

#[test]
fn parse_method_sig_blob_vararg_calling_conv() {
    // calling_conv=0x05 (VARARG), 0 params, ret=void
    let info = parse_method_sig_blob(&[0x05, 0x00, 0x01]).unwrap();
    assert_eq!(info.calling_conv, 0x05);
    assert!(!info.is_instance);
    assert!(!info.is_generic);
}

// ─── 9. parse_field_sig_blob fuzz ──────────────────────────────────────

#[test]
fn parse_field_sig_blob_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = usize::try_from(g() % 10).unwrap();
        let blob: Vec<u8> = (0..len).map(|_| lo_u8(g())).collect();
        let _ = parse_field_sig_blob(&blob);
    }
}

// ─── 10. parse_local_var_sig fuzz ──────────────────────────────────────

#[test]
fn parse_local_var_sig_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = usize::try_from(g() % 12).unwrap();
        let mut blob: Vec<u8> = (0..len).map(|_| lo_u8(g())).collect();
        // half the time, valid magic
        if g() & 1 == 0 && !blob.is_empty() {
            blob[0] = 0x07;
        }
        let _ = parse_local_var_sig(&blob);
    }
}

#[test]
fn parse_local_var_sig_zero_count() {
    let v = parse_local_var_sig(&[0x07, 0x00]).unwrap();
    assert!(v.is_empty());
}

// ─── 11. parse_array_shape fuzz ────────────────────────────────────────

#[test]
fn parse_array_shape_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..40 {
        let len = usize::try_from(g() % 16).unwrap();
        let blob: Vec<u8> = (0..len).map(|_| lo_u8(g())).collect();
        let _ = parse_array_shape(&blob);
    }
}

#[test]
fn array_shape_bracket_notation_round_trip() {
    for rank in 1u32..=6 {
        let s = ArrayShape {
            rank,
            sizes: vec![],
            lower_bounds: vec![],
        };
        let b = s.bracket_notation();
        // commas == rank - 1 inside brackets
        let commas = b.matches(',').count();
        assert_eq!(u32::try_from(commas).unwrap(), rank - 1, "rank={rank} got {b}");
    }
}

// ─── 12. parse_custom_attribute_blob fuzz ──────────────────────────────

#[test]
fn parse_ca_blob_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = usize::try_from(g() % 20).unwrap();
        let blob: Vec<u8> = (0..len).map(|_| lo_u8(g())).collect();
        let _ = parse_custom_attribute_blob(&blob);
    }
}

#[test]
fn parse_ca_blob_typed_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..40 {
        let blen = usize::try_from(g() % 24).unwrap();
        let plen = usize::try_from(g() % 5).unwrap();
        let blob: Vec<u8> = (0..blen).map(|_| lo_u8(g())).collect();
        let params: Vec<u8> = (0..plen).map(|_| (g() & 0x1F) as u8).collect();
        let _ = parse_custom_attribute_blob_typed(&blob, &params);
    }
}

// ─── 13. parse_method_body fuzz ────────────────────────────────────────

#[test]
fn parse_method_body_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = usize::try_from(g() % 32).unwrap();
        let buf: Vec<u8> = (0..len).map(|_| lo_u8(g())).collect();
        let off = (lo_usize(g())) % (len + 1);
        let _ = parse_method_body(&buf, off);
    }
}

#[test]
fn parse_method_body_tiny_zero_code() {
    // header byte = 0 << 2 | 0x02 = 0x02 => empty code
    let body = parse_method_body(&[0x02], 0).unwrap();
    assert_eq!(body.code_size(), 0);
    assert_eq!(body.max_stack, 8);
    assert!(!body.has_exception_handlers());
}

// ─── 14. parse_metadata_direct fuzz ────────────────────────────────────

#[test]
fn parse_metadata_direct_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..40 {
        let len = usize::try_from(g() % 80).unwrap();
        let buf: Vec<u8> = (0..len).map(|_| lo_u8(g())).collect();
        let _ = parse_metadata_direct(&buf);
    }
}

// ─── 15. pretty_print_type_sig fuzz ────────────────────────────────────

#[test]
fn pretty_print_type_sig_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = usize::try_from(g() % 16).unwrap();
        let blob: Vec<u8> = (0..len).map(|_| lo_u8(g())).collect();
        let _ = pretty_print_type_sig(&blob);
    }
}

#[test]
fn pretty_print_primitives_full_set() {
    // every is_numeric should map to a non-"?" pretty name
    for et in [
        element_type::I1,
        element_type::U1,
        element_type::I2,
        element_type::U2,
        element_type::I4,
        element_type::U4,
        element_type::I8,
        element_type::U8,
        element_type::R4,
        element_type::R8,
        element_type::I,
        element_type::U,
    ] {
        let p = pretty_print_type_sig(&[et]).unwrap();
        assert_ne!(p, "?", "et={et:#x}");
    }
}

// ─── 16. element_type module sweeps ────────────────────────────────────

#[test]
fn element_type_to_csharp_full_sweep_no_panic() {
    for et in 0u8..=255 {
        let s = element_type::to_csharp(et);
        assert!(!s.is_empty());
    }
}

#[test]
fn element_type_is_numeric_consistency() {
    // STRING / OBJECT / BOOLEAN must not be numeric, primitives must.
    assert!(!element_type::is_numeric(element_type::STRING));
    assert!(!element_type::is_numeric(element_type::OBJECT));
    assert!(!element_type::is_numeric(element_type::BOOLEAN));
    assert!(!element_type::is_numeric(element_type::CHAR));
    assert!(!element_type::is_numeric(element_type::VOID));
    assert!(element_type::is_numeric(element_type::I4));
    assert!(element_type::is_numeric(element_type::R8));
}

// ─── 17. ConstantValue display variant sweep ──────────────────────────

#[test]
fn constant_value_display_never_panics_for_all_variants() {
    let vals = vec![
        ConstantValue::Bool(false),
        ConstantValue::Char('A'),
        ConstantValue::Int8(-1),
        ConstantValue::UInt8(255),
        ConstantValue::Int16(i16::MIN),
        ConstantValue::UInt16(u16::MAX),
        ConstantValue::Int32(i32::MIN),
        ConstantValue::UInt32(u32::MAX),
        ConstantValue::Int64(i64::MAX),
        ConstantValue::UInt64(u64::MAX),
        ConstantValue::Float32(1.5),
        ConstantValue::Float64(-3.25),
        ConstantValue::String("hi".into()),
        ConstantValue::Null,
    ];
    for v in vals {
        let s = format!("{v}");
        assert!(!s.is_empty(), "display empty for {v:?}");
    }
}

// ─── 18. ConstantValue Eq/Hash-style coverage ──────────────────────────

#[test]
fn constant_value_eq_30_pairs() {
    // Build 30 deterministic comparison pairs (eq + neq).
    let mut rng = lcg();
    for _ in 0..15 {
        let val = lo_i32(rng());
        let lhs = ConstantValue::Int32(val);
        let rhs = ConstantValue::Int32(val);
        assert_eq!(lhs, rhs);
        // Different variant — never equal.
        let other = ConstantValue::Int64(i64::from(val));
        assert_ne!(lhs, other);
    }
}

// ─── 19. TypeVisibility full flag sweep ────────────────────────────────

#[test]
fn type_visibility_from_flags_all_low_bits() {
    // Low 3 bits drive the variant. Sweep all 8.
    for v in 0u32..8 {
        let tv = TypeVisibility::from_flags(v);
        // Must produce a defined variant (no panic).
        let _ = format!("{tv:?}");
    }
}

// ─── 20. typed Ref structs Hash/Eq ─────────────────────────────────────

#[test]
fn typed_refs_hash_eq_30_pairs() {
    let mut g = lcg();
    let mut set: HashSet<TypeRef> = HashSet::new();
    let mut fset: HashSet<FieldRef> = HashSet::new();
    let mut mset: HashSet<MethodRef> = HashSet::new();
    for _ in 0..30 {
        let v = lo_u32(g());
        let a = TypeRef(v);
        let b = TypeRef(v);
        assert_eq!(a, b);
        set.insert(a);
        set.insert(b); // dedup
        fset.insert(FieldRef(v));
        mset.insert(MethodRef(v));
    }
    // duplicate insertion: set length should equal number of unique values.
    assert!(!set.is_empty());
    assert!(set.len() <= 30);
    assert_eq!(set.len(), fset.len());
    assert_eq!(set.len(), mset.len());
}

// ─── 21. MetadataTables index boundary ─────────────────────────────────

#[test]
fn metadata_tables_zero_index_always_error() {
    let t = MetadataTables::default();
    assert!(t.type_def_by_index(0).is_err());
    assert!(t.method_def_by_index(0).is_err());
    assert!(t.field_by_index(0).is_err());
    assert!(t.param_by_index(0).is_err());
}

#[test]
fn metadata_tables_one_past_end_error() {
    let mut t = MetadataTables::default();
    t.type_def.push(TypeDefRow::default());
    assert!(t.type_def_by_index(1).is_ok());
    assert!(t.type_def_by_index(2).is_err());
}

#[test]
fn metadata_tables_u32_max_index_error() {
    let t = MetadataTables::default();
    match t.type_def_by_index(u32::MAX) {
        Err(MetadataError::TableIndexOutOfRange { index, .. }) => {
            assert_eq!(index, u32::MAX);
        }
        other => panic!("got {other:?}"),
    }
}

// ─── 22. MetadataReader helpers — boundary methods/fields ──────────────

fn empty_reader() -> MetadataReader {
    MetadataReader {
        root: MetadataRoot::default(),
        heaps: MetadataHeaps::default(),
        tables: MetadataTables::default(),
    }
}

#[test]
fn reader_no_types_methods_for_type_safe() {
    let r = empty_reader();
    assert!(r.methods_for_type(0).is_empty());
    assert!(r.methods_for_type(1).is_empty());
    assert!(r.methods_for_type(u32::MAX).is_empty());
}

#[test]
fn reader_total_row_count_zero_when_empty() {
    let r = empty_reader();
    assert_eq!(r.total_row_count(), 0);
}

// ─── 23. ValidationResult helpers ─────────────────────────────────────

#[test]
fn validation_result_empty_is_valid() {
    let r = ValidationResult { issues: vec![] };
    assert!(r.is_valid());
    assert_eq!(r.issue_count(), 0);
    assert!(r.errors().is_empty());
    assert!(r.warnings().is_empty());
}

#[test]
fn validation_result_only_warnings_valid() {
    let r = ValidationResult {
        issues: vec![ValidationIssue::warning("w1"), ValidationIssue::warning("w2")],
    };
    assert!(r.is_valid());
    assert_eq!(r.warnings().len(), 2);
    assert!(r.errors().is_empty());
}

// ─── 24. PInvokeDecl calling-convention sweep ──────────────────────────

#[test]
fn pinvoke_decl_calling_convention_all_variants() {
    let variants = [
        (impl_map_attributes::CALL_CONV_CDECL, "cdecl"),
        (impl_map_attributes::CALL_CONV_STDCALL, "stdcall"),
        (impl_map_attributes::CALL_CONV_THISCALL, "thiscall"),
        (impl_map_attributes::CALL_CONV_FASTCALL, "fastcall"),
    ];
    for (mask, name) in variants {
        let p = PInvokeDecl {
            method_name: "m".into(),
            module_name: "x".into(),
            entry_point: "m".into(),
            mapping_flags: mask,
        };
        assert_eq!(p.calling_convention(), name, "mask={mask:#x}");
    }
}

#[test]
fn pinvoke_decl_char_set_variants() {
    for (mask, name) in [
        (impl_map_attributes::CHAR_SET_ANSI, "Ansi"),
        (impl_map_attributes::CHAR_SET_UNICODE, "Unicode"),
        (impl_map_attributes::CHAR_SET_AUTO, "Auto"),
    ] {
        let p = PInvokeDecl {
            method_name: String::new(),
            module_name: String::new(),
            entry_point: String::new(),
            mapping_flags: mask,
        };
        assert_eq!(p.char_set(), name, "mask={mask:#x}");
    }
}

// ─── 25. SecurityAction round-trip ─────────────────────────────────────

#[test]
fn security_action_from_raw_sweep_30_values() {
    for v in 0u16..30 {
        let a = SecurityAction::from_raw(v);
        let n = a.name();
        // All names must be non-empty.
        assert!(!n.is_empty(), "v={v}");
    }
}

// ─── 26. coded_index name lookups full sweep ───────────────────────────

#[test]
fn coded_index_name_lookups_all_bytes() {
    for b in 0u8..=255 {
        let n1 = coded_index::typedef_or_ref_name(b);
        let n2 = coded_index::resolution_scope_name(b);
        assert!(!n1.is_empty());
        assert!(!n2.is_empty());
    }
}

// ─── 27. CliHeader flag combinations ───────────────────────────────────

#[test]
fn cli_header_all_flag_combinations() {
    for f in 0u32..16 {
        let h = CliHeader {
            flags: f,
            ..Default::default()
        };
        assert_eq!(h.is_il_only(), (f & 0x0001) != 0);
        assert_eq!(h.requires_32bit(), (f & 0x0002) != 0);
        assert_eq!(h.is_strong_named(), (f & 0x0008) != 0);
    }
}

// ─── 28. CliHeaderParser robustness ────────────────────────────────────

#[test]
fn cli_header_parser_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..30 {
        let len = usize::try_from(g() % 256).unwrap();
        let buf: Vec<u8> = (0..len).map(|_| lo_u8(g())).collect();
        let _ = CliHeaderParser::parse_pe_embedded(&buf);
    }
}

// ─── 29. MetadataIndexer with many rows ────────────────────────────────

#[test]
fn metadata_indexer_50_types_lookup() {
    let mut t = MetadataTables::default();
    for i in 0..50 {
        t.type_def.push(TypeDefRow {
            type_name: format!("T{i}"),
            type_namespace: "Ns".into(),
            field_list: 1,
            method_list: 1,
            ..Default::default()
        });
    }
    t.method_def.push(MethodDefRow {
        name: "m".into(),
        ..Default::default()
    });
    let ix = MetadataIndexer::new(&t);
    for i in 0..50 {
        let name = format!("T{i}");
        let tok = ix.type_token("Ns", &name);
        assert!(tok.is_some(), "missing {name}");
    }
    assert!(ix.type_token("Ns", "Missing").is_none());
}

// ─── 30. build_test_metadata_blob → parse_metadata_direct round-trip ──

#[test]
fn build_blob_then_parse_does_not_panic() {
    let mut g = lcg();
    for _ in 0..10 {
        let n_strings = usize::try_from(g() % 4).unwrap();
        let strings: Vec<u8> = std::iter::once(0u8)
            .chain((0..n_strings).flat_map(|i| {
                let s = format!("s{i}");
                s.into_bytes().into_iter().chain(std::iter::once(0u8))
            }))
            .collect();
        let blob = build_test_metadata_blob(&strings, &[], &[], &[]);
        let _ = parse_metadata_direct(&blob);
    }
}

// ─── 31. MethodSigInfo invariants ──────────────────────────────────────

#[test]
fn method_sig_info_param_count_matches() {
    // 3 params, return void, all int
    let blob = [0x00, 0x03, 0x01, 0x08, 0x08, 0x08];
    let info = parse_method_sig_blob(&blob).unwrap();
    assert_eq!(info.params.len(), 3);
    assert!(info.params.iter().all(|p| p == "int"));
    assert_eq!(info.return_type, "void");
}

// ─── 32. CustomAttributeValue helpers ──────────────────────────────────

#[test]
fn custom_attribute_value_helpers_sweep() {
    // as_i32 is documented to extract only from the I4 variant.
    assert_eq!(CustomAttributeValue::I4(-1).as_i32(), Some(-1));
    assert_eq!(CustomAttributeValue::I4(i32::MAX).as_i32(), Some(i32::MAX));
    // Other numeric variants yield None.
    assert_eq!(CustomAttributeValue::I1(-1).as_i32(), None);
    assert_eq!(CustomAttributeValue::U4(9).as_i32(), None);
    assert_eq!(CustomAttributeValue::String(None).as_str(), None);
    assert_eq!(
        CustomAttributeValue::String(Some("ok".into())).as_str(),
        Some("ok")
    );
    assert_eq!(CustomAttributeValue::Bool(true).as_bool(), Some(true));
    assert_eq!(CustomAttributeValue::Bool(false).as_bool(), Some(false));
    assert_eq!(CustomAttributeValue::I4(1).as_bool(), None);
}

// ─── 33. Send+Sync threaded stress ─────────────────────────────────────

#[test]
fn metadata_tables_threaded_stress_4x100() {
    use std::sync::Arc;
    use std::thread;
    let mut t = MetadataTables::default();
    for i in 0..32 {
        t.type_def.push(TypeDefRow {
            type_name: format!("T{i}"),
            ..Default::default()
        });
    }
    let t = Arc::new(t);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let t2 = Arc::clone(&t);
        handles.push(thread::spawn(move || {
            let mut count = 0u32;
            for i in 1u32..=100 {
                let idx = ((i - 1) % 32) + 1;
                if t2.type_def_by_index(idx).is_ok() {
                    count += 1;
                }
            }
            count
        }));
    }
    for h in handles {
        assert_eq!(h.join().unwrap(), 100);
    }
}

#[test]
fn metadata_reader_threaded_stress_4x100() {
    use std::sync::Arc;
    use std::thread;
    let mut r = empty_reader();
    for i in 0..10 {
        r.tables.type_def.push(TypeDefRow {
            type_name: format!("T{i}"),
            type_namespace: "Ns".into(),
            ..Default::default()
        });
    }
    let r = Arc::new(r);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let r2 = Arc::clone(&r);
        handles.push(thread::spawn(move || {
            let mut sum = 0usize;
            for _ in 0..100 {
                sum += r2.total_row_count();
            }
            sum
        }));
    }
    for h in handles {
        let v = h.join().unwrap();
        assert_eq!(v, 10 * 100);
    }
}

// ─── 34. Hash consistency between equal items ──────────────────────────

#[test]
fn typed_ref_hash_eq_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    fn h<T: Hash>(t: &T) -> u64 {
        let mut h = DefaultHasher::new();
        t.hash(&mut h);
        h.finish()
    }
    let mut g = lcg();
    for _ in 0..30 {
        let v = lo_u32(g());
        assert_eq!(h(&TypeRef(v)), h(&TypeRef(v)));
        assert_eq!(h(&FieldRef(v)), h(&FieldRef(v)));
        assert_eq!(h(&MethodRef(v)), h(&MethodRef(v)));
        assert_eq!(h(&ParamRef(v)), h(&ParamRef(v)));
    }
}

// ─── 35. ExceptionClauseKind variants ──────────────────────────────────

#[test]
fn exception_clause_kind_variant_distinctness() {
    let kinds = [
        ExceptionClauseKind::Catch(1),
        ExceptionClauseKind::Catch(2),
        ExceptionClauseKind::Filter,
        ExceptionClauseKind::Finally,
        ExceptionClauseKind::Fault,
    ];
    for (i, a) in kinds.iter().enumerate() {
        for (j, b) in kinds.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b, "{a:?} vs {b:?}");
            }
        }
    }
}

// ─── 36. ArrayShape rank-0 vs rank-1 distinct ──────────────────────────

#[test]
fn array_shape_rank0_bracket() {
    let s = ArrayShape {
        rank: 0,
        sizes: vec![],
        lower_bounds: vec![],
    };
    assert_eq!(s.bracket_notation(), "[]");
}

#[test]
fn array_shape_rank1_simple_szarray() {
    let s = ArrayShape {
        rank: 1,
        sizes: vec![],
        lower_bounds: vec![],
    };
    assert!(s.is_simple_szarray());
}

// ─── 37. AssemblyManifest version edge cases ───────────────────────────

#[test]
fn assembly_manifest_version_string_max_values() {
    let m = AssemblyManifest {
        name: "x".into(),
        culture: "neutral".into(),
        major_version: u16::MAX,
        minor_version: u16::MAX,
        build_number: u16::MAX,
        revision_number: u16::MAX,
        resource_count: 0,
        ..Default::default()
    };
    let v = m.version_string();
    assert!(v.contains("65535"));
    assert!(m.has_culture());
    assert!(!m.has_resources());
}

// ─── 38. Validation error count vs is_valid ────────────────────────────

#[test]
fn validation_mixed_errors_warnings_invalid() {
    let issues = vec![
        ValidationIssue::error("e1"),
        ValidationIssue::warning("w1"),
        ValidationIssue::error("e2"),
    ];
    let r = ValidationResult { issues };
    assert!(!r.is_valid());
    assert_eq!(r.errors().len(), 2);
    assert_eq!(r.warnings().len(), 1);
    assert_eq!(r.issue_count(), 3);
}

// ─── 39. custom_attributes_for filter consistency ──────────────────────

#[test]
fn custom_attributes_for_50_entries_filter() {
    let mut t = MetadataTables::default();
    let mut expected: HashMap<u32, usize> = HashMap::new();
    let mut g = lcg();
    for _ in 0..50 {
        let parent = (lo_u32(g())) % 5;
        t.custom_attribute.push(CustomAttributeRow {
            parent,
            ..Default::default()
        });
        *expected.entry(parent).or_default() += 1;
    }
    for (parent, count) in expected {
        assert_eq!(t.custom_attributes_for(parent).len(), count);
    }
}

// ─── 40. MetadataError Display formatting ──────────────────────────────

#[test]
fn metadata_error_display_variants_nonempty() {
    let errors = vec![
        MetadataError::UnexpectedEof {
            offset: 0,
            need: 1,
            have: 0,
        },
        MetadataError::InvalidPeMagic(0),
        MetadataError::InvalidMetadataSignature(0xDEAD),
        MetadataError::StreamNotFound("x".into()),
        MetadataError::StringOffsetOutOfRange(1),
        MetadataError::GuidIndexOutOfRange(2),
        MetadataError::BlobOffsetOutOfRange(3),
        MetadataError::InvalidCompressedInt(4),
        MetadataError::UnsupportedTable(0xFF),
        MetadataError::InvalidToken(0x1234_5678),
        MetadataError::InvalidUtf8,
        MetadataError::TableIndexOutOfRange {
            table: 0x02,
            index: 9,
            rows: 0,
        },
    ];
    for e in errors {
        let s = format!("{e}");
        assert!(!s.is_empty(), "empty display for {e:?}");
    }
}

// ─── 41. method_semantics flags constants ──────────────────────────────

#[test]
fn method_semantics_event_property_flags_distinct() {
    let vals: HashSet<u16> = [
        method_semantics::SETTER,
        method_semantics::GETTER,
        method_semantics::OTHER,
        method_semantics::ADD_ON,
        method_semantics::REMOVE_ON,
        method_semantics::FIRE,
    ]
    .into_iter()
    .collect();
    // Each constant must be unique.
    assert_eq!(vals.len(), 6);
}

// ─── 42. TypeModel flags edge bits ─────────────────────────────────────

#[test]
fn type_model_flag_combinations() {
    let mut m = TypeModel {
        index: 1,
        full_name: "X".into(),
        flags: 0x0080 | 0x0100, // abstract + sealed
        base_type: 0,
        interfaces: vec![],
        nested_types: vec![],
        generic_params: vec![],
        method_indices: vec![],
        field_indices: vec![],
    };
    assert!(m.is_abstract());
    assert!(m.is_sealed());
    assert!(!m.is_interface());
    m.flags |= 0x0020;
    assert!(m.is_interface());
}
