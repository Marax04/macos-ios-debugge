//! Blitz test suite for `rustre-analysis-vtable` public API.

use std::collections::HashMap;

use rustre_analysis_vtable::*;

// ─── helpers ────────────────────────────────────────────────────────────────

fn code_section(base: u64, len: usize) -> Section {
    let mut s = Section::new(".text", base, vec![0xCC; len]);
    s.executable = true;
    s
}

fn ptr_data(base: u64, ptrs: &[u64]) -> Section {
    make_ptr_section(base, ptrs, false)
}

fn vt_with(addr: u64, ptrs: &[u64]) -> Vtable {
    let mut vt = Vtable::new(addr);
    for (i, &p) in ptrs.iter().enumerate() {
        vt.add_entry(VtableEntry::new(i * 8, p));
    }
    vt
}

// ─── Section ────────────────────────────────────────────────────────────────

#[test]
fn section_contains_lower_bound_inclusive() {
    let s = Section::new(".x", 0x100, vec![0; 16]);
    assert!(s.contains(0x100));
}

#[test]
fn section_contains_upper_bound_exclusive() {
    let s = Section::new(".x", 0x100, vec![0; 16]);
    assert!(s.contains(0x10F));
    assert!(!s.contains(0x110));
}

#[test]
fn section_end_address_correct() {
    let s = Section::new(".x", 0x100, vec![0; 32]);
    assert_eq!(s.end_address(), 0x120);
}

#[test]
fn section_end_address_saturates() {
    let s = Section::new(".x", u64::MAX - 4, vec![0; 16]);
    assert_eq!(s.end_address(), u64::MAX);
}

#[test]
fn section_read_ptr_returns_none_for_unsupported_size() {
    let s = make_ptr_section(0x1000, &[0xDEAD], false);
    assert_eq!(s.read_ptr(0x1000, 2), None);
    assert_eq!(s.read_ptr(0x1000, 16), None);
}

#[test]
fn section_read_ptr_returns_none_out_of_range() {
    let s = make_ptr_section(0x1000, &[0xDEAD], false);
    assert_eq!(s.read_ptr(0x5000, 8), None);
}

#[test]
fn section_read_ptr_partial_at_end() {
    // 8 bytes of data, trying to read 8-byte ptr at offset 4 should fail.
    let s = Section::new(".x", 0x1000, vec![0u8; 8]);
    assert_eq!(s.read_ptr(0x1004, 8), None);
}

#[test]
fn section_read_cstr_basic() {
    let s = make_str_section(0x2000, "abc");
    assert_eq!(s.read_cstr(0x2000), Some("abc".to_string()));
}

#[test]
fn section_read_cstr_no_terminator_returns_none() {
    // No NUL anywhere — read_cstr should return None.
    let s = Section::new(".x", 0x1000, b"abcd".to_vec());
    assert_eq!(s.read_cstr(0x1000), None);
}

#[test]
fn section_read_cstr_invalid_utf8_returns_none() {
    let s = Section::new(".x", 0x1000, vec![0xFF, 0xFE, 0xFD, 0x00]);
    assert_eq!(s.read_cstr(0x1000), None);
}

#[test]
fn section_read_cstr_out_of_range() {
    let s = make_str_section(0x2000, "abc");
    assert!(s.read_cstr(0x9000).is_none());
}

#[test]
fn section_read_i32_negative() {
    let mut data = Vec::new();
    data.extend_from_slice(&(-7i32).to_le_bytes());
    let s = Section::new(".x", 0x1000, data);
    assert_eq!(s.read_i32(0x1000), Some(-7));
}

#[test]
fn section_read_u32_basic() {
    let mut data = Vec::new();
    data.extend_from_slice(&0xCAFE_BABE_u32.to_le_bytes());
    let s = Section::new(".x", 0x1000, data);
    assert_eq!(s.read_u32(0x1000), Some(0xCAFE_BABE));
}

#[test]
fn section_read_u32_out_of_range() {
    let s = Section::new(".x", 0x1000, vec![0; 4]);
    assert!(s.read_u32(0x9000).is_none());
}

// ─── VtableDetector ─────────────────────────────────────────────────────────

#[test]
fn detector_rejects_ptr_size_zero() {
    let d = VtableDetector::new(0);
    let code = code_section(0x1000, 0x100);
    let data = Section::new(".d", 0x4000, vec![0; 16]);
    assert!(matches!(
        d.detect(&data, &[code]),
        Err(VtableError::UnsupportedPointerSize(0))
    ));
}

#[test]
fn detector_rejects_ptr_size_16() {
    let d = VtableDetector::new(16);
    let code = code_section(0x1000, 0x100);
    let data = Section::new(".d", 0x4000, vec![0; 16]);
    assert!(matches!(
        d.detect(&data, &[code]),
        Err(VtableError::UnsupportedPointerSize(16))
    ));
}

#[test]
fn detector_only_executable_sections_count_as_code() {
    let mut not_exec = Section::new(".text_but_data", 0x1000, vec![0; 0x100]);
    not_exec.executable = false;
    let data = ptr_data(0x4000, &[0x1010, 0x1020]);
    let d = VtableDetector::new(8);
    let vts = d.detect(&data, &[not_exec]).unwrap();
    assert!(vts.is_empty(), "non-executable section must not be treated as code");
}

#[test]
fn detector_skips_non_code_pointers() {
    let code = code_section(0x1000, 0x100);
    // Pointers point outside code: should produce nothing.
    let data = ptr_data(0x4000, &[0x9000, 0x9100, 0x9200]);
    let d = VtableDetector::new(8);
    assert!(d.detect(&data, &[code]).unwrap().is_empty());
}

#[test]
fn detector_handles_empty_data_section() {
    let code = code_section(0x1000, 0x100);
    let data = Section::new(".d", 0x4000, vec![]);
    let d = VtableDetector::new(8);
    assert!(d.detect(&data, &[code]).unwrap().is_empty());
}

#[test]
fn detector_4byte_pointers() {
    let code = code_section(0x1000, 0x1000);
    let mut data = Vec::new();
    for v in [0x1100u32, 0x1200, 0x1300] {
        data.extend_from_slice(&v.to_le_bytes());
    }
    let mut sec = Section::new(".d", 0x4000, data);
    sec.executable = false;
    let d = VtableDetector::new(4);
    let vts = d.detect(&sec, &[code]).unwrap();
    assert_eq!(vts.len(), 1);
    assert_eq!(vts[0].entry_count(), 3);
}

// ─── VtableEntry ────────────────────────────────────────────────────────────

#[test]
fn vtable_entry_with_name_sets_name() {
    let e = VtableEntry::with_name(16, 0xAA, "foo");
    assert_eq!(e.offset, 16);
    assert_eq!(e.target_address, 0xAA);
    assert_eq!(e.function_name.as_deref(), Some("foo"));
}

#[test]
fn vtable_entry_eq_and_clone() {
    let a = VtableEntry::with_name(0, 0x10, "f");
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn vtable_entry_serde_roundtrip() {
    let e = VtableEntry::with_name(8, 0xDEAD, "x");
    let s = serde_json::to_string(&e).unwrap();
    let e2: VtableEntry = serde_json::from_str(&s).unwrap();
    assert_eq!(e, e2);
}

// ─── Vtable serde ───────────────────────────────────────────────────────────

#[test]
fn vtable_serde_roundtrip() {
    let mut vt = Vtable::new(0x4000);
    vt.class_name = Some("Foo".into());
    vt.offset_to_top = Some(-16);
    vt.add_entry(VtableEntry::new(0, 0x100));
    let s = serde_json::to_string(&vt).unwrap();
    let vt2: Vtable = serde_json::from_str(&s).unwrap();
    assert_eq!(vt, vt2);
}

// ─── Itanium decoder ────────────────────────────────────────────────────────

fn make_itanium_with_base() -> Section {
    // Layout in one section starting at 0x8000, size 0x80.
    //   derived: vtable_ptr@0, name_ptr@8, base_type_ptr@16
    //   "Derived" at 0x40
    //   base: vtable_ptr@0x20, name_ptr@0x28
    //   "Base" at 0x50
    let base = 0x8000u64;
    let mut data = vec![0u8; 0x80];
    // derived.name_ptr at +8 -> 0x8040
    data[8..16].copy_from_slice(&(base + 0x40).to_le_bytes());
    // derived.base_type_ptr at +16 -> 0x8020
    data[16..24].copy_from_slice(&(base + 0x20).to_le_bytes());
    // base.name_ptr at +0x28 -> 0x8050
    data[0x28..0x30].copy_from_slice(&(base + 0x50).to_le_bytes());
    data[0x40..0x47].copy_from_slice(b"Derived");
    data[0x47] = 0;
    data[0x50..0x54].copy_from_slice(b"Base");
    data[0x54] = 0;
    Section::new(".rodata", base, data)
}

#[test]
fn itanium_decode_with_base_class() {
    let s = make_itanium_with_base();
    let info = ItaniumRttiDecoder::decode(0x8000, &s, 8, &HashMap::new()).unwrap();
    assert_eq!(info.type_name, "Derived");
    assert_eq!(info.base_classes, vec!["Base".to_string()]);
}

#[test]
fn itanium_decode_uses_known_names_fallback() {
    // Name pointer is valid but points to junk that's not utf8 or NUL terminated.
    let base = 0x9000u64;
    let mut data = vec![0u8; 0x40];
    // name_ptr -> 0x9020
    data[8..16].copy_from_slice(&(base + 0x20).to_le_bytes());
    // At 0x20 put invalid utf8 with NUL.
    data[0x20..0x24].copy_from_slice(&[0xFF, 0xFE, 0xFD, 0]);
    let s = Section::new(".rodata", base, data);
    let mut known = HashMap::new();
    known.insert(base + 0x20, "FallbackName".to_string());
    let info = ItaniumRttiDecoder::decode(base, &s, 8, &known).unwrap();
    assert_eq!(info.type_name, "FallbackName");
}

#[test]
fn itanium_decode_unresolved_name_yields_placeholder() {
    // name_ptr points outside section -> read_cstr returns None and no fallback.
    let base = 0xA000u64;
    let mut data = vec![0u8; 0x20];
    data[8..16].copy_from_slice(&0xFFFF_FFFFu64.to_le_bytes());
    let s = Section::new(".rodata", base, data);
    let info = ItaniumRttiDecoder::decode(base, &s, 8, &HashMap::new()).unwrap();
    assert!(info.type_name.contains("name@"));
}

#[test]
fn itanium_decode_out_of_range_name_ptr_field_errors() {
    // Section too small to even hold the name pointer field.
    let s = Section::new(".rodata", 0x1000, vec![0u8; 4]);
    let r = ItaniumRttiDecoder::decode(0x1000, &s, 8, &HashMap::new());
    assert!(matches!(r, Err(VtableError::AddressOutOfRange(_))));
}

// ─── MSVC demangle helpers ──────────────────────────────────────────────────

#[test]
fn msvc_demangle_plain_returns_unchanged_minus_at() {
    // No prefix, no suffix.
    assert_eq!(MsvcRttiDecoder::demangle_msvc("Plain"), "Plain");
}

#[test]
fn msvc_demangle_empty_string_safe() {
    assert_eq!(MsvcRttiDecoder::demangle_msvc(""), "");
}

#[test]
fn msvc_demangle_only_prefix() {
    assert_eq!(MsvcRttiDecoder::demangle_msvc(".?AV"), "");
}

// ─── MSVC COL decode error path ─────────────────────────────────────────────

#[test]
fn msvc_decode_col_truncated_section_errors() {
    let s = Section::new(".rdata", 0x1000, vec![0u8; 2]);
    let r = MsvcRttiDecoder::decode_col(0x1000, &s, 0x1000);
    assert!(r.is_err());
}

// ─── RttiDecoder facade ─────────────────────────────────────────────────────

#[test]
fn rtti_decoder_construct_fields() {
    let d = RttiDecoder::new(8, 0x4000_0000);
    assert_eq!(d.ptr_size, 8);
    assert_eq!(d.image_base, 0x4000_0000);
}

#[test]
fn rtti_decoder_itanium_delegates() {
    let s = make_itanium_with_base();
    let d = RttiDecoder::new(8, 0);
    let info = d.decode_itanium(0x8000, &s, &HashMap::new()).unwrap();
    assert_eq!(info.type_name, "Derived");
}

// ─── VtableDatabase ─────────────────────────────────────────────────────────

#[test]
fn database_rtti_for_vtable_returns_none_when_unlinked() {
    let db = VtableDatabase::new();
    assert!(db.rtti_for_vtable(0x4000).is_none());
}

#[test]
fn database_link_propagates_class_name_only_when_rtti_present() {
    let mut db = VtableDatabase::new();
    db.add_vtable(Vtable::new(0x4000));
    // Link to a non-existent RTTI: must not crash; class_name unchanged.
    db.link_vtable_rtti(0x4000, 0x9999);
    assert!(db.vtables.get(&0x4000).unwrap().class_name.is_none());
}

#[test]
fn database_link_then_rtti_for_vtable_returns_some() {
    let mut db = VtableDatabase::new();
    db.add_vtable(Vtable::new(0x4000));
    db.add_rtti(RttiInfo {
        type_name: "X".into(),
        base_classes: vec![],
        rtti_address: 0x5000,
        abi: RttiAbi::Itanium,
    });
    db.link_vtable_rtti(0x4000, 0x5000);
    assert!(db.rtti_for_vtable(0x4000).is_some());
    assert_eq!(
        db.vtables.get(&0x4000).unwrap().class_name.as_deref(),
        Some("X")
    );
}

// ─── PureVirtualDetector ────────────────────────────────────────────────────

#[test]
fn pure_virtual_annotate_sets_name_when_missing() {
    let mut det = PureVirtualDetector::new();
    det.add_stub_address(0xDEAD);
    let mut vt = Vtable::new(0x1000);
    vt.add_entry(VtableEntry::new(0, 0xDEAD));
    let n = det.annotate(&mut vt);
    assert_eq!(n, 1);
    assert_eq!(
        vt.entries[0].function_name.as_deref(),
        Some("__cxa_pure_virtual")
    );
}

#[test]
fn pure_virtual_all_known_names_recognised() {
    let det = PureVirtualDetector::new();
    for n in &["__cxa_pure_virtual", "_purecall", "___cxa_pure_virtual", "__pure_virtual"] {
        let e = VtableEntry::with_name(0, 0x1, *n);
        assert!(det.is_pure_virtual(&e), "name {n} should be recognised");
    }
}

// ─── MultipleInheritanceLayout ──────────────────────────────────────────────

#[test]
fn mi_layout_primary_vtable_none_when_no_primary() {
    let mut l = MultipleInheritanceLayout::new("X", 16);
    l.add_sub_object(SubObject {
        class_name: "B".into(),
        offset: 0,
        vtable_address: Some(0x1000),
        is_primary: false, // not primary
    });
    assert!(l.primary_vtable().is_none());
}

#[test]
fn mi_layout_secondary_filters_none_vtable() {
    let mut l = MultipleInheritanceLayout::new("X", 64);
    l.add_sub_object(SubObject {
        class_name: "A".into(),
        offset: 0,
        vtable_address: Some(0x1000),
        is_primary: true,
    });
    l.add_sub_object(SubObject {
        class_name: "B".into(),
        offset: 16,
        vtable_address: None, // non-polymorphic base
        is_primary: false,
    });
    assert!(l.secondary_vtables().is_empty());
}

// ─── VtableScanner ──────────────────────────────────────────────────────────

#[test]
#[should_panic]
fn scanner_panics_on_bad_ptr_size() {
    // Documented panic; do not silently weaken.
    let _ = VtableScanner::new(7, 2);
}

#[test]
fn scanner_below_threshold_short_data() {
    let s = VtableScanner::new(8, 4);
    // 24 bytes < 8*4 minimum
    assert!(s.scan(&vec![0u8; 24], 0).is_empty());
}

#[test]
fn scanner_confidence_in_range() {
    let mut s = VtableScanner::new(8, 2);
    s.add_code_range(0x1000, 0x2000);
    let mut data = vec![0u8; 8 * 5];
    for (i, &a) in [0x1100u64, 0x1200, 0x1300, 0x1400, 0x1500].iter().enumerate() {
        data[i * 8..i * 8 + 8].copy_from_slice(&a.to_le_bytes());
    }
    let cands = s.scan(&data, 0x4000);
    assert!(!cands.is_empty());
    for c in &cands {
        assert!((0.0..=1.0).contains(&c.confidence));
    }
}

#[test]
fn scanner_method_ptrs_filter_zeros() {
    // Zeros should not appear in method_ptrs.
    let mut s = VtableScanner::new(8, 2);
    s.add_code_range(0x1000, 0x2000);
    let data: Vec<u8> = {
        let mut d = vec![0u8; 8 * 3];
        d[0..8].copy_from_slice(&0x1100u64.to_le_bytes());
        d[8..16].copy_from_slice(&0x1200u64.to_le_bytes());
        // last 8 bytes left zero
        d
    };
    let cands = s.scan(&data, 0x4000);
    assert_eq!(cands.len(), 1);
    for &p in &cands[0].method_ptrs {
        assert_ne!(p, 0);
    }
}

// ─── VtableSlotAnnotator ────────────────────────────────────────────────────

#[test]
fn annotator_load_symbols_merges() {
    let mut a = VtableSlotAnnotator::new();
    a.add_symbol(0x1000, "first");
    let mut more = HashMap::new();
    more.insert(0x2000u64, "second".to_string());
    a.load_symbols(more);
    assert_eq!(a.symbol_count(), 2);
}

#[test]
fn annotator_annotate_all_across_database() {
    let mut a = VtableSlotAnnotator::new();
    a.add_symbol(0x1000, "f");
    let mut db = VtableDatabase::new();
    db.add_vtable(vt_with(0x4000, &[0x1000]));
    db.add_vtable(vt_with(0x5000, &[0x1000]));
    let n = a.annotate_all(&mut db);
    assert_eq!(n, 2);
}

// ─── VtableComparer ─────────────────────────────────────────────────────────

#[test]
fn comparer_no_changes_returns_empty() {
    let a = vt_with(0, &[0x10, 0x20]);
    let c = VtableComparer::new();
    assert!(c.diff(&a, &a).is_empty());
}

#[test]
fn comparer_diff_multiple_slots() {
    let a = vt_with(0, &[0x10, 0x20, 0x30]);
    let b = vt_with(0, &[0x10, 0xAA, 0xBB]);
    let c = VtableComparer::new();
    let d = c.diff(&a, &b);
    assert_eq!(d.len(), 2);
    assert_eq!(d[0].slot, 1);
    assert_eq!(d[1].slot, 2);
}

// ─── VtableStats ────────────────────────────────────────────────────────────

#[test]
fn stats_multiple_vtables_avg() {
    let mut db = VtableDatabase::new();
    db.add_vtable(vt_with(0x1000, &[0x1, 0x2]));
    db.add_vtable(vt_with(0x2000, &[0x1, 0x2, 0x3, 0x4]));
    let s = VtableStats::from_database(&db);
    assert_eq!(s.vtable_count, 2);
    assert_eq!(s.total_slots, 6);
    assert_eq!(s.max_slots, 4);
    assert!((s.avg_slots - 3.0).abs() < 1e-9);
}

// ─── VmiFlags / VmiRttiInfo ─────────────────────────────────────────────────

#[test]
fn vmi_flags_zero_has_neither() {
    let f = VmiFlags(0);
    assert!(!f.is_diamond_shaped());
    assert!(!f.has_non_diamond_repeat());
}

#[test]
fn vmi_flags_combined_bits() {
    let f = VmiFlags(VmiFlags::DIAMOND_SHAPED | VmiFlags::NON_DIAMOND_REPEAT);
    assert!(f.is_diamond_shaped());
    assert!(f.has_non_diamond_repeat());
}

#[test]
fn vmi_rtti_single_base_not_multiple_inheritance() {
    let info = VmiRttiInfo {
        class_name: "X".into(),
        rtti_address: 0,
        flags: 0,
        base_classes: vec![VmiBaseClassEntry {
            base_class_name: "A".into(),
            offset: 0,
            is_virtual: false,
            is_public: true,
        }],
    };
    assert!(!info.has_multiple_inheritance());
    assert_eq!(info.base_count(), 1);
}

// ─── parse_msvc_rtti / parse_itanium_rtti ──────────────────────────────────

#[test]
fn parse_itanium_rtti_too_small_returns_none() {
    let v = vec![0u8; 15];
    assert!(parse_itanium_rtti(&v, 0x1000).is_none());
}

#[test]
fn parse_msvc_rtti_too_small_returns_none() {
    let v = vec![0u8; 23];
    assert!(parse_msvc_rtti(&v, 0x1000).is_none());
}

#[test]
fn parse_itanium_rtti_minimal_decodes() {
    let base = 0x1000u64;
    let mut data = vec![0u8; 0x40];
    data[8..16].copy_from_slice(&(base + 0x10).to_le_bytes());
    data[0x10..0x18].copy_from_slice(b"TypeXY\0\0");
    let info = parse_itanium_rtti(&data, base).unwrap();
    assert_eq!(info.type_name, "TypeXY");
    assert_eq!(info.abi, RttiAbi::Itanium);
}

// ─── vtable_extends ─────────────────────────────────────────────────────────

#[test]
fn vtable_extends_false_for_empty_base() {
    let a = Vtable::new(0);
    let b = vt_with(0, &[0x10, 0x20]);
    assert!(!vtable_extends(&a, &b));
}

#[test]
fn vtable_extends_false_for_equal_length() {
    let a = vt_with(0, &[0x10, 0x20]);
    let b = vt_with(0, &[0x10, 0x20]);
    assert!(!vtable_extends(&a, &b));
}

#[test]
fn vtable_extends_false_when_prefix_mismatch() {
    let a = vt_with(0, &[0x10, 0x20]);
    let b = vt_with(0, &[0x10, 0xFF, 0x30]);
    assert!(!vtable_extends(&a, &b));
}

#[test]
fn vtable_extends_true_when_strict_prefix() {
    let a = vt_with(0, &[0x10, 0x20]);
    let b = vt_with(0, &[0x10, 0x20, 0x30]);
    assert!(vtable_extends(&a, &b));
}

// ─── VtableSet ──────────────────────────────────────────────────────────────

#[test]
fn vtable_set_len_and_empty() {
    let mut s = VtableSet::new();
    assert!(s.is_empty());
    s.push(Vtable::new(0x1000));
    assert_eq!(s.len(), 1);
    assert!(!s.is_empty());
}

#[test]
fn vtable_set_to_json_roundtrip_via_serde() {
    let mut s = VtableSet::new();
    let mut vt = Vtable::new(0x3000);
    vt.class_name = Some("Foo".into());
    vt.offset_to_top = Some(-8);
    vt.add_entry(VtableEntry::with_name(0, 0x100, "Foo::f"));
    s.push(vt);
    let json = s.to_json();
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    let obj = &arr[0];
    assert_eq!(obj["offset_to_top"], -8);
    assert_eq!(obj["entries"][0]["function_name"], "Foo::f");
}

// ─── VtableBuilder ──────────────────────────────────────────────────────────

#[test]
fn vtable_builder_edges_strict_prefix_detected() {
    let mut b = VtableBuilder::new();
    let mut base = vt_with(0x1000, &[0x100, 0x200]);
    base.class_name = Some("Base".into());
    let mut derived = vt_with(0x2000, &[0x100, 0x200, 0x300]);
    derived.class_name = Some("Derived".into());
    b.add_vtable(base);
    b.add_vtable(derived);
    let edges = b.edges();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].base, "Base");
    assert_eq!(edges[0].derived, "Derived");
}

#[test]
fn vtable_builder_no_edges_for_unrelated_vtables() {
    let mut b = VtableBuilder::new();
    b.add_vtable(vt_with(0x1000, &[0x100, 0x200]));
    b.add_vtable(vt_with(0x2000, &[0xAA, 0xBB, 0xCC]));
    assert!(b.edges().is_empty());
}

// ─── Demangler ──────────────────────────────────────────────────────────────

#[test]
fn demangler_detect_itanium_prefix() {
    assert!(is_itanium_mangled("_ZN3FooEv"));
    assert!(is_itanium_mangled("__ZN3FooEv"));
    assert!(!is_itanium_mangled("Foo::bar"));
}

#[test]
fn demangler_detect_msvc_prefix() {
    assert!(is_msvc_mangled("?foo@bar@@QAEXXZ"));
    assert!(is_msvc_mangled(".?AVFoo@@"));
    assert!(is_msvc_mangled(".?AUStr@@"));
    assert!(!is_msvc_mangled("foo"));
}

#[test]
fn demangler_demangle_unmangled_returns_unchanged() {
    assert_eq!(demangle("foo"), "foo");
}

#[test]
fn demangler_demangle_msvc_class() {
    // demangle() dispatches based on prefix; for .?AV form should at least strip.
    let out = demangle(".?AVFoo@@");
    assert!(out.contains("Foo"));
}

#[test]
fn demangler_itanium_empty_after_prefix() {
    // "_Z" alone — should not panic; returns the original name (per docstring).
    let out = demangle_itanium("_Z");
    assert_eq!(out, "_Z");
}

#[test]
fn demangler_itanium_simple_nested() {
    // _ZN3Foo3barEv -> something containing "Foo" and "bar"
    let out = demangle_itanium("_ZN3Foo3barEv");
    assert!(out.contains("Foo"), "got {out}");
    assert!(out.contains("bar"), "got {out}");
}
