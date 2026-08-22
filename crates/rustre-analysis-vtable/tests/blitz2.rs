//! blitz2: deep adversarial tests for rustre-analysis-vtable.
//!
//! Focuses on the public API in `lib.rs`: Section, Vtable/VtableEntry,
//! `VtableDetector`, `ItaniumRttiDecoder`, `MsvcRttiDecoder`, `VtableDatabase`,
//! `PureVirtualDetector`, `AbstractClassInference`, `MultipleInheritanceLayout`,
//! `VtableScanner`, `VtableSlotAnnotator`, `VtableComparer`, `VtableStats`,
//! and demangler helpers.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::thread;

use rustre_analysis_vtable::*;

// Seeded LCG ------------------------------------------------------------------

struct Lcg(u64);
impl Lcg {
    const fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            v.extend_from_slice(&self.next().to_le_bytes());
        }
        v.truncate(n);
        v
    }
}

// ── Section ─────────────────────────────────────────────────────────────────

#[test]
fn test_section_contains_boundaries() {
    let s = Section::new(".x", 0x1000, vec![0u8; 16]);
    assert!(s.contains(0x1000));
    assert!(s.contains(0x100F));
    assert!(!s.contains(0x1010));
    assert!(!s.contains(0x0FFF));
}

#[test]
fn test_section_end_address_saturates() {
    let s = Section::new(".x", u64::MAX - 4, vec![0u8; 8]);
    assert_eq!(s.end_address(), u64::MAX);
}

#[test]
fn test_section_read_ptr_invalid_size_returns_none() {
    let s = Section::new(".x", 0x1000, vec![0u8; 16]);
    assert!(s.read_ptr(0x1000, 3).is_none());
    assert!(s.read_ptr(0x1000, 0).is_none());
}

#[test]
fn test_section_read_ptr_truncated() {
    let s = Section::new(".x", 0x1000, vec![0u8; 4]);
    assert!(s.read_ptr(0x1000, 8).is_none());
    assert!(s.read_ptr(0x1000, 4).is_some());
}

#[test]
fn test_section_read_cstr_no_nul_returns_none() {
    let s = Section::new(".x", 0x1000, b"NoNullTerm".to_vec());
    assert!(s.read_cstr(0x1000).is_none());
}

#[test]
fn test_section_read_cstr_empty_string_at_offset() {
    let s = Section::new(".x", 0x1000, vec![0u8; 8]);
    assert_eq!(s.read_cstr(0x1000).as_deref(), Some(""));
}

#[test]
fn test_section_read_cstr_invalid_utf8_returns_none() {
    let mut data = vec![0xFFu8, 0xFE, 0xFD];
    data.push(0);
    let s = Section::new(".x", 0x1000, data);
    assert!(s.read_cstr(0x1000).is_none());
}

#[test]
fn test_section_read_i32_u32_roundtrip_lcg() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let v = lcg.next() as u32;
        let mut data = Vec::new();
        data.extend_from_slice(&v.to_le_bytes());
        let s = Section::new(".x", 0x4000, data);
        assert_eq!(s.read_u32(0x4000), Some(v));
        assert_eq!(s.read_i32(0x4000), Some(v as i32));
    }
}

#[test]
fn test_section_read_u32_out_of_range() {
    let s = Section::new(".x", 0x1000, vec![0u8; 8]);
    assert!(s.read_u32(0x9000).is_none());
    assert!(s.read_i32(0x9000).is_none());
}

#[test]
fn test_section_read_ptr_fuzz_never_panics() {
    let mut lcg = Lcg::new();
    let base = 0x4000u64;
    for _ in 0..60 {
        let n = (lcg.next() as usize) % 64;
        let data = lcg.bytes(n);
        let s = Section::new(".x", base, data);
        let addr = base.wrapping_add(lcg.next() % 128);
        let _ = s.read_ptr(addr, 8);
        let _ = s.read_ptr(addr, 4);
        let _ = s.read_cstr(addr);
        let _ = s.read_u32(addr);
        let _ = s.read_i32(addr);
    }
}

// ── VtableEntry / Vtable ────────────────────────────────────────────────────

#[test]
fn test_vtable_entry_new_no_name() {
    let e = VtableEntry::new(8, 0xABCD);
    assert_eq!(e.offset, 8);
    assert_eq!(e.target_address, 0xABCD);
    assert!(e.function_name.is_none());
}

#[test]
fn test_vtable_entry_with_name_display_contains_unknown_for_none() {
    let e = VtableEntry::new(0, 0x1234);
    let s = format!("{e}");
    assert!(s.contains("<unknown>"));
}

#[test]
fn test_vtable_entry_eq_hash_consistency_pairs() {
    // VtableEntry doesn't impl Hash directly; check Eq consistency.
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let off = (lcg.next() as usize) & 0xFFF;
        let addr = lcg.next();
        let a = VtableEntry::new(off, addr);
        let b = VtableEntry::new(off, addr);
        assert_eq!(a, b);
        let c = VtableEntry::with_name(off, addr, "x");
        assert_ne!(a, c);
    }
}

#[test]
fn test_vtable_entry_max_values() {
    let e = VtableEntry::new(usize::MAX, u64::MAX);
    assert_eq!(e.offset, usize::MAX);
    assert_eq!(e.target_address, u64::MAX);
}

#[test]
fn test_vtable_zero_entries_display() {
    let vt = Vtable::new(0x9000);
    let s = format!("{vt}");
    assert!(s.contains("<unknown class>"));
    assert!(s.contains("0x9000"));
    assert!(s.contains("0 entries"));
}

// ── VtableDetector ──────────────────────────────────────────────────────────

#[test]
fn test_vtable_detector_rejects_ptr_size_zero() {
    let data = Section::new(".d", 0, vec![]);
    let det = VtableDetector::new(0);
    assert!(matches!(
        det.detect(&data, &[]),
        Err(VtableError::UnsupportedPointerSize(0))
    ));
}

#[test]
fn test_vtable_detector_rejects_ptr_size_16() {
    let data = Section::new(".d", 0, vec![]);
    let det = VtableDetector::new(16);
    assert!(matches!(
        det.detect(&data, &[]),
        Err(VtableError::UnsupportedPointerSize(16))
    ));
}

#[test]
fn test_vtable_detector_empty_data() {
    let data = Section::new(".d", 0x4000, vec![]);
    let mut code = Section::new(".t", 0x1000, vec![0; 0x100]);
    code.executable = true;
    let det = VtableDetector::new(8);
    assert!(det.detect(&data, &[code]).unwrap().is_empty());
}

#[test]
fn test_vtable_detector_no_code_sections() {
    let data = make_ptr_section(0x4000, &[0x1000, 0x1008, 0x1010], false);
    let det = VtableDetector::new(8);
    assert!(det.detect(&data, &[]).unwrap().is_empty());
}

#[test]
fn test_vtable_detector_ptrs_outside_code() {
    let mut code = Section::new(".t", 0x1000, vec![0; 0x100]);
    code.executable = true;
    let data = make_ptr_section(0x4000, &[0xDEAD, 0xBEEF, 0xCAFE], false);
    let det = VtableDetector::new(8);
    assert!(det.detect(&data, &[code]).unwrap().is_empty());
}

#[test]
fn test_vtable_detector_4byte_ptrs() {
    let mut code = Section::new(".t", 0x1000, vec![0; 0x1000]);
    code.executable = true;
    let mut data = Vec::new();
    for p in [0x1000u32, 0x1100, 0x1200, 0x1300] {
        data.extend_from_slice(&p.to_le_bytes());
    }
    let dsec = Section::new(".d", 0x4000, data);
    let det = VtableDetector::new(4);
    let v = det.detect(&dsec, &[code]).unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].entry_count(), 4);
}

#[test]
fn test_vtable_detector_non_executable_code_ignored() {
    let code = Section::new(".t", 0x1000, vec![0; 0x100]); // not executable
    let data = make_ptr_section(0x4000, &[0x1000, 0x1008], false);
    let det = VtableDetector::new(8);
    assert!(det.detect(&data, &[code]).unwrap().is_empty());
}

#[test]
fn test_vtable_detector_fuzz_never_panics() {
    let mut lcg = Lcg::new();
    let mut code = Section::new(".t", 0x1000, vec![0u8; 0x2000]);
    code.executable = true;
    for _ in 0..40 {
        let n = (lcg.next() as usize) % 256;
        let data = Section::new(".d", 0x4000, lcg.bytes(n));
        let det = VtableDetector::new(8);
        let _ = det.detect(&data, std::slice::from_ref(&code));
    }
}

// ── Itanium RTTI ────────────────────────────────────────────────────────────

#[test]
fn test_itanium_decode_falls_back_to_known_names() {
    let mut data = vec![0u8; 0x40];
    // name pointer at offset 8 -> some addr that isn't in section
    let name_ptr = 0xFFFF_0000u64;
    data[8..16].copy_from_slice(&name_ptr.to_le_bytes());
    let sec = Section::new(".rodata", 0x8000, data);
    let mut known = HashMap::new();
    known.insert(name_ptr, "KnownName".to_string());
    let info = ItaniumRttiDecoder::decode(0x8000, &sec, 8, &known).unwrap();
    assert_eq!(info.type_name, "KnownName");
}

#[test]
fn test_itanium_decode_unknown_name_synthesises_placeholder() {
    let mut data = vec![0u8; 0x40];
    let name_ptr = 0xFFFF_1234u64;
    data[8..16].copy_from_slice(&name_ptr.to_le_bytes());
    let sec = Section::new(".rodata", 0x8000, data);
    let known = HashMap::new();
    let info = ItaniumRttiDecoder::decode(0x8000, &sec, 8, &known).unwrap();
    assert!(info.type_name.contains("0xffff1234"));
}

#[test]
fn test_itanium_decode_out_of_range_addr() {
    let sec = Section::new(".rodata", 0x8000, vec![0u8; 16]);
    let res = ItaniumRttiDecoder::decode(0x9000, &sec, 8, &HashMap::new());
    assert!(res.is_err());
}

#[test]
fn test_itanium_decode_no_base_when_zero_ptr() {
    let mut data = vec![0u8; 0x40];
    let name_addr = 0x8020u64;
    data[8..16].copy_from_slice(&name_addr.to_le_bytes());
    data[0x20..0x27].copy_from_slice(b"NoBase\0");
    // base ptr at +16 stays zero
    let sec = Section::new(".rodata", 0x8000, data);
    let info = ItaniumRttiDecoder::decode(0x8000, &sec, 8, &HashMap::new()).unwrap();
    assert_eq!(info.type_name, "NoBase");
    assert!(info.base_classes.is_empty());
}

// ── MSVC decoder ────────────────────────────────────────────────────────────

#[test]
fn test_msvc_demangle_class_with_namespace() {
    assert_eq!(
        MsvcRttiDecoder::demangle_msvc(".?AVInner@Outer@@"),
        "Inner::Outer"
    );
}

#[test]
fn test_msvc_demangle_no_prefix_unchanged_except_at() {
    assert_eq!(MsvcRttiDecoder::demangle_msvc("Plain"), "Plain");
    assert_eq!(MsvcRttiDecoder::demangle_msvc("A@B"), "A::B");
}

#[test]
fn test_msvc_demangle_empty() {
    assert_eq!(MsvcRttiDecoder::demangle_msvc(""), "");
}

#[test]
fn test_msvc_decode_col_out_of_range() {
    let sec = Section::new(".rdata", 0x10000, vec![0u8; 4]);
    let res = MsvcRttiDecoder::decode_col(0x20000, &sec, 0x400000);
    assert!(res.is_err());
}

// ── VtableDatabase ──────────────────────────────────────────────────────────

#[test]
fn test_database_add_and_lookup() {
    let mut db = VtableDatabase::new();
    let vt = Vtable::new(0x1000);
    db.add_vtable(vt);
    assert!(db.vtables.contains_key(&0x1000));
}

#[test]
fn test_database_link_propagates_name() {
    let mut db = VtableDatabase::new();
    db.add_vtable(Vtable::new(0xAAA));
    db.add_rtti(RttiInfo {
        type_name: "X".into(),
        base_classes: vec![],
        rtti_address: 0xBBB,
        abi: RttiAbi::Msvc,
    });
    db.link_vtable_rtti(0xAAA, 0xBBB);
    assert_eq!(
        db.vtables.get(&0xAAA).unwrap().class_name.as_deref(),
        Some("X")
    );
    assert!(db.rtti_for_vtable(0xAAA).is_some());
}

#[test]
fn test_database_link_missing_rtti_is_noop_for_name() {
    let mut db = VtableDatabase::new();
    db.add_vtable(Vtable::new(0xAAA));
    db.link_vtable_rtti(0xAAA, 0xCCC); // RTTI not present
    assert!(db.vtables.get(&0xAAA).unwrap().class_name.is_none());
    assert!(db.rtti_for_vtable(0xAAA).is_none());
}

#[test]
fn test_database_find_by_class_multiple() {
    let mut db = VtableDatabase::new();
    for (addr, name) in [(0x1000u64, "A"), (0x2000, "A"), (0x3000, "B")] {
        let mut vt = Vtable::new(addr);
        vt.class_name = Some(name.into());
        db.add_vtable(vt);
    }
    assert_eq!(db.find_by_class("A").len(), 2);
    assert_eq!(db.find_by_class("B").len(), 1);
    assert!(db.find_by_class("Z").is_empty());
}

// ── PureVirtualDetector ─────────────────────────────────────────────────────

#[test]
fn test_pure_virtual_by_name() {
    let pv = PureVirtualDetector::new();
    let e = VtableEntry::with_name(0, 0xDEAD, "__cxa_pure_virtual");
    assert!(pv.is_pure_virtual(&e));
    let e2 = VtableEntry::with_name(0, 0xDEAD, "_purecall");
    assert!(pv.is_pure_virtual(&e2));
}

#[test]
fn test_pure_virtual_by_addr() {
    let mut pv = PureVirtualDetector::new();
    pv.add_stub_address(0xDEAD_BEEF);
    let e = VtableEntry::new(0, 0xDEAD_BEEF);
    assert!(pv.is_pure_virtual(&e));
}

#[test]
fn test_pure_virtual_not_matched_for_normal() {
    let pv = PureVirtualDetector::new();
    let e = VtableEntry::with_name(0, 0x1234, "Foo::bar");
    assert!(!pv.is_pure_virtual(&e));
}

#[test]
fn test_pure_virtual_annotate_assigns_name() {
    let mut pv = PureVirtualDetector::new();
    pv.add_stub_address(0x55);
    let mut vt = Vtable::new(0x1000);
    vt.add_entry(VtableEntry::new(0, 0x55));
    vt.add_entry(VtableEntry::new(8, 0x66));
    let n = pv.annotate(&mut vt);
    assert_eq!(n, 1);
    assert_eq!(
        vt.entries[0].function_name.as_deref(),
        Some("__cxa_pure_virtual")
    );
    assert!(vt.entries[1].function_name.is_none());
}

#[test]
fn test_pure_virtual_count_in_database() {
    let mut db = VtableDatabase::new();
    let mut vt = Vtable::new(0x1000);
    vt.add_entry(VtableEntry::with_name(0, 1, "_purecall"));
    vt.add_entry(VtableEntry::with_name(8, 2, "Foo"));
    vt.add_entry(VtableEntry::with_name(16, 3, "__cxa_pure_virtual"));
    db.add_vtable(vt);
    let pv = PureVirtualDetector::new();
    assert_eq!(pv.count_in_database(&db), 2);
}

// ── AbstractClassInference ──────────────────────────────────────────────────

#[test]
fn test_abstract_class_inference_marks_abstract() {
    let mut db = VtableDatabase::new();
    let mut vt = Vtable::new(0x1000);
    vt.class_name = Some("Abs".into());
    vt.add_entry(VtableEntry::with_name(0, 1, "__cxa_pure_virtual"));
    db.add_vtable(vt);
    let mut concrete = Vtable::new(0x2000);
    concrete.class_name = Some("Conc".into());
    concrete.add_entry(VtableEntry::with_name(0, 2, "Foo::bar"));
    db.add_vtable(concrete);

    let inf = AbstractClassInference::new();
    let res = inf.infer(&db);
    let mut by_name = HashMap::new();
    for r in &res {
        by_name.insert(r.class_name.clone(), r);
    }
    assert!(by_name.get("Abs").unwrap().is_abstract);
    assert!(!by_name.get("Conc").unwrap().is_abstract);
}

#[test]
fn test_abstract_class_inference_synthetic_name() {
    let mut db = VtableDatabase::new();
    let vt = Vtable::new(0xABCD);
    db.add_vtable(vt);
    let inf = AbstractClassInference::new();
    let res = inf.infer(&db);
    assert_eq!(res.len(), 1);
    assert!(res[0].class_name.contains("0xabcd"));
    assert!(!res[0].is_abstract);
}

// ── MultipleInheritanceLayout ───────────────────────────────────────────────

#[test]
fn test_mi_layout_primary_and_secondary() {
    let mut layout = MultipleInheritanceLayout::new("Derived", 64);
    layout.add_sub_object(SubObject {
        class_name: "B".into(),
        offset: 16,
        vtable_address: Some(0xB000),
        is_primary: false,
    });
    layout.add_sub_object(SubObject {
        class_name: "A".into(),
        offset: 0,
        vtable_address: Some(0xA000),
        is_primary: true,
    });
    assert_eq!(layout.primary_vtable(), Some(0xA000));
    let sec = layout.secondary_vtables();
    assert_eq!(sec, vec![(16, 0xB000)]);
    assert_eq!(layout.base_count(), 2);
    // sub_objects sorted by offset
    assert_eq!(layout.sub_objects[0].offset, 0);
}

#[test]
fn test_mi_layout_primary_none_if_not_primary() {
    let mut layout = MultipleInheritanceLayout::new("D", 32);
    layout.add_sub_object(SubObject {
        class_name: "A".into(),
        offset: 0,
        vtable_address: Some(0xA000),
        is_primary: false,
    });
    assert!(layout.primary_vtable().is_none());
}

// ── VtableScanner ───────────────────────────────────────────────────────────

#[test]
#[should_panic]
fn test_vtable_scanner_panics_on_bad_ptr_size() {
    let _ = VtableScanner::new(5, 2);
}

#[test]
fn test_vtable_scanner_finds_candidate() {
    let mut sc = VtableScanner::new(8, 2);
    sc.add_code_range(0x1000, 0x2000);
    let mut data = Vec::new();
    for p in [0x1100u64, 0x1200, 0x1300] {
        data.extend_from_slice(&p.to_le_bytes());
    }
    let cands = sc.scan(&data, 0x4000);
    assert!(!cands.is_empty());
    assert_eq!(cands[0].slot_count, 3);
    assert!(cands[0].confidence > 0.0 && cands[0].confidence <= 1.0);
}

#[test]
fn test_vtable_scanner_short_data_returns_empty() {
    let mut sc = VtableScanner::new(8, 4);
    sc.add_code_range(0x1000, 0x2000);
    let data = vec![0u8; 8]; // not enough for 4 slots of 8 bytes
    assert!(sc.scan(&data, 0).is_empty());
}

#[test]
fn test_vtable_scanner_confidence_capped() {
    let mut sc = VtableScanner::new(8, 2);
    sc.add_code_range(0x1000, 0x9000);
    let mut data = Vec::new();
    for i in 0..30u64 {
        data.extend_from_slice(&(0x1000 + i * 16).to_le_bytes());
    }
    let cands = sc.scan(&data, 0x4000);
    for c in &cands {
        assert!(c.confidence <= 1.0 && c.confidence >= 0.0);
    }
}

#[test]
fn test_vtable_scanner_is_code_address() {
    let mut sc = VtableScanner::new(8, 2);
    sc.add_code_range(0x1000, 0x2000);
    assert!(sc.is_code_address(0x1000));
    assert!(sc.is_code_address(0x1FFF));
    assert!(!sc.is_code_address(0x2000));
    assert!(!sc.is_code_address(0x0FFF));
}

#[test]
fn test_vtable_scanner_fuzz_never_panics() {
    let mut lcg = Lcg::new();
    let mut sc = VtableScanner::new(8, 2);
    sc.add_code_range(0x1000, 0x9000);
    for _ in 0..50 {
        let n = (lcg.next() as usize) % 256;
        let data = lcg.bytes(n);
        let base = lcg.next();
        let _ = sc.scan(&data, base);
    }
}

// ── VtableSlotAnnotator ─────────────────────────────────────────────────────

#[test]
fn test_slot_annotator_named() {
    let mut ann = VtableSlotAnnotator::new();
    ann.add_symbol(0x1000, "Foo::bar");
    let mut vt = Vtable::new(0x4000);
    vt.add_entry(VtableEntry::new(0, 0x1000));
    vt.add_entry(VtableEntry::new(8, 0x9999));
    let n = ann.annotate(&mut vt);
    assert_eq!(n, 1);
    assert_eq!(vt.entries[0].function_name.as_deref(), Some("Foo::bar"));
    assert!(vt.entries[1].function_name.is_none());
    assert_eq!(ann.symbol_count(), 1);
}

#[test]
fn test_slot_annotator_does_not_overwrite() {
    let mut ann = VtableSlotAnnotator::new();
    ann.add_symbol(0x1000, "Replacement");
    let mut vt = Vtable::new(0x4000);
    vt.add_entry(VtableEntry::with_name(0, 0x1000, "Original"));
    let n = ann.annotate(&mut vt);
    assert_eq!(n, 0);
    assert_eq!(vt.entries[0].function_name.as_deref(), Some("Original"));
}

#[test]
fn test_slot_annotator_annotate_all_db() {
    let mut ann = VtableSlotAnnotator::new();
    let mut syms = HashMap::new();
    syms.insert(0x1000u64, "f1".to_string());
    syms.insert(0x2000u64, "f2".to_string());
    ann.load_symbols(syms);
    let mut db = VtableDatabase::new();
    let mut v1 = Vtable::new(0x4000);
    v1.add_entry(VtableEntry::new(0, 0x1000));
    let mut v2 = Vtable::new(0x5000);
    v2.add_entry(VtableEntry::new(0, 0x2000));
    v2.add_entry(VtableEntry::new(8, 0xDEAD));
    db.add_vtable(v1);
    db.add_vtable(v2);
    let total = ann.annotate_all(&mut db);
    assert_eq!(total, 2);
}

// ── VtableComparer ──────────────────────────────────────────────────────────

#[test]
fn test_comparer_identical() {
    let mut a = Vtable::new(0x4000);
    let mut b = Vtable::new(0x4000);
    for i in 0..5 {
        a.add_entry(VtableEntry::new(i * 8, 0x1000 + i as u64));
        b.add_entry(VtableEntry::new(i * 8, 0x1000 + i as u64));
    }
    let c = VtableComparer::new();
    assert!(c.diff(&a, &b).is_empty());
    assert!(c.is_identical(&a, &b));
}

#[test]
fn test_comparer_detects_patched_slot() {
    let mut a = Vtable::new(0x4000);
    let mut b = Vtable::new(0x4000);
    a.add_entry(VtableEntry::new(0, 0x1000));
    a.add_entry(VtableEntry::new(8, 0x2000));
    b.add_entry(VtableEntry::new(0, 0x1000));
    b.add_entry(VtableEntry::new(8, 0xDEAD));
    let c = VtableComparer::new();
    let d = c.diff(&a, &b);
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].slot, 1);
    assert_eq!(d[0].original_address, 0x2000);
    assert_eq!(d[0].patched_address, 0xDEAD);
    assert!(!c.is_identical(&a, &b));
}

#[test]
fn test_comparer_different_lengths_not_identical() {
    let mut a = Vtable::new(0x4000);
    let mut b = Vtable::new(0x4000);
    a.add_entry(VtableEntry::new(0, 0x1));
    b.add_entry(VtableEntry::new(0, 0x1));
    b.add_entry(VtableEntry::new(8, 0x2));
    let c = VtableComparer::new();
    assert!(c.diff(&a, &b).is_empty()); // common prefix matches
    assert!(!c.is_identical(&a, &b));
}

// ── VtableStats ─────────────────────────────────────────────────────────────

#[test]
fn test_vtable_stats_empty_db() {
    let db = VtableDatabase::new();
    let s = VtableStats::from_database(&db);
    assert_eq!(s.vtable_count, 0);
    assert_eq!(s.total_slots, 0);
    assert_eq!(s.max_slots, 0);
    assert_eq!(s.avg_slots, 0.0);
}

#[test]
fn test_vtable_stats_basic() {
    let mut db = VtableDatabase::new();
    let mut v1 = Vtable::new(0x1000);
    v1.add_entry(VtableEntry::with_name(0, 1, "_purecall"));
    v1.add_entry(VtableEntry::new(8, 2));
    let mut v2 = Vtable::new(0x2000);
    v2.add_entry(VtableEntry::new(0, 3));
    db.add_vtable(v1);
    db.add_vtable(v2);
    let s = VtableStats::from_database(&db);
    assert_eq!(s.vtable_count, 2);
    assert_eq!(s.total_slots, 3);
    assert_eq!(s.max_slots, 2);
    assert!(s.avg_slots > 1.0 && s.avg_slots < 2.0);
    assert_eq!(s.pure_virtual_count, 1);
    assert_eq!(s.abstract_class_count, 1);
    assert_eq!(s.rtti_linked_count, 0);
}

// ── Demangler ───────────────────────────────────────────────────────────────

#[test]
fn test_demangler_itanium_predicate() {
    assert!(is_itanium_mangled("_ZN3FooC1Ev"));
    assert!(!is_itanium_mangled("?foo@bar@@QEAAXXZ"));
}

#[test]
fn test_demangler_msvc_predicate() {
    assert!(is_msvc_mangled("?foo@bar@@QEAAXXZ"));
    assert!(!is_msvc_mangled("_ZN3FooC1Ev"));
}

#[test]
fn test_demangler_top_level_dispatch_doesnt_panic_on_garbage() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let n = (lcg.next() as usize) % 32;
        let bytes = lcg.bytes(n);
        let s: String = bytes.iter().map(|b| (b % 94 + 33) as char).collect();
        let _ = demangle(&s);
        let _ = demangle_itanium(&s);
        let _ = demangle_msvc(&s);
        let _ = demangle_msvc_function(&s);
        let _ = is_itanium_mangled(&s);
        let _ = is_msvc_mangled(&s);
    }
}

// ── Send/Sync threading ─────────────────────────────────────────────────────

#[test]
fn test_database_arc_send_sync_reads() {
    let mut db = VtableDatabase::new();
    for i in 0..10u64 {
        let mut vt = Vtable::new(0x1000 + i * 0x100);
        vt.class_name = Some(format!("C{i}"));
        vt.add_entry(VtableEntry::new(0, 0xABC));
        db.add_vtable(vt);
    }
    let db = Arc::new(db);
    let mut handles = Vec::new();
    for t in 0..4 {
        let dbc = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            let mut sum = 0usize;
            for _ in 0..100 {
                for i in 0..10u64 {
                    if let Some(vt) = dbc.vtables.get(&(0x1000 + i * 0x100)) {
                        sum += vt.entries.len();
                    }
                }
            }
            (t, sum)
        }));
    }
    let mut seen = HashSet::new();
    for h in handles {
        let (t, sum) = h.join().unwrap();
        assert_eq!(sum, 100 * 10);
        seen.insert(t);
    }
    assert_eq!(seen.len(), 4);
}

#[test]
fn test_scanner_arc_send_sync() {
    let mut sc = VtableScanner::new(8, 2);
    sc.add_code_range(0x1000, 0x9000);
    let sc = Arc::new(sc);
    let mut data = Vec::new();
    for p in [0x1100u64, 0x1200, 0x1300, 0x1400] {
        data.extend_from_slice(&p.to_le_bytes());
    }
    let data = Arc::new(data);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let s = Arc::clone(&sc);
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            let mut total = 0;
            for _ in 0..100 {
                total += s.scan(&d, 0x4000).len();
            }
            total
        }));
    }
    for h in handles {
        assert!(h.join().unwrap() > 0);
    }
}

// ── Round-trip / boundary ───────────────────────────────────────────────────

#[test]
fn test_make_ptr_section_roundtrip() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let n = ((lcg.next() as usize) % 8) + 1;
        let mut ptrs = Vec::new();
        for _ in 0..n {
            ptrs.push(lcg.next());
        }
        let sec = make_ptr_section(0x4000, &ptrs, true);
        assert!(sec.executable);
        for (i, &p) in ptrs.iter().enumerate() {
            let addr = 0x4000 + (i * 8) as u64;
            assert_eq!(sec.read_ptr(addr, 8), Some(p));
        }
    }
}

#[test]
fn test_make_str_section_roundtrip() {
    for s in [
        "", "a", "ab", "Hello", "MyClass", "a::b::c",
        "with spaces", "with_underscores",
    ] {
        let sec = make_str_section(0x9000, s);
        assert_eq!(sec.read_cstr(0x9000).as_deref(), Some(s));
    }
}

#[test]
fn test_rtti_abi_eq_and_clone() {
    let a = RttiAbi::Itanium;
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(RttiAbi::Itanium, RttiAbi::Msvc);
    assert_ne!(RttiAbi::Msvc, RttiAbi::Unknown);
}

#[test]
fn test_vtable_error_address_out_of_range_formats_hex() {
    let e = VtableError::AddressOutOfRange(0xABCD_EF01);
    let s = e.to_string();
    assert!(s.contains("0xabcdef01"));
}

#[test]
fn test_vtable_detector_overlapping_vtables_skip_correctly() {
    // Two contiguous vtables should be detected as either one big or two.
    let mut code = Section::new(".t", 0x1000, vec![0u8; 0x2000]);
    code.executable = true;
    let ptrs: Vec<u64> = (0..6).map(|i| 0x1000 + i * 0x10).collect();
    let data = make_ptr_section(0x4000, &ptrs, false);
    let det = VtableDetector::new(8);
    let v = det.detect(&data, &[code]).unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].entry_count(), 6);
}
