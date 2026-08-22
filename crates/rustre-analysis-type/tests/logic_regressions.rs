//! Regression tests for logic defects found by the wave-1 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact output the audit predicted.

use rustre_analysis_type::struct_layout_recovery::{CandidateStruct, FieldAccessPattern};

/// `RecoveredField::new` already starts `access_count` at 1, and `observe`
/// then increments it again — so the very first access to an offset is
/// counted twice. The inflation is not even uniform: two accesses to one
/// offset give 3 inside a single candidate but 4 when observed once in each of
/// two candidates that are later merged, so any threshold on `access_count`
/// (hot-field detection, confidence scoring) is applied to a number that
/// depends on how the observations happened to be grouped.
#[test]
fn a_single_observation_counts_once() {
    let mut c = CandidateStruct::new("p");
    c.observe(&FieldAccessPattern::read("p", 0, 4, 0));

    assert_eq!(
        c.fields[&0].access_count, 1,
        "one observed access must be counted once"
    );
}

#[test]
fn repeated_observations_count_exactly() {
    let mut c = CandidateStruct::new("p");
    for i in 0..5u64 {
        c.observe(&FieldAccessPattern::read("p", 8, 4, i));
    }
    assert_eq!(c.fields[&8].access_count, 5);
}

/// Distinct offsets are independent fields, each with its own count.
#[test]
fn each_offset_is_counted_separately() {
    let mut c = CandidateStruct::new("p");
    c.observe(&FieldAccessPattern::read("p", 0, 4, 0));
    c.observe(&FieldAccessPattern::read("p", 0, 4, 1));
    c.observe(&FieldAccessPattern::read("p", 4, 4, 2));

    assert_eq!(c.fields[&0].access_count, 2);
    assert_eq!(c.fields[&4].access_count, 1);
}

/// The total of the per-field counts must equal the number of observations —
/// the invariant the double-increment broke.
#[test]
fn field_counts_sum_to_the_observation_count() {
    let mut c = CandidateStruct::new("p");
    let pats = [
        FieldAccessPattern::read("p", 0, 4, 0),
        FieldAccessPattern::read("p", 0, 4, 1),
        FieldAccessPattern::read("p", 8, 8, 2),
        FieldAccessPattern::read("p", 16, 2, 3),
        FieldAccessPattern::read("p", 8, 8, 4),
    ];
    for p in &pats {
        c.observe(p);
    }

    let total: usize = c.fields.values().map(|f| f.access_count).sum();
    assert_eq!(
        total,
        pats.len(),
        "per-field counts must add up to the number of observations"
    );
}

// ── InterproceduralTypes::propagate ────────────────────────────────────────

use rustre_analysis_type::type_propagation::{
    FloatSize, FunctionTypeSig, IntSize, InterproceduralTypes, ReType,
};

/// The doc promises "when a caller passes a typed argument to a callee with
/// Unknown param type, the callee's param type is updated" — i.e. propagate
/// the CALL-SITE ARGUMENT types. The body instead copied the CALLER'S OWN
/// parameter types positionally into the callee's slots, which is unrelated
/// information: `main(int argc, char **argv)` calling `f(double, size_t)`
/// typed `f` as `(int, char**)`.
#[test]
fn a_callers_own_params_are_not_the_callees_params() {
    let mut it = InterproceduralTypes::new();
    // main(int argc, char **argv)
    it.register_sig(FunctionTypeSig::new(
        0x1000,
        vec![
            ReType::Int(IntSize::I32),
            ReType::ptr(ReType::ptr(ReType::Char)),
        ],
        ReType::Int(IntSize::I32),
    ));
    // f(?, ?) — really f(double, size_t)
    it.register_sig(FunctionTypeSig::new(
        0x2000,
        vec![ReType::Unknown, ReType::Unknown],
        ReType::Void,
    ));
    it.add_call(0x1000, 0x2000);
    it.propagate();

    let f = it.sig(0x2000).expect("callee present");
    assert_ne!(
        f.params[0],
        ReType::Int(IntSize::I32),
        "main's `argc` says nothing about f's first parameter"
    );
    assert_ne!(
        f.params[1],
        ReType::ptr(ReType::ptr(ReType::Char)),
        "main's `argv` says nothing about f's second parameter"
    );
}

/// With the ARGUMENT types recorded at the call site, propagation must work as
/// documented.
#[test]
fn call_site_argument_types_reach_the_callee() {
    let mut it = InterproceduralTypes::new();
    it.register_sig(FunctionTypeSig::new(
        0x1000,
        vec![ReType::Int(IntSize::I32)],
        ReType::Void,
    ));
    it.register_sig(FunctionTypeSig::new(
        0x2000,
        vec![ReType::Unknown, ReType::Unknown],
        ReType::Void,
    ));
    // f(double, char*) at the call site.
    it.add_call_with_args(
        0x1000,
        0x2000,
        vec![ReType::Float(FloatSize::F64), ReType::ptr(ReType::Char)],
    );
    let updates = it.propagate();

    let f = it.sig(0x2000).expect("callee present");
    assert_eq!(f.params[0], ReType::Float(FloatSize::F64));
    assert_eq!(f.params[1], ReType::ptr(ReType::Char));
    assert_eq!(updates, 2);
}

/// An already-known parameter type must not be overwritten by a call site.
#[test]
fn known_parameter_types_are_not_overwritten() {
    let mut it = InterproceduralTypes::new();
    it.register_sig(FunctionTypeSig::new(0x1000, vec![], ReType::Void));
    it.register_sig(FunctionTypeSig::new(
        0x2000,
        vec![ReType::Int(IntSize::I64)],
        ReType::Void,
    ));
    it.add_call_with_args(0x1000, 0x2000, vec![ReType::Float(FloatSize::F64)]);
    it.propagate();

    assert_eq!(
        it.sig(0x2000).unwrap().params[0],
        ReType::Int(IntSize::I64),
        "a known type wins over a call-site guess"
    );
}

// ── parse_itanium_typeinfo ─────────────────────────────────────────────────

use rustre_analysis_type::vtable::{
    parse_itanium_typeinfo, BinaryView, ItaniumTypeinfoKind, SectionDesc,
};
use rustre_analysis_type::constraints::Address;

const BASE: u64 = 0x1000;

fn rodata(size: u64) -> SectionDesc {
    SectionDesc {
        name: ".rodata".to_string(),
        start: BASE,
        size,
        is_executable: false,
        is_readable: true,
        is_writable: false,
    }
}

fn put_ptr(d: &mut [u8], addr: u64, v: u64) {
    let off = (addr - BASE) as usize;
    d[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(d: &mut [u8], addr: u64, v: u32) {
    let off = (addr - BASE) as usize;
    d[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_str(d: &mut [u8], addr: u64, s: &str) {
    let off = (addr - BASE) as usize;
    d[off..off + s.len()].copy_from_slice(s.as_bytes());
    d[off + s.len()] = 0;
}

/// Single-inheritance Itanium typeinfo was NEVER detected. The kind was
/// decided by testing bits of the word at `ti + 2*ptr_size`, but in
/// `__si_class_type_info` that word is the base-class typeinfo POINTER — it is
/// pointer-aligned, so bits 0 and 1 are always zero and the class was always
/// reported as a leaf with no bases.
#[test]
fn single_inheritance_typeinfo_is_detected() {
    let mut d = vec![0u8; 0x400];

    // Derived's typeinfo at 0x1200: vptr, name*, base_type*
    put_ptr(&mut d, 0x1200, 0x1300); // vptr (some __si_class_type_info vtable)
    put_ptr(&mut d, 0x1208, 0x1280); // name pointer
    put_ptr(&mut d, 0x1210, 0x1100); // base typeinfo (Base), pointer-aligned
    put_str(&mut d, 0x1280, "_ZTI7Derived");

    // Base's typeinfo at 0x1100 — a leaf.
    put_ptr(&mut d, 0x1100, 0x1320);
    put_ptr(&mut d, 0x1108, 0x1290);
    put_str(&mut d, 0x1290, "_ZTI4Base");

    // The vtable: typeinfo pointer sits one word before the first slot.
    let vtable_addr = 0x1240u64;
    put_ptr(&mut d, vtable_addr - 8, 0x1200);

    let bv = BinaryView::new(d, BASE, vec![rodata(0x400)], 8);
    let ti = parse_itanium_typeinfo(&bv, Address(vtable_addr))
        .expect("typeinfo must parse");

    assert_eq!(ti.class_name, "7Derived");
    assert_eq!(
        ti.kind,
        ItaniumTypeinfoKind::SingleInheritance,
        "a typeinfo whose third word points at another typeinfo is __si_class_type_info"
    );
    assert_eq!(ti.base_classes.len(), 1);
    assert_eq!(ti.base_classes[0].base_typeinfo_rva, 0x1100);
}

/// A genuine leaf must stay a leaf — the fix must not start inventing bases.
#[test]
fn leaf_typeinfo_stays_a_leaf() {
    let mut d = vec![0u8; 0x400];

    // Leaf typeinfo at 0x1200: vptr, name*, then nothing meaningful (zeros).
    put_ptr(&mut d, 0x1200, 0x1300);
    put_ptr(&mut d, 0x1208, 0x1280);
    put_str(&mut d, 0x1280, "_ZTI4Leaf");

    let vtable_addr = 0x1240u64;
    put_ptr(&mut d, vtable_addr - 8, 0x1200);

    let bv = BinaryView::new(d, BASE, vec![rodata(0x400)], 8);
    let ti = parse_itanium_typeinfo(&bv, Address(vtable_addr)).expect("parses");

    assert_eq!(ti.kind, ItaniumTypeinfoKind::Leaf);
    assert!(ti.base_classes.is_empty());
}

/// Multiple inheritance keeps working: flags + `base_count` + the base array.
#[test]
fn multiple_inheritance_typeinfo_is_detected() {
    let mut d = vec![0u8; 0x400];

    put_ptr(&mut d, 0x1200, 0x1300); // vptr
    put_ptr(&mut d, 0x1208, 0x1280); // name*
    put_u32(&mut d, 0x1210, 0x2); // flags = diamond_shaped
    put_u32(&mut d, 0x1214, 2); // base_count
    put_ptr(&mut d, 0x1218, 0x1100); // base[0].typeinfo
    put_ptr(&mut d, 0x1220, 0); // base[0].offset_flags
    put_ptr(&mut d, 0x1228, 0x1150); // base[1].typeinfo
    put_ptr(&mut d, 0x1230, 8); // base[1].offset_flags
    put_str(&mut d, 0x1280, "_ZTI4Both");

    let vtable_addr = 0x12A0u64;
    put_ptr(&mut d, vtable_addr - 8, 0x1200);

    let bv = BinaryView::new(d, BASE, vec![rodata(0x400)], 8);
    let ti = parse_itanium_typeinfo(&bv, Address(vtable_addr)).expect("parses");

    assert_eq!(ti.kind, ItaniumTypeinfoKind::MultipleInheritance);
    assert_eq!(ti.base_classes.len(), 2);
    assert_eq!(ti.base_classes[0].base_typeinfo_rva, 0x1100);
    assert_eq!(ti.base_classes[1].base_typeinfo_rva, 0x1150);
}
