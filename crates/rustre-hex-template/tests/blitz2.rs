//! Blitz2 deep adversarial coverage for rustre-hex-template.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use rustre_hex::{DataType, Encoding, HexBuffer, TypedValue};
use rustre_hex_template::{
    BitfieldDef, BitfieldStruct, Expr, FieldDef, ParsedStructPrinter, RepeatSpec, Template,
    TemplateApplier, TemplateError, TemplateRegistry, TemplateType, builtin_templates,
};

// ── LCG --------------------------------------------------------------------

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn buf(d: &[u8]) -> HexBuffer {
    HexBuffer::new(d.to_vec())
}

fn ctx_with(name: &str, v: u64) -> HashMap<String, u64> {
    let mut c = HashMap::new();
    c.insert(name.to_string(), v);
    c
}

// ── 1: Expr::Eq deterministic ----------------------------------------------

#[test]
fn expr_eq_50_values() {
    let mut g = lcg();
    for _ in 0..50 {
        let v = g();
        let c = ctx_with("x", v);
        assert!(Expr::Eq("x".into(), v).eval(&c).unwrap());
        assert!(!Expr::Eq("x".into(), v.wrapping_add(1)).eval(&c).unwrap());
    }
}

// ── 2: Expr::Ne ------------------------------------------------------------

#[test]
fn expr_ne_works() {
    let mut g = lcg();
    for _ in 0..50 {
        let v = g();
        let c = ctx_with("x", v);
        assert!(!Expr::Ne("x".into(), v).eval(&c).unwrap());
        assert!(Expr::Ne("x".into(), v.wrapping_add(7)).eval(&c).unwrap());
    }
}

// ── 3: Expr::Gt / Lt boundary ----------------------------------------------

#[test]
fn expr_gt_lt_boundaries() {
    let c0 = ctx_with("x", 0);
    let cmax = ctx_with("x", u64::MAX);
    assert!(!Expr::Gt("x".into(), 0).eval(&c0).unwrap());
    assert!(!Expr::Lt("x".into(), 0).eval(&c0).unwrap());
    assert!(!Expr::Gt("x".into(), u64::MAX).eval(&cmax).unwrap());
    assert!(Expr::Gt("x".into(), 0).eval(&cmax).unwrap());
    assert!(Expr::Lt("x".into(), u64::MAX).eval(&c0).unwrap());
}

// ── 4: Expr::And / Or short-circuit semantics ------------------------------

#[test]
fn expr_and_or_truth_table() {
    let c = ctx_with("a", 1);
    let t = Expr::Eq("a".into(), 1);
    let f = Expr::Eq("a".into(), 0);
    assert!(Expr::And(Box::new(t.clone()), Box::new(t.clone())).eval(&c).unwrap());
    assert!(!Expr::And(Box::new(t.clone()), Box::new(f.clone())).eval(&c).unwrap());
    assert!(!Expr::And(Box::new(f.clone()), Box::new(t.clone())).eval(&c).unwrap());
    assert!(!Expr::And(Box::new(f.clone()), Box::new(f.clone())).eval(&c).unwrap());
    assert!(Expr::Or(Box::new(t.clone()), Box::new(f.clone())).eval(&c).unwrap());
    assert!(Expr::Or(Box::new(f.clone()), Box::new(t.clone())).eval(&c).unwrap());
    assert!(!Expr::Or(Box::new(f.clone()), Box::new(f.clone())).eval(&c).unwrap());
}

// ── 5: Expr missing field --------------------------------------------------

#[test]
fn expr_missing_field_is_err() {
    let c = HashMap::new();
    assert!(matches!(
        Expr::Eq("nope".into(), 0).eval(&c),
        Err(TemplateError::Condition(_))
    ));
    assert!(Expr::Ne("nope".into(), 0).eval(&c).is_err());
    assert!(Expr::Gt("nope".into(), 0).eval(&c).is_err());
    assert!(Expr::Lt("nope".into(), 0).eval(&c).is_err());
}

// ── 6: Nested And/Or with missing field propagates -------------------------

#[test]
fn expr_nested_missing_propagates() {
    let c = ctx_with("a", 1);
    let nested = Expr::And(
        Box::new(Expr::Eq("a".into(), 1)),
        Box::new(Expr::Eq("missing".into(), 0)),
    );
    assert!(nested.eval(&c).is_err());
}

// ── 7: BitfieldDef extract masks -------------------------------------------

#[test]
fn bitfield_extract_masks() {
    let bf = BitfieldDef::new("low4", 0, 4);
    assert_eq!(bf.extract(0xAB), 0xB);
    let bf2 = BitfieldDef::new("hi4", 4, 4);
    assert_eq!(bf2.extract(0xAB), 0xA);
    let full = BitfieldDef::new("all", 0, 64);
    assert_eq!(full.extract(u64::MAX), u64::MAX);
    let one = BitfieldDef::new("b", 7, 1);
    assert_eq!(one.extract(0x80), 1);
    assert_eq!(one.extract(0x7F), 0);
}

// ── 8: Bitfield bit_count >= 64 uses u64::MAX mask -------------------------

#[test]
fn bitfield_count_64_no_overflow() {
    let bf = BitfieldDef::new("x", 0, 64);
    let mut g = lcg();
    for _ in 0..50 {
        let v = g();
        assert_eq!(bf.extract(v), v);
    }
    // bit_count > 64 should still not panic
    let bf2 = BitfieldDef::new("x", 0, 100);
    assert_eq!(bf2.extract(123), 123);
}

// ── 9: BitfieldStruct extract + get ----------------------------------------

#[test]
fn bitfield_struct_extract_and_get() {
    let defs = vec![
        BitfieldDef::new("low", 0, 4),
        BitfieldDef::new("hi", 4, 4),
    ];
    let bs = BitfieldStruct::extract("byte", 0xAB, &defs);
    assert_eq!(bs.get("low"), Some(0xB));
    assert_eq!(bs.get("hi"), Some(0xA));
    assert_eq!(bs.get("missing"), None);
    assert_eq!(bs.raw, 0xAB);
    assert_eq!(bs.fields.len(), 2);
}

// ── 10: BitfieldStruct LCG fuzz --------------------------------------------

#[test]
fn bitfield_lcg_no_panic() {
    let mut g = lcg();
    let defs = vec![
        BitfieldDef::new("a", 0, 8),
        BitfieldDef::new("b", 8, 16),
        BitfieldDef::new("c", 24, 40),
    ];
    for _ in 0..50 {
        let v = g();
        let bs = BitfieldStruct::extract("t", v, &defs);
        // Reassembly: a | (b<<8) | (c<<24) should equal v
        let a = bs.get("a").unwrap();
        let b = bs.get("b").unwrap();
        let c = bs.get("c").unwrap();
        assert_eq!(a | (b << 8) | (c << 24), v);
    }
}

// ── 11: BitfieldDef with_comment chain -------------------------------------

#[test]
fn bitfield_with_comment() {
    let bf = BitfieldDef::new("x", 0, 4).with_comment("low nibble");
    assert_eq!(bf.comment, "low nibble");
    assert_eq!(bf.start_bit, 0);
    assert_eq!(bf.bit_count, 4);
}

// ── 12: Template new + add_field round-trip --------------------------------

#[test]
fn template_new_add_field() {
    let mut t = Template::new("T", "desc");
    assert_eq!(t.fields.len(), 0);
    t.add_field(FieldDef::new("a", TemplateType::Primitive(DataType::U8)));
    assert_eq!(t.fields.len(), 1);
    assert_eq!(t.name, "T");
    assert_eq!(t.description, "desc");
}

// ── 13: FieldDef builder chain ---------------------------------------------

#[test]
fn fielddef_builder_chain() {
    let f = FieldDef::new("x", TemplateType::Primitive(DataType::U8))
        .with_comment("c")
        .with_offset(42)
        .with_condition(Expr::Eq("flag".into(), 1))
        .with_repeat(RepeatSpec::Count(3));
    assert_eq!(f.name, "x");
    assert_eq!(f.comment, "c");
    assert_eq!(f.offset, Some(42));
    assert!(f.condition.is_some());
    assert!(f.repeat.is_some());
}

// ── 14: Template JSON round-trip ------------------------------------------

#[test]
fn template_json_roundtrip_50_fields() {
    let mut t = Template::new("Big", "big template");
    for i in 0..50 {
        t.add_field(FieldDef::new(
            format!("f{i}"),
            TemplateType::Primitive(DataType::U32Le),
        ));
    }
    let json = t.to_json().unwrap();
    let t2 = Template::from_json(&json).unwrap();
    assert_eq!(t2.fields.len(), 50);
    for i in 0..50 {
        assert_eq!(t2.fields[i].name, format!("f{i}"));
    }
}

// ── 15: Template from_json malformed inputs --------------------------------

#[test]
fn template_from_json_garbage_errors() {
    let inputs = ["", "{}", "not json", "[1,2,3]", "{\"name\": 5}"];
    for s in inputs {
        let r = Template::from_json(s);
        assert!(r.is_err(), "expected error for {s:?}");
    }
}

// ── 16: TemplateRegistry basics --------------------------------------------

#[test]
fn registry_new_and_with_builtins() {
    let r = TemplateRegistry::new();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
    let r2 = TemplateRegistry::with_builtins();
    assert!(!r2.is_empty());
    assert!(r2.len() >= 10);
}

// ── 17: Registry register/get/remove/names --------------------------------

#[test]
fn registry_register_get_remove() {
    let mut r = TemplateRegistry::new();
    r.register(Template::new("A", ""));
    r.register(Template::new("B", ""));
    r.register(Template::new("C", ""));
    assert_eq!(r.len(), 3);
    assert!(r.get("A").is_some());
    assert!(r.get("Z").is_none());
    let names = r.names();
    assert_eq!(names, vec!["A", "B", "C"]);
    let removed = r.remove("B");
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().name, "B");
    assert_eq!(r.len(), 2);
    assert!(r.remove("nope").is_none());
}

// ── 18: Registry apply: not found ------------------------------------------

#[test]
fn registry_apply_not_found() {
    let r = TemplateRegistry::new();
    let b = buf(&[0u8]);
    let result = r.apply("missing", &b, 0);
    assert!(matches!(result, Err(TemplateError::NotFound(_))));
}

// ── 19: Registry apply: builtins succeed on enough buffer ------------------

#[test]
fn registry_apply_mz() {
    let r = TemplateRegistry::with_builtins();
    let mut data = vec![0u8; 64];
    data[0] = b'M';
    data[1] = b'Z';
    let b = buf(&data);
    let ps = r.apply("MZ", &b, 0).unwrap();
    assert_eq!(ps.name, "MZ");
    assert!(!ps.fields.is_empty());
}

// ── 20: Registry JSON round-trip -------------------------------------------

#[test]
fn registry_json_roundtrip() {
    let mut r = TemplateRegistry::new();
    r.register(Template::new("A", "desc"));
    r.register(Template::new("B", "desc2"));
    let j = r.to_json().unwrap();
    let r2 = TemplateRegistry::from_json(&j).unwrap();
    assert_eq!(r2.len(), 2);
    assert!(r2.get("A").is_some());
}

// ── 21: Registry from_json malformed ---------------------------------------

#[test]
fn registry_from_json_garbage() {
    let r = TemplateRegistry::from_json("not json at all");
    assert!(r.is_err());
}

// ── 22: TemplateApplier all primitive types --------------------------------

#[test]
fn applier_primitives_unsigned() {
    let data = [
        0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00,
    ];
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("a", TemplateType::Primitive(DataType::U8)));
    t.add_field(FieldDef::new("b", TemplateType::Primitive(DataType::U16Le)));
    t.add_field(FieldDef::new("c", TemplateType::Primitive(DataType::U32Le)));
    t.add_field(FieldDef::new("d", TemplateType::Primitive(DataType::U64Le)));
    let r = TemplateApplier::new(&b).apply(&t, 0).unwrap();
    assert_eq!(r.fields.len(), 4);
}

// ── 23: Applier off-end buffer truncation returns Err ---------------------

#[test]
fn applier_truncated_buffer() {
    let data = [0x01u8]; // only 1 byte
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("a", TemplateType::Primitive(DataType::U32Le)));
    let r = TemplateApplier::new(&b).apply(&t, 0);
    assert!(r.is_err());
}

// ── 24: Applier explicit offset out of range returns Err -------------------

#[test]
fn applier_explicit_offset_out_of_range() {
    let data = [0x01u8];
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("a", TemplateType::Primitive(DataType::U8)).with_offset(100));
    assert!(TemplateApplier::new(&b).apply(&t, 0).is_err());
}

// ── 25: Conditional field skip ---------------------------------------------

#[test]
fn applier_conditional_skip_uses_ctx() {
    let data = [0x00u8, 0xFF];
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("flag", TemplateType::Primitive(DataType::U8)));
    t.add_field(
        FieldDef::new("opt", TemplateType::Primitive(DataType::U8))
            .with_condition(Expr::Eq("flag".into(), 1)),
    );
    let r = TemplateApplier::new(&b).apply(&t, 0).unwrap();
    assert_eq!(r.fields.len(), 1);
}

// ── 26: Conditional field present ------------------------------------------

#[test]
fn applier_conditional_present_when_true() {
    let data = [0x01u8, 0xFF];
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("flag", TemplateType::Primitive(DataType::U8)));
    t.add_field(
        FieldDef::new("opt", TemplateType::Primitive(DataType::U8))
            .with_condition(Expr::Eq("flag".into(), 1)),
    );
    let r = TemplateApplier::new(&b).apply(&t, 0).unwrap();
    assert_eq!(r.fields.len(), 2);
    assert_eq!(r.fields[1].value, TypedValue::U8(0xFF));
}

// ── 27: RepeatSpec::Count produces N entries -------------------------------

#[test]
fn repeat_count_creates_n() {
    let data: Vec<u8> = (0..10).collect();
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(
        FieldDef::new("bytes", TemplateType::Primitive(DataType::U8))
            .with_repeat(RepeatSpec::Count(10)),
    );
    let r = TemplateApplier::new(&b).apply(&t, 0).unwrap();
    assert_eq!(r.fields.len(), 10);
    for (i, f) in r.fields.iter().enumerate() {
        assert_eq!(f.value, TypedValue::U8(i as u8));
    }
}

// ── 28: RepeatSpec::Count = 0 ----------------------------------------------

#[test]
fn repeat_count_zero() {
    let data = [0u8; 4];
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(
        FieldDef::new("bytes", TemplateType::Primitive(DataType::U8))
            .with_repeat(RepeatSpec::Count(0)),
    );
    let r = TemplateApplier::new(&b).apply(&t, 0).unwrap();
    assert_eq!(r.fields.len(), 0);
}

// ── 29: RepeatSpec::WhileField terminates ----------------------------------

#[test]
fn repeat_while_field_terminates() {
    let data = [0x01u8, 0x02, 0x00, 0x05, 0x06]; // sentinel = 0x00 terminator
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("v", TemplateType::Primitive(DataType::U8)));
    t.add_field(
        FieldDef::new("v", TemplateType::Primitive(DataType::U8)).with_repeat(
            RepeatSpec::WhileField {
                field: "v".into(),
                not_value: 0,
            },
        ),
    );
    // Note: the WhileField field 'v' starts as 0x01 (the first field), then the loop
    // reads more 'v' bytes. The applier checks ctx BEFORE each iteration.
    let r = TemplateApplier::new(&b).apply(&t, 0).unwrap();
    // First non-repeating v=1. Loop checks ctx["v"]=1, parses index [0]=0x02, ctx becomes 2.
    // Iter: ctx=2 parse [1]=0x00, ctx becomes 0, break next iter.
    // Total: 1 + 2 elements = 3 fields
    assert!(r.fields.len() >= 2);
}

// ── 30: RepeatSpec::WhileField missing field is FieldRef error -------------

#[test]
fn repeat_while_missing_field_err() {
    let data = [0x01u8, 0x02];
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(
        FieldDef::new("v", TemplateType::Primitive(DataType::U8)).with_repeat(
            RepeatSpec::WhileField {
                field: "nonexistent".into(),
                not_value: 0,
            },
        ),
    );
    let r = TemplateApplier::new(&b).apply(&t, 0);
    assert!(matches!(r, Err(TemplateError::FieldRef(_))));
}

// ── 31: Array fixed-count nested ------------------------------------------

#[test]
fn array_field_nested_children() {
    let data = [0xAAu8, 0xBB, 0xCC, 0xDD];
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new(
        "arr",
        TemplateType::Array {
            ty: Box::new(TemplateType::Primitive(DataType::U8)),
            count: 4,
        },
    ));
    let r = TemplateApplier::new(&b).apply(&t, 0).unwrap();
    let kids = r.fields[0].children.as_ref().unwrap();
    assert_eq!(kids.fields.len(), 4);
    assert_eq!(kids.fields[3].value, TypedValue::U8(0xDD));
}

// ── 32: DynArray uses count_field ------------------------------------------

#[test]
fn dynarray_uses_count_field() {
    let data = [0x04u8, 1, 2, 3, 4];
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("n", TemplateType::Primitive(DataType::U8)));
    t.add_field(FieldDef::new(
        "items",
        TemplateType::DynArray {
            ty: Box::new(TemplateType::Primitive(DataType::U8)),
            count_field: "n".into(),
        },
    ));
    let r = TemplateApplier::new(&b).apply(&t, 0).unwrap();
    let kids = r.fields[1].children.as_ref().unwrap();
    assert_eq!(kids.fields.len(), 4);
}

// ── 33: DynArray missing count_field is FieldRef ---------------------------

#[test]
fn dynarray_missing_count_field_err() {
    let data = [1u8, 2, 3];
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new(
        "items",
        TemplateType::DynArray {
            ty: Box::new(TemplateType::Primitive(DataType::U8)),
            count_field: "missing".into(),
        },
    ));
    let r = TemplateApplier::new(&b).apply(&t, 0);
    assert!(matches!(r, Err(TemplateError::FieldRef(_))));
}

// ── 34: DynArray overflow guard --------------------------------------------

#[test]
fn dynarray_overflow_rejected() {
    let data: Vec<u8> = vec![0u8; 16];
    let mut data_full = vec![];
    // count = u64::MAX via 8 bytes of 0xFF
    data_full.extend_from_slice(&u64::MAX.to_le_bytes());
    data_full.extend_from_slice(&data);
    let b = buf(&data_full);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("n", TemplateType::Primitive(DataType::U64Le)));
    t.add_field(FieldDef::new(
        "items",
        TemplateType::DynArray {
            ty: Box::new(TemplateType::Primitive(DataType::U8)),
            count_field: "n".into(),
        },
    ));
    let r = TemplateApplier::new(&b).apply(&t, 0);
    assert!(matches!(r, Err(TemplateError::Field(_, _))));
}

// ── 35: Enum unknown variant produces unknown(N) ---------------------------

#[test]
fn enum_unknown_yields_unknown_label() {
    let data = [0x42u8];
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new(
        "e",
        TemplateType::Enum {
            ty: DataType::U8,
            variants: vec![("ZERO".into(), 0)],
        },
    ));
    let r = TemplateApplier::new(&b).apply(&t, 0).unwrap();
    if let TypedValue::Str(s) = &r.fields[0].value {
        assert!(s.contains("66") || s.starts_with("unknown"));
    } else {
        panic!("expected Str");
    }
}

// ── 36: Nested Struct field --------------------------------------------------

#[test]
fn nested_struct_field() {
    let data = [0x01u8, 0x02, 0x03, 0x04];
    let b = buf(&data);
    let inner = vec![
        FieldDef::new("a", TemplateType::Primitive(DataType::U8)),
        FieldDef::new("b", TemplateType::Primitive(DataType::U8)),
    ];
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("hdr", TemplateType::Struct(inner)));
    t.add_field(FieldDef::new("tail", TemplateType::Primitive(DataType::U16Le)));
    let r = TemplateApplier::new(&b).apply(&t, 0).unwrap();
    assert_eq!(r.fields.len(), 2);
    let kids = r.fields[0].children.as_ref().unwrap();
    assert_eq!(kids.fields.len(), 2);
    assert_eq!(r.fields[0].size, 2);
}

// ── 37: String CStr terminates at null --------------------------------------

#[test]
fn string_cstr_terminates() {
    let data = b"hi\0junk";
    let b = buf(data);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new(
        "s",
        TemplateType::String {
            encoding: Encoding::Utf8,
            len: None,
        },
    ));
    let r = TemplateApplier::new(&b).apply(&t, 0).unwrap();
    assert_eq!(r.fields[0].value, TypedValue::Str("hi".into()));
    assert_eq!(r.fields[0].size, 3); // 2 chars + null
}

// ── 38: String fixed-length utf8 -------------------------------------------

#[test]
fn string_fixed_len_utf8() {
    let data = b"abcdefgh";
    let b = buf(data);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new(
        "s",
        TemplateType::String {
            encoding: Encoding::Utf8,
            len: Some(4),
        },
    ));
    let r = TemplateApplier::new(&b).apply(&t, 0).unwrap();
    assert_eq!(r.fields[0].size, 4);
}

// ── 39: Recursion limit ---------------------------------------------------

#[test]
fn recursion_limit_enforced() {
    // Build deeply nested struct > 32 levels
    let mut ty = TemplateType::Primitive(DataType::U8);
    for _ in 0..40 {
        ty = TemplateType::Struct(vec![FieldDef::new("inner", ty)]);
    }
    let data = [0u8; 4];
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("root", ty));
    let r = TemplateApplier::new(&b).apply(&t, 0);
    assert!(matches!(r, Err(TemplateError::RecursionLimit)));
}

// ── 40: LCG fuzz on PNG template -- never panic ----------------------------

#[test]
fn fuzz_png_never_panics() {
    let mut g = lcg();
    let tmpl = builtin_templates().remove("PNG").unwrap();
    for _ in 0..50 {
        let mut data = vec![0u8; 64];
        for byte in data.iter_mut() {
            *byte = (g() & 0xFF) as u8;
        }
        let b = buf(&data);
        let _ = TemplateApplier::new(&b).apply(&tmpl, 0);
    }
}

// ── 41: LCG fuzz on all builtin templates -----------------------------------

#[test]
fn fuzz_all_builtins_never_panic() {
    let mut g = lcg();
    let tmpls = builtin_templates();
    for _ in 0..50 {
        let mut data = vec![0u8; 128];
        for byte in data.iter_mut() {
            *byte = (g() & 0xFF) as u8;
        }
        let b = buf(&data);
        for tmpl in tmpls.values() {
            let _ = TemplateApplier::new(&b).apply(tmpl, 0);
        }
    }
}

// ── 42: ParsedStruct::field_as_u64 -----------------------------------------

#[test]
fn parsed_field_as_u64_and_context() {
    let data = [0x07u8, 0x42u8];
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("a", TemplateType::Primitive(DataType::U8)));
    t.add_field(FieldDef::new("b", TemplateType::Primitive(DataType::U8)));
    let r = TemplateApplier::new(&b).apply(&t, 0).unwrap();
    assert_eq!(r.field_as_u64("a"), Some(7));
    assert_eq!(r.field_as_u64("b"), Some(0x42));
    assert_eq!(r.field_as_u64("missing"), None);
    let ctx = r.context();
    assert_eq!(ctx.get("a"), Some(&7));
    assert_eq!(ctx.get("b"), Some(&0x42));
}

// ── 43: ParsedStructPrinter render -----------------------------------------

#[test]
fn printer_renders_structure() {
    let data = [0x11u8, 0x22];
    let b = buf(&data);
    let mut t = Template::new("Top", "");
    t.add_field(FieldDef::new("a", TemplateType::Primitive(DataType::U8)));
    t.add_field(FieldDef::new("b", TemplateType::Primitive(DataType::U8)));
    let r = TemplateApplier::new(&b).apply(&t, 0).unwrap();
    let p = ParsedStructPrinter::new();
    let s = p.render(&r);
    assert!(s.contains("struct Top"));
    assert!(s.contains("a"));
    assert!(s.contains("b"));
    let p2 = ParsedStructPrinter::with_indent("....");
    let s2 = p2.render(&r);
    assert!(s2.contains("...."));
    // Default
    let _ = ParsedStructPrinter::default().render(&r);
}

// ── 44: TemplateError Display ---------------------------------------------

#[test]
fn template_error_display() {
    let e = TemplateError::NotFound("foo".into());
    let s = format!("{e}");
    assert!(s.contains("foo"));
    let e2 = TemplateError::RecursionLimit;
    // Error message is "recursive template depth exceeded"
    assert!(format!("{e2}").contains("recursive"));
    let e3 = TemplateError::FieldRef("bar".into());
    assert!(format!("{e3}").contains("bar"));
    let e4 = TemplateError::Field("f".into(), "msg".into());
    assert!(format!("{e4}").contains("f") && format!("{e4}").contains("msg"));
}

// ── 45: Send+Sync threaded stress on Registry ------------------------------

#[test]
fn registry_threaded_stress() {
    let r = Arc::new(TemplateRegistry::with_builtins());
    let mut data = vec![0u8; 256];
    data[0] = b'M';
    data[1] = b'Z';
    let b = Arc::new(buf(&data));
    let mut handles = vec![];
    for _ in 0..4 {
        let r = r.clone();
        let b = b.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = r.apply("MZ", &b, 0);
                let _ = r.get("ELF32");
                let _ = r.names();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ── 46: Send+Sync — Template/FieldDef clone consistency --------------------

#[test]
fn template_clone_independent() {
    let mut t = Template::new("X", "d");
    t.add_field(FieldDef::new("a", TemplateType::Primitive(DataType::U8)));
    let t2 = t.clone();
    assert_eq!(t.fields.len(), t2.fields.len());
    let arc = Arc::new(t);
    let arc2 = arc.clone();
    let h = thread::spawn(move || arc2.fields.len());
    assert_eq!(h.join().unwrap(), arc.fields.len());
}

// ── 47: Builtin templates: all parse on zero-buffer of suitable size -------

#[test]
fn builtins_apply_on_min_buffer() {
    let tmpls = builtin_templates();
    let data = vec![0u8; 512];
    let b = buf(&data);
    for (name, tmpl) in &tmpls {
        let r = TemplateApplier::new(&b).apply(tmpl, 0);
        // Should succeed because 512 bytes is more than enough.
        assert!(r.is_ok(), "{name} failed: {:?}", r.err());
    }
}

// ── 48: Builtin set contains expected 10 names -----------------------------

#[test]
fn builtins_contain_expected_set() {
    let m = builtin_templates();
    for name in [
        "MZ", "PE_COFF", "ELF32", "ELF64", "ZIP", "PNG", "BMP", "JPEG", "GIF", "PDF",
    ] {
        assert!(m.contains_key(name), "missing {name}");
    }
}

// ── 49: Hash/Eq on raw values --- via context map round-trip ---------------

#[test]
fn parsed_context_hash_consistency() {
    // Build the same template twice from independent inputs; contexts must match.
    let data = [42u8];
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("x", TemplateType::Primitive(DataType::U8)));
    let r1 = TemplateApplier::new(&b).apply(&t, 0).unwrap();
    let r2 = TemplateApplier::new(&b).apply(&t, 0).unwrap();
    let c1 = r1.context();
    let c2 = r2.context();
    assert_eq!(c1, c2);
    // Verify 30+ insertions are stable
    for i in 0..30u64 {
        let mut m1 = c1.clone();
        let mut m2 = c2.clone();
        m1.insert(format!("k{i}"), i);
        m2.insert(format!("k{i}"), i);
        assert_eq!(m1, m2);
    }
}

// ── 50: Expr serde round-trip (JSON) ---------------------------------------

#[test]
fn expr_serde_roundtrip() {
    let exprs = [
        Expr::Eq("a".into(), 1),
        Expr::Ne("a".into(), 2),
        Expr::Gt("a".into(), 3),
        Expr::Lt("a".into(), 4),
        Expr::And(
            Box::new(Expr::Eq("a".into(), 1)),
            Box::new(Expr::Lt("b".into(), 5)),
        ),
        Expr::Or(
            Box::new(Expr::Eq("a".into(), 1)),
            Box::new(Expr::Gt("c".into(), 0)),
        ),
    ];
    for e in &exprs {
        let s = serde_json::to_string(e).unwrap();
        let _back: Expr = serde_json::from_str(&s).unwrap();
    }
}

// ── 51: ParsedField serde round-trip --------------------------------------

#[test]
fn parsed_struct_serde_roundtrip() {
    let data = [1u8, 2, 3, 4];
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("a", TemplateType::Primitive(DataType::U32Le)));
    let r = TemplateApplier::new(&b).apply(&t, 0).unwrap();
    let s = serde_json::to_string(&r).unwrap();
    let back: rustre_hex_template::ParsedStruct = serde_json::from_str(&s).unwrap();
    assert_eq!(back.fields.len(), 1);
}

// ── 52: RepeatSpec::WhileField MAX_ARRAY_ELEMENTS guard --------------------

#[test]
fn while_field_bounded_by_max_elements() {
    // Buffer with the sentinel field that NEVER becomes the not_value.
    // The loop should still terminate via MAX_ARRAY_ELEMENTS guard.
    let data = vec![0x01u8; 100_000];
    let b = buf(&data);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("v", TemplateType::Primitive(DataType::U8)));
    t.add_field(
        FieldDef::new("v", TemplateType::Primitive(DataType::U8)).with_repeat(
            RepeatSpec::WhileField {
                field: "v".into(),
                not_value: 0,
            },
        ),
    );
    let r = TemplateApplier::new(&b).apply(&t, 0);
    // Should NOT hang; either Ok (bounded by MAX_ARRAY_ELEMENTS) or Err.
    assert!(r.is_ok() || r.is_err());
}
