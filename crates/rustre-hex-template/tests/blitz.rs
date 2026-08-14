//! Exhaustive tests for rustre-hex-template public API in lib.rs.

use std::collections::HashMap;

use rustre_hex::{DataType, Encoding, HexBuffer, TypedValue};
use rustre_hex_template::{
    Expr, FieldDef, ParsedStruct, RepeatSpec, Template, TemplateApplier, TemplateError,
    TemplateType, builtin_templates,
};

fn buf(bytes: Vec<u8>) -> HexBuffer {
    HexBuffer::new(bytes)
}

// ─── Expr::eval ────────────────────────────────────────────────────────────

#[test]
fn expr_eq_true() {
    let mut c = HashMap::new();
    c.insert("x".into(), 5);
    assert!(Expr::Eq("x".into(), 5).eval(&c).unwrap());
}

#[test]
fn expr_eq_false() {
    let mut c = HashMap::new();
    c.insert("x".into(), 4);
    assert!(!Expr::Eq("x".into(), 5).eval(&c).unwrap());
}

#[test]
fn expr_ne_true() {
    let mut c = HashMap::new();
    c.insert("x".into(), 1);
    assert!(Expr::Ne("x".into(), 2).eval(&c).unwrap());
}

#[test]
fn expr_gt_lt() {
    let mut c = HashMap::new();
    c.insert("x".into(), 10);
    assert!(Expr::Gt("x".into(), 5).eval(&c).unwrap());
    assert!(!Expr::Gt("x".into(), 10).eval(&c).unwrap());
    assert!(Expr::Lt("x".into(), 11).eval(&c).unwrap());
    assert!(!Expr::Lt("x".into(), 10).eval(&c).unwrap());
}

#[test]
fn expr_and_or() {
    let mut c = HashMap::new();
    c.insert("x".into(), 5);
    c.insert("y".into(), 7);
    let e = Expr::And(
        Box::new(Expr::Eq("x".into(), 5)),
        Box::new(Expr::Gt("y".into(), 6)),
    );
    assert!(e.eval(&c).unwrap());
    let e2 = Expr::Or(
        Box::new(Expr::Eq("x".into(), 999)),
        Box::new(Expr::Eq("y".into(), 7)),
    );
    assert!(e2.eval(&c).unwrap());
    let e3 = Expr::Or(
        Box::new(Expr::Eq("x".into(), 999)),
        Box::new(Expr::Eq("y".into(), 999)),
    );
    assert!(!e3.eval(&c).unwrap());
}

#[test]
fn expr_missing_field_errors() {
    let c = HashMap::new();
    let err = Expr::Eq("missing".into(), 0).eval(&c).unwrap_err();
    match err {
        TemplateError::Condition(_) => {}
        e => panic!("expected Condition, got {e:?}"),
    }
}

// ─── FieldDef builder ──────────────────────────────────────────────────────

#[test]
fn fielddef_builder_chain() {
    let f = FieldDef::new("foo", TemplateType::Primitive(DataType::U8))
        .with_comment("hi")
        .with_offset(0x10)
        .with_condition(Expr::Eq("x".into(), 1))
        .with_repeat(RepeatSpec::Count(3));
    assert_eq!(f.name, "foo");
    assert_eq!(f.comment, "hi");
    assert_eq!(f.offset, Some(0x10));
    assert!(f.condition.is_some());
    assert!(matches!(f.repeat, Some(RepeatSpec::Count(3))));
}

// ─── Template / JSON round-trip ────────────────────────────────────────────

#[test]
fn template_new_empty() {
    let t = Template::new("n", "d");
    assert_eq!(t.name, "n");
    assert_eq!(t.description, "d");
    assert!(t.fields.is_empty());
}

#[test]
fn template_add_field() {
    let mut t = Template::new("n", "d");
    t.add_field(FieldDef::new("a", TemplateType::Primitive(DataType::U8)));
    t.add_field(FieldDef::new("b", TemplateType::Primitive(DataType::U16Le)));
    assert_eq!(t.fields.len(), 2);
}

#[test]
fn template_json_roundtrip() {
    let mut t = Template::new("rt", "desc");
    t.add_field(FieldDef::new("a", TemplateType::Primitive(DataType::U32Le)));
    t.add_field(
        FieldDef::new(
            "b",
            TemplateType::Enum {
                ty: DataType::U16Le,
                variants: vec![("X".into(), 1), ("Y".into(), 2)],
            },
        )
        .with_comment("enum"),
    );
    let json = t.to_json().unwrap();
    let back = Template::from_json(&json).unwrap();
    assert_eq!(back.name, "rt");
    assert_eq!(back.fields.len(), 2);
}

#[test]
fn template_from_json_invalid() {
    let err = Template::from_json("not json").unwrap_err();
    assert!(matches!(err, TemplateError::Serde(_)));
}

// ─── builtin_templates ────────────────────────────────────────────────────

#[test]
fn builtin_templates_keys() {
    let m = builtin_templates();
    for k in [
        "MZ", "PE_COFF", "ELF32", "ELF64", "ZIP", "PNG", "BMP", "JPEG", "GIF", "PDF",
    ] {
        assert!(m.contains_key(k), "missing {k}");
    }
}

#[test]
fn builtin_mz_fields_nonempty() {
    let m = builtin_templates();
    let mz = &m["MZ"];
    assert_eq!(mz.name, "MZ");
    assert!(!mz.fields.is_empty());
}

#[test]
fn builtin_all_json_roundtrip() {
    for (k, t) in builtin_templates() {
        let s = t.to_json().unwrap_or_else(|e| panic!("{k}: {e}"));
        let back = Template::from_json(&s).unwrap_or_else(|e| panic!("{k}: {e}"));
        assert_eq!(back.name, t.name, "{k}");
    }
}

// ─── TemplateApplier: primitives ───────────────────────────────────────────

#[test]
fn applier_primitive_u8() {
    let b = buf(vec![0xAB]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("x", TemplateType::Primitive(DataType::U8)));
    let out = a.apply(&t, 0).unwrap();
    assert_eq!(out.fields.len(), 1);
    assert_eq!(out.fields[0].offset, 0);
    assert_eq!(out.fields[0].size, 1);
    assert_eq!(out.fields[0].value, TypedValue::U8(0xAB));
}

#[test]
fn applier_primitive_u16_le() {
    let b = buf(vec![0x01, 0x02]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("x", TemplateType::Primitive(DataType::U16Le)));
    let out = a.apply(&t, 0).unwrap();
    assert_eq!(out.fields[0].value, TypedValue::U16(0x0201));
    assert_eq!(out.fields[0].size, 2);
}

#[test]
fn applier_sequential_cursor() {
    let b = buf(vec![0xAA, 0x11, 0x22, 0x33, 0x44]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("a", TemplateType::Primitive(DataType::U8)));
    t.add_field(FieldDef::new("b", TemplateType::Primitive(DataType::U32Le)));
    let out = a.apply(&t, 0).unwrap();
    assert_eq!(out.fields[0].offset, 0);
    assert_eq!(out.fields[1].offset, 1);
    assert_eq!(out.fields[1].value, TypedValue::U32(0x44332211));
}

#[test]
fn applier_explicit_offset() {
    let b = buf(vec![0, 0, 0, 0, 0xEE, 0xFF]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(
        FieldDef::new("x", TemplateType::Primitive(DataType::U16Le)).with_offset(4),
    );
    let out = a.apply(&t, 0).unwrap();
    assert_eq!(out.fields[0].offset, 4);
    assert_eq!(out.fields[0].value, TypedValue::U16(0xFFEE));
}

#[test]
fn applier_short_buffer_errors() {
    let b = buf(vec![0x01]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("x", TemplateType::Primitive(DataType::U32Le)));
    let err = a.apply(&t, 0).unwrap_err();
    assert!(matches!(err, TemplateError::Field(_, _)));
}

#[test]
fn applier_base_offset_respected() {
    let b = buf(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("x", TemplateType::Primitive(DataType::U16Le)));
    let out = a.apply(&t, 2).unwrap();
    assert_eq!(out.fields[0].offset, 2);
    assert_eq!(out.fields[0].value, TypedValue::U16(0xEFBE));
}

// ─── Conditional fields ───────────────────────────────────────────────────

#[test]
fn applier_condition_skips_field() {
    let b = buf(vec![0x00, 0xAB]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("flag", TemplateType::Primitive(DataType::U8)));
    t.add_field(
        FieldDef::new("data", TemplateType::Primitive(DataType::U8))
            .with_condition(Expr::Eq("flag".into(), 1)),
    );
    let out = a.apply(&t, 0).unwrap();
    assert_eq!(out.fields.len(), 1, "data should have been skipped");
}

#[test]
fn applier_condition_includes_field() {
    let b = buf(vec![0x01, 0xAB]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("flag", TemplateType::Primitive(DataType::U8)));
    t.add_field(
        FieldDef::new("data", TemplateType::Primitive(DataType::U8))
            .with_condition(Expr::Eq("flag".into(), 1)),
    );
    let out = a.apply(&t, 0).unwrap();
    assert_eq!(out.fields.len(), 2);
    assert_eq!(out.fields[1].value, TypedValue::U8(0xAB));
}

// ─── Repeat ────────────────────────────────────────────────────────────────

#[test]
fn applier_repeat_count() {
    let b = buf(vec![1, 2, 3, 4]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(
        FieldDef::new("x", TemplateType::Primitive(DataType::U8))
            .with_repeat(RepeatSpec::Count(4)),
    );
    let out = a.apply(&t, 0).unwrap();
    assert_eq!(out.fields.len(), 4);
    assert_eq!(out.fields[3].value, TypedValue::U8(4));
}

#[test]
fn applier_repeat_count_zero() {
    let b = buf(vec![1, 2, 3]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(
        FieldDef::new("x", TemplateType::Primitive(DataType::U8))
            .with_repeat(RepeatSpec::Count(0)),
    );
    let out = a.apply(&t, 0).unwrap();
    assert_eq!(out.fields.len(), 0);
}

#[test]
fn applier_repeat_while_field_missing_field_errors() {
    let b = buf(vec![1, 2, 3]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(
        FieldDef::new("x", TemplateType::Primitive(DataType::U8)).with_repeat(
            RepeatSpec::WhileField {
                field: "nonexistent".into(),
                not_value: 0,
            },
        ),
    );
    let err = a.apply(&t, 0).unwrap_err();
    assert!(matches!(err, TemplateError::FieldRef(_)));
}

#[test]
fn applier_repeat_while_field_terminates_on_zero() {
    // sequence: 1, 2, 3, 0  — read u8s until value == 0
    let b = buf(vec![1, 2, 3, 0]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    // Seed `x` first by reading one u8, then repeat reading u8 "x" while x != 0.
    t.add_field(FieldDef::new("x", TemplateType::Primitive(DataType::U8)));
    t.add_field(
        FieldDef::new("x", TemplateType::Primitive(DataType::U8)).with_repeat(
            RepeatSpec::WhileField {
                field: "x".into(),
                not_value: 0,
            },
        ),
    );
    let out = a.apply(&t, 0).unwrap();
    // initial + 3 more iterations (reads 2,3,0) then breaks when x becomes 0
    // initial x=1 → loop reads index 1=2 (x=2), index 2=3 (x=3), index 3=0 (x=0), breaks next check
    assert!(out.fields.len() >= 2);
}

// ─── Enum ──────────────────────────────────────────────────────────────────

#[test]
fn applier_enum_known_variant() {
    let b = buf(vec![0x02, 0x00]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new(
        "e",
        TemplateType::Enum {
            ty: DataType::U16Le,
            variants: vec![("ONE".into(), 1), ("TWO".into(), 2)],
        },
    ));
    let out = a.apply(&t, 0).unwrap();
    match &out.fields[0].value {
        TypedValue::Str(s) => assert_eq!(s, "TWO"),
        v => panic!("expected Str, got {v:?}"),
    }
    assert_eq!(out.fields[0].size, 2);
}

#[test]
fn applier_enum_unknown_variant() {
    let b = buf(vec![0x99, 0x00]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new(
        "e",
        TemplateType::Enum {
            ty: DataType::U16Le,
            variants: vec![("ONE".into(), 1)],
        },
    ));
    let out = a.apply(&t, 0).unwrap();
    match &out.fields[0].value {
        TypedValue::Str(s) => assert!(s.starts_with("unknown(")),
        v => panic!("got {v:?}"),
    }
}

// ─── Array / Struct / DynArray ────────────────────────────────────────────

#[test]
fn applier_fixed_array() {
    let b = buf(vec![1, 2, 3, 4]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new(
        "arr",
        TemplateType::Array {
            ty: Box::new(TemplateType::Primitive(DataType::U8)),
            count: 4,
        },
    ));
    let out = a.apply(&t, 0).unwrap();
    let kids = out.fields[0].children.as_ref().unwrap();
    assert_eq!(kids.fields.len(), 4);
    assert_eq!(kids.fields[2].value, TypedValue::U8(3));
    assert_eq!(out.fields[0].size, 4);
}

#[test]
fn applier_nested_struct() {
    let b = buf(vec![0x01, 0x02, 0x03]);
    let a = TemplateApplier::new(&b);
    let inner = vec![
        FieldDef::new("a", TemplateType::Primitive(DataType::U8)),
        FieldDef::new("b", TemplateType::Primitive(DataType::U8)),
    ];
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("hdr", TemplateType::Struct(inner)));
    t.add_field(FieldDef::new("tail", TemplateType::Primitive(DataType::U8)));
    let out = a.apply(&t, 0).unwrap();
    let kids = out.fields[0].children.as_ref().unwrap();
    assert_eq!(kids.fields.len(), 2);
    assert_eq!(out.fields[0].size, 2);
    assert_eq!(out.fields[1].offset, 2);
    assert_eq!(out.fields[1].value, TypedValue::U8(0x03));
}

#[test]
fn applier_dyn_array_uses_ctx() {
    let b = buf(vec![0x03, 0x0A, 0x0B, 0x0C]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("n", TemplateType::Primitive(DataType::U8)));
    t.add_field(FieldDef::new(
        "items",
        TemplateType::DynArray {
            ty: Box::new(TemplateType::Primitive(DataType::U8)),
            count_field: "n".into(),
        },
    ));
    let out = a.apply(&t, 0).unwrap();
    let kids = out.fields[1].children.as_ref().unwrap();
    assert_eq!(kids.fields.len(), 3);
    assert_eq!(kids.fields[2].value, TypedValue::U8(0x0C));
}

#[test]
fn applier_dyn_array_missing_count_field_errors() {
    let b = buf(vec![0; 4]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new(
        "items",
        TemplateType::DynArray {
            ty: Box::new(TemplateType::Primitive(DataType::U8)),
            count_field: "n".into(),
        },
    ));
    let err = a.apply(&t, 0).unwrap_err();
    assert!(matches!(err, TemplateError::FieldRef(_)));
}

#[test]
fn applier_dyn_array_oversize_count_errors() {
    // count is 100_000 — exceeds MAX_ARRAY_ELEMENTS (65536)
    let mut data = vec![0xA0, 0x86, 0x01, 0x00]; // 100_000 LE u32
    data.extend(vec![0; 16]);
    let b = buf(data);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("n", TemplateType::Primitive(DataType::U32Le)));
    t.add_field(FieldDef::new(
        "items",
        TemplateType::DynArray {
            ty: Box::new(TemplateType::Primitive(DataType::U8)),
            count_field: "n".into(),
        },
    ));
    let err = a.apply(&t, 0).unwrap_err();
    match err {
        TemplateError::Field(_, msg) => assert!(msg.contains("exceeds maximum")),
        e => panic!("expected Field, got {e:?}"),
    }
}

// ─── String types ──────────────────────────────────────────────────────────

#[test]
fn applier_cstring_null_terminated() {
    let b = buf(b"hi\0rest".to_vec());
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new(
        "s",
        TemplateType::String {
            encoding: Encoding::Utf8,
            len: None,
        },
    ));
    let out = a.apply(&t, 0).unwrap();
    match &out.fields[0].value {
        TypedValue::Str(s) => assert_eq!(s, "hi"),
        v => panic!("{v:?}"),
    }
    assert_eq!(out.fields[0].size, 3); // "hi" + nul
}

#[test]
fn applier_fixed_bytes_string() {
    let b = buf(b"abcdef".to_vec());
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new(
        "s",
        TemplateType::String {
            encoding: Encoding::Ascii,
            len: Some(4),
        },
    ));
    let out = a.apply(&t, 0).unwrap();
    assert_eq!(out.fields[0].size, 4);
}

// ─── ParsedStruct helpers ─────────────────────────────────────────────────

#[test]
fn parsedstruct_field_as_u64_and_context() {
    let b = buf(vec![0x05, 0x00, 0x00, 0x00, 0xAB]);
    let a = TemplateApplier::new(&b);
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("n", TemplateType::Primitive(DataType::U32Le)));
    t.add_field(FieldDef::new("x", TemplateType::Primitive(DataType::U8)));
    let out = a.apply(&t, 0).unwrap();
    assert_eq!(out.field_as_u64("n"), Some(5));
    assert_eq!(out.field_as_u64("x"), Some(0xAB));
    assert_eq!(out.field_as_u64("missing"), None);
    let ctx = out.context();
    assert_eq!(ctx.get("n"), Some(&5));
    assert_eq!(ctx.get("x"), Some(&0xAB));
}

#[test]
fn parsedstruct_default() {
    let ps = ParsedStruct::default();
    assert!(ps.name.is_empty());
    assert!(ps.fields.is_empty());
    assert_eq!(ps.field_as_u64("anything"), None);
    assert!(ps.context().is_empty());
}

// ─── Recursion limit ──────────────────────────────────────────────────────

#[test]
fn applier_recursion_limit_triggers() {
    // Build deeply nested struct > MAX_RECURSION (32)
    let mut inner = TemplateType::Primitive(DataType::U8);
    for _ in 0..40 {
        inner = TemplateType::Struct(vec![FieldDef::new("n", inner)]);
    }
    let mut t = Template::new("T", "");
    t.add_field(FieldDef::new("root", inner));
    let b = buf(vec![0; 8]);
    let a = TemplateApplier::new(&b);
    let err = a.apply(&t, 0).unwrap_err();
    assert!(matches!(err, TemplateError::RecursionLimit));
}

// ─── Builtins exercised against real-ish headers ──────────────────────────

#[test]
fn apply_png_template_on_synthetic_header() {
    // 8-byte PNG sig + 4 length + 4 type "IHDR" + 13 bytes IHDR + 4 CRC = 33 bytes
    let mut data = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n'];
    data.extend_from_slice(&13u32.to_be_bytes());
    data.extend_from_slice(b"IHDR");
    data.extend_from_slice(&100u32.to_be_bytes()); // Width
    data.extend_from_slice(&50u32.to_be_bytes()); // Height
    data.extend_from_slice(&[8, 2, 0, 0, 0]); // bit/color/comp/filter/interlace
    data.extend_from_slice(&0u32.to_be_bytes()); // CRC
    let b = buf(data);
    let a = TemplateApplier::new(&b);
    let t = &builtin_templates()["PNG"];
    let out = a.apply(t, 0).unwrap();
    assert_eq!(out.field_as_u64("Width"), Some(100));
    assert_eq!(out.field_as_u64("Height"), Some(50));
    assert_eq!(out.field_as_u64("BitDepth"), Some(8));
}

#[test]
fn apply_mz_template_on_synthetic_header() {
    let mut data = b"MZ".to_vec();
    data.extend(vec![0; 62]); // total 64 bytes for full MZ
    let b = buf(data);
    let a = TemplateApplier::new(&b);
    let t = &builtin_templates()["MZ"];
    let out = a.apply(t, 0).unwrap();
    // First field is "e_magic"
    assert_eq!(out.fields[0].name, "e_magic");
    assert_eq!(out.fields[0].size, 2);
}

// ─── Error trait / Display ────────────────────────────────────────────────

#[test]
fn template_error_display() {
    let e = TemplateError::NotFound("x".into());
    assert_eq!(format!("{e}"), "template 'x' not found");
    let e = TemplateError::RecursionLimit;
    assert!(format!("{e}").to_lowercase().contains("recurs"));
    let e = TemplateError::FieldRef("y".into());
    assert!(format!("{e}").contains("'y'"));
}
