//! Deep adversarial tests for `rustre_mcp_tools::tool_schema`.

use rustre_mcp_tools::tool_schema::*;
use serde_json::json;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ---- LCG ----
fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        s
    }
}

// ---- SchemaType ----
#[test]
fn schema_type_as_str_all() {
    let pairs = [
        (SchemaType::String, "string"),
        (SchemaType::Number, "number"),
        (SchemaType::Integer, "integer"),
        (SchemaType::Boolean, "boolean"),
        (SchemaType::Array, "array"),
        (SchemaType::Object, "object"),
        (SchemaType::Null, "null"),
    ];
    for (t, s) in pairs {
        assert_eq!(t.as_str(), s);
        assert_eq!(t.to_string(), s);
    }
}

#[test]
fn schema_type_matches_value() {
    assert!(SchemaType::String.matches_value(&json!("x")));
    assert!(!SchemaType::String.matches_value(&json!(1)));
    assert!(SchemaType::Integer.matches_value(&json!(1)));
    assert!(SchemaType::Integer.matches_value(&json!(u64::MAX)));
    assert!(!SchemaType::Integer.matches_value(&json!(1.5)));
    assert!(SchemaType::Number.matches_value(&json!(1.5)));
    assert!(SchemaType::Number.matches_value(&json!(1)));
    assert!(SchemaType::Boolean.matches_value(&json!(true)));
    assert!(SchemaType::Array.matches_value(&json!([])));
    assert!(SchemaType::Object.matches_value(&json!({})));
    assert!(SchemaType::Null.matches_value(&json!(null)));
    assert!(!SchemaType::Null.matches_value(&json!(0)));
}

#[test]
fn schema_type_serde_roundtrip() {
    for t in [SchemaType::String, SchemaType::Number, SchemaType::Integer,
              SchemaType::Boolean, SchemaType::Array, SchemaType::Object, SchemaType::Null] {
        let s = serde_json::to_string(&t).unwrap();
        let back: SchemaType = serde_json::from_str(&s).unwrap();
        assert_eq!(back, t);
    }
}

#[test]
fn schema_type_hash_eq_consistency() {
    let variants = [SchemaType::String, SchemaType::Number, SchemaType::Integer,
                    SchemaType::Boolean, SchemaType::Array, SchemaType::Object, SchemaType::Null];
    for a in &variants {
        for b in &variants {
            let mut h1 = DefaultHasher::new();
            let mut h2 = DefaultHasher::new();
            a.hash(&mut h1);
            b.hash(&mut h2);
            if a == b {
                assert_eq!(h1.finish(), h2.finish());
            }
        }
    }
}

// ---- SchemaProperty constructors ----
#[test]
fn property_constructors() {
    assert_eq!(SchemaProperty::string("d").schema_type, SchemaType::String);
    assert_eq!(SchemaProperty::integer("d").schema_type, SchemaType::Integer);
    assert_eq!(SchemaProperty::number("d").schema_type, SchemaType::Number);
    assert_eq!(SchemaProperty::boolean("d").schema_type, SchemaType::Boolean);
    assert_eq!(SchemaProperty::object("d").schema_type, SchemaType::Object);
    let a = SchemaProperty::array("d", SchemaProperty::integer("e"));
    assert_eq!(a.schema_type, SchemaType::Array);
    assert!(a.items.is_some());
}

#[test]
fn property_empty_description_skipped_in_json() {
    let p = SchemaProperty::string("");
    let j = p.to_json();
    assert!(j.get("description").is_none());
}

#[test]
fn property_with_all_modifiers() {
    let p = SchemaProperty::integer("port")
        .with_default(json!(8080))
        .with_minimum(1.0)
        .with_maximum(65535.0)
        .with_pattern("\\d+")
        .with_enum(vec![json!(80), json!(443)])
        .with_format("port")
        .with_example(json!(443));
    let j = p.to_json();
    assert_eq!(j["default"], 8080);
    assert_eq!(j["minimum"], 1.0);
    assert_eq!(j["maximum"], 65535.0);
    assert_eq!(j["pattern"], "\\d+");
    assert!(j["enum"].is_array());
    assert_eq!(j["format"], "port");
    assert_eq!(j["example"], 443);
}

#[test]
fn property_to_json_no_optional_fields() {
    let p = SchemaProperty::boolean("flag");
    let j = p.to_json();
    assert_eq!(j["type"], "boolean");
    for k in ["default", "minimum", "maximum", "minLength", "maxLength",
              "pattern", "enum", "items", "format", "example"] {
        assert!(j.get(k).is_none(), "expected no '{k}'");
    }
}

#[test]
fn array_property_nested_items() {
    let inner = SchemaProperty::string("s");
    let outer = SchemaProperty::array("a", SchemaProperty::array("b", inner));
    let j = outer.to_json();
    assert_eq!(j["type"], "array");
    assert_eq!(j["items"]["type"], "array");
    assert_eq!(j["items"]["items"]["type"], "string");
}

#[test]
fn property_serde_roundtrip() {
    let p = SchemaProperty::integer("count").with_default(json!(5)).with_minimum(0.0);
    let s = serde_json::to_string(&p).unwrap();
    let back: SchemaProperty = serde_json::from_str(&s).unwrap();
    assert_eq!(back.schema_type, SchemaType::Integer);
    assert_eq!(back.description, "count");
    assert_eq!(back.default, Some(json!(5)));
    assert_eq!(back.minimum, Some(0.0));
}

// ---- ToolParameterSchema ----
#[test]
fn schema_new_and_default_equal() {
    let a = ToolParameterSchema::new();
    let b = ToolParameterSchema::default();
    assert_eq!(a.schema_type, b.schema_type);
    assert_eq!(a.required, b.required);
    assert_eq!(a.additional_properties, b.additional_properties);
}

#[test]
fn schema_with_required_and_optional() {
    let s = ToolParameterSchema::new()
        .with_required("a", SchemaProperty::string("a"))
        .with_optional("b", SchemaProperty::integer("b"));
    assert!(s.required.contains(&"a".to_string()));
    assert!(!s.required.contains(&"b".to_string()));
    assert_eq!(s.properties.len(), 2);
}

#[test]
fn schema_allow_additional() {
    let s = ToolParameterSchema::new().allow_additional();
    assert!(s.additional_properties);
}

#[test]
fn schema_to_json_required_omitted_when_empty() {
    let s = ToolParameterSchema::new();
    let j = s.to_json();
    assert!(j.get("required").is_none());
    assert_eq!(j["type"], "object");
    assert_eq!(j["additionalProperties"], false);
}

#[test]
fn schema_to_json_with_description() {
    let mut s = ToolParameterSchema::new();
    s.description = Some("desc".to_string());
    let j = s.to_json();
    assert_eq!(j["description"], "desc");
}

// ---- validate() ----
#[test]
fn validate_non_object_root() {
    let s = ToolParameterSchema::new();
    for v in [json!(1), json!("x"), json!([]), json!(null), json!(true)] {
        let errs = validate(&s, &v);
        assert_eq!(errs.len(), 1);
        assert!(matches!(errs[0], SchemaValidationError::WrongType { .. }));
    }
}

#[test]
fn validate_empty_object_against_empty_schema() {
    let s = ToolParameterSchema::new();
    let errs = validate(&s, &json!({}));
    assert!(errs.is_empty());
}

#[test]
fn validate_missing_multiple_required() {
    let s = ToolParameterSchema::new()
        .with_required("a", SchemaProperty::string("a"))
        .with_required("b", SchemaProperty::integer("b"));
    let errs = validate(&s, &json!({}));
    assert_eq!(errs.len(), 2);
    for e in &errs {
        assert!(matches!(e, SchemaValidationError::MissingRequired(_)));
    }
}

#[test]
fn validate_wrong_types_each() {
    let cases: &[(SchemaProperty, serde_json::Value)] = &[
        (SchemaProperty::string("s"), json!(1)),
        (SchemaProperty::integer("i"), json!("x")),
        (SchemaProperty::integer("i"), json!(1.5)),
        (SchemaProperty::number("n"), json!("x")),
        (SchemaProperty::boolean("b"), json!(1)),
        (SchemaProperty::array("a", SchemaProperty::string("e")), json!("x")),
        (SchemaProperty::object("o"), json!([])),
    ];
    for (p, v) in cases {
        let s = ToolParameterSchema::new().with_required("f", p.clone());
        let errs = validate(&s, &json!({"f": v}));
        assert!(errs.iter().any(|e| matches!(e, SchemaValidationError::WrongType { .. })),
                "expected WrongType for {v}");
    }
}

#[test]
fn validate_integer_accepts_u64_max() {
    let s = ToolParameterSchema::new().with_required("n", SchemaProperty::integer("n"));
    let errs = validate(&s, &json!({"n": u64::MAX}));
    assert!(errs.is_empty(), "{errs:?}");
}

#[test]
fn validate_number_accepts_integer_value() {
    let s = ToolParameterSchema::new().with_required("n", SchemaProperty::number("n"));
    let errs = validate(&s, &json!({"n": 1}));
    assert!(errs.is_empty());
}

#[test]
fn validate_min_boundary_inclusive() {
    let s = ToolParameterSchema::new().with_required(
        "v", SchemaProperty::integer("v").with_minimum(10.0));
    assert!(validate(&s, &json!({"v": 10})).is_empty());
    assert!(!validate(&s, &json!({"v": 9})).is_empty());
}

#[test]
fn validate_max_boundary_inclusive() {
    let s = ToolParameterSchema::new().with_required(
        "v", SchemaProperty::integer("v").with_maximum(10.0));
    assert!(validate(&s, &json!({"v": 10})).is_empty());
    assert!(!validate(&s, &json!({"v": 11})).is_empty());
}

#[test]
fn validate_zero_boundary() {
    let s = ToolParameterSchema::new().with_required(
        "v", SchemaProperty::integer("v").with_minimum(0.0).with_maximum(0.0));
    assert!(validate(&s, &json!({"v": 0})).is_empty());
    assert!(!validate(&s, &json!({"v": 1})).is_empty());
    assert!(!validate(&s, &json!({"v": -1})).is_empty());
}

#[test]
fn validate_additional_property_when_disallowed() {
    let s = ToolParameterSchema::new().with_required("x", SchemaProperty::integer("x"));
    let errs = validate(&s, &json!({"x": 1, "y": 2}));
    assert!(errs.iter().any(|e| matches!(e, SchemaValidationError::AdditionalProperty(_))));
}

#[test]
fn validate_additional_property_allowed() {
    let s = ToolParameterSchema::new()
        .with_required("x", SchemaProperty::integer("x"))
        .allow_additional();
    let errs = validate(&s, &json!({"x": 1, "y": 2}));
    assert!(errs.is_empty());
}

#[test]
fn validate_enum_match_and_mismatch() {
    let p = SchemaProperty::string("m").with_enum(vec![json!("a"), json!("b")]);
    let s = ToolParameterSchema::new().with_required("m", p);
    assert!(validate(&s, &json!({"m": "a"})).is_empty());
    let errs = validate(&s, &json!({"m": "c"}));
    assert!(errs.iter().any(|e| matches!(e, SchemaValidationError::NotInEnum { .. })));
}

#[test]
fn validate_lcg_fuzz_never_panics() {
    let mut g = lcg();
    let schema = disassemble_at_schema();
    for _ in 0..200 {
        let v = match g() % 6 {
            0 => json!(g() as i64),
            1 => json!(format!("{}", g())),
            2 => json!({"address": g() as i64, "count": (g() % 2000) as i64}),
            3 => json!({"address": g().to_string()}),
            4 => json!({"address": g() as i64, "arch": "x86"}),
            _ => json!({"unknown_field": g() as i64}),
        };
        // Must not panic — returns errors or empty.
        let _ = validate(&schema, &v);
    }
}

// ---- rust_type_to_schema_type ----
#[test]
fn rust_type_all_integers() {
    for t in ["u8","u16","u32","u64","u128","usize","i8","i16","i32","i64","i128","isize"] {
        assert_eq!(rust_type_to_schema_type(t), SchemaType::Integer, "{t}");
    }
}

#[test]
fn rust_type_floats_and_bool_string() {
    assert_eq!(rust_type_to_schema_type("f32"), SchemaType::Number);
    assert_eq!(rust_type_to_schema_type("f64"), SchemaType::Number);
    assert_eq!(rust_type_to_schema_type("bool"), SchemaType::Boolean);
    assert_eq!(rust_type_to_schema_type("String"), SchemaType::String);
    assert_eq!(rust_type_to_schema_type("&str"), SchemaType::String);
    assert_eq!(rust_type_to_schema_type("&'static str"), SchemaType::String);
}

#[test]
fn rust_type_arrays_and_maps() {
    assert_eq!(rust_type_to_schema_type("Vec<u8>"), SchemaType::Array);
    assert_eq!(rust_type_to_schema_type("Vec<String>"), SchemaType::Array);
    assert_eq!(rust_type_to_schema_type("[u8; 32]"), SchemaType::Array);
    assert_eq!(rust_type_to_schema_type("HashMap<String, u64>"), SchemaType::Object);
    assert_eq!(rust_type_to_schema_type("BTreeMap<u32, u32>"), SchemaType::Object);
}

#[test]
fn rust_type_trimmed() {
    assert_eq!(rust_type_to_schema_type("  u64  "), SchemaType::Integer);
    assert_eq!(rust_type_to_schema_type("\tbool\n"), SchemaType::Boolean);
}

#[test]
fn rust_type_unknown_falls_back_object() {
    assert_eq!(rust_type_to_schema_type("CustomFoo"), SchemaType::Object);
    assert_eq!(rust_type_to_schema_type(""), SchemaType::Object);
}

// ---- FieldDescriptor ----
#[test]
fn field_descriptor_required_optional() {
    let r = FieldDescriptor::required("a", "u64", "d");
    assert!(r.required);
    let o = FieldDescriptor::optional("a", "u64", "d");
    assert!(!o.required);
}

#[test]
fn field_descriptor_vec_items_inferred() {
    let f = FieldDescriptor::required("xs", "Vec<u32>", "list");
    let p = f.to_property();
    assert_eq!(p.schema_type, SchemaType::Array);
    let items = p.items.expect("items present");
    assert_eq!(items.schema_type, SchemaType::Integer);
}

#[test]
fn field_descriptor_no_items_for_non_vec() {
    let f = FieldDescriptor::required("n", "u32", "n");
    let p = f.to_property();
    assert!(p.items.is_none());
}

// ---- SchemaBuilder ----
#[test]
fn schema_builder_chains() {
    let s = SchemaBuilder::new()
        .req_string("name", "n")
        .req_integer("count", "c")
        .opt_string("filter", "f", "")
        .opt_bool("verbose", "v", false)
        .opt_integer("limit", "l", 100)
        .bounded_integer("port", "p", 1.0, 65535.0, true)
        .enum_field("mode", "m", vec!["a", "b"], false)
        .build();
    assert!(s.required.contains(&"name".to_string()));
    assert!(s.required.contains(&"count".to_string()));
    assert!(s.required.contains(&"port".to_string()));
    assert!(!s.required.contains(&"filter".to_string()));
    assert!(!s.required.contains(&"verbose".to_string()));
    assert!(!s.required.contains(&"mode".to_string()));
    assert_eq!(s.properties.len(), 7);
}

#[test]
fn schema_builder_from_fields_required_and_optional() {
    let fields = vec![
        FieldDescriptor::required("a", "String", "a"),
        FieldDescriptor::optional("b", "u32", "b"),
        FieldDescriptor::optional("c", "Vec<u8>", "c"),
    ];
    let s = SchemaBuilder::from_fields(fields);
    assert_eq!(s.required, vec!["a".to_string()]);
    assert_eq!(s.properties.len(), 3);
    assert_eq!(s.properties["c"].schema_type, SchemaType::Array);
}

// ---- Common schemas ----
#[test]
fn disassemble_at_schema_shape() {
    let s = disassemble_at_schema();
    assert!(s.required.contains(&"address".to_string()));
    assert!(s.properties.contains_key("count"));
    assert!(s.properties.contains_key("arch"));
}

#[test]
fn get_function_schema_shape() {
    let s = get_function_schema();
    assert!(s.required.contains(&"name".to_string()));
    assert!(s.properties.contains_key("decompile"));
    assert!(s.properties.contains_key("disassemble"));
}

#[test]
fn list_functions_schema_no_required() {
    let s = list_functions_schema();
    assert!(s.required.is_empty());
    assert_eq!(s.properties.len(), 3);
}

#[test]
fn search_string_schema_required_pattern() {
    let s = search_string_schema();
    assert_eq!(s.required, vec!["pattern".to_string()]);
}

#[test]
fn compute_hash_schema_enum_present() {
    let s = compute_hash_schema();
    assert!(s.required.contains(&"data".to_string()));
    let alg = s.properties.get("algorithm").expect("algorithm");
    assert!(!alg.enum_values.is_empty());
    assert!(alg.enum_values.contains(&json!("md5")));
    assert!(alg.enum_values.contains(&json!("sha256")));
}

#[test]
fn get_section_schema_shape() {
    let s = get_section_schema();
    assert!(s.required.contains(&"name".to_string()));
    assert!(s.properties.contains_key("include_data"));
}

#[test]
fn compute_hash_validate_good_and_bad() {
    let s = compute_hash_schema();
    assert!(validate(&s, &json!({"data": "deadbeef"})).is_empty());
    assert!(validate(&s, &json!({"data": "x", "algorithm": "md5"})).is_empty());
    let errs = validate(&s, &json!({"data": "x", "algorithm": "rot13"}));
    assert!(errs.iter().any(|e| matches!(e, SchemaValidationError::NotInEnum { .. })));
    let errs = validate(&s, &json!({}));
    assert!(errs.iter().any(|e| matches!(e, SchemaValidationError::MissingRequired(s) if s == "data")));
}

#[test]
fn disassemble_at_validate_bounds() {
    let s = disassemble_at_schema();
    let errs = validate(&s, &json!({"address": 0, "count": 0}));
    assert!(errs.iter().any(|e| matches!(e, SchemaValidationError::BelowMinimum { .. })));
    let errs = validate(&s, &json!({"address": 0, "count": 1001}));
    assert!(errs.iter().any(|e| matches!(e, SchemaValidationError::ExceedsMaximum { .. })));
    assert!(validate(&s, &json!({"address": 0, "count": 1})).is_empty());
    assert!(validate(&s, &json!({"address": 0, "count": 1000})).is_empty());
}

// ---- Send + Sync threaded ----
#[test]
fn schema_send_sync_threaded() {
    use std::sync::Arc;
    use std::thread;
    let s = Arc::new(disassemble_at_schema());
    let mut handles = Vec::new();
    for tid in 0..4 {
        let s = Arc::clone(&s);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let v = json!({"address": (tid * 1000 + i) as i64, "count": 1});
                let errs = validate(&s, &v);
                assert!(errs.is_empty(), "tid={tid} i={i} errs={errs:?}");
                let _ = s.to_json();
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn validation_error_display_nonempty() {
    let errs = vec![
        SchemaValidationError::MissingRequired("x".into()),
        SchemaValidationError::WrongType { field: "x".into(), expected: "int".into(), got: "str".into() },
        SchemaValidationError::BelowMinimum { field: "x".into(), value: 0.0, min: 1.0 },
        SchemaValidationError::ExceedsMaximum { field: "x".into(), value: 10.0, max: 5.0 },
        SchemaValidationError::TooShort { field: "x".into(), len: 0, min_len: 1 },
        SchemaValidationError::TooLong { field: "x".into(), len: 10, max_len: 5 },
        SchemaValidationError::NotInEnum { field: "x".into() },
        SchemaValidationError::AdditionalProperty("x".into()),
    ];
    for e in errs {
        let s = format!("{e}");
        assert!(!s.is_empty());
    }
}

#[test]
fn schema_clone_independent() {
    let a = ToolParameterSchema::new().with_required("x", SchemaProperty::integer("x"));
    let mut b = a.clone();
    b.required.push("y".to_string());
    assert_ne!(a.required.len(), b.required.len());
}
