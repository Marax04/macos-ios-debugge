//! Comprehensive integration tests for `rustre-loader-pdf` public API.

use rustre_core::address::Address;
use rustre_core::arch::Architecture;
use rustre_core::endian::Endian;
use rustre_core::{Loader, LoaderInput};
use rustre_loader_pdf::{
    PdfArch, PdfDict, PdfDocument, PdfError, PdfJsExtractor, PdfLoader, PdfObjKind, PdfObject,
    PdfParser, PdfStream, PdfTrailer, PdfVersion, PdfXrefEntry, extract_streams,
    has_embedded_files, has_javascript, is_pdf, pdf_version, xref_offsets,
};

fn make_pdf(version: &str, extra: &[u8]) -> Vec<u8> {
    let mut d = format!("%PDF-{version}\n").into_bytes();
    d.extend_from_slice(extra);
    d
}

fn make_full_pdf() -> Vec<u8> {
    let mut data: Vec<u8> = b"%PDF-1.7\n".to_vec();
    data.extend_from_slice(b"1 0 obj\n<<>>\nendobj\n");
    data.extend_from_slice(b"2 0 obj\n<</Length 5>>\nstream\nhello\nendstream\nendobj\n");
    let xref_off = data.len();
    data.extend_from_slice(b"xref\n0 3\n");
    data.extend_from_slice(b"0000000000 65535 f \r\n");
    data.extend_from_slice(b"0000000009 00000 n \r\n");
    data.extend_from_slice(b"0000000029 00000 n \r\n");
    data.extend_from_slice(b"trailer\n<<\n/Size 3\n/Root 1 0 R\n>>\n");
    data.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    data
}

// ---------- is_pdf ----------

#[test]
fn is_pdf_valid_minimal() {
    assert!(is_pdf(b"%PDF-1.7"));
}

#[test]
fn is_pdf_empty() {
    assert!(!is_pdf(b""));
}

#[test]
fn is_pdf_wrong_magic_jpeg() {
    assert!(!is_pdf(&[0xFF, 0xD8, 0xFF, 0xE0]));
}

#[test]
fn is_pdf_partial_magic() {
    assert!(!is_pdf(b"%PDF"));
}

#[test]
fn is_pdf_offset_magic_fails() {
    assert!(!is_pdf(b"X%PDF-1.7"));
}

// ---------- pdf_version ----------

#[test]
fn pdf_version_17() {
    assert_eq!(pdf_version(b"%PDF-1.7\n").as_deref(), Some("1.7"));
}

#[test]
fn pdf_version_20() {
    assert_eq!(pdf_version(b"%PDF-2.0\n").as_deref(), Some("2.0"));
}

#[test]
fn pdf_version_invalid_returns_none() {
    assert!(pdf_version(b"not a pdf").is_none());
}

#[test]
fn pdf_version_empty_returns_none() {
    assert!(pdf_version(b"").is_none());
}

// ---------- has_javascript / has_embedded_files ----------

#[test]
fn has_javascript_present() {
    assert!(has_javascript(b"%PDF-1.7\n/JavaScript foo"));
}

#[test]
fn has_javascript_absent() {
    assert!(!has_javascript(b"%PDF-1.7\nclean"));
}

#[test]
fn has_embedded_files_present() {
    assert!(has_embedded_files(b"%PDF-1.7\n/EmbeddedFile"));
}

#[test]
fn has_embedded_files_absent() {
    assert!(!has_embedded_files(b"%PDF-1.7\n"));
}

// ---------- PdfVersion Display ----------

#[test]
fn pdf_version_display_format() {
    let v = PdfVersion { major: 1, minor: 4 };
    assert_eq!(v.to_string(), "PDF-1.4");
}

#[test]
fn pdf_version_eq() {
    let a = PdfVersion { major: 1, minor: 7 };
    let b = PdfVersion { major: 1, minor: 7 };
    let c = PdfVersion { major: 2, minor: 0 };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn pdf_version_copy_clone() {
    let a = PdfVersion { major: 1, minor: 7 };
    let b = a;
    assert_eq!(a, b);
}

// ---------- PdfObjKind Display ----------

#[test]
fn obj_display_boolean_true() {
    assert_eq!(PdfObjKind::Boolean(true).to_string(), "true");
}

#[test]
fn obj_display_boolean_false() {
    assert_eq!(PdfObjKind::Boolean(false).to_string(), "false");
}

#[test]
fn obj_display_integer_negative() {
    assert_eq!(PdfObjKind::Integer(-5).to_string(), "-5");
}

#[test]
fn obj_display_integer_zero() {
    assert_eq!(PdfObjKind::Integer(0).to_string(), "0");
}

#[test]
fn obj_display_integer_max() {
    assert_eq!(PdfObjKind::Integer(i64::MAX).to_string(), i64::MAX.to_string());
}

#[test]
fn obj_display_real() {
    let s = PdfObjKind::Real(2.5).to_string();
    assert!(s.contains("2.5"));
}

#[test]
fn obj_display_name() {
    assert_eq!(PdfObjKind::Name("Foo".into()).to_string(), "/Foo");
}

#[test]
fn obj_display_string() {
    assert_eq!(PdfObjKind::PdfString("hi".into()).to_string(), "(hi)");
}

#[test]
fn obj_display_array() {
    assert_eq!(PdfObjKind::Array(vec![]).to_string(), "[...]");
}

#[test]
fn obj_display_dict() {
    assert_eq!(PdfObjKind::Dictionary(vec![]).to_string(), "<<...>>");
}

#[test]
fn obj_display_null() {
    assert_eq!(PdfObjKind::Null.to_string(), "null");
}

#[test]
fn obj_display_stream() {
    let s = PdfObjKind::Stream { dict: vec![], offset: 0, length: 0 };
    assert_eq!(s.to_string(), "stream");
}

#[test]
fn obj_display_reference() {
    let r = PdfObjKind::Reference { obj: 12, generation: 0 };
    assert_eq!(r.to_string(), "12 0 R");
}

// ---------- PdfXrefEntry ----------

#[test]
fn xref_entry_eq() {
    let a = PdfXrefEntry { obj_num: 1, generation: 0, offset: 10, in_use: true };
    let b = PdfXrefEntry { obj_num: 1, generation: 0, offset: 10, in_use: true };
    assert_eq!(a, b);
}

#[test]
fn xref_entry_copy() {
    let a = PdfXrefEntry { obj_num: 1, generation: 0, offset: 0, in_use: false };
    let b = a;
    assert_eq!(a.obj_num, b.obj_num);
}

// ---------- PdfTrailer ----------

#[test]
fn trailer_construction() {
    let t = PdfTrailer { size: 3, root_ref: Some(1), info_ref: None };
    assert_eq!(t.size, 3);
    assert_eq!(t.root_ref, Some(1));
    assert!(t.info_ref.is_none());
}

// ---------- PdfDocument::parse ----------

#[test]
fn doc_parse_v17() {
    let doc = PdfDocument::parse(&make_pdf("1.7", b"")).unwrap();
    assert_eq!(doc.version, PdfVersion { major: 1, minor: 7 });
}

#[test]
fn doc_parse_v20() {
    let doc = PdfDocument::parse(&make_pdf("2.0", b"")).unwrap();
    assert_eq!(doc.version.major, 2);
    assert_eq!(doc.version.minor, 0);
}

#[test]
fn doc_parse_invalid_magic() {
    let err = PdfDocument::parse(b"not a pdf at all").unwrap_err();
    assert!(matches!(err, PdfError::InvalidMagic));
}

#[test]
fn doc_parse_empty_is_invalid_magic() {
    let err = PdfDocument::parse(b"").unwrap_err();
    assert!(matches!(err, PdfError::InvalidMagic));
}

#[test]
fn doc_parse_full_xref() {
    let doc = PdfDocument::parse(&make_full_pdf()).unwrap();
    assert!(doc.obj_count() >= 1);
    assert!(doc.trailer.size > 0);
}

#[test]
fn doc_is_encrypted_true() {
    let doc = PdfDocument::parse(&make_pdf("1.7", b"<</Encrypt 1 0 R>>")).unwrap();
    assert!(doc.is_encrypted());
}

#[test]
fn doc_is_encrypted_false() {
    let doc = PdfDocument::parse(&make_pdf("1.7", b"clean stuff")).unwrap();
    assert!(!doc.is_encrypted());
}

#[test]
fn doc_obj_count_matches_xref_len() {
    let doc = PdfDocument::parse(&make_full_pdf()).unwrap();
    assert_eq!(doc.obj_count(), doc.xref.len());
}

#[test]
fn doc_raw_preserved() {
    let data = make_pdf("1.7", b"abc");
    let doc = PdfDocument::parse(&data).unwrap();
    assert_eq!(doc.raw, data);
}

// ---------- PdfError ----------

#[test]
fn err_invalid_magic_display() {
    assert!(PdfError::InvalidMagic.to_string().contains("magic"));
}

#[test]
fn err_parse_error_display() {
    assert!(PdfError::ParseError("oops".into()).to_string().contains("oops"));
}

#[test]
fn err_xref_error_display() {
    assert!(PdfError::XrefError("bad".into()).to_string().contains("bad"));
}

#[test]
fn err_truncated_display() {
    assert!(PdfError::TruncatedData.to_string().contains("truncated"));
}

// ---------- xref_offsets ----------

#[test]
fn xref_offsets_full() {
    let data = make_full_pdf();
    let off = xref_offsets(&data);
    assert_eq!(off.len(), 2);
    assert_eq!(off[0], (1, 9));
    assert_eq!(off[1], (2, 29));
}

#[test]
fn xref_offsets_no_startxref() {
    assert!(xref_offsets(b"%PDF-1.7\nno xref").is_empty());
}

#[test]
fn xref_offsets_empty_input() {
    assert!(xref_offsets(b"").is_empty());
}

// ---------- extract_streams ----------

fn pdf_with_stream(filter: Option<&str>) -> Vec<u8> {
    let content = b"hello world";
    let dict = if let Some(f) = filter {
        format!("<</Length {}\n/Filter /{}>>\n", content.len(), f)
    } else {
        format!("<</Length {}>>\n", content.len())
    };
    let mut data: Vec<u8> = b"%PDF-1.7\n1 0 obj\n".to_vec();
    data.extend_from_slice(dict.as_bytes());
    data.extend_from_slice(b"stream\n");
    data.extend_from_slice(content);
    data.extend_from_slice(b"\nendstream\nendobj\n%%EOF\n");
    data
}

#[test]
fn extract_streams_none() {
    assert!(extract_streams(b"%PDF-1.7\nno streams").is_empty());
}

#[test]
fn extract_streams_basic() {
    let s = extract_streams(&pdf_with_stream(None));
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].object_id, 1);
    assert_eq!(s[0].length, b"hello world".len());
    assert!(s[0].filter.is_none());
}

#[test]
fn extract_streams_with_filter() {
    let s = extract_streams(&pdf_with_stream(Some("FlateDecode")));
    assert_eq!(s[0].filter.as_deref(), Some("FlateDecode"));
}

#[test]
fn pdf_stream_struct_fields() {
    let s = PdfStream { object_id: 7, offset: 100, length: 50, filter: Some("F".into()) };
    assert_eq!(s.object_id, 7);
    assert_eq!(s.offset, 100);
    assert_eq!(s.length, 50);
}

// ---------- PdfJsExtractor ----------

#[test]
fn js_extractor_default() {
    let _ = PdfJsExtractor;
    let _ = PdfJsExtractor::default();
}

#[test]
fn js_extractor_new() {
    let e = PdfJsExtractor::new();
    let r = e.extract(b"%PDF-1.7\nclean");
    assert!(r.is_empty());
}

#[test]
fn js_extractor_literal() {
    let data = b"%PDF-1.7\n1 0 obj\n<</JS (alert(1);)>>\nendobj\n%%EOF\n";
    let entries = PdfJsExtractor::new().extract(data);
    assert!(!entries.is_empty());
    assert!(entries.iter().any(|e| e.source.contains("alert(1)")));
}

#[test]
fn js_extractor_hex() {
    let mut data: Vec<u8> = b"%PDF-1.7\n1 0 obj\n<</JS <616c657274>".to_vec();
    data.extend_from_slice(b">>\nendobj\n%%EOF\n");
    let entries = PdfJsExtractor::new().extract(&data);
    assert!(!entries.is_empty());
    assert!(entries.iter().any(|e| e.source.contains("alert")));
}

#[test]
fn js_extractor_javascript_keyword() {
    let data = b"%PDF-1.7\n1 0 obj\n<</JavaScript (var x=1;)>>\nendobj\n%%EOF\n";
    let entries = PdfJsExtractor::new().extract(data);
    assert!(!entries.is_empty());
}

// ---------- PdfArch ----------

#[test]
fn arch_name() {
    assert_eq!(PdfArch.name(), "pdf");
}

#[test]
fn arch_pointer_size() {
    assert_eq!(PdfArch.pointer_size(), 8);
}

#[test]
fn arch_endian() {
    assert!(matches!(PdfArch.endian(), Endian::Little));
}

#[test]
fn arch_registers_empty() {
    assert!(PdfArch.registers().is_empty());
}

#[test]
fn arch_calling_conventions_empty() {
    assert!(PdfArch.calling_conventions().is_empty());
}

#[test]
fn arch_disassemble_one_byte() {
    let i = PdfArch.disassemble(Address::new(0), &[0xAB]).unwrap();
    assert_eq!(i.size, 1);
}

#[test]
fn arch_get_branches_empty() {
    let i = PdfArch.disassemble(Address::new(0), &[0]).unwrap();
    assert!(PdfArch.get_branches(&i).is_empty());
}

// ---------- PdfLoader ----------

#[test]
fn loader_name() {
    assert_eq!(PdfLoader.name(), "pdf");
}

#[test]
fn loader_can_load_pdf() {
    let i = LoaderInput::new("a.pdf", make_pdf("1.7", b""));
    assert!(PdfLoader.can_load(&i));
}

#[test]
fn loader_rejects_non_pdf() {
    let i = LoaderInput::new("a.bin", b"random".to_vec());
    assert!(!PdfLoader.can_load(&i));
}

#[tokio::test]
async fn loader_load_round_trip() {
    let i = LoaderInput::new("a.pdf", make_pdf("1.7", b"content"));
    let r = PdfLoader.load(i).await.unwrap();
    assert_eq!(r.view.uri, "a.pdf");
}

#[tokio::test]
async fn loader_load_empty_data() {
    let i = LoaderInput::new("a.pdf", b"%PDF-".to_vec());
    let r = PdfLoader.load(i).await.unwrap();
    assert_eq!(r.view.uri, "a.pdf");
}

#[tokio::test]
async fn loader_find_nested_empty() {
    let i = LoaderInput::new("a.pdf", make_pdf("1.7", b""));
    assert!(PdfLoader.find_nested(&i).await.unwrap().is_empty());
}

// ---------- Send/Sync ----------

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn loader_send_sync() {
    assert_send_sync::<PdfLoader>();
    assert_send_sync::<PdfArch>();
    assert_send_sync::<PdfDocument>();
    assert_send_sync::<PdfError>();
}

// ---------- PdfDict / PdfObject ----------

#[test]
fn pdf_dict_default_empty() {
    let d = PdfDict::default();
    assert!(d.is_empty());
    assert_eq!(d.len(), 0);
}

#[test]
fn pdf_dict_set_and_get() {
    let mut d = PdfDict::default();
    d.set("Type", PdfObject::Name("Catalog".into()));
    assert_eq!(d.len(), 1);
    assert!(!d.is_empty());
    assert!(d.contains_key("Type"));
    assert_eq!(d.get_name("Type"), Some("Catalog"));
}

#[test]
fn pdf_dict_set_overwrites() {
    let mut d = PdfDict::default();
    d.set("X", PdfObject::Integer(1));
    d.set("X", PdfObject::Integer(2));
    assert_eq!(d.len(), 1);
    assert_eq!(d.get_int("X"), Some(2));
}

#[test]
fn pdf_dict_get_int() {
    let mut d = PdfDict::default();
    d.set("N", PdfObject::Integer(42));
    assert_eq!(d.get_int("N"), Some(42));
    assert_eq!(d.get_int("missing"), None);
}

#[test]
fn pdf_dict_get_bool() {
    let mut d = PdfDict::default();
    d.set("B", PdfObject::Bool(true));
    assert_eq!(d.get_bool("B"), Some(true));
}

#[test]
fn pdf_dict_get_array() {
    let mut d = PdfDict::default();
    d.set("A", PdfObject::Array(vec![PdfObject::Integer(1)]));
    let a = d.get_array("A").unwrap();
    assert_eq!(a.len(), 1);
}

#[test]
fn pdf_dict_get_wrong_type_returns_none() {
    let mut d = PdfDict::default();
    d.set("X", PdfObject::Integer(1));
    assert!(d.get_name("X").is_none());
    assert!(d.get_bool("X").is_none());
    assert!(d.get_array("X").is_none());
}

#[test]
fn pdf_dict_contains_key_false() {
    let d = PdfDict::default();
    assert!(!d.contains_key("Anything"));
}

#[test]
fn pdf_object_is_null() {
    assert!(PdfObject::Null.is_null());
    assert!(!PdfObject::Integer(0).is_null());
}

#[test]
fn pdf_object_as_int() {
    assert_eq!(PdfObject::Integer(7).as_int(), Some(7));
    assert_eq!(PdfObject::Null.as_int(), None);
    assert_eq!(PdfObject::Bool(true).as_int(), None);
}

#[test]
fn pdf_object_as_str_lossy_bytes() {
    let o = PdfObject::Bytes(b"hello".to_vec());
    assert_eq!(o.as_str_lossy().as_deref(), Some("hello"));
}

#[test]
fn pdf_object_as_str_lossy_name() {
    let o = PdfObject::Name("Type".into());
    assert_eq!(o.as_str_lossy().as_deref(), Some("Type"));
}

#[test]
fn pdf_object_as_str_lossy_other() {
    assert!(PdfObject::Null.as_str_lossy().is_none());
    assert!(PdfObject::Integer(1).as_str_lossy().is_none());
}

#[test]
fn pdf_object_as_dict_from_dict() {
    let mut d = PdfDict::default();
    d.set("X", PdfObject::Integer(1));
    let o = PdfObject::Dict(d);
    assert!(o.as_dict().is_some());
    assert_eq!(o.as_dict().unwrap().len(), 1);
}

#[test]
fn pdf_object_as_dict_from_stream() {
    let o = PdfObject::Stream { dict: PdfDict::default(), data: vec![1, 2, 3] };
    assert!(o.as_dict().is_some());
}

#[test]
fn pdf_object_as_dict_other_none() {
    assert!(PdfObject::Null.as_dict().is_none());
    assert!(PdfObject::Integer(0).as_dict().is_none());
}

// ---------- PdfParser ----------

#[test]
fn parser_invalid_magic() {
    match PdfParser::parse(b"nope".to_vec()) {
        Err(PdfError::InvalidMagic) => {}
        _ => panic!("expected InvalidMagic"),
    }
}

#[test]
fn parser_truncated() {
    match PdfParser::parse(b"%PDF-".to_vec()) {
        Err(PdfError::TruncatedData) => {}
        _ => panic!("expected TruncatedData"),
    }
}

#[test]
fn parser_basic_v17() {
    let p = PdfParser::parse(make_pdf("1.7", b"  ")).unwrap();
    assert!(p.version.starts_with("1.7"));
}

#[test]
fn parser_full_doc_loads_xref() {
    let p = PdfParser::parse(make_full_pdf()).unwrap();
    assert!(!p.xref.is_empty());
    assert!(p.trailer.is_some());
}

#[test]
fn parser_get_object_resolves() {
    let p = PdfParser::parse(make_full_pdf()).unwrap();
    // Object 1 exists at offset 9.
    let obj = p.get_object(1);
    assert!(obj.is_some());
}

#[test]
fn parser_get_object_missing() {
    let p = PdfParser::parse(make_full_pdf()).unwrap();
    assert!(p.get_object(999).is_none());
}

#[test]
fn parser_resolve_non_indirect_returns_clone() {
    let p = PdfParser::parse(make_pdf("1.7", b"")).unwrap();
    let r = p.resolve(&PdfObject::Integer(5));
    assert_eq!(r.as_int(), Some(5));
}

#[test]
fn parser_resolve_indirect_missing_yields_null() {
    let p = PdfParser::parse(make_pdf("1.7", b"")).unwrap();
    let r = p.resolve(&PdfObject::Indirect(999, 0));
    assert!(r.is_null());
}
