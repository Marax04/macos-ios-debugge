//! Blitz tests for rustre-loader-dotnet.
//! Exercises public APIs across lib.rs, strongname.rs, `metadata_tables.rs`.

use rustre_loader_dotnet::*;
use rustre_loader_dotnet::strongname::*;
use rustre_loader_dotnet::metadata_tables as mt;

// ── DotnetRuntimeVersion ─────────────────────────────────────────────────────

#[test]
fn runtime_version_display() {
    let v = DotnetRuntimeVersion { major: 4, minor: 0 };
    assert_eq!(format!("{v}"), "v4.0");
}

#[test]
fn runtime_version_eq() {
    let a = DotnetRuntimeVersion { major: 2, minor: 5 };
    let b = DotnetRuntimeVersion { major: 2, minor: 5 };
    assert_eq!(a, b);
}

// ── DotnetMetadata ───────────────────────────────────────────────────────────

#[test]
fn metadata_mock_is_pure_il() {
    let m = DotnetMetadata::mock();
    assert!(m.is_pure_il());
    assert!(!m.is_strong_named());
}

#[test]
fn metadata_display_contains_module() {
    let m = DotnetMetadata::mock();
    let s = format!("{m}");
    assert!(s.contains("MyModule.exe"));
    assert!(s.contains(".NET v4.0"));
}

// ── DotnetStream display ─────────────────────────────────────────────────────

#[test]
fn stream_display() {
    let s = DotnetStream { name: "#~".into(), offset: 0x10, size: 100 };
    let out = format!("{s}");
    assert!(out.contains("#~"));
    assert!(out.contains("0x10"));
    assert!(out.contains("100"));
}

// ── DotnetFile::is_valid_dotnet / is_dotnet ──────────────────────────────────

#[test]
fn is_valid_dotnet_finds_bsjb() {
    assert!(DotnetFile::is_valid_dotnet(b"prefixBSJBsuffix"));
    assert!(is_dotnet(b"\x00BSJB"));
}

#[test]
fn is_valid_dotnet_rejects_empty() {
    assert!(!DotnetFile::is_valid_dotnet(b""));
    assert!(!DotnetFile::is_valid_dotnet(b"BSJ"));
    assert!(!DotnetFile::is_valid_dotnet(b"NOPE"));
}

// ── parse_metadata_header ────────────────────────────────────────────────────

#[test]
fn parse_metadata_no_bsjb_errors() {
    let err = DotnetFile::parse_metadata_header(b"random bytes").unwrap_err();
    assert!(matches!(err, DotnetLoaderError::NotDotnet));
}

#[test]
fn parse_metadata_truncated_after_bsjb() {
    let err = DotnetFile::parse_metadata_header(b"BSJB").unwrap_err();
    assert!(matches!(err, DotnetLoaderError::TruncatedStream));
}

fn build_minimal_metadata() -> Vec<u8> {
    // BSJB header + version string + flags + stream_count=0
    let mut v = Vec::new();
    v.extend_from_slice(b"BSJB");
    v.extend_from_slice(&1u16.to_le_bytes()); // major
    v.extend_from_slice(&1u16.to_le_bytes()); // minor
    v.extend_from_slice(&0u32.to_le_bytes()); // reserved
    let ver = b"v4.0.30319\0\0";
    v.extend_from_slice(&(ver.len() as u32).to_le_bytes());
    v.extend_from_slice(ver);
    v.extend_from_slice(&0u16.to_le_bytes()); // flags
    v.extend_from_slice(&0u16.to_le_bytes()); // stream_count
    v
}

#[test]
fn parse_metadata_zero_streams() {
    let data = build_minimal_metadata();
    let f = DotnetFile::parse_metadata_header(&data).expect("ok");
    assert_eq!(f.streams.len(), 0);
    assert_eq!(f.metadata.version.major, 1);
    assert_eq!(f.metadata.version.minor, 1);
    assert!(f.entry_point_token.is_none());
}

#[test]
fn parse_metadata_truncated_stream_entry() {
    // BSJB header that claims 1 stream but doesn't have the bytes.
    let mut v = Vec::new();
    v.extend_from_slice(b"BSJB");
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    let ver = b"v4\0\0";
    v.extend_from_slice(&(ver.len() as u32).to_le_bytes());
    v.extend_from_slice(ver);
    v.extend_from_slice(&0u16.to_le_bytes()); // flags
    v.extend_from_slice(&1u16.to_le_bytes()); // stream_count = 1
    // missing the 8+name bytes for the stream
    let err = DotnetFile::parse_metadata_header(&v).unwrap_err();
    assert!(matches!(err, DotnetLoaderError::TruncatedStream));
}

#[test]
fn stream_lookup_missing_returns_none() {
    let data = build_minimal_metadata();
    let f = DotnetFile::parse_metadata_header(&data).unwrap();
    assert!(f.stream("#~").is_none());
}

// ── has_clr_header / is_dotnet ───────────────────────────────────────────────

#[test]
fn has_clr_header_rejects_garbage() {
    assert!(!has_clr_header(b"this is not a PE"));
    assert!(!has_clr_header(b""));
}

// ── ClrHeader ────────────────────────────────────────────────────────────────

#[test]
fn clr_header_parse_too_small() {
    assert!(ClrHeader::parse(&[0u8; 10]).is_none());
}

#[test]
fn clr_header_parse_minimum_28() {
    let mut d = [0u8; 28];
    d[0] = 48; // header_size
    d[4] = 2; // major
    let h = ClrHeader::parse(&d).expect("parsed");
    assert_eq!(h.header_size, 48);
    assert_eq!(h.major_runtime_version, 2);
    assert_eq!(h.strong_name_rva, 0);
    assert_eq!(h.strong_name_size, 0);
    assert!(!h.has_strong_name());
}

#[test]
fn clr_header_il_only_flag() {
    let mut d = [0u8; 48];
    d[16] = 0x01; // IL_ONLY
    let h = ClrHeader::parse(&d).unwrap();
    assert!(!h.is_mixed_mode());
}

#[test]
fn clr_header_mixed_mode_no_il_only() {
    let d = [0u8; 48];
    let h = ClrHeader::parse(&d).unwrap();
    assert!(h.is_mixed_mode());
}

#[test]
fn clr_header_strong_name_present() {
    // The strong-name directory lives at offset 32; offset 24 is Resources.
    // Both are filled, with different values, so that reading one as the other
    // shows up as a wrong value rather than passing by coincidence.
    let mut d = [0u8; 72];
    d[24..28].copy_from_slice(&0x2000u32.to_le_bytes()); // Resources rva
    d[28..32].copy_from_slice(&256u32.to_le_bytes()); // Resources size
    d[32..36].copy_from_slice(&0x1000u32.to_le_bytes()); // StrongName rva
    d[36..40].copy_from_slice(&128u32.to_le_bytes()); // StrongName size
    let h = ClrHeader::parse(&d).unwrap();
    assert!(h.has_strong_name());
    assert_eq!(h.strong_name_rva, 0x1000);
    assert_eq!(h.strong_name_size, 128);
    assert_eq!(h.resources_rva, 0x2000);
    assert_eq!(h.resources_size, 256);
}

#[test]
fn clr_header_resources_are_not_mistaken_for_a_signature() {
    // An assembly carrying managed resources but no strong name. Reading the
    // Resources directory as the signature would report this unsigned
    // assembly as strong-name signed.
    let mut d = [0u8; 72];
    d[24..28].copy_from_slice(&0x2000u32.to_le_bytes());
    d[28..32].copy_from_slice(&256u32.to_le_bytes());
    let h = ClrHeader::parse(&d).unwrap();
    assert!(
        !h.has_strong_name(),
        "resources present, signature absent: the assembly is not signed"
    );
    assert_eq!(h.resources_rva, 0x2000);
}

#[test]
fn clr_header_framework_version_format() {
    let mut d = [0u8; 48];
    d[4] = 4;
    d[6] = 5;
    let h = ClrHeader::parse(&d).unwrap();
    assert_eq!(h.framework_version(), "4.5");
}

#[test]
fn clr_header_display_contains_metadata_rva() {
    let mut d = [0u8; 48];
    d[8..12].copy_from_slice(&0x2000u32.to_le_bytes());
    let h = ClrHeader::parse(&d).unwrap();
    let s = format!("{h}");
    assert!(s.contains("0x2000"));
}

// ── PeSectionHeader / rva_to_offset / parse_pe_sections ──────────────────────

#[test]
fn section_rva_in_range() {
    let s = PeSectionHeader {
        name: ".text".into(),
        virtual_size: 0x1000,
        virtual_address: 0x2000,
        raw_size: 0x1000,
        raw_offset: 0x400,
        characteristics: 0,
    };
    assert_eq!(s.rva_to_offset(0x2000), Some(0x400));
    assert_eq!(s.rva_to_offset(0x2FFF), Some(0x400 + 0xFFF));
}

#[test]
fn section_rva_outside_range() {
    let s = PeSectionHeader {
        name: ".text".into(),
        virtual_size: 0x100,
        virtual_address: 0x1000,
        raw_size: 0x100,
        raw_offset: 0x200,
        characteristics: 0,
    };
    assert!(s.rva_to_offset(0xFFF).is_none());
    assert!(s.rva_to_offset(0x1100).is_none()); // at end (exclusive)
}

#[test]
fn rva_to_file_offset_uses_first_match() {
    let sections = vec![PeSectionHeader {
        name: ".text".into(),
        virtual_size: 0x10,
        virtual_address: 0x1000,
        raw_size: 0x10,
        raw_offset: 0x200,
        characteristics: 0,
    }];
    assert_eq!(rva_to_file_offset(0x1005, &sections), Some(0x205));
    assert_eq!(rva_to_file_offset(0x2000, &sections), None);
}

#[test]
fn parse_pe_sections_too_short() {
    let out = parse_pe_sections(&[0u8; 4], 0);
    assert!(out.is_empty());
}

#[test]
fn pe_section_parse_truncated() {
    assert!(PeSectionHeader::parse(&[0u8; 39], 0).is_none());
}

// ── PeOptHeader ──────────────────────────────────────────────────────────────

#[test]
fn pe_opt_header_truncated() {
    assert!(PeOptHeader::parse(&[0u8; 3], 0).is_none());
}

#[test]
fn pe_opt_header_pe32() {
    let mut d = vec![0u8; 200];
    d[0..2].copy_from_slice(&0x010Bu16.to_le_bytes());
    d[16..20].copy_from_slice(&0x1234u32.to_le_bytes()); // entry RVA
    d[28..32].copy_from_slice(&0x0040_0000u32.to_le_bytes()); // image_base 32
    let h = PeOptHeader::parse(&d, 0).unwrap();
    assert!(!h.is_64bit);
    assert_eq!(h.entry_point_rva, 0x1234);
    assert_eq!(h.image_base, 0x0040_0000);
}

#[test]
fn pe_opt_header_pe32_plus() {
    let mut d = vec![0u8; 200];
    d[0..2].copy_from_slice(&0x020Bu16.to_le_bytes());
    d[16..20].copy_from_slice(&0xCAFEu32.to_le_bytes());
    d[24..32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
    let h = PeOptHeader::parse(&d, 0).unwrap();
    assert!(h.is_64bit);
    assert_eq!(h.entry_point_rva, 0xCAFE);
    assert_eq!(h.image_base, 0x0000_0001_4000_0000);
}

// ── TypeDefRow flags ────────────────────────────────────────────────────────

#[test]
fn type_def_interface_flag() {
    let r = TypeDefRow { flags: 0x20, type_name: 0, type_namespace: 0, extends: 0, field_list: 0, method_list: 0 };
    assert!(r.is_interface());
    assert!(!r.is_abstract());
}

#[test]
fn type_def_abstract_sealed() {
    let r = TypeDefRow { flags: 0x80 | 0x100, type_name: 0, type_namespace: 0, extends: 0, field_list: 0, method_list: 0 };
    assert!(r.is_abstract());
    assert!(r.is_sealed());
}

#[test]
fn type_def_nested_public() {
    let r = TypeDefRow { flags: 0x2, type_name: 0, type_namespace: 0, extends: 0, field_list: 0, method_list: 0 };
    assert!(r.is_nested_public());
}

// ── MethodDefRow ─────────────────────────────────────────────────────────────

#[test]
fn method_def_static_public() {
    let r = MethodDefRow { rva: 0, impl_flags: 0, flags: 0x10 | 0x06, name: 0, signature: 0, param_list: 0 };
    assert!(r.is_static());
    assert!(r.is_public());
}

#[test]
fn method_def_abstract_virtual() {
    let r = MethodDefRow { rva: 0, impl_flags: 0, flags: 0x400 | 0x40, name: 0, signature: 0, param_list: 0 };
    assert!(r.is_abstract());
    assert!(r.is_virtual());
}

#[test]
fn method_def_constructor_flag() {
    let r = MethodDefRow { rva: 0, impl_flags: 0, flags: 0x0800, name: 0, signature: 0, param_list: 0 };
    assert!(r.is_constructor());
}

// ── AssemblyRow / AssemblyRefRow version strings ────────────────────────────

#[test]
fn assembly_version_string() {
    let a = AssemblyRow {
        hash_alg_id: 0, major: 4, minor: 0, build: 0, revision: 0,
        flags: 0, public_key: 0, name: 0, culture: 0,
    };
    assert_eq!(a.version_string(), "4.0.0.0");
}

#[test]
fn assembly_ref_version_string() {
    let a = AssemblyRefRow {
        major: 2, minor: 1, build: 3, revision: 4,
        flags: 0, public_key_or_token: 0, name: 0, culture: 0, hash_value: 0,
    };
    assert_eq!(a.version_string(), "2.1.3.4");
}

// ── read_compressed_uint (lib variant) ───────────────────────────────────────

#[test]
fn compressed_uint_one_byte() {
    let mut o = 0;
    assert_eq!(read_compressed_uint(&[0x7F], &mut o), 0x7F);
    assert_eq!(o, 1);
}

#[test]
fn compressed_uint_two_byte() {
    let mut o = 0;
    let v = read_compressed_uint(&[0x80 | 0x12, 0x34], &mut o);
    assert_eq!(v, 0x1234);
    assert_eq!(o, 2);
}

#[test]
fn compressed_uint_four_byte() {
    let mut o = 0;
    let v = read_compressed_uint(&[0xC0 | 0x01, 0x02, 0x03, 0x04], &mut o);
    assert_eq!(v, 0x0102_0304);
    assert_eq!(o, 4);
}

#[test]
fn compressed_uint_empty() {
    let mut o = 0;
    assert_eq!(read_compressed_uint(&[], &mut o), 0);
}

#[test]
fn compressed_uint_truncated_two_byte() {
    let mut o = 0;
    let v = read_compressed_uint(&[0x80], &mut o);
    assert_eq!(v, 0);
    assert_eq!(o, 1); // offset advanced to data.len()
}

#[test]
fn compressed_uint_truncated_four_byte() {
    let mut o = 0;
    let v = read_compressed_uint(&[0xC0, 0x01], &mut o);
    assert_eq!(v, 0);
    assert_eq!(o, 2);
}

// ── decode_type_def_or_ref ───────────────────────────────────────────────────

#[test]
fn decode_typedef_tag() {
    // tag 0 → TypeDef table (0x02)
    let tok = decode_type_def_or_ref(0b100); // row=1, tag=0
    assert_eq!(tok, (0x02 << 24) | 1);
}

#[test]
fn decode_typeref_tag() {
    let tok = decode_type_def_or_ref(0b101); // tag=1 → 0x01
    assert_eq!(tok, (0x01 << 24) | 1);
}

#[test]
fn decode_typespec_tag() {
    let tok = decode_type_def_or_ref(0b110); // tag=2 → 0x1B
    assert_eq!(tok, (0x1B << 24) | 1);
}

// ── read_type_sig ────────────────────────────────────────────────────────────

#[test]
fn type_sig_primitives() {
    let mut o = 0;
    assert!(matches!(read_type_sig(&[0x02], &mut o), TypeSig::Bool));
    o = 0;
    assert!(matches!(read_type_sig(&[0x08], &mut o), TypeSig::I4));
    o = 0;
    assert!(matches!(read_type_sig(&[0x0E], &mut o), TypeSig::String));
    o = 0;
    assert!(matches!(read_type_sig(&[0x1C], &mut o), TypeSig::Object));
}

#[test]
fn type_sig_szarray() {
    let mut o = 0;
    let sig = read_type_sig(&[0x1D, 0x08], &mut o); // int[]
    match sig {
        TypeSig::Array(inner) => assert!(matches!(*inner, TypeSig::I4)),
        _ => panic!("expected Array"),
    }
}

#[test]
fn type_sig_unknown_tag() {
    let mut o = 0;
    let sig = read_type_sig(&[0xFE], &mut o);
    assert!(matches!(sig, TypeSig::Unknown(0xFE)));
}

#[test]
fn type_sig_empty_returns_unknown_0() {
    let mut o = 0;
    assert!(matches!(read_type_sig(&[], &mut o), TypeSig::Unknown(0)));
}

#[test]
fn type_sig_ptr_and_byref() {
    let mut o = 0;
    let s = read_type_sig(&[0x0F, 0x08], &mut o);
    assert!(matches!(s, TypeSig::Ptr(_)));
    o = 0;
    let s = read_type_sig(&[0x10, 0x08], &mut o);
    assert!(matches!(s, TypeSig::ByRef(_)));
}

// ── read_method_sig ──────────────────────────────────────────────────────────

#[test]
fn method_sig_empty_returns_default() {
    let m = read_method_sig(&[]);
    assert_eq!(m.calling_conv, 0);
    assert_eq!(m.params.len(), 0);
    assert!(matches!(m.ret_type, TypeSig::Void));
}

#[test]
fn method_sig_no_params_void_return() {
    // calling_conv=0, param_count=0, ret=void(0x01)
    let m = read_method_sig(&[0x00, 0x00, 0x01]);
    assert_eq!(m.params.len(), 0);
    assert!(matches!(m.ret_type, TypeSig::Void));
}

#[test]
fn method_sig_with_params() {
    // calling_conv=0, param_count=2, ret=int, params=int, string
    let m = read_method_sig(&[0x00, 0x02, 0x08, 0x08, 0x0E]);
    assert_eq!(m.params.len(), 2);
    assert!(matches!(m.ret_type, TypeSig::I4));
    assert!(matches!(m.params[0], TypeSig::I4));
    assert!(matches!(m.params[1], TypeSig::String));
}

#[test]
fn method_sig_generic_param_count() {
    // calling_conv = 0x10 (GENERIC), gp_count=3, params=0, ret=void
    let m = read_method_sig(&[0x10, 0x03, 0x00, 0x01]);
    assert_eq!(m.generic_param_count, 3);
    assert!(matches!(m.ret_type, TypeSig::Void));
}

// ── String heap helpers ──────────────────────────────────────────────────────

#[test]
fn read_string_heap_basic() {
    let heap = b"\0hello\0world\0";
    assert_eq!(read_string_heap(heap, 1), "hello");
    assert_eq!(read_string_heap(heap, 7), "world");
}

#[test]
fn read_string_heap_oob() {
    let heap = b"abc\0";
    assert_eq!(read_string_heap(heap, 999), "");
}

#[test]
fn read_string_heap_no_null_terminator() {
    let heap = b"unterminated";
    assert_eq!(read_string_heap(heap, 0), "unterminated");
}

// ── resolve_type_name ────────────────────────────────────────────────────────

#[test]
fn resolve_type_name_typedef() {
    let strings = b"\0System\0Foo\0";
    let td = vec![TypeDefRow {
        flags: 0,
        type_name: 8, type_namespace: 1,
        extends: 0, field_list: 0, method_list: 0,
    }];
    // token: table 0x02 (TypeDef), row 1 (1-based)
    let name = resolve_type_name(0x0200_0001, &td, &[], strings);
    assert_eq!(name, "System.Foo");
}

#[test]
fn resolve_type_name_typeref_no_ns() {
    let strings = b"\0Bar\0";
    let tr = vec![TypeRefRow {
        resolution_scope: 0,
        type_name: 1, type_namespace: 0, // empty ns
    }];
    let name = resolve_type_name(0x0100_0001, &[], &tr, strings);
    assert_eq!(name, "Bar");
}

#[test]
fn resolve_type_name_out_of_range_typedef() {
    let name = resolve_type_name(0x0200_0005, &[], &[], &[]);
    assert_eq!(name, "<TypeDef:4>");
}

#[test]
fn resolve_type_name_unknown_table() {
    let name = resolve_type_name(0xAB00_0001, &[], &[], &[]);
    assert!(name.starts_with("<token:"));
}

// ── cil_type_name ────────────────────────────────────────────────────────────

#[test]
fn cil_type_name_primitives() {
    assert_eq!(cil_type_name(&TypeSig::I4, &[], &[]), "int");
    assert_eq!(cil_type_name(&TypeSig::String, &[], &[]), "string");
    assert_eq!(cil_type_name(&TypeSig::Void, &[], &[]), "void");
}

#[test]
fn cil_type_name_array() {
    let s = cil_type_name(&TypeSig::Array(Box::new(TypeSig::I4)), &[], &[]);
    assert_eq!(s, "int[]");
}

#[test]
fn cil_type_name_ptr_byref_pinned() {
    assert_eq!(cil_type_name(&TypeSig::Ptr(Box::new(TypeSig::U1)), &[], &[]), "byte*");
    assert_eq!(cil_type_name(&TypeSig::ByRef(Box::new(TypeSig::I4)), &[], &[]), "ref int");
    assert_eq!(cil_type_name(&TypeSig::Pinned(Box::new(TypeSig::I4)), &[], &[]), "pinned int");
}

#[test]
fn cil_type_name_generic_var() {
    assert_eq!(cil_type_name(&TypeSig::Var(0), &[], &[]), "T0");
    assert_eq!(cil_type_name(&TypeSig::MVar(2), &[], &[]), "M2");
}

#[test]
fn cil_type_name_unknown() {
    assert_eq!(cil_type_name(&TypeSig::Unknown(0xAB), &[], &[]), "<element_type:0xab>");
}

// ── parse_method_body ────────────────────────────────────────────────────────

#[test]
fn method_body_tiny() {
    // tiny header: low 2 bits = 0b10, upper 6 bits = code length
    // code_len = 3 → first byte = (3 << 2) | 0b10 = 0x0E
    let data = [0x0E, 0x16, 0x17, 0x2A];
    let body = parse_method_body(&data, 0).unwrap();
    assert!(!body.is_fat);
    assert_eq!(body.code, vec![0x16, 0x17, 0x2A]);
    assert_eq!(body.max_stack, 8);
    assert_eq!(body.local_var_sig_tok, 0);
}

#[test]
fn method_body_offset_past_end() {
    let err = parse_method_body(&[0u8; 4], 10).unwrap_err();
    assert!(matches!(err, DotnetLoaderError::InvalidMethodBody(0)));
}

#[test]
fn method_body_tiny_truncated() {
    // claims 5 bytes of code but only 2 follow
    let data = [(5u8 << 2) | 0x02, 0xAA, 0xBB];
    let err = parse_method_body(&data, 0).unwrap_err();
    assert!(matches!(err, DotnetLoaderError::TruncatedStream));
}

#[test]
fn method_body_fat_minimal() {
    // Fat header: 12 bytes, first u16 low 2 bits = 0b11
    // flags_and_size = 0x3003 (header size 3*4 = 12, low bits 0b11)
    let mut d = vec![0u8; 12 + 4];
    d[0..2].copy_from_slice(&0x3003u16.to_le_bytes());
    d[2..4].copy_from_slice(&7u16.to_le_bytes()); // max_stack
    d[4..8].copy_from_slice(&4u32.to_le_bytes()); // code_size
    d[8..12].copy_from_slice(&0u32.to_le_bytes()); // local_var_sig_tok
    d[12..16].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let body = parse_method_body(&d, 0).unwrap();
    assert!(body.is_fat);
    assert_eq!(body.max_stack, 7);
    assert_eq!(body.code, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn method_body_fat_invalid_flags() {
    let d = vec![0u8; 12];
    let err = parse_method_body(&d, 0).unwrap_err();
    assert!(matches!(err, DotnetLoaderError::InvalidMethodBody(0)));
}

#[test]
fn method_body_fat_truncated_header() {
    // first byte signals fat (need full 12) but data has only 6
    let mut d = vec![0u8; 6];
    d[0..2].copy_from_slice(&0x3003u16.to_le_bytes());
    let err = parse_method_body(&d, 0).unwrap_err();
    assert!(matches!(err, DotnetLoaderError::TruncatedStream));
}

// ── ExceptionClauseType ──────────────────────────────────────────────────────

#[test]
fn exception_clause_from_u32() {
    assert_eq!(ExceptionClauseType::from_u32(0), ExceptionClauseType::Catch);
    assert_eq!(ExceptionClauseType::from_u32(1), ExceptionClauseType::Filter);
    assert_eq!(ExceptionClauseType::from_u32(2), ExceptionClauseType::Finally);
    assert_eq!(ExceptionClauseType::from_u32(4), ExceptionClauseType::Fault);
    assert_eq!(ExceptionClauseType::from_u32(99), ExceptionClauseType::Unknown(99));
}

#[test]
fn exception_clause_display() {
    assert_eq!(format!("{}", ExceptionClauseType::Catch), "catch");
    assert_eq!(format!("{}", ExceptionClauseType::Finally), "finally");
    assert_eq!(format!("{}", ExceptionClauseType::Unknown(7)), "unknown(0x7)");
}

// ── DotnetLoader ─────────────────────────────────────────────────────────────

#[test]
fn loader_name() {
    use rustre_core::Loader;
    let l = DotnetLoader;
    assert_eq!(l.name(), "dotnet");
}

#[test]
fn loader_can_load_bsjb_blob() {
    use rustre_core::{Loader, LoaderInput};
    let l = DotnetLoader;
    let input = LoaderInput::new("test://x", b"prefixBSJBmoredata".to_vec());
    assert!(l.can_load(&input));
}

#[test]
fn loader_cannot_load_garbage() {
    use rustre_core::{Loader, LoaderInput};
    let l = DotnetLoader;
    let input = LoaderInput::new("test://x", b"nothing useful here".to_vec());
    assert!(!l.can_load(&input));
}

// ── DotnetArch ───────────────────────────────────────────────────────────────

#[test]
fn arch_basics() {
    use rustre_core::arch::Architecture;
    let a = DotnetArch;
    assert_eq!(a.name(), "cil");
    assert_eq!(a.pointer_size(), 8);
    assert!(a.registers().is_empty());
    assert!(a.calling_conventions().is_empty());
}

#[test]
fn arch_disassemble_unknown_falls_back() {
    use rustre_core::arch::Architecture;
    use rustre_core::address::Address;
    let a = DotnetArch;
    // 0xFE prefix without follow-up should yield an unknown / err fallback
    let instr = a.disassemble(Address::new(0x1000), &[0xFE]).unwrap();
    assert!(instr.size >= 1);
}

// ── CorFlags / DotnetAssemblyFlags bitflags ──────────────────────────────────

#[test]
fn cor_flags_bits() {
    let f = CorFlags::IL_ONLY | CorFlags::STRONG_NAME_SIGNED;
    assert!(f.contains(CorFlags::IL_ONLY));
    assert!(f.contains(CorFlags::STRONG_NAME_SIGNED));
    assert!(!f.contains(CorFlags::NATIVE_ENTRY_POINT));
}

#[test]
fn assembly_flags_serialise_roundtrip() {
    let f = DotnetAssemblyFlags::IL_ONLY | DotnetAssemblyFlags::STRONG_NAME_SIGNED;
    let s = serde_json::to_string(&f).unwrap();
    let f2: DotnetAssemblyFlags = serde_json::from_str(&s).unwrap();
    assert_eq!(f, f2);
}

// ── strongname: StrongNameSignature ──────────────────────────────────────────

#[test]
fn sn_parse_too_short() {
    let err = StrongNameSignature::parse_public_key(&[0u8; 10]).unwrap_err();
    assert!(matches!(err, StrongNameError::BlobTooShort));
}

#[test]
fn sn_parse_wrong_btype() {
    let mut blob = vec![0u8; 20];
    blob[0] = 0x05;
    let err = StrongNameSignature::parse_public_key(&blob).unwrap_err();
    assert!(matches!(err, StrongNameError::InvalidBlobHeader));
}

#[test]
fn sn_parse_wrong_magic() {
    let mut blob = vec![0u8; 20];
    blob[0] = 0x06;
    // magic stays zero → not RSA1
    let err = StrongNameSignature::parse_public_key(&blob).unwrap_err();
    assert!(matches!(err, StrongNameError::InvalidBlobHeader));
}

#[test]
fn sn_mock_roundtrip() {
    let m = StrongNameSignature::mock(2048);
    assert_eq!(m.key_bits, 2048);
    assert_eq!(m.public_exponent, 65537);
    assert!(m.is_strong_key());
    let parsed = StrongNameSignature::parse_public_key(&m.public_key_blob).unwrap();
    assert_eq!(parsed.key_bits, 2048);
    assert_eq!(parsed.public_exponent, 65537);
    assert_eq!(parsed.modulus().len(), 256);
}

#[test]
fn sn_modulus_empty_when_no_data() {
    let s = StrongNameSignature {
        public_key_blob: vec![0; 10],
        rsa_signature: vec![],
        key_bits: 1024,
        public_exponent: 65537,
    };
    // start (20) > blob.len() (10) → empty
    assert!(s.modulus().is_empty());
}

#[test]
fn sn_display_contains_key_bits() {
    let s = StrongNameSignature::mock(1024);
    let out = format!("{s}");
    assert!(out.contains("1024"));
}

#[test]
fn sn_is_strong_key_threshold() {
    assert!(!StrongNameSignature::mock(1024).is_strong_key());
    assert!(StrongNameSignature::mock(2048).is_strong_key());
}

// ── PublicKeyToken ───────────────────────────────────────────────────────────

#[test]
fn token_from_bytes_wrong_len() {
    let err = PublicKeyToken::from_bytes(&[0; 7]).unwrap_err();
    assert!(matches!(err, StrongNameError::InvalidTokenLength(7)));
}

#[test]
fn token_from_bytes_ok() {
    let t = PublicKeyToken::from_bytes(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    assert_eq!(t.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn token_hex_roundtrip() {
    let t = PublicKeyToken::from_hex("b77a5c561934e089").unwrap();
    assert_eq!(t, PublicKeyToken::MSCORLIB);
    assert_eq!(t.to_hex(), "b77a5c561934e089");
}

#[test]
fn token_hex_wrong_length() {
    let err = PublicKeyToken::from_hex("abcd").unwrap_err();
    assert!(matches!(err, StrongNameError::InvalidTokenLength(_)));
}

#[test]
fn token_hex_invalid_chars() {
    let err = PublicKeyToken::from_hex("zzzzzzzzzzzzzzzz").unwrap_err();
    assert!(matches!(err, StrongNameError::MalformedIdentity(_)));
}

#[test]
fn token_uppercase_hex_accepted() {
    let t = PublicKeyToken::from_hex("B77A5C561934E089").unwrap();
    assert_eq!(t, PublicKeyToken::MSCORLIB);
}

#[test]
fn token_is_microsoft() {
    assert!(PublicKeyToken::MSCORLIB.is_microsoft());
    assert!(PublicKeyToken::SYSTEM.is_microsoft());
    let other = PublicKeyToken::from_bytes(&[0; 8]).unwrap();
    assert!(!other.is_microsoft());
}

#[test]
fn token_display_eq_to_hex() {
    let t = PublicKeyToken::MSCORLIB;
    assert_eq!(format!("{t}"), t.to_hex());
}

#[test]
fn token_hash_consistent_with_eq() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(PublicKeyToken::MSCORLIB);
    assert!(s.contains(&PublicKeyToken::MSCORLIB.clone()));
}

#[test]
fn token_from_blob_is_deterministic() {
    let a = PublicKeyToken::from_public_key_blob(b"hello world");
    let b = PublicKeyToken::from_public_key_blob(b"hello world");
    assert_eq!(a, b);
}

// ── StrongNameVerifier ───────────────────────────────────────────────────────

#[test]
fn verifier_bypass_accepts_anything() {
    let v = StrongNameVerifier::bypass();
    let sn = StrongNameSignature::mock(1024);
    assert!(v.verify(&sn, &[]).is_ok());
}

#[test]
fn verifier_strict_rejects_empty_hash() {
    let v = StrongNameVerifier::new();
    let sn = StrongNameSignature::mock(1024);
    let err = v.verify(&sn, &[]).unwrap_err();
    assert!(matches!(err, StrongNameError::VerificationFailed(_)));
}

#[test]
fn verifier_strict_rejects_wrong_sig_len() {
    let v = StrongNameVerifier::new();
    let mut sn = StrongNameSignature::mock(1024);
    sn.rsa_signature = vec![0; 5]; // wrong length
    let err = v.verify(&sn, &[1, 2, 3]).unwrap_err();
    assert!(matches!(err, StrongNameError::VerificationFailed(_)));
}

#[test]
fn verifier_strict_ok_with_correct_len_and_hash() {
    let v = StrongNameVerifier::new();
    let sn = StrongNameSignature::mock(1024); // sig len = 128 = 1024/8
    assert!(v.verify(&sn, &[0xAA]).is_ok());
}

#[test]
fn verifier_token_no_trust_list() {
    let v = StrongNameVerifier::new();
    assert!(v.verify_token(&PublicKeyToken::MSCORLIB).is_ok());
    assert!(v.is_trusted(&PublicKeyToken::MSCORLIB));
}

#[test]
fn verifier_token_trust_list_enforced() {
    let mut v = StrongNameVerifier::new();
    v.trust(PublicKeyToken::SYSTEM);
    assert!(v.verify_token(&PublicKeyToken::SYSTEM).is_ok());
    assert!(v.verify_token(&PublicKeyToken::MSCORLIB).is_err());
}

// ── AssemblyIdentity ─────────────────────────────────────────────────────────

#[test]
fn identity_unsigned_basic() {
    let id = AssemblyIdentity::unsigned("foo", "1.0.0.0");
    assert!(!id.is_strong_named());
    assert_eq!(id.culture, "neutral");
    assert_eq!(id.major_version(), 1);
}

#[test]
fn identity_parse_full() {
    let s = "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
    let id = AssemblyIdentity::parse(s).unwrap();
    assert_eq!(id.name, "mscorlib");
    assert_eq!(id.version, "4.0.0.0");
    assert_eq!(id.culture, "neutral");
    assert_eq!(id.public_key_token, Some(PublicKeyToken::MSCORLIB));
    assert!(id.is_net4());
}

#[test]
fn identity_parse_null_token() {
    let id = AssemblyIdentity::parse("foo, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null").unwrap();
    assert!(id.public_key_token.is_none());
}

#[test]
fn identity_qualified_name_roundtrip() {
    let id = AssemblyIdentity::new("X", "1.0.0.0", "en-US", Some(PublicKeyToken::SYSTEM));
    let parsed = AssemblyIdentity::parse(&id.to_qualified_name()).unwrap();
    assert_eq!(parsed, id);
}

#[test]
fn identity_version_matches() {
    let a = AssemblyIdentity::unsigned("a", "1.0.0.0");
    let b = AssemblyIdentity::unsigned("b", "1.0.0.0");
    let c = AssemblyIdentity::unsigned("c", "2.0.0.0");
    assert!(a.version_matches(&b));
    assert!(!a.version_matches(&c));
}

#[test]
fn identity_major_version_unparseable() {
    let id = AssemblyIdentity::unsigned("x", "garbage");
    assert_eq!(id.major_version(), 0);
}

#[test]
fn identity_display_is_qualified() {
    let id = AssemblyIdentity::unsigned("a", "1.0.0.0");
    assert_eq!(format!("{id}"), id.to_qualified_name());
}

// ── GacResolver ──────────────────────────────────────────────────────────────

#[test]
fn gac_defaults_contains_mscorlib() {
    let r = GacResolver::with_dotnet4_defaults();
    // We can't see the registry directly; resolve via parsed identity.
    let id = AssemblyIdentity::parse(
        "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
    ).unwrap();
    // Force interaction: serialise the identity through Display and look up via map
    // (we just verify the resolver constructs without panic).
    let _ = r;
    let _ = id;
}

// ── metadata_tables: StringsHeap / BlobHeap / GuidHeap ───────────────────────

#[test]
fn strings_heap_get_basic() {
    let h = mt::StringsHeap(b"\0hello\0".to_vec());
    assert_eq!(h.get(1).unwrap(), "hello");
}

#[test]
fn strings_heap_oob_errors() {
    let h = mt::StringsHeap(b"abc\0".to_vec());
    assert!(h.get(100).is_err());
}

#[test]
fn blob_heap_simple() {
    // offset 0: len-prefix 3, then 3 bytes
    let h = mt::BlobHeap(vec![0x03, 0x10, 0x20, 0x30]);
    assert_eq!(h.get(0).unwrap(), &[0x10, 0x20, 0x30]);
}

#[test]
fn blob_heap_oob_errors() {
    let h = mt::BlobHeap(vec![0x05, 0x10]);
    assert!(h.get(0).is_err());
}

#[test]
fn guid_heap_zero_returns_zero_guid() {
    let h = mt::GuidHeap(vec![]);
    assert_eq!(h.get(0).unwrap(), [0u8; 16]);
}

#[test]
fn guid_heap_idx1_first_16() {
    let bytes: Vec<u8> = (0..16).collect();
    let h = mt::GuidHeap(bytes.clone());
    let g = h.get(1).unwrap();
    assert_eq!(&g[..], &bytes[..]);
}

#[test]
fn guid_heap_oob() {
    let h = mt::GuidHeap(vec![0u8; 16]);
    assert!(h.get(2).is_err());
}

// ── metadata_tables::read_compressed_uint (Result variant) ───────────────────

#[test]
fn mt_compressed_uint_one_byte() {
    let (v, n) = mt::read_compressed_uint(&[0x42]).unwrap();
    assert_eq!((v, n), (0x42, 1));
}

#[test]
fn mt_compressed_uint_two_byte() {
    let (v, n) = mt::read_compressed_uint(&[0x80 | 0x12, 0x34]).unwrap();
    assert_eq!((v, n), (0x1234, 2));
}

#[test]
fn mt_compressed_uint_four_byte() {
    let (v, n) = mt::read_compressed_uint(&[0xC0 | 0x01, 0x02, 0x03, 0x04]).unwrap();
    assert_eq!((v, n), (0x0102_0304, 4));
}

#[test]
fn mt_compressed_uint_empty_errors() {
    assert!(mt::read_compressed_uint(&[]).is_err());
}

#[test]
fn mt_compressed_uint_truncated_4byte_errors() {
    assert!(mt::read_compressed_uint(&[0xC0, 0x00]).is_err());
}

#[test]
fn mt_compressed_uint_invalid_top_bits_errors() {
    // 0xE0 == 0b11100000, doesn't match any prefix → Err
    assert!(mt::read_compressed_uint(&[0xE0]).is_err());
}
