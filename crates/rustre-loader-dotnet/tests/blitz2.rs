//! Deep adversarial tests for rustre-loader-dotnet public API.

use rustre_loader_dotnet::{
    AssemblyRefRow, AssemblyRow, CilOpcodeClass, ClrHeader, ConstantRow, CorFlags,
    CustomAttributeRow, DotnetArch, DotnetAssemblyFlags, DotnetFile, DotnetLoader,
    DotnetLoaderError, DotnetMetadata, DotnetRuntimeVersion, DotnetStream, ExceptionClause,
    ExceptionClauseType, FieldRow, GenericParamRow, InterfaceImplRow, MemberRefRow, MethodDefRow,
    MethodSig, ModuleRow, NestedClassRow, ParamRow, PeOptHeader, PeSectionHeader, TypeDefRow,
    TypeRefRow, TypeSig, build_type_hierarchy, cil_opcode_class, cil_opcode_histogram,
    cil_type_name, cil_type_name_full, decode_type_def_or_ref, has_clr_header, is_dotnet,
    parse_method_body, parse_pe_sections, parse_tables_stream, read_compressed_uint,
    read_method_sig, read_string_heap, read_type_sig, resolve_type_name, rva_to_file_offset,
};
use rustre_core::Loader;
use rustre_core::LoaderInput;
use rustre_core::arch::Architecture;
use rustre_core::address::Address;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

// ── helpers ─────────────────────────────────────────────────────────────────

const fn lcg_seed() -> u64 {
    0xDEAD_BEEF_CAFE_BABE
}

struct Lcg(u64);
impl Lcg {
    const fn new(s: u64) -> Self {
        Self(s)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn next_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            let r = self.next();
            v.extend_from_slice(&r.to_le_bytes());
        }
        v.truncate(n);
        v
    }
}

fn minimal_dotnet() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"BSJB");
    v.extend_from_slice(&[1u8, 0, 1, 0]);
    v.extend_from_slice(&[0u8; 4]);
    let version = b"v4.0.30319\0\0";
    v.extend_from_slice(&(version.len() as u32).to_le_bytes());
    v.extend_from_slice(version);
    v.extend_from_slice(&[0u8, 0]); // flags
    v.extend_from_slice(&[1u8, 0]); // stream count
    v.extend_from_slice(&[0u8; 4]); // offset
    v.extend_from_slice(&[4u8, 0, 0, 0]); // size
    v.extend_from_slice(b"#~\0\0");
    v
}

fn make_dotnet_pe(clr_rva: u32, magic: u16) -> Vec<u8> {
    let mut data = vec![0u8; 1024];
    data[0] = 0x4D;
    data[1] = 0x5A;
    data[60] = 0x40;
    data[0x40] = 0x50;
    data[0x41] = 0x45;
    data[0x58] = (magic & 0xff) as u8;
    data[0x59] = (magic >> 8) as u8;
    let opt_off = 0x58_usize;
    let clr_off = match magic {
        0x10B => opt_off + 96 + 14 * 8,
        0x20B => opt_off + 112 + 14 * 8,
        _ => return data,
    };
    data[clr_off..clr_off + 4].copy_from_slice(&clr_rva.to_le_bytes());
    data[clr_off + 4..clr_off + 8].copy_from_slice(&0x48_u32.to_le_bytes());
    data
}

fn h<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn t01_runtime_version_display_roundtrip() {
    for major in 0u16..10 {
        for minor in 0u16..10 {
            let v = DotnetRuntimeVersion { major, minor };
            let s = v.to_string();
            assert_eq!(s, format!("v{major}.{minor}"));
        }
    }
}

#[test]
fn t02_runtime_version_eq_hash() {
    for i in 0u16..30 {
        let a = DotnetRuntimeVersion {
            major: i,
            minor: i.wrapping_mul(3),
        };
        let b = a;
        assert_eq!(a, b);
    }
}

#[test]
fn t03_runtime_version_boundary() {
    let v = DotnetRuntimeVersion {
        major: u16::MAX,
        minor: u16::MAX,
    };
    assert_eq!(v.to_string(), format!("v{}.{}", u16::MAX, u16::MAX));
}

#[test]
fn t04_assembly_flags_bitops() {
    let a = DotnetAssemblyFlags::IL_ONLY | DotnetAssemblyFlags::STRONG_NAME_SIGNED;
    assert!(a.contains(DotnetAssemblyFlags::IL_ONLY));
    let b = a - DotnetAssemblyFlags::IL_ONLY;
    assert!(!b.contains(DotnetAssemblyFlags::IL_ONLY));
    assert!(b.contains(DotnetAssemblyFlags::STRONG_NAME_SIGNED));
}

#[test]
fn t05_corflags_all_known() {
    let all = CorFlags::IL_ONLY
        | CorFlags::REQUIRES_32BIT_PROCESS
        | CorFlags::STRONG_NAME_SIGNED
        | CorFlags::NATIVE_ENTRY_POINT
        | CorFlags::TRACK_DEBUG_DATA
        | CorFlags::PREFER_32BIT_PROCESS;
    assert!(all.contains(CorFlags::IL_ONLY));
    assert!(all.contains(CorFlags::PREFER_32BIT_PROCESS));
}

#[test]
fn t06_dotnet_metadata_mock_is_pure_il() {
    let m = DotnetMetadata::mock();
    assert!(m.is_pure_il());
    assert!(!m.is_strong_named());
    assert!(m.to_string().contains(".NET"));
    assert!(m.to_string().contains("MyModule.exe"));
}

#[test]
fn t07_dotnet_stream_display_contains_name() {
    let s = DotnetStream {
        name: "#GUID".to_string(),
        offset: 0xABCD,
        size: 0x1234,
    };
    let txt = s.to_string();
    assert!(txt.contains("#GUID"));
    assert!(txt.contains("4660")); // 0x1234 decimal
}

#[test]
fn t08_dotnet_stream_eq_hash_clone() {
    let a = DotnetStream {
        name: "#~".into(),
        offset: 0,
        size: 1,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn t09_is_valid_dotnet_true_false() {
    assert!(DotnetFile::is_valid_dotnet(b"prefixBSJBsuffix"));
    assert!(!DotnetFile::is_valid_dotnet(b"BSJ"));
    assert!(!DotnetFile::is_valid_dotnet(b""));
    assert!(!DotnetFile::is_valid_dotnet(b"random data without sig"));
    assert!(is_dotnet(b"....BSJB...."));
}

#[test]
fn t10_parse_metadata_header_min() {
    let f = DotnetFile::parse_metadata_header(&minimal_dotnet()).unwrap();
    assert_eq!(f.streams.len(), 1);
    assert_eq!(f.streams[0].name, "#~");
    assert!(f.stream("#~").is_some());
    assert!(f.stream("#Strings").is_none());
    assert_eq!(f.entry_point_token, None);
}

#[test]
fn t11_parse_metadata_header_not_dotnet() {
    assert!(matches!(
        DotnetFile::parse_metadata_header(b"not dotnet").unwrap_err(),
        DotnetLoaderError::NotDotnet
    ));
}

#[test]
fn t12_parse_metadata_header_truncated() {
    assert!(matches!(
        DotnetFile::parse_metadata_header(b"BSJB").unwrap_err(),
        DotnetLoaderError::TruncatedStream
    ));
}

#[test]
fn t13_parse_metadata_header_fuzz_no_panic() {
    let mut lcg = Lcg::new(lcg_seed());
    for _ in 0..50 {
        let n = (lcg.next() as usize) % 256;
        let mut data = lcg.next_bytes(n);
        // 50% chance: prepend BSJB
        if lcg.next() & 1 == 0 && data.len() >= 4 {
            data[0..4].copy_from_slice(b"BSJB");
        }
        let _ = DotnetFile::parse_metadata_header(&data);
    }
}

#[test]
fn t14_has_clr_header_pe32() {
    assert!(has_clr_header(&make_dotnet_pe(0x2000, 0x10B)));
    assert!(!has_clr_header(&make_dotnet_pe(0, 0x10B)));
}

#[test]
fn t15_has_clr_header_pe32_plus() {
    assert!(has_clr_header(&make_dotnet_pe(0x2000, 0x20B)));
    assert!(!has_clr_header(&make_dotnet_pe(0, 0x20B)));
}

#[test]
fn t16_has_clr_header_invalid_inputs() {
    assert!(!has_clr_header(b""));
    assert!(!has_clr_header(&[0u8; 4]));
    assert!(!has_clr_header(&[0u8; 100])); // not MZ
    let mut bad = vec![0u8; 256];
    bad[0] = 0x4D;
    bad[1] = 0x5A;
    // bad e_lfanew
    bad[0x3C] = 0xFF;
    bad[0x3D] = 0xFF;
    bad[0x3E] = 0xFF;
    bad[0x3F] = 0xFF;
    assert!(!has_clr_header(&bad));
}

#[test]
fn t17_has_clr_header_fuzz() {
    let mut lcg = Lcg::new(lcg_seed());
    for _ in 0..50 {
        let n = (lcg.next() as usize) % 1024;
        let data = lcg.next_bytes(n);
        let _ = has_clr_header(&data);
    }
}

#[test]
fn t18_clr_header_parse_min() {
    let mut data = vec![0u8; 28];
    data[0..4].copy_from_slice(&72u32.to_le_bytes());
    let hdr = ClrHeader::parse(&data).unwrap();
    assert_eq!(hdr.header_size, 72);
    assert_eq!(hdr.strong_name_rva, 0);
    assert!(!hdr.has_strong_name());
}

#[test]
fn t19_clr_header_full() {
    let mut data = vec![0u8; 72];
    data[0..4].copy_from_slice(&72u32.to_le_bytes());
    data[4..6].copy_from_slice(&2u16.to_le_bytes());
    data[6..8].copy_from_slice(&5u16.to_le_bytes());
    data[8..12].copy_from_slice(&0x8000u32.to_le_bytes());
    data[16..20].copy_from_slice(&1u32.to_le_bytes());
    // Resources at 24, StrongNameSignature at 32 — filling both with distinct
    // values keeps this test able to tell them apart.
    data[24..28].copy_from_slice(&0x3000u32.to_le_bytes());
    data[28..32].copy_from_slice(&0x40u32.to_le_bytes());
    data[32..36].copy_from_slice(&0x1000u32.to_le_bytes());
    data[36..40].copy_from_slice(&0x80u32.to_le_bytes());
    let hdr = ClrHeader::parse(&data).unwrap();
    assert_eq!(hdr.framework_version(), "2.5");
    assert!(hdr.has_strong_name());
    assert_eq!(hdr.strong_name_rva, 0x1000);
    assert_eq!(hdr.resources_rva, 0x3000);
    assert!(!hdr.is_mixed_mode());
    assert!(hdr.to_string().contains("CLR"));
}

#[test]
fn t20_clr_header_too_short() {
    assert!(ClrHeader::parse(&[]).is_none());
    assert!(ClrHeader::parse(&[0u8; 27]).is_none());
}

#[test]
fn t21_clr_header_eq_clone() {
    let mut data = vec![0u8; 48];
    data[0..4].copy_from_slice(&48u32.to_le_bytes());
    let a = ClrHeader::parse(&data).unwrap();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn t22_clr_header_fuzz() {
    let mut lcg = Lcg::new(lcg_seed());
    for _ in 0..50 {
        let n = (lcg.next() as usize) % 80;
        let data = lcg.next_bytes(n);
        let _ = ClrHeader::parse(&data);
    }
}

#[test]
fn t23_pe_opt_header_pe32() {
    let mut data = vec![0u8; 256];
    data[0..2].copy_from_slice(&0x010Bu16.to_le_bytes());
    data[16..20].copy_from_slice(&0x1234u32.to_le_bytes());
    data[28..32].copy_from_slice(&0x40_0000u32.to_le_bytes());
    let h = PeOptHeader::parse(&data, 0).unwrap();
    assert!(!h.is_64bit);
    assert_eq!(h.entry_point_rva, 0x1234);
    assert_eq!(h.image_base, 0x40_0000);
    assert!(h.to_string().contains("PE32"));
}

#[test]
fn t24_pe_opt_header_pe32_plus() {
    let mut data = vec![0u8; 256];
    data[0..2].copy_from_slice(&0x020Bu16.to_le_bytes());
    data[16..20].copy_from_slice(&0x4321u32.to_le_bytes());
    data[24..32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    let h = PeOptHeader::parse(&data, 0).unwrap();
    assert!(h.is_64bit);
    assert_eq!(h.entry_point_rva, 0x4321);
    assert!(h.to_string().contains("PE32+"));
}

#[test]
fn t25_pe_opt_header_too_short() {
    assert!(PeOptHeader::parse(&[], 0).is_none());
    assert!(PeOptHeader::parse(&[0u8; 4], 0).is_none());
}

#[test]
fn t26_pe_section_header_parse() {
    let mut d = vec![0u8; 40];
    d[0..5].copy_from_slice(b".text");
    d[8..12].copy_from_slice(&0x1000u32.to_le_bytes());
    d[12..16].copy_from_slice(&0x2000u32.to_le_bytes());
    d[16..20].copy_from_slice(&0x800u32.to_le_bytes());
    d[20..24].copy_from_slice(&0x400u32.to_le_bytes());
    d[36..40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    let s = PeSectionHeader::parse(&d, 0).unwrap();
    assert_eq!(s.name, ".text");
    assert_eq!(s.virtual_address, 0x2000);
    assert_eq!(s.rva_to_offset(0x2100), Some(0x500));
    assert_eq!(s.rva_to_offset(0x4000), None);
    assert_eq!(s.rva_to_offset(0x1FFF), None);
}

#[test]
fn t27_pe_section_header_too_short() {
    assert!(PeSectionHeader::parse(&[0u8; 10], 0).is_none());
    assert!(PeSectionHeader::parse(&[0u8; 39], 0).is_none());
}

#[test]
fn t28_rva_to_file_offset_search() {
    let s1 = PeSectionHeader {
        name: ".text".into(),
        virtual_size: 0x1000,
        virtual_address: 0x1000,
        raw_size: 0x1000,
        raw_offset: 0x200,
        characteristics: 0,
    };
    let s2 = PeSectionHeader {
        name: ".data".into(),
        virtual_size: 0x500,
        virtual_address: 0x3000,
        raw_size: 0x500,
        raw_offset: 0x1200,
        characteristics: 0,
    };
    assert_eq!(rva_to_file_offset(0x1100, &[s1.clone(), s2.clone()]), Some(0x300));
    assert_eq!(rva_to_file_offset(0x3100, &[s1.clone(), s2.clone()]), Some(0x1300));
    assert_eq!(rva_to_file_offset(0xDEAD, &[s1, s2]), None);
    assert_eq!(rva_to_file_offset(0, &[]), None);
}

#[test]
fn t29_parse_pe_sections_empty() {
    assert!(parse_pe_sections(&[], 0).is_empty());
    assert!(parse_pe_sections(&[0u8; 4], 0).is_empty());
}

#[test]
fn t30_compressed_uint_1byte_all_values() {
    for v in 0u8..=0x7F {
        let mut off = 0;
        assert_eq!(read_compressed_uint(&[v], &mut off), u32::from(v));
        assert_eq!(off, 1);
    }
}

#[test]
fn t31_compressed_uint_2byte() {
    // 0x80 0x80 -> 0x80
    let mut off = 0;
    assert_eq!(read_compressed_uint(&[0x80, 0x80], &mut off), 0x80);
    assert_eq!(off, 2);
    let mut off = 0;
    assert_eq!(read_compressed_uint(&[0xBF, 0xFF], &mut off), 0x3FFF);
    assert_eq!(off, 2);
}

#[test]
fn t32_compressed_uint_4byte() {
    let mut off = 0;
    assert_eq!(
        read_compressed_uint(&[0xC0, 0x00, 0x40, 0x00], &mut off),
        0x4000
    );
    assert_eq!(off, 4);
}

#[test]
fn t33_compressed_uint_truncated() {
    let mut off = 0;
    assert_eq!(read_compressed_uint(&[], &mut off), 0);
    let mut off = 0;
    assert_eq!(read_compressed_uint(&[0x80], &mut off), 0);
    let mut off = 0;
    assert_eq!(read_compressed_uint(&[0xC0, 0x00], &mut off), 0);
}

#[test]
fn t34_compressed_uint_fuzz() {
    let mut lcg = Lcg::new(lcg_seed());
    for _ in 0..100 {
        let n = (lcg.next() as usize) % 16;
        let buf = lcg.next_bytes(n);
        let mut off = 0;
        let _ = read_compressed_uint(&buf, &mut off);
        assert!(off <= buf.len());
    }
}

#[test]
fn t35_decode_type_def_or_ref_all_tags() {
    assert_eq!(decode_type_def_or_ref(0), 0x0200_0000);
    assert_eq!(decode_type_def_or_ref(1), 0x0100_0000);
    assert_eq!(decode_type_def_or_ref(2), 0x1B00_0000);
    assert_eq!(decode_type_def_or_ref(3), 0xFF00_0000);
    // row preserved
    assert_eq!(decode_type_def_or_ref(5 << 2), 0x0200_0005);
    assert_eq!(decode_type_def_or_ref((10 << 2) | 1), 0x0100_000A);
}

#[test]
fn t36_read_type_sig_primitives() {
    let cases = [
        (0x01u8, TypeSig::Void),
        (0x02, TypeSig::Bool),
        (0x03, TypeSig::Char),
        (0x04, TypeSig::I1),
        (0x05, TypeSig::U1),
        (0x06, TypeSig::I2),
        (0x07, TypeSig::U2),
        (0x08, TypeSig::I4),
        (0x09, TypeSig::U4),
        (0x0A, TypeSig::I8),
        (0x0B, TypeSig::U8),
        (0x0C, TypeSig::R4),
        (0x0D, TypeSig::R8),
        (0x0E, TypeSig::String),
        (0x1C, TypeSig::Object),
    ];
    for (tag, expected) in cases {
        let mut off = 0;
        assert_eq!(read_type_sig(&[tag], &mut off), expected);
    }
}

#[test]
fn t37_read_type_sig_composite() {
    let mut off = 0;
    let s = read_type_sig(&[0x1D, 0x08], &mut off); // SZARRAY I4
    if let TypeSig::Array(inner) = s {
        assert_eq!(*inner, TypeSig::I4);
    } else {
        panic!("expected Array");
    }
    let mut off = 0;
    let s = read_type_sig(&[0x0F, 0x05], &mut off); // PTR U1
    if let TypeSig::Ptr(inner) = s {
        assert_eq!(*inner, TypeSig::U1);
    } else {
        panic!("expected Ptr");
    }
    let mut off = 0;
    let s = read_type_sig(&[0x45, 0x10, 0x08], &mut off); // Pinned ByRef I4
    if let TypeSig::Pinned(_) = s {} else {
        panic!("expected Pinned");
    }
}

#[test]
fn t38_read_type_sig_unknown_and_oob() {
    let mut off = 0;
    assert!(matches!(read_type_sig(&[0xAA], &mut off), TypeSig::Unknown(0xAA)));
    let mut off = 0;
    assert!(matches!(read_type_sig(&[], &mut off), TypeSig::Unknown(0)));
}

#[test]
fn t39_read_type_sig_fuzz() {
    let mut lcg = Lcg::new(lcg_seed());
    for _ in 0..50 {
        let n = (lcg.next() as usize) % 32;
        let buf = lcg.next_bytes(n);
        let mut off = 0;
        let _ = read_type_sig(&buf, &mut off);
    }
}

#[test]
fn t40_cil_type_name_primitives() {
    let pairs = [
        (TypeSig::Void, "void"),
        (TypeSig::Bool, "bool"),
        (TypeSig::Char, "char"),
        (TypeSig::I1, "sbyte"),
        (TypeSig::U1, "byte"),
        (TypeSig::I2, "short"),
        (TypeSig::U2, "ushort"),
        (TypeSig::I4, "int"),
        (TypeSig::U4, "uint"),
        (TypeSig::I8, "long"),
        (TypeSig::U8, "ulong"),
        (TypeSig::R4, "float"),
        (TypeSig::R8, "double"),
        (TypeSig::String, "string"),
        (TypeSig::Object, "object"),
    ];
    for (s, expected) in pairs {
        assert_eq!(cil_type_name(&s, &[], &[]), expected);
    }
}

#[test]
fn t41_cil_type_name_composite() {
    let a = TypeSig::Array(Box::new(TypeSig::I4));
    assert_eq!(cil_type_name(&a, &[], &[]), "int[]");
    let p = TypeSig::Ptr(Box::new(TypeSig::U1));
    assert_eq!(cil_type_name(&p, &[], &[]), "byte*");
    let b = TypeSig::ByRef(Box::new(TypeSig::I4));
    assert_eq!(cil_type_name(&b, &[], &[]), "ref int");
    let pi = TypeSig::Pinned(Box::new(TypeSig::I4));
    assert_eq!(cil_type_name(&pi, &[], &[]), "pinned int");
    assert_eq!(cil_type_name(&TypeSig::Var(2), &[], &[]), "T2");
    assert_eq!(cil_type_name(&TypeSig::MVar(3), &[], &[]), "M3");
    assert!(cil_type_name(&TypeSig::Unknown(0x77), &[], &[]).contains("0x77"));
}

#[test]
fn t42_read_string_heap_oob_and_unterminated() {
    assert_eq!(read_string_heap(b"abc\0def", 0), "abc");
    assert_eq!(read_string_heap(b"abc\0def", 4), "def");
    assert_eq!(read_string_heap(b"abc", 0), "abc"); // no terminator
    assert_eq!(read_string_heap(b"", 0), "");
    assert_eq!(read_string_heap(b"abc\0", 100), "");
}

#[test]
fn t43_resolve_type_name_typedef_typeref() {
    let strings = b"\0Foo\0Bar.Baz\0Quux\0";
    let td = TypeDefRow {
        flags: 0,
        type_name: 1, // "Foo"
        type_namespace: 0,
        extends: 0,
        field_list: 1,
        method_list: 1,
    };
    let tr = TypeRefRow {
        resolution_scope: 0,
        type_name: 13, // "Quux"
        type_namespace: 5, // "Bar.Baz"
    };
    let name_td = resolve_type_name(0x0200_0001, &[td.clone()], &[tr.clone()], strings);
    assert_eq!(name_td, "Foo");
    let name_tr = resolve_type_name(0x0100_0001, &[td], &[tr], strings);
    assert_eq!(name_tr, "Bar.Baz.Quux");
    // out of range token
    assert!(resolve_type_name(0x0200_0099, &[], &[], strings).contains("TypeDef"));
    // unknown table
    assert!(resolve_type_name(0xAB00_0001, &[], &[], strings).contains("token"));
}

#[test]
fn t44_parse_method_body_tiny_all_sizes() {
    for code_len in 0u8..=63 {
        let mut data = vec![((code_len << 2) | 0x02)];
        data.extend(0..code_len);
        let body = parse_method_body(&data, 0).unwrap();
        assert!(!body.is_fat);
        assert_eq!(body.code.len(), code_len as usize);
        assert_eq!(body.max_stack, 8);
        assert_eq!(body.local_var_sig_tok, 0);
    }
}

#[test]
fn t45_parse_method_body_fat_basic() {
    let mut data = vec![0u8; 32];
    data[0] = 0x03;
    data[1] = 0x30; // (3<<12)|3 => header_size 12
    data[2] = 4;
    data[3] = 0; // max_stack=4
    data[4..8].copy_from_slice(&8u32.to_le_bytes()); // code size
    data[8..12].copy_from_slice(&0x1100_0001u32.to_le_bytes()); // local sig
    let body = parse_method_body(&data, 0).unwrap();
    assert!(body.is_fat);
    assert_eq!(body.max_stack, 4);
    assert_eq!(body.code.len(), 8);
    assert_eq!(body.local_var_sig_tok, 0x1100_0001);
    assert!(body.exception_handlers.is_empty());
}

#[test]
fn t46_parse_method_body_invalid_fat_signature() {
    // 12 bytes but flags not 0x03
    let data = vec![0u8; 16];
    assert!(matches!(
        parse_method_body(&data, 0).unwrap_err(),
        DotnetLoaderError::InvalidMethodBody(_)
    ));
}

#[test]
fn t47_parse_method_body_truncated() {
    assert!(matches!(
        parse_method_body(&[], 0).unwrap_err(),
        DotnetLoaderError::InvalidMethodBody(_)
    ));
    // tiny with not enough code
    let data = vec![(5u8 << 2) | 0x02]; // claims 5 bytes
    assert!(matches!(
        parse_method_body(&data, 0).unwrap_err(),
        DotnetLoaderError::TruncatedStream
    ));
    // fat truncated
    let mut data = vec![0u8; 6];
    data[0] = 0x03;
    data[1] = 0x30;
    assert!(matches!(
        parse_method_body(&data, 0).unwrap_err(),
        DotnetLoaderError::TruncatedStream
    ));
}

#[test]
fn t48_parse_method_body_fuzz() {
    let mut lcg = Lcg::new(lcg_seed());
    for _ in 0..80 {
        let n = (lcg.next() as usize) % 64;
        let data = lcg.next_bytes(n);
        let r = parse_method_body(&data, 0);
        match r {
            Ok(_) | Err(_) => {}
        }
    }
}

#[test]
fn t49_exception_clause_type_full() {
    assert_eq!(ExceptionClauseType::from_u32(0), ExceptionClauseType::Catch);
    assert_eq!(ExceptionClauseType::from_u32(1), ExceptionClauseType::Filter);
    assert_eq!(ExceptionClauseType::from_u32(2), ExceptionClauseType::Finally);
    assert_eq!(ExceptionClauseType::from_u32(4), ExceptionClauseType::Fault);
    match ExceptionClauseType::from_u32(99) {
        ExceptionClauseType::Unknown(99) => {}
        _ => panic!(),
    }
    assert_eq!(ExceptionClauseType::Catch.to_string(), "catch");
    assert_eq!(ExceptionClauseType::Filter.to_string(), "filter");
    assert_eq!(ExceptionClauseType::Finally.to_string(), "finally");
    assert_eq!(ExceptionClauseType::Fault.to_string(), "fault");
    assert!(ExceptionClauseType::Unknown(0x77).to_string().contains("0x77"));
}

#[test]
fn t50_typedef_row_flag_helpers() {
    let mk = |flags| TypeDefRow {
        flags,
        type_name: 0,
        type_namespace: 0,
        extends: 0,
        field_list: 1,
        method_list: 1,
    };
    assert!(mk(0x20).is_interface());
    assert!(!mk(0).is_interface());
    assert!(mk(0x80).is_abstract());
    assert!(mk(0x100).is_sealed());
    assert!(mk(0x2).is_nested_public());
    assert!(!mk(0x1).is_nested_public());
}

#[test]
fn t51_methoddef_row_flag_helpers() {
    let mk = |flags| MethodDefRow {
        rva: 0,
        impl_flags: 0,
        flags,
        name: 0,
        signature: 0,
        param_list: 0,
    };
    assert!(mk(0x0400).is_abstract());
    assert!(mk(0x0040).is_virtual());
    assert!(mk(0x0010).is_static());
    assert!(mk(0x0006).is_public());
    assert!(mk(0x0800).is_constructor());
    assert!(!mk(0).is_static());
}

#[test]
fn t52_assembly_row_versions() {
    let a = AssemblyRow {
        hash_alg_id: 0,
        major: u16::MAX,
        minor: 0,
        build: 1,
        revision: 2,
        flags: 0,
        public_key: 0,
        name: 0,
        culture: 0,
    };
    assert_eq!(a.version_string(), format!("{}.0.1.2", u16::MAX));
    let r = AssemblyRefRow {
        major: 1,
        minor: 2,
        build: 3,
        revision: 4,
        flags: 0,
        public_key_or_token: 0,
        name: 0,
        culture: 0,
        hash_value: 0,
    };
    assert_eq!(r.version_string(), "1.2.3.4");
}

#[test]
fn t53_row_eq_hash_pairs() {
    for i in 0u32..30 {
        let a = ModuleRow {
            generation: i as u16,
            name: i,
            mvid: i + 1,
            enc_id: 0,
            enc_base_id: 0,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}

#[test]
fn t54_field_param_constant_member_rows() {
    let f = FieldRow {
        flags: 0,
        name: 1,
        signature: 2,
    };
    assert_eq!(f, f.clone());
    let p = ParamRow {
        flags: 0,
        sequence: 1,
        name: 2,
    };
    assert_eq!(p, p.clone());
    let c = ConstantRow {
        type_: 0x08,
        parent: 1,
        value: 2,
    };
    assert_eq!(c, c.clone());
    let m = MemberRefRow {
        class: 0,
        name: 1,
        signature: 2,
    };
    assert_eq!(m, m.clone());
    let ca = CustomAttributeRow {
        parent: 0,
        type_: 1,
        value: 2,
    };
    assert_eq!(ca, ca.clone());
    let ii = InterfaceImplRow {
        class: 1,
        interface: 2,
    };
    assert_eq!(ii, ii.clone());
    let nc = NestedClassRow {
        nested_class: 1,
        enclosing_class: 2,
    };
    assert_eq!(nc, nc.clone());
    let gp = GenericParamRow {
        number: 0,
        flags: 0,
        owner: 1,
        name: 2,
    };
    assert_eq!(gp, gp.clone());
}

#[test]
fn t55_cil_opcode_class_known() {
    assert_eq!(cil_opcode_class(0x00), CilOpcodeClass::Stack); // nop
    assert_eq!(cil_opcode_class(0x2A), CilOpcodeClass::Call); // ret
    assert_eq!(cil_opcode_class(0x28), CilOpcodeClass::Call); // call
    assert_eq!(cil_opcode_class(0x7A), CilOpcodeClass::Exception); // throw
    assert_eq!(cil_opcode_class(0x58), CilOpcodeClass::Arithmetic); // add
    assert_eq!(cil_opcode_class(0x6F), CilOpcodeClass::Call); // callvirt
    assert_eq!(cil_opcode_class(0x2B), CilOpcodeClass::Branch); // br.s
    assert_eq!(cil_opcode_class(0xFF), CilOpcodeClass::Misc);
}

#[test]
fn t56_cil_opcode_histogram_consistent() {
    let code = [0x00u8, 0x00, 0x2A, 0x58]; // nop, nop, ret, add
    let h = cil_opcode_histogram(&code);
    assert_eq!(h[&CilOpcodeClass::Stack], 2);
    assert_eq!(h[&CilOpcodeClass::Call], 1);
    assert_eq!(h[&CilOpcodeClass::Arithmetic], 1);
}

#[test]
fn t57_cil_opcode_class_all_bytes_no_panic() {
    let mut counts = std::collections::HashMap::new();
    for b in 0u16..=255 {
        let c = cil_opcode_class(b as u8);
        *counts.entry(c).or_insert(0) += 1;
    }
    assert!(counts.values().sum::<u32>() == 256);
}

#[test]
fn t58_parse_tables_stream_truncated() {
    assert!(matches!(
        parse_tables_stream(&[0u8; 23]).unwrap_err(),
        DotnetLoaderError::TruncatedStream
    ));
}

#[test]
fn t59_parse_tables_stream_empty_valid() {
    let mut data = vec![0u8; 24]; // all-zero valid mask -> no tables
    let t = parse_tables_stream(&data).unwrap();
    assert!(t.modules.is_empty());
    assert!(t.type_defs.is_empty());
    // ensure tweak doesn't crash
    data[6] = 0x07; // heap sizes
    let t = parse_tables_stream(&data).unwrap();
    assert!(t.modules.is_empty());
}

#[test]
fn t60_parse_tables_stream_fuzz() {
    let mut lcg = Lcg::new(lcg_seed());
    for _ in 0..30 {
        let n = (lcg.next() as usize) % 256 + 24;
        let buf = lcg.next_bytes(n);
        let _ = parse_tables_stream(&buf);
    }
}

#[test]
fn t61_build_type_hierarchy_basic() {
    let strings = b"\0Class\0Ns\0";
    let td = TypeDefRow {
        flags: 0,
        type_name: 1,
        type_namespace: 7,
        extends: 0,
        field_list: 1,
        method_list: 1,
    };
    let nodes = build_type_hierarchy(&[td], &[], &[], &[], &[], strings);
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].full_name, "Ns.Class");
    assert!(nodes[0].base_type.is_empty());
}

#[test]
fn t62_build_type_hierarchy_with_nested() {
    let strings = b"\0Outer\0Inner\0";
    let td_outer = TypeDefRow {
        flags: 0,
        type_name: 1,
        type_namespace: 0,
        extends: 0,
        field_list: 1,
        method_list: 1,
    };
    let td_inner = TypeDefRow {
        flags: 0,
        type_name: 7,
        type_namespace: 0,
        extends: 0,
        field_list: 1,
        method_list: 1,
    };
    let nc = NestedClassRow {
        nested_class: 2,
        enclosing_class: 1,
    };
    let nodes = build_type_hierarchy(&[td_outer, td_inner], &[], &[], &[nc], &[], strings);
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0].nested_children, vec![1]);
}

#[test]
fn t63_read_method_sig_basic() {
    // calling_conv=0, param_count=1, ret=void(0x01), arg=I4(0x08)
    let blob = [0x00, 0x01, 0x01, 0x08];
    let sig = read_method_sig(&blob);
    assert_eq!(sig.calling_conv, 0);
    assert_eq!(sig.params.len(), 1);
    assert_eq!(sig.ret_type, TypeSig::Void);
    assert_eq!(sig.params[0], TypeSig::I4);
}

#[test]
fn t64_read_method_sig_empty_blob() {
    let sig = read_method_sig(&[]);
    assert_eq!(sig.calling_conv, 0);
    assert_eq!(sig.params.len(), 0);
}

#[test]
fn t65_read_method_sig_generic() {
    // calling_conv with generic flag 0x10, gen_count=2, param_count=0, ret=void
    let blob = [0x10, 0x02, 0x00, 0x01];
    let sig = read_method_sig(&blob);
    assert_eq!(sig.generic_param_count, 2);
    assert_eq!(sig.params.len(), 0);
}

#[test]
fn t66_read_method_sig_fuzz() {
    let mut lcg = Lcg::new(lcg_seed());
    for _ in 0..50 {
        let n = (lcg.next() as usize) % 32;
        let buf = lcg.next_bytes(n);
        let _ = read_method_sig(&buf);
    }
}

#[test]
fn t67_exception_clause_eq() {
    let a = ExceptionClause {
        clause_type: ExceptionClauseType::Catch,
        try_offset: 1,
        try_length: 2,
        handler_offset: 3,
        handler_length: 4,
        class_token_or_filter_offset: 5,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn t68_dotnet_arch_basic() {
    let a = DotnetArch;
    assert_eq!(a.name(), "cil");
    assert_eq!(a.pointer_size(), 8);
    assert!(a.registers().is_empty());
    assert!(a.calling_conventions().is_empty());
    // nop disassembles
    let insn = a.disassemble(Address::new(0), &[0x00]).unwrap();
    assert!(a.get_branches(&insn).is_empty());
}

#[test]
fn t69_loader_basic() {
    let l = DotnetLoader;
    assert_eq!(l.name(), "dotnet");
    assert!(l.can_load(&LoaderInput::new("a.exe", minimal_dotnet())));
    assert!(!l.can_load(&LoaderInput::new("x.bin", b"junk".to_vec())));
}

#[tokio::test]
async fn t70_loader_load_and_nested() {
    let l = DotnetLoader;
    let r = l
        .load(LoaderInput::new("z.exe", minimal_dotnet()))
        .await
        .unwrap();
    assert!(!r.view.entry_points.is_empty());
    let n = l
        .find_nested(&LoaderInput::new("z.exe", minimal_dotnet()))
        .await
        .unwrap();
    assert!(n.is_empty());
}

#[test]
fn t71_send_sync_threaded() {
    let loader = Arc::new(DotnetLoader);
    let mut handles = vec![];
    for _ in 0..4 {
        let l = loader.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let _ = l.name();
                let _ = l.can_load(&LoaderInput::new("a.exe", minimal_dotnet()));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn t72_errors_display() {
    assert!(DotnetLoaderError::NotDotnet.to_string().contains(".NET"));
    assert!(DotnetLoaderError::InvalidMetadata.to_string().contains("metadata"));
    assert!(DotnetLoaderError::TruncatedStream.to_string().contains("truncated"));
    assert!(DotnetLoaderError::InvalidMethodBody(0x1234).to_string().contains("0x00001234"));
    assert!(DotnetLoaderError::UnresolvableRva(0x42).to_string().contains("0x00000042"));
    assert!(DotnetLoaderError::ParseError("x".into()).to_string().contains('x'));
}

#[test]
fn t73_cil_type_name_full_generic_inst() {
    let strings = b"\0Foo`1\0Bar\0";
    let td = TypeDefRow {
        flags: 0,
        type_name: 1,
        type_namespace: 0,
        extends: 0,
        field_list: 1,
        method_list: 1,
    };
    // Generic instance of Foo`1<I4>
    let sig = TypeSig::GenericInst(true, 0x0200_0001, vec![TypeSig::I4]);
    let s = cil_type_name_full(&sig, &[td], &[], strings);
    // base trimmed at backtick
    assert!(s.starts_with("Foo"));
    assert!(s.contains("int"));
}

#[test]
fn t74_method_sig_clone() {
    let s = MethodSig {
        calling_conv: 0,
        generic_param_count: 0,
        ret_type: TypeSig::Void,
        params: vec![TypeSig::I4],
    };
    let c = s;
    assert_eq!(c.params.len(), 1);
}
