//! Exhaustive blitz tests for `rustre-pe-editor`.
//!
//! These tests fabricate minimal valid PE32+ buffers and exercise the public
//! APIs of every editor type. The goal is to surface bugs by stressing
//! boundaries, malformed inputs, round-trips, and currently-unwired APIs.

use rustre_pe_editor::{
    section_chars, CertificateHeader, DosHeader, EditError, ExportEdit, ExportEditor, HeaderField,
    ImportEditor, ImportEntry, Patch, PatchSet, PeEditor, PeField, PeParser, PeSection,
    PeSigningScaffold, PeTreeBuilder, PeTreeNode, Rc4, ResourceEditor, ResourceEntry, ResourceType,
    SectionEdit, SectionEditor, resource_types, xor_section,
};

// ---------------------------------------------------------------------------
// Fixture: minimal PE32+ with one ".text" section.
// Layout:
//   0x000  MZ + DOS header (e_lfanew=0x80)
//   0x080  "PE\0\0"
//   0x084  COFF header (20 bytes), NumberOfSections=1, SizeOfOptionalHeader=0xF0
//   0x098  Optional header PE32+ (0xF0 bytes incl. data dirs)
//   0x188  Section table (40 bytes per section)
//   0x200  raw data for .text (0x200 bytes)
// total: 0x400 bytes
// ---------------------------------------------------------------------------

const PE_OFF: usize = 0x80;
const OPT_OFF: usize = PE_OFF + 24; // 0x98
const SECT_TABLE: usize = OPT_OFF + 0xF0; // 0x188
const RAW_OFF: u32 = 0x200;
const RAW_SZ: u32 = 0x200;
const VA: u32 = 0x1000;
const VSZ: u32 = 0x200;
const FILE_SIZE: usize = 0x400;

fn make_pe() -> Vec<u8> {
    let mut data = vec![0u8; FILE_SIZE];
    // DOS
    data[0] = b'M';
    data[1] = b'Z';
    data[0x3C..0x40].copy_from_slice(&(PE_OFF as u32).to_le_bytes());
    // PE sig
    data[PE_OFF..PE_OFF + 4].copy_from_slice(b"PE\0\0");
    // COFF: machine AMD64 = 0x8664, NumberOfSections = 1
    data[PE_OFF + 4] = 0x64;
    data[PE_OFF + 5] = 0x86;
    data[PE_OFF + 6] = 1;
    data[PE_OFF + 7] = 0;
    // SizeOfOptionalHeader = 0xF0
    data[PE_OFF + 20] = 0xF0;
    data[PE_OFF + 21] = 0x00;
    // Characteristics
    data[PE_OFF + 22] = 0x22;
    data[PE_OFF + 23] = 0x00;
    // Optional header magic = 0x020B (PE32+)
    data[OPT_OFF] = 0x0B;
    data[OPT_OFF + 1] = 0x02;
    // SectionAlignment (offset +32) = 0x1000
    data[OPT_OFF + 32..OPT_OFF + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    // FileAlignment (offset +36) = 0x200
    data[OPT_OFF + 36..OPT_OFF + 40].copy_from_slice(&0x200u32.to_le_bytes());
    // SizeOfImage (+56) = 0x2000
    data[OPT_OFF + 56..OPT_OFF + 60].copy_from_slice(&0x2000u32.to_le_bytes());
    // SizeOfHeaders (+60) = 0x200
    data[OPT_OFF + 60..OPT_OFF + 64].copy_from_slice(&0x200u32.to_le_bytes());
    // NumberOfRvaAndSizes (+108) = 16
    data[OPT_OFF + 108..OPT_OFF + 112].copy_from_slice(&16u32.to_le_bytes());
    // Section header at SECT_TABLE for ".text"
    let s = SECT_TABLE;
    data[s..s + 5].copy_from_slice(b".text");
    // VirtualSize +8
    data[s + 8..s + 12].copy_from_slice(&VSZ.to_le_bytes());
    // VirtualAddress +12
    data[s + 12..s + 16].copy_from_slice(&VA.to_le_bytes());
    // SizeOfRawData +16
    data[s + 16..s + 20].copy_from_slice(&RAW_SZ.to_le_bytes());
    // PointerToRawData +20
    data[s + 20..s + 24].copy_from_slice(&RAW_OFF.to_le_bytes());
    // Characteristics +36 — code | execute | read
    let chars: u32 = section_chars::CODE | section_chars::MEM_EXECUTE | section_chars::MEM_READ;
    data[s + 36..s + 40].copy_from_slice(&chars.to_le_bytes());
    // Fill .text with marker bytes
    for (i, b) in data[RAW_OFF as usize..RAW_OFF as usize + RAW_SZ as usize]
        .iter_mut()
        .enumerate()
    {
        *b = (i & 0xFF) as u8;
    }
    data
}

// ---------------------------------------------------------------------------
// Patch / PatchSet
// ---------------------------------------------------------------------------

#[test]
fn patch_simple_constructor() {
    let p = Patch::simple(0x10, vec![1, 2, 3], "test".to_string());
    assert_eq!(p.offset, 0x10);
    assert_eq!(p.len(), 3);
    assert!(!p.is_empty());
    assert!(!p.has_verification());
    assert!(p.original.is_empty());
}

#[test]
fn patch_verified_constructor() {
    let p = Patch::verified(0, vec![0xAA], vec![0xBB], "v".to_string());
    assert!(p.has_verification());
    assert_eq!(p.original, vec![0xAA]);
    assert_eq!(p.replacement, vec![0xBB]);
}

#[test]
fn patch_is_empty_for_empty_replacement() {
    let p = Patch::simple(0, vec![], "e".to_string());
    assert!(p.is_empty());
    assert_eq!(p.len(), 0);
}

#[test]
fn patch_display_contains_offset_and_description() {
    let p = Patch::simple(0x1234, vec![0, 1, 2, 3], "hello".to_string());
    let s = format!("{p}");
    assert!(s.contains("0x1234"));
    assert!(s.contains("hello"));
    assert!(s.contains("4"));
}

#[test]
fn patchset_new_is_empty() {
    let ps = PatchSet::new("x".to_string());
    assert_eq!(ps.len(), 0);
    assert!(ps.is_empty());
    assert_eq!(ps.total_bytes(), 0);
    assert_eq!(ps.name, "x");
}

#[test]
fn patchset_add_and_total_bytes() {
    let mut ps = PatchSet::new("set".to_string());
    ps.add(Patch::simple(0, vec![1, 2], "a".to_string()));
    ps.add(Patch::simple(2, vec![3, 4, 5], "b".to_string()));
    assert_eq!(ps.len(), 2);
    assert!(!ps.is_empty());
    assert_eq!(ps.total_bytes(), 5);
}

#[test]
fn patchset_display_contains_name_and_count() {
    let mut ps = PatchSet::new("myset".to_string());
    ps.add(Patch::simple(0, vec![1], String::new()));
    let s = format!("{ps}");
    assert!(s.contains("myset"));
    assert!(s.contains("1"));
}

// ---------------------------------------------------------------------------
// PeEditor — construction / IO
// ---------------------------------------------------------------------------

#[test]
fn pe_editor_new_rejects_too_short() {
    let r = PeEditor::new(vec![0u8; 10]);
    assert!(matches!(r, Err(EditError::Pe(_))));
}

#[test]
fn pe_editor_new_rejects_non_mz() {
    let mut d = vec![0u8; 256];
    d[0] = b'X';
    d[1] = b'X';
    let r = PeEditor::new(d);
    assert!(matches!(r, Err(EditError::Pe(_))));
}

#[test]
fn pe_editor_new_accepts_minimal_pe() {
    let r = PeEditor::new(make_pe());
    assert!(r.is_ok(), "{:?}", r.err());
}

#[test]
fn pe_editor_bytes_and_into_bytes_roundtrip() {
    let data = make_pe();
    let editor = PeEditor::new(data.clone()).unwrap();
    assert_eq!(editor.bytes(), data.as_slice());
    let back = editor.into_bytes();
    assert_eq!(back, data);
}

#[test]
fn pe_editor_debug_contains_size() {
    let editor = PeEditor::new(make_pe()).unwrap();
    let s = format!("{editor:?}");
    assert!(s.contains(&FILE_SIZE.to_string()));
}

// ---------------------------------------------------------------------------
// apply_patch / nop_range / int3_range / write_bytes / read_bytes
// ---------------------------------------------------------------------------

#[test]
fn apply_patch_writes_bytes() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    e.apply_patch(Patch::simple(0x200, vec![0xDE, 0xAD], "x".into()))
        .unwrap();
    assert_eq!(&e.bytes()[0x200..0x202], &[0xDE, 0xAD]);
    assert_eq!(e.applied_count(), 1);
    assert_eq!(e.applied_patches().len(), 1);
}

#[test]
fn apply_patch_out_of_bounds() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    let r = e.apply_patch(Patch::simple(FILE_SIZE - 1, vec![0, 0, 0], "oob".into()));
    match r {
        Err(EditError::PatchOutOfBounds { offset, len, file_size }) => {
            assert_eq!(offset, FILE_SIZE - 1);
            assert_eq!(len, 3);
            assert_eq!(file_size, FILE_SIZE);
        }
        other => panic!("expected PatchOutOfBounds, got {other:?}"),
    }
}

#[test]
fn apply_patch_exact_end_succeeds() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    let r = e.apply_patch(Patch::simple(FILE_SIZE - 4, vec![1, 2, 3, 4], "edge".into()));
    assert!(r.is_ok());
}

#[test]
fn apply_patch_zero_length_at_end_ok() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    let r = e.apply_patch(Patch::simple(FILE_SIZE, vec![], "empty-at-end".into()));
    // offset == len, length 0 — should be in bounds
    assert!(r.is_ok());
}

#[test]
fn apply_patchset_in_order() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    let mut ps = PatchSet::new("set".into());
    ps.add(Patch::simple(0x200, vec![0xAA], "a".into()));
    ps.add(Patch::simple(0x201, vec![0xBB], "b".into()));
    e.apply_patchset(ps).unwrap();
    assert_eq!(&e.bytes()[0x200..0x202], &[0xAA, 0xBB]);
    assert_eq!(e.applied_count(), 2);
}

#[test]
fn nop_range_fills_0x90() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    e.nop_range(0x200, 8).unwrap();
    assert_eq!(&e.bytes()[0x200..0x208], &[0x90; 8]);
}

#[test]
fn nop_range_oob() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    assert!(matches!(
        e.nop_range(FILE_SIZE - 1, 5),
        Err(EditError::PatchOutOfBounds { .. })
    ));
}

#[test]
fn int3_range_fills_cc() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    e.int3_range(0x200, 4).unwrap();
    assert_eq!(&e.bytes()[0x200..0x204], &[0xCC; 4]);
}

#[test]
fn int3_range_oob() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    assert!(matches!(
        e.int3_range(FILE_SIZE - 1, 5),
        Err(EditError::PatchOutOfBounds { .. })
    ));
}

#[test]
fn write_bytes_then_read_bytes_roundtrip() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    e.write_bytes(0x200, &[1, 2, 3, 4]).unwrap();
    let got = e.read_bytes(0x200, 4).unwrap();
    assert_eq!(got, &[1, 2, 3, 4]);
}

#[test]
fn read_bytes_oob() {
    let e = PeEditor::new(make_pe()).unwrap();
    assert!(matches!(
        e.read_bytes(FILE_SIZE - 1, 5),
        Err(EditError::PatchOutOfBounds { .. })
    ));
}

// ---------------------------------------------------------------------------
// patch_entry_point / zero_checksum / set_aslr / set_nx / image_base / subsystem
// ---------------------------------------------------------------------------

#[test]
fn patch_entry_point_writes_at_opt_plus_16() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    e.patch_entry_point(0xCAFE_BABE).unwrap();
    let ep = u32::from_le_bytes(e.bytes()[OPT_OFF + 16..OPT_OFF + 20].try_into().unwrap());
    assert_eq!(ep, 0xCAFE_BABE);
}

#[test]
fn zero_checksum_clears_field() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    // pre-populate
    e.write_bytes(OPT_OFF + 64, &[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
    e.zero_checksum().unwrap();
    assert_eq!(&e.bytes()[OPT_OFF + 64..OPT_OFF + 68], &[0, 0, 0, 0]);
}

#[test]
fn set_aslr_toggle_bit() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    e.set_aslr(true).unwrap();
    let dc = u16::from_le_bytes([e.bytes()[OPT_OFF + 70], e.bytes()[OPT_OFF + 71]]);
    assert_eq!(dc & 0x0040, 0x0040);
    e.set_aslr(false).unwrap();
    let dc = u16::from_le_bytes([e.bytes()[OPT_OFF + 70], e.bytes()[OPT_OFF + 71]]);
    assert_eq!(dc & 0x0040, 0);
}

#[test]
fn set_nx_toggle_bit() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    e.set_nx(true).unwrap();
    let dc = u16::from_le_bytes([e.bytes()[OPT_OFF + 70], e.bytes()[OPT_OFF + 71]]);
    assert_eq!(dc & 0x0100, 0x0100);
}

#[test]
fn set_image_base_64bit() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    e.set_image_base(0x0000_0001_4000_0000).unwrap();
    let base = u64::from_le_bytes(e.bytes()[OPT_OFF + 24..OPT_OFF + 32].try_into().unwrap());
    assert_eq!(base, 0x0000_0001_4000_0000);
}

#[test]
fn set_subsystem_writes_field() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    e.set_subsystem(3).unwrap();
    let sub = u16::from_le_bytes([e.bytes()[OPT_OFF + 68], e.bytes()[OPT_OFF + 69]]);
    assert_eq!(sub, 3);
}

// ---------------------------------------------------------------------------
// XOR / RC4
// ---------------------------------------------------------------------------

#[test]
fn xor_section_inverse() {
    let key = b"K3y";
    let mut data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let orig = data.clone();
    xor_section(&mut data, key);
    assert_ne!(data, orig);
    xor_section(&mut data, key);
    assert_eq!(data, orig);
}

#[test]
#[should_panic(expected = "xor key must not be empty")]
fn xor_section_empty_key_panics() {
    let mut data = vec![1, 2, 3];
    xor_section(&mut data, &[]);
}

#[test]
fn xor_section_empty_data_ok() {
    let mut data: Vec<u8> = vec![];
    xor_section(&mut data, b"key");
    assert!(data.is_empty());
}

#[test]
fn rc4_round_trip() {
    let key = b"secret";
    let plain: Vec<u8> = (0..=255u8).collect();
    let mut buf = plain.clone();
    Rc4::new(key).process(&mut buf);
    assert_ne!(buf, plain);
    Rc4::new(key).process(&mut buf);
    assert_eq!(buf, plain);
}

#[test]
#[should_panic(expected = "RC4 key must not be empty")]
fn rc4_empty_key_panics() {
    let _ = Rc4::new(&[]);
}

#[test]
fn rc4_next_byte_progresses() {
    let mut rc = Rc4::new(b"k");
    let a = rc.next_byte();
    let b = rc.next_byte();
    // RC4 stream of "k" produces 0x42, 0xb1, ... — just check they differ
    assert_ne!(a, b);
}

#[test]
fn pe_editor_xor_encrypt_section_inverse() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    let pre: Vec<u8> = e.bytes()[RAW_OFF as usize..(RAW_OFF + RAW_SZ) as usize].to_vec();
    e.xor_encrypt_section(".text", b"abc").unwrap();
    let mid: Vec<u8> = e.bytes()[RAW_OFF as usize..(RAW_OFF + RAW_SZ) as usize].to_vec();
    assert_ne!(pre, mid);
    e.xor_decrypt_section(".text", b"abc").unwrap();
    let post: Vec<u8> = e.bytes()[RAW_OFF as usize..(RAW_OFF + RAW_SZ) as usize].to_vec();
    assert_eq!(pre, post);
}

#[test]
fn pe_editor_rc4_encrypt_section_changes_bytes() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    let pre: Vec<u8> = e.bytes()[RAW_OFF as usize..(RAW_OFF + RAW_SZ) as usize].to_vec();
    e.rc4_encrypt_section(".text", b"k").unwrap();
    let post: Vec<u8> = e.bytes()[RAW_OFF as usize..(RAW_OFF + RAW_SZ) as usize].to_vec();
    assert_ne!(pre, post);
}

#[test]
fn pe_editor_xor_unknown_section() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    let r = e.xor_encrypt_section(".nope", b"k");
    assert!(matches!(r, Err(EditError::SectionNotFound(_))));
}

// ---------------------------------------------------------------------------
// SectionEditor
// ---------------------------------------------------------------------------

#[test]
fn section_editor_new_rejects_invalid() {
    assert!(SectionEditor::new(vec![0u8; 5]).is_err());
}

#[test]
fn section_editor_rename() {
    let mut se = SectionEditor::new(make_pe()).unwrap();
    se.rename_section(".text", ".code").unwrap();
    let name = &se.bytes()[SECT_TABLE..SECT_TABLE + 8];
    assert_eq!(&name[..5], b".code");
    assert_eq!(name[5], 0);
}

#[test]
fn section_editor_rename_truncates_to_8() {
    let mut se = SectionEditor::new(make_pe()).unwrap();
    se.rename_section(".text", "ABCDEFGHIJ").unwrap();
    let name = &se.bytes()[SECT_TABLE..SECT_TABLE + 8];
    assert_eq!(name, b"ABCDEFGH");
}

#[test]
fn section_editor_rename_missing() {
    let mut se = SectionEditor::new(make_pe()).unwrap();
    assert!(matches!(
        se.rename_section(".nope", ".x"),
        Err(EditError::SectionNotFound(_))
    ));
}

#[test]
fn section_editor_set_characteristics() {
    let mut se = SectionEditor::new(make_pe()).unwrap();
    se.set_characteristics(".text", 0xDEAD_BEEF).unwrap();
    let v = u32::from_le_bytes(
        se.bytes()[SECT_TABLE + 36..SECT_TABLE + 40]
            .try_into()
            .unwrap(),
    );
    assert_eq!(v, 0xDEAD_BEEF);
}

#[test]
fn section_editor_zero_section() {
    let mut se = SectionEditor::new(make_pe()).unwrap();
    se.zero_section(".text").unwrap();
    assert!(se.bytes()[RAW_OFF as usize..(RAW_OFF + RAW_SZ) as usize]
        .iter()
        .all(|&b| b == 0));
}

#[test]
fn section_editor_read_section_returns_raw_data() {
    let se = SectionEditor::new(make_pe()).unwrap();
    let s = se.read_section(".text").unwrap();
    assert_eq!(s.len(), RAW_SZ as usize);
    assert_eq!(s[0], 0);
    assert_eq!(s[1], 1);
}

#[test]
fn section_editor_write_into_section_ok() {
    let mut se = SectionEditor::new(make_pe()).unwrap();
    se.write_into_section(".text", 0, &[0xAA, 0xBB]).unwrap();
    assert_eq!(&se.bytes()[RAW_OFF as usize..RAW_OFF as usize + 2], &[0xAA, 0xBB]);
}

#[test]
fn section_editor_write_into_section_oob() {
    let mut se = SectionEditor::new(make_pe()).unwrap();
    let r = se.write_into_section(".text", (RAW_SZ - 1) as usize, &[1, 2, 3]);
    assert!(matches!(r, Err(EditError::PatchOutOfBounds { .. })));
}

#[test]
fn section_editor_debug_includes_size() {
    let se = SectionEditor::new(make_pe()).unwrap();
    let s = format!("{se:?}");
    assert!(s.contains(&FILE_SIZE.to_string()));
}

#[test]
fn section_edit_set_chars_constructor() {
    let e = SectionEdit::set_chars("x".into(), 0xF0);
    assert_eq!(e.new_characteristics, Some(0xF0));
    assert!(!e.zero_out);
    assert!(e.append_bytes.is_empty());
}

#[test]
fn section_edit_zero_constructor() {
    let e = SectionEdit::zero("x".into());
    assert!(e.zero_out);
    assert!(e.new_characteristics.is_none());
}

// ---------------------------------------------------------------------------
// ImportEditor / ImportEntry
// ---------------------------------------------------------------------------

#[test]
fn import_entry_named_and_ordinal() {
    let n = ImportEntry::named("k32.dll".into(), "GetProcAddress".into(), 0);
    assert!(n.is_named());
    assert_eq!(n.display(), "k32.dll!GetProcAddress");

    let o = ImportEntry::ordinal("k32.dll".into(), 17);
    assert!(!o.is_named());
    assert_eq!(o.display(), "k32.dll!#17");
}

#[test]
fn import_entry_display_via_fmt() {
    let n = ImportEntry::named("user32.dll".into(), "MessageBoxA".into(), 0);
    let s = format!("{n}");
    assert_eq!(s, "user32.dll!MessageBoxA");
}

#[test]
fn import_editor_lifecycle() {
    let mut ie = ImportEditor::new();
    assert_eq!(ie.pending_additions(), 0);
    assert_eq!(ie.pending_removals(), 0);
    ie.add_import(ImportEntry::named(
        "a.dll".into(),
        "foo".into(),
        0,
    ));
    ie.remove_dll("b.dll".into());
    assert_eq!(ie.pending_additions(), 1);
    assert_eq!(ie.pending_removals(), 1);
    assert_eq!(ie.additions().len(), 1);
    assert_eq!(ie.removals().len(), 1);
    ie.clear();
    assert_eq!(ie.pending_additions(), 0);
    assert_eq!(ie.pending_removals(), 0);
}

#[test]
fn import_editor_default() {
    let ie = ImportEditor::default();
    assert_eq!(ie.pending_additions(), 0);
}

#[test]
fn import_editor_debug_format() {
    let mut ie = ImportEditor::new();
    ie.add_import(ImportEntry::named("a.dll".into(), "f".into(), 0));
    ie.remove_dll("b.dll".into());
    let s = format!("{ie:?}");
    assert!(s.contains("+1"));
    assert!(s.contains("-1"));
}

#[test]
fn import_editor_apply_no_additions_returns_zero() {
    let ie = ImportEditor::new();
    let mut data = make_pe();
    let r = ie.apply(&mut data).unwrap();
    assert_eq!(r, 0);
}

#[test]
fn import_editor_apply_adds_section_and_returns_count() {
    let mut ie = ImportEditor::new();
    ie.add_import(ImportEntry::named(
        "kernel32.dll".into(),
        "GetProcAddress".into(),
        0,
    ));
    ie.add_import(ImportEntry::named(
        "kernel32.dll".into(),
        "LoadLibraryA".into(),
        0,
    ));
    let mut data = make_pe();
    let before = data.len();
    let n = ie.apply(&mut data).unwrap();
    assert_eq!(n, 2);
    assert!(data.len() > before);
}

#[test]
fn import_editor_apply_too_short_buffer() {
    let ie = {
        let mut x = ImportEditor::new();
        x.add_import(ImportEntry::named("a".into(), "b".into(), 0));
        x
    };
    let mut data = vec![0u8; 10];
    assert!(matches!(ie.apply(&mut data), Err(EditError::ImportError(_))));
}

// ---------------------------------------------------------------------------
// ExportEditor / ExportEdit
// ---------------------------------------------------------------------------

#[test]
fn export_edit_add_and_remove_constructors() {
    let a = ExportEdit::add("foo".into(), 1, 0x1000);
    assert!(!a.remove);
    assert_eq!(a.ordinal, 1);
    assert_eq!(a.rva, 0x1000);
    let r = ExportEdit::remove("foo".into());
    assert!(r.remove);
    assert_eq!(r.ordinal, 0);
    assert_eq!(r.rva, 0);
}

#[test]
fn export_edit_display() {
    let a = ExportEdit::add("foo".into(), 1, 0x1000);
    assert_eq!(format!("{a}"), "Add export: foo ord=1 rva=0x1000");
    let r = ExportEdit::remove("foo".into());
    assert_eq!(format!("{r}"), "Remove export: foo");
}

#[test]
fn export_editor_lifecycle() {
    let mut ee = ExportEditor::new("mydll.dll".into());
    assert_eq!(ee.dll_name(), "mydll.dll");
    assert_eq!(ee.pending_count(), 0);
    ee.add_export("foo".into(), 1, 0x1000);
    ee.add_export("bar".into(), 2, 0x2000);
    ee.remove_export("baz".into());
    assert_eq!(ee.pending_count(), 3);
    assert_eq!(ee.additions().len(), 2);
    assert_eq!(ee.removals().len(), 1);
    ee.clear();
    assert_eq!(ee.pending_count(), 0);
}

#[test]
fn export_editor_debug() {
    let mut ee = ExportEditor::new("d".into());
    ee.add_export("f".into(), 0, 0);
    let s = format!("{ee:?}");
    assert!(s.contains("d"));
    assert!(s.contains("edits: 1"));
}

// ---------------------------------------------------------------------------
// ResourceEditor / ResourceEntry / ResourceType
// ---------------------------------------------------------------------------

#[test]
fn resource_type_display() {
    assert_eq!(format!("{}", ResourceType::Id(24)), "#24");
    assert_eq!(format!("{}", ResourceType::Name("FOO".into())), "FOO");
}

#[test]
fn resource_type_eq_hash_id() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(ResourceType::Id(3));
    s.insert(ResourceType::Id(3));
    assert_eq!(s.len(), 1);
    s.insert(ResourceType::Name("X".into()));
    assert_eq!(s.len(), 2);
}

#[test]
fn resource_entry_new_and_manifest() {
    let e = ResourceEntry::new(resource_types::RT_VERSION, 1, 0x0409, vec![1, 2, 3]);
    assert_eq!(e.len(), 3);
    assert!(!e.is_empty());
    let m = ResourceEntry::manifest(vec![]);
    assert!(m.is_empty());
    assert_eq!(m.resource_type, ResourceType::Id(24));
    assert_eq!(m.id, 1);
    assert_eq!(m.language, 0x0409);
}

#[test]
fn resource_entry_display() {
    let e = ResourceEntry::new(3, 5, 0x0409, vec![1, 2, 3, 4]);
    let s = format!("{e}");
    assert!(s.contains("#3"));
    assert!(s.contains("id=5"));
    assert!(s.contains("size=4"));
}

#[test]
fn resource_editor_lifecycle() {
    let mut re = ResourceEditor::new();
    assert_eq!(re.pending_additions(), 0);
    assert_eq!(re.pending_removals(), 0);
    re.add_resource(ResourceEntry::manifest(vec![0u8; 100]));
    re.add_resource(ResourceEntry::new(3, 1, 0x0409, vec![0u8; 50]));
    re.remove_resource(ResourceType::Id(3), 2);
    assert_eq!(re.pending_additions(), 2);
    assert_eq!(re.pending_removals(), 1);
    assert_eq!(re.total_data_size(), 150);
    assert_eq!(re.additions().len(), 2);
    re.clear();
    assert_eq!(re.pending_additions(), 0);
}

#[test]
fn resource_editor_default_and_debug() {
    let re = ResourceEditor::default();
    let s = format!("{re:?}");
    assert!(s.contains("+0"));
    assert!(s.contains("-0"));
}

// ---------------------------------------------------------------------------
// CertificateHeader / PeSigningScaffold
// ---------------------------------------------------------------------------

#[test]
fn certificate_header_new_layout() {
    let h = CertificateHeader::new(100);
    assert_eq!(h.dw_length, 108);
    assert_eq!(h.w_revision, 0x0200);
    assert_eq!(h.w_certificate_type, 0x0002);
}

#[test]
fn certificate_header_to_bytes_roundtrip() {
    let h = CertificateHeader::new(0x10);
    let b = h.to_bytes();
    assert_eq!(&b[0..4], &24u32.to_le_bytes());
    assert_eq!(&b[4..6], &0x0200u16.to_le_bytes());
    assert_eq!(&b[6..8], &0x0002u16.to_le_bytes());
}

#[test]
fn signing_scaffold_payload_len() {
    let s = PeSigningScaffold::new(vec![0u8; 17]);
    assert_eq!(s.payload_len(), 17);
}

#[test]
fn signing_scaffold_blob_is_8_byte_aligned() {
    let s = PeSigningScaffold::new(vec![0u8; 13]);
    let blob = s.build_certificate_blob();
    assert_eq!(blob.len() % 8, 0);
    assert!(blob.len() >= 8 + 13);
}

#[test]
fn signing_scaffold_inject_updates_dd4() {
    let mut data = make_pe();
    let before_len = data.len();
    let s = PeSigningScaffold::new(vec![0xAA; 32]);
    s.inject(&mut data).unwrap();
    assert!(data.len() > before_len);
    // DataDirectory[4] for PE32+ is at opt_off + 112 + 32
    let dd4 = OPT_OFF + 112 + 4 * 8;
    let rva = u32::from_le_bytes(data[dd4..dd4 + 4].try_into().unwrap());
    let size = u32::from_le_bytes(data[dd4 + 4..dd4 + 8].try_into().unwrap());
    assert_eq!(rva as usize, before_len);
    assert!(size >= 8 + 32);
}

#[test]
fn signing_scaffold_inject_too_short() {
    let mut d = vec![0u8; 10];
    let s = PeSigningScaffold::new(vec![]);
    assert!(matches!(s.inject(&mut d), Err(EditError::SignError(_))));
}

// ---------------------------------------------------------------------------
// HeaderField (Display + Eq)
// ---------------------------------------------------------------------------

#[test]
fn header_field_display_and_eq() {
    assert_eq!(HeaderField::Subsystem, HeaderField::Subsystem);
    assert_ne!(HeaderField::Subsystem, HeaderField::DllCharacteristics);
    assert_eq!(format!("{}", HeaderField::Subsystem), "Subsystem");
}

// ---------------------------------------------------------------------------
// PeParser
// ---------------------------------------------------------------------------

#[test]
fn parser_dos_header_ok() {
    let data = make_pe();
    let dos = PeParser::parse_dos_header(&data).unwrap();
    assert_eq!(dos.e_magic, 0x5A4D);
    assert_eq!(dos.e_lfanew as usize, PE_OFF);
}

#[test]
fn parser_dos_header_too_short() {
    let r = PeParser::parse_dos_header(&[0u8; 10]);
    assert!(matches!(
        r,
        Err(rustre_pe_editor::ParseError::TooShort { needed: 64, got: 10 })
    ));
}

#[test]
fn parser_dos_header_bad_magic() {
    let mut d = vec![0u8; 64];
    d[0] = b'X';
    d[1] = b'Y';
    let r = PeParser::parse_dos_header(&d);
    assert!(matches!(
        r,
        Err(rustre_pe_editor::ParseError::InvalidDosMagic(_))
    ));
}

#[test]
fn parser_file_header_ok() {
    let data = make_pe();
    let fh = PeParser::parse_file_header(&data, PE_OFF + 4).unwrap();
    assert_eq!(fh.number_of_sections, 1);
    assert_eq!(fh.size_of_optional_header, 0xF0);
    assert_eq!(fh.machine, 0x8664);
}

#[test]
fn parser_file_header_too_short() {
    let data = vec![0u8; 5];
    let r = PeParser::parse_file_header(&data, 0);
    assert!(matches!(
        r,
        Err(rustre_pe_editor::ParseError::TooShort { .. })
    ));
}

#[test]
fn parser_optional_header64_ok() {
    let data = make_pe();
    let oh = PeParser::parse_optional_header64(&data, OPT_OFF).unwrap();
    assert_eq!(oh.magic, 0x020B);
    assert_eq!(oh.file_alignment, 0x200);
    assert_eq!(oh.section_alignment, 0x1000);
    assert_eq!(oh.number_of_rva_and_sizes, 16);
}

#[test]
fn parser_optional_header64_wrong_magic() {
    let mut data = make_pe();
    data[OPT_OFF] = 0x0B;
    data[OPT_OFF + 1] = 0x01; // PE32
    let r = PeParser::parse_optional_header64(&data, OPT_OFF);
    assert!(matches!(
        r,
        Err(rustre_pe_editor::ParseError::MalformedHeader(_))
    ));
}

#[test]
fn parser_sections_ok() {
    let data = make_pe();
    let secs = PeParser::parse_sections(&data, SECT_TABLE, 1).unwrap();
    assert_eq!(secs.len(), 1);
    assert_eq!(secs[0].name, ".text");
    assert_eq!(secs[0].virtual_address, VA);
    assert_eq!(secs[0].size_of_raw_data, RAW_SZ);
}

#[test]
fn parser_sections_too_short() {
    let data = vec![0u8; 10];
    let r = PeParser::parse_sections(&data, 0, 5);
    assert!(matches!(
        r,
        Err(rustre_pe_editor::ParseError::TooShort { .. })
    ));
}

// ---------------------------------------------------------------------------
// PeTreeBuilder
// ---------------------------------------------------------------------------

#[test]
fn tree_builder_unknown_yields_stub() {
    let t = PeTreeBuilder::build_tree(&[1u8; 4]);
    assert_eq!(t.sections.len(), 1);
    assert_eq!(t.sections[0].name, "Unknown");
}

#[test]
fn tree_builder_valid_pe_has_known_top_nodes() {
    let data = make_pe();
    let t = PeTreeBuilder::build_tree(&data);
    assert!(t.find("DOS Header").is_some());
    assert!(t.find("NT Headers").is_some());
    assert!(t.find("Section Table").is_some());
    assert!(t.find("Data Directories").is_some());
}

#[test]
fn tree_node_total_fields_recursive() {
    let mut root = PeTreeNode::leaf("root", 0, 0);
    root.fields.push(PeField::new("a", 1, "x"));
    let mut child = PeTreeNode::leaf("c", 0, 0);
    child.fields.push(PeField::new("b", 2, "y"));
    child.fields.push(PeField::new("c", 3, "z"));
    root.children.push(child);
    assert_eq!(root.total_fields(), 3);
}

#[test]
fn tree_node_display() {
    let n = PeTreeNode::leaf("X", 0x40, 16);
    let s = format!("{n}");
    assert!(s.contains("X"));
    assert!(s.contains("0x40"));
    assert!(s.contains("16B"));
}

#[test]
fn pe_field_display() {
    let f = PeField::new("Magic", 0x5A4D, "MZ");
    let s = format!("{f}");
    assert!(s.contains("Magic"));
    assert!(s.contains("0x5a4d"));
    assert!(s.contains("MZ"));
}

#[test]
fn tree_dos_header_node_fields_count() {
    let data = make_pe();
    let dos = PeParser::parse_dos_header(&data).unwrap();
    let node = PeTreeBuilder::dos_header_node(&dos);
    // 17 fields per implementation
    assert_eq!(node.fields.len(), 17);
    assert_eq!(node.name, "DOS Header");
}

#[test]
fn tree_data_directories_for_pe32plus() {
    let data = make_pe();
    let node = PeTreeBuilder::data_directories_node(&data, OPT_OFF);
    // 16 directories
    assert_eq!(node.children.len(), 16);
    assert_eq!(node.children[0].name, "Export Table");
    assert_eq!(node.children[1].name, "Import Table");
}

// ---------------------------------------------------------------------------
// PeEditor higher-level: parse_current, edit_log, rva_in_section, recalculate_checksum
// ---------------------------------------------------------------------------

#[test]
fn parse_current_roundtrips() {
    let e = PeEditor::new(make_pe()).unwrap();
    assert!(e.parse_current().is_ok());
}

#[test]
fn edit_log_grows_with_operations() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    assert!(e.edit_log().is_empty());
    e.nop_range(0x200, 4).unwrap();
    e.patch_entry_point(0).unwrap();
    let log = e.edit_log();
    assert!(log.len() >= 2);
}

#[test]
fn rva_in_section_true_for_text_range() {
    let e = PeEditor::new(make_pe()).unwrap();
    let r = e.rva_in_section(VA + 0x10).unwrap();
    assert!(r);
}

#[test]
fn rva_in_section_false_outside() {
    let e = PeEditor::new(make_pe()).unwrap();
    let r = e.rva_in_section(0xFFFF_0000).unwrap();
    assert!(!r);
}

#[test]
fn recalculate_checksum_returns_nonzero_for_real_data() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    let cs = e.recalculate_checksum().unwrap();
    // checksum field updated
    let stored = u32::from_le_bytes(e.bytes()[OPT_OFF + 64..OPT_OFF + 68].try_into().unwrap());
    assert_eq!(stored, cs);
}

#[test]
fn recalculate_checksum_idempotent_after_zero() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    e.zero_checksum().unwrap();
    let a = e.recalculate_checksum().unwrap();
    let b = e.recalculate_checksum().unwrap();
    assert_eq!(a, b, "checksum recalc should be idempotent");
}

// ---------------------------------------------------------------------------
// PeSection wrapper
// ---------------------------------------------------------------------------

#[test]
fn pe_section_rename_via_wrapper() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    {
        let mut s = PeSection::new(&mut e);
        s.rename_section(".text", ".X").unwrap();
    }
    let name = &e.bytes()[SECT_TABLE..SECT_TABLE + 8];
    assert_eq!(&name[..2], b".X");
}

#[test]
fn pe_section_rename_missing_errors() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    let mut s = PeSection::new(&mut e);
    assert!(matches!(
        s.rename_section(".no", ".y"),
        Err(EditError::SectionNotFound(_))
    ));
}

#[test]
fn pe_section_set_section_data_truncates() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    let big = vec![0x55u8; (RAW_SZ + 100) as usize];
    {
        let mut s = PeSection::new(&mut e);
        s.set_section_data(".text", &big).unwrap();
    }
    // VirtualSize updated to write_len (= raw_sz, since data > raw_sz)
    let vs = u32::from_le_bytes(e.bytes()[SECT_TABLE + 8..SECT_TABLE + 12].try_into().unwrap());
    assert_eq!(vs, RAW_SZ);
}

#[test]
fn pe_section_set_section_data_small_zeroes_rest() {
    let mut e = PeEditor::new(make_pe()).unwrap();
    {
        let mut s = PeSection::new(&mut e);
        s.set_section_data(".text", &[0xAB, 0xCD]).unwrap();
    }
    assert_eq!(&e.bytes()[RAW_OFF as usize..RAW_OFF as usize + 2], &[0xAB, 0xCD]);
    // remainder zeroed
    assert!(e.bytes()[RAW_OFF as usize + 2..(RAW_OFF + RAW_SZ) as usize]
        .iter()
        .all(|&b| b == 0));
    // VirtualSize = 2
    let vs = u32::from_le_bytes(e.bytes()[SECT_TABLE + 8..SECT_TABLE + 12].try_into().unwrap());
    assert_eq!(vs, 2);
}

// ---------------------------------------------------------------------------
// Send/Sync
// ---------------------------------------------------------------------------

#[test]
fn editor_types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PeEditor>();
    assert_send_sync::<SectionEditor>();
    assert_send_sync::<ImportEditor>();
    assert_send_sync::<ExportEditor>();
    assert_send_sync::<ResourceEditor>();
    assert_send_sync::<PeSigningScaffold>();
}

// ---------------------------------------------------------------------------
// EditError Display
// ---------------------------------------------------------------------------

#[test]
fn edit_error_display_variants() {
    let e = EditError::SectionNotFound("foo".into());
    assert!(format!("{e}").contains("foo"));
    let e = EditError::PatchOutOfBounds {
        offset: 1,
        len: 2,
        file_size: 3,
    };
    let s = format!("{e}");
    assert!(s.contains("1") && s.contains("2") && s.contains("3"));
    let e = EditError::InvalidAlignment("x".into());
    assert!(format!("{e}").contains("x"));
    let e = EditError::CryptoError("c".into());
    assert!(format!("{e}").contains("c"));
}
