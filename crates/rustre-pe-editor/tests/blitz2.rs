//! Adversarial deep tests for `rustre-pe-editor` (blitz2).
//!
//! Complements `blitz.rs` with seeded fuzz, boundary coverage, round-trips,
//! Hash/Eq consistency, Display checks, and Send/Sync threaded stress.

use rustre_pe_editor::{
    section_chars, CertificateHeader, EditError, ExportEdit, ExportEditor, ImportEditor,
    ImportEntry, ParseError, Patch, PatchSet, PeEditor, PeField, PeParser, PeSection,
    PeSigningScaffold, PeTreeBuilder, PeTreeNode, Rc4, ResourceEditor, ResourceEntry,
    ResourceType, SectionEdit, SectionEditor, resource_types, xor_section,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

// ---------------------------------------------------------------------------
// Seeded LCG fuzz helper
// ---------------------------------------------------------------------------

fn lcg_seed(seed: u64) -> impl FnMut() -> u64 {
    let mut s: u64 = seed;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn lcg_bytes<F: FnMut() -> u64>(g: &mut F, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let w = g();
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.truncate(n);
    out
}

// ---------------------------------------------------------------------------
// Minimal PE32+ fixture (matches blitz.rs layout)
// ---------------------------------------------------------------------------

const PE_OFF: usize = 0x80;
const OPT_OFF: usize = PE_OFF + 24;
const SECT_TABLE: usize = OPT_OFF + 0xF0;
const RAW_OFF: u32 = 0x200;
const RAW_SZ: u32 = 0x200;
const VA: u32 = 0x1000;
const VSZ: u32 = 0x200;
const FILE_SIZE: usize = 0x400;

fn make_pe() -> Vec<u8> {
    let mut data = vec![0u8; FILE_SIZE];
    data[0] = b'M';
    data[1] = b'Z';
    data[0x3C..0x40].copy_from_slice(&(PE_OFF as u32).to_le_bytes());
    data[PE_OFF..PE_OFF + 4].copy_from_slice(b"PE\0\0");
    data[PE_OFF + 4] = 0x64;
    data[PE_OFF + 5] = 0x86;
    data[PE_OFF + 6] = 1;
    data[PE_OFF + 7] = 0;
    data[PE_OFF + 20] = 0xF0;
    data[PE_OFF + 21] = 0x00;
    data[PE_OFF + 22] = 0x22;
    data[OPT_OFF] = 0x0B;
    data[OPT_OFF + 1] = 0x02;
    data[OPT_OFF + 32..OPT_OFF + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    data[OPT_OFF + 36..OPT_OFF + 40].copy_from_slice(&0x200u32.to_le_bytes());
    data[OPT_OFF + 56..OPT_OFF + 60].copy_from_slice(&0x2000u32.to_le_bytes());
    data[OPT_OFF + 60..OPT_OFF + 64].copy_from_slice(&0x200u32.to_le_bytes());
    data[OPT_OFF + 108..OPT_OFF + 112].copy_from_slice(&16u32.to_le_bytes());
    let s = SECT_TABLE;
    data[s..s + 5].copy_from_slice(b".text");
    data[s + 8..s + 12].copy_from_slice(&VSZ.to_le_bytes());
    data[s + 12..s + 16].copy_from_slice(&VA.to_le_bytes());
    data[s + 16..s + 20].copy_from_slice(&RAW_SZ.to_le_bytes());
    data[s + 20..s + 24].copy_from_slice(&RAW_OFF.to_le_bytes());
    let chars: u32 = section_chars::CODE | section_chars::MEM_EXECUTE | section_chars::MEM_READ;
    data[s + 36..s + 40].copy_from_slice(&chars.to_le_bytes());
    for (i, b) in data[RAW_OFF as usize..RAW_OFF as usize + RAW_SZ as usize]
        .iter_mut()
        .enumerate()
    {
        *b = (i & 0xFF) as u8;
    }
    data
}

// ---------------------------------------------------------------------------
// Patch / PatchSet boundary + Display tests
// ---------------------------------------------------------------------------

#[test]
fn patch_zero_len_is_empty() {
    let p = Patch::simple(0, vec![], "empty".to_string());
    assert!(p.is_empty());
    assert_eq!(p.len(), 0);
    assert!(!p.has_verification());
}

#[test]
fn patch_verified_has_verification() {
    let p = Patch::verified(0, vec![1, 2], vec![3, 4], "v".to_string());
    assert!(p.has_verification());
}

#[test]
fn patch_display_format() {
    let p = Patch::simple(0xDEAD, vec![0; 4], "trampoline".to_string());
    let s = format!("{p}");
    assert!(s.contains("0xdead"));
    assert!(s.contains("trampoline"));
    assert!(s.contains("[4]"));
}

#[test]
fn patchset_empty_default() {
    let ps = PatchSet::default();
    assert!(ps.is_empty());
    assert_eq!(ps.len(), 0);
    assert_eq!(ps.total_bytes(), 0);
}

#[test]
fn patchset_total_bytes_sums_correctly() {
    let mut ps = PatchSet::new("p".to_string());
    for i in 0..20u8 {
        ps.add(Patch::simple(0, vec![i; (i as usize) + 1], "x".to_string()));
    }
    let expected: usize = (1..=20).sum();
    assert_eq!(ps.total_bytes(), expected);
    assert_eq!(ps.len(), 20);
}

#[test]
fn patchset_display_contains_name() {
    let ps = PatchSet::new("crackme".to_string());
    let s = format!("{ps}");
    assert!(s.contains("crackme"));
}

// ---------------------------------------------------------------------------
// PeEditor fuzz / boundary
// ---------------------------------------------------------------------------

#[test]
fn pe_editor_rejects_too_short_buffers() {
    for n in 0..32usize {
        let r = PeEditor::new(vec![0u8; n]);
        assert!(r.is_err(), "should reject {n}-byte buffer");
    }
}

#[test]
fn pe_editor_apply_patch_at_eof_succeeds_then_oob() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    let at_end = ed.bytes().len() - 4;
    ed.apply_patch(Patch::simple(at_end, vec![0xAA; 4], "tail".to_string()))
        .unwrap();
    let r = ed.apply_patch(Patch::simple(at_end + 1, vec![0; 4], "oob".to_string()));
    assert!(matches!(r, Err(EditError::PatchOutOfBounds { .. })));
}

#[test]
fn pe_editor_nop_oob_boundary() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    let len = ed.bytes().len();
    assert!(ed.nop_range(0, len).is_ok());
    let r = ed.nop_range(0, len + 1);
    assert!(matches!(r, Err(EditError::PatchOutOfBounds { .. })));
}

#[test]
fn pe_editor_int3_writes_cc() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    ed.int3_range(RAW_OFF as usize, 16).unwrap();
    let slice = ed.read_bytes(RAW_OFF as usize, 16).unwrap();
    assert!(slice.iter().all(|&b| b == 0xCC));
}

#[test]
fn pe_editor_read_bytes_oob() {
    let ed = PeEditor::new(make_pe()).unwrap();
    let len = ed.bytes().len();
    let r = ed.read_bytes(len, 1);
    assert!(matches!(r, Err(EditError::PatchOutOfBounds { .. })));
    assert!(ed.read_bytes(len, 0).is_ok());
}

#[test]
fn pe_editor_set_entry_point_overflow() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    let r = ed.set_entry_point(u64::from(u32::MAX) + 1);
    assert!(r.is_err());
}

#[test]
fn pe_editor_set_entry_point_valid_roundtrip() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    ed.set_entry_point(0x1234_5678).unwrap();
    let read = u32::from_le_bytes(
        ed.read_bytes(OPT_OFF + 16, 4).unwrap().try_into().unwrap(),
    );
    assert_eq!(read, 0x1234_5678);
}

#[test]
fn pe_editor_zero_checksum_then_recalculate() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    ed.zero_checksum().unwrap();
    let cs1 = ed.recalculate_checksum().unwrap();
    // Calling again on already-set checksum must yield the same value (idempotent).
    let cs2 = ed.recalculate_checksum().unwrap();
    assert_eq!(cs1, cs2);
}

#[test]
fn pe_editor_aslr_nx_toggle_roundtrip() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    let dll_off = OPT_OFF + 70;
    ed.set_aslr(true).unwrap();
    ed.set_nx(true).unwrap();
    let v = u16::from_le_bytes(ed.read_bytes(dll_off, 2).unwrap().try_into().unwrap());
    assert_eq!(v & 0x0040, 0x0040);
    assert_eq!(v & 0x0100, 0x0100);
    ed.set_aslr(false).unwrap();
    let v = u16::from_le_bytes(ed.read_bytes(dll_off, 2).unwrap().try_into().unwrap());
    assert_eq!(v & 0x0040, 0);
    assert_eq!(v & 0x0100, 0x0100);
}

#[test]
fn pe_editor_set_image_base_64bit() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    ed.set_image_base(0x0000_0001_4000_0000).unwrap();
    let v = u64::from_le_bytes(
        ed.read_bytes(OPT_OFF + 24, 8).unwrap().try_into().unwrap(),
    );
    assert_eq!(v, 0x0000_0001_4000_0000);
}

#[test]
fn pe_editor_set_subsystem_roundtrip() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    for s in [1u16, 2, 3, 9, 14] {
        ed.set_subsystem(s).unwrap();
        let v =
            u16::from_le_bytes(ed.read_bytes(OPT_OFF + 68, 2).unwrap().try_into().unwrap());
        assert_eq!(v, s);
    }
}

#[test]
fn pe_editor_write_bytes_oob() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    let len = ed.bytes().len();
    let r = ed.write_bytes(len - 2, &[0; 4]);
    assert!(matches!(r, Err(EditError::PatchOutOfBounds { .. })));
}

#[test]
fn pe_editor_rva_in_section_known() {
    let ed = PeEditor::new(make_pe()).unwrap();
    let inside = ed.rva_in_section(VA).unwrap_or(false);
    let outside = ed.rva_in_section(0xFFFF_F000).unwrap_or(true);
    assert!(inside);
    assert!(!outside);
}

#[test]
fn pe_editor_applied_count_grows() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    assert_eq!(ed.applied_count(), 0);
    for i in 0..10 {
        ed.apply_patch(Patch::simple(RAW_OFF as usize + i, vec![0u8], "x".to_string()))
            .unwrap();
    }
    assert_eq!(ed.applied_count(), 10);
    assert_eq!(ed.applied_patches().len(), 10);
}

#[test]
fn pe_editor_edit_log_records_actions() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    ed.nop_range(RAW_OFF as usize, 4).unwrap();
    ed.zero_checksum().unwrap();
    let log = ed.edit_log();
    assert!(log.iter().any(|s| s.contains("nop")));
}

#[test]
fn pe_editor_into_bytes_preserves() {
    let original = make_pe();
    let ed = PeEditor::new(original.clone()).unwrap();
    assert_eq!(ed.into_bytes(), original);
}

// ---------------------------------------------------------------------------
// PeEditor fuzz: random byte mutations should never panic
// ---------------------------------------------------------------------------

#[test]
fn pe_editor_constructor_fuzz_no_panic() {
    let mut g = lcg_seed(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..100 {
        let len = (g() as usize) % 1024;
        let buf = lcg_bytes(&mut g, len);
        let _ = PeEditor::new(buf);
    }
}

#[test]
fn pe_editor_apply_patch_fuzz_no_panic() {
    let mut g = lcg_seed(0x1234_5678_9ABC_DEF0);
    for _ in 0..60 {
        let mut ed = PeEditor::new(make_pe()).unwrap();
        let off = (g() as usize) % (FILE_SIZE + 64);
        let len = (g() as usize) % 32;
        let bytes = lcg_bytes(&mut g, len);
        let _ = ed.apply_patch(Patch::simple(off, bytes, "fuzz".to_string()));
    }
}

// ---------------------------------------------------------------------------
// SectionEditor
// ---------------------------------------------------------------------------

#[test]
fn section_editor_rename_truncates_to_8() {
    let mut se = SectionEditor::new(make_pe()).unwrap();
    se.rename_section(".text", "TOOOOLONGNAME").unwrap();
    let bytes = se.bytes();
    assert_eq!(&bytes[SECT_TABLE..SECT_TABLE + 8], b"TOOOOLON");
}

#[test]
fn section_editor_rename_short_name_pads_with_zero() {
    let mut se = SectionEditor::new(make_pe()).unwrap();
    se.rename_section(".text", ".x").unwrap();
    let bytes = se.bytes();
    assert_eq!(&bytes[SECT_TABLE..SECT_TABLE + 2], b".x");
    assert!(bytes[SECT_TABLE + 2..SECT_TABLE + 8].iter().all(|&b| b == 0));
}

#[test]
fn section_editor_set_chars_roundtrip() {
    let mut se = SectionEditor::new(make_pe()).unwrap();
    let target = section_chars::MEM_READ | section_chars::MEM_WRITE | section_chars::INITIALIZED_DATA;
    se.set_characteristics(".text", target).unwrap();
    let read = u32::from_le_bytes(se.bytes()[SECT_TABLE + 36..SECT_TABLE + 40].try_into().unwrap());
    assert_eq!(read, target);
}

#[test]
fn section_editor_zero_section() {
    let mut se = SectionEditor::new(make_pe()).unwrap();
    se.zero_section(".text").unwrap();
    let data = se.read_section(".text").unwrap();
    assert!(data.iter().all(|&b| b == 0));
}

#[test]
fn section_editor_missing_section() {
    let mut se = SectionEditor::new(make_pe()).unwrap();
    assert!(matches!(
        se.rename_section(".nope", ".x"),
        Err(EditError::SectionNotFound(_))
    ));
}

#[test]
fn section_editor_write_into_section_oob() {
    let mut se = SectionEditor::new(make_pe()).unwrap();
    let r = se.write_into_section(".text", RAW_SZ as usize, &[0; 1]);
    assert!(matches!(r, Err(EditError::PatchOutOfBounds { .. })));
}

// ---------------------------------------------------------------------------
// SectionEdit constructors
// ---------------------------------------------------------------------------

#[test]
fn section_edit_set_chars_constructor() {
    let e = SectionEdit::set_chars(".text".to_string(), 0xC000_0040);
    assert_eq!(e.new_characteristics, Some(0xC000_0040));
    assert!(!e.zero_out);
}

#[test]
fn section_edit_zero_constructor() {
    let e = SectionEdit::zero(".text".to_string());
    assert!(e.zero_out);
    assert!(e.new_characteristics.is_none());
}

// ---------------------------------------------------------------------------
// ImportEntry / ImportEditor
// ---------------------------------------------------------------------------

#[test]
fn import_entry_named_vs_ordinal() {
    let n = ImportEntry::named("k32.dll".into(), "LoadLibraryA".into(), 5);
    assert!(n.is_named());
    let o = ImportEntry::ordinal("k32.dll".into(), 17);
    assert!(!o.is_named());
    assert_eq!(o.ordinal, Some(17));
}

#[test]
fn import_entry_display_named_and_ordinal() {
    let n = ImportEntry::named("a.dll".into(), "f".into(), 0);
    assert_eq!(format!("{n}"), "a.dll!f");
    let o = ImportEntry::ordinal("a.dll".into(), 7);
    assert_eq!(format!("{o}"), "a.dll!#7");
}

#[test]
fn import_editor_apply_empty_returns_zero() {
    let ie = ImportEditor::new();
    let mut data = make_pe();
    let added = ie.apply(&mut data).unwrap();
    assert_eq!(added, 0);
}

#[test]
fn import_editor_apply_adds_entries() {
    let mut ie = ImportEditor::new();
    ie.add_import(ImportEntry::named(
        "k32.dll".into(),
        "GetStdHandle".into(),
        0,
    ));
    ie.add_import(ImportEntry::ordinal("u32.dll".into(), 7));
    let mut data = make_pe();
    let added = ie.apply(&mut data).unwrap();
    assert_eq!(added, 2);
    // file grew
    assert!(data.len() > FILE_SIZE);
}

#[test]
fn import_editor_apply_too_short_buffer() {
    let mut ie = ImportEditor::new();
    ie.add_import(ImportEntry::named("a".into(), "f".into(), 0));
    let mut data = vec![0u8; 10];
    let r = ie.apply(&mut data);
    assert!(matches!(r, Err(EditError::ImportError(_))));
}

#[test]
fn import_editor_clear_resets_counts() {
    let mut ie = ImportEditor::new();
    ie.add_import(ImportEntry::named("a".into(), "f".into(), 0));
    ie.remove_dll("b.dll".into());
    assert_eq!(ie.pending_additions(), 1);
    assert_eq!(ie.pending_removals(), 1);
    ie.clear();
    assert_eq!(ie.pending_additions(), 0);
    assert_eq!(ie.pending_removals(), 0);
}

// ---------------------------------------------------------------------------
// ExportEditor / ExportEdit
// ---------------------------------------------------------------------------

#[test]
fn export_edit_display_add_remove() {
    let a = ExportEdit::add("foo".into(), 1, 0x1000);
    let r = ExportEdit::remove("foo".into());
    assert!(format!("{a}").contains("Add export"));
    assert!(format!("{r}").contains("Remove export"));
}

#[test]
fn export_editor_partition() {
    let mut ee = ExportEditor::new("mylib.dll".into());
    for i in 0..5 {
        ee.add_export(format!("f{i}"), i, i * 0x100);
    }
    for i in 0..3 {
        ee.remove_export(format!("g{i}"));
    }
    assert_eq!(ee.additions().len(), 5);
    assert_eq!(ee.removals().len(), 3);
    assert_eq!(ee.pending_count(), 8);
    assert_eq!(ee.dll_name(), "mylib.dll");
    ee.clear();
    assert_eq!(ee.pending_count(), 0);
}

// ---------------------------------------------------------------------------
// ResourceType / ResourceEntry Hash+Eq consistency
// ---------------------------------------------------------------------------

fn hash<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

#[test]
fn resource_type_eq_implies_hash_eq_30_pairs() {
    let mut g = lcg_seed(0xAAAA_BBBB_CCCC_DDDD);
    for _ in 0..15 {
        let id = (g() & 0xFFFF) as u16;
        let a = ResourceType::Id(id);
        let b = ResourceType::Id(id);
        assert_eq!(a, b);
        assert_eq!(hash(&a), hash(&b));
        let n = format!("n{}", g() % 1000);
        let an = ResourceType::Name(n.clone());
        let bn = ResourceType::Name(n);
        assert_eq!(an, bn);
        assert_eq!(hash(&an), hash(&bn));
    }
}

#[test]
fn resource_type_display() {
    assert_eq!(format!("{}", ResourceType::Id(24)), "#24");
    assert_eq!(format!("{}", ResourceType::Name("FOO".to_string())), "FOO");
}

#[test]
fn resource_entry_manifest_constructor() {
    let m = ResourceEntry::manifest(vec![1, 2, 3]);
    assert_eq!(m.resource_type, ResourceType::Id(resource_types::RT_MANIFEST));
    assert_eq!(m.language, 0x0409);
    assert_eq!(m.len(), 3);
    assert!(!m.is_empty());
}

#[test]
fn resource_entry_empty_is_empty() {
    let e = ResourceEntry::new(1, 0, 0, vec![]);
    assert!(e.is_empty());
    assert_eq!(e.len(), 0);
}

#[test]
fn resource_editor_lifecycle() {
    let mut re = ResourceEditor::new();
    for i in 0..7 {
        re.add_resource(ResourceEntry::new(1, i, 0, vec![0; i as usize]));
    }
    re.remove_resource(ResourceType::Id(1), 3);
    re.remove_resource(ResourceType::Name("X".into()), 0);
    assert_eq!(re.pending_additions(), 7);
    assert_eq!(re.pending_removals(), 2);
    assert_eq!(re.total_data_size(), 1 + 2 + 3 + 4 + 5 + 6);
    re.clear();
    assert_eq!(re.pending_additions(), 0);
    assert_eq!(re.pending_removals(), 0);
}

// ---------------------------------------------------------------------------
// XOR / RC4
// ---------------------------------------------------------------------------

#[test]
fn xor_section_self_inverse_50_inputs() {
    let mut g = lcg_seed(0xCAFE_F00D_BAAD_F00D);
    for _ in 0..50 {
        let n = (g() as usize) % 256 + 1;
        let mut buf = lcg_bytes(&mut g, n);
        let original = buf.clone();
        let key_len = ((g() as usize) % 16) + 1;
        let key = lcg_bytes(&mut g, key_len);
        xor_section(&mut buf, &key);
        xor_section(&mut buf, &key);
        assert_eq!(buf, original);
    }
}

#[test]
#[should_panic]
fn xor_section_empty_key_should_panic() {
    let mut buf = [1u8, 2, 3];
    xor_section(&mut buf, &[]);
}

#[test]
fn rc4_self_inverse_roundtrip() {
    let mut g = lcg_seed(0xFEED_FACE_DEAD_BEEF);
    for _ in 0..30 {
        let n = (g() as usize) % 512 + 1;
        let mut buf = lcg_bytes(&mut g, n);
        let original = buf.clone();
        let klen = ((g() as usize) % 32) + 1;
        let key = lcg_bytes(&mut g, klen);
        let mut rc4 = Rc4::new(&key);
        rc4.process(&mut buf);
        let mut rc4 = Rc4::new(&key);
        rc4.process(&mut buf);
        assert_eq!(buf, original);
    }
}

#[test]
fn rc4_first_byte_known_vector() {
    // RC4("Key", "Plaintext") well-known: BBF316E8D940AF0AD3
    let mut rc4 = Rc4::new(b"Key");
    let mut data = b"Plaintext".to_vec();
    rc4.process(&mut data);
    assert_eq!(
        data,
        vec![0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]
    );
}

#[test]
#[should_panic]
fn rc4_empty_key_should_panic() {
    let _ = Rc4::new(&[]);
}

#[test]
fn pe_editor_xor_section_roundtrip() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    let orig = ed.read_bytes(RAW_OFF as usize, RAW_SZ as usize).unwrap().to_vec();
    ed.xor_encrypt_section(".text", b"key1").unwrap();
    ed.xor_decrypt_section(".text", b"key1").unwrap();
    let now = ed.read_bytes(RAW_OFF as usize, RAW_SZ as usize).unwrap();
    assert_eq!(now, orig);
}

#[test]
fn pe_editor_rc4_section_roundtrip() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    let orig = ed.read_bytes(RAW_OFF as usize, RAW_SZ as usize).unwrap().to_vec();
    ed.rc4_encrypt_section(".text", b"k1").unwrap();
    ed.rc4_encrypt_section(".text", b"k1").unwrap();
    let now = ed.read_bytes(RAW_OFF as usize, RAW_SZ as usize).unwrap();
    assert_eq!(now, orig);
}

// ---------------------------------------------------------------------------
// CertificateHeader / PeSigningScaffold
// ---------------------------------------------------------------------------

#[test]
fn certificate_header_layout_roundtrip() {
    for &len in &[0u32, 1, 16, 1024, u32::MAX - 8] {
        let h = CertificateHeader::new(len);
        let b = h.to_bytes();
        assert_eq!(b.len(), 8);
        let dw = u32::from_le_bytes(b[0..4].try_into().unwrap());
        assert_eq!(dw, 8u32.wrapping_add(len));
        let rev = u16::from_le_bytes(b[4..6].try_into().unwrap());
        let ty = u16::from_le_bytes(b[6..8].try_into().unwrap());
        assert_eq!(rev, 0x0200);
        assert_eq!(ty, 0x0002);
    }
}

#[test]
fn pe_signing_scaffold_blob_8byte_aligned() {
    for n in [0usize, 1, 7, 8, 9, 100, 1000] {
        let s = PeSigningScaffold::new(vec![0u8; n]);
        let blob = s.build_certificate_blob();
        assert_eq!(blob.len() % 8, 0);
        assert!(blob.len() >= 8 + n);
        assert_eq!(s.payload_len(), n);
    }
}

#[test]
fn pe_signing_scaffold_inject_updates_data_dir() {
    let mut data = make_pe();
    let s = PeSigningScaffold::new(vec![0xAB; 32]);
    let pre_len = data.len();
    s.inject(&mut data).unwrap();
    assert!(data.len() > pre_len);
    let dd_off = OPT_OFF + 112 + 4 * 8;
    let rva = u32::from_le_bytes(data[dd_off..dd_off + 4].try_into().unwrap());
    let size = u32::from_le_bytes(data[dd_off + 4..dd_off + 8].try_into().unwrap());
    assert_eq!(rva, pre_len as u32);
    assert_eq!(size as usize, data.len() - pre_len);
}

#[test]
fn pe_signing_scaffold_inject_too_short() {
    let mut data = vec![0u8; 8];
    let s = PeSigningScaffold::new(vec![]);
    let r = s.inject(&mut data);
    assert!(matches!(r, Err(EditError::SignError(_))));
}

// ---------------------------------------------------------------------------
// PeParser
// ---------------------------------------------------------------------------

#[test]
fn pe_parser_dos_too_short() {
    for n in 0..64 {
        let r = PeParser::parse_dos_header(&vec![0u8; n]);
        assert!(matches!(r, Err(ParseError::TooShort { .. })));
    }
}

#[test]
fn pe_parser_dos_bad_magic() {
    let mut d = vec![0u8; 64];
    d[0] = b'X';
    d[1] = b'X';
    let r = PeParser::parse_dos_header(&d);
    assert!(matches!(r, Err(ParseError::InvalidDosMagic(_))));
}

#[test]
fn pe_parser_dos_roundtrip_on_fixture() {
    let pe = make_pe();
    let dos = PeParser::parse_dos_header(&pe).unwrap();
    assert_eq!(dos.e_magic, 0x5A4D);
    assert_eq!(dos.e_lfanew as usize, PE_OFF);
}

#[test]
fn pe_parser_file_header_too_short() {
    let r = PeParser::parse_file_header(&[0u8; 10], 0);
    assert!(matches!(r, Err(ParseError::TooShort { .. })));
}

#[test]
fn pe_parser_file_header_ok() {
    let pe = make_pe();
    let fh = PeParser::parse_file_header(&pe, PE_OFF + 4).unwrap();
    assert_eq!(fh.machine, 0x8664);
    assert_eq!(fh.number_of_sections, 1);
    assert_eq!(fh.size_of_optional_header, 0xF0);
}

#[test]
fn pe_parser_optional_header64_wrong_magic() {
    let mut pe = make_pe();
    pe[OPT_OFF] = 0x0B;
    pe[OPT_OFF + 1] = 0x01; // PE32
    let r = PeParser::parse_optional_header64(&pe, OPT_OFF);
    assert!(matches!(r, Err(ParseError::MalformedHeader(_))));
}

#[test]
fn pe_parser_optional_header64_too_short() {
    let r = PeParser::parse_optional_header64(&[0u8; 50], 0);
    assert!(matches!(r, Err(ParseError::TooShort { .. })));
}

#[test]
fn pe_parser_optional_header64_ok() {
    let pe = make_pe();
    let oh = PeParser::parse_optional_header64(&pe, OPT_OFF).unwrap();
    assert_eq!(oh.magic, 0x020B);
    assert_eq!(oh.section_alignment, 0x1000);
    assert_eq!(oh.file_alignment, 0x200);
    assert_eq!(oh.number_of_rva_and_sizes, 16);
}

#[test]
fn pe_parser_sections_ok_and_too_short() {
    let pe = make_pe();
    let s = PeParser::parse_sections(&pe, SECT_TABLE, 1).unwrap();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].name, ".text");
    assert_eq!(s[0].virtual_address, VA);
    let r = PeParser::parse_sections(&pe, SECT_TABLE, 100);
    assert!(matches!(r, Err(ParseError::TooShort { .. })));
}

#[test]
fn pe_parser_fuzz_no_panic() {
    let mut g = lcg_seed(0x0F0F_F0F0_1234_5678);
    for _ in 0..100 {
        let n = (g() as usize) % 512;
        let buf = lcg_bytes(&mut g, n);
        let _ = PeParser::parse_dos_header(&buf);
        let off = (g() as usize) % (n + 1);
        let _ = PeParser::parse_file_header(&buf, off);
        let _ = PeParser::parse_optional_header64(&buf, off);
        let count = (g() & 0x1F) as u16;
        let _ = PeParser::parse_sections(&buf, off, count);
    }
}

// ---------------------------------------------------------------------------
// PeTreeBuilder
// ---------------------------------------------------------------------------

#[test]
fn pe_tree_unknown_returns_stub() {
    let t = PeTreeBuilder::build_tree(&[0u8; 4]);
    assert_eq!(t.sections.len(), 1);
    assert_eq!(t.sections[0].name, "Unknown");
}

#[test]
fn pe_tree_build_on_fixture_has_structure() {
    let pe = make_pe();
    let t = PeTreeBuilder::build_tree(&pe);
    assert!(t.find("DOS Header").is_some());
    assert!(t.find("NT Headers").is_some());
    assert!(t.find("Section Table").is_some());
    assert!(t.find("Data Directories").is_some());
}

#[test]
fn pe_tree_node_total_fields_recursive() {
    let mut root = PeTreeNode::leaf("root", 0, 0);
    root.fields.push(PeField::new("a", 1, "x"));
    let mut child = PeTreeNode::leaf("c", 0, 0);
    child.fields.push(PeField::new("b", 2, "y"));
    child.fields.push(PeField::new("c", 3, "z"));
    root.children.push(child);
    assert_eq!(root.total_fields(), 3);
}

#[test]
fn pe_tree_node_display() {
    let n = PeTreeNode::leaf("foo", 0x100, 0x40);
    let s = format!("{n}");
    assert!(s.contains("foo"));
    assert!(s.contains("0x100"));
}

#[test]
fn pe_field_display_format() {
    let f = PeField::new("Magic", 0x020B, "PE32+");
    let s = format!("{f}");
    assert!(s.contains("Magic"));
    assert!(s.contains("0x20b"));
    assert!(s.contains("PE32+"));
}

#[test]
fn pe_tree_fuzz_no_panic() {
    let mut g = lcg_seed(0xABCD_EF01_2345_6789);
    for _ in 0..40 {
        let n = (g() as usize) % 1024;
        let buf = lcg_bytes(&mut g, n);
        let _ = PeTreeBuilder::build_tree(&buf);
    }
}

// ---------------------------------------------------------------------------
// PeSection high-level
// ---------------------------------------------------------------------------

#[test]
fn pe_section_set_data_truncates() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    let big = vec![0xEE; (RAW_SZ as usize) * 4];
    {
        let mut ps = PeSection::new(&mut ed);
        ps.set_section_data(".text", &big).unwrap();
    }
    // Only RAW_SZ bytes should have been written; section data must equal first RAW_SZ bytes
    let s = ed.read_bytes(RAW_OFF as usize, RAW_SZ as usize).unwrap();
    assert!(s.iter().all(|&b| b == 0xEE));
}

#[test]
fn pe_section_set_data_zero_pads_remainder() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    {
        let mut ps = PeSection::new(&mut ed);
        ps.set_section_data(".text", &[1, 2, 3, 4]).unwrap();
    }
    let s = ed.read_bytes(RAW_OFF as usize, RAW_SZ as usize).unwrap();
    assert_eq!(&s[..4], &[1, 2, 3, 4]);
    assert!(s[4..].iter().all(|&b| b == 0));
}

#[test]
fn pe_section_rename_roundtrip() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    {
        let mut ps = PeSection::new(&mut ed);
        ps.rename_section(".text", ".code").unwrap();
    }
    let bytes = ed.bytes();
    assert_eq!(&bytes[SECT_TABLE..SECT_TABLE + 5], b".code");
}

#[test]
fn pe_section_rename_missing() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    let mut ps = PeSection::new(&mut ed);
    let r = ps.rename_section(".nope", ".x");
    assert!(matches!(r, Err(EditError::SectionNotFound(_))));
}

#[test]
fn pe_section_remove_unknown_returns_false() {
    let mut ed = PeEditor::new(make_pe()).unwrap();
    let mut ps = PeSection::new(&mut ed);
    let r = ps.remove_section(".nope").unwrap();
    assert!(!r);
}

// ---------------------------------------------------------------------------
// Send + Sync threaded stress (PatchSet, ImportEntry, ResourceType are Send+Sync)
// ---------------------------------------------------------------------------

#[test]
fn patchset_is_send_sync_threaded() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PatchSet>();
    assert_send_sync::<ImportEntry>();
    assert_send_sync::<ResourceType>();
    assert_send_sync::<ResourceEntry>();

    let mut ps = PatchSet::new("base".into());
    for i in 0..50u8 {
        ps.add(Patch::simple(i as usize, vec![i], "x".to_string()));
    }
    let shared = Arc::new(ps);

    let mut handles = Vec::new();
    for tid in 0..4 {
        let s = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            let mut sum = 0usize;
            for _ in 0..100 {
                sum = sum.wrapping_add(s.total_bytes());
                sum = sum.wrapping_add(s.len());
                sum = sum.wrapping_add(tid);
            }
            sum
        }));
    }
    for h in handles {
        let _ = h.join().unwrap();
    }
}

#[test]
fn import_entry_threaded() {
    let e = Arc::new(ImportEntry::named(
        "k32.dll".into(),
        "GetStdHandle".into(),
        0,
    ));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let e = Arc::clone(&e);
        handles.push(thread::spawn(move || {
            let mut k = 0usize;
            for _ in 0..100 {
                if e.is_named() {
                    k += e.display().len();
                }
            }
            k
        }));
    }
    let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert!(total > 0);
}
