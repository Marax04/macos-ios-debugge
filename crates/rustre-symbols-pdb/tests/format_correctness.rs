//! Regression tests for format-level correctness bugs.
//!
//! Every test here fails against the pre-fix crate. Where a bug involved a
//! wrong constant, the fixture is built from the *published* `cvinfo.h` /
//! MSF literal — never from the crate's own constants — so the encoder and
//! decoder cannot share a mistake.

use std::collections::HashMap;

use rustre_symbols_pdb::module_symbols::parse_module_symbols;
use rustre_symbols_pdb::pdb_gsi::{GsiBitmap, GsiHash, HR_IN_MEMORY_SIZE};
use rustre_symbols_pdb::pdb_type_info::{
    leaf, read_numeric_leaf, FieldListItem, ModifierType, PdbTypeInfo, TypeNameResolver,
    TypeRecord, TypeSizeCalculator,
};
use rustre_symbols_pdb::sym_kinds;

// ── Finding 1: symbol record codes ───────────────────────────────────────────

/// Literal values transcribed from `cvinfo.h`'s `SYM_ENUM_e`.
#[test]
fn symbol_codes_match_cvinfo_h_literals() {
    assert_eq!(sym_kinds::S_CONSTANT, 0x1107);
    assert_eq!(sym_kinds::S_UDT, 0x1108);
    assert_eq!(sym_kinds::S_LDATA32, 0x110C);
    assert_eq!(sym_kinds::S_GDATA32, 0x110D);
    assert_eq!(sym_kinds::S_PUB32, 0x110E);
    assert_eq!(sym_kinds::S_LPROC32, 0x110F);
    assert_eq!(sym_kinds::S_GPROC32, 0x1110);
    assert_eq!(sym_kinds::S_PROCREF, 0x1125);
    assert_eq!(sym_kinds::S_DATAREF, 0x1126);
    assert_eq!(sym_kinds::S_LPROCREF, 0x1127);
}

/// The crate previously re-exported `S_LPROC32 = 0x1108` (really `S_UDT`) and
/// `S_LDATA32 = 0x1107` (really `S_CONSTANT`) from four separate modules.
#[test]
fn public_symbol_code_reexports_are_correct() {
    use rustre_symbols_pdb::pdb_symbol_info as psi;
    assert_eq!(psi::S_LPROC32, 0x110F);
    assert_eq!(psi::S_LDATA32, 0x110C);
    assert_eq!(psi::S_UDT, 0x1108);
    assert_eq!(psi::S_CONSTANT, 0x1107);
    // The invented "non-overlapping" aliases 0x1003 / 0x1009 are gone.
    assert_ne!(psi::S_UDT32, 0x1003);
    assert_ne!(psi::S_CONSTANT32, 0x1009);
}

/// Append one `CodeView` symbol record (`u16 len, u16 kind, body`) with the
/// 4-byte record alignment the format requires.
fn push_record(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
    let len = u16::try_from(body.len() + 2).unwrap();
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(body);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

/// A `static` function is an `S_LPROC32` (0x110F). Parsing a module stream
/// containing one must yield it; the old constant skipped the record entirely.
#[test]
fn module_stream_yields_static_lproc32_function() {
    // S_LPROC32 body: u32 parent, u32 end, u32 next, u32 len, u32 dbg_start,
    // u32 dbg_end, u32 type_index, u32 offset, u16 segment, u8 flags, name.
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes()); // parent
    body.extend_from_slice(&0u32.to_le_bytes()); // end
    body.extend_from_slice(&0u32.to_le_bytes()); // next
    body.extend_from_slice(&0x40u32.to_le_bytes()); // code length
    body.extend_from_slice(&0u32.to_le_bytes()); // dbg start
    body.extend_from_slice(&0u32.to_le_bytes()); // dbg end
    body.extend_from_slice(&0x1000u32.to_le_bytes()); // type index
    body.extend_from_slice(&0x2000u32.to_le_bytes()); // offset
    body.extend_from_slice(&1u16.to_le_bytes()); // segment
    body.push(0); // flags
    body.extend_from_slice(b"my_static_fn\0");

    let mut stream = Vec::new();
    push_record(&mut stream, 0x110F, &body); // S_LPROC32, cvinfo.h literal
    push_record(&mut stream, 0x0006, &[]); // S_END closes the procedure scope

    let syms = parse_module_symbols(&stream).expect("module stream should parse");
    assert!(
        syms.procedures.iter().any(|p| p.name == "my_static_fn"),
        "S_LPROC32 (0x110F) static function was dropped; got {:?}",
        syms.procedures.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
}

/// A real `S_UDT` (0x1108) must not be mistaken for a procedure and parsed with
/// the 36-byte proc layout, which fabricated a function from a type alias.
#[test]
fn udt_record_is_not_parsed_as_a_procedure() {
    // S_UDT body: u32 type_index, name.
    let mut body = Vec::new();
    body.extend_from_slice(&0x1234u32.to_le_bytes());
    body.extend_from_slice(b"MyTypedef\0");

    let mut stream = Vec::new();
    push_record(&mut stream, 0x1108, &body); // S_UDT, cvinfo.h literal

    let syms = parse_module_symbols(&stream).expect("module stream should parse");
    assert!(
        syms.procedures.is_empty(),
        "S_UDT (0x1108) fabricated a phantom procedure: {:?}",
        syms.procedures.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
}

// ── Finding 2: unbounded type recursion ──────────────────────────────────────

fn info_with(records: Vec<(u32, TypeRecord)>) -> PdbTypeInfo {
    let mut map = HashMap::new();
    for (ti, rec) in records {
        map.insert(ti, rec);
    }
    PdbTypeInfo {
        records: map,
        ti_min: 0x1000,
        ti_max: 0x2000,
    }
}

fn modifier(base_ti: u32) -> TypeRecord {
    TypeRecord::Modifier(ModifierType {
        base_ti,
        attr: 0x01, // const
    })
}

/// A self-referential `LF_MODIFIER` used to recurse until the stack ran out,
/// which is a `SIGSEGV`/abort in Rust — uncatchable by any caller.
#[test]
fn resolve_terminates_on_self_referential_modifier() {
    let info = info_with(vec![(0x1000, modifier(0x1000))]);
    let name = TypeNameResolver::new(&info).resolve(0x1000);
    assert!(name.contains("<cyclic>"), "got {name}");
}

#[test]
fn resolve_terminates_on_two_record_cycle() {
    let info = info_with(vec![(0x1000, modifier(0x1001)), (0x1001, modifier(0x1000))]);
    let name = TypeNameResolver::new(&info).resolve(0x1000);
    assert!(name.contains("<cyclic>"), "got {name}");
}

#[test]
fn size_of_terminates_on_self_referential_modifier() {
    let info = info_with(vec![(0x1000, modifier(0x1000))]);
    assert_eq!(TypeSizeCalculator::new(&info, 8).size_of(0x1000), None);
}

#[test]
fn size_of_terminates_on_two_record_cycle() {
    let info = info_with(vec![(0x1000, modifier(0x1001)), (0x1001, modifier(0x1000))]);
    assert_eq!(TypeSizeCalculator::new(&info, 8).size_of(0x1000), None);
}

// ── Finding 3: GSI hash / bitmap / bucket divisor ────────────────────────────

/// `HashStringV1` case-folds with `|= 0x20202020` before the shift-XORs.
/// Without it, no computed bucket matches the one the linker wrote — and,
/// notably, names differing only in case must land in the same bucket.
#[test]
fn gsi_hash_is_case_insensitive() {
    assert_eq!(GsiHash::hash_name("main"), GsiHash::hash_name("MAIN"));
    assert_eq!(GsiHash::hash_name("MyFunc"), GsiHash::hash_name("myfunc"));
    assert_eq!(
        GsiHash::hash_name("_ZN3foo3barEv"),
        GsiHash::hash_name("_zn3FOO3BAREV")
    );
}

/// The bitmap covers `IPHR_HASH` + 1 = 4097 bits rounded to a 32-bit boundary.
#[test]
fn gsi_bitmap_is_516_bytes_not_512() {
    assert_eq!(GsiBitmap::EXPECTED_BYTES, 516);
}

/// Bucket offsets are in units of the 12-byte in-memory `HRFile`, not the 8-byte
/// on-disk one.
#[test]
fn gsi_hash_record_in_memory_size_is_12() {
    assert_eq!(HR_IN_MEMORY_SIZE, 12);
}

/// End-to-end: a hand-built GSI where bucket 0 owns exactly the first two of
/// three hash records. With the old 8-byte divisor and `cref`-based chain end,
/// the walk both started at the wrong index and ran to the end of the stream.
#[test]
fn gsi_bucket_chain_is_bounded_by_next_bucket() {
    // Header: u32 signature(-1), u32 version, u32 hr_size, u32 num_buckets.
    let hr_count = 3usize;
    let hr_size = hr_count * 8;
    let mut data = Vec::new();
    data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    data.extend_from_slice(&0x8000_0001u32.to_le_bytes()); // GSIHashHdr V70
    data.extend_from_slice(&u32::try_from(hr_size).unwrap().to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());

    // Three hash records: sym offsets 1, 2, 3 stored as offset_cf = off + 1.
    for i in 1..=3u32 {
        data.extend_from_slice(&(i + 1).to_le_bytes()); // offset_cf
        data.extend_from_slice(&1i32.to_le_bytes()); // cref (always 1 in V7)
    }

    // Bitmap: 516 bytes, buckets 0 and 1 set.
    let mut bitmap = vec![0u8; 516];
    bitmap[0] = 0b0000_0011;
    data.extend_from_slice(&bitmap);

    // Bucket table: bucket 0 starts at in-memory offset 0, bucket 1 at 24
    // (= 2 records * 12 bytes).
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&24i32.to_le_bytes());

    let hash = GsiHash::parse(&data).expect("GSI should parse");
    assert_eq!(hash.hash_records.len(), 3);
    assert_eq!(hash.bitmap.count_set(), 2);

    // Bucket 0 owns records [0, 2) → sym offsets 1 and 2, NOT all three.
    assert_eq!(hash.offsets_for_bucket(0), vec![1, 2]);
    // Bucket 1 owns record [2, 3) → sym offset 3.
    assert_eq!(hash.offsets_for_bucket(1), vec![3]);
}

// ── Finding 5: LF_ONEMETHOD in field lists ───────────────────────────────────

/// Build an `LF_FIELDLIST` TPI stream from raw field-list item bytes.
fn tpi_stream_with_field_list(items: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; 56];
    v[0..4].copy_from_slice(&20_040_203u32.to_le_bytes()); // version
    v[4..8].copy_from_slice(&56u32.to_le_bytes()); // header size
    v[8..12].copy_from_slice(&0x1000u32.to_le_bytes()); // ti_min
    v[12..16].copy_from_slice(&0x1001u32.to_le_bytes()); // ti_max
    let body_len = 2 + items.len();
    v[16..20].copy_from_slice(&u32::try_from(body_len + 2).unwrap().to_le_bytes());

    v.extend_from_slice(&u16::try_from(body_len).unwrap().to_le_bytes());
    v.extend_from_slice(&leaf::LF_FIELDLIST.to_le_bytes());
    v.extend_from_slice(items);
    v
}

/// `struct S { int a; void f(); int b; };` — the field list is
/// `[LF_MEMBER a][LF_ONEMETHOD f][LF_MEMBER b]`. Before the fix, `LF_ONEMETHOD`
/// hit the `_ => Stop` catch-all and member `b` vanished without any error.
#[test]
fn field_list_survives_lf_onemethod() {
    let mut items = Vec::new();

    // LF_MEMBER a: u16 leaf, u16 attr, u32 type_ti, numeric offset, name.
    items.extend_from_slice(&leaf::LF_MEMBER.to_le_bytes());
    items.extend_from_slice(&3u16.to_le_bytes()); // attr: public
    items.extend_from_slice(&0x0074u32.to_le_bytes()); // int
    items.extend_from_slice(&0u16.to_le_bytes()); // offset 0 (numeric < 0x8000)
    items.extend_from_slice(b"a\0");

    // LF_ONEMETHOD f: u16 leaf, u16 attr (non-virtual), u32 type_ti, name.
    items.extend_from_slice(&0x1511u16.to_le_bytes()); // cvinfo.h literal
    items.extend_from_slice(&3u16.to_le_bytes()); // attr: public, not virtual
    items.extend_from_slice(&0x1500u32.to_le_bytes());
    items.extend_from_slice(b"f\0");

    // LF_MEMBER b.
    items.extend_from_slice(&leaf::LF_MEMBER.to_le_bytes());
    items.extend_from_slice(&3u16.to_le_bytes());
    items.extend_from_slice(&0x0074u32.to_le_bytes());
    items.extend_from_slice(&4u16.to_le_bytes()); // offset 4
    items.extend_from_slice(b"b\0");

    let stream = tpi_stream_with_field_list(&items);
    let info = PdbTypeInfo::parse_stream(&stream).expect("TPI should parse");
    let Some(TypeRecord::FieldList(fl)) = info.get(0x1000) else {
        panic!("expected a field list, got {:?}", info.get(0x1000));
    };

    assert_eq!(
        fl.truncated_at, None,
        "field list truncated at leaf {:?}",
        fl.truncated_at
    );

    let member_names: Vec<&str> = fl
        .members
        .iter()
        .filter_map(|m| match m {
            FieldListItem::Member(f) => Some(f.name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        member_names,
        vec!["a", "b"],
        "member after LF_ONEMETHOD was silently dropped"
    );

    let methods: Vec<&str> = fl
        .members
        .iter()
        .filter_map(|m| match m {
            FieldListItem::OneMethod(om) => Some(om.name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(methods, vec!["f"]);
}

// ── Finding 6: numeric leaf widths and signs ─────────────────────────────────

/// Under-consuming a wide numeric leaf leaves the cursor inside the value and
/// desynchronizes every following field-list member.
#[test]
fn numeric_leaf_consumes_full_width() {
    let cases: &[(u16, usize, usize)] = &[
        // (tag, payload bytes, expected total consumed)
        (0x8005, 4, 6),   // LF_REAL32
        (0x8006, 8, 10),  // LF_REAL64
        (0x8007, 10, 12), // LF_REAL80
        (0x8008, 16, 18), // LF_REAL128
        (0x8017, 16, 18), // LF_OCTWORD
        (0x8018, 16, 18), // LF_UOCTWORD
    ];
    for &(tag, payload, expected) in cases {
        let mut data = tag.to_le_bytes().to_vec();
        data.extend(std::iter::repeat_n(0xAAu8, payload));
        let (_, consumed) = read_numeric_leaf(&data, 0)
            .unwrap_or_else(|e| panic!("tag {tag:#06x} failed: {e}"));
        assert_eq!(consumed, expected, "wrong width for tag {tag:#06x}");
    }
}

#[test]
fn numeric_leaf_varstring_consumes_length_prefixed_body() {
    let mut data = 0x8010u16.to_le_bytes().to_vec(); // LF_VARSTRING
    data.extend_from_slice(&5u16.to_le_bytes());
    data.extend_from_slice(b"hello");
    let (_, consumed) = read_numeric_leaf(&data, 0).unwrap();
    assert_eq!(consumed, 9);
}

/// An unrecognized tag must fail loudly rather than claim it consumed 2 bytes.
#[test]
fn numeric_leaf_rejects_unknown_tag() {
    let data = 0x8FFFu16.to_le_bytes().to_vec();
    assert!(read_numeric_leaf(&data, 0).is_err());
}

/// `LF_CHAR` / `LF_SHORT` / `LF_LONG` are signed: `enum E { NEG = -1 }` must
/// come back as -1, not 255 / 65535 / 4294967295.
#[test]
fn signed_numeric_leaves_sign_extend() {
    let mut c = 0x8000u16.to_le_bytes().to_vec(); // LF_CHAR
    c.push(0xFF);
    assert_eq!(read_numeric_leaf(&c, 0).unwrap().0 as i64, -1);

    let mut s = 0x8001u16.to_le_bytes().to_vec(); // LF_SHORT
    s.extend_from_slice(&(-1i16).to_le_bytes());
    assert_eq!(read_numeric_leaf(&s, 0).unwrap().0 as i64, -1);

    let mut l = 0x8003u16.to_le_bytes().to_vec(); // LF_LONG
    l.extend_from_slice(&(-1i32).to_le_bytes());
    assert_eq!(read_numeric_leaf(&l, 0).unwrap().0 as i64, -1);

    // Unsigned counterparts stay unsigned.
    let mut us = 0x8002u16.to_le_bytes().to_vec(); // LF_USHORT
    us.extend_from_slice(&0xFFFFu16.to_le_bytes());
    assert_eq!(read_numeric_leaf(&us, 0).unwrap().0, 0xFFFF);
}

// ── Finding 8: DBI section-contribution stride ───────────────────────────────

use rustre_symbols_pdb::pdb_dbi_reader::DbiReader;
use rustre_symbols_pdb::pdb_dbi_stream::parse_source_file_table;

/// Build a 64-byte DBI header with only the section-contribution substream
/// populated.
fn dbi_header(version: i32, sec_contrib_size: i32) -> Vec<u8> {
    let mut v = vec![0u8; 64];
    v[0..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    v[4..8].copy_from_slice(&version.to_le_bytes());
    v[24..28].copy_from_slice(&0i32.to_le_bytes()); // mod_info_size
    v[28..32].copy_from_slice(&sec_contrib_size.to_le_bytes());
    v
}

/// One 28-byte section contribution with distinctive field values.
fn sec_contrib(section: u16, offset: u32, size: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&section.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes()); // padding1
    v.extend_from_slice(&offset.to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    v.extend_from_slice(&0x6000_0020u32.to_le_bytes()); // characteristics
    v.extend_from_slice(&section.to_le_bytes()); // module_index
    v.extend_from_slice(&0u16.to_le_bytes()); // padding2
    v.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // data_crc
    v.extend_from_slice(&0xFEED_FACEu32.to_le_bytes()); // reloc_crc
    assert_eq!(v.len(), 28);
    v
}

/// A `V2` (0xF13151E4) substream uses a **32**-byte stride. With the old fixed
/// 28-byte stride, entry 1 was read 4 bytes early, so its `offset` was actually
/// entry 0's `data_crc`.
#[test]
fn dbi_v2_section_contributions_use_32_byte_stride() {
    let mut sub = 0xF131_51E4u32.to_le_bytes().to_vec(); // SC version V2
    for (i, (off, size)) in [(0x1000u32, 0x100u32), (0x2000, 0x200), (0x3000, 0x300)]
        .into_iter()
        .enumerate()
    {
        sub.extend_from_slice(&sec_contrib(u16::try_from(i + 1).unwrap(), off, size));
        sub.extend_from_slice(&0u32.to_le_bytes()); // ISectCoff — the V2 extra
    }

    let mut data = dbi_header(20_091_201, i32::try_from(sub.len()).unwrap());
    data.extend_from_slice(&sub);

    let dbi = DbiReader::parse(&data).expect("DBI should parse");
    let got: Vec<(u16, u32, u32)> = dbi
        .section_contributions
        .iter()
        .map(|c| (c.section, c.offset, c.size))
        .collect();
    assert_eq!(
        got,
        vec![(1, 0x1000, 0x100), (2, 0x2000, 0x200), (3, 0x3000, 0x300)],
        "V2 substream parsed with the wrong stride"
    );
}

/// The `Ver60` (0xF12EBA2D) path must keep its 28-byte stride.
#[test]
fn dbi_ver60_section_contributions_use_28_byte_stride() {
    let mut sub = 0xF12E_BA2Du32.to_le_bytes().to_vec();
    sub.extend_from_slice(&sec_contrib(1, 0x1000, 0x100));
    sub.extend_from_slice(&sec_contrib(2, 0x2000, 0x200));

    let mut data = dbi_header(20_091_201, i32::try_from(sub.len()).unwrap());
    data.extend_from_slice(&sub);

    let dbi = DbiReader::parse(&data).expect("DBI should parse");
    let got: Vec<(u16, u32, u32)> = dbi
        .section_contributions
        .iter()
        .map(|c| (c.section, c.offset, c.size))
        .collect();
    assert_eq!(got, vec![(1, 0x1000, 0x100), (2, 0x2000, 0x200)]);
}

/// `PdbDbiV41` is 930803, not 19930803. It used to be rejected outright.
#[test]
fn dbi_accepts_v41_version_930803() {
    let data = dbi_header(930_803, 0);
    assert!(DbiReader::parse(&data).is_ok(), "V41 (930803) was rejected");
}

// ── Finding 10: source-file table vs the truncated u16 count ─────────────────

/// The header's `NumSourceFiles` is a u16 and saturates; the authoritative
/// count is the sum of `ModFileCounts`. Trusting the header put
/// `string_table_start` inside the offsets array, decoding u32 offset bytes as
/// filenames.
#[test]
fn source_file_table_sums_mod_file_counts_over_truncated_header() {
    let module_count = 2usize;
    let per_module = [3usize, 2];
    let total: usize = per_module.iter().sum(); // 5

    let mut data = Vec::new();
    data.extend_from_slice(&u16::try_from(module_count).unwrap().to_le_bytes());
    // Header count deliberately UNDER-reports (as a saturated writer would).
    data.extend_from_slice(&1u16.to_le_bytes());
    for _ in 0..module_count {
        data.extend_from_slice(&0u16.to_le_bytes()); // mod_indices, ignored
    }
    for &c in &per_module {
        data.extend_from_slice(&u16::try_from(c).unwrap().to_le_bytes());
    }

    // Offsets array sized by the REAL total, then the string buffer.
    let names = ["a.c", "b.c", "c.c", "d.c", "e.c"];
    let mut strings = Vec::new();
    let mut offsets = Vec::new();
    for n in &names {
        offsets.push(u32::try_from(strings.len()).unwrap());
        strings.extend_from_slice(n.as_bytes());
        strings.push(0);
    }
    assert_eq!(offsets.len(), total);
    for o in &offsets {
        data.extend_from_slice(&o.to_le_bytes());
    }
    data.extend_from_slice(&strings);

    let table = parse_source_file_table(&data).expect("source file table should parse");
    assert_eq!(table.modules.len(), 2);
    assert_eq!(table.modules[0].file_names, vec!["a.c", "b.c", "c.c"]);
    assert_eq!(table.modules[1].file_names, vec!["d.c", "e.c"]);
}

// ── Finding 7: lib.rs TPI enum name offset / struct numeric-leaf size ────────

use rustre_symbols_pdb::{parse_tpi_stream, TypeKind};

/// Frame a TPI stream containing one record.
fn tpi_stream(kind: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; 56];
    let len = u16::try_from(payload.len() + 2).unwrap();
    v.extend_from_slice(&len.to_le_bytes());
    v.extend_from_slice(&kind.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

/// `LF_ENUM`'s name starts at offset **12** (after a full u32 `field_list_ti`).
/// Reading at 10 spliced the low two bytes of `field_list_ti` onto the name.
#[test]
fn lib_tpi_enum_name_starts_at_offset_12() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&3u16.to_le_bytes()); // count
    payload.extend_from_slice(&0u16.to_le_bytes()); // property
    payload.extend_from_slice(&0x0074u32.to_le_bytes()); // underlying_ti
    // Chosen so its low bytes would be visible ASCII if read as name bytes.
    payload.extend_from_slice(&0x4142_4344u32.to_le_bytes()); // field_list_ti
    payload.extend_from_slice(b"Color\0");

    let types = parse_tpi_stream(&tpi_stream(0x1507, &payload))
        .expect("TPI should parse");
    assert!(
        types.iter().any(|t| t.name == "Color"),
        "enum name mis-read; got {:?}",
        types.iter().map(|t| &t.name).collect::<Vec<_>>()
    );
}

/// A struct larger than 32767 bytes stores its size as an `LF_LONG` numeric leaf
/// (0x8003 + 4 bytes), pushing the name past the hardcoded offset 18.
#[test]
fn lib_tpi_struct_size_is_a_numeric_leaf() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u16.to_le_bytes()); // count
    payload.extend_from_slice(&0u16.to_le_bytes()); // property
    payload.extend_from_slice(&0x1000u32.to_le_bytes()); // field
    payload.extend_from_slice(&0u32.to_le_bytes()); // derived
    payload.extend_from_slice(&0u32.to_le_bytes()); // vshape
    payload.extend_from_slice(&0x8003u16.to_le_bytes()); // LF_LONG tag
    payload.extend_from_slice(&40_000u32.to_le_bytes()); // size
    payload.extend_from_slice(b"Big\0");

    let types = parse_tpi_stream(&tpi_stream(0x1505, &payload))
        .expect("TPI should parse");
    let big = types
        .iter()
        .find(|t| t.name == "Big")
        .unwrap_or_else(|| panic!("name mis-read; got {:?}",
            types.iter().map(|t| &t.name).collect::<Vec<_>>()));
    assert_eq!(big.size, 40_000);
    assert!(matches!(big.kind, TypeKind::Struct { .. }));
}
