//! Hardening / regression tests for the 2026-07-21 audit findings.
//!
//! Same contract as `hardening.rs`: attacker-shaped or merely unusual-but-legal
//! input must produce an error or a degraded result — never a panic, a stack
//! overflow, or a silently wrong decode.

use rustre_symbols_stabs::stabs_complete::StabsComplete;
use rustre_symbols_stabs::stabs_line_info::{LineInfoDb, StabsLineEntry, StabsLineTable};
use rustre_symbols_stabs::stabs_reconstruct::StructLayout;
use rustre_symbols_stabs::stabs_type_decoder::{
    decode_type, underlying_type, StabType as DecStabType, TypeDatabase, TypeId,
};
use rustre_symbols_stabs::stabs_types::{
    StabsBaseType, StabsType as TypesStabsType, StabsStructField, StabsTypeDb, TypeRef as TypesRef,
};
use rustre_symbols_stabs::split_stab_name;

// ── Finding 1: underlying_type() cycles ──────────────────────────────────────

#[test]
fn underlying_type_terminates_on_mutual_typeref_cycle() {
    // `a:t(0,100)=(0,101)` and `b:t(0,101)=(0,100)` — legal, mutually recursive.
    let mut db = TypeDatabase::new();
    db.insert(
        TypeId::new(0, 100),
        DecStabType::TypeRef { module: 0, index: 101 },
    );
    db.insert(
        TypeId::new(0, 101),
        DecStabType::TypeRef { module: 0, index: 100 },
    );
    let start = DecStabType::TypeRef { module: 0, index: 100 };
    // Before the fix this recursed until STATUS_STACK_OVERFLOW.
    let resolved = underlying_type(&start, &db);
    assert!(matches!(resolved, DecStabType::TypeRef { .. }));
}

// ── Finding 2: unbounded recursive descent in all four type parsers ──────────

#[test]
fn decoder_parse_type_survives_deep_pointer_nesting() {
    let bomb = "*".repeat(100_000);
    let _ = decode_type(&bomb);
}

#[test]
fn full_parser_parse_type_descriptor_survives_deep_nesting() {
    let bomb = "*".repeat(100_000);
    let _ = rustre_symbols_stabs::stabs_full_parser::parse_type_descriptor(&bomb);
}

#[test]
fn type_parser_survives_deep_nesting() {
    let bomb = "*".repeat(100_000);
    let _ = rustre_symbols_stabs::stabs_type_parser::parse_type_descriptor(&bomb);
}

#[test]
fn type_resolver_survives_deep_nesting() {
    let bomb = "*".repeat(100_000);
    let _ = rustre_symbols_stabs::stabs_type_resolver::parse_type_string(&bomb, 0);
}

// ── Finding 3: StabsTypeDb::resolve() alias cycle ────────────────────────────

#[test]
fn typedb_resolve_terminates_on_alias_cycle() {
    let mut db = StabsTypeDb::new();
    db.insert(
        TypesRef::local(1),
        TypesStabsType::Alias(TypesRef::local(2)),
    );
    db.insert(
        TypesRef::local(2),
        TypesStabsType::Alias(TypesRef::local(1)),
    );
    // Before the fix this recursed forever.
    let got = db.resolve(&TypesRef::local(1));
    assert!(got.is_some());
}

// ── Finding 4: StructLayout::analyze integer overflow ────────────────────────

fn field(name: &str, bit_offset: u32, bit_size: u32) -> StabsStructField {
    StabsStructField {
        name: name.to_string(),
        type_ref: TypesRef::local(1),
        bit_offset,
        bit_size,
    }
}

#[test]
fn struct_layout_huge_declared_size_does_not_overflow() {
    // `s536870912` — a struct declaring 512 MiB. total_bytes * 8 wrapped.
    let l = StructLayout::analyze("S", &[field("a", 0, 8)], 0x2000_0000);
    assert_eq!(l.total_bytes, 0x2000_0000);
}

#[test]
fn struct_layout_max_offsets_do_not_overflow() {
    let fields = [field("a", u32::MAX - 16, 32)];
    let l = StructLayout::analyze("S", &fields, u32::MAX);
    // Efficiency must stay a sane ratio, never negative.
    let e = l.efficiency();
    assert!((0.0..=1.0).contains(&e), "efficiency out of range: {e}");
}

// ── Finding 6: XCOFF unchecked section arithmetic ────────────────────────────

#[test]
fn xcoff_extreme_section_offsets_return_error_not_panic() {
    use rustre_symbols_stabs::xcoff_stabs::XcoffStabsExtractor;
    for &scn_ptr in &[0u32, 1, u32::MAX] {
        for &size in &[0u32, 1, u32::MAX] {
            let mut data = vec![0u8; 128];
            // XCOFF32 magic + 1 section.
            data[0..2].copy_from_slice(&0x01DFu16.to_be_bytes());
            data[2..4].copy_from_slice(&1u16.to_be_bytes());
            // Section header at offset 20: 8-byte name then addresses.
            let sh = 20usize;
            data[sh..sh + 6].copy_from_slice(b".debug");
            data[sh + 20..sh + 24].copy_from_slice(&size.to_be_bytes());
            data[sh + 24..sh + 28].copy_from_slice(&scn_ptr.to_be_bytes());
            // Must not panic; any Result is acceptable.
            let _ = XcoffStabsExtractor::extract(&data);
        }
    }
}

// ── Finding 7: the canonical GCC array descriptor ────────────────────────────

#[test]
fn type_parser_parses_canonical_array_descriptor() {
    // `int buf[10]` — the form GCC actually emits. Previously Err(UnexpectedEnd).
    let got = rustre_symbols_stabs::stabs_type_parser::parse_type_descriptor("ar(0,1);0;9;(0,1)");
    assert!(got.is_ok(), "canonical array descriptor failed: {got:?}");
}

#[test]
fn type_parser_parses_unbounded_and_nested_arrays() {
    assert!(
        rustre_symbols_stabs::stabs_type_parser::parse_type_descriptor("ar(0,1);0;-1;(0,2)")
            .is_ok()
    );
    assert!(rustre_symbols_stabs::stabs_type_parser::parse_type_descriptor(
        "ar(0,1);0;1;ar(0,1);0;2;(0,1)"
    )
    .is_ok());
}

// ── Finding 8: the GNU negative built-in type table ──────────────────────────

#[test]
fn gnu_builtin_negative_numbers_match_the_gdb_assignment() {
    use rustre_symbols_stabs::stabs_types::StabsTypeParser;
    let base = |s: &str| match StabsTypeParser::parse(s).unwrap().0 {
        TypesStabsType::Base(b) => b,
        other => panic!("expected base type for {s}, got {other:?}"),
    };
    assert!(matches!(base("-2"), StabsBaseType::Char), "-2 is char");
    assert!(
        matches!(base("-4"), StabsBaseType::Int { bits: 64, signed: true }),
        "-4 is long"
    );
    assert!(
        matches!(base("-6"), StabsBaseType::Int { bits: 8, signed: true }),
        "-6 is signed char"
    );
    assert!(matches!(base("-11"), StabsBaseType::Void), "-11 is void");
    assert!(matches!(base("-16"), StabsBaseType::Bool), "-16 is boolean");
    assert!(
        matches!(base("-12"), StabsBaseType::Float { bits: 32 }),
        "-12 is float"
    );
    assert!(
        matches!(base("-13"), StabsBaseType::Float { bits: 64 }),
        "-13 is double"
    );
    assert!(
        matches!(base("-31"), StabsBaseType::Int { bits: 64, signed: true }),
        "-31 is long long"
    );
}

// ── Finding 15: C++ names must not be split at the first colon ───────────────

#[test]
fn split_stab_name_skips_cxx_qualifiers() {
    assert_eq!(split_stab_name("Foo::bar:F(0,1)"), ("Foo::bar", "F(0,1)"));
    assert_eq!(split_stab_name("main:F(0,1)"), ("main", "F(0,1)"));
    assert_eq!(split_stab_name("A::B::c:V"), ("A::B::c", "V"));
    assert_eq!(split_stab_name("noColon"), ("noColon", ""));
}

#[test]
fn stab_record_symbol_name_is_cxx_aware() {
    use rustre_symbols_stabs::{StabRecord, StabType};
    let r = StabRecord {
        strx: 0,
        stab_type: StabType::NFun,
        other: 0,
        desc: 0,
        value: 0x1000,
        string: "Foo::bar:F(0,1)".to_string(),
    };
    assert_eq!(r.symbol_name(), "Foo::bar");
    assert_eq!(r.type_descriptor(), "F(0,1)");
}

// ── Finding 13: saturating address arithmetic in LineInfoDb ──────────────────

#[test]
fn line_info_huge_image_base_does_not_panic() {
    let entries: Vec<(u8, u16, u32, &str)> = vec![
        (0x64, 0, 0, "prog.c"),
        (0x24, 0, 0xFFFF_FFFF, "main:F(0,1)"),
        (0x44, 7, 0xFFFF_FFFF, ""),
    ];
    let _ = LineInfoDb::build_from_stabs(&entries, u64::MAX);
}

// ── Finding 14: per-function line tables must be sorted ──────────────────────

#[test]
fn non_final_function_table_is_sorted_for_binary_search() {
    let mut db = LineInfoDb::new();
    // "foo" is flushed first, and its N_SLINEs arrive out of address order.
    let mut foo = StabsLineTable::new("foo".to_string(), 0x1000);
    foo.add(StabsLineEntry::new(0x1030, "a.c".to_string(), 30));
    foo.add(StabsLineEntry::new(0x1010, "a.c".to_string(), 10));
    foo.add(StabsLineEntry::new(0x1020, "a.c".to_string(), 20));
    db.add_table(foo);
    let mut bar = StabsLineTable::new("bar".to_string(), 0x2000);
    bar.add(StabsLineEntry::new(0x2000, "a.c".to_string(), 99));
    db.add_table(bar);

    let t = db.function_table("foo").expect("foo table");
    // Before the fix add_table stored the table unsorted and partition_point
    // walked garbage.
    let hit = t.lookup_address(0x1025).expect("lookup 0x1025");
    assert_eq!(hit.line, 20, "expected the entry at 0x1020");
}

// ── Finding 9: N_FUN terminator and name/descriptor split in StabsComplete ───

#[test]
fn stabs_complete_strips_descriptor_and_closes_function() {
    use rustre_symbols_stabs::stabs_complete::RawStab;
    fn r(str_index: u32, n_type: u8, n_value: u32) -> RawStab {
        RawStab { str_index, n_type, n_other: 0, n_desc: 0, n_value }
    }
    let mut strtab = Vec::new();
    let so = 0u32;
    strtab.extend_from_slice(b"prog.c ");
    let fun = u32::try_from(strtab.len()).unwrap();
    strtab.extend_from_slice(b"main:F(0,1) ");
    let end = u32::try_from(strtab.len()).unwrap();
    strtab.extend_from_slice(b" ");

    let stabs = vec![
        r(so, 0x64, 0),       // N_SO prog.c
        r(fun, 0x24, 0x1000), // N_FUN main
        r(end, 0x24, 0x80),   // empty-name N_FUN = size 0x80
    ];
    let report = StabsComplete::new().parse(&stabs, &strtab).expect("parse");
    let cu = report.compilation_units.first().expect("one CU");
    assert_eq!(cu.children.len(), 1, "no phantom empty-named scope");
    assert_eq!(cu.children[0].name, "main", "descriptor must be stripped");
    assert_eq!(cu.children[0].end, 0x1080, "end must come from the terminator");
}

// ── Finding 19: N_LBRAC nesting depth is capped ──────────────────────────────

#[test]
fn cfparser_caps_scope_nesting_depth() {
    use rustre_symbols_stabs::stabs_cfparser::{CfRecord, StabsCfParser};
    let mut p = StabsCfParser::new();
    p.feed(CfRecord::NFun {
        name_desc: "f:F(0,1)".to_string(),
        address: 0x1000,
    });
    for i in 0..100_000u64 {
        p.feed(CfRecord::LBrac { address: 0x1000 + i });
    }
    for i in (0..100_000u64).rev() {
        p.feed(CfRecord::RBrac { address: 0x1000 + i });
    }
    // Must not overflow the stack on construction, traversal, or drop.
    let _ = p.functions.len();
}

// ── Finding 21: structural range decoding ────────────────────────────────────

#[test]
fn range_descriptor_decodes_widths_structurally() {
    use rustre_symbols_stabs::stabs_type_resolver::{parse_type_string, StabsType as RType};
    // 64-bit signed range must not be reported as 4 bytes.
    let ll = parse_type_string("r(0,1);-9223372036854775808;9223372036854775807;", 0)
        .expect("long long range");
    assert!(
        matches!(ll, RType::Int { signed: true, bytes: 8 }),
        "long long decoded as {ll:?}"
    );
    // An array index range must not become a float.
    let idx = parse_type_string("r(0,1);0;9;", 0).expect("index range");
    assert!(matches!(idx, RType::Int { .. }), "index range decoded as {idx:?}");
    // The unsigned-word form.
    let u = parse_type_string("r1;0;-1;", 0).expect("unsigned form");
    assert!(
        matches!(u, RType::Int { signed: false, .. }),
        "r1;0;-1; decoded as {u:?}"
    );
    // The float size-encoding form.
    let f = parse_type_string("r1;8;0;", 0).expect("float form");
    assert!(matches!(f, RType::Float { bytes: 8 }), "r1;8;0; decoded as {f:?}");
}

// ── Finding 16: cross-reference kind must survive ────────────────────────────

#[test]
fn xref_union_and_enum_keep_their_kind() {
    use rustre_symbols_stabs::stabs_type_resolver::{parse_type_string, StabsType as RType};
    let u = parse_type_string("xuMyUnion:", 0).expect("xu");
    assert!(matches!(u, RType::Union { .. }), "xu became {u:?}");
    let e = parse_type_string("xeMyEnum:", 0).expect("xe");
    assert!(matches!(e, RType::Enum { .. }), "xe became {e:?}");
    let s = parse_type_string("xsMyStruct:", 0).expect("xs");
    assert!(matches!(s, RType::Struct { .. }), "xs became {s:?}");
}

// ── Finding 12: debug_asserts must not fire on ordinary malformed input ──────

#[test]
fn line_for_addr_on_unterminated_function_does_not_assert() {
    use rustre_symbols_stabs::stabs_parser::{LineEntry, ParsedFunction};
    let f = ParsedFunction {
        name: "f".to_string(),
        type_str: String::new(),
        start_addr: 0x1000,
        end_addr: 0, // never closed by an empty-name N_FUN
        source_file: String::new(),
        params: Vec::new(),
        locals: Vec::new(),
        reg_vars: Vec::new(),
        lines: vec![LineEntry { address: 0x1000, line: 1, file_idx: 0 }],
        brackets: Vec::new(),
    };
    // Debug builds previously aborted here because size() is 0.
    let _ = f.line_for_addr(0x1FFF);
}
