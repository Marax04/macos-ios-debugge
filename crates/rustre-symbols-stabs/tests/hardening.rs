//! Hardening / regression tests for the 2026-07-20 audit findings.
//!
//! Mirrors the pattern of `rustre-symbols-pdb/tests/hardening.rs`:
//! attacker-shaped inputs must produce errors or degraded results, never a
//! panic, stack overflow, or unbounded allocation.

use rustre_symbols::SymbolProvider;
use rustre_symbols_stabs::stabs_type_resolver::{StabsType, StabsTypeResolver, TypeRef};
use rustre_symbols_stabs::{
    sline_address, StabRecord, StabsParser, StabsProvider, StabsTypeDescParser, StabType,
};

fn rec(t: StabType, desc: u16, value: u32, s: &str) -> StabRecord {
    StabRecord {
        strx: 0,
        stab_type: t,
        other: 0,
        desc,
        value,
        string: s.to_string(),
    }
}

// ── Finding 1 (critical): self-referential types must not overflow the stack ──

#[test]
fn resolve_all_terminates_on_self_referential_type() {
    // struct node { struct node *next; } → "(0,1)=*(0,1)"
    let mut r = StabsTypeResolver::new();
    r.register_definition("(0,1)=*(0,1)").unwrap();
    r.resolve_all(); // must terminate, not overflow
    assert!(r.lookup(TypeRef::new(0, 1)).is_some());
}

#[test]
fn resolve_all_terminates_on_mutual_cycle() {
    // "(0,1)=(0,2)" / "(0,2)=(0,1)"
    let mut r = StabsTypeResolver::new();
    r.register_definition("(0,1)=(0,2)").unwrap();
    r.register_definition("(0,2)=(0,1)").unwrap();
    r.resolve_all();
    // Cycle collapses to Unresolved instead of recursing forever.
    let t = r.lookup(TypeRef::new(0, 1)).unwrap().clone();
    assert!(matches!(t, StabsType::Unresolved(_)));
}

// ── Finding 2 (high): N_ code constants must agree with binutils stab.def ──

#[test]
fn stabs_complete_codes_match_stab_def() {
    use rustre_symbols_stabs::stabs_complete::StabType as C;
    assert_eq!(C::from_byte(0x3C), Some(C::Opt), "N_OPT is 0x3C");
    assert_eq!(C::from_byte(0x3A), Some(C::MacUndef), "N_MAC_UNDEF is 0x3A");
    assert_eq!(C::from_byte(0x3E), None, "0x3E is not a defined N_ code");
    assert_eq!(C::from_byte(0xF4), Some(C::Nbbss), "0xF4 is N_NBBSS");
}

#[test]
fn stabs_complete_agrees_with_lib_enum_for_all_bytes() {
    use rustre_symbols_stabs::stabs_complete::StabType as C;
    for b in 0..=255u8 {
        if let Some(t) = C::from_byte(b) {
            // Discriminant roundtrip: no shifted/colliding values.
            assert_eq!(t as u8, b, "stabs_complete roundtrip for byte {b:#04x}");
            // Where lib.rs names the byte, the complete enum must not
            // occupy a byte lib.rs considers a *different* record family.
            if b == 0x3C {
                assert_eq!(StabType::from_u8(b), StabType::NOpt);
                assert_eq!(t, C::Opt);
            }
            if b == 0xF4 {
                assert_eq!(StabType::from_u8(b), StabType::NNbbss);
                assert_eq!(t, C::Nbbss);
            }
        }
    }
}

// ── Finding 3 (medium): consistent N_SLINE address semantics ──

#[test]
fn sline_semantics_consistent_between_parser_and_provider() {
    let base = 0x40_0000u64;
    let records = vec![
        rec(StabType::NSo, 0, 0, "main.c"),
        rec(StabType::NFun, 1, 0x1000, "foo:F1"),
        rec(StabType::NSline, 5, 0x10, ""), // fn-relative offset 0x10
    ];

    // StabsParser path.
    let mut p = StabsParser::new();
    p.process(&records, base).unwrap();
    let e = &p.line_table().entries()[0];
    assert_eq!(e.address, base + 0x1000 + 0x10);
    assert_eq!(e.line, 5);

    // StabsProvider path must agree.
    let prov = StabsProvider::from_records(&records, base);
    let loc = prov.source_line_for_address(base + 0x1000 + 0x10).unwrap();
    assert_eq!(loc.line, 5);
    assert_eq!(loc.file, "main.c");

    // Outside any N_FUN scope: absolute (image_base + value).
    let records2 = vec![
        rec(StabType::NSo, 0, 0, "main.c"),
        rec(StabType::NSline, 7, 0x2000, ""),
    ];
    let prov2 = StabsProvider::from_records(&records2, base);
    assert_eq!(
        prov2.source_line_for_address(base + 0x2000).unwrap().line,
        7
    );
    // Shared helper encodes the same rule.
    assert_eq!(sline_address(None, base, 0x2000), base + 0x2000);
    assert_eq!(sline_address(Some(base + 0x1000), base, 0x10), base + 0x1010);
}

// ── Finding 4 (medium): strip at most ONE leading symbol-code letter ──

#[test]
fn type_desc_strips_single_code_letter_only() {
    // Bare "f" is the float built-in — must not be stripped to "".
    let f = StabsTypeDescParser::parse_type_desc("f");
    assert_eq!(f.kind, "float");
    // Bare "d" double still works.
    assert_eq!(StabsTypeDescParser::parse_type_desc("d").kind, "double");
    // "f(0,1)" (function code + type ref) strips exactly one letter.
    let fr = StabsTypeDescParser::parse_type_desc("f(0,1)");
    assert_eq!(fr.kind, "ref");
    // "Tt..." must lose only the first letter, so the struct payload after
    // the single code letter is still visible to the descriptor arms.
    let ts = StabsTypeDescParser::parse_type_desc("Ts4x:1,0,32;;");
    assert_eq!(ts.kind, "struct");
}

// ── Finding 5 (medium): provider lookups are index/binary-search based ──

#[test]
fn provider_lookups_correct_after_sorting() {
    let base = 0x1000u64;
    let records = vec![
        rec(StabType::NSo, 0, 0, "a.c"),
        rec(StabType::NFun, 1, 0x300, "zeta:F1"),
        rec(StabType::NFun, 1, 0x100, "alpha:F1"),
        rec(StabType::NGsym, 0, 0x200, "g:G1"),
    ];
    let prov = StabsProvider::from_records(&records, base);
    assert_eq!(prov.lookup_name("alpha").unwrap().address, base + 0x100);
    assert_eq!(prov.lookup_address(base + 0x300).unwrap().name, "zeta");
    assert_eq!(prov.lookup_nearest(base + 0x350).unwrap().name, "zeta");
    assert_eq!(prov.lookup_nearest(base + 0x150).unwrap().name, "alpha");
    assert!(prov.lookup_nearest(0).is_none());
    let sorted = prov.symbols_sorted();
    assert!(sorted.windows(2).all(|w| w[0].address <= w[1].address));
}

// ── Finding 7 (low): image_base + value must never overflow/panic ──

#[test]
fn huge_image_base_does_not_panic() {
    let records = vec![
        rec(StabType::NSo, 0, 0, "a.c"),
        rec(StabType::NFun, 1, u32::MAX, "f:F1"),
        rec(StabType::NSline, 1, u32::MAX, ""),
        rec(StabType::NStsym, 0, u32::MAX, "s:S1"),
        rec(StabType::NGsym, 0, u32::MAX, "g:G1"),
    ];
    let _ = StabsProvider::from_records(&records, u64::MAX);
    let mut p = StabsParser::new();
    p.process(&records, u64::MAX).unwrap();
}

// ── Finding 8 (info): truncated/garbage raw input never panics ──

#[test]
fn parse_all_on_truncated_and_garbage_bytes() {
    for len in 0..48usize {
        let data: Vec<u8> = (0..len).map(|i| (i * 37) as u8).collect();
        let _ = StabRecord::parse_all(&data, &data);
        let _ = StabsProvider::from_bytes(&data, &data, u64::MAX);
    }
    // strx values pointing far past the string table.
    let mut bad = vec![0u8; 24];
    bad[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
    let _ = StabRecord::parse_all(&bad, b"x\0");
}
