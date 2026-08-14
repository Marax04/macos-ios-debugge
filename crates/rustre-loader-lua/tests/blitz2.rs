//! Second deep-coverage integration test file for `rustre-loader-lua`.
//!
//! Targets modules under-tested by `blitz.rs`: the standalone
//! `lua_bytecode_parser`, `lua_constant_pool`, `lua_string_extractor`,
//! `lua_version_detector`, and `luajit_loader` sub-modules.

use rustre_loader_lua::lua_bytecode_parser::{
    LocalVar, LuaBytecodeParser, LuaConstant, LuaHeader, LuaProto as LbpProto,
    LuaVersion as BpVersion, ParseError, UpvalueDesc,
};
use rustre_loader_lua::lua_constant_pool::{
    ConstKind, ConstRef, ConstantPoolBuilder, ConstantUsageTracker, LuaConstantPool,
    PooledConst, resolve_const, resolve_const_kind,
};
use rustre_loader_lua::lua_string_extractor::{
    ExtractedString, LuaStringExtractor, StringCategory, StringFilter, StringStats,
};
use rustre_loader_lua::lua_version_detector::{
    AutoDecoder, LuaFeatureSet, LuaVersion as DetVersion, LuaVersionDetector, VersionReport,
    VersionSignature, all_signatures,
};
use rustre_loader_lua::luajit_loader::{
    BcDumpHeader, LuaJitVersion, is_luajit_bytecode, is_call_op, is_jump_op, is_return_op,
    kgc_tag_name, ktab_tag_name, load_luajit, opcode_name as ljit_opcode_name,
    proto_has_iloop,
};
use rustre_loader_lua::{LuaConst, LuaProto, LuaVersion};

use std::collections::HashSet;

// ── Seeded LCG ──────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    const fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self.0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn next_u8(&mut self) -> u8 {
        (self.next() >> 56) as u8
    }
}

// ── lua_bytecode_parser tests ───────────────────────────────────────────────

#[test]
fn bp_version_byte_roundtrip() {
    for b in [0x51u8, 0x52, 0x53, 0x54] {
        let v = BpVersion::from_byte(b).expect("known version");
        assert!(v.as_str().starts_with("5."));
    }
}

#[test]
fn bp_version_unknown_byte_returns_none() {
    assert!(BpVersion::from_byte(0x00).is_none());
    assert!(BpVersion::from_byte(0x50).is_none());
    assert!(BpVersion::from_byte(0xFF).is_none());
}

#[test]
fn bp_version_integer64_flags() {
    assert!(!BpVersion::Lua51.uses_integer64());
    assert!(!BpVersion::Lua52.uses_integer64());
    assert!(BpVersion::Lua53.uses_integer64());
    assert!(BpVersion::Lua54.uses_integer64());
}

#[test]
fn bp_version_integer_tag_only_53_54() {
    assert_eq!(BpVersion::Lua51.integer_tag(), None);
    assert_eq!(BpVersion::Lua52.integer_tag(), None);
    assert_eq!(BpVersion::Lua53.integer_tag(), Some(0x13));
    assert_eq!(BpVersion::Lua54.integer_tag(), Some(0x13));
}

#[test]
fn bp_header_check_magic_good_and_bad() {
    assert!(LuaHeader::check_magic(b"\x1bLua...."));
    assert!(!LuaHeader::check_magic(b"\x1bLu"));
    assert!(!LuaHeader::check_magic(b""));
    assert!(!LuaHeader::check_magic(b"\x1bLub....."));
}

#[test]
fn bp_constant_is_string_variants() {
    assert!(LuaConstant::String("x".into()).is_string());
    assert!(LuaConstant::ShortString("y".into()).is_string());
    assert!(!LuaConstant::Nil.is_string());
    assert!(!LuaConstant::Integer(7).is_string());
    assert!(!LuaConstant::Float(1.5).is_string());
    assert!(!LuaConstant::Boolean(true).is_string());
}

#[test]
fn bp_constant_as_str_extracts() {
    assert_eq!(LuaConstant::String("hi".into()).as_str(), Some("hi"));
    assert_eq!(LuaConstant::ShortString("ho".into()).as_str(), Some("ho"));
    assert_eq!(LuaConstant::Nil.as_str(), None);
    assert_eq!(LuaConstant::Integer(0).as_str(), None);
}

#[test]
fn bp_constant_display_formats() {
    assert_eq!(format!("{}", LuaConstant::Nil), "nil");
    assert_eq!(format!("{}", LuaConstant::Boolean(true)), "true");
    assert_eq!(format!("{}", LuaConstant::Integer(-42)), "-42");
    // strings are debug-quoted
    let s = format!("{}", LuaConstant::String("hi".into()));
    assert!(s.contains("hi"));
    assert!(s.starts_with('"'));
}

#[test]
fn bp_upvalue_simple_and_local_capture() {
    let u = UpvalueDesc::simple(1, 7);
    assert!(u.is_local_capture());
    assert_eq!(u.idx, 7);
    let u2 = UpvalueDesc::simple(0, 0);
    assert!(!u2.is_local_capture());
}

#[test]
fn bp_localvar_is_live_at_boundaries() {
    let lv = LocalVar { name: "a".into(), start_pc: 5, end_pc: 10 };
    // Live range is [start_pc, end_pc)
    assert!(!lv.is_live_at(4));
    assert!(lv.is_live_at(5));
    assert!(lv.is_live_at(9));
    assert!(!lv.is_live_at(10));
    assert!(!lv.is_live_at(11));
}

#[test]
fn bp_proto_empty_defaults() {
    let p = LbpProto::empty();
    assert_eq!(p.insn_count(), 0);
    assert_eq!(p.total_proto_count(), 1);
    assert!(p.all_strings().is_empty());
    assert!(!p.has_debug_info());
    assert!(p.locals_at(0).is_empty());
}

#[test]
fn bp_proto_total_count_with_nesting() {
    let mut root = LbpProto::empty();
    let mut a = LbpProto::empty();
    a.protos.push(LbpProto::empty());
    a.protos.push(LbpProto::empty());
    root.protos.push(a);
    root.protos.push(LbpProto::empty());
    // root + a + 2 children + sibling = 5
    assert_eq!(root.total_proto_count(), 5);
}

#[test]
fn bp_proto_opcode_at_masks_correctly() {
    let mut p = LbpProto::empty();
    p.instructions.push(0xFFFF_FFFF);
    // Lua 5.1/5.2/5.3: low 6 bits
    assert_eq!(p.opcode_at(0, BpVersion::Lua51), 0x3F);
    assert_eq!(p.opcode_at(0, BpVersion::Lua53), 0x3F);
    // Lua 5.4: low 7 bits
    assert_eq!(p.opcode_at(0, BpVersion::Lua54), 0x7F);
}

#[test]
fn bp_parser_bad_magic_errors() {
    let mut p = LuaBytecodeParser::new();
    let r = p.parse(b"not lua bytecode");
    assert!(matches!(r, Err(ParseError::BadMagic)));
}

#[test]
fn bp_parser_truncated_after_magic_errors() {
    let mut p = LuaBytecodeParser::new();
    let r = p.parse(b"\x1bLua");
    // No version byte → truncated
    assert!(matches!(r, Err(ParseError::Truncated)));
}

#[test]
fn bp_parser_unknown_version_errors() {
    let mut p = LuaBytecodeParser::new();
    let mut buf = b"\x1bLua".to_vec();
    buf.push(0x99);
    let r = p.parse(&buf);
    assert!(matches!(r, Err(ParseError::UnknownVersion(0x99))));
}

#[test]
fn bp_parser_lcg_fuzz_never_panics() {
    let mut lcg = Lcg::new();
    let mut parser = LuaBytecodeParser::new();
    for _ in 0..60 {
        let len = (lcg.next() as usize % 96) + 4;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(lcg.next_u8());
        }
        // Force-magic some of the iterations to drive deeper parsing.
        if lcg.next_u8() & 1 == 0 && buf.len() >= 5 {
            buf[0] = 0x1b;
            buf[1] = b'L';
            buf[2] = b'u';
            buf[3] = b'a';
            buf[4] = match lcg.next_u8() % 4 {
                0 => 0x51,
                1 => 0x52,
                2 => 0x53,
                _ => 0x54,
            };
        }
        let _ = parser.parse(&buf); // must return, never panic
    }
}

#[test]
fn bp_parse_error_display_contains_kind() {
    assert!(format!("{}", ParseError::Truncated).contains("trunc"));
    assert!(format!("{}", ParseError::BadMagic).contains("magic"));
    assert!(format!("{}", ParseError::UnknownVersion(0xAB)).contains("0xab"));
    assert!(format!("{}", ParseError::Unsupported("x".into())).contains('x'));
    assert!(format!("{}", ParseError::Malformed("y".into())).contains('y'));
}

// ── lua_constant_pool tests ─────────────────────────────────────────────────

fn sample() -> Vec<LuaConst> {
    vec![
        LuaConst::Str("hello".into()),
        LuaConst::Integer(42),
        LuaConst::Number(3.14),
        LuaConst::Bool(true),
        LuaConst::Nil,
        LuaConst::Str("world".into()),
        LuaConst::LongStr("loooong".into()),
        LuaConst::Bool(false),
        LuaConst::Integer(-7),
        LuaConst::Str("hello".into()), // duplicate of index 0
    ]
}

#[test]
fn cp_kind_is_string_and_numeric() {
    assert!(ConstKind::ShortString.is_string());
    assert!(ConstKind::LongString.is_string());
    assert!(!ConstKind::Integer.is_string());
    assert!(ConstKind::Float.is_numeric());
    assert!(ConstKind::Integer.is_numeric());
    assert!(!ConstKind::Boolean.is_numeric());
    assert!(!ConstKind::Nil.is_numeric());
}

#[test]
fn cp_kind_display_strings() {
    assert_eq!(format!("{}", ConstKind::Nil), "nil");
    assert_eq!(format!("{}", ConstKind::Boolean), "boolean");
    assert_eq!(format!("{}", ConstKind::Float), "float");
    assert_eq!(format!("{}", ConstKind::Integer), "integer");
    assert_eq!(format!("{}", ConstKind::ShortString), "string");
    assert_eq!(format!("{}", ConstKind::LongString), "longstring");
}

#[test]
fn cp_constref_new_and_display() {
    let cr = ConstRef::new(3, 7);
    assert_eq!(cr.proto_id, 3);
    assert_eq!(cr.const_index, 7);
    let s = format!("{cr}");
    assert!(s.contains('3') && s.contains('7'));
}

#[test]
fn cp_constref_hash_eq_consistency() {
    let pairs: Vec<(ConstRef, ConstRef)> = (0..40)
        .map(|i| (ConstRef::new(i, i + 1), ConstRef::new(i, i + 1)))
        .collect();
    let mut set: HashSet<ConstRef> = HashSet::new();
    for (a, b) in &pairs {
        assert_eq!(a, b);
        set.insert(*a);
    }
    // All 40 should be distinct, equality matches
    assert_eq!(set.len(), 40);
}

#[test]
fn cp_pool_ingest_counts_and_indexes() {
    let mut pool = LuaConstantPool::new();
    pool.ingest_proto_constants(0, &sample());
    assert_eq!(pool.total_count(), 10);
    assert_eq!(pool.count_by_kind(ConstKind::ShortString), 3);
    assert_eq!(pool.count_by_kind(ConstKind::LongString), 1);
    assert_eq!(pool.count_by_kind(ConstKind::Integer), 2);
    assert_eq!(pool.count_by_kind(ConstKind::Boolean), 2);
    assert_eq!(pool.count_by_kind(ConstKind::Nil), 1);
    assert_eq!(pool.count_by_kind(ConstKind::Float), 1);
    // unique string values: hello, world, loooong = 3
    assert_eq!(pool.unique_string_count(), 3);
}

#[test]
fn cp_pool_find_by_string_returns_all_refs() {
    let mut pool = LuaConstantPool::new();
    pool.ingest_proto_constants(0, &sample());
    let refs = pool.find_by_string("hello");
    assert_eq!(refs.len(), 2);
    assert!(refs.iter().any(|r| r.const_index == 0));
    assert!(refs.iter().any(|r| r.const_index == 9));
    assert!(pool.find_by_string("does-not-exist").is_empty());
}

#[test]
fn cp_pool_find_by_integer() {
    let mut pool = LuaConstantPool::new();
    pool.ingest_proto_constants(0, &sample());
    assert_eq!(pool.find_by_integer(42).len(), 1);
    assert_eq!(pool.find_by_integer(-7).len(), 1);
    assert!(pool.find_by_integer(9999).is_empty());
}

#[test]
fn cp_pool_resolve_roundtrip() {
    let mut pool = LuaConstantPool::new();
    pool.ingest_proto_constants(0, &sample());
    let refs = pool.find_by_string("world");
    assert_eq!(refs.len(), 1);
    let pc: &PooledConst = pool.resolve(refs[0]).expect("present");
    assert_eq!(pc.string_value.as_deref(), Some("world"));
    // bad ref
    assert!(pool.resolve(ConstRef::new(99, 99)).is_none());
}

#[test]
fn cp_pool_duplicate_strings_only_lists_multi() {
    let mut pool = LuaConstantPool::new();
    pool.ingest_proto_constants(0, &sample());
    let dups = pool.duplicate_strings();
    assert_eq!(dups.len(), 1);
    assert_eq!(dups[0].0, "hello");
    assert_eq!(dups[0].1, 2);
}

#[test]
fn cp_pool_sorted_integers_dedup_and_sort() {
    let consts = vec![
        LuaConst::Integer(5),
        LuaConst::Integer(-3),
        LuaConst::Integer(5),
        LuaConst::Integer(0),
        LuaConst::Integer(i64::MAX),
        LuaConst::Integer(i64::MIN),
    ];
    let mut pool = LuaConstantPool::new();
    pool.ingest_proto_constants(0, &consts);
    let sorted = pool.sorted_integers();
    assert_eq!(sorted, vec![i64::MIN, -3, 0, 5, i64::MAX]);
}

#[test]
fn cp_pool_multiple_protos_proto_count_grows() {
    let mut pool = LuaConstantPool::new();
    pool.ingest_proto_constants(0, &sample());
    pool.ingest_proto_constants(2, &[LuaConst::Nil]);
    // proto_count = max id + 1 = 3
    assert_eq!(pool.proto_count(), 3);
}

#[test]
fn cp_pool_strings_containing() {
    let mut pool = LuaConstantPool::new();
    pool.ingest_proto_constants(0, &sample());
    let hits = pool.find_strings_containing("ell");
    assert_eq!(hits.len(), 2); // both "hello"
    let none = pool.find_strings_containing("zzzz");
    assert!(none.is_empty());
}

#[test]
fn cp_resolve_const_helpers() {
    let consts = sample();
    assert!(resolve_const(&consts, 0).is_some());
    assert!(resolve_const(&consts, 9).is_some());
    assert!(resolve_const(&consts, 10).is_none());
    assert_eq!(resolve_const_kind(&consts, 1), Some(ConstKind::Integer));
    assert_eq!(resolve_const_kind(&consts, 2), Some(ConstKind::Float));
    assert_eq!(resolve_const_kind(&consts, 4), Some(ConstKind::Nil));
    assert_eq!(resolve_const_kind(&consts, 6), Some(ConstKind::LongString));
    assert_eq!(resolve_const_kind(&consts, 999), None);
}

#[test]
fn cp_builder_walks_proto_tree() {
    let mut root = LuaProto::mock(LuaVersion::Lua54);
    let mut child = LuaProto::mock(LuaVersion::Lua54);
    child.constants = vec![LuaConst::Integer(100)];
    root.protos.push(child);
    let pool = ConstantPoolBuilder::build(&root);
    // root has 5 constants + child has 1 = 6
    assert_eq!(pool.total_count(), 6);
    assert_eq!(pool.proto_count(), 2);
    assert_eq!(pool.find_by_integer(100).len(), 1);
}

#[test]
fn cp_usage_tracker_basic() {
    let mut pool = LuaConstantPool::new();
    pool.ingest_proto_constants(0, &sample());
    let mut tr = ConstantUsageTracker::new();
    for _ in 0..3 {
        tr.record_use(0, 0);
    }
    tr.record_use(0, 1);
    assert_eq!(tr.use_count(0, 0), 3);
    assert_eq!(tr.use_count(0, 1), 1);
    assert_eq!(tr.use_count(0, 5), 0);
    let dead = tr.dead_constants(&pool);
    // 10 total, 2 used => 8 dead
    assert_eq!(dead.len(), 8);
    let hot = tr.hottest_constants(&pool);
    assert_eq!(hot.len(), 10);
    assert_eq!(hot[0].1, 3); // hottest is the one used 3x
}

#[test]
fn cp_pooled_const_label_and_display() {
    let mut pool = LuaConstantPool::new();
    pool.ingest_proto_constants(0, &sample());
    for entry in pool.by_kind(ConstKind::Integer) {
        let lbl = entry.label();
        // integers parse as numbers
        assert!(lbl.parse::<i64>().is_ok());
        let disp = format!("{entry}");
        assert!(disp.contains("integer"));
    }
}

// ── lua_string_extractor tests ──────────────────────────────────────────────

#[test]
fn se_extracted_string_basic_fields() {
    let e = ExtractedString::new("hello".into(), 0, 0);
    assert_eq!(e.byte_len, 5);
    assert_eq!(e.char_len, 5);
    assert!(e.is_valid_utf8);
    assert!(e.entropy >= 0.0);
}

#[test]
fn se_category_url_detected() {
    let e = ExtractedString::new("https://example.com/foo".into(), 0, 0);
    assert!(e.has_category(StringCategory::Url));
}

#[test]
fn se_category_path_detected() {
    let e = ExtractedString::new("/usr/local/lib/lua/init.lua".into(), 0, 0);
    assert!(e.has_category(StringCategory::FilePath));
}

#[test]
fn se_category_format_string() {
    let e = ExtractedString::new("user=%s id=%d".into(), 0, 0);
    assert!(e.has_category(StringCategory::FormatString));
}

#[test]
fn se_category_crypto_constant() {
    let e = ExtractedString::new("AES-256-CBC".into(), 0, 0);
    assert!(e.has_category(StringCategory::CryptoConstant));
}

#[test]
fn se_category_keyword() {
    let e = ExtractedString::new("function".into(), 0, 0);
    assert!(e.has_category(StringCategory::Keyword));
}

#[test]
fn se_category_empty_for_empty_string() {
    let e = ExtractedString::new(String::new(), 0, 0);
    assert!(e.has_category(StringCategory::Empty));
    assert_eq!(e.entropy, 0.0);
}

#[test]
fn se_extractor_dedup_works() {
    let raw = vec![
        ("alpha".to_string(), 0, 0),
        ("alpha".to_string(), 1, 0),
        ("beta".to_string(), 0, 1),
    ];
    let ex = LuaStringExtractor::new().with_dedup(true).with_min_length(1);
    let out = ex.extract_from_raw(raw);
    assert_eq!(out.len(), 2);
}

#[test]
fn se_extractor_min_length_filter() {
    let raw = vec![
        ("a".to_string(), 0, 0),
        ("ab".to_string(), 0, 1),
        ("abc".to_string(), 0, 2),
    ];
    let ex = LuaStringExtractor::new().with_min_length(3).with_dedup(false);
    let out = ex.extract_from_raw(raw);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].value, "abc");
}

#[test]
fn se_extractor_sorted_by_score_desc() {
    let raw = vec![
        ("plain text here".to_string(), 0, 0),
        ("https://x.com/very/long/url/with/depth".to_string(), 0, 1),
        ("AES-CBC-256-SECRET".to_string(), 0, 2),
    ];
    let ex = LuaStringExtractor::new().with_dedup(false);
    let out = ex.extract_from_raw(raw);
    // results sorted descending by score
    for w in out.windows(2) {
        assert!(w[0].interesting_score >= w[1].interesting_score);
    }
}

#[test]
fn se_filter_rejects_keywords_by_default() {
    let v = vec![
        ExtractedString::new("function".into(), 0, 0),
        ExtractedString::new("my_table_name".into(), 0, 1),
    ];
    let f = StringFilter::default();
    let out = f.apply(&v);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].value, "my_table_name");
}

#[test]
fn se_filter_min_max_length() {
    let v: Vec<ExtractedString> = (1..=10)
        .map(|n| ExtractedString::new("x".repeat(n), 0, n))
        .collect();
    let f = StringFilter {
        min_length: 3,
        max_length: 6,
        forbidden_categories: vec![],
        ..Default::default()
    };
    let out = f.apply(&v);
    assert_eq!(out.len(), 4); // lengths 3,4,5,6
}

#[test]
fn se_stats_compute_empty() {
    let stats = StringStats::compute(&[]);
    assert_eq!(stats.total, 0);
    assert_eq!(stats.unique, 0);
    assert_eq!(stats.avg_length, 0.0);
}

#[test]
fn se_stats_compute_aggregates() {
    let v = vec![
        ExtractedString::new("https://a.test".into(), 0, 0),
        ExtractedString::new("https://a.test".into(), 1, 0),
        ExtractedString::new("luaopen_foo".into(), 0, 1),
        ExtractedString::new("AES key here".into(), 0, 2),
    ];
    let stats = StringStats::compute(&v);
    assert_eq!(stats.total, 4);
    assert_eq!(stats.unique, 3);
    assert!(stats.url_count >= 2);
    assert!(stats.api_count >= 1);
    assert!(stats.crypto_count >= 1);
    assert!(stats.avg_length > 0.0);
}

// ── lua_version_detector tests ──────────────────────────────────────────────

#[test]
fn vd_version_byte_known() {
    assert_eq!(DetVersion::Lua50.version_byte(), Some(0x50));
    assert_eq!(DetVersion::Lua54.version_byte(), Some(0x54));
    assert_eq!(DetVersion::LuaJIT20.version_byte(), None);
    assert_eq!(DetVersion::Unknown.version_byte(), None);
}

#[test]
fn vd_is_luajit_predicate() {
    assert!(DetVersion::LuaJIT20.is_luajit());
    assert!(DetVersion::LuaJIT21.is_luajit());
    assert!(!DetVersion::Lua51.is_luajit());
    assert!(!DetVersion::Unknown.is_luajit());
}

#[test]
fn vd_major_minor_consistency() {
    for v in [
        DetVersion::Lua50, DetVersion::Lua51, DetVersion::Lua52,
        DetVersion::Lua53, DetVersion::Lua54,
    ] {
        assert_eq!(v.major(), 5);
    }
    assert_eq!(DetVersion::Lua54.minor(), 4);
    assert_eq!(DetVersion::LuaJIT21.minor(), 1);
    assert_eq!(DetVersion::LuaJIT20.minor(), 0);
}

#[test]
fn vd_feature_flags_per_version() {
    assert!(!DetVersion::Lua51.has_integer_type());
    assert!(DetVersion::Lua53.has_integer_type());
    assert!(DetVersion::Lua54.has_integer_type());
    assert!(DetVersion::Lua53.has_bitwise_ops());
    assert!(DetVersion::LuaJIT20.has_bitwise_ops());
    assert!(!DetVersion::Lua51.has_goto());
    assert!(DetVersion::Lua52.has_goto());
    assert!(DetVersion::Lua54.has_goto());
}

#[test]
fn vd_signature_matches_expected_versions() {
    let det = LuaVersionDetector::new();
    let mut buf = vec![0u8; 12];
    buf[0..4].copy_from_slice(b"\x1bLua");
    for (byte, expected) in [
        (0x51u8, DetVersion::Lua51),
        (0x52, DetVersion::Lua52),
        (0x53, DetVersion::Lua53),
        (0x54, DetVersion::Lua54),
        (0x50, DetVersion::Lua50),
    ] {
        buf[4] = byte;
        assert_eq!(det.detect(&buf), expected);
    }
}

#[test]
fn vd_signature_unknown_returns_unknown() {
    let det = LuaVersionDetector::new();
    let mut buf = vec![0u8; 16];
    buf[0..4].copy_from_slice(b"\x1bLua");
    buf[4] = 0x99;
    assert_eq!(det.detect(&buf), DetVersion::Unknown);
}

#[test]
fn vd_signature_too_short_returns_unknown() {
    let det = LuaVersionDetector::new();
    assert_eq!(det.detect(b""), DetVersion::Unknown);
    assert_eq!(det.detect(b"\x1bLua"), DetVersion::Unknown);
}

#[test]
fn vd_luajit_signature_matched() {
    let det = LuaVersionDetector::new();
    let buf = [0x1bu8, b'L', b'J', 2, 0];
    assert_eq!(det.detect(&buf), DetVersion::LuaJIT21);
    let buf = [0x1bu8, b'L', b'J', 1, 0];
    assert_eq!(det.detect(&buf), DetVersion::LuaJIT20);
}

#[test]
fn vd_all_signatures_count_matches_detector() {
    let det = LuaVersionDetector::new();
    let sigs = all_signatures();
    assert_eq!(det.signature_count(), sigs.len());
    assert!(sigs.len() >= 7);
}

#[test]
fn vd_signature_matches_predicate() {
    let sigs = all_signatures();
    let mut buf = vec![0u8; 12];
    buf[0..4].copy_from_slice(b"\x1bLua");
    buf[4] = 0x54;
    let sig54: &VersionSignature = sigs.iter().find(|s| s.version == DetVersion::Lua54).unwrap();
    assert!(sig54.matches(&buf));
    // wrong version byte
    buf[4] = 0x51;
    assert!(!sig54.matches(&buf));
    // too short
    assert!(!sig54.matches(&[0x1b, b'L', b'u']));
}

#[test]
fn vd_report_from_detection_populates() {
    let mut buf = vec![0u8; 12];
    buf[0..4].copy_from_slice(b"\x1bLua");
    buf[4] = 0x54;
    buf[6] = 1;
    buf[7] = 4;
    let r = VersionReport::from_detection(DetVersion::Lua54, &buf);
    assert_eq!(r.version, DetVersion::Lua54);
    assert_eq!(r.magic_bytes, b"\x1bLua".to_vec());
    assert_eq!(r.endianness.as_deref(), Some("little"));
    assert_eq!(r.int_size, Some(4));
}

#[test]
fn vd_feature_set_for_version_opcode_counts() {
    assert!(LuaFeatureSet::for_version(DetVersion::Lua54).opcode_count >= 80);
    assert!(LuaFeatureSet::for_version(DetVersion::Lua53).has_bitwise_ops);
    assert!(LuaFeatureSet::for_version(DetVersion::LuaJIT20).has_jit);
    assert!(!LuaFeatureSet::for_version(DetVersion::Unknown).has_closures);
}

#[test]
fn vd_autodecoder_lcg_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    let dec = AutoDecoder::new();
    for _ in 0..50 {
        let len = (lcg.next() as usize % 64) + 1;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(lcg.next_u8());
        }
        let _r = dec.detect(&buf); // returns a report — never panics
        let _ = AutoDecoder::is_lua_bytecode(&buf);
    }
}

#[test]
fn vd_version_display_strings() {
    assert_eq!(format!("{}", DetVersion::Lua54), "Lua 5.4");
    assert_eq!(format!("{}", DetVersion::LuaJIT20), "LuaJIT 2.0");
    assert_eq!(format!("{}", DetVersion::Unknown), "Unknown");
}

// ── luajit_loader tests ─────────────────────────────────────────────────────

#[test]
fn lj_is_luajit_bytecode_predicate() {
    assert!(is_luajit_bytecode(b"\x1bLJ\x02"));
    assert!(is_luajit_bytecode(b"\x1bLJ\x01"));
    assert!(!is_luajit_bytecode(b"\x1bLua\x54"));
    assert!(!is_luajit_bytecode(b""));
    assert!(!is_luajit_bytecode(b"LJ"));
}

#[test]
fn lj_kgc_tag_name_known_and_unknown() {
    // Just exercise it on a wide range; must always return a valid &'static str.
    for tag in 0u8..=255 {
        let n = kgc_tag_name(tag);
        assert!(!n.is_empty());
    }
}

#[test]
fn lj_ktab_tag_name_known_and_unknown() {
    for tag in 0u8..=255 {
        let n = ktab_tag_name(tag);
        assert!(!n.is_empty());
    }
}

#[test]
fn lj_opcode_name_total() {
    for op in 0u8..=255 {
        let n = ljit_opcode_name(op);
        assert!(!n.is_empty());
    }
}

#[test]
fn lj_classifier_predicates_disjoint_or_named() {
    // Just ensure they return without panic over the full byte range and
    // remain stable: cross-check at least one known op family.
    let mut any_call = false;
    let mut any_ret = false;
    let mut any_jump = false;
    for op in 0u8..=255 {
        if is_call_op(op) { any_call = true; }
        if is_return_op(op) { any_ret = true; }
        if is_jump_op(op) { any_jump = true; }
    }
    assert!(any_call);
    assert!(any_ret);
    assert!(any_jump);
}

#[test]
fn lj_proto_has_iloop_bit_pattern() {
    // proto_has_iloop tests a specific bit; both true & false must be reachable
    let mut seen_true = false;
    let mut seen_false = false;
    for f in 0u8..=255 {
        if proto_has_iloop(f) { seen_true = true; } else { seen_false = true; }
    }
    assert!(seen_true && seen_false);
}

#[test]
fn lj_bcdump_header_too_short_errors() {
    assert!(BcDumpHeader::parse(b"").is_err());
    assert!(BcDumpHeader::parse(b"\x1b").is_err());
    assert!(BcDumpHeader::parse(b"\x1bL").is_err());
}

#[test]
fn lj_bcdump_header_wrong_magic_errors() {
    assert!(BcDumpHeader::parse(b"XYZ\x02").is_err());
    assert!(BcDumpHeader::parse(b"\x1bLuaQ").is_err());
}

#[test]
fn lj_bcdump_header_unknown_version_errors() {
    assert!(BcDumpHeader::parse(b"\x1bLJ\x99\x00").is_err());
}

#[test]
fn lj_bcdump_header_stripped_no_chunk_name() {
    // Stripped flag = 0x02 (BCDUMP_F_STRIP); set it so no chunk name is parsed.
    let data = b"\x1bLJ\x02\x02";
    let (hdr, pos) = BcDumpHeader::parse(data).expect("parses");
    assert_eq!(hdr.version, LuaJitVersion::V21);
    assert!(hdr.is_stripped);
    assert!(hdr.chunk_name.is_none());
    assert_eq!(pos, 5);
}

#[test]
fn lj_bcdump_header_with_chunk_name_uleb() {
    // Not stripped: chunk_name length is a uleb128 followed by bytes.
    // Use 0x05 "hello" (uleb 0x05).
    let mut data: Vec<u8> = vec![0x1b, b'L', b'J', 0x02, 0x00];
    data.push(0x05);
    data.extend_from_slice(b"hello");
    let (hdr, pos) = BcDumpHeader::parse(&data).expect("parses");
    assert_eq!(hdr.chunk_name.as_deref(), Some("hello"));
    assert_eq!(pos, data.len());
}

#[test]
fn lj_load_luajit_rejects_random_data() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let len = (lcg.next() as usize % 32) + 1;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(lcg.next_u8());
        }
        // Force magic so the loader at least tries parsing structures.
        if buf.len() >= 5 {
            buf[0] = 0x1b;
            buf[1] = b'L';
            buf[2] = b'J';
            buf[3] = if lcg.next_u8() & 1 == 0 { 1 } else { 2 };
        }
        let _ = load_luajit(&buf); // Must Err or Ok, never panic
    }
}

#[test]
fn lj_version_as_str() {
    assert_eq!(LuaJitVersion::V20.as_str(), "LuaJIT 2.0");
    assert_eq!(LuaJitVersion::V21.as_str(), "LuaJIT 2.1");
}

// ── Send + Sync sanity for documented Send+Sync types ───────────────────────

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn send_sync_types() {
    assert_send_sync::<LuaConst>();
    assert_send_sync::<LuaProto>();
    assert_send_sync::<LuaConstantPool>();
    assert_send_sync::<LuaConstant>();
    assert_send_sync::<LbpProto>();
    assert_send_sync::<ExtractedString>();
    assert_send_sync::<LuaConstantPool>();
}

#[test]
fn threaded_constant_pool_build_stress() {
    use std::sync::Arc;
    use std::thread;
    let consts = Arc::new(sample());
    let mut handles = Vec::new();
    for t in 0..4 {
        let c = Arc::clone(&consts);
        handles.push(thread::spawn(move || {
            let mut local_pool = LuaConstantPool::new();
            for i in 0..100 {
                local_pool.ingest_proto_constants((t * 100 + i) as usize, &c);
            }
            local_pool.total_count()
        }));
    }
    let mut sum = 0usize;
    for h in handles {
        sum += h.join().unwrap();
    }
    // 4 threads * 100 ingests * 10 constants each
    assert_eq!(sum, 4 * 100 * 10);
}
