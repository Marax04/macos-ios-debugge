//! Comprehensive integration tests for the public surface of `rustre-yara-engine`.
//!
//! Covers core types (rules, strings, conditions, matchers, parser, scanner),
//! their constructors, display/debug formatting, error variants, and behavior on
//! boundary inputs.

use rustre_yara_engine::{
    CompOp, Condition, HexToken, MetaValue, PatternMatch, RuleMatch, StringMatch, StringModifiers,
    StringValue, YaraError, YaraMatch, YaraParser, YaraRule, YaraRuleDefinition, YaraRuleSet,
    YaraScanner, YaraString, compute_entropy,
};

// ─── helpers ───────────────────────────────────────────────────────────────

fn text_string(id: &str, text: &str, modifiers: StringModifiers) -> YaraString {
    YaraString {
        identifier: id.to_string(),
        value: StringValue::Text(text.to_string()),
        modifiers,
    }
}

// ─── StringModifiers bitflags ──────────────────────────────────────────────

#[test]
fn string_modifiers_none_is_zero() {
    assert_eq!(StringModifiers::NONE.bits(), 0);
}

#[test]
fn string_modifiers_unique_bits() {
    let all = [
        StringModifiers::NOCASE,
        StringModifiers::WIDE,
        StringModifiers::ASCII,
        StringModifiers::FULLWORD,
        StringModifiers::PRIVATE,
        StringModifiers::BASE64,
    ];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_eq!((*a & *b).bits(), 0, "{a:?} overlaps {b:?}");
        }
    }
}

#[test]
fn string_modifiers_combine_and_contains() {
    let m = StringModifiers::NOCASE | StringModifiers::WIDE;
    assert!(m.contains(StringModifiers::NOCASE));
    assert!(m.contains(StringModifiers::WIDE));
    assert!(!m.contains(StringModifiers::FULLWORD));
}

#[test]
fn string_modifiers_hash_eq_consistent() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(StringModifiers::NOCASE);
    s.insert(StringModifiers::NOCASE);
    assert_eq!(s.len(), 1);
    assert!(s.contains(&StringModifiers::NOCASE));
}

// ─── CompOp ────────────────────────────────────────────────────────────────

#[test]
fn compop_display_symbols() {
    assert_eq!(format!("{}", CompOp::Eq), "==");
    assert_eq!(format!("{}", CompOp::Ne), "!=");
    assert_eq!(format!("{}", CompOp::Lt), "<");
    assert_eq!(format!("{}", CompOp::Le), "<=");
    assert_eq!(format!("{}", CompOp::Gt), ">");
    assert_eq!(format!("{}", CompOp::Ge), ">=");
}

#[test]
fn compop_equality() {
    assert_eq!(CompOp::Eq, CompOp::Eq);
    assert_ne!(CompOp::Eq, CompOp::Ne);
}

// ─── MetaValue ─────────────────────────────────────────────────────────────

#[test]
fn metavalue_display_variants() {
    assert_eq!(format!("{}", MetaValue::String("hi".into())), "\"hi\"");
    assert_eq!(format!("{}", MetaValue::Int(-7)), "-7");
    assert_eq!(format!("{}", MetaValue::Bool(true)), "true");
    assert_eq!(format!("{}", MetaValue::Bool(false)), "false");
}

#[test]
fn metavalue_serde_round_trip() {
    let vals = [
        MetaValue::String("alpha".into()),
        MetaValue::Int(42),
        MetaValue::Bool(true),
    ];
    for v in &vals {
        let j = serde_json::to_string(v).unwrap();
        let back: MetaValue = serde_json::from_str(&j).unwrap();
        assert_eq!(format!("{v}"), format!("{back}"));
    }
}

// ─── HexToken ──────────────────────────────────────────────────────────────

#[test]
fn hex_token_display() {
    assert_eq!(format!("{}", HexToken::Byte(0xAB)), "AB");
    assert_eq!(format!("{}", HexToken::Wildcard), "??");
    assert_eq!(format!("{}", HexToken::MaskedByte(0xAB, 0xF0)), "AB&F0");
    assert_eq!(format!("{}", HexToken::Jump(2, None)), "[2]");
    assert_eq!(format!("{}", HexToken::Jump(1, Some(5))), "[1-5]");
    assert_eq!(format!("{}", HexToken::Alternative(vec![])), "(...)");
}

// ─── StringValue / YaraString Display ──────────────────────────────────────

#[test]
fn stringvalue_display_text() {
    assert_eq!(
        format!("{}", StringValue::Text("hello".into())),
        "\"hello\""
    );
}

#[test]
fn stringvalue_display_regex() {
    assert_eq!(format!("{}", StringValue::Regex("ab+".into())), "/ab+/");
}

#[test]
fn stringvalue_display_hex() {
    let v = StringValue::Hex(vec![HexToken::Byte(0xDE), HexToken::Byte(0xAD)]);
    assert_eq!(format!("{v}"), "{ DE AD }");
}

#[test]
fn yara_string_display() {
    let ys = text_string("$a", "x", StringModifiers::NONE);
    assert_eq!(format!("{ys}"), "$a = \"x\"");
}

// ─── YaraRule builder ──────────────────────────────────────────────────────

#[test]
fn yara_rule_new_defaults() {
    let r = YaraRule::new("r1".into());
    assert_eq!(r.name, "r1");
    assert_eq!(r.namespace, "default");
    assert!(r.tags.is_empty());
    assert!(r.meta.is_empty());
    assert!(r.strings.is_empty());
    assert!(matches!(r.condition, Condition::True));
}

#[test]
fn yara_rule_builder_chain() {
    let r = YaraRule::new("r".into())
        .with_tag("malware".into())
        .with_tag("apt".into())
        .with_meta("author".into(), MetaValue::String("me".into()))
        .with_string(text_string("$a", "AAAA", StringModifiers::NONE))
        .with_condition(Condition::Any);
    assert_eq!(r.tags, vec!["malware", "apt"]);
    assert_eq!(r.meta.len(), 1);
    assert_eq!(r.strings.len(), 1);
    assert!(matches!(r.condition, Condition::Any));
}

#[test]
fn yara_rule_display_contains_name() {
    let r = YaraRule::new("foo".into())
        .with_string(text_string("$a", "x", StringModifiers::NONE));
    let s = format!("{r}");
    assert!(s.contains("foo"));
    assert!(s.contains("strings: 1"));
}

// ─── StringMatch / RuleMatch display ───────────────────────────────────────

#[test]
fn string_match_display() {
    let m = StringMatch {
        identifier: "$a".into(),
        offset: 0x10,
        length: 4,
        matched_data: vec![1, 2, 3, 4],
    };
    let s = format!("{m}");
    assert!(s.contains("$a"));
    assert!(s.contains("0x10"));
    assert!(s.contains("len=4"));
}

#[test]
fn rule_match_display() {
    let m = RuleMatch {
        rule_name: "r1".into(),
        namespace: "ns".into(),
        tags: vec![],
        meta: Default::default(),
        string_matches: vec![],
    };
    let s = format!("{m}");
    assert!(s.contains("r1"));
    assert!(s.contains("strings=0"));
}

// ─── YaraScanner: basic plumbing ───────────────────────────────────────────

#[test]
fn scanner_new_is_empty() {
    let s = YaraScanner::new();
    assert_eq!(s.rule_count(), 0);
    assert!(s.scan(b"").is_empty());
    assert!(s.scan_names(b"anything").is_empty());
}

#[test]
fn scanner_default_equivalent_to_new() {
    let s = YaraScanner::default();
    assert_eq!(s.rule_count(), 0);
}

#[test]
fn scanner_debug_contains_count() {
    let s = YaraScanner::new();
    s.add_rule(YaraRule::new("r".into()));
    let d = format!("{s:?}");
    assert!(d.contains('1'));
}

#[test]
fn scanner_add_rule_increments() {
    let s = YaraScanner::new();
    assert_eq!(s.rule_count(), 0);
    s.add_rule(YaraRule::new("a".into()));
    s.add_rule(YaraRule::new("b".into()));
    assert_eq!(s.rule_count(), 2);
}

// ─── YaraScanner: text matching ────────────────────────────────────────────

#[test]
fn scan_text_simple_match() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("hi".into())
            .with_string(text_string("$a", "hello", StringModifiers::NONE))
            .with_condition(Condition::StringMatch("$a".into())),
    );
    let res = s.scan(b"say hello world");
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].rule_name, "hi");
    assert_eq!(res[0].string_matches.len(), 1);
    assert_eq!(res[0].string_matches[0].offset, 4);
}

#[test]
fn scan_text_no_match() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("hi".into())
            .with_string(text_string("$a", "zzz", StringModifiers::NONE))
            .with_condition(Condition::StringMatch("$a".into())),
    );
    assert!(s.scan(b"hello").is_empty());
}

#[test]
fn scan_nocase_matches_uppercase() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("c".into())
            .with_string(text_string("$a", "hello", StringModifiers::NOCASE))
            .with_condition(Condition::StringMatch("$a".into())),
    );
    let res = s.scan(b"HELLO world");
    assert_eq!(res.len(), 1);
}

#[test]
fn scan_wide_matches_utf16_le() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("w".into())
            .with_string(text_string("$a", "ab", StringModifiers::WIDE))
            .with_condition(Condition::StringMatch("$a".into())),
    );
    // "ab" as UTF-16LE: 61 00 62 00
    let data = b"\x00\x00\x61\x00\x62\x00\x00";
    let res = s.scan(data);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].string_matches[0].length, 4);
}

#[test]
fn scan_fullword_blocks_substring() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("fw".into())
            .with_string(text_string(
                "$a",
                "cat",
                StringModifiers::FULLWORD,
            ))
            .with_condition(Condition::StringMatch("$a".into())),
    );
    assert!(s.scan(b"category").is_empty());
    assert_eq!(s.scan(b"a cat sat").len(), 1);
}

#[test]
fn scan_multiple_matches_returned() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("m".into())
            .with_string(text_string("$a", "ab", StringModifiers::NONE))
            .with_condition(Condition::StringMatch("$a".into())),
    );
    let res = s.scan(b"ababab");
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].string_matches.len(), 3);
}

#[test]
fn scan_names_returns_only_names() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("alpha".into())
            .with_string(text_string("$a", "x", StringModifiers::NONE))
            .with_condition(Condition::StringMatch("$a".into())),
    );
    s.add_rule(
        YaraRule::new("beta".into())
            .with_string(text_string("$a", "y", StringModifiers::NONE))
            .with_condition(Condition::StringMatch("$a".into())),
    );
    let names = s.scan_names(b"x");
    assert_eq!(names, vec!["alpha".to_string()]);
}

// ─── YaraScanner: hex matching ─────────────────────────────────────────────

#[test]
fn scan_hex_exact_bytes() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("h".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Hex(vec![
                    HexToken::Byte(0xDE),
                    HexToken::Byte(0xAD),
                ]),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$a".into())),
    );
    let res = s.scan(&[0x00, 0xDE, 0xAD, 0x00]);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].string_matches[0].offset, 1);
}

#[test]
fn scan_hex_wildcard() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("h".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Hex(vec![
                    HexToken::Byte(0xDE),
                    HexToken::Wildcard,
                    HexToken::Byte(0xEF),
                ]),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$a".into())),
    );
    let res = s.scan(&[0xDE, 0xBE, 0xEF]);
    assert_eq!(res.len(), 1);
}

#[test]
fn scan_hex_masked_byte() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("h".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Hex(vec![HexToken::MaskedByte(0xA0, 0xF0)]),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$a".into())),
    );
    let res = s.scan(&[0xA5]);
    assert_eq!(res.len(), 1);
    assert!(s.scan(&[0xB5]).is_empty());
}

#[test]
fn scan_hex_jump_range() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("h".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Hex(vec![
                    HexToken::Byte(0xAA),
                    HexToken::Jump(1, Some(3)),
                    HexToken::Byte(0xBB),
                ]),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$a".into())),
    );
    assert_eq!(s.scan(&[0xAA, 0x00, 0xBB]).len(), 1);
    assert_eq!(s.scan(&[0xAA, 0x00, 0x00, 0x00, 0xBB]).len(), 1);
}

#[test]
fn scan_hex_alternative() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("h".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Hex(vec![HexToken::Alternative(vec![
                    vec![HexToken::Byte(0x11)],
                    vec![HexToken::Byte(0x22)],
                ])]),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$a".into())),
    );
    assert!(!s.scan(&[0x11]).is_empty());
    assert!(!s.scan(&[0x22]).is_empty());
    assert!(s.scan(&[0x33]).is_empty());
}

// ─── YaraScanner: regex matching ───────────────────────────────────────────

#[test]
fn scan_regex_basic() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("re".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Regex("ab+c".into()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$a".into())),
    );
    assert_eq!(s.scan(b"abc").len(), 1);
    assert_eq!(s.scan(b"abbbc").len(), 1);
    assert!(s.scan(b"ac").is_empty());
}

#[test]
fn scan_regex_invalid_yields_no_matches() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("re".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Regex("[unclosed".into()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$a".into())),
    );
    assert!(s.scan(b"anything").is_empty());
}

// ─── Conditions ───────────────────────────────────────────────────────────

#[test]
fn condition_true_always_matches() {
    let s = YaraScanner::new();
    s.add_rule(YaraRule::new("t".into()).with_condition(Condition::True));
    assert_eq!(s.scan(b"").len(), 1);
}

#[test]
fn condition_false_never_matches() {
    let s = YaraScanner::new();
    s.add_rule(YaraRule::new("f".into()).with_condition(Condition::False));
    assert!(s.scan(b"abc").is_empty());
}

#[test]
fn condition_and_or_not() {
    let mk = |c: Condition| {
        let s = YaraScanner::new();
        s.add_rule(YaraRule::new("r".into()).with_condition(c));
        s.scan(b"").len()
    };
    assert_eq!(mk(Condition::And(Box::new(Condition::True), Box::new(Condition::True))), 1);
    assert_eq!(mk(Condition::And(Box::new(Condition::True), Box::new(Condition::False))), 0);
    assert_eq!(mk(Condition::Or(Box::new(Condition::False), Box::new(Condition::True))), 1);
    assert_eq!(mk(Condition::Not(Box::new(Condition::False))), 1);
    assert_eq!(mk(Condition::Not(Box::new(Condition::True))), 0);
}

#[test]
fn condition_filesize_all_ops() {
    let mk = |op: CompOp, n: u64, data: &[u8]| {
        let s = YaraScanner::new();
        s.add_rule(YaraRule::new("r".into()).with_condition(Condition::FileSize(op, n)));
        s.scan(data).len()
    };
    let d = b"abcd"; // size 4
    assert_eq!(mk(CompOp::Eq, 4, d), 1);
    assert_eq!(mk(CompOp::Ne, 4, d), 0);
    assert_eq!(mk(CompOp::Lt, 5, d), 1);
    assert_eq!(mk(CompOp::Le, 4, d), 1);
    assert_eq!(mk(CompOp::Gt, 3, d), 1);
    assert_eq!(mk(CompOp::Ge, 4, d), 1);
    assert_eq!(mk(CompOp::Lt, 4, d), 0);
}

#[test]
fn condition_entrypoint_mz_magic() {
    let s = YaraScanner::new();
    s.add_rule(YaraRule::new("r".into()).with_condition(Condition::EntryPoint));
    assert_eq!(s.scan(b"MZ junk").len(), 1);
    assert!(s.scan(b"ELF").is_empty());
    assert!(s.scan(b"").is_empty());
}

#[test]
fn condition_string_at_and_in() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_string(text_string("$a", "ZZ", StringModifiers::NONE))
            .with_condition(Condition::StringAt("$a".into(), 2)),
    );
    assert_eq!(s.scan(b"AAZZBB").len(), 1);
    assert!(s.scan(b"ZZAABB").is_empty());

    let s2 = YaraScanner::new();
    s2.add_rule(
        YaraRule::new("r".into())
            .with_string(text_string("$a", "ZZ", StringModifiers::NONE))
            .with_condition(Condition::StringIn("$a".into(), 1, 3)),
    );
    assert_eq!(s2.scan(b"AAZZBB").len(), 1);
    assert!(s2.scan(b"ZZAAAA").is_empty());
}

#[test]
fn condition_all_any_none_quantifiers() {
    let mut rule = YaraRule::new("r".into())
        .with_string(text_string("$a", "x", StringModifiers::NONE))
        .with_string(text_string("$b", "y", StringModifiers::NONE));

    rule.condition = Condition::All;
    let s = YaraScanner::new();
    s.add_rule(rule.clone());
    assert_eq!(s.scan(b"xy").len(), 1);
    // The "only $a present" fixture must not contain $b — the previous one,
    // b"x only", has a 'y' inside "only", so All legitimately matched and the
    // assertion was asking the scanner to be wrong.
    assert!(s.scan(b"x alone").is_empty());

    rule.condition = Condition::Any;
    let s2 = YaraScanner::new();
    s2.add_rule(rule.clone());
    assert_eq!(s2.scan(b"x alone").len(), 1);
    assert!(s2.scan(b"nope").is_empty());

    rule.condition = Condition::None;
    let s3 = YaraScanner::new();
    s3.add_rule(rule);
    assert_eq!(s3.scan(b"nope").len(), 1);
    assert!(s3.scan(b"x").is_empty());
}

#[test]
fn condition_int_at_bounds() {
    let s = YaraScanner::new();
    s.add_rule(YaraRule::new("r".into()).with_condition(Condition::IntAt(0)));
    assert_eq!(s.scan(b"abcd").len(), 1);
    assert!(s.scan(b"abc").is_empty()); // need 4 bytes from offset 0
}

#[test]
fn condition_forall_vacuous_true() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into()).with_condition(Condition::ForAll(Box::new(Condition::True))),
    );
    assert_eq!(s.scan(b"abc").len(), 1);
}

// ─── YaraParser ────────────────────────────────────────────────────────────

#[test]
fn parser_new_default_debug() {
    let p = YaraParser::new();
    let _ = format!("{p:?}");
    let _ = YaraParser;
}

#[test]
fn parser_parse_minimal_rule() {
    let p = YaraParser::new();
    let r = p.parse_rule("rule foo { condition: true }").unwrap();
    assert_eq!(r.name, "foo");
    assert!(matches!(r.condition, Condition::True));
}

#[test]
fn parser_parse_tags() {
    let p = YaraParser::new();
    let r = p
        .parse_rule("rule r : tag1 tag2 { condition: true }")
        .unwrap();
    assert_eq!(r.tags, vec!["tag1", "tag2"]);
}

#[test]
fn parser_parse_meta_section() {
    let p = YaraParser::new();
    let src = r#"rule m {
        meta:
            author = "me"
            count = 5
            flag = true
        condition:
            true
    }"#;
    let r = p.parse_rule(src).unwrap();
    assert!(matches!(r.meta.get("author"), Some(MetaValue::String(_))));
    assert!(matches!(r.meta.get("count"), Some(MetaValue::Int(5))));
    assert!(matches!(r.meta.get("flag"), Some(MetaValue::Bool(true))));
}

#[test]
fn parser_parse_strings_section() {
    let p = YaraParser::new();
    let src = r#"rule s {
        strings:
            $a = "hi" nocase wide
        condition:
            $a
    }"#;
    let r = p.parse_rule(src).unwrap();
    assert_eq!(r.strings.len(), 1);
    assert_eq!(r.strings[0].identifier, "$a");
    assert!(r.strings[0].modifiers.contains(StringModifiers::NOCASE));
    assert!(r.strings[0].modifiers.contains(StringModifiers::WIDE));
}

#[test]
fn parser_parse_condition_keywords() {
    let p = YaraParser::new();
    assert!(matches!(
        p.parse_rule("rule a { condition: any of them }").unwrap().condition,
        Condition::Any
    ));
    assert!(matches!(
        p.parse_rule("rule a { condition: all of them }").unwrap().condition,
        Condition::All
    ));
    assert!(matches!(
        p.parse_rule("rule a { condition: none of them }").unwrap().condition,
        Condition::None
    ));
    assert!(matches!(
        p.parse_rule("rule a { condition: false }").unwrap().condition,
        Condition::False
    ));
}

#[test]
fn parser_parse_filesize_condition() {
    let p = YaraParser::new();
    let r = p
        .parse_rule("rule fs { condition: filesize > 100 }")
        .unwrap();
    match r.condition {
        Condition::FileSize(CompOp::Gt, 100) => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn parser_parse_not_condition() {
    let p = YaraParser::new();
    let r = p.parse_rule("rule n { condition: not false }").unwrap();
    assert!(matches!(r.condition, Condition::Not(_)));
}

#[test]
fn parser_error_missing_rule_keyword() {
    let p = YaraParser::new();
    let err = p.parse_rule("foo bar").unwrap_err();
    match err {
        YaraError::ParseError { line: 1, .. } => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn parser_error_missing_brace() {
    let p = YaraParser::new();
    let err = p.parse_rule("rule onlyname").unwrap_err();
    assert!(matches!(err, YaraError::ParseError { .. }));
}

#[test]
fn parser_parse_rules_multi() {
    let p = YaraParser::new();
    let src = "rule a { condition: true } rule b { condition: false }";
    let rules = p.parse_rules(src).unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].name, "a");
    assert_eq!(rules[1].name, "b");
}

#[test]
fn parser_parse_rules_empty_input() {
    let p = YaraParser::new();
    let rules = p.parse_rules("").unwrap();
    assert!(rules.is_empty());
}

// ─── YaraError ─────────────────────────────────────────────────────────────

#[test]
fn yara_error_display_variants() {
    let e = YaraError::ParseError {
        line: 3,
        message: "oops".into(),
    };
    let s = format!("{e}");
    assert!(s.contains("line 3"));
    assert!(s.contains("oops"));

    let e = YaraError::CompileError("bad".into());
    assert!(format!("{e}").contains("bad"));

    let e = YaraError::RuleNotFound("zzz".into());
    assert!(format!("{e}").contains("zzz"));

    let e = YaraError::ScanError("scan".into());
    assert!(format!("{e}").contains("scan"));

    let e = YaraError::RegexError("rx".into());
    assert!(format!("{e}").contains("rx"));
}

#[test]
fn yara_error_from_io() {
    let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
    let e: YaraError = io.into();
    assert!(matches!(e, YaraError::Io(_)));
}

// ─── YaraRuleDefinition ────────────────────────────────────────────────────

#[test]
fn rule_definition_extracts_name() {
    let d = YaraRuleDefinition::new("id1", "rule MyRule { condition: true }");
    assert_eq!(d.id, "id1");
    assert_eq!(d.name, "MyRule");
    assert_eq!(d.namespace, "default");
    assert!(d.tags.is_empty());
    assert!(d.meta.is_empty());
}

#[test]
fn rule_definition_falls_back_to_id_when_no_name() {
    let d = YaraRuleDefinition::new("fallback", "not a yara rule");
    assert_eq!(d.name, "fallback");
}

#[test]
fn rule_definition_parse_name_with_tags() {
    let n = YaraRuleDefinition::parse_name_from_source("rule Foo : tag1 { }").unwrap();
    assert_eq!(n, "Foo");
}

#[test]
fn rule_definition_parse_name_none_on_empty() {
    assert!(YaraRuleDefinition::parse_name_from_source("").is_none());
}

#[test]
fn rule_definition_builder_methods() {
    let d = YaraRuleDefinition::new("i", "rule R { condition: true }")
        .with_namespace("ns")
        .with_tag("t1")
        .with_meta("k", "v");
    assert_eq!(d.namespace, "ns");
    assert_eq!(d.tags, vec!["t1"]);
    assert_eq!(d.meta.get("k").map(String::as_str), Some("v"));
}

#[test]
fn rule_definition_display() {
    let d = YaraRuleDefinition::new("xx", "rule Yy { condition: true }");
    let s = format!("{d}");
    assert!(s.contains("xx"));
    assert!(s.contains("Yy"));
}

// ─── YaraRuleSet ───────────────────────────────────────────────────────────

#[test]
fn ruleset_new_is_empty() {
    let rs = YaraRuleSet::new();
    assert!(rs.is_empty());
    assert_eq!(rs.len(), 0);
    assert!(!rs.is_compiled());
}

#[test]
fn ruleset_default_equivalent() {
    let rs = YaraRuleSet::default();
    assert_eq!(rs.len(), 0);
}

#[test]
fn ruleset_add_rule_increments() {
    let mut rs = YaraRuleSet::new();
    rs.add_rule("rule A { condition: true }").unwrap();
    assert_eq!(rs.len(), 1);
    assert!(!rs.is_empty());
}

#[test]
fn ruleset_add_empty_rule_errors() {
    let mut rs = YaraRuleSet::new();
    let err = rs.add_rule("   ").unwrap_err();
    assert!(matches!(err, YaraError::ParseError { .. }));
}

#[test]
fn ruleset_compile_succeeds_for_valid_rule() {
    let mut rs = YaraRuleSet::new();
    rs.add_rule("rule A { condition: true }").unwrap();
    rs.compile().unwrap();
    assert!(rs.is_compiled());
}

#[test]
fn ruleset_compile_fails_for_invalid_source() {
    let mut rs = YaraRuleSet::new();
    rs.add_rule("rule A { condition: this_is_not_valid_yara_syntax }").unwrap();
    let err = rs.compile().unwrap_err();
    assert!(matches!(err, YaraError::CompileError(_)));
}

#[test]
fn ruleset_debug_contains_counts() {
    let rs = YaraRuleSet::new();
    let d = format!("{rs:?}");
    assert!(d.contains("rules=0"));
    assert!(d.contains("compiled=false"));
}

#[test]
fn ruleset_add_invalidates_compiled() {
    let mut rs = YaraRuleSet::new();
    rs.add_rule("rule A { condition: true }").unwrap();
    rs.compile().unwrap();
    assert!(rs.is_compiled());
    rs.add_rule("rule B { condition: true }").unwrap();
    assert!(!rs.is_compiled());
}

// ─── YaraEngineScanner via YaraRuleSet ─────────────────────────────────────

#[test]
fn engine_scanner_compiles_and_scans() {
    use rustre_yara_engine::YaraEngineScanner;
    let mut rs = YaraRuleSet::new();
    rs.add_rule(r#"rule R { strings: $a = "MAGIC" condition: $a }"#).unwrap();
    let scanner = YaraEngineScanner::new(&mut rs).unwrap();
    let matches = scanner.scan_bytes(b"prefix MAGIC suffix");
    assert!(matches.iter().any(|m| m.rule_name == "R"));
    let no = scanner.scan_bytes(b"none here");
    assert!(no.iter().all(|m| m.rule_name != "R"));
}

#[test]
fn engine_scanner_scan_file_missing() {
    use rustre_yara_engine::YaraEngineScanner;
    let mut rs = YaraRuleSet::new();
    rs.add_rule("rule R { condition: true }").unwrap();
    let scanner = YaraEngineScanner::new(&mut rs).unwrap();
    let err = scanner
        .scan_file(std::path::Path::new("definitely-not-a-real-file.xyz"))
        .unwrap_err();
    assert!(matches!(err, YaraError::Io(_)));
}

// ─── PatternMatch / YaraMatch display ──────────────────────────────────────

#[test]
fn pattern_match_display_format() {
    let p = PatternMatch {
        identifier: "$x".into(),
        offset: 0x10,
        length: 3,
        data: vec![1, 2, 3],
    };
    let s = format!("{p}");
    assert!(s.contains("$x"));
    assert!(s.contains("0x00000010"));
}

#[test]
fn yara_match_display_format() {
    let m = YaraMatch {
        rule_name: "R".into(),
        namespace: "ns".into(),
        tags: vec![],
        meta: Default::default(),
        patterns: vec![],
    };
    let s = format!("{m}");
    assert!(s.contains('R'));
    assert!(s.contains("ns"));
    assert!(s.contains("patterns=0"));
}

// ─── compute_entropy ───────────────────────────────────────────────────────

#[test]
fn entropy_empty_is_zero() {
    assert_eq!(compute_entropy(&[]), 0.0);
}

#[test]
fn entropy_single_byte_class_is_zero() {
    let e = compute_entropy(&[0u8; 32]);
    assert!(e.abs() < 1e-9, "got {e}");
}

#[test]
fn entropy_uniform_is_high() {
    let data: Vec<u8> = (0u8..=255u8).collect();
    let e = compute_entropy(&data);
    assert!(e > 7.9, "expected near-8, got {e}");
    assert!(e <= 8.0001);
}

#[test]
fn entropy_two_classes_is_one() {
    // Half 0x00 and half 0xFF → entropy ~1.0
    let mut data = vec![0u8; 50];
    data.extend(std::iter::repeat_n(0xFFu8, 50));
    let e = compute_entropy(&data);
    assert!((e - 1.0).abs() < 0.001, "got {e}");
}

// ─── Send/Sync sanity (compile-time) ───────────────────────────────────────

#[test]
fn scanner_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<YaraScanner>();
    assert_send_sync::<YaraRule>();
    assert_send_sync::<YaraString>();
    assert_send_sync::<StringValue>();
    assert_send_sync::<Condition>();
    assert_send_sync::<YaraError>();
}

// ─── serde round-trip on core types ────────────────────────────────────────

#[test]
fn yara_rule_serde_round_trip() {
    let r = YaraRule::new("r".into())
        .with_tag("t".into())
        .with_string(text_string("$a", "x", StringModifiers::NOCASE))
        .with_condition(Condition::StringMatch("$a".into()));
    let j = serde_json::to_string(&r).unwrap();
    let back: YaraRule = serde_json::from_str(&j).unwrap();
    assert_eq!(back.name, "r");
    assert_eq!(back.tags, vec!["t"]);
    assert_eq!(back.strings.len(), 1);
}

#[test]
fn string_modifiers_serde_round_trip() {
    let m = StringModifiers::NOCASE | StringModifiers::WIDE;
    let j = serde_json::to_string(&m).unwrap();
    let back: StringModifiers = serde_json::from_str(&j).unwrap();
    assert_eq!(m, back);
}
