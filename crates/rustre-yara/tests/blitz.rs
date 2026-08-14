//! Exhaustive blitz tests for `rustre-yara` public API surface (lib.rs).
//!
//! Goal: surface bugs in parsing, matching, condition eval, edge cases.

use rustre_yara::*;

// ─── HexToken parsing ──────────────────────────────────────────────────────

#[test]
fn parse_hex_empty() {
    let t = YaraParser::parse_hex_pattern("").unwrap();
    assert!(t.is_empty());
}

#[test]
fn parse_hex_single_byte() {
    let t = YaraParser::parse_hex_pattern("ab").unwrap();
    assert_eq!(t, vec![HexToken::Byte(0xab)]);
}

#[test]
fn parse_hex_uppercase_lowercase_mixed() {
    let t = YaraParser::parse_hex_pattern("De aD bE eF").unwrap();
    assert_eq!(
        t,
        vec![
            HexToken::Byte(0xDE),
            HexToken::Byte(0xAD),
            HexToken::Byte(0xBE),
            HexToken::Byte(0xEF),
        ]
    );
}

#[test]
fn parse_hex_low_nibble_known() {
    // "?A" => low nibble A, high nibble wildcard
    let t = YaraParser::parse_hex_pattern("?A").unwrap();
    assert_eq!(t, vec![HexToken::Masked(0x0A, 0x0F)]);
}

#[test]
fn parse_hex_high_nibble_known() {
    let t = YaraParser::parse_hex_pattern("A?").unwrap();
    assert_eq!(t, vec![HexToken::Masked(0xA0, 0xF0)]);
}

#[test]
fn parse_hex_double_wildcard() {
    let t = YaraParser::parse_hex_pattern("??").unwrap();
    assert_eq!(t, vec![HexToken::Wildcard]);
}

#[test]
fn parse_hex_jump_single() {
    let t = YaraParser::parse_hex_pattern("[5]").unwrap();
    assert_eq!(t, vec![HexToken::Jump(5, 5)]);
}

#[test]
fn parse_hex_jump_range() {
    let t = YaraParser::parse_hex_pattern("[2-7]").unwrap();
    assert_eq!(t, vec![HexToken::Jump(2, 7)]);
}

#[test]
fn parse_hex_invalid_char_errors() {
    let r = YaraParser::parse_hex_pattern("ZZ");
    assert!(matches!(r, Err(YaraError::ParseError { .. })));
}

#[test]
fn parse_hex_incomplete_byte_errors() {
    // single hex digit at end with no follower
    let r = YaraParser::parse_hex_pattern("A");
    assert!(matches!(r, Err(YaraError::ParseError { .. })));
}

#[test]
fn parse_hex_alternation_multi() {
    let t = YaraParser::parse_hex_pattern("(AA | BB CC | DD)").unwrap();
    match &t[0] {
        HexToken::Alternation(alts) => assert_eq!(alts.len(), 3),
        _ => panic!("expected Alternation"),
    }
}

// ─── StringMatcher::match_hex ───────────────────────────────────────────────

#[test]
fn match_hex_empty_data() {
    let p = vec![HexToken::Byte(0xAA)];
    assert!(StringMatcher::match_hex(&p, &[]).is_empty());
}

#[test]
fn match_hex_empty_pattern() {
    assert!(StringMatcher::match_hex(&[], &[1, 2, 3]).is_empty());
}

#[test]
fn match_hex_no_match() {
    let p = vec![HexToken::Byte(0xAA), HexToken::Byte(0xBB)];
    assert!(StringMatcher::match_hex(&p, &[0x01, 0x02, 0x03]).is_empty());
}

#[test]
fn match_hex_at_end_of_data() {
    let p = vec![HexToken::Byte(0xAA), HexToken::Byte(0xBB)];
    let offs = StringMatcher::match_hex(&p, &[0x00, 0xAA, 0xBB]);
    assert_eq!(offs, vec![1]);
}

#[test]
fn match_hex_pattern_longer_than_data() {
    let p = vec![HexToken::Byte(0xAA); 10];
    assert!(StringMatcher::match_hex(&p, &[0xAA, 0xAA]).is_empty());
}

#[test]
fn match_hex_masked_byte_matches_range() {
    let p = vec![HexToken::Masked(0x40, 0xF0)];
    let offs = StringMatcher::match_hex(&p, &[0x3F, 0x40, 0x4F, 0x50]);
    assert_eq!(offs, vec![1, 2]);
}

#[test]
fn match_hex_jump_zero_to_zero() {
    let p = vec![
        HexToken::Byte(0xAA),
        HexToken::Jump(0, 0),
        HexToken::Byte(0xBB),
    ];
    let offs = StringMatcher::match_hex(&p, &[0xAA, 0xBB]);
    assert_eq!(offs, vec![0]);
}

#[test]
fn match_hex_alternation_first_arm() {
    let p = vec![HexToken::Alternation(vec![
        vec![HexToken::Byte(0xAA)],
        vec![HexToken::Byte(0xBB)],
    ])];
    let offs = StringMatcher::match_hex(&p, &[0xAA, 0xCC, 0xBB]);
    assert!(offs.contains(&0));
    assert!(offs.contains(&2));
}

// ─── StringMatcher::match_text ──────────────────────────────────────────────

#[test]
fn match_text_empty_needle() {
    let m = StringModifiers::default();
    let offs = StringMatcher::match_text("", &m, b"abc");
    assert!(offs.is_empty());
}

#[test]
fn match_text_empty_data() {
    let m = StringModifiers::default();
    let offs = StringMatcher::match_text("abc", &m, b"");
    assert!(offs.is_empty());
}

#[test]
fn match_text_overlapping() {
    let m = StringModifiers::default();
    let offs = StringMatcher::match_text("aa", &m, b"aaaa");
    assert_eq!(offs, vec![0, 1, 2]);
}

#[test]
fn match_text_needle_equals_data() {
    let m = StringModifiers::default();
    let offs = StringMatcher::match_text("xyz", &m, b"xyz");
    assert_eq!(offs, vec![0]);
}

#[test]
fn match_text_nocase_modifier() {
    let mut m = StringModifiers::default();
    *m.nocase_mut() = true;
    let offs = StringMatcher::match_text("HELLO", &m, b"hello HELLO Hello");
    assert_eq!(offs, vec![0, 6, 12]);
}

#[test]
fn match_text_wide_modifier() {
    let mut m = StringModifiers::default();
    *m.wide_mut() = true;
    *m.ascii_mut() = false;
    let data: &[u8] = &[b'h', 0, b'i', 0];
    let offs = StringMatcher::match_text("hi", &m, data);
    assert_eq!(offs, vec![0]);
}

#[test]
fn match_text_fullword_filters_subword() {
    let mut m = StringModifiers::default();
    *m.fullword_mut() = true;
    // "cat" appears in "catnip" (not fullword) and " cat " (fullword)
    let offs = StringMatcher::match_text("cat", &m, b"catnip cat dog");
    assert_eq!(offs, vec![7]);
}

#[test]
fn match_text_xor_takes_priority() {
    let mut m = StringModifiers::default();
    m.xor = Some((0x42, 0x42));
    let plain = b"key";
    let xored: Vec<u8> = plain.iter().map(|&b| b ^ 0x42).collect();
    let offs = StringMatcher::match_text("key", &m, &xored);
    assert_eq!(offs, vec![0]);
}

// ─── match_xor edge cases ──────────────────────────────────────────────────

#[test]
fn match_xor_zero_key_is_plain() {
    let offs = StringMatcher::match_xor("abc", 0, 0, b"xxabcxx");
    assert_eq!(offs, vec![(2, 0)]);
}

#[test]
fn match_xor_min_greater_than_max_swaps() {
    // implementation swaps min/max so (5,1) iterates keys 1..=5; key 0 NOT tried.
    let offs = StringMatcher::match_xor("abc", 5, 1, b"xxabcxx");
    // The plain (key=0) match must NOT appear since 0 is outside the swapped range.
    assert!(offs.iter().all(|&(_, k)| (1..=5).contains(&k)));
    // But if we shift by an in-range key, it should match.
    let xored: Vec<u8> = b"abc".iter().map(|&b| b ^ 3).collect();
    let mut data = b"xx".to_vec();
    data.extend(&xored);
    let offs = StringMatcher::match_xor("abc", 5, 1, &data);
    assert!(offs.iter().any(|&(off, k)| off == 2 && k == 3));
}

#[test]
fn match_xor_empty_text() {
    let offs = StringMatcher::match_xor("", 0, 10, b"abcd");
    assert!(offs.is_empty());
}

#[test]
fn match_xor_full_range_finds_multiple_keys() {
    let plain = b"AB";
    // Same data XOR'd with different keys should be findable
    let data: Vec<u8> = plain.iter().map(|&b| b ^ 0x10).collect();
    let offs = StringMatcher::match_xor("AB", 0, 0xFF, &data);
    assert!(offs.iter().any(|&(_, k)| k == 0x10));
}

// ─── check_fullword ─────────────────────────────────────────────────────────

#[test]
fn fullword_at_start_of_data() {
    assert!(StringMatcher::check_fullword(b"foo bar", 0, 3));
}

#[test]
fn fullword_at_end_of_data() {
    assert!(StringMatcher::check_fullword(b"foo bar", 4, 3));
}

#[test]
fn fullword_blocked_by_underscore() {
    // "foo" preceded by '_' should NOT be fullword
    assert!(!StringMatcher::check_fullword(b"_foo bar", 1, 3));
    // "foo" followed by '_' should NOT be fullword
    assert!(!StringMatcher::check_fullword(b"foo_bar", 0, 3));
}

#[test]
fn fullword_blocked_by_digit() {
    assert!(!StringMatcher::check_fullword(b"1foo", 1, 3));
    assert!(!StringMatcher::check_fullword(b"foo1", 0, 3));
}

#[test]
fn fullword_punctuation_ok() {
    assert!(StringMatcher::check_fullword(b".foo.", 1, 3));
}

// ─── match_masked_byte ──────────────────────────────────────────────────────

#[test]
fn masked_byte_full_mask_exact() {
    assert!(StringMatcher::match_masked_byte(0xAB, 0xFF, 0xAB));
    assert!(!StringMatcher::match_masked_byte(0xAB, 0xFF, 0xAC));
}

#[test]
fn masked_byte_zero_mask_always_true() {
    assert!(StringMatcher::match_masked_byte(0x00, 0x00, 0xFF));
    assert!(StringMatcher::match_masked_byte(0xAB, 0x00, 0x00));
}

// ─── StringModifiers ────────────────────────────────────────────────────────

#[test]
fn string_modifiers_default_ascii_only() {
    let m = StringModifiers::default();
    assert!(m.ascii());
    assert!(!m.wide());
    assert!(!m.nocase());
    assert!(!m.fullword());
    assert!(!m.is_private());
    assert!(!m.base64());
    assert!(m.xor.is_none());
}

#[test]
fn string_modifiers_setters() {
    let mut m = StringModifiers::default();
    *m.nocase_mut() = true;
    *m.wide_mut() = true;
    *m.fullword_mut() = true;
    *m.private_mut() = true;
    *m.base64_mut() = true;
    assert!(m.nocase() && m.wide() && m.fullword() && m.is_private() && m.base64());
}

#[test]
fn parse_string_modifiers_keywords() {
    let m = YaraParser::parse_string_modifiers(&["nocase", "wide", "fullword"]);
    assert!(m.nocase() && m.wide() && m.fullword());
}

#[test]
fn parse_string_modifiers_xor_bare() {
    let m = YaraParser::parse_string_modifiers(&["xor"]);
    assert_eq!(m.xor, Some((0, 255)));
}

#[test]
fn parse_string_modifiers_xor_range() {
    let m = YaraParser::parse_string_modifiers(&["xor", "(0x10-0x20)"]);
    assert_eq!(m.xor, Some((0x10, 0x20)));
}

// ─── YaraError ──────────────────────────────────────────────────────────────

#[test]
fn yara_error_display_parse() {
    let e = YaraError::ParseError {
        line: 7,
        message: "bad".to_string(),
    };
    let s = format!("{e}");
    assert!(s.contains('7'));
    assert!(s.contains("bad"));
}

#[test]
fn yara_error_eq() {
    assert_eq!(
        YaraError::CompileError("x".into()),
        YaraError::CompileError("x".into())
    );
    assert_ne!(
        YaraError::CompileError("x".into()),
        YaraError::ScanError("x".into())
    );
}

// ─── YaraRule / YaraRuleSet ─────────────────────────────────────────────────

#[test]
fn rule_new_defaults() {
    let r = YaraRule::new("foo");
    assert_eq!(r.name, "foo");
    assert!(r.tags.is_empty());
    assert!(r.meta.is_empty());
    assert!(r.strings.is_empty());
    assert!(!r.is_private);
    assert!(!r.is_global);
    assert!(matches!(r.condition, YaraCondition::False));
}

#[test]
fn rule_meta_helpers() {
    let mut r = YaraRule::new("r");
    r.meta.push(YaraMeta {
        key: "description".into(),
        value: YaraMetaValue::String("desc".into()),
    });
    r.meta.push(YaraMeta {
        key: "author".into(),
        value: YaraMetaValue::String("Alice".into()),
    });
    r.meta.push(YaraMeta {
        key: "date".into(),
        value: YaraMetaValue::String("2024".into()),
    });
    assert_eq!(r.description(), Some("desc".into()));
    assert_eq!(r.author(), Some("Alice".into()));
    assert_eq!(r.date(), Some("2024".into()));
    assert!(r.get_meta("missing").is_none());
}

#[test]
fn rule_meta_helpers_wrong_type_returns_none() {
    let mut r = YaraRule::new("r");
    r.meta.push(YaraMeta {
        key: "description".into(),
        value: YaraMetaValue::Integer(42),
    });
    assert!(r.description().is_none());
}

#[test]
fn ruleset_add_count_lookup() {
    let mut rs = YaraRuleSet::new();
    rs.add_rule(YaraRule::new("a"));
    rs.add_rule(YaraRule::new("b"));
    assert_eq!(rs.rule_count(), 2);
    assert!(rs.rule_by_name("a").is_some());
    assert!(rs.rule_by_name("nope").is_none());
}

// ─── YaraParser::parse — full rule parsing ──────────────────────────────────

#[test]
fn parse_rule_with_tags() {
    let src = r"rule foo : tag1 tag2 { condition: true }";
    let r = YaraParser::parse_rule(src).unwrap();
    assert_eq!(r.name, "foo");
    assert_eq!(r.tags, vec!["tag1".to_string(), "tag2".into()]);
}

#[test]
fn parse_private_rule() {
    let src = r"private rule p { condition: true }";
    let r = YaraParser::parse_rule(src).unwrap();
    assert!(r.is_private);
}

#[test]
fn parse_global_rule() {
    let src = r"global rule g { condition: true }";
    let r = YaraParser::parse_rule(src).unwrap();
    assert!(r.is_global);
}

#[test]
fn parse_multiple_rules() {
    let src = r"
        rule a { condition: true }
        rule b { condition: false }
    ";
    let rs = YaraParser::parse(src).unwrap();
    assert_eq!(rs.rule_count(), 2);
}

#[test]
fn parse_no_rules_empty_input() {
    let rs = YaraParser::parse("").unwrap();
    assert_eq!(rs.rule_count(), 0);
}

#[test]
fn parse_rule_missing_brace_errors() {
    let src = r"rule broken condition: true }";
    let r = YaraParser::parse(src);
    assert!(r.is_err());
}

#[test]
fn parse_rule_missing_name_errors() {
    let src = r"rule { condition: true }";
    let r = YaraParser::parse(src);
    assert!(r.is_err());
}

#[test]
fn parse_rule_missing_condition_errors() {
    let src = r#"rule foo { strings: $a = "x" }"#;
    let r = YaraParser::parse(src);
    assert!(r.is_err());
}

#[test]
fn parse_rule_with_meta() {
    let src = r#"
        rule r {
            meta:
                author = "bob"
                score = 5
                flag = true
            condition: true
        }
    "#;
    let r = YaraParser::parse_rule(src).unwrap();
    assert_eq!(r.meta.len(), 3);
    assert_eq!(r.author(), Some("bob".into()));
    assert!(matches!(
        r.get_meta("score"),
        Some(YaraMetaValue::Integer(5))
    ));
    assert!(matches!(r.get_meta("flag"), Some(YaraMetaValue::Bool(true))));
}

#[test]
fn parse_rule_with_hex_string() {
    let src = r"rule h { strings: $a = { DE AD BE EF } condition: $a }";
    let r = YaraParser::parse_rule(src).unwrap();
    match &r.strings[0].pattern {
        YaraPattern::Hex(t) => assert_eq!(t.len(), 4),
        _ => panic!("expected hex"),
    }
}

#[test]
fn parse_rule_with_regex_string() {
    let src = r"rule rg { strings: $a = /foo.*bar/ condition: $a }";
    let r = YaraParser::parse_rule(src).unwrap();
    match &r.strings[0].pattern {
        YaraPattern::Regex(s) => assert_eq!(s, "foo.*bar"),
        _ => panic!("expected regex"),
    }
}

#[test]
fn parse_rule_with_escaped_quotes() {
    let src = r#"rule e { strings: $a = "he said \"hi\"" condition: $a }"#;
    let r = YaraParser::parse_rule(src).unwrap();
    match &r.strings[0].pattern {
        YaraPattern::Text(s) => assert_eq!(s, "he said \"hi\""),
        _ => panic!("expected text"),
    }
}

#[test]
fn parse_rule_with_string_modifiers() {
    let src = r#"rule m { strings: $a = "X" nocase wide fullword condition: $a }"#;
    let r = YaraParser::parse_rule(src).unwrap();
    let m = &r.strings[0].modifiers;
    assert!(m.nocase() && m.wide() && m.fullword());
}

// ─── Condition parsing ─────────────────────────────────────────────────────

#[test]
fn parse_condition_true_false() {
    let r = YaraParser::parse_rule(r"rule t { condition: true }").unwrap();
    assert!(matches!(r.condition, YaraCondition::True));
    let r = YaraParser::parse_rule(r"rule f { condition: false }").unwrap();
    assert!(matches!(r.condition, YaraCondition::False));
}

#[test]
fn parse_condition_any_all_of_them() {
    let r = YaraParser::parse_rule(
        r#"rule a { strings: $x = "y" condition: any of them }"#,
    )
    .unwrap();
    assert!(matches!(r.condition, YaraCondition::Any));
}

#[test]
fn parse_condition_and_or_not() {
    let r = YaraParser::parse_rule(
        r#"rule c { strings: $a = "a" $b = "b" condition: $a and $b }"#,
    )
    .unwrap();
    assert!(matches!(r.condition, YaraCondition::And(_, _)));

    let r = YaraParser::parse_rule(
        r#"rule c { strings: $a = "a" $b = "b" condition: $a or $b }"#,
    )
    .unwrap();
    assert!(matches!(r.condition, YaraCondition::Or(_, _)));

    let r = YaraParser::parse_rule(r"rule c { condition: not true }").unwrap();
    assert!(matches!(r.condition, YaraCondition::Not(_)));
}

#[test]
fn parse_condition_comparison() {
    let r = YaraParser::parse_rule(r"rule c { condition: filesize > 100 }").unwrap();
    assert!(matches!(r.condition, YaraCondition::Comparison(_, CmpOp::Gt, _)));
}

// ─── Scanner end-to-end ─────────────────────────────────────────────────────

#[test]
fn scanner_matches_text_string() {
    let src = r#"rule m { strings: $a = "needle" condition: $a }"#;
    let s = YaraScanner::from_rules_text(src).unwrap();
    let matches = s.scan(b"prefix needle suffix").unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_name, "m");
    assert_eq!(matches[0].strings.len(), 1);
    assert_eq!(matches[0].strings[0].offset, 7);
}

#[test]
fn scanner_no_match() {
    let src = r#"rule m { strings: $a = "needle" condition: $a }"#;
    let s = YaraScanner::from_rules_text(src).unwrap();
    let matches = s.scan(b"nothing here").unwrap();
    assert!(matches.is_empty());
}

#[test]
fn scanner_condition_true_always_matches() {
    let src = r"rule t { condition: true }";
    let s = YaraScanner::from_rules_text(src).unwrap();
    assert_eq!(s.scan(b"").unwrap().len(), 1);
    assert_eq!(s.scan(b"abc").unwrap().len(), 1);
}

#[test]
fn scanner_condition_false_never_matches() {
    let src = r"rule t { condition: false }";
    let s = YaraScanner::from_rules_text(src).unwrap();
    assert!(s.scan(b"abc").unwrap().is_empty());
}

#[test]
fn scanner_private_rule_skipped() {
    let src = r"private rule p { condition: true }";
    let s = YaraScanner::from_rules_text(src).unwrap();
    assert!(s.scan(b"abc").unwrap().is_empty());
}

#[test]
fn scanner_and_condition() {
    let src = "rule c {\n strings:\n $a = \"foo\"\n $b = \"bar\"\n condition: $a and $b\n}";
    let s = YaraScanner::from_rules_text(src).unwrap();
    assert!(s.scan(b"only foo here").unwrap().is_empty());
    assert_eq!(s.scan(b"foo and bar").unwrap().len(), 1);
}

#[test]
fn scanner_or_condition() {
    let src = "rule c {\n strings:\n $a = \"foo\"\n $b = \"bar\"\n condition: $a or $b\n}";
    let s = YaraScanner::from_rules_text(src).unwrap();
    assert_eq!(s.scan(b"foo only").unwrap().len(), 1);
    assert_eq!(s.scan(b"bar only").unwrap().len(), 1);
    assert!(s.scan(b"nope").unwrap().is_empty());
}

#[test]
fn scanner_filesize_comparison() {
    let src = r"rule big { condition: filesize > 10 }";
    let s = YaraScanner::from_rules_text(src).unwrap();
    assert!(s.scan(b"short").unwrap().is_empty());
    assert_eq!(s.scan(b"this is more than ten bytes").unwrap().len(), 1);
}

#[test]
fn scanner_string_count_condition() {
    // #a == 3 must be parsed as Comparison(StringCount, ==, 3), not as a bare
    // StringCount with stringy id "a == 3".
    let src = "rule c {\n strings:\n $a = \"x\"\n condition: #a == 3\n}";
    let s = YaraScanner::from_rules_text(src).unwrap();
    assert_eq!(s.scan(b"xxx").unwrap().len(), 1);
    assert!(s.scan(b"xx").unwrap().is_empty());
}

#[test]
fn scanner_hex_pattern_match() {
    let src = r"rule h { strings: $a = { DE AD BE EF } condition: $a }";
    let s = YaraScanner::from_rules_text(src).unwrap();
    let m = s.scan(&[0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF]).unwrap();
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].strings[0].offset, 1);
}

#[test]
fn scanner_string_at_offset() {
    let src = r#"rule c { strings: $a = "abc" condition: $a at 5 }"#;
    let s = YaraScanner::from_rules_text(src).unwrap();
    assert_eq!(s.scan(b"00000abcXX").unwrap().len(), 1);
    assert!(s.scan(b"abc0000000").unwrap().is_empty());
}

#[test]
fn scanner_match_records_offset_and_length() {
    let src = r#"rule m { strings: $a = "needle" condition: $a }"#;
    let s = YaraScanner::from_rules_text(src).unwrap();
    let m = s.scan(b"xx needle xx").unwrap();
    assert_eq!(m[0].strings[0].offset, 3);
    assert_eq!(m[0].strings[0].length, 6);
    assert_eq!(m[0].strings[0].data, b"needle".to_vec());
}

#[test]
fn scanner_multiple_rules_independent_matches() {
    let src = r#"
        rule a { strings: $x = "foo" condition: $x }
        rule b { strings: $y = "bar" condition: $y }
    "#;
    let s = YaraScanner::from_rules_text(src).unwrap();
    let m = s.scan(b"foo bar").unwrap();
    assert_eq!(m.len(), 2);
    let names: Vec<&str> = m.iter().map(|x| x.rule_name.as_str()).collect();
    assert!(names.contains(&"a") && names.contains(&"b"));
}

#[test]
fn scanner_scan_with_base_address() {
    let src = r"rule b { condition: entrypoint == 0x1000 }";
    let s = YaraScanner::from_rules_text(src).unwrap();
    assert_eq!(s.scan_with_base(b"abc", 0x1000).unwrap().len(), 1);
    assert!(s.scan_with_base(b"abc", 0x2000).unwrap().is_empty());
}

// ─── ScanContext ───────────────────────────────────────────────────────────

#[test]
fn scancontext_basics() {
    let data = b"abcdef";
    let ctx = ScanContext::new(data);
    assert_eq!(ctx.data, data);
    assert_eq!(ctx.filesize, 6);
    assert_eq!(ctx.base_address, 0);
    assert_eq!(ctx.string_count("x"), 0);
    assert!(!ctx.string_matched("x"));
    assert_eq!(ctx.string_offset("x", 0), None);
}

#[test]
fn scancontext_with_base() {
    let ctx = ScanContext::new(b"x").with_base(0xDEAD);
    assert_eq!(ctx.base_address, 0xDEAD);
}

#[test]
fn scancontext_string_helpers() {
    let mut ctx = ScanContext::new(b"data");
    ctx.string_matches.insert("a".into(), vec![1, 5, 10]);
    assert_eq!(ctx.string_count("a"), 3);
    assert!(ctx.string_matched("a"));
    assert_eq!(ctx.string_offset("a", 0), Some(1));
    assert_eq!(ctx.string_offset("a", 2), Some(10));
    assert_eq!(ctx.string_offset("a", 3), None);
}

// ─── eval_expr / eval_condition direct ──────────────────────────────────────

#[test]
fn eval_expr_arith() {
    let ctx = ScanContext::new(b"");
    let e = YaraExpr::Add(
        Box::new(YaraExpr::Integer(2)),
        Box::new(YaraExpr::Mul(
            Box::new(YaraExpr::Integer(3)),
            Box::new(YaraExpr::Integer(4)),
        )),
    );
    assert_eq!(YaraScanner::eval_expr(&e, &ctx).unwrap(), 14);
}

#[test]
fn eval_expr_div_zero_errors() {
    let ctx = ScanContext::new(b"");
    let e = YaraExpr::Div(
        Box::new(YaraExpr::Integer(1)),
        Box::new(YaraExpr::Integer(0)),
    );
    assert!(matches!(
        YaraScanner::eval_expr(&e, &ctx),
        Err(YaraError::ScanError(_))
    ));
}

#[test]
fn eval_expr_mod_zero_errors() {
    let ctx = ScanContext::new(b"");
    let e = YaraExpr::Mod(
        Box::new(YaraExpr::Integer(1)),
        Box::new(YaraExpr::Integer(0)),
    );
    assert!(matches!(
        YaraScanner::eval_expr(&e, &ctx),
        Err(YaraError::ScanError(_))
    ));
}

#[test]
fn eval_expr_filesize() {
    let ctx = ScanContext::new(b"hello");
    let e = YaraExpr::FileSize;
    assert_eq!(YaraScanner::eval_expr(&e, &ctx).unwrap(), 5);
}

#[test]
fn eval_expr_unknown_identifier() {
    let ctx = ScanContext::new(b"");
    let e = YaraExpr::Identifier("bogus".into());
    assert!(matches!(
        YaraScanner::eval_expr(&e, &ctx),
        Err(YaraError::UnknownIdentifier(_))
    ));
}

#[test]
fn eval_expr_funccall_errors() {
    let ctx = ScanContext::new(b"");
    let e = YaraExpr::FuncCall("foo".into(), vec![]);
    assert!(YaraScanner::eval_expr(&e, &ctx).is_err());
}

#[test]
fn eval_expr_bitops() {
    let ctx = ScanContext::new(b"");
    let e = YaraExpr::BitAnd(
        Box::new(YaraExpr::Integer(0xF0)),
        Box::new(YaraExpr::Integer(0x33)),
    );
    assert_eq!(YaraScanner::eval_expr(&e, &ctx).unwrap(), 0x30);
    let e = YaraExpr::BitOr(
        Box::new(YaraExpr::Integer(0xF0)),
        Box::new(YaraExpr::Integer(0x0F)),
    );
    assert_eq!(YaraScanner::eval_expr(&e, &ctx).unwrap(), 0xFF);
    let e = YaraExpr::BitXor(
        Box::new(YaraExpr::Integer(0xFF)),
        Box::new(YaraExpr::Integer(0x0F)),
    );
    assert_eq!(YaraScanner::eval_expr(&e, &ctx).unwrap(), 0xF0);
    let e = YaraExpr::Shl(Box::new(YaraExpr::Integer(1)), Box::new(YaraExpr::Integer(4)));
    assert_eq!(YaraScanner::eval_expr(&e, &ctx).unwrap(), 16);
    let e = YaraExpr::Shr(Box::new(YaraExpr::Integer(16)), Box::new(YaraExpr::Integer(2)));
    assert_eq!(YaraScanner::eval_expr(&e, &ctx).unwrap(), 4);
    let e = YaraExpr::Neg(Box::new(YaraExpr::Integer(5)));
    assert_eq!(YaraScanner::eval_expr(&e, &ctx).unwrap(), -5);
}

#[test]
fn eval_condition_comparison_eq() {
    let ctx = ScanContext::new(b"hello");
    let c = YaraCondition::Comparison(
        Box::new(YaraExpr::FileSize),
        CmpOp::Eq,
        Box::new(YaraExpr::Integer(5)),
    );
    assert!(YaraScanner::eval_condition(&c, &ctx).unwrap());
}

#[test]
fn eval_condition_string_match_at() {
    let mut ctx = ScanContext::new(b"xxxxxabc");
    ctx.string_matches.insert("a".into(), vec![5]);
    let c = YaraCondition::StringMatchAt(
        "$a".into(),
        Box::new(YaraExpr::Integer(5)),
    );
    assert!(YaraScanner::eval_condition(&c, &ctx).unwrap());
    let c = YaraCondition::StringMatchAt(
        "$a".into(),
        Box::new(YaraExpr::Integer(0)),
    );
    assert!(!YaraScanner::eval_condition(&c, &ctx).unwrap());
}

#[test]
fn eval_condition_string_match_in_range() {
    let data = b"x".repeat(100);
    let mut ctx = ScanContext::new(data.as_slice());
    ctx.string_matches.insert("a".into(), vec![50]);
    let c = YaraCondition::StringMatchIn(
        "$a".into(),
        Box::new(YaraExpr::Integer(40)),
        Box::new(YaraExpr::Integer(60)),
    );
    assert!(YaraScanner::eval_condition(&c, &ctx).unwrap());
    let c = YaraCondition::StringMatchIn(
        "$a".into(),
        Box::new(YaraExpr::Integer(0)),
        Box::new(YaraExpr::Integer(10)),
    );
    assert!(!YaraScanner::eval_condition(&c, &ctx).unwrap());
}

// ─── YaraScanner Send/Sync ──────────────────────────────────────────────────

#[test]
fn scanner_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<YaraScanner>();
    assert_send_sync::<YaraRuleSet>();
    assert_send_sync::<YaraRule>();
    assert_send_sync::<YaraError>();
}

// ─── Adversarial / malformed ────────────────────────────────────────────────

#[test]
fn parse_rule_unclosed_brace() {
    let src = r"rule x { condition: true";
    assert!(YaraParser::parse(src).is_err());
}

#[test]
fn parse_rule_unclosed_string() {
    let src = r#"rule x { strings: $a = "no_close condition: $a }"#;
    assert!(YaraParser::parse(src).is_err());
}

#[test]
fn parse_rule_unclosed_regex() {
    let src = r"rule x { strings: $a = /no_close condition: $a }";
    assert!(YaraParser::parse(src).is_err());
}

#[test]
fn parse_rule_unclosed_hex() {
    let src = r"rule x { strings: $a = { DE AD condition: $a";
    assert!(YaraParser::parse(src).is_err());
}

#[test]
fn parse_rule_empty_meta_value_is_string() {
    // YARA-ish; check non-crash behavior
    let src = r"rule x { meta: k = abc condition: true }";
    let r = YaraParser::parse_rule(src).unwrap();
    assert!(matches!(r.get_meta("k"), Some(YaraMetaValue::String(_))));
}

#[test]
fn parser_no_panic_on_random_input() {
    // Some adversarial inputs that should error rather than panic
    let inputs = [
        "}}}}",
        "rule",
        "rule {",
        "rule x {",
        "rule x }",
        "{{{{",
    ];
    for inp in inputs {
        let _ = YaraParser::parse(inp); // must not panic
    }
}

#[test]
fn scanner_recursive_alternation_no_crash() {
    // Nested alternations should not crash
    let src = r"rule x { strings: $a = { (AA | BB) (CC | DD) } condition: $a }";
    let s = YaraScanner::from_rules_text(src).unwrap();
    let _ = s.scan(&[0xAA, 0xCC, 0xBB, 0xDD]).unwrap();
}

#[test]
fn yara_meta_value_variants_constructable() {
    let _ = YaraMetaValue::String("x".into());
    let _ = YaraMetaValue::Integer(1);
    let _ = YaraMetaValue::Bool(false);
}

#[test]
fn yara_pattern_variants_constructable() {
    let _ = YaraPattern::Text("x".into());
    let _ = YaraPattern::Hex(vec![HexToken::Byte(0)]);
    let _ = YaraPattern::Regex("x".into());
}

#[test]
fn hextoken_eq_and_clone() {
    let a = HexToken::Byte(1);
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(HexToken::Byte(1), HexToken::Byte(2));
    assert_ne!(HexToken::Byte(1), HexToken::Wildcard);
}

#[test]
fn ruleset_default_is_empty() {
    let rs = YaraRuleSet::default();
    assert_eq!(rs.rule_count(), 0);
    assert!(rs.imports.is_empty());
}

#[test]
fn parse_rule_with_import() {
    let src = r#"
        import "pe"
        rule r { condition: true }
    "#;
    let rs = YaraParser::parse(src).unwrap();
    assert_eq!(rs.rule_count(), 1);
}
