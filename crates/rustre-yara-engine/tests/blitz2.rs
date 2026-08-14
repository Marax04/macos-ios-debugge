//! Adversarial tests for rustre-yara-engine core API.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use rustre_yara_engine::{
    CompOp, Condition, HexToken, MetaValue, PatternMatch, RuleMatch, StringMatch, StringModifiers,
    StringValue, YaraError, YaraParser, YaraRule, YaraRuleDefinition, YaraRuleSet, YaraScanner,
    YaraString,
};

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn rand_bytes(g: &mut impl FnMut() -> u64, n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    while v.len() < n {
        let x = g();
        for i in 0..8 {
            if v.len() == n {
                break;
            }
            v.push(((x >> (i * 8)) & 0xFF) as u8);
        }
    }
    v
}

// ── basic constructors / defaults ────────────────────────────────────────────

#[test]
fn test_scanner_new_empty() {
    let s = YaraScanner::new();
    assert_eq!(s.rule_count(), 0);
    assert!(s.scan(b"hello").is_empty());
    assert!(s.scan_names(b"").is_empty());
}

#[test]
fn test_scanner_default_eq_new() {
    let a = YaraScanner::new();
    let b = YaraScanner::default();
    assert_eq!(a.rule_count(), b.rule_count());
}

#[test]
fn test_parser_default() {
    let _ = YaraParser;
    let _ = YaraParser::new();
}

#[test]
fn test_rule_new_defaults() {
    let r = YaraRule::new("foo".into());
    assert_eq!(r.name, "foo");
    assert_eq!(r.namespace, "default");
    assert!(r.tags.is_empty());
    assert!(r.strings.is_empty());
    assert!(r.meta.is_empty());
    match r.condition {
        Condition::True => {}
        _ => panic!("default cond should be True"),
    }
}

#[test]
fn test_rule_builders() {
    let r = YaraRule::new("r".into())
        .with_tag("a".into())
        .with_tag("b".into())
        .with_meta("k".into(), MetaValue::Int(42))
        .with_condition(Condition::False);
    assert_eq!(r.tags, vec!["a", "b"]);
    assert_eq!(r.meta.len(), 1);
    matches!(r.condition, Condition::False);
}

#[test]
fn test_ruleset_empty() {
    let rs = YaraRuleSet::new();
    assert!(rs.is_empty());
    assert_eq!(rs.len(), 0);
    assert!(!rs.is_compiled());
}

#[test]
fn test_ruleset_default() {
    let rs = YaraRuleSet::default();
    assert!(rs.is_empty());
}

#[test]
fn test_ruleset_add_empty_source_err() {
    let mut rs = YaraRuleSet::new();
    let err = rs.add_rule("   \t\n").unwrap_err();
    match err {
        YaraError::ParseError { .. } => {}
        e => panic!("expected ParseError got {e:?}"),
    }
}

#[test]
fn test_ruleset_add_ok_invalidates_compiled() {
    let mut rs = YaraRuleSet::new();
    rs.add_rule("rule a { condition: true }").unwrap();
    assert_eq!(rs.len(), 1);
    assert!(!rs.is_compiled());
}

// ── parser ──────────────────────────────────────────────────────────────────

#[test]
fn test_parse_minimal_rule() {
    let p = YaraParser::new();
    let r = p.parse_rule("rule foo { condition: true }").unwrap();
    assert_eq!(r.name, "foo");
    matches!(r.condition, Condition::True);
}

#[test]
fn test_parse_rule_missing_keyword() {
    let p = YaraParser::new();
    let e = p.parse_rule("foo { condition: true }").unwrap_err();
    matches!(e, YaraError::ParseError { .. });
}

#[test]
fn test_parse_rule_no_body() {
    let p = YaraParser::new();
    // "rule foo" with no brace at all -> parse error
    let e = p.parse_rule("rule foo").unwrap_err();
    matches!(e, YaraError::ParseError { .. });
}

#[test]
fn test_parse_rule_unmatched_brace() {
    let p = YaraParser::new();
    let e = p.parse_rule("rule foo { condition: true").unwrap_err();
    matches!(e, YaraError::ParseError { .. });
}

#[test]
fn test_parse_rule_with_tags() {
    let p = YaraParser::new();
    let r = p
        .parse_rule("rule foo : tag1 tag2 { condition: false }")
        .unwrap();
    assert_eq!(r.tags, vec!["tag1", "tag2"]);
    matches!(r.condition, Condition::False);
}

#[test]
fn test_parse_rule_with_meta() {
    let p = YaraParser::new();
    let r = p
        .parse_rule(
            r#"rule m {
                meta:
                    author = "alice"
                    count = 7
                    flag = true
                    other = false
                condition: true
            }"#,
        )
        .unwrap();
    assert!(matches!(r.meta.get("author"), Some(MetaValue::String(s)) if s == "alice"));
    assert!(matches!(r.meta.get("count"), Some(MetaValue::Int(7))));
    assert!(matches!(r.meta.get("flag"), Some(MetaValue::Bool(true))));
    assert!(matches!(r.meta.get("other"), Some(MetaValue::Bool(false))));
}

#[test]
fn test_parse_rule_with_strings_and_text_match() {
    let p = YaraParser::new();
    let r = p
        .parse_rule(
            r#"rule s {
                strings:
                    $a = "hello"
                condition: $a
            }"#,
        )
        .unwrap();
    assert_eq!(r.strings.len(), 1);
    assert_eq!(r.strings[0].identifier, "$a");
    let scanner = YaraScanner::new();
    scanner.add_rule(r);
    let m = scanner.scan(b"xxhelloxx");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].string_matches[0].offset, 2);
}

#[test]
fn test_parse_rule_nocase_modifier() {
    let p = YaraParser::new();
    let r = p
        .parse_rule(
            r#"rule s {
                strings: $a = "Hello" nocase
                condition: $a
            }"#,
        )
        .unwrap();
    assert!(r.strings[0].modifiers.contains(StringModifiers::NOCASE));
}

#[test]
fn test_parse_rule_wide_fullword_ascii_modifiers() {
    let p = YaraParser::new();
    let r = p
        .parse_rule(
            r#"rule s {
                strings: $a = "x" wide ascii fullword
                condition: $a
            }"#,
        )
        .unwrap();
    let m = r.strings[0].modifiers;
    assert!(m.contains(StringModifiers::WIDE));
    assert!(m.contains(StringModifiers::ASCII));
    assert!(m.contains(StringModifiers::FULLWORD));
}

#[test]
fn test_parse_filesize_conditions() {
    let p = YaraParser::new();
    for (txt, op) in [
        ("filesize > 10", CompOp::Gt),
        ("filesize < 10", CompOp::Lt),
        ("filesize >= 10", CompOp::Ge),
        ("filesize <= 10", CompOp::Le),
        ("filesize == 10", CompOp::Eq),
        ("filesize != 10", CompOp::Ne),
    ] {
        let r = p
            .parse_rule(&format!("rule r {{ condition: {txt} }}"))
            .unwrap();
        match r.condition {
            Condition::FileSize(got, n) => {
                assert_eq!(got, op);
                assert_eq!(n, 10);
            }
            _ => panic!("expected FileSize for {txt}"),
        }
    }
}

#[test]
fn test_parse_condition_simple_keywords() {
    let p = YaraParser::new();
    let cases = [
        ("any of them", "any"),
        ("all of them", "all"),
        ("none of them", "none"),
    ];
    for (txt, kind) in cases {
        let r = p
            .parse_rule(&format!("rule r {{ condition: {txt} }}"))
            .unwrap();
        let ok = match (&r.condition, kind) {
            (Condition::Any, "any") => true,
            (Condition::All, "all") => true,
            (Condition::None, "none") => true,
            _ => false,
        };
        assert!(ok, "mismatch for {txt}");
    }
}

#[test]
fn test_parse_condition_and_or_not() {
    let p = YaraParser::new();
    let r = p
        .parse_rule("rule r { condition: true and false }")
        .unwrap();
    assert!(matches!(r.condition, Condition::And(_, _)));
    let r = p
        .parse_rule("rule r { condition: true or false }")
        .unwrap();
    assert!(matches!(r.condition, Condition::Or(_, _)));
    let r = p.parse_rule("rule r { condition: not true }").unwrap();
    assert!(matches!(r.condition, Condition::Not(_)));
}

#[test]
fn test_parse_rules_multi() {
    let p = YaraParser::new();
    let src = "rule a { condition: true } rule b { condition: false }";
    let rs = p.parse_rules(src).unwrap();
    assert_eq!(rs.len(), 2);
    assert_eq!(rs[0].name, "a");
    assert_eq!(rs[1].name, "b");
}

#[test]
fn test_parse_rules_unmatched_braces_err() {
    let p = YaraParser::new();
    let e = p.parse_rules("rule a { condition: true ").unwrap_err();
    matches!(e, YaraError::ParseError { .. });
}

#[test]
fn test_parse_rules_empty_input() {
    let p = YaraParser::new();
    let rs = p.parse_rules("").unwrap();
    assert!(rs.is_empty());
}

// ── parser fuzz: never panic ─────────────────────────────────────────────────

#[test]
fn test_parser_fuzz_random_inputs_no_panic() {
    let p = YaraParser::new();
    let mut g = lcg();
    for _ in 0..60 {
        let n = (g() as usize) % 200;
        let bytes = rand_bytes(&mut g, n);
        let s: String = bytes.iter().map(|&b| (b % 0x60 + 0x20) as char).collect();
        let _ = p.parse_rule(&s);
        let _ = p.parse_rules(&s);
    }
}

#[test]
fn test_parser_fuzz_around_keywords() {
    let p = YaraParser::new();
    let mut g = lcg();
    let snippets = [
        "rule ",
        "{",
        "}",
        "condition:",
        "strings:",
        "meta:",
        "$a",
        "true",
        "false",
    ];
    for _ in 0..60 {
        let mut s = String::new();
        for _ in 0..=((g() as usize) % 8) {
            s.push_str(snippets[(g() as usize) % snippets.len()]);
            s.push(' ');
        }
        let _ = p.parse_rule(&s);
        let _ = p.parse_rules(&s);
    }
}

// ── helpers / scanner string matching ────────────────────────────────────────

#[test]
fn test_scan_text_basic() {
    let scanner = YaraScanner::new();
    scanner.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Text("abc".into()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$a".into())),
    );
    let hits = scanner.scan(b"xxabcyyabc");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].string_matches.len(), 2);
}

#[test]
fn test_scan_text_nocase() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Text("Hi".into()),
                modifiers: StringModifiers::NOCASE,
            })
            .with_condition(Condition::StringMatch("$a".into())),
    );
    let hits = s.scan(b"HI hi Hi hI");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].string_matches.len(), 4);
}

#[test]
fn test_scan_text_wide() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Text("AB".into()),
                modifiers: StringModifiers::WIDE,
            })
            .with_condition(Condition::StringMatch("$a".into())),
    );
    // "AB" wide = 41 00 42 00
    let mut data = vec![0xFFu8, 0xFF];
    data.extend_from_slice(&[0x41, 0x00, 0x42, 0x00]);
    data.extend_from_slice(&[0xFF, 0xFF]);
    let hits = s.scan(&data);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].string_matches[0].offset, 2);
    assert_eq!(hits[0].string_matches[0].length, 4);
}

#[test]
fn test_scan_text_fullword() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Text("cat".into()),
                modifiers: StringModifiers::FULLWORD,
            })
            .with_condition(Condition::StringMatch("$a".into())),
    );
    // "cats" -> no match; " cat " -> match
    assert!(s.scan(b"cats").is_empty());
    assert_eq!(s.scan(b" cat ")[0].string_matches.len(), 1);
    assert_eq!(s.scan(b"cat")[0].string_matches.len(), 1);
}

#[test]
fn test_scan_text_empty_pattern_no_match() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Text(String::new()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$a".into())),
    );
    assert!(s.scan(b"abc").is_empty());
}

#[test]
fn test_scan_text_empty_data_no_match() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Text("x".into()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$a".into())),
    );
    assert!(s.scan(b"").is_empty());
}

#[test]
fn test_scan_hex_exact() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$h".into(),
                value: StringValue::Hex(vec![HexToken::Byte(0xDE), HexToken::Byte(0xAD)]),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$h".into())),
    );
    let hits = s.scan(&[0x00, 0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].string_matches[0].offset, 1);
}

#[test]
fn test_scan_hex_wildcard() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$h".into(),
                value: StringValue::Hex(vec![
                    HexToken::Byte(0xDE),
                    HexToken::Wildcard,
                    HexToken::Byte(0xEF),
                ]),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$h".into())),
    );
    let hits = s.scan(&[0xDE, 0xAD, 0xEF]);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].string_matches[0].length, 3);
}

#[test]
fn test_scan_hex_masked() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$h".into(),
                value: StringValue::Hex(vec![HexToken::MaskedByte(0xA0, 0xF0)]),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$h".into())),
    );
    // matches any byte with high nibble 0xA
    let hits = s.scan(&[0x01, 0xA5, 0xBC]);
    assert!(hits[0].string_matches.iter().any(|m| m.offset == 1));
}

#[test]
fn test_scan_hex_jump() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$h".into(),
                value: StringValue::Hex(vec![
                    HexToken::Byte(0x01),
                    HexToken::Jump(2, Some(3)),
                    HexToken::Byte(0x02),
                ]),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$h".into())),
    );
    // 01 ?? ?? 02 (jump=2)
    let hits = s.scan(&[0x01, 0xAA, 0xBB, 0x02]);
    assert!(!hits.is_empty());
}

#[test]
fn test_scan_hex_alternative() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$h".into(),
                value: StringValue::Hex(vec![HexToken::Alternative(vec![
                    vec![HexToken::Byte(0xAA)],
                    vec![HexToken::Byte(0xBB)],
                ])]),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$h".into())),
    );
    let h1 = s.scan(&[0xAA]);
    let h2 = s.scan(&[0xBB]);
    let h3 = s.scan(&[0xCC]);
    assert!(!h1.is_empty());
    assert!(!h2.is_empty());
    assert!(h3.is_empty());
}

#[test]
fn test_scan_regex_basic() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$r".into(),
                value: StringValue::Regex(r"\d+".into()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$r".into())),
    );
    let hits = s.scan(b"abc123def456");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].string_matches.len(), 2);
}

#[test]
fn test_scan_regex_invalid_does_not_panic() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$r".into(),
                value: StringValue::Regex("[invalid".into()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$r".into())),
    );
    // invalid regex -> no matches, no panic
    let hits = s.scan(b"abc");
    assert!(hits.is_empty());
}

// ── conditions ───────────────────────────────────────────────────────────────

#[test]
fn test_cond_true_false() {
    let s = YaraScanner::new();
    s.add_rule(YaraRule::new("t".into()).with_condition(Condition::True));
    s.add_rule(YaraRule::new("f".into()).with_condition(Condition::False));
    let names = s.scan_names(b"");
    assert!(names.contains(&"t".to_string()));
    assert!(!names.contains(&"f".to_string()));
}

#[test]
fn test_cond_filesize_all_ops() {
    let data = b"01234567";
    for (op, val, expect) in [
        (CompOp::Eq, 8u64, true),
        (CompOp::Ne, 8, false),
        (CompOp::Lt, 9, true),
        (CompOp::Le, 8, true),
        (CompOp::Gt, 7, true),
        (CompOp::Ge, 8, true),
        (CompOp::Eq, 0, false),
    ] {
        let s = YaraScanner::new();
        s.add_rule(YaraRule::new("r".into()).with_condition(Condition::FileSize(op, val)));
        assert_eq!(!s.scan(data).is_empty(), expect, "{op:?} {val}");
    }
}

#[test]
fn test_cond_entrypoint() {
    let s = YaraScanner::new();
    s.add_rule(YaraRule::new("r".into()).with_condition(Condition::EntryPoint));
    assert!(!s.scan(&[0x4D, 0x5A, 0, 0]).is_empty());
    assert!(s.scan(&[0x00, 0x00]).is_empty());
    assert!(s.scan(&[]).is_empty());
}

#[test]
fn test_cond_and_or_not() {
    let s = YaraScanner::new();
    s.add_rule(YaraRule::new("a".into()).with_condition(Condition::And(
        Box::new(Condition::True),
        Box::new(Condition::False),
    )));
    s.add_rule(YaraRule::new("b".into()).with_condition(Condition::Or(
        Box::new(Condition::True),
        Box::new(Condition::False),
    )));
    s.add_rule(YaraRule::new("c".into()).with_condition(Condition::Not(Box::new(Condition::False))));
    let names = s.scan_names(b"x");
    assert!(!names.contains(&"a".to_string()));
    assert!(names.contains(&"b".to_string()));
    assert!(names.contains(&"c".to_string()));
}

#[test]
fn test_cond_string_at_and_in() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Text("foo".into()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringAt("$a".into(), 4)),
    );
    let hits = s.scan(b"xxxxfoo");
    assert_eq!(hits.len(), 1);
    let s2 = YaraScanner::new();
    s2.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Text("foo".into()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringIn("$a".into(), 0, 10)),
    );
    assert!(!s2.scan(b"xxxxfoo").is_empty());
    let s3 = YaraScanner::new();
    s3.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Text("foo".into()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringIn("$a".into(), 0, 2)),
    );
    assert!(s3.scan(b"xxxxfoo").is_empty());
}

#[test]
fn test_cond_int_at_bounds() {
    let s = YaraScanner::new();
    s.add_rule(YaraRule::new("r".into()).with_condition(Condition::IntAt(0)));
    assert!(!s.scan(b"1234").is_empty());
    assert!(s.scan(b"123").is_empty());
    // overflow: u64::MAX -> usize::MAX, +4 overflows -> handled (returns false)
    let s2 = YaraScanner::new();
    s2.add_rule(YaraRule::new("r".into()).with_condition(Condition::IntAt(u64::MAX)));
    assert!(s2.scan(b"abcdef").is_empty());
}

#[test]
fn test_cond_forall_empty_strings_vacuous_true() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_condition(Condition::ForAll(Box::new(Condition::True))),
    );
    assert!(!s.scan(b"x").is_empty());
}

#[test]
fn test_cond_any_all_none() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("a".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Text("hit".into()),
                modifiers: StringModifiers::NONE,
            })
            .with_string(YaraString {
                identifier: "$b".into(),
                value: StringValue::Text("miss".into()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::Any),
    );
    assert!(!s.scan(b"hit only").is_empty());
    let s2 = YaraScanner::new();
    s2.add_rule(
        YaraRule::new("a".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Text("hit".into()),
                modifiers: StringModifiers::NONE,
            })
            .with_string(YaraString {
                identifier: "$b".into(),
                value: StringValue::Text("nope".into()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::All),
    );
    assert!(s2.scan(b"hit only").is_empty());
}

// ── Display ──────────────────────────────────────────────────────────────────

#[test]
fn test_display_compop() {
    assert_eq!(format!("{}", CompOp::Eq), "==");
    assert_eq!(format!("{}", CompOp::Ne), "!=");
    assert_eq!(format!("{}", CompOp::Lt), "<");
    assert_eq!(format!("{}", CompOp::Le), "<=");
    assert_eq!(format!("{}", CompOp::Gt), ">");
    assert_eq!(format!("{}", CompOp::Ge), ">=");
}

#[test]
fn test_display_hex_token() {
    assert_eq!(format!("{}", HexToken::Byte(0xAB)), "AB");
    assert_eq!(format!("{}", HexToken::Wildcard), "??");
    assert_eq!(format!("{}", HexToken::MaskedByte(0xAB, 0xF0)), "AB&F0");
    assert_eq!(format!("{}", HexToken::Jump(1, Some(3))), "[1-3]");
    assert_eq!(format!("{}", HexToken::Jump(2, None)), "[2]");
    assert_eq!(format!("{}", HexToken::Alternative(vec![])), "(...)");
}

#[test]
fn test_display_meta_value() {
    assert_eq!(format!("{}", MetaValue::String("x".into())), "\"x\"");
    assert_eq!(format!("{}", MetaValue::Int(-5)), "-5");
    assert_eq!(format!("{}", MetaValue::Bool(true)), "true");
}

#[test]
fn test_display_string_match() {
    let m = StringMatch {
        identifier: "$a".into(),
        offset: 0x10,
        length: 3,
        matched_data: vec![1, 2, 3],
    };
    assert!(format!("{m}").contains("$a"));
    assert!(format!("{m}").contains("0x10"));
}

#[test]
fn test_display_rule_match() {
    let rm = RuleMatch {
        rule_name: "r".into(),
        namespace: "default".into(),
        tags: vec![],
        meta: HashMap::new(),
        string_matches: vec![],
    };
    let s = format!("{rm}");
    assert!(s.contains("rule=r"));
}

#[test]
fn test_display_yara_rule_and_string_and_value() {
    let ys = YaraString {
        identifier: "$a".into(),
        value: StringValue::Text("hi".into()),
        modifiers: StringModifiers::NONE,
    };
    assert!(format!("{ys}").contains("$a"));
    assert_eq!(format!("{}", StringValue::Text("h".into())), "\"h\"");
    assert_eq!(format!("{}", StringValue::Regex("x".into())), "/x/");
    let _ = format!("{}", StringValue::Hex(vec![HexToken::Byte(1)]));
    let r = YaraRule::new("foo".into());
    assert!(format!("{r}").contains("foo"));
}

#[test]
fn test_display_pattern_match_and_yara_match() {
    let pm = PatternMatch {
        identifier: "$a".into(),
        offset: 0x20,
        length: 4,
        data: vec![0; 4],
    };
    assert!(format!("{pm}").contains("$a"));
}

// ── Hash/Eq on StringModifiers (Copy + Eq + Hash) ────────────────────────────

#[test]
fn test_string_modifiers_hash_eq_pairs() {
    let mut set: std::collections::HashSet<StringModifiers> = std::collections::HashSet::new();
    let variants = [
        StringModifiers::NONE,
        StringModifiers::NOCASE,
        StringModifiers::WIDE,
        StringModifiers::ASCII,
        StringModifiers::FULLWORD,
        StringModifiers::PRIVATE,
        StringModifiers::BASE64,
        StringModifiers::NOCASE | StringModifiers::WIDE,
        StringModifiers::WIDE | StringModifiers::ASCII,
        StringModifiers::FULLWORD | StringModifiers::NOCASE,
    ];
    for v in variants {
        set.insert(v);
        set.insert(v);
    }
    assert_eq!(set.len(), variants.len());
    // 30+ pair consistency
    let mut g = lcg();
    for _ in 0..40 {
        let a = StringModifiers::from_bits_truncate((g() & 0x3F) as u16);
        let b = StringModifiers::from_bits_truncate((g() & 0x3F) as u16);
        let eq = a == b;
        // hash consistency: equal => same hash
        if eq {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h1 = DefaultHasher::new();
            let mut h2 = DefaultHasher::new();
            a.hash(&mut h1);
            b.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }
}

#[test]
fn test_compop_eq_pairs() {
    let ops = [CompOp::Eq, CompOp::Ne, CompOp::Lt, CompOp::Le, CompOp::Gt, CompOp::Ge];
    for (i, a) in ops.iter().enumerate() {
        for (j, b) in ops.iter().enumerate() {
            assert_eq!(a == b, i == j);
        }
    }
}

// ── YaraRuleDefinition ───────────────────────────────────────────────────────

#[test]
fn test_yara_rule_definition_parse_name() {
    let r = YaraRuleDefinition::new("id1", "rule MyRule { condition: true }");
    assert_eq!(r.name, "MyRule");
    assert_eq!(r.id, "id1");
}

#[test]
fn test_yara_rule_definition_parse_name_with_tags_and_brace() {
    assert_eq!(
        YaraRuleDefinition::parse_name_from_source("rule abc:tag { }").unwrap(),
        "abc"
    );
    assert_eq!(
        YaraRuleDefinition::parse_name_from_source("rule xyz{").unwrap(),
        "xyz"
    );
    assert!(YaraRuleDefinition::parse_name_from_source("no rule keyword").is_none());
    assert!(YaraRuleDefinition::parse_name_from_source("rule ").is_none());
}

#[test]
fn test_yara_rule_definition_no_name_falls_back_to_id() {
    let r = YaraRuleDefinition::new("fallback", "no rule keyword here");
    assert_eq!(r.name, "fallback");
}

#[test]
fn test_yara_rule_definition_builders() {
    let r = YaraRuleDefinition::new("i", "rule a { condition: true }")
        .with_namespace("ns")
        .with_tag("t1")
        .with_tag("t2")
        .with_meta("k", "v");
    assert_eq!(r.namespace, "ns");
    assert_eq!(r.tags, vec!["t1", "t2"]);
    assert_eq!(r.meta.get("k").map(std::string::String::as_str), Some("v"));
    assert!(format!("{r}").contains("id=i"));
}

// ── YaraRuleSet add_file / nonexistent ──────────────────────────────────────

#[test]
fn test_ruleset_add_file_nonexistent() {
    let mut rs = YaraRuleSet::new();
    let err = rs
        .add_file(std::path::Path::new("definitely_does_not_exist_xyz.yar"))
        .unwrap_err();
    matches!(err, YaraError::Io(_));
}

#[test]
fn test_ruleset_add_directory_nonexistent() {
    let mut rs = YaraRuleSet::new();
    let err = rs
        .add_directory(std::path::Path::new("definitely_no_such_dir_zzz"))
        .unwrap_err();
    matches!(err, YaraError::Io(_));
}

// ── Send + Sync threaded stress on YaraScanner ───────────────────────────────

#[test]
fn test_scanner_send_sync_threaded() {
    let scanner = Arc::new(YaraScanner::new());
    scanner.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Text("AAA".into()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$a".into())),
    );
    let mut handles = vec![];
    for t in 0..4 {
        let s = Arc::clone(&scanner);
        handles.push(thread::spawn(move || {
            let mut acc = 0usize;
            for i in 0..100 {
                let buf = if (t + i) % 2 == 0 { b"xxAAAyy" as &[u8] } else { b"zzz" };
                acc += s.scan(buf).len();
            }
            acc
        }));
    }
    let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert!(total > 0);
}

// ── round-trip / determinism ─────────────────────────────────────────────────

#[test]
fn test_scan_deterministic_50_inputs() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Text("MARK".into()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$a".into())),
    );
    let mut g = lcg();
    for i in 0..60 {
        let mut data = rand_bytes(&mut g, 200);
        let pos = (g() as usize) % (data.len() - 4);
        data[pos..pos + 4].copy_from_slice(b"MARK");
        let r1 = s.scan(&data);
        let r2 = s.scan(&data);
        assert_eq!(r1.len(), r2.len(), "iter {i}");
        assert!(!r1.is_empty());
    }
}

#[test]
fn test_scanner_fuzz_no_panic() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Hex(vec![
                    HexToken::Byte(0xCC),
                    HexToken::Wildcard,
                    HexToken::Jump(0, Some(2)),
                    HexToken::Byte(0xDD),
                ]),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$a".into())),
    );
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() as usize) % 300 + 1;
        let buf = rand_bytes(&mut g, n);
        let _ = s.scan(&buf);
    }
}

#[test]
fn test_serde_round_trip_yara_rule() {
    let r = YaraRule::new("foo".into())
        .with_tag("t".into())
        .with_meta("k".into(), MetaValue::Int(3))
        .with_string(YaraString {
            identifier: "$a".into(),
            value: StringValue::Text("abc".into()),
            modifiers: StringModifiers::NOCASE,
        })
        .with_condition(Condition::FileSize(CompOp::Gt, 100));
    let j = serde_json::to_string(&r).unwrap();
    let r2: YaraRule = serde_json::from_str(&j).unwrap();
    assert_eq!(r2.name, "foo");
    assert_eq!(r2.tags, vec!["t"]);
    assert_eq!(r2.strings.len(), 1);
    assert!(r2.strings[0].modifiers.contains(StringModifiers::NOCASE));
}

#[test]
fn test_serde_round_trip_string_modifiers() {
    let m = StringModifiers::NOCASE | StringModifiers::WIDE | StringModifiers::FULLWORD;
    let j = serde_json::to_string(&m).unwrap();
    let m2: StringModifiers = serde_json::from_str(&j).unwrap();
    assert_eq!(m, m2);
}

#[test]
fn test_scan_huge_pattern_truncated_data() {
    let s = YaraScanner::new();
    s.add_rule(
        YaraRule::new("r".into())
            .with_string(YaraString {
                identifier: "$a".into(),
                value: StringValue::Text("X".repeat(1000)),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$a".into())),
    );
    assert!(s.scan(b"short").is_empty());
    assert!(s.scan(&[]).is_empty());
}

#[test]
fn test_yara_error_io_from() {
    let e: YaraError = std::io::Error::other("x").into();
    matches!(e, YaraError::Io(_));
    let txt = format!("{e}");
    assert!(txt.contains("io error"));
}

#[test]
fn test_yara_error_display_variants() {
    let v = YaraError::ParseError { line: 5, message: "m".into() };
    assert!(format!("{v}").contains("line 5"));
    assert!(format!("{}", YaraError::CompileError("c".into())).contains("compile"));
    assert!(format!("{}", YaraError::RuleNotFound("n".into())).contains("not found"));
    assert!(format!("{}", YaraError::ScanError("s".into())).contains("scan"));
    assert!(format!("{}", YaraError::RegexError("r".into())).contains("regex"));
}

#[test]
fn test_scanner_multi_rules_independent() {
    let s = YaraScanner::new();
    for i in 0..10 {
        s.add_rule(
            YaraRule::new(format!("r{i}"))
                .with_string(YaraString {
                    identifier: "$a".into(),
                    value: StringValue::Text(format!("tok{i}")),
                    modifiers: StringModifiers::NONE,
                })
                .with_condition(Condition::StringMatch("$a".into())),
        );
    }
    assert_eq!(s.rule_count(), 10);
    let names = s.scan_names(b"tok3 and tok7");
    assert!(names.contains(&"r3".to_string()));
    assert!(names.contains(&"r7".to_string()));
    assert!(!names.contains(&"r1".to_string()));
}
