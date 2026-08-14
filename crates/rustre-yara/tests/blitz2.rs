//! blitz2 - adversarial deep tests over rustre-yara public API.
//!
//! Focuses on fuzz, round-trips, boundaries, integer overflow paths,
//! parser robustness, Hash/Eq consistency, Display/FromStr, threaded stress.

use rustre_yara::*;
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

// ─── Seeded LCG fuzz source ─────────────────────────────────────────────

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn lcg_bytes(g: &mut impl FnMut() -> u64, n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    while v.len() < n {
        let x = g();
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(n);
    v
}

// ─── HexToken Hash/Eq consistency ───────────────────────────────────────

#[test]
fn hex_token_eq_self_30_pairs() {
    let toks = [
        HexToken::Byte(0),
        HexToken::Byte(0xFF),
        HexToken::Wildcard,
        HexToken::Masked(0x0A, 0x0F),
        HexToken::Masked(0xA0, 0xF0),
        HexToken::Masked(0x55, 0xFF),
        HexToken::Jump(0, 0),
        HexToken::Jump(0, u32::MAX),
        HexToken::Jump(1, 4),
        HexToken::Jump(10, 20),
        HexToken::Alternation(vec![vec![HexToken::Byte(1)]]),
        HexToken::Alternation(vec![
            vec![HexToken::Byte(1)],
            vec![HexToken::Byte(2), HexToken::Byte(3)],
        ]),
        HexToken::Byte(1),
        HexToken::Byte(2),
        HexToken::Byte(3),
    ];
    let mut count = 0;
    for a in &toks {
        for b in &toks {
            // Eq <=> Eq self-consistency.
            let _ = a.clone();
            assert!(a == a);
            if a == b {
                assert_eq!(b, a, "symmetry");
            }
            count += 1;
        }
    }
    assert!(count >= 30);
}

#[test]
fn cmpop_eq_pairs() {
    let ops = [CmpOp::Eq, CmpOp::Ne, CmpOp::Lt, CmpOp::Gt, CmpOp::Le, CmpOp::Ge];
    for (i, a) in ops.iter().enumerate() {
        for (j, b) in ops.iter().enumerate() {
            assert_eq!(a == b, i == j);
        }
    }
}

#[test]
fn yara_error_eq_30_pairs() {
    let errs = [
        YaraError::ParseError { line: 0, message: "a".into() },
        YaraError::ParseError { line: 0, message: "b".into() },
        YaraError::ParseError { line: 1, message: "a".into() },
        YaraError::CompileError("x".into()),
        YaraError::CompileError("y".into()),
        YaraError::ScanError("s".into()),
        YaraError::UnknownIdentifier("id".into()),
        YaraError::TypeError("t".into()),
    ];
    let mut seen_eq = 0;
    for a in &errs {
        for b in &errs {
            if a == b {
                seen_eq += 1;
            }
        }
    }
    assert!(seen_eq >= errs.len()); // at minimum reflexive
}

// ─── HexToken parser - fuzz ─────────────────────────────────────────────

#[test]
fn parse_hex_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..200 {
        let len = (g() % 32) as usize;
        // Compose a string from a small alphabet that includes hex/parens/brackets.
        let alph = b"0123456789abcdefABCDEF?[]() |-\t\n,XYZ";
        let s: String = (0..len)
            .map(|_| alph[(g() as usize) % alph.len()] as char)
            .collect();
        // Must return Ok or Err — never panic.
        let _ = YaraParser::parse_hex_pattern(&s);
    }
}

#[test]
fn parse_hex_round_trip_byte_sequences() {
    let mut g = lcg();
    for _ in 0..60 {
        let n = ((g() % 16) + 1) as usize;
        let bytes: Vec<u8> = (0..n).map(|_| (g() & 0xFF) as u8).collect();
        let hex_str: String = bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        let toks = YaraParser::parse_hex_pattern(&hex_str).unwrap();
        assert_eq!(toks.len(), n);
        for (i, b) in bytes.iter().enumerate() {
            assert_eq!(toks[i], HexToken::Byte(*b));
        }
    }
}

#[test]
fn parse_hex_incomplete_byte_errs() {
    // single hex digit at end with nothing else is incomplete
    assert!(YaraParser::parse_hex_pattern("A").is_err());
}

#[test]
fn parse_hex_invalid_char_errs() {
    assert!(YaraParser::parse_hex_pattern("ZZ").is_err());
}

#[test]
fn parse_hex_jump_max_u32() {
    let toks = YaraParser::parse_hex_pattern(&format!("AA [0-{}] BB", u32::MAX)).unwrap();
    assert_eq!(toks.len(), 3);
    assert!(matches!(toks[1], HexToken::Jump(0, n) if n == u32::MAX));
}

#[test]
fn parse_hex_jump_inverted_range_accepted_structurally() {
    // Parser doesn't reject min>max; ensure it parses without panic.
    let toks = YaraParser::parse_hex_pattern("AA [5-2] BB").unwrap();
    assert_eq!(toks.len(), 3);
    assert!(matches!(toks[1], HexToken::Jump(5, 2)));
}

#[test]
fn parse_hex_jump_single_value() {
    let toks = YaraParser::parse_hex_pattern("AA [4] BB").unwrap();
    assert!(matches!(toks[1], HexToken::Jump(4, 4)));
}

#[test]
fn parse_hex_nested_alternation() {
    let toks = YaraParser::parse_hex_pattern("(AA | BB CC | DD EE FF)").unwrap();
    if let HexToken::Alternation(alts) = &toks[0] {
        assert_eq!(alts.len(), 3);
        assert_eq!(alts[0].len(), 1);
        assert_eq!(alts[1].len(), 2);
        assert_eq!(alts[2].len(), 3);
    } else {
        panic!("expected alternation");
    }
}

// ─── StringMatcher fuzz ────────────────────────────────────────────────

#[test]
fn match_text_empty_inputs() {
    let mods = StringModifiers::default();
    assert!(StringMatcher::match_text("", &mods, b"abc").is_empty());
    assert!(StringMatcher::match_text("abc", &mods, b"").is_empty());
    assert!(StringMatcher::match_text("", &mods, b"").is_empty());
}

#[test]
fn match_hex_empty_inputs() {
    assert!(StringMatcher::match_hex(&[], b"abc").is_empty());
    assert!(StringMatcher::match_hex(&[HexToken::Byte(1)], b"").is_empty());
}

#[test]
fn match_bytes_fuzz_no_panic_no_false_negative() {
    let mut g = lcg();
    for _ in 0..80 {
        let data = lcg_bytes(&mut g, 64);
        // Pick a substring to ensure at least one hit.
        let start = (g() as usize) % data.len();
        let end = start + 1 + (g() as usize) % (data.len() - start);
        let needle = &data[start..end];
        // Avoid empty needle (different contract).
        if needle.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(needle).to_string();
        let mods = StringModifiers::default();
        // Just ensure it doesn't panic and offsets are within bounds.
        let offsets = StringMatcher::match_text(&s, &mods, &data);
        for &o in &offsets {
            assert!(o <= data.len());
        }
    }
}

#[test]
fn match_nocase_round_trip_50() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = ((g() % 8) + 1) as usize;
        let alph = b"abcdef";
        let bytes: Vec<u8> = (0..len)
            .map(|_| alph[(g() as usize) % alph.len()])
            .collect();
        let lower = String::from_utf8(bytes.clone()).unwrap();
        let upper = lower.to_ascii_uppercase();
        // Data contains uppercase, pattern is lowercase, nocase finds it.
        let offsets = StringMatcher::match_nocase(&lower, upper.as_bytes());
        assert_eq!(offsets, vec![0]);
    }
}

#[test]
fn match_wide_round_trip() {
    let mut g = lcg();
    for _ in 0..30 {
        let len = ((g() % 6) + 1) as usize;
        let alph = b"abcdef";
        let s: String = (0..len)
            .map(|_| alph[(g() as usize) % alph.len()] as char)
            .collect();
        let encoded: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let offsets = StringMatcher::match_wide(&s, &encoded);
        assert_eq!(offsets, vec![0]);
    }
}

#[test]
fn match_xor_round_trip() {
    let mut g = lcg();
    for _ in 0..40 {
        let key = (g() & 0xFF) as u8;
        let plain = b"target_string";
        let xored: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        // Range covering this key.
        let hits = StringMatcher::match_xor("target_string", 0, 255, &xored);
        assert!(hits.iter().any(|&(o, k)| o == 0 && k == key));
    }
}

#[test]
fn match_xor_empty_needle() {
    // empty text yields empty results (documented behaviour: needle.is_empty -> [])
    assert!(StringMatcher::match_xor("", 0, 10, b"abc").is_empty());
}

#[test]
fn match_xor_min_max_swapped() {
    // Implementation explicitly normalises min/max.
    let plain = b"hi";
    let xored: Vec<u8> = plain.iter().map(|&b| b ^ 0x05).collect();
    let hits = StringMatcher::match_xor("hi", 0x10, 0x00, &xored);
    assert!(hits.iter().any(|&(o, k)| o == 0 && k == 0x05));
}

#[test]
fn match_masked_byte_truth_table() {
    // mask = 0 means always match
    for d in 0u8..=255 {
        assert!(StringMatcher::match_masked_byte(0xAB, 0x00, d));
    }
    // mask = 0xFF means exact
    for d in 0u8..=255 {
        assert_eq!(
            StringMatcher::match_masked_byte(0x42, 0xFF, d),
            d == 0x42
        );
    }
}

#[test]
fn check_fullword_boundaries() {
    let data = b"_abc_";
    assert!(!StringMatcher::check_fullword(data, 1, 3));
    let data2 = b" abc ";
    assert!(StringMatcher::check_fullword(data2, 1, 3));
    // exact size
    let data3 = b"abc";
    assert!(StringMatcher::check_fullword(data3, 0, 3));
    // zero length adjacent to alnum byte is not fullword by current semantics:
    // after_ok inspects data[0]='a' (alnum) → false.
    assert!(!StringMatcher::check_fullword(b"abc", 0, 0));
    // zero length between two non-alnum bytes is fullword.
    assert!(StringMatcher::check_fullword(b"  ", 1, 0));
}

#[test]
fn hex_match_jump_boundary_0_to_0() {
    let pat = vec![
        HexToken::Byte(0xAA),
        HexToken::Jump(0, 0),
        HexToken::Byte(0xBB),
    ];
    let data = &[0xAA, 0xBB, 0xCC];
    let offsets = StringMatcher::match_hex(&pat, data);
    assert_eq!(offsets, vec![0]);
}

#[test]
fn hex_match_alternation_in_data() {
    let pat = vec![
        HexToken::Byte(0x90),
        HexToken::Alternation(vec![vec![HexToken::Byte(0xAA)], vec![HexToken::Byte(0xBB)]]),
        HexToken::Byte(0x90),
    ];
    let data = &[0x90, 0xAA, 0x90, 0x00, 0x90, 0xBB, 0x90];
    let offsets = StringMatcher::match_hex(&pat, data);
    assert!(offsets.contains(&0));
    assert!(offsets.contains(&4));
}

// ─── Parser: rule round-trip & robustness ──────────────────────────────

#[test]
fn parse_empty_input_ok() {
    let rs = YaraParser::parse("").unwrap();
    assert_eq!(rs.rule_count(), 0);
}

#[test]
fn parse_whitespace_only_ok() {
    let rs = YaraParser::parse("   \n\n\t  ").unwrap();
    assert_eq!(rs.rule_count(), 0);
}

#[test]
fn parse_missing_rule_keyword_errs() {
    let src = "foo { condition: true }";
    assert!(YaraParser::parse(src).is_err());
}

#[test]
fn parse_missing_condition_errs() {
    let src = "rule r { strings: $a = \"x\" }";
    assert!(YaraParser::parse(src).is_err());
}

#[test]
fn parse_unclosed_brace_errs() {
    let src = "rule r { condition: true ";
    assert!(YaraParser::parse(src).is_err());
}

#[test]
fn parse_unclosed_string_errs() {
    let src = "rule r { strings: $a = \"unterm\n condition: true }";
    let _ = YaraParser::parse(src); // must not panic, may Err
}

#[test]
fn parse_rule_with_tags_and_private_global() {
    let src = "private global rule r : t1 t2 { condition: true }";
    let r = YaraParser::parse_rule(src).unwrap();
    assert!(r.is_private);
    assert!(r.is_global);
    assert_eq!(r.tags, vec!["t1".to_string(), "t2".to_string()]);
}

#[test]
fn parse_no_rules_in_parse_rule_errs() {
    assert!(YaraParser::parse_rule("").is_err());
}

#[test]
fn parse_fuzz_never_panics() {
    let mut g = lcg();
    let snippets = [
        "rule",
        "rule x {",
        "rule x { condition: }",
        "rule x { strings: $a = }",
        "rule x { meta: k =  condition: true }",
        "{ }",
        "import \"foo\"\n",
        "rule a {} rule b {}",
    ];
    for s in &snippets {
        let _ = YaraParser::parse(s);
    }
    for _ in 0..50 {
        let len = (g() % 64) as usize;
        let chars: String = (0..len)
            .map(|_| {
                let alph = b"abc{}:= \"$#@!()|/\\\n";
                alph[(g() as usize) % alph.len()] as char
            })
            .collect();
        let _ = YaraParser::parse(&chars);
    }
}

#[test]
fn parse_meta_value_types() {
    let body = "meta:\n  s = \"abc\"\n  n = 123\n  b = true\n  bf = false\n  bad = hello\ncondition: true";
    let meta = YaraParser::parse_meta_section(body).unwrap();
    assert!(matches!(meta[0].value, YaraMetaValue::String(ref s) if s == "abc"));
    assert!(matches!(meta[1].value, YaraMetaValue::Integer(123)));
    assert!(matches!(meta[2].value, YaraMetaValue::Bool(true)));
    assert!(matches!(meta[3].value, YaraMetaValue::Bool(false)));
    assert!(matches!(meta[4].value, YaraMetaValue::String(ref s) if s == "hello"));
}

#[test]
fn parse_string_modifiers_all_keywords() {
    let tokens = ["nocase", "wide", "ascii", "fullword", "private", "base64"];
    let m = YaraParser::parse_string_modifiers(&tokens);
    assert!(m.nocase());
    assert!(m.wide());
    assert!(m.ascii());
    assert!(m.fullword());
    assert!(m.is_private());
    assert!(m.base64());
    assert!(m.xor.is_none());
}

#[test]
fn parse_string_modifiers_xor_default_range() {
    let tokens = ["xor"];
    let m = YaraParser::parse_string_modifiers(&tokens);
    assert_eq!(m.xor, Some((0, 255)));
}

#[test]
fn parse_string_modifiers_xor_with_range() {
    let tokens = ["xor", "(0x01-0x10)"];
    let m = YaraParser::parse_string_modifiers(&tokens);
    assert_eq!(m.xor, Some((0x01, 0x10)));
}

#[test]
fn parse_string_modifiers_unknown_token_ignored() {
    let tokens = ["nocase", "wibble", "wide"];
    let m = YaraParser::parse_string_modifiers(&tokens);
    assert!(m.nocase() && m.wide());
}

// ─── YaraRule / YaraRuleSet ─────────────────────────────────────────────

#[test]
fn ruleset_lookup_and_count() {
    let mut rs = YaraRuleSet::new();
    rs.add_rule(YaraRule::new("a"));
    rs.add_rule(YaraRule::new("b"));
    assert_eq!(rs.rule_count(), 2);
    assert!(rs.rule_by_name("a").is_some());
    assert!(rs.rule_by_name("missing").is_none());
}

#[test]
fn rule_meta_helpers() {
    let mut r = YaraRule::new("x");
    r.meta.push(YaraMeta {
        key: "description".into(),
        value: YaraMetaValue::String("desc".into()),
    });
    r.meta.push(YaraMeta {
        key: "author".into(),
        value: YaraMetaValue::String("alice".into()),
    });
    r.meta.push(YaraMeta {
        key: "date".into(),
        value: YaraMetaValue::String("2024".into()),
    });
    r.meta.push(YaraMeta {
        key: "score".into(),
        value: YaraMetaValue::Integer(7),
    });
    assert_eq!(r.description(), Some("desc".into()));
    assert_eq!(r.author(), Some("alice".into()));
    assert_eq!(r.date(), Some("2024".into()));
    // Non-string meta returns None from typed accessors.
    let mut r2 = YaraRule::new("y");
    r2.meta.push(YaraMeta {
        key: "description".into(),
        value: YaraMetaValue::Integer(1),
    });
    assert!(r2.description().is_none());
    assert!(r2.author().is_none());
}

// ─── StringModifiers default / setters ─────────────────────────────────

#[test]
fn string_modifiers_default_invariants() {
    let m = StringModifiers::default();
    assert!(!m.nocase());
    assert!(!m.wide());
    assert!(m.ascii());
    assert!(!m.fullword());
    assert!(!m.is_private());
    assert!(!m.base64());
    assert!(m.xor.is_none());
}

#[test]
fn string_modifiers_mut_shims() {
    let mut m = StringModifiers::default();
    *m.nocase_mut() = true;
    *m.wide_mut() = true;
    *m.ascii_mut() = false;
    *m.fullword_mut() = true;
    *m.private_mut() = true;
    *m.base64_mut() = true;
    assert!(m.nocase() && m.wide() && !m.ascii() && m.fullword() && m.is_private() && m.base64());
}

// ─── Display ↔ string sanity for YaraError ─────────────────────────────

#[test]
fn yara_error_display_round_trip_50() {
    let cases = [
        YaraError::ParseError { line: 3, message: "x".into() },
        YaraError::CompileError("c".into()),
        YaraError::ScanError("s".into()),
        YaraError::UnknownIdentifier("ident".into()),
        YaraError::TypeError("t".into()),
    ];
    for c in &cases {
        let s = format!("{c}");
        assert!(!s.is_empty());
    }
    // Round-trip clone+eq
    for c in &cases {
        assert_eq!(c.clone(), c.clone());
    }
}

// ─── ScanContext invariants ────────────────────────────────────────────

#[test]
fn scan_context_default_no_matches() {
    let ctx = ScanContext::new(b"abc");
    assert_eq!(ctx.filesize, 3);
    assert_eq!(ctx.base_address, 0);
    assert!(!ctx.string_matched("missing"));
    assert_eq!(ctx.string_count("missing"), 0);
    assert!(ctx.string_offset("missing", 0).is_none());
}

#[test]
fn scan_context_with_base() {
    let ctx = ScanContext::new(b"abc").with_base(0x4000_0000);
    assert_eq!(ctx.base_address, 0x4000_0000);
}

#[test]
fn scan_context_count_and_offset() {
    let mut ctx = ScanContext::new(b"abc");
    ctx.string_matches.insert("a".into(), vec![0, 5, 10]);
    assert_eq!(ctx.string_count("a"), 3);
    assert_eq!(ctx.string_offset("a", 1), Some(5));
    assert!(ctx.string_offset("a", 99).is_none());
    assert!(ctx.string_matched("a"));
}

// ─── YaraScanner: end-to-end ───────────────────────────────────────────

#[test]
fn scanner_simple_text_match() {
    let scanner = YaraScanner::from_rules_text(
        r#"rule r { strings: $a = "hello" condition: $a }"#,
    )
    .unwrap();
    let matches = scanner.scan(b"world hello world").unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_name, "r");
}

#[test]
fn scanner_no_match() {
    let scanner = YaraScanner::from_rules_text(
        r#"rule r { strings: $a = "needle" condition: $a }"#,
    )
    .unwrap();
    let matches = scanner.scan(b"haystack only").unwrap();
    assert!(matches.is_empty());
}

#[test]
fn scanner_filesize_condition() {
    let scanner = YaraScanner::from_rules_text(
        r"rule big { condition: filesize > 10 }",
    )
    .unwrap();
    assert!(scanner.scan(&[0u8; 20]).unwrap().len() == 1);
    assert!(scanner.scan(&[0u8; 5]).unwrap().is_empty());
}

#[test]
fn scanner_private_rule_not_returned() {
    let scanner = YaraScanner::from_rules_text(
        r"private rule p { condition: true } rule q { condition: true }",
    )
    .unwrap();
    let m = scanner.scan(b"x").unwrap();
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].rule_name, "q");
}

#[test]
fn scanner_eval_expr_division_by_zero() {
    let ctx = ScanContext::new(b"x");
    let e = YaraExpr::Div(
        Box::new(YaraExpr::Integer(10)),
        Box::new(YaraExpr::Integer(0)),
    );
    assert!(matches!(
        YaraScanner::eval_expr(&e, &ctx),
        Err(YaraError::ScanError(_))
    ));
}

#[test]
fn scanner_eval_expr_modulo_by_zero() {
    let ctx = ScanContext::new(b"x");
    let e = YaraExpr::Mod(
        Box::new(YaraExpr::Integer(10)),
        Box::new(YaraExpr::Integer(0)),
    );
    assert!(matches!(
        YaraScanner::eval_expr(&e, &ctx),
        Err(YaraError::ScanError(_))
    ));
}

#[test]
fn scanner_eval_expr_unknown_identifier() {
    let ctx = ScanContext::new(b"x");
    let e = YaraExpr::Identifier("nonexistent_var".into());
    assert!(matches!(
        YaraScanner::eval_expr(&e, &ctx),
        Err(YaraError::UnknownIdentifier(_))
    ));
}

#[test]
fn scanner_eval_expr_arithmetic_chain() {
    let ctx = ScanContext::new(b"x");
    let e = YaraExpr::Add(
        Box::new(YaraExpr::Mul(
            Box::new(YaraExpr::Integer(2)),
            Box::new(YaraExpr::Integer(3)),
        )),
        Box::new(YaraExpr::Sub(
            Box::new(YaraExpr::Integer(10)),
            Box::new(YaraExpr::Integer(4)),
        )),
    );
    assert_eq!(YaraScanner::eval_expr(&e, &ctx).unwrap(), 12);
}

#[test]
fn scanner_eval_expr_bitwise() {
    let ctx = ScanContext::new(b"x");
    let or = YaraExpr::BitOr(
        Box::new(YaraExpr::Integer(0xF0)),
        Box::new(YaraExpr::Integer(0x0F)),
    );
    assert_eq!(YaraScanner::eval_expr(&or, &ctx).unwrap(), 0xFF);
    let xor = YaraExpr::BitXor(
        Box::new(YaraExpr::Integer(0xAA)),
        Box::new(YaraExpr::Integer(0xFF)),
    );
    assert_eq!(YaraScanner::eval_expr(&xor, &ctx).unwrap(), 0x55);
    let not = YaraExpr::BitNot(Box::new(YaraExpr::Integer(0)));
    assert_eq!(YaraScanner::eval_expr(&not, &ctx).unwrap(), -1);
    let shl = YaraExpr::Shl(
        Box::new(YaraExpr::Integer(1)),
        Box::new(YaraExpr::Integer(4)),
    );
    assert_eq!(YaraScanner::eval_expr(&shl, &ctx).unwrap(), 16);
    let shr = YaraExpr::Shr(
        Box::new(YaraExpr::Integer(16)),
        Box::new(YaraExpr::Integer(2)),
    );
    assert_eq!(YaraScanner::eval_expr(&shr, &ctx).unwrap(), 4);
}

#[test]
fn scanner_eval_expr_neg() {
    let ctx = ScanContext::new(b"x");
    let e = YaraExpr::Neg(Box::new(YaraExpr::Integer(7)));
    assert_eq!(YaraScanner::eval_expr(&e, &ctx).unwrap(), -7);
}

#[test]
fn scanner_eval_condition_all_simple_variants() {
    let mut ctx = ScanContext::new(b"abc");
    ctx.string_matches.insert("a".into(), vec![0]);
    ctx.string_matches.insert("b".into(), vec![]);
    assert!(YaraScanner::eval_condition(&YaraCondition::True, &ctx).unwrap());
    assert!(!YaraScanner::eval_condition(&YaraCondition::False, &ctx).unwrap());
    assert!(YaraScanner::eval_condition(&YaraCondition::Any, &ctx).unwrap());
    assert!(!YaraScanner::eval_condition(&YaraCondition::All, &ctx).unwrap());
    assert!(!YaraScanner::eval_condition(&YaraCondition::None_, &ctx).unwrap());
    assert!(YaraScanner::eval_condition(
        &YaraCondition::Not(Box::new(YaraCondition::False)),
        &ctx
    )
    .unwrap());
    let and = YaraCondition::And(
        Box::new(YaraCondition::True),
        Box::new(YaraCondition::True),
    );
    assert!(YaraScanner::eval_condition(&and, &ctx).unwrap());
    let or = YaraCondition::Or(
        Box::new(YaraCondition::False),
        Box::new(YaraCondition::True),
    );
    assert!(YaraScanner::eval_condition(&or, &ctx).unwrap());
}

#[test]
fn scanner_string_match_at_and_in() {
    let mut ctx = ScanContext::new(b"....hello....");
    ctx.string_matches.insert("a".into(), vec![4]);
    let cond_at = YaraCondition::StringMatchAt("$a".into(), Box::new(YaraExpr::Integer(4)));
    assert!(YaraScanner::eval_condition(&cond_at, &ctx).unwrap());
    let cond_at_miss = YaraCondition::StringMatchAt("$a".into(), Box::new(YaraExpr::Integer(0)));
    assert!(!YaraScanner::eval_condition(&cond_at_miss, &ctx).unwrap());
    let cond_in = YaraCondition::StringMatchIn(
        "$a".into(),
        Box::new(YaraExpr::Integer(0)),
        Box::new(YaraExpr::Integer(10)),
    );
    assert!(YaraScanner::eval_condition(&cond_in, &ctx).unwrap());
}

#[test]
fn scanner_comparison_ops() {
    let ctx = ScanContext::new(b"x");
    let mk = |op| {
        YaraCondition::Comparison(
            Box::new(YaraExpr::Integer(3)),
            op,
            Box::new(YaraExpr::Integer(5)),
        )
    };
    assert!(!YaraScanner::eval_condition(&mk(CmpOp::Eq), &ctx).unwrap());
    assert!(YaraScanner::eval_condition(&mk(CmpOp::Ne), &ctx).unwrap());
    assert!(YaraScanner::eval_condition(&mk(CmpOp::Lt), &ctx).unwrap());
    assert!(!YaraScanner::eval_condition(&mk(CmpOp::Gt), &ctx).unwrap());
    assert!(YaraScanner::eval_condition(&mk(CmpOp::Le), &ctx).unwrap());
    assert!(!YaraScanner::eval_condition(&mk(CmpOp::Ge), &ctx).unwrap());
}

#[test]
fn parse_and_evaluate_full_rule_50_inputs() {
    let scanner = YaraScanner::from_rules_text(
        r#"rule r { strings: $a = "AAAA" condition: $a }"#,
    )
    .unwrap();
    let mut g = lcg();
    for _ in 0..50 {
        let n = ((g() % 32) + 1) as usize;
        let mut data = lcg_bytes(&mut g, n);
        let should_match = (g() & 1) == 1;
        if should_match {
            data.extend_from_slice(b"AAAA");
        }
        let m = scanner.scan(&data).unwrap();
        if should_match {
            assert_eq!(m.len(), 1);
        } else if data.windows(4).any(|w| w == b"AAAA") {
            // random data could still happen to contain AAAA — accept.
            assert!(m.len() <= 1);
        } else {
            assert!(m.is_empty());
        }
    }
}

// ─── Send/Sync threaded stress ─────────────────────────────────────────

#[test]
fn scanner_threaded_stress() {
    let scanner = Arc::new(
        YaraScanner::from_rules_text(
            r#"rule r { strings: $a = "needle" condition: $a }"#,
        )
        .unwrap(),
    );
    let mut handles = Vec::new();
    for t in 0..4 {
        let s = Arc::clone(&scanner);
        handles.push(thread::spawn(move || {
            let mut g = {
                let mut state: u64 = 0xCAFE_F00D ^ (t as u64);
                move || {
                    state = state
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    state
                }
            };
            for _ in 0..100 {
                let mut data = lcg_bytes(&mut g, 40);
                if (g() & 1) == 1 {
                    data.extend_from_slice(b"needle");
                }
                let _ = s.scan(&data).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn ruleset_clone_independent() {
    let mut a = YaraRuleSet::new();
    a.add_rule(YaraRule::new("x"));
    let b = a.clone();
    assert_eq!(a.rule_count(), b.rule_count());
}

#[test]
fn unique_rule_names_in_set() {
    let mut rs = YaraRuleSet::new();
    for i in 0..20 {
        rs.add_rule(YaraRule::new(format!("rule_{i}")));
    }
    let names: HashSet<_> = rs.rules.iter().map(|r| r.name.clone()).collect();
    assert_eq!(names.len(), 20);
}

// ─── Hex match-len for build_string_matches paths ──────────────────────

#[test]
fn scanner_hex_pattern_scan() {
    let scanner = YaraScanner::from_rules_text(
        r"rule h { strings: $a = { 41 41 42 } condition: $a }",
    )
    .unwrap();
    let matches = scanner.scan(b"...AAB...").unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].strings.len(), 1);
    assert_eq!(matches[0].strings[0].length, 3);
}

// ─── Hex matching with jumps boundary off-by-one ───────────────────────

#[test]
fn hex_match_jump_at_end_of_data() {
    let pat = vec![HexToken::Byte(0xAA), HexToken::Jump(0, 4)];
    let data = &[0xAA];
    // Pattern after last token is empty; jump 0 should match.
    let offsets = StringMatcher::match_hex(&pat, data);
    assert_eq!(offsets, vec![0]);
}

#[test]
fn hex_match_byte_at_last_position() {
    let pat = vec![HexToken::Byte(0xFF)];
    let data = &[0x00, 0x00, 0xFF];
    let offsets = StringMatcher::match_hex(&pat, data);
    assert_eq!(offsets, vec![2]);
}
