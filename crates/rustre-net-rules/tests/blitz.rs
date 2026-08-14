//! Exhaustive smoke tests for `rustre-net-rules` core APIs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rustre_net::TcpFlags;
use rustre_net_rules::{
    AhoCorasick, CompiledRuleSet, Condition, FlowbitOp, FlowbitStore, IpSpec, MatchResult,
    NetworkSpec, PacketContext, PortSpec, Proto, Rule, RuleAction, RuleEngine, RuleError,
    RuleParser, RuleStore, VarTable, builtin_catalogue, export_rules_json, export_rules_snort,
    find_bytes_nocase, import_rules_json,
};

const fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn pkt_tcp(src: IpAddr, dst: IpAddr, sp: u16, dp: u16, payload: &[u8]) -> PacketContext {
    PacketContext {
        src_ip: src,
        dst_ip: dst,
        src_port: sp,
        dst_port: dp,
        ip_proto: 6,
        ttl: 64,
        payload: payload.to_vec(),
        tcp_flags: TcpFlags::SYN | TcpFlags::ACK,
    }
}

// ─── IpSpec ─────────────────────────────────────────────────────────────────

#[test]
fn ipspec_any_matches_everything() {
    assert!(IpSpec::Any.matches(v4(0, 0, 0, 0)));
    assert!(IpSpec::Any.matches(v4(255, 255, 255, 255)));
    assert!(IpSpec::Any.matches(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
}

#[test]
fn ipspec_single_exact() {
    let s = IpSpec::Single(v4(10, 0, 0, 1));
    assert!(s.matches(v4(10, 0, 0, 1)));
    assert!(!s.matches(v4(10, 0, 0, 2)));
}

#[test]
fn ipspec_range_boundaries() {
    let s = IpSpec::Range(v4(10, 0, 0, 5), v4(10, 0, 0, 10));
    assert!(s.matches(v4(10, 0, 0, 5)));
    assert!(s.matches(v4(10, 0, 0, 10)));
    assert!(s.matches(v4(10, 0, 0, 7)));
    assert!(!s.matches(v4(10, 0, 0, 4)));
    assert!(!s.matches(v4(10, 0, 0, 11)));
}

#[test]
fn ipspec_cidr_v4_prefix_0_matches_all() {
    let s = IpSpec::Cidr(v4(0, 0, 0, 0), 0);
    assert!(s.matches(v4(8, 8, 8, 8)));
    assert!(s.matches(v4(192, 168, 1, 1)));
}

#[test]
fn ipspec_cidr_v4_full_prefix_32() {
    let s = IpSpec::Cidr(v4(10, 1, 2, 3), 32);
    assert!(s.matches(v4(10, 1, 2, 3)));
    assert!(!s.matches(v4(10, 1, 2, 4)));
}

#[test]
fn ipspec_cidr_v4_invalid_prefix_above_32() {
    let s = IpSpec::Cidr(v4(10, 0, 0, 0), 33);
    assert!(!s.matches(v4(10, 0, 0, 1)));
}

#[test]
fn ipspec_cidr_v4_subnet_match() {
    let s = IpSpec::Cidr(v4(192, 168, 1, 0), 24);
    assert!(s.matches(v4(192, 168, 1, 1)));
    assert!(s.matches(v4(192, 168, 1, 254)));
    assert!(!s.matches(v4(192, 168, 2, 1)));
}

#[test]
fn ipspec_cidr_v6_prefix_0_and_full() {
    let s0 = IpSpec::Cidr(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    assert!(s0.matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    let s_full = IpSpec::Cidr(IpAddr::V6(Ipv6Addr::LOCALHOST), 128);
    assert!(s_full.matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(!s_full.matches(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
}

#[test]
fn ipspec_cidr_mixed_v4_v6_never_matches() {
    let s = IpSpec::Cidr(v4(10, 0, 0, 0), 8);
    assert!(!s.matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

#[test]
fn ipspec_group_any_matches() {
    let s = IpSpec::Group(vec![
        IpSpec::Single(v4(1, 2, 3, 4)),
        IpSpec::Cidr(v4(10, 0, 0, 0), 8),
    ]);
    assert!(s.matches(v4(1, 2, 3, 4)));
    assert!(s.matches(v4(10, 99, 99, 99)));
    assert!(!s.matches(v4(8, 8, 8, 8)));
}

#[test]
fn ipspec_not_inverts() {
    let s = IpSpec::Not(Box::new(IpSpec::Single(v4(1, 1, 1, 1))));
    assert!(s.matches(v4(2, 2, 2, 2)));
    assert!(!s.matches(v4(1, 1, 1, 1)));
}

// ─── PortSpec ───────────────────────────────────────────────────────────────

#[test]
fn portspec_any() {
    assert!(PortSpec::Any.matches(0));
    assert!(PortSpec::Any.matches(65535));
}

#[test]
fn portspec_single() {
    let s = PortSpec::Single(80);
    assert!(s.matches(80));
    assert!(!s.matches(81));
}

#[test]
fn portspec_range_boundaries() {
    let s = PortSpec::Range(100, 200);
    assert!(s.matches(100));
    assert!(s.matches(200));
    assert!(s.matches(150));
    assert!(!s.matches(99));
    assert!(!s.matches(201));
}

#[test]
fn portspec_list_membership() {
    let s = PortSpec::List(vec![22, 80, 443]);
    assert!(s.matches(22));
    assert!(s.matches(443));
    assert!(!s.matches(8080));
}

#[test]
fn portspec_not_inverts() {
    let s = PortSpec::Not(Box::new(PortSpec::Single(80)));
    assert!(!s.matches(80));
    assert!(s.matches(81));
}

#[test]
fn portspec_boundaries_zero_and_max() {
    assert!(PortSpec::Single(0).matches(0));
    assert!(PortSpec::Single(u16::MAX).matches(u16::MAX));
    assert!(PortSpec::Range(0, u16::MAX).matches(12345));
}

// ─── NetworkSpec ────────────────────────────────────────────────────────────

#[test]
fn networkspec_any_matches_all() {
    let n = NetworkSpec::any();
    assert!(n.matches(v4(1, 2, 3, 4), 1234));
}

#[test]
fn networkspec_requires_both() {
    let n = NetworkSpec {
        addr: IpSpec::Single(v4(10, 0, 0, 1)),
        port: PortSpec::Single(80),
    };
    assert!(n.matches(v4(10, 0, 0, 1), 80));
    assert!(!n.matches(v4(10, 0, 0, 1), 81));
    assert!(!n.matches(v4(10, 0, 0, 2), 80));
}

// ─── RuleEngine ─────────────────────────────────────────────────────────────

#[test]
fn engine_evaluate_returns_match() {
    let e = RuleEngine::new();
    let r = Rule::new(
        42,
        RuleAction::Alert,
        Proto::Tcp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "hi",
    );
    e.add_rule(r);
    let ctx = pkt_tcp(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, b"data");
    let m = e.evaluate(&ctx).expect("should match");
    assert_eq!(m.rule_id, 42);
    assert_eq!(m.action, RuleAction::Alert);
    assert!(m.matched);
}

#[test]
fn engine_proto_mismatch_skips() {
    let e = RuleEngine::new();
    e.add_rule(Rule::new(
        1,
        RuleAction::Alert,
        Proto::Udp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "u",
    ));
    let ctx = pkt_tcp(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, b"x");
    assert!(e.evaluate(&ctx).is_none());
}

#[test]
fn engine_disabled_rule_skipped() {
    let e = RuleEngine::new();
    let mut r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Any,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "d",
    );
    r.enabled = false;
    e.add_rule(r);
    let ctx = pkt_tcp(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, b"x");
    assert!(e.evaluate(&ctx).is_none());
}

#[test]
fn engine_remove_rule() {
    let e = RuleEngine::new();
    e.add_rule(Rule::new(
        7,
        RuleAction::Drop,
        Proto::Any,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "",
    ));
    assert_eq!(e.rules().len(), 1);
    e.remove_rule(7);
    assert_eq!(e.rules().len(), 0);
}

#[test]
fn engine_evaluate_all_returns_all_matches() {
    let e = RuleEngine::new();
    for id in 1..=3u32 {
        e.add_rule(Rule::new(
            id,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "",
        ));
    }
    let ctx = pkt_tcp(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, b"x");
    let all: Vec<MatchResult> = e.evaluate_all(&ctx);
    assert_eq!(all.len(), 3);
}

#[test]
fn engine_content_match() {
    let e = RuleEngine::new();
    let mut r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Any,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "c",
    );
    r.conditions.push(Condition::Content(b"evil".to_vec()));
    e.add_rule(r);
    let ctx = pkt_tcp(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, b"hello evil world");
    assert!(e.evaluate(&ctx).is_some());
    let ctx2 = pkt_tcp(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, b"hello world");
    assert!(e.evaluate(&ctx2).is_none());
}

#[test]
fn engine_dsize_bounds() {
    let e = RuleEngine::new();
    let mut r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Any,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "",
    );
    r.conditions.push(Condition::DSize { min: 5, max: 10 });
    e.add_rule(r);
    let small = pkt_tcp(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, b"abcd");
    let mid = pkt_tcp(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, b"abcdefg");
    let big = pkt_tcp(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, b"abcdefghijk");
    assert!(e.evaluate(&small).is_none());
    assert!(e.evaluate(&mid).is_some());
    assert!(e.evaluate(&big).is_none());
}

#[test]
fn engine_ttl_match() {
    let e = RuleEngine::new();
    let mut r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Any,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "",
    );
    r.conditions.push(Condition::Ttl(64));
    e.add_rule(r);
    let ctx = pkt_tcp(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, b"");
    assert!(e.evaluate(&ctx).is_some());
}

#[test]
fn engine_pcre_invalid_regex_is_non_match() {
    let e = RuleEngine::new();
    let mut r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Any,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "",
    );
    r.conditions.push(Condition::Pcre("[invalid(".to_string()));
    e.add_rule(r);
    let ctx = pkt_tcp(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, b"anything");
    assert!(e.evaluate(&ctx).is_none());
}

#[test]
fn engine_pcre_valid_match() {
    let e = RuleEngine::new();
    let mut r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Any,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "",
    );
    r.conditions.push(Condition::Pcre("ev.l".to_string()));
    e.add_rule(r);
    let ctx = pkt_tcp(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, b"evil");
    assert!(e.evaluate(&ctx).is_some());
}

// ─── RuleParser ─────────────────────────────────────────────────────────────

#[test]
fn parser_basic_alert() {
    let s = r#"alert tcp any any -> any 80 (msg:"hi"; content:"GET"; sid:1001;)"#;
    let r = RuleParser::parse(s).expect("parse");
    assert_eq!(r.id, 1001);
    assert_eq!(r.action, RuleAction::Alert);
    assert_eq!(r.proto, Proto::Tcp);
    assert_eq!(r.msg, "hi");
    assert_eq!(r.conditions.len(), 1);
}

#[test]
fn parser_empty_input_errors() {
    let e = RuleParser::parse("").unwrap_err();
    assert!(matches!(e, RuleError::ParseError { .. }));
}

#[test]
fn parser_comment_errors() {
    let e = RuleParser::parse("# a comment").unwrap_err();
    assert!(matches!(e, RuleError::ParseError { .. }));
}

#[test]
fn parser_missing_paren_errors() {
    let e = RuleParser::parse("alert tcp any any -> any 80 msg only").unwrap_err();
    assert!(matches!(e, RuleError::ParseError { .. }));
}

#[test]
fn parser_unknown_action_errors() {
    let r = RuleParser::parse(r"frobnicate tcp any any -> any 80 (sid:1;)");
    assert!(matches!(r, Err(RuleError::ParseError { .. })));
}

#[test]
fn parser_unknown_proto_errors() {
    let r = RuleParser::parse(r"alert quux any any -> any 80 (sid:1;)");
    assert!(matches!(r, Err(RuleError::ParseError { .. })));
}

#[test]
fn parser_cidr_ip() {
    let r =
        RuleParser::parse(r"alert tcp 192.168.1.0/24 any -> any any (sid:1;)").expect("parse");
    assert!(matches!(r.src.addr, IpSpec::Cidr(_, 24)));
}

#[test]
fn parser_port_range() {
    let r = RuleParser::parse(r"alert tcp any any -> any 1000:2000 (sid:1;)").expect("parse");
    assert!(matches!(r.dst.port, PortSpec::Range(1000, 2000)));
}

#[test]
fn parser_port_list() {
    let r = RuleParser::parse(r"alert tcp any any -> any [80,443,8080] (sid:1;)").expect("parse");
    match r.dst.port {
        PortSpec::List(ref v) => assert_eq!(v, &vec![80u16, 443, 8080]),
        _ => panic!("expected list"),
    }
}

#[test]
fn parser_port_not() {
    let r = RuleParser::parse(r"alert tcp any any -> any !80 (sid:1;)").expect("parse");
    assert!(matches!(r.dst.port, PortSpec::Not(_)));
}

#[test]
fn parser_hex_content() {
    let r = RuleParser::parse(r"alert tcp any any -> any any (content:|DE AD BE EF|; sid:1;)")
        .expect("parse");
    match &r.conditions[0] {
        Condition::Content(b) => assert_eq!(b, &vec![0xDE, 0xAD, 0xBE, 0xEF]),
        _ => panic!("expected content"),
    }
}

#[test]
fn parser_dsize_range_format() {
    let r =
        RuleParser::parse(r"alert tcp any any -> any any (dsize:100<>200; sid:1;)").expect("p");
    match r.conditions[0] {
        Condition::DSize { min, max } => {
            assert_eq!(min, 100);
            assert_eq!(max, 200);
        }
        _ => panic!(),
    }
}

#[test]
fn parser_dsize_exact() {
    let r = RuleParser::parse(r"alert tcp any any -> any any (dsize:512; sid:1;)").expect("p");
    match r.conditions[0] {
        Condition::DSize { min, max } => assert_eq!((min, max), (512, 512)),
        _ => panic!(),
    }
}

#[test]
fn parser_dsize_gt() {
    let r = RuleParser::parse(r"alert tcp any any -> any any (dsize:>1000; sid:1;)").expect("p");
    match r.conditions[0] {
        Condition::DSize { min, max } => {
            assert_eq!(min, 1000);
            assert_eq!(max, u32::MAX);
        }
        _ => panic!(),
    }
}

#[test]
fn parser_parse_many_skips_comments_and_blanks() {
    let input = "# header\n\nalert tcp any any -> any 80 (sid:1;)\n# end\n";
    let results = RuleParser::parse_many(input);
    assert_eq!(results.len(), 1);
    assert!(results[0].is_ok());
}

#[test]
fn parser_var_ip_becomes_any() {
    let r = RuleParser::parse(r"alert tcp $HOME_NET any -> any 80 (sid:1;)").expect("p");
    assert!(matches!(r.src.addr, IpSpec::Any));
}

#[test]
fn parser_flags_condition() {
    let r =
        RuleParser::parse(r"alert tcp any any -> any any (flags:SA; sid:1;)").expect("p");
    match r.conditions[0] {
        Condition::Flags(f) => assert_eq!(f, TcpFlags::SYN | TcpFlags::ACK),
        _ => panic!(),
    }
}

// ─── Display ────────────────────────────────────────────────────────────────

#[test]
fn display_action_proto() {
    assert_eq!(format!("{}", RuleAction::Alert), "alert");
    assert_eq!(format!("{}", RuleAction::Drop), "drop");
    assert_eq!(format!("{}", Proto::Tcp), "tcp");
    assert_eq!(format!("{}", Proto::Any), "any");
}

// ─── AhoCorasick ────────────────────────────────────────────────────────────

#[test]
fn ac_empty_patterns_no_match() {
    let ac = AhoCorasick::build(&[]);
    assert!(ac.find_all(b"hello").is_empty());
    assert!(ac.find_first(b"hello").is_none());
    assert!(!ac.contains_any(b"hello"));
}

#[test]
fn ac_single_pattern_match() {
    let pats: &[&[u8]] = &[b"abc"];
    let ac = AhoCorasick::build(pats);
    let matches = ac.find_all(b"xxabcxx");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].start, 2);
    assert_eq!(matches[0].end, 5);
    assert_eq!(matches[0].pattern_idx, 0);
}

#[test]
fn ac_multiple_patterns_overlap() {
    let pats: &[&[u8]] = &[b"he", b"she", b"his", b"hers"];
    let ac = AhoCorasick::build(pats);
    let matches = ac.find_all(b"ushers");
    // expected: "she" at 1..4, "he" at 2..4, "hers" at 2..6
    let idxs: Vec<usize> = matches.iter().map(|m| m.pattern_idx).collect();
    assert!(idxs.contains(&0)); // he
    assert!(idxs.contains(&1)); // she
    assert!(idxs.contains(&3)); // hers
}

#[test]
fn ac_no_match() {
    let pats: &[&[u8]] = &[b"abc"];
    let ac = AhoCorasick::build(pats);
    assert!(ac.find_first(b"xyz").is_none());
}

#[test]
fn ac_find_first_returns_earliest() {
    let pats: &[&[u8]] = &[b"abc", b"def"];
    let ac = AhoCorasick::build(pats);
    let m = ac.find_first(b"...abc...def").expect("match");
    assert_eq!(m.start, 3);
}

#[test]
fn ac_state_count_at_least_one() {
    let ac = AhoCorasick::build(&[]);
    assert!(ac.state_count() >= 1);
}

// ─── find_bytes_nocase ──────────────────────────────────────────────────────

#[test]
fn nocase_empty_needle_returns_zero() {
    assert_eq!(find_bytes_nocase(b"abc", b""), Some(0));
}

#[test]
fn nocase_needle_longer_than_haystack() {
    assert_eq!(find_bytes_nocase(b"ab", b"abc"), None);
}

#[test]
fn nocase_case_insensitive_match() {
    assert_eq!(find_bytes_nocase(b"Hello World", b"WORLD"), Some(6));
    assert_eq!(find_bytes_nocase(b"FOOBAR", b"foo"), Some(0));
}

#[test]
fn nocase_no_match() {
    assert_eq!(find_bytes_nocase(b"abcdef", b"xyz"), None);
}

// ─── CompiledRuleSet ────────────────────────────────────────────────────────

#[test]
fn compiled_rule_set_matches_content() {
    let mut r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Any,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "x",
    );
    r.conditions.push(Condition::Content(b"badword".to_vec()));
    let c = CompiledRuleSet::compile(vec![r]);
    let ctx = pkt_tcp(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, b"hello badword end");
    let matches = c.evaluate(&ctx);
    assert!(!matches.is_empty());
}

// ─── RuleStore (in-memory SQLite) ───────────────────────────────────────────

#[test]
fn store_in_memory_save_load_count() {
    let store = RuleStore::in_memory().unwrap();
    assert_eq!(store.count().unwrap(), 0);
    let r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Tcp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "msg",
    );
    store.save_rule(&r).unwrap();
    assert_eq!(store.count().unwrap(), 1);
    let loaded = store.load_all().unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].id, 1);
    assert_eq!(loaded[0].msg, "msg");
}

#[test]
fn store_delete_missing_returns_not_found() {
    let store = RuleStore::in_memory().unwrap();
    let e = store.delete_rule(999).unwrap_err();
    assert!(matches!(e, RuleError::NotFound(999)));
}

#[test]
fn store_set_enabled_missing_returns_not_found() {
    let store = RuleStore::in_memory().unwrap();
    let e = store.set_enabled(999, false).unwrap_err();
    assert!(matches!(e, RuleError::NotFound(999)));
}

#[test]
fn store_save_replace_idempotent() {
    let store = RuleStore::in_memory().unwrap();
    let mut r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Tcp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "v1",
    );
    store.save_rule(&r).unwrap();
    r.msg = "v2".to_string();
    store.save_rule(&r).unwrap();
    assert_eq!(store.count().unwrap(), 1);
    let loaded = store.load_all().unwrap();
    assert_eq!(loaded[0].msg, "v2");
}

#[test]
fn store_set_enabled_persists() {
    let store = RuleStore::in_memory().unwrap();
    let r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Tcp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "",
    );
    store.save_rule(&r).unwrap();
    store.set_enabled(1, false).unwrap();
    let loaded = store.load_all().unwrap();
    assert!(!loaded[0].enabled);
}

// ─── JSON import/export round-trip ──────────────────────────────────────────

#[test]
fn json_round_trip() {
    let r = Rule::new(
        7,
        RuleAction::Drop,
        Proto::Udp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "udp drop",
    );
    let json = export_rules_json(std::slice::from_ref(&r)).unwrap();
    let back = import_rules_json(&json).unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].id, 7);
    assert_eq!(back[0].action, RuleAction::Drop);
    assert_eq!(back[0].msg, "udp drop");
}

#[test]
fn json_import_invalid_errors() {
    let e = import_rules_json("not json").unwrap_err();
    assert!(matches!(e, RuleError::Serialization(_)));
}

#[test]
fn export_snort_contains_action_and_msg() {
    let r = Rule::new(
        7,
        RuleAction::Alert,
        Proto::Tcp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "hello",
    );
    let s = export_rules_snort(&[r]);
    assert!(s.contains("alert"));
    assert!(s.contains("hello"));
}

// ─── PacketContext ──────────────────────────────────────────────────────────

#[test]
fn packet_context_from_ipv4_truncated_returns_none() {
    let buf = [0u8; 5];
    assert!(PacketContext::from_ipv4(&buf).is_none());
}

// ─── FlowbitStore ───────────────────────────────────────────────────────────

#[test]
fn flowbits_set_unset_toggle() {
    let f = FlowbitStore::new();
    assert!(!f.is_set("flow1", "bit"));
    f.set("flow1", "bit");
    assert!(f.is_set("flow1", "bit"));
    f.toggle("flow1", "bit");
    assert!(!f.is_set("flow1", "bit"));
    f.set("flow1", "bit");
    f.unset("flow1", "bit");
    assert!(!f.is_set("flow1", "bit"));
}

#[test]
fn flowbits_eval_ops() {
    let f = FlowbitStore::new();
    f.set("flow", "a");
    assert!(f.eval("flow", &FlowbitOp::IsSet("a".to_string())));
    assert!(!f.eval("flow", &FlowbitOp::IsSet("b".to_string())));
    assert!(!f.eval("flow", &FlowbitOp::IsNotSet("a".to_string())));
    assert!(f.eval("flow", &FlowbitOp::IsNotSet("b".to_string())));
}

#[test]
fn flowbits_flow_count() {
    let f = FlowbitStore::new();
    f.set("f1", "b1");
    f.set("f2", "b1");
    assert_eq!(f.flow_count(), 2);
}

// ─── VarTable ───────────────────────────────────────────────────────────────

#[test]
fn vartable_defaults_present() {
    let v = VarTable::with_defaults();
    assert!(!v.ip_var_names().is_empty());
    assert!(!v.port_var_names().is_empty());
}

#[test]
fn vartable_resolve_unknown_returns_any() {
    let v = VarTable::new();
    match v.resolve_ip("$DOES_NOT_EXIST") {
        IpSpec::Any => {}
        _ => panic!("expected Any"),
    }
    match v.resolve_port("$DOES_NOT_EXIST") {
        PortSpec::Any => {}
        _ => panic!("expected Any"),
    }
}

#[test]
fn vartable_set_get_roundtrip() {
    let mut v = VarTable::new();
    v.set_ip("HOME_NET", IpSpec::Single(v4(10, 0, 0, 1)));
    match v.resolve_ip("HOME_NET") {
        IpSpec::Single(_) => {}
        _ => panic!(),
    }
}

// ─── Builtin catalogue ──────────────────────────────────────────────────────

#[test]
fn builtin_catalogue_has_rules() {
    let c = builtin_catalogue();
    assert!(c.count() > 0);
    let engine = c.build_engine();
    assert!(!engine.rules().is_empty());
}

// ─── Concurrency invariants ─────────────────────────────────────────────────

const fn is_sync<T: Sync>() {}
const fn is_send<T: Send>() {}

#[test]
fn rule_engine_is_send_sync() {
    is_send::<RuleEngine>();
    is_sync::<RuleEngine>();
}

#[test]
fn rule_is_send_sync() {
    is_send::<Rule>();
    is_sync::<Rule>();
}
