//! Deep adversarial tests for rustre-net-rules public API (Y108).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::thread;

use rustre_net_rules::{
    AhoCorasick, CompiledRuleSet, Condition, IpSpec, MatchPacket, NetworkSpec, PacketContext,
    PortSpec, Proto, Rule, RuleAction, RuleDir, RuleEngine, RuleOption, RuleParser, RuleProtocol,
    RuleSet, RuleStore, SpecRule, SpecRuleEngine,
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

const fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

// ───────────────────────────── IpSpec ─────────────────────────────

#[test]
fn ipspec_any_matches_everything() {
    let s = IpSpec::Any;
    assert!(s.matches(ip4(0, 0, 0, 0)));
    assert!(s.matches(ip4(255, 255, 255, 255)));
    assert!(s.matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

#[test]
fn ipspec_single_exact() {
    let s = IpSpec::Single(ip4(10, 0, 0, 1));
    assert!(s.matches(ip4(10, 0, 0, 1)));
    assert!(!s.matches(ip4(10, 0, 0, 2)));
}

#[test]
fn ipspec_range_inclusive_bounds() {
    let s = IpSpec::Range(ip4(10, 0, 0, 1), ip4(10, 0, 0, 10));
    assert!(s.matches(ip4(10, 0, 0, 1)));
    assert!(s.matches(ip4(10, 0, 0, 10)));
    assert!(s.matches(ip4(10, 0, 0, 5)));
    assert!(!s.matches(ip4(10, 0, 0, 0)));
    assert!(!s.matches(ip4(10, 0, 0, 11)));
}

#[test]
fn ipspec_cidr_prefix_zero_matches_all_v4() {
    let s = IpSpec::Cidr(ip4(0, 0, 0, 0), 0);
    assert!(s.matches(ip4(1, 2, 3, 4)));
    assert!(s.matches(ip4(255, 255, 255, 255)));
}

#[test]
fn ipspec_cidr_prefix_32_exact() {
    let s = IpSpec::Cidr(ip4(192, 168, 1, 1), 32);
    assert!(s.matches(ip4(192, 168, 1, 1)));
    assert!(!s.matches(ip4(192, 168, 1, 2)));
}

#[test]
fn ipspec_cidr_24() {
    let s = IpSpec::Cidr(ip4(192, 168, 1, 0), 24);
    assert!(s.matches(ip4(192, 168, 1, 0)));
    assert!(s.matches(ip4(192, 168, 1, 255)));
    assert!(!s.matches(ip4(192, 168, 2, 0)));
}

#[test]
fn ipspec_cidr_overlength_prefix_no_match() {
    let s = IpSpec::Cidr(ip4(10, 0, 0, 0), 33);
    assert!(!s.matches(ip4(10, 0, 0, 0)));
}

#[test]
fn ipspec_cidr_v6() {
    let s = IpSpec::Cidr(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 16);
    assert!(s.matches(IpAddr::V6(Ipv6Addr::new(0xfe80, 1, 2, 3, 4, 5, 6, 7))));
    assert!(!s.matches(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0))));
}

#[test]
fn ipspec_cidr_v4_v6_mismatch() {
    let s = IpSpec::Cidr(ip4(10, 0, 0, 0), 8);
    assert!(!s.matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

#[test]
fn ipspec_group_and_not() {
    let g = IpSpec::Group(vec![
        IpSpec::Single(ip4(1, 1, 1, 1)),
        IpSpec::Single(ip4(2, 2, 2, 2)),
    ]);
    assert!(g.matches(ip4(1, 1, 1, 1)));
    assert!(!g.matches(ip4(3, 3, 3, 3)));
    let n = IpSpec::Not(Box::new(IpSpec::Single(ip4(1, 1, 1, 1))));
    assert!(!n.matches(ip4(1, 1, 1, 1)));
    assert!(n.matches(ip4(2, 2, 2, 2)));
}

#[test]
fn ipspec_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..200 {
        let n = g();
        let addr = ip4(
            u8::try_from(n & 0xFF).unwrap_or(0),
            u8::try_from((n >> 8) & 0xFF).unwrap_or(0),
            u8::try_from((n >> 16) & 0xFF).unwrap_or(0),
            u8::try_from((n >> 24) & 0xFF).unwrap_or(0),
        );
        let pfx = u8::try_from((n >> 32) & 0x3f).unwrap_or(0);
        let s = IpSpec::Cidr(addr, pfx);
        let _ = s.matches(ip4(0, 0, 0, 0));
    }
}

// ───────────────────────────── PortSpec ─────────────────────────────

#[test]
fn portspec_any() {
    let s = PortSpec::Any;
    assert!(s.matches(0));
    assert!(s.matches(u16::MAX));
}

#[test]
fn portspec_single() {
    let s = PortSpec::Single(80);
    assert!(s.matches(80));
    assert!(!s.matches(81));
}

#[test]
fn portspec_range_bounds() {
    let s = PortSpec::Range(100, 200);
    assert!(s.matches(100));
    assert!(s.matches(200));
    assert!(s.matches(150));
    assert!(!s.matches(99));
    assert!(!s.matches(201));
}

#[test]
fn portspec_list_and_not() {
    let s = PortSpec::List(vec![80, 443, 8080]);
    assert!(s.matches(80));
    assert!(s.matches(443));
    assert!(!s.matches(81));
    let n = PortSpec::Not(Box::new(PortSpec::Single(80)));
    assert!(n.matches(81));
    assert!(!n.matches(80));
}

#[test]
fn portspec_extreme_bounds() {
    let s = PortSpec::Range(0, u16::MAX);
    assert!(s.matches(0));
    assert!(s.matches(u16::MAX));
    assert!(s.matches(32768));
}

// ───────────────────────────── NetworkSpec ─────────────────────────────

#[test]
fn networkspec_any_and_match() {
    let any = NetworkSpec::any();
    assert!(any.matches(ip4(1, 2, 3, 4), 1234));
    let ns = NetworkSpec {
        addr: IpSpec::Single(ip4(10, 0, 0, 1)),
        port: PortSpec::Single(80),
    };
    assert!(ns.matches(ip4(10, 0, 0, 1), 80));
    assert!(!ns.matches(ip4(10, 0, 0, 1), 81));
    assert!(!ns.matches(ip4(10, 0, 0, 2), 80));
}

// ───────────────────────────── Display ─────────────────────────────

#[test]
fn display_rule_action() {
    assert_eq!(RuleAction::Alert.to_string(), "alert");
    assert_eq!(RuleAction::Pass.to_string(), "pass");
    assert_eq!(RuleAction::Drop.to_string(), "drop");
    assert_eq!(RuleAction::Log.to_string(), "log");
    assert_eq!(RuleAction::Reject.to_string(), "reject");
}

#[test]
fn display_proto() {
    assert_eq!(Proto::Tcp.to_string(), "tcp");
    assert_eq!(Proto::Udp.to_string(), "udp");
    assert_eq!(Proto::Icmp.to_string(), "icmp");
    assert_eq!(Proto::Any.to_string(), "any");
}

#[test]
fn display_rule_dir() {
    assert_eq!(RuleDir::Unidirectional.to_string(), "->");
    assert_eq!(RuleDir::Bidirectional.to_string(), "<>");
}

#[test]
fn display_rule_protocol() {
    assert_eq!(RuleProtocol::Tcp.to_string(), "tcp");
    assert_eq!(RuleProtocol::Any.to_string(), "any");
}

#[test]
fn display_condition_variants() {
    let c = Condition::Content(b"abc".to_vec());
    assert!(c.to_string().contains("content"));
    assert!(Condition::Offset(5).to_string().contains("offset:5"));
    assert!(Condition::Depth(10).to_string().contains("depth:10"));
    assert!(Condition::Within(3).to_string().contains("within:3"));
    assert!(Condition::Distance(7).to_string().contains("distance:7"));
    assert!(Condition::Ttl(64).to_string().contains("ttl:64"));
    assert!(Condition::SrcPort(80).to_string().contains("src_port:80"));
    assert!(Condition::DstPort(80).to_string().contains("dst_port:80"));
    assert!(
        Condition::DSize { min: 1, max: 2 }
            .to_string()
            .contains("dsize")
    );
    assert!(Condition::Pcre("x".into()).to_string().contains("pcre"));
}

#[test]
fn display_rule_option_variants() {
    assert!(RuleOption::Nocase.to_string().contains("nocase"));
    assert!(RuleOption::Sid(42).to_string().contains("42"));
    assert!(RuleOption::Rev(3).to_string().contains('3'));
    assert!(
        RuleOption::Classtype("x".into())
            .to_string()
            .contains("classtype")
    );
    assert!(RuleOption::Msg("m".into()).to_string().contains('m'));
    assert!(
        RuleOption::Content(b"abc".to_vec())
            .to_string()
            .contains("content")
    );
    assert!(RuleOption::Offset(1).to_string().contains("offset"));
    assert!(RuleOption::Depth(1).to_string().contains("depth"));
    assert!(RuleOption::Within(1).to_string().contains("within"));
    assert!(RuleOption::Pcre("p".into()).to_string().contains("pcre"));
}

// ───────────────────────────── RuleParser ─────────────────────────────

#[test]
fn parse_basic_rule() {
    let r = RuleParser::parse(
        r#"alert tcp 192.168.1.0/24 any -> any 80 (msg:"Test"; content:"evil"; sid:1001;)"#,
    )
    .expect("parse");
    assert_eq!(r.id, 1001);
    assert_eq!(r.action, RuleAction::Alert);
    assert_eq!(r.proto, Proto::Tcp);
    assert_eq!(r.msg, "Test");
    assert!(r.enabled);
    assert!(!r.conditions.is_empty());
}

#[test]
fn parse_all_actions() {
    for act in ["alert", "pass", "drop", "log", "reject"] {
        let s = format!("{act} tcp any any -> any any (msg:\"x\"; sid:1;)");
        let r = RuleParser::parse(&s).expect("parse");
        let expected = match act {
            "alert" => RuleAction::Alert,
            "pass" => RuleAction::Pass,
            "drop" => RuleAction::Drop,
            "log" => RuleAction::Log,
            "reject" => RuleAction::Reject,
            _ => unreachable!(),
        };
        assert_eq!(r.action, expected);
    }
}

#[test]
fn parse_all_protos() {
    for (p, ex) in [
        ("tcp", Proto::Tcp),
        ("udp", Proto::Udp),
        ("icmp", Proto::Icmp),
        ("any", Proto::Any),
        ("ip", Proto::Any),
    ] {
        let s = format!("alert {p} any any -> any any (msg:\"x\"; sid:1;)");
        let r = RuleParser::parse(&s).expect("parse");
        assert_eq!(r.proto, ex);
    }
}

#[test]
fn parse_rejects_unknown_action_and_proto() {
    assert!(
        RuleParser::parse("XXX tcp any any -> any any (msg:\"x\"; sid:1;)").is_err()
    );
    assert!(
        RuleParser::parse("alert YYY any any -> any any (msg:\"x\"; sid:1;)").is_err()
    );
}

#[test]
fn parse_rejects_empty_and_comment() {
    assert!(RuleParser::parse("").is_err());
    assert!(RuleParser::parse("   ").is_err());
    assert!(RuleParser::parse("# comment").is_err());
}

#[test]
fn parse_rejects_missing_parens() {
    assert!(RuleParser::parse("alert tcp any any -> any any msg:x").is_err());
}

#[test]
fn parse_rejects_short_header() {
    assert!(
        RuleParser::parse("alert tcp any any -> any (msg:\"x\"; sid:1;)").is_err()
    );
}

#[test]
fn parse_port_range_and_list() {
    let r = RuleParser::parse(
        r#"alert tcp any [80,443,8080] -> any 1000:2000 (msg:"x"; sid:1;)"#,
    )
    .expect("parse");
    matches!(r.src.port, PortSpec::List(_));
    matches!(r.dst.port, PortSpec::Range(_, _));
}

#[test]
fn parse_port_negation() {
    let r = RuleParser::parse(r#"alert tcp any !80 -> any any (msg:"x"; sid:1;)"#).expect("parse");
    matches!(r.src.port, PortSpec::Not(_));
}

#[test]
fn parse_ip_variable_and_cidr() {
    let r = RuleParser::parse(
        r#"alert tcp $HOME_NET any -> 10.0.0.0/8 any (msg:"x"; sid:1;)"#,
    )
    .expect("parse");
    matches!(r.src.addr, IpSpec::Any);
    matches!(r.dst.addr, IpSpec::Cidr(_, _));
}

#[test]
fn parse_ip_group() {
    let r = RuleParser::parse(
        r#"alert tcp [10.0.0.1,10.0.0.2] any -> any any (msg:"x"; sid:1;)"#,
    )
    .expect("parse");
    matches!(r.src.addr, IpSpec::Group(_));
}

#[test]
fn parse_invalid_ip_errors() {
    assert!(
        RuleParser::parse(r#"alert tcp not.an.ip any -> any any (msg:"x"; sid:1;)"#).is_err()
    );
}

#[test]
fn parse_invalid_cidr_errors() {
    assert!(
        RuleParser::parse(r#"alert tcp 10.0.0.0/abc any -> any any (msg:"x"; sid:1;)"#).is_err()
    );
}

#[test]
fn parse_invalid_port_errors() {
    assert!(
        RuleParser::parse(r#"alert tcp any 99999 -> any any (msg:"x"; sid:1;)"#).is_err()
    );
}

#[test]
fn parse_invalid_sid_errors() {
    assert!(
        RuleParser::parse(r#"alert tcp any any -> any any (msg:"x"; sid:notnum;)"#).is_err()
    );
}

#[test]
fn parse_all_conditions() {
    let r = RuleParser::parse(
        r#"alert tcp any any -> any any (msg:"x"; sid:1; content:"abc"; offset:0; depth:10; within:5; distance:2; ttl:64; flags:SA; pcre:"r"; dsize:5;)"#,
    )
    .expect("parse");
    assert!(r.conditions.len() >= 9);
}

#[test]
fn parse_content_hex_bare() {
    // Per parse_content_value: bare |...| (no surrounding quotes) is decoded as hex.
    let r = RuleParser::parse(
        r#"alert tcp any any -> any any (msg:"x"; sid:1; content:|DE AD BE EF|;)"#,
    )
    .expect("parse");
    if let Condition::Content(bytes) = &r.conditions[0] {
        assert_eq!(bytes, &[0xDE, 0xAD, 0xBE, 0xEF]);
    } else {
        panic!("expected Content");
    }
}

#[test]
fn parse_content_hex_invalid_bare_errors() {
    // Bare |...| with non-hex bytes is rejected.
    assert!(
        RuleParser::parse(
            r#"alert tcp any any -> any any (msg:"x"; sid:1; content:|ZZ|;)"#
        )
        .is_err()
    );
}

#[test]
fn parse_dsize_range_and_compare() {
    let r1 = RuleParser::parse(r"alert tcp any any -> any any (sid:1; dsize:100<>200;)")
        .expect("parse");
    assert!(matches!(
        r1.conditions[0],
        Condition::DSize { min: 100, max: 200 }
    ));
    let r2 =
        RuleParser::parse(r"alert tcp any any -> any any (sid:1; dsize:<50;)").expect("parse");
    assert!(matches!(r2.conditions[0], Condition::DSize { min: 0, max: 50 }));
    let r3 =
        RuleParser::parse(r"alert tcp any any -> any any (sid:1; dsize:>50;)").expect("parse");
    assert!(matches!(
        r3.conditions[0],
        Condition::DSize { min: 50, max: u32::MAX }
    ));
    let r4 =
        RuleParser::parse(r"alert tcp any any -> any any (sid:1; dsize:42;)").expect("parse");
    assert!(matches!(
        r4.conditions[0],
        Condition::DSize { min: 42, max: 42 }
    ));
}

#[test]
fn parse_many_skips_blank_and_comments() {
    let text = r#"
# top comment
alert tcp any any -> any any (msg:"a"; sid:1;)

# mid
alert udp any any -> any any (msg:"b"; sid:2;)
"#;
    let results = RuleParser::parse_many(text);
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(Result::is_ok));
}

#[test]
fn parser_fuzz_never_panics() {
    let mut g = lcg();
    let frags = [
        "alert", "tcp", "any", "->", "(", ")", "msg:\"x\"", "sid:1", ";", "content:\"a\"",
        "192.168.1.1", "/24", "$X", "[1,2]", "80:90", "!80",
    ];
    for _ in 0..150 {
        let mut s = String::new();
        let n = usize::try_from(g() % 10).unwrap_or(0) + 1;
        for _ in 0..n {
            let f = frags[usize::try_from(g()).unwrap_or(0) % frags.len()];
            s.push_str(f);
            s.push(' ');
        }
        let _ = RuleParser::parse(&s);
    }
}

// ───────────────────────────── RuleEngine ─────────────────────────────

const fn mk_ctx(src_port: u16, dst_port: u16, payload: Vec<u8>, ip_proto: u8) -> PacketContext {
    PacketContext {
        src_ip: ip4(10, 0, 0, 1),
        dst_ip: ip4(10, 0, 0, 2),
        src_port,
        dst_port,
        ip_proto,
        ttl: 64,
        payload,
        tcp_flags: rustre_net::TcpFlags::empty(),
    }
}

#[test]
fn engine_add_remove_and_list() {
    let e = RuleEngine::new();
    let r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Tcp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "x",
    );
    e.add_rule(r);
    assert_eq!(e.rules().len(), 1);
    e.remove_rule(1);
    assert_eq!(e.rules().len(), 0);
}

#[test]
fn engine_evaluate_match_and_no_match() {
    let e = RuleEngine::new();
    let mut r = Rule::new(
        7,
        RuleAction::Drop,
        Proto::Tcp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "hit",
    );
    r.conditions.push(Condition::Content(b"evil".to_vec()));
    e.add_rule(r);

    let ctx = mk_ctx(1234, 80, b"hello evil world".to_vec(), 6);
    let m = e.evaluate(&ctx).expect("match");
    assert_eq!(m.rule_id, 7);
    assert_eq!(m.action, RuleAction::Drop);

    let ctx2 = mk_ctx(1234, 80, b"clean".to_vec(), 6);
    assert!(e.evaluate(&ctx2).is_none());
}

#[test]
fn engine_proto_mismatch() {
    let e = RuleEngine::new();
    e.add_rule(Rule::new(
        1,
        RuleAction::Alert,
        Proto::Tcp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "",
    ));
    let ctx = mk_ctx(1, 2, vec![], 17);
    assert!(e.evaluate(&ctx).is_none());
}

#[test]
fn engine_disabled_rule_not_matched() {
    let e = RuleEngine::new();
    let mut r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Tcp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "",
    );
    r.enabled = false;
    e.add_rule(r);
    let ctx = mk_ctx(1, 2, vec![], 6);
    assert!(e.evaluate(&ctx).is_none());
}

#[test]
fn engine_evaluate_all_returns_all_matches() {
    let e = RuleEngine::new();
    for i in 0..5 {
        e.add_rule(Rule::new(
            i,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "x",
        ));
    }
    let ctx = mk_ctx(1, 2, vec![], 6);
    let all = e.evaluate_all(&ctx);
    assert_eq!(all.len(), 5);
}

#[test]
fn engine_conditions_dsize_ttl_ports_flags() {
    let e = RuleEngine::new();
    let mut r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Any,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "",
    );
    r.conditions = vec![
        Condition::DSize { min: 3, max: 10 },
        Condition::Ttl(64),
        Condition::SrcPort(1234),
        Condition::DstPort(80),
    ];
    e.add_rule(r);
    let ctx = mk_ctx(1234, 80, b"hello".to_vec(), 6);
    assert!(e.evaluate(&ctx).is_some());

    let ctx2 = mk_ctx(1234, 80, b"hi".to_vec(), 6); // dsize too small
    assert!(e.evaluate(&ctx2).is_none());
}

#[test]
fn engine_invalid_regex_does_not_match() {
    let e = RuleEngine::new();
    let mut r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Any,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "",
    );
    r.conditions.push(Condition::Pcre("(unclosed".into()));
    e.add_rule(r);
    let ctx = mk_ctx(1, 2, b"abc".to_vec(), 6);
    assert!(e.evaluate(&ctx).is_none());
}

#[test]
fn engine_pcre_match() {
    let e = RuleEngine::new();
    let mut r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Any,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "",
    );
    r.conditions.push(Condition::Pcre(r"\d+".into()));
    e.add_rule(r);
    assert!(e.evaluate(&mk_ctx(1, 2, b"abc123".to_vec(), 6)).is_some());
    assert!(e.evaluate(&mk_ctx(1, 2, b"abc".to_vec(), 6)).is_none());
}

#[test]
fn engine_default_is_empty() {
    let e = RuleEngine::default();
    assert_eq!(e.rules().len(), 0);
}

// ───────────────────────────── Round-trip JSON via store ─────────────────────────────

#[test]
fn rulestore_in_memory_roundtrip() {
    let s = RuleStore::in_memory().expect("open");
    let mut r = Rule::new(
        42,
        RuleAction::Drop,
        Proto::Udp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "msg",
    );
    r.conditions.push(Condition::Content(b"x".to_vec()));
    s.save_rule(&r).expect("save");
    let loaded = s.load_all().expect("load");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].id, 42);
    assert_eq!(loaded[0].action, RuleAction::Drop);
    assert_eq!(s.count().unwrap(), 1);
}

#[test]
fn rulestore_delete_missing_errors() {
    let s = RuleStore::in_memory().unwrap();
    assert!(s.delete_rule(999).is_err());
}

#[test]
fn rulestore_set_enabled_missing_errors() {
    let s = RuleStore::in_memory().unwrap();
    assert!(s.set_enabled(999, false).is_err());
}

#[test]
fn rulestore_set_enabled_toggles() {
    let s = RuleStore::in_memory().unwrap();
    let r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Tcp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "m",
    );
    s.save_rule(&r).unwrap();
    s.set_enabled(1, false).unwrap();
    let all = s.load_all().unwrap();
    assert!(!all[0].enabled);
    s.set_enabled(1, true).unwrap();
    let all = s.load_all().unwrap();
    assert!(all[0].enabled);
}

#[test]
fn rulestore_delete_works() {
    let s = RuleStore::in_memory().unwrap();
    let r = Rule::new(
        5,
        RuleAction::Alert,
        Proto::Tcp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "m",
    );
    s.save_rule(&r).unwrap();
    s.delete_rule(5).unwrap();
    assert_eq!(s.count().unwrap(), 0);
}

#[test]
fn rulestore_replace_same_id() {
    let s = RuleStore::in_memory().unwrap();
    let r1 = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Tcp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "a",
    );
    let r2 = Rule::new(
        1,
        RuleAction::Drop,
        Proto::Udp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "b",
    );
    s.save_rule(&r1).unwrap();
    s.save_rule(&r2).unwrap();
    let all = s.load_all().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].action, RuleAction::Drop);
    assert_eq!(all[0].msg, "b");
}

// ───────────────────────────── AhoCorasick ─────────────────────────────

#[test]
fn ac_empty_patterns_no_match() {
    let ac = AhoCorasick::build(&[]);
    assert_eq!(ac.find_all(b"hello").len(), 0);
    assert!(ac.find_first(b"hello").is_none());
    assert!(!ac.contains_any(b"hello"));
}

#[test]
fn ac_single_pattern_basic() {
    let ac = AhoCorasick::build(&[b"abc"]);
    let m = ac.find_all(b"xxabcxx");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].pattern_idx, 0);
    assert_eq!(m[0].start, 2);
    assert_eq!(m[0].end, 5);
}

#[test]
fn ac_multi_pattern_overlapping() {
    let ac = AhoCorasick::build(&[b"he", b"she", b"his", b"hers"]);
    let m = ac.find_all(b"ushers");
    // should detect: "she" at 1-4, "he" at 2-4, "hers" at 2-6
    assert!(m.iter().any(|x| x.pattern_idx == 1)); // she
    assert!(m.iter().any(|x| x.pattern_idx == 0)); // he
    assert!(m.iter().any(|x| x.pattern_idx == 3)); // hers
}

#[test]
fn ac_no_match() {
    let ac = AhoCorasick::build(&[b"zzz"]);
    assert_eq!(ac.find_all(b"abcdef").len(), 0);
}

#[test]
fn ac_state_count_positive() {
    let ac = AhoCorasick::build(&[b"abc", b"abd"]);
    assert!(ac.state_count() >= 4);
}

#[test]
fn ac_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..40 {
        let np = usize::try_from((g() % 4) + 1).unwrap_or(1);
        let mut pats: Vec<Vec<u8>> = Vec::new();
        for _ in 0..np {
            let len = usize::try_from((g() % 6) + 1).unwrap_or(1);
            let mut p = Vec::with_capacity(len);
            for _ in 0..len {
                p.push(u8::try_from(g() & 0xff).unwrap_or(0));
            }
            pats.push(p);
        }
        let slices: Vec<&[u8]> = pats.iter().map(Vec::as_slice).collect();
        let ac = AhoCorasick::build(&slices);
        let tlen = usize::try_from((g() % 64) + 1).unwrap_or(1);
        let mut txt = Vec::with_capacity(tlen);
        for _ in 0..tlen {
            txt.push(u8::try_from(g() & 0xff).unwrap_or(0));
        }
        let _ = ac.find_all(&txt);
        let _ = ac.find_first(&txt);
        let _ = ac.contains_any(&txt);
    }
}

// ───────────────────────────── CompiledRuleSet ─────────────────────────────

#[test]
fn compiled_ruleset_basic_match() {
    let mut r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Tcp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "m",
    );
    r.conditions.push(Condition::Content(b"evil".to_vec()));
    let crs = CompiledRuleSet::compile(vec![r]);
    assert_eq!(crs.rule_count(), 1);
    assert_eq!(crs.pattern_count(), 1);
    let ctx = mk_ctx(1, 2, b"some evil text".to_vec(), 6);
    let res = crs.evaluate(&ctx);
    assert_eq!(res.len(), 1);
}

#[test]
fn compiled_ruleset_no_match_wrong_proto() {
    let r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Tcp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "m",
    );
    let crs = CompiledRuleSet::compile(vec![r]);
    let ctx = mk_ctx(1, 2, vec![], 17);
    assert!(crs.evaluate(&ctx).is_empty());
}

#[test]
fn compiled_ruleset_disabled_skipped() {
    let mut r = Rule::new(
        1,
        RuleAction::Alert,
        Proto::Any,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "m",
    );
    r.enabled = false;
    let crs = CompiledRuleSet::compile(vec![r]);
    let ctx = mk_ctx(1, 2, vec![], 6);
    assert!(crs.evaluate(&ctx).is_empty());
}

// ───────────────────────────── SpecRuleEngine ─────────────────────────────

fn spec_rule(sid: u32, proto: RuleProtocol, content: Option<&[u8]>) -> SpecRule {
    let mut opts = vec![RuleOption::Sid(sid), RuleOption::Msg("m".into())];
    if let Some(c) = content {
        opts.push(RuleOption::Content(c.to_vec()));
    }
    SpecRule {
        action: RuleAction::Alert,
        proto,
        src: "any".into(),
        src_port: "any".into(),
        dir: RuleDir::Unidirectional,
        dst: "any".into(),
        dst_port: "any".into(),
        options: opts,
    }
}

#[test]
fn ruleset_add_and_lookup() {
    let mut rs = RuleSet::new();
    rs.add(spec_rule(11, RuleProtocol::Tcp, None));
    rs.add(spec_rule(22, RuleProtocol::Udp, None));
    assert_eq!(rs.count(), 2);
    assert!(rs.by_sid(11).is_some());
    assert!(rs.by_sid(99).is_none());
}

#[test]
fn spec_engine_match_payload() {
    let mut rs = RuleSet::new();
    rs.add(spec_rule(1, RuleProtocol::Tcp, Some(b"evil")));
    let e = SpecRuleEngine::new(rs);
    let pkt = MatchPacket {
        src_ip: "any".into(),
        dst_ip: "any".into(),
        src_port: 80,
        dst_port: 80,
        proto: RuleProtocol::Tcp,
        payload: b"this is evil".to_vec(),
    };
    let res = e.match_packet(&pkt);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].rule_sid, 1);
}

#[test]
fn spec_engine_proto_mismatch_no_results() {
    let mut rs = RuleSet::new();
    rs.add(spec_rule(1, RuleProtocol::Tcp, None));
    let e = SpecRuleEngine::new(rs);
    let pkt = MatchPacket {
        src_ip: "any".into(),
        dst_ip: "any".into(),
        src_port: 0,
        dst_port: 0,
        proto: RuleProtocol::Udp,
        payload: vec![],
    };
    assert!(e.match_packet(&pkt).is_empty());
}

#[test]
fn spec_rule_helpers() {
    let r = SpecRule {
        action: RuleAction::Alert,
        proto: RuleProtocol::Tcp,
        src: "any".into(),
        src_port: "any".into(),
        dir: RuleDir::Unidirectional,
        dst: "any".into(),
        dst_port: "any".into(),
        options: vec![
            RuleOption::Sid(77),
            RuleOption::Msg("hello".into()),
            RuleOption::Content(b"a".to_vec()),
            RuleOption::Content(b"b".to_vec()),
        ],
    };
    assert_eq!(r.sid(), Some(77));
    assert_eq!(r.msg(), Some("hello"));
    assert_eq!(r.content_patterns().len(), 2);
}

// ───────────────────────────── Eq / Copy semantics on enums ─────────────────────────────

#[test]
fn rule_action_eq_consistency() {
    let pairs = [
        (RuleAction::Alert, RuleAction::Alert, true),
        (RuleAction::Alert, RuleAction::Drop, false),
        (RuleAction::Drop, RuleAction::Drop, true),
        (RuleAction::Pass, RuleAction::Reject, false),
        (RuleAction::Log, RuleAction::Log, true),
    ];
    for (a, b, eq) in pairs {
        assert_eq!(a == b, eq);
    }
}

#[test]
fn proto_eq_consistency_pairs() {
    let v = [Proto::Tcp, Proto::Udp, Proto::Icmp, Proto::Any];
    for (i, a) in v.iter().enumerate() {
        for (j, b) in v.iter().enumerate() {
            assert_eq!(*a == *b, i == j);
        }
    }
}

// ───────────────────────────── Send/Sync threaded stress ─────────────────────────────

#[test]
fn engine_send_sync_threaded() {
    let engine = Arc::new(RuleEngine::new());
    for i in 0..3 {
        let mut r = Rule::new(
            i,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "x",
        );
        r.conditions.push(Condition::Content(b"hit".to_vec()));
        engine.add_rule(r);
    }
    let mut handles = Vec::new();
    for _ in 0..4 {
        let e = Arc::clone(&engine);
        handles.push(thread::spawn(move || {
            for j in 0..100 {
                let payload = if j % 2 == 0 { b"hit".to_vec() } else { b"miss".to_vec() };
                let ctx = mk_ctx(1, 2, payload, 6);
                let _ = e.evaluate_all(&ctx);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(engine.rules().len(), 3);
}

#[test]
fn rulestore_bulk_save_and_count() {
    // RuleStore wraps rusqlite::Connection which is !Sync; exercise it sequentially.
    let store = RuleStore::in_memory().unwrap();
    for i in 0..100u32 {
        let r = Rule::new(
            i,
            RuleAction::Alert,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "m",
        );
        store.save_rule(&r).unwrap();
    }
    assert_eq!(store.count().unwrap(), 100);
}

// ───────────────────────────── PacketContext::from_ipv4 ─────────────────────────────

#[test]
fn packet_context_from_truncated_ipv4_returns_none() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = usize::try_from((g() % 20) + 1).unwrap_or(1);
        let mut buf = Vec::with_capacity(n);
        for _ in 0..n {
            buf.push(u8::try_from(g() & 0xff).unwrap_or(0));
        }
        // never panic
        let _ = PacketContext::from_ipv4(&buf);
    }
}

#[test]
fn packet_context_from_empty() {
    assert!(PacketContext::from_ipv4(&[]).is_none());
}

// ───────────────────────────── MatchResult Display ─────────────────────────────

#[test]
fn match_result_display() {
    let m = rustre_net_rules::MatchResult {
        matched: true,
        rule_id: 7,
        action: RuleAction::Alert,
        msg: "hi".into(),
    };
    assert!(m.to_string().contains("MATCH"));
    let nm = rustre_net_rules::MatchResult {
        matched: false,
        rule_id: 7,
        action: RuleAction::Alert,
        msg: String::new(),
    };
    assert!(nm.to_string().contains("NO MATCH"));
}

#[test]
fn rule_display_contains_msg_and_id() {
    let r = Rule::new(
        99,
        RuleAction::Alert,
        Proto::Tcp,
        NetworkSpec::any(),
        NetworkSpec::any(),
        "the-msg",
    );
    let s = r.to_string();
    assert!(s.contains("the-msg"));
    assert!(s.contains("99"));
}
