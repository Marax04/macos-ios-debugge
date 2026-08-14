//! Blitz2 coverage tests for `rustre-net-proxy`.
//!
//! Focused on pure-function and small-struct surface: parsers, ACL, MITM config,
//! rate-limiter, HTTP method/request/status, hex codec, base64 decode, glob and
//! simple regex matchers, ProxyMode/AclAction display, traffic log, shared stats.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::thread;

use rustre_net_proxy::{
    base64_decode, glob_match, hex_decode, hex_encode, simple_regex_match, AclAction, AclEntry,
    HttpConnectRequest, HttpMethod, HttpRequestLine, HttpStatusLine, MitmConfig, ProxyAcl,
    ProxyConfig, ProxyError, ProxyMode, ProxyRequest, ProxyResponse, ProxyStats, RateLimiter,
    SharedStats, TrafficLog,
};

// ── Seeded LCG ────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

const fn sa(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

// ── ProxyMode ────────────────────────────────────────────────────────────────

#[test]
fn proxy_mode_display_all_variants() {
    assert_eq!(ProxyMode::Transparent.to_string(), "Transparent");
    assert_eq!(ProxyMode::Http.to_string(), "HTTP");
    assert_eq!(ProxyMode::Socks4.to_string(), "SOCKS4");
    assert_eq!(ProxyMode::Socks5.to_string(), "SOCKS5");
    assert_eq!(ProxyMode::Raw.to_string(), "Raw");
}

#[test]
fn proxy_mode_eq_and_copy() {
    let m = ProxyMode::Socks5;
    let m2 = m;
    assert_eq!(m, m2);
    assert_ne!(ProxyMode::Http, ProxyMode::Raw);
}

// ── ProxyConfig constructors ─────────────────────────────────────────────────

#[test]
fn proxy_config_http_constructor() {
    let cfg = ProxyConfig::http(sa(8080));
    assert_eq!(cfg.mode, ProxyMode::Http);
    assert!(cfg.upstream.is_none());
    assert!(!cfg.tls_intercept);
    assert_eq!(cfg.max_buffer, 64 * 1024);
}

#[test]
fn proxy_config_socks5_constructor() {
    let cfg = ProxyConfig::socks5(sa(1080));
    assert_eq!(cfg.mode, ProxyMode::Socks5);
    assert_eq!(cfg.bind_addr.port(), 1080);
}

// ── ProxyRequest/Response constructors ───────────────────────────────────────

#[test]
fn proxy_request_new_sets_fields() {
    let r = ProxyRequest::new(7, sa(100), sa(200), vec![1, 2, 3]);
    assert_eq!(r.id, 7);
    assert_eq!(r.client_addr, sa(100));
    assert_eq!(r.target_addr, sa(200));
    assert_eq!(r.data, vec![1, 2, 3]);
}

#[test]
fn proxy_response_new_sets_fields() {
    let r = ProxyResponse::new(9, sa(300), vec![4, 5]);
    assert_eq!(r.id, 9);
    assert_eq!(r.source_addr, sa(300));
    assert_eq!(r.data, vec![4, 5]);
}

// ── ProxyError Display ───────────────────────────────────────────────────────

#[test]
fn proxy_error_display_variants() {
    assert!(ProxyError::Socks5AuthFailed.to_string().contains("SOCKS5"));
    assert!(ProxyError::Socks4Rejected.to_string().contains("SOCKS4"));
    assert!(ProxyError::ConnectionDropped.to_string().contains("refused"));
    assert!(ProxyError::Timeout.to_string().contains("timeout"));
    assert!(
        ProxyError::HttpConnectFailed("x".into())
            .to_string()
            .contains('x')
    );
    assert!(
        ProxyError::InvalidRequest("foo".into())
            .to_string()
            .contains("foo")
    );
    assert!(
        ProxyError::Socks5UnsupportedCommand(7)
            .to_string()
            .contains('7')
    );
    assert!(
        ProxyError::Socks5UnsupportedAddressType(9)
            .to_string()
            .contains('9')
    );
}

// ── HttpConnectRequest parsing ───────────────────────────────────────────────

#[test]
fn http_connect_basic_parse() {
    let raw = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    let r = HttpConnectRequest::parse(raw).unwrap();
    assert_eq!(r.host, "example.com");
    assert_eq!(r.port, 443);
    assert_eq!(r.http_version, "HTTP/1.1");
    assert_eq!(r.header("host"), Some("example.com:443"));
}

#[test]
fn http_connect_default_port_443() {
    let raw = "CONNECT host HTTP/1.0\r\n\r\n";
    let r = HttpConnectRequest::parse(raw).unwrap();
    assert_eq!(r.port, 443);
    assert_eq!(r.host, "host");
}

#[test]
fn http_connect_rejects_get() {
    let raw = "GET / HTTP/1.1\r\n\r\n";
    assert!(matches!(
        HttpConnectRequest::parse(raw),
        Err(ProxyError::InvalidRequest(_))
    ));
}

#[test]
fn http_connect_rejects_bad_port() {
    let raw = "CONNECT host:notanumber HTTP/1.1\r\n\r\n";
    assert!(matches!(
        HttpConnectRequest::parse(raw),
        Err(ProxyError::InvalidRequest(_))
    ));
}

#[test]
fn http_connect_empty_request_errors() {
    assert!(HttpConnectRequest::parse("").is_err());
}

#[test]
fn http_connect_success_response_uses_version() {
    let r = HttpConnectRequest::parse("CONNECT h:80 HTTP/1.0\r\n\r\n").unwrap();
    let resp = r.success_response();
    assert!(resp.starts_with("HTTP/1.0 200"));
    assert!(resp.ends_with("\r\n\r\n"));
}

#[test]
fn http_connect_error_response_format() {
    let s = HttpConnectRequest::error_response(502, "Bad Gateway");
    assert!(s.contains("502"));
    assert!(s.contains("Bad Gateway"));
    assert!(s.ends_with("\r\n\r\n"));
}

// ── AclEntry / ProxyAcl ──────────────────────────────────────────────────────

#[test]
fn acl_default_allow() {
    let acl = ProxyAcl::new(AclAction::Allow);
    assert_eq!(acl.evaluate("any", 80), AclAction::Allow);
    assert!(acl.is_empty());
    assert_eq!(acl.len(), 0);
}

#[test]
fn acl_default_deny_with_allow_entry() {
    let mut acl = ProxyAcl::new(AclAction::Deny);
    acl.add(AclEntry::allow_all());
    assert_eq!(acl.evaluate("foo", 99), AclAction::Allow);
    assert_eq!(acl.len(), 1);
    assert!(!acl.is_empty());
}

#[test]
fn acl_entry_case_insensitive_match() {
    let e = AclEntry::deny_host("EXAMPLE.com");
    assert!(e.matches("example.COM", 80));
    assert!(!e.matches("other.com", 80));
}

#[test]
fn acl_entry_port_filter() {
    let e = AclEntry {
        host_pattern: "*".to_string(),
        port: Some(443),
        action: AclAction::Deny,
    };
    assert!(e.matches("anything", 443));
    assert!(!e.matches("anything", 80));
}

#[test]
fn acl_first_match_wins() {
    let mut acl = ProxyAcl::new(AclAction::Allow);
    acl.add(AclEntry::deny_host("a.com"));
    acl.add(AclEntry::allow_all());
    assert_eq!(acl.evaluate("a.com", 80), AclAction::Deny);
    assert_eq!(acl.evaluate("b.com", 80), AclAction::Allow);
}

#[test]
fn acl_action_display() {
    assert_eq!(AclAction::Allow.to_string(), "ALLOW");
    assert_eq!(AclAction::Deny.to_string(), "DENY");
}

// ── MitmConfig ───────────────────────────────────────────────────────────────

#[test]
fn mitm_disabled_default() {
    let c = MitmConfig::disabled();
    assert!(!c.enabled);
    assert!(!c.should_intercept("foo"));
}

#[test]
fn mitm_enabled_basic() {
    let c = MitmConfig::enabled("ca.pem", "ca.key");
    assert!(c.enabled);
    assert!(c.should_intercept("anything"));
    assert_eq!(c.ca_cert_path.as_deref(), Some("ca.pem"));
    assert_eq!(c.ca_key_path.as_deref(), Some("ca.key"));
}

#[test]
fn mitm_exclude_and_case_insensitive() {
    let mut c = MitmConfig::enabled("c", "k");
    c.exclude("Excluded.Example");
    assert!(c.is_excluded("excluded.example"));
    assert!(!c.should_intercept("EXCLUDED.example"));
    assert!(c.should_intercept("other"));
}

// ── RateLimiter ──────────────────────────────────────────────────────────────

#[test]
fn rate_limiter_max_connections() {
    let rl = RateLimiter::new(1024, 2);
    assert!(rl.try_connect());
    assert!(rl.try_connect());
    assert!(!rl.try_connect());
    assert_eq!(rl.active_connections(), 2);
    rl.release_connection();
    assert_eq!(rl.active_connections(), 1);
    assert!(rl.try_connect());
}

#[test]
fn rate_limiter_release_floor_at_zero() {
    let rl = RateLimiter::new(100, 4);
    rl.release_connection();
    rl.release_connection();
    assert_eq!(rl.active_connections(), 0);
}

#[test]
fn rate_limiter_bytes_window() {
    let rl = RateLimiter::new(100, 10);
    assert!(rl.try_send_bytes(0, 50));
    assert!(rl.try_send_bytes(100, 50));
    assert!(!rl.try_send_bytes(200, 1));
    // Past 1 second: window resets.
    assert!(rl.try_send_bytes(1500, 100));
    assert_eq!(rl.bytes_this_window(), 100);
}

#[test]
fn rate_limiter_boundary_exact_max() {
    let rl = RateLimiter::new(10, 1);
    assert!(rl.try_send_bytes(0, 10));
    assert!(!rl.try_send_bytes(0, 1));
}

// ── HttpMethod ───────────────────────────────────────────────────────────────

#[test]
fn http_method_from_str_known() {
    assert_eq!(HttpMethod::from_str("get"), HttpMethod::Get);
    assert_eq!(HttpMethod::from_str("POST"), HttpMethod::Post);
    assert_eq!(HttpMethod::from_str("PuT"), HttpMethod::Put);
    assert_eq!(HttpMethod::from_str("CONNECT"), HttpMethod::Connect);
}

#[test]
fn http_method_from_str_other() {
    let m = HttpMethod::from_str("PROPFIND");
    match m {
        HttpMethod::Other(s) => assert_eq!(s, "PROPFIND"),
        _ => panic!("expected Other"),
    }
}

#[test]
fn http_method_idempotent_and_body() {
    assert!(HttpMethod::Get.is_idempotent());
    assert!(HttpMethod::Head.is_idempotent());
    assert!(!HttpMethod::Post.is_idempotent());
    assert!(HttpMethod::Post.has_body());
    assert!(HttpMethod::Patch.has_body());
    assert!(!HttpMethod::Get.has_body());
}

#[test]
fn http_method_display() {
    assert_eq!(HttpMethod::Delete.to_string(), "DELETE");
    assert_eq!(
        HttpMethod::Other("XYZ".to_string()).to_string(),
        "XYZ"
    );
}

#[test]
fn http_method_from_trait() {
    use std::str::FromStr;
    let m: HttpMethod = HttpMethod::from_str("OPTIONS");
    let m2 = <HttpMethod as FromStr>::from_str("OPTIONS").unwrap();
    assert_eq!(m, m2);
}

// ── HttpRequestLine / HttpStatusLine ─────────────────────────────────────────

#[test]
fn request_line_parse_ok() {
    let l = HttpRequestLine::parse("GET /index HTTP/1.1").unwrap();
    assert_eq!(l.method, HttpMethod::Get);
    assert_eq!(l.uri, "/index");
    assert!(l.is_http11());
    assert!(!l.is_http2());
    assert_eq!(l.to_string(), "GET /index HTTP/1.1");
}

#[test]
fn request_line_parse_http2() {
    let l = HttpRequestLine::parse("POST /x HTTP/2.0").unwrap();
    assert!(l.is_http2());
    assert!(!l.is_http11());
}

#[test]
fn request_line_parse_bad() {
    assert!(HttpRequestLine::parse("BROKEN").is_err());
    assert!(HttpRequestLine::parse("").is_err());
}

#[test]
fn status_line_parse_ok() {
    let s = HttpStatusLine::parse("HTTP/1.1 200 OK").unwrap();
    assert_eq!(s.code, 200);
    assert_eq!(s.reason, "OK");
    assert!(s.is_success());
    assert!(!s.is_redirect());
    assert!(!s.is_client_error());
    assert!(!s.is_server_error());
}

#[test]
fn status_line_classes() {
    assert!(HttpStatusLine::parse("HTTP/1.1 301 Moved")
        .unwrap()
        .is_redirect());
    assert!(HttpStatusLine::parse("HTTP/1.1 404 NF")
        .unwrap()
        .is_client_error());
    assert!(HttpStatusLine::parse("HTTP/1.1 500 Err")
        .unwrap()
        .is_server_error());
}

#[test]
fn status_line_no_reason_ok() {
    let s = HttpStatusLine::parse("HTTP/1.1 204").unwrap();
    assert_eq!(s.code, 204);
    assert_eq!(s.reason, "");
}

#[test]
fn status_line_bad_code() {
    assert!(HttpStatusLine::parse("HTTP/1.1 ABC OK").is_err());
    assert!(HttpStatusLine::parse("only_one_part").is_err());
}

// ── hex codec round-trip on 50 LCG inputs ────────────────────────────────────

#[test]
fn hex_roundtrip_lcg_50() {
    let mut rng = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let len = (rng.next() % 32) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| (rng.next() & 0xff) as u8).collect();
        let enc = hex_encode(&bytes);
        let dec = hex_decode(&enc).expect("decode");
        assert_eq!(dec, bytes);
        assert_eq!(enc.len(), bytes.len() * 2);
        assert!(enc.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}

#[test]
fn hex_decode_boundaries() {
    assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
    assert_eq!(hex_decode("00").unwrap(), vec![0]);
    assert_eq!(hex_decode("ff").unwrap(), vec![0xff]);
    assert_eq!(hex_decode("FF").unwrap(), vec![0xff]);
    assert!(hex_decode("f").is_none());
    assert!(hex_decode("gg").is_none());
    assert!(hex_decode("0g").is_none());
}

#[test]
fn hex_encode_known() {
    assert_eq!(hex_encode(&[]), "");
    assert_eq!(hex_encode(&[0x00, 0xff, 0xab]), "00ffab");
}

// ── base64 decode ────────────────────────────────────────────────────────────

#[test]
fn base64_decode_known() {
    assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
    assert_eq!(base64_decode("Zg==").unwrap(), b"f".to_vec());
    assert_eq!(base64_decode("Zm8=").unwrap(), b"fo".to_vec());
    assert_eq!(base64_decode("Zm9v").unwrap(), b"foo".to_vec());
    assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar".to_vec());
}

#[test]
fn base64_decode_invalid_chars() {
    assert!(base64_decode("!!!!").is_none());
    assert!(base64_decode("Zm 9v").is_none());
}

// ── glob_match ───────────────────────────────────────────────────────────────

#[test]
fn glob_basic_match() {
    assert!(glob_match("foo", "foo"));
    assert!(!glob_match("foo", "bar"));
    assert!(glob_match("f?o", "foo"));
    assert!(glob_match("f*o", "fxxxxo"));
    assert!(!glob_match("f*o", "fxxxxoZ"));
}

#[test]
fn glob_double_star() {
    assert!(glob_match("**/x", "a/b/x"));
    assert!(glob_match("**", "anything/at/all"));
}

#[test]
fn glob_empty() {
    assert!(glob_match("", ""));
    assert!(!glob_match("", "x"));
    assert!(glob_match("*", ""));
}

// ── simple_regex_match ───────────────────────────────────────────────────────

#[test]
fn regex_literal() {
    assert!(simple_regex_match("abc", "xxabcyy"));
    assert!(!simple_regex_match("abc", "xxabyy"));
}

#[test]
fn regex_anchors_and_dot() {
    assert!(simple_regex_match("^a.c$", "abc"));
    assert!(!simple_regex_match("^a.c$", "abcd"));
    assert!(simple_regex_match("^hello", "hello world"));
    assert!(simple_regex_match("world$", "hello world"));
}

#[test]
fn regex_star_plus_question() {
    assert!(simple_regex_match("^ab*c$", "ac"));
    assert!(simple_regex_match("^ab*c$", "abbbbc"));
    assert!(simple_regex_match("^ab+c$", "abc"));
    assert!(!simple_regex_match("^ab+c$", "ac"));
    assert!(simple_regex_match("^ab?c$", "ac"));
    assert!(simple_regex_match("^ab?c$", "abc"));
}

#[test]
fn regex_char_class() {
    assert!(simple_regex_match("^[abc]$", "b"));
    assert!(!simple_regex_match("^[abc]$", "d"));
    assert!(simple_regex_match("^[a-z]+$", "hello"));
    assert!(!simple_regex_match("^[a-z]+$", "Hello"));
    assert!(simple_regex_match("^[^0-9]+$", "abc"));
    assert!(!simple_regex_match("^[^0-9]+$", "ab1"));
}

// ── TrafficLog ───────────────────────────────────────────────────────────────

#[test]
fn traffic_log_basics() {
    let log = TrafficLog::new(100);
    assert!(log.is_empty());
    let req = ProxyRequest::new(1, sa(1), sa(2), vec![1, 2]);
    log.log_request(&req);
    assert_eq!(log.len(), 1);
    assert!(!log.is_empty());
    log.clear();
    assert!(log.is_empty());
}

#[test]
fn traffic_log_ring_eviction() {
    let log = TrafficLog::new(3);
    for i in 0..5u64 {
        let req = ProxyRequest::new(i, sa(1), sa(2), vec![u8::try_from(i).unwrap_or(u8::MAX)]);
        log.log_request(&req);
    }
    assert_eq!(log.len(), 3);
    let entries = log.entries();
    let ids: Vec<u64> = entries.iter().map(|e| e.id).collect();
    assert_eq!(ids, vec![2, 3, 4]);
}

#[test]
fn traffic_log_response_dst() {
    let log = TrafficLog::new(10);
    let resp = ProxyResponse::new(7, sa(50), vec![9]);
    log.log_response(&resp, sa(60));
    let entries = log.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].src, sa(50));
    assert_eq!(entries[0].dst, sa(60));
    assert_eq!(entries[0].id, 7);
}

// ── SharedStats / ProxyStats ─────────────────────────────────────────────────

#[test]
fn shared_stats_increments() {
    let s = SharedStats::new();
    s.inc_connections();
    s.inc_requests(100);
    s.inc_responses(50);
    s.inc_errors();
    let snap = s.snapshot();
    assert_eq!(snap.connections, 1);
    assert_eq!(snap.requests, 1);
    assert_eq!(snap.bytes_in, 100);
    assert_eq!(snap.bytes_out, 50);
    assert_eq!(snap.errors, 1);
}

#[test]
fn shared_stats_default_zeros() {
    let s = SharedStats::default();
    let snap = s.snapshot();
    assert_eq!(snap.requests, 0);
    assert_eq!(snap.errors, 0);
}

#[test]
fn proxy_stats_display() {
    let s = ProxyStats {
        connections: 1,
        requests: 2,
        bytes_in: 3,
        bytes_out: 4,
        errors: 5,
    };
    let txt = s.to_string();
    assert!(txt.contains("connections=1"));
    assert!(txt.contains("requests=2"));
    assert!(txt.contains("errors=5"));
}

// ── Debug/Display/Eq/Hash style consistency on 30+ pairs ─────────────────────

#[test]
fn enum_eq_consistency_30_pairs() {
    let modes = [
        ProxyMode::Transparent,
        ProxyMode::Http,
        ProxyMode::Socks4,
        ProxyMode::Socks5,
        ProxyMode::Raw,
    ];
    let mut pairs = 0;
    for a in modes {
        for b in modes {
            // Display equality consistent with Eq.
            assert_eq!(a == b, a.to_string() == b.to_string());
            pairs += 1;
        }
    }
    // Methods (only those with PartialEq; HttpMethod has it).
    let methods = [
        HttpMethod::Get,
        HttpMethod::Post,
        HttpMethod::Put,
        HttpMethod::Delete,
        HttpMethod::Head,
        HttpMethod::Connect,
    ];
    for a in &methods {
        for b in &methods {
            assert_eq!(a == b, a.to_string() == b.to_string());
            pairs += 1;
        }
    }
    assert!(pairs >= 30);
}

#[test]
fn http_method_hashmap_lookup() {
    let mut m: HashMap<String, HttpMethod> = HashMap::new();
    m.insert("g".into(), HttpMethod::Get);
    m.insert("p".into(), HttpMethod::Post);
    assert!(matches!(m.get("g"), Some(HttpMethod::Get)));
    assert!(matches!(m.get("p"), Some(HttpMethod::Post)));
}

// ── Send/Sync 4×100 threaded test ────────────────────────────────────────────

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn types_are_send_sync() {
    assert_send_sync::<TrafficLog>();
    assert_send_sync::<SharedStats>();
    assert_send_sync::<RateLimiter>();
    assert_send_sync::<ProxyAcl>();
}

#[test]
fn shared_stats_threaded_4x100() {
    let s = Arc::new(SharedStats::new());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let s2 = Arc::clone(&s);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                s2.inc_requests(1);
                s2.inc_responses(2);
                s2.inc_connections();
                s2.inc_errors();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let snap = s.snapshot();
    assert_eq!(snap.requests, 400);
    assert_eq!(snap.bytes_in, 400);
    assert_eq!(snap.bytes_out, 800);
    assert_eq!(snap.connections, 400);
    assert_eq!(snap.errors, 400);
}

#[test]
fn traffic_log_threaded_4x100() {
    let log = Arc::new(TrafficLog::new(10_000));
    let mut handles = Vec::new();
    for t in 0..4u64 {
        let log2 = Arc::clone(&log);
        handles.push(thread::spawn(move || {
            for i in 0..100u64 {
                let req = ProxyRequest::new(t * 1000 + i, sa(1), sa(2), vec![u8::try_from(i).unwrap_or(u8::MAX)]);
                log2.log_request(&req);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(log.len(), 400);
}

// ── Round-trip 50 random hex strings via LCG already done above ──────────────
// ── Round-trip request-line parse → display ──────────────────────────────────

#[test]
fn request_line_roundtrip_lcg() {
    let methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];
    let mut rng = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let m = methods[usize::try_from(rng.next()).unwrap_or(usize::MAX) % methods.len()];
        let path_len = usize::try_from((rng.next() % 8) + 1).unwrap_or(usize::MAX);
        let path: String = (0..path_len)
            .map(|_| (b'a' + (u8::try_from(rng.next()).unwrap_or(u8::MAX) % 26)) as char)
            .collect();
        let raw = format!("{m} /{path} HTTP/1.1");
        let parsed = HttpRequestLine::parse(&raw).unwrap();
        assert_eq!(parsed.to_string(), raw);
    }
}
