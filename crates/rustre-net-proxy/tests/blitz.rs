//! Blitz integration tests for `rustre-net-proxy`.
//!
//! These tests exercise the public surface of the crate without relying on
//! actual network I/O. They focus on parsers, configuration constructors,
//! pure utility functions, and in-memory data structures.

use std::collections::HashMap;
use std::net::SocketAddr;

use rustre_net_proxy::{
    apply_rules_to_request, apply_rules_to_response, base64_decode, glob_match, hex_decode,
    hex_encode, inject_xff_headers, simple_regex_match, AclAction, AclEntry, ConnectionMetrics,
    DataModifier, DnsCache, DnsCacheEntry, HeaderInjector, HeaderRewriteRule, HeaderRewriter,
    HookAction, HttpConnectRequest, HttpMethod, HttpRequestLine, HttpStatusLine, MitmConfig,
    ModifierPipeline, ProxyAcl, ProxyConfig, ProxyError, ProxyMode, ProxyRecord, ProxyRecordStore,
    ProxyRequest, ProxyResponse, ProxyStats, RateLimiter, SearchReplaceModifier, SessionManager,
    SessionState, SharedStats, Socks5UdpHeader, TrafficLog, TrafficRecord, TrafficRecorder,
};

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

// ──────────────────────────────────────────────────────────
// ProxyMode / Display
// ──────────────────────────────────────────────────────────

#[test]
fn proxy_mode_display() {
    assert_eq!(ProxyMode::Transparent.to_string(), "Transparent");
    assert_eq!(ProxyMode::Http.to_string(), "HTTP");
    assert_eq!(ProxyMode::Socks4.to_string(), "SOCKS4");
    assert_eq!(ProxyMode::Socks5.to_string(), "SOCKS5");
    assert_eq!(ProxyMode::Raw.to_string(), "Raw");
}

#[test]
fn proxy_mode_eq_copy() {
    let a = ProxyMode::Http;
    let b = a;
    assert_eq!(a, b);
    assert_ne!(ProxyMode::Http, ProxyMode::Socks5);
}

// ──────────────────────────────────────────────────────────
// ProxyConfig constructors
// ──────────────────────────────────────────────────────────

#[test]
fn proxy_config_http_defaults() {
    let cfg = ProxyConfig::http(addr("127.0.0.1:8080"));
    assert_eq!(cfg.mode, ProxyMode::Http);
    assert!(cfg.upstream.is_none());
    assert!(!cfg.tls_intercept);
    assert!(cfg.socks5_auth.is_none());
    assert_eq!(cfg.max_buffer, 64 * 1024);
}

#[test]
fn proxy_config_socks5_defaults() {
    let cfg = ProxyConfig::socks5(addr("0.0.0.0:1080"));
    assert_eq!(cfg.mode, ProxyMode::Socks5);
    assert_eq!(cfg.bind_addr, addr("0.0.0.0:1080"));
}

#[test]
fn proxy_config_serde_roundtrip() {
    let cfg = ProxyConfig::http(addr("127.0.0.1:8080"));
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ProxyConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back.mode, cfg.mode);
    assert_eq!(back.bind_addr, cfg.bind_addr);
}

// ──────────────────────────────────────────────────────────
// ProxyRequest / ProxyResponse
// ──────────────────────────────────────────────────────────

#[test]
fn proxy_request_new_assigns_fields() {
    let req = ProxyRequest::new(42, addr("1.2.3.4:1111"), addr("5.6.7.8:2222"), vec![1, 2, 3]);
    assert_eq!(req.id, 42);
    assert_eq!(req.data, vec![1, 2, 3]);
    assert_eq!(req.client_addr, addr("1.2.3.4:1111"));
    assert_eq!(req.target_addr, addr("5.6.7.8:2222"));
}

#[test]
fn proxy_response_new_assigns_fields() {
    let resp = ProxyResponse::new(7, addr("9.9.9.9:80"), b"hello".to_vec());
    assert_eq!(resp.id, 7);
    assert_eq!(resp.data, b"hello");
    assert_eq!(resp.source_addr, addr("9.9.9.9:80"));
}

// ──────────────────────────────────────────────────────────
// ProxyError display
// ──────────────────────────────────────────────────────────

#[test]
fn proxy_error_display_variants() {
    assert!(ProxyError::Socks5AuthFailed.to_string().contains("SOCKS5"));
    assert!(ProxyError::Socks5UnsupportedCommand(9)
        .to_string()
        .contains('9'));
    assert!(ProxyError::Socks5UnsupportedAddressType(7)
        .to_string()
        .contains('7'));
    assert!(ProxyError::Socks4Rejected.to_string().contains("SOCKS4"));
    assert_eq!(ProxyError::Timeout.to_string(), "timeout");
    assert!(ProxyError::ConnectionDropped.to_string().contains("hook"));
    assert!(ProxyError::HttpConnectFailed("x".into())
        .to_string()
        .contains('x'));
    assert!(ProxyError::ConfigError("bad".into())
        .to_string()
        .contains("bad"));
    assert!(ProxyError::InvalidRequest("nope".into())
        .to_string()
        .contains("nope"));
    assert!(ProxyError::UpstreamFailed("u".into())
        .to_string()
        .contains('u'));
}

// ──────────────────────────────────────────────────────────
// TrafficLog
// ──────────────────────────────────────────────────────────

#[test]
fn traffic_log_basic_ops() {
    let log = TrafficLog::new(100);
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
    let req = ProxyRequest::new(1, addr("127.0.0.1:1"), addr("127.0.0.1:2"), vec![1]);
    log.log_request(&req);
    assert_eq!(log.len(), 1);
    let resp = ProxyResponse::new(1, addr("127.0.0.1:2"), vec![2]);
    log.log_response(&resp, addr("127.0.0.1:1"));
    assert_eq!(log.len(), 2);
    assert_eq!(log.entries().len(), 2);
    log.clear();
    assert!(log.is_empty());
}

#[test]
fn traffic_log_capacity_eviction() {
    let log = TrafficLog::new(2);
    for i in 0..5 {
        let req = ProxyRequest::new(i, addr("127.0.0.1:1"), addr("127.0.0.1:2"), vec![]);
        log.log_request(&req);
    }
    assert_eq!(log.len(), 2);
}

// ──────────────────────────────────────────────────────────
// SharedStats / ProxyStats
// ──────────────────────────────────────────────────────────

#[test]
fn shared_stats_counters() {
    let s = SharedStats::new();
    s.inc_connections();
    s.inc_requests(100);
    s.inc_responses(200);
    s.inc_errors();
    let snap = s.snapshot();
    assert_eq!(snap.connections, 1);
    assert_eq!(snap.requests, 1);
    assert_eq!(snap.bytes_in, 100);
    assert_eq!(snap.bytes_out, 200);
    assert_eq!(snap.errors, 1);
}

#[test]
fn proxy_stats_default_and_display() {
    let ps = ProxyStats::default();
    assert_eq!(ps.requests, 0);
    let s = ps.to_string();
    assert!(s.contains("ProxyStats"));
    assert!(s.contains("connections=0"));
}

#[test]
fn shared_stats_default_impl() {
    let s: SharedStats = SharedStats::default();
    assert_eq!(s.snapshot().requests, 0);
}

// ──────────────────────────────────────────────────────────
// HookAction (Debug / Clone)
// ──────────────────────────────────────────────────────────

#[test]
fn hook_action_clone_debug() {
    let h = HookAction::Modify(vec![1, 2, 3]);
    let _ = format!("{h:?}");
    let _ = h;
    let _ = HookAction::Forward;
    let _ = HookAction::Drop;
    let _ = HookAction::Redirect(addr("1.1.1.1:80"));
}

// ──────────────────────────────────────────────────────────
// ProxyRecord / ProxyRecordStore
// ──────────────────────────────────────────────────────────

#[test]
fn proxy_record_constructors() {
    let r = ProxyRecord::new_http("GET", "http://x/y", 200, b"ok".to_vec());
    assert_eq!(r.method, "GET");
    assert_eq!(r.response_status, 200);
    assert!(!r.is_tls);

    let r2 = ProxyRecord::new_tls("POST", "https://x/", "CN=x", 201, vec![]);
    assert!(r2.is_tls);
    assert_eq!(r2.request_headers.get("X-Cert-Subject").map(String::as_str), Some("CN=x"));
}

#[test]
fn proxy_record_store_add_and_get() {
    let store = ProxyRecordStore::new();
    assert!(store.is_empty());
    let id = store.add(ProxyRecord::new_http("GET", "http://a/", 200, vec![]));
    assert_eq!(id, 1);
    let id2 = store.add(ProxyRecord::new_http("GET", "http://b/", 200, vec![]));
    assert_eq!(id2, 2);
    assert_eq!(store.len(), 2);
    let r = store.get(id).unwrap();
    assert_eq!(r.url, "http://a/");
    assert!(store.get(999).is_none());
}

#[test]
fn proxy_record_store_filter_and_json() {
    let store = ProxyRecordStore::default();
    store.add(ProxyRecord::new_http("GET", "http://example.com/a", 200, vec![]));
    store.add(ProxyRecord::new_http("GET", "http://other.com/b", 200, vec![]));
    let filtered = store.filter_by_domain("example.com");
    assert_eq!(filtered.len(), 1);
    let json = store.to_json();
    assert!(json.is_array());
    assert_eq!(json.as_array().unwrap().len(), 2);
}

// ──────────────────────────────────────────────────────────
// HttpConnectRequest
// ──────────────────────────────────────────────────────────

#[test]
fn http_connect_parse_valid() {
    let raw = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: test\r\n\r\n";
    let r = HttpConnectRequest::parse(raw).unwrap();
    assert_eq!(r.host, "example.com");
    assert_eq!(r.port, 443);
    assert_eq!(r.http_version, "HTTP/1.1");
    assert_eq!(r.header("host"), Some("example.com:443"));
    assert_eq!(r.header("missing"), None);
}

#[test]
fn http_connect_parse_default_port() {
    let raw = "CONNECT example.com HTTP/1.1\r\n\r\n";
    let r = HttpConnectRequest::parse(raw).unwrap();
    assert_eq!(r.port, 443);
}

#[test]
fn http_connect_parse_invalid() {
    let res = HttpConnectRequest::parse("");
    assert!(matches!(res, Err(ProxyError::InvalidRequest(_))));
    let res = HttpConnectRequest::parse("GET / HTTP/1.1\r\n\r\n");
    assert!(matches!(res, Err(ProxyError::InvalidRequest(_))));
    let res = HttpConnectRequest::parse("CONNECT host:abc HTTP/1.1\r\n\r\n");
    assert!(matches!(res, Err(ProxyError::InvalidRequest(_))));
}

#[test]
fn http_connect_success_response_format() {
    let raw = "CONNECT host:1 HTTP/1.0\r\n\r\n";
    let r = HttpConnectRequest::parse(raw).unwrap();
    assert!(r.success_response().starts_with("HTTP/1.0 200"));
    let err = HttpConnectRequest::error_response(502, "Bad");
    assert!(err.starts_with("HTTP/1.1 502 Bad"));
}

// ──────────────────────────────────────────────────────────
// ACL
// ──────────────────────────────────────────────────────────

#[test]
fn acl_entry_matches() {
    let allow = AclEntry::allow_all();
    assert!(allow.matches("anything", 80));
    let deny = AclEntry::deny_host("evil.com");
    assert!(deny.matches("evil.com", 443));
    assert!(deny.matches("EVIL.COM", 80));
    assert!(!deny.matches("good.com", 80));
}

#[test]
fn acl_evaluate_default_and_rules() {
    let mut acl = ProxyAcl::new(AclAction::Deny);
    assert!(acl.is_empty());
    assert_eq!(acl.evaluate("x", 80), AclAction::Deny);
    acl.add(AclEntry::allow_all());
    assert_eq!(acl.len(), 1);
    assert_eq!(acl.evaluate("x", 80), AclAction::Allow);
}

#[test]
fn acl_action_display_and_default() {
    assert_eq!(AclAction::Allow.to_string(), "ALLOW");
    assert_eq!(AclAction::Deny.to_string(), "DENY");
    assert_eq!(AclAction::default(), AclAction::Allow);
}

// ──────────────────────────────────────────────────────────
// MitmConfig
// ──────────────────────────────────────────────────────────

#[test]
fn mitm_config_disabled_and_enabled() {
    let d = MitmConfig::disabled();
    assert!(!d.enabled);
    assert!(!d.should_intercept("x"));
    let mut e = MitmConfig::enabled("ca.crt", "ca.key");
    assert!(e.enabled);
    assert!(e.should_intercept("x"));
    e.exclude("skip.me");
    assert!(e.is_excluded("SKIP.ME"));
    assert!(!e.should_intercept("skip.me"));
    assert!(e.should_intercept("other.com"));
}

// ──────────────────────────────────────────────────────────
// Modifiers
// ──────────────────────────────────────────────────────────

#[test]
fn search_replace_modifier_basic() {
    let m = SearchReplaceModifier::new(b"foo".to_vec(), b"bar".to_vec());
    let mut data = b"a foo b foo".to_vec();
    assert!(m.modify(&mut data));
    assert_eq!(data, b"a bar b bar");
    assert_eq!(m.name(), "search-replace");
}

#[test]
fn search_replace_no_match_returns_false() {
    let m = SearchReplaceModifier::new(b"xyz".to_vec(), b"q".to_vec());
    let mut data = b"hello".to_vec();
    assert!(!m.modify(&mut data));
    assert_eq!(data, b"hello");
}

#[test]
fn search_replace_empty_search_no_op() {
    let m = SearchReplaceModifier::new(vec![], b"q".to_vec());
    let mut data = b"abc".to_vec();
    assert!(!m.modify(&mut data));
    assert_eq!(data, b"abc");
}

#[test]
fn header_injector_inserts_at_blank_line() {
    let m = HeaderInjector::new("X-Test", "yes");
    let mut data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nBODY".to_vec();
    assert!(m.modify(&mut data));
    let s = String::from_utf8(data).unwrap();
    assert!(s.contains("X-Test: yes"));
    assert!(s.ends_with("BODY"));
    assert_eq!(m.name(), "header-injector");
}

#[test]
fn header_injector_no_terminator() {
    let m = HeaderInjector::new("X-Test", "v");
    let mut data = b"no terminator".to_vec();
    assert!(!m.modify(&mut data));
}

#[test]
fn modifier_pipeline_runs_all() {
    let mut p = ModifierPipeline::new();
    assert!(p.is_empty());
    p.push(Box::new(SearchReplaceModifier::new(b"a".to_vec(), b"A".to_vec())));
    p.push(Box::new(SearchReplaceModifier::new(b"b".to_vec(), b"B".to_vec())));
    assert_eq!(p.len(), 2);
    let mut data = b"abc".to_vec();
    assert!(p.apply(&mut data));
    assert_eq!(data, b"ABc");
}

#[test]
fn modifier_pipeline_default_is_empty() {
    let p = ModifierPipeline::default();
    assert!(p.is_empty());
}

// ──────────────────────────────────────────────────────────
// TrafficRecord / TrafficRecorder
// ──────────────────────────────────────────────────────────

#[test]
fn traffic_record_as_str_and_display() {
    use rustre_net_proxy::Direction;
    let r = TrafficRecord::new(1, Direction::Request, b"hi".to_vec(), "peer:1");
    assert_eq!(r.as_str(), "hi");
    let s = r.to_string();
    assert!(s.contains("session=1"));
}

#[test]
fn traffic_recorder_capacity() {
    use rustre_net_proxy::Direction;
    let rec = TrafficRecorder::new(2);
    assert!(rec.is_empty());
    for i in 0..5 {
        rec.record(TrafficRecord::new(i, Direction::Request, vec![1, 2], "p"));
    }
    assert_eq!(rec.len(), 2);
    assert_eq!(rec.total_bytes(), 4);
    let all = rec.all();
    assert_eq!(all.len(), 2);
    let r1 = rec.for_session(4);
    assert_eq!(r1.len(), 1);
    rec.clear();
    assert!(rec.is_empty());
}

// ──────────────────────────────────────────────────────────
// SessionManager
// ──────────────────────────────────────────────────────────

#[test]
fn session_manager_lifecycle() {
    use rustre_net_proxy::ProxyProtocol;
    let mgr = SessionManager::new();
    let id = mgr.new_session("c", "t", ProxyProtocol::Http);
    assert_eq!(id, 1);
    let e = mgr.get(id).unwrap();
    assert_eq!(e.state, SessionState::Connecting);
    assert!(e.is_active());
    mgr.add_bytes(id, 10, 20);
    let e2 = mgr.get(id).unwrap();
    assert_eq!(e2.bytes_in, 10);
    assert_eq!(e2.bytes_out, 20);
    mgr.set_state(id, SessionState::Closed);
    assert!(!mgr.get(id).unwrap().is_active());
    assert_eq!(mgr.active().len(), 0);
    mgr.prune();
    assert_eq!(mgr.total(), 0);
}

#[test]
fn session_state_display() {
    assert_eq!(SessionState::Connecting.to_string(), "Connecting");
}

#[test]
fn session_manager_default_works() {
    let m = SessionManager::default();
    assert_eq!(m.total(), 0);
}

// ──────────────────────────────────────────────────────────
// inject_xff_headers
// ──────────────────────────────────────────────────────────

#[test]
fn inject_xff_headers_modifies() {
    let mut data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
    assert!(inject_xff_headers(&mut data, "1.2.3.4", "proxy"));
    let s = String::from_utf8(data).unwrap();
    assert!(s.contains("X-Forwarded-For: 1.2.3.4"));
    assert!(s.contains("Via: 1.1 proxy"));
}

#[test]
fn inject_xff_headers_no_terminator() {
    let mut data = b"junk".to_vec();
    assert!(!inject_xff_headers(&mut data, "1.1.1.1", "p"));
}

// ──────────────────────────────────────────────────────────
// HttpMethod
// ──────────────────────────────────────────────────────────

#[test]
fn http_method_from_str_and_display() {
    assert_eq!(HttpMethod::from_str("get"), HttpMethod::Get);
    assert_eq!(HttpMethod::from_str("XYZ"), HttpMethod::Other("XYZ".to_string()));
    assert_eq!(HttpMethod::Post.to_string(), "POST");
    assert_eq!(HttpMethod::Other("X".to_string()).to_string(), "X");
}

#[test]
fn http_method_idempotent_and_body() {
    assert!(HttpMethod::Get.is_idempotent());
    assert!(HttpMethod::Put.is_idempotent());
    assert!(!HttpMethod::Post.is_idempotent());
    assert!(HttpMethod::Post.has_body());
    assert!(!HttpMethod::Get.has_body());
}

#[test]
fn http_method_fromstr_trait() {
    use std::str::FromStr;
    let m: HttpMethod = HttpMethod::from_str("POST");
    assert_eq!(m, HttpMethod::Post);
    let m2: HttpMethod = <HttpMethod as FromStr>::from_str("delete").unwrap();
    assert_eq!(m2, HttpMethod::Delete);
}

// ──────────────────────────────────────────────────────────
// HttpRequestLine / HttpStatusLine
// ──────────────────────────────────────────────────────────

#[test]
fn http_request_line_parse() {
    let r = HttpRequestLine::parse("GET /path HTTP/1.1").unwrap();
    assert_eq!(r.method, HttpMethod::Get);
    assert_eq!(r.uri, "/path");
    assert!(r.is_http11());
    assert!(!r.is_http2());
    assert_eq!(r.to_string(), "GET /path HTTP/1.1");
}

#[test]
fn http_request_line_invalid() {
    assert!(matches!(
        HttpRequestLine::parse("GET"),
        Err(ProxyError::InvalidRequest(_))
    ));
}

#[test]
fn http_status_line_parse_and_categories() {
    let s = HttpStatusLine::parse("HTTP/1.1 200 OK").unwrap();
    assert_eq!(s.code, 200);
    assert!(s.is_success());
    assert!(!s.is_redirect());
    let r = HttpStatusLine::parse("HTTP/1.1 301 Moved").unwrap();
    assert!(r.is_redirect());
    let c = HttpStatusLine::parse("HTTP/1.1 404 NF").unwrap();
    assert!(c.is_client_error());
    let s5 = HttpStatusLine::parse("HTTP/1.1 500 Boom").unwrap();
    assert!(s5.is_server_error());
}

#[test]
fn http_status_line_invalid() {
    assert!(matches!(
        HttpStatusLine::parse("nope"),
        Err(ProxyError::InvalidRequest(_))
    ));
    assert!(matches!(
        HttpStatusLine::parse("HTTP/1.1 ABC"),
        Err(ProxyError::InvalidRequest(_))
    ));
}

// ──────────────────────────────────────────────────────────
// RateLimiter
// ──────────────────────────────────────────────────────────

#[test]
fn rate_limiter_connections() {
    let r = RateLimiter::new(1000, 2);
    assert!(r.try_connect());
    assert!(r.try_connect());
    assert!(!r.try_connect());
    assert_eq!(r.active_connections(), 2);
    r.release_connection();
    assert_eq!(r.active_connections(), 1);
    assert!(r.try_connect());
}

#[test]
fn rate_limiter_bytes_window() {
    let r = RateLimiter::new(100, 10);
    assert!(r.try_send_bytes(0, 50));
    assert!(r.try_send_bytes(500, 50));
    assert!(!r.try_send_bytes(600, 1));
    // New window
    assert!(r.try_send_bytes(2000, 100));
    assert_eq!(r.bytes_this_window(), 100);
}

// ──────────────────────────────────────────────────────────
// DnsCache
// ──────────────────────────────────────────────────────────

#[test]
fn dns_cache_lookup_and_expire() {
    let c = DnsCache::new();
    assert!(c.is_empty());
    c.insert("h", "1.1.1.1", 0, 10);
    assert_eq!(c.lookup("h", 5000), Some("1.1.1.1".to_string()));
    assert!(c.lookup("h", 11_000).is_none());
    assert_eq!(c.len(), 1);
    assert_eq!(c.evict_expired(20_000), 1);
    assert!(c.is_empty());
}

#[test]
fn dns_cache_entry_is_valid() {
    let e = DnsCacheEntry::new("1.2.3.4", 1000, 5);
    assert!(e.is_valid(2000));
    assert!(!e.is_valid(7000));
}

#[test]
fn dns_cache_clear() {
    let c = DnsCache::default();
    c.insert("a", "0.0.0.0", 0, 60);
    c.clear();
    assert!(c.is_empty());
}

// ──────────────────────────────────────────────────────────
// ConnectionMetrics
// ──────────────────────────────────────────────────────────

#[test]
fn connection_metrics_accumulate() {
    let mut m = ConnectionMetrics::new(1000);
    m.add_client_in(10);
    m.add_client_out(20);
    m.add_upstream_in(30);
    m.add_upstream_out(40);
    m.inc_round_trips();
    assert_eq!(m.total_bytes(), 100);
    assert_eq!(m.round_trips, 1);
    assert_eq!(m.duration_ms(), 0);
    m.close(1500);
    assert_eq!(m.duration_ms(), 500);
    let s = m.to_string();
    assert!(s.contains("client_in=10"));
}

// ──────────────────────────────────────────────────────────
// HeaderRewriter
// ──────────────────────────────────────────────────────────

#[test]
fn header_rewrite_rule_set_and_remove() {
    let set = HeaderRewriteRule::set("X-A", "v");
    let headers = "Host: x\r\nX-A: old";
    let out = set.apply(headers);
    assert!(out.contains("X-A: v"));
    assert!(!out.contains("X-A: old"));
    let rm = HeaderRewriteRule::remove("X-A");
    let out2 = rm.apply(&out);
    assert!(!out2.contains("X-A"));
}

#[test]
fn header_rewrite_rule_adds_if_missing() {
    let set = HeaderRewriteRule::set("X-B", "v");
    let out = set.apply("Host: x");
    assert!(out.contains("X-B: v"));
}

#[test]
fn header_rewrite_rule_display() {
    assert_eq!(HeaderRewriteRule::set("X", "y").to_string(), "SET X: y");
    assert_eq!(HeaderRewriteRule::remove("X").to_string(), "REMOVE X");
}

#[test]
fn header_rewriter_chain() {
    let mut rw = HeaderRewriter::new();
    assert!(rw.is_empty());
    rw.add_rule(HeaderRewriteRule::set("A", "1"));
    rw.add_rule(HeaderRewriteRule::set("B", "2"));
    assert_eq!(rw.rule_count(), 2);
    let out = rw.apply_all("Host: x");
    assert!(out.contains("A: 1"));
    assert!(out.contains("B: 2"));
}

// ──────────────────────────────────────────────────────────
// Socks5UdpHeader
// ──────────────────────────────────────────────────────────

#[test]
fn socks5_udp_header_parse_ipv4() {
    let mut data = vec![0, 0, 0, 1, 1, 2, 3, 4];
    data.extend_from_slice(&80u16.to_be_bytes());
    let h = Socks5UdpHeader::parse(&data).unwrap();
    assert_eq!(h.atyp, 1);
    assert_eq!(h.dst_addr, "1.2.3.4");
    assert_eq!(h.dst_port, 80);
    assert_eq!(h.frag, 0);
}

#[test]
fn socks5_udp_header_parse_domain() {
    let mut data = vec![0, 0, 0, 3, 3];
    data.extend_from_slice(b"foo");
    data.extend_from_slice(&443u16.to_be_bytes());
    let h = Socks5UdpHeader::parse(&data).unwrap();
    assert_eq!(h.atyp, 3);
    assert_eq!(h.dst_addr, "foo");
    assert_eq!(h.dst_port, 443);
}

#[test]
fn socks5_udp_header_too_short() {
    assert!(matches!(
        Socks5UdpHeader::parse(&[0, 0, 0]),
        Err(ProxyError::InvalidRequest(_))
    ));
}

#[test]
fn socks5_udp_header_bad_atyp() {
    let data = vec![0, 0, 0, 9, 0, 0, 0];
    assert!(matches!(
        Socks5UdpHeader::parse(&data),
        Err(ProxyError::Socks5UnsupportedAddressType(9))
    ));
}

// ──────────────────────────────────────────────────────────
// hex_encode / hex_decode
// ──────────────────────────────────────────────────────────

#[test]
fn hex_encode_decode_roundtrip() {
    let bytes = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0xff];
    let s = hex_encode(&bytes);
    assert_eq!(s, "deadbeef00ff");
    assert_eq!(hex_decode(&s), Some(bytes));
}

#[test]
fn hex_decode_uppercase_and_invalid() {
    assert_eq!(hex_decode("AB"), Some(vec![0xab]));
    assert_eq!(hex_decode(""), Some(vec![]));
    assert!(hex_decode("a").is_none());
    assert!(hex_decode("zz").is_none());
}

// ──────────────────────────────────────────────────────────
// base64_decode
// ──────────────────────────────────────────────────────────

#[test]
fn base64_decode_basic() {
    assert_eq!(base64_decode("aGVsbG8="), Some(b"hello".to_vec()));
    assert_eq!(base64_decode(""), Some(vec![]));
    assert!(base64_decode("!!!").is_none());
}

// ──────────────────────────────────────────────────────────
// glob_match
// ──────────────────────────────────────────────────────────

#[test]
fn glob_match_basic() {
    assert!(glob_match("*.txt", "foo.txt"));
    assert!(!glob_match("*.txt", "foo.md"));
    assert!(glob_match("**/foo", "a/b/foo"));
    assert!(glob_match("foo", "foo"));
    assert!(!glob_match("foo", "bar"));
}

// ──────────────────────────────────────────────────────────
// simple_regex_match
// ──────────────────────────────────────────────────────────

#[test]
fn simple_regex_match_basic() {
    assert!(simple_regex_match("abc", "xabcx"));
    assert!(simple_regex_match("^abc$", "abc"));
    assert!(!simple_regex_match("^abc$", "xabc"));
    assert!(simple_regex_match("a.c", "abc"));
    assert!(simple_regex_match("a*b", "aaab"));
    assert!(simple_regex_match("[0-9]+", "abc123"));
    assert!(!simple_regex_match("[^a-z]+", "abc"));
}

// ──────────────────────────────────────────────────────────
// Match/replace rules
// ──────────────────────────────────────────────────────────

#[test]
fn apply_rules_empty_no_changes() {
    use rustre_net_proxy::HttpRequest as LibReq;
    use rustre_net_proxy::HttpResponse as LibResp;
    let mut req = LibReq::get("http://x/");
    assert_eq!(apply_rules_to_request(&[], &mut req), 0);
    let mut resp = LibResp::ok();
    assert_eq!(apply_rules_to_response(&[], &mut resp), 0);
}

#[test]
fn http_request_header_helpers() {
    use rustre_net_proxy::HttpRequest as LibReq;
    let mut r = LibReq::get("http://x/");
    r.set_header("X", "1");
    assert_eq!(r.header("x"), Some("1"));
    r.set_header("X", "2");
    assert_eq!(r.header("x"), Some("2"));
    assert!(r.remove_header("X"));
    assert!(r.header("X").is_none());
    assert!(!r.remove_header("X"));
}

#[test]
fn http_response_helpers() {
    use rustre_net_proxy::HttpResponse as LibResp;
    let mut r = LibResp::ok();
    assert!(r.is_success());
    r.set_header("A", "b");
    assert_eq!(r.header("a"), Some("b"));
    r.status = 500;
    assert!(!r.is_success());
}

// ──────────────────────────────────────────────────────────
// Send/Sync bounds
// ──────────────────────────────────────────────────────────

#[test]
fn key_types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ProxyConfig>();
    assert_send_sync::<ProxyStats>();
    assert_send_sync::<SharedStats>();
    assert_send_sync::<TrafficLog>();
    assert_send_sync::<ProxyRecordStore>();
    assert_send_sync::<DnsCache>();
    assert_send_sync::<SessionManager>();
    assert_send_sync::<RateLimiter>();
    assert_send_sync::<ProxyAcl>();
    assert_send_sync::<MitmConfig>();
    assert_send_sync::<TrafficRecorder>();
}

// ──────────────────────────────────────────────────────────
// Make sure HashMap-based record headers serialize
// ──────────────────────────────────────────────────────────

#[test]
fn proxy_record_serde_roundtrip() {
    let mut h = HashMap::new();
    h.insert("a".to_string(), "b".to_string());
    let r = ProxyRecord::new("GET", "http://x/", h, vec![1], 200, vec![2], false);
    let json = serde_json::to_string(&r).unwrap();
    let r2: ProxyRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(r2.method, "GET");
    assert_eq!(r2.url, "http://x/");
    assert_eq!(r2.request_headers.get("a").map(String::as_str), Some("b"));
}
