//! Deep adversarial tests for rustre-mcp-federation public API.

use rustre_mcp_federation::*;
use serde_json::json;
use std::sync::Arc;
use std::thread;

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

// ── ServerTransport ─────────────────────────────────────────────────────────

#[test]
fn transport_type_strings() {
    let stdio = ServerTransport::Stdio {
        command: "cmd".into(),
        args: vec![],
        env: Default::default(),
    };
    assert_eq!(stdio.transport_type(), "stdio");
    assert!(stdio.is_local());

    let http = ServerTransport::SseHttp {
        url: "http://x".into(),
        headers: Default::default(),
        timeout_secs: 5,
    };
    assert_eq!(http.transport_type(), "sse_http");
    assert!(!http.is_local());

    let ws = ServerTransport::WebSocket {
        url: "ws://x".into(),
        headers: Default::default(),
    };
    assert_eq!(ws.transport_type(), "websocket");
    assert!(!ws.is_local());

    let unix = ServerTransport::UnixSocket { path: "/p".into() };
    assert_eq!(unix.transport_type(), "unix_socket");
    assert!(unix.is_local());
}

// ── ExternalServerConfig ────────────────────────────────────────────────────

#[test]
fn external_server_config_builder() {
    let c = ExternalServerConfig::new_stdio("s1", "cmd")
        .with_description("desc")
        .with_tag("a")
        .with_tag("b");
    assert_eq!(c.name, "s1");
    assert_eq!(c.description, "desc");
    assert!(c.has_tag("a"));
    assert!(c.has_tag("b"));
    assert!(!c.has_tag("c"));
    assert!(c.enabled);
}

#[test]
fn external_server_config_http_and_disabled() {
    let c = ExternalServerConfig::new_http("h", "http://x:1").disabled();
    assert!(!c.enabled);
    match c.transport {
        ServerTransport::SseHttp { ref url, timeout_secs, .. } => {
            assert_eq!(url, "http://x:1");
            assert_eq!(timeout_secs, 30);
        }
        _ => panic!("wrong transport"),
    }
}

// ── glob via RoutingRule.matches ────────────────────────────────────────────

#[test]
fn glob_exact_match() {
    let r = RoutingRule::new("foo", RouteTarget::Broadcast, 0);
    assert!(r.matches("foo"));
    assert!(!r.matches("foob"));
    assert!(!r.matches(""));
}

#[test]
fn glob_star_match() {
    let r = RoutingRule::new("foo.*", RouteTarget::Broadcast, 0);
    assert!(r.matches("foo.bar"));
    assert!(r.matches("foo."));
    assert!(!r.matches("fo.bar"));
}

#[test]
fn glob_question_mark() {
    let r = RoutingRule::new("a?b", RouteTarget::Broadcast, 0);
    assert!(r.matches("axb"));
    assert!(r.matches("a1b"));
    assert!(!r.matches("ab"));
    assert!(!r.matches("axxb"));
}

#[test]
fn glob_multi_star() {
    let r = RoutingRule::new("****x", RouteTarget::Broadcast, 0);
    assert!(r.matches("x"));
    assert!(r.matches("aaax"));
    assert!(!r.matches("xa"));
}

#[test]
fn glob_universal() {
    let r = RoutingRule::new("*", RouteTarget::Broadcast, 0);
    assert!(r.matches(""));
    assert!(r.matches("anything"));
    let mut g = lcg();
    for _ in 0..60 {
        let v = g();
        let s = format!("{:x}", v);
        assert!(r.matches(&s));
    }
}

#[test]
fn glob_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..200 {
        let pat_len = (g() % 8) as usize;
        let inp_len = (g() % 16) as usize;
        let charset: &[u8] = b"abc*?.";
        let pat: String = (0..pat_len)
            .map(|_| charset[(g() as usize) % charset.len()] as char)
            .collect();
        let inp: String = (0..inp_len)
            .map(|_| charset[(g() as usize) % charset.len()] as char)
            .collect();
        let r = RoutingRule::new(&pat, RouteTarget::Broadcast, 0);
        let _ = r.matches(&inp);
    }
}

// ── RouteTarget Display ─────────────────────────────────────────────────────

#[test]
fn route_target_display() {
    assert_eq!(
        RouteTarget::Server("s".into()).to_string(),
        "server:s"
    );
    assert_eq!(
        RouteTarget::ServerGroup(vec!["a".into(), "b".into()]).to_string(),
        "group:[a,b]"
    );
    assert_eq!(RouteTarget::Broadcast.to_string(), "broadcast");
    assert_eq!(RouteTarget::FirstSuccess.to_string(), "first_success");
}

// ── FederationConfig ────────────────────────────────────────────────────────

#[test]
fn federation_config_new_default() {
    let c = FederationConfig::new();
    assert!(c.servers.is_empty());
    assert!(c.routing_rules.is_empty());
    assert_eq!(c.max_concurrent_calls, 16);
    assert_eq!(c.call_timeout_secs, 30);
}

#[test]
fn federation_config_toml_roundtrip() {
    let c = FederationConfig::default_config();
    let s = c.to_toml().unwrap();
    let back = FederationConfig::from_toml(&s).unwrap();
    assert_eq!(c.servers.len(), back.servers.len());
    assert_eq!(c.fallback_server, back.fallback_server);
    assert_eq!(c.routing_rules.len(), back.routing_rules.len());
}

#[test]
fn federation_config_from_toml_invalid() {
    let res = FederationConfig::from_toml("not valid toml ===");
    assert!(matches!(res, Err(ConfigError::TomlParse(_))));
}

#[test]
fn federation_config_from_json_roundtrip() {
    let mut c = FederationConfig::new();
    c.servers.push(ExternalServerConfig::new_stdio("s", "c"));
    let s = serde_json::to_string(&c).unwrap();
    let back = FederationConfig::from_json(&s).unwrap();
    assert_eq!(back.servers.len(), 1);
}

#[test]
fn federation_config_from_json_invalid() {
    let res = FederationConfig::from_json("{not json");
    assert!(matches!(res, Err(ConfigError::JsonParse(_))));
}

#[test]
fn federation_config_validate_empty_name() {
    let mut c = FederationConfig::new();
    c.servers.push(ExternalServerConfig::new_stdio("", "cmd"));
    let errs = c.validate();
    assert!(errs.iter().any(|e| e.field.starts_with("server.name")));
}

#[test]
fn federation_config_validate_duplicate_names() {
    let mut c = FederationConfig::new();
    c.servers.push(ExternalServerConfig::new_stdio("dup", "c"));
    c.servers.push(ExternalServerConfig::new_stdio("dup", "c"));
    let errs = c.validate();
    assert!(errs.iter().any(|e| e.message.contains("duplicate")));
}

#[test]
fn federation_config_validate_unknown_fallback() {
    let mut c = FederationConfig::new();
    c.servers.push(ExternalServerConfig::new_stdio("a", "c"));
    c.fallback_server = Some("missing".into());
    let errs = c.validate();
    assert!(errs.iter().any(|e| e.field == "fallback_server"));
}

#[test]
fn federation_config_validate_unknown_route_server() {
    let mut c = FederationConfig::new();
    c.servers.push(ExternalServerConfig::new_stdio("a", "c"));
    c.routing_rules.push(RoutingRule::new(
        "*",
        RouteTarget::Server("missing".into()),
        1,
    ));
    let errs = c.validate();
    assert!(!errs.is_empty());
}

#[test]
fn federation_config_validate_unknown_group_member() {
    let mut c = FederationConfig::new();
    c.servers.push(ExternalServerConfig::new_stdio("a", "c"));
    c.routing_rules.push(RoutingRule::new(
        "*",
        RouteTarget::ServerGroup(vec!["a".into(), "missing".into()]),
        1,
    ));
    let errs = c.validate();
    assert!(errs.iter().any(|e| e.message.contains("missing")));
}

#[test]
fn federation_config_validate_zero_max_concurrent() {
    let mut c = FederationConfig::new();
    c.max_concurrent_calls = 0;
    let errs = c.validate();
    assert!(errs.iter().any(|e| e.field == "max_concurrent_calls"));
}

#[test]
fn federation_config_validate_default_ok() {
    let c = FederationConfig::default_config();
    let errs = c.validate();
    assert!(errs.is_empty(), "errors: {:?}", errs);
}

#[test]
fn federation_config_add_remove_get() {
    let mut c = FederationConfig::new();
    c.add_server(ExternalServerConfig::new_stdio("x", "c"));
    assert!(c.get_server("x").is_some());
    assert!(c.get_server("y").is_none());
    assert!(c.remove_server("x"));
    assert!(!c.remove_server("x"));
    assert!(c.get_server("x").is_none());
}

#[test]
fn federation_config_enabled_and_by_tag() {
    let mut c = FederationConfig::new();
    c.add_server(
        ExternalServerConfig::new_stdio("a", "c")
            .with_tag("t1"),
    );
    c.add_server(
        ExternalServerConfig::new_stdio("b", "c")
            .with_tag("t1")
            .disabled(),
    );
    assert_eq!(c.enabled_servers().len(), 1);
    assert_eq!(c.servers_by_tag("t1").len(), 2);
    assert_eq!(c.servers_by_tag("none").len(), 0);
}

// ── ConfigValidationError Display ───────────────────────────────────────────

#[test]
fn config_validation_error_display() {
    let e = ConfigValidationError {
        field: "f".into(),
        message: "m".into(),
    };
    assert_eq!(e.to_string(), "f: m");
}

// ── FederatedTool / ToolRegistry ────────────────────────────────────────────

#[test]
fn federated_tool_local_and_remote() {
    let lt = FederatedTool::new_local("t", "d", json!({}));
    assert!(lt.is_local);
    assert_eq!(lt.qualified_name, "local.t");
    assert_eq!(lt.server_name, "local");

    let rt = FederatedTool::new_remote("srv", "t", "d", json!({}));
    assert!(!rt.is_local);
    assert_eq!(rt.qualified_name, "srv.t");
    assert_eq!(rt.server_name, "srv");
}

#[test]
fn tool_registry_find_and_search() {
    let mut reg = ToolRegistry::new();
    reg.register_local(FederatedTool::new_local("ping", "ping desc", json!({})));
    reg.register_remote(
        "ghidra",
        vec![FederatedTool::new_remote(
            "ghidra",
            "disasm.at",
            "disassemble at",
            json!({}),
        )],
    );
    assert!(reg.find_tool("ping").is_some());
    assert!(reg.find_tool("local.ping").is_some());
    assert!(reg.find_tool("disasm.at").is_some());
    assert!(reg.find_tool("ghidra.disasm.at").is_some());
    assert!(reg.find_tool("nope").is_none());

    assert_eq!(reg.total_tool_count(), 2);
    assert_eq!(reg.server_count(), 2); // 1 remote + 1 local
    assert!(reg.has_server("ghidra"));
    assert!(!reg.has_server("x"));

    let s = reg.search_tools("DISASM");
    assert_eq!(s.len(), 1);
    let s2 = reg.search_tools("nomatch");
    assert!(s2.is_empty());

    let cat = reg.tools_for_category("disasm");
    assert_eq!(cat.len(), 1);

    reg.clear_server("ghidra");
    assert!(!reg.has_server("ghidra"));
    assert_eq!(reg.total_tool_count(), 1);
}

#[test]
fn tool_registry_list_by_server() {
    let mut reg = ToolRegistry::new();
    reg.register_local(FederatedTool::new_local("l1", "", json!({})));
    reg.register_remote(
        "s",
        vec![FederatedTool::new_remote("s", "r1", "", json!({}))],
    );
    assert_eq!(reg.list_by_server("local").len(), 1);
    assert_eq!(reg.list_by_server("s").len(), 1);
    assert_eq!(reg.list_by_server("unknown").len(), 0);
}

#[test]
fn tool_registry_server_count_no_local() {
    let mut reg = ToolRegistry::new();
    reg.register_remote(
        "s",
        vec![FederatedTool::new_remote("s", "r", "", json!({}))],
    );
    assert_eq!(reg.server_count(), 1);
}

#[test]
fn tool_registry_default() {
    let reg = ToolRegistry::default();
    assert_eq!(reg.total_tool_count(), 0);
}

// ── ToolRouter / RoutingDecision ────────────────────────────────────────────

#[test]
fn router_routes_by_pattern() {
    let mut cfg = FederationConfig::new();
    cfg.servers
        .push(ExternalServerConfig::new_stdio("frida", "f"));
    cfg.routing_rules.push(RoutingRule::new(
        "frida.*",
        RouteTarget::Server("frida".into()),
        100,
    ));
    let r = ToolRouter::new(cfg);
    let d = r.route("frida.attach");
    assert!(d.is_routable());
    assert_eq!(d.primary_server(), Some("frida"));
    assert!(r.can_route("frida.attach"));
}

#[test]
fn router_fallback_when_no_rule_matches() {
    let mut cfg = FederationConfig::new();
    cfg.servers
        .push(ExternalServerConfig::new_stdio("s", "c"));
    cfg.fallback_server = Some("s".into());
    let r = ToolRouter::new(cfg);
    let d = r.route("unmatched");
    assert!(d.is_routable());
    assert_eq!(d.primary_server(), Some("s"));
}

#[test]
fn router_unroutable() {
    let cfg = FederationConfig::new();
    let r = ToolRouter::new(cfg);
    let d = r.route("nothing");
    assert!(!d.is_routable());
    assert_eq!(d.primary_server(), None);
    assert!(!r.can_route("nothing"));
}

#[test]
fn router_prefer_local_uses_registry() {
    let mut cfg = FederationConfig::new();
    cfg.routing_rules.push(RoutingRule::new(
        "*",
        RouteTarget::Server("remote".into()),
        100,
    ));
    cfg.servers
        .push(ExternalServerConfig::new_stdio("remote", "c"));
    let mut reg = ToolRegistry::new();
    reg.register_local(FederatedTool::new_local("mytool", "", json!({})));
    let r = ToolRouter::with_registry(cfg, reg);
    let ctx = RoutingContext::new("test").prefer_local();
    let d = r.route_with_context("mytool", &ctx);
    assert_eq!(d.primary_server(), Some("local"));
}

#[test]
fn router_priority_order() {
    let mut cfg = FederationConfig::new();
    cfg.servers
        .push(ExternalServerConfig::new_stdio("low", "c"));
    cfg.servers
        .push(ExternalServerConfig::new_stdio("high", "c"));
    cfg.routing_rules.push(RoutingRule::new(
        "*",
        RouteTarget::Server("low".into()),
        1,
    ));
    cfg.routing_rules.push(RoutingRule::new(
        "*",
        RouteTarget::Server("high".into()),
        100,
    ));
    let r = ToolRouter::new(cfg);
    let d = r.route("anything");
    assert_eq!(d.primary_server(), Some("high"));
}

#[test]
fn routing_context_builder() {
    let ctx = RoutingContext::new("c").with_priority(5).prefer_local();
    assert_eq!(ctx.caller_id, "c");
    assert_eq!(ctx.priority, Some(5));
    assert!(ctx.prefer_local);
}

// ── HealthStatus / HealthCheck / ServerHealth ───────────────────────────────

#[test]
fn health_status_display_roundtrip_like() {
    assert_eq!(HealthStatus::Unknown.to_string(), "unknown");
    assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
    assert_eq!(HealthStatus::Degraded.to_string(), "degraded");
    assert_eq!(HealthStatus::Unhealthy.to_string(), "unhealthy");
    assert_eq!(HealthStatus::Unreachable.to_string(), "unreachable");
}

#[test]
fn health_status_eq_pairs() {
    let cases = [
        HealthStatus::Unknown,
        HealthStatus::Healthy,
        HealthStatus::Degraded,
        HealthStatus::Unhealthy,
        HealthStatus::Unreachable,
    ];
    let mut pairs = 0;
    for a in &cases {
        for b in &cases {
            if a == b {
                assert_eq!(a.clone(), b.clone());
            } else {
                assert_ne!(a.clone(), b.clone());
            }
            pairs += 1;
        }
    }
    assert!(pairs >= 25);
}

#[test]
fn health_check_success_failure() {
    let s = HealthCheck::success(123, 10);
    assert_eq!(s.status, HealthStatus::Healthy);
    assert_eq!(s.response_ms, 10);
    assert!(s.error.is_none());

    let f = HealthCheck::failure(456, "boom");
    assert_eq!(f.status, HealthStatus::Unreachable);
    assert_eq!(f.response_ms, 0);
    assert_eq!(f.error.as_deref(), Some("boom"));
}

#[test]
fn server_health_new_unknown() {
    let h = ServerHealth::new("s");
    assert_eq!(h.status, HealthStatus::Unknown);
    assert!(!h.is_available());
    assert_eq!(h.uptime_pct, 100.0);
}

// ── HealthMonitor ───────────────────────────────────────────────────────────

#[test]
fn health_monitor_record_and_state() {
    let mut m = HealthMonitor::new(5);
    for i in 0..3 {
        m.record_check("s", HealthCheck::success(i, 10));
    }
    let h = m.get_health("s").unwrap();
    assert_eq!(h.status, HealthStatus::Healthy);
    assert_eq!(h.consecutive_failures, 0);
    assert!((h.uptime_pct - 100.0).abs() < 1e-9);
    assert!((h.avg_response_ms - 10.0).abs() < 1e-9);
}

#[test]
fn health_monitor_history_trim() {
    let mut m = HealthMonitor::new(3);
    for i in 0..10 {
        m.record_check("s", HealthCheck::success(i, 1));
    }
    assert_eq!(m.get_history("s").len(), 3);
}

#[test]
fn health_monitor_consecutive_failures_and_status_tiers() {
    let mut m = HealthMonitor::new(100);
    m.trigger_health_check_logic("s", true, 5);
    assert_eq!(m.get_health("s").unwrap().status, HealthStatus::Healthy);

    m.trigger_health_check_logic("s", false, 0);
    assert_eq!(m.get_health("s").unwrap().status, HealthStatus::Degraded);
    m.trigger_health_check_logic("s", false, 0);
    assert_eq!(m.get_health("s").unwrap().status, HealthStatus::Degraded);

    m.trigger_health_check_logic("s", false, 0);
    assert_eq!(m.get_health("s").unwrap().status, HealthStatus::Unhealthy);
    m.trigger_health_check_logic("s", false, 0);
    m.trigger_health_check_logic("s", false, 0);
    assert_eq!(m.get_health("s").unwrap().status, HealthStatus::Unhealthy);

    m.trigger_health_check_logic("s", false, 0);
    assert_eq!(m.get_health("s").unwrap().status, HealthStatus::Unreachable);
}

#[test]
fn health_monitor_healthy_unhealthy_lists() {
    let mut m = HealthMonitor::new(10);
    m.record_check("good", HealthCheck::success(1, 5));
    m.record_check("bad", HealthCheck::failure(1, "x"));
    let healthy = m.healthy_servers();
    let unhealthy = m.unhealthy_servers();
    assert!(healthy.contains(&"good"));
    assert!(unhealthy.contains(&"bad"));
    let avail = m.availability_report();
    assert!(avail.contains_key("good"));
    assert!(avail.contains_key("bad"));
    let known = m.known_servers();
    assert_eq!(known.len(), 2);
}

#[test]
fn health_monitor_unknown_lookup() {
    let m = HealthMonitor::new(5);
    assert!(m.get_health("nope").is_none());
    assert!(m.get_history("nope").is_empty());
}

// ── CallAggregator ──────────────────────────────────────────────────────────

#[test]
fn aggregator_merge_results() {
    let v = CallAggregator::merge_results(vec![
        ("s1".into(), json!({"a": 1})),
        ("s2".into(), json!({"b": 2})),
    ]);
    assert_eq!(v["count"], 2);
    assert_eq!(v["results"][0]["server"], "s1");
    assert_eq!(v["results"][1]["server"], "s2");
}

#[test]
fn aggregator_first_success() {
    let r = CallAggregator::first_success(vec![
        ("a".into(), Err("nope".into())),
        ("b".into(), Ok(json!(42))),
        ("c".into(), Ok(json!("ignored"))),
    ]);
    assert_eq!(r, Some(("b".into(), json!(42))));

    let none: Vec<(String, Result<serde_json::Value, String>)> =
        vec![("a".into(), Err("x".into()))];
    assert_eq!(CallAggregator::first_success(none), None);
}

#[test]
fn aggregator_deduplicate_array() {
    let v = json!([
        {"id": 1, "v": "a"},
        {"id": 1, "v": "b"},
        {"id": 2, "v": "c"},
    ]);
    let out = CallAggregator::deduplicate(v, "id");
    assert_eq!(out["count"], 2);
}

#[test]
fn aggregator_deduplicate_items_wrapper() {
    let v = json!({"items": [{"k":1},{"k":1},{"k":2}]});
    let out = CallAggregator::deduplicate(v, "k");
    assert_eq!(out["count"], 2);
}

#[test]
fn aggregator_deduplicate_passes_through_unknown() {
    let v = json!({"foo": "bar"});
    let out = CallAggregator::deduplicate(v.clone(), "k");
    assert_eq!(out, v);
}

#[test]
fn aggregator_combine_arrays_mixed() {
    let out = CallAggregator::combine_arrays(vec![
        json!([1, 2]),
        json!({"results": [3, 4]}),
        json!({"items": [5]}),
        json!({"other": "ignored"}),
    ]);
    assert_eq!(out["count"], 5);
}

#[test]
fn aggregator_merge_objects() {
    let out = CallAggregator::merge_objects(
        json!({"a": 1, "b": 2}),
        json!({"b": 99, "c": 3}),
    );
    assert_eq!(out["a"], 1);
    assert_eq!(out["b"], 99);
    assert_eq!(out["c"], 3);
}

#[test]
fn aggregator_merge_objects_non_object_override() {
    let out = CallAggregator::merge_objects(json!({"a": 1}), json!(42));
    assert_eq!(out, json!(42));
}

// ── CallLog / CallLogEntry / CallStats ──────────────────────────────────────

#[test]
fn call_log_record_and_id_increments() {
    let mut log = CallLog::new(100);
    log.record(CallLogEntry::new(
        0,
        "t",
        "s",
        &json!({"x": 1}),
        10,
        true,
        None,
    ));
    log.record(CallLogEntry::new(
        0,
        "t",
        "s",
        &json!({"x": 2}),
        20,
        false,
        Some("e".into()),
    ));
    assert_eq!(log.total_calls(), 2);
    let recent: Vec<u64> = log.recent(10).iter().map(|e| e.id).collect();
    assert_eq!(recent, vec![1, 2]);
}

#[test]
fn call_log_trim_and_recent() {
    let mut log = CallLog::new(3);
    for i in 0..10u64 {
        log.record(CallLogEntry::new(
            0,
            "t",
            "s",
            &json!({"i": i}),
            i,
            true,
            None,
        ));
    }
    assert_eq!(log.total_calls(), 3);
    let r = log.recent(2);
    assert_eq!(r.len(), 2);
}

#[test]
fn call_log_stats_and_success_rate() {
    let mut log = CallLog::new(100);
    for i in 0..5 {
        log.record(CallLogEntry::new(
            0,
            "tool_a",
            "srv_a",
            &json!({"i": i}),
            10,
            true,
            None,
        ));
    }
    for i in 0..3 {
        log.record(CallLogEntry::new(
            0,
            "tool_b",
            "srv_b",
            &json!({"i": i}),
            20,
            false,
            Some("err".into()),
        ));
    }
    let s = log.stats();
    assert_eq!(s.total_calls, 8);
    assert_eq!(s.successful, 5);
    assert_eq!(s.failed, 3);
    assert!((s.success_rate() - 5.0 / 8.0).abs() < 1e-9);
    assert_eq!(s.calls_by_server.get("srv_a").copied(), Some(5));
    assert_eq!(s.calls_by_tool.get("tool_b").copied(), Some(3));

    assert!((log.success_rate(None) - 5.0 / 8.0).abs() < 1e-9);
    assert!((log.success_rate(Some("srv_a")) - 1.0).abs() < 1e-9);
    assert_eq!(log.success_rate(Some("nope")), 0.0);

    assert_eq!(log.by_server("srv_a").len(), 5);
    assert_eq!(log.by_tool("tool_b").len(), 3);
}

#[test]
fn call_stats_empty_success_rate() {
    let s = CallStats {
        total_calls: 0,
        successful: 0,
        failed: 0,
        avg_duration_ms: 0.0,
        calls_by_server: Default::default(),
        calls_by_tool: Default::default(),
    };
    assert_eq!(s.success_rate(), 0.0);
}

#[test]
fn call_log_entry_hash_determinism() {
    let a = CallLogEntry::new(1, "t", "s", &json!({"k": 1}), 0, true, None);
    let b = CallLogEntry::new(1, "t", "s", &json!({"k": 1}), 0, true, None);
    assert_eq!(a.params_hash, b.params_hash);
    let c = CallLogEntry::new(1, "t", "s", &json!({"k": 2}), 0, true, None);
    assert_ne!(a.params_hash, c.params_hash);
    // 30+ pairs
    let mut g = lcg();
    for _ in 0..40 {
        let v = g();
        let p = json!({"v": v});
        let h1 = CallLogEntry::new(0, "t", "s", &p, 0, true, None).params_hash;
        let h2 = CallLogEntry::new(0, "t", "s", &p, 0, true, None).params_hash;
        assert_eq!(h1, h2);
    }
}

// ── FederationStatus ────────────────────────────────────────────────────────

#[test]
fn federation_status_is_healthy() {
    let s = FederationStatus {
        total_servers: 1,
        healthy_servers: 1,
        total_tools: 0,
        local_tools: 0,
        remote_tools: 0,
        calls_today: 0,
        success_rate: 0.0,
    };
    assert!(s.is_healthy());
    let s2 = FederationStatus {
        healthy_servers: 0,
        ..s
    };
    assert!(!s2.is_healthy());
}

// ── FederationManager ──────────────────────────────────────────────────────

#[test]
fn federation_manager_default_and_register() {
    let mut m = FederationManager::default_manager();
    m.register_local_tool(FederatedTool::new_local("t", "", json!({})));
    assert_eq!(m.registry.total_tool_count(), 1);
}

#[test]
fn federation_manager_from_toml_invalid_err() {
    let res = FederationManager::from_toml("!!!");
    assert!(res.is_err());
}

#[test]
fn federation_manager_from_toml_ok() {
    let cfg = FederationConfig::default_config();
    let s = cfg.to_toml().unwrap();
    let m = FederationManager::from_toml(&s).unwrap();
    assert_eq!(m.config.servers.len(), 3);
}

// ── Error conversions ──────────────────────────────────────────────────────

#[test]
fn federation_error_display_variants() {
    let e = FederationError::ServerNotFound("x".into());
    assert!(e.to_string().contains("x"));
    let e = FederationError::ToolNotFound("t".into());
    assert!(e.to_string().contains("t"));
    let e = FederationError::Timeout("s".into());
    assert!(e.to_string().contains("s"));
    let e = FederationError::UnsupportedTransport("u".into());
    assert!(e.to_string().contains("u"));
}

#[test]
fn config_error_to_federation_error() {
    let ce = ConfigError::Validation("v".into());
    let fe: FederationError = ce.into();
    assert!(matches!(fe, FederationError::Config(_)));
}

// ── Send/Sync threaded stress ──────────────────────────────────────────────

#[test]
fn threaded_send_sync_config_validate() {
    let mut cfg = FederationConfig::new();
    cfg.servers.push(ExternalServerConfig::new_stdio("a", "c"));
    cfg.routing_rules.push(RoutingRule::new(
        "x.*",
        RouteTarget::Server("a".into()),
        1,
    ));
    let arc = Arc::new(cfg);
    let mut handles = vec![];
    for _ in 0..4 {
        let a = Arc::clone(&arc);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let errs = a.validate();
                assert!(errs.is_empty());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn threaded_glob_match() {
    let r = Arc::new(RoutingRule::new("foo.*", RouteTarget::Broadcast, 0));
    let mut handles = vec![];
    for _ in 0..4 {
        let r = Arc::clone(&r);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                assert!(r.matches("foo.bar"));
                assert!(!r.matches("bar.baz"));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ── TOML round-trip 50+ inputs ──────────────────────────────────────────────

#[test]
fn toml_roundtrip_many_configs() {
    let mut g = lcg();
    for i in 0..55 {
        let mut c = FederationConfig::new();
        let n = (g() % 5) as usize + 1;
        for j in 0..n {
            c.servers.push(ExternalServerConfig::new_stdio(
                format!("s{i}_{j}"),
                "cmd",
            ));
        }
        c.max_concurrent_calls = ((g() % 32) + 1) as u32;
        c.call_timeout_secs = (g() % 120) + 1;
        let s = c.to_toml().unwrap();
        let back = FederationConfig::from_toml(&s).unwrap();
        assert_eq!(c.servers.len(), back.servers.len());
        assert_eq!(c.max_concurrent_calls, back.max_concurrent_calls);
        assert_eq!(c.call_timeout_secs, back.call_timeout_secs);
    }
}

// ── Boundary: 0, 1, max u32/u64 ─────────────────────────────────────────────

#[test]
fn routing_rule_priority_boundaries() {
    let _ = RoutingRule::new("*", RouteTarget::Broadcast, 0);
    let _ = RoutingRule::new("*", RouteTarget::Broadcast, u32::MAX);
    let mut cfg = FederationConfig::new();
    cfg.servers
        .push(ExternalServerConfig::new_stdio("a", "c"));
    cfg.routing_rules.push(RoutingRule::new(
        "*",
        RouteTarget::Server("a".into()),
        u32::MAX,
    ));
    cfg.routing_rules.push(RoutingRule::new(
        "*",
        RouteTarget::Server("a".into()),
        0,
    ));
    let r = ToolRouter::new(cfg);
    let d = r.route("anything");
    assert!(d.is_routable());
}

#[test]
fn health_monitor_zero_history_limit() {
    let mut m = HealthMonitor::new(0);
    m.record_check("s", HealthCheck::success(1, 5));
    assert_eq!(m.get_history("s").len(), 0);
}

#[test]
fn call_log_zero_capacity() {
    let mut log = CallLog::new(0);
    log.record(CallLogEntry::new(
        0,
        "t",
        "s",
        &json!({}),
        0,
        true,
        None,
    ));
    assert_eq!(log.total_calls(), 0);
}

#[test]
fn call_log_one_capacity() {
    let mut log = CallLog::new(1);
    log.record(CallLogEntry::new(0, "t", "s", &json!({}), 0, true, None));
    log.record(CallLogEntry::new(0, "t", "s", &json!({}), 0, true, None));
    assert_eq!(log.total_calls(), 1);
}
