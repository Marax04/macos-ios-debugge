//! Exhaustive blitz tests for rustre-mcp-federation public surface.
//! These are integration tests — exercise public API only.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::json;

use rustre_mcp_federation::{
    CallAggregator, CallLog, CallLogEntry, CallStats, ConfigError, ConfigValidationError,
    ExternalServer, ExternalServerConfig, FederatedBackend, FederatedClient, FederatedTool,
    FederationConfig, FederationError, FederationManager, FederationRouter,
    FederationStatus, FederationTransport, HealthCheck, HealthMonitor, HealthStatus,
    McpFederationConfig, MockConnection, RouteDecision, RouteTarget, RoutingContext, RoutingDecision,
    RoutingRule, ServerHealth, ServerTransport, ServiceRegistry, ToolRegistry, ToolRouter,
};

use rustre_mcp_federation::federation_cache::{
    CacheEntry as FCacheEntry, CacheKey as FCacheKey, CachePolicy, CacheStats as FCacheStats,
    FederationCache, Fnv1aHasher, fnv1a_hashable, get_cached, get_cached_timed,
};
use rustre_mcp_federation::result_cache::{
    CacheEntry as RCacheEntry, CacheKey as RCacheKey, CacheStats as RCacheStats, ResultCache,
};

// ─────────────────────────────────────────────────────────────────────────────
// ExternalServerConfig / ServerTransport
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn config_new_stdio_defaults() {
    let c = ExternalServerConfig::new_stdio("a", "cmd");
    assert_eq!(c.name, "a");
    assert!(c.enabled);
    assert_eq!(c.health_check_interval_secs, 60);
    assert!(c.tags.is_empty());
    assert_eq!(c.transport.transport_type(), "stdio");
    assert!(c.transport.is_local());
}

#[test]
fn config_new_http_defaults() {
    let c = ExternalServerConfig::new_http("g", "http://localhost:1234");
    assert_eq!(c.transport.transport_type(), "sse_http");
    assert!(!c.transport.is_local());
}

#[test]
fn config_with_description_and_tags() {
    let c = ExternalServerConfig::new_stdio("x", "y")
        .with_description("desc")
        .with_tag("t1")
        .with_tag("t2");
    assert_eq!(c.description, "desc");
    assert!(c.has_tag("t1"));
    assert!(c.has_tag("t2"));
    assert!(!c.has_tag("absent"));
}

#[test]
fn config_disabled() {
    let c = ExternalServerConfig::new_stdio("x", "y").disabled();
    assert!(!c.enabled);
}

#[test]
fn server_transport_unix_socket_local() {
    let t = ServerTransport::UnixSocket { path: "/tmp/x".into() };
    assert_eq!(t.transport_type(), "unix_socket");
    assert!(t.is_local());
}

#[test]
fn server_transport_websocket_not_local() {
    let t = ServerTransport::WebSocket { url: "ws://x".into(), headers: HashMap::new() };
    assert!(!t.is_local());
    assert_eq!(t.transport_type(), "websocket");
}

// ─────────────────────────────────────────────────────────────────────────────
// FederationConfig
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn federation_config_const_new() {
    let c = FederationConfig::new();
    assert_eq!(c.max_concurrent_calls, 16);
    assert_eq!(c.call_timeout_secs, 30);
    assert!(c.fallback_server.is_none());
    assert!(c.servers.is_empty());
    assert!(c.routing_rules.is_empty());
}

#[test]
fn federation_config_add_remove() {
    let mut c = FederationConfig::new();
    c.add_server(ExternalServerConfig::new_stdio("s1", "x"));
    c.add_server(ExternalServerConfig::new_stdio("s2", "x"));
    assert_eq!(c.servers.len(), 2);
    assert!(c.remove_server("s1"));
    assert!(!c.remove_server("s1"));
    assert_eq!(c.servers.len(), 1);
    assert_eq!(c.get_server("s2").unwrap().name, "s2");
    assert!(c.get_server("nope").is_none());
}

#[test]
fn federation_config_enabled_servers_filter() {
    let mut c = FederationConfig::new();
    c.add_server(ExternalServerConfig::new_stdio("a", "x"));
    c.add_server(ExternalServerConfig::new_stdio("b", "x").disabled());
    assert_eq!(c.enabled_servers().len(), 1);
}

#[test]
fn federation_config_servers_by_tag_empty() {
    let c = FederationConfig::new();
    assert!(c.servers_by_tag("any").is_empty());
}

#[test]
fn federation_config_validate_empty_name() {
    let mut c = FederationConfig::new();
    c.add_server(ExternalServerConfig::new_stdio("", "cmd"));
    let errs = c.validate();
    assert!(errs.iter().any(|e| e.field.contains("server.name")));
}

#[test]
fn federation_config_validate_dup_name() {
    let mut c = FederationConfig::new();
    c.add_server(ExternalServerConfig::new_stdio("s", "cmd"));
    c.add_server(ExternalServerConfig::new_stdio("s", "cmd2"));
    let errs = c.validate();
    assert!(errs.iter().any(|e| e.message.contains("duplicate")));
}

#[test]
fn federation_config_validate_bad_fallback() {
    let mut c = FederationConfig::new();
    c.add_server(ExternalServerConfig::new_stdio("s", "cmd"));
    c.fallback_server = Some("ghost".into());
    let errs = c.validate();
    assert!(errs.iter().any(|e| e.field == "fallback_server"));
}

#[test]
fn federation_config_validate_bad_rule_server() {
    let mut c = FederationConfig::new();
    c.add_server(ExternalServerConfig::new_stdio("s", "cmd"));
    c.routing_rules.push(RoutingRule::new("p", RouteTarget::Server("ghost".into()), 1));
    let errs = c.validate();
    assert!(errs.iter().any(|e| e.message.contains("ghost")));
}

#[test]
fn federation_config_validate_bad_rule_group() {
    let mut c = FederationConfig::new();
    c.add_server(ExternalServerConfig::new_stdio("s", "cmd"));
    c.routing_rules.push(RoutingRule::new(
        "p",
        RouteTarget::ServerGroup(vec!["s".into(), "ghost".into()]),
        1,
    ));
    let errs = c.validate();
    assert!(errs.iter().any(|e| e.message.contains("ghost")));
}

#[test]
fn federation_config_validate_zero_concurrent() {
    let mut c = FederationConfig::new();
    c.max_concurrent_calls = 0;
    let errs = c.validate();
    assert!(errs.iter().any(|e| e.field == "max_concurrent_calls"));
}

#[test]
fn federation_config_default_valid() {
    let c = FederationConfig::default_config();
    assert!(c.validate().is_empty());
    assert!(!c.servers.is_empty());
    assert!(!c.routing_rules.is_empty());
    assert_eq!(c.fallback_server.as_deref(), Some("ghidra-mcp"));
}

#[test]
fn federation_config_toml_roundtrip() {
    let c = FederationConfig::default_config();
    let s = c.to_toml().unwrap();
    let back = FederationConfig::from_toml(&s).unwrap();
    assert_eq!(back.servers.len(), c.servers.len());
    assert_eq!(back.routing_rules.len(), c.routing_rules.len());
    assert_eq!(back.fallback_server, c.fallback_server);
}

#[test]
fn federation_config_from_toml_bad() {
    let r = FederationConfig::from_toml("not = valid = toml === !!");
    assert!(matches!(r, Err(ConfigError::TomlParse(_))));
}

#[test]
fn federation_config_from_json_bad() {
    let r = FederationConfig::from_json("{not json");
    assert!(matches!(r, Err(ConfigError::JsonParse(_))));
}

#[test]
fn federation_config_from_json_ok() {
    let r = FederationConfig::from_json(r#"{"servers":[],"routing_rules":[],"max_concurrent_calls":4,"call_timeout_secs":5}"#).unwrap();
    assert_eq!(r.max_concurrent_calls, 4);
    assert_eq!(r.call_timeout_secs, 5);
}

// ─────────────────────────────────────────────────────────────────────────────
// RoutingRule / glob (exercised via RoutingRule::matches)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rule_matches_exact() {
    let r = RoutingRule::new("foo", RouteTarget::Broadcast, 0);
    assert!(r.matches("foo"));
    assert!(!r.matches("bar"));
}

#[test]
fn rule_matches_star() {
    let r = RoutingRule::new("foo.*", RouteTarget::Broadcast, 0);
    assert!(r.matches("foo.bar"));
    assert!(r.matches("foo."));
    assert!(!r.matches("food"));
}

#[test]
fn rule_matches_question() {
    let r = RoutingRule::new("a?c", RouteTarget::Broadcast, 0);
    assert!(r.matches("abc"));
    assert!(r.matches("a.c"));
    assert!(!r.matches("ac"));
}

#[test]
fn rule_matches_multi_star() {
    let r = RoutingRule::new("*x*", RouteTarget::Broadcast, 0);
    assert!(r.matches("foox"));
    assert!(r.matches("xbar"));
    assert!(r.matches("foxhole"));
    assert!(!r.matches("nope"));
}

#[test]
fn rule_matches_empty_inputs() {
    let r = RoutingRule::new("*", RouteTarget::Broadcast, 0);
    assert!(r.matches(""));
    let r2 = RoutingRule::new("", RouteTarget::Broadcast, 0);
    assert!(r2.matches(""));
    assert!(!r2.matches("x"));
}

#[test]
fn route_target_display_variants() {
    assert_eq!(RouteTarget::Server("s".into()).to_string(), "server:s");
    assert_eq!(
        RouteTarget::ServerGroup(vec!["a".into(), "b".into()]).to_string(),
        "group:[a,b]"
    );
    assert_eq!(RouteTarget::Broadcast.to_string(), "broadcast");
    assert_eq!(RouteTarget::FirstSuccess.to_string(), "first_success");
}

// ─────────────────────────────────────────────────────────────────────────────
// FederatedTool / ToolRegistry
// ─────────────────────────────────────────────────────────────────────────────

fn ft(server: &str, name: &str) -> FederatedTool {
    FederatedTool::new_remote(server, name, "d", json!({}))
}

#[test]
fn federated_tool_qualified_names() {
    let l = FederatedTool::new_local("t", "d", json!({}));
    assert_eq!(l.qualified_name, "local.t");
    assert!(l.is_local);
    assert_eq!(l.server_name, "local");

    let r = FederatedTool::new_remote("srv", "t", "d", json!({}));
    assert_eq!(r.qualified_name, "srv.t");
    assert!(!r.is_local);
}

#[test]
fn registry_default_empty() {
    let r = ToolRegistry::default();
    assert_eq!(r.total_tool_count(), 0);
    assert_eq!(r.server_count(), 0);
}

#[test]
fn registry_server_count_with_local() {
    let mut r = ToolRegistry::new();
    r.register_local(FederatedTool::new_local("a", "d", json!({})));
    r.register_remote("s", vec![ft("s", "x")]);
    assert_eq!(r.server_count(), 2); // +1 for local
}

#[test]
fn registry_find_by_qualified_and_short() {
    let mut r = ToolRegistry::new();
    r.register_remote("srv", vec![ft("srv", "tool")]);
    assert!(r.find_tool("tool").is_some());
    assert!(r.find_tool("srv.tool").is_some());
    assert!(r.find_tool("srv.nope").is_none());
}

#[test]
fn registry_list_by_server_local() {
    let mut r = ToolRegistry::new();
    r.register_local(FederatedTool::new_local("a", "d", json!({})));
    assert_eq!(r.list_by_server("local").len(), 1);
}

#[test]
fn registry_search_matches_description() {
    let mut r = ToolRegistry::new();
    r.register_remote(
        "srv",
        vec![FederatedTool::new_remote("srv", "tool", "Decompiles function", json!({}))],
    );
    assert_eq!(r.search_tools("decompiles").len(), 1);
}

#[test]
fn registry_tools_for_category_short_name() {
    let mut r = ToolRegistry::new();
    r.register_remote("srv", vec![ft("srv", "decompile")]);
    let v = r.tools_for_category("decompile");
    assert_eq!(v.len(), 1);
}

#[test]
fn registry_clear_server_removes_tools() {
    let mut r = ToolRegistry::new();
    r.register_remote("g", vec![ft("g", "x")]);
    assert!(r.has_server("g"));
    r.clear_server("g");
    assert!(!r.has_server("g"));
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolRouter / RoutingDecision / RoutingContext
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn router_no_servers_no_rules_no_route() {
    let r = ToolRouter::new(FederationConfig::new());
    let d = r.route("x.y");
    assert!(!d.is_routable());
    assert!(!r.can_route("x.y"));
}

#[test]
fn router_priority_ordering() {
    let mut cfg = FederationConfig::new();
    cfg.add_server(ExternalServerConfig::new_stdio("hi", "x"));
    cfg.add_server(ExternalServerConfig::new_stdio("lo", "x"));
    cfg.routing_rules.push(RoutingRule::new("*", RouteTarget::Server("lo".into()), 1));
    cfg.routing_rules.push(RoutingRule::new("*", RouteTarget::Server("hi".into()), 100));
    let r = ToolRouter::new(cfg);
    let d = r.route("anything");
    assert_eq!(d.primary_server(), Some("hi"));
}

#[test]
fn router_broadcast_expands_enabled() {
    let mut cfg = FederationConfig::new();
    cfg.add_server(ExternalServerConfig::new_stdio("a", "x"));
    cfg.add_server(ExternalServerConfig::new_stdio("b", "x"));
    cfg.add_server(ExternalServerConfig::new_stdio("c", "x").disabled());
    cfg.routing_rules.push(RoutingRule::new("*", RouteTarget::Broadcast, 1));
    let r = ToolRouter::new(cfg);
    let d = r.route("t");
    assert_eq!(d.servers.len(), 2);
}

#[test]
fn router_decision_fallback_propagated() {
    let mut cfg = FederationConfig::new();
    cfg.add_server(ExternalServerConfig::new_stdio("fb", "x"));
    cfg.fallback_server = Some("fb".into());
    cfg.routing_rules.push(RoutingRule::new("foo", RouteTarget::Server("fb".into()), 1));
    let r = ToolRouter::new(cfg);
    let d = r.route("foo");
    assert_eq!(d.fallback.as_deref(), Some("fb"));
}

#[test]
fn routing_context_builders() {
    let c = RoutingContext::new("u").with_priority(5).prefer_local();
    assert_eq!(c.caller_id, "u");
    assert_eq!(c.priority, Some(5));
    assert!(c.prefer_local);
}

#[test]
fn routing_decision_primary_server_empty() {
    let d = RoutingDecision {
        tool_name: "x".into(),
        servers: vec![],
        strategy: RouteTarget::Broadcast,
        confidence: 0.0,
        fallback: None,
    };
    assert!(!d.is_routable());
    assert!(d.primary_server().is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// HealthMonitor / HealthCheck / ServerHealth / HealthStatus
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn health_status_display_all() {
    assert_eq!(HealthStatus::Unknown.to_string(), "unknown");
    assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
    assert_eq!(HealthStatus::Degraded.to_string(), "degraded");
    assert_eq!(HealthStatus::Unhealthy.to_string(), "unhealthy");
    assert_eq!(HealthStatus::Unreachable.to_string(), "unreachable");
}

#[test]
fn health_check_success_failure() {
    let s = HealthCheck::success(1234, 7);
    assert_eq!(s.status, HealthStatus::Healthy);
    assert!(s.error.is_none());
    assert_eq!(s.response_ms, 7);

    let f = HealthCheck::failure(99, "boom");
    assert_eq!(f.status, HealthStatus::Unreachable);
    assert_eq!(f.error.as_deref(), Some("boom"));
}

#[test]
fn server_health_is_available() {
    let mut h = ServerHealth::new("s");
    assert!(!h.is_available()); // Unknown
    h.status = HealthStatus::Healthy;
    assert!(h.is_available());
    h.status = HealthStatus::Degraded;
    assert!(h.is_available());
    h.status = HealthStatus::Unhealthy;
    assert!(!h.is_available());
}

#[test]
fn health_monitor_records_and_reports() {
    let mut m = HealthMonitor::new(10);
    m.record_check("s", HealthCheck::success(1, 5));
    m.record_check("s", HealthCheck::success(2, 15));
    let h = m.get_health("s").unwrap();
    assert_eq!(h.status, HealthStatus::Healthy);
    assert_eq!(h.consecutive_failures, 0);
    assert!((h.avg_response_ms - 10.0).abs() < 0.01);
    assert!((h.uptime_pct - 100.0).abs() < 0.01);
}

#[test]
fn health_monitor_consecutive_failure_promotion() {
    let mut m = HealthMonitor::new(10);
    for _ in 0..6 {
        m.trigger_health_check_logic("s", false, 0);
    }
    let h = m.get_health("s").unwrap();
    assert_eq!(h.status, HealthStatus::Unreachable);
}

#[test]
fn health_monitor_history_capped() {
    let mut m = HealthMonitor::new(3);
    for i in 0..10 {
        m.record_check("s", HealthCheck::success(i, 1));
    }
    assert_eq!(m.get_history("s").len(), 3);
}

#[test]
fn health_monitor_healthy_and_unhealthy_lists() {
    let mut m = HealthMonitor::new(5);
    m.record_check("good", HealthCheck::success(1, 1));
    m.record_check("bad", HealthCheck::failure(1, "x"));
    let healthy = m.healthy_servers();
    let unhealthy = m.unhealthy_servers();
    assert!(healthy.contains(&"good"));
    assert!(unhealthy.contains(&"bad"));
}

#[test]
fn health_monitor_availability_report() {
    let mut m = HealthMonitor::new(10);
    m.record_check("a", HealthCheck::success(1, 1));
    m.record_check("a", HealthCheck::failure(2, "x"));
    let rep = m.availability_report();
    assert!((rep["a"] - 50.0).abs() < 0.01);
}

#[test]
fn health_monitor_known_servers() {
    let mut m = HealthMonitor::new(10);
    m.record_check("a", HealthCheck::success(1, 1));
    m.record_check("b", HealthCheck::success(1, 1));
    let mut names: Vec<&str> = m.known_servers();
    names.sort();
    assert_eq!(names, vec!["a", "b"]);
}

// ─────────────────────────────────────────────────────────────────────────────
// CallAggregator
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn aggregator_merge_results() {
    let v = CallAggregator::merge_results(vec![("a".into(), json!(1)), ("b".into(), json!(2))]);
    assert_eq!(v["count"], 2);
    assert_eq!(v["results"][0]["server"], "a");
}

#[test]
fn aggregator_first_success_picks_first_ok() {
    let r = CallAggregator::first_success(vec![
        ("a".into(), Err("nope".into())),
        ("b".into(), Ok(json!(42))),
        ("c".into(), Ok(json!(99))),
    ]);
    assert_eq!(r, Some(("b".into(), json!(42))));
}

#[test]
fn aggregator_first_success_all_err() {
    let r = CallAggregator::first_success(vec![("a".into(), Err("e".into()))]);
    assert!(r.is_none());
}

#[test]
fn aggregator_deduplicate_array_input() {
    let arr = json!([{"id": 1}, {"id": 2}, {"id": 1}, {"id": 3}]);
    let out = CallAggregator::deduplicate(arr, "id");
    assert_eq!(out["count"], 3);
}

#[test]
fn aggregator_deduplicate_with_items_wrapper() {
    let v = json!({"items": [{"k": "a"}, {"k": "a"}, {"k": "b"}]});
    let out = CallAggregator::deduplicate(v, "k");
    assert_eq!(out["count"], 2);
}

#[test]
fn aggregator_deduplicate_passthrough_on_other_shape() {
    let v = json!({"foo": "bar"});
    let out = CallAggregator::deduplicate(v.clone(), "k");
    assert_eq!(out, v);
}

#[test]
fn aggregator_combine_arrays_mixed_shapes() {
    let a = json!([1, 2, 3]);
    let b = json!({"results": [4, 5]});
    let c = json!({"items": [6]});
    let out = CallAggregator::combine_arrays(vec![a, b, c]);
    assert_eq!(out["count"], 6);
}

#[test]
fn aggregator_merge_objects() {
    let base = json!({"a": 1, "b": 2});
    let over = json!({"b": 99, "c": 3});
    let out = CallAggregator::merge_objects(base, over);
    assert_eq!(out["a"], 1);
    assert_eq!(out["b"], 99);
    assert_eq!(out["c"], 3);
}

#[test]
fn aggregator_merge_objects_non_object_override_wins() {
    let out = CallAggregator::merge_objects(json!({"a": 1}), json!("scalar"));
    assert_eq!(out, json!("scalar"));
}

// ─────────────────────────────────────────────────────────────────────────────
// CallLog / CallStats
// ─────────────────────────────────────────────────────────────────────────────

fn entry(tool: &str, server: &str, success: bool) -> CallLogEntry {
    CallLogEntry::new(0, tool, server, &json!({}), 10, success, None)
}

#[test]
fn call_log_records_with_increasing_ids() {
    let mut l = CallLog::new(10);
    l.record(entry("t", "s", true));
    l.record(entry("t", "s", true));
    let recent = l.recent(2);
    assert_eq!(recent[0].id, 1);
    assert_eq!(recent[1].id, 2);
}

#[test]
fn call_log_capped() {
    let mut l = CallLog::new(2);
    for _ in 0..5 {
        l.record(entry("t", "s", true));
    }
    assert_eq!(l.total_calls(), 2);
}

#[test]
fn call_log_recent_n_more_than_total() {
    let mut l = CallLog::new(10);
    l.record(entry("t", "s", true));
    assert_eq!(l.recent(10).len(), 1);
}

#[test]
fn call_log_stats_split_success() {
    let mut l = CallLog::new(10);
    l.record(entry("t", "s", true));
    l.record(entry("t", "s", false));
    let s = l.stats();
    assert_eq!(s.total_calls, 2);
    assert_eq!(s.successful, 1);
    assert_eq!(s.failed, 1);
    assert!((s.success_rate() - 0.5).abs() < 0.01);
}

#[test]
fn call_log_filter_by_server_tool() {
    let mut l = CallLog::new(10);
    l.record(entry("t1", "s1", true));
    l.record(entry("t1", "s2", true));
    l.record(entry("t2", "s1", true));
    assert_eq!(l.by_server("s1").len(), 2);
    assert_eq!(l.by_tool("t1").len(), 2);
}

#[test]
fn call_log_success_rate_no_entries() {
    let l = CallLog::new(10);
    assert_eq!(l.success_rate(None), 0.0);
}

#[test]
fn call_stats_success_rate_zero_total() {
    let s = CallStats {
        total_calls: 0,
        successful: 0,
        failed: 0,
        avg_duration_ms: 0.0,
        calls_by_server: HashMap::new(),
        calls_by_tool: HashMap::new(),
    };
    assert_eq!(s.success_rate(), 0.0);
}

#[test]
fn call_log_entry_hash_deterministic() {
    let e1 = CallLogEntry::new(1, "t", "s", &json!({"a":1}), 0, true, None);
    let e2 = CallLogEntry::new(2, "t", "s", &json!({"a":1}), 0, true, None);
    assert_eq!(e1.params_hash, e2.params_hash);
    let e3 = CallLogEntry::new(3, "t", "s", &json!({"a":2}), 0, true, None);
    assert_ne!(e1.params_hash, e3.params_hash);
}

// ─────────────────────────────────────────────────────────────────────────────
// FederationManager
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn manager_default_empty_status() {
    let m = FederationManager::default_manager();
    let s = m.status_report();
    assert_eq!(s.total_servers, 0);
    assert_eq!(s.total_tools, 0);
    assert!(!s.is_healthy());
}

#[test]
fn manager_register_local_and_status() {
    let mut m = FederationManager::default_manager();
    m.register_local_tool(FederatedTool::new_local("t", "d", json!({})));
    let s = m.status_report();
    assert_eq!(s.local_tools, 1);
    assert_eq!(s.total_tools, 1);
}

#[test]
fn manager_from_toml_bad() {
    let r = FederationManager::from_toml("===");
    assert!(r.is_err());
}

#[test]
fn manager_simulate_call_unknown_tool() {
    let mut m = FederationManager::default_manager();
    let r = m.simulate_call("ghost", json!({}));
    assert!(matches!(r, Err(FederationError::ToolNotFound(_))));
}

#[test]
fn manager_simulate_call_routes_via_fallback() {
    let mut cfg = FederationConfig::new();
    cfg.add_server(ExternalServerConfig::new_stdio("fb", "x"));
    cfg.fallback_server = Some("fb".into());
    let mut m = FederationManager::new(cfg);
    let r = m.simulate_call("anything", json!({"x":1})).unwrap();
    assert_eq!(r["tool"], "anything");
    assert_eq!(r["server"], "fb");
    assert_eq!(m.call_log.total_calls(), 1);
}

#[test]
fn manager_server_list_returns_all() {
    let mut cfg = FederationConfig::new();
    cfg.add_server(ExternalServerConfig::new_stdio("a", "x"));
    cfg.add_server(ExternalServerConfig::new_stdio("b", "x").disabled());
    let m = FederationManager::new(cfg);
    assert_eq!(m.server_list().len(), 2);
}

#[test]
fn manager_tool_exists() {
    let mut m = FederationManager::default_manager();
    assert!(!m.tool_exists("x"));
    m.register_local_tool(FederatedTool::new_local("x", "d", json!({})));
    assert!(m.tool_exists("x"));
}

// ─────────────────────────────────────────────────────────────────────────────
// FederatedClient / MockConnection / FederationRouter (legacy)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn federated_client_inject_disconnect() {
    let c = FederatedClient::new(McpFederationConfig::new());
    let conn = MockConnection::new_client_conn("mock", vec![], 1);
    c.inject_connection(conn);
    assert_eq!(c.connected_servers(), vec!["mock".to_string()]);
    c.disconnect("mock");
    assert!(c.connected_servers().is_empty());
}

#[test]
fn mcp_federation_config_add() {
    let mut c = McpFederationConfig::new();
    c.add_server(ExternalServer {
        name: "s".into(),
        transport: FederationTransport::Http { url: "http://x".into() },
        tool_prefix: None,
        timeout_secs: 5,
        max_reconnects: 1,
    });
    assert_eq!(c.servers.len(), 1);
}

#[test]
fn legacy_federation_router_forward_reject() {
    let mut r = FederationRouter::new();
    r.add_backend(FederatedBackend::new("a", "u").with_cap("disasm"));
    r.add_backend(FederatedBackend::new("b", "u").with_cap("yara"));
    let d = r.route("disasm");
    assert!(matches!(d, RouteDecision::ForwardTo(ref n) if n == "a"));
    let d2 = r.route("ghost");
    assert!(matches!(d2, RouteDecision::Reject(_)));
}

#[test]
fn legacy_route_decision_display() {
    assert_eq!(RouteDecision::ForwardTo("x".into()).to_string(), "forward-to:x");
    assert_eq!(RouteDecision::BroadcastAll.to_string(), "broadcast-all");
    assert_eq!(RouteDecision::Reject("r".into()).to_string(), "reject:r");
}

#[test]
fn legacy_backend_supports_and_filter() {
    let mut r = FederationRouter::new();
    r.add_backend(FederatedBackend::new("a", "u").with_cap("x").with_cap("y"));
    r.add_backend(FederatedBackend::new("b", "u").with_cap("y"));
    assert_eq!(r.backends_for_cap("y").len(), 2);
    assert_eq!(r.backends_for_cap("x").len(), 1);
    assert!(r.backends_for_cap("z").is_empty());
}

#[test]
fn service_registry_register_lookup_list() {
    let r = ServiceRegistry::new();
    r.register(FederatedBackend::new("svc", "u"));
    assert!(r.lookup("svc").is_some());
    assert!(r.lookup("absent").is_none());
    assert_eq!(r.list(), vec!["svc".to_string()]);
}

// ─────────────────────────────────────────────────────────────────────────────
// FederationStatus
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn federation_status_is_healthy() {
    let s = FederationStatus {
        total_servers: 1,
        healthy_servers: 0,
        total_tools: 0,
        local_tools: 0,
        remote_tools: 0,
        calls_today: 0,
        success_rate: 0.0,
    };
    assert!(!s.is_healthy());
    let s2 = FederationStatus { healthy_servers: 1, ..s };
    assert!(s2.is_healthy());
}

// ─────────────────────────────────────────────────────────────────────────────
// ConfigValidationError display
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn config_validation_error_display() {
    let e = ConfigValidationError { field: "a".into(), message: "b".into() };
    assert_eq!(e.to_string(), "a: b");
}

// ─────────────────────────────────────────────────────────────────────────────
// FederationError → McpError conversion
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn federation_error_into_mcp_error() {
    let fe = FederationError::ToolNotFound("x".into());
    let me: rustre_mcp_server::McpError = fe.into();
    assert!(me.to_string().to_lowercase().contains("tool"));
}

// ─────────────────────────────────────────────────────────────────────────────
// federation_cache module
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn fcache_policy_default_and_disabled() {
    let d = CachePolicy::default();
    assert!(d.enabled);
    assert_eq!(d.ttl_secs, 60);
    let x = CachePolicy::disabled();
    assert!(!x.enabled);
    assert!(!x.should_cache_response(0));
}

#[test]
fn fcache_should_cache_response_size_limit() {
    let p = CachePolicy::default_ttl(10);
    assert!(p.should_cache_response(p.max_response_bytes));
    assert!(!p.should_cache_response(p.max_response_bytes + 1));
}

#[test]
fn fcache_key_display_format() {
    let k = FCacheKey::from_args("tool", &json!({"a": 1}));
    let s = format!("{k}");
    assert!(s.starts_with("tool:"));
    assert_eq!(s.len(), "tool:".len() + 16);
}

#[test]
fn fcache_key_eq_hash() {
    let a = FCacheKey::from_args("t", &json!({"x": 1}));
    let b = FCacheKey::from_args("t", &json!({"x": 1}));
    assert_eq!(a, b);
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(a);
    assert!(s.contains(&b));
}

#[test]
fn fnv1a_hasher_deterministic() {
    let h1 = fnv1a_hashable("hello");
    let h2 = fnv1a_hashable("hello");
    let h3 = fnv1a_hashable("world");
    assert_eq!(h1, h2);
    assert_ne!(h1, h3);
}

#[test]
fn fcache_put_get_roundtrip() {
    let c = FederationCache::new(10, 100_000);
    c.put("t", &json!({"k": 1}), json!({"v": 42}), false);
    let hit = get_cached(&c, "t", &json!({"k": 1})).unwrap();
    assert_eq!(hit.value, json!({"v": 42}));
}

#[test]
fn fcache_miss_increments_misses() {
    let c = FederationCache::new(10, 100_000);
    assert!(get_cached(&c, "t", &json!({})).is_none());
    assert_eq!(c.stats().total_misses, 1);
}

#[test]
fn fcache_put_disabled_policy_returns_false() {
    let c = FederationCache::new(10, 100_000);
    c.set_policy("t", CachePolicy::disabled());
    assert!(!c.put("t", &json!({}), json!("v"), false));
}

#[test]
fn fcache_invalidate_tool_only() {
    let c = FederationCache::new(10, 100_000);
    c.put("a", &json!({}), json!(1), false);
    c.put("b", &json!({}), json!(2), false);
    c.invalidate_tool("a");
    assert!(get_cached(&c, "a", &json!({})).is_none());
    assert!(get_cached(&c, "b", &json!({})).is_some());
}

#[test]
fn fcache_clear_resets() {
    let c = FederationCache::new(10, 100_000);
    c.put("a", &json!({}), json!(1), false);
    c.clear();
    assert!(c.is_empty());
    assert_eq!(c.len(), 0);
}

#[test]
fn fcache_entry_remaining_ttl_and_valid() {
    let key = FCacheKey::from_args("t", &json!({}));
    let e = FCacheEntry::new(key, json!("v"), 60, false);
    assert!(e.is_valid());
    assert!(e.remaining_ttl() <= 60);
}

#[test]
fn fcache_entry_zero_ttl_expired() {
    let key = FCacheKey::from_args("t", &json!({}));
    let e = FCacheEntry::new(key, json!("v"), 0, false);
    // ttl=0 means inserted_at == expires_at, and is_valid uses strict `<`.
    assert!(!e.is_valid());
    assert_eq!(e.remaining_ttl(), 0);
}

#[test]
fn fcache_stats_default_hit_rate_zero() {
    let s = FCacheStats::default();
    assert_eq!(s.hit_rate(), 0.0);
}

#[test]
fn fcache_get_timed_returns_duration() {
    let c = FederationCache::new(10, 100_000);
    let (e, _d) = get_cached_timed(&c, "t", &json!({}));
    assert!(e.is_none());
}

#[test]
fn fcache_put_too_large_rejected() {
    let c = FederationCache::new(10, 100_000);
    let mut policy = CachePolicy::default_ttl(60);
    policy.max_response_bytes = 1;
    c.set_policy("t", policy);
    assert!(!c.put("t", &json!({}), json!("more than one byte"), false));
}

#[test]
fn fcache_error_not_cached_default() {
    let c = FederationCache::new(10, 100_000);
    assert!(!c.put("t", &json!({}), json!("err"), true));
}

// Exercise Fnv1aHasher Hasher trait directly
#[test]
fn fnv1a_hasher_write_and_finish() {
    use std::hash::Hasher;
    let mut h = Fnv1aHasher::default();
    h.write(b"abc");
    let v1 = h.finish();
    let mut h2 = Fnv1aHasher::default();
    h2.write(b"abc");
    assert_eq!(v1, h2.finish());
}

// ─────────────────────────────────────────────────────────────────────────────
// result_cache module
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rcache_key_compute_deterministic() {
    let a = RCacheKey::compute("t", &json!({"x": 1}));
    let b = RCacheKey::compute("t", &json!({"x": 1}));
    assert_eq!(a, b);
    let c = RCacheKey::compute("t", &json!({"x": 2}));
    assert_ne!(a, c);
}

#[test]
fn rcache_key_display() {
    let k = RCacheKey::compute("tool", &json!({}));
    let s = format!("{k}");
    assert!(s.starts_with("tool@"));
}

#[test]
fn rcache_insert_get_roundtrip() {
    let mut c = ResultCache::new(10, Duration::from_secs(60));
    let k = RCacheKey::compute("t", &json!({}));
    c.insert(k.clone(), json!(42));
    assert_eq!(c.get(&k), Some(json!(42)));
    assert_eq!(c.stats().hits, 1);
}

#[test]
fn rcache_peek_no_lru_update() {
    let mut c = ResultCache::new(10, Duration::from_secs(60));
    let k = RCacheKey::compute("t", &json!({}));
    c.insert(k.clone(), json!(1));
    let _ = c.peek(&k);
    assert_eq!(c.stats().hits, 0);
}

#[test]
fn rcache_lru_eviction_capacity_1() {
    let mut c = ResultCache::new(1, Duration::from_secs(60));
    let k1 = RCacheKey::compute("t", &json!(1));
    let k2 = RCacheKey::compute("t", &json!(2));
    c.insert(k1.clone(), json!("a"));
    c.insert(k2.clone(), json!("b"));
    assert!(c.get(&k1).is_none());
    assert!(c.get(&k2).is_some());
}

#[test]
fn rcache_invalidate() {
    let mut c = ResultCache::new(10, Duration::from_secs(60));
    let k = RCacheKey::compute("t", &json!({}));
    c.insert(k.clone(), json!(1));
    c.invalidate(&k);
    assert!(c.get(&k).is_none());
    assert_eq!(c.stats().invalidations, 1);
}

#[test]
fn rcache_invalidate_tool() {
    let mut c = ResultCache::new(10, Duration::from_secs(60));
    let k1 = RCacheKey::compute("a", &json!({}));
    let k2 = RCacheKey::compute("b", &json!({}));
    c.insert(k1.clone(), json!(1));
    c.insert(k2.clone(), json!(2));
    c.invalidate_tool("a");
    assert!(c.get(&k1).is_none());
    assert!(c.get(&k2).is_some());
}

#[test]
fn rcache_clear() {
    let mut c = ResultCache::new(10, Duration::from_secs(60));
    c.insert(RCacheKey::compute("t", &json!({})), json!(1));
    c.clear();
    assert!(c.is_empty());
}

#[test]
fn rcache_entry_age_nonneg() {
    let k = RCacheKey::compute("t", &json!({}));
    let e = RCacheEntry::new(k, json!(1), 60, 1);
    // newly created — age 0 (or very small)
    let _ = e.age_secs();
    assert!(!e.is_expired());
    assert!(!e.should_evict());
}

#[test]
fn rcache_to_from_json_roundtrip() {
    let mut c = ResultCache::new(10, Duration::from_secs(60));
    c.insert(RCacheKey::compute("t", &json!({"k": 1})), json!("v"));
    let j = c.to_json().unwrap();
    let mut c2 = ResultCache::new(10, Duration::from_secs(60));
    let n = c2.load_json(&j).unwrap();
    assert_eq!(n, 1);
}

#[test]
fn rcache_cached_tools_sorted_unique() {
    let mut c = ResultCache::new(10, Duration::from_secs(60));
    c.insert(RCacheKey::compute("b", &json!(1)), json!(0));
    c.insert(RCacheKey::compute("a", &json!(1)), json!(0));
    c.insert(RCacheKey::compute("a", &json!(2)), json!(0));
    let tools = c.cached_tools();
    assert_eq!(tools, vec!["a", "b"]);
}

#[test]
fn rcache_stats_default_hit_rate_zero() {
    let s = RCacheStats::default();
    assert_eq!(s.hit_rate(), 0.0);
}

#[test]
fn rcache_mru_keys_order() {
    let mut c = ResultCache::new(10, Duration::from_secs(60));
    let k1 = RCacheKey::compute("t", &json!(1));
    let k2 = RCacheKey::compute("t", &json!(2));
    c.insert(k1.clone(), json!(1));
    c.insert(k2.clone(), json!(2));
    let _ = c.get(&k1); // promote k1
    let mru = c.mru_keys(2);
    assert_eq!(mru[0], &k1);
}

// Compile-time: types are Send (helps catch accidental !Send)
#[test]
fn types_are_send() {
    fn assert_send<T: Send>() {}
    assert_send::<FederationConfig>();
    assert_send::<ToolRegistry>();
    assert_send::<HealthMonitor>();
    assert_send::<CallLog>();
    assert_send::<FederationCache>();
}
