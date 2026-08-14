//! Exhaustive blitz tests for the rustre-mcp public API surface (lib.rs).
//!
//! Targets the coordinator, tool trait, middleware, rate limiter, schema
//! validation, metrics, audit log, batch dispatch, capability flags,
//! tool/resource catalogue, and built-in tools.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rustre_mcp::{
    AuditEntry, BatchRequest, BatchResponse, CounterTool, DenyListMiddleware, EchoTool, FailingTool,
    HealthTool, IntrospectTool, LoggingMiddleware, McpCapability, McpCapabilityFlags, McpCoordinator,
    McpError, McpMiddleware, McpRequest, McpResourceDef, McpResponse, McpTool, McpToolDef,
    RateLimiter, RequestContext, RpcError, RustreCapabilities, ToolCategory, ToolDescriptor,
    ToolMetrics, ToolSchema, ValidatedTool,
};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

// ── McpCapability ───────────────────────────────────────────────────────────

#[test]
fn capability_new_and_display() {
    let c = McpCapability::new("foo", "bar", "1.2.3");
    assert_eq!(c.to_string(), "foo@1.2.3");
}

#[test]
fn capability_equality_and_clone() {
    let a = McpCapability::new("a", "x", "1.0.0");
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn capability_serde_roundtrip_empty_fields() {
    let c = McpCapability::new("", "", "");
    let json = serde_json::to_string(&c).unwrap();
    let back: McpCapability = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ── ToolCategory ────────────────────────────────────────────────────────────

#[test]
fn tool_category_all_variants_as_str() {
    assert_eq!(ToolCategory::Analysis.as_str(), "analysis");
    assert_eq!(ToolCategory::Debug.as_str(), "debug");
    assert_eq!(ToolCategory::Loader.as_str(), "loader");
    assert_eq!(ToolCategory::Symbols.as_str(), "symbols");
    assert_eq!(ToolCategory::Script.as_str(), "script");
    assert_eq!(ToolCategory::ThreatIntel.as_str(), "threat_intel");
    assert_eq!(ToolCategory::Visualize.as_str(), "visualize");
    assert_eq!(ToolCategory::Utility.as_str(), "utility");
    assert_eq!(ToolCategory::Custom("zz".into()).as_str(), "zz");
}

#[test]
fn tool_category_eq_hash() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(ToolCategory::Analysis);
    s.insert(ToolCategory::Analysis);
    s.insert(ToolCategory::Custom("k".into()));
    s.insert(ToolCategory::Custom("k".into()));
    assert_eq!(s.len(), 2);
}

#[test]
fn tool_category_custom_empty_string() {
    let c = ToolCategory::Custom(String::new());
    assert_eq!(c.as_str(), "");
    assert_eq!(c.to_string(), "");
}

// ── ToolSchema ──────────────────────────────────────────────────────────────

#[test]
fn schema_any_accepts_empty_object() {
    ToolSchema::any().validate(&serde_json::json!({})).unwrap();
}

#[test]
fn schema_rejects_non_object() {
    for v in [
        serde_json::json!(null),
        serde_json::json!(0),
        serde_json::json!("string"),
        serde_json::json!([1, 2, 3]),
        serde_json::json!(true),
    ] {
        let err = ToolSchema::any().validate(&v).unwrap_err();
        assert!(matches!(err, McpError::SchemaValidation(_)));
    }
}

#[test]
fn schema_required_missing_reports_name() {
    let s = ToolSchema::any().require("addr", "number");
    let e = s.validate(&serde_json::json!({})).unwrap_err();
    let msg = e.to_string();
    assert!(msg.contains("addr"), "msg={msg}");
    assert!(msg.contains("missing"), "msg={msg}");
}

#[test]
fn schema_required_present_wrong_type() {
    let s = ToolSchema::any().require("count", "number");
    let e = s
        .validate(&serde_json::json!({"count": "five"}))
        .unwrap_err();
    assert!(e.to_string().contains("count"));
}

#[test]
fn schema_required_present_correct_type() {
    let s = ToolSchema::any().require("count", "number");
    s.validate(&serde_json::json!({"count": 5})).unwrap();
}

#[test]
fn schema_optional_can_be_missing() {
    let s = ToolSchema::any().optional("x", "string");
    s.validate(&serde_json::json!({})).unwrap();
}

#[test]
fn schema_optional_wrong_type_rejected() {
    let s = ToolSchema::any().optional("x", "string");
    let e = s.validate(&serde_json::json!({"x": 7})).unwrap_err();
    assert!(matches!(e, McpError::SchemaValidation(_)));
}

#[test]
fn schema_multiple_required_all_missing_first_reported() {
    let s = ToolSchema::any()
        .require("a", "string")
        .require("b", "number");
    let e = s.validate(&serde_json::json!({})).unwrap_err();
    // Order-independent: just ensure missing message
    assert!(e.to_string().contains("missing"));
}

#[test]
fn schema_type_names_cover_all_json_kinds() {
    // Build schema requiring one of each type and validate matching values.
    for (ty, val) in [
        ("null", serde_json::json!(null)),
        ("boolean", serde_json::json!(true)),
        ("number", serde_json::json!(3.14)),
        ("string", serde_json::json!("hi")),
        ("array", serde_json::json!([])),
        ("object", serde_json::json!({})),
    ] {
        let s = ToolSchema::any().require("v", ty);
        s.validate(&serde_json::json!({"v": val.clone()})).unwrap();
    }
}

// ── RequestContext ──────────────────────────────────────────────────────────

#[test]
fn context_now_recent() {
    let c = RequestContext::now();
    assert!(c.received_at_ms > 0);
    assert!(c.age_ms() < 5_000);
}

#[test]
fn context_builders_chain() {
    let c = RequestContext::now()
        .with_caller("alice")
        .with_trace_id("t1")
        .with_meta("k", "v")
        .with_meta("k2", "v2");
    assert_eq!(c.caller.as_deref(), Some("alice"));
    assert_eq!(c.trace_id.as_deref(), Some("t1"));
    assert_eq!(c.metadata.len(), 2);
}

#[test]
fn context_default_zero_received_at() {
    let c = RequestContext::default();
    assert_eq!(c.received_at_ms, 0);
    assert!(c.caller.is_none());
}

#[test]
fn context_age_saturates_when_received_in_future() {
    // received_at_ms in the future → saturating_sub returns 0, not panic.
    let mut c = RequestContext::default();
    c.received_at_ms = u64::MAX;
    assert_eq!(c.age_ms(), 0);
}

// ── McpRequest / McpResponse ────────────────────────────────────────────────

#[test]
fn request_new_default_params_is_empty_object() {
    let r = McpRequest::new("id", "m");
    assert!(r.params.is_object());
    assert_eq!(r.params.as_object().unwrap().len(), 0);
}

#[test]
fn request_with_params_preserved() {
    let r = McpRequest::with_params("i", "m", serde_json::json!([1, 2, 3]));
    assert!(r.params.is_array());
}

#[test]
fn response_ok_and_err() {
    let ok = McpResponse::ok("i", serde_json::json!(1), 10);
    assert!(ok.is_ok());
    assert_eq!(ok.elapsed_ms, 10);
    assert!(ok.error.is_none());
    let err = McpResponse::err(
        "i",
        RpcError {
            code: -1,
            message: "x".into(),
        },
        5,
    );
    assert!(!err.is_ok());
    assert!(err.result.is_none());
}

#[test]
fn rpc_error_display() {
    let e = RpcError {
        code: -32600,
        message: "bad".into(),
    };
    assert_eq!(e.to_string(), "[-32600] bad");
}

#[test]
fn request_serde_roundtrip_with_complex_params() {
    let r = McpRequest::with_params(
        "i",
        "m",
        serde_json::json!({"nested": {"arr": [1, 2, 3], "b": true}}),
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: McpRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.params["nested"]["arr"][2], 3);
}

// ── McpError ────────────────────────────────────────────────────────────────

#[test]
fn error_rpc_codes_distinct() {
    let codes = [
        McpError::ToolNotFound("x".into()).rpc_code(),
        McpError::InvalidRequest("x".into()).rpc_code(),
        McpError::SchemaValidation("x".into()).rpc_code(),
        McpError::RateLimited("x".into()).rpc_code(),
        McpError::MiddlewareRejected("x".into()).rpc_code(),
        McpError::Timeout("x".into()).rpc_code(),
        McpError::CategoryDisabled("x".into()).rpc_code(),
        McpError::BatchTooLarge {
            count: 2,
            limit: 1,
        }
        .rpc_code(),
        McpError::Internal("x".into()).rpc_code(),
    ];
    let set: std::collections::HashSet<_> = codes.iter().copied().collect();
    assert_eq!(set.len(), codes.len());
}

#[test]
fn error_is_transient() {
    assert!(McpError::RateLimited("x".into()).is_transient());
    assert!(McpError::Timeout("x".into()).is_transient());
    assert!(!McpError::ToolNotFound("x".into()).is_transient());
    assert!(!McpError::Internal("x".into()).is_transient());
}

#[test]
fn error_is_client_error() {
    assert!(McpError::InvalidRequest("x".into()).is_client_error());
    assert!(McpError::SchemaValidation("x".into()).is_client_error());
    assert!(McpError::ToolNotFound("x".into()).is_client_error());
    assert!(McpError::BatchTooLarge { count: 2, limit: 1 }.is_client_error());
    assert!(!McpError::Internal("x".into()).is_client_error());
    assert!(!McpError::Timeout("x".into()).is_client_error());
}

#[test]
fn error_execution_constructor() {
    let e = McpError::execution("t", "d");
    match e {
        McpError::Execution { tool, detail } => {
            assert_eq!(tool, "t");
            assert_eq!(detail, "d");
        }
        _ => panic!(),
    }
}

#[test]
fn error_to_rpc_error_carries_message() {
    let e = McpError::ToolNotFound("zz".into());
    let r = e.to_rpc_error();
    assert!(r.message.contains("zz"));
    assert_eq!(r.code, -32601);
}

// ── ToolMetrics ─────────────────────────────────────────────────────────────

#[test]
fn metrics_default_zero() {
    let m = ToolMetrics::default();
    assert_eq!(m.total_calls(), 0);
    assert_eq!(m.avg_us(), 0);
    assert_eq!(m.error_rate(), 0.0);
}

#[test]
fn metrics_record_success() {
    let mut m = ToolMetrics::default();
    m.record(Duration::from_micros(100), true, None);
    assert_eq!(m.success_count, 1);
    assert_eq!(m.min_us, 100);
    assert_eq!(m.max_us, 100);
    assert_eq!(m.avg_us(), 100);
}

#[test]
fn metrics_record_failure_stores_last_error() {
    let mut m = ToolMetrics::default();
    m.record(Duration::from_micros(50), false, Some("boom".into()));
    assert_eq!(m.error_count, 1);
    assert_eq!(m.last_error.as_deref(), Some("boom"));
    assert_eq!(m.error_rate(), 1.0);
}

#[test]
fn metrics_min_max_tracked() {
    let mut m = ToolMetrics::default();
    m.record(Duration::from_micros(100), true, None);
    m.record(Duration::from_micros(50), true, None);
    m.record(Duration::from_micros(200), true, None);
    assert_eq!(m.min_us, 50);
    assert_eq!(m.max_us, 200);
    assert_eq!(m.total_calls(), 3);
}

#[test]
fn metrics_error_rate_partial() {
    let mut m = ToolMetrics::default();
    m.record(Duration::from_micros(10), true, None);
    m.record(Duration::from_micros(10), false, Some("e".into()));
    m.record(Duration::from_micros(10), true, None);
    m.record(Duration::from_micros(10), true, None);
    assert!((m.error_rate() - 0.25).abs() < 1e-9);
}

#[test]
fn metrics_min_us_zero_initial_recording_bug_probe() {
    // ToolMetrics.min_us starts at 0; record() uses `if self.min_us == 0 || us < self.min_us`.
    // If the first recording is exactly 0 microseconds, min_us stays 0, then a subsequent
    // larger recording correctly updates it. Probe behaviour with a 0us recording followed
    // by 100us to ensure min is still meaningful.
    let mut m = ToolMetrics::default();
    m.record(Duration::from_micros(0), true, None);
    m.record(Duration::from_micros(100), true, None);
    // Expectation: min_us should reflect the actual smallest call (0us).
    assert_eq!(m.min_us, 0, "min_us should track the actual smallest call");
}

// ── RateLimiter ─────────────────────────────────────────────────────────────

#[test]
fn rate_limiter_allows_up_to_max() {
    let mut rl = RateLimiter::new(3, Duration::from_secs(60));
    assert!(rl.allow());
    assert!(rl.allow());
    assert!(rl.allow());
    assert!(!rl.allow());
    assert_eq!(rl.current_count(), 3);
}

#[test]
fn rate_limiter_evicts_old() {
    let mut rl = RateLimiter::new(2, Duration::from_millis(50));
    assert!(rl.allow());
    assert!(rl.allow());
    assert!(!rl.allow());
    std::thread::sleep(Duration::from_millis(80));
    assert!(rl.allow(), "old entries should have been evicted");
}

#[test]
fn rate_limiter_zero_max_calls_rejects() {
    let mut rl = RateLimiter::new(0, Duration::from_secs(60));
    assert!(!rl.allow());
    assert_eq!(rl.current_count(), 0);
}

// ── Coordinator: registration ───────────────────────────────────────────────

#[test]
fn coord_register_and_query() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    assert!(c.has_tool("echo"));
    assert_eq!(c.tool_count(), 1);
    assert_eq!(c.tool_names(), vec!["echo".to_string()]);
}

#[test]
fn coord_remove_tool() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    assert!(c.remove_tool("echo"));
    assert!(!c.has_tool("echo"));
    assert!(!c.remove_tool("echo"));
}

#[test]
fn coord_register_replaces_same_name() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    c.register_tool(Arc::new(EchoTool));
    assert_eq!(c.tool_count(), 1);
}

#[test]
fn coord_tools_by_category() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    c.register_tool(Arc::new(FailingTool));
    let utils = c.tools_by_category(&ToolCategory::Utility);
    assert!(utils.iter().any(|n| n == "echo"));
    // FailingTool overrides nothing, defaults to Utility per trait default.
    assert!(utils.iter().any(|n| n == "fail"));
}

#[test]
fn coord_all_capabilities_aggregated() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    c.register_tool(Arc::new(HealthTool));
    let caps = c.all_capabilities();
    assert!(caps.iter().any(|c| c.name == "echo"));
    assert!(caps.iter().any(|c| c.name == "health"));
}

#[test]
fn coord_tool_descriptors_sorted() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(HealthTool));
    c.register_tool(Arc::new(EchoTool));
    let d: Vec<ToolDescriptor> = c.tool_descriptors();
    let names: Vec<_> = d.iter().map(|x| x.name.clone()).collect();
    assert_eq!(names, vec!["echo".to_string(), "health".to_string()]);
}

// ── Coordinator: dispatch ───────────────────────────────────────────────────

#[test]
fn dispatch_unknown_tool_returns_rpc_error() {
    let c = McpCoordinator::new();
    let resp = rt().block_on(c.dispatch(McpRequest::new("i", "missing")));
    assert!(!resp.is_ok());
    let err = resp.error.as_ref().unwrap();
    assert_eq!(err.code, -32601);
}

#[test]
fn dispatch_echo_success() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    let req = McpRequest::with_params("i", "echo", serde_json::json!({"hello": "world"}));
    let resp = rt().block_on(c.dispatch(req));
    assert!(resp.is_ok());
    assert_eq!(resp.result.unwrap()["hello"], "world");
}

#[test]
fn dispatch_failing_tool_records_error() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(FailingTool));
    let resp = rt().block_on(c.dispatch(McpRequest::new("i", "fail")));
    assert!(!resp.is_ok());
    let m = c.metrics("fail").unwrap();
    assert_eq!(m.error_count, 1);
    assert!(m.last_error.is_some());
}

#[test]
fn dispatch_disabled_category() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    c.disable_category(ToolCategory::Utility);
    let resp = rt().block_on(c.dispatch(McpRequest::new("i", "echo")));
    assert!(!resp.is_ok());
    assert_eq!(resp.error.unwrap().code, -32003);
}

#[test]
fn dispatch_reenable_category() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    c.disable_category(ToolCategory::Utility);
    c.enable_category(&ToolCategory::Utility);
    assert!(c.is_category_enabled(&ToolCategory::Utility));
    let resp = rt().block_on(c.dispatch(McpRequest::new("i", "echo")));
    assert!(resp.is_ok());
}

#[test]
fn dispatch_schema_validation_failure() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(ValidatedTool::new("vtool", "needed")));
    let resp = rt().block_on(c.dispatch(McpRequest::with_params(
        "i",
        "vtool",
        serde_json::json!({}),
    )));
    assert!(!resp.is_ok());
    assert_eq!(resp.error.unwrap().code, -32602);
}

#[test]
fn dispatch_schema_validation_success() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(ValidatedTool::new("vtool", "needed")));
    let resp = rt().block_on(c.dispatch(McpRequest::with_params(
        "i",
        "vtool",
        serde_json::json!({"needed": "yes"}),
    )));
    assert!(resp.is_ok());
}

#[test]
fn dispatch_rate_limit_triggers() {
    let c = McpCoordinator::new();
    c.register(
        McpCoordinator::builder(Arc::new(EchoTool)).rate_limit(2, Duration::from_secs(60)),
    );
    let rt = rt();
    assert!(rt.block_on(c.dispatch(McpRequest::new("a", "echo"))).is_ok());
    assert!(rt.block_on(c.dispatch(McpRequest::new("b", "echo"))).is_ok());
    let resp = rt.block_on(c.dispatch(McpRequest::new("c", "echo")));
    assert!(!resp.is_ok());
    assert_eq!(resp.error.unwrap().code, -32000);
}

#[test]
fn dispatch_timeout_returns_timeout_error() {
    use async_trait::async_trait;

    #[derive(Debug)]
    struct SlowTool;
    #[async_trait]
    impl McpTool for SlowTool {
        fn name(&self) -> &str {
            "slow"
        }
        fn description(&self) -> &str {
            "slow"
        }
        fn capabilities(&self) -> Vec<McpCapability> {
            vec![]
        }
        async fn execute(
            &self,
            _p: serde_json::Value,
            _c: &RequestContext,
        ) -> Result<serde_json::Value, McpError> {
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok(serde_json::json!({}))
        }
    }

    let c = McpCoordinator::new();
    c.register(McpCoordinator::builder(Arc::new(SlowTool)).timeout_ms(30));
    let resp = rt().block_on(c.dispatch(McpRequest::new("i", "slow")));
    assert!(!resp.is_ok());
    assert_eq!(resp.error.unwrap().code, -32002);
}

#[test]
fn dispatch_metrics_updated() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    let rt = rt();
    for i in 0..5 {
        rt.block_on(c.dispatch(McpRequest::new(format!("{i}"), "echo")));
    }
    let m = c.metrics("echo").unwrap();
    assert_eq!(m.success_count, 5);
    assert_eq!(m.error_count, 0);
}

#[test]
fn dispatch_audit_log_populated() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    rt().block_on(c.dispatch(McpRequest::new("i", "echo")));
    let log: Vec<AuditEntry> = c.audit_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].tool, "echo");
    assert!(log[0].success);
}

#[test]
fn audit_log_clear() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    rt().block_on(c.dispatch(McpRequest::new("i", "echo")));
    assert_eq!(c.audit_log_len(), 1);
    c.clear_audit_log();
    assert_eq!(c.audit_log_len(), 0);
}

#[test]
fn audit_log_ring_eviction() {
    let c = McpCoordinator::with_limits(3, 100);
    c.register_tool(Arc::new(EchoTool));
    let rt = rt();
    for i in 0..7 {
        rt.block_on(c.dispatch(McpRequest::new(format!("{i}"), "echo")));
    }
    assert_eq!(c.audit_log_len(), 3);
}

// ── Middleware ──────────────────────────────────────────────────────────────

#[test]
fn middleware_count_tracks_adds_and_clear() {
    let c = McpCoordinator::new();
    assert_eq!(c.middleware_count(), 0);
    c.add_middleware(Arc::new(LoggingMiddleware));
    c.add_middleware(Arc::new(LoggingMiddleware));
    assert_eq!(c.middleware_count(), 2);
    c.clear_middleware();
    assert_eq!(c.middleware_count(), 0);
}

#[test]
fn denylist_middleware_rejects_caller() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    c.add_middleware(Arc::new(DenyListMiddleware::new(vec!["bad".into()])));
    let resp = rt().block_on(
        c.dispatch_with_context(
            McpRequest::new("i", "echo"),
            RequestContext::now().with_caller("bad"),
        ),
    );
    assert!(!resp.is_ok());
    assert_eq!(resp.error.unwrap().code, -32001);
}

#[test]
fn denylist_middleware_allows_other_callers() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    c.add_middleware(Arc::new(DenyListMiddleware::new(vec!["bad".into()])));
    let resp = rt().block_on(
        c.dispatch_with_context(
            McpRequest::new("i", "echo"),
            RequestContext::now().with_caller("good"),
        ),
    );
    assert!(resp.is_ok());
}

#[test]
fn middleware_after_runs_even_when_before_rejects() {
    // Custom middleware counts before+after invocations.
    #[derive(Debug)]
    struct Counter {
        before: AtomicU64,
        after: AtomicU64,
    }
    impl McpMiddleware for Counter {
        fn before(&self, _r: &McpRequest, _c: &RequestContext) -> Result<(), McpError> {
            self.before.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn after(&self, _r: &McpRequest, _resp: &McpResponse, _c: &RequestContext) {
            self.after.fetch_add(1, Ordering::SeqCst);
        }
    }
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    let mw = Arc::new(Counter {
        before: AtomicU64::new(0),
        after: AtomicU64::new(0),
    });
    c.add_middleware(mw.clone());
    c.add_middleware(Arc::new(DenyListMiddleware::new(vec!["b".into()])));
    rt().block_on(
        c.dispatch_with_context(
            McpRequest::new("i", "echo"),
            RequestContext::now().with_caller("b"),
        ),
    );
    // Counter.before should have run once (it precedes the deny), and after should also run.
    assert_eq!(mw.before.load(Ordering::SeqCst), 1);
    assert_eq!(mw.after.load(Ordering::SeqCst), 1);
}

// ── Batch ───────────────────────────────────────────────────────────────────

#[test]
fn batch_basic() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    let batch = BatchRequest::new(vec![
        McpRequest::with_params("1", "echo", serde_json::json!({"v": 1})),
        McpRequest::with_params("2", "echo", serde_json::json!({"v": 2})),
        McpRequest::new("3", "missing"),
    ]);
    let resp: BatchResponse = rt()
        .block_on(c.dispatch_batch(batch, RequestContext::now()))
        .unwrap();
    assert_eq!(resp.responses.len(), 3);
    assert_eq!(resp.success_count(), 2);
    assert_eq!(resp.error_count(), 1);
    assert_eq!(resp.errors().len(), 1);
}

#[test]
fn batch_too_large_rejected() {
    let c = McpCoordinator::with_limits(100, 2);
    c.register_tool(Arc::new(EchoTool));
    let batch = BatchRequest::new(vec![
        McpRequest::new("1", "echo"),
        McpRequest::new("2", "echo"),
        McpRequest::new("3", "echo"),
    ]);
    let err = rt()
        .block_on(c.dispatch_batch(batch, RequestContext::now()))
        .unwrap_err();
    match err {
        McpError::BatchTooLarge { count, limit } => {
            assert_eq!(count, 3);
            assert_eq!(limit, 2);
        }
        _ => panic!("wrong err: {err:?}"),
    }
}

#[test]
fn batch_empty_ok() {
    let c = McpCoordinator::new();
    let b = BatchRequest::new(vec![]);
    assert!(b.is_empty());
    assert_eq!(b.len(), 0);
    let r = rt()
        .block_on(c.dispatch_batch(b, RequestContext::now()))
        .unwrap();
    assert_eq!(r.responses.len(), 0);
}

// ── Built-in tools ──────────────────────────────────────────────────────────

#[test]
fn counter_tool_increments() {
    let t = Arc::new(CounterTool::new());
    assert_eq!(t.value(), 0);
    let r = rt()
        .block_on(t.execute(serde_json::json!({}), &RequestContext::now()))
        .unwrap();
    assert_eq!(r["count"], 1);
    assert_eq!(t.value(), 1);
}

#[test]
fn counter_tool_default() {
    let t = CounterTool::default();
    assert_eq!(t.value(), 0);
}

#[test]
fn introspect_tool_lists_registered() {
    let c = Arc::new(McpCoordinator::new());
    c.register_tool(Arc::new(EchoTool));
    let intro = IntrospectTool::new(c.clone());
    let r = rt()
        .block_on(intro.execute(serde_json::json!({}), &RequestContext::now()))
        .unwrap();
    assert_eq!(r["tool_count"], 1);
    assert!(r["tools"].as_array().unwrap().iter().any(|v| v == "echo"));
}

#[test]
fn health_tool_returns_ok() {
    let r = rt()
        .block_on(HealthTool.execute(serde_json::json!({}), &RequestContext::now()))
        .unwrap();
    assert_eq!(r["status"], "ok");
}

#[test]
fn validated_tool_uses_schema() {
    let t = ValidatedTool::new("vt", "field");
    let s = t.schema();
    assert_eq!(s.required, vec!["field".to_string()]);
}

// ── McpCapabilityFlags ──────────────────────────────────────────────────────

#[test]
fn flags_all_and_tools_only() {
    let a = McpCapabilityFlags::all();
    assert!(a.tools && a.resources && a.prompts && a.logging);
    assert!(a.any());
    let t = McpCapabilityFlags::tools_only();
    assert!(t.tools && !t.resources && !t.prompts && !t.logging);
    assert!(t.any());
}

#[test]
fn flags_default_none_set() {
    let d = McpCapabilityFlags::default();
    assert!(!d.any());
}

#[test]
fn flags_display_lists_enabled() {
    let f = McpCapabilityFlags {
        tools: true,
        resources: false,
        prompts: true,
        logging: false,
    };
    let s = f.to_string();
    assert!(s.contains("tools"));
    assert!(s.contains("prompts"));
    assert!(!s.contains("resources"));
}

#[test]
fn flags_to_json_structure() {
    let v = McpCapabilityFlags::all().to_json();
    assert_eq!(v["tools"]["enabled"], true);
    assert_eq!(v["resources"]["enabled"], true);
    assert_eq!(v["prompts"]["enabled"], true);
    assert_eq!(v["logging"]["enabled"], true);
}

// ── McpToolDef / McpResourceDef ─────────────────────────────────────────────

#[test]
fn tool_def_simple_schema_shape() {
    let s = McpToolDef::simple_schema(&[("a", "string", "A"), ("b", "integer", "B")]);
    assert_eq!(s["type"], "object");
    assert_eq!(s["required"].as_array().unwrap().len(), 2);
    assert_eq!(s["properties"]["a"]["type"], "string");
}

#[test]
fn tool_def_display() {
    let t = McpToolDef::new("foo.bar", "desc", serde_json::json!({}));
    assert_eq!(t.to_string(), "McpToolDef(foo.bar)");
}

#[test]
fn resource_def_is_text() {
    let r = McpResourceDef::new("u", "n", "d", "text/plain");
    assert!(r.is_text());
    let r2 = McpResourceDef::new("u", "n", "d", "application/json");
    assert!(r2.is_text());
    let r3 = McpResourceDef::new("u", "n", "d", "application/octet-stream");
    assert!(!r3.is_text());
}

#[test]
fn resource_def_display() {
    let r = McpResourceDef::new("u://x", "Name", "d", "text/plain");
    assert_eq!(r.to_string(), "McpResourceDef(Name -> u://x)");
}

// ── RustreCapabilities catalogue ────────────────────────────────────────────

#[test]
fn rustre_tool_count_matches_list() {
    assert_eq!(
        RustreCapabilities::tool_count(),
        RustreCapabilities::list_tools().len()
    );
    assert!(RustreCapabilities::tool_count() >= 20);
}

#[test]
fn rustre_resource_count_matches_list() {
    assert_eq!(
        RustreCapabilities::resource_count(),
        RustreCapabilities::list_resources().len()
    );
}

#[test]
fn rustre_tool_names_unique() {
    let names: Vec<_> = RustreCapabilities::list_tools()
        .into_iter()
        .map(|t| t.name)
        .collect();
    let set: std::collections::HashSet<_> = names.iter().cloned().collect();
    assert_eq!(names.len(), set.len(), "duplicate tool names in catalogue");
}

#[test]
fn rustre_resource_uris_unique() {
    let uris: Vec<_> = RustreCapabilities::list_resources()
        .into_iter()
        .map(|r| r.uri)
        .collect();
    let set: std::collections::HashSet<_> = uris.iter().cloned().collect();
    assert_eq!(uris.len(), set.len());
}

#[test]
fn rustre_find_tool_present_and_absent() {
    assert!(RustreCapabilities::find_tool("project.open").is_some());
    assert!(RustreCapabilities::find_tool("nope.nada").is_none());
}

#[test]
fn rustre_find_resource_by_name() {
    // find_resource matches by name not URI (per source).
    assert!(RustreCapabilities::find_resource("Current Project").is_some());
    assert!(RustreCapabilities::find_resource("DoesNotExist").is_none());
}

#[test]
fn rustre_tools_by_namespace_groups() {
    let map = RustreCapabilities::tools_by_namespace();
    assert!(map.contains_key("project"));
    assert!(map.contains_key("binary"));
    assert!(map.contains_key("disasm"));
    // Every tool name in the namespace should actually start with that namespace.
    for (ns, names) in &map {
        for n in names {
            assert!(
                n.starts_with(&format!("{ns}.")) || n == ns,
                "tool {n} not in namespace {ns}"
            );
        }
    }
}

#[test]
fn rustre_capability_flags_all_enabled() {
    let f = RustreCapabilities::capability_flags();
    assert!(f.tools && f.resources && f.prompts && f.logging);
}

#[test]
fn rustre_every_tool_schema_is_object() {
    for t in RustreCapabilities::list_tools() {
        assert_eq!(
            t.input_schema["type"], "object",
            "tool {} input_schema.type != object",
            t.name
        );
    }
}

// ── Coordinator Send/Sync sanity ────────────────────────────────────────────

#[test]
fn coordinator_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<McpCoordinator>();
    assert_send_sync::<Arc<McpCoordinator>>();
}

#[test]
fn coordinator_concurrent_dispatch() {
    let c = Arc::new(McpCoordinator::new());
    c.register_tool(Arc::new(CounterTool::new()));
    let rt = rt();
    rt.block_on(async {
        let mut handles = vec![];
        for i in 0..20 {
            let c2 = c.clone();
            handles.push(tokio::spawn(async move {
                c2.dispatch(McpRequest::new(format!("{i}"), "counter")).await
            }));
        }
        for h in handles {
            let r = h.await.unwrap();
            assert!(r.is_ok());
        }
    });
    let m = c.metrics("counter").unwrap();
    assert_eq!(m.success_count, 20);
}
