//! Adversarial deep-coverage tests for `rustre-mcp` (Y092 blitz2).
//!
//! Covers: McpError, McpCapability, ToolCategory, ToolSchema, RequestContext,
//! McpRequest/Response, RpcError, ToolMetrics, RateLimiter, McpCoordinator
//! dispatch/batch/middleware/category gating/audit/metrics, built-in tools,
//! McpCapabilityFlags, McpToolDef, McpResourceDef, RustreCapabilities.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustre_mcp::*;

// ── Seeded LCG ───────────────────────────────────────────────────────────
fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

// ── McpError ─────────────────────────────────────────────────────────────

#[test]
fn err_rpc_codes_distinct_buckets() {
    use McpError::*;
    let pairs: Vec<(McpError, i32)> = vec![
        (ToolNotFound("t".into()), -32601),
        (InvalidRequest("x".into()), -32600),
        (SchemaValidation("x".into()), -32602),
        (RateLimited("x".into()), -32000),
        (MiddlewareRejected("x".into()), -32001),
        (Timeout("x".into()), -32002),
        (CategoryDisabled("x".into()), -32003),
        (BatchTooLarge { count: 1, limit: 0 }, -32004),
        (
            Execution {
                tool: "a".into(),
                detail: "b".into(),
            },
            -32603,
        ),
        (Internal("z".into()), -32603),
    ];
    for (e, code) in pairs {
        assert_eq!(e.rpc_code(), code, "for {e:?}");
        let rpc = e.to_rpc_error();
        assert_eq!(rpc.code, code);
        assert!(!rpc.message.is_empty());
    }
}

#[test]
fn err_is_transient_classification() {
    assert!(McpError::RateLimited("x".into()).is_transient());
    assert!(McpError::Timeout("x".into()).is_transient());
    assert!(!McpError::InvalidRequest("x".into()).is_transient());
    assert!(!McpError::Internal("x".into()).is_transient());
}

#[test]
fn err_is_client_error_classification() {
    assert!(McpError::InvalidRequest("x".into()).is_client_error());
    assert!(McpError::SchemaValidation("x".into()).is_client_error());
    assert!(McpError::ToolNotFound("x".into()).is_client_error());
    assert!(McpError::BatchTooLarge { count: 9, limit: 1 }.is_client_error());
    assert!(!McpError::Internal("x".into()).is_client_error());
    assert!(!McpError::RateLimited("x".into()).is_client_error());
}

#[test]
fn err_execution_helper_constructs_variant() {
    let e = McpError::execution("foo", "bar");
    match &e {
        McpError::Execution { tool, detail } => {
            assert_eq!(tool, "foo");
            assert_eq!(detail, "bar");
        }
        other => panic!("wrong variant: {other:?}"),
    }
    assert!(e.to_string().contains("foo"));
    assert!(e.to_string().contains("bar"));
}

#[test]
fn err_display_contains_payload() {
    assert!(McpError::ToolNotFound("xyz".into()).to_string().contains("xyz"));
    assert!(
        McpError::BatchTooLarge { count: 5, limit: 3 }
            .to_string()
            .contains("5")
    );
}

// ── McpCapability ────────────────────────────────────────────────────────

#[test]
fn capability_display_format_and_eq() {
    let a = McpCapability::new("n", "d", "1.2.3");
    let b = McpCapability::new("n", "d", "1.2.3");
    assert_eq!(a, b);
    assert_eq!(a.to_string(), "n@1.2.3");
}

#[test]
fn capability_serde_roundtrip_fuzz() {
    let mut g = lcg();
    for _ in 0..60 {
        let n = format!("n{}", g() % 1000);
        let v = format!("{}.{}.{}", g() % 10, g() % 10, g() % 10);
        let c = McpCapability::new(n.clone(), "desc", v.clone());
        let s = serde_json::to_string(&c).unwrap();
        let back: McpCapability = serde_json::from_str(&s).unwrap();
        assert_eq!(back.name, n);
        assert_eq!(back.version, v);
        assert_eq!(back, c);
    }
}

// ── ToolCategory ─────────────────────────────────────────────────────────

#[test]
fn tool_category_as_str_all_variants() {
    let cases = [
        (ToolCategory::Analysis, "analysis"),
        (ToolCategory::Debug, "debug"),
        (ToolCategory::Loader, "loader"),
        (ToolCategory::Symbols, "symbols"),
        (ToolCategory::Script, "script"),
        (ToolCategory::ThreatIntel, "threat_intel"),
        (ToolCategory::Visualize, "visualize"),
        (ToolCategory::Utility, "utility"),
        (ToolCategory::Custom("yo".into()), "yo"),
    ];
    for (c, s) in cases {
        assert_eq!(c.as_str(), s);
        assert_eq!(c.to_string(), s);
    }
}

#[test]
fn tool_category_hash_eq_consistency() {
    let mut set: HashSet<ToolCategory> = HashSet::new();
    set.insert(ToolCategory::Debug);
    set.insert(ToolCategory::Debug);
    set.insert(ToolCategory::Custom("a".into()));
    set.insert(ToolCategory::Custom("a".into()));
    set.insert(ToolCategory::Custom("b".into()));
    assert_eq!(set.len(), 3);
    assert!(set.contains(&ToolCategory::Debug));
    assert!(set.contains(&ToolCategory::Custom("b".into())));
}

// ── ToolSchema ───────────────────────────────────────────────────────────

#[test]
fn schema_any_accepts_empty_object() {
    ToolSchema::any().validate(&serde_json::json!({})).unwrap();
}

#[test]
fn schema_rejects_non_object() {
    for v in [
        serde_json::json!(null),
        serde_json::json!(1),
        serde_json::json!("s"),
        serde_json::json!([1, 2, 3]),
        serde_json::json!(true),
    ] {
        let e = ToolSchema::any().validate(&v).unwrap_err();
        assert!(matches!(e, McpError::SchemaValidation(_)));
    }
}

#[test]
fn schema_all_type_names_recognised() {
    let schema = ToolSchema::any()
        .require("s", "string")
        .require("n", "number")
        .require("b", "boolean")
        .require("a", "array")
        .require("o", "object")
        .require("z", "null");
    let ok = serde_json::json!({
        "s": "hi", "n": 4, "b": true, "a": [], "o": {}, "z": null
    });
    schema.validate(&ok).unwrap();
}

#[test]
fn schema_wrong_type_each_field() {
    let s = ToolSchema::any().require("addr", "number");
    let bad = [
        serde_json::json!({"addr": "x"}),
        serde_json::json!({"addr": true}),
        serde_json::json!({"addr": null}),
        serde_json::json!({"addr": []}),
        serde_json::json!({"addr": {}}),
    ];
    for b in bad {
        assert!(s.validate(&b).is_err(), "should reject {b}");
    }
}

#[test]
fn schema_optional_wrong_type_rejected() {
    let s = ToolSchema::any().optional("count", "number");
    assert!(
        s.validate(&serde_json::json!({"count": "no"})).is_err(),
        "wrong type in optional must still fail"
    );
    s.validate(&serde_json::json!({})).unwrap();
    s.validate(&serde_json::json!({"count": 1})).unwrap();
}

#[test]
fn schema_fuzz_never_panics() {
    let s = ToolSchema::any()
        .require("a", "string")
        .optional("b", "number");
    let mut g = lcg();
    for _ in 0..200 {
        let pick = g() % 6;
        let v = match pick {
            0 => serde_json::json!({}),
            1 => serde_json::json!({"a": format!("s{}", g() % 100)}),
            2 => serde_json::json!({"a": "ok", "b": (g() % 1000) as i64}),
            3 => serde_json::json!({"a": (g() % 5) as i64}),
            4 => serde_json::json!(null),
            _ => serde_json::json!({"b": "wrong"}),
        };
        let _ = s.validate(&v); // must never panic
    }
}

// ── RequestContext ───────────────────────────────────────────────────────

#[test]
fn ctx_now_and_age_monotone() {
    let c = RequestContext::now();
    assert!(c.received_at_ms > 0);
    let a1 = c.age_ms();
    std::thread::sleep(Duration::from_millis(1));
    let a2 = c.age_ms();
    assert!(a2 >= a1);
}

#[test]
fn ctx_builders_layered() {
    let c = RequestContext::now()
        .with_caller("c")
        .with_trace_id("t")
        .with_meta("k1", "v1")
        .with_meta("k2", "v2");
    assert_eq!(c.caller.as_deref(), Some("c"));
    assert_eq!(c.trace_id.as_deref(), Some("t"));
    assert_eq!(c.metadata.len(), 2);
}

// ── McpRequest / McpResponse / RpcError ──────────────────────────────────

#[test]
fn request_with_params_keeps_payload() {
    let r = McpRequest::with_params("i", "m", serde_json::json!({"k": 42}));
    assert_eq!(r.params["k"], 42);
}

#[test]
fn response_ok_err_invariants() {
    let ok = McpResponse::ok("a", serde_json::json!(1), 7);
    assert!(ok.is_ok());
    assert!(ok.error.is_none());
    let err = McpResponse::err(
        "a",
        RpcError {
            code: -32000,
            message: "x".into(),
        },
        9,
    );
    assert!(!err.is_ok());
    assert!(err.result.is_none());
}

#[test]
fn rpc_error_display() {
    let e = RpcError {
        code: -32000,
        message: "boom".into(),
    };
    let s = e.to_string();
    assert!(s.contains("-32000"));
    assert!(s.contains("boom"));
}

#[test]
fn request_response_serde_roundtrip_fuzz() {
    let mut g = lcg();
    for _ in 0..50 {
        let id = format!("id{}", g() % 10_000);
        let method = format!("m{}", g() % 100);
        let req = McpRequest::with_params(id.clone(), method.clone(), serde_json::json!({"x": (g() % 1000) as i64}));
        let s = serde_json::to_string(&req).unwrap();
        let back: McpRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, id);
        assert_eq!(back.method, method);

        let resp = McpResponse::ok(&id, serde_json::json!({"y": 1}), g() % 5000);
        let rs = serde_json::to_string(&resp).unwrap();
        let rb: McpResponse = serde_json::from_str(&rs).unwrap();
        assert!(rb.is_ok());
    }
}

// ── ToolMetrics ──────────────────────────────────────────────────────────

#[test]
fn metrics_empty_defaults() {
    let m = ToolMetrics::default();
    assert_eq!(m.total_calls(), 0);
    assert_eq!(m.avg_us(), 0);
    assert_eq!(m.error_rate(), 0.0);
}

#[test]
fn metrics_record_updates_min_max_avg() {
    let mut m = ToolMetrics::default();
    m.record(Duration::from_micros(10), true, None);
    m.record(Duration::from_micros(40), true, None);
    m.record(Duration::from_micros(20), false, Some("e".into()));
    assert_eq!(m.total_calls(), 3);
    assert_eq!(m.success_count, 2);
    assert_eq!(m.error_count, 1);
    assert_eq!(m.min_us, 10);
    assert_eq!(m.max_us, 40);
    assert!((m.error_rate() - (1.0 / 3.0)).abs() < 1e-9);
    assert_eq!(m.last_error.as_deref(), Some("e"));
    assert!(m.avg_us() >= 20 && m.avg_us() <= 30);
}

#[test]
fn metrics_fuzz_never_panics() {
    let mut g = lcg();
    let mut m = ToolMetrics::default();
    for _ in 0..200 {
        let us = (g() % 10_000) as u64;
        let ok = (g() & 1) == 0;
        m.record(
            Duration::from_micros(us),
            ok,
            if ok { None } else { Some("e".into()) },
        );
    }
    assert_eq!(m.total_calls(), 200);
    assert!(m.error_rate() >= 0.0 && m.error_rate() <= 1.0);
}

// ── RateLimiter ──────────────────────────────────────────────────────────

#[test]
fn rate_limiter_within_budget() {
    let mut rl = RateLimiter::new(3, Duration::from_secs(60));
    assert!(rl.allow());
    assert!(rl.allow());
    assert!(rl.allow());
    assert!(!rl.allow());
    assert_eq!(rl.current_count(), 3);
}

#[test]
fn rate_limiter_zero_budget_always_denied() {
    let mut rl = RateLimiter::new(0, Duration::from_secs(60));
    for _ in 0..10 {
        assert!(!rl.allow());
    }
    assert_eq!(rl.current_count(), 0);
}

#[test]
fn rate_limiter_window_eviction() {
    let mut rl = RateLimiter::new(2, Duration::from_millis(20));
    assert!(rl.allow());
    assert!(rl.allow());
    assert!(!rl.allow());
    std::thread::sleep(Duration::from_millis(40));
    assert!(rl.allow(), "after window passes, slot should free");
}

// ── McpCoordinator ───────────────────────────────────────────────────────

#[test]
fn coord_register_and_dispatch_echo() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    assert!(c.has_tool("echo"));
    assert_eq!(c.tool_count(), 1);
    let resp = rt().block_on(async {
        c.dispatch(McpRequest::with_params("i", "echo", serde_json::json!({"a": 1})))
            .await
    });
    assert!(resp.is_ok());
    assert_eq!(resp.result.unwrap()["a"], 1);
}

#[test]
fn coord_missing_tool_is_tool_not_found() {
    let c = McpCoordinator::new();
    let resp = rt().block_on(async { c.dispatch(McpRequest::new("i", "nope")).await });
    let e = resp.error.unwrap();
    assert_eq!(e.code, -32601);
}

#[test]
fn coord_failing_tool_returns_execution_error() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(FailingTool));
    let resp = rt().block_on(async { c.dispatch(McpRequest::new("i", "fail")).await });
    let e = resp.error.unwrap();
    assert_eq!(e.code, -32603);
}

#[test]
fn coord_remove_and_names() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    c.register_tool(Arc::new(HealthTool));
    let mut names = c.tool_names();
    names.sort();
    assert_eq!(names, vec!["echo", "health"]);
    assert!(c.remove_tool("echo"));
    assert!(!c.remove_tool("echo"));
    assert_eq!(c.tool_count(), 1);
}

#[test]
fn coord_tools_by_category_filters() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    c.register_tool(Arc::new(HealthTool));
    let util = c.tools_by_category(&ToolCategory::Utility);
    assert_eq!(util.len(), 2);
    let an = c.tools_by_category(&ToolCategory::Analysis);
    assert!(an.is_empty());
}

#[test]
fn coord_disable_category_rejects_dispatch() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    c.disable_category(ToolCategory::Utility);
    assert!(!c.is_category_enabled(&ToolCategory::Utility));
    let resp = rt().block_on(async { c.dispatch(McpRequest::new("i", "echo")).await });
    assert_eq!(resp.error.unwrap().code, -32003);
    c.enable_category(&ToolCategory::Utility);
    let resp = rt().block_on(async { c.dispatch(McpRequest::new("i", "echo")).await });
    assert!(resp.is_ok());
}

#[test]
fn coord_schema_validation_rejects_bad_params() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(ValidatedTool::new("v", "name")));
    let resp = rt().block_on(async {
        c.dispatch(McpRequest::with_params("i", "v", serde_json::json!({})))
            .await
    });
    assert_eq!(resp.error.unwrap().code, -32602);
    let resp = rt().block_on(async {
        c.dispatch(McpRequest::with_params(
            "i",
            "v",
            serde_json::json!({"name": "ok"}),
        ))
        .await
    });
    assert!(resp.is_ok());
}

#[test]
fn coord_metrics_track_success_and_error() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    c.register_tool(Arc::new(FailingTool));
    rt().block_on(async {
        for _ in 0..5 {
            c.dispatch(McpRequest::new("i", "echo")).await;
        }
        for _ in 0..3 {
            c.dispatch(McpRequest::new("i", "fail")).await;
        }
    });
    let em = c.metrics("echo").unwrap();
    assert_eq!(em.success_count, 5);
    let fm = c.metrics("fail").unwrap();
    assert_eq!(fm.error_count, 3);
    assert!(fm.last_error.is_some());
    assert_eq!(c.all_metrics().len(), 2);
}

#[test]
fn coord_audit_log_truncates() {
    let c = McpCoordinator::with_limits(3, 100);
    c.register_tool(Arc::new(EchoTool));
    rt().block_on(async {
        for i in 0..10 {
            c.dispatch(McpRequest::new(format!("r{i}"), "echo")).await;
        }
    });
    assert_eq!(c.audit_log_len(), 3);
    c.clear_audit_log();
    assert_eq!(c.audit_log_len(), 0);
}

#[test]
fn coord_rate_limit_path() {
    let c = McpCoordinator::new();
    c.register(
        McpCoordinator::builder(Arc::new(EchoTool))
            .rate_limit(2, Duration::from_secs(60)),
    );
    rt().block_on(async {
        let a = c.dispatch(McpRequest::new("1", "echo")).await;
        let b = c.dispatch(McpRequest::new("2", "echo")).await;
        let cc = c.dispatch(McpRequest::new("3", "echo")).await;
        assert!(a.is_ok() && b.is_ok());
        assert!(!cc.is_ok());
        assert_eq!(cc.error.unwrap().code, -32000);
    });
}

#[test]
fn coord_timeout_path() {
    #[derive(Debug)]
    struct Slow;
    #[async_trait::async_trait]
    impl McpTool for Slow {
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
    c.register(McpCoordinator::builder(Arc::new(Slow)).timeout_ms(20));
    let resp = rt().block_on(async { c.dispatch(McpRequest::new("i", "slow")).await });
    assert_eq!(resp.error.unwrap().code, -32002);
}

#[test]
fn coord_middleware_deny_rejects() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    c.add_middleware(Arc::new(DenyListMiddleware::new(vec!["bad".into()])));
    c.add_middleware(Arc::new(LoggingMiddleware));
    assert_eq!(c.middleware_count(), 2);
    let ctx = RequestContext::now().with_caller("bad");
    let resp = rt().block_on(async {
        c.dispatch_with_context(McpRequest::new("i", "echo"), ctx).await
    });
    assert_eq!(resp.error.unwrap().code, -32001);
    let ctx2 = RequestContext::now().with_caller("good");
    let resp2 = rt().block_on(async {
        c.dispatch_with_context(McpRequest::new("i", "echo"), ctx2).await
    });
    assert!(resp2.is_ok());
    c.clear_middleware();
    assert_eq!(c.middleware_count(), 0);
}

#[test]
fn coord_batch_dispatch_and_errors() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    c.register_tool(Arc::new(FailingTool));
    let batch = BatchRequest::new(vec![
        McpRequest::new("1", "echo"),
        McpRequest::new("2", "fail"),
        McpRequest::new("3", "echo"),
        McpRequest::new("4", "nope"),
    ]);
    let resp = rt().block_on(async {
        c.dispatch_batch(batch, RequestContext::now()).await.unwrap()
    });
    assert_eq!(resp.responses.len(), 4);
    assert_eq!(resp.success_count(), 2);
    assert_eq!(resp.error_count(), 2);
    assert_eq!(resp.errors().len(), 2);
}

#[test]
fn coord_batch_too_large_errors() {
    let c = McpCoordinator::with_limits(100, 2);
    c.register_tool(Arc::new(EchoTool));
    let batch = BatchRequest::new(vec![
        McpRequest::new("1", "echo"),
        McpRequest::new("2", "echo"),
        McpRequest::new("3", "echo"),
    ]);
    let e = rt()
        .block_on(async { c.dispatch_batch(batch, RequestContext::now()).await })
        .unwrap_err();
    assert!(matches!(e, McpError::BatchTooLarge { .. }));
}

#[test]
fn coord_counter_tool_increments() {
    let c = McpCoordinator::new();
    let counter = Arc::new(CounterTool::new());
    c.register_tool(counter.clone());
    rt().block_on(async {
        for _ in 0..7 {
            c.dispatch(McpRequest::new("i", "counter")).await;
        }
    });
    assert_eq!(counter.value(), 7);
}

#[test]
fn coord_introspect_tool_lists_names() {
    let coord = Arc::new(McpCoordinator::new());
    coord.register_tool(Arc::new(EchoTool));
    coord.register_tool(Arc::new(HealthTool));
    let introspect = Arc::new(IntrospectTool::new(coord.clone()));
    coord.register_tool(introspect);
    let resp = rt().block_on(async {
        coord.dispatch(McpRequest::new("i", "introspect")).await
    });
    assert!(resp.is_ok());
    let v = resp.result.unwrap();
    assert_eq!(v["tool_count"], 3);
}

#[test]
fn coord_tool_descriptors_sorted() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(HealthTool));
    c.register_tool(Arc::new(EchoTool));
    let d = c.tool_descriptors();
    assert_eq!(d.len(), 2);
    assert!(d[0].name <= d[1].name);
}

#[test]
fn coord_health_tool_executes() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(HealthTool));
    let r = rt().block_on(async { c.dispatch(McpRequest::new("i", "health")).await });
    assert!(r.is_ok());
    assert_eq!(r.result.unwrap()["status"], "ok");
}

#[test]
fn coord_all_capabilities_aggregates() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    c.register_tool(Arc::new(HealthTool));
    let caps = c.all_capabilities();
    assert!(caps.len() >= 2);
}

#[test]
fn coord_threaded_register_and_dispatch_stress() {
    let c = Arc::new(McpCoordinator::new());
    c.register_tool(Arc::new(EchoTool));
    let mut handles = vec![];
    for _ in 0..4 {
        let cc = c.clone();
        handles.push(thread::spawn(move || {
            let rt = rt();
            for i in 0..100 {
                let r = rt.block_on(async {
                    cc.dispatch(McpRequest::with_params(
                        format!("r{i}"),
                        "echo",
                        serde_json::json!({"i": i}),
                    ))
                    .await
                });
                assert!(r.is_ok());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let m = c.metrics("echo").unwrap();
    assert_eq!(m.success_count, 400);
}

// ── McpCapabilityFlags ───────────────────────────────────────────────────

#[test]
fn capability_flags_all_and_tools_only() {
    let all = McpCapabilityFlags::all();
    assert!(all.tools && all.resources && all.prompts && all.logging);
    assert!(all.any());
    let to = McpCapabilityFlags::tools_only();
    assert!(to.tools && !to.resources && !to.prompts && !to.logging);
    assert!(to.any());
    let none = McpCapabilityFlags::default();
    assert!(!none.any());
}

#[test]
fn capability_flags_to_json_and_display() {
    let j = McpCapabilityFlags::all().to_json();
    assert_eq!(j["tools"]["enabled"], true);
    assert_eq!(j["logging"]["enabled"], true);
    let s = McpCapabilityFlags::tools_only().to_string();
    assert!(s.contains("tools"));
    assert!(!s.contains("logging"));
}

// ── McpToolDef / McpResourceDef ──────────────────────────────────────────

#[test]
fn tool_def_simple_schema_shape() {
    let s = McpToolDef::simple_schema(&[("a", "string", "x"), ("b", "integer", "y")]);
    assert_eq!(s["type"], "object");
    assert!(s["properties"]["a"]["type"] == "string");
    let req = s["required"].as_array().unwrap();
    assert_eq!(req.len(), 2);
}

#[test]
fn tool_def_display() {
    let t = McpToolDef::new("foo.bar", "d", serde_json::json!({}));
    assert!(t.to_string().contains("foo.bar"));
}

#[test]
fn resource_def_is_text_branches() {
    assert!(McpResourceDef::new("u", "n", "d", "text/plain").is_text());
    assert!(McpResourceDef::new("u", "n", "d", "application/json").is_text());
    assert!(!McpResourceDef::new("u", "n", "d", "application/octet-stream").is_text());
}

#[test]
fn resource_def_display_contains_name_and_uri() {
    let r = McpResourceDef::new("u://x", "TheName", "d", "text/plain");
    let s = r.to_string();
    assert!(s.contains("TheName"));
    assert!(s.contains("u://x"));
}

// ── RustreCapabilities ──────────────────────────────────────────────────

#[test]
fn rustre_capabilities_counts_match_lists() {
    let tools = RustreCapabilities::list_tools();
    assert_eq!(tools.len(), RustreCapabilities::tool_count());
    assert!(tools.len() >= 20);
    let resources = RustreCapabilities::list_resources();
    assert_eq!(resources.len(), RustreCapabilities::resource_count());
}

#[test]
fn rustre_capabilities_find_known_tool_and_resource() {
    assert!(RustreCapabilities::find_tool("project.open").is_some());
    assert!(RustreCapabilities::find_tool("does.not.exist").is_none());
    assert!(RustreCapabilities::find_resource("Type Library").is_some());
    assert!(RustreCapabilities::find_resource("Unknown").is_none());
}

#[test]
fn rustre_capabilities_tools_by_namespace_partitions_all() {
    let tools = RustreCapabilities::list_tools();
    let map = RustreCapabilities::tools_by_namespace();
    let total: usize = map.values().map(Vec::len).sum();
    assert_eq!(total, tools.len());
    assert!(map.contains_key("project"));
    assert!(map.contains_key("disasm"));
}

#[test]
fn rustre_capabilities_tool_names_unique() {
    let tools = RustreCapabilities::list_tools();
    let mut set: HashSet<String> = HashSet::new();
    for t in &tools {
        assert!(set.insert(t.name.clone()), "duplicate tool name: {}", t.name);
    }
}

#[test]
fn rustre_capabilities_flag_set_is_all() {
    assert_eq!(
        RustreCapabilities::capability_flags(),
        McpCapabilityFlags::all()
    );
}

// ── Hash/Eq pair fuzz on ToolCategory + McpCapability ────────────────────

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

#[test]
fn tool_category_hash_eq_pair_fuzz() {
    let mut g = lcg();
    let variants = |i: u64| match i % 9 {
        0 => ToolCategory::Analysis,
        1 => ToolCategory::Debug,
        2 => ToolCategory::Loader,
        3 => ToolCategory::Symbols,
        4 => ToolCategory::Script,
        5 => ToolCategory::ThreatIntel,
        6 => ToolCategory::Visualize,
        7 => ToolCategory::Utility,
        _ => ToolCategory::Custom(format!("c{}", i % 5)),
    };
    for _ in 0..40 {
        let a = variants(g());
        let b = variants(g());
        if a == b {
            assert_eq!(hash_of(&a), hash_of(&b));
        }
    }
}

#[test]
fn capability_pair_eq_consistency_fuzz() {
    let mut g = lcg();
    for _ in 0..40 {
        let n1 = format!("n{}", g() % 5);
        let v1 = format!("{}", g() % 3);
        let n2 = format!("n{}", g() % 5);
        let v2 = format!("{}", g() % 3);
        let a = McpCapability::new(&n1, "d", &v1);
        let b = McpCapability::new(&n2, "d", &v2);
        if n1 == n2 && v1 == v2 {
            assert_eq!(a, b);
        } else {
            // names or versions differ ⇒ inequality is permitted (description equal)
            if a != b {
                assert!(a.name != b.name || a.version != b.version);
            }
        }
    }
}

// ── Send/Sync compile-time guards ────────────────────────────────────────

#[test]
fn coordinator_is_send_sync() {
    fn assert_ss<T: Send + Sync>() {}
    assert_ss::<McpCoordinator>();
    assert_ss::<McpRequest>();
    assert_ss::<McpResponse>();
    assert_ss::<ToolMetrics>();
    assert_ss::<McpCapabilityFlags>();
    assert_ss::<McpToolDef>();
    assert_ss::<McpResourceDef>();
}

// ── HashMap usage for metrics snapshot ──────────────────────────────────

#[test]
fn coord_all_metrics_keys_match_tool_names() {
    let c = McpCoordinator::new();
    c.register_tool(Arc::new(EchoTool));
    c.register_tool(Arc::new(HealthTool));
    let m: HashMap<String, ToolMetrics> = c.all_metrics();
    let names: HashSet<String> = c.tool_names().into_iter().collect();
    let keys: HashSet<String> = m.keys().cloned().collect();
    assert_eq!(names, keys);
}
