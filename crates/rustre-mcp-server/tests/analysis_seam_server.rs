//! Integration-seam tests for rustre-mcp-server's rustre_tools entry points
//! that marshal into the rustre-analysis-* crates.

use rustre_mcp_server::rustre_tools;
use serde_json::json;

#[test]
fn trace_backward_missing_addr_is_invalid_params() {
    let err = rustre_tools::analysis_dataflow_trace_backward(&json!({})).unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("InvalidParams"), "got {msg}");
}

#[test]
fn trace_backward_huge_hops_no_panic() {
    // Real edges + an absurd hop count: must clamp, not hang or panic.
    //
    // This used to pass no `edges` at all and assert only that the result was
    // an object. The tool hard-coded an empty edge set back then, so it always
    // answered "nothing reaches this address" — the assertion held for a
    // result that was never computed from anything.
    let v = rustre_tools::analysis_dataflow_trace_backward(&json!({
        "addr": 0x1400_0000u64,
        "hops": u64::MAX,
        "edges": [[0x1400_1000u64, 0x1400_0000u64], [0x1400_2000u64, 0x1400_1000u64]],
    }))
    .unwrap();
    assert!(v.is_object(), "canonical trace shape, got {v}");
    assert!(
        v["total"].as_u64().unwrap_or(0) >= 1,
        "the supplied edges reach the address, so the trace must not be empty: {v}"
    );
}

#[test]
fn trace_backward_without_edges_is_invalid_params() {
    // No call graph supplied: the tool must say so rather than report an
    // empty trace, which reads as "nothing calls this address".
    let err =
        rustre_tools::analysis_dataflow_trace_backward(&json!({"addr": 0x1000u64})).unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("InvalidParams"), "got {msg}");
    assert!(msg.contains("edges"), "the error must name what is missing: {msg}");
}

#[test]
fn trace_forward_zero_addr_and_zero_hops() {
    let v = rustre_tools::analysis_dataflow_trace_forward(&json!({
        "addr": 0,
        "hops": 0,
        "edges": [[0u64, 0x10u64]],
    }))
    .unwrap();
    assert!(v.is_object());
}

#[test]
fn cfg_basic_blocks_from_address_alone_is_refused() {
    // `rustre-analysis-cfg` owns no disassembler, so blocks cannot be
    // recovered from an address on its own.
    //
    // This test used to assert a "sane shape": `count` equal to the length of
    // `blocks`. That held trivially — the underlying call was a stub returning
    // an empty Vec, so the tool answered `{"count": 0, "blocks": []}` for
    // EVERY address, and 0 == 0 passed forever while the tool told every
    // caller the function had no basic blocks.
    let err = rustre_tools::analysis_cfg_basic_blocks(&json!({"addr": u64::MAX})).unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("InvalidParams"), "got {msg}");
    assert!(
        msg.contains("analysis_basic_blocks_path"),
        "the error must point at the tool that can answer: {msg}"
    );
}

#[test]
fn vsa_query_no_session_returns_low_confidence_unknown() {
    let v = rustre_tools::analysis_vsa_query(&json!({"addr": 0x1000, "target": "rax"})).unwrap();
    let s = v.to_string();
    assert!(s.contains("no session context"), "degenerate sentinel, got {s}");
}

#[test]
fn vsa_query_with_session_runs_engine_no_panic() {
    // session_id present: drives the real VsaEngine over the degenerate
    // single-Nop CFG. Adversarial target strings must not panic.
    for target in ["rax", "", "not_a_register", "[rsp+0x123456789]", "💥"] {
        let v = rustre_tools::analysis_vsa_query(
            &json!({"addr": 0x2000, "session_id": "s1", "target": target}),
        )
        .unwrap();
        assert!(v.get("values").is_some(), "point query shape, got {v}");
    }
}
