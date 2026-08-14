//! Integration-seam tests: adversarial/degenerate JSON inputs fed through the
//! MCP tool handlers (the consumer entry points) into the rustre-analysis-*
//! crates. Asserts no panic and sentinel-conformant outputs.

use rustre_mcp_server::{ContentBlock, McpError, ToolHandler};
use rustre_mcp_tools::tools::analysis::{
    AnalysisDataflowComputeLivenessTool, AnalysisDataflowComputeReachingDefsTool,
};
use rustre_mcp_tools::wire_tools::{
    AnalysisDataflowComputeDominanceFrontiersTool, AnalysisDataflowComputeDominatorsFromEdgesTool,
    AnalysisDataflowComputeDominatorsTool, AnalysisDataflowInsertPhiNodesTool,
    AnalysisDataflowLinearCfgSizeTool, AnalysisDataflowPropagateConstantsTool,
    AnalysisDataflowTraceCallersBackwardTool,
};
use serde_json::{json, Value};

async fn call_json(tool: &dyn ToolHandler, args: Value) -> Value {
    let res = tool.call(args).await.expect("tool call ok");
    let txt = res
        .content
        .iter()
        .find_map(|b| match b {
            ContentBlock::Text { text } => Some(text.clone()),
            _ => None,
        })
        .expect("text content");
    serde_json::from_str(&txt).expect("valid json payload")
}

async fn expect_invalid(tool: &dyn ToolHandler, args: Value) {
    match tool.call(args).await {
        Err(McpError::InvalidParams(_)) => {}
        other => panic!("expected InvalidParams, got {other:?}"),
    }
}

// ── compute_dominators ──────────────────────────────────────────────────────

#[tokio::test]
async fn dominators_empty_graph() {
    let v = call_json(
        &AnalysisDataflowComputeDominatorsTool,
        json!({"n": 0, "successors": [], "entry": 0}),
    )
    .await;
    assert_eq!(v["idom"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn dominators_out_of_range_entry_yields_self_loop_sentinels() {
    let v = call_json(
        &AnalysisDataflowComputeDominatorsTool,
        json!({"n": 3, "successors": [[1],[2],[]], "entry": 99}),
    )
    .await;
    let idom: Vec<u64> = v["idom"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap())
        .collect();
    // Documented sentinel: idom[i] == i for every node when entry >= n.
    assert_eq!(idom, vec![0, 1, 2]);
}

#[tokio::test]
async fn dominators_unreachable_self_loop_and_short_rows() {
    // n=4 but only 2 successor rows; node 2 has a self-loop; node 3 unreachable.
    let v = call_json(
        &AnalysisDataflowComputeDominatorsTool,
        json!({"n": 4, "successors": [[1, 7, 2], [2]], "entry": 0}),
    )
    .await;
    let idom: Vec<u64> = v["idom"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap())
        .collect();
    assert_eq!(idom.len(), 4);
    assert_eq!(idom[0], 0, "entry dominates itself");
    assert_eq!(idom[3], 3, "unreachable node keeps self-loop sentinel");
    // Out-of-range successor 7 must be ignored, node 2 reachable via 0.
    assert_eq!(idom[2], 0);
}

#[tokio::test]
async fn dominators_huge_n_rejected_not_oom() {
    expect_invalid(
        &AnalysisDataflowComputeDominatorsTool,
        json!({"n": 4_000_000_000u64, "successors": [], "entry": 0}),
    )
    .await;
    expect_invalid(
        &AnalysisDataflowComputeDominatorsTool,
        json!({"n": u64::MAX, "successors": [[0]], "entry": 0}),
    )
    .await;
}

#[tokio::test]
async fn dominators_from_edges_out_of_range_and_huge_n() {
    // Edge endpoints out of range must be ignored, not panic.
    let v = call_json(
        &AnalysisDataflowComputeDominatorsFromEdgesTool,
        json!({"n": 2, "edges": [[0,1],[5,1],[1,9],[1,1]], "entry": 0}),
    )
    .await;
    let idom = v["idom"].as_array().unwrap();
    assert_eq!(idom.len(), 2);
    assert_eq!(idom[1].as_u64().unwrap(), 0);

    expect_invalid(
        &AnalysisDataflowComputeDominatorsFromEdgesTool,
        json!({"n": 4_000_000_000u64, "edges": [], "entry": 0}),
    )
    .await;
}

// ── dominance frontiers (regression: short idom used to panic) ─────────────

#[tokio::test]
async fn dominance_frontiers_short_idom_rejected_regression() {
    // Before the seam fix this reached compute_dominance_frontiers with
    // idom.len()=0 < n=2 and panicked with index-out-of-bounds on idom[y].
    expect_invalid(
        &AnalysisDataflowComputeDominanceFrontiersTool,
        json!({"n": 2, "successors": [[1],[0]], "idom": []}),
    )
    .await;
    // Non-numeric idom entries are dropped by the marshaller -> length
    // mismatch must also be rejected, not passed through.
    expect_invalid(
        &AnalysisDataflowComputeDominanceFrontiersTool,
        json!({"n": 2, "successors": [[1],[0]], "idom": [0, "bogus"]}),
    )
    .await;
}

#[tokio::test]
async fn dominance_frontiers_valid_loop_header() {
    let v = call_json(
        &AnalysisDataflowComputeDominanceFrontiersTool,
        json!({"n": 2, "successors": [[1],[0]], "idom": [0, 0]}),
    )
    .await;
    let fr = v["frontiers"].as_array().unwrap();
    assert_eq!(fr.len(), 2);
    // Back edge 1->0: entry is in its own frontier.
    assert!(fr[0].as_array().unwrap().iter().any(|x| x.as_u64() == Some(0)));
}

// ── insert_phi_nodes ────────────────────────────────────────────────────────

#[tokio::test]
async fn insert_phi_nodes_degenerate_inputs() {
    // Empty cfg -> empty result, no panic.
    let v = call_json(
        &AnalysisDataflowInsertPhiNodesTool,
        json!({"cfg": [], "defs": {}}),
    )
    .await;
    assert_eq!(v["phi_blocks"].as_array().unwrap().len(), 0);

    // Duplicate bb_ids, self-loop, defs referencing nonexistent blocks,
    // successors referencing nonexistent bb_ids.
    let v = call_json(
        &AnalysisDataflowInsertPhiNodesTool,
        json!({
            "cfg": [
                {"bb_id": 0, "successors": [1, 2, 999]},
                {"bb_id": 1, "successors": [3]},
                {"bb_id": 1, "successors": [3]},
                {"bb_id": 2, "successors": [3, 2]},
                {"bb_id": 3, "successors": []}
            ],
            "defs": {"7": [1, 2, 12345], "8": []}
        }),
    )
    .await;
    // Var 7 defined in both branch arms -> phi at join block 3.
    let phi = v["phi_blocks"].as_array().unwrap();
    assert!(phi
        .iter()
        .any(|b| b["bb_id"].as_u64() == Some(3)
            && b["vars"].as_array().unwrap().iter().any(|x| x.as_u64() == Some(7))));

    // Non-u32 defs key -> InvalidParams, not panic.
    expect_invalid(
        &AnalysisDataflowInsertPhiNodesTool,
        json!({"cfg": [{"bb_id": 0, "successors": []}], "defs": {"-1": [0]}}),
    )
    .await;
}

// ── liveness / reaching defs ────────────────────────────────────────────────

#[tokio::test]
async fn liveness_degenerate_inputs() {
    // Empty node list.
    let v = call_json(&AnalysisDataflowComputeLivenessTool, json!({"cfg_nodes": []})).await;
    assert_eq!(v["blocks"].as_array().unwrap().len(), 0);

    // Successor referencing a nonexistent block + self-loop + duplicate bb_id
    // (documented: last write wins, one entry per distinct id).
    let v = call_json(
        &AnalysisDataflowComputeLivenessTool,
        json!({"cfg_nodes": [
            {"bb_id": 0, "successors": [0, 42], "gen": [5], "kill": []},
            {"bb_id": 0, "successors": [], "gen": [], "kill": [5]},
            {"bb_id": 1, "successors": [0], "gen": [], "kill": []}
        ]}),
    )
    .await;
    let blocks = v["blocks"].as_array().unwrap();
    let mut ids: Vec<u64> = blocks.iter().map(|b| b["bb_id"].as_u64().unwrap()).collect();
    ids.sort_unstable();
    // 3 rows in, but the duplicate id-0 rows share one identity in the map;
    // the tool echoes one row per input node — just require no panic and
    // that every reported id is one of the inputs.
    assert!(ids.iter().all(|&i| i == 0 || i == 1));
}

#[tokio::test]
async fn reaching_defs_degenerate_inputs() {
    let v = call_json(
        &AnalysisDataflowComputeReachingDefsTool,
        json!({"cfg_nodes": [
            {"bb_id": 10, "successors": [10], "gen": [1], "kill": [2]},
            {"bb_id": 11, "successors": [99], "gen": [2], "kill": [1]}
        ]}),
    )
    .await;
    let blocks = v["blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), 2);
    // Self-loop block: its own gen must reach out.
    let b10 = blocks.iter().find(|b| b["bb_id"].as_u64() == Some(10)).unwrap();
    assert!(b10["rd_out"].as_array().unwrap().iter().any(|x| x.as_u64() == Some(1)));

    // Missing cfg_nodes -> InvalidParams.
    expect_invalid(&AnalysisDataflowComputeReachingDefsTool, json!({})).await;
}

// ── propagate_constants ─────────────────────────────────────────────────────

#[tokio::test]
async fn propagate_constants_malformed_and_conflicting() {
    let v = call_json(
        &AnalysisDataflowPropagateConstantsTool,
        json!({
            // malformed rows (non-array, short array, wrong types) are dropped
            "assignments": [[1, 5], [1, 6], "junk", [2], [3, 7], null],
            "uses": [[0, 4], ["x", 1]]
        }),
    )
    .await;
    let vars = v["vars"].as_array().unwrap();
    let get = |id: u64| vars.iter().find(|e| e["var_id"].as_u64() == Some(id));
    // Var 1 assigned 5 and 6 -> meet is bottom.
    assert_eq!(get(1).unwrap()["kind"].as_str().unwrap(), "bottom");
    // Var 3 single assignment -> const 7.
    let v3 = get(3).unwrap();
    assert_eq!(v3["kind"].as_str().unwrap(), "const");
    assert_eq!(v3["value"].as_i64().unwrap(), 7);
    // Var 4 used but never assigned -> bottom sentinel.
    assert_eq!(get(4).unwrap()["kind"].as_str().unwrap(), "bottom");
}

// ── trace_callers_backward ──────────────────────────────────────────────────

#[tokio::test]
async fn trace_callers_backward_degenerate() {
    // Empty edges, huge hops (must be clamped internally), self-loop edge.
    let v = call_json(
        &AnalysisDataflowTraceCallersBackwardTool,
        json!({"addr": 0x1000, "hops": u64::MAX, "edges": []}),
    )
    .await;
    assert!(v.get("trace").is_some(), "canonical empty-trace shape");

    let v = call_json(
        &AnalysisDataflowTraceCallersBackwardTool,
        json!({"addr": 16, "hops": 1_000_000, "edges": [[16, 16], [8, 16], [8, 8]]}),
    )
    .await;
    assert!(v.get("trace").is_some());

    // Malformed edge row -> InvalidParams, not panic.
    expect_invalid(
        &AnalysisDataflowTraceCallersBackwardTool,
        json!({"addr": 16, "hops": 1, "edges": [[16]]}),
    )
    .await;
}

// ── linear_cfg size (allocation bound) ──────────────────────────────────────

#[tokio::test]
async fn linear_cfg_huge_count_rejected() {
    expect_invalid(
        &AnalysisDataflowLinearCfgSizeTool,
        json!({"count": 4_000_000_000u64}),
    )
    .await;
    let v = call_json(&AnalysisDataflowLinearCfgSizeTool, json!({"count": 0})).await;
    assert_eq!(v["node_count"].as_u64().unwrap(), 0);
}

// ── VSA seam ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn vsa_strided_interval_degenerate() {
    use rustre_mcp_tools::tools::vsa::{
        VsaStridedIntervalJoinWrapTool, VsaValueSetStridedWrapTool,
    };
    // stride 0 and inverted bounds through the wrap tool (defaults fill hi=lo).
    let v = call_json(
        &VsaValueSetStridedWrapTool,
        json!({"lo": 10, "hi": 2, "stride": 0}),
    )
    .await;
    assert!(v.get("display").is_some());

    // Join with degenerate/missing operand fields (all default to 0/hi=lo).
    let v = call_json(
        &VsaStridedIntervalJoinWrapTool,
        json!({"a_lo": u64::MAX, "a_hi": 0, "a_stride": 0}),
    )
    .await;
    // Normalized StridedInterval invariants: lo <= hi.
    assert!(v["lo"].as_u64().unwrap() <= v["hi"].as_u64().unwrap());
}
