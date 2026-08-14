// ─── extra dataflow wrappers (generated) ─────────────────────────────────

/// Upper bound on node counts accepted over the wire. The dataflow
/// algorithms allocate `O(n)` vectors sized by `n` directly, so an
/// unchecked JSON `n` (e.g. `18446744073709551615`) would attempt a
/// multi-terabyte allocation and abort the process.
const DF_MAX_NODES: usize = 1_000_000;

fn df_check_n(n: usize) -> Result<usize, McpError> {
    if n > DF_MAX_NODES {
        return Err(McpError::InvalidParams(format!(
            "'n' too large ({n} > {DF_MAX_NODES})"
        )));
    }
    Ok(n)
}

fn df_parse_succ_lists(args: &Value) -> Result<(usize, Vec<Vec<usize>>, usize), McpError> {
    let n = df_check_n(args.get("n").and_then(Value::as_u64)
        .ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))? as usize)?;
    let entry = args.get("entry").and_then(Value::as_u64).unwrap_or(0) as usize;
    let succ_arr = args.get("successors").and_then(Value::as_array)
        .ok_or_else(|| McpError::InvalidParams("missing 'successors'".into()))?;
    let mut succ: Vec<Vec<usize>> = Vec::with_capacity(succ_arr.len());
    for row in succ_arr {
        let inner = row.as_array().ok_or_else(|| McpError::InvalidParams("successors row not array".into()))?;
        succ.push(inner.iter().filter_map(|v| v.as_u64().map(|x| x as usize)).collect());
    }
    Ok((n, succ, entry))
}

pub struct AnalysisDataflowPropagateConstantsTool;
impl AnalysisDataflowPropagateConstantsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_dataflow_propagate_constants".to_string(),
            description: "Sparse constant propagation over assignments and uses.".to_string(),
            input_schema: json!({"type":"object","properties":{"assignments":{"type":"array"},"uses":{"type":"array"}},"required":["assignments"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisDataflowPropagateConstantsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let assigns: Vec<(u32, i64)> = args.get("assignments").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| {
            let arr = v.as_array()?;
            Some((arr.first()?.as_u64()? as u32, arr.get(1)?.as_i64()?))
        }).collect()).unwrap_or_default();
        let uses: Vec<(u32, u32)> = args.get("uses").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| {
            let arr = v.as_array()?;
            Some((arr.first()?.as_u64()? as u32, arr.get(1)?.as_u64()? as u32))
        }).collect()).unwrap_or_default();
        let res = rustre_analysis_dataflow::propagate_constants(&assigns, &uses);
        let out: Vec<Value> = res.into_iter().map(|(k, v)| {
            let (kind, val) = match v {
                rustre_analysis_dataflow::LatticeValue::Top => ("top", None),
                rustre_analysis_dataflow::LatticeValue::Const(c) => ("const", Some(c)),
                rustre_analysis_dataflow::LatticeValue::Bottom => ("bottom", None),
            };
            json!({"var_id": k, "kind": kind, "value": val})
        }).collect();
        Ok(ToolResult::text(json!({"vars": out, "source":"rustre_analysis_dataflow::propagate_constants"}).to_string()))
    }
}

pub struct AnalysisDataflowComputeDominatorsTool;
impl AnalysisDataflowComputeDominatorsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_dataflow_compute_dominators".to_string(),
            description: "Compute immediate dominators via Cooper-Harvey-Kennedy iterative RPO.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"successors":{"type":"array"},"entry":{"type":"integer"}},"required":["n","successors"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisDataflowComputeDominatorsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (n, succ, entry) = df_parse_succ_lists(&args)?;
        let idom = rustre_analysis_dataflow::compute_dominators(n, &succ, entry);
        Ok(ToolResult::text(json!({"idom": idom, "source":"rustre_analysis_dataflow::compute_dominators"}).to_string()))
    }
}

pub struct AnalysisDataflowComputeDominatorsFromEdgesTool;
impl AnalysisDataflowComputeDominatorsFromEdgesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_dataflow_compute_dominators_from_edges".to_string(),
            description: "Compute idom from [from,to] edge list.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"edges":{"type":"array"},"entry":{"type":"integer"}},"required":["n","edges"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisDataflowComputeDominatorsFromEdgesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = df_check_n(args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))? as usize)?;
        let entry = args.get("entry").and_then(Value::as_u64).unwrap_or(0) as usize;
        let edges_arr = args.get("edges").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'edges'".into()))?;
        let mut edges: Vec<[usize; 2]> = Vec::with_capacity(edges_arr.len());
        for e in edges_arr {
            let a = e.as_array().ok_or_else(|| McpError::InvalidParams("edge not array".into()))?;
            let from = a.first().and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("edge from".into()))? as usize;
            let to = a.get(1).and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("edge to".into()))? as usize;
            edges.push([from, to]);
        }
        let idom = rustre_analysis_dataflow::compute_dominators_from_edges(n, &edges, entry);
        Ok(ToolResult::text(json!({"idom": idom, "source":"rustre_analysis_dataflow::compute_dominators_from_edges"}).to_string()))
    }
}

pub struct AnalysisDataflowPostorderTool;
impl AnalysisDataflowPostorderTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_dataflow_postorder".to_string(),
            description: "Iterative DFS postorder over successor adjacency list.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"successors":{"type":"array"},"entry":{"type":"integer"}},"required":["n","successors"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisDataflowPostorderTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (n, succ, entry) = df_parse_succ_lists(&args)?;
        let po = rustre_analysis_dataflow::postorder(n, &succ, entry);
        Ok(ToolResult::text(json!({"postorder": po, "source":"rustre_analysis_dataflow::postorder"}).to_string()))
    }
}

pub struct AnalysisDataflowComputeDominanceFrontiersTool;
impl AnalysisDataflowComputeDominanceFrontiersTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_dataflow_compute_dominance_frontiers".to_string(),
            description: "Compute dominance frontiers given successors and idom.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"successors":{"type":"array"},"idom":{"type":"array"}},"required":["n","successors","idom"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisDataflowComputeDominanceFrontiersTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (n, succ, _entry) = df_parse_succ_lists(&args)?;
        let idom: Vec<usize> = args.get("idom").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'idom'".into()))?
            .iter().filter_map(|v| v.as_u64().map(|x| x as usize)).collect();
        // compute_dominance_frontiers indexes `idom[y]` for every y < n with
        // no length guard (its documented precondition is "idom as returned
        // by compute_dominators", i.e. length n). A shorter wire-supplied
        // idom array panics with index-out-of-bounds — validate here.
        if idom.len() != n {
            return Err(McpError::InvalidParams(format!(
                "'idom' length {} != n ({n})", idom.len()
            )));
        }
        let df = rustre_analysis_dataflow::compute_dominance_frontiers(n, &succ, &idom);
        Ok(ToolResult::text(json!({"frontiers": df, "source":"rustre_analysis_dataflow::compute_dominance_frontiers"}).to_string()))
    }
}

pub struct AnalysisDataflowInsertPhiNodesTool;
impl AnalysisDataflowInsertPhiNodesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_dataflow_insert_phi_nodes".to_string(),
            description: "Insert SSA phi-nodes at iterated dominance frontier of each variable.".to_string(),
            input_schema: json!({"type":"object","properties":{"cfg":{"type":"array"},"defs":{"type":"object"}},"required":["cfg","defs"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisDataflowInsertPhiNodesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg_arr = args.get("cfg").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'cfg'".into()))?;
        let mut cfg: Vec<(u32, Vec<u32>)> = Vec::with_capacity(cfg_arr.len());
        for v in cfg_arr {
            let bb = v.get("bb_id").and_then(Value::as_u64)
                .ok_or_else(|| McpError::InvalidParams("cfg missing bb_id".into()))? as u32;
            let succs: Vec<u32> = v.get("successors").and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|x| x.as_u64().map(|n| n as u32)).collect())
                .unwrap_or_default();
            cfg.push((bb, succs));
        }
        let defs_obj = args.get("defs").and_then(Value::as_object)
            .ok_or_else(|| McpError::InvalidParams("missing 'defs'".into()))?;
        let mut defs: std::collections::HashMap<u32, Vec<u32>> = std::collections::HashMap::new();
        for (k, v) in defs_obj {
            let var_id: u32 = k.parse().map_err(|_| McpError::InvalidParams("defs key not u32".into()))?;
            let bbs: Vec<u32> = v.as_array().map(|a| a.iter().filter_map(|x| x.as_u64().map(|n| n as u32)).collect()).unwrap_or_default();
            defs.insert(var_id, bbs);
        }
        let phi = rustre_analysis_dataflow::insert_phi_nodes(&cfg, &defs);
        let out: Vec<Value> = phi.into_iter().map(|(bb, vars)| json!({"bb_id": bb, "vars": vars})).collect();
        Ok(ToolResult::text(json!({"phi_blocks": out, "source":"rustre_analysis_dataflow::insert_phi_nodes"}).to_string()))
    }
}

fn df_parse_edges_u64(args: &Value) -> Result<Vec<(u64, u64)>, McpError> {
    let arr = args.get("edges").and_then(Value::as_array)
        .ok_or_else(|| McpError::InvalidParams("missing 'edges'".into()))?;
    let mut out = Vec::with_capacity(arr.len());
    for e in arr {
        let a = e.as_array().ok_or_else(|| McpError::InvalidParams("edge not array".into()))?;
        let caller = a.first().and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("edge caller".into()))?;
        let callee = a.get(1).and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("edge callee".into()))?;
        out.push((caller, callee));
    }
    Ok(out)
}

pub struct AnalysisDataflowTraceCallersBackwardTool;
impl AnalysisDataflowTraceCallersBackwardTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_dataflow_trace_callers_backward".to_string(),
            description: "BFS call-graph backwards from address up to `hops` hops.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"hops":{"type":"integer"},"edges":{"type":"array"}},"required":["addr","hops","edges"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisDataflowTraceCallersBackwardTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let hops = args.get("hops").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'hops'".into()))? as usize;
        let edges = df_parse_edges_u64(&args)?;
        let bt = rustre_analysis_dataflow::trace_callers_backward(addr, hops, &edges);
        Ok(ToolResult::text(serde_json::to_string(&json!({"trace": bt, "source":"rustre_analysis_dataflow::trace_callers_backward"})).unwrap()))
    }
}

pub struct AnalysisDataflowTraceCalleesForwardTool;
impl AnalysisDataflowTraceCalleesForwardTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_dataflow_trace_callees_forward".to_string(),
            description: "BFS call-graph forward from address up to `hops` hops.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"hops":{"type":"integer"},"edges":{"type":"array"}},"required":["addr","hops","edges"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisDataflowTraceCalleesForwardTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let hops = args.get("hops").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'hops'".into()))? as usize;
        let edges = df_parse_edges_u64(&args)?;
        let ft = rustre_analysis_dataflow::trace_callees_forward(addr, hops, &edges);
        Ok(ToolResult::text(serde_json::to_string(&json!({"trace": ft, "source":"rustre_analysis_dataflow::trace_callees_forward"})).unwrap()))
    }
}

pub struct AnalysisDataflowLatticeMeetTool;
impl AnalysisDataflowLatticeMeetTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_dataflow_lattice_meet".to_string(),
            description: "Meet (GLB) of two lattice values (Top/Const/Bottom).".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"object"},"b":{"type":"object"}},"required":["a","b"]}),
            parameters: Value::Null,
        }
    }
}
/// Parse one lattice value from the tool arguments.
///
/// An unrecognised or missing `kind` maps to `Bottom`, which is the
/// *conservative* element of this lattice (`Bottom` = "more than one value or
/// non-constant"), so an unparseable input can only weaken the result.
///
/// `kind: "const"` is different: it is a claim that the value is exactly one
/// specific integer. A missing or out-of-`i64`-range `value` used to be
/// silently read as `Const(0)` — turning "you did not tell me the constant"
/// into "the constant is zero", which `meet` then propagates as fact
/// (`meet(Const(0), Const(0)) == Const(0)`). There is no conservative integer
/// to fall back on, so this is rejected instead.
fn df_parse_lattice(v: &Value, field: &str) -> Result<rustre_analysis_dataflow::LatticeValue, McpError> {
    let kind = v.get("kind").and_then(Value::as_str).unwrap_or("bottom");
    Ok(match kind {
        "top" => rustre_analysis_dataflow::LatticeValue::Top,
        "const" => {
            let c = v.get("value").and_then(Value::as_i64).ok_or_else(|| {
                McpError::InvalidParams(format!(
                    "'{field}.kind' is \"const\" but '{field}.value' is missing or not an i64"
                ))
            })?;
            rustre_analysis_dataflow::LatticeValue::Const(c)
        }
        _ => rustre_analysis_dataflow::LatticeValue::Bottom,
    })
}
#[async_trait]
impl ToolHandler for AnalysisDataflowLatticeMeetTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = df_parse_lattice(args.get("a").unwrap_or(&Value::Null), "a")?;
        let b = df_parse_lattice(args.get("b").unwrap_or(&Value::Null), "b")?;
        let m = rustre_analysis_dataflow::LatticeValue::meet(&a, &b);
        let (kind, val) = match m {
            rustre_analysis_dataflow::LatticeValue::Top => ("top", None),
            rustre_analysis_dataflow::LatticeValue::Const(c) => ("const", Some(c)),
            rustre_analysis_dataflow::LatticeValue::Bottom => ("bottom", None),
        };
        Ok(ToolResult::text(json!({"kind": kind, "value": val, "source":"rustre_analysis_dataflow::LatticeValue::meet"}).to_string()))
    }
}

pub struct AnalysisDataflowMaxBackwardHopsTool;
impl AnalysisDataflowMaxBackwardHopsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_dataflow_max_backward_hops".to_string(),
            description: "Return MAX_BACKWARD_HOPS clamp constant.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisDataflowMaxBackwardHopsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({"max_hops": rustre_analysis_dataflow::MAX_BACKWARD_HOPS, "source":"rustre_analysis_dataflow::MAX_BACKWARD_HOPS"}).to_string()))
    }
}

pub struct AnalysisDataflowMaxForwardHopsTool;
impl AnalysisDataflowMaxForwardHopsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_dataflow_max_forward_hops".to_string(),
            description: "Return MAX_FORWARD_HOPS clamp constant.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisDataflowMaxForwardHopsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({"max_hops": rustre_analysis_dataflow::MAX_FORWARD_HOPS, "source":"rustre_analysis_dataflow::MAX_FORWARD_HOPS"}).to_string()))
    }
}

pub struct AnalysisDataflowLinearCfgSizeTool;
impl AnalysisDataflowLinearCfgSizeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_dataflow_linear_cfg_size".to_string(),
            description: "Build a linear CFG of N single-statement blocks; return node count and exit id.".to_string(),
            input_schema: json!({"type":"object","properties":{"count":{"type":"integer"}},"required":["count"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisDataflowLinearCfgSizeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = df_check_n(args.get("count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'count'".into()))? as usize)?;
        let stmts: Vec<rustre_analysis_dataflow::Statement> = (0..n)
            .map(|i| rustre_analysis_dataflow::Statement::new(i, Some("v"), vec!["a"]))
            .collect();
        let cfg = rustre_analysis_dataflow::linear_cfg(stmts);
        Ok(ToolResult::text(json!({"node_count": cfg.node_count(), "entry": cfg.entry, "exit": cfg.exit, "source":"rustre_analysis_dataflow::linear_cfg"}).to_string()))
    }
}

pub(crate) fn dataflow_extra_handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (AnalysisDataflowPropagateConstantsTool::definition(), Box::new(AnalysisDataflowPropagateConstantsTool)),
        (AnalysisDataflowComputeDominatorsTool::definition(), Box::new(AnalysisDataflowComputeDominatorsTool)),
        (AnalysisDataflowComputeDominatorsFromEdgesTool::definition(), Box::new(AnalysisDataflowComputeDominatorsFromEdgesTool)),
        (AnalysisDataflowPostorderTool::definition(), Box::new(AnalysisDataflowPostorderTool)),
        (AnalysisDataflowComputeDominanceFrontiersTool::definition(), Box::new(AnalysisDataflowComputeDominanceFrontiersTool)),
        (AnalysisDataflowInsertPhiNodesTool::definition(), Box::new(AnalysisDataflowInsertPhiNodesTool)),
        (AnalysisDataflowTraceCallersBackwardTool::definition(), Box::new(AnalysisDataflowTraceCallersBackwardTool)),
        (AnalysisDataflowTraceCalleesForwardTool::definition(), Box::new(AnalysisDataflowTraceCalleesForwardTool)),
        (AnalysisDataflowLatticeMeetTool::definition(), Box::new(AnalysisDataflowLatticeMeetTool)),
        (AnalysisDataflowMaxBackwardHopsTool::definition(), Box::new(AnalysisDataflowMaxBackwardHopsTool)),
        (AnalysisDataflowMaxForwardHopsTool::definition(), Box::new(AnalysisDataflowMaxForwardHopsTool)),
        (AnalysisDataflowLinearCfgSizeTool::definition(), Box::new(AnalysisDataflowLinearCfgSizeTool)),
    ]
}

#[cfg(test)]
mod lattice_parse_tests {
    use super::*;

    /// `kind: "const"` without a usable `value` must be REJECTED, not silently
    /// read as `Const(0)`.
    ///
    /// This is the defect this module's parser used to have. `Bottom` (the
    /// fallback for an unknown `kind`) is conservative — it only ever weakens
    /// a `meet`. `Const(0)` is not: it is a positive claim, and `meet` treats
    /// it as fact, so `meet({kind:"const"}, {kind:"const", value:0})` used to
    /// report `Const(0)` for a caller that never named a constant at all.
    #[test]
    fn const_without_value_is_rejected_not_read_as_zero() {
        let missing = json!({"kind": "const"});
        let err = df_parse_lattice(&missing, "a").expect_err("must reject");
        assert!(
            matches!(err, McpError::InvalidParams(_)),
            "expected InvalidParams, got {err:?}"
        );

        // Out of i64 range: `as_i64` returns None, so the old code also read
        // this as Const(0) — a different integer from the one requested.
        let too_big = json!({"kind": "const", "value": 9_223_372_036_854_775_808_u64});
        assert!(
            df_parse_lattice(&too_big, "a").is_err(),
            "an out-of-i64-range constant must not be silently reinterpreted"
        );
    }

    /// An unknown or absent `kind` stays `Bottom`: that fallback is the
    /// conservative element and is deliberately kept.
    #[test]
    fn unknown_kind_stays_conservative_bottom() {
        for v in [json!({}), json!({"kind": "nonsense"}), Value::Null] {
            assert_eq!(
                df_parse_lattice(&v, "a").expect("non-const kinds never fail"),
                rustre_analysis_dataflow::LatticeValue::Bottom,
                "unknown kind must map to Bottom, the conservative element"
            );
        }
    }

    /// The well-formed cases keep working unchanged.
    #[test]
    fn well_formed_values_round_trip() {
        assert_eq!(
            df_parse_lattice(&json!({"kind": "top"}), "a").expect("valid"),
            rustre_analysis_dataflow::LatticeValue::Top
        );
        assert_eq!(
            df_parse_lattice(&json!({"kind": "const", "value": -7}), "a").expect("valid"),
            rustre_analysis_dataflow::LatticeValue::Const(-7)
        );
    }
}
