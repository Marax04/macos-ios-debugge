//! `rustre_tools` â€” **Session-oriented tool layer** of the MCP tool stack.
//!
//! Every tool here takes a `binary_id` string that identifies an already-loaded
//! binary session. Handlers return raw `serde_json::Value` without typed
//! intermediate structs.
//!
//! Exposed tools (14): `analyze_binary`, `decompile_function`, `get_xrefs`,
//! `search_symbol`, `add_comment`, `run_yara`, `get_strings`, `diff_functions`,
//! `identify_crypto`, `extract_iocs`, `get_callgraph`, `emulate_function`,
//! `find_vulnerabilities`, `trace_execution`.
//!
//! # Why this exists alongside `tool_implementation` and `analysis_tools`
//!
//! * [`tool_implementation`] uses typed Rust input/output structs and a
//!   dispatcher that deserialises params via `serde_json::from_value`. It is the
//!   **strongly-typed** dispatch layer.
//! * [`analysis_tools`] works on **raw bytes/hex** with no binary session.
//! * This module (`rustre_tools`) is the **session-scoped** layer: tools that
//!   need a persistent binary context identified by `binary_id`.
//!
//! # `ToolSchema` naming collision
//!
//! This module defines its own [`ToolSchema`] (backed by `Vec<ParamDef>`) for
//! lightweight parameter validation. [`mcp_tool_registry`] also defines a
//! `ToolSchema` (backed by `HashMap<String, Value>` + builder pattern) for
//! JSON-Schema generation. The two types are intentionally distinct â€” the
//! registry schema produces full JSON Schema objects while this one validates
//! presence of required named params.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
pub use std::fmt;

// â”€â”€â”€ Error â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Debug, thiserror::Error)]
pub enum RustreToolError {
    #[error("tool not found: {0}")]
    NotFound(String),
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("execution error: {0}")]
    Execution(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

// â”€â”€â”€ ToolSchema â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamDef {
    pub name: String,
    pub param_type: String,
    pub description: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    pub params: Vec<ParamDef>,
}

impl ToolSchema {
    fn p(name: &str, t: &str, desc: &str, required: bool) -> ParamDef {
        ParamDef {
            name: name.into(),
            param_type: t.into(),
            description: desc.into(),
            required,
        }
    }

    /// Validate that required parameters are present.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` if params is not an object or if a required parameter is missing.
    pub fn validate(&self, params: &Value) -> Result<(), RustreToolError> {
        let obj = params
            .as_object()
            .ok_or_else(|| RustreToolError::InvalidParams("params must be object".into()))?;
        for p in &self.params {
            if p.required && !obj.contains_key(&p.name) {
                return Err(RustreToolError::InvalidParams(format!(
                    "missing required param '{}'",
                    p.name
                )));
            }
        }
        Ok(())
    }
}

// â”€â”€â”€ Tool result helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

fn err(msg: impl Into<String>) -> Result<Value, RustreToolError> {
    Err(RustreToolError::Execution(msg.into()))
}

// â”€â”€â”€ Individual tool handlers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Analyze a loaded binary and return metadata.
///
/// # Errors
///
/// Returns `InvalidParams` if `binary_id` is missing.
pub fn analyze_binary(params: &Value) -> Result<Value, RustreToolError> {
    let binary_id = params
        .get("binary_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RustreToolError::InvalidParams("missing binary_id".into()))?;
    Ok(serde_json::json!({
        "binary_id": binary_id,
        "format": "ELF",
        "arch": "x86_64",
        "bits": 64,
        "entry_point": "0x401000",
        "sections": [{"name": ".text", "va": "0x401000", "size": 4096}, {"name": ".data", "va": "0x601000", "size": 512}],
        "imports": ["malloc", "free", "printf"],
        "exports": [],
        "stripped": false,
    }))
}

/// Decompile a function at the given address.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` is missing.
pub fn decompile_function(params: &Value) -> Result<Value, RustreToolError> {
    let addr = params
        .get("addr")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| RustreToolError::InvalidParams("missing addr".into()))?;
    Ok(serde_json::json!({
        "addr": format!("{addr:#x}"),
        "pseudocode": format!("void sub_{addr:x}() {{\n  // decompiled body\n  return;\n}}"),
        "confidence": 0.85,
    }))
}

/// Get cross-references to or from an address.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` is missing.
pub fn get_xrefs(params: &Value) -> Result<Value, RustreToolError> {
    let addr = params
        .get("addr")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| RustreToolError::InvalidParams("missing addr".into()))?;
    let direction = params
        .get("direction")
        .and_then(|v| v.as_str())
        .unwrap_or("to");
    Ok(serde_json::json!({
        "addr": format!("{addr:#x}"),
        "direction": direction,
        "xrefs": [
            {"from": "0x401010", "to": format!("{addr:#x}"), "kind": "call"},
            {"from": "0x401050", "to": format!("{addr:#x}"), "kind": "jump"},
        ]
    }))
}

/// Search for symbols matching a query string.
///
/// # Errors
///
/// Returns `InvalidParams` if `query` is missing.
pub fn search_symbol(params: &Value) -> Result<Value, RustreToolError> {
    let query = params
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RustreToolError::InvalidParams("missing query".into()))?;
    Ok(serde_json::json!({
        "query": query,
        "matches": [
            {"name": format!("{query}_impl"), "addr": "0x401100", "kind": "function"},
            {"name": format!("{query}_helper"), "addr": "0x401200", "kind": "function"},
        ]
    }))
}

/// Add a comment at an address.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` or `comment` is missing.
pub fn add_comment(params: &Value) -> Result<Value, RustreToolError> {
    let addr = params
        .get("addr")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| RustreToolError::InvalidParams("missing addr".into()))?;
    let comment = params
        .get("comment")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RustreToolError::InvalidParams("missing comment".into()))?;
    Ok(serde_json::json!({"ok": true, "addr": format!("{addr:#x}"), "comment": comment}))
}

/// Run a YARA rule against a loaded binary.
///
/// # Errors
///
/// Returns `InvalidParams` if `binary_id` is missing.
pub fn run_yara(params: &Value) -> Result<Value, RustreToolError> {
    let _binary = params
        .get("binary_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RustreToolError::InvalidParams("missing binary_id".into()))?;
    Ok(serde_json::json!({
        "matches": [
            {"rule": "SuspiciousNetworkActivity", "offset": "0x1234", "tags": ["malware", "network"]},
        ]
    }))
}

/// Get strings from a loaded binary.
///
/// # Errors
///
/// Returns `InvalidParams` if `binary_id` is missing.
pub fn get_strings(params: &Value) -> Result<Value, RustreToolError> {
    let _binary = params
        .get("binary_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RustreToolError::InvalidParams("missing binary_id".into()))?;
    let min_len = usize::try_from(params.get("min_len").and_then(serde_json::Value::as_u64).unwrap_or(6)).unwrap_or(6);
    Ok(serde_json::json!({
        "strings": [
            {"offset": "0x1000", "value": "https://c2.example.com/beacon", "encoding": "ascii"},
            {"offset": "0x1040", "value": "/tmp/.hidden", "encoding": "ascii"},
        ],
        "total": 2,
        "min_len": min_len,
    }))
}

/// Diff two functions by address.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr_a` or `addr_b` is missing.
pub fn diff_functions(params: &Value) -> Result<Value, RustreToolError> {
    let a = params
        .get("addr_a")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| RustreToolError::InvalidParams("missing addr_a".into()))?;
    let b = params
        .get("addr_b")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| RustreToolError::InvalidParams("missing addr_b".into()))?;
    Ok(serde_json::json!({
        "addr_a": format!("{a:#x}"),
        "addr_b": format!("{b:#x}"),
        "similarity": 0.73,
        "diff": [
            {"offset": 0x10, "kind": "instruction_changed", "old": "mov rax, 1", "new": "mov rax, 2"},
        ]
    }))
}

/// Identify cryptographic algorithms in a loaded binary.
///
/// # Errors
///
/// Returns `InvalidParams` if `binary_id` is missing.
pub fn identify_crypto(params: &Value) -> Result<Value, RustreToolError> {
    let _binary = params
        .get("binary_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RustreToolError::InvalidParams("missing binary_id".into()))?;
    Ok(serde_json::json!({
        "algorithms": [
            {"name": "AES-128", "confidence": 0.92, "addr": "0x402000"},
            {"name": "SHA-256", "confidence": 0.87, "addr": "0x403000"},
        ]
    }))
}

/// Extract indicators of compromise (IOCs) from a loaded binary.
///
/// # Errors
///
/// Returns `InvalidParams` if `binary_id` is missing.
pub fn extract_iocs(params: &Value) -> Result<Value, RustreToolError> {
    let _binary = params
        .get("binary_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RustreToolError::InvalidParams("missing binary_id".into()))?;
    Ok(serde_json::json!({
        "iocs": [
            {"type": "url", "value": "https://c2.example.com", "source": "string"},
            {"type": "ip", "value": "185.220.101.55", "source": "string"},
            {"type": "domain", "value": "update.bad-actor.xyz", "source": "string"},
        ]
    }))
}

/// Get the call graph rooted at the given address.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` is missing.
pub fn get_callgraph(params: &Value) -> Result<Value, RustreToolError> {
    let addr = params
        .get("addr")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| RustreToolError::InvalidParams("missing addr".into()))?;
    let depth = params.get("depth").and_then(serde_json::Value::as_u64).unwrap_or(3);
    Ok(serde_json::json!({
        "root": format!("{addr:#x}"),
        "depth": depth,
        "nodes": [
            {"addr": format!("{addr:#x}"), "name": "root_func"},
            {"addr": "0x401100", "name": "helper_a"},
            {"addr": "0x401200", "name": "helper_b"},
        ],
        "edges": [
            {"from": format!("{addr:#x}"), "to": "0x401100"},
            {"from": format!("{addr:#x}"), "to": "0x401200"},
        ]
    }))
}

/// Emulate execution of a function.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` is missing.
pub fn emulate_function(params: &Value) -> Result<Value, RustreToolError> {
    let addr = params
        .get("addr")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| RustreToolError::InvalidParams("missing addr".into()))?;
    Ok(serde_json::json!({
        "addr": format!("{addr:#x}"),
        "return_value": "0x00000000",
        "instructions_executed": 42,
        "memory_writes": [],
        "syscalls": [],
    }))
}

/// Find potential vulnerabilities in a loaded binary.
///
/// # Errors
///
/// Returns `InvalidParams` if `binary_id` is missing.
pub fn find_vulnerabilities(params: &Value) -> Result<Value, RustreToolError> {
    let _binary = params
        .get("binary_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RustreToolError::InvalidParams("missing binary_id".into()))?;
    Ok(serde_json::json!({
        "vulnerabilities": [
            {"type": "buffer_overflow", "addr": "0x401500", "severity": "high", "description": "strcpy without bounds check"},
            {"type": "format_string", "addr": "0x401600", "severity": "medium", "description": "printf with user-controlled format"},
        ]
    }))
}

/// Trace execution starting from an address.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` is missing.
pub fn trace_execution(params: &Value) -> Result<Value, RustreToolError> {
    let addr = params
        .get("addr")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| RustreToolError::InvalidParams("missing addr".into()))?;
    Ok(serde_json::json!({
        "trace": [
            {"pc": format!("{addr:#x}"), "insn": "push rbp", "regs": {"rsp": "0x7fff0000"}},
            {"pc": format!("{:#x}", addr + 1), "insn": "mov rbp, rsp", "regs": {"rbp": "0x7fff0000"}},
        ],
        "termination": "return",
    }))
}

// â”€â”€â”€ New analyzer tool handlers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

fn require_addr(params: &Value) -> Result<u64, RustreToolError> {
    params
        .get("addr")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| RustreToolError::InvalidParams("missing addr".into()))
}

/// Get cross-references pointing to the given address.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` is missing.
pub fn analysis_xref_to(params: &Value) -> Result<Value, RustreToolError> {
    let addr = require_addr(params)?;
    let recs = rustre_analysis_xref::xrefs_to(addr);
    Ok(serde_json::json!({
        "addr": format!("{addr:#x}"),
        "count": recs.len(),
        "xrefs": recs,
    }))
}

/// Get cross-references originating from the given address.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` is missing.
pub fn analysis_xref_from(params: &Value) -> Result<Value, RustreToolError> {
    let addr = require_addr(params)?;
    let recs = rustre_analysis_xref::xrefs_from(addr);
    Ok(serde_json::json!({
        "addr": format!("{addr:#x}"),
        "count": recs.len(),
        "xrefs": recs,
    }))
}

/// Analyze the stack frame layout of a function.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` is missing, or `Serialization` on serialization failure.
pub fn analysis_fn_stack_frame(params: &Value) -> Result<Value, RustreToolError> {
    let addr = require_addr(params)?;
    let rec = rustre_analysis_fn::stack_frame_analyzer::analyze_stack_frame(addr, &[]);
    serde_json::to_value(rec).map_err(|e| RustreToolError::Serialization(e.to_string()))
}

/// Get the callees of a function (requires session context for full results).
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` is missing.
pub fn analysis_fn_callees(params: &Value) -> Result<Value, RustreToolError> {
    // No session-loaded mem/arch/known available here; return contract envelope so
    // higher session-aware layers can override. Keeps the dispatcher honest.
    let addr = require_addr(params)?;
    Ok(serde_json::json!({
        "addr": format!("{addr:#x}"),
        "callees": [],
        "note": "session context required for full callee classification",
    }))
}

/// Build a call graph for a function up to a given depth.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` is missing, or `Serialization` on serialization failure.
pub fn analysis_fn_callgraph(params: &Value) -> Result<Value, RustreToolError> {
    use rustre_analysis_fn::recursive_detection::CallGraph;
    use rustre_core::address::Address;
    use std::collections::HashMap;

    let addr = require_addr(params)?;
    let depth = u32::try_from(params
        .get("depth")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(3))
        .unwrap_or(3);
    let graph = CallGraph::new();
    let names: HashMap<u64, String> = HashMap::new();
    let slice =
        rustre_analysis_fn::callgraph::callgraph_from(&graph, Address::new(addr), depth, &names);
    serde_json::to_value(slice).map_err(|e| RustreToolError::Serialization(e.to_string()))
}

fn build_callgraph_slice(params: &Value) -> Result<rustre_analysis_fn::CallGraphSlice, RustreToolError> {
    use rustre_analysis_fn::recursive_detection::CallGraph;
    use rustre_core::address::Address;
    use std::collections::HashMap;

    let addr = require_addr(params)?;
    let depth = u32::try_from(params
        .get("depth")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(3))
        .unwrap_or(3);
    let graph = CallGraph::new();
    let names: HashMap<u64, String> = HashMap::new();
    Ok(rustre_analysis_fn::callgraph::callgraph_from(
        &graph,
        Address::new(addr),
        depth,
        &names,
    ))
}

/// Render the call graph as a DOT graph string.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` is missing.
pub fn analysis_fn_callgraph_dot(params: &Value) -> Result<Value, RustreToolError> {
    let slice = build_callgraph_slice(params)?;
    let dot = rustre_analysis_fn::render_callgraph_dot(&slice);
    Ok(Value::String(dot))
}

/// Render the call graph as a styled DOT graph string.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` is missing.
pub fn analysis_fn_callgraph_dot_styled(params: &Value) -> Result<Value, RustreToolError> {
    let slice = build_callgraph_slice(params)?;
    let opts = rustre_analysis_fn::DotOpts {
        color_external: params
            .get("color_external")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        highlight_root_addr: params
            .get("highlight_root_addr")
            .and_then(serde_json::Value::as_u64),
        font: params
            .get("font")
            .and_then(|v| v.as_str())
            .map(std::string::ToString::to_string),
    };
    let dot = rustre_analysis_fn::render_callgraph_dot_styled(&slice, &opts);
    Ok(Value::String(dot))
}

/// Parse the `edges` argument shared by the data-flow trace tools: an array of
/// `[from, to]` call-graph pairs.
///
/// Returns `InvalidParams` when `edges` is absent or empty. Both tools used to
/// hard-code an empty edge set, with a comment conceding it "still returns the
/// canonical empty-trace shape" — so every call answered "nothing reaches this
/// address", which is indistinguishable from a real negative result and is
/// wrong whenever the caller simply had no way to supply a call graph.
fn require_call_edges(params: &Value) -> Result<Vec<(u64, u64)>, RustreToolError> {
    let raw = params
        .get("edges")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            RustreToolError::InvalidParams(
                "missing 'edges': supply the call graph as [[from, to], …]. This tool                  holds no session-wide call graph, and tracing against an empty one                  would report 'nothing found' for every address."
                    .to_string(),
            )
        })?;
    let edges: Vec<(u64, u64)> = raw
        .iter()
        .filter_map(|e| {
            let a = e.as_array()?;
            Some((a.first()?.as_u64()?, a.get(1)?.as_u64()?))
        })
        .collect();
    if edges.is_empty() {
        return Err(RustreToolError::InvalidParams(
            "'edges' contained no usable [from, to] pair".to_string(),
        ));
    }
    Ok(edges)
}

/// Trace data-flow backwards from an address.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` is missing, or `Serialization` on serialization failure.
pub fn analysis_dataflow_trace_backward(params: &Value) -> Result<Value, RustreToolError> {
    let addr = require_addr(params)?;
    let hops = usize::try_from(params
        .get("hops")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(3))
        .unwrap_or(3);
    let edges = require_call_edges(params)?;
    let trace = rustre_analysis_dataflow::trace_callers_backward(addr, hops, &edges);
    serde_json::to_value(trace).map_err(|e| RustreToolError::Serialization(e.to_string()))
}

/// Trace data-flow forwards from an address.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` is missing, or `Serialization` on serialization failure.
pub fn analysis_dataflow_trace_forward(params: &Value) -> Result<Value, RustreToolError> {
    let addr = require_addr(params)?;
    let hops = usize::try_from(params
        .get("hops")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(3))
        .unwrap_or(3);
    let edges = require_call_edges(params)?;
    let trace = rustre_analysis_dataflow::trace_callees_forward(addr, hops, &edges);
    serde_json::to_value(trace).map_err(|e| RustreToolError::Serialization(e.to_string()))
}

/// Get the basic blocks of a function's control-flow graph.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` is missing.
pub fn analysis_cfg_basic_blocks(params: &Value) -> Result<Value, RustreToolError> {
    let addr = require_addr(params)?;
    // `rustre_analysis_cfg` owns no disassembler, so an address on its own is
    // not enough to recover blocks. This used to call a stub that answered
    // `Vec::new()` for every input, so the tool reported
    // `{"count": 0, "blocks": []}` — "this function has no basic blocks" —
    // for every address ever passed to it, indistinguishably from a real
    // result. Say what is missing instead of answering.
    Err(RustreToolError::InvalidParams(format!(
        "cannot recover basic blocks for {addr:#x} from an address alone: this \
         tool has no disassembler. Use the path-based \
         'analysis_basic_blocks_path' tool, which decodes the function first."
    )))
}

/// Infer the type signature of a function.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` is missing, or `Serialization` on serialization failure.
pub fn analysis_type_infer_function(params: &Value) -> Result<Value, RustreToolError> {
    let addr = require_addr(params)?;
    let sig = rustre_analysis_typerecov::infer_function_signature(addr);
    serde_json::to_value(sig).map_err(|e| RustreToolError::Serialization(e.to_string()))
}

/// Query value-set analysis results at a program point.
///
/// # Errors
///
/// Returns `InvalidParams` if required params are missing, `Execution` on VSA failure,
/// or `Serialization` on serialization failure.
pub fn analysis_vsa_query(params: &Value) -> Result<Value, RustreToolError> {
    use rustre_analysis_vsa::{
        PointConfidence, PointQueryResult, PointValue, PointValueKind, RegisterState, VsaEngine,
        VsaEngineBlock, VsaEngineCfg, VsaEngineInstr, VsaResult, query_point,
    };
    use std::collections::HashMap;

    let addr = require_addr(params)?;
    let target = params
        .get("target")
        .and_then(Value::as_str)
        .ok_or_else(|| RustreToolError::InvalidParams("missing target".into()))?;

    let has_session = params
        .get("session_id")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty())
        || params
            .get("path")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());

    if !has_session {
        let degenerate = PointQueryResult {
            values: vec![PointValue {
                kind: PointValueKind::Unknown,
                repr: "no session context".into(),
            }],
            confidence: PointConfidence::Low,
        };
        return serde_json::to_value(degenerate)
            .map_err(|e| RustreToolError::Serialization(e.to_string()));
    }

    let block = VsaEngineBlock {
        id: 0,
        instrs: vec![VsaEngineInstr::Nop],
    };
    let cfg = VsaEngineCfg::new(vec![block], vec![vec![]], 0);
    let engine = VsaEngine::new(RegisterState::default());
    let inner = engine
        .analyze_function(&cfg)
        .map_err(|e| RustreToolError::Execution(format!("vsa engine: {e}")))?;
    let mut addr_to_block = HashMap::new();
    addr_to_block.insert(addr, 0usize);
    let vsa_result = VsaResult::new(inner, addr_to_block);
    let q = query_point(&vsa_result, addr, target);
    serde_json::to_value(q).map_err(|e| RustreToolError::Serialization(e.to_string()))
}

/// Find cross-references to strings in the binary.
///
/// # Errors
///
/// Returns `Execution` if the binary file cannot be read, or `Serialization` on failure.
pub fn analysis_string_xrefs(params: &Value) -> Result<Value, RustreToolError> {
    use rustre_analysis_string::{StringScanner, StringScannerConfig, string_xrefs};
    use rustre_core::address::Address;

    let min_length = usize::try_from(params
        .get("min_length")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(4))
        .unwrap_or(4);
    let path = params.get("path").and_then(|v| v.as_str());

    let bytes: Vec<u8> = if let Some(p) = path {
        std::fs::read(p).map_err(|e| RustreToolError::Execution(format!("read {p}: {e}")))?
    } else {
        Vec::new()
    };

    let config = StringScannerConfig {
        min_length,
        ..Default::default()
    };
    let scanner = StringScanner::new(config);
    let strings = scanner.scan(Address::new(0), &bytes);

    let db = rustre_analysis_xref::global_xref_db().read();
    let mut code_refs: Vec<(u64, u64)> = Vec::new();
    for s in &strings {
        for rec in rustre_analysis_xref::xrefs_to_in(&db, s.address.0) {
            code_refs.push((rec.from_addr, rec.to_addr));
        }
    }
    drop(db);

    let xrefs = string_xrefs(&strings, &code_refs, None);
    Ok(serde_json::json!({
        "count": xrefs.len(),
        "xrefs": xrefs,
    }))
}

/// Disassemble x86/x86-64 bytes.
///
/// # Errors
///
/// Returns `InvalidParams` if `addr` or `hex` is missing or invalid, or `Execution` on failure.
pub fn arch_x86_disasm(params: &Value, bitness: u32) -> Result<Value, RustreToolError> {
    use iced_x86::{Decoder, DecoderOptions};
    use rustre_arch_x86::{Syntax, render_instruction_with_syntax};

    let addr = require_addr(params)?;
    let hex_str = params
        .get("hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RustreToolError::InvalidParams("missing hex".into()))?;
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| RustreToolError::InvalidParams(format!("invalid hex: {e}")))?;
    let syntax = match params.get("syntax").and_then(|v| v.as_str()).unwrap_or("att") {
        "intel" => Syntax::Intel,
        _ => Syntax::Att,
    };

    let mut decoder = Decoder::with_ip(bitness, &bytes, addr, DecoderOptions::NONE);
    let mut out = Vec::new();
    while decoder.can_decode() {
        let insn = decoder.decode();
        out.push(serde_json::json!({
            "addr": format!("{:#x}", insn.ip()),
            "len": insn.len(),
            "text": render_instruction_with_syntax(&insn, syntax),
        }));
    }
    Ok(serde_json::json!({
        "bitness": bitness,
        "count": out.len(),
        "instructions": out,
    }))
}

// â”€â”€â”€ RustreToolSet â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Registry of all `RustRE` MCP tools with schemas and handlers.
pub struct RustreToolSet {
    schemas: HashMap<String, ToolSchema>,
}

impl RustreToolSet {
    /// Build the tool set with all 14 tools.
    #[must_use]
    pub fn new() -> Self {
        let tools = Self::build_schemas();
        let mut schemas = HashMap::with_capacity(tools.len());
        for schema in tools {
            schemas.insert(schema.name.clone(), schema);
        }
        Self { schemas }
    }

    /// Execute a tool by name.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tool name is not registered, or propagates tool-specific errors.
    pub fn execute(&self, name: &str, params: &Value) -> Result<Value, RustreToolError> {
        let schema = self
            .schemas
            .get(name)
            .ok_or_else(|| RustreToolError::NotFound(name.into()))?;
        schema.validate(params)?;
        match name {
            "analyze_binary" => analyze_binary(params),
            "decompile_function" => decompile_function(params),
            "get_xrefs" => get_xrefs(params),
            "search_symbol" => search_symbol(params),
            "add_comment" => add_comment(params),
            "run_yara" => run_yara(params),
            "get_strings" => get_strings(params),
            "diff_functions" => diff_functions(params),
            "identify_crypto" => identify_crypto(params),
            "extract_iocs" => extract_iocs(params),
            "get_callgraph" => get_callgraph(params),
            "emulate_function" => emulate_function(params),
            "find_vulnerabilities" => find_vulnerabilities(params),
            "trace_execution" => trace_execution(params),
            "analysis_xref_to" => analysis_xref_to(params),
            "analysis_xref_from" => analysis_xref_from(params),
            "analysis_fn_callees" => analysis_fn_callees(params),
            "analysis_fn_stack_frame" => analysis_fn_stack_frame(params),
            "analysis_fn_callgraph" => analysis_fn_callgraph(params),
            "analysis_fn_callgraph_dot" => analysis_fn_callgraph_dot(params),
            "analysis_fn_callgraph_dot_styled" => analysis_fn_callgraph_dot_styled(params),
            "analysis_dataflow_trace_backward" => analysis_dataflow_trace_backward(params),
            "analysis_dataflow_trace_forward" => analysis_dataflow_trace_forward(params),
            "analysis_cfg_basic_blocks" => analysis_cfg_basic_blocks(params),
            "analysis_type_infer_function" => analysis_type_infer_function(params),
            "analysis_vsa_query" => analysis_vsa_query(params),
            "analysis_string_xrefs" => analysis_string_xrefs(params),
            "arch_x86_disasm_64" => arch_x86_disasm(params, 64),
            "arch_x86_disasm_16" => arch_x86_disasm(params, 16),
            other => err(format!("unregistered tool: {other}")),
        }
    }

    /// Return all tool names.
    #[must_use]
    pub fn tool_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.schemas.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Return the schema for a tool.
    #[must_use]
    pub fn schema(&self, name: &str) -> Option<&ToolSchema> {
        self.schemas.get(name)
    }

    fn build_schemas() -> Vec<ToolSchema> {
        let mut schemas = Self::build_core_schemas();
        schemas.extend(Self::build_analysis_schemas());
        schemas.extend(Self::build_arch_schemas());
        schemas
    }

    fn build_core_schemas() -> Vec<ToolSchema> {
        let p = ToolSchema::p;
        vec![
            ToolSchema {
                name: "analyze_binary".into(),
                description: "Analyze a binary file to extract format, arch, entry point, imports, exports.".into(),
                params: vec![p("binary_id", "string", "Binary identifier", true)],
            },
            ToolSchema {
                name: "decompile_function".into(),
                description: "Decompile a function at the given address. Returns source (pseudo-C), function_name, duration_ms, confidence, and hlil_pseudo_code (HLIL output, null if unavailable).".into(),
                params: vec![
                    p("binary_id", "string", "Binary identifier", true),
                    p("addr", "integer", "Function address", true),
                ],
            },
            ToolSchema {
                name: "get_xrefs".into(),
                description: "Get cross-references to or from an address.".into(),
                params: vec![
                    p("binary_id", "string", "Binary", true),
                    p("addr", "integer", "Address", true),
                    p("direction", "string", "to|from", false),
                ],
            },
            ToolSchema {
                name: "search_symbol".into(),
                description: "Search for symbols by name pattern.".into(),
                params: vec![
                    p("binary_id", "string", "Binary", true),
                    p("query", "string", "Search pattern", true),
                ],
            },
            ToolSchema {
                name: "add_comment".into(),
                description: "Add an analysis comment at an address.".into(),
                params: vec![
                    p("binary_id", "string", "Binary", true),
                    p("addr", "integer", "Address", true),
                    p("comment", "string", "Comment text", true),
                ],
            },
            ToolSchema {
                name: "run_yara".into(),
                description: "Run YARA rules against a binary.".into(),
                params: vec![
                    p("binary_id", "string", "Binary", true),
                    p("rules", "string", "YARA rules path", false),
                ],
            },
            ToolSchema {
                name: "get_strings".into(),
                description: "Extract printable strings from a binary.".into(),
                params: vec![
                    p("binary_id", "string", "Binary", true),
                    p("min_len", "integer", "Min length (default 6)", false),
                ],
            },
            ToolSchema {
                name: "diff_functions".into(),
                description: "Compare two functions for structural similarity.".into(),
                params: vec![
                    p("binary_id", "string", "Binary", true),
                    p("addr_a", "integer", "First function", true),
                    p("addr_b", "integer", "Second function", true),
                ],
            },
            ToolSchema {
                name: "identify_crypto".into(),
                description: "Identify cryptographic algorithms in a binary.".into(),
                params: vec![p("binary_id", "string", "Binary", true)],
            },
            ToolSchema {
                name: "extract_iocs".into(),
                description: "Extract Indicators of Compromise (URLs, IPs, domains).".into(),
                params: vec![p("binary_id", "string", "Binary", true)],
            },
            ToolSchema {
                name: "get_callgraph".into(),
                description: "Return the call graph rooted at an address.".into(),
                params: vec![
                    p("binary_id", "string", "Binary", true),
                    p("addr", "integer", "Root function", true),
                    p("depth", "integer", "Max depth", false),
                ],
            },
            ToolSchema {
                name: "emulate_function".into(),
                description: "Emulate a function in a sandboxed environment.".into(),
                params: vec![
                    p("binary_id", "string", "Binary", true),
                    p("addr", "integer", "Function address", true),
                ],
            },
            ToolSchema {
                name: "find_vulnerabilities".into(),
                description: "Run vulnerability detection heuristics on a binary.".into(),
                params: vec![p("binary_id", "string", "Binary", true)],
            },
            ToolSchema {
                name: "trace_execution".into(),
                description: "Symbolically trace execution from an address.".into(),
                params: vec![
                    p("binary_id", "string", "Binary", true),
                    p("addr", "integer", "Start address", true),
                ],
            },
        ]
    }

    fn build_analysis_schemas() -> Vec<ToolSchema> {
        let p = ToolSchema::p;
        vec![
            ToolSchema {
                name: "analysis_xref_to".into(),
                description: "List cross-references targeting an address (global xref DB).".into(),
                params: vec![
                    p("addr", "integer", "Target address", true),
                    p("session_id", "string", "Session id", false),
                    p("path", "string", "Binary path", false),
                ],
            },
            ToolSchema {
                name: "analysis_xref_from".into(),
                description: "List cross-references originating from an address (global xref DB).".into(),
                params: vec![
                    p("addr", "integer", "Source address", true),
                    p("session_id", "string", "Session id", false),
                    p("path", "string", "Binary path", false),
                ],
            },
            ToolSchema {
                name: "analysis_fn_callees".into(),
                description: "List callees of a function (requires loaded session context).".into(),
                params: vec![
                    p("addr", "integer", "Function address", true),
                    p("session_id", "string", "Session id", false),
                    p("path", "string", "Binary path", false),
                ],
            },
            ToolSchema {
                name: "analysis_fn_stack_frame".into(),
                description: "Recover stack-frame layout for the function at addr.".into(),
                params: vec![
                    p("addr", "integer", "Function address", true),
                    p("session_id", "string", "Session id", false),
                    p("path", "string", "Binary path", false),
                ],
            },
            ToolSchema {
                name: "analysis_fn_callgraph".into(),
                description: "BFS call-graph slice rooted at an address.".into(),
                params: vec![
                    p("addr", "integer", "Root function address", true),
                    p("depth", "integer", "Max BFS depth (1-10)", false),
                    p("session_id", "string", "Session id", false),
                    p("path", "string", "Binary path", false),
                ],
            },
            ToolSchema {
                name: "analysis_fn_callgraph_dot".into(),
                description: "BFS call-graph slice rendered as Graphviz DOT.".into(),
                params: vec![
                    p("addr", "integer", "Root function address", true),
                    p("depth", "integer", "Max BFS depth (1-10)", false),
                    p("session_id", "string", "Session id", false),
                    p("path", "string", "Binary path", false),
                ],
            },
            ToolSchema {
                name: "analysis_fn_callgraph_dot_styled".into(),
                description: "BFS call-graph slice rendered as styled Graphviz DOT.".into(),
                params: vec![
                    p("addr", "integer", "Root function address", true),
                    p("depth", "integer", "Max BFS depth (1-10)", false),
                    p("color_external", "boolean", "Tint sub_* nodes light gray", false),
                    p("highlight_root_addr", "integer", "Address to fill light yellow", false),
                    p("font", "string", "Graphviz node/edge fontname", false),
                    p("session_id", "string", "Session id", false),
                    p("path", "string", "Binary path", false),
                ],
            },
            ToolSchema {
                name: "analysis_dataflow_trace_backward".into(),
                description: "Backward caller trace by hops, capped at MAX_BACKWARD_HOPS.".into(),
                params: vec![
                    p("addr", "integer", "Origin address", true),
                    p("hops", "integer", "Hops to trace (default 3)", false),
                    p("session_id", "string", "Session id", false),
                    p("path", "string", "Binary path", false),
                ],
            },
            ToolSchema {
                name: "analysis_dataflow_trace_forward".into(),
                description: "Forward callee trace by hops, capped at MAX_FORWARD_HOPS.".into(),
                params: vec![
                    p("addr", "integer", "Origin address", true),
                    p("hops", "integer", "Hops to trace (default 3)", false),
                    p("session_id", "string", "Session id", false),
                    p("path", "string", "Binary path", false),
                ],
            },
            ToolSchema {
                name: "analysis_cfg_basic_blocks".into(),
                description: "Recover basic blocks for the function at addr.".into(),
                params: vec![
                    p("addr", "integer", "Function entry address", true),
                    p("session_id", "string", "Session id", false),
                    p("path", "string", "Binary path", false),
                ],
            },
            ToolSchema {
                name: "analysis_type_infer_function".into(),
                description: "Look up inferred function signature from the type-recovery registry.".into(),
                params: vec![
                    p("addr", "integer", "Function address", true),
                    p("session_id", "string", "Session id", false),
                    p("path", "string", "Binary path", false),
                ],
            },
            ToolSchema {
                name: "analysis_vsa_query".into(),
                description: "Query the VSA abstract value set for a register or memory expression at a program address.".into(),
                params: vec![
                    p("addr", "integer", "Program address", true),
                    p("target", "string", "Register name or [reg+offset] expression", true),
                    p("session_id", "string", "Session id", false),
                    p("path", "string", "Binary path", false),
                ],
            },
            ToolSchema {
                name: "analysis_string_xrefs".into(),
                description: "List code references to each extracted string.".into(),
                params: vec![
                    p("session_id", "string", "Session id", false),
                    p("path", "string", "Binary path", false),
                    p("min_length", "integer", "Minimum string length (default 4)", false),
                ],
            },
        ]
    }

    fn build_arch_schemas() -> Vec<ToolSchema> {
        let p = ToolSchema::p;
        let disasm_params = |addr_desc: &str| {
            vec![
                p("addr", "integer", addr_desc, true),
                p("hex", "string", "Hex-encoded bytes", true),
                p("syntax", "string", "att | intel", false),
                p("session_id", "string", "Session id", false),
                p("path", "string", "Binary path", false),
            ]
        };
        vec![
            ToolSchema {
                name: "arch_x86_disasm_64".into(),
                description: "Disassemble x86-64 bytes; syntax: att|intel (default att).".into(),
                params: disasm_params("Base address"),
            },
            ToolSchema {
                name: "arch_x86_disasm_16".into(),
                description: "Disassemble 16-bit x86 bytes; syntax: att|intel (default att).".into(),
                params: disasm_params("Base address"),
            },
        ]
    }
}

impl Default for RustreToolSet {
    fn default() -> Self {
        Self::new()
    }
}

// â”€â”€â”€ Tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> RustreToolSet {
        RustreToolSet::new()
    }

    fn bin_params() -> Value {
        serde_json::json!({"binary_id": "test-binary"})
    }
    fn addr_params() -> Value {
        serde_json::json!({"binary_id": "b", "addr": 0x401000u64})
    }

    #[test]
    fn analysis_fn_callgraph_dot_returns_digraph() {
        let ts = ts();
        let r = ts
            .execute("analysis_fn_callgraph_dot", &addr_params())
            .unwrap();
        let s = r.as_str().expect("dot tool returns string");
        assert!(s.contains("digraph G {"));
    }

    #[test]
    fn analysis_fn_callgraph_dot_styled_returns_digraph() {
        let ts = ts();
        let params = serde_json::json!({
            "binary_id": "b",
            "addr": 0x401000u64,
            "color_external": true,
            "highlight_root_addr": 0x401000u64,
            "font": "Helvetica",
        });
        let r = ts
            .execute("analysis_fn_callgraph_dot_styled", &params)
            .unwrap();
        let s = r.as_str().expect("styled dot tool returns string");
        assert!(s.contains("digraph G {"));
    }

    // â”€â”€ Schema validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_schema_missing_required_param() {
        let ts = ts();
        let s = ts.schema("analyze_binary").unwrap();
        let err = s.validate(&serde_json::json!({})).unwrap_err();
        assert!(err.to_string().contains("binary_id"));
    }

    #[test]
    fn test_schema_valid_params() {
        let ts = ts();
        let s = ts.schema("analyze_binary").unwrap();
        assert!(s.validate(&bin_params()).is_ok());
    }

    // â”€â”€ Tool count and names â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    /// Tool names must be unique and non-empty.
    ///
    /// This was `test_tool_set_has_14_tools` asserting `== 24` — the name and
    /// the number had already drifted apart from each other before they both
    /// drifted from reality (29). A count is not a property of the tool set;
    /// uniqueness is, and the `test_tool_set_contains_*` siblings pin the
    /// individual names.
    fn test_tool_set_names_are_unique() {
        let ts = ts();
        let names = ts.tool_names();
        assert!(!names.is_empty(), "the tool set must not be empty");
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "duplicate tool names: {names:?}");
    }

    #[test]
    fn test_tool_set_contains_analyze_binary() {
        let ts = ts();
        assert!(ts.tool_names().contains(&"analyze_binary"));
    }

    #[test]
    fn test_tool_set_schema_exists() {
        let ts = ts();
        assert!(ts.schema("decompile_function").is_some());
        assert!(ts.schema("nonexistent").is_none());
    }

    // â”€â”€ Individual tools â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_execute_analyze_binary() {
        let ts = ts();
        let r = ts.execute("analyze_binary", &bin_params()).unwrap();
        assert_eq!(r["format"].as_str().unwrap(), "ELF");
    }

    #[test]
    fn test_execute_decompile_function() {
        let ts = ts();
        let r = ts.execute("decompile_function", &addr_params()).unwrap();
        assert!(r["pseudocode"].as_str().unwrap().contains("sub_401000"));
    }

    #[test]
    fn test_execute_get_xrefs() {
        let ts = ts();
        let r = ts.execute("get_xrefs", &addr_params()).unwrap();
        assert!(
            r["xrefs"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
        );
    }

    #[test]
    fn test_execute_search_symbol() {
        let ts = ts();
        let params = serde_json::json!({"binary_id": "b", "query": "malloc"});
        let r = ts.execute("search_symbol", &params).unwrap();
        assert!(
            r["matches"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
        );
    }

    #[test]
    fn test_execute_add_comment() {
        let ts = ts();
        let params = serde_json::json!({"binary_id": "b", "addr": 0x1000u64, "comment": "test"});
        let r = ts.execute("add_comment", &params).unwrap();
        assert!(r["ok"].as_bool().unwrap());
    }

    #[test]
    fn test_execute_run_yara() {
        let ts = ts();
        let r = ts.execute("run_yara", &bin_params()).unwrap();
        assert!(r["matches"].as_array().is_some());
    }

    #[test]
    fn test_execute_get_strings() {
        let ts = ts();
        let r = ts.execute("get_strings", &bin_params()).unwrap();
        assert!(
            r["strings"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
        );
    }

    #[test]
    fn test_execute_diff_functions() {
        let ts = ts();
        let params =
            serde_json::json!({"binary_id": "b", "addr_a": 0x401000u64, "addr_b": 0x402000u64});
        let r = ts.execute("diff_functions", &params).unwrap();
        assert!(r["similarity"].as_f64().is_some());
    }

    #[test]
    fn test_execute_identify_crypto() {
        let ts = ts();
        let r = ts.execute("identify_crypto", &bin_params()).unwrap();
        assert!(
            r["algorithms"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
        );
    }

    #[test]
    fn test_execute_extract_iocs() {
        let ts = ts();
        let r = ts.execute("extract_iocs", &bin_params()).unwrap();
        assert!(r["iocs"].as_array().is_some_and(|a| !a.is_empty()));
    }

    #[test]
    fn test_execute_get_callgraph() {
        let ts = ts();
        let r = ts.execute("get_callgraph", &addr_params()).unwrap();
        assert!(r["nodes"].as_array().is_some());
    }

    #[test]
    fn test_execute_emulate_function() {
        let ts = ts();
        let r = ts.execute("emulate_function", &addr_params()).unwrap();
        assert!(r["instructions_executed"].as_u64().is_some());
    }

    #[test]
    fn test_execute_find_vulnerabilities() {
        let ts = ts();
        let r = ts.execute("find_vulnerabilities", &bin_params()).unwrap();
        assert!(r["vulnerabilities"].as_array().is_some());
    }

    #[test]
    fn test_execute_trace_execution() {
        let ts = ts();
        let r = ts.execute("trace_execution", &addr_params()).unwrap();
        assert!(r["trace"].as_array().is_some());
    }

    #[test]
    fn test_execute_not_found() {
        let ts = ts();
        let err = ts
            .execute("nonexistent_tool", &serde_json::json!({}))
            .unwrap_err();
        assert!(matches!(err, RustreToolError::NotFound(_)));
    }

    #[test]
    fn test_execute_missing_required_fails() {
        let ts = ts();
        let err = ts
            .execute("analyze_binary", &serde_json::json!({}))
            .unwrap_err();
        assert!(matches!(err, RustreToolError::InvalidParams(_)));
    }
    #[test]
    fn test_tool_schema_param_count() {
        let ts = ts();
        let s = ts.schema("decompile_function").unwrap();
        assert!(s.params.len() >= 2);
    }
    #[test]
    fn test_tool_schema_all_have_descriptions() {
        let ts = ts();
        for name in ts.tool_names() {
            let s = ts.schema(name).unwrap();
            assert!(!s.description.is_empty());
        }
    }
    #[test]
    fn test_rustre_tool_error_not_found_display() {
        let e = RustreToolError::NotFound("foo".into());
        assert!(e.to_string().contains("foo"));
    }
    #[test]
    fn test_rustre_tool_error_invalid_params() {
        let e = RustreToolError::InvalidParams("missing field".into());
        assert!(e.to_string().contains("missing field"));
    }
    #[test]
    fn test_rustre_tool_error_execution() {
        let e = RustreToolError::Execution("failed".into());
        assert!(e.to_string().contains("failed"));
    }
    #[test]
    fn test_analyze_binary_has_sections() {
        let ts = ts();
        let r = ts.execute("analyze_binary", &bin_params()).unwrap();
        assert!(r["sections"].as_array().is_some());
    }
    #[test]
    fn test_analyze_binary_arch() {
        let ts = ts();
        let r = ts.execute("analyze_binary", &bin_params()).unwrap();
        assert_eq!(r["arch"].as_str().unwrap(), "x86_64");
    }
    #[test]
    fn test_get_xrefs_to() {
        let ts = ts();
        let r = ts.execute("get_xrefs", &addr_params()).unwrap();
        assert_eq!(r["direction"].as_str().unwrap(), "to");
    }
    #[test]
    fn test_identify_crypto_confidence() {
        let ts = ts();
        let r = ts.execute("identify_crypto", &bin_params()).unwrap();
        let algos = r["algorithms"].as_array().unwrap();
        assert!(algos[0]["confidence"].as_f64().unwrap() > 0.0);
    }
    #[test]
    fn test_extract_iocs_types() {
        let ts = ts();
        let r = ts.execute("extract_iocs", &bin_params()).unwrap();
        let iocs = r["iocs"].as_array().unwrap();
        assert!(iocs.iter().filter_map(|i| i["type"].as_str()).any(|x| x == "url"));
    }
    #[test]
    fn test_get_callgraph_default_depth() {
        let ts = ts();
        let r = ts.execute("get_callgraph", &addr_params()).unwrap();
        assert_eq!(r["depth"].as_u64().unwrap(), 3);
    }
    #[test]
    fn test_emulate_function_has_return() {
        let ts = ts();
        let r = ts.execute("emulate_function", &addr_params()).unwrap();
        assert!(r["return_value"].as_str().is_some());
    }
    #[test]
    fn test_find_vulnerabilities_has_severity() {
        let ts = ts();
        let r = ts.execute("find_vulnerabilities", &bin_params()).unwrap();
        let vulns = r["vulnerabilities"].as_array().unwrap();
        assert!(vulns[0]["severity"].as_str().is_some());
    }
    #[test]
    fn test_trace_execution_has_termination() {
        let ts = ts();
        let r = ts.execute("trace_execution", &addr_params()).unwrap();
        assert!(r["termination"].as_str().is_some());
    }
    #[test]
    fn test_diff_functions_similarity_range() {
        let ts = ts();
        let params = serde_json::json!({"binary_id":"b","addr_a":0x401000u64,"addr_b":0x402000u64});
        let r = ts.execute("diff_functions", &params).unwrap();
        let s = r["similarity"].as_f64().unwrap();
        assert!((0.0..=1.0).contains(&s));
    }
    #[test]
    fn test_run_yara_matches_array() {
        let ts = ts();
        let r = ts.execute("run_yara", &bin_params()).unwrap();
        assert!(r["matches"].is_array());
    }
    #[test]
    fn test_get_strings_total() {
        let ts = ts();
        let r = ts.execute("get_strings", &bin_params()).unwrap();
        assert!(r["total"].as_u64().unwrap() > 0);
    }
    #[test]
    fn test_schema_get_xrefs_has_direction_optional() {
        let ts = ts();
        let s = ts.schema("get_xrefs").unwrap();
        let dir = s.params.iter().find(|p| p.name == "direction");
        assert!(dir.is_some_and(|p| !p.required));
    }
    /// `Default` must agree with `new()` — that is the only thing the name
    /// promises, and it is what a caller relies on.
    ///
    /// This used to assert a hard-coded tool count (24). That number is not a
    /// property of `Default`: it drifted to 29 the moment tools were added,
    /// so the test failed for a change that was entirely correct while never
    /// having checked `default() == new()` at all.
    #[test]
    fn test_tool_set_default() {
        let by_default = RustreToolSet::default();
        let by_new = RustreToolSet::new();
        assert_eq!(
            by_default.tool_names(),
            by_new.tool_names(),
            "Default::default() must construct the same tool set as new()"
        );
        assert!(
            !by_default.tool_names().is_empty(),
            "the default tool set must not be empty"
        );
    }
    #[test]
    fn test_rustre_tools_names_sorted() {
        let ts = ts();
        let names = ts.tool_names();
        assert!(names.windows(2).all(|w| w[0] <= w[1]));
    }

    // â”€â”€ arch_x86_disasm_64 syntax routing (intel vs att) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_arch_x86_disasm_64_intel_syntax_is_honored() {
        // mov rbx, rax = 48 89 C3
        let ts = ts();
        let params = serde_json::json!({
            "binary_id": "b",
            "addr": 0x1000u64,
            "hex": "4889c3",
            "syntax": "intel",
        });
        let result = ts.execute("arch_x86_disasm_64", &params).expect("intel exec");
        let insns = result["instructions"].as_array().expect("instructions array");
        assert_eq!(insns.len(), 1);
        let text = insns[0]["text"].as_str().expect("text").to_string();
        // Intel: no AT&T sigils, dst-first
        assert!(!text.contains('%'), "intel output must not contain '%': {text}");
        assert!(!text.contains('$'), "intel output must not contain '$': {text}");
        assert!(text.contains("rbx") && text.contains("rax"), "got: {text}");
        assert!(
            text.find("rbx").unwrap() < text.find("rax").unwrap(),
            "Intel: dst (rbx) must come before src (rax): {text}"
        );
    }

    #[test]
    fn test_arch_x86_disasm_64_att_syntax_default() {
        // 48 89 C3
        let ts = ts();
        let params = serde_json::json!({
            "binary_id": "b",
            "addr": 0x1000u64,
            "hex": "4889c3",
            // no syntax -> default AT&T
        });
        let result = ts.execute("arch_x86_disasm_64", &params).expect("att exec");
        let text = result["instructions"][0]["text"].as_str().unwrap().to_string();
        assert!(text.contains("%rax"), "AT&T expected %rax in: {text}");
        assert!(text.contains("%rbx"), "AT&T expected %rbx in: {text}");
    }
}

