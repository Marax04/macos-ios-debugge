//! MCP wrappers for the rustre-analysis crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes};
use crate::wire_tools::{build_xref_index, parse_xref_kind_str_axr};

pub struct AnalysisDataflowComputeLivenessTool;

pub struct AnalysisDataflowComputeReachingDefsTool;

pub struct AnalysisXrefCallGraphTool;

pub struct AnalysisXrefGetXrefsToTool;

pub struct AnalysisXrefGetXrefsFromTool;

pub struct AnalysisXrefCallGraphRootFunctionsTool;

pub struct AnalysisXrefStringRefCountsTool;

pub struct AnalysisFnDetectExtraTool;

pub struct AnalysisVsaResolveJumpTableTool;

pub struct AnalysisVsaResolveIndirectCallsTool;

pub struct AnalysisVsaDetectBufferOverflowsTool;

pub struct AnalysisTypeListBuiltinTypesTool;

pub struct AnalysisTypeLookupBuiltinTypeTool;

pub struct AnalysisTypeWinapiLookupTool;

pub struct AnalysisXrefGlobalToTool;

pub struct AnalysisXrefGlobalFromTool;

pub struct AnalysisResultZeroTotalItemsTool;

pub struct AnalysisScanCallTargetsTool;

pub struct AnalysisStringDetectXorKeyWire2Tool;

pub struct AnalysisStringShannonEntropyWire2Tool;

pub struct AnalysisXrefKindIsCodeTool;
impl AnalysisXrefKindIsCodeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_kind_is_code".to_string(),
            description: "Whether the named XrefKind represents a code-flow transfer.".to_string(),
            input_schema: json!({"type":"object","required":["kind"],"properties":{"kind":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefKindIsCodeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("kind").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let k = parse_xref_kind_str_axr(s).ok_or_else(|| McpError::InvalidParams("unknown kind".into()))?;
        Ok(ToolResult::text(json!({"kind": s, "is_code": k.is_code()}).to_string()))
    }
}

pub struct AnalysisXrefKindIsDataTool;
impl AnalysisXrefKindIsDataTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_kind_is_data".to_string(),
            description: "Whether the named XrefKind represents a data access.".to_string(),
            input_schema: json!({"type":"object","required":["kind"],"properties":{"kind":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefKindIsDataTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("kind").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let k = parse_xref_kind_str_axr(s).ok_or_else(|| McpError::InvalidParams("unknown kind".into()))?;
        Ok(ToolResult::text(json!({"kind": s, "is_data": k.is_data()}).to_string()))
    }
}

pub struct AnalysisXrefKindIsImportTool;
impl AnalysisXrefKindIsImportTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_kind_is_import".to_string(),
            description: "Whether the named XrefKind is an import reference.".to_string(),
            input_schema: json!({"type":"object","required":["kind"],"properties":{"kind":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefKindIsImportTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("kind").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let k = parse_xref_kind_str_axr(s).ok_or_else(|| McpError::InvalidParams("unknown kind".into()))?;
        Ok(ToolResult::text(json!({"kind": s, "is_import": k.is_import()}).to_string()))
    }
}

pub struct AnalysisXrefKindAllTool;
impl AnalysisXrefKindAllTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_kind_all".to_string(),
            description: "List all XrefKind variants in canonical order.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefKindAllTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let names: Vec<String> = rustre_analysis_xref::XrefKind::all()
            .iter().map(|k| k.to_string()).collect();
        Ok(ToolResult::text(json!({"count": names.len(), "kinds": names}).to_string()))
    }
}

pub struct AnalysisXrefParseKindTool;
impl AnalysisXrefParseKindTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_parse_kind".to_string(),
            description: "Parse an XrefKind string and echo classification flags.".to_string(),
            input_schema: json!({"type":"object","required":["kind"],"properties":{"kind":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefParseKindTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("kind").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        match parse_xref_kind_str_axr(s) {
            Some(k) => Ok(ToolResult::text(json!({
                "valid": true,
                "kind": k.to_string(),
                "is_code": k.is_code(),
                "is_data": k.is_data(),
                "is_import": k.is_import(),
            }).to_string())),
            None => Ok(ToolResult::text(json!({"valid": false, "kind": s}).to_string())),
        }
    }
}

pub struct AnalysisXrefIndexFromPathV2Tool;
impl AnalysisXrefIndexFromPathV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_index_from_path_v2".to_string(),
            description: "Load a PE from disk, build an XrefIndex, and return its total xref count.".to_string(),
            input_schema: json!({"type":"object","required":["path"],"properties":{"path":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefIndexFromPathV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args.get("path").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        match rustre_analysis_xref::xref_index_from_path(std::path::Path::new(path)) {
            Ok(idx) => Ok(ToolResult::text(json!({"ok": true, "total": idx.total()}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"ok": false, "error": e.to_string()}).to_string())),
        }
    }
}

pub struct AnalysisXrefIndexFromBytesV2Tool;
impl AnalysisXrefIndexFromBytesV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_index_from_bytes_v2".to_string(),
            description: "Build an XrefIndex from a hex byte buffer (PE) and return its total xref count.".to_string(),
            input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefIndexFromBytesV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?;
        let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        // panic su lunghezza dispari prima di questa conversione.
        let bytes = crate::hex_decode(&clean)?;
        let idx = rustre_analysis_xref::xref_index_from_bytes(&bytes);
        Ok(ToolResult::text(json!({"total": idx.total(), "input_bytes": bytes.len()}).to_string()))
    }
}

pub struct AnalysisXrefGlobalDbTotalTool;
impl AnalysisXrefGlobalDbTotalTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_global_db_total".to_string(),
            description: "Return total number of xref records in the crate-global XrefDatabase.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefGlobalDbTotalTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let db = rustre_analysis_xref::global_xref_db().read();
        Ok(ToolResult::text(json!({
            "total": db.total_count(),
            "is_empty": db.is_empty(),
        }).to_string()))
    }
}

pub struct AnalysisXrefIndexTotalTool;
impl AnalysisXrefIndexTotalTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_index_total".to_string(),
            description: "Total xref record count from BinaryXrefIndex built over code bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"base":{"type":"integer"},"arch":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefIndexTotalTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let idx = build_xref_index(&args)?;
        Ok(ToolResult::text(json!({"total": idx.total(), "is_empty": idx.is_empty()}).to_string()))
    }
}

pub struct AnalysisXrefIndexCountKindTool;
impl AnalysisXrefIndexCountKindTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_index_count_kind".to_string(),
            description: "Count xrefs of a given SimpleXrefKind in a BinaryXrefIndex.".to_string(),
            input_schema: json!({"type":"object","required":["kind"],"properties":{"kind":{"type":"string"},"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"base":{"type":"integer"},"arch":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefIndexCountKindTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let k = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let kind = match k {
            "Call" => rustre_analysis_xref::SimpleXrefKind::Call,
            "Jump" => rustre_analysis_xref::SimpleXrefKind::Jump,
            "DataRead" => rustre_analysis_xref::SimpleXrefKind::DataRead,
            "DataWrite" => rustre_analysis_xref::SimpleXrefKind::DataWrite,
            "DataAddr" => rustre_analysis_xref::SimpleXrefKind::DataAddr,
            other => return Err(McpError::InvalidParams(format!("unknown kind: {other}"))),
        };
        let idx = build_xref_index(&args)?;
        Ok(ToolResult::text(json!({"kind": k, "count": idx.count_kind(kind)}).to_string()))
    }
}

pub struct AnalysisXrefIndexHotCallTargetsTool;
impl AnalysisXrefIndexHotCallTargetsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_index_hot_call_targets".to_string(),
            description: "Top-N most-called targets in a BinaryXrefIndex.".to_string(),
            input_schema: json!({"type":"object","properties":{"top_n":{"type":"integer"},"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"base":{"type":"integer"},"arch":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefIndexHotCallTargetsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("top_n").and_then(Value::as_u64).unwrap_or(10) as usize;
        let idx = build_xref_index(&args)?;
        let top = idx.hot_call_targets(n);
        Ok(ToolResult::text(json!({"top": top.iter().map(|(a,c)| json!({"addr":a,"count":c})).collect::<Vec<_>>(), "count": top.len()}).to_string()))
    }
}

pub struct AnalysisXrefIndexCallersOfTool;
impl AnalysisXrefIndexCallersOfTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_index_callers_of".to_string(),
            description: "Callers (Call xref sources) for an address in BinaryXrefIndex.".to_string(),
            input_schema: json!({"type":"object","required":["addr"],"properties":{"addr":{"type":"integer"},"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"base":{"type":"integer"},"arch":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefIndexCallersOfTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let idx = build_xref_index(&args)?;
        let c = idx.callers_of(addr);
        Ok(ToolResult::text(json!({"callers": c, "count": c.len()}).to_string()))
    }
}

pub struct AnalysisXrefIndexCalleesOfTool;
impl AnalysisXrefIndexCalleesOfTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_index_callees_of".to_string(),
            description: "Callees (Call xref targets) originating at an address in BinaryXrefIndex.".to_string(),
            input_schema: json!({"type":"object","required":["addr"],"properties":{"addr":{"type":"integer"},"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"base":{"type":"integer"},"arch":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefIndexCalleesOfTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let idx = build_xref_index(&args)?;
        let c = idx.callees_of(addr);
        Ok(ToolResult::text(json!({"callees": c, "count": c.len()}).to_string()))
    }
}

pub struct AnalysisXrefIndexDataRefsToTool;
impl AnalysisXrefIndexDataRefsToTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_index_data_refs_to".to_string(),
            description: "Data reads/writes/address-of xref sources targeting an address.".to_string(),
            input_schema: json!({"type":"object","required":["addr"],"properties":{"addr":{"type":"integer"},"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"base":{"type":"integer"},"arch":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefIndexDataRefsToTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let idx = build_xref_index(&args)?;
        let r = idx.data_refs_to(addr);
        Ok(ToolResult::text(json!({"refs": r, "count": r.len()}).to_string()))
    }
}

pub struct AnalysisXrefIndexIsLeafTool;
impl AnalysisXrefIndexIsLeafTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_index_is_leaf".to_string(),
            description: "Whether an address has no outgoing Call xrefs (leaf function heuristic).".to_string(),
            input_schema: json!({"type":"object","required":["addr"],"properties":{"addr":{"type":"integer"},"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"base":{"type":"integer"},"arch":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefIndexIsLeafTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let idx = build_xref_index(&args)?;
        Ok(ToolResult::text(json!({"addr": addr, "is_leaf": idx.is_leaf(addr)}).to_string()))
    }
}

pub struct AnalysisXrefIndexSourcesTargetsTool;
impl AnalysisXrefIndexSourcesTargetsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_index_sources_targets".to_string(),
            description: "All unique source and target VAs in the BinaryXrefIndex.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"base":{"type":"integer"},"arch":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefIndexSourcesTargetsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let idx = build_xref_index(&args)?;
        let src = idx.all_sources();
        let tgt = idx.all_targets();
        Ok(ToolResult::text(json!({"sources_count": src.len(), "targets_count": tgt.len(), "sources": src, "targets": tgt}).to_string()))
    }
}

pub struct AnalysisXrefKindClassifyTool;
impl AnalysisXrefKindClassifyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_kind_classify".to_string(),
            description: "Classify an XrefKind name into (is_code, is_data, is_import) buckets.".to_string(),
            input_schema: json!({"type":"object","required":["kind"],"properties":{"kind":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefKindClassifyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let k = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let kind = match k {
            "CodeCall" => rustre_analysis_xref::XrefKind::CodeCall,
            "CodeJump" => rustre_analysis_xref::XrefKind::CodeJump,
            "CodeReturn" => rustre_analysis_xref::XrefKind::CodeReturn,
            "DataRead" => rustre_analysis_xref::XrefKind::DataRead,
            "DataWrite" => rustre_analysis_xref::XrefKind::DataWrite,
            "DataAddress" => rustre_analysis_xref::XrefKind::DataAddress,
            "DataPointer" => rustre_analysis_xref::XrefKind::DataPointer,
            "ImportByName" => rustre_analysis_xref::XrefKind::ImportByName,
            "ImportByOrdinal" => rustre_analysis_xref::XrefKind::ImportByOrdinal,
            "StringRef" => rustre_analysis_xref::XrefKind::StringRef,
            "TypeRef" => rustre_analysis_xref::XrefKind::TypeRef,
            "ThunkCall" => rustre_analysis_xref::XrefKind::ThunkCall,
            other => return Err(McpError::InvalidParams(format!("unknown kind: {other}"))),
        };
        Ok(ToolResult::text(json!({"kind": k, "is_code": kind.is_code(), "is_data": kind.is_data(), "is_import": kind.is_import(), "display": kind.to_string()}).to_string()))
    }
}

pub struct AnalysisXrefDatabaseStatsTool;
impl AnalysisXrefDatabaseStatsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_database_stats".to_string(),
            description: "Build XrefDatabase from code bytes via X86XrefScanner and return XrefStats report.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"base":{"type":"integer"},"code_end":{"type":"integer"},"pointer_size":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefDatabaseStatsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let code = args_to_bytes(&args)?;
        let base = args.get("base").and_then(Value::as_u64).unwrap_or(0);
        let end = args.get("code_end").and_then(Value::as_u64).unwrap_or(base + code.len() as u64);
        let ps = args.get("pointer_size").and_then(Value::as_u64).unwrap_or(8) as usize;
        let range = rustre_core::address::AddressRange::new(
            rustre_core::address::Address::new(base),
            rustre_core::address::Address::new(end),
        );
        let scanner = rustre_analysis_xref::X86XrefScanner::new(range, ps);
        let mut db = rustre_analysis_xref::XrefDatabase::new();
        scanner.scan_code(rustre_core::address::Address::new(base), &code, &mut db);
        let stats = rustre_analysis_xref::XrefStats::compute(&db);
        Ok(ToolResult::text(json!({
            "total": stats.total,
            "unique_callers": stats.unique_callers,
            "unique_callees": stats.unique_callees,
            "leaf_functions": stats.leaf_functions,
            "total_imports": stats.total_imports,
            "total_strings": stats.total_strings,
            "total_types": stats.total_types,
            "report": stats.format_report(),
        }).to_string()))
    }
}

pub struct AnalysisScanProloguesTool;
impl AnalysisScanProloguesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_scan_prologues".to_string(),
            description: "Scan bytes for x86-64 function prologue patterns via rustre_analysis::FunctionBoundaryAnalysis::scan_prologues.".to_string(),
            input_schema: json!({ "type": "object", "properties": {
                "bytes": { "type": "array", "items": { "type": "integer" } },
                "hex": { "type": "string" },
                "base": { "type": "integer" }
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisScanProloguesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let base = args.get("base").and_then(Value::as_u64).unwrap_or(0);
        let boundaries = rustre_analysis::FunctionBoundaryAnalysis::scan_prologues(base, &data);
        let starts: Vec<u64> = boundaries.iter().map(|b| b.start).collect();
        Ok(ToolResult::text(json!({
            "count": boundaries.len(),
            "starts": starts,
            "source": "rustre_analysis::FunctionBoundaryAnalysis::scan_prologues",
        }).to_string()))
    }
}

pub struct AnalysisCountStringsTool;
impl AnalysisCountStringsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_count_strings".to_string(),
            description: "Count null-terminated printable ASCII strings via rustre_analysis::StringRecoveryPass::count_strings.".to_string(),
            input_schema: json!({ "type": "object", "properties": {
                "bytes": { "type": "array", "items": { "type": "integer" } },
                "hex": { "type": "string" }
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisCountStringsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let count = rustre_analysis::StringRecoveryPass::count_strings(&data);
        Ok(ToolResult::text(json!({
            "count": count,
            "source": "rustre_analysis::StringRecoveryPass::count_strings",
        }).to_string()))
    }
}

pub struct AnalysisCountXrefsTool;
impl AnalysisCountXrefsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_count_xrefs".to_string(),
            description: "Count x86-64 CALL/JMP rel32 xrefs via rustre_analysis::XrefRecoveryPass::count_xrefs.".to_string(),
            input_schema: json!({ "type": "object", "properties": {
                "bytes": { "type": "array", "items": { "type": "integer" } },
                "hex": { "type": "string" },
                "base": { "type": "integer" }
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisCountXrefsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let base = args.get("base").and_then(Value::as_u64).unwrap_or(0);
        let count = rustre_analysis::XrefRecoveryPass::count_xrefs(base, &data);
        Ok(ToolResult::text(json!({
            "count": count,
            "source": "rustre_analysis::XrefRecoveryPass::count_xrefs",
        }).to_string()))
    }
}

pub struct AnalysisCountBasicBlocksTool;
impl AnalysisCountBasicBlocksTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_count_basic_blocks".to_string(),
            description: "Count approximate basic-block boundaries via rustre_analysis::CfgAnalysisPass::count_basic_blocks.".to_string(),
            input_schema: json!({ "type": "object", "properties": {
                "bytes": { "type": "array", "items": { "type": "integer" } },
                "hex": { "type": "string" }
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisCountBasicBlocksTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let count = rustre_analysis::CfgAnalysisPass::count_basic_blocks(&data);
        Ok(ToolResult::text(json!({
            "count": count,
            "source": "rustre_analysis::CfgAnalysisPass::count_basic_blocks",
        }).to_string()))
    }
}

pub struct AnalysisLinearSweepTool;
impl AnalysisLinearSweepTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_linear_sweep".to_string(),
            description: "Run rustre_analysis::LinearSweepAnalyzer with default config over bytes at base.".to_string(),
            input_schema: json!({ "type": "object", "properties": {
                "bytes": { "type": "array", "items": { "type": "integer" } },
                "hex": { "type": "string" },
                "base": { "type": "integer" }
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisLinearSweepTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let base = args.get("base").and_then(Value::as_u64).unwrap_or(0);
        let analyzer = rustre_analysis::LinearSweepAnalyzer::default();
        let boundaries = analyzer.sweep(base, &data);
        let starts: Vec<u64> = boundaries.iter().map(|b| b.start).collect();
        Ok(ToolResult::text(json!({
            "count": boundaries.len(),
            "starts": starts,
            "source": "rustre_analysis::LinearSweepAnalyzer::sweep",
        }).to_string()))
    }
}

pub struct AnalysisRecursiveDescentTool;
impl AnalysisRecursiveDescentTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_recursive_descent".to_string(),
            description: "Run rustre_analysis::RecursiveDescentAnalyzer over bytes at base with the given entry points.".to_string(),
            input_schema: json!({ "type": "object", "properties": {
                "bytes": { "type": "array", "items": { "type": "integer" } },
                "hex": { "type": "string" },
                "base": { "type": "integer" },
                "entry_points": { "type": "array", "items": { "type": "integer" } },
                "max_depth": { "type": "integer" }
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisRecursiveDescentTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let base = args.get("base").and_then(Value::as_u64).unwrap_or(0);
        let max_depth = args.get("max_depth").and_then(Value::as_u64).unwrap_or(512) as usize;
        let eps: Vec<u64> = args.get("entry_points").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect())
            .unwrap_or_else(|| vec![base]);
        let analyzer = rustre_analysis::RecursiveDescentAnalyzer::new(max_depth);
        let boundaries = analyzer.analyze(base, &data, &eps);
        Ok(ToolResult::text(json!({
            "count": boundaries.len(),
            "source": "rustre_analysis::RecursiveDescentAnalyzer::analyze",
        }).to_string()))
    }
}

pub struct AnalysisBoundaryInfoTool;
impl AnalysisBoundaryInfoTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_boundary_info".to_string(),
            description: "Report size and high-confidence flag for a rustre_analysis::FunctionBoundary.".to_string(),
            input_schema: json!({ "type": "object", "properties": {
                "start": { "type": "integer" },
                "end": { "type": "integer" },
                "confidence": { "type": "integer" }
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisBoundaryInfoTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let start = args.get("start").and_then(Value::as_u64).unwrap_or(0);
        let end = args.get("end").and_then(Value::as_u64).unwrap_or(start);
        let conf = args.get("confidence").and_then(Value::as_u64).unwrap_or(50) as u8;
        let b = rustre_analysis::FunctionBoundary::new(start, end, rustre_analysis::BoundaryMethod::LinearSweep)
            .with_confidence(conf);
        Ok(ToolResult::text(json!({
            "size": b.size(),
            "is_high_confidence": b.is_high_confidence(),
            "source": "rustre_analysis::FunctionBoundary",
        }).to_string()))
    }
}

pub struct AnalysisXrefDbRoundtripTool;
impl AnalysisXrefDbRoundtripTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_xref_db_roundtrip".to_string(),
            description: "Populate a rustre_analysis::CrossReferenceDb with xrefs, return count/calls/targets.".to_string(),
            input_schema: json!({ "type": "object", "properties": {
                "xrefs": { "type": "array", "items": { "type": "object" } }
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisXrefDbRoundtripTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let db = rustre_analysis::CrossReferenceDb::new();
        if let Some(arr) = args.get("xrefs").and_then(Value::as_array) {
            for v in arr {
                let from = v.get("from").and_then(Value::as_u64).unwrap_or(0);
                let to = v.get("to").and_then(Value::as_u64).unwrap_or(0);
                let kind = match v.get("kind").and_then(Value::as_str).unwrap_or("call") {
                    "jump" => rustre_analysis::XrefType::Jump,
                    "data_read" => rustre_analysis::XrefType::DataRead,
                    "data_write" => rustre_analysis::XrefType::DataWrite,
                    "string_ref" => rustre_analysis::XrefType::StringRef,
                    "unknown" => rustre_analysis::XrefType::Unknown,
                    _ => rustre_analysis::XrefType::Call,
                };
                db.add_raw(from, to, kind);
            }
        }
        Ok(ToolResult::text(json!({
            "count": db.count(),
            "calls": db.calls().len(),
            "call_targets": db.call_targets(),
            "source": "rustre_analysis::CrossReferenceDb",
        }).to_string()))
    }
}

pub struct AnalysisStatsAggregateTool;
impl AnalysisStatsAggregateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_stats_aggregate".to_string(),
            description: "Aggregate pass results via rustre_analysis::AnalysisStats.".to_string(),
            input_schema: json!({ "type": "object", "properties": {
                "results": { "type": "array", "items": { "type": "object" } }
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisStatsAggregateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut stats = rustre_analysis::AnalysisStats::new();
        if let Some(arr) = args.get("results").and_then(Value::as_array) {
            for v in arr {
                let name = v.get("name").and_then(Value::as_str).unwrap_or("pass").to_string();
                let r = rustre_analysis::AnalysisResult {
                    kind: rustre_analysis::AnalysisKind::LinearSweep,
                    functions_found: v.get("functions").and_then(Value::as_u64).unwrap_or(0) as usize,
                    data_refs_found: v.get("data_refs").and_then(Value::as_u64).unwrap_or(0) as usize,
                    strings_found: v.get("strings").and_then(Value::as_u64).unwrap_or(0) as usize,
                    duration_ms: v.get("duration_ms").and_then(Value::as_u64).unwrap_or(0),
                    warnings: Vec::new(),
                };
                stats.record_result(&name, &r);
            }
        }
        Ok(ToolResult::text(json!({
            "total_functions": stats.total_functions,
            "total_strings": stats.total_strings,
            "total_duration_ms": stats.total_duration_ms,
            "avg_duration_ms": stats.avg_duration_ms(),
            "slowest": stats.slowest_pass().map(|p| p.pass_name.clone()),
            "all_succeeded": stats.all_succeeded(),
            "source": "rustre_analysis::AnalysisStats",
        }).to_string()))
    }
}

pub struct AnalysisSchedulerOrderTool;
impl AnalysisSchedulerOrderTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_scheduler_order".to_string(),
            description: "Topologically schedule passes via rustre_analysis::PassScheduler.".to_string(),
            input_schema: json!({ "type": "object", "properties": {
                "passes": { "type": "array", "items": { "type": "object" } }
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisSchedulerOrderTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut sched = rustre_analysis::PassScheduler::new();
        if let Some(arr) = args.get("passes").and_then(Value::as_array) {
            for v in arr {
                let name = v.get("name").and_then(Value::as_str).unwrap_or("pass");
                let mut desc = rustre_analysis::PassDescriptor::new(name)
                    .with_priority(v.get("priority").and_then(Value::as_i64).unwrap_or(0) as i32);
                if let Some(deps) = v.get("deps").and_then(Value::as_array) {
                    for d in deps { if let Some(s) = d.as_str() { desc = desc.with_dep(s); } }
                }
                sched.add(desc);
            }
        }
        match sched.schedule() {
            Ok(order) => Ok(ToolResult::text(json!({
                "order": order,
                "source": "rustre_analysis::PassScheduler::schedule",
            }).to_string())),
            Err(e) => Ok(ToolResult::text(json!({ "error": e }).to_string())),
        }
    }
}

pub struct AnalysisSchedulerGroupsTool;
impl AnalysisSchedulerGroupsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_scheduler_groups".to_string(),
            description: "Compute parallel-run groups via rustre_analysis::PassScheduler::schedule_groups.".to_string(),
            input_schema: json!({ "type": "object", "properties": {
                "passes": { "type": "array", "items": { "type": "object" } }
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisSchedulerGroupsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut sched = rustre_analysis::PassScheduler::new();
        if let Some(arr) = args.get("passes").and_then(Value::as_array) {
            for v in arr {
                let name = v.get("name").and_then(Value::as_str).unwrap_or("pass");
                let mut desc = rustre_analysis::PassDescriptor::new(name)
                    .with_priority(v.get("priority").and_then(Value::as_i64).unwrap_or(0) as i32);
                if let Some(deps) = v.get("deps").and_then(Value::as_array) {
                    for d in deps { if let Some(s) = d.as_str() { desc = desc.with_dep(s); } }
                }
                sched.add(desc);
            }
        }
        match sched.schedule_groups() {
            Ok(groups) => {
                let ng = groups.len();
                Ok(ToolResult::text(json!({
                    "groups": groups,
                    "num_groups": ng,
                    "source": "rustre_analysis::PassScheduler::schedule_groups",
                }).to_string()))
            }
            Err(e) => Ok(ToolResult::text(json!({ "error": e }).to_string())),
        }
    }
}

pub struct AnalysisIncrementalAffectedTool;
impl AnalysisIncrementalAffectedTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_incremental_affected".to_string(),
            description: "Compute affected passes via rustre_analysis::IncrementalAnalysis.".to_string(),
            input_schema: json!({ "type": "object", "properties": {
                "byte_sensitive": { "type": "array", "items": { "type": "string" } },
                "symbol_sensitive": { "type": "array", "items": { "type": "string" } },
                "ran": { "type": "array", "items": { "type": "string" } },
                "changes": { "type": "array", "items": { "type": "string" } }
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisIncrementalAffectedTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut inc = rustre_analysis::IncrementalAnalysis::new();
        if let Some(a) = args.get("byte_sensitive").and_then(Value::as_array) {
            for v in a { if let Some(s) = v.as_str() { inc.mark_byte_sensitive(s); } }
        }
        if let Some(a) = args.get("symbol_sensitive").and_then(Value::as_array) {
            for v in a { if let Some(s) = v.as_str() { inc.mark_symbol_sensitive(s); } }
        }
        if let Some(a) = args.get("ran").and_then(Value::as_array) {
            for v in a { if let Some(s) = v.as_str() { inc.mark_run(s); } }
        }
        let mut changes: Vec<rustre_analysis::BinaryChange> = Vec::new();
        if let Some(a) = args.get("changes").and_then(Value::as_array) {
            for v in a {
                let kind = match v.as_str().unwrap_or("data") {
                    "section" => rustre_analysis::ChangeKind::SectionAdded,
                    "symbol" => rustre_analysis::ChangeKind::SymbolRenamed,
                    "metadata" => rustre_analysis::ChangeKind::MetadataChanged,
                    _ => rustre_analysis::ChangeKind::DataModified,
                };
                changes.push(rustre_analysis::BinaryChange { address_start: 0, address_end: 0, kind });
            }
        }
        let affected = inc.affected_passes(&changes);
        Ok(ToolResult::text(json!({
            "affected": affected,
            "source": "rustre_analysis::IncrementalAnalysis::affected_passes",
        }).to_string()))
    }
}

pub struct AnalysisEventBusPublishTool;
impl AnalysisEventBusPublishTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_event_bus_publish".to_string(),
            description: "Subscribe a counting handler on rustre_analysis::AnalysisEventBus and publish N Warning events.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "count": { "type": "integer" } }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisEventBusPublishTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let bus = rustre_analysis::AnalysisEventBus::new();
        let n = args.get("count").and_then(Value::as_u64).unwrap_or(3) as usize;
        let counter = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&counter);
        bus.subscribe(Arc::new(move |_e| { c2.fetch_add(1, Ordering::AcqRel); }));
        for i in 0..n {
            bus.publish(&rustre_analysis::AnalysisEvent::Warning {
                pass_name: "tool".into(),
                message: format!("msg{i}"),
            });
        }
        Ok(ToolResult::text(json!({
            "handler_count": bus.handler_count(),
            "received": counter.load(Ordering::Acquire),
            "source": "rustre_analysis::AnalysisEventBus",
        }).to_string()))
    }
}

pub struct AnalysisReportSummaryTool;
impl AnalysisReportSummaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_report_summary".to_string(),
            description: "Build a rustre_analysis::AnalysisReport from a list of pass results.".to_string(),
            input_schema: json!({ "type": "object", "properties": {
                "uri": { "type": "string" },
                "results": { "type": "array", "items": { "type": "object" } }
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisReportSummaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let uri = args.get("uri").and_then(Value::as_str).unwrap_or("mem://");
        let mut outcomes: Vec<(String, Result<rustre_analysis::AnalysisResult, rustre_analysis::AnalysisError>)> = Vec::new();
        if let Some(arr) = args.get("results").and_then(Value::as_array) {
            for v in arr {
                let name = v.get("name").and_then(Value::as_str).unwrap_or("pass").to_string();
                let warnings: Vec<String> = v.get("warnings").and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                let r = rustre_analysis::AnalysisResult {
                    kind: rustre_analysis::AnalysisKind::LinearSweep,
                    functions_found: v.get("functions").and_then(Value::as_u64).unwrap_or(0) as usize,
                    data_refs_found: v.get("data_refs").and_then(Value::as_u64).unwrap_or(0) as usize,
                    strings_found: v.get("strings").and_then(Value::as_u64).unwrap_or(0) as usize,
                    duration_ms: v.get("duration_ms").and_then(Value::as_u64).unwrap_or(0),
                    warnings,
                };
                outcomes.push((name, Ok(r)));
            }
        }
        let report = rustre_analysis::AnalysisReport::build(uri, &outcomes);
        Ok(ToolResult::text(json!({
            "summary": report.summary(),
            "total_functions": report.total_functions(),
            "total_strings": report.total_strings(),
            "success": report.success,
            "warnings": report.all_warnings,
            "source": "rustre_analysis::AnalysisReport::build",
        }).to_string()))
    }
}

pub struct AnalysisCacheComputeHashTool;
impl AnalysisCacheComputeHashTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_cache_compute_hash".to_string(), description: "FNV-1a via rustre_analysis::analysis_cache::compute_hash.".to_string(), input_schema: json!({ "type":"object", "properties": { "hex": {"type":"string"}, "bytes": {"type":"array"} } }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AnalysisCacheComputeHashTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = args_to_bytes(&args)?; let h = rustre_analysis::analysis_cache::compute_hash(&data); Ok(ToolResult::text(json!({ "len": data.len(), "hash": h, "hash_hex": format!("{:016x}", h), "source": "rustre_analysis::analysis_cache::compute_hash" }).to_string())) } }

pub struct AnalysisCtxFunctionInfoNewTool;
impl AnalysisCtxFunctionInfoNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_ctx_function_info_new".to_string(), description: "Build FunctionInfo via rustre_analysis::analysis_context::FunctionInfo.".to_string(), input_schema: json!({ "type":"object", "properties": { "start": {"type":"integer"}, "length": {"type":"integer"}, "name": {"type":"string"}, "probe": {"type":"integer"} }, "required":["start"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AnalysisCtxFunctionInfoNewTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let start = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))?; let length = args.get("length").and_then(Value::as_u64).unwrap_or(0); let name = args.get("name").and_then(Value::as_str).map(str::to_string); let probe = args.get("probe").and_then(Value::as_u64).unwrap_or(start); let mut f = rustre_analysis::analysis_context::FunctionInfo::new(start); f.length = length; f.name = name; Ok(ToolResult::text(json!({ "start": f.start, "length": f.length, "end": f.end(), "display_name": f.display_name(), "contains_probe": f.contains(probe), "source": "rustre_analysis::analysis_context::FunctionInfo" }).to_string())) } }

pub struct AnalysisCtxFunctionInfoAddTagTool;
impl AnalysisCtxFunctionInfoAddTagTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_ctx_function_info_add_tag".to_string(), description: "Dedup-add tags via rustre_analysis::analysis_context::FunctionInfo::add_tag.".to_string(), input_schema: json!({ "type":"object", "properties": { "start": {"type":"integer"}, "tags": {"type":"array"} }, "required":["start","tags"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AnalysisCtxFunctionInfoAddTagTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let start = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))?; let arr = args.get("tags").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'tags'".into()))?; let mut f = rustre_analysis::analysis_context::FunctionInfo::new(start); for v in arr { if let Some(s) = v.as_str() { f.add_tag(s.to_string()); } } Ok(ToolResult::text(json!({ "tags": f.tags, "unique_count": f.tags.len(), "source": "rustre_analysis::analysis_context::FunctionInfo::add_tag" }).to_string())) } }

pub struct AnalysisCtxStringInfoClassifyTool;
impl AnalysisCtxStringInfoClassifyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_ctx_string_info_classify".to_string(), description: "Classify a StringInfo via rustre_analysis::analysis_context::StringInfo.".to_string(), input_schema: json!({ "type":"object", "properties": { "address": {"type":"integer"}, "value": {"type":"string"} }, "required":["value"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AnalysisCtxStringInfoClassifyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("address").and_then(Value::as_u64).unwrap_or(0); let value = args.get("value").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?; let s = rustre_analysis::analysis_context::StringInfo::new(addr, value.to_string()); Ok(ToolResult::text(json!({ "address": s.address, "byte_length": s.byte_length, "is_non_ascii": s.is_non_ascii(), "looks_like_api": s.looks_like_api(), "source": "rustre_analysis::analysis_context::StringInfo" }).to_string())) } }

pub struct AnalysisCtxXrefInfoBuildTool;
impl AnalysisCtxXrefInfoBuildTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_ctx_xref_info_build".to_string(), description: "Build XrefInfo via rustre_analysis::analysis_context::XrefInfo.".to_string(), input_schema: json!({ "type":"object", "properties": { "from": {"type":"integer"}, "to": {"type":"integer"}, "kind": {"type":"string"} }, "required":["from","to"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AnalysisCtxXrefInfoBuildTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let from = args.get("from").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'from'".into()))?; let to = args.get("to").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'to'".into()))?; let kind = args.get("kind").and_then(Value::as_str).unwrap_or("call"); let x = match kind { "jump" => rustre_analysis::analysis_context::XrefInfo::jump(from, to), "data" => rustre_analysis::analysis_context::XrefInfo::data(from, to), _ => rustre_analysis::analysis_context::XrefInfo::call(from, to), }; Ok(ToolResult::text(json!({ "from": x.from, "to": x.to, "kind": format!("{:?}", x.kind), "source": "rustre_analysis::analysis_context::XrefInfo" }).to_string())) } }

pub struct AnalysisProgressTrackTool;
impl AnalysisProgressTrackTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_progress_track".to_string(), description: "Track passes via rustre_analysis::analysis_context::AnalysisProgress.".to_string(), input_schema: json!({ "type":"object", "properties": { "done": {"type":"array"}, "failed": {"type":"array"}, "query": {"type":"string"} } }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AnalysisProgressTrackTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let mut p = rustre_analysis::analysis_context::AnalysisProgress::new(); if let Some(a) = args.get("done").and_then(Value::as_array) { for v in a { if let Some(s) = v.as_str() { p.mark_done(s.to_string()); } } } if let Some(a) = args.get("failed").and_then(Value::as_array) { for v in a { let name = v.get("name").and_then(Value::as_str).unwrap_or("").to_string(); let reason = v.get("reason").and_then(Value::as_str).unwrap_or("").to_string(); if !name.is_empty() { p.mark_failed(name, reason); } } } let q = args.get("query").and_then(Value::as_str).unwrap_or(""); Ok(ToolResult::text(json!({ "completed": p.all_completed(), "failed": p.all_failed().iter().map(|(a,b)| json!([a,b])).collect::<Vec<_>>(), "is_done_query": p.is_done(q), "has_failed_query": p.has_failed(q), "source": "rustre_analysis::analysis_context::AnalysisProgress" }).to_string())) } }

pub struct AnalysisCtxBuilderTool;
impl AnalysisCtxBuilderTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_ctx_builder".to_string(), description: "Build AnalysisCtx via rustre_analysis::analysis_context::AnalysisCtxBuilder.".to_string(), input_schema: json!({ "type":"object", "properties": { "id": {"type":"string"}, "name": {"type":"string"}, "arch": {"type":"string"} }, "required":["id","name","arch"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AnalysisCtxBuilderTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let id = args.get("id").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'id'".into()))?; let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?; let arch = args.get("arch").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'arch'".into()))?; let ctx = rustre_analysis::analysis_context::AnalysisCtxBuilder::new().id(id).name(name).arch(arch).build().map_err(|e| McpError::InvalidParams(format!("{e}")))?; let s = ctx.stats(); Ok(ToolResult::text(json!({ "function_count": s.function_count, "string_count": s.string_count, "xref_count": s.xref_count, "code_bytes": s.code_bytes, "symbolicated_functions": s.symbolicated_functions, "source": "rustre_analysis::analysis_context::AnalysisCtxBuilder" }).to_string())) } }

pub struct AnalysisCacheKeyFromDataTool;
impl AnalysisCacheKeyFromDataTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_cache_key_from_data".to_string(), description: "Compute a CacheKey via rustre_analysis::analysis_cache::CacheKey::from_data.".to_string(), input_schema: json!({ "type":"object", "properties": { "pass_name": {"type":"string"}, "uri": {"type":"string"}, "hex": {"type":"string"}, "bytes": {"type":"array"} }, "required":["pass_name","uri"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AnalysisCacheKeyFromDataTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pass_name = args.get("pass_name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pass_name'".into()))?; let uri = args.get("uri").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'uri'".into()))?; let data = args_to_bytes(&args).unwrap_or_default(); let k = rustre_analysis::analysis_cache::CacheKey::from_data(pass_name, uri, &data); Ok(ToolResult::text(json!({ "pass_name": k.pass_name, "uri": k.uri, "content_hash": k.content_hash, "content_hash_hex": format!("{:016x}", k.content_hash), "source": "rustre_analysis::analysis_cache::CacheKey::from_data" }).to_string())) } }

pub struct AnalysisCacheLruBasicsTool;
impl AnalysisCacheLruBasicsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_cache_lru_basics".to_string(), description: "Exercise rustre_analysis::analysis_cache::AnalysisCache new/put/len/fill_ratio.".to_string(), input_schema: json!({ "type":"object", "properties": { "max_entries": {"type":"integer"}, "puts": {"type":"array"} }, "required":["max_entries"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AnalysisCacheLruBasicsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let max = args.get("max_entries").and_then(Value::as_u64).unwrap_or(4) as usize; let mut c = rustre_analysis::analysis_cache::AnalysisCache::new(max.max(1)); let mut evictions: Vec<String> = Vec::new(); if let Some(a) = args.get("puts").and_then(Value::as_array) { for v in a { let pass = v.get("pass").and_then(Value::as_str).unwrap_or("p").to_string(); let uri = v.get("uri").and_then(Value::as_str).unwrap_or("u").to_string(); let payload = v.get("payload").and_then(Value::as_str).unwrap_or("").to_string(); let k = rustre_analysis::analysis_cache::CacheKey::new(pass, uri, 0); if let Some(evicted) = c.put(k, payload) { evictions.push(format!("{}::{}", evicted.pass_name, evicted.uri)); } } } Ok(ToolResult::text(json!({ "len": c.len(), "is_empty": c.is_empty(), "fill_ratio": c.fill_ratio(), "evictions": evictions, "source": "rustre_analysis::analysis_cache::AnalysisCache" }).to_string())) } }

pub struct AnalysisPassRegistryBuiltinTool;
impl AnalysisPassRegistryBuiltinTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_pass_registry_builtin".to_string(), description: "List built-in analysis passes via rustre_analysis::pass_registry::builtin_registry.".to_string(), input_schema: json!({ "type":"object", "properties": {} }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AnalysisPassRegistryBuiltinTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let reg = rustre_analysis::pass_registry::builtin_registry(); let mut names = reg.names(); names.sort(); Ok(ToolResult::text(json!({ "len": reg.len(), "is_empty": reg.is_empty(), "names": names, "source": "rustre_analysis::pass_registry::builtin_registry" }).to_string())) } }

pub struct AnalysisTypeFactByteSizeTool;
impl AnalysisTypeFactByteSizeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_type_fact_byte_size".to_string(),
            description: "Return TypeFact::byte_size() for a JSON-encoded TypeFact.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "fact": {} }, "required": ["fact"] }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTypeFactByteSizeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let fact_v = args.get("fact").cloned().ok_or_else(|| McpError::InvalidParams("missing 'fact'".into()))?;
        let fact: rustre_analysis_type::TypeFact = serde_json::from_value(fact_v)
            .map_err(|e| McpError::InvalidParams(format!("bad fact: {e}")))?;
        Ok(ToolResult::text(json!({ "byte_size": fact.byte_size() }).to_string()))
    }
}

pub struct AnalysisTypeFactIsKnownTool;
impl AnalysisTypeFactIsKnownTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_type_fact_is_known".to_string(),
            description: "Return TypeFact::is_known() for a JSON-encoded TypeFact.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "fact": {} }, "required": ["fact"] }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTypeFactIsKnownTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let fact_v = args.get("fact").cloned().ok_or_else(|| McpError::InvalidParams("missing 'fact'".into()))?;
        let fact: rustre_analysis_type::TypeFact = serde_json::from_value(fact_v)
            .map_err(|e| McpError::InvalidParams(format!("bad fact: {e}")))?;
        Ok(ToolResult::text(json!({ "is_known": fact.is_known() }).to_string()))
    }
}

pub struct AnalysisTypeFactJoinTool;
impl AnalysisTypeFactJoinTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_type_fact_join".to_string(),
            description: "Return TypeFact::join(a, b) — most-specific meet on the lattice.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "a": {}, "b": {} }, "required": ["a","b"] }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTypeFactJoinTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a: rustre_analysis_type::TypeFact = serde_json::from_value(
            args.get("a").cloned().ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?
        ).map_err(|e| McpError::InvalidParams(format!("bad a: {e}")))?;
        let b: rustre_analysis_type::TypeFact = serde_json::from_value(
            args.get("b").cloned().ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?
        ).map_err(|e| McpError::InvalidParams(format!("bad b: {e}")))?;
        let joined = a.join(&b);
        let v = serde_json::to_value(&joined).map_err(|e| McpError::InternalError(format!("serialize: {e}")))?;
        Ok(ToolResult::text(json!({ "joined": v, "display": joined.display_name() }).to_string()))
    }
}

pub struct AnalysisTypeFactDisplayNameTool;
impl AnalysisTypeFactDisplayNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_type_fact_display_name".to_string(),
            description: "Return TypeFact::display_name() — compact human-readable form.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "fact": {} }, "required": ["fact"] }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTypeFactDisplayNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let fact: rustre_analysis_type::TypeFact = serde_json::from_value(
            args.get("fact").cloned().ok_or_else(|| McpError::InvalidParams("missing 'fact'".into()))?
        ).map_err(|e| McpError::InvalidParams(format!("bad fact: {e}")))?;
        Ok(ToolResult::text(json!({ "display_name": fact.display_name() }).to_string()))
    }
}

pub struct AnalysisTypeFactDisplayTool;
impl AnalysisTypeFactDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_type_fact_display".to_string(),
            description: "Return the Display impl string for a TypeFact (as `to_string`).".to_string(),
            input_schema: json!({ "type": "object", "properties": { "fact": {} }, "required": ["fact"] }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTypeFactDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let fact: rustre_analysis_type::TypeFact = serde_json::from_value(
            args.get("fact").cloned().ok_or_else(|| McpError::InvalidParams("missing 'fact'".into()))?
        ).map_err(|e| McpError::InvalidParams(format!("bad fact: {e}")))?;
        Ok(ToolResult::text(json!({ "display": fact.to_string() }).to_string()))
    }
}

pub struct AnalysisTypeWinapiAllSignaturesTool;
impl AnalysisTypeWinapiAllSignaturesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_type_winapi_all_signatures".to_string(),
            description: "Return every FunctionSignature from WinApiTypeDb::all_signatures().".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTypeWinapiAllSignaturesTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let sigs = rustre_analysis_type::WinApiTypeDb::all_signatures();
        let v = serde_json::to_value(&sigs).map_err(|e| McpError::InternalError(format!("serialize: {e}")))?;
        Ok(ToolResult::text(json!({ "count": sigs.len(), "signatures": v }).to_string()))
    }
}

pub struct AnalysisTypeWinapiSignatureArityTool;
impl AnalysisTypeWinapiSignatureArityTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_type_winapi_signature_arity".to_string(),
            description: "Return arity() of the FunctionSignature named `name` (optional `dll`).".to_string(),
            input_schema: json!({ "type": "object", "properties": { "name": {"type":"string"}, "dll": {"type":"string"} }, "required": ["name"] }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTypeWinapiSignatureArityTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let dll = args.get("dll").and_then(Value::as_str);
        let sig = match dll {
            Some(d) => rustre_analysis_type::WinApiTypeDb::lookup(name, d),
            None => rustre_analysis_type::WinApiTypeDb::lookup_by_name(name),
        };
        Ok(ToolResult::text(json!({
            "name": name, "found": sig.is_some(),
            "arity": sig.as_ref().map(|s| s.arity())
        }).to_string()))
    }
}

pub struct AnalysisTypeWinapiSignatureParamTool;
impl AnalysisTypeWinapiSignatureParamTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_type_winapi_signature_param".to_string(),
            description: "Return param_type(idx) for the FunctionSignature named `name`.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "name": {"type":"string"}, "idx": {"type":"integer"}, "dll": {"type":"string"} }, "required": ["name","idx"] }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTypeWinapiSignatureParamTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let idx = args.get("idx").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'idx'".into()))? as usize;
        let dll = args.get("dll").and_then(Value::as_str);
        let sig = match dll {
            Some(d) => rustre_analysis_type::WinApiTypeDb::lookup(name, d),
            None => rustre_analysis_type::WinApiTypeDb::lookup_by_name(name),
        };
        let param = sig.as_ref().and_then(|s| s.param_type(idx)).cloned();
        let v = serde_json::to_value(&param).map_err(|e| McpError::InternalError(format!("serialize: {e}")))?;
        Ok(ToolResult::text(json!({
            "name": name, "idx": idx, "found": param.is_some(), "param": v
        }).to_string()))
    }
}

pub struct AnalysisTypeCallGraphTopoOrderTool;
impl AnalysisTypeCallGraphTopoOrderTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_type_call_graph_topo_order".to_string(),
            description: "Build a CallGraph from `edges` [[from,to], ...] and return topological_order().".to_string(),
            input_schema: json!({ "type": "object", "properties": { "edges": {"type":"array"} }, "required": ["edges"] }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTypeCallGraphTopoOrderTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let edges = args.get("edges").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'edges'".into()))?;
        let mut cg = rustre_analysis_type::CallGraph::new();
        for e in edges {
            let arr = e.as_array().ok_or_else(|| McpError::InvalidParams("edge not array".into()))?;
            let from = arr.first().and_then(Value::as_str).unwrap_or("");
            let to = arr.get(1).and_then(Value::as_str).unwrap_or("");
            cg.add_function(from);
            cg.add_function(to);
            cg.add_call(from, to);
        }
        let order = cg.topological_order();
        Ok(ToolResult::text(json!({ "order": order, "nodes": cg.nodes.len() }).to_string()))
    }
}

pub struct AnalysisTypeEnvironmentMergeTool;
impl AnalysisTypeEnvironmentMergeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_type_environment_merge".to_string(),
            description: "Merge TypeEnvironment `b` into `a` (widening on conflict); return the merged env.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "a": {}, "b": {} }, "required": ["a","b"] }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTypeEnvironmentMergeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut a: rustre_analysis_type::TypeEnvironment = serde_json::from_value(
            args.get("a").cloned().ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?
        ).map_err(|e| McpError::InvalidParams(format!("bad a: {e}")))?;
        let b: rustre_analysis_type::TypeEnvironment = serde_json::from_value(
            args.get("b").cloned().ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?
        ).map_err(|e| McpError::InvalidParams(format!("bad b: {e}")))?;
        a.merge(&b);
        let v = serde_json::to_value(&a).map_err(|e| McpError::InternalError(format!("serialize: {e}")))?;
        Ok(ToolResult::text(json!({ "merged": v }).to_string()))
    }
}

pub struct AnalysisTypeInferSignatureTool;
impl AnalysisTypeInferSignatureTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_type_infer_signature".to_string(),
            description: "Call infer_function_signature(addr, calling_conv, env) and return the InferredSignature.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "addr": {"type":"integer"},
                    "calling_conv": {"type":"string"},
                    "env": {}
                },
                "required": ["addr","env"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTypeInferSignatureTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let cc = args.get("calling_conv").and_then(Value::as_str);
        let env: rustre_analysis_type::TypeEnvironment = serde_json::from_value(
            args.get("env").cloned().ok_or_else(|| McpError::InvalidParams("missing 'env'".into()))?
        ).map_err(|e| McpError::InvalidParams(format!("bad env: {e}")))?;
        let sig = rustre_analysis_type::infer_function_signature(addr, cc, &env);
        let v = serde_json::to_value(&sig).map_err(|e| McpError::InternalError(format!("serialize: {e}")))?;
        Ok(ToolResult::text(v.to_string()))
    }
}

pub struct AnalysisTypeSolveSimpleTool;
impl AnalysisTypeSolveSimpleTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_type_solve_simple".to_string(),
            description: "Build TypeInferenceEngine, add HasType constraints from hints, solve, return per-name TypeFact.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "hints": {"type":"array"} }, "required": ["hints"] }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTypeSolveSimpleTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hints = args.get("hints").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'hints'".into()))?;
        let mut engine = rustre_analysis_type::TypeInferenceEngine::new();
        let mut names: Vec<String> = Vec::new();
        for h in hints {
            let name = h.get("name").and_then(Value::as_str)
                .ok_or_else(|| McpError::InvalidParams("hint missing 'name'".into()))?;
            let fact: rustre_analysis_type::TypeFact = serde_json::from_value(
                h.get("fact").cloned().ok_or_else(|| McpError::InvalidParams("hint missing 'fact'".into()))?
            ).map_err(|e| McpError::InvalidParams(format!("bad fact: {e}")))?;
            let v = engine.var_for(name);
            engine.add_constraint(rustre_analysis_type::TypeConstraint::HasType(v, fact));
            names.push(name.to_string());
        }
        let assignment = engine.solve()
            .map_err(|e| McpError::InternalError(format!("solve: {e}")))?;
        let mut out = serde_json::Map::new();
        for name in &names {
            let ty = engine.type_of(name, &assignment)
                .unwrap_or(rustre_analysis_type::TypeFact::Unknown);
            out.insert(name.clone(), json!({
                "display": ty.display_name(),
                "fact": serde_json::to_value(&ty).unwrap_or(Value::Null),
            }));
        }
        Ok(ToolResult::text(json!({ "types": out }).to_string()))
    }
}

pub struct AnalysisFnDetectFunctionsPathTool;

pub struct AnalysisStringScanPathTool;

pub struct AnalysisCryptoScanPathTool;

pub struct AnalysisStringDetectXorKeyTool;
impl AnalysisStringDetectXorKeyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_string_detect_xor_key".to_string(),
            description: "Detect single-byte XOR key from hex-encoded data via rustre_analysis_string::detect_xor_key.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "hex": { "type": "string", "description": "Hex-encoded input bytes" } },
                "required": ["hex"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisStringDetectXorKeyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?;
        let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        if clean.len() % 2 != 0 {
            return Err(McpError::InvalidParams("hex length must be even".into()));
        }
        let mut data = Vec::with_capacity(clean.len() / 2);
        for i in (0..clean.len()).step_by(2) {
            let byte = u8::from_str_radix(&clean[i..i + 2], 16)
                .map_err(|e| McpError::InvalidParams(format!("bad hex: {e}")))?;
            data.push(byte);
        }
        let key = rustre_analysis_string::detect_xor_key(&data);
        Ok(ToolResult::text(json!({
            "input_bytes": data.len(),
            "key": key,
            "found": key.is_some(),
            "source": "rustre_analysis_string::detect_xor_key",
        }).to_string()))
    }
}

pub struct AnalysisStringExtractUrlsPathTool;
impl AnalysisStringExtractUrlsPathTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_string_extract_urls_path".to_string(),
            description: "Scan a binary's sections for strings and extract URLs via rustre_analysis_string::extract_urls.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "min_length": { "type": "integer" },
                    "limit": { "type": "integer" }
                },
                "required": ["path"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisStringExtractUrlsPathTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_analysis_string::{StringScanner, StringScannerConfig, extract_urls};
        

        let path = args.get("path").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let min_length = args.get("min_length").and_then(Value::as_u64)
            .map(|v| v as usize).unwrap_or(5);
        let limit = args.get("limit").and_then(Value::as_u64)
            .map(|v| v as usize).unwrap_or(1000);

        let load = rustre_decompiler::load_binary(std::path::Path::new(path))
            .map_err(|e| McpError::InternalError(format!("load failed: {e}")))?;
        let image_base = load.base_address;
        let mut cfg = StringScannerConfig::default();
        cfg.min_length = min_length;
        let scanner = StringScanner::new(cfg);

        let mut all = Vec::new();
        if load.sections.is_empty() {
            all.extend(scanner.scan(rustre_core::address::Address::new(image_base), &load.data));
        } else {
            for sec in &load.sections {
                let start = usize::try_from(sec.raw_offset).unwrap_or(usize::MAX);
                let size = usize::try_from(sec.raw_size).unwrap_or(0);
                let end = start.saturating_add(size).min(load.data.len());
                if start >= end { continue; }
                let va_base = image_base + sec.virtual_addr;
                all.extend(scanner.scan(rustre_core::address::Address::new(va_base), &load.data[start..end]));
            }
        }
        let urls = extract_urls(&all);
        let total = urls.len();
        let out: Vec<serde_json::Value> = urls.into_iter().take(limit).map(|u| {
            serde_json::json!({
                "url": u.url,
                "scheme": u.scheme,
                "host": u.host,
            })
        }).collect();
        Ok(ToolResult::text(serde_json::json!({
            "path": path,
            "total": total,
            "returned": out.len(),
            "urls": out,
            "source": "rustre_analysis_string::extract_urls",
        }).to_string()))
    }
}

pub struct AnalysisStringStatsPathTool;
impl AnalysisStringStatsPathTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_string_stats_path".to_string(),
            description: "Scan a binary and return aggregate string statistics via rustre_analysis_string::StringStats::compute.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "min_length": { "type": "integer" }
                },
                "required": ["path"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AnalysisStringStatsPathTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_analysis_string::{StringScanner, StringScannerConfig, StringStats};

        let path = args.get("path").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let min_length = args.get("min_length").and_then(Value::as_u64)
            .map(|v| v as usize).unwrap_or(5);

        let load = rustre_decompiler::load_binary(std::path::Path::new(path))
            .map_err(|e| McpError::InternalError(format!("load failed: {e}")))?;
        let image_base = load.base_address;
        let mut cfg = StringScannerConfig::default();
        cfg.min_length = min_length;
        let scanner = StringScanner::new(cfg);

        let mut all = Vec::new();
        if load.sections.is_empty() {
            all.extend(scanner.scan(rustre_core::address::Address::new(image_base), &load.data));
        } else {
            for sec in &load.sections {
                let start = usize::try_from(sec.raw_offset).unwrap_or(usize::MAX);
                let size = usize::try_from(sec.raw_size).unwrap_or(0);
                let end = start.saturating_add(size).min(load.data.len());
                if start >= end { continue; }
                let va_base = image_base + sec.virtual_addr;
                all.extend(scanner.scan(rustre_core::address::Address::new(va_base), &load.data[start..end]));
            }
        }
        let stats = StringStats::compute(&all);
        Ok(ToolResult::text(serde_json::json!({
            "path": path,
            "total": stats.total,
            "by_encoding": stats.by_encoding,
            "avg_length": stats.avg_length,
            "max_length": stats.max_length,
            "interesting_count": stats.interesting_count,
            "classified_count": stats.classified_count,
            "format_string_count": stats.format_string_count,
            "url_count": stats.url_count,
            "path_count": stats.path_count,
            "longest": stats.longest,
            "shortest_interesting": stats.shortest_interesting,
            "source": "rustre_analysis_string::StringStats::compute",
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (AnalysisDataflowComputeLivenessTool::definition(), Box::new(AnalysisDataflowComputeLivenessTool)),
        (AnalysisDataflowComputeReachingDefsTool::definition(), Box::new(AnalysisDataflowComputeReachingDefsTool)),
        (AnalysisXrefCallGraphTool::definition(), Box::new(AnalysisXrefCallGraphTool)),
        (AnalysisXrefGetXrefsToTool::definition(), Box::new(AnalysisXrefGetXrefsToTool)),
        (AnalysisXrefGetXrefsFromTool::definition(), Box::new(AnalysisXrefGetXrefsFromTool)),
        (AnalysisXrefCallGraphRootFunctionsTool::definition(), Box::new(AnalysisXrefCallGraphRootFunctionsTool)),
        (AnalysisXrefStringRefCountsTool::definition(), Box::new(AnalysisXrefStringRefCountsTool)),
        (AnalysisFnDetectExtraTool::definition(), Box::new(AnalysisFnDetectExtraTool)),
        (AnalysisVsaResolveJumpTableTool::definition(), Box::new(AnalysisVsaResolveJumpTableTool)),
        (AnalysisVsaResolveIndirectCallsTool::definition(), Box::new(AnalysisVsaResolveIndirectCallsTool)),
        (AnalysisVsaDetectBufferOverflowsTool::definition(), Box::new(AnalysisVsaDetectBufferOverflowsTool)),
        (AnalysisTypeListBuiltinTypesTool::definition(), Box::new(AnalysisTypeListBuiltinTypesTool)),
        (AnalysisTypeLookupBuiltinTypeTool::definition(), Box::new(AnalysisTypeLookupBuiltinTypeTool)),
        (AnalysisTypeWinapiLookupTool::definition(), Box::new(AnalysisTypeWinapiLookupTool)),
        (AnalysisXrefGlobalToTool::definition(), Box::new(AnalysisXrefGlobalToTool)),
        (AnalysisXrefGlobalFromTool::definition(), Box::new(AnalysisXrefGlobalFromTool)),
        (AnalysisResultZeroTotalItemsTool::definition(), Box::new(AnalysisResultZeroTotalItemsTool)),
        (AnalysisScanCallTargetsTool::definition(), Box::new(AnalysisScanCallTargetsTool)),
        (AnalysisStringDetectXorKeyWire2Tool::definition(), Box::new(AnalysisStringDetectXorKeyWire2Tool)),
        (AnalysisStringShannonEntropyWire2Tool::definition(), Box::new(AnalysisStringShannonEntropyWire2Tool)),
        (AnalysisXrefKindIsCodeTool::definition(), Box::new(AnalysisXrefKindIsCodeTool)),
        (AnalysisXrefKindIsDataTool::definition(), Box::new(AnalysisXrefKindIsDataTool)),
        (AnalysisXrefKindIsImportTool::definition(), Box::new(AnalysisXrefKindIsImportTool)),
        (AnalysisXrefKindAllTool::definition(), Box::new(AnalysisXrefKindAllTool)),
        (AnalysisXrefParseKindTool::definition(), Box::new(AnalysisXrefParseKindTool)),
        (AnalysisXrefIndexFromPathV2Tool::definition(), Box::new(AnalysisXrefIndexFromPathV2Tool)),
        (AnalysisXrefIndexFromBytesV2Tool::definition(), Box::new(AnalysisXrefIndexFromBytesV2Tool)),
        (AnalysisXrefGlobalDbTotalTool::definition(), Box::new(AnalysisXrefGlobalDbTotalTool)),
        (AnalysisXrefIndexTotalTool::definition(), Box::new(AnalysisXrefIndexTotalTool)),
        (AnalysisXrefIndexCountKindTool::definition(), Box::new(AnalysisXrefIndexCountKindTool)),
        (AnalysisXrefIndexHotCallTargetsTool::definition(), Box::new(AnalysisXrefIndexHotCallTargetsTool)),
        (AnalysisXrefIndexCallersOfTool::definition(), Box::new(AnalysisXrefIndexCallersOfTool)),
        (AnalysisXrefIndexCalleesOfTool::definition(), Box::new(AnalysisXrefIndexCalleesOfTool)),
        (AnalysisXrefIndexDataRefsToTool::definition(), Box::new(AnalysisXrefIndexDataRefsToTool)),
        (AnalysisXrefIndexIsLeafTool::definition(), Box::new(AnalysisXrefIndexIsLeafTool)),
        (AnalysisXrefIndexSourcesTargetsTool::definition(), Box::new(AnalysisXrefIndexSourcesTargetsTool)),
        (AnalysisXrefKindClassifyTool::definition(), Box::new(AnalysisXrefKindClassifyTool)),
        (AnalysisXrefDatabaseStatsTool::definition(), Box::new(AnalysisXrefDatabaseStatsTool)),
        (AnalysisScanProloguesTool::definition(), Box::new(AnalysisScanProloguesTool)),
        (AnalysisCountStringsTool::definition(), Box::new(AnalysisCountStringsTool)),
        (AnalysisCountXrefsTool::definition(), Box::new(AnalysisCountXrefsTool)),
        (AnalysisCountBasicBlocksTool::definition(), Box::new(AnalysisCountBasicBlocksTool)),
        (AnalysisLinearSweepTool::definition(), Box::new(AnalysisLinearSweepTool)),
        (AnalysisRecursiveDescentTool::definition(), Box::new(AnalysisRecursiveDescentTool)),
        (AnalysisBoundaryInfoTool::definition(), Box::new(AnalysisBoundaryInfoTool)),
        (AnalysisXrefDbRoundtripTool::definition(), Box::new(AnalysisXrefDbRoundtripTool)),
        (AnalysisStatsAggregateTool::definition(), Box::new(AnalysisStatsAggregateTool)),
        (AnalysisSchedulerOrderTool::definition(), Box::new(AnalysisSchedulerOrderTool)),
        (AnalysisSchedulerGroupsTool::definition(), Box::new(AnalysisSchedulerGroupsTool)),
        (AnalysisIncrementalAffectedTool::definition(), Box::new(AnalysisIncrementalAffectedTool)),
        (AnalysisEventBusPublishTool::definition(), Box::new(AnalysisEventBusPublishTool)),
        (AnalysisReportSummaryTool::definition(), Box::new(AnalysisReportSummaryTool)),
        (AnalysisCacheComputeHashTool::definition(), Box::new(AnalysisCacheComputeHashTool)),
        (AnalysisCtxFunctionInfoNewTool::definition(), Box::new(AnalysisCtxFunctionInfoNewTool)),
        (AnalysisCtxFunctionInfoAddTagTool::definition(), Box::new(AnalysisCtxFunctionInfoAddTagTool)),
        (AnalysisCtxStringInfoClassifyTool::definition(), Box::new(AnalysisCtxStringInfoClassifyTool)),
        (AnalysisCtxXrefInfoBuildTool::definition(), Box::new(AnalysisCtxXrefInfoBuildTool)),
        (AnalysisProgressTrackTool::definition(), Box::new(AnalysisProgressTrackTool)),
        (AnalysisCtxBuilderTool::definition(), Box::new(AnalysisCtxBuilderTool)),
        (AnalysisCacheKeyFromDataTool::definition(), Box::new(AnalysisCacheKeyFromDataTool)),
        (AnalysisCacheLruBasicsTool::definition(), Box::new(AnalysisCacheLruBasicsTool)),
        (AnalysisPassRegistryBuiltinTool::definition(), Box::new(AnalysisPassRegistryBuiltinTool)),
        (AnalysisTypeFactByteSizeTool::definition(), Box::new(AnalysisTypeFactByteSizeTool)),
        (AnalysisTypeFactIsKnownTool::definition(), Box::new(AnalysisTypeFactIsKnownTool)),
        (AnalysisTypeFactJoinTool::definition(), Box::new(AnalysisTypeFactJoinTool)),
        (AnalysisTypeFactDisplayNameTool::definition(), Box::new(AnalysisTypeFactDisplayNameTool)),
        (AnalysisTypeFactDisplayTool::definition(), Box::new(AnalysisTypeFactDisplayTool)),
        (AnalysisTypeWinapiAllSignaturesTool::definition(), Box::new(AnalysisTypeWinapiAllSignaturesTool)),
        (AnalysisTypeWinapiSignatureArityTool::definition(), Box::new(AnalysisTypeWinapiSignatureArityTool)),
        (AnalysisTypeWinapiSignatureParamTool::definition(), Box::new(AnalysisTypeWinapiSignatureParamTool)),
        (AnalysisTypeCallGraphTopoOrderTool::definition(), Box::new(AnalysisTypeCallGraphTopoOrderTool)),
        (AnalysisTypeEnvironmentMergeTool::definition(), Box::new(AnalysisTypeEnvironmentMergeTool)),
        (AnalysisTypeInferSignatureTool::definition(), Box::new(AnalysisTypeInferSignatureTool)),
        (AnalysisTypeSolveSimpleTool::definition(), Box::new(AnalysisTypeSolveSimpleTool)),
        (AnalysisFnDetectFunctionsPathTool::definition(), Box::new(AnalysisFnDetectFunctionsPathTool)),
        // Defined in `wire_tools` (their integration tests construct them by
        // path), registered here so they are reachable over MCP rather than
        // existing only for the tests.
        (crate::wire_tools::AnalysisBasicBlocksPathTool::definition(), Box::new(crate::wire_tools::AnalysisBasicBlocksPathTool)),
        (crate::wire_tools::AnalysisTraceDataFlowPathTool::definition(), Box::new(crate::wire_tools::AnalysisTraceDataFlowPathTool)),
        (AnalysisStringScanPathTool::definition(), Box::new(AnalysisStringScanPathTool)),
        (AnalysisCryptoScanPathTool::definition(), Box::new(AnalysisCryptoScanPathTool)),
        (AnalysisStringDetectXorKeyTool::definition(), Box::new(AnalysisStringDetectXorKeyTool)),
        (AnalysisStringExtractUrlsPathTool::definition(), Box::new(AnalysisStringExtractUrlsPathTool)),
        (AnalysisStringStatsPathTool::definition(), Box::new(AnalysisStringStatsPathTool)),
    ]
}
