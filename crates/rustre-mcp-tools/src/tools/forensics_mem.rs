//! MCP wrappers for the rustre-forensics_mem crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes};

pub struct ForensicsMemScanPeHeadersTool;
impl ForensicsMemScanPeHeadersTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_mem_scan_pe_headers".to_string(),
            description: "Scan bytes for embedded PE headers (MZ + e_lfanew + PE00). Returns absolute VAs.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex":   { "type": "string" },
                    "base":  { "type": "integer" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ForensicsMemScanPeHeadersTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let base = args.get("base").and_then(Value::as_u64).unwrap_or(0);
        let hits = rustre_forensics_mem::MemoryForensicsScanner::scan_pe_headers(&data, base);
        Ok(ToolResult::text(json!({
            "count": hits.len(),
            "hits": hits,
            "base": base,
        }).to_string()))
    }
}

pub struct ForensicsMemScanStackCanariesTool;
impl ForensicsMemScanStackCanariesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_mem_scan_stack_canaries".to_string(),
            description: "Scan bytes for known canary DWORDs (DEADBEEF, ABABABAB, FEEEFEEE, CDCDCDCD, BAADF00D).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex":   { "type": "string" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ForensicsMemScanStackCanariesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let hits = rustre_forensics_mem::MemoryForensicsScanner::scan_stack_canaries(&data);
        Ok(ToolResult::text(json!({
            "count": hits.len(),
            "offsets": hits,
        }).to_string()))
    }
}

pub struct ForensicsMemFindUnicodeStringsTool;
impl ForensicsMemFindUnicodeStringsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_mem_find_unicode_strings".to_string(),
            description: "Extract UTF-16LE printable strings (>= min_len chars) from bytes.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bytes":   { "type": "array", "items": { "type": "integer" } },
                    "hex":     { "type": "string" },
                    "min_len": { "type": "integer" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ForensicsMemFindUnicodeStringsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let min_len = args
            .get("min_len")
            .and_then(Value::as_u64)
            .map(|n| n as usize)
            .unwrap_or(4);
        let results = rustre_forensics_mem::MemoryForensicsScanner::find_unicode_strings(&data, min_len);
        let arr: Vec<Value> = results
            .into_iter()
            .map(|(a, s)| json!({ "offset": a, "string": s }))
            .collect();
        Ok(ToolResult::text(json!({
            "count": arr.len(),
            "strings": arr,
        }).to_string()))
    }
}

pub struct ForensicsMemThreadStateFromU8Tool;

pub struct ForensicsMemConnectionStateFromU8Tool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ForensicsMemScanPeHeadersTool::definition(), Box::new(ForensicsMemScanPeHeadersTool)),
        (ForensicsMemScanStackCanariesTool::definition(), Box::new(ForensicsMemScanStackCanariesTool)),
        (ForensicsMemFindUnicodeStringsTool::definition(), Box::new(ForensicsMemFindUnicodeStringsTool)),
        (ForensicsMemThreadStateFromU8Tool::definition(), Box::new(ForensicsMemThreadStateFromU8Tool)),
        (ForensicsMemConnectionStateFromU8Tool::definition(), Box::new(ForensicsMemConnectionStateFromU8Tool)),
    ]
}
