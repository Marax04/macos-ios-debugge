//! MCP wrappers for the rustre-dwarf crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{dwarf_hex_decode};

pub struct DwarfFunctionsPathTool;

pub struct DwarfTypesPathTool;

pub struct DwarfLineInfoPathTool;

pub struct DwarfFunctionsCountPathTool;

pub struct DwarfTypesCountPathTool;

pub struct DwarfGimliFunctionsPathTool;

pub struct DwarfGimliTypesPathTool;

pub struct DwarfGimliLineInfoPathTool;

pub struct DwarfVariablesPathTool;

pub struct DwarfSymbolSetSummaryPathTool;

pub struct DwarfUnwinderAtPathTool;

pub struct DwarfAbbrevReadUleb128Tool;
impl DwarfAbbrevReadUleb128Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dwarf_abbrev_read_uleb128".to_string(),
            description: "Decode ULEB128 via rustre_symbols_dwarf::dwarf_abbrev::read_uleb128 from hex bytes starting at pos.".to_string(),
            input_schema: json!({"type":"object","properties":{"hex":{"type":"string"},"pos":{"type":"integer"}},"required":["hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DwarfAbbrevReadUleb128Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?;
        let mut pos = args.get("pos").and_then(Value::as_u64).unwrap_or(0) as usize;
        let data = dwarf_hex_decode(hex)?;
        let val = rustre_symbols_dwarf::dwarf_abbrev::read_uleb128(&data, &mut pos);
        Ok(ToolResult::text(json!({"value": val, "pos_after": pos, "source":"rustre_symbols_dwarf::dwarf_abbrev::read_uleb128"}).to_string()))
    }
}

pub struct DwarfAbbrevReadSleb128Tool;
impl DwarfAbbrevReadSleb128Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dwarf_abbrev_read_sleb128".to_string(),
            description: "Decode SLEB128 via rustre_symbols_dwarf::dwarf_abbrev::read_sleb128 from hex bytes starting at pos.".to_string(),
            input_schema: json!({"type":"object","properties":{"hex":{"type":"string"},"pos":{"type":"integer"}},"required":["hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DwarfAbbrevReadSleb128Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?;
        let mut pos = args.get("pos").and_then(Value::as_u64).unwrap_or(0) as usize;
        let data = dwarf_hex_decode(hex)?;
        let val = rustre_symbols_dwarf::dwarf_abbrev::read_sleb128(&data, &mut pos);
        Ok(ToolResult::text(json!({"value": val, "pos_after": pos, "source":"rustre_symbols_dwarf::dwarf_abbrev::read_sleb128"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DwarfFunctionsPathTool::definition(), Box::new(DwarfFunctionsPathTool)),
        (DwarfTypesPathTool::definition(), Box::new(DwarfTypesPathTool)),
        (DwarfLineInfoPathTool::definition(), Box::new(DwarfLineInfoPathTool)),
        (DwarfFunctionsCountPathTool::definition(), Box::new(DwarfFunctionsCountPathTool)),
        (DwarfTypesCountPathTool::definition(), Box::new(DwarfTypesCountPathTool)),
        (DwarfGimliFunctionsPathTool::definition(), Box::new(DwarfGimliFunctionsPathTool)),
        (DwarfGimliTypesPathTool::definition(), Box::new(DwarfGimliTypesPathTool)),
        (DwarfGimliLineInfoPathTool::definition(), Box::new(DwarfGimliLineInfoPathTool)),
        (DwarfVariablesPathTool::definition(), Box::new(DwarfVariablesPathTool)),
        (DwarfSymbolSetSummaryPathTool::definition(), Box::new(DwarfSymbolSetSummaryPathTool)),
        (DwarfUnwinderAtPathTool::definition(), Box::new(DwarfUnwinderAtPathTool)),
        (DwarfAbbrevReadUleb128Tool::definition(), Box::new(DwarfAbbrevReadUleb128Tool)),
        (DwarfAbbrevReadSleb128Tool::definition(), Box::new(DwarfAbbrevReadSleb128Tool)),
    ]
}


impl DwarfGimliFunctionsPathTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "dwarf_gimli_functions_path".to_string(),
            description: "Parse DWARF via gimli and return functions.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }),
            parameters: serde_json::Value::Null,
        }
    }
}

#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for DwarfGimliFunctionsPathTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let path = args.get("path").and_then(serde_json::Value::as_str)
            .ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing path".into()))?;
        let set = rustre_symbols_dwarf::load_dwarf_symbols(std::path::Path::new(path))
            .map_err(|e| rustre_mcp_server::McpError::InternalError(format!("gimli load failed: {e}")))?;
        let payload = serde_json::to_value(&set.functions)
            .map_err(|e| rustre_mcp_server::McpError::InternalError(format!("serialize failed: {e}")))?;
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({ "count": set.functions.len(), "functions": payload }).to_string()))
    }
}

impl DwarfGimliTypesPathTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "dwarf_gimli_types_path".to_string(),
            description: "Parse DWARF via gimli and return type definitions.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }),
            parameters: serde_json::Value::Null,
        }
    }
}

#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for DwarfGimliTypesPathTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let path = args.get("path").and_then(serde_json::Value::as_str)
            .ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing path".into()))?;
        let set = rustre_symbols_dwarf::load_dwarf_symbols(std::path::Path::new(path))
            .map_err(|e| rustre_mcp_server::McpError::InternalError(format!("gimli load failed: {e}")))?;
        let payload = serde_json::to_value(&set.types)
            .map_err(|e| rustre_mcp_server::McpError::InternalError(format!("serialize failed: {e}")))?;
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({ "count": set.types.len(), "types": payload }).to_string()))
    }
}

impl DwarfGimliLineInfoPathTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "dwarf_gimli_line_info_path".to_string(),
            description: "Parse DWARF .debug_line via gimli and return the line-info table.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }),
            parameters: serde_json::Value::Null,
        }
    }
}

#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for DwarfGimliLineInfoPathTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let path = args.get("path").and_then(serde_json::Value::as_str)
            .ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing path".into()))?;
        let set = rustre_symbols_dwarf::load_dwarf_symbols(std::path::Path::new(path))
            .map_err(|e| rustre_mcp_server::McpError::InternalError(format!("gimli load failed: {e}")))?;
        let payload = serde_json::to_value(&set.line_info)
            .map_err(|e| rustre_mcp_server::McpError::InternalError(format!("serialize failed: {e}")))?;
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({ "line_info": payload }).to_string()))
    }
}

