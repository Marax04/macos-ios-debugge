//! MCP wrappers for the rustre-symbols_stabs crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct SymbolsStabsParseAllTool;

pub struct SymbolsStabsParseFromElfTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (SymbolsStabsParseAllTool::definition(), Box::new(SymbolsStabsParseAllTool)),
        (SymbolsStabsParseFromElfTool::definition(), Box::new(SymbolsStabsParseFromElfTool)),
    ]
}


impl SymbolsStabsParseAllTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "symbols_stabs_parse_all".to_string(),
            description: "Parse all STABS records from raw .stab and .stabstr bytes.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "stab_hex":    { "type": "string" },
                    "stabstr_hex": { "type": "string" }
                }
            }),
            parameters: serde_json::Value::Null,
        }
    }
}

#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for SymbolsStabsParseAllTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let stab = crate::wire_tools::extract_byte_array(&args, "stab", "stab_hex")?;
        let stabstr = crate::wire_tools::extract_byte_array(&args, "stabstr", "stabstr_hex").unwrap_or_default();
        let recs = rustre_symbols_stabs::StabRecord::parse_all(&stab, &stabstr);
        let entries: Vec<serde_json::Value> = recs.iter().map(|r| serde_json::json!({
            "strx":  r.strx,
            "type":  r.stab_type.name(),
            "other": r.other,
            "desc":  r.desc,
            "value": r.value,
            "string": r.string,
        })).collect();
        Ok(rustre_mcp_server::ToolResult::text(
            serde_json::json!({ "count": entries.len(), "entries": entries }).to_string(),
        ))
    }
}

impl SymbolsStabsParseFromElfTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "symbols_stabs_parse_from_elf".to_string(),
            description: "Locate .stab/.stabstr in an ELF and parse all STABS entries.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex":   { "type": "string" }
                }
            }),
            parameters: serde_json::Value::Null,
        }
    }
}

#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for SymbolsStabsParseFromElfTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let data = crate::args_to_bytes(&args)?;
        let entries = rustre_symbols_stabs::StabsLowParser::parse_from_elf(&data)
            .map_err(|e| rustre_mcp_server::McpError::InvalidParams(format!("parse_from_elf: {e}")))?;
        let out_v: Vec<serde_json::Value> = entries.iter().map(|e| serde_json::json!({
            "n_strx":    e.n_strx,
            "n_type":    e.n_type,
            "type_name": e.stabs_type().to_string(),
            "n_other":   e.n_other,
            "n_desc":    e.n_desc,
            "n_value":   e.n_value,
            "string_value": e.string_value,
        })).collect();
        Ok(rustre_mcp_server::ToolResult::text(
            serde_json::json!({ "count": out_v.len(), "entries": out_v }).to_string(),
        ))
    }
}

