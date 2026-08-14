//! MCP wrappers for the rustre-symbols_pdb crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes};

pub struct SymbolsPdbParseInfoTool;

pub struct SymbolsPdbFromBytesTool;

pub struct SymbolsPdbSymbolsListTool;

pub struct SymbolsPdbSymbolsCountByKindTool;

pub struct SymbolsPdbModuleProcSymbolsTool;

pub struct SymbolsPdbSymbolsWithSegmentTool;

pub struct SymbolsPdbGuidFormatTool;
impl SymbolsPdbGuidFormatTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_pdb_guid_format".to_string(), description: "Format 16 raw GUID bytes via PdbGuid::to_string_fmt.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsPdbGuidFormatTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let data = args_to_bytes(&args)?;
    if data.len() < 16 { return Ok(ToolResult::text(json!({"ok":false,"error":"need at least 16 bytes"}).to_string())); }
    let mut g = [0u8; 16]; g.copy_from_slice(&data[..16]);
    let guid = rustre_symbols_pdb::PdbGuid { data: g };
    Ok(ToolResult::text(json!({"ok":true,"guid":guid.to_string_fmt(),"source":"rustre_symbols_pdb::PdbGuid::to_string_fmt"}).to_string()))
} }

pub struct SymbolsPdbReaderTypesTool;
impl SymbolsPdbReaderTypesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_pdb_reader_types".to_string(), description: "Parse a PDB and return TPI type names (PdbReader::types).".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsPdbReaderTypesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let data = args_to_bytes(&args)?;
    match rustre_symbols_pdb::PdbReader::from_bytes(&data) {
        Ok(r) => { let ts = r.types(); let names: Vec<String> = ts.iter().take(256).map(|t| t.name.clone()).collect(); Ok(ToolResult::text(json!({"ok":true,"count":ts.len(),"names_sample":names,"source":"rustre_symbols_pdb::PdbReader::types"}).to_string())) }
        Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
    }
} }

pub struct SymbolsPdbReaderModulesTool;
impl SymbolsPdbReaderModulesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_pdb_reader_modules".to_string(), description: "List DBI-stream modules (PdbReader::modules).".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsPdbReaderModulesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let data = args_to_bytes(&args)?;
    match rustre_symbols_pdb::PdbReader::from_bytes(&data) {
        Ok(r) => { let ms = r.modules(); let items: Vec<Value> = ms.iter().take(256).map(|m| json!({"name":m.name,"object_file":m.object_file,"stream_index":m.stream_index})).collect(); Ok(ToolResult::text(json!({"ok":true,"count":ms.len(),"modules":items,"source":"rustre_symbols_pdb::PdbReader::modules"}).to_string())) }
        Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
    }
} }

pub struct SymbolsPdbReaderGuidTool;
impl SymbolsPdbReaderGuidTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_pdb_reader_guid".to_string(), description: "Return PDB GUID and Age via PdbReader::guid/age.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsPdbReaderGuidTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let data = args_to_bytes(&args)?;
    match rustre_symbols_pdb::PdbReader::from_bytes(&data) {
        Ok(r) => Ok(ToolResult::text(json!({"ok":true,"guid":r.guid().to_string_fmt(),"age":r.age().0,"source":"rustre_symbols_pdb::PdbReader::guid"}).to_string())),
        Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
    }
} }

pub struct SymbolsPdbPublicScanTool;
impl SymbolsPdbPublicScanTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_pdb_public_scan".to_string(), description: "Scan PDB publics via PdbPublicSymbolScanner::scan_public_symbols.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsPdbPublicScanTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let data = args_to_bytes(&args)?;
    let syms = rustre_symbols_pdb::PdbPublicSymbolScanner::scan_public_symbols(&data);
    let sample: Vec<Value> = syms.iter().take(64).map(|s| json!({"name":s.name,"offset":s.offset,"section":s.section})).collect();
    Ok(ToolResult::text(json!({"ok":true,"count":syms.len(),"sample":sample,"source":"rustre_symbols_pdb::PdbPublicSymbolScanner::scan_public_symbols"}).to_string()))
} }

pub struct SymbolsPdbStreamNamesTool;
impl SymbolsPdbStreamNamesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_pdb_stream_names".to_string(), description: "Parse PDB named-stream directory (PdbStreamReader::parse_stream_names).".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsPdbStreamNamesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let data = args_to_bytes(&args)?;
    let m = rustre_symbols_pdb::PdbStreamReader::parse_stream_names(&data);
    let names: Vec<Value> = m.iter().map(|(k, v)| json!({"name":k,"stream":v})).collect();
    Ok(ToolResult::text(json!({"ok":true,"count":names.len(),"entries":names,"source":"rustre_symbols_pdb::PdbStreamReader::parse_stream_names"}).to_string()))
} }

pub struct SymbolsPdbReaderSymbolsCountTool;
impl SymbolsPdbReaderSymbolsCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_pdb_reader_symbols_count".to_string(), description: "Count symbols via PdbReader::symbols.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsPdbReaderSymbolsCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let data = args_to_bytes(&args)?;
    match rustre_symbols_pdb::PdbReader::from_bytes(&data) {
        Ok(r) => Ok(ToolResult::text(json!({"ok":true,"count":r.symbols().len(),"source":"rustre_symbols_pdb::PdbReader::symbols"}).to_string())),
        Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
    }
} }

pub struct SymbolsPdbTypesByKindTool;
impl SymbolsPdbTypesByKindTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_pdb_types_by_kind".to_string(), description: "Group TPI types by kind.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsPdbTypesByKindTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let data = args_to_bytes(&args)?;
    match rustre_symbols_pdb::PdbReader::from_bytes(&data) {
        Ok(r) => {
            use rustre_symbols_pdb::TypeKind;
            let (mut s, mut u, mut e, mut p, mut ptr, mut a, mut f) = (0u64,0u64,0u64,0u64,0u64,0u64,0u64);
            for t in r.types() { match t.kind {
                TypeKind::Struct { .. } => s += 1,
                TypeKind::Union { .. } => u += 1,
                TypeKind::Enum { .. } => e += 1,
                TypeKind::Primitive => p += 1,
                TypeKind::Pointer => ptr += 1,
                TypeKind::Array => a += 1,
                TypeKind::Function => f += 1,
            } }
            Ok(ToolResult::text(json!({"ok":true,"struct":s,"union":u,"enum":e,"primitive":p,"pointer":ptr,"array":a,"function":f,"source":"rustre_symbols_pdb::PdbReader::types"}).to_string()))
        }
        Err(err) => Ok(ToolResult::text(json!({"ok":false,"error":err.to_string()}).to_string())),
    }
} }

pub struct SymbolsPdbModuleProcCountTool;
impl SymbolsPdbModuleProcCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_pdb_module_proc_count".to_string(), description: "Count per-module procedure symbols (PdbReader::module_proc_symbols).".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsPdbModuleProcCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let data = args_to_bytes(&args)?;
    match rustre_symbols_pdb::PdbReader::from_bytes(&data) {
        Ok(r) => { let ps = r.module_proc_symbols(); let total_size: u64 = ps.iter().map(|p| u64::from(p.code_size)).sum(); Ok(ToolResult::text(json!({"ok":true,"count":ps.len(),"total_code_size":total_size,"source":"rustre_symbols_pdb::PdbReader::module_proc_symbols"}).to_string())) }
        Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
    }
} }

pub struct SymbolsPdbSymbolsFilterFunctionsTool;
impl SymbolsPdbSymbolsFilterFunctionsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_pdb_symbols_filter_functions".to_string(), description: "Return PdbReader::symbols filtered to SymbolKind::Function.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsPdbSymbolsFilterFunctionsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let data = args_to_bytes(&args)?;
    match rustre_symbols_pdb::PdbReader::from_bytes(&data) {
        Ok(r) => {
            use rustre_symbols_pdb::SymbolKind;
            let fns: Vec<Value> = r.symbols().into_iter().filter(|s| s.kind == SymbolKind::Function).take(256).map(|s| json!({"name":s.name,"address":s.address,"size":s.size})).collect();
            Ok(ToolResult::text(json!({"ok":true,"count":fns.len(),"sample":fns,"source":"rustre_symbols_pdb::PdbReader::symbols"}).to_string()))
        }
        Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
    }
} }

pub struct SymbolsPdbStreamInfoSignatureTool;
impl SymbolsPdbStreamInfoSignatureTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_pdb_stream_info_signature".to_string(), description: "Return version/signature/age from PdbStreamReader::parse_pdb_info.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsPdbStreamInfoSignatureTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let data = args_to_bytes(&args)?;
    match rustre_symbols_pdb::PdbStreamReader::parse_pdb_info(&data) {
        Some(info) => Ok(ToolResult::text(json!({"ok":true,"version":info.version,"signature":info.signature,"age":info.age,"source":"rustre_symbols_pdb::PdbStreamReader::parse_pdb_info"}).to_string())),
        None => Ok(ToolResult::text(json!({"ok":false,"error":"invalid PDB or too short"}).to_string())),
    }
} }

pub struct SymbolsPdbSymbolServerUrlTool;
impl SymbolsPdbSymbolServerUrlTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_pdb_symbol_server_url".to_string(),
            description: "Build Microsoft Symbol Server PDB URL via rustre_symbols::PdbSymbolServer::pdb_url.".to_string(),
            input_schema: json!({"type":"object","properties":{"base_url":{"type":"string"},"pdb_name":{"type":"string"},"guid":{"type":"string"},"age":{"type":"integer"}},"required":["pdb_name","guid","age"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbolsPdbSymbolServerUrlTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_url").and_then(Value::as_str).unwrap_or("https://msdl.microsoft.com/download/symbols");
        let pdb = args.get("pdb_name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("pdb_name required".into()))?;
        let guid = args.get("guid").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("guid required".into()))?;
        let age = args.get("age").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("age required".into()))? as u32;
        let srv = rustre_symbols::PdbSymbolServer::new(base);
        let url = srv.pdb_url(pdb, guid, age);
        Ok(ToolResult::text(json!({"url":url}).to_string()))
    }
}

pub struct SymbolsPdbSymbolServerMsdlTool;
impl SymbolsPdbSymbolServerMsdlTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_pdb_symbol_server_msdl".to_string(),
            description: "Return default MSDL server via rustre_symbols::PdbSymbolServer::msdl.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbolsPdbSymbolServerMsdlTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let srv = rustre_symbols::PdbSymbolServer::msdl();
        Ok(ToolResult::text(json!({"base_url":srv.base_url}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (SymbolsPdbParseInfoTool::definition(), Box::new(SymbolsPdbParseInfoTool)),
        (SymbolsPdbFromBytesTool::definition(), Box::new(SymbolsPdbFromBytesTool)),
        (SymbolsPdbSymbolsListTool::definition(), Box::new(SymbolsPdbSymbolsListTool)),
        (SymbolsPdbSymbolsCountByKindTool::definition(), Box::new(SymbolsPdbSymbolsCountByKindTool)),
        (SymbolsPdbModuleProcSymbolsTool::definition(), Box::new(SymbolsPdbModuleProcSymbolsTool)),
        (SymbolsPdbSymbolsWithSegmentTool::definition(), Box::new(SymbolsPdbSymbolsWithSegmentTool)),
        (SymbolsPdbGuidFormatTool::definition(), Box::new(SymbolsPdbGuidFormatTool)),
        (SymbolsPdbReaderTypesTool::definition(), Box::new(SymbolsPdbReaderTypesTool)),
        (SymbolsPdbReaderModulesTool::definition(), Box::new(SymbolsPdbReaderModulesTool)),
        (SymbolsPdbReaderGuidTool::definition(), Box::new(SymbolsPdbReaderGuidTool)),
        (SymbolsPdbPublicScanTool::definition(), Box::new(SymbolsPdbPublicScanTool)),
        (SymbolsPdbStreamNamesTool::definition(), Box::new(SymbolsPdbStreamNamesTool)),
        (SymbolsPdbReaderSymbolsCountTool::definition(), Box::new(SymbolsPdbReaderSymbolsCountTool)),
        (SymbolsPdbTypesByKindTool::definition(), Box::new(SymbolsPdbTypesByKindTool)),
        (SymbolsPdbModuleProcCountTool::definition(), Box::new(SymbolsPdbModuleProcCountTool)),
        (SymbolsPdbSymbolsFilterFunctionsTool::definition(), Box::new(SymbolsPdbSymbolsFilterFunctionsTool)),
        (SymbolsPdbStreamInfoSignatureTool::definition(), Box::new(SymbolsPdbStreamInfoSignatureTool)),
        (SymbolsPdbSymbolServerUrlTool::definition(), Box::new(SymbolsPdbSymbolServerUrlTool)),
        (SymbolsPdbSymbolServerMsdlTool::definition(), Box::new(SymbolsPdbSymbolServerMsdlTool)),
    ]
}
