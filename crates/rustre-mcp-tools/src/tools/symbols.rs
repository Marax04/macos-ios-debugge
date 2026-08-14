//! MCP wrappers for the rustre-symbols crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{parse_symbols_array_v2};

pub struct SymbolsDiscoverPdbForBinaryTool;

pub struct SymbolsBackendsRegistryTool;

pub struct SymbolsExporterToCsvTool;

pub struct SymbolsFunctionBoundaryOverlapsTool;

pub struct SymbolsSymbolSourcePriorityTool;

pub struct SymbolsDiscoverPdbV2Tool;

pub struct SymbolsBackendsRegistryV2Tool;

pub struct SymbolsTryDemangleTool;

pub struct SymbolsSymbolContainsTool;

pub struct SymbolsFunctionBoundarySizeTool;

pub struct SymbolsFunctionBoundaryContainsTool;

pub struct SymbolsTryDemangleV5Tool;
impl SymbolsTryDemangleV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_try_demangle_v5".to_string(), description: "Attempt auto demangle via rustre_symbols::try_demangle.".to_string(), input_schema: json!({ "type":"object", "properties": { "name": {"type":"string"} }, "required":["name"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsTryDemangleV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?; let r = rustre_symbols::try_demangle(name); Ok(ToolResult::text(json!({ "input": name, "demangled": r, "source": "rustre_symbols::try_demangle" }).to_string())) } }

pub struct SymbolsDemangleAutoV5Tool;
impl SymbolsDemangleAutoV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_demangle_auto_v5".to_string(), description: "Auto demangler via rustre_symbols::symbol_demangler::demangle_auto.".to_string(), input_schema: json!({ "type":"object", "properties": { "name": {"type":"string"} }, "required":["name"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsDemangleAutoV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?; let r = rustre_symbols::symbol_demangler::demangle_auto(name); Ok(ToolResult::text(json!({ "input": name, "demangled": r, "source": "rustre_symbols::symbol_demangler::demangle_auto" }).to_string())) } }

pub struct SymbolsDemangleItaniumV5Tool;
impl SymbolsDemangleItaniumV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_demangle_itanium_v5".to_string(), description: "Itanium demangler.".to_string(), input_schema: json!({ "type":"object", "properties": { "name": {"type":"string"} }, "required":["name"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsDemangleItaniumV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?; let r = rustre_symbols::symbol_demangler::demangle_itanium(name).ok(); Ok(ToolResult::text(json!({ "input": name, "ok": r.is_some(), "source": "rustre_symbols::symbol_demangler::demangle_itanium" }).to_string())) } }

pub struct SymbolsDemangleMsvcV5Tool;
impl SymbolsDemangleMsvcV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_demangle_msvc_v5".to_string(), description: "MSVC demangler.".to_string(), input_schema: json!({ "type":"object", "properties": { "name": {"type":"string"} }, "required":["name"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsDemangleMsvcV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?; let r = rustre_symbols::symbol_demangler::demangle_msvc(name).ok(); Ok(ToolResult::text(json!({ "input": name, "ok": r.is_some(), "source": "rustre_symbols::symbol_demangler::demangle_msvc" }).to_string())) } }

pub struct SymbolsDemangleRustV0V5Tool;
impl SymbolsDemangleRustV0V5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_demangle_rust_v0_v5".to_string(), description: "Rust v0 demangler.".to_string(), input_schema: json!({ "type":"object", "properties": { "name": {"type":"string"} }, "required":["name"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsDemangleRustV0V5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?; let r = rustre_symbols::symbol_demangler::demangle_rust_v0(name).ok(); Ok(ToolResult::text(json!({ "input": name, "ok": r.is_some(), "source": "rustre_symbols::symbol_demangler::demangle_rust_v0" }).to_string())) } }

pub struct SymbolsDemangleSwiftV5Tool;
impl SymbolsDemangleSwiftV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_demangle_swift_v5".to_string(), description: "Swift demangler.".to_string(), input_schema: json!({ "type":"object", "properties": { "name": {"type":"string"} }, "required":["name"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsDemangleSwiftV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?; let r = rustre_symbols::symbol_demangler::demangle_swift(name).ok(); Ok(ToolResult::text(json!({ "input": name, "ok": r.is_some(), "source": "rustre_symbols::symbol_demangler::demangle_swift" }).to_string())) } }

pub struct SymbolsFuzzyScoreV5Tool;
impl SymbolsFuzzyScoreV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_fuzzy_score_v5".to_string(), description: "Fuzzy score via rustre_symbols::symbol_search::fuzzy_score.".to_string(), input_schema: json!({ "type":"object", "properties": { "needle": {"type":"string"}, "haystack": {"type":"string"} }, "required":["needle","haystack"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsFuzzyScoreV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let needle = args.get("needle").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'needle'".into()))?; let haystack = args.get("haystack").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'haystack'".into()))?; let r = rustre_symbols::symbol_search::fuzzy_score(needle, haystack); Ok(ToolResult::text(json!({ "score": r.as_ref().map(|(s,_)| *s), "indices": r.map(|(_,i)| i), "source": "rustre_symbols::symbol_search::fuzzy_score" }).to_string())) } }

pub struct SymbolsWildcardMatchV5Tool;
impl SymbolsWildcardMatchV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_wildcard_match_v5".to_string(), description: "Wildcard match via rustre_symbols::symbol_search::wildcard_match.".to_string(), input_schema: json!({ "type":"object", "properties": { "pattern": {"type":"string"}, "text": {"type":"string"} }, "required":["pattern","text"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsWildcardMatchV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pattern = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?; let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?; let r = rustre_symbols::symbol_search::wildcard_match(pattern, text); Ok(ToolResult::text(json!({ "matches": r, "source": "rustre_symbols::symbol_search::wildcard_match" }).to_string())) } }

pub struct SymbolsCvParseSymV5Tool;
impl SymbolsCvParseSymV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_cv_parse_sym_v5".to_string(), description: "Parse CodeView SYM records.".to_string(), input_schema: json!({ "type":"object", "properties": { "hex": {"type":"string"} }, "required":["hex"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsCvParseSymV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let bytes: Vec<u8> = (0..hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(hex.get(i..i+2)?, 16).ok()).collect(); let recs = rustre_symbols::codeview_provider::parse_sym_records(&bytes); Ok(ToolResult::text(json!({ "count": recs.len(), "source": "rustre_symbols::codeview_provider::parse_sym_records" }).to_string())) } }

pub struct SymbolsCvParseTypeV5Tool;
impl SymbolsCvParseTypeV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_cv_parse_type_v5".to_string(), description: "Parse CodeView TYPE records.".to_string(), input_schema: json!({ "type":"object", "properties": { "hex": {"type":"string"} }, "required":["hex"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsCvParseTypeV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let bytes: Vec<u8> = (0..hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(hex.get(i..i+2)?, 16).ok()).collect(); let recs = rustre_symbols::codeview_provider::parse_type_records(&bytes); Ok(ToolResult::text(json!({ "count": recs.len(), "source": "rustre_symbols::codeview_provider::parse_type_records" }).to_string())) } }

pub struct SymbolsElfRel64V5Tool;
impl SymbolsElfRel64V5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_elf_rel64_v5".to_string(), description: "Parse ELF64 REL entries.".to_string(), input_schema: json!({ "type":"object", "properties": { "hex": {"type":"string"} }, "required":["hex"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsElfRel64V5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let bytes: Vec<u8> = (0..hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(hex.get(i..i+2)?, 16).ok()).collect(); let r = rustre_symbols::elf_provider::parse_rel64(&bytes); Ok(ToolResult::text(json!({ "count": r.len(), "source": "rustre_symbols::elf_provider::parse_rel64" }).to_string())) } }

pub struct SymbolsElfRela64V5Tool;
impl SymbolsElfRela64V5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "symbols_elf_rela64_v5".to_string(), description: "Parse ELF64 RELA entries.".to_string(), input_schema: json!({ "type":"object", "properties": { "hex": {"type":"string"} }, "required":["hex"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for SymbolsElfRela64V5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let bytes: Vec<u8> = (0..hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(hex.get(i..i+2)?, 16).ok()).collect(); let r = rustre_symbols::elf_provider::parse_rela64(&bytes); Ok(ToolResult::text(json!({ "count": r.len(), "source": "rustre_symbols::elf_provider::parse_rela64" }).to_string())) } }

pub struct SymbolsSyntheticFunctionNameTool;
impl SymbolsSyntheticFunctionNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_synthetic_function_name".to_string(),
            description: "Synthetic function name via rustre_symbols::SyntheticSymbolGen::function_name.".to_string(),
            input_schema: json!({"type":"object","properties":{"address":{"type":"integer"}},"required":["address"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbolsSyntheticFunctionNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("address required".into()))?;
        let name = rustre_symbols::SyntheticSymbolGen::function_name(addr);
        Ok(ToolResult::text(json!({"name":name}).to_string()))
    }
}

pub struct SymbolsSyntheticDataNameTool;
impl SymbolsSyntheticDataNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_synthetic_data_name".to_string(),
            description: "Synthetic data name via rustre_symbols::SyntheticSymbolGen::data_name.".to_string(),
            input_schema: json!({"type":"object","properties":{"address":{"type":"integer"}},"required":["address"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbolsSyntheticDataNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("address required".into()))?;
        let name = rustre_symbols::SyntheticSymbolGen::data_name(addr);
        Ok(ToolResult::text(json!({"name":name}).to_string()))
    }
}

pub struct SymbolsSyntheticLabelNameTool;
impl SymbolsSyntheticLabelNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_synthetic_label_name".to_string(),
            description: "Synthetic label name via rustre_symbols::SyntheticSymbolGen::label_name.".to_string(),
            input_schema: json!({"type":"object","properties":{"address":{"type":"integer"}},"required":["address"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbolsSyntheticLabelNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("address required".into()))?;
        let name = rustre_symbols::SyntheticSymbolGen::label_name(addr);
        Ok(ToolResult::text(json!({"name":name}).to_string()))
    }
}

pub struct SymbolsSyntheticDwordNameTool;
impl SymbolsSyntheticDwordNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_synthetic_dword_name".to_string(),
            description: "Synthetic dword name via rustre_symbols::SyntheticSymbolGen::dword_name.".to_string(),
            input_schema: json!({"type":"object","properties":{"address":{"type":"integer"}},"required":["address"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbolsSyntheticDwordNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("address required".into()))?;
        let name = rustre_symbols::SyntheticSymbolGen::dword_name(addr);
        Ok(ToolResult::text(json!({"name":name}).to_string()))
    }
}

pub struct SymbolsSyntheticQwordNameTool;
impl SymbolsSyntheticQwordNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_synthetic_qword_name".to_string(),
            description: "Synthetic qword name via rustre_symbols::SyntheticSymbolGen::qword_name.".to_string(),
            input_schema: json!({"type":"object","properties":{"address":{"type":"integer"}},"required":["address"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbolsSyntheticQwordNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("address required".into()))?;
        let name = rustre_symbols::SyntheticSymbolGen::qword_name(addr);
        Ok(ToolResult::text(json!({"name":name}).to_string()))
    }
}

pub struct SymbolsExporterToIdcTool;
impl SymbolsExporterToIdcTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_exporter_to_idc".to_string(),
            description: "Export symbols as IDA .idc via rustre_symbols::SymbolExporter::to_idc.".to_string(),
            input_schema: json!({"type":"object","properties":{"symbols":{"type":"array"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbolsExporterToIdcTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let syms = parse_symbols_array_v2(&args);
        let idc = rustre_symbols::SymbolExporter::to_idc(&syms);
        Ok(ToolResult::text(json!({"idc":idc,"count":syms.len()}).to_string()))
    }
}

pub struct SymbolsExporterToMapTool;
impl SymbolsExporterToMapTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_exporter_to_map".to_string(),
            description: "Export symbols as linker .map via rustre_symbols::SymbolExporter::to_map.".to_string(),
            input_schema: json!({"type":"object","properties":{"symbols":{"type":"array"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbolsExporterToMapTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let syms = parse_symbols_array_v2(&args);
        let map = rustre_symbols::SymbolExporter::to_map(&syms);
        Ok(ToolResult::text(json!({"map":map,"count":syms.len()}).to_string()))
    }
}

pub struct SymbolsExporterToJsonTool;
impl SymbolsExporterToJsonTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_exporter_to_json".to_string(),
            description: "Export symbols as JSON via rustre_symbols::SymbolExporter::to_json.".to_string(),
            input_schema: json!({"type":"object","properties":{"symbols":{"type":"array"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbolsExporterToJsonTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let syms = parse_symbols_array_v2(&args);
        let s = rustre_symbols::SymbolExporter::to_json(&syms).map_err(|e| McpError::InternalError(format!("{e:?}")))?;
        Ok(ToolResult::text(json!({"json":s,"count":syms.len()}).to_string()))
    }
}

pub struct SymbolsTryDemangleTopTool;
impl SymbolsTryDemangleTopTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_try_demangle_top".to_string(),
            description: "Demangle via rustre_symbols::try_demangle (Itanium/Rust/MSVC).".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbolsTryDemangleTopTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name required".into()))?;
        let out = rustre_symbols::try_demangle(n);
        Ok(ToolResult::text(json!({"input":n,"demangled":out}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (SymbolsDiscoverPdbForBinaryTool::definition(), Box::new(SymbolsDiscoverPdbForBinaryTool)),
        (SymbolsBackendsRegistryTool::definition(), Box::new(SymbolsBackendsRegistryTool)),
        (SymbolsExporterToCsvTool::definition(), Box::new(SymbolsExporterToCsvTool)),
        (SymbolsFunctionBoundaryOverlapsTool::definition(), Box::new(SymbolsFunctionBoundaryOverlapsTool)),
        (SymbolsSymbolSourcePriorityTool::definition(), Box::new(SymbolsSymbolSourcePriorityTool)),
        (SymbolsDiscoverPdbV2Tool::definition(), Box::new(SymbolsDiscoverPdbV2Tool)),
        (SymbolsBackendsRegistryV2Tool::definition(), Box::new(SymbolsBackendsRegistryV2Tool)),
        (SymbolsTryDemangleTool::definition(), Box::new(SymbolsTryDemangleTool)),
        (SymbolsSymbolContainsTool::definition(), Box::new(SymbolsSymbolContainsTool)),
        (SymbolsFunctionBoundarySizeTool::definition(), Box::new(SymbolsFunctionBoundarySizeTool)),
        (SymbolsFunctionBoundaryContainsTool::definition(), Box::new(SymbolsFunctionBoundaryContainsTool)),
        (SymbolsTryDemangleV5Tool::definition(), Box::new(SymbolsTryDemangleV5Tool)),
        (SymbolsDemangleAutoV5Tool::definition(), Box::new(SymbolsDemangleAutoV5Tool)),
        (SymbolsDemangleItaniumV5Tool::definition(), Box::new(SymbolsDemangleItaniumV5Tool)),
        (SymbolsDemangleMsvcV5Tool::definition(), Box::new(SymbolsDemangleMsvcV5Tool)),
        (SymbolsDemangleRustV0V5Tool::definition(), Box::new(SymbolsDemangleRustV0V5Tool)),
        (SymbolsDemangleSwiftV5Tool::definition(), Box::new(SymbolsDemangleSwiftV5Tool)),
        (SymbolsFuzzyScoreV5Tool::definition(), Box::new(SymbolsFuzzyScoreV5Tool)),
        (SymbolsWildcardMatchV5Tool::definition(), Box::new(SymbolsWildcardMatchV5Tool)),
        (SymbolsCvParseSymV5Tool::definition(), Box::new(SymbolsCvParseSymV5Tool)),
        (SymbolsCvParseTypeV5Tool::definition(), Box::new(SymbolsCvParseTypeV5Tool)),
        (SymbolsElfRel64V5Tool::definition(), Box::new(SymbolsElfRel64V5Tool)),
        (SymbolsElfRela64V5Tool::definition(), Box::new(SymbolsElfRela64V5Tool)),
        (SymbolsSyntheticFunctionNameTool::definition(), Box::new(SymbolsSyntheticFunctionNameTool)),
        (SymbolsSyntheticDataNameTool::definition(), Box::new(SymbolsSyntheticDataNameTool)),
        (SymbolsSyntheticLabelNameTool::definition(), Box::new(SymbolsSyntheticLabelNameTool)),
        (SymbolsSyntheticDwordNameTool::definition(), Box::new(SymbolsSyntheticDwordNameTool)),
        (SymbolsSyntheticQwordNameTool::definition(), Box::new(SymbolsSyntheticQwordNameTool)),
        (SymbolsExporterToIdcTool::definition(), Box::new(SymbolsExporterToIdcTool)),
        (SymbolsExporterToMapTool::definition(), Box::new(SymbolsExporterToMapTool)),
        (SymbolsExporterToJsonTool::definition(), Box::new(SymbolsExporterToJsonTool)),
        (SymbolsTryDemangleTopTool::definition(), Box::new(SymbolsTryDemangleTopTool)),
    ]
}
