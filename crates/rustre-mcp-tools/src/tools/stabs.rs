//! MCP wrappers for the rustre-stabs crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{extract_byte_array, stabs_parse_type_byte};

pub struct StabsTypeNameForTool;

pub struct StabsTypeCodeFromCharTool;

pub struct StabsIsSymbolTool;

pub struct StabsCategoryTool;

pub struct StabsIsSourceFileTool;

pub struct StabsIsLineNumberTool;

pub struct StabsTypeIsSymbolTool;
impl StabsTypeIsSymbolTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_stabs_type_is_symbol".to_string(),
            description: "StabType::from_u8(byte).is_symbol() true for NFun/NGsym/NStsym/NRsym/NPsym.".to_string(),
            input_schema: json!({"type":"object","properties":{"byte":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for StabsTypeIsSymbolTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let b = stabs_parse_type_byte(&args);
        let t = rustre_symbols_stabs::StabType::from_u8(b);
        Ok(ToolResult::text(json!({
            "byte": b, "type": t.name(), "is_symbol": t.is_symbol(),
            "source": "rustre_symbols_stabs::StabType::is_symbol"
        }).to_string()))
    }
}

pub struct StabsTypeIsSourceFileTool;
impl StabsTypeIsSourceFileTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_stabs_type_is_source_file".to_string(),
            description: "StabType::from_u8(byte).is_source_file().".to_string(),
            input_schema: json!({"type":"object","properties":{"byte":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for StabsTypeIsSourceFileTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let b = stabs_parse_type_byte(&args);
        let t = rustre_symbols_stabs::StabType::from_u8(b);
        Ok(ToolResult::text(json!({
            "byte": b, "type": t.name(), "is_source_file": t.is_source_file(),
            "source": "rustre_symbols_stabs::StabType::is_source_file"
        }).to_string()))
    }
}

pub struct StabsTypeIsLineNumberTool;
impl StabsTypeIsLineNumberTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_stabs_type_is_line_number".to_string(),
            description: "StabType::from_u8(byte).is_line_number().".to_string(),
            input_schema: json!({"type":"object","properties":{"byte":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for StabsTypeIsLineNumberTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let b = stabs_parse_type_byte(&args);
        let t = rustre_symbols_stabs::StabType::from_u8(b);
        Ok(ToolResult::text(json!({
            "byte": b, "type": t.name(), "is_line_number": t.is_line_number(),
            "source": "rustre_symbols_stabs::StabType::is_line_number"
        }).to_string()))
    }
}

pub struct StabsTypeIsScopeBracketTool;
impl StabsTypeIsScopeBracketTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_stabs_type_is_scope_bracket".to_string(),
            description: "StabType::from_u8(byte).is_scope_bracket() NLbrac/NRbrac.".to_string(),
            input_schema: json!({"type":"object","properties":{"byte":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for StabsTypeIsScopeBracketTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let b = stabs_parse_type_byte(&args);
        let t = rustre_symbols_stabs::StabType::from_u8(b);
        Ok(ToolResult::text(json!({
            "byte": b, "type": t.name(), "is_scope_bracket": t.is_scope_bracket(),
            "source": "rustre_symbols_stabs::StabType::is_scope_bracket"
        }).to_string()))
    }
}

pub struct StabsTypeCategoryTool;
impl StabsTypeCategoryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_stabs_type_category".to_string(),
            description: "StabType::from_u8(byte).category() symbol/file/line/scope/other.".to_string(),
            input_schema: json!({"type":"object","properties":{"byte":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for StabsTypeCategoryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let b = stabs_parse_type_byte(&args);
        let t = rustre_symbols_stabs::StabType::from_u8(b);
        Ok(ToolResult::text(json!({
            "byte": b, "type": t.name(), "category": t.category(),
            "source": "rustre_symbols_stabs::StabType::category"
        }).to_string()))
    }
}

pub struct StabsRecordParseAllBeTool;
impl StabsRecordParseAllBeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_stabs_record_parse_all_be".to_string(),
            description: "Big-endian variant of StabRecord::parse_all (rustre_symbols_stabs::StabRecord::parse_all_be).".to_string(),
            input_schema: json!({"type":"object","properties":{"stab_hex":{"type":"string"},"stabstr_hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for StabsRecordParseAllBeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let stab = extract_byte_array(&args, "stab", "stab_hex")?;
        let stabstr = extract_byte_array(&args, "stabstr", "stabstr_hex").unwrap_or_default();
        let recs = rustre_symbols_stabs::StabRecord::parse_all_be(&stab, &stabstr);
        let entries: Vec<Value> = recs.iter().map(|r| json!({
            "strx": r.strx, "type": r.stab_type.name(), "other": r.other,
            "desc": r.desc, "value": r.value, "string": r.string,
        })).collect();
        Ok(ToolResult::text(json!({
            "count": entries.len(), "entries": entries,
            "source": "rustre_symbols_stabs::StabRecord::parse_all_be"
        }).to_string()))
    }
}

pub struct StabsTypeCodeFromCharV2Tool;
impl StabsTypeCodeFromCharV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_stabs_type_code_from_char_v2".to_string(),
            description: "StabTypeCode::from_char(c) decode STABS descriptor code letter.".to_string(),
            input_schema: json!({"type":"object","properties":{"c":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for StabsTypeCodeFromCharV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("c").and_then(Value::as_str).unwrap_or("");
        let c = s.chars().next().unwrap_or(' ');
        let tc = rustre_symbols_stabs::StabTypeCode::from_char(c);
        Ok(ToolResult::text(json!({
            "input": c.to_string(), "code": tc.to_string(),
            "source": "rustre_symbols_stabs::StabTypeCode::from_char"
        }).to_string()))
    }
}

pub struct StabsStringTableRoundtripTool;
impl StabsStringTableRoundtripTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_stabs_string_table_roundtrip".to_string(),
            description: "Intern strings into StabsStringTable and verify get() roundtrip.".to_string(),
            input_schema: json!({"type":"object","properties":{"strings":{"type":"array","items":{"type":"string"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for StabsStringTableRoundtripTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let list: Vec<String> = args.get("strings").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let mut tbl = rustre_symbols_stabs::StabsStringTable::new();
        let mut entries = Vec::new();
        for s in &list {
            let off = tbl.intern(s);
            let back = tbl.get(off).to_string();
            entries.push(json!({"input": s, "offset": off, "roundtrip": back}));
        }
        Ok(ToolResult::text(json!({
            "count": entries.len(), "entries": entries,
            "table_len": tbl.len(), "is_empty": tbl.is_empty(),
            "source": "rustre_symbols_stabs::StabsStringTable"
        }).to_string()))
    }
}

pub struct StabsTypeParserPrimitivesTool;
impl StabsTypeParserPrimitivesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_stabs_type_parser_primitives".to_string(),
            description: "Return StabsTypeParser::new() length of built-in primitive map and lookup a key.".to_string(),
            input_schema: json!({"type":"object","properties":{"key":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for StabsTypeParserPrimitivesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let key = args.get("key").and_then(Value::as_str).unwrap_or("(0,1)");
        let p = rustre_symbols_stabs::StabsTypeParser::new();
        let hit = p.lookup(key).is_some();
        Ok(ToolResult::text(json!({
            "len": p.len(), "is_empty": p.is_empty(),
            "key": key, "found": hit,
            "source": "rustre_symbols_stabs::StabsTypeParser::new"
        }).to_string()))
    }
}

pub struct StabsTypeParserParseDescriptorTool;
impl StabsTypeParserParseDescriptorTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_stabs_type_parser_parse_descriptor".to_string(),
            description: "Parse a STABS type-descriptor string via StabsTypeParser::parse_descriptor.".to_string(),
            input_schema: json!({"type":"object","properties":{"desc":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for StabsTypeParserParseDescriptorTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let desc = args.get("desc").and_then(Value::as_str).unwrap_or("");
        let p = rustre_symbols_stabs::StabsTypeParser::new();
        match p.parse_descriptor(desc) {
            Ok(info) => Ok(ToolResult::text(json!({
                "desc": desc, "ok": true, "type_info": format!("{:?}", info),
                "source": "rustre_symbols_stabs::StabsTypeParser::parse_descriptor"
            }).to_string())),
            Err(e) => Ok(ToolResult::text(json!({
                "desc": desc, "ok": false, "error": e.to_string(),
                "source": "rustre_symbols_stabs::StabsTypeParser::parse_descriptor"
            }).to_string())),
        }
    }
}

pub struct StabsLineNumberTableLookupTool;
impl StabsLineNumberTableLookupTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_stabs_line_number_table_lookup".to_string(),
            description: "Build LineNumberTable from entries (addr,line,file) and lookup an address.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "entries":{"type":"array"},"addr":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for StabsLineNumberTableLookupTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut tbl = rustre_symbols_stabs::LineNumberTable::new();
        if let Some(arr) = args.get("entries").and_then(Value::as_array) {
            for e in arr {
                let addr = e.get("addr").and_then(Value::as_u64).unwrap_or(0);
                let line = e.get("line").and_then(Value::as_u64).unwrap_or(0) as u32;
                let file = e.get("file").and_then(Value::as_str).unwrap_or("").to_string();
                tbl.add(rustre_symbols_stabs::LineEntry { address: addr, line, file });
            }
        }
        tbl.sort();
        let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0);
        let found = tbl.lookup(addr).map(|e| json!({
            "address": e.address, "line": e.line, "file": e.file
        }));
        Ok(ToolResult::text(json!({
            "len": tbl.len(), "is_empty": tbl.is_empty(),
            "query_addr": addr, "hit": found,
            "source": "rustre_symbols_stabs::LineNumberTable::lookup"
        }).to_string()))
    }
}

pub struct StabsProviderFromBytesTool;
impl StabsProviderFromBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symbols_stabs_provider_from_bytes".to_string(),
            description: "Build StabsProvider::from_bytes(stab, stabstr, image_base) and report counts.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "stab_hex":{"type":"string"},"stabstr_hex":{"type":"string"},"image_base":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for StabsProviderFromBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let stab = extract_byte_array(&args, "stab", "stab_hex")?;
        let stabstr = extract_byte_array(&args, "stabstr", "stabstr_hex").unwrap_or_default();
        let image_base = args.get("image_base").and_then(Value::as_u64).unwrap_or(0);
        let p = rustre_symbols_stabs::StabsProvider::from_bytes(&stab, &stabstr, image_base);
        Ok(ToolResult::text(json!({
            "symbol_count": p.symbol_count(),
            "source_map_len": p.source_map_len(),
            "image_base": image_base,
            "source": "rustre_symbols_stabs::StabsProvider::from_bytes"
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (StabsTypeNameForTool::definition(), Box::new(StabsTypeNameForTool)),
        (StabsTypeCodeFromCharTool::definition(), Box::new(StabsTypeCodeFromCharTool)),
        (StabsIsSymbolTool::definition(), Box::new(StabsIsSymbolTool)),
        (StabsCategoryTool::definition(), Box::new(StabsCategoryTool)),
        (StabsIsSourceFileTool::definition(), Box::new(StabsIsSourceFileTool)),
        (StabsIsLineNumberTool::definition(), Box::new(StabsIsLineNumberTool)),
        (StabsTypeIsSymbolTool::definition(), Box::new(StabsTypeIsSymbolTool)),
        (StabsTypeIsSourceFileTool::definition(), Box::new(StabsTypeIsSourceFileTool)),
        (StabsTypeIsLineNumberTool::definition(), Box::new(StabsTypeIsLineNumberTool)),
        (StabsTypeIsScopeBracketTool::definition(), Box::new(StabsTypeIsScopeBracketTool)),
        (StabsTypeCategoryTool::definition(), Box::new(StabsTypeCategoryTool)),
        (StabsRecordParseAllBeTool::definition(), Box::new(StabsRecordParseAllBeTool)),
        (StabsTypeCodeFromCharV2Tool::definition(), Box::new(StabsTypeCodeFromCharV2Tool)),
        (StabsStringTableRoundtripTool::definition(), Box::new(StabsStringTableRoundtripTool)),
        (StabsTypeParserPrimitivesTool::definition(), Box::new(StabsTypeParserPrimitivesTool)),
        (StabsTypeParserParseDescriptorTool::definition(), Box::new(StabsTypeParserParseDescriptorTool)),
        (StabsLineNumberTableLookupTool::definition(), Box::new(StabsLineNumberTableLookupTool)),
        (StabsProviderFromBytesTool::definition(), Box::new(StabsProviderFromBytesTool)),
    ]
}
