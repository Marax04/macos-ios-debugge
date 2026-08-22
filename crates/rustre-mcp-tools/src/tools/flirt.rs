//! MCP wrappers for the rustre-flirt crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{_flirt_hex_to_bytes, _flirt_parse_pat_bytes};

pub struct FlirtCrc16Tool;

pub struct FlirtDemoSigCountTool;

pub struct FlirtParsePatternTool;

pub struct FlirtCrc16IbmTool;

pub struct FlirtParseSigHeaderTool;

pub struct FlirtArchFromU8Tool;

pub struct FlirtCrc16FlirtTool;

pub struct FlirtBuiltinCrtLibraryX64Tool;

pub struct FlirtBuiltinMatcherTool;

pub struct FlirtPatternWildcardRatioWireTool;

pub struct FlirtFileTypeContainsWireTool;

pub struct FlirtPatternMatchesInitialTool;
impl FlirtPatternMatchesInitialTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_pattern_matches_initial_wire".to_string(), description: "FlirtPattern::matches_initial.".to_string(), input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"buf_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtPatternMatchesInitialTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pat_s = args.get("pattern").and_then(Value::as_str).unwrap_or("55 8B EC"); let buf_hex = args.get("buf_hex").and_then(Value::as_str).unwrap_or("558bec"); let bytes = _flirt_hex_to_bytes(buf_hex)?; let pat = rustre_flirt::FlirtPattern::new(_flirt_parse_pat_bytes(pat_s)); Ok(ToolResult::text(json!({"matches":pat.matches_initial(&bytes),"source":"rustre_flirt::FlirtPattern::matches_initial"}).to_string())) } }

pub struct FlirtPatternHexTool;
impl FlirtPatternHexTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_pattern_hex_wire".to_string(), description: "FlirtPattern::pattern_hex.".to_string(), input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtPatternHexTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pat_s = args.get("pattern").and_then(Value::as_str).unwrap_or("55 8B .. EC"); let pat = rustre_flirt::FlirtPattern::new(_flirt_parse_pat_bytes(pat_s)); Ok(ToolResult::text(json!({"hex":pat.pattern_hex(),"wildcard_ratio":pat.wildcard_ratio(),"source":"rustre_flirt::FlirtPattern::pattern_hex"}).to_string())) } }

pub struct FlirtSigPatternMatchesTool;
impl FlirtSigPatternMatchesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_sig_pattern_matches_wire".to_string(), description: "SigPattern::matches.".to_string(), input_schema: json!({"type":"object","properties":{"buf_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtSigPatternMatchesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let buf_hex = args.get("buf_hex").and_then(Value::as_str).unwrap_or("deadbeef"); let bytes = _flirt_hex_to_bytes(buf_hex)?; let sp = rustre_flirt::SigPattern::new(); Ok(ToolResult::text(json!({"matches":sp.matches(&bytes),"source":"rustre_flirt::SigPattern::matches"}).to_string())) } }

pub struct FlirtLibraryRoundtripTool;
impl FlirtLibraryRoundtripTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_library_serialize_roundtrip_wire".to_string(), description: "FlirtLibrary serialize/deserialize.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtLibraryRoundtripTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).unwrap_or("test"); let lib = rustre_flirt::FlirtLibrary::new(name, rustre_flirt::FlirtArch::X64, rustre_flirt::FlirtOs::Linux); let s = lib.serialize(); let rt = rustre_flirt::FlirtLibrary::deserialize(&s).map_err(|e| McpError::InvalidParams(format!("deser: {e}")))?; Ok(ToolResult::text(json!({"name":rt.name,"pattern_count":rt.pattern_count(),"serialized_len":s.len(),"source":"rustre_flirt::FlirtLibrary"}).to_string())) } }

pub struct FlirtTrieBuildFindTool;
impl FlirtTrieBuildFindTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_trie_build_find_wire".to_string(), description: "FlirtTrie::build + find_candidates.".to_string(), input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"buf_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtTrieBuildFindTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pat_s = args.get("pattern").and_then(Value::as_str).unwrap_or("55 8B EC"); let buf_hex = args.get("buf_hex").and_then(Value::as_str).unwrap_or("558bec00"); let bytes = _flirt_hex_to_bytes(buf_hex)?; let mut lib = rustre_flirt::FlirtLibrary::new("t", rustre_flirt::FlirtArch::X64, rustre_flirt::FlirtOs::Linux); lib.add_pattern(rustre_flirt::FlirtPattern::new(_flirt_parse_pat_bytes(pat_s))); let trie = rustre_flirt::FlirtTrie::build(&lib); Ok(ToolResult::text(json!({"total":trie.total_patterns(),"candidates":trie.find_candidates(&bytes).len(),"source":"rustre_flirt::FlirtTrie"}).to_string())) } }

pub struct FlirtMatcherAddLibTool;
impl FlirtMatcherAddLibTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_matcher_add_library_wire".to_string(), description: "FlirtMatcher::add_library.".to_string(), input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtMatcherAddLibTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pat_s = args.get("pattern").and_then(Value::as_str).unwrap_or("55 8B EC 90"); let mut lib = rustre_flirt::FlirtLibrary::new("t", rustre_flirt::FlirtArch::X64, rustre_flirt::FlirtOs::Linux); lib.add_pattern(rustre_flirt::FlirtPattern::new(_flirt_parse_pat_bytes(pat_s))); let mut m = rustre_flirt::FlirtMatcher::new(); m.add_library(lib); Ok(ToolResult::text(json!({"libraries":m.library_count(),"patterns":m.pattern_count(),"min_bytes":m.min_bytes_needed(),"source":"rustre_flirt::FlirtMatcher"}).to_string())) } }

pub struct FlirtDatabaseAddModuleTool;
impl FlirtDatabaseAddModuleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_database_add_module_wire".to_string(), description: "FlirtDatabase::add_module + candidate_modules.".to_string(), input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"buf_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtDatabaseAddModuleTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pat_s = args.get("pattern").and_then(Value::as_str).unwrap_or("55 8B EC 90"); let buf_hex = args.get("buf_hex").and_then(Value::as_str).unwrap_or("558bec90"); let bytes = _flirt_hex_to_bytes(buf_hex)?; let m = rustre_flirt::SigModule { library_name: "t".into(), arch: rustre_flirt::FlirtArch::X64, file_types: rustre_flirt::FlirtFileType::from_u32(0), patterns: vec![rustre_flirt::FlirtPattern::new(_flirt_parse_pat_bytes(pat_s))] }; let mut db = rustre_flirt::FlirtDatabase::new(); db.add_module(m); Ok(ToolResult::text(json!({"total":db.total_patterns(),"candidates":db.candidate_modules(&bytes).len(),"source":"rustre_flirt::FlirtDatabase"}).to_string())) } }

pub struct FlirtArchToU8Tool;
impl FlirtArchToU8Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_arch_to_u8_wire".to_string(), description: "FlirtArch::to_u8.".to_string(), input_schema: json!({"type":"object","properties":{"code":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtArchToU8Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let c = args.get("code").and_then(Value::as_u64).unwrap_or(132) as u8; let a = rustre_flirt::FlirtArch::from_u8(c); Ok(ToolResult::text(json!({"code":c,"to_u8":a.to_u8(),"source":"rustre_flirt::FlirtArch::to_u8"}).to_string())) } }

pub struct FlirtFileTypeBitsTool;
impl FlirtFileTypeBitsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_file_type_bits_wire".to_string(), description: "FlirtFileType::from_u32.".to_string(), input_schema: json!({"type":"object","properties":{"value":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtFileTypeBitsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("value").and_then(Value::as_u64).unwrap_or(0x800) as u32; let ft = rustre_flirt::FlirtFileType::from_u32(v); Ok(ToolResult::text(json!({"bits":ft.bits(),"contains_pe":ft.contains(rustre_flirt::FlirtFileType::PE),"source":"rustre_flirt::FlirtFileType"}).to_string())) } }

pub struct FlirtPatternMatchesAllTool;
impl FlirtPatternMatchesAllTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_pattern_matches_all_wire".to_string(), description: "FlirtPattern::matches_all.".to_string(), input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"buf_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtPatternMatchesAllTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pat_s = args.get("pattern").and_then(Value::as_str).unwrap_or("55 8B EC"); let buf_hex = args.get("buf_hex").and_then(Value::as_str).unwrap_or("558bec"); let bytes = _flirt_hex_to_bytes(buf_hex)?; let pat = rustre_flirt::FlirtPattern::new(_flirt_parse_pat_bytes(pat_s)); Ok(ToolResult::text(json!({"initial":pat.matches_initial(&bytes),"crc":pat.matches_crc16(&bytes),"tail":pat.matches_tail(&bytes),"all":pat.matches_all(&bytes),"source":"rustre_flirt::FlirtPattern::matches_all"}).to_string())) } }

pub struct FlirtMatcherBestMatchTool;
impl FlirtMatcherBestMatchTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_matcher_best_match_wire".to_string(), description: "FlirtMatcher::best_match.".to_string(), input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"buf_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtMatcherBestMatchTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pat_s = args.get("pattern").and_then(Value::as_str).unwrap_or("55 8B EC"); let buf_hex = args.get("buf_hex").and_then(Value::as_str).unwrap_or("558bec"); let bytes = _flirt_hex_to_bytes(buf_hex)?; let mut pat = rustre_flirt::FlirtPattern::new(_flirt_parse_pat_bytes(pat_s)); pat.names.push(rustre_flirt::FlirtName { name: "foo".into(), offset: 0, is_public: true, is_local: false }); let mut lib = rustre_flirt::FlirtLibrary::new("t", rustre_flirt::FlirtArch::X64, rustre_flirt::FlirtOs::Linux); lib.add_pattern(pat); let mut m = rustre_flirt::FlirtMatcher::new(); m.add_library(lib); let best = m.best_match(rustre_core::address::Address::from(0x1000u64), &bytes); Ok(ToolResult::text(json!({"found":best.is_some(),"name":best.as_ref().map(|b| b.name.clone()),"source":"rustre_flirt::FlirtMatcher::best_match"}).to_string())) } }

pub struct FlirtSigFileParseErrTool;
impl FlirtSigFileParseErrTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_sig_file_parse_wire".to_string(), description: "FlirtSigFile::parse.".to_string(), input_schema: json!({"type":"object","properties":{"buf_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtSigFileParseErrTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let buf_hex = args.get("buf_hex").and_then(Value::as_str).unwrap_or("00"); let bytes = _flirt_hex_to_bytes(buf_hex)?; let r = rustre_flirt::FlirtSigFile::parse(&bytes); Ok(ToolResult::text(json!({"ok":r.is_ok(),"error":r.err().map(|e| e.to_string()),"source":"rustre_flirt::FlirtSigFile::parse"}).to_string())) } }

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (FlirtCrc16Tool::definition(), Box::new(FlirtCrc16Tool)),
        (FlirtDemoSigCountTool::definition(), Box::new(FlirtDemoSigCountTool)),
        (FlirtParsePatternTool::definition(), Box::new(FlirtParsePatternTool)),
        (FlirtCrc16IbmTool::definition(), Box::new(FlirtCrc16IbmTool)),
        (FlirtParseSigHeaderTool::definition(), Box::new(FlirtParseSigHeaderTool)),
        (FlirtArchFromU8Tool::definition(), Box::new(FlirtArchFromU8Tool)),
        (FlirtCrc16FlirtTool::definition(), Box::new(FlirtCrc16FlirtTool)),
        (FlirtBuiltinCrtLibraryX64Tool::definition(), Box::new(FlirtBuiltinCrtLibraryX64Tool)),
        (FlirtBuiltinMatcherTool::definition(), Box::new(FlirtBuiltinMatcherTool)),
        (FlirtPatternWildcardRatioWireTool::definition(), Box::new(FlirtPatternWildcardRatioWireTool)),
        (FlirtFileTypeContainsWireTool::definition(), Box::new(FlirtFileTypeContainsWireTool)),
        (FlirtPatternMatchesInitialTool::definition(), Box::new(FlirtPatternMatchesInitialTool)),
        (FlirtPatternHexTool::definition(), Box::new(FlirtPatternHexTool)),
        (FlirtSigPatternMatchesTool::definition(), Box::new(FlirtSigPatternMatchesTool)),
        (FlirtLibraryRoundtripTool::definition(), Box::new(FlirtLibraryRoundtripTool)),
        (FlirtTrieBuildFindTool::definition(), Box::new(FlirtTrieBuildFindTool)),
        (FlirtMatcherAddLibTool::definition(), Box::new(FlirtMatcherAddLibTool)),
        (FlirtDatabaseAddModuleTool::definition(), Box::new(FlirtDatabaseAddModuleTool)),
        (FlirtArchToU8Tool::definition(), Box::new(FlirtArchToU8Tool)),
        (FlirtFileTypeBitsTool::definition(), Box::new(FlirtFileTypeBitsTool)),
        (FlirtPatternMatchesAllTool::definition(), Box::new(FlirtPatternMatchesAllTool)),
        (FlirtMatcherBestMatchTool::definition(), Box::new(FlirtMatcherBestMatchTool)),
        (FlirtSigFileParseErrTool::definition(), Box::new(FlirtSigFileParseErrTool)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FLIRT identification must refuse a malformed payload.
    ///
    /// Verified against the matcher itself (`rustre_flirt::FlirtPattern::
    /// matches_initial`): it guards on length and then compares positionally
    /// under `all(...)`, so a dropped byte yields NO match rather than a wrong
    /// name. That is the loud end of this defect family — but "no library
    /// function found" is still an answer the caller did not ask for, and it is
    /// indistinguishable from a genuine miss.
    ///
    /// Keys come from each tool's own schema, never guessed: two generations of
    /// the same tool in this crate disagree on the key name, and guessing one
    /// produced a false result earlier in this campaign.
    #[tokio::test]
    async fn flirt_tools_refuse_bad_hex_instead_of_reporting_no_match() {
        let handlers = handlers();
        let mut checked = 0;
        for (def, h) in &handlers {
            let schema = def.input_schema.to_string();
            let keys: Vec<&str> = ["buf_hex", "hex", "data_hex"]
                .into_iter()
                .filter(|k| schema.contains(&format!("\"{k}\"")))
                .collect();
            if keys.is_empty() {
                continue;
            }
            let mut bad = serde_json::Map::new();
            for k in &keys {
                bad.insert((*k).to_string(), json!("4885c0zz"));
            }
            assert!(
                h.call(Value::Object(bad)).await.is_err(),
                "{} accepted an invalid digit",
                def.name
            );
            checked += 1;
        }
        assert!(checked > 0, "no flirt tool declares a hex key — probe is blind");
    }
}
