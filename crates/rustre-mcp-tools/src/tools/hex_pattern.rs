//! MCP wrappers for the rustre-hex_pattern crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes};
use crate::wire_tools::{hp_parse_bytes};

pub struct HexPatternCrc16IbmTool;

pub struct HexPatternParseTool;

pub struct HexPatternAlternationParseTool;

pub struct HexPatternMaskedFromStrTool;

pub struct HexPatternAlternationMatchesTool;

pub struct HexPatternMaskedSearchTool;

pub struct HexPatternSearchTool;
impl HexPatternSearchTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_search".to_string(),
            description: "Parse an IDA/HxD-style pattern and return match offsets in the given byte buffer via rustre_hex_pattern::Pattern::search.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"bytes":{"type":"array","items":{"type":"integer"}}},"required":["pattern","bytes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternSearchTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let buf = hp_parse_bytes(args.get("bytes").unwrap_or(&Value::Null))?;
        let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        let hits = pat.search(&buf);
        Ok(ToolResult::text(json!({"pattern_len":pat.len(),"match_count":hits.len(),"offsets":hits,"source":"rustre_hex_pattern::Pattern::search"}).to_string()))
    }
}

pub struct HexPatternMatchesAtTool;
impl HexPatternMatchesAtTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_matches_at".to_string(),
            description: "Check whether an IDA/HxD-style pattern matches the buffer at a specific offset via rustre_hex_pattern::Pattern::matches.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"bytes":{"type":"array","items":{"type":"integer"}},"offset":{"type":"integer","minimum":0}},"required":["pattern","bytes","offset"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternMatchesAtTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let buf = hp_parse_bytes(args.get("bytes").unwrap_or(&Value::Null))?;
        let off = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'offset'".into()))? as usize;
        let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        Ok(ToolResult::text(json!({"matches":pat.matches(&buf,off),"source":"rustre_hex_pattern::Pattern::matches"}).to_string()))
    }
}

pub struct HexPatternToSimdFormTool;
impl HexPatternToSimdFormTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_to_simd_form".to_string(),
            description: "Convert an IDA/HxD-style pattern into SIMD-friendly (values, masks) byte arrays via rustre_hex_pattern::Pattern::to_simd_form.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"}},"required":["pattern"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternToSimdFormTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        let (values, masks) = pat.to_simd_form();
        Ok(ToolResult::text(json!({"len":pat.len(),"values":values,"masks":masks,"source":"rustre_hex_pattern::Pattern::to_simd_form"}).to_string()))
    }
}

pub struct HexPatternToBytesTool;
impl HexPatternToBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_to_bytes".to_string(),
            description: "Attempt to convert a wildcard-free pattern to a plain byte array via rustre_hex_pattern::Pattern::to_bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"}},"required":["pattern"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternToBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        let bytes = pat.to_bytes();
        Ok(ToolResult::text(json!({"has_wildcards":bytes.is_none(),"bytes":bytes,"source":"rustre_hex_pattern::Pattern::to_bytes"}).to_string()))
    }
}

pub struct HexPatternCanonicalizeTool;
impl HexPatternCanonicalizeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_canonicalize".to_string(),
            description: "Parse a pattern string and return its canonical uppercase IDA-style hex form via rustre_hex_pattern::Pattern::to_hex_string.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"}},"required":["pattern"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternCanonicalizeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        Ok(ToolResult::text(json!({"canonical":pat.to_hex_string(),"source":"rustre_hex_pattern::Pattern::to_hex_string"}).to_string()))
    }
}

pub struct HexPatternCompiledSearchTool;
impl HexPatternCompiledSearchTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_compiled_search".to_string(),
            description: "Compile a pattern and search the given byte buffer via rustre_hex_pattern::CompiledPattern::search.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"bytes":{"type":"array","items":{"type":"integer"}}},"required":["pattern","bytes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternCompiledSearchTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let buf = hp_parse_bytes(args.get("bytes").unwrap_or(&Value::Null))?;
        let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        let cp = rustre_hex_pattern::CompiledPattern::compile(&pat);
        let hits = cp.search(&buf);
        Ok(ToolResult::text(json!({"pattern_len":cp.len,"match_count":hits.len(),"offsets":hits,"source":"rustre_hex_pattern::CompiledPattern::search"}).to_string()))
    }
}

pub struct HexPatternAlternationSearchTool;
impl HexPatternAlternationSearchTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_alternation_search".to_string(),
            description: "Parse a pipe-delimited alternation pattern and return match offsets via rustre_hex_pattern::AlternationPattern::search.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"bytes":{"type":"array","items":{"type":"integer"}}},"required":["pattern","bytes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternAlternationSearchTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let buf = hp_parse_bytes(args.get("bytes").unwrap_or(&Value::Null))?;
        let alt = rustre_hex_pattern::AlternationPattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        let hits = alt.search(&buf);
        Ok(ToolResult::text(json!({"alternatives":alt.len(),"match_count":hits.len(),"offsets":hits,"source":"rustre_hex_pattern::AlternationPattern::search"}).to_string()))
    }
}

pub struct HexPatternGroupSearchAllTool;
impl HexPatternGroupSearchAllTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_group_search_all".to_string(),
            description: "Build a PatternGroup from a list of pattern strings and search all simultaneously via rustre_hex_pattern::PatternGroup::search_all.".to_string(),
            input_schema: json!({"type":"object","properties":{"group_name":{"type":"string"},"patterns":{"type":"array","items":{"type":"string"}},"bytes":{"type":"array","items":{"type":"integer"}}},"required":["patterns","bytes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternGroupSearchAllTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("group_name").and_then(Value::as_str).unwrap_or("group");
        let pats_arr = args.get("patterns").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'patterns'".into()))?;
        let buf = hp_parse_bytes(args.get("bytes").unwrap_or(&Value::Null))?;
        let mut group = rustre_hex_pattern::PatternGroup::new(name);
        for (i, v) in pats_arr.iter().enumerate() {
            let s = v.as_str().ok_or_else(|| McpError::InvalidParams(format!("patterns[{i}] not string")))?;
            let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("patterns[{i}] parse: {e}")))?;
            group.add(pat);
        }
        let hits = group.search_all(&buf);
        Ok(ToolResult::text(json!({"group":name,"pattern_count":pats_arr.len(),"match_count":hits.len(),"matches":hits.iter().map(|m| json!({"pattern_index":m.pattern_index,"offset":m.offset})).collect::<Vec<_>>(),"source":"rustre_hex_pattern::PatternGroup::search_all"}).to_string()))
    }
}

pub struct HexPatternExportIdaPatTool;
impl HexPatternExportIdaPatTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_export_ida_pat".to_string(),
            description: "Export named pattern strings to IDA .pat text via rustre_hex_pattern::PatternExporter::export_ida_pat.".to_string(),
            input_schema: json!({"type":"object","properties":{"patterns":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"pattern":{"type":"string"}},"required":["pattern"]}}},"required":["patterns"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternExportIdaPatTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("patterns").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'patterns'".into()))?;
        let mut pats = Vec::with_capacity(arr.len());
        for (i, v) in arr.iter().enumerate() {
            let s = v.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams(format!("patterns[{i}].pattern missing")))?;
            let mut p = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse[{i}]: {e}")))?;
            if let Some(n) = v.get("name").and_then(Value::as_str) { p = p.with_name(n); }
            pats.push(p);
        }
        let text = rustre_hex_pattern::PatternExporter::export_ida_pat(&pats);
        Ok(ToolResult::text(json!({"count":pats.len(),"ida_pat":text,"source":"rustre_hex_pattern::PatternExporter::export_ida_pat"}).to_string()))
    }
}

pub struct HexPatternImportIdaPatTool;
impl HexPatternImportIdaPatTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_import_ida_pat".to_string(),
            description: "Import IDA .pat text and return the parsed patterns via rustre_hex_pattern::PatternExporter::import_ida_pat.".to_string(),
            input_schema: json!({"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternImportIdaPatTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?;
        let pats = rustre_hex_pattern::PatternExporter::import_ida_pat(text).map_err(|e| McpError::InvalidParams(format!("import: {e}")))?;
        let items: Vec<Value> = pats.iter().map(|p| json!({"name":p.name,"len":p.len(),"canonical":p.to_hex_string(),"specificity":p.specificity()})).collect();
        Ok(ToolResult::text(json!({"count":pats.len(),"patterns":items,"source":"rustre_hex_pattern::PatternExporter::import_ida_pat"}).to_string()))
    }
}

pub struct HexPatternSignatureSearchTool;
impl HexPatternSignatureSearchTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_signature_search".to_string(),
            description: "FLIRT-style signature search: prologue pattern + CRC-16/IBM over crc_len bytes following it, via rustre_hex_pattern::SignaturePattern::search.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"prologue":{"type":"string"},"crc16":{"type":"integer"},"crc_len":{"type":"integer"},"func_len":{"type":"integer"},"bytes":{"type":"array","items":{"type":"integer"}}},"required":["name","prologue","crc16","crc_len","func_len","bytes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternSignatureSearchTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let prologue_s = args.get("prologue").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'prologue'".into()))?;
        let crc16 = args.get("crc16").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'crc16'".into()))?;
        let crc_len = args.get("crc_len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'crc_len'".into()))?;
        let func_len = args.get("func_len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'func_len'".into()))?;
        let buf = hp_parse_bytes(args.get("bytes").unwrap_or(&Value::Null))?;
        let prologue = rustre_hex_pattern::Pattern::parse(prologue_s).map_err(|e| McpError::InvalidParams(format!("prologue parse: {e}")))?;
        let sig = rustre_hex_pattern::SignaturePattern::new(name, prologue,
            u16::try_from(crc16).map_err(|_| McpError::InvalidParams("crc16 out of u16".into()))?,
            u8::try_from(crc_len).map_err(|_| McpError::InvalidParams("crc_len out of u8".into()))?,
            u32::try_from(func_len).map_err(|_| McpError::InvalidParams("func_len out of u32".into()))?);
        let hits = sig.search(&buf);
        Ok(ToolResult::text(json!({"name":name,"match_count":hits.len(),"offsets":hits,"source":"rustre_hex_pattern::SignaturePattern::search"}).to_string()))
    }
}

pub struct HexPatternMaskedNewTool;
impl HexPatternMaskedNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_masked_new".to_string(),
            description: "Construct a MaskedPattern from raw bytes+mask arrays via rustre_hex_pattern::MaskedPattern::new.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"mask":{"type":"array","items":{"type":"integer"}}},"required":["bytes","mask"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternMaskedNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let b = hp_parse_bytes(args.get("bytes").unwrap_or(&Value::Null))?;
        let m = hp_parse_bytes(args.get("mask").unwrap_or(&Value::Null))?;
        let mp = rustre_hex_pattern::MaskedPattern::new(b, m).map_err(|e| McpError::InvalidParams(format!("new: {e}")))?;
        Ok(ToolResult::text(json!({"len":mp.len(),"is_empty":mp.is_empty(),"source":"rustre_hex_pattern::MaskedPattern::new"}).to_string()))
    }
}

pub struct HexPatternExactCountTool;
impl HexPatternExactCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_exact_count".to_string(),
            description: "Count non-wildcard exact bytes in an IDA/HxD-style pattern via rustre_hex_pattern::Pattern::exact_count.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"}},"required":["pattern"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternExactCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        Ok(ToolResult::text(json!({"len":pat.len(),"exact_count":pat.exact_count(),"source":"rustre_hex_pattern::Pattern::exact_count"}).to_string()))
    }
}

pub struct HexPatternWildcardCountTool;
impl HexPatternWildcardCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_wildcard_count".to_string(),
            description: "Count wildcard slots in an IDA/HxD-style pattern via rustre_hex_pattern::Pattern::wildcard_count.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"}},"required":["pattern"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternWildcardCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        Ok(ToolResult::text(json!({"len":pat.len(),"wildcard_count":pat.wildcard_count(),"source":"rustre_hex_pattern::Pattern::wildcard_count"}).to_string()))
    }
}

pub struct HexPatternSpecificityTool;
impl HexPatternSpecificityTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_specificity".to_string(),
            description: "Compute specificity (exact_count/len) of an IDA/HxD-style pattern via rustre_hex_pattern::Pattern::specificity.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"}},"required":["pattern"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternSpecificityTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        Ok(ToolResult::text(json!({"len":pat.len(),"specificity":pat.specificity(),"source":"rustre_hex_pattern::Pattern::specificity"}).to_string()))
    }
}

pub struct HexPatternToJsonTool;
impl HexPatternToJsonTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_to_json".to_string(),
            description: "Serialize a parsed IDA/HxD-style pattern to JSON via rustre_hex_pattern::Pattern::to_json.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"name":{"type":"string"}},"required":["pattern"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternToJsonTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let mut pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        if let Some(n) = args.get("name").and_then(Value::as_str) { pat = pat.with_name(n); }
        let j = pat.to_json().map_err(|e| McpError::InvalidParams(format!("json: {e}")))?;
        Ok(ToolResult::text(json!({"json":j,"source":"rustre_hex_pattern::Pattern::to_json"}).to_string()))
    }
}

pub struct HexPatternFromJsonTool;
impl HexPatternFromJsonTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_from_json".to_string(),
            description: "Deserialize a JSON-encoded pattern via rustre_hex_pattern::Pattern::from_json and report canonical form.".to_string(),
            input_schema: json!({"type":"object","properties":{"json":{"type":"string"}},"required":["json"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternFromJsonTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let j = args.get("json").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'json'".into()))?;
        let pat = rustre_hex_pattern::Pattern::from_json(j).map_err(|e| McpError::InvalidParams(format!("from_json: {e}")))?;
        Ok(ToolResult::text(json!({"len":pat.len(),"name":pat.name,"canonical":pat.to_hex_string(),"source":"rustre_hex_pattern::Pattern::from_json"}).to_string()))
    }
}

pub struct HexPatternMaskedMatchesAtTool;
impl HexPatternMaskedMatchesAtTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_masked_matches_at".to_string(),
            description: "Check MaskedPattern match at a given offset via rustre_hex_pattern::MaskedPattern::matches.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"mask":{"type":"array","items":{"type":"integer"}},"data":{"type":"array","items":{"type":"integer"}},"offset":{"type":"integer","minimum":0}},"required":["bytes","mask","data","offset"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternMaskedMatchesAtTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let b = hp_parse_bytes(args.get("bytes").unwrap_or(&Value::Null))?;
        let m = hp_parse_bytes(args.get("mask").unwrap_or(&Value::Null))?;
        let d = hp_parse_bytes(args.get("data").unwrap_or(&Value::Null))?;
        let off = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'offset'".into()))? as usize;
        let mp = rustre_hex_pattern::MaskedPattern::new(b, m).map_err(|e| McpError::InvalidParams(format!("new: {e}")))?;
        Ok(ToolResult::text(json!({"matches":mp.matches(&d,off),"source":"rustre_hex_pattern::MaskedPattern::matches"}).to_string()))
    }
}

pub struct HexPatternCompiledMatchesAtTool;
impl HexPatternCompiledMatchesAtTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_compiled_matches_at".to_string(),
            description: "Check CompiledPattern match at a given offset via rustre_hex_pattern::CompiledPattern::matches.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"bytes":{"type":"array","items":{"type":"integer"}},"offset":{"type":"integer","minimum":0}},"required":["pattern","bytes","offset"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternCompiledMatchesAtTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let buf = hp_parse_bytes(args.get("bytes").unwrap_or(&Value::Null))?;
        let off = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'offset'".into()))? as usize;
        let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        let cp = rustre_hex_pattern::CompiledPattern::compile(&pat);
        Ok(ToolResult::text(json!({"matches":cp.matches(&buf,off),"len":cp.len,"source":"rustre_hex_pattern::CompiledPattern::matches"}).to_string()))
    }
}

pub struct HexPatternExporterExportJsonTool;
impl HexPatternExporterExportJsonTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_exporter_export_json".to_string(),
            description: "Export a list of pattern strings to JSON via rustre_hex_pattern::PatternExporter::export_json.".to_string(),
            input_schema: json!({"type":"object","properties":{"patterns":{"type":"array","items":{"type":"string"}}},"required":["patterns"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternExporterExportJsonTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("patterns").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'patterns'".into()))?;
        let mut pats = Vec::with_capacity(arr.len());
        for (i, v) in arr.iter().enumerate() {
            let s = v.as_str().ok_or_else(|| McpError::InvalidParams(format!("patterns[{i}] not string")))?;
            pats.push(rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse[{i}]: {e}")))?);
        }
        let j = rustre_hex_pattern::PatternExporter::export_json(&pats).map_err(|e| McpError::InvalidParams(format!("export: {e}")))?;
        Ok(ToolResult::text(json!({"count":pats.len(),"json":j,"source":"rustre_hex_pattern::PatternExporter::export_json"}).to_string()))
    }
}

pub struct HexPatternRegexSearchTool;
impl HexPatternRegexSearchTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_regex_search".to_string(),
            description: "Search a byte buffer using a binary regex via rustre_hex_pattern::RegexPattern::search.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"bytes":{"type":"array","items":{"type":"integer"}}},"required":["pattern","bytes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternRegexSearchTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let buf = hp_parse_bytes(args.get("bytes").unwrap_or(&Value::Null))?;
        let rp = rustre_hex_pattern::RegexPattern::new(s);
        let hits = rp.search(&buf).map_err(|e| McpError::InvalidParams(format!("regex: {e}")))?;
        Ok(ToolResult::text(json!({"match_count":hits.len(),"offsets":hits,"source":"rustre_hex_pattern::RegexPattern::search"}).to_string()))
    }
}

pub struct HexPatternSearchWithCapturesTool;
impl HexPatternSearchWithCapturesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "hex_pattern_search_with_captures".to_string(),
            description: "Search with named captures and return matches + captured byte ranges via rustre_hex_pattern::Pattern::search_with_captures.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"bytes":{"type":"array","items":{"type":"integer"}},"captures":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"start":{"type":"integer"},"len":{"type":"integer"}},"required":["name","start","len"]}}},"required":["pattern","bytes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for HexPatternSearchWithCapturesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let buf = hp_parse_bytes(args.get("bytes").unwrap_or(&Value::Null))?;
        let mut pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        if let Some(caps) = args.get("captures").and_then(Value::as_array) {
            for c in caps {
                let name = c.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("capture.name missing".into()))?;
                let start = c.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("capture.start missing".into()))? as usize;
                let len = c.get("len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("capture.len missing".into()))? as usize;
                pat = pat.with_capture(name, start, len);
            }
        }
        let hits = pat.search_with_captures(&buf);
        let items: Vec<Value> = hits.iter().map(|(off, caps)| json!({"offset":off,"captures":caps.iter().map(|c| json!({"name":c.name,"offset":c.offset,"bytes":c.bytes})).collect::<Vec<_>>()})).collect();
        Ok(ToolResult::text(json!({"match_count":items.len(),"matches":items,"source":"rustre_hex_pattern::Pattern::search_with_captures"}).to_string()))
    }
}

pub struct HexPatternWithNameV4Tool;
impl HexPatternWithNameV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_with_name_v4".to_string(), description: "Pattern::with_name.".to_string(), input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for HexPatternWithNameV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("pattern").and_then(Value::as_str).unwrap_or("DE AD"); let n = args.get("name").and_then(Value::as_str).unwrap_or("p"); let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?.with_name(n); Ok(ToolResult::text(json!({"name":pat.name,"len":pat.len(),"source":"rustre_hex_pattern::Pattern::with_name"}).to_string())) } }

pub struct HexPatternWithTagV4Tool;
impl HexPatternWithTagV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_with_tag_v4".to_string(), description: "Pattern::with_tag.".to_string(), input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"tag":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for HexPatternWithTagV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("pattern").and_then(Value::as_str).unwrap_or("DE AD"); let t = args.get("tag").and_then(Value::as_str).unwrap_or("crypto"); let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?.with_tag(t); Ok(ToolResult::text(json!({"tags":pat.tags,"source":"rustre_hex_pattern::Pattern::with_tag"}).to_string())) } }

pub struct HexPatternWithCommentV4Tool;
impl HexPatternWithCommentV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_with_comment_v4".to_string(), description: "Pattern::with_comment.".to_string(), input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"comment":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for HexPatternWithCommentV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("pattern").and_then(Value::as_str).unwrap_or("DE AD"); let c = args.get("comment").and_then(Value::as_str).unwrap_or("hi"); let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?.with_comment(c); Ok(ToolResult::text(json!({"comment":pat.comment,"source":"rustre_hex_pattern::Pattern::with_comment"}).to_string())) } }

pub struct HexPatternAlternationNewV4Tool;
impl HexPatternAlternationNewV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_alternation_new_v4".to_string(), description: "AlternationPattern::new.".to_string(), input_schema: json!({"type":"object","properties":{"patterns":{"type":"array","items":{"type":"string"}}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for HexPatternAlternationNewV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let empty = vec![]; let pats_arr = args.get("patterns").and_then(Value::as_array).unwrap_or(&empty); let mut alts = Vec::new(); for (i, v) in pats_arr.iter().enumerate() { let s = v.as_str().ok_or_else(|| McpError::InvalidParams(format!("patterns[{i}]")))?; alts.push(rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse[{i}]: {e}")))?); } let alt = rustre_hex_pattern::AlternationPattern::new(alts); Ok(ToolResult::text(json!({"len":alt.len(),"is_empty":alt.is_empty(),"source":"rustre_hex_pattern::AlternationPattern::new"}).to_string())) } }

pub struct HexPatternMaskedLenV4Tool;
impl HexPatternMaskedLenV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_masked_len_v4".to_string(), description: "MaskedPattern::len.".to_string(), input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for HexPatternMaskedLenV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("pattern").and_then(Value::as_str).unwrap_or("DE AD"); let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?; let mp = rustre_hex_pattern::MaskedPattern::from_pattern(&pat); Ok(ToolResult::text(json!({"len":mp.len(),"is_empty":mp.is_empty(),"source":"rustre_hex_pattern::MaskedPattern::len"}).to_string())) } }

pub struct HexPatternRegexSearchV4Tool;
impl HexPatternRegexSearchV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_regex_search_v4".to_string(), description: "RegexPattern::search.".to_string(), input_schema: json!({"type":"object","properties":{"regex":{"type":"string"},"data_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for HexPatternRegexSearchV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let re = args.get("regex").and_then(Value::as_str).unwrap_or(""); let buf = args_to_bytes(&args)?; let rp = rustre_hex_pattern::RegexPattern::new(re); let hits = rp.search(&buf).map_err(|e| McpError::InvalidParams(format!("regex: {e}")))?; Ok(ToolResult::text(json!({"match_count":hits.len(),"offsets":hits,"source":"rustre_hex_pattern::RegexPattern::search"}).to_string())) } }

pub struct HexPatternGroupCompileV4Tool;
impl HexPatternGroupCompileV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_group_compile_v4".to_string(), description: "CompiledPatternGroup::search_all.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"patterns":{"type":"array","items":{"type":"string"}},"data_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for HexPatternGroupCompileV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).unwrap_or("g"); let empty = vec![]; let pats_arr = args.get("patterns").and_then(Value::as_array).unwrap_or(&empty); let buf = args_to_bytes(&args)?; let mut group = rustre_hex_pattern::PatternGroup::new(name); for (i, v) in pats_arr.iter().enumerate() { let s = v.as_str().ok_or_else(|| McpError::InvalidParams(format!("patterns[{i}]")))?; let p = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse[{i}]: {e}")))?; group.add(p); } let cg = group.compile(); let hits = cg.search_all(&buf); Ok(ToolResult::text(json!({"group":cg.name,"pattern_count":cg.patterns.len(),"match_count":hits.len(),"source":"rustre_hex_pattern::CompiledPatternGroup::search_all"}).to_string())) } }

pub struct HexPatternGroupAnyMatchesV4Tool;
impl HexPatternGroupAnyMatchesV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_group_any_matches_v4".to_string(), description: "PatternGroup::any_matches.".to_string(), input_schema: json!({"type":"object","properties":{"patterns":{"type":"array","items":{"type":"string"}},"data_hex":{"type":"string"},"offset":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for HexPatternGroupAnyMatchesV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let empty = vec![]; let pats_arr = args.get("patterns").and_then(Value::as_array).unwrap_or(&empty); let buf = args_to_bytes(&args)?; let off = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize; let mut group = rustre_hex_pattern::PatternGroup::new("g"); for (i, v) in pats_arr.iter().enumerate() { let s = v.as_str().ok_or_else(|| McpError::InvalidParams(format!("patterns[{i}]")))?; let p = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse[{i}]: {e}")))?; group.add(p); } Ok(ToolResult::text(json!({"any_matches":group.any_matches(&buf, off),"source":"rustre_hex_pattern::PatternGroup::any_matches"}).to_string())) } }

pub struct HexPatternGroupToJsonV4Tool;
impl HexPatternGroupToJsonV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_group_to_json_v4".to_string(), description: "PatternGroup::to_json roundtrip.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"patterns":{"type":"array","items":{"type":"string"}}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for HexPatternGroupToJsonV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).unwrap_or("g"); let empty = vec![]; let pats_arr = args.get("patterns").and_then(Value::as_array).unwrap_or(&empty); let mut group = rustre_hex_pattern::PatternGroup::new(name); for (i, v) in pats_arr.iter().enumerate() { let s = v.as_str().ok_or_else(|| McpError::InvalidParams(format!("patterns[{i}]")))?; let p = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse[{i}]: {e}")))?; group.add(p); } let js = group.to_json().map_err(|e| McpError::InvalidParams(format!("to_json: {e}")))?; let rt = rustre_hex_pattern::PatternGroup::from_json(&js).map_err(|e| McpError::InvalidParams(format!("from_json: {e}")))?; Ok(ToolResult::text(json!({"json_len":js.len(),"roundtrip_patterns":rt.patterns.len(),"source":"rustre_hex_pattern::PatternGroup::to_json"}).to_string())) } }

pub struct HexPatternSignatureMatchesV4Tool;
impl HexPatternSignatureMatchesV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_signature_matches_v4".to_string(), description: "SignaturePattern::matches with_module.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"module":{"type":"string"},"prologue":{"type":"string"},"crc16":{"type":"integer"},"crc_len":{"type":"integer"},"func_len":{"type":"integer"},"data_hex":{"type":"string"},"offset":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for HexPatternSignatureMatchesV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).unwrap_or("f"); let module = args.get("module").and_then(Value::as_str).unwrap_or("m"); let prologue_s = args.get("prologue").and_then(Value::as_str).unwrap_or("55 48 89 E5"); let crc16 = args.get("crc16").and_then(Value::as_u64).unwrap_or(0) as u16; let crc_len = args.get("crc_len").and_then(Value::as_u64).unwrap_or(0) as u8; let func_len = args.get("func_len").and_then(Value::as_u64).unwrap_or(0) as u32; let buf = args_to_bytes(&args)?; let off = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize; let prologue = rustre_hex_pattern::Pattern::parse(prologue_s).map_err(|e| McpError::InvalidParams(format!("prologue: {e}")))?; let sig = rustre_hex_pattern::SignaturePattern::new(name, prologue, crc16, crc_len, func_len).with_module(module); Ok(ToolResult::text(json!({"matches":sig.matches(&buf, off),"module":sig.module_name,"source":"rustre_hex_pattern::SignaturePattern::matches"}).to_string())) } }

pub struct HexPatternDbRoundtripV4Tool;
impl HexPatternDbRoundtripV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_db_roundtrip_v4".to_string(), description: "PatternDatabase in-memory roundtrip.".to_string(), input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"name":{"type":"string"},"tag":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for HexPatternDbRoundtripV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("pattern").and_then(Value::as_str).unwrap_or("DE AD BE EF"); let name = args.get("name").and_then(Value::as_str).unwrap_or("test"); let tag = args.get("tag").and_then(Value::as_str).unwrap_or("t"); let db = rustre_hex_pattern::PatternDatabase::open_in_memory().map_err(|e| McpError::InvalidParams(format!("open: {e}")))?; let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?.with_name(name).with_tag(tag); let id = db.insert(&pat).map_err(|e| McpError::InvalidParams(format!("insert: {e}")))?; let by_name = db.search_by_name(name).map_err(|e| McpError::InvalidParams(format!("name: {e}")))?; let by_tag = db.search_by_tag(tag).map_err(|e| McpError::InvalidParams(format!("tag: {e}")))?; let count = db.count().map_err(|e| McpError::InvalidParams(format!("count: {e}")))?; db.delete(id).map_err(|e| McpError::InvalidParams(format!("delete: {e}")))?; let after = db.count().map_err(|e| McpError::InvalidParams(format!("count2: {e}")))?; Ok(ToolResult::text(json!({"id":id,"by_name":by_name.len(),"by_tag":by_tag.len(),"count":count,"count_after_delete":after,"source":"rustre_hex_pattern::PatternDatabase"}).to_string())) } }

pub struct HexPatternExporterJsonV4Tool;
impl HexPatternExporterJsonV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_exporter_json_v4".to_string(), description: "PatternExporter::export_json/import_json.".to_string(), input_schema: json!({"type":"object","properties":{"patterns":{"type":"array","items":{"type":"string"}}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for HexPatternExporterJsonV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let empty = vec![]; let pats_arr = args.get("patterns").and_then(Value::as_array).unwrap_or(&empty); let mut pats = Vec::new(); for (i, v) in pats_arr.iter().enumerate() { let s = v.as_str().ok_or_else(|| McpError::InvalidParams(format!("patterns[{i}]")))?; pats.push(rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("parse[{i}]: {e}")))?); } let js = rustre_hex_pattern::PatternExporter::export_json(&pats).map_err(|e| McpError::InvalidParams(format!("export: {e}")))?; let rt = rustre_hex_pattern::PatternExporter::import_json(&js).map_err(|e| McpError::InvalidParams(format!("import: {e}")))?; Ok(ToolResult::text(json!({"json_len":js.len(),"roundtrip":rt.len(),"source":"rustre_hex_pattern::PatternExporter::export_json"}).to_string())) } }

pub struct HexPatternToHexStringV3Tool;
impl HexPatternToHexStringV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_to_hex_string_v3".to_string(), description: "Format Pattern as IDA-style hex string via Pattern::to_hex_string.".to_string(), input_schema: json!({ "type":"object", "properties": { "pat": {"type":"string"} }, "required":["pat"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexPatternToHexStringV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("pat").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pat'".into()))?; let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("{e}")))?; let hs = pat.to_hex_string(); Ok(ToolResult::text(json!({ "hex_string": hs, "source": "rustre_hex_pattern::Pattern::to_hex_string" }).to_string())) } }

pub struct HexPatternNfaFindAllV3Tool;
impl HexPatternNfaFindAllV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_nfa_find_all_v3".to_string(), description: "Compile pattern into PatternNfa and return all (offset,len) matches in data_hex.".to_string(), input_schema: json!({ "type":"object", "properties": { "pat": {"type":"string"}, "data_hex": {"type":"string"} }, "required":["pat","data_hex"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexPatternNfaFindAllV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("pat").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pat'".into()))?; let data = crate::hex_decode(args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?)?; let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("{e}")))?; let nfa = rustre_hex_pattern::PatternNfa::compile(&pat); let hits = nfa.find_all(&data); Ok(ToolResult::text(json!({ "count": hits.len(), "hits": hits, "source": "rustre_hex_pattern::PatternNfa::find_all" }).to_string())) } }

pub struct HexPatternNfaFindFirstV3Tool;
impl HexPatternNfaFindFirstV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_nfa_find_first_v3".to_string(), description: "Compile pattern into PatternNfa and return the first (offset,len) match starting from 'start'.".to_string(), input_schema: json!({ "type":"object", "properties": { "pat": {"type":"string"}, "data_hex": {"type":"string"}, "start": {"type":"integer"} }, "required":["pat","data_hex"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexPatternNfaFindFirstV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("pat").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pat'".into()))?; let data = crate::hex_decode(args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?)?; let start = args.get("start").and_then(Value::as_u64).unwrap_or(0) as usize; let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("{e}")))?; let nfa = rustre_hex_pattern::PatternNfa::compile(&pat); let hit = nfa.find_first(&data, start); Ok(ToolResult::text(json!({ "hit": hit, "source": "rustre_hex_pattern::PatternNfa::find_first" }).to_string())) } }

pub struct HexPatternDfaSearchV3Tool;
impl HexPatternDfaSearchV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_dfa_search_v3".to_string(), description: "Compile pattern into PatternDfa and return match offsets in data_hex.".to_string(), input_schema: json!({ "type":"object", "properties": { "pat": {"type":"string"}, "data_hex": {"type":"string"} }, "required":["pat","data_hex"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexPatternDfaSearchV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("pat").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pat'".into()))?; let data = crate::hex_decode(args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?)?; let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("{e}")))?; let dfa = rustre_hex_pattern::PatternDfa::compile(&pat); let hits = dfa.search(&data); Ok(ToolResult::text(json!({ "count": hits.len(), "hits": hits, "source": "rustre_hex_pattern::PatternDfa::search" }).to_string())) } }

pub struct HexPatternMultiMatcherSearchV3Tool;
impl HexPatternMultiMatcherSearchV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_multi_matcher_search_v3".to_string(), description: "Build MultiPatternMatcher from a list of patterns and return (pattern_idx, offset) matches.".to_string(), input_schema: json!({ "type":"object", "properties": { "patterns": {"type":"array"}, "data_hex": {"type":"string"} }, "required":["patterns","data_hex"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexPatternMultiMatcherSearchV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("patterns").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'patterns'".into()))?; let data = crate::hex_decode(args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?)?; let mut pats = Vec::new(); for v in arr { let s = v.as_str().ok_or_else(|| McpError::InvalidParams("pattern must be string".into()))?; pats.push(rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("{e}")))?); } let m = rustre_hex_pattern::MultiPatternMatcher::build(&pats); let hits = m.search(&data); Ok(ToolResult::text(json!({ "count": hits.len(), "hits": hits, "source": "rustre_hex_pattern::MultiPatternMatcher::search" }).to_string())) } }

pub struct HexPatternBmhSearchV3Tool;
impl HexPatternBmhSearchV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_bmh_search_v3".to_string(), description: "Boyer-Moore-Horspool search for needle_hex in haystack_hex via BmhTable.".to_string(), input_schema: json!({ "type":"object", "properties": { "needle_hex": {"type":"string"}, "haystack_hex": {"type":"string"} }, "required":["needle_hex","haystack_hex"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexPatternBmhSearchV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let needle = crate::hex_decode(args.get("needle_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'needle_hex'".into()))?)?; let hay = crate::hex_decode(args.get("haystack_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'haystack_hex'".into()))?)?; if needle.is_empty() { return Ok(ToolResult::text(json!({ "count": 0, "hits": [], "note": "needle empty; BmhTable requires >=1 byte", "source": "rustre_hex_pattern::BmhTable::search" }).to_string())); } let t = rustre_hex_pattern::BmhTable::build(&needle); let hits = t.search(&hay, &needle); Ok(ToolResult::text(json!({ "count": hits.len(), "hits": hits, "source": "rustre_hex_pattern::BmhTable::search" }).to_string())) } }

pub struct HexPatternByteMaskSpecificityV3Tool;
impl HexPatternByteMaskSpecificityV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_byte_mask_specificity_v3".to_string(), description: "Compute specificity of a ByteMask (popcount(mask)/8).".to_string(), input_schema: json!({ "type":"object", "properties": { "mask": {"type":"integer"}, "value": {"type":"integer"} }, "required":["mask","value"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexPatternByteMaskSpecificityV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let mask = args.get("mask").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'mask'".into()))? as u8; let value = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))? as u8; let bm = rustre_hex_pattern::ByteMask { mask, value }; Ok(ToolResult::text(json!({ "specificity": bm.specificity(), "is_wildcard": bm.is_wildcard(), "is_exact": bm.is_exact(), "source": "rustre_hex_pattern::ByteMask::specificity" }).to_string())) } }

pub struct HexPatternRangeExpandV3Tool;
impl HexPatternRangeExpandV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_range_expand_v3".to_string(), description: "Expand a PatternRange [lo,hi] into the list of byte values it covers.".to_string(), input_schema: json!({ "type":"object", "properties": { "lo": {"type":"integer"}, "hi": {"type":"integer"} }, "required":["lo","hi"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexPatternRangeExpandV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let lo = args.get("lo").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lo'".into()))? as u8; let hi = args.get("hi").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'hi'".into()))? as u8; let r = rustre_hex_pattern::PatternRange::new(lo, hi); let v = r.expand(); Ok(ToolResult::text(json!({ "count": v.len(), "bytes": v, "source": "rustre_hex_pattern::PatternRange::expand" }).to_string())) } }

pub struct HexPatternStatisticsComputeV3Tool;
impl HexPatternStatisticsComputeV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_statistics_compute_v3".to_string(), description: "Compute PatternStatistics over a list of pattern strings.".to_string(), input_schema: json!({ "type":"object", "properties": { "patterns": {"type":"array"} }, "required":["patterns"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexPatternStatisticsComputeV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("patterns").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'patterns'".into()))?; let mut pats = Vec::new(); for v in arr { let s = v.as_str().ok_or_else(|| McpError::InvalidParams("pattern must be string".into()))?; pats.push(rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("{e}")))?); } let st = rustre_hex_pattern::PatternStatistics::compute(&pats); Ok(ToolResult::text(json!({ "total": st.total, "exact_only": st.exact_only, "with_wildcards": st.with_wildcards, "avg_length": st.avg_length, "avg_specificity": st.avg_specificity, "min_length": st.min_length, "max_length": st.max_length, "tagged": st.tagged, "named": st.named, "source": "rustre_hex_pattern::PatternStatistics::compute" }).to_string())) } }

pub struct HexPatternToMaskedV3Tool;
impl HexPatternToMaskedV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_to_masked_v3".to_string(), description: "Convert Pattern to MaskedBytePattern via rustre_hex_pattern::pattern_to_masked and return specificity.".to_string(), input_schema: json!({ "type":"object", "properties": { "pat": {"type":"string"} }, "required":["pat"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexPatternToMaskedV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("pat").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pat'".into()))?; let pat = rustre_hex_pattern::Pattern::parse(s).map_err(|e| McpError::InvalidParams(format!("{e}")))?; let m = rustre_hex_pattern::pattern_to_masked(&pat); Ok(ToolResult::text(json!({ "len": m.elements.len(), "specificity": m.specificity(), "source": "rustre_hex_pattern::pattern_to_masked" }).to_string())) } }

pub struct HexPatternSequenceSearchV3Tool;
impl HexPatternSequenceSearchV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_pattern_sequence_search_v3".to_string(), description: "Build a SequencePattern from (offset, pattern_string) entries and search data_hex.".to_string(), input_schema: json!({ "type":"object", "properties": { "entries": {"type":"array"}, "data_hex": {"type":"string"} }, "required":["entries","data_hex"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexPatternSequenceSearchV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("entries").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'entries'".into()))?; let data = crate::hex_decode(args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?)?; let mut seq = rustre_hex_pattern::SequencePattern::new(); for v in arr { let off = v.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("entry missing 'offset'".into()))? as usize; let ps = v.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("entry missing 'pattern'".into()))?; let p = rustre_hex_pattern::Pattern::parse(ps).map_err(|e| McpError::InvalidParams(format!("{e}")))?; seq.add(off, p); } let hits = seq.search(&data); Ok(ToolResult::text(json!({ "count": hits.len(), "hits": hits, "source": "rustre_hex_pattern::SequencePattern::search" }).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (HexPatternCrc16IbmTool::definition(), Box::new(HexPatternCrc16IbmTool)),
        (HexPatternParseTool::definition(), Box::new(HexPatternParseTool)),
        (HexPatternAlternationParseTool::definition(), Box::new(HexPatternAlternationParseTool)),
        (HexPatternMaskedFromStrTool::definition(), Box::new(HexPatternMaskedFromStrTool)),
        (HexPatternAlternationMatchesTool::definition(), Box::new(HexPatternAlternationMatchesTool)),
        (HexPatternMaskedSearchTool::definition(), Box::new(HexPatternMaskedSearchTool)),
        (HexPatternSearchTool::definition(), Box::new(HexPatternSearchTool)),
        (HexPatternMatchesAtTool::definition(), Box::new(HexPatternMatchesAtTool)),
        (HexPatternToSimdFormTool::definition(), Box::new(HexPatternToSimdFormTool)),
        (HexPatternToBytesTool::definition(), Box::new(HexPatternToBytesTool)),
        (HexPatternCanonicalizeTool::definition(), Box::new(HexPatternCanonicalizeTool)),
        (HexPatternCompiledSearchTool::definition(), Box::new(HexPatternCompiledSearchTool)),
        (HexPatternAlternationSearchTool::definition(), Box::new(HexPatternAlternationSearchTool)),
        (HexPatternGroupSearchAllTool::definition(), Box::new(HexPatternGroupSearchAllTool)),
        (HexPatternExportIdaPatTool::definition(), Box::new(HexPatternExportIdaPatTool)),
        (HexPatternImportIdaPatTool::definition(), Box::new(HexPatternImportIdaPatTool)),
        (HexPatternSignatureSearchTool::definition(), Box::new(HexPatternSignatureSearchTool)),
        (HexPatternMaskedNewTool::definition(), Box::new(HexPatternMaskedNewTool)),
        (HexPatternExactCountTool::definition(), Box::new(HexPatternExactCountTool)),
        (HexPatternWildcardCountTool::definition(), Box::new(HexPatternWildcardCountTool)),
        (HexPatternSpecificityTool::definition(), Box::new(HexPatternSpecificityTool)),
        (HexPatternToJsonTool::definition(), Box::new(HexPatternToJsonTool)),
        (HexPatternFromJsonTool::definition(), Box::new(HexPatternFromJsonTool)),
        (HexPatternMaskedMatchesAtTool::definition(), Box::new(HexPatternMaskedMatchesAtTool)),
        (HexPatternCompiledMatchesAtTool::definition(), Box::new(HexPatternCompiledMatchesAtTool)),
        (HexPatternExporterExportJsonTool::definition(), Box::new(HexPatternExporterExportJsonTool)),
        (HexPatternRegexSearchTool::definition(), Box::new(HexPatternRegexSearchTool)),
        (HexPatternSearchWithCapturesTool::definition(), Box::new(HexPatternSearchWithCapturesTool)),
        (HexPatternWithNameV4Tool::definition(), Box::new(HexPatternWithNameV4Tool)),
        (HexPatternWithTagV4Tool::definition(), Box::new(HexPatternWithTagV4Tool)),
        (HexPatternWithCommentV4Tool::definition(), Box::new(HexPatternWithCommentV4Tool)),
        (HexPatternAlternationNewV4Tool::definition(), Box::new(HexPatternAlternationNewV4Tool)),
        (HexPatternMaskedLenV4Tool::definition(), Box::new(HexPatternMaskedLenV4Tool)),
        (HexPatternRegexSearchV4Tool::definition(), Box::new(HexPatternRegexSearchV4Tool)),
        (HexPatternGroupCompileV4Tool::definition(), Box::new(HexPatternGroupCompileV4Tool)),
        (HexPatternGroupAnyMatchesV4Tool::definition(), Box::new(HexPatternGroupAnyMatchesV4Tool)),
        (HexPatternGroupToJsonV4Tool::definition(), Box::new(HexPatternGroupToJsonV4Tool)),
        (HexPatternSignatureMatchesV4Tool::definition(), Box::new(HexPatternSignatureMatchesV4Tool)),
        (HexPatternDbRoundtripV4Tool::definition(), Box::new(HexPatternDbRoundtripV4Tool)),
        (HexPatternExporterJsonV4Tool::definition(), Box::new(HexPatternExporterJsonV4Tool)),
        (HexPatternToHexStringV3Tool::definition(), Box::new(HexPatternToHexStringV3Tool)),
        (HexPatternNfaFindAllV3Tool::definition(), Box::new(HexPatternNfaFindAllV3Tool)),
        (HexPatternNfaFindFirstV3Tool::definition(), Box::new(HexPatternNfaFindFirstV3Tool)),
        (HexPatternDfaSearchV3Tool::definition(), Box::new(HexPatternDfaSearchV3Tool)),
        (HexPatternMultiMatcherSearchV3Tool::definition(), Box::new(HexPatternMultiMatcherSearchV3Tool)),
        (HexPatternBmhSearchV3Tool::definition(), Box::new(HexPatternBmhSearchV3Tool)),
        (HexPatternByteMaskSpecificityV3Tool::definition(), Box::new(HexPatternByteMaskSpecificityV3Tool)),
        (HexPatternRangeExpandV3Tool::definition(), Box::new(HexPatternRangeExpandV3Tool)),
        (HexPatternStatisticsComputeV3Tool::definition(), Box::new(HexPatternStatisticsComputeV3Tool)),
        (HexPatternToMaskedV3Tool::definition(), Box::new(HexPatternToMaskedV3Tool)),
        (HexPatternSequenceSearchV3Tool::definition(), Box::new(HexPatternSequenceSearchV3Tool)),
    ]
}
