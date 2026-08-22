//! MCP wrappers for the rustre-flirt_apply crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{extract_byte_array};

pub struct FlirtApplyAutoTool;

pub struct FlirtApplyCrc16Tool;

pub struct FlirtApplyLibraryMarksFromMatchesTool;

pub struct FlirtApplyCrc16FlirtWireTool;

pub struct FlirtApplyDemoSigsCountWireTool;

pub struct FlirtApplyPatternNewWireTool;
impl FlirtApplyPatternNewWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "flirt_apply_pattern_new_wire".to_string(),
            description: "Build a FlirtPattern from name+bytes and return length.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}},"required":["name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FlirtApplyPatternNewWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("f").to_string();
        let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default();
        let opts: Vec<Option<u8>> = data.iter().map(|&b| Some(b)).collect();
        let p = rustre_flirt_apply::FlirtPattern::new(name, opts);
        Ok(ToolResult::text(json!({"pattern_len": p.pattern_len(),"display": p.to_string(),"source":"rustre_flirt_apply::FlirtPattern::new"}).to_string()))
    }
}

pub struct FlirtApplyPatternMatchesWireTool;
impl FlirtApplyPatternMatchesWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "flirt_apply_pattern_matches_wire".to_string(),
            description: "Parse a FLIRT hex-pattern and test whether it matches the given data.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"data_bytes":{"type":"array","items":{"type":"integer"}},"data_hex":{"type":"string"}},"required":["pattern"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FlirtApplyPatternMatchesWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pat_str = args.get("pattern").and_then(|v| v.as_str()).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".to_string()))?;
        let data = extract_byte_array(&args, "data_bytes", "data_hex").unwrap_or_default();
        let pat = rustre_flirt_apply::FlirtPattern::from_pattern_str(pat_str, "fn".to_string(), "lib".to_string()).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        Ok(ToolResult::text(json!({"matches": pat.matches(&data),"pattern_len": pat.pattern_len(),"source":"rustre_flirt_apply::FlirtPattern::matches"}).to_string()))
    }
}

pub struct FlirtApplyPatternFromStrWireTool;
impl FlirtApplyPatternFromStrWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "flirt_apply_pattern_from_str_wire".to_string(),
            description: "Parse a FLIRT hex-pattern string into a FlirtPattern.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"name":{"type":"string"},"lib":{"type":"string"}},"required":["pattern"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FlirtApplyPatternFromStrWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pat_str = args.get("pattern").and_then(|v| v.as_str()).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".to_string()))?;
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("f").to_string();
        let lib = args.get("lib").and_then(|v| v.as_str()).unwrap_or("lib").to_string();
        let pat = rustre_flirt_apply::FlirtPattern::from_pattern_str(pat_str, name, lib).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        let wildcards = pat.bytes.iter().filter(|b| b.is_none()).count();
        Ok(ToolResult::text(json!({"pattern_len": pat.pattern_len(),"wildcards": wildcards,"lib_name": pat.lib_name,"source":"rustre_flirt_apply::FlirtPattern::from_pattern_str"}).to_string()))
    }
}

pub struct FlirtApplySignatureFromPatternWireTool;
impl FlirtApplySignatureFromPatternWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "flirt_apply_signature_from_pattern_wire".to_string(),
            description: "Convert a FLIRT hex-pattern into a FlirtSignature.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"}},"required":["pattern"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FlirtApplySignatureFromPatternWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pat_str = args.get("pattern").and_then(|v| v.as_str()).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".to_string()))?;
        let pat = rustre_flirt_apply::FlirtPattern::from_pattern_str(pat_str, "f".to_string(), "l".to_string()).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        let sig = rustre_flirt_apply::FlirtSignature::from_flirt_pattern(&pat);
        let concrete = sig.mask.iter().filter(|&&m| m != 0).count();
        Ok(ToolResult::text(json!({"bytes_len": sig.bytes.len(),"mask_len": sig.mask.len(),"concrete_bytes": concrete,"source":"rustre_flirt_apply::FlirtSignature::from_flirt_pattern"}).to_string()))
    }
}

pub struct FlirtApplySignatureMatchesAtWireTool;
impl FlirtApplySignatureMatchesAtWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "flirt_apply_signature_matches_at_wire".to_string(),
            description: "Test whether a FlirtSignature matches at start of data.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"data_bytes":{"type":"array","items":{"type":"integer"}},"data_hex":{"type":"string"}},"required":["pattern"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FlirtApplySignatureMatchesAtWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pat_str = args.get("pattern").and_then(|v| v.as_str()).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".to_string()))?;
        let data = extract_byte_array(&args, "data_bytes", "data_hex").unwrap_or_default();
        let pat = rustre_flirt_apply::FlirtPattern::from_pattern_str(pat_str, "f".to_string(), "l".to_string()).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        let sig = rustre_flirt_apply::FlirtSignature::from_flirt_pattern(&pat);
        Ok(ToolResult::text(json!({"matches_at": sig.matches_at(&data),"source":"rustre_flirt_apply::FlirtSignature::matches_at"}).to_string()))
    }
}

pub struct FlirtApplyWildcardPrefixWireTool;
impl FlirtApplyWildcardPrefixWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "flirt_apply_wildcard_prefix_wire".to_string(),
            description: "Return length of the longest concrete prefix of a FLIRT signature.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"}},"required":["pattern"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FlirtApplyWildcardPrefixWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pat_str = args.get("pattern").and_then(|v| v.as_str()).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".to_string()))?;
        let pat = rustre_flirt_apply::FlirtPattern::from_pattern_str(pat_str, "f".to_string(), "l".to_string()).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        let sig = rustre_flirt_apply::FlirtSignature::from_flirt_pattern(&pat);
        let wp = rustre_flirt_apply::WildcardPattern::from_signature(&sig);
        Ok(ToolResult::text(json!({"prefix_len": wp.prefix().len(),"source":"rustre_flirt_apply::WildcardPattern::from_signature"}).to_string()))
    }
}

pub struct FlirtApplySigDbAddCountWireTool;
impl FlirtApplySigDbAddCountWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "flirt_apply_sig_db_add_count_wire".to_string(),
            description: "Build empty FlirtSigDb, add pattern, return count.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"}},"required":["pattern"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FlirtApplySigDbAddCountWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pat_str = args.get("pattern").and_then(|v| v.as_str()).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".to_string()))?;
        let pat = rustre_flirt_apply::FlirtPattern::from_pattern_str(pat_str, "f".to_string(), "l".to_string()).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        let mut db = rustre_flirt_apply::FlirtSigDb::new();
        db.add_pattern(pat);
        Ok(ToolResult::text(json!({"pattern_count": db.pattern_count(),"source":"rustre_flirt_apply::FlirtSigDb::add_pattern"}).to_string()))
    }
}

pub struct FlirtApplyScanBytesDemoWireTool;
impl FlirtApplyScanBytesDemoWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "flirt_apply_scan_bytes_demo_wire".to_string(),
            description: "Run FlirtApplier::scan_bytes over bytes using demo sig DB.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"base_addr":{"type":"integer"},"min_confidence":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FlirtApplyScanBytesDemoWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default();
        let base = args.get("base_addr").and_then(|v| v.as_u64()).unwrap_or(0);
        let mc = args.get("min_confidence").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
        let db = rustre_flirt_apply::FlirtSigDb::load_demo_sigs();
        let hits = rustre_flirt_apply::FlirtApplier::scan_bytes(&data, &db, base, mc);
        Ok(ToolResult::text(json!({"hits": hits.len(),"source":"rustre_flirt_apply::FlirtApplier::scan_bytes"}).to_string()))
    }
}

pub struct FlirtApplyAcIndexBuiltWireTool;
impl FlirtApplyAcIndexBuiltWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "flirt_apply_ac_index_built_wire".to_string(),
            description: "Build AhoCorasickIndex from a FLIRT pattern and return is_built.".to_string(),
            input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"}},"required":["pattern"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FlirtApplyAcIndexBuiltWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pat_str = args.get("pattern").and_then(|v| v.as_str()).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".to_string()))?;
        let pat = rustre_flirt_apply::FlirtPattern::from_pattern_str(pat_str, "f".to_string(), "l".to_string()).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        let sig = rustre_flirt_apply::FlirtSignature::from_flirt_pattern(&pat);
        let sigs = vec![sig];
        let idx = rustre_flirt_apply::AhoCorasickIndex::build(&sigs);
        Ok(ToolResult::text(json!({"is_built": idx.is_built(),"source":"rustre_flirt_apply::AhoCorasickIndex::build"}).to_string()))
    }
}

pub struct FlirtApplyApplierMatchCountWireTool;
impl FlirtApplyApplierMatchCountWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "flirt_apply_applier_match_count_wire".to_string(),
            description: "Run FlirtApplier over bytes using demo sig DB, return match_count.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"base_addr":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FlirtApplyApplierMatchCountWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default();
        let base = args.get("base_addr").and_then(|v| v.as_u64()).unwrap_or(0);
        let db = rustre_flirt_apply::FlirtSigDb::load_demo_sigs();
        let applier = rustre_flirt_apply::FlirtApplier::new(db);
        Ok(ToolResult::text(json!({"match_count": applier.match_count(&data, base),"source":"rustre_flirt_apply::FlirtApplier::match_count"}).to_string()))
    }
}

pub struct FlirtApplyResolveRenamesWireTool;
impl FlirtApplyResolveRenamesWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "flirt_apply_resolve_renames_wire".to_string(),
            description: "Resolve FlirtMatches into deduplicated renames via resolve_renames.".to_string(),
            input_schema: json!({"type":"object","properties":{"matches":{"type":"array","items":{"type":"object"}},"min_confidence":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FlirtApplyResolveRenamesWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mc = args.get("min_confidence").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
        let arr = args.get("matches").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let mut ms: Vec<rustre_flirt_apply::FlirtMatch> = Vec::new();
        for v in arr {
            ms.push(rustre_flirt_apply::FlirtMatch {
                address: v.get("address").and_then(|x| x.as_u64()).unwrap_or(0),
                function_name: v.get("function_name").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                lib_name: v.get("lib_name").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                confidence: v.get("confidence").and_then(|x| x.as_u64()).unwrap_or(0) as u8,
                pattern_length: v.get("pattern_length").and_then(|x| x.as_u64()).unwrap_or(0) as usize,
            });
        }
        let (renames, stats) = rustre_flirt_apply::resolve_renames(&ms, mc);
        Ok(ToolResult::text(json!({"renames": renames.len(),"scanned": stats.scanned,"matched": stats.matched,"applied": stats.applied,"skipped": stats.skipped,"source":"rustre_flirt_apply::resolve_renames"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (FlirtApplyAutoTool::definition(), Box::new(FlirtApplyAutoTool)),
        (FlirtApplyCrc16Tool::definition(), Box::new(FlirtApplyCrc16Tool)),
        (FlirtApplyLibraryMarksFromMatchesTool::definition(), Box::new(FlirtApplyLibraryMarksFromMatchesTool)),
        (FlirtApplyCrc16FlirtWireTool::definition(), Box::new(FlirtApplyCrc16FlirtWireTool)),
        (FlirtApplyDemoSigsCountWireTool::definition(), Box::new(FlirtApplyDemoSigsCountWireTool)),
        (FlirtApplyPatternNewWireTool::definition(), Box::new(FlirtApplyPatternNewWireTool)),
        (FlirtApplyPatternMatchesWireTool::definition(), Box::new(FlirtApplyPatternMatchesWireTool)),
        (FlirtApplyPatternFromStrWireTool::definition(), Box::new(FlirtApplyPatternFromStrWireTool)),
        (FlirtApplySignatureFromPatternWireTool::definition(), Box::new(FlirtApplySignatureFromPatternWireTool)),
        (FlirtApplySignatureMatchesAtWireTool::definition(), Box::new(FlirtApplySignatureMatchesAtWireTool)),
        (FlirtApplyWildcardPrefixWireTool::definition(), Box::new(FlirtApplyWildcardPrefixWireTool)),
        (FlirtApplySigDbAddCountWireTool::definition(), Box::new(FlirtApplySigDbAddCountWireTool)),
        (FlirtApplyScanBytesDemoWireTool::definition(), Box::new(FlirtApplyScanBytesDemoWireTool)),
        (FlirtApplyAcIndexBuiltWireTool::definition(), Box::new(FlirtApplyAcIndexBuiltWireTool)),
        (FlirtApplyApplierMatchCountWireTool::definition(), Box::new(FlirtApplyApplierMatchCountWireTool)),
        (FlirtApplyResolveRenamesWireTool::definition(), Box::new(FlirtApplyResolveRenamesWireTool)),
    ]
}
