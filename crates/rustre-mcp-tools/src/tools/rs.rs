//! MCP wrappers for the rustre-rs crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes};

pub struct RsAnalysisStringScanAsciiTool;
impl RsAnalysisStringScanAsciiTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_analysis_string_scan_ascii".to_string(),
            description: "Scan bytes for null-terminated ASCII strings via StringScanner.".to_string(),
            input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"hex":{"type":"string"},"min_length":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RsAnalysisStringScanAsciiTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).unwrap_or(0);
        let bytes = args_to_bytes(&args).unwrap_or_default();
        let mut cfg = rustre_analysis_string::StringScannerConfig::fast();
        if let Some(m) = args.get("min_length").and_then(Value::as_u64) { cfg.min_length = m as usize; }
        let scanner = rustre_analysis_string::StringScanner::new(cfg);
        let f = scanner.scan_ascii(rustre_core::address::Address::new(base), &bytes);
        Ok(ToolResult::text(json!({"count":f.len(),"source":"rustre_analysis_string::StringScanner::scan_ascii"}).to_string()))
    }
}

pub struct RsAnalysisStringScanUtf8Tool;
impl RsAnalysisStringScanUtf8Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_analysis_string_scan_utf8".to_string(), description: "Scan bytes for UTF-8 strings.".to_string(), input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"hex":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RsAnalysisStringScanUtf8Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).unwrap_or(0);
        let bytes = args_to_bytes(&args).unwrap_or_default();
        let scanner = rustre_analysis_string::StringScanner::default();
        let f = scanner.scan_utf8(rustre_core::address::Address::new(base), &bytes);
        Ok(ToolResult::text(json!({"count":f.len(),"source":"rustre_analysis_string::StringScanner::scan_utf8"}).to_string()))
    }
}

pub struct RsAnalysisStringScanUtf16LeTool;
impl RsAnalysisStringScanUtf16LeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_analysis_string_scan_utf16_le".to_string(), description: "Scan bytes for UTF-16 LE strings.".to_string(), input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"hex":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RsAnalysisStringScanUtf16LeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).unwrap_or(0);
        let bytes = args_to_bytes(&args).unwrap_or_default();
        let scanner = rustre_analysis_string::StringScanner::default();
        let f = scanner.scan_utf16_le(rustre_core::address::Address::new(base), &bytes);
        Ok(ToolResult::text(json!({"count":f.len(),"source":"rustre_analysis_string::StringScanner::scan_utf16_le"}).to_string()))
    }
}

pub struct RsAnalysisStringScanPascalTool;
impl RsAnalysisStringScanPascalTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_analysis_string_scan_pascal".to_string(), description: "Scan bytes for Pascal-style length-prefixed strings.".to_string(), input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"hex":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RsAnalysisStringScanPascalTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).unwrap_or(0);
        let bytes = args_to_bytes(&args).unwrap_or_default();
        let scanner = rustre_analysis_string::StringScanner::default();
        let f = scanner.scan_pascal_strings(rustre_core::address::Address::new(base), &bytes);
        Ok(ToolResult::text(json!({"count":f.len(),"source":"rustre_analysis_string::StringScanner::scan_pascal_strings"}).to_string()))
    }
}

pub struct RsAnalysisStringReadCstringTool;
impl RsAnalysisStringReadCstringTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_analysis_string_read_cstring".to_string(), description: "Read a null-terminated C string at a given address.".to_string(), input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"hex":{"type":"string"},"addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RsAnalysisStringReadCstringTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).unwrap_or(0);
        let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(base);
        let bytes = args_to_bytes(&args).unwrap_or_default();
        let scanner = rustre_analysis_string::StringScanner::default();
        let r = scanner.read_cstring(rustre_core::address::Address::new(base), &bytes, rustre_core::address::Address::new(addr));
        Ok(ToolResult::text(json!({"found":r.is_some(),"value":r.as_ref().map(|s| s.value.clone()),"source":"rustre_analysis_string::StringScanner::read_cstring"}).to_string()))
    }
}

pub struct RsAnalysisStringDetectXorKeyTool;
impl RsAnalysisStringDetectXorKeyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_analysis_string_detect_xor_key".to_string(), description: "Detect single-byte XOR key from a buffer.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RsAnalysisStringDetectXorKeyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bytes = args_to_bytes(&args).unwrap_or_default();
        let k = rustre_analysis_string::detect_xor_key(&bytes);
        Ok(ToolResult::text(json!({"key":k,"source":"rustre_analysis_string::detect_xor_key"}).to_string()))
    }
}

pub struct RsAnalysisStringStatsTool;
impl RsAnalysisStringStatsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_analysis_string_stats".to_string(), description: "Compute StringStats over bytes scanned at base.".to_string(), input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"hex":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RsAnalysisStringStatsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).unwrap_or(0);
        let bytes = args_to_bytes(&args).unwrap_or_default();
        let db = rustre_analysis_string::StringDatabase::from_scan(rustre_core::address::Address::new(base), &bytes, rustre_analysis_string::StringScannerConfig::fast());
        let s = db.stats();
        Ok(ToolResult::text(json!({"total":s.total,"avg_length":s.avg_length,"max_length":s.max_length,"interesting":s.interesting_count,"classified":s.classified_count,"urls":s.url_count,"paths":s.path_count,"formats":s.format_string_count,"source":"rustre_analysis_string::StringDatabase::stats"}).to_string()))
    }
}

pub struct RsAnalysisStringEncodingInfoTool;
impl RsAnalysisStringEncodingInfoTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_analysis_string_encoding_info".to_string(), description: "Return is_unicode + min_char_bytes for a StringEncoding.".to_string(), input_schema: json!({"type":"object","properties":{"encoding":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RsAnalysisStringEncodingInfoTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let e = args.get("encoding").and_then(Value::as_str).unwrap_or("Ascii");
        use rustre_analysis_string::StringEncoding as E;
        let enc = match e {
            "Ascii" => E::Ascii, "Utf8" => E::Utf8, "Utf16Le" => E::Utf16Le, "Utf16Be" => E::Utf16Be,
            "Utf32Le" => E::Utf32Le, "Utf32Be" => E::Utf32Be, "Latin1" => E::Latin1, "ShiftJis" => E::ShiftJis,
            _ => return Err(McpError::InvalidParams(format!("unknown encoding: {e}"))),
        };
        Ok(ToolResult::text(json!({"encoding":enc.to_string(),"is_unicode":enc.is_unicode(),"min_char_bytes":enc.min_char_bytes(),"source":"rustre_analysis_string::StringEncoding"}).to_string()))
    }
}

pub struct RsAnalysisStringShannonEntropyTool;
impl RsAnalysisStringShannonEntropyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_analysis_string_shannon_entropy".to_string(), description: "Compute Shannon entropy of a string.".to_string(), input_schema: json!({"type":"object","properties":{"text":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RsAnalysisStringShannonEntropyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let t = args.get("text").and_then(Value::as_str).unwrap_or("");
        Ok(ToolResult::text(json!({"entropy":rustre_analysis_string::shannon_entropy(t.as_bytes()),"source":"rustre_analysis_string::shannon_entropy"}).to_string()))
    }
}

pub struct RsAnalysisStringExtractUrlsTool;
impl RsAnalysisStringExtractUrlsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_analysis_string_extract_urls".to_string(), description: "Extract URLs from a string.".to_string(), input_schema: json!({"type":"object","properties":{"text":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RsAnalysisStringExtractUrlsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let t = args.get("text").and_then(Value::as_str).unwrap_or("");
        let fs = vec![rustre_analysis_string::FoundString{ address: rustre_core::address::Address::new(0), length: t.len(), encoding: rustre_analysis_string::StringEncoding::Ascii, value: t.to_string(), char_count: t.chars().count(), is_null_terminated: false, xref_count: 0 }];
        let u = rustre_analysis_string::extract_urls(&fs);
        Ok(ToolResult::text(json!({"count":u.len(),"source":"rustre_analysis_string::extract_urls"}).to_string()))
    }
}

pub struct RsAnalysisStringExtractIpsTool;
impl RsAnalysisStringExtractIpsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_analysis_string_extract_ips".to_string(), description: "Extract IPv4 addresses from a string.".to_string(), input_schema: json!({"type":"object","properties":{"text":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RsAnalysisStringExtractIpsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let t = args.get("text").and_then(Value::as_str).unwrap_or("");
        let fs = vec![rustre_analysis_string::FoundString{ address: rustre_core::address::Address::new(0), length: t.len(), encoding: rustre_analysis_string::StringEncoding::Ascii, value: t.to_string(), char_count: t.chars().count(), is_null_terminated: false, xref_count: 0 }];
        let ips = rustre_analysis_string::extract_ips(&fs);
        Ok(ToolResult::text(json!({"count":ips.len(),"source":"rustre_analysis_string::extract_ips"}).to_string()))
    }
}

pub struct RsAnalysisStringLevenshteinTool;
impl RsAnalysisStringLevenshteinTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_analysis_string_levenshtein".to_string(), description: "Compute Levenshtein distance between two strings.".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RsAnalysisStringLevenshteinTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_str).unwrap_or("");
        let b = args.get("b").and_then(Value::as_str).unwrap_or("");
        Ok(ToolResult::text(json!({"distance":rustre_analysis_string::levenshtein(a,b),"similarity":rustre_analysis_string::levenshtein_similarity(a,b),"source":"rustre_analysis_string::levenshtein"}).to_string()))
    }
}

pub struct RsAnalysisStringJaroWinklerTool;
impl RsAnalysisStringJaroWinklerTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_analysis_string_jaro_winkler".to_string(), description: "Compute Jaro-Winkler similarity between two strings.".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RsAnalysisStringJaroWinklerTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_str).unwrap_or("");
        let b = args.get("b").and_then(Value::as_str).unwrap_or("");
        Ok(ToolResult::text(json!({"jaro":rustre_analysis_string::jaro(a,b),"jaro_winkler":rustre_analysis_string::jaro_winkler(a,b),"source":"rustre_analysis_string::jaro_winkler"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (RsAnalysisStringScanAsciiTool::definition(), Box::new(RsAnalysisStringScanAsciiTool)),
        (RsAnalysisStringScanUtf8Tool::definition(), Box::new(RsAnalysisStringScanUtf8Tool)),
        (RsAnalysisStringScanUtf16LeTool::definition(), Box::new(RsAnalysisStringScanUtf16LeTool)),
        (RsAnalysisStringScanPascalTool::definition(), Box::new(RsAnalysisStringScanPascalTool)),
        (RsAnalysisStringReadCstringTool::definition(), Box::new(RsAnalysisStringReadCstringTool)),
        (RsAnalysisStringDetectXorKeyTool::definition(), Box::new(RsAnalysisStringDetectXorKeyTool)),
        (RsAnalysisStringStatsTool::definition(), Box::new(RsAnalysisStringStatsTool)),
        (RsAnalysisStringEncodingInfoTool::definition(), Box::new(RsAnalysisStringEncodingInfoTool)),
        (RsAnalysisStringShannonEntropyTool::definition(), Box::new(RsAnalysisStringShannonEntropyTool)),
        (RsAnalysisStringExtractUrlsTool::definition(), Box::new(RsAnalysisStringExtractUrlsTool)),
        (RsAnalysisStringExtractIpsTool::definition(), Box::new(RsAnalysisStringExtractIpsTool)),
        (RsAnalysisStringLevenshteinTool::definition(), Box::new(RsAnalysisStringLevenshteinTool)),
        (RsAnalysisStringJaroWinklerTool::definition(), Box::new(RsAnalysisStringJaroWinklerTool)),
    ]
}
