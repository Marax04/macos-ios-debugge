//! MCP wrappers for the rustre-function crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct FunctionListByKindTool;

// ── analysis_fn_extra wrappers (appended 2026-07-12) ──────────────────────────

use async_trait::async_trait;

pub struct AnalysisFnDetectAtTool;
impl AnalysisFnDetectAtTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_fn_detect_at".to_string(), description: "Detect function boundaries from raw bytes at a given image base.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_base":{"type":"integer"},"bytes_hex":{"type":"string","description":"hex-encoded binary bytes"}},"required":["image_base","bytes_hex"]}),
            parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisFnDetectAtTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("image_base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'image_base'".into()))?;
        let hex = args.get("bytes_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'bytes_hex'".into()))?;
        let bytes: Vec<u8> = crate::hex_decode(hex)?;
        let set = rustre_analysis_fn::detect_functions_at(rustre_analysis_fn::DetectedArch::X86_64, base, &bytes);
        Ok(ToolResult::text(json!({"count": set.functions.len(), "image_base": base, "source":"rustre_analysis_fn::detect_functions_at"}).to_string()))
    }
}

pub struct AnalysisFnDetectFromPathTool;
impl AnalysisFnDetectFromPathTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_fn_detect_from_path".to_string(), description: "Detect function boundaries from a binary file path.".to_string(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}),
            parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisFnDetectFromPathTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path_str = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let path = std::path::Path::new(path_str);
        let (set, arch, base) = rustre_analysis_fn::detect_functions_from_path(path)
            .map_err(|e| McpError::InvalidParams(format!("detect_functions_from_path: {e}")))?;
        Ok(ToolResult::text(json!({"count": set.functions.len(), "arch": format!("{arch:?}"), "image_base": base, "source":"rustre_analysis_fn::detect_functions_from_path"}).to_string()))
    }
}

pub struct AnalysisFnDetectSegmentsTool;
impl AnalysisFnDetectSegmentsTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_fn_detect_segments".to_string(), description: "Detect functions from path using per-segment strategy.".to_string(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}),
            parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisFnDetectSegmentsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path_str = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let path = std::path::Path::new(path_str);
        let (_, arch, _) = rustre_analysis_fn::detect_functions_from_path(path)
            .map_err(|e| McpError::InvalidParams(format!("path load: {e}")))?;
        let funcs = rustre_analysis_fn::detect_functions_from_path_segments(path, arch)
            .map_err(|e| McpError::InvalidParams(format!("detect_segments: {e}")))?;
        Ok(ToolResult::text(json!({"count": funcs.len(), "source":"rustre_analysis_fn::detect_functions_from_path_segments"}).to_string()))
    }
}

pub struct AnalysisFnScanProloguesTool;
impl AnalysisFnScanProloguesTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_fn_scan_prologues".to_string(), description: "Scan bytes for function prologues; return candidate addresses.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_base":{"type":"integer"},"bytes_hex":{"type":"string"}},"required":["image_base","bytes_hex"]}),
            parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisFnScanProloguesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("image_base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'image_base'".into()))?;
        let hex = args.get("bytes_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'bytes_hex'".into()))?;
        let bytes: Vec<u8> = crate::hex_decode(hex)?;
        let mem = rustre_analysis_fn::MemorySlice::new(rustre_core::address::Address::new(base), &bytes);
        let detector = rustre_analysis_fn::FunctionDetector::new(rustre_analysis_fn::DetectedArch::X86_64);
        let results = detector.scan_prologues(&mem);
        let addrs: Vec<u64> = results.iter().map(|b| b.start.0).collect();
        Ok(ToolResult::text(json!({"count": addrs.len(), "addresses": addrs, "source":"rustre_analysis_fn::FunctionDetector::scan_prologues"}).to_string()))
    }
}

pub struct AnalysisFnCallTargetsTool;
impl AnalysisFnCallTargetsTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_fn_call_targets".to_string(), description: "Collect call targets by scanning CALL instructions.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_base":{"type":"integer"},"bytes_hex":{"type":"string"}},"required":["image_base","bytes_hex"]}),
            parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisFnCallTargetsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("image_base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'image_base'".into()))?;
        let hex = args.get("bytes_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'bytes_hex'".into()))?;
        let bytes: Vec<u8> = crate::hex_decode(hex)?;
        let mem = rustre_analysis_fn::MemorySlice::new(rustre_core::address::Address::new(base), &bytes);
        let detector = rustre_analysis_fn::FunctionDetector::new(rustre_analysis_fn::DetectedArch::X86_64);
        let results = detector.collect_call_targets(&mem);
        let addrs: Vec<u64> = results.iter().map(|b| b.start.0).collect();
        Ok(ToolResult::text(json!({"count": addrs.len(), "addresses": addrs, "source":"rustre_analysis_fn::FunctionDetector::collect_call_targets"}).to_string()))
    }
}

pub struct AnalysisFnMergeResultsTool;
impl AnalysisFnMergeResultsTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_fn_merge_results".to_string(), description: "Merge and deduplicate a list of function boundary addresses.".to_string(),
            input_schema: json!({"type":"object","properties":{"addresses":{"type":"array","items":{"type":"integer"}}},"required":["addresses"]}),
            parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisFnMergeResultsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addrs = args.get("addresses").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'addresses'".into()))?;
        let boundaries: Vec<rustre_analysis_fn::FunctionBoundary> = addrs.iter()
            .filter_map(|v| v.as_u64())
            .map(|a| rustre_analysis_fn::FunctionBoundary {
                start: rustre_core::address::Address::new(a),
                end: None,
                confidence: rustre_analysis_fn::Confidence::Medium,
                source: rustre_analysis_fn::DetectionSource::CallTarget,
                name: None,
            })
            .collect();
        let detector = rustre_analysis_fn::FunctionDetector::new(rustre_analysis_fn::DetectedArch::X86_64);
        let merged = detector.merge_results(boundaries);
        let out: Vec<u64> = merged.iter().map(|b| b.start.0).collect();
        Ok(ToolResult::text(json!({"count": out.len(), "addresses": out, "source":"rustre_analysis_fn::FunctionDetector::merge_results"}).to_string()))
    }
}

pub struct AnalysisFnBoundaryAtTool;
impl AnalysisFnBoundaryAtTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_fn_boundary_at".to_string(), description: "Look up a function boundary at an exact address in a boundary set.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_base":{"type":"integer"},"bytes_hex":{"type":"string"},"addr":{"type":"integer"}},"required":["image_base","bytes_hex","addr"]}),
            parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisFnBoundaryAtTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("image_base").and_then(Value::as_u64).unwrap_or(0);
        let hex = args.get("bytes_hex").and_then(Value::as_str).unwrap_or("");
        let bytes: Vec<u8> = crate::hex_decode(hex)?;
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let set = rustre_analysis_fn::detect_functions_at(rustre_analysis_fn::DetectedArch::X86_64, base, &bytes);
        let found = set.at(rustre_core::address::Address::new(addr)).map(|b| b.start.0);
        Ok(ToolResult::text(json!({"found": found, "addr": addr, "source":"rustre_analysis_fn::FunctionBoundarySet::at"}).to_string()))
    }
}

pub struct AnalysisFnBoundaryContainingTool;
impl AnalysisFnBoundaryContainingTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_fn_boundary_containing".to_string(), description: "Find the function boundary that contains a given address.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_base":{"type":"integer"},"bytes_hex":{"type":"string"},"addr":{"type":"integer"}},"required":["image_base","bytes_hex","addr"]}),
            parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisFnBoundaryContainingTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("image_base").and_then(Value::as_u64).unwrap_or(0);
        let hex = args.get("bytes_hex").and_then(Value::as_str).unwrap_or("");
        let bytes: Vec<u8> = crate::hex_decode(hex)?;
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let set = rustre_analysis_fn::detect_functions_at(rustre_analysis_fn::DetectedArch::X86_64, base, &bytes);
        let found = set.containing(rustre_core::address::Address::new(addr)).map(|b| b.start.0);
        Ok(ToolResult::text(json!({"containing_fn_start": found, "addr": addr, "source":"rustre_analysis_fn::FunctionBoundarySet::containing"}).to_string()))
    }
}

pub struct AnalysisFnHighConfidenceTool;
impl AnalysisFnHighConfidenceTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_fn_high_confidence".to_string(), description: "Return only high/certain-confidence function boundaries from a scan.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_base":{"type":"integer"},"bytes_hex":{"type":"string"}},"required":["image_base","bytes_hex"]}),
            parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisFnHighConfidenceTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("image_base").and_then(Value::as_u64).unwrap_or(0);
        let hex = args.get("bytes_hex").and_then(Value::as_str).unwrap_or("");
        let bytes: Vec<u8> = crate::hex_decode(hex)?;
        let set = rustre_analysis_fn::detect_functions_at(rustre_analysis_fn::DetectedArch::X86_64, base, &bytes);
        let hi: Vec<u64> = set.high_confidence().map(|b| b.start.0).collect();
        Ok(ToolResult::text(json!({"count": hi.len(), "addresses": hi, "source":"rustre_analysis_fn::FunctionBoundarySet::high_confidence"}).to_string()))
    }
}

pub struct AnalysisFnX86CallsTool;
impl AnalysisFnX86CallsTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_fn_x86_calls".to_string(), description: "Collect x86-64 CALL targets using CallTargetCollector.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_base":{"type":"integer"},"bytes_hex":{"type":"string"}},"required":["image_base","bytes_hex"]}),
            parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisFnX86CallsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("image_base").and_then(Value::as_u64).unwrap_or(0);
        let hex = args.get("bytes_hex").and_then(Value::as_str).unwrap_or("");
        let bytes: Vec<u8> = crate::hex_decode(hex)?;
        let mem = rustre_analysis_fn::MemorySlice::new(rustre_core::address::Address::new(base), &bytes);
        let collector = rustre_analysis_fn::CallTargetCollector::new(rustre_analysis_fn::DetectedArch::X86_64);
        let addrs: Vec<u64> = collector.collect_x86_calls(&mem).iter().map(|a| a.0).collect();
        Ok(ToolResult::text(json!({"count": addrs.len(), "addresses": addrs, "source":"rustre_analysis_fn::CallTargetCollector::collect_x86_calls"}).to_string()))
    }
}

pub struct AnalysisFnX64ProloguePatternsTool;
impl AnalysisFnX64ProloguePatternsTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_fn_x64_prologue_patterns".to_string(), description: "Return the built-in x86-64 prologue pattern list.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisFnX64ProloguePatternsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let patterns = rustre_analysis_fn::x86_64_prologue_patterns();
        let items: Vec<Value> = patterns.iter().map(|p| json!({"name": p.name, "byte_len": p.min_len()})).collect();
        Ok(ToolResult::text(json!({"count": items.len(), "patterns": items, "source":"rustre_analysis_fn::x86_64_prologue_patterns"}).to_string()))
    }
}

pub struct AnalysisFnFindGapsTool;
impl AnalysisFnFindGapsTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_fn_find_gaps".to_string(), description: "Find code gaps between known function starts.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_base":{"type":"integer"},"bytes_hex":{"type":"string"},"known_starts":{"type":"array","items":{"type":"integer"}}},"required":["image_base","bytes_hex","known_starts"]}),
            parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisFnFindGapsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("image_base").and_then(Value::as_u64).unwrap_or(0);
        let hex = args.get("bytes_hex").and_then(Value::as_str).unwrap_or("");
        let bytes: Vec<u8> = crate::hex_decode(hex)?;
        let known: Vec<rustre_core::address::Address> = args.get("known_starts").and_then(Value::as_array).unwrap_or(&vec![])
            .iter().filter_map(|v| v.as_u64()).map(rustre_core::address::Address::new).collect();
        let mem = rustre_analysis_fn::MemorySlice::new(rustre_core::address::Address::new(base), &bytes);
        let code_range = rustre_core::address::AddressRange::new(
            rustre_core::address::Address::new(base),
            rustre_core::address::Address::new(base + bytes.len() as u64),
        );
        let analyzer = rustre_analysis_fn::GapAnalyzer::new();
        let gaps = analyzer.find_gaps(&known, code_range, &mem);
        let items: Vec<Value> = gaps.iter().map(|g| json!({"start": g.start.0, "end": g.end.0})).collect();
        Ok(ToolResult::text(json!({"count": items.len(), "gaps": items, "source":"rustre_analysis_fn::GapAnalyzer::find_gaps"}).to_string()))
    }
}

pub struct AnalysisFnFirstCodeByteTool;
impl AnalysisFnFirstCodeByteTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_fn_first_code_byte".to_string(), description: "Find the first likely code byte in a gap range.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_base":{"type":"integer"},"bytes_hex":{"type":"string"},"gap_start":{"type":"integer"},"gap_end":{"type":"integer"}},"required":["image_base","bytes_hex","gap_start","gap_end"]}),
            parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisFnFirstCodeByteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("image_base").and_then(Value::as_u64).unwrap_or(0);
        let hex = args.get("bytes_hex").and_then(Value::as_str).unwrap_or("");
        let bytes: Vec<u8> = crate::hex_decode(hex)?;
        let gs = args.get("gap_start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing gap_start".into()))?;
        let ge = args.get("gap_end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing gap_end".into()))?;
        let mem = rustre_analysis_fn::MemorySlice::new(rustre_core::address::Address::new(base), &bytes);
        let gap = rustre_core::address::AddressRange::new(
            rustre_core::address::Address::new(gs),
            rustre_core::address::Address::new(ge),
        );
        let analyzer = rustre_analysis_fn::GapAnalyzer::new();
        let result = analyzer.first_code_byte(gap, &mem).map(|a| a.0);
        Ok(ToolResult::text(json!({"first_code_byte": result, "source":"rustre_analysis_fn::GapAnalyzer::first_code_byte"}).to_string()))
    }
}

pub struct AnalysisFnPrologueMatchesTool;
impl AnalysisFnPrologueMatchesTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_fn_prologue_matches".to_string(), description: "Test whether a byte slice matches any known x86-64 prologue pattern.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes_hex":{"type":"string"}},"required":["bytes_hex"]}),
            parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisFnPrologueMatchesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("bytes_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'bytes_hex'".into()))?;
        let bytes: Vec<u8> = crate::hex_decode(hex)?;
        let patterns = rustre_analysis_fn::x86_64_prologue_patterns();
        let matches: Vec<Value> = patterns.iter().filter(|p| p.matches(&bytes))
            .map(|p| json!({"name": p.name})).collect();
        Ok(ToolResult::text(json!({"matched": !matches.is_empty(), "matches": matches, "source":"rustre_analysis_fn::ProloguePattern::matches"}).to_string()))
    }
}

pub struct AnalysisFnBoundaryByteSizeTool;
impl AnalysisFnBoundaryByteSizeTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_fn_boundary_byte_size".to_string(), description: "Return the byte size of a detected function boundary, if the end address is known.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_base":{"type":"integer"},"bytes_hex":{"type":"string"},"addr":{"type":"integer"}},"required":["image_base","bytes_hex","addr"]}),
            parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisFnBoundaryByteSizeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("image_base").and_then(Value::as_u64).unwrap_or(0);
        let hex = args.get("bytes_hex").and_then(Value::as_str).unwrap_or("");
        let bytes: Vec<u8> = crate::hex_decode(hex)?;
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let set = rustre_analysis_fn::detect_functions_at(rustre_analysis_fn::DetectedArch::X86_64, base, &bytes);
        let size = set.at(rustre_core::address::Address::new(addr)).and_then(|b| b.byte_size());
        Ok(ToolResult::text(json!({"addr": addr, "byte_size": size, "source":"rustre_analysis_fn::FunctionBoundary::byte_size"}).to_string()))
    }
}

pub struct AnalysisFnArm64CallsTool;
impl AnalysisFnArm64CallsTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_fn_arm64_calls".to_string(), description: "Collect AArch64 BL/BLR call targets using CallTargetCollector.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_base":{"type":"integer"},"bytes_hex":{"type":"string"}},"required":["image_base","bytes_hex"]}),
            parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisFnArm64CallsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("image_base").and_then(Value::as_u64).unwrap_or(0);
        let hex = args.get("bytes_hex").and_then(Value::as_str).unwrap_or("");
        let bytes: Vec<u8> = crate::hex_decode(hex)?;
        let mem = rustre_analysis_fn::MemorySlice::new(rustre_core::address::Address::new(base), &bytes);
        let collector = rustre_analysis_fn::CallTargetCollector::new(rustre_analysis_fn::DetectedArch::Arm64);
        let addrs: Vec<u64> = collector.collect_arm64_calls(&mem).iter().map(|a| a.0).collect();
        Ok(ToolResult::text(json!({"count": addrs.len(), "addresses": addrs, "source":"rustre_analysis_fn::CallTargetCollector::collect_arm64_calls"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (FunctionListByKindTool::definition(), Box::new(FunctionListByKindTool)),
        (AnalysisFnDetectAtTool::definition(), Box::new(AnalysisFnDetectAtTool)),
        (AnalysisFnDetectFromPathTool::definition(), Box::new(AnalysisFnDetectFromPathTool)),
        (AnalysisFnDetectSegmentsTool::definition(), Box::new(AnalysisFnDetectSegmentsTool)),
        (AnalysisFnScanProloguesTool::definition(), Box::new(AnalysisFnScanProloguesTool)),
        (AnalysisFnCallTargetsTool::definition(), Box::new(AnalysisFnCallTargetsTool)),
        (AnalysisFnMergeResultsTool::definition(), Box::new(AnalysisFnMergeResultsTool)),
        (AnalysisFnBoundaryAtTool::definition(), Box::new(AnalysisFnBoundaryAtTool)),
        (AnalysisFnBoundaryContainingTool::definition(), Box::new(AnalysisFnBoundaryContainingTool)),
        (AnalysisFnHighConfidenceTool::definition(), Box::new(AnalysisFnHighConfidenceTool)),
        (AnalysisFnX86CallsTool::definition(), Box::new(AnalysisFnX86CallsTool)),
        (AnalysisFnArm64CallsTool::definition(), Box::new(AnalysisFnArm64CallsTool)),
        (AnalysisFnX64ProloguePatternsTool::definition(), Box::new(AnalysisFnX64ProloguePatternsTool)),
        (AnalysisFnFindGapsTool::definition(), Box::new(AnalysisFnFindGapsTool)),
        (AnalysisFnFirstCodeByteTool::definition(), Box::new(AnalysisFnFirstCodeByteTool)),
        (AnalysisFnPrologueMatchesTool::definition(), Box::new(AnalysisFnPrologueMatchesTool)),
        (AnalysisFnBoundaryByteSizeTool::definition(), Box::new(AnalysisFnBoundaryByteSizeTool)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An odd-length hex must be REFUSED — before this repair it PANICKED.
    ///
    /// These twelve tools indexed `&hex[i..i+2]` with no parity guard, so the
    /// last iteration of `"deadbee"` sliced 6..8 of a 7-byte string: not a wrong
    /// answer, a dead call. And it was reachable while respecting the published
    /// contract — 779 of 795 hex schemas in this crate declare `{"type":
    /// "string"}` and nothing more, so nothing stops a caller from sending an
    /// odd number of digits.
    ///
    /// The test cannot catch a panic across an `await`, so it asserts the
    /// opposite: an `Err` comes back. If the repair regressed, this test would
    /// not fail — it would abort the whole binary, which is itself the signal.
    #[tokio::test]
    async fn odd_length_hex_is_refused_not_a_panic() {
        let handlers = handlers();
        let mut checked = 0;
        for (def, h) in &handlers {
            let schema = def.input_schema.to_string();
            if !schema.contains("\"bytes_hex\"") {
                continue;
            }
            // Other required params get plausible values so the call reaches
            // the decoder rather than failing on a missing argument.
            let args = json!({
                "bytes_hex": "deadbee",      // 7 digits: the panicking case
                "image_base": 0x1000,
                "addr": 0x1000,
                "base": 0x1000,
                "arch": "x86_64",
                // Two tools need these as well; without them the call would fail
                // on a missing argument and the assertion would pass without
                // ever reaching the decoder. Types read from each schema:
                // known_starts is an array, gap_* are integers.
                "known_starts": [],
                "gap_start": 0,
                "gap_end": 16
            });
            assert!(
                h.call(args).await.is_err(),
                "{} accepted an odd-length hex",
                def.name
            );
            checked += 1;
        }
        assert!(checked > 0, "no tool declares bytes_hex — probe is blind");
    }
}
