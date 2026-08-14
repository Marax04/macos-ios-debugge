//! MCP wrappers for the rustre-triage_entropy crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{extract_byte_array};

pub struct TriageEntropyPackingIndicatorsTool;

pub struct TriageEntropyShannonPathTool;

pub struct TriageEntropyShannonF32PathTool;

pub struct TriageEntropyAnalyzeBlocksPathTool;

pub struct TriageEntropyReportPathTool;

pub struct TriageEntropyHistogramPathTool;

pub struct TriageEntropySurveyBinaryPathTool;

pub struct TriageEntropyClassifyTool;

pub struct TriageEntropyColorRgbTool;

pub struct TriageEntropyRatingFromEntropyTool;
impl TriageEntropyRatingFromEntropyTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_rating_from_entropy".to_string(),
            description: "Classify a Shannon entropy value into a qualitative EntropyRating.".to_string(),
            input_schema: json!({"type":"object","properties":{"entropy":{"type":"number"}},"required":["entropy"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyRatingFromEntropyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let e = args.get("entropy").and_then(Value::as_f64)
            .ok_or_else(|| McpError::InvalidParams("missing 'entropy'".to_string()))?;
        let r = rustre_triage_entropy::EntropyRating::from_entropy(e);
        Ok(ToolResult::text(json!({"entropy": e, "rating": r.to_string()}).to_string()))
    }
}

pub struct TriageEntropySectionNewTool;
impl TriageEntropySectionNewTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_section_new_path".to_string(),
            description: "Read a slice from a file and build SectionEntropy.".to_string(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"name":{"type":"string"},"offset":{"type":"integer"},"size":{"type":"integer"}},"required":["path","name","offset","size"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropySectionNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args.get("path").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".to_string()))?;
        let name = args.get("name").and_then(Value::as_str).unwrap_or("section");
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
        let size = args.get("size").and_then(Value::as_u64).unwrap_or(0) as usize;
        let data = std::fs::read(path).map_err(|e| McpError::InternalError(e.to_string()))?;
        let end = offset.saturating_add(size).min(data.len());
        let slice: &[u8] = if offset < data.len() { &data[offset..end] } else { &[] };
        let se = rustre_triage_entropy::SectionEntropy::new(name, slice, offset);
        Ok(ToolResult::text(json!({
            "name": se.name, "entropy": se.entropy, "size": se.size, "offset": se.offset,
            "rating": se.rating.to_string(),
            "is_packed": se.is_packed(), "is_encrypted": se.is_encrypted()
        }).to_string()))
    }
}

pub struct TriageEntropyAnalyzerAnalyzePathTool;
impl TriageEntropyAnalyzerAnalyzePathTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_analyzer_analyze_path".to_string(),
            description: "Run EntropyAnalyzer::analyze over a file.".to_string(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"chunk_size":{"type":"integer"}},"required":["path"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyAnalyzerAnalyzePathTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args.get("path").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".to_string()))?;
        let chunk_size = args.get("chunk_size").and_then(Value::as_u64).unwrap_or(4096) as usize;
        let data = std::fs::read(path).map_err(|e| McpError::InternalError(e.to_string()))?;
        let a = rustre_triage_entropy::EntropyAnalyzer::new(chunk_size);
        let r = a.analyze(&data);
        Ok(ToolResult::text(json!({
            "overall": r.overall, "rating": r.rating.to_string(),
            "chunks": r.chunks.len(), "max_chunk_entropy": r.max_chunk_entropy(),
        }).to_string()))
    }
}

pub struct TriageEntropyCategoryLabelTool;
impl TriageEntropyCategoryLabelTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_category_label".to_string(),
            description: "Return the short label for an EntropyCategory from an f32 entropy value.".to_string(),
            input_schema: json!({"type":"object","properties":{"entropy":{"type":"number"}},"required":["entropy"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyCategoryLabelTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let e = args.get("entropy").and_then(Value::as_f64)
            .ok_or_else(|| McpError::InvalidParams("missing 'entropy'".to_string()))? as f32;
        let c = rustre_triage_entropy::EntropyCategory::classify(e);
        Ok(ToolResult::text(json!({"entropy": e, "label": c.label()}).to_string()))
    }
}

pub struct TriageEntropyBlockFromSlicePathTool;
impl TriageEntropyBlockFromSlicePathTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_block_from_slice_path".to_string(),
            description: "Build an EntropyBlock for a byte range within a file.".to_string(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"offset":{"type":"integer"},"size":{"type":"integer"}},"required":["path","offset","size"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyBlockFromSlicePathTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args.get("path").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".to_string()))?;
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let size = args.get("size").and_then(Value::as_u64).unwrap_or(0) as usize;
        let data = std::fs::read(path).map_err(|e| McpError::InternalError(e.to_string()))?;
        let off_us = offset as usize;
        let end = off_us.saturating_add(size).min(data.len());
        let slice: &[u8] = if off_us < data.len() { &data[off_us..end] } else { &[] };
        let b = rustre_triage_entropy::EntropyBlock::from_slice(offset, slice);
        Ok(ToolResult::text(json!({
            "offset": b.offset, "size": b.size, "entropy": b.entropy,
            "category": b.category.label(),
        }).to_string()))
    }
}

pub struct TriageEntropyAnalyzeWithSectionsPathTool;
impl TriageEntropyAnalyzeWithSectionsPathTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_analyze_with_sections_path".to_string(),
            description: "Call analyze_with_sections on a file using caller SectionDescriptors.".to_string(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"sections":{"type":"array"}},"required":["path","sections"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyAnalyzeWithSectionsPathTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args.get("path").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".to_string()))?;
        let secs_val = args.get("sections").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'sections'".to_string()))?;
        let data = std::fs::read(path).map_err(|e| McpError::InternalError(e.to_string()))?;
        let descs: Vec<rustre_triage_entropy::SectionDescriptor> = secs_val.iter().map(|v| {
            rustre_triage_entropy::SectionDescriptor {
                name: v.get("name").and_then(Value::as_str).unwrap_or("").to_string(),
                raw_offset: v.get("raw_offset").and_then(Value::as_u64).unwrap_or(0),
                raw_size: v.get("raw_size").and_then(Value::as_u64).unwrap_or(0),
            }
        }).collect();
        let blocks = rustre_triage_entropy::analyze_with_sections(&data, &descs);
        Ok(ToolResult::text(json!({
            "blocks": blocks.iter().map(|b| json!({
                "offset": b.offset, "size": b.size, "entropy": b.entropy, "category": b.category.label(),
            })).collect::<Vec<_>>(),
            "count": blocks.len(),
        }).to_string()))
    }
}

pub struct TriageEntropyHistogramChiSquarePathTool;
impl TriageEntropyHistogramChiSquarePathTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_histogram_chi_square_path".to_string(),
            description: "Compute chi-square statistic from a file's byte histogram.".to_string(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyHistogramChiSquarePathTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args.get("path").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".to_string()))?;
        let data = std::fs::read(path).map_err(|e| McpError::InternalError(e.to_string()))?;
        let h = rustre_triage_entropy::ByteHistogram::new(&data);
        Ok(ToolResult::text(json!({
            "total": h.total,
            "chi_square": h.chi_square_statistic(),
            "is_likely_random": h.is_likely_random(),
        }).to_string()))
    }
}

pub struct TriageEntropyHistogramMostCommonPathTool;
impl TriageEntropyHistogramMostCommonPathTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_histogram_most_common_path".to_string(),
            description: "Return N most-frequent byte values in a file's histogram.".to_string(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"n":{"type":"integer"}},"required":["path"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyHistogramMostCommonPathTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args.get("path").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".to_string()))?;
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(16) as usize;
        let data = std::fs::read(path).map_err(|e| McpError::InternalError(e.to_string()))?;
        let h = rustre_triage_entropy::ByteHistogram::new(&data);
        let top = h.most_common_bytes(n);
        Ok(ToolResult::text(json!({
            "top": top.iter().map(|(b, c)| json!({"byte": b, "count": c})).collect::<Vec<_>>(),
        }).to_string()))
    }
}

pub struct TriageEntropyHeatmapAsciiPathTool;
impl TriageEntropyHeatmapAsciiPathTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_heatmap_ascii_path".to_string(),
            description: "Render HeatmapData::to_ascii_heatmap for a file.".to_string(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"block_size":{"type":"integer"},"width":{"type":"integer"}},"required":["path"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyHeatmapAsciiPathTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args.get("path").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".to_string()))?;
        let block_size = args.get("block_size").and_then(Value::as_u64).unwrap_or(512) as usize;
        let width = args.get("width").and_then(Value::as_u64).unwrap_or(80) as usize;
        let data = std::fs::read(path).map_err(|e| McpError::InternalError(e.to_string()))?;
        let hm = rustre_triage_entropy::HeatmapData::from_data(&data, block_size);
        let art = hm.to_ascii_heatmap(width);
        Ok(ToolResult::text(json!({"ascii": art, "blocks": hm.blocks.len()}).to_string()))
    }
}

pub struct TriageEntropyHeatmapRgbColorsPathTool;
impl TriageEntropyHeatmapRgbColorsPathTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_heatmap_rgb_colors_path".to_string(),
            description: "Return per-block RGB heatmap colours for a file.".to_string(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"block_size":{"type":"integer"}},"required":["path"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyHeatmapRgbColorsPathTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args.get("path").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".to_string()))?;
        let block_size = args.get("block_size").and_then(Value::as_u64).unwrap_or(512) as usize;
        let data = std::fs::read(path).map_err(|e| McpError::InternalError(e.to_string()))?;
        let hm = rustre_triage_entropy::HeatmapData::from_data(&data, block_size);
        let colors = hm.to_rgb_colors();
        Ok(ToolResult::text(json!({
            "count": colors.len(),
            "colors": colors.iter().map(|c| json!([c[0], c[1], c[2]])).collect::<Vec<_>>(),
        }).to_string()))
    }
}

pub struct TriageEntropyReportHighBlocksPathTool;
impl TriageEntropyReportHighBlocksPathTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_report_high_blocks_path".to_string(),
            description: "Generate an EntropyReport for a file and return blocks above threshold.".to_string(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"threshold":{"type":"number"},"block_size":{"type":"integer"}},"required":["path"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyReportHighBlocksPathTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args.get("path").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".to_string()))?;
        let threshold = args.get("threshold").and_then(Value::as_f64).unwrap_or(7.0) as f32;
        let block_size = args.get("block_size").and_then(Value::as_u64).unwrap_or(512) as usize;
        let data = std::fs::read(path).map_err(|e| McpError::InternalError(e.to_string()))?;
        let rep = rustre_triage_entropy::EntropyReport::generate_with_block_size(&data, block_size);
        let high = rep.high_entropy_blocks(threshold);
        Ok(ToolResult::text(json!({
            "threshold": threshold,
            "count": high.len(),
            "summary": rep.summary(),
            "high_offsets": high.iter().map(|b| b.offset).collect::<Vec<_>>(),
        }).to_string()))
    }
}

pub struct TriageEntropyShannonBytesTool;

pub struct TriageEntropyShannonBytesF32Tool;

pub struct TriageEntropyShannonF32BytesTool;
impl TriageEntropyShannonF32BytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_shannon_f32_bytes".to_string(),
            description: "Compute Shannon entropy (f32) of raw bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyShannonF32BytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let e = rustre_triage_entropy::shannon_entropy_f32(&data);
        Ok(ToolResult::text(json!({"entropy": e, "size": data.len(), "source":"rustre_triage_entropy::shannon_entropy_f32"}).to_string()))
    }
}

pub struct TriageEntropyCategoryClassifyBytesTool;
impl TriageEntropyCategoryClassifyBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_category_classify_bytes".to_string(),
            description: "Classify entropy category directly from raw bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyCategoryClassifyBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let e = rustre_triage_entropy::shannon_entropy_f32(&data);
        let cat = rustre_triage_entropy::EntropyCategory::classify(e);
        Ok(ToolResult::text(json!({"entropy": e, "category": cat.label(), "source":"rustre_triage_entropy::EntropyCategory::classify"}).to_string()))
    }
}

pub struct TriageEntropyRatingFromBytesTool;
impl TriageEntropyRatingFromBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_rating_from_bytes".to_string(),
            description: "Compute EntropyRating from raw bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyRatingFromBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let e = rustre_triage_entropy::shannon_entropy(&data);
        let r = rustre_triage_entropy::EntropyRating::from_entropy(e);
        Ok(ToolResult::text(json!({"entropy": e, "rating": r.to_string(), "source":"rustre_triage_entropy::EntropyRating::from_entropy"}).to_string()))
    }
}

pub struct TriageEntropyHistogramNewBytesTool;
impl TriageEntropyHistogramNewBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_histogram_new_bytes".to_string(),
            description: "Build ByteHistogram and return total + chi-square.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyHistogramNewBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let h = rustre_triage_entropy::ByteHistogram::new(&data);
        Ok(ToolResult::text(json!({"total": h.total, "chi_square": h.chi_square_statistic(), "is_random": h.is_likely_random(), "source":"rustre_triage_entropy::ByteHistogram::new"}).to_string()))
    }
}

pub struct TriageEntropyHistogramMostCommonBytesTool;
impl TriageEntropyHistogramMostCommonBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_histogram_most_common_bytes".to_string(),
            description: "Return top-N most-frequent byte values from raw bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"n":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyHistogramMostCommonBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(5) as usize;
        let h = rustre_triage_entropy::ByteHistogram::new(&data);
        let top = h.most_common_bytes(n);
        let out: Vec<Value> = top.iter().map(|(b,c)| json!({"byte": b, "count": c})).collect();
        Ok(ToolResult::text(json!({"top": out, "source":"rustre_triage_entropy::ByteHistogram::most_common_bytes"}).to_string()))
    }
}

pub struct TriageEntropyHeatmapFromDataBytesTool;
impl TriageEntropyHeatmapFromDataBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_heatmap_from_data_bytes".to_string(),
            description: "Build a HeatmapData from bytes; return block count.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"block_size":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyHeatmapFromDataBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let bs = args.get("block_size").and_then(Value::as_u64).unwrap_or(64) as usize;
        let hm = rustre_triage_entropy::HeatmapData::from_data(&data, bs);
        Ok(ToolResult::text(json!({"block_count": hm.blocks.len(), "block_size": bs, "source":"rustre_triage_entropy::HeatmapData::from_data"}).to_string()))
    }
}

pub struct TriageEntropyHeatmapAsciiBytesTool;
impl TriageEntropyHeatmapAsciiBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_heatmap_ascii_bytes".to_string(),
            description: "Render ASCII heatmap of bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"block_size":{"type":"integer"},"width":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyHeatmapAsciiBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let bs = args.get("block_size").and_then(Value::as_u64).unwrap_or(64) as usize;
        let w = args.get("width").and_then(Value::as_u64).unwrap_or(40) as usize;
        let hm = rustre_triage_entropy::HeatmapData::from_data(&data, bs);
        let art = hm.to_ascii_heatmap(w);
        Ok(ToolResult::text(json!({"ascii_len": art.len(), "width": w, "source":"rustre_triage_entropy::HeatmapData::to_ascii_heatmap"}).to_string()))
    }
}

pub struct TriageEntropyHeatmapRgbBytesTool;
impl TriageEntropyHeatmapRgbBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_heatmap_rgb_bytes".to_string(),
            description: "Return RGB color count for each block of bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"block_size":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyHeatmapRgbBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let bs = args.get("block_size").and_then(Value::as_u64).unwrap_or(64) as usize;
        let hm = rustre_triage_entropy::HeatmapData::from_data(&data, bs);
        let colors = hm.to_rgb_colors();
        Ok(ToolResult::text(json!({"color_count": colors.len(), "source":"rustre_triage_entropy::HeatmapData::to_rgb_colors"}).to_string()))
    }
}

pub struct TriageEntropyAnalyzerAnalyzeBytesTool;
impl TriageEntropyAnalyzerAnalyzeBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_analyzer_analyze_bytes".to_string(),
            description: "Run EntropyAnalyzer::analyze on raw bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"chunk_size":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyAnalyzerAnalyzeBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let cs = args.get("chunk_size").and_then(Value::as_u64).unwrap_or(256) as usize;
        let a = rustre_triage_entropy::EntropyAnalyzer::new(cs);
        let r = a.analyze(&data);
        Ok(ToolResult::text(json!({"overall": r.overall, "rating": r.rating.to_string(), "chunks": r.chunks.len(), "max_chunk_entropy": r.max_chunk_entropy(), "source":"rustre_triage_entropy::EntropyAnalyzer::analyze"}).to_string()))
    }
}

pub struct TriageEntropyAnalyzeWithSectionsBytesTool;
impl TriageEntropyAnalyzeWithSectionsBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_analyze_with_sections_bytes".to_string(),
            description: "analyze_with_sections on bytes with one whole-buffer section.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyAnalyzeWithSectionsBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let secs = vec![rustre_triage_entropy::SectionDescriptor {
            name: ".full".to_string(),
            raw_offset: 0,
            raw_size: data.len() as u64,
        }];
        let out = rustre_triage_entropy::analyze_with_sections(&data, &secs);
        let max = out.iter().map(|b| b.entropy).fold(0.0_f32, f32::max);
        Ok(ToolResult::text(json!({"block_count": out.len(), "max_entropy": max, "source":"rustre_triage_entropy::analyze_with_sections"}).to_string()))
    }
}

pub struct TriageEntropyReportGenerateBytesTool;
impl TriageEntropyReportGenerateBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_report_generate_bytes".to_string(),
            description: "Generate EntropyReport from bytes with a custom block size.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"block_size":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyReportGenerateBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let bs = args.get("block_size").and_then(Value::as_u64).unwrap_or(512) as usize;
        let r = rustre_triage_entropy::EntropyReport::generate_with_block_size(&data, bs);
        Ok(ToolResult::text(json!({"overall_entropy": r.overall_entropy, "category": r.category.label(), "is_likely_packed": r.is_likely_packed, "packing_indicators": r.packing_indicators.len(), "sections": r.sections.len(), "source":"rustre_triage_entropy::EntropyReport::generate_with_block_size"}).to_string()))
    }
}

pub struct TriageEntropyPackingIndicatorsBytesTool;
impl TriageEntropyPackingIndicatorsBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_packing_indicators_bytes".to_string(),
            description: "Run PackingDetector::detect_packing_indicators on raw bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyPackingIndicatorsBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let ind = rustre_triage_entropy::PackingDetector::detect_packing_indicators(&data);
        Ok(ToolResult::text(json!({"indicator_count": ind.len(), "indicators": ind, "source":"rustre_triage_entropy::PackingDetector::detect_packing_indicators"}).to_string()))
    }
}

pub struct TriageEntropyReportHeatmapBytesTool;
impl TriageEntropyReportHeatmapBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_entropy_report_heatmap_bytes".to_string(), description: "Generate EntropyReport from bytes and return HeatmapData block count.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageEntropyReportHeatmapBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex")?; let rep = rustre_triage_entropy::EntropyReport::generate(&data); let hm = rep.heatmap(); Ok(ToolResult::text(json!({"block_count": hm.blocks.len(), "source":"rustre_triage_entropy::EntropyReport::heatmap"}).to_string())) } }

pub struct TriageEntropyReportHighBlocksBytesTool;
impl TriageEntropyReportHighBlocksBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_entropy_report_high_blocks_bytes".to_string(), description: "EntropyReport::high_entropy_blocks from raw bytes.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"threshold":{"type":"number"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageEntropyReportHighBlocksBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex")?; let th = args.get("threshold").and_then(Value::as_f64).unwrap_or(7.0) as f32; let rep = rustre_triage_entropy::EntropyReport::generate(&data); let hi = rep.high_entropy_blocks(th); Ok(ToolResult::text(json!({"high_block_count": hi.len(), "threshold": th, "source":"rustre_triage_entropy::EntropyReport::high_entropy_blocks"}).to_string())) } }

pub struct TriageEntropyReportSummaryPathTool;
impl TriageEntropyReportSummaryPathTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_entropy_report_summary_path".to_string(), description: "Load path bytes, generate EntropyReport, return summary().".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageEntropyReportSummaryPathTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let path = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing path".into()))?; let data = std::fs::read(path).map_err(|e| McpError::InternalError(e.to_string()))?; let rep = rustre_triage_entropy::EntropyReport::generate(&data); Ok(ToolResult::text(json!({"summary": rep.summary(), "source":"rustre_triage_entropy::EntropyReport::summary"}).to_string())) } }

pub struct TriageEntropyResultPackedSectionsBytesTool;
impl TriageEntropyResultPackedSectionsBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_entropy_result_packed_sections_bytes".to_string(), description: "EntropyAnalyzer analyze bytes then EntropyResult::packed_sections count.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"chunk_size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageEntropyResultPackedSectionsBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex")?; let cs = args.get("chunk_size").and_then(Value::as_u64).unwrap_or(4096) as usize; let a = rustre_triage_entropy::EntropyAnalyzer::new(cs); let r = a.analyze(&data); Ok(ToolResult::text(json!({"packed_section_count": r.packed_sections().len(), "chunks": r.chunks.len(), "source":"rustre_triage_entropy::EntropyResult::packed_sections"}).to_string())) } }

pub struct TriageEntropyAnalyzerNewTool;
impl TriageEntropyAnalyzerNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_entropy_analyzer_new".to_string(), description: "Construct EntropyAnalyzer::new and echo chunk_size.".to_string(), input_schema: json!({"type":"object","properties":{"chunk_size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageEntropyAnalyzerNewTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cs = args.get("chunk_size").and_then(Value::as_u64).unwrap_or(4096) as usize; let a = rustre_triage_entropy::EntropyAnalyzer::new(cs); Ok(ToolResult::text(json!({"chunk_size": a.chunk_size, "source":"rustre_triage_entropy::EntropyAnalyzer::new"}).to_string())) } }

pub struct TriageEntropyReportDisplayPathTool;
impl TriageEntropyReportDisplayPathTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_entropy_report_display_path".to_string(), description: "Load path, generate EntropyReport, return Display text length.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageEntropyReportDisplayPathTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let path = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing path".into()))?; let data = std::fs::read(path).map_err(|e| McpError::InternalError(e.to_string()))?; let rep = rustre_triage_entropy::EntropyReport::generate(&data); let s = format!("{rep}"); Ok(ToolResult::text(json!({"display_len": s.len(), "source":"rustre_triage_entropy::EntropyReport::fmt"}).to_string())) } }

pub struct TriageEntropyShannonAliasTool;
impl TriageEntropyShannonAliasTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_entropy_shannon_alias".to_string(), description: "Alias for shannon_entropy(bytes) returning f64.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageEntropyShannonAliasTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex")?; let h = rustre_triage_entropy::shannon_entropy(&data); Ok(ToolResult::text(json!({"entropy": h, "size": data.len(), "source":"rustre_triage_entropy::shannon_entropy"}).to_string())) } }

pub struct TriageEntropyResultOverallBytesTool;
impl TriageEntropyResultOverallBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_entropy_result_overall_bytes".to_string(), description: "EntropyAnalyzer analyze bytes then return overall entropy.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"chunk_size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageEntropyResultOverallBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex")?; let cs = args.get("chunk_size").and_then(Value::as_u64).unwrap_or(4096) as usize; let r = rustre_triage_entropy::EntropyAnalyzer::new(cs).analyze(&data); Ok(ToolResult::text(json!({"overall": r.overall, "rating": r.rating.to_string(), "source":"rustre_triage_entropy::EntropyResult"}).to_string())) } }

pub struct TriageEntropyReportIndicatorsBytesTool;
impl TriageEntropyReportIndicatorsBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_entropy_report_indicators_bytes".to_string(), description: "Generate EntropyReport from bytes; return packing_indicators list.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageEntropyReportIndicatorsBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex")?; let rep = rustre_triage_entropy::EntropyReport::generate(&data); Ok(ToolResult::text(json!({"indicator_count": rep.packing_indicators.len(), "indicators": rep.packing_indicators, "is_likely_packed": rep.is_likely_packed, "source":"rustre_triage_entropy::EntropyReport"}).to_string())) } }

pub struct TriageEntropyHistogramChiSquareBytesTool;
impl TriageEntropyHistogramChiSquareBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_entropy_histogram_chi_square_bytes".to_string(), description: "ByteHistogram::chi_square_statistic on raw bytes.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageEntropyHistogramChiSquareBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex")?; let h = rustre_triage_entropy::ByteHistogram::new(&data); Ok(ToolResult::text(json!({"chi_square": h.chi_square_statistic(), "is_likely_random": h.is_likely_random(), "source":"rustre_triage_entropy::ByteHistogram::chi_square_statistic"}).to_string())) } }

pub struct TriageEntropyRatingDisplayTool;
impl TriageEntropyRatingDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_rating_display_from_entropy".to_string(),
            description: "Classify entropy via rustre_triage_entropy::EntropyRating::from_entropy and Display.".to_string(),
            input_schema: json!({ "type":"object", "properties": { "entropy": { "type":"number" } }, "required": ["entropy"] }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyRatingDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let e = args.get("entropy").and_then(Value::as_f64)
            .ok_or_else(|| McpError::InvalidParams("missing 'entropy'".to_string()))?;
        let r = rustre_triage_entropy::EntropyRating::from_entropy(e);
        Ok(ToolResult::text(json!({ "entropy": e, "rating": r.to_string(), "source": "rustre_triage_entropy::EntropyRating::from_entropy" }).to_string()))
    }
}

pub struct TriageEntropySectionIsPackedBytesTool;
impl TriageEntropySectionIsPackedBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_section_is_packed_bytes".to_string(),
            description: "Build SectionEntropy from raw bytes and return is_packed.".to_string(),
            input_schema: json!({ "type":"object", "properties": { "bytes": { "type":"array", "items": { "type":"integer" } }, "hex": { "type":"string" }, "name": { "type":"string" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropySectionIsPackedBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let name = args.get("name").and_then(Value::as_str).unwrap_or(".text");
        let se = rustre_triage_entropy::SectionEntropy::new(name, &data, 0);
        Ok(ToolResult::text(json!({ "name": se.name, "entropy": se.entropy, "size": se.size, "is_packed": se.is_packed(), "source": "rustre_triage_entropy::SectionEntropy::is_packed" }).to_string()))
    }
}

pub struct TriageEntropySectionIsEncryptedBytesTool;
impl TriageEntropySectionIsEncryptedBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_section_is_encrypted_bytes".to_string(),
            description: "Build SectionEntropy from raw bytes and return is_encrypted.".to_string(),
            input_schema: json!({ "type":"object", "properties": { "bytes": { "type":"array", "items": { "type":"integer" } }, "hex": { "type":"string" }, "name": { "type":"string" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropySectionIsEncryptedBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let name = args.get("name").and_then(Value::as_str).unwrap_or(".text");
        let se = rustre_triage_entropy::SectionEntropy::new(name, &data, 0);
        Ok(ToolResult::text(json!({ "name": se.name, "entropy": se.entropy, "size": se.size, "is_encrypted": se.is_encrypted(), "source": "rustre_triage_entropy::SectionEntropy::is_encrypted" }).to_string()))
    }
}

pub struct TriageEntropyResultMaxChunkBytesTool;
impl TriageEntropyResultMaxChunkBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_result_max_chunk_bytes".to_string(),
            description: "Run EntropyAnalyzer::analyze then return EntropyResult::max_chunk_entropy.".to_string(),
            input_schema: json!({ "type":"object", "properties": { "bytes": { "type":"array", "items": { "type":"integer" } }, "hex": { "type":"string" }, "chunk_size": { "type":"integer" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyResultMaxChunkBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let cs = args.get("chunk_size").and_then(Value::as_u64).unwrap_or(256) as usize;
        let a = rustre_triage_entropy::EntropyAnalyzer::new(cs);
        let r = a.analyze(&data);
        Ok(ToolResult::text(json!({ "overall": r.overall, "chunks": r.chunks.len(), "max_chunk_entropy": r.max_chunk_entropy(), "source": "rustre_triage_entropy::EntropyResult::max_chunk_entropy" }).to_string()))
    }
}

pub struct TriageEntropyHistogramIsRandomBytesTool;
impl TriageEntropyHistogramIsRandomBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_histogram_is_random_bytes".to_string(),
            description: "Build ByteHistogram; return chi-square and is_likely_random.".to_string(),
            input_schema: json!({ "type":"object", "properties": { "bytes": { "type":"array", "items": { "type":"integer" } }, "hex": { "type":"string" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyHistogramIsRandomBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let h = rustre_triage_entropy::ByteHistogram::new(&data);
        Ok(ToolResult::text(json!({ "total": h.total, "chi_square": h.chi_square_statistic(), "is_likely_random": h.is_likely_random(), "source": "rustre_triage_entropy::ByteHistogram::is_likely_random" }).to_string()))
    }
}

pub struct TriageEntropyHistogramCountOfBytesTool;
impl TriageEntropyHistogramCountOfBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_histogram_count_of_bytes".to_string(),
            description: "Count occurrences of a specific byte via ByteHistogram::count_of.".to_string(),
            input_schema: json!({ "type":"object", "properties": { "bytes": { "type":"array", "items": { "type":"integer" } }, "hex": { "type":"string" }, "byte": { "type":"integer" } }, "required": ["byte"] }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyHistogramCountOfBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'byte'".to_string()))?;
        if b > 255 { return Err(McpError::InvalidParams("byte must be 0..=255".to_string())); }
        let h = rustre_triage_entropy::ByteHistogram::new(&data);
        let c = h.count_of(b as u8);
        Ok(ToolResult::text(json!({ "byte": b, "count": c, "total": h.total, "source": "rustre_triage_entropy::ByteHistogram::count_of" }).to_string()))
    }
}

pub struct TriageEntropyReportSummaryBytesTool;
impl TriageEntropyReportSummaryBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_report_summary_bytes".to_string(),
            description: "Generate EntropyReport then return EntropyReport::summary.".to_string(),
            input_schema: json!({ "type":"object", "properties": { "bytes": { "type":"array", "items": { "type":"integer" } }, "hex": { "type":"string" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyReportSummaryBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let rep = rustre_triage_entropy::EntropyReport::generate(&data);
        Ok(ToolResult::text(json!({ "summary": rep.summary(), "overall_entropy": rep.overall_entropy, "is_likely_packed": rep.is_likely_packed, "indicators": rep.packing_indicators.len(), "source": "rustre_triage_entropy::EntropyReport::summary" }).to_string()))
    }
}

pub struct TriageEntropyReportDisplayBytesTool;
impl TriageEntropyReportDisplayBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_report_display_bytes".to_string(),
            description: "Generate EntropyReport then return its full Display rendering.".to_string(),
            input_schema: json!({ "type":"object", "properties": { "bytes": { "type":"array", "items": { "type":"integer" } }, "hex": { "type":"string" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyReportDisplayBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let rep = rustre_triage_entropy::EntropyReport::generate(&data);
        Ok(ToolResult::text(json!({ "display": rep.to_string(), "source": "rustre_triage_entropy::EntropyReport (Display impl)" }).to_string()))
    }
}

pub struct TriageEntropySurveyBinaryBytesTool;
impl TriageEntropySurveyBinaryBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_survey_binary_bytes".to_string(),
            description: "Run survey_binary on raw bytes and summarize.".to_string(),
            input_schema: json!({ "type":"object", "properties": { "bytes": { "type":"array", "items": { "type":"integer" } }, "hex": { "type":"string" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropySurveyBinaryBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let s = rustre_triage_entropy::survey_binary(&data);
        Ok(ToolResult::text(json!({ "file_kind": s.file_kind, "size": s.size, "is_pe": s.is_pe, "overall_entropy": s.overall_entropy, "import_count": s.import_count, "section_count": s.sections.len(), "packing_indicator_count": s.packing_indicators.len(), "crypto_hit_count": s.crypto_hit_count, "source": "rustre_triage_entropy::survey_binary" }).to_string()))
    }
}

pub struct TriageEntropyBlockFromSliceBytesTool;
impl TriageEntropyBlockFromSliceBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_block_from_slice_bytes".to_string(),
            description: "Build EntropyBlock from raw bytes via EntropyBlock::from_slice.".to_string(),
            input_schema: json!({ "type":"object", "properties": { "bytes": { "type":"array", "items": { "type":"integer" } }, "hex": { "type":"string" }, "offset": { "type":"integer" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyBlockFromSliceBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let off = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let b = rustre_triage_entropy::EntropyBlock::from_slice(off, &data);
        Ok(ToolResult::text(json!({ "offset": b.offset, "size": b.size, "entropy": b.entropy, "category": b.category.label(), "source": "rustre_triage_entropy::EntropyBlock::from_slice" }).to_string()))
    }
}

pub struct TriageEntropyAnalyzeBlocksBytesTool;
impl TriageEntropyAnalyzeBlocksBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_entropy_analyze_blocks_bytes".to_string(),
            description: "Split raw bytes into fixed-size blocks; compute entropy per block.".to_string(),
            input_schema: json!({ "type":"object", "properties": { "bytes": { "type":"array", "items": { "type":"integer" } }, "hex": { "type":"string" }, "block_size": { "type":"integer" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageEntropyAnalyzeBlocksBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "hex")?;
        let bs = args.get("block_size").and_then(Value::as_u64).unwrap_or(512) as usize;
        let blocks = rustre_triage_entropy::analyze_blocks(&data, bs);
        let max_e = blocks.iter().map(|b| b.entropy).fold(0.0_f32, f32::max);
        Ok(ToolResult::text(json!({ "block_count": blocks.len(), "block_size": bs, "max_entropy": max_e, "source": "rustre_triage_entropy::analyze_blocks" }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TriageEntropyPackingIndicatorsTool::definition(), Box::new(TriageEntropyPackingIndicatorsTool)),
        (TriageEntropyShannonPathTool::definition(), Box::new(TriageEntropyShannonPathTool)),
        (TriageEntropyShannonF32PathTool::definition(), Box::new(TriageEntropyShannonF32PathTool)),
        (TriageEntropyAnalyzeBlocksPathTool::definition(), Box::new(TriageEntropyAnalyzeBlocksPathTool)),
        (TriageEntropyReportPathTool::definition(), Box::new(TriageEntropyReportPathTool)),
        (TriageEntropyHistogramPathTool::definition(), Box::new(TriageEntropyHistogramPathTool)),
        (TriageEntropySurveyBinaryPathTool::definition(), Box::new(TriageEntropySurveyBinaryPathTool)),
        (TriageEntropyClassifyTool::definition(), Box::new(TriageEntropyClassifyTool)),
        (TriageEntropyColorRgbTool::definition(), Box::new(TriageEntropyColorRgbTool)),
        (TriageEntropyRatingFromEntropyTool::definition(), Box::new(TriageEntropyRatingFromEntropyTool)),
        (TriageEntropySectionNewTool::definition(), Box::new(TriageEntropySectionNewTool)),
        (TriageEntropyAnalyzerAnalyzePathTool::definition(), Box::new(TriageEntropyAnalyzerAnalyzePathTool)),
        (TriageEntropyCategoryLabelTool::definition(), Box::new(TriageEntropyCategoryLabelTool)),
        (TriageEntropyBlockFromSlicePathTool::definition(), Box::new(TriageEntropyBlockFromSlicePathTool)),
        (TriageEntropyAnalyzeWithSectionsPathTool::definition(), Box::new(TriageEntropyAnalyzeWithSectionsPathTool)),
        (TriageEntropyHistogramChiSquarePathTool::definition(), Box::new(TriageEntropyHistogramChiSquarePathTool)),
        (TriageEntropyHistogramMostCommonPathTool::definition(), Box::new(TriageEntropyHistogramMostCommonPathTool)),
        (TriageEntropyHeatmapAsciiPathTool::definition(), Box::new(TriageEntropyHeatmapAsciiPathTool)),
        (TriageEntropyHeatmapRgbColorsPathTool::definition(), Box::new(TriageEntropyHeatmapRgbColorsPathTool)),
        (TriageEntropyReportHighBlocksPathTool::definition(), Box::new(TriageEntropyReportHighBlocksPathTool)),
        (TriageEntropyShannonBytesTool::definition(), Box::new(TriageEntropyShannonBytesTool)),
        (TriageEntropyShannonBytesF32Tool::definition(), Box::new(TriageEntropyShannonBytesF32Tool)),
        (TriageEntropyShannonF32BytesTool::definition(), Box::new(TriageEntropyShannonF32BytesTool)),
        (TriageEntropyCategoryClassifyBytesTool::definition(), Box::new(TriageEntropyCategoryClassifyBytesTool)),
        (TriageEntropyRatingFromBytesTool::definition(), Box::new(TriageEntropyRatingFromBytesTool)),
        (TriageEntropyHistogramNewBytesTool::definition(), Box::new(TriageEntropyHistogramNewBytesTool)),
        (TriageEntropyHistogramMostCommonBytesTool::definition(), Box::new(TriageEntropyHistogramMostCommonBytesTool)),
        (TriageEntropyHeatmapFromDataBytesTool::definition(), Box::new(TriageEntropyHeatmapFromDataBytesTool)),
        (TriageEntropyHeatmapAsciiBytesTool::definition(), Box::new(TriageEntropyHeatmapAsciiBytesTool)),
        (TriageEntropyHeatmapRgbBytesTool::definition(), Box::new(TriageEntropyHeatmapRgbBytesTool)),
        (TriageEntropyAnalyzerAnalyzeBytesTool::definition(), Box::new(TriageEntropyAnalyzerAnalyzeBytesTool)),
        (TriageEntropyAnalyzeWithSectionsBytesTool::definition(), Box::new(TriageEntropyAnalyzeWithSectionsBytesTool)),
        (TriageEntropyReportGenerateBytesTool::definition(), Box::new(TriageEntropyReportGenerateBytesTool)),
        (TriageEntropyPackingIndicatorsBytesTool::definition(), Box::new(TriageEntropyPackingIndicatorsBytesTool)),
        (TriageEntropyReportHeatmapBytesTool::definition(), Box::new(TriageEntropyReportHeatmapBytesTool)),
        (TriageEntropyReportHighBlocksBytesTool::definition(), Box::new(TriageEntropyReportHighBlocksBytesTool)),
        (TriageEntropyReportSummaryPathTool::definition(), Box::new(TriageEntropyReportSummaryPathTool)),
        (TriageEntropyResultPackedSectionsBytesTool::definition(), Box::new(TriageEntropyResultPackedSectionsBytesTool)),
        (TriageEntropyAnalyzerNewTool::definition(), Box::new(TriageEntropyAnalyzerNewTool)),
        (TriageEntropyReportDisplayPathTool::definition(), Box::new(TriageEntropyReportDisplayPathTool)),
        (TriageEntropyShannonAliasTool::definition(), Box::new(TriageEntropyShannonAliasTool)),
        (TriageEntropyResultOverallBytesTool::definition(), Box::new(TriageEntropyResultOverallBytesTool)),
        (TriageEntropyReportIndicatorsBytesTool::definition(), Box::new(TriageEntropyReportIndicatorsBytesTool)),
        (TriageEntropyHistogramChiSquareBytesTool::definition(), Box::new(TriageEntropyHistogramChiSquareBytesTool)),
        (TriageEntropyRatingDisplayTool::definition(), Box::new(TriageEntropyRatingDisplayTool)),
        (TriageEntropySectionIsPackedBytesTool::definition(), Box::new(TriageEntropySectionIsPackedBytesTool)),
        (TriageEntropySectionIsEncryptedBytesTool::definition(), Box::new(TriageEntropySectionIsEncryptedBytesTool)),
        (TriageEntropyResultMaxChunkBytesTool::definition(), Box::new(TriageEntropyResultMaxChunkBytesTool)),
        (TriageEntropyHistogramIsRandomBytesTool::definition(), Box::new(TriageEntropyHistogramIsRandomBytesTool)),
        (TriageEntropyHistogramCountOfBytesTool::definition(), Box::new(TriageEntropyHistogramCountOfBytesTool)),
        (TriageEntropyReportSummaryBytesTool::definition(), Box::new(TriageEntropyReportSummaryBytesTool)),
        (TriageEntropyReportDisplayBytesTool::definition(), Box::new(TriageEntropyReportDisplayBytesTool)),
        (TriageEntropySurveyBinaryBytesTool::definition(), Box::new(TriageEntropySurveyBinaryBytesTool)),
        (TriageEntropyBlockFromSliceBytesTool::definition(), Box::new(TriageEntropyBlockFromSliceBytesTool)),
        (TriageEntropyAnalyzeBlocksBytesTool::definition(), Box::new(TriageEntropyAnalyzeBlocksBytesTool)),
    ]
}
