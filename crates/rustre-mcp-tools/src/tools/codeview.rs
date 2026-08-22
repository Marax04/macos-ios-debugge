//! MCP wrappers for the rustre-codeview crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes};

pub struct CodeviewParseSymbolsTool;

pub struct CodeviewParseTypeRecordsTool;

pub struct CodeviewSignatureFromBytesTool;

pub struct CodeviewSignatureAsStrTool;

pub struct CodeviewPrimitiveTypeTool;

pub struct CodeviewBuildTestPub32Tool;

pub struct CodeviewParseCv8LinesTool;

pub struct CodeviewSymbolFilterCountTool;

pub struct CodeviewMagicDetectTool;
impl CodeviewMagicDetectTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "codeview_magic_detect".to_string(),
            description: "Detect CodeViewMagic from first 4 bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CodeviewMagicDetectTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let m = rustre_debug::codeview::CodeViewMagic::detect(&data);
        Ok(ToolResult::text(json!({"magic": m.map(|x| x.label()), "source":"rustre_debug::codeview::CodeViewMagic::detect"}).to_string()))
    }
}

pub struct CodeviewMagicLabelTool;
impl CodeviewMagicLabelTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "codeview_magic_label".to_string(),
            description: "Human-readable label for a CodeViewMagic variant.".to_string(),
            input_schema: json!({"type":"object","properties":{"variant":{"type":"string"}},"required":["variant"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CodeviewMagicLabelTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        // Lo schema dichiara 'variant' obbligatoria. Con `unwrap_or("cv70")` chi la
        // ometteva riceveva l'etichetta di una variante specifica come se l'avesse
        // chiesta: una risposta plausibile e falsa, non un errore.
        let v = args
            .get("variant")
            .and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'variant'".into()))?;
        let m = match v.to_ascii_lowercase().as_str() {
            "cv41" => rustre_debug::codeview::CodeViewMagic::Cv41,
            "cv50" => rustre_debug::codeview::CodeViewMagic::Cv50,
            _ => rustre_debug::codeview::CodeViewMagic::Cv70,
        };
        Ok(ToolResult::text(json!({"label": m.label(), "source":"rustre_debug::codeview::CodeViewMagic::label"}).to_string()))
    }
}

pub struct CodeviewSymKindIsNamedAddressTool;
impl CodeviewSymKindIsNamedAddressTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "codeview_sym_kind_is_named_address".to_string(),
            description: "Classify a raw u16 CV symbol kind: named/address, function, data.".to_string(),
            input_schema: json!({"type":"object","properties":{"tag":{"type":"integer"}},"required":["tag"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CodeviewSymKindIsNamedAddressTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        // 'tag' e' obbligatoria: `unwrap_or(0)` classificava il tag 0 per chi non
        // ne aveva chiesto nessuno.
        let tag = args
            .get("tag")
            .and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'tag'".into()))? as u16;
        let k = rustre_debug::codeview::CvSymKind::from_u16(tag);
        Ok(ToolResult::text(json!({
            "kind": k.to_string(),
            "is_named_address": k.is_named_address(),
            "is_function": k.is_function(),
            "is_data": k.is_data(),
            "source":"rustre_debug::codeview::CvSymKind"
        }).to_string()))
    }
}

pub struct CodeviewTypeKindFromU16Tool;
impl CodeviewTypeKindFromU16Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "codeview_type_kind_from_u16".to_string(),
            description: "Decode CvTypeKind from a raw u16 leaf tag.".to_string(),
            input_schema: json!({"type":"object","properties":{"tag":{"type":"integer"}},"required":["tag"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CodeviewTypeKindFromU16Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        // 'tag' e' obbligatoria: `unwrap_or(0)` classificava il tag 0 per chi non
        // ne aveva chiesto nessuno.
        let tag = args
            .get("tag")
            .and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'tag'".into()))? as u16;
        let k = rustre_debug::codeview::CvTypeKind::from_u16(tag);
        Ok(ToolResult::text(json!({"kind": k.to_string(), "source":"rustre_debug::codeview::CvTypeKind::from_u16"}).to_string()))
    }
}

pub struct CodeviewParseTypeRecordSingleTool;
impl CodeviewParseTypeRecordSingleTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "codeview_parse_type_record_single".to_string(),
            description: "Parse a single CodeView type record (with length prefix).".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CodeviewParseTypeRecordSingleTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let rec = rustre_debug::codeview::parse_type_record(&data);
        Ok(ToolResult::text(json!({
            "parsed": rec.is_some(),
            "kind": rec.as_ref().map(|r| r.kind.to_string()),
            "name": rec.as_ref().map(|r| r.name.clone()),
            "size": rec.as_ref().map(|r| r.size),
            "source":"rustre_debug::codeview::parse_type_record"
        }).to_string()))
    }
}

pub struct CodeviewPdbPathFromPeTool;
impl CodeviewPdbPathFromPeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "codeview_pdb_path_from_pe".to_string(),
            description: "Extract PDB path/GUID/age from a PE binary's debug directory.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CodeviewPdbPathFromPeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let loc = rustre_debug::codeview::PdbPathFromPe::extract(&data);
        Ok(ToolResult::text(json!({
            "found": loc.is_some(),
            "path": loc.as_ref().map(|l| l.path.clone()),
            "guid": loc.as_ref().map(|l| l.guid.clone()),
            "age": loc.as_ref().map(|l| l.age),
            "source":"rustre_debug::codeview::PdbPathFromPe::extract"
        }).to_string()))
    }
}

pub struct CodeviewGuidToStringTool;
impl CodeviewGuidToStringTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "codeview_guid_to_string".to_string(),
            description: "Format 16 raw GUID bytes as mixed-endian GUID string.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CodeviewGuidToStringTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        if data.len() < 16 {
            return Err(McpError::InvalidParams("need 16 bytes".into()));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&data[..16]);
        let s = rustre_debug::codeview::guid_to_string(&arr);
        Ok(ToolResult::text(json!({"guid": s, "source":"rustre_debug::codeview::guid_to_string"}).to_string()))
    }
}

pub struct CodeviewPdbSuperblockParseTool;
impl CodeviewPdbSuperblockParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "codeview_pdb_superblock_parse".to_string(),
            description: "Parse a PDB 7.0 MSF super-block from the first 52 bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CodeviewPdbSuperblockParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let sb = rustre_debug::codeview::PdbSuperBlock::parse(&data);
        Ok(ToolResult::text(json!({
            "parsed": sb.is_some(),
            "magic_ok": sb.as_ref().map(|s| s.magic_ok),
            "page_size": sb.as_ref().map(|s| s.page_size),
            "num_pages": sb.as_ref().map(|s| s.num_pages),
            "valid": sb.as_ref().map(|s| s.is_valid()),
            "source":"rustre_debug::codeview::PdbSuperBlock::parse"
        }).to_string()))
    }
}

pub struct CodeviewProc32ParseTool;
impl CodeviewProc32ParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "codeview_proc32_parse".to_string(),
            description: "Parse an S_GPROC32/S_LPROC32 record payload.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CodeviewProc32ParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let p = rustre_debug::codeview::CvProc32::parse(&data);
        Ok(ToolResult::text(json!({
            "parsed": p.is_some(),
            "name": p.as_ref().map(|x| x.name.clone()),
            "offset": p.as_ref().map(|x| x.offset),
            "segment": p.as_ref().map(|x| x.segment),
            "len": p.as_ref().map(|x| x.len),
            "type_index": p.as_ref().map(|x| x.type_index),
            "source":"rustre_debug::codeview::CvProc32::parse"
        }).to_string()))
    }
}

pub struct CodeviewPublic32ParseTool;
impl CodeviewPublic32ParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "codeview_public32_parse".to_string(),
            description: "Parse an S_PUB32 record payload.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CodeviewPublic32ParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let p = rustre_debug::codeview::CvPublic32::parse(&data);
        Ok(ToolResult::text(json!({
            "parsed": p.is_some(),
            "name": p.as_ref().map(|x| x.name.clone()),
            "offset": p.as_ref().map(|x| x.offset),
            "flags": p.as_ref().map(|x| x.flags),
            "is_function": p.as_ref().map(|x| x.is_function()),
            "source":"rustre_debug::codeview::CvPublic32::parse"
        }).to_string()))
    }
}

pub struct CodeviewData32ParseTool;
impl CodeviewData32ParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "codeview_data32_parse".to_string(),
            description: "Parse an S_GDATA32/S_LDATA32 record payload.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CodeviewData32ParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let p = rustre_debug::codeview::CvData32::parse(&data);
        Ok(ToolResult::text(json!({
            "parsed": p.is_some(),
            "name": p.as_ref().map(|x| x.name.clone()),
            "offset": p.as_ref().map(|x| x.offset),
            "segment": p.as_ref().map(|x| x.segment),
            "type_index": p.as_ref().map(|x| x.type_index),
            "source":"rustre_debug::codeview::CvData32::parse"
        }).to_string()))
    }
}

pub struct CodeviewFrameprocParseTool;
impl CodeviewFrameprocParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "codeview_frameproc_parse".to_string(),
            description: "Parse an S_FRAMEPROC record payload (28+ bytes).".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CodeviewFrameprocParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let p = rustre_debug::codeview::CvFrameproc::parse(&data);
        Ok(ToolResult::text(json!({
            "parsed": p.is_some(),
            "frame_size": p.as_ref().map(|x| x.frame_size),
            "save_regs_size": p.as_ref().map(|x| x.save_regs_size),
            "flags": p.as_ref().map(|x| x.flags),
            "has_alloca": p.as_ref().map(|x| x.has_alloca()),
            "has_async_eh": p.as_ref().map(|x| x.has_async_eh()),
            "source":"rustre_debug::codeview::CvFrameproc::parse"
        }).to_string()))
    }
}

pub struct CodeviewSymbolStreamCountTool;
impl CodeviewSymbolStreamCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "codeview_symbol_stream_count".to_string(),
            description: "Iterate a raw CV symbol stream and count records via CvSymbolStream.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CodeviewSymbolStreamCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let n = rustre_debug::codeview::CvSymbolStream::new(&data).count();
        Ok(ToolResult::text(json!({"count": n, "source":"rustre_debug::codeview::CvSymbolStream"}).to_string()))
    }
}

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (CodeviewParseSymbolsTool::definition(), Box::new(CodeviewParseSymbolsTool)),
        (CodeviewParseTypeRecordsTool::definition(), Box::new(CodeviewParseTypeRecordsTool)),
        (CodeviewSignatureFromBytesTool::definition(), Box::new(CodeviewSignatureFromBytesTool)),
        (CodeviewSignatureAsStrTool::definition(), Box::new(CodeviewSignatureAsStrTool)),
        (CodeviewPrimitiveTypeTool::definition(), Box::new(CodeviewPrimitiveTypeTool)),
        (CodeviewBuildTestPub32Tool::definition(), Box::new(CodeviewBuildTestPub32Tool)),
        (CodeviewParseCv8LinesTool::definition(), Box::new(CodeviewParseCv8LinesTool)),
        (CodeviewSymbolFilterCountTool::definition(), Box::new(CodeviewSymbolFilterCountTool)),
        (CodeviewMagicDetectTool::definition(), Box::new(CodeviewMagicDetectTool)),
        (CodeviewMagicLabelTool::definition(), Box::new(CodeviewMagicLabelTool)),
        (CodeviewSymKindIsNamedAddressTool::definition(), Box::new(CodeviewSymKindIsNamedAddressTool)),
        (CodeviewTypeKindFromU16Tool::definition(), Box::new(CodeviewTypeKindFromU16Tool)),
        (CodeviewParseTypeRecordSingleTool::definition(), Box::new(CodeviewParseTypeRecordSingleTool)),
        (CodeviewPdbPathFromPeTool::definition(), Box::new(CodeviewPdbPathFromPeTool)),
        (CodeviewGuidToStringTool::definition(), Box::new(CodeviewGuidToStringTool)),
        (CodeviewPdbSuperblockParseTool::definition(), Box::new(CodeviewPdbSuperblockParseTool)),
        (CodeviewProc32ParseTool::definition(), Box::new(CodeviewProc32ParseTool)),
        (CodeviewPublic32ParseTool::definition(), Box::new(CodeviewPublic32ParseTool)),
        (CodeviewData32ParseTool::definition(), Box::new(CodeviewData32ParseTool)),
        (CodeviewFrameprocParseTool::definition(), Box::new(CodeviewFrameprocParseTool)),
        (CodeviewSymbolStreamCountTool::definition(), Box::new(CodeviewSymbolStreamCountTool)),
    ]
}
