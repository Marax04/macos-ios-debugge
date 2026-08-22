//! MCP wrappers for the rustre-hex crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes};

pub struct HexTplXBuiltinCountTool;
impl HexTplXBuiltinCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tplx_builtin_count".to_string(), description: "Count builtin templates.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplXBuiltinCountTool { async fn call(&self, _a: Value) -> Result<ToolResult, McpError> { let m = rustre_hex_template::builtin_templates(); Ok(ToolResult::text(json!({"count": m.len(), "source":"rustre_hex_template::builtin_templates"}).to_string())) } }

pub struct HexTplXRegistryWithBuiltinsTool;
impl HexTplXRegistryWithBuiltinsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tplx_registry_with_builtins".to_string(), description: "TemplateRegistry::with_builtins len+names.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplXRegistryWithBuiltinsTool { async fn call(&self, _a: Value) -> Result<ToolResult, McpError> { let r = rustre_hex_template::TemplateRegistry::with_builtins(); Ok(ToolResult::text(json!({"len": r.len(), "is_empty": r.is_empty(), "names": r.names(), "source":"rustre_hex_template::TemplateRegistry::with_builtins"}).to_string())) } }

pub struct HexTplXTemplateJsonRoundtripTool;
impl HexTplXTemplateJsonRoundtripTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tplx_template_json_roundtrip".to_string(), description: "Roundtrip a named builtin template via to_json/from_json.".to_string(), input_schema: json!({"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplXTemplateJsonRoundtripTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?; let mut m = rustre_hex_template::builtin_templates(); let t = m.remove(n).ok_or_else(|| McpError::InvalidParams(format!("no template {n}")))?; let j = t.to_json().map_err(|e| McpError::InternalError(e.to_string()))?; let t2 = rustre_hex_template::Template::from_json(&j).map_err(|e| McpError::InternalError(e.to_string()))?; Ok(ToolResult::text(json!({"name": t2.name, "fields_count": t2.fields.len(), "json_len": j.len(), "source":"rustre_hex_template::Template::{to_json,from_json}"}).to_string())) } }

pub struct HexTplXExprEvalTool;
impl HexTplXExprEvalTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tplx_expr_eval".to_string(), description: "Evaluate Expr::Eq(field,value) with a provided context value.".to_string(), input_schema: json!({"type":"object","required":["field","value","actual"],"properties":{"field":{"type":"string"},"value":{"type":"integer"},"actual":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplXExprEvalTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let f = args.get("field").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("field".into()))?.to_string(); let v = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("value".into()))?; let a = args.get("actual").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("actual".into()))?; let mut ctx = std::collections::HashMap::new(); ctx.insert(f.clone(), a); let e = rustre_hex_template::Expr::Eq(f, v); let r = e.eval(&ctx).map_err(|e| McpError::InternalError(e.to_string()))?; Ok(ToolResult::text(json!({"result": r, "source":"rustre_hex_template::Expr::eval"}).to_string())) } }

pub struct HexTplXBitfieldDefExtractTool;
impl HexTplXBitfieldDefExtractTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tplx_bitfield_def_extract".to_string(), description: "BitfieldDef::extract with start_bit/bit_count.".to_string(), input_schema: json!({"type":"object","required":["raw","start_bit","bit_count"],"properties":{"raw":{"type":"integer"},"start_bit":{"type":"integer"},"bit_count":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplXBitfieldDefExtractTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let raw = args.get("raw").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("raw".into()))?; let sb = args.get("start_bit").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("start_bit".into()))? as u8; let bc = args.get("bit_count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("bit_count".into()))? as u8; let d = rustre_hex_template::BitfieldDef::new("f", sb, bc); Ok(ToolResult::text(json!({"value": d.extract(raw), "source":"rustre_hex_template::BitfieldDef::extract"}).to_string())) } }

pub struct HexTplXBitfieldStructExtractTool;
impl HexTplXBitfieldStructExtractTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tplx_bitfield_struct_extract".to_string(), description: "BitfieldStruct::extract with two named fields.".to_string(), input_schema: json!({"type":"object","required":["raw"],"properties":{"raw":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplXBitfieldStructExtractTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let raw = args.get("raw").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("raw".into()))?; let defs = vec![rustre_hex_template::BitfieldDef::new("lo", 0, 4), rustre_hex_template::BitfieldDef::new("hi", 4, 4)]; let bs = rustre_hex_template::BitfieldStruct::extract("s", raw, &defs); Ok(ToolResult::text(json!({"raw": bs.raw, "lo": bs.get("lo"), "hi": bs.get("hi"), "field_count": bs.fields.len(), "source":"rustre_hex_template::BitfieldStruct::extract"}).to_string())) } }

pub struct HexTplXPrinterRenderTool;
impl HexTplXPrinterRenderTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tplx_printer_render".to_string(), description: "Render an empty ParsedStruct with a named printer.".to_string(), input_schema: json!({"type":"object","properties":{"indent":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplXPrinterRenderTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ind = args.get("indent").and_then(Value::as_str).unwrap_or("  ").to_string(); let p = rustre_hex_template::ParsedStructPrinter::with_indent(ind); let ps = rustre_hex_template::ParsedStruct { name: "Empty".to_string(), fields: vec![] }; let s = p.render(&ps); Ok(ToolResult::text(json!({"output": s, "source":"rustre_hex_template::ParsedStructPrinter::render"}).to_string())) } }

pub struct HexTplXApplyBuiltinToBytesTool;
impl HexTplXApplyBuiltinToBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tplx_apply_builtin_to_bytes".to_string(), description: "Apply a builtin template to hex bytes via TemplateApplier.".to_string(), input_schema: json!({"type":"object","required":["name","hex"],"properties":{"name":{"type":"string"},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplXApplyBuiltinToBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?; let bytes = args_to_bytes(&args)?; let mut m = rustre_hex_template::builtin_templates(); let t = m.remove(n).ok_or_else(|| McpError::InvalidParams(format!("no template {n}")))?; let buf = rustre_hex::HexBuffer::new(bytes); let r = rustre_hex_template::TemplateApplier::new(&buf).apply(&t, 0).map_err(|e| McpError::InternalError(e.to_string()))?; Ok(ToolResult::text(json!({"name": r.name, "field_count": r.fields.len(), "source":"rustre_hex_template::TemplateApplier::apply"}).to_string())) } }

pub struct HexTplXRegistryApplyTool;
impl HexTplXRegistryApplyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tplx_registry_apply".to_string(), description: "Apply a template via TemplateRegistry (with_builtins).".to_string(), input_schema: json!({"type":"object","required":["name","hex"],"properties":{"name":{"type":"string"},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplXRegistryApplyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?; let bytes = args_to_bytes(&args)?; let reg = rustre_hex_template::TemplateRegistry::with_builtins(); let buf = rustre_hex::HexBuffer::new(bytes); let r = reg.apply(n, &buf, 0).map_err(|e| McpError::InternalError(e.to_string()))?; Ok(ToolResult::text(json!({"name": r.name, "field_count": r.fields.len(), "source":"rustre_hex_template::TemplateRegistry::apply"}).to_string())) } }

pub struct HexTplXPeOptHeaderTool;
impl HexTplXPeOptHeaderTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tplx_pe_opt_header".to_string(), description: "template_pe_optional_header field count.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplXPeOptHeaderTool { async fn call(&self, _a: Value) -> Result<ToolResult, McpError> { let t = rustre_hex_template::template_pe_optional_header(); Ok(ToolResult::text(json!({"name": t.name, "field_count": t.fields.len(), "source":"rustre_hex_template::template_pe_optional_header"}).to_string())) } }

pub struct HexTplXElf32ShdrTool;
impl HexTplXElf32ShdrTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tplx_elf32_shdr".to_string(), description: "template_elf32_shdr field count.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplXElf32ShdrTool { async fn call(&self, _a: Value) -> Result<ToolResult, McpError> { let t = rustre_hex_template::template_elf32_shdr(); Ok(ToolResult::text(json!({"name": t.name, "field_count": t.fields.len(), "source":"rustre_hex_template::template_elf32_shdr"}).to_string())) } }

pub struct HexTplYBmpHeaderTool;
impl HexTplYBmpHeaderTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tply_bmp_header".to_string(), description: "template_bmp_header field count.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplYBmpHeaderTool { async fn call(&self, _a: Value) -> Result<ToolResult, McpError> { let t = rustre_hex_template::template_bmp_header(); Ok(ToolResult::text(json!({"name": t.name, "field_count": t.fields.len(), "source":"rustre_hex_template::template_bmp_header"}).to_string())) } }

pub struct HexTplYJpegJfifTool;
impl HexTplYJpegJfifTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tply_jpeg_jfif".to_string(), description: "template_jpeg_jfif field count.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplYJpegJfifTool { async fn call(&self, _a: Value) -> Result<ToolResult, McpError> { let t = rustre_hex_template::template_jpeg_jfif(); Ok(ToolResult::text(json!({"name": t.name, "field_count": t.fields.len(), "source":"rustre_hex_template::template_jpeg_jfif"}).to_string())) } }

pub struct HexTplYZipLocalTool;
impl HexTplYZipLocalTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tply_zip_local_file_header".to_string(), description: "template_zip_local_file_header field count.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplYZipLocalTool { async fn call(&self, _a: Value) -> Result<ToolResult, McpError> { let t = rustre_hex_template::template_zip_local_file_header(); Ok(ToolResult::text(json!({"name": t.name, "field_count": t.fields.len(), "source":"rustre_hex_template::template_zip_local_file_header"}).to_string())) } }

pub struct HexTplYZipEocdTool;
impl HexTplYZipEocdTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tply_zip_eocd".to_string(), description: "template_zip_eocd field count.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplYZipEocdTool { async fn call(&self, _a: Value) -> Result<ToolResult, McpError> { let t = rustre_hex_template::template_zip_eocd(); Ok(ToolResult::text(json!({"name": t.name, "field_count": t.fields.len(), "source":"rustre_hex_template::template_zip_eocd"}).to_string())) } }

pub struct HexTplYCoffFileHeaderTool;
impl HexTplYCoffFileHeaderTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tply_coff_file_header".to_string(), description: "template_coff_file_header field count.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplYCoffFileHeaderTool { async fn call(&self, _a: Value) -> Result<ToolResult, McpError> { let t = rustre_hex_template::template_coff_file_header(); Ok(ToolResult::text(json!({"name": t.name, "field_count": t.fields.len(), "source":"rustre_hex_template::template_coff_file_header"}).to_string())) } }

pub struct HexTplYPe32PlusOptionalTool;
impl HexTplYPe32PlusOptionalTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tply_pe32plus_optional_header".to_string(), description: "template_pe32plus_optional_header field count.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplYPe32PlusOptionalTool { async fn call(&self, _a: Value) -> Result<ToolResult, McpError> { let t = rustre_hex_template::template_pe32plus_optional_header(); Ok(ToolResult::text(json!({"name": t.name, "field_count": t.fields.len(), "source":"rustre_hex_template::template_pe32plus_optional_header"}).to_string())) } }

pub struct HexTplYElf64ShdrTool;
impl HexTplYElf64ShdrTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tply_elf64_shdr".to_string(), description: "template_elf64_shdr field count.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplYElf64ShdrTool { async fn call(&self, _a: Value) -> Result<ToolResult, McpError> { let t = rustre_hex_template::template_elf64_shdr(); Ok(ToolResult::text(json!({"name": t.name, "field_count": t.fields.len(), "source":"rustre_hex_template::template_elf64_shdr"}).to_string())) } }

pub struct HexTplYPeImportDescriptorTool;
impl HexTplYPeImportDescriptorTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tply_pe_import_descriptor".to_string(), description: "template_pe_import_descriptor field count.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplYPeImportDescriptorTool { async fn call(&self, _a: Value) -> Result<ToolResult, McpError> { let t = rustre_hex_template::template_pe_import_descriptor(); Ok(ToolResult::text(json!({"name": t.name, "field_count": t.fields.len(), "source":"rustre_hex_template::template_pe_import_descriptor"}).to_string())) } }

pub struct HexTplYPeExportDirectoryTool;
impl HexTplYPeExportDirectoryTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tply_pe_export_directory".to_string(), description: "template_pe_export_directory field count.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplYPeExportDirectoryTool { async fn call(&self, _a: Value) -> Result<ToolResult, McpError> { let t = rustre_hex_template::template_pe_export_directory(); Ok(ToolResult::text(json!({"name": t.name, "field_count": t.fields.len(), "source":"rustre_hex_template::template_pe_export_directory"}).to_string())) } }

pub struct HexTplYAutoSelectTool;
impl HexTplYAutoSelectTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tply_auto_select_template".to_string(), description: "auto_select_template for hex bytes; returns matched template name or none.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplYAutoSelectTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bytes = args_to_bytes(&args)?; let m = rustre_hex_template::auto_select_template(&bytes); Ok(ToolResult::text(json!({"matched": m.is_some(), "name": m.as_ref().map(|t| t.name.clone()), "field_count": m.as_ref().map(|t| t.fields.len()), "source":"rustre_hex_template::auto_select_template"}).to_string())) } }

pub struct HexTplYFlattenParsedTool;
impl HexTplYFlattenParsedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tply_flatten_parsed".to_string(), description: "Apply a builtin template to hex bytes then flatten_parsed; returns field count.".to_string(), input_schema: json!({"type":"object","required":["name","hex"],"properties":{"name":{"type":"string"},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplYFlattenParsedTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?; let bytes = args_to_bytes(&args)?; let mut m = rustre_hex_template::builtin_templates(); let t = m.remove(n).ok_or_else(|| McpError::InvalidParams(format!("no template {n}")))?; let buf = rustre_hex::HexBuffer::new(bytes); let r = rustre_hex_template::TemplateApplier::new(&buf).apply(&t, 0).map_err(|e| McpError::InternalError(e.to_string()))?; let flat = rustre_hex_template::flatten_parsed(&r); Ok(ToolResult::text(json!({"flat_count": flat.len(), "source":"rustre_hex_template::flatten_parsed"}).to_string())) } }

pub struct HexTplYTemplateReportTool;
impl HexTplYTemplateReportTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "hex_tply_template_report".to_string(), description: "Apply a builtin template + build TemplateReport, return field_count/total_size.".to_string(), input_schema: json!({"type":"object","required":["name","hex"],"properties":{"name":{"type":"string"},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for HexTplYTemplateReportTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?; let bytes = args_to_bytes(&args)?; let mut m = rustre_hex_template::builtin_templates(); let t = m.remove(n).ok_or_else(|| McpError::InvalidParams(format!("no template {n}")))?; let buf = rustre_hex::HexBuffer::new(bytes); let r = rustre_hex_template::TemplateApplier::new(&buf).apply(&t, 0).map_err(|e| McpError::InternalError(e.to_string()))?; let rep = rustre_hex_template::TemplateReport::build(&t, &r, "wire"); Ok(ToolResult::text(json!({"template_name": rep.template_name, "source_name": rep.source, "field_count": rep.field_count, "total_size": rep.total_size, "source":"rustre_hex_template::TemplateReport::build"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (HexTplXBuiltinCountTool::definition(), Box::new(HexTplXBuiltinCountTool)),
        (HexTplXRegistryWithBuiltinsTool::definition(), Box::new(HexTplXRegistryWithBuiltinsTool)),
        (HexTplXTemplateJsonRoundtripTool::definition(), Box::new(HexTplXTemplateJsonRoundtripTool)),
        (HexTplXExprEvalTool::definition(), Box::new(HexTplXExprEvalTool)),
        (HexTplXBitfieldDefExtractTool::definition(), Box::new(HexTplXBitfieldDefExtractTool)),
        (HexTplXBitfieldStructExtractTool::definition(), Box::new(HexTplXBitfieldStructExtractTool)),
        (HexTplXPrinterRenderTool::definition(), Box::new(HexTplXPrinterRenderTool)),
        (HexTplXApplyBuiltinToBytesTool::definition(), Box::new(HexTplXApplyBuiltinToBytesTool)),
        (HexTplXRegistryApplyTool::definition(), Box::new(HexTplXRegistryApplyTool)),
        (HexTplXPeOptHeaderTool::definition(), Box::new(HexTplXPeOptHeaderTool)),
        (HexTplXElf32ShdrTool::definition(), Box::new(HexTplXElf32ShdrTool)),
        (HexTplYBmpHeaderTool::definition(), Box::new(HexTplYBmpHeaderTool)),
        (HexTplYJpegJfifTool::definition(), Box::new(HexTplYJpegJfifTool)),
        (HexTplYZipLocalTool::definition(), Box::new(HexTplYZipLocalTool)),
        (HexTplYZipEocdTool::definition(), Box::new(HexTplYZipEocdTool)),
        (HexTplYCoffFileHeaderTool::definition(), Box::new(HexTplYCoffFileHeaderTool)),
        (HexTplYPe32PlusOptionalTool::definition(), Box::new(HexTplYPe32PlusOptionalTool)),
        (HexTplYElf64ShdrTool::definition(), Box::new(HexTplYElf64ShdrTool)),
        (HexTplYPeImportDescriptorTool::definition(), Box::new(HexTplYPeImportDescriptorTool)),
        (HexTplYPeExportDirectoryTool::definition(), Box::new(HexTplYPeExportDirectoryTool)),
        (HexTplYAutoSelectTool::definition(), Box::new(HexTplYAutoSelectTool)),
        (HexTplYFlattenParsedTool::definition(), Box::new(HexTplYFlattenParsedTool)),
        (HexTplYTemplateReportTool::definition(), Box::new(HexTplYTemplateReportTool)),
    ]
}
