//! MCP wrappers for the rustre-pe_editor crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{hex_encode};
use crate::wire_tools::{pe_editor_hex_decode, pe_editor_hex_encode};

pub struct PeEditorCertificateHeaderTool;

pub struct PeEditorPatchSetNewTool;

pub struct PeEditorExportAddTool;

pub struct PeEditorExportRemoveTool;

pub struct PeEditorPatchVerifiedTool;
impl PeEditorPatchVerifiedTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "pe_editor_patch_verified".to_string(), description: "Build a rustre_pe_editor::Patch::verified.".to_string(), input_schema: json!({"type":"object","properties":{"offset":{"type":"integer"},"original_hex":{"type":"string"},"replacement_hex":{"type":"string"},"description":{"type":"string"}},"required":["offset","original_hex","replacement_hex"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for PeEditorPatchVerifiedTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let offset = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("offset".into()))? as usize;
        let orig = crate::hex_decode(args.get("original_hex").and_then(Value::as_str).unwrap_or(""))?;
        let repl = crate::hex_decode(args.get("replacement_hex").and_then(Value::as_str).unwrap_or(""))?;
        let desc = args.get("description").and_then(Value::as_str).unwrap_or("").to_string();
        let p = rustre_pe_editor::Patch::verified(offset, orig, repl, desc);
        Ok(ToolResult::text(json!({"display": format!("{p}"), "len": p.len(), "is_empty": p.is_empty(), "has_verification": p.has_verification(), "source":"rustre_pe_editor::Patch::verified"}).to_string()))
    }
}

pub struct PeEditorPatchSetTotalBytesTool;
impl PeEditorPatchSetTotalBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "pe_editor_patchset_total_bytes".to_string(), description: "Build rustre_pe_editor::PatchSet and return total_bytes/len.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"patches":{"type":"array"}},"required":["name","patches"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for PeEditorPatchSetTotalBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        let mut ps = rustre_pe_editor::PatchSet::new(name);
        if let Some(arr) = args.get("patches").and_then(Value::as_array) {
            for v in arr {
                let off = v.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
                let repl = crate::hex_decode(v.get("replacement_hex").and_then(Value::as_str).unwrap_or(""))?;
                let desc = v.get("description").and_then(Value::as_str).unwrap_or("").to_string();
                ps.add(rustre_pe_editor::Patch::simple(off, repl, desc));
            }
        }
        Ok(ToolResult::text(json!({"display": format!("{ps}"), "len": ps.len(), "is_empty": ps.is_empty(), "total_bytes": ps.total_bytes(), "source":"rustre_pe_editor::PatchSet"}).to_string()))
    }
}

pub struct PeEditorImportEntryOrdinalTool;
impl PeEditorImportEntryOrdinalTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "pe_editor_import_entry_ordinal".to_string(), description: "Build rustre_pe_editor::ImportEntry::ordinal.".to_string(), input_schema: json!({"type":"object","properties":{"dll":{"type":"string"},"ordinal":{"type":"integer"}},"required":["dll","ordinal"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for PeEditorImportEntryOrdinalTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let dll = args.get("dll").and_then(Value::as_str).unwrap_or("").to_string();
        let ord = args.get("ordinal").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("ordinal".into()))? as u16;
        let e = rustre_pe_editor::ImportEntry::ordinal(dll, ord);
        Ok(ToolResult::text(json!({"display": e.display(), "is_named": e.is_named(), "source":"rustre_pe_editor::ImportEntry::ordinal"}).to_string()))
    }
}

pub struct PeEditorResourceManifestTool;
impl PeEditorResourceManifestTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "pe_editor_resource_manifest".to_string(), description: "Build rustre_pe_editor::ResourceEntry::manifest.".to_string(), input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for PeEditorResourceManifestTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = crate::hex_decode(args.get("data_hex").and_then(Value::as_str).unwrap_or(""))?;
        let r = rustre_pe_editor::ResourceEntry::manifest(data);
        Ok(ToolResult::text(json!({"display": format!("{r}"), "len": r.len(), "is_empty": r.is_empty(), "source":"rustre_pe_editor::ResourceEntry::manifest"}).to_string()))
    }
}

pub struct PeEditorExportEditDisplayTool;
impl PeEditorExportEditDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "pe_editor_export_edit_display".to_string(), description: "Build rustre_pe_editor::ExportEdit::add or ::remove.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"ordinal":{"type":"integer"},"rva":{"type":"integer"},"remove":{"type":"boolean"}},"required":["name"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for PeEditorExportEditDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        let remove = args.get("remove").and_then(Value::as_bool).unwrap_or(false);
        let e = if remove {
            rustre_pe_editor::ExportEdit::remove(name)
        } else {
            let ord = args.get("ordinal").and_then(Value::as_u64).unwrap_or(0) as u32;
            let rva = args.get("rva").and_then(Value::as_u64).unwrap_or(0) as u32;
            rustre_pe_editor::ExportEdit::add(name, ord, rva)
        };
        Ok(ToolResult::text(json!({"display": format!("{e}"), "remove": e.remove, "source":"rustre_pe_editor::ExportEdit"}).to_string()))
    }
}

pub struct PeEditorSigningScaffoldBlobTool;
impl PeEditorSigningScaffoldBlobTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "pe_editor_signing_scaffold_blob".to_string(), description: "Build WIN_CERTIFICATE blob via rustre_pe_editor::PeSigningScaffold.".to_string(), input_schema: json!({"type":"object","properties":{"payload_hex":{"type":"string"}},"required":["payload_hex"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for PeEditorSigningScaffoldBlobTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let payload = crate::hex_decode(args.get("payload_hex").and_then(Value::as_str).unwrap_or(""))?;
        let scaffold = rustre_pe_editor::PeSigningScaffold::new(payload);
        let blob = scaffold.build_certificate_blob();
        Ok(ToolResult::text(json!({"blob_hex": hex_encode(&blob), "blob_len": blob.len(), "payload_len": scaffold.payload_len(), "source":"rustre_pe_editor::PeSigningScaffold::build_certificate_blob"}).to_string()))
    }
}

pub struct PeEditorParseDosHeaderTool;
impl PeEditorParseDosHeaderTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "pe_editor_parse_dos_header".to_string(), description: "Parse a DOS header via rustre_pe_editor::PeParser::parse_dos_header.".to_string(), input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for PeEditorParseDosHeaderTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = crate::hex_decode(args.get("data_hex").and_then(Value::as_str).unwrap_or(""))?;
        match rustre_pe_editor::PeParser::parse_dos_header(&data) {
            Ok(h) => Ok(ToolResult::text(json!({"e_magic": h.e_magic, "e_lfanew": h.e_lfanew, "source":"rustre_pe_editor::PeParser::parse_dos_header"}).to_string())),
            Err(e) => Err(McpError::InvalidParams(format!("{e}"))),
        }
    }
}

pub struct PeEditorParseFileHeaderTool;
impl PeEditorParseFileHeaderTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "pe_editor_parse_file_header".to_string(), description: "Parse a COFF FileHeader via rustre_pe_editor::PeParser::parse_file_header.".to_string(), input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"},"offset":{"type":"integer"}},"required":["data_hex","offset"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for PeEditorParseFileHeaderTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = crate::hex_decode(args.get("data_hex").and_then(Value::as_str).unwrap_or(""))?;
        let off = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("offset".into()))? as usize;
        match rustre_pe_editor::PeParser::parse_file_header(&data, off) {
            Ok(h) => Ok(ToolResult::text(json!({"machine": h.machine, "number_of_sections": h.number_of_sections, "time_date_stamp": h.time_date_stamp, "size_of_optional_header": h.size_of_optional_header, "characteristics": h.characteristics, "source":"rustre_pe_editor::PeParser::parse_file_header"}).to_string())),
            Err(e) => Err(McpError::InvalidParams(format!("{e}"))),
        }
    }
}

pub struct PeEditorParseOptionalHeader64Tool;
impl PeEditorParseOptionalHeader64Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "pe_editor_parse_optional_header64".to_string(), description: "Parse a PE32+ optional header.".to_string(), input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"},"offset":{"type":"integer"}},"required":["data_hex","offset"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for PeEditorParseOptionalHeader64Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = crate::hex_decode(args.get("data_hex").and_then(Value::as_str).unwrap_or(""))?;
        let off = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("offset".into()))? as usize;
        match rustre_pe_editor::PeParser::parse_optional_header64(&data, off) {
            Ok(h) => Ok(ToolResult::text(json!({"magic": h.magic, "address_of_entry_point": h.address_of_entry_point, "image_base": h.image_base, "section_alignment": h.section_alignment, "file_alignment": h.file_alignment, "size_of_image": h.size_of_image, "size_of_headers": h.size_of_headers, "subsystem": h.subsystem, "dll_characteristics": h.dll_characteristics, "number_of_rva_and_sizes": h.number_of_rva_and_sizes, "source":"rustre_pe_editor::PeParser::parse_optional_header64"}).to_string())),
            Err(e) => Err(McpError::InvalidParams(format!("{e}"))),
        }
    }
}

pub struct PeEditorBuildTreeTool;
impl PeEditorBuildTreeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "pe_editor_build_tree".to_string(), description: "Build a CFF-Explorer-style PE tree via rustre_pe_editor::PeTreeBuilder::build_tree.".to_string(), input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for PeEditorBuildTreeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = crate::hex_decode(args.get("data_hex").and_then(Value::as_str).unwrap_or(""))?;
        let tree = rustre_pe_editor::PeTreeBuilder::build_tree(&data);
        let nodes: Vec<Value> = tree.sections.iter().map(|n| json!({"name": n.name, "raw_offset": n.raw_offset, "raw_size": n.raw_size, "fields": n.fields.len(), "children": n.children.len(), "total_fields": n.total_fields()})).collect();
        Ok(ToolResult::text(json!({"top_level": nodes, "count": tree.sections.len(), "source":"rustre_pe_editor::PeTreeBuilder::build_tree"}).to_string()))
    }
}

pub struct PeEditorCertificateHeaderNewTool;
impl PeEditorCertificateHeaderNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "pe_editor_certificate_header_new".to_string(), description: "Build rustre_pe_editor::CertificateHeader::new(payload_len).".to_string(), input_schema: json!({"type":"object","properties":{"payload_len":{"type":"integer"}},"required":["payload_len"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for PeEditorCertificateHeaderNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let len = args.get("payload_len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("payload_len".into()))? as u32;
        let h = rustre_pe_editor::CertificateHeader::new(len);
        let bytes = h.to_bytes();
        Ok(ToolResult::text(json!({"dw_length": h.dw_length, "w_revision": h.w_revision, "w_certificate_type": h.w_certificate_type, "bytes_hex": hex_encode(&bytes), "source":"rustre_pe_editor::CertificateHeader::new"}).to_string()))
    }
}

pub struct PeEditorPatchLenTool;
impl PeEditorPatchLenTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "pe_editor_patch_len".to_string(),
            description: "Build a Patch::simple and return len/is_empty/has_verification (rustre_pe_editor::Patch).".to_string(),
            input_schema: json!({"type":"object","properties":{"offset":{"type":"integer"},"replacement_hex":{"type":"string"}},"required":["offset","replacement_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for PeEditorPatchLenTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
        let hex = args.get("replacement_hex").and_then(Value::as_str).unwrap_or("");
        let repl = pe_editor_hex_decode(hex)?;
        let p = rustre_pe_editor::Patch::simple(offset, repl, "t".to_string());
        Ok(ToolResult::text(json!({"len":p.len(),"is_empty":p.is_empty(),"has_verification":p.has_verification(),"source":"rustre_pe_editor::Patch"}).to_string()))
    }
}

pub struct PeEditorSectionEditSetCharsTool;
impl PeEditorSectionEditSetCharsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "pe_editor_section_edit_set_chars".to_string(),
            description: "Build a SectionEdit::set_chars (rustre_pe_editor::SectionEdit).".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"characteristics":{"type":"integer"}},"required":["name","characteristics"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for PeEditorSectionEditSetCharsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        let chars = args.get("characteristics").and_then(Value::as_u64).unwrap_or(0) as u32;
        let se = rustre_pe_editor::SectionEdit::set_chars(name.clone(), chars);
        Ok(ToolResult::text(json!({"name":se.name,"new_characteristics":se.new_characteristics,"zero_out":se.zero_out,"source":"rustre_pe_editor::SectionEdit::set_chars"}).to_string()))
    }
}

pub struct PeEditorSectionEditZeroTool;
impl PeEditorSectionEditZeroTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "pe_editor_section_edit_zero".to_string(),
            description: "Build a SectionEdit::zero (rustre_pe_editor::SectionEdit).".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for PeEditorSectionEditZeroTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        let se = rustre_pe_editor::SectionEdit::zero(name);
        Ok(ToolResult::text(json!({"name":se.name,"zero_out":se.zero_out,"has_chars":se.new_characteristics.is_some(),"source":"rustre_pe_editor::SectionEdit::zero"}).to_string()))
    }
}

pub struct PeEditorImportEditorNewTool;
impl PeEditorImportEditorNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "pe_editor_import_editor_new".to_string(),
            description: "Construct an empty ImportEditor (rustre_pe_editor::ImportEditor::new).".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for PeEditorImportEditorNewTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let ie = rustre_pe_editor::ImportEditor::new();
        Ok(ToolResult::text(json!({"pending_additions":ie.pending_additions(),"pending_removals":ie.pending_removals(),"source":"rustre_pe_editor::ImportEditor::new"}).to_string()))
    }
}

pub struct PeEditorExportEditorNewTool;
impl PeEditorExportEditorNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "pe_editor_export_editor_new".to_string(),
            description: "Construct an ExportEditor for a DLL (rustre_pe_editor::ExportEditor::new).".to_string(),
            input_schema: json!({"type":"object","properties":{"dll":{"type":"string"}},"required":["dll"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for PeEditorExportEditorNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let dll = args.get("dll").and_then(Value::as_str).unwrap_or("").to_string();
        let ee = rustre_pe_editor::ExportEditor::new(dll);
        Ok(ToolResult::text(json!({"dll_name":ee.dll_name(),"pending_count":ee.pending_count(),"source":"rustre_pe_editor::ExportEditor::new"}).to_string()))
    }
}

pub struct PeEditorResourceEditorNewTool;
impl PeEditorResourceEditorNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "pe_editor_resource_editor_new".to_string(),
            description: "Construct an empty ResourceEditor (rustre_pe_editor::ResourceEditor::new).".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for PeEditorResourceEditorNewTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let re = rustre_pe_editor::ResourceEditor::new();
        Ok(ToolResult::text(json!({"pending_additions":re.pending_additions(),"pending_removals":re.pending_removals(),"total_data_size":re.total_data_size(),"source":"rustre_pe_editor::ResourceEditor::new"}).to_string()))
    }
}

pub struct PeEditorResourceEntryNewTool;
impl PeEditorResourceEntryNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "pe_editor_resource_entry_new".to_string(),
            description: "Build a ResourceEntry::new (rustre_pe_editor::ResourceEntry).".to_string(),
            input_schema: json!({"type":"object","properties":{"type_id":{"type":"integer"},"id":{"type":"integer"},"language":{"type":"integer"},"data_hex":{"type":"string"}},"required":["type_id","id","language","data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for PeEditorResourceEntryNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let t = args.get("type_id").and_then(Value::as_u64).unwrap_or(0) as u16;
        let id = args.get("id").and_then(Value::as_u64).unwrap_or(0) as u32;
        let lang = args.get("language").and_then(Value::as_u64).unwrap_or(0) as u16;
        let hex = args.get("data_hex").and_then(Value::as_str).unwrap_or("");
        let data = pe_editor_hex_decode(hex)?;
        let e = rustre_pe_editor::ResourceEntry::new(t, id, lang, data);
        Ok(ToolResult::text(json!({"len":e.len(),"is_empty":e.is_empty(),"display":e.to_string(),"source":"rustre_pe_editor::ResourceEntry::new"}).to_string()))
    }
}

pub struct PeEditorResourceTypeDisplayTool;
impl PeEditorResourceTypeDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "pe_editor_resource_type_display".to_string(),
            description: "Display a ResourceType via Display impl (rustre_pe_editor::ResourceType).".to_string(),
            input_schema: json!({"type":"object","properties":{"id":{"type":"integer"},"name":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for PeEditorResourceTypeDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let rt = if let Some(n) = args.get("name").and_then(Value::as_str) {
            rustre_pe_editor::ResourceType::Name(n.to_string())
        } else {
            let id = args.get("id").and_then(Value::as_u64).unwrap_or(0) as u16;
            rustre_pe_editor::ResourceType::Id(id)
        };
        Ok(ToolResult::text(json!({"display":rt.to_string(),"source":"rustre_pe_editor::ResourceType"}).to_string()))
    }
}

pub struct PeEditorSigningScaffoldNewTool;
impl PeEditorSigningScaffoldNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "pe_editor_signing_scaffold_new".to_string(),
            description: "Construct PeSigningScaffold from hex payload; return blob (rustre_pe_editor::PeSigningScaffold).".to_string(),
            input_schema: json!({"type":"object","properties":{"payload_hex":{"type":"string"}},"required":["payload_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for PeEditorSigningScaffoldNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("payload_hex").and_then(Value::as_str).unwrap_or("");
        let payload = pe_editor_hex_decode(hex)?;
        let s = rustre_pe_editor::PeSigningScaffold::new(payload);
        let blob = s.build_certificate_blob();
        Ok(ToolResult::text(json!({"payload_len":s.payload_len(),"blob_len":blob.len(),"blob_hex":pe_editor_hex_encode(&blob),"source":"rustre_pe_editor::PeSigningScaffold"}).to_string()))
    }
}

pub struct PeEditorHeaderFieldDisplayTool;
impl PeEditorHeaderFieldDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "pe_editor_header_field_display".to_string(),
            description: "Display string for a HeaderField variant (rustre_pe_editor::HeaderField).".to_string(),
            input_schema: json!({"type":"object","properties":{"field":{"type":"string"}},"required":["field"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for PeEditorHeaderFieldDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let f = args.get("field").and_then(Value::as_str).unwrap_or("Subsystem");
        use rustre_pe_editor::HeaderField as H;
        let hf = match f {
            "MajorLinkerVersion" => H::MajorLinkerVersion,
            "MinorLinkerVersion" => H::MinorLinkerVersion,
            "MajorOsVersion" => H::MajorOsVersion,
            "MinorOsVersion" => H::MinorOsVersion,
            "MajorImageVersion" => H::MajorImageVersion,
            "MinorImageVersion" => H::MinorImageVersion,
            "MajorSubsystemVersion" => H::MajorSubsystemVersion,
            "MinorSubsystemVersion" => H::MinorSubsystemVersion,
            "Win32VersionValue" => H::Win32VersionValue,
            "SizeOfStackReserve" => H::SizeOfStackReserve,
            "SizeOfStackCommit" => H::SizeOfStackCommit,
            "SizeOfHeapReserve" => H::SizeOfHeapReserve,
            "SizeOfHeapCommit" => H::SizeOfHeapCommit,
            "DllCharacteristics" => H::DllCharacteristics,
            _ => H::Subsystem,
        };
        Ok(ToolResult::text(json!({"display":hf.to_string(),"source":"rustre_pe_editor::HeaderField"}).to_string()))
    }
}

pub struct PeEditorImportEntryNamedIsNamedTool;
impl PeEditorImportEntryNamedIsNamedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_import_entry_named_is_named".to_string(), description: "Build a named rustre_pe_editor::ImportEntry and check is_named() + display().".to_string(), input_schema: json!({"type":"object","required":["dll","name","hint"],"properties":{"dll":{"type":"string"},"name":{"type":"string"},"hint":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorImportEntryNamedIsNamedTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let dll = args.get("dll").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("dll".into()))?.to_string(); let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?.to_string(); let hint = args.get("hint").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("hint".into()))? as u16; let e = rustre_pe_editor::ImportEntry::named(dll, name, hint); Ok(ToolResult::text(json!({"display": e.display(), "is_named": e.is_named(), "dll": e.dll, "name": e.name, "hint": e.hint, "source": "rustre_pe_editor::ImportEntry::named"}).to_string())) } }

pub struct PeEditorExportEditAddDisplayTool;
impl PeEditorExportEditAddDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_export_edit_add_display".to_string(), description: "Build rustre_pe_editor::ExportEdit::add and return Display + fields.".to_string(), input_schema: json!({"type":"object","required":["name","ordinal","rva"],"properties":{"name":{"type":"string"},"ordinal":{"type":"integer","minimum":0},"rva":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorExportEditAddDisplayTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?.to_string(); let ord = args.get("ordinal").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("ordinal".into()))? as u32; let rva = args.get("rva").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("rva".into()))? as u32; let e = rustre_pe_editor::ExportEdit::add(name, ord, rva); Ok(ToolResult::text(json!({"display": e.to_string(), "name": e.name, "ordinal": e.ordinal, "rva": e.rva, "remove": e.remove, "source": "rustre_pe_editor::ExportEdit::add"}).to_string())) } }

pub struct PeEditorExportEditRemoveDisplayTool;
impl PeEditorExportEditRemoveDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_export_edit_remove_display".to_string(), description: "Build rustre_pe_editor::ExportEdit::remove and return Display + fields.".to_string(), input_schema: json!({"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorExportEditRemoveDisplayTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?.to_string(); let e = rustre_pe_editor::ExportEdit::remove(name); Ok(ToolResult::text(json!({"display": e.to_string(), "name": e.name, "remove": e.remove, "source": "rustre_pe_editor::ExportEdit::remove"}).to_string())) } }

pub struct PeEditorResourceEntryManifestLenTool;
impl PeEditorResourceEntryManifestLenTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_resource_entry_manifest_len".to_string(), description: "Build a rustre_pe_editor::ResourceEntry::manifest from hex data and return len/is_empty/display.".to_string(), input_schema: json!({"type":"object","required":["data_hex"],"properties":{"data_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorResourceEntryManifestLenTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let dhex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("data_hex".into()))?; let d = pe_editor_hex_decode(dhex)?; let r = rustre_pe_editor::ResourceEntry::manifest(d); Ok(ToolResult::text(json!({"display": r.to_string(), "len": r.len(), "is_empty": r.is_empty(), "id": r.id, "language": r.language, "source": "rustre_pe_editor::ResourceEntry::manifest"}).to_string())) } }

pub struct PeEditorResourceTypeIdDisplayTool;
impl PeEditorResourceTypeIdDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_resource_type_id_display".to_string(), description: "Display rustre_pe_editor::ResourceType::Id(id).".to_string(), input_schema: json!({"type":"object","required":["id"],"properties":{"id":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorResourceTypeIdDisplayTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let id = args.get("id").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("id".into()))? as u16; let rt = rustre_pe_editor::ResourceType::Id(id); Ok(ToolResult::text(json!({"display": rt.to_string(), "source": "rustre_pe_editor::ResourceType::Id"}).to_string())) } }

pub struct PeEditorResourceTypeNameDisplayTool;
impl PeEditorResourceTypeNameDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_resource_type_name_display".to_string(), description: "Display rustre_pe_editor::ResourceType::Name(name).".to_string(), input_schema: json!({"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorResourceTypeNameDisplayTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?.to_string(); let rt = rustre_pe_editor::ResourceType::Name(name); Ok(ToolResult::text(json!({"display": rt.to_string(), "source": "rustre_pe_editor::ResourceType::Name"}).to_string())) } }

pub struct PeEditorRc4KeystreamTool;
impl PeEditorRc4KeystreamTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_rc4_keystream".to_string(), description: "Generate n RC4 keystream bytes via rustre_pe_editor::Rc4::new(key).next_byte().".to_string(), input_schema: json!({"type":"object","required":["key_hex","n"],"properties":{"key_hex":{"type":"string"},"n":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorRc4KeystreamTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let khex = args.get("key_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("key_hex".into()))?; let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("n".into()))? as usize; let key = pe_editor_hex_decode(khex)?; if key.is_empty() { return Err(McpError::InvalidParams("key must not be empty".into())); } let mut rc4 = rustre_pe_editor::Rc4::new(&key); let mut out_bytes = Vec::with_capacity(n); for _ in 0..n { out_bytes.push(rc4.next_byte()); } Ok(ToolResult::text(json!({"keystream_hex": pe_editor_hex_encode(&out_bytes), "len": out_bytes.len(), "source": "rustre_pe_editor::Rc4::next_byte"}).to_string())) } }

pub struct PeEditorCertificateHeaderDwLengthTool;
impl PeEditorCertificateHeaderDwLengthTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_certificate_header_dw_length".to_string(), description: "Return dw_length/w_revision/w_certificate_type of rustre_pe_editor::CertificateHeader::new(payload_len).".to_string(), input_schema: json!({"type":"object","required":["payload_len"],"properties":{"payload_len":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorCertificateHeaderDwLengthTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pl = args.get("payload_len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("payload_len".into()))? as u32; let h = rustre_pe_editor::CertificateHeader::new(pl); Ok(ToolResult::text(json!({"dw_length": h.dw_length, "w_revision": h.w_revision, "w_certificate_type": h.w_certificate_type, "source": "rustre_pe_editor::CertificateHeader::new"}).to_string())) } }

pub struct PeEditorSectionEditZeroFlagsTool;
impl PeEditorSectionEditZeroFlagsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_section_edit_zero_flags".to_string(), description: "Build a rustre_pe_editor::SectionEdit::zero(name) and report its flags.".to_string(), input_schema: json!({"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorSectionEditZeroFlagsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?.to_string(); let se = rustre_pe_editor::SectionEdit::zero(name); Ok(ToolResult::text(json!({"name": se.name, "zero_out": se.zero_out, "has_new_chars": se.new_characteristics.is_some(), "append_len": se.append_bytes.len(), "prepend_len": se.prepend_bytes.len(), "source": "rustre_pe_editor::SectionEdit::zero"}).to_string())) } }

pub struct PeEditorPatchsetAddCountTool;
impl PeEditorPatchsetAddCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_patchset_add_count".to_string(), description: "Build a rustre_pe_editor::PatchSet, add N simple patches, and report len/is_empty/total_bytes.".to_string(), input_schema: json!({"type":"object","required":["name","patches"],"properties":{"name":{"type":"string"},"patches":{"type":"array","items":{"type":"object","required":["offset","replacement_hex"],"properties":{"offset":{"type":"integer","minimum":0},"replacement_hex":{"type":"string"},"description":{"type":"string"}}}}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorPatchsetAddCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?.to_string(); let arr = args.get("patches").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("patches".into()))?; let mut ps = rustre_pe_editor::PatchSet::new(name); for p in arr { let off = p.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("patch.offset".into()))? as usize; let rh = p.get("replacement_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("patch.replacement_hex".into()))?; let d = p.get("description").and_then(Value::as_str).unwrap_or("").to_string(); let repl = pe_editor_hex_decode(rh)?; ps.add(rustre_pe_editor::Patch::simple(off, repl, d)); } Ok(ToolResult::text(json!({"display": ps.to_string(), "len": ps.len(), "is_empty": ps.is_empty(), "total_bytes": ps.total_bytes(), "source": "rustre_pe_editor::PatchSet"}).to_string())) } }

pub struct PeEditorHeaderFieldDebugTool;
impl PeEditorHeaderFieldDebugTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_header_field_debug".to_string(), description: "Display a rustre_pe_editor::HeaderField enum variant by name.".to_string(), input_schema: json!({"type":"object","required":["field"],"properties":{"field":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorHeaderFieldDebugTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let f = args.get("field").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("field".into()))?; use rustre_pe_editor::HeaderField as H; let hf = match f { "MajorLinkerVersion" => H::MajorLinkerVersion, "MinorLinkerVersion" => H::MinorLinkerVersion, "MajorOsVersion" => H::MajorOsVersion, "MinorOsVersion" => H::MinorOsVersion, "MajorImageVersion" => H::MajorImageVersion, "MinorImageVersion" => H::MinorImageVersion, "MajorSubsystemVersion" => H::MajorSubsystemVersion, "MinorSubsystemVersion" => H::MinorSubsystemVersion, "Win32VersionValue" => H::Win32VersionValue, "SizeOfStackReserve" => H::SizeOfStackReserve, "SizeOfStackCommit" => H::SizeOfStackCommit, "SizeOfHeapReserve" => H::SizeOfHeapReserve, "SizeOfHeapCommit" => H::SizeOfHeapCommit, "Subsystem" => H::Subsystem, "DllCharacteristics" => H::DllCharacteristics, other => return Err(McpError::InvalidParams(format!("unknown field: {other}"))), }; Ok(ToolResult::text(json!({"display": hf.to_string(), "source": "rustre_pe_editor::HeaderField"}).to_string())) } }

pub struct PeEditorPatchVerifiedHasVerificationTool;
impl PeEditorPatchVerifiedHasVerificationTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_patch_verified_has_verification".to_string(), description: "Build a rustre_pe_editor::Patch::verified and return has_verification/len/display.".to_string(), input_schema: json!({"type":"object","required":["offset","original_hex","replacement_hex","description"],"properties":{"offset":{"type":"integer","minimum":0},"original_hex":{"type":"string"},"replacement_hex":{"type":"string"},"description":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorPatchVerifiedHasVerificationTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let off = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("offset".into()))? as usize; let oh = args.get("original_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("original_hex".into()))?; let rh = args.get("replacement_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("replacement_hex".into()))?; let d = args.get("description").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("description".into()))?.to_string(); let o = pe_editor_hex_decode(oh)?; let r = pe_editor_hex_decode(rh)?; let p = rustre_pe_editor::Patch::verified(off, o, r, d); Ok(ToolResult::text(json!({"display": p.to_string(), "len": p.len(), "is_empty": p.is_empty(), "has_verification": p.has_verification(), "source": "rustre_pe_editor::Patch::verified"}).to_string())) } }

pub struct PeEditorPatchSimpleDisplayTool;
impl PeEditorPatchSimpleDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_patch_simple_display".to_string(), description: "Build rustre_pe_editor::Patch::simple and return display/len/is_empty/has_verification.".to_string(), input_schema: json!({"type":"object","required":["offset","replacement_hex","description"],"properties":{"offset":{"type":"integer","minimum":0},"replacement_hex":{"type":"string"},"description":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorPatchSimpleDisplayTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let off = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("offset".into()))? as usize; let rh = args.get("replacement_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("replacement_hex".into()))?; let d = args.get("description").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("description".into()))?.to_string(); let r = pe_editor_hex_decode(rh)?; let p = rustre_pe_editor::Patch::simple(off, r, d); Ok(ToolResult::text(json!({"display": p.to_string(), "len": p.len(), "is_empty": p.is_empty(), "has_verification": p.has_verification(), "source":"rustre_pe_editor::Patch::simple"}).to_string())) } }

pub struct PeEditorPatchsetNewEmptyTool;
impl PeEditorPatchsetNewEmptyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_patchset_new_empty".to_string(), description: "Build empty rustre_pe_editor::PatchSet::new(name) and report display/len/is_empty/total_bytes.".to_string(), input_schema: json!({"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorPatchsetNewEmptyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?.to_string(); let ps = rustre_pe_editor::PatchSet::new(n); Ok(ToolResult::text(json!({"display": ps.to_string(), "len": ps.len(), "is_empty": ps.is_empty(), "total_bytes": ps.total_bytes(), "source":"rustre_pe_editor::PatchSet::new"}).to_string())) } }

pub struct PeEditorImportEntryOrdinalDisplayTool;
impl PeEditorImportEntryOrdinalDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_import_entry_ordinal_display".to_string(), description: "Build rustre_pe_editor::ImportEntry::ordinal and return display/is_named/ordinal.".to_string(), input_schema: json!({"type":"object","required":["dll","ordinal"],"properties":{"dll":{"type":"string"},"ordinal":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorImportEntryOrdinalDisplayTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let dll = args.get("dll").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("dll".into()))?.to_string(); let ord = args.get("ordinal").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("ordinal".into()))? as u16; let e = rustre_pe_editor::ImportEntry::ordinal(dll, ord); Ok(ToolResult::text(json!({"display": e.display(), "is_named": e.is_named(), "ordinal": e.ordinal, "dll": e.dll, "source":"rustre_pe_editor::ImportEntry::ordinal"}).to_string())) } }

pub struct PeEditorExportEditorPendingTool;
impl PeEditorExportEditorPendingTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_export_editor_pending".to_string(), description: "Build ExportEditor, queue add/remove edits, report pending_count/additions/removals/dll_name.".to_string(), input_schema: json!({"type":"object","required":["dll_name"],"properties":{"dll_name":{"type":"string"},"adds":{"type":"array","items":{"type":"object","required":["name","ordinal","rva"],"properties":{"name":{"type":"string"},"ordinal":{"type":"integer"},"rva":{"type":"integer"}}}},"removes":{"type":"array","items":{"type":"string"}}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorExportEditorPendingTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let dll = args.get("dll_name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("dll_name".into()))?.to_string(); let mut e = rustre_pe_editor::ExportEditor::new(dll); if let Some(a) = args.get("adds").and_then(Value::as_array) { for x in a { let n = x.get("name").and_then(Value::as_str).unwrap_or("").to_string(); let o = x.get("ordinal").and_then(Value::as_u64).unwrap_or(0) as u32; let r = x.get("rva").and_then(Value::as_u64).unwrap_or(0) as u32; e.add_export(n, o, r); } } if let Some(a) = args.get("removes").and_then(Value::as_array) { for x in a { if let Some(s) = x.as_str() { e.remove_export(s.to_string()); } } } Ok(ToolResult::text(json!({"dll_name": e.dll_name(), "pending_count": e.pending_count(), "additions": e.additions().len(), "removals": e.removals().len(), "source":"rustre_pe_editor::ExportEditor"}).to_string())) } }

pub struct PeEditorImportEditorPendingTool;
impl PeEditorImportEditorPendingTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_import_editor_pending".to_string(), description: "Build ImportEditor, queue named imports and DLL removals, report pending totals.".to_string(), input_schema: json!({"type":"object","properties":{"adds":{"type":"array","items":{"type":"object","required":["dll","name","hint"],"properties":{"dll":{"type":"string"},"name":{"type":"string"},"hint":{"type":"integer"}}}},"removes":{"type":"array","items":{"type":"string"}}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorImportEditorPendingTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let mut e = rustre_pe_editor::ImportEditor::new(); if let Some(a) = args.get("adds").and_then(Value::as_array) { for x in a { let dll = x.get("dll").and_then(Value::as_str).unwrap_or("").to_string(); let n = x.get("name").and_then(Value::as_str).unwrap_or("").to_string(); let h = x.get("hint").and_then(Value::as_u64).unwrap_or(0) as u16; e.add_import(rustre_pe_editor::ImportEntry::named(dll, n, h)); } } if let Some(a) = args.get("removes").and_then(Value::as_array) { for x in a { if let Some(s) = x.as_str() { e.remove_dll(s.to_string()); } } } Ok(ToolResult::text(json!({"pending_additions": e.pending_additions(), "pending_removals": e.pending_removals(), "additions_len": e.additions().len(), "removals_len": e.removals().len(), "source":"rustre_pe_editor::ImportEditor"}).to_string())) } }

pub struct PeEditorResourceEditorTotalsTool;
impl PeEditorResourceEditorTotalsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_resource_editor_totals".to_string(), description: "Build ResourceEditor, add resources by hex data, report pending totals + total_data_size.".to_string(), input_schema: json!({"type":"object","properties":{"adds":{"type":"array","items":{"type":"object","required":["resource_type","id","language","data_hex"],"properties":{"resource_type":{"type":"integer"},"id":{"type":"integer"},"language":{"type":"integer"},"data_hex":{"type":"string"}}}}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorResourceEditorTotalsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let mut e = rustre_pe_editor::ResourceEditor::new(); if let Some(a) = args.get("adds").and_then(Value::as_array) { for x in a { let rt = x.get("resource_type").and_then(Value::as_u64).unwrap_or(0) as u16; let id = x.get("id").and_then(Value::as_u64).unwrap_or(0) as u32; let lang = x.get("language").and_then(Value::as_u64).unwrap_or(0) as u16; let dh = x.get("data_hex").and_then(Value::as_str).unwrap_or(""); let d = pe_editor_hex_decode(dh)?; e.add_resource(rustre_pe_editor::ResourceEntry::new(rt, id, lang, d)); } } Ok(ToolResult::text(json!({"pending_additions": e.pending_additions(), "pending_removals": e.pending_removals(), "total_data_size": e.total_data_size(), "additions_len": e.additions().len(), "source":"rustre_pe_editor::ResourceEditor"}).to_string())) } }

pub struct PeEditorResourceEntryNewLenTool;
impl PeEditorResourceEntryNewLenTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_resource_entry_new_len".to_string(), description: "Build rustre_pe_editor::ResourceEntry::new and report len/is_empty/display.".to_string(), input_schema: json!({"type":"object","required":["resource_type","id","language","data_hex"],"properties":{"resource_type":{"type":"integer"},"id":{"type":"integer"},"language":{"type":"integer"},"data_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorResourceEntryNewLenTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let rt = args.get("resource_type").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("resource_type".into()))? as u16; let id = args.get("id").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("id".into()))? as u32; let lang = args.get("language").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("language".into()))? as u16; let dh = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("data_hex".into()))?; let d = pe_editor_hex_decode(dh)?; let r = rustre_pe_editor::ResourceEntry::new(rt, id, lang, d); Ok(ToolResult::text(json!({"display": r.to_string(), "len": r.len(), "is_empty": r.is_empty(), "id": r.id, "language": r.language, "source":"rustre_pe_editor::ResourceEntry::new"}).to_string())) } }

pub struct PeEditorSectionEditSetCharsFlagsTool;
impl PeEditorSectionEditSetCharsFlagsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_section_edit_set_chars_flags".to_string(), description: "Build rustre_pe_editor::SectionEdit::set_chars(name, chars) and report fields.".to_string(), input_schema: json!({"type":"object","required":["name","characteristics"],"properties":{"name":{"type":"string"},"characteristics":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorSectionEditSetCharsFlagsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?.to_string(); let c = args.get("characteristics").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("characteristics".into()))? as u32; let se = rustre_pe_editor::SectionEdit::set_chars(n, c); Ok(ToolResult::text(json!({"name": se.name, "new_characteristics": se.new_characteristics, "zero_out": se.zero_out, "append_len": se.append_bytes.len(), "prepend_len": se.prepend_bytes.len(), "source":"rustre_pe_editor::SectionEdit::set_chars"}).to_string())) } }

pub struct PeEditorCertificateHeaderToBytesTool;
impl PeEditorCertificateHeaderToBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_certificate_header_to_bytes".to_string(), description: "Serialize rustre_pe_editor::CertificateHeader::new(payload_len).to_bytes() as hex.".to_string(), input_schema: json!({"type":"object","required":["payload_len"],"properties":{"payload_len":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorCertificateHeaderToBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pl = args.get("payload_len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("payload_len".into()))? as u32; let h = rustre_pe_editor::CertificateHeader::new(pl); let b = h.to_bytes(); Ok(ToolResult::text(json!({"bytes_hex": pe_editor_hex_encode(&b), "dw_length": h.dw_length, "w_revision": h.w_revision, "w_certificate_type": h.w_certificate_type, "source":"rustre_pe_editor::CertificateHeader::to_bytes"}).to_string())) } }

pub struct PeEditorRc4ProcessBytesTool;
impl PeEditorRc4ProcessBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_rc4_process_bytes".to_string(), description: "Encrypt/decrypt hex data with rustre_pe_editor::Rc4::new(key).process(&mut data).".to_string(), input_schema: json!({"type":"object","required":["key_hex","data_hex"],"properties":{"key_hex":{"type":"string"},"data_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorRc4ProcessBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let kh = args.get("key_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("key_hex".into()))?; let dh = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("data_hex".into()))?; let key = pe_editor_hex_decode(kh)?; if key.is_empty() { return Err(McpError::InvalidParams("key must not be empty".into())); } let mut data = pe_editor_hex_decode(dh)?; let mut rc4 = rustre_pe_editor::Rc4::new(&key); rc4.process(&mut data); Ok(ToolResult::text(json!({"out_hex": pe_editor_hex_encode(&data), "len": data.len(), "source":"rustre_pe_editor::Rc4::process"}).to_string())) } }

pub struct PeEditorXorSectionBytesTool;
impl PeEditorXorSectionBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_xor_section_bytes".to_string(), description: "Apply rustre_pe_editor::xor_section(data, key) with a non-empty repeating key.".to_string(), input_schema: json!({"type":"object","required":["data_hex","key_hex"],"properties":{"data_hex":{"type":"string"},"key_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorXorSectionBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let dh = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("data_hex".into()))?; let kh = args.get("key_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("key_hex".into()))?; let mut d = pe_editor_hex_decode(dh)?; let k = pe_editor_hex_decode(kh)?; if k.is_empty() { return Err(McpError::InvalidParams("key must not be empty".into())); } rustre_pe_editor::xor_section(&mut d, &k); Ok(ToolResult::text(json!({"out_hex": pe_editor_hex_encode(&d), "len": d.len(), "source":"rustre_pe_editor::xor_section"}).to_string())) } }

pub struct PeEditorPatchEmptyCheckTool;
impl PeEditorPatchEmptyCheckTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_patch_empty_check".to_string(), description: "Build rustre_pe_editor::Patch::simple with empty replacement and confirm is_empty()/len().".to_string(), input_schema: json!({"type":"object","required":["offset","description"],"properties":{"offset":{"type":"integer","minimum":0},"description":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorPatchEmptyCheckTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let off = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("offset".into()))? as usize; let d = args.get("description").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("description".into()))?.to_string(); let p = rustre_pe_editor::Patch::simple(off, Vec::new(), d); Ok(ToolResult::text(json!({"display": p.to_string(), "len": p.len(), "is_empty": p.is_empty(), "has_verification": p.has_verification(), "source":"rustre_pe_editor::Patch::simple"}).to_string())) } }

pub struct PeEditorPatchVerifiedLenTool;
impl PeEditorPatchVerifiedLenTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_patch_verified_len".to_string(), description: "Build rustre_pe_editor::Patch::verified and report len/is_empty/has_verification/display.".to_string(), input_schema: json!({"type":"object","required":["offset","original_hex","replacement_hex","description"],"properties":{"offset":{"type":"integer","minimum":0},"original_hex":{"type":"string"},"replacement_hex":{"type":"string"},"description":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorPatchVerifiedLenTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let off = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("offset".into()))? as usize; let oh = args.get("original_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("original_hex".into()))?; let rh = args.get("replacement_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("replacement_hex".into()))?; let d = args.get("description").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("description".into()))?.to_string(); let orig = pe_editor_hex_decode(oh)?; let repl = pe_editor_hex_decode(rh)?; let p = rustre_pe_editor::Patch::verified(off, orig, repl, d); Ok(ToolResult::text(json!({"display": p.to_string(), "len": p.len(), "is_empty": p.is_empty(), "has_verification": p.has_verification(), "offset": p.offset, "source": "rustre_pe_editor::Patch::verified"}).to_string())) } }

pub struct PeEditorPatchsetDefaultEmptyTool;
impl PeEditorPatchsetDefaultEmptyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_patchset_default_empty".to_string(), description: "Build rustre_pe_editor::PatchSet::default() and report len/is_empty/total_bytes/display.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorPatchsetDefaultEmptyTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let ps: rustre_pe_editor::PatchSet = rustre_pe_editor::PatchSet::default(); Ok(ToolResult::text(json!({"display": ps.to_string(), "len": ps.len(), "is_empty": ps.is_empty(), "total_bytes": ps.total_bytes(), "name": ps.name, "source": "rustre_pe_editor::PatchSet::default"}).to_string())) } }

pub struct PeEditorPatchsetAddMultiTool;
impl PeEditorPatchsetAddMultiTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_patchset_add_multi".to_string(), description: "Build a rustre_pe_editor::PatchSet and add two Patch::simple entries, reporting total_bytes/len.".to_string(), input_schema: json!({"type":"object","required":["name","repl1_hex","repl2_hex"],"properties":{"name":{"type":"string"},"repl1_hex":{"type":"string"},"repl2_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorPatchsetAddMultiTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?.to_string(); let r1 = pe_editor_hex_decode(args.get("repl1_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("repl1_hex".into()))?)?; let r2 = pe_editor_hex_decode(args.get("repl2_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("repl2_hex".into()))?)?; let mut ps = rustre_pe_editor::PatchSet::new(name); ps.add(rustre_pe_editor::Patch::simple(0, r1, "p1".to_string())); ps.add(rustre_pe_editor::Patch::simple(0x100, r2, "p2".to_string())); Ok(ToolResult::text(json!({"display": ps.to_string(), "len": ps.len(), "is_empty": ps.is_empty(), "total_bytes": ps.total_bytes(), "source": "rustre_pe_editor::PatchSet::add"}).to_string())) } }

pub struct PeEditorSectionEditZeroFieldsTool;
impl PeEditorSectionEditZeroFieldsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_section_edit_zero_fields".to_string(), description: "Build rustre_pe_editor::SectionEdit::zero(name) and dump all field snapshot.".to_string(), input_schema: json!({"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorSectionEditZeroFieldsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?.to_string(); let se = rustre_pe_editor::SectionEdit::zero(n); Ok(ToolResult::text(json!({"name": se.name, "zero_out": se.zero_out, "new_characteristics": se.new_characteristics, "append_bytes_hex": pe_editor_hex_encode(&se.append_bytes), "prepend_bytes_hex": pe_editor_hex_encode(&se.prepend_bytes), "source": "rustre_pe_editor::SectionEdit::zero"}).to_string())) } }

pub struct PeEditorRc4NextByteSequenceTool;
impl PeEditorRc4NextByteSequenceTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_rc4_next_byte_sequence".to_string(), description: "Produce first N keystream bytes from rustre_pe_editor::Rc4::next_byte and return their sum.".to_string(), input_schema: json!({"type":"object","required":["key_hex","n"],"properties":{"key_hex":{"type":"string"},"n":{"type":"integer","minimum":0,"maximum":65536}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorRc4NextByteSequenceTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let kh = args.get("key_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("key_hex".into()))?; let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("n".into()))? as usize; let key = pe_editor_hex_decode(kh)?; if key.is_empty() { return Err(McpError::InvalidParams("key must not be empty".into())); } let mut rc4 = rustre_pe_editor::Rc4::new(&key); let mut buf = Vec::with_capacity(n); let mut sum: u64 = 0; for _ in 0..n { let b = rc4.next_byte(); sum += u64::from(b); buf.push(b); } Ok(ToolResult::text(json!({"first_hex": pe_editor_hex_encode(&buf), "len": buf.len(), "byte_sum": sum, "source": "rustre_pe_editor::Rc4::next_byte"}).to_string())) } }

pub struct PeEditorCertificateHeaderBytesLenTool;
impl PeEditorCertificateHeaderBytesLenTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_certificate_header_bytes_len".to_string(), description: "Confirm rustre_pe_editor::CertificateHeader::to_bytes() length is exactly 8.".to_string(), input_schema: json!({"type":"object","required":["payload_len"],"properties":{"payload_len":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorCertificateHeaderBytesLenTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pl = args.get("payload_len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("payload_len".into()))? as u32; let h = rustre_pe_editor::CertificateHeader::new(pl); let b = h.to_bytes(); Ok(ToolResult::text(json!({"len": b.len(), "expected": 8usize, "dw_length": h.dw_length, "source": "rustre_pe_editor::CertificateHeader::to_bytes"}).to_string())) } }

pub struct PeEditorSectionCharsConstantsTool;
impl PeEditorSectionCharsConstantsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_section_chars_constants".to_string(), description: "Return rustre_pe_editor::section_chars::* flag constants.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorSectionCharsConstantsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { Ok(ToolResult::text(json!({"CODE": rustre_pe_editor::section_chars::CODE, "INITIALIZED_DATA": rustre_pe_editor::section_chars::INITIALIZED_DATA, "UNINITIALIZED_DATA": rustre_pe_editor::section_chars::UNINITIALIZED_DATA, "MEM_DISCARDABLE": rustre_pe_editor::section_chars::MEM_DISCARDABLE, "MEM_EXECUTE": rustre_pe_editor::section_chars::MEM_EXECUTE, "MEM_READ": rustre_pe_editor::section_chars::MEM_READ, "MEM_WRITE": rustre_pe_editor::section_chars::MEM_WRITE, "source": "rustre_pe_editor::section_chars"}).to_string())) } }

pub struct PeEditorImportEditorDefaultEmptyTool;
impl PeEditorImportEditorDefaultEmptyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_import_editor_default_empty".to_string(), description: "Build rustre_pe_editor::ImportEditor::default() and confirm additions/removals are empty.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorImportEditorDefaultEmptyTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let ie: rustre_pe_editor::ImportEditor = rustre_pe_editor::ImportEditor::default(); Ok(ToolResult::text(json!({"additions_len": ie.additions().len(), "removals_len": ie.removals().len(), "source": "rustre_pe_editor::ImportEditor::default"}).to_string())) } }

pub struct PeEditorExportEditorNewDllTool;
impl PeEditorExportEditorNewDllTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_export_editor_new_dll".to_string(), description: "Build rustre_pe_editor::ExportEditor::new(dll) and report dll_name/additions/removals.".to_string(), input_schema: json!({"type":"object","required":["dll"],"properties":{"dll":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorExportEditorNewDllTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let dll = args.get("dll").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("dll".into()))?.to_string(); let ee = rustre_pe_editor::ExportEditor::new(dll); Ok(ToolResult::text(json!({"dll_name": ee.dll_name(), "additions_len": ee.additions().len(), "removals_len": ee.removals().len(), "source": "rustre_pe_editor::ExportEditor::new"}).to_string())) } }

pub struct PeEditorResourceEditorDefaultTotalsTool;
impl PeEditorResourceEditorDefaultTotalsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_resource_editor_default_totals".to_string(), description: "Build rustre_pe_editor::ResourceEditor::default() and report total_data_size/additions.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorResourceEditorDefaultTotalsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let re: rustre_pe_editor::ResourceEditor = rustre_pe_editor::ResourceEditor::default(); Ok(ToolResult::text(json!({"additions_len": re.additions().len(), "total_data_size": re.total_data_size(), "source": "rustre_pe_editor::ResourceEditor::default"}).to_string())) } }

pub struct PeEditorImportEntryOrdinalIsNamedTool;
impl PeEditorImportEntryOrdinalIsNamedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_import_entry_ordinal_is_named".to_string(), description: "Build rustre_pe_editor::ImportEntry::ordinal(dll, ord) and confirm is_named() == false.".to_string(), input_schema: json!({"type":"object","required":["dll","ordinal"],"properties":{"dll":{"type":"string"},"ordinal":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for PeEditorImportEntryOrdinalIsNamedTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let dll = args.get("dll").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("dll".into()))?.to_string(); let ord = args.get("ordinal").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("ordinal".into()))? as u16; let e = rustre_pe_editor::ImportEntry::ordinal(dll, ord); Ok(ToolResult::text(json!({"display": e.display(), "is_named": e.is_named(), "dll": e.dll, "hint": e.hint, "source": "rustre_pe_editor::ImportEntry::ordinal"}).to_string())) } }

pub struct PeEditorXPatchIsEmptyTool;
impl PeEditorXPatchIsEmptyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_x_patch_is_empty".to_string(), description: "Build rustre_pe_editor::Patch::simple and check is_empty()/len()/has_verification().".to_string(), input_schema: json!({"type":"object","properties":{"offset":{"type":"integer"},"repl_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for PeEditorXPatchIsEmptyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let off = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize; let hex_s: String = args.get("repl_hex").and_then(Value::as_str).unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect(); let repl: Vec<u8> = (0..hex_s.len()).step_by(2).filter_map(|i| u8::from_str_radix(hex_s.get(i..i+2)?, 16).ok()).collect(); let p = rustre_pe_editor::Patch::simple(off, repl, "x".to_string()); Ok(ToolResult::text(json!({"is_empty":p.is_empty(),"len":p.len(),"has_verification":p.has_verification(),"source":"rustre_pe_editor::Patch::is_empty"}).to_string())) } }

pub struct PeEditorXPatchsetIsEmptyTool;
impl PeEditorXPatchsetIsEmptyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_x_patchset_is_empty".to_string(), description: "Build rustre_pe_editor::PatchSet::new and check is_empty()/len().".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for PeEditorXPatchsetIsEmptyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).unwrap_or("ps").to_string(); let ps = rustre_pe_editor::PatchSet::new(name); Ok(ToolResult::text(json!({"is_empty":ps.is_empty(),"len":ps.len(),"display":ps.to_string(),"source":"rustre_pe_editor::PatchSet::is_empty"}).to_string())) } }

pub struct PeEditorXPatchsetTotalBytesTool;
impl PeEditorXPatchsetTotalBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_x_patchset_total_bytes_after_add".to_string(), description: "Add 3 fixed patches then read rustre_pe_editor::PatchSet::total_bytes.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for PeEditorXPatchsetTotalBytesTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut ps = rustre_pe_editor::PatchSet::new("t".to_string()); ps.add(rustre_pe_editor::Patch::simple(0, vec![0u8;4], "a".to_string())); ps.add(rustre_pe_editor::Patch::simple(4, vec![0u8;8], "b".to_string())); ps.add(rustre_pe_editor::Patch::simple(12, vec![0u8;2], "c".to_string())); Ok(ToolResult::text(json!({"total_bytes":ps.total_bytes(),"len":ps.len(),"source":"rustre_pe_editor::PatchSet::total_bytes"}).to_string())) } }

pub struct PeEditorXResourceEntryIsEmptyTool;
impl PeEditorXResourceEntryIsEmptyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_x_resource_entry_is_empty".to_string(), description: "Build rustre_pe_editor::ResourceEntry::new and check is_empty()/len()/display.".to_string(), input_schema: json!({"type":"object","properties":{"rtype":{"type":"integer"},"id":{"type":"integer"},"data_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for PeEditorXResourceEntryIsEmptyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let rt = args.get("rtype").and_then(Value::as_u64).unwrap_or(24) as u16; let id = args.get("id").and_then(Value::as_u64).unwrap_or(1) as u32; let hex_s: String = args.get("data_hex").and_then(Value::as_str).unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect(); let data: Vec<u8> = (0..hex_s.len()).step_by(2).filter_map(|i| u8::from_str_radix(hex_s.get(i..i+2)?, 16).ok()).collect(); let e = rustre_pe_editor::ResourceEntry::new(rt, id, 0x0409, data); Ok(ToolResult::text(json!({"is_empty":e.is_empty(),"len":e.len(),"display":e.to_string(),"source":"rustre_pe_editor::ResourceEntry::is_empty"}).to_string())) } }

pub struct PeEditorXResourceEditorTotalDataSizeTool;
impl PeEditorXResourceEditorTotalDataSizeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_x_resource_editor_total_data_size".to_string(), description: "Add manifest + 2 entries, then read rustre_pe_editor::ResourceEditor::total_data_size.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for PeEditorXResourceEditorTotalDataSizeTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut r = rustre_pe_editor::ResourceEditor::new(); r.add_resource(rustre_pe_editor::ResourceEntry::manifest(vec![0u8;16])); r.add_resource(rustre_pe_editor::ResourceEntry::new(3,2,0x0409,vec![0u8;32])); Ok(ToolResult::text(json!({"total_data_size":r.total_data_size(),"pending_additions":r.pending_additions(),"pending_removals":r.pending_removals(),"source":"rustre_pe_editor::ResourceEditor::total_data_size"}).to_string())) } }

pub struct PeEditorXImportEntryIsNamedFlagTool;
impl PeEditorXImportEntryIsNamedFlagTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_x_import_entry_is_named_flag".to_string(), description: "Build both rustre_pe_editor::ImportEntry::named and ::ordinal and report is_named/display.".to_string(), input_schema: json!({"type":"object","properties":{"dll":{"type":"string"},"name":{"type":"string"},"ordinal":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for PeEditorXImportEntryIsNamedFlagTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let dll = args.get("dll").and_then(Value::as_str).unwrap_or("k32.dll").to_string(); let name = args.get("name").and_then(Value::as_str).unwrap_or("Fn").to_string(); let ord = args.get("ordinal").and_then(Value::as_u64).unwrap_or(7) as u16; let a = rustre_pe_editor::ImportEntry::named(dll.clone(), name, 0); let b = rustre_pe_editor::ImportEntry::ordinal(dll, ord); Ok(ToolResult::text(json!({"named":{"is_named":a.is_named(),"display":a.display()},"ordinal":{"is_named":b.is_named(),"display":b.display()},"source":"rustre_pe_editor::ImportEntry::is_named"}).to_string())) } }

pub struct PeEditorXExportEditorPendingCountTool;
impl PeEditorXExportEditorPendingCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_x_export_editor_pending_count".to_string(), description: "Add/remove exports and report pending_count/additions/removals via rustre_pe_editor::ExportEditor.".to_string(), input_schema: json!({"type":"object","properties":{"dll":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for PeEditorXExportEditorPendingCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let dll = args.get("dll").and_then(Value::as_str).unwrap_or("mylib.dll").to_string(); let mut e = rustre_pe_editor::ExportEditor::new(dll); e.add_export("A".to_string(),1,0x1000); e.add_export("B".to_string(),2,0x1010); e.remove_export("Old".to_string()); Ok(ToolResult::text(json!({"pending_count":e.pending_count(),"additions":e.additions().len(),"removals":e.removals().len(),"source":"rustre_pe_editor::ExportEditor::pending_count"}).to_string())) } }

pub struct PeEditorXExportEditorDllNameTool;
impl PeEditorXExportEditorDllNameTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_x_export_editor_dll_name".to_string(), description: "Return rustre_pe_editor::ExportEditor::dll_name.".to_string(), input_schema: json!({"type":"object","properties":{"dll":{"type":"string"}},"required":["dll"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for PeEditorXExportEditorDllNameTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let dll = args.get("dll").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'dll'".into()))?.to_string(); let e = rustre_pe_editor::ExportEditor::new(dll); Ok(ToolResult::text(json!({"dll_name":e.dll_name(),"pending_count":e.pending_count(),"source":"rustre_pe_editor::ExportEditor::dll_name"}).to_string())) } }

pub struct PeEditorXSectionEditZeroBuildTool;
impl PeEditorXSectionEditZeroBuildTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_x_section_edit_zero_build".to_string(), description: "Build rustre_pe_editor::SectionEdit::zero and report fields.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for PeEditorXSectionEditZeroBuildTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).unwrap_or(".text").to_string(); let se = rustre_pe_editor::SectionEdit::zero(name); Ok(ToolResult::text(json!({"name":se.name,"zero_out":se.zero_out,"new_characteristics":se.new_characteristics,"append_len":se.append_bytes.len(),"prepend_len":se.prepend_bytes.len(),"source":"rustre_pe_editor::SectionEdit::zero"}).to_string())) } }

pub struct PeEditorXResourceTypesConstantsTool;
impl PeEditorXResourceTypesConstantsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_x_resource_types_constants".to_string(), description: "Return rustre_pe_editor::resource_types::RT_* constants.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for PeEditorXResourceTypesConstantsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_pe_editor::resource_types as rt; Ok(ToolResult::text(json!({"RT_CURSOR":rt::RT_CURSOR,"RT_BITMAP":rt::RT_BITMAP,"RT_ICON":rt::RT_ICON,"RT_MENU":rt::RT_MENU,"RT_DIALOG":rt::RT_DIALOG,"RT_STRING":rt::RT_STRING,"RT_VERSION":rt::RT_VERSION,"RT_MANIFEST":rt::RT_MANIFEST,"source":"rustre_pe_editor::resource_types"}).to_string())) } }

pub struct PeEditorXSigningScaffoldPayloadLenTool;
impl PeEditorXSigningScaffoldPayloadLenTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_x_signing_scaffold_payload_len".to_string(), description: "Build rustre_pe_editor::PeSigningScaffold::new and read payload_len/build_certificate_blob length.".to_string(), input_schema: json!({"type":"object","properties":{"payload_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for PeEditorXSigningScaffoldPayloadLenTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex_s: String = args.get("payload_hex").and_then(Value::as_str).unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect(); let payload: Vec<u8> = (0..hex_s.len()).step_by(2).filter_map(|i| u8::from_str_radix(hex_s.get(i..i+2)?, 16).ok()).collect(); let s = rustre_pe_editor::PeSigningScaffold::new(payload); let blob = s.build_certificate_blob(); Ok(ToolResult::text(json!({"payload_len":s.payload_len(),"blob_len":blob.len(),"source":"rustre_pe_editor::PeSigningScaffold::payload_len"}).to_string())) } }

pub struct PeEditorXHeaderFieldAllDisplayTool;
impl PeEditorXHeaderFieldAllDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "pe_editor_x_header_field_all_display".to_string(), description: "Display every rustre_pe_editor::HeaderField variant via Display impl.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for PeEditorXHeaderFieldAllDisplayTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_pe_editor::HeaderField as H; let all = [H::MajorLinkerVersion,H::MinorLinkerVersion,H::MajorOsVersion,H::MinorOsVersion,H::MajorImageVersion,H::MinorImageVersion,H::MajorSubsystemVersion,H::MinorSubsystemVersion,H::Win32VersionValue,H::SizeOfStackReserve,H::SizeOfStackCommit,H::SizeOfHeapReserve,H::SizeOfHeapCommit,H::Subsystem,H::DllCharacteristics]; let names: Vec<String> = all.iter().map(|h| h.to_string()).collect(); Ok(ToolResult::text(json!({"count":names.len(),"names":names,"source":"rustre_pe_editor::HeaderField::Display"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (PeEditorCertificateHeaderTool::definition(), Box::new(PeEditorCertificateHeaderTool)),
        (PeEditorPatchSetNewTool::definition(), Box::new(PeEditorPatchSetNewTool)),
        (PeEditorExportAddTool::definition(), Box::new(PeEditorExportAddTool)),
        (PeEditorExportRemoveTool::definition(), Box::new(PeEditorExportRemoveTool)),
        (PeEditorPatchVerifiedTool::definition(), Box::new(PeEditorPatchVerifiedTool)),
        (PeEditorPatchSetTotalBytesTool::definition(), Box::new(PeEditorPatchSetTotalBytesTool)),
        (PeEditorImportEntryOrdinalTool::definition(), Box::new(PeEditorImportEntryOrdinalTool)),
        (PeEditorResourceManifestTool::definition(), Box::new(PeEditorResourceManifestTool)),
        (PeEditorExportEditDisplayTool::definition(), Box::new(PeEditorExportEditDisplayTool)),
        (PeEditorSigningScaffoldBlobTool::definition(), Box::new(PeEditorSigningScaffoldBlobTool)),
        (PeEditorParseDosHeaderTool::definition(), Box::new(PeEditorParseDosHeaderTool)),
        (PeEditorParseFileHeaderTool::definition(), Box::new(PeEditorParseFileHeaderTool)),
        (PeEditorParseOptionalHeader64Tool::definition(), Box::new(PeEditorParseOptionalHeader64Tool)),
        (PeEditorBuildTreeTool::definition(), Box::new(PeEditorBuildTreeTool)),
        (PeEditorCertificateHeaderNewTool::definition(), Box::new(PeEditorCertificateHeaderNewTool)),
        (PeEditorPatchLenTool::definition(), Box::new(PeEditorPatchLenTool)),
        (PeEditorSectionEditSetCharsTool::definition(), Box::new(PeEditorSectionEditSetCharsTool)),
        (PeEditorSectionEditZeroTool::definition(), Box::new(PeEditorSectionEditZeroTool)),
        (PeEditorImportEditorNewTool::definition(), Box::new(PeEditorImportEditorNewTool)),
        (PeEditorExportEditorNewTool::definition(), Box::new(PeEditorExportEditorNewTool)),
        (PeEditorResourceEditorNewTool::definition(), Box::new(PeEditorResourceEditorNewTool)),
        (PeEditorResourceEntryNewTool::definition(), Box::new(PeEditorResourceEntryNewTool)),
        (PeEditorResourceTypeDisplayTool::definition(), Box::new(PeEditorResourceTypeDisplayTool)),
        (PeEditorSigningScaffoldNewTool::definition(), Box::new(PeEditorSigningScaffoldNewTool)),
        (PeEditorHeaderFieldDisplayTool::definition(), Box::new(PeEditorHeaderFieldDisplayTool)),
        (PeEditorImportEntryNamedIsNamedTool::definition(), Box::new(PeEditorImportEntryNamedIsNamedTool)),
        (PeEditorExportEditAddDisplayTool::definition(), Box::new(PeEditorExportEditAddDisplayTool)),
        (PeEditorExportEditRemoveDisplayTool::definition(), Box::new(PeEditorExportEditRemoveDisplayTool)),
        (PeEditorResourceEntryManifestLenTool::definition(), Box::new(PeEditorResourceEntryManifestLenTool)),
        (PeEditorResourceTypeIdDisplayTool::definition(), Box::new(PeEditorResourceTypeIdDisplayTool)),
        (PeEditorResourceTypeNameDisplayTool::definition(), Box::new(PeEditorResourceTypeNameDisplayTool)),
        (PeEditorRc4KeystreamTool::definition(), Box::new(PeEditorRc4KeystreamTool)),
        (PeEditorCertificateHeaderDwLengthTool::definition(), Box::new(PeEditorCertificateHeaderDwLengthTool)),
        (PeEditorSectionEditZeroFlagsTool::definition(), Box::new(PeEditorSectionEditZeroFlagsTool)),
        (PeEditorPatchsetAddCountTool::definition(), Box::new(PeEditorPatchsetAddCountTool)),
        (PeEditorHeaderFieldDebugTool::definition(), Box::new(PeEditorHeaderFieldDebugTool)),
        (PeEditorPatchVerifiedHasVerificationTool::definition(), Box::new(PeEditorPatchVerifiedHasVerificationTool)),
        (PeEditorPatchSimpleDisplayTool::definition(), Box::new(PeEditorPatchSimpleDisplayTool)),
        (PeEditorPatchsetNewEmptyTool::definition(), Box::new(PeEditorPatchsetNewEmptyTool)),
        (PeEditorImportEntryOrdinalDisplayTool::definition(), Box::new(PeEditorImportEntryOrdinalDisplayTool)),
        (PeEditorExportEditorPendingTool::definition(), Box::new(PeEditorExportEditorPendingTool)),
        (PeEditorImportEditorPendingTool::definition(), Box::new(PeEditorImportEditorPendingTool)),
        (PeEditorResourceEditorTotalsTool::definition(), Box::new(PeEditorResourceEditorTotalsTool)),
        (PeEditorResourceEntryNewLenTool::definition(), Box::new(PeEditorResourceEntryNewLenTool)),
        (PeEditorSectionEditSetCharsFlagsTool::definition(), Box::new(PeEditorSectionEditSetCharsFlagsTool)),
        (PeEditorCertificateHeaderToBytesTool::definition(), Box::new(PeEditorCertificateHeaderToBytesTool)),
        (PeEditorRc4ProcessBytesTool::definition(), Box::new(PeEditorRc4ProcessBytesTool)),
        (PeEditorXorSectionBytesTool::definition(), Box::new(PeEditorXorSectionBytesTool)),
        (PeEditorPatchEmptyCheckTool::definition(), Box::new(PeEditorPatchEmptyCheckTool)),
        (PeEditorPatchVerifiedLenTool::definition(), Box::new(PeEditorPatchVerifiedLenTool)),
        (PeEditorPatchsetDefaultEmptyTool::definition(), Box::new(PeEditorPatchsetDefaultEmptyTool)),
        (PeEditorPatchsetAddMultiTool::definition(), Box::new(PeEditorPatchsetAddMultiTool)),
        (PeEditorSectionEditZeroFieldsTool::definition(), Box::new(PeEditorSectionEditZeroFieldsTool)),
        (PeEditorRc4NextByteSequenceTool::definition(), Box::new(PeEditorRc4NextByteSequenceTool)),
        (PeEditorCertificateHeaderBytesLenTool::definition(), Box::new(PeEditorCertificateHeaderBytesLenTool)),
        (PeEditorSectionCharsConstantsTool::definition(), Box::new(PeEditorSectionCharsConstantsTool)),
        (PeEditorImportEditorDefaultEmptyTool::definition(), Box::new(PeEditorImportEditorDefaultEmptyTool)),
        (PeEditorExportEditorNewDllTool::definition(), Box::new(PeEditorExportEditorNewDllTool)),
        (PeEditorResourceEditorDefaultTotalsTool::definition(), Box::new(PeEditorResourceEditorDefaultTotalsTool)),
        (PeEditorImportEntryOrdinalIsNamedTool::definition(), Box::new(PeEditorImportEntryOrdinalIsNamedTool)),
        (PeEditorXPatchIsEmptyTool::definition(), Box::new(PeEditorXPatchIsEmptyTool)),
        (PeEditorXPatchsetIsEmptyTool::definition(), Box::new(PeEditorXPatchsetIsEmptyTool)),
        (PeEditorXPatchsetTotalBytesTool::definition(), Box::new(PeEditorXPatchsetTotalBytesTool)),
        (PeEditorXResourceEntryIsEmptyTool::definition(), Box::new(PeEditorXResourceEntryIsEmptyTool)),
        (PeEditorXResourceEditorTotalDataSizeTool::definition(), Box::new(PeEditorXResourceEditorTotalDataSizeTool)),
        (PeEditorXImportEntryIsNamedFlagTool::definition(), Box::new(PeEditorXImportEntryIsNamedFlagTool)),
        (PeEditorXExportEditorPendingCountTool::definition(), Box::new(PeEditorXExportEditorPendingCountTool)),
        (PeEditorXExportEditorDllNameTool::definition(), Box::new(PeEditorXExportEditorDllNameTool)),
        (PeEditorXSectionEditZeroBuildTool::definition(), Box::new(PeEditorXSectionEditZeroBuildTool)),
        (PeEditorXResourceTypesConstantsTool::definition(), Box::new(PeEditorXResourceTypesConstantsTool)),
        (PeEditorXSigningScaffoldPayloadLenTool::definition(), Box::new(PeEditorXSigningScaffoldPayloadLenTool)),
        (PeEditorXHeaderFieldAllDisplayTool::definition(), Box::new(PeEditorXHeaderFieldAllDisplayTool)),
    ]
}
