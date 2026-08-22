//! MCP wrappers for the rustre-dotnet_metadata crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{libfuzzer_hex_str_to_bytes};

pub struct DotnetMetadataParseFieldSigBlobTool;

pub struct DotnetMetadataParseLocalVarSigTool;

pub struct DotnetMetadataParseMethodSigBlobTool;

pub struct DotnetMetadataPrettyPrintTypeSigTool;

pub struct DotnetMetadataParseArrayShapeTool;
impl DotnetMetadataParseArrayShapeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_parse_array_shape".to_string(),
            description: "Parse a .NET ArrayShape blob (hex) into rank/sizes/lower_bounds via rustre_dotnet_metadata::parse_array_shape.".to_string(),
            input_schema: json!({"type":"object","properties":{"blob_hex":{"type":"string"}},"required":["blob_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataParseArrayShapeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("blob_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'blob_hex'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let s = rustre_dotnet_metadata::parse_array_shape(&bytes).map_err(|e| McpError::InternalError(format!("parse_array_shape: {e}")))?;
        Ok(ToolResult::text(json!({
            "rank": s.rank,
            "sizes": s.sizes,
            "lower_bounds": s.lower_bounds,
            "bracket_notation": s.bracket_notation(),
            "is_simple_szarray": s.is_simple_szarray(),
            "source": "rustre_dotnet_metadata::parse_array_shape"
        }).to_string()))
    }
}

pub struct DotnetMetadataParseCustomAttributeBlobTool;
impl DotnetMetadataParseCustomAttributeBlobTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_parse_custom_attribute_blob".to_string(),
            description: "Parse a .NET CustomAttribute blob (hex) via rustre_dotnet_metadata::parse_custom_attribute_blob.".to_string(),
            input_schema: json!({"type":"object","properties":{"blob_hex":{"type":"string"}},"required":["blob_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataParseCustomAttributeBlobTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("blob_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'blob_hex'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let decoded = rustre_dotnet_metadata::parse_custom_attribute_blob(&bytes).map_err(|e| McpError::InternalError(format!("parse_custom_attribute_blob: {e}")))?;
        Ok(ToolResult::text(json!({
            "fixed_arg_count": decoded.fixed_args.len(),
            "named_arg_count": decoded.named_args.len(),
            "source": "rustre_dotnet_metadata::parse_custom_attribute_blob"
        }).to_string()))
    }
}

pub struct DotnetMetadataParseDirectSummaryTool;
impl DotnetMetadataParseDirectSummaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_parse_direct_summary".to_string(),
            description: "Parse a .NET metadata blob (hex) and return aggregate statistics.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataParseDirectSummaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let stats = reader.statistics();
        Ok(ToolResult::text(json!({
            "string_heap_total_bytes": stats.string_heap_total_bytes,
            "blob_heap_total_bytes": stats.blob_heap_total_bytes,
            "total_rows": stats.total_rows,
            "custom_attribute_count": stats.custom_attribute_count,
            "generic_type_count": stats.generic_type_count,
            "source": "rustre_dotnet_metadata::parse_metadata_direct"
        }).to_string()))
    }
}

pub struct DotnetMetadataTypeFullNamesTool;
impl DotnetMetadataTypeFullNamesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_type_full_names".to_string(),
            description: "Return all TypeDef full names from a .NET metadata image (hex).".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataTypeFullNamesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let names = reader.type_full_names();
        Ok(ToolResult::text(json!({"count": names.len(), "names": names, "source": "rustre_dotnet_metadata::MetadataReader::type_full_names"}).to_string()))
    }
}

pub struct DotnetMetadataAllMethodNamesTool;
impl DotnetMetadataAllMethodNamesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_all_method_names".to_string(),
            description: "Return unique MethodDef names from a .NET metadata image (hex).".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataAllMethodNamesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let names = reader.all_method_names_unique();
        Ok(ToolResult::text(json!({"count": names.len(), "names": names, "source": "rustre_dotnet_metadata::MetadataReader::all_method_names_unique"}).to_string()))
    }
}

pub struct DotnetMetadataFindTypeTool;
impl DotnetMetadataFindTypeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_find_type".to_string(),
            description: "Look up a TypeDef by name in a .NET metadata image (hex).".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"},"name":{"type":"string"}},"required":["data_hex","name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataFindTypeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let idx = reader.type_def_index(name);
        Ok(ToolResult::text(json!({"name": name, "index": idx, "found": idx.is_some(), "source": "rustre_dotnet_metadata::MetadataReader::type_def_index"}).to_string()))
    }
}

pub struct DotnetMetadataTableSummaryTool;
impl DotnetMetadataTableSummaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_table_summary".to_string(),
            description: "Return a human-readable table row-count summary for a .NET metadata image (hex).".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataTableSummaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        Ok(ToolResult::text(json!({"summary": reader.table_summary(), "source": "rustre_dotnet_metadata::MetadataReader::table_summary"}).to_string()))
    }
}

pub struct DotnetMetadataValidateTool;
impl DotnetMetadataValidateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_validate".to_string(),
            description: "Validate a .NET metadata image (hex) via rustre_dotnet_metadata::validate_metadata.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataValidateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let vr = rustre_dotnet_metadata::validate_metadata(&reader);
        let issues: Vec<Value> = vr.issues.iter().map(|i| json!({"message": i.message, "is_error": i.is_error})).collect();
        Ok(ToolResult::text(json!({"is_valid": vr.is_valid(), "issue_count": vr.issue_count(), "issues": issues, "source": "rustre_dotnet_metadata::validate_metadata"}).to_string()))
    }
}

pub struct DotnetMetadataParseMethodBodyTool;
impl DotnetMetadataParseMethodBodyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_parse_method_body".to_string(),
            description: "Parse a CIL method body from a raw PE image (hex) at file_offset.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_hex":{"type":"string"},"file_offset":{"type":"integer","minimum":0}},"required":["image_hex","file_offset"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataParseMethodBodyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("image_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'image_hex'".into()))?;
        let off = args.get("file_offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'file_offset'".into()))? as usize;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let body = rustre_dotnet_metadata::parse_method_body(&bytes, off).map_err(|e| McpError::InternalError(format!("parse_method_body: {e}")))?;
        Ok(ToolResult::text(json!({
            "init_locals": body.init_locals,
            "max_stack": body.max_stack,
            "local_var_sig_token": body.local_var_sig_token,
            "code_size": body.code_size(),
            "exception_clause_count": body.exception_clauses.len(),
            "catch_count": body.catch_clauses().len(),
            "finally_count": body.finally_clauses().len(),
            "has_exception_handlers": body.has_exception_handlers(),
            "source": "rustre_dotnet_metadata::parse_method_body"
        }).to_string()))
    }
}

pub struct DotnetMetadataAssemblyManifestTool;
impl DotnetMetadataAssemblyManifestTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_assembly_manifest".to_string(),
            description: "Extract AssemblyManifest from a .NET metadata image (hex).".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataAssemblyManifestTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let m = reader.assembly_manifest();
        Ok(ToolResult::text(json!({
            "found": m.is_some(),
            "manifest": m.as_ref().map(|a| json!({
                "name": a.name,
                "culture": a.culture,
                "version": a.version_string(),
                "reference_count": a.reference_count,
                "exported_type_count": a.exported_type_count,
                "resource_count": a.resource_count,
                "file_count": a.file_count,
                "has_culture": a.has_culture(),
                "has_resources": a.has_resources(),
            })),
            "source": "rustre_dotnet_metadata::MetadataReader::assembly_manifest"
        }).to_string()))
    }
}

pub struct DotnetMetadataAllModuleNamesTool;
impl DotnetMetadataAllModuleNamesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_all_module_names".to_string(),
            description: "Return Module + ModuleRef names.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataAllModuleNamesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let names = reader.all_module_names();
        Ok(ToolResult::text(json!({"count": names.len(), "names": names, "source": "rustre_dotnet_metadata::MetadataReader::all_module_names"}).to_string()))
    }
}

pub struct DotnetMetadataExportedTypeNamesTool;
impl DotnetMetadataExportedTypeNamesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_exported_type_names".to_string(),
            description: "Return ExportedType full names.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataExportedTypeNamesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let names = reader.exported_type_names();
        Ok(ToolResult::text(json!({"count": names.len(), "names": names, "source": "rustre_dotnet_metadata::MetadataReader::exported_type_names"}).to_string()))
    }
}

pub struct DotnetMetadataResourceNamesTool;
impl DotnetMetadataResourceNamesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_resource_names".to_string(),
            description: "Return ManifestResource names.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataResourceNamesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let names = reader.resource_names();
        Ok(ToolResult::text(json!({"count": names.len(), "names": names, "source": "rustre_dotnet_metadata::MetadataReader::resource_names"}).to_string()))
    }
}

pub struct DotnetMetadataFileNamesTool;
impl DotnetMetadataFileNamesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_file_names".to_string(),
            description: "Return File table names.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataFileNamesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let names = reader.file_names();
        Ok(ToolResult::text(json!({"count": names.len(), "names": names, "source": "rustre_dotnet_metadata::MetadataReader::file_names"}).to_string()))
    }
}

pub struct DotnetMetadataHasEntryPointTool;
impl DotnetMetadataHasEntryPointTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_has_entry_point".to_string(),
            description: "Return true if the image declares an entry point.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataHasEntryPointTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        Ok(ToolResult::text(json!({"has_entry_point": reader.has_entry_point(), "source": "rustre_dotnet_metadata::MetadataReader::has_entry_point"}).to_string()))
    }
}

pub struct DotnetMetadataFindMethodsByNameTool;
impl DotnetMetadataFindMethodsByNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_find_methods_by_name".to_string(),
            description: "Find MethodDef rows matching a name.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"},"name":{"type":"string"}},"required":["data_hex","name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataFindMethodsByNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let ms = reader.find_methods_by_name(name);
        let out: Vec<Value> = ms.iter().map(|m| json!({"name": m.name, "rva": m.rva, "flags": m.flags})).collect();
        Ok(ToolResult::text(json!({"count": out.len(), "matches": out, "source": "rustre_dotnet_metadata::MetadataReader::find_methods_by_name"}).to_string()))
    }
}

pub struct DotnetMetadataMethodIndexTool;
impl DotnetMetadataMethodIndexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_method_index".to_string(),
            description: "1-based index of first MethodDef with the given name.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"},"name":{"type":"string"}},"required":["data_hex","name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataMethodIndexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let idx = reader.method_index(name);
        Ok(ToolResult::text(json!({"name": name, "index": idx, "found": idx.is_some(), "source": "rustre_dotnet_metadata::MetadataReader::method_index"}).to_string()))
    }
}

pub struct DotnetMetadataMethodsForTypeTool;
impl DotnetMetadataMethodsForTypeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_methods_for_type".to_string(),
            description: "MethodDef names for a TypeDef index.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"},"type_index":{"type":"integer","minimum":1}},"required":["data_hex","type_index"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataMethodsForTypeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let idx = args.get("type_index").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'type_index'".into()))? as u32;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let ms = reader.methods_for_type(idx);
        let names: Vec<&str> = ms.iter().map(|m| m.name.as_str()).collect();
        Ok(ToolResult::text(json!({"type_index": idx, "count": names.len(), "names": names, "source": "rustre_dotnet_metadata::MetadataReader::methods_for_type"}).to_string()))
    }
}

pub struct DotnetMetadataFieldsForTypeTool;
impl DotnetMetadataFieldsForTypeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_fields_for_type".to_string(),
            description: "Field names for a TypeDef index.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"},"type_index":{"type":"integer","minimum":1}},"required":["data_hex","type_index"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataFieldsForTypeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let idx = args.get("type_index").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'type_index'".into()))? as u32;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let fs = reader.fields_for_type(idx);
        let names: Vec<&str> = fs.iter().map(|f| f.name.as_str()).collect();
        Ok(ToolResult::text(json!({"type_index": idx, "count": names.len(), "names": names, "source": "rustre_dotnet_metadata::MetadataReader::fields_for_type"}).to_string()))
    }
}

pub struct DotnetMetadataTypeIsAbstractTool;
impl DotnetMetadataTypeIsAbstractTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_type_is_abstract".to_string(),
            description: "Whether TypeDef index is abstract.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"},"type_index":{"type":"integer","minimum":1}},"required":["data_hex","type_index"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataTypeIsAbstractTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let idx = args.get("type_index").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'type_index'".into()))? as u32;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        Ok(ToolResult::text(json!({"type_index": idx, "is_abstract": reader.type_is_abstract(idx), "source": "rustre_dotnet_metadata::MetadataReader::type_is_abstract"}).to_string()))
    }
}

pub struct DotnetMetadataTypeIsSealedTool;
impl DotnetMetadataTypeIsSealedTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_type_is_sealed".to_string(),
            description: "Whether TypeDef index is sealed.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"},"type_index":{"type":"integer","minimum":1}},"required":["data_hex","type_index"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataTypeIsSealedTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let idx = args.get("type_index").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'type_index'".into()))? as u32;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        Ok(ToolResult::text(json!({"type_index": idx, "is_sealed": reader.type_is_sealed(idx), "source": "rustre_dotnet_metadata::MetadataReader::type_is_sealed"}).to_string()))
    }
}

pub struct DotnetMetadataAllTypeNamesBasicTool;
impl DotnetMetadataAllTypeNamesBasicTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_all_type_names_basic".to_string(),
            description: "List all TypeDef names from a .NET metadata image (hex) via rustre_dotnet_metadata::MetadataReader::all_type_names.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_hex":{"type":"string"}},"required":["image_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataAllTypeNamesBasicTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("image_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'image_hex'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let names = reader.all_type_names();
        Ok(ToolResult::text(json!({"count": names.len(), "names": names, "source":"rustre_dotnet_metadata::MetadataReader::all_type_names"}).to_string()))
    }
}

pub struct DotnetMetadataAllFieldNamesTool;
impl DotnetMetadataAllFieldNamesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_all_field_names".to_string(),
            description: "List all field names from a .NET metadata image (hex) via rustre_dotnet_metadata::MetadataReader::all_field_names.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_hex":{"type":"string"}},"required":["image_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataAllFieldNamesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("image_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'image_hex'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let names = reader.all_field_names();
        Ok(ToolResult::text(json!({"count": names.len(), "names": names, "source":"rustre_dotnet_metadata::MetadataReader::all_field_names"}).to_string()))
    }
}

pub struct DotnetMetadataAssemblyRefNamesTool;
impl DotnetMetadataAssemblyRefNamesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_assembly_ref_names".to_string(),
            description: "List AssemblyRef names from a .NET metadata image (hex) via rustre_dotnet_metadata::MetadataReader::assembly_ref_names.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_hex":{"type":"string"}},"required":["image_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataAssemblyRefNamesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("image_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'image_hex'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let names: Vec<String> = reader.assembly_ref_names().into_iter().map(String::from).collect();
        Ok(ToolResult::text(json!({"count": names.len(), "names": names, "source":"rustre_dotnet_metadata::MetadataReader::assembly_ref_names"}).to_string()))
    }
}

pub struct DotnetMetadataFindTypeDefRowTool;
impl DotnetMetadataFindTypeDefRowTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_find_type_def_row".to_string(),
            description: "Find a TypeDef row by name via rustre_dotnet_metadata::MetadataReader::find_type_def.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_hex":{"type":"string"},"name":{"type":"string"}},"required":["image_hex","name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataFindTypeDefRowTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("image_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'image_hex'".into()))?;
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let row = reader.find_type_def(name).map_err(|e| McpError::InternalError(format!("find_type_def: {e}")))?;
        Ok(ToolResult::text(json!({
            "flags": row.flags,
            "type_name": row.type_name,
            "type_namespace": row.type_namespace,
            "extends": row.extends,
            "field_list": row.field_list,
            "method_list": row.method_list,
            "source":"rustre_dotnet_metadata::MetadataReader::find_type_def"
        }).to_string()))
    }
}

pub struct DotnetMetadataGetTypeViewTool;
impl DotnetMetadataGetTypeViewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_get_type_view".to_string(),
            description: "Resolve a TypeDef token into a rich view via rustre_dotnet_metadata::MetadataReader::get_type.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_hex":{"type":"string"},"token":{"type":"integer","minimum":0}},"required":["image_hex","token"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataGetTypeViewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("image_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'image_hex'".into()))?;
        let token = args.get("token").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'token'".into()))? as u32;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let v = reader.get_type(token).map_err(|e| McpError::InternalError(format!("get_type: {e}")))?;
        let fields: Vec<u32> = v.fields.iter().map(|f| f.0).collect();
        let methods: Vec<u32> = v.methods.iter().map(|m| m.0).collect();
        Ok(ToolResult::text(json!({
            "access_flags": v.access_flags,
            "name": v.name,
            "namespace": v.namespace,
            "extends": v.extends.0,
            "fields": fields,
            "methods": methods,
            "source":"rustre_dotnet_metadata::MetadataReader::get_type"
        }).to_string()))
    }
}

pub struct DotnetMetadataGetMethodViewTool;
impl DotnetMetadataGetMethodViewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_get_method_view".to_string(),
            description: "Resolve a MethodDef token into a rich view via rustre_dotnet_metadata::MetadataReader::get_method.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_hex":{"type":"string"},"token":{"type":"integer","minimum":0}},"required":["image_hex","token"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataGetMethodViewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("image_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'image_hex'".into()))?;
        let token = args.get("token").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'token'".into()))? as u32;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let v = reader.get_method(token).map_err(|e| McpError::InternalError(format!("get_method: {e}")))?;
        let params: Vec<u32> = v.params.iter().map(|p| p.0).collect();
        Ok(ToolResult::text(json!({
            "rva": v.rva,
            "impl_flags": v.impl_flags,
            "flags": v.flags,
            "name": v.name,
            "signature_len": v.signature.len(),
            "params": params,
            "source":"rustre_dotnet_metadata::MetadataReader::get_method"
        }).to_string()))
    }
}

pub struct DotnetMetadataResolveTokenTool;
impl DotnetMetadataResolveTokenTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_resolve_token".to_string(),
            description: "Resolve any metadata token via rustre_dotnet_metadata::MetadataReader::resolve_token.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_hex":{"type":"string"},"token":{"type":"integer","minimum":0}},"required":["image_hex","token"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataResolveTokenTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("image_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'image_hex'".into()))?;
        let token = args.get("token").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'token'".into()))? as u32;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let res = reader.resolve_token(token).map_err(|e| McpError::InternalError(format!("resolve_token: {e}")))?;
        use rustre_dotnet_metadata::TokenResolution as TR;
        let kind = match &res {
            TR::TypeDef(_) => "TypeDef",
            TR::TypeRef(_) => "TypeRef",
            TR::MethodDef(_) => "MethodDef",
            TR::Field(_) => "Field",
            TR::MemberRef(_) => "MemberRef",
            TR::Assembly(_) => "Assembly",
            TR::AssemblyRef(_) => "AssemblyRef",
            TR::String(_) => "String",
            TR::Unknown(_) => "Unknown",
        };
        Ok(ToolResult::text(json!({
            "token": token,
            "kind": kind,
            "debug": format!("{:?}", res),
            "source":"rustre_dotnet_metadata::MetadataReader::resolve_token"
        }).to_string()))
    }
}

pub struct DotnetMetadataParseCaTypedTool;
impl DotnetMetadataParseCaTypedTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_parse_ca_typed".to_string(),
            description: "Parse a .NET CustomAttribute blob (hex) with explicit fixed-arg element types via rustre_dotnet_metadata::parse_custom_attribute_blob_typed.".to_string(),
            input_schema: json!({"type":"object","properties":{"blob_hex":{"type":"string"},"fixed_arg_types":{"type":"array","items":{"type":"integer","minimum":0,"maximum":255}}},"required":["blob_hex","fixed_arg_types"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataParseCaTypedTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("blob_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'blob_hex'".into()))?;
        let types_arr = args.get("fixed_arg_types").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'fixed_arg_types'".into()))?;
        let mut types: Vec<u8> = Vec::with_capacity(types_arr.len());
        for t in types_arr {
            let n = t.as_u64().ok_or_else(|| McpError::InvalidParams("fixed_arg_types entries must be u8".into()))?;
            types.push(u8::try_from(n).map_err(|_| McpError::InvalidParams("fixed_arg_types entry out of range".into()))?);
        }
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let decoded = rustre_dotnet_metadata::parse_custom_attribute_blob_typed(&bytes, &types).map_err(|e| McpError::InternalError(format!("parse_custom_attribute_blob_typed: {e}")))?;
        Ok(ToolResult::text(json!({
            "fixed_arg_count": decoded.fixed_args.len(),
            "named_arg_count": decoded.named_args.len(),
            "debug": format!("{:?}", decoded),
            "source":"rustre_dotnet_metadata::parse_custom_attribute_blob_typed"
        }).to_string()))
    }
}

pub struct DotnetMetadataTypeDefByIndexTool;
impl DotnetMetadataTypeDefByIndexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_type_def_by_index".to_string(),
            description: "Fetch a TypeDef row by 1-based index via rustre_dotnet_metadata::MetadataTables::type_def_by_index.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_hex":{"type":"string"},"index":{"type":"integer","minimum":1}},"required":["image_hex","index"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataTypeDefByIndexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("image_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'image_hex'".into()))?;
        let idx = args.get("index").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'index'".into()))? as u32;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let row = reader.tables.type_def_by_index(idx).map_err(|e| McpError::InternalError(format!("type_def_by_index: {e}")))?;
        Ok(ToolResult::text(json!({
            "flags": row.flags,
            "type_name": row.type_name,
            "type_namespace": row.type_namespace,
            "extends": row.extends,
            "field_list": row.field_list,
            "method_list": row.method_list,
            "source":"rustre_dotnet_metadata::MetadataTables::type_def_by_index"
        }).to_string()))
    }
}

pub struct DotnetMetadataMethodDefByIndexTool;
impl DotnetMetadataMethodDefByIndexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_metadata_method_def_by_index".to_string(),
            description: "Fetch a MethodDef row by 1-based index via rustre_dotnet_metadata::MetadataTables::method_def_by_index.".to_string(),
            input_schema: json!({"type":"object","properties":{"image_hex":{"type":"string"},"index":{"type":"integer","minimum":1}},"required":["image_hex","index"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetMetadataMethodDefByIndexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("image_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'image_hex'".into()))?;
        let idx = args.get("index").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'index'".into()))? as u32;
        let bytes = libfuzzer_hex_str_to_bytes(hex)?;
        let reader = rustre_dotnet_metadata::parse_metadata_direct(&bytes).map_err(|e| McpError::InternalError(format!("parse_metadata_direct: {e}")))?;
        let row = reader.tables.method_def_by_index(idx).map_err(|e| McpError::InternalError(format!("method_def_by_index: {e}")))?;
        Ok(ToolResult::text(json!({
            "rva": row.rva,
            "impl_flags": row.impl_flags,
            "flags": row.flags,
            "name": row.name,
            "signature_len": row.signature.len(),
            "param_list": row.param_list,
            "source":"rustre_dotnet_metadata::MetadataTables::method_def_by_index"
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DotnetMetadataParseFieldSigBlobTool::definition(), Box::new(DotnetMetadataParseFieldSigBlobTool)),
        (DotnetMetadataParseLocalVarSigTool::definition(), Box::new(DotnetMetadataParseLocalVarSigTool)),
        (DotnetMetadataParseMethodSigBlobTool::definition(), Box::new(DotnetMetadataParseMethodSigBlobTool)),
        (DotnetMetadataPrettyPrintTypeSigTool::definition(), Box::new(DotnetMetadataPrettyPrintTypeSigTool)),
        (DotnetMetadataParseArrayShapeTool::definition(), Box::new(DotnetMetadataParseArrayShapeTool)),
        (DotnetMetadataParseCustomAttributeBlobTool::definition(), Box::new(DotnetMetadataParseCustomAttributeBlobTool)),
        (DotnetMetadataParseDirectSummaryTool::definition(), Box::new(DotnetMetadataParseDirectSummaryTool)),
        (DotnetMetadataTypeFullNamesTool::definition(), Box::new(DotnetMetadataTypeFullNamesTool)),
        (DotnetMetadataAllMethodNamesTool::definition(), Box::new(DotnetMetadataAllMethodNamesTool)),
        (DotnetMetadataFindTypeTool::definition(), Box::new(DotnetMetadataFindTypeTool)),
        (DotnetMetadataTableSummaryTool::definition(), Box::new(DotnetMetadataTableSummaryTool)),
        (DotnetMetadataValidateTool::definition(), Box::new(DotnetMetadataValidateTool)),
        (DotnetMetadataParseMethodBodyTool::definition(), Box::new(DotnetMetadataParseMethodBodyTool)),
        (DotnetMetadataAssemblyManifestTool::definition(), Box::new(DotnetMetadataAssemblyManifestTool)),
        (DotnetMetadataAllModuleNamesTool::definition(), Box::new(DotnetMetadataAllModuleNamesTool)),
        (DotnetMetadataExportedTypeNamesTool::definition(), Box::new(DotnetMetadataExportedTypeNamesTool)),
        (DotnetMetadataResourceNamesTool::definition(), Box::new(DotnetMetadataResourceNamesTool)),
        (DotnetMetadataFileNamesTool::definition(), Box::new(DotnetMetadataFileNamesTool)),
        (DotnetMetadataHasEntryPointTool::definition(), Box::new(DotnetMetadataHasEntryPointTool)),
        (DotnetMetadataFindMethodsByNameTool::definition(), Box::new(DotnetMetadataFindMethodsByNameTool)),
        (DotnetMetadataMethodIndexTool::definition(), Box::new(DotnetMetadataMethodIndexTool)),
        (DotnetMetadataMethodsForTypeTool::definition(), Box::new(DotnetMetadataMethodsForTypeTool)),
        (DotnetMetadataFieldsForTypeTool::definition(), Box::new(DotnetMetadataFieldsForTypeTool)),
        (DotnetMetadataTypeIsAbstractTool::definition(), Box::new(DotnetMetadataTypeIsAbstractTool)),
        (DotnetMetadataTypeIsSealedTool::definition(), Box::new(DotnetMetadataTypeIsSealedTool)),
        (DotnetMetadataAllTypeNamesBasicTool::definition(), Box::new(DotnetMetadataAllTypeNamesBasicTool)),
        (DotnetMetadataAllFieldNamesTool::definition(), Box::new(DotnetMetadataAllFieldNamesTool)),
        (DotnetMetadataAssemblyRefNamesTool::definition(), Box::new(DotnetMetadataAssemblyRefNamesTool)),
        (DotnetMetadataFindTypeDefRowTool::definition(), Box::new(DotnetMetadataFindTypeDefRowTool)),
        (DotnetMetadataGetTypeViewTool::definition(), Box::new(DotnetMetadataGetTypeViewTool)),
        (DotnetMetadataGetMethodViewTool::definition(), Box::new(DotnetMetadataGetMethodViewTool)),
        (DotnetMetadataResolveTokenTool::definition(), Box::new(DotnetMetadataResolveTokenTool)),
        (DotnetMetadataParseCaTypedTool::definition(), Box::new(DotnetMetadataParseCaTypedTool)),
        (DotnetMetadataTypeDefByIndexTool::definition(), Box::new(DotnetMetadataTypeDefByIndexTool)),
        (DotnetMetadataMethodDefByIndexTool::definition(), Box::new(DotnetMetadataMethodDefByIndexTool)),
    ]
}
