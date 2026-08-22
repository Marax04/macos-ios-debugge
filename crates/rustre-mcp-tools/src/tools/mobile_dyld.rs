//! MCP wrappers for the rustre-mobile_dyld crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct MobileDyldHeaderParseTool;

pub struct MobileDyldMockImageCountTool;

pub struct MobileDyldImageFilenameTool;
impl MobileDyldImageFilenameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "mobile_dyld_image_filename".to_string(),
            description: "Return the filename of a dyld cache image path via rustre_mobile_dyld::DyldImage::filename.".to_string(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for MobileDyldImageFilenameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args.get("path").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let img = rustre_mobile_dyld::DyldImage { address:0, mod_time:0, inode:0, path_offset:0, path: path.to_string() };
        Ok(ToolResult::text(json!({"filename": img.filename().to_string(), "path": path, "source":"rustre_mobile_dyld::DyldImage::filename"}).to_string()))
    }
}

pub struct MobileDyldHeaderIsArm64Tool;
impl MobileDyldHeaderIsArm64Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "mobile_dyld_header_is_arm64".to_string(),
            description: "Return true if magic indicates arm64/arm64e via rustre_mobile_dyld::DyldHeader::is_arm64.".to_string(),
            input_schema: json!({"type":"object","properties":{"magic":{"type":"string"}},"required":["magic"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for MobileDyldHeaderIsArm64Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let magic = args.get("magic").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'magic'".into()))?;
        let hdr = rustre_mobile_dyld::DyldHeader {
            magic: magic.to_string(),
            mapping_offset:0, mapping_count:0, images_offset:0, images_count:0,
            dyld_base_address:0, code_sig_offset:0, code_sig_size:0,
            slide_info_offset:0, slide_info_size:0, uuid:[0u8;16],
            platform:0, format_version:0,
            images_text_offset:0, images_text_count:0,
            subcache_array_offset:0, subcache_array_count:0,
        };
        Ok(ToolResult::text(json!({"is_arm64": hdr.is_arm64(), "magic": magic, "source":"rustre_mobile_dyld::DyldHeader::is_arm64"}).to_string()))
    }
}

pub struct MobileDyldParseDyldMagicTool;
impl MobileDyldParseDyldMagicTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_dyld_parse_dyld_magic".to_string(), description: "Parse dyld cache header magic via rustre_mobile_dyld::parse_dyld_magic.".to_string(), input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileDyldParseDyldMagicTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?; let bytes = crate::hex_decode(hex)?; let magic = rustre_mobile_dyld::parse_dyld_magic(&bytes).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?; Ok(ToolResult::text(json!({"magic":magic,"source":"rustre_mobile_dyld::parse_dyld_magic"}).to_string())) } }

pub struct MobileDyldIsSystemFrameworkPathTool;
impl MobileDyldIsSystemFrameworkPathTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_dyld_is_system_framework_path".to_string(), description: "Check path is a system framework via rustre_mobile_dyld::is_system_framework_path.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileDyldIsSystemFrameworkPathTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?; Ok(ToolResult::text(json!({"is_system_framework": rustre_mobile_dyld::is_system_framework_path(p), "source":"rustre_mobile_dyld::is_system_framework_path"}).to_string())) } }

pub struct MobileDyldFormatUuidTool;
impl MobileDyldFormatUuidTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_dyld_format_uuid".to_string(), description: "Format 16-byte UUID via rustre_mobile_dyld::format_uuid.".to_string(), input_schema: json!({"type":"object","properties":{"uuid":{"type":"array","items":{"type":"integer"}}},"required":["uuid"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileDyldFormatUuidTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("uuid").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'uuid'".into()))?; if arr.len() != 16 { return Err(McpError::InvalidParams("uuid must have 16 bytes".into())); } let mut u = [0u8;16]; for (i,v) in arr.iter().enumerate() { u[i] = v.as_u64().unwrap_or(0) as u8; } Ok(ToolResult::text(json!({"uuid": rustre_mobile_dyld::format_uuid(&u), "source":"rustre_mobile_dyld::format_uuid"}).to_string())) } }

pub struct MobileDyldImageIsSystemFrameworkTool;
impl MobileDyldImageIsSystemFrameworkTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_dyld_image_is_system_framework".to_string(), description: "DyldImage::is_system_framework via rustre_mobile_dyld.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileDyldImageIsSystemFrameworkTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?; let img = rustre_mobile_dyld::DyldImage { address:0, mod_time:0, inode:0, path_offset:0, path: p.to_string() }; Ok(ToolResult::text(json!({"is_system_framework": img.is_system_framework(),"path":p,"source":"rustre_mobile_dyld::DyldImage::is_system_framework"}).to_string())) } }

pub struct MobileDyldImageIsSwiftOverlayTool;
impl MobileDyldImageIsSwiftOverlayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_dyld_image_is_swift_overlay".to_string(), description: "DyldImage::is_swift_overlay via rustre_mobile_dyld.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileDyldImageIsSwiftOverlayTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?; let img = rustre_mobile_dyld::DyldImage { address:0, mod_time:0, inode:0, path_offset:0, path: p.to_string() }; Ok(ToolResult::text(json!({"is_swift_overlay": img.is_swift_overlay(),"path":p,"source":"rustre_mobile_dyld::DyldImage::is_swift_overlay"}).to_string())) } }

pub struct MobileDyldSymbolIsWeakTool;
impl MobileDyldSymbolIsWeakTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_dyld_symbol_is_weak".to_string(), description: "DyldSymbol::is_weak via rustre_mobile_dyld.".to_string(), input_schema: json!({"type":"object","properties":{"flags":{"type":"integer"}},"required":["flags"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileDyldSymbolIsWeakTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let flags = args.get("flags").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'flags'".into()))? as u32; let s = rustre_mobile_dyld::DyldSymbol { name: String::new(), address: 0, image_path: String::new(), flags }; Ok(ToolResult::text(json!({"is_weak": s.is_weak(),"flags":flags,"source":"rustre_mobile_dyld::DyldSymbol::is_weak"}).to_string())) } }

pub struct MobileDyldSymbolIsObjcTool;
impl MobileDyldSymbolIsObjcTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_dyld_symbol_is_objc".to_string(), description: "DyldSymbol::is_objc via rustre_mobile_dyld.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileDyldSymbolIsObjcTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?; let s = rustre_mobile_dyld::DyldSymbol { name: n.to_string(), address: 0, image_path: String::new(), flags: 0 }; Ok(ToolResult::text(json!({"is_objc": s.is_objc(),"name":n,"source":"rustre_mobile_dyld::DyldSymbol::is_objc"}).to_string())) } }

pub struct MobileDyldSymbolIsSwiftTool;
impl MobileDyldSymbolIsSwiftTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_dyld_symbol_is_swift".to_string(), description: "DyldSymbol::is_swift via rustre_mobile_dyld.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileDyldSymbolIsSwiftTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?; let s = rustre_mobile_dyld::DyldSymbol { name: n.to_string(), address: 0, image_path: String::new(), flags: 0 }; Ok(ToolResult::text(json!({"is_swift": s.is_swift(),"name":n,"source":"rustre_mobile_dyld::DyldSymbol::is_swift"}).to_string())) } }

pub struct MobileDyldHeaderPlatformNameTool;
impl MobileDyldHeaderPlatformNameTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_dyld_header_platform_name".to_string(), description: "DyldHeader::platform_name via rustre_mobile_dyld.".to_string(), input_schema: json!({"type":"object","properties":{"platform":{"type":"integer"}},"required":["platform"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileDyldHeaderPlatformNameTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = args.get("platform").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'platform'".into()))? as u32; let hdr = rustre_mobile_dyld::DyldHeader { magic: String::new(), mapping_offset:0, mapping_count:0, images_offset:0, images_count:0, dyld_base_address:0, code_sig_offset:0, code_sig_size:0, slide_info_offset:0, slide_info_size:0, uuid:[0u8;16], platform: p, format_version:0, images_text_offset:0, images_text_count:0, subcache_array_offset:0, subcache_array_count:0 }; Ok(ToolResult::text(json!({"platform_name": hdr.platform_name(),"platform":p,"source":"rustre_mobile_dyld::DyldHeader::platform_name"}).to_string())) } }

pub struct MobileDyldHeaderIsSimulatorTool;
impl MobileDyldHeaderIsSimulatorTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_dyld_header_is_simulator".to_string(), description: "DyldHeader::is_simulator via rustre_mobile_dyld.".to_string(), input_schema: json!({"type":"object","properties":{"platform":{"type":"integer"}},"required":["platform"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileDyldHeaderIsSimulatorTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = args.get("platform").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'platform'".into()))? as u32; let hdr = rustre_mobile_dyld::DyldHeader { magic: String::new(), mapping_offset:0, mapping_count:0, images_offset:0, images_count:0, dyld_base_address:0, code_sig_offset:0, code_sig_size:0, slide_info_offset:0, slide_info_size:0, uuid:[0u8;16], platform: p, format_version:0, images_text_offset:0, images_text_count:0, subcache_array_offset:0, subcache_array_count:0 }; Ok(ToolResult::text(json!({"is_simulator": hdr.is_simulator(),"platform":p,"source":"rustre_mobile_dyld::DyldHeader::is_simulator"}).to_string())) } }

pub struct MobileDyldHeaderUuidStringTool;
impl MobileDyldHeaderUuidStringTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_dyld_header_uuid_string".to_string(), description: "DyldHeader::uuid_string via rustre_mobile_dyld.".to_string(), input_schema: json!({"type":"object","properties":{"uuid":{"type":"array","items":{"type":"integer"}}},"required":["uuid"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileDyldHeaderUuidStringTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("uuid").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'uuid'".into()))?; if arr.len() != 16 { return Err(McpError::InvalidParams("uuid must have 16 bytes".into())); } let mut u = [0u8;16]; for (i,v) in arr.iter().enumerate() { u[i] = v.as_u64().unwrap_or(0) as u8; } let hdr = rustre_mobile_dyld::DyldHeader { magic: String::new(), mapping_offset:0, mapping_count:0, images_offset:0, images_count:0, dyld_base_address:0, code_sig_offset:0, code_sig_size:0, slide_info_offset:0, slide_info_size:0, uuid: u, platform:0, format_version:0, images_text_offset:0, images_text_count:0, subcache_array_offset:0, subcache_array_count:0 }; Ok(ToolResult::text(json!({"uuid_string": hdr.uuid_string(),"source":"rustre_mobile_dyld::DyldHeader::uuid_string"}).to_string())) } }

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (MobileDyldHeaderParseTool::definition(), Box::new(MobileDyldHeaderParseTool)),
        (MobileDyldMockImageCountTool::definition(), Box::new(MobileDyldMockImageCountTool)),
        (MobileDyldImageFilenameTool::definition(), Box::new(MobileDyldImageFilenameTool)),
        (MobileDyldHeaderIsArm64Tool::definition(), Box::new(MobileDyldHeaderIsArm64Tool)),
        (MobileDyldParseDyldMagicTool::definition(), Box::new(MobileDyldParseDyldMagicTool)),
        (MobileDyldIsSystemFrameworkPathTool::definition(), Box::new(MobileDyldIsSystemFrameworkPathTool)),
        (MobileDyldFormatUuidTool::definition(), Box::new(MobileDyldFormatUuidTool)),
        (MobileDyldImageIsSystemFrameworkTool::definition(), Box::new(MobileDyldImageIsSystemFrameworkTool)),
        (MobileDyldImageIsSwiftOverlayTool::definition(), Box::new(MobileDyldImageIsSwiftOverlayTool)),
        (MobileDyldSymbolIsWeakTool::definition(), Box::new(MobileDyldSymbolIsWeakTool)),
        (MobileDyldSymbolIsObjcTool::definition(), Box::new(MobileDyldSymbolIsObjcTool)),
        (MobileDyldSymbolIsSwiftTool::definition(), Box::new(MobileDyldSymbolIsSwiftTool)),
        (MobileDyldHeaderPlatformNameTool::definition(), Box::new(MobileDyldHeaderPlatformNameTool)),
        (MobileDyldHeaderIsSimulatorTool::definition(), Box::new(MobileDyldHeaderIsSimulatorTool)),
        (MobileDyldHeaderUuidStringTool::definition(), Box::new(MobileDyldHeaderUuidStringTool)),
    ]
}
