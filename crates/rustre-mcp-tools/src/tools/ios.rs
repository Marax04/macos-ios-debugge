//! MCP wrappers for the rustre-ios crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{__ios_hex_decode};

pub struct IosScanObjcSelectorsPathTool;

pub struct IosScanObjcClassesPathTool;

pub struct IosSecCheckArcTool;
impl IosSecCheckArcTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ios_security_check_arc_usage_wire".to_string(), description: "rustre_mobile_ios::IosSecurityChecker::check_arc_usage on hex bytes".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IosSecCheckArcTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let h = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let b = __ios_hex_decode(h)?; let r = rustre_mobile_ios::IosSecurityChecker::check_arc_usage(&b); Ok(ToolResult::text(json!({"arc":r,"source":"rustre_mobile_ios::IosSecurityChecker::check_arc_usage"}).to_string())) } }

pub struct IosSecCheckPieTool;
impl IosSecCheckPieTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ios_security_check_pie_enabled_wire".to_string(), description: "rustre_mobile_ios::IosSecurityChecker::check_pie_enabled on hex bytes".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IosSecCheckPieTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let h = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let b = __ios_hex_decode(h)?; let r = rustre_mobile_ios::IosSecurityChecker::check_pie_enabled(&b); Ok(ToolResult::text(json!({"pie":r,"source":"rustre_mobile_ios::IosSecurityChecker::check_pie_enabled"}).to_string())) } }

pub struct IosSecCheckStackCanaryTool;
impl IosSecCheckStackCanaryTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ios_security_check_stack_canary_wire".to_string(), description: "rustre_mobile_ios::IosSecurityChecker::check_stack_canary on hex bytes".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IosSecCheckStackCanaryTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let h = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let b = __ios_hex_decode(h)?; let r = rustre_mobile_ios::IosSecurityChecker::check_stack_canary(&b); Ok(ToolResult::text(json!({"stack_canary":r,"source":"rustre_mobile_ios::IosSecurityChecker::check_stack_canary"}).to_string())) } }

pub struct IosSecCheckDebugSymsTool;
impl IosSecCheckDebugSymsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ios_security_check_debug_symbols_wire".to_string(), description: "rustre_mobile_ios::IosSecurityChecker::check_debug_symbols on hex bytes".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IosSecCheckDebugSymsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let h = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let b = __ios_hex_decode(h)?; let r = rustre_mobile_ios::IosSecurityChecker::check_debug_symbols(&b); Ok(ToolResult::text(json!({"has_debug_symbols":r,"source":"rustre_mobile_ios::IosSecurityChecker::check_debug_symbols"}).to_string())) } }

pub struct IosSecReportTool;
impl IosSecReportTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ios_security_report_wire".to_string(), description: "rustre_mobile_ios::IosSecurityChecker::report on hex bytes".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IosSecReportTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let h = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let b = __ios_hex_decode(h)?; let r = rustre_mobile_ios::IosSecurityChecker::report(&b); Ok(ToolResult::text(json!({"arc":r.arc,"pie":r.pie,"stack_canary":r.stack_canary,"has_debug_symbols":r.has_debug_symbols.is_present(),"source":"rustre_mobile_ios::IosSecurityChecker::report"}).to_string())) } }

pub struct IosSwiftIsMangledTool;
impl IosSwiftIsMangledTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ios_swift_is_mangled_wire".to_string(), description: "rustre_mobile_ios::SwiftDemangler::is_swift_mangled".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IosSwiftIsMangledTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?; let r = rustre_mobile_ios::SwiftDemangler::is_swift_mangled(n); Ok(ToolResult::text(json!({"is_swift_mangled":r,"source":"rustre_mobile_ios::SwiftDemangler::is_swift_mangled"}).to_string())) } }

pub struct IosSwiftDemangleTool;
impl IosSwiftDemangleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ios_swift_demangle_wire".to_string(), description: "rustre_mobile_ios::SwiftDemangler::demangle".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IosSwiftDemangleTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?; let r = rustre_mobile_ios::SwiftDemangler::demangle(n); Ok(ToolResult::text(json!({"demangled":r,"source":"rustre_mobile_ios::SwiftDemangler::demangle"}).to_string())) } }

pub struct IosDecodeTypeEncodingTool;
impl IosDecodeTypeEncodingTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ios_decode_type_encoding_wire".to_string(), description: "rustre_mobile_ios::decode_type_encoding".to_string(), input_schema: json!({"type":"object","properties":{"encoding":{"type":"string"}},"required":["encoding"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IosDecodeTypeEncodingTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let e = args.get("encoding").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'encoding'".into()))?; let r = rustre_mobile_ios::decode_type_encoding(e); Ok(ToolResult::text(json!({"types":r,"source":"rustre_mobile_ios::decode_type_encoding"}).to_string())) } }

pub struct IosIpaInfoFromMachoTool;
impl IosIpaInfoFromMachoTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ios_ipa_info_from_macho_wire".to_string(), description: "rustre_mobile_ios::IpaInfo::from_macho on hex bytes".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IosIpaInfoFromMachoTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let h = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let b = __ios_hex_decode(h)?; let r = rustre_mobile_ios::IpaInfo::from_macho(&b); Ok(ToolResult::text(json!({"bundle_id":r.bundle_id,"version":r.version,"min_os":r.min_os,"class_count":r.class_count,"method_count":r.method_count,"swift_class_count":r.swift_class_count,"has_bitcode":r.has_bitcode,"architectures":r.architectures,"source":"rustre_mobile_ios::IpaInfo::from_macho"}).to_string())) } }

pub struct IosParsePlistTool;
impl IosParsePlistTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ios_parse_plist_wire".to_string(), description: "rustre_mobile_ios::IosAppInfoExtractor::parse_plist on plist text".to_string(), input_schema: json!({"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IosParsePlistTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let t = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?; let r = rustre_mobile_ios::IosAppInfoExtractor::parse_plist(t.as_bytes()); Ok(ToolResult::text(json!({"info":r.as_ref().map(|i| json!({"bundle_id":i.bundle_id,"version":i.version,"min_ios":i.min_ios,"permissions":i.permissions})),"source":"rustre_mobile_ios::IosAppInfoExtractor::parse_plist"}).to_string())) } }

pub struct IosClassDumperClassesTool;
impl IosClassDumperClassesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ios_class_dumper_extract_objc_classes_wire".to_string(), description: "rustre_mobile_ios::IosClassDumper::extract_objc_classes on hex bytes".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IosClassDumperClassesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let h = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let b = __ios_hex_decode(h)?; let r = rustre_mobile_ios::IosClassDumper::extract_objc_classes(&b); Ok(ToolResult::text(json!({"classes":r,"source":"rustre_mobile_ios::IosClassDumper::extract_objc_classes"}).to_string())) } }

pub struct IosClassDumperSwiftTool;
impl IosClassDumperSwiftTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ios_class_dumper_extract_swift_types_wire".to_string(), description: "rustre_mobile_ios::IosClassDumper::extract_swift_types on hex bytes".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IosClassDumperSwiftTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let h = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let b = __ios_hex_decode(h)?; let r = rustre_mobile_ios::IosClassDumper::extract_swift_types(&b); Ok(ToolResult::text(json!({"swift_types":r,"source":"rustre_mobile_ios::IosClassDumper::extract_swift_types"}).to_string())) } }

pub struct IosIpaBundleMockTool;
impl IosIpaBundleMockTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ios_ipa_bundle_mock_wire".to_string(), description: "rustre_mobile_ios::IpaBundle::mock summary".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IosIpaBundleMockTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let b = rustre_mobile_ios::IpaBundle::mock(); Ok(ToolResult::text(json!({"bundle_id":b.info.bundle_id,"framework_count":b.framework_count(),"is_debuggable":b.is_debuggable(),"system_frameworks":b.system_frameworks().len(),"source":"rustre_mobile_ios::IpaBundle::mock"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (IosScanObjcSelectorsPathTool::definition(), Box::new(IosScanObjcSelectorsPathTool)),
        (IosScanObjcClassesPathTool::definition(), Box::new(IosScanObjcClassesPathTool)),
        (IosSecCheckArcTool::definition(), Box::new(IosSecCheckArcTool)),
        (IosSecCheckPieTool::definition(), Box::new(IosSecCheckPieTool)),
        (IosSecCheckStackCanaryTool::definition(), Box::new(IosSecCheckStackCanaryTool)),
        (IosSecCheckDebugSymsTool::definition(), Box::new(IosSecCheckDebugSymsTool)),
        (IosSecReportTool::definition(), Box::new(IosSecReportTool)),
        (IosSwiftIsMangledTool::definition(), Box::new(IosSwiftIsMangledTool)),
        (IosSwiftDemangleTool::definition(), Box::new(IosSwiftDemangleTool)),
        (IosDecodeTypeEncodingTool::definition(), Box::new(IosDecodeTypeEncodingTool)),
        (IosIpaInfoFromMachoTool::definition(), Box::new(IosIpaInfoFromMachoTool)),
        (IosParsePlistTool::definition(), Box::new(IosParsePlistTool)),
        (IosClassDumperClassesTool::definition(), Box::new(IosClassDumperClassesTool)),
        (IosClassDumperSwiftTool::definition(), Box::new(IosClassDumperSwiftTool)),
        (IosIpaBundleMockTool::definition(), Box::new(IosIpaBundleMockTool)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The third silent-drop shape must refuse bad hex like the other two.
    ///
    /// `__ios_hex_decode` skipped an invalid pair via `if let (Some, Some)`,
    /// which neither census regex could see — it was found only by re-reading a
    /// function already classified. These tools parse Mach-O and dyld cache
    /// structures, where a shifted offset does not shorten the answer, it names
    /// a different symbol.
    #[tokio::test]
    async fn ios_tools_refuse_bad_hex_rather_than_shifting_offsets() {
        let handlers = handlers();
        let mut checked = 0;
        for (def, h) in &handlers {
            let keys: Vec<&str> = ["hex", "data_hex", "bytes_hex"]
                .into_iter()
                .filter(|k| def.input_schema.to_string().contains(&format!("\"{k}\"")))
                .collect();
            if keys.is_empty() {
                continue;
            }
            let mut bad = serde_json::Map::new();
            for k in &keys {
                bad.insert((*k).to_string(), json!("deadbezz"));
            }
            assert!(
                h.call(Value::Object(bad)).await.is_err(),
                "{} accepted an invalid digit",
                def.name
            );
            checked += 1;
        }
        // Positive control on the probe itself: if no tool was exercised the
        // assertion above never ran, and a green test would mean nothing.
        assert!(checked > 0, "no ios tool declares a hex key — probe is blind");
    }
}
