//! MCP wrappers for the rustre-dm crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct DmSwiftDemangleTool;
impl DmSwiftDemangleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_swift_heuristic_wire".to_string(), description: "rustre_demangle::swift_demangler::swift_demangle".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmSwiftDemangleTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let r = rustre_demangle::swift_demangler::swift_demangle(&s); Ok(ToolResult::text(json!({"demangled":r,"source":"rustre_demangle::swift_demangler::swift_demangle"}).to_string())) } }

pub struct DmMsvcFullDemangleTool;
impl DmMsvcFullDemangleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_msvc_full_wire".to_string(), description: "rustre_demangle::msvc_full::msvc_demangle".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmMsvcFullDemangleTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let r = rustre_demangle::msvc_full::msvc_demangle(&s); Ok(ToolResult::text(json!({"demangled":r,"source":"rustre_demangle::msvc_full::msvc_demangle"}).to_string())) } }

pub struct DmDDemangleTool;
impl DmDDemangleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_d_lang_wire".to_string(), description: "rustre_demangle::d_demangler::d_demangle".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmDDemangleTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let r = rustre_demangle::d_demangler::d_demangle(&s); Ok(ToolResult::text(json!({"demangled":r,"source":"rustre_demangle::d_demangler::d_demangle"}).to_string())) } }

pub struct DmStripRustHashTool;
impl DmStripRustHashTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_strip_rust_hash_wire".to_string(), description: "rustre_demangle::rust_demangler::strip_rust_hash".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmStripRustHashTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let r = rustre_demangle::rust_demangler::strip_rust_hash(&s); Ok(ToolResult::text(json!({"stripped":r,"source":"rustre_demangle::rust_demangler::strip_rust_hash"}).to_string())) } }

pub struct DmItaniumIsStdTool;
impl DmItaniumIsStdTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_itanium_is_std_symbol_wire".to_string(), description: "rustre_demangle::itanium_full::is_std_symbol".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmItaniumIsStdTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let r = rustre_demangle::itanium_full::is_std_symbol(&s); Ok(ToolResult::text(json!({"is_std":r,"source":"rustre_demangle::itanium_full::is_std_symbol"}).to_string())) } }

pub struct DmItaniumIsLambdaTool;
impl DmItaniumIsLambdaTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_itanium_is_lambda_wire".to_string(), description: "rustre_demangle::itanium_full::is_lambda".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmItaniumIsLambdaTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let r = rustre_demangle::itanium_full::is_lambda(&s); Ok(ToolResult::text(json!({"is_lambda":r,"source":"rustre_demangle::itanium_full::is_lambda"}).to_string())) } }

pub struct DmDispatcherAutoDemangleTool;
impl DmDispatcherAutoDemangleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_dispatcher_auto_wire".to_string(), description: "rustre_demangle::demangler_dispatcher::auto_demangle".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmDispatcherAutoDemangleTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let r = rustre_demangle::demangler_dispatcher::auto_demangle(&s); Ok(ToolResult::text(json!({"demangled":r,"source":"rustre_demangle::demangler_dispatcher::auto_demangle"}).to_string())) } }

pub struct DmRustV0Tool;
impl DmRustV0Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_rust_v0_wire".to_string(), description: "rustre_demangle::rust_demangler::demangle_rust_v0".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmRustV0Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); match rustre_demangle::rust_demangler::demangle_rust_v0(&s) { Ok(r) => Ok(ToolResult::text(json!({"ok":true,"demangled":r,"source":"rustre_demangle::rust_demangler::demangle_rust_v0"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string(),"source":"rustre_demangle::rust_demangler::demangle_rust_v0"}).to_string())) } } }

pub struct DmRustLegacyTool;
impl DmRustLegacyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_rust_legacy_wire".to_string(), description: "rustre_demangle::rust_demangler::demangle_rust_legacy".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmRustLegacyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); match rustre_demangle::rust_demangler::demangle_rust_legacy(&s) { Ok(r) => Ok(ToolResult::text(json!({"ok":true,"demangled":r,"source":"rustre_demangle::rust_demangler::demangle_rust_legacy"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string(),"source":"rustre_demangle::rust_demangler::demangle_rust_legacy"}).to_string())) } } }

pub struct DmRustAutoTool;
impl DmRustAutoTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_rust_auto_wire".to_string(), description: "rustre_demangle::rust_demangler::demangle_rust".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmRustAutoTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); match rustre_demangle::rust_demangler::demangle_rust(&s) { Ok(r) => Ok(ToolResult::text(json!({"ok":true,"demangled":r,"source":"rustre_demangle::rust_demangler::demangle_rust"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string(),"source":"rustre_demangle::rust_demangler::demangle_rust"}).to_string())) } } }

pub struct DmCppItaniumTool;
impl DmCppItaniumTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_cpp_itanium_wire".to_string(), description: "rustre_demangle::cpp_demangler::demangle_itanium".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmCppItaniumTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); match rustre_demangle::cpp_demangler::demangle_itanium(&s) { Ok(r) => Ok(ToolResult::text(json!({"ok":true,"demangled":r,"source":"rustre_demangle::cpp_demangler::demangle_itanium"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string(),"source":"rustre_demangle::cpp_demangler::demangle_itanium"}).to_string())) } } }

pub struct DmCppMsvcTool;
impl DmCppMsvcTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_cpp_msvc_wire".to_string(), description: "rustre_demangle::cpp_demangler::demangle_msvc".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmCppMsvcTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); match rustre_demangle::cpp_demangler::demangle_msvc(&s) { Ok(r) => Ok(ToolResult::text(json!({"ok":true,"demangled":r,"source":"rustre_demangle::cpp_demangler::demangle_msvc"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string(),"source":"rustre_demangle::cpp_demangler::demangle_msvc"}).to_string())) } } }

pub struct DmCppAutoTool;
impl DmCppAutoTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_cpp_auto_wire".to_string(), description: "rustre_demangle::cpp_demangler::demangle_cpp".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmCppAutoTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); match rustre_demangle::cpp_demangler::demangle_cpp(&s) { Ok(r) => Ok(ToolResult::text(json!({"ok":true,"demangled":r,"source":"rustre_demangle::cpp_demangler::demangle_cpp"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string(),"source":"rustre_demangle::cpp_demangler::demangle_cpp"}).to_string())) } } }

pub struct DmItaniumExtractNsTool;
impl DmItaniumExtractNsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_itanium_extract_namespace_wire".to_string(), description: "rustre_demangle::itanium_full::extract_namespace".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmItaniumExtractNsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let r = rustre_demangle::itanium_full::extract_namespace(&s).map(str::to_string); Ok(ToolResult::text(json!({"namespace":r,"source":"rustre_demangle::itanium_full::extract_namespace"}).to_string())) } }

pub struct DmItaniumLookupStdSubTool;
impl DmItaniumLookupStdSubTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_itanium_lookup_std_sub_wire".to_string(), description: "rustre_demangle::itanium_full::lookup_standard_sub".to_string(), input_schema: json!({"type":"object","properties":{"abbrev":{"type":"string"}},"required":["abbrev"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmItaniumLookupStdSubTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("abbrev").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'abbrev'".into()))?.to_string(); let r = rustre_demangle::itanium_full::lookup_standard_sub(&s); Ok(ToolResult::text(json!({"expanded":r,"source":"rustre_demangle::itanium_full::lookup_standard_sub"}).to_string())) } }

pub struct DmGoRuntimeSymbolTool;
impl DmGoRuntimeSymbolTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_go_runtime_symbol_wire".to_string(), description: "rustre_demangle::go_demangler::describe_runtime_symbol".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmGoRuntimeSymbolTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let r = rustre_demangle::go_demangler::describe_runtime_symbol(&s); Ok(ToolResult::text(json!({"description":r,"source":"rustre_demangle::go_demangler::describe_runtime_symbol"}).to_string())) } }

pub struct DmItaniumNativeDetectKindTool;
impl DmItaniumNativeDetectKindTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_itanium_native_detect_kind_wire".to_string(), description: "rustre_demangle::ItaniumNativeDemangler::detect_kind".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmItaniumNativeDetectKindTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let k = rustre_demangle::ItaniumNativeDemangler::detect_kind(&s); Ok(ToolResult::text(json!({"kind":format!("{:?}",k),"source":"rustre_demangle::ItaniumNativeDemangler::detect_kind"}).to_string())) } }

pub struct DmDDemanglerDetectTool;
impl DmDDemanglerDetectTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_d_detect_wire".to_string(), description: "rustre_demangle::DDemangler::detect".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmDDemanglerDetectTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let v = rustre_demangle::DDemangler::detect(&s); Ok(ToolResult::text(json!({"detected":v,"source":"rustre_demangle::DDemangler::detect"}).to_string())) } }

pub struct DmDDemanglerDemangleTool;
impl DmDDemanglerDemangleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_d_struct_demangle_wire".to_string(), description: "rustre_demangle::DDemangler::demangle".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmDDemanglerDemangleTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let r = rustre_demangle::DDemangler::demangle(&s); Ok(ToolResult::text(json!({"demangled":r,"source":"rustre_demangle::DDemangler::demangle"}).to_string())) } }

pub struct DmRustV0DetectTool;
impl DmRustV0DetectTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_rust_v0_detect_wire".to_string(), description: "rustre_demangle::RustV0Demangler::detect".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmRustV0DetectTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let v = rustre_demangle::RustV0Demangler::detect(&s); Ok(ToolResult::text(json!({"detected":v,"source":"rustre_demangle::RustV0Demangler::detect"}).to_string())) } }

pub struct DmRustV0StructDemangleTool;
impl DmRustV0StructDemangleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_rust_v0_struct_demangle_wire".to_string(), description: "rustre_demangle::RustV0Demangler::demangle".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmRustV0StructDemangleTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let r = rustre_demangle::RustV0Demangler::demangle(&s); Ok(ToolResult::text(json!({"demangled":r,"source":"rustre_demangle::RustV0Demangler::demangle"}).to_string())) } }

pub struct DmDemangler2Tool;
impl DmDemangler2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_demangler2_auto_wire".to_string(), description: "rustre_demangle::Demangler2::demangle".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmDemangler2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let r = rustre_demangle::Demangler2::demangle(&s); Ok(ToolResult::text(json!({"mangled":r.mangled,"demangled":r.demangled,"language":format!("{:?}",r.language),"kind":format!("{:?}",r.kind),"source":"rustre_demangle::Demangler2::demangle"}).to_string())) } }

pub struct DmObjCDetectTool;
impl DmObjCDetectTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_objc_detect_wire".to_string(), description: "rustre_demangle::ObjCDemangler::detect".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmObjCDetectTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let v = rustre_demangle::ObjCDemangler::detect(&s); Ok(ToolResult::text(json!({"detected":v,"source":"rustre_demangle::ObjCDemangler::detect"}).to_string())) } }

pub struct DmObjCDemangleTool;
impl DmObjCDemangleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_objc_demangle_wire".to_string(), description: "rustre_demangle::ObjCDemangler::demangle".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmObjCDemangleTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let r = rustre_demangle::ObjCDemangler::demangle(&s); Ok(ToolResult::text(json!({"demangled":r,"source":"rustre_demangle::ObjCDemangler::demangle"}).to_string())) } }

pub struct DmSwiftExtendedParseTool;
impl DmSwiftExtendedParseTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_swift_extended_parse_wire".to_string(), description: "rustre_demangle::SwiftExtendedParser::parse".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmSwiftExtendedParseTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let r = rustre_demangle::SwiftExtendedParser::parse(&s); let out = r.map(|sym| json!({"module":sym.module,"path":sym.path,"is_function":sym.is_function})); Ok(ToolResult::text(json!({"parsed":out,"source":"rustre_demangle::SwiftExtendedParser::parse"}).to_string())) } }

pub struct DmSymbolClassifierTool;
impl DmSymbolClassifierTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_symbol_classifier_classify_wire".to_string(), description: "rustre_demangle::SymbolClassifier::classify".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmSymbolClassifierTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let l = rustre_demangle::SymbolClassifier::classify(&s); Ok(ToolResult::text(json!({"language":format!("{:?}",l),"source":"rustre_demangle::SymbolClassifier::classify"}).to_string())) } }

pub struct DmItaniumNativeDemangleTool;
impl DmItaniumNativeDemangleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "demangle_itanium_native_demangle_wire".to_string(), description: "rustre_demangle::ItaniumNativeDemangler::demangle".to_string(), input_schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DmItaniumNativeDemangleTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("symbol").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'symbol'".into()))?.to_string(); let r = rustre_demangle::ItaniumNativeDemangler::demangle(&s); Ok(ToolResult::text(json!({"demangled":r,"source":"rustre_demangle::ItaniumNativeDemangler::demangle"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DmSwiftDemangleTool::definition(), Box::new(DmSwiftDemangleTool)),
        (DmMsvcFullDemangleTool::definition(), Box::new(DmMsvcFullDemangleTool)),
        (DmDDemangleTool::definition(), Box::new(DmDDemangleTool)),
        (DmStripRustHashTool::definition(), Box::new(DmStripRustHashTool)),
        (DmItaniumIsStdTool::definition(), Box::new(DmItaniumIsStdTool)),
        (DmItaniumIsLambdaTool::definition(), Box::new(DmItaniumIsLambdaTool)),
        (DmDispatcherAutoDemangleTool::definition(), Box::new(DmDispatcherAutoDemangleTool)),
        (DmRustV0Tool::definition(), Box::new(DmRustV0Tool)),
        (DmRustLegacyTool::definition(), Box::new(DmRustLegacyTool)),
        (DmRustAutoTool::definition(), Box::new(DmRustAutoTool)),
        (DmCppItaniumTool::definition(), Box::new(DmCppItaniumTool)),
        (DmCppMsvcTool::definition(), Box::new(DmCppMsvcTool)),
        (DmCppAutoTool::definition(), Box::new(DmCppAutoTool)),
        (DmItaniumExtractNsTool::definition(), Box::new(DmItaniumExtractNsTool)),
        (DmItaniumLookupStdSubTool::definition(), Box::new(DmItaniumLookupStdSubTool)),
        (DmGoRuntimeSymbolTool::definition(), Box::new(DmGoRuntimeSymbolTool)),
        (DmItaniumNativeDetectKindTool::definition(), Box::new(DmItaniumNativeDetectKindTool)),
        (DmDDemanglerDetectTool::definition(), Box::new(DmDDemanglerDetectTool)),
        (DmDDemanglerDemangleTool::definition(), Box::new(DmDDemanglerDemangleTool)),
        (DmRustV0DetectTool::definition(), Box::new(DmRustV0DetectTool)),
        (DmRustV0StructDemangleTool::definition(), Box::new(DmRustV0StructDemangleTool)),
        (DmDemangler2Tool::definition(), Box::new(DmDemangler2Tool)),
        (DmObjCDetectTool::definition(), Box::new(DmObjCDetectTool)),
        (DmObjCDemangleTool::definition(), Box::new(DmObjCDemangleTool)),
        (DmSwiftExtendedParseTool::definition(), Box::new(DmSwiftExtendedParseTool)),
        (DmSymbolClassifierTool::definition(), Box::new(DmSymbolClassifierTool)),
        (DmItaniumNativeDemangleTool::definition(), Box::new(DmItaniumNativeDemangleTool)),
    ]
}
