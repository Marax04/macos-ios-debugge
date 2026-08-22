//! MCP wrappers for the rustre-mobile_jadx crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

// ─────────────────────────────────────────────────────────────────────────────
// Real APK/DEX input
//
// ⚠ Why this exists. All six tools below called
// `rustre_mobile_jadx::DecompiledProject::mock()`. That constructor used to
// fabricate a nine-class project, and an earlier pass made it return an EMPTY
// one — honest, but it left these tools answering questions about nothing:
// `success_rate` reported 1.0 ("100% succeeded") over zero classes, and
// `find_class` could only ever answer null. A confident answer over no data is
// the same defect as an invented one wearing different clothes.
//
// They now take the APK or .dex and decode it through
// `rustre_mobile_jadx::dex_project::project_from_path`, which walks the real
// DEX class_data_items.
// ─────────────────────────────────────────────────────────────────────────────

/// Schema for a tool that decodes one Android artefact.
fn jadx_schema(extra: &[(&str, Value)]) -> Value {
    let mut props = serde_json::Map::new();
    props.insert(
        "path".to_string(),
        json!({"type": "string", "description": "Path to the .apk or .dex to decode"}),
    );
    let mut required = vec![json!("path")];
    for (k, v) in extra {
        props.insert((*k).to_string(), v.clone());
        required.push(json!(*k));
    }
    json!({"type": "object", "properties": Value::Object(props), "required": required})
}

/// Decode the artefact named by `args["path"]`.
///
/// # Errors
/// `InvalidParams` when `path` is absent; `ToolError` when the file cannot be
/// read or decoded. Never substitutes an empty or invented project.
fn jadx_project_from_args(
    args: &Value,
) -> Result<rustre_mobile_jadx::DecompiledProject, McpError> {
    let path = args.get("path").and_then(Value::as_str).ok_or_else(|| {
        McpError::InvalidParams("'path' is required: the .apk or .dex to decode".to_string())
    })?;
    rustre_mobile_jadx::dex_project::project_from_path(path)
        .map_err(|e| McpError::ToolError(format!("cannot decode '{path}': {e}")))
}

pub struct MobileJadxFindTool;

pub struct MobileJadxDescriptorToTypeTool;

pub struct MobileJadxConfigNewTool;

pub struct MobileJadxJavaMethodIsConstructorTool;

pub struct MobileJadxDalvikOpcodeFromByteTool;
impl MobileJadxDalvikOpcodeFromByteTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_jadx_dalvik_opcode_from_byte".to_string(), description: "rustre_mobile_jadx::DalvikOpcode::from_byte".to_string(), input_schema: json!({"type":"object","properties":{"byte":{"type":"integer"}},"required":["byte"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileJadxDalvikOpcodeFromByteTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'byte'".into()))? as u8; let op = rustre_mobile_jadx::DalvikOpcode::from_byte(b); Ok(ToolResult::text(json!({"byte":b,"mnemonic":op.map(|o| o.mnemonic()),"source":"rustre_mobile_jadx::DalvikOpcode::from_byte"}).to_string())) } }

pub struct MobileJadxDalvikOpcodeMnemonicTool;
impl MobileJadxDalvikOpcodeMnemonicTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_jadx_dalvik_opcode_mnemonic".to_string(), description: "rustre_mobile_jadx::DalvikOpcode::mnemonic (via from_byte)".to_string(), input_schema: json!({"type":"object","properties":{"byte":{"type":"integer"}},"required":["byte"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileJadxDalvikOpcodeMnemonicTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'byte'".into()))? as u8; let m = rustre_mobile_jadx::DalvikOpcode::from_byte(b).map(|o| o.mnemonic().to_string()); Ok(ToolResult::text(json!({"byte":b,"mnemonic":m,"source":"rustre_mobile_jadx::DalvikOpcode::mnemonic"}).to_string())) } }

pub struct MobileJadxConfigWithThreadsTool;
impl MobileJadxConfigWithThreadsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_jadx_config_with_threads".to_string(), description: "rustre_mobile_jadx::JadxConfig::with_threads".to_string(), input_schema: json!({"type":"object","properties":{"threads":{"type":"integer"}},"required":["threads"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileJadxConfigWithThreadsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let t = args.get("threads").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'threads'".into()))? as u32; let cfg = rustre_mobile_jadx::JadxConfig::new("jadx","in","out").with_threads(t); Ok(ToolResult::text(json!({"threads":cfg.threads,"source":"rustre_mobile_jadx::JadxConfig::with_threads"}).to_string())) } }

pub struct MobileJadxConfigWithDeobfTool;
impl MobileJadxConfigWithDeobfTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_jadx_config_with_deobfuscate".to_string(), description: "rustre_mobile_jadx::JadxConfig::with_deobfuscate".to_string(), input_schema: jadx_schema(&[]), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileJadxConfigWithDeobfTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let cfg = rustre_mobile_jadx::JadxConfig::new("jadx","in","out").with_deobfuscate(); Ok(ToolResult::text(json!({"deobfuscate":cfg.deobfuscate,"source":"rustre_mobile_jadx::JadxConfig::with_deobfuscate"}).to_string())) } }

pub struct MobileJadxProjectMockTool;
impl MobileJadxProjectMockTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_jadx_project_mock".to_string(), description: "rustre_mobile_jadx::DecompiledProject::mock".to_string(), input_schema: jadx_schema(&[]), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileJadxProjectMockTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = jadx_project_from_args(&args)?; Ok(ToolResult::text(json!({"total":p.total,"failed":p.failed,"classes":p.classes.len(),"source":"rustre_mobile_jadx::DecompiledProject::mock"}).to_string())) } }

pub struct MobileJadxProjectSuccessRateTool;
impl MobileJadxProjectSuccessRateTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_jadx_project_success_rate".to_string(), description: "rustre_mobile_jadx::DecompiledProject::success_rate".to_string(), input_schema: jadx_schema(&[]), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileJadxProjectSuccessRateTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = jadx_project_from_args(&args)?; Ok(ToolResult::text(json!({"success_rate":p.success_rate(),"source":"rustre_mobile_jadx::DecompiledProject::success_rate"}).to_string())) } }

pub struct MobileJadxProjectFindClassTool;
impl MobileJadxProjectFindClassTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_jadx_project_find_class".to_string(), description: "rustre_mobile_jadx::DecompiledProject::find_class on mock project".to_string(), input_schema: jadx_schema(&[("name", json!({"type":"string"}))]), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileJadxProjectFindClassTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?; let p = jadx_project_from_args(&args)?; let found = p.find_class(n).map(|c| c.class_name.clone()); Ok(ToolResult::text(json!({"query":n,"found":found,"source":"rustre_mobile_jadx::DecompiledProject::find_class"}).to_string())) } }

pub struct MobileJadxProjectInPackageTool;
impl MobileJadxProjectInPackageTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_jadx_project_in_package".to_string(), description: "rustre_mobile_jadx::DecompiledProject::in_package on mock project".to_string(), input_schema: jadx_schema(&[("pkg", json!({"type":"string"}))]), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileJadxProjectInPackageTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pkg = args.get("pkg").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pkg'".into()))?; let p = jadx_project_from_args(&args)?; let names: Vec<String> = p.in_package(pkg).iter().map(|c| c.class_name.clone()).collect(); Ok(ToolResult::text(json!({"pkg":pkg,"classes":names,"source":"rustre_mobile_jadx::DecompiledProject::in_package"}).to_string())) } }

pub struct MobileJadxClassStaticMethodsTool;
impl MobileJadxClassStaticMethodsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_jadx_class_static_methods".to_string(), description: "rustre_mobile_jadx::JavaClass::static_methods on Utils of mock project".to_string(), input_schema: jadx_schema(&[]), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileJadxClassStaticMethodsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = jadx_project_from_args(&args)?; let names: Vec<String> = p.find_class("Utils").map(|c| c.static_methods().iter().map(|m| m.name.clone()).collect()).unwrap_or_default(); Ok(ToolResult::text(json!({"class":"Utils","static_methods":names,"source":"rustre_mobile_jadx::JavaClass::static_methods"}).to_string())) } }

pub struct MobileJadxClassNativeMethodsTool;
impl MobileJadxClassNativeMethodsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_jadx_class_native_methods".to_string(), description: "rustre_mobile_jadx::JavaClass::native_methods on MainActivity of mock project".to_string(), input_schema: jadx_schema(&[]), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileJadxClassNativeMethodsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = jadx_project_from_args(&args)?; let names: Vec<String> = p.find_class("MainActivity").map(|c| c.native_methods().iter().map(|m| m.name.clone()).collect()).unwrap_or_default(); Ok(ToolResult::text(json!({"class":"MainActivity","native_methods":names,"source":"rustre_mobile_jadx::JavaClass::native_methods"}).to_string())) } }

pub struct MobileJadxCliConfigDefaultTool;
impl MobileJadxCliConfigDefaultTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_jadx_cli_config_default".to_string(), description: "rustre_mobile_jadx::CliJadxConfig::default".to_string(), input_schema: jadx_schema(&[]), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileJadxCliConfigDefaultTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let cfg = rustre_mobile_jadx::CliJadxConfig::default(); Ok(ToolResult::text(json!({"jadx_path":cfg.jadx_path.display().to_string(),"deobfuscate":cfg.deobfuscate,"no_res":cfg.no_res,"show_bad":cfg.show_inconsistent_code,"source":"rustre_mobile_jadx::CliJadxConfig::default"}).to_string())) } }

pub struct MobileJadxCliFindInPathTool;
impl MobileJadxCliFindInPathTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_jadx_cli_find_in_path".to_string(), description: "rustre_mobile_jadx::CliJadxRunner::find_jadx_in_path".to_string(), input_schema: jadx_schema(&[]), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileJadxCliFindInPathTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let p = rustre_mobile_jadx::CliJadxRunner::find_jadx_in_path().map(|p| p.display().to_string()); Ok(ToolResult::text(json!({"found":p,"source":"rustre_mobile_jadx::CliJadxRunner::find_jadx_in_path"}).to_string())) } }

pub struct MobileJadxNativeDecompileMethodTool;
impl MobileJadxNativeDecompileMethodTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_jadx_native_decompile_method".to_string(), description: "rustre_mobile_jadx::NativeDexDecompiler::decompile_method".to_string(), input_schema: json!({"type":"object","properties":{"instructions":{"type":"array","items":{"type":"string"}}},"required":["instructions"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileJadxNativeDecompileMethodTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let insns: Vec<String> = args.get("instructions").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default(); let m = rustre_mobile_jadx::DalvikMethod { name: "m".to_string(), class_name: "C".to_string(), return_type: "void".to_string(), params: vec![], instructions: insns }; match rustre_mobile_jadx::NativeDexDecompiler::decompile_method(&m) { Ok(out) => Ok(ToolResult::text(json!({"source_len":out.len(),"pseudo":out,"source":"rustre_mobile_jadx::NativeDexDecompiler::decompile_method"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"error":e.to_string()}).to_string())) } } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (MobileJadxFindTool::definition(), Box::new(MobileJadxFindTool)),
        (MobileJadxDescriptorToTypeTool::definition(), Box::new(MobileJadxDescriptorToTypeTool)),
        (MobileJadxConfigNewTool::definition(), Box::new(MobileJadxConfigNewTool)),
        (MobileJadxJavaMethodIsConstructorTool::definition(), Box::new(MobileJadxJavaMethodIsConstructorTool)),
        (MobileJadxDalvikOpcodeFromByteTool::definition(), Box::new(MobileJadxDalvikOpcodeFromByteTool)),
        (MobileJadxDalvikOpcodeMnemonicTool::definition(), Box::new(MobileJadxDalvikOpcodeMnemonicTool)),
        (MobileJadxConfigWithThreadsTool::definition(), Box::new(MobileJadxConfigWithThreadsTool)),
        (MobileJadxConfigWithDeobfTool::definition(), Box::new(MobileJadxConfigWithDeobfTool)),
        (MobileJadxProjectMockTool::definition(), Box::new(MobileJadxProjectMockTool)),
        (MobileJadxProjectSuccessRateTool::definition(), Box::new(MobileJadxProjectSuccessRateTool)),
        (MobileJadxProjectFindClassTool::definition(), Box::new(MobileJadxProjectFindClassTool)),
        (MobileJadxProjectInPackageTool::definition(), Box::new(MobileJadxProjectInPackageTool)),
        (MobileJadxClassStaticMethodsTool::definition(), Box::new(MobileJadxClassStaticMethodsTool)),
        (MobileJadxClassNativeMethodsTool::definition(), Box::new(MobileJadxClassNativeMethodsTool)),
        (MobileJadxCliConfigDefaultTool::definition(), Box::new(MobileJadxCliConfigDefaultTool)),
        (MobileJadxCliFindInPathTool::definition(), Box::new(MobileJadxCliFindInPathTool)),
        (MobileJadxNativeDecompileMethodTool::definition(), Box::new(MobileJadxNativeDecompileMethodTool)),
    ]
}
