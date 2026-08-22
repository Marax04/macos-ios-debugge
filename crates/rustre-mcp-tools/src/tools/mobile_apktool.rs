//! MCP wrappers for the rustre-mobile_apktool crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct MobileApktoolFindTool;

pub struct MobileApktoolConfigNewTool;

pub struct MobileApktoolErrorDisplayTool;

pub struct MobileApktoolMockSuccessTool;

pub struct MobileApktoolConfigWithNoSrcTool;
impl MobileApktoolConfigWithNoSrcTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_apktool_config_with_no_src".to_string(), description: "ApktoolConfig with_no_src flag.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"out":{"type":"string"}},"required":["path","out"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileApktoolConfigWithNoSrcTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?; let o = args.get("out").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'out'".into()))?; let c = rustre_mobile_apktool::ApktoolConfig::new(p, o).with_no_src(); Ok(ToolResult::text(json!({"no_src":c.no_src,"no_res":c.no_res,"force":c.force,"source":"rustre_mobile_apktool::ApktoolConfig::with_no_src"}).to_string())) } }

pub struct MobileApktoolConfigWithNoResTool;
impl MobileApktoolConfigWithNoResTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_apktool_config_with_no_res".to_string(), description: "ApktoolConfig::with_no_res.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"out":{"type":"string"}},"required":["path","out"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileApktoolConfigWithNoResTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?; let o = args.get("out").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'out'".into()))?; let c = rustre_mobile_apktool::ApktoolConfig::new(p, o).with_no_res(); Ok(ToolResult::text(json!({"no_res":c.no_res,"source":"rustre_mobile_apktool::ApktoolConfig::with_no_res"}).to_string())) } }

pub struct MobileApktoolConfigWithForceTool;
impl MobileApktoolConfigWithForceTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_apktool_config_with_force".to_string(), description: "ApktoolConfig::with_force.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"out":{"type":"string"}},"required":["path","out"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileApktoolConfigWithForceTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?; let o = args.get("out").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'out'".into()))?; let c = rustre_mobile_apktool::ApktoolConfig::new(p, o).with_force(); Ok(ToolResult::text(json!({"force":c.force,"source":"rustre_mobile_apktool::ApktoolConfig::with_force"}).to_string())) } }

pub struct MobileApktoolMockFailureTool;
impl MobileApktoolMockFailureTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_apktool_mock_failure".to_string(), description: "Report the CONFIGURATION of a MockApktoolRunner::failure (which operations it is set to attempt, and its smali-directory filter). This performs NO decode and analyses NO file: it inspects constructor defaults. Real decoding is mobile_apktool_mock_decode / _impl_build, which run the apktool on PATH against a file that must exist.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileApktoolMockFailureTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let r = rustre_mobile_apktool::MockApktoolRunner::failure(); Ok(ToolResult::text(json!({"decode_ok":r.decode_ok,"build_ok":r.build_ok,"smali_dirs":r.smali_dirs.len(),"source":"rustre_mobile_apktool::MockApktoolRunner::failure"}).to_string())) } }

pub struct MobileApktoolMockDecodeTool;
impl MobileApktoolMockDecodeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_apktool_mock_decode".to_string(), description: "MockApktoolRunner::success().decode.".to_string(), input_schema: json!({"type":"object","properties":{"apk":{"type":"string"},"out":{"type":"string"}},"required":["apk","out"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileApktoolMockDecodeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_mobile_apktool::ApktoolRunner; let apk = args.get("apk").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'apk'".into()))?; let out = args.get("out").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'out'".into()))?; let r = rustre_mobile_apktool::MockApktoolRunner::success(); let cfg = rustre_mobile_apktool::ApktoolConfig::new("apktool", out); match r.decode(apk, &cfg) { Ok(d) => Ok(ToolResult::text(json!({"success":d.success,"smali_count":d.smali_count(),"res_dir":d.res_dir,"source":"rustre_mobile_apktool::MockApktoolRunner::decode"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct MobileApktoolMockBuildTool;
impl MobileApktoolMockBuildTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_apktool_mock_build".to_string(), description: "MockApktoolRunner::success().build.".to_string(), input_schema: json!({"type":"object","properties":{"dir":{"type":"string"},"out":{"type":"string"}},"required":["dir","out"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileApktoolMockBuildTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_mobile_apktool::ApktoolRunner; let dir = args.get("dir").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'dir'".into()))?; let out = args.get("out").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'out'".into()))?; let r = rustre_mobile_apktool::MockApktoolRunner::success(); let cfg = rustre_mobile_apktool::ApktoolConfig::new("apktool", out); match r.build(dir, &cfg) { Ok(b) => Ok(ToolResult::text(json!({"success":b.success,"apk_path":b.apk_path,"source":"rustre_mobile_apktool::MockApktoolRunner::build"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct MobileApktoolCliWithPathTool;
impl MobileApktoolCliWithPathTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_apktool_cli_with_path".to_string(), description: "CliApktoolRunner::with_path.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileApktoolCliWithPathTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?; let r = rustre_mobile_apktool::CliApktoolRunner::with_path(p); Ok(ToolResult::text(json!({"apktool_path":r.apktool_path.to_string_lossy(),"source":"rustre_mobile_apktool::CliApktoolRunner::with_path"}).to_string())) } }

pub struct MobileApktoolApkDecodeSmaliCountTool;
impl MobileApktoolApkDecodeSmaliCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_apktool_apk_decode_smali_count".to_string(), description: "ApkDecodeResult::smali_count via ApktoolRunnerImpl.".to_string(), input_schema: json!({"type":"object","properties":{"apk":{"type":"string"},"out":{"type":"string"}},"required":["apk","out"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileApktoolApkDecodeSmaliCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let apk = args.get("apk").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'apk'".into()))?; let out = args.get("out").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'out'".into()))?; let cfg = rustre_mobile_apktool::ApktoolConfig::new("apktool", out); let r = rustre_mobile_apktool::ApktoolRunnerImpl::new(cfg); match r.decode(apk) { Ok(d) => Ok(ToolResult::text(json!({"smali_count":d.smali_count(),"is_clean":d.is_clean(),"source":"rustre_mobile_apktool::ApkDecodeResult::smali_count"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct MobileApktoolImplBuildTool;
impl MobileApktoolImplBuildTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_apktool_impl_build".to_string(), description: "ApktoolRunnerImpl::build.".to_string(), input_schema: json!({"type":"object","properties":{"dir":{"type":"string"},"out":{"type":"string"}},"required":["dir","out"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileApktoolImplBuildTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let dir = args.get("dir").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'dir'".into()))?; let out = args.get("out").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'out'".into()))?; let cfg = rustre_mobile_apktool::ApktoolConfig::new("apktool", out); let r = rustre_mobile_apktool::ApktoolRunnerImpl::new(cfg); match r.build(dir) { Ok(b) => Ok(ToolResult::text(json!({"apk_path":b.apk_path,"unsigned":b.unsigned,"size_bytes":b.size_bytes,"source":"rustre_mobile_apktool::ApktoolRunnerImpl::build"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct MobileApktoolInstallFrameworkTool;
impl MobileApktoolInstallFrameworkTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_apktool_install_framework".to_string(), description: "ApktoolRunnerImpl::install_framework validation.".to_string(), input_schema: json!({"type":"object","properties":{"apk_path":{"type":"string"}},"required":["apk_path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileApktoolInstallFrameworkTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = args.get("apk_path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'apk_path'".into()))?; let cfg = rustre_mobile_apktool::ApktoolConfig::new("apktool", "out"); let r = rustre_mobile_apktool::ApktoolRunnerImpl::new(cfg); let ok = r.install_framework(p).is_ok(); Ok(ToolResult::text(json!({"ok":ok,"source":"rustre_mobile_apktool::ApktoolRunnerImpl::install_framework"}).to_string())) } }

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (MobileApktoolFindTool::definition(), Box::new(MobileApktoolFindTool)),
        (MobileApktoolConfigNewTool::definition(), Box::new(MobileApktoolConfigNewTool)),
        (MobileApktoolErrorDisplayTool::definition(), Box::new(MobileApktoolErrorDisplayTool)),
        (MobileApktoolMockSuccessTool::definition(), Box::new(MobileApktoolMockSuccessTool)),
        (MobileApktoolConfigWithNoSrcTool::definition(), Box::new(MobileApktoolConfigWithNoSrcTool)),
        (MobileApktoolConfigWithNoResTool::definition(), Box::new(MobileApktoolConfigWithNoResTool)),
        (MobileApktoolConfigWithForceTool::definition(), Box::new(MobileApktoolConfigWithForceTool)),
        (MobileApktoolMockFailureTool::definition(), Box::new(MobileApktoolMockFailureTool)),
        (MobileApktoolMockDecodeTool::definition(), Box::new(MobileApktoolMockDecodeTool)),
        (MobileApktoolMockBuildTool::definition(), Box::new(MobileApktoolMockBuildTool)),
        (MobileApktoolCliWithPathTool::definition(), Box::new(MobileApktoolCliWithPathTool)),
        (MobileApktoolApkDecodeSmaliCountTool::definition(), Box::new(MobileApktoolApkDecodeSmaliCountTool)),
        (MobileApktoolImplBuildTool::definition(), Box::new(MobileApktoolImplBuildTool)),
        (MobileApktoolInstallFrameworkTool::definition(), Box::new(MobileApktoolInstallFrameworkTool)),
    ]
}
