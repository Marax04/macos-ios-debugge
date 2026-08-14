//! MCP wrappers for the rustre-ghidra_backend crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct GhidraBackendSupportedArchsTool;
impl GhidraBackendSupportedArchsTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_backend_supported_archs".to_string(),
            description: "List supported archs for rustre_decompiler_ghidra::GhidraBackend.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraBackendSupportedArchsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_decompiler::DecompilerBackend;
        let b = rustre_decompiler_ghidra::GhidraBackend::for_x86_64();
        let a = b.supported_archs();
        Ok(ToolResult::text(json!({"name":b.name(),"archs":a,"target":format!("{:?}",b.target_level()),"source":"rustre_decompiler_ghidra::GhidraBackend"}).to_string()))
    }
}

pub struct GhidraBackendForArm64Wire3Tool;
impl GhidraBackendForArm64Wire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_backend_for_arm64_wire3".to_string(), description: "GhidraBackend::for_arm64 via rustre_decompiler_ghidra::GhidraBackend.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for GhidraBackendForArm64Wire3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { use rustre_decompiler::DecompilerBackend; let b = rustre_decompiler_ghidra::GhidraBackend::for_arm64(); Ok(ToolResult::text(json!({"arch":b.arch(),"name":b.name(),"source":"rustre_decompiler_ghidra::GhidraBackend::for_arm64"}).to_string())) } }

pub struct GhidraBackendArchGhidfixp1Tool;
impl GhidraBackendArchGhidfixp1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_backend_arch_ghidfixp1".to_string(), description: "GhidraBackend::arch via rustre_decompiler_ghidra::GhidraBackend::new+arch.".to_string(), input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}},"required":["arch"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraBackendArchGhidfixp1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = args.get("arch").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'arch'".into()))?.to_string(); let b = rustre_decompiler_ghidra::GhidraBackend::new(a.clone()); Ok(ToolResult::text(json!({"arch":b.arch(),"input":a,"source":"rustre_decompiler_ghidra::GhidraBackend::arch"}).to_string())) } }

pub struct GhidraBackendForX8664Ghidfixp1Tool;
impl GhidraBackendForX8664Ghidfixp1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_backend_for_x86_64_ghidfixp1".to_string(), description: "GhidraBackend::for_x86_64 via rustre_decompiler_ghidra::GhidraBackend.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraBackendForX8664Ghidfixp1Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let b = rustre_decompiler_ghidra::GhidraBackend::for_x86_64(); Ok(ToolResult::text(json!({"arch":b.arch(),"source":"rustre_decompiler_ghidra::GhidraBackend::for_x86_64"}).to_string())) } }

pub struct GhidraBackendNewCustomArchGwx4Tool;
impl GhidraBackendNewCustomArchGwx4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_backend_new_custom_arch_gwx4".to_string(), description: "Build GhidraBackend with a custom arch via rustre_decompiler_ghidra::GhidraBackend::new.".to_string(), input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraBackendNewCustomArchGwx4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arch = args.get("arch").and_then(Value::as_str).unwrap_or("mips64").to_string(); let b = rustre_decompiler_ghidra::GhidraBackend::new(arch.clone()); Ok(ToolResult::text(json!({"arch":b.arch(),"requested":arch,"source":"rustre_decompiler_ghidra::GhidraBackend::new"}).to_string())) } }

pub struct GhidraBackendArm64InfoTool;
impl GhidraBackendArm64InfoTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_backend_arm64_info".to_string(),
            description: "Return name/arch/target-level of a GhidraBackend::for_arm64 instance.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraBackendArm64InfoTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_decompiler::DecompilerBackend;
        let b = rustre_decompiler_ghidra::GhidraBackend::for_arm64();
        Ok(ToolResult::text(json!({
            "name":b.name(),"arch":b.arch(),
            "target_level":format!("{:?}", b.target_level()),
            "supported_archs":b.supported_archs(),
            "source":"rustre_decompiler_ghidra::GhidraBackend::for_arm64"
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (GhidraBackendSupportedArchsTool::definition(), Box::new(GhidraBackendSupportedArchsTool)),
        (GhidraBackendForArm64Wire3Tool::definition(), Box::new(GhidraBackendForArm64Wire3Tool)),
        (GhidraBackendArchGhidfixp1Tool::definition(), Box::new(GhidraBackendArchGhidfixp1Tool)),
        (GhidraBackendForX8664Ghidfixp1Tool::definition(), Box::new(GhidraBackendForX8664Ghidfixp1Tool)),
        (GhidraBackendNewCustomArchGwx4Tool::definition(), Box::new(GhidraBackendNewCustomArchGwx4Tool)),
        (GhidraBackendArm64InfoTool::definition(), Box::new(GhidraBackendArm64InfoTool)),
    ]
}
