//! MCP wrappers for the rustre-arch_x86 crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{x86_arch_for_bits};

pub struct ArchX86DisassembleAndLiftTool;

pub struct ArchX86LiftToLlilTool;

pub struct ArchX86MetadataTool;
impl ArchX86MetadataTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_x86_metadata".to_string(),
            description: "Return X86Arch metadata (name, pointer_size, endian, bits) \
                          via rustre_arch_x86::X86Arch."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "bits": { "type": "integer" } }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchX86MetadataTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_core::arch::Architecture;
        let bits = args.get("bits").and_then(Value::as_u64).unwrap_or(64);
        let arch = x86_arch_for_bits(bits)?;
        Ok(ToolResult::text(json!({
            "name": arch.name(),
            "pointer_size": arch.pointer_size(),
            "endian": format!("{:?}", arch.endian()),
            "bits": arch.bits(),
            "source": "rustre_arch_x86::X86Arch",
        }).to_string()))
    }
}

pub struct ArchX86RegistersTool;
impl ArchX86RegistersTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_x86_registers".to_string(),
            description: "List all registers exposed by X86Arch::registers() for a given bitness."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "bits": { "type": "integer" } }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchX86RegistersTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_core::arch::Architecture;
        let bits = args.get("bits").and_then(Value::as_u64).unwrap_or(64);
        let arch = x86_arch_for_bits(bits)?;
        let regs = arch.registers();
        let names: Vec<&str> = regs.iter().map(|r| r.name.as_str()).collect();
        Ok(ToolResult::text(json!({
            "bits": bits,
            "count": regs.len(),
            "names": names,
            "source": "rustre_arch_x86::X86Arch::registers",
        }).to_string()))
    }
}

pub struct ArchX86CallingConventionsTool;
impl ArchX86CallingConventionsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_x86_calling_conventions".to_string(),
            description: "List calling conventions exposed by X86Arch::calling_conventions() \
                          (name, int_args, return_regs, caller_cleans_stack)."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "bits": { "type": "integer" } }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchX86CallingConventionsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_core::arch::Architecture;
        let bits = args.get("bits").and_then(Value::as_u64).unwrap_or(64);
        let arch = x86_arch_for_bits(bits)?;
        let ccs = arch.calling_conventions();
        let items: Vec<Value> = ccs.iter().map(|cc| json!({
            "name": cc.name,
            "int_args": cc.int_args,
            "return_regs": cc.return_regs,
            "caller_cleans_stack": cc.caller_cleans_stack,
        })).collect();
        Ok(ToolResult::text(json!({
            "bits": bits,
            "count": items.len(),
            "calling_conventions": items,
            "source": "rustre_arch_x86::X86Arch::calling_conventions",
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ArchX86DisassembleAndLiftTool::definition(), Box::new(ArchX86DisassembleAndLiftTool)),
        (ArchX86LiftToLlilTool::definition(), Box::new(ArchX86LiftToLlilTool)),
        (ArchX86MetadataTool::definition(), Box::new(ArchX86MetadataTool)),
        (ArchX86RegistersTool::definition(), Box::new(ArchX86RegistersTool)),
        (ArchX86CallingConventionsTool::definition(), Box::new(ArchX86CallingConventionsTool)),
    ]
}
