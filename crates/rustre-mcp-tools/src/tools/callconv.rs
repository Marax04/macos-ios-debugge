//! MCP wrappers for the rustre-callconv crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{callconv_pattern_to_json};

pub struct CallconvSysvX64NameTool;

pub struct CallconvMsvcX64NameTool;

pub struct CallconvSysvX64Tool;
impl CallconvSysvX64Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "callconv_sysv_x64".to_string(),
            description: "Return the System V AMD64 ABI calling convention pattern via rustre_analysis_callconv::sysv_x64().".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CallconvSysvX64Tool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let p = rustre_analysis_callconv::sysv_x64();
        Ok(ToolResult::text(json!({
            "pattern": callconv_pattern_to_json(&p),
            "source":  "rustre_analysis_callconv::sysv_x64",
        }).to_string()))
    }
}

pub struct CallconvMsvcX64Tool;
impl CallconvMsvcX64Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "callconv_msvc_x64".to_string(),
            description: "Return the Microsoft x64 calling convention pattern via rustre_analysis_callconv::msvc_x64().".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CallconvMsvcX64Tool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let p = rustre_analysis_callconv::msvc_x64();
        Ok(ToolResult::text(json!({
            "pattern": callconv_pattern_to_json(&p),
            "source":  "rustre_analysis_callconv::msvc_x64",
        }).to_string()))
    }
}

pub struct CallconvAapcs64Tool;
impl CallconvAapcs64Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "callconv_aapcs64".to_string(),
            description: "Return the AAPCS64 (Arm64) calling convention pattern via rustre_analysis_callconv::aapcs64().".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CallconvAapcs64Tool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let p = rustre_analysis_callconv::aapcs64();
        Ok(ToolResult::text(json!({
            "pattern": callconv_pattern_to_json(&p),
            "source":  "rustre_analysis_callconv::aapcs64",
        }).to_string()))
    }
}

pub struct CallconvSysvX64IsArgRegisterTool;
impl CallconvSysvX64IsArgRegisterTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "callconv_sysv_x64_is_arg_register".to_string(),
            description: "Check whether a register name is an integer/fp arg register in SysV x64.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "reg": {"type":"string"} }, "required":["reg"] }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CallconvSysvX64IsArgRegisterTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let reg = args.get("reg").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'reg'".into()))?;
        let cc = rustre_analysis_callconv::sysv_x64();
        Ok(ToolResult::text(json!({
            "reg": reg,
            "is_arg_register": cc.is_arg_register(reg),
            "source": "rustre_analysis_callconv::CallingConventionPattern::is_arg_register",
        }).to_string()))
    }
}

pub struct CallconvMsvcX64IsCalleeSavedTool;
impl CallconvMsvcX64IsCalleeSavedTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "callconv_msvc_x64_is_callee_saved".to_string(),
            description: "Check whether a register is callee-saved under the Microsoft x64 ABI.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "reg": {"type":"string"} }, "required":["reg"] }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CallconvMsvcX64IsCalleeSavedTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let reg = args.get("reg").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'reg'".into()))?;
        let cc = rustre_analysis_callconv::msvc_x64();
        Ok(ToolResult::text(json!({
            "reg": reg,
            "is_callee_saved": cc.is_callee_saved(reg),
            "source": "rustre_analysis_callconv::CallingConventionPattern::is_callee_saved",
        }).to_string()))
    }
}

pub struct CallconvSysvX64ArgRegisterAtTool;
impl CallconvSysvX64ArgRegisterAtTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "callconv_sysv_x64_arg_register_at".to_string(),
            description: "Return the SysV x64 integer arg register at index n (or null if stack-passed).".to_string(),
            input_schema: json!({ "type": "object", "properties": { "n": {"type":"integer"} }, "required":["n"] }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CallconvSysvX64ArgRegisterAtTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))? as usize;
        let cc = rustre_analysis_callconv::sysv_x64();
        Ok(ToolResult::text(json!({
            "n": n,
            "reg": cc.arg_register_at(n),
            "source": "rustre_analysis_callconv::CallingConventionPattern::arg_register_at",
        }).to_string()))
    }
}

pub struct CallconvAapcs64ArgRegisterCountTool;
impl CallconvAapcs64ArgRegisterCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "callconv_aapcs64_arg_register_count".to_string(),
            description: "Return the number of integer argument registers in AAPCS64.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CallconvAapcs64ArgRegisterCountTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let cc = rustre_analysis_callconv::aapcs64();
        Ok(ToolResult::text(json!({
            "count": cc.arg_register_count(),
            "source": "rustre_analysis_callconv::CallingConventionPattern::arg_register_count",
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (CallconvSysvX64NameTool::definition(), Box::new(CallconvSysvX64NameTool)),
        (CallconvMsvcX64NameTool::definition(), Box::new(CallconvMsvcX64NameTool)),
        (CallconvSysvX64Tool::definition(), Box::new(CallconvSysvX64Tool)),
        (CallconvMsvcX64Tool::definition(), Box::new(CallconvMsvcX64Tool)),
        (CallconvAapcs64Tool::definition(), Box::new(CallconvAapcs64Tool)),
        (CallconvSysvX64IsArgRegisterTool::definition(), Box::new(CallconvSysvX64IsArgRegisterTool)),
        (CallconvMsvcX64IsCalleeSavedTool::definition(), Box::new(CallconvMsvcX64IsCalleeSavedTool)),
        (CallconvSysvX64ArgRegisterAtTool::definition(), Box::new(CallconvSysvX64ArgRegisterAtTool)),
        (CallconvAapcs64ArgRegisterCountTool::definition(), Box::new(CallconvAapcs64ArgRegisterCountTool)),
    ]
}
