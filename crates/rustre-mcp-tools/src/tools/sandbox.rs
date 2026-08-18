//! MCP wrappers for the rustre-sandbox crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct SandboxVmMemoryMapMockTool;

pub struct SandboxVmQemuBuildArgsTool;

pub struct SandboxPolicyBalancedValidateTool;
impl SandboxPolicyBalancedValidateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_policy_balanced_validate".to_string(),
            description: "Return the balanced SandboxPolicy summary and validation result \
                          (rustre_sandbox::SandboxPolicy::balanced + validate)."
                .to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxPolicyBalancedValidateTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let policy = rustre_sandbox::SandboxPolicy::balanced();
        let valid = policy.validate().is_ok();
        Ok(ToolResult::text(json!({
            "timeout_secs": policy.timeout_secs,
            "max_memory_mb": policy.max_memory_mb,
            "perms_bits": policy.perms.bits(),
            "fs_write_paths": policy.fs_write_paths,
            "valid": valid,
            "source": "rustre_sandbox::SandboxPolicy::balanced",
        }).to_string()))
    }
}

pub struct SandboxResourceLimitsCheckTool;
impl SandboxResourceLimitsCheckTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_resource_limits_check".to_string(),
            description: "Check tight ResourceLimits against a given memory/disk usage \
                          (rustre_sandbox::ResourceLimits::tight + memory_exceeded/disk_exceeded)."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "used_mb": {"type": "integer"},
                    "written_mb": {"type": "integer"}
                },
                "required": ["used_mb", "written_mb"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxResourceLimitsCheckTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let used_mb = args.get("used_mb").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'used_mb'".into()))? as u32;
        let written_mb = args.get("written_mb").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'written_mb'".into()))? as u32;
        let limits = rustre_sandbox::ResourceLimits::tight();
        Ok(ToolResult::text(json!({
            "used_mb": used_mb,
            "written_mb": written_mb,
            "memory_exceeded": limits.memory_exceeded(used_mb),
            "disk_exceeded": limits.disk_exceeded(written_mb),
            "max_memory_mb": limits.max_memory_mb,
            "max_disk_write_mb": limits.max_disk_write_mb,
            "source": "rustre_sandbox::ResourceLimits::tight",
        }).to_string()))
    }
}

pub struct SandboxBehaviorRecordMockSummaryTool;
impl SandboxBehaviorRecordMockSummaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_behavior_record_mock_summary".to_string(),
            description: "Summary counts and threat score for a BehaviorRecord from a real \
                          sandbox run, supplied as the `record` argument."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "record": {
                        "type": "object",
                        "description": "A BehaviorRecord from a real sandbox run"
                    },
                    "use_synthetic_fixture": {
                        "type": "boolean",
                        "description": "Summarise the built-in fixture instead. The response is labelled is_synthetic_fixture and its threat score is NOT an observation."
                    }
                },
                "required": ["record"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxBehaviorRecordMockSummaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        // ⚠ This declared no arguments and summarised `BehaviorRecord::mock()`,
        // so a client asking for a run's threat score, flagged syscalls and
        // persistence operations received the fixture's — numbers that describe
        // nothing that was ever executed.
        //
        // `BehaviorRecord` is `Deserialize`, so a caller that ran an analysis
        // hands the record straight back and gets a summary of its own run.
        let (rec, is_synthetic_fixture) =
            if args.get("use_synthetic_fixture").and_then(Value::as_bool) == Some(true) {
                (rustre_sandbox::BehaviorRecord::mock(), true)
            } else {
                let raw = args.get("record").ok_or_else(|| {
                    McpError::InvalidParams(
                        "'record' is required: a BehaviorRecord from a real run. Pass \
                         \"use_synthetic_fixture\": true for the built-in fixture."
                            .to_string(),
                    )
                })?;
                let parsed: rustre_sandbox::BehaviorRecord = serde_json::from_value(raw.clone())
                    .map_err(|e| {
                        McpError::ToolError(format!("'record' is not a BehaviorRecord: {e}"))
                    })?;
                (parsed, false)
            };
        Ok(ToolResult::text(json!({
            "syscall_count": rec.syscalls.len(),
            "flagged_syscalls": rec.flagged_syscall_count(),
            "external_conns": rec.external_conn_count(),
            "dropped_exes": rec.dropped_exe_count(),
            "persistence_ops": rec.persistence_op_count(),
            "process_count": rec.process_tree.process_count(),
            "threat_score": rec.flags.threat_score(),
            "behaviors": rec.flags.describe(),
            "is_synthetic_fixture": is_synthetic_fixture,
            "source": "rustre_sandbox::BehaviorRecord (supplied by the caller)",
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (SandboxVmMemoryMapMockTool::definition(), Box::new(SandboxVmMemoryMapMockTool)),
        (SandboxVmQemuBuildArgsTool::definition(), Box::new(SandboxVmQemuBuildArgsTool)),
        (SandboxPolicyBalancedValidateTool::definition(), Box::new(SandboxPolicyBalancedValidateTool)),
        (SandboxResourceLimitsCheckTool::definition(), Box::new(SandboxResourceLimitsCheckTool)),
        (SandboxBehaviorRecordMockSummaryTool::definition(), Box::new(SandboxBehaviorRecordMockSummaryTool)),
    ]
}

/// Expose `rustre_sandbox_report::Severity::parse` as an MCP tool.
pub struct SandboxReportSeverityParseToolV2;

impl SandboxReportSeverityParseToolV2 {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_severity_parse_v2".to_string(),
            description: "Parse a severity string (info/low/medium/high/critical) and return its numeric score (rustre_sandbox_report::Severity::parse).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "severity": { "type": "string" } },
                "required": ["severity"]
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for SandboxReportSeverityParseToolV2 {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("severity").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'severity'".to_string()))?;
        let sev = rustre_sandbox_report::Severity::parse(s)
            .map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(
            json!({
                "severity": sev.to_string(),
                "score": sev.score(),
                "source": "rustre_sandbox_report::Severity::parse"
            }).to_string(),
        ))
    }
}

/// Expose `rustre_sandbox_report::IocSet::mock` as an MCP tool.
pub struct SandboxReportIocsetMockToolV2;

impl SandboxReportIocsetMockToolV2 {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_iocset_mock_v2".to_string(),
            description: "Return a mock IOC set for testing (rustre_sandbox_report::IocSet::mock).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for SandboxReportIocsetMockToolV2 {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let set = rustre_sandbox_report::IocSet::mock();
        let iocs: Vec<serde_json::Value> = set.iocs.iter().map(|i| json!({
            "kind": i.kind.to_string(),
            "value": i.value,
            "confidence": i.confidence,
            "context": i.context,
        })).collect();
        Ok(ToolResult::text(
            json!({
                "count": set.len(),
                "iocs": iocs,
                "source": "rustre_sandbox_report::IocSet::mock"
            }).to_string(),
        ))
    }
}
