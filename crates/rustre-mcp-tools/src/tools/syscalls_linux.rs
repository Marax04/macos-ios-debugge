//! MCP wrappers for the rustre-syscalls_linux crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct SyscallsLinuxX8664NameTool;

pub struct SyscallsLinuxX8664NrTool;

pub struct SyscallsLinuxSecuritySeverityTool;

pub struct SyscallsLinuxCategoryTool;

pub struct SyscallsLinuxErrorNotFoundDisplayTool;

pub struct SyscallsLinuxParamNewTool;

pub struct SyscallsLinuxDecodeOpenFlagsTool;
impl SyscallsLinuxDecodeOpenFlagsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_linux_decode_open_flags".to_string(),
            description: "Decode an open()/openat() flags bitmask into a human string.".to_string(),
            input_schema: json!({"type":"object","properties":{"flags":{"type":"integer","minimum":0}},"required":["flags"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsLinuxDecodeOpenFlagsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let f = args.get("flags").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'flags'".into()))?;
        let f32v = u32::try_from(f).map_err(|_| McpError::InvalidParams("flags out of range".into()))?;
        let s = rustre_syscalls_linux::decode_open_flags(f32v);
        Ok(ToolResult::text(json!({"flags":f32v,"decoded":s,"source":"rustre_syscalls_linux::decode_open_flags"}).to_string()))
    }
}

pub struct SyscallsLinuxDecodeMmapProtTool;
impl SyscallsLinuxDecodeMmapProtTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_linux_decode_mmap_prot".to_string(),
            description: "Decode an mmap() prot bitmask into a human string.".to_string(),
            input_schema: json!({"type":"object","properties":{"prot":{"type":"integer","minimum":0}},"required":["prot"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsLinuxDecodeMmapProtTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let p = args.get("prot").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'prot'".into()))?;
        let p32 = u32::try_from(p).map_err(|_| McpError::InvalidParams("prot out of range".into()))?;
        let s = rustre_syscalls_linux::decode_mmap_prot(p32);
        Ok(ToolResult::text(json!({"prot":p32,"decoded":s,"source":"rustre_syscalls_linux::decode_mmap_prot"}).to_string()))
    }
}

pub struct SyscallsLinuxDecodeMmapFlagsTool;
impl SyscallsLinuxDecodeMmapFlagsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_linux_decode_mmap_flags".to_string(),
            description: "Decode an mmap() flags bitmask into a human string.".to_string(),
            input_schema: json!({"type":"object","properties":{"flags":{"type":"integer","minimum":0}},"required":["flags"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsLinuxDecodeMmapFlagsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let f = args.get("flags").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'flags'".into()))?;
        let f32v = u32::try_from(f).map_err(|_| McpError::InvalidParams("flags out of range".into()))?;
        let s = rustre_syscalls_linux::decode_mmap_flags(f32v);
        Ok(ToolResult::text(json!({"flags":f32v,"decoded":s,"source":"rustre_syscalls_linux::decode_mmap_flags"}).to_string()))
    }
}

pub struct SyscallsLinuxLookupX8664EntryTool;
impl SyscallsLinuxLookupX8664EntryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_linux_lookup_x86_64_entry".to_string(),
            description: "Look up an x86_64 Linux syscall entry (name + param count).".to_string(),
            input_schema: json!({"type":"object","properties":{"number":{"type":"integer","minimum":0}},"required":["number"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsLinuxLookupX8664EntryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("number").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'number'".into()))?;
        let n32 = u32::try_from(n).map_err(|_| McpError::InvalidParams("out of range".into()))?;
        let e = rustre_syscalls_linux::lookup_x86_64_entry(n32);
        let (found, name, nparams) = match e {
            Some(entry) => (true, Some(entry.name), Some(entry.arg_count as usize)),
            None => (false, None, None),
        };
        Ok(ToolResult::text(json!({"number":n32,"found":found,"name":name,"param_count":nparams,"source":"rustre_syscalls_linux::lookup_x86_64_entry"}).to_string()))
    }
}

pub struct SyscallsLinuxAarch64NameTool;
impl SyscallsLinuxAarch64NameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_linux_aarch64_name".to_string(),
            description: "Return the aarch64 Linux syscall name for a given number.".to_string(),
            input_schema: json!({"type":"object","properties":{"number":{"type":"integer","minimum":0}},"required":["number"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsLinuxAarch64NameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("number").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'number'".into()))?;
        let n32 = u32::try_from(n).map_err(|_| McpError::InvalidParams("out of range".into()))?;
        let name = rustre_syscalls_linux::aarch64_syscall_name(n32);
        Ok(ToolResult::text(json!({"number":n32,"name":name,"source":"rustre_syscalls_linux::aarch64_syscall_name"}).to_string()))
    }
}

pub struct SyscallsLinuxAarch64NrTool;
impl SyscallsLinuxAarch64NrTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_linux_aarch64_nr".to_string(),
            description: "Return the aarch64 Linux syscall number for a given name.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsLinuxAarch64NrTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let nr = rustre_syscalls_linux::aarch64_syscall_nr(name);
        Ok(ToolResult::text(json!({"name":name,"number":nr,"source":"rustre_syscalls_linux::aarch64_syscall_nr"}).to_string()))
    }
}

pub struct SyscallsLinuxFormatRetvalTool;
impl SyscallsLinuxFormatRetvalTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_linux_format_retval".to_string(),
            description: "Format a Linux syscall return value (errno-aware if negative).".to_string(),
            input_schema: json!({"type":"object","properties":{"retval":{"type":"integer"}},"required":["retval"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsLinuxFormatRetvalTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let r = args.get("retval").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("missing 'retval'".into()))?;
        let s = rustre_syscalls_linux::format_retval(r);
        Ok(ToolResult::text(json!({"retval":r,"formatted":s,"source":"rustre_syscalls_linux::format_retval"}).to_string()))
    }
}

pub struct SyscallsLinuxFormatMmapArgsTool;
impl SyscallsLinuxFormatMmapArgsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_linux_format_mmap_args".to_string(),
            description: "Format mmap() prot+flags as a human-readable string.".to_string(),
            input_schema: json!({"type":"object","properties":{"prot":{"type":"integer","minimum":0},"flags":{"type":"integer","minimum":0}},"required":["prot","flags"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsLinuxFormatMmapArgsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let p = args.get("prot").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'prot'".into()))?;
        let f = args.get("flags").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'flags'".into()))?;
        let s = rustre_syscalls_linux::format_mmap_args(p, f);
        Ok(ToolResult::text(json!({"prot":p,"flags":f,"formatted":s,"source":"rustre_syscalls_linux::format_mmap_args"}).to_string()))
    }
}

pub struct SyscallsLinuxFormatOpenFlagsTool;
impl SyscallsLinuxFormatOpenFlagsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_linux_format_open_flags".to_string(),
            description: "Format open()/openat() flags (u64) as a human-readable string.".to_string(),
            input_schema: json!({"type":"object","properties":{"flags":{"type":"integer","minimum":0}},"required":["flags"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsLinuxFormatOpenFlagsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let f = args.get("flags").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'flags'".into()))?;
        let s = rustre_syscalls_linux::format_open_flags(f);
        Ok(ToolResult::text(json!({"flags":f,"formatted":s,"source":"rustre_syscalls_linux::format_open_flags"}).to_string()))
    }
}

pub struct SyscallsLinuxFormatSignalDeliveryTool;
impl SyscallsLinuxFormatSignalDeliveryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_linux_format_signal_delivery".to_string(),
            description: "Format a strace-style signal delivery record.".to_string(),
            input_schema: json!({"type":"object","properties":{"sig":{"type":"integer","minimum":0},"si_code":{"type":"integer"},"si_addr":{"type":"integer","minimum":0}},"required":["sig","si_code","si_addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsLinuxFormatSignalDeliveryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let sig = args.get("sig").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'sig'".into()))?;
        let sig32 = u32::try_from(sig).map_err(|_| McpError::InvalidParams("sig out of range".into()))?;
        let sic = args.get("si_code").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("missing 'si_code'".into()))?;
        let sic32 = i32::try_from(sic).map_err(|_| McpError::InvalidParams("si_code out of range".into()))?;
        let addr = args.get("si_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'si_addr'".into()))?;
        let s = rustre_syscalls_linux::format_signal_delivery(sig32, sic32, addr);
        Ok(ToolResult::text(json!({"formatted":s,"source":"rustre_syscalls_linux::format_signal_delivery"}).to_string()))
    }
}

pub struct SyscallsLinuxFormatExitEventTool;
impl SyscallsLinuxFormatExitEventTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_linux_format_exit_event".to_string(),
            description: "Format a strace-style process exit event.".to_string(),
            input_schema: json!({"type":"object","properties":{"pid":{"type":"integer","minimum":0},"code":{"type":"integer"},"signal":{"type":["integer","null"],"minimum":0}},"required":["pid","code"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsLinuxFormatExitEventTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pid = args.get("pid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'pid'".into()))?;
        let pid32 = u32::try_from(pid).map_err(|_| McpError::InvalidParams("pid out of range".into()))?;
        let code = args.get("code").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("missing 'code'".into()))?;
        let code32 = i32::try_from(code).map_err(|_| McpError::InvalidParams("code out of range".into()))?;
        let signal = args.get("signal").and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok());
        let s = rustre_syscalls_linux::format_exit_event(pid32, code32, signal);
        Ok(ToolResult::text(json!({"formatted":s,"source":"rustre_syscalls_linux::format_exit_event"}).to_string()))
    }
}

pub struct SyscallsLinuxHexDumpExtTool;
impl SyscallsLinuxHexDumpExtTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_linux_hex_dump_ext".to_string(),
            description: "Hex-dump a byte string (strace-style, truncated to max_bytes).".to_string(),
            input_schema: json!({"type":"object","properties":{"hex":{"type":"string"},"max_bytes":{"type":"integer","minimum":0}},"required":["hex","max_bytes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsLinuxHexDumpExtTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?;
        let max = args.get("max_bytes").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'max_bytes'".into()))? as usize;
        let bytes: Vec<u8> = (0..hex.len()).step_by(2)
            .filter_map(|i| hex.get(i..i+2).and_then(|s| u8::from_str_radix(s, 16).ok()))
            .collect();
        let s = rustre_syscalls_linux::hex_dump_ext(&bytes, max);
        Ok(ToolResult::text(json!({"len":bytes.len(),"dump":s,"source":"rustre_syscalls_linux::hex_dump_ext"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (SyscallsLinuxX8664NameTool::definition(), Box::new(SyscallsLinuxX8664NameTool)),
        (SyscallsLinuxX8664NrTool::definition(), Box::new(SyscallsLinuxX8664NrTool)),
        (SyscallsLinuxSecuritySeverityTool::definition(), Box::new(SyscallsLinuxSecuritySeverityTool)),
        (SyscallsLinuxCategoryTool::definition(), Box::new(SyscallsLinuxCategoryTool)),
        (SyscallsLinuxErrorNotFoundDisplayTool::definition(), Box::new(SyscallsLinuxErrorNotFoundDisplayTool)),
        (SyscallsLinuxParamNewTool::definition(), Box::new(SyscallsLinuxParamNewTool)),
        (SyscallsLinuxDecodeOpenFlagsTool::definition(), Box::new(SyscallsLinuxDecodeOpenFlagsTool)),
        (SyscallsLinuxDecodeMmapProtTool::definition(), Box::new(SyscallsLinuxDecodeMmapProtTool)),
        (SyscallsLinuxDecodeMmapFlagsTool::definition(), Box::new(SyscallsLinuxDecodeMmapFlagsTool)),
        (SyscallsLinuxLookupX8664EntryTool::definition(), Box::new(SyscallsLinuxLookupX8664EntryTool)),
        (SyscallsLinuxAarch64NameTool::definition(), Box::new(SyscallsLinuxAarch64NameTool)),
        (SyscallsLinuxAarch64NrTool::definition(), Box::new(SyscallsLinuxAarch64NrTool)),
        (SyscallsLinuxFormatRetvalTool::definition(), Box::new(SyscallsLinuxFormatRetvalTool)),
        (SyscallsLinuxFormatMmapArgsTool::definition(), Box::new(SyscallsLinuxFormatMmapArgsTool)),
        (SyscallsLinuxFormatOpenFlagsTool::definition(), Box::new(SyscallsLinuxFormatOpenFlagsTool)),
        (SyscallsLinuxFormatSignalDeliveryTool::definition(), Box::new(SyscallsLinuxFormatSignalDeliveryTool)),
        (SyscallsLinuxFormatExitEventTool::definition(), Box::new(SyscallsLinuxFormatExitEventTool)),
        (SyscallsLinuxHexDumpExtTool::definition(), Box::new(SyscallsLinuxHexDumpExtTool)),
    ]
}
