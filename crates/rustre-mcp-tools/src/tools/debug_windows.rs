//! MCP wrappers for the rustre-debug_windows crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct DebugWindowsIsCommittedTool;

pub struct DebugWindowsExceptionNameTool;

pub struct DebugWindowsStatusNameTool;
impl DebugWindowsStatusNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_status_name".to_string(),
            description: "Human-readable name for any known Windows/NT exception or STATUS_* code via rustre_debug_windows::DebugEventDecoder::status_name.".to_string(),
            input_schema: json!({"type":"object","required":["code"],"properties":{"code":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsStatusNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let code = args.get("code").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'code'".into()))? as u32;
        let name = rustre_debug_windows::DebugEventDecoder::status_name(code);
        Ok(ToolResult::text(json!({"code":code,"name":name,"source":"rustre_debug_windows::DebugEventDecoder::status_name"}).to_string()))
    }
}

pub struct DebugWindowsIsContinuableTool;
impl DebugWindowsIsContinuableTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_is_continuable".to_string(),
            description: "True when the given exception code is recoverable (not EXCEPTION_NONCONTINUABLE) via rustre_debug_windows::DebugEventDecoder::is_continuable.".to_string(),
            input_schema: json!({"type":"object","required":["code"],"properties":{"code":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsIsContinuableTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let code = args.get("code").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'code'".into()))? as u32;
        let ok = rustre_debug_windows::DebugEventDecoder::is_continuable(code);
        Ok(ToolResult::text(json!({"code":code,"is_continuable":ok,"source":"rustre_debug_windows::DebugEventDecoder::is_continuable"}).to_string()))
    }
}

pub struct DebugWindowsIsBreakpointLikeTool;
impl DebugWindowsIsBreakpointLikeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_is_breakpoint_like".to_string(),
            description: "True when the exception code is a debugger-generated breakpoint-style event via rustre_debug_windows::DebugEventDecoder::is_breakpoint_like.".to_string(),
            input_schema: json!({"type":"object","required":["code"],"properties":{"code":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsIsBreakpointLikeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let code = args.get("code").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'code'".into()))? as u32;
        let ok = rustre_debug_windows::DebugEventDecoder::is_breakpoint_like(code);
        Ok(ToolResult::text(json!({"code":code,"is_breakpoint_like":ok,"source":"rustre_debug_windows::DebugEventDecoder::is_breakpoint_like"}).to_string()))
    }
}

pub struct DebugWindowsClassifyExceptionTool;
impl DebugWindowsClassifyExceptionTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_classify_exception".to_string(),
            description: "Classify a Windows exception code into a broad ExceptionClass via rustre_debug_windows::DebugEventDecoder::classify.".to_string(),
            input_schema: json!({"type":"object","required":["code"],"properties":{"code":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsClassifyExceptionTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let code = args.get("code").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'code'".into()))? as u32;
        let cls = rustre_debug_windows::DebugEventDecoder::classify(code);
        Ok(ToolResult::text(json!({"code":code,"class":format!("{:?}",cls),"source":"rustre_debug_windows::DebugEventDecoder::classify"}).to_string()))
    }
}

pub struct DebugWindowsHwBpConditionDr7Tool;
impl DebugWindowsHwBpConditionDr7Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_hwbp_condition_dr7".to_string(),
            description: "Return the 2-bit DR7 condition encoding for a HwBpCondition via rustre_debug_windows::HwBpCondition::dr7_cond.".to_string(),
            input_schema: json!({"type":"object","required":["condition"],"properties":{"condition":{"type":"string","enum":["execute","write","io_readwrite","readwrite"]}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsHwBpConditionDr7Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("condition").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'condition'".into()))?;
        let c = match s {
            "execute" => rustre_debug_windows::HwBpCondition::Execute,
            "write" => rustre_debug_windows::HwBpCondition::Write,
            "io_readwrite" => rustre_debug_windows::HwBpCondition::IoReadWrite,
            "readwrite" => rustre_debug_windows::HwBpCondition::ReadWrite,
            _ => return Err(McpError::InvalidParams("bad 'condition'".into())),
        };
        let enc = c.dr7_cond();
        Ok(ToolResult::text(json!({"condition":s,"dr7_cond":enc,"source":"rustre_debug_windows::HwBpCondition::dr7_cond"}).to_string()))
    }
}

pub struct DebugWindowsHwBpSizeDr7Tool;
impl DebugWindowsHwBpSizeDr7Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_hwbp_size_dr7".to_string(),
            description: "Return the 2-bit DR7 size encoding for a HwBpSize via rustre_debug_windows::HwBpSize::dr7_size.".to_string(),
            input_schema: json!({"type":"object","required":["size"],"properties":{"size":{"type":"string","enum":["byte","word","dword","qword"]}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsHwBpSizeDr7Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("size").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))?;
        let sz = match s {
            "byte" => rustre_debug_windows::HwBpSize::Byte,
            "word" => rustre_debug_windows::HwBpSize::Word,
            "dword" => rustre_debug_windows::HwBpSize::Dword,
            "qword" => rustre_debug_windows::HwBpSize::Qword,
            _ => return Err(McpError::InvalidParams("bad 'size'".into())),
        };
        let enc = sz.dr7_size();
        Ok(ToolResult::text(json!({"size":s,"dr7_size":enc,"source":"rustre_debug_windows::HwBpSize::dr7_size"}).to_string()))
    }
}

pub struct DebugWindowsWow64TrapFlagTool;
impl DebugWindowsWow64TrapFlagTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_wow64_trap_flag".to_string(),
            description: "Return whether the Trap Flag (TF, bit 8) is set in a given EFLAGS value via rustre_debug_windows::Wow64Context::trap_flag.".to_string(),
            input_schema: json!({"type":"object","required":["eflags"],"properties":{"eflags":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsWow64TrapFlagTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let eflags = args.get("eflags").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'eflags'".into()))? as u32;
        let mut ctx = rustre_debug_windows::Wow64Context::default();
        ctx.eflags = eflags;
        let tf = ctx.trap_flag();
        Ok(ToolResult::text(json!({"eflags":eflags,"trap_flag":tf,"source":"rustre_debug_windows::Wow64Context::trap_flag"}).to_string()))
    }
}

pub struct DebugWindowsWow64SetTrapFlagTool;
impl DebugWindowsWow64SetTrapFlagTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_wow64_set_trap_flag".to_string(),
            description: "Set or clear the Trap Flag (TF, bit 8) in EFLAGS via rustre_debug_windows::Wow64Context::set_trap_flag.".to_string(),
            input_schema: json!({"type":"object","required":["eflags","set"],"properties":{"eflags":{"type":"integer"},"set":{"type":"boolean"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsWow64SetTrapFlagTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let eflags = args.get("eflags").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'eflags'".into()))? as u32;
        let set = args.get("set").and_then(Value::as_bool).ok_or_else(|| McpError::InvalidParams("missing 'set'".into()))?;
        let mut ctx = rustre_debug_windows::Wow64Context::default();
        ctx.eflags = eflags;
        ctx.set_trap_flag(set);
        Ok(ToolResult::text(json!({"eflags_in":eflags,"set":set,"eflags_out":ctx.eflags,"source":"rustre_debug_windows::Wow64Context::set_trap_flag"}).to_string()))
    }
}

pub struct DebugWindowsProtectNameTool;
impl DebugWindowsProtectNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_protect_name".to_string(),
            description: "Return the human-readable PAGE_* protection name for a Win32 protect flag value via rustre_debug_windows::MemoryRegionInfo::protect_name.".to_string(),
            input_schema: json!({"type":"object","required":["protect"],"properties":{"protect":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsProtectNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let protect = args.get("protect").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'protect'".into()))? as u32;
        let info = rustre_debug_windows::MemoryRegionInfo {
            base: 0, size: 0, state: rustre_debug_windows::MEM_COMMIT, protect, type_: 0,
        };
        let name = info.protect_name();
        Ok(ToolResult::text(json!({"protect":protect,"name":name,"source":"rustre_debug_windows::MemoryRegionInfo::protect_name"}).to_string()))
    }
}

pub struct DebugWindowsRegionPermsTool;
impl DebugWindowsRegionPermsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_region_perms".to_string(),
            description: "Given Win32 memory region state + protect flags, report readable/writable/executable/is_committed via rustre_debug_windows::MemoryRegionInfo.".to_string(),
            input_schema: json!({"type":"object","required":["state","protect"],"properties":{"state":{"type":"integer"},"protect":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsRegionPermsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let state = args.get("state").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'state'".into()))? as u32;
        let protect = args.get("protect").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'protect'".into()))? as u32;
        let info = rustre_debug_windows::MemoryRegionInfo {
            base: 0, size: 0, state, protect, type_: 0,
        };
        Ok(ToolResult::text(json!({
            "state":state,"protect":protect,
            "is_committed":info.is_committed(),
            "readable":info.is_readable(),
            "writable":info.is_writable(),
            "executable":info.is_executable(),
            "protect_name":info.protect_name(),
            "source":"rustre_debug_windows::MemoryRegionInfo"
        }).to_string()))
    }
}

pub struct DebugWindowsMemoryRegionToMapTool;
impl DebugWindowsMemoryRegionToMapTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_memory_region_to_map".to_string(),
            description: "Convert Win32 MEMORY_BASIC_INFORMATION fields to a MemoryMap via rustre_debug_windows::MemoryRegionInfo::to_memory_map.".to_string(),
            input_schema: json!({"type":"object","required":["base","size","state","protect","type_"],"properties":{"base":{"type":"integer"},"size":{"type":"integer"},"state":{"type":"integer"},"protect":{"type":"integer"},"type_":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsMemoryRegionToMapTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))?;
        let state = args.get("state").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'state'".into()))? as u32;
        let protect = args.get("protect").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'protect'".into()))? as u32;
        let type_ = args.get("type_").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'type_'".into()))? as u32;
        let info = rustre_debug_windows::MemoryRegionInfo { base, size, state, protect, type_ };
        let mm = info.to_memory_map();
        Ok(ToolResult::text(json!({
            "base": mm.base.as_u64(), "size": mm.size,
            "readable": mm.readable, "writable": mm.writable, "executable": mm.executable,
            "source":"rustre_debug_windows::MemoryRegionInfo::to_memory_map"
        }).to_string()))
    }
}

pub struct DebugWindowsDecodeExitProcessTool;
impl DebugWindowsDecodeExitProcessTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_decode_exit_process".to_string(),
            description: "Decode EXIT_PROCESS_DEBUG_EVENT via rustre_debug_windows::DebugEventDecoder::decode_exit_process.".to_string(),
            input_schema: json!({"type":"object","required":["exit_code","pid","tid"],"properties":{"exit_code":{"type":"integer"},"pid":{"type":"integer"},"tid":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsDecodeExitProcessTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let exit_code = args.get("exit_code").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'exit_code'".into()))? as u32;
        let pid = args.get("pid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'pid'".into()))? as u32;
        let tid = args.get("tid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'tid'".into()))? as u32;
        let sr = rustre_debug_windows::DebugEventDecoder::decode_exit_process(exit_code, rustre_debug::ProcessId(pid), rustre_debug::ThreadId(tid));
        Ok(ToolResult::text(json!({"stop_reason": format!("{sr:?}"),"source":"rustre_debug_windows::DebugEventDecoder::decode_exit_process"}).to_string()))
    }
}

pub struct DebugWindowsDecodeExitThreadTool;
impl DebugWindowsDecodeExitThreadTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_decode_exit_thread".to_string(),
            description: "Decode EXIT_THREAD_DEBUG_EVENT via rustre_debug_windows::DebugEventDecoder::decode_exit_thread.".to_string(),
            input_schema: json!({"type":"object","required":["tid","exit_code","pid"],"properties":{"tid":{"type":"integer"},"exit_code":{"type":"integer"},"pid":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsDecodeExitThreadTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let tid = args.get("tid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'tid'".into()))? as u32;
        let exit_code = args.get("exit_code").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'exit_code'".into()))? as u32;
        let pid = args.get("pid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'pid'".into()))? as u32;
        let sr = rustre_debug_windows::DebugEventDecoder::decode_exit_thread(rustre_debug::ThreadId(tid), exit_code, rustre_debug::ProcessId(pid));
        Ok(ToolResult::text(json!({"stop_reason": format!("{sr:?}"),"source":"rustre_debug_windows::DebugEventDecoder::decode_exit_thread"}).to_string()))
    }
}

pub struct DebugWindowsDecodeCreateThreadTool;
impl DebugWindowsDecodeCreateThreadTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_decode_create_thread".to_string(),
            description: "Decode CREATE_THREAD_DEBUG_EVENT via rustre_debug_windows::DebugEventDecoder::decode_create_thread.".to_string(),
            input_schema: json!({"type":"object","required":["tid","pid"],"properties":{"tid":{"type":"integer"},"pid":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsDecodeCreateThreadTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let tid = args.get("tid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'tid'".into()))? as u32;
        let pid = args.get("pid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'pid'".into()))? as u32;
        let sr = rustre_debug_windows::DebugEventDecoder::decode_create_thread(rustre_debug::ThreadId(tid), rustre_debug::ProcessId(pid));
        Ok(ToolResult::text(json!({"stop_reason": format!("{sr:?}"),"source":"rustre_debug_windows::DebugEventDecoder::decode_create_thread"}).to_string()))
    }
}

pub struct DebugWindowsDecodeLoadDllTool;
impl DebugWindowsDecodeLoadDllTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_decode_load_dll".to_string(),
            description: "Decode LOAD_DLL_DEBUG_EVENT via rustre_debug_windows::DebugEventDecoder::decode_load_dll.".to_string(),
            input_schema: json!({"type":"object","required":["base","path","pid","tid"],"properties":{"base":{"type":"integer"},"path":{"type":"string"},"pid":{"type":"integer"},"tid":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsDecodeLoadDllTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let path = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?.to_string();
        let pid = args.get("pid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'pid'".into()))? as u32;
        let tid = args.get("tid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'tid'".into()))? as u32;
        let sr = rustre_debug_windows::DebugEventDecoder::decode_load_dll(base, path, rustre_debug::ProcessId(pid), rustre_debug::ThreadId(tid));
        Ok(ToolResult::text(json!({"stop_reason": format!("{sr:?}"),"source":"rustre_debug_windows::DebugEventDecoder::decode_load_dll"}).to_string()))
    }
}

pub struct DebugWindowsDecodeUnloadDllTool;
impl DebugWindowsDecodeUnloadDllTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_decode_unload_dll".to_string(),
            description: "Decode UNLOAD_DLL_DEBUG_EVENT via rustre_debug_windows::DebugEventDecoder::decode_unload_dll.".to_string(),
            input_schema: json!({"type":"object","required":["base","pid","tid"],"properties":{"base":{"type":"integer"},"pid":{"type":"integer"},"tid":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsDecodeUnloadDllTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let pid = args.get("pid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'pid'".into()))? as u32;
        let tid = args.get("tid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'tid'".into()))? as u32;
        let sr = rustre_debug_windows::DebugEventDecoder::decode_unload_dll(base, rustre_debug::ProcessId(pid), rustre_debug::ThreadId(tid));
        Ok(ToolResult::text(json!({"stop_reason": format!("{sr:?}"),"source":"rustre_debug_windows::DebugEventDecoder::decode_unload_dll"}).to_string()))
    }
}

pub struct DebugWindowsDecodeExceptionFullTool;
impl DebugWindowsDecodeExceptionFullTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_decode_exception_full".to_string(),
            description: "Decode EXCEPTION_DEBUG_EVENT via rustre_debug_windows::DebugEventDecoder::decode_exception.".to_string(),
            input_schema: json!({"type":"object","required":["code","address","is_first_chance","pid","tid"],"properties":{"code":{"type":"integer"},"address":{"type":"integer"},"is_first_chance":{"type":"boolean"},"pid":{"type":"integer"},"tid":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsDecodeExceptionFullTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let code = args.get("code").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'code'".into()))? as u32;
        let address = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?;
        let is_first_chance = args.get("is_first_chance").and_then(Value::as_bool).ok_or_else(|| McpError::InvalidParams("missing 'is_first_chance'".into()))?;
        let pid = args.get("pid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'pid'".into()))? as u32;
        let tid = args.get("tid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'tid'".into()))? as u32;
        let sr = rustre_debug_windows::DebugEventDecoder::decode_exception(code, address, is_first_chance, rustre_debug::ProcessId(pid), rustre_debug::ThreadId(tid));
        Ok(ToolResult::text(json!({"stop_reason": format!("{sr:?}"),"source":"rustre_debug_windows::DebugEventDecoder::decode_exception"}).to_string()))
    }
}

pub struct DebugWindowsWow64ContextDefaultTool;
impl DebugWindowsWow64ContextDefaultTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_wow64_context_default".to_string(),
            description: "Return a default-initialised rustre_debug_windows::Wow64Context.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsWow64ContextDefaultTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let ctx = rustre_debug_windows::Wow64Context::default();
        Ok(ToolResult::text(json!({
            "context_flags": ctx.context_flags,"eip": ctx.eip,"esp": ctx.esp,"ebp": ctx.ebp,
            "eax": ctx.eax,"ebx": ctx.ebx,"ecx": ctx.ecx,"edx": ctx.edx,
            "esi": ctx.esi,"edi": ctx.edi,"eflags": ctx.eflags,"trap_flag": ctx.trap_flag(),
            "source":"rustre_debug_windows::Wow64Context::default"
        }).to_string()))
    }
}

pub struct DebugWindowsWow64ContextToRegisterSetTool;
impl DebugWindowsWow64ContextToRegisterSetTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_wow64_context_to_register_set".to_string(),
            description: "Convert a Wow64Context to a RegisterSet via rustre_debug_windows::Wow64Context::to_register_set.".to_string(),
            input_schema: json!({"type":"object","properties":{"eax":{"type":"integer"},"ebx":{"type":"integer"},"ecx":{"type":"integer"},"edx":{"type":"integer"},"esi":{"type":"integer"},"edi":{"type":"integer"},"esp":{"type":"integer"},"ebp":{"type":"integer"},"eip":{"type":"integer"},"eflags":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsWow64ContextToRegisterSetTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let g = |k: &str| args.get(k).and_then(Value::as_u64).unwrap_or(0) as u32;
        let ctx = rustre_debug_windows::Wow64Context {
            context_flags: g("context_flags"),
            dr0: g("dr0"), dr1: g("dr1"), dr2: g("dr2"), dr3: g("dr3"), dr6: g("dr6"), dr7: g("dr7"),
            eax: g("eax"), ecx: g("ecx"), edx: g("edx"), ebx: g("ebx"),
            esp: g("esp"), ebp: g("ebp"), esi: g("esi"), edi: g("edi"),
            eip: g("eip"), eflags: g("eflags"),
        };
        let rs = ctx.to_register_set();
        Ok(ToolResult::text(json!({
            "pc": rs.pc,"sp": rs.sp,"fp": rs.fp,
            "eip": rs.get("eip"),"esp": rs.get("esp"),"ebp": rs.get("ebp"),
            "eax": rs.get("eax"),"eflags": rs.get("eflags"),
            "source":"rustre_debug_windows::Wow64Context::to_register_set"
        }).to_string()))
    }
}

pub struct DebugWindowsPageConstantsTool;
impl DebugWindowsPageConstantsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_windows_page_constants".to_string(),
            description: "Return PAGE_*, MEM_*, EXCEPTION_* constants from rustre_debug_windows.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugWindowsPageConstantsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_debug_windows as w;
        Ok(ToolResult::text(json!({
            "PAGE_NOACCESS": w::PAGE_NOACCESS,"PAGE_READONLY": w::PAGE_READONLY,
            "PAGE_READWRITE": w::PAGE_READWRITE,"PAGE_WRITECOPY": w::PAGE_WRITECOPY,
            "PAGE_EXECUTE": w::PAGE_EXECUTE,"PAGE_EXECUTE_READ": w::PAGE_EXECUTE_READ,
            "PAGE_EXECUTE_READWRITE": w::PAGE_EXECUTE_READWRITE,"PAGE_EXECUTE_WRITECOPY": w::PAGE_EXECUTE_WRITECOPY,
            "PAGE_GUARD": w::PAGE_GUARD,"MEM_COMMIT": w::MEM_COMMIT,"MEM_RESERVE": w::MEM_RESERVE,
            "MEM_FREE": w::MEM_FREE,"MEM_IMAGE": w::MEM_IMAGE,"MEM_MAPPED": w::MEM_MAPPED,"MEM_PRIVATE": w::MEM_PRIVATE,
            "EXCEPTION_ACCESS_VIOLATION": w::EXCEPTION_ACCESS_VIOLATION,"EXCEPTION_BREAKPOINT": w::EXCEPTION_BREAKPOINT,
            "EXCEPTION_SINGLE_STEP": w::EXCEPTION_SINGLE_STEP,"EXCEPTION_STACK_OVERFLOW": w::EXCEPTION_STACK_OVERFLOW,
            "EXCEPTION_INT_DIVIDE_BY_ZERO": w::EXCEPTION_INT_DIVIDE_BY_ZERO,
            "EXCEPTION_ILLEGAL_INSTRUCTION": w::EXCEPTION_ILLEGAL_INSTRUCTION,
            "EXCEPTION_GUARD_PAGE": w::EXCEPTION_GUARD_PAGE,
            "source":"rustre_debug_windows constants"
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DebugWindowsIsCommittedTool::definition(), Box::new(DebugWindowsIsCommittedTool)),
        (DebugWindowsExceptionNameTool::definition(), Box::new(DebugWindowsExceptionNameTool)),
        (DebugWindowsStatusNameTool::definition(), Box::new(DebugWindowsStatusNameTool)),
        (DebugWindowsIsContinuableTool::definition(), Box::new(DebugWindowsIsContinuableTool)),
        (DebugWindowsIsBreakpointLikeTool::definition(), Box::new(DebugWindowsIsBreakpointLikeTool)),
        (DebugWindowsClassifyExceptionTool::definition(), Box::new(DebugWindowsClassifyExceptionTool)),
        (DebugWindowsHwBpConditionDr7Tool::definition(), Box::new(DebugWindowsHwBpConditionDr7Tool)),
        (DebugWindowsHwBpSizeDr7Tool::definition(), Box::new(DebugWindowsHwBpSizeDr7Tool)),
        (DebugWindowsWow64TrapFlagTool::definition(), Box::new(DebugWindowsWow64TrapFlagTool)),
        (DebugWindowsWow64SetTrapFlagTool::definition(), Box::new(DebugWindowsWow64SetTrapFlagTool)),
        (DebugWindowsProtectNameTool::definition(), Box::new(DebugWindowsProtectNameTool)),
        (DebugWindowsRegionPermsTool::definition(), Box::new(DebugWindowsRegionPermsTool)),
        (DebugWindowsMemoryRegionToMapTool::definition(), Box::new(DebugWindowsMemoryRegionToMapTool)),
        (DebugWindowsDecodeExitProcessTool::definition(), Box::new(DebugWindowsDecodeExitProcessTool)),
        (DebugWindowsDecodeExitThreadTool::definition(), Box::new(DebugWindowsDecodeExitThreadTool)),
        (DebugWindowsDecodeCreateThreadTool::definition(), Box::new(DebugWindowsDecodeCreateThreadTool)),
        (DebugWindowsDecodeLoadDllTool::definition(), Box::new(DebugWindowsDecodeLoadDllTool)),
        (DebugWindowsDecodeUnloadDllTool::definition(), Box::new(DebugWindowsDecodeUnloadDllTool)),
        (DebugWindowsDecodeExceptionFullTool::definition(), Box::new(DebugWindowsDecodeExceptionFullTool)),
        (DebugWindowsWow64ContextDefaultTool::definition(), Box::new(DebugWindowsWow64ContextDefaultTool)),
        (DebugWindowsWow64ContextToRegisterSetTool::definition(), Box::new(DebugWindowsWow64ContextToRegisterSetTool)),
        (DebugWindowsPageConstantsTool::definition(), Box::new(DebugWindowsPageConstantsTool)),
    ]
}
