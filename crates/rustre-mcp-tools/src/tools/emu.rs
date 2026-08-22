//! MCP wrappers for the rustre-emu crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes, hex_encode};
use crate::wire_tools::{emu_base_arg_arch, parse_emu_arch_extra};

#[cfg(any())] pub struct EmuQilingLinuxX8664Tool;

#[cfg(any())] pub struct EmuQilingShellcodeRunnerTool;

pub struct EmuLibraryStubIsStubbedTool;

pub struct EmuLibraryStubModuleTool;

pub struct EmuBackendsRegistryFindTool;

pub struct EmuMemProviderFindTool;

pub struct EmuOsLinuxSyscallGroupTool;

pub struct EmuArchPointerSizeTool;

pub struct EmuArchNameTool;

#[cfg(any())] pub struct EmuQilingRootfsExistsTool;

#[cfg(any())] pub struct EmuQilingProcessEnvNewLinux64Tool;

pub struct EmuArchPointerSizeWireTool;

pub struct EmuArchNameWireTool;

#[cfg(any())] pub struct EmuQilingElfLoaderStubIsElfTool;

#[cfg(any())] pub struct EmuQilingRootfsPathHostPathTool;

#[cfg(any())] pub struct EmuQilingOsTargetNameTool;
#[cfg(any())] impl EmuQilingOsTargetNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_os_target_name".to_string(),
            description: "OsTarget::name.".to_string(),
            input_schema: json!({"type": "object", "properties": {"os": {"type": "string"}}, "required": ["os"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingOsTargetNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let os = args.get("os").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'os'".into()))?;
        let t = match os.to_lowercase().as_str() {
            "linux" => rustre_emu_qiling::OsTarget::Linux,
            "windows" => rustre_emu_qiling::OsTarget::Windows,
            "macos" => rustre_emu_qiling::OsTarget::MacOs,
            "freebsd" => rustre_emu_qiling::OsTarget::FreeBsd,
            "baremetal" => rustre_emu_qiling::OsTarget::BareMetal,
            other => return Err(McpError::InvalidParams(format!("unknown os '{other}'"))),
        };
        Ok(ToolResult::text(json!({"name": t.name(), "source": "rustre_emu_qiling::OsTarget::name"}).to_string()))
    }
}

#[cfg(any())] pub struct EmuQilingSyscallResultRetvalTool;
#[cfg(any())] impl EmuQilingSyscallResultRetvalTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_syscall_result_retval".to_string(),
            description: "SyscallResult::retval.".to_string(),
            input_schema: json!({"type": "object", "properties": {"kind": {"type": "string"}, "value": {"type": "integer"}}, "required": ["kind"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingSyscallResultRetvalTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let kind = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let r = match kind {
            "ok" => rustre_emu_qiling::SyscallResult::Ok(args.get("value").and_then(Value::as_i64).unwrap_or(0)),
            "not_implemented" => rustre_emu_qiling::SyscallResult::NotImplemented,
            "fatal" => rustre_emu_qiling::SyscallResult::Fatal("fatal".into()),
            other => return Err(McpError::InvalidParams(format!("unknown kind '{other}'"))),
        };
        Ok(ToolResult::text(json!({"retval": r.retval(), "source": "rustre_emu_qiling::SyscallResult::retval"}).to_string()))
    }
}

#[cfg(any())] pub struct EmuQilingProcessEnvGetenvTool;
#[cfg(any())] impl EmuQilingProcessEnvGetenvTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_process_env_getenv".to_string(),
            description: "ProcessEnv::getenv on new_linux64.".to_string(),
            input_schema: json!({"type": "object", "properties": {"key": {"type": "string"}}, "required": ["key"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingProcessEnvGetenvTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let key = args.get("key").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'key'".into()))?;
        let env = rustre_emu_qiling::ProcessEnv::new_linux64(vec!["guest".into()]);
        let val = env.getenv(key).map(String::from);
        let found = val.is_some();
        Ok(ToolResult::text(json!({"key": key, "value": val, "found": found, "source": "rustre_emu_qiling::ProcessEnv::getenv"}).to_string()))
    }
}

#[cfg(any())] pub struct EmuQilingProcessEnvSetenvTool;
#[cfg(any())] impl EmuQilingProcessEnvSetenvTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_process_env_setenv".to_string(),
            description: "ProcessEnv::setenv returning new envp.".to_string(),
            input_schema: json!({"type": "object", "properties": {"key": {"type": "string"}, "value": {"type": "string"}}, "required": ["key", "value"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingProcessEnvSetenvTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let key = args.get("key").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'key'".into()))?;
        let val = args.get("value").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let mut env = rustre_emu_qiling::ProcessEnv::new_linux64(vec!["guest".into()]);
        env.setenv(key, val);
        Ok(ToolResult::text(json!({"envp": env.envp, "source": "rustre_emu_qiling::ProcessEnv::setenv"}).to_string()))
    }
}

#[cfg(any())] pub struct EmuQilingFdTableNewTool;
#[cfg(any())] impl EmuQilingFdTableNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_fd_table_new".to_string(),
            description: "FdTable::new state.".to_string(),
            input_schema: json!({"type": "object", "properties": {}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingFdTableNewTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let t = rustre_emu_qiling::FdTable::new();
        Ok(ToolResult::text(json!({"len": t.len(), "is_empty": t.is_empty(), "open_fds": t.open_fds(), "source": "rustre_emu_qiling::FdTable::new"}).to_string()))
    }
}

#[cfg(any())] pub struct EmuQilingFdTableOpenCloseTool;
#[cfg(any())] impl EmuQilingFdTableOpenCloseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_fd_table_open_close".to_string(),
            description: "Open GuestFile in FdTable.".to_string(),
            input_schema: json!({"type": "object", "properties": {"guest_path": {"type": "string"}, "host_path": {"type": "string"}, "readable": {"type": "boolean"}, "writable": {"type": "boolean"}, "close_after": {"type": "boolean"}}, "required": ["guest_path", "host_path"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingFdTableOpenCloseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let gp = args.get("guest_path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'guest_path'".into()))?;
        let hp = args.get("host_path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'host_path'".into()))?;
        let r = args.get("readable").and_then(Value::as_bool).unwrap_or(true);
        let w = args.get("writable").and_then(Value::as_bool).unwrap_or(false);
        let close = args.get("close_after").and_then(Value::as_bool).unwrap_or(false);
        let mut t = rustre_emu_qiling::FdTable::new();
        let file = rustre_emu_qiling::GuestFile::new(0, gp, hp, r, w);
        let fd = t.open(file);
        let closed = if close { t.close(fd) } else { false };
        Ok(ToolResult::text(json!({"fd": fd, "closed": closed, "len_after": t.len(), "open_fds_after": t.open_fds(), "source": "rustre_emu_qiling::FdTable::{open,close}"}).to_string()))
    }
}

#[cfg(any())] pub struct EmuQilingGuestFileRwTool;
#[cfg(any())] impl EmuQilingGuestFileRwTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_guest_file_rw".to_string(),
            description: "GuestFile write/read round-trip.".to_string(),
            input_schema: json!({"type": "object", "properties": {"hex_data": {"type": "string"}, "read_len": {"type": "integer"}}, "required": ["hex_data"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingGuestFileRwTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("hex_data").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex_data'".into()))?;
        let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        if clean.len() % 2 != 0 { return Err(McpError::InvalidParams("hex length must be even".into())); }
        let mut data = Vec::with_capacity(clean.len() / 2);
        for i in (0..clean.len()).step_by(2) {
            data.push(u8::from_str_radix(&clean[i..i+2], 16).map_err(|e| McpError::InvalidParams(format!("bad hex: {e}")))?);
        }
        let read_len = args.get("read_len").and_then(Value::as_u64).map(|n| n as usize).unwrap_or(data.len());
        let mut f = rustre_emu_qiling::GuestFile::new(10, "/g", "/h", true, true);
        f.write(&data);
        f.offset = 0;
        let read_bytes = f.read(read_len);
        let read_len_out = read_bytes.len();
        Ok(ToolResult::text(json!({"written": data.len(), "read": read_bytes, "read_len": read_len_out, "is_eof": f.is_eof(), "remaining": f.remaining(), "source": "rustre_emu_qiling::GuestFile"}).to_string()))
    }
}

#[cfg(any())] pub struct EmuQilingRootfsRootTool;
#[cfg(any())] impl EmuQilingRootfsRootTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_rootfs_root".to_string(),
            description: "RootfsPath::root.".to_string(),
            input_schema: json!({"type": "object", "properties": {"root": {"type": "string"}}, "required": ["root"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingRootfsRootTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let root = args.get("root").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'root'".into()))?;
        let r = rustre_emu_qiling::RootfsPath::new(root);
        Ok(ToolResult::text(json!({"root": r.root().display().to_string(), "source": "rustre_emu_qiling::RootfsPath::root"}).to_string()))
    }
}

pub struct EmuMemRegionInspectTool;
impl EmuMemRegionInspectTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_mem_region_inspect".to_string(),
            description: "Compute end() and contains() for a rustre_emu::MemRegion.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "start":{"type":"integer"},"size":{"type":"integer"},"query_addr":{"type":"integer"}
            },"required":["start","size"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuMemRegionInspectTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let start = args.get("start").and_then(Value::as_u64).unwrap_or(0);
        let size = args.get("size").and_then(Value::as_u64).unwrap_or(0) as usize;
        let q = args.get("query_addr").and_then(Value::as_u64).unwrap_or(start);
        let r = rustre_emu::MemRegion::new(start, size, rustre_emu::MemPerms::RW);
        Ok(ToolResult::text(json!({
            "start": r.start, "size": r.size, "end": r.end(),
            "contains": r.contains(q),
            "source":"rustre_emu::MemRegion",
        }).to_string()))
    }
}

pub struct EmuRegistryNamesTool;
impl EmuRegistryNamesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_registry_names".to_string(),
            description: "List backend names in a fresh rustre_emu::EmulatorRegistry.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuRegistryNamesTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let reg = rustre_emu::EmulatorRegistry::new();
        let names: Vec<String> = reg.names().into_iter().map(str::to_string).collect();
        Ok(ToolResult::text(json!({
            "count": names.len(), "names": names,
            "source":"rustre_emu::EmulatorRegistry::names",
        }).to_string()))
    }
}

pub struct EmuCoverageMapSummaryTool;
impl EmuCoverageMapSummaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_coverage_map_summary".to_string(),
            description: "Feed hit addresses into rustre_emu::CoverageMap; report unique/covered/singletons.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "addresses":{"type":"array","items":{"type":"integer"}}
            },"required":["addresses"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuCoverageMapSummaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addrs: Vec<u64> = args.get("addresses").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
        let mut m = rustre_emu::CoverageMap::new();
        for a in &addrs { m.record(*a); }
        Ok(ToolResult::text(json!({
            "unique_count": m.unique_count(),
            "covered": m.covered_addresses(),
            "singletons": m.singleton_addresses(),
            "source":"rustre_emu::CoverageMap",
        }).to_string()))
    }
}

pub struct EmuCoverageTrackerPctTool;
impl EmuCoverageTrackerPctTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_coverage_tracker_pct".to_string(),
            description: "Compute rustre_emu::EmuCoverageTracker::coverage_pct in [start,end).".to_string(),
            input_schema: json!({"type":"object","properties":{
                "visited":{"type":"array","items":{"type":"integer"}},
                "start":{"type":"integer"},"end":{"type":"integer"}
            },"required":["visited","start","end"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuCoverageTrackerPctTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addrs: Vec<u64> = args.get("visited").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
        let start = args.get("start").and_then(Value::as_u64).unwrap_or(0);
        let end = args.get("end").and_then(Value::as_u64).unwrap_or(0);
        let mut t = rustre_emu::EmuCoverageTracker::new();
        for a in &addrs { t.record(*a); }
        Ok(ToolResult::text(json!({
            "unique_count": t.unique_count(),
            "coverage_pct": t.coverage_pct(start, end),
            "visited_sorted": t.visited_sorted(),
            "source":"rustre_emu::EmuCoverageTracker::coverage_pct",
        }).to_string()))
    }
}

pub struct EmuStatsAggregateTool;
impl EmuStatsAggregateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_stats_aggregate".to_string(),
            description: "Populate rustre_emu::EmuStats; return ipc() and branch_ratio().".to_string(),
            input_schema: json!({"type":"object","properties":{
                "insns_executed":{"type":"integer"},
                "mem_reads":{"type":"integer"},"mem_writes":{"type":"integer"},
                "branches_taken":{"type":"integer"},"branches_not_taken":{"type":"integer"}
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuStatsAggregateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut s = rustre_emu::EmuStats::default();
        s.insns_executed = args.get("insns_executed").and_then(Value::as_u64).unwrap_or(0);
        s.mem_reads = args.get("mem_reads").and_then(Value::as_u64).unwrap_or(0);
        s.mem_writes = args.get("mem_writes").and_then(Value::as_u64).unwrap_or(0);
        s.branches_taken = args.get("branches_taken").and_then(Value::as_u64).unwrap_or(0);
        s.branches_not_taken = args.get("branches_not_taken").and_then(Value::as_u64).unwrap_or(0);
        Ok(ToolResult::text(json!({
            "ipc": s.ipc(),
            "branch_ratio": s.branch_ratio(),
            "source":"rustre_emu::EmuStats",
        }).to_string()))
    }
}

pub struct EmuInterpreterMemRoundtripTool;
impl EmuInterpreterMemRoundtripTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_interpreter_mem_roundtrip".to_string(),
            description: "Map a RW region in rustre_emu::SimpleInterpreter, write bytes, read them back.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "arch":{"type":"string"},
                "base":{"type":"integer"},"size":{"type":"integer"},
                "offset":{"type":"integer"},"hex":{"type":"string"}
            },"required":["base","size","hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuInterpreterMemRoundtripTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_emu::Emulator;
        let arch = parse_emu_arch_extra(args.get("arch").and_then(Value::as_str).unwrap_or("x86-64"));
        let base = args.get("base").and_then(Value::as_u64).unwrap_or(0x1000);
        let size = args.get("size").and_then(Value::as_u64).unwrap_or(0x1000) as usize;
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let hex = args.get("hex").and_then(Value::as_str).unwrap_or("");
        let bytes = args_to_bytes(&json!({"hex": hex}))?;
        let mut emu = rustre_emu::SimpleInterpreter::new(arch);
        emu.map_memory(base, size, rustre_emu::MemPerms::RW)
            .map_err(|e| McpError::ToolError(e.to_string()))?;
        emu.write_memory(base + offset, &bytes)
            .map_err(|e| McpError::ToolError(e.to_string()))?;
        let read = emu.read_memory(base + offset, bytes.len())
            .map_err(|e| McpError::ToolError(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "arch": arch.name(),
            "written_len": bytes.len(),
            "read_hex": hex_encode(&read),
            "match": read == bytes,
            "regions": emu.regions().len(),
            "source":"rustre_emu::SimpleInterpreter",
        }).to_string()))
    }
}

pub struct EmuMemRegionBatchCheckTool;
impl EmuMemRegionBatchCheckTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_mem_region_batch_check".to_string(),
            description: "Given a list of {start,size} MemRegions and an addr, report which contains it.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "regions":{"type":"array","items":{"type":"object","properties":{
                    "start":{"type":"integer"},"size":{"type":"integer"}
                }}},
                "addr":{"type":"integer"}
            },"required":["regions","addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuMemRegionBatchCheckTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0);
        let mut idx: Option<usize> = None;
        let mut summary = Vec::new();
        if let Some(arr) = args.get("regions").and_then(Value::as_array) {
            for (i, v) in arr.iter().enumerate() {
                let s = v.get("start").and_then(Value::as_u64).unwrap_or(0);
                let sz = v.get("size").and_then(Value::as_u64).unwrap_or(0) as usize;
                let r = rustre_emu::MemRegion::new(s, sz, rustre_emu::MemPerms::R);
                if r.contains(addr) && idx.is_none() { idx = Some(i); }
                summary.push(json!({"start": r.start, "end": r.end(), "contains": r.contains(addr)}));
            }
        }
        Ok(ToolResult::text(json!({
            "addr": addr, "match_index": idx, "regions": summary,
            "source":"rustre_emu::MemRegion::contains",
        }).to_string()))
    }
}

pub struct EmuBaseArchIs64BitTool;
impl EmuBaseArchIs64BitTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_base_arch_is_64bit".into(),
            description: "Return whether the emulator arch is 64-bit.".into(),
            input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}},"required":["arch"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuBaseArchIs64BitTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = emu_base_arg_arch(&args)?;
        Ok(ToolResult::text(json!({"is_64bit": a.is_64bit(),"name": a.name(),
            "source":"rustre_emu::EmulatorArch::is_64bit"}).to_string()))
    }
}

pub struct EmuBaseArchIsX86Tool;
impl EmuBaseArchIsX86Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_base_arch_is_x86".into(),
            description: "Return whether the emulator arch is any x86 flavour.".into(),
            input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}},"required":["arch"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuBaseArchIsX86Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = emu_base_arg_arch(&args)?;
        Ok(ToolResult::text(json!({"is_x86": a.is_x86(),
            "source":"rustre_emu::EmulatorArch::is_x86"}).to_string()))
    }
}

pub struct EmuBaseMemRegionInfoTool;
impl EmuBaseMemRegionInfoTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_base_mem_region_info".into(),
            description: "Compute end/contains for a MemRegion (start,size) at addr.".into(),
            input_schema: json!({"type":"object","properties":{
                "start":{"type":"integer"},"size":{"type":"integer"},"addr":{"type":"integer"}},
                "required":["start","size","addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuBaseMemRegionInfoTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let start = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("start".into()))?;
        let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("size".into()))? as usize;
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("addr".into()))?;
        let r = rustre_emu::MemRegion::new(start, size, rustre_emu::MemPerms::RW);
        Ok(ToolResult::text(json!({"end": r.end(),"contains": r.contains(addr),
            "source":"rustre_emu::MemRegion"}).to_string()))
    }
}

pub struct EmuBaseStatsIpcTool;
impl EmuBaseStatsIpcTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_base_stats_ipc".into(),
            description: "Compute IPC and branch ratio from EmuStats counters.".into(),
            input_schema: json!({"type":"object","properties":{
                "insns_executed":{"type":"integer"},"mem_reads":{"type":"integer"},"mem_writes":{"type":"integer"},
                "branches_taken":{"type":"integer"},"branches_not_taken":{"type":"integer"}},
                "required":["insns_executed","mem_reads","mem_writes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuBaseStatsIpcTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut s = rustre_emu::EmuStats::default();
        s.insns_executed = args.get("insns_executed").and_then(Value::as_u64).unwrap_or(0);
        s.mem_reads = args.get("mem_reads").and_then(Value::as_u64).unwrap_or(0);
        s.mem_writes = args.get("mem_writes").and_then(Value::as_u64).unwrap_or(0);
        s.branches_taken = args.get("branches_taken").and_then(Value::as_u64).unwrap_or(0);
        s.branches_not_taken = args.get("branches_not_taken").and_then(Value::as_u64).unwrap_or(0);
        Ok(ToolResult::text(json!({"ipc": s.ipc(),"branch_ratio": s.branch_ratio(),
            "source":"rustre_emu::EmuStats"}).to_string()))
    }
}

pub struct EmuBaseCoverageMapSummaryTool;
impl EmuBaseCoverageMapSummaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_base_coverage_map_summary".into(),
            description: "Build a CoverageMap from addresses and summarise unique/singletons.".into(),
            input_schema: json!({"type":"object","properties":{
                "addresses":{"type":"array","items":{"type":"integer"}}},
                "required":["addresses"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuBaseCoverageMapSummaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addrs = args.get("addresses").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("addresses".into()))?;
        let mut cov = rustre_emu::CoverageMap::new();
        for a in addrs { if let Some(v) = a.as_u64() { cov.record(v); } }
        Ok(ToolResult::text(json!({
            "unique_count": cov.unique_count(),
            "covered": cov.covered_addresses(),
            "singletons": cov.singleton_addresses(),
            "source":"rustre_emu::CoverageMap"
        }).to_string()))
    }
}

pub struct EmuBaseCoverageTrackerPctTool;
impl EmuBaseCoverageTrackerPctTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_base_coverage_tracker_pct".into(),
            description: "Compute coverage percent over [start,end) given visited addresses.".into(),
            input_schema: json!({"type":"object","properties":{
                "visited":{"type":"array","items":{"type":"integer"}},
                "start":{"type":"integer"},"end":{"type":"integer"}},
                "required":["visited","start","end"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuBaseCoverageTrackerPctTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addrs = args.get("visited").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("visited".into()))?;
        let start = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("start".into()))?;
        let end = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("end".into()))?;
        let mut t = rustre_emu::EmuCoverageTracker::new();
        for a in addrs { if let Some(v) = a.as_u64() { t.record(v); } }
        Ok(ToolResult::text(json!({
            "unique_count": t.unique_count(),
            "coverage_pct": t.coverage_pct(start, end),
            "visited_sorted": t.visited_sorted(),
            "source":"rustre_emu::EmuCoverageTracker"
        }).to_string()))
    }
}

pub struct EmuBaseTraceSummaryTool;
impl EmuBaseTraceSummaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_base_trace_summary".into(),
            description: "Build a Trace from PCs and return len/unique_pcs/is_empty.".into(),
            input_schema: json!({"type":"object","properties":{
                "pcs":{"type":"array","items":{"type":"integer"}}},
                "required":["pcs"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuBaseTraceSummaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pcs = args.get("pcs").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("pcs".into()))?;
        let mut t = rustre_emu::Trace::new();
        for p in pcs {
            if let Some(pc) = p.as_u64() {
                t.push(rustre_emu::TraceEntry{ pc, size: 1, bytes: vec![], disasm: String::new() });
            }
        }
        let mut uniq: Vec<u64> = t.unique_pcs().into_iter().collect();
        uniq.sort_unstable();
        Ok(ToolResult::text(json!({
            "len": t.len(),"is_empty": t.is_empty(),"unique_pcs": uniq,
            "source":"rustre_emu::Trace"
        }).to_string()))
    }
}

pub struct EmuBaseRegistersRoundTripTool;
impl EmuBaseRegistersRoundTripTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_base_registers_round_trip".into(),
            description: "Run a SimpleInterpreter register write/read round-trip.".into(),
            input_schema: json!({"type":"object","properties":{
                "arch":{"type":"string"},"reg":{"type":"integer"},"value":{"type":"integer"}},
                "required":["arch","reg","value"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuBaseRegistersRoundTripTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_emu::Emulator;
        let arch = emu_base_arg_arch(&args)?;
        let reg = args.get("reg").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("reg".into()))? as u32;
        let value = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("value".into()))?;
        let mut emu = rustre_emu::SimpleInterpreter::new(arch);
        emu.write_register(reg, value).map_err(|e| McpError::InternalError(e.to_string()))?;
        let got = emu.read_register(reg).map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "arch": arch.name(),"reg": reg,"written": value,"read_back": got,"match": got == value,
            "source":"rustre_emu::SimpleInterpreter"
        }).to_string()))
    }
}

pub struct EmuBaseFactoryCreateTool;
impl EmuBaseFactoryCreateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_base_factory_create".into(),
            description: "Create an EmulatorFactory instance and report arch metadata.".into(),
            input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}},"required":["arch"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuBaseFactoryCreateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arch = emu_base_arg_arch(&args)?;
        let emu = rustre_emu::EmulatorFactory::create(arch);
        Ok(ToolResult::text(json!({
            "arch": emu.arch().name(),
            "pointer_size": emu.arch().pointer_size(),
            "region_count": emu.regions().len(),
            "source":"rustre_emu::EmulatorFactory::create"
        }).to_string()))
    }
}

pub struct EmuBaseRegistrySizeTool;
impl EmuBaseRegistrySizeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_base_registry_size".into(),
            description: "Count backends in a fresh EmulatorRegistry.".into(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuBaseRegistrySizeTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let r = rustre_emu::EmulatorRegistry::new();
        Ok(ToolResult::text(json!({
            "backend_count": r.names().len(),
            "names": r.names(),
            "source":"rustre_emu::EmulatorRegistry"
        }).to_string()))
    }
}

pub struct EmuBaseMemPermsFlagsTool;
impl EmuBaseMemPermsFlagsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_base_mem_perms_flags".into(),
            description: "Decode a MemPerms bitmask into READ/WRITE/EXEC booleans.".into(),
            input_schema: json!({"type":"object","properties":{"bits":{"type":"integer"}},"required":["bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuBaseMemPermsFlagsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bits = args.get("bits").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("bits".into()))? as u32;
        let p = rustre_emu::MemPerms::from_bits_truncate(bits);
        Ok(ToolResult::text(json!({
            "read": p.contains(rustre_emu::MemPerms::READ),
            "write": p.contains(rustre_emu::MemPerms::WRITE),
            "exec": p.contains(rustre_emu::MemPerms::EXEC),
            "bits": p.bits(),
            "source":"rustre_emu::MemPerms"
        }).to_string()))
    }
}

#[cfg(any())] pub struct EmuQilingOsTargetDisplayAllTool;
#[cfg(any())] impl EmuQilingOsTargetDisplayAllTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_qiling_os_target_display_all".to_string(), description: "List OsTarget::to_string() for all variants.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingOsTargetDisplayAllTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_emu_qiling::OsTarget; let all = [OsTarget::Linux, OsTarget::Windows, OsTarget::MacOs, OsTarget::FreeBsd, OsTarget::BareMetal]; let vals: Vec<String> = all.iter().map(|o| o.to_string()).collect(); Ok(ToolResult::text(json!({"display": vals, "source": "rustre_emu_qiling::OsTarget::fmt"}).to_string())) } }

#[cfg(any())] pub struct EmuQilingFdTableIsEmptyTool;
#[cfg(any())] impl EmuQilingFdTableIsEmptyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_qiling_fd_table_is_empty".to_string(), description: "FdTable::is_empty() and len() on a fresh table.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingFdTableIsEmptyTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let t = rustre_emu_qiling::FdTable::new(); Ok(ToolResult::text(json!({"is_empty": t.is_empty(), "len": t.len(), "source": "rustre_emu_qiling::FdTable::is_empty"}).to_string())) } }

#[cfg(any())] pub struct EmuQilingSyscallTableEmptyTool;
#[cfg(any())] impl EmuQilingSyscallTableEmptyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_qiling_syscall_table_empty".to_string(), description: "Build an empty SyscallTable and report is_empty/len/os.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingSyscallTableEmptyTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_emu_qiling::{SyscallTable, OsTarget}; use rustre_emu::EmulatorArch; let t = SyscallTable::new(OsTarget::Windows, EmulatorArch::X86_64); Ok(ToolResult::text(json!({"is_empty": t.is_empty(), "len": t.len(), "os": t.os().to_string(), "source": "rustre_emu_qiling::SyscallTable::new"}).to_string())) } }

#[cfg(any())] pub struct EmuQilingEmulatorStateNewX8664Tool;
#[cfg(any())] impl EmuQilingEmulatorStateNewX8664Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_qiling_emulator_state_new_x86_64".to_string(), description: "Create an x86-64 EmulatorState and list register names.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingEmulatorStateNewX8664Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let s = rustre_emu_qiling::EmulatorState::new_x86_64(); let mut names: Vec<String> = s.regs.keys().cloned().collect(); names.sort(); Ok(ToolResult::text(json!({"count": names.len(), "names": names, "source": "rustre_emu_qiling::EmulatorState::new_x86_64"}).to_string())) } }

#[cfg(any())] pub struct EmuQilingEmulatorStateMemU64RoundtripTool;
#[cfg(any())] impl EmuQilingEmulatorStateMemU64RoundtripTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_qiling_emulator_state_mem_u64_roundtrip".to_string(), description: "Write then read a u64 via EmulatorState.".to_string(), input_schema: json!({"type":"object","required":["addr","val"],"properties":{"addr":{"type":"integer"},"val":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingEmulatorStateMemU64RoundtripTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("addr".into()))?; let val = args.get("val").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("val".into()))?; let mut s = rustre_emu_qiling::EmulatorState::new(); s.write_mem_u64(addr, val); let got = s.read_mem_u64(addr); Ok(ToolResult::text(json!({"addr": addr, "wrote": val, "read": got, "match": got == val, "source": "rustre_emu_qiling::EmulatorState::write_mem_u64"}).to_string())) } }

#[cfg(any())] pub struct EmuQilingEmulatorStateMemU32RoundtripTool;
#[cfg(any())] impl EmuQilingEmulatorStateMemU32RoundtripTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_qiling_emulator_state_mem_u32_roundtrip".to_string(), description: "Write then read a u32 via EmulatorState.".to_string(), input_schema: json!({"type":"object","required":["addr","val"],"properties":{"addr":{"type":"integer"},"val":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingEmulatorStateMemU32RoundtripTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("addr".into()))?; let val = args.get("val").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("val".into()))? as u32; let mut s = rustre_emu_qiling::EmulatorState::new(); s.write_mem_u32(addr, val); let got = s.read_mem_u32(addr); Ok(ToolResult::text(json!({"addr": addr, "wrote": val, "read": got, "match": got == val, "source": "rustre_emu_qiling::EmulatorState::write_mem_u32"}).to_string())) } }

#[cfg(any())] pub struct EmuQilingEmulatorStateCstringRoundtripTool;
#[cfg(any())] impl EmuQilingEmulatorStateCstringRoundtripTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_qiling_emulator_state_cstring_roundtrip".to_string(), description: "Write and read back a C string via EmulatorState.".to_string(), input_schema: json!({"type":"object","required":["addr","s"],"properties":{"addr":{"type":"integer"},"s":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingEmulatorStateCstringRoundtripTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("addr".into()))?; let s = args.get("s").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("s".into()))?; let mut st = rustre_emu_qiling::EmulatorState::new(); st.write_cstring(addr, s); let got = st.read_cstring(addr, s.len() + 16); Ok(ToolResult::text(json!({"addr": addr, "wrote": s, "read": got, "match": got == s, "source": "rustre_emu_qiling::EmulatorState::write_cstring"}).to_string())) } }

#[cfg(any())] pub struct EmuQilingEmulatorStateReadBytesTool;
#[cfg(any())] impl EmuQilingEmulatorStateReadBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_qiling_emulator_state_read_bytes".to_string(), description: "Write hex bytes then read them back via EmulatorState.".to_string(), input_schema: json!({"type":"object","required":["addr","hex"],"properties":{"addr":{"type":"integer"},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingEmulatorStateReadBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("addr".into()))?; let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("hex".into()))?; let data = args_to_bytes(&json!({"hex": hex}))?; let mut st = rustre_emu_qiling::EmulatorState::new(); st.write_mem_bytes(addr, &data); let got = st.read_mem_bytes(addr, data.len()); Ok(ToolResult::text(json!({"addr": addr, "len": data.len(), "match": got == data, "source": "rustre_emu_qiling::EmulatorState::read_mem_bytes"}).to_string())) } }

#[cfg(any())] pub struct EmuQilingClosureSyscallTableLinuxLenTool;
#[cfg(any())] impl EmuQilingClosureSyscallTableLinuxLenTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_qiling_closure_syscall_table_linux_len".to_string(), description: "Build Linux ClosureSyscallTable and report handler count.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingClosureSyscallTableLinuxLenTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let t = rustre_emu_qiling::ClosureSyscallTable::new_linux(); Ok(ToolResult::text(json!({"len": t.len(), "is_empty": t.is_empty(), "os": t.os().to_string(), "source": "rustre_emu_qiling::ClosureSyscallTable::new_linux"}).to_string())) } }

#[cfg(any())] pub struct EmuQilingClosureSyscallTableWindowsLenTool;
#[cfg(any())] impl EmuQilingClosureSyscallTableWindowsLenTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_qiling_closure_syscall_table_windows_len".to_string(), description: "Build Windows ClosureSyscallTable and report handler count.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingClosureSyscallTableWindowsLenTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let t = rustre_emu_qiling::ClosureSyscallTable::new_windows(); Ok(ToolResult::text(json!({"len": t.len(), "is_empty": t.is_empty(), "os": t.os().to_string(), "source": "rustre_emu_qiling::ClosureSyscallTable::new_windows"}).to_string())) } }

#[cfg(any())] pub struct EmuQilingClosureSyscallDispatchExitTool;
#[cfg(any())] impl EmuQilingClosureSyscallDispatchExitTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_qiling_closure_syscall_dispatch_exit".to_string(), description: "Dispatch Linux exit (60) through ClosureSyscallTable.".to_string(), input_schema: json!({"type":"object","required":["code"],"properties":{"code":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingClosureSyscallDispatchExitTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let code = args.get("code").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("code".into()))?; let t = rustre_emu_qiling::ClosureSyscallTable::new_linux(); let mut st = rustre_emu_qiling::EmulatorState::new(); let ret = t.dispatch(60, &mut st, [code, 0, 0, 0, 0, 0]); Ok(ToolResult::text(json!({"ret": ret, "recorded_exit": st.get_reg("__exit_code"), "source": "rustre_emu_qiling::ClosureSyscallTable::dispatch"}).to_string())) } }

#[cfg(any())] pub struct EmuQilingErrnoConstantsTool;
#[cfg(any())] impl EmuQilingErrnoConstantsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_qiling_errno_constants".to_string(), description: "Return selected Linux errno constants from rustre_emu_qiling::errno.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingErrnoConstantsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_emu_qiling::errno; Ok(ToolResult::text(json!({"EPERM": errno::EPERM, "ENOENT": errno::ENOENT, "EBADF": errno::EBADF, "EACCES": errno::EACCES, "EINVAL": errno::EINVAL, "ENOSYS": errno::ENOSYS, "ECONNREFUSED": errno::ECONNREFUSED, "source": "rustre_emu_qiling::errno"}).to_string())) } }

#[cfg(any())] pub struct EmuQilingGuestFileIsEofTool;
#[cfg(any())] impl EmuQilingGuestFileIsEofTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_guest_file_is_eof".to_string(),
            description: "Create a GuestFile with the given content and offset, then report is_eof() and remaining().".to_string(),
            input_schema: json!({"type":"object","required":["content_hex","offset"],"properties":{"content_hex":{"type":"string"},"offset":{"type":"integer","minimum":0}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingGuestFileIsEofTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("content_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing content_hex".into()))?;
        let off = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing offset".into()))?;
        let bytes = args_to_bytes(&json!({"hex": hex}))?;
        let mut gf = rustre_emu_qiling::GuestFile::new(10, "/g", "/h", true, true);
        gf.content = bytes;
        gf.offset = off;
        Ok(ToolResult::text(json!({
            "is_eof": gf.is_eof(),
            "remaining": gf.remaining(),
            "content_len": gf.content.len(),
            "source": "rustre_emu_qiling::GuestFile::is_eof"
        }).to_string()))
    }
}

#[cfg(any())] pub struct EmuQilingGuestFileRemainingTool;
#[cfg(any())] impl EmuQilingGuestFileRemainingTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_guest_file_remaining".to_string(),
            description: "Return GuestFile::remaining() for given content size and offset.".to_string(),
            input_schema: json!({"type":"object","required":["content_size","offset"],"properties":{"content_size":{"type":"integer","minimum":0},"offset":{"type":"integer","minimum":0}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingGuestFileRemainingTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let sz = args.get("content_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing content_size".into()))? as usize;
        let off = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing offset".into()))?;
        let mut gf = rustre_emu_qiling::GuestFile::new(11, "/g", "/h", true, true);
        gf.content = vec![0u8; sz];
        gf.offset = off;
        Ok(ToolResult::text(json!({
            "remaining": gf.remaining(),
            "is_eof": gf.is_eof(),
            "source": "rustre_emu_qiling::GuestFile::remaining"
        }).to_string()))
    }
}

#[cfg(any())] pub struct EmuQilingFdTableOpenFdsTool;
#[cfg(any())] impl EmuQilingFdTableOpenFdsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_fd_table_open_fds".to_string(),
            description: "Create a default FdTable, optionally open N extra files, and return open_fds() sorted list.".to_string(),
            input_schema: json!({"type":"object","properties":{"extra_opens":{"type":"integer","minimum":0,"maximum":32}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingFdTableOpenFdsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("extra_opens").and_then(Value::as_u64).unwrap_or(0);
        let mut t = rustre_emu_qiling::FdTable::new();
        for i in 0..n {
            let gf = rustre_emu_qiling::GuestFile::new(0, format!("/tmp/f{i}"), format!("/tmp/f{i}"), true, false);
            t.open(gf);
        }
        Ok(ToolResult::text(json!({
            "open_fds": t.open_fds(),
            "len": t.len(),
            "source": "rustre_emu_qiling::FdTable::open_fds"
        }).to_string()))
    }
}

#[cfg(any())] pub struct EmuQilingFdTableLenTool;
#[cfg(any())] impl EmuQilingFdTableLenTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_fd_table_len".to_string(),
            description: "Return len() and is_empty() of a fresh FdTable after optional close operations on stdio fds.".to_string(),
            input_schema: json!({"type":"object","properties":{"close_stdio":{"type":"boolean"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingFdTableLenTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let close = args.get("close_stdio").and_then(Value::as_bool).unwrap_or(false);
        let mut t = rustre_emu_qiling::FdTable::new();
        if close {
            t.close(0);
            t.close(1);
            t.close(2);
        }
        Ok(ToolResult::text(json!({
            "len": t.len(),
            "is_empty": t.is_empty(),
            "source": "rustre_emu_qiling::FdTable::len"
        }).to_string()))
    }
}

#[cfg(any())] pub struct EmuQilingSyscallCtxArgsTool;
#[cfg(any())] impl EmuQilingSyscallCtxArgsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_syscall_ctx_args".to_string(),
            description: "Construct a SyscallCtx and echo back arg0..arg5 accessors.".to_string(),
            input_schema: json!({"type":"object","required":["nr","args"],"properties":{"nr":{"type":"integer","minimum":0},"args":{"type":"array","items":{"type":"integer"},"minItems":6,"maxItems":6}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingSyscallCtxArgsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let nr = args.get("nr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing nr".into()))?;
        let a = args.get("args").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing args".into()))?;
        if a.len() != 6 { return Err(McpError::InvalidParams("args must have exactly 6 entries".into())); }
        let mut arr = [0u64; 6];
        for (i, v) in a.iter().enumerate() {
            arr[i] = v.as_u64().ok_or_else(|| McpError::InvalidParams(format!("args[{i}] not u64")))?;
        }
        let ctx = rustre_emu_qiling::SyscallCtx::new(nr, arr, rustre_emu::EmulatorArch::X86_64, rustre_emu_qiling::OsTarget::Linux);
        Ok(ToolResult::text(json!({
            "nr": ctx.nr,
            "arg0": ctx.arg0(), "arg1": ctx.arg1(), "arg2": ctx.arg2(),
            "arg3": ctx.arg3(), "arg4": ctx.arg4(), "arg5": ctx.arg5(),
            "source": "rustre_emu_qiling::SyscallCtx"
        }).to_string()))
    }
}

#[cfg(any())] pub struct EmuQilingSyscallResultNotImplRetvalTool;
#[cfg(any())] impl EmuQilingSyscallResultNotImplRetvalTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_syscall_result_not_impl_retval".to_string(),
            description: "Return retval() for SyscallResult variants Ok(v)/NotImplemented/Fatal.".to_string(),
            input_schema: json!({"type":"object","required":["variant"],"properties":{"variant":{"type":"string","enum":["ok","not_impl","fatal"]},"value":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingSyscallResultNotImplRetvalTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("variant").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing variant".into()))?;
        let r = match v {
            "ok" => rustre_emu_qiling::SyscallResult::Ok(args.get("value").and_then(Value::as_i64).unwrap_or(0)),
            "not_impl" => rustre_emu_qiling::SyscallResult::NotImplemented,
            "fatal" => rustre_emu_qiling::SyscallResult::Fatal("test".into()),
            _ => return Err(McpError::InvalidParams("variant must be ok|not_impl|fatal".into())),
        };
        Ok(ToolResult::text(json!({
            "variant": v,
            "retval": r.retval(),
            "source": "rustre_emu_qiling::SyscallResult::retval"
        }).to_string()))
    }
}

#[cfg(any())] pub struct EmuQilingDefaultLinuxX8664TableLenTool;
#[cfg(any())] impl EmuQilingDefaultLinuxX8664TableLenTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_default_linux_x86_64_table_len".to_string(),
            description: "Build the default Linux x86_64 syscall table and return len, is_empty, os, arch.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingDefaultLinuxX8664TableLenTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let t = rustre_emu_qiling::default_linux_x86_64_table();
        Ok(ToolResult::text(json!({
            "len": t.len(),
            "is_empty": t.is_empty(),
            "os": format!("{}", t.os()),
            "arch": format!("{:?}", t.arch()),
            "source": "rustre_emu_qiling::default_linux_x86_64_table"
        }).to_string()))
    }
}

#[cfg(any())] pub struct EmuQilingProcessEnvSetenvCheckTool;
#[cfg(any())] impl EmuQilingProcessEnvSetenvCheckTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_process_env_setenv_check".to_string(),
            description: "Build a linux64 ProcessEnv, setenv(key,value), then re-getenv to confirm round-trip.".to_string(),
            input_schema: json!({"type":"object","required":["key","value"],"properties":{"key":{"type":"string"},"value":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingProcessEnvSetenvCheckTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let k = args.get("key").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing key".into()))?;
        let v = args.get("value").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing value".into()))?;
        let mut env = rustre_emu_qiling::ProcessEnv::new_linux64(vec!["guest".into()]);
        env.setenv(k, v);
        let got = env.getenv(k).map(|s| s.to_string());
        Ok(ToolResult::text(json!({
            "key": k,
            "value": v,
            "getenv": got,
            "envp_len": env.envp.len(),
            "source": "rustre_emu_qiling::ProcessEnv::setenv"
        }).to_string()))
    }
}

#[cfg(any())] pub struct EmuQilingRawBinaryLoaderFormatNameTool;
#[cfg(any())] impl EmuQilingRawBinaryLoaderFormatNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_raw_binary_loader_format_name".to_string(),
            description: "Return RawBinaryLoader::format_name() and can_load() for arbitrary bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"load_base":{"type":"integer","minimum":0},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingRawBinaryLoaderFormatNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_emu_qiling::BinaryLoader;
        let base = args.get("load_base").and_then(Value::as_u64).unwrap_or(0x400000);
        let hex = args.get("hex").and_then(Value::as_str).unwrap_or("");
        let bytes = if hex.is_empty() { Vec::new() } else { args_to_bytes(&json!({"hex": hex}))? };
        let l = rustre_emu_qiling::RawBinaryLoader::new(base);
        Ok(ToolResult::text(json!({
            "format_name": l.format_name(),
            "can_load": l.can_load(&bytes),
            "load_base": l.load_base,
            "source": "rustre_emu_qiling::RawBinaryLoader::format_name"
        }).to_string()))
    }
}

#[cfg(any())] pub struct EmuQilingElfLoaderStubFormatNameTool;
#[cfg(any())] impl EmuQilingElfLoaderStubFormatNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_qiling_elf_loader_stub_format_name".to_string(),
            description: "Return ElfLoaderStub::format_name() and can_load() for the provided bytes.".to_string(),
            input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
#[cfg(any())] impl ToolHandler for EmuQilingElfLoaderStubFormatNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_emu_qiling::BinaryLoader;
        let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing hex".into()))?;
        let bytes = args_to_bytes(&json!({"hex": hex}))?;
        let l = rustre_emu_qiling::ElfLoaderStub;
        Ok(ToolResult::text(json!({
            "format_name": l.format_name(),
            "can_load": l.can_load(&bytes),
            "is_elf": rustre_emu_qiling::ElfLoaderStub::is_elf(&bytes),
            "source": "rustre_emu_qiling::ElfLoaderStub::format_name"
        }).to_string()))
    }
}

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        // [DISABLED 2026-07-12]         (EmuQilingLinuxX8664Tool::definition(), Box::new(EmuQilingLinuxX8664Tool)),
        // [DISABLED 2026-07-12]         (EmuQilingShellcodeRunnerTool::definition(), Box::new(EmuQilingShellcodeRunnerTool)),
        (EmuLibraryStubIsStubbedTool::definition(), Box::new(EmuLibraryStubIsStubbedTool)),
        (EmuLibraryStubModuleTool::definition(), Box::new(EmuLibraryStubModuleTool)),
        (EmuBackendsRegistryFindTool::definition(), Box::new(EmuBackendsRegistryFindTool)),
        (EmuMemProviderFindTool::definition(), Box::new(EmuMemProviderFindTool)),
        (EmuOsLinuxSyscallGroupTool::definition(), Box::new(EmuOsLinuxSyscallGroupTool)),
        (EmuArchPointerSizeTool::definition(), Box::new(EmuArchPointerSizeTool)),
        (EmuArchNameTool::definition(), Box::new(EmuArchNameTool)),
        // [DISABLED 2026-07-12]         (EmuQilingRootfsExistsTool::definition(), Box::new(EmuQilingRootfsExistsTool)),
        // [DISABLED 2026-07-12]         (EmuQilingProcessEnvNewLinux64Tool::definition(), Box::new(EmuQilingProcessEnvNewLinux64Tool)),
        (EmuArchPointerSizeWireTool::definition(), Box::new(EmuArchPointerSizeWireTool)),
        (EmuArchNameWireTool::definition(), Box::new(EmuArchNameWireTool)),
        // [DISABLED 2026-07-12]         (EmuQilingElfLoaderStubIsElfTool::definition(), Box::new(EmuQilingElfLoaderStubIsElfTool)),
        // [DISABLED 2026-07-12]         (EmuQilingRootfsPathHostPathTool::definition(), Box::new(EmuQilingRootfsPathHostPathTool)),
        // [DISABLED 2026-07-12]         (EmuQilingOsTargetNameTool::definition(), Box::new(EmuQilingOsTargetNameTool)),
        // [DISABLED 2026-07-12]         (EmuQilingSyscallResultRetvalTool::definition(), Box::new(EmuQilingSyscallResultRetvalTool)),
        // [DISABLED 2026-07-12]         (EmuQilingProcessEnvGetenvTool::definition(), Box::new(EmuQilingProcessEnvGetenvTool)),
        // [DISABLED 2026-07-12]         (EmuQilingProcessEnvSetenvTool::definition(), Box::new(EmuQilingProcessEnvSetenvTool)),
        // [DISABLED 2026-07-12]         (EmuQilingFdTableNewTool::definition(), Box::new(EmuQilingFdTableNewTool)),
        // [DISABLED 2026-07-12]         (EmuQilingFdTableOpenCloseTool::definition(), Box::new(EmuQilingFdTableOpenCloseTool)),
        // [DISABLED 2026-07-12]         (EmuQilingGuestFileRwTool::definition(), Box::new(EmuQilingGuestFileRwTool)),
        // [DISABLED 2026-07-12]         (EmuQilingRootfsRootTool::definition(), Box::new(EmuQilingRootfsRootTool)),
        (EmuMemRegionInspectTool::definition(), Box::new(EmuMemRegionInspectTool)),
        (EmuRegistryNamesTool::definition(), Box::new(EmuRegistryNamesTool)),
        (EmuCoverageMapSummaryTool::definition(), Box::new(EmuCoverageMapSummaryTool)),
        (EmuCoverageTrackerPctTool::definition(), Box::new(EmuCoverageTrackerPctTool)),
        (EmuStatsAggregateTool::definition(), Box::new(EmuStatsAggregateTool)),
        (EmuInterpreterMemRoundtripTool::definition(), Box::new(EmuInterpreterMemRoundtripTool)),
        (EmuMemRegionBatchCheckTool::definition(), Box::new(EmuMemRegionBatchCheckTool)),
        (EmuBaseArchIs64BitTool::definition(), Box::new(EmuBaseArchIs64BitTool)),
        (EmuBaseArchIsX86Tool::definition(), Box::new(EmuBaseArchIsX86Tool)),
        (EmuBaseMemRegionInfoTool::definition(), Box::new(EmuBaseMemRegionInfoTool)),
        (EmuBaseStatsIpcTool::definition(), Box::new(EmuBaseStatsIpcTool)),
        (EmuBaseCoverageMapSummaryTool::definition(), Box::new(EmuBaseCoverageMapSummaryTool)),
        (EmuBaseCoverageTrackerPctTool::definition(), Box::new(EmuBaseCoverageTrackerPctTool)),
        (EmuBaseTraceSummaryTool::definition(), Box::new(EmuBaseTraceSummaryTool)),
        (EmuBaseRegistersRoundTripTool::definition(), Box::new(EmuBaseRegistersRoundTripTool)),
        (EmuBaseFactoryCreateTool::definition(), Box::new(EmuBaseFactoryCreateTool)),
        (EmuBaseRegistrySizeTool::definition(), Box::new(EmuBaseRegistrySizeTool)),
        (EmuBaseMemPermsFlagsTool::definition(), Box::new(EmuBaseMemPermsFlagsTool)),
        // [DISABLED 2026-07-12]         (EmuQilingOsTargetDisplayAllTool::definition(), Box::new(EmuQilingOsTargetDisplayAllTool)),
        // [DISABLED 2026-07-12]         (EmuQilingFdTableIsEmptyTool::definition(), Box::new(EmuQilingFdTableIsEmptyTool)),
        // [DISABLED 2026-07-12]         (EmuQilingSyscallTableEmptyTool::definition(), Box::new(EmuQilingSyscallTableEmptyTool)),
        // [DISABLED 2026-07-12]         (EmuQilingEmulatorStateNewX8664Tool::definition(), Box::new(EmuQilingEmulatorStateNewX8664Tool)),
        // [DISABLED 2026-07-12]         (EmuQilingEmulatorStateMemU64RoundtripTool::definition(), Box::new(EmuQilingEmulatorStateMemU64RoundtripTool)),
        // [DISABLED 2026-07-12]         (EmuQilingEmulatorStateMemU32RoundtripTool::definition(), Box::new(EmuQilingEmulatorStateMemU32RoundtripTool)),
        // [DISABLED 2026-07-12]         (EmuQilingEmulatorStateCstringRoundtripTool::definition(), Box::new(EmuQilingEmulatorStateCstringRoundtripTool)),
        // [DISABLED 2026-07-12]         (EmuQilingEmulatorStateReadBytesTool::definition(), Box::new(EmuQilingEmulatorStateReadBytesTool)),
        // [DISABLED 2026-07-12]         (EmuQilingClosureSyscallTableLinuxLenTool::definition(), Box::new(EmuQilingClosureSyscallTableLinuxLenTool)),
        // [DISABLED 2026-07-12]         (EmuQilingClosureSyscallTableWindowsLenTool::definition(), Box::new(EmuQilingClosureSyscallTableWindowsLenTool)),
        // [DISABLED 2026-07-12]         (EmuQilingClosureSyscallDispatchExitTool::definition(), Box::new(EmuQilingClosureSyscallDispatchExitTool)),
        // [DISABLED 2026-07-12]         (EmuQilingErrnoConstantsTool::definition(), Box::new(EmuQilingErrnoConstantsTool)),
        // [DISABLED 2026-07-12]         (EmuQilingGuestFileIsEofTool::definition(), Box::new(EmuQilingGuestFileIsEofTool)),
        // [DISABLED 2026-07-12]         (EmuQilingGuestFileRemainingTool::definition(), Box::new(EmuQilingGuestFileRemainingTool)),
        // [DISABLED 2026-07-12]         (EmuQilingFdTableOpenFdsTool::definition(), Box::new(EmuQilingFdTableOpenFdsTool)),
        // [DISABLED 2026-07-12]         (EmuQilingFdTableLenTool::definition(), Box::new(EmuQilingFdTableLenTool)),
        // [DISABLED 2026-07-12]         (EmuQilingSyscallCtxArgsTool::definition(), Box::new(EmuQilingSyscallCtxArgsTool)),
        // [DISABLED 2026-07-12]         (EmuQilingSyscallResultNotImplRetvalTool::definition(), Box::new(EmuQilingSyscallResultNotImplRetvalTool)),
        // [DISABLED 2026-07-12]         (EmuQilingDefaultLinuxX8664TableLenTool::definition(), Box::new(EmuQilingDefaultLinuxX8664TableLenTool)),
        // [DISABLED 2026-07-12]         (EmuQilingProcessEnvSetenvCheckTool::definition(), Box::new(EmuQilingProcessEnvSetenvCheckTool)),
        // [DISABLED 2026-07-12]         (EmuQilingRawBinaryLoaderFormatNameTool::definition(), Box::new(EmuQilingRawBinaryLoaderFormatNameTool)),
        // [DISABLED 2026-07-12]         (EmuQilingElfLoaderStubFormatNameTool::definition(), Box::new(EmuQilingElfLoaderStubFormatNameTool)),
    ]
}

pub struct EmuUnicornPermCanExecToolV2;
impl EmuUnicornPermCanExecToolV2 {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "emu_unicorn_perm_can_exec_v2".to_string(),
            description: "Whether a Perm bitmask includes EXEC (v2).".to_string(),
            input_schema: json!({"type":"object","properties":{"bits":{"type":"integer"}},"required":["bits"]}),
            parameters: Value::Null }
    }
}
#[cfg(any())] // [DISABLED 2026-07-12]
#[async_trait]
impl ToolHandler for EmuUnicornPermCanExecToolV2 {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as u8;
        let p = rustre_emu_unicorn::Perm(bits);
        Ok(ToolResult::text(json!({"can_exec": p.can_exec(), "bits": bits}).to_string()))
    }
}
