//! MCP tool wrappers for Linux-specific debug features.
//!
//! Exposes four domain modules as MCP tool-calls:
//!
//! | Tool | Module |
//! |------|--------|
//! | `linux_proc_snapshot`   | `rustre_debug::proc_snapshot` |
//! | `linux_proc_maps`       | `rustre_debug::proc_snapshot::maps` |
//! | `linux_rr_list_traces`  | `rustre_debug::rr_trace::list_traces` |
//! | `linux_rr_trace_info`   | `rustre_debug::rr_trace::trace_info` |
//! | `linux_perf_snapshot`   | `rustre_debug::perf_events::snapshot_counters` |
//! | `linux_ebpf_uprobe_dry` | `rustre_debug::ebpf_uprobe` (config validation) |
//!
//! All tools are unconditionally present in the tool registry (they compile on
//! Windows/macOS) but return an informative `"platform": "linux-only"` error
//! when called on non-Linux hosts, so the MCP client can surface a clear
//! message rather than a missing-tool error.

use async_trait::async_trait;
use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

// ── Helper ────────────────────────────────────────────────────────────────────

fn linux_only_error(tool: &str) -> Result<ToolResult, McpError> {
    Ok(ToolResult::text(
        json!({
            "error": format!("{tool} is only available on Linux"),
            "platform": "linux-only",
            "hint": "Run this tool on a Linux host or inside WSL"
        })
        .to_string(),
    ))
}

#[cfg(target_os = "linux")]
fn coerce_u64(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() { return Some(n); }
    if let Some(f) = v.as_f64() {
        if f >= 0.0 && f.fract() == 0.0 { return Some(f as u64); }
    }
    let s = v.as_str()?.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    s.parse::<u64>().ok()
}

// ── 1. linux_proc_snapshot ────────────────────────────────────────────────────

/// MCP tool: capture a full `/proc/<pid>` snapshot.
pub struct LinuxProcSnapshotTool;

impl LinuxProcSnapshotTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "linux_proc_snapshot".to_string(),
            description: "Capture a point-in-time snapshot of /proc/<pid>: virtual memory maps, \
                          status fields (name/state/memory stats), stat (utime/stime/vsize/rss), \
                          current blocking syscall, wchan (kernel wait-channel), and open file \
                          descriptors. Linux only."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Target process PID (use 0 for the MCP server's own PID)"
                    }
                },
                "required": ["pid"]
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for LinuxProcSnapshotTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        #[cfg(not(target_os = "linux"))]
        return linux_only_error("linux_proc_snapshot");

        #[cfg(target_os = "linux")]
        {
            let pid_raw = args
                .get("pid")
                .and_then(|v| coerce_u64(v))
                .ok_or_else(|| McpError::InvalidParams("missing 'pid'".into()))?;

            let pid = if pid_raw == 0 {
                std::process::id()
            } else {
                u32::try_from(pid_raw)
                    .map_err(|_| McpError::InvalidParams("pid out of range".into()))?
            };

            match rustre_debug::proc_snapshot::snapshot(pid) {
                Ok(snap) => {
                    let json_val = serde_json::to_value(&snap)
                        .unwrap_or_else(|e| json!({"error": e.to_string()}));
                    Ok(ToolResult::text(json_val.to_string()))
                }
                Err(e) => Ok(ToolResult::text(
                    json!({"error": e.to_string(), "pid": pid}).to_string(),
                )),
            }
        }
    }
}

// ── 2. linux_proc_maps ────────────────────────────────────────────────────────

/// MCP tool: return only the virtual memory map for a process.
pub struct LinuxProcMapsTool;

impl LinuxProcMapsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "linux_proc_maps".to_string(),
            description: "Return the virtual memory map from /proc/<pid>/maps: address ranges, \
                          permissions (r/w/x/p), backing file and offset. Faster than \
                          linux_proc_snapshot when only the memory layout is needed. Linux only."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Target process PID"
                    }
                },
                "required": ["pid"]
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for LinuxProcMapsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        #[cfg(not(target_os = "linux"))]
        return linux_only_error("linux_proc_maps");

        #[cfg(target_os = "linux")]
        {
            let pid = args
                .get("pid")
                .and_then(|v| coerce_u64(v))
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| McpError::InvalidParams("missing 'pid'".into()))?;

            match rustre_debug::proc_snapshot::maps(pid) {
                Ok(maps) => {
                    let json_val = serde_json::to_value(&maps)
                        .unwrap_or_else(|e| json!({"error": e.to_string()}));
                    Ok(ToolResult::text(
                        json!({"pid": pid, "map_count": maps.len(), "maps": json_val}).to_string(),
                    ))
                }
                Err(e) => Ok(ToolResult::text(
                    json!({"error": e.to_string(), "pid": pid}).to_string(),
                )),
            }
        }
    }
}

// ── 3. linux_rr_list_traces ───────────────────────────────────────────────────

/// MCP tool: list rr trace directories.
pub struct LinuxRrListTracesTool;

impl LinuxRrListTracesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "linux_rr_list_traces".to_string(),
            description: "List Mozilla rr record/replay trace directories under the default rr \
                          traces root (~/.local/share/rr or $_RR_TRACE_DIR). Returns name, path, \
                          format version, and recorded thread count for each trace. Linux only."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "root": {
                        "type": "string",
                        "description": "Override the rr traces root directory (optional; \
                                        default: ~/.local/share/rr or $_RR_TRACE_DIR)"
                    }
                },
                "required": []
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for LinuxRrListTracesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        #[cfg(not(target_os = "linux"))]
        return linux_only_error("linux_rr_list_traces");

        #[cfg(target_os = "linux")]
        {
            let root = if let Some(r) = args.get("root").and_then(Value::as_str) {
                std::path::PathBuf::from(r)
            } else {
                rustre_debug::rr_trace::default_traces_dir()
            };

            let rr_ver = rustre_debug::rr_trace::rr_version();

            match rustre_debug::rr_trace::list_traces(&root) {
                Ok(traces) => Ok(ToolResult::text(
                    json!({
                        "root": root.to_string_lossy(),
                        "rr_version": rr_ver,
                        "trace_count": traces.len(),
                        "traces": serde_json::to_value(&traces)
                            .unwrap_or(json!([]))
                    })
                    .to_string(),
                )),
                Err(e) => Ok(ToolResult::text(
                    json!({
                        "error": e.to_string(),
                        "root": root.to_string_lossy(),
                        "rr_version": rr_ver,
                        "hint": "Run 'rr record <cmd>' first to create a trace"
                    })
                    .to_string(),
                )),
            }
        }
    }
}

// ── 4. linux_rr_trace_info ────────────────────────────────────────────────────

/// MCP tool: detailed info about one rr trace directory.
pub struct LinuxRrTraceInfoTool;

impl LinuxRrTraceInfoTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "linux_rr_trace_info".to_string(),
            description: "Return detailed metadata for a single rr trace directory: format \
                          version, bound CPU, recorded thread TIDs, events file size, mmaps file \
                          size, and captured binary names. Linux only."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to the rr trace directory"
                    }
                },
                "required": ["path"]
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for LinuxRrTraceInfoTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        #[cfg(not(target_os = "linux"))]
        return linux_only_error("linux_rr_trace_info");

        #[cfg(target_os = "linux")]
        {
            let path = args
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;

            match rustre_debug::rr_trace::trace_info(std::path::Path::new(path)) {
                Ok(info) => Ok(ToolResult::text(
                    serde_json::to_value(&info)
                        .unwrap_or_else(|e| json!({"error": e.to_string()}))
                        .to_string(),
                )),
                Err(e) => Ok(ToolResult::text(
                    json!({"error": e.to_string(), "path": path}).to_string(),
                )),
            }
        }
    }
}

// ── 5. linux_perf_snapshot ────────────────────────────────────────────────────

/// MCP tool: read hardware performance counters for a live process.
pub struct LinuxPerfSnapshotTool;

impl LinuxPerfSnapshotTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "linux_perf_snapshot".to_string(),
            description: "Read hardware performance counters for a live process via \
                          perf_event_open(2): CPU cycles, instructions, branch instructions, \
                          branch mispredictions, cache references, cache misses, minor/major \
                          page faults. Also computes IPC (instructions-per-cycle) and \
                          branch-miss rate. Requires CAP_PERFMON (Linux ≥ 5.8) or \
                          perf_event_paranoid ≤ 1. Linux only."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Target process PID (0 = self, -1 = any process on CPU)"
                    }
                },
                "required": ["pid"]
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for LinuxPerfSnapshotTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        #[cfg(not(target_os = "linux"))]
        return linux_only_error("linux_perf_snapshot");

        #[cfg(target_os = "linux")]
        {
            let pid_raw = args
                .get("pid")
                .and_then(|v| {
                    if let Some(n) = v.as_i64() { return Some(n); }
                    if let Some(n) = v.as_u64() { return Some(n as i64); }
                    v.as_str()?.parse::<i64>().ok()
                })
                .ok_or_else(|| McpError::InvalidParams("missing 'pid'".into()))?;

            let pid = i32::try_from(pid_raw)
                .map_err(|_| McpError::InvalidParams("pid out of i32 range".into()))?;

            match rustre_debug::perf_events::snapshot_counters(pid) {
                Ok(snap) => {
                    let ipc = snap.ipc();
                    let bmr = snap.branch_miss_rate();
                    let mut j = serde_json::to_value(&snap)
                        .unwrap_or_else(|e| json!({"error": e.to_string()}));
                    if let Some(obj) = j.as_object_mut() {
                        obj.insert("ipc".into(), ipc.map_or(Value::Null, |v| json!(v)));
                        obj.insert("branch_miss_rate".into(), bmr.map_or(Value::Null, |v| json!(v)));
                        obj.insert("source".into(), json!("rustre_debug::perf_events::snapshot_counters"));
                    }
                    Ok(ToolResult::text(j.to_string()))
                }
                Err(e) => {
                    let hint = if e.to_string().contains("permission") {
                        "Set /proc/sys/kernel/perf_event_paranoid to 1 or grant CAP_PERFMON"
                    } else {
                        "perf_event_open may not be available on this kernel/VM"
                    };
                    Ok(ToolResult::text(
                        json!({
                            "error": e.to_string(),
                            "pid": pid,
                            "hint": hint
                        })
                        .to_string(),
                    ))
                }
            }
        }
    }
}

// ── 6. linux_ebpf_uprobe_config ───────────────────────────────────────────────

/// MCP tool: validate and describe an eBPF uprobe/kprobe configuration.
///
/// On a privileged host this also attempts to attach the probe; on an
/// unprivileged host it returns the configuration that *would* be submitted,
/// allowing the LLM to reason about what the attachment would do.
pub struct LinuxEbpfUprobeConfigTool;

impl LinuxEbpfUprobeConfigTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "linux_ebpf_uprobe_config".to_string(),
            description: "Validate and (on privileged Linux) attach an eBPF hit-counter uprobe \
                          or kprobe. For a uprobe: provide 'path' (binary/library path) and \
                          'offset' (hex or decimal byte offset). For a kprobe: provide 'symbol' \
                          (kernel function name) and optional 'offset'. Requires CAP_BPF or \
                          CAP_SYS_ADMIN and mounted tracefs. Returns attachment status or a \
                          detailed description of what would be attached. Linux only."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": ["uprobe", "kprobe"],
                        "description": "Probe kind"
                    },
                    "path": {
                        "type": "string",
                        "description": "Absolute path to binary/library (uprobe only)"
                    },
                    "offset": {
                        "description": "Byte offset from start of file (uprobe) or symbol (kprobe)",
                        "oneOf": [{"type": "integer"}, {"type": "string"}]
                    },
                    "symbol": {
                        "type": "string",
                        "description": "Kernel function name (kprobe only)"
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Scope uprobe to this PID (-1 = any process, default)",
                        "default": -1
                    }
                },
                "required": ["kind"]
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for LinuxEbpfUprobeConfigTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        #[cfg(not(target_os = "linux"))]
        return linux_only_error("linux_ebpf_uprobe_config");

        #[cfg(target_os = "linux")]
        {
            let kind = args
                .get("kind")
                .and_then(Value::as_str)
                .ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;

            let offset = args
                .get("offset")
                .and_then(|v| coerce_u64(v))
                .unwrap_or(0);

            match kind {
                "uprobe" => {
                    let path = args
                        .get("path")
                        .and_then(Value::as_str)
                        .ok_or_else(|| McpError::InvalidParams("missing 'path' for uprobe".into()))?;
                    let pid = args
                        .get("pid")
                        .and_then(|v| v.as_i64())
                        .map(|n| n as i32)
                        .unwrap_or(-1);

                    let cfg = rustre_debug::ebpf_uprobe::UprobeConfig {
                        path: path.to_owned(),
                        offset,
                        pid,
                    };

                    match rustre_debug::ebpf_uprobe::attach_uprobe(&cfg) {
                        Ok(probe) => Ok(ToolResult::text(
                            json!({
                                "status": "attached",
                                "description": probe.description,
                                "kind": "uprobe",
                                "path": path,
                                "offset": offset,
                                "pid": pid,
                                "note": "probe will be detached when the MCP server closes this handle"
                            })
                            .to_string(),
                        )),
                        Err(e) => Ok(ToolResult::text(
                            json!({
                                "status": "error",
                                "error": e.to_string(),
                                "config": {
                                    "kind": "uprobe",
                                    "path": path,
                                    "offset": format!("{offset:#x}"),
                                    "pid": pid
                                },
                                "hint": "Ensure CAP_BPF + tracefs mounted at /sys/kernel/tracing"
                            })
                            .to_string(),
                        )),
                    }
                }
                "kprobe" => {
                    let symbol = args
                        .get("symbol")
                        .and_then(Value::as_str)
                        .ok_or_else(|| McpError::InvalidParams("missing 'symbol' for kprobe".into()))?;

                    let cfg = rustre_debug::ebpf_uprobe::KprobeConfig {
                        symbol: symbol.to_owned(),
                        offset,
                    };

                    match rustre_debug::ebpf_uprobe::attach_kprobe(&cfg) {
                        Ok(probe) => Ok(ToolResult::text(
                            json!({
                                "status": "attached",
                                "description": probe.description,
                                "kind": "kprobe",
                                "symbol": symbol,
                                "offset": offset
                            })
                            .to_string(),
                        )),
                        Err(e) => Ok(ToolResult::text(
                            json!({
                                "status": "error",
                                "error": e.to_string(),
                                "config": {
                                    "kind": "kprobe",
                                    "symbol": symbol,
                                    "offset": format!("{offset:#x}")
                                },
                                "hint": "Ensure CAP_SYS_ADMIN/CAP_BPF + tracefs mounted"
                            })
                            .to_string(),
                        )),
                    }
                }
                other => Ok(ToolResult::text(
                    json!({
                        "error": format!("unknown probe kind '{other}'; expected 'uprobe' or 'kprobe'")
                    })
                    .to_string(),
                )),
            }
        }
    }
}

// ── Registration helper ───────────────────────────────────────────────────────

/// Register all Linux-debug MCP tools into a [`crate::ToolRegistry`].
///
/// Call from `register_advanced_tools()` or any aggregation function.
pub fn register_linux_debug_tools(reg: &mut crate::ToolRegistry) {
    reg.register(LinuxProcSnapshotTool::definition(), Box::new(LinuxProcSnapshotTool));
    reg.register(LinuxProcMapsTool::definition(), Box::new(LinuxProcMapsTool));
    reg.register(LinuxRrListTracesTool::definition(), Box::new(LinuxRrListTracesTool));
    reg.register(LinuxRrTraceInfoTool::definition(), Box::new(LinuxRrTraceInfoTool));
    reg.register(LinuxPerfSnapshotTool::definition(), Box::new(LinuxPerfSnapshotTool));
    reg.register(LinuxEbpfUprobeConfigTool::definition(), Box::new(LinuxEbpfUprobeConfigTool));
}
