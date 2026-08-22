//! MCP wrappers for the rustre-f crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};

// ─────────────────────────────────────────────────────────────────────────────
// Real dump loading
//
// ⚠ Why this exists. Every `forensics_mem_*_mock` tool below used to call
// `rustre_forensics_mem::build_mock_image(..)`, analyse THAT, and report the
// result — with an `input_schema` that accepted no arguments at all. So a
// client asking "what processes were running in this dump" received the
// processes this very crate had just written into a 4 KiB synthetic buffer.
// The analysers underneath were made real (real `_EPROCESS` pool-tag scanning,
// real `regf` checksum validation, real PE header walking), but that changed
// nothing here, because the bytes being analysed were still manufactured.
//
// The tools now take a `path` and analyse the file at it. Their names are
// unchanged so existing clients keep working, and the `_mock` suffix is kept
// deliberately as a scar: it records what these tools used to do.
// ─────────────────────────────────────────────────────────────────────────────

/// Load the memory image named by `args["path"]`, detecting the container.
///
/// Detection is by magic, not by extension: `MDMP` is a Windows minidump,
/// `\x7fELF` is an ELF core dump, anything else is treated as a flat physical
/// dump. A flat dump carries no header, so `arch` and `os` may be supplied and
/// default to 64-bit Windows — the same defaults `MemoryImageFile::open_raw`
/// documents.
///
/// # Errors
/// Returns `InvalidParams` when `path` is absent, and a tool error when
/// the file cannot be read or its container cannot be parsed. It never falls
/// back to a synthetic image: a dump that cannot be opened is reported, not
/// replaced.
fn open_image_arg(args: &Value) -> Result<Box<dyn rustre_forensics::MemoryImage>, McpError> {
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| McpError::InvalidParams(
            "'path' is required: the memory dump to analyse".to_string(),
        ))?;

    let data = std::fs::read(path)
        .map_err(|e| McpError::ToolError(format!("cannot read '{path}': {e}")))?;

    if data.starts_with(b"MDMP") {
        let img = rustre_forensics::MinidumpImage::from_bytes(&data)
            .map_err(|e| McpError::ToolError(format!("minidump parse failed: {e}")))?;
        return Ok(Box::new(img));
    }
    if data.starts_with(b"\x7fELF") {
        let img = rustre_forensics::ElfCoredumpImage::from_bytes(&data)
            .map_err(|e| McpError::ToolError(format!("ELF core parse failed: {e}")))?;
        return Ok(Box::new(img));
    }

    let arch = match args.get("arch").and_then(Value::as_str) {
        Some("32" | "x86") => rustre_forensics::ArchBits::Bits32,
        _ => rustre_forensics::ArchBits::Bits64,
    };
    let os = match args.get("os").and_then(Value::as_str) {
        Some("linux") => rustre_forensics::OsType::Linux,
        _ => rustre_forensics::OsType::Windows,
    };
    Ok(Box::new(rustre_forensics::RawMemoryImage::from_bytes_with_base(
        data, arch, os, 0,
    )))
}

/// Input schema shared by every dump-analysing tool.
fn dump_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Path to the memory dump (minidump, ELF core, or flat physical dump)"},
            "arch": {"type": "string", "enum": ["32", "64"], "description": "Only for headerless flat dumps. Default 64."},
            "os":   {"type": "string", "enum": ["windows", "linux"], "description": "Only for headerless flat dumps. Default windows."}
        },
        "required": ["path"]
    })
}
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes};

pub struct FMemHeapAllocTool;
impl FMemHeapAllocTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition {
        name: "forensics_mem_scan_heap_allocations".to_string(),
        description: "NT heap busy blocks.".to_string(),
        input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
        parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for FMemHeapAllocTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let allocs = rustre_forensics_mem::MemoryForensicsScanner::scan_heap_allocations(&data);
        let arr: Vec<Value> = allocs.iter().map(|a| json!({"addr":a.addr,"size":a.size})).collect();
        Ok(ToolResult::text(json!({"count":arr.len(),"allocations":arr}).to_string()))
    }
}

pub struct FMemWinVerDisplayTool;
impl FMemWinVerDisplayTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition {
        name: "forensics_mem_windows_version_display".to_string(),
        description: "WindowsVersion::display.".to_string(),
        input_schema: json!({"type":"object","properties":{"major":{"type":"integer"},"minor":{"type":"integer"},"build":{"type":"integer"}},"required":["major","minor","build"]}),
        parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for FMemWinVerDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let major = args.get("major").and_then(Value::as_u64).unwrap_or(0) as u32;
        let minor = args.get("minor").and_then(Value::as_u64).unwrap_or(0) as u32;
        let build = args.get("build").and_then(Value::as_u64).unwrap_or(0) as u32;
        let v = rustre_forensics_mem::WindowsVersion::new(major, minor, build);
        Ok(ToolResult::text(json!({"display":v.display()}).to_string()))
    }
}

pub struct FMemNetProtoStrTool;
impl FMemNetProtoStrTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition {
        name: "forensics_mem_net_protocol_as_str".to_string(),
        description: "NetProtocol::as_str.".to_string(),
        input_schema: json!({"type":"object","properties":{"index":{"type":"integer"}},"required":["index"]}),
        parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for FMemNetProtoStrTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let idx = args.get("index").and_then(Value::as_u64).unwrap_or(0);
        let p = match idx {
            0 => rustre_forensics_mem::NetProtocol::TcpV4,
            1 => rustre_forensics_mem::NetProtocol::TcpV6,
            2 => rustre_forensics_mem::NetProtocol::UdpV4,
            _ => rustre_forensics_mem::NetProtocol::UdpV6,
        };
        Ok(ToolResult::text(json!({"as_str":p.as_str()}).to_string()))
    }
}

pub struct FMemProcNameMatchesTool;
impl FMemProcNameMatchesTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition {
        name: "forensics_mem_process_name_matches".to_string(),
        description: "ProcessInfo::name_matches.".to_string(),
        input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"pattern":{"type":"string"}},"required":["name","pattern"]}),
        parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for FMemProcNameMatchesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        let pat  = args.get("pattern").and_then(Value::as_str).unwrap_or("");
        let pi = rustre_forensics_mem::ProcessInfo { pid:0, ppid:0, name, base:0, size:0, threads:vec![], modules:vec![], handle_count:0, create_time:0 };
        Ok(ToolResult::text(json!({"matches":pi.name_matches(pat)}).to_string()))
    }
}

pub struct FMemHiveParseKeyTool;
impl FMemHiveParseKeyTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition {
        name: "forensics_mem_registry_hive_parse_key".to_string(),
        description: "RegistryHive::parse_key.".to_string(),
        input_schema: json!({"type":"object","properties":{"key_path":{"type":"string"}},"required":["key_path"]}),
        parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for FMemHiveParseKeyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let key_path = args.get("key_path").and_then(Value::as_str).unwrap_or("");
        let mut data = vec![0u8; 64]; data[0..4].copy_from_slice(b"regf");
        let hive = rustre_forensics_mem::RegistryHive { name: "SYNTHETIC".to_string(), base:0, size:64, data };
        let key = hive.parse_key(key_path);
        Ok(ToolResult::text(json!({
            "found": key.is_some(),
            "name":  key.as_ref().map(|k| k.name.clone()),
            "value_count":  key.as_ref().map(|k| k.values.len()).unwrap_or(0),
            "subkey_count": key.as_ref().map(|k| k.subkeys.len()).unwrap_or(0),
        }).to_string()))
    }
}

pub struct FMemWinFindProcsMockTool;
impl FMemWinFindProcsMockTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition {
        name: "forensics_mem_win_find_processes_mock".to_string(),
        description: "WindowsAnalyzer::find_processes over mock.".to_string(),
        input_schema: dump_schema(),
        parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for FMemWinFindProcsMockTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let img = open_image_arg(&args)?;
        let procs = rustre_forensics_mem::WindowsAnalyzer::find_processes(img.as_ref());
        let arr: Vec<Value> = procs.iter().map(|p| json!({"pid":p.pid,"ppid":p.ppid,"name":p.name,"base":p.base,"size":p.size})).collect();
        Ok(ToolResult::text(json!({"count":arr.len(),"processes":arr}).to_string()))
    }
}

pub struct FMemWinFindModsMockTool;
impl FMemWinFindModsMockTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition {
        name: "forensics_mem_win_find_modules_mock".to_string(),
        description: "WindowsAnalyzer::find_modules over mock.".to_string(),
        input_schema: { let mut sc = dump_schema(); sc["properties"]["pid"] = json!({"type":"integer"}); sc },
        parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for FMemWinFindModsMockTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pid = args.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32;
        let img = open_image_arg(&args)?;
        let mods = rustre_forensics_mem::WindowsAnalyzer::find_modules(img.as_ref(), pid);
        let arr: Vec<Value> = mods.iter().map(|m| json!({"name":m.name,"base":m.base,"size":m.size,"path":m.path})).collect();
        Ok(ToolResult::text(json!({"count":arr.len(),"modules":arr}).to_string()))
    }
}

pub struct FMemWinFindNetMockTool;
impl FMemWinFindNetMockTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition {
        name: "forensics_mem_win_find_network_connections_mock".to_string(),
        description: "WindowsAnalyzer::find_network_connections over mock.".to_string(),
        input_schema: dump_schema(),
        parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for FMemWinFindNetMockTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let img = open_image_arg(&args)?;
        let conns = rustre_forensics_mem::WindowsAnalyzer::find_network_connections(img.as_ref());
        let arr: Vec<Value> = conns.iter().map(|c| json!({
            "protocol": c.protocol.as_str(),
            "local_addr": c.local_addr, "local_port": c.local_port,
            "remote_addr": c.remote_addr, "remote_port": c.remote_port,
            "pid": c.pid })).collect();
        Ok(ToolResult::text(json!({"count":arr.len(),"connections":arr}).to_string()))
    }
}

pub struct FMemWinExtractHivesMockTool;
impl FMemWinExtractHivesMockTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition {
        name: "forensics_mem_win_extract_registry_hives_mock".to_string(),
        description: "WindowsAnalyzer::extract_registry_hives over mock.".to_string(),
        input_schema: dump_schema(),
        parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for FMemWinExtractHivesMockTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let img = open_image_arg(&args)?;
        let hives = rustre_forensics_mem::WindowsAnalyzer::extract_registry_hives(img.as_ref());
        let arr: Vec<Value> = hives.iter().map(|h| json!({"name":h.name,"base":h.base,"size":h.size,"data_len":h.data.len()})).collect();
        Ok(ToolResult::text(json!({"count":arr.len(),"hives":arr}).to_string()))
    }
}

pub struct FMemWinKernelInfoMockTool;
impl FMemWinKernelInfoMockTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition {
        name: "forensics_mem_win_find_kernel_info_mock".to_string(),
        description: "WindowsAnalyzer::find_kernel_info over mock.".to_string(),
        input_schema: dump_schema(),
        parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for FMemWinKernelInfoMockTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let img = open_image_arg(&args)?;
        let info = rustre_forensics_mem::WindowsAnalyzer::find_kernel_info(img.as_ref());
        Ok(ToolResult::text(json!({
            "found": info.is_some(),
            "kdbg":  info.as_ref().and_then(|i| i.kdbg),
            "ntoskrnl_base": info.as_ref().map(|i| i.ntoskrnl_base),
            "version": info.as_ref().map(|i| i.version.display()),
        }).to_string()))
    }
}

pub struct FMemLinuxFindProcsMockTool;
impl FMemLinuxFindProcsMockTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition {
        name: "forensics_mem_linux_find_processes_mock".to_string(),
        description: "LinuxAnalyzer::find_processes over mock.".to_string(),
        input_schema: dump_schema(),
        parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for FMemLinuxFindProcsMockTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let img = open_image_arg(&args)?;
        let procs = rustre_forensics_mem::LinuxAnalyzer::find_processes(img.as_ref());
        let arr: Vec<Value> = procs.iter().map(|p| json!({"pid":p.pid,"ppid":p.ppid,"name":p.name})).collect();
        Ok(ToolResult::text(json!({"count":arr.len(),"processes":arr}).to_string()))
    }
}

pub struct FMemLinuxFindModsMockTool;
impl FMemLinuxFindModsMockTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition {
        name: "forensics_mem_linux_find_modules_mock".to_string(),
        description: "LinuxAnalyzer::find_modules over mock.".to_string(),
        input_schema: dump_schema(),
        parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for FMemLinuxFindModsMockTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let img = open_image_arg(&args)?;
        let mods = rustre_forensics_mem::LinuxAnalyzer::find_modules(img.as_ref());
        let arr: Vec<Value> = mods.iter().map(|m| json!({"name":m.name,"base":m.base,"size":m.size,"path":m.path})).collect();
        Ok(ToolResult::text(json!({"count":arr.len(),"modules":arr}).to_string()))
    }
}

pub struct FMemLinuxFindSocksMockTool;
impl FMemLinuxFindSocksMockTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition {
        name: "forensics_mem_linux_find_sockets_mock".to_string(),
        description: "LinuxAnalyzer::find_sockets over mock.".to_string(),
        input_schema: dump_schema(),
        parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for FMemLinuxFindSocksMockTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let img = open_image_arg(&args)?;
        let socks = rustre_forensics_mem::LinuxAnalyzer::find_sockets(img.as_ref());
        let arr: Vec<Value> = socks.iter().map(|c| json!({
            "protocol": c.protocol.as_str(),
            "local_addr": c.local_addr, "local_port": c.local_port,
            "remote_addr": c.remote_addr, "remote_port": c.remote_port,
            "pid": c.pid })).collect();
        Ok(ToolResult::text(json!({"count":arr.len(),"sockets":arr}).to_string()))
    }
}

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (FMemHeapAllocTool::definition(), Box::new(FMemHeapAllocTool)),
        (FMemWinVerDisplayTool::definition(), Box::new(FMemWinVerDisplayTool)),
        (FMemNetProtoStrTool::definition(), Box::new(FMemNetProtoStrTool)),
        (FMemProcNameMatchesTool::definition(), Box::new(FMemProcNameMatchesTool)),
        (FMemHiveParseKeyTool::definition(), Box::new(FMemHiveParseKeyTool)),
        (FMemWinFindProcsMockTool::definition(), Box::new(FMemWinFindProcsMockTool)),
        (FMemWinFindModsMockTool::definition(), Box::new(FMemWinFindModsMockTool)),
        (FMemWinFindNetMockTool::definition(), Box::new(FMemWinFindNetMockTool)),
        (FMemWinExtractHivesMockTool::definition(), Box::new(FMemWinExtractHivesMockTool)),
        (FMemWinKernelInfoMockTool::definition(), Box::new(FMemWinKernelInfoMockTool)),
        (FMemLinuxFindProcsMockTool::definition(), Box::new(FMemLinuxFindProcsMockTool)),
        (FMemLinuxFindModsMockTool::definition(), Box::new(FMemLinuxFindModsMockTool)),
        (FMemLinuxFindSocksMockTool::definition(), Box::new(FMemLinuxFindSocksMockTool)),
    ]
}

#[cfg(test)]
mod real_dump_tests {
    //! ⚠ These pin the fix for the worst fake-data defect in the repo.
    //!
    //! The eight `forensics_mem_*_mock` tools declared an `input_schema` with
    //! NO properties, built a 4 KiB synthetic image with `build_mock_image`,
    //! analysed that, and reported the result. A client asking "what processes
    //! were running in this dump" got the processes this crate had just written
    //! into its own buffer — and had no way to pass a dump at all.

    use super::*;

    /// Every dump tool must now REQUIRE a path. A call with no arguments is a
    /// parameter error, not a synthetic answer.
    #[tokio::test]
    async fn a_call_without_a_path_is_rejected() {
        let out = FMemWinFindProcsMockTool.call(json!({})).await;
        match out {
            Err(McpError::InvalidParams(m)) => {
                assert!(m.contains("path"), "the error must name the missing arg: {m}");
            }
            other => panic!("expected InvalidParams, got {other:?}"),
        }
    }

    /// A path that does not exist is reported as such — never silently
    /// replaced by a synthetic image.
    #[tokio::test]
    async fn a_missing_file_is_reported_not_substituted() {
        let out = FMemWinFindProcsMockTool
            .call(json!({"path": "no/such/dump.raw"}))
            .await;
        assert!(
            matches!(out, Err(McpError::ToolError(_))),
            "a missing dump must be an error, got {out:?}"
        );
    }

    /// The schema must advertise `path` as required, so a client can discover
    /// the argument instead of calling with `{}` and getting invented data.
    #[test]
    fn the_schema_requires_a_path() {
        for schema in [
            FMemWinFindProcsMockTool::definition().input_schema,
            FMemWinFindModsMockTool::definition().input_schema,
        ] {
            let required = schema["required"]
                .as_array()
                .expect("every dump tool must declare a required list");
            assert!(
                required.iter().any(|v| v == "path"),
                "path must be required, got {required:?}"
            );
        }
    }

    /// A real file IS opened and analysed: a buffer of zeroes is a valid flat
    /// dump containing no `_EPROCESS` pool tags, so the honest answer is an
    /// empty process list — not the fixture's invented processes.
    #[tokio::test]
    async fn an_empty_flat_dump_yields_no_processes() {
        let dir = std::env::temp_dir().join("rustre_f_real_dump_test");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("zero.raw");
        std::fs::write(&path, vec![0u8; 64 * 1024]).expect("write dump");

        let out = FMemWinFindProcsMockTool
            .call(json!({"path": path.to_string_lossy()}))
            .await
            .expect("a readable flat dump must be analysed");

        let text = format!("{out:?}");
        assert!(
            text.contains("\\\"count\\\":0") || text.contains("\"count\":0"),
            "zeroed memory holds no processes, got {text}"
        );
    }
}
