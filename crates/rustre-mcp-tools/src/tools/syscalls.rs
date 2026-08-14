//! MCP wrappers for the rustre-syscalls crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct SyscallsCategorizeByNameTool;

pub struct SyscallsEstimateRiskTool;

pub struct SyscallsIa32ToX8664NrTool;
impl SyscallsIa32ToX8664NrTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_ia32_to_x86_64_nr".to_string(),
            description: "Translate IA-32 syscall nr to x86-64 via rustre_syscalls::compat_layer::ia32_to_x86_64_nr".to_string(),
            input_schema: json!({"type":"object","properties":{"nr":{"type":"integer"}},"required":["nr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsIa32ToX8664NrTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let nr = args.get("nr").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'nr'".into()))? as u32;
        let out = rustre_syscalls::compat_layer::ia32_to_x86_64_nr(nr);
        Ok(ToolResult::text(json!({"ia32_nr": nr, "x86_64_nr": out}).to_string()))
    }
}

pub struct SyscallsCrossArchTableTool;
impl SyscallsCrossArchTableTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_cross_arch_table".to_string(),
            description: "Return cross-arch syscall table via rustre_syscalls::compat_layer::cross_arch_table".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsCrossArchTableTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let tbl = rustre_syscalls::compat_layer::cross_arch_table();
        Ok(ToolResult::text(json!({"count": tbl.len(), "entries": tbl}).to_string()))
    }
}

pub struct SyscallsLookupCrossArchTool;
impl SyscallsLookupCrossArchTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_lookup_cross_arch".to_string(),
            description: "Lookup cross-arch syscall by name via rustre_syscalls::compat_layer::lookup_cross_arch".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsLookupCrossArchTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let out = rustre_syscalls::compat_layer::lookup_cross_arch(name);
        Ok(ToolResult::text(json!({"name": name, "entry": out}).to_string()))
    }
}

pub struct SyscallsFormatCrossArchTableTool;
impl SyscallsFormatCrossArchTableTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_format_cross_arch_table".to_string(),
            description: "Format cross-arch syscall table as text via rustre_syscalls::compat_layer::format_cross_arch_table".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsFormatCrossArchTableTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let text = rustre_syscalls::compat_layer::format_cross_arch_table();
        Ok(ToolResult::text(json!({"text": text}).to_string()))
    }
}

pub struct SyscallsDetectIa32MechanismTool;
impl SyscallsDetectIa32MechanismTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_detect_ia32_mechanism".to_string(),
            description: "Detect IA-32 syscall mechanism from bytes via rustre_syscalls::compat_layer::detect_ia32_mechanism".to_string(),
            input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsDetectIa32MechanismTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?;
        let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        // panic su lunghezza dispari prima di questa conversione.
        let bytes = crate::hex_decode(&clean)?;
        let mech = rustre_syscalls::compat_layer::detect_ia32_mechanism(&bytes);
        Ok(ToolResult::text(json!({"mechanism": mech}).to_string()))
    }
}

pub struct SyscallsWin10Syscalls22H2Tool;
impl SyscallsWin10Syscalls22H2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_win10_22h2_syscalls".to_string(),
            description: "Windows 10 22H2 syscall list via rustre_syscalls::windows_syscalls::get_win10_22h2_syscalls".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsWin10Syscalls22H2Tool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let raw = rustre_syscalls::windows_syscalls::get_win10_22h2_syscalls();
        let items: Vec<serde_json::Value> = raw.iter().map(|(nr, name, module, argc, cat)| {
            json!({"nr": nr, "name": name, "module": module, "argc": argc, "category": format!("{:?}", cat)})
        }).collect();
        Ok(ToolResult::text(json!({"count": items.len(), "entries": items}).to_string()))
    }
}

pub struct SyscallsTableNumberToNameTool;
impl SyscallsTableNumberToNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_table_number_to_name".to_string(),
            description: "Resolve syscall number to name via rustre_syscalls::SyscallTable::number_to_name".to_string(),
            input_schema: json!({"type":"object","properties":{"nr":{"type":"integer"},"arch":{"type":"string"}},"required":["nr","arch"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsTableNumberToNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let nr = args.get("nr").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'nr'".into()))?;
        let arch = args.get("arch").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'arch'".into()))?;
        let name = rustre_syscalls::SyscallTable::number_to_name(nr, arch);
        Ok(ToolResult::text(json!({"nr": nr, "arch": arch, "name": name}).to_string()))
    }
}

pub struct SyscallsTableNameToNumberTool;
impl SyscallsTableNameToNumberTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_table_name_to_number".to_string(),
            description: "Resolve syscall name to number via rustre_syscalls::SyscallTable::name_to_number".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"arch":{"type":"string"}},"required":["name","arch"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsTableNameToNumberTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let arch = args.get("arch").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'arch'".into()))?;
        let nr = rustre_syscalls::SyscallTable::name_to_number(name, arch);
        Ok(ToolResult::text(json!({"name": name, "arch": arch, "nr": nr}).to_string()))
    }
}

pub struct SyscallsTableLinuxX8664ListTool;
impl SyscallsTableLinuxX8664ListTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_table_linux_x86_64_list".to_string(),
            description: "List Linux x86-64 syscall entries via rustre_syscalls::SyscallTable::linux_x86_64".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsTableLinuxX8664ListTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let t = rustre_syscalls::SyscallTable::linux_x86_64();
        let entries: Vec<serde_json::Value> = t.entries().iter().map(|e| json!({"number": e.number, "name": e.name})).collect();
        Ok(ToolResult::text(json!({"count": entries.len(), "entries": entries}).to_string()))
    }
}

pub struct SyscallsTableLinuxArm64ListTool;
impl SyscallsTableLinuxArm64ListTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_table_linux_arm64_list".to_string(),
            description: "List Linux arm64 syscall entries via rustre_syscalls::SyscallTable::linux_arm64".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsTableLinuxArm64ListTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let t = rustre_syscalls::SyscallTable::linux_arm64();
        let entries: Vec<serde_json::Value> = t.entries().iter().map(|e| json!({"number": e.number, "name": e.name})).collect();
        Ok(ToolResult::text(json!({"count": entries.len(), "entries": entries}).to_string()))
    }
}

pub struct SyscallsTableWindowsX64ListTool;
impl SyscallsTableWindowsX64ListTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_table_windows_x64_list".to_string(),
            description: "List Windows x64 syscall entries via rustre_syscalls::SyscallTable::windows_x64".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsTableWindowsX64ListTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let t = rustre_syscalls::SyscallTable::windows_x64();
        let entries: Vec<serde_json::Value> = t.entries().iter().map(|e| json!({"number": e.number, "name": e.name})).collect();
        Ok(ToolResult::text(json!({"count": entries.len(), "entries": entries}).to_string()))
    }
}

pub struct SyscallsDatabaseStatsTool;
impl SyscallsDatabaseStatsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "syscalls_database_stats".to_string(),
            description: "Stats of empty SyscallDatabase via rustre_syscalls::SyscallDatabase::stats".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SyscallsDatabaseStatsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let db = rustre_syscalls::SyscallDatabase::new();
        let s = db.stats();
        Ok(ToolResult::text(json!({"stats": s, "len": db.len(), "is_empty": db.is_empty()}).to_string()))
    }
}

pub struct SyscallsSignalNameTool;

pub struct SyscallsErrnoNameTool;

pub struct SyscallsSignalNameLookupTool;

pub struct SyscallsErrnoNameLookupTool;

pub struct SyscallsSignalNameLookupWireTool;

pub struct SyscallsErrnoNameLookupWireTool;

pub struct SyscallsClockIdNameV2Tool;
impl SyscallsClockIdNameV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "syscalls_clock_id_name_v2".to_string(), description: "Map clock ID to name via rustre_syscalls::clock_id_name".to_string(), input_schema: json!({"type":"object","properties":{"id":{"type":"integer"}},"required":["id"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SyscallsClockIdNameV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let id = args.get("id").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("id".into()))? as u32; let name = rustre_syscalls::clock_id_name(id); Ok(ToolResult::text(json!({"id":id,"name":name,"source":"rustre_syscalls::clock_id_name"}).to_string())) } }

pub struct SyscallsSaFamilyNameV2Tool;
impl SyscallsSaFamilyNameV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "syscalls_sa_family_name_v2".to_string(), description: "Map address family constant to name via rustre_syscalls::sa_family_name".to_string(), input_schema: json!({"type":"object","properties":{"family":{"type":"integer"}},"required":["family"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SyscallsSaFamilyNameV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let f = args.get("family").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("family".into()))? as u16; let name = rustre_syscalls::sa_family_name(f); Ok(ToolResult::text(json!({"family":f,"name":name,"source":"rustre_syscalls::sa_family_name"}).to_string())) } }

pub struct SyscallsDecodeArgFdV2Tool;
impl SyscallsDecodeArgFdV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "syscalls_decode_arg_fd_v2".to_string(), description: "Decode a raw u64 as an Fd via rustre_syscalls::decode_arg_value".to_string(), input_schema: json!({"type":"object","properties":{"raw":{"type":"integer"}},"required":["raw"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SyscallsDecodeArgFdV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let raw = args.get("raw").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("raw".into()))?; let d = rustre_syscalls::decode_arg_value(&rustre_syscalls::SyscallType::Fd, raw); Ok(ToolResult::text(json!({"raw":d.raw,"display":d.display,"is_null":d.is_null,"source":"rustre_syscalls::decode_arg_value"}).to_string())) } }

pub struct SyscallsDecodeArgSignalV2Tool;
impl SyscallsDecodeArgSignalV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "syscalls_decode_arg_signal_v2".to_string(), description: "Decode a raw u64 as a Signal via rustre_syscalls::decode_arg_value".to_string(), input_schema: json!({"type":"object","properties":{"raw":{"type":"integer"}},"required":["raw"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SyscallsDecodeArgSignalV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let raw = args.get("raw").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("raw".into()))?; let d = rustre_syscalls::decode_arg_value(&rustre_syscalls::SyscallType::Signal, raw); Ok(ToolResult::text(json!({"raw":d.raw,"display":d.display,"source":"rustre_syscalls::decode_arg_value"}).to_string())) } }

pub struct SyscallsDecodeArgIpAddrV2Tool;
impl SyscallsDecodeArgIpAddrV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "syscalls_decode_arg_ip_addr_v2".to_string(), description: "Decode a raw u64 as an IPv4 addr via rustre_syscalls::decode_arg_value".to_string(), input_schema: json!({"type":"object","properties":{"raw":{"type":"integer"}},"required":["raw"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SyscallsDecodeArgIpAddrV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let raw = args.get("raw").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("raw".into()))?; let d = rustre_syscalls::decode_arg_value(&rustre_syscalls::SyscallType::IpAddr, raw); Ok(ToolResult::text(json!({"raw":d.raw,"display":d.display,"source":"rustre_syscalls::decode_arg_value"}).to_string())) } }

pub struct SyscallsTableMaxNumberX8664V2Tool;
impl SyscallsTableMaxNumberX8664V2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "syscalls_table_max_number_x86_64_v2".to_string(), description: "Report the max syscall number of the Linux x86_64 SyscallTable.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SyscallsTableMaxNumberX8664V2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let t = rustre_syscalls::SyscallTable::linux_x86_64(); Ok(ToolResult::text(json!({"len":t.len(),"is_empty":t.is_empty(),"max_number":t.max_number(),"source":"rustre_syscalls::SyscallTable::max_number"}).to_string())) } }

pub struct SyscallsDatabaseEmptyStatsV2Tool;
impl SyscallsDatabaseEmptyStatsV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "syscalls_database_empty_stats_v2".to_string(), description: "Build empty SyscallDatabase and report len/is_empty/stats.total.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SyscallsDatabaseEmptyStatsV2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let db = rustre_syscalls::SyscallDatabase::new(); let stats = db.stats(); Ok(ToolResult::text(json!({"len":db.len(),"is_empty":db.is_empty(),"total":stats.total,"source":"rustre_syscalls::SyscallDatabase::stats"}).to_string())) } }

pub struct SyscallsTraceEmptyErrorRateV2Tool;
impl SyscallsTraceEmptyErrorRateV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "syscalls_trace_empty_error_rate_v2".to_string(), description: "Empty SyscallTrace probe: len/is_empty/error_rate/duration_ns.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SyscallsTraceEmptyErrorRateV2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let t = rustre_syscalls::SyscallTrace::new(); Ok(ToolResult::text(json!({"len":t.len(),"is_empty":t.is_empty(),"error_rate":t.error_rate(),"duration_ns":t.duration_ns(),"source":"rustre_syscalls::SyscallTrace"}).to_string())) } }

pub struct SyscallsSeccompPolicyEvaluateV2Tool;
impl SyscallsSeccompPolicyEvaluateV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "syscalls_seccomp_policy_evaluate_v2".to_string(), description: "Build a SeccompPolicy with one Allow rule and evaluate it.".to_string(), input_schema: json!({"type":"object","properties":{"nr":{"type":"integer"}},"required":["nr"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SyscallsSeccompPolicyEvaluateV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let nr = args.get("nr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("nr".into()))? as u32; let mut p = rustre_syscalls::SeccompPolicy::new("test", rustre_syscalls::SeccompAction::Kill); p.add_rule(rustre_syscalls::SeccompRule::new(nr, rustre_syscalls::SeccompAction::Allow, rustre_syscalls::SyscallArch::X86_64, "allow test")); let action = p.evaluate(nr, rustre_syscalls::SyscallArch::X86_64); let allowed = p.would_allow(nr, rustre_syscalls::SyscallArch::X86_64); let counts = p.rule_counts(); Ok(ToolResult::text(json!({"nr":nr,"action":action.to_string(),"would_allow":allowed,"allowed_count":p.allowed_syscalls().len(),"denied_count":p.denied_syscalls().len(),"rule_counts":counts,"source":"rustre_syscalls::SeccompPolicy::evaluate"}).to_string())) } }

pub struct SyscallsCallPrefixFlagsV2Tool;
impl SyscallsCallPrefixFlagsV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "syscalls_call_prefix_flags_v2".to_string(), description: "Report show_pid/show_timestamp for each CallPrefix variant.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SyscallsCallPrefixFlagsV2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_syscalls::CallPrefix; let variants = [("none",CallPrefix::None),("pid",CallPrefix::Pid),("timestamp",CallPrefix::Timestamp),("both",CallPrefix::Both)]; let arr: Vec<Value> = variants.iter().map(|(n,v)| json!({"variant":n,"show_pid":v.show_pid(),"show_timestamp":v.show_timestamp()})).collect(); Ok(ToolResult::text(json!({"variants":arr,"source":"rustre_syscalls::CallPrefix"}).to_string())) } }

pub struct SyscallsFormatterFormatArgFdV2Tool;
impl SyscallsFormatterFormatArgFdV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "syscalls_formatter_format_arg_fd_v2".to_string(), description: "SyscallFormatter::format_arg for Fd type.".to_string(), input_schema: json!({"type":"object","properties":{"raw":{"type":"integer"}},"required":["raw"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SyscallsFormatterFormatArgFdV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let raw = args.get("raw").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("raw".into()))?; let s = rustre_syscalls::SyscallFormatter::format_arg(&rustre_syscalls::SyscallType::Fd, raw); Ok(ToolResult::text(json!({"raw":raw,"display":s,"source":"rustre_syscalls::SyscallFormatter::format_arg"}).to_string())) } }

pub struct SyscallsBuilderBuildOpenV2Tool;
impl SyscallsBuilderBuildOpenV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "syscalls_builder_build_open_v2".to_string(), description: "Build 'open' via SyscallBuilder and report prototype/input_arg_count/has_output_args.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SyscallsBuilderBuildOpenV2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_syscalls::{SyscallBuilder, OsFamily, SyscallArch, SyscallType, ArgDirection, SyscallCategory, RiskLevel}; let s = SyscallBuilder::new(2, "open", OsFamily::Linux, SyscallArch::X86_64).arg("path", SyscallType::String, ArgDirection::In).arg("flags", SyscallType::Int, ArgDirection::In).opt_arg("mode", SyscallType::Mode, ArgDirection::In).returns(SyscallType::Fd).category(SyscallCategory::FileSystem).risk(RiskLevel::Low).alias("open64").build(); Ok(ToolResult::text(json!({"name":s.name,"number":s.number,"prototype":s.prototype(),"input_arg_count":s.input_arg_count(),"has_output_args":s.has_output_args(),"aliases":s.aliases,"source":"rustre_syscalls::SyscallBuilder::build"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (SyscallsCategorizeByNameTool::definition(), Box::new(SyscallsCategorizeByNameTool)),
        (SyscallsEstimateRiskTool::definition(), Box::new(SyscallsEstimateRiskTool)),
        (SyscallsIa32ToX8664NrTool::definition(), Box::new(SyscallsIa32ToX8664NrTool)),
        (SyscallsCrossArchTableTool::definition(), Box::new(SyscallsCrossArchTableTool)),
        (SyscallsLookupCrossArchTool::definition(), Box::new(SyscallsLookupCrossArchTool)),
        (SyscallsFormatCrossArchTableTool::definition(), Box::new(SyscallsFormatCrossArchTableTool)),
        (SyscallsDetectIa32MechanismTool::definition(), Box::new(SyscallsDetectIa32MechanismTool)),
        (SyscallsWin10Syscalls22H2Tool::definition(), Box::new(SyscallsWin10Syscalls22H2Tool)),
        (SyscallsTableNumberToNameTool::definition(), Box::new(SyscallsTableNumberToNameTool)),
        (SyscallsTableNameToNumberTool::definition(), Box::new(SyscallsTableNameToNumberTool)),
        (SyscallsTableLinuxX8664ListTool::definition(), Box::new(SyscallsTableLinuxX8664ListTool)),
        (SyscallsTableLinuxArm64ListTool::definition(), Box::new(SyscallsTableLinuxArm64ListTool)),
        (SyscallsTableWindowsX64ListTool::definition(), Box::new(SyscallsTableWindowsX64ListTool)),
        (SyscallsDatabaseStatsTool::definition(), Box::new(SyscallsDatabaseStatsTool)),
        (SyscallsSignalNameTool::definition(), Box::new(SyscallsSignalNameTool)),
        (SyscallsErrnoNameTool::definition(), Box::new(SyscallsErrnoNameTool)),
        (SyscallsSignalNameLookupTool::definition(), Box::new(SyscallsSignalNameLookupTool)),
        (SyscallsErrnoNameLookupTool::definition(), Box::new(SyscallsErrnoNameLookupTool)),
        (SyscallsSignalNameLookupWireTool::definition(), Box::new(SyscallsSignalNameLookupWireTool)),
        (SyscallsErrnoNameLookupWireTool::definition(), Box::new(SyscallsErrnoNameLookupWireTool)),
        (SyscallsClockIdNameV2Tool::definition(), Box::new(SyscallsClockIdNameV2Tool)),
        (SyscallsSaFamilyNameV2Tool::definition(), Box::new(SyscallsSaFamilyNameV2Tool)),
        (SyscallsDecodeArgFdV2Tool::definition(), Box::new(SyscallsDecodeArgFdV2Tool)),
        (SyscallsDecodeArgSignalV2Tool::definition(), Box::new(SyscallsDecodeArgSignalV2Tool)),
        (SyscallsDecodeArgIpAddrV2Tool::definition(), Box::new(SyscallsDecodeArgIpAddrV2Tool)),
        (SyscallsTableMaxNumberX8664V2Tool::definition(), Box::new(SyscallsTableMaxNumberX8664V2Tool)),
        (SyscallsDatabaseEmptyStatsV2Tool::definition(), Box::new(SyscallsDatabaseEmptyStatsV2Tool)),
        (SyscallsTraceEmptyErrorRateV2Tool::definition(), Box::new(SyscallsTraceEmptyErrorRateV2Tool)),
        (SyscallsSeccompPolicyEvaluateV2Tool::definition(), Box::new(SyscallsSeccompPolicyEvaluateV2Tool)),
        (SyscallsCallPrefixFlagsV2Tool::definition(), Box::new(SyscallsCallPrefixFlagsV2Tool)),
        (SyscallsFormatterFormatArgFdV2Tool::definition(), Box::new(SyscallsFormatterFormatArgFdV2Tool)),
        (SyscallsBuilderBuildOpenV2Tool::definition(), Box::new(SyscallsBuilderBuildOpenV2Tool)),
    ]
}
