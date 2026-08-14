//! MCP wrappers for the rustre-debug_unicorn crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes, hex_encode};
use crate::wire_tools::{__du_parse_faultkind, __du_parse_granularity, __du_parse_watchkind_v2, __mem_hex_decode_v2, du_parse_arch, du_parse_watchkind};

pub struct DebugUnicornMemRegionPermsTool;

pub struct DebugUnicornArchPointerSizeTool;

pub struct DebugUnicornTraceEntryBuildTool;
impl DebugUnicornTraceEntryBuildTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_unicorn_trace_entry_build".to_string(),
            description: "Construct a rustre_debug_unicorn::TraceEntry and return its display form.".to_string(),
            input_schema: json!({"type":"object","properties":{"address":{"type":"integer"},"next_pc":{"type":"integer"},"raw_hex":{"type":"string"},"mnemonic":{"type":"string"},"seq":{"type":"integer"},"thread_id":{"type":"integer"}},"required":["address","mnemonic"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugUnicornTraceEntryBuildTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let address = args.get("address").and_then(Value::as_u64).unwrap_or(0);
        let next_pc = args.get("next_pc").and_then(Value::as_u64).unwrap_or(address);
        let raw_hex = args.get("raw_hex").and_then(Value::as_str).unwrap_or("");
        let raw = args_to_bytes(&json!({"hex": raw_hex})).unwrap_or_default();
        let mnemonic = args.get("mnemonic").and_then(Value::as_str).unwrap_or("");
        let seq = args.get("seq").and_then(Value::as_u64).unwrap_or(0);
        let thread_id = args.get("thread_id").and_then(Value::as_u64).unwrap_or(0) as u32;
        let e = rustre_debug_unicorn::TraceEntry::new(address, next_pc, &raw, mnemonic, seq, thread_id);
        Ok(ToolResult::text(json!({"display": e.to_string(),"bytes_hex": hex_encode(e.bytes()),"raw_len": e.raw_len,"source":"rustre_debug_unicorn::TraceEntry"}).to_string()))
    }
}

pub struct DebugUnicornInstructionTraceStatsTool;
impl DebugUnicornInstructionTraceStatsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_unicorn_instruction_trace_stats".to_string(),
            description: "Push a list of TraceEntries into an InstructionTrace and return summary stats.".to_string(),
            input_schema: json!({"type":"object","properties":{"capacity":{"type":"integer"},"entries":{"type":"array"},"filter_mnemonic":{"type":"string"},"range_start":{"type":"integer"},"range_end":{"type":"integer"}},"required":["entries"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugUnicornInstructionTraceStatsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cap = args.get("capacity").and_then(Value::as_u64).unwrap_or(0) as usize;
        let mut trace = rustre_debug_unicorn::InstructionTrace::new(cap);
        let entries = args.get("entries").and_then(Value::as_array).cloned().unwrap_or_default();
        for (i, e) in entries.iter().enumerate() {
            let addr = e.get("address").and_then(Value::as_u64).unwrap_or(0);
            let next_pc = e.get("next_pc").and_then(Value::as_u64).unwrap_or(addr);
            let mnem = e.get("mnemonic").and_then(Value::as_str).unwrap_or("");
            let seq = e.get("seq").and_then(Value::as_u64).unwrap_or(i as u64);
            let tid = e.get("thread_id").and_then(Value::as_u64).unwrap_or(0) as u32;
            let raw_hex = e.get("raw_hex").and_then(Value::as_str).unwrap_or("");
            let raw = args_to_bytes(&json!({"hex": raw_hex})).unwrap_or_default();
            trace.push(rustre_debug_unicorn::TraceEntry::new(addr, next_pc, &raw, mnem, seq, tid));
        }
        let filter_hits = args.get("filter_mnemonic").and_then(Value::as_str).map(|p| trace.filter_mnemonic(p).len()).unwrap_or(0);
        let range_hits = match (args.get("range_start").and_then(Value::as_u64), args.get("range_end").and_then(Value::as_u64)) {
            (Some(s), Some(e)) => trace.in_range(s, e).len(),
            _ => 0,
        };
        Ok(ToolResult::text(json!({"len":trace.len(),"is_empty":trace.is_empty(),"unique_addresses":trace.unique_addresses().len(),"first":trace.first().map(std::string::ToString::to_string),"last":trace.last().map(std::string::ToString::to_string),"filter_mnemonic_hits":filter_hits,"range_hits":range_hits,"text":trace.to_text(),"source":"rustre_debug_unicorn::InstructionTrace"}).to_string()))
    }
}

pub struct DebugUnicornWatchpointProbeTool;
impl DebugUnicornWatchpointProbeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_unicorn_watchpoint_probe".to_string(),
            description: "Create a Watchpoint(address,size,kind) and test covers/matches for a probe access.".to_string(),
            input_schema: json!({"type":"object","properties":{"address":{"type":"integer"},"size":{"type":"integer"},"kind":{"type":"string"},"probe_addr":{"type":"integer"},"probe_kind":{"type":"string"}},"required":["address","size","kind"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugUnicornWatchpointProbeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("address").and_then(Value::as_u64).unwrap_or(0);
        let size = args.get("size").and_then(Value::as_u64).unwrap_or(0) as usize;
        let kind_s = args.get("kind").and_then(Value::as_str).unwrap_or("read");
        let kind = du_parse_watchkind(kind_s)?;
        let w = rustre_debug_unicorn::Watchpoint::new(1, addr, size, kind);
        let probe_addr = args.get("probe_addr").and_then(Value::as_u64).unwrap_or(addr);
        let probe_kind = du_parse_watchkind(args.get("probe_kind").and_then(Value::as_str).unwrap_or(kind_s))?;
        Ok(ToolResult::text(json!({"display":w.to_string(),"covers":w.covers(probe_addr),"matches":w.matches(probe_kind),"source":"rustre_debug_unicorn::Watchpoint"}).to_string()))
    }
}

pub struct DebugUnicornWatchpointManagerSimulateTool;
impl DebugUnicornWatchpointManagerSimulateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_unicorn_watchpoint_manager_simulate".to_string(),
            description: "Add watchpoints and simulate access checks; report which watchpoints fired.".to_string(),
            input_schema: json!({"type":"object","properties":{"watches":{"type":"array"},"accesses":{"type":"array"}},"required":["watches","accesses"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugUnicornWatchpointManagerSimulateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut m = rustre_debug_unicorn::WatchpointManager::new();
        let mut ids = Vec::new();
        for w in args.get("watches").and_then(Value::as_array).cloned().unwrap_or_default() {
            let a = w.get("address").and_then(Value::as_u64).unwrap_or(0);
            let s = w.get("size").and_then(Value::as_u64).unwrap_or(1) as usize;
            let k = du_parse_watchkind(w.get("kind").and_then(Value::as_str).unwrap_or("read"))?;
            ids.push(m.add(a, s, k));
        }
        let mut fired_log = Vec::new();
        for acc in args.get("accesses").and_then(Value::as_array).cloned().unwrap_or_default() {
            let a = acc.get("address").and_then(Value::as_u64).unwrap_or(0);
            let k = du_parse_watchkind(acc.get("kind").and_then(Value::as_str).unwrap_or("read"))?;
            fired_log.push(json!({"address": a, "fired": m.check(a, k)}));
        }
        Ok(ToolResult::text(json!({"ids":ids,"total_hits":m.total_hits(),"watchpoint_count":m.all().len(),"fired":fired_log,"source":"rustre_debug_unicorn::WatchpointManager"}).to_string()))
    }
}

pub struct DebugUnicornCoverageMapReportTool;
impl DebugUnicornCoverageMapReportTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_unicorn_coverage_map_report".to_string(),
            description: "Build a CoverageMap, record addresses, and return covered count + ratio.".to_string(),
            input_schema: json!({"type":"object","properties":{"granularity":{"type":"string"},"regions":{"type":"array"},"addresses":{"type":"array"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugUnicornCoverageMapReportTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_debug_unicorn::CoverageGranularity as G;
        let g = match args.get("granularity").and_then(Value::as_str).unwrap_or("instruction") {
            "instruction" => G::Instruction,
            "cache_line" | "cacheline" => G::CacheLine,
            "page" => G::Page,
            other => return Err(McpError::InvalidParams(format!("granularity: '{other}'"))),
        };
        let mut m = rustre_debug_unicorn::CoverageMap::new(g);
        for r in args.get("regions").and_then(Value::as_array).cloned().unwrap_or_default() {
            let arr = r.as_array().cloned().unwrap_or_default();
            if arr.len() == 2 {
                let s = arr[0].as_u64().unwrap_or(0);
                let e = arr[1].as_u64().unwrap_or(0);
                m.register_region(s, e);
            }
        }
        for a in args.get("addresses").and_then(Value::as_array).cloned().unwrap_or_default() {
            if let Some(u) = a.as_u64() { m.record(u); }
        }
        Ok(ToolResult::text(json!({"covered_count":m.covered_count(),"coverage_ratio":m.coverage_ratio(),"sorted_addresses":m.sorted_addresses(),"source":"rustre_debug_unicorn::CoverageMap"}).to_string()))
    }
}

pub struct DebugUnicornCoverageMapMergeTool;
impl DebugUnicornCoverageMapMergeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_unicorn_coverage_map_merge".to_string(),
            description: "Merge two instruction-level coverage sets; report merged size and new-addr delta.".to_string(),
            input_schema: json!({"type":"object","properties":{"base":{"type":"array"},"other":{"type":"array"}},"required":["base","other"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugUnicornCoverageMapMergeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut base = rustre_debug_unicorn::CoverageMap::instruction_level();
        let mut other = rustre_debug_unicorn::CoverageMap::instruction_level();
        for a in args.get("base").and_then(Value::as_array).cloned().unwrap_or_default() { if let Some(u) = a.as_u64() { base.record(u); } }
        for a in args.get("other").and_then(Value::as_array).cloned().unwrap_or_default() { if let Some(u) = a.as_u64() { other.record(u); } }
        let new_addrs = base.new_coverage(&other);
        base.merge(&other);
        Ok(ToolResult::text(json!({"merged_count":base.covered_count(),"new_addresses":new_addrs,"sorted":base.sorted_addresses(),"source":"rustre_debug_unicorn::CoverageMap::merge"}).to_string()))
    }
}

pub struct DebugUnicornSymbolTableResolveTool;
impl DebugUnicornSymbolTableResolveTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_unicorn_symbol_table_resolve".to_string(),
            description: "Build a SymbolTable and resolve address->symbol+offset / name->address.".to_string(),
            input_schema: json!({"type":"object","properties":{"symbols":{"type":"array"},"query_addr":{"type":"integer"},"query_name":{"type":"string"},"prefix":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugUnicornSymbolTableResolveTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut t = rustre_debug_unicorn::SymbolTable::new();
        for s in args.get("symbols").and_then(Value::as_array).cloned().unwrap_or_default() {
            let addr = s.get("address").and_then(Value::as_u64).unwrap_or(0);
            let name = s.get("name").and_then(Value::as_str).unwrap_or("").to_string();
            let module = s.get("module").and_then(Value::as_str);
            let size = s.get("size").and_then(Value::as_u64);
            let sym = match (module, size) {
                (Some(m), Some(sz)) => rustre_debug_unicorn::Symbol::with_meta(addr, name, m, sz),
                _ => rustre_debug_unicorn::Symbol::new(addr, name),
            };
            t.add(sym);
        }
        let addr_q = args.get("query_addr").and_then(Value::as_u64);
        let name_q = args.get("query_name").and_then(Value::as_str);
        let prefix = args.get("prefix").and_then(Value::as_str);
        Ok(ToolResult::text(json!({"count":t.count(),"resolve_addr_display":addr_q.map(|a| t.format_address(a)),"resolve_name_addr":name_q.and_then(|n| t.resolve_name(n)),"prefix_hits":prefix.map(|p| t.search_prefix(p).len()),"sorted_names":t.sorted().iter().map(|s| s.to_string()).collect::<Vec<_>>(),"source":"rustre_debug_unicorn::SymbolTable"}).to_string()))
    }
}

pub struct DebugUnicornCodePatcherApplyTool;
impl DebugUnicornCodePatcherApplyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_unicorn_code_patcher_apply".to_string(),
            description: "Register/apply/revert byte patches via CodePatcher.".to_string(),
            input_schema: json!({"type":"object","properties":{"patches":{"type":"array"},"apply_indices":{"type":"array"},"revert_indices":{"type":"array"},"query_addr":{"type":"integer"},"query_size":{"type":"integer"}},"required":["patches"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugUnicornCodePatcherApplyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut p = rustre_debug_unicorn::CodePatcher::new();
        for entry in args.get("patches").and_then(Value::as_array).cloned().unwrap_or_default() {
            let addr = entry.get("address").and_then(Value::as_u64).unwrap_or(0);
            let orig_hex = entry.get("original_hex").and_then(Value::as_str).unwrap_or("");
            let patched_hex = entry.get("patched_hex").and_then(Value::as_str).unwrap_or("");
            let orig = args_to_bytes(&json!({"hex": orig_hex})).unwrap_or_default();
            let patched = args_to_bytes(&json!({"hex": patched_hex})).unwrap_or_default();
            p.register(addr, orig, patched);
        }
        for i in args.get("apply_indices").and_then(Value::as_array).cloned().unwrap_or_default() { if let Some(u) = i.as_u64() { let _ = p.apply(u as usize); } }
        for i in args.get("revert_indices").and_then(Value::as_array).cloned().unwrap_or_default() { if let Some(u) = i.as_u64() { let _ = p.revert(u as usize); } }
        let q_addr = args.get("query_addr").and_then(Value::as_u64).unwrap_or(0);
        let q_size = args.get("query_size").and_then(Value::as_u64).unwrap_or(0) as usize;
        let q_hits = if q_size > 0 { p.patches_at(q_addr, q_size).len() } else { 0 };
        Ok(ToolResult::text(json!({"count":p.count(),"applied_count":p.applied_count(),"records":p.all().iter().map(std::string::ToString::to_string).collect::<Vec<_>>(),"query_hits":q_hits,"source":"rustre_debug_unicorn::CodePatcher"}).to_string()))
    }
}

pub struct DebugUnicornThreadSimulateTool;
impl DebugUnicornThreadSimulateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_unicorn_thread_simulate".to_string(),
            description: "Spawn/step/suspend/exit simulated threads via ThreadSimulator.".to_string(),
            input_schema: json!({"type":"object","properties":{"spawns":{"type":"array"},"steps":{"type":"integer"},"stride":{"type":"integer"},"suspend_tid":{"type":"integer"},"exit_tid":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugUnicornThreadSimulateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut sim = rustre_debug_unicorn::ThreadSimulator::new();
        let mut tids = Vec::new();
        for s in args.get("spawns").and_then(Value::as_array).cloned().unwrap_or_default() {
            let pc = s.get("pc").and_then(Value::as_u64).unwrap_or(0);
            let sp = s.get("sp").and_then(Value::as_u64).unwrap_or(0);
            tids.push(sim.spawn(pc, sp));
        }
        let stride = args.get("stride").and_then(Value::as_u64).unwrap_or(1);
        let steps = args.get("steps").and_then(Value::as_u64).unwrap_or(0);
        let mut final_pc = None;
        for _ in 0..steps { final_pc = sim.step_current(stride); }
        if let Some(t) = args.get("suspend_tid").and_then(Value::as_u64) { sim.suspend(t as u32); }
        if let Some(t) = args.get("exit_tid").and_then(Value::as_u64) { sim.exit(t as u32); }
        Ok(ToolResult::text(json!({"spawned_tids":tids,"count":sim.count(),"tids":sim.tids(),"current":sim.current(),"running_count":sim.running().len(),"final_pc":final_pc,"source":"rustre_debug_unicorn::ThreadSimulator"}).to_string()))
    }
}

pub struct DebugUnicornScriptGenTool;
impl DebugUnicornScriptGenTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_unicorn_script_gen".to_string(),
            description: "Generate boilerplate Unicorn scripts (hello/trace/watchpoint) for python/rust/c.".to_string(),
            input_schema: json!({"type":"object","properties":{"arch":{"type":"string"},"target":{"type":"string"},"kind":{"type":"string"},"start":{"type":"integer"},"end":{"type":"integer"},"addr":{"type":"integer"},"size":{"type":"integer"}},"required":["arch","target","kind"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugUnicornScriptGenTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_debug_unicorn::ScriptTarget as T;
        let arch = du_parse_arch(args.get("arch").and_then(Value::as_str).unwrap_or("x86_64"))?;
        let target = match args.get("target").and_then(Value::as_str).unwrap_or("python") {
            "python" | "py" => T::Python,
            "rust" | "rs" => T::Rust,
            "c" => T::C,
            other => return Err(McpError::InvalidParams(format!("target: '{other}'"))),
        };
        let g = rustre_debug_unicorn::EmulatorScriptGen::new(arch, target);
        let kind = args.get("kind").and_then(Value::as_str).unwrap_or("hello");
        let script = match kind {
            "hello" => g.hello_world(),
            "trace" => g.trace_script(args.get("start").and_then(Value::as_u64).unwrap_or(0x1000), args.get("end").and_then(Value::as_u64).unwrap_or(0x2000)),
            "watchpoint" | "watch" => g.watchpoint_script(args.get("addr").and_then(Value::as_u64).unwrap_or(0x1000), args.get("size").and_then(Value::as_u64).unwrap_or(4)),
            other => return Err(McpError::InvalidParams(format!("kind: '{other}'"))),
        };
        Ok(ToolResult::text(json!({"script":script,"lines":script.lines().count(),"source":"rustre_debug_unicorn::EmulatorScriptGen"}).to_string()))
    }
}

pub struct DebugUnicornHookRecordDescribeTool;
impl DebugUnicornHookRecordDescribeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_unicorn_hook_record_describe".to_string(),
            description: "Construct a rustre_debug_unicorn::HookRecord and return its display form.".to_string(),
            input_schema: json!({"type":"object","properties":{"hook_id":{"type":"integer"},"hook_type":{"type":"string"},"address":{"type":"integer"},"size":{"type":"integer"}},"required":["hook_type"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugUnicornHookRecordDescribeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_debug_unicorn::HookType as H;
        let ht = match args.get("hook_type").and_then(Value::as_str).unwrap_or("code") {
            "code" => H::Code,
            "mem_read" => H::MemRead,
            "mem_write" => H::MemWrite,
            "mem_invalid" => H::MemInvalid,
            "interrupt" => H::Interrupt,
            other => return Err(McpError::InvalidParams(format!("hook_type: '{other}'"))),
        };
        let rec = rustre_debug_unicorn::HookRecord {
            hook_id: args.get("hook_id").and_then(Value::as_u64).unwrap_or(1),
            hook_type: ht.clone(),
            address: args.get("address").and_then(Value::as_u64).unwrap_or(0),
            size: args.get("size").and_then(Value::as_u64).unwrap_or(0) as usize,
        };
        Ok(ToolResult::text(json!({"display":rec.to_string(),"hook_type":ht.to_string(),"source":"rustre_debug_unicorn::HookRecord"}).to_string()))
    }
}

pub struct DebugUnicornEmulateStepsTool;
impl DebugUnicornEmulateStepsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_unicorn_emulate_steps".to_string(),
            description: "Create UnicornDebugger, map memory, install hooks, run emulate() and report state.".to_string(),
            input_schema: json!({"type":"object","properties":{"arch":{"type":"string"},"regions":{"type":"array"},"hooks":{"type":"array"},"begin":{"type":"integer"},"until":{"type":"integer"},"steps":{"type":"integer"}},"required":["arch"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugUnicornEmulateStepsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_debug_unicorn::HookType as H;
        let arch = du_parse_arch(args.get("arch").and_then(Value::as_str).unwrap_or("x86_64"))?;
        let mut dbg = rustre_debug_unicorn::UnicornDebugger::new(arch);
        for r in args.get("regions").and_then(Value::as_array).cloned().unwrap_or_default() {
            let a = r.get("addr").and_then(Value::as_u64).unwrap_or(0);
            let s = r.get("size").and_then(Value::as_u64).unwrap_or(0);
            let p = r.get("perms").and_then(Value::as_u64).unwrap_or(7) as u8;
            let _ = dbg.map_memory(a, s, p);
        }
        for h in args.get("hooks").and_then(Value::as_array).cloned().unwrap_or_default() {
            let ht = match h.get("kind").and_then(Value::as_str).unwrap_or("code") {
                "code" => H::Code,
                "mem_read" => H::MemRead,
                "mem_write" => H::MemWrite,
                "mem_invalid" => H::MemInvalid,
                "interrupt" => H::Interrupt,
                _ => H::Code,
            };
            let a = h.get("addr").and_then(Value::as_u64).unwrap_or(0);
            let _ = dbg.add_hook(ht, a);
        }
        let begin = args.get("begin").and_then(Value::as_u64).unwrap_or(0);
        let until = args.get("until").and_then(Value::as_u64).unwrap_or(begin + 0x100);
        let steps = args.get("steps").and_then(Value::as_u64).unwrap_or(4);
        dbg.set_running(true);
        let end_pc = dbg.emulate(begin, until, steps).map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({"final_pc":end_pc,"mem_regions":dbg.mem_regions().iter().map(std::string::ToString::to_string).collect::<Vec<_>>(),"installed_hooks":dbg.installed_hooks().iter().map(std::string::ToString::to_string).collect::<Vec<_>>(),"source":"rustre_debug_unicorn::UnicornDebugger::emulate"}).to_string()))
    }
}

pub struct DebugUnicornFaultInjectorRunTool;
impl DebugUnicornFaultInjectorRunTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_unicorn_fault_injector_run".to_string(),
            description: "Add fault rules and simulate check_and_fire() for a probe address list.".to_string(),
            input_schema: json!({"type":"object","properties":{"rules":{"type":"array"},"probe_addrs":{"type":"array"}},"required":["rules"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugUnicornFaultInjectorRunTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_debug_unicorn::FaultKind as F;
        let mut inj = rustre_debug_unicorn::FaultInjector::default();
        for r in args.get("rules").and_then(Value::as_array).cloned().unwrap_or_default() {
            let a = r.get("address").and_then(Value::as_u64).unwrap_or(0);
            let param = r.get("param").and_then(Value::as_u64).unwrap_or(0);
            let kind = match r.get("kind").and_then(Value::as_str).unwrap_or("mem_read_replace") {
                "mem_read_replace" => F::MemReadReplace,
                "mem_read_fault" => F::MemReadFault,
                "mem_write_fault" => F::MemWriteFault,
                "bit_flip" => F::BitFlip,
                "register_corrupt" => F::RegisterCorrupt,
                "force_branch" => F::ForceBranch,
                other => return Err(McpError::InvalidParams(format!("kind: '{other}'"))),
            };
            let _ = inj.add_rule(a, kind, param);
        }
        let mut fires = Vec::new();
        for a in args.get("probe_addrs").and_then(Value::as_array).cloned().unwrap_or_default() {
            if let Some(u) = a.as_u64() {
                if let Some((k, v)) = inj.check_and_fire(u) {
                    fires.push(json!({"addr": u, "kind": k.to_string(), "param": v}));
                }
            }
        }
        Ok(ToolResult::text(json!({"rule_count":inj.rules().len(),"total_fires":inj.total_fires(),"fires":fires,"source":"rustre_debug_unicorn::FaultInjector"}).to_string()))
    }
}

pub struct DebugUnicornRegisterHistoryDiffTool;
impl DebugUnicornRegisterHistoryDiffTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug_unicorn_register_history_diff".to_string(),
            description: "Push register snapshots and diff first vs latest to list changed registers.".to_string(),
            input_schema: json!({"type":"object","properties":{"capacity":{"type":"integer"},"snapshots":{"type":"array"}},"required":["snapshots"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DebugUnicornRegisterHistoryDiffTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cap = args.get("capacity").and_then(Value::as_u64).unwrap_or(16).max(1) as usize;
        let mut h = rustre_debug_unicorn::RegisterHistory::new(cap);
        for (i, s) in args.get("snapshots").and_then(Value::as_array).cloned().unwrap_or_default().iter().enumerate() {
            let seq = s.get("seq").and_then(Value::as_u64).unwrap_or(i as u64);
            let pc = s.get("pc").and_then(Value::as_u64).unwrap_or(0);
            let mut regs = std::collections::HashMap::new();
            if let Some(obj) = s.get("regs").and_then(Value::as_object) {
                for (k, v) in obj {
                    if let Some(u) = v.as_u64() { regs.insert(k.clone(), u); }
                }
            }
            h.push(rustre_debug_unicorn::RegisterSnapshot::new(seq, pc, regs));
        }
        let diff = match (h.oldest(), h.latest()) {
            (Some(o), Some(l)) => o.diff(l),
            _ => Vec::new(),
        };
        Ok(ToolResult::text(json!({"len":h.len(),"diff_first_last":diff,"latest_pc":h.latest().map(|s| s.pc),"source":"rustre_debug_unicorn::RegisterHistory"}).to_string()))
    }
}

pub struct DebugUnicornMemRegionFlagsTool;
impl DebugUnicornMemRegionFlagsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_mem_region_flags".to_string(), description: "MemRegion perm flags.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"size":{"type":"integer"},"perms":{"type":"integer"}},"required":["addr","size","perms"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DebugUnicornMemRegionFlagsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0);
    let size = args.get("size").and_then(Value::as_u64).unwrap_or(0);
    let perms = args.get("perms").and_then(Value::as_u64).unwrap_or(0) as u8;
    let r = rustre_debug_unicorn::MemRegion { addr, size, perms };
    Ok(ToolResult::text(json!({"readable":r.readable(),"writable":r.writable(),"executable":r.executable(),"display":r.to_string(),"source":"rustre_debug_unicorn::MemRegion"}).to_string()))
} }

pub struct DebugUnicornTraceEntryBytesTool;
impl DebugUnicornTraceEntryBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_trace_entry_bytes".to_string(), description: "TraceEntry bytes as hex.".to_string(), input_schema: json!({"type":"object","properties":{"address":{"type":"integer"},"next_pc":{"type":"integer"},"raw_hex":{"type":"string"},"mnemonic":{"type":"string"},"seq":{"type":"integer"},"thread_id":{"type":"integer"}},"required":["address","mnemonic"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DebugUnicornTraceEntryBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let address = args.get("address").and_then(Value::as_u64).unwrap_or(0);
    let next_pc = args.get("next_pc").and_then(Value::as_u64).unwrap_or(address);
    let raw = args_to_bytes(&json!({"hex": args.get("raw_hex").and_then(Value::as_str).unwrap_or("")})).unwrap_or_default();
    let mnemonic = args.get("mnemonic").and_then(Value::as_str).unwrap_or("");
    let seq = args.get("seq").and_then(Value::as_u64).unwrap_or(0);
    let thread_id = args.get("thread_id").and_then(Value::as_u64).unwrap_or(0) as u32;
    let e = rustre_debug_unicorn::TraceEntry::new(address, next_pc, &raw, mnemonic, seq, thread_id);
    Ok(ToolResult::text(json!({"bytes_hex":hex_encode(e.bytes()),"raw_len":e.raw_len,"display":e.to_string(),"source":"rustre_debug_unicorn::TraceEntry::bytes"}).to_string()))
} }

pub struct DebugUnicornSnapshotManagerOpsTool;
impl DebugUnicornSnapshotManagerOpsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_snapshot_manager_ops".to_string(), description: "SnapshotManager save/find/labels.".to_string(), input_schema: json!({"type":"object","properties":{"snapshots":{"type":"array"},"find_label":{"type":"string"}},"required":["snapshots"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DebugUnicornSnapshotManagerOpsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let mut mgr = rustre_debug_unicorn::SnapshotManager::new();
    let mut ids = Vec::new();
    for s in args.get("snapshots").and_then(Value::as_array).cloned().unwrap_or_default() {
        let label = s.get("label").and_then(Value::as_str).unwrap_or("snap").to_string();
        let seq = s.get("seq").and_then(Value::as_u64).unwrap_or(0);
        let mut regs = std::collections::HashMap::new();
        if let Some(rmap) = s.get("registers").and_then(Value::as_object) { for (k, v) in rmap { regs.insert(k.clone(), v.as_u64().unwrap_or(0)); } }
        ids.push(mgr.save(label, seq, regs, std::collections::HashMap::new()));
    }
    let found = args.get("find_label").and_then(Value::as_str).and_then(|l| mgr.find_by_label(l)).map(std::string::ToString::to_string);
    Ok(ToolResult::text(json!({"ids":ids,"count":mgr.count(),"labels":mgr.labels(),"found":found,"source":"rustre_debug_unicorn::SnapshotManager"}).to_string()))
} }

pub struct DebugUnicornSymbolTableFormatTool;
impl DebugUnicornSymbolTableFormatTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_symbol_table_format".to_string(), description: "SymbolTable populate/format/resolve/search.".to_string(), input_schema: json!({"type":"object","properties":{"symbols":{"type":"array"},"format_addr":{"type":"integer"},"resolve_name":{"type":"string"},"prefix":{"type":"string"}},"required":["symbols"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DebugUnicornSymbolTableFormatTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let mut tbl = rustre_debug_unicorn::SymbolTable::new();
    for s in args.get("symbols").and_then(Value::as_array).cloned().unwrap_or_default() {
        let addr = s.get("address").and_then(Value::as_u64).unwrap_or(0);
        let name = s.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        if let (Some(m), Some(sz)) = (s.get("module").and_then(Value::as_str), s.get("size").and_then(Value::as_u64)) { tbl.add(rustre_debug_unicorn::Symbol::with_meta(addr, name, m, sz)); } else { tbl.define(addr, name); }
    }
    let formatted = args.get("format_addr").and_then(Value::as_u64).map(|a| tbl.format_address(a));
    let resolved = args.get("resolve_name").and_then(Value::as_str).and_then(|n| tbl.resolve_name(n));
    let prefix_hits = args.get("prefix").and_then(Value::as_str).map(|p| tbl.search_prefix(p).len()).unwrap_or(0);
    Ok(ToolResult::text(json!({"count":tbl.count(),"formatted":formatted,"resolved_name_addr":resolved,"prefix_hits":prefix_hits,"sorted_count":tbl.sorted().len(),"source":"rustre_debug_unicorn::SymbolTable"}).to_string()))
} }

pub struct DebugUnicornCoverageGranularityAlignTool;
impl DebugUnicornCoverageGranularityAlignTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_coverage_granularity_align".to_string(), description: "CoverageGranularity align.".to_string(), input_schema: json!({"type":"object","properties":{"granularity":{"type":"string"},"addr":{"type":"integer"}},"required":["granularity","addr"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DebugUnicornCoverageGranularityAlignTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let g = args.get("granularity").and_then(Value::as_str).unwrap_or("instruction");
    let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0);
    let gr = match g { "instruction" => rustre_debug_unicorn::CoverageGranularity::Instruction, "cache_line" => rustre_debug_unicorn::CoverageGranularity::CacheLine, "page" => rustre_debug_unicorn::CoverageGranularity::Page, other => return Err(McpError::InvalidParams(format!("granularity: unknown '{other}'"))) };
    Ok(ToolResult::text(json!({"aligned":gr.align(addr),"display":gr.to_string(),"source":"rustre_debug_unicorn::CoverageGranularity::align"}).to_string()))
} }

pub struct DebugUnicornFaultRuleShouldFireTool;
impl DebugUnicornFaultRuleShouldFireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_fault_rule_should_fire".to_string(), description: "FaultRule should_fire probe.".to_string(), input_schema: json!({"type":"object","properties":{"id":{"type":"integer"},"address":{"type":"integer"},"kind":{"type":"string"},"param":{"type":"integer"},"probe_addr":{"type":"integer"},"max_fires":{"type":"integer"},"enabled":{"type":"boolean"}},"required":["address","kind","probe_addr"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DebugUnicornFaultRuleShouldFireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    use rustre_debug_unicorn::FaultKind as F;
    let id = args.get("id").and_then(Value::as_u64).unwrap_or(1) as u32;
    let address = args.get("address").and_then(Value::as_u64).unwrap_or(0);
    let param = args.get("param").and_then(Value::as_u64).unwrap_or(0);
    let kind = match args.get("kind").and_then(Value::as_str).unwrap_or("bit_flip") { "mem_read_replace" => F::MemReadReplace, "mem_read_fault" => F::MemReadFault, "mem_write_fault" => F::MemWriteFault, "bit_flip" => F::BitFlip, "register_corrupt" => F::RegisterCorrupt, "force_branch" => F::ForceBranch, other => return Err(McpError::InvalidParams(format!("kind: unknown '{other}'"))) };
    let mut r = rustre_debug_unicorn::FaultRule::new(id, address, kind, param);
    if let Some(m) = args.get("max_fires").and_then(Value::as_u64) { r.max_fires = m as u32; }
    if let Some(e) = args.get("enabled").and_then(Value::as_bool) { r.enabled = e; }
    let probe = args.get("probe_addr").and_then(Value::as_u64).unwrap_or(address);
    Ok(ToolResult::text(json!({"should_fire":r.should_fire(probe),"display":r.to_string(),"kind":kind.to_string(),"source":"rustre_debug_unicorn::FaultRule::should_fire"}).to_string()))
} }

pub struct DebugUnicornSimulatedThreadStepTool;
impl DebugUnicornSimulatedThreadStepTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_simulated_thread_step".to_string(), description: "SimulatedThread step/suspend/resume.".to_string(), input_schema: json!({"type":"object","properties":{"tid":{"type":"integer"},"pc":{"type":"integer"},"sp":{"type":"integer"},"stride":{"type":"integer"},"steps":{"type":"integer"},"suspend_then_resume":{"type":"boolean"},"hit_bp":{"type":"boolean"}},"required":["pc","sp"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DebugUnicornSimulatedThreadStepTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let tid = args.get("tid").and_then(Value::as_u64).unwrap_or(1) as u32;
    let pc = args.get("pc").and_then(Value::as_u64).unwrap_or(0);
    let sp = args.get("sp").and_then(Value::as_u64).unwrap_or(0);
    let stride = args.get("stride").and_then(Value::as_u64).unwrap_or(4);
    let steps = args.get("steps").and_then(Value::as_u64).unwrap_or(1);
    let mut t = rustre_debug_unicorn::SimulatedThread::new(tid, pc, sp);
    for _ in 0..steps { t.step(stride); }
    if args.get("suspend_then_resume").and_then(Value::as_bool).unwrap_or(false) {
        t.suspend();
        let suspended_state = t.state.to_string();
        t.resume();
        return Ok(ToolResult::text(json!({"pc":t.pc,"instruction_count":t.instruction_count,"schedulable":t.is_schedulable(),"suspended_state":suspended_state,"final_state":t.state.to_string(),"display":t.to_string(),"source":"rustre_debug_unicorn::SimulatedThread"}).to_string()));
    }
    if args.get("hit_bp").and_then(Value::as_bool).unwrap_or(false) { t.hit_breakpoint(); }
    Ok(ToolResult::text(json!({"pc":t.pc,"instruction_count":t.instruction_count,"schedulable":t.is_schedulable(),"state":t.state.to_string(),"display":t.to_string(),"source":"rustre_debug_unicorn::SimulatedThread"}).to_string()))
} }

pub struct DebugUnicornThreadSimulatorSchedulingTool;
impl DebugUnicornThreadSimulatorSchedulingTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_thread_simulator_scheduling".to_string(), description: "ThreadSimulator spawn/step/exit.".to_string(), input_schema: json!({"type":"object","properties":{"threads":{"type":"array"},"stride":{"type":"integer"},"exit_tid":{"type":"integer"}},"required":["threads"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DebugUnicornThreadSimulatorSchedulingTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let mut sim = rustre_debug_unicorn::ThreadSimulator::new();
    let mut spawned = Vec::new();
    for t in args.get("threads").and_then(Value::as_array).cloned().unwrap_or_default() {
        let pc = t.get("pc").and_then(Value::as_u64).unwrap_or(0);
        let sp = t.get("sp").and_then(Value::as_u64).unwrap_or(0);
        spawned.push(sim.spawn(pc, sp));
    }
    let stride = args.get("stride").and_then(Value::as_u64).unwrap_or(4);
    let new_pc = sim.step_current(stride);
    let mut exited = false;
    if let Some(tid) = args.get("exit_tid").and_then(Value::as_u64) { exited = sim.exit(tid as u32); }
    Ok(ToolResult::text(json!({"tids":sim.tids(),"count":sim.count(),"current":sim.current(),"stepped_pc":new_pc,"running_count":sim.running().len(),"exited":exited,"spawned":spawned,"source":"rustre_debug_unicorn::ThreadSimulator"}).to_string()))
} }

pub struct DebugUnicornV2ConfigPresetsTool;
impl DebugUnicornV2ConfigPresetsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_v2_config_presets".to_string(), description: "v2::UnicornConfig preset.".to_string(), input_schema: json!({"type":"object","properties":{"preset":{"type":"string"}},"required":["preset"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DebugUnicornV2ConfigPresetsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let p = args.get("preset").and_then(Value::as_str).unwrap_or("x86_64");
    let cfg = match p { "x86_64" => rustre_debug_unicorn::v2::UnicornConfig::x86_64(), "arm64" => rustre_debug_unicorn::v2::UnicornConfig::arm64(), "arm_thumb" => rustre_debug_unicorn::v2::UnicornConfig::arm_thumb(), other => return Err(McpError::InvalidParams(format!("preset: unknown '{other}'"))) };
    Ok(ToolResult::text(json!({"arch":cfg.arch.to_string(),"mode":cfg.mode.to_string(),"stack_size":cfg.stack_size,"timeout_ms":cfg.timeout_ms,"pointer_size":cfg.arch.pointer_size(),"source":"rustre_debug_unicorn::v2::UnicornConfig"}).to_string()))
} }

pub struct DebugUnicornV2DebuggerEmulateTool;
impl DebugUnicornV2DebuggerEmulateTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_v2_debugger_emulate".to_string(), description: "v2 UnicornDebugger emulate.".to_string(), input_schema: json!({"type":"object","properties":{"preset":{"type":"string"},"map_base":{"type":"integer"},"map_hex":{"type":"string"},"reg_name":{"type":"string"},"reg_value":{"type":"integer"},"hooks":{"type":"array"},"start":{"type":"integer"},"end":{"type":"integer"}},"required":["start","end"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DebugUnicornV2DebuggerEmulateTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    use rustre_debug_unicorn::v2::{UnicornConfig, UnicornDebugger, HookType};
    let cfg = match args.get("preset").and_then(Value::as_str).unwrap_or("x86_64") { "x86_64" => UnicornConfig::x86_64(), "arm64" => UnicornConfig::arm64(), "arm_thumb" => UnicornConfig::arm_thumb(), other => return Err(McpError::InvalidParams(format!("preset: unknown '{other}'"))) };
    let mut d = UnicornDebugger::new(cfg);
    if let (Some(base), Some(hex)) = (args.get("map_base").and_then(Value::as_u64), args.get("map_hex").and_then(Value::as_str)) { let bytes = args_to_bytes(&json!({"hex": hex})).unwrap_or_default(); d.map_memory(base, bytes); }
    if let (Some(name), Some(val)) = (args.get("reg_name").and_then(Value::as_str), args.get("reg_value").and_then(Value::as_u64)) { d.set_reg(name.to_string(), val); }
    let mut hook_ids = Vec::new();
    for h in args.get("hooks").and_then(Value::as_array).cloned().unwrap_or_default() {
        let kind = match h.get("type").and_then(Value::as_str).unwrap_or("code") { "code" => HookType::Code, "mem_read" => HookType::MemRead, "mem_write" => HookType::MemWrite, "block" => HookType::Block, "interrupt" => HookType::Interrupt, "invalid" => HookType::Invalid, other => return Err(McpError::InvalidParams(format!("hook type: unknown '{other}'"))) };
        let desc = h.get("desc").and_then(Value::as_str).unwrap_or("").to_string();
        hook_ids.push(d.add_hook(kind, desc));
    }
    let start = args.get("start").and_then(Value::as_u64).unwrap_or(0);
    let end = args.get("end").and_then(Value::as_u64).unwrap_or(0);
    let r = d.emulate(start, end);
    Ok(ToolResult::text(json!({"instructions":r.instructions,"mem_reads":r.mem_reads,"mem_writes":r.mem_writes,"exit_addr":r.exit_addr,"error":r.error,"success":r.success(),"hook_count":d.hook_count(),"hook_ids":hook_ids,"source":"rustre_debug_unicorn::v2::UnicornDebugger::emulate"}).to_string()))
} }

pub struct DebugUnicornPatchRecordNewTool;
impl DebugUnicornPatchRecordNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_patch_record_new".to_string(), description: "PatchRecord new+size+display.".to_string(), input_schema: json!({"type":"object","properties":{"address":{"type":"integer"},"original_hex":{"type":"string"},"patched_hex":{"type":"string"}},"required":["address","original_hex","patched_hex"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DebugUnicornPatchRecordNewTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let address = args.get("address").and_then(Value::as_u64).unwrap_or(0);
    let orig = args_to_bytes(&json!({"hex": args.get("original_hex").and_then(Value::as_str).unwrap_or("")})).unwrap_or_default();
    let patched = args_to_bytes(&json!({"hex": args.get("patched_hex").and_then(Value::as_str).unwrap_or("")})).unwrap_or_default();
    let p = rustre_debug_unicorn::PatchRecord::new(address, orig, patched);
    Ok(ToolResult::text(json!({"size":p.size(),"applied":p.applied,"display":p.to_string(),"source":"rustre_debug_unicorn::PatchRecord"}).to_string()))
} }

pub struct DebugUnicornCoverageGranularityAlignV2Tool;
impl DebugUnicornCoverageGranularityAlignV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_coverage_granularity_align_v2".to_string(), description: "Align an address per rustre_debug_unicorn::CoverageGranularity.".to_string(), input_schema: json!({"type":"object","required":["granularity","addr"],"properties":{"granularity":{"type":"string"},"addr":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DebugUnicornCoverageGranularityAlignV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let g = __du_parse_granularity(args.get("granularity").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'granularity'".into()))?)?; let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; Ok(ToolResult::text(json!({"aligned":g.align(addr),"display":g.to_string(),"source":"rustre_debug_unicorn::CoverageGranularity::align"}).to_string())) } }

pub struct DebugUnicornRegionPermsFlagsV2Tool;
impl DebugUnicornRegionPermsFlagsV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_region_perms_flags_v2".to_string(), description: "Return rustre_debug_unicorn::RegionPerms preset flags.".to_string(), input_schema: json!({"type":"object","required":["preset"],"properties":{"preset":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DebugUnicornRegionPermsFlagsV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_debug_unicorn::RegionPerms as P; let p = match args.get("preset").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'preset'".into()))? { "r" => P::r(), "rw" => P::rw(), "rx" => P::rx(), "rwx" => P::rwx(), _ => return Err(McpError::InvalidParams("preset must be r|rw|rx|rwx".into())) }; Ok(ToolResult::text(json!({"read":p.read,"write":p.write,"execute":p.execute,"source":"rustre_debug_unicorn::RegionPerms"}).to_string())) } }

pub struct DebugUnicornMappedRegionContainsV2Tool;
impl DebugUnicornMappedRegionContainsV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_mapped_region_contains_v2".to_string(), description: "Check MappedRegion::contains and overlaps via rustre_debug_unicorn.".to_string(), input_schema: json!({"type":"object","required":["addr","size","probe"],"properties":{"addr":{"type":"integer","minimum":0},"size":{"type":"integer","minimum":1},"probe":{"type":"integer","minimum":0},"other_addr":{"type":"integer","minimum":0},"other_size":{"type":"integer","minimum":1}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DebugUnicornMappedRegionContainsV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))?; let probe = args.get("probe").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'probe'".into()))?; let r = rustre_debug_unicorn::MappedRegion { addr, size, perms: rustre_debug_unicorn::RegionPerms::rw() }; let ov = match (args.get("other_addr").and_then(Value::as_u64), args.get("other_size").and_then(Value::as_u64)) { (Some(a), Some(s)) => Some(r.overlaps(a, s)), _ => None }; Ok(ToolResult::text(json!({"contains":r.contains(probe),"end":r.end(),"overlaps":ov,"source":"rustre_debug_unicorn::MappedRegion"}).to_string())) } }

pub struct DebugUnicornMemoryMapperMapV2Tool;
impl DebugUnicornMemoryMapperMapV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_memory_mapper_map_v2".to_string(), description: "Map two regions via rustre_debug_unicorn::UnicornMemoryMapper and report totals.".to_string(), input_schema: json!({"type":"object","required":["a_addr","a_size","b_addr","b_size"],"properties":{"a_addr":{"type":"integer","minimum":0},"a_size":{"type":"integer","minimum":1},"b_addr":{"type":"integer","minimum":0},"b_size":{"type":"integer","minimum":1}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DebugUnicornMemoryMapperMapV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let aa = args.get("a_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_addr'".into()))?; let as_ = args.get("a_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_size'".into()))?; let ba = args.get("b_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_addr'".into()))?; let bs = args.get("b_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_size'".into()))?; let mut m = rustre_debug_unicorn::UnicornMemoryMapper::new(); let ra = m.map_region(aa, as_, rustre_debug_unicorn::RegionPerms::rw()); let rb = m.map_region(ba, bs, rustre_debug_unicorn::RegionPerms::rx()); Ok(ToolResult::text(json!({"a_ok":ra,"b_ok":rb,"count":m.count(),"total_bytes":m.total_mapped_bytes(),"source":"rustre_debug_unicorn::UnicornMemoryMapper"}).to_string())) } }

pub struct DebugUnicornFaultInjectorFireV2Tool;
impl DebugUnicornFaultInjectorFireV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_fault_injector_fire_v2".to_string(), description: "Add a rule to rustre_debug_unicorn::FaultInjector and probe check_and_fire.".to_string(), input_schema: json!({"type":"object","required":["address","kind","param","probe"],"properties":{"address":{"type":"integer","minimum":0},"kind":{"type":"string"},"param":{"type":"integer","minimum":0},"probe":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DebugUnicornFaultInjectorFireV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?; let kind = __du_parse_faultkind(args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?)?; let param = args.get("param").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'param'".into()))?; let probe = args.get("probe").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'probe'".into()))?; let mut fi = rustre_debug_unicorn::FaultInjector::new(); let id = fi.add_rule(addr, kind, param); let fired = fi.check_and_fire(probe).map(|(k,p)| json!({"kind":k.to_string(),"param":p})); Ok(ToolResult::text(json!({"id":id,"rule_count":fi.rule_count(),"total_fires":fi.total_fires(),"fired":fired,"source":"rustre_debug_unicorn::FaultInjector"}).to_string())) } }

pub struct DebugUnicornFaultRuleShouldFireV2Tool;
impl DebugUnicornFaultRuleShouldFireV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_fault_rule_should_fire_v2".to_string(), description: "Construct a FaultRule and check should_fire for a probe address.".to_string(), input_schema: json!({"type":"object","required":["address","kind","param","probe"],"properties":{"address":{"type":"integer","minimum":0},"kind":{"type":"string"},"param":{"type":"integer","minimum":0},"probe":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DebugUnicornFaultRuleShouldFireV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?; let kind = __du_parse_faultkind(args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?)?; let param = args.get("param").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'param'".into()))?; let probe = args.get("probe").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'probe'".into()))?; let r = rustre_debug_unicorn::FaultRule::new(1, addr, kind, param); Ok(ToolResult::text(json!({"should_fire":r.should_fire(probe),"display":r.to_string(),"source":"rustre_debug_unicorn::FaultRule::should_fire"}).to_string())) } }

pub struct DebugUnicornSnapshotManagerSaveV2Tool;
impl DebugUnicornSnapshotManagerSaveV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_snapshot_manager_save_v2".to_string(), description: "Save a snapshot into rustre_debug_unicorn::SnapshotManager and query it.".to_string(), input_schema: json!({"type":"object","required":["label","seq"],"properties":{"label":{"type":"string"},"seq":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DebugUnicornSnapshotManagerSaveV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let label = args.get("label").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'label'".into()))?; let seq = args.get("seq").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'seq'".into()))?; let mut sm = rustre_debug_unicorn::SnapshotManager::new(); let id = sm.save(label.to_string(), seq, std::collections::HashMap::new(), std::collections::HashMap::new()); let snap = sm.find(id).map(std::string::ToString::to_string); Ok(ToolResult::text(json!({"id":id,"count":sm.count(),"labels":sm.labels(),"snap":snap,"source":"rustre_debug_unicorn::SnapshotManager::save"}).to_string())) } }

pub struct DebugUnicornSymbolTablePrefixV2Tool;
impl DebugUnicornSymbolTablePrefixV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_symbol_table_prefix_v2".to_string(), description: "Populate SymbolTable and run search_prefix / resolve.".to_string(), input_schema: json!({"type":"object","required":["symbols","prefix"],"properties":{"symbols":{"type":"array","items":{"type":"object","properties":{"addr":{"type":"integer"},"name":{"type":"string"}}}},"prefix":{"type":"string"},"probe_addr":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DebugUnicornSymbolTablePrefixV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let syms = args.get("symbols").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'symbols'".into()))?; let prefix = args.get("prefix").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'prefix'".into()))?; let mut t = rustre_debug_unicorn::SymbolTable::new(); for s in syms { if let (Some(a), Some(n)) = (s.get("addr").and_then(Value::as_u64), s.get("name").and_then(Value::as_str)) { t.define(a, n.to_string()); } } let hits: Vec<String> = t.search_prefix(prefix).iter().map(|s| s.to_string()).collect(); let resolved = args.get("probe_addr").and_then(Value::as_u64).map(|a| t.format_address(a)); Ok(ToolResult::text(json!({"count":t.count(),"prefix_hits":hits,"resolved":resolved,"source":"rustre_debug_unicorn::SymbolTable::search_prefix"}).to_string())) } }

pub struct DebugUnicornRegisterHistoryDiffV2Tool;
impl DebugUnicornRegisterHistoryDiffV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_register_history_diff_v2".to_string(), description: "Push two RegisterSnapshots and diff them via rustre_debug_unicorn::RegisterSnapshot::diff.".to_string(), input_schema: json!({"type":"object","required":["a","b"],"properties":{"a":{"type":"object"},"b":{"type":"object"},"pc_a":{"type":"integer","minimum":0},"pc_b":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DebugUnicornRegisterHistoryDiffV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a_obj = args.get("a").and_then(Value::as_object).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?; let b_obj = args.get("b").and_then(Value::as_object).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?; let mut a: std::collections::HashMap<String,u64> = std::collections::HashMap::new(); for (k,v) in a_obj { if let Some(x) = v.as_u64() { a.insert(k.clone(), x); } } let mut b: std::collections::HashMap<String,u64> = std::collections::HashMap::new(); for (k,v) in b_obj { if let Some(x) = v.as_u64() { b.insert(k.clone(), x); } } let pc_a = args.get("pc_a").and_then(Value::as_u64).unwrap_or(0); let pc_b = args.get("pc_b").and_then(Value::as_u64).unwrap_or(0); let sa = rustre_debug_unicorn::RegisterSnapshot::new(1, pc_a, a); let sb = rustre_debug_unicorn::RegisterSnapshot::new(2, pc_b, b); let mut h = rustre_debug_unicorn::RegisterHistory::new(4); h.push(sa.clone()); h.push(sb.clone()); Ok(ToolResult::text(json!({"len":h.len(),"latest_pc":h.latest().map(|s| s.pc),"oldest_pc":h.oldest().map(|s| s.pc),"changed":sa.diff(&sb),"source":"rustre_debug_unicorn::RegisterSnapshot::diff"}).to_string())) } }

pub struct DebugUnicornWatchKindMatchesV2Tool;
impl DebugUnicornWatchKindMatchesV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_watch_kind_matches_v2".to_string(), description: "Check Watchpoint::matches / covers via rustre_debug_unicorn.".to_string(), input_schema: json!({"type":"object","required":["addr","size","kind","probe_addr","probe_kind"],"properties":{"addr":{"type":"integer","minimum":0},"size":{"type":"integer","minimum":1},"kind":{"type":"string"},"probe_addr":{"type":"integer","minimum":0},"probe_kind":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DebugUnicornWatchKindMatchesV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))?; let kind = __du_parse_watchkind_v2(args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?)?; let pa = args.get("probe_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'probe_addr'".into()))?; let pk = __du_parse_watchkind_v2(args.get("probe_kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'probe_kind'".into()))?)?; let w = rustre_debug_unicorn::Watchpoint::new(1, addr, size as usize, kind); Ok(ToolResult::text(json!({"display":w.to_string(),"covers":w.covers(pa),"matches":w.matches(pk),"source":"rustre_debug_unicorn::Watchpoint::matches"}).to_string())) } }

pub struct DebugUnicornTraceEntryBytesV2Tool;
impl DebugUnicornTraceEntryBytesV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_trace_entry_bytes_v2".to_string(), description: "Construct rustre_debug_unicorn::TraceEntry and report its bytes length.".to_string(), input_schema: json!({"type":"object","required":["address","next_pc","raw_hex","mnemonic","seq","thread_id"],"properties":{"address":{"type":"integer","minimum":0},"next_pc":{"type":"integer","minimum":0},"raw_hex":{"type":"string"},"mnemonic":{"type":"string"},"seq":{"type":"integer","minimum":0},"thread_id":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DebugUnicornTraceEntryBytesV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let address = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?; let next_pc = args.get("next_pc").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'next_pc'".into()))?; let raw_hex = args.get("raw_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'raw_hex'".into()))?; let mnemonic = args.get("mnemonic").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'mnemonic'".into()))?; let seq = args.get("seq").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'seq'".into()))?; let tid = args.get("thread_id").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'thread_id'".into()))? as u32; let raw = __mem_hex_decode_v2(raw_hex)?; let e = rustre_debug_unicorn::TraceEntry::new(address, next_pc, &raw, mnemonic.to_string(), seq, tid); Ok(ToolResult::text(json!({"bytes_len":e.bytes().len(),"raw_len":e.raw_len,"display":e.to_string(),"source":"rustre_debug_unicorn::TraceEntry::bytes"}).to_string())) } }

pub struct DebugUnicornCoverageMapRatioV2Tool;
impl DebugUnicornCoverageMapRatioV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "debug_unicorn_coverage_map_ratio_v2".to_string(), description: "Register regions and record hits on rustre_debug_unicorn::CoverageMap; report ratio.".to_string(), input_schema: json!({"type":"object","required":["regions","hits"],"properties":{"granularity":{"type":"string"},"regions":{"type":"array","items":{"type":"array","items":{"type":"integer"}}},"hits":{"type":"array","items":{"type":"integer"}}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DebugUnicornCoverageMapRatioV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let g = match args.get("granularity").and_then(Value::as_str) { Some(s) => __du_parse_granularity(s)?, None => rustre_debug_unicorn::CoverageGranularity::Instruction }; let regs = args.get("regions").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'regions'".into()))?; let hits = args.get("hits").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'hits'".into()))?; let mut m = rustre_debug_unicorn::CoverageMap::new(g); for r in regs { if let Some(pair) = r.as_array() { if pair.len() == 2 { if let (Some(s), Some(e)) = (pair[0].as_u64(), pair[1].as_u64()) { m.register_region(s, e); } } } } for h in hits { if let Some(a) = h.as_u64() { m.record(a); } } Ok(ToolResult::text(json!({"covered_count":m.covered_count(),"coverage_ratio":m.coverage_ratio(),"sorted":m.sorted_addresses(),"source":"rustre_debug_unicorn::CoverageMap::coverage_ratio"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DebugUnicornMemRegionPermsTool::definition(), Box::new(DebugUnicornMemRegionPermsTool)),
        (DebugUnicornArchPointerSizeTool::definition(), Box::new(DebugUnicornArchPointerSizeTool)),
        (DebugUnicornTraceEntryBuildTool::definition(), Box::new(DebugUnicornTraceEntryBuildTool)),
        (DebugUnicornInstructionTraceStatsTool::definition(), Box::new(DebugUnicornInstructionTraceStatsTool)),
        (DebugUnicornWatchpointProbeTool::definition(), Box::new(DebugUnicornWatchpointProbeTool)),
        (DebugUnicornWatchpointManagerSimulateTool::definition(), Box::new(DebugUnicornWatchpointManagerSimulateTool)),
        (DebugUnicornCoverageMapReportTool::definition(), Box::new(DebugUnicornCoverageMapReportTool)),
        (DebugUnicornCoverageMapMergeTool::definition(), Box::new(DebugUnicornCoverageMapMergeTool)),
        (DebugUnicornSymbolTableResolveTool::definition(), Box::new(DebugUnicornSymbolTableResolveTool)),
        (DebugUnicornCodePatcherApplyTool::definition(), Box::new(DebugUnicornCodePatcherApplyTool)),
        (DebugUnicornThreadSimulateTool::definition(), Box::new(DebugUnicornThreadSimulateTool)),
        (DebugUnicornScriptGenTool::definition(), Box::new(DebugUnicornScriptGenTool)),
        (DebugUnicornHookRecordDescribeTool::definition(), Box::new(DebugUnicornHookRecordDescribeTool)),
        (DebugUnicornEmulateStepsTool::definition(), Box::new(DebugUnicornEmulateStepsTool)),
        (DebugUnicornFaultInjectorRunTool::definition(), Box::new(DebugUnicornFaultInjectorRunTool)),
        (DebugUnicornRegisterHistoryDiffTool::definition(), Box::new(DebugUnicornRegisterHistoryDiffTool)),
        (DebugUnicornMemRegionFlagsTool::definition(), Box::new(DebugUnicornMemRegionFlagsTool)),
        (DebugUnicornTraceEntryBytesTool::definition(), Box::new(DebugUnicornTraceEntryBytesTool)),
        (DebugUnicornSnapshotManagerOpsTool::definition(), Box::new(DebugUnicornSnapshotManagerOpsTool)),
        (DebugUnicornSymbolTableFormatTool::definition(), Box::new(DebugUnicornSymbolTableFormatTool)),
        (DebugUnicornCoverageGranularityAlignTool::definition(), Box::new(DebugUnicornCoverageGranularityAlignTool)),
        (DebugUnicornFaultRuleShouldFireTool::definition(), Box::new(DebugUnicornFaultRuleShouldFireTool)),
        (DebugUnicornSimulatedThreadStepTool::definition(), Box::new(DebugUnicornSimulatedThreadStepTool)),
        (DebugUnicornThreadSimulatorSchedulingTool::definition(), Box::new(DebugUnicornThreadSimulatorSchedulingTool)),
        (DebugUnicornV2ConfigPresetsTool::definition(), Box::new(DebugUnicornV2ConfigPresetsTool)),
        (DebugUnicornV2DebuggerEmulateTool::definition(), Box::new(DebugUnicornV2DebuggerEmulateTool)),
        (DebugUnicornPatchRecordNewTool::definition(), Box::new(DebugUnicornPatchRecordNewTool)),
        (DebugUnicornCoverageGranularityAlignV2Tool::definition(), Box::new(DebugUnicornCoverageGranularityAlignV2Tool)),
        (DebugUnicornRegionPermsFlagsV2Tool::definition(), Box::new(DebugUnicornRegionPermsFlagsV2Tool)),
        (DebugUnicornMappedRegionContainsV2Tool::definition(), Box::new(DebugUnicornMappedRegionContainsV2Tool)),
        (DebugUnicornMemoryMapperMapV2Tool::definition(), Box::new(DebugUnicornMemoryMapperMapV2Tool)),
        (DebugUnicornFaultInjectorFireV2Tool::definition(), Box::new(DebugUnicornFaultInjectorFireV2Tool)),
        (DebugUnicornFaultRuleShouldFireV2Tool::definition(), Box::new(DebugUnicornFaultRuleShouldFireV2Tool)),
        (DebugUnicornSnapshotManagerSaveV2Tool::definition(), Box::new(DebugUnicornSnapshotManagerSaveV2Tool)),
        (DebugUnicornSymbolTablePrefixV2Tool::definition(), Box::new(DebugUnicornSymbolTablePrefixV2Tool)),
        (DebugUnicornRegisterHistoryDiffV2Tool::definition(), Box::new(DebugUnicornRegisterHistoryDiffV2Tool)),
        (DebugUnicornWatchKindMatchesV2Tool::definition(), Box::new(DebugUnicornWatchKindMatchesV2Tool)),
        (DebugUnicornTraceEntryBytesV2Tool::definition(), Box::new(DebugUnicornTraceEntryBytesV2Tool)),
        (DebugUnicornCoverageMapRatioV2Tool::definition(), Box::new(DebugUnicornCoverageMapRatioV2Tool)),
    ]
}
