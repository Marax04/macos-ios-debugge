//! MCP wrappers for the rustre-trace_navigate crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes};

pub struct TraceNavigateBytesToU64Tool;

pub struct TraceNavigateInsnEntryTool;

pub struct TraceNavigateBytesToU64V2Tool;

pub struct TraceNavigateExecutionTraceNewV2Tool;

pub struct TraceNavigateBookmarkNewTool;

pub struct TraceNavigateStackFrameNewTool;

pub struct TraceNavigateBytesToU64V3Tool;
impl TraceNavigateBytesToU64V3Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_bytes_to_u64_v3".to_string(),
            description: "Convert byte slice (little-endian, up to 8 bytes) to u64.".to_string(),
            input_schema: json!({ "type": "object", "required": ["bytes"], "properties": { "bytes": { "type": "array" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateBytesToU64V3Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bytes = args_to_bytes(&args)?;
        let v = rustre_trace_navigate::bytes_to_u64(&bytes);
        Ok(ToolResult::text(json!({ "value": v, "hex": format!("0x{:x}", v), "source": "rustre_trace_navigate::bytes_to_u64" }).to_string()))
    }
}

pub struct TraceNavigateAccessKindDisplayTool;
impl TraceNavigateAccessKindDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_access_kind_display".to_string(),
            description: "Format AccessKind::Read / AccessKind::Write.".to_string(),
            input_schema: json!({ "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateAccessKindDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let k = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let ak = match k {
            "read" => rustre_trace_navigate::AccessKind::Read,
            "write" => rustre_trace_navigate::AccessKind::Write,
            _ => return Err(McpError::InvalidParams("'kind' must be 'read' or 'write'".into())),
        };
        Ok(ToolResult::text(json!({ "display": ak.to_string(), "source": "rustre_trace_navigate::AccessKind::Display" }).to_string()))
    }
}

pub struct TraceNavigateInsnEntryV2Tool;
impl TraceNavigateInsnEntryV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_insn_entry_v2".to_string(),
            description: "Construct TraceEntry::insn and return summary.".to_string(),
            input_schema: json!({ "type": "object", "required": ["idx","pc","tid","disasm"], "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateInsnEntryV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let idx = args.get("idx").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'idx'".into()))? as usize;
        let pc = args.get("pc").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'pc'".into()))?;
        let tid = args.get("tid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'tid'".into()))? as u32;
        let disasm = args.get("disasm").and_then(Value::as_str).unwrap_or("").to_string();
        let e = rustre_trace_navigate::TraceEntry::insn(idx, pc, tid, disasm);
        Ok(ToolResult::text(json!({ "idx": e.idx, "pc": e.pc, "tid": e.tid, "disasm": e.disasm, "is_call": e.is_call(), "is_ret": e.is_ret(), "display": e.to_string(), "source": "rustre_trace_navigate::TraceEntry::insn" }).to_string()))
    }
}

pub struct TraceNavigateCallEntryTool;
impl TraceNavigateCallEntryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_call_entry".to_string(),
            description: "Construct TraceEntry::call.".to_string(),
            input_schema: json!({ "type": "object", "required": ["idx","pc","tid","target","ret_addr"], "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateCallEntryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let idx = args.get("idx").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'idx'".into()))? as usize;
        let pc = args.get("pc").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'pc'".into()))?;
        let tid = args.get("tid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'tid'".into()))? as u32;
        let target = args.get("target").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'target'".into()))?;
        let ret_addr = args.get("ret_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'ret_addr'".into()))?;
        let e = rustre_trace_navigate::TraceEntry::call(idx, pc, tid, target, ret_addr);
        Ok(ToolResult::text(json!({ "idx": e.idx, "pc": e.pc, "call_target": e.call_target(), "ret_addr": e.ret_addr(), "is_call": e.is_call(), "disasm": e.disasm, "source": "rustre_trace_navigate::TraceEntry::call" }).to_string()))
    }
}

pub struct TraceNavigateRetEntryTool;
impl TraceNavigateRetEntryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_ret_entry".to_string(),
            description: "Construct TraceEntry::ret.".to_string(),
            input_schema: json!({ "type": "object", "required": ["idx","pc","tid","target"], "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateRetEntryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let idx = args.get("idx").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'idx'".into()))? as usize;
        let pc = args.get("pc").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'pc'".into()))?;
        let tid = args.get("tid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'tid'".into()))? as u32;
        let target = args.get("target").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'target'".into()))?;
        let e = rustre_trace_navigate::TraceEntry::ret(idx, pc, tid, target);
        Ok(ToolResult::text(json!({ "idx": e.idx, "pc": e.pc, "ret_target": e.ret_target(), "is_ret": e.is_ret(), "disasm": e.disasm, "source": "rustre_trace_navigate::TraceEntry::ret" }).to_string()))
    }
}

pub struct TraceNavigateStackFrameDisplayNameTool;
impl TraceNavigateStackFrameDisplayNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_stackframe_display_name".to_string(),
            description: "Return StackFrame::display_name.".to_string(),
            input_schema: json!({ "type": "object", "required": ["fn_addr"], "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateStackFrameDisplayNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let fn_addr = args.get("fn_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'fn_addr'".into()))?;
        let mut sf = rustre_trace_navigate::StackFrame::new(fn_addr, 0, 0, 0);
        if let Some(n) = args.get("name").and_then(Value::as_str) { sf = sf.with_name(n); }
        Ok(ToolResult::text(json!({ "display_name": sf.display_name(), "source": "rustre_trace_navigate::StackFrame::display_name" }).to_string()))
    }
}

pub struct TraceNavigateBookmarkWithNoteTool;
impl TraceNavigateBookmarkWithNoteTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_bookmark_with_note".to_string(),
            description: "Construct Bookmark with note.".to_string(),
            input_schema: json!({ "type": "object", "required": ["name","idx","pc","note"], "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateBookmarkWithNoteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string();
        let idx = args.get("idx").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'idx'".into()))? as usize;
        let pc = args.get("pc").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'pc'".into()))?;
        let note = args.get("note").and_then(Value::as_str).unwrap_or("").to_string();
        let bm = rustre_trace_navigate::Bookmark::new(name, idx, pc).with_note(note);
        Ok(ToolResult::text(json!({ "name": bm.name, "idx": bm.idx, "pc": bm.pc, "note": bm.note, "display": bm.to_string(), "source": "rustre_trace_navigate::Bookmark::with_note" }).to_string()))
    }
}

pub struct TraceNavigateBookmarkStoreSortedTool;
impl TraceNavigateBookmarkStoreSortedTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_bookmark_store_sorted".to_string(),
            description: "Insert bookmarks and return sorted-by-idx list.".to_string(),
            input_schema: json!({ "type": "object", "required": ["items"], "properties": { "items": { "type": "array" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateBookmarkStoreSortedTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let items = args.get("items").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'items'".into()))?;
        let mut store = rustre_trace_navigate::BookmarkStore::new();
        for it in items {
            let name = it.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string();
            let idx = it.get("idx").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'idx'".into()))? as usize;
            let pc = it.get("pc").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'pc'".into()))?;
            store.insert(rustre_trace_navigate::Bookmark::new(name, idx, pc));
        }
        let sorted: Vec<Value> = store.sorted_by_idx().into_iter().map(|b| json!({ "name": b.name, "idx": b.idx, "pc": b.pc })).collect();
        Ok(ToolResult::text(json!({ "len": store.len(), "sorted": sorted, "source": "rustre_trace_navigate::BookmarkStore::sorted_by_idx" }).to_string()))
    }
}

pub struct TraceNavigateNavigationHistoryTool;
impl TraceNavigateNavigationHistoryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_navigation_history".to_string(),
            description: "Push indices into NavigationHistory.".to_string(),
            input_schema: json!({ "type": "object", "required": ["indices"], "properties": { "indices": { "type": "array" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateNavigationHistoryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let idxs = args.get("indices").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'indices'".into()))?;
        let mut h = rustre_trace_navigate::NavigationHistory::new();
        for v in idxs {
            let n = v.as_u64().ok_or_else(|| McpError::InvalidParams("indices must be integers".into()))? as usize;
            h.push(n);
        }
        Ok(ToolResult::text(json!({ "current": h.current(), "undo_depth": h.undo_depth(), "redo_depth": h.redo_depth(), "source": "rustre_trace_navigate::NavigationHistory" }).to_string()))
    }
}

pub struct TraceNavigateStepWindowTool;
impl TraceNavigateStepWindowTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_step_window".to_string(),
            description: "Push Moved events into StepWindow(cap).".to_string(),
            input_schema: json!({ "type": "object", "required": ["cap","moves"], "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateStepWindowTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cap = args.get("cap").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'cap'".into()))? as usize;
        let moves = args.get("moves").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'moves'".into()))?;
        let mut w = rustre_trace_navigate::StepWindow::new(cap);
        for m in moves {
            let from = m.get("from").and_then(Value::as_u64).unwrap_or(0) as usize;
            let to = m.get("to").and_then(Value::as_u64).unwrap_or(0) as usize;
            w.push(rustre_trace_navigate::NavEvent::Moved { from, to });
        }
        let latest = w.latest().map(std::string::ToString::to_string);
        Ok(ToolResult::text(json!({ "len": w.len(), "is_empty": w.is_empty(), "latest": latest, "source": "rustre_trace_navigate::StepWindow" }).to_string()))
    }
}

pub struct TraceNavigateIdxForTscTool;
impl TraceNavigateIdxForTscTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_idx_for_tsc".to_string(),
            description: "Build ExecutionTrace and look up idx for a TSC value.".to_string(),
            input_schema: json!({ "type": "object", "required": ["entries","tsc"], "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateIdxForTscTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let entries = args.get("entries").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'entries'".into()))?;
        let tsc = args.get("tsc").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'tsc'".into()))?;
        let mut te: Vec<rustre_trace_navigate::TraceEntry> = Vec::new();
        for (i, e) in entries.iter().enumerate() {
            let pc = e.get("pc").and_then(Value::as_u64).unwrap_or(0);
            let t = e.get("tsc").and_then(Value::as_u64);
            let mut entry = rustre_trace_navigate::TraceEntry::insn(i, pc, 0, "");
            if let Some(tv) = t { entry = entry.with_tsc(tv); }
            te.push(entry);
        }
        let trace = rustre_trace_navigate::ExecutionTrace::new(te, "wire");
        Ok(ToolResult::text(json!({ "len": trace.len(), "idx": trace.idx_for_tsc(tsc), "tsc_base": trace.tsc_base, "total_tsc": trace.total_tsc, "source": "rustre_trace_navigate::ExecutionTrace::idx_for_tsc" }).to_string()))
    }
}

pub struct TraceNavigateMemAccessIndexTool;
impl TraceNavigateMemAccessIndexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_mem_access_index".to_string(),
            description: "Build MemAccessIndex from write/read events; report stats.".to_string(),
            input_schema: json!({ "type": "object", "required": ["writes","reads"], "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateMemAccessIndexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let writes = args.get("writes").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'writes'".into()))?;
        let reads = args.get("reads").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'reads'".into()))?;
        let mut te: Vec<rustre_trace_navigate::TraceEntry> = Vec::new();
        for (i, w) in writes.iter().enumerate() {
            let addr = w.get("addr").and_then(Value::as_u64).unwrap_or(0);
            let val = w.get("value").and_then(Value::as_u64).unwrap_or(0);
            let mut e = rustre_trace_navigate::TraceEntry::insn(i, 0, 0, "w");
            e.add_mem_write(addr, val.to_le_bytes().to_vec());
            te.push(e);
        }
        let base = te.len();
        for (j, r) in reads.iter().enumerate() {
            let addr = r.get("addr").and_then(Value::as_u64).unwrap_or(0);
            let size = r.get("size").and_then(Value::as_u64).unwrap_or(4) as u8;
            let mut e = rustre_trace_navigate::TraceEntry::insn(base + j, 0, 0, "r");
            e.add_mem_read(addr, size);
            te.push(e);
        }
        let trace = rustre_trace_navigate::ExecutionTrace::new(te, "wire");
        let idx = rustre_trace_navigate::MemAccessIndex::build(&trace);
        let mut result = json!({ "address_count": idx.address_count(), "written_addresses": idx.written_addresses(), "read_addresses": idx.read_addresses(), "source": "rustre_trace_navigate::MemAccessIndex::build" });
        if let Some(qa) = args.get("query_addr").and_then(Value::as_u64) {
            result["writes_at_query"] = json!(idx.writes(qa));
            result["reads_at_query"] = json!(idx.reads(qa));
        }
        Ok(ToolResult::text(result.to_string()))
    }
}

pub struct TraceNavigateAccessKindDisplayWireTool;
impl TraceNavigateAccessKindDisplayWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_access_kind_display_wire".to_string(),
            description: "Return Display strings for rustre_trace_navigate::AccessKind Read/Write.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateAccessKindDisplayWireTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let r = format!("{}", rustre_trace_navigate::AccessKind::Read);
        let w = format!("{}", rustre_trace_navigate::AccessKind::Write);
        Ok(ToolResult::text(json!({"read":r,"write":w,"source":"rustre_trace_navigate::AccessKind"}).to_string()))
    }
}

pub struct TraceNavigateCallEntryWireTool;
impl TraceNavigateCallEntryWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_call_entry_wire".to_string(),
            description: "Build a CALL TraceEntry.".to_string(),
            input_schema: json!({"type":"object","properties":{"idx":{"type":"integer"},"pc":{"type":"integer"},"tid":{"type":"integer"},"target":{"type":"integer"},"ret_addr":{"type":"integer"}},"required":["idx","pc","tid","target","ret_addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateCallEntryWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let idx = args.get("idx").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("idx".into()))? as usize;
        let pc = args.get("pc").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("pc".into()))?;
        let tid = args.get("tid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("tid".into()))?;
        let target = args.get("target").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("target".into()))?;
        let ret_addr = args.get("ret_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("ret_addr".into()))?;
        let tid_u32 = u32::try_from(tid).map_err(|_| McpError::InvalidParams("tid u32".into()))?;
        let e = rustre_trace_navigate::TraceEntry::call(idx, pc, tid_u32, target, ret_addr);
        Ok(ToolResult::text(json!({"display":format!("{e}"),"is_call":e.is_call(),"call_target":e.call_target(),"ret_addr":e.ret_addr(),"source":"rustre_trace_navigate::TraceEntry::call"}).to_string()))
    }
}

pub struct TraceNavigateRetEntryWireTool;
impl TraceNavigateRetEntryWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_ret_entry_wire".to_string(),
            description: "Build a RET TraceEntry.".to_string(),
            input_schema: json!({"type":"object","properties":{"idx":{"type":"integer"},"pc":{"type":"integer"},"tid":{"type":"integer"},"target":{"type":"integer"}},"required":["idx","pc","tid","target"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateRetEntryWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let idx = args.get("idx").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("idx".into()))? as usize;
        let pc = args.get("pc").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("pc".into()))?;
        let tid = args.get("tid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("tid".into()))?;
        let target = args.get("target").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("target".into()))?;
        let tid_u32 = u32::try_from(tid).map_err(|_| McpError::InvalidParams("tid u32".into()))?;
        let e = rustre_trace_navigate::TraceEntry::ret(idx, pc, tid_u32, target);
        Ok(ToolResult::text(json!({"display":format!("{e}"),"is_ret":e.is_ret(),"ret_target":e.ret_target(),"source":"rustre_trace_navigate::TraceEntry::ret"}).to_string()))
    }
}

pub struct TraceNavigateStackFrameDisplayNameWireTool;
impl TraceNavigateStackFrameDisplayNameWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_stackframe_display_name_wire".to_string(),
            description: "Build a StackFrame with optional name and return display_name.".to_string(),
            input_schema: json!({"type":"object","properties":{"fn_addr":{"type":"integer"},"ret_addr":{"type":"integer"},"depth":{"type":"integer"},"called_at_idx":{"type":"integer"},"name":{"type":"string"}},"required":["fn_addr","ret_addr","depth","called_at_idx"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateStackFrameDisplayNameWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let fn_addr = args.get("fn_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("fn_addr".into()))?;
        let ret_addr = args.get("ret_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("ret_addr".into()))?;
        let depth = args.get("depth").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("depth".into()))?;
        let called_at_idx = args.get("called_at_idx").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("called_at_idx".into()))? as usize;
        let depth_u32 = u32::try_from(depth).map_err(|_| McpError::InvalidParams("depth u32".into()))?;
        let mut sf = rustre_trace_navigate::StackFrame::new(fn_addr, ret_addr, depth_u32, called_at_idx);
        if let Some(n) = args.get("name").and_then(Value::as_str) { sf = sf.with_name(n.to_string()); }
        Ok(ToolResult::text(json!({"display":format!("{sf}"),"display_name":sf.display_name(),"source":"rustre_trace_navigate::StackFrame"}).to_string()))
    }
}

pub struct TraceNavigateExecutionTraceLenWireTool;
impl TraceNavigateExecutionTraceLenWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_execution_trace_len_wire".to_string(),
            description: "Empty ExecutionTrace with with_arch/with_tsc_freq; report metadata.".to_string(),
            input_schema: json!({"type":"object","properties":{"binary":{"type":"string"},"arch":{"type":"string"},"tsc_freq_hz":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateExecutionTraceLenWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let binary = args.get("binary").and_then(Value::as_str).unwrap_or("bin").to_string();
        let mut t = rustre_trace_navigate::ExecutionTrace::new(Vec::new(), binary);
        if let Some(a) = args.get("arch").and_then(Value::as_str) { t = t.with_arch(a.to_string()); }
        if let Some(hz) = args.get("tsc_freq_hz").and_then(Value::as_u64) { t = t.with_tsc_freq(hz); }
        Ok(ToolResult::text(json!({"len":t.len(),"is_empty":t.is_empty(),"arch":t.arch,"tsc_freq_hz":t.tsc_freq_hz,"idx_for_tsc_0":t.idx_for_tsc(0),"source":"rustre_trace_navigate::ExecutionTrace"}).to_string()))
    }
}

pub struct TraceNavigateNavHistoryWireTool;
impl TraceNavigateNavHistoryWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_nav_history_new_wire".to_string(),
            description: "NavigationHistory push/undo/redo depths.".to_string(),
            input_schema: json!({"type":"object","properties":{"pushes":{"type":"array","items":{"type":"integer"}}},"required":["pushes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateNavHistoryWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pushes: Vec<usize> = args.get("pushes").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("pushes".into()))?
            .iter().filter_map(Value::as_u64).map(|v| v as usize).collect();
        let mut h = rustre_trace_navigate::NavigationHistory::new();
        for p in &pushes { h.push(*p); }
        let current = h.current();
        let undo = h.undo();
        let redo = h.redo();
        Ok(ToolResult::text(json!({"pushed":pushes.len(),"current_after_push":current,"undo":undo,"redo":redo,"undo_depth":h.undo_depth(),"redo_depth":h.redo_depth(),"source":"rustre_trace_navigate::NavigationHistory"}).to_string()))
    }
}

pub struct TraceNavigateStepWindowWireTool;
impl TraceNavigateStepWindowWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_step_window_new_wire".to_string(),
            description: "StepWindow push N Moved events.".to_string(),
            input_schema: json!({"type":"object","properties":{"cap":{"type":"integer"},"count":{"type":"integer"}},"required":["cap","count"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateStepWindowWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cap = args.get("cap").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("cap".into()))? as usize;
        let count = args.get("count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("count".into()))? as usize;
        let mut w = rustre_trace_navigate::StepWindow::new(cap);
        for i in 0..count { w.push(rustre_trace_navigate::NavEvent::Moved { from: i, to: i + 1 }); }
        let latest = w.latest().map(|e| format!("{e}"));
        Ok(ToolResult::text(json!({"cap":cap,"pushed":count,"len":w.len(),"is_empty":w.is_empty(),"latest":latest,"source":"rustre_trace_navigate::StepWindow"}).to_string()))
    }
}

pub struct TraceNavigateBookmarkStoreWireTool;
impl TraceNavigateBookmarkStoreWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_bookmark_store_new_wire".to_string(),
            description: "BookmarkStore insert & query.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"idx":{"type":"integer"},"pc":{"type":"integer"},"note":{"type":"string"}},"required":["name","idx","pc"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateBookmarkStoreWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?.to_string();
        let idx = args.get("idx").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("idx".into()))? as usize;
        let pc = args.get("pc").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("pc".into()))?;
        let mut bm = rustre_trace_navigate::Bookmark::new(name.clone(), idx, pc);
        if let Some(n) = args.get("note").and_then(Value::as_str) { bm = bm.with_note(n.to_string()); }
        let display = format!("{bm}");
        let mut store = rustre_trace_navigate::BookmarkStore::new();
        store.insert(bm);
        let sorted_len = store.sorted_by_idx().len();
        let names: Vec<String> = store.names().into_iter().map(str::to_string).collect();
        Ok(ToolResult::text(json!({"display":display,"len":store.len(),"is_empty":store.is_empty(),"has":store.get(&name).is_some(),"sorted_len":sorted_len,"names":names,"source":"rustre_trace_navigate::BookmarkStore"}).to_string()))
    }
}

pub struct TraceNavigateCoverageBuildEmptyWireTool;
impl TraceNavigateCoverageBuildEmptyWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_coverage_build_empty_wire".to_string(),
            description: "CoverageStats over empty trace.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateCoverageBuildEmptyWireTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let t = rustre_trace_navigate::ExecutionTrace::new(Vec::new(), "empty");
        let c = rustre_trace_navigate::CoverageStats::build(&t);
        Ok(ToolResult::text(json!({"unique_blocks":c.unique_block_count(),"total_instructions":c.total_instructions(),"hot_top10_len":c.hot_blocks(10).len(),"hot_fraction_10":c.hot_fraction(10),"source":"rustre_trace_navigate::CoverageStats::build"}).to_string()))
    }
}

pub struct TraceNavigateCallStackReconstructorWireTool;
impl TraceNavigateCallStackReconstructorWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_call_stack_reconstructor_new_wire".to_string(),
            description: "CallStackReconstructor with_max_depth.".to_string(),
            input_schema: json!({"type":"object","properties":{"max_depth":{"type":"integer"}},"required":["max_depth"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateCallStackReconstructorWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let md = args.get("max_depth").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("max_depth".into()))? as usize;
        let r = rustre_trace_navigate::CallStackReconstructor::new().with_max_depth(md);
        Ok(ToolResult::text(json!({"depth":r.depth(),"overflow":r.overflow_count(),"frames":r.frames().len(),"source":"rustre_trace_navigate::CallStackReconstructor"}).to_string()))
    }
}

pub struct TraceNavigateEntryCallTargetXTool;
impl TraceNavigateEntryCallTargetXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_navigate_entry_call_target_x".to_string(), description: "Build CALL TraceEntry, read call_target/ret_addr.".to_string(), input_schema: json!({"type":"object","properties":{"pc":{"type":"integer"},"target":{"type":"integer"},"ret_addr":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for TraceNavigateEntryCallTargetXTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
    let pc = args.get("pc").and_then(Value::as_u64).unwrap_or(0x1000);
    let target = args.get("target").and_then(Value::as_u64).unwrap_or(0x2000);
    let ret_addr = args.get("ret_addr").and_then(Value::as_u64).unwrap_or(pc.wrapping_add(5));
    let e = rustre_trace_navigate::TraceEntry::call(0, pc, 1, target, ret_addr);
    Ok(ToolResult::text(json!({"is_call":e.is_call(),"is_ret":e.is_ret(),"call_target":e.call_target(),"ret_addr":e.ret_addr(),"source":"rustre_trace_navigate::TraceEntry::call_target"}).to_string()))
} }

pub struct TraceNavigateEntryRetTargetXTool;
impl TraceNavigateEntryRetTargetXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_navigate_entry_ret_target_x".to_string(), description: "Build RET TraceEntry, read ret_target.".to_string(), input_schema: json!({"type":"object","properties":{"pc":{"type":"integer"},"target":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for TraceNavigateEntryRetTargetXTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
    let pc = args.get("pc").and_then(Value::as_u64).unwrap_or(0x3000);
    let target = args.get("target").and_then(Value::as_u64).unwrap_or(0x1005);
    let e = rustre_trace_navigate::TraceEntry::ret(0, pc, 1, target);
    Ok(ToolResult::text(json!({"is_ret":e.is_ret(),"is_call":e.is_call(),"ret_target":e.ret_target(),"source":"rustre_trace_navigate::TraceEntry::ret_target"}).to_string()))
} }

pub struct TraceNavigateEntryIsCallXTool;
impl TraceNavigateEntryIsCallXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_navigate_entry_is_call_x".to_string(), description: "is_call for an Insn TraceEntry.".to_string(), input_schema: json!({"type":"object","properties":{"pc":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for TraceNavigateEntryIsCallXTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
    let pc = args.get("pc").and_then(Value::as_u64).unwrap_or(0x1000);
    let e = rustre_trace_navigate::TraceEntry::insn(0, pc, 1, "nop");
    Ok(ToolResult::text(json!({"is_call":e.is_call(),"is_ret":e.is_ret(),"source":"rustre_trace_navigate::TraceEntry::is_call"}).to_string()))
} }

pub struct TraceNavigateEntryIsRetXTool;
impl TraceNavigateEntryIsRetXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_navigate_entry_is_ret_x".to_string(), description: "is_ret over a RET TraceEntry.".to_string(), input_schema: json!({"type":"object","properties":{"pc":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for TraceNavigateEntryIsRetXTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
    let pc = args.get("pc").and_then(Value::as_u64).unwrap_or(0x1000);
    let e = rustre_trace_navigate::TraceEntry::ret(0, pc, 1, pc + 5);
    Ok(ToolResult::text(json!({"is_ret":e.is_ret(),"is_call":e.is_call(),"ret_target":e.ret_target(),"source":"rustre_trace_navigate::TraceEntry::is_ret"}).to_string()))
} }

pub struct TraceNavigateEntryRetAddrXTool;
impl TraceNavigateEntryRetAddrXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_navigate_entry_ret_addr_x".to_string(), description: "Read ret_addr accessor from CALL entry.".to_string(), input_schema: json!({"type":"object","properties":{"pc":{"type":"integer"},"target":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for TraceNavigateEntryRetAddrXTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
    let pc = args.get("pc").and_then(Value::as_u64).unwrap_or(0x1000);
    let target = args.get("target").and_then(Value::as_u64).unwrap_or(0x2000);
    let e = rustre_trace_navigate::TraceEntry::call(0, pc, 1, target, pc + 5);
    Ok(ToolResult::text(json!({"ret_addr":e.ret_addr(),"call_target":e.call_target(),"ret_target":e.ret_target(),"source":"rustre_trace_navigate::TraceEntry::ret_addr"}).to_string()))
} }

pub struct TraceNavigateBookmarkDisplayXTool;
impl TraceNavigateBookmarkDisplayXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_navigate_bookmark_display_x".to_string(), description: "Format Bookmark via Display and with_note.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"idx":{"type":"integer"},"pc":{"type":"integer"},"note":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for TraceNavigateBookmarkDisplayXTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
    let name = args.get("name").and_then(Value::as_str).unwrap_or("bm1").to_string();
    let idx = args.get("idx").and_then(Value::as_u64).unwrap_or(0) as usize;
    let pc = args.get("pc").and_then(Value::as_u64).unwrap_or(0x1000);
    let note = args.get("note").and_then(Value::as_str).map(std::string::ToString::to_string);
    let bm = rustre_trace_navigate::Bookmark::new(name, idx, pc);
    let bm = if let Some(n) = note { bm.with_note(n) } else { bm };
    Ok(ToolResult::text(json!({"display":format!("{}", bm),"has_note":bm.note.is_some(),"source":"rustre_trace_navigate::Bookmark::Display"}).to_string()))
} }

pub struct TraceNavigateExecutionTraceIdxForTscXTool;
impl TraceNavigateExecutionTraceIdxForTscXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_navigate_execution_trace_idx_for_tsc_x".to_string(), description: "idx_for_tsc on an empty ExecutionTrace (None).".to_string(), input_schema: json!({"type":"object","properties":{"tsc":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for TraceNavigateExecutionTraceIdxForTscXTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
    let tsc = args.get("tsc").and_then(Value::as_u64).unwrap_or(100);
    let t = rustre_trace_navigate::ExecutionTrace::new(Vec::new(), "bin");
    let idx = t.idx_for_tsc(tsc);
    Ok(ToolResult::text(json!({"idx":idx,"is_empty":t.is_empty(),"len":t.len(),"source":"rustre_trace_navigate::ExecutionTrace::idx_for_tsc"}).to_string()))
} }

pub struct TraceNavigateNaveventDisplayXTool;
impl TraceNavigateNaveventDisplayXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_navigate_navevent_display_x".to_string(), description: "Format NavEvent via Display.".to_string(), input_schema: json!({"type":"object","properties":{"kind":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for TraceNavigateNaveventDisplayXTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
    let k = args.get("kind").and_then(Value::as_str).unwrap_or("moved");
    let ev = match k {
        "end" => rustre_trace_navigate::NavEvent::End,
        "beginning" => rustre_trace_navigate::NavEvent::Beginning,
        _ => rustre_trace_navigate::NavEvent::Moved { from: 0, to: 1 },
    };
    Ok(ToolResult::text(json!({"display":format!("{}", ev),"source":"rustre_trace_navigate::NavEvent::Display"}).to_string()))
} }

pub struct TraceNavigateStackframeDisplayNameXTool;
impl TraceNavigateStackframeDisplayNameXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_navigate_stackframe_display_name_x".to_string(), description: "StackFrame display_name (with/without symbol).".to_string(), input_schema: json!({"type":"object","properties":{"fn_addr":{"type":"integer"},"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for TraceNavigateStackframeDisplayNameXTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
    let addr = args.get("fn_addr").and_then(Value::as_u64).unwrap_or(0x400000);
    let sf = rustre_trace_navigate::StackFrame::new(addr, addr + 5, 0, 0);
    let unnamed = sf.display_name();
    let name = args.get("name").and_then(Value::as_str).unwrap_or("main").to_string();
    let named = rustre_trace_navigate::StackFrame::new(addr, addr + 5, 0, 0).with_name(name).display_name();
    Ok(ToolResult::text(json!({"unnamed":unnamed,"named":named,"source":"rustre_trace_navigate::StackFrame::display_name"}).to_string()))
} }

pub struct TraceNavigateStackframeWithNameXTool;
impl TraceNavigateStackframeWithNameXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_navigate_stackframe_with_name_x".to_string(), description: "StackFrame::with_name Display.".to_string(), input_schema: json!({"type":"object","properties":{"fn_addr":{"type":"integer"},"ret_addr":{"type":"integer"},"depth":{"type":"integer"},"called_at_idx":{"type":"integer"},"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for TraceNavigateStackframeWithNameXTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
    let fa = args.get("fn_addr").and_then(Value::as_u64).unwrap_or(0x400000);
    let ra = args.get("ret_addr").and_then(Value::as_u64).unwrap_or(0x400010);
    let d = args.get("depth").and_then(Value::as_u64).unwrap_or(0) as u32;
    let ci = args.get("called_at_idx").and_then(Value::as_u64).unwrap_or(0) as usize;
    let name = args.get("name").and_then(Value::as_str).unwrap_or("func").to_string();
    let sf = rustre_trace_navigate::StackFrame::new(fa, ra, d, ci).with_name(name);
    Ok(ToolResult::text(json!({"display":format!("{}", sf),"display_name":sf.display_name(),"depth":sf.depth,"source":"rustre_trace_navigate::StackFrame::with_name"}).to_string()))
} }

pub struct TraceNavigateAccessKindFromStrXTool;
impl TraceNavigateAccessKindFromStrXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_navigate_access_kind_from_str_x".to_string(), description: "Parse 'read'/'write' into AccessKind, Display.".to_string(), input_schema: json!({"type":"object","required":["kind"],"properties":{"kind":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for TraceNavigateAccessKindFromStrXTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
    let k = args.get("kind").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'kind'".into()))?;
    let ak = match k {
        "read" => rustre_trace_navigate::AccessKind::Read,
        "write" => rustre_trace_navigate::AccessKind::Write,
        other => return Err(rustre_mcp_server::McpError::InvalidParams(format!("unknown kind: {other}"))),
    };
    Ok(ToolResult::text(json!({"display":format!("{}", ak),"is_write":ak == rustre_trace_navigate::AccessKind::Write,"source":"rustre_trace_navigate::AccessKind::Display"}).to_string()))
} }

pub struct TraceNavigateBytesToU64XTool;
impl TraceNavigateBytesToU64XTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_navigate_bytes_to_u64_x".to_string(), description: "bytes_to_u64 accepting integer array.".to_string(), input_schema: json!({"type":"object","required":["bytes"],"properties":{"bytes":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for TraceNavigateBytesToU64XTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
    let bytes: Vec<u8> = args.get("bytes").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect()).unwrap_or_default();
    let v = rustre_trace_navigate::bytes_to_u64(&bytes);
    Ok(ToolResult::text(json!({"value":v,"hex":format!("0x{:x}", v),"len":bytes.len(),"source":"rustre_trace_navigate::bytes_to_u64"}).to_string()))
} }

pub struct TraceNavigateTraceEntryWithRegsWpTool;
impl TraceNavigateTraceEntryWithRegsWpTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_trace_entry_with_regs_wp".to_string(),
            description: "Build an insn TraceEntry then attach a reg list; report reg_value lookups.".to_string(),
            input_schema: json!({"type":"object","properties":{"idx":{"type":"integer"},"pc":{"type":"integer"},"tid":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateTraceEntryWithRegsWpTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let idx = args.get("idx").and_then(Value::as_u64).unwrap_or(0) as usize;
        let pc = args.get("pc").and_then(Value::as_u64).unwrap_or(0);
        let tid = args.get("tid").and_then(Value::as_u64).unwrap_or(0) as u32;
        let e = rustre_trace_navigate::TraceEntry::insn(idx, pc, tid, "nop").with_regs(vec![(1, 0x1111), (2, 0x2222)]);
        let v1 = e.reg_value(1);
        let v2 = e.reg_value(2);
        let vmissing = e.reg_value(99);
        Ok(ToolResult::text(json!({"reg1":v1,"reg2":v2,"missing":vmissing,"source":"rustre_trace_navigate::TraceEntry::with_regs"}).to_string()))
    }
}

pub struct TraceNavigateTraceEntryMemAccessWpTool;
impl TraceNavigateTraceEntryMemAccessWpTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_trace_entry_mem_access_wp".to_string(),
            description: "Attach mem read/write to a TraceEntry and report display.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateTraceEntryMemAccessWpTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut e = rustre_trace_navigate::TraceEntry::insn(0, 0x400000, 0, "mov");
        e.add_mem_write(0x1000, vec![1, 2, 3, 4]);
        e.add_mem_read(0x2000, 4);
        Ok(ToolResult::text(json!({"display":format!("{e}"),"source":"rustre_trace_navigate::TraceEntry::add_mem_write"}).to_string()))
    }
}

pub struct TraceNavigateExecutionTraceWithArchWpTool;
impl TraceNavigateExecutionTraceWithArchWpTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_execution_trace_with_arch_wp".to_string(),
            description: "Build ExecutionTrace, set arch, report get(0)/len/is_empty.".to_string(),
            input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateExecutionTraceWithArchWpTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arch = args.get("arch").and_then(Value::as_str).unwrap_or("x86_64").to_string();
        let entries = vec![rustre_trace_navigate::TraceEntry::insn(0, 0x400000, 0, "nop")];
        let t = rustre_trace_navigate::ExecutionTrace::new(entries, "bin").with_arch(arch);
        Ok(ToolResult::text(json!({"len":t.len(),"is_empty":t.is_empty(),"arch":t.arch,"get0_some":t.get(0).is_some(),"source":"rustre_trace_navigate::ExecutionTrace::with_arch"}).to_string()))
    }
}

pub struct TraceNavigateExecutionTraceIdxForMsWpTool;
impl TraceNavigateExecutionTraceIdxForMsWpTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_execution_trace_idx_for_ms_wp".to_string(),
            description: "Report idx_for_ms on an empty ExecutionTrace.".to_string(),
            input_schema: json!({"type":"object","properties":{"ms":{"type":"number"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateExecutionTraceIdxForMsWpTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ms = args.get("ms").and_then(Value::as_f64).unwrap_or(0.0);
        let t = rustre_trace_navigate::ExecutionTrace::new(Vec::new(), "bin");
        Ok(ToolResult::text(json!({"idx":t.idx_for_ms(ms),"source":"rustre_trace_navigate::ExecutionTrace::idx_for_ms"}).to_string()))
    }
}

pub struct TraceNavigateMemAccessIndexQueriesWpTool;
impl TraceNavigateMemAccessIndexQueriesWpTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_mem_access_index_queries_wp".to_string(),
            description: "Build MemAccessIndex from a small trace and exercise accesses/writes/reads/value_at_idx.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateMemAccessIndexQueriesWpTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut e0 = rustre_trace_navigate::TraceEntry::insn(0, 0x400000, 0, "mov");
        e0.add_mem_write(0x1000, vec![0xAA, 0, 0, 0, 0, 0, 0, 0]);
        let mut e1 = rustre_trace_navigate::TraceEntry::insn(1, 0x400004, 0, "mov");
        e1.add_mem_read(0x1000, 8);
        let t = rustre_trace_navigate::ExecutionTrace::new(vec![e0, e1], "bin");
        let idx = rustre_trace_navigate::MemAccessIndex::build(&t);
        Ok(ToolResult::text(json!({
            "accesses":idx.accesses(0x1000).len(),
            "writes":idx.writes(0x1000).len(),
            "reads":idx.reads(0x1000).len(),
            "value_at":idx.value_at_idx(0x1000, 1),
            "source":"rustre_trace_navigate::MemAccessIndex"
        }).to_string()))
    }
}

pub struct TraceNavigateMemAccessIndexAddrsWpTool;
impl TraceNavigateMemAccessIndexAddrsWpTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_mem_access_index_addrs_wp".to_string(),
            description: "Report written_addresses/read_addresses/address_count and first/last write of value.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateMemAccessIndexAddrsWpTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut e0 = rustre_trace_navigate::TraceEntry::insn(0, 0x400000, 0, "mov");
        e0.add_mem_write(0x1000, vec![0xAA, 0, 0, 0, 0, 0, 0, 0]);
        let t = rustre_trace_navigate::ExecutionTrace::new(vec![e0], "bin");
        let idx = rustre_trace_navigate::MemAccessIndex::build(&t);
        Ok(ToolResult::text(json!({
            "written":idx.written_addresses().len(),
            "read":idx.read_addresses().len(),
            "count":idx.address_count(),
            "first":idx.first_write_of_value(0x1000, 0xAA),
            "last":idx.last_write_of_value(0x1000, 0xAA),
            "source":"rustre_trace_navigate::MemAccessIndex"
        }).to_string()))
    }
}

pub struct TraceNavigateCallIndexBuildWpTool;
impl TraceNavigateCallIndexBuildWpTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_call_index_build_wp".to_string(),
            description: "Build CallIndex from a trace with a call and report queries.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateCallIndexBuildWpTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let e = rustre_trace_navigate::TraceEntry::call(0, 0x400000, 0, 0x500000, 0x400005);
        let t = rustre_trace_navigate::ExecutionTrace::new(vec![e], "bin");
        let ci = rustre_trace_navigate::CallIndex::build(&t);
        Ok(ToolResult::text(json!({
            "callers":ci.callers_of(0x500000).len(),
            "function_count":ci.function_count(),
            "call_counts_len":ci.call_counts().len(),
            "functions":ci.functions().len(),
            "source":"rustre_trace_navigate::CallIndex::build"
        }).to_string()))
    }
}

pub struct TraceNavigateRegTimelineBuildWpTool;
impl TraceNavigateRegTimelineBuildWpTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_reg_timeline_build_wp".to_string(),
            description: "Build RegTimeline and exercise history/find_value/value_at/tracked_regs.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateRegTimelineBuildWpTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let e = rustre_trace_navigate::TraceEntry::insn(0, 0x400000, 0, "mov").with_regs(vec![(1, 42)]);
        let t = rustre_trace_navigate::ExecutionTrace::new(vec![e], "bin");
        let rt = rustre_trace_navigate::RegTimeline::build(&t);
        Ok(ToolResult::text(json!({
            "history":rt.history(1, 0..1).len(),
            "find":rt.find_value(1, 42).len(),
            "value_at":rt.value_at(1, 0),
            "tracked":rt.tracked_regs().len(),
            "snapshot":rt.snapshot_at(0).len(),
            "changed":rt.changed_between(0, 0).len(),
            "source":"rustre_trace_navigate::RegTimeline::build"
        }).to_string()))
    }
}

pub struct TraceNavigateCallStackReconstructorProcessWpTool;
impl TraceNavigateCallStackReconstructorProcessWpTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_call_stack_reconstructor_process_wp".to_string(),
            description: "Add a symbol, process a CALL entry, reset, and rebuild_to.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateCallStackReconstructorProcessWpTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut r = rustre_trace_navigate::CallStackReconstructor::new();
        r.add_symbol(0x500000, "target_fn");
        let e = rustre_trace_navigate::TraceEntry::call(0, 0x400000, 0, 0x500000, 0x400005);
        r.process(&e);
        let after_process = r.frames().len();
        r.reset();
        let after_reset = r.frames().len();
        let t = rustre_trace_navigate::ExecutionTrace::new(vec![e], "bin");
        let rebuilt = r.rebuild_to(&t, 0);
        Ok(ToolResult::text(json!({
            "after_process":after_process,
            "after_reset":after_reset,
            "rebuilt_len":rebuilt.len(),
            "source":"rustre_trace_navigate::CallStackReconstructor::process"
        }).to_string()))
    }
}

pub struct TraceNavigateStackFrameWithNameWpTool;
impl TraceNavigateStackFrameWithNameWpTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_navigate_stack_frame_with_name_wp".to_string(),
            description: "Build StackFrame with a name and report display_name.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceNavigateStackFrameWithNameWpTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("main").to_string();
        let sf = rustre_trace_navigate::StackFrame::new(0x400000, 0x400005, 0, 0).with_name(name);
        Ok(ToolResult::text(json!({"display_name":sf.display_name(),"source":"rustre_trace_navigate::StackFrame::with_name"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TraceNavigateBytesToU64Tool::definition(), Box::new(TraceNavigateBytesToU64Tool)),
        (TraceNavigateInsnEntryTool::definition(), Box::new(TraceNavigateInsnEntryTool)),
        (TraceNavigateBytesToU64V2Tool::definition(), Box::new(TraceNavigateBytesToU64V2Tool)),
        (TraceNavigateExecutionTraceNewV2Tool::definition(), Box::new(TraceNavigateExecutionTraceNewV2Tool)),
        (TraceNavigateBookmarkNewTool::definition(), Box::new(TraceNavigateBookmarkNewTool)),
        (TraceNavigateStackFrameNewTool::definition(), Box::new(TraceNavigateStackFrameNewTool)),
        (TraceNavigateBytesToU64V3Tool::definition(), Box::new(TraceNavigateBytesToU64V3Tool)),
        (TraceNavigateAccessKindDisplayTool::definition(), Box::new(TraceNavigateAccessKindDisplayTool)),
        (TraceNavigateInsnEntryV2Tool::definition(), Box::new(TraceNavigateInsnEntryV2Tool)),
        (TraceNavigateCallEntryTool::definition(), Box::new(TraceNavigateCallEntryTool)),
        (TraceNavigateRetEntryTool::definition(), Box::new(TraceNavigateRetEntryTool)),
        (TraceNavigateStackFrameDisplayNameTool::definition(), Box::new(TraceNavigateStackFrameDisplayNameTool)),
        (TraceNavigateBookmarkWithNoteTool::definition(), Box::new(TraceNavigateBookmarkWithNoteTool)),
        (TraceNavigateBookmarkStoreSortedTool::definition(), Box::new(TraceNavigateBookmarkStoreSortedTool)),
        (TraceNavigateNavigationHistoryTool::definition(), Box::new(TraceNavigateNavigationHistoryTool)),
        (TraceNavigateStepWindowTool::definition(), Box::new(TraceNavigateStepWindowTool)),
        (TraceNavigateIdxForTscTool::definition(), Box::new(TraceNavigateIdxForTscTool)),
        (TraceNavigateMemAccessIndexTool::definition(), Box::new(TraceNavigateMemAccessIndexTool)),
        (TraceNavigateAccessKindDisplayWireTool::definition(), Box::new(TraceNavigateAccessKindDisplayWireTool)),
        (TraceNavigateCallEntryWireTool::definition(), Box::new(TraceNavigateCallEntryWireTool)),
        (TraceNavigateRetEntryWireTool::definition(), Box::new(TraceNavigateRetEntryWireTool)),
        (TraceNavigateStackFrameDisplayNameWireTool::definition(), Box::new(TraceNavigateStackFrameDisplayNameWireTool)),
        (TraceNavigateExecutionTraceLenWireTool::definition(), Box::new(TraceNavigateExecutionTraceLenWireTool)),
        (TraceNavigateNavHistoryWireTool::definition(), Box::new(TraceNavigateNavHistoryWireTool)),
        (TraceNavigateStepWindowWireTool::definition(), Box::new(TraceNavigateStepWindowWireTool)),
        (TraceNavigateBookmarkStoreWireTool::definition(), Box::new(TraceNavigateBookmarkStoreWireTool)),
        (TraceNavigateCoverageBuildEmptyWireTool::definition(), Box::new(TraceNavigateCoverageBuildEmptyWireTool)),
        (TraceNavigateCallStackReconstructorWireTool::definition(), Box::new(TraceNavigateCallStackReconstructorWireTool)),
        (TraceNavigateEntryCallTargetXTool::definition(), Box::new(TraceNavigateEntryCallTargetXTool)),
        (TraceNavigateEntryRetTargetXTool::definition(), Box::new(TraceNavigateEntryRetTargetXTool)),
        (TraceNavigateEntryIsCallXTool::definition(), Box::new(TraceNavigateEntryIsCallXTool)),
        (TraceNavigateEntryIsRetXTool::definition(), Box::new(TraceNavigateEntryIsRetXTool)),
        (TraceNavigateEntryRetAddrXTool::definition(), Box::new(TraceNavigateEntryRetAddrXTool)),
        (TraceNavigateBookmarkDisplayXTool::definition(), Box::new(TraceNavigateBookmarkDisplayXTool)),
        (TraceNavigateExecutionTraceIdxForTscXTool::definition(), Box::new(TraceNavigateExecutionTraceIdxForTscXTool)),
        (TraceNavigateNaveventDisplayXTool::definition(), Box::new(TraceNavigateNaveventDisplayXTool)),
        (TraceNavigateStackframeDisplayNameXTool::definition(), Box::new(TraceNavigateStackframeDisplayNameXTool)),
        (TraceNavigateStackframeWithNameXTool::definition(), Box::new(TraceNavigateStackframeWithNameXTool)),
        (TraceNavigateAccessKindFromStrXTool::definition(), Box::new(TraceNavigateAccessKindFromStrXTool)),
        (TraceNavigateBytesToU64XTool::definition(), Box::new(TraceNavigateBytesToU64XTool)),
        (TraceNavigateTraceEntryWithRegsWpTool::definition(), Box::new(TraceNavigateTraceEntryWithRegsWpTool)),
        (TraceNavigateTraceEntryMemAccessWpTool::definition(), Box::new(TraceNavigateTraceEntryMemAccessWpTool)),
        (TraceNavigateExecutionTraceWithArchWpTool::definition(), Box::new(TraceNavigateExecutionTraceWithArchWpTool)),
        (TraceNavigateExecutionTraceIdxForMsWpTool::definition(), Box::new(TraceNavigateExecutionTraceIdxForMsWpTool)),
        (TraceNavigateMemAccessIndexQueriesWpTool::definition(), Box::new(TraceNavigateMemAccessIndexQueriesWpTool)),
        (TraceNavigateMemAccessIndexAddrsWpTool::definition(), Box::new(TraceNavigateMemAccessIndexAddrsWpTool)),
        (TraceNavigateCallIndexBuildWpTool::definition(), Box::new(TraceNavigateCallIndexBuildWpTool)),
        (TraceNavigateRegTimelineBuildWpTool::definition(), Box::new(TraceNavigateRegTimelineBuildWpTool)),
        (TraceNavigateCallStackReconstructorProcessWpTool::definition(), Box::new(TraceNavigateCallStackReconstructorProcessWpTool)),
        (TraceNavigateStackFrameWithNameWpTool::definition(), Box::new(TraceNavigateStackFrameWithNameWpTool)),
    ]
}
