//! MCP wrappers for the rustre-emu_unicorn crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{parse_emu_unicorn_mode_v2};

pub struct EmuUnicornModePtrSizeTool;

pub struct EmuUnicornModeIsLittleEndianTool;

pub struct EmuUnicornNewX8664Tool;

pub struct EmuUnicornNewArm64Tool;

pub struct EmuUnicornNewArmThumbTool;

pub struct EmuUnicornPermCanReadTool;

pub struct EmuUnicornPermCanExecTool;

pub struct EmuUnicornPermCanWriteTool;
impl EmuUnicornPermCanWriteTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "emu_unicorn_perm_can_write".to_string(),
            description: "Whether a Perm bitmask includes WRITE.".to_string(),
            input_schema: json!({"type":"object","properties":{"bits":{"type":"integer"}},"required":["bits"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornPermCanWriteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as u8;
        let p = rustre_emu_unicorn::Perm(bits);
        Ok(ToolResult::text(json!({"can_write": p.can_write(), "bits": bits}).to_string()))
    }
}

pub struct EmuUnicornHeapMallocSimTool;
impl EmuUnicornHeapMallocSimTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "emu_unicorn_heap_malloc_sim".to_string(),
            description: "Simulate a HeapAllocator malloc call.".to_string(),
            input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"heap_size":{"type":"integer"},"alloc_size":{"type":"integer"}},"required":["base","heap_size","alloc_size"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornHeapMallocSimTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let heap_size = args.get("heap_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'heap_size'".into()))? as usize;
        let alloc_size = args.get("alloc_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'alloc_size'".into()))? as usize;
        let mut h = rustre_emu_unicorn::HeapAllocator::new(base, heap_size);
        let addr = h.malloc(alloc_size);
        Ok(ToolResult::text(json!({"addr": addr, "bytes_used": h.bytes_used(), "allocation_count": h.allocation_count()}).to_string()))
    }
}

pub struct EmuUnicornHeapCallocSimTool;
impl EmuUnicornHeapCallocSimTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "emu_unicorn_heap_calloc_sim".to_string(),
            description: "Simulate HeapAllocator calloc.".to_string(),
            input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"heap_size":{"type":"integer"},"count":{"type":"integer"},"elem_size":{"type":"integer"}},"required":["base","heap_size","count","elem_size"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornHeapCallocSimTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let heap_size = args.get("heap_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'heap_size'".into()))? as usize;
        let count = args.get("count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'count'".into()))? as usize;
        let elem_size = args.get("elem_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'elem_size'".into()))? as usize;
        let mut h = rustre_emu_unicorn::HeapAllocator::new(base, heap_size);
        let addr = h.calloc(count, elem_size);
        Ok(ToolResult::text(json!({"addr": addr, "bytes_used": h.bytes_used()}).to_string()))
    }
}

pub struct EmuUnicornHeapReallocSimTool;
impl EmuUnicornHeapReallocSimTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "emu_unicorn_heap_realloc_sim".to_string(),
            description: "Simulate malloc(initial) then realloc(new_size).".to_string(),
            input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"heap_size":{"type":"integer"},"initial":{"type":"integer"},"new_size":{"type":"integer"}},"required":["base","heap_size","initial","new_size"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornHeapReallocSimTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let heap_size = args.get("heap_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'heap_size'".into()))? as usize;
        let initial = args.get("initial").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'initial'".into()))? as usize;
        let new_size = args.get("new_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'new_size'".into()))? as usize;
        let mut h = rustre_emu_unicorn::HeapAllocator::new(base, heap_size);
        let a1 = h.malloc(initial);
        let a2 = a1.and_then(|a| h.realloc(a, new_size));
        Ok(ToolResult::text(json!({"initial_addr": a1, "realloc_addr": a2, "bytes_used": h.bytes_used()}).to_string()))
    }
}

pub struct EmuUnicornHeapFreeSimTool;
impl EmuUnicornHeapFreeSimTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "emu_unicorn_heap_free_sim".to_string(),
            description: "Simulate malloc + free on a HeapAllocator.".to_string(),
            input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"heap_size":{"type":"integer"},"alloc_size":{"type":"integer"}},"required":["base","heap_size","alloc_size"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornHeapFreeSimTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let heap_size = args.get("heap_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'heap_size'".into()))? as usize;
        let alloc_size = args.get("alloc_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'alloc_size'".into()))? as usize;
        let mut h = rustre_emu_unicorn::HeapAllocator::new(base, heap_size);
        let a = h.malloc(alloc_size);
        let freed = a.is_some_and(|addr| h.free(addr));
        Ok(ToolResult::text(json!({"addr": a, "freed": freed, "bytes_used_after": h.bytes_used()}).to_string()))
    }
}

pub struct EmuUnicornCoverageRecordSeqTool;
impl EmuUnicornCoverageRecordSeqTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "emu_unicorn_coverage_record_seq".to_string(),
            description: "Record a sequence of basic-block addresses in a CoverageTracker.".to_string(),
            input_schema: json!({"type":"object","properties":{"bb_addrs":{"type":"array","items":{"type":"integer"}}},"required":["bb_addrs"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornCoverageRecordSeqTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("bb_addrs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'bb_addrs'".into()))?;
        let mut cov = rustre_emu_unicorn::CoverageTracker::default();
        for v in arr { if let Some(a) = v.as_u64() { cov.record_bb(a); } }
        Ok(ToolResult::text(json!({"coverage_count": cov.coverage_count(), "edge_count": cov.edge_count(), "most_visited": cov.most_visited()}).to_string()))
    }
}

pub struct EmuUnicornModeIsLittleEndianV2Tool;
impl EmuUnicornModeIsLittleEndianV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "emu_unicorn_mode_is_little_endian_v2".to_string(),
            description: "Endianness for a Mode name (v2).".to_string(),
            input_schema: json!({"type":"object","properties":{"mode":{"type":"string"}},"required":["mode"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornModeIsLittleEndianV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("mode").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'mode'".into()))?;
        let m = parse_emu_unicorn_mode_v2(name).ok_or_else(|| McpError::InvalidParams("unknown mode".into()))?;
        Ok(ToolResult::text(json!({"mode": name, "is_little_endian": m.is_little_endian()}).to_string()))
    }
}

pub struct EmuUnicornModePtrSizeV2Tool;
impl EmuUnicornModePtrSizeV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "emu_unicorn_mode_ptr_size_v2".to_string(),
            description: "Pointer size in bytes for a Mode name (v2).".to_string(),
            input_schema: json!({"type":"object","properties":{"mode":{"type":"string"}},"required":["mode"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornModePtrSizeV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("mode").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'mode'".into()))?;
        let m = parse_emu_unicorn_mode_v2(name).ok_or_else(|| McpError::InvalidParams("unknown mode".into()))?;
        Ok(ToolResult::text(json!({"mode": name, "ptr_size": m.ptr_size()}).to_string()))
    }
}

pub struct EmuUnicornRegisterFileRoundtripTool;
impl EmuUnicornRegisterFileRoundtripTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "emu_unicorn_register_file_roundtrip".to_string(),
            description: "Set X86 RAX/RIP/RSP in a RegisterFile then read pc/sp masked for a Mode.".to_string(),
            input_schema: json!({"type":"object","properties":{"rax":{"type":"integer"},"rip":{"type":"integer"},"rsp":{"type":"integer"},"mode":{"type":"string"}},"required":["rax","rip","rsp","mode"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornRegisterFileRoundtripTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let rax = args.get("rax").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rax'".into()))?;
        let rip = args.get("rip").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rip'".into()))?;
        let rsp = args.get("rsp").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rsp'".into()))?;
        let mode_name = args.get("mode").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'mode'".into()))?;
        let mode = parse_emu_unicorn_mode_v2(mode_name).ok_or_else(|| McpError::InvalidParams("unknown mode".into()))?;
        let mut rf = rustre_emu_unicorn::RegisterFile::default();
        rf.set_x86(rustre_emu_unicorn::X86Reg::RAX, rax);
        rf.set_x86(rustre_emu_unicorn::X86Reg::RIP, rip);
        rf.set_x86(rustre_emu_unicorn::X86Reg::RSP, rsp);
        Ok(ToolResult::text(json!({
            "rax": rf.get_x86(rustre_emu_unicorn::X86Reg::RAX),
            "pc_masked": rf.pc(rustre_emu_unicorn::Arch::X86, mode),
            "sp_masked": rf.sp(rustre_emu_unicorn::Arch::X86, mode),
        }).to_string()))
    }
}

pub struct EmuUnicornPermWriteBitTool;
impl EmuUnicornPermWriteBitTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_perm_write_bit".to_string(),
            description: "Report whether the given Unicorn Perm bitmask allows writes.".to_string(),
            input_schema: json!({"type":"object","required":["perm"],"properties":{"perm":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornPermWriteBitTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("perm").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'perm'".into()))?;
        let p = rustre_emu_unicorn::Perm(v as u8);
        Ok(ToolResult::text(json!({"perm":v,"can_write":p.can_write(),"source":"rustre_emu_unicorn::Perm::can_write"}).to_string()))
    }
}

pub struct EmuUnicornHeapAllocFreeCycleTool;
impl EmuUnicornHeapAllocFreeCycleTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_heap_alloc_free_cycle".to_string(),
            description: "Simulate malloc/free round-trip on a fresh HeapAllocator.".to_string(),
            input_schema: json!({"type":"object","required":["base","size","alloc"],"properties":{"base":{"type":"integer"},"size":{"type":"integer"},"alloc":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornHeapAllocFreeCycleTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as usize;
        let alloc = args.get("alloc").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'alloc'".into()))? as usize;
        let mut h = rustre_emu_unicorn::HeapAllocator::new(base, size);
        let addr = h.malloc(alloc);
        let freed = addr.map(|a| h.free(a)).unwrap_or(false);
        Ok(ToolResult::text(json!({"addr":addr,"freed":freed,"source":"rustre_emu_unicorn::HeapAllocator"}).to_string()))
    }
}

pub struct EmuUnicornHeapCallocOverflowCheckTool;
impl EmuUnicornHeapCallocOverflowCheckTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_heap_calloc_overflow_check".to_string(),
            description: "Attempt HeapAllocator::calloc(count, elem) and report None on overflow.".to_string(),
            input_schema: json!({"type":"object","required":["base","size","count","elem"],"properties":{"base":{"type":"integer"},"size":{"type":"integer"},"count":{"type":"integer"},"elem":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornHeapCallocOverflowCheckTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as usize;
        let count = args.get("count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'count'".into()))? as usize;
        let elem = args.get("elem").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'elem'".into()))? as usize;
        let mut h = rustre_emu_unicorn::HeapAllocator::new(base, size);
        let addr = h.calloc(count, elem);
        Ok(ToolResult::text(json!({"addr":addr,"overflow":addr.is_none(),"source":"rustre_emu_unicorn::HeapAllocator::calloc"}).to_string()))
    }
}

pub struct EmuUnicornHeapReallocGrowTool;
impl EmuUnicornHeapReallocGrowTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_heap_realloc_grow".to_string(),
            description: "Malloc, then realloc to a larger size; report both addresses.".to_string(),
            input_schema: json!({"type":"object","required":["base","size","first","grown"],"properties":{"base":{"type":"integer"},"size":{"type":"integer"},"first":{"type":"integer"},"grown":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornHeapReallocGrowTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as usize;
        let first = args.get("first").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'first'".into()))? as usize;
        let grown = args.get("grown").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'grown'".into()))? as usize;
        let mut h = rustre_emu_unicorn::HeapAllocator::new(base, size);
        let a1 = h.malloc(first);
        let a2 = a1.and_then(|a| h.realloc(a, grown));
        Ok(ToolResult::text(json!({"first":a1,"realloc":a2,"source":"rustre_emu_unicorn::HeapAllocator::realloc"}).to_string()))
    }
}

pub struct EmuUnicornHeapAllocationStatsTool;
impl EmuUnicornHeapAllocationStatsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_heap_allocation_stats".to_string(),
            description: "Perform a sequence of mallocs and report bytes_used + allocation_count.".to_string(),
            input_schema: json!({"type":"object","required":["base","size","sizes"],"properties":{"base":{"type":"integer"},"size":{"type":"integer"},"sizes":{"type":"array","items":{"type":"integer"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornHeapAllocationStatsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as usize;
        let sizes: Vec<usize> = args.get("sizes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'sizes'".into()))?
            .iter().filter_map(|v| v.as_u64().map(|n| n as usize)).collect();
        let mut h = rustre_emu_unicorn::HeapAllocator::new(base, size);
        let mut ok = 0usize;
        for s in &sizes { if h.malloc(*s).is_some() { ok += 1; } }
        Ok(ToolResult::text(json!({"requested":sizes.len(),"allocated":ok,"bytes_used":h.bytes_used(),"allocation_count":h.allocation_count(),"source":"rustre_emu_unicorn::HeapAllocator"}).to_string()))
    }
}

pub struct EmuUnicornCoverageResetCheckTool;
impl EmuUnicornCoverageResetCheckTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_coverage_reset_check".to_string(),
            description: "Record BBs then reset; report counts pre/post reset.".to_string(),
            input_schema: json!({"type":"object","required":["bbs"],"properties":{"bbs":{"type":"array","items":{"type":"integer"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornCoverageResetCheckTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bbs: Vec<u64> = args.get("bbs").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'bbs'".into()))?
            .iter().filter_map(Value::as_u64).collect();
        let mut c = rustre_emu_unicorn::CoverageTracker::default();
        for a in &bbs { c.record_bb(*a); }
        let before = c.coverage_count();
        let edges = c.edge_count();
        c.reset();
        let after = c.coverage_count();
        Ok(ToolResult::text(json!({"before":before,"edges":edges,"after":after,"source":"rustre_emu_unicorn::CoverageTracker::reset"}).to_string()))
    }
}

pub struct EmuUnicornCoverageHotBlockTool;
impl EmuUnicornCoverageHotBlockTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_coverage_hot_block".to_string(),
            description: "Report the most-visited basic block after replaying a BB sequence.".to_string(),
            input_schema: json!({"type":"object","required":["bbs"],"properties":{"bbs":{"type":"array","items":{"type":"integer"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornCoverageHotBlockTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bbs: Vec<u64> = args.get("bbs").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'bbs'".into()))?
            .iter().filter_map(Value::as_u64).collect();
        let mut c = rustre_emu_unicorn::CoverageTracker::default();
        for a in &bbs { c.record_bb(*a); }
        let hot = c.most_visited();
        Ok(ToolResult::text(json!({"hot_addr":hot.map(|(a,_)| a),"hits":hot.map(|(_,h)| h),"coverage":c.coverage_count(),"source":"rustre_emu_unicorn::CoverageTracker::most_visited"}).to_string()))
    }
}

pub struct EmuUnicornCoverageEdgeWalkTool;
impl EmuUnicornCoverageEdgeWalkTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_coverage_edge_walk".to_string(),
            description: "Report distinct edge count after a BB walk sequence.".to_string(),
            input_schema: json!({"type":"object","required":["bbs"],"properties":{"bbs":{"type":"array","items":{"type":"integer"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornCoverageEdgeWalkTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bbs: Vec<u64> = args.get("bbs").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'bbs'".into()))?
            .iter().filter_map(Value::as_u64).collect();
        let mut c = rustre_emu_unicorn::CoverageTracker::default();
        for a in &bbs { c.record_bb(*a); }
        Ok(ToolResult::text(json!({"edges":c.edge_count(),"bbs":c.coverage_count(),"source":"rustre_emu_unicorn::CoverageTracker::edge_count"}).to_string()))
    }
}

pub struct EmuUnicornOptionsDefaultsV2Tool;
impl EmuUnicornOptionsDefaultsV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_options_defaults_v2".to_string(),
            description: "Report default EmuOptions timeout/max_instructions/stop flags.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornOptionsDefaultsV2Tool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let o = rustre_emu_unicorn::EmuOptions::default();
        Ok(ToolResult::text(json!({"timeout_us":o.timeout_us,"max_instructions":o.max_instructions,"stop_on_unmapped":o.stop_on_unmapped,"stop_on_invalid_insn":o.stop_on_invalid_insn,"source":"rustre_emu_unicorn::EmuOptions::default"}).to_string()))
    }
}

pub struct EmuUnicornMappedRegionContainsTool;
impl EmuUnicornMappedRegionContainsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_mapped_region_contains".to_string(),
            description: "After mapping a region, test whether an address falls in it (via list_regions).".to_string(),
            input_schema: json!({"type":"object","required":["base","size","addr"],"properties":{"base":{"type":"integer"},"size":{"type":"integer"},"addr":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornMappedRegionContainsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as usize;
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let mut emu = rustre_emu_unicorn::UnicornEmu::new(rustre_emu_unicorn::Arch::X86, rustre_emu_unicorn::Mode::X86_64)
            .map_err(|e| McpError::InvalidParams(format!("new: {e}")))?;
        emu.map_region(base, size, rustre_emu_unicorn::Perm::RW)
            .map_err(|e| McpError::InvalidParams(format!("map: {e}")))?;
        let regions = emu.list_regions();
        let contains = regions.iter().any(|r| addr >= r.base && addr < r.base + r.size as u64);
        Ok(ToolResult::text(json!({"contains":contains,"region_count":regions.len(),"source":"rustre_emu_unicorn::UnicornEmu::list_regions"}).to_string()))
    }
}

pub struct EmuUnicornHookkindLabelsTool;
impl EmuUnicornHookkindLabelsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_hookkind_labels".to_string(),
            description: "List label strings for all HookKind variants (code/mem/intr/insn/insn_invalid).".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornHookkindLabelsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_emu_unicorn::HookKind;
        let code = HookKind::Code { begin:0, end:0, f: Box::new(|_,_|{}) };
        let mem = HookKind::Mem { access: rustre_emu_unicorn::MemAccessType::Read, begin:0, end:0, f: Box::new(|_,_,_,_|{}) };
        let intr = HookKind::Intr { f: Box::new(|_|{}) };
        let insn = HookKind::Insn { insn: rustre_emu_unicorn::InsnType::SYSCALL, f: Box::new(|_|{}) };
        let inv = HookKind::InsnInvalid { f: Box::new(|_| true) };
        Ok(ToolResult::text(json!({"labels":[code.label(),mem.label(),intr.label(),insn.label(),inv.label()],"source":"rustre_emu_unicorn::HookKind::label"}).to_string()))
    }
}

pub struct EmuUnicornSyscallArgsPackTool;
impl EmuUnicornSyscallArgsPackTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_syscall_args_pack".to_string(),
            description: "Build a SyscallArgs value and echo its fields.".to_string(),
            input_schema: json!({"type":"object","required":["number"],"properties":{"number":{"type":"integer"},"args":{"type":"array","items":{"type":"integer"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornSyscallArgsPackTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let number = args.get("number").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'number'".into()))?;
        let a: Vec<u64> = args.get("args").and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(Value::as_u64).collect())
            .unwrap_or_default();
        let get = |i: usize| a.get(i).copied().unwrap_or(0);
        let sa = rustre_emu_unicorn::SyscallArgs {
            number, arg0:get(0), arg1:get(1), arg2:get(2), arg3:get(3), arg4:get(4), arg5:get(5)
        };
        Ok(ToolResult::text(json!({"number":sa.number,"arg0":sa.arg0,"arg1":sa.arg1,"arg2":sa.arg2,"arg3":sa.arg3,"arg4":sa.arg4,"arg5":sa.arg5,"source":"rustre_emu_unicorn::SyscallArgs"}).to_string()))
    }
}

pub struct EmuUnicornPermConstantsB2Tool;
impl EmuUnicornPermConstantsB2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_perm_constants".to_string(), description: "Report Perm constant bitmasks.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornPermConstantsB2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { use rustre_emu_unicorn::Perm; Ok(ToolResult::text(json!({"none":Perm::NONE.0,"read":Perm::READ.0,"write":Perm::WRITE.0,"exec":Perm::EXEC.0,"rw":Perm::RW.0,"rx":Perm::RX.0,"rwx":Perm::RWX.0,"source":"rustre_emu_unicorn::Perm"}).to_string())) } }

pub struct EmuUnicornPermReadBitB2Tool;
impl EmuUnicornPermReadBitB2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_perm_read_bit".to_string(), description: "Perm::can_read.".to_string(), input_schema: json!({"type":"object","required":["perm"],"properties":{"perm":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornPermReadBitB2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let v = args.get("perm").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'perm'".into()))?; let p = rustre_emu_unicorn::Perm(v as u8); Ok(ToolResult::text(json!({"perm":v,"can_read":p.can_read(),"source":"rustre_emu_unicorn::Perm::can_read"}).to_string())) } }

pub struct EmuUnicornPermExecBitB2Tool;
impl EmuUnicornPermExecBitB2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_perm_exec_bit".to_string(), description: "Perm::can_exec.".to_string(), input_schema: json!({"type":"object","required":["perm"],"properties":{"perm":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornPermExecBitB2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let v = args.get("perm").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'perm'".into()))?; let p = rustre_emu_unicorn::Perm(v as u8); Ok(ToolResult::text(json!({"perm":v,"can_exec":p.can_exec(),"source":"rustre_emu_unicorn::Perm::can_exec"}).to_string())) } }

pub struct EmuUnicornPermBitmaskEncodeB2Tool;
impl EmuUnicornPermBitmaskEncodeB2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_perm_bitmask_encode".to_string(), description: "Encode r/w/x flags to Perm bits.".to_string(), input_schema: json!({"type":"object","properties":{"r":{"type":"boolean"},"w":{"type":"boolean"},"x":{"type":"boolean"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornPermBitmaskEncodeB2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let r = args.get("r").and_then(Value::as_bool).unwrap_or(false); let w = args.get("w").and_then(Value::as_bool).unwrap_or(false); let x = args.get("x").and_then(Value::as_bool).unwrap_or(false); let mut v: u8 = 0; if r { v |= 1; } if w { v |= 2; } if x { v |= 4; } let p = rustre_emu_unicorn::Perm(v); Ok(ToolResult::text(json!({"bits":v,"can_read":p.can_read(),"can_write":p.can_write(),"can_exec":p.can_exec(),"source":"rustre_emu_unicorn::Perm"}).to_string())) } }

pub struct EmuUnicornHeapZeroSizeMallocB2Tool;
impl EmuUnicornHeapZeroSizeMallocB2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_heap_zero_size_malloc".to_string(), description: "HeapAllocator::malloc(0) returns None.".to_string(), input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornHeapZeroSizeMallocB2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let base = args.get("base").and_then(Value::as_u64).unwrap_or(0x4000_0000); let size = args.get("size").and_then(Value::as_u64).unwrap_or(0x1000) as usize; let mut h = rustre_emu_unicorn::HeapAllocator::new(base, size); let a = h.malloc(0); Ok(ToolResult::text(json!({"addr":a,"is_none":a.is_none(),"source":"rustre_emu_unicorn::HeapAllocator::malloc"}).to_string())) } }

pub struct EmuUnicornHeapExhaustionCheckB2Tool;
impl EmuUnicornHeapExhaustionCheckB2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_heap_exhaustion_check".to_string(), description: "Alloc beyond capacity returns None.".to_string(), input_schema: json!({"type":"object","required":["base","size","alloc"],"properties":{"base":{"type":"integer"},"size":{"type":"integer"},"alloc":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornHeapExhaustionCheckB2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'base'".into()))?; let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'size'".into()))? as usize; let alloc = args.get("alloc").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'alloc'".into()))? as usize; let mut h = rustre_emu_unicorn::HeapAllocator::new(base, size); let a = h.malloc(alloc); Ok(ToolResult::text(json!({"addr":a,"exhausted":a.is_none(),"heap_size":size,"requested":alloc,"source":"rustre_emu_unicorn::HeapAllocator::malloc"}).to_string())) } }

pub struct EmuUnicornHeapFreeInvalidB2Tool;
impl EmuUnicornHeapFreeInvalidB2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_heap_free_invalid".to_string(), description: "Free bogus addr returns false.".to_string(), input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"size":{"type":"integer"},"addr":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornHeapFreeInvalidB2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let base = args.get("base").and_then(Value::as_u64).unwrap_or(0x4000_0000); let size = args.get("size").and_then(Value::as_u64).unwrap_or(0x1000) as usize; let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0xdead_beef); let mut h = rustre_emu_unicorn::HeapAllocator::new(base, size); let ok = h.free(addr); Ok(ToolResult::text(json!({"addr":addr,"freed":ok,"source":"rustre_emu_unicorn::HeapAllocator::free"}).to_string())) } }

pub struct EmuUnicornHeapBrkPositionB2Tool;
impl EmuUnicornHeapBrkPositionB2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_heap_brk_position".to_string(), description: "Report brk after mallocs.".to_string(), input_schema: json!({"type":"object","required":["base","size","sizes"],"properties":{"base":{"type":"integer"},"size":{"type":"integer"},"sizes":{"type":"array","items":{"type":"integer"}}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornHeapBrkPositionB2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'base'".into()))?; let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'size'".into()))? as usize; let sizes: Vec<usize> = args.get("sizes").and_then(Value::as_array).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'sizes'".into()))?.iter().filter_map(|v| v.as_u64().map(|n| n as usize)).collect(); let mut h = rustre_emu_unicorn::HeapAllocator::new(base, size); for s in &sizes { let _ = h.malloc(*s); } Ok(ToolResult::text(json!({"base":base,"brk":h.brk,"advanced":h.brk.saturating_sub(base),"allocation_count":h.allocation_count(),"source":"rustre_emu_unicorn::HeapAllocator::brk"}).to_string())) } }

pub struct EmuUnicornHeapReallocFreeAddrB2Tool;
impl EmuUnicornHeapReallocFreeAddrB2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_heap_realloc_free_addr".to_string(), description: "Realloc unknown addr; report result.".to_string(), input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"size":{"type":"integer"},"addr":{"type":"integer"},"new_size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornHeapReallocFreeAddrB2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let base = args.get("base").and_then(Value::as_u64).unwrap_or(0x4000_0000); let size = args.get("size").and_then(Value::as_u64).unwrap_or(0x1000) as usize; let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0xdead_beef); let ns = args.get("new_size").and_then(Value::as_u64).unwrap_or(64) as usize; let mut h = rustre_emu_unicorn::HeapAllocator::new(base, size); let a = h.realloc(addr, ns); Ok(ToolResult::text(json!({"addr":addr,"new_size":ns,"result":a,"source":"rustre_emu_unicorn::HeapAllocator::realloc"}).to_string())) } }

pub struct EmuUnicornCoverageDefaultEmptyB2Tool;
impl EmuUnicornCoverageDefaultEmptyB2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_coverage_default_empty".to_string(), description: "Default CoverageTracker is empty.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornCoverageDefaultEmptyB2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let c = rustre_emu_unicorn::CoverageTracker::default(); Ok(ToolResult::text(json!({"coverage":c.coverage_count(),"edges":c.edge_count(),"hot":c.most_visited(),"source":"rustre_emu_unicorn::CoverageTracker::default"}).to_string())) } }

pub struct EmuUnicornCoverageHitCountB2Tool;
impl EmuUnicornCoverageHitCountB2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_coverage_hit_count".to_string(), description: "Record N visits to a BB.".to_string(), input_schema: json!({"type":"object","required":["addr","hits"],"properties":{"addr":{"type":"integer"},"hits":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornCoverageHitCountB2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'addr'".into()))?; let hits = args.get("hits").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'hits'".into()))?; let mut c = rustre_emu_unicorn::CoverageTracker::default(); for _ in 0..hits { c.record_bb(addr); } let hot = c.most_visited(); Ok(ToolResult::text(json!({"addr":addr,"requested_hits":hits,"hot":hot,"coverage":c.coverage_count(),"edges":c.edge_count(),"source":"rustre_emu_unicorn::CoverageTracker::most_visited"}).to_string())) } }

pub struct EmuUnicornCoverageSingleBbB2Tool;
impl EmuUnicornCoverageSingleBbB2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_coverage_single_bb".to_string(), description: "Record one BB; coverage=1, edges=0.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornCoverageSingleBbB2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0x1000); let mut c = rustre_emu_unicorn::CoverageTracker::default(); c.record_bb(addr); Ok(ToolResult::text(json!({"addr":addr,"coverage":c.coverage_count(),"edges":c.edge_count(),"source":"rustre_emu_unicorn::CoverageTracker::record_bb"}).to_string())) } }

pub struct EmuUnicornNewMips32Tool;
impl EmuUnicornNewMips32Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_new_mips32".to_string(), description: "Instantiate preconfigured MIPS32LE UnicornEmu; return region summary.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornNewMips32Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let emu = rustre_emu_unicorn::new_mips32_emu().map_err(|e| rustre_mcp_server::McpError::InternalError(e.to_string()))?; Ok(ToolResult::text(json!({"arch":"mips32","regions":emu.list_regions().len(),"source":"rustre_emu_unicorn::new_mips32_emu"}).to_string())) } }

pub struct EmuUnicornHeapAllocatorNewTool;
impl EmuUnicornHeapAllocatorNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_heap_allocator_new".to_string(), description: "Construct HeapAllocator; report base/size/brk/alloc_count.".to_string(), input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornHeapAllocatorNewTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let base = args.get("base").and_then(Value::as_u64).unwrap_or(0x1000); let size = args.get("size").and_then(Value::as_u64).unwrap_or(0x10000) as usize; let h = rustre_emu_unicorn::HeapAllocator::new(base, size); Ok(ToolResult::text(json!({"base":h.base,"size":h.size,"brk":h.brk,"allocs":h.allocation_count(),"bytes_used":h.bytes_used(),"source":"rustre_emu_unicorn::HeapAllocator::new"}).to_string())) } }

pub struct EmuUnicornHeapBytesUsedTool;
impl EmuUnicornHeapBytesUsedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_heap_bytes_used".to_string(), description: "Malloc a size then report bytes_used and allocation_count.".to_string(), input_schema: json!({"type":"object","properties":{"size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornHeapBytesUsedTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let size = args.get("size").and_then(Value::as_u64).unwrap_or(64) as usize; let mut h = rustre_emu_unicorn::HeapAllocator::new(0x2000, 0x10000); let a = h.malloc(size); Ok(ToolResult::text(json!({"requested":size,"addr":a,"bytes_used":h.bytes_used(),"allocs":h.allocation_count(),"source":"rustre_emu_unicorn::HeapAllocator::bytes_used"}).to_string())) } }

pub struct EmuUnicornHeapReallocSameTool;
impl EmuUnicornHeapReallocSameTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_heap_realloc_same".to_string(), description: "Realloc to a size <= existing returns same address.".to_string(), input_schema: json!({"type":"object","properties":{"size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornHeapReallocSameTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let size = args.get("size").and_then(Value::as_u64).unwrap_or(128) as usize; let mut h = rustre_emu_unicorn::HeapAllocator::new(0x2000, 0x10000); let a = h.malloc(size).ok_or_else(|| rustre_mcp_server::McpError::InternalError("malloc failed".into()))?; let b = h.realloc(a, size / 2); Ok(ToolResult::text(json!({"orig":a,"reallocated":b,"same":Some(a)==b,"source":"rustre_emu_unicorn::HeapAllocator::realloc"}).to_string())) } }

pub struct EmuUnicornHeapReallocMissingTool;
impl EmuUnicornHeapReallocMissingTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_heap_realloc_missing".to_string(), description: "Realloc unknown addr yields None.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornHeapReallocMissingTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0xdeadbeef); let mut h = rustre_emu_unicorn::HeapAllocator::new(0x2000, 0x10000); let r = h.realloc(addr, 128); Ok(ToolResult::text(json!({"addr":addr,"result":r,"is_none":r.is_none(),"source":"rustre_emu_unicorn::HeapAllocator::realloc"}).to_string())) } }

pub struct EmuUnicornCoverageMostVisitedTool;
impl EmuUnicornCoverageMostVisitedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_coverage_most_visited".to_string(), description: "Record BBs; return most visited (addr,hits).".to_string(), input_schema: json!({"type":"object","properties":{"addrs":{"type":"array","items":{"type":"integer"}}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornCoverageMostVisitedTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let addrs: Vec<u64> = args.get("addrs").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_else(|| vec![0x1000, 0x2000, 0x1000, 0x1000, 0x2000]); let mut c = rustre_emu_unicorn::CoverageTracker::default(); for a in &addrs { c.record_bb(*a); } let mv = c.most_visited(); Ok(ToolResult::text(json!({"count":addrs.len(),"most_visited":mv.map(|(a,h)| json!({"addr":a,"hits":h})),"source":"rustre_emu_unicorn::CoverageTracker::most_visited"}).to_string())) } }

pub struct EmuUnicornCoverageResetClearsTool;
impl EmuUnicornCoverageResetClearsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_coverage_reset_clears".to_string(), description: "Record BBs then reset; verify counters are zero.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornCoverageResetClearsTool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let mut c = rustre_emu_unicorn::CoverageTracker::default(); c.record_bb(0x1000); c.record_bb(0x2000); let before = c.coverage_count(); c.reset(); Ok(ToolResult::text(json!({"before":before,"after_coverage":c.coverage_count(),"after_edges":c.edge_count(),"source":"rustre_emu_unicorn::CoverageTracker::reset"}).to_string())) } }

pub struct EmuUnicornHeapFreeThenAllocTool;
impl EmuUnicornHeapFreeThenAllocTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_heap_free_then_alloc".to_string(), description: "Alloc, free, alloc same size — verifies free-list reuse.".to_string(), input_schema: json!({"type":"object","properties":{"size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornHeapFreeThenAllocTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let size = args.get("size").and_then(Value::as_u64).unwrap_or(64) as usize; let mut h = rustre_emu_unicorn::HeapAllocator::new(0x2000, 0x10000); let a = h.malloc(size); let freed = a.map(|x| h.free(x)).unwrap_or(false); let b = h.malloc(size); Ok(ToolResult::text(json!({"first":a,"freed":freed,"second":b,"reused":a==b,"source":"rustre_emu_unicorn::HeapAllocator::free"}).to_string())) } }

pub struct EmuUnicornHeapCallocZeroTool;
impl EmuUnicornHeapCallocZeroTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_heap_calloc_zero".to_string(), description: "Calloc(0,N) yields None (zero-size).".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornHeapCallocZeroTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let n = args.get("n").and_then(Value::as_u64).unwrap_or(8) as usize; let mut h = rustre_emu_unicorn::HeapAllocator::new(0x2000, 0x10000); let r = h.calloc(0, n); Ok(ToolResult::text(json!({"result":r,"is_none":r.is_none(),"source":"rustre_emu_unicorn::HeapAllocator::calloc"}).to_string())) } }

pub struct EmuUnicornHeapMallocSequenceTool;
impl EmuUnicornHeapMallocSequenceTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "emu_unicorn_heap_malloc_sequence".to_string(), description: "Malloc N distinct blocks and report count/bytes_used.".to_string(), input_schema: json!({"type":"object","properties":{"count":{"type":"integer"},"size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EmuUnicornHeapMallocSequenceTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let count = args.get("count").and_then(Value::as_u64).unwrap_or(4) as usize; let size = args.get("size").and_then(Value::as_u64).unwrap_or(32) as usize; let mut h = rustre_emu_unicorn::HeapAllocator::new(0x2000, 0x10000); let mut addrs = Vec::new(); for _ in 0..count { if let Some(a) = h.malloc(size) { addrs.push(a); } } Ok(ToolResult::text(json!({"addrs":addrs,"allocs":h.allocation_count(),"bytes_used":h.bytes_used(),"source":"rustre_emu_unicorn::HeapAllocator::malloc"}).to_string())) } }

pub struct EmuUnicornPermRoundtripTool;
impl EmuUnicornPermRoundtripTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_perm_roundtrip".to_string(),
            description: "Report can_read/can_write/can_exec for a Perm bitmask.".to_string(),
            input_schema: json!({"type":"object","required":["perm"],"properties":{"perm":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornPermRoundtripTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("perm").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'perm'".into()))?;
        let p = rustre_emu_unicorn::Perm(v as u8);
        Ok(ToolResult::text(json!({"perm":v,"can_read":p.can_read(),"can_write":p.can_write(),"can_exec":p.can_exec(),"source":"rustre_emu_unicorn::Perm"}).to_string()))
    }
}

pub struct EmuUnicornModeEndianCheckTool;
impl EmuUnicornModeEndianCheckTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_mode_endian_check".to_string(),
            description: "Report ptr_size and is_little_endian for every Mode variant.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornModeEndianCheckTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_emu_unicorn::Mode;
        let modes = [Mode::X86_16, Mode::X86_32, Mode::X86_64, Mode::ArmMode, Mode::ThumbMode, Mode::Arm64Mode,
                     Mode::Mips32LE, Mode::Mips32BE, Mode::Mips64LE, Mode::Mips64BE,
                     Mode::Sparc32, Mode::Sparc64, Mode::RiscV32, Mode::RiscV64,
                     Mode::M68K, Mode::Ppc32, Mode::Ppc64, Mode::S390X];
        let arr: Vec<Value> = modes.iter().map(|m| json!({"mode":format!("{:?}",m),"ptr_size":m.ptr_size(),"is_le":m.is_little_endian()})).collect();
        Ok(ToolResult::text(json!({"modes":arr,"count":modes.len(),"source":"rustre_emu_unicorn::Mode"}).to_string()))
    }
}

pub struct EmuUnicornHeapBrkFrontierTool;
impl EmuUnicornHeapBrkFrontierTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_heap_brk_frontier".to_string(),
            description: "Track HeapAllocator brk after a sequence of mallocs.".to_string(),
            input_schema: json!({"type":"object","required":["base","size","sizes"],"properties":{"base":{"type":"integer"},"size":{"type":"integer"},"sizes":{"type":"array","items":{"type":"integer"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornHeapBrkFrontierTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as usize;
        let sizes: Vec<usize> = args.get("sizes").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'sizes'".into()))?
            .iter().filter_map(|v| v.as_u64().map(|n| n as usize)).collect();
        let mut h = rustre_emu_unicorn::HeapAllocator::new(base, size);
        let mut addrs = Vec::new();
        for s in &sizes { addrs.push(h.malloc(*s)); }
        Ok(ToolResult::text(json!({"brk":h.brk,"base":h.base,"cap":h.size,"addrs":addrs,"source":"rustre_emu_unicorn::HeapAllocator"}).to_string()))
    }
}

pub struct EmuUnicornHeapDoubleFreeTool;
impl EmuUnicornHeapDoubleFreeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_heap_double_free".to_string(),
            description: "Malloc then free twice; report whether second free returned false.".to_string(),
            input_schema: json!({"type":"object","required":["base","size","alloc"],"properties":{"base":{"type":"integer"},"size":{"type":"integer"},"alloc":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornHeapDoubleFreeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as usize;
        let alloc = args.get("alloc").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'alloc'".into()))? as usize;
        let mut h = rustre_emu_unicorn::HeapAllocator::new(base, size);
        let addr = h.malloc(alloc);
        let f1 = addr.map(|a| h.free(a)).unwrap_or(false);
        let f2 = addr.map(|a| h.free(a)).unwrap_or(false);
        Ok(ToolResult::text(json!({"addr":addr,"free1":f1,"free2":f2,"source":"rustre_emu_unicorn::HeapAllocator::free"}).to_string()))
    }
}

pub struct EmuUnicornHeapReallocShrinkTool;
impl EmuUnicornHeapReallocShrinkTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_heap_realloc_shrink".to_string(),
            description: "Malloc then realloc to a smaller size; addresses should match.".to_string(),
            input_schema: json!({"type":"object","required":["base","size","first","shrunk"],"properties":{"base":{"type":"integer"},"size":{"type":"integer"},"first":{"type":"integer"},"shrunk":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornHeapReallocShrinkTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as usize;
        let first = args.get("first").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'first'".into()))? as usize;
        let shrunk = args.get("shrunk").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'shrunk'".into()))? as usize;
        let mut h = rustre_emu_unicorn::HeapAllocator::new(base, size);
        let a1 = h.malloc(first);
        let a2 = a1.and_then(|a| h.realloc(a, shrunk));
        Ok(ToolResult::text(json!({"first":a1,"realloc":a2,"same":a1==a2,"source":"rustre_emu_unicorn::HeapAllocator::realloc"}).to_string()))
    }
}

pub struct EmuUnicornCoverageEmptyReportTool;
impl EmuUnicornCoverageEmptyReportTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_coverage_empty_report".to_string(),
            description: "Report an empty CoverageTracker's counts and hottest block (None).".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornCoverageEmptyReportTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let c = rustre_emu_unicorn::CoverageTracker::default();
        Ok(ToolResult::text(json!({"coverage":c.coverage_count(),"edges":c.edge_count(),"most_visited":c.most_visited().map(|(a,h)| json!([a,h])),"source":"rustre_emu_unicorn::CoverageTracker"}).to_string()))
    }
}

pub struct EmuUnicornHookAccessKindTool;
impl EmuUnicornHookAccessKindTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_hook_access_kind".to_string(),
            description: "Build a Mem HookKind and report label + mem_access + address_range.".to_string(),
            input_schema: json!({"type":"object","required":["begin","end"],"properties":{"begin":{"type":"integer"},"end":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornHookAccessKindTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let begin = args.get("begin").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'begin'".into()))?;
        let end = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'end'".into()))?;
        let hk = rustre_emu_unicorn::HookKind::Mem { access: rustre_emu_unicorn::MemAccessType::ReadWrite, begin, end, f: Box::new(|_,_,_,_|{}) };
        Ok(ToolResult::text(json!({"label":hk.label(),"range":hk.address_range().map(|(a,b)| json!([a,b])),"access":format!("{:?}", hk.mem_access()),"insn":format!("{:?}", hk.insn_type()),"source":"rustre_emu_unicorn::HookKind"}).to_string()))
    }
}

pub struct EmuUnicornHookInsnKindTool;
impl EmuUnicornHookInsnKindTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_hook_insn_kind".to_string(),
            description: "Build an Insn HookKind and report insn_type + label.".to_string(),
            input_schema: json!({"type":"object","required":["insn"],"properties":{"insn":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornHookInsnKindTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let insn = args.get("insn").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'insn'".into()))?;
        use rustre_emu_unicorn::InsnType;
        let it = match insn.to_ascii_uppercase().as_str() {
            "SYSCALL" => InsnType::SYSCALL,
            "SYSENTER" => InsnType::SYSENTER,
            "CPUID" => InsnType::CPUID,
            "IN" => InsnType::IN,
            "OUT" => InsnType::OUT,
            _ => return Err(McpError::InvalidParams("unknown insn".into())),
        };
        let hk = rustre_emu_unicorn::HookKind::Insn { insn: it, f: Box::new(|_|{}) };
        Ok(ToolResult::text(json!({"label":hk.label(),"insn":format!("{:?}", hk.insn_type()),"range":hk.address_range(),"source":"rustre_emu_unicorn::HookKind::Insn"}).to_string()))
    }
}

pub struct EmuUnicornEmuOptionsCustomTool;
impl EmuUnicornEmuOptionsCustomTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_emu_options_custom".to_string(),
            description: "Construct a custom EmuOptions and echo fields.".to_string(),
            input_schema: json!({"type":"object","required":["timeout_us","max_instructions"],"properties":{"timeout_us":{"type":"integer"},"max_instructions":{"type":"integer"},"stop_on_unmapped":{"type":"boolean"},"stop_on_invalid_insn":{"type":"boolean"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornEmuOptionsCustomTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let timeout_us = args.get("timeout_us").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'timeout_us'".into()))?;
        let max_instructions = args.get("max_instructions").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'max_instructions'".into()))?;
        let stop_on_unmapped = args.get("stop_on_unmapped").and_then(Value::as_bool).unwrap_or(true);
        let stop_on_invalid_insn = args.get("stop_on_invalid_insn").and_then(Value::as_bool).unwrap_or(true);
        let o = rustre_emu_unicorn::EmuOptions { timeout_us, max_instructions, stop_on_unmapped, stop_on_invalid_insn };
        Ok(ToolResult::text(json!({"timeout_us":o.timeout_us,"max_instructions":o.max_instructions,"stop_on_unmapped":o.stop_on_unmapped,"stop_on_invalid_insn":o.stop_on_invalid_insn,"source":"rustre_emu_unicorn::EmuOptions"}).to_string()))
    }
}

pub struct EmuUnicornRegisterFileMaskTool;
impl EmuUnicornRegisterFileMaskTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_register_file_mask".to_string(),
            description: "Set an X86 register, then read pc/sp masked by mode ptr_size.".to_string(),
            input_schema: json!({"type":"object","required":["rip","rsp","mode"],"properties":{"rip":{"type":"integer"},"rsp":{"type":"integer"},"mode":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornRegisterFileMaskTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let rip = args.get("rip").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rip'".into()))?;
        let rsp = args.get("rsp").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rsp'".into()))?;
        let mode_s = args.get("mode").and_then(Value::as_str).unwrap_or("X86_64");
        use rustre_emu_unicorn::Mode;
        let mode = match mode_s {
            "X86_16" => Mode::X86_16,
            "X86_32" => Mode::X86_32,
            "X86_64" => Mode::X86_64,
            _ => return Err(McpError::InvalidParams("unsupported mode".into())),
        };
        let mut rf = rustre_emu_unicorn::RegisterFile::default();
        rf.set_x86(rustre_emu_unicorn::X86Reg::RIP, rip);
        rf.set_x86(rustre_emu_unicorn::X86Reg::RSP, rsp);
        let pc = rf.pc(rustre_emu_unicorn::Arch::X86, mode);
        let sp = rf.sp(rustre_emu_unicorn::Arch::X86, mode);
        Ok(ToolResult::text(json!({"pc":pc,"sp":sp,"ptr_size":mode.ptr_size(),"source":"rustre_emu_unicorn::RegisterFile"}).to_string()))
    }
}

pub struct EmuUnicornMappedRegionReadRoundtripTool;
impl EmuUnicornMappedRegionReadRoundtripTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "emu_unicorn_mapped_region_read_roundtrip".to_string(),
            description: "Map a region, write bytes, read back and hex-encode.".to_string(),
            input_schema: json!({"type":"object","required":["base","size","offset","data_hex"],"properties":{"base":{"type":"integer"},"size":{"type":"integer"},"offset":{"type":"integer"},"data_hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EmuUnicornMappedRegionReadRoundtripTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as usize;
        let offset = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'offset'".into()))?;
        let data_hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let bytes: Vec<u8> = (0..data_hex.len()).step_by(2)
            .filter_map(|i| u8::from_str_radix(data_hex.get(i..i+2)?, 16).ok())
            .collect();
        let mut emu = rustre_emu_unicorn::UnicornEmu::new(rustre_emu_unicorn::Arch::X86, rustre_emu_unicorn::Mode::X86_64)
            .map_err(|e| McpError::InvalidParams(format!("new: {e}")))?;
        emu.map_region(base, size, rustre_emu_unicorn::Perm::RW).map_err(|e| McpError::InvalidParams(format!("map: {e}")))?;
        emu.write_mem(base + offset, &bytes).map_err(|e| McpError::InvalidParams(format!("write: {e}")))?;
        let read = emu.read_mem(base + offset, bytes.len()).map_err(|e| McpError::InvalidParams(format!("read: {e}")))?;
        let hex: String = read.iter().map(|b| format!("{:02x}", b)).collect();
        Ok(ToolResult::text(json!({"read_hex":hex,"len":read.len(),"match":read==bytes,"source":"rustre_emu_unicorn::UnicornEmu::read_mem"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (EmuUnicornModePtrSizeTool::definition(), Box::new(EmuUnicornModePtrSizeTool)),
        (EmuUnicornModeIsLittleEndianTool::definition(), Box::new(EmuUnicornModeIsLittleEndianTool)),
        (EmuUnicornNewX8664Tool::definition(), Box::new(EmuUnicornNewX8664Tool)),
        (EmuUnicornNewArm64Tool::definition(), Box::new(EmuUnicornNewArm64Tool)),
        (EmuUnicornNewArmThumbTool::definition(), Box::new(EmuUnicornNewArmThumbTool)),
        (EmuUnicornPermCanReadTool::definition(), Box::new(EmuUnicornPermCanReadTool)),
        (EmuUnicornPermCanExecTool::definition(), Box::new(EmuUnicornPermCanExecTool)),
        (EmuUnicornPermCanWriteTool::definition(), Box::new(EmuUnicornPermCanWriteTool)),
        (EmuUnicornHeapMallocSimTool::definition(), Box::new(EmuUnicornHeapMallocSimTool)),
        (EmuUnicornHeapCallocSimTool::definition(), Box::new(EmuUnicornHeapCallocSimTool)),
        (EmuUnicornHeapReallocSimTool::definition(), Box::new(EmuUnicornHeapReallocSimTool)),
        (EmuUnicornHeapFreeSimTool::definition(), Box::new(EmuUnicornHeapFreeSimTool)),
        (EmuUnicornCoverageRecordSeqTool::definition(), Box::new(EmuUnicornCoverageRecordSeqTool)),
        (EmuUnicornModeIsLittleEndianV2Tool::definition(), Box::new(EmuUnicornModeIsLittleEndianV2Tool)),
        (EmuUnicornModePtrSizeV2Tool::definition(), Box::new(EmuUnicornModePtrSizeV2Tool)),
        (EmuUnicornRegisterFileRoundtripTool::definition(), Box::new(EmuUnicornRegisterFileRoundtripTool)),
        (EmuUnicornPermWriteBitTool::definition(), Box::new(EmuUnicornPermWriteBitTool)),
        (EmuUnicornHeapAllocFreeCycleTool::definition(), Box::new(EmuUnicornHeapAllocFreeCycleTool)),
        (EmuUnicornHeapCallocOverflowCheckTool::definition(), Box::new(EmuUnicornHeapCallocOverflowCheckTool)),
        (EmuUnicornHeapReallocGrowTool::definition(), Box::new(EmuUnicornHeapReallocGrowTool)),
        (EmuUnicornHeapAllocationStatsTool::definition(), Box::new(EmuUnicornHeapAllocationStatsTool)),
        (EmuUnicornCoverageResetCheckTool::definition(), Box::new(EmuUnicornCoverageResetCheckTool)),
        (EmuUnicornCoverageHotBlockTool::definition(), Box::new(EmuUnicornCoverageHotBlockTool)),
        (EmuUnicornCoverageEdgeWalkTool::definition(), Box::new(EmuUnicornCoverageEdgeWalkTool)),
        (EmuUnicornOptionsDefaultsV2Tool::definition(), Box::new(EmuUnicornOptionsDefaultsV2Tool)),
        (EmuUnicornMappedRegionContainsTool::definition(), Box::new(EmuUnicornMappedRegionContainsTool)),
        (EmuUnicornHookkindLabelsTool::definition(), Box::new(EmuUnicornHookkindLabelsTool)),
        (EmuUnicornSyscallArgsPackTool::definition(), Box::new(EmuUnicornSyscallArgsPackTool)),
        (EmuUnicornPermConstantsB2Tool::definition(), Box::new(EmuUnicornPermConstantsB2Tool)),
        (EmuUnicornPermReadBitB2Tool::definition(), Box::new(EmuUnicornPermReadBitB2Tool)),
        (EmuUnicornPermExecBitB2Tool::definition(), Box::new(EmuUnicornPermExecBitB2Tool)),
        (EmuUnicornPermBitmaskEncodeB2Tool::definition(), Box::new(EmuUnicornPermBitmaskEncodeB2Tool)),
        (EmuUnicornHeapZeroSizeMallocB2Tool::definition(), Box::new(EmuUnicornHeapZeroSizeMallocB2Tool)),
        (EmuUnicornHeapExhaustionCheckB2Tool::definition(), Box::new(EmuUnicornHeapExhaustionCheckB2Tool)),
        (EmuUnicornHeapFreeInvalidB2Tool::definition(), Box::new(EmuUnicornHeapFreeInvalidB2Tool)),
        (EmuUnicornHeapBrkPositionB2Tool::definition(), Box::new(EmuUnicornHeapBrkPositionB2Tool)),
        (EmuUnicornHeapReallocFreeAddrB2Tool::definition(), Box::new(EmuUnicornHeapReallocFreeAddrB2Tool)),
        (EmuUnicornCoverageDefaultEmptyB2Tool::definition(), Box::new(EmuUnicornCoverageDefaultEmptyB2Tool)),
        (EmuUnicornCoverageHitCountB2Tool::definition(), Box::new(EmuUnicornCoverageHitCountB2Tool)),
        (EmuUnicornCoverageSingleBbB2Tool::definition(), Box::new(EmuUnicornCoverageSingleBbB2Tool)),
        (EmuUnicornNewMips32Tool::definition(), Box::new(EmuUnicornNewMips32Tool)),
        (EmuUnicornHeapAllocatorNewTool::definition(), Box::new(EmuUnicornHeapAllocatorNewTool)),
        (EmuUnicornHeapBytesUsedTool::definition(), Box::new(EmuUnicornHeapBytesUsedTool)),
        (EmuUnicornHeapReallocSameTool::definition(), Box::new(EmuUnicornHeapReallocSameTool)),
        (EmuUnicornHeapReallocMissingTool::definition(), Box::new(EmuUnicornHeapReallocMissingTool)),
        (EmuUnicornCoverageMostVisitedTool::definition(), Box::new(EmuUnicornCoverageMostVisitedTool)),
        (EmuUnicornCoverageResetClearsTool::definition(), Box::new(EmuUnicornCoverageResetClearsTool)),
        (EmuUnicornHeapFreeThenAllocTool::definition(), Box::new(EmuUnicornHeapFreeThenAllocTool)),
        (EmuUnicornHeapCallocZeroTool::definition(), Box::new(EmuUnicornHeapCallocZeroTool)),
        (EmuUnicornHeapMallocSequenceTool::definition(), Box::new(EmuUnicornHeapMallocSequenceTool)),
        (EmuUnicornPermRoundtripTool::definition(), Box::new(EmuUnicornPermRoundtripTool)),
        (EmuUnicornModeEndianCheckTool::definition(), Box::new(EmuUnicornModeEndianCheckTool)),
        (EmuUnicornHeapBrkFrontierTool::definition(), Box::new(EmuUnicornHeapBrkFrontierTool)),
        (EmuUnicornHeapDoubleFreeTool::definition(), Box::new(EmuUnicornHeapDoubleFreeTool)),
        (EmuUnicornHeapReallocShrinkTool::definition(), Box::new(EmuUnicornHeapReallocShrinkTool)),
        (EmuUnicornCoverageEmptyReportTool::definition(), Box::new(EmuUnicornCoverageEmptyReportTool)),
        (EmuUnicornHookAccessKindTool::definition(), Box::new(EmuUnicornHookAccessKindTool)),
        (EmuUnicornHookInsnKindTool::definition(), Box::new(EmuUnicornHookInsnKindTool)),
        (EmuUnicornEmuOptionsCustomTool::definition(), Box::new(EmuUnicornEmuOptionsCustomTool)),
        (EmuUnicornRegisterFileMaskTool::definition(), Box::new(EmuUnicornRegisterFileMaskTool)),
        (EmuUnicornMappedRegionReadRoundtripTool::definition(), Box::new(EmuUnicornMappedRegionReadRoundtripTool)),
    ]
}
