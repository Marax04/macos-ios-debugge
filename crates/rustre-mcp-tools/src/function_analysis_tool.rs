//! MCP tool: analyze a function — CFG, call sites, size estimation.
//!
//! The `FunctionAnalysisTool` accepts a byte buffer (the function body) plus a
//! base address.  It disassembles the bytes, builds a basic-block Control Flow
//! Graph, identifies intra-function edges, external calls, and estimated size.
//! The result is a structured JSON value suitable for MCP responses.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use async_trait::async_trait;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use rustre_mcp_server::{ContentBlock, McpError, ToolDefinition, ToolHandler, ToolResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ─── BasicBlock ──────────────────────────────────────────────────────────────

/// A single basic block in the control-flow graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Address of the first instruction.
    pub start: u64,
    /// Address one byte past the last instruction.
    pub end: u64,
    /// Number of instructions.
    pub instruction_count: usize,
    /// Addresses of successor blocks (up to 2 for conditional branches).
    pub successors: Vec<u64>,
    /// Addresses of predecessor blocks.
    pub predecessors: Vec<u64>,
    /// Whether this block ends with a return.
    pub is_exit: bool,
    /// Whether this block contains a call instruction.
    pub has_call: bool,
}

impl BasicBlock {
    /// Size of the block in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

impl std::fmt::Display for BasicBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BB[0x{:x}..0x{:x}] insns={} succs={}",
            self.start,
            self.end,
            self.instruction_count,
            self.successors.len()
        )
    }
}

// ─── CallSite ─────────────────────────────────────────────────────────────────

/// A call site found within the analyzed function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    /// Address of the call instruction.
    pub address: u64,
    /// Resolved call target (if determinable from static analysis).
    pub target: Option<u64>,
    /// Whether this is an indirect call (via register/memory).
    pub is_indirect: bool,
    /// Raw bytes of the call instruction.
    pub bytes: Vec<u8>,
}

// ─── FunctionInput ────────────────────────────────────────────────────────────

/// Input parameters for the function analysis tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInput {
    /// Hex-encoded bytes of the function body.
    pub hex: Option<String>,
    /// Raw byte array of the function body.
    pub bytes: Option<Vec<u8>>,
    /// Base virtual address of the function.
    pub base_address: Option<u64>,
    /// CPU bitness (16, 32, 64; default 64).
    pub bitness: Option<u32>,
    /// Maximum bytes to analyse (default: entire buffer, capped at 64 KiB).
    pub max_bytes: Option<usize>,
}

impl FunctionInput {
    fn resolve_bytes(&self) -> Result<Vec<u8>, McpError> {
        if let Some(hex) = &self.hex {
            return hex_decode(hex);
        }
        if let Some(bytes) = &self.bytes {
            return Ok(bytes.clone());
        }
        Err(McpError::InvalidParams(
            "function_analysis: provide 'hex' or 'bytes'".into(),
        ))
    }

    const fn effective_base(&self) -> u64 {
        match self.base_address {
            Some(v) => v,
            None => 0,
        }
    }

    const fn effective_bitness(&self) -> u32 {
        match self.bitness {
            Some(16 | 32 | 64) => self.bitness.unwrap(),
            _ => 64,
        }
    }

    const fn effective_max_bytes(&self) -> usize {
        match self.max_bytes {
            Some(n) if n > 0 && n <= 65536 => n,
            _ => 65536,
        }
    }
}

// ─── FunctionOutput ───────────────────────────────────────────────────────────

/// Structured result of function analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionOutput {
    /// Base address of the function.
    pub base_address: u64,
    /// Estimated function size in bytes.
    pub estimated_size: u64,
    /// Total number of instructions.
    pub instruction_count: usize,
    /// Number of basic blocks.
    pub block_count: usize,
    /// All basic blocks, keyed by start address.
    pub blocks: Vec<BasicBlock>,
    /// Call sites found in the function.
    pub call_sites: Vec<CallSite>,
    /// Unique external call targets (resolved only).
    pub external_calls: Vec<u64>,
    /// CFG cyclomatic complexity (edges - nodes + 2).
    pub cyclomatic_complexity: i64,
    /// Whether the function appears to have a standard prologue.
    pub has_prologue: bool,
    /// Whether the function appears to have a standard epilogue.
    pub has_epilogue: bool,
    /// JSON representation of the CFG.
    pub cfg_json: Value,
}

// ─── cfg_to_json() ────────────────────────────────────────────────────────────

/// Serialise a slice of `BasicBlock`s to a compact JSON CFG representation.
///
/// The returned object has the form:
/// ```json
/// {
///   "nodes": [{ "id": "0x1000", "size": 12, "instruction_count": 3 }, ...],
///   "edges": [{ "from": "0x1000", "to": "0x100c", "kind": "fall" }, ...]
/// }
/// ```
#[must_use]
pub fn cfg_to_json(blocks: &[BasicBlock]) -> Value {
    let nodes: Vec<Value> = blocks
        .iter()
        .map(|b| {
            json!({
                "id": format!("0x{:x}", b.start),
                "start": b.start,
                "end": b.end,
                "size": b.size(),
                "instruction_count": b.instruction_count,
                "is_exit": b.is_exit,
                "has_call": b.has_call
            })
        })
        .collect();

    let mut edges: Vec<Value> = Vec::new();
    for b in blocks {
        let kind = if b.successors.len() > 1 { "branch" } else { "fall" };
        for &succ in &b.successors {
            edges.push(json!({
                "from": format!("0x{:x}", b.start),
                "to": format!("0x{:x}", succ),
                "kind": kind
            }));
        }
    }

    json!({ "nodes": nodes, "edges": edges })
}

// ─── Core analysis ────────────────────────────────────────────────────────────

/// Analyse the function body in `data`.
pub fn analyse_function(
    data: &[u8],
    base_address: u64,
    bitness: u32,
    max_bytes: usize,
) -> FunctionOutput {
    let data = if data.len() > max_bytes {
        &data[..max_bytes]
    } else {
        data
    };

    // ── Pass 1: decode all reachable instructions via BFS ─────────────────────
    let mut decoded: BTreeMap<u64, (Instruction, Vec<u8>)> = BTreeMap::new();
    let mut work_queue: VecDeque<u64> = VecDeque::new();
    work_queue.push_back(base_address);

    while let Some(ip) = work_queue.pop_front() {
        if decoded.contains_key(&ip) {
            continue;
        }
        let offset = ip.saturating_sub(base_address) as usize;
        if offset >= data.len() {
            continue;
        }
        let slice = &data[offset..];
        let mut dec = Decoder::with_ip(bitness, slice, ip, DecoderOptions::NONE);
        let mut insn = Instruction::default();
        dec.decode_out(&mut insn);
        if insn.is_invalid() || insn.len() == 0 {
            continue;
        }
        let raw_len = insn.len();
        let raw_end = offset + raw_len;
        let raw = if raw_end <= data.len() {
            data[offset..raw_end].to_vec()
        } else {
            vec![]
        };
        let next_ip = ip + raw_len as u64;
        let flow = insn.flow_control();

        match flow {
            FlowControl::Next => {
                work_queue.push_back(next_ip);
            }
            FlowControl::ConditionalBranch => {
                work_queue.push_back(next_ip);
                if let Some(target) = near_branch_target(&insn) {
                    if target >= base_address && target.saturating_sub(base_address) < data.len() as u64 {
                        work_queue.push_back(target);
                    }
                }
            }
            FlowControl::UnconditionalBranch => {
                if let Some(target) = near_branch_target(&insn) {
                    if target >= base_address && target.saturating_sub(base_address) < data.len() as u64 {
                        work_queue.push_back(target);
                    }
                }
            }
            FlowControl::Call => {
                work_queue.push_back(next_ip);
            }
            FlowControl::Return => {} // stop BFS at return
            _ => {
                work_queue.push_back(next_ip);
            }
        }
        decoded.insert(ip, (insn, raw));
    }

    // ── Pass 2: build basic blocks ────────────────────────────────────────────
    // Determine block leaders: entry + every branch target + instruction after branch.
    let mut leaders: HashSet<u64> = HashSet::new();
    leaders.insert(base_address);

    for (&ip, (insn, _)) in &decoded {
        let flow = insn.flow_control();
        let next_ip = ip + insn.len() as u64;
        match flow {
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                if let Some(target) = near_branch_target(insn) {
                    leaders.insert(target);
                }
                leaders.insert(next_ip);
            }
            FlowControl::Call | FlowControl::IndirectCall => {
                leaders.insert(next_ip);
            }
            FlowControl::Return => {
                leaders.insert(next_ip);
            }
            _ => {}
        }
    }

    let mut sorted_leaders: Vec<u64> = leaders.into_iter().collect();
    sorted_leaders.sort_unstable();

    // Build blocks from the sorted leaders.
    let all_ips: Vec<u64> = decoded.keys().copied().collect();
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut block_map: HashMap<u64, usize> = HashMap::new(); // start → index

    for &leader in &sorted_leaders {
        if !decoded.contains_key(&leader) {
            continue;
        }
        let block_idx = blocks.len();
        block_map.insert(leader, block_idx);

        let mut insn_count = 0usize;
        let mut cur = leader;
        let mut is_exit = false;
        let mut has_call = false;
        let mut successors: Vec<u64> = Vec::new();
        let mut block_end = leader;

        loop {
            let Some((insn, _)) = decoded.get(&cur) else {
                break;
            };
            insn_count += 1;
            let next_ip = cur + insn.len() as u64;
            block_end = next_ip;
            let flow = insn.flow_control();

            match flow {
                FlowControl::Return => {
                    is_exit = true;
                    break;
                }
                FlowControl::ConditionalBranch => {
                    successors.push(next_ip);
                    if let Some(target) = near_branch_target(insn) {
                        successors.push(target);
                    }
                    break;
                }
                FlowControl::UnconditionalBranch => {
                    if let Some(target) = near_branch_target(insn) {
                        successors.push(target);
                    }
                    break;
                }
                FlowControl::Call | FlowControl::IndirectCall => {
                    has_call = true;
                    // fall through to next instruction
                    if sorted_leaders.binary_search(&next_ip).is_ok()
                        && decoded.contains_key(&next_ip)
                    {
                        successors.push(next_ip);
                        break;
                    }
                }
                _ => {}
            }

            // If next_ip is a leader of another block, stop here.
            if next_ip != leader && sorted_leaders.binary_search(&next_ip).is_ok() {
                successors.push(next_ip);
                break;
            }

            if !decoded.contains_key(&next_ip) {
                break;
            }
            cur = next_ip;
        }

        blocks.push(BasicBlock {
            start: leader,
            end: block_end,
            instruction_count: insn_count,
            successors,
            predecessors: Vec::new(), // filled next
            is_exit,
            has_call,
        });
    }

    // Fill predecessors.
    let edges: Vec<(u64, u64)> = blocks
        .iter()
        .flat_map(|b| b.successors.iter().map(move |&s| (b.start, s)))
        .collect();
    for (from, to) in &edges {
        if let Some(&to_idx) = block_map.get(to) {
            if !blocks[to_idx].predecessors.contains(from) {
                blocks[to_idx].predecessors.push(*from);
            }
        }
    }

    // ── Call site extraction ───────────────────────────────────────────────────
    let mut call_sites: Vec<CallSite> = Vec::new();
    for (&ip, (insn, raw)) in &decoded {
        let flow = insn.flow_control();
        if matches!(flow, FlowControl::Call | FlowControl::IndirectCall) {
            let target = near_branch_target(insn);
            let is_indirect = matches!(flow, FlowControl::IndirectCall);
            call_sites.push(CallSite {
                address: ip,
                target,
                is_indirect,
                bytes: raw.clone(),
            });
        }
    }
    call_sites.sort_by_key(|c| c.address);

    let external_calls: Vec<u64> = call_sites
        .iter()
        .filter_map(|c| c.target)
        .filter(|&t| t < base_address || t >= base_address + data.len() as u64)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    // ── Cyclomatic complexity ──────────────────────────────────────────────────
    let e = edges.len() as i64;
    let n = blocks.len() as i64;
    let cyclomatic_complexity = e - n + 2;

    // ── Prologue / epilogue detection ─────────────────────────────────────────
    let has_prologue = check_prologue(data, bitness);
    let has_epilogue = check_epilogue(data, bitness);

    // ── Estimated size ────────────────────────────────────────────────────────
    let estimated_size = all_ips
        .iter()
        .filter_map(|&ip| decoded.get(&ip).map(|(insn, _)| ip + insn.len() as u64))
        .max()
        .unwrap_or(base_address)
        .saturating_sub(base_address);

    let cfg_json = cfg_to_json(&blocks);

    FunctionOutput {
        base_address,
        estimated_size,
        instruction_count: decoded.len(),
        block_count: blocks.len(),
        blocks,
        call_sites,
        external_calls,
        cyclomatic_complexity,
        has_prologue,
        has_epilogue,
        cfg_json,
    }
}

fn near_branch_target(insn: &Instruction) -> Option<u64> {
    use iced_x86::OpKind;
    for i in 0..insn.op_count() {
        match insn.op_kind(i) {
            OpKind::NearBranch16 => return Some(u64::from(insn.near_branch16())),
            OpKind::NearBranch32 => return Some(u64::from(insn.near_branch32())),
            OpKind::NearBranch64 => return Some(insn.near_branch64()),
            _ => {}
        }
    }
    None
}

/// Heuristic prologue detection (x86-64: push rbp / mov rbp,rsp).
fn check_prologue(data: &[u8], bitness: u32) -> bool {
    if data.len() < 3 {
        return false;
    }
    if bitness == 64 {
        // push rbp = 0x55; mov rbp,rsp = 0x48 0x89 0xE5
        data[0] == 0x55 && data.len() >= 4 && data[1] == 0x48 && data[2] == 0x89 && data[3] == 0xE5
    } else if bitness == 32 {
        // push ebp = 0x55; mov ebp,esp = 0x89 0xE5
        data[0] == 0x55 && data.len() >= 3 && data[1] == 0x89 && data[2] == 0xE5
    } else {
        false
    }
}

/// Heuristic epilogue detection: function ends with `ret` (0xC3) or
/// `leave; ret` (0xC9 0xC3).
fn check_epilogue(data: &[u8], _bitness: u32) -> bool {
    if data.is_empty() {
        return false;
    }
    let last = data[data.len() - 1];
    if last == 0xC3 || last == 0xCB {
        return true;
    }
    if data.len() >= 2 && data[data.len() - 2] == 0xC9 && last == 0xC3 {
        return true;
    }
    false
}

// ─── FunctionAnalysisTool ─────────────────────────────────────────────────────

/// MCP tool: analyze a function's control-flow graph, call sites, and size.
pub struct FunctionAnalysisTool;

impl FunctionAnalysisTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analyze_function".to_owned(),
            description: "Analyse a function: build CFG, count basic blocks, identify call sites, \
                          estimate size, compute cyclomatic complexity. \
                          Provide 'hex' (hex string) or 'bytes' (array). \
                          Optional: base_address, bitness (64), max_bytes."
                .to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "hex": { "type": "string" },
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "base_address": { "type": "integer" },
                    "bitness": { "type": "integer", "enum": [16, 32, 64] },
                    "max_bytes": { "type": "integer" }
                }
            }),
            parameters: serde_json::Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for FunctionAnalysisTool {

    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let input = FunctionInput {
            hex: args.get("hex").and_then(Value::as_str).map(str::to_owned),
            bytes: args
                .get("bytes")
                .and_then(Value::as_array)
                .map(|arr| bytes_from_json_array(arr, "bytes"))
                .transpose()?,
            base_address: args.get("base_address").and_then(Value::as_u64),
            bitness: args.get("bitness").and_then(Value::as_u64).map(|n| n as u32),
            max_bytes: args.get("max_bytes").and_then(Value::as_u64).map(|n| n as usize),
        };

        let data = input.resolve_bytes()?;
        if data.is_empty() {
            return Err(McpError::InvalidParams("empty byte buffer".into()));
        }

        let output = analyse_function(
            &data,
            input.effective_base(),
            input.effective_bitness(),
            input.effective_max_bytes(),
        );

        // Build a human-readable summary.
        let summary = build_summary(&output);

        Ok(ToolResult {
            content: vec![ContentBlock::Text { text: summary }],
            is_error: false,
        })
    }
}

fn build_summary(o: &FunctionOutput) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = write!(s, "Function @ 0x{:x}\n", o.base_address);
    let _ = write!(s, "  Estimated size : {} bytes\n", o.estimated_size);
    let _ = write!(s, "  Instructions   : {}\n", o.instruction_count);
    let _ = write!(s, "  Basic blocks   : {}\n", o.block_count);
    let _ = write!(s, "  Cyclomatic CC  : {}\n", o.cyclomatic_complexity);
    let _ = write!(s, "  Has prologue   : {}\n", o.has_prologue);
    let _ = write!(s, "  Has epilogue   : {}\n", o.has_epilogue);
    let _ = write!(s, "  Call sites     : {}\n", o.call_sites.len());
    let _ = write!(s, "  External calls : {}\n", o.external_calls.len());
    if !o.blocks.is_empty() {
        s.push_str("\nBasic blocks:\n");
        for b in &o.blocks {
            let _ = write!(
                s,
                "  0x{:x} .. 0x{:x}  {} insns  succs=[",
                b.start, b.end, b.instruction_count,
            );
            for (i, a) in b.successors.iter().enumerate() {
                if i > 0 { s.push_str(", "); }
                let _ = write!(s, "0x{a:x}");
            }
            s.push_str("]\n");
        }
    }
    if !o.call_sites.is_empty() {
        s.push_str("\nCall sites:\n");
        for c in &o.call_sites {
            let _ = write!(s, "  0x{:x} -> ", c.address);
            match c.target {
                Some(t) => { let _ = write!(s, "0x{t:x}\n"); }
                None => s.push_str("indirect\n"),
            }
        }
    }
    s
}

// ─── Hex helpers ─────────────────────────────────────────────────────────────

fn hex_decode(s: &str) -> Result<Vec<u8>, McpError> {
    let s = s.replace([' ', '\n', '\t'], "");
    if !s.len().is_multiple_of(2) {
        return Err(McpError::InvalidParams("odd-length hex string".into()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let b = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| McpError::InvalidParams(format!("invalid hex at {i}")))?;
        out.push(b);
    }
    Ok(out)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple 64-bit function: push rbp / mov rbp,rsp / nop / pop rbp / ret
    const SIMPLE_FUNC: &[u8] = &[
        0x55, // push rbp
        0x48, 0x89, 0xE5, // mov rbp, rsp
        0x90, // nop
        0x5D, // pop rbp
        0xC3, // ret
    ];

    #[test]
    fn analyse_simple_function() {
        let out = analyse_function(SIMPLE_FUNC, 0x1000, 64, 65536);
        assert!(out.instruction_count > 0);
        assert!(out.block_count >= 1);
        assert!(out.has_prologue);
        assert!(out.has_epilogue);
    }

    /// A bad element must be an ERROR, not a silently shorter buffer.
    ///
    /// This is the negative control the family was missing: `parse_pdata` reads
    /// fixed-size records, so dropping one element shifts every later record and
    /// the caller gets a confident wrong answer instead of a complaint.
    #[test]
    fn a_bad_array_element_is_refused_not_dropped() {
        let good = serde_json::json!({ "pdata": [1, 2, 3, 4] });
        assert_eq!(
            extract_byte_array(&good, "pdata", "pdata_hex").unwrap(),
            vec![1, 2, 3, 4],
            "positive control: a well-formed array must still decode"
        );

        for bad in [
            serde_json::json!({ "pdata": [1, 2, 999, 4] }), // out of byte range
            serde_json::json!({ "pdata": [1, 2, "ff", 4] }), // not an integer
            serde_json::json!({ "pdata": [1, 2, -1, 4] }),  // negative
        ] {
            let err = extract_byte_array(&bad, "pdata", "pdata_hex").unwrap_err();
            assert!(
                format!("{err:?}").contains("pdata"),
                "the error must name the offending key: {err:?}"
            );
        }
    }

    #[test]
    fn cfg_to_json_empty() {
        let json = cfg_to_json(&[]);
        assert!(json["nodes"].as_array().unwrap().is_empty());
        assert!(json["edges"].as_array().unwrap().is_empty());
    }

    #[test]
    fn cfg_to_json_single_block() {
        let blocks = vec![BasicBlock {
            start: 0x1000,
            end: 0x1007,
            instruction_count: 3,
            successors: vec![],
            predecessors: vec![],
            is_exit: true,
            has_call: false,
        }];
        let json = cfg_to_json(&blocks);
        assert_eq!(json["nodes"].as_array().unwrap().len(), 1);
        assert_eq!(json["edges"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn check_prologue_64() {
        let data = &[0x55u8, 0x48, 0x89, 0xE5];
        assert!(check_prologue(data, 64));
    }

    #[test]
    fn check_prologue_32() {
        let data = &[0x55u8, 0x89, 0xE5];
        assert!(check_prologue(data, 32));
    }

    #[test]
    fn check_epilogue_ret() {
        assert!(check_epilogue(&[0x90, 0xC3], 64));
    }

    #[test]
    fn check_epilogue_leave_ret() {
        assert!(check_epilogue(&[0x90, 0xC9, 0xC3], 64));
    }

    #[test]
    fn no_call_sites_in_simple() {
        let out = analyse_function(SIMPLE_FUNC, 0, 64, 65536);
        assert!(out.call_sites.is_empty());
    }

    #[test]
    fn function_with_call() {
        // call +0 (5 bytes) then ret
        let data: Vec<u8> = vec![0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3];
        let out = analyse_function(&data, 0x2000, 64, 65536);
        assert_eq!(out.call_sites.len(), 1);
    }

    #[test]
    fn cyclomatic_complexity_linear() {
        // Linear function: no branches, 1 block => CC = 0 - 1 + 2 = 1
        let out = analyse_function(SIMPLE_FUNC, 0, 64, 65536);
        assert!(out.cyclomatic_complexity >= 1);
    }
}

// ─── FindExtraPdataFuncsTool ──────────────────────────────────────────────────

/// MCP tool: gap F — recover functions missing from a PE x64 `.pdata`
/// exception directory by scanning the uncovered regions of `.text` for
/// x86-64 prologues with a valid RET/JMP terminator.
pub struct FindExtraPdataFuncsTool;

impl FindExtraPdataFuncsTool {
    /// Return the `ToolDefinition` for this tool.
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "find_extra_pdata_funcs".to_owned(),
            description:
                "Find x86-64 functions present in .text but missing from the PE .pdata exception \
                 directory. Provide hex/bytes for both .pdata and .text, the .text virtual base \
                 address, and the PE image base."
                    .to_owned(),
            input_schema: json!({
                "type": "object",
                "required": ["pdata", "text", "text_base", "image_base"],
                "properties": {
                    "pdata":      { "type": "array", "items": { "type": "integer" }, "description": "Raw .pdata bytes" },
                    "pdata_hex":  { "type": "string", "description": "Hex .pdata bytes (alt to pdata)" },
                    "text":       { "type": "array", "items": { "type": "integer" }, "description": "Raw .text bytes" },
                    "text_hex":   { "type": "string", "description": "Hex .text bytes (alt to text)" },
                    "text_base":  { "type": "integer", "description": ".text virtual base address" },
                    "image_base": { "type": "integer", "description": "PE image base" }
                }
            }),
            parameters: serde_json::Value::Null,
        }
    }
}

/// Convert a JSON array into bytes, refusing anything that is not one.
///
/// The previous `filter_map(...ok())` here silently DROPPED a non-integer or
/// out-of-range element, so `[1, 2, 999, 4]` yielded three bytes. That is not a
/// smaller answer, it is a wrong one: `parse_pdata` reads fixed 12-byte records,
/// so one dropped element misaligns every record after it and the tool reports a
/// plausible, false result. The sibling copy in `wire_tools.rs` already returned
/// `Err` here — of the two, only one can be right.
fn bytes_from_json_array(arr: &[Value], key: &str) -> Result<Vec<u8>, McpError> {
    arr.iter()
        .map(|v| {
            v.as_u64()
                .ok_or_else(|| McpError::InvalidParams(format!("{key}: not integer")))
                .and_then(|n| {
                    u8::try_from(n)
                        .map_err(|_| McpError::InvalidParams(format!("{key}: byte out of range")))
                })
        })
        .collect()
}

fn extract_byte_array(args: &Value, key: &str, hex_key: &str) -> Result<Vec<u8>, McpError> {
    if let Some(arr) = args.get(key).and_then(Value::as_array) {
        return bytes_from_json_array(arr, key);
    }
    if let Some(hex) = args.get(hex_key).and_then(Value::as_str) {
        return hex_decode(hex);
    }
    Err(McpError::InvalidParams(format!(
        "missing '{key}' or '{hex_key}'"
    )))
}

#[async_trait]
impl ToolHandler for FindExtraPdataFuncsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_analysis_fn::{find_extra_pdata_funcs, parse_pdata};
        use rustre_core::address::{Address, AddressRange};

        let pdata = extract_byte_array(&args, "pdata", "pdata_hex")?;
        let text = extract_byte_array(&args, "text", "text_hex")?;
        let text_base = args
            .get("text_base")
            .and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'text_base'".into()))?;
        let image_base = args
            .get("image_base")
            .and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'image_base'".into()))?;

        let entries = parse_pdata(&pdata);
        let text_range = AddressRange::new(
            Address::new(text_base),
            Address::new(text_base + text.len() as u64),
        );
        let (extras, stats) = find_extra_pdata_funcs(
            Address::new(image_base),
            text_range,
            &text,
            &entries,
        );

        let extras_json: Vec<Value> = extras
            .iter()
            .map(|fb| {
                json!({
                    "start_va": format!("0x{:x}", fb.start.as_u64()),
                    "end_va": fb.end.map(|e| format!("0x{:x}", e.as_u64())),
                    "size": fb.byte_size(),
                    "prologue": fb.name.clone().unwrap_or_default(),
                    "confidence": format!("{:?}", fb.confidence),
                })
            })
            .collect();

        Ok(ToolResult {
            content: vec![ContentBlock::Text {
                text: json!({
                    "extras": extras_json,
                    "stats": {
                        "gaps_scanned": stats.gaps_scanned,
                        "prologue_matches": stats.prologue_matches,
                        "candidates_validated": stats.candidates_validated,
                        "pdata_count": stats.pdata_count,
                    }
                })
                .to_string(),
            }],
            is_error: false,
        })
    }
}
