//! x86 control-flow graph builder.
//!
//! Provides [`X86ControlFlowGraph`], [`X86Block`], [`X86Edge`], and
//! [`build_cfg()`] for constructing a basic-block-level CFG from a sequence
//! of x86 instructions decoded via `iced-x86`.
//!
//! # Dispatch status (NOT wired — 2026-07-23)
//!
//! Nothing outside this file and `tests/blitz.rs` uses it. The decompiler
//! builds its CFG elsewhere (`rustre-decompiler` + `rustre-analysis-cfg`);
//! `rustre-arch-x86` contributes only `X86Arch::get_branches` to that path.
//! `build_cfg` hits in those other crates are their own same-named functions,
//! not this one.
//!
//! Unlike its four sibling `x86_*` modules this file carried no such note, so
//! its doc comment read as live infrastructure — meaning any edge-classification
//! work done here (e.g. indirect-branch handling) has zero effect on output.
//! Stated explicitly so that is a decision rather than a surprise.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};

// ─────────────────────────────────────────────────────────────────────────────
// EdgeKind
// ─────────────────────────────────────────────────────────────────────────────

/// The type of a control-flow edge between two basic blocks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// Unconditional branch (JMP or fall-through from a non-terminating insn).
    Unconditional,
    /// Taken branch of a conditional jump.
    ConditionalTrue,
    /// Not-taken (fall-through) branch of a conditional jump.
    ConditionalFalse,
    /// Call edge (destination may be another function).
    Call,
    /// Return edge from a RET instruction.
    Return,
    /// Indirect branch (unknown destination at analysis time).
    Indirect,
    /// Exception edge (fault path).
    Exception,
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Unconditional => "jmp",
            Self::ConditionalTrue => "jcc-T",
            Self::ConditionalFalse => "jcc-F",
            Self::Call => "call",
            Self::Return => "ret",
            Self::Indirect => "indir",
            Self::Exception => "exn",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// X86Edge
// ─────────────────────────────────────────────────────────────────────────────

/// A directed edge in the control-flow graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X86Edge {
    /// Address of the source basic block's first instruction.
    pub from_block: u64,
    /// Address of the destination basic block's first instruction.
    pub to_block: u64,
    /// Kind of edge.
    pub kind: EdgeKind,
}

impl X86Edge {
    #[must_use]
    pub fn new(from: u64, to: u64, kind: EdgeKind) -> Self {
        Self { from_block: from, to_block: to, kind }
    }
}

impl fmt::Display for X86Edge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#010x} --{}--> {:#010x}",
            self.from_block, self.kind, self.to_block
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// X86Insn (lightweight decoded snapshot stored inside blocks)
// ─────────────────────────────────────────────────────────────────────────────

/// A lightweight decoded instruction record stored in a [`X86Block`].
#[derive(Debug, Clone)]
pub struct X86Insn {
    /// Virtual address.
    pub address: u64,
    /// Mnemonic text.
    pub mnemonic: String,
    /// Length in bytes.
    pub len: usize,
    /// iced-x86 [`FlowControl`] classification.
    pub flow: FlowControl,
    /// Resolved branch target (if statically known).
    pub target: Option<u64>,
}

impl X86Insn {
    #[must_use]
    pub fn is_terminator(&self) -> bool {
        !matches!(self.flow, FlowControl::Next)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// X86Block
// ─────────────────────────────────────────────────────────────────────────────

/// A single basic block in the CFG.
///
/// A basic block is a maximal sequence of instructions with a single entry
/// point and (at most) a single exit point before a branch or fall-through.
#[derive(Debug, Clone)]
pub struct X86Block {
    /// Address of the first instruction.
    pub start: u64,
    /// Address one past the last byte of the last instruction.
    pub end: u64,
    /// The instructions in this block, in address order.
    pub insns: Vec<X86Insn>,
    /// Predecessor block addresses.
    pub predecessors: Vec<u64>,
    /// Successor block addresses.
    pub successors: Vec<u64>,
    /// Whether this block ends with a return.
    pub is_return: bool,
    /// Whether this block is unreachable (no predecessors except possibly the
    /// entry block).
    pub is_unreachable: bool,
}

impl X86Block {
    /// Construct an empty block beginning at `start`.
    ///
    /// Used by CFG builders to seed a fresh basic block before instructions
    /// are appended.
    #[must_use]
    pub fn new(start: u64) -> Self {
        Self {
            start,
            end: start,
            insns: Vec::new(),
            predecessors: Vec::new(),
            successors: Vec::new(),
            is_return: false,
            is_unreachable: false,
        }
    }

    #[must_use]
    pub fn len_bytes(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    #[must_use]
    pub fn insn_count(&self) -> usize {
        self.insns.len()
    }

    #[must_use]
    pub fn terminator(&self) -> Option<&X86Insn> {
        self.insns.last().filter(|i| i.is_terminator())
    }
}

impl fmt::Display for X86Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Block[{:#010x}..{:#010x}, {} insns, {} preds, {} succs]",
            self.start,
            self.end,
            self.insns.len(),
            self.predecessors.len(),
            self.successors.len(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CfgStats
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics about a constructed CFG.
#[derive(Debug, Clone, Default)]
pub struct CfgStats {
    pub block_count: usize,
    pub edge_count: usize,
    pub insn_count: usize,
    pub return_block_count: usize,
    pub indirect_branch_count: usize,
    pub call_edge_count: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// X86ControlFlowGraph
// ─────────────────────────────────────────────────────────────────────────────

/// A control-flow graph for an x86 function or code region.
///
/// Blocks are keyed by their start address. Edges are stored separately
/// and can be queried by source or destination.
#[derive(Debug, Default)]
pub struct X86ControlFlowGraph {
    /// Blocks, keyed by start address.
    blocks: BTreeMap<u64, X86Block>,
    /// All edges in the CFG.
    edges: Vec<X86Edge>,
    /// Entry block address.
    entry: Option<u64>,
    /// Machine bitness (16, 32, or 64).
    bitness: u32,
}

impl X86ControlFlowGraph {
    #[must_use]
    pub fn new(bitness: u32) -> Self {
        Self {
            bitness,
            ..Default::default()
        }
    }

    #[must_use]
    pub fn entry(&self) -> Option<u64> {
        self.entry
    }

    /// Machine bitness (16, 32, or 64) this CFG was constructed for.
    #[must_use]
    pub fn bitness(&self) -> u32 {
        self.bitness
    }

    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn blocks(&self) -> impl Iterator<Item = &X86Block> {
        self.blocks.values()
    }

    pub fn edges(&self) -> impl Iterator<Item = &X86Edge> {
        self.edges.iter()
    }

    #[must_use]
    pub fn get_block(&self, addr: u64) -> Option<&X86Block> {
        self.blocks.get(&addr)
    }

    /// Edges leaving a given block.
    #[must_use]
    pub fn successors_of(&self, addr: u64) -> Vec<&X86Edge> {
        self.edges
            .iter()
            .filter(|e| e.from_block == addr)
            .collect()
    }

    /// Edges entering a given block.
    #[must_use]
    pub fn predecessors_of(&self, addr: u64) -> Vec<&X86Edge> {
        self.edges
            .iter()
            .filter(|e| e.to_block == addr)
            .collect()
    }

    /// All addresses reachable from `start` via BFS.
    #[must_use]
    pub fn reachable_from(&self, start: u64) -> Vec<u64> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        // Only BLOCKS are reachable blocks. An edge may legitimately leave the
        // analysed range — `EdgeKind::Call` is documented as possibly targeting
        // another function, and a tail-call JMP does the same — but such a
        // target is not a node of this graph: `get_block` on it returns `None`.
        //
        // This used to enqueue and RETURN every edge target unconditionally, so
        // the result mixed block starts with external addresses. A caller doing
        // `get_block(a).unwrap()` over the result panicked; one using `if let
        // Some` silently dropped real blocks it thought it had visited, and
        // reachable-block counts were simply wrong. Measured on 200 generated
        // programs, 80 reported at least one non-block as reachable.
        if self.blocks.contains_key(&start) {
            queue.push_back(start);
        }
        while let Some(addr) = queue.pop_front() {
            if visited.insert(addr) {
                for edge in self.successors_of(addr) {
                    if self.blocks.contains_key(&edge.to_block) {
                        queue.push_back(edge.to_block);
                    }
                }
            }
        }
        let mut result: Vec<u64> = visited.into_iter().collect();
        result.sort_unstable();
        result
    }

    /// Compute statistics.
    #[must_use]
    pub fn stats(&self) -> CfgStats {
        CfgStats {
            block_count: self.blocks.len(),
            edge_count: self.edges.len(),
            insn_count: self.blocks.values().map(|b| b.insns.len()).sum(),
            return_block_count: self.blocks.values().filter(|b| b.is_return).count(),
            indirect_branch_count: self
                .edges
                .iter()
                .filter(|e| e.kind == EdgeKind::Indirect)
                .count(),
            call_edge_count: self
                .edges
                .iter()
                .filter(|e| e.kind == EdgeKind::Call)
                .count(),
        }
    }

    // ------------------------------------------------------------------
    // Internal builder helpers
    // ------------------------------------------------------------------

    fn add_edge(&mut self, from: u64, to: u64, kind: EdgeKind) {
        self.edges.push(X86Edge::new(from, to, kind));
        if let Some(blk) = self.blocks.get_mut(&from)
            && !blk.successors.contains(&to)
        {
            blk.successors.push(to);
        }
        if let Some(blk) = self.blocks.get_mut(&to)
            && !blk.predecessors.contains(&from)
        {
            blk.predecessors.push(from);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CFG builder implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Build a CFG by decoding all instructions from `bytes` starting at
/// `entry_address` and following control flow within the provided byte slice.
#[must_use]
pub fn build_cfg(entry_address: u64, bytes: &[u8], bitness: u32) -> X86ControlFlowGraph {
    let mut cfg = X86ControlFlowGraph::new(bitness);
    if bytes.is_empty() {
        return cfg;
    }

    let base = entry_address;

    // Phase 1: linear decode — collect all instructions and their flow info.
    let mut insns_by_addr: BTreeMap<u64, X86Insn> = BTreeMap::new();
    {
        let mut decoder = Decoder::with_ip(bitness, bytes, base, DecoderOptions::NONE);
        while decoder.can_decode() {
            let instr: Instruction = decoder.decode();
            if instr.is_invalid() {
                continue;
            }
            let addr = instr.ip();
            let len = instr.len();
            let flow = instr.flow_control();
            let target = match flow {
                FlowControl::UnconditionalBranch
                | FlowControl::ConditionalBranch
                | FlowControl::Call => Some(instr.near_branch_target()),
                _ => None,
            };
            let mnemonic = format!("{:?}", instr.mnemonic()).to_ascii_lowercase();
            insns_by_addr.insert(
                addr,
                X86Insn { address: addr, mnemonic, len, flow, target },
            );
        }
    }

    if insns_by_addr.is_empty() {
        return cfg;
    }

    // Phase 2: identify leaders (first instruction of every block).
    // Leaders:
    //   - Entry address
    //   - Targets of any branch
    //   - Instruction following a branch
    let mut leaders: HashSet<u64> = HashSet::new();
    leaders.insert(entry_address);

    for insn in insns_by_addr.values() {
        match insn.flow {
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                if let Some(t) = insn.target
                    && insns_by_addr.contains_key(&t)
                {
                    leaders.insert(t);
                }
                let fall = insn.address.wrapping_add(insn.len as u64);
                if insns_by_addr.contains_key(&fall) {
                    leaders.insert(fall);
                }
            }
            FlowControl::Return | FlowControl::Exception => {
                let fall = insn.address.wrapping_add(insn.len as u64);
                if insns_by_addr.contains_key(&fall) {
                    leaders.insert(fall);
                }
            }
            FlowControl::Call => {
                // A call target inside this function's byte range starts a
                // block too (recursive/thunk-style intra-function calls).
                if let Some(t) = insn.target
                    && insns_by_addr.contains_key(&t)
                {
                    leaders.insert(t);
                }
                let fall = insn.address.wrapping_add(insn.len as u64);
                if insns_by_addr.contains_key(&fall) {
                    leaders.insert(fall);
                }
            }
            // Indirect control transfers and software interrupts terminate a
            // block just like their direct counterparts: the following
            // instruction is a leader. Previously these fell through `_ => {}`
            // and flow silently continued through them.
            FlowControl::IndirectBranch
            | FlowControl::IndirectCall
            | FlowControl::Interrupt => {
                let fall = insn.address.wrapping_add(insn.len as u64);
                if insns_by_addr.contains_key(&fall) {
                    leaders.insert(fall);
                }
            }
            _ => {}
        }
    }

    // Phase 3: partition instructions into blocks.
    // BTreeMap keys are already in sorted order; no extra sort needed.
    let sorted_addrs: Vec<u64> = insns_by_addr.keys().copied().collect();

    let mut current_leader: Option<u64> = None;
    let mut block_map: BTreeMap<u64, Vec<X86Insn>> = BTreeMap::new();

    for addr in &sorted_addrs {
        if leaders.contains(addr) {
            current_leader = Some(*addr);
        }
        if let Some(leader) = current_leader {
            block_map
                .entry(leader)
                .or_default()
                .push(insns_by_addr[addr].clone());
        }
    }

    // Phase 4: build X86Block objects.
    for (leader, insns) in &block_map {
        let last = insns.last().unwrap();
        let end = last.address.wrapping_add(last.len as u64);
        let is_return = matches!(last.flow, FlowControl::Return);
        cfg.blocks.insert(
            *leader,
            X86Block {
                start: *leader,
                end,
                insns: insns.clone(),
                predecessors: Vec::new(),
                successors: Vec::new(),
                is_return,
                is_unreachable: false,
            },
        );
    }

    cfg.entry = Some(entry_address);

    // Phase 5: add edges.
    // Collect the edges first (immutable borrow), then add them.
    // Use a HashSet for O(1) membership checks instead of Vec::contains.
    let block_starts: HashSet<u64> = cfg.blocks.keys().copied().collect();
    let mut pending_edges: Vec<(u64, u64, EdgeKind)> = Vec::new();

    for (leader, insns) in &block_map {
        let last = insns.last().unwrap();
        match last.flow {
            FlowControl::UnconditionalBranch => {
                if let Some(t) = last.target {
                    pending_edges.push((*leader, t, EdgeKind::Unconditional));
                }
                // No target (register/memory JMP): destination unknown at
                // analysis time — emit no edge rather than a bogus
                // self-referential one.
            }
            FlowControl::ConditionalBranch => {
                if let Some(t) = last.target {
                    pending_edges.push((*leader, t, EdgeKind::ConditionalTrue));
                }
                let fall = last.address.wrapping_add(last.len as u64);
                if block_starts.contains(&fall) {
                    pending_edges.push((*leader, fall, EdgeKind::ConditionalFalse));
                }
            }
            FlowControl::Return => {
                // No outgoing edges from return blocks.
            }
            FlowControl::Call => {
                if let Some(t) = last.target {
                    pending_edges.push((*leader, t, EdgeKind::Call));
                }
                let fall = last.address.wrapping_add(last.len as u64);
                if block_starts.contains(&fall) {
                    pending_edges.push((*leader, fall, EdgeKind::Unconditional));
                }
            }
            FlowControl::IndirectBranch => {
                // Unknown destination — no successor edge. If a jump-table
                // recovery pass resolves targets it can add Indirect edges.
            }
            FlowControl::IndirectCall => {
                // Callee unknown, but the call returns: fall-through edge.
                let fall = last.address.wrapping_add(last.len as u64);
                if block_starts.contains(&fall) {
                    pending_edges.push((*leader, fall, EdgeKind::Unconditional));
                }
            }
            FlowControl::Interrupt => {
                // INT/INT3/etc: execution normally resumes after the trap.
                let fall = last.address.wrapping_add(last.len as u64);
                if block_starts.contains(&fall) {
                    pending_edges.push((*leader, fall, EdgeKind::Exception));
                }
            }
            FlowControl::Exception => {
                let fall = last.address.wrapping_add(last.len as u64);
                if block_starts.contains(&fall) {
                    pending_edges.push((*leader, fall, EdgeKind::Exception));
                }
            }
            FlowControl::Next => {
                // Fall-through.
                let fall = last.address.wrapping_add(last.len as u64);
                if block_starts.contains(&fall) {
                    pending_edges.push((*leader, fall, EdgeKind::Unconditional));
                }
            }
            _ => {}
        }
    }

    for (from, to, kind) in pending_edges {
        cfg.add_edge(from, to, kind);
    }

    // Phase 6: mark unreachable blocks.
    if let Some(entry) = cfg.entry {
        let reachable = cfg.reachable_from(entry);
        let reachable_set: HashSet<u64> = reachable.into_iter().collect();
        for blk in cfg.blocks.values_mut() {
            if !reachable_set.contains(&blk.start) {
                blk.is_unreachable = true;
            }
        }
    }

    cfg
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A simple x86-64 function:
    ///   mov eax, 0      ; 0x1000: B8 00 00 00 00
    ///   ret             ; 0x1005: C3
    const SIMPLE_RET: &[u8] = &[0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3];

    /// Unconditional jump to itself (infinite loop):
    ///   jmp $ ; EB FE
    const INFINITE_LOOP: &[u8] = &[0xEB, 0xFE];

    /// Simple conditional:
    ///   test eax, eax   ; 85 C0
    ///   jz +2           ; 74 02
    ///   nop             ; 90
    ///   nop             ; 90
    ///   ret             ; C3
    const CONDITIONAL: &[u8] = &[0x85, 0xC0, 0x74, 0x02, 0x90, 0x90, 0xC3];

    #[test]
    fn simple_function_builds() {
        let cfg = build_cfg(0x1000, SIMPLE_RET, 64);
        assert!(cfg.block_count() >= 1);
    }

    #[test]
    fn simple_function_has_return_block() {
        let cfg = build_cfg(0x1000, SIMPLE_RET, 64);
        assert!(cfg.blocks().any(|b| b.is_return));
    }

    #[test]
    fn entry_address_set() {
        let cfg = build_cfg(0x1000, SIMPLE_RET, 64);
        assert_eq!(cfg.entry(), Some(0x1000));
    }

    #[test]
    fn infinite_loop_single_block() {
        let cfg = build_cfg(0x2000, INFINITE_LOOP, 64);
        assert_eq!(cfg.block_count(), 1);
        // Should have a self-referential edge.
        assert!(cfg.edges().any(|e| e.from_block == 0x2000));
    }

    #[test]
    fn indirect_call_splits_block_and_falls_through() {
        // call rax   ; 0x4000: FF D0
        // mov eax, 1 ; 0x4002: B8 01 00 00 00
        // ret        ; 0x4007: C3
        let cfg = build_cfg(0x4000, &[0xFF, 0xD0, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3], 64);
        // The instruction after the indirect call must start a new block.
        assert!(cfg.blocks().any(|b| b.start == 0x4002), "0x4002 must be a leader");
        // And the call block must have a fall-through edge to it.
        assert!(
            cfg.edges().any(|e| e.from_block == 0x4000 && e.to_block == 0x4002),
            "indirect call must fall through to the next block"
        );
    }

    #[test]
    fn indirect_jmp_has_no_bogus_self_edge() {
        // jmp rax ; 0x5000: FF E0
        // ret     ; 0x5002: C3
        let cfg = build_cfg(0x5000, &[0xFF, 0xE0, 0xC3], 64);
        // Following instruction is a leader (block terminated)...
        assert!(cfg.blocks().any(|b| b.start == 0x5002));
        // ...and the indirect jmp emits no self-referential edge.
        assert!(
            !cfg.edges().any(|e| e.from_block == 0x5000
                && (e.to_block == 0x5000 || e.to_block == 0x5002)),
            "indirect jmp destination is unknown — no edge expected"
        );
    }

    #[test]
    fn backward_jump_into_block_middle_splits_it() {
        // 0x7000: nop            ; 90
        // 0x7001: nop            ; 90   <- backward target: must become a leader
        // 0x7002: test eax, eax  ; 85 C0
        // 0x7004: jne 0x7001     ; 75 FB
        // 0x7006: ret            ; C3
        let cfg = build_cfg(0x7000, &[0x90, 0x90, 0x85, 0xC0, 0x75, 0xFB, 0xC3], 64);
        assert!(
            cfg.blocks().any(|b| b.start == 0x7001),
            "jump target inside a block must split it"
        );
        // The entry block must now END before 0x7001.
        let entry = cfg.blocks().find(|b| b.start == 0x7000).unwrap();
        assert_eq!(entry.end, 0x7001, "entry block must stop at the split point");
        // And the loop edge lands on the split block.
        assert!(cfg.edges().any(|e| e.to_block == 0x7001 && e.from_block == 0x7001));
    }

    #[test]
    fn intra_function_call_target_is_leader() {
        // 0x6000: call +3 (to 0x6008)  ; E8 03 00 00 00
        // 0x6005: ret                  ; C3  (padding: nop nop)
        // 0x6008: ret                  ; C3
        let cfg = build_cfg(0x6000, &[0xE8, 0x03, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90, 0xC3], 64);
        assert!(
            cfg.blocks().any(|b| b.start == 0x6008),
            "in-range call target must start a block"
        );
    }

    #[test]
    fn conditional_produces_multiple_blocks() {
        let cfg = build_cfg(0x3000, CONDITIONAL, 64);
        assert!(cfg.block_count() >= 2);
    }

    #[test]
    fn reachable_from_entry() {
        let cfg = build_cfg(0x1000, SIMPLE_RET, 64);
        let reachable = cfg.reachable_from(0x1000);
        assert!(reachable.contains(&0x1000));
    }

    #[test]
    fn stats_block_count() {
        let cfg = build_cfg(0x1000, SIMPLE_RET, 64);
        let stats = cfg.stats();
        assert!(stats.block_count >= 1);
        assert!(stats.insn_count >= 2);
    }

    #[test]
    fn empty_bytes_returns_empty_cfg() {
        let cfg = build_cfg(0x1000, &[], 64);
        assert_eq!(cfg.block_count(), 0);
    }

    #[test]
    fn edge_display() {
        let e = X86Edge::new(0x1000, 0x2000, EdgeKind::ConditionalTrue);
        let s = e.to_string();
        assert!(s.contains("jcc-T"));
    }

    #[test]
    fn block_display() {
        let mut b = X86Block::new(0x1000);
        b.end = 0x1010;
        let s = b.to_string();
        assert!(s.contains("0x00001000"));
    }

    #[test]
    fn successors_and_predecessors() {
        let cfg = build_cfg(0x3000, CONDITIONAL, 64);
        let entry = cfg.get_block(0x3000).unwrap();
        assert!(!entry.successors.is_empty());
    }
}
