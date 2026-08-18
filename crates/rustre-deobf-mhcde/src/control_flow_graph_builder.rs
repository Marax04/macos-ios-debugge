//! CFG builder: leader detection, basic block construction, branch/call/ret
//! edges, and natural loop detection for x86/x64 instruction streams.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use ahash::AHashMap as HashMap;
use serde::{Deserialize, Serialize};

// ─── Public types ─────────────────────────────────────────────────────────────

/// A virtual address (byte offset into the binary image).
pub type Addr = u64;

/// Classification of a basic block terminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TermKind {
    /// Unconditional jump (JMP rel8/rel32, JMP r/m64).
    Jump,
    /// Conditional branch (Jcc rel8/rel32).
    Branch,
    /// Call instruction — creates a non-local successor.
    Call,
    /// Return instruction.
    Return,
    /// Interrupt / `SYSCALL` / `SYSENTER`.
    Trap,
    /// Falls through into the next basic block (no explicit terminator).
    FallThrough,
}

/// A single basic block in the CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Address of the first byte.
    pub start: Addr,
    /// Address one past the last byte.
    pub end: Addr,
    /// Kind of the block's terminator instruction.
    pub term: TermKind,
    /// Successor addresses (0–2 elements).
    pub succs: Vec<Addr>,
    /// Predecessor addresses.
    pub preds: Vec<Addr>,
    /// `true` when this block is a loop header.
    pub is_loop_header: bool,
    /// Loop depth (0 = not in any loop).
    pub loop_depth: u32,
}

impl BasicBlock {
    /// Create a new basic block.
    #[must_use]
    pub const fn new(start: Addr, end: Addr, term: TermKind) -> Self {
        Self {
            start,
            end,
            term,
            succs: Vec::new(),
            preds: Vec::new(),
            is_loop_header: false,
            loop_depth: 0,
        }
    }

    /// Return the length in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// True when the block has no predecessors (entry-like).
    #[must_use]
    pub const fn is_entry(&self) -> bool {
        self.preds.is_empty()
    }
}

/// A natural loop detected in the CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NaturalLoop {
    /// The loop header block address.
    pub header: Addr,
    /// All blocks in the loop body (including the header).
    pub body: BTreeSet<Addr>,
    /// Back-edge source that defines this loop.
    pub back_edge_from: Addr,
    /// Loop nesting depth (1 = outermost).
    pub depth: u32,
}

impl NaturalLoop {
    /// Check whether `addr` is in the loop body.
    #[must_use]
    pub fn contains(&self, addr: Addr) -> bool {
        self.body.contains(&addr)
    }

    /// Number of blocks in the loop.
    #[must_use]
    pub fn size(&self) -> usize {
        self.body.len()
    }
}

/// The full control-flow graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    /// All basic blocks, keyed by start address.
    pub blocks: BTreeMap<Addr, BasicBlock>,
    /// Entry point address.
    pub entry: Addr,
    /// Detected natural loops.
    pub loops: Vec<NaturalLoop>,
    /// Dominator tree: for each block, its immediate dominator.
    pub idom: HashMap<Addr, Addr>,
}

impl ControlFlowGraph {
    /// Return an iterator over blocks in address order.
    pub fn iter_blocks(&self) -> impl Iterator<Item = &BasicBlock> {
        self.blocks.values()
    }

    /// Look up a block by start address.
    #[must_use]
    pub fn block(&self, addr: Addr) -> Option<&BasicBlock> {
        self.blocks.get(&addr)
    }

    /// Return all back-edge pairs `(tail, header)` where `tail` → `header`
    /// and `header` dominates `tail`.
    #[must_use]
    pub fn back_edges(&self) -> Vec<(Addr, Addr)> {
        let mut edges = Vec::new();
        for block in self.blocks.values() {
            for &succ in &block.succs {
                if self.dominates(succ, block.start) {
                    edges.push((block.start, succ));
                }
            }
        }
        edges
    }

    /// Return `true` when `a` dominates `b` (i.e., every path from the entry
    /// to `b` passes through `a`).
    #[must_use]
    pub fn dominates(&self, a: Addr, b: Addr) -> bool {
        if a == b {
            return true;
        }
        let mut cur = b;
        loop {
            match self.idom.get(&cur) {
                None => return false,
                Some(&dom) if dom == a => return true,
                Some(&dom) if dom == cur => return false, // root
                Some(&dom) => cur = dom,
            }
        }
    }

    /// Return the number of basic blocks.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Compute the total number of CFG edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.blocks.values().map(|b| b.succs.len()).sum()
    }

    /// Return the reverse post-order traversal of the CFG.
    #[must_use]
    pub fn reverse_post_order(&self) -> Vec<Addr> {
        let mut visited = HashSet::new();
        let mut post_order = Vec::new();
        self.dfs_post(self.entry, &mut visited, &mut post_order);
        post_order.reverse();
        post_order
    }

    fn dfs_post(&self, addr: Addr, visited: &mut HashSet<Addr>, order: &mut Vec<Addr>) {
        // Iterative post-order DFS to avoid stack overflow on adversarial input
        // with deeply nested or cyclically structured CFGs.
        enum Frame { Enter(Addr), Leave(Addr) }
        let mut stack: Vec<Frame> = vec![Frame::Enter(addr)];
        while let Some(frame) = stack.pop() {
            match frame {
                Frame::Enter(a) => {
                    if !visited.insert(a) {
                        continue;
                    }
                    stack.push(Frame::Leave(a));
                    if let Some(block) = self.blocks.get(&a) {
                        for &succ in block.succs.iter().rev() {
                            stack.push(Frame::Enter(succ));
                        }
                    }
                }
                Frame::Leave(a) => {
                    order.push(a);
                }
            }
        }
    }
}

// ─── Instruction scanner ─────────────────────────────────────────────────────

/// Minimal x86/x64 instruction length estimator — not a full disassembler, but
/// sufficient to find branch targets and block terminators in typical code.
#[derive(Debug, Default, Clone)]
pub struct InsnScanner;

/// Result of scanning a single instruction.
#[derive(Debug, Clone)]
pub struct InsnInfo {
    /// Byte offset of this instruction.
    pub offset: usize,
    /// Total byte length.
    pub len: usize,
    /// Whether this instruction is a leader (start of a basic block).
    pub is_leader: bool,
    /// Terminator kind, if this instruction ends a block.
    pub term: Option<TermKind>,
    /// Branch/call target if resolvable.
    pub target: Option<Addr>,
}

impl InsnScanner {
    /// Estimate the length of a single x86/x64 instruction starting at `data[off]`.
    ///
    /// This is intentionally conservative — it handles the common patterns seen
    /// in obfuscated code, not the full x86 encoding table.
    #[must_use]
    pub fn estimate_len(data: &[u8], off: usize) -> usize {
        if off >= data.len() {
            return 1;
        }
        let b0 = data[off];
        // REX prefix (0x40-0x4F)
        let (b1_off, b0_eff) = if b0 >= 0x40 && b0 <= 0x4F && off + 1 < data.len() {
            (off + 1, data[off + 1])
        } else {
            (off, b0)
        };
        // 66h / 67h / F2h / F3h prefixes
        let b1_off = if matches!(b0_eff, 0x66 | 0x67 | 0xF2 | 0xF3) && b1_off + 1 < data.len() {
            b1_off + 1
        } else {
            b1_off
        };

        let main_byte = if b1_off < data.len() { data[b1_off] } else { return 1; };

        match main_byte {
            // Single-byte instructions
            0x90 | 0xC3 | 0xCB | 0xC9 | 0xF4 | 0xCC | 0xCE | 0xF8 | 0xF9 | 0xFA | 0xFB
            | 0xFC | 0xFD | 0x9C | 0x9D | 0x60 | 0x61 => 1 + (b1_off - off),
            // Short jump / call rel8
            0xEB | 0xE3 | 0x70..=0x7F => 2 + (b1_off - off),
            // Near jump / call rel32
            0xE8 | 0xE9 => 5 + (b1_off - off),
            // Push/pop reg (50-57, 58-5F)
            0x50..=0x5F => 1 + (b1_off - off),
            // MOV r8, imm8  (B0-B7)
            0xB0..=0xB7 => 2 + (b1_off - off),
            // MOV r32/r64, imm32/imm64  (B8-BF)
            0xB8..=0xBF => {
                // Without REX.W we assume imm32 (5 bytes total with opcode)
                5 + (b1_off - off)
            }
            // INT imm8
            0xCD => 2 + (b1_off - off),
            // RETN imm16
            0xC2 | 0xCA => 3 + (b1_off - off),
            // MOV rm8, imm8 / MOV rm32, imm32
            0xC6 | 0xC7 => 4 + (b1_off - off),
            // Two-byte opcode prefix 0F
            0x0F if b1_off + 1 < data.len() => {
                let b2 = data[b1_off + 1];
                match b2 {
                    // Jcc rel32  (0F 80..8F)
                    0x80..=0x8F => 6 + (b1_off - off),
                    // SETcc, CMOV, etc.  (2-byte ModRM form)
                    0x90..=0x9F | 0x40..=0x4F => 3 + (b1_off - off),
                    // NOP DWORD PTR [rax+disp]
                    0x1F => {
                        if b1_off + 2 < data.len() {
                            let modrm = data[b1_off + 2];
                            3 + modrm_extra(modrm) + (b1_off - off)
                        } else {
                            3 + (b1_off - off)
                        }
                    }
                    _ => 3 + (b1_off - off),
                }
            }
            // ALU rm, r / r, rm — 2-byte form with ModRM
            0x00..=0x3F if main_byte & 0x04 == 0 => {
                if b1_off + 1 < data.len() {
                    let modrm = data[b1_off + 1];
                    2 + modrm_extra(modrm) + (b1_off - off)
                } else {
                    2 + (b1_off - off)
                }
            }
            // Catch-all
            _ => {
                if b1_off + 1 < data.len() {
                    let modrm = data[b1_off + 1];
                    2 + modrm_extra(modrm) + (b1_off - off)
                } else {
                    2 + (b1_off - off)
                }
            }
        }
        .max(1)
    }

    /// Classify `data[off]` as a terminator and resolve its target if possible.
    /// `base` is the virtual address of `data[0]`.
    #[must_use]
    pub fn classify_terminator(
        data: &[u8],
        off: usize,
        base: Addr,
        len: usize,
    ) -> Option<(TermKind, Option<Addr>)> {
        if off >= data.len() {
            return None;
        }
        // Skip REX prefix
        let mut p = off;
        if data[p] >= 0x40 && data[p] <= 0x4F {
            p += 1;
        }
        if p >= data.len() {
            return None;
        }
        let b = data[p];
        let insn_end = base + (off + len) as Addr;
        match b {
            // JMP rel8
            0xEB if p + 1 < data.len() => {
                let rel = data[p + 1] as i8 as i64;
                let target = (insn_end as i64 + rel) as Addr;
                Some((TermKind::Jump, Some(target)))
            }
            // JMP rel32
            0xE9 if p + 4 < data.len() => {
                let rel = i32::from_le_bytes([data[p+1], data[p+2], data[p+3], data[p+4]]) as i64;
                let target = (insn_end as i64 + rel) as Addr;
                Some((TermKind::Jump, Some(target)))
            }
            // CALL rel32
            0xE8 if p + 4 < data.len() => {
                let rel = i32::from_le_bytes([data[p+1], data[p+2], data[p+3], data[p+4]]) as i64;
                let target = (insn_end as i64 + rel) as Addr;
                Some((TermKind::Call, Some(target)))
            }
            // RETN / RET FAR / IRET
            0xC3 | 0xCB | 0xC2 | 0xCA | 0xCF => Some((TermKind::Return, None)),
            // JMP r/m64 (indirect)
            0xFF if p + 1 < data.len() => {
                let modrm_reg = (data[p + 1] >> 3) & 0x07;
                match modrm_reg {
                    4 => Some((TermKind::Jump, None)),   // JMP r/m
                    2 => Some((TermKind::Call, None)),   // CALL r/m
                    _ => None,
                }
            }
            // Jcc rel8 (0x70-0x7F)
            0x70..=0x7F if p + 1 < data.len() => {
                let rel = data[p + 1] as i8 as i64;
                let taken = (insn_end as i64 + rel) as Addr;
                Some((TermKind::Branch, Some(taken)))
            }
            // 0x0F 0x8x — Jcc rel32
            0x0F if p + 1 < data.len() && data[p + 1] >= 0x80 && data[p + 1] <= 0x8F => {
                if p + 5 < data.len() {
                    let rel = i32::from_le_bytes([
                        data[p+2], data[p+3], data[p+4], data[p+5],
                    ]) as i64;
                    let taken = (insn_end as i64 + rel) as Addr;
                    Some((TermKind::Branch, Some(taken)))
                } else {
                    Some((TermKind::Branch, None))
                }
            }
            // SYSCALL / SYSENTER / INT3 / INT imm8 / HLT
            0x0F if p + 1 < data.len() && matches!(data[p+1], 0x05 | 0x34) => {
                Some((TermKind::Trap, None))
            }
            0xCC | 0xCD | 0xCE | 0xF4 => Some((TermKind::Trap, None)),
            _ => None,
        }
    }
}

/// Extra bytes due to a `ModRM` displacement / SIB.
const fn modrm_extra(modrm: u8) -> usize {
    let md = modrm >> 6;
    let rm = modrm & 0x07;
    match md {
        0 if rm == 5 => 4,     // disp32
        0 if rm == 4 => 1,     // SIB, no disp
        1 => 1 + if rm == 4 { 1 } else { 0 }, // disp8 (+ SIB)
        2 => 4 + if rm == 4 { 1 } else { 0 }, // disp32 (+ SIB)
        _ => 0,
    }
}

// ─── CFG builder ─────────────────────────────────────────────────────────────

/// Builds a [`ControlFlowGraph`] from a raw byte slice.
#[derive(Debug, Default, Clone)]
pub struct CfgBuilder {
    /// Virtual base address of `data[0]`.
    pub base: Addr,
}

impl CfgBuilder {
    /// Create a new builder with the given virtual base address.
    #[must_use]
    pub const fn new(base: Addr) -> Self {
        Self { base }
    }

    /// Build a CFG from `data` starting at virtual address `entry`.
    ///
    /// Uses a two-pass algorithm:
    /// 1. Identify leaders by linear scan.
    /// 2. Build basic blocks and edges.
    /// 3. Compute dominators and detect natural loops.
    #[must_use]
    pub fn build(&self, data: &[u8], entry: Addr) -> ControlFlowGraph {
        let leaders = self.find_leaders(data, entry);
        let mut blocks = self.build_blocks(data, &leaders);
        self.add_edges(&mut blocks, data);
        self.fill_predecessors(&mut blocks);
        let idom = self.compute_dominators(&blocks, entry);
        let loops = self.find_natural_loops(&blocks, &idom, entry);
        self.annotate_loop_depth(&mut blocks, &loops);

        ControlFlowGraph {
            blocks,
            entry,
            loops,
            idom,
        }
    }

    /// Pass 1: find all leader addresses.
    ///
    /// Leaders are:
    /// - The entry address.
    /// - Branch/jump targets.
    /// - The fall-through address after a conditional branch.
    fn find_leaders(&self, data: &[u8], entry: Addr) -> BTreeSet<Addr> {
        let mut leaders = BTreeSet::new();
        leaders.insert(entry);

        let _base_usize = self.base as usize;
        let entry_off = entry.saturating_sub(self.base) as usize;

        let mut off = entry_off;
        while off < data.len() {
            let len = InsnScanner::estimate_len(data, off);
            let vaddr = self.base + off as Addr;
            let next_vaddr = vaddr + len as Addr;

            if let Some((term, target)) = InsnScanner::classify_terminator(data, off, self.base, len)
            {
                match term {
                    TermKind::Jump | TermKind::Branch | TermKind::Call => {
                        if let Some(t) = target {
                            // Target is a leader if it falls within data.
                            let t_off = t.saturating_sub(self.base) as usize;
                            if t >= self.base && t_off < data.len() {
                                leaders.insert(t);
                            }
                        }
                        if term == TermKind::Branch || term == TermKind::Call {
                            // Fall-through is also a leader.
                            let ft_off = next_vaddr.saturating_sub(self.base) as usize;
                            if ft_off < data.len() {
                                leaders.insert(next_vaddr);
                            }
                        }
                    }
                    TermKind::Return | TermKind::Trap => {
                        // Next byte is a new leader (dead code or separate function).
                        if (off + len) < data.len() {
                            leaders.insert(next_vaddr);
                        }
                    }
                    TermKind::FallThrough => {}
                }
            }
            off += len.max(1);
        }
        leaders
    }

    /// Pass 2: carve basic blocks from the leader set.
    fn build_blocks(
        &self,
        data: &[u8],
        leaders: &BTreeSet<Addr>,
    ) -> BTreeMap<Addr, BasicBlock> {
        let mut blocks = BTreeMap::new();
        let leader_vec: Vec<Addr> = leaders.iter().copied().collect();

        for (i, &start) in leader_vec.iter().enumerate() {
            let end_limit = leader_vec
                .get(i + 1)
                .copied()
                .unwrap_or(self.base + data.len() as Addr);

            let start_off = start.saturating_sub(self.base) as usize;
            let end_off_limit = end_limit.saturating_sub(self.base) as usize;

            if start_off >= data.len() {
                continue;
            }

            let mut off = start_off;
            let mut term = TermKind::FallThrough;
            let mut succs: Vec<Addr> = Vec::new();

            while off < data.len() && off < end_off_limit {
                let len = InsnScanner::estimate_len(data, off).max(1);
                let vaddr = self.base + off as Addr;
                let next_vaddr = vaddr + len as Addr;

                if let Some((tk, target)) =
                    InsnScanner::classify_terminator(data, off, self.base, len)
                {
                    term = tk;
                    match tk {
                        TermKind::Jump => {
                            if let Some(t) = target {
                                succs.push(t);
                            }
                        }
                        TermKind::Branch => {
                            if let Some(t) = target {
                                succs.push(t); // taken
                            }
                            succs.push(next_vaddr); // not-taken
                        }
                        TermKind::Call => {
                            succs.push(next_vaddr); // return address
                            if let Some(t) = target {
                                succs.push(t);
                            }
                        }
                        TermKind::Return | TermKind::Trap => {}
                        TermKind::FallThrough => {
                            succs.push(next_vaddr);
                        }
                    }
                    off += len;
                    break;
                }
                off += len;
            }

            // If we walked off the end without finding a terminator, fall-through.
            if term == TermKind::FallThrough && off >= end_off_limit {
                succs.push(end_limit);
            }

            let block_end = self.base + off as Addr;
            let mut bb = BasicBlock::new(start, block_end, term);
            bb.succs = succs;
            blocks.insert(start, bb);
        }
        blocks
    }

    /// Ensure edges respect block boundaries — remove successors that don't
    /// correspond to known block starts.
    fn add_edges(&self, blocks: &mut BTreeMap<Addr, BasicBlock>, _data: &[u8]) {
        let known: HashSet<Addr> = blocks.keys().copied().collect();
        for bb in blocks.values_mut() {
            bb.succs.retain(|s| known.contains(s));
        }
    }

    /// Fill in predecessor lists from successor lists.
    fn fill_predecessors(&self, blocks: &mut BTreeMap<Addr, BasicBlock>) {
        let edges: Vec<(Addr, Addr)> = blocks
            .values()
            .flat_map(|b| b.succs.iter().map(move |&s| (b.start, s)))
            .collect();
        for (from, to) in edges {
            if let Some(target_block) = blocks.get_mut(&to) {
                if !target_block.preds.contains(&from) {
                    target_block.preds.push(from);
                }
            }
        }
    }

    // ── Dominator computation ─────────────────────────────────────────────────
    //
    // Classic iterative Cooper–Harvey–Kennedy algorithm on the reverse-post-order.

    fn compute_dominators(
        &self,
        blocks: &BTreeMap<Addr, BasicBlock>,
        entry: Addr,
    ) -> HashMap<Addr, Addr> {
        // Build RPO numbering.
        let rpo = self.rpo(blocks, entry);
        let rpo_idx: HashMap<Addr, usize> =
            rpo.iter().enumerate().map(|(i, &a)| (a, i)).collect();

        let n = rpo.len();
        // idom[i] = RPO index of immediate dominator of rpo[i].
        let mut idom: Vec<Option<usize>> = vec![None; n];
        if n == 0 {
            return HashMap::new();
        }
        idom[0] = Some(0); // entry dominates itself

        let mut changed = true;
        while changed {
            changed = false;
            for b in 1..n {
                let addr = rpo[b];
                let block = match blocks.get(&addr) {
                    Some(bb) => bb,
                    None => continue,
                };
                let mut new_idom: Option<usize> = None;
                for &pred_addr in &block.preds {
                    let pred_idx = match rpo_idx.get(&pred_addr) {
                        Some(&i) => i,
                        None => continue,
                    };
                    if idom[pred_idx].is_some() {
                        new_idom = Some(match new_idom {
                            None => pred_idx,
                            Some(d) => Self::intersect(&idom, d, pred_idx),
                        });
                    }
                }
                if new_idom != idom[b] {
                    idom[b] = new_idom;
                    changed = true;
                }
            }
        }

        let mut result = HashMap::new();
        for (i, addr) in rpo.iter().enumerate() {
            if let Some(dom_idx) = idom[i] {
                result.insert(*addr, rpo[dom_idx]);
            }
        }
        result
    }

    fn intersect(idom: &[Option<usize>], mut b1: usize, mut b2: usize) -> usize {
        // Walk up the dominator tree from b1 and b2 until they meet.
        // Bound the iteration to prevent an infinite loop if idom is cyclic
        // (can happen on malformed input).
        let max_steps = idom.len() + 2;
        let mut steps = 0usize;
        while b1 != b2 {
            if steps > max_steps {
                // Degenerate input: give up and return the root (index 0).
                return 0;
            }
            while b1 > b2 {
                b1 = idom[b1].unwrap_or(b1);
                steps += 1;
                if steps > max_steps { return 0; }
            }
            while b2 > b1 {
                b2 = idom[b2].unwrap_or(b2);
                steps += 1;
                if steps > max_steps { return 0; }
            }
        }
        b1
    }

    fn rpo(&self, blocks: &BTreeMap<Addr, BasicBlock>, entry: Addr) -> Vec<Addr> {
        let mut visited = HashSet::new();
        let mut post = Vec::new();
        Self::dfs_post_static(blocks, entry, &mut visited, &mut post);
        post.reverse();
        post
    }

    fn dfs_post_static(
        blocks: &BTreeMap<Addr, BasicBlock>,
        entry: Addr,
        visited: &mut HashSet<Addr>,
        post: &mut Vec<Addr>,
    ) {
        // Iterative post-order DFS to prevent stack overflow on adversarial input.
        enum Frame { Enter(Addr), Leave(Addr) }
        let mut stack: Vec<Frame> = vec![Frame::Enter(entry)];
        while let Some(frame) = stack.pop() {
            match frame {
                Frame::Enter(addr) => {
                    if !visited.insert(addr) {
                        continue;
                    }
                    stack.push(Frame::Leave(addr));
                    if let Some(block) = blocks.get(&addr) {
                        for &succ in block.succs.iter().rev() {
                            stack.push(Frame::Enter(succ));
                        }
                    }
                }
                Frame::Leave(addr) => {
                    post.push(addr);
                }
            }
        }
    }

    // ── Natural loop detection ────────────────────────────────────────────────

    /// Detect natural loops using Lengauer–Tarjan back-edges.
    fn find_natural_loops(
        &self,
        blocks: &BTreeMap<Addr, BasicBlock>,
        idom: &HashMap<Addr, Addr>,
        _entry: Addr,
    ) -> Vec<NaturalLoop> {
        let mut loops = Vec::new();
        // Find back-edges: (tail, header) where header dominates tail.
        let back_edges: Vec<(Addr, Addr)> = blocks
            .values()
            .flat_map(|b| {
                b.succs.iter().filter_map(move |&succ| {
                    if Self::dominates_static(idom, succ, b.start) {
                        Some((b.start, succ))
                    } else {
                        None
                    }
                })
            })
            .collect();

        for (tail, header) in back_edges {
            let body = self.natural_loop_body(blocks, tail, header);
            loops.push(NaturalLoop {
                header,
                body,
                back_edge_from: tail,
                depth: 1,
            });
        }

        // Assign nesting depths by inclusion.
        let loop_count = loops.len();
        for i in 0..loop_count {
            let mut depth = 1u32;
            let body_i = loops[i].body.clone();
            for j in 0..loop_count {
                if i != j && loops[j].body.is_superset(&body_i) {
                    depth += 1;
                }
            }
            loops[i].depth = depth;
        }

        loops
    }

    fn dominates_static(idom: &HashMap<Addr, Addr>, a: Addr, b: Addr) -> bool {
        if a == b {
            return true;
        }
        let mut cur = b;
        let mut steps = 0;
        loop {
            match idom.get(&cur) {
                Some(&d) if d == a => return true,
                Some(&d) if d == cur => return false,
                Some(&d) => cur = d,
                None => return false,
            }
            steps += 1;
            if steps > 1000 {
                return false;
            }
        }
    }

    /// Collect all blocks in the natural loop defined by back-edge `tail → header`.
    fn natural_loop_body(
        &self,
        blocks: &BTreeMap<Addr, BasicBlock>,
        tail: Addr,
        header: Addr,
    ) -> BTreeSet<Addr> {
        let mut body = BTreeSet::new();
        body.insert(header);
        body.insert(tail);

        let mut worklist: VecDeque<Addr> = VecDeque::new();
        if tail != header {
            worklist.push_back(tail);
        }

        while let Some(node) = worklist.pop_front() {
            if let Some(block) = blocks.get(&node) {
                for &pred in &block.preds {
                    if body.insert(pred) {
                        worklist.push_back(pred);
                    }
                }
            }
        }
        body
    }

    /// Annotate blocks with their loop depth from the computed loops.
    fn annotate_loop_depth(
        &self,
        blocks: &mut BTreeMap<Addr, BasicBlock>,
        loops: &[NaturalLoop],
    ) {
        for lp in loops {
            for &addr in &lp.body {
                if let Some(block) = blocks.get_mut(&addr) {
                    if lp.depth > block.loop_depth {
                        block.loop_depth = lp.depth;
                    }
                    if addr == lp.header {
                        block.is_loop_header = true;
                    }
                }
            }
        }
    }
}

// ─── CfgStats ─────────────────────────────────────────────────────────────────

/// Aggregate statistics for a CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgStats {
    pub block_count: usize,
    pub edge_count: usize,
    pub loop_count: usize,
    pub max_loop_depth: u32,
    pub back_edge_count: usize,
    /// `McCabe` cyclomatic complexity M = E - N + 2.
    pub cyclomatic_complexity: i64,
}

impl CfgStats {
    /// Compute statistics for a CFG.
    #[must_use]
    pub fn compute(cfg: &ControlFlowGraph) -> Self {
        let n = cfg.block_count() as i64;
        let e = cfg.edge_count() as i64;
        let max_loop_depth = cfg
            .blocks
            .values()
            .map(|b| b.loop_depth)
            .max()
            .unwrap_or(0);
        let back_edge_count = cfg.back_edges().len();
        Self {
            block_count: n as usize,
            edge_count: e as usize,
            loop_count: cfg.loops.len(),
            max_loop_depth,
            back_edge_count,
            cyclomatic_complexity: e - n + 2,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_len_nop() {
        assert_eq!(InsnScanner::estimate_len(&[0x90], 0), 1);
    }

    #[test]
    fn test_estimate_len_jmp_rel8() {
        // EB 05 (JMP +5)
        assert!(InsnScanner::estimate_len(&[0xEB, 0x05], 0) >= 2);
    }

    #[test]
    fn test_classify_jmp_rel8() {
        let data = [0xEB, 0x03, 0x90, 0x90, 0x90, 0x90];
        let (term, target) = InsnScanner::classify_terminator(&data, 0, 0x1000, 2).unwrap();
        assert_eq!(term, TermKind::Jump);
        assert_eq!(target, Some(0x1005)); // 0x1002 + 3
    }

    #[test]
    fn test_classify_ret() {
        let data = [0xC3];
        let (term, _) = InsnScanner::classify_terminator(&data, 0, 0x1000, 1).unwrap();
        assert_eq!(term, TermKind::Return);
    }

    #[test]
    fn test_build_trivial_cfg() {
        // NOP; RET
        let data = [0x90u8, 0xC3];
        let builder = CfgBuilder::new(0x1000);
        let cfg = builder.build(&data, 0x1000);
        assert!(!cfg.blocks.is_empty());
    }

    #[test]
    fn test_modrm_extra_disp32() {
        assert_eq!(modrm_extra(0b00_000_101), 4); // mod=0, rm=5 => disp32
    }

    #[test]
    fn test_cfg_stats() {
        let data = [0x90u8, 0xC3];
        let cfg = CfgBuilder::new(0x400000).build(&data, 0x400000);
        let stats = CfgStats::compute(&cfg);
        assert!(stats.block_count > 0);
        assert!(stats.cyclomatic_complexity >= 1);
    }
}
