// cil_branch_analyzer.rs — CIL control-flow graph, loop detection, exception regions

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cil_decoder::{DecodedCilInstr, Opcode};

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CfgError {
    #[error("decode error at offset {0:#x}: {1}")]
    Decode(u32, String),
    #[error("branch target {0:#x} is outside method body")]
    OutOfBounds(u32),
    #[error("overlapping exception handler regions")]
    OverlappingHandlers,
}

// ─── Exception-handling region types ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HandlerKind {
    Catch,
    Filter,
    Finally,
    Fault,
}

/// One clause in the method's exception-handling table (ECMA-335 §II.19).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionRegion {
    pub kind: HandlerKind,
    /// Offset of first instruction in the `try` block.
    pub try_start: u32,
    /// Offset just past the last instruction in the `try` block.
    pub try_end: u32,
    /// Offset of first instruction in the handler.
    pub handler_start: u32,
    /// Offset just past the last instruction in the handler.
    pub handler_end: u32,
    /// For `Catch` — the TypeDef/TypeRef/TypeSpec token of the exception type.
    pub catch_token: Option<u32>,
    /// For `Filter` — offset of the filter clause.
    pub filter_offset: Option<u32>,
}

impl ExceptionRegion {
    #[must_use]
    pub const fn contains_try(&self, offset: u32) -> bool {
        offset >= self.try_start && offset < self.try_end
    }
    #[must_use]
    pub const fn contains_handler(&self, offset: u32) -> bool {
        offset >= self.handler_start && offset < self.handler_end
    }
    #[must_use]
    pub const fn overlaps_try(&self, other: &ExceptionRegion) -> bool {
        self.try_start < other.try_end && other.try_start < self.try_end
    }
}

// ─── Basic-block types ───────────────────────────────────────────────────────

/// Kind of edge leaving a basic block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    /// Unconditional fall-through or branch.
    Unconditional,
    /// Taken branch (conditional-true).
    True,
    /// Not-taken branch (conditional-false).
    False,
    /// Switch case (carries case index).
    Switch(u32),
    /// Leave from a protected region to a handler or continuation.
    Leave,
    /// Exception-handler entry edge.
    ExceptionEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    /// Index of the target block in `CilCfg::blocks`.
    pub target_block: usize,
    pub kind: EdgeKind,
}

/// A single basic block: a maximal straight-line sequence of instructions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CilBlock {
    /// Index of this block in `CilCfg::blocks`.
    pub id: usize,
    /// Byte offset of the first instruction.
    pub start_offset: u32,
    /// Byte offset just past the last instruction.
    pub end_offset: u32,
    /// Instructions in this block, in order.
    pub instrs: Vec<DecodedCilInstr>,
    /// Successor edges.
    pub succs: Vec<CfgEdge>,
    /// Predecessor block indices.
    pub preds: Vec<usize>,
    /// True if this block is the method entry.
    pub is_entry: bool,
    /// True if this block ends with `ret`, `throw`, or `rethrow`.
    pub is_exit: bool,
    /// True if this block is the entry of a loop.
    pub is_loop_header: bool,
    /// Innermost exception region this block belongs to (index into `CilCfg::regions`).
    pub exception_region: Option<usize>,
}

impl CilBlock {
    #[must_use]
    pub const fn contains(&self, offset: u32) -> bool {
        offset >= self.start_offset && offset < self.end_offset
    }
    #[must_use]
    pub fn last_instr(&self) -> Option<&DecodedCilInstr> {
        self.instrs.last()
    }
}

// ─── CFG ─────────────────────────────────────────────────────────────────────

/// Full control-flow graph for one CIL method body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CilCfg {
    pub blocks: Vec<CilBlock>,
    pub regions: Vec<ExceptionRegion>,
    /// Mapping from byte offset → block index.
    #[serde(skip)]
    pub offset_to_block: HashMap<u32, usize>,
    /// Dominance frontiers (block index → set of block indices).
    #[serde(skip)]
    pub dom_frontiers: Vec<HashSet<usize>>,
    /// Immediate dominator of each block (block 0 dominates itself).
    #[serde(skip)]
    pub idoms: Vec<Option<usize>>,
    /// Loop back-edges: (`header_block`, `latch_block`) pairs.
    pub back_edges: Vec<(usize, usize)>,
    /// Natural loop bodies: for each back-edge, set of block indices in the loop.
    pub loop_bodies: Vec<HashSet<usize>>,
}

impl CilCfg {
    #[must_use]
    pub fn entry_block(&self) -> Option<&CilBlock> {
        self.blocks.first()
    }

    #[must_use]
    pub fn block_at(&self, offset: u32) -> Option<&CilBlock> {
        self.offset_to_block
            .get(&offset)
            .and_then(|&i| self.blocks.get(i))
    }

    #[must_use]
    pub const fn block_count(&self) -> usize {
        self.blocks.len()
    }

    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.blocks.iter().map(|b| b.succs.len()).sum()
    }

    /// Blocks that are loop headers (have at least one back-edge targeting them).
    #[must_use]
    pub fn loop_headers(&self) -> Vec<usize> {
        self.back_edges.iter().map(|(h, _)| *h).collect()
    }

    /// Returns all blocks dominated by `dominator` (including itself).
    #[must_use]
    pub fn dominated_by(&self, dominator: usize) -> Vec<usize> {
        (0..self.blocks.len())
            .filter(|&b| self.dominates(dominator, b))
            .collect()
    }

    /// True if `a` dominates `b` in the CFG.
    #[must_use]
    pub fn dominates(&self, a: usize, b: usize) -> bool {
        let mut cur = b;
        loop {
            if cur == a {
                return true;
            }
            match self.idoms[cur] {
                Some(p) if p != cur => cur = p,
                _ => return false,
            }
        }
    }

    /// Number of distinct loops detected.
    #[must_use]
    pub const fn loop_count(&self) -> usize {
        self.loop_bodies.len()
    }

    /// Topological ordering of blocks (post-order reversed).
    #[must_use]
    pub fn rpo(&self) -> Vec<usize> {
        let mut visited = vec![false; self.blocks.len()];
        let mut order = Vec::with_capacity(self.blocks.len());
        self.dfs_post(0, &mut visited, &mut order);
        order.reverse();
        order
    }

    fn dfs_post(&self, start: usize, visited: &mut Vec<bool>, out: &mut Vec<usize>) {
        // Iterative post-order DFS to avoid stack overflow on deep attacker-controlled CFGs.
        let mut stack: Vec<(usize, usize)> = Vec::new();
        if !visited[start] {
            visited[start] = true;
            stack.push((start, 0));
        }
        while let Some((b, ei)) = stack.last_mut() {
            let b = *b;
            let succs = &self.blocks[b].succs;
            let ei_val = *ei;
            if ei_val < succs.len() {
                *stack.last_mut().unwrap() = (b, ei_val + 1);
                let tgt = succs[ei_val].target_block;
                if !visited[tgt] {
                    visited[tgt] = true;
                    stack.push((tgt, 0));
                }
            } else {
                out.push(b);
                stack.pop();
            }
        }
    }
}

// ─── CFG builder ─────────────────────────────────────────────────────────────

/// Builds a `CilCfg` from decoded CIL instructions and exception regions.
pub struct CfgBuilder {
    instrs: Vec<DecodedCilInstr>,
    regions: Vec<ExceptionRegion>,
}

impl CfgBuilder {
    #[must_use]
    pub const fn new(instrs: Vec<DecodedCilInstr>, regions: Vec<ExceptionRegion>) -> Self {
        Self { instrs, regions }
    }

    pub fn build(self) -> Result<CilCfg, CfgError> {
        if self.instrs.is_empty() {
            return Ok(CilCfg {
                blocks: vec![],
                regions: self.regions,
                offset_to_block: HashMap::new(),
                dom_frontiers: vec![],
                idoms: vec![],
                back_edges: vec![],
                loop_bodies: vec![],
            });
        }

        // Step 1: find all leader offsets (start of a basic block).
        let mut leaders: HashSet<u32> = HashSet::new();
        leaders.insert(self.instrs[0].offset);

        // Handler entry points are also leaders.
        for r in &self.regions {
            leaders.insert(r.handler_start);
            if let Some(fo) = r.filter_offset {
                leaders.insert(fo);
            }
        }

        let max_offset = self.instrs.last().map(|i| i.offset + i.size).unwrap_or(0);

        for instr in &self.instrs {
            match instr.opcode {
                Opcode::Br | Opcode::BrS => {
                    if let Some(tgt) = instr.branch_target() {
                        if tgt >= max_offset {
                            return Err(CfgError::OutOfBounds(tgt));
                        }
                        leaders.insert(tgt);
                        leaders.insert(instr.offset + instr.size);
                    }
                }
                Opcode::Brtrue
                | Opcode::BrtrueS
                | Opcode::Brfalse
                | Opcode::BrfalseS
                | Opcode::Beq
                | Opcode::BeqS
                | Opcode::Bge
                | Opcode::BgeS
                | Opcode::BgeUn
                | Opcode::BgeUnS
                | Opcode::Bgt
                | Opcode::BgtS
                | Opcode::BgtUn
                | Opcode::BgtUnS
                | Opcode::Ble
                | Opcode::BleS
                | Opcode::BleUn
                | Opcode::BleUnS
                | Opcode::Blt
                | Opcode::BltS
                | Opcode::BltUn
                | Opcode::BltUnS
                | Opcode::Bne
                | Opcode::BneUnS => {
                    if let Some(tgt) = instr.branch_target() {
                        if tgt >= max_offset {
                            return Err(CfgError::OutOfBounds(tgt));
                        }
                        leaders.insert(tgt);
                    }
                    leaders.insert(instr.offset + instr.size);
                }
                Opcode::Switch => {
                    for tgt in instr.switch_targets() {
                        if tgt >= max_offset {
                            return Err(CfgError::OutOfBounds(tgt));
                        }
                        leaders.insert(tgt);
                    }
                    leaders.insert(instr.offset + instr.size);
                }
                Opcode::Leave | Opcode::LeaveS => {
                    if let Some(tgt) = instr.branch_target() {
                        leaders.insert(tgt);
                    }
                    leaders.insert(instr.offset + instr.size);
                }
                Opcode::Ret | Opcode::Throw | Opcode::Rethrow | Opcode::Endfinally => {
                    leaders.insert(instr.offset + instr.size);
                }
                _ => {}
            }
        }

        // Step 2: partition instructions into basic blocks.
        let mut sorted_leaders: Vec<u32> = leaders.into_iter().collect();
        sorted_leaders.sort_unstable();

        // Map each instr offset to its position.
        let offset_to_idx: BTreeMap<u32, usize> = self
            .instrs
            .iter()
            .enumerate()
            .map(|(i, instr)| (instr.offset, i))
            .collect();

        let mut raw_blocks: Vec<(u32, Vec<DecodedCilInstr>)> = Vec::new();
        for (li, &leader) in sorted_leaders.iter().enumerate() {
            let next_leader = sorted_leaders.get(li + 1).copied().unwrap_or(max_offset);
            let start_idx = match offset_to_idx.get(&leader) {
                Some(&i) => i,
                None => continue,
            };
            let slice: Vec<DecodedCilInstr> = self.instrs[start_idx..]
                .iter()
                .take_while(|i| i.offset < next_leader)
                .cloned()
                .collect();
            if !slice.is_empty() {
                raw_blocks.push((leader, slice));
            }
        }

        // Step 3: build CilBlock structs.
        let n = raw_blocks.len();
        let mut blocks: Vec<CilBlock> = raw_blocks
            .iter()
            .enumerate()
            .map(|(id, &(start, ref instrs)): (usize, &(u32, Vec<DecodedCilInstr>))| {
                let end = instrs.last().map(|i| i.offset + i.size).unwrap_or(start);
                let is_exit = instrs.last().map(|i| matches!(
                    i.opcode,
                    Opcode::Ret | Opcode::Throw | Opcode::Rethrow | Opcode::Endfinally
                )).unwrap_or(false);
                CilBlock {
                    id,
                    start_offset: start,
                    end_offset: end,
                    instrs: instrs.clone(),
                    succs: vec![],
                    preds: vec![],
                    is_entry: id == 0,
                    is_exit,
                    is_loop_header: false,
                    exception_region: None,
                }
            })
            .collect();

        // Build offset→block map.
        let mut offset_to_block: HashMap<u32, usize> = HashMap::new();
        for (i, block) in blocks.iter().enumerate() {
            offset_to_block.insert(block.start_offset, i);
        }

        // Helper: find block index by offset.
        let find_block = |off: u32| -> Option<usize> { offset_to_block.get(&off).copied() };

        // Step 4: wire edges.
        for i in 0..n {
            let last = match blocks[i].last_instr().cloned() {
                Some(l) => l,
                None => continue,
            };
            let fall_through = blocks[i].end_offset;
            let mut succs: Vec<CfgEdge> = vec![];

            match last.opcode {
                Opcode::Ret | Opcode::Throw | Opcode::Rethrow | Opcode::Endfinally => {
                    // no successors
                }
                Opcode::Br | Opcode::BrS => {
                    if let Some(tgt) = last.branch_target() {
                        if let Some(b) = find_block(tgt) {
                            succs.push(CfgEdge { target_block: b, kind: EdgeKind::Unconditional });
                        }
                    }
                }
                Opcode::Leave | Opcode::LeaveS => {
                    if let Some(tgt) = last.branch_target() {
                        if let Some(b) = find_block(tgt) {
                            succs.push(CfgEdge { target_block: b, kind: EdgeKind::Leave });
                        }
                    }
                }
                Opcode::Switch => {
                    for (case, tgt) in last.switch_targets().into_iter().enumerate() {
                        if let Some(b) = find_block(tgt) {
                            succs.push(CfgEdge {
                                target_block: b,
                                kind: EdgeKind::Switch(case as u32),
                            });
                        }
                    }
                    // default (fall-through)
                    if let Some(b) = find_block(fall_through) {
                        succs.push(CfgEdge { target_block: b, kind: EdgeKind::False });
                    }
                }
                _ => {
                    // Conditional branches
                    if let Some(tgt) = last.branch_target() {
                        if let Some(b) = find_block(tgt) {
                            succs.push(CfgEdge { target_block: b, kind: EdgeKind::True });
                        }
                        if let Some(b) = find_block(fall_through) {
                            succs.push(CfgEdge { target_block: b, kind: EdgeKind::False });
                        }
                    } else if let Some(b) = find_block(fall_through) {
                        succs.push(CfgEdge { target_block: b, kind: EdgeKind::Unconditional });
                    }
                }
            }

            blocks[i].succs = succs;
        }

        // Step 5: fill predecessor lists.
        let succs_copy: Vec<Vec<CfgEdge>> = blocks.iter().map(|b| b.succs.clone()).collect();
        for (src, edges) in succs_copy.iter().enumerate() {
            for e in edges {
                blocks[e.target_block].preds.push(src);
            }
        }

        // Step 6: assign exception regions.
        for (ri, region) in self.regions.iter().enumerate() {
            for block in blocks.iter_mut() {
                if region.contains_handler(block.start_offset)
                    || region.contains_try(block.start_offset)
                {
                    block.exception_region = Some(ri);
                }
            }
        }

        // Step 7: compute dominators (Lengauer-Tarjan simplified).
        let idoms = compute_idoms(&blocks, n);

        // Step 8: dominance frontiers.
        let dom_frontiers = compute_dom_frontiers(&blocks, &idoms, n);

        // Step 9: find back-edges (DFS).
        let (back_edges, loop_bodies) = find_loops(&blocks, n);

        // Mark loop headers.
        for (header, _) in &back_edges {
            blocks[*header].is_loop_header = true;
        }

        Ok(CilCfg {
            blocks,
            regions: self.regions,
            offset_to_block,
            dom_frontiers,
            idoms,
            back_edges,
            loop_bodies,
        })
    }
}

// ─── Dominator computation ────────────────────────────────────────────────────

fn compute_idoms(blocks: &[CilBlock], n: usize) -> Vec<Option<usize>> {
    // Simple iterative dominator algorithm (Cooper et al. 2001).
    // RPO numbering.
    let mut visited = vec![false; n];
    let mut rpo: Vec<usize> = Vec::with_capacity(n);
    dfs_post_order(blocks, 0, &mut visited, &mut rpo);
    rpo.reverse();
    let rpo_num: Vec<usize> = {
        let mut v = vec![0usize; n];
        for (pos, &b) in rpo.iter().enumerate() {
            v[b] = pos;
        }
        v
    };

    let mut idoms: Vec<Option<usize>> = vec![None; n];
    idoms[0] = Some(0);
    let mut changed = true;
    while changed {
        changed = false;
        for &b in rpo.iter() {
            if b == 0 {
                continue;
            }
            let processed_preds: Vec<usize> = blocks[b]
                .preds
                .iter()
                .copied()
                .filter(|&p| idoms[p].is_some())
                .collect();
            if processed_preds.is_empty() {
                continue;
            }
            let mut new_idom = processed_preds[0];
            for &p in &processed_preds[1..] {
                new_idom = intersect(p, new_idom, &idoms, &rpo_num);
            }
            if idoms[b] != Some(new_idom) {
                idoms[b] = Some(new_idom);
                changed = true;
            }
        }
    }
    idoms
}

fn intersect(a: usize, b: usize, idoms: &[Option<usize>], rpo_num: &[usize]) -> usize {
    let mut x = a;
    let mut y = b;
    // Bound iterations to prevent infinite loop on malformed/unreachable idoms.
    let max_iters = idoms.len() * 2 + 2;
    let mut iters = 0usize;
    while x != y && iters < max_iters {
        iters += 1;
        while rpo_num[x] > rpo_num[y] {
            match idoms[x] {
                Some(p) if p != x => x = p,
                _ => break,
            }
        }
        while rpo_num[y] > rpo_num[x] {
            match idoms[y] {
                Some(p) if p != y => y = p,
                _ => break,
            }
        }
    }
    x
}

fn dfs_post_order(blocks: &[CilBlock], start: usize, visited: &mut Vec<bool>, out: &mut Vec<usize>) {
    // Iterative post-order DFS — avoids stack overflow on adversarially deep CFGs
    // where recursive DFS would exhaust the native call stack.
    // Each entry is (block_index, next_successor_edge_index).
    let mut stack: Vec<(usize, usize)> = Vec::new();
    if !visited[start] {
        visited[start] = true;
        stack.push((start, 0));
    }
    while let Some((b, ei)) = stack.last_mut() {
        let b = *b;
        let succs = &blocks[b].succs;
        let ei_val = *ei;
        if ei_val < succs.len() {
            *stack.last_mut().unwrap() = (b, ei_val + 1);
            let tgt = succs[ei_val].target_block;
            if !visited[tgt] {
                visited[tgt] = true;
                stack.push((tgt, 0));
            }
        } else {
            out.push(b);
            stack.pop();
        }
    }
}

fn compute_dom_frontiers(
    blocks: &[CilBlock],
    idoms: &[Option<usize>],
    n: usize,
) -> Vec<HashSet<usize>> {
    let mut df: Vec<HashSet<usize>> = vec![HashSet::new(); n];
    for b in 0..n {
        if blocks[b].preds.len() >= 2 {
            for &p in &blocks[b].preds {
                let mut runner = p;
                while Some(runner) != idoms[b] {
                    df[runner].insert(b);
                    runner = idoms[runner].unwrap_or(runner);
                    if runner == 0 && idoms[b] != Some(0) {
                        break;
                    }
                }
            }
        }
    }
    df
}

// ─── Loop detection ───────────────────────────────────────────────────────────

fn find_loops(blocks: &[CilBlock], n: usize) -> (Vec<(usize, usize)>, Vec<HashSet<usize>>) {
    // DFS coloring: white=0, gray=1 (on stack), black=2 (done).
    let mut color = vec![0u8; n];
    let mut back_edges: Vec<(usize, usize)> = Vec::new();
    let mut stack: Vec<(usize, usize)> = vec![(0, 0)]; // (block, edge_index)

    while let Some((b, ei)) = stack.last_mut() {
        let b = *b;
        if color[b] == 0 {
            color[b] = 1;
        }
        let succs = &blocks[b].succs;
        let ei_val = *ei;
        if ei_val < succs.len() {
            *stack.last_mut().unwrap() = (b, ei_val + 1);
            let tgt = succs[ei_val].target_block;
            if color[tgt] == 1 {
                back_edges.push((tgt, b)); // tgt is the header, b is the latch
            } else if color[tgt] == 0 {
                stack.push((tgt, 0));
            }
        } else {
            color[b] = 2;
            stack.pop();
        }
    }

    let mut loop_bodies: Vec<HashSet<usize>> = Vec::with_capacity(back_edges.len());
    for &(header, latch) in &back_edges {
        let body = natural_loop_body(blocks, header, latch);
        loop_bodies.push(body);
    }

    (back_edges, loop_bodies)
}

fn natural_loop_body(blocks: &[CilBlock], header: usize, latch: usize) -> HashSet<usize> {
    let mut body: HashSet<usize> = HashSet::new();
    body.insert(header);
    if latch == header {
        return body;
    }
    body.insert(latch);
    let mut queue: VecDeque<usize> = VecDeque::new();
    queue.push_back(latch);
    while let Some(b) = queue.pop_front() {
        for &p in &blocks[b].preds {
            if !body.contains(&p) {
                body.insert(p);
                queue.push_back(p);
            }
        }
    }
    body
}

// ─── CFG analysis helpers ─────────────────────────────────────────────────────

/// Computes live sets for each block (simplified backward liveness over block graph).
pub struct LivenessInfo {
    /// For each block index: set of variable indices live at entry.
    pub live_in: Vec<HashSet<u32>>,
    /// For each block index: set of variable indices live at exit.
    pub live_out: Vec<HashSet<u32>>,
}

impl LivenessInfo {
    #[must_use]
    pub fn compute(cfg: &CilCfg, num_locals: u32) -> Self {
        let n = cfg.blocks.len();
        let mut live_in: Vec<HashSet<u32>> = vec![HashSet::new(); n];
        let mut live_out: Vec<HashSet<u32>> = vec![HashSet::new(); n];

        // Build use/def per block from instructions.
        let mut use_sets: Vec<HashSet<u32>> = vec![HashSet::new(); n];
        let mut def_sets: Vec<HashSet<u32>> = vec![HashSet::new(); n];

        for (bi, block) in cfg.blocks.iter().enumerate() {
            for instr in &block.instrs {
                if let Some(local) = instr.local_load_index() {
                    if !def_sets[bi].contains(&local) {
                        use_sets[bi].insert(local);
                    }
                }
                if let Some(local) = instr.local_store_index() {
                    def_sets[bi].insert(local);
                }
            }
            // Clamp to actual locals.
            use_sets[bi].retain(|&l| l < num_locals);
            def_sets[bi].retain(|&l| l < num_locals);
        }

        let mut changed = true;
        while changed {
            changed = false;
            for bi in (0..n).rev() {
                // live_out[bi] = union of live_in[succ] for all successors.
                let new_out: HashSet<u32> = cfg.blocks[bi]
                    .succs
                    .iter()
                    .flat_map(|e| live_in[e.target_block].iter().copied())
                    .collect();
                // live_in[bi] = use[bi] ∪ (live_out[bi] - def[bi])
                let new_in: HashSet<u32> = use_sets[bi]
                    .iter()
                    .copied()
                    .chain(
                        new_out
                            .iter()
                            .copied()
                            .filter(|v| !def_sets[bi].contains(v)),
                    )
                    .collect();
                if new_out != live_out[bi] || new_in != live_in[bi] {
                    live_out[bi] = new_out;
                    live_in[bi] = new_in;
                    changed = true;
                }
            }
        }

        LivenessInfo { live_in, live_out }
    }
}

/// Summary statistics for a CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgStats {
    pub block_count: usize,
    pub edge_count: usize,
    pub loop_count: usize,
    pub loop_header_offsets: Vec<u32>,
    pub exception_region_count: usize,
    pub max_loop_depth: usize,
    pub cyclomatic_complexity: i64,
}

impl CfgStats {
    #[must_use]
    pub fn from(cfg: &CilCfg) -> Self {
        let cyclomatic_complexity = cfg.edge_count() as i64 - cfg.block_count() as i64 + 2;
        let loop_header_offsets = cfg
            .loop_headers()
            .iter()
            .map(|&bi| cfg.blocks[bi].start_offset)
            .collect();
        let max_loop_depth = compute_max_loop_depth(cfg);
        Self {
            block_count: cfg.block_count(),
            edge_count: cfg.edge_count(),
            loop_count: cfg.loop_count(),
            loop_header_offsets,
            exception_region_count: cfg.regions.len(),
            max_loop_depth,
            cyclomatic_complexity,
        }
    }
}

fn compute_max_loop_depth(cfg: &CilCfg) -> usize {
    if cfg.loop_bodies.is_empty() {
        return 0;
    }
    let n = cfg.blocks.len();
    let mut depth = vec![0usize; n];
    for body in &cfg.loop_bodies {
        for &b in body {
            depth[b] += 1;
        }
    }
    *depth.iter().max().unwrap_or(&0)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cil_decoder::{DecodedCilInstr, Opcode};

    fn instr(offset: u32, size: u32, opcode: Opcode) -> DecodedCilInstr {
        DecodedCilInstr { offset, size, opcode, operand: crate::cil_decoder::Operand::None }
    }

    fn br_instr(offset: u32, size: u32, target: u32) -> DecodedCilInstr {
        DecodedCilInstr {
            offset,
            size,
            opcode: Opcode::Br,
            operand: crate::cil_decoder::Operand::BranchTarget(target),
        }
    }

    fn cond_instr(offset: u32, size: u32, target: u32) -> DecodedCilInstr {
        DecodedCilInstr {
            offset,
            size,
            opcode: Opcode::Brtrue,
            operand: crate::cil_decoder::Operand::BranchTarget(target),
        }
    }

    fn ret_instr(offset: u32) -> DecodedCilInstr {
        DecodedCilInstr { offset, size: 1, opcode: Opcode::Ret, operand: crate::cil_decoder::Operand::None }
    }

    #[test]
    fn test_linear_method_single_block() {
        // nop; nop; ret  — should produce one block.
        let instrs = vec![
            instr(0, 1, Opcode::Nop),
            instr(1, 1, Opcode::Nop),
            ret_instr(2),
        ];
        let cfg = CfgBuilder::new(instrs, vec![]).build().unwrap();
        assert_eq!(cfg.block_count(), 1);
        assert_eq!(cfg.edge_count(), 0);
        assert!(cfg.blocks[0].is_entry);
        assert!(cfg.blocks[0].is_exit);
    }

    #[test]
    fn test_unconditional_branch_two_blocks() {
        // 0: br 2; 2: ret
        let instrs = vec![br_instr(0, 2, 2), ret_instr(2)];
        let cfg = CfgBuilder::new(instrs, vec![]).build().unwrap();
        assert_eq!(cfg.block_count(), 2);
        assert_eq!(cfg.edge_count(), 1);
        assert_eq!(cfg.blocks[0].succs[0].kind, EdgeKind::Unconditional);
    }

    #[test]
    fn test_conditional_branch_three_blocks() {
        // 0: brtrue 4; 2: ret; 4: ret
        let instrs = vec![cond_instr(0, 2, 4), ret_instr(2), ret_instr(4)];
        let cfg = CfgBuilder::new(instrs, vec![]).build().unwrap();
        assert_eq!(cfg.block_count(), 3);
        // Block 0 has two successors: true=block@4, false=block@2
        assert_eq!(cfg.blocks[0].succs.len(), 2);
    }

    #[test]
    fn test_loop_back_edge_detected() {
        // 0: nop (1 byte); 1: brtrue 0 (2 bytes — back edge to 0); 3: ret
        let instrs = vec![
            instr(0, 1, Opcode::Nop),
            cond_instr(1, 2, 0),
            ret_instr(3),
        ];
        let cfg = CfgBuilder::new(instrs, vec![]).build().unwrap();
        assert!(!cfg.back_edges.is_empty(), "should detect at least one back edge");
        assert!(cfg.loop_count() >= 1);
    }

    #[test]
    fn test_loop_header_marked() {
        let instrs = vec![
            instr(0, 1, Opcode::Nop),
            cond_instr(1, 2, 0),
            ret_instr(3),
        ];
        let cfg = CfgBuilder::new(instrs, vec![]).build().unwrap();
        let headers = cfg.loop_headers();
        assert!(!headers.is_empty());
        for h in headers {
            assert!(cfg.blocks[h].is_loop_header);
        }
    }

    #[test]
    fn test_cfg_stats_cyclomatic() {
        // Diamond: 4 blocks, 4 edges → CC = 4-4+2 = 2
        // 0: cond 4; 2: br 6; 4: br 6; 6: ret
        let instrs = vec![
            cond_instr(0, 2, 4),
            br_instr(2, 2, 6),
            br_instr(4, 2, 6),
            ret_instr(6),
        ];
        let cfg = CfgBuilder::new(instrs, vec![]).build().unwrap();
        let stats = CfgStats::from(&cfg);
        assert_eq!(stats.cyclomatic_complexity, 2);
    }

    #[test]
    fn test_exception_region_assigned() {
        let region = ExceptionRegion {
            kind: HandlerKind::Catch,
            try_start: 0,
            try_end: 2,
            handler_start: 2,
            handler_end: 4,
            catch_token: Some(0x0100_0001),
            filter_offset: None,
        };
        let instrs = vec![instr(0, 1, Opcode::Nop), instr(1, 1, Opcode::Nop), ret_instr(2)];
        let cfg = CfgBuilder::new(instrs, vec![region]).build().unwrap();
        // Block 0 (offset 0) should be in the try region.
        assert!(cfg.blocks[0].exception_region.is_some());
    }

    #[test]
    fn test_predecessor_wired() {
        let instrs = vec![cond_instr(0, 2, 4), ret_instr(2), ret_instr(4)];
        let cfg = CfgBuilder::new(instrs, vec![]).build().unwrap();
        // Both exit blocks should have block 0 as predecessor.
        let preds_of_1 = &cfg.blocks[1].preds;
        let preds_of_2 = &cfg.blocks[2].preds;
        assert!(preds_of_1.contains(&0) || preds_of_2.contains(&0));
    }

    #[test]
    fn test_block_at_lookup() {
        let instrs = vec![instr(0, 1, Opcode::Nop), ret_instr(1)];
        let cfg = CfgBuilder::new(instrs, vec![]).build().unwrap();
        assert!(cfg.block_at(0).is_some());
        assert!(cfg.block_at(99).is_none());
    }

    #[test]
    fn test_rpo_covers_all_reachable() {
        let instrs = vec![
            cond_instr(0, 2, 4),
            br_instr(2, 2, 6),
            br_instr(4, 2, 6),
            ret_instr(6),
        ];
        let cfg = CfgBuilder::new(instrs, vec![]).build().unwrap();
        let rpo = cfg.rpo();
        assert_eq!(rpo.len(), cfg.block_count());
    }

    #[test]
    fn test_natural_loop_body_contains_header_and_latch() {
        let instrs = vec![
            instr(0, 1, Opcode::Nop),
            cond_instr(1, 2, 0),
            ret_instr(3),
        ];
        let cfg = CfgBuilder::new(instrs, vec![]).build().unwrap();
        for ((header, latch), body) in cfg.back_edges.iter().zip(cfg.loop_bodies.iter()) {
            assert!(body.contains(header));
            assert!(body.contains(latch));
        }
    }

    #[test]
    fn test_dominator_entry_dominates_all() {
        let instrs = vec![
            cond_instr(0, 2, 4),
            br_instr(2, 2, 6),
            br_instr(4, 2, 6),
            ret_instr(6),
        ];
        let cfg = CfgBuilder::new(instrs, vec![]).build().unwrap();
        for i in 0..cfg.block_count() {
            assert!(cfg.dominates(0, i), "entry should dominate block {i}");
        }
    }

    #[test]
    fn test_empty_method() {
        let cfg = CfgBuilder::new(vec![], vec![]).build().unwrap();
        assert_eq!(cfg.block_count(), 0);
    }

    #[test]
    fn test_switch_edges() {
        // 0: switch [4, 6] (size=10); 10: ret; 4 would be unreachable with these sizes
        // Simulate with manual instrs.
        let switch_instr = DecodedCilInstr {
            offset: 0,
            size: 10,
            opcode: Opcode::Switch,
            operand: crate::cil_decoder::Operand::SwitchTargets(vec![10, 10]),
        };
        let instrs = vec![switch_instr, ret_instr(10)];
        let cfg = CfgBuilder::new(instrs, vec![]).build().unwrap();
        // Block 0 should have Switch edges.
        let switch_edges: Vec<_> = cfg.blocks[0]
            .succs
            .iter()
            .filter(|e| matches!(e.kind, EdgeKind::Switch(_)))
            .collect();
        assert!(!switch_edges.is_empty());
    }
}
