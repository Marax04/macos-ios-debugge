//! DREAM algorithm implementation for control-flow structuring.
//!
//! DREAM ("Decompiling Real Executables with Abstract Machines") is the
//! "no-more-gotos" algorithm originally described by Yakdan et al. (2015).
//! It works on the post-order of the dominator tree and collapses reducible
//! patterns into structured constructs, emitting `goto` for any remaining
//! irreducible edges.
//!
//! This module provides a standalone implementation that operates on the
//! [`BasicBlock`] / [`BlockId`] types from the crate root.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::{BasicBlock, BlockId, LoopKind, Statement, StructuredNode, SwitchCase};

// ── PostOrder ─────────────────────────────────────────────────────────────────

/// Post-order traversal of the dominator tree.
///
/// Each entry contains a block and its immediate dominator.
#[derive(Debug, Clone)]
pub struct PostOrder {
    /// Blocks in post-order (leaves first, root last).
    pub order: Vec<BlockId>,
    /// Immediate dominator for each block.
    pub idom: HashMap<BlockId, BlockId>,
}

impl PostOrder {
    /// Build the post-order and idom map from a block list.
    #[must_use]
    pub fn build(blocks: &[BasicBlock], entry: BlockId) -> Self {
        let mut succ: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        let mut pred: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for bb in blocks {
            succ.entry(bb.id).or_default().extend_from_slice(&bb.successors);
            for &s in &bb.successors {
                pred.entry(s).or_default().push(bb.id);
            }
        }

        // RPO for the dominator algorithm.
        let rpo = rpo_order(&succ, entry);
        let rpo_pos: HashMap<BlockId, usize> =
            rpo.iter().enumerate().map(|(i, &n)| (n, i)).collect();

        // Compute immediate dominators using the simple iterative algorithm.
        let mut idom: HashMap<BlockId, BlockId> = HashMap::new();
        idom.insert(entry, entry);
        let mut changed = true;
        while changed {
            changed = false;
            for &b in &rpo {
                if b == entry {
                    continue;
                }
                let processed_preds: Vec<BlockId> = pred
                    .get(&b)
                    .map_or(vec![], |ps| {
                        ps.iter()
                            .filter(|&&p| idom.contains_key(&p))
                            .copied()
                            .collect()
                    });
                if processed_preds.is_empty() {
                    continue;
                }
                let mut new_idom = processed_preds[0];
                for &p in processed_preds.iter().skip(1) {
                    new_idom = intersect(new_idom, p, &idom, &rpo_pos);
                }
                if idom.get(&b) != Some(&new_idom) {
                    idom.insert(b, new_idom);
                    changed = true;
                }
            }
        }

        // Build post-order of the dominator tree (children before parents).
        let mut dom_children: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for (&b, &d) in &idom {
            if b != d {
                dom_children.entry(d).or_default().push(b);
            }
        }
        let mut post = Vec::with_capacity(rpo.len());
        let mut visited = HashSet::new();
        dom_tree_post(entry, &dom_children, &mut visited, &mut post);

        Self { order: post, idom }
    }

    /// Whether `a` dominates `b`.
    #[must_use]
    pub fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        let mut cur = b;
        loop {
            if cur == a {
                return true;
            }
            let Some(&dom) = self.idom.get(&cur) else { return false };
            if dom == cur {
                break;
            }
            cur = dom;
        }
        false
    }
}

fn rpo_order(succ: &HashMap<BlockId, Vec<BlockId>>, entry: BlockId) -> Vec<BlockId> {
    // Iterative post-order DFS to avoid stack overflow on deep CFGs.
    let mut visited = HashSet::new();
    let mut post = Vec::new();
    // Stack frame: (node, index into successors already processed).
    let mut stack: Vec<(BlockId, usize)> = Vec::new();
    if visited.insert(entry) {
        stack.push((entry, 0));
    }
    while let Some(frame) = stack.last_mut() {
        let succs = succ.get(&frame.0).map_or(&[][..], Vec::as_slice);
        if frame.1 < succs.len() {
            let next = succs[frame.1];
            frame.1 += 1;
            if visited.insert(next) {
                stack.push((next, 0));
            }
        } else {
            post.push(frame.0);
            stack.pop();
        }
    }
    post.reverse();
    post
}

fn dom_tree_post(
    root: BlockId,
    children: &HashMap<BlockId, Vec<BlockId>>,
    visited: &mut HashSet<BlockId>,
    post: &mut Vec<BlockId>,
) {
    // Iterative post-order traversal to avoid stack overflow on deep dom trees.
    let mut stack: Vec<(BlockId, usize)> = Vec::new();
    if visited.insert(root) {
        stack.push((root, 0));
    }
    while let Some(frame) = stack.last_mut() {
        let ch = children.get(&frame.0).map_or(&[][..], Vec::as_slice);
        if frame.1 < ch.len() {
            let next = ch[frame.1];
            frame.1 += 1;
            if visited.insert(next) {
                stack.push((next, 0));
            }
        } else {
            post.push(frame.0);
            stack.pop();
        }
    }
}

fn intersect(
    mut b1: BlockId,
    mut b2: BlockId,
    idom: &HashMap<BlockId, BlockId>,
    rpo_pos: &HashMap<BlockId, usize>,
) -> BlockId {
    while b1 != b2 {
        while rpo_pos.get(&b1).copied().unwrap_or(usize::MAX)
            > rpo_pos.get(&b2).copied().unwrap_or(usize::MAX)
        {
            b1 = idom[&b1];
        }
        while rpo_pos.get(&b2).copied().unwrap_or(usize::MAX)
            > rpo_pos.get(&b1).copied().unwrap_or(usize::MAX)
        {
            b2 = idom[&b2];
        }
    }
    b1
}

// ── BackEdge ──────────────────────────────────────────────────────────────────

/// A back-edge identified in the CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BackEdge {
    /// The loop header (target of the back-edge).
    pub header: BlockId,
    /// The latch (source of the back-edge).
    pub latch: BlockId,
}

impl BackEdge {
    /// Create a new back-edge record.
    #[must_use]
    pub const fn new(header: BlockId, latch: BlockId) -> Self {
        Self { header, latch }
    }
}

// ── StructuredNode helpers ────────────────────────────────────────────────────

fn leaf(bb: &BasicBlock) -> StructuredNode {
    StructuredNode::BasicBlock {
        id: bb.id,
        stmts: bb.stmts.clone(),
    }
}

fn seq(nodes: Vec<StructuredNode>) -> StructuredNode {
    let flat: Vec<StructuredNode> = nodes
        .into_iter()
        .flat_map(|n| match n {
            StructuredNode::Sequence(v) => v,
            other => vec![other],
        })
        .filter(|n| !matches!(n, StructuredNode::Sequence(v) if v.is_empty()))
        .collect();
    match flat.len() {
        0 => StructuredNode::Sequence(vec![]),
        1 => flat.into_iter().next().unwrap(),
        _ => StructuredNode::Sequence(flat),
    }
}

fn cond_from_block(bb: &BasicBlock) -> String {
    bb.stmts
        .iter()
        .rev()
        .find_map(|s| {
            if let Statement::Branch(c) = s {
                Some(c.clone())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "true".to_string())
}

// ── RegionCtx ─────────────────────────────────────────────────────────────────

/// Shared mutable context threaded through the recursive structuring pass.
///
/// Bundling these three arguments avoids exceeding the clippy `too_many_arguments`
/// limit on the inner helpers.
struct RegionCtx<'a> {
    po: &'a PostOrder,
    node_map: &'a mut HashMap<BlockId, StructuredNode>,
    visited: &'a mut HashSet<BlockId>,
}

// ── DreamAlgorithm ────────────────────────────────────────────────────────────

/// The DREAM structuring algorithm.
///
/// Processes blocks in post-order of the dominator tree and collapses
/// each reducible pattern into a structured AST node.  Any unstructurable
/// edges are left as `StructuredNode::Goto`.
pub struct DreamAlgorithm {
    /// Block map for fast lookup.
    blocks: HashMap<BlockId, BasicBlock>,
    /// Pre-computed back-edges.
    back_edges: HashSet<(BlockId, BlockId)>,
    /// Loop-header set.
    loop_headers: HashSet<BlockId>,
    /// Successor map (excluding back-edges).
    fwd_succ: HashMap<BlockId, Vec<BlockId>>,
    /// Predecessor map (excluding back-edges).
    fwd_pred: HashMap<BlockId, Vec<BlockId>>,
}

impl DreamAlgorithm {
    /// Build the algorithm state from a list of basic blocks and an entry.
    #[must_use]
    pub fn new(blocks: &[BasicBlock], entry: BlockId) -> Self {
        let block_map: HashMap<BlockId, BasicBlock> =
            blocks.iter().map(|b| (b.id, b.clone())).collect();

        // Find back-edges via DFS.
        let back_edges = find_back_edges(&block_map, entry);
        let loop_headers: HashSet<BlockId> = back_edges.iter().map(|&(h, _)| h).collect();

        // Build forward successor / predecessor maps (excluding back-edges).
        let mut fwd_succ: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        let mut fwd_pred: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for bb in blocks {
            for &s in &bb.successors {
                if !back_edges.contains(&(s, bb.id)) {
                    fwd_succ.entry(bb.id).or_default().push(s);
                    fwd_pred.entry(s).or_default().push(bb.id);
                }
            }
        }

        Self {
            blocks: block_map,
            back_edges,
            loop_headers,
            fwd_succ,
            fwd_pred,
        }
    }

    /// Return the predecessor map (excluding back-edges).
    #[must_use]
    pub const fn fwd_pred(&self) -> &HashMap<BlockId, Vec<BlockId>> {
        &self.fwd_pred
    }

    /// Run the structuring pass and return the root [`StructuredNode`].
    #[must_use]
    pub fn structurize(&self, entry: BlockId) -> StructuredNode {
        let blocks_vec: Vec<BasicBlock> = self.blocks.values().cloned().collect();
        let po = PostOrder::build(&blocks_vec, entry);

        let mut node_map: HashMap<BlockId, StructuredNode> = HashMap::new();
        let mut visited: HashSet<BlockId> = HashSet::new();

        let mut ctx = RegionCtx { po: &po, node_map: &mut node_map, visited: &mut visited };
        self.structure_region(entry, None, &mut ctx)
    }

    fn structure_region(
        &self,
        node: BlockId,
        follow: Option<BlockId>,
        ctx: &mut RegionCtx<'_>,
    ) -> StructuredNode {
        if Some(node) == follow {
            return StructuredNode::Sequence(vec![]);
        }
        // Return memoized result if this node was already fully structured.
        if let Some(cached) = ctx.node_map.get(&node) {
            return cached.clone();
        }
        if !ctx.visited.insert(node) {
            return StructuredNode::Goto(node);
        }

        let bb = match self.blocks.get(&node) {
            Some(b) => b.clone(),
            None => return StructuredNode::Goto(node),
        };

        let fwd_succs: Vec<BlockId> = self
            .fwd_succ
            .get(&node)
            .map_or(vec![], std::clone::Clone::clone);

        // Terminal block.
        if fwd_succs.is_empty() {
            let ret_val = bb.stmts.iter().rev().find_map(|s| {
                if let Statement::Return(v) = s {
                    Some(v.clone())
                } else {
                    None
                }
            }).flatten();
            return seq(vec![leaf(&bb), StructuredNode::Return(ret_val)]);
        }

        // Loop header.
        if self.loop_headers.contains(&node) {
            return self.structure_loop(node, &bb, follow, ctx);
        }

        // Straight sequence.
        if fwd_succs.len() == 1 {
            let next = fwd_succs[0];
            if Some(next) == follow {
                return leaf(&bb);
            }
            let rest = self.structure_region(next, follow, ctx);
            return seq(vec![leaf(&bb), rest]);
        }

        // Conditional.
        if fwd_succs.len() == 2 {
            return self.structure_cond(node, &bb, fwd_succs[0], fwd_succs[1], follow, ctx);
        }

        // Switch.
        self.structure_switch(node, &bb, &fwd_succs, follow, ctx)
    }

    fn structure_loop(
        &self,
        header: BlockId,
        bb: &BasicBlock,
        follow: Option<BlockId>,
        ctx: &mut RegionCtx<'_>,
    ) -> StructuredNode {
        let latches: Vec<BlockId> = self
            .back_edges
            .iter()
            .filter(|&&(h, _)| h == header)
            .map(|&(_, l)| l)
            .collect();

        let header_succs: Vec<BlockId> = self
            .fwd_succ
            .get(&header)
            .map_or(vec![], std::clone::Clone::clone);

        let loop_follow = header_succs.iter().find(|&&s| {
            ctx.po.idom.get(&s).copied() != Some(header) || latches.contains(&s)
        }).copied();

        let follow_node = loop_follow.or(follow);

        let (kind, condition) = if header_succs.len() == 2 {
            (LoopKind::While, cond_from_block(bb))
        } else {
            let latch_id = latches.first().copied();
            let cond = latch_id
                .and_then(|lid| self.blocks.get(&lid))
                .map_or_else(|| "1".to_string(), cond_from_block);
            (LoopKind::DoWhile, cond)
        };

        let body_entry = header_succs.iter().find(|&&s| Some(s) != follow_node).copied();
        let body = body_entry.map_or_else(|| StructuredNode::Sequence(vec![]), |bs| self.structure_region(bs, follow_node, ctx));

        let loop_node = StructuredNode::Loop {
            kind,
            condition,
            body: Box::new(body),
        };
        let result = seq(vec![leaf(bb), loop_node]);

        if let Some(fn_) = follow_node.filter(|&f| Some(f) != follow) {
            let after = self.structure_region(fn_, follow, ctx);
            return seq(vec![result, after]);
        }
        result
    }

    fn structure_cond(
        &self,
        _node: BlockId,
        bb: &BasicBlock,
        then_ni: BlockId,
        else_ni: BlockId,
        follow: Option<BlockId>,
        ctx: &mut RegionCtx<'_>,
    ) -> StructuredNode {
        let condition = cond_from_block(bb);
        let l = leaf(bb);

        let join = find_join_two(
            then_ni,
            else_ni,
            &self.fwd_succ,
        );
        let branch_follow = join.or(follow);

        if Some(then_ni) == branch_follow {
            let else_body = self.structure_region(else_ni, branch_follow, ctx);
            let if_node = StructuredNode::If {
                condition: negate(&condition),
                then_branch: Box::new(else_body),
            };
            let result = seq(vec![l, if_node]);
            if let Some(j) = branch_follow.filter(|&j| Some(j) != follow) {
                let after = self.structure_region(j, follow, ctx);
                return seq(vec![result, after]);
            }
            return result;
        }
        if Some(else_ni) == branch_follow {
            let then_body = self.structure_region(then_ni, branch_follow, ctx);
            let if_node = StructuredNode::If {
                condition,
                then_branch: Box::new(then_body),
            };
            let result = seq(vec![l, if_node]);
            if let Some(j) = branch_follow.filter(|&j| Some(j) != follow) {
                let after = self.structure_region(j, follow, ctx);
                return seq(vec![result, after]);
            }
            return result;
        }

        let then_body = self.structure_region(then_ni, branch_follow, ctx);
        let else_body = self.structure_region(else_ni, branch_follow, ctx);
        let if_else_node = StructuredNode::IfElse {
            condition,
            then_branch: Box::new(then_body),
            else_branch: Box::new(else_body),
        };
        let result = seq(vec![l, if_else_node]);
        if let Some(j) = branch_follow.filter(|&j| Some(j) != follow) {
            let after = self.structure_region(j, follow, ctx);
            return seq(vec![result, after]);
        }
        result
    }

    fn structure_switch(
        &self,
        _node: BlockId,
        bb: &BasicBlock,
        targets: &[BlockId],
        follow: Option<BlockId>,
        ctx: &mut RegionCtx<'_>,
    ) -> StructuredNode {
        let expr = cond_from_block(bb);
        let l = leaf(bb);

        let join = find_switch_join_fwd(targets, &self.fwd_succ);
        let case_follow = join.or(follow);

        let mut cases = Vec::new();
        for (i, &t) in targets.iter().enumerate() {
            let body = self.structure_region(t, case_follow, ctx);
            cases.push(SwitchCase {
                value: Some(i64::try_from(i).unwrap_or(i64::MAX)),
                body: Box::new(body),
            });
        }
        let sw = StructuredNode::Switch { expr, cases };
        let result = seq(vec![l, sw]);
        if let Some(j) = case_follow.filter(|&j| Some(j) != follow) {
            let after = self.structure_region(j, follow, ctx);
            return seq(vec![result, after]);
        }
        result
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn find_back_edges(
    blocks: &HashMap<BlockId, BasicBlock>,
    entry: BlockId,
) -> HashSet<(BlockId, BlockId)> {
    let mut colour: HashMap<BlockId, u8> = HashMap::new();
    let mut back = HashSet::new();
    dfs_colour(entry, blocks, &mut colour, &mut back);
    back
}

fn dfs_colour(
    entry: BlockId,
    blocks: &HashMap<BlockId, BasicBlock>,
    colour: &mut HashMap<BlockId, u8>,
    back: &mut HashSet<(BlockId, BlockId)>,
) {
    // Iterative DFS back-edge detection to avoid stack overflow on deep CFGs.
    // Stack frame: (node, index into successors already processed).
    let mut stack: Vec<(BlockId, usize)> = vec![(entry, 0)];
    colour.insert(entry, 1);
    while let Some(frame) = stack.last_mut() {
        let node = frame.0;
        let succs = blocks.get(&node)
            .map_or(&[][..], |b| b.successors.as_slice());
        if frame.1 < succs.len() {
            let s = succs[frame.1];
            frame.1 += 1;
            match colour.get(&s).copied().unwrap_or(0) {
                1 => { back.insert((s, node)); }
                0 => {
                    colour.insert(s, 1);
                    stack.push((s, 0));
                }
                _ => {}
            }
        } else {
            colour.insert(node, 2);
            stack.pop();
        }
    }
}

fn bfs_reach(start: BlockId, succ: &HashMap<BlockId, Vec<BlockId>>) -> HashSet<BlockId> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::from([start]);
    while let Some(n) = queue.pop_front() {
        if visited.insert(n) {
            for &s in succ.get(&n).map_or(&[][..], Vec::as_slice) {
                queue.push_back(s);
            }
        }
    }
    visited
}

fn find_join_two(
    a: BlockId,
    b: BlockId,
    succ: &HashMap<BlockId, Vec<BlockId>>,
) -> Option<BlockId> {
    let ra = bfs_reach(a, succ);
    let rb = bfs_reach(b, succ);
    if ra.contains(&b) { return Some(b); }
    if rb.contains(&a) { return Some(a); }
    let common: HashSet<BlockId> = ra.intersection(&rb).copied().collect();
    if common.is_empty() { return None; }
    let mut queue = VecDeque::from([a]);
    let mut seen = HashSet::new();
    seen.insert(a);
    while let Some(n) = queue.pop_front() {
        if common.contains(&n) && n != a { return Some(n); }
        for &s in succ.get(&n).map_or(&[][..], Vec::as_slice) {
            if seen.insert(s) { queue.push_back(s); }
        }
    }
    common.into_iter().next()
}

fn find_switch_join_fwd(
    targets: &[BlockId],
    succ: &HashMap<BlockId, Vec<BlockId>>,
) -> Option<BlockId> {
    if targets.is_empty() { return None; }
    let sets: Vec<HashSet<BlockId>> = targets.iter().map(|&t| bfs_reach(t, succ)).collect();
    let mut queue = VecDeque::from([targets[0]]);
    let mut seen = HashSet::new();
    while let Some(n) = queue.pop_front() {
        if sets.iter().all(|s| s.contains(&n)) && !targets.contains(&n) {
            return Some(n);
        }
        for &s in succ.get(&n).map_or(&[][..], Vec::as_slice) {
            if seen.insert(s) { queue.push_back(s); }
        }
    }
    None
}

/// True when `s` is fully wrapped in one pair of parentheses, i.e. the `(` at
/// index 0 is closed by the final `)` rather than by something in the middle
/// (`(a) && (b)` must not be unwrapped).
fn is_fully_parenthesized(s: &str) -> bool {
    if !(s.starts_with('(') && s.ends_with(')')) {
        return false;
    }
    let mut depth = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1 == s.len();
                }
            }
            _ => {}
        }
    }
    false
}

fn negate(cond: &str) -> String {
    let Some(rest) = cond.strip_prefix('!') else {
        return format!("!({cond})");
    };
    // `!(x)` → `x`, not `(x)`.
    if is_fully_parenthesized(rest) {
        return rest[1..rest.len() - 1].to_string();
    }
    rest.to_string()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Statement;

    fn bb(id: u32, stmts: Vec<Statement>, succs: Vec<u32>) -> BasicBlock {
        BasicBlock {
            id: BlockId::new(id),
            stmts,
            successors: succs.into_iter().map(BlockId::new).collect(),
        }
    }

    fn raw(s: &str) -> Statement { Statement::Raw(s.to_string()) }
    fn branch(s: &str) -> Statement { Statement::Branch(s.to_string()) }

    #[test]
    fn single_block() {
        let blocks = vec![bb(0, vec![Statement::Return(None)], vec![])];
        let algo = DreamAlgorithm::new(&blocks, BlockId::new(0));
        let node = algo.structurize(BlockId::new(0));
        assert!(node.goto_count() == 0);
    }

    #[test]
    fn linear_sequence() {
        let blocks = vec![
            bb(0, vec![raw("a")], vec![1]),
            bb(1, vec![Statement::Return(None)], vec![]),
        ];
        let algo = DreamAlgorithm::new(&blocks, BlockId::new(0));
        let node = algo.structurize(BlockId::new(0));
        assert_eq!(node.goto_count(), 0);
    }

    #[test]
    fn simple_if() {
        let blocks = vec![
            bb(0, vec![branch("x > 0")], vec![1, 2]),
            bb(1, vec![raw("a = 1")], vec![2]),
            bb(2, vec![Statement::Return(None)], vec![]),
        ];
        let algo = DreamAlgorithm::new(&blocks, BlockId::new(0));
        let node = algo.structurize(BlockId::new(0));
        assert_eq!(node.goto_count(), 0);
    }

    #[test]
    fn if_else() {
        let blocks = vec![
            bb(0, vec![branch("flag")], vec![1, 2]),
            bb(1, vec![raw("a = 1")], vec![3]),
            bb(2, vec![raw("a = 2")], vec![3]),
            bb(3, vec![Statement::Return(None)], vec![]),
        ];
        let algo = DreamAlgorithm::new(&blocks, BlockId::new(0));
        let node = algo.structurize(BlockId::new(0));
        assert_eq!(node.goto_count(), 0);
    }

    #[test]
    fn while_loop() {
        let blocks = vec![
            bb(0, vec![raw("i=0")], vec![1]),
            bb(1, vec![branch("i<10")], vec![2, 3]),
            bb(2, vec![raw("i++")], vec![1]),
            bb(3, vec![Statement::Return(None)], vec![]),
        ];
        let algo = DreamAlgorithm::new(&blocks, BlockId::new(0));
        let node = algo.structurize(BlockId::new(0));
        assert!(node.node_count() > 1);
    }

    #[test]
    fn post_order_entry_last() {
        let blocks = vec![
            bb(0, vec![], vec![1]),
            bb(1, vec![], vec![2]),
            bb(2, vec![], vec![]),
        ];
        let po = PostOrder::build(&blocks, BlockId::new(0));
        // In post-order of the dominator tree, the entry (root) should come last.
        assert_eq!(po.order.last().copied(), Some(BlockId::new(0)));
    }

    #[test]
    fn back_edge_detected() {
        let blocks = [bb(0, vec![], vec![1]),
            bb(1, vec![branch("c")], vec![2, 3]),
            bb(2, vec![], vec![1]),
            bb(3, vec![], vec![])];
        let block_map: HashMap<BlockId, BasicBlock> =
            blocks.iter().map(|b| (b.id, b.clone())).collect();
        let back = find_back_edges(&block_map, BlockId::new(0));
        assert!(!back.is_empty());
    }

    #[test]
    fn negate_double() {
        assert_eq!(negate("!(x)"), "x");
        assert_eq!(negate("a > 0"), "!(a > 0)");
    }

    #[test]
    fn dominates_linear() {
        let blocks = vec![
            bb(0, vec![], vec![1]),
            bb(1, vec![], vec![2]),
            bb(2, vec![], vec![]),
        ];
        let po = PostOrder::build(&blocks, BlockId::new(0));
        assert!(po.dominates(BlockId::new(0), BlockId::new(2)));
        assert!(!po.dominates(BlockId::new(2), BlockId::new(0)));
    }

    #[test]
    fn switch_structuring() {
        let blocks = vec![
            bb(0, vec![branch("x")], vec![1, 2, 3]),
            bb(1, vec![raw("case0")], vec![4]),
            bb(2, vec![raw("case1")], vec![4]),
            bb(3, vec![raw("case2")], vec![4]),
            bb(4, vec![Statement::Return(None)], vec![]),
        ];
        let algo = DreamAlgorithm::new(&blocks, BlockId::new(0));
        let node = algo.structurize(BlockId::new(0));
        assert_eq!(node.goto_count(), 0);
    }

    #[test]
    fn empty_blocks_does_not_panic() {
        let algo = DreamAlgorithm::new(&[], BlockId::new(0));
        let node = algo.structurize(BlockId::new(0));
        // Should return a goto since block 0 is not found.
        assert!(matches!(node, StructuredNode::Goto(_)));
    }

    #[test]
    fn self_loop() {
        let blocks = vec![bb(0, vec![raw("spin")], vec![0])];
        let algo = DreamAlgorithm::new(&blocks, BlockId::new(0));
        let node = algo.structurize(BlockId::new(0));
        assert!(node.node_count() >= 1);
    }
}
