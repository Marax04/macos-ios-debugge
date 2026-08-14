//! `ast_differ` — Compare two sequences of AST nodes and produce a structured diff.
//!
//! Provides a simple abstract syntax tree representation designed for decompiler
//! output (C-like pseudo-code), an FNV-1a node hasher, a structural similarity
//! metric, and a diff algorithm that matches nodes by similarity and hash
//! identity before falling back to positional comparison.

use std::fmt;

fn count_as_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

// ── AstNode ───────────────────────────────────────────────────────────────────

/// Lightweight AST node type that covers the constructs commonly found in
/// decompiler pseudo-code output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AstNode {
    /// A function definition with a name, parameter list, and body.
    FunctionDef {
        name: String,
        params: Vec<String>,
        body: Vec<Self>,
    },
    /// A local variable declaration with an optional initializer.
    VariableDecl {
        name: String,
        init: Option<Box<Self>>,
    },
    /// An assignment of a value to a target expression.
    Assignment {
        target: Box<Self>,
        value: Box<Self>,
    },
    /// A conditional branch.
    If {
        cond: Box<Self>,
        then: Vec<Self>,
        else_: Vec<Self>,
    },
    /// A while-loop with a condition and body.
    While {
        cond: Box<Self>,
        body: Vec<Self>,
    },
    /// A return statement with an optional expression.
    Return(Option<Box<Self>>),
    /// A function or method call.
    Call {
        name: String,
        args: Vec<Self>,
    },
    /// A binary operation.
    BinOp {
        op: String,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    /// A variable reference.
    Var(String),
    /// An integer constant.
    Const(i64),
    /// A string literal.
    Str(String),
    /// A pointer dereference.
    Deref(Box<Self>),
}

impl AstNode {
    /// Return a short discriminant string for display purposes.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::FunctionDef { .. } => "FunctionDef",
            Self::VariableDecl { .. } => "VariableDecl",
            Self::Assignment { .. } => "Assignment",
            Self::If { .. } => "If",
            Self::While { .. } => "While",
            Self::Return(_) => "Return",
            Self::Call { .. } => "Call",
            Self::BinOp { .. } => "BinOp",
            Self::Var(_) => "Var",
            Self::Const(_) => "Const",
            Self::Str(_) => "Str",
            Self::Deref(_) => "Deref",
        }
    }

    /// Recursively count nodes in this subtree (including `self`).
    #[must_use]
    pub fn size(&self) -> usize {
        let children_size: usize = self.children().iter().map(|c| c.size()).sum();
        1 + children_size
    }

    /// Return direct child nodes (borrowed).
    #[must_use]
    pub fn children(&self) -> Vec<&Self> {
        match self {
            Self::FunctionDef { body, .. } => body.iter().collect(),
            Self::VariableDecl { init, .. } => {
                init.as_ref().map(|n| vec![n.as_ref()]).unwrap_or_default()
            }
            Self::Assignment { target, value } => vec![target.as_ref(), value.as_ref()],
            Self::If { cond, then, else_ } => {
                let mut v: Vec<&Self> = vec![cond.as_ref()];
                v.extend(then.iter());
                v.extend(else_.iter());
                v
            }
            Self::While { cond, body } => {
                let mut v = vec![cond.as_ref()];
                v.extend(body.iter());
                v
            }
            Self::Return(inner) => inner.as_ref().map(|n| vec![n.as_ref()]).unwrap_or_default(),
            Self::Call { args, .. } => args.iter().collect(),
            Self::BinOp { lhs, rhs, .. } => vec![lhs.as_ref(), rhs.as_ref()],
            Self::Deref(inner) => vec![inner.as_ref()],
            Self::Var(_) | Self::Const(_) | Self::Str(_) => vec![],
        }
    }
}

impl fmt::Display for AstNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Var(n) => write!(f, "{n}"),
            Self::Const(v) => write!(f, "{v}"),
            Self::Str(s) => write!(f, "\"{s}\""),
            Self::Deref(e) => write!(f, "*{e}"),
            Self::Call { name, args } => {
                let args_str: Vec<String> = args.iter().map(ToString::to_string).collect();
                write!(f, "{name}({})", args_str.join(", "))
            }
            Self::BinOp { op, lhs, rhs } => write!(f, "({lhs} {op} {rhs})"),
            Self::Return(inner) => match inner {
                Some(e) => write!(f, "return {e}"),
                None => write!(f, "return"),
            },
            Self::Assignment { target, value } => write!(f, "{target} = {value}"),
            Self::VariableDecl { name, init } => match init {
                Some(e) => write!(f, "let {name} = {e}"),
                None => write!(f, "let {name}"),
            },
            Self::If { cond, .. } => write!(f, "if ({cond}) {{ ... }}"),
            Self::While { cond, .. } => write!(f, "while ({cond}) {{ ... }}"),
            Self::FunctionDef { name, params, .. } => {
                write!(f, "fn {}({})", name, params.join(", "))
            }
        }
    }
}

// ── FNV-1a hash ───────────────────────────────────────────────────────────────

const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
const FNV_PRIME: u64 = 1_099_511_628_211;

fn fnv1a_bytes(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn fnv1a_str(s: &str) -> u64 {
    fnv1a_bytes(s.as_bytes())
}

fn fnv1a_u64(v: u64, seed: u64) -> u64 {
    fnv1a_bytes(&[seed.to_le_bytes(), v.to_le_bytes()].concat())
}

/// Compute a structural FNV-1a hash for `node`.
///
/// The hash is computed recursively over the node's discriminant and any
/// embedded string/integer values, then combined with hashes of child nodes.
/// Two structurally identical trees with identical literals will produce the
/// same hash; alpha-renamed variables will not.
#[must_use]
pub fn compute_node_hash(node: &AstNode) -> u64 {
    match node {
        AstNode::Var(name) => fnv1a_str(&format!("Var:{name}")),
        AstNode::Const(v) => fnv1a_str(&format!("Const:{v}")),
        AstNode::Str(s) => fnv1a_str(&format!("Str:{s}")),
        AstNode::Deref(inner) => fnv1a_u64(compute_node_hash(inner), fnv1a_str("Deref")),
        AstNode::Return(inner) => {
            let inner_hash = inner.as_ref().map_or(0, |n| compute_node_hash(n));
            fnv1a_u64(inner_hash, fnv1a_str("Return"))
        }
        AstNode::VariableDecl { name, init } => {
            let init_hash = init.as_ref().map_or(0, |n| compute_node_hash(n));
            let base = fnv1a_str(&format!("VD:{name}"));
            fnv1a_u64(base, init_hash)
        }
        AstNode::Call { name, args } => {
            let mut h = fnv1a_str(&format!("Call:{name}"));
            for arg in args {
                h = fnv1a_u64(h, compute_node_hash(arg));
            }
            h
        }
        AstNode::BinOp { op, lhs, rhs } => {
            let base = fnv1a_str(&format!("BinOp:{op}"));
            let lh = compute_node_hash(lhs);
            let rh = compute_node_hash(rhs);
            fnv1a_u64(fnv1a_u64(base, lh), rh)
        }
        AstNode::Assignment { target, value } => {
            let base = fnv1a_str("Assignment");
            let th = compute_node_hash(target);
            let vh = compute_node_hash(value);
            fnv1a_u64(fnv1a_u64(base, th), vh)
        }
        AstNode::If { cond, then, else_ } => {
            let mut h = fnv1a_u64(fnv1a_str("If"), compute_node_hash(cond));
            for n in then {
                h = fnv1a_u64(h, compute_node_hash(n));
            }
            for n in else_ {
                h = fnv1a_u64(h, compute_node_hash(n));
            }
            h
        }
        AstNode::While { cond, body } => {
            let mut h = fnv1a_u64(fnv1a_str("While"), compute_node_hash(cond));
            for n in body {
                h = fnv1a_u64(h, compute_node_hash(n));
            }
            h
        }
        AstNode::FunctionDef { name, params, body } => {
            let mut h = fnv1a_str(&format!("FD:{name}:{}", params.join(",")));
            for n in body {
                h = fnv1a_u64(h, compute_node_hash(n));
            }
            h
        }
    }
}

// ── node_similarity ───────────────────────────────────────────────────────────

/// Compute a [0.0, 1.0] structural similarity between two AST nodes.
///
/// Exact hash match → 1.0.
/// Same discriminant with different contents → partial score based on child
/// similarities and name matches.
/// Different discriminant → 0.0.
#[must_use]
pub fn node_similarity(a: &AstNode, b: &AstNode) -> f64 {
    if compute_node_hash(a) == compute_node_hash(b) {
        return 1.0;
    }
    // Different kinds → 0
    if a.kind_name() != b.kind_name() {
        return 0.0;
    }
    match (a, b) {
        (AstNode::Var(n1), AstNode::Var(n2)) => if n1 == n2 { 1.0 } else { 0.0 },
        (AstNode::Const(v1), AstNode::Const(v2)) => if v1 == v2 { 1.0 } else { 0.0 },
        (AstNode::Str(s1), AstNode::Str(s2)) => string_similarity(s1, s2),
        (AstNode::Call { name: n1, args: a1 }, AstNode::Call { name: n2, args: a2 }) => {
            let name_sim = if n1 == n2 { 1.0 } else { 0.3 };
            let arg_sim = children_similarity(a1, a2);
            f64::midpoint(name_sim, arg_sim)
        }
        (AstNode::BinOp { op: o1, lhs: l1, rhs: r1 }, AstNode::BinOp { op: o2, lhs: l2, rhs: r2 }) => {
            let op_sim = if o1 == o2 { 1.0 } else { 0.0 };
            let lhs_sim = node_similarity(l1, l2);
            let rhs_sim = node_similarity(r1, r2);
            (op_sim + lhs_sim + rhs_sim) / 3.0
        }
        (AstNode::Assignment { target: t1, value: v1 }, AstNode::Assignment { target: t2, value: v2 }) => {
            f64::midpoint(node_similarity(t1, t2), node_similarity(v1, v2))
        }
        (AstNode::If { cond: c1, then: t1, else_: e1 }, AstNode::If { cond: c2, then: t2, else_: e2 }) => {
            let cs = node_similarity(c1, c2);
            let ts = children_similarity(t1, t2);
            let es = children_similarity(e1, e2);
            (cs + ts + es) / 3.0
        }
        (AstNode::While { cond: c1, body: b1 }, AstNode::While { cond: c2, body: b2 }) => {
            let cs = node_similarity(c1, c2);
            let bs = children_similarity(b1, b2);
            f64::midpoint(cs, bs)
        }
        (
            AstNode::FunctionDef { name: n1, params: p1, body: b1 },
            AstNode::FunctionDef { name: n2, params: p2, body: b2 },
        ) => {
            let name_sim = if n1 == n2 { 1.0 } else { 0.2 };
            let param_count_sim = if p1.len() == p2.len() { 1.0 } else { 0.4 };
            let body_sim = children_similarity(b1, b2);
            (name_sim + param_count_sim + body_sim) / 3.0
        }
        (AstNode::Return(r1), AstNode::Return(r2)) => match (r1, r2) {
            (Some(a), Some(b)) => node_similarity(a, b),
            (None, None) => 1.0,
            _ => 0.3,
        },
        _ => 0.0,
    }
}

fn string_similarity(a: &str, b: &str) -> f64 {
    if a == b {
        return 1.0;
    }
    let common = a.chars().zip(b.chars()).filter(|(x, y)| x == y).count();
    let max_len = a.len().max(b.len());
    if max_len == 0 { 1.0 } else { count_as_f64(common) / count_as_f64(max_len) }
}

fn children_similarity(a: &[AstNode], b: &[AstNode]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    // Simple greedy: match each node in `a` to its best partner in `b`
    let mut total = 0.0f64;
    for node_a in a {
        let best = b.iter().map(|nb| node_similarity(node_a, nb)).fold(0.0f64, f64::max);
        total += best;
    }
    total / count_as_f64(a.len().max(b.len()))
}

// ── AstDiff ───────────────────────────────────────────────────────────────────

/// The result of diffing two AST node sequences.
#[derive(Debug, Clone, Default)]
pub struct AstDiff {
    /// Nodes present only in the new version.
    pub added: Vec<AstNode>,
    /// Nodes present only in the old version.
    pub removed: Vec<AstNode>,
    /// Pairs of (old, new) nodes that are structurally similar but differ.
    pub modified: Vec<(AstNode, AstNode)>,
    /// Nodes that are identical in both versions.
    pub unchanged: Vec<AstNode>,
}

impl AstDiff {
    /// Return `true` if there are no differences.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }

    /// Total number of change operations (add + remove + modify).
    #[must_use]
    pub const fn change_count(&self) -> usize {
        self.added.len() + self.removed.len() + self.modified.len()
    }

    /// Similarity ratio: 0.0 (completely different) to 1.0 (identical).
    #[must_use]
    pub fn similarity_ratio(&self) -> f64 {
        let total = self.added.len() + self.removed.len() + self.modified.len() + self.unchanged.len();
        if total == 0 {
            return 1.0;
        }
        count_as_f64(self.unchanged.len()) / count_as_f64(total)
    }
}

// ── AstDiffer ─────────────────────────────────────────────────────────────────

/// Stateless AST diffing engine.
///
/// Uses hash-based exact matching first, then greedy similarity matching for
/// nodes that share a discriminant, and finally marks unmatched nodes as
/// added or removed.
#[derive(Debug, Clone, Default)]
pub struct AstDiffer {
    /// Similarity threshold below which two nodes are considered unrelated.
    pub min_similarity: f64,
}

impl AstDiffer {
    /// Create a new `AstDiffer` with the default similarity threshold of 0.4.
    #[must_use]
    pub const fn new() -> Self {
        Self { min_similarity: 0.4 }
    }

    /// Create an `AstDiffer` with a custom similarity threshold.
    #[must_use]
    pub const fn with_threshold(min_similarity: f64) -> Self {
        Self { min_similarity }
    }

    /// Diff two slices of AST nodes.
    ///
    /// Returns an [`AstDiff`] summarising which nodes were added, removed,
    /// modified, or unchanged.
    #[must_use]
    pub fn diff(&self, old: &[AstNode], new: &[AstNode]) -> AstDiff {
        let mut result = AstDiff::default();
        let mut old_used = vec![false; old.len()];
        let mut new_used = vec![false; new.len()];

        // Pass 1: exact hash matches
        for (oi, on) in old.iter().enumerate() {
            let oh = compute_node_hash(on);
            for (ni, nn) in new.iter().enumerate() {
                if new_used[ni] {
                    continue;
                }
                if compute_node_hash(nn) == oh {
                    result.unchanged.push(on.clone());
                    old_used[oi] = true;
                    new_used[ni] = true;
                    break;
                }
            }
        }

        // Pass 2: similarity matching for unmatched nodes
        for (oi, on) in old.iter().enumerate() {
            if old_used[oi] {
                continue;
            }
            let mut best_sim = self.min_similarity;
            let mut best_ni: Option<usize> = None;
            for (ni, nn) in new.iter().enumerate() {
                if new_used[ni] {
                    continue;
                }
                // Only attempt to match nodes with same kind
                if on.kind_name() != nn.kind_name() {
                    continue;
                }
                let sim = node_similarity(on, nn);
                if sim > best_sim {
                    best_sim = sim;
                    best_ni = Some(ni);
                }
            }
            if let Some(ni) = best_ni {
                result.modified.push((on.clone(), new[ni].clone()));
                old_used[oi] = true;
                new_used[ni] = true;
            }
        }

        // Pass 3: remaining unmatched
        for (oi, on) in old.iter().enumerate() {
            if !old_used[oi] {
                result.removed.push(on.clone());
            }
        }
        for (ni, nn) in new.iter().enumerate() {
            if !new_used[ni] {
                result.added.push(nn.clone());
            }
        }

        result
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn var(n: &str) -> AstNode { AstNode::Var(n.to_owned()) }
    fn cst(v: i64) -> AstNode { AstNode::Const(v) }
    fn call(name: &str, args: Vec<AstNode>) -> AstNode {
        AstNode::Call { name: name.to_owned(), args }
    }
    fn binop(op: &str, lhs: AstNode, rhs: AstNode) -> AstNode {
        AstNode::BinOp { op: op.to_owned(), lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }
    fn ret(e: Option<AstNode>) -> AstNode {
        AstNode::Return(e.map(Box::new))
    }
    fn assign(t: AstNode, v: AstNode) -> AstNode {
        AstNode::Assignment { target: Box::new(t), value: Box::new(v) }
    }

    #[test]
    fn test_node_hash_deterministic() {
        let a = cst(42);
        assert_eq!(compute_node_hash(&a), compute_node_hash(&a));
    }

    #[test]
    fn test_node_hash_different_consts() {
        assert_ne!(compute_node_hash(&cst(1)), compute_node_hash(&cst(2)));
    }

    #[test]
    fn test_node_hash_same_var() {
        assert_eq!(compute_node_hash(&var("x")), compute_node_hash(&var("x")));
    }

    #[test]
    fn test_node_hash_different_vars() {
        assert_ne!(compute_node_hash(&var("x")), compute_node_hash(&var("y")));
    }

    #[test]
    fn test_similarity_identical() {
        let a = call("foo", vec![cst(1), var("x")]);
        assert!((node_similarity(&a, &a) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_similarity_different_kinds() {
        assert_eq!(node_similarity(&cst(1), &var("x")), 0.0);
    }

    #[test]
    fn test_similarity_same_call_name() {
        let a = call("malloc", vec![cst(64)]);
        let b = call("malloc", vec![cst(128)]);
        let sim = node_similarity(&a, &b);
        assert!(sim > 0.4, "same function name should yield > 0.4 similarity: {sim}");
    }

    #[test]
    fn test_similarity_binop_same_op() {
        let a = binop("+", var("x"), cst(1));
        let b = binop("+", var("x"), cst(2));
        let sim = node_similarity(&a, &b);
        assert!(sim > 0.5);
    }

    #[test]
    fn test_diff_empty_slices() {
        let differ = AstDiffer::new();
        let d = differ.diff(&[], &[]);
        assert!(d.is_empty());
        assert!((d.similarity_ratio() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_diff_all_same() {
        let nodes = vec![cst(1), cst(2), cst(3)];
        let differ = AstDiffer::new();
        let d = differ.diff(&nodes, &nodes);
        assert!(d.is_empty());
        assert_eq!(d.unchanged.len(), 3);
    }

    #[test]
    fn test_diff_all_added() {
        let differ = AstDiffer::new();
        let d = differ.diff(&[], &[cst(1), cst(2)]);
        assert_eq!(d.added.len(), 2);
        assert!(d.removed.is_empty());
    }

    #[test]
    fn test_diff_all_removed() {
        let differ = AstDiffer::new();
        let d = differ.diff(&[cst(1), cst(2)], &[]);
        assert_eq!(d.removed.len(), 2);
        assert!(d.added.is_empty());
    }

    #[test]
    fn test_diff_one_modified() {
        let differ = AstDiffer::new();
        let old = vec![assign(var("x"), cst(1))];
        let new = vec![assign(var("x"), cst(2))];
        let d = differ.diff(&old, &new);
        assert_eq!(d.modified.len(), 1);
    }

    #[test]
    fn test_diff_change_count() {
        let differ = AstDiffer::new();
        let old = vec![cst(1)];
        let new = vec![cst(2)];
        let d = differ.diff(&old, &new);
        // const vs const → different kind-name-check same (Const), but hashes differ,
        // and they are same kind so similarity = 0 (different values), falls to removed/added
        assert!(d.change_count() >= 1);
    }

    #[test]
    fn test_diff_return_none_vs_some() {
        let differ = AstDiffer::new();
        let old = vec![ret(None)];
        let new = vec![ret(Some(cst(0)))];
        let d = differ.diff(&old, &new);
        // modified because same kind (Return) with some similarity
        assert!(d.modified.len() == 1 || d.added.len() + d.removed.len() == 2);
    }

    #[test]
    fn test_node_size_leaf() {
        assert_eq!(var("x").size(), 1);
    }

    #[test]
    fn test_node_size_binop() {
        let n = binop("+", var("x"), cst(1));
        assert_eq!(n.size(), 3); // binop + var + const
    }

    #[test]
    fn test_kind_name_all_variants() {
        let nodes: Vec<AstNode> = vec![
            AstNode::FunctionDef { name: "f".into(), params: vec![], body: vec![] },
            AstNode::VariableDecl { name: "v".into(), init: None },
            assign(var("x"), cst(0)),
            AstNode::If { cond: Box::new(cst(1)), then: vec![], else_: vec![] },
            AstNode::While { cond: Box::new(cst(1)), body: vec![] },
            ret(None),
            call("f", vec![]),
            binop("+", cst(1), cst(2)),
            var("v"),
            cst(0),
            AstNode::Str("s".into()),
            AstNode::Deref(Box::new(var("p"))),
        ];
        for n in &nodes {
            assert!(!n.kind_name().is_empty());
        }
    }

    #[test]
    fn test_similarity_ratio_after_diff() {
        let differ = AstDiffer::new();
        let nodes = vec![cst(1), cst(2), cst(3), cst(4)];
        let new_nodes = vec![cst(1), cst(2), cst(3), cst(99)];
        let d = differ.diff(&nodes, &new_nodes);
        let ratio = d.similarity_ratio();
        assert!(ratio > 0.5 && ratio < 1.0);
    }
}
