//! `semantic_equivalence` — Semantic equivalence checking for RustRE.
//!
//! Provides [`SemanticEquivalenceChecker`], [`NormalizedIL`], [`EquivalenceClass`],
//! [`SMTEquivalenceProver`], [`FunctionHash`], and [`EquivalenceDb`].

use std::collections::HashMap;
use std::fmt;

// ── NormalizedIL ──────────────────────────────────────────────────────────────

/// A normalized IL statement (α-renamed, constant-folded).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NilStmt {
    /// Assignment: `var_id` ← `expr_id`.
    Assign { dst: u32, src: u32 },
    /// Return: optionally with expr.
    Return(Option<u32>),
    /// Conditional branch.
    Branch {
        cond: u32,
        taken: u32,
        fallthrough: u32,
    },
    /// Call: result ← `call(func_id`, args).
    Call {
        result: Option<u32>,
        func: u32,
        args: Vec<u32>,
    },
    /// Memory store.
    Store { ptr: u32, val: u32, size: u8 },
    /// No-op / unreachable.
    Nop,
}

/// A normalized IL expression node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NilExpr {
    /// Symbolic variable (α-renamed index).
    Var(u32),
    /// Constant value.
    Const(i64),
    /// Binary operation.
    BinOp {
        op: &'static str,
        lhs: u32,
        rhs: u32,
    },
    /// Unary operation.
    UnOp { op: &'static str, src: u32 },
    /// Memory load.
    Load { ptr: u32, size: u8 },
    /// Function call result.
    CallResult { func: u32, args: Vec<u32> },
    /// Phi node (SSA).
    Phi(Vec<u32>),
    /// Unknown.
    Unknown,
}

/// A fully normalized function body.
#[derive(Debug, Clone)]
pub struct NormalizedIL {
    pub func_name: String,
    pub address: u64,
    pub stmts: Vec<NilStmt>,
    pub exprs: Vec<NilExpr>,
    /// Variable count (after α-renaming).
    pub var_count: u32,
    /// Hash of normalized form.
    pub normal_hash: u64,
}

impl NormalizedIL {
    #[must_use] 
    pub fn new(func_name: &str, address: u64) -> Self {
        Self {
            func_name: func_name.to_owned(),
            address,
            stmts: Vec::new(),
            exprs: Vec::new(),
            var_count: 0,
            normal_hash: 0,
        }
    }

    /// Compute the normalization hash from stmts/exprs.
    pub fn compute_hash(&mut self) {
        let mut h: u64 = 0xCBF2_9CE4_8422_2325;
        for (i, stmt) in self.stmts.iter().enumerate() {
            let sv = match stmt {
                NilStmt::Assign { dst, src } => u64::from(*dst).wrapping_add(u64::from(*src)),
                NilStmt::Return(Some(v)) => u64::from(*v),
                NilStmt::Return(None) => 0xFF,
                NilStmt::Branch { cond, .. } => u64::from(*cond),
                NilStmt::Call { func, .. } => u64::from(*func),
                NilStmt::Store { ptr, val, .. } => u64::from(*ptr).wrapping_add(u64::from(*val)),
                NilStmt::Nop => 0,
            };
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
            h ^= sv ^ (i as u64);
        }
        self.normal_hash = h;
    }

    /// Return true if the two normalizations appear equivalent.
    #[must_use] 
    pub const fn is_equivalent_to(&self, other: &Self) -> bool {
        self.normal_hash == other.normal_hash && self.stmts.len() == other.stmts.len()
    }
}

// ── FunctionHash ──────────────────────────────────────────────────────────────

/// A semantic hash of a function.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionHash {
    /// SHA-3-like structural hash over normalized IL.
    pub semantic_hash: u64,
    /// Hash computed only from the dominance tree structure.
    pub structural_hash: u64,
    /// Hash of the concrete constant values used.
    pub constant_hash: u64,
    /// Combined fingerprint.
    pub fingerprint: u128,
}

impl FunctionHash {
    #[must_use] 
    pub fn compute(nil: &NormalizedIL) -> Self {
        let semantic = nil.normal_hash;
        let structural = nil.stmts.iter().enumerate().fold(0u64, |h, (i, _s)| {
            h.wrapping_mul(0x61C8_8646_80B5_83EB).wrapping_add(i as u64)
        });
        let constant = nil
            .exprs
            .iter()
            .filter_map(|e| {
                if let NilExpr::Const(v) = e {
                    Some(v.unsigned_abs())
                } else {
                    None
                }
            })
            .fold(0u64, |h, c| h ^ c.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let fingerprint = (u128::from(semantic) << 64) | u128::from(structural);
        Self {
            semantic_hash: semantic,
            structural_hash: structural,
            constant_hash: constant,
            fingerprint,
        }
    }

    /// Are these hashes likely equivalent?
    #[must_use] 
    pub fn likely_equivalent(&self, other: &Self) -> f64 {
        let mut score = 0.0f64;
        if self.semantic_hash == other.semantic_hash {
            score += 0.7;
        }
        if self.structural_hash == other.structural_hash {
            score += 0.2;
        }
        if self.constant_hash == other.constant_hash {
            score += 0.1;
        }
        score
    }
}

// ── EquivalenceClass ──────────────────────────────────────────────────────────

/// A set of semantically identical functions.
#[derive(Debug, Clone)]
pub struct EquivalenceClass {
    pub id: u64,
    pub members: Vec<u64>, // function addresses
    pub hash: FunctionHash,
    pub label: Option<String>,
}

impl EquivalenceClass {
    #[must_use] 
    pub const fn new(id: u64, hash: FunctionHash) -> Self {
        Self {
            id,
            members: Vec::new(),
            hash,
            label: None,
        }
    }
    pub fn add_member(&mut self, addr: u64) {
        self.members.push(addr);
    }
    #[must_use] 
    pub const fn size(&self) -> usize {
        self.members.len()
    }
    #[must_use] 
    pub fn contains(&self, addr: u64) -> bool {
        self.members.contains(&addr)
    }
}

// ── EquivalenceDb ─────────────────────────────────────────────────────────────

/// Database of equivalence classes.
#[derive(Debug, Default)]
pub struct EquivalenceDb {
    classes: Vec<EquivalenceClass>,
    addr_to_class: HashMap<u64, u64>, // addr → class id
    next_id: u64,
}

impl EquivalenceDb {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_class(&mut self, cls: EquivalenceClass) -> u64 {
        let id = cls.id;
        for &addr in &cls.members {
            self.addr_to_class.insert(addr, id);
        }
        self.classes.push(cls);
        id
    }

    /// # Panics
    ///
    /// Panics if the internal class list is unexpectedly empty after push (unreachable).
    pub fn new_class(&mut self, hash: FunctionHash) -> &mut EquivalenceClass {
        let id = self.next_id;
        self.next_id += 1;
        self.classes.push(EquivalenceClass::new(id, hash));
        self.classes.last_mut().unwrap()
    }

    #[must_use] 
    pub fn class_of(&self, addr: u64) -> Option<&EquivalenceClass> {
        let cls_id = self.addr_to_class.get(&addr)?;
        self.classes.iter().find(|c| c.id == *cls_id)
    }

    #[must_use] 
    pub const fn class_count(&self) -> usize {
        self.classes.len()
    }

    pub fn merge_classes(&mut self, id_a: u64, id_b: u64) {
        // Move all members from class_b into class_a.
        let members_b: Vec<u64> = self
            .classes
            .iter()
            .find(|c| c.id == id_b)
            .map(|c| c.members.clone())
            .unwrap_or_default();
        for addr in &members_b {
            self.addr_to_class.insert(*addr, id_a);
        }
        if let Some(cls_a) = self.classes.iter_mut().find(|c| c.id == id_a) {
            cls_a.members.extend(members_b);
        }
        self.classes.retain(|c| c.id != id_b);
    }
}

// ── SMTEquivalenceProver ──────────────────────────────────────────────────────

/// Models an SMT-based equivalence prover (using Z3 in concept).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProverResult {
    Equivalent,
    NotEquivalent,
    Unknown,
    Timeout,
}

impl fmt::Display for ProverResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Equivalent => f.write_str("equivalent"),
            Self::NotEquivalent => f.write_str("not_equivalent"),
            Self::Unknown => f.write_str("unknown"),
            Self::Timeout => f.write_str("timeout"),
        }
    }
}

pub struct SMTEquivalenceProver {
    pub timeout_ms: u64,
}

impl SMTEquivalenceProver {
    #[must_use] 
    pub const fn new(timeout_ms: u64) -> Self {
        Self { timeout_ms }
    }

    /// Prove equivalence of two normalized IL functions.
    /// (This is a model — a real implementation would invoke Z3/Boolector.)
    #[must_use] 
    pub const fn prove(&self, a: &NormalizedIL, b: &NormalizedIL) -> ProverResult {
        if a.stmts.is_empty() && b.stmts.is_empty() {
            return ProverResult::Equivalent;
        }
        // Fast path: hash equality → likely equivalent.
        if a.is_equivalent_to(b) {
            return ProverResult::Equivalent;
        }
        // Different stmt counts → not equivalent.
        if a.stmts.len() != b.stmts.len() {
            return ProverResult::NotEquivalent;
        }
        // Otherwise: model says unknown (real Z3 call needed).
        ProverResult::Unknown
    }

    /// Check if two functions have equivalent return semantics.
    #[must_use] 
    pub fn check_return_equivalence(&self, a: &NormalizedIL, b: &NormalizedIL) -> ProverResult {
        let ret_a: Vec<_> = a
            .stmts
            .iter()
            .filter(|s| matches!(s, NilStmt::Return(_)))
            .collect();
        let ret_b: Vec<_> = b
            .stmts
            .iter()
            .filter(|s| matches!(s, NilStmt::Return(_)))
            .collect();
        if ret_a.len() == ret_b.len() && ret_a == ret_b {
            ProverResult::Equivalent
        } else {
            ProverResult::Unknown
        }
    }
}

impl Default for SMTEquivalenceProver {
    fn default() -> Self {
        Self::new(5000)
    }
}

// ── SemanticEquivalenceChecker ────────────────────────────────────────────────

/// Top-level semantic equivalence checker.
pub struct SemanticEquivalenceChecker {
    pub prover: SMTEquivalenceProver,
    pub db: EquivalenceDb,
}

impl SemanticEquivalenceChecker {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            prover: SMTEquivalenceProver::default(),
            db: EquivalenceDb::new(),
        }
    }

    /// Add a normalized function and cluster it into an equivalence class.
    pub fn add_function(&mut self, nil: &NormalizedIL) {
        let hash = FunctionHash::compute(nil);
        // Find an existing class with the same semantic hash.
        let existing_id = self
            .db
            .classes
            .iter()
            .find(|c| c.hash.semantic_hash == hash.semantic_hash)
            .map(|c| c.id);

        if let Some(cls_id) = existing_id {
            if let Some(cls) = self.db.classes.iter_mut().find(|c| c.id == cls_id) {
                cls.add_member(nil.address);
                self.db.addr_to_class.insert(nil.address, cls_id);
            }
        } else {
            let cls = self.db.new_class(hash);
            let id = cls.id;
            cls.add_member(nil.address);
            self.db.addr_to_class.insert(nil.address, id);
        }
    }

    /// Compare two functions for semantic equivalence.
    #[must_use] 
    pub const fn compare(&self, a: &NormalizedIL, b: &NormalizedIL) -> ProverResult {
        self.prover.prove(a, b)
    }

    /// Return all equivalence classes with more than one member.
    #[must_use] 
    pub fn equivalent_pairs(&self) -> Vec<&EquivalenceClass> {
        self.db.classes.iter().filter(|c| c.size() > 1).collect()
    }
}

impl Default for SemanticEquivalenceChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_nil(name: &str, addr: u64) -> NormalizedIL {
        let mut n = NormalizedIL::new(name, addr);
        n.stmts.push(NilStmt::Assign { dst: 0, src: 1 });
        n.stmts.push(NilStmt::Return(Some(0)));
        n.var_count = 2;
        n.compute_hash();
        n
    }

    // ── NilStmt / NilExpr ─────────────────────────────────────────────────────

    #[test]
    fn test_nil_stmt_nop() {
        let s = NilStmt::Nop;
        assert!(matches!(s, NilStmt::Nop));
    }

    #[test]
    fn test_nil_expr_const() {
        let e = NilExpr::Const(42);
        assert_eq!(e, NilExpr::Const(42));
    }

    // ── NormalizedIL ──────────────────────────────────────────────────────────

    #[test]
    fn test_normalized_il_hash_deterministic() {
        let mut a = make_nil("foo", 0x1000);
        a.compute_hash();
        let h1 = a.normal_hash;
        a.compute_hash();
        let h2 = a.normal_hash;
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_normalized_il_equivalent() {
        let a = make_nil("foo", 0x1000);
        let b = make_nil("foo", 0x2000); // same structure, different address
        assert!(a.is_equivalent_to(&b));
    }

    #[test]
    fn test_normalized_il_not_equivalent() {
        let a = make_nil("foo", 0x1000);
        let mut b = NormalizedIL::new("bar", 0x2000);
        b.stmts.push(NilStmt::Return(None));
        b.compute_hash();
        assert!(!a.is_equivalent_to(&b));
    }

    // ── FunctionHash ──────────────────────────────────────────────────────────

    #[test]
    fn test_function_hash_same_il() {
        let a = make_nil("f", 0x1000);
        let b = make_nil("f", 0x2000);
        let ha = FunctionHash::compute(&a);
        let hb = FunctionHash::compute(&b);
        assert_eq!(ha.semantic_hash, hb.semantic_hash);
    }

    #[test]
    fn test_function_hash_likely_equivalent() {
        let a = make_nil("f", 0x1000);
        let ha = FunctionHash::compute(&a);
        let hb = ha.clone();
        assert!(ha.likely_equivalent(&hb) >= 0.9);
    }

    #[test]
    fn test_function_hash_different_il() {
        let a = make_nil("f", 0x1000);
        let mut b = NormalizedIL::new("g", 0x2000);
        b.stmts.push(NilStmt::Nop);
        b.compute_hash();
        let ha = FunctionHash::compute(&a);
        let hb = FunctionHash::compute(&b);
        assert_ne!(ha.semantic_hash, hb.semantic_hash);
    }

    // ── EquivalenceClass ──────────────────────────────────────────────────────

    #[test]
    fn test_equivalence_class_add_member() {
        let nil = make_nil("foo", 0);
        let hash = FunctionHash::compute(&nil);
        let mut cls = EquivalenceClass::new(1, hash);
        cls.add_member(0x1000);
        cls.add_member(0x2000);
        assert_eq!(cls.size(), 2);
        assert!(cls.contains(0x1000));
    }

    // ── EquivalenceDb ─────────────────────────────────────────────────────────

    #[test]
    fn test_db_new_class() {
        let mut db = EquivalenceDb::new();
        let nil = make_nil("f", 0x1000);
        let hash = FunctionHash::compute(&nil);
        let cls = db.new_class(hash);
        cls.add_member(0x1000);
        assert_eq!(db.class_count(), 1);
    }

    #[test]
    fn test_db_class_of() {
        let mut db = EquivalenceDb::new();
        let nil = make_nil("f", 0x1000);
        let hash = FunctionHash::compute(&nil);
        let cls = db.new_class(hash);
        let id = cls.id;
        cls.add_member(0x1000);
        db.addr_to_class.insert(0x1000, id);
        assert!(db.class_of(0x1000).is_some());
    }

    #[test]
    fn test_db_merge_classes() {
        let mut db = EquivalenceDb::new();
        let nil = make_nil("f", 0);
        let hash = FunctionHash::compute(&nil);
        let cls_a = db.new_class(hash.clone());
        let id_a = cls_a.id;
        cls_a.add_member(0x1000);
        let cls_b = db.new_class(hash);
        let id_b = cls_b.id;
        cls_b.add_member(0x2000);
        db.merge_classes(id_a, id_b);
        assert_eq!(db.class_count(), 1);
    }

    // ── SMTEquivalenceProver ──────────────────────────────────────────────────

    #[test]
    fn test_prover_both_empty_equivalent() {
        let p = SMTEquivalenceProver::new(1000);
        let a = NormalizedIL::new("f", 0);
        let b = NormalizedIL::new("g", 0);
        assert_eq!(p.prove(&a, &b), ProverResult::Equivalent);
    }

    #[test]
    fn test_prover_same_hash_equivalent() {
        let p = SMTEquivalenceProver::default();
        let a = make_nil("f", 0x1000);
        let b = make_nil("g", 0x2000);
        assert_eq!(p.prove(&a, &b), ProverResult::Equivalent);
    }

    #[test]
    fn test_prover_different_stmt_count() {
        let p = SMTEquivalenceProver::default();
        let a = make_nil("f", 0x1000);
        let mut b = NormalizedIL::new("g", 0x2000);
        b.stmts.push(NilStmt::Nop);
        b.compute_hash();
        assert_eq!(p.prove(&a, &b), ProverResult::NotEquivalent);
    }

    #[test]
    fn test_prover_result_display() {
        assert_eq!(ProverResult::Equivalent.to_string(), "equivalent");
        assert_eq!(ProverResult::NotEquivalent.to_string(), "not_equivalent");
        assert_eq!(ProverResult::Unknown.to_string(), "unknown");
        assert_eq!(ProverResult::Timeout.to_string(), "timeout");
    }

    // ── SemanticEquivalenceChecker ─────────────────────────────────────────────

    #[test]
    fn test_checker_cluster_identical() {
        let mut checker = SemanticEquivalenceChecker::new();
        let a = make_nil("f", 0x1000);
        let b = make_nil("g", 0x2000);
        checker.add_function(&a);
        checker.add_function(&b);
        let pairs = checker.equivalent_pairs();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].size(), 2);
    }

    #[test]
    fn test_checker_no_pairs_different() {
        let mut checker = SemanticEquivalenceChecker::new();
        let a = make_nil("f", 0x1000);
        let mut b = NormalizedIL::new("g", 0x2000);
        b.stmts.push(NilStmt::Return(None));
        b.compute_hash();
        checker.add_function(&a);
        checker.add_function(&b);
        let pairs = checker.equivalent_pairs();
        assert!(pairs.is_empty());
    }

    #[test]
    fn test_checker_compare() {
        let checker = SemanticEquivalenceChecker::new();
        let a = make_nil("f", 0x1000);
        let b = make_nil("g", 0x2000);
        let result = checker.compare(&a, &b);
        assert_eq!(result, ProverResult::Equivalent);
    }
}
