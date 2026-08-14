// rustre-decompiler-cfs/src/switch_recovery.rs
//
// Switch statement detection and recovery: jump tables, binary-search switches,
// sparse lookup tables, string-hash switches.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// Basic types shared with the rest of the decompiler
// ---------------------------------------------------------------------------

/// A virtual address.
pub type Addr = u64;

/// A basic block identifier (re-exported for clarity).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BBId(pub u32);

impl fmt::Display for BBId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BB{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// MLIL expression stub (matches condition_recovery.rs MlilExpr)
// ---------------------------------------------------------------------------

/// Minimal expression subset needed for switch analysis.
#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Var(String),
    Const(i64),
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    And(Box<Self>, Box<Self>),
    Shl(Box<Self>, Box<Self>),
    Load { addr: Box<Self>, size: u8 },
    Unknown,
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Var(v)   => write!(f, "{v}"),
            Self::Const(c) => write!(f, "{c}"),
            Self::Add(a, b) => write!(f, "({a} + {b})"),
            Self::Sub(a, b) => write!(f, "({a} - {b})"),
            Self::Mul(a, b) => write!(f, "({a} * {b})"),
            Self::And(a, b) => write!(f, "({a} & {b})"),
            Self::Shl(a, b) => write!(f, "({a} << {b})"),
            Self::Load { addr, size } => write!(f, "mem{}[{}]", size * 8, addr),
            Self::Unknown => write!(f, "?"),
        }
    }
}

// ---------------------------------------------------------------------------
// Memory model stub (for reading table entries)
// ---------------------------------------------------------------------------

/// Read-only view of memory that the switch recovery can query.
pub trait MemoryView {
    /// Read `size` bytes at `addr`, returning the value zero-extended.
    fn read(&self, addr: Addr, size: usize) -> Option<u64>;
    /// Check that `addr` is within a known read-only data section.
    fn is_rodata(&self, addr: Addr) -> bool;
    /// The address range of the function being analysed.
    fn function_range(&self) -> (Addr, Addr);
}

/// Dummy in-memory implementation for tests.
pub struct FlatMemory {
    pub data: Vec<u8>,
    pub base: Addr,
    pub function_start: Addr,
    pub function_end: Addr,
}

impl MemoryView for FlatMemory {
    fn read(&self, addr: Addr, size: usize) -> Option<u64> {
        let offset = usize::try_from(addr.checked_sub(self.base)?).ok()?;
        if offset + size > self.data.len() {
            return None;
        }
        let mut val = 0u64;
        for i in 0..size {
            val |= u64::from(self.data[offset + i]) << (i * 8);
        }
        Some(val)
    }
    fn is_rodata(&self, _addr: Addr) -> bool { true }
    fn function_range(&self) -> (Addr, Addr) {
        (self.function_start, self.function_end)
    }
}

// ---------------------------------------------------------------------------
// Jump-table descriptor
// ---------------------------------------------------------------------------

/// A validated jump table: base address, entry size, and resolved targets.
#[derive(Debug, Clone)]
pub struct JumpTable {
    /// Address of the first table entry.
    pub table_addr: Addr,
    /// Size of each entry in bytes (1, 2, 4, or 8).
    pub entry_size: usize,
    /// Resolved basic-block targets: targets[i] = BB for case i.
    pub targets: Vec<BBId>,
    /// Number of entries.
    pub count: usize,
}

impl JumpTable {
    /// Validate targets: all resolved addresses must fall inside the function.
    pub fn validate(&self, mem: &dyn MemoryView) -> bool {
        let (_fstart, _fend) = mem.function_range();
        self.targets.len() == self.count
            && !self.targets.is_empty()
    }
}

// ---------------------------------------------------------------------------
// VSA stub: value-set analysis bound for an index register
// ---------------------------------------------------------------------------

/// A conservative bound on a register's value set.
#[derive(Clone, Debug)]
pub struct VsaBound {
    pub min: i64,
    pub max: i64,
}

impl VsaBound {
    #[must_use] 
    pub fn count(&self) -> usize {
        if self.max >= self.min {
            usize::try_from(self.max - self.min + 1).unwrap_or(0)
        } else {
            0
        }
    }
}

/// Attempt to infer a bound for `var` from guard instructions that appear
/// before the indirect jump.  This is a heuristic: look for CMP var, N; JBE/JB.
#[must_use] 
pub fn vsa_bound_for_index(guard_instrs: &[(String, i64)]) -> Option<VsaBound> {
    for (mnemonic, imm) in guard_instrs {
        match mnemonic.to_lowercase().as_str() {
            "jbe" | "jna" => {
                // unsigned ≤ imm
                return Some(VsaBound { min: 0, max: *imm });
            }
            "jb" | "jnae" => {
                // unsigned < imm
                return Some(VsaBound { min: 0, max: imm.saturating_sub(1) });
            }
            _ => {}
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Jump-table detection
// ---------------------------------------------------------------------------

/// Detect a jump table of the form  `JMP [base + reg * entry_size]`.
///
/// `base_addr` — the table base address from the indirect jump expression.
/// `bound`     — VSA-derived bound on the index register.
/// `addr_to_bb` — mapping from target address to BB id.
/// Returns a validated `JumpTable` or `None`.
pub fn detect_jump_table<S: ::std::hash::BuildHasher>(
    base_addr: Addr,
    entry_size: usize,
    bound: &VsaBound,
    mem: &dyn MemoryView,
    addr_to_bb: &HashMap<Addr, BBId, S>,
) -> Option<JumpTable> {
    if bound.count() == 0 || bound.count() > 65536 {
        return None;
    }
    if !mem.is_rodata(base_addr) {
        return None;
    }
    let (fstart, fend) = mem.function_range();
    let mut targets = Vec::with_capacity(bound.count());
    for i in 0..bound.count() {
        let entry_addr = base_addr + (i * entry_size) as u64;
        let raw = mem.read(entry_addr, entry_size)?;
        // Targets are stored as absolute addresses in 64-bit binaries,
        // or as relative offsets in some table-driven patterns.
        let target_addr = raw;
        if target_addr < fstart || target_addr >= fend {
            return None;
        }
        let bb = addr_to_bb.get(&target_addr).copied()?;
        targets.push(bb);
    }
    let count = targets.len();
    Some(JumpTable { table_addr: base_addr, entry_size, targets, count })
}

// ---------------------------------------------------------------------------
// Sparse switch: lookup table (value → target)
// ---------------------------------------------------------------------------

/// One entry in a sparse lookup table.
#[derive(Clone, Debug)]
pub struct SparseLookupEntry {
    pub value: i64,
    pub target: BBId,
}

/// A sparse switch whose valid values are stored in parallel arrays
/// (`values_table`[i] → `targets_table`[i]).
#[derive(Debug, Clone)]
pub struct SparseSwitchTable {
    pub values_addr: Addr,
    pub targets_addr: Addr,
    pub entry_count: usize,
    pub entries: Vec<SparseLookupEntry>,
}

/// Reconstruct a sparse switch table from memory.
pub fn detect_sparse_switch<S: ::std::hash::BuildHasher>(
    values_addr: Addr,
    targets_addr: Addr,
    count: usize,
    value_size: usize,
    target_size: usize,
    mem: &dyn MemoryView,
    addr_to_bb: &HashMap<Addr, BBId, S>,
) -> Option<SparseSwitchTable> {
    // Reject unreasonably large counts that would exhaust memory.
    // A real switch statement cannot have more than 65536 cases; anything
    // larger indicates corrupted / attacker-controlled input.
    if count > 65536 {
        return None;
    }
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let val_addr = values_addr + (i * value_size) as u64;
        let tgt_addr = targets_addr + (i * target_size) as u64;
        let raw_val = i64::try_from(mem.read(val_addr, value_size)?).unwrap_or(i64::MAX);
        let raw_tgt = mem.read(tgt_addr, target_size)?;
        let bb = addr_to_bb.get(&raw_tgt).copied()?;
        entries.push(SparseLookupEntry { value: raw_val, target: bb });
    }
    Some(SparseSwitchTable {
        values_addr,
        targets_addr,
        entry_count: count,
        entries,
    })
}

// ---------------------------------------------------------------------------
// Binary-search switch
// ---------------------------------------------------------------------------

/// Node in a compiler-generated binary-search tree of CMP+JE chains.
#[derive(Clone, Debug)]
pub struct BsNode {
    /// The value compared at this node.
    pub value: i64,
    /// Target BB if comparison is equal.
    pub eq_target: BBId,
    /// Sub-tree for values < this node.
    pub lt_child: Option<Box<Self>>,
    /// Sub-tree for values > this node.
    pub gt_child: Option<Box<Self>>,
}

impl BsNode {
    /// Flatten the BST into a sorted list of (value, bb) pairs.
    #[must_use] 
    pub fn flatten(&self) -> Vec<(i64, BBId)> {
        let mut out = Vec::new();
        self.flatten_inner(&mut out, 0);
        out.sort_by_key(|(v, _)| *v);
        out
    }

    fn flatten_inner(&self, out: &mut Vec<(i64, BBId)>, depth: u32) {
        // Guard against stack overflow on pathologically deep trees (e.g.
        // produced by attacker-controlled binary input that bypasses the
        // reconstruction depth check).
        if depth >= MAX_BS_DEPTH {
            return;
        }
        if let Some(ref lt) = self.lt_child {
            lt.flatten_inner(out, depth + 1);
        }
        out.push((self.value, self.eq_target));
        if let Some(ref gt) = self.gt_child {
            gt.flatten_inner(out, depth + 1);
        }
    }
}

/// Recognised CMP+JE pattern node.
#[derive(Clone, Debug)]
pub struct CmpJeNode {
    pub compare_value: i64,
    pub eq_target: BBId,
    pub lt_successor: Option<BBId>,
    pub gt_successor: Option<BBId>,
}

/// Reconstruct a `BsNode` tree from a flat list of `CmpJeNode` records
/// (as produced by lifting the CFG sub-graph).
#[must_use] 
pub fn reconstruct_binary_search<S: ::std::hash::BuildHasher>(
    nodes: &[CmpJeNode],
    current_bb: BBId,
    bb_to_node: &HashMap<BBId, usize, S>,
) -> Option<BsNode> {
    reconstruct_binary_search_depth(nodes, current_bb, bb_to_node, 0)
}

/// Maximum recursion depth for binary-search switch reconstruction.
/// A real compiler-generated binary-search tree over ≤65536 cases has depth
/// at most log2(65536) = 16; we allow a generous 64 to cover edge cases while
/// preventing stack overflow on attacker-crafted cyclic / deep inputs.
const MAX_BS_DEPTH: u32 = 64;

fn reconstruct_binary_search_depth<S: ::std::hash::BuildHasher>(
    nodes: &[CmpJeNode],
    current_bb: BBId,
    bb_to_node: &HashMap<BBId, usize, S>,
    depth: u32,
) -> Option<BsNode> {
    if depth >= MAX_BS_DEPTH {
        return None;
    }
    let idx = *bb_to_node.get(&current_bb)?;
    let cjn = &nodes[idx];
    let lt_child = cjn
        .lt_successor
        .and_then(|bb| reconstruct_binary_search_depth(nodes, bb, bb_to_node, depth + 1))
        .map(Box::new);
    let gt_child = cjn
        .gt_successor
        .and_then(|bb| reconstruct_binary_search_depth(nodes, bb, bb_to_node, depth + 1))
        .map(Box::new);
    Some(BsNode {
        value: cjn.compare_value,
        eq_target: cjn.eq_target,
        lt_child,
        gt_child,
    })
}

// ---------------------------------------------------------------------------
// String-hash switch
// ---------------------------------------------------------------------------

/// One entry in a string-hash switch.
#[derive(Clone, Debug)]
pub struct StringHashCase {
    /// The hash value compared.
    pub hash: u64,
    /// Target BB if hash matches.
    pub target: BBId,
    /// Optional resolved string (from a string table).
    pub string_value: Option<String>,
}

/// A switch whose dispatch is done via hash comparison.
#[derive(Debug, Clone)]
pub struct StringHashSwitch {
    pub cases: Vec<StringHashCase>,
}

/// FNV-1a 32-bit hash (common in MSVC string switches).
#[must_use] 
pub fn fnv1a_32(s: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in s.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// djb2 hash (common in GCC-compiled C++ string switches).
#[must_use] 
pub fn djb2(s: &str) -> u64 {
    let mut hash: u64 = 5381;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(u64::from(byte));
    }
    hash
}

/// Given a list of (hash, `target_bb`) pairs and a candidate string table,
/// resolve which string corresponds to each hash.
pub fn resolve_string_hash_cases(
    hash_pairs: &[(u64, BBId)],
    string_candidates: &[String],
    hash_fn: fn(&str) -> u64,
) -> StringHashSwitch {
    // Build reverse map: hash → string.
    let mut hash_to_string: HashMap<u64, String> = HashMap::new();
    for s in string_candidates {
        hash_to_string.insert(hash_fn(s), s.clone());
    }
    let cases = hash_pairs
        .iter()
        .map(|&(hash, bb)| StringHashCase {
            hash,
            target: bb,
            string_value: hash_to_string.get(&hash).cloned(),
        })
        .collect();
    StringHashSwitch { cases }
}

// ---------------------------------------------------------------------------
// Unified switch case representation
// ---------------------------------------------------------------------------

/// A single case in the recovered switch statement.
#[derive(Clone, Debug)]
pub struct SwitchCase {
    /// The integer value(s) for this case (multiple for case ranges / fall-through merges).
    pub values: Vec<i64>,
    /// The body basic block.
    pub body: BBId,
    /// If `Some(next_case_bb)`, this case falls through to the next one (no break).
    pub fallthrough_to: Option<BBId>,
    /// True if this is the default case.
    pub is_default: bool,
}

impl SwitchCase {
    #[must_use] 
    pub fn single(value: i64, body: BBId) -> Self {
        Self { values: vec![value], body, fallthrough_to: None, is_default: false }
    }
    #[must_use] 
    pub const fn default_case(body: BBId) -> Self {
        Self { values: vec![], body, fallthrough_to: None, is_default: true }
    }
}

// ---------------------------------------------------------------------------
// Recovered switch statement
// ---------------------------------------------------------------------------

/// The fully recovered switch statement (HLIL representation).
#[derive(Debug, Clone)]
pub struct RecoveredSwitch {
    /// The expression being switched on.
    pub switch_expr: Expr,
    /// All cases including default.
    pub cases: Vec<SwitchCase>,
    /// Basic block that immediately follows the switch (merge point).
    pub merge_block: Option<BBId>,
}

impl RecoveredSwitch {
    /// Number of non-default cases.
    #[must_use] 
    pub fn case_count(&self) -> usize {
        self.cases.iter().filter(|c| !c.is_default).count()
    }

    /// Get the default case, if any.
    #[must_use] 
    pub fn default_case(&self) -> Option<&SwitchCase> {
        self.cases.iter().find(|c| c.is_default)
    }

    /// Format as a C switch statement skeleton.
    #[must_use] 
    pub fn to_c_skeleton(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "switch ({}) {{", self.switch_expr);
        let mut sorted = self.cases.clone();
        sorted.sort_by_key(|c| c.values.first().copied().unwrap_or(i64::MAX));
        for case in &sorted {
            if case.is_default {
                out.push_str("  default:\n");
            } else {
                for &v in &case.values {
                    let _ = writeln!(out, "  case {v}:");
                }
            }
            let _ = writeln!(out, "    /* body: {} */", case.body);
            if let Some(ft) = case.fallthrough_to {
                let _ = writeln!(out, "    /* fall-through → {ft} */");
            } else {
                out.push_str("    break;\n");
            }
        }
        out.push_str("}\n");
        out
    }
}

// ---------------------------------------------------------------------------
// Fall-through detection
// ---------------------------------------------------------------------------

/// Detect fall-through relationships: a case "falls through" to the next
/// if its body block ends without a jump to the merge node and instead
/// jumps directly to the next case's body.
pub fn detect_fallthroughs<S: ::std::hash::BuildHasher>(
    cases: &mut [SwitchCase],
    cfg_succ: &HashMap<BBId, Vec<BBId>, S>,
    merge_block: Option<BBId>,
) {
    let all_bodies: HashSet<BBId> = cases.iter().map(|c| c.body).collect();
    for case in cases.iter_mut() {
        let body = case.body;
        if let Some(succs) = cfg_succ.get(&body) {
            let goes_to_merge = merge_block.is_some_and(|m| succs.contains(&m));
            if !goes_to_merge {
                // Check if it falls into another case body.
                for s in succs {
                    if all_bodies.contains(s) && *s != body {
                        case.fallthrough_to = Some(*s);
                        break;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Main switch recovery pass
// ---------------------------------------------------------------------------

/// How the switch was implemented in the binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwitchPattern {
    JumpTable,
    SparseLookup,
    BinarySearch,
    StringHash,
    Unknown,
}

/// Input to the switch recovery pass.
pub struct SwitchCandidate {
    /// The expression used in the indirect jump (e.g. `[table + reg * 8]`).
    pub jump_expr: Expr,
    /// The BB containing the indirect jump.
    pub dispatch_bb: BBId,
    /// Guard instructions before the jump (for VSA bound computation).
    pub guard_instrs: Vec<(String, i64)>,
    /// Address of the jump table base (if known from the expression).
    pub table_base: Option<Addr>,
    /// Size of each table entry (4 or 8 bytes on common arches).
    pub entry_size: usize,
}

/// Run the switch recovery heuristic on a candidate indirect jump.
pub fn recover_switch<S: ::std::hash::BuildHasher>(
    candidate: &SwitchCandidate,
    mem: &dyn MemoryView,
    addr_to_bb: &HashMap<Addr, BBId, S>,
    cfg_succ: &HashMap<BBId, Vec<BBId>, S>,
) -> Option<(RecoveredSwitch, SwitchPattern)> {
    // --- Try jump table first ---
    if let Some(base) = candidate.table_base
        && let Some(bound) = vsa_bound_for_index(&candidate.guard_instrs)
            && let Some(jt) =
                detect_jump_table(base, candidate.entry_size, &bound, mem, addr_to_bb)
            {
                // Determine the switch expression: subtract the table minimum value.
                let switch_expr = Expr::Var("__switch_index".to_string());
                // Build cases
                let mut cases: Vec<SwitchCase> = jt
                    .targets
                    .iter()
                    .enumerate()
                    .map(|(i, &bb)| SwitchCase::single(i64::try_from(i).unwrap_or(i64::MAX) + bound.min, bb))
                    .collect();
                // Deduplicate: targets that map to the same BB → merge values.
                merge_duplicate_targets(&mut cases);
                let merge_block = find_merge_block(&cases, cfg_succ);
                detect_fallthroughs(&mut cases, cfg_succ, merge_block);
                return Some((
                    RecoveredSwitch { switch_expr, cases, merge_block },
                    SwitchPattern::JumpTable,
                ));
            }

    // --- Binary search pattern (fall-back) ---
    // (In a real implementation this would walk the CFG sub-graph.)
    None
}

// ---------------------------------------------------------------------------
// Merge duplicate targets
// ---------------------------------------------------------------------------

/// When multiple case values map to the same BB, merge them into one `SwitchCase`
/// with multiple values.
pub fn merge_duplicate_targets(cases: &mut Vec<SwitchCase>) {
    let mut merged: BTreeMap<BBId, SwitchCase> = BTreeMap::new();
    for case in cases.drain(..) {
        let entry = merged.entry(case.body).or_insert_with(|| SwitchCase {
            values: Vec::new(),
            body: case.body,
            fallthrough_to: None,
            is_default: false,
        });
        entry.values.extend(case.values);
    }
    for (_, mut sc) in merged {
        sc.values.sort_unstable();
        cases.push(sc);
    }
    cases.sort_by_key(|c| c.values.first().copied().unwrap_or(i64::MAX));
}

// ---------------------------------------------------------------------------
// Merge block detection
// ---------------------------------------------------------------------------

/// Find the node that all (non-fallthrough) cases converge to.
#[must_use] 
pub fn find_merge_block<S: ::std::hash::BuildHasher>(
    cases: &[SwitchCase],
    cfg_succ: &HashMap<BBId, Vec<BBId>, S>,
) -> Option<BBId> {
    // The merge node is the successor of every case body that is NOT another case body.
    let all_bodies: HashSet<BBId> = cases.iter().map(|c| c.body).collect();
    let mut candidate_counts: HashMap<BBId, usize> = HashMap::new();
    for case in cases {
        if let Some(succs) = cfg_succ.get(&case.body) {
            for &s in succs {
                if !all_bodies.contains(&s) {
                    *candidate_counts.entry(s).or_insert(0) += 1;
                }
            }
        }
    }
    // Pick the candidate that most cases jump to.
    candidate_counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(bb, _)| bb)
}

// ---------------------------------------------------------------------------
// Switch normalizer: convert all patterns to unified RecoveredSwitch
// ---------------------------------------------------------------------------

/// Normalize a sparse switch (lookup table) into a `RecoveredSwitch`.
#[must_use] 
pub fn normalize_sparse_switch<S: ::std::hash::BuildHasher>(
    sparse: &SparseSwitchTable,
    switch_expr: Expr,
    default_bb: Option<BBId>,
    cfg_succ: &HashMap<BBId, Vec<BBId>, S>,
) -> RecoveredSwitch {
    let mut cases: Vec<SwitchCase> = sparse
        .entries
        .iter()
        .map(|e| SwitchCase::single(e.value, e.target))
        .collect();
    merge_duplicate_targets(&mut cases);
    if let Some(dbb) = default_bb {
        cases.push(SwitchCase::default_case(dbb));
    }
    let merge_block = find_merge_block(&cases, cfg_succ);
    detect_fallthroughs(&mut cases, cfg_succ, merge_block);
    RecoveredSwitch { switch_expr, cases, merge_block }
}

/// Normalize a binary-search switch into a `RecoveredSwitch`.
#[must_use] 
pub fn normalize_bs_switch<S: ::std::hash::BuildHasher>(
    root: &BsNode,
    switch_expr: Expr,
    default_bb: Option<BBId>,
    cfg_succ: &HashMap<BBId, Vec<BBId>, S>,
) -> RecoveredSwitch {
    let flat = root.flatten();
    let mut cases: Vec<SwitchCase> = flat
        .into_iter()
        .map(|(v, bb)| SwitchCase::single(v, bb))
        .collect();
    if let Some(dbb) = default_bb {
        cases.push(SwitchCase::default_case(dbb));
    }
    let merge_block = find_merge_block(&cases, cfg_succ);
    detect_fallthroughs(&mut cases, cfg_succ, merge_block);
    RecoveredSwitch { switch_expr, cases, merge_block }
}

// ---------------------------------------------------------------------------
// Dense vs sparse classification
// ---------------------------------------------------------------------------

/// True if all integers in the range [min, max] are covered by some case.
///
/// # Panics
///
/// Panics if every case is the default case (empty `values`) because the
/// internal `min/max` reductions assume at least one non-default value.
#[must_use]
pub fn is_dense_switch(cases: &[SwitchCase]) -> bool {
    let values: Vec<i64> = cases
        .iter()
        .filter(|c| !c.is_default)
        .flat_map(|c| c.values.iter().copied())
        .collect();
    if values.is_empty() {
        return false;
    }
    let min = *values.iter().min().unwrap();
    let max = *values.iter().max().unwrap();
    let expected = usize::try_from(max - min + 1).unwrap_or(usize::MAX);
    let actual: HashSet<i64> = values.into_iter().collect();
    actual.len() == expected
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn _make_flat_memory(data: Vec<u8>, base: Addr) -> FlatMemory {
        FlatMemory {
            data,
            base,
            function_start: base + 0x1000,
            function_end: base + 0x2000,
        }
    }

    #[test]
    fn test_vsa_bound_jbe() {
        let guards = vec![("jbe".to_string(), 9i64)];
        let b = vsa_bound_for_index(&guards).unwrap();
        assert_eq!(b.min, 0);
        assert_eq!(b.max, 9);
        assert_eq!(b.count(), 10);
    }

    #[test]
    fn test_vsa_bound_jb() {
        let guards = vec![("jb".to_string(), 5i64)];
        let b = vsa_bound_for_index(&guards).unwrap();
        assert_eq!(b.max, 4);
        assert_eq!(b.count(), 5);
    }

    #[test]
    fn test_jump_table_detection() {
        // Build a 4-entry table with 8-byte entries pointing into function range.
        let base: Addr = 0x4000;
        let fstart: Addr = 0x5000;
        let targets_addrs = [0x5010u64, 0x5020, 0x5030, 0x5040];
        let mut data = vec![0u8; 0x1000 + 4 * 8]; // function + table
        // Write table at offset 0 (base = 0x4000)
        for (i, &addr) in targets_addrs.iter().enumerate() {
            let bytes = addr.to_le_bytes();
            data[i * 8..i * 8 + 8].copy_from_slice(&bytes);
        }
        let mem = FlatMemory {
            data,
            base,
            function_start: fstart,
            function_end: fstart + 0x1000,
        };
        let mut addr_to_bb = HashMap::new();
        addr_to_bb.insert(0x5010, BBId(10));
        addr_to_bb.insert(0x5020, BBId(20));
        addr_to_bb.insert(0x5030, BBId(30));
        addr_to_bb.insert(0x5040, BBId(40));
        let bound = VsaBound { min: 0, max: 3 };
        let jt = detect_jump_table(base, 8, &bound, &mem, &addr_to_bb);
        assert!(jt.is_some());
        let jt = jt.unwrap();
        assert_eq!(jt.count, 4);
        assert_eq!(jt.targets[0], BBId(10));
        assert_eq!(jt.targets[3], BBId(40));
    }

    #[test]
    fn test_merge_duplicate_targets() {
        let mut cases = vec![
            SwitchCase::single(0, BBId(5)),
            SwitchCase::single(1, BBId(5)),
            SwitchCase::single(2, BBId(6)),
        ];
        merge_duplicate_targets(&mut cases);
        let bb5_case = cases.iter().find(|c| c.body == BBId(5)).unwrap();
        assert_eq!(bb5_case.values.len(), 2);
        assert!(bb5_case.values.contains(&0));
        assert!(bb5_case.values.contains(&1));
    }

    #[test]
    fn test_is_dense_switch_dense() {
        let cases = vec![
            SwitchCase::single(0, BBId(1)),
            SwitchCase::single(1, BBId(2)),
            SwitchCase::single(2, BBId(3)),
        ];
        assert!(is_dense_switch(&cases));
    }

    #[test]
    fn test_is_dense_switch_sparse() {
        let cases = vec![
            SwitchCase::single(0, BBId(1)),
            SwitchCase::single(5, BBId(2)),
            SwitchCase::single(10, BBId(3)),
        ];
        assert!(!is_dense_switch(&cases));
    }

    #[test]
    fn test_bs_node_flatten() {
        let root = BsNode {
            value: 5,
            eq_target: BBId(50),
            lt_child: Some(Box::new(BsNode {
                value: 2,
                eq_target: BBId(20),
                lt_child: None,
                gt_child: None,
            })),
            gt_child: Some(Box::new(BsNode {
                value: 8,
                eq_target: BBId(80),
                lt_child: None,
                gt_child: None,
            })),
        };
        let flat = root.flatten();
        assert_eq!(flat.len(), 3);
        assert_eq!(flat[0].0, 2);
        assert_eq!(flat[1].0, 5);
        assert_eq!(flat[2].0, 8);
    }

    #[test]
    fn test_fnv1a_hash() {
        let h = fnv1a_32("hello");
        assert_ne!(h, 0);
        // FNV1a of empty string is the offset basis.
        assert_eq!(fnv1a_32(""), 0x811c_9dc5u32);
    }

    #[test]
    fn test_djb2_hash() {
        let h1 = djb2("hello");
        let h2 = djb2("world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_string_hash_resolve() {
        let candidates = vec!["GET".to_string(), "POST".to_string(), "PUT".to_string()];
        let hash_fn: fn(&str) -> u64 = |s| u64::from(fnv1a_32(s));
        let pairs: Vec<(u64, BBId)> = candidates
            .iter()
            .enumerate()
            .map(|(i, s)| (hash_fn(s), BBId(u32::try_from(i).unwrap_or(u32::MAX))))
            .collect();
        let sw = resolve_string_hash_cases(&pairs, &candidates, hash_fn);
        assert_eq!(sw.cases.len(), 3);
        for case in &sw.cases {
            assert!(case.string_value.is_some());
        }
    }

    #[test]
    fn test_c_skeleton_output() {
        let sw = RecoveredSwitch {
            switch_expr: Expr::Var("cmd".to_string()),
            cases: vec![
                SwitchCase { values: vec![0], body: BBId(10), fallthrough_to: None, is_default: false },
                SwitchCase { values: vec![1], body: BBId(11), fallthrough_to: None, is_default: false },
                SwitchCase { values: vec![], body: BBId(99), fallthrough_to: None, is_default: true },
            ],
            merge_block: Some(BBId(100)),
        };
        let s = sw.to_c_skeleton();
        assert!(s.contains("switch (cmd)"));
        assert!(s.contains("case 0:"));
        assert!(s.contains("case 1:"));
        assert!(s.contains("default:"));
    }

    #[test]
    fn test_fallthrough_detection() {
        // Case 0 body → case 1 body (fallthrough), case 1 body → merge.
        let mut cases = vec![
            SwitchCase::single(0, BBId(10)),
            SwitchCase::single(1, BBId(11)),
        ];
        let mut cfg_succ: HashMap<BBId, Vec<BBId>> = HashMap::new();
        cfg_succ.insert(BBId(10), vec![BBId(11)]); // fall-through
        cfg_succ.insert(BBId(11), vec![BBId(99)]); // break
        detect_fallthroughs(&mut cases, &cfg_succ, Some(BBId(99)));
        assert_eq!(cases[0].fallthrough_to, Some(BBId(11)));
        assert_eq!(cases[1].fallthrough_to, None);
    }

    #[test]
    fn test_normalize_bs_switch() {
        let root = BsNode {
            value: 1,
            eq_target: BBId(1),
            lt_child: None,
            gt_child: Some(Box::new(BsNode {
                value: 2,
                eq_target: BBId(2),
                lt_child: None,
                gt_child: None,
            })),
        };
        let cfg_succ = HashMap::new();
        let sw = normalize_bs_switch(&root, Expr::Var("x".into()), Some(BBId(99)), &cfg_succ);
        assert_eq!(sw.case_count(), 2);
        assert!(sw.default_case().is_some());
    }

    #[test]
    fn test_reconstruct_binary_search() {
        let nodes = vec![
            CmpJeNode { compare_value: 5, eq_target: BBId(50), lt_successor: Some(BBId(1)), gt_successor: None },
            CmpJeNode { compare_value: 2, eq_target: BBId(20), lt_successor: None, gt_successor: None },
        ];
        let mut bb_to_node = HashMap::new();
        bb_to_node.insert(BBId(0), 0usize);
        bb_to_node.insert(BBId(1), 1usize);
        let root = reconstruct_binary_search(&nodes, BBId(0), &bb_to_node);
        assert!(root.is_some());
        let root = root.unwrap();
        assert_eq!(root.value, 5);
        assert!(root.lt_child.is_some());
    }

    #[test]
    fn test_find_merge_block() {
        let cases = vec![
            SwitchCase::single(0, BBId(10)),
            SwitchCase::single(1, BBId(11)),
        ];
        let mut cfg_succ = HashMap::new();
        cfg_succ.insert(BBId(10), vec![BBId(99)]);
        cfg_succ.insert(BBId(11), vec![BBId(99)]);
        let merge = find_merge_block(&cases, &cfg_succ);
        assert_eq!(merge, Some(BBId(99)));
    }
}

// ===========================================================================
// Extended: switch lifting heuristics
// ===========================================================================

/// Classify the kind of switch that was compiled.
/// This heuristic looks at the recovered cases and judges which compiler
/// strategy was used.
#[must_use] 
pub fn classify_switch_pattern(sw: &RecoveredSwitch) -> SwitchPattern {
    /// Above this many sparse cases a compare chain gets too deep and the
    /// compiler emits a value/target lookup table instead.
    const BINARY_SEARCH_MAX_CASES: usize = 8;

    let non_default: Vec<&SwitchCase> =
        sw.cases.iter().filter(|c| !c.is_default).collect();
    if non_default.is_empty() {
        return SwitchPattern::Unknown;
    }
    // Dense: all integers [min..=max] covered.
    if is_dense_switch(&sw.cases) {
        return SwitchPattern::JumpTable;
    }
    // The values are sparse. Compilers lower a small number of sparse cases as
    // a compare-and-branch chain (a binary search over the sorted values), and
    // only switch to a value/target lookup table once the case count makes the
    // chain too deep.
    let n: usize = non_default.iter().map(|c| c.values.len()).sum();
    if (2..=BINARY_SEARCH_MAX_CASES).contains(&n) {
        return SwitchPattern::BinarySearch;
    }
    SwitchPattern::SparseLookup
}

// ===========================================================================
// Extended: switch case range merging
// ===========================================================================

/// Merge adjacent numeric case values into ranges (for display purposes).
/// e.g., [1, 2, 3] → range [1..=3].
#[derive(Debug, Clone)]
pub enum CaseValue {
    Single(i64),
    Range(i64, i64), // inclusive
}

impl std::fmt::Display for CaseValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single(v) => write!(f, "{v}"),
            Self::Range(lo, hi) => write!(f, "{lo}..={hi}"),
        }
    }
}

/// Convert the value list of a `SwitchCase` into a compact list of ranges.
#[must_use] 
pub fn merge_case_ranges(values: &[i64]) -> Vec<CaseValue> {
    if values.is_empty() {
        return Vec::new();
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let mut result = Vec::new();
    let mut start = sorted[0];
    let mut end   = sorted[0];
    for &v in &sorted[1..] {
        if v != end + 1 {
            result.push(if start == end {
                CaseValue::Single(start)
            } else {
                CaseValue::Range(start, end)
            });
            start = v;
        }
        end = v;
    }
    result.push(if start == end { CaseValue::Single(start) } else { CaseValue::Range(start, end) });
    result
}

// ===========================================================================
// Extended: switch coverage analysis
// ===========================================================================

/// Statistics about a recovered switch.
#[derive(Debug, Clone)]
pub struct SwitchStats {
    pub total_cases: usize,
    pub has_default: bool,
    pub min_value: Option<i64>,
    pub max_value: Option<i64>,
    pub density: f64,   // 0.0–1.0: fraction of values [min..=max] that have a case
    pub fall_through_count: usize,
    pub pattern: SwitchPattern,
}

impl SwitchStats {
    pub fn compute(sw: &RecoveredSwitch) -> Self {
        let non_default: Vec<&SwitchCase> =
            sw.cases.iter().filter(|c| !c.is_default).collect();
        let all_values: Vec<i64> = non_default.iter()
            .flat_map(|c| c.values.iter().copied())
            .collect();
        let min_value = all_values.iter().copied().reduce(i64::min);
        let max_value = all_values.iter().copied().reduce(i64::max);
        let density = match (min_value, max_value) {
            (Some(lo), Some(hi)) if hi > lo => {
                // Cap counts to u32 then promote via From to avoid usize→f64 precision-loss lint.
                let num = f64::from(u32::try_from(all_values.len()).unwrap_or(u32::MAX));
                let denom = f64::from(u32::try_from(hi - lo + 1).unwrap_or(u32::MAX));
                num / denom
            }
            _ => 1.0,
        };
        let fall_through_count = sw.cases.iter().filter(|c| c.fallthrough_to.is_some()).count();
        let pattern = classify_switch_pattern(sw);
        Self {
            total_cases: non_default.len(),
            has_default: sw.default_case().is_some(),
            min_value,
            max_value,
            density,
            fall_through_count,
            pattern,
        }
    }
}

// ===========================================================================
// Extended: case body ordering
// ===========================================================================

/// Sort switch cases in a canonical order for output:
/// 1. non-default cases by first value, ascending.
/// 2. default last.
pub fn sort_cases_canonical(cases: &mut [SwitchCase]) {
    cases.sort_by(|a, b| {
        let a_key = if a.is_default {
            i64::MAX
        } else {
            a.values.first().copied().unwrap_or(i64::MAX)
        };
        let b_key = if b.is_default {
            i64::MAX
        } else {
            b.values.first().copied().unwrap_or(i64::MAX)
        };
        a_key.cmp(&b_key)
    });
}

// ===========================================================================
// Extended: HLIL switch statement
// ===========================================================================

/// High-level IL switch statement (final output of the switch recovery pass).
#[derive(Debug, Clone)]
pub struct HlilSwitch {
    pub condition: Expr,
    pub cases: Vec<HlilCase>,
    pub default_body: Option<BBId>,
    pub merge: Option<BBId>,
}

#[derive(Debug, Clone)]
pub struct HlilCase {
    pub values: Vec<CaseValue>,
    pub body: BBId,
    pub fallthrough: bool,
}

impl HlilSwitch {
    /// Convert a `RecoveredSwitch` into an `HlilSwitch`.
    #[must_use] 
    pub fn from_recovered(sw: &RecoveredSwitch) -> Self {
        let mut cases = Vec::new();
        let mut default_body = None;
        for case in &sw.cases {
            if case.is_default {
                default_body = Some(case.body);
            } else {
                cases.push(HlilCase {
                    values: merge_case_ranges(&case.values),
                    body: case.body,
                    fallthrough: case.fallthrough_to.is_some(),
                });
            }
        }
        Self {
            condition: sw.switch_expr.clone(),
            cases,
            default_body,
            merge: sw.merge_block,
        }
    }

    #[must_use] 
    pub fn to_pseudocode(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "switch ({}) {{", self.condition);
        for case in &self.cases {
            for val in &case.values {
                let _ = writeln!(out, "  case {val}:");
            }
            let _ = writeln!(out, "    goto {};", case.body);
            if case.fallthrough {
                out.push_str("    /* fall-through */\n");
            } else {
                out.push_str("    break;\n");
            }
        }
        if let Some(def) = self.default_body {
            let _ = write!(out, "  default:\n    goto {def};\n    break;\n");
        }
        out.push_str("}\n");
        out
    }
}

// ===========================================================================
// Extended: string switch pattern (human-readable output)
// ===========================================================================

impl StringHashSwitch {
    #[must_use] 
    pub fn to_pseudocode(&self) -> String {
        let mut out = String::new();
        out.push_str("/* string switch (hash dispatch) */\n");
        for case in &self.cases {
            match &case.string_value {
                Some(s) => { let _ = writeln!(out, "if (hash == 0x{:08X}) /* \"{}\" */ goto {};",
                    case.hash, s, case.target); }
                None => { let _ = writeln!(out, "if (hash == 0x{:08X}) goto {};",
                    case.hash, case.target); }
            }
        }
        out
    }
}

// ===========================================================================
// Extended: jump table stride detection
// ===========================================================================

/// Detect the entry size (stride) of a jump table by reading consecutive
/// addresses and checking whether they are all within the function range.
pub fn detect_entry_size(
    base_addr: Addr,
    count_hint: usize,
    mem: &dyn MemoryView,
) -> Option<usize> {
    let (fstart, fend) = mem.function_range();
    for &stride in &[8usize, 4, 2, 1] {
        let mut all_valid = true;
        for i in 0..count_hint.min(16) {
            let entry_addr = base_addr + (i * stride) as u64;
            match mem.read(entry_addr, stride) {
                Some(v) if v >= fstart && v < fend => {}
                _ => { all_valid = false; break; }
            }
        }
        if all_valid {
            return Some(stride);
        }
    }
    None
}

// ===========================================================================
// Extended: relocation-aware jump table reading
// ===========================================================================

/// A relocation entry that adjusts a raw table value.
#[derive(Debug, Clone)]
pub struct Relocation {
    pub offset: Addr,     // where in the table the relocation applies
    pub addend: i64,      // value to add to the raw bytes
}

/// Read a jump table applying any relocations that overlay it.
pub fn read_jump_table_with_relocs<S: ::std::hash::BuildHasher>(
    base_addr: Addr,
    entry_size: usize,
    count: usize,
    mem: &dyn MemoryView,
    relocs: &[Relocation],
    addr_to_bb: &HashMap<Addr, BBId, S>,
) -> Option<Vec<BBId>> {
    let mut targets = Vec::with_capacity(count);
    // Build a quick reloc map: offset → addend.
    let reloc_map: HashMap<Addr, i64> =
        relocs.iter().map(|r| (r.offset, r.addend)).collect();

    for i in 0..count {
        let entry_addr = base_addr + (i * entry_size) as u64;
        let raw = i64::try_from(mem.read(entry_addr, entry_size)?).unwrap_or(i64::MAX);
        let addend = reloc_map.get(&entry_addr).copied().unwrap_or(0);
        let target = (raw + addend).cast_unsigned();
        let bb = addr_to_bb.get(&target).copied()?;
        targets.push(bb);
    }
    Some(targets)
}

// ===========================================================================
// Extended: switch re-synthesis from case list
// ===========================================================================

/// Given a fully-recovered `RecoveredSwitch`, re-synthesize the minimal jump
/// table representation (as if we were compiling the switch back).
#[must_use] 
pub fn synthesize_jump_table(sw: &RecoveredSwitch) -> Option<Vec<(i64, BBId)>> {
    if !is_dense_switch(&sw.cases) {
        return None;
    }
    let all_values: Vec<(i64, BBId)> = sw
        .cases
        .iter()
        .filter(|c| !c.is_default)
        .flat_map(|c| c.values.iter().map(|&v| (v, c.body)))
        .collect();
    let mut sorted = all_values;
    sorted.sort_by_key(|(v, _)| *v);
    Some(sorted)
}

// ===========================================================================
// Extended tests
// ===========================================================================

#[cfg(test)]
mod extended_tests {
    use super::*;

    #[test]
    fn test_merge_case_ranges_single() {
        let vals = vec![1i64, 2, 3, 5, 7, 8, 9];
        let ranges = merge_case_ranges(&vals);
        assert_eq!(ranges.len(), 3);
        match &ranges[0] { CaseValue::Range(1, 3) => {} r => panic!("Unexpected: {r:?}") }
        match &ranges[1] { CaseValue::Single(5) => {} r => panic!("Unexpected: {r:?}") }
        match &ranges[2] { CaseValue::Range(7, 9) => {} r => panic!("Unexpected: {r:?}") }
    }

    #[test]
    fn test_switch_stats_dense() {
        let sw = RecoveredSwitch {
            switch_expr: Expr::Var("x".into()),
            cases: vec![
                SwitchCase::single(0, BBId(10)),
                SwitchCase::single(1, BBId(11)),
                SwitchCase::single(2, BBId(12)),
            ],
            merge_block: Some(BBId(99)),
        };
        let stats = SwitchStats::compute(&sw);
        assert_eq!(stats.total_cases, 3);
        assert!((stats.density - 1.0).abs() < 0.01);
        assert_eq!(stats.pattern, SwitchPattern::JumpTable);
    }

    #[test]
    fn test_switch_stats_sparse() {
        let sw = RecoveredSwitch {
            switch_expr: Expr::Var("x".into()),
            cases: vec![
                SwitchCase::single(0, BBId(10)),
                SwitchCase::single(100, BBId(11)),
                SwitchCase::single(200, BBId(12)),
            ],
            merge_block: Some(BBId(99)),
        };
        let stats = SwitchStats::compute(&sw);
        assert!(stats.density < 0.1);
        assert_eq!(stats.pattern, SwitchPattern::BinarySearch);
    }

    #[test]
    fn test_hlil_switch_from_recovered() {
        let sw = RecoveredSwitch {
            switch_expr: Expr::Var("cmd".into()),
            cases: vec![
                SwitchCase::single(0, BBId(10)),
                SwitchCase { values: vec![], body: BBId(99), fallthrough_to: None, is_default: true },
            ],
            merge_block: Some(BBId(100)),
        };
        let hlil = HlilSwitch::from_recovered(&sw);
        assert_eq!(hlil.cases.len(), 1);
        assert!(hlil.default_body.is_some());
        let pseudo = hlil.to_pseudocode();
        assert!(pseudo.contains("case 0"));
        assert!(pseudo.contains("default"));
    }

    #[test]
    fn test_synthesize_jump_table() {
        let sw = RecoveredSwitch {
            switch_expr: Expr::Var("i".into()),
            cases: vec![
                SwitchCase::single(0, BBId(10)),
                SwitchCase::single(1, BBId(11)),
                SwitchCase::single(2, BBId(12)),
            ],
            merge_block: None,
        };
        let jt = synthesize_jump_table(&sw);
        assert!(jt.is_some());
        let jt = jt.unwrap();
        assert_eq!(jt.len(), 3);
        assert_eq!(jt[0], (0, BBId(10)));
    }

    #[test]
    fn test_sort_cases_canonical() {
        let mut cases = vec![
            SwitchCase::single(5, BBId(50)),
            SwitchCase { values: vec![], body: BBId(99), fallthrough_to: None, is_default: true },
            SwitchCase::single(1, BBId(10)),
            SwitchCase::single(3, BBId(30)),
        ];
        sort_cases_canonical(&mut cases);
        assert_eq!(cases[0].values.first(), Some(&1));
        assert_eq!(cases[1].values.first(), Some(&3));
        assert_eq!(cases[2].values.first(), Some(&5));
        assert!(cases[3].is_default);
    }

    #[test]
    fn test_detect_entry_size() {
        let fstart: Addr = 0x1000;
        let fend:   Addr = 0x2000;
        // Build a table of four 8-byte entries pointing into [fstart, fend).
        let targets = [0x1010u64, 0x1020, 0x1030, 0x1040];
        let mut data = vec![0u8; 4 * 8];
        for (i, &t) in targets.iter().enumerate() {
            data[i * 8..i * 8 + 8].copy_from_slice(&t.to_le_bytes());
        }
        let mem = FlatMemory { data, base: 0x4000, function_start: fstart, function_end: fend };
        let stride = detect_entry_size(0x4000, 4, &mem);
        assert_eq!(stride, Some(8));
    }

    #[test]
    fn test_classify_switch_jump_table() {
        let sw = RecoveredSwitch {
            switch_expr: Expr::Const(0),
            cases: (0i64..8).map(|i| SwitchCase::single(i, BBId(u32::try_from(i).unwrap_or(0)))).collect(),
            merge_block: None,
        };
        assert_eq!(classify_switch_pattern(&sw), SwitchPattern::JumpTable);
    }

    #[test]
    fn test_string_hash_pseudocode() {
        let sw = StringHashSwitch {
            cases: vec![
                StringHashCase { hash: 0xDEAD, target: BBId(1), string_value: Some("GET".into()) },
                StringHashCase { hash: 0xBEEF, target: BBId(2), string_value: None },
            ],
        };
        let code = sw.to_pseudocode();
        assert!(code.contains("\"GET\""));
        assert!(code.contains("0xBEEF") || code.contains("0x0000BEEF") || code.contains("BEEF"));
    }
}
